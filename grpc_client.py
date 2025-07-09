import grpc
from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc
from p4.config.v1 import p4info_pb2
from google.protobuf import text_format
from collections import namedtuple
import time
import queue
import threading
import signal

from logger import thread_entry, setup_thread_logger, get_global_logger

# Main thread logger
logger = get_global_logger()
logger.info("Starting P4Runtime client")

# Global flag to exit cleanly
running = True

def signal_handler(sig, frame):
    global running
    logger.info("\nReceived SIGINT, exiting gracefully...")
    running = False

# Register SIGINT handler
signal.signal(signal.SIGINT, signal_handler)


def connect_to_switch(address='127.0.0.1:50051', device_id=0):
    channel = grpc.insecure_channel(address)
    stub = p4runtime_pb2_grpc.P4RuntimeStub(channel)

    # This queue will hold StreamMessageRequest objects
    q = queue.Queue()

    def request_generator():
        while True:
            req = q.get()
            if req is None:
                break
            yield req

    # Start stream
    stream = stub.StreamChannel(request_generator())

    # Send the initial arbitration message
    election_id = p4runtime_pb2.Uint128(high=0, low=2)
    req = p4runtime_pb2.StreamMessageRequest()
    req.arbitration.device_id = device_id
    req.arbitration.election_id.CopyFrom(election_id)

    q.put(req)

    # Wait for arbitration response
    response = next(stream)
    assert response.HasField("arbitration")
    logger.info("Connected to switch with device_id = %s", device_id)

    # Return the stub, the stream, and the request queue to send more messages later
    return stub, stream, q

def set_pipeline_config(stub, device_id, election_id, p4info_path, bmv2_json_path):
    # Load P4Info
    p4info = p4info_pb2.P4Info()
    with open(p4info_path, 'r') as f:
        text_format.Merge(f.read(), p4info)

    # Load BMv2 JSON
    with open(bmv2_json_path, 'rb') as f:
        bmv2_json_bytes = f.read()

    # Create request
    request = p4runtime_pb2.SetForwardingPipelineConfigRequest()
    request.device_id = device_id
    request.election_id.CopyFrom(election_id)
    request.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT
    request.config.p4info.CopyFrom(p4info)
    request.config.p4_device_config = bmv2_json_bytes

    # Send the request
    stub.SetForwardingPipelineConfig(request)
    logger.info(f"Pipeline config set for device {device_id}")

    return p4info

def get_p4info(stub, device_id=0):
    req = p4runtime_pb2.GetForwardingPipelineConfigRequest()
    req.device_id = device_id
    req.response_type =  p4runtime_pb2.GetForwardingPipelineConfigRequest.P4INFO_AND_COOKIE
    resp = stub.GetForwardingPipelineConfig(req)
    return resp.config.p4info

def read_register(stub, device_id, p4info, register_name, index):
    register_id = get_register_id(p4info, register_name)
    entity = p4runtime_pb2.Entity()
    entity.register_entry.register_id = register_id
    entity.register_entry.index.index = index

    request = p4runtime_pb2.ReadRequest(device_id=device_id)
    request.entities.append(entity)

    for response in stub.Read(request):
        for entity in response.entities:
            if entity.HasField("register_entry"):
                data = entity.register_entry.data
                logger.info(f"Register {register_name}[{index}] = {int.from_bytes(data, 'big')}")

def write_register(stub, device_id, p4info, register_name, index, value):
    register_id = get_register_id(p4info, register_name)
    
    entry = p4runtime_pb2.RegisterEntry()
    entry.register_id = register_id
    entry.index.index = index
    entry.data = value.to_bytes(4, byteorder='big')  # Adjust byte length as needed

    update = p4runtime_pb2.Update()
    update.type = p4runtime_pb2.Update.MODIFY
    update.entity.register_entry.CopyFrom(entry)

    request = p4runtime_pb2.WriteRequest()
    request.device_id = device_id
    request.election_id.low = 2  # Must match the controller's arbitration ID
    request.updates.extend([update])

    stub.Write(request)
    logger.info(f"Register {register_name}[{index}] <- {value}")


def get_register_id(p4info, register_name):
    for reg in p4info.registers:
        if reg.preamble.name == register_name:
            return reg.preamble.id
    raise KeyError(f"Register {register_name} not found")


def get_digest_id(p4info, digest_name):
    for digest in p4info.digests:
        if digest.preamble.name == digest_name:
            return digest.preamble.id
    raise ValueError(f"Digest '{digest_name}' not found in P4Info.")


def list_digests(p4info):
    return [digest.preamble.name for digest in p4info.digests]


def build_digest_field_map(p4info, digest_name):
    """Returns an ordered list of (name, bitwidth) based on digest type_spec."""
    for digest in p4info.digests:
        if digest.preamble.name == digest_name:
            struct_name = digest.type_spec.struct.name
            struct = p4info.type_info.structs[struct_name]
            field_list = []
            for member in struct.members:
                bitwidth = member.type_spec.bitstring.bit.bitwidth
                field_list.append((member.name, bitwidth))
            return field_list
    raise ValueError(f"Digest '{digest_name}' not found in P4Info.")


def listen_for_digests(stream, digest_name, field_list, request_queue, device_id, logger):
    logger.info(f"Listening for digest messages: {digest_name}")
    logfile = open(f"./logs/s{device_id}_digests.log", "w")
    while running:
        try:
            response = next(stream)
        except StopIteration:
            break
        except Exception as e:
            logger.info(f"[!] Error receiving stream message: {e}")
            break

        if response.HasField("digest"):
            digest = response.digest
            logger.info(f"\n[!] Received digest ID: {digest.digest_id}, List ID: {digest.list_id}")

            for entry in digest.data:
                logger.info("  Digest entry:")
                for i, member in enumerate(entry.struct.members):
                    if i < len(field_list):
                        name, bitwidth = field_list[i]
                        value = int.from_bytes(member.bitstring)
                        logger.info(f"    {name:<15} = {value}")
                    else:
                        logger.warning(f"    Unknown member (too many): {member}")

            # Send digest acknowledgment
            ack = p4runtime_pb2.StreamMessageRequest()
            ack.digest_ack.digest_id = digest.digest_id
            ack.digest_ack.list_id = digest.list_id
            request_queue.put(ack)
            logger.info("  [✓] Sent digest_ack\n")
        else:
            logger.info("Other message:", response)
    logfile.close()


if __name__ == '__main__':
    devices = {
            "s1": {"address": "127.0.0.1:50051", "device_id": 1},
            "s2": {"address": "127.0.0.1:50052", "device_id": 2},
            "s3": {"address": "127.0.0.1:50053", "device_id": 3},
    }
    digest_name = "flow_class_digest"

    Switch = namedtuple('Switch', 
                        [
                            'stub',
                            'stream',
                            'device_id',
                            'queue',
                            'p4info',
                            'field_list'
                        ]
            )
    switches = {}

    # Connect to all switches
    for name, info in devices.items():
        stub, stream, q = connect_to_switch(address=info["address"], device_id=info["device_id"])
        p4info = get_p4info(stub, device_id=info["device_id"])
        field_list = build_digest_field_map(p4info, digest_name)
        sw = Switch(stub,
                    p4info=p4info,
                    stream=stream,
                    device_id=info["device_id"],
                    queue=q,
                    field_list=field_list
            )
        switches[name] = sw

    # Build field map from P4Info

    # Start listener for each switch
    for name, sw in switches.items():
        logger.info(f"Starting thread for {name}...")
        
        controller_thread = threading.Thread(
            target=thread_entry,
            args=(listen_for_digests, f'c{sw.device_id}', sw.stream, digest_name, sw.field_list, sw.queue, sw.device_id),
            daemon=True
        )
        controller_thread.start()

    # Keep the main thread alive until SIGINT
    try:
        while running:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass

    logger.info("Controller exiting.")
