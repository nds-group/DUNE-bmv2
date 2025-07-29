import grpc
import json
from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc

import bmpy_utils as bm
from bm_runtime.standard.ttypes import BmMatchParam, BmMatchParamExact, BmAddEntryOptions

from collections import namedtuple

import queue
import argparse
import threading
import socket
import signal

from logger import thread_entry, get_global_logger

logger = get_global_logger()
logger.info("Starting P4Runtime client")

Switch = namedtuple('Switch', 
                    [
                        'stub',
                        'stream',
                        'device_id',
                        'queue',
                        'p4info',
                        'field_list',
                        'thrift_client',
                        'registers'
                    ]
                   )

DuneDigest = namedtuple('DuneDigest',
                        [
                            'src_addr',
                            'dst_addr',
                            'src_port',
                            'dst_port',
                            'protocol',
                            'mpls_label',
                            'flow_class',
                            'register_index',
                        ]
                       )

def connect_to_switch(address, device_id):
    # TODO : Maybe close the channel ?
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


def get_p4info(stub, device_id):
    req = p4runtime_pb2.GetForwardingPipelineConfigRequest()
    req.device_id = device_id
    req.response_type =  p4runtime_pb2.GetForwardingPipelineConfigRequest.P4INFO_AND_COOKIE
    resp = stub.GetForwardingPipelineConfig(req)
    return resp.config.p4info



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


def get_registers_from_switch(thrift_client):
    config = json.loads(thrift_client.bm_get_config())

    registers = []
    for register_array in config["register_arrays"]:
        registers.append(register_array["name"])
    return registers


def get_DuneDigest(entry, field_list, logger):
    logger.debug("  Digest entry:")
    dune_digest = {}
    for i, member in enumerate(entry.struct.members):
        if i < len(field_list):
            name, bitwidth = field_list[i]
            value = int.from_bytes(member.bitstring)
            dune_digest[name] = value
            logger.debug(f"    {name:<15} = {value}")
        else:
            logger.debug(f"    Unknown member (too many): {member}")

    return DuneDigest(**dune_digest)


def send_digest_ack(digest_id, list_id, request_queue):
    ack = p4runtime_pb2.StreamMessageRequest()                                                                                                                                                                                                      
    ack.digest_ack.digest_id = digest_id                                                                                                                                                                                                     
    ack.digest_ack.list_id = list_id                                                                                                                                                                                                         
    request_queue.put(ack)  


def insert_flow_table(dune_digest, sw, logger):
    client = sw.thrift_client
    cxt_id = 0

    match_keys = [
        BmMatchParam(exact=BmMatchParamExact(dune_digest.src_addr.to_bytes(4, 'big'))),
        BmMatchParam(exact=BmMatchParamExact(dune_digest.dst_addr.to_bytes(4, 'big'))),
        BmMatchParam(exact=BmMatchParamExact(dune_digest.src_port.to_bytes(2, 'big'))),
        BmMatchParam(exact=BmMatchParamExact(dune_digest.dst_port.to_bytes(2, 'big'))),
        BmMatchParam(exact=BmMatchParamExact(dune_digest.protocol.to_bytes(1, 'big')))
    ]

    options = BmAddEntryOptions()
    # If you are doing ternary or LPM matches and need to set priority, you must use:
    # options.priority = 10  # or whatever

    action_data = [dune_digest.flow_class.to_bytes(1, 'big')] 

    client.bm_mt_add_entry(
        cxt_id,
        "DuneIngress.Inference.IsFlowClassKnownLocally.FlowClass",
        match_keys,
        "DuneIngress.Inference.IsFlowClassKnownLocally.MetaSetFlowClass",
        action_data,
        options
    )
    logger.info(f"[!] Inserted entry into IsFlowClassKnownLocally table")
    for key in match_keys:
        logger.debug(f"      Match key: {key.exact.value.hex()}")

def clear_registers(dune_digest, sw, logger):
    client = sw.thrift_client
    cxt_id = 0

    for register in sw.registers:
        client.bm_register_write(cxt_id, register, dune_digest.register_index, 0)
        logger.info(f"[!] Cleared register {register} at index {dune_digest.register_index}")

def get_path_switches_by_mpls_label(mpls_label):
    return topo['paths'][mpls_label]


def process_digest_entries(sw, logger):
    response = next(sw.stream)
    request_queue = sw.queue
    field_list = sw.field_list


    if response.HasField("digest"):
        digest = response.digest
        logger.info(f"[!] Received digest ID: {digest.digest_id}, List ID: {digest.list_id}")

        for entry in digest.data:
            dune_digest = get_DuneDigest(entry, field_list, logger)
            # TODO:
            # get list of switches related to the mpls label in the digest,
            try:
                path_switches = get_path_switches_by_mpls_label(dune_digest.mpls_label)
            except KeyError:
                logger.error(f"[!] No path found for MPLS label {dune_digest.mpls_label}. Skipping digest.")
                raise RuntimeError(f"No path found for MPLS label {dune_digest.mpls_label}")
            # and put the digest in the queue of each switch
            for other_sw in path_switches:
                queues[(other_sw.grpc_port, other_sw.thrift_port, other_sw.device_id)].put(dune_digest)
            insert_flow_table(dune_digest, sw, logger)
            clear_registers(dune_digest, sw, logger)
            logger.info(f"[✓] Handled digest ID: {digest.digest_id}, List ID: {digest.list_id}")
            logger.debug("      Digest Content: %s", dune_digest)

        send_digest_ack(digest_id=digest.digest_id, list_id=digest.list_id, request_queue=request_queue)
        logger.info("[✓] Sent digest_ack\n")


    else:
        logger.info("Other message:", response)

def controller_thread(grpc_port, thrift_port, device_id, logger):
    digest_name = "FlowDigest_t"
    stub, stream, q = connect_to_switch(address=f'127.0.0.1:{grpc_port}', device_id=int(device_id))
    p4info = get_p4info(stub, device_id=int(device_id))
    field_list = build_digest_field_map(p4info, digest_name)

    # Thrift connection to the switch
    # (because registers not implemented in GRPC)
    # thrift_client: Client = bm.thrift_connect_standard(
    thrift_client = bm.thrift_connect_standard(
        thrift_ip='127.0.0.1',
        thrift_port=thrift_port,
    )
    registers = get_registers_from_switch(thrift_client)

    sw = Switch(stub,
                p4info=p4info,
                stream=stream,
                device_id=device_id,
                queue=q,
                field_list=field_list,
                thrift_client=thrift_client,
                registers=registers
         )
    logger.info(f"Listening for digest messages: {digest_name}")
    while not shutdown_event.is_set():
        try:
            external_dune_digest = queues[(grpc_port, thrift_port, device_id)].get()
            insert_flow_table(external_dune_digest, sw, logger)
            clear_registers(external_dune_digest, sw, logger)
        except queue.Empty:
            continue
        try:
            process_digest_entries(sw, logger)
        except StopIteration:
            break
        except RuntimeError:
            shutdown_event.set()
            break
        except Exception as e:
            logger.error(f"[!] Error receiving stream message: {e}")
            break
            
            

topo = None
threads = {}
queues = {}
shutdown_event = threading.Event()

def add_controller_thread(grpc_port, thrift_port, device_id):
    key = (grpc_port, thrift_port, device_id)
    assert key not in threads, 'Controller thread already exists for this key'
    thread = threading.Thread(
            target=thread_entry,
            args=(controller_thread, f'c{device_id}', grpc_port, thrift_port, device_id)
            )
    threads[key] = thread
    queues[key] = queue.Queue()
    thread.start()
    logger.info(f'Started controller thread for device {device_id} on ports {grpc_port}, {thrift_port}')

def handle_new_connection(conn, addr):
    logger.debug('New connection from %s:%s to register a switch', addr[0], addr[1])
    try:
        data = conn.recv(1024).decode()
        if data:
            logger.debug('Received registration data')
            grpc_port, thrift_port, device_id = data.strip().split(',')
            ack = 'ACK'
            logger.debug(f'Sending acknowledgment of registration data to switch {device_id}')
            conn.sendall(ack.encode())
            add_controller_thread(grpc_port, thrift_port, device_id)
    except Exception as e:
        logger.info(e)
    finally:
        logger.debug('Closing connection from %s:%s', addr[0], addr[1])
        conn.close()


def run_server(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logger.info('Binding')
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.settimeout(1.0)
    s.listen(1)

    shutdown_event.clear()

    while not shutdown_event.is_set():
        try:
            # TODO: check if all the switches have registered and break if so
            # logger.info('Listening')
            conn, addr = s.accept()
            handle_new_connection(conn, addr)
        except socket.timeout:
            continue
    s.close()


def shutdown(sig, frame):
    logger.info('WOW shut down SIGINT')
    shutdown_event.set()
    for thread in threads.values():
        thread.join()

def shutdown2(sig, frame):
    logger.info('WOW shut down SIGTERM')
    shutdown_event.set()
    for thread in threads.values():
        thread.join()


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('--ip', required=True)
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--topo', required=True)

    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown2)
    shutdown_event.clear()

    logger.info('Starting the server')
    topo = json.loads(args.topo)
    run_server(args.ip, args.port)


if __name__ == '__main__':
    main()

