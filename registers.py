from p4.v1 import p4runtime_pb2
from p4.config.v1 import p4info_pb2
from google.protobuf import text_format

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
                print(f"Register {register_name}[{index}] = {int.from_bytes(data, 'big')}")

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
    print(f"Register {register_name}[{index}] <- {value}")


def get_register_id(p4info, register_name):
    for reg in p4info.registers:
        if reg.preamble.name == register_name:
            return reg.preamble.id
    raise KeyError(f"Register {register_name} not found")


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
    print(f"Pipeline config set for device {device_id}")

    return p4info
