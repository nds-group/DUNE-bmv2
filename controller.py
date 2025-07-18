import p4runtime_sh.shell as p4
import time
import ipaddress
import bmpy_utils as bm
from bm_runtime.standard.Standard import Client
import argparse
import json

import logging
logging.basicConfig(level=logging.INFO)

def get_registers_from_switch(thrift_client):
    config = json.loads(thrift_client.bm_get_config())

    registers = []
    for register_array in config["register_arrays"]:
        registers.append(register_array["name"])
    logging.info('Switch registers affected by reset :%s', '\n - '.join([''] + registers) )
    return registers


#TODO :
# - Rework the table updates and the register updates
# - Add some logging here ?
def handle_digest(thrift_client, registers, classe, dl):
    for response in dl:
        logging.info('Received a digest')
        for data in response.digest.data:
            src_addr = int.from_bytes(data.struct.members[0].bitstring)
            dst_addr = int.from_bytes(data.struct.members[1].bitstring)
            src_port = int.from_bytes(data.struct.members[2].bitstring)
            dst_port = int.from_bytes(data.struct.members[3].bitstring)
            protocol = int.from_bytes(data.struct.members[4].bitstring)
            flow_class = int.from_bytes(data.struct.members[5].bitstring)
            register_index = int.from_bytes(data.struct.members[6].bitstring)

            entry = p4.TableEntry("DuneIngress.IsFlowClassKnownLocally.FlowClass")(
                action="DuneIngress.IsFlowClassKnownLocally.MetaSetFlowClass"
            )
            entry.match["hdr.ipv4.src_addr"] = str(src_addr)
            entry.match["hdr.ipv4.dst_addr"] = str(dst_addr)
            entry.match["meta.src_port"] = str(src_port)
            entry.match["meta.dst_port"] = str(dst_port)
            entry.match["hdr.ipv4.protocol"] = str(protocol)
            entry.action["flow_class"] = str(flow_class)
            
            log = '\n - '.join([''] + [
                'src_addr : ' + str(ipaddress.IPv4Address(src_addr)),
                'dst_addr : ' + str(ipaddress.IPv4Address(dst_addr)),
                'src_port : ' + str(src_port),
                'dst_port : ' + str(dst_port),
                'protocol : ' + str(protocol),
                'flow_class : ' + str(flow_class),
            ])
            logging.info('Inserting entry :%s', log) 

            entry.insert()

            for register in registers:
                thrift_client.bm_register_write(0, register, register_index, 0)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--grpc-port", required=True)
    parser.add_argument("--thrift-port", required=True)
    parser.add_argument("--device-id", required=True, type=int)
    parser.add_argument("--classe", required=True, type=int)
    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    # GRPC connecting to the switch
    p4.setup(
        device_id=args.device_id,
        grpc_addr=f"0.0.0.0:{args.grpc_port}",
        election_id=(0, 1),  # (high, low)
        verbose=False,
    )
    # Thrift connection to the switch
    # (because registers not implemented in GRPC)
    thrift_client: Client = bm.thrift_connect_standard(
        thrift_ip="0.0.0.0",
        thrift_port=args.thrift_port,
    )

    digest_list = p4.DigestList()

    registers = get_registers_from_switch(thrift_client)

    logging.info('Starting listening for digests')
    while True:
        dl = digest_list.sniff(timeout=1)
        
        handle_digest(thrift_client, registers, args.classe, dl)

    p4.teardown()
    output.close()


if __name__ == "__main__":
    main()
