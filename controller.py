#!/usr/bin/env python3

import p4runtime_sh.shell as p4
import time
import ipaddress
import bmpy_utils as bm
from bm_runtime.standard.Standard import Client
import argparse
import json


def get_registers_from_switch(thrift_client):
    config = json.loads(thrift_client.bm_get_config())

    registers = []
    for register_array in config["register_arrays"]:
        registers.append(register_array["name"])
    return registers


def handle_digest(thrift_client, registers, classe, dl, output):
    for response in dl:
        for data in response.digest.data:
            source_addr = int.from_bytes(data.struct.members[0].bitstring)
            destin_addr = int.from_bytes(data.struct.members[1].bitstring)
            source_port = int.from_bytes(data.struct.members[2].bitstring)
            destin_port = int.from_bytes(data.struct.members[3].bitstring)
            protocol = int.from_bytes(data.struct.members[4].bitstring)
            flow_packet_class = int.from_bytes(data.struct.members[5].bitstring)
            pkt_count = int.from_bytes(data.struct.members[6].bitstring)
            register_index = int.from_bytes(data.struct.members[7].bitstring)
            is_flow = int.from_bytes(data.struct.members[8].bitstring)
            is_store = int.from_bytes(data.struct.members[9].bitstring)
            is_refresh = int.from_bytes(data.struct.members[10].bitstring)

            csv_src_addr = str(ipaddress.IPv4Address(source_addr))
            csv_dst_addr = str(ipaddress.IPv4Address(destin_addr))
            csv_row = f"{csv_src_addr},{csv_dst_addr},{source_port},{destin_port},{protocol},{pkt_count},{is_flow}"
            if is_store == 1:
                if flow_packet_class == classe:
                    csv_row = f"{csv_row},{32}"
                else:
                    csv_row = f"{csv_row},{flow_packet_class}"
            else:
                csv_row = f"{csv_row},{55}"
            print(csv_row, file=output)

            if is_refresh == 1:
                entry = p4.TableEntry("MyIngress.flow_action_table")(
                    action="MyIngress.set_flow_action"
                )
                entry.match["hdr.ipv4.src_addr"] = str(source_addr)
                entry.match["hdr.ipv4.dst_addr"] = str(destin_addr)
                entry.match["meta.hdr_srcport"] = str(source_port)
                entry.match["meta.hdr_dstport"] = str(destin_port)
                entry.match["hdr.ipv4.protocol"] = str(protocol)
                entry.action["f_action"] = "0"
                entry.modify()

                for register in registers:
                    thrift_client.bm_register_write(0, register, register_index, 0)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--grpc-port", required=True)
    parser.add_argument("--thrift-port", required=True)
    parser.add_argument("--device-id", required=True, type=int)
    parser.add_argument("--classe", required=True, type=int)
    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    output = open(args.output, "w", 1)
    header = "source_addr,destin_addr,source_port,destin_port,protocol,pkt_count,is_flow,flow_packet_class"
    print(header, file=output)

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

    while True:
        dl = digest_list.sniff(timeout=1)
        
        handle_digest(thrift_client, registers, args.classe, dl, output)

    p4.teardown()
    output.close()


if __name__ == "__main__":
    main()
