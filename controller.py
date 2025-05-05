#!/usr/bin/env python3

import p4runtime_sh.shell as p4
import time
import ipaddress
import bmpy_utils as bm
from bm_runtime.standard.Standard import Client

# GRPC connecting to the switch
p4.setup(
    device_id=0,
    grpc_addr="0.0.0.0:50051",
    election_id=(0, 1),  # (high, low)
    verbose=False,
)
# Thrift connection to the switch
# (because registers not implemented in GRPC)
thrift_client: Client = bm.thrift_connect_standard(
    thrift_ip="0.0.0.0",
    thrift_port="9090",
)


digest_list = p4.DigestList()

# file_out = sys.argv[1]
file_out = "output"
output = open(file_out, "w", 1)

header = "source_addr,destin_addr,source_port,destin_port,protocol,pkt_count,flow_packet_class"
registers = [
    "MyIngress.reg_classified_flag",
    "MyIngress.reg_flow_ID",
    "MyIngress.reg_pkt_count",
    "MyIngress.reg_time_last_pkt",
]
print(header, file=output)

npkts = 3

while True:
    print("sniffing")
    dl = digest_list.sniff(timeout=1)

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

            csv_src_addr = str(ipaddress.IPv4Address(source_addr))
            csv_dst_addr = str(ipaddress.IPv4Address(destin_addr))
            csv_row = f"{csv_src_addr},{csv_dst_addr},{source_port},{destin_port},{protocol},{pkt_count},{flow_packet_class}"
            print(csv_row, file=output)

            if pkt_count == npkts:
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
                    a = thrift_client.bm_register_write(0, register, register_index, 0)

    # Necessaray to stop the loop because digest_list.sniff()
    # already catch KeyboardInterrupt
    try:
        print("sleeping")
        time.sleep(1)
    except KeyboardInterrupt:
        print("exiting")
        break

p4.teardown()
output.close()
