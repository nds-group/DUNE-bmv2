#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.cli import CLI

from p4_mininet.host import P4Host
from p4_mininet.switch import P4RuntimeSwitch

from time import sleep
import threading

switches = {
    "s1": {  # CL2-0
        "prog": "unsw_jewel_3_3_41_N3_1_6_481_N2",
        "models": [
            "FINAL_unsw_ClID2_N3_T3_F3_L41_With_Others.sav",
            "unsw_ClID0_N2_T1_F6_L481_With_Others.sav",
        ],
    },
    "s2": {  # CL1-3
        "prog": "ton_jewel_1_5_437_N3_1_6_85_N4",
        "models": [
            "unsw_ClID1_N3_T1_F5_L437_With_Others.sav",
            "unsw_ClID3_N4_T1_F6_L85_With_Others.sav",
        ],
    },
    "s3": {  # CL4-5
        "prog": "unsw_jewel_1_7_217_N3_1_5_129_N3",
        "models": [
            "N_unsw_ClID4_N3_T1_F7_L217_With_Others.sav",
            "unsw_ClID5_N3_T1_F5_L129_With_Others.sav",
        ],
    },
}


class Topology(Topo):
    def __init__(self, conf=None, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        h1 = self.addNode("h1")
        s1 = self.addSwitch(
            "s1",
            sw_path="simple_switch_grpc",
            json_path=f"build/{switches['s1']['prog']}.json",
            pcap_dump="pcaps/",
            log_console=True,
            log_file="logs/s1.log",
            verbose=True,
        )
        s2 = self.addSwitch(
            "s2",
            sw_path="simple_switch_grpc",
            json_path=f"build/{switches['s2']['prog']}.json",
            pcap_dump="pcaps/",
            log_file="logs/s2.log",
            log_console=True,
        )
        s3 = self.addSwitch(
            "s3",
            sw_path="simple_switch_grpc",
            json_path=f"build/{switches['s3']['prog']}.json",
            pcap_dump="pcaps/",
            log_file="logs/s3.log",
            log_console=True,
        )
        self.addLink(h1, s1)
        self.addLink(s1, s2)
        self.addLink(s2, s3)

def program_switches(net, parallel):
    if parallel:
        print("*** Programming switches in parallel")
        threads = []
        for switch in net.switches:
            t = threading.Thread(
                target=program_switch, args=[net, switch.name, switches[switch.name]["models"]]
            )
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
    else:
        for switch in net.switches:
            program_switch(net, switch.name, switches[switch.name]["models"])

def program_switch(net, sw_name, models):
    print(f"*** Programming switch {sw_name}")
    sw = net.get(sw_name)

    args = ["python", "convert_RF_and_populate_tables.py"]
    args += ["--p4info", f"build/{switches[sw_name]['prog']}.p4.p4info.txtpb"]
    args += ["--json", f"build/{switches[sw_name]['prog']}.json"]
    args += ["--grpc-port", str(sw.grpc_port)]
    args += ["--device-id", str(sw.device_id)]
    args += ["--models"] + [*map(lambda m: f"models/{m}", models)]

    args += [">", f"logs/{sw_name}.p4runtime-requests.txt", "2>&1"]
    command = " ".join(args)
    print(command)
    sw.cmd(command)
    print(f"*** Switch {sw_name} programmed")


def main():
    topo = Topology()
    net = Mininet(
        topo=topo, host=P4Host, switch=P4RuntimeSwitch, controller=None, link=TCLink
    )
    print("*** Starting the network")
    net.start()
    print("*** Network started")

    print("*** Programming switches")
    sleep(1)
    program_switches(net, True)
    print("*** Switches programmed")

    sleep(1)

    CLI(net)
    print("*** Stoping the network")
    net.stop()
    print("*** Network stoped")


if __name__ == "__main__":
    # setLogLevel("info")
    main()
