#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.cli import CLI

from p4_mininet.host import P4Host
from p4_mininet.switch import P4RuntimeSwitch

from time import sleep

switches = {
    "s1": "unsw_jewel_3_3_41_N3_1_6_481_N2",
    "s2": "ton_jewel_1_5_437_N3_1_6_85_N4",
    "s3": "unsw_jewel_1_7_217_N3_1_5_129_N3",
}


class Topology(Topo):
    def __init__(self, conf=None, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        h1 = self.addNode("h1")
        s1 = self.addSwitch(
            "s1",
            sw_path="simple_switch_grpc",
            json_path=f"build/{switches['s1']}.json",
            pcap_dump="pcaps/",
            log_console=True,
        )
        s2 = self.addSwitch(
            "s2",
            sw_path="simple_switch_grpc",
            json_path=f"build/{switches['s2']}.json",
            pcap_dump="pcaps/",
            log_console=True,
        )
        s3 = self.addSwitch(
            "s3",
            sw_path="simple_switch_grpc",
            json_path=f"build/{switches['s3']}.json",
            pcap_dump="pcaps/",
            log_console=True,
        )
        self.addLink(h1, s1)
        self.addLink(s1, s2)
        self.addLink(s2, s3)


def main():
    topo = Topology()
    net = Mininet(
        topo=topo, host=P4Host, switch=P4RuntimeSwitch, controller=None, link=TCLink
    )
    net.start()

    sleep(1)
    # print("Configuring the switch")
    # out = net.get("s1").cmd("python convert_RF_and_populate_tables.py")
    # print(out)
    # ! The next commands never finishes
    # out = net.get("s1").cmd("python controller.py")
    # print(out)
    # print("Switch configured")

    CLI(net)
    net.stop()


if __name__ == "__main__":
    # setLogLevel("info")
    main()
