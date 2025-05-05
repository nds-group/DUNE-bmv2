#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.cli import CLI

from p4_mininet.host import P4Host
from p4_mininet.switch import P4RuntimeSwitch

from time import sleep

class Topology(Topo):
    def __init__(self, conf=None, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        h1 = self.addNode("h1")
        s1 = self.addSwitch(
            "s1",
            sw_path="simple_switch_grpc",
            json_path="build/unsw_jewel_14_3_6_N3.json",
            pcap_dump="pcaps/",
            log_console=True,
        )
        # s2 = self.addSwitch(
        #     "s2",
        #     sw_path="simple_switch_grpc",
        #     json_path="build/unsw_jewel_14_3_6_N3.json",
        #     pcap_dump="pcaps/",
        #     log_console=True,
        # )
        self.addLink(h1, s1)
        # self.addLink(s1, s2)

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
