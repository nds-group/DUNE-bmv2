from mininet.log import setLogLevel
from mininet.log import debug, info, error

from mininet.node import Host, Switch, Controller
from mininet.link import TCLink
from mininet.net import Mininet

from mininet.cli import CLI
from mininet.clean import cleanup
from mininet.moduledeps import pathCheck

import json
import sys
import os
import psutil
import multiprocessing
import tempfile
import time


def check_listening_on_port(port):
    for c in psutil.net_connections(kind="inet"):
        if c.status == "LISTEN" and c.laddr[1] == port:
            return True
    return False

def throw_if_not_readable(path):
    with open(path, 'r') as _:
        pass

class P4Host(Host):
    def config(self, **_params):
        r = Host.config(self, **_params)

        self.defaultIntf().rename('eth0')
        for off in ["rx", "tx", "sg"]:
            cmd = f"/sbin/ethtool --offload eth0 {off} off"
            self.cmd(cmd)

        # disable IPv6
        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

        return r

class P4SimpleSwitchGRPC(Switch):
    next_device_id = 1
    next_thrift_port = 9091
    next_grpc_port = 50051
    #sw_path = 'simple_switch_grpc'
    sw_path = '/home/alexis/P4/custom/behavioral-model/targets/simple_switch_grpc/simple_switch_grpc'
    START_TIMEOUT = 10

    def __init__(self, name, sw_conf=None, **kwargs):
        Switch.__init__(self, name, **kwargs)
        self.sw_conf = sw_conf
        assert self.sw_conf

        self.sw_path = P4SimpleSwitchGRPC.sw_path
        assert self.sw_path
        pathCheck(self.sw_path)
       
        self.sw_json = f'build/{self.sw_conf["prog"]}.json'
        throw_if_not_readable(self.sw_json)
        
        self.sw_p4info = f'build/{self.sw_conf["prog"]}.p4.p4info.txtpb'
        throw_if_not_readable(self.sw_p4info)

        self.models = [*map(lambda m: f"models/{m}", self.sw_conf["models"])]
        for path in self.models:
            throw_if_not_readable(path)

        self.device_id = P4SimpleSwitchGRPC.next_device_id
        P4SimpleSwitchGRPC.next_device_id += 1

        self.grpc_port = P4SimpleSwitchGRPC.next_grpc_port
        P4SimpleSwitchGRPC.next_grpc_port += 1
        if check_listening_on_port(self.grpc_port):
            raise Exception(
                    f"{self.name} cannot bind port {self.grpc_port} because it is bound by another process\n"
                )

        self.thrift_port = P4SimpleSwitchGRPC.next_thrift_port
        P4SimpleSwitchGRPC.next_thrift_port += 1
        if check_listening_on_port(self.thrift_port):
            raise Exception(
                    f"{self.name} cannot bind port {self.thrift_port} because it is bound by another process\n"
                )
        

    def start(self, controller):
        self.controller = controller[0]
        self.controller.config(
                self.grpc_port, 
                self.thrift_port, 
                self.device_id, 
                self.sw_conf['controller_class']
            )

        args = [self.sw_path]
        for port, intf in self.intfs.items():
            if not intf.IP():
                args += ['-i', str(port) + '@' + intf.name]
        args += ['--pcap', 'pcaps']
        args += ['--nanolog', f'ipc:///tmp/bm-{self.device_id}-log.ipc']
        args += ['--device-id', str(self.device_id)]
        args += [self.sw_json]
        args += ['--log-console']
        args += ['--thrift-port', str(self.thrift_port)]
        args += ['--']
        args += ['--grpc-server-addr', f'0.0.0.0:{self.grpc_port}']

        self.command = ' '.join(args)

        pid = None
        with tempfile.NamedTemporaryFile() as f:
            self.cmd(self.command + f' > logs/{self.name}.log 2>&1 & echo $! >> ' + f.name)
            pid = int(f.read())
        if not self.check_switch_started(pid):
            raise Exception(
                    f'Switch {self.name} failed to start before timeout'
                )

    def check_switch_started(self, pid):
        for _ in range(self.START_TIMEOUT * 2):
            if not os.path.exists(os.path.join("/proc", str(pid))):
                return False
            listening = check_listening_on_port(self.grpc_port)
            listening = check_listening_on_port(self.thrift_port) and listening
            if listening:
                return True
            time.sleep(0.5)
        return False
        
    def stop(self):
        self.cmd(f'pkill -f "{self.command}"')

        args = ["python", "recover_csv.py"]
        args += ["--output", f"logs/recovered_{self.name}.csv"]
        args += ["--input", f"logs/{self.name}.log"]
        args += ["--classe", str(self.sw_conf['controller_class'])]

        command = ' '.join(args)
        self.cmd(command + f' 2>&1')

    def connected(self):
        self.controller.start()
        return True

controllerSwitchMap = {}

class MultiP4SimpleSwitchGRPC(P4SimpleSwitchGRPC):
    # Start the P4SimpleSwitchGRPC with its associated controller
    def start(self, controllers):
        return P4SimpleSwitchGRPC.start(self, [controllerSwitchMap[self.name]])

    # Using batchStartup to program the switches in parallel
    def batchStartup(switches):
        info('\n*** Programming switches\n')
        processes = []
        for sw in switches:
            ps = multiprocessing.Process(target=program_switch, args=[sw])
            processes.append(ps)
            ps.start()
        try:
            for ps in processes:
                ps.join()
        except KeyboardInterrupt:
            for ps in processes:
                ps.terminate()
            raise KeyboardInterrupt
        return switches

def program_switch(sw):
    args = ["python", "convert_RF_and_populate_tables.py"]
    args += ["--p4info", sw.sw_p4info]
    args += ["--json", sw.sw_json]
    args += ["--grpc-port", str(sw.grpc_port)]
    args += ["--device-id", str(sw.device_id)]
    args += ["--models"] + sw.models

    args += [">", f"logs/{sw.name}.p4runtime-requests.txt", "2>&1"]
    command = " ".join(args)
    sw.cmd(command)
    info(sw.name + ' ')

class P4Controller(Controller):
    def __init__(self, name, **kwargs):
        Controller.__init__(self, name, **kwargs)
        self.grpc_port = None
        self.thrift_port = None
        self.device_id = None
        self.classe = None
        self.is_config = False

    def config(self, grpc_port, thrift_port, device_id, classe):
        self.grpc_port = grpc_port 
        self.thrift_port = thrift_port 
        self.device_id = device_id 
        self.classe = classe 
        self.is_config = True

        args = ["python", "controller.py"]
        args += ["--output", f"logs/{self.name}.csv"]
        args += ["--grpc-port", str(self.grpc_port)] 
        args += ["--thrift-port", str(self.thrift_port)] 
        args += ["--device-id", str(self.device_id)] 
        args += ["--classe", str(self.classe)]

        self.command = " ".join(args)

    # Prevent automatic start, the associated switch needs to start first
    def start(self):
        if self.is_config:
            self.cmd(self.command + f' 2>&1 &')

    def stop(self):
        self.cmd(f'pkill -f "{self.command}"')

class Dune():
    def __init__(self, json_path):
        self.config = None
        self.loadJson(json_path)
        info('*** Creating network\n')
        self.net = Mininet(
                host=P4Host,
                switch=MultiP4SimpleSwitchGRPC,
                controller=P4Controller,
                link=TCLink,
                waitConnected=True
            )
        self.configured = False

    def loadJson(self,json_path):
        with open(json_path, 'r') as f:
            self.config = json.load(f)

    def configureFromJson(self):
        info('*** Adding controllers:\n')
        for sw in self.config['switches']:
            name = f'c{sw["name"][1:]}'
            info(name + ' ')
            c = self.net.addController(name)
            controllerSwitchMap[sw['name']] = c
        info('\n')

        info('*** Adding hosts:\n')
        for host in self.config['hosts']:
            info(host + ' ')
            self.net.addHost(host)
        info('\n')

        info('*** Adding switches:\n')
        for sw in self.config['switches']:
            info(sw['name'] + ' ')
            self.net.addSwitch(sw['name'], sw_conf=sw)
        info('\n')

        info('*** Adding links:\n')
        for link in self.config['links']:
            info(f'({link[0]}, {link[1]}) ')
            self.net.addLink(link[0], link[1])
        info('\n')
        self.configured = True

    def start(self):
        if not self.configured:
            self.configureFromJson()
        self.net.start()

    def stop(self):
        self.net.stop()

def main():
    setLogLevel('info')

    dune = Dune('topo.json')

    dune.start()
    CLI(dune.net)
    dune.stop()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        info( "\n\nKeyboard Interrupt. Shutting down and cleaning up...\n\n")
        cleanup()
    except Exception:
        # Print exception
        type_, val_, trace_ = sys.exc_info()
        errorMsg = ( "-"*80 + "\n" +
                     "Caught exception. Cleaning up...\n\n" +
                     "%s: %s\n" % ( type_.__name__, val_ ) +
                     "-"*80 + "\n" )
        error( errorMsg )
        # Print stack trace to debug log
        import traceback
        stackTrace = traceback.format_exc()
        debug( stackTrace + "\n" )
        cleanup()
