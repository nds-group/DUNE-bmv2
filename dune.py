from mininet.log import setLogLevel
from mininet.log import debug, info, warn, error

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
    for c in psutil.net_connections(kind='inet'):
        if c.status == 'LISTEN' and c.laddr[1] == port:
            return True
    return False

def throw_if_not_readable(path):
    with open(path, 'r') as _:
        pass

class P4Host(Host):
    def config(self, **_params):
        r = Host.config(self, **_params)

        intf = self.defaultIntf()
        for off in ['rx', 'tx', 'sg']:
            cmd = f'/sbin/ethtool --offload {intf} {off} off'
            self.cmd(cmd)

        # disable IPv6
        self.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
        self.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')
        self.cmd('sysctl -w net.ipv6.conf.lo.disable_ipv6=1')

        return r

class P4SimpleSwitchGRPC(Switch):
    next_device_id = 1
    next_thrift_port = 9091
    next_grpc_port = 50051
    sw_path = 'simple_switch_grpc'
    START_TIMEOUT = 10

    def __init__(self, name, selected_model=None, config=None, **kwargs):
        Switch.__init__(self, name, **kwargs)
        # TODO : handle no deployed model
        self.selected_model = selected_model
        assert self.selected_model
        self.config = config
        assert self.config

        self.sw_path = P4SimpleSwitchGRPC.sw_path
        assert self.sw_path
        pathCheck(self.sw_path)


        selected_model_conf = self.config['models'][self.selected_model]
        p4 = selected_model_conf['p4']

        # TODO :
        # Get p4objects dir as a parameter
        self.sw_json = 'p4objects/' + p4 + '.json'
        throw_if_not_readable(self.sw_json)
        
        self.sw_p4info = 'p4objects/' + p4 + '.p4.p4info.txtpb'
        throw_if_not_readable(self.sw_p4info)

        self.models = [*map(lambda m: 'models/' + m, selected_model_conf['files'])]
        for path in self.models:
            throw_if_not_readable(path)

        self.device_id = P4SimpleSwitchGRPC.next_device_id
        P4SimpleSwitchGRPC.next_device_id += 1

        self.grpc_port = P4SimpleSwitchGRPC.next_grpc_port
        P4SimpleSwitchGRPC.next_grpc_port += 1
        if check_listening_on_port(self.grpc_port):
            raise Exception(
                    f'{self.name} cannot bind port {self.grpc_port} because it is bound by another process\n'
                )

        self.thrift_port = P4SimpleSwitchGRPC.next_thrift_port
        P4SimpleSwitchGRPC.next_thrift_port += 1
        if check_listening_on_port(self.thrift_port):
            raise Exception(
                    f'{self.name} cannot bind port {self.thrift_port} because it is bound by another process\n'
                )
        

    def start(self, controller):
        self.controller = controller[0]
        self.controller.config(
                self.grpc_port, 
                self.thrift_port, 
                self.device_id, 
                self.config['models'][self.selected_model]['controller_class']
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
            if not os.path.exists(os.path.join('/proc', str(pid))):
                return False
            listening = check_listening_on_port(self.grpc_port)
            listening = check_listening_on_port(self.thrift_port) and listening
            if listening:
                return True
            time.sleep(0.5)
        return False
        
    def stop(self):
        self.cmd(f'pkill -f "{self.command}"')

    def connected(self):
        self.controller.start()
        return True

switchToControllerMap = {}
switchToModelMap = {}

class ControlledP4SimpleSwitchGRPC(P4SimpleSwitchGRPC):
    # Start the P4SimpleSwitchGRPC with its associated controller
    def start(self, controllers):
        return P4SimpleSwitchGRPC.start(self, [switchToControllerMap[self.name]])

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
    args = ['python', 'convert_RF_and_populate_tables.py']
    args += ['--p4info', sw.sw_p4info]
    args += ['--json', sw.sw_json]
    args += ['--grpc-port', str(sw.grpc_port)]
    args += ['--device-id', str(sw.device_id)]
    args += ['--models'] + sw.models

    args += ['>', f'logs/{sw.name}.p4runtime-requests.txt', '2>&1']
    command = ' '.join(args)
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

        args = ['python', 'controller.py']
        args += ['--grpc-port', str(self.grpc_port)] 
        args += ['--thrift-port', str(self.thrift_port)] 
        args += ['--device-id', str(self.device_id)] 
        args += ['--classe', str(self.classe)]

        self.command = ' '.join(args)

    # Prevent automatic start, the associated switch needs to start first
    def start(self):
        if self.is_config:
            self.cmd(self.command + f' > logs/{self.name}.log 2>&1 &')

    def stop(self):
        self.cmd(f'pkill -f "{self.command}"')

class Dune():
    def __init__(self, json_path):
        self.config = None
        self.loadJson(json_path)
        info('*** Creating network\n')
        self.net = Mininet(
                host=P4Host,
                switch=ControlledP4SimpleSwitchGRPC,
                controller=P4Controller,
                link=TCLink,
                waitConnected=True
            )
        self.configured = False

    def loadJson(self,json_path):
        with open(json_path, 'r') as f:
            self.config = json.load(f)

    def assignModels(self):
        # Create graph of the network
        # TODO : move import
        import networkx as nx
        G = nx.Graph()
        switches = self.config['switches']
        hosts = self.config['hosts']
        links = self.config['links']
        G.add_nodes_from(switches)
        G.add_nodes_from(hosts)
        G.add_edges_from(links)

        # Draw
        # TODO : refactor
        display = 0
        if display:
            import matplotlib.pyplot as plt
            pos = nx.spring_layout(G)
            nx.draw_networkx_nodes(G, pos, nodelist=switches, node_color='tab:blue')
            nx.draw_networkx_nodes(G, pos, nodelist=hosts, node_color='tab:red')
            nx.draw_networkx_edges(G, pos, edgelist=links)
            nx.draw_networkx_labels(G, pos)
            #nx.draw(G, with_labels=True)
            plt.show()

        models = self.config['models']
        # TODO : move imports
        import pulp
        import itertools
        prob = pulp.LpProblem('Assign', pulp.LpMinimize)

        # Deployment variables
        X = {}
        for sw in switches:
            X[sw] = {}
            for m in models: 
                X[sw][m] = pulp.LpVariable(f'x_{sw}_{m}', cat='Binary')

        # Objective function
        # Info : For now we minize the number of deployed models
        prob += pulp.lpSum(X)

        # Creating paths
        pairs = itertools.permutations(hosts, 2)
        paths = []
        for p1, p2 in pairs:
            for path in nx.all_simple_paths(G, p1, p2):
                sw_in_path = list(filter(lambda node: node in switches, path))
                paths.append(sw_in_path)
    
        # At least one of each model on the path
        for path in paths:
            for m in models:
                expr = pulp.LpAffineExpression()
                for sw in path:
                    expr.addInPlace(X[sw][m], 1)
                prob += expr >= 1

        # Models in order
        for path in paths:
            for m in models:
                prev = self.config['models'][m]['previous']
                if prev is not None:
                    accumulator = [path[:i + 1] for i in range(len(path))]
                    for sws in accumulator:
                        current_model_switch = sws.pop()
                        expr = pulp.LpAffineExpression()
                        for sw in sws:
                            expr.addInPlace(X[sw][prev], 1)
                        prob += expr >= X[current_model_switch][m]

        prob.solve()
        # TODO : use log and remove prints
        print("Status:", pulp.LpStatus[prob.status])
        for v in prob.variables():
            print(v.name, "=", v.varValue)
        for sw in switches:
            switchToModelMap[sw] = None
            for m in models: 
                if X[sw][m].varValue == 1:
                    switchToModelMap[sw] = m


    def configureFromJson(self):
        info('*** Adding controllers:\n')
        for sw in self.config['switches']:
            name = f'c{sw[1:]}'
            info(name + ' ')
            c = self.net.addController(name)
            switchToControllerMap[sw] = c
        info('\n')

        info('*** Adding hosts:\n')
        for host in self.config['hosts']:
            info(host + ' ')
            self.net.addHost(host)
        info('\n')

        info('*** Adding switches:\n')
        for sw in self.config['switches']:
            info(sw + ' ')
            self.net.addSwitch(sw, selected_model=switchToModelMap[sw], config=self.config)
        info('\n')

        info('*** Adding links:\n')
        for link in self.config['links']:
            info(f'({link[0]}, {link[1]}) ')
            intfs = self.net.addLink(link[0], link[1])
            # Jumbo frame support 
            self.net.get(link[0]).cmd(f'ip link set dev {intfs.intf1} mtu 9000')
            self.net.get(link[1]).cmd(f'ip link set dev {intfs.intf2} mtu 9000')
        info('\n')
        self.configured = True

    def start(self):
        if not self.configured:
            self.configureFromJson()
        self.net.start()

    def stop(self):
        self.net.stop()

    def CLI(self):
        CLI(self.net)

def main():
    setLogLevel('debug')

    #path = input('Path for the topology file: ')
    #dune = Dune(path)
    dune = Dune('topo_no_populate.json')
    #dune = Dune('topo.json')

    # TODO : move next line and add checks
    dune.assignModels()

    dune.start()
    dune.CLI()
    dune.stop()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        info( '\n\nKeyboard Interrupt. Shutting down and cleaning up...\n\n')
        cleanup()
    except Exception:
        # Print exception
        type_, val_, trace_ = sys.exc_info()
        errorMsg = ( '-'*80 + '\n' +
                     'Caught exception. Cleaning up...\n\n' +
                     '%s: %s\n' % ( type_.__name__, val_ ) +
                     '-'*80 + '\n' )
        error( errorMsg )
        # Print stack trace to debug log
        import traceback
        stackTrace = traceback.format_exc()
        debug( stackTrace + '\n' )
        cleanup()
