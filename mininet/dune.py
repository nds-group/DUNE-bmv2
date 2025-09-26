from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import info, debug, lg
from abc import ABC, abstractmethod

from time import sleep
from os import listdir
from os.path import isfile, isdir, join
import json
import networkx as nx
import pulp
import itertools
import re
from collections import defaultdict

from pprint import pprint

def assertIsFile(path):
    assert isfile(path), path + ' was not found or is a directory'


def assertIsDir(path):
    assert isdir(path), path + ' was not found or is a file'


def loadJsonFile(path):
    with open(path, 'r') as file:
        return json.load(file)

def assignModels(topo, models, paths, pulp_msg=0):
    # remove hosts from the paths
    paths = list(topo['paths'].values())
    paths = [list(filter(lambda node: node in topo['switches'], path)) for path in paths]

    G = nx.Graph()
    G.add_nodes_from(topo['switches'])
    G.add_nodes_from(topo['hosts'])
    G.add_edges_from(topo['links'])

    # Minimisation problem
    ilp = pulp.LpProblem('AssignModels', pulp.LpMinimize)

    # Deployment variables
    X = {}
    for sw in topo['switches']:
        X[sw] = {}
        for m in models:
            X[sw][m] = pulp.LpVariable(f'x_{sw}_{m}', cat='Binary')

    # Adding the objective function
    ilp += pulp.lpSum(X)

    # Integrity constraints :
    # For each path, one of each model must appear in a switch in the path
    for path in paths:
        for m in models:
            expr = pulp.LpAffineExpression()
            for sw in path:
                expr.addInPlace(X[sw][m], 1)
            ilp += expr >= 1

    # Dependency constraints :
    # For each path, if a model is deployed in a switch and has a dependency
    # then the dependency must apprear earlier in the path
    for path in paths:
        for m in models:
            prev = models[m]['previous']
            if prev is not None:
                accumulator = [path[:i + 1] for i in range(len(path))]
                for sws in accumulator:
                    current_model_switch = sws.pop()
                    expr = pulp.LpAffineExpression()
                    for sw in sws:
                        expr.addInPlace(X[sw][prev], 1)
                    ilp += expr >= X[current_model_switch][m]

    ilp.solve(pulp.PULP_CBC_CMD(msg=pulp_msg))
    assert ilp.status == pulp.constants.LpStatusOptimal, 'ILP could not find a solution'

    #TODO log the results
    model_assignment = {}
    for sw in topo['switches']:
        model_assignment[sw] = None
        for m in models:
            if X[sw][m].varValue == 1:
                assert model_assignment[sw] is None, 'A switch received more than one model'
                model_assignment[sw] = models[m]
        if model_assignment[sw] is None:
            model_assignment[sw] = { 'p4': 'no_inference' }

    return model_assignment


def build_fattree_topo(super_spines,  pods, spines, leafs, hosts_per_leaf):
        topo = {
            'switches': [],
            'hosts': [],
            'links': [],
            'paths': {}
        }
        for spine_idx in range(spines):
            for super_spine_idx in range(super_spines):
                topo['switches'].append(f'ss_{spine_idx}_{super_spine_idx}')

        def set_up_pod(pod_idx, hosts_per_leaf=hosts_per_leaf):
            # Create super spines for current spine
            for spine_idx in range(spines):
                for super_spine_idx in range(super_spines): # Connect spine switches to super spines
                    topo['links'].append([f'p{pod_idx}_s{spine_idx}', f'ss_{spine_idx}_{super_spine_idx}'])
            for spine_idx in range(spines):
                # Create spine switch
                topo['switches'].append(f'p{pod_idx}_s{spine_idx}')

            for leaf_idx in range(leafs):
                # Create leaf switches
                topo['switches'].append(f'p{pod_idx}_l{leaf_idx}')
                # Connect leafs to spines
                for spine_idx in range(spines):
                    topo['links'].append([f'p{pod_idx}_s{spine_idx}', f'p{pod_idx}_l{leaf_idx}'])
                # Create hosts
                for host_idx in range(hosts_per_leaf):
                    topo['hosts'].append(f'p{pod_idx}_h{leaf_idx}_{host_idx}')
                    # Connect hosts to leafs
                    topo['links'].append([f'p{pod_idx}_l{leaf_idx}', f'p{pod_idx}_h{leaf_idx}_{host_idx}'])

        for pod_idx in range(pods):
            set_up_pod(pod_idx)

        set_up_pod('e', pods*hosts_per_leaf)
        
        # Set up paths
        path_id = 1
        pod_spine_counters = defaultdict(int)  # pod_idx -> spine counter

        for leaf_idx in range(leafs):
            for host_idx in range(hosts_per_leaf):
                dst_leaf = f'pe_l{leaf_idx}'
                for pod_idx in range(pods):
                    src_host = f'p{pod_idx}_h{leaf_idx}_{host_idx}'
                    src_leaf = f'p{pod_idx}_l{leaf_idx}'

                    # Destination host: match pod_idx in the host suffix to create unique egress host
                    dst_host = f'pe_h{leaf_idx}_{pod_idx}'

                    # Balanced spine selection *within each pod*
                    spine_idx = pod_spine_counters[pod_idx] % spines
                    pod_spine_counters[pod_idx] += 1

                    spine = f'p{pod_idx}_s{spine_idx}'
                    super_spine_idx = (path_id -  1) % super_spines
                    super_spine = f'ss_{spine_idx}_{super_spine_idx}'
                    dst_spine = f'pe_s{spine_idx}'

                    path = [
                        src_host,
                        src_leaf,
                        spine,
                        super_spine,
                        dst_spine,
                        dst_leaf,
                        dst_host
                    ]

                    topo['paths'][path_id] = path
                    path_id += 1
        return topo

class Dune(Topo, ABC):
    @abstractmethod
    def set_topo(self, **kwargs):
        """
        Set the topology for the Dune instance.
        This method should be implemented by subclasses to define how the topology is set.
        """
        pass

    def debugTopo(self):
        debug(f"*** Hosts: {self.topo['hosts']}\n")
        debug(f"*** Switches: {self.topo['switches']}\n")
        debug(f'*** Links: ***\n')
        for link in self.topo['links']:
            debug(f'  {link[0]} <-> {link[1]}\n')
        debug(f'*** Paths: ***\n')
        for path_id, path in self.topo['paths'].items():
            debug(f'  {path_id}: {path}\n')

    def build(self, models, models_dir, objects_dir, log_dir, pcap_dir, pcap_regex='.*', **kwargs):
        assertIsFile(models)
        assertIsDir(models_dir)
        assertIsDir(objects_dir)
        assertIsDir(log_dir)
        assertIsDir(pcap_dir)

        self.set_topo(**kwargs)
        self.debugTopo()
        assert self.topo
        self.models = loadJsonFile(models)
        self.models_dir = models_dir
        self.objects_dir = objects_dir
        self.log_dir = log_dir
        self.pcap_dir = pcap_dir
        self.pcap_regex = pcap_regex
        self.test_pps = kwargs.get('test_pps', 100)
        self.pkt_num = kwargs.get('pkt_num', None)

        regex_pattern = re.compile(pcap_regex)


        for host in self.topo['hosts']:
            self.addHost(host)

        if self.__class__.__name__ == 'DuneJsonTopo':
            # Creating paths
            pairs = itertools.combinations(self.topo['hosts'], 2)
            paths = {}
            for idx, (h1, h2) in enumerate(pairs):
                for path in nx.all_simple_paths(G, h1, h2):
                    sw_in_path = list(filter(lambda node: node in self.topo['switches'], path))
                    paths[idx]=sw_in_path

            self.paths=paths
        else:
            self.paths = self.topo['paths']

        # Mininet's debug level is 10
        msg = 1 if lg.level == 10 else 0

        self.model_assignment = assignModels(self.topo, self.models, self.paths, msg)
        info('*** Model assignment:\n')
        for sw in self.topo['switches']:
            info(f'Added switch {sw} with model {self.model_assignment[sw]}\n')

        for sw in self.topo['switches']:
            enable_pcap = True if regex_pattern.match(sw) else False
            self.addSwitch(
                    sw,
                    model_config=self.model_assignment[sw],
                    model_dir=self.models_dir,
                    objects_dir=self.objects_dir,
                    log_dir=self.log_dir,
                    enable_pcap=enable_pcap,
                    pcap_dir=self.pcap_dir,
                    ingress_port_to_mpls=None,
                    mpls_to_egress_port=None,
                )

        for nodes in self.topo['links']:
            self.addLink(nodes[0], nodes[1])

        for path in self.topo['paths']:
            self.processPathForwardingInfo(path)

    def processPathForwardingInfo(self, path):
        for node1, node2 in itertools.pairwise(self.topo['paths'][path]):
            port1, port2 = self.port(node1, node2)
            if not self.isSwitch(node1) and self.isSwitch(node2):
                # Ingress switch
                self.updateSwitchForwardingInfo(
                        node2, 'ingress_port_to_mpls', port2, path
                        )
            if self.isSwitch(node1):
                # Every other ones
                self.updateSwitchForwardingInfo(
                        node1, 'mpls_to_egress_port', path, port1
                        )

    def updateSwitchForwardingInfo(self, node, info_key, key, value):
        nodeInfo = self.nodeInfo(node)
        if nodeInfo[info_key] is None:
            nodeInfo[info_key] = {}
        nodeInfo[info_key][key] = value
        self.setNodeInfo(node, nodeInfo)


class DuneJsonTopo(Dune):
    def set_topo(self, **kwargs):
        topo = kwargs.get('topo')
        assertIsFile(topo)
        self.topo = loadJsonFile(topo)


class DuneFatTree(Dune):
    def set_topo(self, super_spines=1,  pods=3, spines=2, leafs=3, hosts_per_leaf=1, **kwargs):
        debug(f'Building FatTree with {super_spines} super spines, {pods} pods, {spines} spines per pod, {leafs} leafs per pod and {hosts_per_leaf} hosts per leaf\n')
        topo = build_fattree_topo(super_spines=super_spines,
                                  pods=pods,
                                  spines=spines,
                                  leafs=leafs,
                                  hosts_per_leaf=hosts_per_leaf
                                  )

        with open('configs/topos/fattreetopo.json', 'w') as f:
            json.dump(topo, f)
        self.topo = topo

def injectPcaps(net, pcap_dir=None, pps=100, pkt_num=None):
    debug('*** Pcap directory: {}\n'.format(pcap_dir))
    pcap_files = [f for f in listdir(pcap_dir) if isfile(join(pcap_dir, f))]
    pcap_files.sort()

    ingress_hosts = [host for host in net.hosts if not host.name.startswith('pe')]
    procs = {host.name: {'host': host, 'proc': None, 'pcap': None} for host in ingress_hosts}

    def start_on_host(host, pcap_file):
        pcap_file_path = join(pcap_dir, pcap_file)
        assertIsFile(pcap_file_path)
        cmd = f'tcpreplay -i {host.defaultIntf()} --pps {pps}'
        if pkt_num:
            cmd += f' --limit {pkt_num}'
        cmd += f' {pcap_file_path}'
        return host.popen(cmd)

    # Seed initial runs up to the number of hosts
    to_assign = pcap_files[:]
    for host in ingress_hosts:
        if not to_assign:
            break
        file = to_assign.pop(0)
        procs[host.name]['pcap'] = file
        procs[host.name]['proc'] = start_on_host(host, file)

    while True:
        # Assign new work to any host that finished
        for name, s in procs.items():
            p = s['proc']
            if p is not None and p.poll() is not None:
                # Finished current pcap
                s['proc'] = None
                s['pcap'] = None
            if s['proc'] is None and to_assign:
                next_file = to_assign.pop(0)
                s['pcap'] = next_file
                s['proc'] = start_on_host(s['host'], next_file)

        # Build single-line status with running and pending names
        running = [f"{s['host'].name}:{s['pcap']}" for s in procs.values() if s['proc'] is not None]
        pending = to_assign  # remaining filenames
        info(f"  running: {len(running)}, pending: {len(pending)}\r")

        # Exit when no processes are running and nothing is pending
        if not pending and all(s['proc'] is None for s in procs.values()):
            break

        sleep(0.5)

class DuneCLI(CLI):
    def do_toniot_test(self, line):
        """Run tcpreplay on all ingress hosts with one pcap per host.
           Usage: toniot_test [pcap_dir (default: utils/experiment_pcaps)] [pps (default: 100)]
        """
        args = line.split()
        if len(args) == 0:
            pcap_dir = 'utils/experiment_pcaps'
        else:
            pcap_dir = args[0]

        if not isdir(pcap_dir):
            info(f"Error: pcap directory '{pcap_dir}' not found\n")
            return

        try:
            pps = int(args[1]) if len(args) > 1 else 100
        except ValueError:
            info("Error: pps must be an integer\n")
            return

        info("*** Starting traffic injection\n")
        injectPcaps(self.mn, pcap_dir, pps=pps)

    def do_linear_toniot_test(self, line):
        """Run tcpreplay of a single pcap on a specific host.
           Usage: linear_toniot_test <host> <pcap> [pps]
        """
        args = line.split()
        if len(args) < 2:
            info("Usage: linear_toniot_test <host> <pcap> [pps]\n")
            return

        hostName, pcap = args[0], args[1]
        try:
            pps = int(args[2]) if len(args) > 2 else 100
        except ValueError:
            info("Error: pps must be an integer\n")
            return

        if hostName not in [h.name for h in self.mn.hosts]:
            info(f"Error: host '{hostName}' not found\n")
            return

        if not isfile(pcap):
            alt = join('utils/experiment_pcaps', pcap)
            if isfile(alt):
                pcap = alt
            else:
                info(f"Error: pcap file '{pcap}' not found\n")
                return

        info(f"*** host: {hostName}\n")
        info(f"*** pcap: {pcap}\n")
        info(f"*** pps: {pps}\n")

        host = self.mn.get(hostName)
        cmd = f'tcpreplay -i {host.defaultIntf()} --pps {pps} {pcap}'
        info(f'  {host.name}: {cmd}\n')
        host.cmd(cmd)


def injectParallelTraffic(net):
    pcap_dir = getattr(net.topo, 'test_pcap_dir', 'utils/experiment_pcaps')
    pps = getattr(net.topo, 'test_pps', 100)
    pkt_num = getattr(net.topo, 'pkt_num', None)

    injectPcaps(net, pcap_dir, pps=pps, pkt_num=pkt_num)
    info('*** All replays finished. Waiting for controller to finish.\n')

def injectLinearTraffic(net):
    pcap = getattr(net.topo, 'test_pcap', '/nas_storage/shared/MetaCom/data/edited_nopayload/ToN_IoT_test.pcap')
    pps = getattr(net.topo, 'test_pps', 100)
    pkt_num = getattr(net.topo, 'pkt_num', None)
    hostName = 'p0_h0_0'


    info(f"*** host: {hostName}\n")
    info(f"*** pcap: {pcap}\n")
    info(f"*** pps: {pps}\n")

    host = net.get(hostName)
    cmd = f'tcpreplay -i {host.defaultIntf()} --pps {pps}'
    cmd += f' --limit {pkt_num}' if pkt_num else ''
    cmd += f' {pcap}'
    info(f'  {host.name}: {cmd}\n')
    host.cmd(cmd)




# Override the default CLI class globally
CLI = DuneCLI


tests = { 'tonfattree': injectParallelTraffic,
          'tonlinear': injectLinearTraffic}


topos = { 'dunejson' : DuneJsonTopo,
          'dunefattree': DuneFatTree}
