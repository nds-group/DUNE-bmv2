from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import info
from abc import ABC, abstractmethod

from time import sleep
from os import listdir
from os.path import isfile, isdir, join
import json
import networkx as nx
import pulp
import itertools

from pprint import pprint

def assertIsFile(path):
    assert isfile(path), path + ' was not found or is a directory'


def assertIsDir(path):
    assert isdir(path), path + ' was not found or is a file'


def loadJsonFile(path):
    with open(path, 'r') as file:
        return json.load(file)


class Dune(Topo, ABC):
    def assignModels(self):
        G = nx.Graph()
        G.add_nodes_from(self.topo['switches'])
        G.add_nodes_from(self.topo['hosts'])
        G.add_edges_from(self.topo['links'])

        # Minimisation problem
        ilp = pulp.LpProblem('AssignModels', pulp.LpMinimize)

        # Deployment variables
        X = {}
        for sw in self.topo['switches']:
            X[sw] = {}
            for m in self.models:
                X[sw][m] = pulp.LpVariable(f'x_{sw}_{m}', cat='Binary')

        # Adding the objective function
        ilp += pulp.lpSum(X)

        if self.__class__.__name__ == 'DuneFatTree':
            paths = list(self.topo['paths'].values())
            paths = [list(filter(lambda node: node in self.topo['switches'], path)) for path in paths]
        else:
            # Creating paths
            pairs = itertools.combinations(self.topo['hosts'], 2)
            paths = []
            for h1, h2 in pairs:
                for path in nx.all_simple_paths(G, h1, h2):
                    sw_in_path = list(filter(lambda node: node in self.topo['switches'], path))
                    paths.append(sw_in_path)


        # Integrity constraints :
        # For each path, one of each model must appear in a switch in the path
        for path in paths:
            for m in self.models:
                expr = pulp.LpAffineExpression()
                for sw in path:
                    expr.addInPlace(X[sw][m], 1)
                ilp += expr >= 1

        # Dependency constraints :
        # For each path, if a model is deployed in a switch and has a dependency
        # then the dependency must apprear earlier in the path
        for path in paths:
            for m in self.models:
                prev = self.models[m]['previous']
                if prev is not None:
                    accumulator = [path[:i + 1] for i in range(len(path))]
                    for sws in accumulator:
                        current_model_switch = sws.pop()
                        expr = pulp.LpAffineExpression()
                        for sw in sws:
                            expr.addInPlace(X[sw][prev], 1)
                        ilp += expr >= X[current_model_switch][m]

        ilp.solve()
        assert ilp.status == pulp.constants.LpStatusOptimal, 'ILP could not find a solution'
        self.model_assignment = {}
        #TODO log the results
        for sw in self.topo['switches']:
            self.model_assignment[sw] = None
            for m in self.models:
                if X[sw][m].varValue == 1:
                    assert self.model_assignment[sw] is None, 'A switch received more than one model'
                    self.model_assignment[sw] = self.models[m]
            if self.model_assignment[sw] is None:
                self.model_assignment[sw] = { 'p4': 'no_inference' }

    @abstractmethod
    def set_topo(self, **kwargs):
        """
        Set the topology for the Dune instance.
        This method should be implemented by subclasses to define how the topology is set.
        """
        pass


    def build(self, models, models_dir, objects_dir, log_dir, pcap_dir, **kwargs):
        assertIsFile(models)
        assertIsDir(models_dir)
        assertIsDir(objects_dir)
        assertIsDir(log_dir)
        assertIsDir(pcap_dir)

        self.set_topo(**kwargs)
        assert self.topo
        self.models = loadJsonFile(models)
        self.models_dir = models_dir
        self.objects_dir = objects_dir
        self.log_dir = log_dir
        self.pcap_dir = pcap_dir

        for host in self.topo['hosts']:
            self.addHost(host)

        self.assignModels()
        for sw in self.topo['switches']:
            self.addSwitch(
                    sw,
                    model_config=self.model_assignment[sw],
                    model_dir=self.models_dir,
                    objects_dir=self.objects_dir,
                    log_dir=self.log_dir,
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
        topo = {
            'switches': [],
            'hosts': [],
            'links': [],
            'paths': {}
        }
        egress_hosts_per_leaf = pods
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

        # Create a matrix of egress hosts indexed by [leaf][host] => 'podegress_host{leaf_idx}_{host_idx}'
        egress_host_matrix = [
            [f'pe_h{leaf_idx}_{host_idx}' for host_idx in range(egress_hosts_per_leaf)]
            for leaf_idx in range(leafs)
        ]

        # Track how many total hosts per pod
        total_hosts_per_pod = leafs * hosts_per_leaf

        # Flatten column-wise across pods: group by host position, not by pod
        # For each host_index in the pod (0..N), assign corresponding egress host [i][j]
        for host_pos in range(total_hosts_per_pod):
            egress_leaf_idx = host_pos % leafs
            egress_host_idx = host_pos // leafs

            # Defensive check
            if egress_host_idx >= hosts_per_leaf:
                raise RuntimeError("Not enough egress hosts to assign uniquely")

            dst_leaf = f'pe_l{egress_leaf_idx}'
            dst_host = egress_host_matrix[egress_leaf_idx][egress_host_idx]

            for pod_idx in range(pods):
                # Compute leaf and host index in current pod
                leaf_idx = host_pos // hosts_per_leaf
                host_idx = host_pos % hosts_per_leaf

                # Defensive check
                if leaf_idx >= leafs:
                    continue  # in case pods have fewer hosts

                src_host = f'p{pod_idx}_h{leaf_idx}_{host_idx}'
                src_leaf = f'p{pod_idx}_l{leaf_idx}'

                # Balanced  spine selection
                spine_idx = (path_id -  1) % spines
                super_spine_idx = (path_id -  1) % super_spines
                spine = f'p{pod_idx}_s{spine_idx}'
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

        with open('configs/topos/fattreetopo.json', 'w') as f:
            json.dump(topo, f)
        self.topo = topo

def injectTonPcap(net):
    pps = 1000
    pcap_dir = 'utils/merged_pcaps'
    pcap_files = [f for f in listdir(pcap_dir) if isfile(join(pcap_dir, f))]
    ingress_hosts = [host for host in net.hosts if not host.name.startswith('pe')]
    procs = {}

    info('*** Starting tcpreplay on ingress hosts\n')
    for host, pcap_file in zip(ingress_hosts, pcap_files):
        pcap_file_path = join(pcap_dir, pcap_file)
        assertIsFile(pcap_file_path)
        cmd = f'tcpreplay -i {host.defaultIntf()} -t {pcap_file_path}'
        info(f'  {host.name}: {cmd}\n')
        procs[host.name] = host.popen(cmd)
        info('\n')

    while True:
        still_running = [name for name, p in procs.items() if p.poll() is None]
        if not still_running:
            break
        info(f'  still running: {still_running}\n')
        sleep(0.5)

    info('*** All replays finished\n')
    CLI(net)





tests = { 'tonpcap': injectTonPcap }


topos = { 'dunejson' : DuneJsonTopo,
          'dunefattree': DuneFatTree}
