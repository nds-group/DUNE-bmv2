from mininet.topo import Topo
from abc import ABC, abstractmethod

from os.path import isfile, isdir
import json
import networkx as nx
import pulp
import itertools

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
    def set_topo(self, topo):
        """
        Set the topology for the Dune instance.
        This method should be implemented by subclasses to define how the topology is set.
        """
        pass


    def build(self, topo, models, models_dir, objects_dir, log_dir, pcap_dir):
        assertIsFile(topo)
        assertIsFile(models)
        assertIsDir(models_dir)
        assertIsDir(objects_dir)
        assertIsDir(log_dir)
        assertIsDir(pcap_dir)

        self.set_topo(topo)
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
    def set_topo(self, topo):
        self.topo = loadJsonFile(topo)


class DuneFatTree(Dune):
    def set_topo(self, topo, spines=2, leafs=3, hosts_per_leaf=1):
        topo = {
            'switches': [],
            'hosts': [],
            'links': []
        }
        for i in range(spines):
            # Create spine switches
            topo['switches'].append(f'spine{i}')
            # Create DC interconnect hosts
            topo['hosts'].append(f'dc_host{i}')
            for j in range(spines):
                # Connect spines to DC interconnect hosts
                topo['links'].append([f'spine{i}', f'dc_host{j}'])

        for i in range(leafs):
            # Create leaf switches
            topo['switches'].append(f'leaf{i}')
            # Connect leafs to spines
            for j in range(spines):
                topo['links'].append([f'spine{j}', f'leaf{i}'])
            # Create hosts
            for j in range(hosts_per_leaf):
                topo['hosts'].append(f'host{i}_{j}')
                # Connect hosts to leafs
                topo['links'].append([f'leaf{i}', f'host{i}_{j}'])

        self.topo = topo




topos = { 'dunejson' : DuneJsonTopo,
          'dunefattree': DuneFatTree}
