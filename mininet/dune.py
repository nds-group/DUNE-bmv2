from mininet.topo import Topo

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


class Dune(Topo):
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
            for m in self.topo['models']:
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
        for sw in self.topo['switches']:
            self.model_assignment[sw] = None
            for m in self.models:
                if X[sw][m].varValue == 1:
                    assert self.model_assignment[sw] is None, 'A switch received more than one model'
                    self.model_assignment[sw] = self.models[m]

    def build(self, topo, models, models_dir, log_dir, pcap_dir):
        assertIsFile(topo)
        assertIsFile(models)
        assertIsDir(models_dir)
        assertIsDir(log_dir)
        assertIsDir(pcap_dir)

        self.topo = loadJsonFile(topo)
        self.models = loadJsonFile(models)
        self.models_dir = models_dir
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
                    log_dir=self.log_dir,
                    pcap_dir=self.pcap_dir
                )

        for nodes in self.topo['links']:
            self.addLink(nodes[0], nodes[1])

topos = { 'dune' : Dune }
