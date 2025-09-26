from dune.custom_topo import assignModels, build_fattree_topo, loadJsonFile
import argparse
import networkx as nx
import itertools



def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("-s", "--spines", default=2, type=int)
    parser.add_argument("-l", "--leafs", default=2, type=int)
    parser.add_argument("-p", "--pods", default=2, type=int)
    parser.add_argument("-ss", "--super-spines", default=1, type=int)
    parser.add_argument("-x", "--hosts-per-leaf", default=1, type=int)

    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = parse_args()

    models = loadJsonFile("configs/models/ton.json")

    topo = build_fattree_topo(
            spines=args.spines,
            leafs=args.leafs,
            pods=args.pods,
            #hosts_per_leaf=args.leafs, # to produce all simple paths between leafs
            hosts_per_leaf=args.hosts_per_leaf,
            super_spines=args.super_spines
    )

    # G = nx.Graph()
    # G.add_nodes_from(topo['switches'])
    # G.add_nodes_from(topo['hosts'])
    # G.add_edges_from(topo['links'])

    # pairs = itertools.combinations(topo['hosts'], 2)
    # paths = {}
    # for idx, (h1, h2) in enumerate(pairs):
    #     for path in nx.all_simple_paths(G, h1, h2):
    #         sw_in_path = list(filter(lambda node: node in topo['switches'], path))
    #         paths[idx]=sw_in_path
    # topo['paths'] = paths
    # print(topo['switches'])

    res = assignModels(topo, models, topo["paths"], pulp_msg=0)
    nodes_no_inference = sum(1 for v in res.values() if v.get('p4') == 'no_inference')
    nodes_inference = sum(1 for v in res.values() if v.get('p4') != 'no_inference')

    paths = list(topo['paths'].values())
    paths = [list(filter(lambda node: node in topo['switches'], path)) for path in paths]

    print(f"Paths: {len(paths)}")
    unique_paths = set(tuple(path) for path in paths)
    print(f"Unique paths: {len(unique_paths)}")
    # for path in unique_paths:
    #   print(f"\t {path}")
    print(f"Nodes with inference: {nodes_inference}")
    print(f"Nodes without inference: {nodes_no_inference}")
