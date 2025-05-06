#!/usr/bin/env python3

import p4runtime_sh.shell as p4
import numpy as np
import pandas as pd
import warnings
from statistics import mode
from ipaddress import ip_address
import argparse

pd.options.mode.chained_assignment = None  # default='warn'
warnings.filterwarnings("ignore")


## definition of useful functions
## gets all splits and conditions
def get_splits(forest, feature_names):
    data = []
    # generate dataframe with all thresholds and features
    for t in range(len(forest.estimators_)):
        clf = forest[t]
        n_nodes = clf.tree_.node_count
        features = [feature_names[i] for i in clf.tree_.feature]
        for i in range(0, n_nodes):
            node_id = i
            left_child_id = clf.tree_.children_left[i]
            right_child_id = clf.tree_.children_right[i]
            threshold = clf.tree_.threshold[i]
            feature = features[i]
            if threshold != -2.0:
                data.append(
                    [t, node_id, left_child_id, right_child_id, threshold, feature]
                )
    data = pd.DataFrame(data)
    data.columns = ["Tree", "NodeID", "LeftID", "RightID", "Threshold", "Feature"]
    return data


## gets the feature table of each feature from the splits
def get_feature_table(splits_data, feature_name):
    feature_data = splits_data[splits_data["Feature"] == feature_name]
    feature_data = feature_data.sort_values(by="Threshold")
    feature_data = feature_data.reset_index(drop=True)
    ##
    # feature_data["Threshold"] = (feature_data["Threshold"]).astype(int)
    feature_data["Threshold"] = feature_data["Threshold"].astype(int)
    ##
    code_table = pd.DataFrame()
    code_table["Threshold"] = feature_data["Threshold"]
    # print(feature_data)
    # create a column for each split in each tree
    for tree_id, node in zip(list(feature_data["Tree"]), list(feature_data["NodeID"])):
        colname = "s" + str(tree_id) + "_" + str(node)
        code_table[colname] = np.where(
            (
                code_table["Threshold"]
                <= feature_data[
                    (feature_data["NodeID"] == node) & (feature_data["Tree"] == tree_id)
                ]["Threshold"].values[0]
            ),
            0,
            1,
        )
    # add a row to represent the values above the largest threshold
    temp = [max(code_table["Threshold"]) + 1]
    temp.extend(list([1] * (len(code_table.columns) - 1)))
    code_table.loc[len(code_table)] = temp
    code_table = code_table.drop_duplicates(subset=["Threshold"])
    code_table = code_table.reset_index(drop=True)
    return code_table


## get feature tables with ranges and codes only
def get_feature_codes_with_ranges(feature_table, num_of_trees):
    Codes = pd.DataFrame()
    for tree_id in range(num_of_trees):
        colname = "code" + str(tree_id)
        Codes[colname] = feature_table[
            feature_table[
                [
                    col
                    for col in feature_table.columns
                    if ("s" + str(tree_id) + "_") in col
                ]
            ].columns[0:]
        ].apply(lambda x: "".join(x.dropna().astype(str)), axis=1)
        Codes[colname] = ["0b" + x for x in Codes[colname]]
    feature_table["Range"] = [0] * len(feature_table)
    feature_table["Range"].loc[0] = "0," + str(feature_table["Threshold"].loc[0])
    for i in range(1, len(feature_table)):
        if i == (len(feature_table)) - 1:
            feature_table["Range"].loc[i] = (
                str(feature_table["Threshold"].loc[i])
                + ","
                + str(feature_table["Threshold"].loc[i])
            )
        else:
            feature_table["Range"].loc[i] = (
                str(feature_table["Threshold"].loc[i - 1] + 1)
                + ","
                + str(feature_table["Threshold"].loc[i])
            )
    Ranges = feature_table["Range"]
    return Ranges, Codes


## get list of splits crossed to get to leaves
def retrieve_branches(estimator):
    number_nodes = estimator.tree_.node_count
    children_left_list = estimator.tree_.children_left
    children_right_list = estimator.tree_.children_right
    feature = estimator.tree_.feature
    threshold = estimator.tree_.threshold
    # Calculate if a node is a leaf
    is_leaves_list = [
        (False if cl != cr else True)
        for cl, cr in zip(children_left_list, children_right_list)
    ]
    # Store the branches paths
    paths = []
    for i in range(number_nodes):
        if is_leaves_list[i]:
            # Search leaf node in previous paths
            end_node = [path[-1] for path in paths]
            # If it is a leave node yield the path
            if i in end_node:
                output = paths.pop(np.argwhere(i == np.array(end_node))[0][0])
                yield output
        else:
            # Origin and end nodes
            origin, end_l, end_r = i, children_left_list[i], children_right_list[i]
            # Iterate over previous paths to add nodes
            for index, path in enumerate(paths):
                if origin == path[-1]:
                    paths[index] = path + [end_l]
                    paths.append(path + [end_r])
            # Initialize path in first iteration
            if i == 0:
                paths.append([i, children_left_list[i]])
                paths.append([i, children_right_list[i]])


## get classes and certainties
def get_classes(clf):
    leaves = []
    classes = []
    certainties = []
    for branch in list(retrieve_branches(clf)):
        leaves.append(branch[-1])
    for leaf in leaves:
        if clf.tree_.n_outputs == 1:
            value = clf.tree_.value[leaf][0]
        else:
            value = clf.tree_.value[leaf].T[0]
        class_name = np.argmax(value)
        certainty = int(round(max(value) / sum(value), 2) * 100)
        classes.append(class_name)
        certainties.append(certainty)
    return classes, certainties


## get the codes corresponging to the branches followed
def get_leaf_paths(clf):
    depth = clf.max_depth
    branch_codes = []
    for branch in list(retrieve_branches(clf)):
        code = [0] * len(branch)
        for i in range(1, len(branch)):
            if branch[i] == clf.tree_.children_left[branch[i - 1]]:
                code[i] = 0
            elif branch[i] == clf.tree_.children_right[branch[i - 1]]:
                code[i] = 1
        branch_codes.append(list(code[1:]))
    return branch_codes


## get the order of the splits to enable code generation
def get_order_of_splits(data, feature_names):
    splits_order = []
    for feature_name in feature_names:
        feature_data = data[data.iloc[:, 4] == feature_name]
        feature_data = feature_data.sort_values(by="Threshold")
        for node in list(feature_data.iloc[:, 0]):
            splits_order.append(node)
    return splits_order


def get_splits_per_tree(clf, feature_names):
    data = []
    n_nodes = clf.tree_.node_count
    # set feature names
    features = [feature_names[i] for i in clf.tree_.feature]
    # generate dataframe with all thresholds and features
    for i in range(0, n_nodes):
        node_id = i
        left_child_id = clf.tree_.children_left[i]
        right_child_id = clf.tree_.children_right[i]
        threshold = clf.tree_.threshold[i]
        feature = features[i]
        if threshold != -2.0:
            data.append([node_id, left_child_id, right_child_id, threshold, feature])
    data = pd.DataFrame(data)
    data.columns = ["NodeID", "LeftID", "RightID", "Threshold", "Feature"]
    return data


## Get codes and masks
def get_codes_and_masks(clf, feature_names):
    splits = get_order_of_splits(get_splits_per_tree(clf, feature_names), feature_names)
    depth = clf.max_depth
    codes = []
    masks = []
    for branch, coded in zip(list(retrieve_branches(clf)), get_leaf_paths(clf)):
        code = [0] * len(splits)
        mask = [0] * len(splits)
        for index, split in enumerate(splits):
            if split in branch:
                mask[index] = 1
        masks.append(mask)
        codes.append(code)
    masks = pd.DataFrame(masks)
    masks["Mask"] = masks[masks.columns[0:]].apply(
        lambda x: "".join(x.dropna().astype(str)), axis=1
    )
    masks = ["0b" + x for x in masks["Mask"]]
    indices = range(0, len(splits))
    temp = pd.DataFrame(columns=["split", "index"], dtype=object)
    temp["split"] = splits
    temp["index"] = indices
    final_codes = []
    for branch, code, coded in zip(
        list(retrieve_branches(clf)), codes, get_leaf_paths(clf)
    ):
        indices_to_use = temp[temp["split"].isin(branch)].sort_values(by="split")[
            "index"
        ]
        for i, j in zip(range(0, len(coded)), list(indices_to_use)):
            code[j] = coded[i]
        final_codes.append(code)
    final_codes = pd.DataFrame(final_codes)
    final_codes["Code"] = final_codes[final_codes.columns[0:]].apply(
        lambda x: "".join(x.dropna().astype(str)), axis=1
    )
    final_codes = ["0b" + x for x in final_codes["Code"]]
    return final_codes, masks


## End of model manipulation ##


def extractKBits(num):
    # convert number into binary first
    binary = bin(int(num))
    # remove first two characters
    binary = binary[2:].zfill(30)
    # extract required bits
    num_bin = str("0b") + binary[0:20]
    num_dec = int(num_bin, 2)
    return num_dec


def upload_model(model, feature_offset, code_table_offset, index):
    # import and get entries from trained models ##
    clf = pd.read_pickle(model)

    # list the feature names
    feature_names = clf.feature_names_in_
    print(feature_names)

    tree_code_sizes = [[] for _ in range(len(clf.estimators_))]

    for fea in range(0, len(feature_names)):
        Ranges, Codes = get_feature_codes_with_ranges(
            get_feature_table(get_splits(clf, feature_names), feature_names[fea]),
            len(clf.estimators_),
        )
        for i, ran in enumerate(Ranges):
            entry = p4.TableEntry(f"MyIngress.table_feature{fea + feature_offset}")(
                action=f"MyIngress.SetCode{fea + feature_offset}"
            )
            start = ran.split(",")[0]
            end = (
                # Trickery to get the upper power of two for
                # for the last range
                2 ** (int(ran.split(",")[1]).bit_length()) - 1
                if ran == Ranges[len(Ranges) - 1]
                else ran.split(",")[1]
            )
            entry.match[f"feature{fea + feature_offset}"] = f"{start}..{end}"
            for j in range(0, len(clf.estimators_)):
                entry.action[f"code{j}"] = str(Codes.iloc[i, j])
            entry.priority = 1
            entry.insert()
        for j in range(0, len(clf.estimators_)):
            tree_code_sizes[j].append(len(Codes.iloc[0, j]) - 2)

    print(tree_code_sizes)

    for tree_id in range(0, len(clf.estimators_)):
        Final_Codes, Final_Masks = get_codes_and_masks(
            clf.estimators_[tree_id], feature_names
        )
        Classe, Certain = get_classes(clf.estimators_[tree_id])
        print("!!!!!!!!!!!!!!!!!!!!!! DEBUG !!!!!!!!!!!!!!!!!!!!!!")
        print("Final_Codes unique: ", len(np.unique(Final_Codes)))
        print("Final_Codes Length: ", len(Final_Codes))
        print("Final_Masks unique: ", len(np.unique(Final_Masks)))
        print("Final_Codes Length: ", len(Final_Masks))
        # print('Classe Length: ', len(Classe.unique()))
        for cod, mas, cla, cer in zip(Final_Codes, Final_Masks, Classe, Certain):
            entry = p4.TableEntry(f"MyIngress.code_table{tree_id+code_table_offset}")(
                action=f"MyIngress.SetClass{tree_id+code_table_offset}"
            )
            start = 0
            cod = str(cod).removeprefix("0b")
            mas = str(mas).removeprefix("0b")
            for i, size in enumerate(tree_code_sizes[tree_id]):
                code = f"0b{cod[start : start + size]}"
                mask = f"0b{mas[start : start + size]}"
                start += size
                if int(mask, base=0):  # Ignore the "Don't care" mask
                    entry.match[f"meta.codeword{tree_id+code_table_offset}_{i}"] = f"{code}&&&{mask}"
            entry.action["classe"] = str(cla + 1)
            entry.priority = 1
            entry.insert()

    if index == 0:
        for i in range(1, 3):
            for j in range(1, 3):
                for k in range(1, 3):
                    if (i != j) & (j != k) & (i != k):
                        pass
                    else:
                        entry = p4.TableEntry("MyIngress.voting_table")(
                            action="MyIngress.set_final_class"
                        )
                        entry.match["meta.class1"] = str(i)
                        entry.match["meta.class2"] = str(j)
                        entry.match["meta.class3"] = str(k)
                        entry.action["class_result"] = str(mode([i, j, k]))
                        entry.insert()

    # TODO
    # # Get 'INFERENCE FORWARDING BLOCK' table entries
    # # Read csv file to get flow 5 tuple ids (src_addr, hdr.ipv4.dst_addr, meta.hdr_srcport, meta.hdr_dstport, hdr.ipv4.protocol, action)
    # # ACTION: Forwarding: 0 Inference: 1
    # flow_id_info = pd.read_csv("model/test_data_flow_packet_counts.csv")
    # flow_id_info = flow_id_info.dropna()
    # flow_id_info = flow_id_info.drop_duplicates(subset=["flow.id"])
    # for index, flow in flow_id_info.iterrows():
    #     flow_id = flow["flow.id"]
    #     id_values = flow_id.split(" ")
    #     # With all tuple elements
    #     try:
    #         entry = p4.TableEntry("MyIngress.flow_action_table")(
    #             action="MyIngress.set_flow_action"
    #         )
    #         entry.match["hdr.ipv4.src_addr"] = str(int(ip_address(id_values[0])))
    #         entry.match["hdr.ipv4.dst_addr"] = str(int(ip_address(id_values[1])))
    #         entry.match["meta.hdr_srcport"] = str(id_values[2])
    #         entry.match["meta.hdr_dstport"] = str(id_values[3])
    #         entry.match["hdr.ipv4.protocol"] = str(id_values[4])
    #         entry.action["f_action"] = "1"
    #         entry.insert()
    #     except:
    #         continue
    return len(feature_names), len(clf.estimators_)


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--p4info", required=True)
    parser.add_argument("--json", required=True)

    parser.add_argument("--models", nargs="+", required=True)
    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    # Connecting to the switch
    p4.setup(
        device_id=0,
        grpc_addr="0.0.0.0:50051",
        election_id=(0, 1),  # (high, low)
        config=p4.FwdPipeConfig(args.p4info, args.json),
        verbose=False,
    )

    np.random.seed(42)

    feature_offset = 0
    code_table_offset = 0
    for index, model in enumerate(args.models):
        len_features, len_code_tables = upload_model(
            model, feature_offset, code_table_offset, index
        )
        feature_offset += len_features
        code_table_offset += len_code_tables

    # Configure digest
    d = p4.DigestEntry("flow_class_digest")
    d.ack_timeout_ns = 1000000000
    d.max_timeout_ns = 1000000000
    d.max_list_size = 100
    d.insert()

    p4.teardown()


if __name__ == "__main__":
    main()
