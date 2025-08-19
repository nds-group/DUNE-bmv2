import pandas as pd
import argparse
from pprint import pprint
from sklearn.metrics import classification_report

def compute_classification_report(results_df, ground_truth_df, classes):
    # Build flow id
    results_df['Flow ID'] = (
        results_df['src_ip'].astype(str) + ' ' +
        results_df['dst_ip'].astype(str) + ' ' +
        results_df['src_port'].astype(str) + ' ' +
        results_df['dst_port'].astype(str) + ' ' +
        results_df['transport_proto'].astype(str)
    )
    results_df['class'] = results_df['class'].astype(int)

    # Merge two dataframes and calculate weight per packet
    labeled_results_csv = pd.merge(results_df, ground_truth_df, on=['Flow ID'])

    # Map class names to integer ids (avoids FutureWarning from replace downcasting)
    class_mapping = {cls: i + 1 for i, cls in enumerate(classes)}
    labeled_results_csv = labeled_results_csv[labeled_results_csv['type'].isin(class_mapping)].copy()
    labeled_results_csv['ground_truth'] = labeled_results_csv['type'].map(class_mapping)

    labeled_results_csv['weight'] = 1 / labeled_results_csv['packet_counts']

    # Keep unique (label, ground_truth) pairs in the same order to use in classification report
    unique_df = labeled_results_csv.drop_duplicates(subset=["type", "ground_truth"], keep="first")

    # Classification report (silence UndefinedMetricWarning with zero_division=0)
    c_report = classification_report(
        labeled_results_csv['ground_truth'],
        labeled_results_csv['class'],
        labels=unique_df['ground_truth'],
        target_names=unique_df['type'],
        sample_weight=labeled_results_csv['weight'],
        output_dict=True,
        zero_division=0,
    )
    return c_report


def calculate_score(c_report):
    macro_f1 = c_report['macro avg']['f1-score']
    weighted_f1 = c_report['weighted avg']['f1-score']
    try:
        micro_f1 = c_report['micro avg']['f1-score']
    except KeyError:
        micro_f1 = c_report['accuracy']
    return macro_f1, weighted_f1, micro_f1

def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--results", required=True)
    parser.add_argument("--ground-truth", required=True)

    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = parse_args()

    classes = ['normal', 'ddos', 'ransomware', 'xss', 'scanning', 'injection', 'password']
    results_df = pd.read_csv(args.results)
    ground_truth_df = pd.read_csv(args.ground_truth)

    c_report = compute_classification_report(results_df, ground_truth_df, classes)
    pprint(c_report)

    macro_f1, weighted_f1, micro_f1 = calculate_score(c_report)

    print(f"The score information:   Macro={macro_f1} Weighted={weighted_f1} Micro={micro_f1}")
