import pandas as pd
from sklearn.metrics import classification_report
import warnings
# Filter all warnings
warnings.filterwarnings("ignore")

def calculate_score(results_df, ground_truth_df, classes):
    results_df['Flow ID'] = results_df['src_ip'].astype(str) + ' ' + results_df['dst_ip'].astype(str) + ' ' + results_df['src_port'].astype(str) + ' ' + results_df['dst_port'].astype(str) + ' ' + results_df['transport_proto'].astype(str)
    results_df['class'] = results_df['class'].astype(int)
    # Merge two dataframes and calculate weight per packet
    labeled_results_csv = pd.merge(results_df, ground_truth_df, on=['Flow ID'])
    labeled_results_csv['ground_truth'] = labeled_results_csv['type'].replace(classes, range(1, len(classes)+1))
    labeled_results_csv['weight'] = 1/labeled_results_csv['packet_counts']
    
    # Keep unique (label, ground_truth) pairs in the same order to use in classification report
    unique_df = labeled_results_csv.drop_duplicates(subset=["type", "ground_truth"], keep="first")
    
    # Classification report
    c_report = classification_report(labeled_results_csv['ground_truth'], labeled_results_csv['class'], labels=unique_df['ground_truth'], target_names=unique_df['type'], sample_weight=labeled_results_csv['weight'], output_dict=True)
    print(c_report)
    
    macro_f1 = c_report['macro avg']['f1-score']
    weighted_f1 = c_report['weighted avg']['f1-score']
    try:
        micro_f1 = c_report['micro avg']['f1-score']
    except:
        micro_f1 = c_report['accuracy']
    
    return macro_f1, weighted_f1, micro_f1


if __name__ == "__main__":
    classes = ['normal', 'ddos', 'ransomware', 'xss', 'scanning', 'injection', 'password']
    results_df = pd.read_csv('/home/beyzabutun/shared/combined_100.csv')
    ground_truth_df = pd.read_csv('/home/beyzabutun/shared/ToN-IoT/ToN_IoT_Test_Flow_PktCounts.csv')
    
    macro_f1, weighted_f1, micro_f1 = calculate_score(results_df, ground_truth_df, classes=classes)
    
    print(f"The score information:   Macro={macro_f1} Weighted={weighted_f1} Micro={micro_f1}")