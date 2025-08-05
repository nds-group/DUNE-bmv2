#!/usr/bin/env python3
import subprocess
import sys
import pandas as pd
import configparser
import math
import os
import multiprocessing as mp
from os import path
from multiprocessing import current_process
import configparser
import logging

def merge_with_mergecap(input_files, merged_file):
    """
    Merge the given pcap traces
    """
    cmd = ["mergecap", "-w", merged_file] + input_files
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        sys.exit("Error: mergecap not found. Please install Wireshark.")
    logger.info(f"--> mergecap wrote {merged_file}")
    
def collect_chunked_target_flows(flow_info_df, eliminated_classes, chunksize=500):
    """
        Read flow IDs from a DataFrame, filter out unwanted classes, and split into chunks.

        Parameters
        ----------
        flow_info_df : pandas.DataFrame
            DataFrame containing at least the columns `['Flow ID', 'type']`.
        eliminated_classes : list of str
            Any rows whose `type` is in this list will be excluded.
        chunksize : int, optional
            Maximum number of flow IDs per chunk (default: 500).

        Returns
        -------
        List[List[Tuple[str, str, str, str, str]]]
            A list of chunks; each chunk is a list of 5‑tuples
            `(src, dst, sport, dport, proto_int)`.
    """
    flow_ids = flow_info_df[~flow_info_df['type'].isin(eliminated_classes)]['Flow ID'].to_list()[:]
    target_flows = []
    for c in range(math.ceil(len(flow_ids)/chunksize)):
        temp = []
        for id in flow_ids[c*chunksize:c*chunksize+chunksize]:
            src, dst, sport, dport, proto_int = id.split()
            temp.append((src, dst, sport, dport, proto_int))
        target_flows.append(temp)
        
    return target_flows
    
def _filter_with_tshark(input_pcap, output_folder, output_pcap, flow_ids):
    """
    Use tshark to keep only packets matching one of our target 5‑tuples.
    flow_ids is an iterable of (src, dst, sport, dport, proto_int).
    """
    exprs = []
    for src, dst, sport, dport, pr in flow_ids:
        proto = "tcp" if pr == "6" else "udp"
        fwd = f"{proto} && ip.src=={src} && ip.dst=={dst} && {proto}.srcport=={sport} && {proto}.dstport=={dport}"
        exprs.append(f"({fwd})")
    display_filter = " or ".join(exprs)
    if not display_filter:
        sys.exit("No flow IDs provided")
    cmd = [
        "tshark", "-r", input_pcap,
        "-Y", display_filter,
        "-w", f"{output_folder}/{output_pcap}"
    ]
    subprocess.run(cmd, check=True)
    logger.info(f"--> tshark wrote {output_pcap}")

def run_filter_with_tshark(input_data):
    filename = input_data[0] + "_" + str(input_data[4]) + ".pcap"
    data_generator_obj = input_data[3]
    output_folder = input_data[2]
    input_pcap = input_data[1]
    proc = current_process()
    try:
        logger.info(f"[{proc.name} pid={proc.pid}] ➤ starting chunk #{input_data[4]} ({len(input_data[3])} flows)")
        return _filter_with_tshark(input_pcap, output_folder, filename, data_generator_obj)
    except Exception as e:
        return []
    
def run_filtering(input_pcap, target_flows, consumed_cores, output_folder):  
    """
        Orchestrate parallel `tshark` filtering to keep only target flows.

        Parameters
        ----------
        input_pcap : str
            Path to the pcapng to be filtered.
        target_flows : List[List[Tuple]]
            Chunks of flow‑ID lists as produced by `collect_chunked_target_flows`.
        consumed_cores : int
            Number of worker processes to spawn in the pool.
        output_folder : str
            Directory where per‑chunk filtered pcaps will be written.
    """
    # Filter the pcap by keeping only target traffic   
    os.makedirs(f"{output_folder}", exist_ok=True)
    
    with mp.get_context('fork').Pool(processes=consumed_cores) as pool:
        input_data = [
            ('filtered_ton', input_pcap, output_folder, flow, idx)
            for idx, flow in enumerate(target_flows, start=1)
        ]
        try:
            # issue tasks to the process pool
            pool.imap_unordered(run_filter_with_tshark, input_data, chunksize=5)
            # shutdown the process pool
            pool.close()
        except KeyboardInterrupt:
            pool.terminate()
        # wait for all issued task to complete
        pool.join()

    del pool  

    
def run_splitting(input_pcap, flow_info_df, eliminated_classes, number_of_hosts, output_folder):
    """
        High‑level driver to chunk flows across hosts and filter in parallel.

        Parameters
        ----------
        input_pcap : str
            Path to the source pcap/ng to be split and filtered.
        flow_info_df : pandas.DataFrame
            DataFrame listing all flows (with types) to chunk.
        eliminated_classes : list of str
            Flow types to exclude entirely.
        number_of_hosts : int
            Number of parallel “splits” desired; determines chunk size.
        output_folder : str
            Directory where per‑split pcaps and merged results will be stored.
    """
    # flow_info_df = flow_info_df.sample(frac=1, random_state=42).reset_index(drop=True) # If you want to shuffle flows before splitting
    chunks = collect_chunked_target_flows(flow_info_df, eliminated_classes, chunksize=math.ceil(len(flow_info_df)/number_of_hosts))
    
    os.makedirs(f"{output_folder}", exist_ok=True)
    
    with mp.get_context('fork').Pool(processes=consumed_cores) as pool:
        input_data = [
            (f'{use_case}', input_pcap, output_folder, flow, idx)
            for idx, flow in enumerate(chunks, start=1)
        ]
        try:
            # issue tasks to the process pool
            pool.imap_unordered(run_filter_with_tshark, input_data, chunksize=5)
            # shutdown the process pool
            pool.close()
        except KeyboardInterrupt:
            pool.terminate()
        # wait for all issued task to complete
        pool.join()

    del pool 
    
    
def main():
    
    # RUN ONLY IF you need to filter a big pcap trace to keep only target traffic
    # run_filtering(input_pcap_before_filtering, target_flows, consumed_cores, 'tshark_files')
    
    # RUN to split the test pcap into H number of chunks ---> STORE to output_folder
    run_splitting(input_pcap, flow_info_df, eliminated_classes, number_of_hosts, output_folder)
    
    # RUN ONLY IF you need to merge some pcaps together (number of hosts less than 48 requires merge for ToN-IoT)
    filenames = os.listdir(output_folder)
    os.makedirs(f"merged_pcaps", exist_ok=True)
    file_paths = [f"{output_folder}/{file}" for file in filenames]
    for i in range(0, math.ceil(len(file_paths)/number_of_pcaps_to_merge)):
        merge_with_mergecap(file_paths[i*number_of_pcaps_to_merge:i*number_of_pcaps_to_merge+number_of_pcaps_to_merge], f'merged_pcaps/{use_case}_{i+1}.pcap')
        

if __name__ == "__main__":
    basepath = path.dirname(__file__)
    logging.basicConfig()
    config = configparser.ConfigParser()
    config.read(path.abspath(path.join(basepath,'params.ini')))
    use_case = 'TON-IOT'
    
    log_level = config['DEFAULT']['log_level']
    level = logging.getLevelName(log_level)
    logger = logging.getLogger(use_case)
    logger.setLevel(level)
    
    consumed_cores = int(config[use_case]['consumed_cores'])
    number_of_hosts = int(config[use_case]['number_of_hosts']) # H
    number_of_pcaps_to_merge = int(config[use_case]['number_of_pcaps_to_merge']) # If you need to merge individual pcaps to obtain H number of pcaps at the end
    flow_info_path = config[use_case]['flow_info_path']
    input_pcap_before_filtering = config[use_case]['input_pcap_before_filtering']
    input_pcap = config[use_case]['input_pcap']
    output_folder = config[use_case]['output_folder']
    
    #
    eliminated_classes = ['mitm', 'dos', 'backdoor']
    flow_info_df = pd.read_csv(flow_info_path)
    target_flows = collect_chunked_target_flows(flow_info_df, eliminated_classes, chunksize=500)
    
    raise SystemExit(main())