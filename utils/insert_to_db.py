import sqlite3
import argparse

from populate_db import parse_results_file, parse_filename, create_tables

conn = sqlite3.connect("experiments.db")
c = conn.cursor()

def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--file", required=True)
    parser.add_argument("--archive", required=True)

    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = parse_args()

    topo = parse_filename(args.file)
    collision_count, metrics_dict, macro, weighted, micro = parse_results_file(args.file)

    create_tables(c)

    # insert into experiments
    c.execute("""INSERT OR IGNORE INTO experiments
        (result_file, experiment_file, pods, superspines, spines, leafs, hosts_per_leaf,
         rate_pps, collision_count, macro_f1, weighted_f1, micro_f1)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (args.file, args.archive, topo["pods"], topo["superspines"], topo["spines"],
         topo["leafs"], topo["hosts_per_leaf"], topo["rate_pps"],
         collision_count, macro, weighted, micro))

    exp_id = c.lastrowid or c.execute(
        "SELECT id FROM experiments WHERE result_file=?", (args.file,)
    ).fetchone()[0]

    # insert per-class metrics
    for label, vals in metrics_dict.items():
        c.execute("""INSERT INTO metrics (experiment_id, label, f1, precision, recall, support)
                     VALUES (?, ?, ?, ?, ?, ?)""",
                  (exp_id, label, vals["f1-score"], vals["precision"],
                   vals["recall"], vals["support"]))

    conn.commit()
    conn.close()
