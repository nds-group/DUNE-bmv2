import os
import re
import sqlite3
import ast

# --- parse filename for topology info ---
def parse_filename(fname):
    m = re.match(r"results_p(\d+)_ss(\d+)_s(\d+)_l(\d+)_h(\d+)_(\d+)pps\.txt", fname)
    if not m:
        raise ValueError(f"Filename {fname} does not match expected pattern")
    return {
        "pods": int(m.group(1)),
        "superspines": int(m.group(2)),
        "spines": int(m.group(3)),
        "leafs": int(m.group(4)),
        "hosts_per_leaf": int(m.group(5)),
        "rate_pps": int(m.group(6)),
    }

# --- parse results file contents ---
def parse_results_file(path):
    with open(path) as f:
        lines = f.readlines()

    # --- 1. First line: collision count ---
    collision_count = None
    if lines:
        m = re.search(r"Collision count:\s*(\d+)", lines[0])
        if m:
            collision_count = int(m.group(1))

    # --- 2. Last line: macro/weighted/micro ---
    macro, weighted, micro = None, None, None
    if lines:
        m = re.search(
            r"Macro=([\d\.e-]+)\s+Weighted=([\d\.e-]+)\s+Micro=([\d\.e-]+)",
            lines[-1]
        )
        if m:
            macro, weighted, micro = map(float, m.groups())

    # --- 3. Remaining lines: the dictionary ---
    dict_lines = lines[1:-1]
    dict_text = "".join(dict_lines).strip()  # join middle lines
    metrics_dict = ast.literal_eval(dict_text)

    return collision_count, metrics_dict, macro, weighted, micro

def parse_mapping(path):
    mapping = {}
    with open(path) as f:
        for line in f:
            results, artifact = line.split(' -> ')
            mapping[results] = artifact
    return mapping

def create_tables(cursor):

    cursor.execute("""CREATE TABLE IF NOT EXISTS experiments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        result_file TEXT UNIQUE,
        experiment_file TEXT,
        pods INTEGER,
        superspines INTEGER,
        spines INTEGER,
        leafs INTEGER,
        hosts_per_leaf INTEGER,
        rate_pps INTEGER,
        collision_count INTEGER,
        macro_f1 REAL,
        weighted_f1 REAL,
        micro_f1 REAL
    )""")

    cursor.execute("""CREATE TABLE IF NOT EXISTS metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        experiment_id INTEGER,
        label TEXT,
        f1 REAL,
        precision REAL,
        recall REAL,
        support REAL,
        FOREIGN KEY (experiment_id) REFERENCES experiments(id)
    )""")

if __name__ == '__main__':
    # --- setup sqlite ---
    conn = sqlite3.connect("experiments.db")
    c = conn.cursor()

    # --- create tables if not existing ---
    create_tables(c)

    mapping = parse_mapping('mapping.txt')

    # --- insert data ---
    for result_file, exp_file in mapping.items():
        topo = parse_filename(result_file)
        collision_count, metrics_dict, macro, weighted, micro = parse_results_file(result_file)

        # insert into experiments
        c.execute("""INSERT OR IGNORE INTO experiments
            (result_file, experiment_file, pods, superspines, spines, leafs, hosts_per_leaf,
             rate_pps, collision_count, macro_f1, weighted_f1, micro_f1)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (result_file, exp_file, topo["pods"], topo["superspines"], topo["spines"],
             topo["leafs"], topo["hosts_per_leaf"], topo["rate_pps"],
             collision_count, macro, weighted, micro))

        exp_id = c.lastrowid or c.execute(
            "SELECT id FROM experiments WHERE result_file=?", (result_file,)
        ).fetchone()[0]

        # insert per-class metrics
        for label, vals in metrics_dict.items():
            c.execute("""INSERT INTO metrics (experiment_id, label, f1, precision, recall, support)
                         VALUES (?, ?, ?, ?, ?, ?)""",
                      (exp_id, label, vals["f1-score"], vals["precision"],
                       vals["recall"], vals["support"]))

    conn.commit()
    conn.close()

