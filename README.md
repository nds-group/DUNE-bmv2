# How to run
To run DUNE in the Mininet environment, you can use the provided `Makefile`. This file contains all the necessary commands to compile the P4 programs, build the parameter strings, and start the Mininet environment. It also includes test targets to run experiments and collect results.


## Quick start

- Run the topology:
  - make run
- Run the fattree test workflow:
  - make run-test
- Run the linear-topology test workflow:
  - make run-linear-test

No need to run make clean before make run, make run-test, or make run-linear-test. These rebuild as needed and create missing run directories automatically.

## Targets

- run
  - Builds required artifacts (if out of date) and launches BMv2/Mininet with the fattree topology and your config.
- run-test
  - Same as run, then executes the fattree test (tonfattree), processes pcaps, computes scores, and archives results.
- run-linear-test
  - Same as run, but forces a linear topology by overriding fattree parameters:
    - Uses TOPO_ARGS_LINEAR (1 super spine, 1 pod, 1 spine, 1 leaf, 1 host).
    - Runs the linear test (tonlinear), then processes pcaps, computes scores, and archives results.
- results
  - Post-processes pcaps, computes scores (vs. ground truth), and creates an experiment tarball.
- stop
  - Cleans Mininet state (mn -c).
- clean
  - Removes run artifacts (logs/, pcaps/), but keeps compiled P4 artifacts.
- clean-all
  - Also removes compiled artifacts (p4objects/) and result files.

## Configurable variables (override on the make command line)

- TEST_PPS: Packet rate for tests (default 100)
  - Example: make TEST_PPS=1000 run-test
- PKT_NUM: Total packets to send (empty by default)
  - Example: make PKT_NUM=50000 run-test
- LOG_LEVEL: BMv2/Mininet log level (default INFO)
  - Example: make LOG_LEVEL=DEBUG run
- MODELS, MODELS_DIR: Model configuration and directory (defaults in Makefile)

## Artifacts and outputs

- Compiled P4: p4objects/*.json (+ p4info files)
- Logs: logs/ (mn.log and controller/switch logs)
  - *WARNING*: logs can grow large, especially with DEBUG log level. Make sure to clean them up periodically.
- Pcaps:
  - Fattree runs: pcaps/
  - Linear runs: linear_pcaps/ (per-test pcaps), plus combined results in pcaps/combined.csv
- Results:
  - results_$(TEST_PPS).txt (scores)
  - experiment_$(TEST_PPS).tar.gz (archive of logs/ and pcaps/ plus results)

## Typical workflows

- Fresh run after a crash or stale Mininet state:
  - make stop
  - make run
- Rerun tests from a clean runtime state (keep compiled artifacts):
  - make clean
  - make run-test
- Run linear-topology tests:
  - make run-linear-test
- Force complete rebuild of P4/BMv2 artifacts:
  - make clean-all
  - make run

## Troubleshooting

- Interfaces/namespaces already exist or Mininet refuses to start:
  - make stop
- Logs/pcaps contain old data:
  - make clean
- Unexpected behavior after changing P4 or pipeline configuration:
  - make clean-all
  - make run
### Further debugging
To debug the execution of the Mininet network, controller and test execution, you can inspect the logs in the `logs/` directory. You can control the log level by modifying the `LOG_LEVEL` variable in the Makefile. The available log levels are `DEBUG`, `INFO`, `WARNING`, `ERROR`, and `CRITICAL`.
The controller will log its output to `logs/controller.log`. The controller will start a thread to control each switch in the Mininet network, and each thread will log its output to `logs/c_<switch_id>.log`. Additionally, each switch will log its output to `logs/<switch_id>.log` (Bmv2 output). Finally, the `populate_<switch_id>_tables.log` files will contain the output of the `convert_RF_and_populate_tables.py`, and `populate_forwarding_tables.py` script for each switch. Here you will be able to find out whether the switch is running an inference model or not, and whether the tables were populated correctly.

## Running interactively
```bash
make run
```
In the Mininet CLI, use the custom commands provided by the DuneCLI:

- toniot_test [pcap_dir] [pps]
  - Replays one pcap per ingress host in parallel.
  - Defaults: pcap_dir=utils/experiment_pcaps, pps=100
  - Example:
    ```bash
    toniot_test utils/experiment_pcaps 200
    ```

- linear_toniot_test <host> <pcap> [pps]
  - Replays a single pcap on a specific host.
  - <pcap> can be an absolute path or a file inside utils/experiment_pcaps.
  - Example (basename resolved under utils/experiment_pcaps):
    ```bash
    linear_toniot_test p0_h0_0 TON-IOT_1.pcap 100
    ```
Once the pcap is replayed successfully, you can issue `quit` or `CTRL-D` to tear-down the mininet environment.
You can generate results using the `make results` target as described above.

---
# Project Structure
The project is organized as follows:
```
.
├── configs
│   ├── models
│   │   └── ton.json
│   └── topos
│       ├── fattreetopo.json
│       └── topo.json
├── controller.py
├── convert_RF_and_populate_tables.py
├── dune.lua
├── Makefile
├── mininet
│   ├── dune.py
│   └── p4
│       ├── link.py
│       └── node.py
├── models
│   └── ton
│       ├── ToN_IoT_ClID0_T3_F5_L41_N4_With_Others.sav
│       ├── ToN_IoT_ClID1_T1_F5_L41_N2_With_Others.sav
│       ├── ToN_IoT_ClID2_T1_F6_L85_N3_With_Others.sav
│       └── ToN_IoT_ClID3_T1_F12_L129_N3_With_Others.sav
├── p4include
│   ├── dune_compute_checksum.p4
│   ├── dune_egress_deparser.p4
│   ├── dune_egress.p4
│   ├── dune_headers.p4
│   ├── dune_inference.p4
│   ├── dune_ingress.p4
│   ├── dune_ingress_parser.p4
│   ├── dune_verify_checksum.p4
│   └── network_headers.p4
├── p4sources
│   ├── no_inference.p4
│   ├── template
│   ├── ton_iot_m1.p4
│   ├── ton_iot_m2.p4
│   ├── ton_iot_m3.p4
│   ├── ton_iot_m4.p4
│   └── TON_IOT.md
├── populate_forwarding_tables.py
├── README.md
├── requirements.txt
├── upload_p4prog_to_switch.py
├── logs
├── pcaps
└── utils
    ├── params.ini
    ├── prepare_pcap_traces.py
    └── process_result_pcaps.sh

```
## Critical Files
- `controller.py`: The main controller script for managing the Mininet switches.
- `Makefile`: Central script to build and run the project. It compiles the P4 programs, builds the parameter strings, and starts the Mininet environment.
- `mininet/`: Contains the custom Mininet classes for creating a `simple_switch_grpc`-based network that supports DUNE-based inference models.
  - `dune.py`: Main script to set up the topologies and test, i.e., traffic injection patters.
  - `p4/`: Contains custom mininet classes for handling links and p4-based switches.
- `p4include/`: Contains P4 header files and definitions used in the project. You should not need to modify these files.
- `p4sources/`: Contains the P4 source files:
  - `no_inference.p4`: A P4 program without inference capabilities.
  - `template`: A template for creating new P4 programs. You should use this as a starting point for new P4 programs.
  - `ton_iot_m*.p4`: P4 programs for different models of the ToN IoT dataset.
  - `TON_IOT.md`: Documentation for the ToN IoT dataset.
- `utils/`:
  - `prepare_pcap_traces.py`: Script to prepare PCAP traces for being injected in the Mininet topo.
  - `process_result_pcaps.sh`: Script to process the result PCAPs generated by the Mininet tests.   

## Output Files
- `logs/`: Contains the logs generated by the controller and switches during the execution of the Mininet tests.
- `pcaps/`: Contains the PCAP files generated by each switch in the Mininet network. Each file is named according to the switch and port, e.g., `pe_l0-eth5_out.pcap` for the output of the first leaf switch from the egress pod on the fifth port.

## Advanced Usage Files
- `configs/`: Contains configuration files for models and topologies.
- `convert_RF_and_populate_tables.py`: Script to convert previously pickled RF models into table data, and populate tables.
- `dune.lua`: dissector script to help Wireshark parse the Dune protocol.
- `models/`: Contains the trained models used for inference.
- `populate_forwarding_tables.py`: Script to populate the forwarding tables (not related to inference).
- `upload_p4prog_to_switch.py`: Script to upload P4 programs to the switch.
- `utils/`:
  - `params.ini`: Configuration file for the `prepare_pcap_traces.py` script.
