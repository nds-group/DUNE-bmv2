# Workflows and Configuration

## Configurable variables (override on the make command line)

- `TEST_PPS`: Packet rate for tests (default 100)
  - Example: `make TEST_PPS=1000 run-test`
- `PKT_NUM`: Total packets to send (empty by default)
  - Example: `make PKT_NUM=50000 run-test`
- `LOG_LEVEL`: BMv2/Mininet log level (default INFO)
  - Example: `make LOG_LEVEL=DEBUG run`
- `MODELS`, `MODELS_DIR`: Model configuration and directory (defaults in Makefile)

## Artifacts and outputs

- Compiled P4: `p4objects/*.json` (+ p4info files)
- Logs: `logs/` (mn.log and controller/switch logs)
  - *WARNING*: logs can grow large, especially with DEBUG log level. Make sure to clean them up periodically.
- Pcaps:
  - Fattree runs: `pcaps/`
  - Linear runs: `linear_pcaps/` (per-test pcaps), plus combined results in `pcaps/combined.csv`
- Results:
  - `results_$(TEST_PPS).txt` (scores)
  - `experiment_$(TEST_PPS).tar.gz` (archive of logs/ and pcaps/ plus results)

## Targets

- `run`
  - Builds required artifacts (if out of date) and launches BMv2/Mininet with the fattree topology and your config.
- `run-test`
  - Same as run, then executes the fattree test (tonfattree), processes pcaps, computes scores, and archives results.
- `run-linear-test`
  - Same as run, but forces a linear topology by overriding fattree parameters:
    - Uses TOPO_ARGS_LINEAR (1 super spine, 1 pod, 1 spine, 1 leaf, 1 host).
    - Runs the linear test (tonlinear), then processes pcaps, computes scores, and archives results.
- `results`
  - Post-processes pcaps, computes scores (vs. ground truth), and creates an experiment tarball.
- `stop`
  - Cleans Mininet state (`mn -c`).
- `clean`
  - Removes run artifacts (`logs/`, `pcaps/`), but keeps compiled P4 artifacts.
- `clean-all`
  - Also removes compiled artifacts (`p4objects/`) and result files.

## Typical workflows

- Fresh run after a crash or stale Mininet state:
  - `make stop`
  - `make run`
- Rerun tests from a clean runtime state (keep compiled artifacts):
  - `make clean`
  - `make run-test`
- Run linear-topology tests:
  - `make run-linear-test`
- Force complete rebuild of P4/BMv2 artifacts:
  - `make clean-all`
  - `make run`

## Running interactively

```bash
make run
```
In the Mininet CLI, use the custom commands provided by the DuneCLI:

- `toniot_test [pcap_dir] [pps]`
  - Replays one pcap per ingress host in parallel.
  - Defaults: `pcap_dir=utils/experiment_pcaps`, `pps=100`
  - Example:
    ```bash
    toniot_test utils/experiment_pcaps 200
    ```

- `linear_toniot_test <host> <pcap> [pps]`
  - Replays a single pcap on a specific host.
  - `<pcap>` can be an absolute path or a file inside `utils/experiment_pcaps`.
  - Example (basename resolved under `utils/experiment_pcaps`):
    ```bash
    linear_toniot_test p0_h0_0 TON-IOT_1.pcap 100
    ```

Once the pcap is replayed successfully, you can issue `quit` or `CTRL-D` to tear-down the mininet environment.
You can generate results using the `make results` target as described above.