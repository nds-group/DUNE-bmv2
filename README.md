# DUNE-bmv2

This repository contains the software switch implementation of DUNE. It allows running Mininet-based experiments to test inference models using Bmv2.

## Dependencies and Installation

To run this project, you need to set up the P4 development environment. We rely on the scripts provided by the [p4-guide](https://github.com/jafingerhut/p4-guide) repository to install all the necessary dependencies (e.g., PI, BMv2, P4C, Mininet).

Run the following commands to install the dependencies:

```bash
git clone https://github.com/jafingerhut/p4-guide.git
./p4-guide/bin/install-p4dev-v10.sh
```

**⚠️ WARNING:** There is a known issue with the `behavioral-model` Thrift interface ([p4lang/behavioral-model#1367](https://github.com/p4lang/behavioral-model/pull/1367)) that prevents the controller from connecting to the switches. Until this is fixed upstream, you must apply a patch. Please refer to the [Troubleshooting guide](docs/troubleshooting.md#thrift-interface-connection-issue) for instructions to apply the patch.

Ensure you activate the Python virtual environment created by the installation script before executing commands or make targets:

```bash
source ~/p4-guide/p4dev-python-venv/bin/activate
```

## Required Files

Before running the experiments, ensure you have the required ToN_IoT dataset files placed in a `data/` directory at the root of the project:

- `data/ToN_IoT_Test_Flow_PktCounts.csv`
- `data/ToN_IoT_test.pcap`
- `data/ton_tcp_udp.pcapng` (optional depending on your exact configuration)

*(You can verify the expected paths in `utils/params.ini`)*

To generate these data files, please follow the procedure described in the [DUNE data generation guide](https://github.com/nds-group/DUNE/tree/main/data_generation/README.md).

*Note: This repository will eventually become a submodule of the main [nds-group/DUNE](https://github.com/nds-group/DUNE) repository.*

## Quick Start: Minimal Example

To run a minimal smoke test and ensure the environment is correctly set up, run:

```bash
make run-smoke-test
```

## Reproducing DUNE Paper Results

To reproduce the results presented in Table V of the DUNE paper, execute the following target:

```bash
make run-table-5
```

## Additional Documentation

For more detailed information regarding the project's architecture, workflows, configurations, and advanced usage, please refer to the documentation in the `docs/` folder:

- [Project Structure & Architecture](docs/project-structure.md)
- [Workflows & Targets](docs/workflows.md)
- [Troubleshooting & Debugging](docs/troubleshooting.md)

## Citation
If you use this code or framework in your research, please kindly cite our INFOCOM 2025 paper:

```bibtex
@INPROCEEDINGS{11044678,
  author={Bütün, Beyza and De Andres Hernandez, David and Gucciardo, Michele and Fiore, Marco},
  booktitle={IEEE INFOCOM 2025 - IEEE Conference on Computer Communications}, 
  title={DUNE: Distributed Inference in the User Plane}, 
  year={2025},
  volume={},
  number={},
  pages={1-10},
  keywords={Sequential analysis;Accuracy;Computational modeling;Scalability;Memory management;Machine learning;Hardware;Delays;Resource management;Monitoring},
  doi={10.1109/INFOCOM55648.2025.11044678}
}
```
