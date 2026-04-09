# Troubleshooting and Debugging

## Installation Issues

### Thrift Interface Connection Issue
There is a known issue with the `behavioral-model` Thrift interface ([p4lang/behavioral-model#1367](https://github.com/p4lang/behavioral-model/pull/1367)) that prevents the controller from connecting to the switches. Until this is fixed upstream, you must apply a patch to the `behavioral-model` repository during the `p4-guide` build installation process.

To apply the fix, navigate to the cloned `behavioral-model` directory (typically in your home folder or where the script downloads it), apply the patch, and recompile it:

```bash
cd ~/behavioral-model
curl -L https://github.com/p4lang/behavioral-model/pull/1367.patch | git apply
make
sudo make install
cd -
```

## General Troubleshooting

- Interfaces/namespaces already exist or Mininet refuses to start:
  - Run `make stop`
- Logs/pcaps contain old data:
  - Run `make clean`
- Unexpected behavior after changing P4 or pipeline configuration:
  - Run `make clean-all`
  - Run `make run`

## Further Debugging

To debug the execution of the Mininet network, controller, and test execution, you can inspect the logs in the `logs/` directory. You can control the log level by modifying the `LOG_LEVEL` variable in the Makefile. The available log levels are `DEBUG`, `INFO`, `WARNING`, `ERROR`, and `CRITICAL`.

### Controller Logs
The controller will log its output to `logs/controller.log`. The controller will start a thread to control each switch in the Mininet network, and each thread will log its output to `logs/c_<switch_id>.log`. 

### Switch Logs
Additionally, each switch will log its output to `logs/<switch_id>.log` (Bmv2 output). 

### Table Population Logs
Finally, the `populate_<switch_id>_tables.log` files will contain the output of the `convert_RF_and_populate_tables.py`, and `populate_forwarding_tables.py` script for each switch. Here you will be able to find out whether the switch is running an inference model or not, and whether the tables were populated correctly.