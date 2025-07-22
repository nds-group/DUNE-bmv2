from mininet.node import Host, Switch, Controller
from mininet.moduledeps import pathCheck

from os.path import isfile, isdir
from os import access, R_OK
import os.path
import psutil
import tempfile
import time
import multiprocessing
import socket


def assertIsFile(path):
    assert isfile(path) and access(path, R_OK), path + ' was not found, is a directory, or cannot be read'


def assertIsDir(path):
    assert isdir(path), path + ' was not found or is a file'


class P4Host(Host):
    def config(self, **_params):
        r = Host.config(self, **_params)

        intf = self.defaultIntf()
        for off in ['rx', 'tx', 'sg']:
            cmd = f'/sbin/ethtool --offload {intf} {off} off'
            self.cmd(cmd)

        # disable IPv6
        self.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
        self.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')
        self.cmd('sysctl -w net.ipv6.conf.lo.disable_ipv6=1')

        return r

hosts = { 'p4host' : P4Host }

class P4SimpleSwitchGRPC(Switch):
    next_device_id = 1
    next_thrift_port = 9091
    next_grpc_port = 50051
    sw_path = 'simple_switch_grpc'
    pathCheck(sw_path)
    START_TIMEOUT = 10

    def get_device_id(self):
        dev_id = P4SimpleSwitchGRPC.next_device_id
        P4SimpleSwitchGRPC.next_device_id += 1
        return dev_id

    def get_ports(self):
        grpc_port = P4SimpleSwitchGRPC.next_grpc_port
        P4SimpleSwitchGRPC.next_grpc_port += 1

        thrift_port = P4SimpleSwitchGRPC.next_thrift_port
        P4SimpleSwitchGRPC.next_thrift_port += 1

        return (grpc_port, thrift_port)

    def __init__(self, name, model_config, model_dir, objects_dir, log_dir, pcap_dir, **kwargs):
        Switch.__init__(self, name, **kwargs)
        assert model_config is not None, 'No model config provided'
        assertIsDir(model_dir)
        assertIsDir(objects_dir)
        assertIsDir(log_dir)
        assertIsDir(pcap_dir)

        self.controller_is_connected = False

        self.model_config = model_config
        self.model_dir = model_dir
        self.objects_dir = objects_dir
        self.log_dir = log_dir
        self.pcap_dir = pcap_dir

        self.sw_json = os.path.join(objects_dir, self.model_config['p4'] + '.json')
        self.sw_p4info = os.path.join(objects_dir, self.model_config['p4'] + '.p4.p4info.txtpb')
        assertIsFile(self.sw_json)
        assertIsFile(self.sw_p4info)

        if self.model_config['p4'] == 'no_inference':
            self.models = None
        else:
            # TODO : simplify next line
            # we no longer have more than 1 models per switch
            # also, do same for convert_RF_and_populate_tables.py
            self.models = [*map(lambda m: os.path.join(self.model_dir, m), self.model_config['files'])]
            for path in self.models:
                assertIsFile(path)

        self.device_id = self.get_device_id()
        self.grpc_port, self.thrift_port = self.get_ports()

    @staticmethod
    def is_port_listening(port):
        for c in psutil.net_connections(kind='inet'):
            if c.status == 'LISTEN' and c.laddr[1] == port:
                return True
        return False

    def as_switch_started(self, pid):
        for _ in range(self.START_TIMEOUT * 2):
            time.sleep(0.5)
            if not os.path.exists(os.path.join('/proc', str(pid))):
                return False
            grpc_listening = self.is_port_listening(self.grpc_port)
            thrift_listening = self.is_port_listening(self.thrift_port)
            if grpc_listening and thrift_listening:
                return True
        return False

    def start(self, controllers):
        assert_msg = '{} cannot bind port {} because it is bound by another process\n'
        assert not self.is_port_listening(self.grpc_port), assert_msg.format(self.name, self.grpc_port)
        assert not self.is_port_listening(self.thrift_port), assert_msg.format(self.name, self.thrift_port)

        self.start_cmd = [P4SimpleSwitchGRPC.sw_path]
        for port, intf in self.intfs.items():
            if not intf.IP():
                self.start_cmd += ['-i', str(port) + '@' + intf.name]
        self.start_cmd += ['--pcap', 'pcaps']
        self.start_cmd += ['--nanolog', f'ipc:///tmp/bm-{self.device_id}-log.ipc']
        self.start_cmd += ['--device-id', str(self.device_id)]
        self.start_cmd += [self.sw_json]
        self.start_cmd += ['--log-console']
        self.start_cmd += ['--thrift-port', str(self.thrift_port)]
        self.start_cmd += ['--']
        self.start_cmd += ['--grpc-server-addr', f'127.0.0.1:{self.grpc_port}']

        self.start_cmd = ' '.join(self.start_cmd)

        pid = None
        with tempfile.NamedTemporaryFile() as f:
            log_file = os.path.join(self.log_dir, self.name + '.log')
            self.cmd(self.start_cmd + ' > ' + log_file + ' 2>&1 & echo $! >> ' + f.name)
            pid = int(f.read())
        assert self.as_switch_started(pid), 'Switch ' + self.name + ' failed to start before timeout'
        self.controller = controllers[0]
        self.controller_is_connected = False

    def stop(self):
        self.cmd(f'pkill -f "{self.start_cmd}"')

    # Using batchStartup to program the switches in parallel
    # and advertise to controller when ready
    @classmethod
    def batchStartup(cls, switches):
        processes = []
        for sw in switches:
            ps = multiprocessing.Process(
                    target=cls.populate_tables,
                    args=[sw]
                )
            processes.append(ps)
            ps.start()
        try:
            for ps in processes:
                ps.join()
        except KeyboardInterrupt:
            for ps in processes:
                ps.terminate()
            raise KeyboardInterrupt
        for sw in switches:
            sw.advertise_to_controller()
        return switches

    def connected(self):
        if not self.controller_is_connected:
            self.advertise_to_controller()
        return self.controller_is_connected

    def populate_tables(sw):
        if sw.models is not None:
            args = ['python', 'convert_RF_and_populate_tables.py']
            args += ['--p4info', sw.sw_p4info]
            args += ['--json', sw.sw_json]
            args += ['--grpc-port', str(sw.grpc_port)]
            args += ['--device-id', str(sw.device_id)]
            args += ['--models'] + sw.models
        else:
            args = ['echo', '"The inference pipeline is disabled in this switch"']

        log_file = os.path.join(sw.log_dir, 'populate_' + sw.name + '.txt')
        args += ['>', log_file, '2>&1']

        populate_cmd = ' '.join(args)
        sw.cmd(populate_cmd)

    def advertise_to_controller(self):
        self.controller_is_connected = True
        return
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.controller.ip, self.controller.port))
            data = f'{self.grpc_port},{self.thrift_port},{self.device_id}'
            s.sendall(data.encode())
            print('Sending data')

            ack = s.recv(1024).decode()
            self.controller_is_connected = ack == 'ACK'
            print('Received ack :', ack)

switches = { 'p4simpleswitchgrpc' : P4SimpleSwitchGRPC }

class P4Controller(Controller):
    ctrl_path = 'controller.py'
    assertIsFile(ctrl_path)

    def __init__(self, name, **kwargs):
        Controller.__init__(self, name, **kwargs)
        return

        args = ['python', P4Controller.ctrl_path]
        args += ['--ip', str(self.ip)]
        args += ['--port', str(self.port)]

        self.start_cmd = ' '.join(args)

    def start(self):
        return
        assert not P4SimpleSwitchGRPC.is_port_listening(self.port)

        # TODO : better logging
        self.cmd(self.start_cmd + ' > output 2>&1 &')

    def stop(self):
        return
        self.cmd(f'pkill -f "{self.start_cmd}"')


controllers = { 'p4controller' : P4Controller }
