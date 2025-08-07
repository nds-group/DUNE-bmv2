import grpc
import json
from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc

import bmpy_utils as bm
from bm_runtime.standard.ttypes import BmMatchParam, BmMatchParamExact, BmAddEntryOptions

import queue
import argparse
import threading
import socket
import signal

import os
import logging

# Formatter
FORMAT = "%(asctime)s [%(threadName)s] [%(levelname)s] %(message)s"

from collections import namedtuple

# --- Shared thread-safe context for controller ---
class ControllerContext:
    def __init__(self):
        self._lock = threading.Lock()
        self.paths = None
        self.switches = None
        self.hosts = None

    def set_paths(self, paths_dict):
        with self._lock:
            self.paths = paths_dict

    def get_paths(self):
        with self._lock:
            return self.paths

    def set_switches(self, switches_dict):
        with self._lock:
            self.switches = switches_dict

    def get_switches(self):
        with self._lock:
            return self.switches

    def set_hosts(self, hosts_dict):
        with self._lock:
            self.hosts = hosts_dict

    def get_hosts(self):
        with self._lock:
            return self.hosts

context = ControllerContext()

DuneDigest = namedtuple('DuneDigest',
                        [
                            'src_addr',
                            'dst_addr',
                            'src_port',
                            'dst_port',
                            'protocol',
                            'mpls_label',
                            'flow_class',
                            'register_index',
                        ]
                       )

threads = {}
queues = {}
shutdown_event = threading.Event()



class Controller():
    digest_name = 'FlowDigest_t'

    def __init__(self, grpc_port, thrift_port, device_id, name, models, log_dir):
        self.c_name = 'c_' + name
        threading.current_thread().name = self.c_name
        
        self.logger = logging.getLogger(self.c_name)

        log_file = os.path.join(log_dir, self.c_name + '.log')
        handler = logging.FileHandler(log_file, mode='w')
        formatter = logging.Formatter(FORMAT)
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        self.logger.info('Controller %s started', self.c_name)
        self.logger.debug('\t GRPC port: %s', grpc_port)
        self.logger.debug('\t Thrift port: %s', thrift_port)
        self.logger.debug('\t Device ID: %s', device_id)

        try:
            self.models = None if models == 'None' else models
            self.key = name
            self.device_id = int(device_id)

            # Thrift connection to the switch
            # (because registers not implemented in GRPC)
            # thrift_client: Client = bm.thrift_connect_standard(
            self.logger.info('Connecting with thrift')
            self.thrift_client = bm.thrift_connect_standard(
                    thrift_ip='127.0.0.1',
                    thrift_port=thrift_port,
                    )
            self.connect_with_grpc(grpc_port, int(device_id))
            self.get_p4info()
            self.main()
        except Exception as e:
            self.logger.exception(e)

    def main(self):
        if self.models is not None:
            self.build_digest_field_map()

        self.get_registers_from_switch()

        self.logger.info('Listening for digest messages')
        while not shutdown_event.is_set():
            if not queues[self.key].empty():
                external_dune_digest = queues[self.key].get()
                self.logger.debug('Received digest from queue: %s', external_dune_digest)
                self.insert_flow_table(external_dune_digest)
                self.clear_registers(external_dune_digest)
            if self.models is not None and not self.stream_responses.empty():
                self.logger.debug('Received direct digest')
                dune_digest = self.stream_responses.get()
                self.process_digest_entries(dune_digest)
    
        self.logger.info('Controller %s shuting down', self.c_name)
        self.stream_thread.join()

    def connect_with_grpc(self, grpc_port, device_id):
        self.logger.info('Connecting with grpc')
        channel = grpc.insecure_channel('127.0.0.1:' + grpc_port)
        self.stub = p4runtime_pb2_grpc.P4RuntimeStub(channel)
        self.stream_requests = queue.Queue()
        self.stream_responses = queue.Queue()

        def request_generator():
            while not shutdown_event.is_set():
                req = self.stream_requests.get()
                if req is None:
                    break
                yield req

        stream = self.stub.StreamChannel(request_generator())

        def response_reader():
            try:
                while not shutdown_event.is_set():
                    resp = next(stream)
                    self.stream_responses.put(resp)
            except grpc._channel._MultiThreadedRendezvous as e:
                if e.code() == grpc.StatusCode.UNAVAILABLE and 'Socket closed' in e.details():
                    self.logger.info('Stream thread socket closed, shuting down')
                    shutdown_event.set()
                else:
                    raise

        self.stream_thread = threading.Thread(
                target=response_reader, args=()
                )

        self.logger.info('Starting stream thread')
        self.stream_thread.start()

        # Send the initial arbitration message
        election_id = p4runtime_pb2.Uint128(high=0, low=2)
        req = p4runtime_pb2.StreamMessageRequest()
        req.arbitration.device_id = device_id
        req.arbitration.election_id.CopyFrom(election_id)

        self.stream_requests.put(req)

        # Wait for arbitration response
        response = self.stream_responses.get()
        assert response.HasField('arbitration')
        self.logger.info('GRPC connection with the switch established')

    def get_p4info(self):
        req = p4runtime_pb2.GetForwardingPipelineConfigRequest()
        req.device_id = self.device_id
        req.response_type =  p4runtime_pb2.GetForwardingPipelineConfigRequest.P4INFO_AND_COOKIE
        resp = self.stub.GetForwardingPipelineConfig(req)

        self.p4info = resp.config.p4info

    def build_digest_field_map(self):
        """Returns an ordered list of (name, bitwidth) based on digest type_spec."""
        for digest in self.p4info.digests:
            if digest.preamble.name == Controller.digest_name:
                struct_name = digest.type_spec.struct.name
                struct = self.p4info.type_info.structs[struct_name]
                self.field_list = []
                for member in struct.members:
                    bitwidth = member.type_spec.bitstring.bit.bitwidth
                    self.field_list.append((member.name, bitwidth))
                return
        raise ValueError(f'Digest "{self.digest_name}" not found in P4Info.')

    def get_registers_from_switch(self):
        config = json.loads(self.thrift_client.bm_get_config())

        self.registers = []
        for register_array in config['register_arrays']:
            self.registers.append(register_array['name'])

    def insert_flow_table(self, dune_digest):
        client = self.thrift_client
        cxt_id = 0

        match_keys = [
            BmMatchParam(exact=BmMatchParamExact(dune_digest.src_addr.to_bytes(4, 'big'))),
            BmMatchParam(exact=BmMatchParamExact(dune_digest.dst_addr.to_bytes(4, 'big'))),
            BmMatchParam(exact=BmMatchParamExact(dune_digest.src_port.to_bytes(2, 'big'))),
            BmMatchParam(exact=BmMatchParamExact(dune_digest.dst_port.to_bytes(2, 'big'))),
            BmMatchParam(exact=BmMatchParamExact(dune_digest.protocol.to_bytes(1, 'big')))
        ]

        options = BmAddEntryOptions()
        # If you are doing ternary or LPM matches and need to set priority, you must use:
        # options.priority = 10  # or whatever

        action_data = [dune_digest.flow_class.to_bytes(1, 'big')] 

        client.bm_mt_add_entry(
            cxt_id,
            'DuneIngress.Inference.IsFlowClassKnownLocally.FlowClass',
            match_keys,
            'DuneIngress.Inference.IsFlowClassKnownLocally.MetaSetFlowClass',
            action_data,
            options
        )

        self.logger.info(f'Inserted entry into IsFlowClassKnownLocally table')
        for key in match_keys:
            self.logger.debug('      Match key: %s', key.exact.key.hex())
        self.logger.debug('      Action parameters: %s', [*map(lambda data: data.hex(), action_data)])

    def clear_registers(self, dune_digest):
        client = self.thrift_client
        cxt_id = 0

        for register in self.registers:
            client.bm_register_write(cxt_id, register, dune_digest.register_index, 0)

    def process_digest_entries(self, response):
        if response.HasField('digest'):
            digest = response.digest
            self.logger.debug('Processing digest (ID: %s, List ID: %s)', digest.digest_id, digest.list_id)

            for entry in digest.data:
                dune_digest = self.parse_dune_digest_entry(entry)
                path_switches = self.get_switches_in_mpls_path(dune_digest.mpls_label)
                for sw in path_switches:
                    queues[sw].put(dune_digest)

            self.logger.info('Handled digest (ID: %s, List ID: %s)', digest.digest_id, digest.list_id)
            self.logger.debug('      Digest content: %s', dune_digest)

            self.send_digest_ack(digest.digest_id, digest.list_id)
        else:
            self.logger.info('Received message that is not a digest : %s', response)

    def parse_dune_digest_entry(self, entry):
        self.logger.debug('  Digest entry:')
        dune_digest = {}
        for i, member in enumerate(entry.struct.members):
            if i < len(self.field_list):
                name, bitwidth = self.field_list[i]
                value = int.from_bytes(member.bitstring)
                dune_digest[name] = value
                self.logger.debug(f'    {name:<15} = {value}')
            else:
                self.logger.debug(f'    Unknown member (too many): {member}')
        return DuneDigest(**dune_digest)

    def get_switches_in_mpls_path(self, mpls_label):
        try:
            paths = context.get_paths()
            nodes = paths[str(mpls_label)]
            self.logger.debug('Found path for mpls label %s: %s', mpls_label, nodes)
        except KeyError:
            self.logger.error('No path corresponding to mpls label %s', mpls_label)
            shutdown_event.set()
        switches = filter(lambda node: node not in context.get_hosts(), nodes)
        return list(switches)

    def send_digest_ack(self, digest_id, list_id):
        ack = p4runtime_pb2.StreamMessageRequest()
        ack.digest_ack.digest_id = digest_id
        ack.digest_ack.list_id = list_id
        self.logger.info('Sending digest ACK (ID: %s, List ID: %s)', digest_id, list_id)
        self.stream_requests.put(ack)

def shutdown(sig, frame):
    logging.info('Received %s, shuting down', signal.Signals(sig).name)
    shutdown_event.set()
    for thread in threads.values():
        thread.join()

class Server():
    logger = None

    def __init__(self, ip, port, topo, log_dir):
        self.ip = ip
        self.port = port
        self.topo = topo
        self.log_dir = log_dir

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(1.0)

    def run(self):
        shutdown_event.clear()

        threading.current_thread().name = self.__class__.__name__

        self.logger = logging.getLogger(self.__class__.__name__)

        self.logger.info('Binding server to %s:%s', self.ip, self.port)
        self.server_socket.bind((self.ip, self.port))
        self.server_socket.listen(1)

        self.logger.info('Listening for connections')
        while not shutdown_event.is_set():
            try:
                conn, _ = self.server_socket.accept()
                self.logger.info('Accepted a new connection')
                self.handle_new_connection(conn)
            except socket.timeout:
                continue
        self.logger.info('Closing the server socket')
        self.server_socket.close()

    def handle_new_connection(self, conn):
        self.logger.debug('New connection to register a switch')
        try:
            data = conn.recv(1024).decode()
            if data:
                self.logger.debug('Received registration data')
                grpc_port, thrift_port, device_id, name, models = data.strip().split(',')
                ack = 'ACK'
                self.logger.debug('Sending registration data ACK to %s', name)
                conn.sendall(ack.encode())
                self.add_threaded_controller(grpc_port, thrift_port, device_id, name, models)
        except Exception as e:
            self.logger.info(e)
        finally:
            self.logger.debug('Switch registered, closing connnection')
            conn.close()

    def add_threaded_controller(self, grpc_port, thrift_port, device_id, name, models):
        # key = 's' + device_id
        key = name
        assert key not in threads, f'Controller thread already exists for key {key}'
        thread = threading.Thread(
                target=Controller,
                args=(grpc_port,
                      thrift_port,
                      device_id,
                      key,
                      models,
                      self.log_dir,
                      )
                )
        threads[key] = thread
        queues[key] = queue.Queue()
        self.logger.info('Starting controller thread for switch %s', key)
        thread.start()

def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('--ip', required=True)
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--topo', required=True)
    parser.add_argument('--log-dir', required=True)
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])

    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    # Set up logging
    log_level = getattr(logging, args.log_level.upper())

    logging.basicConfig(level=log_level, format=FORMAT)
    logging.info('Log level set to %s', args.log_level.upper())

    with open(args.topo, 'r') as file:
        topo = json.load(file)
        paths = topo['paths']
        switches = topo['switches']
        hosts = topo['hosts']
        logging.debug('Loaded switches: %s', switches)
        context.set_switches(switches)
        logging.debug('Loaded hosts: %s', hosts)
        context.set_hosts(hosts)
        logging.debug('Loaded paths: %s', paths)
        context.set_paths(paths)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    server = Server(args.ip, args.port, args.topo, args.log_dir)

    logging.info('Starting the server')
    server_thread = threading.Thread(target=server.run, args=())
    server_thread.start()
    signal.pause()
    logging.info('Waiting for server shutdown')
    server_thread.join()
    logging.info('Server now stopped')


if __name__ == '__main__':
    main()

