import p4runtime_sh.shell as p4
import argparse
import json

import logging
logging.basicConfig(level=logging.INFO)

def populate_forwarding_tables(ingress_port_to_mpls, mpls_to_egress_port):
    if ingress_port_to_mpls is not None:
        table_name = 'DuneIngress.Forwarding.TableIngressPortToMPLS'
        logging.info(f'Populating table : {table_name}')
        for port in ingress_port_to_mpls:
            mpls = ingress_port_to_mpls[port]
            entry = p4.TableEntry(table_name)(
                    action='DuneIngress.Forwarding.SetMplsLabel'
                    )
            entry.match['std_meta.ingress_port'] = port
            entry.action['label'] = str(mpls)
            entry.priority = 0
            entry.insert()
    if mpls_to_egress_port is not None:
        table_name = 'DuneIngress.Forwarding.TableMPLSToEgressPort'
        logging.info(f'Populating table : {table_name}')
        for mpls in mpls_to_egress_port:
            port = mpls_to_egress_port[mpls]
            entry = p4.TableEntry(table_name)(
                    action='DuneIngress.Forwarding.SetEgressPort'
                    )
            entry.match['hdr.dune.mpls_label'] = mpls
            entry.action['port'] = str(port)
            entry.priority = 0
            entry.insert()


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--grpc-port", required=True)
    parser.add_argument("--device-id", required=True, type=int)

    parser.add_argument("--ingress-port-to-mpls", required=True)
    parser.add_argument("--mpls-to-egress-port", required=True)
    args = parser.parse_args()
    return args


def main():
    #TODO add log to say we starting new populating ...
    args = parse_args()

    # Connecting to the switch
    logging.info('Establishing GRPC connection')
    p4.setup(
        device_id=args.device_id,
        grpc_addr=f"0.0.0.0:{args.grpc_port}",
        election_id=(0, 1),  # (high, low)
        verbose=False,
    )

    with \
            open(args.ingress_port_to_mpls, 'r') as ingress_port_to_mpls,\
            open(args.mpls_to_egress_port, 'r') as mpls_to_egress_port:
                populate_forwarding_tables(
                        json.load(ingress_port_to_mpls),
                        json.load(mpls_to_egress_port),
                        )

    p4.teardown()

if __name__ == "__main__":
    main()
