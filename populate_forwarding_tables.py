import p4runtime_sh.shell as p4
import argparse

import logging
logging.basicConfig(level=logging.INFO)

def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--p4info", required=True)
    parser.add_argument("--json", required=True)
    parser.add_argument("--grpc-port", required=True)
    parser.add_argument("--device-id", required=True, type=int)

    parser.add_argument("--paths", required=True)
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    print(args.paths, flush=True)
    return

    # Connecting to the switch
    logging.info('Establishing GRPC connection')
    p4.setup(
        device_id=args.device_id,
        grpc_addr=f"0.0.0.0:{args.grpc_port}",
        election_id=(0, 1),  # (high, low)
        config=p4.FwdPipeConfig(args.p4info, args.json),
        verbose=False,
    )


    logging.info('Uploading models : %s', args.models)
    for index, model in enumerate(args.models):
        len_features, len_code_tables = upload_model(
            model, feature_offset, code_table_offset, index
        )
        feature_offset += len_features
        code_table_offset += len_code_tables


    p4.teardown()

if __name__ == "__main__":
    main()
