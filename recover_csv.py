import argparse

def load_file(path):
    with open(path) as file:
        lines = [line.rstrip() for line in file.readlines()]
    return lines

def handle_digest(digest_content, classe, output):
    for digest in digest_content:
        digest = digest.split('=')[1].split(',')
        src_addr = digest[0]
        dst_addr = digest[1]
        src_port = digest[2]
        dst_port = digest[3]
        protocol = digest[4]
        flow_packet_class = int(digest[5])
        pkt_count = digest[6]
        register_index = digest[7]
        is_flow = digest[8]
        is_store = digest[9]
        is_refresh = digest[10]

        csv_row = f'{src_addr},{dst_addr},{src_port},{dst_port},{protocol},{pkt_count},{is_flow}'
        if is_store == '1':
            if flow_packet_class == classe:
                csv_row = f'{csv_row},{32}'
            else:
                csv_row = f'{csv_row},{flow_packet_class}'
        else:
            csv_row = f'{csv_row},{55}'
        print(csv_row, file=output)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    parser.add_argument('--input', required=True)
    parser.add_argument('--classe', required=True, type=int)
    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    lines = load_file(args.input)
    digest_content = list(filter((lambda line: 'digest_content=' in line), lines))
    for digest in digest_content:
        print(digest)

    output = open(args.output, 'w', 1)
    header = 'source_addr,destin_addr,source_port,destin_port,protocol,pkt_count,is_flow,flow_packet_class'
    print(header, file=output)
    handle_digest(digest_content, args.classe, output)


if __name__ == '__main__':
    main()
