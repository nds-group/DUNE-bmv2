#ifndef DUNE_INGRESS_PARSER_P4
#define DUNE_INGRESS_PARSER_P4

#include "dune_headers.p4"

error {
    IPv4InvalidHeader,
    Reject
}

parser DuneIngressParser(
    packet_in pkt,
    out Headers_t hdr,
    inout Metadata_t meta,
    inout standard_metadata_t std_meta
)
{
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            EtherType.DUNE: parse_dune;
            EtherType.IPV4: parse_ipv4;
            default: to_reject;
        }
    }

    state parse_dune {
        pkt.extract(hdr.dune);
        transition select(hdr.dune.ether_type) {
            EtherType.IPV4: parse_ipv4;
            default: to_reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        verify(hdr.ipv4.version == 4 && hdr.ipv4.ihl >= 5, error.IPv4InvalidHeader);
        pkt.extract(hdr.ipv4_options, ((bit<32>)hdr.ipv4.ihl - 5) * 32);
        transition select(hdr.ipv4.protocol) {
            IPv4Proto.TCP: parse_tcp;
            IPv4Proto.UDP: parse_udp;
            default: to_reject;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.src_port = hdr.tcp.src_port;
        meta.dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.src_port = hdr.udp.src_port;
        meta.dst_port = hdr.udp.dst_port;
        transition accept;
    }

    // We cannot transition to the reject directly on Bmv2
    // C.f. https://github.com/p4lang/behavioral-model/blob/971732f48570f848a27a8f54b25b7447732d8591/docs/simple_switch.md#restrictions-on-parser-code
    state to_reject {
        verify(false, error.Reject);
        transition accept;
    }
}

#endif
