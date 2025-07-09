#ifndef NETWORK_HEADERS_P4
#define NETWORK_HEADERS_P4

// This files contains standard networks headers
// with the necessary values for indicating
// the encapsulation of the DUNE protocol inside
// an Ethernet frame

typedef bit<48> EthernetAddress;

enum bit<16> EtherType {
    IPV4 = 0x0800,
    DUNE = 0xd00e
}

header Ethernet_h {
    EthernetAddress dst_addr;
    EthernetAddress src_addr;
    // Asuming no IEEE 802.1Q or IEEE 802.1ad tag (VLAN)
    EtherType ether_type;
}

typedef bit<32> IPv4Address;

typedef bit<8> IPv4Protocol;
enum IPv4Protocol IPv4Proto {
    TCP = 0x06,
    UDP = 0x11
}

header IPv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> total_length;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragment_offset;
    bit<8> ttl;
    IPv4Protocol protocol;
    bit<16> hdr_checksum;
    IPv4Address src_addr;
    IPv4Address dst_addr;
}

header IPv4Options_h {
    varbit<320> options;
}

header Tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_nb;
    bit<32> ack_nb;
    bit<4> data_offset;
    bit<4> reserved;
    bit<1> cwr;
    bit<1> ece;
    bit<1> urg;
    bit<1> ack;
    bit<1> psh;
    bit<1> rst;
    bit<1> syn;
    bit<1> fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header Udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

#endif
