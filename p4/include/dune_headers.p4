#ifndef DUNE_HEADERS_P4
#define DUNE_HEADERS_P4

// This file contains the headers and structures
// used by the DUNE protocol

// Warning :
// This file define the following :
// - struct Headers_t
// - struct Metadata_t
// Both structures are use throughout the packet processing pipeline
// and are essential to passing logic from one control block to the next

#include "network_headers.p4"

const bit<8> UNKNOWN_FLOW_CLASS = 0;

header Dune_h {
    EtherType ether_type; // Backup from ethernet header since Dune replaces it 
    /* TODO */
}

struct Headers_t {
   Ethernet_h       ethernet;
   Dune_h           dune;
   IPv4_h           ipv4;
   IPv4Options_h    ipv4_options;
   Tcp_h            tcp;
   Udp_h            udp;
}

#define IDX_BIT_WIDTH 16
#define NB_REG_ENTRIES (1 << IDX_BIT_WIDTH)

struct Hash_t {
    tuple<IPv4Address, IPv4Address, bit<16>, bit<16>, bit<8>> key;
    bit<32> flow_id;
    bit<16> reg_idx;
    bit<32> reg_idx32; // Only used to avoid cast for reading registers
}

struct Metadata_t {
   // Ports with no regards to TCP or UDP
    bit<16> src_port;
    bit<16> dst_port;

    bit<8> flow_class;
    /* TODO */
}

struct FlowDigest_t {
    /* TODO */
}

#endif
