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

typedef bit<8> Class_t;

const Class_t UNKNOWN_FLOW_CLASS = 0;

// Use typedef instead of type to for comparaisons without casting
#define PKT_CNT_BIT_WIDTH 32
typedef bit<PKT_CNT_BIT_WIDTH> PktCount_t;

header Dune_h {
    EtherType ether_type; // Backup from ethernet header since Dune replaces it 
    Class_t flow_class;
    bool collision;
    PktCount_t pkt_count;
    /* TODO : */
    // Forwarding
    bit<7> _padding_;
}

struct Headers_t {
   Ethernet_h       ethernet;
   Dune_h           dune;
   IPv4_h           ipv4;
   IPv4Options_h    ipv4_options;
   Tcp_h            tcp;
   Udp_h            udp;
}

#define ID_BIT_WIDTH 32
#define IDX_BIT_WIDTH 16

typedef bit<ID_BIT_WIDTH> FlowId_t;
typedef bit<IDX_BIT_WIDTH> RegIdx_t;

#define NB_REG_ENTRIES (1 << IDX_BIT_WIDTH)

struct Hash_t {
    tuple<IPv4Address, IPv4Address, bit<16>, bit<16>, bit<8>> key;
    FlowId_t flow_id;
    RegIdx_t reg_idx;
    bit<32> reg_idx32; // Only used to avoid cast for reading registers
}

struct Metadata_t {
   // Ports with no regards to TCP or UDP
    bit<16> src_port;
    bit<16> dst_port;

    Class_t flow_class;
    /* TODO */
}

struct FlowDigest_t {
    IPv4Address src_addr;
    IPv4Address dst_addr;
    bit<16> src_port;
    bit<16> dst_port;
    IPv4Protocol protocol;
    Class_t flow_class;
    RegIdx_t register_index;
}

// The Bmv2 uses timestamps in microseconds whereas Tofino uses nanoseconds.
// DUNE was initialy developped for Tofino so use the following
// macro when converting models using time trained on Tofino to Bmv2.
#define BMV2_TIME(T) (1000 * (T))

enum InferencePointStatus_t {
    BELOW_INFERENCE_POINT,
    AT_INFERENCE_POINT,
    AFTER_INFERENCE_POINT
}

#endif
