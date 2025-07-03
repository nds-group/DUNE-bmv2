#include <core.p4>
#include <v1model.p4>

#include "include/network_headers.p4"
#include "include/dune_ingress_parser.p4"
#include "include/dune_verify_checksum.p4"
#include "include/dune_egress.p4"
#include "include/dune_compute_checksum.p4"
#include "include/dune_egress_deparser.p4"

control DuneIngress(
    inout Headers_t hdr,
    inout Metadata_t meta,
    inout standard_metadata_t std_meta
)
{
    action InsertDuneHeader() {
        hdr.dune.setValid();
        hdr.dune.ether_type = hdr.ethernet.ether_type;
        hdr.ethernet.ether_type = EtherType.DUNE;
        /* TODO */
        // initialize fields
    }

    action MetaSetFlowClass(bit<8> flow_class) {
        meta.flow_class = flow_class;
    }

    action MetaSetDefaultFlowClass() {
        meta.flow_class = UNKNOWN_FLOW_CLASS;
    }

    table FlowClass {
        key = {
            hdr.ipv4.src_addr:                exact;
            hdr.ipv4.dst_addr:                exact;
            meta.src_port:  exact;
            meta.dst_port:  exact;
            hdr.ipv4.protocol:              exact;
        }
        actions = {
            MetaSetFlowClass;
            @defaultonly MetaSetDefaultFlowClass;
        }
        size = 65535;
        const default_action = MetaSetDefaultFlowClass();
    }

    register<bit<32>>(NB_REG_ENTRIES) previous_pkt_timestamp;

    Hash_t hashes;

    bit<32> time;
    apply {

        /* TODO */
        // Maybe don't insert header if flow already classified
        if (!hdr.dune.isValid()) {
            // Packet was not equiped with a DUNE header yet
            InsertDuneHeader();
        }

        hashes.key = {
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,
            meta.src_port,
            meta.dst_port,
            hdr.ipv4.protocol,
        };
        hash(
            hashes.flow_id,
            HashAlgorithm.crc32,
            (bit<64>) 0,
            hashes.key,
            (bit<64>) 1 << 32
        );
        hash(
            hashes.reg_idx,
            HashAlgorithm.crc16,
            (bit<64>) 0,
            hashes.key,
            (bit<64>) 1 << 16
        );
        hashes.reg_idx32 = (bit<32>) hashes.reg_idx;

        // Check if flow is known and populate meta.flow_class
        FlowClass.apply();

        // Check for collisions
        previous_pkt_timestamp.read(time, hashes.reg_idx32);
        previous_pkt_timestamp.write(
            hashes.reg_idx32, 
            // Multiply by 1000 because tofino uses nano seconds
            // but v1model uses micro seconds
            std_meta.ingress_global_timestamp[31:0] * 1000 
        );

        if (UNKNOWN_FLOW_CLASS == meta.flow_class) {
            // Apply model
        }
        
        // do forwarding
        /* TODO */
    }
}

V1Switch(
    DuneIngressParser(),
    DuneVerifyChecksum(),
    DuneIngress(),
    DuneEgress(),
    DuneComputeChecksum(),
    DuneEgressDeparser()
) main;
