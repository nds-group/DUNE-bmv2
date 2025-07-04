#include <core.p4>
#include <v1model.p4>

#include "include/network_headers.p4"
#include "include/dune_ingress_parser.p4"
#include "include/dune_verify_checksum.p4"
#include "include/dune_egress.p4"
#include "include/dune_compute_checksum.p4"
#include "include/dune_egress_deparser.p4"

control IsFlowClassKnownLocally(
    inout Headers_t hdr,
    inout Metadata_t meta
)
{
    // TODO MAYBE
    // Change this to be a binary setting instead of storing the class ?
    action MetaSetFlowClass(Class_t flow_class) {
        meta.flow_class = flow_class;
    }

    action MetaSetUnkownFlowClass() {
        meta.flow_class = UNKNOWN_FLOW_CLASS;
    }

    table FlowClass {
        key = {
            hdr.ipv4.src_addr:  exact;
            hdr.ipv4.dst_addr:  exact;
            meta.src_port:      exact;
            meta.dst_port:      exact;
            hdr.ipv4.protocol:  exact;
        }
        actions = {
            MetaSetFlowClass;
            @defaultonly MetaSetUnkownFlowClass;
        }
        size = 65535;
        const default_action = MetaSetUnkownFlowClass();
    }

    apply {
        // TODO MAYBE
        // Also do packet class ?
        FlowClass.apply();
    }
}

control ComputeHashes(
    out Hash_t hashes,
    inout Headers_t hdr,
    inout Metadata_t meta
)
{
    apply {
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
        hashes.reg_idx32 = (bit<32>) ((bit<16>)hashes.reg_idx);
    }
}

control DuneIngress(
    inout Headers_t hdr,
    inout Metadata_t meta,
    inout standard_metadata_t std_meta
)
{
    action InsertDuneHeaderIfNotPresent() {
        if (!hdr.dune.isValid()) {
            // Packet was not equiped with a DUNE header yet
            hdr.dune = {
                ether_type = hdr.ethernet.ether_type,
                flow_class = UNKNOWN_FLOW_CLASS,
                collision = false,
                pkt_count = 0,
                _padding_ = 0
            };
            hdr.ethernet.ether_type = EtherType.DUNE;
        }
    }

    register<bool>(NB_REG_ENTRIES) flow_id_used;
    register<FlowId_t>(NB_REG_ENTRIES) flow_ids;
    action CheckColision(in Hash_t hashes, inout Dune_h dune) {
        bool used;
        FlowId_t flow_id;

        flow_id_used.read(used, hashes.reg_idx32);
        if (used) {
            flow_ids.read(flow_id, hashes.reg_idx32);
            dune.collision = flow_id != hashes.flow_id;
        } else {
            dune.collision = false;
        }
    }
    action UpdateUsedFlowIds(in Hash_t hashes) {
        flow_id_used.write(hashes.reg_idx32, true);
    }


    register<bit<32>>(NB_REG_ENTRIES) previous_pkt_timestamp;

    Hash_t hashes;

    bit<32> prev_pkt_timestamp;
    bit<32> pkt_timestamp;
    bit<32> inter_arrival_time;

    apply {
        InsertDuneHeaderIfNotPresent();
        // Check if flow is known and populate meta.flow_class
        IsFlowClassKnownLocally.apply(hdr, meta);
        if (UNKNOWN_FLOW_CLASS == meta.flow_class) {
            ComputeHashes.apply(hashes, hdr, meta);
            CheckColision(hashes, hdr.dune);
            UpdateUsedFlowIds(hashes);
            if (UNKNOWN_FLOW_CLASS != hdr.dune.flow_class) {
                // Flow is known by a previous switch
                // TODO
                // Send digest and clear registers (in controller, no clear if collision)
                digest<FlowDigest_t>(1, {});
            } else {
                // Flow is not know by a previous switch

                /* TODO */
                // Apply model

                //pkt_arrival_time = BMV2_TIME(std_meta.ingress_global_timestamp[31:0])

                //previous_pkt_timestamp.read(prev_pkt_, hashes.reg_idx32);
                previous_pkt_timestamp.write(
                    hashes.reg_idx32, 
                    // Multiply by 1000 because tofino uses nano seconds
                    // but v1model uses micro seconds
                    std_meta.ingress_global_timestamp[31:0] * 1000 
                );



                // Apply model
            }
        } else {
            // Flow is locally known
            hdr.dune.flow_class = meta.flow_class;
            // TODO
            // Use local info to populate dune header
        }
        /* TODO */
        // Move forwarding to egress ?
        // do forwarding
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
