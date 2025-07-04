#ifndef DUNE_INGRESS_P4
#define DUNE_INGRESS_P4

#include "dune_headers.p4"

control IsFlowClassKnownLocally(
    inout Headers_t hdr,
    inout Metadata_t meta
)
{
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

control CheckCollision(
    in Hash_t hashes, 
    inout Dune_h dune
)
{
    register<bit<1>>(NB_REG_ENTRIES) flow_id_used;

    action UpdateUsedFlowIds() {
        flow_id_used.write(hashes.reg_idx32, 1);
    }

    register<FlowId_t>(NB_REG_ENTRIES) flow_ids;
    apply {
        bit<1> used;
        FlowId_t flow_id;

        flow_id_used.read(used, hashes.reg_idx32);
        if ((bool)used) {
            flow_ids.read(flow_id, hashes.reg_idx32);
            dune.collision = flow_id != hashes.flow_id;
        } else {
            dune.collision = false;
        }
        UpdateUsedFlowIds();
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

    Hash_t hashes;

    apply {
        InsertDuneHeaderIfNotPresent();
        // Check if flow is known and populate meta.flow_class
        IsFlowClassKnownLocally.apply(hdr, meta);
        if (UNKNOWN_FLOW_CLASS == meta.flow_class) {
            ComputeHashes.apply(hashes, hdr, meta);
            CheckCollision.apply(hashes, hdr.dune);
            if (UNKNOWN_FLOW_CLASS != hdr.dune.flow_class) {
                // Flow is known by a previous switch but not locally
                // TODO
                // Can't remember what to do when colision is this specific case
                // Send digest and clear registers (in controller, no clear if collision)
                digest<FlowDigest_t>(1, {});
            } else {
                // Flow is neither know by a previous switch nor locally
                if (!hdr.dune.collision) {
                    // TODO : 
                    // - get and update packet count
                    // - same for statefull features (provided in separate controll block ?)
                    //   the following is a temporary name
                    GetAndUpdateStatefullFeatures.apply();
                } else {
                    // TODO :
                    // - pkt count = 0
                }

                // TODO :
                // if pkt count < inference point
                // - set flow features to 0 (provided in separate controll block ?)
                //   the following is a temporary name
                ResetFlowFeaturesIfInferencePointNotReached.apply();

                // TODO :
                // - Apply model (provided in separate controll block ?)
                //   the following is a temporary name
                InferenceModel.apply();
            }
        } else {
            // Flow is already locally known
            hdr.dune.flow_class = meta.flow_class;
            // TODO
            // Use local info to populate dune header
        }
    }
}

#endif
