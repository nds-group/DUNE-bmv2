#ifndef DUNE_INFERENCE_P4
#define DUNE_INFERENCE_P4

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

control CheckCollisionAndNewFlow(
    in Hash_t hashes, 
    inout Dune_h dune,
    out bool new_flow
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
            new_flow = false;
        } else {
            dune.collision = false;
            new_flow = true;
            flow_ids.write(hashes.reg_idx32, hashes.flow_id);
        }
        UpdateUsedFlowIds();
    }
}

control GetPktCount(
    in Hash_t hashes,
    out PktCount_t pkt_count
)
{
    register<PktCount_t>(NB_REG_ENTRIES) pkt_counts;
    apply {
        pkt_counts.read(pkt_count, hashes.reg_idx32);
        pkt_count = pkt_count + 1;
        pkt_counts.write(hashes.reg_idx32, pkt_count);
    }
}

#ifndef INFERENCE_POINT
    #error "The inference point of the model is not defined"
#elif INFERENCE_POINT < 1
    #error "The inference point of the model must be at least 1"
#endif

control ResetFlowFeaturesIfInferencePointNotReached(
    in PktCount_t pkt_count,
    inout StatefullFeatures_t statefull_features,
    out InferencePointStatus_t inference_point_status
)
{
    apply {
        if (pkt_count < INFERENCE_POINT) {
            inference_point_status = InferencePointStatus_t.BELOW_INFERENCE_POINT;
            GetStatefullFeaturesDefaultValues.apply(statefull_features);
        } else if (pkt_count > INFERENCE_POINT) {
            inference_point_status = InferencePointStatus_t.AFTER_INFERENCE_POINT;
        } else {
            inference_point_status = InferencePointStatus_t.AT_INFERENCE_POINT;
        }
    }
}

control Inference(
    inout Headers_t hdr,
    inout Metadata_t meta,
    inout standard_metadata_t std_meta
)
{
    Hash_t hashes;

    bool new_flow;
    PktCount_t pkt_count;
    StatefullFeatures_t statefull_features;
    Class_t class;

    InferencePointStatus_t inference_point_status;
    register<Class_t>(NB_REG_ENTRIES) FlowClassBeforeControllerUpdate;

    apply {
        // Check if flow is known and populate meta.flow_class
        IsFlowClassKnownLocally.apply(hdr, meta);
        if (UNKNOWN_FLOW_CLASS == meta.flow_class) {
            ComputeHashes.apply(hashes, hdr, meta);
            CheckCollisionAndNewFlow.apply(hashes, hdr.dune, new_flow);
            if (UNKNOWN_FLOW_CLASS != hdr.dune.flow_class) {
                // Flow is known by a previous switch but not locally
                // TODO
                // Can't remember what to do when colision is this specific case
                // Send digest and clear registers (in controller, no clear if collision)
                digest<FlowDigest_t>(1, {
                    hdr.ipv4.src_addr,
                    hdr.ipv4.dst_addr,
                    meta.src_port,
                    meta.dst_port,
                    hdr.ipv4.protocol,
                    hdr.dune.flow_class,
                    hashes.reg_idx
                });
            } else {
                // Flow is neither know by a previous switch nor locally
                if (!hdr.dune.collision) {
                    GetPktCount.apply(hashes, pkt_count);
                    UpdateAndGetStatefullFeatures.apply(
                        std_meta,
                        hashes,
                        pkt_count,
                        new_flow,
                        statefull_features
                    );
                } else {
                    pkt_count = 0;
                    GetStatefullFeaturesDefaultValues.apply(statefull_features);
                }
                // TODO MAYBE :
                // Split  :
                // - GetInferencePoint (in model file)
                // - GetInferencePointStatus (here)
                // - GetDefaultFlowFeaturesValues (move reset logic to ingress)
                ResetFlowFeaturesIfInferencePointNotReached.apply(
                    pkt_count,
                    statefull_features,
                    inference_point_status
                );
                if (inference_point_status == InferencePointStatus_t.AFTER_INFERENCE_POINT) {
                    FlowClassBeforeControllerUpdate.read(class, hashes.reg_idx32);
                } else {
                    InferenceModel.apply(
                        hdr,
                        meta,
                        std_meta,
                        statefull_features,
                        class
                    );
                }
                // TODO :
                // Inform the switch if the class different from UKNOWN
                // Also, populate DUNE header
                if (inference_point_status == InferencePointStatus_t.AT_INFERENCE_POINT) {
                    digest<FlowDigest_t>(2, {
                        hdr.ipv4.src_addr,
                        hdr.ipv4.dst_addr,
                        meta.src_port,
                        meta.dst_port,
                        hdr.ipv4.protocol,
                        class,
                        hashes.reg_idx
                    });
                }
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
