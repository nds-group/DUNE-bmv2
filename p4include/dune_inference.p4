#ifndef DUNE_INFERENCE_P4
#define DUNE_INFERENCE_P4

#include "dune_headers.p4"

control IsFlowClassKnownLocally(
    in Headers_t hdr,
    in Metadata_t meta,
    out Class_t class
)
{
    action MetaSetFlowClass(Class_t flow_class) {
        class = flow_class;
    }

    action MetaSetUnkownFlowClass() {
        class = UNKNOWN_CLASS;
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
    in Headers_t hdr,
    in Metadata_t meta
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
    out bool collision,
    out bool is_new_flow
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
            collision = flow_id != hashes.flow_id;
            is_new_flow = false;
        } else {
            collision = false;
            is_new_flow = true;
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

// The MODEL_ID is used to ensure correct execution of the models
// with respect to the dependencies
#ifndef MODEL_ID
    #error "The model id is not defined"
#elif MODEL_ID < 1
    #error "The model id must be at least 1"
#endif

control Inference(
    inout Headers_t hdr,
    inout Metadata_t meta,
    inout standard_metadata_t std_meta
)
{
    Hash_t hashes;
    StatefullFeatures_t statefull_features;

    register<Class_t>(NB_REG_ENTRIES) FlowClassBeforeControllerUpdate;

    ClassType_t class_type;
    Class_t class;

    bool collision;
    PktCount_t pkt_count;
    bool is_new_flow;

    bool flow_known_locally;

    bool type_is_fl_hdr;
    bool class_is_known_hdr;

    apply {
        if (hdr.dune.model_id != MODEL_ID - 1) {
            return;
        }

        class_type = UNKNOWN_CLASS_TYPE;
        class = UNKNOWN_CLASS;
        collision = false;
        pkt_count = 0;

        type_is_fl_hdr = hdr.dune.class_type == ClassType_t.FL;
        class_is_known_hdr = hdr.dune.class != UNKNOWN_CLASS;

        ComputeHashes.apply(hashes, hdr, meta);
        GetStatefullFeaturesDefaultValues.apply(statefull_features);

        // Updating the features of the flow
        if (!(type_is_fl_hdr && class_is_known_hdr)) {
            IsFlowClassKnownLocally.apply(hdr, meta, class);
            flow_known_locally = class != UNKNOWN_CLASS;
            // If the flow is classified in the table than we have cleared
            // registers, skipping the next part to not repopulate the registers
            if (!flow_known_locally) {
                CheckCollisionAndNewFlow.apply(hashes, collision, is_new_flow);
                if (!collision) {
                    // The flow ID doesn't colides with a previous one so we can track
                    // the number of packets we received from it and other features.
                    GetPktCount.apply(hashes, pkt_count);
                    if (pkt_count <= INFERENCE_POINT) {
                        UpdateAndGetStatefullFeatures.apply(
                            hdr, std_meta, hashes, pkt_count, is_new_flow, statefull_features
                        );
                    }
                }
            }
        }

        if ((!class_is_known_hdr &&
            !(type_is_fl_hdr && !class_is_known_hdr && pkt_count >= INFERENCE_POINT)) ||
            (!collision && !type_is_fl_hdr && class_is_known_hdr && pkt_count < INFERENCE_POINT)) {
            GetStatefullFeaturesDefaultValues.apply(statefull_features);
            class_type = ClassType_t.PL;
        } else {
            class_type = ClassType_t.FL;
        }

        if (!class_is_known_hdr ||
            (!collision && !type_is_fl_hdr && class_is_known_hdr && pkt_count <= INFERENCE_POINT)) {
            if (class_type == ClassType_t.FL && pkt_count > INFERENCE_POINT) {
                FlowClassBeforeControllerUpdate.read(class, hashes.reg_idx32);
            } else {
                InferenceModel.apply(
                    hdr, meta, std_meta, statefull_features, class
                );
            }
            if (class_type == ClassType_t.FL
                && class != UNKNOWN_CLASS
                && hdr.dune.class_type == ClassType_t.FL
                && hdr.dune.class == UNKNOWN_CLASS) {
                digest<FlowDigest_t>(0, {
                    hdr.ipv4.src_addr,
                    hdr.ipv4.dst_addr,
                    meta.src_port,
                    meta.dst_port,
                    hdr.ipv4.protocol,
                    class,
                    hashes.reg_idx,
                });
            }
        }

        // Load results from header to not overwrite them
        if (hdr.dune.class != UNKNOWN_CLASS) {
            class_type = hdr.dune.class_type;
            class = hdr.dune.class;
        }

        // Update the results
        hdr.dune.class_type = class_type;
        hdr.dune.class = class;
        // For statistics do not overide a collision that happened upstream;
        hdr.dune.collision = hdr.dune.collision || collision;
    }
}

#endif
