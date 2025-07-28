#ifndef DUNE_INGRESS_P4
#define DUNE_INGRESS_P4

#include "dune_headers.p4"

#ifndef ENABLE_INFERENCE
#define ENABLE_INFERENCE 1
#endif

#if ENABLE_INFERENCE
#include "dune_inference.p4"
#endif

control Forwarding(
    inout standard_metadata_t std_meta
)
{
    apply {
        // TODO :
        // Do the forwarding
        std_meta.egress_spec = 2;
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
                class_type = UNKNOWN_CLASS_TYPE,
                class = UNKNOWN_CLASS,
                collision = false,
                pkt_count = 0,
                model_id = NO_MODEL_ID,
            };
            hdr.ethernet.ether_type = EtherType.DUNE;
        }
    }

    apply {
        // Because rejected packets are not automatically droped on Bmv2
        if (std_meta.parser_error != error.NoError) {
            mark_to_drop(std_meta);
            exit;
        }
        InsertDuneHeaderIfNotPresent();
        // TODO better
#if ENABLE_INFERENCE
        Inference.apply(hdr, meta, std_meta);
#endif
        Forwarding.apply(std_meta);
    }
}

#endif
