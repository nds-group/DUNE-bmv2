#ifndef DUNE_INGRESS_P4
#define DUNE_INGRESS_P4

#include "dune_headers.p4"

#ifndef ENABLE_INFERENCE
#define ENABLE_INFERENCE 1
#endif

#define NO_MPLS_LABEL 0

#if ENABLE_INFERENCE
#include "dune_inference.p4"
#endif

control Forwarding(
    inout Headers_t hdr,
    inout standard_metadata_t std_meta
)
{
    action nop() {}

    action SetMplsLabel(MplsLabel_t label) {
        hdr.dune.mpls_label = label;
    }

    action SetEgressPort(bit<9> port) {
        std_meta.egress_spec = port;
    }

    table TableIngressPortToMPLS {
        key = {
            std_meta.ingress_port: exact;
        }
        actions = {
            SetMplsLabel;
            nop;
        }
        // TODO: change to compile-time variable
        size = 32;
        const default_action = nop();
    }

    table TableMPLSToEgressPort {
        key = {
            hdr.dune.mpls_label: exact;
        }
        actions = {
            SetEgressPort;
            nop;
        }
        // TODO: change to compile-time variable
        size = 1024;
        const default_action = nop();
    }

    apply {
        if (hdr.dune.mpls_label == NO_MPLS_LABEL) {
            TableIngressPortToMPLS.apply();
        }
        TableMPLSToEgressPort.apply();
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
                collision = 0,
                model_id = NO_MODEL_ID,
                mpls_label = 0,
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
        Forwarding.apply(hdr, std_meta);
    }
}

#endif
