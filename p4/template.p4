#include <core.p4>
#include <v1model.p4>

// Warning : 
// The following names :
// - StatefullFeatures_t
// - UpdateStatefullFeaturesIfInferencePointReached
// - InitStatefullFeatures
// - InferenceModel
// are shared with the ingress control block. They must be the same
// or the compilation will fail.

struct StatefullFeatures_t {
}

control UpdateStatefullFeaturesIfInferencePointReached(
    in bit<8> pkt_count,
    in bool new_flow,
    inout StatefullFeatures_t statefull_features
)
{
    const bit<8> inference_point = 3;

    apply {
        if (pkt_count == inference_point) {
            // TODO :
            // really get and update the features
            statefull_features = {
            };
        }
    }
}

control InitStatefullFeatures(
    out StatefullFeatures_t statefull_features
)
{
    apply {
        statefull_features = {
        };
    }
}

control InferenceModel(
)
{
    apply {
    }
}

// The following headers must be included after the declaration with
// the names mentionned in the WARNING at the top of the file
// otherwise the compilation will fail

#include "include/dune_ingress_parser.p4"
#include "include/dune_verify_checksum.p4"
#include "include/dune_ingress.p4"
#include "include/dune_egress.p4"
#include "include/dune_compute_checksum.p4"
#include "include/dune_egress_deparser.p4"

V1Switch(
    DuneIngressParser(),
    DuneVerifyChecksum(),
    DuneIngress(),
    DuneEgress(),
    DuneComputeChecksum(),
    DuneEgressDeparser()
) main;
