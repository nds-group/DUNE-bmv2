#include <core.p4>
#include <v1model.p4>

// Warning : 
// The following names :
// - GetAndUpdateStatefullFeatures
// - ResetFlowFeaturesIfInferencePointNotReached
// - InferenceModel
// are shared with the ingress control block. They must be the same
// or the compilation will fail.

control GetAndUpdateStatefullFeatures()
{
    apply {
    }
}

control ResetFlowFeaturesIfInferencePointNotReached()
{
    apply {
    }
}

control InferenceModel()

{
    apply {
    }
}

// The following headers must be included after the declaration of the
// 3 control blocks mentionned in the WARNING at the top of the file
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
