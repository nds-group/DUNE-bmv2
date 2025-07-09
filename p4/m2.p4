#include <core.p4>
#include <v1model.p4>

// Warning : 
// The following names :
// - StatefullFeatures_t
// - UpdateAndGetStatefullFeatures
// - GetStatefullFeaturesDefaultValues
// - ResetFlowFeaturesIfInferencePointNotReached
// - InferenceModel
// are shared with the ingress control block. They must be the same
// or the compilation will fail.

#include "include/dune_headers.p4"

struct StatefullFeatures_t {
    // This model has no statefull features
}

control UpdateAndGetStatefullFeatures(
    in standard_metadata_t std_meta,
    in Hash_t hashes,
    in PktCount_t pkt_count,
    in bool new_flow,
    inout StatefullFeatures_t statefull_features
)
{
    apply {
        // This model has no statefull features
        statefull_features = {};
    }
}

control GetStatefullFeaturesDefaultValues(
    out StatefullFeatures_t statefull_features
)
{
    apply {
        // This model has no statefull features
        statefull_features = {};
    }
}

control ResetFlowFeaturesIfInferencePointNotReached(
    in PktCount_t pkt_count,
    inout StatefullFeatures_t statefull_features,
    out InferencePointStatus_t inference_point_status
)
{
    // This model has no statefull features
    const PktCount_t inference_point = 0;

    apply {
        if (pkt_count < inference_point) {
            inference_point_status = InferencePointStatus_t.BELOW_INFERENCE_POINT;
            GetStatefullFeaturesDefaultValues.apply(statefull_features);
        } else if (pkt_count < inference_point) {
            inference_point_status = InferencePointStatus_t.AFTER_INFERENCE_POINT;
        } else {
            inference_point_status = InferencePointStatus_t.AT_INFERENCE_POINT;
        }
    }
}

struct Features_t {
    bit<16> udp_len;
    bit<16> ip_len;
    bit<16> src_port;
    bit<16> dst_port;
    bit<8> ip_ttl;
    bit<16> tcp_window;
};

struct Codewords_t {
    bit<67> codeword3_0;
    bit<69> codeword3_1;
    bit<105> codeword3_2;
    bit<90> codeword3_3;
    bit<63> codeword3_4;
    bit<86> codeword3_5;
}

control InferenceModel(
    in Headers_t hdr,
    in Metadata_t meta,
    in standard_metadata_t std_meta,
    in StatefullFeatures_t statefull_features,
    out Class_t class
)
{
    Codewords_t codewords = {0,0,0,0,0,0};

    action SetCode3(bit<67> code0) {
        codewords.codeword3_0 = code0;
    }
    action SetCode4(bit<69> code0) {
        codewords.codeword3_1 = code0;
    }
    action SetCode5(bit<105> code0) {
        codewords.codeword3_2 = code0;
    }
     action SetCode6(bit<90> code0) {
        codewords.codeword3_3 = code0;
    }
    action SetCode7(bit<63> code0) {
        codewords.codeword3_4 = code0;
    }
    action SetCode8(bit<86> code0) {
        codewords.codeword3_5 = code0;
    }

    action nop() {}

    Features_t features;
    // FEATURES: ['udp.length' 'ip.len' 'dstport' 'srcport' 'ip.ttl' 'tcp.window_size_value']
    table TableFeature3{
        key = {features.udp_len: range @name("feature3");}
        actions = {@defaultonly nop; SetCode3;}
        size = 70;
        const default_action = nop();
    }
    table TableFeature4{
        key = {features.ip_len: range @name("feature4");}
        actions = {@defaultonly nop; SetCode4;}
        size = 70;
        const default_action = nop();
    }
    table TableFeature5{
        key = {features.dst_port: range @name("feature5");}
        actions = {@defaultonly nop; SetCode5;}
        size = 100;
        const default_action = nop();
    }
    table TableFeature6{
        key = {features.src_port: range @name("feature6");}
        actions = {@defaultonly nop; SetCode6;}
        size = 80;
        const default_action = nop();
    }
    table TableFeature7{
        key = {features.ip_ttl: range @name("feature7");}
        actions = {@defaultonly nop; SetCode7;}
        size = 50;
        const default_action = nop();
    }
    table TableFeature8{
        key = {features.tcp_window: range @name("feature8");}
        actions = {@defaultonly nop; SetCode8;}
        size = 90;
        const default_action = nop();
    }

    action SetClass3(bit<8> classe) {
        class = classe;
    }
    action SetClass3ToUnknown() {
        class = UNKNOWN_FLOW_CLASS;
    }

    table CodeTable3{
        key = {
            codewords.codeword3_0: ternary;
            codewords.codeword3_1: ternary;
            codewords.codeword3_2: ternary;
            codewords.codeword3_3: ternary;
            codewords.codeword3_4: ternary;
            codewords.codeword3_5: ternary;
        }
        actions = {SetClass3; @defaultonly SetClass3ToUnknown;}
        size = 481;
        const default_action = SetClass3ToUnknown();
    }

    apply {
        if (hdr.ipv4.protocol == IPv4Proto.UDP) {
            features.udp_len = hdr.udp.length;
        } else {
            features.udp_len = 0;
        }
        features.ip_len = hdr.ipv4.total_length;
        features.dst_port = meta.dst_port;
        features.src_port = meta.src_port;
        features.ip_ttl = hdr.ipv4.ttl;
        if (hdr.ipv4.protocol == IPv4Proto.TCP) {
            features.tcp_window = hdr.tcp.window;
        } else {
            features.tcp_window = 0;
        }

        TableFeature3.apply();
        TableFeature4.apply();
        TableFeature5.apply();
        TableFeature6.apply();
        TableFeature7.apply();
        TableFeature8.apply();

        CodeTable3.apply();
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
