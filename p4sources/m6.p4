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

#include "dune_headers.p4"

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
    bit<16> ip_len;
    bit<8> ip_ttl;
    bit<16> tcp_window;
    bit<16> src_port;
    bit<16> dst_port;
};

struct Codewords_t {
    bit<32> codeword0_0;
    bit<12> codeword0_1;
    bit<10> codeword0_2;
    bit<32> codeword0_3;
    bit<42> codeword0_4;
}

control InferenceModel(
    in Headers_t hdr,
    in Metadata_t meta,
    in standard_metadata_t std_meta,
    in StatefullFeatures_t statefull_features,
    out Class_t class
)
{
    Codewords_t codewords = {0,0,0,0,0};
    action SetCode0(bit<32> code0) {
        codewords.codeword0_0 = code0;
    }
    action SetCode1(bit<12> code0) {
        codewords.codeword0_1 = code0;
    }
    action SetCode2(bit<10> code0) {
        codewords.codeword0_2 = code0;
    }
    action SetCode3(bit<32> code0) {
        codewords.codeword0_3 = code0;
    }
    action SetCode4(bit<42> code0) {
        codewords.codeword0_4 = code0;
    }

    action nop() {}

    Features_t features;
    //  ['ip.len' 'ip.ttl' 'tcp.window_size_value' 'srcport' 'dstport']
    table TableFeature0{
	    key = {features.ip_len: range @name("feature0");}
	    actions = {@defaultonly nop; SetCode0;}
	    size = 30;
        const default_action = nop();
	}
    table TableFeature1{
	    key = {features.ip_ttl: range @name("feature1");}
	    actions = {@defaultonly nop; SetCode1;}
	    size = 15;
        const default_action = nop();
	}
    table TableFeature2{
        key = {features.tcp_window: range @name("feature2");}
	    actions = {@defaultonly nop; SetCode2;}
	    size = 15;
        const default_action = nop();
	}
    table TableFeature3{
	    key = {features.src_port: range @name("feature3");}
	    actions = {@defaultonly nop; SetCode3;}
	    size = 40;
        const default_action = nop();
	}
    table TableFeature4{
	    key = {features.dst_port: range @name("feature4");}
	    actions = {@defaultonly nop; SetCode4;}
	    size = 50;
        const default_action = nop();
	}

    action SetClass0(bit<8> classe) {
        class = classe;
    }
    action SetClass0ToUnknown() {
        class = UNKNOWN_FLOW_CLASS;
    }
	table CodeTable0 {
        key = {
            codewords.codeword0_0: ternary;
            codewords.codeword0_1: ternary;
            codewords.codeword0_2: ternary;
            codewords.codeword0_3: ternary;
            codewords.codeword0_4: ternary;
        }
	    actions = {SetClass0; @defaultonly SetClass0ToUnknown;}
	    size = 129;
        const default_action = SetClass0ToUnknown();
	}

    apply {
        features.ip_len = hdr.ipv4.total_length;
        features.ip_ttl = hdr.ipv4.ttl;
        if (hdr.ipv4.protocol == IPv4Proto.TCP) {
            features.tcp_window = hdr.tcp.window;
        } else {
            features.tcp_window = 0;
        }
        features.src_port = meta.src_port;
        features.dst_port = meta.dst_port;

        TableFeature0.apply();
        TableFeature1.apply();
        TableFeature2.apply();
        TableFeature3.apply();
        TableFeature4.apply();

        CodeTable0.apply();
    }
}

// The following headers must be included after the declaration with
// the names mentionned in the WARNING at the top of the file
// otherwise the compilation will fail

#include "dune_ingress_parser.p4"
#include "dune_verify_checksum.p4"
#include "dune_ingress.p4"
#include "dune_egress.p4"
#include "dune_compute_checksum.p4"
#include "dune_egress_deparser.p4"

V1Switch(
    DuneIngressParser(),
    DuneVerifyChecksum(),
    DuneIngress(),
    DuneEgress(),
    DuneComputeChecksum(),
    DuneEgressDeparser()
) main;
