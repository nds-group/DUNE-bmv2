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
    bit<4> tcp_data_off;
    bit<16> src_port;
    bit<16> udp_len;
    bit<8> ip_ttl;
    bit<16> dst_port;
    bit<16> tcp_window;
};

struct Codewords_t {
    bit<7> codeword0_0;
    bit<13> codeword0_1;
    bit<9> codeword0_2;
    bit<18> codeword0_3;
    bit<18> codeword0_4;
    bit<19> codeword0_5;
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

    action SetCode0(bit<7> code0) {
        codewords.codeword0_0 = code0;
    }
    action SetCode1(bit<13> code0) {
        codewords.codeword0_1 = code0;
    }
    action SetCode2(bit<9> code0) {
        codewords.codeword0_2 = code0;
    }
    action SetCode3(bit<18> code0) {
        codewords.codeword0_3 = code0;
    }
    action SetCode4(bit<18> code0) {
        codewords.codeword0_4 = code0;
    }
    action SetCode5(bit<19> code0) {
        codewords.codeword0_5 = code0;
    }

    action nop() {}

    Features_t features;
    table TableFeature0{
	    key = {features.tcp_data_off: range @name("feature0");}
	    actions = {@defaultonly nop; SetCode0;}
	    size = 10;
        const default_action = nop();
	}
    table TableFeature1{
	    key = {features.src_port: range @name("feature1");}
	    actions = {@defaultonly nop; SetCode1;}
	    size = 15;
        const default_action = nop();
	}
    table TableFeature2{
        key = {features.udp_len: range @name("feature2");}
	    actions = {@defaultonly nop; SetCode2;}
	    size = 15;
        const default_action = nop();
	}
    table TableFeature3{
	    key = {features.ip_ttl: range @name("feature3");}
	    actions = {@defaultonly nop; SetCode3;}
	    size = 15;
        const default_action = nop();
	}
    table TableFeature4{
	    key = {features.dst_port: range @name("feature4");}
	    actions = {@defaultonly nop; SetCode4;}
	    size = 20;
        const default_action = nop();
	}
    table TableFeature5{
	    key = {features.tcp_window: range @name("feature5");}
	    actions = {@defaultonly nop; SetCode5;}
	    size = 20;
        const default_action = nop();
	}

    action SetClass0(bit<8> classe) {
        class = classe;
    }
    action SetClass0ToUnknown() {
        class = UNKNOWN_FLOW_CLASS;
    }
	table CodeTable0{
        key = {
            codewords.codeword0_0: ternary;
            codewords.codeword0_1: ternary;
            codewords.codeword0_2: ternary;
            codewords.codeword0_3: ternary;
            codewords.codeword0_4: ternary;
            codewords.codeword0_5: ternary;
        }
	    actions = {SetClass0; @defaultonly SetClass0ToUnknown;}
	    size = 85;
        const default_action = SetClass0ToUnknown();
	}

    apply {
        if (hdr.ipv4.protocol == IPv4Proto.TCP) {
            features.tcp_data_off = hdr.tcp.data_offset;
        } else {
            features.tcp_data_off = 0;
        }
        features.src_port = meta.src_port;
        if (hdr.ipv4.protocol == IPv4Proto.UDP) {
            features.udp_len = hdr.udp.length;
        } else {
            features.udp_len = 0;
        }
        features.ip_ttl = hdr.ipv4.ttl;
        features.dst_port = meta.dst_port;
        if (hdr.ipv4.protocol == IPv4Proto.TCP) {
            features.tcp_window = hdr.tcp.window;
        } else {
            features.tcp_window = 0;
        }

        TableFeature0.apply();
        TableFeature1.apply();
        TableFeature2.apply();
        TableFeature3.apply();
        TableFeature4.apply();
        TableFeature5.apply();

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
