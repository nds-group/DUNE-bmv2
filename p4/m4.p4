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
    bit<4> tcp_data_off;
    bit<16> src_port;
    bit<16> udp_len;
    bit<8> ip_ttl;
    bit<16> dst_port;
    bit<16> tcp_window;
};

struct Codewords_t {
    bit<7> codeword1_0;
    bit<13> codeword1_1;
    bit<9> codeword1_2;
    bit<18> codeword1_3;
    bit<18> codeword1_4;
    bit<19> codeword1_5;
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

    action SetCode5(bit<7> code0) {
        codewords.codeword1_0 = code0;
    }
    action SetCode6(bit<13> code0) {
        codewords.codeword1_1 = code0;
    }
    action SetCode7(bit<9> code0) {
        codewords.codeword1_2 = code0;
    }
    action SetCode8(bit<18> code0) {
        codewords.codeword1_3 = code0;
    }
    action SetCode9(bit<18> code0) {
        codewords.codeword1_4 = code0;
    }
    action SetCode10(bit<19> code0) {
        codewords.codeword1_5 = code0;
    }

    action nop() {}

    Features_t features;
    table TableFeature5{
	    key = {features.tcp_data_off: range @name("feature5");}
	    actions = {@defaultonly nop; SetCode5;}
	    size = 10;
        const default_action = nop();
	}
    table TableFeature6{
	    key = {features.src_port: range @name("feature6");}
	    actions = {@defaultonly nop; SetCode6;}
	    size = 15;
        const default_action = nop();
	}
    table TableFeature7{
        key = {features.udp_len: range @name("feature7");}
	    actions = {@defaultonly nop; SetCode7;}
	    size = 15;
        const default_action = nop();
	}
    table TableFeature8{
	    key = {features.ip_ttl: range @name("feature8");}
	    actions = {@defaultonly nop; SetCode8;}
	    size = 15;
        const default_action = nop();
	}
    table TableFeature9{
	    key = {features.dst_port: range @name("feature9");}
	    actions = {@defaultonly nop; SetCode9;}
	    size = 20;
        const default_action = nop();
	}
    table TableFeature10{
	    key = {features.tcp_window: range @name("feature10");}
	    actions = {@defaultonly nop; SetCode10;}
	    size = 20;
        const default_action = nop();
	}

    action SetClass1(bit<8> classe) {
        class = classe;
    }
    action SetClass1ToUnknown() {
        class = UNKNOWN_FLOW_CLASS;
    }
	table CodeTable1{
        key = {
            codewords.codeword1_0: ternary;
            codewords.codeword1_1: ternary;
            codewords.codeword1_2: ternary;
            codewords.codeword1_3: ternary;
            codewords.codeword1_4: ternary;
            codewords.codeword1_5: ternary;
        }
	    actions = {SetClass1; @defaultonly SetClass1ToUnknown;}
	    size = 85;
        const default_action = SetClass1ToUnknown();
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

        TableFeature5.apply();
        TableFeature6.apply();
        TableFeature7.apply();
        TableFeature8.apply();
        TableFeature9.apply();
        TableFeature10.apply();

        CodeTable1.apply();
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
