#include <core.p4>
#include <v1model.p4>

// Warning : 
// The following names :
// - StatefullFeatures_t
// - UpdateAndGetStatefullFeatures
// - GetStatefullFeaturesDefaultValues
// - INFERENCE_POINT
// - InferenceModel
// are shared with the ingress control block. They must be the same
// or the compilation will fail.

#include "dune_headers.p4"

struct StatefullFeatures_t {
    bit<16> total_length;
}

control UpdateAndGetStatefullFeatures(
    in Headers_t hdr,
    in standard_metadata_t std_meta,
    in Hash_t hashes,
    in PktCount_t pkt_count,
    in bool new_flow,
    out StatefullFeatures_t statefull_features
)
{
    bit<16> total_length;
    register<bit<16>>(NB_REG_ENTRIES) flows_total_length;
    action GetUpdateTotalLength () {
        if (new_flow) {
            total_length = 0;
        } else {
            flows_total_length.read(total_length, hashes.reg_idx32);
        }
        total_length += hdr.ipv4.total_length;
        flows_total_length.write(hashes.reg_idx32, total_length);
    }

    apply {
        GetUpdateTotalLength();
        statefull_features = {
            total_length = total_length
        };
    }
}

control GetStatefullFeaturesDefaultValues(
    out StatefullFeatures_t statefull_features
)
{
    apply {
        statefull_features = {
            total_length = 0
        };
    }
}

#define INFERENCE_POINT 2

struct Features_t {
    bit<8> ip_ttl;
    bit<16> udp_len;
    bit<16> ip_len;
    bit<16> tcp_window;
};

struct Codewords_t {
    bit<4> codeword0_0;
    bit<4> codeword0_1;
    bit<14> codeword0_2;
    bit<7> codeword0_3;
    bit<11> codeword0_4;
};

control InferenceModel(
    in Headers_t hdr,
    in Metadata_t meta,
    in standard_metadata_t std_meta,
    in StatefullFeatures_t statefull_features,
    out Class_t class
)
{
    Codewords_t codewords = {0,0,0,0,0};

    action SetCode0(bit<4> code0) {
        codewords.codeword0_0 = code0;
    }
    action SetCode1(bit<4> code0) {
        codewords.codeword0_1 = code0;
    }
    action SetCode2(bit<14> code0) {
        codewords.codeword0_2 = code0;
    }
     action SetCode3(bit<7> code0) {
        codewords.codeword0_3 = code0;
    }
    action SetCode4(bit<11> code0) {
        codewords.codeword0_4 = code0;
    }

    action nop() {}

    Features_t features;
    // FEATURES: ['ip.ttl' 'udp.length' 'ip.len' 'Packet Length Total' 'tcp.window_size_value']
    table TableFeature0{
	    key = {features.ip_ttl: range @name("feature0");}
	    actions = {@defaultonly nop; SetCode0;}
	    size = 10;
        const default_action = nop();
	}
    table TableFeature1{
	    key = {features.udp_len: range @name("feature1");}
	    actions = {@defaultonly nop; SetCode1;}
	    size = 10;
        const default_action = nop();
	}
    table TableFeature2{
        key = {features.ip_len: range @name("feature2");}
	    actions = {@defaultonly nop; SetCode2;}
	    size = 20;
        const default_action = nop();
	}
    table TableFeature3{
	    key = {statefull_features.total_length: range @name("feature3");}
	    actions = {@defaultonly nop; SetCode3;}
	    size = 15;
        const default_action = nop();
	}
    table TableFeature4{
	    key = {features.tcp_window: range @name("feature4");}
	    actions = {@defaultonly nop; SetCode4;}
	    size = 20;
        const default_action = nop();
	}

    action SetClass0(bit<8> classe) {
        class = classe;
    }
    action SetClass0ToUnknown() {
        class = UNKNOWN_CLASS;
    }

    table CodeTable0{
        key = {
            codewords.codeword0_0: ternary;
            codewords.codeword0_1: ternary;
            codewords.codeword0_2: ternary;
            codewords.codeword0_3: ternary;
            codewords.codeword0_4: ternary;
        }
        actions = {SetClass0; @defaultonly SetClass0ToUnknown;}
        size = 41;
        const default_action = SetClass0ToUnknown();
    }

    apply {
        features.ip_ttl = hdr.ipv4.ttl;
        if (hdr.ipv4.protocol == IPv4Proto.UDP) {
            features.udp_len = hdr.udp.length;
        } else {
            features.udp_len = 0;
        }
        features.ip_len = hdr.ipv4.total_length;
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

        CodeTable0.apply();

        class += 0;
        if (2 == class) {
            class = UNKNOWN_CLASS;
        }
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
