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
    bit<8> psh_flag_count;
    bit<16> max_length;
    bit<8> ack_flag_count;
    bit<16> min_length;
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

    bit<8> psh_flag_count;
    register<bit<8>>(NB_REG_ENTRIES) flows_psh_flag_count;
    action GetUpdatePSHFlagCount () {
        flows_psh_flag_count.read(psh_flag_count, hashes.reg_idx32);
        if (hdr.ipv4.protocol == IPv4Proto.TCP && hdr.tcp.psh == 1) {
            psh_flag_count += 1;
            flows_psh_flag_count.write(hashes.reg_idx32, psh_flag_count);
        }
    }

    bit<16> max_length;
    register<bit<16>>(NB_REG_ENTRIES) flows_max_length;
    action GetUpdateMaxLength () {
        flows_max_length.read(max_length, hashes.reg_idx32);
        if (new_flow || max_length < hdr.ipv4.total_length) {
            max_length = hdr.ipv4.total_length;
            flows_max_length.write(hashes.reg_idx32, max_length);
        }
    }

    bit<8> ack_flag_count;
    register<bit<8>>(NB_REG_ENTRIES) flows_ack_flag_count;
    action GetUpdateACKFlagCount () {
        flows_ack_flag_count.read(ack_flag_count, hashes.reg_idx32);
        if (hdr.ipv4.protocol == IPv4Proto.TCP && hdr.tcp.ack == 1) {
            ack_flag_count += 1;
            flows_ack_flag_count.write(hashes.reg_idx32, ack_flag_count);
        }
    }

    bit<16> min_length;
    register<bit<16>>(NB_REG_ENTRIES) flows_min_length;
    action GetUpdateMinLength () {
        flows_min_length.read(min_length, hashes.reg_idx32);
        if (new_flow || min_length < hdr.ipv4.total_length) {
            min_length = hdr.ipv4.total_length;
            flows_min_length.write(hashes.reg_idx32, min_length);
        }
    }

    apply {
        GetUpdateTotalLength();
        GetUpdatePSHFlagCount();
        GetUpdateMaxLength();
        GetUpdateACKFlagCount();
        GetUpdateMinLength();

        statefull_features = {
            total_length = total_length,
            psh_flag_count = psh_flag_count,
            max_length = max_length,
            ack_flag_count = ack_flag_count,
            min_length = min_length
        };
    }
}

control GetStatefullFeaturesDefaultValues(
    out StatefullFeatures_t statefull_features
)
{
    apply {
        statefull_features = {
            total_length = 0,
            psh_flag_count = 0,
            max_length = 0,
            ack_flag_count = 0,
            min_length = 0
        };
    }
}

#define INFERENCE_POINT 3

struct Features_t {
    bit<16> ip_len;
    bit<16> udp_len;
    bit<16> dst_port;
    bit<1> tcp_ack;
    bit<4> tcp_len;
    bit<8> ip_ttl;
    bit<16> tcp_window;
};

struct Codewords_t {
    bit<25> codeword0_0;
    bit<9> codeword0_1;
    bit<17> codeword0_2;
    bit<11> codeword0_3;
    bit<3> codeword0_4;
    bit<2> codeword0_5;
    bit<17> codeword0_6;
    bit<4> codeword0_7;
    bit<12> codeword0_8;
    bit<6> codeword0_9;
    bit<9> codeword0_10;
    bit<13> codeword0_11;
};

control InferenceModel(
    in Headers_t hdr,
    in Metadata_t meta,
    in standard_metadata_t std_meta,
    in StatefullFeatures_t statefull_features,
    out Class_t class
)
{
    Codewords_t codewords = {0,0,0,0,0,0,0,0,0,0,0,0};

    action SetCode0(bit<25> code0) {
        codewords.codeword0_0 = code0;
    }
    action SetCode1(bit<9> code0) {
        codewords.codeword0_1 = code0;
    }
    action SetCode2(bit<17> code0) {
        codewords.codeword0_2 = code0;
    }
    action SetCode3(bit<11> code0) {
        codewords.codeword0_3 = code0;
    }
    action SetCode4(bit<3> code0) {
        codewords.codeword0_4 = code0;
    }
    action SetCode5(bit<2> code0) {
        codewords.codeword0_5 = code0;
    }
    action SetCode6(bit<17> code0) {
        codewords.codeword0_6 = code0;
    }
    action SetCode7(bit<4> code0) {
        codewords.codeword0_7 = code0;
    }
    action SetCode8(bit<12> code0) {
        codewords.codeword0_8 = code0;
    }
    action SetCode9(bit<6> code0) {
        codewords.codeword0_9 = code0;
    }
    action SetCode10(bit<9> code0) {
        codewords.codeword0_10 = code0;
    }
    action SetCode11(bit<13> code0) {
        codewords.codeword0_11 = code0;
    }

    action nop() {}

    Features_t features;
    // FEATURES: ['ip.len' 'udp.length' 'Packet Length Total' 'dstport' 'tcp.flags.ack' 'PSH Flag Count' 'Max Packet Length' 'ACK Flag Count' 'Min Packet Length' 'tcp.hdr_len' 'ip.ttl' 'tcp.window_size_value']
    table TableFeature0{
	    key = {features.ip_len: range @name("feature0");}
	    actions = {@defaultonly nop; SetCode0;}
	    size = 25;
        const default_action = nop();
	}
    table TableFeature1{
	    key = {features.udp_len: range @name("feature1");}
	    actions = {@defaultonly nop; SetCode1;}
	    size = 10;
        const default_action = nop();
	}
    table TableFeature2{
	    key = {statefull_features.total_length: range @name("feature2");}
	    actions = {@defaultonly nop; SetCode2;}
	    size = 20;
        const default_action = nop();
	}
    table TableFeature3{
        key = {features.dst_port: range @name("feature3");}
	    actions = {@defaultonly nop; SetCode3;}
	    size = 15;
        const default_action = nop();
	}
    table TableFeature4{
        key = {features.tcp_ack: range @name("feature4");}
	    actions = {@defaultonly nop; SetCode4;}
	    size = 5;
        const default_action = nop();
	}
    table TableFeature5{
	    key = {statefull_features.psh_flag_count: range @name("feature5");}
	    actions = {@defaultonly nop; SetCode5;}
	    size = 5;
        const default_action = nop();
	}
    table TableFeature6{
	    key = {statefull_features.max_length: range @name("feature6");}
	    actions = {@defaultonly nop; SetCode6;}
	    size = 20;
        const default_action = nop();
	}
    table TableFeature7{
	    key = {statefull_features.ack_flag_count: range @name("feature7");}
	    actions = {@defaultonly nop; SetCode7;}
	    size = 5;
        const default_action = nop();
	}
    table TableFeature8{
	    key = {statefull_features.min_length: range @name("feature8");}
	    actions = {@defaultonly nop; SetCode8;}
	    size = 15;
        const default_action = nop();
	}
    table TableFeature9{
	    key = {features.tcp_len: range @name("feature9");}
	    actions = {@defaultonly nop; SetCode9;}
	    size = 10;
        const default_action = nop();
	}
    table TableFeature10{
	    key = {hdr.ipv4.ttl: range @name("feature10");}
	    actions = {@defaultonly nop; SetCode10;}
	    size = 10;
        const default_action = nop();
	}
    table TableFeature11{
	    key = {features.tcp_window: range @name("feature11");}
	    actions = {@defaultonly nop; SetCode11;}
	    size = 15;
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
            codewords.codeword0_6: ternary;
            codewords.codeword0_7: ternary;
            codewords.codeword0_8: ternary;
            codewords.codeword0_9: ternary;
            codewords.codeword0_10: ternary;
            codewords.codeword0_11: ternary;
        }
        actions = {SetClass0; @defaultonly SetClass0ToUnknown;}
        size = 41;
        const default_action = SetClass0ToUnknown();
    }

    apply {
        features.ip_len = hdr.ipv4.total_length;
        if (hdr.ipv4.protocol == IPv4Proto.UDP) {
            features.udp_len = hdr.udp.length;
        } else {
            features.udp_len = 0;
        }
        features.dst_port = meta.dst_port;
        if (hdr.ipv4.protocol == IPv4Proto.TCP) {
            features.tcp_ack = hdr.tcp.ack;
        } else {
            features.tcp_ack = 0;
        }
        if (hdr.ipv4.protocol == IPv4Proto.TCP) {
            features.tcp_len = hdr.tcp.data_offset;
        } else {
            features.tcp_len = 0;
        }
        features.ip_ttl = hdr.ipv4.ttl;
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
        TableFeature6.apply();
        TableFeature7.apply();
        TableFeature8.apply();
        TableFeature9.apply();
        TableFeature10.apply();
        TableFeature11.apply();

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
