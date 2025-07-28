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
    bit<16> max_length;
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
    bit<16> max_length;
    register<bit<16>>(NB_REG_ENTRIES) flows_max_length;
    action GetUpdateMaxLength () {
        flows_max_length.read(max_length, hashes.reg_idx32);
        if (new_flow || max_length < hdr.ipv4.total_length) {
            max_length = hdr.ipv4.total_length;
            flows_max_length.write(hashes.reg_idx32, max_length);
        }
    }

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
        GetUpdateMaxLength();
        GetUpdateTotalLength();
        statefull_features = {
            max_length = max_length,
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
            max_length = 0,
            total_length = 0
        };
    }
}

#define INFERENCE_POINT 4

struct Features_t {
    bit<16> dst_port;
    bit<4> tcp_len;
    bit<16> tcp_window;
}

struct Codewords_t {
    bit<10> codeword0_0;
    bit<5> codeword0_1;
    bit<8> codeword0_2;
    bit<4> codeword0_3;
    bit<13> codeword0_4;

    bit<10> codeword1_0;
    bit<2> codeword1_1;
    bit<14> codeword1_2;
    bit<8> codeword1_3;
    bit<6> codeword1_4;

    bit<10> codeword2_0;
    bit<6> codeword2_1;
    bit<10> codeword2_2;
    bit<9> codeword2_3;
    bit<5> codeword2_4;
}

struct VotingClasses_t {
    Class_t class0;
    Class_t class1;
    Class_t class2;
}

control InferenceModel(
    in Headers_t hdr,
    in Metadata_t meta,
    in standard_metadata_t std_meta,
    in StatefullFeatures_t statefull_features,
    out Class_t class
)
{
    Codewords_t codewords = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    action SetCode0(bit<10> code0, bit<10> code1, bit<10> code2) {
        codewords.codeword0_0 = code0;
        codewords.codeword1_0 = code1;
        codewords.codeword2_0 = code2;
    }
    action SetCode1(bit<5> code0, bit<2> code1, bit<6> code2) {
        codewords.codeword0_1 = code0;
        codewords.codeword1_1 = code1;
        codewords.codeword2_1 = code2;
    }
    action SetCode2(bit<8> code0, bit<14> code1, bit<10> code2) {
        codewords.codeword0_2 = code0;
        codewords.codeword1_2 = code1;
        codewords.codeword2_2 = code2;
    }
    action SetCode3(bit<4> code0, bit<8> code1, bit<9> code2) {
        codewords.codeword0_3 = code0;
        codewords.codeword1_3 = code1;
        codewords.codeword2_3 = code2;
    }
    action SetCode4(bit<13> code0, bit<6> code1, bit<5> code2) {
        codewords.codeword0_4 = code0;
        codewords.codeword1_4 = code1;
        codewords.codeword2_4 = code2;
    }

    action nop() {}

    Features_t features;
    // FEATURES: ['dstport' 'tcp.hdr_len' 'tcp.window_size_value' 'Max Packet Length' 'Packet Length Total']
    table TableFeature0{
        key = {features.dst_port: range @name("feature0");}
	    actions = {@defaultonly nop; SetCode0;}
	    size = 15;
        const default_action = nop();
	}
    table TableFeature1{
	    key = {features.tcp_len: range @name("feature1");}
	    actions = {@defaultonly nop; SetCode1;}
	    size = 10;
        const default_action = nop();
	}
    table TableFeature2{
	    key = {features.tcp_window: range @name("feature2");}
	    actions = {@defaultonly nop; SetCode2;}
	    size = 30;
        const default_action = nop();
	}
    table TableFeature3{
	    key = {statefull_features.max_length: range @name("feature3");}
	    actions = {@defaultonly nop; SetCode3;}
	    size = 30;
        const default_action = nop();
	}
    table TableFeature4{
	    key = {statefull_features.total_length: range @name("feature4");}
	    actions = {@defaultonly nop; SetCode4;}
	    size = 30;
        const default_action = nop();
	}

    VotingClasses_t voting_classes = {0,0,0};

    action SetClass0(bit<8> classe) {
        voting_classes.class0 = classe;
    }
    action SetClass1(bit<8> classe) {
        voting_classes.class1 = classe;
    }
    action SetClass2(bit<8> classe) {
        voting_classes.class2 = classe;
    }

    table CodeTable0{
        key = {
            codewords.codeword0_0: ternary;
            codewords.codeword0_1: ternary;
            codewords.codeword0_2: ternary;
            codewords.codeword0_3: ternary;
            codewords.codeword0_4: ternary;
        }
	    actions = {@defaultonly nop; SetClass0;}
	    size = 41;
        const default_action = nop();
	}
	table CodeTable1{
        key = {
            codewords.codeword1_0: ternary;
            codewords.codeword1_1: ternary;
            codewords.codeword1_2: ternary;
            codewords.codeword1_3: ternary;
            codewords.codeword1_4: ternary;
        }
	    actions = {@defaultonly nop; SetClass1;}
	    size = 41;
        const default_action = nop();
	}
    table CodeTable2{
        key = {
            codewords.codeword2_0: ternary;
            codewords.codeword2_1: ternary;
            codewords.codeword2_2: ternary;
            codewords.codeword2_3: ternary;
            codewords.codeword2_4: ternary;
        }
	    actions = {@defaultonly nop; SetClass2;}
	    size = 41;
        const default_action = nop();
	}

    action SetVotingResult(Class_t vote_result) {
        class = vote_result;
    }
    action SetVotingResultToUnknown() {
        class = UNKNOWN_CLASS;
    }
    table VotingTable {
        key = {
            voting_classes.class0: exact;
            voting_classes.class1: exact;
            voting_classes.class2: exact;
        }
        actions = {SetVotingResult; @defaultonly SetVotingResultToUnknown;}
        size = 64;
        const default_action = SetVotingResultToUnknown();
    }
 
 
    apply {
        features.dst_port = meta.dst_port;
        if (hdr.ipv4.protocol == IPv4Proto.TCP) {
            features.tcp_len = hdr.tcp.data_offset;
        } else {
            features.tcp_len = 0;
        }
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
        CodeTable1.apply();
        CodeTable2.apply();

        VotingTable.apply();

        class += 5;
        if (8 == class) {
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
