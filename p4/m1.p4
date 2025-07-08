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

typedef bit<32> Time_t;

struct StatefullFeatures_t {
    Time_t flow_iat_max;
    Time_t flow_iat_min;
}

control GetThenUpdatePreviousPktTimestamp(
    in standard_metadata_t std_meta,
    in Hash_t hashes,
    out Time_t timestamp
)
{
    register<Time_t>(NB_REG_ENTRIES) previous_timestamps; 

    apply {
        previous_timestamps.read(timestamp, hashes.reg_idx32);
        previous_timestamps.write(
            hashes.reg_idx32,
            BMV2_TIME(std_meta.ingress_global_timestamp[31:0])
        );
    }
}

control UpdateAndGetStatefullFeatures(
    in standard_metadata_t std_meta,
    in Hash_t hashes,
    in PktCount_t pkt_count,
    in bool new_flow,
    out StatefullFeatures_t statefull_features
)
{
    Time_t iat;

    Time_t iat_max;
    register<Time_t>(NB_REG_ENTRIES) flows_iat_max;
    action GetUpdateFlowIatMax () {
        flows_iat_max.read(iat_max, hashes.reg_idx32);
        // Skip update on first packet of the flow
        // to not have ridiculous IAT
        if (!new_flow) {
            if (iat > iat_max) {
                iat_max = iat;
                flows_iat_max.write(hashes.reg_idx32, iat_max);
            }
        }
    }

    Time_t iat_min;
    register<Time_t>(NB_REG_ENTRIES) flows_iat_min;
    action GetUpdateFlowIatMin() {
        flows_iat_min.read(iat_min, hashes.reg_idx32);
        if (pkt_count <= 2) {
            // We do not have enough packets to establish a min
            // so force the update
            iat_min = iat;
            flows_iat_min.write(hashes.reg_idx32, iat_min);
        } else if (iat < iat_min) {
            iat_min = iat;
            flows_iat_min.write(hashes.reg_idx32, iat_min);
        }
    }

    Time_t timestamp;

    apply {
        GetThenUpdatePreviousPktTimestamp.apply(
            std_meta,
            hashes,
            timestamp
        );
        iat = BMV2_TIME(std_meta.ingress_global_timestamp[31:0]) - timestamp;
        GetUpdateFlowIatMax();
        GetUpdateFlowIatMin();
        statefull_features = {
            flow_iat_max = iat_max,
            flow_iat_min = iat_min
        };
    }
}

control GetStatefullFeaturesDefaultValues(
    out StatefullFeatures_t statefull_features
)
{
    apply {
        statefull_features = {
            flow_iat_max = 0,
            flow_iat_min = 0
        };
    } 
}


control ResetFlowFeaturesIfInferencePointNotReached(
    in PktCount_t pkt_count,
    inout StatefullFeatures_t statefull_features
)
{
    const PktCount_t inference_point = 3;

    apply {
        if (pkt_count < inference_point) {
            GetStatefullFeaturesDefaultValues.apply(statefull_features);
        } 
    }
}

struct Features_t {
    bit<16> udp_len;
}

struct Codewords_t {
    bit<9> codeword0_0;
    bit<11> codeword0_1;
    bit<20> codeword0_2;

    bit<13> codeword1_0;
    bit<7> codeword1_1;
    bit<20> codeword1_2;

    bit<15> codeword2_0;
    bit<7> codeword2_1;
    bit<18> codeword2_2;
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
    Codewords_t codewords = {0,0,0,0,0,0,0,0,0};

    action SetCode0(bit<9> code0, bit<13> code1, bit<15> code2) {
        codewords.codeword0_0 = code0;
        codewords.codeword1_0 = code1;
        codewords.codeword2_0 = code2;
    }
    action SetCode1(bit<11> code0, bit<7> code1, bit<7> code2) {
        codewords.codeword0_1 = code0;
        codewords.codeword1_1 = code1;
        codewords.codeword2_1 = code2;
    }
    action SetCode2(bit<20> code0, bit<20> code1, bit<18> code2) {
        codewords.codeword0_2 = code0;
        codewords.codeword1_2 = code1;
        codewords.codeword2_2 = code2;
    }

    action nop() {}

    Features_t features;
    // FEATURES: ['udp.length' 'Flow IAT Max' 'Flow IAT Min']
    table TableFeature0{
        key = {features.udp_len: range @name("feature0");}
	    actions = {@defaultonly nop; SetCode0;}
	    size = 25;
        const default_action = nop();
	}
    table TableFeature1{
	    key = {statefull_features.flow_iat_max[31:29]: range @name("feature1");}
	    actions = {@defaultonly nop; SetCode1;}
	    size = 10;
        const default_action = nop();
	}
    table TableFeature2{
	    key = {statefull_features.flow_iat_min[31:21]: range @name("feature2");}
	    actions = {@defaultonly nop; SetCode2;}
	    size = 50;
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
        }
	    actions = {@defaultonly nop; SetClass2;}
	    size = 41;
        const default_action = nop();
	}

    action SetVotingResult(Class_t vote_result) {
        class = vote_result;
    }
    action SetVotingResultToUnknown() {
        class = UNKNOWN_FLOW_CLASS;
    }
    table VotingTable {
        key = {
            voting_classes.class0: exact;
            voting_classes.class1: exact;
            voting_classes.class2: exact;
        }
        actions = {SetVotingResult; @defaultonly SetVotingResultToUnknown;}
        size = 32;
        const default_action = SetVotingResultToUnknown();
    }
 
    apply {
        if (hdr.ipv4.protocol == IPv4Proto.UDP) {
            features.udp_len = hdr.udp.length;
        } else {
            features.udp_len = 0;
        }
        TableFeature0.apply();
        TableFeature1.apply();
        TableFeature2.apply();

        CodeTable0.apply();
        CodeTable1.apply();
        CodeTable2.apply();

        VotingTable.apply();
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
