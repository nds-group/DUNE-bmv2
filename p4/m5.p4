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
    Time_t flow_duration;
    Time_t flow_iat_max;
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

    Time_t duration;
    register<Time_t>(NB_REG_ENTRIES) flows_duration;
    action GetUpdateDuration() {
        flows_duration.read(duration, hashes.reg_idx32);
        if (!new_flow) {
            duration = duration + iat;
            flows_duration.write(hashes.reg_idx32, duration);
        }
    }

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

    Time_t timestamp;

    apply {
        GetThenUpdatePreviousPktTimestamp.apply(
            std_meta,
            hashes,
            timestamp
        );
        iat = BMV2_TIME(std_meta.ingress_global_timestamp[31:0]) - timestamp;
        GetUpdateDuration();
        GetUpdateFlowIatMax();
        statefull_features = {
            flow_duration = duration,
            flow_iat_max = iat_max
        };
    }
}

control GetStatefullFeaturesDefaultValues(
    out StatefullFeatures_t statefull_features
)
{
    apply {
        statefull_features = {
            flow_duration = 0,
            flow_iat_max = 0
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
    bit<16> ip_len;
    bit<16> dst_port;
    bit<16> udp_len;
    bit<16> src_port;
    bit<16> tcp_window;
}

struct Codewords_t {
    bit<26> codeword0_0;
    bit<81> codeword0_1;
    bit<23> codeword0_2;
    bit<23> codeword0_3;
    bit<14> codeword0_4;
    bit<34> codeword0_5;
    bit<15> codeword0_6;
}

control InferenceModel(
    in Headers_t hdr,
    in Metadata_t meta,
    in standard_metadata_t std_meta,
    in StatefullFeatures_t statefull_features,
    out Class_t class
)
{
    Codewords_t codewords = {0,0,0,0,0,0,0};

    action SetCode0(bit<26> code0) {
        codewords.codeword0_0 = code0;
    }
    action SetCode1(bit<81> code0) {
        codewords.codeword0_1 = code0;
    }
    action SetCode2(bit<23> code0) {
        codewords.codeword0_2 = code0;
    }
    action SetCode3(bit<23> code0) {
        codewords.codeword0_3 = code0;
    }
    action SetCode4(bit<14> code0) {
        codewords.codeword0_4 = code0;
    }
    action SetCode5(bit<34> code0) {
        codewords.codeword0_5 = code0;
    }
    action SetCode6(bit<15> code0) {
        codewords.codeword0_6 = code0;
    }

    action nop() {}

    Features_t features;
    // FEATURES: ['ip.len' 'dstport' 'udp.length' 'Flow Duration' 'Flow IAT Max' 'srcport' 'tcp.window_size_value']
    table TableFeature0{
	    key = {features.ip_len: range @name("feature0");}
	    actions = {@defaultonly nop; SetCode0;}
	    size = 35;
        const default_action = nop();
	}
    table TableFeature1{
        key = {features.dst_port: range @name("feature1");}
	    actions = {@defaultonly nop; SetCode1;}
	    size = 85;
        const default_action = nop();
	}
    table TableFeature2{
	    key = {features.udp_len: range @name("feature2");}
	    actions = {@defaultonly nop; SetCode2;}
	    size = 25;
        const default_action = nop();
	}
    table TableFeature3{
        key = {statefull_features.flow_duration[31:19]: range @name("feature3");}
	    actions = {@defaultonly nop; SetCode3;}
	    size = 30;
        const default_action = nop();
	}
    table TableFeature4{
        key = {statefull_features.flow_iat_max[31:24]: range @name("feature4");}
	    actions = {@defaultonly nop; SetCode4;}
	    size = 20;
        const default_action = nop();
	}
    table TableFeature5{
	    key = {features.src_port: range @name("feature5");}
	    actions = {@defaultonly nop; SetCode5;}
	    size = 40;
        const default_action = nop();
	}
    table TableFeature6{
        key = {features.tcp_window: range @name("feature6");}
	    actions = {@defaultonly nop; SetCode6;}
	    size = 15;
        const default_action = nop();
	}
 

    action SetClass0(Class_t vote_result) {
        class = vote_result;
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
            codewords.codeword0_5: ternary;
            codewords.codeword0_6: ternary;
        }
	    actions = {SetClass0; @defaultonly SetClass0ToUnknown;}
	    size = 217;
        const default_action = SetClass0ToUnknown();
	}

    apply {
        features.ip_len = hdr.ipv4.total_length;
        features.dst_port = meta.dst_port;
        if (hdr.ipv4.protocol == IPv4Proto.UDP) {
            features.udp_len = hdr.udp.length;
        } else {
            features.udp_len = 0;
        }
        features.src_port = meta.src_port;
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

        CodeTable0.apply();
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
