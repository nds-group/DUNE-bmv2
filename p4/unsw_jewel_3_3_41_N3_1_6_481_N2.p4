/* -*- P4_16 -*- */

#include <core.p4>
#include <v1model.p4>


/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
typedef bit<9>  PortId_t;

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;

const bit<16>       TYPE_RECIRC = 0x88B5;
const bit<16>       TYPE_IPV4 = 0x800;
const bit<8>        TYPE_TCP = 6;
const bit<8>        TYPE_UDP = 17;
const bit<32>       MAX_REGISTER_ENTRIES = 65536;

#define INDEX_WIDTH 16

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/* Standard ethernet header */
header ethernet_h {
    mac_addr_t   dst_addr;
    mac_addr_t   src_addr;
    ether_type_t ether_type;
}

/*Custom header for notifying the next switch about the classification result */
header notify_h {
    bit<8>       inf_result;
    bit<8>       is_flow_classified;
    bit<8>      pkt_count;
}

/* IPV4 header */
header ipv4_h {
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      total_len;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      frag_offset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdr_checksum;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;
}

/* TCP header */
header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

/* UDP header */
header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_total_len;
    bit<16> checksum;
}

// header tna_timestamps_h {
    // bit<16> pad_1;
    // bit<48> ingress_mac;
    // bit<16> pad_2;
    // bit<48> ingress_global;
    // bit<14> pad_3;
    // bit<18> enqueue;
    // bit<14> pad_4;
    // bit<18> dequeue_delta;
    // bit<16> pad_5;
    // bit<48> egress_global;
    // bit<16> pad_6;
    // bit<48> egress_tx;
// }

/***********************  H E A D E R S  ************************/
struct my_ingress_headers_t {
    ethernet_h   ethernet;
    // recirc_h     recirc;
    ipv4_h       ipv4;
    tcp_h        tcp;
    udp_h        udp;
    notify_h notify;

}


/******  G L O B A L   I N G R E S S   M E T A D A T A  *********/
struct my_ingress_metadata_t {
    bit<1> is_first;

    bit<32> flow_ID;
    bit<(INDEX_WIDTH)> register_index;

    bit<16> hdr_srcport;
    bit<16> hdr_dstport;
    bit<4> tcp_hdr_len;
    bit<16> tcp_windows_size;
    bit<16> udp_len;
    bit<16> pkt_len_max;
    // bit<16> pkt_len_min;
    // bit<16> pkt_len_total;
    bit<8> ip_proto;
    // bit<1> tcp_flag_ack;
    bit<16> total_len;
    bit<8> pkt_count;
    bit<32> time_last_pkt;
    bit<32> flow_iat_max;
    bit<32> flow_iat_min;
    bit<32> iat;

    bit<8> class0;
    bit<8> class1;
    bit<8> class2;
    bit<8> class3;
    bit<8> class_model1;
    bit<8> class_model2;
    bit<8> final_class;
    bit<8> classified_flag;

    bit<9> codeword0_0;
    bit<11> codeword0_1;
    bit<20> codeword0_2;

    bit<13> codeword1_0;
    bit<7> codeword1_1;
    bit<20> codeword1_2;

    bit<15> codeword2_0;
    bit<7> codeword2_1;
    bit<18> codeword2_2;

    bit<67> codeword3_0;
    bit<69> codeword3_1;
    bit<105> codeword3_2;
    bit<90> codeword3_3;
    bit<63> codeword3_4;
    bit<86> codeword3_5;



    bit<8> digest_info; // used for either class or collision info

    bit<8> f_action; // For flow_action table
    bit<2> is_store;
    bit<2> is_refresh;
    bit<2> is_flow;

    // tna_timestamps_h tna_timestamps_hdr;
    // ptp_metadata_t tx_ptp_md_hdr;

    // bit<48> measured_latency;
}

struct flow_class_digest {  // maximum size allowed is 47 bytes

    ipv4_addr_t  source_addr;   // 32 bits
    ipv4_addr_t  destin_addr;   // 32 bits
    bit<16> source_port;
    bit<16> destin_port;
    bit<8> protocol;
    bit<8> class_value;
    bit<8> packet_num;
    bit<(INDEX_WIDTH)> register_index; // To send register index info to the controller
    bit<2> is_refresh;
    bit<2> is_store;
    bit<2> is_flow;
    // total size is 2*2 + 2*4 + 2 + (16/8==2) = 16 bytes
}

// struct timestamp_digest {  // maximum size allowed is 47 bytes

//     bit<48>  latency;
//     // total size is = 6 bytes
// }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser MyIngressParser(packet_in        pkt,
    out my_ingress_headers_t            hdr,
    inout my_ingress_metadata_t         meta,
    inout standard_metadata_t           std_meta)
{
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.total_len = hdr.ipv4.total_len;
        meta.ip_proto  = hdr.ipv4.protocol;
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP:  parse_tcp;
            TYPE_UDP:  parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.hdr_dstport = hdr.tcp.dst_port;
        meta.hdr_srcport = hdr.tcp.src_port;
        meta.tcp_hdr_len = hdr.tcp.data_offset;
        meta.tcp_windows_size = hdr.tcp.window;
        // meta.tcp_flag_ack = hdr.tcp.ack;
        meta.udp_len = 0;
        // transition accept;
        transition parse_notify;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.hdr_dstport = hdr.udp.dst_port;
        meta.hdr_srcport = hdr.udp.src_port;
        // meta.tcp_flag_ack = 0;
        meta.tcp_hdr_len = 0;
        meta.tcp_windows_size = 0;
        meta.udp_len = hdr.udp.udp_total_len;
        // transition accept;
        transition parse_notify;
    }

    state parse_notify {
       pkt.extract(hdr.notify);
       transition accept;
    }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control NoVerifyChecksum(
    inout my_ingress_headers_t hdr,
    inout my_ingress_metadata_t meta)
{
    apply {  }
}

/***************** M A T C H - A C T I O N  *********************/
control MyIngress(
    /* User */
    inout my_ingress_headers_t  hdr,
    inout my_ingress_metadata_t meta,
    inout standard_metadata_t   std_meta)
{

    /* Registers for flow management */
    // First model
    register<bit<8>>(MAX_REGISTER_ENTRIES) reg_classified_flag_model1;
    /* Register read action */
    action read_classified_flag_model1(bit<INDEX_WIDTH> register_index) {
        reg_classified_flag_model1.read(meta.f_action, (bit<32>)register_index);
    }
    action update_classified_flag_model1(bit<INDEX_WIDTH> register_index) {
        reg_classified_flag_model1.write((bit<32>)register_index, meta.final_class);
    }

    // Second model
    register<bit<8>>(MAX_REGISTER_ENTRIES) reg_classified_flag_model2;
    /* Register read action */
    action read_classified_flag_model2(bit<INDEX_WIDTH> register_index) {
        reg_classified_flag_model2.read(meta.classified_flag, (bit<32>)register_index);
    }
    action update_classified_flag_model2(bit<INDEX_WIDTH> register_index) {
        reg_classified_flag_model2.write((bit<32>)register_index, meta.class_model2);
    }

    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_flow_ID;
    /* Register read action */
    action update_flow_ID(bit<INDEX_WIDTH> register_index) {
        reg_flow_ID.write((bit<32>)register_index, meta.flow_ID);
    }
    /* Register read action */
    bit<32> tmp_flow_ID;
    action read_only_flow_ID(bit<INDEX_WIDTH> register_index) {
        reg_flow_ID.read(tmp_flow_ID, (bit<32>)register_index);
    }

    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_time_last_pkt;
    /* Register read action */
    action read_time_last_pkt(bit<INDEX_WIDTH> register_index) {
        reg_time_last_pkt.read(meta.time_last_pkt, (bit<32>)register_index);
        reg_time_last_pkt.write((bit<32>)register_index, std_meta.ingress_global_timestamp[31:0]);
    }

    //registers for ML inference - features
    register<bit<8>>(MAX_REGISTER_ENTRIES) reg_pkt_count;
    /* Register read action */
    action read_pkt_count(bit<INDEX_WIDTH> register_index) {
        reg_pkt_count.read(meta.pkt_count, (bit<32>)register_index);
        meta.pkt_count = meta.pkt_count + 1;
        reg_pkt_count.write((bit<32>)register_index, meta.pkt_count);
    }


    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_flow_iat_max;
    /* Register read action */
    action read_flow_iat_max(bit<INDEX_WIDTH> register_index) {
        reg_flow_iat_max.read(meta.flow_iat_max, (bit<32>)register_index);
        if (meta.is_first != 1){
            if(meta.iat > meta.flow_iat_max){
                meta.flow_iat_max = meta.iat;
                reg_flow_iat_max.write((bit<32>)register_index, meta.flow_iat_max);
            }
        }
    }

    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_flow_iat_min;
    /* Register read action */
    action read_flow_iat_min(bit<INDEX_WIDTH> register_index) {
        reg_flow_iat_min.read(meta.flow_iat_min, (bit<32>)register_index);
        if (meta.pkt_count <= 2) {
            meta.flow_iat_min = meta.iat;
            reg_flow_iat_min.write((bit<32>)register_index, meta.flow_iat_min);
        }
        else if(meta.iat < meta.flow_iat_min) {
            meta.flow_iat_min = meta.iat;
            reg_flow_iat_min.write((bit<32>)register_index, meta.flow_iat_min);
        }
    }

    /* Calculate hash of the 5-tuple to represent the flow ID */
    action get_flow_ID(bit<16> srcPort, bit<16> dstPort) {
        hash(meta.flow_ID,HashAlgorithm.crc32,(bit<64>) 0,{hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,srcPort, dstPort, hdr.ipv4.protocol},(bit<64>) 2<<32);

    }
    /* Calculate hash of the 5-tuple to use as 1st register index */
    action get_register_index(bit<16> srcPort, bit<16> dstPort) {
        hash(meta.register_index, HashAlgorithm.crc16,(bit<64>) 0,{hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,srcPort, dstPort, hdr.ipv4.protocol}, (bit<64>) 2<<INDEX_WIDTH);
    }

    /* Assign class if at leaf node */
    action SetClass0(bit<8> classe) {
        // meta.class0 = classe;
        meta.class0 = classe;
    }
    action SetClass1(bit<8> classe) {
        meta.class1 = classe;
    }
    action SetClass2(bit<8> classe) {
        meta.class2 = classe;
    }
    action SetClass3(bit<8> classe) {
        meta.class_model2 = classe;
    }

    /* Forward to a specific port upon classification */
    action ipv4_forward(PortId_t port) {
        std_meta.egress_spec = port;
    }
    /* Custom Do Nothing Action */
    action nop(){}

    action drop() {
        mark_to_drop(std_meta);
    }

    action set_final_class(bit<8> class_result) {
        meta.class_model1 = class_result;
    }

    action set_default_class() {
    }

    action set_flow_feats() {
        meta.flow_iat_min = 0;
        meta.flow_iat_max = 0;
    }

    /* Feature table actions */
    // First model - [[9, 11, 20], [13, 7, 20], [15, 7, 18]]
    action SetCode0(bit<9> code0, bit<13> code1, bit<15> code2) {
        meta.codeword0_0 = code0;
        meta.codeword1_0 = code1;
        meta.codeword2_0 = code2;
    }
    action SetCode1(bit<11> code0, bit<7> code1, bit<7> code2) {
        meta.codeword0_1 = code0;
        meta.codeword1_1 = code1;
        meta.codeword2_1 = code2;
    }
    action SetCode2(bit<20> code0, bit<20> code1, bit<18> code2) {
        meta.codeword0_2 = code0;
        meta.codeword1_2 = code1;
        meta.codeword2_2 = code2;
    }

    // Second model
    // [[67, 69, 105, 90, 63, 86]]
    /* Feature table actions */
    action SetCode3(bit<67> code0) {
        meta.codeword3_0 = code0;
    }
    action SetCode4(bit<69> code0) {
        meta.codeword3_1 = code0;
    }
    action SetCode5(bit<105> code0) {
        meta.codeword3_2 = code0;
    }
     action SetCode6(bit<90> code0) {
        meta.codeword3_3 = code0;
    }
    action SetCode7(bit<63> code0) {
        meta.codeword3_4 = code0;
    }
    action SetCode8(bit<86> code0) {
        meta.codeword3_5 = code0;
    }



    action set_flow_action(bit<8> f_action) {
        meta.f_action = f_action;
    }
    action set_def_flow_action() {
        meta.f_action = 34;
        drop();
    }

    // FEATURES: ['udp.length' 'Flow IAT Max' 'Flow IAT Min']
    /* Feature tables */
    table table_feature0{
        key = {meta.udp_len: range @name("feature0");}
	    actions = {@defaultonly nop; SetCode0;}
	    size = 25;
        const default_action = nop();
	}
    table table_feature1{
	    key = {meta.flow_iat_max[31:29]: range @name("feature1");}
	    actions = {@defaultonly nop; SetCode1;}
	    size = 10;
        const default_action = nop();
	}
    table table_feature2{
        // [4,0]
	    key = {meta.flow_iat_min[31:21]: range @name("feature2");}
	    actions = {@defaultonly nop; SetCode2;}
	    size = 50;
        const default_action = nop();
	}
    //
    // FEATURES: ['udp.length' 'ip.len' 'dstport' 'srcport' 'ip.ttl' 'tcp.window_size_value']
    /* Feature tables */
    table table_feature3{
        key = {meta.udp_len: range @name("feature3");}
	    actions = {@defaultonly nop; SetCode3;}
	    size = 70;
        const default_action = nop();
	}
    table table_feature4{
	    key = {meta.total_len: range @name("feature4");}
	    actions = {@defaultonly nop; SetCode4;}
	    size = 70;
        const default_action = nop();
	}
    table table_feature5{
	    key = {meta.hdr_dstport: range @name("feature5");}
	    actions = {@defaultonly nop; SetCode5;}
	    size = 100;
        const default_action = nop();
	}
    table table_feature6{
	    key = {meta.hdr_srcport: range @name("feature6");}
	    actions = {@defaultonly nop; SetCode6;}
	    size = 80;
        const default_action = nop();
	}
    table table_feature7{
	    key = {hdr.ipv4.ttl: range @name("feature7");}
	    actions = {@defaultonly nop; SetCode7;}
	    size = 50;
        const default_action = nop();
	}
    table table_feature8{
	    key = {meta.tcp_windows_size: range @name("feature8");}
	    actions = {@defaultonly nop; SetCode8;}
	    size = 90;
        const default_action = nop();
	}


    /* Code tables */
	table code_table0{
	    key = {
            meta.codeword0_0: ternary;
            meta.codeword0_1: ternary;
            meta.codeword0_2: ternary;
        }
	    actions = {@defaultonly nop; SetClass0;}
	    size = 41;
        const default_action = nop();
	}
	table code_table1{
        key = {
            meta.codeword1_0: ternary;
            meta.codeword1_1: ternary;
            meta.codeword1_2: ternary;
        }
	    actions = {@defaultonly nop; SetClass1;}
	    size = 41;
        const default_action = nop();
	}
	table code_table2{
        key = {
            meta.codeword2_0: ternary;
            meta.codeword2_1: ternary;
            meta.codeword2_2: ternary;
        }
	    actions = {@defaultonly nop; SetClass2;}
	    size = 41;
        const default_action = nop();
	}
    table code_table3{
        key = {
            meta.codeword3_0: ternary;
            meta.codeword3_1: ternary;
            meta.codeword3_2: ternary;
            meta.codeword3_3: ternary;
            meta.codeword3_4: ternary;
            meta.codeword3_5: ternary;
        }
	    actions = {@defaultonly nop; SetClass3;}
	    size = 481;
        const default_action = nop();
	}

    table voting_table {
        key = {
            meta.class1: exact;
            meta.class2: exact;
            meta.class3: exact;
        }
        actions = {set_final_class; @defaultonly set_default_class;}
        size = 32;
        const default_action = set_default_class();
    }

    /* Forwarding-Inference Block Table */
    table flow_action_table {
        key = {
            hdr.ipv4.src_addr: exact;
            hdr.ipv4.dst_addr: exact;
            meta.hdr_srcport: exact;
            meta.hdr_dstport: exact;
            hdr.ipv4.protocol: exact;
        }
        actions = {set_flow_action; @defaultonly set_def_flow_action;}
        size = 63000;
        const default_action = set_def_flow_action();
    }

    /* Compute packet interarrival time (IAT)*/
    action get_iat_value(){
        meta.iat = std_meta.ingress_global_timestamp[31:0] - meta.time_last_pkt;
    }

    apply {
        // Forward, if flow is already classified as Others. Otherwise, run model.
        flow_action_table.apply();
        //compute flow_ID and hash index
        get_flow_ID(meta.hdr_srcport, meta.hdr_dstport);
        get_register_index(meta.hdr_srcport, meta.hdr_dstport);
        // code here to execute if table experienced a hit
        if (meta.f_action == 50) {  // The flow is not classified

            // modify timestamp register
            read_time_last_pkt(meta.register_index);
            // calculate iat
            get_iat_value();

            // check if register array is empty
            if (meta.time_last_pkt == 0){ // we do not yet know this flow
                meta.is_first = 1;
                update_flow_ID(meta.register_index);
                read_pkt_count(meta.register_index);
            }
            else { // not the first packet - get flow_ID from register
                meta.is_first = 0;
                read_only_flow_ID(meta.register_index);
                if(meta.flow_ID != tmp_flow_ID){ // hash collision
                    meta.pkt_count = 0;
                }
                else { // not first packet and not hash collision
                    //read and update packet count
                    read_pkt_count(meta.register_index);
                    read_flow_iat_max(meta.register_index);
                    read_flow_iat_min(meta.register_index);
                } //END OF CHECK ON IF NO COLLISION
            } // END OF CHECK ON WHETHER FIRST CLASS
            meta.is_flow = 0;
            if (meta.pkt_count < 4){
                if(meta.pkt_count < 3){  // Set flow level features as 0 if the packet before N1th, where N1 = the inference point of the first model
                    set_flow_feats();
                }
                // ** First Model **
                // apply feature tables to assign codes
                table_feature0.apply();
                table_feature1.apply();
                table_feature2.apply();

                // apply code tables to assign labels
                code_table0.apply();
                code_table1.apply();
                code_table2.apply();

                voting_table.apply(); // It sets class_model1: the class from the first model

                // ** Second Model **
                table_feature3.apply();
                table_feature4.apply();
                table_feature5.apply();
                table_feature6.apply();
                table_feature7.apply();
                table_feature8.apply();

                code_table3.apply();

                meta.class_model2 = meta.class_model2 + 1;  // It sets class_model2: the class from the second model

                meta.is_refresh = 0;
                hdr.notify.is_flow_classified = 1;

                if (meta.pkt_count < 3){ // If the packet count is less than N1+1
                    update_classified_flag_model2(meta.register_index); // store the result of second model

                    if (meta.class_model1 == 2){ // OTHERS: If the packet classified as Others in the first model, set the final class with the result coming from the second model
                        meta.final_class =  meta.class_model2;
                    }
                    else{  // ONE OF THE CLASSES: : If the packet classified as one of the classes in the first model, set the final class with the result coming from the first model
                        meta.final_class =  meta.class_model1;
                    }
                }
                else{
                    read_classified_flag_model2(meta.register_index);  // since the N2 (2) < N1 (3), we already stored the result and here we read it
                    if (meta.class_model1 == 2){ // OTHERS
                        meta.final_class =  meta.classified_flag;
                    }
                    else{  // ONE OF THE CLASSES
                        meta.final_class =  meta.class_model1;
                    }
                    update_classified_flag_model1(meta.register_index);
                    meta.is_refresh = 1; // Store the result and refresh the memory since it is a FL classification
                    meta.is_flow = 1;
                }
                // ** SET CLASS and NOTIFICATION DATA, and ACTIVATE DIGEST **
                hdr.notify.inf_result = meta.final_class;
                // hdr.notify.pkt_count = meta.pkt_count;
                meta.is_store = 1;
                // Sending the digest after classification
                digest<flow_class_digest>(1, {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, meta.hdr_srcport, meta.hdr_dstport, hdr.ipv4.protocol, meta.final_class, meta.pkt_count, meta.register_index, meta.is_refresh, meta.is_store, meta.is_flow});
                ipv4_forward(2);
            }
            else {
                read_classified_flag_model1(meta.register_index);
            }
            // }
        }
        if (meta.f_action == 19) {  // If the flow is classified as OTHERS (obtained by the flow_action table)
            hdr.notify.inf_result = meta.f_action;
            hdr.notify.is_flow_classified = 0;
            ipv4_forward(2);
        }
        // }
    } //END OF APPLY
} //END OF INGRESS CONTROL

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***************** M A T C H - A C T I O N  *********************/

control NoEgress(
    /* User */
    inout my_ingress_headers_t                          hdr,
    inout my_ingress_metadata_t                         meta,
    inout standard_metadata_t                          std_meta)
{
    apply {}
}

control NoComputeChecksum(
    inout my_ingress_headers_t hdr,
    inout my_ingress_metadata_t meta)
{
    apply {}
}

    /*********************  D E P A R S E R  ************************/

control MyEgressDeparser(
    packet_out              pkt,
    in my_ingress_headers_t hdr)
{
    apply {
        pkt.emit(hdr);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.notify);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
V1Switch(
    MyIngressParser(),
    NoVerifyChecksum(),
    MyIngress(),
    NoEgress(),
    NoComputeChecksum(),
    MyEgressDeparser()
) main;
