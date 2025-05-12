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
    bit<8> classified_flag;

    bit<32> flow_ID;
    bit<(INDEX_WIDTH)> register_index;

    bit<16> hdr_srcport;
    bit<16> hdr_dstport;
    bit<4> tcp_hdr_len;
    bit<16> tcp_windows_size;
    bit<16> udp_len;
    // bit<16> pkt_len_max;
    // bit<16> pkt_len_min;
    // bit<16> pkt_len_total;
    bit<8> ip_proto;
    // bit<1> tcp_flag_ack;

    bit<8> pkt_count;
    bit<32> time_last_pkt;
    bit<16> total_len;
    // bit<32> flow_duration;

    bit<8> class1;
    bit<8> class2;
    bit<8> class_model1;
    bit<8> final_class;

    bit<38> codeword0_0;
    bit<120> codeword0_1;
    bit<103> codeword0_2;
    bit<73> codeword0_3;
    bit<102> codeword0_4;

    bit<7> codeword1_0;
    bit<13> codeword1_1;
    bit<9> codeword1_2;
    bit<18> codeword1_3;
    bit<18> codeword1_4;
    bit<19> codeword1_5;

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
        reg_classified_flag_model1.read(meta.class_model1, (bit<32>)register_index);
    }

    action update_classified_flag_model1(bit<INDEX_WIDTH> register_index) {
        reg_classified_flag_model1.write((bit<32>)register_index, meta.class_model1);
    }

    // Second model
    register<bit<8>>(MAX_REGISTER_ENTRIES) reg_classified_flag_model2;
    /* Register read action */
    action read_classified_flag_model2(bit<INDEX_WIDTH> register_index) {
        reg_classified_flag_model2.read(meta.f_action, (bit<32>)register_index);
    }
    action update_classified_flag_model2(bit<INDEX_WIDTH> register_index) {
        reg_classified_flag_model2.write((bit<32>)register_index, meta.final_class);
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
        meta.class1 = classe;
        meta.class_model1 = classe;
    }
    action SetClass1(bit<8> classe) {
        meta.class2 = classe;
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
        meta.final_class = class_result;
    }


    // [[38, 120, 103, 73, 102]] - [[7, 13, 9, 18, 18, 19]]
    /* Feature table actions */
    action SetCode0(bit<38> code0) {
        meta.codeword0_0 = code0;
    }
    action SetCode1(bit<120> code0) {
        meta.codeword0_1 = code0;
    }
    action SetCode2(bit<103> code0) {
        meta.codeword0_2 = code0;
    }
    action SetCode3(bit<73> code0) {
        meta.codeword0_3 = code0;
    }
    action SetCode4(bit<102> code0) {
        meta.codeword0_4 = code0;
    }
    //
    action SetCode5(bit<7> code0) {
        meta.codeword1_0 = code0;
    }
    action SetCode6(bit<13> code0) {
        meta.codeword1_1 = code0;
    }
    action SetCode7(bit<9> code0) {
        meta.codeword1_2 = code0;
    }
    action SetCode8(bit<18> code0) {
        meta.codeword1_3 = code0;
    }
    action SetCode9(bit<18> code0) {
        meta.codeword1_4 = code0;
    }
    action SetCode10(bit<19> code0) {
        meta.codeword1_5 = code0;
    }


    action set_flow_action(bit<8> f_action) {
        meta.f_action = f_action;
    }
    action set_def_flow_action() {
        meta.f_action = 34;
        drop();
    }

    // FEATURES: ['tcp.window_size_value' 'ip.len' 'srcport' 'udp.length' 'dstport']
    /* Feature tables */
    table table_feature0{
	    key = {meta.tcp_windows_size: range @name("feature0");}
	    actions = {@defaultonly nop; SetCode0;}
	    size = 35;
        const default_action = nop();
	}
    table table_feature1{
        key = {meta.total_len: range @name("feature1");}
	    actions = {@defaultonly nop; SetCode1;}
	    size = 125;
        const default_action = nop();
	}
    table table_feature2{
	    key = {meta.hdr_srcport: range @name("feature2");}
	    actions = {@defaultonly nop; SetCode2;}
	    size = 105;
        const default_action = nop();
	}
    table table_feature3{
	    key = {meta.udp_len: range @name("feature3");}
	    actions = {@defaultonly nop; SetCode3;}
	    size = 70;
        const default_action = nop();
	}
    table table_feature4{
	    key = {meta.hdr_dstport: range @name("feature4");}
	    actions = {@defaultonly nop; SetCode4;}
	    size = 105;
        const default_action = nop();
	}
    //  ['tcp.hdr_len' 'srcport' 'udp.length' 'ip.ttl' 'dstport' 'tcp.window_size_value']
    table table_feature5{
	    key = {meta.tcp_hdr_len: range @name("feature5");}
	    actions = {@defaultonly nop; SetCode5;}
	    size = 10;
        const default_action = nop();
	}
    table table_feature6{
	    key = {meta.hdr_srcport: range @name("feature6");}
	    actions = {@defaultonly nop; SetCode6;}
	    size = 15;
        const default_action = nop();
	}
    table table_feature7{
        key = {meta.udp_len: range @name("feature7");}
	    actions = {@defaultonly nop; SetCode7;}
	    size = 15;
        const default_action = nop();
	}
    table table_feature8{
	    key = {hdr.ipv4.ttl: range @name("feature8");}
	    actions = {@defaultonly nop; SetCode8;}
	    size = 15;
        const default_action = nop();
	}
    table table_feature9{
	    key = {meta.hdr_dstport: range @name("feature9");}
	    actions = {@defaultonly nop; SetCode9;}
	    size = 20;
        const default_action = nop();
	}
    table table_feature10{
	    key = {meta.tcp_windows_size: range @name("feature10");}
	    actions = {@defaultonly nop; SetCode10;}
	    size = 20;
        const default_action = nop();
	}


    /* Code tables */
	table code_table0{
	    key = {
            meta.codeword0_0: ternary;
            meta.codeword0_1: ternary;
            meta.codeword0_2: ternary;
            meta.codeword0_3: ternary;
            meta.codeword0_4: ternary;
        }
	    actions = {@defaultonly nop; SetClass0;}
	    size = 437;
        const default_action = nop();
	}
	table code_table1{
        key = {
            meta.codeword1_0: ternary;
            meta.codeword1_1: ternary;
            meta.codeword1_2: ternary;
            meta.codeword1_3: ternary;
            meta.codeword1_4: ternary;
            meta.codeword1_5: ternary;
        }
	    actions = {@defaultonly nop; SetClass1;}
	    size = 85;
        const default_action = nop();
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
        // size = 25000;
        size = 63000;
        const default_action = set_def_flow_action();
    }

    apply {
        flow_action_table.apply();
        // Forward, if flow is already classified as Others. Otherwise, run model.
        //compute flow_ID and hash index
        get_flow_ID(meta.hdr_srcport, meta.hdr_dstport);
        get_register_index(meta.hdr_srcport, meta.hdr_dstport);
        // code here to execute if table experienced a hit
        if (meta.f_action == 50) {
            if (hdr.notify.is_flow_classified == 1){  // If the flow is classified by the previous models
                read_only_flow_ID(meta.register_index);
                if(meta.flow_ID == tmp_flow_ID){ // No hash collision
                    meta.is_refresh = 1;  // to make it CLEAN the register but do NOT STORE the result
                }
                else{
                    meta.is_refresh = 0;
                }
                meta.is_store = 0;
                meta.pkt_count = hdr.notify.pkt_count; // Required for the digest, if stored before
                meta.final_class = hdr.notify.inf_result;
                hdr.notify.is_flow_classified = 1; // Required for the downstream switches
                // Sending the digest after classification
                digest<flow_class_digest>(1, {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, meta.hdr_srcport, meta.hdr_dstport, hdr.ipv4.protocol, meta.final_class, meta.pkt_count, meta.register_index, meta.is_refresh, meta.is_store, meta.is_flow});
                ipv4_forward(2);
            }
            else {
                // modify timestamp register
                read_time_last_pkt(meta.register_index);

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

                    } //END OF CHECK ON IF NO COLLISION
                } // END OF CHECK ON WHETHER FIRST CLASS
                meta.is_flow = 0;
                if (meta.pkt_count < 5){
                    // ** First Model **
                    // apply feature tables to assign codes
                    table_feature0.apply();
                    table_feature1.apply();
                    table_feature2.apply();
                    table_feature3.apply();
                    table_feature4.apply();

                    // apply code tables to assign labels
                    code_table0.apply();
                    meta.class1 = meta.class1 + 18;
                    meta.class_model1 = meta.class_model1 + 18;

                    // ** Second Model **
                    table_feature5.apply();
                    table_feature6.apply();
                    table_feature7.apply();
                    table_feature8.apply();
                    table_feature9.apply();
                    table_feature10.apply();

                    code_table1.apply();
                    meta.class2 = meta.class2 + 19;

                    meta.is_refresh = 0;

                    if (meta.pkt_count < 4){
                        update_classified_flag_model1(meta.register_index); // Store the results of the first inference model
                        if (meta.class1 == 20){ // OTHERS: If the packet classified as Others in the first model, set the final class with the result obtained from the second model
                            set_final_class(meta.class2);
                        }
                        else{  // ONE OF THE CLASSES: If the packet classified as one of the classes in the first model, set the final class with the result obtained from the first model
                            set_final_class(meta.class1);
                            if (meta.pkt_count == 3){ //if meta.pkt_count == N1 (3)
                                meta.is_flow = 1;
                                meta.is_refresh = 1; // Store the result and refresh the memory
                                hdr.notify.is_flow_classified = 1; // Notify the downstream switches about tft the flow is classified
                            }
                        }
                        if (meta.pkt_count == 3){
                            update_classified_flag_model2(meta.register_index); // Store the results of the second inference model
                        }
                    }
                    else{
                        read_classified_flag_model1(meta.register_index);

                        if (meta.class_model1 == 20){ // OTHERS: If the packet classified as Others in the first model
                            set_final_class(meta.class2);
                        }
                        else{  // ONE OF THE CLASSES
                            set_final_class(meta.class_model1);
                        }
                        if (meta.pkt_count == 4){
                            meta.is_flow = 1;
                            meta.is_refresh = 1; // Store the result and refresh the memory
                            if (meta.final_class != 22){ // If the flow is classified with one of the classes not others
                                hdr.notify.is_flow_classified = 1; // Notify the downstream switches about tft the flow is classified
                            }
                        }
                        update_classified_flag_model2(meta.register_index);
                    }

                    // SET CLASS and NOTIFICATION DATA, and ACTIVATE the digest
                    if (hdr.notify.inf_result < 19){ // We check the result coming from the upstream switch here
                        // If the flow is classified as one of the classes not others in the upstream switch, just refresh the memory if necessary but do not store the result
                        meta.is_store = 0; // do not store the result
                    }
                    else {
                        // If the flow is classified as Others in the upstream switch, tag with the result obtained in the current switch.
                        hdr.notify.inf_result = meta.final_class;
                        hdr.notify.pkt_count = meta.pkt_count;
                        meta.is_store = 1;
                    }
                    // Sending the digest after classification
                    digest<flow_class_digest>(1, {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, meta.hdr_srcport, meta.hdr_dstport, hdr.ipv4.protocol, meta.final_class, meta.pkt_count, meta.register_index, meta.is_refresh, meta.is_store, meta.is_flow});
                    ipv4_forward(2);
                }
                else {
                    read_classified_flag_model2(meta.register_index); // Store the classification results obtained from the second model
                }
            }
        }
        if (meta.f_action == 22) { // If the flow is classified as OTHERS (obtained by the flow_action table)
            hdr.notify.inf_result = meta.f_action;
            hdr.notify.is_flow_classified = 0;
            hdr.notify.pkt_count = 5;
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
        // pkt.emit(hdr);
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
