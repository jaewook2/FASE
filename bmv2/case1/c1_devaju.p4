#include <core.p4>
#include <v1model.p4>


const bit<16> TYPE_NSH = 0x894f;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ETHER = 0x6558;
const bit<8> TYPE_TCP = 6;
const bit<8> TYPE_UDP = 17;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header nsh_t {
    bit<2>    ver;
    bit<1>    oam;
    bit<1>    un1;
    bit<6>    ttl;
    bit<6>    len;
    bit<4>    un4;
    bit<4>    MDtype;
    bit<16>   Nextpro;
    bit<24>   spi;
    bit<8>    si;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}

header tcp_t {
    bit<16>     srcPort;
    bit<16>     dstPort;
    bit<32>     seqNo;
    bit<32>     ackNo;
    bit<4>      dataOffset;
    bit<4>      res;
    bit<8>      flags;
    bit<16>     windows;
    bit<16>     checksum;
    bit<16>     urgenPtr;

}

header udp_t {
    
    bit<16>    srcPort;
    bit<16>    dstPort;
    bit<16>    length_;
    bit<16>    checksum;
}

header resubmit_metadata_t {
// Maximum 64 bits
    bit<24>   spi;
    bit<8>    si;
    bit<32>   dst_ip;
    
}
struct headers {
    resubmit_metadata_t resubmit_meta;
    ethernet_t   out_ethernet;
    nsh_t        nsh;
    ethernet_t   in_ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;
}


//////////////////* Metadata *//////////////////
//////////////////* Metadata *//////////////////
//////////////////* Metadata *//////////////////


struct l3_metadata_t {
    bit<2> lkp_ip_type;
    bit<4> lkp_ip_version;
    bit<8> lkp_ip_proto;
    bit<8> lkp_dscp;
    bit<8> lkp_ip_ttl;
    bit<16> lkp_l4_sport ;
    bit<16> lkp_l4_dport ;
    bit<16> lkp_outer_l4_sport ;
    bit<16> lkp_outer_l4_dport ;

    //bit<>vrf : VRF_BIT_WIDTH;                   /* VRF */
    bit<10> rmac_group;                           /* Rmac group, for rmac indirection */
    bit<1>  rmac_hit ;                          /* dst mac is the router's mac */
    bit<2>  urpf_mode;                         /* urpf mode for current lookup */
    bit<1>  urpf_hit;                          /* hit in urpf table */
    bit<1>  urpf_check_fail;                    /* urpf check failed */
    //bit<>urpf_bd_group : BD_BIT_WIDTH;          /* urpf bd group */
    bit<1>  fib_hit ;                           /* fib hit */
    bit<16> fib_nexthop ;                      /* next hop from fib */
    bit<2>  fib_nexthop_type ;                  /* ecmp or nexthop */
    //bit<>same_bd_check : BD_BIT_WIDTH;          /* ingress bd xor egress bd */
    bit<16> nexthop_index ;                    /* nexthop/rewrite index */
    bit<1>  routed ;                            /* is packet routed? */
    bit<1>  outer_routed ;                      /* is outer packet routed? */
    bit<8>  mtu_index ;                         /* index into mtu table */
    bit<1>  l3_copy ;                           /* copy packet to CPU */
    bit<16> l3_mtu_check;                        /* result of mtu check */

    bit<16> egress_l4_sport;
    bit<16> egress_l4_dport;

}
struct l2_metadata_t {
    bit<48>     dstAddr;
    bit<48>     srcAddr;
    bit<16>     etherType;
}
struct ipv4_metadata_t {    
    bit<32>    lkp_ipv4_sa;
    bit<32>    lkp_ipv4_da;
    bit<1>    ipv4_unicast_enabled;      /* is ipv4 unicast routing enabled */
    bit<2>    ipv4_urpf_mode;            /* 0: none, 1: strict, 3: loose */
}

struct pkt_id_t {
    bit<32> id;
    bit<32> next_id;
}

struct nat_metadata_t {
    bit<2>  ingress_nat_mode;           /* 0: none, 1: inside, 2: outside */
    bit<2>  egress_nat_mode;            /* nat mode of egress_bd */
    bit<16> nat_nexthop;                /* next hop from nat */
    bit<2>  nat_nexthop_type;           /* ecmp or nexthop */
    bit<1>  nat_hit;                    /* fwd and rewrite info from nat */
    bit<14> nat_rewrite_index;          /* NAT rewrite index */
    bit<1>  update_checksum;            /* update tcp/udp checksum */
    bit<1>  update_inner_checksum;      /* update inner tcp/udp checksum */    
    bit<16> l4_len;                     /* l4 length */
}

struct metadata_t {
    bit<24> metadata_spi;
    bit<8>  metadata_si;
    bit<1>  resubmit;
    l2_metadata_t l2_metadata;
    l3_metadata_t l3_metadata;
    ipv4_metadata_t ipv4_metadata;
    pkt_id_t   pkt_id;
    nat_metadata_t  nat_metadata;
    bit<16> ecmp_select;
    bit<48> ingress_timestamp;
}




/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser SwitchIngressParser(
                packet_in packet,
                out headers hdr,
	            out metadata_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        packet.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        packet.extract<resubmit_metadata_t>(hdr.resubmit_meta);
        transition parse_out_ethernet;
    }

    state parse_port_metadata {
        packet.advance(PORT_METADATA_SIZE);
        transition parse_out_ethernet;
    }

    state parse_out_ethernet {
        packet.extract(hdr.out_ethernet);
        transition select(hdr.out_ethernet.etherType) {
            TYPE_NSH: parse_nsh;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_nsh {
        packet.extract(hdr.nsh);
        transition select(hdr.nsh.Nextpro) {
            TYPE_ETHER: parse_in_ethernet;
            default: accept;
        }
    }

    state parse_in_ethernet {
        packet.extract(hdr.in_ethernet);
        transition select(hdr.in_ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}




/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control SwitchIngress(
        inout headers hdr,
        inout metadata_t meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
                      ) {
                    
                       

            

    action change_hdr_to_meta() {

	    meta.metadata_spi = hdr.nsh.spi;
	    meta.metadata_si = hdr.nsh.si;	
        meta.l2_metadata.dstAddr = hdr.out_ethernet.dstAddr; 
        meta.l2_metadata.srcAddr = hdr.out_ethernet.srcAddr;
        meta.l3_metadata.lkp_ip_proto = hdr.ipv4.protocol;
        meta.l3_metadata.lkp_l4_sport = hdr.tcp.srcPort;
        meta.l3_metadata.lkp_l4_dport = hdr.tcp.dstPort;
        meta.ipv4_metadata.lkp_ipv4_sa = hdr.ipv4.srcAddr;
        meta.ipv4_metadata.lkp_ipv4_da = hdr.ipv4.dstAddr;
        
    } 

    action on_miss(){    }

    action nop(){    }

//SF1_NAT actions
    action set_src_nat_rewrite_index(bit<14> nat_rewrite_index) {
        meta.nat_metadata.nat_rewrite_index = nat_rewrite_index;
    }

    action set_dst_nat_nexthop_index(bit<14> nat_rewrite_index) { // nexthop_index, nexthop_type,
        meta.nat_metadata.nat_rewrite_index = nat_rewrite_index;
        meta.nat_metadata.nat_hit = 1;
    }

    action set_twice_nat_nexthop_index(bit<14> nat_rewrite_index) { // nexthop_index, nexthop_type,
        meta.nat_metadata.nat_rewrite_index = nat_rewrite_index;
        meta.nat_metadata.nat_hit = 1;  
    }

    action nat_update_l4_checksum() {
        meta.nat_metadata.update_checksum = 1;
        meta.nat_metadata.l4_len = hdr.ipv4.totalLen -20;
    }       


    action set_nat_src_rewrite(bit<32> src_ip) {
        hdr.ipv4.srcAddr = src_ip;
        nat_update_l4_checksum();
        meta.metadata_si = meta.metadata_si - 1;

    }

    action set_nat_dst_rewrite(bit<32> dst_ip, bit<9> port) {
        hdr.ipv4.dstAddr = dst_ip;
        nat_update_l4_checksum();
        ig_tm_md.ucast_egress_port = port; 
        meta.metadata_si = meta.metadata_si - 1;
    }

    action set_nat_src_dst_rewrite(bit<32> src_ip, bit<32> dst_ip) {
        hdr.ipv4.srcAddr = src_ip;
        hdr.ipv4.dstAddr = dst_ip;
        nat_update_l4_checksum();
        meta.metadata_si = meta.metadata_si - 1;
    }

    action set_nat_src_udp_rewrite(bit<32> src_ip, bit<16> src_port) {
        hdr.ipv4.srcAddr = src_ip;
        hdr.udp.srcPort = src_port;
        nat_update_l4_checksum();
        meta.metadata_si = meta.metadata_si - 1;
    }

    action set_nat_dst_udp_rewrite(bit<32> dst_ip, bit<16>dst_port) {
        hdr.ipv4.dstAddr = dst_ip;
        hdr.udp.dstPort = dst_port;
        nat_update_l4_checksum();
        meta.metadata_si = meta.metadata_si - 1;
    }

    action set_nat_src_dst_udp_rewrite(bit<32> src_ip, bit<32> dst_ip, bit<16> src_port, bit<16> dst_port) {
        hdr.ipv4.srcAddr = src_ip;
        hdr.ipv4.dstAddr = dst_ip;
        hdr.udp.srcPort = src_port;
        hdr.udp.dstPort = dst_port;
        nat_update_l4_checksum();
        meta.metadata_si = meta.metadata_si - 1;
    }

    action set_nat_src_tcp_rewrite(bit<32> src_ip, bit<16> src_port) {
        hdr.ipv4.srcAddr = src_ip;
        hdr.tcp.srcPort = src_port;
        nat_update_l4_checksum();
        meta.metadata_si = meta.metadata_si - 1;
    }

    action set_nat_dst_tcp_rewrite(bit<32> dst_ip, bit<16> dst_port) {
        hdr.ipv4.dstAddr = dst_ip;
        hdr.tcp.dstPort = dst_port;
        nat_update_l4_checksum();
        meta.metadata_si = meta.metadata_si - 1;
    }

    action set_nat_src_dst_tcp_rewrite(bit<32> src_ip, bit<32> dst_ip, bit<16> src_port, bit<16> dst_port) {
        hdr.ipv4.srcAddr = src_ip;
        hdr.ipv4.dstAddr = dst_ip;
        hdr.tcp.srcPort = src_port;
        hdr.tcp.dstPort = dst_port;
        nat_update_l4_checksum();
        meta.metadata_si = meta.metadata_si - 1;
    }

//SF2_LB actions
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash;
 
    action set_ecmp_select(bit<16> ecmp_base, bit<16> ecmp_count) {
	meta.ecmp_select = hash.get({hdr.ipv4.srcAddr, hdr.ipv4.dstAddr,
                        hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort},
                        ecmp_base, ecmp_count);	
    }

    action set_nhop(bit<48> nhop_dmac, bit<32> nhop_ipv4, bit<9> port) {
        hdr.out_ethernet.dstAddr = nhop_dmac;
        meta.ipv4_metadata.lkp_ipv4_da = nhop_ipv4;
        hdr.ipv4.dstAddr = nhop_ipv4;
        ig_tm_md.ucast_egress_port = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action rewrite_mac(bit<48> smac) {
        hdr.out_ethernet.srcAddr = smac;
        meta.metadata_si = meta.metadata_si - 1;
    }

//SF3_ipv4 actions
    action send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        meta.metadata_si = meta.metadata_si - 1;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action forward(bit<9> port) {
        meta.metadata_si = meta.metadata_si - 1;
        ig_tm_md.ucast_egress_port = port; ///
    }
    
    action sff_forward() {
        hdr.nsh.spi = meta.metadata_spi;
        hdr.nsh.si = meta.metadata_si;
        hdr.ipv4.srcAddr = meta.ipv4_metadata.lkp_ipv4_sa;
        hdr.ipv4.dstAddr = meta.ipv4_metadata.lkp_ipv4_da;
        hdr.out_ethernet.srcAddr = meta.l2_metadata.srcAddr;
        hdr.out_ethernet.dstAddr = meta.l2_metadata.dstAddr;
    }

    action loopback() {  
        ig_tm_md.ucast_egress_port = 68;
        hdr.nsh.spi = meta.metadata_spi;
        hdr.nsh.si = meta.metadata_si;
        hdr.ipv4.srcAddr = meta.ipv4_metadata.lkp_ipv4_sa;
        hdr.ipv4.dstAddr = meta.ipv4_metadata.lkp_ipv4_da;
        hdr.out_ethernet.srcAddr = meta.l2_metadata.srcAddr;
        hdr.out_ethernet.dstAddr = meta.l2_metadata.dstAddr;
    } 

/****************** Ingress Tables*******************/

// SF1_NAT Table
    table nat_twice {
        key = {
            meta.ipv4_metadata.lkp_ipv4_sa : exact;
            meta.ipv4_metadata.lkp_ipv4_da : exact;
            meta.l3_metadata.lkp_ip_proto : exact;
            meta.l3_metadata.lkp_l4_sport : exact;
            meta.l3_metadata.lkp_l4_dport : exact;
            meta.metadata_spi: exact;
            meta.metadata_si: exact;
        }
        actions = {
            on_miss;
            set_twice_nat_nexthop_index;
            NoAction;
        }
        
        default_action = NoAction();
    }
   
    table nat_dst {
        key = {
            meta.ipv4_metadata.lkp_ipv4_da : exact;
            meta.l3_metadata.lkp_ip_proto : exact;
            meta.l3_metadata.lkp_l4_dport : exact;
            meta.metadata_spi: exact;
            meta.metadata_si: exact;
        }
        actions = {
            on_miss;
            set_dst_nat_nexthop_index;
            NoAction;
        }
        default_action = NoAction();
    }

    table nat_src {
        key = {
            meta.ipv4_metadata.lkp_ipv4_sa : exact;
            meta.l3_metadata.lkp_ip_proto : exact;
            meta.l3_metadata.lkp_l4_sport : exact;
            meta.metadata_spi: exact;
            meta.metadata_si: exact;
        }
        actions = {
            on_miss;
            set_src_nat_rewrite_index;
            NoAction;
        }
        default_action = NoAction();
    }

    table nat_flow {
        key = {
            meta.ipv4_metadata.lkp_ipv4_sa : exact; //ternary;
            meta.ipv4_metadata.lkp_ipv4_da : exact; //ternary;
            meta.l3_metadata.lkp_ip_proto : exact; //ternary;
            meta.l3_metadata.lkp_l4_sport : exact; //ternary;
            meta.l3_metadata.lkp_l4_dport : exact; //ternary;
            meta.metadata_spi: exact;
            meta.metadata_si: exact;
        }
        actions = {
            
            set_src_nat_rewrite_index;
            set_dst_nat_nexthop_index;
            set_twice_nat_nexthop_index;
            NoAction;
        }
        default_action = NoAction();
    }

    table egress_nat {
        key =  {
            meta.nat_metadata.nat_rewrite_index : exact;
            meta.metadata_spi: exact;
            meta.metadata_si: exact;
        }
        actions = {
            NoAction;
            set_nat_src_rewrite;
            set_nat_dst_rewrite;
            set_nat_src_dst_rewrite;
            set_nat_src_udp_rewrite;
            set_nat_dst_udp_rewrite;
            set_nat_src_dst_udp_rewrite;
            set_nat_src_tcp_rewrite;
            set_nat_dst_tcp_rewrite;
            set_nat_src_dst_tcp_rewrite;
        }
        default_action = NoAction();
    }

// SF2_LB Table
    table ecmp_group {
        key = {
            hdr.ipv4.dstAddr: lpm;
            meta.metadata_spi: exact;
            meta.metadata_si: exact;
        }
        actions = {
            drop;
            set_ecmp_select;
        }

    }
    table ecmp_nhop {
        key = {
            meta.ecmp_select: ternary;
            meta.metadata_spi: exact;
            meta.metadata_si: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
    }
    table send_frame {
        key = {
            ig_tm_md.ucast_egress_port: exact;
            meta.metadata_spi: exact;
            meta.metadata_si: exact;
        }
        actions = {
            rewrite_mac;
            drop;
        }
    }

// SF3_ipv4 Table
    table l3 {
        key     = { 
            meta.ipv4_metadata.lkp_ipv4_da : exact;
            meta.metadata_spi: exact;
            meta.metadata_si: exact;
        }
        actions = {
            send;
            drop;
            NoAction;
        }
        default_action = NoAction();
    }

    table fw {
        key = {
            meta.l2_metadata.srcAddr : exact;
            meta.ipv4_metadata.lkp_ipv4_sa : exact;
            meta.metadata_spi: exact;
            meta.metadata_si: exact;
        }
        actions ={
            NoAction;
            forward;
            drop;
        }
        default_action = NoAction();
    }

    table sff {
        key = {
            meta.metadata_spi: exact;
            meta.metadata_si: exact;
        }
        actions = {
            sff_forward;
            drop;
            loopback;
            NoAction;
        }
        
        default_action = sff_forward();
    }

    table ecmp_group2 {
        key = {
            hdr.ipv4.dstAddr: lpm;
            meta.metadata_spi: exact;
            meta.metadata_si: exact;
        }
        actions = {
            drop;
            set_ecmp_select;
        }

    }
    table ecmp_nhop2 {
        key = {
            meta.ecmp_select: ternary;
            meta.metadata_spi: exact;
            meta.metadata_si: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
    }
    table send_frame2 {
        key = {
            ig_tm_md.ucast_egress_port: exact;
            meta.metadata_spi: exact;
            meta.metadata_si: exact;
        }
        actions = {
            rewrite_mac;
            drop;
        }
    }


// apply

    apply{
        if(ig_intr_md.ingress_port != 68){
            hdr.in_ethernet.srcAddr = ig_prsr_md.global_tstamp;
        }
        meta.nat_metadata.ingress_nat_mode = 1;
        change_hdr_to_meta(); //

        //SF2_FW
        fw.apply();

        //SF3_NAT
        if(meta.nat_metadata.ingress_nat_mode ==0){
            nat_twice.apply();       
        }
        else if(meta.nat_metadata.ingress_nat_mode == 1){
            nat_dst.apply();
        }
        else if(meta.nat_metadata.ingress_nat_mode == 2){
            nat_src.apply();
        }
        else if(meta.nat_metadata.ingress_nat_mode == 3){
            nat_flow.apply();
        }
        egress_nat.apply();

        //SF4_L3
        l3.apply();
        
        //SF1'_LB
        ecmp_group.apply();
        ecmp_nhop.apply();
        send_frame.apply();
        
        sff.apply();
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control SwitchIngressDeparser(
        packet_out packet,
        inout headers hdr,
        in metadata_t meta,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    
    

    apply{

        packet.emit(hdr);

    }
    
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

parser EgressParser(
	packet_in packet,
	out headers hdr,
	out metadata_t meta,
	out egress_intrinsic_metadata_t eg_intr_md){

	state start {
 		packet.extract(eg_intr_md);
        transition parse_out_ethernet;
	}
   
    state parse_out_ethernet {
        packet.extract(hdr.out_ethernet);
        transition select(hdr.out_ethernet.etherType) {
            TYPE_NSH: parse_nsh;
            default: accept;
        }
    }
    
    state parse_nsh {
        packet.extract(hdr.nsh);
        transition select(hdr.nsh.Nextpro) {
            TYPE_ETHER: parse_in_ethernet;
            default: accept;
        }
    }

    state parse_in_ethernet {
        packet.extract(hdr.in_ethernet);
        transition accept;
        
    }

}

control Egress(
	inout headers hdr,
	inout metadata_t meta,
	in egress_intrinsic_metadata_t eg_intr_md,
	in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
	inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
	inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport){



	apply{
        hdr.in_ethernet.dstAddr = eg_prsr_md.global_tstamp; 
    }

}

control EgressDeparser(
	packet_out packet,
	inout headers hdr,
	in metadata_t eg_md,
	in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

	apply{
        packet.emit(hdr);
    }
}


/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EgressParser(),
         Egress(),
         EgressDeparser()) pipe;

Switch(pipe) main;