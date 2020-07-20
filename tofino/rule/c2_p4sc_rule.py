from ipaddress import ip_address

# SFC1 : FW-NAT-L3-LB
# SFC2 : LB-FW
# SFC3 : NAT-L2-LB-L3
# SFC4 : LB-NAT

# --------------------------- #

# EMBEDDING : LB FW NAT L3 LB
# SFC1 : FW-NAT-L3-LB
# SFC2 : LB-FW
# SFC3 : NAT-L2-LB-L3


# src : 10.10.0.1, dst : 10.10.0.2, dst_port 80, src_port 20

def insert_rule(bfrt):

    p4 = bfrt.c2_p4sc.SwitchIngress

# SFC1 : FW-NAT-L3-LB'

    p4.fw.add_with_forward(srcaddr=1, lkp_ipv4_sa=ip_address("10.10.0.1"),
                metadata_spi=1, metadata_si=255, port=163)

    p4.nat_dst.add_with_set_dst_nat_nexthop_index(lkp_ipv4_da=ip_address("10.10.0.2"), 
                lkp_ip_proto=6, lkp_l4_dport=80, metadata_spi=1,
                metadata_si=254, nat_rewrite_index=1)
    p4.egress_nat.add_with_set_nat_dst_rewrite(nat_rewrite_index=1, metadata_spi=1,
                metadata_si=254, dst_ip=ip_address("10.10.0.2"), port=163)
    
    p4.l3.add_with_send(lkp_ipv4_da=ip_address("10.10.0.2"), metadata_spi=1, metadata_si=253,
                port=163)
    
    p4.ecmp_group2.add_with_set_ecmp_select(dstaddr=ip_address("10.10.0.2"), dstaddr_p_length=24, metadata_spi=1, metadata_si=252, 
                ecmp_base=1, ecmp_count=1)
    p4.ecmp_nhop2.add_with_set_nhop(ecmp_select=0xEE72, ecmp_select_mask=0x0000, metadata_spi=1, metadata_si=252,
                nhop_dmac=2, nhop_ipv4=ip_address("10.10.0.2"), port=163)
    # p4.send_frame2.add_with_rewrite_mac(ucast_egress_port=163, metadata_spi=1,metadata_si=252, 
    #             smac=1)

    
# SFC2 : LB-FW

    p4.ecmp_group.add_with_set_ecmp_select(dstaddr=ip_address("10.10.0.2"), 
                dstaddr_p_length=24, metadata_spi=2, metadata_si=255, 
                ecmp_base=1, ecmp_count=1)
    p4.ecmp_nhop.add_with_set_nhop(ecmp_select=0xEE72, ecmp_select_mask=0x0000, metadata_spi=2, metadata_si=255,
                nhop_dmac=2, nhop_ipv4=ip_address("10.10.0.2"), port=163)
    # p4.send_frame.add_with_rewrite_mac(ucast_egress_port=163, metadata_spi=2, metadata_si=255,
    #             smac=1)

    p4.fw.add_with_forward(srcaddr=1, lkp_ipv4_sa=ip_address("10.10.0.1"),
                metadata_spi=2, metadata_si=254, port=163)

# SFC3 : NAT-L2-LB'-loopback-L3
    p4.nat_dst.add_with_set_dst_nat_nexthop_index(lkp_ipv4_da=ip_address("10.10.0.2"), 
                lkp_ip_proto=6, lkp_l4_dport=80, metadata_spi=3,
                metadata_si=255, nat_rewrite_index=1)
    p4.egress_nat.add_with_set_nat_dst_rewrite(nat_rewrite_index=1, metadata_spi=3,
                metadata_si=255, dst_ip=ip_address("10.10.0.2"), port=163)
    
    p4.l2.add_with_send(dstaddr=2, metadata_spi=3, metadata_si=254, port=163)

    p4.ecmp_group2.add_with_set_ecmp_select(dstaddr=ip_address("10.10.0.2"), 
                dstaddr_p_length=24, metadata_spi=3, metadata_si=253, 
                ecmp_base=1, ecmp_count=1)
    p4.ecmp_nhop2.add_with_set_nhop(ecmp_select=0xEE72, ecmp_select_mask=0x0000, metadata_spi=3, metadata_si=253,
                nhop_dmac=2, nhop_ipv4=ip_address("10.10.0.2"), port=176)
    # p4.send_frame2.add_with_rewrite_mac(ucast_egress_port=176, metadata_spi=3, metadata_si=253,
    #             smac=1)

    p4.sff.add_with_sff_forward_no_tstamp(metadata_spi=3, metadata_si=251)

    p4.l3.add_with_send(lkp_ipv4_da=ip_address("10.10.0.2"), metadata_spi=3, metadata_si=252, port=163)
