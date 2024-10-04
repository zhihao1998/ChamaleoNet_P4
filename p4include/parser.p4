/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h          ethernet;
    ipv4_h              ipv4;
    icmp_h              icmp;
    tcp_h               tcp;
    udp_h               udp;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    bit<32>  src_ip;
    bit<32>  dst_ip;
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<8>   ip_protocol;

    bit<32>  internal_ip;
    bit<16>  internal_port;
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:     parse_ipv4;
            default:            parse_non_ipv4;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.src_ip = hdr.ipv4.src_addr;
        meta.dst_ip = hdr.ipv4.dst_addr;
        meta.ip_protocol = hdr.ipv4.protocol;
        meta.internal_ip = 0;
        meta.internal_port = 0;

        transition select(hdr.ipv4.protocol) {
            IP_PROTO_ICMP: parse_icmp;
            IP_PROTO_TCP:  parse_tcp;
            IP_PROTO_UDP:  parse_udp;
            default:       parse_unknow_ip;
        }
    }
    /* Actually useless, just to avoid warning */
    state parse_non_ipv4 {
        meta.src_ip = 0;
        meta.dst_ip = 0;
        meta.ip_protocol = 0;
        meta.src_port = 0;
        meta.dst_port = 0;
        meta.internal_ip = 0;
        meta.internal_port = 0;
        transition reject;
    }
    state parse_icmp {
        pkt.extract(hdr.icmp);
        meta.src_port = 0;
        meta.dst_port = 0;
        transition accept;
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.src_port = hdr.tcp.src_port;
        meta.dst_port = hdr.tcp.dst_port;
        transition accept;
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        meta.src_port = hdr.udp.src_port;
        meta.dst_port = hdr.udp.dst_port;
        transition accept;
    }
    state parse_unknow_ip {
        meta.src_port = 0;
        meta.dst_port = 0;
        transition accept;
    }


}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}