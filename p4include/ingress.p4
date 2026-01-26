/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

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
        meta.internal_ip = 0;
        meta.internal_port = 0;
        meta.external_ip = 0;
        meta.external_port = 0;

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


 /***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{

    action send_to_cpu() {
        ig_tm_md.ucast_egress_port = CPU_PORT_1;
    }

    action set_egress_port(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    @idletime_precision(ENTRY_IDLE_TIMEOUT_NBIT_NOTIFICATION)
    table active_host_tbl {
        key = {
            meta.internal_ip   : exact;
            meta.internal_port : exact;
            meta.ip_protocol   : exact;
        }
        
        actions = {
            set_egress_port; 
            send_to_cpu;
            drop;
            NoAction;
        }
        default_action = NoAction();
        size = ACTIVE_HOST_TABLE_SIZE;
        idle_timeout = true;
    }
    
    action set_src_internal() {
        meta.internal_ip = meta.src_ip;
        meta.internal_port = meta.src_port;
        meta.external_ip = meta.dst_ip;
        meta.external_port = meta.dst_port;
    }

    action set_dst_internal() {
        meta.internal_ip = meta.dst_ip;
        meta.internal_port = meta.dst_port;        
        meta.external_ip = meta.src_ip;
        meta.external_port = meta.src_port;
    }

    table internal_ip_check {
        key = {
            hdr.ipv4.src_addr : ternary;
            hdr.ipv4.dst_addr : ternary;
        }
        actions = {
            set_src_internal();
            set_dst_internal();
            send_to_cpu();
            NoAction;
        }
        size = 10;
        const default_action = NoAction();
        // const entries = {
        //     (INTERNAL_NET &&& INTERNAL_NET_MASK, _) : set_src_internal();
        //     (_, INTERNAL_NET &&& INTERNAL_NET_MASK) : set_dst_internal();
        // }
    }


    table whitelist_tbl {
        key = {
            meta.external_ip : exact;
            meta.external_port : exact;
            meta.ip_protocol: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 4096;
        const default_action = NoAction();
    }

    action send_to_controller(bit<48> dst_mac, PortId_t out_port)
    {
        hdr.ethernet.dst_addr = dst_mac;
        ig_tm_md.ucast_egress_port = out_port;
    }

    
    ActionProfile(16) send_to_controller_ap;
    Hash<bit<8>>(HashAlgorithm_t.CRC16) hash_fn;
    ActionSelector(action_profile = send_to_controller_ap,
                   hash = hash_fn,
                   mode = SelectorMode_t.FAIR,
                   max_group_size = 16,
                   num_groups = 16) send_to_controller_selector;

    table fwd_controller_tbl {
        key = {
            // Just a placeholder, do not need the key
            hdr.ethernet.ether_type: exact;

            meta.internal_ip: selector;
            meta.external_ip: selector;
            meta.internal_port: selector;
            meta.external_port: selector;
            meta.ip_protocol: selector;
        }

        actions = {
            send_to_controller;
            NoAction;
        }

        implementation = send_to_controller_selector;
        size = 16;
        const default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid())
        {
            if ((hdr.ipv4.protocol != IP_PROTO_ICMP) && (hdr.ipv4.protocol != IP_PROTO_TCP) && (hdr.ipv4.protocol != IP_PROTO_UDP))
            {
                drop();
            }
            if (internal_ip_check.apply().hit) 
            {
                if (!whitelist_tbl.apply().hit)
                {
                    if(!active_host_tbl.apply().hit)
                    {
                        // Set dst_mac and outport
                        fwd_controller_tbl.apply();
                    }
                }
            }
            else 
            {
                // drop all external-external packets
                drop();
            }
        }

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