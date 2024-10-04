/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

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
        // ig_tm_md.copy_to_cpu       = 1;
    }

    action send_to_nf() {
        hdr.ethernet.dst_addr = NF_MAC_ADDR;
        ig_tm_md.ucast_egress_port = NF_PORT_2;
    }

    action set_egress_port(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    @idletime_precision(ENTRY_IDLE_TIMEOUT_NBIT_POLL)
    table icmp_flow {
        key = {
            hdr.ipv4.src_addr              : ternary;
            hdr.ipv4.dst_addr              : ternary;
        }
        
        actions = {
            set_egress_port; 
            send_to_cpu;
            send_to_nf;
            drop;
        }
        default_action = send_to_nf();
        size = 500;
        idle_timeout = true;
    }
    
    @idletime_precision(ENTRY_IDLE_TIMEOUT_NBIT_POLL)
    table tcp_flow {
        key = {
            hdr.ipv4.src_addr              : ternary;
            hdr.ipv4.dst_addr              : ternary;
            hdr.tcp.src_port               : exact;
            hdr.tcp.dst_port               : exact;
        }
        
        actions = {
            set_egress_port; 
            send_to_cpu;
            send_to_nf;
            drop;
        }
        default_action = send_to_nf();
        size = DEFAULT_TABLE_SIZE;
        idle_timeout = true;
    }
    
    @idletime_precision(ENTRY_IDLE_TIMEOUT_NBIT_POLL)
    table udp_flow {
        key = {
            hdr.ipv4.src_addr              : ternary;
            hdr.ipv4.dst_addr              : ternary;
            hdr.udp.src_port               : exact;
            hdr.udp.dst_port               : exact;
        }
        
        actions = {
            set_egress_port; 
            send_to_cpu;
            send_to_nf;
            drop;
        }
        default_action = send_to_nf();
        size = DEFAULT_TABLE_SIZE;
        idle_timeout = true;
    }
    
    apply {
        if (hdr.ipv4.isValid()) {
            if (hdr.icmp.isValid()){
                icmp_flow.apply();
            }
            else if (hdr.tcp.isValid()){
                tcp_flow.apply();
            }
            else if (hdr.udp.isValid()){
                udp_flow.apply();
            }
        }
    }
}