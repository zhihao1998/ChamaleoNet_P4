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
            ETHERTYPE_RULE:     parse_bloom_ipv4;
            default:            parse_non_ipv4;
        }
    }
    state parse_bloom_ipv4 {
        meta.bloom_op = 1; // write

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
    state parse_ipv4 {
        meta.bloom_op = 0; // read
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
        meta.internal_port = 0;
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
#define BLOOM_REG(i) \
    Register<BLOOM_WORD_BITS, bit<32>>(BLOOM_WORDS) bloom_group0_epoch##i; \
    RegisterAction<BLOOM_WORD_BITS, bit<32>, BLOOM_WORD_BITS>(bloom_group0_epoch##i) bloom_group0_read_epoch##i = { \
        void apply(inout BLOOM_WORD_BITS reg_value, out BLOOM_WORD_BITS out_value){ \
            out_value = reg_value; \
        } \
    }; \
    RegisterAction<BLOOM_WORD_BITS, bit<32>, void>(bloom_group0_epoch##i) bloom_group0_set_epoch##i = { \
        void apply(inout BLOOM_WORD_BITS reg_value) { \
            reg_value = 1; \
        } \
    }; \
    Register<BLOOM_WORD_BITS, bit<32>>(BLOOM_WORDS) bloom_group1_epoch##i; \
    RegisterAction<BLOOM_WORD_BITS, bit<32>, BLOOM_WORD_BITS>(bloom_group1_epoch##i) bloom_group1_read_epoch##i = { \
        void apply(inout BLOOM_WORD_BITS reg_value, out BLOOM_WORD_BITS out_value){ \
            out_value = reg_value; \
        } \
    }; \
    RegisterAction<BLOOM_WORD_BITS, bit<32>, void>(bloom_group1_epoch##i) bloom_group1_set_epoch##i = { \
        void apply(inout BLOOM_WORD_BITS reg_value) { \
            reg_value = 1; \
        } \
    }; \
    action bloom_read_group0_epoch##i() { \
        bit<1> hit = bloom_group0_read_epoch##i.execute(meta.bloom_idx0); \
        meta.bloom_hit_##i = meta.bloom_hit_##i & hit; \
    } \
    action bloom_set_group0_epoch##i() { \
        bloom_group0_set_epoch##i.execute(meta.bloom_idx0); \
    } \
    table bloom_op_tbl0_epoch##i { \
        key = {meta.bloom_op: exact;} \
        actions = {bloom_read_group0_epoch##i; bloom_set_group0_epoch##i;} \
        const entries = { \
            (0): bloom_read_group0_epoch##i(); \
            (1): bloom_set_group0_epoch##i(); \
        } \
        size = 2; \
    } \
    action bloom_read_group1_epoch##i() { \
        bit<1> hit = bloom_group1_read_epoch##i.execute(meta.bloom_idx1); \
        meta.bloom_hit_##i = meta.bloom_hit_##i & hit; \
    } \
    action bloom_set_group1_epoch##i() { \
        bloom_group1_set_epoch##i.execute(meta.bloom_idx1); \
    } \
    table bloom_op_tbl1_epoch##i { \
        key = {meta.bloom_op: exact;} \
        actions = {bloom_read_group1_epoch##i; bloom_set_group1_epoch##i;} \
        const entries = { \
            (0): bloom_read_group1_epoch##i(); \
            (1): bloom_set_group1_epoch##i(); \
        } \
        size = 2; \
    } \


    CRCPolynomial<bit<32>>(32w0x04C11DB7, // polynomial
                           true,          // reversed
                           false,         // use msb?
                           false,         // extended?
                           32w0x00000000, // initial shift register value
                           32w0xFFFFFFFF  // result xor
                           ) poly0;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly0) hash0;

    CRCPolynomial<bit<32>>(32w0x1EDC6F41, // polynomial
                           true,          // reversed
                           false,         // use msb?
                           false,         // extended?
                           32w0x00000000, // initial shift register value
                           32w0xFFFFFFFF  // result xor
                           ) poly1;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly1) hash1;


    action hash0_apply() {
        meta.bloom_idx0 = hash0.get({meta.internal_ip, meta.internal_port, meta.ip_protocol}) % BLOOM_WORDS;
    }
    table hash0_tbl {
        actions = {hash0_apply;}
        const default_action = hash0_apply();
        size = 1;
    }

    action hash1_apply() {
        meta.bloom_idx1 = hash1.get({meta.internal_ip, meta.internal_port, meta.ip_protocol}) % BLOOM_WORDS;
    }
    table hash1_tbl {
        actions = {hash1_apply;}
        const default_action = hash1_apply();
        size = 1;
    }


    // Define bloom filters
    BLOOM_REG(0)
    BLOOM_REG(1)

    // table used to set the current bloom_epoch (by bfrt)
    action set_epoch(bit<2> e) { meta.bloom_epoch = e; }
    table bloom_epoch_tbl {
        key = { hdr.ethernet.ether_type : exact; }
        actions = { set_epoch; }
        size = 1;
        const default_action = set_epoch(0);
    }

    // Actions for packet output 
    action set_egress_port(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    // Exact match table for persistent entries
    @idletime_precision(ENTRY_IDLE_TIMEOUT_NBIT_NOTIFICATION)
    table active_host_tbl {
        key = {
            meta.internal_ip   : exact;
            meta.internal_port : exact;
            meta.ip_protocol   : exact;
        }
        
        actions = {
            set_egress_port; 
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
                        /* Check if bloom filter is hit */
                        hash0_tbl.apply();
                        hash1_tbl.apply();
                        bloom_epoch_tbl.apply();
                        // initialize bloom_hit
                        meta.bloom_hit_0 = 1;
                        meta.bloom_hit_1 = 1;
                        // decide which epochs to execute
                        bool do_e0 = false;
                        bool do_e1 = false;

                        if (meta.bloom_op == 0) {
                            // read from all epochs
                            do_e0 = true; do_e1 = true;
                        } else {
                            // write only to current epoch
                            if (meta.bloom_epoch == 0)      do_e0 = true;
                            else if (meta.bloom_epoch == 1) do_e1 = true;
                             // drop / mark packets used to set the bloom op
                            meta.bloom_hit = 1;
                        }

                        // apply each table at most once in this control
                        if (do_e0) {
                            bloom_op_tbl0_epoch0.apply();
                            bloom_op_tbl1_epoch0.apply();
                            meta.bloom_hit = meta.bloom_hit + (bit<3>)meta.bloom_hit_0;
                        }
                        if (do_e1) {
                            bloom_op_tbl0_epoch1.apply();
                            bloom_op_tbl1_epoch1.apply();
                            meta.bloom_hit = meta.bloom_hit + (bit<3>)meta.bloom_hit_1;
                        }
                        

                        // packet actions
                        if (meta.bloom_hit == 0) {
                            // the first time to see this flow or unanswered, send to controller
                            fwd_controller_tbl.apply();
                        } else {
                            // answered flows, drop
                            drop();
                        }
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