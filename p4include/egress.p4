/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

/***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         my_eg_meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition parse_metadata;
    }

    state parse_metadata {
        my_eg_meta.egr_mir_ses = 0;
        my_eg_meta.pkt_type = 0;
        
        mirror_h mirror_md = pkt.lookahead<mirror_h>();
        transition select(mirror_md.pkt_type) {
            PKT_TYPE_MIRROR : parse_mirror_md;
            PKT_TYPE_NORMAL : parse_bridged_md;
            default: accept;
        }
    }

    state parse_mirror_md {
        mirror_h mirror_md;
        pkt.extract(mirror_md);
        transition parse_ethernet;
    }

    state parse_bridged_md {
        pkt.extract(hdr.mirror_bridged_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}

/***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         my_eg_meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    action set_egr_mirror () {
        my_eg_meta.egr_mir_ses = hdr.mirror_bridged_md.egr_mir_ses;
        my_eg_meta.pkt_type = PKT_TYPE_MIRROR;
        eg_dprsr_md.mirror_type = MIRROR_TYPE_E2E;

    }
    apply {
        if (hdr.mirror_bridged_md.do_egr_mir == 1) {
            set_egr_mirror();
        }
    }
}

/*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      my_eg_meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    Mirror() mirror;

    apply {
        if (eg_dprsr_md.mirror_type == MIRROR_TYPE_E2E) {
            mirror.emit<mirror_h>(my_eg_meta.egr_mir_ses, {my_eg_meta.pkt_type});
        }

        pkt.emit(hdr.ethernet);
    }
}
