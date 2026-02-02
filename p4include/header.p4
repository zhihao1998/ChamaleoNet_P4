/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */

header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<6>   dscp;
    bit<2>   ecn;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header icmp_h {
    bit<8> icmp_type;
    bit<8> icmp_code;
    bit<16> checksum;
    // the following bits depend on the type of ICMP msgs, which could be unused/meaningless
    bit<16> identifier;
    bit<16> sequence_number;
    bit<64> timestamp;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
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

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length_;
    bit<16> checksum;
}

/***********************  U S E R - D E F I N E D   H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h          ethernet;
    ipv4_h              ipv4;
    icmp_h              icmp;
    tcp_h               tcp;
    udp_h               udp;
}

struct my_ingress_metadata_t {
    bit<32>  src_ip;
    bit<32>  dst_ip;
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<8>   ip_protocol;

    bit<32>  internal_ip;
    bit<16>  internal_port;
    bit<32>  external_ip;
    bit<16>  external_port;

    bit<1>  bloom_op; // 0 read 1 set

    bit<2> bloom_epoch;

    // hash indices (0..(BLOOM_WORDS*32-1))
    bit<32> bloom_idx0;
    bit<32> bloom_idx1;
    bit<32> bloom_idx2;
    bit<32> bloom_idx3;

    // query results
    bit<3>  bloom_hit;
    bit<1>  bloom_hit_0; // and
    bit<1>  bloom_hit_1; // OR across epochs
    bit<1>  bloom_hit_2; // OR across epochs
    bit<1>  bloom_hit_3; // OR across epochs
}

typedef my_ingress_headers_t my_egress_headers_t;

struct my_egress_metadata_t {
}




