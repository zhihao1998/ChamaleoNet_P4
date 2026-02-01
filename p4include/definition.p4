/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/

/*Type Defination*/
const bit<16> ETHERTYPE_IPV4 = 0x0800;

const bit<8> IP_PROTO_ICMP = 1;
const bit<8> IP_PROTO_TCP = 6;
const bit<8> IP_PROTO_UDP = 17;

const bit<8> ICMP_TYPE_ECHO_REPLY = 0;
const bit<8> ICMP_TYPE_DEST_UNREACHABLE = 3;
const bit<8> ICMP_TYPE_ECHO_REQUEST = 8;
const bit<8> ICMP_TYPE_TIME_EXCEEDED = 11;

/* Length Defination */
const bit<8> ETH_HEADER_LEN = 14;
const bit<8> IPV4_MIN_HEAD_LEN = 20;
const bit<8> UDP_HEADER_LEN = 8;

/* Port Number */
// const PortId_t CPU_PORT_1 = 64; 
// const PortId_t CPU_PORT_2 = 66; 

/*Table Sizing*/
const int ACTIVE_HOST_TABLE_SIZE = 80000;

/* Entry Idle Timeout */
/* check readme for more information */
const int ENTRY_IDLE_TIMEOUT_NBIT_POLL = 1; 
const int ENTRY_IDLE_TIMEOUT_NBIT_NOTIFICATION = 0; 

typedef bit<1> BLOOM_WORD_BITS;
const bit<32> BLOOM_WORDS = 4194304;
const int BLOOM_HASH_NUM = 4;
const int BLOOM_ROTATION_NUM = 4;