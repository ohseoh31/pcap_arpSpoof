
struct ether_h /* 14byte */
{
  unsigned char ether_dst_mac[6];  /*dst_mac 6byte*/
  unsigned char ether_src_mac[6];  /*src_mac 6byte*/  
  unsigned short ether_type; //2byte
};

struct ARP_Spoof
{
  unsigned char ether_dst_mac[6];
  unsigned char ether_src_mac[6];
  unsigned short opcode;
  u_int32_t ip_src; 
  u_int32_t ip_dst; 
};

struct arp_hdr /* 28byte */
{
   unsigned short hardware_type; /* hardware type 2byte */
   unsigned short proto_type;    /* protocol type 2byte */
   u_int8_t hard_add_len;        /* hardware address length 1byte */
   u_int8_t proto_add_len;       /* protocol address length 1byte */
   unsigned short opcode;        /* opcode */
   unsigned char send_mac[6];    /* sender Mac address 6byte */
   u_int32_t ip_src;             /* sender ip address 4byte */
   unsigned char dst_mac[6];     /* destination Mac address 6byte*/
   u_int32_t ip_dst;     	 /* destination ip address 4byte*/
};



struct ip_hdr
{
    unsigned int ip_hl:4;   /* header length */
    unsigned int ip_v:4;    /* version */
    u_int8_t ip_tos;        /* type of service */
    u_short ip_len;         /* total length */
    u_short ip_id;          /* identification */
    u_short ip_off;         /* fragment offset field */
    u_int8_t ip_ttl;        /* time to live */
    u_int8_t ip_p;          /* protocol */
    u_short ip_sum;         /* checksum */
    struct in_addr ip_src;
    struct in_addr ip_dst;
 };


struct tcp_hdr
{
    u_int16_t th_sport;     /* source port */
    u_int16_t th_dport;     /* destination port */
    tcp_seq th_seq;         /* sequence number */
    tcp_seq th_ack;         /* acknowledgement number */
    u_int8_t th_x2:4;       /* (unused) */
    u_int8_t th_off:4;      /* data offset */
    u_int8_t th_flags;      
    u_int16_t th_win;       /* window */
    u_int16_t th_check;       /* checksum */
    u_int16_t th_urp;       /* urgent pointer */
};

struct dns_hdr
{
    u_int16_t th_sport;
    u_int16_t th_dport;
};
