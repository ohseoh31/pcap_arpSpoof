
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
  struct in_addr ip_src; 
  struct in_addr ip_dst; 
};

struct arp_hdr /* 28byte */
{
   unsigned short hardware_type; /* hardware type 2byte */
   unsigned short proto_type;    /* protocol type 2byte */
   u_int8_t hard_add_len;        /* hardware address length 1byte */
   u_int8_t proto_add_len;       /* protocol address length 1byte */
   unsigned short opcode;        /* opcode */
   unsigned char send_mac[6];    /* sender Mac address 6byte */
   struct in_addr ip_src;             /* sender ip address 4byte */
   unsigned char dst_mac[6];     /* destination Mac address 6byte*/
   struct in_addr ip_dst;     	 /* destination ip address 4byte*/
};


struct eth_arp
{
    struct ether_h;
    struct arp_hdr;
};
