#include <stdio.h>
#include <pcap.h>
#include <libnet.h>
#include "kmh_header.h"

char* my_ether_ntoa(struct libnet_ether_addr* HA, char* buf)
{
	snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x", HA->ether_addr_octet[0], HA->ether_addr_octet[1], HA->ether_addr_octet[2], HA->ether_addr_octet[3], HA->ether_addr_octet[4], HA->ether_addr_octet[5]);
	return buf;
}

int GetLocalIP(struct in_addr* IP, const char *dev)
{
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, strlen(dev));
	if(ioctl(fd, SIOCGIFADDR, &ifr) == -1) 
		return 0;
	close(fd);

	memcpy(IP, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, sizeof(in_addr));

	return 1;
}


int GetLocalHA(struct libnet_ether_addr* HA, const char *dev)
{
	int fd;        struct ifreq ifr;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, strlen(dev));       
	if(ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) 
		return 0;
	close(fd);

	memcpy(HA, ifr.ifr_ifru.ifru_hwaddr.sa_data, sizeof(libnet_ether_addr));

	return 1;
}

int SendARPRequest(pcap_t* handle, struct in_addr* SenderIP, struct in_addr* TargetIP, struct libnet_ether_addr* SenderHA)
{
	
	struct arp_packet* arp = (struct arp_packet*)malloc(sizeof(arp_packet));
	unsigned char* packet = (unsigned char*)malloc(sizeof(arp_packet));
	int i;

	// ethernet header
	for(i=0;i<6;i++)
		arp->ethernet.ether_dhost[i] = 0xff;
	memcpy(arp->ethernet.ether_shost, SenderHA, sizeof(libnet_ether_addr));
	
	arp->ethernet.ether_type = htons(ETHERTYPE_ARP);
	
	// arp header 
	arp->arp.ar_hrd = htons(0x0001);
	arp->arp.ar_pro = htons(0x0800);
	arp->arp.ar_hln = 6;
	arp->arp.ar_pln = 4;
	arp->arp.ar_op = htons(0x0001);

	// Address
	memcpy(arp->source_HA, SenderHA, sizeof(libnet_ether_addr));
	memcpy(arp->source_IP, SenderIP, sizeof(in_addr));
	for(i=0;i<6;i++)
		arp->destination_HA[i] = 0x00;
	memcpy(arp->destination_IP, TargetIP, sizeof(in_addr));

	memcpy(packet, arp, sizeof(arp_packet));
	
	if(pcap_sendpacket(handle, packet, sizeof(arp_packet)) != 0)
	{
		fprintf(stderr, "Error ARP broadcast: %s\n", pcap_geterr(handle));
		return -1;
	}

	free(arp);
	free(packet);
	
	return 1;
}

int SendARPReply(pcap_t* handle, struct in_addr* SenderIP, struct in_addr* TargetIP, struct libnet_ether_addr* SenderHA, struct libnet_ether_addr* TargetHA)
{
        
    struct arp_packet* arp = (struct arp_packet*)malloc(sizeof(arp_packet));
    unsigned char* packet = (unsigned char*)malloc(sizeof(arp_packet));

    // ethernet header
    memcpy(arp->ethernet.ether_dhost, TargetHA, sizeof(libnet_ether_addr));
    memcpy(arp->ethernet.ether_shost, SenderHA, sizeof(libnet_ether_addr));
    arp->ethernet.ether_type = htons(ETHERTYPE_ARP);
        
    // arp header 
    arp->arp.ar_hrd = htons(0x0001);
    arp->arp.ar_pro = htons(0x0800);
    arp->arp.ar_hln = 6;
    arp->arp.ar_pln = 4;
    arp->arp.ar_op = htons(0x0002);

    // Address
    memcpy(arp->source_HA, SenderHA, sizeof(libnet_ether_addr));
    memcpy(arp->source_IP, SenderIP, sizeof(in_addr));
    memcpy(arp->destination_HA, TargetHA, sizeof(libnet_ether_addr));
    memcpy(arp->destination_IP, TargetIP, sizeof(in_addr));

    memcpy(packet, arp, sizeof(arp_packet));
        
    if(pcap_sendpacket(handle, packet, sizeof(arp_packet)) != 0)
    {   
        fprintf(stderr, "Error Sending ARP Reply: %s\n", pcap_geterr(handle));
        return -1; 
    }  

    free(arp);
    free(packet);
        
    return 1;
}

int GetTargetHA(pcap_t* handle, struct in_addr* SenderIP, struct in_addr* TargetIP, struct libnet_ether_addr* SenderHA, struct libnet_ether_addr* TargetHA)
{
	struct pcap_pkthdr* header;
	const u_char* packet;
	struct arp_packet* arp;

	while(1)
	{
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0)
			continue;
		if(res == -1 || res == -2)
		{
			fprintf(stderr, "Error reading packet: %s\n", pcap_geterr(handle));
			return -1;
		}

		arp = (struct arp_packet*)packet;
		
		/* check ethernet header */
		if(memcmp(arp->ethernet.ether_dhost, SenderHA, sizeof(libnet_ether_addr)) != 0)
			continue;
		if(ntohs(arp->ethernet.ether_type) != ETHERTYPE_ARP)
			continue;
		
		/* check arp header */
		if(ntohs(arp->arp.ar_hrd) != 0x0001 || ntohs(arp->arp.ar_pro) != 0x0800 || arp->arp.ar_hln != 6 || arp->arp.ar_pln != 4 || ntohs(arp->arp.ar_op) != 0x0002)
			continue;

		/* check address */
		if(memcmp(arp->source_IP, TargetIP, sizeof(in_addr)) != 0)
			continue;
		if(memcmp(arp->destination_HA, SenderHA, sizeof(libnet_ether_addr)) != 0)
			continue;
		if(memcmp(arp->destination_IP, SenderIP, sizeof(in_addr)) != 0)
			continue;

		/* if all correct */
		memcpy(TargetHA, arp->source_HA, sizeof(libnet_ether_addr));

		return 1;
	}
}
