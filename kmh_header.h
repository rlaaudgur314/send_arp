#include <libnet.h>
#include <stdint.h>

struct arp_packet
{
	struct libnet_ethernet_hdr ethernet;
	struct libnet_arp_hdr arp;
	uint8_t source_HA[6];
	uint8_t source_IP[4];
	uint8_t destination_HA[6];
	uint8_t destination_IP[4];
};

char* my_ether_ntoa(struct libnet_ether_addr* HA, char *buf);
int GetLocalIP(struct in_addr* IP, const char *dev);
int GetLocalHA(struct libnet_ether_addr* HA, const char *dev);
int SendARPRequest(pcap_t* handle, struct in_addr* SenderIP, struct in_addr* TargetIP, struct libnet_ether_addr* SenderHA);
int SendARPReply(pcap_t* handle, struct in_addr* SenderIP, struct in_addr* TargetIP, struct libnet_ether_addr* SenderHA, struct libnet_ether_addr* TargetHA);
int GetTargetHA(pcap_t* handle, struct in_addr* SenderIP, struct in_addr* TargetIP, struct libnet_ether_addr* SenderHA, struct libnet_ether_addr* TargetHA);
