#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include "libnet/include/libnet.h"

#define IPV4_TYPE 0x8
#define TCP_PROTOCOL 0x6

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test en0\n");
}

typedef struct {
	char *dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param *param, int argc, char *argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

u_int8_t word_to_bytes(u_int8_t word) {
	return word * 4;
}

void print_mac_address(u_int8_t *host) {
	for (int i = 0; i < 6; i++) {
		if (i == 5) {
			printf("%2x\n", host[i]);	
			break;
		}
		printf("%2x:", host[i]);
	}
}

int main(int argc, char *argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "[!] pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	struct pcap_pkthdr *header;
	const u_char *packet;
	
	struct libnet_ethernet_hdr *ethernet;
	struct libnet_ipv4_hdr *ip;
	struct libnet_tcp_hdr *tcp;
	const u_char *payload;

	while (true) {
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		ethernet = (struct libnet_ethernet_hdr *)(packet);
		if (ethernet->ether_type != IPV4_TYPE)
			continue;

		ip = (struct libnet_ipv4_hdr *)(packet + LIBNET_ETH_H);
		if (ip->ip_p != TCP_PROTOCOL)
			continue;
		u_int8_t ip_hdr_size = word_to_bytes(ip->ip_hl);

		tcp = (struct libnet_tcp_hdr *)(packet + LIBNET_ETH_H + ip_hdr_size);
		u_int8_t tcp_hdr_size = word_to_bytes(tcp->th_off);

		payload = packet + LIBNET_ETH_H + ip_hdr_size + tcp_hdr_size;
		

		printf("[>] %u bytes captured\n", header->caplen);

		printf("[+] Ethernet header size: %u bytes\n", LIBNET_ETH_H);
		printf("[>] Destination MAC adress: ");
		print_mac_address(ethernet->ether_dhost);
		printf("[>] Source MAC adress: ");
		print_mac_address(ethernet->ether_shost);

		printf("[+] IP header size: %u bytes\n", ip_hdr_size);
		printf("[>] Source IP adress: %s\n", inet_ntoa(ip->ip_src));
		printf("[>] Destination IP adress: %s\n", inet_ntoa(ip->ip_dst));

		printf("[+] TCP header size: %u bytes\n", tcp_hdr_size);
		printf("[>] Source port number: %u\n", ntohs(tcp->th_sport));
		printf("[>] Destination port number: %u\n", ntohs(tcp->th_dport));

		printf("[+] Payload hexadecimal value (8 bytes): ");
		for (int i = 0; i < 8; i++) {
			printf("%02x ", payload[i]);
		}
		printf("\n==============================================================\n\n");
	}

	pcap_close(pcap);
	return 0;
}
