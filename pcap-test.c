#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}


void print_ether_hdr(const u_char* packet){
    struct libnet_ethernet_hdr *eth_hdr;
    eth_hdr = (struct libnet_ethernet_hdr *)packet;
    printf("=========Ethernet=========\n");

    printf("-Src Addr: ");
    for(int i = 0; i < 5; i++)
        printf("%02x:" ,eth_hdr->ether_shost[i]);
    printf("%02x\n" , eth_hdr->ether_shost[5]);

    printf("-Dst Addr: ");
    for(int i = 0; i < 5; i++)
        printf("%02x:" ,eth_hdr->ether_dhost[i]);
    printf("%02x\n\n" , eth_hdr->ether_dhost[5]);

}



int print_ip_hdr(const u_char* packet){
    struct libnet_ipv4_hdr *ip_hdr;
    ip_hdr = (struct libnet_ipv4_hdr *)packet;

    printf("=========IP Address=========\n");
    printf("-Src IP Addr : %s\n", inet_ntoa(ip_hdr->ip_src) );
    printf("-Dst IP Addr : %s\n\n", inet_ntoa(ip_hdr->ip_dst) );
}



int print_tcp_hdr(const u_char* packet){
    struct libnet_tcp_hdr *tcp_hdr;
    tcp_hdr = (struct libnet_tcp_hdr *)packet;

    printf("=========TCP Address=========\n");
    printf("-Src TCP Port : %d\n", ntohs(tcp_hdr->th_sport));
    printf("-Dst TCP Port : %d\n\n", ntohs(tcp_hdr->th_dport));

}



int print_payload(const u_char *packet){
    printf("=========Payload(Data)=========\n");
           printf("Payload(Data): ");
    for(int i =0 ; i<8; i++){
        printf("%02x ", packet[i]);
    }
    printf("\n");
}



int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;


	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    //pcap_open_live packet
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

        while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;

		}

        struct libnet_tcp_hdr *tcp_hdr;
        tcp_hdr = (struct libnet_tcp_hdr *)packet;
        print_ether_hdr(packet);
        packet = packet + 14;
        print_ip_hdr(packet);
        print_tcp_hdr(packet + 20);
        print_payload(packet + 20 + (tcp_hdr->th_off*4));


	}

	pcap_close(pcap);
}
