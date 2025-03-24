#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>

// 패킷 처리 함수
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;

    // Ethernet 헤더 확인
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
        return;

    // IP 헤더 추출
    struct ip *ip_packet = (struct ip *)(packet + sizeof(struct ether_header));
    int ip_header_len = ip_packet->ip_hl << 2; // IP 헤더 길이 계산
    if (ip_packet->ip_p != IPPROTO_TCP)
        return;

    // TCP 헤더 추출
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
    int tcp_header_len = tcp_header->th_off << 2; // TCP 헤더 길이 계산

    // Ethernet 정보 출력
    printf("Ethernet Header:\n");
    printf(" Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
           eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf(" Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
           eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    // IP 정보 출력
    printf("IP Header:\n");
    printf(" Source IP: %s\n", inet_ntoa(ip_packet->ip_src));
    printf(" Destination IP: %s\n", inet_ntoa(ip_packet->ip_dst));

    // TCP 정보 출력
    printf("TCP Header:\n");
    printf(" Source Port: %d\n", ntohs(tcp_header->th_sport));
    printf(" Destination Port: %d\n", ntohs(tcp_header->th_dport));

    // 데이터 페이로드 출력
    int data_length = pkthdr->len - sizeof(struct ether_header) - ip_header_len - tcp_header_len;
    if (data_length > 0) {
        printf("Message Data (First 64 Bytes):\n");
        for (int i = 0; i < data_length && i < 64; i++) {
            printf("%02x ", packet[sizeof(struct ether_header) + ip_header_len + tcp_header_len + i]);
        }
        printf("\n");
    }
}

// 메인 함수
int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("ens32", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[] = "tcp";

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_close(handle);

    return 0;
}
