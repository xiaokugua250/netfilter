//
// Created by liangdu on 20-1-2.
// Author liang.du@nscc-gz.cn
//capture a single packet

#include<stdio.h>
#include<time.h>
#include<pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);

int main(int argc,char **argv){
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handler;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int packet_count_limit=1;
    int timeout_limit=10000; // in millisecond
    device = pcap_lookupdev(error_buffer);
    if (device == NULL){
        printf("error in find device,err is :%s\n",error_buffer);
        return 1;
    }
    handler = pcap_open_live(device,BUFSIZ,packet_count_limit,timeout_limit,error_buffer);

    /* Attempt to capture one packet. If there is no network traffic
     and the timeout is reached, it will return NULL */
    packet =pcap_next(handler,&packet_header);
    if (packet == NULL){
        printf("NO PACKET FOUND,\n");
        return 2;
    }
    print_packet_info(packet,packet_header);
    return  0;

}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);

}