//
// Created by liangdu on 20-1-3.
// Author liangdu1992@gmail.com
// get packet payload

/**
 * The payload is not always going to be in the same location. Headers will be different sizes based on the type of packet and what options are present. For this example we are strictly talking about IP packets with TCP on top.

We start with the pointer to the beginning of the packet. The first 14 bytes are the ethernet header. That is always going to be the same because it is defined in the standard. That ethernet header contains the destination then source MAC(hardware) addresses, which are lower level than IP addresses. Each one of those is 6 bytes. There are also two more bytes at the end of the ethernet header that represent the type. With two bytes you could have thousands of different types. They could be ARP packets but we only want IP packets in this situation.

Ethernet is considered the second layer in OSI's model. The only level lower than ethernet is the physical medium that the data uses, like a copper wire, fiber optics, or radio signals.

On top of ethernet, the second layer, we have the third layer: IP. That is our IP address which is one level higher than the hardware MAC address. Layer four is TCP and UDP. Before we can actually get to our payload, we have to get past the ethernet, IP, and TCP layer. That is how we will come up with the formula for calculating the payload location in memory.

IP and TCP header length are variable. The length of the IP header is one of the very first values provided in the IP header. We have to get the IP header length to figure out how much further we have to look to find the beginning of the TCP header. Once we know where the TCP header is we can get the data offset value, which is part of the TCP header. The data offset is how much further we have to go from the start of the TCP packet to the actual payload. Look at this psuedo-code.

payload_pointer =
packet_pointer + len(Ethernet header) + len(IP header) + len(TCP header)
The ethernet header is always 14 bytes as defined by standards.
The IP header length is always stored in a 4 byte integer at byte offset 4 of the IP header.
The TCP header length is always stored in a 4 byte integer at byte offset 12 of the TCP header.
The payload starts at packet base location plus all the header lengths.
Now we have enough knowledge to figure out where the payload is in memory. The IP header and TCP are typically about 20 bytes each if there are no options passed. That means the first 54 bytes are the header layers, and the rest is actual data. We should not guess or assume the headers will always be 20 bytes each though. We need to get the actual header length for both IP and TCP layers in order to calculate the offset for the payload. That is what this code example will do.
 *
 */


#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

/**
 *  find payload of tcp/ip packet
 */
void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  //first fillter IP

  struct ether_header *eth_header;
  eth_header = (struct ether_header *) packet;
  if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
    printf("Only filltering IP Packet....\n");
    return;
  }

  /* The total packet length, including all headers
     and the data payload is stored in
     include->len and include->caplen. Caplen is
     the amount actually available, and len is the
     total packet length even if it is larger
     than what we currently have captured. If the snapshot
     length set with pcap_open_live() is too small, you may
     not have the whole packet. */

  printf("Total packet avaliable:%d bytes \n", header->caplen);
  printf("Expected packet size:%d bytes \n", header->len);

  /* Pointers to start point of various headers */
  const u_char *ip_header;
  const u_char *tcp_header;
  const u_char *payload;

  // include length in bytes

  int ethernet_header_length = 14; // ethernet default include length and does not change
  int ip_header_length;
  int tcp_header_length;
  int payload_length;

  // find start of ip include
  ip_header = packet + ethernet_header_length;

  /* The second-half of the first byte in ip_header
  contains the IP include length (IHL). */
  ip_header_length = ((*ip_header) & 0x0F);

  /* The IHL is number of 32-bit segments. Multiply
     by four to get a byte count for pointer arithmetic */
  ip_header_length = ip_header_length * 4;
  printf("IP include length (IHL) in bytes :%d\n", ip_header_length);

  /* Now that we know where the IP include is, we can
   inspect the IP include for a protocol number to
   make sure it is TCP before going any further.
   Protocol is always the 10th byte of the IP include */
  u_char protocol = *(ip_header + 9);
  if (protocol != IPPROTO_TCP) {
    printf("Only handler TCP Packet ...\n");
    return;
  }

  /* Add the ethernet and ip include length to the start of the packet
       to find the beginning of the TCP include */

  tcp_header= packet + ethernet_header_length + ip_header_length;

  /* TCP include length is stored in the first half
     of the 12th byte in the TCP include. Because we only want
     the value of the top half of the byte, we have to shift it
     down to the bottom half otherwise it is using the most
     significant bits instead of the least significant bits */
  tcp_header_length = ((*(tcp_header + 12)) & 0XF0) >> 4;
  printf("TCP Header length in bytes :%d\n", tcp_header_length);

  /* Add up all the include sizes to find the payload offset */

  int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
  printf("Size of all headers combined:%d bytes\n", total_headers_size);
  payload_length = header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
  printf("Payload size:%d bytes\n", payload_length);
  payload = packet + total_headers_size;
  printf("Memory addrss where payload begins: %p\n\n", payload);

  /* Print payload in ASCII */
  if (payload_length > 0) {
    const u_char *temp_pointer = payload;
    int byte_count = 0;
    while (byte_count++ < payload_length) {
      printf("%c", *temp_pointer);
      //printf("%x", *temp_pointer);
      temp_pointer++;
    }
    printf("\n");
  }
  return;

}

int main(int argc,char **argv){

  char *device;
  char error_buffer[PCAP_ERRBUF_SIZE];
  device = pcap_lookupdev(error_buffer);
  if (device == NULL){
    printf("Error finding network device:%s\n",error_buffer);
    return 1;
  }
  printf("Network Device found:%s\n",device);
  pcap_t *handler;
  /* Snapshot length is how many bytes to capture from each packet. This includes*/
  int snapshot_length =1024;
  /* End the loop after this many packets are captured */
  int total_packet_count=200;
  u_char *my_argument=NULL;
  handler = pcap_open_live(device,snapshot_length,0,10000,error_buffer);
  pcap_loop(handler,total_packet_count,my_packet_handler,my_argument);
  return 0;
}
