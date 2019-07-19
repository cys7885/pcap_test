#include <pcap.h>
#include <stdio.h>
#include <pcap_test.h>
#include <stdint.h>

#define ethernet_header_offset 14
#define tcp_protocol 6
#define ethernet_ip_type 0x0800

int check_type(const unsigned char *packet){  //check ethernet type of header whether next chunk is IP chunk
  struct ethernet_header *eth_header;
  eth_header = (struct ethernet_header*)packet;
  unsigned short eth_type = ntohs(eth_header->type);
  if(eth_type == ethernet_ip_type){
    return 0;
   }
  else {
    return 1;
   }
}

uint8_t check_tcp_header(const unsigned char *packet){
    struct ip_header *ip_head;
    packet = packet+ethernet_header_offset; //ip header offset
    ip_head = (struct ip_header*)packet;
    if(ip_head->ip_protocol == tcp_protocol)
      return ip_head->ip_header_length*4;
    else {
        return 0;
      }
}

int check_tcp_data(const unsigned char *packet, int offset){
  struct ip_header *ip_header;
  struct tcp_header *tcp_header;
  packet = packet+ethernet_header_offset;
  ip_header = (struct ip_header*)packet;
  packet = packet+offset;
  tcp_header = (struct tcp_header*)packet;
  if(ntohs(tcp_header->tcp_src_port) == 80 || ntohs(tcp_header->tcp_dst_port) == 80){
      int total_length = ntohs(ip_header->ip_total_length);
      int tcp_header_length = tcp_header->tcp_header_length;
      int ip_header_length = ip_header->ip_header_length;
      //printf("%d - (%d + %d)*4\n", total_length, tcp_header_length, ip_header_length);
      int tcp_data_length = total_length - (tcp_header_length + ip_header_length)*4;  // tcp data's size
      return tcp_data_length;
    }
  else {
      return 0;
    }
}

void print_mac(const unsigned char *packet){
  struct ethernet_header *eth_header;
  eth_header = (struct ethernet_header*)packet;

  printf("Source MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
         eth_header->src_mac.ether_addr_object[0],
         eth_header->src_mac.ether_addr_object[1],
         eth_header->src_mac.ether_addr_object[2],
         eth_header->src_mac.ether_addr_object[3],
         eth_header->src_mac.ether_addr_object[4],
         eth_header->src_mac.ether_addr_object[5]);

  printf("Destination MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
         eth_header->dst_mac.ether_addr_object[0],
         eth_header->dst_mac.ether_addr_object[1],
         eth_header->dst_mac.ether_addr_object[2],
         eth_header->dst_mac.ether_addr_object[3],
         eth_header->dst_mac.ether_addr_object[4],
         eth_header->dst_mac.ether_addr_object[5]);
}

void print_ip(const unsigned char *packet){
  struct ip_header *ip_header;
  packet = packet+14;
  ip_header = (struct ip_header*)packet;
  printf("Source IP : %u.%u.%u.%u\n",
         ip_header->ip_src.ip_addr_object[0],
         ip_header->ip_src.ip_addr_object[1],
         ip_header->ip_src.ip_addr_object[2],
         ip_header->ip_src.ip_addr_object[3]);
  printf("Destination IP : %u.%u.%u.%u\n",
         ip_header->ip_dst.ip_addr_object[0],
         ip_header->ip_dst.ip_addr_object[1],
         ip_header->ip_dst.ip_addr_object[2],
         ip_header->ip_dst.ip_addr_object[3]);

}

void print_port(const unsigned char *packet, int offset){
  struct tcp_header *tcp_header;
  packet = packet+ethernet_header_offset+offset;
  tcp_header = (struct tcp_header*)packet;
  printf("Source port : %d\n", ntohs(tcp_header->tcp_src_port));
  printf("Destination port : %d\n", ntohs(tcp_header->tcp_dst_port));
}

void print_tcp_data(const unsigned char *packet, int offset, int length){
  struct tcp_header *tcp_header;
  packet = packet+ethernet_header_offset+offset;
  tcp_header = (struct tcp_header*)packet;
  packet = packet + tcp_header->tcp_header_length*4;
  //printf("length : %d\n", length);
  printf("TCP PAYLOAD : ");
  if(length>0){
      if(length < 10){
          for(int i = 0; i < length; i++)
            printf("%02x ", packet[i]);
          printf("\n");
      }
      else {
          for(int i = 0; i < 10; i++)
            printf("%02x ", packet[i]);
          printf("\n");
        }
    }
}
