#include "stdint.h"
#ifndef PCAP_TEST_H
#define PCAP_TEST_H

#endif // PCAP_TEST_H

int check_type(const unsigned char *packet);
uint8_t check_tcp_header(const unsigned char *packet);
int check_tcp_data(const unsigned char *packet, int offset);
void print_mac(const unsigned char *packet);  //only type check?
void print_ip(const unsigned char *packet);
void print_port(const unsigned char *packet, int offset);
void print_tcp_data(const unsigned char *packet, int offset, int length);

struct ethernet_addr{
  unsigned char ether_addr_object[6];
};

struct ethernet_header{
   struct ethernet_addr dst_mac;
   struct ethernet_addr src_mac;
   unsigned short type;
};

struct ip_addr{
  unsigned char ip_addr_object[4];
};

struct ip_header{
  unsigned char ip_header_length:4;
  unsigned char ip_version:4;
  unsigned char ip_type_of_service;
  unsigned short ip_total_length;
  unsigned short ip_id;
  //unsigned short ip_flag;
  unsigned char ip_frag_offset:5;
  unsigned char ip_more_fragment:1;
  unsigned char ip_dont_fragment:1;
  unsigned char ip_reserved_zero:1;
  unsigned char ip_frag_offset1;
  unsigned char ip_ttl;
  unsigned char ip_protocol;  // here
  unsigned short ip_header_checksum;
  struct ip_addr ip_src;
  struct ip_addr ip_dst;
  //unsigned int ip_src;
  //unsigned int ip_dst;
};

struct tcp_header{
  unsigned short tcp_src_port;
  unsigned short tcp_dst_port;
  unsigned int tcp_sequence_number;
  unsigned int tcp_ack_number;
  unsigned char flag_nonce:1;
  unsigned char flag_reserved:3;
  unsigned char tcp_header_length:4;
  unsigned short flags;
  unsigned short window;
  unsigned short checksum;
  unsigned short urgrent_pointer;
};




