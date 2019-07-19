#include <stdio.h>
#include "pcap.h"
#include "pcap_test.h"
#include "stdint.h"

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    if(!check_type(packet)){
        uint8_t offset = check_tcp_header(packet);
        if(offset){
            int tcp_data_length = check_tcp_data(packet, offset);
            if(tcp_data_length){
                print_mac(packet);
                print_ip(packet);
                print_port(packet, offset);
                print_tcp_data(packet, offset, tcp_data_length);
                printf("\n-------------------------------------\n");
              }
         }
      }
  }

  pcap_close(handle);
  return 0;
}
