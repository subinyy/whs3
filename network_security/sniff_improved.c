#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h> //isprint

/* Ethernet header */
struct ethheader {
  unsigned char  ether_dhost[6]; /* destination host address */
  unsigned char  ether_shost[6]; /* source host address */
  unsigned short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
  unsigned short tcp_sport; //thdtls
  unsigned short tcp_dport; //tntls
  unsigned int tcp_seq;
  unsigned int tcp_ack;
  unsigned char tcp_offx2;
  unsigned char tcp_flags;
  unsigned short tcp_win;
  unsigned short tcp_sum;
  unsigned short tcp_urp;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  printf("Packet received!\n");
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));   
    
    //check TCP packet or not
    if (ip->iph_protocol == IPPROTO_TCP) {
      //access the TCP header
      struct tcpheader *tcp = (struct tcpheader *) (packet + sizeof(struct ethheader) + ip->iph_ihl * 4);
    
      //print information of ethernet header
      printf("Ethernet Header: \n");
      printf("  Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
              eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
              eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
      printf("  Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
              eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
              eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

      //print information of IP Header
      printf("IP Header: \n");
      printf("  Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
      printf("  Dst IP: %s\n", inet_ntoa(ip->iph_destip));
      
      //TCP Header
      printf("TCP Header: \n");
      printf("  Src Port: %d\n", ntohs(tcp->tcp_sport));
      printf("  Dst Port: %d\n", ntohs(tcp->tcp_dport));
      
      //payload
      int ip_header_len = ip->iph_ihl *4;
      int tcp_header_len = (tcp->tcp_offx2 >> 4) * 4;
      int total_headers_size = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
      int payload_size = header->caplen - total_headers_size;
      const unsigned char *payload = packet + total_headers_size;
      
      printf("Payload (%d bytes):\n  ", payload_size);
      for(int i=0; i<payload_size && i<100; i++) {
        printf("%c", isprint(payload[i]) ? payload[i] : '.');
      }
      printf("\n--------------------------------------------------------\n");
    
    /* determine protocol */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
}
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net, mask;
  pcap_lookupnet("lo", &net, &mask, errbuf); 

  // Step 1: Open live pcap session on NIC with name enp0s9
  handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device lo: %s\n", errbuf);
    return 2;
  }

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}
