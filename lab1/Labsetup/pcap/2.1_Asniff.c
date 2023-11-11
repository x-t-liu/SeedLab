#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <ctype.h>




/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
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


void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 
     struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethheader));
          printf("\n====IP Header====\n");   
    // 打印IP数据包的源IP地址和目标IP地址
    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
      // 打印IP数据包的头部长度和总长度
    printf("IP header length: %d bytes\n", ip_header->ip_hl * 4);
    printf("IP total length: %d bytes\n", ntohs(ip_header->ip_len));
    
    
    switch(ip_header->ip_p) {                                 
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
                    printf("====TCP Packet Received====\n");
            // 获取TCP数据包头部的指针
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethheader) + ip_header->ip_hl * 4);
    // 打印TCP数据包的源端口号和目标端口号
    printf("Source port: %d\n", ntohs(tcp_header->source));
    printf("Destination port: %d\n", ntohs(tcp_header->dest));
    // 打印TCP数据包的序列号和确认号
    printf("Sequence number: %u\n", ntohl(tcp_header->seq));
    printf("Acknowledgment number: %u\n", ntohl(tcp_header->ack_seq));
    
    // 获取TCP数据包的数据部分的指针和长度
    u_char *tcp_data = (u_char *)(packet + sizeof(struct ethheader) + ip_header->ip_hl * 4 + tcp_header->doff * 4);
    int tcp_data_len = ntohs(ip_header->ip_len) - ip_header->ip_hl * 4 - tcp_header->doff * 4;
    // if its a telnet pac
    if (tcp_header->source == htons(23) || tcp_header->dest == htons(23)) {
    
    printf("TELNET data:\n");

    }
    else{
    
    
    
    // 如果TCP数据包没有数据部分，直接返回
    if (tcp_data_len == 0) {
        return;
    }
    
    
    
    // 打印TCP数据包的数据部分，以ASCII方式显示
    printf("TCP data:(size %d)\n",tcp_data_len);
    for (int i = 0; i < tcp_data_len; i++) {
        // 每16个字节换行
        if (i % 16 == 0) {
            printf("   ");
        }
        // 如果是可打印字符，打印字符，否则打印'.'
        if (isprint(tcp_data[i])) {
            printf("%c", tcp_data[i]);
        } else {
            printf(".");
        }
        // 如果是最后一个字节，换行
        if (i == tcp_data_len - 1) {
            printf("\n");
        }
    }
    // 打印一条分隔线
    printf("-------------------------------------------------\n");        
            
            }
        
            return;         
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n\n");
            return;
        default:
            printf("   Protocol: others\n\n");
            return;
    }
    
    
                      
                           
                           
                           
                           }
}

int main()
{
  printf("br-...:(iface)");
  char str1[40];
  scanf("%s",str1);
  
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp and dst portrange 10-100";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name ens33
  handle = pcap_open_live(str1, BUFSIZ, 1, 1000, errbuf);
  printf("listening on network card, ret: %p...\n", handle);

  // Step 2: Compile filter_exp into BPF psuedo-code
  printf("try to compile filter...\n");
  pcap_compile(handle, &fp, filter_exp, 0, net);
  printf("try to set filter...\n");
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  printf("start to sniff...\n");
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}


