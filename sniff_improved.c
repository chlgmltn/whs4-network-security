#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>

#include "myheader.h"

#define ETHERNET_HEADER_LEN sizeof(struct ethheader)
#define IPV4_TYPE 0x0800

/*
 * Print a MAC address in the common xx:xx:xx:xx:xx:xx format.
 * The Ethernet header stores each address as 6 bytes.
 */
void print_mac(const u_char *mac)
{
  printf("%02x:%02x:%02x:%02x:%02x:%02x",
         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/*
 * Print TCP payload as an HTTP message.
 * Printable ASCII bytes are shown as-is. Other bytes are replaced with '.'.
 */
void print_http_payload(const u_char *payload, int payload_len)
{
  int i;

  for (i = 0; i < payload_len; i++) {
    if (payload[i] >= 32 && payload[i] <= 126) {
      putchar(payload[i]);
    } else if (payload[i] == '\r' || payload[i] == '\n' || payload[i] == '\t') {
      putchar(payload[i]);
    } else {
      putchar('.');
    }
  }

  if (payload_len > 0 && payload[payload_len - 1] != '\n') {
    putchar('\n');
  }
}

int payload_starts_with(const u_char *payload, unsigned int payload_len,
                        const char *prefix)
{
  size_t prefix_len = strlen(prefix);

  return payload_len >= prefix_len &&
         memcmp(payload, prefix, prefix_len) == 0;
}

int is_http_payload(const u_char *payload, unsigned int payload_len)
{
  return payload_starts_with(payload, payload_len, "GET ") ||
         payload_starts_with(payload, payload_len, "POST ") ||
         payload_starts_with(payload, payload_len, "HEAD ") ||
         payload_starts_with(payload, payload_len, "PUT ") ||
         payload_starts_with(payload, payload_len, "DELETE ") ||
         payload_starts_with(payload, payload_len, "OPTIONS ") ||
         payload_starts_with(payload, payload_len, "HTTP/");
}

/*
 * Safely parse and print one captured packet.
 * Return 1 when a TCP/IPv4 packet is printed, otherwise return 0.
 */
int process_packet(const struct pcap_pkthdr *header, const u_char *packet,
                   int packet_no)
{
  const struct ethheader *eth;
  const struct ipheader *ip;
  const struct tcpheader *tcp;
  const u_char *payload;
  unsigned int caplen = header->caplen;
  unsigned int ip_total_len;
  unsigned int ip_header_len;
  unsigned int tcp_header_len;
  unsigned int captured_ip_len;
  unsigned int captured_tcp_len;
  unsigned int tcp_segment_len;
  unsigned int payload_len;
  unsigned short src_port;
  unsigned short dst_port;
  char src_ip[INET_ADDRSTRLEN];
  char dst_ip[INET_ADDRSTRLEN];

  /* Ethernet header must be fully captured before reading ether_type. */
  if (caplen < ETHERNET_HEADER_LEN) {
    return 0;
  }

  eth = (const struct ethheader *)packet;

  /* Only IPv4 packets are part of this assignment. */
  if (ntohs(eth->ether_type) != IPV4_TYPE) {
    return 0;
  }

  /* At least the minimum IPv4 header must be present. */
  if (caplen < ETHERNET_HEADER_LEN + sizeof(struct ipheader)) {
    return 0;
  }

  ip = (const struct ipheader *)(packet + ETHERNET_HEADER_LEN);
  ip_header_len = ip->iph_ihl * 4;

  /* IHL is measured in 32-bit words. IPv4's minimum header size is 20 bytes. */
  if (ip->iph_ver != 4 || ip_header_len < 20) {
    return 0;
  }

  if (caplen < ETHERNET_HEADER_LEN + ip_header_len) {
    return 0;
  }

  /* Only TCP packets are printed. UDP and all other protocols are ignored. */
  if (ip->iph_protocol != IPPROTO_TCP) {
    return 0;
  }

  ip_total_len = ntohs(ip->iph_len);
  if (ip_total_len < ip_header_len) {
    return 0;
  }

  captured_ip_len = caplen - ETHERNET_HEADER_LEN;
  if (captured_ip_len > ip_total_len) {
    captured_ip_len = ip_total_len;
  }

  captured_tcp_len = captured_ip_len - ip_header_len;
  if (captured_tcp_len < sizeof(struct tcpheader)) {
    return 0;
  }

  tcp = (const struct tcpheader *)(packet + ETHERNET_HEADER_LEN + ip_header_len);
  tcp_header_len = TH_OFF(tcp) * 4;

  /* TCP data offset is also measured in 32-bit words; minimum TCP header is 20. */
  if (tcp_header_len < 20 || captured_tcp_len < tcp_header_len) {
    return 0;
  }

  tcp_segment_len = ip_total_len - ip_header_len;
  if (tcp_segment_len < tcp_header_len) {
    return 0;
  }

  payload = packet + ETHERNET_HEADER_LEN + ip_header_len + tcp_header_len;

  /*
   * Payload length is limited by both IP total length and captured length.
   * This prevents reading beyond the bytes that actually exist in the packet.
   */
  payload_len = tcp_segment_len - tcp_header_len;
  if (payload_len > captured_tcp_len - tcp_header_len) {
    payload_len = captured_tcp_len - tcp_header_len;
  }

  inet_ntop(AF_INET, &(ip->iph_sourceip), src_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ip->iph_destip), dst_ip, INET_ADDRSTRLEN);
  src_port = ntohs(tcp->tcp_sport);
  dst_port = ntohs(tcp->tcp_dport);

  printf("========== Packet %d ==========\n", packet_no);
  printf("[Ethernet Header]\n");
  printf("Src MAC: ");
  print_mac(eth->ether_shost);
  printf("\n");
  printf("Dst MAC: ");
  print_mac(eth->ether_dhost);
  printf("\n\n");

  printf("[IP Header]\n");
  printf("Src IP: %s\n", src_ip);
  printf("Dst IP: %s\n\n", dst_ip);

  printf("[TCP Header]\n");
  printf("Src Port: %u\n", src_port);
  printf("Dst Port: %u\n\n", dst_port);

  if (payload_len > 0 &&
      (src_port == 80 || dst_port == 80) &&
      is_http_payload(payload, payload_len)) {
    printf("[HTTP Message]\n");
    print_http_payload(payload, payload_len);
  }

  printf("\n");
  return 1;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
  static int packet_no = 1;

  (void)args;

  if (process_packet(header, packet, packet_no)) {
    packet_no++;
  }
}

int main(int argc, char *argv[])
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp and not port 22";
  /* To see only HTTP test traffic, use: "tcp port 80". */
  bpf_u_int32 net = PCAP_NETMASK_UNKNOWN;
  const char *interface;

  if (argc != 2) {
    fprintf(stderr, "Usage: sudo %s <interface>\n", argv[0]);
    return EXIT_FAILURE;
  }

  interface = argv[1];

  /* Open a live capture session on the interface given by argv[1]. */
  handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
    return EXIT_FAILURE;
  }

  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "Unsupported data link type: %s\n",
            pcap_datalink_val_to_name(pcap_datalink(handle)));
    pcap_close(handle);
    return EXIT_FAILURE;
  }

  /* Compile and apply a BPF filter so libpcap gives this program TCP packets. */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "pcap_compile() failed: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return EXIT_FAILURE;
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "pcap_setfilter() failed: %s\n", pcap_geterr(handle));
    pcap_freecode(&fp);
    pcap_close(handle);
    return EXIT_FAILURE;
  }

  pcap_freecode(&fp);

  /* Each captured packet is passed to got_packet(), which runs the parser. */
  if (pcap_loop(handle, -1, got_packet, NULL) == -1) {
    fprintf(stderr, "pcap_loop() failed: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return EXIT_FAILURE;
  }

  pcap_close(handle);
  return EXIT_SUCCESS;
}
