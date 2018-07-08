#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "ltest.h"
#include "checksum.h"
#include "print.h"
#include "analyze.h"

int AnalyzePacket(u_char *data, int size)
{
  u_char *ptr;
  int lest;
  struct ether_header *eh;

  ptr = data;
  lest = size;

  if (lest < sizeof(struct ether_header))
  {
    fprintf(stderr, "lest(%d) < sizeof(struct ether_header)\n", lest);
    return -1;
  }

  eh = (struct ether_header *) ptr;
  ptr += sizeof(struct ether_header);
  lest -= sizeof(struct ether_header);

  if (ntohs(eh->ether_type) == ETHERTYPE_IP)
  {
    fprintf(stderr, "Packet[%dbytes]\n", size);
    PrintEtherHeader(eh, stdout);
    AnalyzeIp(ptr, lest);
  }

  return 0;
}

int AnalyzeIp(u_char *data, int size)
{
  u_char *ptr;
  int lest;
  struct iphdr *iphdr;
  u_char *option;
  int optionLen, len;
  unsigned short sum;

  ptr = data;
  lest = size;

  if (lest < sizeof(struct iphdr))
  {
    fprintf(stderr, "lest(%d) < sizeof(struct iphdr)\n", lest);
    return -1;
  }

  iphdr = (struct iphdr *)ptr;
  ptr += sizeof(struct iphdr);
  lest -= sizeof(struct iphdr);

  optionLen = iphdr->ihl * 4 - sizeof(struct iphdr);

  if (optionLen > 0)
  {
    if (optionLen >= 1500)
    {
      fprintf(stderr, "IP optionLen(%d):too big\n", optionLen);
      return -1;
    }
    option = ptr;
    ptr += optionLen;
    lest -= optionLen;
  }

  if (checkIPchecksum(iphdr, option, optionLen) == 0)
  {
    fprintf(stderr, "bad ip checksum\n");
    return -1;
  }

  PrintIpHeader(iphdr, option, optionLen, stdout);

  if (iphdr->protocol == IPPROTO_ICMP)
  {
    len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
    if (checkIPDATAchecksum(iphdr, ptr, len) == 0)
    {
      fprintf(stderr, "bad tcp checksum\n");
      return -1;
    }
    AnalyzeTcp(ptr, lest);
  }
  else if (iphdr->protocol == IPPROTO_UDP)
  {
    struct udphdr *udphdr;
    udphdr = (struct udphdr *) ptr;
    len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
    if (udphdr->check != 0 && checkIPDATAchecksum(iphdr, ptr, len) == 0)
    {
      fprintf(stderr, "bad udp checksum\n");
      return -1;
    }
    AnalyzeUdp(ptr, lest);
  }

  return 0;
}

int AnalyzeTcp(u_char *data, int size)
{
  u_char *ptr;
  int lest;
  struct tcphdr *tcphdr;

  ptr = data;
  lest = size;

  if (lest < sizeof(struct tcphdr))
  {
    fprintf(stderr, "lest(%d) < sizeof(struct tcphdr)\n", lest);
    return -1;
  }

  tcphdr = (struct tcphdr *) ptr;
  ptr += sizeof(struct tcphdr);
  lest -= sizeof(struct tcphdr);

  PrintTcp(tcphdr, stdout);

  return 0;
}

int AnalyzeUdp(u_char *data, int size)
{
  u_char *ptr;
  int lest;
  struct udphdr *udphdr;

  ptr = data;
  lest = size;

  if (lest < sizeof(struct udphdr))
  {
    fprintf(stderr, "lest(%d) < sizeof(struct udphdr)\n", lest);
    return -1;
  }

  udphdr = (struct udphdr *) ptr;
  ptr += sizeof(struct udphdr);
  lest -= sizeof(struct udphdr);

  PrintUdp(udphdr, stdout);

  return 0;
}
