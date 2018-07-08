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

#include "print.h"

static char *Proto[] = {
  "undefined",
  "ICMP",
  "IGMP",
  "undefined",
  "IPIP",
  "undefined",
  "TCP",
  "undefined",
  "EGP",
  "undefined",
  "undefined",
  "undefined",
  "PUP",
  "undefined",
  "undefined",
  "undefined",
  "undefined",
  "UDP"
};

char *ip_ip2str(u_int32_t ip, char *buf, socklen_t size)
{
  struct in_addr *addr;

  addr = (struct in_addr *) &ip;
  inet_ntop(AF_INET, addr, buf, size);

  return buf;
}

int PrintIpHeader(struct iphdr *iphdr, u_char *option, int optionLen, FILE *fp)
{
  int i;
  char buf[80];

  fprintf(fp, "ip---------------------------\n");
  fprintf(fp, "version=%u,", iphdr->version);
  fprintf(fp, "ihl=%u,", iphdr->ihl);
  fprintf(fp, "tos=%x, ", iphdr->tos);
  fprintf(fp, "tot_len=%u,", ntohs(iphdr->tot_len));
  fprintf(fp, "id=%u,", ntohs(iphdr->id));
  fprintf(fp, "frag_off%x, %u,", (ntohs(iphdr->frag_off) >> 13) & 0x07, ntohs(iphdr->frag_off) & 0x1FFF );
  fprintf(fp, "ttl=%u", iphdr->ttl);
  fprintf(fp, "protocol=%u", iphdr->protocol);

  if (iphdr->protocol <= 17)
  {
    fprintf(fp, "(%s),", Proto[iphdr->protocol]);
  }
  else
  {
    fprintf(fp, "(undefined),");
  }
  fprintf(fp, "check=%x\n", iphdr->check);
  fprintf(fp, "saddr=%s,", ip_ip2str(iphdr->saddr, buf, sizeof(buf)));
  fprintf(fp, "daddr=%s\n", ip_ip2str(iphdr->daddr, buf, sizeof(buf)));
  if (optionLen > 0)
  {
    fprintf(fp, "option:");
    for (i = 0; i < optionLen; i++)
    {
      if (i != 0)
      {
        fprintf(fp, ":%02x", option[i]);
      }
      else
      {
        fprintf(fp, "%02x", option[i]);
      }
    }
  }

  return 0;
}

int PrintTcp(struct tcphdr *tcphdr, FILE *fp)
{
  fprintf(fp, "tcp------------------------\n");

  fprintf(fp, "source=%u, ", ntohs(tcphdr->source));
  fprintf(fp, "dest=%u\n", ntohs(tcphdr->dest));
  fprintf(fp, "seq=%u\n", ntohl(tcphdr->seq));
  fprintf(fp, "ack_seq=%u\n", ntohl(tcphdr->ack_seq));
  fprintf(fp, "doff=%u,", tcphdr->doff);
  fprintf(fp, "urg=%u,", tcphdr->urg);
  fprintf(fp, "ack=%u,", tcphdr->ack);
  fprintf(fp, "psh=%u,", tcphdr->psh);
  fprintf(fp, "rst=%u,", tcphdr->rst);
  fprintf(fp, "syn=%u,", tcphdr->syn);
  fprintf(fp, "fin=%u,", tcphdr->fin);
  fprintf(fp, "th_win=%u\n", ntohs(tcphdr->window));
  fprintf(fp, "th_sum=%u, ", ntohs(tcphdr->check));
  fprintf(fp, "th_urp=%u\n", ntohs(tcphdr->urg_ptr));

  return 0;
}

int PrintUdp(struct udphdr *udphdr, FILE *fp)
{
  fprintf(fp, "udp------------------------\n");

  fprintf(fp, "source=%u, ", ntohs(udphdr->source));
  fprintf(fp, "dest=%u\n", ntohs(udphdr->dest));
  fprintf(fp, "len=%u, ", ntohs(udphdr->len));
  fprintf(fp, "check=%x\n", ntohs(udphdr->check));

  return 0;
}
