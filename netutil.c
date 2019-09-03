#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>

#include "netutil.h"

extern int DebugPrintf(char *fmt, ...);
extern int DebugPerror(char *msg);

int InitRawSocket(char *device, int promiscFlag, int ipOnly)
{
  struct ifreq ifreq;
  struct sockaddr_ll sa;
  int sock;

  int protocolID = ipOnly ? htons(ETH_P_IP) : htons(ETH_P_ALL);

  if ( ( sock = socket(PF_PACKET, SOCK_RAW, protocolID) ) < 0 ) {
    DebugPerror("socket() failed.");
    return -1;
  }

  memset(&ifreq, 0, sizeof(struct ifreq));
  strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);

  if (ioctl(sock, SIOCGIFINDEX, &ifreq) < 0) {
    DebugPerror("ioctl() failed.");
    close(sock);

    return -1;
  }

  sa.sll_family = PF_PACKET;
  sa.sll_protocol = protocolID;
  sa.sll_ifindex = ifreq.ifr_ifindex;
  if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    DebugPerror("bind() failed.");
    close(sock);
    return -1;
  }

  if (promiscFlag) {
    if (ioctl(sock, SIOCGIFFLAGS, &ifreq) < 0 ) {
      DebugPerror("ioctl() failed.");
      close(sock);
      return -1;
    }

    ifreq.ifr_flags = ifreq.ifr_flags | IFF_PROMISC;
    if (ioctl(sock, SIOCSIFFLAGS, &ifreq) < 0) {
      DebugPerror("ioctl failed.");
      close(sock);
      return -1;
    }
  }

  return sock;
}

/*
 * GetDeviceNames
 *
 * インターフェースの一覧を取得する.
 *
 * char (*ifnames)[16] カーネルから返ってきたインターフェース名が入る配列. 十分な要素数が必要.
 * int   *ifrn    インターフェースの個数が格納される変数
 */
int GetDeviceNames(char (*ifnames)[16], int *ifrn)
{
  struct ifreq  ifr[10];
  struct ifconf ifc;
  int fd;
  int nifs, i;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if ( (fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0 ) {
    DebugPerror("socket");
    return -1;
  }

  ifc.ifc_len = sizeof(ifr);            /* データを受け取る部分の長さ */
  ifc.ifc_ifcu.ifcu_buf = (void *)ifr;  /* Kernelからデータを受け取る部分を指定 */

  ioctl(fd, SIOCGIFCONF, &ifc);
  if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
    DebugPerror("ioctl");
    close(fd);
    return -1;
  }

  nifs = ifc.ifc_len / sizeof(struct ifreq); /* Kernelから返ってきた数を計算 */

  *ifrn = nifs;

  /* すべてのインターフェース名を表示 */
  for (i = 0; i < nifs; i++) {
    strcpy(ifnames[i], ifr[i].ifr_name);
    printf("%d: %s\n", i, ifr[i].ifr_name);
  }

  close(fd);

  return 0;
}

int GetDeviceInfo(char *device, u_char hwaddr[6], struct in_addr *uaddr, struct in_addr *subnet, struct in_addr *mask)
{
  struct  ifreq ifreq;
  struct  sockaddr_in addr;
  int     sock;
  u_char *p;

  if ( (sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0 ) {
    DebugPerror("socket");
    return -1;
  }

  memset(&ifreq, 0, sizeof(struct ifreq));
  strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);

  if (ioctl(sock, SIOCGIFHWADDR, &ifreq) == -1) {
    DebugPerror("ioctl");
    close(sock);
    return -1;
  }
  else
  {
    p = (u_char *)&ifreq.ifr_hwaddr.sa_data;
    memcpy(hwaddr, p, 6);
  }

  if (ioctl(sock, SIOCGIFADDR, &ifreq) == -1) {
    DebugPerror("ioctl");
    close(sock);
    return -1;
  }
  else if (ifreq.ifr_addr.sa_family != PF_INET) {
    DebugPrintf("%s not PF_INET\n", device);
    close(sock);
    return -1;
  }
  else
  {
    memcpy(&addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));
    *uaddr = addr.sin_addr;
  }

  if (ioctl(sock, SIOCGIFNETMASK, &ifreq) == -1) {
    DebugPerror("ioctl");
    close(sock);
    return -1;
  }
  else
  {
    memcpy(&addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));
    *mask = addr.sin_addr;
  }

  subnet->s_addr = ((uaddr->s_addr) & (mask->s_addr));

  close(sock);

  return 0;
}

char *my_ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size)
{
  snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
    hwaddr[0],
    hwaddr[1],
    hwaddr[2],
    hwaddr[3],
    hwaddr[4],
    hwaddr[5] );
  return buf;
}

char *my_inet_ntoa_r(struct in_addr *addr, char *buf, socklen_t size)
{
  inet_ntop(PF_INET, addr, buf, size);

  return buf;
}

char *in_addr_t2str(in_addr_t addr, char *buf, socklen_t size)
{
  struct in_addr a;
  a.s_addr = addr;
  inet_ntop(PF_INET, &a, buf, size);

  return buf;
}

int PrintEtherHeader(struct ether_header *eh, FILE *fp)
{
  char buf[80];
  
  DebugPrintf("ether_header-------------------------------------------------\n");
  DebugPrintf("ether_dhost=%s\n", my_ether_ntoa_r(eh->ether_dhost, buf, sizeof(buf)));
  DebugPrintf("ether_shost=%s\n", my_ether_ntoa_r(eh->ether_shost, buf, sizeof(buf)));
  DebugPrintf("ether_type=%02x", ntohs(eh->ether_type));

  switch( ntohs(eh->ether_type) )
  {
    case ETH_P_IP:
      DebugPrintf("(IP)\n");
      break;
    case ETH_P_IPV6:
      DebugPrintf("(IPv6)\n");
      break;
    case ETH_P_ARP:
      DebugPrintf("(ARP)\n");
      break;
    default:
      DebugPrintf("(unknown)\n");
      break;
  }

  return 0;
}

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

  addr = (struct in_addr *)&ip;
  inet_ntop(AF_INET, addr, buf, size);

  return buf;
}

int PrintIpHeader(struct iphdr *iphdr, u_char *option, int optionLen, FILE *fp)
{
  int i;
  char buf[80];

  /* debug filter */
  /*
  struct in_addr macbook;
  inet_aton("192.168.10.108", &macbook);
  if (iphdr->saddr == macbook.s_addr)
    return 1;
    */

  DebugPrintf("ip-------------------------------------------\n");
  DebugPrintf("version=%u, ", iphdr->version);
  DebugPrintf("ihl=%u, ", iphdr->ihl);
  DebugPrintf("tos=%x, ", iphdr->tos);
  DebugPrintf("tot_len=%u, ", ntohs(iphdr->tot_len));
  DebugPrintf("id=%u, ", ntohs(iphdr->id));
  DebugPrintf("frag_off=%x, %u, ", (ntohs(iphdr->frag_off) >> 13) & 0x07, ntohs(iphdr->frag_off) & 0x1FFF );
  DebugPrintf("ttl=%u, ", iphdr->ttl);
  DebugPrintf("protocol=%u", iphdr->protocol);

  if (iphdr->protocol <= 17) {
    DebugPrintf("(%s), ", Proto[iphdr->protocol]);
  } else {
    DebugPrintf("(undefined), ");
  }

  DebugPrintf("check=%x\n", iphdr->check);
  DebugPrintf("saddr=%s >>>>>> ", ip_ip2str(iphdr->saddr, buf, sizeof(buf)));
  DebugPrintf("daddr=%s\n", ip_ip2str(iphdr->daddr, buf, sizeof(buf)));
  if (optionLen > 0) {
    DebugPrintf("option:");
    for (i = 0; i < optionLen; i++) {
      if (i != 0)
        DebugPrintf(":%02x", option[i]);
      else
        DebugPrintf("%02x", option[i]);
    }
  }

  return 0;
}

/*
 *  ## TCPヘッダの情報を表示する
 */
int print_tcp(struct tcphdr *tcp)
{
  printf("tcp-------------------------------------------\n");

  printf("source=%u >>>>>> ", ntohs(tcp->source));
  printf("dest=%u\n", ntohs(tcp->dest));
  printf("seq=%u\n", ntohl(tcp->seq));
  printf("ack_seq=%u\n,", ntohl(tcp->ack_seq));
  printf("doff=%u,", tcp->doff);
  printf("urg=%u,", tcp->urg);
  printf("ack=%u,", tcp->ack);
  printf("psh=%u,", tcp->psh);
  printf("rst=%u,", tcp->rst);
  printf("syn=%u,", tcp->syn);
  printf("fin=%u,", tcp->fin);
  printf("window=%u\n", ntohs(tcp->window));
  printf("check=%04x,", ntohs(tcp->check));
  printf("urg_ptr=%u\n", ntohs(tcp->urg_ptr));

  return(0);
}

/*
 *  ## UDPヘッダ情報を表示する
 */
int print_udp(struct udphdr *udp)
{
  printf("udp----------------------------------------------------\n");

  printf("source=%d\n", ntohs(udp->source));
  printf("dest=%d\n", ntohs(udp->dest));
  printf("len=%d\n", ntohs(udp->len));
  printf("check=%04x\n", ntohs(udp->check));

  return(0);
}

u_int16_t checksum(u_char *data, int len)
{
  register u_int32_t sum;
  register u_int16_t *ptr;
  register int       c;

  sum = 0;
  ptr = (u_int16_t *)data;

  for (c = len; c > 1; c -= 2) {
    sum += (*ptr);
    if (sum & 0x80000000) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ptr ++;
  }

  if (c == 1) {
    u_int16_t val;
    
    val = 0;
    memcpy(&val, ptr, sizeof(u_int8_t));
    sum += val;
  }

  while (sum >> 16)
  {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return ~sum;
}

u_int16_t checksum2(u_char *data1, int len1, u_char *data2, int len2)
{
  register u_int32_t sum;
  register u_int16_t *ptr;
  register int       c;

  sum = 0;
  ptr = (u_int16_t *)data1;
  for (c = len1; c > 1; c -= 2) {
    sum += (*ptr);
    if (sum & 0x80000000) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ptr++;
  }

  if (c == 1) {
    u_int16_t val;
    
    val = ((*ptr) << 8) + (*data2);
    sum += val;

    if (sum & 0x80000000) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ptr = (u_int16_t *)(data2 + 1);
    len2--;
  } else {
    ptr = (u_int16_t *)data2;
  }

  for (c = len2; c > 1; c -= 2) {
    sum += (*ptr);
    if (sum & 0x80000000) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ptr++;
  }

  if (c == 1) {
    u_int16_t val;

    val = 0;
    memcpy(&val, ptr, sizeof(u_int8_t));
    sum += val;
  }

  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return ~sum;
}
  

int checkIPchecksum(struct iphdr *iphdr, u_char *option, int optionLen)
{
  unsigned short sum;

  sum =
    (optionLen == 0)
      ? checksum((u_char *)iphdr, sizeof(struct iphdr))
      : checksum2((u_char *)iphdr, sizeof(struct iphdr), option, optionLen);

  if (sum == 0 || sum == 0xFFFF)
    return 1;
  else
    return 0;
}


typedef struct {
  struct ether_header  eh;
  struct ether_arp     arp;
} PACKET_ARP;

int SendArpRequestB(int sock, in_addr_t target_ip, u_char target_mac[6], in_addr_t my_ip, u_char my_mac[6])
{
  PACKET_ARP arp;
  int total;
  u_char *p;
  u_char buf[sizeof(struct ether_header) + sizeof(struct ether_arp)];

  union {
    unsigned long l;
    u_char c[4];
  } lc;

  int i;

  arp.arp.arp_hrd = htons(ARPHRD_ETHER);
  arp.arp.arp_pro = htons(ETHERTYPE_IP);
  arp.arp.arp_hln = 6;
  arp.arp.arp_pln = 4;
  arp.arp.arp_op  = htons(ARPOP_REQUEST);

  for (i = 0; i < 6; i++) {
    arp.arp.arp_sha[i] = my_mac[i];
  }

  for (i = 0; i < 6; i++) {
    arp.arp.arp_tha[i] = 0;
  }

  lc.l = my_ip;
  for (i = 0; i < 4; i++) {
    arp.arp.arp_spa[i] = lc.c[i];
  }

  lc.l = target_ip;
  for (i = 0; i < 4; i++) {
    arp.arp.arp_tpa[i] = lc.c[i];
  }

  arp.eh.ether_dhost[0] = target_mac[0];
  arp.eh.ether_dhost[1] = target_mac[1];
  arp.eh.ether_dhost[2] = target_mac[2];
  arp.eh.ether_dhost[3] = target_mac[3];
  arp.eh.ether_dhost[4] = target_mac[4];
  arp.eh.ether_dhost[5] = target_mac[5];

  arp.eh.ether_shost[0] = my_mac[0];
  arp.eh.ether_shost[1] = my_mac[1];
  arp.eh.ether_shost[2] = my_mac[2];
  arp.eh.ether_shost[3] = my_mac[3];
  arp.eh.ether_shost[4] = my_mac[4];
  arp.eh.ether_shost[5] = my_mac[5];

  arp.eh.ether_type = htons(ETHERTYPE_ARP);

  memset(buf, 0, sizeof(buf));
  p = buf;

  memcpy(p, &arp.eh, sizeof(struct ether_header));
  p += sizeof(struct ether_header);

  memcpy(p, &arp.arp, sizeof(struct ether_arp));
  p += sizeof(struct ether_arp);

  total = p - buf;

  write(sock, buf, total);

  return 0;
}
