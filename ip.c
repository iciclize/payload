#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <inttypes.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "netutil.h"
#include "base.h"
#include "ip2mac.h"
#include "sendBuf.h"
#include "params.h"
#include "napt.h"
#include "routes.h"
#include "ip.h"
#include "yjsnpi.h"


  struct in_addr macbook = { .s_addr = /*0xc0a80a6c*/ 0x6c0aa8c0 /* 192.168.10.108 */ };

/*
 * SendIcmpTimeExceeded
 *
 * TTL0につきパケットを破棄したという通知を送り返す
 *
 * int ifNo            インターフェースに対応する構造体の配列のインデックス.
 * struct ether_header *eh IPパケットの送り主から送られてきたパケットを含んでいたEthernetフレームのヘッダ.
 * struct iphdr *iphdr     IPパケットの送り主から送られてきたパケットのIPヘッダ.
 * u_char *data            IPパケットの送り主から送られてきたパケットのペイロード.
 * int size                IPパケットの送り主から送られてきたパケットのペイロード長だと思う. 使われてなくて草.
 */
int SendIcmpTimeExceeded(int ifNo, struct ether_header *eh, struct iphdr *iphdr, u_char *data, int size)
{
  extern DEVICE *ifs;

  struct ether_header reh;
  struct iphdr        rih;
  struct icmp         icmp;
  u_char             *ipptr;
  u_char             *ptr;
  u_char              buf[1500];
  int                 len;

  memcpy(reh.ether_dhost, eh->ether_shost, 6);
  memcpy(reh.ether_shost, ifs[ifNo].hwaddr, 6);
  reh.ether_type = htons(ETHERTYPE_IP);

  rih.version  = 4;
  rih.ihl      = 20 / 4;
  rih.tos      = 0;
  rih.tot_len  = htons(sizeof(struct icmp) + 64);
  rih.id       = 0;
  rih.frag_off = 0;
  rih.ttl      = 64;
  rih.protocol = IPPROTO_ICMP;
  rih.check    = 0;
  rih.saddr    = ifs[ifNo].addr.s_addr;
  rih.daddr    = iphdr->saddr;

  rih.check = checksum((u_char *) &rih, sizeof(struct iphdr));

  icmp.icmp_type  = ICMP_TIME_EXCEEDED;
  icmp.icmp_code  = ICMP_TIMXCEED_INTRANS;
  icmp.icmp_cksum = 0;
  icmp.icmp_void  = 0;

  ipptr = data + sizeof(struct ether_header);

  icmp.icmp_cksum = checksum2((u_char *) &icmp, 8, ipptr, 64);

  ptr = buf;
  memcpy(ptr, &reh, sizeof(struct ether_header));
  ptr += sizeof(struct ether_header);
  memcpy(ptr, &rih, sizeof(struct iphdr));
  ptr += sizeof(struct iphdr);
  memcpy(ptr, &icmp, 8);
  ptr += 8;
  memcpy(ptr, ipptr, 64);
  ptr += 64;
  len = ptr - buf;

  DebugPrintf("write:SendIcmpTimeExceeded:[%d] %dbytes\n", ifNo, len);
  write(ifs[ifNo].sock, buf, len);

  return 0;
}

int EtherIpSend(int ifNo, struct ether_header *eh, struct ip *iphdr,
                uint8_t *ip_option, int ip_option_len,
                uint8_t *ip_payload, int frame_size)
{
  extern DEVICE *ifs;

  int             tno;
  struct in_addr  nextAddr;

  struct routing_table_entry *entry = lookup_route_entry(iphdr->ip_dst.s_addr);
  if (entry == NULL) {
    char buf[80];
    fprintf(stderr, "No route entry for dest [%s]\n",
        in_addr_t2str(iphdr->ip_dst.s_addr, buf, sizeof(buf)));
    return -1;
  }

  tno = entry->ifNo;

  if ((iphdr->ip_dst.s_addr & ifs[tno].netmask.s_addr) == ifs[tno].subnet.s_addr) {
    /*  わし(53)のネットワーク */
    if (iphdr->ip_dst.s_addr == ifs[tno].addr.s_addr) {
      /* 宛先がわし(53) */
      // DebugPrintf("[%s]:recv:myaddr\n", ifs[ifNo].name);
      return 1;
    }
    nextAddr.s_addr = iphdr->ip_dst.s_addr;
  } else {
    nextAddr.s_addr = entry->gateway;
  }

  // TODO: test
  struct tcphdr *h = (struct tcphdr *)ip_payload;
  if (iphdr->ip_p == IPPROTO_TCP) {
    if (ntohs(h->source) == 80 || ntohs(h->dest) == 80) {
      DebugPrintf("\n[TCP/IP] Sent\n");
      PrintIpHeader((struct iphdr *)iphdr, ip_option, ip_option_len, stderr);
      print_tcp(h);
      print_hex((uint8_t *)eh, frame_size);
      DebugPrintf("\n");
    }
  }

  IP2MAC *ip2mac = Ip2Mac(tno, nextAddr.s_addr, NULL);

  if (ip2mac->flag == FLAG_NG || ip2mac->sd.dno != 0) {
    DebugPrintf("[%s]:Ip2Mac:error or sending\n", ifs[tno].name);
    AppendSendData(ip2mac, 1, nextAddr.s_addr, (uint8_t *)eh, frame_size);
    return -1;
  }

  iphdr->ip_ttl--;
  iphdr->ip_sum = 0;
  iphdr->ip_sum = checksum2((u_char *)iphdr, sizeof(struct iphdr), ip_option, ip_option_len);

  memcpy(eh->ether_dhost, ip2mac->hwaddr, 6);
  memcpy(eh->ether_shost, ifs[tno].hwaddr, 6);

  write(ifs[tno].sock, eh, frame_size);
  return 0;
}

int IpSend(struct ip *iphdr, uint8_t *ip_payload)
{
  uint8_t frame[1522];
  struct ether_header *eh = (struct ether_header *)frame;
  struct ip *ih = (struct ip *)(frame + sizeof(struct ether_header));
  eh->ether_type = htons(0x0800);
  *ih = *iphdr; // copy
  memcpy((ih + 1), ip_payload, ntohs(ih->ip_len) - sizeof(struct ip));

  EtherIpSend(114514, eh, ih,
              (uint8_t *)ih + sizeof(struct ip), ih->ip_hl * 4 - sizeof(struct ip), 
              (uint8_t *)ih + ih->ip_hl * 4, sizeof(struct ether_header) + ntohs(ih->ip_len));
  return 0;
}

int IpRecv(int ifNo, struct ether_header *eh, u_char *data, int frame_size)
{
  extern DEVICE *ifs;

  struct iphdr   *iphdr;
  u_char          option[1500];
  int             optionLen;
  unsigned int    lest;
  u_char         *ptr;

  lest = frame_size;
  ptr = data;
  
  /* IPヘッダは20Bytesはあるのに残りのフレームサイズがそれより小さいのはおかしいという話 */
  if (lest < sizeof(struct iphdr)) {
    DebugPrintf("[%s]:lest(%d) < sizeof(struct iphdr)\n", ifs[ifNo].name, lest);
    return -1;
  }

  iphdr = (struct iphdr *)ptr;
  ptr  += sizeof(struct iphdr); /* ポインタはIPペイロードもしくはIPヘッダのオプション部分に進む */
  lest -= sizeof(struct iphdr); /* IPペイロード長(CRC部のサイズも含んでいる…？) */

  /*
   * オプショオォン!アォン!
   */
  optionLen = iphdr->ihl * 4 - sizeof(struct iphdr);
  if (optionLen > 0) {
    if (optionLen >= 1500) {
      DebugPrintf("[%s]:IP optionLen(%d):too big\n", ifs[ifNo].name, optionLen);
      return -1;
    }

    memcpy(option, ptr, optionLen);
    ptr  += optionLen; /* ポインタはIPペイロード */
    lest -= optionLen; /* IPペイロード長 */
  }

  /* IPチェックサムを検証して壊れたパケットを弾く */
  if (checkIPchecksum(iphdr, option, optionLen) == 0) {
    DebugPrintf("[%s]:bad ip checksum\n", ifs[ifNo].name);
    return -1;
  }

  if (iphdr->ttl - 1 <= 0) {
    DebugPrintf("[%s]:iphdr->ttl <= 0 error\n", ifs[ifNo].name);
    SendIcmpTimeExceeded(ifNo, eh, iphdr, data, frame_size);
    return -1;
  }

  size_t ip_payload_len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
  lest -= ip_payload_len;

  /*
   * NAPTする
   */
  int yj;
  if (iphdr->saddr != macbook.s_addr) {
    if (ifNo != 0 && iphdr->protocol == IPPROTO_TCP) {
      /* OUTGOINGならyj -> napt */
      yj = YJSNPInize(ifNo, (struct ip *)iphdr, (struct tcphdr *)ptr, ip_payload_len);
    }
    if (iphdr->protocol == IPPROTO_TCP || iphdr->protocol == IPPROTO_UDP) {
      DoNAPT(ifNo, (struct ip *)iphdr, ptr, ip_payload_len);
    }
    if (ifNo == 0 && iphdr->protocol == IPPROTO_TCP) {
      /* INCOMINGならnapt -> yj */
      yj = YJSNPInize(ifNo, (struct ip *)iphdr, (struct tcphdr *)ptr, ip_payload_len);
    }
    if (yj != 0)
      return 1;
  }

  EtherIpSend(ifNo, eh, (struct ip *)iphdr, option, optionLen, ptr, frame_size);
  return 0;
}
