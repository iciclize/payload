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

PARAM Param;

int EndFlag = 0;

DEVICE *ifs;           /* Interfaces */

int getIfIndexByAddress(struct in_addr nexthop)
{
  for (int i = 0; i < Param.ifnum; i++)
    if ( (nexthop.s_addr & ifs[i].netmask.s_addr) == ifs[i].subnet.s_addr )
      return i;
  return -1;
}

/*
 * DebugPrintf
 * 表示非表示を制御可能なデバッグ用のprintfらしい
 */
int DebugPrintf(char *fmt, ...)
{
  if (Param.DebugOut) {
    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
  }

  return 0;
}

/* DebugPerror
 * 表示非表示を制御可能なデバッグ用のperrorらしい
 */
int DebugPerror(char *msg)
{
  if (Param.DebugOut)
    fprintf(stderr, "%s : %s\n", msg, strerror(errno));

  return 0;
}

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
  struct ether_header reh;
  struct iphdr        rih;
  struct icmp         icmp;
  u_char             *ipptr;
  u_char             *ptr,
                      buf[1500];
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

/*
 * AnalyzePacket
 *
 * Ethernetフレームを見て中身をARP, IPか判定して転送までやってしまう巨大関数. 参考書は雰囲気だけ説明できればOKというつもりなのでしょう.
 *
 * int ifNo インターフェースを紐付けた構造体の配列インデックス
 * u_char *data Ethernetフレーム
 * int     size Ethernetフレーム長
 */
int AnalyzePacket(int ifNo, u_char *data, int size)
{
  u_char *ptr;
  int  lest;
  struct  ether_header *eh;
  char    buf[80];
  int     tno;
  u_char  hwaddr[6];

  ptr = data;
  lest = size;

  /* フレーム長がヘッダーの長さ14Bytesより小さいのはおかしい */
  if (lest < sizeof(struct ether_header)) {
    DebugPrintf("[%d]:lest(%d) < sizeof(struct ether_header)\n", ifNo, lest);
    return -1;
  }

  eh = (struct ether_header *)ptr;
  ptr += sizeof(struct ether_header);  /* ポインタをEthernetのペイロードの先頭に持っていく */
  lest -= sizeof(struct ether_header); /* フレームのケツまでのサイズを計算 */

  /* フレームの宛先が自分ではなかったら無視する */
  if (memcmp(&eh->ether_dhost, ifs[ifNo].hwaddr, 6) != 0) {
    /*
    DebugPrintf("[%s]:dhost not match %s\n", ifs[ifNo].name, my_ether_ntoa_r((u_char *)&eh->ether_dhost, buf, sizeof(buf)));
    PrintEtherHeader(eh, stderr);
    */
    return -1;
  }

  if (ntohs(eh->ether_type) == ETHERTYPE_ARP) {
    /* フレームの中身がARPパケットだったとき */
    struct ether_arp  *arp;

    if (lest < sizeof(struct ether_arp)) {
      DebugPrintf("[%s]:lest(%d) < sizeof(struct ether_arp)\n", ifs[ifNo].name, lest);
      return -1;
    }

    arp  = (struct ether_arp *)ptr;
    ptr  += sizeof(struct ether_arp); /* ポインタをARPヘッダの分だけ進める. ARPにはボディがなく空っぽになるので得に意味はなさそう. */
    lest -= sizeof(struct ether_arp); /* 残りフレームサイズはたぶん0になるよね */

    if (arp->arp_op == htons(ARPOP_REQUEST)) {
      /* ARP要求が聞こえたので送り主のプロトコルアドレス(IPアドレス)とハードウェアアドレス(MACアドレス)を覚えとこ */
      DebugPrintf("[%s]recv:ARP REQUEST:%dbytes\n", ifs[ifNo].name, size);
      Ip2Mac(ifNo, *(in_addr_t *)arp->arp_spa, arp->arp_sha);
    } else if (arp->arp_op == htons(ARPOP_REPLY)) {
      /* ARPリプライが聞こえたので送り主のプロトコルアドレス(IPアドレス)とハードウェアアドレス(MACアドレス)を覚えとこ */
      DebugPrintf("[%s]recv: ARP REPLY:%dbytes\n", ifs[ifNo].name, size);
      Ip2Mac(ifNo, *(in_addr_t *)arp->arp_spa, arp->arp_sha);
    }
  }
  else if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
    /* フレームの中身がIPパケットだったとき */
    struct iphdr *iphdr;
    u_char        option[1500];
    int           optionLen;

    struct in_addr macbook;
    inet_aton("192.168.10.108", &macbook);

    /* IPヘッダは20Bytesはあるのに残りのフレームサイズがそれより小さいのはおかしいという話 */
    if (lest < sizeof(struct iphdr)) {
      DebugPrintf("[%s]:lest(%d) < sizeof(struct iphdr)\n", ifs[ifNo].name, lest);
      return -1;
    }

    iphdr = (struct iphdr *)ptr;
    ptr  += sizeof(struct iphdr); /* ポインタはIPペイロードもしくはIPヘッダのオプション部分に進む */
    lest -= sizeof(struct iphdr); /* IPペイロード長(CRC部のサイズも含んでいる…？) */

    optionLen = iphdr->ihl * 4 - sizeof(struct iphdr); /* IPヘッダのオプション部分のサイズ. ヘッダ長の値から20Bytes引いているんですね */
    if (optionLen > 0) {
      if (optionLen >= 1500) {
        DebugPrintf("[%s]:IP optionLen(%d):too big\n", ifs[ifNo].name, optionLen);
        return -1;
      }

      memcpy(option, ptr, optionLen);
      ptr  += optionLen; /* ポインタはIPペイロード */
      lest -= optionLen; /* IPペイロード長 */

      printf("\nIPペイロード(オプションあり)長: %d\n\n", lest);
    }

    /* IPチェックサムを検証して壊れたパケットを弾く */
    if (checkIPchecksum(iphdr, option, optionLen) == 0) {
      DebugPrintf("[%s]:bad ip checksum\n", ifs[ifNo].name);
      fprintf(stderr, "IP checksum error\n");
      return -1;
    }

    if (iphdr->ttl - 1 <= 0) {
      DebugPrintf("[%s]:iphdr->ttl <= 0 error\n", ifs[ifNo].name);
      SendIcmpTimeExceeded(ifNo, eh, iphdr, data, size);
      return -1;
    }

    /*
     * NAPTする
     */
    if (iphdr->saddr != macbook.s_addr) {
      DoNAPT(ifNo, (struct ip *)iphdr, ptr, ntohs(iphdr->tot_len) - iphdr->ihl * 4);
    }

    struct routing_table_entry *entry = lookup_route_entry(iphdr->daddr);
    if (entry == NULL) {
      fprintf(stderr, "No route entry for dest %s\n", in_addr_t2str(iphdr->daddr, buf, sizeof(buf)));
      return -1;
    }

    tno = entry->ifNo;

    if ((iphdr->daddr & ifs[tno].netmask.s_addr) == ifs[tno].subnet.s_addr) {
      /* Target Segment */
      if (iphdr->saddr != macbook.s_addr) {
        // PrintEtherHeader(eh, stderr);
        // PrintIpHeader(iphdr, option, optionLen, stderr);
      }
      IP2MAC *ip2mac;

      // DebugPrintf("[%s]:%s to TargetSegment\n", ifs[ifNo].name, in_addr_t2str(iphdr->daddr, buf, sizeof(buf)));

      if (iphdr->daddr == ifs[tno].addr.s_addr) {
        // DebugPrintf("[%s]:recv:myaddr\n", ifs[ifNo].name);
        return 1;
      }

      ip2mac = Ip2Mac(tno, iphdr->daddr, NULL);
      if (ip2mac->flag == FLAG_NG || ip2mac->sd.dno != 0) {
        DebugPrintf("[%s]:Ip2Mac:error or sending\n", ifs[ifNo].name);
        AppendSendData(ip2mac, 1, iphdr->daddr, data, size);
        return -1;
      } else {
        memcpy(hwaddr, ip2mac->hwaddr, 6);
      }
    } else {
      // PrintEtherHeader(eh, stderr);
      // PrintIpHeader(iphdr, option, optionLen, stderr);
      char buf2[80];
      DebugPrintf("Nexthop(interface): %s (if: %s/%s)\n", in_addr_t2str(entry->gateway, buf, sizeof(buf)), ifs[tno].name, in_addr_t2str(ifs[tno].addr.s_addr, buf2, sizeof(buf2)));

      IP2MAC *ip2mac;
      ip2mac = Ip2Mac(tno, entry->gateway, NULL);

      if (ip2mac->flag == FLAG_NG || ip2mac->sd.dno != 0) {
        DebugPrintf("[%s]:Ip2Mac:error or sending\n", ifs[ifNo].name);
        AppendSendData(ip2mac, 1, entry->gateway, data, size);
        return -1;
      } else {
        memcpy(hwaddr, ip2mac->hwaddr, 6);
      }
    }

    memcpy(eh->ether_dhost, hwaddr, 6);
    memcpy(eh->ether_shost, ifs[tno].hwaddr, 6);

    iphdr->ttl--;
    iphdr->check = 0;
    iphdr->check = checksum2((u_char *)iphdr, sizeof(struct iphdr), option, optionLen);

    fprintf(stderr, " >>>>>>>> Written to %s <<<<<<<<\n", ifs[tno].name);
    // PrintEtherHeader(eh, stderr);
    PrintIpHeader(iphdr, option, optionLen, stderr);

    if (iphdr->protocol == 6) {
      print_tcp((struct tcphdr *)ptr);
    } else if (iphdr->protocol == 17) {
      print_udp((struct udphdr *)ptr);
    }

    fprintf(stderr, " ===============================\n");
    write(ifs[tno].sock, data, size);
  }

  return 0;
}

/*
 * Router
 *
 * ルーター(直球). パケット待ちビジーループ.
 */
int Router(void)
{
  struct pollfd *targets;
  int           nready, i, size;
  u_char        buf[2048];

  targets = (struct pollfd *)malloc(sizeof(struct pollfd) * Param.ifnum);

  for (i = 0; i < Param.ifnum; i++) {
    targets[i].fd = ifs[i].sock;
    targets[i].events = POLLIN | POLLERR;
  }

  while (EndFlag == 0)
  {
    switch (nready = poll(targets, Param.ifnum, 100))
    {
      case -1:
        if (errno != EINTR)
          DebugPerror("poll");

        break;
      case 0:
        break;
      default:
        for (i = 0; i < Param.ifnum; ++i)
        {
          if( (targets[i].revents & (POLLIN | POLLERR)) == 0 ) {
            continue;
          }

          if ( (size = read(ifs[i].sock, buf, sizeof(buf))) <= 0 ) {
            DebugPerror("read");
            continue;
          }

          AnalyzePacket(i, buf, size);
        }
        break;
    }
  }

  free(targets);

  return 0;
}

int DisableIpForward()
{
  FILE *fp;

  if ( (fp = fopen("/proc/sys/net/ipv4/ip_forward", "w")) == NULL ) {
    DebugPrintf("cannot write /proc/sys/net/ipv4/ip_forward\n");
    return -1;
  }

  fputs("0", fp);
  fclose(fp);

  return 0;
}

void *BufThread(void *arg)
{
  BufferSend();

  return NULL;
}

void EndSignal(int sig)
{
  EndFlag = 1;
}

pthread_t BufTid;

int main(int argc, char *argv[], char *envp[])
{
  char            buf[80];
  pthread_attr_t  attr;
  int             status;
  int             i, res;

  char ifnames[10][16];

  /*
  res = GetDeviceNames(ifnames, &ifnum);
  if ( 0 != res ) {
    perror("Failed to get devices name!");
    return -1;
  }
  */

  if (ReadParam("router-config.txt") != 0) {
    fprintf(stderr, "Failed to read router-config.txt\n");
    return -1;
  }

  for (i = 0; i < Param.ifnum; i++)
    strcpy(ifnames[i], Param.devices[i]);

  /* Interfaces */
  ifs = (DEVICE *)malloc(sizeof(DEVICE) * Param.ifnum);
  if (ifs == NULL) {
    perror("malloc");
    return -1;
  }

  for (i = 0; i < Param.ifnum; i++) {
    DEVICE *iface = &ifs[i];
    strcpy(iface->name, ifnames[i]);
    if (GetDeviceInfo(ifnames[i], iface->hwaddr, &iface->addr, &iface->subnet, &iface->netmask) == -1) {
      DebugPrintf("GetDeviceInfo:error:%s\n", ifnames[i]);
      return -1;
    }

    if ( (iface->sock = InitRawSocket(ifnames[i], 1, 0)) == -1 ) {
      DebugPrintf("InitRawSocket:error:%s\n", ifnames[i]);
      return -1;
    }

    DebugPrintf("%s OK ", iface->name);
    DebugPrintf("addr=%s ", my_inet_ntoa_r(&iface->addr, buf, sizeof(buf)));
    DebugPrintf("subnet=%s ", my_inet_ntoa_r(&iface->subnet, buf, sizeof(buf)));
    DebugPrintf("netmask=%s\n", my_inet_ntoa_r(&iface->netmask, buf, sizeof(buf)));
  }

  /* load the full route */
  res = load_routes("entry.txt");
  if ( 0 != res ) {
    perror("Failed to load routes!");
    return -1;
  }

  /*
  struct in_addr testaddr;
  inet_aton("172.114.22.22", &testaddr);
  struct routing_table_entry* test = lookup_route_entry(testaddr.s_addr);
  */
  
  DisableIpForward();

  pthread_attr_init(&attr);

  if ( (status = pthread_create(&BufTid, &attr, BufThread, NULL)) != 0 ) {
    DebugPrintf("pthread_create:%s\n", strerror(status));
  }

  signal(SIGINT, EndSignal);
  signal(SIGTERM, EndSignal);
  signal(SIGQUIT, EndSignal);

  signal(SIGPIPE, SIG_IGN);
  signal(SIGTTIN, SIG_IGN);
  signal(SIGTTOU, SIG_IGN);

  DebugPrintf("router start\n");
  Router();
  DebugPrintf("router end\n");

  pthread_join(BufTid, NULL);

  for (i = 0; i < Param.ifnum; i++)
    close(ifs[i].sock);

  free(ifs);

  return 0;
}
