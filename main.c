#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <signal.h>
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
  size_t  lest;
  struct  ether_header *eh;

  /* フレームはFCS含んでたり含んでなかったりするみたいなので注意 */
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
    IpRecv(ifNo, eh, ptr, size);
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

  load_yjsnpi_response("yjsnpi.jpg");

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
