#include <stdio.h>
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

#include "radix.h"

#include "netutil.h"
#include "base.h"
#include "ip2mac.h"
#include "sendBuf.h"
#include "params.h"
#include "napt.h"

PARAM Param;

int EndFlag = 0;

struct radix_tree *rt; /* Routing table */
DEVICE *ifs;           /* Interfaces */
int ifnum;             /* The number of interfaces */

int getIfIndexByAddress(struct in_addr nexthop)
{
  for (int i = 0; i < ifnum; i++)
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
  int     lest;
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
    DebugPrintf("[%d]:dhost not match %s\n", ifNo, my_ether_ntoa_r((u_char *)&eh->ether_dhost, buf, sizeof(buf)));
    return -1;
  }

  if (ntohs(eh->ether_type) == ETHERTYPE_ARP) {
    /* フレームの中身がARPパケットだったとき */
    struct ether_arp  *arp;

    if (lest < sizeof(struct ether_arp)) {
      DebugPrintf("[%d]:lest(%d) < sizeof(struct ether_arp)\n", ifNo, lest);
      return -1;
    }

    arp  = (struct ether_arp *)ptr;
    ptr  += sizeof(struct ether_arp); /* ポインタをARPヘッダの分だけ進める. ARPにはボディがなく空っぽになるので得に意味はなさそう. */
    lest -= sizeof(struct ether_arp); /* 残りフレームサイズはたぶん0になるよね */

    if (arp->arp_op == htons(ARPOP_REQUEST)) {
      /* ARP要求が聞こえたので送り主のプロトコルアドレス(IPアドレス)とハードウェアアドレス(MACアドレス)を覚えとこ */
      DebugPrintf("[%s]recv:ARP REQUEST:%dbytes\n", ifs[ifNo].name, size);
      Ip2Mac(ifNo, *(in_addr_t *)arp->arp_spa, arp->arp_sha);
    }

    if (arp->arp_op == htons(ARPOP_REPLY)) {
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

    /* IPヘッダは20Bytesはあるのに残りのフレームサイズがそれより小さいのはおかしいという話 */
    if (lest < sizeof(struct iphdr)) {
      DebugPrintf("[%d]:lest(%d) < sizeof(struct iphdr)\n", ifNo, lest);
      return -1;
    }

    iphdr = (struct iphdr *)ptr;
    ptr  += sizeof(struct iphdr); /* ポインタはIPペイロードもしくはIPヘッダのオプション部分に進む */
    lest -= sizeof(struct iphdr); /* フレーム残りサイズ */

    optionLen = iphdr->ihl * 4 - sizeof(struct iphdr); /* IPヘッダのオプション部分のサイズ. ヘッダ長の値から20Bytes引いているんですね */
    if (optionLen > 0) {
      if (optionLen >= 1500) {
        DebugPrintf("[%d]:IP optionLen(%d):too big\n", ifNo, optionLen);
        return -1;
      }

      memcpy(option, ptr, optionLen);
      ptr  += optionLen; /* ポインタはIPペイロード */
      lest -= optionLen;
    }

    /* IPチェックサムを検証して壊れたパケットを弾く */
    if (checkIPchecksum(iphdr, option, optionLen) == 0) {
      DebugPrintf("[%d]:bad ip checksum\n", ifNo);
      fprintf(stderr, "IP checksum error\n");
      return -1;
    }

    if (iphdr->ttl - 1 <= 0) {
      DebugPrintf("[%d]:iphdr->ttl <= 0 error\n", ifNo);
      SendIcmpTimeExceeded(ifNo, eh, iphdr, data, size);
      return -1;
    }

    PrintIpHeader(iphdr, option, optionLen, stdout);

    /*
     * NAPTする
     */
    DoNAPT(ifNo, iphdr, ptr, lest);

    struct in_addr nexthop;
    /* ネクストホップ探し、バイトオーダーをビッグエンディアンに */
    nexthop.s_addr = (in_addr_t) htonl( (uint64_t)radix_tree_lookup(rt, (uint8_t *)&iphdr->daddr) );

    tno = getIfIndexByAddress(nexthop);
    if ( -1 == tno ) {
      fprintf(stderr, "No interfaces correspond to nexthop %s\n", in_addr_t2str(nexthop.s_addr, buf, sizeof(buf)));
      return -1;
    }

    DebugPrintf("Nexthop: %s (if: %s)\n", in_addr_t2str(nexthop.s_addr, buf, sizeof(buf)), ifs[tno].name);

    IP2MAC *ip2mac;
    ip2mac = Ip2Mac(tno, nexthop.s_addr, NULL);

    if (ip2mac->flag == FLAG_NG || ip2mac->sd.dno !=0) {
      DebugPrintf("[%s]:Ip2Mac:error or sending\n", ifs[ifNo].name);
      AppendSendData(ip2mac, 1, nexthop.s_addr, data, size);
      return -1;
    }
    else {
      memcpy(hwaddr, ip2mac->hwaddr, 6);
    }

    memcpy(eh->ether_dhost, hwaddr, 6);
    memcpy(eh->ether_shost, ifs[tno].hwaddr, 6);

    iphdr->ttl--;
    iphdr->check = 0;
    iphdr->check = checksum2((u_char *)iphdr, sizeof(struct iphdr), option, optionLen);

    write(ifs[tno].sock, data, size);
  }

  return 0;
}

/*
 * load_full_route
 *
 * 経路情報の読み込み.
 *
 * char *filename 経路情報の記述されたファイル名.
 */
int load_full_route(char *filename)
{
  FILE *fp;
  char buf[4096];
  int prefix[4];
  int prefixlen;
  int nexthop[4];
  int ret;
  uint8_t addr1[4];
  uint64_t addr2;

  /* Load from the linx file */
  fp = fopen(filename, "r");
  if ( NULL == fp ) {
    return -1;
  }

  /* Load the full route */
  while ( !feof(fp) ) {
    if ( !fgets(buf, sizeof(buf), fp) ) {
      continue;
    }
    ret = sscanf(buf, "%d.%d.%d.%d/%d %d.%d.%d.%d", &prefix[0], &prefix[1],
        &prefix[2], &prefix[3], &prefixlen, &nexthop[0],
        &nexthop[1], &nexthop[2], &nexthop[3]);
    if ( ret < 0 ) {
      return -1;
    }

    /* Convert to u32 */
    addr1[0] = prefix[0];
    addr1[1] = prefix[1];
    addr1[2] = prefix[2];
    addr1[3] = prefix[3];
    addr2 = ((uint32_t)nexthop[0] << 24) + ((uint32_t)nexthop[1] << 16)
      + ((uint32_t)nexthop[2] << 8) + (uint32_t)nexthop[3];

    /* Add an entry */
    ret = radix_tree_add(rt, addr1, prefixlen, (void *)(uint64_t)addr2);
    if ( ret < 0 ) {
      return -1;
    }
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

  targets = (struct pollfd *)malloc(sizeof(struct pollfd) * ifnum);

  for (i = 0; i < ifnum; i++) {
    targets[i].fd = ifs[i].sock;
    targets[i].events = POLLIN | POLLERR;
  }

  while (EndFlag == 0)
  {
    switch (nready = poll(targets, ifnum, 100))
    {
      case -1:
        if (errno != EINTR)
          DebugPerror("poll");

        break;
      case 0:
        break;
      default:
        for (i = 0; i < ifnum; ++i)
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

  /* Initialize radix tree */
  rt = radix_tree_init(NULL);
  if ( NULL == rt ) {
    perror("Failed to initialize routing table!");
    return -1;
  }

  /* load the full route */
  res = load_full_route("entry.txt");
  if ( 0 != res ) {
    perror("Failed to load routes!");
    return -1;
  }

  /*
  res = GetDeviceNames(ifnames, &ifnum);
  if ( 0 != res ) {
    perror("Failed to get devices name!");
    return -1;
  }
  */

  if (argc <= 1) {
    printf("Usage: %s if1 if2 ...\n", argv[0]);
    return 0;
  }

  ifnum = argc - 1;
  for (i = 0; i < ifnum; i++)
    strcpy(ifnames[i], argv[i + 1]);

  /* Interfaces */
  ifs = (DEVICE *)malloc(sizeof(DEVICE) * ifnum);
  if (ifs == NULL) {
    perror("malloc");
    return -1;
  }

  for (i = 0; i < ifnum; i++) {
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

  for (i = 0; i < ifnum; i++)
    close(ifs[i].sock);

  free(ifs);

  return 0;
}
