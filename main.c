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

#include "netutil.h"
#include "base.h"
#include "ip2mac.h"
#include "sendBuf.h"

typedef struct {
  char *Device1;
  char *Device2;
  int   DebugOut;
  char *nextRouter;
} PARAM;

PARAM Param = { "eth0", "eth1", 0, "192.168.10.221" };

typedef struct {
  int sock;
} DEVICE;

DEVICE          Device[2];
struct in_addr  NextRouter;
int             EndFlag = 0;

int DebugPrintf(char *fmt, ...)
{
  if (Param.DebugOut)
  {
    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
  }

  return 0;
}

int DebugPerror(char *msg)
{
  if (Param.DebugOut)
    fprintf(stderr, "%s : %s\n", msg, strerror(errno));

  return 0;
}

int SendIcmpTimeExceeded(int deviceNo, struct ether_header *eh, struct iphdr *iphdr, u_char *data, int size)
{
  struct ether_header reh;
  struct iphdr        rih;
  struct icmp         icmp;
  u_char             *ipptr;
  u_char             *ptr,
                      buf[1500];
  int                 len;

  memcpy(reh.ether_dhost, eh->ether_shost, 6);
  memcpy(reh.ether_shost, Device[deviceNo].hwaddr, 6);
  reh.ether_type = htons(ETHERTYPE_IP);

  rih.version  = 4;
  rih.ihl      = 20 / 4;
  rih.tos      = 0;
  rih.tot_len  = htons(sizeof(struct icmp) + 64);
  rih.id       = 0;
  rih.frag_off = 0
  rih.ttl      = 64;
  rih.protocol = IPPROTO_ICMP;
  rih.check    = 0;
  rih.saddr    = Device[deviceNo].addr.s_addr;
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
  memcpt(ptr, &icmp, 8);
  ptr += 8;
  memcpy(ptr, ipptr, 64);
  ptr += 64;
  len = ptr - buf;

  DebugPrintf("write:SendIcmpTimeExceeded:[%d] %dbytes\n", deviceNo, len);
  write(Device[deviceNo].sock, buf, len);

  return 0;
}

int AnalyzePacket(int deviceNo, u_char *data, int size)
{
  u_char *ptr;
  int     lest;
  struct ether_header *eh;

  ptr = data;
  lest = size;

  if (lest < sizeof(struct ether_header))
  {
    DebugPrintf("[%d]:lest(%d) < sizeof(struct ether_header)\n", deviceNo, lest);
    return -1;
  }

  eh = (struct ether_header *)ptr;
  ptr += sizeof(struct ether_header);
  lest -= sizeof(struct ether_header);
  DebugPrintf("[%d]", deviceNo);

  if (Param.DebugOut)
    PrintEtherHeader(eh, stderr);

  return 0;
}

int Bridge(void)
{
  struct pollfd targets[2];
  int           nready, i, size;
  u_char        buf[2048];

  targets[0].fd = Device[0].sock;
  targets[0].events = POLLIN | POLLERR;
  targets[1].fd = Device[1].sock;
  targets[1].events = POLLIN | POLLERR;

  while (EndFlag == 0)
  {
    switch (nready = poll(targets, 2, 100))
    {
      case -1:
        if (errno != EINTR)
          perror("poll");

        break;
      case 0:
        break;
      default:
        for (i = 1; i >= 0; --i)
        {
          if( (targets[i].revents & (POLLIN | POLLERR)) == 0 )
            break;

          if ( (size = read(Device[i].sock, buf, sizeof(buf))) <= 0 )
          {
            perror("read");
            break;
          }
          else if ( AnalyzePacket(i, buf, size) == -1 )
            break;
          else if ( (size = write(Device[(!i)].sock, buf, size)) <= 0 )
          {
            perror("write");
            break;
          }
        }
    }
  }

  return 0;
}

int DisableIpForward()
{
  FILE *fp;

  if ( (fp = fopen("/proc/sys/net/ipv4/ip_forward", "w")) == NULL )
  {
    DebugPrintf("cannot write /proc/sys/net/ipv4/ip_forward\n");
    return -1;
  }

  fputs("0", fp);
  fclose(fp);

  return 0;
}

int EnableIpForward()
{
  FILE *fp;

  if ( (fp = fopen("/proc/sys/net/ipv4/ip_forward", "w")) == NULL )
  {
    DebugPrintf("cannot write /proc/sys/net/ipv4/ip_forward\n");
    return -1;
  }

  fputs("1", fp);
  fclose(fp);

  return 0;
}

void EndSignal(int sig)
{
  EndFlag = 1;
}

int main(int argc, char *argv[], char *envp[])
{
  if ( (Device[0].sock = InitRawSocket(Param.Device1, 1, 0)) == -1 )
  {
    DebugPrintf("InitRawSocket:error:%s\n", Param.Device1);
    return -1;
  }

  DebugPrintf("%s OK\n", Param.Device1);

  if ( (Device[1].sock = InitRawSocket(Param.Device2, 1, 0)) == -1 )
  {
    DebugPrintf("InitRawSocket:error:%s\n", Param.Device2);
    return -1;
  }

  DebugPrintf("%s OK\n", Param.Device2);

  DisableIpForward();

  signal(SIGINT, EndSignal);
  signal(SIGTERM, EndSignal);
  signal(SIGQUIT, EndSignal);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGTTIN, SIG_IGN);
  signal(SIGTTOU, SIG_IGN);

  DebugPrintf("bridge start\n");
  Bridge();
  DebugPrintf("bridge end\n");

  close(Device[0].sock);
  close(Device[1].sock);
  
  EnableIpForward();

  return 0;
}
