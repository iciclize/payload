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

#include "netutil.h"
#include "analyze.h"

typedef struct {
  char *Device1;
  char *Device2;
  int   DebugOut;
} PARAM;

PARAM Param = { "eth0", "eth1", 1 };

typedef struct {
  int sock;
} DEVICE;

DEVICE Device[2];

int EndFlag = 0;

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

int printPacket(int deviceNo, u_char *data, int size)
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
  
  u_int16_t ether_type = ntohs(eh->ether_type);

  DebugPrintf("[%d][%d Bytes]\n", deviceNo, size);

  if (Param.DebugOut)
  {
    PrintEtherHeader(eh, stderr);
    switch (ether_type)
    {
      case ETHERTYPE_ARP:
        AnalyzeArp(ptr, lest);
        break;
      case ETHERTYPE_IP:
        AnalyzeIp(ptr, lest);
        break;
      case ETHERTYPE_IPV6:
        AnalyzeIpv6(ptr, lest);
        break;
    }
  }

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
        for (i = 0; i <= 1; ++i)
        {
          if( (targets[i].revents & (POLLIN | POLLERR)) == 0 )
            break;

          if ( (size = read(Device[i].sock, buf, sizeof(buf))) <= 0 )
          {
            perror("read");
            break;
          }
          else if ( printPacket(i, buf, size) == -1 )
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
