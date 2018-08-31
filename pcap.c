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

#include "pcap.h"
#include "analyze.h"

int InitRawSocket(char *device, int promiscFlag, int ipOnly)
{
  struct ifreq ifreq;
  struct sockaddr_ll sa;
  int sock;

  int protocolID = ipOnly ? htons(ETH_P_IP) : htons(ETH_P_ALL);

  if ( ( sock = socket(PF_PACKET, SOCK_RAW, protocolID) ) < 0 )
  {
    perror("socket() failed.");
    return -1;
  }

  memset(&ifreq, 0, sizeof(struct ifreq));
  strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);

  if (ioctl(sock, SIOCGIFINDEX, &ifreq) < 0)
  {
    perror("ioctl() failed.");
    close(sock);

    return -1;
  }

  sa.sll_family = PF_PACKET;
  sa.sll_protocol = protocolID;
  sa.sll_ifindex = ifreq.ifr_ifindex;
  if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
  {
    perror("bind() failed.");
    close(sock);
    return -1;
  }

  if (promiscFlag) {
    if (ioctl(sock, SIOCGIFFLAGS, &ifreq) < 0 )
    {
      perror("ioctl() failed.");
      close(sock);
      return -1;
    }

    ifreq.ifr_flags = ifreq.ifr_flags | IFF_PROMISC;
    if (ioctl(sock, SIOCSIFFLAGS, &ifreq) < 0)
    {
      perror("ioctl failed.");
      close(sock);
      return -1;
    }
  }

  return sock;
}

int main(int argc, char *argv[], char *envp[])
{
  int sock, size;
  u_char buf[65535];

  /* Arguments check */
  if (argc <= 1)
  {
    fprintf(stderr, "pcap device-name\n");
    return 1;
  }

  /* Init a socket */
  if ( (sock = InitRawSocket(argv[1], 0, 0)) == -1 )
  {
    fprintf(stderr, "InitRawSocket:error:%s\n", argv[1]);
    return -1;
  }

  while (1)
  {
    if ( (size = read(sock, buf, sizeof(buf))) <= 0 )
    {
      perror("read() failed.");
    }
    else
    {
      AnalyzePacket(buf, size);
    }
  }

  close(sock);

  return 0;
}
