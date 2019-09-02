#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "params.h"

extern PARAM  Param;
static char  *ParamFname = NULL;

int my_ether_aton(char *str, u_int8_t *mac)
{
  char  *ptr, *saveptr = NULL;
  int  c;
  char  *tmp = strdup(str);

  for (c = 0, ptr = strtok_r(tmp, ":", &saveptr); c < 6; c++, ptr = strtok_r(NULL, ":", &saveptr)) {
    if (ptr == NULL) {
      free(tmp);
      return(-1);
    }
    mac[c] = strtol(ptr, NULL, 16);
  }
  free(tmp);

  return(0);
}

int SetDefaultParam()
{
  Param.MTU = DEFAULT_MTU;
  Param.IpTTL = DEFAULT_IP_TTL;
  Param.MSS = DEFAULT_MSS;
  Param.ifnum = 1;
  Param.devices[0] = 0;

  return(0);
}

int ReadParam(char *fname)
{
  FILE  *fp;
  char  buf[1024];
  char  *ptr, *saveptr;

  ParamFname = fname;

  if ( (fp = fopen(fname, "r")) == NULL ) {
    printf("%s cannot read\n", fname);
    return(-1);
  }

  while (1) {
    fgets(buf, sizeof(buf), fp);
    if (feof(fp)) {
      break;
    }
    ptr = strtok_r(buf, "=", &saveptr);
    if (ptr != NULL) {
      if (strcmp(ptr, "IP-TTL") == 0) {
        if ( (ptr = strtok_r(NULL, "\r\n", &saveptr)) != NULL ) {
          Param.IpTTL = atoi(ptr);
        }
      } else if (strcmp(ptr, "DebugOut") == 0) {
        if ( (ptr = strtok_r(NULL, "\r\n", &saveptr)) != NULL) {
          Param.DebugOut = atoi(ptr);
        }
      } else if (strcmp(ptr, "MTU") == 0) {
        if ( (ptr = strtok_r(NULL, "\r\n", &saveptr)) != NULL) {
          Param.MTU = atoi(ptr);
          if (Param.MTU > ETHERMTU) {
            printf("ReadParam:MTU(%d) <= ETHERMTU(%d)\n", Param.MTU, ETHERMTU);
            Param.MTU = ETHERMTU;
          }
        }
      } else if (strcmp(ptr, "MSS") == 0) {
        if ( (ptr = strtok_r(NULL, "\r\n", &saveptr)) != NULL ) {
          Param.MSS = atoi(ptr);
          if (Param.MSS > ETHERMTU) {
            printf("ReadParam:MSS(%d) <= ETHERMTU(%d)\n", Param.MSS, ETHERMTU);
            Param.MSS = ETHERMTU;
          }
        }
      } else if (strcmp(ptr, "gateway") == 0) {
        if ( (ptr = strtok_r(NULL, "\r\n", &saveptr)) != NULL ) {
          Param.gateway.s_addr = inet_addr(ptr);
        }
      } else if (strcmp(ptr, "wandev") == 0) {
        if ( (ptr = strtok_r(NULL, " \r\n", &saveptr)) != NULL ) {
          Param.devices[0] = strdup(ptr);
          Param.ifnum++;
        }
      } else if (strcmp(ptr, "landevs") == 0) {
        for (int i = 1; (ptr = strtok_r(NULL, ",\r\n", &saveptr)) != NULL; i++ ) {
          Param.devices[i] = strdup(ptr);
          Param.ifnum++;
        }
      } else if (strcmp(ptr, "DhcpRequestLeaseTime") == 0) {
        if ( (ptr = strtok_r(NULL, " \r\n", &saveptr)) != NULL ) {
          Param.DhcpRequestLeaseTime = atoi(ptr);
        }
      }
    }
  }

  fclose(fp);

  if (*Param.devices[0] == 0) {
    fprintf(stderr, "Error. No WAN-side devices specified.\n");
    return -1;
  }

  return 0;
}

