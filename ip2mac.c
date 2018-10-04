#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>

#include "netutil.h"
#include "base.h"
#include "ip2mac.h"
#include "sendBuf.h"

extern int DebugPrintf(char *fmt, ...);

#define IP2MAC_TIMEOUT_SEC      60
#define IP2MAC_NG_TIMEOUT_SEC   1

struct {
  IP2MAC *data;
  int     size;
  int     no;
} Ip2Macs[2];

extern DEVICE Device[2];
extern int    ArpSock[2];

extern int EndFlag;

IP2MAC *Ip2MacSearch(int deviceNo, in_addr_t addr, u_char *hwaddr)
{
  register int i;
  int          freeNo, no;
  time_t       now;
  char         buf[80];
  IP2MAC      *ip2mac;

  freeNo = -1;
  now = time(NULL);

  for (i = 0; i < Ip2Macs[deviceNo].no; i++)
  {
    ip2mac = &Ip2Macs[deviceNo].data[i];
    if (ip2mac->flag == FLAG_FREE)
    {
      if (freeNo == -1)
      {
        freeNo = i;
      }
      continue;
    }
    if (ip2mac->addr == addr)
    {
      if (ip2mac->flag == FLAG_OK)
      {
        ip2mac->lastTime = now;
      }
      if (hwaddr != NULL)
      {
        memcpy(ip2mac->hwaddr, hwaddr, 6);
        ip2mac->flag = FLAG_OK;
        if (ip2mac->sd.top != NULL)
        {
            AppendSendReqData(deviceNo, i);
        }
        // DebugPrintf("Ip2Mac EXIST [%d] %s = %d\n", deviceNo, in_addr_t2str(addr, buf, sizeof(buf)), i);
        return ip2mac;
      }
      else
      {
        if ( (ip2mac->flag == FLAG_OK && now - ip2mac->lastTime > IP2MAC_TIMEOUT_SEC)
          || (ip2mac->flag == FLAG_NG && now - ip2mac->lastTime > IP2MAC_NG_TIMEOUT_SEC) )
        {
          FreeSendData(ip2mac);
          ip2mac->flag = FLAG_FREE;
          // DebugPrintf("Ip2Mac FREE [%d] %s = %d\n", deviceNo, in_addr_t2str(ip2mac->addr, buf, sizeof(buf)), i);            
          if (freeNo == -1)
          {
            freeNo = i;
          }
        }
        else
        {
          // DebugPrintf("Ip2Mac EXIST [%d] %s = %d\n", deviceNo, in_addr_t2str(addr, buf, sizeof(buf)), i);
          return ip2mac;
        }
      }
    }
    else
    {
      if ( (ip2mac->flag == FLAG_OK && now - ip2mac->lastTime > IP2MAC_TIMEOUT_SEC)
          || (ip2mac->flag == FLAG_NG && now - ip2mac->lastTime > IP2MAC_NG_TIMEOUT_SEC) )
      {
        FreeSendData(ip2mac);
        ip2mac->flag = FLAG_FREE;
        // DebugPrintf("Ip2Mac FREE [%d] %s = %d\n", deviceNo, in_addr_t2str(ip2mac->addr, buf, sizeof(buf)), i);            
        if (freeNo == -1)
        {
          freeNo = i;
        }
      }
    }
  }

  if (freeNo == -1)
  {
    no = Ip2Macs[deviceNo].no;
    if (no >= Ip2Macs[deviceNo].size)
    {
      if (Ip2Macs[deviceNo].size == 0)
      {
        Ip2Macs[deviceNo].size = 1024;
        Ip2Macs[deviceNo].data = (IP2MAC *)malloc(Ip2Macs[deviceNo].size * sizeof(IP2MAC));
      }
      else
      {
        Ip2Macs[deviceNo].size += 1024;
        Ip2Macs[deviceNo].data = (IP2MAC *)realloc(Ip2Macs[deviceNo].data, Ip2Macs[deviceNo].size * sizeof(IP2MAC));
      }
    }
    Ip2Macs[deviceNo].no ++;
  }
  else
  {
    no = freeNo;
  }

  ip2mac = &Ip2Macs[deviceNo].data[no];
  ip2mac->deviceNo = deviceNo;
  ip2mac->addr = addr;
  if (hwaddr == NULL)
  {
    ip2mac->flag = FLAG_NG;
    memset(ip2mac->hwaddr, 0, 6);
  }
  else
  {
    ip2mac->flag = FLAG_OK;
    memcpy(ip2mac->hwaddr, hwaddr, 6);
  }

  ip2mac->lastTime = now;
  memset(&ip2mac->sd, 0, sizeof(SEND_DATA));
  pthread_mutex_init(&ip2mac->sd.mutex, NULL);

  DebugPrintf("Ip2Mac ADD [%d] %s = %d\n", deviceNo, in_addr_t2str(ip2mac->addr, buf, sizeof(buf)), no);

  return ip2mac;
}

IP2MAC *Ip2Mac(int deviceNo, in_addr_t addr, u_char *hwaddr)
{
  IP2MAC *ip2mac;
  static u_char bcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  char buf[80];

  ip2mac = Ip2MacSearch(deviceNo, addr, hwaddr);

  if (ip2mac->flag == FLAG_OK)
  {
    DebugPrintf("Ip2Mac(%s):OK\n", in_addr_t2str(addr, buf, sizeof(buf)));
    return ip2mac;
  }
  else
  {
    DebugPrintf("Ip2Mac(%s):NG\n", in_addr_t2str(addr, buf, sizeof(buf)));
    DebugPrintf("Ip2Mac(%s):Send Aep Request\n", in_addr_t2str(addr, buf, sizeof(buf)));
    SendArpRequestB(Device[deviceNo].sock, addr, bcast, Device[deviceNo].addr.s_addr, Device[deviceNo].hwaddr);
    return ip2mac;
  }
}

int BufferSendOne(int deviceNo, IP2MAC *ip2mac)
{
  struct ether_header  eh;
  struct iphdr iphdr;
  u_char option[1500];
  int optionLen;
  int size;
  u_char *data;
  u_char *ptr;

  while (1)
  {
    if (GetSendData(ip2mac, &size, &data) == -1)
      break;

    ptr = data;

    memcpy(&eh, ptr, sizeof(struct ether_header));
    ptr += sizeof(struct ether_header);

    memcpy(&iphdr, ptr, sizeof(struct iphdr));
    ptr += sizeof(struct iphdr);

    optionLen = iphdr.ihl * 4 - sizeof(struct iphdr);
    if (optionLen > 0)
    {
      memcpy(option, ptr, optionLen);
      ptr += optionLen;
    }

    memcpy(eh.ether_dhost, ip2mac->hwaddr, 6);
    memcpy(data, &eh, sizeof(struct ether_header));

    DebugPrintf("iphdr.ttl %d->%d\n", iphdr.ttl, iphdr.ttl - 1);
    iphdr.ttl --;

    iphdr.check = 0;
    iphdr.check = checksum2((u_char *)&iphdr, sizeof(struct iphdr), option, optionLen);
    memcpy(data + sizeof(struct ether_header), &iphdr, sizeof(struct iphdr));

    DebugPrintf("write:BufferSendOne:[%d] %dbytes\n", deviceNo, size);
    write(Device[deviceNo].sock, data, size);

    /*
    DebugPrintf("***********************************[%d]\n", deviceNo);
    print_ether_header(&eh);
    print_ip(&ip);
    DebugPrintf("***********************************[%d}\n", deviceNo);
    */
  }

  return 0;
}

typedef struct _send_req_data_ {
  struct _send_req_data_  *next;
  struct _send_req_data_ *before;
  int deviceNo;
  int ip2macNo;
} SEND_REQ_DATA;

struct {
  SEND_REQ_DATA *top;
  SEND_REQ_DATA *bottom;
  pthread_mutex_t mutex;
  pthread_cond_t  cond;
} SendReq = { NULL, NULL, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER };

int AppendSendReqData(int deviceNo, int ip2macNo)
{
  SEND_REQ_DATA *d;
  int status;

  if ( (status = pthread_mutex_lock(&SendReq.mutex)) != 0 )
  {
    DebugPrintf("AppendSendReqData:pthread_mutex_lock:%s\n", strerror(status));
    return -1;
  }

  for (d = SendReq.top; d != NULL; d = d->next)
  {
    if (d->deviceNo == deviceNo && d->ip2macNo == ip2macNo)
    {
      pthread_mutex_unlock(&SendReq.mutex);
      return 1;
    }
  }

  d = (SEND_REQ_DATA *)malloc(sizeof(SEND_REQ_DATA));

  if (d == NULL)
  {
    DebugPrintf("AppendSendReqData:malloc");
    pthread_mutex_unlock(&SendReq.mutex);
    return -1;
  }

  d->next = d->before = NULL;
  d->deviceNo = deviceNo;
  d->ip2macNo = ip2macNo;

  if (SendReq.bottom == NULL)
  {
    SendReq.top = SendReq.bottom = d;
  }
  else
  {
    SendReq.bottom->next = d;
    d->before = SendReq.bottom;
    SendReq.bottom = d;
  }

  pthread_cond_signal(&SendReq.cond);
  pthread_mutex_unlock(&SendReq.mutex);

  DebugPrintf("AppendSendReqData:[%d] %d\n", deviceNo, ip2macNo);

  return 0;
}

int GetSendReqData(int *deviceNo, int *ip2macNo)
{
  SEND_REQ_DATA *d;
  int status;

  if (SendReq.top == NULL)
    return -1;

  if ( (status = pthread_mutex_lock(&SendReq.mutex)) != 0 )
  {
    DebugPrintf("pthread_mutex_lock:%s\n", strerror(status));
    return -1;
  }

  d = SendReq.top;
  SendReq.top = d->next;

  if (SendReq.top == NULL)
  {
    SendReq.bottom = NULL;
  }
  else
  {
    SendReq.top->before = NULL;
  }
  pthread_mutex_unlock(&SendReq.mutex);

  *deviceNo = d->deviceNo;
  *ip2macNo = d->ip2macNo;

  DebugPrintf("GetSendReqData:[%d] %d\n", *deviceNo, *ip2macNo);

  return 0;
}

int BufferSend()
{
  struct timeval now;
  struct timespec timeout;
  int deviceNo, ip2macNo;
  int status;

  while (EndFlag == 0)
  {
    gettimeofday(&now, NULL);
    timeout.tv_sec = now.tv_sec + 1;
    timeout.tv_nsec = now.tv_usec * 1000;

    pthread_mutex_lock(&SendReq.mutex);

    if ( (status = pthread_cond_timedwait(&SendReq.cond, &SendReq.mutex, &timeout)) != 0 )
    {
      DebugPrintf("pthread_cond_timedwait:%s\n", strerror(status));
    }
    pthread_mutex_unlock(&SendReq.mutex);

    while (1)
    {
      if ( GetSendReqData(&deviceNo, &ip2macNo) == -1 )
      {
        break;
      }

      BufferSendOne(deviceNo, &Ip2Macs[deviceNo].data[ip2macNo]);
    }
  }

  DebugPrintf("BufferSend:end\n");

  return 0;
}
