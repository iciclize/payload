#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "params.h"
#include "netutil.h"
#include "base.h"
#include "napt.h"

extern PARAM Param;

extern int DebugPrintf(char *fmt, ...);


extern DEVICE *ifs; /* Interfaces */

struct napt_table_entry napt_table_tcp[NAPT_TABLE_SIZE];
struct napt_table_entry napt_table_udp[NAPT_TABLE_SIZE];

u_int16_t L4checksum(struct in_addr *saddr, struct in_addr *daddr, u_int8_t proto, u_int8_t *data, int len)
{
  struct pseudo_ip  p_ip;
  u_int16_t  sum;

  memset(&p_ip, 0, sizeof(struct pseudo_ip));
  p_ip.ip_src.s_addr = saddr->s_addr;
  p_ip.ip_dst.s_addr = daddr->s_addr;
  p_ip.ip_p = proto;
  p_ip.ip_len = htons(len);

  sum = checksum2((u_int8_t *)&p_ip, sizeof(struct pseudo_ip), data, len);
  return sum;
}

uint16_t lookup_free_port(struct napt_table_entry *table)
{
  for (uint16_t i = 32768; i < 61000; i++) {
CONT:
    for (uint8_t j = 0; j < NAPT_TABLE_SIZE; j++) {
      if (table[j].external_port == htons(i)) {
        i++;
        goto CONT;
      }
    }
    return i;
  }
  return 0;
}

int validate_napt_entry(struct timeval *now, struct napt_table_entry *entry)
{
  if (entry->used == 0)
    return 1;

  unsigned int sec = now->tv_sec - entry->last_time.tv_sec;
  unsigned int msec = (now->tv_usec - entry->last_time.tv_usec) / 1000;
  if (sec * 1000 + msec >= NAPT_TIMEOUT) {
    entry->used = 0;
    char buf[80], buf1[80];
    if (entry->protocol == IPPROTO_TCP) {
      DebugPrintf("[NAPT/TCP] Entry [%s:%d === %s:%d] deleted for expiration.\n",
          in_addr_t2str(entry->client_addr, buf, sizeof(buf)), ntohs(entry->client_port),
          in_addr_t2str(ifs[0].addr.s_addr, buf1, sizeof(buf1)), ntohs(entry->external_port));
    } else if (entry->protocol == IPPROTO_UDP) {
      DebugPrintf("[NAPT/UDP] Entry [%s:%d === %s:%d] deleted for expiration.\n",
          in_addr_t2str(entry->client_addr, buf, sizeof(buf)), ntohs(entry->client_port),
          in_addr_t2str(ifs[0].addr.s_addr, buf1, sizeof(buf1)), ntohs(entry->external_port));
    }
    return 1;
  }
  return 0;
}

void update_napt_entry(struct napt_table_entry *entry)
{
  struct timeval now;
  gettimeofday(&now, NULL);
  entry->last_time = now;
}

struct napt_table_entry*
_create_napt_entry(struct napt_table_entry *table, uint32_t client_addr, uint16_t client_port)
{
  struct timeval now;
  gettimeofday(&now, NULL);
  int index = -1;
  for (int i = 0; i< NAPT_TABLE_SIZE; i++) {
    validate_napt_entry(&now, &table[i]);
    if (table[i].used == 0) {
      index = i;
    }
  }

  if (index == -1) {
    return NULL;
  }

  gettimeofday(&now, NULL);
  struct napt_table_entry *entry = &table[index];
  entry->used = 1;
  entry->client_addr = client_addr;
  entry->client_port = client_port;
  entry->external_port = htons(lookup_free_port(table));
  if (entry->external_port == 0) {
    fprintf(stderr, "まいったねこれは\n");
  }
  entry->last_time = now;
  if (table == napt_table_tcp)
    entry->protocol = IPPROTO_TCP;
  else if (table == napt_table_udp)
    entry->protocol = IPPROTO_UDP;
  else
    entry->protocol = 0;
  return entry;
}

struct napt_table_entry*
create_napt_tcp(uint32_t client_addr, uint16_t client_port)
{
  return _create_napt_entry(napt_table_tcp, client_addr, client_port);
}

struct napt_table_entry*
create_napt_udp(uint32_t client_addr, uint16_t client_port)
{
  return _create_napt_entry(napt_table_udp, client_addr, client_port);
}

struct napt_table_entry*
_lookup_napt_entry(struct napt_table_entry *table, enum packet_direction direction, uint32_t addr, uint16_t port)
{
  struct timeval now;
  gettimeofday(&now, NULL);

  for (int i = 0; i < NAPT_TABLE_SIZE; i++) {
    struct napt_table_entry *entry = &table[i];
    validate_napt_entry(&now, entry);
    if (entry->used == 0) {
      continue;
    }
    if (direction == DIRECTION_INCOMING) {
      if (port == entry->external_port) {
        /* someAddr:somePort --> eAddr:ePort*/
        return entry;
      }
    } else {
      if (addr == entry->client_addr &&
          port == entry->client_port) {
        /* iAddr:iPort --> someAddr:somePort */
        return entry;
      }
    }
  }

  return NULL;
}

struct napt_table_entry*
lookup_napt_tcp(enum packet_direction direction, uint32_t addr, uint16_t port)
{
  return _lookup_napt_entry(napt_table_tcp, direction, addr, port);
}

struct napt_table_entry*
lookup_napt_udp(enum packet_direction direction, uint32_t addr, uint16_t port)
{
  return _lookup_napt_entry(napt_table_udp, direction, addr, port);
}

int do_napt_tcp(enum packet_direction direction, struct ip *iphdr, struct tcphdr *tcphdr, int dlen)
{
  struct napt_table_entry *entry;

  /* TODO: test */
  /*
  DebugPrintf("===== [NAPT-TCP TABLE] =====\n");
  int ind = 0;
  for (int i = 0; i < NAPT_TABLE_SIZE; i++) {
    struct napt_table_entry *e  = &napt_table_tcp[i];
    if (e->used == 0) continue;
    ind++;
    char buf[80], buf1[80];
    struct timeval now; gettimeofday(&now, NULL);
    unsigned int sec = now.tv_sec - e->last_time.tv_sec;
    unsigned int msec = (now.tv_usec - e->last_time.tv_usec) / 1000;
    int lst = sec * 1000 + msec;
    DebugPrintf("%02d | %s:%d --- %s:%d | %d ms\n", ind,
                                          in_addr_t2str((in_addr_t)e->client_addr, buf, sizeof(buf)), ntohs(e->client_port),
                                          in_addr_t2str((in_addr_t)ifs[0].addr.s_addr, buf1, sizeof(buf1)), ntohs(e->external_port),
                                          lst);
  }
  DebugPrintf("===== ================ =====\n");
  */

  if (direction == DIRECTION_INCOMING) {
    entry = lookup_napt_tcp(DIRECTION_INCOMING, iphdr->ip_dst.s_addr, tcphdr->dest);
    if (entry == NULL) {
      char buf[80];
      DebugPrintf("[NAPT/TCP] No entry for INCOMING packet from %s:%d\n", in_addr_t2str(iphdr->ip_dst.s_addr, buf, sizeof(buf)), ntohs(tcphdr->dest));
      return -1;
    }

    iphdr->ip_dst.s_addr = entry->client_addr;
    tcphdr->dest = entry->client_port;

  } else { /* OUTGOING */
    entry = lookup_napt_tcp(DIRECTION_OUTGOING, iphdr->ip_src.s_addr, tcphdr->source);
    if (entry == NULL) {
      entry = create_napt_tcp(iphdr->ip_src.s_addr, tcphdr->source);
      char buf[80], buf1[80];
      if (entry == NULL) {
        DebugPrintf("[NAPT/TCP] Couldn't create entry for OUTGOING packet from %s:%d >>> %s:%d\n",
            in_addr_t2str(iphdr->ip_src.s_addr, buf, sizeof(buf)), ntohs(tcphdr->source),
            in_addr_t2str(iphdr->ip_dst.s_addr, buf1, sizeof(buf1)), ntohs(tcphdr->dest));
        return -1;
      }
      DebugPrintf("[NAPT/TCP] OUTGOING packet is assigned [%s:%d => %s:%d]\n\n", 
          in_addr_t2str(iphdr->ip_src.s_addr, buf, sizeof(buf)), ntohs(tcphdr->source),
          in_addr_t2str(ifs[0].addr.s_addr, buf1, sizeof(buf1)), ntohs(entry->external_port));
    }

    iphdr->ip_src.s_addr = ifs[0].addr.s_addr;
    tcphdr->source = entry->external_port;
  }

  tcphdr->check = 0;
  uint16_t cksum = L4checksum(&iphdr->ip_src, &iphdr->ip_dst, iphdr->ip_p, (uint8_t *)tcphdr, dlen);
  tcphdr->check = cksum;

  update_napt_entry(entry);
  return 0;
}

int do_napt_udp(enum packet_direction direction, struct ip *iphdr, struct udphdr *udphdr, int dlen)
{
  struct napt_table_entry *entry;

  if (direction == DIRECTION_INCOMING) {
    entry = lookup_napt_udp(DIRECTION_INCOMING, iphdr->ip_dst.s_addr, udphdr->dest);
    if (entry == NULL) {
      char buf[80];
      DebugPrintf("[NAPT/UDP] No entry for INCOMING packet from %s:%d\n", in_addr_t2str(iphdr->ip_dst.s_addr, buf, sizeof(buf)), ntohs(udphdr->dest));
      return -1;
    }

    iphdr->ip_dst.s_addr = entry->client_addr;
    udphdr->dest = entry->client_port;

  } else { /* OUTGOING */
    entry = lookup_napt_udp(DIRECTION_OUTGOING, iphdr->ip_src.s_addr, udphdr->source);
    if (entry == NULL) {
      entry = create_napt_udp(iphdr->ip_src.s_addr, udphdr->source);
      char buf[80], buf1[80];
      if (entry == NULL) {
        DebugPrintf("[NAPT/UDP] Couldn't create entry for OUTGOING packet from %s:%d >>> %s:%d\n",
            in_addr_t2str(iphdr->ip_src.s_addr, buf, sizeof(buf)), ntohs(udphdr->source),
            in_addr_t2str(iphdr->ip_dst.s_addr, buf1, sizeof(buf1)), ntohs(udphdr->dest));
        return -1;
      }
      DebugPrintf("[NAPT/UDP] OUTGOING packet from %s:%d is assigned to %s:%d\n\n", 
          in_addr_t2str(iphdr->ip_src.s_addr, buf, sizeof(buf)), ntohs(udphdr->source),
          in_addr_t2str(ifs[0].addr.s_addr, buf1, sizeof(buf1)), ntohs(entry->external_port));
    }

    iphdr->ip_src.s_addr = ifs[0].addr.s_addr;
    udphdr->source = entry->external_port;
  }

  udphdr->check = 0;
  uint16_t cksum;
  cksum = L4checksum(&iphdr->ip_src, &iphdr->ip_dst, iphdr->ip_p, (uint8_t *)udphdr, dlen);
  if (cksum == 0x0000) {
    cksum = 0xFFFF;
  }
  udphdr->check = cksum;

  update_napt_entry(entry);
  return 0;
}

int DoNAPT(int ifNo, struct ip *iphdr, uint8_t *ipdata, int size)
{
  if (ifNo == 0) {
    /* From WAN-side interface */
    /* Incoming or External */
    if ( iphdr->ip_dst.s_addr != ifs[0].addr.s_addr ) {
      /* External. No translation */
      return 1;
    }
    /* Incoming */
    if (iphdr->ip_p == IPPROTO_TCP) {
      do_napt_tcp(DIRECTION_INCOMING, iphdr, (struct tcphdr *)ipdata, size);
    } else if (iphdr->ip_p == IPPROTO_UDP) {
      do_napt_udp(DIRECTION_INCOMING, iphdr, (struct udphdr *)ipdata, size);
    }

  } else {
    /* Outgoing or Internal */
    for (int i = 1; i < Param.ifnum; i++) {
      if (ifs[i].subnet.s_addr == (iphdr->ip_dst.s_addr & ifs[i].netmask.s_addr)) {
        /* Internal. No translation */
        return 1;
      }
    }
    /* Outgoing */
    if (iphdr->ip_p == IPPROTO_TCP) {
      do_napt_tcp(DIRECTION_OUTGOING, iphdr, (struct tcphdr *)ipdata, size);
    } else if (iphdr->ip_p == IPPROTO_UDP) {
      do_napt_udp(DIRECTION_OUTGOING, iphdr, (struct udphdr *)ipdata, size);
    }

  }

  return 0;
}
