#include <stdio.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "params.h"
#include "base.h"

extern PARAM Param;

extern int DebugPrintf(char *fmt, ...);

struct napt_table_entry {
  int used;
  uint32_t client_addr;
  uint16_t client_port;
  /* uint32_t external_addr;  redundant. Always equals to ifs[0].addr */
  uint16_t external_port;
  struct timeval last_time;
};

enum packet_direction {
  DIRECTION_INCOMING = 1,
  DIRECTION_OUTGOING
};

#define NAPT_TABLE_SIZE 24
#define NAPT_TIMEOUT 2500

extern DEVICE *ifs; /* Interfaces */

struct napt_table_entry napt_table_tcp[NAPT_TABLE_SIZE];
struct napt_table_entry napt_table_udp[NAPT_TABLE_SIZE];

int validate_napt_entry(struct timeval *now, struct napt_table_entry *entry)
{
  if (entry->used == 0)
    return 1;

  unsigned int sec = now->tv_sec - entry->last_time.tv_sec;
  unsigned int msec = (now->tv_usec - entry->last_time.tv_usec) / 1000;
  if (sec * 1000 + msec >= NAPT_TIMEOUT) {
    entry->used = 0;
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

int _create_napt_entry(struct napt_table_entry *table, uint32_t client_addr, uint16_t client_port, uint32_t external_addr, uint16_t external_port)
{
  struct timeval now;
  gettimeofday(&now, NULL);
  int index = -1;
  for (int i = 0; i< NAPT_TABLE_SIZE; i++) {
    validate_napt_entry(&now, &table[i]);
    if (table[i].used != 1) {
      index = i;
    }
  }

  if (index == -1) {
    return -1;
  }

  gettimeofday(&now, NULL);
  struct napt_table_entry *entry = &table[index];
  entry->used = 1;
  entry->client_addr = client_addr;
  entry->client_port = client_port;
  entry->external_port = external_port;
  entry->last_time = now;
  return index;
}

int create_napt_tcp(uint32_t client_addr, uint16_t client_port, uint32_t external_addr, uint16_t external_port)
{
  return _create_napt_entry(napt_table_tcp, client_addr, client_port, external_addr, external_port);
}

int create_napt_udp(uint32_t client_addr, uint16_t client_port, uint32_t external_addr, uint16_t external_port)
{
  return _create_napt_entry(napt_table_udp, client_addr, client_port, external_addr, external_port);
}

int _lookup_napt_entry(struct napt_table_entry *table, enum packet_direction direction, uint32_t addr, uint16_t port)
{
  struct timeval now;
  gettimeofday(&now, NULL);
  for (int i = 0; i < NAPT_TABLE_SIZE; i++) {
    struct napt_table_entry *entry = &table[i];
    validate_napt_entry(&now, entry);
    if (entry->used == 0) {
      return -1;
    }
    if (direction == DIRECTION_INCOMING) {
      if (port == entry->external_port) {
        /* someAddr:somePort --> eAddr:ePort*/
        return i;
      }
    } else {
      if (addr == entry->client_addr &&
          port == entry->client_port) {
        /* iAddr:iPort --> someAddr:somePort */
        return i;
      }
    }
  }

  return -1;
}

int lookup_napt_tcp(enum packet_direction direction, uint32_t addr, uint16_t port)
{
  return _lookup_napt_entry(napt_table_tcp, direction, addr, port);
}

int lookup_napt_udp(enum packet_direction direction, uint32_t addr, uint16_t port)
{
  return _lookup_napt_entry(napt_table_udp, direction, addr, port);
}

int do_napt_tcp(enum packet_direction direction, struct ip *iphdr, struct tcphdr *tcphdr)
{
  int entry_index;
  struct napt_table_entry *entry;

  if (direction == DIRECTION_INCOMING) {
    entry_index = lookup_napt_tcp(DIRECTION_INCOMING, iphdr->ip_dst.s_addr, tcphdr->dest);
    if (entry_index == -1) {
      return -1;
    }

    entry = &napt_table_tcp[entry_index];
    iphdr->ip_dst.s_addr = entry->client_addr;
    tcphdr->dest = entry->client_port;

  } else { /* OUTGOING */
    entry_index = lookup_napt_tcp(DIRECTION_OUTGOING, iphdr->ip_src.s_addr, tcphdr->source);
    if (entry_index == -1) {
      entry_index = create_napt_tcp(iphdr->ip_src.s_addr, tcphdr->source, iphdr->ip_dst.s_addr, tcphdr->dest);
      if (entry_index == -1) {
        return -1;
      }
    }

    entry = &napt_table_tcp[entry_index];
    iphdr->ip_src.s_addr = ifs[0].addr.s_addr;
    tcphdr->source = entry->external_port;

  }

  /* TODO: recalculate checksum */

  update_napt_entry(entry);
  return 0;
}

int do_napt_udp(enum packet_direction direction, struct ip *iphdr, struct udphdr *udphdr)
{
  int entry_index;
  struct napt_table_entry *entry;

  if (direction == DIRECTION_INCOMING) {
    entry_index = lookup_napt_udp(DIRECTION_INCOMING, iphdr->ip_dst.s_addr, udphdr->dest);
    if (entry_index == -1) {
      return -1;
    }

    entry = &napt_table_udp[entry_index];
    iphdr->ip_dst.s_addr = entry->client_addr;
    udphdr->dest = entry->client_port;

  } else { /* OUTGOING */
    entry_index = lookup_napt_udp(DIRECTION_OUTGOING, iphdr->ip_src.s_addr, udphdr->source);
    if (entry_index == -1) {
      entry_index = create_napt_udp(iphdr->ip_src.s_addr, udphdr->source, iphdr->ip_dst.s_addr, udphdr->dest);
      if (entry_index == -1) {
        return -1;
      }
    }

    entry = &napt_table_udp[entry_index];
    iphdr->ip_src.s_addr = ifs[0].addr.s_addr;
    udphdr->source = entry->external_port;

  }

  /* TODO: recalculate checksum */
  udphdr->check = 0x0000;

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
      do_napt_tcp(DIRECTION_INCOMING, iphdr, (struct tcphdr *)ipdata);
    } else if (iphdr->ip_p == IPPROTO_UDP) {
      do_napt_udp(DIRECTION_INCOMING, iphdr, (struct udphdr *)ipdata);
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
      do_napt_tcp(DIRECTION_OUTGOING, iphdr, (struct tcphdr *)ipdata);
    } else if (iphdr->ip_p == IPPROTO_UDP) {
      do_napt_udp(DIRECTION_OUTGOING, iphdr, (struct udphdr *)ipdata);
    }

  }

  return 0;
}
