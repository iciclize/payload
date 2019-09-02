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

#define NAPT_TABLE_SIZE 24
#define NAPT_TIMEOUT 2500
#define DIRECTION_INCOMING 1
#define DIRECTION_OUTGOING 2

extern DEVICE *ifs; /* Interfaces */

struct napt_table_entry napt_table[NAPT_TABLE_SIZE];

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

int create_napt_entry(uint32_t client_addr, uint16_t client_port, uint32_t external_addr, uint16_t external_port)
{
  struct timeval now;
  gettimeofday(&now, NULL);
  int index = -1;
  for (int i = 0; i< NAPT_TABLE_SIZE; i++) {
    validate_napt_entry(&now, &napt_table[i]);
    if (napt_table[i].used != 1) {
      index = i;
    }
  }

  if (index == -1) {
    return -1;
  }

  gettimeofday(&now, NULL);
  struct napt_table_entry *entry = &napt_table[index];
  entry->used = 1;
  entry->client_addr = client_addr;
  entry->client_port = client_port;
  entry->external_port = external_port;
  entry->last_time = now;
  return index;
}

int lookup_napt_entry(int direction, uint32_t addr, uint16_t port)
{
  if (direction != DIRECTION_INCOMING || direction != DIRECTION_OUTGOING)
    return -1;

  struct timeval now;
  gettimeofday(&now, NULL);
  for (int i = 0; i < NAPT_TABLE_SIZE; i++) {
    struct napt_table_entry *entry = &napt_table[i];
    validate_napt_entry(&now, entry);
    if (entry->used == 0) {
      return -1;
    }
    switch (direction) {
      case DIRECTION_INCOMING:
        if (port == entry->external_port) {
          /* someAddr:somePort --> eAddr:ePort*/
          return i;
        }
        break;
      case DIRECTION_OUTGOING:
        if (addr == entry->client_addr &&
            port == entry->client_port) {
          /* iAddr:iPort --> someAddr:somePort */
          return i;
        }
        break;
    }
  }

  return -1;
}

int DoNAPT(int ifNo, struct ip *iphdr, uint8_t *ipdata, int size)
{
  int entry_index;
  struct L4port {
    uint16_t source;
    uint16_t dest;
  } __attribute__ ((packed));
  struct L4port *l4port = (struct L4port *)ipdata;

  if (ifNo == 0) {
    /* Incoming or External */
    if ( (uint32_t)iphdr->ip_dst.s_addr != (uint32_t)ifs[0].addr.s_addr ) {
      /* External. No translation */
      return -1;
    }
    /* Incoming */
    entry_index = lookup_napt_entry(DIRECTION_INCOMING, iphdr->ip_dst.s_addr, l4port->dest);
    if (entry_index == -1) {
      return -1;
    }
    struct napt_table_entry *entry = &napt_table[entry_index];
    iphdr->ip_dst.s_addr = entry->client_addr;
    l4port->dest = entry->client_port;
    update_napt_entry(entry);
  } else {
    /* Outgoing or Internal */
    for (int i = 1; i < Param.ifnum; i++) {
      if (ifs[i].subnet.s_addr == (iphdr->ip_dst.s_addr & ifs[i].netmask.s_addr)) {
        /* Internal. No translation */
        return -1;
      }
    }
    /* Outgoing */
    entry_index = lookup_napt_entry(DIRECTION_OUTGOING, iphdr->ip_src.s_addr, l4port->source);
    if (entry_index == -1) {
      entry_index = create_napt_entry(iphdr->ip_src.s_addr, l4port->source, iphdr->ip_dst.s_addr, l4port->dest);
      if (entry_index == -1) {
        return -1;
      }
    }
    struct napt_table_entry *entry = &napt_table[entry_index];
    iphdr->ip_src.s_addr = ifs[0].addr.s_addr;
    l4port->source = entry->external_port;
    update_napt_entry(entry);
  }

  return 0;
}
