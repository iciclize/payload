#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

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
};

#define NAPT_TABLE_SIZE 24

extern DEVICE *ifs; /* Interfaces */
extern int ifnum;

struct napt_table_entry napt_table[NAPT_TABLE_SIZE];

int create_napt_entry(int direction, uint32_t addr, uint16_t port)
{
  for (int i = 0; i< NAPT_TABLE_SIZE; i++) {
    if (napt_table[i].used != 1) {
      napt_table[i].used = 1;
      return i;
    }
  }
  return -1;
}

#define DIRECTION_INCOMING 1
#define DIRECTION_OUTGOING 2

int lookup_napt_entry(int direction, uint32_t addr, uint16_t port)
{
  if (direction != DIRECTION_INCOMING || direction != DIRECTION_OUTGOING)
    return -1;

  for (int i = 0; i < NAPT_TABLE_SIZE; i++) {
    struct napt_table_entry *entry = &napt_table[i];
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
  struct tcphdr *tcphdr = (struct tcphdr *)ipdata;

  if (ifNo == 0) {
    /* Incoming or External */
    if ( (uint32_t)iphdr->ip_dst.s_addr != (uint32_t)ifs[0].addr.s_addr ) {
      /* External. No translation */
      return -1;
    }
    /* Incoming */
    entry_index = lookup_napt_entry(DIRECTION_INCOMING, iphdr->ip_dst.s_addr, tcphdr->dest);
  } else {
    /* Outgoing or Internal */
    for (int i = 1; i < ifnum; i++) {
      if (ifs[i].subnet.s_addr == ( iphdr->ip_dst.s_addr & ifs[i].netmask.s_addr)) {
        /* Internal. No translation */
        return -1;
      }
    }
    /* Outgoing */
  }
  entry_index = lookup_napt_entry(DIRECTION_OUTGOING, iphdr->ip_src.s_addr, tcphdr->source);

  if (entry_index == -1) {
    entry_index = create_napt_entry(dir, key_addr, key_port);
    if (entry_index == -1) {
      return -1;
    }
  }
}
