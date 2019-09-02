#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "base.h"
#include "params.h"
#include "routes.h"

extern PARAM Param;
extern DEVICE *ifs;

struct routing_table_entry *routing_table_head;

void init_routing_table(void)
{
  routing_table_head = NULL;
}

int add_route_entry(in_addr_t dest, in_addr_t netmask, in_addr_t gateway, in_addr_t iface)
{
  struct routing_table_entry *entry;
  struct routing_table_entry *last;
  entry = (struct routing_table_entry *)malloc(sizeof(struct routing_table_entry));
  if (entry == NULL) {
    perror("malloc");
    return -1;
  }

  entry->dest = dest;
  entry->netmask = netmask;
  entry->gateway = gateway;
  entry->interface = iface;
  entry->subnet = dest & netmask;
  int ifNo = -1;
  for (int i = 0; i < Param.ifnum; i++)
    if (ifs[i].addr.s_addr == iface)
      ifNo = i;
  entry->ifNo = ifNo;
  entry->next = NULL;

  if (routing_table_head == NULL) {
    routing_table_head = entry;
    return 0;
  }

  last = routing_table_head;
  while (last->next != NULL)
    last = last->next;

  last->next = entry;

  return 0;
}

/*
 *   longest match
 */
struct routing_table_entry *
lookup_route_entry(in_addr_t dest)
{
  struct routing_table_entry *p, *cand = NULL;

  for (p = routing_table_head; p != NULL; p = p->next)
    if ( (dest & p->netmask) == p->subnet )
      if (!cand || ntohl(cand->netmask) < ntohl(p->netmask))
        cand = p;

  return cand;
}

int load_routes(char *fname)
{
  FILE *fp = fopen(fname, "r");
  if (fp == NULL) {
    perror("fopen");
    return -1;
  }

  char line[256];
  char dest_str[16], netmask_str[16], gateway_str[16], iface_str[16];
  while (fgets(line, 256, fp) != NULL) {
    if (*line == '#')
      continue;
    int input = sscanf(line, "%s %s %s %s", dest_str, netmask_str, gateway_str, iface_str);
    if (input != 4)
      continue;
    struct in_addr dest, netmask, gateway, iface;
    inet_aton(dest_str, &dest);
    inet_aton(netmask_str, &netmask);
    inet_aton(gateway_str, &gateway);
    inet_aton(iface_str, &iface);
    add_route_entry(dest.s_addr, netmask.s_addr, gateway.s_addr, iface.s_addr);
  }

  fclose(fp);

  return 0;
}
