#ifndef YJSNPI_ROUTES_H
#define YJSNPI_ROUTES_H

struct routing_table_entry {
  in_addr_t dest;
  in_addr_t netmask;
  in_addr_t gateway;
  in_addr_t interface;
  in_addr_t subnet;
  int ifNo;
  struct routing_table_entry* next;
};

void init_routing_table(void);
int add_route_entry(in_addr_t dest, in_addr_t netmask, in_addr_t gateway, in_addr_t iface);
struct routing_table_entry *lookup_route_entry(in_addr_t dest);
int load_routes(char *fname);

#endif /* YJSNPI_ROUTES_H */
