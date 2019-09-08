#ifndef YJSNPI_NAPT_H
#define YJSNPI_NAPT_H

struct napt_table_entry {
  int used;
  uint8_t protocol;
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

#define NAPT_TABLE_SIZE 36
#define NAPT_TIMEOUT 3000

uint16_t lookup_free_port(struct napt_table_entry *table);
int validate_napt_entry(struct timeval *now, struct napt_table_entry *entry);
void update_napt_entry(struct napt_table_entry *entry);
struct napt_table_entry* _create_napt_entry(struct napt_table_entry *table, uint32_t client_addr, uint16_t client_port);
struct napt_table_entry* create_napt_tcp(uint32_t client_addr, uint16_t client_port);
struct napt_table_entry* _lookup_napt_entry(struct napt_table_entry *table, enum packet_direction direction, uint32_t addr, uint16_t port);
struct napt_table_entry* lookup_napt_tcp(enum packet_direction direction, uint32_t addr, uint16_t port);
struct napt_table_entry* lookup_napt_udp(enum packet_direction direction, uint32_t addr, uint16_t port);
int do_napt_tcp(enum packet_direction direction, struct ip *iphdr, struct tcphdr *tcphdr, int dlen);
int do_napt_udp(enum packet_direction direction, struct ip *iphdr, struct udphdr *udphdr, int dlen);
int DoNAPT(int ifNo, struct ip *iphdr, uint8_t *ipdata, int size);

#endif /* YJSNPI_NAPT_H */
