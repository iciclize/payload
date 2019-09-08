#ifndef YJSNPI_IP_H
#define YJSNPI_IP_H

int SendIcmpTimeExceeded(int ifNo, struct ether_header *eh, struct iphdr *iphdr, u_char *data, int size);
int EtherIpSend(int ifNo, struct ether_header *eh, struct ip *iphdr,
                uint8_t *ip_option, int ip_option_len,
                uint8_t *ip_payload, int frame_size);
int IpRecv(int ifNo, struct ether_header *eh, u_char *data, int frame_size);
int IpSend(struct ip *iphdr, uint8_t *ip_data);

#endif /* YJSNPI_IP_H */
