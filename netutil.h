#ifndef YJSNPI_NETUTIL_H
#define YJSNPI_NETUTIL_H

char *my_ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size);
char *my_inet_ntoa_r(struct in_addr *addr, char *buf, socklen_t size);
char *in_addr_t2str(in_addr_t addr, char *buf, socklen_t size);
char *ip_ip2str(u_int32_t ip, char *buf, socklen_t size);
int GetDeviceNames(char (*ifnames)[16], int *ifrn);
int GetDeviceInfo(char *device, u_char hwaddr[6], struct in_addr *uaddr, struct in_addr *subnet, struct in_addr *mask);
int print_hex(u_int8_t *data, int size);
int PrintEtherHeader(struct ether_header *eh, FILE *fp);
int PrintIpHeader(struct iphdr *iphdr, u_char *option, int optionLen, FILE *fp);
int print_tcp(struct tcphdr *tcp);
int print_udp(struct udphdr *udp);
int InitRawSocket(char *device, int promiscFlag, int ipOnly);
u_int16_t checksum(u_char *data, int len);
u_int16_t checksum2(u_char *data1, int len1, u_char *data2, int len2);
int checkIPchecksum(struct iphdr *iphdr, u_char *option, int optionLen);
int SendArpRequestB(int sock, in_addr_t target_ip, u_char target_mac[6], in_addr_t my_ip, u_char my_mac[6]);

#endif /* YJSNPI_NETUTIL_H */
