#ifndef YJSNPI_PRINT
#define YJSNPI_PRINT

#include <stdio.h>

char *ip_ip2str(u_int32_t ip, char *buf, socklen_t size);
int PrintIpHeader(struct iphdr *iphdr, u_char *option, int optionLen, FILE *fp);
int PrintTcp(struct tcphdr *tcphdr, FILE *fp);
int PrintUdp(struct udphdr *udphdr, FILE *fp);

#endif /* YJSNPI_PRINT */
