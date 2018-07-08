#ifndef YJSNPI_LTEST
#define YJSNPI_LTEST

int InitRawSocket(char *device, int promiscFlag, int ipOnly);
char *my_ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size);
int PrintEtherHeader(struct ether_header *eh, FILE *fp);

#endif /* YJSNPI_LTEST */
