#ifndef YJSNPI_CHECKSUM
#define YJSNPI_CHECKSUM

int checkIPchecksum(struct iphdr *iphdr, u_char *option, int optionLen);
int checkIPDATAchecksum(struct iphdr *iphdr, unsigned char *data, int len);

#endif /* YJSNPI_CHECKSUM */
