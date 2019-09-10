#ifndef YJSNPI_YJSNPI_H
#define YJSNPI_YJSNPI_H

#define YJSNPI_RESPONSE_IMAGE  1
#define YJSNPI_RESPONSE_NOT_IMAGE 2
#define YJSNPI_IMAGE_SENT 24
#define YJSNPI_UNKNOWN 19

#define YJSNPI_TIMEOUT 10000

int load_yjsnpi_response(const char *fname);
int YJSNPInize(int ifNo, struct ip *iphdr, struct tcphdr *tcphdr, size_t tcp_len);

#endif /* YJSNPI_YJSNPI_H */
