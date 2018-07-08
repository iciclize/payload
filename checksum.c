#include <netinet/ip.h>

#include "checksum.h"

int checkIPchecksum(struct iphdr *iphdr, u_char *option, int optionLen)
{
  return 0;
}

int checkIPDATAchecksum(struct iphdr *iphdr, unsigned char *data, int len)
{
  return 0;
}
