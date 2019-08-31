// ETHERMTUは<net/ethernet.h>で#define ETHERMTU ETH_DATA_LENと定義されている
// ETH_DATA_LENは<linux/if_ether.hに#define ETH_DATA_LEN 1500と定義されている

#define    DEFAULT_MTU    (ETHERMTU)
#define    DEFAULT_IP_TTL    (64)
#define    DEFAULT_MSS    (DEFAULT_MTU - sizeof(struct ip) - sizeof(struct tcphdr))
#define    DEFAULT_PING_SIZE    (64)

#define    DUMMY_WAIT_MS    (100)
#define    RETRY_COUNT    (3)
#define    TCP_INIT_WINDOW    (1460)
#define    TCP_FIN_TIMEOUT    (3)

typedef struct {
  int  DebugOut;
  char  *devices[16];
  u_int8_t  mymac[6];
  struct in_addr  myip;
  int  IpTTL;
  int  MTU;
  int  MSS;
  struct in_addr  gateway;
  u_int32_t  DhcpRequestLeaseTime;
  u_int32_t  DhcpLeaseTime;
  time_t  DhcpStartTime;
  struct in_addr  DhcpServer;
} PARAM;

int SetDefaultParam();
int my_ether_aton(char *str, u_int8_t *mac);
int ReadParam(char *fname);

