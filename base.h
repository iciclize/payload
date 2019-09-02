#ifndef BASE_H
#define BASE_H

typedef struct {
  int             sock;
  char            name[32];
  u_char          hwaddr[6];
  struct in_addr  addr, subnet, netmask;
} DEVICE;

#define FLAG_FREE 0
#define FLAG_OK   1
#define FLAG_NG  -1

typedef struct _data_buf_ {
  struct _data_buf_  *next;
  struct _data_buf_  *before;
  time_t              t;
  int                 size;
  unsigned char       *data;
} DATA_BUF;

typedef struct {
  DATA_BUF       *top;
  DATA_BUF       *bottom;
  unsigned long   dno;
  unsigned long   inBucketSize;
  pthread_mutex_t mutex;
} SEND_DATA;

typedef struct {
  int           flag;
  int           ifNo;
  in_addr_t     addr;
  unsigned char hwaddr[6];
  time_t        lastTime;
  SEND_DATA     sd;
} IP2MAC;

struct pseudo_ip {
  struct in_addr ip_src;
  struct in_addr ip_dst;
  uint8_t dummy;
  uint8_t ip_p;
  uint8_t ip_len;
};

#endif /* BASE_H */
