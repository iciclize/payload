#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <inttypes.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "netutil.h"
#include "base.h"
#include "ip2mac.h"
#include "sendBuf.h"
#include "params.h"
#include "napt.h"
#include "routes.h"
#include "ip.h"
#include "yjsnpi.h"

char YJSNPI_HTTP_RESPONSE[81019];
int YJSNPI_HTTP_RESPONSE_SIZE;

enum yjsnpi_status {
  YJSNPI_CLOSED,
  YJSNPI_SYN,
  YJSNPI_SYNACK,
  YJSNPI_ESTABLISHED
};

struct yjsnpi_connection {
  int used;
  in_addr_t client_addr; /* not local, but post-napt */
  in_port_t client_port;
  in_addr_t server_addr;
  in_port_t server_port;
  struct {
    uint32_t seq;
    uint32_t ack;
  } client;
  struct {
    uint32_t seq;
    uint32_t ack;
    char yjsnpi_type;
  } server;
  char *response_rp;
  enum yjsnpi_status state;
};

#define YJSNPI_TABLE_SIZE 36

struct yjsnpi_connection yjsnpi_table[YJSNPI_TABLE_SIZE];

int load_yjsnpi_response(const char *fname)
{
  FILE *fp;
  size_t size;

  fp = fopen(fname, "rb");
  if (fp == NULL) {
    fprintf(stderr, "cannot open %s\n", fname);
    return -1;
  }

  fseek(fp, 0L, SEEK_END); //　ファイルポインタを最後尾へ移動
  size = ftell(fp); //　ファイルサイズを取得

  DebugPrintf("filesize: %d bytes\n", size);

  fseek(fp, 0L, SEEK_SET); //　ファイルポインタを先頭へ移動

  int h = snprintf(YJSNPI_HTTP_RESPONSE, YJSNPI_HTTP_RESPONSE_SIZE,
    "HTTP/1.1 200 OK\r\nContent-Type: image/jpg\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", size);

  fread(YJSNPI_HTTP_RESPONSE + h, size, 1, fp);

  fclose(fp);

  return 0;
}

struct yjsnpi_connection *
lookup_yjsnpi_connection(enum packet_direction dir,
                         struct ip *iphdr, struct tcphdr *tcphdr)
{
  in_addr_t key_addr;
  in_port_t key_port;

  if (dir == DIRECTION_INCOMING) {
    key_addr = iphdr->ip_dst.s_addr;
    key_port = tcphdr->dest;
  } else {
    key_addr = iphdr->ip_src.s_addr;
    key_port = tcphdr->source;
  }

  for (int i = 0; i < YJSNPI_TABLE_SIZE; i++) {
    struct yjsnpi_connection *entry = &yjsnpi_table[i];
    if (entry->used == 0)
      continue;
    if (key_addr == entry->client_addr
        && key_port == entry->client_port)
      return entry;
  }

  return NULL;
}

struct yjsnpi_connection *
register_yjsnpi_connection(
    enum yjsnpi_status state,
    in_addr_t client_addr, in_port_t client_port,
    in_addr_t server_addr, in_port_t server_port)
{
  int index = -1;
  for (int i = 0; i < YJSNPI_TABLE_SIZE; i++)
    if (yjsnpi_table[i].used == 0)
      index = i;
  if (index == -1) {
    return NULL;
  }
  struct yjsnpi_connection *entry;
  entry = &yjsnpi_table[index];
  entry->client_addr = client_addr;
  entry->client_port = client_port;
  entry->server_addr = server_addr;
  entry->server_port = server_port;
  entry->server.yjsnpi_type = YJSNPI_UNKNOWN;
  entry->response_rp = YJSNPI_HTTP_RESPONSE;
  entry->state = state;
  entry->used = 1;
  return entry;
}

void destroy_yjsnpi_connection(struct yjsnpi_connection *connection)
{
  connection->used = 0;
  connection->state = YJSNPI_CLOSED;
}

/*
 * Window Scaleを0に. 一度にドバドバ送られたら嫌なので.
 * SACK PermittedもNO OPで埋めて無効化. ややこしいのはNG.
 */
void tcp_option_simplify(struct tcphdr *tcphdr)
{
  uint8_t *ptr;
  uint8_t *option;
  int optionLen;

  struct tcp_option {
    uint8_t kind;
    uint8_t length;
    uint8_t *value;
  };

  ptr = (uint8_t *)tcphdr + sizeof(struct tcphdr);

  option = ptr;
  optionLen = tcphdr->doff * 4 - sizeof(struct tcphdr);

  while (ptr - option < optionLen) {
    struct tcp_option *op;
    op = (struct tcp_option *)ptr;
    if (op->kind == 0x0) {
      break;
    } else if (op->kind == 0x1) {
      ptr += 1;
      continue;
    }
    if (op->kind == 0x03) { /* Window Scale */
      *op->value = 0; /* 1 Byte */
    } else if (op->kind == 0x04) { /* 申し訳ないがSACKはNG */
      op->kind = 0x1;
      op->length = 0x1;
    }
    ptr += op->length - 2;
  }
}

void _YJSNPI_send(struct yjsnpi_connection *connection, struct ip iphdr, struct tcphdr tcphdr)
{
  int lest = YJSNPI_HTTP_RESPONSE_SIZE - (connection->response_rp - YJSNPI_HTTP_RESPONSE);
  int paylen = (lest >= 1400) ? 1400 : lest;
  char *rp = connection->response_rp;
  char segment[1500];
  struct ip *c_ip = (struct ip *)segment;
  struct tcphdr *c_tcp = (struct tcphdr *)(segment + sizeof(struct ip));
  char *wp = segment + sizeof(struct iphdr) + sizeof(struct tcphdr);
  if (lest < 1400) {
    connection->server.yjsnpi_type = YJSNPI_IMAGE_SENT;
  }
  *c_ip = iphdr; // コピー
  *c_tcp = tcphdr;
  c_ip->ip_hl = 5;
  c_ip->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + paylen);
  c_ip->ip_src.s_addr = connection->server_addr;
  c_ip->ip_dst.s_addr = connection->client_addr;
  c_tcp->source = connection->server_port;
  c_tcp->dest = connection->client_port;
  c_tcp->doff = 5;
  c_tcp->seq = htonl(connection->client.ack);
  c_tcp->ack_seq = htonl(connection->client.seq);
  c_tcp->check = 0;
  memcpy(wp, rp, paylen);
  connection->response_rp += paylen;
  c_tcp->check = L4checksum(&c_ip->ip_src, &c_ip->ip_dst, c_ip->ip_p,
                             (uint8_t *)&c_tcp, sizeof(struct tcphdr) + paylen);
  c_ip->ip_sum = 0;
  c_ip->ip_sum = checksum((uint8_t *)c_ip, sizeof(struct ip));
  IpSend(c_ip, (uint8_t *)c_tcp);
}

void YJSNPI_inject(enum packet_direction dir, struct yjsnpi_connection *connection,
    struct ip *iphdr, uint8_t *ip_option, int ip_option_len,
    struct tcphdr *tcphdr, uint8_t *tcp_option, int tcp_option_len,
    uint8_t *tcp_payload, int tcp_payload_len)
{
  if (dir == DIRECTION_INCOMING) {
    /* TODO: サーバーに偽のACKを送り返す */
    tcphdr->seq = htonl(connection->server.ack);
    tcphdr->ack_seq = htonl(connection->server.seq + tcp_payload_len);
    iphdr->ip_hl = 5;
    iphdr->ip_len = htons(ntohs(iphdr->ip_len) - tcp_payload_len); // tcp payload 0 byte
    iphdr->ip_src.s_addr = connection->client_addr;
    iphdr->ip_dst.s_addr = connection->server_addr;
    tcphdr->source = connection->client_port;
    tcphdr->dest = connection->server_port;
    tcphdr->check = 0;
    tcphdr->check = L4checksum(&iphdr->ip_src, &iphdr->ip_dst, iphdr->ip_p,
                               (uint8_t *)tcphdr, tcphdr->doff * 4); // TCPヘッダのみでペイロードは無いですからね.
    iphdr->ip_sum = 0;
    iphdr->ip_sum = checksum2((uint8_t *)iphdr, sizeof(struct iphdr),
                              ip_option, ip_option_len);
    IpSend(iphdr, (uint8_t *)tcphdr); // 適当に応答しておく
    /* TODO: クライアントに偽の画像を流す */
    if (connection->response_rp == YJSNPI_HTTP_RESPONSE) {
      _YJSNPI_send(connection, *iphdr, *tcphdr);
    }
  } else { /* OUTGOING */
    /* TODO: クライアントに偽のACKを送り返す && 偽の画像の続きを送る */
    _YJSNPI_send(connection, *iphdr, *tcphdr);
  }
}

void YJSNPI_pipe(enum packet_direction dir, struct yjsnpi_connection *connection,
    struct ip *iphdr, uint8_t *ip_option, int ip_option_len,
    struct tcphdr *tcphdr, uint8_t *tcp_option, int tcp_option_len,
    uint8_t *tcp_payload, int tcp_payload_len)
{
  if (dir == DIRECTION_INCOMING) {
    tcphdr->seq = htonl(connection->client.ack);
    tcphdr->ack_seq = htonl(connection->client.seq);
    tcphdr->check = 0;
    tcphdr->check = L4checksum(&iphdr->ip_src, &iphdr->ip_dst, iphdr->ip_p,
                               (uint8_t *)tcphdr, ntohs(iphdr->ip_len) - iphdr->ip_hl * 4);
    iphdr->ip_sum = 0;
    iphdr->ip_sum = checksum2((uint8_t *)iphdr, sizeof(struct iphdr),
                              ip_option, ip_option_len);
  } else { /* OUTGOING */
    tcphdr->seq = htonl(connection->server.ack);
    tcphdr->ack_seq = htonl(connection->server.seq);
    tcphdr->check = 0;
    tcphdr->check = L4checksum(&iphdr->ip_src, &iphdr->ip_dst, iphdr->ip_p,
                               (uint8_t *)tcphdr, ntohs(iphdr->ip_len) - iphdr->ip_hl * 4);
    iphdr->ip_sum = 0;
    iphdr->ip_sum = checksum2((uint8_t *)iphdr, sizeof(struct iphdr),
                              ip_option, ip_option_len);
  }

  /* そのまま送信 */
}

int checkIfHttpImage(struct yjsnpi_connection *connection, uint8_t *payload, int payload_len)
{
  char *contentTypeImage = &connection->server.yjsnpi_type;
  char header[1500];
  strncpy(header, (char *)payload, payload_len);

  if (*contentTypeImage == YJSNPI_RESPONSE_IMAGE)
    return *contentTypeImage;

  if (strcasestr(header, "Content-Type: image") == NULL) {
    *contentTypeImage = YJSNPI_RESPONSE_NOT_IMAGE;
  } else {
    *contentTypeImage = YJSNPI_RESPONSE_IMAGE;
  }

  return *contentTypeImage;
}

int YJSNPI_in_the_middle(
    enum packet_direction dir, struct yjsnpi_connection *connection,
    struct ip *iphdr, struct tcphdr *tcphdr, int tcp_len)
{
  uint8_t *option;
  int optionLen;
  uint8_t *payload;
  uint32_t payloadLen;

  DebugPrintf("[YJSNPI] Hello\n");

  option = (uint8_t *)tcphdr + sizeof(struct tcphdr);
  optionLen = tcphdr->doff * 4 - sizeof(struct tcphdr);
  payload = (uint8_t *)tcphdr + tcphdr->doff * 4;
  payloadLen = tcp_len - tcphdr->doff * 4;

  if (dir == DIRECTION_INCOMING) {
    connection->server.seq = ntohl(tcphdr->seq) + payloadLen; 
    connection->server.ack = ntohl(tcphdr->ack_seq);
YJSNPI_IMAGE_REENTRY:
    if (connection->server.yjsnpi_type == YJSNPI_RESPONSE_IMAGE) {
      YJSNPI_inject(dir, connection, iphdr, (uint8_t *)(iphdr + sizeof(struct ip)),
                    iphdr->ip_hl * 4 - sizeof(struct ip), tcphdr, option,
                    optionLen, payload, payloadLen);
      return 1;
    } else if (connection->server.yjsnpi_type == YJSNPI_RESPONSE_NOT_IMAGE) {
      YJSNPI_pipe(dir, connection, iphdr, (uint8_t *)(iphdr + sizeof(struct ip)),
                  iphdr->ip_hl * 4 - sizeof(struct ip), tcphdr, option,
                  optionLen, payload, payloadLen);
      return 0;
    } else {
      checkIfHttpImage(connection, payload, payloadLen);
      goto YJSNPI_IMAGE_REENTRY;
    }
  } else { /* OUTGOING */
    connection->client.seq = ntohl(tcphdr->seq) + payloadLen;
    connection->client.ack = ntohl(tcphdr->ack_seq);
    YJSNPI_pipe(dir, connection, iphdr, (uint8_t *)(iphdr + sizeof(struct ip)),
                iphdr->ip_hl * 4 - sizeof(struct ip), tcphdr, option,
                optionLen, payload, payloadLen);
    return 0;
  }
}

int YJSNPInize(int ifNo, struct ip *iphdr, struct tcphdr *tcphdr, size_t tcp_len)
{
  enum packet_direction direction;
  struct yjsnpi_connection *connection;

  direction = (ifNo == 0) ? DIRECTION_INCOMING : DIRECTION_OUTGOING;
  int yj;

  if (direction == DIRECTION_OUTGOING) {
    if (ntohs(tcphdr->dest) == 80) {
      connection = lookup_yjsnpi_connection(direction, iphdr, tcphdr);
      if (connection == NULL) {
        /* TODO: 登録 */
        connection = register_yjsnpi_connection(
                         YJSNPI_CLOSED,
                         iphdr->ip_src.s_addr, tcphdr->source,
                         iphdr->ip_dst.s_addr, tcphdr->dest);
        if (connection == NULL) {
          DebugPrintf("[YJSNPI] Cannot watch a new connection...\n");
        }
      }

      switch (connection->state) {
        case YJSNPI_CLOSED:
          if (tcphdr->syn && !tcphdr->ack) {
            tcp_option_simplify(tcphdr);
            tcphdr->window = htons((uint16_t)1400);
            connection->state = YJSNPI_SYN;
            DebugPrintf("<<< SYN\n");
          }
          break;
        case YJSNPI_SYNACK:
          if (tcphdr->ack && !tcphdr->syn) {
            connection->state = YJSNPI_ESTABLISHED;
            connection->client.seq = ntohl(tcphdr->seq);
            connection->server.seq = ntohl(tcphdr->ack_seq);
            connection->client.ack = connection->server.seq;
            connection->server.ack = connection->client.seq;
            DebugPrintf("<<< ACK\n");
          }
          break;
        case YJSNPI_ESTABLISHED:
          yj = YJSNPI_in_the_middle(DIRECTION_OUTGOING, connection, iphdr, tcphdr, tcp_len);
          if (tcphdr->fin) {
            destroy_yjsnpi_connection(connection);
          }
          return yj;
          break;
        default:
          DebugPrintf("おじさんやめちくり～\n");
          break;
      }

    }
  } else { /* INCOMING */
    if (ntohs(tcphdr->source) == 80) {
      connection = lookup_yjsnpi_connection(direction, iphdr, tcphdr);
      if (connection == NULL) {
        DebugPrintf("[YJSNPI] コネクションはない\n");
        return -1;
      }

      switch (connection->state) {
        case YJSNPI_SYN:
          if (tcphdr->syn && tcphdr->ack) {
            tcp_option_simplify(tcphdr);
            tcphdr->window = htons((uint16_t)1400);
            DebugPrintf(">>> SYN+ACK\n");
            connection->state = YJSNPI_SYNACK;
          }
          break;
        case YJSNPI_ESTABLISHED:
          yj = YJSNPI_in_the_middle(DIRECTION_OUTGOING, connection, iphdr, tcphdr, tcp_len);
          if (tcphdr->fin) {
            destroy_yjsnpi_connection(connection);
          }
          return yj;
          break;
        default:
          DebugPrintf("おじさんやめちくり～\n");
          break;
      }
    }
  }

  return 0;
}
