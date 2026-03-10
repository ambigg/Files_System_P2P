#include "../include/communication.h"
#include "../include/log.h"
#include "../include/protocol.h"
#include "../include/structures.h"
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* ── helpers ── */
static void fill_addr(struct sockaddr_in *a, const char *ip, int port) {
  memset(a, 0, sizeof(*a));
  a->sin_family = AF_INET;
  a->sin_port = htons(port);
  inet_pton(AF_INET, ip, &a->sin_addr);
}

static int udp_sock(int timeout_sec) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
    return -1;
  if (timeout_sec > 0) {
    struct timeval tv = {timeout_sec, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  }
  return fd;
}

/* ── public API ── */

/*
 * Send datagram and wait for response on the SAME socket.
 * The server sees our ephemeral port via recvfrom and replies to it.
 */
int comm_send_recv(const char *ip, int port, const char *msg, char *resp,
                   int resp_len) {
  int fd = udp_sock(CONN_TIMEOUT);
  if (fd < 0)
    return P2P_ERR;

  struct sockaddr_in dst;
  fill_addr(&dst, ip, port);

  int mlen = strlen(msg);
  if (sendto(fd, msg, mlen, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
    LOG_W("COMM", "sendto %s:%d failed: %s", ip, port, strerror(errno));
    close(fd);
    return P2P_ERR;
  }

  struct sockaddr_in src;
  socklen_t slen = sizeof(src);
  int n = recvfrom(fd, resp, resp_len - 1, 0, (struct sockaddr *)&src, &slen);
  close(fd);

  if (n <= 0) {
    LOG_W("COMM", "no response from %s:%d", ip, port);
    return P2P_TIMEOUT;
  }
  resp[n] = '\0';
  LOG_N("COMM", "SEND_RECV %s:%d sent=%d recv=%d", ip, port, mlen, n);
  return P2P_OK;
}

/* Send without waiting */
int comm_send(const char *ip, int port, const char *msg) {
  int fd = udp_sock(CONN_TIMEOUT);
  if (fd < 0)
    return P2P_ERR;

  struct sockaddr_in dst;
  fill_addr(&dst, ip, port);

  int sent =
      sendto(fd, msg, strlen(msg), 0, (struct sockaddr *)&dst, sizeof(dst));
  close(fd);
  if (sent < 0) {
    LOG_W("COMM", "send to %s:%d failed", ip, port);
    return P2P_ERR;
  }
  LOG_N("COMM", "SEND %s:%d %d bytes", ip, port, sent);
  return P2P_OK;
}

/* UDP server: bind to port, set 1s timeout for non-blocking loop */
int comm_start_server(int port) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    LOG_E("COMM", "socket failed: %s", strerror(errno));
    return -1;
  }

  int opt = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    LOG_E("COMM", "bind port %d failed: %s", port, strerror(errno));
    close(fd);
    return -1;
  }

  struct timeval tv = {1, 0}; /* 1s timeout so loop can check running flag */
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  LOG_I("COMM", "UDP server on port %d", port);
  return fd;
}

/* Receive datagram — returns sender IP and PORT */
int comm_recv_from(int fd, char *buf, int max_len, char *sender_ip,
                   int *sender_port) {
  struct sockaddr_in src;
  socklen_t slen = sizeof(src);
  int n = recvfrom(fd, buf, max_len - 1, 0, (struct sockaddr *)&src, &slen);
  if (n <= 0)
    return n;
  buf[n] = '\0';
  if (sender_ip)
    inet_ntop(AF_INET, &src.sin_addr, sender_ip, MAX_IP_LEN);
  if (sender_port)
    *sender_port = ntohs(src.sin_port);
  return n;
}

/* Reply using server fd back to exact sender (ephemeral) port */
int comm_reply(int fd, const char *data, int len, const char *ip, int port) {
  struct sockaddr_in dst;
  fill_addr(&dst, ip, port);
  int sent = sendto(fd, data, len, 0, (struct sockaddr *)&dst, sizeof(dst));
  if (sent < 0) {
    LOG_W("COMM", "reply to %s:%d failed", ip, port);
    return P2P_ERR;
  }
  return P2P_OK;
}

/* Broadcast to all reachable peers */
int comm_broadcast(const char *msg) {
  int n = 0;
  for (int i = 0; i < g_node.peer_count; i++) {
    if (g_node.peers[i].reachable &&
        comm_send(g_node.peers[i].ip, g_node.peers[i].port, msg) == P2P_OK)
      n++;
  }
  LOG_N("COMM", "BROADCAST %d/%d", n, g_node.peer_count);
  return n;
}

void comm_close(int fd) {
  if (fd >= 0)
    close(fd);
}
