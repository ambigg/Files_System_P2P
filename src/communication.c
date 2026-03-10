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

static void fill_addr(struct sockaddr_in *a, const char *ip, int port) {
  memset(a, 0, sizeof(*a));
  a->sin_family = AF_INET;
  a->sin_port = htons(port);
  inet_pton(AF_INET, ip, &a->sin_addr);
}

static int udp_fd(int timeout_sec) {
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

/* Send datagram and wait for reply on the SAME ephemeral socket */
int comm_send_recv(const char *ip, int port, const char *msg, char *resp,
                   int resp_len) {
  int fd = udp_fd(CONN_TIMEOUT);
  if (fd < 0)
    return P2P_ERR;

  struct sockaddr_in dst;
  fill_addr(&dst, ip, port);

  int mlen = strlen(msg);
  if (sendto(fd, msg, mlen, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
    LOG_W("COMM", "sendto %s:%d: %s", ip, port, strerror(errno));
    close(fd);
    return P2P_ERR;
  }

  struct sockaddr_in src;
  socklen_t slen = sizeof(src);
  int n = recvfrom(fd, resp, resp_len - 1, 0, (struct sockaddr *)&src, &slen);
  close(fd);

  if (n <= 0) {
    LOG_W("COMM", "no reply from %s:%d", ip, port);
    return P2P_TIMEOUT;
  }
  resp[n] = '\0';
  return P2P_OK;
}

/* Fire-and-forget */
int comm_send(const char *ip, int port, const char *msg) {
  int fd = udp_fd(CONN_TIMEOUT);
  if (fd < 0)
    return P2P_ERR;
  struct sockaddr_in dst;
  fill_addr(&dst, ip, port);
  int sent =
      sendto(fd, msg, strlen(msg), 0, (struct sockaddr *)&dst, sizeof(dst));
  close(fd);
  return (sent < 0) ? P2P_ERR : P2P_OK;
}

/* Bind UDP server socket */
int comm_start_server(int port) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    LOG_E("COMM", "socket: %s", strerror(errno));
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
    LOG_E("COMM", "bind %d: %s", port, strerror(errno));
    close(fd);
    return -1;
  }

  /* 1s timeout so the loop can check g_node.running */
  struct timeval tv = {1, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  LOG_I("COMM", "UDP server on port %d", port);
  return fd;
}

/* Receive datagram, return sender ip+port */
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

/* Reply to the exact ephemeral port the request came from */
int comm_reply(int fd, const char *data, int len, const char *ip, int port) {
  struct sockaddr_in dst;
  fill_addr(&dst, ip, port);
  int s = sendto(fd, data, len, 0, (struct sockaddr *)&dst, sizeof(dst));
  return (s < 0) ? P2P_ERR : P2P_OK;
}

int comm_broadcast(const char *msg) {
  int n = 0;
  for (int i = 0; i < g_node.peer_count; i++)
    if (g_node.peers[i].reachable &&
        comm_send(g_node.peers[i].ip, g_node.peers[i].port, msg) == P2P_OK)
      n++;
  return n;
}

void comm_close(int fd) {
  if (fd >= 0)
    close(fd);
}
