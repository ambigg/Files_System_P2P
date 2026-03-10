#include "../include/communication.h"
#include "../include/log.h"
#include "../include/protocol.h"
#include "../include/structures.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* ==========================================================
 * SEND + RECEIVE (UDP)
 * Creates a temporary socket, sends the datagram to ip:port,
 * waits CONN_TIMEOUT seconds for a response, then closes.
 * ========================================================== */
int comm_send_recv(const char *ip, int port, const char *message,
                   char *response, int resp_len) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    LOG_E("COMM", "socket() failed: %s", strerror(errno));
    return P2P_ERR;
  }

  /* Receive timeout */
  struct timeval tv = {CONN_TIMEOUT, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
    LOG_E("COMM", "Invalid IP: %s", ip);
    close(fd);
    return P2P_ERR;
  }

  int msg_len = strlen(message);
  if (sendto(fd, message, msg_len, 0, (struct sockaddr *)&addr, sizeof(addr)) !=
      msg_len) {
    LOG_W("COMM", "sendto() to %s:%d failed: %s", ip, port, strerror(errno));
    close(fd);
    return P2P_ERR;
  }

  struct sockaddr_in from;
  socklen_t from_len = sizeof(from);
  int n = recvfrom(fd, response, resp_len - 1, 0, (struct sockaddr *)&from,
                   &from_len);
  close(fd);

  if (n <= 0) {
    LOG_W("COMM", "No response from %s:%d", ip, port);
    return P2P_TIMEOUT;
  }

  response[n] = '\0';
  LOG_N("COMM", "SEND_RECV %s:%d → %d sent, %d received", ip, port, msg_len, n);
  return P2P_OK;
}

/* ==========================================================
 * SEND ONLY (UDP) — fire and forget
 * ========================================================== */
int comm_send(const char *ip, int port, const char *message) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
    return P2P_ERR;

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, ip, &addr.sin_addr);

  int msg_len = strlen(message);
  int sent =
      sendto(fd, message, msg_len, 0, (struct sockaddr *)&addr, sizeof(addr));
  close(fd);

  if (sent != msg_len) {
    LOG_E("COMM", "sendto() incomplete to %s:%d", ip, port);
    return P2P_ERR;
  }

  LOG_N("COMM", "SEND %s:%d (%d bytes)", ip, port, sent);
  return P2P_OK;
}

/* ==========================================================
 * UDP SERVER — bind and return fd
 * ========================================================== */
int comm_start_server(int port) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    LOG_E("COMM", "server socket() failed: %s", strerror(errno));
    return -1;
  }

  int opt = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  /* 1-second receive timeout so the thread loop can check g_node.running */
  struct timeval tv = {1, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    LOG_E("COMM", "bind() port %d failed: %s", port, strerror(errno));
    close(fd);
    return -1;
  }

  LOG_I("COMM", "UDP server listening on port %d", port);
  return fd;
}

/* ==========================================================
 * RECEIVE DATAGRAM on server socket
 * Returns bytes received, -1 on error / timeout.
 * ========================================================== */
int comm_recv(int server_fd, char *buffer, int max_len, char *sender_ip,
              int *sender_port) {
  struct sockaddr_in from;
  socklen_t from_len = sizeof(from);

  int n = recvfrom(server_fd, buffer, max_len - 1, 0, (struct sockaddr *)&from,
                   &from_len);
  if (n <= 0)
    return n;

  buffer[n] = '\0';

  if (sender_ip)
    inet_ntop(AF_INET, &from.sin_addr, sender_ip, MAX_IP_LEN);
  if (sender_port)
    *sender_port = ntohs(from.sin_port);

  return n;
}

/* ==========================================================
 * SEND RESPONSE back to a client using the server socket
 * ========================================================== */
int comm_send_to(int server_fd, const char *data, int len, const char *ip,
                 int port) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, ip, &addr.sin_addr);

  int sent =
      sendto(server_fd, data, len, 0, (struct sockaddr *)&addr, sizeof(addr));
  if (sent != len) {
    LOG_E("COMM", "comm_send_to: sent %d of %d to %s:%d", sent, len, ip, port);
    return P2P_ERR;
  }
  return P2P_OK;
}

/* ==========================================================
 * CLOSE
 * ========================================================== */
void comm_close(int fd) {
  if (fd >= 0)
    close(fd);
}

/* ==========================================================
 * BROADCAST to all known peers
 * ========================================================== */
int comm_broadcast(const char *message) {
  int sent_count = 0;
  for (int i = 0; i < g_node.peer_count; i++) {
    if (comm_send(g_node.peers[i].ip, g_node.peers[i].port, message) == P2P_OK)
      sent_count++;
  }
  LOG_N("COMM", "BROADCAST: %d/%d peers", sent_count, g_node.peer_count);
  return sent_count;
}
// AAGG
// 202127378
