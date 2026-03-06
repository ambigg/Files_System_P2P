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
 * INTERNAL HELPER: create a UDP socket with timeout
 * ========================================================== */
static int make_udp(int timeout_sec) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    LOG_E("COMM", "socket() failed: %s", strerror(errno));
    return -1;
  }
  if (timeout_sec > 0) {
    struct timeval tv = {timeout_sec, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  }
  return fd;
}

/* ==========================================================
 * SEND + RECEIVE (UDP)
 * Opens a socket, sends datagram, waits for response on the
 * SAME socket (so the server replies to our ephemeral port).
 * ========================================================== */
int comm_send_recv(const char *ip, int port, const char *message,
                   char *response, int resp_len) {
  int fd = make_udp(CONN_TIMEOUT);
  if (fd < 0)
    return P2P_ERR;

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
  if (sendto(fd, message, msg_len, 0, (struct sockaddr *)&addr, sizeof(addr)) <
      0) {
    LOG_W("COMM", "sendto() to %s:%d failed: %s", ip, port, strerror(errno));
    close(fd);
    return P2P_ERR;
  }

  /* Wait for response on the same socket — server replies to our port */
  struct sockaddr_in sender;
  socklen_t sender_len = sizeof(sender);
  int n = recvfrom(fd, response, resp_len - 1, 0, (struct sockaddr *)&sender,
                   &sender_len);
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
 * SEND WITHOUT RESPONSE (UDP)
 * ========================================================== */
int comm_send(const char *ip, int port, const char *message) {
  int fd = make_udp(CONN_TIMEOUT);
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

  if (sent < 0) {
    LOG_E("COMM", "sendto() to %s:%d failed: %s", ip, port, strerror(errno));
    return P2P_ERR;
  }

  LOG_N("COMM", "SEND %s:%d (%d bytes)", ip, port, sent);
  return P2P_OK;
}

/* ==========================================================
 * UDP SERVER — bind to port and return fd
 * ========================================================== */
int comm_start_server(int port) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    LOG_E("COMM", "server socket() failed: %s", strerror(errno));
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
    LOG_E("COMM", "bind() port %d failed: %s", port, strerror(errno));
    close(fd);
    return -1;
  }

  /* 1 second timeout so thread can check g_node.running */
  struct timeval tv = {1, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  LOG_I("COMM", "UDP server listening on port %d", port);
  return fd;
}

/* ==========================================================
 * RECEIVE DATAGRAM — returns bytes read, fills ip AND port
 * ========================================================== */
int comm_recv_from(int fd, char *buffer, int max_len, char *sender_ip,
                   int *sender_port) {
  struct sockaddr_in sender;
  socklen_t sender_len = sizeof(sender);

  int n = recvfrom(fd, buffer, max_len - 1, 0, (struct sockaddr *)&sender,
                   &sender_len);
  if (n <= 0)
    return n;

  buffer[n] = '\0';
  if (sender_ip)
    inet_ntop(AF_INET, &sender.sin_addr, sender_ip, MAX_IP_LEN);
  if (sender_port)
    *sender_port = ntohs(sender.sin_port);

  return n;
}

/* ==========================================================
 * SEND RESPONSE using existing server fd back to sender
 * This is the KEY fix: reply to the exact port the request
 * came from (the client's ephemeral port), not P2P_PORT.
 * ========================================================== */
int comm_send_to(int fd, const char *data, int len, const char *ip, int port) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, ip, &addr.sin_addr);

  int sent = sendto(fd, data, len, 0, (struct sockaddr *)&addr, sizeof(addr));
  if (sent < 0) {
    LOG_E("COMM", "comm_send_to %s:%d failed: %s", ip, port, strerror(errno));
    return P2P_ERR;
  }
  return P2P_OK;
}

/* ==========================================================
 * KEPT FOR COMPATIBILITY — no-op in UDP mode
 * ========================================================== */
int comm_send_fd(int fd, const char *data, int len) {
  (void)fd;
  (void)data;
  (void)len;
  return P2P_OK;
}

void comm_close(int fd) {
  if (fd >= 0)
    close(fd);
}

/* ==========================================================
 * BROADCAST TO ALL KNOWN PEERS
 * ========================================================== */
int comm_broadcast(const char *message) {
  int sent_count = 0;
  for (int i = 0; i < g_node.peer_count; i++) {
    if (!g_node.peers[i].reachable)
      continue;
    if (comm_send(g_node.peers[i].ip, g_node.peers[i].port, message) == P2P_OK)
      sent_count++;
  }
  LOG_N("COMM", "BROADCAST: %d/%d peers reached", sent_count,
        g_node.peer_count);
  return sent_count;
}

/* ==========================================================
 * PING
 * ========================================================== */
int comm_ping(const char *ip, int port) {
  int fd = make_udp(2);
  if (fd < 0)
    return 0;

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, ip, &addr.sin_addr);

  const char *probe = "PING\n";
  sendto(fd, probe, strlen(probe), 0, (struct sockaddr *)&addr, sizeof(addr));

  char buf[16];
  struct sockaddr_in sender;
  socklen_t slen = sizeof(sender);
  int alive = (recvfrom(fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&sender,
                        &slen) > 0);
  close(fd);

  LOG_N("COMM", "PING %s:%d → %s", ip, port, alive ? "online" : "offline");
  return alive;
}
