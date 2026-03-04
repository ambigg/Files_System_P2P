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
 * INTERNAL HELPER: set read/write timeout on socket
 * to avoid blocking indefinitely.
 * ========================================================== */
static void set_timeout(int fd, int seconds) {
  struct timeval tv;
  tv.tv_sec = seconds;
  tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* ==========================================================
 * INTERNAL HELPER: create a TCP socket and connect to ip:port.
 * Returns connected fd, -1 on error.
 * ========================================================== */
static int connect_to(const char *ip, int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    LOG_E("COMM", "socket() failed: %s", strerror(errno));
    return -1;
  }

  set_timeout(fd, CONN_TIMEOUT);

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

  if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
    LOG_E("COMM", "Invalid IP: %s", ip);
    close(fd);
    return -1;
  }

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    LOG_W("COMM", "connect() to %s:%d failed: %s", ip, port, strerror(errno));
    close(fd);
    return -1;
  }

  return fd;
}

/* ==========================================================
 * SEND + RECEIVE
 * Most exchanges follow this pattern:
 * I send something → the other replies → I close the connection.
 * ========================================================== */
int comm_send_recv(const char *ip, int port, const char *message,
                   char *response, int resp_len) {
  int fd = connect_to(ip, port);
  if (fd < 0)
    return P2P_ERR;

  int msg_len = strlen(message);
  if (send(fd, message, msg_len, 0) != msg_len) {
    LOG_E("COMM", "incomplete send() to %s:%d", ip, port);
    close(fd);
    return P2P_ERR;
  }

  int n = comm_recv(fd, response, resp_len);
  close(fd);

  if (n <= 0) {
    LOG_W("COMM", "No response from %s:%d", ip, port);
    return P2P_TIMEOUT;
  }

  LOG_N("COMM", "SEND_RECV %s:%d → %d bytes sent, %d received", ip, port,
        msg_len, n);
  return P2P_OK;
}

/* ==========================================================
 * SEND WITHOUT WAITING FOR RESPONSE
 * For broadcasts and one‑way notifications.
 * ========================================================== */
int comm_send(const char *ip, int port, const char *message) {
  int fd = connect_to(ip, port);
  if (fd < 0)
    return P2P_ERR;

  int msg_len = strlen(message);
  int sent = send(fd, message, msg_len, 0);
  close(fd);

  if (sent != msg_len) {
    LOG_E("COMM", "incomplete send() to %s:%d", ip, port);
    return P2P_ERR;
  }

  LOG_N("COMM", "SEND %s:%d (%d bytes)", ip, port, sent);
  return P2P_OK;
}

/* ==========================================================
 * TCP SERVER
 * ========================================================== */
int comm_start_server(int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
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

  if (listen(fd, 16) < 0) {
    LOG_E("COMM", "listen() failed: %s", strerror(errno));
    close(fd);
    return -1;
  }

  LOG_I("COMM", "TCP server listening on port %d", port);
  return fd;
}

/* ==========================================================
 * ACCEPT INCOMING CONNECTION
 * ========================================================== */
int comm_accept(int server_fd, char *client_ip) {
  struct sockaddr_in caddr;
  socklen_t clen = sizeof(caddr);

  int fd = accept(server_fd, (struct sockaddr *)&caddr, &clen);
  if (fd < 0)
    return -1;

  if (client_ip)
    inet_ntop(AF_INET, &caddr.sin_addr, client_ip, MAX_IP_LEN);

  set_timeout(fd, CONN_TIMEOUT);
  return fd;
}

/* ==========================================================
 * RECEIVE COMPLETE MESSAGE
 * Reads byte by byte until '\n' is found.
 * This way the message length can be variable.
 * ========================================================== */
int comm_recv(int fd, char *buffer, int max_len) {
  int total = 0;
  while (total < max_len - 1) {
    int n = recv(fd, buffer + total, 1, 0);
    if (n <= 0)
      break;
    total++;
    if (buffer[total - 1] == '\n')
      break;
  }
  buffer[total] = '\0';
  return total;
}

/* ==========================================================
 * SEND USING AN OPEN FILE DESCRIPTOR
 * For when we already have the accepted client fd.
 * ========================================================== */
int comm_send_fd(int fd, const char *data, int len) {
  int sent = send(fd, data, len, 0);
  if (sent != len) {
    LOG_E("COMM", "comm_send_fd: sent %d of %d bytes", sent, len);
    return P2P_ERR;
  }
  return P2P_OK;
}

/* ==========================================================
 * CLOSE FILE DESCRIPTOR
 * ========================================================== */
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

    if (comm_send(g_node.peers[i].ip, g_node.peers[i].port, message) ==
        P2P_OK) {
      sent_count++;
    }
  }
  LOG_N("COMM", "BROADCAST: %d/%d peers reached", sent_count,
        g_node.peer_count);
  return sent_count;
}
// AAGG
// 202127378

/* ==========================================================
 * PING — check if a peer is alive
 * Simply tries to connect and closes immediately.
 * ========================================================== */
int comm_ping(const char *ip, int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    return 0;

  struct timeval tv = {2, 0};
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, ip, &addr.sin_addr);

  int alive = (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
  close(fd);

  LOG_N("COMM", "PING %s:%d → %s", ip, port, alive ? "online" : "offline");
  return alive;
}
