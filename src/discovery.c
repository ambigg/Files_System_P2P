#include "../include/discovery.h"
#include "../include/log.h"
#include "../include/protocol.h"
#include "../include/structures.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* ==========================================================
 * HELPER — add a peer if it doesn't already exist in the list
 * ========================================================== */
static void add_peer_if_new(const char *ip, int port) {
  /* Do not add ourselves */
  if (strcmp(ip, g_node.my_ip) == 0)
    return;

  /* Check if already present */
  for (int i = 0; i < g_node.peer_count; i++) {
    if (strcmp(g_node.peers[i].ip, ip) == 0)
      return;
  }

  if (g_node.peer_count >= MAX_PEERS) {
    LOG_W("DISC", "Peer list full, ignoring %s", ip);
    return;
  }

  strncpy(g_node.peers[g_node.peer_count].ip, ip, MAX_IP_LEN - 1);
  g_node.peers[g_node.peer_count].port = port;
  g_node.peers[g_node.peer_count].reachable = 1;
  g_node.peers[g_node.peer_count].last_seen = 0;
  g_node.peer_count++;

  LOG_I("DISC", "Peer discovered: %s:%d (total: %d)", ip, port,
        g_node.peer_count);
}

/* ==========================================================
 * HELPER — create and configure a UDP socket for discovery
 * ========================================================== */
static int make_udp_socket(int timeout_sec) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    LOG_E("DISC", "UDP socket() failed");
    return -1;
  }

  int opt = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));

  if (timeout_sec > 0) {
    struct timeval tv = {timeout_sec, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  }

  return fd;
}

/* ==========================================================
 * HELPER — parse a discovery message
 * Format: TYPE|IP|PORT\n
 * Returns 1 if parsed successfully, 0 otherwise.
 * ========================================================== */
static int parse_disc_msg(char *buf, char *type_out, char *ip_out,
                          int *port_out) {
  buf[strcspn(buf, "\n")] = '\0';

  char *rest = buf;
  char *tok;

  tok = strsep(&rest, "|");
  if (!tok)
    return 0;
  strncpy(type_out, tok, 31);

  tok = strsep(&rest, "|");
  if (!tok)
    return 0;
  strncpy(ip_out, tok, MAX_IP_LEN - 1);

  tok = strsep(&rest, "|");
  if (!tok)
    return 0;
  *port_out = atoi(tok);

  return 1;
}

/* ==========================================================
 * ANNOUNCE — call once at startup
 * ========================================================== */
void discovery_announce(void) {
  LOG_I("DISC", "Looking for peers on the local network...");

  int fd = make_udp_socket(2); /* 2 sec timeout for responses */
  if (fd < 0)
    return;

  /* Bind to be able to receive responses */
  struct sockaddr_in my_addr;
  memset(&my_addr, 0, sizeof(my_addr));
  my_addr.sin_family = AF_INET;
  my_addr.sin_addr.s_addr = INADDR_ANY;
  my_addr.sin_port = htons(DISCOVERY_PORT);

  if (bind(fd, (struct sockaddr *)&my_addr, sizeof(my_addr)) < 0) {
    /*
     * If bind fails, probably the discovery thread is already using that port
     * (if discovery_announce is called after threads_start). It is not a fatal
     * error.
     */
    LOG_W("DISC",
          "bind() failed in announce, the thread might already be active");
    close(fd);
    return;
  }

  /* Build HELLO */
  char hello[64];
  snprintf(hello, sizeof(hello), "%s|%s|%d\n", DISC_HELLO, g_node.my_ip,
           g_node.my_port);

  /* Send broadcast */
  struct sockaddr_in bcast;
  memset(&bcast, 0, sizeof(bcast));
  bcast.sin_family = AF_INET;
  bcast.sin_port = htons(DISCOVERY_PORT);
  bcast.sin_addr.s_addr = INADDR_BROADCAST;

  sendto(fd, hello, strlen(hello), 0, (struct sockaddr *)&bcast, sizeof(bcast));
  LOG_I("DISC", "HELLO sent to broadcast");

  /* Wait for ACKs for 2 seconds */
  char buf[128];
  struct sockaddr_in sender;
  socklen_t sender_len;

  while (1) {
    sender_len = sizeof(sender);
    int n = recvfrom(fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&sender,
                     &sender_len);
    if (n <= 0)
      break; /* timeout */
    buf[n] = '\0';

    char type[32], ip[MAX_IP_LEN];
    int port;
    if (!parse_disc_msg(buf, type, ip, &port))
      continue;
    if (strcmp(type, DISC_ACK) != 0)
      continue;

    add_peer_if_new(ip, port);
  }

  close(fd);
  LOG_I("DISC", "Discovery complete: %d peers found", g_node.peer_count);
}

/* ==========================================================
 * DISCOVERY THREAD — always listening
 * ========================================================== */
void *thread_discovery(void *arg) {
  (void)arg;
  LOG_I("DISC", "Discovery thread started (UDP:%d)", DISCOVERY_PORT);

  int fd = make_udp_socket(1); /* 1 sec timeout to check running flag */
  if (fd < 0)
    return NULL;

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(DISCOVERY_PORT);

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    LOG_E("DISC", "thread bind() failed on port %d", DISCOVERY_PORT);
    close(fd);
    return NULL;
  }

  char buf[128];
  struct sockaddr_in sender;
  socklen_t sender_len;

  while (g_node.running) {
    sender_len = sizeof(sender);
    int n = recvfrom(fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&sender,
                     &sender_len);
    if (n <= 0)
      continue; /* timeout, check running flag */
    buf[n] = '\0';

    char type[32], ip[MAX_IP_LEN];
    int port;
    if (!parse_disc_msg(buf, type, ip, &port))
      continue;
    if (strcmp(type, DISC_HELLO) != 0)
      continue;
    if (strcmp(ip, g_node.my_ip) == 0)
      continue; /* it's me */

    LOG_I("DISC", "HELLO from %s:%d", ip, port);
    add_peer_if_new(ip, port);

    /* Reply with direct ACK (not broadcast) */
    char ack[64];
    snprintf(ack, sizeof(ack), "%s|%s|%d\n", DISC_ACK, g_node.my_ip,
             g_node.my_port);

    sendto(fd, ack, strlen(ack), 0, (struct sockaddr *)&sender, sender_len);
    LOG_I("DISC", "ACK sent to %s:%d", ip, port);
  }

  close(fd);
  LOG_I("DISC", "Discovery thread terminated");
  return NULL;
}
