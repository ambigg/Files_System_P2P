#include "../include/data.h"
#include "../include/directory.h"
#include "../include/log.h"
#include "../include/presentation.h"
#include "../include/protocol.h"
#include "../include/structures.h"
#include "../include/threads.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
// AAGG
// 202127378
NodeState g_node;
static void handle_signal(int sig) {
  (void)sig;
  printf("\n");
  g_node.running = 0;
}
static void ensure_dirs(void) {
  mkdir("shared", 0755);
  mkdir("logs", 0755);
  mkdir("tmp", 0755);
  mkdir("config", 0755);
}
int main(int argc, char *argv[]) {
  signal(SIGPIPE, SIG_IGN);
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <my_ip> [port]\n", argv[0]);
    fprintf(stderr, "  Example: %s 192.168.1.10\n", argv[0]);
    return 1;
  }
  ensure_dirs();
  memset(&g_node, 0, sizeof(g_node));
  strncpy(g_node.my_ip, argv[1], MAX_IP_LEN - 1);
  g_node.my_port = (argc >= 3) ? atoi(argv[2]) : P2P_PORT;
  strncpy(g_node.shared_folder, "shared", MAX_PATH_LEN - 1);
  strncpy(g_node.own_list_file, "config/files.txt", MAX_PATH_LEN - 1);
  g_node.running = 1;
  snprintf(g_node.log_file, MAX_PATH_LEN, "logs/%s.log", g_node.my_ip);
  for (char *p = g_node.log_file + 5; *p; p++)
    if (*p == '.')
      *p = '_';
  log_init(g_node.log_file, g_node.my_ip);
  LOG_I("MAIN", "════════════════════════════");
  LOG_I("MAIN", "NODE STARTED");
  LOG_I("MAIN", "IP:     %s", g_node.my_ip);
  LOG_I("MAIN", "Port:   %d", g_node.my_port);
  dir_init();
  pthread_mutex_init(&g_node.lease_mutex, NULL);
  int loaded = data_load_peers("config/peers.conf", g_node.peers, MAX_PEERS);
  g_node.peer_count = loaded;
  if (loaded > 0)
    LOG_I("MAIN", "peers.conf: %d peers loaded", loaded);
  else
    LOG_I("MAIN", "No peers.conf — add peers manually to config/peers.conf");
  dir_scan_own();
  dir_save_own();
  LOG_I("MAIN", "Own files: %d", g_node.dir.own_count);
  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);
  if (threads_start() != P2P_OK) {
    LOG_E("MAIN", "Error starting threads, aborting");
    log_close();
    return 1;
  }
  presentation_run();
  LOG_I("MAIN", "Initiating shutdown...");
  threads_stop();
  threads_join();
  log_close();
  LOG_I("MAIN", "NODE TERMINATED");
  LOG_I("MAIN", "════════════════════════════");
  return 0;
}
