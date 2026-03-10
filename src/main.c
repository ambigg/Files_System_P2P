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
    return 1;
  }

  ensure_dirs();
  memset(&g_node, 0, sizeof(g_node));

  strncpy(g_node.my_ip, argv[1], MAX_IP_LEN - 1);
  g_node.my_port = (argc >= 3) ? atoi(argv[2]) : P2P_PORT;
  strncpy(g_node.shared_folder, "shared", MAX_PATH_LEN - 1);
  strncpy(g_node.own_list_file, "config/files.txt", MAX_PATH_LEN - 1);
  g_node.running = 1;

  /* Log file includes port so two instances don't collide */
  snprintf(g_node.log_file, MAX_PATH_LEN, "logs/node_%d.log", g_node.my_port);
  log_init(g_node.log_file, g_node.my_ip);

  LOG_I("MAIN", "Node %s:%d starting", g_node.my_ip, g_node.my_port);

  dir_init();
  pthread_mutex_init(&g_node.lease_mutex, NULL);

  g_node.peer_count =
      data_load_peers("config/peers.conf", g_node.peers, MAX_PEERS);
  LOG_I("MAIN", "Peers loaded: %d", g_node.peer_count);

  dir_scan_own();
  dir_save_own();
  LOG_I("MAIN", "Own files: %d", g_node.dir.own_count);

  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  if (threads_start() != P2P_OK) {
    LOG_E("MAIN", "Failed to start threads");
    log_close();
    return 1;
  }

  presentation_run();

  threads_stop();
  threads_join();
  log_close();
  return 0;
}
