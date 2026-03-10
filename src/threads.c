#include "../include/threads.h"
#include "../include/communication.h"
#include "../include/data.h"
#include "../include/directory.h"
#include "../include/log.h"
#include "../include/logic.h"
#include "../include/protocol.h"
#include "../include/security.h"
#include "../include/structures.h"
#include "../include/transfer.h"
#include <dirent.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static pthread_t tid_connectivity;
static pthread_t tid_system;

/* ==========================================================
 * Ask every peer "what do you have?" via UDP
 * ========================================================== */
static void poll_peers(void) {
  if (g_node.peer_count == 0)
    return;
  LOG_I("CONN", "Polling %d peers...", g_node.peer_count);

  char plain[MAX_MSG_LEN];
  transfer_build_get_list(plain, g_node.my_ip);

  char secure[MAX_MSG_LEN * 2];
  sec_encrypt(plain, strlen(plain), secure);

  for (int i = 0; i < g_node.peer_count; i++) {
    PeerNode *p = &g_node.peers[i];

    char resp_raw[MAX_MSG_LEN];
    int rc = comm_send_recv(p->ip, p->port, secure, resp_raw, sizeof(resp_raw));

    if (rc != P2P_OK) {
      p->fail_count++;
      if (p->fail_count >= 3 && p->reachable) {
        LOG_W("CONN", "Peer %s:%d unreachable", p->ip, p->port);
        dir_general_remove_peer(p->ip);
        p->reachable = 0;
      }
      continue;
    }

    p->fail_count = 0;
    p->reachable = 1;
    p->last_seen = time(NULL);

    char resp_plain[MAX_MSG_LEN];
    int resp_len;
    if (sec_is_secure(resp_raw)) {
      if (sec_decrypt(resp_raw, resp_plain, &resp_len) != P2P_OK)
        continue;
    } else {
      strncpy(resp_plain, resp_raw, MAX_MSG_LEN - 1);
    }

    Message msg;
    if (transfer_parse_message(resp_plain, &msg) != P2P_OK)
      continue;
    if (strcmp(msg.type, MSG_LIST_RESP) != 0)
      continue;

    FileEntry files[MAX_FILES];
    int count = transfer_parse_list_payload(msg.payload, files, MAX_FILES);
    if (count >= 0) {
      dir_general_update_from_peer(p->ip, files, count);
      LOG_D("CONN", "Peer %s: %d files", p->ip, count);
    }
  }
  LOG_I("CONN", "Poll done");
}

/* ==========================================================
 * CONNECTIVITY THREAD
 * - UDP server: receive requests and reply
 * - Periodic poll of all peers
 * ========================================================== */
void *thread_connectivity(void *arg) {
  (void)arg;
  LOG_I("CONN", "Connectivity thread started");

  int fd = comm_start_server(g_node.my_port);
  if (fd < 0) {
    LOG_E("CONN", "Could not start UDP server");
    return NULL;
  }

  poll_peers();
  time_t last_poll = time(NULL);

  while (g_node.running) {

    /* Periodic poll */
    if (time(NULL) - last_poll >= UPDATE_INTERVAL) {
      poll_peers();
      last_poll = time(NULL);
    }

    /* Receive incoming datagram */
    char raw[MAX_MSG_LEN * 2];
    char sender_ip[MAX_IP_LEN] = {0};
    int sender_port = 0;

    int n = comm_recv_from(fd, raw, sizeof(raw), sender_ip, &sender_port);
    if (n <= 0)
      continue; /* timeout — loop */

    LOG_N("CONN", "UDP from %s:%d", sender_ip, sender_port);

    /* Decrypt */
    char plain[MAX_MSG_LEN];
    int plain_len;
    if (sec_is_secure(raw)) {
      if (sec_decrypt(raw, plain, &plain_len) != P2P_OK) {
        LOG_E("CONN", "Bad CRC from %s", sender_ip);
        continue;
      }
    } else {
      strncpy(plain, raw, MAX_MSG_LEN - 1);
    }

    /* Parse */
    Message msg;
    if (transfer_parse_message(plain, &msg) != P2P_OK) {
      LOG_E("CONN", "Bad message from %s", sender_ip);
      continue;
    }

    /* Handle */
    char resp_plain[MAX_MSG_LEN * 2];
    logic_handle_request(&msg, sender_ip, resp_plain);

    /* Reply to sender's ephemeral port */
    if (strlen(resp_plain) > 0) {
      char resp_sec[MAX_MSG_LEN * 4];
      int rlen = sec_encrypt(resp_plain, strlen(resp_plain), resp_sec);
      if (rlen > 0)
        comm_reply(fd, resp_sec, rlen, sender_ip, sender_port);
    }
  }

  comm_close(fd);
  LOG_I("CONN", "Connectivity thread terminated");
  return NULL;
}

/* ==========================================================
 * SYSTEM THREAD
 * - Watch shared/ folder for changes
 * - Watch peers.conf for new peers
 * ========================================================== */
typedef struct {
  char name[MAX_FILENAME_LEN];
  time_t mtime;
  long size;
} Snap;
static Snap prev[MAX_FILES];
static int prev_n = 0;

static int snap_all(Snap *s, int max) {
  int n = 0;
  DIR *dp = opendir(g_node.shared_folder);
  if (!dp)
    return 0;
  struct dirent *e;
  while ((e = readdir(dp)) && n < max) {
    if (e->d_name[0] == '.')
      continue;
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s", g_node.shared_folder, e->d_name);
    struct stat st;
    if (stat(path, &st) != 0 || S_ISDIR(st.st_mode))
      continue;
    strncpy(s[n].name, e->d_name, MAX_FILENAME_LEN - 1);
    s[n].mtime = st.st_mtime;
    s[n].size = st.st_size;
    n++;
  }
  closedir(dp);
  return n;
}

static int snap_find(const char *name, Snap *s, int n) {
  for (int i = 0; i < n; i++)
    if (strcmp(s[i].name, name) == 0)
      return i;
  return -1;
}

void *thread_system(void *arg) {
  (void)arg;
  LOG_I("SYS", "System thread started");
  prev_n = snap_all(prev, MAX_FILES);

  while (g_node.running) {
    sleep(5);

    /* ── shared/ watcher ── */
    Snap curr[MAX_FILES];
    int curr_n = snap_all(curr, MAX_FILES);

    for (int i = 0; i < curr_n; i++) {
      int idx = snap_find(curr[i].name, prev, prev_n);
      char path[MAX_PATH_LEN];
      snprintf(path, sizeof(path), "%s/%s", g_node.shared_folder, curr[i].name);
      FileEntry fe;
      if (idx < 0) {
        if (data_stat_file(path, &fe) == P2P_OK) {
          dir_own_add(&fe);
          dir_save_own();
          LOG_F("SYS", "New file: %s", curr[i].name);
        }
      } else if (curr[i].mtime != prev[idx].mtime) {
        if (data_stat_file(path, &fe) == P2P_OK) {
          dir_own_add(&fe);
          dir_save_own();
          LOG_F("SYS", "Modified: %s", curr[i].name);
        }
      }
    }
    for (int i = 0; i < prev_n; i++) {
      if (snap_find(prev[i].name, curr, curr_n) < 0) {
        dir_own_remove(prev[i].name);
        dir_save_own();
        LOG_F("SYS", "Deleted: %s", prev[i].name);
      }
    }
    memcpy(prev, curr, curr_n * sizeof(Snap));
    prev_n = curr_n;

    /* ── peers.conf watcher ── */
    static time_t peers_mtime = 0;
    struct stat st;
    if (stat("config/peers.conf", &st) == 0 && st.st_mtime != peers_mtime) {
      peers_mtime = st.st_mtime;
      PeerNode tmp[MAX_PEERS];
      int cnt = data_load_peers("config/peers.conf", tmp, MAX_PEERS);
      for (int i = 0; i < cnt; i++) {
        int found = 0;
        for (int j = 0; j < g_node.peer_count; j++)
          if (strcmp(g_node.peers[j].ip, tmp[i].ip) == 0 &&
              g_node.peers[j].port == tmp[i].port) {
            found = 1;
            break;
          }
        if (!found && g_node.peer_count < MAX_PEERS) {
          g_node.peers[g_node.peer_count] = tmp[i];
          g_node.peers[g_node.peer_count].reachable = 0;
          g_node.peers[g_node.peer_count].fail_count = 0;
          g_node.peer_count++;
          LOG_I("SYS", "New peer: %s:%d", tmp[i].ip, tmp[i].port);
        }
      }
    }
  }

  LOG_I("SYS", "System thread terminated");
  return NULL;
}

/* ==========================================================
 * THREAD MANAGEMENT
 * ========================================================== */
int threads_start(void) {
  if (pthread_create(&tid_connectivity, NULL, thread_connectivity, NULL) != 0) {
    LOG_E("THREADS", "Failed to create connectivity thread");
    return P2P_ERR;
  }
  if (pthread_create(&tid_system, NULL, thread_system, NULL) != 0) {
    LOG_E("THREADS", "Failed to create system thread");
    return P2P_ERR;
  }
  LOG_I("THREADS", "2 threads started");
  return P2P_OK;
}

void threads_stop(void) { g_node.running = 0; }

void threads_join(void) {
  pthread_join(tid_connectivity, NULL);
  pthread_join(tid_system, NULL);
  LOG_I("THREADS", "2 threads terminated");
}
