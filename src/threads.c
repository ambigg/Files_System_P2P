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

/* ----------------------------------------------------------------
 * Ask every peer for their file list via UDP.
 * ALL buffers on heap — MAX_MSG_LEN is 64 KB.
 * ---------------------------------------------------------------- */
static void poll_peers(void) {
  if (g_node.peer_count == 0)
    return;
  LOG_I("CONN", "Polling %d peer(s)...", g_node.peer_count);

  char *plain = malloc(MAX_MSG_LEN);
  char *secure = malloc(MAX_MSG_LEN * 2);
  char *resp_raw = malloc(MAX_MSG_LEN);
  char *resp_plain = malloc(MAX_MSG_LEN);
  FileEntry *files = malloc(MAX_FILES * sizeof(FileEntry));

  if (!plain || !secure || !resp_raw || !resp_plain || !files) {
    LOG_E("CONN", "poll_peers malloc failed");
    goto done;
  }

  transfer_build_get_list(plain, g_node.my_ip);
  sec_encrypt(plain, strlen(plain), secure);

  for (int i = 0; i < g_node.peer_count; i++) {
    PeerNode *p = &g_node.peers[i];

    int rc = comm_send_recv(p->ip, p->port, secure, resp_raw, MAX_MSG_LEN);
    if (rc != P2P_OK) {
      p->fail_count++;
      if (p->fail_count >= 3 && p->reachable) {
        LOG_W("CONN", "Peer %s:%d offline", p->ip, p->port);
        dir_general_remove_peer(p->ip);
        p->reachable = 0;
      }
      continue;
    }

    p->fail_count = 0;
    p->reachable = 1;
    p->last_seen = time(NULL);
    LOG_I("CONN", "Peer %s:%d online", p->ip, p->port);

    int rlen;
    if (sec_is_secure(resp_raw)) {
      if (sec_decrypt(resp_raw, resp_plain, &rlen) != P2P_OK)
        continue;
    } else {
      strncpy(resp_plain, resp_raw, MAX_MSG_LEN - 1);
    }

    Message msg;
    if (transfer_parse_message(resp_plain, &msg) != P2P_OK)
      continue;
    if (strcmp(msg.type, MSG_LIST_RESP) != 0)
      continue;

    int count = transfer_parse_list_payload(msg.payload, files, MAX_FILES);
    if (count >= 0) {
      dir_general_update_from_peer(p->ip, files, count);
      LOG_D("CONN", "Peer %s: %d files", p->ip, count);
    }
  }

done:
  free(plain);
  free(secure);
  free(resp_raw);
  free(resp_plain);
  free(files);
}

/* ----------------------------------------------------------------
 * CONNECTIVITY THREAD
 * - Binds UDP server socket
 * - Polls peers periodically
 * - Handles incoming requests and replies
 * ---------------------------------------------------------------- */
void *thread_connectivity(void *arg) {
  (void)arg;
  LOG_I("CONN", "Connectivity thread started (port %d)", g_node.my_port);

  int fd = comm_start_server(g_node.my_port);
  if (fd < 0) {
    LOG_E("CONN", "Cannot start UDP server");
    return NULL;
  }

  /* Pre-allocate receive/send buffers on heap once */
  char *raw = malloc(MAX_MSG_LEN * 2);
  char *plain = malloc(MAX_MSG_LEN);
  char *resp_plain = malloc(MAX_MSG_LEN * 2);
  char *resp_sec = malloc(MAX_MSG_LEN * 4);

  if (!raw || !plain || !resp_plain || !resp_sec) {
    LOG_E("CONN", "malloc failed");
    free(raw);
    free(plain);
    free(resp_plain);
    free(resp_sec);
    comm_close(fd);
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

    /* Wait for incoming datagram (1 s timeout set on socket) */
    char sender_ip[MAX_IP_LEN] = {0};
    int sender_port = 0;
    int n = comm_recv_from(fd, raw, MAX_MSG_LEN * 2, sender_ip, &sender_port);
    if (n <= 0)
      continue;

    LOG_N("CONN", "UDP from %s:%d (%d bytes)", sender_ip, sender_port, n);

    /* Decrypt */
    int plain_len;
    if (sec_is_secure(raw)) {
      if (sec_decrypt(raw, plain, &plain_len) != P2P_OK) {
        LOG_E("CONN", "bad CRC from %s", sender_ip);
        continue;
      }
    } else {
      strncpy(plain, raw, MAX_MSG_LEN - 1);
    }

    /* Parse */
    Message msg;
    if (transfer_parse_message(plain, &msg) != P2P_OK) {
      LOG_E("CONN", "bad message from %s", sender_ip);
      continue;
    }

    /* Handle — resp_plain is on heap */
    resp_plain[0] = '\0';
    logic_handle_request(&msg, sender_ip, resp_plain);

    /* Reply to the SAME ephemeral port the request came from */
    if (resp_plain[0] != '\0') {
      int rlen = sec_encrypt(resp_plain, strlen(resp_plain), resp_sec);
      if (rlen > 0)
        comm_reply(fd, resp_sec, rlen, sender_ip, sender_port);
    }
  }

  free(raw);
  free(plain);
  free(resp_plain);
  free(resp_sec);
  comm_close(fd);
  LOG_I("CONN", "Connectivity thread stopped");
  return NULL;
}

/* ----------------------------------------------------------------
 * SYSTEM THREAD
 * - Watches shared/ for file changes every 5 s
 * - Watches config/peers.conf for new peers every 5 s
 * ---------------------------------------------------------------- */
typedef struct {
  char name[MAX_FILENAME_LEN];
  time_t mtime;
  long size;
} Snap;

static Snap *g_prev = NULL;
static int g_prev_n = 0;

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
    s[n].name[MAX_FILENAME_LEN - 1] = '\0';
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

  g_prev = malloc(MAX_FILES * sizeof(Snap));
  if (!g_prev) {
    LOG_E("SYS", "malloc failed");
    return NULL;
  }
  g_prev_n = snap_all(g_prev, MAX_FILES);

  while (g_node.running) {
    sleep(5);

    /* ── shared/ watcher ── */
    Snap *curr = malloc(MAX_FILES * sizeof(Snap));
    if (!curr)
      continue;
    int curr_n = snap_all(curr, MAX_FILES);

    for (int i = 0; i < curr_n; i++) {
      char path[MAX_PATH_LEN];
      snprintf(path, sizeof(path), "%s/%s", g_node.shared_folder, curr[i].name);
      FileEntry fe;
      int idx = snap_find(curr[i].name, g_prev, g_prev_n);
      if (idx < 0) {
        if (data_stat_file(path, &fe) == P2P_OK) {
          dir_own_add(&fe);
          dir_save_own();
          LOG_F("SYS", "New file detected: %s", curr[i].name);
        }
      } else if (curr[i].mtime != g_prev[idx].mtime) {
        if (data_stat_file(path, &fe) == P2P_OK) {
          dir_own_add(&fe);
          dir_save_own();
          LOG_F("SYS", "File modified: %s", curr[i].name);
        }
      }
    }
    for (int i = 0; i < g_prev_n; i++) {
      if (snap_find(g_prev[i].name, curr, curr_n) < 0) {
        dir_own_remove(g_prev[i].name);
        dir_save_own();
        LOG_F("SYS", "File deleted: %s", g_prev[i].name);
      }
    }
    memcpy(g_prev, curr, curr_n * sizeof(Snap));
    g_prev_n = curr_n;
    free(curr);

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
          LOG_I("SYS", "New peer from conf: %s:%d", tmp[i].ip, tmp[i].port);
        }
      }
    }
  }

  free(g_prev);
  LOG_I("SYS", "System thread stopped");
  return NULL;
}

/* ----------------------------------------------------------------
 * THREAD MANAGEMENT
 * ---------------------------------------------------------------- */
int threads_start(void) {
  if (pthread_create(&tid_connectivity, NULL, thread_connectivity, NULL)) {
    LOG_E("THREADS", "Failed connectivity thread");
    return P2P_ERR;
  }
  if (pthread_create(&tid_system, NULL, thread_system, NULL)) {
    LOG_E("THREADS", "Failed system thread");
    return P2P_ERR;
  }
  LOG_I("THREADS", "2 threads started");
  return P2P_OK;
}

void threads_stop(void) { g_node.running = 0; }

void threads_join(void) {
  pthread_join(tid_connectivity, NULL);
  pthread_join(tid_system, NULL);
  LOG_I("THREADS", "2 threads joined");
}
