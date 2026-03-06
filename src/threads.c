#include "../include/threads.h"
#include "../include/communication.h"
#include "../include/data.h"
#include "../include/directory.h"
#include "../include/discovery.h"
#include "../include/log.h"
#include "../include/logic.h"
#include "../include/protocol.h"
#include "../include/security.h"
#include "../include/structures.h"
#include "../include/transfer.h"
#include <dirent.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static pthread_t tid_connectivity;
static pthread_t tid_system;
static pthread_t tid_discovery;

typedef struct {
  int fd;
  char ip[MAX_IP_LEN];
} ClientConn;

static void *handle_client(void *arg) {
  ClientConn *conn = (ClientConn *)arg;
  int fd = conn->fd;
  char client_ip[MAX_IP_LEN];
  strncpy(client_ip, conn->ip, MAX_IP_LEN - 1);
  free(conn);

  char *raw = malloc(MAX_MSG_LEN * 2);
  char *plain = malloc(MAX_MSG_LEN);
  char *resp_plain = malloc(MAX_MSG_LEN * 2);
  char *resp_sec = malloc(MAX_MSG_LEN * 4);

  if (!raw || !plain || !resp_plain || !resp_sec) {
    LOG_E("CONN", "malloc failed in handle_client");
    free(raw);
    free(plain);
    free(resp_plain);
    free(resp_sec);
    comm_close(fd);
    return NULL;
  }

  int n = comm_recv(fd, raw, MAX_MSG_LEN * 2);
  if (n <= 0)
    goto cleanup;

  int plain_len;
  if (sec_is_secure(raw)) {
    if (sec_decrypt(raw, plain, &plain_len) != P2P_OK) {
      LOG_E("CONN", "Invalid CRC from %s", client_ip);
      goto cleanup;
    }
  } else {
    strncpy(plain, raw, MAX_MSG_LEN - 1);
  }

  Message msg;
  if (transfer_parse_message(plain, &msg) != P2P_OK) {
    LOG_E("CONN", "Malformed message from %s", client_ip);
    goto cleanup;
  }

  logic_handle_request(&msg, client_ip, resp_plain);

  int resp_len = sec_encrypt(resp_plain, strlen(resp_plain), resp_sec);
  if (resp_len > 0)
    comm_send_fd(fd, resp_sec, resp_len);

cleanup:
  free(raw);
  free(plain);
  free(resp_plain);
  free(resp_sec);
  comm_close(fd);
  return NULL;
}

static void update_all_lists(void) {
  LOG_I("CONN", "Updating lists (%d peers)...", g_node.peer_count);

  char get_list_plain[MAX_MSG_LEN];
  transfer_build_get_list(get_list_plain, g_node.my_ip);

  char *get_list_secure = malloc(MAX_MSG_LEN * 2);
  if (!get_list_secure)
    return;
  sec_encrypt(get_list_plain, strlen(get_list_plain), get_list_secure);

  for (int i = 0; i < g_node.peer_count; i++) {
    PeerNode *peer = &g_node.peers[i];

    char *resp_raw = malloc(MAX_MSG_LEN);
    if (!resp_raw)
      continue;

    int rc = comm_send_recv(peer->ip, peer->port, get_list_secure, resp_raw,
                            MAX_MSG_LEN);

    if (rc != P2P_OK) {
      peer->fail_count++;
      if (peer->fail_count >= 3 && peer->reachable) {
        LOG_W("CONN", "Peer %s not responding (%dx)", peer->ip,
              peer->fail_count);
        dir_general_remove_peer(peer->ip);
        peer->reachable = 0;
      }
      free(resp_raw);
      continue;
    }

    peer->fail_count = 0;
    peer->reachable = 1;
    peer->last_seen = time(NULL);

    char *resp_plain = malloc(MAX_MSG_LEN);
    if (!resp_plain) {
      free(resp_raw);
      continue;
    }

    int resp_len;
    if (sec_is_secure(resp_raw)) {
      if (sec_decrypt(resp_raw, resp_plain, &resp_len) != P2P_OK) {
        free(resp_raw);
        free(resp_plain);
        continue;
      }
    } else {
      strncpy(resp_plain, resp_raw, MAX_MSG_LEN - 1);
    }
    free(resp_raw);

    Message resp_msg;
    if (transfer_parse_message(resp_plain, &resp_msg) != P2P_OK ||
        strcmp(resp_msg.type, MSG_LIST_RESP) != 0) {
      free(resp_plain);
      continue;
    }
    free(resp_plain);

    FileEntry *files = malloc(MAX_FILES * sizeof(FileEntry));
    if (!files)
      continue;

    int count = transfer_parse_list_payload(resp_msg.payload, files, MAX_FILES);
    if (count >= 0) {
      dir_general_update_from_peer(peer->ip, files, count);
      LOG_D("CONN", "Peer %s: %d files", peer->ip, count);
    }
    free(files);
  }

  free(get_list_secure);
  LOG_I("CONN", "Update complete");
}

void *thread_connectivity(void *arg) {
  (void)arg;
  LOG_I("CONN", "Connectivity thread started");

  int server_fd = comm_start_server(g_node.my_port);
  if (server_fd < 0) {
    LOG_E("CONN", "Could not start server");
    return NULL;
  }

  struct timeval tv = {1, 0};
  setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  update_all_lists();
  time_t last_update = time(NULL);

  while (g_node.running) {
    if (time(NULL) - last_update >= UPDATE_INTERVAL) {
      update_all_lists();
      last_update = time(NULL);
    }

    char client_ip[MAX_IP_LEN];
    int client_fd = comm_accept(server_fd, client_ip);
    if (client_fd < 0)
      continue;

    LOG_N("CONN", "Connection from %s", client_ip);

    /* Auto-add or re-activate peer */
    int known = 0;
    for (int i = 0; i < g_node.peer_count; i++) {
      if (strcmp(g_node.peers[i].ip, client_ip) == 0) {
        known = 1;
        g_node.peers[i].reachable = 1;
        g_node.peers[i].fail_count = 0;
        g_node.peers[i].last_seen = time(NULL);
        break;
      }
    }
    if (!known && strcmp(client_ip, g_node.my_ip) != 0 &&
        g_node.peer_count < MAX_PEERS) {
      strncpy(g_node.peers[g_node.peer_count].ip, client_ip, MAX_IP_LEN - 1);
      g_node.peers[g_node.peer_count].port = P2P_PORT;
      g_node.peers[g_node.peer_count].reachable = 1;
      g_node.peers[g_node.peer_count].fail_count = 0;
      g_node.peers[g_node.peer_count].last_seen = time(NULL);
      g_node.peer_count++;
      LOG_I("CONN", "Auto-added peer: %s", client_ip);
    }

    ClientConn *conn = malloc(sizeof(ClientConn));
    if (!conn) {
      comm_close(client_fd);
      continue;
    }
    conn->fd = client_fd;
    strncpy(conn->ip, client_ip, MAX_IP_LEN - 1);

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, handle_client, conn);
    pthread_attr_destroy(&attr);
  }

  comm_close(server_fd);
  LOG_I("CONN", "Connectivity thread terminated");
  return NULL;
}

typedef struct {
  char name[MAX_FILENAME_LEN];
  time_t mtime;
  long size;
} FileSnap;

static FileSnap prev[MAX_FILES];
static int prev_count = 0;

static int take_snapshot(FileSnap *snap, int max) {
  int count = 0;
  DIR *dp = opendir(g_node.shared_folder);
  if (!dp)
    return 0;

  struct dirent *entry;
  while ((entry = readdir(dp)) != NULL && count < max) {
    if (entry->d_name[0] == '.')
      continue;

    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s", g_node.shared_folder, entry->d_name);

    struct stat st;
    if (stat(path, &st) != 0)
      continue;
    if (S_ISDIR(st.st_mode))
      continue;

    strncpy(snap[count].name, entry->d_name, MAX_FILENAME_LEN - 1);
    snap[count].mtime = st.st_mtime;
    snap[count].size = st.st_size;
    count++;
  }

  closedir(dp);
  return count;
}

static int snap_find(const char *name, const FileSnap *snap, int count) {
  for (int i = 0; i < count; i++)
    if (strcmp(snap[i].name, name) == 0)
      return i;
  return -1;
}

void *thread_system(void *arg) {
  (void)arg;
  LOG_I("SYS", "System thread started");

  prev_count = take_snapshot(prev, MAX_FILES);

  while (g_node.running) {
    sleep(5);

    FileSnap *curr = malloc(MAX_FILES * sizeof(FileSnap));
    if (!curr)
      continue;
    int curr_count = take_snapshot(curr, MAX_FILES);

    /* New or modified files */
    for (int i = 0; i < curr_count; i++) {
      int idx = snap_find(curr[i].name, prev, prev_count);
      if (idx < 0) {
        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "%s/%s", g_node.shared_folder,
                 curr[i].name);
        FileEntry entry;
        if (data_stat_file(path, &entry) == P2P_OK) {
          dir_own_add(&entry);
          dir_save_own();
          LOG_F("SYS", "New file: %s", curr[i].name);
        }
      } else if (curr[i].mtime != prev[idx].mtime) {
        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "%s/%s", g_node.shared_folder,
                 curr[i].name);
        FileEntry entry;
        if (data_stat_file(path, &entry) == P2P_OK) {
          dir_own_add(&entry);
          dir_save_own();
          LOG_F("SYS", "File modified: %s", curr[i].name);
        }
      }
    }

    /* Deleted files */
    for (int i = 0; i < prev_count; i++) {
      if (snap_find(prev[i].name, curr, curr_count) < 0) {
        dir_own_remove(prev[i].name);
        dir_save_own();
        LOG_F("SYS", "File deleted: %s", prev[i].name);
      }
    }

    memcpy(prev, curr, curr_count * sizeof(FileSnap));
    prev_count = curr_count;
    free(curr);

    /* Watch peers.conf for manually added peers */
    static time_t last_peers_mtime = 0;
    struct stat peers_st;
    if (stat("config/peers.conf", &peers_st) == 0) {
      if (peers_st.st_mtime != last_peers_mtime) {
        last_peers_mtime = peers_st.st_mtime;

        PeerNode new_peers[MAX_PEERS];
        int new_count =
            data_load_peers("config/peers.conf", new_peers, MAX_PEERS);

        for (int i = 0; i < new_count; i++) {
          int known = 0;
          for (int j = 0; j < g_node.peer_count; j++) {
            if (strcmp(g_node.peers[j].ip, new_peers[i].ip) == 0 &&
                g_node.peers[j].port == new_peers[i].port) {
              known = 1;
              break;
            }
          }
          if (!known && g_node.peer_count < MAX_PEERS) {
            g_node.peers[g_node.peer_count] = new_peers[i];
            g_node.peers[g_node.peer_count].reachable = 0;
            g_node.peers[g_node.peer_count].fail_count = 0;
            g_node.peer_count++;
            LOG_I("SYS", "New peer from peers.conf: %s:%d", new_peers[i].ip,
                  new_peers[i].port);
          }
        }
      }
    }
  }

  LOG_I("SYS", "System thread terminated");
  return NULL;
}

int threads_start(void) {
  if (pthread_create(&tid_connectivity, NULL, thread_connectivity, NULL) != 0) {
    LOG_E("THREADS", "Could not create connectivity thread");
    return P2P_ERR;
  }
  if (pthread_create(&tid_system, NULL, thread_system, NULL) != 0) {
    LOG_E("THREADS", "Could not create system thread");
    return P2P_ERR;
  }
  if (pthread_create(&tid_discovery, NULL, thread_discovery, NULL) != 0) {
    LOG_E("THREADS", "Could not create discovery thread");
    return P2P_ERR;
  }
  LOG_I("THREADS", "3 threads started");
  return P2P_OK;
}

void threads_stop(void) {
  g_node.running = 0;
  LOG_I("THREADS", "Stop signal sent");
}

void threads_join(void) {
  pthread_join(tid_connectivity, NULL);
  pthread_join(tid_system, NULL);
  pthread_join(tid_discovery, NULL);
  LOG_I("THREADS", "3 threads terminated");
}
