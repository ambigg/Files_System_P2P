#ifndef STRUCTURES_H
#define STRUCTURES_H
#include "protocol.h"
#include <pthread.h>
#include <time.h>

typedef struct {
  char name[MAX_FILENAME_LEN];
  char ext[16];
  long size;
  time_t date_created;
  time_t date_modified;
  int ttl;
  char owner_ip[MAX_IP_LEN];
  int is_local;
  time_t last_verified;
} FileEntry;

typedef struct {
  char ip[MAX_IP_LEN];
  int port;
  int reachable;
  time_t last_seen;
  int fail_count;
} PeerNode;

typedef struct {
  char type[32];
  char sender_ip[MAX_IP_LEN];
  time_t timestamp;
  char payload[MAX_PAYLOAD_LEN];
  int payload_len;
} Message;

typedef struct {
  FileEntry own_list[MAX_FILES];
  int own_count;
  pthread_mutex_t own_mutex;
  FileEntry general_list[MAX_FILES];
  int general_count;
  pthread_mutex_t general_mutex;
} Directory;

typedef struct {
  char original_name[MAX_FILENAME_LEN];
  char owner_ip[MAX_IP_LEN];
  char local_path[MAX_PATH_LEN];
  time_t checkout_time;
  int has_changes;
} FileLease;

typedef struct {
  char my_ip[MAX_IP_LEN];
  int my_port;
  char shared_folder[MAX_PATH_LEN];
  char log_file[MAX_PATH_LEN];
  char own_list_file[MAX_PATH_LEN];
  PeerNode peers[MAX_PEERS];
  int peer_count;
  Directory dir;
  FileLease leases[64];
  int lease_count;
  pthread_mutex_t lease_mutex;
  int running;
} NodeState;

extern NodeState g_node;
#endif
