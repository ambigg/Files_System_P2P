#ifndef STRUCTURES_H
#define STRUCTURES_H

#include "protocol.h"
#include <pthread.h>
#include <time.h>

/* Un archivo en cualquier lista */
typedef struct {
  char name[MAX_FILENAME_LEN];
  char ext[16];
  long size;
  time_t date_created;
  time_t date_modified;
  int ttl;
  char owner_ip[MAX_IP_LEN]; /* "LOCAL" si es propio */
  int is_local;
  time_t last_verified;
} FileEntry;

/* Un peer conocido en la red */
typedef struct {
  char ip[MAX_IP_LEN];
  int port;
  int reachable;
  time_t last_seen;
} PeerNode;

/* Un mensaje ya parseado */
typedef struct {
  char type[32];
  char sender_ip[MAX_IP_LEN];
  time_t timestamp;
  char payload[MAX_PAYLOAD_LEN];
  int payload_len;
} Message;

/* Las dos listas + sus mutexes */
typedef struct {
  FileEntry own_list[MAX_FILES];
  int own_count;
  pthread_mutex_t own_mutex;

  FileEntry general_list[MAX_FILES];
  int general_count;
  pthread_mutex_t general_mutex;
} Directory;

/* Una copia temporal en uso */
typedef struct {
  char original_name[MAX_FILENAME_LEN];
  char owner_ip[MAX_IP_LEN];
  char local_path[MAX_PATH_LEN];
  time_t checkout_time;
  int has_changes;
} FileLease;

/* Estado global del nodo — una sola instancia en main.c */
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

/* La única instancia global — definida en main.c, usada en todo */
extern NodeState g_node;

#endif
