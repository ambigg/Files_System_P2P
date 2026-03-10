#include "../include/logic.h"
#include "../include/communication.h"
#include "../include/data.h"
#include "../include/directory.h"
#include "../include/log.h"
#include "../include/protocol.h"
#include "../include/security.h"
#include "../include/transfer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ----------------------------------------------------------------
 * INTERNAL: encrypt → send → receive → decrypt
 * All large buffers on heap (MAX_MSG_LEN = 64 KB).
 * ---------------------------------------------------------------- */
static int request(const char *ip, int port, const char *msg_plain,
                   char *resp_plain) {
  int rc = P2P_ERR;

  char *secure_out = malloc(MAX_MSG_LEN * 2);
  char *secure_in = malloc(MAX_MSG_LEN * 2);
  if (!secure_out || !secure_in)
    goto done;

  if (sec_encrypt(msg_plain, strlen(msg_plain), secure_out) < 0) {
    LOG_E("LOGIC", "encrypt failed for %s", ip);
    goto done;
  }

  rc = comm_send_recv(ip, port, secure_out, secure_in, MAX_MSG_LEN * 2);
  if (rc != P2P_OK)
    goto done;

  int plain_len;
  if (sec_is_secure(secure_in)) {
    if (sec_decrypt(secure_in, resp_plain, &plain_len) != P2P_OK) {
      LOG_E("LOGIC", "decrypt failed from %s", ip);
      rc = P2P_AUTH_FAIL;
      goto done;
    }
  } else {
    strncpy(resp_plain, secure_in, MAX_MSG_LEN - 1);
  }
  rc = P2P_OK;

done:
  free(secure_out);
  free(secure_in);
  return rc;
}

static int notify(const char *ip, int port, const char *msg_plain) {
  char *secure = malloc(MAX_MSG_LEN * 2);
  if (!secure)
    return P2P_ERR;
  int rc = P2P_ERR;
  if (sec_encrypt(msg_plain, strlen(msg_plain), secure) >= 0)
    rc = comm_send(ip, port, secure);
  free(secure);
  return rc;
}

/* ----------------------------------------------------------------
 * SERVER: handle incoming request, write response into `response`
 * ---------------------------------------------------------------- */
int logic_handle_request(const Message *msg, const char *sender_ip,
                         char *response) {
  LOG_I("LOGIC", "req type=%s from=%s", msg->type, sender_ip);

  if (strcmp(msg->type, MSG_GET_LIST) == 0) {
    FileEntry *own = malloc(MAX_FILES * sizeof(FileEntry));
    if (!own) {
      transfer_build_nack(response, g_node.my_ip, "OOM");
      return P2P_ERR;
    }
    int count = dir_own_snapshot(own, MAX_FILES);
    transfer_build_list_resp(response, g_node.my_ip, own, count);
    free(own);
    LOG_D("LOGIC", "GET_LIST → %d files", count);
    return P2P_OK;
  }

  if (strcmp(msg->type, MSG_GET_INFO) == 0) {
    const char *filename = msg->payload;
    FileEntry found;
    if (dir_find(filename, &found) == P2P_OK) {
      if (found.is_local) {
        strncpy(found.owner_ip, g_node.my_ip, MAX_IP_LEN - 1);
        transfer_build_info_resp(response, g_node.my_ip, &found);
      } else {
        transfer_build_info_redir(response, g_node.my_ip, filename,
                                  found.owner_ip);
      }
    } else {
      transfer_build_nack(response, g_node.my_ip, filename);
    }
    return P2P_OK;
  }

  if (strcmp(msg->type, MSG_GET_FILE) == 0) {
    const char *filename = msg->payload;
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s", g_node.shared_folder, filename);
    long size;
    unsigned char *content = data_read_file(path, &size);
    if (!content) {
      transfer_build_nack(response, g_node.my_ip, filename);
      return P2P_NOT_FOUND;
    }
    int rc = transfer_build_file_resp(response, g_node.my_ip, filename, content,
                                      size);
    free(content);
    if (rc < 0)
      transfer_build_nack(response, g_node.my_ip, filename);
    return P2P_OK;
  }

  if (strcmp(msg->type, MSG_NEW_FILE) == 0) {
    FileEntry entry;
    if (transfer_parse_info_payload(msg->payload, &entry) == P2P_OK) {
      strncpy(entry.owner_ip, sender_ip, MAX_IP_LEN - 1);
      entry.is_local = 0;
      logic_handle_new_file(&entry, sender_ip);
    }
    transfer_build_ack(response, g_node.my_ip, "OK");
    return P2P_OK;
  }

  if (strcmp(msg->type, MSG_SYNC_FILE) == 0) {
    char filename[MAX_FILENAME_LEN];
    unsigned char *content = malloc(MAX_PAYLOAD_LEN);
    if (!content) {
      transfer_build_nack(response, g_node.my_ip, "OOM");
      return P2P_ERR;
    }
    long size;
    if (transfer_parse_file_payload(msg->payload, filename, content, &size) ==
        P2P_OK) {
      char path[MAX_PATH_LEN];
      snprintf(path, sizeof(path), "%s/%s", g_node.shared_folder, filename);
      if (data_write_file(path, content, size) == P2P_OK) {
        FileEntry updated;
        if (data_stat_file(path, &updated) == P2P_OK) {
          dir_own_add(&updated);
          dir_save_own();
        }
        LOG_F("LOGIC", "SYNC_FILE %s from %s", filename, sender_ip);
      }
    }
    free(content);
    transfer_build_ack(response, g_node.my_ip, "SYNC_OK");
    return P2P_OK;
  }

  LOG_W("LOGIC", "Unknown type: %s", msg->type);
  transfer_build_nack(response, g_node.my_ip, "UNKNOWN");
  return P2P_ERR;
}

/* ----------------------------------------------------------------
 * CLIENT: get file info
 * ---------------------------------------------------------------- */
int logic_get_file_info(const char *filename, FileEntry *entry_out) {
  LOG_I("LOGIC", "Looking for: %s", filename);

  if (dir_find(filename, entry_out) == P2P_OK && entry_out->is_local)
    return P2P_OK;

  char *get_msg = malloc(MAX_MSG_LEN);
  char *resp_plain = malloc(MAX_MSG_LEN);
  if (!get_msg || !resp_plain) {
    free(get_msg);
    free(resp_plain);
    return P2P_ERR;
  }

  transfer_build_get_info(get_msg, g_node.my_ip, filename);

  /* Try known owner first */
  if (dir_find(filename, entry_out) == P2P_OK && !entry_out->is_local) {
    char owner_ip[MAX_IP_LEN];
    strncpy(owner_ip, entry_out->owner_ip, MAX_IP_LEN - 1);
    if (request(owner_ip, P2P_PORT, get_msg, resp_plain) == P2P_OK) {
      Message resp;
      if (transfer_parse_message(resp_plain, &resp) == P2P_OK &&
          strcmp(resp.type, MSG_INFO_RESP) == 0) {
        transfer_parse_info_payload(resp.payload, entry_out);
        free(get_msg);
        free(resp_plain);
        return P2P_OK;
      }
    }
    dir_general_remove_peer(owner_ip);
  }

  /* Ask all peers */
  for (int i = 0; i < g_node.peer_count; i++) {
    if (!g_node.peers[i].reachable)
      continue;
    if (request(g_node.peers[i].ip, g_node.peers[i].port, get_msg,
                resp_plain) != P2P_OK)
      continue;
    Message resp;
    if (transfer_parse_message(resp_plain, &resp) != P2P_OK)
      continue;
    if (strcmp(resp.type, MSG_INFO_RESP) == 0) {
      transfer_parse_info_payload(resp.payload, entry_out);
      free(get_msg);
      free(resp_plain);
      return P2P_OK;
    }
  }

  free(get_msg);
  free(resp_plain);
  return P2P_NOT_FOUND;
}

/* ----------------------------------------------------------------
 * CLIENT: open (fetch) file
 * ---------------------------------------------------------------- */
int logic_open_file(const char *filename, char *local_path_out) {
  LOG_I("LOGIC", "Opening: %s", filename);

  /* Check if it's a local file */
  FileEntry *own = malloc(MAX_FILES * sizeof(FileEntry));
  if (!own)
    return P2P_ERR;
  int count = dir_own_snapshot(own, MAX_FILES);
  for (int i = 0; i < count; i++) {
    if (strcmp(own[i].name, filename) == 0) {
      snprintf(local_path_out, MAX_PATH_LEN, "%s/%s", g_node.shared_folder,
               filename);
      free(own);
      return P2P_OK;
    }
  }
  free(own);

  /* Remote file */
  FileEntry info;
  if (logic_get_file_info(filename, &info) != P2P_OK)
    return P2P_NOT_FOUND;

  char *get_msg = malloc(MAX_MSG_LEN);
  char *resp_plain = malloc(MAX_MSG_LEN * 2);
  if (!get_msg || !resp_plain) {
    free(get_msg);
    free(resp_plain);
    return P2P_ERR;
  }

  transfer_build_get_file(get_msg, g_node.my_ip, filename);
  int rc = request(info.owner_ip, P2P_PORT, get_msg, resp_plain);
  free(get_msg);

  if (rc != P2P_OK) {
    free(resp_plain);
    return P2P_ERR;
  }

  Message resp;
  if (transfer_parse_message(resp_plain, &resp) != P2P_OK ||
      strcmp(resp.type, MSG_FILE_RESP) != 0) {
    free(resp_plain);
    return P2P_ERR;
  }

  char fname_recv[MAX_FILENAME_LEN];
  unsigned char *content = malloc(MAX_PAYLOAD_LEN);
  long size;
  if (!content) {
    free(resp_plain);
    return P2P_ERR;
  }

  rc = transfer_parse_file_payload(resp.payload, fname_recv, content, &size);
  free(resp_plain);
  if (rc != P2P_OK) {
    free(content);
    return P2P_ERR;
  }

  rc = data_create_temp_copy(filename, info.owner_ip, content, size,
                             local_path_out);
  free(content);
  if (rc != P2P_OK)
    return P2P_ERR;

  pthread_mutex_lock(&g_node.lease_mutex);
  if (g_node.lease_count < 64) {
    FileLease *lease = &g_node.leases[g_node.lease_count++];
    strncpy(lease->original_name, filename, MAX_FILENAME_LEN - 1);
    strncpy(lease->owner_ip, info.owner_ip, MAX_IP_LEN - 1);
    strncpy(lease->local_path, local_path_out, MAX_PATH_LEN - 1);
    lease->checkout_time = time(NULL);
    lease->has_changes = 0;
  }
  pthread_mutex_unlock(&g_node.lease_mutex);
  return P2P_OK;
}

/* ----------------------------------------------------------------
 * CLIENT: close & sync file
 * ---------------------------------------------------------------- */
int logic_close_file(const char *local_path) {
  pthread_mutex_lock(&g_node.lease_mutex);
  int idx = -1;
  for (int i = 0; i < g_node.lease_count; i++)
    if (strcmp(g_node.leases[i].local_path, local_path) == 0) {
      idx = i;
      break;
    }

  if (idx < 0) {
    pthread_mutex_unlock(&g_node.lease_mutex);
    return P2P_OK;
  }

  FileLease lease = g_node.leases[idx];
  g_node.leases[idx] = g_node.leases[--g_node.lease_count];
  pthread_mutex_unlock(&g_node.lease_mutex);

  if (lease.has_changes) {
    long size;
    unsigned char *content = data_read_file(local_path, &size);
    if (content) {
      char *sync_msg = malloc(MAX_MSG_LEN * 2);
      char *resp_plain = malloc(MAX_MSG_LEN);
      if (sync_msg && resp_plain) {
        int n = transfer_build_sync_file(sync_msg, g_node.my_ip,
                                         lease.original_name, content, size,
                                         time(NULL));
        if (n > 0)
          request(lease.owner_ip, P2P_PORT, sync_msg, resp_plain);
      }
      free(sync_msg);
      free(resp_plain);
      free(content);
    }
  }
  data_delete_temp(local_path);
  return P2P_OK;
}

void logic_mark_modified(const char *local_path) {
  pthread_mutex_lock(&g_node.lease_mutex);
  for (int i = 0; i < g_node.lease_count; i++)
    if (strcmp(g_node.leases[i].local_path, local_path) == 0) {
      g_node.leases[i].has_changes = 1;
      break;
    }
  pthread_mutex_unlock(&g_node.lease_mutex);
}

void logic_handle_new_file(const FileEntry *entry, const char *from_ip) {
  dir_general_add(entry);
  LOG_D("DIR", "New file from %s: %s", from_ip, entry->name);
}

void logic_announce_new_file(const FileEntry *entry) {
  char *msg = malloc(MAX_MSG_LEN);
  char *secure = malloc(MAX_MSG_LEN * 2);
  if (!msg || !secure) {
    free(msg);
    free(secure);
    return;
  }
  transfer_build_new_file(msg, g_node.my_ip, entry);
  sec_encrypt(msg, strlen(msg), secure);
  comm_broadcast(secure);
  free(msg);
  free(secure);
}
