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

/* ==========================================================
 * INTERNAL HELPERS
 * Encapsulate the encrypt → send → receive → decrypt pattern
 * that is repeated in all client operations.
 * ========================================================== */

/*
 * Sends a message to a peer and receives its response.
 * Encrypts the outgoing message and decrypts the incoming one.
 * resp_plain must have at least MAX_MSG_LEN bytes.
 */
static int request(const char *ip, int port, const char *msg_plain,
                   char *resp_plain) {
  /* Encrypt output */
  char secure_out[MAX_MSG_LEN * 2];
  if (sec_encrypt(msg_plain, strlen(msg_plain), secure_out) < 0) {
    LOG_E("LOGIC", "Error encrypting message for %s", ip);
    return P2P_ERR;
  }

  /* Send and receive */
  char secure_in[MAX_MSG_LEN * 2];
  int rc = comm_send_recv(ip, port, secure_out, secure_in, sizeof(secure_in));
  if (rc != P2P_OK)
    return rc;

  /* Decrypt input */
  int plain_len;
  if (sec_is_secure(secure_in)) {
    if (sec_decrypt(secure_in, resp_plain, &plain_len) != P2P_OK) {
      LOG_E("LOGIC", "Invalid CRC in response from %s", ip);
      return P2P_AUTH_FAIL;
    }
  } else {
    /* Accept plain text only in development/debug */
    strncpy(resp_plain, secure_in, MAX_MSG_LEN - 1);
  }

  return P2P_OK;
}

/*
 * Sends a message without waiting for a response (for broadcasts).
 */
static int notify(const char *ip, int port, const char *msg_plain) {
  char secure[MAX_MSG_LEN * 2];
  if (sec_encrypt(msg_plain, strlen(msg_plain), secure) < 0)
    return P2P_ERR;
  return comm_send(ip, port, secure);
}

/* ==========================================================
 * SERVER — HANDLE REQUEST
 * Decides what to respond according to the received message type.
 * ========================================================== */
int logic_handle_request(const Message *msg, const char *sender_ip,
                         char *response) {
  LOG_I("LOGIC", "Request type=%s from=%s", msg->type, sender_ip);

  /* ── GET_LIST: return my OWN_LIST ── */
  if (strcmp(msg->type, MSG_GET_LIST) == 0) {
    FileEntry own[MAX_FILES];
    int count = dir_own_snapshot(own, MAX_FILES);
    transfer_build_list_resp(response, g_node.my_ip, own, count);
    LOG_D("LOGIC", "GET_LIST responded: %d files", count);
    return P2P_OK;
  }

  /* ── GET_INFO: look for the file ── */
  if (strcmp(msg->type, MSG_GET_INFO) == 0) {
    const char *filename = msg->payload;
    FileEntry found;

    if (dir_find(filename, &found) == P2P_OK) {
      if (found.is_local) {
        /* I have it → authoritative response */
        strncpy(found.owner_ip, g_node.my_ip, MAX_IP_LEN - 1);
        transfer_build_info_resp(response, g_node.my_ip, &found);
        LOG_D("LOGIC", "GET_INFO %s → authoritative INFO_RESP", filename);
      } else {
        /* I know who owns it → redirect */
        transfer_build_info_redir(response, g_node.my_ip, filename,
                                  found.owner_ip);
        LOG_D("LOGIC", "GET_INFO %s → INFO_REDIR to %s", filename,
              found.owner_ip);
      }
    } else {
      /* I don't know it */
      transfer_build_nack(response, g_node.my_ip, filename);
      LOG_D("LOGIC", "GET_INFO %s → NACK", filename);
    }
    return P2P_OK;
  }

  /* ── GET_FILE: send the file content ── */
  if (strcmp(msg->type, MSG_GET_FILE) == 0) {
    const char *filename = msg->payload;

    /* I can only send files that are mine */
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s", g_node.shared_folder, filename);

    long size;
    unsigned char *content = data_read_file(path, &size);
    if (!content) {
      transfer_build_nack(response, g_node.my_ip, filename);
      LOG_W("LOGIC", "GET_FILE %s → not found", filename);
      return P2P_NOT_FOUND;
    }

    int rc = transfer_build_file_resp(response, g_node.my_ip, filename, content,
                                      size);
    free(content);

    if (rc < 0) {
      transfer_build_nack(response, g_node.my_ip, filename);
      return P2P_ERR;
    }

    LOG_F("LOGIC", "GET_FILE %s → sent (%ld bytes)", filename, size);
    return P2P_OK;
  }

  /* ── NEW_FILE: a peer shares a new file ── */
  if (strcmp(msg->type, MSG_NEW_FILE) == 0) {
    FileEntry entry;
    /* NEW_FILE payload has the same format as INFO_RESP */
    if (transfer_parse_info_payload(msg->payload, &entry) == P2P_OK) {
      strncpy(entry.owner_ip, sender_ip, MAX_IP_LEN - 1);
      entry.is_local = 0;
      logic_handle_new_file(&entry, sender_ip);
    }
    transfer_build_ack(response, g_node.my_ip, "OK");
    return P2P_OK;
  }

  /* ── SYNC_FILE: receive changes of a copy I lent ── */
  if (strcmp(msg->type, MSG_SYNC_FILE) == 0) {
    char filename[MAX_FILENAME_LEN];
    unsigned char content[MAX_PAYLOAD_LEN];
    long size;

    if (transfer_parse_file_payload(msg->payload, filename, content, &size) ==
        P2P_OK) {
      char path[MAX_PATH_LEN];
      snprintf(path, sizeof(path), "%s/%s", g_node.shared_folder, filename);

      if (data_write_file(path, content, size) == P2P_OK) {
        /* Update metadata in OWN_LIST */
        FileEntry updated;
        if (data_stat_file(path, &updated) == P2P_OK) {
          dir_own_add(&updated);
          dir_save_own();
        }
        LOG_F("LOGIC", "SYNC_FILE: %s updated from %s", filename, sender_ip);
      }
    }

    transfer_build_ack(response, g_node.my_ip, "SYNC_OK");
    return P2P_OK;
  }

  /* Unknown type */
  LOG_W("LOGIC", "Unknown message type: %s", msg->type);
  transfer_build_nack(response, g_node.my_ip, "UNKNOWN_TYPE");
  return P2P_ERR;
}

/* ==========================================================
 * CLIENT — GET FILE INFO
 *
 * Search order:
 *   1. OWN_LIST (authoritative, no network)
 *   2. GENERAL_LIST → ask the owner directly
 *   3. Ask every peer until found
 * ========================================================== */
int logic_get_file_info(const char *filename, FileEntry *entry_out) {
  LOG_I("LOGIC", "Looking for info: %s", filename);

  /* 1. Search locally */
  if (dir_find(filename, entry_out) == P2P_OK) {
    if (entry_out->is_local) {
      LOG_D("LOGIC", "%s found locally", filename);
      return P2P_OK;
    }

    /* It is in GENERAL_LIST — we have the owner's IP */
    char owner_ip[MAX_IP_LEN];
    strncpy(owner_ip, entry_out->owner_ip, MAX_IP_LEN - 1);

    /* Ask the owner directly for an authoritative response */
    char get_msg[MAX_MSG_LEN];
    transfer_build_get_info(get_msg, g_node.my_ip, filename);

    char resp_plain[MAX_MSG_LEN];
    if (request(owner_ip, P2P_PORT, get_msg, resp_plain) == P2P_OK) {
      Message resp;
      if (transfer_parse_message(resp_plain, &resp) == P2P_OK &&
          strcmp(resp.type, MSG_INFO_RESP) == 0) {
        transfer_parse_info_payload(resp.payload, entry_out);
        LOG_D("LOGIC", "%s → authoritative info from %s", filename, owner_ip);
        return P2P_OK;
      }
    }

    /* The owner did not respond — maybe he no longer has the file */
    LOG_W("LOGIC", "Owner %s did not respond for %s", owner_ip, filename);
    dir_general_remove_peer(owner_ip);
  }

  /* 2. Ask all peers */
  char get_msg[MAX_MSG_LEN];
  transfer_build_get_info(get_msg, g_node.my_ip, filename);

  for (int i = 0; i < g_node.peer_count; i++) {
    if (!g_node.peers[i].reachable)
      continue;

    char resp_plain[MAX_MSG_LEN];
    int rc =
        request(g_node.peers[i].ip, g_node.peers[i].port, get_msg, resp_plain);
    if (rc != P2P_OK)
      continue;

    Message resp;
    if (transfer_parse_message(resp_plain, &resp) != P2P_OK)
      continue;

    if (strcmp(resp.type, MSG_INFO_RESP) == 0) {
      /* Authoritative response */
      transfer_parse_info_payload(resp.payload, entry_out);
      LOG_D("LOGIC", "%s → authoritative from %s", filename,
            g_node.peers[i].ip);
      return P2P_OK;
    }

    if (strcmp(resp.type, MSG_INFO_REDIR) == 0) {
      /* We are redirected to the real owner */
      char buf[MAX_PAYLOAD_LEN];
      strncpy(buf, resp.payload, MAX_PAYLOAD_LEN - 1);
      char *rest = buf;
      strsep(&rest, "|"); /* skip filename */
      char *owner = strsep(&rest, "|");

      if (!owner)
        continue;

      char resp2_plain[MAX_MSG_LEN];
      if (request(owner, P2P_PORT, get_msg, resp2_plain) != P2P_OK)
        continue;

      Message resp2;
      if (transfer_parse_message(resp2_plain, &resp2) == P2P_OK &&
          strcmp(resp2.type, MSG_INFO_RESP) == 0) {
        transfer_parse_info_payload(resp2.payload, entry_out);
        LOG_D("LOGIC", "%s → authoritative (via redirect) from %s", filename,
              owner);
        return P2P_OK;
      }
    }
    /* MSG_NACK: this peer does not have it, continue with next */
  }

  LOG_W("LOGIC", "%s not found in the network", filename);
  return P2P_NOT_FOUND;
}

/* ==========================================================
 * CLIENT — OPEN FILE
 * ========================================================== */
int logic_open_file(const char *filename, char *local_path_out) {
  LOG_I("LOGIC", "Opening: %s", filename);

  /* Is it mine? → direct path, no copy */
  FileEntry *own = malloc(MAX_FILES * sizeof(FileEntry));
  if (!own)
    return P2P_ERR;
  int count = dir_own_snapshot(own, MAX_FILES);
  for (int i = 0; i < count; i++) {
    if (strcmp(own[i].name, filename) == 0) {
      snprintf(local_path_out, MAX_PATH_LEN, "%s/%s", g_node.shared_folder,
               filename);
      LOG_F("LOGIC", "Local file: %s", local_path_out);
      free(own);
      return P2P_OK;
    }
  }
  free(own);

  /* It is remote — find owner */
  FileEntry info;
  if (logic_get_file_info(filename, &info) != P2P_OK)
    return P2P_NOT_FOUND;

  /* Request the content from the owner */
  char get_msg[MAX_MSG_LEN];
  transfer_build_get_file(get_msg, g_node.my_ip, filename);

  char resp_plain[MAX_MSG_LEN * 2];
  if (request(info.owner_ip, P2P_PORT, get_msg, resp_plain) != P2P_OK) {
    LOG_E("LOGIC", "Could not fetch %s from %s", filename, info.owner_ip);
    return P2P_ERR;
  }

  /* Parse the response */
  Message resp;
  if (transfer_parse_message(resp_plain, &resp) != P2P_OK)
    return P2P_ERR;

  if (strcmp(resp.type, MSG_NACK) == 0) {
    LOG_W("LOGIC", "%s is no longer on %s", filename, info.owner_ip);
    return P2P_NOT_FOUND;
  }

  if (strcmp(resp.type, MSG_FILE_RESP) != 0)
    return P2P_ERR;

  /* Decode content */
  char fname_recv[MAX_FILENAME_LEN];
  unsigned char content[MAX_PAYLOAD_LEN];
  long size;

  if (transfer_parse_file_payload(resp.payload, fname_recv, content, &size) !=
      P2P_OK)
    return P2P_ERR;

  /* Save as temporary copy */
  if (data_create_temp_copy(filename, info.owner_ip, content, size,
                            local_path_out) != P2P_OK)
    return P2P_ERR;

  /* Register lease */
  pthread_mutex_lock(&g_node.lease_mutex);
  if (g_node.lease_count < 64) {
    FileLease *lease = &g_node.leases[g_node.lease_count++];
    strncpy(lease->original_name, filename, MAX_FILENAME_LEN - 1);
    strncpy(lease->owner_ip, info.owner_ip, MAX_IP_LEN - 1);
    strncpy(lease->local_path, local_path_out, MAX_PATH_LEN - 1);
    lease->checkout_time = time(NULL);
    lease->has_changes = 0;
    LOG_F("LOGIC", "Lease registered: %s from %s", filename, info.owner_ip);
  }
  pthread_mutex_unlock(&g_node.lease_mutex);

  return P2P_OK;
}

/* ==========================================================
 * CLIENT — CLOSE FILE AND SYNCHRONIZE
 * ========================================================== */
int logic_close_file(const char *local_path) {
  pthread_mutex_lock(&g_node.lease_mutex);

  /* Find the lease */
  int idx = -1;
  for (int i = 0; i < g_node.lease_count; i++) {
    if (strcmp(g_node.leases[i].local_path, local_path) == 0) {
      idx = i;
      break;
    }
  }

  if (idx < 0) {
    pthread_mutex_unlock(&g_node.lease_mutex);
    /* Local file — nothing to synchronize */
    LOG_F("LOGIC", "Close local file: %s", local_path);
    return P2P_OK;
  }

  /* Copy the lease and remove it from the list */
  FileLease lease = g_node.leases[idx];
  g_node.leases[idx] = g_node.leases[--g_node.lease_count];
  pthread_mutex_unlock(&g_node.lease_mutex);

  /* If there were changes, synchronize with the owner */
  if (lease.has_changes) {
    long size;
    unsigned char *content = data_read_file(local_path, &size);

    if (content) {
      char sync_msg[MAX_MSG_LEN * 2];
      int n =
          transfer_build_sync_file(sync_msg, g_node.my_ip, lease.original_name,
                                   content, size, time(NULL));
      free(content);

      if (n > 0) {
        char resp_plain[MAX_MSG_LEN];
        int rc = request(lease.owner_ip, P2P_PORT, sync_msg, resp_plain);
        if (rc == P2P_OK)
          LOG_F("LOGIC", "SYNC_FILE sent: %s → %s", lease.original_name,
                lease.owner_ip);
        else
          LOG_E("LOGIC", "Error synchronizing %s with %s", lease.original_name,
                lease.owner_ip);
      }
    }
  } else {
    LOG_F("LOGIC", "No changes in %s, not synchronizing", lease.original_name);
  }

  /* Always delete temporary copy */
  data_delete_temp(local_path);
  return P2P_OK;
}

/* ==========================================================
 * MARK AS MODIFIED
 * ========================================================== */
void logic_mark_modified(const char *local_path) {
  pthread_mutex_lock(&g_node.lease_mutex);
  for (int i = 0; i < g_node.lease_count; i++) {
    if (strcmp(g_node.leases[i].local_path, local_path) == 0) {
      g_node.leases[i].has_changes = 1;
      LOG_F("LOGIC", "File marked as modified: %s", local_path);
      break;
    }
  }
  pthread_mutex_unlock(&g_node.lease_mutex);
}

/* ==========================================================
 * NOTIFICATIONS
 * ========================================================== */
void logic_handle_new_file(const FileEntry *entry, const char *from_ip) {
  dir_general_add(entry);
  LOG_D("DIR", "New file from %s: %s", from_ip, entry->name);
}

void logic_announce_new_file(const FileEntry *entry) {
  char msg[MAX_MSG_LEN];
  transfer_build_new_file(msg, g_node.my_ip, entry);

  char secure[MAX_MSG_LEN * 2];
  sec_encrypt(msg, strlen(msg), secure);
  int sent_count = comm_broadcast(secure);

  LOG_D("DIR", "Announced %s to %d peers", entry->name, sent_count);
}
