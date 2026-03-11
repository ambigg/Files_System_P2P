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
 * HELPER — busca el puerto real de un peer por su IP.
 * Si no lo encuentra en la lista, usa P2P_PORT como fallback.
 * Esto es necesario porque los peers pueden correr en puertos
 * distintos al default (ej: 9090 en lugar de 8080).
 * ========================================================== */
static int get_peer_port(const char *ip) {
  for (int i = 0; i < g_node.peer_count; i++) {
    if (strcmp(g_node.peers[i].ip, ip) == 0)
      return g_node.peers[i].port;
  }
  return P2P_PORT; /* fallback */
}

/* ==========================================================
 * HELPER — cifra, envía, recibe y descifra en un solo paso.
 * Encapsula todo el ciclo de request/response para no
 * repetirlo en cada operación de cliente.
 * ========================================================== */
static int request(const char *ip, int port, const char *msg_plain,
                   char *resp_plain) {
  char secure_out[MAX_MSG_LEN * 2];
  if (sec_encrypt(msg_plain, strlen(msg_plain), secure_out) < 0)
    return P2P_ERR;

  char secure_in[MAX_MSG_LEN * 2];
  int rc = comm_send_recv(ip, port, secure_out, secure_in, sizeof(secure_in));
  if (rc != P2P_OK)
    return rc;

  int plain_len;
  if (sec_is_secure(secure_in)) {
    if (sec_decrypt(secure_in, resp_plain, &plain_len) != P2P_OK)
      return P2P_AUTH_FAIL;
  } else {
    strncpy(resp_plain, secure_in, MAX_MSG_LEN - 1);
  }
  return P2P_OK;
}

/* ==========================================================
 * HANDLE REQUEST — despachador de mensajes entrantes.
 * El hilo de conectividad llama esta función por cada
 * datagrama recibido. Decide qué responder según el tipo.
 * ========================================================== */
int logic_handle_request(const Message *msg, const char *sender_ip,
                         char *response) {
  LOG_I("LOGIC", "Request type=%s from=%s", msg->type, sender_ip);

  /* GET_LIST — devuelve LISTA_OWN completa (siempre autoritativo) */
  if (strcmp(msg->type, MSG_GET_LIST) == 0) {
    FileEntry *own = malloc(MAX_FILES * sizeof(FileEntry));
    if (!own)
      return P2P_ERR;
    int count = dir_own_snapshot(own, MAX_FILES);
    transfer_build_list_resp(response, g_node.my_ip, own, count);
    free(own);
    LOG_D("LOGIC", "GET_LIST → %d files", count);
    return P2P_OK;
  }

  /* GET_INFO — 3 casos: mío / sé quién / no sé */
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

  /* GET_FILE — lee shared/ y responde con contenido en Base64 */
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
    if (rc < 0) {
      transfer_build_nack(response, g_node.my_ip, filename);
      return P2P_ERR;
    }
    LOG_F("LOGIC", "GET_FILE %s → sent (%ld bytes)", filename, size);
    return P2P_OK;
  }

  /* NEW_FILE — otro nodo anuncia un archivo nuevo */
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

  /* SYNC_FILE — recibimos cambios a un archivo nuestro */
  if (strcmp(msg->type, MSG_SYNC_FILE) == 0) {
    char filename[MAX_FILENAME_LEN];
    unsigned char *content = malloc(MAX_PAYLOAD_LEN);
    long size;

    if (!content) {
      transfer_build_ack(response, g_node.my_ip, "SYNC_OK");
      return P2P_OK;
    }

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
        LOG_F("LOGIC", "SYNC_FILE: %s from %s", filename, sender_ip);
      }
    }
    free(content);
    transfer_build_ack(response, g_node.my_ip, "SYNC_OK");
    return P2P_OK;
  }

  LOG_W("LOGIC", "Unknown type: %s", msg->type);
  transfer_build_nack(response, g_node.my_ip, "UNKNOWN_TYPE");
  return P2P_ERR;
}

/* ==========================================================
 * GET FILE INFO — obtiene metadatos de un archivo.
 * Busca primero local, luego pregunta al dueño directamente,
 * si falla recorre todos los peers.
 * ========================================================== */
int logic_get_file_info(const char *filename, FileEntry *entry_out) {
  LOG_I("LOGIC", "Info request: %s", filename);

  if (dir_find(filename, entry_out) == P2P_OK) {
    if (entry_out->is_local)
      return P2P_OK;

    char owner_ip[MAX_IP_LEN];
    strncpy(owner_ip, entry_out->owner_ip, MAX_IP_LEN - 1);
    int owner_port = get_peer_port(owner_ip); /* FIX: puerto real del dueño */

    char get_msg[MAX_MSG_LEN];
    transfer_build_get_info(get_msg, g_node.my_ip, filename);

    char resp_plain[MAX_MSG_LEN];
    if (request(owner_ip, owner_port, get_msg, resp_plain) == P2P_OK) {
      Message resp;
      if (transfer_parse_message(resp_plain, &resp) == P2P_OK &&
          strcmp(resp.type, MSG_INFO_RESP) == 0) {
        transfer_parse_info_payload(resp.payload, entry_out);
        return P2P_OK;
      }
    }
    dir_general_remove_peer(owner_ip);
  }

  /* Si el dueño no respondió, preguntamos a todos los peers */
  char get_msg[MAX_MSG_LEN];
  transfer_build_get_info(get_msg, g_node.my_ip, filename);

  for (int i = 0; i < g_node.peer_count; i++) {
    char resp_plain[MAX_MSG_LEN];
    int rc =
        request(g_node.peers[i].ip, g_node.peers[i].port, get_msg, resp_plain);
    if (rc != P2P_OK)
      continue;

    Message resp;
    if (transfer_parse_message(resp_plain, &resp) != P2P_OK)
      continue;

    if (strcmp(resp.type, MSG_INFO_RESP) == 0) {
      transfer_parse_info_payload(resp.payload, entry_out);
      return P2P_OK;
    }

    if (strcmp(resp.type, MSG_INFO_REDIR) == 0) {
      char buf[MAX_PAYLOAD_LEN];
      strncpy(buf, resp.payload, MAX_PAYLOAD_LEN - 1);
      char *rest = buf;
      strsep(&rest, "|");
      char *owner = strsep(&rest, "|");
      if (!owner)
        continue;

      int redir_port =
          get_peer_port(owner); /* FIX: puerto real del redirigido */
      char resp2_plain[MAX_MSG_LEN];
      if (request(owner, redir_port, get_msg, resp2_plain) != P2P_OK)
        continue;

      Message resp2;
      if (transfer_parse_message(resp2_plain, &resp2) == P2P_OK &&
          strcmp(resp2.type, MSG_INFO_RESP) == 0) {
        transfer_parse_info_payload(resp2.payload, entry_out);
        return P2P_OK;
      }
    }
  }

  return P2P_NOT_FOUND;
}

/* ==========================================================
 * OPEN FILE — abre un archivo local o remoto de forma
 * transparente para el usuario.
 * Si es local: devuelve la ruta en shared/.
 * Si es remoto: descarga con GET_FILE, guarda en tmp/,
 * registra lease y devuelve la ruta temporal.
 * ========================================================== */
int logic_open_file(const char *filename, char *local_path_out) {
  LOG_I("LOGIC", "Opening: %s", filename);

  /* Revisar si es un archivo propio */
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

  /* Archivo remoto — obtener info del dueño */
  FileEntry info;
  if (logic_get_file_info(filename, &info) != P2P_OK)
    return P2P_NOT_FOUND;

  int owner_port =
      get_peer_port(info.owner_ip); /* FIX: puerto real del dueño */

  char get_msg[MAX_MSG_LEN];
  transfer_build_get_file(get_msg, g_node.my_ip, filename);

  char resp_plain[MAX_MSG_LEN * 2];
  if (request(info.owner_ip, owner_port, get_msg, resp_plain) != P2P_OK)
    return P2P_ERR;

  Message resp;
  if (transfer_parse_message(resp_plain, &resp) != P2P_OK)
    return P2P_ERR;
  if (strcmp(resp.type, MSG_NACK) == 0)
    return P2P_NOT_FOUND;
  if (strcmp(resp.type, MSG_FILE_RESP) != 0)
    return P2P_ERR;

  char fname_recv[MAX_FILENAME_LEN];
  unsigned char *content = malloc(MAX_PAYLOAD_LEN);
  if (!content)
    return P2P_ERR;
  long size;

  if (transfer_parse_file_payload(resp.payload, fname_recv, content, &size) !=
      P2P_OK) {
    free(content);
    return P2P_ERR;
  }

  int rc = data_create_temp_copy(filename, info.owner_ip, content, size,
                                 local_path_out);
  free(content);
  if (rc != P2P_OK)
    return P2P_ERR;

  /* Registrar lease con IP y puerto del dueño para el SYNC_FILE posterior */
  pthread_mutex_lock(&g_node.lease_mutex);
  if (g_node.lease_count < 64) {
    FileLease *lease = &g_node.leases[g_node.lease_count++];
    strncpy(lease->original_name, filename, MAX_FILENAME_LEN - 1);
    strncpy(lease->owner_ip, info.owner_ip, MAX_IP_LEN - 1);
    lease->owner_port = owner_port; /* FIX: guardar puerto para SYNC_FILE */
    strncpy(lease->local_path, local_path_out, MAX_PATH_LEN - 1);
    lease->checkout_time = time(NULL);
    lease->has_changes = 0;
  }
  pthread_mutex_unlock(&g_node.lease_mutex);

  return P2P_OK;
}

/* ==========================================================
 * CLOSE FILE — cierra el archivo y, si hubo cambios,
 * envía SYNC_FILE al dueño original. Siempre elimina el temporal.
 * ========================================================== */
int logic_close_file(const char *local_path) {
  pthread_mutex_lock(&g_node.lease_mutex);

  int idx = -1;
  for (int i = 0; i < g_node.lease_count; i++) {
    if (strcmp(g_node.leases[i].local_path, local_path) == 0) {
      idx = i;
      break;
    }
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
      char sync_msg[MAX_MSG_LEN * 2];
      int n =
          transfer_build_sync_file(sync_msg, g_node.my_ip, lease.original_name,
                                   content, size, time(NULL));
      free(content);
      if (n > 0) {
        char resp_plain[MAX_MSG_LEN];
        /* FIX: usar el puerto guardado en el lease, no P2P_PORT hardcodeado */
        request(lease.owner_ip, lease.owner_port, sync_msg, resp_plain);
        LOG_F("LOGIC", "SYNC_FILE → %s:%d", lease.owner_ip, lease.owner_port);
      }
    }
  }

  data_delete_temp(local_path);
  return P2P_OK;
}

/* ==========================================================
 * MARK MODIFIED — marca que el archivo temporal fue modificado.
 * Llamado por presentación después de que el editor cierra.
 * ========================================================== */
void logic_mark_modified(const char *local_path) {
  pthread_mutex_lock(&g_node.lease_mutex);
  for (int i = 0; i < g_node.lease_count; i++) {
    if (strcmp(g_node.leases[i].local_path, local_path) == 0) {
      g_node.leases[i].has_changes = 1;
      break;
    }
  }
  pthread_mutex_unlock(&g_node.lease_mutex);
}

/* ==========================================================
 * HANDLE NEW FILE — agrega a LISTA_GENERAL cuando llega
 * una notificación NEW_FILE de otro nodo.
 * ========================================================== */
void logic_handle_new_file(const FileEntry *entry, const char *from_ip) {
  dir_general_add(entry);
  LOG_D("DIR", "New file from %s: %s", from_ip, entry->name);
}

/* ==========================================================
 * ANNOUNCE NEW FILE — broadcast a todos los peers cuando
 * el hilo de sistema detecta un archivo nuevo en shared/.
 * ========================================================== */
void logic_announce_new_file(const FileEntry *entry) {
  char msg[MAX_MSG_LEN];
  transfer_build_new_file(msg, g_node.my_ip, entry);
  char secure[MAX_MSG_LEN * 2];
  sec_encrypt(msg, strlen(msg), secure);
  comm_broadcast(secure);
  LOG_D("DIR", "Announced: %s", entry->name);
}
