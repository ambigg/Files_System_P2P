#include "../include/directory.h"
#include "../include/data.h"
#include "../include/log.h"
#include "../include/protocol.h"
#include "../include/structures.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

/* ==========================================================
 * INITIALIZATION
 * ========================================================== */
void dir_init(void) {
  pthread_mutex_init(&g_node.dir.own_mutex, NULL);
  pthread_mutex_init(&g_node.dir.general_mutex, NULL);
  g_node.dir.own_count = 0;
  g_node.dir.general_count = 0;
  LOG_I("DIR", "Directory initialized");
}

/* ==========================================================
 * OWN LIST — SCAN
 * Escanea shared/ y reconstruye LISTA_OWN desde cero
 * leyendo los archivos reales en disco.
 * ========================================================== */
void dir_scan_own(void) {
  DIR *dp = opendir(g_node.shared_folder);
  if (!dp) {
    LOG_E("DIR", "Could not open folder: %s", g_node.shared_folder);
    return;
  }

  pthread_mutex_lock(&g_node.dir.own_mutex);
  g_node.dir.own_count = 0;

  struct dirent *entry;
  while ((entry = readdir(dp)) != NULL) {
    if (entry->d_name[0] == '.')
      continue;

    char full_path[MAX_PATH_LEN];
    snprintf(full_path, sizeof(full_path), "%s/%s", g_node.shared_folder,
             entry->d_name);

    struct stat st;
    if (stat(full_path, &st) != 0)
      continue;
    if (S_ISDIR(st.st_mode))
      continue;

    if (g_node.dir.own_count >= MAX_FILES) {
      LOG_W("DIR", "OWN_LIST full, ignoring %s", entry->d_name);
      break;
    }

    FileEntry *e = &g_node.dir.own_list[g_node.dir.own_count];
    if (data_stat_file(full_path, e) == P2P_OK)
      g_node.dir.own_count++;
  }

  closedir(dp);
  pthread_mutex_unlock(&g_node.dir.own_mutex);

  LOG_D("DIR", "Own scan: %d files in %s", g_node.dir.own_count,
        g_node.shared_folder);
}

/* ==========================================================
 * OWN LIST — LOAD AND PERSISTENCE
 * ========================================================== */
void dir_load_own(void) {
  pthread_mutex_lock(&g_node.dir.own_mutex);
  g_node.dir.own_count =
      data_load_own_list(g_node.own_list_file, g_node.dir.own_list, MAX_FILES);
  pthread_mutex_unlock(&g_node.dir.own_mutex);

  LOG_D("DIR", "OWN_LIST loaded: %d files", g_node.dir.own_count);
}

void dir_save_own(void) {
  pthread_mutex_lock(&g_node.dir.own_mutex);
  data_save_own_list(g_node.own_list_file, g_node.dir.own_list,
                     g_node.dir.own_count);
  pthread_mutex_unlock(&g_node.dir.own_mutex);
}

/* ==========================================================
 * OWN LIST — ADD / REMOVE
 * ========================================================== */
void dir_own_add(const FileEntry *entry) {
  pthread_mutex_lock(&g_node.dir.own_mutex);

  for (int i = 0; i < g_node.dir.own_count; i++) {
    if (strcmp(g_node.dir.own_list[i].name, entry->name) == 0) {
      g_node.dir.own_list[i] = *entry;
      pthread_mutex_unlock(&g_node.dir.own_mutex);
      LOG_D("DIR", "OWN updated: %s", entry->name);
      return;
    }
  }

  if (g_node.dir.own_count < MAX_FILES) {
    g_node.dir.own_list[g_node.dir.own_count++] = *entry;
    LOG_D("DIR", "OWN added: %s", entry->name);
  } else {
    LOG_W("DIR", "OWN_LIST full, could not add: %s", entry->name);
  }

  pthread_mutex_unlock(&g_node.dir.own_mutex);
}

void dir_own_remove(const char *filename) {
  pthread_mutex_lock(&g_node.dir.own_mutex);

  for (int i = 0; i < g_node.dir.own_count; i++) {
    if (strcmp(g_node.dir.own_list[i].name, filename) == 0) {
      g_node.dir.own_list[i] = g_node.dir.own_list[--g_node.dir.own_count];
      LOG_D("DIR", "OWN removed: %s", filename);
      break;
    }
  }

  pthread_mutex_unlock(&g_node.dir.own_mutex);
}

/* ==========================================================
 * OWN LIST — THREAD-SAFE SNAPSHOT
 * Copia LISTA_OWN a un buffer externo para que el caller
 * pueda trabajar con ella sin mantener el mutex.
 * ========================================================== */
int dir_own_snapshot(FileEntry *out, int max) {
  pthread_mutex_lock(&g_node.dir.own_mutex);
  int n = (g_node.dir.own_count < max) ? g_node.dir.own_count : max;
  memcpy(out, g_node.dir.own_list, n * sizeof(FileEntry));
  pthread_mutex_unlock(&g_node.dir.own_mutex);
  return n;
}

/* ==========================================================
 * GENERAL LIST — UPDATE FROM A PEER
 * Estrategia: borra todo lo del peer e inserta los nuevos.
 * Maneja en una sola operación: archivos nuevos, eliminados
 * y cambios de metadatos.
 * ========================================================== */
void dir_general_update_from_peer(const char *peer_ip, const FileEntry *files,
                                  int count) {
  pthread_mutex_lock(&g_node.dir.general_mutex);

  /* Paso 1: eliminar todo lo de este peer */
  for (int i = 0; i < g_node.dir.general_count;) {
    if (strcmp(g_node.dir.general_list[i].owner_ip, peer_ip) == 0) {
      g_node.dir.general_list[i] =
          g_node.dir.general_list[--g_node.dir.general_count];
    } else {
      i++;
    }
  }

  /* Paso 2: insertar los nuevos */
  for (int i = 0; i < count; i++) {
    if (g_node.dir.general_count >= MAX_FILES) {
      LOG_W("DIR", "GENERAL_LIST full, discarding files from %s", peer_ip);
      break;
    }
    FileEntry e = files[i];
    strncpy(e.owner_ip, peer_ip, MAX_IP_LEN - 1);
    e.is_local = 0;
    e.last_verified = time(NULL);
    g_node.dir.general_list[g_node.dir.general_count++] = e;
  }

  pthread_mutex_unlock(&g_node.dir.general_mutex);

  LOG_D("DIR", "GENERAL updated from %s: %d files", peer_ip, count);
}

/* ==========================================================
 * GENERAL LIST — REMOVE AN ENTIRE PEER
 * Se llama cuando un peer no responde.
 * ========================================================== */
void dir_general_remove_peer(const char *peer_ip) {
  pthread_mutex_lock(&g_node.dir.general_mutex);

  int removed = 0;
  for (int i = 0; i < g_node.dir.general_count;) {
    if (strcmp(g_node.dir.general_list[i].owner_ip, peer_ip) == 0) {
      LOG_D("DIR", "GENERAL removed: %s (peer %s down)",
            g_node.dir.general_list[i].name, peer_ip);
      g_node.dir.general_list[i] =
          g_node.dir.general_list[--g_node.dir.general_count];
      removed++;
    } else {
      i++;
    }
  }

  pthread_mutex_unlock(&g_node.dir.general_mutex);

  LOG_D("DIR", "GENERAL: %d files removed from peer %s", removed, peer_ip);
}

/* ==========================================================
 * GENERAL LIST — ADD A SINGLE ENTRY
 * Para cuando llega una notificación NEW_FILE.
 * ========================================================== */
void dir_general_add(const FileEntry *entry) {
  pthread_mutex_lock(&g_node.dir.general_mutex);

  for (int i = 0; i < g_node.dir.general_count; i++) {
    if (strcmp(g_node.dir.general_list[i].name, entry->name) == 0 &&
        strcmp(g_node.dir.general_list[i].owner_ip, entry->owner_ip) == 0) {
      g_node.dir.general_list[i] = *entry;
      pthread_mutex_unlock(&g_node.dir.general_mutex);
      LOG_D("DIR", "GENERAL updated: %s from %s", entry->name, entry->owner_ip);
      return;
    }
  }

  if (g_node.dir.general_count < MAX_FILES) {
    g_node.dir.general_list[g_node.dir.general_count++] = *entry;
    LOG_D("DIR", "GENERAL added: %s from %s", entry->name, entry->owner_ip);
  }

  pthread_mutex_unlock(&g_node.dir.general_mutex);
}

/* ==========================================================
 * SEARCH IN BOTH LISTS
 * Busca primero en LISTA_OWN (siempre autoritativa),
 * luego en LISTA_GENERAL.
 * ========================================================== */
int dir_find(const char *filename, FileEntry *found_out) {
  pthread_mutex_lock(&g_node.dir.own_mutex);
  for (int i = 0; i < g_node.dir.own_count; i++) {
    if (strcmp(g_node.dir.own_list[i].name, filename) == 0) {
      *found_out = g_node.dir.own_list[i];
      pthread_mutex_unlock(&g_node.dir.own_mutex);
      LOG_D("DIR", "FIND %s → LOCAL (authoritative)", filename);
      return P2P_OK;
    }
  }
  pthread_mutex_unlock(&g_node.dir.own_mutex);

  pthread_mutex_lock(&g_node.dir.general_mutex);
  for (int i = 0; i < g_node.dir.general_count; i++) {
    if (strcmp(g_node.dir.general_list[i].name, filename) == 0) {
      *found_out = g_node.dir.general_list[i];
      pthread_mutex_unlock(&g_node.dir.general_mutex);
      LOG_D("DIR", "FIND %s → %s", filename, found_out->owner_ip);
      return P2P_OK;
    }
  }
  pthread_mutex_unlock(&g_node.dir.general_mutex);

  LOG_D("DIR", "FIND %s → not found", filename);
  return P2P_NOT_FOUND;
}

/* ==========================================================
 * COMPLETE SNAPSHOT — LISTA_OWN + LISTA_GENERAL
 * Para mostrar el directorio completo al usuario.
 * ========================================================== */
int dir_general_snapshot(FileEntry *out, int max) {
  int n = dir_own_snapshot(out, max);

  pthread_mutex_lock(&g_node.dir.general_mutex);
  for (int i = 0; i < g_node.dir.general_count && n < max; i++) {
    out[n++] = g_node.dir.general_list[i];
  }
  pthread_mutex_unlock(&g_node.dir.general_mutex);

  return n;
}

/* ==========================================================
 * GENERAL LIST — SAVE TO DISK
 * Persiste LISTA_GENERAL en config/general.txt.
 * Formato: name|ext|size|date_created|date_modified|ttl|owner_ip
 * Llamar al final de update_all_lists() para que el directorio
 * de red sobreviva reinicios del nodo.
 * ========================================================== */
void dir_save_general(void) {
  /* Construir ruta: shared/ está en g_node.shared_folder,
   * config/ es un nivel arriba o hermano — usamos el mismo
   * directorio base que own_list_file para consistencia. */
  char path[MAX_PATH_LEN];
  snprintf(path, sizeof(path), "%s/../config/general.txt",
           g_node.shared_folder);

  pthread_mutex_lock(&g_node.dir.general_mutex);
  FILE *f = fopen(path, "w");
  if (!f) {
    pthread_mutex_unlock(&g_node.dir.general_mutex);
    LOG_E("DIR", "Could not save GENERAL_LIST to %s", path);
    return;
  }

  for (int i = 0; i < g_node.dir.general_count; i++) {
    FileEntry *e = &g_node.dir.general_list[i];
    fprintf(f, "%s|%s|%ld|%ld|%ld|%d|%s\n", e->name, e->ext, e->size,
            (long)e->date_created, (long)e->date_modified, e->ttl, e->owner_ip);
  }

  fclose(f);
  pthread_mutex_unlock(&g_node.dir.general_mutex);

  LOG_D("DIR", "GENERAL_LIST saved: %d files", g_node.dir.general_count);
}

/* ==========================================================
 * GENERAL LIST — LOAD FROM DISK
 * Carga LISTA_GENERAL desde config/general.txt.
 * Llamar al arrancar, después de dir_load_own(), para tener
 * el último estado conocido de la red antes de que los peers
 * respondan.
 * ========================================================== */
void dir_load_general(void) {
  char path[MAX_PATH_LEN];
  snprintf(path, sizeof(path), "%s/../config/general.txt",
           g_node.shared_folder);

  FILE *f = fopen(path, "r");
  if (!f) {
    LOG_D("DIR", "No GENERAL_LIST file found at %s (first run)", path);
    return;
  }

  pthread_mutex_lock(&g_node.dir.general_mutex);
  g_node.dir.general_count = 0;

  char line[512];
  while (fgets(line, sizeof(line), f) && g_node.dir.general_count < MAX_FILES) {
    /* Quitar el \n del final */
    line[strcspn(line, "\n")] = '\0';
    if (line[0] == '\0')
      continue;

    FileEntry e;
    memset(&e, 0, sizeof(e));
    e.is_local = 0;

    long created, modified;
    int parsed =
        sscanf(line, "%127[^|]|%15[^|]|%ld|%ld|%ld|%d|%47[^\n]", e.name, e.ext,
               &e.size, &created, &modified, &e.ttl, e.owner_ip);
    if (parsed == 7) {
      e.date_created = (time_t)created;
      e.date_modified = (time_t)modified;
      e.last_verified = time(NULL);
      g_node.dir.general_list[g_node.dir.general_count++] = e;
    }
  }

  fclose(f);
  pthread_mutex_unlock(&g_node.dir.general_mutex);

  LOG_D("DIR", "GENERAL_LIST loaded: %d files", g_node.dir.general_count);
}

/* ==========================================================
 * TTL — DECREMENT AND DETECT EXPIRED ENTRIES
 * Llamado periódicamente desde el hilo de conectividad.
 * TTL=0 significa permanente, no se toca.
 * ========================================================== */
int dir_tick_ttl(FileEntry *expired_out, int max) {
  int expired = 0;

  pthread_mutex_lock(&g_node.dir.general_mutex);

  for (int i = 0; i < g_node.dir.general_count;) {
    FileEntry *e = &g_node.dir.general_list[i];

    if (e->ttl == TTL_PERMANENT) {
      i++;
      continue;
    }

    e->ttl--;

    if (e->ttl <= 0) {
      LOG_D("DIR", "TTL expired: %s from %s", e->name, e->owner_ip);
      if (expired < max)
        expired_out[expired++] = *e;
      g_node.dir.general_list[i] =
          g_node.dir.general_list[--g_node.dir.general_count];
    } else {
      i++;
    }
  }

  pthread_mutex_unlock(&g_node.dir.general_mutex);

  if (expired > 0)
    LOG_D("DIR", "TTL tick: %d entries expired", expired);

  return expired;
}
