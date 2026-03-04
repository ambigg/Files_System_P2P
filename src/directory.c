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
 * Scans the shared folder and rebuilds the list
 * from scratch by looking at the actual files on disk.
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
    /* Skip hidden files and directories */
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

  /* Check if already exists to update instead of duplicate */
  for (int i = 0; i < g_node.dir.own_count; i++) {
    if (strcmp(g_node.dir.own_list[i].name, entry->name) == 0) {
      g_node.dir.own_list[i] = *entry;
      pthread_mutex_unlock(&g_node.dir.own_mutex);
      LOG_D("DIR", "OWN updated: %s", entry->name);
      return;
    }
  }

  /* Does not exist — add at the end */
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
      /*
       * Trick to remove without shifting the whole array:
       * copy the last element into the hole and decrement count.
       */
      g_node.dir.own_list[i] = g_node.dir.own_list[--g_node.dir.own_count];
      LOG_D("DIR", "OWN removed: %s", filename);
      break;
    }
  }

  pthread_mutex_unlock(&g_node.dir.own_mutex);
}

/* ==========================================================
 * OWN LIST — THREAD‑SAFE SNAPSHOT
 * Copies the whole list to an external buffer so that
 * the caller can work with it without holding the mutex.
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
 *
 * Strategy: delete everything from the peer, insert the new data.
 * This handles in one operation:
 *   - new files that the peer added
 *   - files that the peer stopped sharing
 *   - metadata changes (size, date)
 * ========================================================== */
void dir_general_update_from_peer(const char *peer_ip, const FileEntry *files,
                                  int count) {
  pthread_mutex_lock(&g_node.dir.general_mutex);

  /* Step 1: remove all entries from this peer */
  for (int i = 0; i < g_node.dir.general_count;) {
    if (strcmp(g_node.dir.general_list[i].owner_ip, peer_ip) == 0) {
      g_node.dir.general_list[i] =
          g_node.dir.general_list[--g_node.dir.general_count];
    } else {
      i++;
    }
  }

  /* Step 2: insert the new ones */
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
 * Called when a peer does not respond.
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
 * For when a NEW_FILE notification arrives.
 * ========================================================== */
void dir_general_add(const FileEntry *entry) {
  pthread_mutex_lock(&g_node.dir.general_mutex);

  /* Update if already exists */
  for (int i = 0; i < g_node.dir.general_count; i++) {
    if (strcmp(g_node.dir.general_list[i].name, entry->name) == 0 &&
        strcmp(g_node.dir.general_list[i].owner_ip, entry->owner_ip) == 0) {
      g_node.dir.general_list[i] = *entry;
      pthread_mutex_unlock(&g_node.dir.general_mutex);
      LOG_D("DIR", "GENERAL updated: %s from %s", entry->name, entry->owner_ip);
      return;
    }
  }

  /* Add new */
  if (g_node.dir.general_count < MAX_FILES) {
    g_node.dir.general_list[g_node.dir.general_count++] = *entry;
    LOG_D("DIR", "GENERAL added: %s from %s", entry->name, entry->owner_ip);
  }

  pthread_mutex_unlock(&g_node.dir.general_mutex);
}

/* ==========================================================
 * SEARCH IN BOTH LISTS
 * First searches OWN_LIST (always authoritative),
 * then GENERAL_LIST.
 * ========================================================== */
int dir_find(const char *filename, FileEntry *found_out) {
  /* Search own files first */
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

  /* Search in general */
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
 * COMPLETE SNAPSHOT — GENERAL_LIST + OWN_LIST
 * For displaying the directory to the user.
 * ========================================================== */
int dir_general_snapshot(FileEntry *out, int max) {
  /* First the own files */
  int n = dir_own_snapshot(out, max);

  /* Then the network files */
  pthread_mutex_lock(&g_node.dir.general_mutex);
  for (int i = 0; i < g_node.dir.general_count && n < max; i++) {
    out[n++] = g_node.dir.general_list[i];
  }
  pthread_mutex_unlock(&g_node.dir.general_mutex);

  return n;
}

/* ==========================================================
 * TTL — DECREMENT AND DETECT EXPIRED ENTRIES
 * Called periodically from the Connectivity Thread.
 * ========================================================== */
int dir_tick_ttl(FileEntry *expired_out, int max) {
  int expired = 0;

  pthread_mutex_lock(&g_node.dir.general_mutex);

  for (int i = 0; i < g_node.dir.general_count;) {
    FileEntry *e = &g_node.dir.general_list[i];

    /* TTL=0 means permanent, do not touch */
    if (e->ttl == TTL_PERMANENT) {
      i++;
      continue;
    }

    e->ttl--;

    if (e->ttl <= 0) {
      LOG_D("DIR", "TTL expired: %s from %s", e->name, e->owner_ip);

      if (expired < max)
        expired_out[expired++] = *e;

      /* Remove from list */
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
