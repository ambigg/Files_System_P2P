#include "../include/data.h"
#include "../include/log.h"
#include "../include/protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

/* ==========================================================
 * READ ENTIRE FILE
 * ========================================================== */
unsigned char *data_read_file(const char *path, long *size_out) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    LOG_E("DATA", "Could not open for reading: %s", path);
    return NULL;
  }

  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  fseek(f, 0, SEEK_SET);

  unsigned char *buf = malloc(size + 1);
  if (!buf) {
    LOG_E("DATA", "malloc failed for %s (%ld bytes)", path, size);
    fclose(f);
    return NULL;
  }

  fread(buf, 1, size, f);
  buf[size] = '\0';
  fclose(f);

  *size_out = size;
  LOG_F("DATA", "READ %s (%ld bytes)", path, size);
  return buf;
}

/* ==========================================================
 * WRITE FILE
 * ========================================================== */
int data_write_file(const char *path, const unsigned char *content, long size) {
  FILE *f = fopen(path, "wb");
  if (!f) {
    LOG_E("DATA", "Could not open for writing: %s", path);
    return P2P_ERR;
  }

  long written = fwrite(content, 1, size, f);
  fclose(f);

  if (written != size) {
    LOG_E("DATA", "Incomplete write on %s (%ld of %ld bytes)", path, written,
          size);
    return P2P_ERR;
  }

  LOG_F("DATA", "WRITE %s (%ld bytes)", path, size);
  return P2P_OK;
}

/* ==========================================================
 * FILE METADATA
 * ========================================================== */
int data_stat_file(const char *path, FileEntry *out) {
  struct stat st;
  if (stat(path, &st) != 0) {
    LOG_E("DATA", "stat() failed on: %s", path);
    return P2P_ERR;
  }

  memset(out, 0, sizeof(FileEntry));

  /* Extract only the name (without the path) */
  const char *slash = strrchr(path, '/');
  const char *name = slash ? slash + 1 : path;
  strncpy(out->name, name, MAX_FILENAME_LEN - 1);

  data_get_extension(name, out->ext);

  out->size = st.st_size;
  out->date_created = st.st_ctime;  /* ctime = last metadata change */
  out->date_modified = st.st_mtime; /* mtime = last content change */
  out->ttl = 120;                   /* Default TTL: 2 minutes */
  out->is_local = 1;
  out->last_verified = time(NULL);
  strncpy(out->owner_ip, "LOCAL", MAX_IP_LEN - 1);

  return P2P_OK;
}

/* ==========================================================
 * LOAD PEERS FROM peers.conf
 *
 * File format:
 *   # comment
 *   192.168.1.11:8080
 *   192.168.1.12        ← without port uses default
 * ========================================================== */
int data_load_peers(const char *conf_path, PeerNode *peers, int max) {
  FILE *f = fopen(conf_path, "r");
  if (!f) {
    LOG_W("DATA", "Could not find %s, no peers configured", conf_path);
    return 0;
  }

  int count = 0;
  char line[64];

  while (fgets(line, sizeof(line), f) && count < max) {
    /* Ignore comments and empty lines */
    if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
      continue;

    line[strcspn(line, "\r\n")] = '\0';
    if (strlen(line) == 0)
      continue;

    memset(&peers[count], 0, sizeof(PeerNode));

    char *colon = strchr(line, ':');
    if (colon) {
      *colon = '\0';
      strncpy(peers[count].ip, line, MAX_IP_LEN - 1);
      peers[count].port = atoi(colon + 1);
    } else {
      strncpy(peers[count].ip, line, MAX_IP_LEN - 1);
      peers[count].port = P2P_PORT;
    }

    peers[count].reachable = 0;
    peers[count].last_seen = 0;
    count++;
  }

  fclose(f);
  LOG_I("DATA", "Loaded %d peers from %s", count, conf_path);
  return count;
}

/* ==========================================================
 * SAVE LIST_OWN TO DISK (files.txt)
 *
 * Format:
 *   # comment
 *   name|ext|size|date_created|date_modified|ttl
 * ========================================================== */
int data_save_own_list(const char *path, const FileEntry *files, int count) {
  FILE *f = fopen(path, "w");
  if (!f) {
    LOG_E("DATA", "Could not save list to: %s", path);
    return P2P_ERR;
  }

  fprintf(f, "# LIST_OWN — files shared by this node\n");
  fprintf(f, "# name|ext|size|date_created|date_modified|ttl\n");

  for (int i = 0; i < count; i++) {
    fprintf(f, "%s|%s|%ld|%ld|%ld|%d\n", files[i].name, files[i].ext,
            files[i].size, (long)files[i].date_created,
            (long)files[i].date_modified, files[i].ttl);
  }

  fclose(f);
  LOG_F("DATA", "LIST_OWN saved to %s (%d files)", path, count);
  return P2P_OK;
}

/* ==========================================================
 * LOAD LIST_OWN FROM DISK
 * ========================================================== */
int data_load_own_list(const char *path, FileEntry *files, int max) {
  FILE *f = fopen(path, "r");
  if (!f) {
    LOG_W("DATA", "Could not find list at: %s", path);
    return 0;
  }

  int count = 0;
  char line[512];

  while (fgets(line, sizeof(line), f) && count < max) {
    if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
      continue;

    line[strcspn(line, "\r\n")] = '\0';
    if (strlen(line) == 0)
      continue;

    FileEntry *e = &files[count];
    memset(e, 0, sizeof(FileEntry));

    char *rest = line;
    char *tok;

    tok = strsep(&rest, "|");
    if (tok)
      strncpy(e->name, tok, MAX_FILENAME_LEN - 1);
    tok = strsep(&rest, "|");
    if (tok)
      strncpy(e->ext, tok, 15);
    tok = strsep(&rest, "|");
    if (tok)
      e->size = atol(tok);
    tok = strsep(&rest, "|");
    if (tok)
      e->date_created = (time_t)atol(tok);
    tok = strsep(&rest, "|");
    if (tok)
      e->date_modified = (time_t)atol(tok);
    tok = strsep(&rest, "|");
    if (tok)
      e->ttl = atoi(tok);

    strncpy(e->owner_ip, "LOCAL", MAX_IP_LEN - 1);
    e->is_local = 1;
    e->last_verified = time(NULL);

    count++;
  }

  fclose(f);
  LOG_F("DATA", "LIST_OWN loaded from %s (%d files)", path, count);
  return count;
}

/* ==========================================================
 * CREATE TEMPORARY COPY
 *
 * File name: tmp/NAME__IP.tmp
 * Dots in the IP are replaced by '_' to keep a valid filename.
 * ========================================================== */
int data_create_temp_copy(const char *filename, const char *owner_ip,
                          const unsigned char *content, long size,
                          char *temp_path_out) {
  /* Build path: tmp/filename.txt__192_168_1_11.tmp */
  snprintf(temp_path_out, MAX_PATH_LEN, "tmp/%s__%s.tmp", filename, owner_ip);

  /* Replace '.' with '_' in the IP part */
  char *ip_start = strstr(temp_path_out, "__");
  if (ip_start) {
    for (char *p = ip_start + 2; *p && *p != '.'; p++) {
    }
    for (char *p = ip_start + 2; *p; p++)
      if (*p == '.')
        *p = '_';
  }

  int rc = data_write_file(temp_path_out, content, size);
  if (rc == P2P_OK)
    LOG_F("DATA", "Temporary copy created: %s", temp_path_out);

  return rc;
}

/* ==========================================================
 * DELETE TEMPORARY FILE
 * ========================================================== */
void data_delete_temp(const char *temp_path) {
  if (remove(temp_path) == 0)
    LOG_F("DATA", "Temporary deleted: %s", temp_path);
  else
    LOG_W("DATA", "Could not delete temporary: %s", temp_path);
}

/* ==========================================================
 * EXTRACT EXTENSION
 * ========================================================== */
void data_get_extension(const char *filename, char *ext_out) {
  ext_out[0] = '\0';
  const char *dot = strrchr(filename, '.');
  if (dot && dot != filename)
    strncpy(ext_out, dot + 1, 15);
}
