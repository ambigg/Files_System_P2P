#include "../include/transfer.h"
#include "../include/log.h"
#include "../include/protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ==========================================================
 * BASE64
 * ========================================================== */

static const char b64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_val(char c) {
  if (c >= 'A' && c <= 'Z')
    return c - 'A';
  if (c >= 'a' && c <= 'z')
    return c - 'a' + 26;
  if (c >= '0' && c <= '9')
    return c - '0' + 52;
  if (c == '+')
    return 62;
  if (c == '/')
    return 63;
  return -1;
}

int transfer_base64_encode(const unsigned char *input, long input_len,
                           char *output) {
  int j = 0;
  for (long i = 0; i < input_len; i += 3) {
    unsigned char b0 = input[i];
    unsigned char b1 = (i + 1 < input_len) ? input[i + 1] : 0;
    unsigned char b2 = (i + 2 < input_len) ? input[i + 2] : 0;

    output[j++] = b64_chars[b0 >> 2];
    output[j++] = b64_chars[((b0 & 0x03) << 4) | (b1 >> 4)];
    output[j++] =
        (i + 1 < input_len) ? b64_chars[((b1 & 0x0f) << 2) | (b2 >> 6)] : '=';
    output[j++] = (i + 2 < input_len) ? b64_chars[b2 & 0x3f] : '=';
  }
  output[j] = '\0';
  return j;
}

int transfer_base64_decode(const char *input, unsigned char *output,
                           long *output_len) {
  int len = strlen(input);
  if (len % 4 != 0)
    return P2P_ERR;

  *output_len = 0;
  for (int i = 0; i < len; i += 4) {
    int v0 = b64_val(input[i]);
    int v1 = b64_val(input[i + 1]);
    int v2 = (input[i + 2] == '=') ? 0 : b64_val(input[i + 2]);
    int v3 = (input[i + 3] == '=') ? 0 : b64_val(input[i + 3]);

    if (v0 < 0 || v1 < 0)
      return P2P_ERR;

    output[(*output_len)++] = (v0 << 2) | (v1 >> 4);
    if (input[i + 2] != '=')
      output[(*output_len)++] = ((v1 & 0x0f) << 4) | (v2 >> 2);
    if (input[i + 3] != '=')
      output[(*output_len)++] = ((v2 & 0x03) << 6) | v3;
  }
  return P2P_OK;
}

/* ==========================================================
 * INTERNAL HELPER: builds the fixed header of every message
 * TYPE|SENDER_IP|TIMESTAMP|
 * ========================================================== */
static int build_header(char *out, const char *type, const char *sender_ip) {
  return snprintf(out, 256, "%s%c%s%c%ld%c", type, FIELD_SEP, sender_ip,
                  FIELD_SEP, (long)time(NULL), FIELD_SEP);
}

/* ==========================================================
 * MESSAGE CONSTRUCTION
 * ========================================================== */

int transfer_build_get_list(char *out, const char *sender_ip) {
  int n = build_header(out, MSG_GET_LIST, sender_ip);
  out[n++] = '\n';
  out[n] = '\0';
  LOG_N("TRANSFER", "BUILD GET_LIST");
  return n;
}

int transfer_build_list_resp(char *out, const char *sender_ip,
                             const FileEntry *files, int count) {
  int n = build_header(out, MSG_LIST_RESP, sender_ip);

  /* payload: count|name,ext,size,date_c,date_m,ttl;name,... */
  n += snprintf(out + n, MAX_MSG_LEN - n, "%d%c", count, FIELD_SEP);

  for (int i = 0; i < count; i++) {
    n +=
        snprintf(out + n, MAX_MSG_LEN - n, "%s%c%s%c%ld%c%ld%c%ld%c%d",
                 files[i].name, ATTR_SEP, files[i].ext, ATTR_SEP, files[i].size,
                 ATTR_SEP, (long)files[i].date_created, ATTR_SEP,
                 (long)files[i].date_modified, ATTR_SEP, files[i].ttl);
    if (i < count - 1)
      out[n++] = ';';
  }

  out[n++] = '\n';
  out[n] = '\0';
  LOG_N("TRANSFER", "BUILD LIST_RESP (%d files)", count);
  return n;
}

int transfer_build_get_info(char *out, const char *sender_ip,
                            const char *filename) {
  int n = build_header(out, MSG_GET_INFO, sender_ip);
  n += snprintf(out + n, MAX_MSG_LEN - n, "%s\n", filename);
  LOG_N("TRANSFER", "BUILD GET_INFO → %s", filename);
  return n;
}

int transfer_build_info_resp(char *out, const char *sender_ip,
                             const FileEntry *entry) {
  int n = build_header(out, MSG_INFO_RESP, sender_ip);
  n += snprintf(out + n, MAX_MSG_LEN - n, "%s%c%s%c%ld%c%ld%c%ld%c%d%c%s\n",
                entry->name, FIELD_SEP, entry->ext, FIELD_SEP, entry->size,
                FIELD_SEP, (long)entry->date_created, FIELD_SEP,
                (long)entry->date_modified, FIELD_SEP, entry->ttl, FIELD_SEP,
                entry->owner_ip);
  LOG_N("TRANSFER", "BUILD INFO_RESP → %s (authoritative)", entry->name);
  return n;
}

int transfer_build_info_redir(char *out, const char *sender_ip,
                              const char *filename, const char *owner_ip) {
  int n = build_header(out, MSG_INFO_REDIR, sender_ip);
  n += snprintf(out + n, MAX_MSG_LEN - n, "%s%c%s\n", filename, FIELD_SEP,
                owner_ip);
  LOG_N("TRANSFER", "BUILD INFO_REDIR → %s owner=%s", filename, owner_ip);
  return n;
}

int transfer_build_get_file(char *out, const char *sender_ip,
                            const char *filename) {
  int n = build_header(out, MSG_GET_FILE, sender_ip);
  n += snprintf(out + n, MAX_MSG_LEN - n, "%s\n", filename);
  LOG_N("TRANSFER", "BUILD GET_FILE → %s", filename);
  return n;
}

int transfer_build_file_resp(char *out, const char *sender_ip,
                             const char *filename, const unsigned char *content,
                             long size) {
  int n = build_header(out, MSG_FILE_RESP, sender_ip);
  n += snprintf(out + n, MAX_MSG_LEN - n, "%s%c%ld%c", filename, FIELD_SEP,
                size, FIELD_SEP);

  long b64_max = ((size + 2) / 3) * 4 + 1;
  if (n + b64_max + 2 > MAX_MSG_LEN) {
    LOG_E("TRANSFER", "FILE_RESP: file too large");
    return P2P_ERR;
  }

  int b64_len = transfer_base64_encode(content, size, out + n);
  n += b64_len;
  out[n++] = '\n';
  out[n] = '\0';
  LOG_N("TRANSFER", "BUILD FILE_RESP → %s (%ld bytes)", filename, size);
  return n;
}

int transfer_build_new_file(char *out, const char *sender_ip,
                            const FileEntry *entry) {
  int n = build_header(out, MSG_NEW_FILE, sender_ip);
  n += snprintf(out + n, MAX_MSG_LEN - n, "%s%c%s%c%ld%c%ld%c%ld%c%d\n",
                entry->name, FIELD_SEP, entry->ext, FIELD_SEP, entry->size,
                FIELD_SEP, (long)entry->date_created, FIELD_SEP,
                (long)entry->date_modified, FIELD_SEP, entry->ttl);
  LOG_N("TRANSFER", "BUILD NEW_FILE → %s", entry->name);
  return n;
}

int transfer_build_sync_file(char *out, const char *sender_ip,
                             const char *filename, const unsigned char *content,
                             long size, time_t mod_time) {
  int n = build_header(out, MSG_SYNC_FILE, sender_ip);
  n += snprintf(out + n, MAX_MSG_LEN - n, "%s%c%ld%c%ld%c", filename, FIELD_SEP,
                size, FIELD_SEP, (long)mod_time, FIELD_SEP);

  long b64_max = ((size + 2) / 3) * 4 + 1;
  if (n + b64_max + 2 > MAX_MSG_LEN) {
    LOG_E("TRANSFER", "SYNC_FILE: file too large");
    return P2P_ERR;
  }

  int b64_len = transfer_base64_encode(content, size, out + n);
  n += b64_len;
  out[n++] = '\n';
  out[n] = '\0';
  LOG_N("TRANSFER", "BUILD SYNC_FILE → %s (%ld bytes)", filename, size);
  return n;
}

int transfer_build_nack(char *out, const char *sender_ip,
                        const char *filename) {
  int n = build_header(out, MSG_NACK, sender_ip);
  n += snprintf(out + n, MAX_MSG_LEN - n, "%s\n", filename);
  LOG_N("TRANSFER", "BUILD NACK → %s", filename);
  return n;
}

int transfer_build_ack(char *out, const char *sender_ip, const char *info) {
  int n = build_header(out, MSG_ACK, sender_ip);
  n += snprintf(out + n, MAX_MSG_LEN - n, "%s\n", info ? info : "");
  return n;
}

/* ==========================================================
 * MESSAGE PARSING
 * ========================================================== */

int transfer_parse_message(const char *raw, Message *msg) {
  if (!raw || !msg)
    return P2P_ERR;

  char buf[MAX_MSG_LEN];
  strncpy(buf, raw, MAX_MSG_LEN - 1);
  buf[MAX_MSG_LEN - 1] = '\0';

  /* Remove trailing '\n' */
  int len = strlen(buf);
  if (len > 0 && buf[len - 1] == '\n')
    buf[--len] = '\0';

  char *rest = buf;
  char *tok;

  tok = strsep(&rest, FIELD_SEP_STR);
  if (!tok)
    return P2P_ERR;
  strncpy(msg->type, tok, sizeof(msg->type) - 1);

  tok = strsep(&rest, FIELD_SEP_STR);
  if (!tok)
    return P2P_ERR;
  strncpy(msg->sender_ip, tok, sizeof(msg->sender_ip) - 1);

  tok = strsep(&rest, FIELD_SEP_STR);
  if (!tok)
    return P2P_ERR;
  msg->timestamp = (time_t)atol(tok);

  /* The payload is whatever remains */
  if (rest) {
    strncpy(msg->payload, rest, MAX_PAYLOAD_LEN - 1);
    msg->payload_len = strlen(msg->payload);
  } else {
    msg->payload[0] = '\0';
    msg->payload_len = 0;
  }

  LOG_N("TRANSFER", "PARSE OK type=%s from=%s", msg->type, msg->sender_ip);
  return P2P_OK;
}

int transfer_parse_list_payload(const char *payload, FileEntry *files,
                                int max_files) {
  if (!payload || !files)
    return P2P_ERR;

  char buf[MAX_PAYLOAD_LEN];
  strncpy(buf, payload, MAX_PAYLOAD_LEN - 1);
  char *rest = buf;

  /* First field: number of files */
  char *tok = strsep(&rest, FIELD_SEP_STR);
  if (!tok)
    return P2P_ERR;
  int count = atoi(tok);
  if (count <= 0 || !rest)
    return 0;

  /* Records separated by ';' */
  int parsed = 0;
  char *record;
  while ((record = strsep(&rest, ";")) && parsed < max_files &&
         parsed < count) {
    FileEntry *e = &files[parsed];
    memset(e, 0, sizeof(FileEntry));

    /* Each record: name,ext,size,date_c,date_m,ttl */
    char rec[MAX_FILENAME_LEN * 4];
    strncpy(rec, record, sizeof(rec) - 1);
    char *rp = rec;
    char *f;

    f = strsep(&rp, ",");
    if (f)
      strncpy(e->name, f, MAX_FILENAME_LEN - 1);
    f = strsep(&rp, ",");
    if (f)
      strncpy(e->ext, f, 15);
    f = strsep(&rp, ",");
    if (f)
      e->size = atol(f);
    f = strsep(&rp, ",");
    if (f)
      e->date_created = (time_t)atol(f);
    f = strsep(&rp, ",");
    if (f)
      e->date_modified = (time_t)atol(f);
    f = strsep(&rp, ",");
    if (f)
      e->ttl = atoi(f);

    parsed++;
  }

  LOG_N("TRANSFER", "PARSE LIST_PAYLOAD: %d files", parsed);
  return parsed;
}

int transfer_parse_info_payload(const char *payload, FileEntry *entry) {
  if (!payload || !entry)
    return P2P_ERR;
  memset(entry, 0, sizeof(FileEntry));

  char buf[MAX_PAYLOAD_LEN];
  strncpy(buf, payload, MAX_PAYLOAD_LEN - 1);
  char *rest = buf;
  char *tok;

  tok = strsep(&rest, FIELD_SEP_STR);
  if (tok)
    strncpy(entry->name, tok, MAX_FILENAME_LEN - 1);
  tok = strsep(&rest, FIELD_SEP_STR);
  if (tok)
    strncpy(entry->ext, tok, 15);
  tok = strsep(&rest, FIELD_SEP_STR);
  if (tok)
    entry->size = atol(tok);
  tok = strsep(&rest, FIELD_SEP_STR);
  if (tok)
    entry->date_created = (time_t)atol(tok);
  tok = strsep(&rest, FIELD_SEP_STR);
  if (tok)
    entry->date_modified = (time_t)atol(tok);
  tok = strsep(&rest, FIELD_SEP_STR);
  if (tok)
    entry->ttl = atoi(tok);
  tok = strsep(&rest, FIELD_SEP_STR);
  if (tok)
    strncpy(entry->owner_ip, tok, MAX_IP_LEN - 1);

  LOG_N("TRANSFER", "PARSE INFO_PAYLOAD: %s owner=%s", entry->name,
        entry->owner_ip);
  return P2P_OK;
}

int transfer_parse_file_payload(const char *payload, char *filename_out,
                                unsigned char *content_out, long *size_out) {
  if (!payload)
    return P2P_ERR;

  char buf[MAX_PAYLOAD_LEN];
  strncpy(buf, payload, MAX_PAYLOAD_LEN - 1);
  char *rest = buf;
  char *tok;

  tok = strsep(&rest, FIELD_SEP_STR);
  if (!tok)
    return P2P_ERR;
  if (filename_out)
    strncpy(filename_out, tok, MAX_FILENAME_LEN - 1);

  tok = strsep(&rest, FIELD_SEP_STR); /* declared size, just for reference */
  if (!tok)
    return P2P_ERR;

  /* rest points to the Base64 content */
  if (!rest)
    return P2P_ERR;
  if (transfer_base64_decode(rest, content_out, size_out) != P2P_OK)
    return P2P_ERR;

  LOG_N("TRANSFER", "PARSE FILE_PAYLOAD: %s (%ld bytes)",
        filename_out ? filename_out : "?", *size_out);
  return P2P_OK;
}
