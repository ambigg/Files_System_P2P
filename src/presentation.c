#include "../include/directory.h"
#include "../include/log.h"
#include "../include/logic.h"
#include "../include/protocol.h"
#include "../include/structures.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ==========================================================
 * ANSI colors — automatically disabled if terminal does not support them
 * ========================================================== */
#define RESET "\033[0m"
#define BOLD "\033[1m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define CYAN "\033[36m"
#define RED "\033[31m"
#define GRAY "\033[90m"

/* ==========================================================
 * INTERNAL HELPERS
 * ========================================================== */
static void fmt_time(time_t t, char *buf, int len) {
  struct tm *tm = localtime(&t);
  strftime(buf, len, "%Y-%m-%d %H:%M", tm);
}

static void fmt_size(long bytes, char *buf) {
  if (bytes < 1024)
    sprintf(buf, "%ld B", bytes);
  else if (bytes < 1024 * 1024)
    sprintf(buf, "%.1f KB", bytes / 1024.0);
  else
    sprintf(buf, "%.1f MB", bytes / (1024.0 * 1024));
}

static void print_divider(void) {
  printf(GRAY "────────────────────────────────────────"
              "────────────────────────────────\n" RESET);
}

/* Read a line from stdin without trailing newline */
static void read_line(char *buf, int max) {
  if (fgets(buf, max, stdin))
    buf[strcspn(buf, "\n")] = '\0';
  else
    buf[0] = '\0';
}

/* ==========================================================
 * MAIN MENU
 * ========================================================== */
static void print_menu(void) {
  printf("\n" BOLD CYAN "╔══════════════════════════════════════╗\n"
         "║        P2P FILE SYSTEM                 ║\n");
  printf("║     Node: %-26s ║\n", g_node.my_ip);
  printf("╚══════════════════════════════════════╝\n" RESET);
  printf(BOLD " 1." RESET " View full directory\n");
  printf(BOLD " 2." RESET " View file info\n");
  printf(BOLD " 3." RESET " Open / edit a file\n");
  printf(BOLD " 4." RESET " View network peers\n");
  printf(BOLD " 5." RESET " Force list update\n");
  printf(BOLD " 0." RESET " Exit\n");
  print_divider();
  printf("Option: ");
}

/* ==========================================================
 * SHOW FULL DIRECTORY
 * ========================================================== */
void presentation_show_directory(void) {
  FileEntry files[MAX_FILES];
  int count = dir_general_snapshot(files, MAX_FILES);

  printf("\n" BOLD CYAN "═══ DISTRIBUTED DIRECTORY (%d files) ═══\n" RESET,
         count);

  printf(BOLD "%-30s %-6s %-10s %-17s %-15s\n" RESET, "Name", "Ext", "Size",
         "Modified", "Node");
  print_divider();

  if (count == 0) {
    printf(YELLOW "  (No files in the network)\n" RESET);
    return;
  }

  for (int i = 0; i < count; i++) {
    FileEntry *e = &files[i];
    char size_str[16];
    char date_str[32];
    fmt_size(e->size, size_str);
    fmt_time(e->date_modified, date_str, sizeof(date_str));

    /* Own files appear in green */
    if (e->is_local) {
      printf("%-30s %-6s %-10s %-17s " GREEN "LOCAL\n" RESET, e->name, e->ext,
             size_str, date_str);
    } else {
      printf("%-30s %-6s %-10s %-17s %s\n", e->name, e->ext, size_str, date_str,
             e->owner_ip);
    }
  }

  LOG_I("UI", "Directory queried: %d files", count);
}

/* ==========================================================
 * SHOW FILE INFO
 * ========================================================== */
void presentation_show_file_info(const char *filename) {
  FileEntry entry;
  int rc = logic_get_file_info(filename, &entry);

  if (rc != P2P_OK) {
    printf(RED "  File '%s' not found in the network.\n" RESET, filename);
    return;
  }

  char created_str[32], modified_str[32], size_str[16];
  fmt_time(entry.date_created, created_str, sizeof(created_str));
  fmt_time(entry.date_modified, modified_str, sizeof(modified_str));
  fmt_size(entry.size, size_str);

  char ttl_str[32];
  if (entry.ttl == TTL_PERMANENT)
    snprintf(ttl_str, sizeof(ttl_str), "Permanent");
  else
    snprintf(ttl_str, sizeof(ttl_str), "%d sec", entry.ttl);

  printf("\n" BOLD CYAN "═══ FILE INFORMATION ═══\n" RESET);
  printf(BOLD "  Name:      " RESET "%s\n", entry.name);
  printf(BOLD "  Extension: " RESET ".%s\n", entry.ext);
  printf(BOLD "  Size:      " RESET "%s\n", size_str);
  printf(BOLD "  Created:   " RESET "%s\n", created_str);
  printf(BOLD "  Modified:  " RESET "%s\n", modified_str);
  printf(BOLD "  TTL:       " RESET "%s\n", ttl_str);
  printf(BOLD "  Node:      " RESET);

  if (entry.is_local)
    printf(GREEN "LOCAL\n" RESET);
  else
    printf("%s\n", entry.owner_ip);

  LOG_I("UI", "Info queried: %s", filename);
}

/* ==========================================================
 * OPEN AND EDIT A FILE
 * ========================================================== */
void presentation_open_file(const char *filename) {
  char local_path[MAX_PATH_LEN];

  printf(YELLOW "  Fetching '%s'...\n" RESET, filename);

  int rc = logic_open_file(filename, local_path);
  if (rc != P2P_OK) {
    printf(RED "  Could not fetch the file.\n" RESET);
    return;
  }

  /* Show current content */
  printf(BOLD CYAN "\n═══ CONTENT OF %s ═══\n" RESET, filename);
  print_divider();

  FILE *f = fopen(local_path, "r");
  if (f) {
    char line[1024];
    int lines = 0;
    while (fgets(line, sizeof(line), f) && lines < 100) {
      printf("%s", line);
      lines++;
    }
    /* Warn if file has more than 100 lines */
    if (!feof(f))
      printf(YELLOW "\n  ... (showing first 100 lines) ...\n" RESET);
    fclose(f);
  }

  print_divider();

  /* Ask if user wants to edit */
  printf("\nEdit this file? (s/n): ");
  char opt[4];
  read_line(opt, sizeof(opt));

  if (opt[0] == 's' || opt[0] == 'S') {
    /*
     * Open with system editor.
     * If EDITOR variable is not set, use nano.
     * User can export EDITOR=vim before running the node.
     */
    const char *editor = getenv("EDITOR");
    if (!editor)
      editor = "nano";

    char cmd[MAX_PATH_LEN + 32];
    snprintf(cmd, sizeof(cmd), "%s \"%s\"", editor, local_path);

    printf(YELLOW "  Opening editor...\n" RESET);
    int ret = system(cmd);

    if (ret == 0) {
      /*
       * Mark as modified.
       * We assume that if the editor closed without error, changes were made.
       * A future improvement would be to compare mtime before and after.
       */
      logic_mark_modified(local_path);
      printf(GREEN "  Changes saved locally.\n" RESET);
    } else {
      printf(YELLOW "  Editor closed with error, no changes.\n" RESET);
    }
  }

  /* Close: synchronize if changes were made, remove temporary */
  printf(YELLOW "  Closing file...\n" RESET);
  logic_close_file(local_path);
  printf(GREEN "  Done.\n" RESET);

  LOG_I("UI", "File opened/closed: %s", filename);
}

/* ==========================================================
 * SHOW PEERS
 * ========================================================== */
void presentation_show_peers(void) {
  printf("\n" BOLD CYAN "═══ PEERS IN THE NETWORK ═══\n" RESET);
  printf(BOLD "%-20s %-8s %-10s %-20s\n" RESET, "IP", "Port", "Status",
         "Last contact");
  print_divider();

  if (g_node.peer_count == 0) {
    printf(YELLOW "  (No peers configured in peers.conf)\n" RESET);
    return;
  }

  for (int i = 0; i < g_node.peer_count; i++) {
    PeerNode *p = &g_node.peers[i];

    char ts[32] = "Never";
    if (p->last_seen > 0)
      fmt_time(p->last_seen, ts, sizeof(ts));

    if (p->reachable)
      printf("%-20s %-8d " GREEN "%-10s" RESET " %-20s\n", p->ip, p->port,
             "Online", ts);
    else
      printf("%-20s %-8d " RED "%-10s" RESET " %-20s\n", p->ip, p->port,
             "Offline", ts);
  }
}

/* ==========================================================
 * MAIN LOOP
 * ========================================================== */
void presentation_run(void) {
  char input[256];

  while (g_node.running) {
    print_menu();
    read_line(input, sizeof(input));

    int opt = atoi(input);

    switch (opt) {

    case 0:
      g_node.running = 0;
      printf(YELLOW "\n  Shutting down node...\n" RESET);
      break;

    case 1:
      presentation_show_directory();
      break;

    case 2:
      printf("File name: ");
      read_line(input, sizeof(input));
      if (input[0])
        presentation_show_file_info(input);
      break;

    case 3:
      printf("File name: ");
      read_line(input, sizeof(input));
      if (input[0])
        presentation_open_file(input);
      break;

    case 4:
      presentation_show_peers();
      break;

    case 5:
      printf(YELLOW "  Update happens automatically every %d seconds.\n"
                    "  The next cycle will update the lists.\n" RESET,
             UPDATE_INTERVAL);
      /* Force immediate local re‑scan */
      dir_scan_own();
      dir_save_own();
      printf(GREEN "  Local scan completed.\n" RESET);
      break;

    default:
      printf(RED "  Invalid option.\n" RESET);
      break;
    }
  }
}
