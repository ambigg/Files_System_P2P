#include "../include/log.h"
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static FILE *log_fp = NULL;
static char node_ip[16] = "0.0.0.0";
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char *level_names[] = {"INFO ", "WARN ", "ERROR", "NET  ",
                                    "DIR  ", "FILE ", "SEC  "};

void log_init(const char *log_path, const char *my_ip) {
  pthread_mutex_lock(&log_mutex);

  if (log_fp && log_fp != stderr)
    fclose(log_fp);

  log_fp = fopen(log_path, "a");
  if (!log_fp) {
    fprintf(stderr, "[LOG] Could not open %s, using stderr\n", log_path);
    log_fp = stderr;
  }

  strncpy(node_ip, my_ip, sizeof(node_ip) - 1);
  pthread_mutex_unlock(&log_mutex);
}

void log_write(LogLevel level, const char *module, const char *fmt, ...) {
  if (!log_fp)
    log_fp = stderr;

  /* Format the user message */
  char msg[1024];
  va_list args;
  va_start(args, fmt);
  vsnprintf(msg, sizeof(msg), fmt, args);
  va_end(args);

  /* Timestamp */
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  char ts[32];
  strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);

  const char *lvl = (level <= LOG_SEC) ? level_names[level] : "?????";

  pthread_mutex_lock(&log_mutex);
  fprintf(log_fp, "[%s] [%s] [%-15s] [%-12s] %s\n", ts, lvl, node_ip, module,
          msg);
  fflush(log_fp);
  pthread_mutex_unlock(&log_mutex);
}

void log_close(void) {
  pthread_mutex_lock(&log_mutex);
  if (log_fp && log_fp != stderr) {
    fclose(log_fp);
    log_fp = NULL;
  }
  pthread_mutex_unlock(&log_mutex);
}
