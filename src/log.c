#include "log.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static log_level_t current_level = LOG_INFO;

static const char *level_names[] = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR"};

static const char *level_colors[] = {
    "\033[90m", // TRACE: gray
    "\033[36m", // DEBUG: cyan
    "\033[32m", // INFO: green
    "\033[33m", // WARN: yellow
    "\033[31m"  // ERROR: red
};

static const char *reset_color = "\033[0m";

void log_init(log_level_t level) { current_level = level; }

void log_set_level_str(const char *level) {
  if (strcmp(level, "trace") == 0) {
    current_level = LOG_TRACE;
  } else if (strcmp(level, "debug") == 0) {
    current_level = LOG_DEBUG;
  } else if (strcmp(level, "info") == 0) {
    current_level = LOG_INFO;
  } else if (strcmp(level, "warn") == 0) {
    current_level = LOG_WARN;
  } else if (strcmp(level, "error") == 0) {
    current_level = LOG_ERROR;
  }
}

log_level_t log_get_level(void) { return current_level; }

void log_write(log_level_t level, const char *fmt, va_list args) {
  if (level < current_level) {
    return;
  }

  time_t now = time(NULL);
  struct tm tm_buf;
  const struct tm *tm_info = localtime_r(&now, &tm_buf); // Thread-safe version
  char time_buf[32];
  strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%S", tm_info);

  fprintf(stderr, "%s%s %s%s ", level_colors[level], time_buf,
          level_names[level], reset_color);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  fflush(stderr);
}

void log_trace(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  log_write(LOG_TRACE, fmt, args);
  va_end(args);
}

void log_debug(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  log_write(LOG_DEBUG, fmt, args);
  va_end(args);
}

void log_info(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  log_write(LOG_INFO, fmt, args);
  va_end(args);
}

void log_warn(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  log_write(LOG_WARN, fmt, args);
  va_end(args);
}

void log_error(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  log_write(LOG_ERROR, fmt, args);
  va_end(args);
}

void log_event_json(const char *namespace, const char *pod_name,
                    const char *container_name, const char *pod_ip,
                    const char *severity, double usage_percent,
                    uint64_t usage_bytes, uint64_t limit_bytes) {
  time_t now = time(NULL);
  struct tm tm_buf;
  const struct tm *tm_info = gmtime_r(&now, &tm_buf); // Thread-safe version
  char time_buf[32];
  strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", tm_info);

  printf("{\"timestamp\":\"%s\","
         "\"namespace\":\"%s\","
         "\"pod\":\"%s\","
         "\"container\":\"%s\","
         "\"pod_ip\":\"%s\","
         "\"severity\":\"%s\","
         "\"usage_percent\":%.4f,"
         "\"usage_bytes\":%lu,"
         "\"limit_bytes\":%lu}\n",
         time_buf, namespace, pod_name, container_name, pod_ip ? pod_ip : "",
         severity, usage_percent, usage_bytes, limit_bytes);
  fflush(stdout);
}
