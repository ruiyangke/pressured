#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <stdint.h>

// Log levels
typedef enum {
  LOG_TRACE = 0,
  LOG_DEBUG = 1,
  LOG_INFO = 2,
  LOG_WARN = 3,
  LOG_ERROR = 4
} log_level_t;

// Initialize logging
void log_init(log_level_t level);

// Set log level from string ("trace", "debug", "info", "warn", "error")
void log_set_level_str(const char *level);

// Get current log level
log_level_t log_get_level(void);

// Log functions
void log_trace(const char *fmt, ...);
void log_debug(const char *fmt, ...);
void log_info(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_error(const char *fmt, ...);

// Log with explicit level
void log_write(log_level_t level, const char *fmt, va_list args);

// Log event as JSON (for structured logging)
void log_event_json(const char *namespace, const char *pod_name,
                    const char *container_name, const char *pod_ip,
                    const char *severity, double usage_percent,
                    uint64_t usage_bytes, uint64_t limit_bytes);

#endif // LOG_H
