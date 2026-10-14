#ifndef PRESSURED_FIXED_BUFFER_H
#define PRESSURED_FIXED_BUFFER_H

#include "log.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

// Failed writes leave an empty string, never a truncated value.
static inline int buffer_copy(char *dst, size_t size, const char *src,
                              const char *name) {
  size_t length = strnlen(src, size);
  if (length >= size) {
    if (size)
      dst[0] = '\0';
    log_error("%s too long (buffer size %zu)", name, size);
    return -1;
  }
  memcpy(dst, src, length + 1);
  return 0;
}

static inline int buffer_format(char *dst, size_t size, const char *name,
                                const char *format, ...) {
  va_list args;
  va_start(args, format);
  int length = vsnprintf(dst, size, format, args);
  va_end(args);
  if (length < 0 || (size_t)length >= size) {
    if (size)
      dst[0] = '\0';
    log_error("%s too long or cannot be formatted (buffer size %zu)", name,
              size);
    return -1;
  }
  return 0;
}

#endif
