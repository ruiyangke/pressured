#ifndef STORAGE_H
#define STORAGE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Storage Interface
 *
 * File-like streaming API for large data with low memory footprint.
 * Plugins implement this interface by embedding storage_t as their first field.
 *
 * Usage:
 *   storage_t *s = (storage_t *)pressured_plugin_create(ctx,
 * PRESSURED_PLUGIN_TYPE_STORAGE); storage_file_t *f = s->open(s, "key",
 * STORAGE_MODE_WRITE); s->write(f, data, len); s->close(f);
 */

// Error codes
enum {
  STORAGE_OK = 0,
  STORAGE_ERR_IO = -1,
  STORAGE_ERR_NOT_FOUND = -2,
  STORAGE_ERR_PERM = -3,
  STORAGE_ERR_NO_SPACE = -4,
  STORAGE_ERR_INVALID = -5,
  STORAGE_ERR_NOT_INIT = -6,
  STORAGE_ERR_OTHER = -99
};

// Open modes
enum { STORAGE_MODE_READ = 0, STORAGE_MODE_WRITE = 1 };

// Forward declare for function signatures
typedef struct storage storage_t;
typedef struct storage_file storage_file_t;

/*
 * Storage vtable - plugins embed this as first field of their handle struct.
 * All functions take storage_t* as first arg (like 'self' in OOP).
 */
struct storage {
  int (*exists)(storage_t *s, const char *key);
  int (*remove)(storage_t *s, const char *key);
  int (*rename)(storage_t *s, const char *old_key, const char *new_key);
  storage_file_t *(*open)(storage_t *s, const char *key, int mode);
  int64_t (*write)(storage_file_t *f, const void *data, size_t len);
  int64_t (*read)(storage_file_t *f, void *buf, size_t len);
  int (*close)(storage_file_t *f);
};

// Helper - convert error code to string
static inline const char *storage_strerror(int err) {
  switch (err) {
  case STORAGE_OK:
    return "ok";
  case STORAGE_ERR_IO:
    return "I/O error";
  case STORAGE_ERR_NOT_FOUND:
    return "not found";
  case STORAGE_ERR_PERM:
    return "permission denied";
  case STORAGE_ERR_NO_SPACE:
    return "no space left";
  case STORAGE_ERR_INVALID:
    return "invalid argument";
  case STORAGE_ERR_NOT_INIT:
    return "not initialized";
  case STORAGE_ERR_OTHER:
    return "unknown error";
  default:
    return "unknown error";
  }
}

#endif // STORAGE_H
