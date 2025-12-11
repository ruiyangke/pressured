/*
 * pprof Analyzer Interface
 *
 * Purpose-built analyzer for Go pprof heap profiles.
 * Finds top memory-consuming functions efficiently.
 *
 * Uses the storage API for all I/O operations, enabling support for
 * any storage backend (local filesystem, S3, etc.).
 */

#ifndef PPROF_H
#define PPROF_H

#include <stddef.h>
#include <stdint.h>

// Forward declare storage types (include storage.h for full definitions)
typedef struct storage storage_t;
typedef struct storage_file storage_file_t;

// Default number of results
#define PPROF_DEFAULT_TOP_N 5

// Error codes
enum {
  PPROF_OK = 0,
  PPROF_ERR_IO = -1,
  PPROF_ERR_DECOMPRESS = -2,
  PPROF_ERR_PARSE = -3,
  PPROF_ERR_NOMEM = -4,
  PPROF_ERR_INVALID = -5,
};

// ─────────────────────────────────────────────────────────────────────────────
// Result types
// ─────────────────────────────────────────────────────────────────────────────

/*
 * Function memory statistics
 */
typedef struct {
  char *name; // function name (owned, caller frees via pprof_results_free)
  int64_t inuse_bytes;   // bytes currently in use
  int64_t inuse_objects; // objects currently in use
} pprof_func_stat_t;

/*
 * Analysis results
 */
typedef struct {
  pprof_func_stat_t
      *funcs;          // array of function stats, sorted by inuse_bytes desc
  size_t count;        // number of results
  int64_t total_inuse; // total bytes in use across all functions
} pprof_results_t;

// ─────────────────────────────────────────────────────────────────────────────
// Analyzer interface
// ─────────────────────────────────────────────────────────────────────────────

typedef struct pprof_analyzer pprof_analyzer_t;

/*
 * Analyzer vtable - plugins embed this as first field
 */
struct pprof_analyzer {
  /*
   * Get top N memory-consuming functions from a heap profile
   *
   * Uses streaming I/O through storage interface. Works with any backend
   * (local filesystem via storage_local, S3 via storage_s3, etc.).
   *
   * @param a       Analyzer instance
   * @param storage Storage interface
   * @param key     Storage key for the gzipped pprof file
   * @param top_n   Maximum number of results (0 = use PPROF_DEFAULT_TOP_N)
   * @param out     Output results (caller must call pprof_results_free)
   * @return        PPROF_OK on success, error code on failure
   */
  int (*top_mem_functions)(pprof_analyzer_t *a, storage_t *storage,
                           const char *key, size_t top_n, pprof_results_t *out);
};

/*
 * Free analysis results
 */
void pprof_results_free(pprof_results_t *results);

// Helper - convert error code to string
static inline const char *pprof_strerror(int err) {
  switch (err) {
  case PPROF_OK:
    return "ok";
  case PPROF_ERR_IO:
    return "I/O error";
  case PPROF_ERR_DECOMPRESS:
    return "decompression failed";
  case PPROF_ERR_PARSE:
    return "parse error";
  case PPROF_ERR_NOMEM:
    return "out of memory";
  case PPROF_ERR_INVALID:
    return "invalid argument";
  default:
    return "unknown error";
  }
}

#endif // PPROF_H
