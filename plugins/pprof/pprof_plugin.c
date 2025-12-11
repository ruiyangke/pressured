/*
 * pprof Heap Analyzer Plugin
 *
 * Purpose-built analyzer for finding top memory-consuming functions
 * in Go pprof heap profiles.
 *
 * Architecture:
 * - Uses storage API for all I/O (works with local files, S3, etc.)
 * - Streaming gzip decompression (64KB chunks)
 * - Single-pass: build lookup tables + aggregate samples
 * - No string table storage during analysis
 * - Targeted re-decompress to fetch only top N function names
 *
 * Memory: ~700KB peak for typical profiles
 * Speed: ~30ms for 7MB compressed profile
 */

#include "log.h"
#include "plugin.h"
#include "pprof.h"
#include "service_registry.h"
#include "storage.h"

// Silence warnings from cwisstable
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "cwisstable.h"
#pragma GCC diagnostic pop

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define PPROF_PLUGIN_TYPE (1 << 2)

// Protobuf wire types
#define WIRE_VARINT 0
#define WIRE_64BIT 1
#define WIRE_LENGTH_DELIMITED 2
#define WIRE_32BIT 5

// Profile field numbers
#define FIELD_SAMPLE 2
#define FIELD_LOCATION 4
#define FIELD_FUNCTION 5
#define FIELD_STRING_TABLE 6

// Function field numbers
#define FUNCTION_ID 1
#define FUNCTION_NAME 2

// Location field numbers
#define LOCATION_ID 1
#define LOCATION_LINE 4

// Line field numbers
#define LINE_FUNCTION_ID 1

// Sample field numbers
#define SAMPLE_LOCATION_ID 1
#define SAMPLE_VALUE 2

// ─────────────────────────────────────────────────────────────────────────────
// Protobuf buffer reader (for parsing embedded messages)
// ─────────────────────────────────────────────────────────────────────────────

typedef struct {
  const uint8_t *data;
  size_t pos;
  size_t len;
} pbuf_t;

static inline int pbuf_eof(pbuf_t *b) { return b->pos >= b->len; }

static uint64_t pbuf_read_varint(pbuf_t *b) {
  uint64_t result = 0;
  int shift = 0;
  while (b->pos < b->len) {
    uint8_t byte = b->data[b->pos++];
    result |= (uint64_t)(byte & 0x7F) << shift;
    if ((byte & 0x80) == 0)
      break;
    shift += 7;
    if (shift >= 64)
      break;
  }
  return result;
}

static void pbuf_read_bytes(pbuf_t *b, const uint8_t **out, size_t *out_len) {
  size_t len = pbuf_read_varint(b);
  size_t remaining = b->len - b->pos; // Safe: pos <= len invariant
  if (len > remaining)
    len = remaining;
  *out = b->data + b->pos;
  *out_len = len;
  b->pos += len;
}

static void pbuf_skip(pbuf_t *b, int wire_type) {
  size_t remaining = b->len - b->pos;
  switch (wire_type) {
  case WIRE_VARINT:
    pbuf_read_varint(b);
    break;
  case WIRE_64BIT:
    b->pos += (remaining >= 8) ? 8 : remaining;
    break;
  case WIRE_LENGTH_DELIMITED: {
    size_t len = pbuf_read_varint(b);
    remaining = b->len - b->pos; // Recalculate after varint read
    b->pos += (len <= remaining) ? len : remaining;
    break;
  }
  case WIRE_32BIT:
    b->pos += (remaining >= 4) ? 4 : remaining;
    break;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Streaming gzip decompression (storage-based)
// ─────────────────────────────────────────────────────────────────────────────

#define DECOMP_CHUNK_SIZE (64 * 1024)
#define INPUT_BUF_SIZE (64 * 1024)

typedef struct {
  z_stream strm;
  storage_t *storage;
  const char *key;      // Storage key (not owned, must outlive this struct)
  storage_file_t *file; // Current open file handle
  uint8_t input_buf[INPUT_BUF_SIZE]; // Compressed input buffer
  uint8_t chunk[DECOMP_CHUNK_SIZE];  // Decompressed output buffer
  size_t chunk_len;
  size_t chunk_pos;
  int finished;
  int initialized;
} decomp_t;

static int decomp_init(decomp_t *d, storage_t *storage, const char *key) {
  memset(d, 0, sizeof(*d));
  d->storage = storage;
  d->key = key;

  // Open file for reading
  d->file = storage->open(storage, key, STORAGE_MODE_READ);
  if (!d->file) {
    log_error("pprof: failed to open storage key: %s", key);
    return -1;
  }

  // Initialize zlib for gzip
  if (inflateInit2(&d->strm, 16 + MAX_WBITS) != Z_OK) {
    storage->close(d->file);
    d->file = NULL;
    return -1;
  }

  d->initialized = 1;
  return 0;
}

static void decomp_free(decomp_t *d) {
  if (d->initialized) {
    inflateEnd(&d->strm);
    d->initialized = 0;
  }
  if (d->file) {
    d->storage->close(d->file);
    d->file = NULL;
  }
}

static int decomp_reset(decomp_t *d) {
  if (!d->initialized)
    return -1;

  // Close current file and re-open from beginning
  if (d->file) {
    d->storage->close(d->file);
    d->file = NULL;
  }

  d->file = d->storage->open(d->storage, d->key, STORAGE_MODE_READ);
  if (!d->file) {
    log_error("pprof: failed to re-open storage key: %s", d->key);
    return -1;
  }

  // Reset zlib state
  inflateReset(&d->strm);
  d->strm.avail_in = 0;
  d->strm.next_in = NULL;
  d->chunk_len = 0;
  d->chunk_pos = 0;
  d->finished = 0;
  return 0;
}

static int decomp_fill(decomp_t *d) {
  if (d->finished)
    return 0;

  // Refill input buffer if needed
  if (d->strm.avail_in == 0) {
    int64_t n = d->storage->read(d->file, d->input_buf, INPUT_BUF_SIZE);
    if (n < 0) {
      log_error("pprof: storage read error");
      return -1;
    }
    d->strm.next_in = d->input_buf;
    d->strm.avail_in = (uInt)n;
  }

  d->strm.next_out = d->chunk;
  d->strm.avail_out = DECOMP_CHUNK_SIZE;

  int ret = inflate(&d->strm, Z_NO_FLUSH);
  if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
    log_error("pprof: decompression error: %d", ret);
    return -1;
  }

  d->chunk_len = DECOMP_CHUNK_SIZE - d->strm.avail_out;
  d->chunk_pos = 0;

  if (ret == Z_STREAM_END)
    d->finished = 1;

  return (int)d->chunk_len;
}

static int decomp_getc(decomp_t *d) {
  if (d->chunk_pos >= d->chunk_len) {
    if (decomp_fill(d) <= 0)
      return -1;
  }
  return d->chunk[d->chunk_pos++];
}

static int decomp_read_varint(decomp_t *d, uint64_t *out) {
  uint64_t result = 0;
  int shift = 0;
  int byte;
  while ((byte = decomp_getc(d)) >= 0) {
    result |= (uint64_t)(byte & 0x7F) << shift;
    if ((byte & 0x80) == 0) {
      *out = result;
      return 0;
    }
    shift += 7;
    if (shift >= 64)
      return -1;
  }
  return -1;
}

static int decomp_skip_bytes(decomp_t *d, size_t n) {
  while (n > 0) {
    size_t avail = d->chunk_len - d->chunk_pos;
    if (avail == 0) {
      if (decomp_fill(d) <= 0)
        return -1;
      avail = d->chunk_len - d->chunk_pos;
    }
    size_t to_skip = (n < avail) ? n : avail;
    d->chunk_pos += to_skip;
    n -= to_skip;
  }
  return 0;
}

static int decomp_read_bytes(decomp_t *d, uint8_t *buf, size_t n) {
  size_t total = 0;
  while (total < n) {
    size_t avail = d->chunk_len - d->chunk_pos;
    if (avail == 0) {
      if (decomp_fill(d) <= 0)
        return -1;
      avail = d->chunk_len - d->chunk_pos;
    }
    size_t to_copy = (n - total < avail) ? (n - total) : avail;
    memcpy(buf + total, d->chunk + d->chunk_pos, to_copy);
    d->chunk_pos += to_copy;
    total += to_copy;
  }
  return 0;
}

static int decomp_skip_field(decomp_t *d, int wire_type) {
  switch (wire_type) {
  case WIRE_VARINT: {
    uint64_t dummy;
    return decomp_read_varint(d, &dummy);
  }
  case WIRE_64BIT:
    return decomp_skip_bytes(d, 8);
  case WIRE_LENGTH_DELIMITED: {
    uint64_t len;
    if (decomp_read_varint(d, &len) != 0)
      return -1;
    return decomp_skip_bytes(d, len);
  }
  case WIRE_32BIT:
    return decomp_skip_bytes(d, 4);
  default:
    return -1;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Swiss table hash maps (using cwisstable)
// ─────────────────────────────────────────────────────────────────────────────

// Function stats value type
typedef struct {
  int64_t name_idx;
  int64_t inuse_bytes;
  int64_t inuse_objects;
} func_stats_t;

// Declare: FuncMap (uint64_t -> func_stats_t)
CWISS_DECLARE_FLAT_HASHMAP(FuncMap, uint64_t, func_stats_t);

// Declare: LocMap (uint64_t -> uint64_t)
CWISS_DECLARE_FLAT_HASHMAP(LocMap, uint64_t, uint64_t);

// ─────────────────────────────────────────────────────────────────────────────
// Analysis context (NO string table!)
// ─────────────────────────────────────────────────────────────────────────────

typedef struct {
  FuncMap funcs;
  LocMap locs;
  int64_t total_inuse;
  size_t string_count; // just count strings for validation
} analysis_ctx_t;

static int ctx_init(analysis_ctx_t *ctx) {
  memset(ctx, 0, sizeof(*ctx));
  ctx->funcs = FuncMap_new(0);
  ctx->locs = LocMap_new(0);
  return 0;
}

static void ctx_free(analysis_ctx_t *ctx) {
  FuncMap_destroy(&ctx->funcs);
  LocMap_destroy(&ctx->locs);
}

// ─────────────────────────────────────────────────────────────────────────────
// Single pass: Collect functions, locations, aggregate samples
// Skip string table entirely - just count entries
// ─────────────────────────────────────────────────────────────────────────────

static int analyze_pass(decomp_t *d, analysis_ctx_t *ctx) {
  uint64_t tag;
  uint8_t *tmp_buf = NULL;
  size_t tmp_cap = 0;

  // Temp arrays for sample parsing
  uint64_t *loc_ids = NULL;
  size_t loc_cap = 0;
  int64_t *values = NULL;
  size_t val_cap = 0;

  while (decomp_read_varint(d, &tag) == 0) {
    int field = tag >> 3;
    int wire = tag & 7;

    switch (field) {
    case FIELD_STRING_TABLE: {
      // Skip string content, just count entries
      uint64_t len;
      if (decomp_read_varint(d, &len) != 0)
        goto error;
      if (decomp_skip_bytes(d, len) != 0)
        goto error;
      ctx->string_count++;
      break;
    }

    case FIELD_FUNCTION: {
      uint64_t len;
      if (decomp_read_varint(d, &len) != 0)
        goto error;
      if (len > tmp_cap) {
        uint8_t *new_buf = realloc(tmp_buf, len);
        if (!new_buf)
          goto error;
        tmp_buf = new_buf;
        tmp_cap = len;
      }
      if (decomp_read_bytes(d, tmp_buf, len) != 0)
        goto error;

      // Parse function message
      uint64_t id = 0;
      int64_t name_idx = 0;
      pbuf_t inner = {tmp_buf, 0, len};
      while (!pbuf_eof(&inner)) {
        uint64_t itag = pbuf_read_varint(&inner);
        int ifield = itag >> 3;
        int iwire = itag & 7;
        if (ifield == FUNCTION_ID)
          id = pbuf_read_varint(&inner);
        else if (ifield == FUNCTION_NAME)
          name_idx = pbuf_read_varint(&inner);
        else
          pbuf_skip(&inner, iwire);
      }
      // Insert into FuncMap
      func_stats_t stats = {name_idx, 0, 0};
      FuncMap_Entry entry = {id, stats};
      FuncMap_insert(&ctx->funcs, &entry);
      break;
    }

    case FIELD_LOCATION: {
      uint64_t len;
      if (decomp_read_varint(d, &len) != 0)
        goto error;
      if (len > tmp_cap) {
        uint8_t *new_buf = realloc(tmp_buf, len);
        if (!new_buf)
          goto error;
        tmp_buf = new_buf;
        tmp_cap = len;
      }
      if (decomp_read_bytes(d, tmp_buf, len) != 0)
        goto error;

      // Parse location - extract id and first line's function_id
      uint64_t loc_id = 0;
      uint64_t func_id = 0;
      int found_line = 0;
      pbuf_t inner = {tmp_buf, 0, len};
      while (!pbuf_eof(&inner)) {
        uint64_t itag = pbuf_read_varint(&inner);
        int ifield = itag >> 3;
        int iwire = itag & 7;
        if (ifield == LOCATION_ID) {
          loc_id = pbuf_read_varint(&inner);
        } else if (ifield == LOCATION_LINE && !found_line) {
          // Parse first line only (leaf frame)
          const uint8_t *line_data;
          size_t line_len;
          pbuf_read_bytes(&inner, &line_data, &line_len);
          pbuf_t line = {line_data, 0, line_len};
          while (!pbuf_eof(&line)) {
            uint64_t ltag = pbuf_read_varint(&line);
            int lfield = ltag >> 3;
            int lwire = ltag & 7;
            if (lfield == LINE_FUNCTION_ID)
              func_id = pbuf_read_varint(&line);
            else
              pbuf_skip(&line, lwire);
          }
          found_line = 1;
        } else {
          pbuf_skip(&inner, iwire);
        }
      }
      // Insert into LocMap
      LocMap_Entry loc_entry = {loc_id, func_id};
      LocMap_insert(&ctx->locs, &loc_entry);
      break;
    }

    case FIELD_SAMPLE: {
      // Parse sample and aggregate
      uint64_t len;
      if (decomp_read_varint(d, &len) != 0)
        goto error;
      if (len > tmp_cap) {
        uint8_t *new_buf = realloc(tmp_buf, len);
        if (!new_buf)
          goto error;
        tmp_buf = new_buf;
        tmp_cap = len;
      }
      if (decomp_read_bytes(d, tmp_buf, len) != 0)
        goto error;

      size_t loc_count = 0;
      size_t val_count = 0;

      pbuf_t inner = {tmp_buf, 0, len};
      while (!pbuf_eof(&inner)) {
        uint64_t itag = pbuf_read_varint(&inner);
        int ifield = itag >> 3;
        int iwire = itag & 7;

        if (ifield == SAMPLE_LOCATION_ID) {
          if (iwire == WIRE_LENGTH_DELIMITED) {
            // Packed repeated
            const uint8_t *packed;
            size_t packed_len;
            pbuf_read_bytes(&inner, &packed, &packed_len);
            pbuf_t p = {packed, 0, packed_len};
            while (!pbuf_eof(&p)) {
              if (loc_count >= loc_cap) {
                size_t new_cap = loc_cap ? loc_cap * 2 : 64;
                uint64_t *new_arr =
                    realloc(loc_ids, new_cap * sizeof(uint64_t));
                if (!new_arr)
                  goto error;
                loc_ids = new_arr;
                loc_cap = new_cap;
              }
              loc_ids[loc_count++] = pbuf_read_varint(&p);
            }
          } else {
            if (loc_count >= loc_cap) {
              size_t new_cap = loc_cap ? loc_cap * 2 : 64;
              uint64_t *new_arr = realloc(loc_ids, new_cap * sizeof(uint64_t));
              if (!new_arr)
                goto error;
              loc_ids = new_arr;
              loc_cap = new_cap;
            }
            loc_ids[loc_count++] = pbuf_read_varint(&inner);
          }
        } else if (ifield == SAMPLE_VALUE) {
          if (iwire == WIRE_LENGTH_DELIMITED) {
            const uint8_t *packed;
            size_t packed_len;
            pbuf_read_bytes(&inner, &packed, &packed_len);
            pbuf_t p = {packed, 0, packed_len};
            while (!pbuf_eof(&p)) {
              if (val_count >= val_cap) {
                size_t new_cap = val_cap ? val_cap * 2 : 16;
                int64_t *new_arr = realloc(values, new_cap * sizeof(int64_t));
                if (!new_arr)
                  goto error;
                values = new_arr;
                val_cap = new_cap;
              }
              values[val_count++] = (int64_t)pbuf_read_varint(&p);
            }
          } else {
            if (val_count >= val_cap) {
              size_t new_cap = val_cap ? val_cap * 2 : 16;
              int64_t *new_arr = realloc(values, new_cap * sizeof(int64_t));
              if (!new_arr)
                goto error;
              values = new_arr;
              val_cap = new_cap;
            }
            values[val_count++] = (int64_t)pbuf_read_varint(&inner);
          }
        } else {
          pbuf_skip(&inner, iwire);
        }
      }

      // Aggregate: inuse_objects = values[2], inuse_space = values[3]
      int64_t inuse_objects = val_count > 2 ? values[2] : 0;
      int64_t inuse_bytes = val_count > 3 ? values[3] : 0;

      if (inuse_bytes > 0 && loc_count > 0) {
        // Attribute to leaf function (first location in stack)
        uint64_t loc_id = loc_ids[0];
        LocMap_Iter loc_it = LocMap_find(&ctx->locs, &loc_id);
        LocMap_Entry *loc_e = LocMap_Iter_get(&loc_it);
        if (loc_e && loc_e->val != 0) {
          uint64_t func_id = loc_e->val;
          FuncMap_Iter func_it = FuncMap_find(&ctx->funcs, &func_id);
          FuncMap_Entry *func_e = FuncMap_Iter_get(&func_it);
          if (func_e) {
            func_e->val.inuse_bytes += inuse_bytes;
            func_e->val.inuse_objects += inuse_objects;
          }
        }
        ctx->total_inuse += inuse_bytes;
      }
      break;
    }

    default:
      if (decomp_skip_field(d, wire) != 0)
        goto error;
    }
  }

  free(tmp_buf);
  free(loc_ids);
  free(values);
  return PPROF_OK;

error:
  free(tmp_buf);
  free(loc_ids);
  free(values);
  return PPROF_ERR_PARSE;
}

// ─────────────────────────────────────────────────────────────────────────────
// Resolve specific string indices by re-scanning (targeted fetch)
// ─────────────────────────────────────────────────────────────────────────────

static int resolve_strings(decomp_t *d, int64_t *indices, size_t num_indices,
                           char **names) {
  uint64_t tag;
  int64_t current_idx = 0;
  int err = PPROF_ERR_PARSE; // Default error

  // Find max index we need (to enable early exit)
  int64_t max_needed = 0;
  for (size_t i = 0; i < num_indices; i++) {
    if (indices[i] > max_needed)
      max_needed = indices[i];
  }

  uint8_t *tmp_buf = NULL;
  size_t tmp_cap = 0;

  while (decomp_read_varint(d, &tag) == 0) {
    int field = tag >> 3;
    int wire = tag & 7;

    if (field == FIELD_STRING_TABLE) {
      uint64_t len;
      if (decomp_read_varint(d, &len) != 0)
        goto error;

      // Check if we need this string (may match multiple indices if functions
      // share names)
      int needed = 0;
      for (size_t i = 0; i < num_indices; i++) {
        if (indices[i] == current_idx) {
          needed = 1;
          break;
        }
      }

      if (needed) {
        // Guard against overflow: len + 1 wraps to 0 if len == SIZE_MAX
        if (len >= SIZE_MAX) {
          err = PPROF_ERR_PARSE;
          goto error;
        }
        // Ensure buffer has space for string + null terminator
        size_t needed_cap = len + 1;
        if (needed_cap > tmp_cap) {
          uint8_t *new_buf = realloc(tmp_buf, needed_cap);
          if (!new_buf) {
            err = PPROF_ERR_NOMEM;
            goto error;
          }
          tmp_buf = new_buf;
          tmp_cap = needed_cap;
        }
        if (decomp_read_bytes(d, tmp_buf, len) != 0)
          goto error;
        tmp_buf[len] = '\0';

        // Populate ALL matching indices (multiple functions may share same
        // name)
        for (size_t i = 0; i < num_indices; i++) {
          if (indices[i] == current_idx) {
            names[i] = strdup((char *)tmp_buf);
            if (!names[i]) {
              err = PPROF_ERR_NOMEM;
              goto error;
            }
          }
        }
      } else {
        if (decomp_skip_bytes(d, len) != 0)
          goto error;
      }

      current_idx++;

      // Early exit if we've found all needed strings
      if (current_idx > max_needed)
        break;
    } else {
      if (decomp_skip_field(d, wire) != 0)
        goto error;
    }
  }

  free(tmp_buf);
  return PPROF_OK;

error:
  free(tmp_buf);
  return err;
}

// ─────────────────────────────────────────────────────────────────────────────
// Sort and build results
// ─────────────────────────────────────────────────────────────────────────────

// Sortable entry extracted from FuncMap
typedef struct {
  uint64_t id;
  int64_t name_idx;
  int64_t inuse_bytes;
  int64_t inuse_objects;
} sortable_func_t;

static int cmp_by_bytes_desc(const void *a, const void *b) {
  const sortable_func_t *fa = (const sortable_func_t *)a;
  const sortable_func_t *fb = (const sortable_func_t *)b;
  if (fb->inuse_bytes > fa->inuse_bytes)
    return 1;
  if (fb->inuse_bytes < fa->inuse_bytes)
    return -1;
  return 0;
}

static int build_results(analysis_ctx_t *ctx, decomp_t *d, size_t top_n,
                         pprof_results_t *out) {
  // Extract all entries from FuncMap into sortable array
  size_t func_count = FuncMap_size(&ctx->funcs);
  sortable_func_t *sorted = NULL;

  if (func_count > 0) {
    sorted = malloc(func_count * sizeof(sortable_func_t));
    if (!sorted)
      return PPROF_ERR_NOMEM;

    size_t n = 0;
    FuncMap_Iter it = FuncMap_iter(&ctx->funcs);
    for (FuncMap_Entry *e = FuncMap_Iter_get(&it); e != NULL;
         e = FuncMap_Iter_next(&it)) {
      sorted[n].id = e->key;
      sorted[n].name_idx = e->val.name_idx;
      sorted[n].inuse_bytes = e->val.inuse_bytes;
      sorted[n].inuse_objects = e->val.inuse_objects;
      n++;
    }
    func_count = n;

    // Sort by inuse_bytes descending
    qsort(sorted, func_count, sizeof(sortable_func_t), cmp_by_bytes_desc);
  }

  // Count how many have non-zero usage
  size_t result_count = 0;
  for (size_t i = 0; i < func_count; i++) {
    if (sorted[i].inuse_bytes > 0)
      result_count++;
    else
      break; // sorted, so rest are zero
  }

  // Limit to top_n
  if (top_n > 0 && result_count > top_n)
    result_count = top_n;

  if (result_count == 0) {
    free(sorted);
    out->funcs = NULL;
    out->count = 0;
    out->total_inuse = ctx->total_inuse;
    return PPROF_OK;
  }

  // Collect name indices we need
  int64_t *indices = malloc(result_count * sizeof(int64_t));
  char **names = calloc(result_count, sizeof(char *));
  if (!indices || !names) {
    free(sorted);
    free(indices);
    free(names);
    return PPROF_ERR_NOMEM;
  }

  for (size_t i = 0; i < result_count; i++) {
    indices[i] = sorted[i].name_idx;
  }

  // Reset decompressor and fetch only needed strings
  if (decomp_reset(d) != 0) {
    free(sorted);
    free(indices);
    free(names);
    return PPROF_ERR_DECOMPRESS;
  }

  int rc = resolve_strings(d, indices, result_count, names);
  free(indices);

  if (rc != PPROF_OK) {
    free(sorted);
    for (size_t i = 0; i < result_count; i++)
      free(names[i]);
    free(names);
    return rc;
  }

  // Allocate results
  out->funcs = calloc(result_count, sizeof(pprof_func_stat_t));
  if (!out->funcs) {
    free(sorted);
    for (size_t i = 0; i < result_count; i++)
      free(names[i]);
    free(names);
    return PPROF_ERR_NOMEM;
  }

  out->count = result_count;
  out->total_inuse = ctx->total_inuse;

  // Transfer ownership of names
  for (size_t i = 0; i < result_count; i++) {
    out->funcs[i].name = names[i] ? names[i] : strdup("");
    if (!out->funcs[i].name) {
      // OOM - free already-assigned names and remaining unassigned names
      for (size_t j = 0; j < i; j++)
        free(out->funcs[j].name);
      for (size_t j = i; j < result_count; j++)
        free(names[j]); // Free names not yet transferred
      free(out->funcs);
      out->funcs = NULL;
      out->count = 0;
      free(sorted);
      free(names);
      return PPROF_ERR_NOMEM;
    }
    out->funcs[i].inuse_bytes = sorted[i].inuse_bytes;
    out->funcs[i].inuse_objects = sorted[i].inuse_objects;
  }

  free(sorted);
  free(names);
  return PPROF_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main analysis function
// ─────────────────────────────────────────────────────────────────────────────

static int do_analyze(storage_t *storage, const char *key, size_t top_n,
                      pprof_results_t *out) {
  decomp_t decomp;
  analysis_ctx_t ctx;
  int rc;

  // Default to 5 results if not specified
  if (top_n == 0)
    top_n = PPROF_DEFAULT_TOP_N;

  memset(out, 0, sizeof(*out));

  if (decomp_init(&decomp, storage, key) != 0)
    return PPROF_ERR_IO;

  if (ctx_init(&ctx) != 0) {
    decomp_free(&decomp);
    return PPROF_ERR_NOMEM;
  }

  // Single pass: collect tables + aggregate samples
  rc = analyze_pass(&decomp, &ctx);
  if (rc != PPROF_OK)
    goto cleanup;

  // Free location table - no longer needed after sample aggregation
  LocMap_destroy(&ctx.locs);
  ctx.locs = LocMap_new(0); // reinit so ctx_free doesn't double-free

  // Build results (will reset decomp to fetch top N strings)
  rc = build_results(&ctx, &decomp, top_n, out);

cleanup:
  ctx_free(&ctx);
  decomp_free(&decomp);
  return rc;
}

// ─────────────────────────────────────────────────────────────────────────────
// Plugin handle
// ─────────────────────────────────────────────────────────────────────────────

typedef struct {
  pprof_analyzer_t base;
} pprof_handle_t;

// vtable: top_mem_functions
static int pprof_top_mem_functions(pprof_analyzer_t *a, storage_t *storage,
                                   const char *key, size_t top_n,
                                   pprof_results_t *out) {
  (void)a;
  if (!storage || !key)
    return PPROF_ERR_INVALID;
  return do_analyze(storage, key, top_n, out);
}

// ─────────────────────────────────────────────────────────────────────────────
// Service registration
// ─────────────────────────────────────────────────────────────────────────────

struct pressured_plugin_ctx {
  int initialized;
};

static void *pprof_factory(void *userdata) {
  (void)userdata;

  pprof_handle_t *h = calloc(1, sizeof(pprof_handle_t));
  if (!h)
    return NULL;

  h->base.top_mem_functions = pprof_top_mem_functions;

  log_debug("pprof: created analyzer handle");
  return h;
}

static void pprof_destructor(void *instance, void *userdata) {
  (void)userdata;
  if (instance) {
    log_debug("pprof: destroyed analyzer handle");
    free(instance);
  }
}

static const char *pprof_tags[] = {"profiling", "heap", "golang", NULL};

static const service_metadata_t analyzer_service_meta = {
    .type = "analyzer",
    .provider = "pprof",
    .version = "1.0.0",
    .description = "pprof heap analyzer for Go applications",
    .priority = 100,
    .tags = pprof_tags,
    .dependencies = NULL,
    .interface_version = 1,
};

// ─────────────────────────────────────────────────────────────────────────────
// Plugin lifecycle (3-symbol protocol)
// ─────────────────────────────────────────────────────────────────────────────

static const pressured_plugin_metadata_t plugin_metadata = {
    .name = "pprof",
    .major_version = 1,
    .minor_version = 0,
    .description = "pprof heap analyzer"};

PRESSURED_PLUGIN_EXPORT const pressured_plugin_metadata_t *
pressured_plugin_get_metadata(void) {
  return &plugin_metadata;
}

PRESSURED_PLUGIN_EXPORT pressured_plugin_ctx_t *
pressured_plugin_load(const char *config_json, service_registry_t *sr) {
  (void)config_json;

  pressured_plugin_ctx_t *ctx = calloc(1, sizeof(pressured_plugin_ctx_t));
  if (!ctx)
    return NULL;

  // Register analyzer service with the registry
  int rc = service_registry_register(sr, &analyzer_service_meta,
                                     SERVICE_SCOPE_SINGLETON, pprof_factory,
                                     pprof_destructor, ctx);
  if (rc != 0) {
    log_error("pprof: failed to register with service registry");
    free(ctx);
    return NULL;
  }

  ctx->initialized = 1;
  log_info("pprof: heap analyzer v1.0 loaded");
  return ctx;
}

PRESSURED_PLUGIN_EXPORT void
pressured_plugin_unload(pressured_plugin_ctx_t *ctx) {
  if (ctx) {
    log_debug("pprof: plugin unloaded");
    free(ctx);
  }
}
