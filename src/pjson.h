#ifndef PJSON_H
#define PJSON_H

// Helpers over the vendored yyjson reader. Call sites use yyjson's own
// accessors (yyjson_obj_get, yyjson_get_str, yyjson_arr_foreach, ...); this
// header adds only what yyjson lacks: parse errors that name the document,
// typed config lookups that warn about wrong types, and reading any JSON number
// as an integer (yyjson_get_int returns 0 for a real).

#include "log.h"
#include "yyjson.h"
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>

// Config files, including the plugin sections that plugins parse from the same
// text: comments, trailing commas, single-quoted strings, NaN/Infinity, lax
// number forms ("1.", "+1", "0x10"), a UTF-8 BOM, invalid UTF-8 and raw
// control characters in strings, and bytes after the document.
#define PJ_READ_CONFIG                                                         \
  (YYJSON_READ_ALLOW_COMMENTS | YYJSON_READ_ALLOW_TRAILING_COMMAS |            \
   YYJSON_READ_ALLOW_SINGLE_QUOTED_STR | YYJSON_READ_ALLOW_INF_AND_NAN |       \
   YYJSON_READ_ALLOW_EXT_NUMBER | YYJSON_READ_ALLOW_BOM |                      \
   YYJSON_READ_ALLOW_INVALID_UNICODE | YYJSON_READ_STOP_WHEN_DONE)

// Kubernetes API and credential responses: strict JSON, except that one bad
// UTF-8 byte in a string does not discard the whole response.
#define PJ_READ_API YYJSON_READ_ALLOW_INVALID_UNICODE

// Parse `len` bytes of `data`. On failure logs the yyjson error, its byte
// offset and `what`, and returns NULL. Free the result with yyjson_doc_free.
static inline yyjson_doc *pj_parse(const char *data, size_t len,
                                   yyjson_read_flag flags, const char *what) {
  yyjson_read_err err;
  // Without YYJSON_READ_INSITU yyjson copies the input and never writes to it.
  yyjson_doc *doc =
      yyjson_read_opts((char *)(void *)(size_t)(const void *)data, len,
                       flags & ~YYJSON_READ_INSITU, NULL, &err);
  if (!doc)
    log_warn("failed to parse %s: %s at byte %zu", what, err.msg, err.pos);
  return doc;
}

// Config value of `key` in `obj` when `is_type` accepts it. A missing key or a
// JSON null returns NULL silently so the caller keeps its default (Helm renders
// unset values as null); any other type returns NULL after one warning naming
// `section`.`key` and the expected `type`, e.g. "a number" ("" section for a
// top-level key).
static inline yyjson_val *pj_config_value(yyjson_val *obj, const char *section,
                                          const char *key, const char *type,
                                          bool (*is_type)(const yyjson_val *)) {
  yyjson_val *val = yyjson_obj_get(obj, key);
  if (!val || yyjson_is_null(val))
    return NULL;
  if (!is_type(val)) {
    log_warn("config: %s%s%s must be %s, ignoring it", section,
             section[0] ? "." : "", key, type);
    return NULL;
  }
  return val;
}

// Any JSON number as an int64_t: integers as-is (an unsigned value above
// INT64_MAX clamps), reals truncated toward zero and clamped. Returns false and
// leaves *out unchanged for NaN and for anything that is not a JSON number;
// numeric strings are not converted.
static inline bool pj_int64(yyjson_val *v, int64_t *out) {
  if (yyjson_is_sint(v)) {
    *out = yyjson_get_sint(v);
  } else if (yyjson_is_uint(v)) {
    uint64_t u = yyjson_get_uint(v);
    *out = u > INT64_MAX ? INT64_MAX : (int64_t)u;
  } else if (yyjson_is_real(v)) {
    double d = yyjson_get_real(v);
    if (isnan(d))
      return false;
    // INT64_MAX is not exact as a double; (double)INT64_MAX rounds up to 2^63.
    if (d >= (double)INT64_MAX)
      *out = INT64_MAX;
    else if (d <= (double)INT64_MIN)
      *out = INT64_MIN;
    else
      *out = (int64_t)d;
  } else {
    return false;
  }
  return true;
}

// pj_int64 clamped to the range of int.
static inline bool pj_int(yyjson_val *v, int *out) {
  int64_t n;
  if (!pj_int64(v, &n))
    return false;
  *out = n > INT_MAX ? INT_MAX : n < INT_MIN ? INT_MIN : (int)n;
  return true;
}

#endif // PJSON_H
