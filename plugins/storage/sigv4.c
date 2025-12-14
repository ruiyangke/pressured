/*
 * AWS Signature Version 4 Signing Utilities
 *
 * Implements the cryptographic primitives and URL handling for AWS SigV4.
 * Reference:
 * https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
 */

#include "sigv4.h"
#include "crypto.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ─────────────────────────────────────────────────────────────────────────────
// Cryptographic Primitives (using crypto abstraction layer)
// ─────────────────────────────────────────────────────────────────────────────

void sigv4_hex_encode(const unsigned char *input, size_t len, char *output) {
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    output[i * 2] = hex[input[i] >> 4];
    output[i * 2 + 1] = hex[input[i] & 0x0f];
  }
  output[len * 2] = '\0';
}

void sigv4_sha256(const void *data, size_t len, unsigned char *hash) {
  crypto_sha256(data, len, hash);
}

void sigv4_hmac_sha256(const void *key, size_t key_len, const void *data,
                       size_t data_len, unsigned char *out) {
  crypto_hmac_sha256(key, key_len, data, data_len, out);
}

// ─────────────────────────────────────────────────────────────────────────────
// AWS SigV4 Key Derivation
// ─────────────────────────────────────────────────────────────────────────────

void sigv4_get_signing_key(const char *secret_key, const char *date_stamp,
                           const char *region, const char *service,
                           unsigned char *out_key) {
  // AWS4 + secret_key (max 512 bytes for secret key)
  char key[520];
  snprintf(key, sizeof(key), "AWS4%s", secret_key);

  unsigned char k_date[32], k_region[32], k_service[32];

  // kDate = HMAC("AWS4" + kSecret, Date)
  sigv4_hmac_sha256(key, strlen(key), date_stamp, strlen(date_stamp), k_date);

  // kRegion = HMAC(kDate, Region)
  sigv4_hmac_sha256(k_date, 32, region, strlen(region), k_region);

  // kService = HMAC(kRegion, Service)
  sigv4_hmac_sha256(k_region, 32, service, strlen(service), k_service);

  // kSigning = HMAC(kService, "aws4_request")
  sigv4_hmac_sha256(k_service, 32, "aws4_request", 12, out_key);
}

// ─────────────────────────────────────────────────────────────────────────────
// URL Parsing
// ─────────────────────────────────────────────────────────────────────────────

int sigv4_parse_url(const char *url, char *host, size_t host_len, char *path,
                    size_t path_len, char *query, size_t query_len) {
  if (!url || !host || !path || !query) {
    return -1;
  }

  // Initialize outputs
  host[0] = '\0';
  path[0] = '/';
  path[1] = '\0';
  query[0] = '\0';

  // Find "://"
  const char *host_start = strstr(url, "://");
  if (!host_start) {
    return -1;
  }
  host_start += 3;

  // Find end of host (first '/')
  const char *host_end = strchr(host_start, '/');
  if (host_end) {
    size_t len = (size_t)(host_end - host_start);
    if (len >= host_len) {
      return -1;
    }
    strncpy(host, host_start, len);
    host[len] = '\0';

    // Check for query string
    const char *query_start = strchr(host_end, '?');
    if (query_start) {
      // Path is from host_end to query_start
      size_t plen = (size_t)(query_start - host_end);
      if (plen >= path_len) {
        return -1;
      }
      strncpy(path, host_end, plen);
      path[plen] = '\0';

      // Query is everything after '?'
      const char *q = query_start + 1;
      size_t qlen = strlen(q);
      if (qlen >= query_len) {
        return -1;
      }
      strncpy(query, q, qlen);
      query[qlen] = '\0';
    } else {
      // No query string, just path
      size_t plen = strlen(host_end);
      if (plen >= path_len) {
        return -1;
      }
      strncpy(path, host_end, plen);
      path[plen] = '\0';
    }
  } else {
    // No path, just host
    size_t len = strlen(host_start);
    if (len >= host_len) {
      return -1;
    }
    strncpy(host, host_start, len);
    host[len] = '\0';
  }

  return 0;
}

// Check if character is AWS unreserved (doesn't need encoding)
static int is_unreserved(unsigned char c) {
  return isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~';
}

// URL encode a string per AWS requirements
static size_t url_encode(const char *src, char *dst, size_t dst_len) {
  static const char hex[] = "0123456789ABCDEF";
  size_t j = 0;

  for (size_t i = 0; src[i] && j < dst_len - 1; i++) {
    unsigned char c = (unsigned char)src[i];
    if (is_unreserved(c)) {
      if (j >= dst_len - 1)
        break;
      dst[j++] = c;
    } else {
      if (j >= dst_len - 3)
        break;
      dst[j++] = '%';
      dst[j++] = hex[c >> 4];
      dst[j++] = hex[c & 0x0f];
    }
  }
  dst[j] = '\0';
  return j;
}

// Comparison function for qsort
static int compare_params(const void *a, const void *b) {
  return strcmp(*(const char **)a, *(const char **)b);
}

int sigv4_canonicalize_query(const char *query_in, char *query_out,
                             size_t out_len) {
  if (!query_out || out_len == 0) {
    return -1;
  }

  query_out[0] = '\0';

  // Empty query string
  if (!query_in || query_in[0] == '\0') {
    return 0;
  }

  // Make a mutable copy
  char *copy = strdup(query_in);
  if (!copy) {
    return -1;
  }

  // Split into params (max 64 params)
  char *params[64] = {NULL};
  int param_count = 0;

  char *saveptr = NULL;
  char *token = strtok_r(copy, "&", &saveptr);
  while (token && param_count < 64) {
    params[param_count++] = token;
    token = strtok_r(NULL, "&", &saveptr);
  }

  // Sort parameters alphabetically
  qsort(params, param_count, sizeof(char *), compare_params);

  // Build canonical query string
  size_t offset = 0;
  for (int i = 0; i < param_count; i++) {
    if (i > 0) {
      if (offset < out_len - 1) {
        query_out[offset++] = '&';
      }
    }

    // Split param into name=value
    char *eq = strchr(params[i], '=');
    if (eq) {
      // Has explicit value
      *eq = '\0';
      const char *name = params[i];
      const char *value = eq + 1;

      // URL encode name and value
      char encoded_name[256], encoded_value[256];
      url_encode(name, encoded_name, sizeof(encoded_name));
      url_encode(value, encoded_value, sizeof(encoded_value));

      int n = snprintf(query_out + offset, out_len - offset, "%s=%s",
                       encoded_name, encoded_value);
      if (n > 0)
        offset += n;
    } else {
      // No value (e.g., "uploads") - AWS requires "uploads="
      char encoded_name[256];
      url_encode(params[i], encoded_name, sizeof(encoded_name));

      int n =
          snprintf(query_out + offset, out_len - offset, "%s=", encoded_name);
      if (n > 0)
        offset += n;
    }
  }

  free(copy);
  return 0;
}
