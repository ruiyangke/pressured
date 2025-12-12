/*
 * AWS S3 storage plugin using libcurl and AWS Signature V4
 *
 * Registers as "storage:s3" with the service registry.
 * Plugin name: "s3-storage" (used for config lookup)
 *
 * Configuration (via JSON config file):
 *   plugins.s3-storage.enabled = false  - Disable this plugin
 *   storage.s3.bucket   - S3 bucket name (required)
 *   storage.s3.region   - AWS region (default: us-east-1)
 *   storage.s3.prefix   - Key prefix (default: "")
 *   storage.s3.endpoint - Custom endpoint (for MinIO, LocalStack, etc.)
 *
 * Credential sources (checked in AWS SDK standard order):
 *   1. Static environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
 *   2. IRSA (IAM Roles for Service Accounts) - EKS with OIDC
 *   3. EKS Pod Identity / ECS Container Credentials
 *   4. EC2 Instance Metadata Service (IMDS v2)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * COMPILE-TIME UPLOAD MODE SELECTION
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Define ONE of these before including this file or via compiler flags:
 *
 *   S3_UPLOAD_STREAMING (default)
 *     - Uses single PutObject with UNSIGNED-PAYLOAD
 *     - Single HTTP request with chunked transfer encoding
 *     - Memory: ~64KB buffer (bounded via backpressure)
 *     - Uses curl_multi for non-blocking upload during write() calls
 *     - Max size: 5GB (S3 PutObject limit)
 *     - Best for: Any file size with minimal memory footprint
 *
 *   S3_UPLOAD_MULTIPART
 *     - Uses S3 Multipart Upload API
 *     - Multiple HTTP requests (init + parts + complete)
 *     - Memory: ~5MB buffer per part (uploads during write, not on close)
 *     - Max size: Unlimited (up to 10,000 parts × 5GB each)
 *     - Best for: Files > 5GB, resumable uploads
 *
 * Example: cmake -DS3_UPLOAD_MODE=MULTIPART ..
 */

// Default to streaming if neither is defined
#if !defined(S3_UPLOAD_MULTIPART) && !defined(S3_UPLOAD_STREAMING)
#define S3_UPLOAD_STREAMING
#endif

// Ensure only one is defined
#if defined(S3_UPLOAD_MULTIPART) && defined(S3_UPLOAD_STREAMING)
#error "Cannot define both S3_UPLOAD_MULTIPART and S3_UPLOAD_STREAMING"
#endif

#include "log.h"
#include "plugin.h"
#include "s3_storage.h"
#include "service_registry.h"
#include "storage.h"
#include <curl/curl.h>
#include <json-c/json.h>
#include <limits.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_URL_LEN 2048
#define MAX_HEADER_LEN 512
#define MULTIPART_PART_SIZE (64 * 1024 * 1024) // 64MB per part
#define MAX_PARTS 10000
#define STREAMING_CHUNK_SIZE (64 * 1024)    // 64KB chunks for streaming PutObject
#define MAX_STREAMING_BUFFER (256 * 1024)   // Cap buffer at 256KB to bound memory
#define RING_BUFFER_SIZE (64 * 1024)        // 64KB ring buffer for true streaming

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

typedef enum {
  CRED_STATIC,
  CRED_IRSA,
  CRED_POD_IDENTITY,
  CRED_IMDS
} cred_source_t;

// Plugin context (global state)
struct pressured_plugin_ctx {
  char access_key[256];
  char secret_key[512];
  char session_token[4096]; // AWS STS session tokens can be large
  char region[64];
  char bucket[256];
  char prefix[512];
  char endpoint[512];
  char role_arn[512];
  char web_identity_token_file[512];
  char container_creds_uri[512];
  cred_source_t cred_source;
  time_t cred_expiration;
  CURL *curl;
};

// Plugin handle (storage instance)
// MUST embed storage_t as first field for vtable dispatch
struct pressured_plugin_handle {
  storage_t base; // vtable - MUST be first
  pressured_plugin_ctx_t *ctx;
};

// Minimum part size for S3 multipart uploads (5MB)
// All parts except the last must be at least this size
#define S3_MIN_PART_SIZE (5 * 1024 * 1024)

#ifdef S3_UPLOAD_STREAMING
// Simple buffer for curl_multi streaming
typedef struct {
  char *data;
  size_t size;     // Current data in buffer
  size_t capacity;
  size_t pos;      // Read position for curl callback
} stream_buffer_t;
#endif

// File handle for streaming
typedef struct {
  pressured_plugin_ctx_t *ctx;
  char key[1024];
  int mode;

#ifdef S3_UPLOAD_MULTIPART
  // For writes: multipart upload state
  char *upload_id;
  int part_number;
  char **etags; // Array of ETags
  int etags_capacity;

  // Write buffer - accumulate data until S3_MIN_PART_SIZE
  char *write_buffer;
  size_t write_buffer_size;
  size_t write_buffer_capacity;
#endif

#ifdef S3_UPLOAD_STREAMING
  // For writes: curl_multi streaming
  CURLM *multi;
  CURL *upload_curl;
  struct curl_slist *headers;
  stream_buffer_t buf;
  int upload_started;
  int upload_finished;
  int64_t expected_size;  // Set via s3_set_upload_size() before first write
#endif

  // For reads: buffer state (non-streaming fallback)
  char *read_buffer;
  size_t read_size;
  size_t read_pos;

#ifdef S3_UPLOAD_STREAMING
  // For reads: curl_multi streaming (reuses upload structures naming for simplicity)
  // When reading, multi/download_curl handle the GET request
  // buf receives data from curl write callback
  CURL *download_curl;        // Separate handle for downloads
  int download_started;
  int download_finished;
  int64_t content_length;     // Total size from Content-Length header (-1 if unknown)
  int64_t bytes_received;     // Total bytes received so far
#endif
} s3_file_t;

// Response buffer
typedef struct {
  char *data;
  size_t size;
  size_t capacity;
} response_buffer_t;

// ─────────────────────────────────────────────────────────────────────────────
// Forward declarations
// ─────────────────────────────────────────────────────────────────────────────

static size_t write_callback(void *contents, size_t size, size_t nmemb,
                             void *userp);
static int ensure_credentials(pressured_plugin_ctx_t *ctx);
static void build_url(const pressured_plugin_ctx_t *ctx, const char *key,
                      char *url, size_t url_len);
static struct curl_slist *sign_request(const pressured_plugin_ctx_t *ctx,
                                       const char *method, const char *url,
                                       const char *payload_hash,
                                       size_t content_length);
static struct curl_slist *sign_copy_request(const pressured_plugin_ctx_t *ctx,
                                            const char *method, const char *url,
                                            const char *payload_hash,
                                            const char *copy_source);

// ─────────────────────────────────────────────────────────────────────────────
// AWS Signature V4 helpers
// ─────────────────────────────────────────────────────────────────────────────

static void hex_encode(const unsigned char *input, size_t len, char *output) {
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    output[i * 2] = hex[input[i] >> 4];
    output[i * 2 + 1] = hex[input[i] & 0x0f];
  }
  output[len * 2] = '\0';
}

static void sha256(const void *data, size_t len, unsigned char *hash) {
  SHA256_CTX sha_ctx;
  SHA256_Init(&sha_ctx);
  SHA256_Update(&sha_ctx, data, len);
  SHA256_Final(hash, &sha_ctx);
}

static void hmac_sha256(const void *key, size_t key_len, const void *data,
                        size_t data_len, unsigned char *out) {
  unsigned int out_len = 32;
  HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &out_len);
}

static void get_signing_key(const char *secret_key, const char *date_stamp,
                            const char *region, const char *service,
                            unsigned char *out_key) {
  char key[520]; // "AWS4" (4) + secret_key (512 max) + null = 517, round up
  snprintf(key, sizeof(key), "AWS4%s", secret_key);

  unsigned char k_date[32], k_region[32], k_service[32];

  hmac_sha256(key, strlen(key), date_stamp, strlen(date_stamp), k_date);
  hmac_sha256(k_date, 32, region, strlen(region), k_region);
  hmac_sha256(k_region, 32, service, strlen(service), k_service);
  hmac_sha256(k_service, 32, "aws4_request", 12, out_key);
}

static size_t write_callback(void *contents, size_t size, size_t nmemb,
                             void *userp) {
  size_t realsize = size * nmemb;
  response_buffer_t *buf = (response_buffer_t *)userp;

  if (buf->size + realsize >= buf->capacity) {
    size_t new_cap = buf->capacity * 2;
    if (new_cap < buf->size + realsize + 1) {
      new_cap = buf->size + realsize + 1;
    }
    char *new_data = realloc(buf->data, new_cap);
    if (!new_data)
      return 0;
    buf->data = new_data;
    buf->capacity = new_cap;
  }

  memcpy(buf->data + buf->size, contents, realsize);
  buf->size += realsize;
  buf->data[buf->size] = '\0';

  return realsize;
}

static void build_url(const pressured_plugin_ctx_t *ctx, const char *key,
                      char *url, size_t url_len) {
  const char *k = key;
  while (*k == '/')
    k++; // Strip leading slashes from key

  // Strip trailing slashes from prefix to avoid double slashes
  char prefix_clean[512];
  strncpy(prefix_clean, ctx->prefix, sizeof(prefix_clean) - 1);
  prefix_clean[sizeof(prefix_clean) - 1] = '\0';
  size_t prefix_len = strlen(prefix_clean);
  while (prefix_len > 0 && prefix_clean[prefix_len - 1] == '/') {
    prefix_clean[--prefix_len] = '\0';
  }

  char full_key[1024];
  if (prefix_clean[0]) {
    snprintf(full_key, sizeof(full_key), "%s/%s", prefix_clean, k);
  } else {
    snprintf(full_key, sizeof(full_key), "%s", k);
  }

  if (ctx->endpoint[0]) {
    snprintf(url, url_len, "%s/%s/%s", ctx->endpoint, ctx->bucket, full_key);
  } else {
    snprintf(url, url_len, "https://%s.s3.%s.amazonaws.com/%s", ctx->bucket,
             ctx->region, full_key);
  }
}

static struct curl_slist *sign_request(const pressured_plugin_ctx_t *ctx,
                                       const char *method, const char *url,
                                       const char *payload_hash,
                                       size_t content_length) {
  time_t now = time(NULL);
  struct tm gmt_buf;
  const struct tm *gmt = gmtime_r(&now, &gmt_buf);

  char amz_date[32], date_stamp[16];
  strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", gmt);
  strftime(date_stamp, sizeof(date_stamp), "%Y%m%d", gmt);

  // Parse URL to get host, path, and query string
  char host[256] = {0};
  char path[1024] = "/";
  char query[1024] = ""; // Empty query string by default

  const char *host_start = strstr(url, "://");
  if (host_start) {
    host_start += 3;
    const char *host_end = strchr(host_start, '/');
    if (host_end) {
      size_t host_len = host_end - host_start;
      if (host_len < sizeof(host)) {
        strncpy(host, host_start, host_len);
        host[host_len] = '\0';
      }
      // Check for query string
      const char *query_start = strchr(host_end, '?');
      if (query_start) {
        // Path is from host_end to query_start
        size_t path_len = query_start - host_end;
        if (path_len < sizeof(path)) {
          strncpy(path, host_end, path_len);
          path[path_len] = '\0';
        }
        // Query is everything after '?'
        // AWS SigV4 requires params without values to have trailing '='
        // e.g., ?uploads becomes "uploads=" in canonical query string
        strncpy(query, query_start + 1, sizeof(query) - 1);
        query[sizeof(query) - 1] = '\0';
        // If query param has no '=', append one (e.g., "uploads" -> "uploads=")
        if (query[0] && !strchr(query, '=')) {
          size_t qlen = strlen(query);
          if (qlen < sizeof(query) - 1) {
            query[qlen] = '=';
            query[qlen + 1] = '\0';
          }
        }
      } else {
        strncpy(path, host_end, sizeof(path) - 1);
      }
    } else {
      strncpy(host, host_start, sizeof(host) - 1);
    }
  }

  // Canonical request (headers buffer must fit session token up to 4096 bytes)
  char canonical_headers[5120];
  const char *signed_headers;

  if (ctx->session_token[0]) {
    snprintf(canonical_headers, sizeof(canonical_headers),
             "host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\nx-amz-security-"
             "token:%s\n",
             host, payload_hash, amz_date, ctx->session_token);
    signed_headers =
        "host;x-amz-content-sha256;x-amz-date;x-amz-security-token";
  } else {
    snprintf(canonical_headers, sizeof(canonical_headers),
             "host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n", host,
             payload_hash, amz_date);
    signed_headers = "host;x-amz-content-sha256;x-amz-date";
  }

  char canonical_request[8192];
  snprintf(canonical_request, sizeof(canonical_request),
           "%s\n%s\n%s\n%s\n%s\n%s", method, path, query, canonical_headers,
           signed_headers, payload_hash);

  // Hash canonical request
  unsigned char canonical_hash[32];
  sha256(canonical_request, strlen(canonical_request), canonical_hash);
  char canonical_hash_hex[65];
  hex_encode(canonical_hash, 32, canonical_hash_hex);

  // String to sign
  char credential_scope[128];
  snprintf(credential_scope, sizeof(credential_scope), "%s/%s/s3/aws4_request",
           date_stamp, ctx->region);

  char string_to_sign[4096];
  snprintf(string_to_sign, sizeof(string_to_sign),
           "AWS4-HMAC-SHA256\n%s\n%s\n%s", amz_date, credential_scope,
           canonical_hash_hex);

  // Sign
  unsigned char signing_key[32];
  get_signing_key(ctx->secret_key, date_stamp, ctx->region, "s3", signing_key);

  unsigned char signature[32];
  hmac_sha256(signing_key, 32, string_to_sign, strlen(string_to_sign),
              signature);
  char signature_hex[65];
  hex_encode(signature, 32, signature_hex);

  // Build headers
  char auth_header[1024];
  snprintf(auth_header, sizeof(auth_header),
           "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, "
           "SignedHeaders=%s, Signature=%s",
           ctx->access_key, credential_scope, signed_headers, signature_hex);

  struct curl_slist *headers = NULL;

  char host_header[MAX_HEADER_LEN];
  snprintf(host_header, sizeof(host_header), "Host: %s", host);
  headers = curl_slist_append(headers, host_header);

  char date_header[MAX_HEADER_LEN];
  snprintf(date_header, sizeof(date_header), "x-amz-date: %s", amz_date);
  headers = curl_slist_append(headers, date_header);

  char sha_header[MAX_HEADER_LEN];
  snprintf(sha_header, sizeof(sha_header), "x-amz-content-sha256: %s",
           payload_hash);
  headers = curl_slist_append(headers, sha_header);

  headers = curl_slist_append(headers, auth_header);

  if (ctx->session_token[0]) {
    char token_header[4200]; // 4096 for token + header prefix
    snprintf(token_header, sizeof(token_header), "x-amz-security-token: %s",
             ctx->session_token);
    headers = curl_slist_append(headers, token_header);
  }

  if (content_length > 0) {
    char len_header[MAX_HEADER_LEN];
    snprintf(len_header, sizeof(len_header), "Content-Length: %zu",
             content_length);
    headers = curl_slist_append(headers, len_header);
  }

  return headers;
}

// Sign request with x-amz-copy-source header (for S3 CopyObject)
static struct curl_slist *sign_copy_request(const pressured_plugin_ctx_t *ctx,
                                            const char *method, const char *url,
                                            const char *payload_hash,
                                            const char *copy_source) {
  time_t now = time(NULL);
  struct tm gmt_buf;
  const struct tm *gmt = gmtime_r(&now, &gmt_buf);

  char amz_date[32], date_stamp[16];
  strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", gmt);
  strftime(date_stamp, sizeof(date_stamp), "%Y%m%d", gmt);

  // Parse URL to get host, path, and query string
  char host[256] = {0};
  char path[1024] = "/";
  char query[1024] = "";

  const char *host_start = strstr(url, "://");
  if (host_start) {
    host_start += 3;
    const char *host_end = strchr(host_start, '/');
    if (host_end) {
      size_t host_len = host_end - host_start;
      if (host_len < sizeof(host)) {
        strncpy(host, host_start, host_len);
        host[host_len] = '\0';
      }
      const char *query_start = strchr(host_end, '?');
      if (query_start) {
        size_t path_len = query_start - host_end;
        if (path_len < sizeof(path)) {
          strncpy(path, host_end, path_len);
          path[path_len] = '\0';
        }
        strncpy(query, query_start + 1, sizeof(query) - 1);
        query[sizeof(query) - 1] = '\0';
        if (query[0] && !strchr(query, '=')) {
          size_t qlen = strlen(query);
          if (qlen < sizeof(query) - 1) {
            query[qlen] = '=';
            query[qlen + 1] = '\0';
          }
        }
      } else {
        strncpy(path, host_end, sizeof(path) - 1);
      }
    } else {
      strncpy(host, host_start, sizeof(host) - 1);
    }
  }

  // Canonical headers (alphabetically sorted, x-amz-copy-source comes between
  // host and x-amz-content-sha256)
  char canonical_headers[6144];
  const char *signed_headers;

  if (ctx->session_token[0]) {
    snprintf(canonical_headers, sizeof(canonical_headers),
             "host:%s\nx-amz-content-sha256:%s\nx-amz-copy-source:%s\nx-amz-"
             "date:%s\nx-amz-security-token:%s\n",
             host, payload_hash, copy_source, amz_date, ctx->session_token);
    signed_headers = "host;x-amz-content-sha256;x-amz-copy-source;x-amz-date;x-"
                     "amz-security-token";
  } else {
    snprintf(canonical_headers, sizeof(canonical_headers),
             "host:%s\nx-amz-content-sha256:%s\nx-amz-copy-source:%s\nx-amz-"
             "date:%s\n",
             host, payload_hash, copy_source, amz_date);
    signed_headers = "host;x-amz-content-sha256;x-amz-copy-source;x-amz-date";
  }

  char canonical_request[8192];
  snprintf(canonical_request, sizeof(canonical_request),
           "%s\n%s\n%s\n%s\n%s\n%s", method, path, query, canonical_headers,
           signed_headers, payload_hash);

  unsigned char canonical_hash[32];
  sha256(canonical_request, strlen(canonical_request), canonical_hash);
  char canonical_hash_hex[65];
  hex_encode(canonical_hash, 32, canonical_hash_hex);

  char credential_scope[128];
  snprintf(credential_scope, sizeof(credential_scope), "%s/%s/s3/aws4_request",
           date_stamp, ctx->region);

  char string_to_sign[4096];
  snprintf(string_to_sign, sizeof(string_to_sign),
           "AWS4-HMAC-SHA256\n%s\n%s\n%s", amz_date, credential_scope,
           canonical_hash_hex);

  unsigned char signing_key[32];
  get_signing_key(ctx->secret_key, date_stamp, ctx->region, "s3", signing_key);

  unsigned char signature[32];
  hmac_sha256(signing_key, 32, string_to_sign, strlen(string_to_sign),
              signature);
  char signature_hex[65];
  hex_encode(signature, 32, signature_hex);

  char auth_header[1024];
  snprintf(auth_header, sizeof(auth_header),
           "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, "
           "SignedHeaders=%s, Signature=%s",
           ctx->access_key, credential_scope, signed_headers, signature_hex);

  struct curl_slist *headers = NULL;

  char host_header[MAX_HEADER_LEN];
  snprintf(host_header, sizeof(host_header), "Host: %s", host);
  headers = curl_slist_append(headers, host_header);

  char date_header[MAX_HEADER_LEN];
  snprintf(date_header, sizeof(date_header), "x-amz-date: %s", amz_date);
  headers = curl_slist_append(headers, date_header);

  char sha_header[MAX_HEADER_LEN];
  snprintf(sha_header, sizeof(sha_header), "x-amz-content-sha256: %s",
           payload_hash);
  headers = curl_slist_append(headers, sha_header);

  char copy_header[MAX_URL_LEN + 32];
  snprintf(copy_header, sizeof(copy_header), "x-amz-copy-source: %s",
           copy_source);
  headers = curl_slist_append(headers, copy_header);

  headers = curl_slist_append(headers, auth_header);

  if (ctx->session_token[0]) {
    char token_header[4200];
    snprintf(token_header, sizeof(token_header), "x-amz-security-token: %s",
             ctx->session_token);
    headers = curl_slist_append(headers, token_header);
  }

  return headers;
}

// ─────────────────────────────────────────────────────────────────────────────
// Credential refresh - supports IRSA, EKS Pod Identity, IMDS, and static creds
// ─────────────────────────────────────────────────────────────────────────────

static int http_get(CURL *curl, const char *url, char *out, size_t out_len,
                    struct curl_slist *headers) {
  if (!curl || !url || !out || out_len == 0)
    return -1;

  response_buffer_t resp = {0};
  resp.data = malloc(8192);
  if (!resp.data)
    return -1;
  resp.capacity = 8192;
  resp.size = 0;

  curl_easy_reset(curl);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
  if (headers) {
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  }

  CURLcode res = curl_easy_perform(curl);
  long http_code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

  if (res == CURLE_OK && http_code == 200 && resp.size > 0) {
    size_t copy_len = resp.size < out_len - 1 ? resp.size : out_len - 1;
    memcpy(out, resp.data, copy_len);
    out[copy_len] = '\0';
    free(resp.data);
    return 0;
  }

  free(resp.data);
  return -1;
}

static int http_post(CURL *curl, const char *url, const char *body, char *out,
                     size_t out_len, struct curl_slist *headers) {
  if (!curl || !url || !out || out_len == 0)
    return -1;

  response_buffer_t resp = {0};
  resp.data = malloc(16384);
  if (!resp.data)
    return -1;
  resp.capacity = 16384;
  resp.size = 0;

  curl_easy_reset(curl);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  if (body) {
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
  }
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
  if (headers) {
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  }

  CURLcode res = curl_easy_perform(curl);
  long http_code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

  if (res == CURLE_OK && http_code == 200 && resp.size > 0) {
    size_t copy_len = resp.size < out_len - 1 ? resp.size : out_len - 1;
    memcpy(out, resp.data, copy_len);
    out[copy_len] = '\0';
    free(resp.data);
    return 0;
  }

  log_debug("s3_storage: http_post failed: curl_code=%d http_code=%ld", res,
            http_code);
  free(resp.data);
  return -1;
}

// Read file contents into buffer
static char *read_file(const char *path, size_t *out_len) {
  FILE *f = fopen(path, "r");
  if (!f)
    return NULL;

  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  fseek(f, 0, SEEK_SET);

  if (size <= 0 || size > 65536) {
    fclose(f);
    return NULL;
  }

  char *buf = malloc(size + 1);
  if (!buf) {
    fclose(f);
    return NULL;
  }

  size_t read_size = fread(buf, 1, size, f);
  fclose(f);

  buf[read_size] = '\0';
  // Trim trailing whitespace
  while (read_size > 0 &&
         (buf[read_size - 1] == '\n' || buf[read_size - 1] == '\r')) {
    buf[--read_size] = '\0';
  }

  if (out_len)
    *out_len = read_size;
  return buf;
}

// Parse ISO 8601 timestamp to time_t (simplified)
static time_t parse_iso8601(const char *str) {
  struct tm tm = {0};
  // Format: 2024-12-07T12:34:56Z
  if (sscanf(str, "%d-%d-%dT%d:%d:%d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
             &tm.tm_hour, &tm.tm_min, &tm.tm_sec) >= 6) {
    tm.tm_year -= 1900;
    tm.tm_mon -= 1;
    return timegm(&tm);
  }
  return 0;
}

// URL encode a string
static char *url_encode(CURL *curl, const char *str) {
  return curl_easy_escape(curl, str, 0);
}

// Extract XML element value
static int extract_xml_value(const char *xml, const char *tag, char *out,
                             size_t out_len) {
  char open_tag[64], close_tag[64];
  snprintf(open_tag, sizeof(open_tag), "<%s>", tag);
  snprintf(close_tag, sizeof(close_tag), "</%s>", tag);

  const char *start = strstr(xml, open_tag);
  if (!start)
    return -1;
  start += strlen(open_tag);

  const char *end = strstr(start, close_tag);
  if (!end)
    return -1;

  size_t len = end - start;
  if (len >= out_len)
    len = out_len - 1;

  strncpy(out, start, len);
  out[len] = '\0';
  return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// IRSA (IAM Roles for Service Accounts) - uses web identity token
// ─────────────────────────────────────────────────────────────────────────────

static int refresh_irsa_credentials(pressured_plugin_ctx_t *ctx) {
  const char *token_file = getenv("AWS_WEB_IDENTITY_TOKEN_FILE");
  const char *role_arn = getenv("AWS_ROLE_ARN");
  const char *session_name = getenv("AWS_ROLE_SESSION_NAME");

  if (!token_file || !role_arn) {
    return -1;
  }

  // Read the web identity token
  char *token = read_file(token_file, NULL);
  if (!token) {
    log_debug("s3_storage: IRSA: failed to read token file %s", token_file);
    return -1;
  }

  // URL encode parameters
  char *encoded_token = url_encode(ctx->curl, token);
  char *encoded_role = url_encode(ctx->curl, role_arn);
  char *encoded_session =
      session_name ? url_encode(ctx->curl, session_name) : NULL;

  free(token);

  if (!encoded_token || !encoded_role) {
    curl_free(encoded_token);
    curl_free(encoded_role);
    curl_free(encoded_session);
    return -1;
  }

  // Build STS request
  char sts_url[512];
  snprintf(sts_url, sizeof(sts_url), "https://sts.%s.amazonaws.com/",
           ctx->region);

  char post_body[32768];
  snprintf(post_body, sizeof(post_body),
           "Action=AssumeRoleWithWebIdentity"
           "&Version=2011-06-15"
           "&RoleArn=%s"
           "&RoleSessionName=%s"
           "&WebIdentityToken=%s"
           "&DurationSeconds=3600",
           encoded_role,
           encoded_session ? encoded_session : "pressured-session",
           encoded_token);

  curl_free(encoded_token);
  curl_free(encoded_role);
  curl_free(encoded_session);

  // Make STS request
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(
      headers, "Content-Type: application/x-www-form-urlencoded");

  char response[16384];
  int rc = http_post(ctx->curl, sts_url, post_body, response, sizeof(response),
                     headers);
  curl_slist_free_all(headers);

  if (rc != 0) {
    log_debug("s3_storage: IRSA: STS request failed");
    return -1;
  }

  // Parse response - extract credentials from XML
  char access_key[256] = {0};
  char secret_key[512] = {0};
  char session_token[4096] = {0};
  char expiration[64] = {0};

  if (extract_xml_value(response, "AccessKeyId", access_key,
                        sizeof(access_key)) != 0 ||
      extract_xml_value(response, "SecretAccessKey", secret_key,
                        sizeof(secret_key)) != 0 ||
      extract_xml_value(response, "SessionToken", session_token,
                        sizeof(session_token)) != 0) {
    log_debug("s3_storage: IRSA: failed to parse STS response");
    return -1;
  }

  extract_xml_value(response, "Expiration", expiration, sizeof(expiration));

  // Store credentials
  strncpy(ctx->access_key, access_key, sizeof(ctx->access_key) - 1);
  strncpy(ctx->secret_key, secret_key, sizeof(ctx->secret_key) - 1);
  strncpy(ctx->session_token, session_token, sizeof(ctx->session_token) - 1);

  // Parse expiration, refresh 5 minutes early
  ctx->cred_expiration = parse_iso8601(expiration);
  if (ctx->cred_expiration > 300) {
    ctx->cred_expiration -= 300;
  }

  ctx->cred_source = CRED_IRSA;
  log_info("s3_storage: IRSA credentials obtained, expires in %ld seconds",
           ctx->cred_expiration - time(NULL));

  return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// EKS Pod Identity - uses container credentials endpoint
// ─────────────────────────────────────────────────────────────────────────────

static int refresh_pod_identity_credentials(pressured_plugin_ctx_t *ctx) {
  const char *creds_uri = getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI");
  const char *auth_token_file =
      getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE");
  const char *auth_token = getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN");

  if (!creds_uri) {
    return -1;
  }

  struct curl_slist *headers = NULL;

  // Add authorization header if available
  if (auth_token_file) {
    char *token = read_file(auth_token_file, NULL);
    if (token) {
      char auth_header[4096];
      snprintf(auth_header, sizeof(auth_header), "Authorization: %s", token);
      headers = curl_slist_append(headers, auth_header);
      free(token);
    }
  } else if (auth_token) {
    char auth_header[4096];
    snprintf(auth_header, sizeof(auth_header), "Authorization: %s", auth_token);
    headers = curl_slist_append(headers, auth_header);
  }

  char response[16384];
  int rc = http_get(ctx->curl, creds_uri, response, sizeof(response), headers);
  curl_slist_free_all(headers);

  if (rc != 0) {
    log_debug("s3_storage: Pod Identity: credential request failed");
    return -1;
  }

  // Parse JSON response
  struct json_object *root = json_tokener_parse(response);
  if (!root) {
    log_debug("s3_storage: Pod Identity: failed to parse response");
    return -1;
  }

  struct json_object *obj;
  const char *access_key = NULL, *secret_key = NULL, *session_token = NULL,
             *expiration = NULL;

  if (json_object_object_get_ex(root, "AccessKeyId", &obj))
    access_key = json_object_get_string(obj);
  if (json_object_object_get_ex(root, "SecretAccessKey", &obj))
    secret_key = json_object_get_string(obj);
  if (json_object_object_get_ex(root, "Token", &obj))
    session_token = json_object_get_string(obj);
  if (json_object_object_get_ex(root, "Expiration", &obj))
    expiration = json_object_get_string(obj);

  if (!access_key || !secret_key) {
    json_object_put(root);
    return -1;
  }

  strncpy(ctx->access_key, access_key, sizeof(ctx->access_key) - 1);
  strncpy(ctx->secret_key, secret_key, sizeof(ctx->secret_key) - 1);
  if (session_token) {
    strncpy(ctx->session_token, session_token, sizeof(ctx->session_token) - 1);
  }

  ctx->cred_expiration =
      expiration ? parse_iso8601(expiration) : time(NULL) + 3600;
  if (ctx->cred_expiration > 300) {
    ctx->cred_expiration -= 300;
  }

  json_object_put(root);
  ctx->cred_source = CRED_POD_IDENTITY;
  log_info("s3_storage: Pod Identity credentials obtained");

  return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// EC2 Instance Metadata Service (IMDS) v2
// ─────────────────────────────────────────────────────────────────────────────

static int refresh_imds_credentials(pressured_plugin_ctx_t *ctx) {
  // Get IMDS token (IMDSv2)
  char token[256] = {0};

  struct curl_slist *token_headers = NULL;
  token_headers = curl_slist_append(
      token_headers, "X-aws-ec2-metadata-token-ttl-seconds: 300");

  response_buffer_t resp = {0};
  resp.data = malloc(512);
  if (!resp.data) {
    curl_slist_free_all(token_headers);
    return -1;
  }
  resp.capacity = 512;

  curl_easy_reset(ctx->curl);
  curl_easy_setopt(ctx->curl, CURLOPT_URL,
                   "http://169.254.169.254/latest/api/token");
  curl_easy_setopt(ctx->curl, CURLOPT_CUSTOMREQUEST, "PUT");
  curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, token_headers);
  curl_easy_setopt(ctx->curl, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, &resp);
  curl_easy_setopt(ctx->curl, CURLOPT_TIMEOUT, 2L);
  curl_easy_setopt(ctx->curl, CURLOPT_CONNECTTIMEOUT, 1L);

  CURLcode res = curl_easy_perform(ctx->curl);
  curl_slist_free_all(token_headers);

  if (res != CURLE_OK || resp.size == 0) {
    free(resp.data);
    log_debug("s3_storage: IMDS: failed to get token");
    return -1;
  }

  strncpy(token, resp.data, sizeof(token) - 1);
  free(resp.data);

  // Get IAM role name
  char token_header[300];
  snprintf(token_header, sizeof(token_header), "X-aws-ec2-metadata-token: %s",
           token);

  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, token_header);

  char role_name[256];
  int rc = http_get(
      ctx->curl,
      "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
      role_name, sizeof(role_name), headers);

  if (rc != 0) {
    curl_slist_free_all(headers);
    log_debug("s3_storage: IMDS: no IAM role attached");
    return -1;
  }

  // Trim trailing whitespace from role name (IMDS may return with newline)
  size_t role_len = strlen(role_name);
  while (role_len > 0 &&
         (role_name[role_len - 1] == '\n' || role_name[role_len - 1] == '\r' ||
          role_name[role_len - 1] == ' ')) {
    role_name[--role_len] = '\0';
  }

  // Get credentials for the role
  char creds_url[512];
  snprintf(
      creds_url, sizeof(creds_url),
      "http://169.254.169.254/latest/meta-data/iam/security-credentials/%s",
      role_name);

  char response[8192];
  rc = http_get(ctx->curl, creds_url, response, sizeof(response), headers);
  curl_slist_free_all(headers);

  if (rc != 0) {
    log_debug("s3_storage: IMDS: failed to get credentials");
    return -1;
  }

  // Parse JSON response
  struct json_object *root = json_tokener_parse(response);
  if (!root) {
    return -1;
  }

  struct json_object *obj;
  const char *access_key = NULL, *secret_key = NULL, *session_token = NULL,
             *expiration = NULL;

  if (json_object_object_get_ex(root, "AccessKeyId", &obj))
    access_key = json_object_get_string(obj);
  if (json_object_object_get_ex(root, "SecretAccessKey", &obj))
    secret_key = json_object_get_string(obj);
  if (json_object_object_get_ex(root, "Token", &obj))
    session_token = json_object_get_string(obj);
  if (json_object_object_get_ex(root, "Expiration", &obj))
    expiration = json_object_get_string(obj);

  if (!access_key || !secret_key) {
    json_object_put(root);
    return -1;
  }

  strncpy(ctx->access_key, access_key, sizeof(ctx->access_key) - 1);
  strncpy(ctx->secret_key, secret_key, sizeof(ctx->secret_key) - 1);
  if (session_token) {
    strncpy(ctx->session_token, session_token, sizeof(ctx->session_token) - 1);
  }

  ctx->cred_expiration =
      expiration ? parse_iso8601(expiration) : time(NULL) + 3600;
  if (ctx->cred_expiration > 300) {
    ctx->cred_expiration -= 300;
  }

  json_object_put(root);
  ctx->cred_source = CRED_IMDS;
  log_info("s3_storage: IMDS credentials obtained for role %s", role_name);

  return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Static credentials from environment
// ─────────────────────────────────────────────────────────────────────────────

static int refresh_static_credentials(pressured_plugin_ctx_t *ctx) {
  const char *env_key = getenv("AWS_ACCESS_KEY_ID");
  const char *env_secret = getenv("AWS_SECRET_ACCESS_KEY");
  const char *env_token = getenv("AWS_SESSION_TOKEN");

  if (env_key && env_secret) {
    strncpy(ctx->access_key, env_key, sizeof(ctx->access_key) - 1);
    strncpy(ctx->secret_key, env_secret, sizeof(ctx->secret_key) - 1);
    if (env_token) {
      strncpy(ctx->session_token, env_token, sizeof(ctx->session_token) - 1);
    }
    ctx->cred_expiration = LONG_MAX;
    ctx->cred_source = CRED_STATIC;
    log_debug("s3_storage: using static credentials from environment");
    return 0;
  }
  return -1;
}

// ─────────────────────────────────────────────────────────────────────────────
// Credential chain - tries all sources in order (follows AWS SDK standard
// order)
// ─────────────────────────────────────────────────────────────────────────────

static int ensure_credentials(pressured_plugin_ctx_t *ctx) {
  // Check if current credentials are still valid
  if (ctx->access_key[0] && ctx->cred_expiration > time(NULL)) {
    return 0;
  }

  // Clear expired credentials
  ctx->access_key[0] = '\0';
  ctx->secret_key[0] = '\0';
  ctx->session_token[0] = '\0';

  // Try credential sources in order (AWS SDK standard order):
  // 1. Static environment variables - explicit credentials take priority
  if (refresh_static_credentials(ctx) == 0) {
    return 0;
  }

  // 2. IRSA (IAM Roles for Service Accounts) - EKS with OIDC
  if (refresh_irsa_credentials(ctx) == 0) {
    return 0;
  }

  // 3. EKS Pod Identity / ECS Container Credentials
  if (refresh_pod_identity_credentials(ctx) == 0) {
    return 0;
  }

  // 4. EC2 Instance Metadata Service
  if (refresh_imds_credentials(ctx) == 0) {
    return 0;
  }

  log_error("s3_storage: no AWS credentials available");
  return -1;
}

// ─────────────────────────────────────────────────────────────────────────────
// Multipart upload helpers
// ─────────────────────────────────────────────────────────────────────────────

static char *extract_upload_id(const char *xml) {
  const char *start = strstr(xml, "<UploadId>");
  if (!start)
    return NULL;
  start += 10;

  const char *end = strstr(start, "</UploadId>");
  if (!end)
    return NULL;

  size_t len = end - start;
  char *upload_id = malloc(len + 1);
  if (!upload_id)
    return NULL;

  strncpy(upload_id, start, len);
  upload_id[len] = '\0';
  return upload_id;
}

static size_t etag_header_callback(char *buffer, size_t size, size_t nitems,
                                   void *userdata) {
  size_t total = size * nitems;
  char *etag = (char *)userdata;

  if (strncasecmp(buffer, "ETag:", 5) == 0) {
    const char *value = buffer + 5;
    while (*value == ' ' || *value == '\t')
      value++;

    size_t i = 0;
    while (*value && *value != '\r' && *value != '\n' && i < 127) {
      if (*value != '"') {
        etag[i++] = *value;
      }
      value++;
    }
    etag[i] = '\0';
  }

  return total;
}

static char *s3_create_multipart_upload(pressured_plugin_ctx_t *ctx,
                                        const char *key) {
  char url[MAX_URL_LEN];
  build_url(ctx, key, url, sizeof(url));
  strcat(url, "?uploads");

  log_info("s3_storage: initiating multipart upload to %s", url);

  const char *empty_hash =
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  struct curl_slist *headers = sign_request(ctx, "POST", url, empty_hash, 0);
  headers =
      curl_slist_append(headers, "Content-Type: application/octet-stream");

  curl_easy_reset(ctx->curl);
  curl_easy_setopt(ctx->curl, CURLOPT_URL, url);
  curl_easy_setopt(ctx->curl, CURLOPT_POST, 1L);
  curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDS, "");
  curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDSIZE, 0L);
  curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);

  response_buffer_t resp = {0};
  resp.data = malloc(4096);
  if (!resp.data) {
    curl_slist_free_all(headers);
    return NULL;
  }
  resp.capacity = 4096;
  curl_easy_setopt(ctx->curl, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, &resp);

  CURLcode res = curl_easy_perform(ctx->curl);
  long http_code = 0;
  curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &http_code);

  curl_slist_free_all(headers);

  if (res != CURLE_OK || http_code != 200) {
    log_error("s3_storage: multipart upload init failed: curl=%d http=%ld "
              "response=%s",
              res, http_code, resp.data ? resp.data : "(null)");
    free(resp.data);
    return NULL;
  }

  char *upload_id = extract_upload_id(resp.data);
  free(resp.data);

  log_debug("s3_storage: multipart upload initiated, UploadId=%s",
            upload_id ? upload_id : "(null)");
  return upload_id;
}

static char *s3_upload_part(pressured_plugin_ctx_t *ctx, const char *key,
                            const char *upload_id, int part_number,
                            const void *data, size_t len) {
  char url[MAX_URL_LEN];
  build_url(ctx, key, url, sizeof(url));

  char query[512];
  snprintf(query, sizeof(query), "?partNumber=%d&uploadId=%s", part_number,
           upload_id);
  strcat(url, query);

  unsigned char hash[32];
  sha256(data, len, hash);
  char payload_hash[65];
  hex_encode(hash, 32, payload_hash);

  struct curl_slist *headers = sign_request(ctx, "PUT", url, payload_hash, len);
  headers =
      curl_slist_append(headers, "Content-Type: application/octet-stream");

  curl_easy_reset(ctx->curl);
  curl_easy_setopt(ctx->curl, CURLOPT_URL, url);
  curl_easy_setopt(ctx->curl, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDS, data);
  curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDSIZE, (long)len);
  curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(ctx->curl, CURLOPT_CUSTOMREQUEST, "PUT");

  char *etag = calloc(128, 1);
  if (!etag) {
    curl_slist_free_all(headers);
    return NULL;
  }
  curl_easy_setopt(ctx->curl, CURLOPT_HEADERFUNCTION, etag_header_callback);
  curl_easy_setopt(ctx->curl, CURLOPT_HEADERDATA, etag);

  response_buffer_t resp = {0};
  resp.data = malloc(1024);
  resp.capacity = 1024;
  curl_easy_setopt(ctx->curl, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, &resp);

  CURLcode res = curl_easy_perform(ctx->curl);
  long http_code = 0;
  curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &http_code);

  curl_slist_free_all(headers);
  free(resp.data);

  if (res != CURLE_OK || http_code != 200 || etag[0] == '\0') {
    log_error("s3_storage: part upload failed: curl=%d http=%ld etag=%s", res,
              http_code, etag[0] ? etag : "(empty)");
    free(etag);
    return NULL;
  }

  log_info("s3_storage: uploaded part %d (%zu bytes), ETag=%s", part_number,
           len, etag);
  return etag;
}

static int s3_complete_multipart_upload(pressured_plugin_ctx_t *ctx,
                                        const char *key, const char *upload_id,
                                        char **etags, int num_parts) {
  char url[MAX_URL_LEN];
  build_url(ctx, key, url, sizeof(url));

  char query[512];
  snprintf(query, sizeof(query), "?uploadId=%s", upload_id);
  strcat(url, query);

  // Build XML
  size_t xml_capacity = 256 + (num_parts * 200);
  char *xml_body = malloc(xml_capacity);
  if (!xml_body)
    return -1;

  strcpy(xml_body, "<CompleteMultipartUpload>");
  size_t offset = strlen(xml_body);

  for (int i = 0; i < num_parts; i++) {
    offset +=
        snprintf(xml_body + offset, xml_capacity - offset,
                 "<Part><PartNumber>%d</PartNumber><ETag>\"%s\"</ETag></Part>",
                 i + 1, etags[i]);
  }
  strcat(xml_body + offset, "</CompleteMultipartUpload>");
  size_t xml_len = strlen(xml_body);

  unsigned char hash[32];
  sha256(xml_body, xml_len, hash);
  char payload_hash[65];
  hex_encode(hash, 32, payload_hash);

  struct curl_slist *headers =
      sign_request(ctx, "POST", url, payload_hash, xml_len);
  headers = curl_slist_append(headers, "Content-Type: application/xml");

  curl_easy_reset(ctx->curl);
  curl_easy_setopt(ctx->curl, CURLOPT_URL, url);
  curl_easy_setopt(ctx->curl, CURLOPT_POST, 1L);
  curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDS, xml_body);
  curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDSIZE, (long)xml_len);
  curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);

  response_buffer_t resp = {0};
  resp.data = malloc(4096);
  resp.capacity = 4096;
  curl_easy_setopt(ctx->curl, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, &resp);

  CURLcode res = curl_easy_perform(ctx->curl);
  long http_code = 0;
  curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &http_code);

  curl_slist_free_all(headers);
  free(xml_body);

  int success = (res == CURLE_OK && http_code == 200 &&
                 (!resp.data || !strstr(resp.data, "<Error>")));

  if (success) {
    log_debug("s3_storage: multipart upload completed");
  } else {
    log_error("s3_storage: multipart complete failed: curl=%d http=%ld "
              "response=%.*s",
              res, http_code, resp.data ? (int)resp.size : 0,
              resp.data ? resp.data : "");
  }
  free(resp.data);

  return success ? 0 : -1;
}

static void s3_abort_multipart_upload(pressured_plugin_ctx_t *ctx,
                                      const char *key, const char *upload_id) {
  char url[MAX_URL_LEN];
  build_url(ctx, key, url, sizeof(url));

  char query[512];
  snprintf(query, sizeof(query), "?uploadId=%s", upload_id);
  strcat(url, query);

  const char *empty_hash =
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  struct curl_slist *headers = sign_request(ctx, "DELETE", url, empty_hash, 0);

  curl_easy_reset(ctx->curl);
  curl_easy_setopt(ctx->curl, CURLOPT_URL, url);
  curl_easy_setopt(ctx->curl, CURLOPT_CUSTOMREQUEST, "DELETE");
  curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);

  curl_easy_perform(ctx->curl);
  curl_slist_free_all(headers);

  log_debug("s3_storage: multipart upload aborted");
}

// ─────────────────────────────────────────────────────────────────────────────
// Streaming PutObject (single request, chunked upload)
// ─────────────────────────────────────────────────────────────────────────────

#ifdef S3_UPLOAD_STREAMING
// Curl read callback for streaming - reads from s3_file_t buffer
static size_t stream_read_callback(char *buffer, size_t size, size_t nitems,
                                   void *userdata) {
  s3_file_t *sf = (s3_file_t *)userdata;
  size_t max_bytes = size * nitems;

  // Check if we have data to send
  size_t available = sf->buf.size - sf->buf.pos;
  if (available == 0) {
    // No data available - pause until write() adds more
    return CURL_READFUNC_PAUSE;
  }

  size_t to_copy = available < max_bytes ? available : max_bytes;
  memcpy(buffer, sf->buf.data + sf->buf.pos, to_copy);
  sf->buf.pos += to_copy;

  // If we've consumed all data, reset buffer for reuse
  if (sf->buf.pos == sf->buf.size) {
    sf->buf.pos = 0;
    sf->buf.size = 0;
  }

  return to_copy;
}

// Start the streaming upload (called on first write)
static int start_streaming_upload(s3_file_t *sf) {
  // Build URL
  char url[MAX_URL_LEN];
  build_url(sf->ctx, sf->key, url, sizeof(url));

  // Use UNSIGNED-PAYLOAD for streaming
  const char *payload_hash = "UNSIGNED-PAYLOAD";
  sf->headers = sign_request(sf->ctx, "PUT", url, payload_hash,
                             sf->expected_size >= 0 ? (size_t)sf->expected_size : 0);
  if (!sf->headers) {
    return -1;
  }
  struct curl_slist *tmp = curl_slist_append(sf->headers, "Content-Type: application/octet-stream");
  if (!tmp) {
    curl_slist_free_all(sf->headers);
    sf->headers = NULL;
    return -1;
  }
  sf->headers = tmp;

  // Create curl handles
  sf->upload_curl = curl_easy_init();
  if (!sf->upload_curl) {
    curl_slist_free_all(sf->headers);
    sf->headers = NULL;
    return -1;
  }

  sf->multi = curl_multi_init();
  if (!sf->multi) {
    curl_easy_cleanup(sf->upload_curl);
    curl_slist_free_all(sf->headers);
    sf->upload_curl = NULL;
    sf->headers = NULL;
    return -1;
  }

  // Configure curl
  curl_easy_setopt(sf->upload_curl, CURLOPT_URL, url);
  curl_easy_setopt(sf->upload_curl, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(sf->upload_curl, CURLOPT_READFUNCTION, stream_read_callback);
  curl_easy_setopt(sf->upload_curl, CURLOPT_READDATA, sf);
  curl_easy_setopt(sf->upload_curl, CURLOPT_HTTPHEADER, sf->headers);

  if (sf->expected_size >= 0) {
    curl_easy_setopt(sf->upload_curl, CURLOPT_INFILESIZE_LARGE,
                     (curl_off_t)sf->expected_size);
  }

  // Add to multi handle
  CURLMcode mc = curl_multi_add_handle(sf->multi, sf->upload_curl);
  if (mc != CURLM_OK) {
    log_error("s3_storage: curl_multi_add_handle failed for upload: %d", mc);
    curl_easy_cleanup(sf->upload_curl);
    curl_multi_cleanup(sf->multi);
    curl_slist_free_all(sf->headers);
    sf->upload_curl = NULL;
    sf->multi = NULL;
    sf->headers = NULL;
    return -1;
  }

  sf->upload_started = 1;
  log_info("s3_storage: streaming upload started for %s (size=%lld)",
           sf->key, (long long)sf->expected_size);
  return 0;
}

// Drive curl_multi forward (non-blocking)
static int drive_upload(s3_file_t *sf) {
  int still_running;
  CURLMcode mc = curl_multi_perform(sf->multi, &still_running);
  if (mc != CURLM_OK) {
    log_error("s3_storage: curl_multi_perform failed: %d", mc);
    return -1;
  }
  if (still_running == 0) {
    sf->upload_finished = 1;
  }
  return 0;
}

// Set expected upload size (optional, for Content-Length header)
int s3_set_upload_size(storage_file_t *f, int64_t size) {
  s3_file_t *sf = (s3_file_t *)f;
  if (!sf || sf->mode != STORAGE_MODE_WRITE)
    return STORAGE_ERR_INVALID;

  if (sf->upload_started) {
    log_error("s3_storage: s3_set_upload_size called after write started");
    return STORAGE_ERR_INVALID;
  }

  sf->expected_size = size;
  log_debug("s3_storage: upload size set to %lld for %s",
            (long long)size, sf->key);
  return STORAGE_OK;
}
// Streaming download: curl write callback receives data into our buffer
static size_t stream_write_callback(char *ptr, size_t size, size_t nmemb,
                                    void *userdata) {
  s3_file_t *sf = (s3_file_t *)userdata;
  size_t bytes = size * nmemb;

  if (bytes == 0)
    return 0;  // Nothing to do

  // Resize buffer if needed (cap at MAX_STREAMING_BUFFER)
  while (sf->buf.size + bytes > sf->buf.capacity) {
    if (sf->buf.capacity >= MAX_STREAMING_BUFFER) {
      // Buffer at max capacity
      if (sf->buf.size == 0) {
        // Buffer is empty but chunk is larger than max - accept partial
        // This handles the edge case of oversized chunks from curl
        // IMPORTANT: must not copy more than 'bytes' (what curl gave us)
        size_t to_accept = bytes < sf->buf.capacity ? bytes : sf->buf.capacity;
        memcpy(sf->buf.data, ptr, to_accept);
        sf->buf.size = to_accept;
        sf->bytes_received += to_accept;
        // Return partial acceptance - curl will call us again with remainder
        return to_accept;
      }
      // Buffer has data, pause transfer until app consumes it
      return CURL_WRITEFUNC_PAUSE;
    }
    size_t new_cap = sf->buf.capacity * 2;
    if (new_cap > MAX_STREAMING_BUFFER)
      new_cap = MAX_STREAMING_BUFFER;
    char *new_data = realloc(sf->buf.data, new_cap);
    if (!new_data)
      return 0; // Error - curl will abort
    sf->buf.data = new_data;
    sf->buf.capacity = new_cap;
  }

  // Copy data to buffer
  memcpy(sf->buf.data + sf->buf.size, ptr, bytes);
  sf->buf.size += bytes;
  sf->bytes_received += bytes;

  return bytes;
}

// Start streaming download (called on first s3_read)
static int start_streaming_download(s3_file_t *sf) {
  if (sf->download_started)
    return 0;

  pressured_plugin_ctx_t *ctx = sf->ctx;

  // Build URL and sign request
  char url[MAX_URL_LEN];
  build_url(ctx, sf->key, url, sizeof(url));

  const char *empty_hash =
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  sf->headers = sign_request(ctx, "GET", url, empty_hash, 0);
  if (!sf->headers) {
    log_error("s3_storage: failed to sign streaming download request");
    return -1;
  }

  // Create curl_multi handle (reuse the multi from uploads if not set)
  if (!sf->multi) {
    sf->multi = curl_multi_init();
    if (!sf->multi) {
      log_error("s3_storage: failed to init curl_multi for download");
      curl_slist_free_all(sf->headers);
      sf->headers = NULL;
      return -1;
    }
  }

  // Create curl easy handle for download
  sf->download_curl = curl_easy_init();
  if (!sf->download_curl) {
    log_error("s3_storage: failed to init curl for streaming download");
    curl_multi_cleanup(sf->multi);
    sf->multi = NULL;
    curl_slist_free_all(sf->headers);
    sf->headers = NULL;
    return -1;
  }

  curl_easy_setopt(sf->download_curl, CURLOPT_URL, url);
  curl_easy_setopt(sf->download_curl, CURLOPT_HTTPGET, 1L);
  curl_easy_setopt(sf->download_curl, CURLOPT_HTTPHEADER, sf->headers);
  curl_easy_setopt(sf->download_curl, CURLOPT_WRITEFUNCTION, stream_write_callback);
  curl_easy_setopt(sf->download_curl, CURLOPT_WRITEDATA, sf);

  // Add to multi handle
  CURLMcode mc = curl_multi_add_handle(sf->multi, sf->download_curl);
  if (mc != CURLM_OK) {
    log_error("s3_storage: curl_multi_add_handle failed for download: %d", mc);
    curl_easy_cleanup(sf->download_curl);
    sf->download_curl = NULL;
    curl_multi_cleanup(sf->multi);
    sf->multi = NULL;
    curl_slist_free_all(sf->headers);
    sf->headers = NULL;
    return -1;
  }

  sf->download_started = 1;
  log_info("s3_storage: streaming download started for %s", sf->key);
  return 0;
}

// Drive download forward (non-blocking)
static int drive_download(s3_file_t *sf) {
  if (!sf->multi || sf->download_finished)
    return 0;

  int still_running;
  CURLMcode mc = curl_multi_perform(sf->multi, &still_running);
  if (mc != CURLM_OK) {
    log_error("s3_storage: curl_multi_perform failed for download: %d", mc);
    return -1;
  }
  if (still_running == 0) {
    sf->download_finished = 1;
  }
  return 0;
}
#endif

// Context for curl read callback wrapper
typedef struct {
  s3_read_callback_t user_callback;
  void *user_data;
  int64_t total_read;
  int error;
} streaming_read_ctx_t;

// Curl read callback that wraps user callback
static size_t streaming_read_callback(char *buffer, size_t size, size_t nitems,
                                      void *userdata) {
  streaming_read_ctx_t *ctx = (streaming_read_ctx_t *)userdata;
  size_t max_bytes = size * nitems;

  if (ctx->error) {
    return CURL_READFUNC_ABORT;
  }

  ssize_t n = ctx->user_callback(buffer, max_bytes, ctx->user_data);

  if (n < 0) {
    ctx->error = 1;
    return CURL_READFUNC_ABORT;
  }

  ctx->total_read += n;
  return (size_t)n; // 0 signals EOF to curl
}

/*
 * Upload data to S3 using streaming PutObject with a single HTTP request.
 *
 * This function uses UNSIGNED-PAYLOAD signing, which allows streaming without
 * needing to hash the entire payload upfront. Data is pulled from the provided
 * callback in chunks and sent over a single HTTP connection.
 *
 * @param s             Storage handle (must be S3 storage)
 * @param key           Object key to upload to
 * @param read_cb       Callback that provides data chunks (return 0 for EOF, -1 for error)
 * @param userdata      User context passed to read_cb
 * @param content_length Total size if known, or -1 for chunked transfer encoding
 * @return STORAGE_OK on success, error code on failure
 *
 * Diagram:
 *   ┌──────────┐        ┌─────────┐        ┌─────┐
 *   │ read_cb  │──64KB─►│  curl   │──64KB─►│ S3  │
 *   │ (user)   │──64KB─►│ (HTTP)  │──64KB─►│ PUT │
 *   └──────────┘        └─────────┘        └─────┘
 *                    Single HTTP Request
 */
int s3_put_streaming(storage_t *s, const char *key, s3_read_callback_t read_cb,
                     void *userdata, int64_t content_length) {
  struct pressured_plugin_handle *h = (struct pressured_plugin_handle *)s;
  if (!h || !h->ctx || !key || !read_cb) {
    return STORAGE_ERR_INVALID;
  }
  pressured_plugin_ctx_t *ctx = h->ctx;

  if (ensure_credentials(ctx) != 0) {
    return STORAGE_ERR_PERM;
  }

  // Build URL
  char url[MAX_URL_LEN];
  build_url(ctx, key, url, sizeof(url));

  log_info("s3_storage: streaming PUT to %s (size=%s)", url,
           content_length >= 0 ? "known" : "chunked");

  // Use UNSIGNED-PAYLOAD - this allows streaming without pre-hashing
  const char *payload_hash = "UNSIGNED-PAYLOAD";
  struct curl_slist *headers =
      sign_request(ctx, "PUT", url, payload_hash,
                   content_length >= 0 ? (size_t)content_length : 0);
  headers =
      curl_slist_append(headers, "Content-Type: application/octet-stream");

  // For chunked encoding when size is unknown
  if (content_length < 0) {
    headers = curl_slist_append(headers, "Transfer-Encoding: chunked");
  }

  // Setup streaming read context
  streaming_read_ctx_t read_ctx = {
      .user_callback = read_cb,
      .user_data = userdata,
      .total_read = 0,
      .error = 0,
  };

  // Configure curl for streaming upload
  curl_easy_reset(ctx->curl);
  curl_easy_setopt(ctx->curl, CURLOPT_URL, url);
  curl_easy_setopt(ctx->curl, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(ctx->curl, CURLOPT_READFUNCTION, streaming_read_callback);
  curl_easy_setopt(ctx->curl, CURLOPT_READDATA, &read_ctx);
  curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);

  if (content_length >= 0) {
    curl_easy_setopt(ctx->curl, CURLOPT_INFILESIZE_LARGE,
                     (curl_off_t)content_length);
  }

  // Response buffer for error messages
  response_buffer_t resp = {0};
  resp.data = malloc(4096);
  if (!resp.data) {
    curl_slist_free_all(headers);
    return STORAGE_ERR_IO;
  }
  resp.capacity = 4096;
  curl_easy_setopt(ctx->curl, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, &resp);

  // Execute the streaming upload
  CURLcode res = curl_easy_perform(ctx->curl);
  long http_code = 0;
  curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &http_code);

  curl_slist_free_all(headers);

  int result = STORAGE_OK;

  if (res != CURLE_OK) {
    log_error("s3_storage: streaming PUT failed: curl=%d (%s)", res,
              curl_easy_strerror(res));
    result = STORAGE_ERR_IO;
  } else if (read_ctx.error) {
    log_error("s3_storage: streaming PUT failed: read callback error");
    result = STORAGE_ERR_IO;
  } else if (http_code != 200) {
    log_error("s3_storage: streaming PUT failed: http=%ld response=%s",
              http_code, resp.data ? resp.data : "(null)");
    result = STORAGE_ERR_IO;
  } else {
    log_info("s3_storage: streaming PUT completed: %lld bytes uploaded",
             (long long)read_ctx.total_read);
  }

  free(resp.data);
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Storage operations
// ─────────────────────────────────────────────────────────────────────────────

static int s3_exists(storage_t *s, const char *key) {
  log_debug("s3_storage: s3_exists called for key=%s", key);
  struct pressured_plugin_handle *h = (struct pressured_plugin_handle *)s;
  if (!h || !h->ctx) {
    log_error("s3_storage: s3_exists - handle or context is NULL");
    return STORAGE_ERR_NOT_INIT;
  }
  pressured_plugin_ctx_t *ctx = h->ctx;
  log_debug("s3_storage: s3_exists - ctx=%p bucket=%s", (void *)ctx,
            ctx->bucket);

  if (ensure_credentials(ctx) != 0)
    return STORAGE_ERR_PERM;

  char url[MAX_URL_LEN];
  build_url(ctx, key, url, sizeof(url));

  const char *empty_hash =
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  struct curl_slist *headers = sign_request(ctx, "HEAD", url, empty_hash, 0);

  curl_easy_reset(ctx->curl);
  curl_easy_setopt(ctx->curl, CURLOPT_URL, url);
  curl_easy_setopt(ctx->curl, CURLOPT_NOBODY, 1L);
  curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);

  CURLcode res = curl_easy_perform(ctx->curl);
  long http_code = 0;
  curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &http_code);

  curl_slist_free_all(headers);

  if (res != CURLE_OK)
    return STORAGE_ERR_IO;
  if (http_code == 200)
    return 1;
  if (http_code == 404)
    return 0;
  return STORAGE_ERR_IO;
}

static int s3_remove(storage_t *s, const char *key) {
  struct pressured_plugin_handle *h = (struct pressured_plugin_handle *)s;
  if (!h || !h->ctx)
    return STORAGE_ERR_NOT_INIT;
  pressured_plugin_ctx_t *ctx = h->ctx;

  if (ensure_credentials(ctx) != 0)
    return STORAGE_ERR_PERM;

  char url[MAX_URL_LEN];
  build_url(ctx, key, url, sizeof(url));

  const char *empty_hash =
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  struct curl_slist *headers = sign_request(ctx, "DELETE", url, empty_hash, 0);

  curl_easy_reset(ctx->curl);
  curl_easy_setopt(ctx->curl, CURLOPT_URL, url);
  curl_easy_setopt(ctx->curl, CURLOPT_CUSTOMREQUEST, "DELETE");
  curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);

  CURLcode res = curl_easy_perform(ctx->curl);
  long http_code = 0;
  curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &http_code);

  curl_slist_free_all(headers);

  if (res != CURLE_OK)
    return STORAGE_ERR_IO;
  if (http_code == 204 || http_code == 200) {
    log_debug("s3_storage: removed %s", key);
    return STORAGE_OK;
  }
  if (http_code == 404)
    return STORAGE_ERR_NOT_FOUND;
  return STORAGE_ERR_IO;
}

// S3 rename is implemented as copy + delete
static int s3_rename(storage_t *s, const char *old_key, const char *new_key) {
  struct pressured_plugin_handle *h = (struct pressured_plugin_handle *)s;
  if (!h || !h->ctx)
    return STORAGE_ERR_NOT_INIT;
  pressured_plugin_ctx_t *ctx = h->ctx;

  if (ensure_credentials(ctx) != 0)
    return STORAGE_ERR_PERM;

  // Build destination URL
  char dest_url[MAX_URL_LEN];
  build_url(ctx, new_key, dest_url, sizeof(dest_url));

  // Build source path for x-amz-copy-source header
  // Format: /bucket/prefix/key (URL-encoded)
  char source_path[MAX_URL_LEN];
  const char *k = old_key;
  while (*k == '/')
    k++; // Strip leading slashes

  char prefix_clean[512];
  strncpy(prefix_clean, ctx->prefix, sizeof(prefix_clean) - 1);
  prefix_clean[sizeof(prefix_clean) - 1] = '\0';
  size_t prefix_len = strlen(prefix_clean);
  while (prefix_len > 0 && prefix_clean[prefix_len - 1] == '/') {
    prefix_clean[--prefix_len] = '\0';
  }

  if (prefix_clean[0]) {
    snprintf(source_path, sizeof(source_path), "/%s/%s/%s", ctx->bucket,
             prefix_clean, k);
  } else {
    snprintf(source_path, sizeof(source_path), "/%s/%s", ctx->bucket, k);
  }

  // Sign request with copy source header included in signature
  const char *empty_hash =
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  struct curl_slist *headers =
      sign_copy_request(ctx, "PUT", dest_url, empty_hash, source_path);

  curl_easy_reset(ctx->curl);
  curl_easy_setopt(ctx->curl, CURLOPT_URL, dest_url);
  curl_easy_setopt(ctx->curl, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(ctx->curl, CURLOPT_INFILESIZE, 0L);
  curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(ctx->curl, CURLOPT_CUSTOMREQUEST, "PUT");

  response_buffer_t resp = {0};
  resp.data = malloc(4096);
  resp.capacity = 4096;
  curl_easy_setopt(ctx->curl, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, &resp);

  CURLcode res = curl_easy_perform(ctx->curl);
  long http_code = 0;
  curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &http_code);

  curl_slist_free_all(headers);

  if (res != CURLE_OK || http_code != 200) {
    log_error("s3_storage: rename copy failed: curl=%d http=%ld response=%s",
              res, http_code, resp.data ? resp.data : "(null)");
    free(resp.data);
    return STORAGE_ERR_IO;
  }

  // Check for error in response body
  if (resp.data && strstr(resp.data, "<Error>")) {
    log_error("s3_storage: rename copy error: %s", resp.data);
    free(resp.data);
    return STORAGE_ERR_IO;
  }
  free(resp.data);

  // Delete the original
  int delete_rc = s3_remove(s, old_key);
  if (delete_rc != STORAGE_OK) {
    log_warn("s3_storage: rename copied but delete failed: %d", delete_rc);
    // Copy succeeded, so we return OK even if delete fails
  }

  log_debug("s3_storage: renamed %s -> %s", old_key, new_key);
  return STORAGE_OK;
}

static storage_file_t *s3_open(storage_t *s, const char *key, int mode) {
  log_info("s3_storage: s3_open called for key=%s mode=%d s=%p", key, mode,
           (void *)s);
  struct pressured_plugin_handle *h = (struct pressured_plugin_handle *)s;
  if (!h || !h->ctx) {
    log_error("s3_storage: s3_open - handle or context is NULL (s=%p)",
              (void *)s);
    return NULL;
  }
  pressured_plugin_ctx_t *ctx = h->ctx;
  log_info("s3_storage: s3_open - ctx=%p bucket=%s region=%s", (void *)ctx,
           ctx->bucket, ctx->region);

  if (ensure_credentials(ctx) != 0) {
    log_error("s3_storage: s3_open - failed to get credentials");
    return NULL;
  }
  log_info("s3_storage: s3_open - credentials OK, proceeding with open");

  s3_file_t *sf = calloc(1, sizeof(s3_file_t));
  if (!sf)
    return NULL;

  sf->ctx = ctx;
  sf->mode = mode;
  strncpy(sf->key, key, sizeof(sf->key) - 1);

  if (mode == STORAGE_MODE_WRITE) {
#ifdef S3_UPLOAD_MULTIPART
    // Start multipart upload
    log_info("s3_storage: s3_open - starting multipart upload for key=%s", key);
    sf->upload_id = s3_create_multipart_upload(ctx, key);
    if (!sf->upload_id) {
      log_error(
          "s3_storage: s3_open - multipart upload initiation failed for key=%s",
          key);
      free(sf);
      return NULL;
    }
    log_info("s3_storage: s3_open - multipart upload started, upload_id=%s",
             sf->upload_id);
    sf->part_number = 0;
    sf->etags_capacity = 16;
    sf->etags = calloc(sf->etags_capacity, sizeof(char *));
    if (!sf->etags) {
      free(sf->upload_id);
      free(sf);
      return NULL;
    }

    // Allocate write buffer for buffering data until S3_MIN_PART_SIZE
    sf->write_buffer_capacity = S3_MIN_PART_SIZE + (1024 * 1024); // 6MB
    sf->write_buffer = malloc(sf->write_buffer_capacity);
    if (!sf->write_buffer) {
      free(sf->etags);
      free(sf->upload_id);
      free(sf);
      return NULL;
    }
    sf->write_buffer_size = 0;
#endif

#ifdef S3_UPLOAD_STREAMING
    // Initialize buffer for curl_multi streaming
    log_info("s3_storage: s3_open - streaming mode for key=%s", key);
    sf->buf.capacity = STREAMING_CHUNK_SIZE;
    sf->buf.data = malloc(sf->buf.capacity);
    if (!sf->buf.data) {
      free(sf);
      return NULL;
    }
    sf->buf.size = 0;
    sf->buf.pos = 0;
    sf->multi = NULL;
    sf->upload_curl = NULL;
    sf->headers = NULL;
    sf->upload_started = 0;
    sf->upload_finished = 0;
    sf->expected_size = -1; // Unknown size; set via s3_set_upload_size()
#endif
  } else {
#ifdef S3_UPLOAD_STREAMING
    // Streaming reads: initialize buffer and curl_multi, defer actual download
    log_info("s3_storage: s3_open - streaming read mode for key=%s", key);
    sf->buf.capacity = STREAMING_CHUNK_SIZE;
    sf->buf.data = malloc(sf->buf.capacity);
    if (!sf->buf.data) {
      free(sf);
      return NULL;
    }
    sf->buf.size = 0;
    sf->buf.pos = 0;  // Used as read position for streaming reads
    sf->multi = NULL;
    sf->download_curl = NULL;
    sf->headers = NULL;
    sf->download_started = 0;
    sf->download_finished = 0;
    sf->content_length = -1;
    sf->bytes_received = 0;
    sf->read_buffer = NULL;  // Not used in streaming mode
    sf->read_size = 0;
    sf->read_pos = 0;
#else
    // Non-streaming: fetch entire object synchronously
    char url[MAX_URL_LEN];
    build_url(ctx, key, url, sizeof(url));

    const char *empty_hash =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    struct curl_slist *headers = sign_request(ctx, "GET", url, empty_hash, 0);

    curl_easy_reset(ctx->curl);
    curl_easy_setopt(ctx->curl, CURLOPT_URL, url);
    curl_easy_setopt(ctx->curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);

    response_buffer_t resp = {0};
    resp.data = malloc(16384);
    if (!resp.data) {
      curl_slist_free_all(headers);
      free(sf);
      return NULL;
    }
    resp.capacity = 16384;
    curl_easy_setopt(ctx->curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, &resp);

    CURLcode res = curl_easy_perform(ctx->curl);
    long http_code = 0;
    curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);

    if (res != CURLE_OK || http_code != 200) {
      free(resp.data);
      free(sf);
      return NULL;
    }

    sf->read_buffer = resp.data;
    sf->read_size = resp.size;
    sf->read_pos = 0;
#endif
  }

  return (storage_file_t *)sf;
}

static int64_t s3_write(storage_file_t *f, const void *data, size_t len) {
  s3_file_t *sf = (s3_file_t *)f;
  if (!sf || !sf->ctx || sf->mode != STORAGE_MODE_WRITE)
    return STORAGE_ERR_INVALID;

#ifdef S3_UPLOAD_MULTIPART
  // Buffer data until we have at least S3_MIN_PART_SIZE
  const char *src = (const char *)data;
  size_t remaining = len;

  while (remaining > 0) {
    // Calculate how much we can buffer
    size_t space = sf->write_buffer_capacity - sf->write_buffer_size;
    size_t to_copy = remaining < space ? remaining : space;

    memcpy(sf->write_buffer + sf->write_buffer_size, src, to_copy);
    sf->write_buffer_size += to_copy;
    src += to_copy;
    remaining -= to_copy;

    // If buffer reached minimum part size, upload it
    if (sf->write_buffer_size >= S3_MIN_PART_SIZE) {
      // Expand etags array if needed (check BEFORE incrementing part_number)
      if (sf->part_number + 1 > sf->etags_capacity) {
        int new_cap = sf->etags_capacity * 2;
        char **new_etags = realloc(sf->etags, new_cap * sizeof(char *));
        if (!new_etags)
          return STORAGE_ERR_IO;
        // Zero-initialize new slots to prevent freeing garbage on error
        for (int i = sf->etags_capacity; i < new_cap; i++) {
          new_etags[i] = NULL;
        }
        sf->etags = new_etags;
        sf->etags_capacity = new_cap;
      }

      char *etag =
          s3_upload_part(sf->ctx, sf->key, sf->upload_id, sf->part_number + 1,
                         sf->write_buffer, sf->write_buffer_size);
      if (!etag) {
        return STORAGE_ERR_IO;
      }

      // Only increment part_number AFTER successful upload
      sf->etags[sf->part_number] = etag;
      sf->part_number++;
      sf->write_buffer_size = 0; // Reset buffer
    }
  }
#endif

#ifdef S3_UPLOAD_STREAMING
  // Start upload on first write
  if (!sf->upload_started) {
    if (start_streaming_upload(sf) != 0) {
      log_error("s3_storage: failed to start streaming upload");
      return STORAGE_ERR_IO;
    }
  }

  if (sf->upload_finished) {
    log_error("s3_storage: upload already finished, cannot write more data");
    return STORAGE_ERR_IO;
  }

  // Process write in chunks to bound memory usage
  const char *src = (const char *)data;
  size_t remaining = len;

  while (remaining > 0) {
    // Backpressure: if buffer is getting full, drain it first
    while (sf->buf.size >= STREAMING_CHUNK_SIZE / 2) {
      curl_easy_pause(sf->upload_curl, CURLPAUSE_CONT);

      int still_running;
      CURLMcode mc = curl_multi_perform(sf->multi, &still_running);
      if (mc != CURLM_OK) {
        log_error("s3_storage: curl_multi_perform failed in backpressure: %d", mc);
        return STORAGE_ERR_IO;
      }

      if (still_running == 0) {
        sf->upload_finished = 1;
        log_error("s3_storage: upload finished unexpectedly");
        return STORAGE_ERR_IO;
      }

      // If buffer didn't drain, wait briefly for network
      if (sf->buf.size >= STREAMING_CHUNK_SIZE / 2) {
        int numfds;
        curl_multi_wait(sf->multi, NULL, 0, 10, &numfds);
      }
    }

    // Calculate how much we can copy
    size_t space = sf->buf.capacity - sf->buf.size;
    size_t to_copy = remaining < space ? remaining : space;

    // Resize buffer if needed, but cap at MAX_STREAMING_BUFFER
    if (to_copy == 0 && sf->buf.capacity < MAX_STREAMING_BUFFER) {
      size_t new_cap = sf->buf.capacity * 2;
      if (new_cap > MAX_STREAMING_BUFFER)
        new_cap = MAX_STREAMING_BUFFER;
      char *new_data = realloc(sf->buf.data, new_cap);
      if (!new_data)
        return STORAGE_ERR_IO;
      sf->buf.data = new_data;
      sf->buf.capacity = new_cap;
      space = sf->buf.capacity - sf->buf.size;
      to_copy = remaining < space ? remaining : space;
    }

    // If still no space (buffer at max cap and full), loop will drain via backpressure
    if (to_copy == 0)
      continue;

    // Copy data to buffer
    memcpy(sf->buf.data + sf->buf.size, src, to_copy);
    sf->buf.size += to_copy;
    src += to_copy;
    remaining -= to_copy;

    // Unpause and drive curl forward after each chunk
    curl_easy_pause(sf->upload_curl, CURLPAUSE_CONT);
    if (drive_upload(sf) != 0) {
      return STORAGE_ERR_IO;
    }
  }
#endif

  return (int64_t)len;
}

static int64_t s3_read(storage_file_t *f, void *buf, size_t len) {
  s3_file_t *sf = (s3_file_t *)f;
  if (!sf || sf->mode != STORAGE_MODE_READ)
    return STORAGE_ERR_INVALID;

#ifdef S3_UPLOAD_STREAMING
  // Streaming read mode
  if (!sf->download_started) {
    if (start_streaming_download(sf) != 0) {
      log_error("s3_storage: failed to start streaming download");
      return STORAGE_ERR_IO;
    }
  }

  char *dst = (char *)buf;
  size_t total_read = 0;

  while (total_read < len) {
    // Check if we have data in buffer
    size_t available = sf->buf.size - sf->buf.pos;

    if (available > 0) {
      // Copy from buffer
      size_t to_copy = (len - total_read) < available ? (len - total_read) : available;
      memcpy(dst + total_read, sf->buf.data + sf->buf.pos, to_copy);
      sf->buf.pos += to_copy;
      total_read += to_copy;

      // Compact buffer if we've consumed most of it
      if (sf->buf.pos > sf->buf.capacity / 2) {
        size_t remaining = sf->buf.size - sf->buf.pos;
        if (remaining > 0) {
          memmove(sf->buf.data, sf->buf.data + sf->buf.pos, remaining);
        }
        sf->buf.size = remaining;
        sf->buf.pos = 0;
      }
    } else if (sf->download_finished) {
      // No more data and download is done
      break;
    } else {
      // Buffer empty, need more data from network
      // Reset buffer position
      sf->buf.size = 0;
      sf->buf.pos = 0;

      // Unpause curl if it was paused due to full buffer
      if (sf->download_curl) {
        curl_easy_pause(sf->download_curl, CURLPAUSE_CONT);
      }

      // Drive download forward
      if (drive_download(sf) != 0) {
        return STORAGE_ERR_IO;
      }

      // Wait for data if none arrived
      if (sf->buf.size == 0 && !sf->download_finished) {
        int numfds;
        curl_multi_wait(sf->multi, NULL, 0, 100, &numfds);
        if (drive_download(sf) != 0) {
          return STORAGE_ERR_IO;
        }
      }
    }
  }

  return (int64_t)total_read;
#else
  // Non-streaming: read from pre-fetched buffer
  if (sf->read_pos >= sf->read_size) {
    return 0; // EOF
  }

  size_t available = sf->read_size - sf->read_pos;
  size_t to_read = len < available ? len : available;

  memcpy(buf, sf->read_buffer + sf->read_pos, to_read);
  sf->read_pos += to_read;

  return (int64_t)to_read;
#endif
}

// Helper for S3_UPLOAD_STREAMING: read callback for buffered data
#ifdef S3_UPLOAD_STREAMING
typedef struct {
  const char *data;
  size_t size;
  size_t pos;
} buffer_read_ctx_t;

static ssize_t buffer_read_callback(void *buf, size_t len, void *userdata) {
  buffer_read_ctx_t *ctx = (buffer_read_ctx_t *)userdata;
  size_t remaining = ctx->size - ctx->pos;
  if (remaining == 0)
    return 0; // EOF
  size_t to_copy = len < remaining ? len : remaining;
  memcpy(buf, ctx->data + ctx->pos, to_copy);
  ctx->pos += to_copy;
  return (ssize_t)to_copy;
}
#endif

static int s3_close(storage_file_t *f) {
  s3_file_t *sf = (s3_file_t *)f;
  if (!sf)
    return STORAGE_ERR_NOT_INIT;

  int rc = STORAGE_OK;

  if (sf->mode == STORAGE_MODE_WRITE) {
#ifdef S3_UPLOAD_MULTIPART
    // Flush any remaining data in write buffer as the final part
    // The last part can be smaller than S3_MIN_PART_SIZE
    if (sf->write_buffer_size > 0) {
      // Expand etags array if needed (check BEFORE incrementing part_number)
      if (sf->part_number + 1 > sf->etags_capacity) {
        int new_cap = sf->etags_capacity * 2;
        char **new_etags = realloc(sf->etags, new_cap * sizeof(char *));
        if (!new_etags) {
          log_error("s3_storage: failed to expand etags array for final part");
          s3_abort_multipart_upload(sf->ctx, sf->key, sf->upload_id);
          rc = STORAGE_ERR_IO;
          goto cleanup_multipart;
        }
        // Zero-initialize new slots to prevent freeing garbage on error
        for (int i = sf->etags_capacity; i < new_cap; i++) {
          new_etags[i] = NULL;
        }
        sf->etags = new_etags;
        sf->etags_capacity = new_cap;
      }

      log_info("s3_storage: flushing final part %d (%zu bytes)",
               sf->part_number + 1, sf->write_buffer_size);
      char *etag =
          s3_upload_part(sf->ctx, sf->key, sf->upload_id, sf->part_number + 1,
                         sf->write_buffer, sf->write_buffer_size);
      if (!etag) {
        log_error("s3_storage: failed to upload final part");
        s3_abort_multipart_upload(sf->ctx, sf->key, sf->upload_id);
        rc = STORAGE_ERR_IO;
        goto cleanup_multipart;
      }
      // Only increment part_number AFTER successful upload
      sf->etags[sf->part_number] = etag;
      sf->part_number++;
    }

    if (sf->part_number > 0) {
      // Complete multipart upload
      if (s3_complete_multipart_upload(sf->ctx, sf->key, sf->upload_id,
                                       sf->etags, sf->part_number) != 0) {
        s3_abort_multipart_upload(sf->ctx, sf->key, sf->upload_id);
        rc = STORAGE_ERR_IO;
      } else {
        log_info("s3_storage: wrote %s (%d parts)", sf->key, sf->part_number);
      }
    } else {
      // No data written, abort
      log_debug("s3_storage: no data written, aborting multipart upload");
      s3_abort_multipart_upload(sf->ctx, sf->key, sf->upload_id);
    }

  cleanup_multipart:
    // Cleanup multipart write resources
    for (int i = 0; i < sf->part_number; i++) {
      free(sf->etags[i]);
    }
    free(sf->etags);
    free(sf->upload_id);
    free(sf->write_buffer);
#endif

#ifdef S3_UPLOAD_STREAMING
    if (sf->upload_started) {
      // Finish sending any remaining data and complete upload
      log_info("s3_storage: finishing upload for %s", sf->key);

      // Keep driving curl until upload completes
      while (!sf->upload_finished) {
        // Unpause in case curl is waiting
        curl_easy_pause(sf->upload_curl, CURLPAUSE_CONT);

        int still_running;
        CURLMcode mc = curl_multi_perform(sf->multi, &still_running);
        if (mc != CURLM_OK) {
          log_error("s3_storage: curl_multi_perform failed in close: %d", mc);
          rc = STORAGE_ERR_IO;
          break;
        }

        if (still_running == 0) {
          sf->upload_finished = 1;
          break;
        }

        // Wait for activity (with timeout)
        int numfds;
        curl_multi_wait(sf->multi, NULL, 0, 100, &numfds);
      }

      // Check result
      CURLMsg *msg;
      int msgs_left;
      while ((msg = curl_multi_info_read(sf->multi, &msgs_left))) {
        if (msg->msg == CURLMSG_DONE) {
          long http_code = 0;
          curl_easy_getinfo(sf->upload_curl, CURLINFO_RESPONSE_CODE, &http_code);

          if (msg->data.result != CURLE_OK || http_code < 200 || http_code >= 300) {
            log_error("s3_storage: streaming PUT failed: curl=%d http=%ld",
                      msg->data.result, http_code);
            rc = STORAGE_ERR_IO;
          } else {
            log_info("s3_storage: wrote %s (streaming PUT, http=%ld)",
                     sf->key, http_code);
          }
        }
      }

      // Cleanup curl handles
      curl_multi_remove_handle(sf->multi, sf->upload_curl);
      curl_easy_cleanup(sf->upload_curl);
      curl_multi_cleanup(sf->multi);
      curl_slist_free_all(sf->headers);
    } else {
      log_debug("s3_storage: no data written, skipping upload");
    }

    // Cleanup buffer
    free(sf->buf.data);
#endif
  } else {
#ifdef S3_UPLOAD_STREAMING
    // Cleanup streaming download resources
    if (sf->download_started) {
      // Finish any in-progress download
      while (!sf->download_finished && sf->download_curl) {
        curl_easy_pause(sf->download_curl, CURLPAUSE_CONT);
        int still_running;
        CURLMcode mc = curl_multi_perform(sf->multi, &still_running);
        if (mc != CURLM_OK) {
          log_error("s3_storage: curl_multi_perform failed in download close: %d", mc);
          rc = STORAGE_ERR_IO;
          break;
        }
        if (still_running == 0)
          break;
        int numfds;
        curl_multi_wait(sf->multi, NULL, 0, 100, &numfds);
      }

      // Check for errors
      if (sf->download_curl) {
        long http_code = 0;
        curl_easy_getinfo(sf->download_curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code != 200) {
          log_error("s3_storage: streaming download failed: http=%ld", http_code);
          rc = STORAGE_ERR_IO;
        }
      }

      // Cleanup curl handles
      if (sf->download_curl) {
        curl_multi_remove_handle(sf->multi, sf->download_curl);
        curl_easy_cleanup(sf->download_curl);
      }
      if (sf->multi) {
        curl_multi_cleanup(sf->multi);
      }
      if (sf->headers) {
        curl_slist_free_all(sf->headers);
      }
    }
    // Cleanup buffer
    free(sf->buf.data);
#else
    free(sf->read_buffer);
#endif
  }

  free(sf);
  return rc;
}

// ─────────────────────────────────────────────────────────────────────────────
// Storage vtable
// ─────────────────────────────────────────────────────────────────────────────

static const struct storage s3_storage_ops = {
    .exists = s3_exists,
    .remove = s3_remove,
    .rename = s3_rename,
    .open = s3_open,
    .write = s3_write,
    .read = s3_read,
    .close = s3_close,
};

// ─────────────────────────────────────────────────────────────────────────────
// Service Metadata (for service registry)
// ─────────────────────────────────────────────────────────────────────────────

static const char *s3_tags[] = {"cloud", "aws", "s3", NULL};

static const service_metadata_t storage_service_meta = {
    .type = "storage",
    .provider = "s3",
    .version = "2.0.0",
    .description = "AWS S3 storage backend",
    .priority = 100, /* Higher priority than local storage */
    .tags = s3_tags,
    .dependencies = NULL,
    .interface_version = 1,
};

// ─────────────────────────────────────────────────────────────────────────────
// Plugin metadata
// ─────────────────────────────────────────────────────────────────────────────

static const pressured_plugin_metadata_t plugin_metadata = {
    .name = "s3-storage",
    .major_version = 2,
    .minor_version = 0,
    .description = "AWS S3 storage backend",
};

PRESSURED_PLUGIN_EXPORT const pressured_plugin_metadata_t *
pressured_plugin_get_metadata(void) {
  return &plugin_metadata;
}

// ─────────────────────────────────────────────────────────────────────────────
// Service Factory
// ─────────────────────────────────────────────────────────────────────────────

static void *s3_storage_factory(void *userdata) {
  pressured_plugin_ctx_t *ctx = userdata;

  struct pressured_plugin_handle *h =
      calloc(1, sizeof(struct pressured_plugin_handle));
  if (!h)
    return NULL;

  /* Copy vtable into handle (embedded as first field) */
  h->base = s3_storage_ops;
  h->ctx = ctx;

  log_debug("s3_storage: created storage instance");
  return h;
}

static void s3_storage_destructor(void *instance, void *userdata) {
  (void)userdata;
  if (instance) {
    log_debug("s3_storage: destroyed storage instance");
    free(instance);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Plugin Lifecycle
// ─────────────────────────────────────────────────────────────────────────────

PRESSURED_PLUGIN_EXPORT pressured_plugin_ctx_t *
pressured_plugin_load(const char *config_json, service_registry_t *sr) {
  pressured_plugin_ctx_t *ctx = calloc(1, sizeof(pressured_plugin_ctx_t));
  if (!ctx)
    return NULL;

  // Default region
  strncpy(ctx->region, "us-east-1", sizeof(ctx->region) - 1);

  // Parse JSON config - look for storage.s3 section
  if (config_json && config_json[0]) {
    struct json_object *root = json_tokener_parse(config_json);
    if (root) {
      struct json_object *storage_obj, *s3_obj, *obj;

      // Try storage.s3 path first (full config structure)
      if (json_object_object_get_ex(root, "storage", &storage_obj) &&
          json_object_object_get_ex(storage_obj, "s3", &s3_obj)) {
        if (json_object_object_get_ex(s3_obj, "bucket", &obj))
          strncpy(ctx->bucket, json_object_get_string(obj),
                  sizeof(ctx->bucket) - 1);
        if (json_object_object_get_ex(s3_obj, "region", &obj))
          strncpy(ctx->region, json_object_get_string(obj),
                  sizeof(ctx->region) - 1);
        if (json_object_object_get_ex(s3_obj, "prefix", &obj))
          strncpy(ctx->prefix, json_object_get_string(obj),
                  sizeof(ctx->prefix) - 1);
        if (json_object_object_get_ex(s3_obj, "endpoint", &obj))
          strncpy(ctx->endpoint, json_object_get_string(obj),
                  sizeof(ctx->endpoint) - 1);
      } else {
        // Fallback: try flat config (for direct plugin tests)
        if (json_object_object_get_ex(root, "bucket", &obj))
          strncpy(ctx->bucket, json_object_get_string(obj),
                  sizeof(ctx->bucket) - 1);
        if (json_object_object_get_ex(root, "region", &obj))
          strncpy(ctx->region, json_object_get_string(obj),
                  sizeof(ctx->region) - 1);
        if (json_object_object_get_ex(root, "prefix", &obj))
          strncpy(ctx->prefix, json_object_get_string(obj),
                  sizeof(ctx->prefix) - 1);
        if (json_object_object_get_ex(root, "endpoint", &obj))
          strncpy(ctx->endpoint, json_object_get_string(obj),
                  sizeof(ctx->endpoint) - 1);
      }
      json_object_put(root);
    }
  }

  // Region can also come from environment (for AWS SDK compatibility)
  if (!ctx->region[0] || strcmp(ctx->region, "us-east-1") == 0) {
    const char *env_region = getenv("AWS_REGION");
    if (!env_region)
      env_region = getenv("AWS_DEFAULT_REGION");
    if (env_region)
      strncpy(ctx->region, env_region, sizeof(ctx->region) - 1);
  }

  if (!ctx->bucket[0]) {
    log_error("s3_storage: missing bucket name in config (storage.s3.bucket)");
    free(ctx);
    return NULL;
  }

  ctx->curl = curl_easy_init();
  if (!ctx->curl) {
    free(ctx);
    return NULL;
  }

  // Initialize credentials
  if (ensure_credentials(ctx) != 0) {
    log_error("s3_storage: no AWS credentials available");
    curl_easy_cleanup(ctx->curl);
    free(ctx);
    return NULL;
  }

  /* Register storage service with the registry */
  int rc = service_registry_register(
      sr, &storage_service_meta, SERVICE_SCOPE_SINGLETON, s3_storage_factory,
      s3_storage_destructor, ctx);
  if (rc != 0) {
    log_error("s3_storage: failed to register with service registry");
    curl_easy_cleanup(ctx->curl);
    free(ctx);
    return NULL;
  }

  log_info("s3_storage: initialized bucket=%s region=%s prefix=%s", ctx->bucket,
           ctx->region, ctx->prefix[0] ? ctx->prefix : "(none)");
  return ctx;
}

PRESSURED_PLUGIN_EXPORT void
pressured_plugin_unload(pressured_plugin_ctx_t *ctx) {
  if (ctx) {
    if (ctx->curl)
      curl_easy_cleanup(ctx->curl);
    memset(ctx->secret_key, 0, sizeof(ctx->secret_key));
    free(ctx);
    log_debug("s3_storage: unloaded");
  }
}
