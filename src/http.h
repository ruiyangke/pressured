/**
 * HTTP Client - Minimal API
 *
 * Usage:
 *   http_client_t *c = http_client_new(NULL);
 *   if (!c) { handle_error(); }
 *
 *   // Simple GET with error handling
 *   http_response_t *r = http_fetch(c, "GET", "https://api.example.com/data",
 * NULL); if (!r) {
 *       // Allocation failed (rare)
 *   } else if (r->error) {
 *       // Network/curl error (e.g., DNS failure, timeout)
 *       fprintf(stderr, "Error: %s\n", r->error);
 *   } else if (r->status != 200) {
 *       // HTTP error (e.g., 404, 500)
 *       fprintf(stderr, "HTTP %d: %s\n", r->status, r->body);
 *   } else {
 *       printf("%s\n", r->body);
 *   }
 *   http_response_free(r);
 *
 *   // POST with JSON
 *   http_request_t req = {
 *       .body = "{\"key\":\"value\"}",
 *       .content_type = "application/json"
 *   };
 *   r = http_fetch(c, "POST", "https://api.example.com/data", &req);
 *   http_response_free(r);
 *
 *   // Download large file to disk
 *   if (http_download(c, url, "/tmp/file.bin", my_progress, ctx) != 0) {
 *       // Download failed (HTTP error, network error, or file write error)
 *   }
 *
 *   // Stream large file to custom handler (e.g., storage backend)
 *   http_stream(c, url, my_write_fn, write_ctx, my_progress, prog_ctx);
 *
 *   http_client_free(c);
 */

#ifndef HTTP_H
#define HTTP_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Types
// ============================================================================

/** Client configuration options */
typedef struct {
  int timeout_ms;         // Request timeout, 0 = default (30s)
  int connect_timeout_ms; // Connection timeout, 0 = default (10s)
  bool skip_ssl_verify; // Skip SSL cert verification (INSECURE), default: false
  const char *ca_path;  // Custom CA bundle path, NULL = system default
  const char *proxy;    // Proxy URL, NULL = no proxy
} http_opts_t;

/** Request options (all fields optional) */
typedef struct {
  const char *body;         // Request body, NULL = no body
  size_t body_len;          // Body length, 0 = strlen(body)
  const char *content_type; // Content-Type header, NULL = none
  const char **headers;     // NULL-terminated array of "Name: Value" strings
} http_request_t;

/** Response (caller must free with http_response_free) */
typedef struct {
  int status;      // HTTP status code (200, 404, etc), 0 on error
  char *body;      // Response body, NULL-terminated
  size_t body_len; // Body length in bytes
  char *error;     // Error message if status==0, NULL on success
} http_response_t;

/** Opaque client handle */
typedef struct http_client http_client_t;

/**
 * Progress callback for downloads
 * @param ctx       User context
 * @param total     Total bytes expected (0 if unknown)
 * @param current   Bytes transferred so far
 * @return 0 to continue, non-zero to abort
 */
typedef int (*http_progress_fn)(void *ctx, size_t total, size_t current);

/**
 * Write callback for streaming downloads
 * Called repeatedly with chunks of data as they arrive.
 * @param data      Pointer to received data chunk
 * @param len       Length of data chunk in bytes
 * @param ctx       User context
 * @return Number of bytes handled (must equal len to continue), 0 to abort
 */
typedef size_t (*http_write_fn)(const void *data, size_t len, void *ctx);

// ============================================================================
// API
// ============================================================================

/**
 * Create HTTP client
 * @param opts  Options (NULL for defaults)
 * @return Client handle, NULL on error
 */
http_client_t *http_client_new(const http_opts_t *opts);

/**
 * Free HTTP client
 * @param c  Client (NULL-safe)
 */
void http_client_free(http_client_t *c);

/**
 * Set basic auth for all requests
 * @param c     Client
 * @param user  Username
 * @param pass  Password
 * @return 0 on success, -1 on error
 */
int http_client_auth_basic(http_client_t *c, const char *user,
                           const char *pass);

/**
 * Set bearer token for all requests
 * @param c      Client
 * @param token  Bearer token (without "Bearer " prefix)
 * @return 0 on success, -1 on error
 */
int http_client_auth_bearer(http_client_t *c, const char *token);

/**
 * Perform HTTP request
 * @param c       Client
 * @param method  HTTP method ("GET", "POST", "PUT", "DELETE", etc)
 * @param url     Request URL
 * @param req     Request options (NULL for simple GET)
 * @return Response (caller must free), NULL on allocation failure
 */
http_response_t *http_fetch(http_client_t *c, const char *method,
                            const char *url, const http_request_t *req);

/**
 * Free response
 * @param r  Response (NULL-safe)
 */
void http_response_free(http_response_t *r);

/**
 * Stream download with custom write callback (for large files)
 * Data is passed to write_fn as it arrives, never buffered in memory.
 * @param c         Client
 * @param method    HTTP method ("GET", "POST", etc)
 * @param url       URL to download
 * @param req       Request options (NULL for simple GET)
 * @param write_fn  Callback to receive data chunks
 * @param write_ctx Context passed to write_fn
 * @param progress  Progress callback (NULL for none)
 * @param prog_ctx  Context passed to progress callback
 * @return 0 on success, -1 on error
 */
int http_stream(http_client_t *c, const char *method, const char *url,
                const http_request_t *req, http_write_fn write_fn,
                void *write_ctx, http_progress_fn progress, void *prog_ctx);

/**
 * Download URL to file (convenience wrapper around http_stream)
 * @param c         Client
 * @param url       URL to download
 * @param path      Destination file path
 * @param progress  Progress callback (NULL for none)
 * @param ctx       User context passed to callback
 * @return 0 on success, -1 on error
 */
int http_download(http_client_t *c, const char *url, const char *path,
                  http_progress_fn progress, void *ctx);

/**
 * URL-encode a string
 * @param s  String to encode
 * @return Encoded string (caller must free), NULL on error
 */
char *http_urlencode(const char *s);

#ifdef __cplusplus
}
#endif

#endif // HTTP_H
