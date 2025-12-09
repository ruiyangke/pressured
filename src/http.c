/**
 * HTTP Client Implementation
 *
 * Minimal HTTP client built on libcurl.
 */

#include "http.h"
#include "log.h"
#include "pressured.h"
#include <curl/curl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// ============================================================================
// Internal Types
// ============================================================================

struct http_client {
  int timeout_ms;
  int connect_timeout_ms;
  bool skip_ssl_verify;
  char *ca_path;
  char *proxy;
  char *bearer_token; // "Authorization: Bearer xxx"
  char *basic_auth;   // "user:pass"
  CURL *curl;
};

typedef struct {
  char *data;
  size_t size;
  size_t capacity;
} buffer_t;

typedef struct {
  http_write_fn write_fn;    // User write callback
  void *write_ctx;           // Context for write callback
  http_progress_fn progress; // Progress callback
  void *prog_ctx;            // Context for progress callback
  size_t written;            // Bytes written so far
  size_t total;              // Total bytes expected (0 if unknown)
  int aborted;               // Set to 1 to abort transfer
} stream_ctx_t;

// ============================================================================
// Global Init (auto-initialized, thread-safe)
// ============================================================================

static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;
static int g_init_result = 0;

static void do_global_init(void) {
  CURLcode rc = curl_global_init(CURL_GLOBAL_DEFAULT);
  if (rc != CURLE_OK) {
    log_error("http: curl_global_init failed: %s", curl_easy_strerror(rc));
    g_init_result = -1;
  }
}

static int ensure_init(void) {
  pthread_once(&g_init_once, do_global_init);
  return g_init_result;
}

// ============================================================================
// Client
// ============================================================================

http_client_t *http_client_new(const http_opts_t *opts) {
  if (ensure_init() != 0)
    return NULL;

  http_client_t *c = calloc(1, sizeof(http_client_t));
  if (!c)
    return NULL;

  // Defaults (calloc zeros skip_ssl_verify to false = verify SSL)
  c->timeout_ms = 30000;
  c->connect_timeout_ms = 10000;

  // Override with user options
  if (opts) {
    if (opts->timeout_ms > 0)
      c->timeout_ms = opts->timeout_ms;
    if (opts->connect_timeout_ms > 0)
      c->connect_timeout_ms = opts->connect_timeout_ms;
    c->skip_ssl_verify = opts->skip_ssl_verify;
    if (opts->ca_path) {
      c->ca_path = strdup(opts->ca_path);
      if (!c->ca_path)
        goto fail;
    }
    if (opts->proxy) {
      c->proxy = strdup(opts->proxy);
      if (!c->proxy)
        goto fail;
    }
  }

  c->curl = curl_easy_init();
  if (!c->curl)
    goto fail;

  return c;

fail:
  free(c->ca_path);
  free(c->proxy);
  free(c);
  return NULL;
}

void http_client_free(http_client_t *c) {
  if (!c)
    return;
  free(c->bearer_token);
  free(c->basic_auth);
  free(c->ca_path);
  free(c->proxy);
  if (c->curl)
    curl_easy_cleanup(c->curl);
  free(c);
}

int http_client_auth_basic(http_client_t *c, const char *user,
                           const char *pass) {
  if (!c || !user || !pass)
    return -1;
  free(c->basic_auth);
  c->basic_auth = NULL;
  size_t len = strlen(user) + 1 + strlen(pass) + 1;
  c->basic_auth = malloc(len);
  if (!c->basic_auth)
    return -1;
  snprintf(c->basic_auth, len, "%s:%s", user, pass);
  return 0;
}

int http_client_auth_bearer(http_client_t *c, const char *token) {
  if (!c || !token)
    return -1;
  free(c->bearer_token);
  c->bearer_token = NULL;
  size_t len = strlen("Authorization: Bearer ") + strlen(token) + 1;
  c->bearer_token = malloc(len);
  if (!c->bearer_token)
    return -1;
  snprintf(c->bearer_token, len, "Authorization: Bearer %s", token);
  return 0;
}

// ============================================================================
// Curl Callbacks
// ============================================================================

static size_t write_cb(void *data, size_t size, size_t nmemb, void *userp) {
  size_t realsize = size * nmemb;
  buffer_t *buf = userp;

  if (buf->size + realsize + 1 > buf->capacity) {
    size_t newcap = buf->capacity ? buf->capacity * 2 : 4096;
    while (newcap < buf->size + realsize + 1)
      newcap *= 2;
    char *newdata = realloc(buf->data, newcap);
    if (!newdata)
      return 0;
    buf->data = newdata;
    buf->capacity = newcap;
  }

  memcpy(buf->data + buf->size, data, realsize);
  buf->size += realsize;
  buf->data[buf->size] = '\0';
  return realsize;
}

static size_t stream_write_cb(void *data, size_t size, size_t nmemb,
                              void *userp) {
  size_t realsize = size * nmemb;
  stream_ctx_t *ctx = userp;

  if (ctx->aborted)
    return 0;

  // Call user's write callback
  size_t written = ctx->write_fn(data, realsize, ctx->write_ctx);
  if (written != realsize) {
    ctx->aborted = 1;
    return 0;
  }

  ctx->written += written;

  // Call progress callback if provided
  if (ctx->progress) {
    if (ctx->progress(ctx->prog_ctx, ctx->total, ctx->written) != 0) {
      ctx->aborted = 1;
      return 0;
    }
  }
  return written;
}

static int stream_progress_cb(void *clientp, curl_off_t dltotal,
                              curl_off_t dlnow, curl_off_t ultotal,
                              curl_off_t ulnow) {
  (void)dlnow;
  (void)ultotal;
  (void)ulnow;
  stream_ctx_t *ctx = clientp;
  if (dltotal > 0)
    ctx->total = (size_t)dltotal;
  return ctx->aborted ? 1 : 0;
}

// ============================================================================
// Fetch
// ============================================================================

static void setup_curl_opts(http_client_t *c, CURL *curl) {
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)c->timeout_ms);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS,
                   (long)c->connect_timeout_ms);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 10L);

  if (c->skip_ssl_verify) {
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
  }
  if (c->ca_path) {
    curl_easy_setopt(curl, CURLOPT_CAINFO, c->ca_path);
  }
  if (c->proxy) {
    curl_easy_setopt(curl, CURLOPT_PROXY, c->proxy);
  }

  curl_easy_setopt(curl, CURLOPT_USERAGENT, "pressured/" PRESSURED_VERSION);

  if (c->basic_auth) {
    curl_easy_setopt(curl, CURLOPT_USERPWD, c->basic_auth);
  }
}

http_response_t *http_fetch(http_client_t *c, const char *method,
                            const char *url, const http_request_t *req) {
  http_response_t *r = calloc(1, sizeof(http_response_t));
  if (!r)
    return NULL;

  if (!c || !method || !url) {
    r->error = strdup("Invalid arguments");
    return r;
  }

  CURL *curl = c->curl;
  curl_easy_reset(curl);

  buffer_t buf = {0};
  struct curl_slist *headers = NULL;

  // URL
  curl_easy_setopt(curl, CURLOPT_URL, url);

  // Method
  if (strcmp(method, "GET") == 0) {
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
  } else if (strcmp(method, "POST") == 0) {
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
  } else if (strcmp(method, "HEAD") == 0) {
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
  } else {
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
  }

  // Body
  if (req && req->body) {
    size_t len = req->body_len ? req->body_len : strlen(req->body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req->body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)len);
  }

  // Content-Type
  if (req && req->content_type) {
    size_t ct_len = strlen("Content-Type: ") + strlen(req->content_type) + 1;
    char *ct = malloc(ct_len);
    if (!ct)
      goto header_fail;
    snprintf(ct, ct_len, "Content-Type: %s", req->content_type);
    struct curl_slist *tmp = curl_slist_append(headers, ct);
    free(ct);
    if (!tmp)
      goto header_fail;
    headers = tmp;
  }

  // Custom headers
  if (req && req->headers) {
    for (const char **h = req->headers; *h; h++) {
      struct curl_slist *tmp = curl_slist_append(headers, *h);
      if (!tmp)
        goto header_fail;
      headers = tmp;
    }
  }

  // Bearer token
  if (c->bearer_token) {
    struct curl_slist *tmp = curl_slist_append(headers, c->bearer_token);
    if (!tmp)
      goto header_fail;
    headers = tmp;
  }

  if (headers) {
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  }

  // Callbacks
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);

  // Options
  setup_curl_opts(c, curl);

  // Execute
  CURLcode res = curl_easy_perform(curl);

  if (res != CURLE_OK) {
    r->error = strdup(curl_easy_strerror(res));
    free(buf.data);
  } else {
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    r->status = (int)code;
    r->body = buf.data;
    r->body_len = buf.size;
  }

  curl_slist_free_all(headers);
  return r;

header_fail:
  curl_slist_free_all(headers);
  free(buf.data);
  r->error = strdup("Failed to allocate headers");
  return r;
}

void http_response_free(http_response_t *r) {
  if (!r)
    return;
  free(r->body);
  free(r->error);
  free(r);
}

// ============================================================================
// Streaming Download
// ============================================================================

int http_stream(http_client_t *c, const char *method, const char *url,
                const http_request_t *req, http_write_fn write_fn,
                void *write_ctx, http_progress_fn progress, void *prog_ctx) {
  if (!c || !url || !write_fn)
    return -1;
  if (!method)
    method = "GET";

  stream_ctx_t sctx = {.write_fn = write_fn,
                       .write_ctx = write_ctx,
                       .progress = progress,
                       .prog_ctx = prog_ctx};

  CURL *curl = c->curl;
  curl_easy_reset(curl);

  struct curl_slist *headers = NULL;

  // URL
  curl_easy_setopt(curl, CURLOPT_URL, url);

  // Method
  if (strcmp(method, "GET") == 0) {
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
  } else if (strcmp(method, "POST") == 0) {
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
  } else if (strcmp(method, "HEAD") == 0) {
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
  } else {
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
  }

  // Body
  if (req && req->body) {
    size_t len = req->body_len ? req->body_len : strlen(req->body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req->body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)len);
  }

  // Content-Type
  if (req && req->content_type) {
    size_t ct_len = strlen("Content-Type: ") + strlen(req->content_type) + 1;
    char *ct = malloc(ct_len);
    if (ct) {
      snprintf(ct, ct_len, "Content-Type: %s", req->content_type);
      struct curl_slist *tmp = curl_slist_append(headers, ct);
      free(ct);
      if (tmp)
        headers = tmp;
    }
  }

  // Custom headers
  if (req && req->headers) {
    for (const char **h = req->headers; *h; h++) {
      struct curl_slist *tmp = curl_slist_append(headers, *h);
      if (tmp)
        headers = tmp;
    }
  }

  // Bearer token
  if (c->bearer_token) {
    struct curl_slist *tmp = curl_slist_append(headers, c->bearer_token);
    if (tmp)
      headers = tmp;
  }

  if (headers) {
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  }

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, stream_write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sctx);
  // Fail early on HTTP errors (4xx/5xx) before writing body to callback
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

  if (progress) {
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, stream_progress_cb);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &sctx);
  }

  setup_curl_opts(c, curl);

  CURLcode res = curl_easy_perform(curl);

  curl_slist_free_all(headers);

  if (res != CURLE_OK) {
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (code >= 400) {
      log_error("http: stream failed with status %ld", code);
    } else {
      log_error("http: stream failed: %s", curl_easy_strerror(res));
    }
    return -1;
  }

  return 0;
}

// File write callback for http_download
static size_t file_write_fn(const void *data, size_t len, void *ctx) {
  FILE *fp = ctx;
  return fwrite(data, 1, len, fp);
}

int http_download(http_client_t *c, const char *url, const char *path,
                  http_progress_fn progress, void *ctx) {
  if (!c || !url || !path)
    return -1;

  FILE *fp = fopen(path, "wb");
  if (!fp) {
    log_error("http: cannot open file: %s", path);
    return -1;
  }

  int ret = http_stream(c, "GET", url, NULL, file_write_fn, fp, progress, ctx);

  if (fclose(fp) != 0) {
    log_error("http: failed to close file: %s", path);
    unlink(path);
    return -1;
  }

  if (ret != 0) {
    unlink(path); // Clean up partial file on error
  }

  return ret;
}

// ============================================================================
// URL Encoding
// ============================================================================

char *http_urlencode(const char *s) {
  if (!s)
    return NULL;

  CURL *curl = curl_easy_init();
  if (!curl)
    return NULL;

  char *encoded = curl_easy_escape(curl, s, 0);
  char *result = encoded ? strdup(encoded) : NULL;

  curl_free(encoded);
  curl_easy_cleanup(curl);
  return result;
}
