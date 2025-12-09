/**
 * HTTP Client Tests
 *
 * Tests for the minimal HTTP API (8 functions).
 */

#include "http.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                             \
  do {                                                                         \
    printf("Testing: %s... ", name);                                           \
    tests_run++;                                                               \
  } while (0)

#define PASS()                                                                 \
  do {                                                                         \
    printf("PASSED\n");                                                        \
    tests_passed++;                                                            \
  } while (0)

#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAILED: %s\n", msg);                                               \
  } while (0)

// ============================================================================
// Client Tests
// ============================================================================

static void test_client_new_default(void) {
  TEST("http_client_new with NULL opts");
  http_client_t *c = http_client_new(NULL);
  assert(c != NULL);
  http_client_free(c);
  PASS();
}

static void test_client_new_with_opts(void) {
  TEST("http_client_new with custom opts");
  http_opts_t opts = {
      .timeout_ms = 5000,
      .connect_timeout_ms = 2000,
      .skip_ssl_verify = true // Skip verification for test
  };
  http_client_t *c = http_client_new(&opts);
  assert(c != NULL);
  http_client_free(c);
  PASS();
}

static void test_client_new_all_opts(void) {
  TEST("http_client_new with all options");
  http_opts_t opts = {.timeout_ms = 60000,
                      .connect_timeout_ms = 5000,
                      .skip_ssl_verify =
                          false, // Verify SSL (default, explicit for clarity)
                      .ca_path = "/etc/ssl/certs/ca-certificates.crt",
                      .proxy = "http://proxy:8080"};
  http_client_t *c = http_client_new(&opts);
  assert(c != NULL);
  http_client_free(c);
  PASS();
}

static void test_client_free_null(void) {
  TEST("http_client_free NULL safety");
  http_client_free(NULL); // Should not crash
  PASS();
}

static void test_multiple_clients(void) {
  TEST("multiple client instances");
  http_client_t *c1 = http_client_new(NULL);
  http_client_t *c2 = http_client_new(NULL);
  http_client_t *c3 = http_client_new(NULL);
  assert(c1 && c2 && c3);
  assert(c1 != c2 && c2 != c3);
  http_client_free(c1);
  http_client_free(c2);
  http_client_free(c3);
  PASS();
}

// ============================================================================
// Auth Tests
// ============================================================================

static void test_auth_basic(void) {
  TEST("http_client_auth_basic");
  http_client_t *c = http_client_new(NULL);
  http_client_auth_basic(c, "user", "pass");
  // No crash, no return value to check
  http_client_free(c);
  PASS();
}

static void test_auth_basic_special_chars(void) {
  TEST("http_client_auth_basic with special chars");
  http_client_t *c = http_client_new(NULL);
  http_client_auth_basic(c, "user@domain.com", "p@ss:word!");
  http_client_free(c);
  PASS();
}

static void test_auth_basic_null_safety(void) {
  TEST("http_client_auth_basic NULL safety");
  http_client_t *c = http_client_new(NULL);
  http_client_auth_basic(NULL, "user", "pass"); // Should not crash
  http_client_auth_basic(c, NULL, "pass");      // Should not crash
  http_client_auth_basic(c, "user", NULL);      // Should not crash
  http_client_free(c);
  PASS();
}

static void test_auth_bearer(void) {
  TEST("http_client_auth_bearer");
  http_client_t *c = http_client_new(NULL);
  http_client_auth_bearer(c, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
  http_client_free(c);
  PASS();
}

static void test_auth_bearer_long_token(void) {
  TEST("http_client_auth_bearer with long token");
  http_client_t *c = http_client_new(NULL);
  char token[2048];
  memset(token, 'x', sizeof(token) - 1);
  token[sizeof(token) - 1] = '\0';
  http_client_auth_bearer(c, token);
  http_client_free(c);
  PASS();
}

static void test_auth_bearer_null_safety(void) {
  TEST("http_client_auth_bearer NULL safety");
  http_client_t *c = http_client_new(NULL);
  http_client_auth_bearer(NULL, "token"); // Should not crash
  http_client_auth_bearer(c, NULL);       // Should not crash
  http_client_free(c);
  PASS();
}

static void test_auth_replace(void) {
  TEST("auth replacement");
  http_client_t *c = http_client_new(NULL);
  http_client_auth_bearer(c, "token1");
  http_client_auth_bearer(c, "token2"); // Should replace, not leak
  http_client_auth_basic(c, "user1", "pass1");
  http_client_auth_basic(c, "user2", "pass2"); // Should replace
  http_client_free(c);
  PASS();
}

// ============================================================================
// Fetch Tests
// ============================================================================

static void test_fetch_null_client(void) {
  TEST("http_fetch with NULL client");
  http_response_t *r = http_fetch(NULL, "GET", "http://example.com", NULL);
  assert(r != NULL);
  assert(r->status == 0);
  assert(r->error != NULL);
  http_response_free(r);
  PASS();
}

static void test_fetch_null_method(void) {
  TEST("http_fetch with NULL method");
  http_client_t *c = http_client_new(NULL);
  http_response_t *r = http_fetch(c, NULL, "http://example.com", NULL);
  assert(r != NULL);
  assert(r->status == 0);
  assert(r->error != NULL);
  http_response_free(r);
  http_client_free(c);
  PASS();
}

static void test_fetch_null_url(void) {
  TEST("http_fetch with NULL URL");
  http_client_t *c = http_client_new(NULL);
  http_response_t *r = http_fetch(c, "GET", NULL, NULL);
  assert(r != NULL);
  assert(r->status == 0);
  assert(r->error != NULL);
  http_response_free(r);
  http_client_free(c);
  PASS();
}

static void test_fetch_with_body(void) {
  TEST("http_fetch with body");
  http_client_t *c = http_client_new(NULL);
  http_request_t req = {.body = "{\"test\":true}",
                        .content_type = "application/json"};
  // This will fail to connect, but tests request building
  http_response_t *r =
      http_fetch(c, "POST", "http://localhost:99999/test", &req);
  assert(r != NULL);
  // Error expected (connection refused)
  http_response_free(r);
  http_client_free(c);
  PASS();
}

static void test_fetch_with_headers(void) {
  TEST("http_fetch with custom headers");
  http_client_t *c = http_client_new(NULL);
  const char *headers[] = {"X-Custom-Header: value", "X-Another: test", NULL};
  http_request_t req = {.headers = headers};
  http_response_t *r =
      http_fetch(c, "GET", "http://localhost:99999/test", &req);
  assert(r != NULL);
  http_response_free(r);
  http_client_free(c);
  PASS();
}

static void test_fetch_with_body_len(void) {
  TEST("http_fetch with explicit body_len");
  http_client_t *c = http_client_new(NULL);
  const char *data = "binary\0data";
  http_request_t req = {.body = data,
                        .body_len = 11, // Include null byte
                        .content_type = "application/octet-stream"};
  http_response_t *r =
      http_fetch(c, "PUT", "http://localhost:99999/test", &req);
  assert(r != NULL);
  http_response_free(r);
  http_client_free(c);
  PASS();
}

static void test_fetch_all_methods(void) {
  TEST("http_fetch with all HTTP methods");
  http_client_t *c = http_client_new(NULL);
  const char *methods[] = {"GET",   "POST", "PUT",     "DELETE",
                           "PATCH", "HEAD", "OPTIONS", NULL};

  for (const char **m = methods; *m; m++) {
    http_response_t *r = http_fetch(c, *m, "http://localhost:99999/test", NULL);
    assert(r != NULL);
    http_response_free(r);
  }

  http_client_free(c);
  PASS();
}

// ============================================================================
// Response Tests
// ============================================================================

static void test_response_free_null(void) {
  TEST("http_response_free NULL safety");
  http_response_free(NULL); // Should not crash
  PASS();
}

static void test_response_structure(void) {
  TEST("http_response_t structure");
  http_client_t *c = http_client_new(NULL);
  http_response_t *r =
      http_fetch(c, "GET", "http://localhost:99999/test", NULL);
  assert(r != NULL);
  // Connection error: status=0, error set
  assert(r->status == 0 || r->error != NULL || r->body != NULL);
  http_response_free(r);
  http_client_free(c);
  PASS();
}

// ============================================================================
// Download Tests
// ============================================================================

static void test_download_null_client(void) {
  TEST("http_download with NULL client");
  int ret =
      http_download(NULL, "http://example.com/file", "/tmp/test", NULL, NULL);
  assert(ret == -1);
  PASS();
}

static void test_download_null_url(void) {
  TEST("http_download with NULL URL");
  http_client_t *c = http_client_new(NULL);
  int ret = http_download(c, NULL, "/tmp/test", NULL, NULL);
  assert(ret == -1);
  http_client_free(c);
  PASS();
}

static void test_download_null_path(void) {
  TEST("http_download with NULL path");
  http_client_t *c = http_client_new(NULL);
  int ret = http_download(c, "http://example.com/file", NULL, NULL, NULL);
  assert(ret == -1);
  http_client_free(c);
  PASS();
}

static int progress_callback_called = 0;
static int test_progress_cb(void *ctx, size_t total, size_t current) {
  (void)ctx;
  (void)total;
  (void)current;
  progress_callback_called = 1;
  return 0;
}

static void test_download_with_progress(void) {
  TEST("http_download with progress callback (signature test)");
  http_client_t *c = http_client_new(NULL);
  // Will fail to connect, but tests API
  progress_callback_called = 0;
  int ret = http_download(c, "http://localhost:99999/file",
                          "/tmp/test_http_download", test_progress_cb, NULL);
  assert(ret == -1); // Expected: connection refused
  // File should not exist (cleaned up on error)
  http_client_free(c);
  PASS();
}

// ============================================================================
// Stream Tests
// ============================================================================

static size_t stream_bytes_received = 0;

static size_t test_stream_write_fn(const void *data, size_t len, void *ctx) {
  (void)data;
  int *call_count = (int *)ctx;
  (*call_count)++;
  stream_bytes_received += len;
  return len; // Accept all data
}

static void test_stream_null_client(void) {
  TEST("http_stream with NULL client");
  int calls = 0;
  int ret = http_stream(NULL, "GET", "http://example.com", NULL,
                        test_stream_write_fn, &calls, NULL, NULL);
  assert(ret == -1);
  PASS();
}

static void test_stream_null_url(void) {
  TEST("http_stream with NULL URL");
  http_client_t *c = http_client_new(NULL);
  int calls = 0;
  int ret = http_stream(c, "GET", NULL, NULL, test_stream_write_fn, &calls,
                        NULL, NULL);
  assert(ret == -1);
  http_client_free(c);
  PASS();
}

static void test_stream_null_write_fn(void) {
  TEST("http_stream with NULL write_fn");
  http_client_t *c = http_client_new(NULL);
  int ret =
      http_stream(c, "GET", "http://example.com", NULL, NULL, NULL, NULL, NULL);
  assert(ret == -1);
  http_client_free(c);
  PASS();
}

static void test_stream_with_callback(void) {
  TEST("http_stream with write callback (signature test)");
  http_client_t *c = http_client_new(NULL);
  int calls = 0;
  stream_bytes_received = 0;
  // Will fail to connect, but tests API accepts the callback
  int ret = http_stream(c, "GET", "http://localhost:99999/data", NULL,
                        test_stream_write_fn, &calls, NULL, NULL);
  assert(ret == -1); // Expected: connection refused
  http_client_free(c);
  PASS();
}

static size_t abort_write_fn(const void *data, size_t len, void *ctx) {
  (void)data;
  (void)len;
  (void)ctx;
  return 0; // Return 0 to abort
}

static void test_stream_abort_via_callback(void) {
  TEST("http_stream abort via write callback returning 0");
  http_client_t *c = http_client_new(NULL);
  // Will fail at connection anyway, but tests the abort path signature
  int ret = http_stream(c, "GET", "http://localhost:99999/data", NULL,
                        abort_write_fn, NULL, NULL, NULL);
  assert(ret == -1);
  http_client_free(c);
  PASS();
}

// ============================================================================
// URL Encoding Tests
// ============================================================================

static void test_urlencode_basic(void) {
  TEST("http_urlencode basic");
  char *encoded = http_urlencode("hello world");
  assert(encoded != NULL);
  assert(strcmp(encoded, "hello%20world") == 0);
  free(encoded);
  PASS();
}

static void test_urlencode_special(void) {
  TEST("http_urlencode special characters");
  char *encoded = http_urlencode("a=b&c=d");
  assert(encoded != NULL);
  assert(strcmp(encoded, "a%3Db%26c%3Dd") == 0);
  free(encoded);
  PASS();
}

static void test_urlencode_unicode(void) {
  TEST("http_urlencode unicode");
  char *encoded = http_urlencode("日本語");
  assert(encoded != NULL);
  // Should be percent-encoded UTF-8
  assert(strstr(encoded, "%") != NULL);
  free(encoded);
  PASS();
}

static void test_urlencode_empty(void) {
  TEST("http_urlencode empty string");
  char *encoded = http_urlencode("");
  assert(encoded != NULL);
  assert(strcmp(encoded, "") == 0);
  free(encoded);
  PASS();
}

static void test_urlencode_null(void) {
  TEST("http_urlencode NULL");
  const char *encoded = http_urlencode(NULL);
  assert(encoded == NULL);
  PASS();
}

static void test_urlencode_no_encoding_needed(void) {
  TEST("http_urlencode no encoding needed");
  char *encoded = http_urlencode("abcdefghijklmnopqrstuvwxyz0123456789");
  assert(encoded != NULL);
  assert(strcmp(encoded, "abcdefghijklmnopqrstuvwxyz0123456789") == 0);
  free(encoded);
  PASS();
}

// ============================================================================
// Integration Tests
// ============================================================================

static void test_client_reuse(void) {
  TEST("client reuse across multiple requests");
  http_client_t *c = http_client_new(NULL);

  for (int i = 0; i < 5; i++) {
    http_response_t *r =
        http_fetch(c, "GET", "http://localhost:99999/test", NULL);
    assert(r != NULL);
    http_response_free(r);
  }

  http_client_free(c);
  PASS();
}

static void test_client_with_auth_reuse(void) {
  TEST("client with auth reuse");
  http_client_t *c = http_client_new(NULL);
  http_client_auth_bearer(c, "test-token");

  http_response_t *r1 =
      http_fetch(c, "GET", "http://localhost:99999/test", NULL);
  http_response_t *r2 =
      http_fetch(c, "POST", "http://localhost:99999/test", NULL);

  assert(r1 && r2);
  http_response_free(r1);
  http_response_free(r2);
  http_client_free(c);
  PASS();
}

static void test_empty_body(void) {
  TEST("empty body handling");
  http_client_t *c = http_client_new(NULL);
  http_request_t req = {.body = "", .content_type = "text/plain"};
  http_response_t *r =
      http_fetch(c, "POST", "http://localhost:99999/test", &req);
  assert(r != NULL);
  http_response_free(r);
  http_client_free(c);
  PASS();
}

static void test_long_url(void) {
  TEST("long URL handling");
  http_client_t *c = http_client_new(NULL);

  char url[4096];
  strcpy(url, "http://localhost:99999/test?");
  for (int i = strlen(url); i < 4000; i++) {
    url[i] = 'x';
  }
  url[4000] = '\0';

  http_response_t *r = http_fetch(c, "GET", url, NULL);
  assert(r != NULL);
  http_response_free(r);
  http_client_free(c);
  PASS();
}

// ============================================================================
// Main
// ============================================================================

int main(void) {
  printf("=== HTTP Interface Tests (Minimal API) ===\n\n");

  // Client tests
  test_client_new_default();
  test_client_new_with_opts();
  test_client_new_all_opts();
  test_client_free_null();
  test_multiple_clients();

  // Auth tests
  test_auth_basic();
  test_auth_basic_special_chars();
  test_auth_basic_null_safety();
  test_auth_bearer();
  test_auth_bearer_long_token();
  test_auth_bearer_null_safety();
  test_auth_replace();

  // Fetch tests
  test_fetch_null_client();
  test_fetch_null_method();
  test_fetch_null_url();
  test_fetch_with_body();
  test_fetch_with_headers();
  test_fetch_with_body_len();
  test_fetch_all_methods();

  // Response tests
  test_response_free_null();
  test_response_structure();

  // Download tests
  test_download_null_client();
  test_download_null_url();
  test_download_null_path();
  test_download_with_progress();

  // Stream tests
  test_stream_null_client();
  test_stream_null_url();
  test_stream_null_write_fn();
  test_stream_with_callback();
  test_stream_abort_via_callback();

  // URL encoding tests
  test_urlencode_basic();
  test_urlencode_special();
  test_urlencode_unicode();
  test_urlencode_empty();
  test_urlencode_null();
  test_urlencode_no_encoding_needed();

  // Integration tests
  test_client_reuse();
  test_client_with_auth_reuse();
  test_empty_body();
  test_long_url();

  printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
  return tests_passed == tests_run ? 0 : 1;
}
