/**
 * HTTP Client E2E Tests
 *
 * Requires the Python test server to be running:
 *   python3 tests/e2e_server.py 8765
 */

#include "http.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BASE_URL "http://127.0.0.1:8765"

#define TEST(name)                                                             \
  printf("Testing: %s... ", name);                                             \
  fflush(stdout)
#define PASS() printf("\033[32mPASSED\033[0m\n")
#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("\033[31mFAILED: %s\033[0m\n", msg);                                \
    failures++;                                                                \
  } while (0)

static int failures = 0;
static int tests_run = 0;

// ============================================================================
// Test Helpers
// ============================================================================

static int check_response(http_response_t *r, int expected_status,
                          const char *contains) {
  if (!r) {
    printf("NULL response\n");
    return 0;
  }
  if (r->error) {
    printf("Error: %s\n", r->error);
    return 0;
  }
  if (r->status != expected_status) {
    printf("Expected status %d, got %d\n", expected_status, r->status);
    return 0;
  }
  if (contains && (!r->body || !strstr(r->body, contains))) {
    printf("Response body doesn't contain '%s'\n", contains);
    if (r->body)
      printf("Body: %s\n", r->body);
    return 0;
  }
  return 1;
}

// Progress callback for download tests
static int download_progress(void *ctx, size_t total, size_t current) {
  int *called = ctx;
  (*called)++;
  return 0; // Continue
}

// ============================================================================
// Tests
// ============================================================================

static void test_simple_get(http_client_t *c) {
  TEST("Simple GET /ping");
  tests_run++;

  http_response_t *r = http_fetch(c, "GET", BASE_URL "/ping", NULL);
  if (check_response(r, 200, "pong")) {
    PASS();
  } else {
    FAIL("Unexpected response");
  }
  http_response_free(r);
}

static void test_post_json(http_client_t *c) {
  TEST("POST JSON to /json");
  tests_run++;

  http_request_t req = {.body = "{\"name\":\"test\",\"value\":42}",
                        .content_type = "application/json"};

  http_response_t *r = http_fetch(c, "POST", BASE_URL "/json", &req);
  if (check_response(r, 200, "\"ok\": true") ||
      check_response(r, 200, "\"ok\":true")) {
    PASS();
  } else {
    FAIL("JSON POST failed");
  }
  http_response_free(r);
}

static void test_post_echo(http_client_t *c) {
  TEST("POST to /echo with custom headers");
  tests_run++;

  const char *headers[] = {"X-Custom-Header: custom-value",
                           "X-Another: another-value", NULL};

  http_request_t req = {.body = "Hello, World!",
                        .content_type = "text/plain",
                        .headers = headers};

  http_response_t *r = http_fetch(c, "POST", BASE_URL "/echo", &req);
  if (check_response(r, 200, "Hello, World!") &&
      strstr(r->body, "X-Custom-Header") && strstr(r->body, "custom-value")) {
    PASS();
  } else {
    FAIL("Echo POST failed");
  }
  http_response_free(r);
}

static void test_basic_auth(http_client_t *c) {
  TEST("Basic authentication");
  tests_run++;

  // First test without auth (should fail)
  http_response_t *r = http_fetch(c, "GET", BASE_URL "/auth/basic", NULL);
  if (r && r->status != 401) {
    FAIL("Expected 401 without auth");
    http_response_free(r);
    return;
  }
  http_response_free(r);

  // Now with auth
  http_client_auth_basic(c, "testuser", "testpass");
  r = http_fetch(c, "GET", BASE_URL "/auth/basic", NULL);
  if (check_response(r, 200, "authenticated")) {
    PASS();
  } else {
    FAIL("Basic auth failed");
  }
  http_response_free(r);

  // Clear auth for subsequent tests (create new client)
}

static void test_bearer_auth(http_client_t *c) {
  TEST("Bearer token authentication");
  tests_run++;

  http_client_auth_bearer(c, "secret-token-123");
  http_response_t *r = http_fetch(c, "GET", BASE_URL "/auth/bearer", NULL);
  if (check_response(r, 200, "authenticated")) {
    PASS();
  } else {
    FAIL("Bearer auth failed");
  }
  http_response_free(r);
}

static void test_error_404(http_client_t *c) {
  TEST("HTTP 404 error handling");
  tests_run++;

  http_response_t *r = http_fetch(c, "GET", BASE_URL "/error/404", NULL);
  if (r && !r->error && r->status == 404) {
    PASS();
  } else {
    FAIL("404 handling failed");
  }
  http_response_free(r);
}

static void test_error_500(http_client_t *c) {
  TEST("HTTP 500 error handling");
  tests_run++;

  http_response_t *r = http_fetch(c, "GET", BASE_URL "/error/500", NULL);
  if (r && !r->error && r->status == 500) {
    PASS();
  } else {
    FAIL("500 handling failed");
  }
  http_response_free(r);
}

static void test_redirect(http_client_t *c) {
  TEST("HTTP redirect following");
  tests_run++;

  http_response_t *r = http_fetch(c, "GET", BASE_URL "/redirect", NULL);
  if (check_response(r, 200, "pong")) {
    PASS();
  } else {
    FAIL("Redirect not followed");
  }
  http_response_free(r);
}

static void test_delete_method(http_client_t *c) {
  TEST("DELETE method");
  tests_run++;

  http_response_t *r = http_fetch(c, "DELETE", BASE_URL "/resource/123", NULL);
  if (check_response(r, 200, "\"deleted\"") && strstr(r->body, "123")) {
    PASS();
  } else {
    FAIL("DELETE method failed");
  }
  http_response_free(r);
}

static void test_put_method(http_client_t *c) {
  TEST("PUT method");
  tests_run++;

  http_request_t req = {.body = "{\"update\":true}",
                        .content_type = "application/json"};

  http_response_t *r = http_fetch(c, "PUT", BASE_URL "/echo", &req);
  if (check_response(r, 200, "update")) {
    PASS();
  } else {
    FAIL("PUT method failed");
  }
  http_response_free(r);
}

static void test_download_small(http_client_t *c) {
  TEST("Download small file (1KB)");
  tests_run++;

  const char *path = "/tmp/http_e2e_small.bin";
  int progress_calls = 0;

  int ret = http_download(c, BASE_URL "/download/1024", path, download_progress,
                          &progress_calls);
  if (ret != 0) {
    FAIL("Download failed");
    return;
  }

  // Verify file size
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    FAIL("Cannot open downloaded file");
    return;
  }
  fseek(fp, 0, SEEK_END);
  long size = ftell(fp);
  fclose(fp);
  unlink(path);

  if (size == 1024) {
    PASS();
  } else {
    printf("Expected 1024 bytes, got %ld\n", size);
    FAIL("Wrong file size");
  }
}

static void test_download_large(http_client_t *c) {
  TEST("Download larger file (100KB) with progress");
  tests_run++;

  const char *path = "/tmp/http_e2e_large.bin";
  int progress_calls = 0;

  int ret = http_download(c, BASE_URL "/download/102400", path,
                          download_progress, &progress_calls);
  if (ret != 0) {
    FAIL("Download failed");
    return;
  }

  // Verify file size and pattern
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    FAIL("Cannot open downloaded file");
    return;
  }
  fseek(fp, 0, SEEK_END);
  long size = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  // Verify first few bytes match expected pattern
  unsigned char buf[256];
  size_t read = fread(buf, 1, sizeof(buf), fp);
  fclose(fp);
  unlink(path);

  int pattern_ok = 1;
  for (size_t i = 0; i < read; i++) {
    if (buf[i] != (i % 256)) {
      pattern_ok = 0;
      break;
    }
  }

  if (size == 102400 && pattern_ok && progress_calls > 0) {
    PASS();
  } else {
    printf("Size: %ld, Pattern OK: %d, Progress calls: %d\n", size, pattern_ok,
           progress_calls);
    FAIL("File verification failed");
  }
}

static void test_download_404(http_client_t *c) {
  TEST("Download 404 error (should fail, no partial file)");
  tests_run++;

  const char *path = "/tmp/http_e2e_404.bin";

  int ret = http_download(c, BASE_URL "/error/404", path, NULL, NULL);
  if (ret != 0) {
    // Should fail - verify no file was created
    FILE *fp = fopen(path, "rb");
    if (fp) {
      fclose(fp);
      unlink(path);
      FAIL("Partial file was created on 404");
    } else {
      PASS();
    }
  } else {
    unlink(path);
    FAIL("Download should have failed on 404");
  }
}

// Stream test - count bytes received
typedef struct {
  size_t bytes_received;
  int chunks;
} stream_ctx_t;

static size_t stream_counter(const void *data, size_t len, void *ctx) {
  (void)data;
  stream_ctx_t *sctx = ctx;
  sctx->bytes_received += len;
  sctx->chunks++;
  return len;
}

static void test_stream(http_client_t *c) {
  TEST("Stream download with custom callback");
  tests_run++;

  stream_ctx_t ctx = {0};
  int ret = http_stream(c, "GET", BASE_URL "/download/50000", NULL,
                        stream_counter, &ctx, NULL, NULL);

  if (ret == 0 && ctx.bytes_received == 50000 && ctx.chunks > 0) {
    PASS();
  } else {
    printf("ret=%d, bytes=%zu, chunks=%d\n", ret, ctx.bytes_received,
           ctx.chunks);
    FAIL("Stream failed");
  }
}

// Progress with stats for large file tests
typedef struct {
  int calls;
  size_t last_total;
  size_t last_current;
} progress_stats_t;

static int progress_with_stats(void *ctx, size_t total, size_t current) {
  progress_stats_t *stats = ctx;
  stats->calls++;
  stats->last_total = total;
  stats->last_current = current;
  // Print progress every 1MB
  if (stats->calls % 100 == 0) {
    printf("[%zu/%zu] ", current, total);
    fflush(stdout);
  }
  return 0;
}

static int verify_file_pattern(const char *path, size_t expected_size) {
  FILE *fp = fopen(path, "rb");
  if (!fp)
    return -1;

  fseek(fp, 0, SEEK_END);
  long size = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  if (size != (long)expected_size) {
    fclose(fp);
    printf("Size mismatch: expected %zu, got %ld\n", expected_size, size);
    return -2;
  }

  // Verify pattern at beginning, middle, and end
  unsigned char buf[256];
  const size_t positions[] = {0, expected_size / 2, expected_size - 256};

  for (int i = 0; i < 3; i++) {
    fseek(fp, positions[i], SEEK_SET);
    size_t to_read = (positions[i] + 256 > expected_size)
                         ? expected_size - positions[i]
                         : 256;
    size_t nread = fread(buf, 1, to_read, fp);

    for (size_t j = 0; j < nread; j++) {
      unsigned char expected = (positions[i] + j) % 256;
      if (buf[j] != expected) {
        fclose(fp);
        printf("Pattern mismatch at offset %zu: expected %u, got %u\n",
               positions[i] + j, expected, buf[j]);
        return -3;
      }
    }
  }

  fclose(fp);
  return 0;
}

static void test_download_1mb(http_client_t *c) {
  TEST("Download 1MB file");
  tests_run++;

  const char *path = "/tmp/http_e2e_1mb.bin";
  const size_t size = 1024 * 1024; // 1MB
  progress_stats_t stats = {0};

  int ret = http_download(c, BASE_URL "/download/1048576", path,
                          progress_with_stats, &stats);
  if (ret != 0) {
    FAIL("Download failed");
    return;
  }

  int verify = verify_file_pattern(path, size);
  unlink(path);

  if (verify == 0 && stats.calls > 0) {
    printf("(%d progress calls) ", stats.calls);
    PASS();
  } else {
    printf("verify=%d, calls=%d\n", verify, stats.calls);
    FAIL("File verification failed");
  }
}

static void test_download_10mb(http_client_t *c) {
  TEST("Download 10MB file");
  tests_run++;

  const char *path = "/tmp/http_e2e_10mb.bin";
  const size_t size = 10 * 1024 * 1024; // 10MB
  progress_stats_t stats = {0};

  printf("\n  ");
  int ret = http_download(c, BASE_URL "/download/10485760", path,
                          progress_with_stats, &stats);
  printf("\n  ");

  if (ret != 0) {
    FAIL("Download failed");
    return;
  }

  int verify = verify_file_pattern(path, size);
  unlink(path);

  if (verify == 0 && stats.calls > 0) {
    printf("(%d progress calls) ", stats.calls);
    PASS();
  } else {
    printf("verify=%d, calls=%d\n", verify, stats.calls);
    FAIL("File verification failed");
  }
}

static void test_stream_large(http_client_t *c) {
  TEST("Stream 5MB to memory");
  tests_run++;

  const size_t size = 5 * 1024 * 1024; // 5MB
  stream_ctx_t ctx = {0};

  int ret = http_stream(c, "GET", BASE_URL "/download/5242880", NULL,
                        stream_counter, &ctx, NULL, NULL);

  if (ret == 0 && ctx.bytes_received == size) {
    printf("(%d chunks) ", ctx.chunks);
    PASS();
  } else {
    printf("ret=%d, bytes=%zu (expected %zu), chunks=%d\n", ret,
           ctx.bytes_received, size, ctx.chunks);
    FAIL("Stream failed");
  }
}

static void test_timeout(http_client_t *c) {
  TEST("Request timeout");
  tests_run++;

  // Create client with short timeout
  http_opts_t opts = {.timeout_ms = 1000, // 1 second timeout
                      .connect_timeout_ms = 1000};
  http_client_t *tc = http_client_new(&opts);
  if (!tc) {
    FAIL("Cannot create timeout client");
    return;
  }

  // Request that takes 5 seconds should timeout
  http_response_t *r = http_fetch(tc, "GET", BASE_URL "/slow?delay=5", NULL);
  if (r && r->error && strstr(r->error, "imeout")) {
    PASS();
  } else {
    if (r && r->error)
      printf("Error: %s\n", r->error);
    if (r)
      printf("Status: %d\n", r->status);
    FAIL("Should have timed out");
  }
  http_response_free(r);
  http_client_free(tc);
}

static void test_urlencode(void) {
  TEST("URL encoding");
  tests_run++;

  char *encoded = http_urlencode("hello world&foo=bar");
  if (encoded && strcmp(encoded, "hello%20world%26foo%3Dbar") == 0) {
    PASS();
  } else {
    if (encoded)
      printf("Got: %s\n", encoded);
    FAIL("URL encoding mismatch");
  }
  free(encoded);
}

static void test_headers_echo(http_client_t *c) {
  TEST("Custom headers in request");
  tests_run++;

  http_response_t *r = http_fetch(c, "GET", BASE_URL "/headers", NULL);
  if (check_response(r, 200, "pressured")) {
    PASS();
  } else {
    FAIL("User-Agent header not found");
  }
  http_response_free(r);
}

// ============================================================================
// Main
// ============================================================================

int main(void) {
  printf("\n=== HTTP Client E2E Tests ===\n");
  printf("Server: %s\n\n", BASE_URL);

  // Check if server is running
  http_client_t *c = http_client_new(NULL);
  if (!c) {
    fprintf(stderr, "Failed to create HTTP client\n");
    return 1;
  }

  http_response_t *r = http_fetch(c, "GET", BASE_URL "/ping", NULL);
  if (!r || r->error || r->status != 200) {
    fprintf(stderr, "\n\033[31mERROR: Test server not running!\033[0m\n");
    fprintf(stderr, "Start it with: python3 tests/e2e_server.py 8765\n\n");
    http_response_free(r);
    http_client_free(c);
    return 1;
  }
  http_response_free(r);
  printf("Server is running. Starting tests...\n\n");

  // Run tests
  test_simple_get(c);
  test_post_json(c);
  test_post_echo(c);
  test_error_404(c);
  test_error_500(c);
  test_redirect(c);
  test_delete_method(c);
  test_put_method(c);
  test_headers_echo(c);
  test_urlencode();
  test_download_small(c);
  test_download_large(c);
  test_download_404(c);
  test_stream(c);

  // Large file tests
  printf("\n--- Large File Tests ---\n");
  test_download_1mb(c);
  test_download_10mb(c);
  test_stream_large(c);
  printf("------------------------\n\n");

  // Auth tests need separate client instances
  http_client_free(c);

  c = http_client_new(NULL);
  test_basic_auth(c);
  http_client_free(c);

  c = http_client_new(NULL);
  test_bearer_auth(c);
  http_client_free(c);

  // Timeout test
  test_timeout(NULL);

  // Results
  printf("\n=== Results: %d/%d tests passed ===\n\n", tests_run - failures,
         tests_run);

  return failures > 0 ? 1 : 0;
}
