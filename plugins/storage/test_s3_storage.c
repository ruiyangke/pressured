/*
 * S3 Storage plugin test using LocalStack - tests streaming interface
 *
 * Prerequisites:
 *   docker run -d --name localstack -p 4566:4566 -e SERVICES=s3
 * localstack/localstack
 *   AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
 * AWS_DEFAULT_REGION=us-east-1 \ aws --endpoint-url=http://localhost:4566 s3 mb
 * s3://pressured-test
 */

#include "log.h"
#include "plugin_manager.h"
#include "service_registry.h"
#include "storage.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Path to built plugin
#define S3_PLUGIN_PATH "./plugins/s3-storage.so"

// LocalStack configuration
#define LOCALSTACK_ENDPOINT "http://localhost:4566"
#define TEST_BUCKET "pressured-test"
#define TEST_REGION "us-east-1"
#define TEST_ACCESS_KEY "test"
#define TEST_SECRET_KEY "test"

// JSON config for the S3 plugin
#define S3_CONFIG_JSON                                                         \
  "{"                                                                          \
  "  \"storage\": {"                                                           \
  "    \"backend\": \"s3\","                                                   \
  "    \"s3\": {"                                                              \
  "      \"bucket\": \"" TEST_BUCKET "\","                                     \
  "      \"region\": \"" TEST_REGION "\","                                     \
  "      \"prefix\": \"\","                                                    \
  "      \"endpoint\": \"" LOCALSTACK_ENDPOINT "\""                            \
  "    }"                                                                      \
  "  }"                                                                        \
  "}"

static int check_localstack_available(void) {
  // Simple check if LocalStack is running
  int rc = system(
      "curl -s http://localhost:4566/_localstack/health > /dev/null 2>&1");
  return rc == 0;
}

static void test_streaming_write_read(storage_t *s) {
  printf("  test_streaming_write_read: ");

  const char *key = "test/stream_data.txt";
  const char *data = "Hello, S3 streaming storage!";
  size_t len = strlen(data);

  // Write using streaming API
  storage_file_t *f = s->open(s, key, STORAGE_MODE_WRITE);
  if (!f) {
    printf("FAILED - open for write returned NULL\n");
    return;
  }

  int64_t written = s->write(f, data, len);
  if (written != (int64_t)len) {
    printf("FAILED - write returned %ld, expected %zu\n", written, len);
    s->close(f);
    return;
  }

  int rc = s->close(f);
  if (rc != STORAGE_OK) {
    printf("FAILED - close after write returned %d\n", rc);
    return;
  }

  // Read back using streaming API
  f = s->open(s, key, STORAGE_MODE_READ);
  if (!f) {
    printf("FAILED - open for read returned NULL\n");
    return;
  }

  char buf[256] = {0};
  int64_t n = s->read(f, buf, sizeof(buf));
  if (n != (int64_t)len) {
    printf("FAILED - read returned %ld, expected %zu\n", n, len);
    s->close(f);
    return;
  }
  assert(memcmp(buf, data, len) == 0);

  rc = s->close(f);
  assert(rc == STORAGE_OK);

  // Cleanup
  rc = s->remove(s, key);
  assert(rc == STORAGE_OK);

  printf("OK\n");
}

static void test_exists(storage_t *s) {
  printf("  test_exists: ");

  const char *key = "test/exists_file.txt";
  const char *data = "test";

  // Should not exist initially
  int exists = s->exists(s, key);
  assert(exists == 0);

  // Write file
  storage_file_t *f = s->open(s, key, STORAGE_MODE_WRITE);
  assert(f != NULL);
  s->write(f, data, strlen(data));
  s->close(f);

  // Should exist now
  exists = s->exists(s, key);
  assert(exists == 1);

  // Cleanup
  s->remove(s, key);

  // Should not exist after removal
  exists = s->exists(s, key);
  assert(exists == 0);

  printf("OK\n");
}

static void test_large_streaming(storage_t *s) {
  printf("  test_large_streaming: ");

  const char *key = "test/large_file.bin";
  const size_t chunk_size = 64 * 1024;  // 64KB chunks
  const size_t total_size = 256 * 1024; // 256KB total

  // Create test data with pattern
  char *chunk = malloc(chunk_size);
  assert(chunk != NULL);

  // Write in chunks
  storage_file_t *f = s->open(s, key, STORAGE_MODE_WRITE);
  if (!f) {
    printf("FAILED - open for write returned NULL\n");
    free(chunk);
    return;
  }

  size_t written_total = 0;
  int chunk_num = 0;
  while (written_total < total_size) {
    // Fill chunk with pattern based on chunk number
    memset(chunk, 'A' + (chunk_num % 26), chunk_size);
    int64_t n = s->write(f, chunk, chunk_size);
    if (n != (int64_t)chunk_size) {
      printf("FAILED - write chunk %d returned %ld\n", chunk_num, n);
      s->close(f);
      free(chunk);
      return;
    }
    written_total += n;
    chunk_num++;
  }

  int rc = s->close(f);
  if (rc != STORAGE_OK) {
    printf("FAILED - close returned %d\n", rc);
    free(chunk);
    return;
  }

  // Read back and verify
  f = s->open(s, key, STORAGE_MODE_READ);
  if (!f) {
    printf("FAILED - open for read returned NULL\n");
    free(chunk);
    return;
  }

  size_t read_total = 0;
  chunk_num = 0;
  while (1) {
    int64_t n = s->read(f, chunk, chunk_size);
    if (n == 0)
      break; // EOF
    if (n < 0) {
      printf("FAILED - read returned error %ld\n", n);
      s->close(f);
      free(chunk);
      return;
    }
    // Verify pattern
    char expected = 'A' + (chunk_num % 26);
    for (int64_t i = 0; i < n; i++) {
      if (chunk[i] != expected) {
        printf("FAILED - data mismatch at offset %zu\n",
               (size_t)(read_total + i));
        s->close(f);
        free(chunk);
        return;
      }
    }
    read_total += n;
    chunk_num++;
  }

  if (read_total != total_size) {
    printf("FAILED - read %zu bytes, expected %zu\n", read_total, total_size);
    s->close(f);
    free(chunk);
    return;
  }

  rc = s->close(f);
  assert(rc == STORAGE_OK);

  free(chunk);

  // Cleanup
  s->remove(s, key);

  printf("OK\n");
}

static void test_not_found(storage_t *s) {
  printf("  test_not_found: ");

  // Opening non-existent file for read should fail
  const storage_file_t *f =
      s->open(s, "nonexistent/file.txt", STORAGE_MODE_READ);
  assert(f == NULL);

  printf("OK\n");
}

int main(void) {
  log_init(LOG_DEBUG);

  printf("test_s3_storage: starting\n");

  // Check if LocalStack is available
  if (!check_localstack_available()) {
    printf("  SKIP: LocalStack not available at %s\n", LOCALSTACK_ENDPOINT);
    printf("  Run: docker run -d --name localstack -p 4566:4566 -e SERVICES=s3 "
           "localstack/localstack\n");
    printf("test_s3_storage: SKIPPED\n");
    return 0; // Don't fail - just skip
  }

  // Set AWS credentials for LocalStack
  // Note: bucket/region/endpoint now come from JSON config, not env vars
  setenv("AWS_ACCESS_KEY_ID", TEST_ACCESS_KEY, 1);
  setenv("AWS_SECRET_ACCESS_KEY", TEST_SECRET_KEY, 1);
  setenv("AWS_DEFAULT_REGION", TEST_REGION, 1);

  // Create service registry and plugin manager
  service_registry_t *sr = service_registry_new();
  assert(sr != NULL);

  plugin_manager_t *pm = plugin_manager_new(sr);
  assert(pm != NULL);

  int rc = plugin_manager_load(pm, S3_PLUGIN_PATH, S3_CONFIG_JSON);
  if (rc != 0) {
    printf("  ERROR: failed to load plugin from %s\n", S3_PLUGIN_PATH);
    printf("  Make sure to run from build directory\n");
    plugin_manager_free(pm);
    service_registry_free(sr);
    return 1;
  }

  // Initialize all services
  service_registry_init_all(sr);

  // Get storage via service registry
  service_ref_t ref = service_registry_acquire(sr, "storage");
  if (!service_ref_valid(&ref)) {
    printf("  ERROR: no storage service registered\n");
    plugin_manager_free(pm);
    service_registry_free(sr);
    return 1;
  }
  storage_t *s = (storage_t *)ref.instance;

  // Run tests
  test_streaming_write_read(s);
  test_exists(s);
  test_large_streaming(s);
  test_not_found(s);

  // Release storage reference
  service_ref_release(&ref);

  // Cleanup - service registry must be freed before plugin manager
  service_registry_free(sr);
  plugin_manager_free(pm);

  printf("test_s3_storage: PASSED\n");
  return 0;
}
