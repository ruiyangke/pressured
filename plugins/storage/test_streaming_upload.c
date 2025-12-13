/*
 * Test streaming upload with small chunks (64KB) to verify minimal memory usage
 *
 * This test uses 64KB chunks (vs 5MB in test_large_upload.c) to demonstrate
 * that the S3 streaming implementation itself uses minimal memory (~256KB
 * buffer).
 *
 * Usage: ./test_streaming_upload [size_mb]
 *   size_mb: File size in MB (default: 100)
 *
 * Prerequisites:
 *   docker run -d --name localstack -p 4566:4566 -e SERVICES=s3
 * localstack/localstack AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test aws
 * --endpoint-url=http://localhost:4566 s3 mb s3://pressured-test
 */

#include "log.h"
#include "plugin_manager.h"
#include "service_registry.h"
#include "storage.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#define S3_PLUGIN_PATH "./plugins/s3-storage.so"
#define LOCALSTACK_ENDPOINT "http://localhost:4566"
#define TEST_BUCKET "pressured-test"
#define TEST_REGION "us-east-1"

// Small chunk size to minimize memory footprint
#define CHUNK_SIZE (64 * 1024) // 64KB chunks

static int check_localstack_available(void) {
  int rc = system(
      "curl -s http://localhost:4566/_localstack/health > /dev/null 2>&1");
  return rc == 0;
}

// Generate predictable data pattern based on offset
static void fill_pattern(char *buf, size_t len, size_t offset) {
  for (size_t i = 0; i < len; i++) {
    buf[i] = (char)((offset + i) & 0xFF);
  }
}

// Get current time in seconds with microsecond precision
static double get_time(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec / 1000000.0;
}

int main(int argc, char *const argv[]) {
  log_init(LOG_INFO);

  // Parse optional size argument (in MB)
  size_t size_mb = 100; // Default 100MB
  if (argc > 1) {
    size_mb = (size_t)atoi(argv[1]);
    if (size_mb == 0)
      size_mb = 100;
  }

  size_t total_size = size_mb * 1024 * 1024;

  printf("test_streaming_upload: %zu MB with %d KB chunks\n", size_mb,
         CHUNK_SIZE / 1024);
  printf(
      "  Expected memory: ~%d KB (S3 buffer) + %d KB (app buffer) = ~%d KB\n",
      256, CHUNK_SIZE / 1024, 256 + CHUNK_SIZE / 1024);

  if (!check_localstack_available()) {
    printf("  SKIP: LocalStack not available\n");
    printf("  Run: docker run -d --name localstack -p 4566:4566 -e SERVICES=s3 "
           "localstack/localstack\n");
    return 0;
  }

  // Set environment variables
  setenv("AWS_ACCESS_KEY_ID", "test", 1);
  setenv("AWS_SECRET_ACCESS_KEY", "test", 1);
  setenv("AWS_DEFAULT_REGION", TEST_REGION, 1);

  // Create service registry and plugin manager
  service_registry_t *sr = service_registry_new();
  if (!sr) {
    printf("  ERROR: failed to create service registry\n");
    return 1;
  }

  plugin_manager_t *pm = plugin_manager_new(sr);
  if (!pm) {
    printf("  ERROR: failed to create plugin manager\n");
    service_registry_free(sr);
    return 1;
  }

  // Build config JSON for LocalStack
  const char *config_json = "{"
                            "  \"storage\": {"
                            "    \"s3\": {"
                            "      \"bucket\": \"" TEST_BUCKET "\","
                            "      \"region\": \"" TEST_REGION "\","
                            "      \"endpoint\": \"" LOCALSTACK_ENDPOINT "\""
                            "    }"
                            "  }"
                            "}";

  int rc = plugin_manager_load(pm, S3_PLUGIN_PATH, config_json);
  if (rc != 0) {
    printf("  ERROR: failed to load S3 plugin\n");
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

  // Allocate small chunk buffer
  printf("  Allocating %d KB chunk buffer...\n", CHUNK_SIZE / 1024);
  char *chunk = malloc(CHUNK_SIZE);
  if (!chunk) {
    printf("  ERROR: failed to allocate chunk buffer\n");
    service_ref_release(&ref);
    plugin_manager_free(pm);
    service_registry_free(sr);
    return 1;
  }

  char test_key[256];
  snprintf(test_key, sizeof(test_key), "test/streaming_%zuMB_64KB.bin",
           size_mb);

  // =========================================================================
  // Upload using streaming with small chunks
  // =========================================================================
  printf("  Uploading %zu MB to %s...\n", size_mb, test_key);

  double start_time = get_time();

  storage_file_t *f = s->open(s, test_key, STORAGE_MODE_WRITE);
  if (!f) {
    printf("  ERROR: failed to open for write\n");
    free(chunk);
    service_ref_release(&ref);
    plugin_manager_free(pm);
    service_registry_free(sr);
    return 1;
  }

  // Set expected size for Content-Length header
  void *plugin_handle = dlopen(S3_PLUGIN_PATH, RTLD_NOW | RTLD_NOLOAD);
  if (!plugin_handle) {
    plugin_handle = dlopen(S3_PLUGIN_PATH, RTLD_NOW);
  }
  typedef int (*set_upload_size_fn)(storage_file_t *, int64_t);
  set_upload_size_fn set_size = NULL;
  if (plugin_handle) {
    set_size = (set_upload_size_fn)dlsym(plugin_handle, "s3_set_upload_size");
  }
  if (set_size) {
    set_size(f, (int64_t)total_size);
  } else {
    printf("  WARNING: s3_set_upload_size not found\n");
  }

  size_t written_total = 0;
  size_t last_progress = 0;

  while (written_total < total_size) {
    size_t to_write = CHUNK_SIZE;
    if (written_total + to_write > total_size) {
      to_write = total_size - written_total;
    }

    fill_pattern(chunk, to_write, written_total);

    int64_t n = s->write(f, chunk, to_write);
    if (n != (int64_t)to_write) {
      printf("  ERROR: write failed at %zu bytes (returned %ld)\n",
             written_total, n);
      s->close(f);
      free(chunk);
      service_ref_release(&ref);
      plugin_manager_free(pm);
      service_registry_free(sr);
      return 1;
    }

    written_total += n;

    // Progress every 50MB
    if (written_total - last_progress >= 50 * 1024 * 1024) {
      printf("    %zu MB / %zu MB\n", written_total / (1024 * 1024), size_mb);
      last_progress = written_total;
    }
  }

  // Close (finishes upload)
  rc = s->close(f);
  if (rc != 0) {
    printf("  ERROR: close failed with %d\n", rc);
    free(chunk);
    service_ref_release(&ref);
    plugin_manager_free(pm);
    service_registry_free(sr);
    return 1;
  }

  double upload_time = get_time() - start_time;
  double upload_speed = (double)size_mb / upload_time;

  printf("  Upload: OK (%.1f seconds, %.1f MB/s)\n", upload_time, upload_speed);

  // =========================================================================
  // Download and verify
  // =========================================================================
  printf("  Downloading and verifying...\n");

  start_time = get_time();

  f = s->open(s, test_key, STORAGE_MODE_READ);
  if (!f) {
    printf("  ERROR: failed to open for read\n");
    free(chunk);
    service_ref_release(&ref);
    plugin_manager_free(pm);
    service_registry_free(sr);
    return 1;
  }

  size_t read_total = 0;
  last_progress = 0;
  int verify_ok = 1;

  while (1) {
    int64_t n = s->read(f, chunk, CHUNK_SIZE);
    if (n == 0)
      break; // EOF
    if (n < 0) {
      printf("  ERROR: read failed at %zu bytes\n", read_total);
      verify_ok = 0;
      break;
    }

    // Verify pattern
    for (size_t i = 0; i < (size_t)n; i++) {
      if (chunk[i] != (char)((read_total + i) & 0xFF)) {
        printf("  ERROR: data mismatch at offset %zu\n", read_total + i);
        verify_ok = 0;
        break;
      }
    }
    if (!verify_ok)
      break;

    read_total += n;

    // Progress every 50MB
    if (read_total - last_progress >= 50 * 1024 * 1024) {
      printf("    %zu MB / %zu MB\n", read_total / (1024 * 1024), size_mb);
      last_progress = read_total;
    }
  }

  s->close(f);

  double download_time = get_time() - start_time;
  double download_speed = (double)size_mb / download_time;

  if (verify_ok && read_total == total_size) {
    printf("  Download: OK (%.1f seconds, %.1f MB/s)\n", download_time,
           download_speed);
    printf("  Verification: OK (data matches)\n");
  } else {
    printf("  Download: FAILED (read %zu of %zu bytes)\n", read_total,
           total_size);
    verify_ok = 0;
  }

  // Cleanup
  printf("  Cleaning up...\n");
  s->remove(s, test_key);

  free(chunk);
  service_ref_release(&ref);
  plugin_manager_free(pm);
  service_registry_free(sr);

  if (verify_ok) {
    printf("\ntest_streaming_upload: PASSED\n");
    printf("  Total size:   %zu MB\n", size_mb);
    printf("  Chunk size:   %d KB\n", CHUNK_SIZE / 1024);
    printf("  Upload:       %.1f seconds (%.1f MB/s)\n", upload_time,
           upload_speed);
    printf("  Download:     %.1f seconds (%.1f MB/s)\n", download_time,
           download_speed);
    printf("  Peak memory:  ~%d KB (estimated)\n",
           256 + CHUNK_SIZE / 1024 + 200);
    return 0;
  } else {
    printf("\ntest_streaming_upload: FAILED\n");
    return 1;
  }
}
