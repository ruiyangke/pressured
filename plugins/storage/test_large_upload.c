/*
 * Large file upload test using streaming interface
 *
 * Tests the streaming storage interface with large files.
 * Uses chunked writes to minimize memory footprint.
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
#include "storage.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#define S3_PLUGIN_PATH "./plugins/storage_s3.so"
#define LOCALSTACK_ENDPOINT "http://localhost:4566"
#define TEST_BUCKET "pressured-test"
#define TEST_REGION "us-east-1"

// Chunk size for streaming (5MB for S3 multipart minimum)
#define CHUNK_SIZE ((size_t)(5 * 1024 * 1024))

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

// Verify data pattern
static int verify_pattern(const char *buf, size_t len, size_t offset) {
  for (size_t i = 0; i < len; i++) {
    if (buf[i] != (char)((offset + i) & 0xFF)) {
      return 0;
    }
  }
  return 1;
}

// Get current time in seconds with microsecond precision
static double get_time(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec / 1000000.0;
}

int main(int argc, const char *argv[]) {
  log_init(LOG_INFO);

  // Parse optional size argument (in MB)
  size_t size_mb = 100; // Default 100MB for streaming test
  if (argc > 1) {
    size_mb = (size_t)atoi(argv[1]);
    if (size_mb == 0)
      size_mb = 100;
  }

  size_t total_size = size_mb * 1024 * 1024;

  printf("test_large_upload: %zu MB streaming upload test\n", size_mb);

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
  setenv("PRESSURED_S3_BUCKET", TEST_BUCKET, 1);
  setenv("PRESSURED_S3_REGION", TEST_REGION, 1);
  setenv("PRESSURED_S3_ENDPOINT", LOCALSTACK_ENDPOINT, 1);

  // Load plugin using plugin manager
  plugin_manager_t *pm = plugin_manager_new();
  if (!pm) {
    printf("  ERROR: failed to create plugin manager\n");
    return 1;
  }

  int rc = plugin_manager_load(pm, S3_PLUGIN_PATH, NULL);
  if (rc != 0) {
    printf("  ERROR: failed to load S3 plugin\n");
    plugin_manager_free(pm);
    return 1;
  }

  // Get storage interface - handle embeds vtable
  storage_t *s =
      (storage_t *)plugin_manager_get_handle(pm, PRESSURED_PLUGIN_TYPE_STORAGE);
  if (!s) {
    printf("  ERROR: failed to get storage interface\n");
    plugin_manager_free(pm);
    return 1;
  }

  // Allocate chunk buffer (not the full file!)
  printf("  Allocating %zu MB chunk buffer...\n", CHUNK_SIZE / (1024 * 1024));
  char *chunk = malloc(CHUNK_SIZE);
  if (!chunk) {
    printf("  ERROR: failed to allocate chunk buffer\n");
    plugin_manager_free(pm);
    return 1;
  }

  char test_key[256];
  snprintf(test_key, sizeof(test_key), "test/large_%zuMB.bin", size_mb);

  // =========================================================================
  // Upload using streaming
  // =========================================================================
  printf("  Uploading %zu MB to %s using streaming...\n", size_mb, test_key);

  double start_time = get_time();

  storage_file_t *f = s->open(s, test_key, STORAGE_MODE_WRITE);
  if (!f) {
    printf("  ERROR: failed to open for write\n");
    free(chunk);
    plugin_manager_free(pm);
    return 1;
  }

  size_t written_total = 0;
  size_t chunk_num = 0;
  while (written_total < total_size) {
    size_t to_write = CHUNK_SIZE;
    if (written_total + to_write > total_size) {
      to_write = total_size - written_total;
    }

    // Fill chunk with predictable pattern
    fill_pattern(chunk, to_write, written_total);

    int64_t n = s->write(f, chunk, to_write);
    if (n != (int64_t)to_write) {
      printf("  ERROR: write chunk %zu failed (returned %ld)\n", chunk_num, n);
      s->close(f);
      free(chunk);
      plugin_manager_free(pm);
      return 1;
    }

    written_total += n;
    chunk_num++;

    // Progress
    if (chunk_num % 10 == 0) {
      printf("    %zu MB / %zu MB\n", written_total / (1024 * 1024), size_mb);
    }
  }

  rc = s->close(f);
  if (rc != STORAGE_OK) {
    printf("  ERROR: close failed with %d\n", rc);
    free(chunk);
    plugin_manager_free(pm);
    return 1;
  }

  double end_time = get_time();
  double upload_time = end_time - start_time;
  double upload_mbps = (total_size / (1024.0 * 1024.0)) / upload_time;

  printf("  Upload: OK (%.1f seconds, %.1f MB/s)\n", upload_time, upload_mbps);

  // =========================================================================
  // Download and verify using streaming
  // =========================================================================
  printf("  Downloading and verifying...\n");

  start_time = get_time();

  f = s->open(s, test_key, STORAGE_MODE_READ);
  if (!f) {
    printf("  ERROR: failed to open for read\n");
    free(chunk);
    plugin_manager_free(pm);
    return 1;
  }

  size_t read_total = 0;
  chunk_num = 0;
  while (1) {
    int64_t n = s->read(f, chunk, CHUNK_SIZE);
    if (n == 0)
      break; // EOF
    if (n < 0) {
      printf("  ERROR: read chunk %zu failed (returned %ld)\n", chunk_num, n);
      s->close(f);
      free(chunk);
      plugin_manager_free(pm);
      return 1;
    }

    // Verify data pattern
    if (!verify_pattern(chunk, n, read_total)) {
      printf("  ERROR: data mismatch at offset %zu\n", read_total);
      s->close(f);
      free(chunk);
      plugin_manager_free(pm);
      return 1;
    }

    read_total += n;
    chunk_num++;

    // Progress
    if (chunk_num % 10 == 0) {
      printf("    %zu MB / %zu MB\n", read_total / (1024 * 1024), size_mb);
    }
  }

  rc = s->close(f);
  if (rc != STORAGE_OK) {
    printf("  ERROR: close failed with %d\n", rc);
    free(chunk);
    plugin_manager_free(pm);
    return 1;
  }

  if (read_total != total_size) {
    printf("  ERROR: read %zu bytes, expected %zu\n", read_total, total_size);
    free(chunk);
    plugin_manager_free(pm);
    return 1;
  }

  end_time = get_time();
  double download_time = end_time - start_time;
  double download_mbps = (total_size / (1024.0 * 1024.0)) / download_time;

  printf("  Download: OK (%.1f seconds, %.1f MB/s)\n", download_time,
         download_mbps);
  printf("  Verification: OK (data matches)\n");

  // Cleanup
  printf("  Cleaning up...\n");
  s->remove(s, test_key);

  free(chunk);
  plugin_manager_free(pm);

  printf("\ntest_large_upload: PASSED\n");
  printf("  Total size:   %zu MB\n", size_mb);
  printf("  Chunk size:   %zu MB\n", CHUNK_SIZE / (1024 * 1024));
  printf("  Upload:       %.1f seconds (%.1f MB/s)\n", upload_time,
         upload_mbps);
  printf("  Download:     %.1f seconds (%.1f MB/s)\n", download_time,
         download_mbps);
  printf("  Peak memory:  ~%zu MB (chunk buffer only)\n",
         CHUNK_SIZE / (1024 * 1024));

  return 0;
}
