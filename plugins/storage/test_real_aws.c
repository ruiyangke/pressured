/*
 * Real AWS S3 streaming test
 *
 * Uses AWS credentials from environment (supports SSO via export).
 * Tests streaming upload/download to real S3.
 *
 * Usage: ./test_real_aws <bucket> <region> [size_mb]
 *
 * Prerequisites:
 *   eval "$(aws configure export-credentials --profile <profile> --format env)"
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
#define CHUNK_SIZE (64 * 1024) // 64KB chunks

static void fill_pattern(char *buf, size_t len, size_t offset) {
  for (size_t i = 0; i < len; i++) {
    buf[i] = (char)((offset + i) & 0xFF);
  }
}

static int verify_pattern(const char *buf, size_t len, size_t offset) {
  for (size_t i = 0; i < len; i++) {
    if (buf[i] != (char)((offset + i) & 0xFF)) {
      return 0;
    }
  }
  return 1;
}

static double get_time(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec / 1000000.0;
}

int main(int argc, char *const argv[]) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <bucket> <region> [size_mb]\n", argv[0]);
    fprintf(stderr, "\nExample:\n");
    fprintf(stderr, "  eval \"$(aws configure export-credentials --profile "
                    "workload-dev --format env)\"\n");
    fprintf(stderr, "  %s my-bucket us-west-2 10\n", argv[0]);
    return 1;
  }

  const char *bucket = argv[1];
  const char *region = argv[2];
  size_t size_mb = argc > 3 ? (size_t)atoi(argv[3]) : 10;
  size_t total_size = size_mb * 1024 * 1024;

  log_init(LOG_INFO);

  printf("=== Real AWS S3 Streaming Test ===\n");
  printf("  Bucket: %s\n", bucket);
  printf("  Region: %s\n", region);
  printf("  Size:   %zu MB\n", size_mb);

  // Check credentials
  const char *access_key = getenv("AWS_ACCESS_KEY_ID");
  const char *secret_key = getenv("AWS_SECRET_ACCESS_KEY");
  if (!access_key || !secret_key) {
    printf("\nERROR: AWS credentials not set in environment\n");
    printf("Run: eval \"$(aws configure export-credentials --profile <profile> "
           "--format env)\"\n");
    return 1;
  }
  printf("  Key:    %.12s...\n", access_key);
  if (getenv("AWS_SESSION_TOKEN")) {
    printf("  Token:  (session token present)\n");
  }

  // Create service registry and plugin manager
  service_registry_t *sr = service_registry_new();
  if (!sr) {
    printf("ERROR: failed to create service registry\n");
    return 1;
  }

  plugin_manager_t *pm = plugin_manager_new(sr);
  if (!pm) {
    printf("ERROR: failed to create plugin manager\n");
    service_registry_free(sr);
    return 1;
  }

  // Build config JSON (no endpoint = real AWS)
  char config_json[1024];
  snprintf(config_json, sizeof(config_json),
           "{"
           "  \"storage\": {"
           "    \"s3\": {"
           "      \"bucket\": \"%s\","
           "      \"region\": \"%s\""
           "    }"
           "  }"
           "}",
           bucket, region);

  int rc = plugin_manager_load(pm, S3_PLUGIN_PATH, config_json);
  if (rc != 0) {
    printf("ERROR: failed to load S3 plugin\n");
    plugin_manager_free(pm);
    service_registry_free(sr);
    return 1;
  }

  service_registry_init_all(sr);

  service_ref_t ref = service_registry_acquire(sr, "storage");
  if (!service_ref_valid(&ref)) {
    printf("ERROR: no storage service registered\n");
    plugin_manager_free(pm);
    service_registry_free(sr);
    return 1;
  }
  storage_t *s = (storage_t *)ref.instance;

  // Allocate chunk buffer
  printf("  Chunk:  %d KB\n", CHUNK_SIZE / 1024);
  char *chunk = malloc(CHUNK_SIZE);
  if (!chunk) {
    printf("ERROR: failed to allocate chunk buffer\n");
    service_ref_release(&ref);
    plugin_manager_free(pm);
    service_registry_free(sr);
    return 1;
  }

  char test_key[256];
  snprintf(test_key, sizeof(test_key), "test/pressured_streaming_%zuMB.bin",
           size_mb);

  // =========================================================================
  // Upload
  // =========================================================================
  printf("\n=== UPLOAD ===\n");
  printf("  Key: %s\n", test_key);

  double start_time = get_time();

  storage_file_t *f = s->open(s, test_key, STORAGE_MODE_WRITE);
  if (!f) {
    printf("ERROR: failed to open for write\n");
    free(chunk);
    service_ref_release(&ref);
    plugin_manager_free(pm);
    service_registry_free(sr);
    return 1;
  }

  // Set expected size
  void *plugin_handle = dlopen(S3_PLUGIN_PATH, RTLD_NOW | RTLD_NOLOAD);
  if (!plugin_handle)
    plugin_handle = dlopen(S3_PLUGIN_PATH, RTLD_NOW);
  typedef int (*set_upload_size_fn)(storage_file_t *, int64_t);
  set_upload_size_fn set_size = NULL;
  if (plugin_handle) {
    set_size = (set_upload_size_fn)dlsym(plugin_handle, "s3_set_upload_size");
  }
  if (set_size) {
    set_size(f, (int64_t)total_size);
    printf("  Size set: %zu bytes\n", total_size);
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
      printf("\nERROR: write failed at %zu bytes (returned %ld)\n",
             written_total, n);
      s->close(f);
      free(chunk);
      service_ref_release(&ref);
      plugin_manager_free(pm);
      service_registry_free(sr);
      return 1;
    }

    written_total += n;

    if (written_total - last_progress >= 1024 * 1024) {
      printf("  Progress: %zu MB / %zu MB\r", written_total / (1024 * 1024),
             size_mb);
      fflush(stdout);
      last_progress = written_total;
    }
  }

  rc = s->close(f);
  if (rc != 0) {
    printf("\nERROR: close failed with %d\n", rc);
    free(chunk);
    service_ref_release(&ref);
    plugin_manager_free(pm);
    service_registry_free(sr);
    return 1;
  }

  double upload_time = get_time() - start_time;
  printf("\n  Upload: OK (%.1f seconds, %.1f MB/s)\n", upload_time,
         (double)size_mb / upload_time);

  // =========================================================================
  // Download and verify
  // =========================================================================
  printf("\n=== DOWNLOAD & VERIFY ===\n");

  start_time = get_time();

  f = s->open(s, test_key, STORAGE_MODE_READ);
  if (!f) {
    printf("ERROR: failed to open for read\n");
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
      break;
    if (n < 0) {
      printf("\nERROR: read failed at %zu bytes\n", read_total);
      verify_ok = 0;
      break;
    }

    if (!verify_pattern(chunk, n, read_total)) {
      printf("\nERROR: data mismatch at offset %zu\n", read_total);
      verify_ok = 0;
      break;
    }

    read_total += n;

    if (read_total - last_progress >= 1024 * 1024) {
      printf("  Progress: %zu MB / %zu MB\r", read_total / (1024 * 1024),
             size_mb);
      fflush(stdout);
      last_progress = read_total;
    }
  }

  s->close(f);

  double download_time = get_time() - start_time;

  if (verify_ok && read_total == total_size) {
    printf("\n  Download: OK (%.1f seconds, %.1f MB/s)\n", download_time,
           (double)size_mb / download_time);
    printf("  Verification: OK (all data matches)\n");
  } else {
    printf("\n  Download: FAILED (read %zu of %zu bytes)\n", read_total,
           total_size);
    verify_ok = 0;
  }

  // =========================================================================
  // Cleanup
  // =========================================================================
  printf("\n=== CLEANUP ===\n");
  rc = s->remove(s, test_key);
  if (rc == 0) {
    printf("  Deleted: %s\n", test_key);
  } else {
    printf("  Warning: failed to delete %s (rc=%d)\n", test_key, rc);
  }

  free(chunk);
  service_ref_release(&ref);
  plugin_manager_free(pm);
  service_registry_free(sr);

  printf("\n");
  if (verify_ok) {
    printf("=== TEST PASSED ===\n");
    printf("  Total size:   %zu MB\n", size_mb);
    printf("  Chunk size:   %d KB\n", CHUNK_SIZE / 1024);
    printf("  Upload:       %.1f seconds (%.1f MB/s)\n", upload_time,
           (double)size_mb / upload_time);
    printf("  Download:     %.1f seconds (%.1f MB/s)\n", download_time,
           (double)size_mb / download_time);
    return 0;
  } else {
    printf("=== TEST FAILED ===\n");
    return 1;
  }
}
