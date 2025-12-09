/*
 * Storage plugin test - tests the streaming storage interface with embedded
 * vtable
 */

#include "log.h"
#include "plugin_manager.h"
#include "storage.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Path to built plugin
#define PLUGIN_PATH "./plugins/storage_local.so"

static void test_streaming_write_read(storage_t *s) {
  printf("  test_streaming_write_read: ");

  const char *key = "test/stream_data.txt";
  const char *data = "Hello, streaming storage!";
  size_t len = strlen(data);

  // Write using streaming API
  storage_file_t *f = s->open(s, key, STORAGE_MODE_WRITE);
  assert(f != NULL);

  int64_t written = s->write(f, data, len);
  assert(written == (int64_t)len);

  int rc = s->close(f);
  assert(rc == STORAGE_OK);

  // Read back using streaming API
  f = s->open(s, key, STORAGE_MODE_READ);
  assert(f != NULL);

  char buf[256] = {0};
  int64_t n = s->read(f, buf, sizeof(buf));
  assert(n == (int64_t)len);
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
  const size_t chunk_size = 4096;
  const size_t total_size = 64 * 1024; // 64KB

  // Create test data
  char *chunk = malloc(chunk_size);
  assert(chunk != NULL);
  memset(chunk, 'X', chunk_size);

  // Write in chunks
  storage_file_t *f = s->open(s, key, STORAGE_MODE_WRITE);
  assert(f != NULL);

  size_t written_total = 0;
  while (written_total < total_size) {
    int64_t n = s->write(f, chunk, chunk_size);
    assert(n == (int64_t)chunk_size);
    written_total += n;
  }

  int rc = s->close(f);
  assert(rc == STORAGE_OK);

  // Read back in chunks and verify
  f = s->open(s, key, STORAGE_MODE_READ);
  assert(f != NULL);

  size_t read_total = 0;
  while (1) {
    int64_t n = s->read(f, chunk, chunk_size);
    if (n == 0)
      break; // EOF
    assert(n > 0);
    read_total += n;
    // Verify data
    for (int64_t i = 0; i < n; i++) {
      assert(chunk[i] == 'X');
    }
  }
  assert(read_total == total_size);

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

  // Removing non-existent file should return NOT_FOUND
  int rc = s->remove(s, "nonexistent/file.txt");
  assert(rc == STORAGE_ERR_NOT_FOUND);

  printf("OK\n");
}

int main(void) {
  log_init(LOG_DEBUG);

  printf("test_storage: starting\n");

  // Use temp directory
  char tmp_dir[] = "/tmp/pressured_storage_test_XXXXXX";
  char *dir = mkdtemp(tmp_dir);
  assert(dir != NULL);
  printf("  using temp dir: %s\n", dir);

  // Set environment variable for storage path
  setenv("PRESSURED_STORAGE_PATH", dir, 1);

  // Load plugin using plugin manager
  plugin_manager_t *pm = plugin_manager_new();
  assert(pm != NULL);

  int rc = plugin_manager_load(pm, PLUGIN_PATH, NULL);
  if (rc != 0) {
    printf("  ERROR: failed to load plugin from %s\n", PLUGIN_PATH);
    printf("  Make sure to run from build directory\n");
    plugin_manager_free(pm);
    return 1;
  }

  // Get storage interface - handle embeds vtable, cast directly
  storage_t *s =
      (storage_t *)plugin_manager_get_handle(pm, PRESSURED_PLUGIN_TYPE_STORAGE);
  assert(s != NULL);

  // Run tests
  test_streaming_write_read(s);
  test_exists(s);
  test_large_streaming(s);
  test_not_found(s);

  // Cleanup
  plugin_manager_free(pm);

  // Remove temp directory
  char cmd[256];
  snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
  system(cmd);

  printf("test_storage: PASSED\n");
  return 0;
}
