/**
 * Test Lua Storage bindings in the Lua plugin
 *
 * Tests the storage module exposed to Lua scripts using the local storage
 * plugin. Uses the new 5-symbol plugin protocol with plugin_manager.
 */

#include "log.h"
#include "plugin.h"
#include "plugin_manager.h"
#include "pressured.h"
#include "storage.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int test_count = 0;
static int pass_count = 0;

#define RUN_TEST(name, script)                                                 \
  do {                                                                         \
    test_count++;                                                              \
    if (run_lua_test(name, script)) {                                          \
      pass_count++;                                                            \
      printf("  [PASS] %s\n", name);                                           \
    } else {                                                                   \
      printf("  [FAIL] %s\n", name);                                           \
    }                                                                          \
  } while (0)

static int run_lua_test(const char *name, const char *script) {
  (void)name;

  // Set the script for this test
  setenv("PRESSURED_LUA_INLINE", script, 1);

  // Create fresh plugin manager for each test
  plugin_manager_t *test_pm = plugin_manager_new();
  if (!test_pm)
    return 0;

  // Load storage plugin first
  setenv("PRESSURED_STORAGE_PATH", "/tmp/lua_storage_test", 1);
  if (plugin_manager_load(test_pm, "plugins/storage_local.so", NULL) != 0) {
    printf("    Failed to load storage plugin\n");
    plugin_manager_free(test_pm);
    return 0;
  }

  // Load lua plugin
  if (plugin_manager_load(test_pm, "plugins/pressured_plugin_lua.so", NULL) !=
      0) {
    printf("    Failed to load lua plugin\n");
    plugin_manager_free(test_pm);
    return 0;
  }

  // Create test event
  pressured_event_t event = {0};
  event.sample.namespace = strdup("test-ns");
  event.sample.pod_name = strdup("test-pod");
  event.sample.container_name = strdup("test-container");
  event.sample.usage_bytes = 85 * 1024 * 1024;
  event.sample.limit_bytes = 100 * 1024 * 1024;
  event.sample.usage_percent = 0.85;
  event.severity = SEVERITY_CRITICAL;
  event.previous_severity = SEVERITY_WARN;

  // Dispatch event - scripts return "pass" or "fail"
  int handled = plugin_manager_dispatch(test_pm, &event, 0);

  pressured_event_free(&event);
  plugin_manager_free(test_pm);

  return handled == 1;
}

int main(void) {
  log_init(LOG_DEBUG);

  printf("test_lua_storage: Testing Lua Storage bindings\n\n");

  // Create temp directory for storage tests
  const char *test_dir = "/tmp/lua_storage_test";
  char cmd[256];
  snprintf(cmd, sizeof(cmd), "rm -rf %s && mkdir -p %s", test_dir, test_dir);
  system(cmd);

  printf("  Storage directory: %s\n\n", test_dir);

  // Test 1: storage.write and storage.read roundtrip
  RUN_TEST("storage.write and storage.read",
           "function on_event(event, ctx)\n"
           "  local key = 'test/hello.txt'\n"
           "  local data = 'Hello, Storage!'\n"
           "  \n"
           "  -- Write\n"
           "  local w = storage.write(key, data)\n"
           "  if not w.ok then\n"
           "    log.error( 'Write failed: ' .. (w.error or 'unknown'))\n"
           "    return 'fail'\n"
           "  end\n"
           "  log.info( 'Wrote ' .. w.bytes .. ' bytes')\n"
           "  \n"
           "  -- Read back\n"
           "  local r = storage.read(key)\n"
           "  if not r.ok then\n"
           "    log.error( 'Read failed: ' .. (r.error or 'unknown'))\n"
           "    return 'fail'\n"
           "  end\n"
           "  \n"
           "  if r.data ~= data then\n"
           "    log.error( 'Data mismatch: expected \"' .. data .. '\" got \"' "
           ".. r.data .. '\"')\n"
           "    return 'fail'\n"
           "  end\n"
           "  \n"
           "  log.info( 'Write/Read roundtrip: OK')\n"
           "  return 'pass'\n"
           "end\n");

  // Test 2: storage.exists
  RUN_TEST("storage.exists", "function on_event(event, ctx)\n"
                             "  local key = 'test/exists_test.txt'\n"
                             "  \n"
                             "  -- Should not exist yet\n"
                             "  if storage.exists(key) then\n"
                             "    log.error( 'File should not exist yet')\n"
                             "    return 'fail'\n"
                             "  end\n"
                             "  \n"
                             "  -- Write it\n"
                             "  local w = storage.write(key, 'test data')\n"
                             "  if not w.ok then\n"
                             "    log.error( 'Write failed')\n"
                             "    return 'fail'\n"
                             "  end\n"
                             "  \n"
                             "  -- Should exist now\n"
                             "  if not storage.exists(key) then\n"
                             "    log.error( 'File should exist after write')\n"
                             "    return 'fail'\n"
                             "  end\n"
                             "  \n"
                             "  log.info( 'storage.exists: OK')\n"
                             "  return 'pass'\n"
                             "end\n");

  // Test 3: storage.remove
  RUN_TEST("storage.remove",
           "function on_event(event, ctx)\n"
           "  local key = 'test/remove_test.txt'\n"
           "  \n"
           "  -- Write\n"
           "  storage.write(key, 'to be removed')\n"
           "  \n"
           "  -- Verify exists\n"
           "  if not storage.exists(key) then\n"
           "    log.error( 'File should exist')\n"
           "    return 'fail'\n"
           "  end\n"
           "  \n"
           "  -- Remove\n"
           "  local r = storage.remove(key)\n"
           "  if not r.ok then\n"
           "    log.error( 'Remove failed: ' .. (r.error or 'unknown'))\n"
           "    return 'fail'\n"
           "  end\n"
           "  \n"
           "  -- Should not exist now\n"
           "  if storage.exists(key) then\n"
           "    log.error( 'File should not exist after remove')\n"
           "    return 'fail'\n"
           "  end\n"
           "  \n"
           "  log.info( 'storage.remove: OK')\n"
           "  return 'pass'\n"
           "end\n");

  // Test 4: storage.open for streaming writes
  RUN_TEST("storage.open streaming write",
           "function on_event(event, ctx)\n"
           "  local key = 'test/stream_write.txt'\n"
           "  \n"
           "  -- Open for writing\n"
           "  local f, err = storage.open(key, 'w')\n"
           "  if not f then\n"
           "    log.error('Open failed: ' .. (err or 'unknown'))\n"
           "    return 'fail'\n"
           "  end\n"
           "  \n"
           "  -- Write in chunks\n"
           "  f:write('Hello, ')\n"
           "  f:write('streaming ')\n"
           "  f:write('world!')\n"
           "  f:close()\n"
           "  \n"
           "  -- Read back using simple API\n"
           "  local r = storage.read(key)\n"
           "  if not r.ok then\n"
           "    log.error('Read failed')\n"
           "    return 'fail'\n"
           "  end\n"
           "  \n"
           "  if r.data ~= 'Hello, streaming world!' then\n"
           "    log.error('Data mismatch: got \"' .. r.data .. '\"')\n"
           "    return 'fail'\n"
           "  end\n"
           "  \n"
           "  log.info('Streaming write: OK')\n"
           "  return 'pass'\n"
           "end\n");

  // Test 5: storage.open for streaming reads
  RUN_TEST(
      "storage.open streaming read",
      "function on_event(event, ctx)\n"
      "  local key = 'test/stream_read.txt'\n"
      "  local data = 'Chunk1|Chunk2|Chunk3'\n"
      "  \n"
      "  -- Write data first\n"
      "  storage.write(key, data)\n"
      "  \n"
      "  -- Open for reading\n"
      "  local f, err = storage.open(key, 'r')\n"
      "  if not f then\n"
      "    log.error('Open failed: ' .. (err or 'unknown'))\n"
      "    return 'fail'\n"
      "  end\n"
      "  \n"
      "  -- Read in chunks\n"
      "  local chunk1 = f:read(6)  -- 'Chunk1'\n"
      "  local chunk2 = f:read(7)  -- '|Chunk2'\n"
      "  local rest = f:read(100)  -- rest of file\n"
      "  f:close()\n"
      "  \n"
      "  if chunk1 ~= 'Chunk1' then\n"
      "    log.error('chunk1 mismatch: got \"' .. (chunk1 or 'nil') .. '\"')\n"
      "    return 'fail'\n"
      "  end\n"
      "  \n"
      "  log.info('Streaming read: OK')\n"
      "  return 'pass'\n"
      "end\n");

  // Test 6: Event data to storage
  RUN_TEST(
      "storage with event data",
      "function on_event(event, ctx)\n"
      "  local key = string.format('events/%s/%s/%s.json',\n"
      "    event.namespace, event.pod_name, os.date('%Y%m%d_%H%M%S'))\n"
      "  local data = "
      "string.format('{\"namespace\":\"%s\",\"pod\":\"%s\",\"usage\":%.1f}',\n"
      "    event.namespace, event.pod_name, event.usage_percent)\n"
      "  \n"
      "  local w = storage.write(key, data)\n"
      "  if not w.ok then\n"
      "    log.error( 'Write failed: ' .. (w.error or 'unknown'))\n"
      "    return 'fail'\n"
      "  end\n"
      "  \n"
      "  log.info( 'Stored event at: ' .. key)\n"
      "  return 'pass'\n"
      "end\n");

  // Cleanup temp directory
  snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
  system(cmd);

  printf("\n");
  printf("test_lua_storage: %d/%d tests passed\n", pass_count, test_count);

  return (pass_count == test_count) ? 0 : 1;
}
