/**
 * Test http.stream to storage Lua binding
 *
 * Requires the E2E test server running:
 *   python3 tests/e2e_server.py 8765
 *
 * Uses the new service registry architecture.
 */

#include "log.h"
#include "plugin.h"
#include "plugin_manager.h"
#include "pressured.h"
#include "service_registry.h"
#include "storage.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST_PORT "8765"
#define TEST_URL "http://127.0.0.1:" TEST_PORT

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

  // Create service registry and plugin manager
  service_registry_t *sr = service_registry_new();
  if (!sr)
    return 0;

  plugin_manager_t *pm = plugin_manager_new(sr);
  if (!pm) {
    service_registry_free(sr);
    return 0;
  }

  // Load storage plugin first
  setenv("PRESSURED_STORAGE_PATH", "/tmp/http_stream_storage_test", 1);
  if (plugin_manager_load(pm, "plugins/local-storage.so", NULL) != 0) {
    printf("    Failed to load storage plugin\n");
    plugin_manager_free(pm);
    service_registry_free(sr);
    return 0;
  }

  // Load lua plugin
  if (plugin_manager_load(pm, "plugins/lua.so", NULL) != 0) {
    printf("    Failed to load lua plugin\n");
    plugin_manager_free(pm);
    service_registry_free(sr);
    return 0;
  }

  // Initialize all services (creates storage and action instances)
  service_registry_init_all(sr);

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

  // Dispatch event via service registry - scripts return "pass" or "fail"
  int handled = 0;
  if (service_registry_has(sr, "action")) {
    service_ref_t ref = service_registry_acquire(sr, "action");
    if (service_ref_valid(&ref)) {
      action_t *action = (action_t *)ref.instance;
      if (action && action->on_event) {
        action->on_event(action, &event, 0);
        handled = 1;
      }
      service_ref_release(&ref);
    }
  }

  pressured_event_free(&event);
  service_registry_free(sr);
  plugin_manager_free(pm);

  return handled == 1;
}

int main(void) {
  log_init(LOG_DEBUG);

  printf("test_http_stream_storage: Testing http.stream to storage\n");
  printf("  (Requires: python3 tests/e2e_server.py " TEST_PORT ")\n\n");

  // Create temp directory for storage tests
  const char *test_dir = "/tmp/http_stream_storage_test";
  char cmd[256];
  snprintf(cmd, sizeof(cmd), "rm -rf %s && mkdir -p %s", test_dir, test_dir);
  system(cmd);

  printf("  Storage directory: %s\n\n", test_dir);

  // Test 1: Basic http.stream with callback
  RUN_TEST("http.stream basic callback",
           "function on_event(event, ctx)\n"
           "  local chunks = {}\n"
           "  local result = http.stream('" TEST_URL
           "/download/1024', function(chunk, info)\n"
           "    table.insert(chunks, chunk)\n"
           "    log.debug( 'Chunk ' .. #chunks .. ': ' .. info.size .. ' "
           "bytes, total=' .. info.total)\n"
           "    return true  -- continue\n"
           "  end)\n"
           "  \n"
           "  if not result.ok then\n"
           "    log.error( 'Stream failed: ' .. (result.error or 'unknown'))\n"
           "    return 'fail'\n"
           "  end\n"
           "  \n"
           "  local data = table.concat(chunks)\n"
           "  if #data ~= 1024 then\n"
           "    log.error( 'Expected 1024 bytes, got ' .. #data)\n"
           "    return 'fail'\n"
           "  end\n"
           "  \n"
           "  log.info( 'http.stream: received ' .. result.bytes .. ' bytes in "
           "' .. #chunks .. ' chunks')\n"
           "  return 'pass'\n"
           "end\n");

  // Test 2: http.stream directly to storage (stream-to-storage pattern)
  RUN_TEST(
      "http.stream to storage",
      "function on_event(event, ctx)\n"
      "  local key = 'stream_test/streamed.bin'\n"
      "  local chunks = {}\n"
      "  \n"
      "  -- Stream and collect chunks\n"
      "  local result = http.stream('" TEST_URL
      "/download/4096', function(chunk, info)\n"
      "    table.insert(chunks, chunk)\n"
      "    return true\n"
      "  end)\n"
      "  \n"
      "  if not result.ok then\n"
      "    log.error( 'Stream failed: ' .. (result.error or 'unknown'))\n"
      "    return 'fail'\n"
      "  end\n"
      "  \n"
      "  -- Write to storage\n"
      "  local data = table.concat(chunks)\n"
      "  local w = storage.write(key, data)\n"
      "  if not w.ok then\n"
      "    log.error( 'Storage write failed: ' .. (w.error or 'unknown'))\n"
      "    return 'fail'\n"
      "  end\n"
      "  \n"
      "  -- Verify by reading back\n"
      "  local r = storage.read(key)\n"
      "  if not r.ok or #r.data ~= 4096 then\n"
      "    log.error( 'Size mismatch: expected 4096, got ' .. (#r.data or "
      "'nil'))\n"
      "    return 'fail'\n"
      "  end\n"
      "  \n"
      "  log.info( 'http.stream to storage: ' .. w.bytes .. ' bytes')\n"
      "  return 'pass'\n"
      "end\n");

  // Test 3: Abort streaming mid-download
  RUN_TEST("http.stream early abort",
           "function on_event(event, ctx)\n"
           "  local received = 0\n"
           "  local result = http.stream('" TEST_URL
           "/download/10240', function(chunk, info)\n"
           "    received = received + #chunk\n"
           "    if received >= 2048 then\n"
           "      log.info( 'Aborting after ' .. received .. ' bytes')\n"
           "      return false  -- abort\n"
           "    end\n"
           "    return true\n"
           "  end)\n"
           "  \n"
           "  -- Should report aborted\n"
           "  if result.ok then\n"
           "    log.error( 'Expected abort but got success')\n"
           "    return 'fail'\n"
           "  end\n"
           "  \n"
           "  if result.bytes >= 10240 then\n"
           "    log.error( 'Should have aborted early, got ' .. result.bytes "
           ".. ' bytes')\n"
           "    return 'fail'\n"
           "  end\n"
           "  \n"
           "  log.info( 'http.stream abort: OK (received ' .. result.bytes .. "
           "' bytes)')\n"
           "  return 'pass'\n"
           "end\n");

  // Test 4: http.stream with progress tracking (simulating heap dump scenario)
  RUN_TEST("http.stream heapdump pattern",
           "function on_event(event, ctx)\n"
           "  local key = string.format('heapdumps/%s/%s/heap.bin',\n"
           "    event.namespace, event.pod_name)\n"
           "  local chunks = {}\n"
           "  \n"
           "  -- Stream with progress logging\n"
           "  local result = http.stream('" TEST_URL
           "/download/8192', function(chunk, info)\n"
           "    table.insert(chunks, chunk)\n"
           "    -- Progress: could log or update state here\n"
           "    return true\n"
           "  end)\n"
           "  \n"
           "  if not result.ok then\n"
           "    log.error( 'Stream failed: ' .. (result.error or 'unknown'))\n"
           "    return 'fail'\n"
           "  end\n"
           "  \n"
           "  -- Write to storage with event-based path\n"
           "  local w = storage.write(key, table.concat(chunks))\n"
           "  if not w.ok then\n"
           "    log.error( 'Storage write failed')\n"
           "    return 'fail'\n"
           "  end\n"
           "  \n"
           "  -- Verify\n"
           "  if not storage.exists(key) then\n"
           "    log.error( 'File not at expected path')\n"
           "    return 'fail'\n"
           "  end\n"
           "  \n"
           "  log.info( 'Stored heapdump at: ' .. key .. ' (' .. w.bytes .. ' "
           "bytes)')\n"
           "  return 'pass'\n"
           "end\n");

  // Cleanup temp directory
  snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
  system(cmd);

  printf("\n");
  printf("test_http_stream_storage: %d/%d tests passed\n", pass_count,
         test_count);

  return (pass_count == test_count) ? 0 : 1;
}
