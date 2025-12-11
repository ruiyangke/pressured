/**
 * Test Lua HTTP bindings in the Lua plugin
 *
 * Requires the E2E test server running:
 *   python3 tests/e2e_server.py 8765
 */

#include "log.h"
#include "plugin.h"
#include "plugin_manager.h"
#include "pressured.h"
#include "service_registry.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

  // Create service registry and plugin manager
  service_registry_t *sr = service_registry_new();
  if (!sr)
    return 0;

  plugin_manager_t *pm = plugin_manager_new(sr);
  if (!pm) {
    service_registry_free(sr);
    return 0;
  }

  // Set the script
  setenv("PRESSURED_LUA_INLINE", script, 1);

  // Load plugin
  if (plugin_manager_load(pm, "plugins/lua.so", NULL) != 0) {
    plugin_manager_free(pm);
    service_registry_free(sr);
    return 0;
  }

  // Initialize all services (creates the action instance)
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

  printf("test_lua_http: Testing Lua HTTP bindings\n");
  printf("  (Requires: python3 tests/e2e_server.py " TEST_PORT ")\n\n");

  // Test 1: Simple GET request
  RUN_TEST("http.fetch GET",
           "function on_event(event, ctx)\n"
           "  local resp = http.fetch('GET', '" TEST_URL "/ping')\n"
           "  if resp.error then\n"
           "    log.error('Error: ' .. resp.error)\n"
           "    return 'fail'\n"
           "  end\n"
           "  if resp.status ~= 200 then\n"
           "    log.error('Bad status: ' .. resp.status)\n"
           "    return 'fail'\n"
           "  end\n"
           "  log.info('GET /ping: status=' .. resp.status)\n"
           "  return 'pass'\n"
           "end\n");

  // Test 2: POST with JSON body
  RUN_TEST("http.fetch POST JSON",
           "function on_event(event, ctx)\n"
           "  local resp = http.fetch('POST', '" TEST_URL "/json', {\n"
           "    body = '{\"test\": \"value\"}',\n"
           "    content_type = 'application/json'\n"
           "  })\n"
           "  if resp.error then\n"
           "    log.error('Error: ' .. resp.error)\n"
           "    return 'fail'\n"
           "  end\n"
           "  if resp.status ~= 200 then\n"
           "    log.error('Bad status: ' .. resp.status)\n"
           "    return 'fail'\n"
           "  end\n"
           "  log.info('POST /json: ' .. resp.body)\n"
           "  return 'pass'\n"
           "end\n");

  // Test 3: Custom headers
  RUN_TEST("http.fetch custom headers",
           "function on_event(event, ctx)\n"
           "  local resp = http.fetch('GET', '" TEST_URL "/headers', {\n"
           "    headers = {'X-Custom-Header: test-value', 'X-Another: 123'}\n"
           "  })\n"
           "  if resp.error then\n"
           "    log.error('Error: ' .. resp.error)\n"
           "    return 'fail'\n"
           "  end\n"
           "  -- Check response contains our header\n"
           "  if not string.find(resp.body, 'X-Custom-Header') then\n"
           "    log.error('Header not echoed back')\n"
           "    return 'fail'\n"
           "  end\n"
           "  log.info('Headers echoed: OK')\n"
           "  return 'pass'\n"
           "end\n");

  // Test 4: Bearer token auth
  RUN_TEST("http.set_bearer_token",
           "function on_event(event, ctx)\n"
           "  http.set_bearer_token('secret-token-123')\n"
           "  local resp = http.fetch('GET', '" TEST_URL "/auth/bearer')\n"
           "  if resp.error then\n"
           "    log.error('Error: ' .. resp.error)\n"
           "    return 'fail'\n"
           "  end\n"
           "  if resp.status ~= 200 then\n"
           "    log.error('Auth failed: ' .. resp.status)\n"
           "    return 'fail'\n"
           "  end\n"
           "  log.info('Bearer auth: OK')\n"
           "  return 'pass'\n"
           "end\n");

  // Test 5: Basic auth
  RUN_TEST("http.set_basic_auth",
           "function on_event(event, ctx)\n"
           "  http.set_basic_auth('testuser', 'testpass')\n"
           "  local resp = http.fetch('GET', '" TEST_URL "/auth/basic')\n"
           "  if resp.error then\n"
           "    log.error('Error: ' .. resp.error)\n"
           "    return 'fail'\n"
           "  end\n"
           "  if resp.status ~= 200 then\n"
           "    log.error('Auth failed: ' .. resp.status)\n"
           "    return 'fail'\n"
           "  end\n"
           "  log.info('Basic auth: OK')\n"
           "  return 'pass'\n"
           "end\n");

  // Test 6: URL encoding
  RUN_TEST("http.urlencode",
           "function on_event(event, ctx)\n"
           "  local encoded = http.urlencode('hello world & foo=bar')\n"
           "  if not encoded then\n"
           "    log.error('urlencode returned nil')\n"
           "    return 'fail'\n"
           "  end\n"
           "  -- Check that spaces and special chars are encoded\n"
           "  if string.find(encoded, ' ') or string.find(encoded, '&') then\n"
           "    log.error('Not properly encoded: ' .. encoded)\n"
           "    return 'fail'\n"
           "  end\n"
           "  log.info('urlencode: ' .. encoded)\n"
           "  return 'pass'\n"
           "end\n");

  // Test 7: Download file
  RUN_TEST("http.download",
           "function on_event(event, ctx)\n"
           "  local result = http.download('" TEST_URL
           "/download/1024', '/tmp/lua_test_download.bin')\n"
           "  if not result.ok then\n"
           "    log.error('Download failed: ' .. (result.error or 'unknown'))\n"
           "    return 'fail'\n"
           "  end\n"
           "  log.info('Download 1KB: OK')\n"
           "  return 'pass'\n"
           "end\n");

  // Test 8: Handle HTTP errors gracefully
  RUN_TEST("http.fetch error handling",
           "function on_event(event, ctx)\n"
           "  local resp = http.fetch('GET', '" TEST_URL "/error/404')\n"
           "  if resp.error then\n"
           "    log.error('Unexpected error: ' .. resp.error)\n"
           "    return 'fail'\n"
           "  end\n"
           "  if resp.status ~= 404 then\n"
           "    log.error('Expected 404, got: ' .. resp.status)\n"
           "    return 'fail'\n"
           "  end\n"
           "  log.info('Error handling: correctly got 404')\n"
           "  return 'pass'\n"
           "end\n");

  // Test 9: Using event data to build request
  RUN_TEST(
      "http.fetch with event data",
      "function on_event(event, ctx)\n"
      "  local body = string.format('{\"pod\": \"%s\", \"usage\": %.1f}',\n"
      "    event.pod_name, event.usage_percent)\n"
      "  local resp = http.fetch('POST', '" TEST_URL "/json', {\n"
      "    body = body,\n"
      "    content_type = 'application/json'\n"
      "  })\n"
      "  if resp.error then\n"
      "    log.error('Error: ' .. resp.error)\n"
      "    return 'fail'\n"
      "  end\n"
      "  if resp.status ~= 200 then\n"
      "    log.error('Bad status: ' .. resp.status)\n"
      "    return 'fail'\n"
      "  end\n"
      "  -- Check that event data was sent\n"
      "  if not string.find(resp.body, 'test-pod') then\n"
      "    log.error('Event data not in response')\n"
      "    return 'fail'\n"
      "  end\n"
      "  log.info('Event data POST: OK')\n"
      "  return 'pass'\n"
      "end\n");

  printf("\n");
  printf("test_lua_http: %d/%d tests passed\n", pass_count, test_count);

  return (pass_count == test_count) ? 0 : 1;
}
