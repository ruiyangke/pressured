/**
 * Test multi-script Lua handler dispatcher
 *
 * Tests that multiple .lua files in a scripts_dir each get their on_event
 * called via the dispatcher mechanism.
 */

#include "log.h"
#include "plugin_manager.h"
#include "pressured.h"
#include "service_registry.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define LUA_PLUGIN_PATH "./plugins/lua.so"
#define TEST_DIR "/tmp/lua_multi_test"

// Create test directory with multiple Lua scripts
static int setup_test_scripts(void) {
  // Clean up any existing test directory
  system("rm -rf " TEST_DIR);

  // Create test directory
  if (mkdir(TEST_DIR, 0755) != 0) {
    perror("mkdir");
    return -1;
  }

  // Create first handler - writes to file
  FILE *f = fopen(TEST_DIR "/handler_alpha.lua", "w");
  if (!f)
    return -1;
  fprintf(f, "function on_event(event, ctx)\n"
             "  log.info('[alpha] Processing: ' .. event.pod_name)\n"
             "  return 'alpha_done'\n"
             "end\n");
  fclose(f);

  // Create second handler - also writes to file
  f = fopen(TEST_DIR "/handler_beta.lua", "w");
  if (!f)
    return -1;
  fprintf(f, "function on_event(event, ctx)\n"
             "  log.info('[beta] Processing: ' .. event.pod_name)\n"
             "  return 'beta_done'\n"
             "end\n");
  fclose(f);

  // Create third handler - yet another one
  f = fopen(TEST_DIR "/handler_gamma.lua", "w");
  if (!f)
    return -1;
  fprintf(f, "function on_event(event, ctx)\n"
             "  log.info('[gamma] Processing: ' .. event.pod_name)\n"
             "  return 'gamma_done'\n"
             "end\n");
  fclose(f);

  return 0;
}

static void cleanup_test_scripts(void) { system("rm -rf " TEST_DIR); }

int main(void) {
  log_init(LOG_DEBUG);
  printf("test_lua_multi: Testing multi-script handler dispatcher\n");

  // Setup test scripts
  if (setup_test_scripts() != 0) {
    printf("  FAILED: Could not create test scripts\n");
    return 1;
  }

  // Build config JSON with scripts_dir
  const char *config_json = "{"
                            "  \"plugins\": {"
                            "    \"lua\": {"
                            "      \"scripts_dir\": \"" TEST_DIR "\""
                            "    }"
                            "  }"
                            "}";

  // Create service registry and plugin manager
  service_registry_t *sr = service_registry_new();
  assert(sr != NULL);

  plugin_manager_t *pm = plugin_manager_new(sr);
  assert(pm != NULL);

  int rc = plugin_manager_load(pm, LUA_PLUGIN_PATH, config_json);
  if (rc != 0) {
    printf("  FAILED: Could not load lua plugin\n");
    cleanup_test_scripts();
    plugin_manager_free(pm);
    service_registry_free(sr);
    return 1;
  }

  // Initialize all services
  service_registry_init_all(sr);

  // Get action via service registry
  if (!service_registry_has(sr, "action")) {
    printf("  FAILED: No action service registered\n");
    cleanup_test_scripts();
    plugin_manager_free(pm);
    service_registry_free(sr);
    return 1;
  }

  service_ref_t ref = service_registry_acquire(sr, "action");
  if (!service_ref_valid(&ref)) {
    printf("  FAILED: Could not acquire action service\n");
    cleanup_test_scripts();
    plugin_manager_free(pm);
    service_registry_free(sr);
    return 1;
  }

  action_t *action = (action_t *)ref.instance;

  // Create test event
  pressured_event_t event = {
      .event_type = EVENT_TYPE_MEMORY_PRESSURE,
      .severity = SEVERITY_WARN,
      .previous_severity = SEVERITY_OK,
      .sample =
          {
              .namespace = "test-ns",
              .pod_name = "multi-test-pod",
              .container_name = "test-container",
              .usage_bytes = 85 * 1024 * 1024,
              .limit_bytes = 100 * 1024 * 1024,
              .usage_percent = 0.85,
          },
  };

  // Fire event - this should call all three handlers via dispatcher
  printf("  Firing event (expecting all 3 handlers to run)...\n");
  rc = action->on_event(action, &event, 0);
  if (rc != 0) {
    printf("  FAILED: on_event returned %d\n", rc);
    service_ref_release(&ref);
    cleanup_test_scripts();
    service_registry_free(sr);
    plugin_manager_free(pm);
    return 1;
  }

  // Cleanup
  service_ref_release(&ref);
  service_registry_free(sr);
  plugin_manager_free(pm);
  cleanup_test_scripts();

  printf("test_lua_multi: PASSED\n");
  printf("  (Check logs above for [alpha], [beta], [gamma] messages)\n");
  return 0;
}
