#include "log.h"
#include "plugin.h"
#include "plugin_manager.h"
#include "pressured.h"
#include "service_registry.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
  log_init(LOG_DEBUG);

  printf("test_plugin: starting\n");

  // Create test config as JSON (demonstrates flexible config support)
  // Note: In new API, config is passed during plugin_manager_load()
  const char *test_config_json = "{\n"
                                 "  \"thresholds\": {\n"
                                 "    \"warn_percent\": 70,\n"
                                 "    \"critical_percent\": 85,\n"
                                 "    \"hysteresis_percent\": 5,\n"
                                 "    \"cooldown_seconds\": 60\n"
                                 "  },\n"
                                 "  \"source\": {\n"
                                 "    \"mode\": \"cgroup\",\n"
                                 "    \"poll_interval_ms\": 1000,\n"
                                 "    \"cgroup\": {\n"
                                 "      \"path\": \"/sys/fs/cgroup\"\n"
                                 "    }\n"
                                 "  },\n"
                                 "  \"lua\": {\n"
                                 "    \"enabled\": true,\n"
                                 "    \"timeout_ms\": 5000\n"
                                 "  },\n"
                                 "  \"dry_run\": false,\n"
                                 "  \"log_level\": \"debug\",\n"
                                 "  \"custom\": {\n"
                                 "    \"nested\": {\n"
                                 "      \"value\": \"hello-from-json\"\n"
                                 "    }\n"
                                 "  }\n"
                                 "}\n";

  // Create service registry
  service_registry_t *sr = service_registry_new();
  assert(sr != NULL);
  printf("  service registry creation: OK\n");

  // Create plugin manager with service registry
  plugin_manager_t *pm = plugin_manager_new(sr);
  assert(pm != NULL);
  printf("  plugin manager creation: OK\n");

  // Try to load the lua plugin
  // The plugin .so should be in build/plugins/
  const char *plugin_path = "plugins/lua.so";

  // Set environment for the plugin - test config access
  setenv("PRESSURED_LUA_INLINE",
         "function on_event(event, ctx)\n"
         "  log.info('Plugin test: ' .. event.pod_name .. ' at ' .. "
         "event.usage_percent .. '%')\n"
         "  -- Test flexible JSON config access\n"
         "  if config.thresholds then\n"
         "    log.info('config.thresholds.warn_percent = ' .. "
         "config.thresholds.warn_percent)\n"
         "    log.info('config.source.mode = ' .. config.source.mode)\n"
         "  end\n"
         "  -- Test custom nested field (flexible JSON support)\n"
         "  if config.custom and config.custom.nested then\n"
         "    log.info('config.custom.nested.value = ' .. "
         "config.custom.nested.value)\n"
         "  end\n"
         "  return 'ok'\n"
         "end\n",
         1);

  // Load plugin with config JSON (new API: config passed during load)
  int ret = plugin_manager_load(pm, plugin_path, test_config_json);
  if (ret != 0) {
    printf("  plugin loading: SKIPPED (plugin not found at %s)\n", plugin_path);
    printf("  (This is OK if running from a different directory)\n");
    plugin_manager_free(pm);
    service_registry_free(sr);
    printf("test_plugin: PASSED (with skipped tests)\n");
    return 0;
  }
  printf("  plugin loading: OK\n");

  assert(plugin_manager_count(pm) == 1);
  printf("  plugin count: OK\n");

  // Initialize all services
  service_registry_init_all(sr);
  printf("  service init: OK\n");

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

  // Dispatch event via service registry
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
  assert(handled == 1);
  printf("  event dispatch: OK\n");

  // Cleanup - service registry must be freed before plugin manager
  // (destructors need to run while plugin code is still loaded)
  pressured_event_free(&event);
  service_registry_free(sr);
  plugin_manager_free(pm);
  printf("  cleanup: OK\n");

  printf("test_plugin: PASSED\n");
  return 0;
}
