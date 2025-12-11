#ifndef PLUGIN_MANAGER_H
#define PLUGIN_MANAGER_H

#include "plugin.h"
#include "service_registry.h"

/*
 * Plugin Manager
 *
 * Loads plugin shared libraries and manages their lifecycle.
 * Plugins register their services with the service_registry during load().
 *
 * Load Policy: IMPLICIT (default: enabled)
 *   - Plugins load unless explicitly disabled via: plugins.<name>.enabled =
 * false
 *   - The "enabled" field is reserved in each plugin's config section
 *   - Plugin names use kebab-case (e.g., "local-storage", "s3-storage")
 *
 * Config example:
 *   {
 *     "plugins": {
 *       "lua": { "enabled": true, "script": "alert.lua" },
 *       "local-storage": { "enabled": false }
 *     }
 *   }
 *
 * Usage:
 *   service_registry_t *sr = service_registry_new();
 *   plugin_manager_t *pm = plugin_manager_new(sr);
 *   plugin_manager_load_dir(pm, "plugins/", config_json);
 *   service_registry_init_all(sr);  // Eagerly instantiate singletons
 *
 *   // Acquire services via registry
 *   service_ref_t ref = service_registry_acquire(sr, "storage");
 *   storage_t *s = ref.instance;
 *
 *   service_registry_free(sr);  // Must free before plugin_manager!
 *   plugin_manager_free(pm);
 */

typedef struct plugin_manager plugin_manager_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * Lifecycle
 * ═══════════════════════════════════════════════════════════════════════════
 */

/*
 * Create plugin manager
 *
 * @param sr  Service registry that plugins will register with
 * @return    New plugin manager, or NULL on failure
 */
plugin_manager_t *plugin_manager_new(service_registry_t *sr);

/*
 * Free plugin manager and unload all plugins
 *
 * Note: This does NOT free the service_registry - caller owns that.
 */
void plugin_manager_free(plugin_manager_t *pm);

/* ═══════════════════════════════════════════════════════════════════════════
 * Loading
 * ═══════════════════════════════════════════════════════════════════════════
 */

/*
 * Load a plugin from a shared library
 *
 * @param pm           Plugin manager
 * @param path         Path to .so file
 * @param config_json  JSON configuration (passed to plugin's load())
 * @return             0 on success, -1 on failure
 */
int plugin_manager_load(plugin_manager_t *pm, const char *path,
                        const char *config_json);

/*
 * Load all plugins from a directory
 *
 * @param pm           Plugin manager
 * @param dir          Directory containing .so files
 * @param config_json  JSON configuration (passed to each plugin's load())
 * @return             Number of plugins loaded, or -1 on error
 */
int plugin_manager_load_dir(plugin_manager_t *pm, const char *dir,
                            const char *config_json);

/* ═══════════════════════════════════════════════════════════════════════════
 * Inspection
 * ═══════════════════════════════════════════════════════════════════════════
 */

/* Get number of loaded plugins */
int plugin_manager_count(plugin_manager_t *pm);

/* Get metadata for a loaded plugin by index */
const pressured_plugin_metadata_t *
plugin_manager_get_metadata(plugin_manager_t *pm, int index);

/* Get the service registry */
service_registry_t *plugin_manager_get_registry(plugin_manager_t *pm);

#endif /* PLUGIN_MANAGER_H */
