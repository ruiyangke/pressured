#ifndef PLUGIN_MANAGER_H
#define PLUGIN_MANAGER_H

#include "plugin.h"
#include "pressured.h"
#include <stdbool.h>

/*
 * Plugin Manager
 *
 * High-level API for loading and managing plugins.
 * Wraps dlopen/dlsym and the 5-symbol plugin protocol.
 *
 * Usage:
 *   plugin_manager_t *pm = plugin_manager_new();
 *   plugin_manager_load(pm, "plugins/storage_local.so", config_json);
 *
 *   // Get storage interface - returns handle that embeds vtable
 *   storage_t *s = (storage_t *)plugin_manager_get_handle(pm,
 * PRESSURED_PLUGIN_TYPE_STORAGE); s->open(s, "key", STORAGE_MODE_WRITE);
 *
 *   plugin_manager_free(pm);  // Destroys handles, unloads plugins, closes .so
 */

typedef struct plugin_manager plugin_manager_t;

// Lifecycle
plugin_manager_t *plugin_manager_new(void);
void plugin_manager_free(plugin_manager_t *pm);

// Loading
int plugin_manager_load(plugin_manager_t *pm, const char *path,
                        const char *config_json);
int plugin_manager_load_dir(plugin_manager_t *pm, const char *dir,
                            const char *config_json);

// Inspection
int plugin_manager_count(plugin_manager_t *pm);
const pressured_plugin_metadata_t *
plugin_manager_get_metadata(plugin_manager_t *pm, int index);

// Get first handle of specified type (NULL if none)
// Returns handle with embedded vtable - caller casts to appropriate type
pressured_plugin_handle_t *plugin_manager_get_handle(plugin_manager_t *pm,
                                                     uint32_t type);

// Check if any plugin supports the specified type
bool plugin_manager_has_type(plugin_manager_t *pm, uint32_t type);

// Iterate over all handles of a type (for multi-plugin scenarios)
typedef void (*plugin_handle_callback_t)(pressured_plugin_handle_t *handle,
                                         void *userdata);
void plugin_manager_foreach_handle(plugin_manager_t *pm, uint32_t type,
                                   plugin_handle_callback_t callback,
                                   void *userdata);

// Dispatch event to all action plugins (calls lua_action_on_event for Lua
// plugins) Returns number of plugins that handled the event
int plugin_manager_dispatch(plugin_manager_t *pm,
                            const pressured_event_t *event, int dry_run);

// ─────────────────────────────────────────────────────────────────────────────
// Global service lookup
// Allows plugins to query for services at runtime
// ─────────────────────────────────────────────────────────────────────────────

// Service types for plugin_get_service()
#define PLUGIN_SERVICE_MANAGER 0 // Returns plugin_manager_t*
#define PLUGIN_SERVICE_STORAGE 1 // Returns storage_t*

// Set the global plugin manager instance (called from main)
void plugin_init(plugin_manager_t *pm);

// Get a service by type
// Returns NULL if service is not available
// Usage:
//   plugin_manager_t *pm = (plugin_manager_t
//   *)plugin_get_service(PLUGIN_SERVICE_MANAGER); storage_t *s = (storage_t
//   *)plugin_get_service(PLUGIN_SERVICE_STORAGE);
void *plugin_get_service(int service_type);

#endif // PLUGIN_MANAGER_H
