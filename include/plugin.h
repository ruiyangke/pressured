#ifndef PLUGIN_H
#define PLUGIN_H

#include <stdint.h>

/*
 * Plugin System
 *
 * Plugins are shared libraries (.so) that export 3 symbols:
 *   pressured_plugin_get_metadata() -> metadata
 *   pressured_plugin_load(config, registry) -> ctx
 *   pressured_plugin_unload(ctx)
 *
 * During load(), plugins register their services with the service_registry.
 * Services are discovered via service_registry_acquire() at runtime.
 *
 * Service Types (string-based):
 *   "storage"  - Storage backends (local, s3, gcs)
 *   "action"   - Event handlers (lua scripts)
 *   "analyzer" - Profile analyzers (pprof)
 */

/* Forward declarations */
typedef struct pressured_event pressured_event_t;
typedef struct service_registry service_registry_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * Plugin Metadata
 * ═══════════════════════════════════════════════════════════════════════════
 */

typedef struct {
  char name[64];
  int major_version;
  int minor_version;
  char description[256];
} pressured_plugin_metadata_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * Plugin Context
 * ═══════════════════════════════════════════════════════════════════════════
 */

/* Opaque plugin context (plugin-specific global state) */
typedef struct pressured_plugin_ctx pressured_plugin_ctx_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * Plugin Exports
 *
 * Plugins must export these 3 symbols:
 * ═══════════════════════════════════════════════════════════════════════════
 */

/* Returns plugin metadata (name, version, description) */
typedef const pressured_plugin_metadata_t *(*pressured_plugin_get_metadata_fn)(
    void);

/*
 * Initialize plugin and register services with the registry.
 *
 * @param config_json  JSON configuration string (may be NULL)
 * @param sr           Service registry for registering services
 * @return             Plugin context, or NULL to skip loading this plugin
 */
typedef pressured_plugin_ctx_t *(*pressured_plugin_load_fn)(
    const char *config_json, service_registry_t *sr);

/* Cleanup plugin resources */
typedef void (*pressured_plugin_unload_fn)(pressured_plugin_ctx_t *ctx);

/* Export macro for plugins */
#define PRESSURED_PLUGIN_EXPORT __attribute__((visibility("default")))

/* Symbol names for dlsym() */
#define PRESSURED_PLUGIN_SYMBOL_METADATA "pressured_plugin_get_metadata"
#define PRESSURED_PLUGIN_SYMBOL_LOAD "pressured_plugin_load"
#define PRESSURED_PLUGIN_SYMBOL_UNLOAD "pressured_plugin_unload"

/* ═══════════════════════════════════════════════════════════════════════════
 * Action Interface
 *
 * Action services implement event handling. Register with type="action".
 * ═══════════════════════════════════════════════════════════════════════════
 */

typedef struct action action_t;

struct action {
  int (*on_event)(action_t *a, const pressured_event_t *event, int dry_run);
};

#endif /* PLUGIN_H */
