#ifndef PLUGIN_H
#define PLUGIN_H

#include <stdint.h>

// Forward declare event type (defined in pressured.h)
typedef struct pressured_event pressured_event_t;

/*
 * Generic Plugin System
 *
 * Plugins export 5 symbols:
 *   pressured_plugin_get_metadata() -> metadata
 *   pressured_plugin_load(config)   -> ctx
 *   pressured_plugin_create(ctx, type) -> handle
 *   pressured_plugin_destroy(ctx, type, handle)
 *   pressured_plugin_unload(ctx)
 *
 * The handle returned by create() embeds a vtable as its first field.
 * For storage: cast to storage_t* and call methods.
 * For action: cast to action_t* and call on_event().
 */

// Plugin capability types (bitmask for metadata, single value for
// create/destroy)
#define PRESSURED_PLUGIN_TYPE_STORAGE (1 << 0)
#define PRESSURED_PLUGIN_TYPE_ACTION (1 << 1)

// Plugin metadata
typedef struct {
  uint32_t types; // Bitmask of PRESSURED_PLUGIN_TYPE_*
  char name[64];
  int major_version;
  int minor_version;
  char description[256];
} pressured_plugin_metadata_t;

// Opaque plugin context (plugin-global state)
typedef struct pressured_plugin_ctx pressured_plugin_ctx_t;

// Opaque plugin handle (instance returned by create)
typedef struct pressured_plugin_handle pressured_plugin_handle_t;

// Plugin-exported function types
typedef const pressured_plugin_metadata_t *(*pressured_plugin_get_metadata_fn)(
    void);
typedef pressured_plugin_ctx_t *(*pressured_plugin_load_fn)(
    const char *config_json);
typedef void (*pressured_plugin_unload_fn)(pressured_plugin_ctx_t *ctx);
typedef pressured_plugin_handle_t *(*pressured_plugin_create_fn)(
    pressured_plugin_ctx_t *ctx, uint32_t type);
typedef void (*pressured_plugin_destroy_fn)(pressured_plugin_ctx_t *ctx,
                                            uint32_t type,
                                            pressured_plugin_handle_t *h);

// Export macro
#define PRESSURED_PLUGIN_EXPORT __attribute__((visibility("default")))

// Symbol names
#define PRESSURED_PLUGIN_SYMBOL_METADATA "pressured_plugin_get_metadata"
#define PRESSURED_PLUGIN_SYMBOL_LOAD "pressured_plugin_load"
#define PRESSURED_PLUGIN_SYMBOL_UNLOAD "pressured_plugin_unload"
#define PRESSURED_PLUGIN_SYMBOL_CREATE "pressured_plugin_create"
#define PRESSURED_PLUGIN_SYMBOL_DESTROY "pressured_plugin_destroy"

/*
 * Action Interface
 *
 * Action plugins embed this as their first field, like storage_t.
 * Allows plugin manager to dispatch events via vtable.
 */
typedef struct action action_t;

struct action {
  int (*on_event)(action_t *a, const pressured_event_t *event, int dry_run);
};

#endif // PLUGIN_H
