/*
 * Plugin Manager Implementation
 *
 * Loads plugin shared libraries and manages their lifecycle.
 * Plugins register their services with the service_registry during load().
 */

#include "plugin_manager.h"
#include "log.h"
#include <dirent.h>
#include <dlfcn.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PLUGINS 32

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal Structures
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
  void *dl_handle; /* dlopen handle */
  char *path;      /* Plugin file path */

  /* Function pointers from plugin */
  pressured_plugin_get_metadata_fn get_metadata;
  pressured_plugin_load_fn load;
  pressured_plugin_unload_fn unload;

  /* Plugin state */
  const pressured_plugin_metadata_t *metadata;
  pressured_plugin_ctx_t *ctx;
} loaded_plugin_t;

struct plugin_manager {
  loaded_plugin_t plugins[MAX_PLUGINS];
  int count;
  service_registry_t *registry;
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Lifecycle
 * ═══════════════════════════════════════════════════════════════════════════ */

plugin_manager_t *plugin_manager_new(service_registry_t *sr) {
  if (!sr) {
    log_error("plugin_manager_new: service_registry required");
    return NULL;
  }

  plugin_manager_t *pm = calloc(1, sizeof(plugin_manager_t));
  if (!pm)
    return NULL;

  pm->registry = sr;
  log_debug("plugin manager created");
  return pm;
}

void plugin_manager_free(plugin_manager_t *pm) {
  if (!pm)
    return;

  /* Unload plugins in reverse order */
  for (int i = pm->count - 1; i >= 0; i--) {
    loaded_plugin_t *lp = &pm->plugins[i];

    if (lp->unload && lp->ctx) {
      log_debug("unloading plugin: %s", lp->metadata ? lp->metadata->name : "?");
      lp->unload(lp->ctx);
    }

    if (lp->dl_handle) {
      dlclose(lp->dl_handle);
    }

    free(lp->path);
  }

  free(pm);
  log_debug("plugin manager freed");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Plugin Disabled Check
 *
 * Load policy: IMPLICIT (default: enabled)
 *   - Plugin loads unless plugins.<name>.enabled = false
 *   - The "enabled" field is reserved in each plugin's config section
 *
 * Config example:
 *   {
 *     "plugins": {
 *       "lua": { "enabled": true, "script": "alert.lua" },
 *       "local_storage": { "enabled": false }
 *     }
 *   }
 * ═══════════════════════════════════════════════════════════════════════════ */

static int plugin_is_disabled(const char *plugin_name, const char *config_json) {
  if (!plugin_name || !config_json)
    return 0; /* No config = enabled (implicit) */

  struct json_object *root = json_tokener_parse(config_json);
  if (!root)
    return 0;

  int disabled = 0;
  struct json_object *plugins, *plugin_cfg, *enabled;

  /* Navigate to plugins.<name>.enabled */
  if (json_object_object_get_ex(root, "plugins", &plugins) &&
      json_object_object_get_ex(plugins, plugin_name, &plugin_cfg) &&
      json_object_object_get_ex(plugin_cfg, "enabled", &enabled)) {
    /* Only disabled if explicitly set to false */
    if (!json_object_get_boolean(enabled)) {
      disabled = 1;
    }
  }

  json_object_put(root);
  return disabled;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Loading
 * ═══════════════════════════════════════════════════════════════════════════ */

int plugin_manager_load(plugin_manager_t *pm, const char *path,
                        const char *config_json) {
  if (!pm || !path)
    return -1;

  if (pm->count >= MAX_PLUGINS) {
    log_error("max plugins reached (%d)", MAX_PLUGINS);
    return -1;
  }

  /* Open shared library */
  void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    log_error("failed to load plugin %s: %s", path, dlerror());
    return -1;
  }

  dlerror(); /* Clear any existing error */

  /* Look up required symbols */
  pressured_plugin_get_metadata_fn get_metadata =
      dlsym(handle, PRESSURED_PLUGIN_SYMBOL_METADATA);
  pressured_plugin_load_fn load_fn =
      dlsym(handle, PRESSURED_PLUGIN_SYMBOL_LOAD);
  pressured_plugin_unload_fn unload_fn =
      dlsym(handle, PRESSURED_PLUGIN_SYMBOL_UNLOAD);

  if (!get_metadata || !load_fn || !unload_fn) {
    log_error("plugin %s missing required symbols (metadata/load/unload)", path);
    dlclose(handle);
    return -1;
  }

  /* Get metadata */
  const pressured_plugin_metadata_t *metadata = get_metadata();
  if (!metadata) {
    log_error("plugin %s returned NULL metadata", path);
    dlclose(handle);
    return -1;
  }

  /* Check if plugin is disabled in config (before calling load) */
  if (plugin_is_disabled(metadata->name, config_json)) {
    log_info("plugin %s: disabled in config, skipping", metadata->name);
    dlclose(handle);
    return 0; /* Not an error - intentionally skipped */
  }

  /* Load plugin - it registers services with the registry */
  pressured_plugin_ctx_t *ctx = load_fn(config_json, pm->registry);
  if (!ctx) {
    /* NULL ctx means plugin chose not to load (e.g., disabled in config) */
    log_debug("plugin %s: load() returned NULL (skipped)", metadata->name);
    dlclose(handle);
    return 0; /* Not an error - plugin skipped itself */
  }

  /* Store plugin */
  loaded_plugin_t *lp = &pm->plugins[pm->count];
  lp->dl_handle = handle;
  lp->path = strdup(path);
  if (!lp->path) {
    log_error("failed to allocate plugin path");
    unload_fn(ctx);
    dlclose(handle);
    return -1;
  }
  lp->get_metadata = get_metadata;
  lp->load = load_fn;
  lp->unload = unload_fn;
  lp->metadata = metadata;
  lp->ctx = ctx;

  pm->count++;

  log_info("loaded plugin: %s v%d.%d (%s)", metadata->name,
           metadata->major_version, metadata->minor_version,
           metadata->description);

  return 0;
}

int plugin_manager_load_dir(plugin_manager_t *pm, const char *dir,
                            const char *config_json) {
  if (!pm || !dir)
    return -1;

  DIR *d = opendir(dir);
  if (!d) {
    log_warn("cannot open plugin directory: %s", dir);
    return -1;
  }

  int loaded = 0;
  const struct dirent *entry;

  while ((entry = readdir(d)) != NULL) {
    const char *name = entry->d_name;
    size_t len = strlen(name);

    /* Only load .so files */
    if (len < 4 || strcmp(name + len - 3, ".so") != 0) {
      continue;
    }

    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, name);

    if (plugin_manager_load(pm, path, config_json) == 0) {
      loaded++;
    }
  }
  closedir(d);

  log_info("loaded %d plugins from %s", loaded, dir);
  return loaded;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Inspection
 * ═══════════════════════════════════════════════════════════════════════════ */

int plugin_manager_count(plugin_manager_t *pm) {
  return pm ? pm->count : 0;
}

const pressured_plugin_metadata_t *plugin_manager_get_metadata(
    plugin_manager_t *pm, int index) {
  if (!pm || index < 0 || index >= pm->count) {
    return NULL;
  }
  return pm->plugins[index].metadata;
}

service_registry_t *plugin_manager_get_registry(plugin_manager_t *pm) {
  return pm ? pm->registry : NULL;
}
