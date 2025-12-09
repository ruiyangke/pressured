#include "log.h"
#include "plugin_manager.h"
#include "storage.h"
#include <dirent.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PLUGINS 32

typedef struct {
  void *dl_handle; // dlopen handle
  char *path;      // Plugin file path

  // Function pointers from plugin
  pressured_plugin_get_metadata_fn get_metadata;
  pressured_plugin_load_fn load;
  pressured_plugin_unload_fn unload;
  pressured_plugin_create_fn create;
  pressured_plugin_destroy_fn destroy;

  // Plugin state
  const pressured_plugin_metadata_t *metadata;
  pressured_plugin_ctx_t *ctx; // Plugin context (from load)

  // Handles for each type (created on demand)
  pressured_plugin_handle_t *storage_handle;
  pressured_plugin_handle_t *action_handle;
} loaded_plugin_t;

struct plugin_manager {
  loaded_plugin_t plugins[MAX_PLUGINS];
  int count;
};

plugin_manager_t *plugin_manager_new(void) {
  plugin_manager_t *pm = calloc(1, sizeof(plugin_manager_t));
  if (!pm)
    return NULL;
  log_debug("plugin manager created");
  return pm;
}

void plugin_manager_free(plugin_manager_t *pm) {
  if (!pm)
    return;

  for (int i = 0; i < pm->count; i++) {
    loaded_plugin_t *lp = &pm->plugins[i];

    // Destroy handles
    if (lp->destroy && lp->ctx) {
      if (lp->storage_handle) {
        lp->destroy(lp->ctx, PRESSURED_PLUGIN_TYPE_STORAGE, lp->storage_handle);
      }
      if (lp->action_handle) {
        lp->destroy(lp->ctx, PRESSURED_PLUGIN_TYPE_ACTION, lp->action_handle);
      }
    }

    // Unload plugin
    if (lp->unload && lp->ctx) {
      lp->unload(lp->ctx);
    }

    // Close shared library
    if (lp->dl_handle) {
      dlclose(lp->dl_handle);
    }

    free(lp->path);
  }

  free(pm);
  log_debug("plugin manager freed");
}

int plugin_manager_load(plugin_manager_t *pm, const char *path,
                        const char *config_json) {
  if (pm->count >= MAX_PLUGINS) {
    log_error("max plugins reached");
    return -1;
  }

  // Open shared library
  void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    log_error("failed to load plugin %s: %s", path, dlerror());
    return -1;
  }

  // Clear any existing error
  dlerror();

  // Look up required symbols
  pressured_plugin_get_metadata_fn get_metadata =
      dlsym(handle, PRESSURED_PLUGIN_SYMBOL_METADATA);
  pressured_plugin_load_fn load_fn =
      dlsym(handle, PRESSURED_PLUGIN_SYMBOL_LOAD);
  pressured_plugin_unload_fn unload_fn =
      dlsym(handle, PRESSURED_PLUGIN_SYMBOL_UNLOAD);
  pressured_plugin_create_fn create_fn =
      dlsym(handle, PRESSURED_PLUGIN_SYMBOL_CREATE);
  pressured_plugin_destroy_fn destroy_fn =
      dlsym(handle, PRESSURED_PLUGIN_SYMBOL_DESTROY);

  if (!get_metadata || !load_fn || !unload_fn || !create_fn || !destroy_fn) {
    log_error("plugin %s missing required symbols", path);
    dlclose(handle);
    return -1;
  }

  // Get metadata
  const pressured_plugin_metadata_t *metadata = get_metadata();
  if (!metadata) {
    log_error("plugin %s returned NULL metadata", path);
    dlclose(handle);
    return -1;
  }

  // Plugin must support at least one type
  if (!(metadata->types &
        (PRESSURED_PLUGIN_TYPE_STORAGE | PRESSURED_PLUGIN_TYPE_ACTION))) {
    log_error("plugin %s does not support any known type", path);
    dlclose(handle);
    return -1;
  }

  // Load plugin (initialize global state)
  pressured_plugin_ctx_t *ctx = load_fn(config_json);
  if (!ctx) {
    log_error("plugin %s load() failed", path);
    dlclose(handle);
    return -1;
  }

  // Store plugin
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
  lp->create = create_fn;
  lp->destroy = destroy_fn;
  lp->metadata = metadata;
  lp->ctx = ctx;
  lp->storage_handle = NULL;
  lp->action_handle = NULL;

  // Eagerly create handles for each supported type
  if (metadata->types & PRESSURED_PLUGIN_TYPE_STORAGE) {
    lp->storage_handle = create_fn(ctx, PRESSURED_PLUGIN_TYPE_STORAGE);
    if (!lp->storage_handle) {
      log_warn("plugin %s: failed to create storage handle", path);
    }
  }

  if (metadata->types & PRESSURED_PLUGIN_TYPE_ACTION) {
    lp->action_handle = create_fn(ctx, PRESSURED_PLUGIN_TYPE_ACTION);
    if (!lp->action_handle) {
      log_warn("plugin %s: failed to create action handle", path);
    }
  }

  pm->count++;

  log_info("loaded plugin: %s v%d.%d (%s) [storage=%s action=%s]",
           metadata->name, metadata->major_version, metadata->minor_version,
           metadata->description, lp->storage_handle ? "yes" : "no",
           lp->action_handle ? "yes" : "no");

  return 0;
}

int plugin_manager_load_dir(plugin_manager_t *pm, const char *dir,
                            const char *config_json) {
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

    // Only load .so files
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

int plugin_manager_count(plugin_manager_t *pm) { return pm ? pm->count : 0; }

const pressured_plugin_metadata_t *
plugin_manager_get_metadata(plugin_manager_t *pm, int index) {
  if (!pm || index < 0 || index >= pm->count) {
    return NULL;
  }
  return pm->plugins[index].metadata;
}

pressured_plugin_handle_t *plugin_manager_get_handle(plugin_manager_t *pm,
                                                     uint32_t type) {
  if (!pm)
    return NULL;

  for (int i = 0; i < pm->count; i++) {
    loaded_plugin_t *lp = &pm->plugins[i];
    if (type == PRESSURED_PLUGIN_TYPE_STORAGE && lp->storage_handle) {
      return lp->storage_handle;
    }
    if (type == PRESSURED_PLUGIN_TYPE_ACTION && lp->action_handle) {
      return lp->action_handle;
    }
  }
  return NULL;
}

bool plugin_manager_has_type(plugin_manager_t *pm, uint32_t type) {
  return plugin_manager_get_handle(pm, type) != NULL;
}

void plugin_manager_foreach_handle(plugin_manager_t *pm, uint32_t type,
                                   plugin_handle_callback_t callback,
                                   void *userdata) {
  if (!pm || !callback)
    return;

  for (int i = 0; i < pm->count; i++) {
    loaded_plugin_t *lp = &pm->plugins[i];
    pressured_plugin_handle_t *handle = NULL;

    if (type == PRESSURED_PLUGIN_TYPE_STORAGE) {
      handle = lp->storage_handle;
    } else if (type == PRESSURED_PLUGIN_TYPE_ACTION) {
      handle = lp->action_handle;
    }

    if (handle) {
      callback(handle, userdata);
    }
  }
}

int plugin_manager_dispatch(plugin_manager_t *pm,
                            const pressured_event_t *event, int dry_run) {
  if (!pm || !event)
    return 0;

  int handled = 0;
  for (int i = 0; i < pm->count; i++) {
    loaded_plugin_t *lp = &pm->plugins[i];
    if (lp->action_handle) {
      // Action handle embeds vtable as first field
      action_t *a = (action_t *)lp->action_handle;
      if (a->on_event) {
        if (a->on_event(a, event, dry_run) == 0) {
          handled++;
        }
      }
    }
  }
  return handled;
}

// ─────────────────────────────────────────────────────────────────────────────
// Global service lookup
// ─────────────────────────────────────────────────────────────────────────────

static plugin_manager_t *g_plugin_manager = NULL;

void plugin_init(plugin_manager_t *pm) { g_plugin_manager = pm; }

void *plugin_get_service(int service_type) {
  if (!g_plugin_manager)
    return NULL;

  switch (service_type) {
  case PLUGIN_SERVICE_MANAGER:
    return g_plugin_manager;
  case PLUGIN_SERVICE_STORAGE:
    return plugin_manager_get_handle(g_plugin_manager,
                                     PRESSURED_PLUGIN_TYPE_STORAGE);
  default:
    return NULL;
  }
}
