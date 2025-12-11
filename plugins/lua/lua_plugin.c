/**
 * Lua Plugin for Pressured
 *
 * Loads and executes Lua scripts on memory pressure events.
 * Uses the 3-symbol plugin protocol (get_metadata, load, unload).
 *
 * Lua API:
 *   log.trace/debug/info/warn/error(msg)
 *   ctx.time_iso(), ctx.getenv(name)
 *   http.fetch(), http.download(), http.stream(), http.urlencode()
 *   http.set_bearer_token(), http.set_basic_auth()
 *   storage.write(), storage.read(), storage.exists(), storage.remove()
 *   storage.open() -> file:write(), file:read(), file:close()
 *   config   - Lua table from JSON config
 *   event    - OOM event data (in on_event callback)
 */

#include "bindings.h"
#include "log.h"
#include "plugin.h"
#include "pressured.h"
#include "service_registry.h"
#include <dirent.h>
#include <json-c/json.h>
#include <lauxlib.h>
#include <limits.h>
#include <lua.h>
#include <lualib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

// ─────────────────────────────────────────────────────────────────────────────
// Plugin context (global state)
// ─────────────────────────────────────────────────────────────────────────────

typedef struct {
  char *script;        // Single script path
  char *scripts_dir;   // Directory with multiple .lua files
  char *inline_script; // Inline Lua code
  int timeout_ms;      // Script timeout (default: 5000)
} lua_plugin_config_t;

struct pressured_plugin_ctx {
  char *config_json;       // Full config JSON for Lua global 'config' table
  lua_plugin_config_t cfg; // Parsed plugin config
  service_registry_t *sr;  // Service registry for storage access
};

// Parse plugin config from plugins.lua section of full config JSON
static void parse_plugin_config(pressured_plugin_ctx_t *ctx,
                                const char *config_json) {
  ctx->cfg.timeout_ms = 5000; // Default

  if (!config_json)
    return;

  struct json_object *root = json_tokener_parse(config_json);
  if (!root)
    return;

  // Look for plugins.lua section
  struct json_object *plugins, *lua_cfg;
  if (json_object_object_get_ex(root, "plugins", &plugins) &&
      json_object_object_get_ex(plugins, "lua", &lua_cfg)) {

    struct json_object *val;
    if (json_object_object_get_ex(lua_cfg, "script", &val)) {
      ctx->cfg.script = strdup(json_object_get_string(val));
    }
    if (json_object_object_get_ex(lua_cfg, "scripts_dir", &val)) {
      ctx->cfg.scripts_dir = strdup(json_object_get_string(val));
    }
    if (json_object_object_get_ex(lua_cfg, "inline_script", &val)) {
      ctx->cfg.inline_script = strdup(json_object_get_string(val));
    }
    if (json_object_object_get_ex(lua_cfg, "timeout_ms", &val)) {
      ctx->cfg.timeout_ms = json_object_get_int(val);
    }
  }

  json_object_put(root);
}

// Initialize the handlers registry table
static void init_handlers_registry(lua_State *L) {
  lua_newtable(L);
  lua_setglobal(L, "_pressured_handlers");
}

// Capture current on_event (if any) into the handlers registry
// Call this AFTER loading each script
static void capture_handler(lua_State *L, const char *script_name) {
  lua_getglobal(L, "on_event");
  if (!lua_isfunction(L, -1)) {
    lua_pop(L, 1);
    return;
  }

  // Get the handlers table
  lua_getglobal(L, "_pressured_handlers");
  int idx = (int)lua_rawlen(L, -1) + 1;

  // Store handler with metadata: {func=on_event, name=script_name}
  lua_newtable(L);
  lua_pushvalue(L, -3); // Copy the on_event function
  lua_setfield(L, -2, "func");
  lua_pushstring(L, script_name);
  lua_setfield(L, -2, "name");

  lua_rawseti(L, -2, idx); // _pressured_handlers[idx] = {func=..., name=...}
  lua_pop(L, 1);           // Pop _pressured_handlers

  // Clear the global on_event to avoid confusion
  lua_pushnil(L);
  lua_setglobal(L, "on_event");

  lua_pop(L, 1); // Pop the original on_event function

  log_debug("lua plugin: captured on_event from %s (handler #%d)", script_name,
            idx);
}

// Create dispatcher on_event that calls all registered handlers
static int install_dispatcher(lua_State *L) {
  const char *dispatcher_code =
      "function on_event(event, ctx)\n"
      "  local results = {}\n"
      "  for i, handler in ipairs(_pressured_handlers) do\n"
      "    local ok, result = pcall(handler.func, event, ctx)\n"
      "    if ok then\n"
      "      log.debug(string.format('[dispatcher] %s returned: %s', "
      "handler.name, tostring(result)))\n"
      "      table.insert(results, result)\n"
      "    else\n"
      "      log.error(string.format('[dispatcher] %s error: %s', "
      "handler.name, tostring(result)))\n"
      "    end\n"
      "  end\n"
      "  return table.concat(results, ',')\n"
      "end\n";

  if (luaL_dostring(L, dispatcher_code) != LUA_OK) {
    log_error("lua plugin: failed to install dispatcher: %s",
              lua_tostring(L, -1));
    lua_pop(L, 1);
    return -1;
  }

  // Count handlers
  lua_getglobal(L, "_pressured_handlers");
  int count = (int)lua_rawlen(L, -1);
  lua_pop(L, 1);

  log_info("lua plugin: dispatcher installed for %d handler(s)", count);
  return count;
}

// Load all .lua files from a directory into Lua state
// Returns: number of files loaded, -1 on error
static int load_scripts_from_dir(lua_State *L, const char *dir_path) {
  DIR *dir = opendir(dir_path);
  if (!dir) {
    log_error("lua plugin: cannot open scripts_dir: %s", dir_path);
    return -1;
  }

  // Initialize handlers registry for multi-script support
  init_handlers_registry(L);

  int loaded = 0;
  const struct dirent *entry;

  while ((entry = readdir(dir)) != NULL) {
    // Skip . and ..
    if (entry->d_name[0] == '.')
      continue;

    // Check for .lua extension
    size_t len = strlen(entry->d_name);
    if (len < 5 || strcmp(entry->d_name + len - 4, ".lua") != 0)
      continue;

    // Build full path
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);

    // Verify it's a regular file
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
      continue;

    // Load the script
    if (luaL_dofile(L, path) != LUA_OK) {
      log_error("lua plugin: failed to load %s: %s", path, lua_tostring(L, -1));
      lua_pop(L, 1);
      closedir(dir);
      return -1;
    }

    log_info("lua plugin: loaded %s", path);
    loaded++;

    // Capture the on_event handler from this script (if any)
    capture_handler(L, entry->d_name);
  }

  closedir(dir);

  // Install dispatcher if we have multiple handlers
  if (loaded > 0) {
    lua_getglobal(L, "_pressured_handlers");
    int handler_count = (int)lua_rawlen(L, -1);
    lua_pop(L, 1);

    if (handler_count > 0) {
      if (install_dispatcher(L) < 0) {
        return -1;
      }
    }
  }

  return loaded;
}

// ─────────────────────────────────────────────────────────────────────────────
// Action handle (per-instance state)
// ─────────────────────────────────────────────────────────────────────────────

// Forward declare on_event for vtable
static int lua_on_event(action_t *a, const pressured_event_t *event,
                        int dry_run);

typedef struct {
  action_t base; // MUST be first - embedded vtable
  lua_State *L;
  char *script_path;
  char *inline_script;
  http_client_t *http_client;
  struct pressured_plugin_ctx *ctx;
} lua_action_t;

// ─────────────────────────────────────────────────────────────────────────────
// JSON to Lua conversion
// ─────────────────────────────────────────────────────────────────────────────

static void json_to_lua(lua_State *L, struct json_object *obj) {
  if (!obj) {
    lua_pushnil(L);
    return;
  }

  switch (json_object_get_type(obj)) {
  case json_type_null:
    lua_pushnil(L);
    break;
  case json_type_boolean:
    lua_pushboolean(L, json_object_get_boolean(obj));
    break;
  case json_type_int:
    lua_pushinteger(L, json_object_get_int64(obj));
    break;
  case json_type_double:
    lua_pushnumber(L, json_object_get_double(obj));
    break;
  case json_type_string:
    lua_pushstring(L, json_object_get_string(obj));
    break;
  case json_type_array: {
    int len = json_object_array_length(obj);
    lua_createtable(L, len, 0);
    for (int i = 0; i < len; i++) {
      json_to_lua(L, json_object_array_get_idx(obj, i));
      lua_rawseti(L, -2, i + 1);
    }
    break;
  }
  case json_type_object: {
    lua_newtable(L);
    struct json_object_iterator it = json_object_iter_begin(obj);
    struct json_object_iterator end = json_object_iter_end(obj);
    while (!json_object_iter_equal(&it, &end)) {
      json_to_lua(L, json_object_iter_peek_value(&it));
      lua_setfield(L, -2, json_object_iter_peek_name(&it));
      json_object_iter_next(&it);
    }
    break;
  }
  default:
    lua_pushnil(L);
    break;
  }
}

static void register_config(lua_State *L, const char *config_json_str) {
  if (config_json_str) {
    struct json_object *root = json_tokener_parse(config_json_str);
    if (root) {
      json_to_lua(L, root);
      json_object_put(root);
    } else {
      log_warn("lua plugin: failed to parse config JSON");
      lua_newtable(L);
    }
  } else {
    lua_newtable(L);
  }
  lua_setglobal(L, "config");
}

// ─────────────────────────────────────────────────────────────────────────────
// Event handling
// ─────────────────────────────────────────────────────────────────────────────

static void push_event(lua_State *L, const pressured_event_t *event) {
  lua_newtable(L);

  // Event type: "memory_pressure" or "oom_killed"
  lua_pushstring(L, pressured_event_type_str(event->event_type));
  lua_setfield(L, -2, "event_type");

  lua_pushstring(L, event->sample.namespace);
  lua_setfield(L, -2, "namespace");

  lua_pushstring(L, event->sample.pod_name);
  lua_setfield(L, -2, "pod_name");

  if (event->sample.pod_uid) {
    lua_pushstring(L, event->sample.pod_uid);
    lua_setfield(L, -2, "pod_uid");
  }

  lua_pushstring(L, event->sample.container_name);
  lua_setfield(L, -2, "container_name");

  if (event->sample.node_name) {
    lua_pushstring(L, event->sample.node_name);
    lua_setfield(L, -2, "node_name");
  }

  if (event->sample.pod_ip) {
    lua_pushstring(L, event->sample.pod_ip);
    lua_setfield(L, -2, "pod_ip");
  }

  lua_pushinteger(L, event->sample.usage_bytes);
  lua_setfield(L, -2, "usage_bytes");

  lua_pushinteger(L, event->sample.limit_bytes);
  lua_setfield(L, -2, "limit_bytes");

  lua_pushnumber(L, event->sample.usage_percent * 100.0);
  lua_setfield(L, -2, "usage_percent");

  lua_pushinteger(L, event->sample.oom_kill_count);
  lua_setfield(L, -2, "oom_kill_count");

  lua_pushstring(L, pressured_severity_str(event->severity));
  lua_setfield(L, -2, "severity");

  lua_pushstring(L, pressured_severity_str(event->previous_severity));
  lua_setfield(L, -2, "previous_severity");

  // Add annotations as Lua table (directly from array)
  lua_newtable(L);
  if (event->sample.annotations && event->sample.annotations_count > 0) {
    for (int i = 0; i < event->sample.annotations_count; i++) {
      if (event->sample.annotations[i].key) {
        lua_pushstring(L, event->sample.annotations[i].value
                              ? event->sample.annotations[i].value
                              : "");
        lua_setfield(L, -2, event->sample.annotations[i].key);
      }
    }
  }
  lua_setfield(L, -2, "annotations");
}

// Called via vtable by plugin manager
static int lua_on_event(action_t *a, const pressured_event_t *event,
                        int dry_run) {
  lua_action_t *la = (lua_action_t *)a;
  if (!la || !la->L)
    return -1;

  lua_getglobal(la->L, "on_event");
  if (!lua_isfunction(la->L, -1)) {
    lua_pop(la->L, 1);
    return -1;
  }

  push_event(la->L, event);

  lua_getglobal(la->L, "ctx");
  lua_pushboolean(la->L, dry_run);
  lua_setfield(la->L, -2, "dry_run");

  if (lua_pcall(la->L, 2, 1, 0) != LUA_OK) {
    log_error("lua plugin: on_event error: %s", lua_tostring(la->L, -1));
    lua_pop(la->L, 1);
    return -1;
  }

  const char *result = lua_tostring(la->L, -1);
  if (result) {
    log_debug("lua plugin: on_event returned: %s", result);
  }
  lua_pop(la->L, 1);

  return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Action handle creation
// ─────────────────────────────────────────────────────────────────────────────

static lua_action_t *lua_action_create(pressured_plugin_ctx_t *ctx) {
  lua_action_t *a = calloc(1, sizeof(lua_action_t));
  if (!a)
    return NULL;

  // Initialize embedded vtable
  a->base.on_event = lua_on_event;
  a->ctx = ctx;

  // Create HTTP client
  http_opts_t http_opts = {.timeout_ms = 30000, .connect_timeout_ms = 10000};
  a->http_client = http_client_new(&http_opts);
  if (!a->http_client) {
    log_error("lua plugin: failed to create HTTP client");
    free(a);
    return NULL;
  }

  // Create Lua state
  a->L = luaL_newstate();
  if (!a->L) {
    log_error("lua plugin: failed to create Lua state");
    http_client_free(a->http_client);
    free(a);
    return NULL;
  }

  luaL_openlibs(a->L);

  // Register bindings
  lua_register_log(a->L);
  lua_register_ctx(a->L);
  lua_register_http(a->L, a->http_client);
  lua_register_storage(a->L, ctx->sr);
  register_config(a->L, ctx->config_json);

  // Load script(s) from plugins.lua config
  a->script_path = ctx->cfg.script ? strdup(ctx->cfg.script) : NULL;
  a->inline_script =
      ctx->cfg.inline_script ? strdup(ctx->cfg.inline_script) : NULL;
  const char *scripts_dir = ctx->cfg.scripts_dir;

  if (a->script_path) {
    // Load single script file
    if (luaL_dofile(a->L, a->script_path) != LUA_OK) {
      log_error("lua plugin: failed to load %s: %s", a->script_path,
                lua_tostring(a->L, -1));
      goto fail;
    }
    log_info("lua plugin: loaded script %s", a->script_path);
  } else if (scripts_dir) {
    // Load all .lua files from directory
    int loaded = load_scripts_from_dir(a->L, scripts_dir);
    if (loaded < 0) {
      goto fail;
    }
    if (loaded == 0) {
      log_warn("lua plugin: no .lua files found in %s", scripts_dir);
    } else {
      log_info("lua plugin: loaded %d script(s) from %s", loaded, scripts_dir);
    }
  } else if (a->inline_script) {
    // Load inline script
    if (luaL_dostring(a->L, a->inline_script) != LUA_OK) {
      log_error("lua plugin: failed to load inline script: %s",
                lua_tostring(a->L, -1));
      goto fail;
    }
    log_info("lua plugin: loaded inline script");
  } else {
    // Use default script
    const char *default_script =
        "function on_event(event, ctx)\n"
        "  log.info(string.format('Memory event: %s/%s at %.1f%%',\n"
        "    event.namespace, event.pod_name, event.usage_percent))\n"
        "  return 'ok'\n"
        "end\n";

    if (luaL_dostring(a->L, default_script) != LUA_OK) {
      log_error("lua plugin: failed to load default script: %s",
                lua_tostring(a->L, -1));
      goto fail;
    }
    log_info("lua plugin: using default script");
  }

  // Verify on_event exists
  lua_getglobal(a->L, "on_event");
  if (!lua_isfunction(a->L, -1)) {
    log_error("lua plugin: script must define 'on_event' function");
    lua_pop(a->L, 1);
    goto fail;
  }
  lua_pop(a->L, 1);

  log_info("lua action handle created");
  return a;

fail:
  lua_settop(a->L, 0); // Clear stack (safe regardless of current state)
  lua_close(a->L);
  http_client_free(a->http_client);
  free(a->script_path);
  free(a->inline_script);
  free(a);
  return NULL;
}

static void lua_action_destroy(lua_action_t *a) {
  if (!a)
    return;

  if (a->L)
    lua_close(a->L);
  if (a->http_client)
    http_client_free(a->http_client);
  free(a->script_path);
  free(a->inline_script);
  free(a);

  log_info("lua action handle destroyed");
}

// ─────────────────────────────────────────────────────────────────────────────
// Service Metadata (for service registry)
// ─────────────────────────────────────────────────────────────────────────────

static const char *lua_tags[] = {"scripting", "lua", NULL};

static const service_metadata_t action_service_meta = {
    .type = "action",
    .provider = "lua",
    .version = "1.0.0",
    .description = "Execute Lua scripts on memory events",
    .priority = 100, /* Default action handler */
    .tags = lua_tags,
    .dependencies = NULL,
    .interface_version = 1,
};

// ─────────────────────────────────────────────────────────────────────────────
// Plugin Metadata
// ─────────────────────────────────────────────────────────────────────────────

static const pressured_plugin_metadata_t metadata = {
    .name = "lua",
    .major_version = 1,
    .minor_version = 0,
    .description = "Execute Lua scripts on memory events",
};

PRESSURED_PLUGIN_EXPORT const pressured_plugin_metadata_t *
pressured_plugin_get_metadata(void) {
  return &metadata;
}

// ─────────────────────────────────────────────────────────────────────────────
// Service Factory
// ─────────────────────────────────────────────────────────────────────────────

static void *lua_action_factory(void *userdata) {
  pressured_plugin_ctx_t *ctx = userdata;

  lua_action_t *a = lua_action_create(ctx);
  if (!a)
    return NULL;

  log_debug("lua: created action instance");
  return a;
}

static void lua_action_destructor(void *instance, void *userdata) {
  (void)userdata;
  if (instance) {
    log_debug("lua: destroyed action instance");
    lua_action_destroy((lua_action_t *)instance);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Plugin Lifecycle
// ─────────────────────────────────────────────────────────────────────────────

PRESSURED_PLUGIN_EXPORT pressured_plugin_ctx_t *
pressured_plugin_load(const char *config_json, service_registry_t *sr) {
  pressured_plugin_ctx_t *ctx = calloc(1, sizeof(pressured_plugin_ctx_t));
  if (!ctx)
    return NULL;

  if (config_json) {
    ctx->config_json = strdup(config_json);
  }

  // Store service registry for storage access
  ctx->sr = sr;

  // Parse plugin-specific config from plugins.lua section
  parse_plugin_config(ctx, config_json);

  /* Register action service with the registry */
  int rc = service_registry_register(sr, &action_service_meta,
                                     SERVICE_SCOPE_SINGLETON, lua_action_factory,
                                     lua_action_destructor, ctx);
  if (rc != 0) {
    log_error("lua: failed to register with service registry");
    free(ctx->config_json);
    free(ctx->cfg.script);
    free(ctx->cfg.scripts_dir);
    free(ctx->cfg.inline_script);
    free(ctx);
    return NULL;
  }

  log_info("lua plugin loaded");
  return ctx;
}

PRESSURED_PLUGIN_EXPORT void
pressured_plugin_unload(pressured_plugin_ctx_t *ctx) {
  if (!ctx)
    return;
  free(ctx->config_json);
  free(ctx->cfg.script);
  free(ctx->cfg.scripts_dir);
  free(ctx->cfg.inline_script);
  free(ctx);
  log_info("lua plugin unloaded");
}
