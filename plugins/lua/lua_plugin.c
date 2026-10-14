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
#include "fixed_buffer.h"
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
#include <time.h>

// ─────────────────────────────────────────────────────────────────────────────
// Plugin context (global state)
// ─────────────────────────────────────────────────────────────────────────────

typedef struct {
  char script[PATH_MAX];      // Single script path
  char scripts_dir[PATH_MAX]; // Directory with multiple .lua files
  char *inline_script;        // Inline Lua code
  int timeout_ms;             // Script timeout (default: 5000)
} lua_plugin_config_t;

struct pressured_plugin_ctx {
  char *config_json;       // Full config JSON for Lua global 'config' table
  lua_plugin_config_t cfg; // Parsed plugin config
  service_registry_t *sr;  // Service registry for storage access
};

static int64_t monotonic_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

int lua_budget_remaining(lua_State *L) {
  lua_budget_t *budget = *(lua_budget_t **)lua_getextraspace(L);
  if (!budget || !budget->active)
    return 0;
  int64_t remaining = budget->deadline_ns - monotonic_ns();
  if (remaining <= 0)
    return -1;
  return (int)((remaining + 999999) / 1000000);
}

// Lua skips hooks inside __gc finalizers, so a nonreturning finalizer cannot be
// interrupted.
static void timeout_hook(lua_State *L, lua_Debug *ar) {
  (void)ar;
  if (lua_budget_remaining(L) < 0) {
    lua_budget_t *budget = *(lua_budget_t **)lua_getextraspace(L);
    luaL_error(L, "timeout after %d ms", budget->timeout_ms);
  }
}

// Only the outer call starts a budget; stream callbacks share its deadline.
static int budget_pcall(lua_State *L, int nargs, int nresults) {
  lua_budget_t *budget = *(lua_budget_t **)lua_getextraspace(L);
  if (budget->timeout_ms <= 0) // No limit configured
    return lua_pcall(L, nargs, nresults, 0);
  budget->deadline_ns = monotonic_ns() + (int64_t)budget->timeout_ms * 1000000;
  budget->active = 1;
  lua_sethook(L, timeout_hook, LUA_MASKCOUNT, 1000);
  int status = lua_pcall(L, nargs, nresults, 0);
  lua_sethook(L, NULL, 0, 0);
  budget->active = 0;
  return status;
}

static int run_script(lua_State *L, const char *source, int is_file) {
  int status = is_file ? luaL_loadfile(L, source) : luaL_loadstring(L, source);
  return status == LUA_OK ? budget_pcall(L, 0, 0) : status;
}

// Parse plugin config from plugins.lua section of full config JSON
static int parse_plugin_config(pressured_plugin_ctx_t *ctx,
                               const char *config_json) {
  ctx->cfg.timeout_ms = 5000; // Default

  if (!config_json)
    return 0;

  struct json_object *root = json_tokener_parse(config_json);
  if (!root)
    return 0;

  // Look for plugins.lua section
  struct json_object *plugins, *lua_cfg;
  if (json_object_object_get_ex(root, "plugins", &plugins) &&
      json_object_object_get_ex(plugins, "lua", &lua_cfg)) {

    struct json_object *val;
    if (json_object_object_get_ex(lua_cfg, "script", &val)) {
      if (buffer_copy(ctx->cfg.script, sizeof(ctx->cfg.script),
                      json_object_get_string(val), "Lua script path") != 0) {
        json_object_put(root);
        return -1;
      }
    }
    if (json_object_object_get_ex(lua_cfg, "scripts_dir", &val)) {
      if (buffer_copy(ctx->cfg.scripts_dir, sizeof(ctx->cfg.scripts_dir),
                      json_object_get_string(val),
                      "Lua scripts_dir path") != 0) {
        json_object_put(root);
        return -1;
      }
    }
    if (json_object_object_get_ex(lua_cfg, "inline_script", &val)) {
      ctx->cfg.inline_script = strdup(json_object_get_string(val));
    }
    if (json_object_object_get_ex(lua_cfg, "timeout_ms", &val)) {
      ctx->cfg.timeout_ms = json_object_get_int(val);
    }
  }

  json_object_put(root);
  return 0;
}

// Retain the handlers table even if a script replaces its global alias.
static int init_handlers_registry(lua_State *L) {
  lua_newtable(L);
  lua_pushvalue(L, -1);
  lua_setglobal(L, "_pressured_handlers");
  return luaL_ref(L, LUA_REGISTRYINDEX);
}

// Capture current on_event (if any) into the handlers registry
// Call this AFTER loading each script
static void capture_handler(lua_State *L, int handlers_ref,
                            const char *script_name) {
  lua_getglobal(L, "on_event");
  if (!lua_isfunction(L, -1)) {
    lua_pop(L, 1);
    return;
  }

  // Get the handlers table
  lua_rawgeti(L, LUA_REGISTRYINDEX, handlers_ref);
  int idx = (int)lua_rawlen(L, -1) + 1;

  // Store handler with metadata: {func=on_event, name=script_name}
  lua_newtable(L);
  lua_pushvalue(L, -3); // Copy the on_event function
  lua_setfield(L, -2, "func");
  lua_pushstring(L, script_name);
  lua_setfield(L, -2, "name");

  lua_rawseti(L, -2, idx); // handlers[idx] = {func=..., name=...}
  lua_pop(L, 1);           // Pop handlers table

  // Clear the global on_event to avoid confusion
  lua_pushnil(L);
  lua_setglobal(L, "on_event");

  lua_pop(L, 1); // Pop the original on_event function

  log_debug("lua plugin: captured on_event from %s (handler #%d)", script_name,
            idx);
}

static int filename_compare(const struct dirent **a, const struct dirent **b) {
  return strcmp((*a)->d_name, (*b)->d_name);
}

static int lua_filename(const struct dirent *entry) {
  size_t len = strlen(entry->d_name);
  return entry->d_name[0] != '.' && len >= 5 &&
         strcmp(entry->d_name + len - 4, ".lua") == 0;
}

// Load all .lua files from a directory into Lua state
// Returns: number of files loaded, -1 on error
static int load_scripts_from_dir(lua_State *L, const char *dir_path,
                                 int *handlers_ref) {
  struct dirent **entries = NULL;
  int count = scandir(dir_path, &entries, lua_filename, filename_compare);
  if (count < 0) {
    log_error("lua plugin: cannot open scripts_dir: %s", dir_path);
    return -1;
  }

  *handlers_ref = init_handlers_registry(L);
  int loaded = 0;
  for (int i = 0; i < count; i++) {
    char path[PATH_MAX];
    if (buffer_format(path, sizeof(path), "Lua script path", "%s/%s", dir_path,
                      entries[i]->d_name) != 0) {
      loaded = -1;
      break;
    }
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
      continue;

    if (run_script(L, path, 1) != LUA_OK) {
      log_error("lua plugin: failed to load %s: %s", path, lua_tostring(L, -1));
      lua_pop(L, 1);
      loaded = -1;
      break;
    }
    log_info("lua plugin: loaded %s", path);
    loaded++;
    capture_handler(L, *handlers_ref, entries[i]->d_name);
  }
  for (int i = 0; i < count; i++)
    free(entries[i]);
  free(entries);

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
  lua_budget_t budget;
  int dispatcher;
  int handlers_ref;
  char script_path[PATH_MAX];
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

  lua_State *L = la->L;
  int base = lua_gettop(L);
  push_event(L, event);
  int event_idx = lua_gettop(L);
  lua_getglobal(L, "ctx");
  int ctx_idx = lua_gettop(L);
  lua_pushboolean(L, dry_run);
  lua_setfield(L, ctx_idx, "dry_run");

  if (la->dispatcher) {
    lua_rawgeti(L, LUA_REGISTRYINDEX, la->handlers_ref);
    int handlers = lua_gettop(L);
    size_t count = lua_rawlen(L, handlers);
    for (size_t i = 1; i <= count; i++) {
      lua_rawgeti(L, handlers, i);
      if (!lua_istable(L, -1)) {
        log_error("[dispatcher] ? error: handler #%zu is not a table", i);
        lua_settop(L, handlers);
        continue;
      }
      lua_pushliteral(L, "name");
      lua_rawget(L, -2);
      const char *name = lua_tostring(L, -1);
      lua_pushliteral(L, "func");
      lua_rawget(L, -3);
      if (!lua_isfunction(L, -1)) {
        log_error("[dispatcher] %s error: func is not a function",
                  name ? name : "?");
        lua_settop(L, handlers);
        continue;
      }
      lua_pushvalue(L, event_idx);
      lua_pushvalue(L, ctx_idx);
      int status = budget_pcall(L, 2, 1);
      const char *result = lua_tostring(L, -1);
      if (!result)
        result = lua_isboolean(L, -1)
                     ? (lua_toboolean(L, -1) ? "true" : "false")
                     : luaL_typename(L, -1);
      if (status != LUA_OK)
        log_error("[dispatcher] %s error: %s", name ? name : "?", result);
      else
        log_debug("[dispatcher] %s returned: %s", name ? name : "?", result);
      lua_settop(L, handlers);
    }
  } else {
    lua_getglobal(L, "on_event");
    if (!lua_isfunction(L, -1)) {
      lua_settop(L, base);
      return -1;
    }
    lua_pushvalue(L, event_idx);
    lua_pushvalue(L, ctx_idx);
    if (budget_pcall(L, 2, 1) != LUA_OK) {
      const char *error = lua_tostring(L, -1);
      log_error("lua plugin: on_event error: %s", error ? error : "Lua error");
      lua_settop(L, base);
      return -1;
    }
    const char *result = lua_tostring(L, -1);
    if (result)
      log_debug("lua plugin: on_event returned: %s", result);
  }
  lua_settop(L, base);

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
  a->handlers_ref = LUA_NOREF;

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

  a->budget.timeout_ms = ctx->cfg.timeout_ms;
  *(lua_budget_t **)lua_getextraspace(a->L) = &a->budget;
  luaL_openlibs(a->L);

  // Register bindings
  lua_register_log(a->L);
  lua_register_ctx(a->L);
  lua_register_http(a->L, a->http_client);
  lua_register_storage(a->L, ctx->sr);
  register_config(a->L, ctx->config_json);

  // Load script(s) from plugins.lua config
  if (buffer_copy(a->script_path, sizeof(a->script_path), ctx->cfg.script,
                  "Lua script path") != 0)
    goto fail;
  a->inline_script =
      ctx->cfg.inline_script ? strdup(ctx->cfg.inline_script) : NULL;
  const char *scripts_dir = ctx->cfg.scripts_dir;

  if (a->script_path[0]) {
    // Load single script file
    if (run_script(a->L, a->script_path, 1) != LUA_OK) {
      log_error("lua plugin: failed to load %s: %s", a->script_path,
                lua_tostring(a->L, -1));
      goto fail;
    }
    log_info("lua plugin: loaded script %s", a->script_path);
  } else if (scripts_dir[0]) {
    a->dispatcher = 1;
    // Load all .lua files from directory
    int loaded = load_scripts_from_dir(a->L, scripts_dir, &a->handlers_ref);
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
    if (run_script(a->L, a->inline_script, 0) != LUA_OK) {
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

    if (run_script(a->L, default_script, 0) != LUA_OK) {
      log_error("lua plugin: failed to load default script: %s",
                lua_tostring(a->L, -1));
      goto fail;
    }
    log_info("lua plugin: using default script");
  }

  // Verify at least one handler exists.
  if (a->dispatcher)
    lua_rawgeti(a->L, LUA_REGISTRYINDEX, a->handlers_ref);
  else
    lua_getglobal(a->L, "on_event");
  if (a->dispatcher ? lua_rawlen(a->L, -1) == 0 : !lua_isfunction(a->L, -1)) {
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
  if (parse_plugin_config(ctx, config_json) != 0) {
    free(ctx->config_json);
    free(ctx->cfg.inline_script);
    free(ctx);
    return NULL;
  }

  /* Register action service with the registry */
  int rc = service_registry_register(
      sr, &action_service_meta, SERVICE_SCOPE_SINGLETON, lua_action_factory,
      lua_action_destructor, ctx);
  if (rc != 0) {
    log_error("lua: failed to register with service registry");
    free(ctx->config_json);
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
  free(ctx->cfg.inline_script);
  free(ctx);
  log_info("lua plugin unloaded");
}
