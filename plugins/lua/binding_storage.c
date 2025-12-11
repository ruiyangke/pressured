/*
 * Lua Storage Bindings
 *
 * Provides two API styles:
 *
 * Simple API (buffers in memory):
 *   storage.write(key, data) -> {ok, error}
 *   storage.read(key)        -> {ok, data, error}
 *   storage.exists(key)      -> bool
 *   storage.remove(key)      -> {ok, error}
 *   storage.rename(old, new) -> {ok, error}
 *
 * Streaming API (for large files):
 *   local f = storage.open(key, "w")
 *   f:write(data)            -> bytes_written
 *   f:close()                -> bool
 *
 *   local f = storage.open(key, "r")
 *   local data = f:read(size) -> data or nil
 *   f:close()                -> bool
 */

#include "bindings.h"
#include "log.h"
#include "service_registry.h"
#include <lauxlib.h>
#include <stdlib.h>
#include <string.h>

// Userdata for file handles
typedef struct {
  storage_t *storage;
  storage_file_t *file;
  int mode; // STORAGE_MODE_READ or STORAGE_MODE_WRITE
} lua_storage_file_t;

#define LUA_STORAGE_FILE_MT "storage_file"

// Get storage from service registry stored in Lua registry
// Acquires storage lazily at runtime (allows storage plugins to load after
// action plugins)
static storage_t *get_storage(lua_State *L) {
  // First check if we already have a cached storage pointer
  lua_getfield(L, LUA_REGISTRYINDEX, LUA_REG_STORAGE);
  if (!lua_isnil(L, -1)) {
    storage_t *s = (storage_t *)lua_touserdata(L, -1);
    lua_pop(L, 1);
    return s;
  }
  lua_pop(L, 1);

  // Get service registry from Lua registry
  lua_getfield(L, LUA_REGISTRYINDEX, LUA_REG_SERVICE_REGISTRY);
  if (lua_isnil(L, -1)) {
    lua_pop(L, 1);
    log_debug("lua_storage: no service registry available");
    return NULL;
  }
  service_registry_t *sr = (service_registry_t *)lua_touserdata(L, -1);
  lua_pop(L, 1);

  if (!sr) {
    return NULL;
  }

  // Acquire storage service
  service_ref_t ref = service_registry_acquire(sr, "storage");
  if (!service_ref_valid(&ref)) {
    log_debug("lua_storage: no storage service registered");
    return NULL;
  }

  storage_t *s = (storage_t *)ref.instance;

  // Cache the storage pointer in Lua registry for future calls
  // Note: We don't release the ref since it's a singleton and we want to keep
  // it
  lua_pushlightuserdata(L, s);
  lua_setfield(L, LUA_REGISTRYINDEX, LUA_REG_STORAGE);

  return s;
}

// ─────────────────────────────────────────────────────────────────────────────
// Simple API
// ─────────────────────────────────────────────────────────────────────────────

/*
 * storage.write(key, data) -> {ok=bool, error=string|nil}
 */
static int lua_storage_write(lua_State *L) {
  const char *key = luaL_checkstring(L, 1);
  size_t len;
  const char *data = luaL_checklstring(L, 2, &len);
  storage_t *s = get_storage(L);

  log_info("lua_storage: storage.write called key=%s len=%zu storage=%p", key,
           len, (void *)s);

  lua_newtable(L);

  if (!s) {
    log_error("lua_storage: storage.write - no storage configured");
    lua_pushboolean(L, 0);
    lua_setfield(L, -2, "ok");
    lua_pushstring(L, "storage not configured");
    lua_setfield(L, -2, "error");
    return 1;
  }

  log_info("lua_storage: storage.write - calling s->open (vtable.open=%p)",
           (void *)s->open);
  storage_file_t *f = s->open(s, key, STORAGE_MODE_WRITE);
  if (!f) {
    lua_pushboolean(L, 0);
    lua_setfield(L, -2, "ok");
    lua_pushstring(L, "failed to open for write");
    lua_setfield(L, -2, "error");
    return 1;
  }

  int64_t written = s->write(f, data, len);
  int rc = s->close(f);

  if (written != (int64_t)len || rc != STORAGE_OK) {
    lua_pushboolean(L, 0);
    lua_setfield(L, -2, "ok");
    lua_pushstring(L, "write failed");
    lua_setfield(L, -2, "error");
    return 1;
  }

  lua_pushboolean(L, 1);
  lua_setfield(L, -2, "ok");
  return 1;
}

/*
 * storage.read(key) -> {ok=bool, data=string, error=string|nil}
 */
static int lua_storage_read(lua_State *L) {
  const char *key = luaL_checkstring(L, 1);
  storage_t *s = get_storage(L);

  lua_newtable(L);

  if (!s) {
    lua_pushboolean(L, 0);
    lua_setfield(L, -2, "ok");
    lua_pushstring(L, "storage not configured");
    lua_setfield(L, -2, "error");
    return 1;
  }

  storage_file_t *f = s->open(s, key, STORAGE_MODE_READ);
  if (!f) {
    lua_pushboolean(L, 0);
    lua_setfield(L, -2, "ok");
    lua_pushstring(L, "file not found");
    lua_setfield(L, -2, "error");
    return 1;
  }

  // Read in chunks and accumulate
  luaL_Buffer buf;
  luaL_buffinit(L, &buf);

  char chunk[8192];
  int64_t n;
  while ((n = s->read(f, chunk, sizeof(chunk))) > 0) {
    luaL_addlstring(&buf, chunk, n);
  }

  s->close(f);

  if (n < 0) {
    lua_pushboolean(L, 0);
    lua_setfield(L, -2, "ok");
    lua_pushstring(L, "read error");
    lua_setfield(L, -2, "error");
    return 1;
  }

  luaL_pushresult(&buf);
  lua_setfield(L, -2, "data");
  lua_pushboolean(L, 1);
  lua_setfield(L, -2, "ok");
  return 1;
}

/*
 * storage.exists(key) -> bool
 */
static int lua_storage_exists(lua_State *L) {
  const char *key = luaL_checkstring(L, 1);
  storage_t *s = get_storage(L);

  if (!s) {
    lua_pushboolean(L, 0);
    return 1;
  }

  lua_pushboolean(L, s->exists(s, key));
  return 1;
}

/*
 * storage.remove(key) -> {ok=bool, error=string|nil}
 */
static int lua_storage_remove(lua_State *L) {
  const char *key = luaL_checkstring(L, 1);
  storage_t *s = get_storage(L);

  lua_newtable(L);

  if (!s) {
    lua_pushboolean(L, 0);
    lua_setfield(L, -2, "ok");
    lua_pushstring(L, "storage not configured");
    lua_setfield(L, -2, "error");
    return 1;
  }

  int rc = s->remove(s, key);
  if (rc == STORAGE_OK) {
    lua_pushboolean(L, 1);
    lua_setfield(L, -2, "ok");
  } else {
    lua_pushboolean(L, 0);
    lua_setfield(L, -2, "ok");
    lua_pushstring(L, storage_strerror(rc));
    lua_setfield(L, -2, "error");
  }
  return 1;
}

/*
 * storage.rename(old_key, new_key) -> {ok=bool, error=string|nil}
 */
static int lua_storage_rename(lua_State *L) {
  const char *old_key = luaL_checkstring(L, 1);
  const char *new_key = luaL_checkstring(L, 2);
  storage_t *s = get_storage(L);

  lua_newtable(L);

  if (!s) {
    lua_pushboolean(L, 0);
    lua_setfield(L, -2, "ok");
    lua_pushstring(L, "storage not configured");
    lua_setfield(L, -2, "error");
    return 1;
  }

  int rc = s->rename(s, old_key, new_key);
  if (rc == STORAGE_OK) {
    lua_pushboolean(L, 1);
    lua_setfield(L, -2, "ok");
  } else {
    lua_pushboolean(L, 0);
    lua_setfield(L, -2, "ok");
    lua_pushstring(L, storage_strerror(rc));
    lua_setfield(L, -2, "error");
  }
  return 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// Streaming API - file handle methods
// ─────────────────────────────────────────────────────────────────────────────

/*
 * file:write(data) -> bytes_written or nil, error
 */
static int lua_file_write(lua_State *L) {
  lua_storage_file_t *sf = luaL_checkudata(L, 1, LUA_STORAGE_FILE_MT);
  size_t len;
  const char *data = luaL_checklstring(L, 2, &len);

  if (!sf->file) {
    lua_pushnil(L);
    lua_pushstring(L, "file closed");
    return 2;
  }

  if (sf->mode != STORAGE_MODE_WRITE) {
    lua_pushnil(L);
    lua_pushstring(L, "file not open for writing");
    return 2;
  }

  int64_t n = sf->storage->write(sf->file, data, len);
  if (n < 0) {
    lua_pushnil(L);
    lua_pushstring(L, "write error");
    return 2;
  }

  lua_pushinteger(L, n);
  return 1;
}

/*
 * file:read(size) -> data or nil (EOF)
 */
static int lua_file_read(lua_State *L) {
  lua_storage_file_t *sf = luaL_checkudata(L, 1, LUA_STORAGE_FILE_MT);
  lua_Integer size = luaL_optinteger(L, 2, 8192);

  if (!sf->file) {
    lua_pushnil(L);
    lua_pushstring(L, "file closed");
    return 2;
  }

  if (sf->mode != STORAGE_MODE_READ) {
    lua_pushnil(L);
    lua_pushstring(L, "file not open for reading");
    return 2;
  }

  if (size <= 0)
    size = 8192;
  if (size > 1024 * 1024)
    size = 1024 * 1024; // Cap at 1MB

  char *buf = malloc(size);
  if (!buf) {
    lua_pushnil(L);
    lua_pushstring(L, "allocation failed");
    return 2;
  }

  int64_t n = sf->storage->read(sf->file, buf, size);
  if (n < 0) {
    free(buf);
    lua_pushnil(L);
    lua_pushstring(L, "read error");
    return 2;
  }

  if (n == 0) {
    free(buf);
    lua_pushnil(L); // EOF
    return 1;
  }

  lua_pushlstring(L, buf, n);
  free(buf);
  return 1;
}

/*
 * file:close() -> bool
 */
static int lua_file_close(lua_State *L) {
  lua_storage_file_t *sf = luaL_checkudata(L, 1, LUA_STORAGE_FILE_MT);

  if (!sf->file) {
    lua_pushboolean(L, 0);
    return 1;
  }

  int rc = sf->storage->close(sf->file);
  sf->file = NULL;

  lua_pushboolean(L, rc == STORAGE_OK);
  return 1;
}

// Garbage collector - close file if not already closed
static int lua_file_gc(lua_State *L) {
  lua_storage_file_t *sf = luaL_checkudata(L, 1, LUA_STORAGE_FILE_MT);
  if (sf->file) {
    sf->storage->close(sf->file);
    sf->file = NULL;
  }
  return 0;
}

/*
 * storage.open(key, mode) -> file handle or nil, error
 *   mode: "r" for read, "w" for write
 */
static int lua_storage_open(lua_State *L) {
  const char *key = luaL_checkstring(L, 1);
  const char *mode_str = luaL_optstring(L, 2, "r");
  storage_t *s = get_storage(L);

  if (!s) {
    lua_pushnil(L);
    lua_pushstring(L, "storage not configured");
    return 2;
  }

  int mode;
  if (mode_str[0] == 'w' || mode_str[0] == 'W') {
    mode = STORAGE_MODE_WRITE;
  } else {
    mode = STORAGE_MODE_READ;
  }

  storage_file_t *f = s->open(s, key, mode);
  if (!f) {
    lua_pushnil(L);
    if (mode == STORAGE_MODE_READ) {
      lua_pushstring(L, "file not found");
    } else {
      lua_pushstring(L, "failed to open for write");
    }
    return 2;
  }

  // Create userdata
  lua_storage_file_t *sf = lua_newuserdata(L, sizeof(lua_storage_file_t));
  sf->storage = s;
  sf->file = f;
  sf->mode = mode;

  // Set metatable
  luaL_getmetatable(L, LUA_STORAGE_FILE_MT);
  lua_setmetatable(L, -2);

  return 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// Registration
// ─────────────────────────────────────────────────────────────────────────────

void lua_register_storage(lua_State *L, service_registry_t *sr) {
  // Store service registry in Lua registry for lazy storage lookup
  if (sr) {
    lua_pushlightuserdata(L, sr);
    lua_setfield(L, LUA_REGISTRYINDEX, LUA_REG_SERVICE_REGISTRY);
  }

  // Create file handle metatable
  luaL_newmetatable(L, LUA_STORAGE_FILE_MT);

  lua_pushcfunction(L, lua_file_write);
  lua_setfield(L, -2, "write");

  lua_pushcfunction(L, lua_file_read);
  lua_setfield(L, -2, "read");

  lua_pushcfunction(L, lua_file_close);
  lua_setfield(L, -2, "close");

  lua_pushcfunction(L, lua_file_gc);
  lua_setfield(L, -2, "__gc");

  // __index = self (methods accessible via :)
  lua_pushvalue(L, -1);
  lua_setfield(L, -2, "__index");

  lua_pop(L, 1); // Pop metatable

  // Create storage table
  lua_newtable(L);

  // Simple API
  lua_pushcfunction(L, lua_storage_write);
  lua_setfield(L, -2, "write");

  lua_pushcfunction(L, lua_storage_read);
  lua_setfield(L, -2, "read");

  lua_pushcfunction(L, lua_storage_exists);
  lua_setfield(L, -2, "exists");

  lua_pushcfunction(L, lua_storage_remove);
  lua_setfield(L, -2, "remove");

  lua_pushcfunction(L, lua_storage_rename);
  lua_setfield(L, -2, "rename");

  // Streaming API
  lua_pushcfunction(L, lua_storage_open);
  lua_setfield(L, -2, "open");

  lua_setglobal(L, "storage");
}
