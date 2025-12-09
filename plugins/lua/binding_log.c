/*
 * Lua Log and Context Bindings
 *
 * log.trace(msg), log.debug(msg), log.info(msg), log.warn(msg), log.error(msg)
 * ctx.time_iso(), ctx.getenv(name)
 */

#include "bindings.h"
#include "log.h"
#include <lauxlib.h>
#include <stdlib.h>
#include <time.h>

// ─────────────────────────────────────────────────────────────────────────────
// Log functions
// ─────────────────────────────────────────────────────────────────────────────

static int lua_log_trace(lua_State *L) {
  const char *msg = luaL_checkstring(L, 1);
  log_trace("[lua] %s", msg);
  return 0;
}

static int lua_log_debug(lua_State *L) {
  const char *msg = luaL_checkstring(L, 1);
  log_debug("[lua] %s", msg);
  return 0;
}

static int lua_log_info(lua_State *L) {
  const char *msg = luaL_checkstring(L, 1);
  log_info("[lua] %s", msg);
  return 0;
}

static int lua_log_warn(lua_State *L) {
  const char *msg = luaL_checkstring(L, 1);
  log_warn("[lua] %s", msg);
  return 0;
}

static int lua_log_error(lua_State *L) {
  const char *msg = luaL_checkstring(L, 1);
  log_error("[lua] %s", msg);
  return 0;
}

void lua_register_log(lua_State *L) {
  lua_newtable(L);

  lua_pushcfunction(L, lua_log_trace);
  lua_setfield(L, -2, "trace");

  lua_pushcfunction(L, lua_log_debug);
  lua_setfield(L, -2, "debug");

  lua_pushcfunction(L, lua_log_info);
  lua_setfield(L, -2, "info");

  lua_pushcfunction(L, lua_log_warn);
  lua_setfield(L, -2, "warn");

  lua_pushcfunction(L, lua_log_error);
  lua_setfield(L, -2, "error");

  lua_setglobal(L, "log");
}

// ─────────────────────────────────────────────────────────────────────────────
// Context functions
// ─────────────────────────────────────────────────────────────────────────────

static int lua_time_iso(lua_State *L) {
  time_t now = time(NULL);
  struct tm tm_buf;
  const struct tm *tm = gmtime_r(&now, &tm_buf);
  char buf[64];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", tm);
  lua_pushstring(L, buf);
  return 1;
}

static int lua_getenv(lua_State *L) {
  const char *name = luaL_checkstring(L, 1);
  const char *value = getenv(name);
  if (value) {
    lua_pushstring(L, value);
  } else {
    lua_pushnil(L);
  }
  return 1;
}

void lua_register_ctx(lua_State *L) {
  lua_newtable(L);

  lua_pushcfunction(L, lua_time_iso);
  lua_setfield(L, -2, "time_iso");

  lua_pushcfunction(L, lua_getenv);
  lua_setfield(L, -2, "getenv");

  lua_setglobal(L, "ctx");
}
