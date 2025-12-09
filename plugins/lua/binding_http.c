/*
 * Lua HTTP Bindings
 *
 * Exposes http.fetch(), http.download(), http.stream(), http.urlencode(),
 * http.set_bearer_token(), http.set_basic_auth()
 */

#include "bindings.h"
#include <lauxlib.h>
#include <stdlib.h>
#include <string.h>

// Get http_client from registry
static http_client_t *get_http_client(lua_State *L) {
  lua_getfield(L, LUA_REGISTRYINDEX, LUA_REG_HTTP_CLIENT);
  http_client_t *client = lua_touserdata(L, -1);
  lua_pop(L, 1);
  return client;
}

/*
 * http.fetch(method, url, opts) -> {status=int, body=string, error=string|nil}
 */
static int lua_http_fetch(lua_State *L) {
  const char *method = luaL_checkstring(L, 1);
  const char *url = luaL_checkstring(L, 2);
  http_client_t *client = get_http_client(L);

  http_request_t req = {0};
  const char **headers = NULL;

  if (lua_istable(L, 3)) {
    lua_getfield(L, 3, "body");
    if (lua_isstring(L, -1)) {
      req.body = lua_tostring(L, -1);
    }
    lua_pop(L, 1);

    lua_getfield(L, 3, "content_type");
    if (lua_isstring(L, -1)) {
      req.content_type = lua_tostring(L, -1);
    }
    lua_pop(L, 1);

    lua_getfield(L, 3, "headers");
    if (lua_istable(L, -1)) {
      int header_count = lua_rawlen(L, -1);
      if (header_count > 0) {
        headers = malloc((header_count + 1) * sizeof(char *));
        if (headers) {
          for (int i = 1; i <= header_count; i++) {
            lua_rawgeti(L, -1, i);
            headers[i - 1] = lua_tostring(L, -1);
            lua_pop(L, 1);
          }
          headers[header_count] = NULL;
          req.headers = headers;
        }
      }
    }
    lua_pop(L, 1);
  }

  http_response_t *resp =
      http_fetch(client, method, url, req.body ? &req : NULL);

  lua_newtable(L);

  if (!resp) {
    lua_pushstring(L, "allocation failed");
    lua_setfield(L, -2, "error");
  } else if (resp->error) {
    lua_pushstring(L, resp->error);
    lua_setfield(L, -2, "error");
  } else {
    lua_pushinteger(L, resp->status);
    lua_setfield(L, -2, "status");

    if (resp->body) {
      lua_pushlstring(L, resp->body, resp->body_len);
      lua_setfield(L, -2, "body");
    }
  }

  http_response_free(resp);
  free(headers);

  return 1;
}

/*
 * http.download(url, path, opts) -> {ok=bool, error=string|nil}
 */
static int lua_http_download(lua_State *L) {
  const char *url = luaL_checkstring(L, 1);
  const char *path = luaL_checkstring(L, 2);
  http_client_t *client = get_http_client(L);

  int ret = http_download(client, url, path, NULL, NULL);

  lua_newtable(L);

  if (ret == 0) {
    lua_pushboolean(L, 1);
    lua_setfield(L, -2, "ok");
  } else {
    lua_pushboolean(L, 0);
    lua_setfield(L, -2, "ok");
    lua_pushstring(L, "download failed");
    lua_setfield(L, -2, "error");
  }

  return 1;
}

// Context for stream callback
typedef struct {
  lua_State *L;
  int callback_ref;
  size_t total_bytes;
  int aborted;
  char *error;
} stream_ctx_t;

static size_t stream_write_cb(const void *data, size_t len, void *ctx) {
  stream_ctx_t *stream_ctx = (stream_ctx_t *)ctx;
  lua_State *L = stream_ctx->L;

  if (stream_ctx->aborted) {
    return 0;
  }

  lua_rawgeti(L, LUA_REGISTRYINDEX, stream_ctx->callback_ref);
  lua_pushlstring(L, (const char *)data, len);

  lua_newtable(L);
  lua_pushinteger(L, len);
  lua_setfield(L, -2, "size");
  lua_pushinteger(L, stream_ctx->total_bytes + len);
  lua_setfield(L, -2, "total");

  if (lua_pcall(L, 2, 1, 0) != LUA_OK) {
    stream_ctx->error = strdup(lua_tostring(L, -1));
    lua_pop(L, 1);
    stream_ctx->aborted = 1;
    return 0;
  }

  int cont = lua_toboolean(L, -1);
  lua_pop(L, 1);

  if (!cont) {
    stream_ctx->aborted = 1;
    return 0;
  }

  stream_ctx->total_bytes += len;
  return len;
}

/*
 * http.stream(url, callback, opts) -> {ok=bool, bytes=int, error=string|nil}
 */
static int lua_http_stream(lua_State *L) {
  const char *url = luaL_checkstring(L, 1);
  luaL_checktype(L, 2, LUA_TFUNCTION);
  http_client_t *client = get_http_client(L);

  const char *method = "GET";
  http_request_t req = {0};
  const char **headers = NULL;

  if (lua_istable(L, 3)) {
    lua_getfield(L, 3, "method");
    if (lua_isstring(L, -1)) {
      method = lua_tostring(L, -1);
    }
    lua_pop(L, 1);

    lua_getfield(L, 3, "body");
    if (lua_isstring(L, -1)) {
      req.body = lua_tostring(L, -1);
    }
    lua_pop(L, 1);

    lua_getfield(L, 3, "content_type");
    if (lua_isstring(L, -1)) {
      req.content_type = lua_tostring(L, -1);
    }
    lua_pop(L, 1);

    lua_getfield(L, 3, "headers");
    if (lua_istable(L, -1)) {
      int header_count = lua_rawlen(L, -1);
      if (header_count > 0) {
        headers = malloc((header_count + 1) * sizeof(char *));
        if (headers) {
          for (int i = 1; i <= header_count; i++) {
            lua_rawgeti(L, -1, i);
            headers[i - 1] = lua_tostring(L, -1);
            lua_pop(L, 1);
          }
          headers[header_count] = NULL;
          req.headers = headers;
        }
      }
    }
    lua_pop(L, 1);
  }

  lua_pushvalue(L, 2);
  int callback_ref = luaL_ref(L, LUA_REGISTRYINDEX);

  stream_ctx_t stream_ctx = {.L = L,
                             .callback_ref = callback_ref,
                             .total_bytes = 0,
                             .aborted = 0,
                             .error = NULL};

  int ret =
      http_stream(client, method, url,
                  (req.body || req.headers || req.content_type) ? &req : NULL,
                  stream_write_cb, &stream_ctx, NULL, NULL);

  free(headers);
  luaL_unref(L, LUA_REGISTRYINDEX, callback_ref);

  lua_newtable(L);

  if (ret != 0 || stream_ctx.aborted) {
    lua_pushboolean(L, 0);
    lua_setfield(L, -2, "ok");
    if (stream_ctx.error) {
      lua_pushstring(L, stream_ctx.error);
      free(stream_ctx.error);
    } else if (stream_ctx.aborted) {
      lua_pushstring(L, "aborted by callback");
    } else {
      lua_pushstring(L, "HTTP stream failed");
    }
    lua_setfield(L, -2, "error");
  } else {
    lua_pushboolean(L, 1);
    lua_setfield(L, -2, "ok");
  }

  lua_pushinteger(L, stream_ctx.total_bytes);
  lua_setfield(L, -2, "bytes");

  return 1;
}

/*
 * http.urlencode(str) -> encoded_string
 */
static int lua_http_urlencode(lua_State *L) {
  const char *str = luaL_checkstring(L, 1);
  char *encoded = http_urlencode(str);

  if (encoded) {
    lua_pushstring(L, encoded);
    free(encoded);
  } else {
    lua_pushnil(L);
  }

  return 1;
}

/*
 * http.set_bearer_token(token) -> bool
 */
static int lua_http_set_bearer_token(lua_State *L) {
  const char *token = luaL_checkstring(L, 1);
  http_client_t *client = get_http_client(L);
  int ret = http_client_auth_bearer(client, token);
  lua_pushboolean(L, ret == 0);
  return 1;
}

/*
 * http.set_basic_auth(user, pass) -> bool
 */
static int lua_http_set_basic_auth(lua_State *L) {
  const char *user = luaL_checkstring(L, 1);
  const char *pass = luaL_checkstring(L, 2);
  http_client_t *client = get_http_client(L);
  int ret = http_client_auth_basic(client, user, pass);
  lua_pushboolean(L, ret == 0);
  return 1;
}

void lua_register_http(lua_State *L, http_client_t *client) {
  // Store client in registry
  lua_pushlightuserdata(L, client);
  lua_setfield(L, LUA_REGISTRYINDEX, LUA_REG_HTTP_CLIENT);

  // Create http table
  lua_newtable(L);

  lua_pushcfunction(L, lua_http_fetch);
  lua_setfield(L, -2, "fetch");

  lua_pushcfunction(L, lua_http_download);
  lua_setfield(L, -2, "download");

  lua_pushcfunction(L, lua_http_stream);
  lua_setfield(L, -2, "stream");

  lua_pushcfunction(L, lua_http_urlencode);
  lua_setfield(L, -2, "urlencode");

  lua_pushcfunction(L, lua_http_set_bearer_token);
  lua_setfield(L, -2, "set_bearer_token");

  lua_pushcfunction(L, lua_http_set_basic_auth);
  lua_setfield(L, -2, "set_basic_auth");

  lua_setglobal(L, "http");
}
