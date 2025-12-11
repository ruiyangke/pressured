#ifndef LUA_BINDINGS_H
#define LUA_BINDINGS_H

#include "http.h"
#include "storage.h"
#include <lua.h>

/*
 * Lua Bindings - shared context and registration functions
 *
 * Each binding module registers a Lua global table with functions.
 * Context is stored in Lua registry for access from C functions.
 */

// Context keys for Lua registry
#define LUA_REG_HTTP_CLIENT "pressured_http_client"
#define LUA_REG_STORAGE "pressured_storage"
#define LUA_REG_SERVICE_REGISTRY "pressured_service_registry"

// Forward declarations
typedef struct service_registry service_registry_t;

// Register binding modules
void lua_register_log(lua_State *L);
void lua_register_ctx(lua_State *L);
void lua_register_http(lua_State *L, http_client_t *client);
void lua_register_storage(lua_State *L, service_registry_t *sr);

#endif // LUA_BINDINGS_H
