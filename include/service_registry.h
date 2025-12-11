/*
 * Service Registry
 *
 * A lightweight registry with factory-based instantiation, metadata-driven
 * provider discovery, and handle-wrapped lifecycle management.
 *
 * Design principles:
 *   1. String-based types for extensibility ("storage", "analyzer")
 *   2. Metadata-driven providers for self-describing services
 *   3. Handle wrapper (service_ref_t) for uniform lifecycle
 *   4. Lock-free design: init all singletons before spawning threads
 *
 * Usage (plugin side):
 *   static const service_metadata_t pprof_meta = {
 *       .type = "analyzer", .provider = "pprof", .priority = 100, ...
 *   };
 *   service_registry_register(sr, &pprof_meta, SERVICE_SCOPE_TRANSIENT,
 *                             pprof_factory, pprof_destroy, ctx);
 *
 * Usage (consumer side):
 *   service_ref_t ref = service_registry_acquire(sr, "analyzer");
 *   analyzer_t *a = ref.instance;
 *   // ... use service ...
 *   service_ref_release(&ref);  // Safe for any scope
 *
 * Thread safety:
 *   - Single-threaded: register(), init_all(), free()
 *   - Multi-threaded: acquire(), release() (lock-free after init_all)
 */

#ifndef SERVICE_REGISTRY_H
#define SERVICE_REGISTRY_H

#include <stddef.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Opaque Types
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct service_registry service_registry_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * Service Reference (Handle Wrapper)
 *
 * Wraps service instance with internal tracking for scope-aware release.
 * Consumer always calls service_ref_release() - behavior depends on scope:
 *   - SINGLETON: no-op (registry owns instance)
 *   - TRANSIENT: calls destructor, frees instance
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct service_ref {
  void *instance;   /* The service instance (cast to your interface type) */
  void *_internal;  /* Internal tracking - DO NOT MODIFY */
} service_ref_t;

/* Check if reference is valid (instance acquired successfully) */
static inline int service_ref_valid(const service_ref_t *ref) {
  return ref && ref->instance != NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Service Metadata (Provider Self-Description)
 *
 * Services describe themselves through metadata, enabling:
 *   - Discovery: list all providers for a type
 *   - Selection: priority-based default, tag filtering, custom matchers
 *   - Introspection: version, description, dependencies
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct service_metadata {
  /* Identity */
  const char *type;         /* Service category: "storage", "analyzer" */
  const char *provider;     /* Implementation name: "local", "s3", "pprof" */
  const char *version;      /* Semver: "1.0.0" */
  const char *description;  /* Human-readable description */

  /* Selection */
  int priority;             /* Higher = preferred for default selection */
  const char **tags;        /* NULL-terminated: ["cloud", "aws", NULL] */

  /* Dependencies (declarative - factory must acquire manually) */
  const char **dependencies; /* Required types: ["storage", "config", NULL] */

  /* Compatibility */
  int interface_version;    /* For breaking change detection */
} service_metadata_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * Service Scope (Registration-Time Only)
 *
 * Scope is a provider decision, not a consumer concern:
 *   - SINGLETON: One instance for app lifetime. release() = no-op.
 *   - TRANSIENT: New instance per acquire(). release() = destroy.
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef enum {
  SERVICE_SCOPE_SINGLETON, /* One instance, app lifetime */
  SERVICE_SCOPE_TRANSIENT, /* New instance per acquire */
} service_scope_e;

/* ═══════════════════════════════════════════════════════════════════════════
 * Service State (SINGLETON only)
 *
 * State machine for services with lifecycle hooks (start/stop).
 * Most services don't need this - just acquire() and use.
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef enum {
  SERVICE_STATE_REGISTERED, /* Factory registered, not instantiated */
  SERVICE_STATE_CREATED,    /* Instance exists, not started */
  SERVICE_STATE_RUNNING,    /* Active and available */
  SERVICE_STATE_STOPPED,    /* Stopped, can restart */
  SERVICE_STATE_FAILED,     /* Error state */
} service_state_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * Function Types
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Factory: Creates service instance
 *
 * @param userdata  Context passed to service_registry_register()
 * @return          Service instance, or NULL on failure
 */
typedef void *(*service_factory_fn)(void *userdata);

/*
 * Destructor: Cleanup service instance
 *
 * @param instance  The service instance returned by factory
 * @param userdata  Context passed to service_registry_register()
 */
typedef void (*service_destructor_fn)(void *instance, void *userdata);

/*
 * Matcher: Custom provider selection predicate
 *
 * @param meta  Provider metadata to check
 * @param ctx   Context passed to acquire_match()
 * @return      Non-zero if provider matches
 */
typedef int (*service_matcher_fn)(const service_metadata_t *meta, void *ctx);

/*
 * Full lifecycle callbacks (optional, for advanced use)
 */
typedef struct {
  service_factory_fn create;    /* Required: create instance */
  service_destructor_fn destroy; /* Optional: final cleanup */
  int (*start)(void *instance, void *userdata);  /* Optional: activate */
  void (*stop)(void *instance, void *userdata);  /* Optional: deactivate */
  int (*health)(void *instance, void *userdata); /* Optional: health check */
} service_callbacks_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * Registry Lifecycle
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Create a new service registry
 *
 * @return  New registry, or NULL on allocation failure
 */
service_registry_t *service_registry_new(void);

/*
 * Free the registry and all singleton instances
 *
 * Calls destructors for all instantiated singletons.
 * Must be called single-threaded (after joining all worker threads).
 *
 * @param sr  Registry to free (NULL-safe)
 */
void service_registry_free(service_registry_t *sr);

/* ═══════════════════════════════════════════════════════════════════════════
 * Eager Initialization (Lock-Free Design)
 *
 * Call these BEFORE spawning threads. After init_all(), all singleton
 * acquire() calls are lock-free reads of cached pointers.
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Instantiate a specific singleton immediately
 *
 * @param sr    Registry
 * @param type  "type" (highest priority) or "type:provider" (specific)
 * @return      0 on success, -1 on failure (not found, factory failed)
 */
int service_registry_init(service_registry_t *sr, const char *type);

/*
 * Instantiate ALL registered singletons
 *
 * Iterates all registered providers and instantiates SINGLETON-scoped ones.
 * TRANSIENT providers are skipped (they create on each acquire).
 *
 * @param sr  Registry
 * @return    0 on success, -1 if any factory fails
 */
int service_registry_init_all(service_registry_t *sr);

/* ═══════════════════════════════════════════════════════════════════════════
 * Registration (Plugin Side)
 *
 * Register services during single-threaded initialization phase.
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Register a service factory with metadata
 *
 * @param sr          Registry
 * @param metadata    Provider self-description (type, provider, priority, etc.)
 * @param scope       SINGLETON or TRANSIENT
 * @param factory     Factory function to create instance
 * @param destructor  Optional destructor (NULL if not needed)
 * @param userdata    Context passed to factory and destructor
 * @return            0 on success, -1 on failure
 */
int service_registry_register(service_registry_t *sr,
                              const service_metadata_t *metadata,
                              service_scope_e scope,
                              service_factory_fn factory,
                              service_destructor_fn destructor,
                              void *userdata);

/*
 * Register with full lifecycle callbacks
 *
 * Use when your service needs start/stop/health hooks.
 *
 * @param sr         Registry
 * @param metadata   Provider self-description
 * @param scope      SINGLETON or TRANSIENT
 * @param callbacks  Full lifecycle callbacks (create required, others optional)
 * @param userdata   Context passed to all callbacks
 * @return           0 on success, -1 on failure
 */
int service_registry_register_ex(service_registry_t *sr,
                                 const service_metadata_t *metadata,
                                 service_scope_e scope,
                                 const service_callbacks_t *callbacks,
                                 void *userdata);

/* ═══════════════════════════════════════════════════════════════════════════
 * Acquisition (Consumer Side)
 *
 * Safe to call from multiple threads after init_all().
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Acquire a service reference
 *
 * For SINGLETON: returns cached instance (lock-free after init_all)
 * For TRANSIENT: creates new instance each call
 *
 * @param sr    Registry
 * @param type  "type" (highest priority) or "type:provider" (specific)
 * @return      Service reference (check with service_ref_valid)
 */
service_ref_t service_registry_acquire(service_registry_t *sr,
                                       const char *type);

/*
 * Release a service reference
 *
 * Always safe to call:
 *   - SINGLETON: no-op (registry owns instance)
 *   - TRANSIENT: calls destructor, frees instance
 *
 * After release, ref->instance is set to NULL.
 *
 * @param ref  Reference to release (NULL-safe)
 */
void service_ref_release(service_ref_t *ref);

/*
 * Acquire by tag (highest priority provider with tag)
 *
 * @param sr   Registry
 * @param type Service type
 * @param tag  Required tag
 * @return     Service reference
 */
service_ref_t service_registry_acquire_tagged(service_registry_t *sr,
                                              const char *type,
                                              const char *tag);

/*
 * Acquire by custom matcher
 *
 * @param sr          Registry
 * @param type        Service type
 * @param matcher     Predicate function
 * @param matcher_ctx Context passed to matcher
 * @return            Service reference
 */
service_ref_t service_registry_acquire_match(service_registry_t *sr,
                                             const char *type,
                                             service_matcher_fn matcher,
                                             void *matcher_ctx);

/*
 * Acquire all providers of a type
 *
 * @param sr         Registry
 * @param type       Service type
 * @param refs       Output array for references
 * @param max_count  Maximum references to return
 * @return           Number of providers (may exceed max_count)
 */
size_t service_registry_acquire_all(service_registry_t *sr,
                                    const char *type,
                                    service_ref_t *refs,
                                    size_t max_count);

/*
 * Acquire all providers with tag
 *
 * @param sr         Registry
 * @param type       Service type
 * @param tag        Required tag
 * @param refs       Output array for references
 * @param max_count  Maximum references to return
 * @return           Number of providers with tag
 */
size_t service_registry_acquire_all_tagged(service_registry_t *sr,
                                           const char *type,
                                           const char *tag,
                                           service_ref_t *refs,
                                           size_t max_count);

/* ═══════════════════════════════════════════════════════════════════════════
 * Query
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Check if type (or specific provider) is registered
 *
 * @param sr    Registry
 * @param type  "type" or "type:provider"
 * @return      1 if registered, 0 if not
 */
int service_registry_has(service_registry_t *sr, const char *type);

/*
 * Count providers for a type
 *
 * @param sr    Registry
 * @param type  Service type
 * @return      Number of registered providers
 */
size_t service_registry_count(service_registry_t *sr, const char *type);

/*
 * Get metadata for a provider
 *
 * @param sr        Registry
 * @param type      Service type
 * @param provider  Provider name (NULL for highest priority)
 * @return          Metadata pointer, or NULL if not found
 */
const service_metadata_t *service_registry_metadata(service_registry_t *sr,
                                                    const char *type,
                                                    const char *provider);

/*
 * Get service state
 *
 * @param sr    Registry
 * @param type  "type" (highest priority) or "type:provider" (specific)
 * @return      Current state
 */
service_state_t service_registry_state(service_registry_t *sr,
                                       const char *type);

/* ═══════════════════════════════════════════════════════════════════════════
 * Lifecycle Control (SINGLETON Only)
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Start a service (call start callback)
 *
 * @param sr    Registry
 * @param type  "type" (highest priority) or "type:provider" (specific)
 * @return      0 on success, -1 on failure
 */
int service_registry_start(service_registry_t *sr, const char *type);

/*
 * Stop a service (call stop callback)
 *
 * @param sr    Registry
 * @param type  "type" (highest priority) or "type:provider" (specific)
 * @return      0 on success, -1 on failure
 */
int service_registry_stop(service_registry_t *sr, const char *type);

/*
 * Restart a service (stop then start)
 *
 * @param sr    Registry
 * @param type  "type" (highest priority) or "type:provider" (specific)
 * @return      0 on success, -1 on failure
 */
int service_registry_restart(service_registry_t *sr, const char *type);

/*
 * Start all services with start callbacks
 *
 * @param sr  Registry
 * @return    0 on success, -1 if any start fails
 */
int service_registry_start_all(service_registry_t *sr);

/*
 * Stop all running services
 *
 * @param sr  Registry
 */
void service_registry_stop_all(service_registry_t *sr);

/* ═══════════════════════════════════════════════════════════════════════════
 * Iteration
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Callback for iterating over service types
 */
typedef void (*service_type_callback_fn)(const char *type,
                                         size_t provider_count,
                                         void *userdata);

/*
 * Iterate over all registered service types
 *
 * @param sr        Registry
 * @param callback  Function to call for each type
 * @param userdata  Context passed to callback
 */
void service_registry_foreach_type(service_registry_t *sr,
                                   service_type_callback_fn callback,
                                   void *userdata);

/*
 * Callback for iterating over providers
 */
typedef void (*service_provider_callback_fn)(const service_metadata_t *metadata,
                                             void *userdata);

/*
 * Iterate over providers of a type
 *
 * @param sr        Registry
 * @param type      Service type
 * @param callback  Function to call for each provider
 * @param userdata  Context passed to callback
 */
void service_registry_foreach_provider(service_registry_t *sr,
                                       const char *type,
                                       service_provider_callback_fn callback,
                                       void *userdata);

/*
 * Callback for iterating over service instances
 */
typedef void (*service_instance_callback_fn)(const char *type,
                                             const char *provider,
                                             void *instance,
                                             void *userdata);

/*
 * Iterate over all instantiated services
 *
 * @param sr        Registry
 * @param callback  Function to call for each instance
 * @param userdata  Context passed to callback
 */
void service_registry_foreach(service_registry_t *sr,
                              service_instance_callback_fn callback,
                              void *userdata);

#endif /* SERVICE_REGISTRY_H */
