/*
 * Service Registry Implementation
 *
 * Hash-based registry with metadata-driven provider discovery,
 * handle-wrapped lifecycle, and lock-free design.
 */

#include "service_registry.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal Structures
 * ═══════════════════════════════════════════════════════════════════════════
 */

typedef struct service_entry {
  struct service_entry *next; /* Next provider for same type (linked list) */

  /* Metadata (copied from registration) */
  service_metadata_t metadata;
  char *type_copy;     /* Owned copy of type string */
  char *provider_copy; /* Owned copy of provider string */

  /* Registration info */
  service_scope_e scope;
  service_callbacks_t callbacks;
  void *userdata;

  /* Instance state */
  void *instance;
  int instantiated;
  service_state_t state;
} service_entry_t;

typedef struct {
  service_entry_t *head; /* Linked list of entries with same hash */
} bucket_t;

struct service_registry {
  bucket_t *buckets;
  size_t bucket_count;
  size_t entry_count;
};

#define INITIAL_BUCKETS 32
#define LOAD_FACTOR_THRESHOLD 0.75

/* ═══════════════════════════════════════════════════════════════════════════
 * Hash Function (FNV-1a)
 * ═══════════════════════════════════════════════════════════════════════════
 */

static uint32_t hash_string(const char *str) {
  uint32_t hash = 2166136261u;
  while (*str) {
    hash ^= (uint8_t)*str++;
    hash *= 16777619u;
  }
  return hash;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Type String Parsing
 *
 * Supports "type" and "type:provider" syntax
 * ═══════════════════════════════════════════════════════════════════════════
 */

typedef struct {
  char type[128];
  char provider[128];
  int has_provider;
} parsed_type_t;

static void parse_type_string(const char *input, parsed_type_t *out) {
  out->has_provider = 0;
  out->provider[0] = '\0';

  const char *colon = strchr(input, ':');
  if (colon) {
    size_t type_len = (size_t)(colon - input);
    if (type_len >= sizeof(out->type))
      type_len = sizeof(out->type) - 1;
    strncpy(out->type, input, type_len);
    out->type[type_len] = '\0';

    strncpy(out->provider, colon + 1, sizeof(out->provider) - 1);
    out->provider[sizeof(out->provider) - 1] = '\0';
    out->has_provider = 1;
  } else {
    strncpy(out->type, input, sizeof(out->type) - 1);
    out->type[sizeof(out->type) - 1] = '\0';
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Tag Matching
 * ═══════════════════════════════════════════════════════════════════════════
 */

static int entry_has_tag(const service_entry_t *e, const char *tag) {
  if (!e->metadata.tags)
    return 0;
  for (const char **t = e->metadata.tags; *t; t++) {
    if (strcmp(*t, tag) == 0)
      return 1;
  }
  return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Entry Management
 * ═══════════════════════════════════════════════════════════════════════════
 */

static service_entry_t *entry_new(const service_metadata_t *metadata,
                                  service_scope_e scope,
                                  const service_callbacks_t *callbacks,
                                  void *userdata) {
  service_entry_t *e = calloc(1, sizeof(*e));
  if (!e)
    return NULL;

  /* Copy strings we need to own */
  e->type_copy = strdup(metadata->type);
  e->provider_copy = metadata->provider ? strdup(metadata->provider) : NULL;

  if (!e->type_copy) {
    free(e->provider_copy);
    free(e);
    return NULL;
  }

  /* Copy metadata, pointing strings to our copies */
  e->metadata = *metadata;
  e->metadata.type = e->type_copy;
  e->metadata.provider = e->provider_copy;

  e->scope = scope;
  e->callbacks = *callbacks;
  e->userdata = userdata;
  e->state = SERVICE_STATE_REGISTERED;

  return e;
}

static void entry_free(service_entry_t *e) {
  if (!e)
    return;

  /* Call destructor if instance was created */
  if (e->instantiated && e->callbacks.destroy) {
    e->callbacks.destroy(e->instance, e->userdata);
  }

  free(e->type_copy);
  free(e->provider_copy);
  free(e);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Bucket Operations
 * ═══════════════════════════════════════════════════════════════════════════
 */

/* Find highest-priority entry for type (optionally matching provider) */
static service_entry_t *bucket_find_best(bucket_t *b, const char *type,
                                         const char *provider) {
  service_entry_t *best = NULL;

  for (service_entry_t *e = b->head; e; e = e->next) {
    if (strcmp(e->metadata.type, type) != 0)
      continue;

    /* If provider specified, must match exactly */
    if (provider) {
      if (e->metadata.provider && strcmp(e->metadata.provider, provider) == 0) {
        return e; /* Exact match */
      }
      continue;
    }

    /* No provider specified - find highest priority */
    if (!best || e->metadata.priority > best->metadata.priority) {
      best = e;
    }
  }

  return best;
}

/* Find highest-priority entry with specific tag */
static service_entry_t *bucket_find_tagged(bucket_t *b, const char *type,
                                           const char *tag) {
  service_entry_t *best = NULL;

  for (service_entry_t *e = b->head; e; e = e->next) {
    if (strcmp(e->metadata.type, type) != 0)
      continue;
    if (!entry_has_tag(e, tag))
      continue;

    if (!best || e->metadata.priority > best->metadata.priority) {
      best = e;
    }
  }

  return best;
}

/* Add entry to bucket (prepends to list) */
static void bucket_add(bucket_t *b, service_entry_t *e) {
  e->next = b->head;
  b->head = e;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Registry Resize
 * ═══════════════════════════════════════════════════════════════════════════
 */

static int registry_resize(service_registry_t *sr, size_t new_count) {
  bucket_t *new_buckets = calloc(new_count, sizeof(bucket_t));
  if (!new_buckets)
    return -1;

  /* Rehash all entries */
  for (size_t i = 0; i < sr->bucket_count; i++) {
    service_entry_t *e = sr->buckets[i].head;
    while (e) {
      service_entry_t *next = e->next;
      size_t idx = hash_string(e->metadata.type) % new_count;
      e->next = new_buckets[idx].head;
      new_buckets[idx].head = e;
      e = next;
    }
  }

  free(sr->buckets);
  sr->buckets = new_buckets;
  sr->bucket_count = new_count;
  return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Instance Creation (Internal)
 * ═══════════════════════════════════════════════════════════════════════════
 */

static int entry_instantiate(service_entry_t *e) {
  if (e->instantiated)
    return 0;

  log_debug("service_registry: instantiating '%s:%s'", e->metadata.type,
            e->metadata.provider ? e->metadata.provider : "(default)");

  e->instance = e->callbacks.create(e->userdata);
  e->instantiated = 1;

  if (!e->instance) {
    log_warn("service_registry: factory for '%s:%s' returned NULL",
             e->metadata.type,
             e->metadata.provider ? e->metadata.provider : "(default)");
    e->state = SERVICE_STATE_FAILED;
    return -1;
  }

  /* Transition to CREATED (or RUNNING if no lifecycle hooks) */
  if (e->callbacks.start) {
    e->state = SERVICE_STATE_CREATED;
  } else {
    e->state = SERVICE_STATE_RUNNING;
  }

  return 0;
}

/* Create service_ref_t from entry */
static service_ref_t make_ref(service_entry_t *e) {
  service_ref_t ref = {0};
  if (e) {
    ref.instance = e->instance;
    ref._internal = e;
  }
  return ref;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API: Registry Lifecycle
 * ═══════════════════════════════════════════════════════════════════════════
 */

service_registry_t *service_registry_new(void) {
  service_registry_t *sr = calloc(1, sizeof(*sr));
  if (!sr)
    return NULL;

  sr->buckets = calloc(INITIAL_BUCKETS, sizeof(bucket_t));
  if (!sr->buckets) {
    free(sr);
    return NULL;
  }

  sr->bucket_count = INITIAL_BUCKETS;
  return sr;
}

void service_registry_free(service_registry_t *sr) {
  if (!sr)
    return;

  /* Free all entries */
  for (size_t i = 0; i < sr->bucket_count; i++) {
    service_entry_t *e = sr->buckets[i].head;
    while (e) {
      service_entry_t *next = e->next;
      entry_free(e);
      e = next;
    }
  }

  free(sr->buckets);
  free(sr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API: Eager Initialization
 * ═══════════════════════════════════════════════════════════════════════════
 */

int service_registry_init(service_registry_t *sr, const char *type) {
  if (!sr || !type)
    return -1;

  parsed_type_t parsed;
  parse_type_string(type, &parsed);

  size_t idx = hash_string(parsed.type) % sr->bucket_count;
  service_entry_t *e =
      bucket_find_best(&sr->buckets[idx], parsed.type,
                       parsed.has_provider ? parsed.provider : NULL);

  if (!e) {
    log_warn("service_registry_init: '%s' not found", type);
    return -1;
  }

  if (e->scope != SERVICE_SCOPE_SINGLETON) {
    log_debug("service_registry_init: '%s' is TRANSIENT, skipping", type);
    return 0;
  }

  return entry_instantiate(e);
}

int service_registry_init_all(service_registry_t *sr) {
  if (!sr)
    return -1;

  int result = 0;

  for (size_t i = 0; i < sr->bucket_count; i++) {
    for (service_entry_t *e = sr->buckets[i].head; e; e = e->next) {
      if (e->scope == SERVICE_SCOPE_SINGLETON && !e->instantiated) {
        if (entry_instantiate(e) != 0) {
          result = -1;
        }
      }
    }
  }

  return result;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API: Registration
 * ═══════════════════════════════════════════════════════════════════════════
 */

int service_registry_register(service_registry_t *sr,
                              const service_metadata_t *metadata,
                              service_scope_e scope, service_factory_fn factory,
                              service_destructor_fn destructor,
                              void *userdata) {
  service_callbacks_t callbacks = {
      .create = factory,
      .destroy = destructor,
  };
  return service_registry_register_ex(sr, metadata, scope, &callbacks,
                                      userdata);
}

int service_registry_register_ex(service_registry_t *sr,
                                 const service_metadata_t *metadata,
                                 service_scope_e scope,
                                 const service_callbacks_t *callbacks,
                                 void *userdata) {
  if (!sr || !metadata || !metadata->type || !callbacks || !callbacks->create)
    return -1;

  /* Check if resize needed */
  double load = (double)sr->entry_count / (double)sr->bucket_count;
  if (load > LOAD_FACTOR_THRESHOLD) {
    if (registry_resize(sr, sr->bucket_count * 2) != 0) {
      log_error("service_registry: failed to resize");
      return -1;
    }
  }

  /* Create entry */
  service_entry_t *e = entry_new(metadata, scope, callbacks, userdata);
  if (!e)
    return -1;

  /* Add to bucket */
  size_t idx = hash_string(metadata->type) % sr->bucket_count;
  bucket_add(&sr->buckets[idx], e);
  sr->entry_count++;

  log_debug("service_registry: registered '%s:%s' (priority=%d, scope=%s)",
            metadata->type, metadata->provider ? metadata->provider : "(anon)",
            metadata->priority,
            scope == SERVICE_SCOPE_SINGLETON ? "singleton" : "transient");

  return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API: Acquisition
 * ═══════════════════════════════════════════════════════════════════════════
 */

service_ref_t service_registry_acquire(service_registry_t *sr,
                                       const char *type) {
  service_ref_t ref = {0};
  if (!sr || !type)
    return ref;

  parsed_type_t parsed;
  parse_type_string(type, &parsed);

  size_t idx = hash_string(parsed.type) % sr->bucket_count;
  service_entry_t *e =
      bucket_find_best(&sr->buckets[idx], parsed.type,
                       parsed.has_provider ? parsed.provider : NULL);

  if (!e)
    return ref;

  /* Handle based on scope */
  if (e->scope == SERVICE_SCOPE_SINGLETON) {
    /* Singleton: return cached instance (should already be instantiated) */
    if (!e->instantiated) {
      /* Lazy init - only safe in single-threaded phase */
      entry_instantiate(e);
    }
    return make_ref(e);
  } else {
    /* Transient: create new instance each time */
    void *instance = e->callbacks.create(e->userdata);
    if (!instance)
      return ref;

    /* Allocate a transient entry to track this instance */
    service_entry_t *transient = calloc(1, sizeof(*transient));
    if (!transient) {
      if (e->callbacks.destroy) {
        e->callbacks.destroy(instance, e->userdata);
      }
      return ref;
    }

    transient->scope = SERVICE_SCOPE_TRANSIENT;
    transient->callbacks = e->callbacks;
    transient->userdata = e->userdata;
    transient->instance = instance;
    transient->instantiated = 1;

    ref.instance = instance;
    ref._internal = transient;
    return ref;
  }
}

void service_ref_release(service_ref_t *ref) {
  if (!ref || !ref->_internal)
    return;

  service_entry_t *e = ref->_internal;

  if (e->scope == SERVICE_SCOPE_TRANSIENT) {
    /* Transient: destroy instance and free tracking entry */
    if (e->callbacks.destroy) {
      e->callbacks.destroy(e->instance, e->userdata);
    }
    free(e);
  }
  /* Singleton: no-op (registry owns instance) */

  ref->instance = NULL;
  ref->_internal = NULL;
}

service_ref_t service_registry_acquire_tagged(service_registry_t *sr,
                                              const char *type,
                                              const char *tag) {
  service_ref_t ref = {0};
  if (!sr || !type || !tag)
    return ref;

  size_t idx = hash_string(type) % sr->bucket_count;
  service_entry_t *e = bucket_find_tagged(&sr->buckets[idx], type, tag);

  if (!e)
    return ref;

  if (e->scope == SERVICE_SCOPE_SINGLETON) {
    if (!e->instantiated)
      entry_instantiate(e);
    return make_ref(e);
  } else {
    /* Transient with tag - same as regular acquire but filtered */
    void *instance = e->callbacks.create(e->userdata);
    if (!instance)
      return ref;

    service_entry_t *transient = calloc(1, sizeof(*transient));
    if (!transient) {
      if (e->callbacks.destroy)
        e->callbacks.destroy(instance, e->userdata);
      return ref;
    }

    transient->scope = SERVICE_SCOPE_TRANSIENT;
    transient->callbacks = e->callbacks;
    transient->userdata = e->userdata;
    transient->instance = instance;
    transient->instantiated = 1;

    ref.instance = instance;
    ref._internal = transient;
    return ref;
  }
}

service_ref_t service_registry_acquire_match(service_registry_t *sr,
                                             const char *type,
                                             service_matcher_fn matcher,
                                             void *matcher_ctx) {
  service_ref_t ref = {0};
  if (!sr || !type || !matcher)
    return ref;

  size_t idx = hash_string(type) % sr->bucket_count;
  service_entry_t *best = NULL;

  for (service_entry_t *e = sr->buckets[idx].head; e; e = e->next) {
    if (strcmp(e->metadata.type, type) != 0)
      continue;
    if (!matcher(&e->metadata, matcher_ctx))
      continue;

    if (!best || e->metadata.priority > best->metadata.priority) {
      best = e;
    }
  }

  if (!best)
    return ref;

  if (best->scope == SERVICE_SCOPE_SINGLETON) {
    if (!best->instantiated)
      entry_instantiate(best);
    return make_ref(best);
  } else {
    void *instance = best->callbacks.create(best->userdata);
    if (!instance)
      return ref;

    service_entry_t *transient = calloc(1, sizeof(*transient));
    if (!transient) {
      if (best->callbacks.destroy)
        best->callbacks.destroy(instance, best->userdata);
      return ref;
    }

    transient->scope = SERVICE_SCOPE_TRANSIENT;
    transient->callbacks = best->callbacks;
    transient->userdata = best->userdata;
    transient->instance = instance;
    transient->instantiated = 1;

    ref.instance = instance;
    ref._internal = transient;
    return ref;
  }
}

size_t service_registry_acquire_all(service_registry_t *sr, const char *type,
                                    service_ref_t *refs, size_t max_count) {
  if (!sr || !type)
    return 0;

  size_t idx = hash_string(type) % sr->bucket_count;
  size_t found = 0;

  for (service_entry_t *e = sr->buckets[idx].head; e; e = e->next) {
    if (strcmp(e->metadata.type, type) != 0)
      continue;

    if (refs && found < max_count) {
      if (e->scope == SERVICE_SCOPE_SINGLETON) {
        if (!e->instantiated)
          entry_instantiate(e);
        refs[found] = make_ref(e);
      } else {
        void *instance = e->callbacks.create(e->userdata);
        if (instance) {
          service_entry_t *transient = calloc(1, sizeof(*transient));
          if (transient) {
            transient->scope = SERVICE_SCOPE_TRANSIENT;
            transient->callbacks = e->callbacks;
            transient->userdata = e->userdata;
            transient->instance = instance;
            transient->instantiated = 1;
            refs[found].instance = instance;
            refs[found]._internal = transient;
          } else {
            if (e->callbacks.destroy)
              e->callbacks.destroy(instance, e->userdata);
          }
        }
      }
    }
    found++;
  }

  return found;
}

size_t service_registry_acquire_all_tagged(service_registry_t *sr,
                                           const char *type, const char *tag,
                                           service_ref_t *refs,
                                           size_t max_count) {
  if (!sr || !type || !tag)
    return 0;

  size_t idx = hash_string(type) % sr->bucket_count;
  size_t found = 0;

  for (service_entry_t *e = sr->buckets[idx].head; e; e = e->next) {
    if (strcmp(e->metadata.type, type) != 0)
      continue;
    if (!entry_has_tag(e, tag))
      continue;

    if (refs && found < max_count) {
      if (e->scope == SERVICE_SCOPE_SINGLETON) {
        if (!e->instantiated)
          entry_instantiate(e);
        refs[found] = make_ref(e);
      } else {
        void *instance = e->callbacks.create(e->userdata);
        if (instance) {
          service_entry_t *transient = calloc(1, sizeof(*transient));
          if (transient) {
            transient->scope = SERVICE_SCOPE_TRANSIENT;
            transient->callbacks = e->callbacks;
            transient->userdata = e->userdata;
            transient->instance = instance;
            transient->instantiated = 1;
            refs[found].instance = instance;
            refs[found]._internal = transient;
          } else {
            if (e->callbacks.destroy)
              e->callbacks.destroy(instance, e->userdata);
          }
        }
      }
    }
    found++;
  }

  return found;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API: Query
 * ═══════════════════════════════════════════════════════════════════════════
 */

int service_registry_has(service_registry_t *sr, const char *type) {
  if (!sr || !type)
    return 0;

  parsed_type_t parsed;
  parse_type_string(type, &parsed);

  size_t idx = hash_string(parsed.type) % sr->bucket_count;
  service_entry_t *e =
      bucket_find_best(&sr->buckets[idx], parsed.type,
                       parsed.has_provider ? parsed.provider : NULL);

  return e != NULL;
}

size_t service_registry_count(service_registry_t *sr, const char *type) {
  if (!sr || !type)
    return 0;

  size_t idx = hash_string(type) % sr->bucket_count;
  size_t count = 0;

  for (service_entry_t *e = sr->buckets[idx].head; e; e = e->next) {
    if (strcmp(e->metadata.type, type) == 0)
      count++;
  }

  return count;
}

const service_metadata_t *service_registry_metadata(service_registry_t *sr,
                                                    const char *type,
                                                    const char *provider) {
  if (!sr || !type)
    return NULL;

  size_t idx = hash_string(type) % sr->bucket_count;
  service_entry_t *e = bucket_find_best(&sr->buckets[idx], type, provider);

  return e ? &e->metadata : NULL;
}

service_state_t service_registry_state(service_registry_t *sr,
                                       const char *type) {
  if (!sr || !type)
    return SERVICE_STATE_REGISTERED;

  parsed_type_t parsed;
  parse_type_string(type, &parsed);

  size_t idx = hash_string(parsed.type) % sr->bucket_count;
  service_entry_t *e =
      bucket_find_best(&sr->buckets[idx], parsed.type,
                       parsed.has_provider ? parsed.provider : NULL);

  return e ? e->state : SERVICE_STATE_REGISTERED;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API: Lifecycle Control
 * ═══════════════════════════════════════════════════════════════════════════
 */

int service_registry_start(service_registry_t *sr, const char *type) {
  if (!sr || !type)
    return -1;

  parsed_type_t parsed;
  parse_type_string(type, &parsed);

  size_t idx = hash_string(parsed.type) % sr->bucket_count;
  service_entry_t *e =
      bucket_find_best(&sr->buckets[idx], parsed.type,
                       parsed.has_provider ? parsed.provider : NULL);

  if (!e)
    return -1;
  if (!e->instantiated && entry_instantiate(e) != 0)
    return -1;
  if (!e->callbacks.start)
    return 0; /* No start callback, already running */

  if (e->state == SERVICE_STATE_RUNNING)
    return 0;

  int rc = e->callbacks.start(e->instance, e->userdata);
  if (rc == 0) {
    e->state = SERVICE_STATE_RUNNING;
  } else {
    e->state = SERVICE_STATE_FAILED;
  }
  return rc;
}

int service_registry_stop(service_registry_t *sr, const char *type) {
  if (!sr || !type)
    return -1;

  parsed_type_t parsed;
  parse_type_string(type, &parsed);

  size_t idx = hash_string(parsed.type) % sr->bucket_count;
  service_entry_t *e =
      bucket_find_best(&sr->buckets[idx], parsed.type,
                       parsed.has_provider ? parsed.provider : NULL);

  if (!e || !e->instantiated)
    return -1;
  if (!e->callbacks.stop)
    return 0;

  if (e->state != SERVICE_STATE_RUNNING)
    return 0;

  e->callbacks.stop(e->instance, e->userdata);
  e->state = SERVICE_STATE_STOPPED;
  return 0;
}

int service_registry_restart(service_registry_t *sr, const char *type) {
  if (service_registry_stop(sr, type) != 0)
    return -1;
  return service_registry_start(sr, type);
}

int service_registry_start_all(service_registry_t *sr) {
  if (!sr)
    return -1;

  int result = 0;

  for (size_t i = 0; i < sr->bucket_count; i++) {
    for (service_entry_t *e = sr->buckets[i].head; e; e = e->next) {
      if (e->scope == SERVICE_SCOPE_SINGLETON && e->instantiated &&
          e->callbacks.start && e->state != SERVICE_STATE_RUNNING) {
        int rc = e->callbacks.start(e->instance, e->userdata);
        if (rc == 0) {
          e->state = SERVICE_STATE_RUNNING;
        } else {
          e->state = SERVICE_STATE_FAILED;
          result = -1;
        }
      }
    }
  }

  return result;
}

void service_registry_stop_all(service_registry_t *sr) {
  if (!sr)
    return;

  for (size_t i = 0; i < sr->bucket_count; i++) {
    for (service_entry_t *e = sr->buckets[i].head; e; e = e->next) {
      if (e->scope == SERVICE_SCOPE_SINGLETON && e->instantiated &&
          e->callbacks.stop && e->state == SERVICE_STATE_RUNNING) {
        e->callbacks.stop(e->instance, e->userdata);
        e->state = SERVICE_STATE_STOPPED;
      }
    }
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API: Iteration
 * ═══════════════════════════════════════════════════════════════════════════
 */

void service_registry_foreach_type(service_registry_t *sr,
                                   service_type_callback_fn callback,
                                   void *userdata) {
  if (!sr || !callback)
    return;

  /* Track visited types to avoid duplicates */
  for (size_t i = 0; i < sr->bucket_count; i++) {
    for (service_entry_t *e = sr->buckets[i].head; e; e = e->next) {
      /* Check if this is the first entry for this type */
      int first = 1;
      for (size_t j = 0; j < i && first; j++) {
        for (service_entry_t *prev = sr->buckets[j].head; prev;
             prev = prev->next) {
          if (strcmp(prev->metadata.type, e->metadata.type) == 0) {
            first = 0;
            break;
          }
        }
      }
      for (service_entry_t *prev = sr->buckets[i].head; prev != e && first;
           prev = prev->next) {
        if (strcmp(prev->metadata.type, e->metadata.type) == 0) {
          first = 0;
          break;
        }
      }

      if (first) {
        size_t count = service_registry_count(sr, e->metadata.type);
        callback(e->metadata.type, count, userdata);
      }
    }
  }
}

void service_registry_foreach_provider(service_registry_t *sr, const char *type,
                                       service_provider_callback_fn callback,
                                       void *userdata) {
  if (!sr || !type || !callback)
    return;

  size_t idx = hash_string(type) % sr->bucket_count;

  for (service_entry_t *e = sr->buckets[idx].head; e; e = e->next) {
    if (strcmp(e->metadata.type, type) == 0) {
      callback(&e->metadata, userdata);
    }
  }
}

void service_registry_foreach(service_registry_t *sr,
                              service_instance_callback_fn callback,
                              void *userdata) {
  if (!sr || !callback)
    return;

  for (size_t i = 0; i < sr->bucket_count; i++) {
    for (service_entry_t *e = sr->buckets[i].head; e; e = e->next) {
      if (e->instantiated) {
        callback(e->metadata.type, e->metadata.provider, e->instance, userdata);
      }
    }
  }
}
