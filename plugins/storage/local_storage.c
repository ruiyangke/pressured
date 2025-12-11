/*
 * Local filesystem storage plugin
 *
 * Registers as "storage:local" with the service registry.
 * Plugin name: "local-storage" (used for config lookup)
 *
 * Configuration:
 *   - PRESSURED_STORAGE_PATH env var
 *   - storage.path in config JSON
 *   - plugins.local-storage.enabled = false to disable
 */

#include "log.h"
#include "plugin.h"
#include "service_registry.h"
#include "storage.h"
#include <errno.h>
#include <json-c/json.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DEFAULT_PATH "/var/lib/pressured/storage"
#define MAX_PATH_LEN 4096

/* ═══════════════════════════════════════════════════════════════════════════
 * Plugin Context
 * ═══════════════════════════════════════════════════════════════════════════ */

struct pressured_plugin_ctx {
  char base_path[MAX_PATH_LEN];
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Storage Handle
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
  storage_t base;                   /* MUST be first - vtable interface */
  struct pressured_plugin_ctx *ctx; /* Back-pointer to plugin context */
} local_storage_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * File Handle
 * ═══════════════════════════════════════════════════════════════════════════ */

struct storage_file {
  FILE *fp;
  char path[MAX_PATH_LEN];
  char tmp_path[MAX_PATH_LEN];
  int mode;
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static void build_path(const char *base, const char *key, char *out,
                       size_t out_len) {
  const char *k = key;
  while (*k == '/')
    k++;
  snprintf(out, out_len, "%s/%s", base, k);
}

static int mkdirs(const char *path) {
  char tmp[MAX_PATH_LEN];
  char *ptr = NULL;

  if (!path || !path[0])
    return -1;

  snprintf(tmp, sizeof(tmp), "%s", path);
  size_t len = strlen(tmp);
  if (len > 0 && tmp[len - 1] == '/')
    tmp[len - 1] = '\0';

  char *parent = strdup(tmp);
  if (!parent)
    return -1;
  char *dir = dirname(parent);

  for (ptr = dir + 1; *ptr; ptr++) {
    if (*ptr == '/') {
      *ptr = '\0';
      if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        free(parent);
        return -1;
      }
      *ptr = '/';
    }
  }
  if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
    free(parent);
    return -1;
  }

  free(parent);
  return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Storage Operations
 * ═══════════════════════════════════════════════════════════════════════════ */

static int local_exists(storage_t *s, const char *key) {
  const local_storage_t *ls = (const local_storage_t *)s;
  char path[MAX_PATH_LEN];
  build_path(ls->ctx->base_path, key, path, sizeof(path));
  return access(path, F_OK) == 0 ? 1 : 0;
}

static int local_remove(storage_t *s, const char *key) {
  const local_storage_t *ls = (const local_storage_t *)s;
  char path[MAX_PATH_LEN];
  build_path(ls->ctx->base_path, key, path, sizeof(path));

  if (unlink(path) != 0) {
    if (errno == ENOENT)
      return STORAGE_ERR_NOT_FOUND;
    return STORAGE_ERR_IO;
  }

  log_debug("local_storage: removed %s", key);
  return STORAGE_OK;
}

static int local_rename(storage_t *s, const char *old_key,
                        const char *new_key) {
  const local_storage_t *ls = (const local_storage_t *)s;
  char old_path[MAX_PATH_LEN];
  char new_path[MAX_PATH_LEN];
  build_path(ls->ctx->base_path, old_key, old_path, sizeof(old_path));
  build_path(ls->ctx->base_path, new_key, new_path, sizeof(new_path));

  if (mkdirs(new_path) != 0) {
    log_error("local_storage: failed to create directories for %s", new_path);
    return STORAGE_ERR_IO;
  }

  if (rename(old_path, new_path) != 0) {
    if (errno == ENOENT)
      return STORAGE_ERR_NOT_FOUND;
    log_error("local_storage: rename failed %s -> %s: %s", old_key, new_key,
              strerror(errno));
    return STORAGE_ERR_IO;
  }

  log_debug("local_storage: renamed %s -> %s", old_key, new_key);
  return STORAGE_OK;
}

static storage_file_t *local_open(storage_t *s, const char *key, int mode) {
  const local_storage_t *ls = (const local_storage_t *)s;

  storage_file_t *f = calloc(1, sizeof(storage_file_t));
  if (!f)
    return NULL;

  f->mode = mode;
  build_path(ls->ctx->base_path, key, f->path, sizeof(f->path));

  if (mode == STORAGE_MODE_WRITE) {
    if (mkdirs(f->path) != 0) {
      log_error("local_storage: failed to create directories for %s", f->path);
      free(f);
      return NULL;
    }
    snprintf(f->tmp_path, sizeof(f->tmp_path), "%s.tmp.%d", f->path, getpid());
    f->fp = fopen(f->tmp_path, "wb");
  } else {
    f->fp = fopen(f->path, "rb");
  }

  if (!f->fp) {
    log_debug("local_storage: failed to open %s: %s", f->path, strerror(errno));
    free(f);
    return NULL;
  }

  return f;
}

static int64_t local_write(storage_file_t *f, const void *data, size_t len) {
  if (!f || !f->fp)
    return STORAGE_ERR_NOT_INIT;

  size_t written = fwrite(data, 1, len, f->fp);
  if (written != len) {
    return STORAGE_ERR_IO;
  }

  return (int64_t)written;
}

static int64_t local_read(storage_file_t *f, void *buf, size_t len) {
  if (!f || !f->fp)
    return STORAGE_ERR_NOT_INIT;

  size_t n = fread(buf, 1, len, f->fp);
  if (n == 0 && ferror(f->fp)) {
    return STORAGE_ERR_IO;
  }

  return (int64_t)n;
}

static int local_close(storage_file_t *f) {
  if (!f)
    return STORAGE_ERR_NOT_INIT;

  int rc = STORAGE_OK;

  if (f->fp) {
    if (f->mode == STORAGE_MODE_WRITE) {
      fflush(f->fp);
      fsync(fileno(f->fp));
    }
    fclose(f->fp);

    if (f->mode == STORAGE_MODE_WRITE) {
      if (rename(f->tmp_path, f->path) != 0) {
        unlink(f->tmp_path);
        rc = STORAGE_ERR_IO;
      } else {
        log_debug("local_storage: wrote to %s", f->path);
      }
    }
  }

  free(f);
  return rc;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Service Factory
 * ═══════════════════════════════════════════════════════════════════════════ */

static void *local_storage_factory(void *userdata) {
  struct pressured_plugin_ctx *ctx = userdata;

  local_storage_t *ls = calloc(1, sizeof(local_storage_t));
  if (!ls)
    return NULL;

  /* Set up vtable */
  ls->base.exists = local_exists;
  ls->base.remove = local_remove;
  ls->base.rename = local_rename;
  ls->base.open = local_open;
  ls->base.write = local_write;
  ls->base.read = local_read;
  ls->base.close = local_close;
  ls->ctx = ctx;

  log_debug("local_storage: created storage instance");
  return ls;
}

static void local_storage_destructor(void *instance, void *userdata) {
  (void)userdata;
  if (instance) {
    log_debug("local_storage: destroyed storage instance");
    free(instance);
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Service Metadata
 * ═══════════════════════════════════════════════════════════════════════════ */

static const char *local_tags[] = {"local", "filesystem", NULL};

static const service_metadata_t storage_service_meta = {
    .type = "storage",
    .provider = "local",
    .version = "2.0.0",
    .description = "Local filesystem storage backend",
    .priority = 50, /* Lower priority than cloud storage */
    .tags = local_tags,
    .dependencies = NULL,
    .interface_version = 1,
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Plugin Metadata
 * ═══════════════════════════════════════════════════════════════════════════ */

static const pressured_plugin_metadata_t plugin_metadata = {
    .name = "local-storage",
    .major_version = 2,
    .minor_version = 0,
    .description = "Local filesystem storage backend",
};

PRESSURED_PLUGIN_EXPORT const pressured_plugin_metadata_t *
pressured_plugin_get_metadata(void) {
  return &plugin_metadata;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Plugin Lifecycle
 * ═══════════════════════════════════════════════════════════════════════════ */

PRESSURED_PLUGIN_EXPORT pressured_plugin_ctx_t *
pressured_plugin_load(const char *config_json, service_registry_t *sr) {
  /* Note: Disabled check is handled by plugin_manager before load() is called.
   * Use config: plugins.local-storage.enabled = false to disable this plugin.
   */

  pressured_plugin_ctx_t *ctx = calloc(1, sizeof(pressured_plugin_ctx_t));
  if (!ctx)
    return NULL;

  /* Default path */
  strncpy(ctx->base_path, DEFAULT_PATH, MAX_PATH_LEN - 1);

  /* Check environment variable */
  const char *env_path = getenv("PRESSURED_STORAGE_PATH");
  if (env_path && env_path[0]) {
    strncpy(ctx->base_path, env_path, MAX_PATH_LEN - 1);
  }

  /* Parse JSON config if provided */
  if (config_json && config_json[0]) {
    struct json_object *root = json_tokener_parse(config_json);
    if (root) {
      struct json_object *storage_obj;
      if (json_object_object_get_ex(root, "storage", &storage_obj)) {
        struct json_object *path_obj;
        if (json_object_object_get_ex(storage_obj, "path", &path_obj)) {
          const char *path = json_object_get_string(path_obj);
          if (path && path[0]) {
            strncpy(ctx->base_path, path, MAX_PATH_LEN - 1);
          }
        }
      }
      json_object_put(root);
    }
  }

  /* Create base directory */
  if (mkdir(ctx->base_path, 0755) != 0 && errno != EEXIST) {
    log_error("local_storage: failed to create directory %s: %s",
              ctx->base_path, strerror(errno));
    free(ctx);
    return NULL;
  }

  /* Register storage service with the registry */
  int rc = service_registry_register(sr, &storage_service_meta,
                                     SERVICE_SCOPE_SINGLETON,
                                     local_storage_factory,
                                     local_storage_destructor, ctx);
  if (rc != 0) {
    log_error("local_storage: failed to register with service registry");
    free(ctx);
    return NULL;
  }

  log_info("local_storage: initialized path=%s", ctx->base_path);
  return ctx;
}

PRESSURED_PLUGIN_EXPORT void
pressured_plugin_unload(pressured_plugin_ctx_t *ctx) {
  if (ctx) {
    log_debug("local_storage: unloaded");
    free(ctx);
  }
}
