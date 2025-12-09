#include "log.h"
#include "pressured.h"
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

pressured_config_t *pressured_config_load(const char *path) {
  pressured_config_t *config = calloc(1, sizeof(pressured_config_t));
  if (!config)
    return NULL;

  // Set defaults
  config->source_mode = SOURCE_MODE_CGROUP;
  config->warn_percent = 0.70;
  config->critical_percent = 0.85;
  config->hysteresis_percent = 0.05;
  config->cooldown_seconds = 60;
  config->cgroup_path = strdup("/sys/fs/cgroup");
  config->poll_interval_ms = 1000;
  config->namespace_filter = NULL;
  config->label_selector = NULL;
  config->dry_run = false;
  config->log_level = strdup("info");

  if (!path) {
    return config;
  }

  // Read JSON config file
  struct json_object *root = json_object_from_file(path);
  if (!root) {
    log_warn("failed to parse config file: %s", path);
    return config;
  }

  struct json_object *obj;

  // Thresholds
  if (json_object_object_get_ex(root, "thresholds", &obj)) {
    struct json_object *val;
    if (json_object_object_get_ex(obj, "warn_percent", &val)) {
      config->warn_percent = json_object_get_double(val) / 100.0;
    }
    if (json_object_object_get_ex(obj, "critical_percent", &val)) {
      config->critical_percent = json_object_get_double(val) / 100.0;
    }
    if (json_object_object_get_ex(obj, "hysteresis_percent", &val)) {
      config->hysteresis_percent = json_object_get_double(val) / 100.0;
    }
    if (json_object_object_get_ex(obj, "cooldown_seconds", &val)) {
      config->cooldown_seconds = json_object_get_int(val);
    }
  }

  // Source
  if (json_object_object_get_ex(root, "source", &obj)) {
    struct json_object *val;

    // Mode selection: "cgroup" or "kubelet"
    if (json_object_object_get_ex(obj, "mode", &val)) {
      const char *mode = json_object_get_string(val);
      if (strcmp(mode, "kubelet") == 0 || strcmp(mode, "cluster") == 0) {
        config->source_mode = SOURCE_MODE_KUBELET;
      } else {
        config->source_mode = SOURCE_MODE_CGROUP;
      }
    }

    // Poll interval (applies to both modes)
    if (json_object_object_get_ex(obj, "poll_interval_ms", &val)) {
      config->poll_interval_ms = json_object_get_int(val);
    }

    // Cgroup-specific settings
    struct json_object *cgroup;
    if (json_object_object_get_ex(obj, "cgroup", &cgroup)) {
      if (json_object_object_get_ex(cgroup, "path", &val)) {
        free(config->cgroup_path);
        config->cgroup_path = strdup(json_object_get_string(val));
      }
      if (json_object_object_get_ex(cgroup, "poll_interval_ms", &val)) {
        config->poll_interval_ms = json_object_get_int(val);
      }
    }

    // Kubelet-specific settings
    struct json_object *kubelet;
    if (json_object_object_get_ex(obj, "kubelet", &kubelet)) {
      if (json_object_object_get_ex(kubelet, "namespace_filter", &val)) {
        config->namespace_filter = strdup(json_object_get_string(val));
      }
      if (json_object_object_get_ex(kubelet, "label_selector", &val)) {
        config->label_selector = strdup(json_object_get_string(val));
      }
      if (json_object_object_get_ex(kubelet, "poll_interval_ms", &val)) {
        config->poll_interval_ms = json_object_get_int(val);
      }
    }
  }

  // General
  if (json_object_object_get_ex(root, "dry_run", &obj)) {
    config->dry_run = json_object_get_boolean(obj);
  }
  if (json_object_object_get_ex(root, "log_level", &obj)) {
    free(config->log_level);
    config->log_level = strdup(json_object_get_string(obj));
  }

  json_object_put(root);

  log_info("config loaded from %s", path);
  return config;
}

void pressured_config_free(pressured_config_t *config) {
  if (config) {
    free(config->cgroup_path);
    free(config->namespace_filter);
    free(config->label_selector);
    free(config->log_level);
    free(config);
  }
}

char *pressured_config_load_json(const char *path) {
  if (!path)
    return NULL;

  FILE *f = fopen(path, "r");
  if (!f)
    return NULL;

  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  fseek(f, 0, SEEK_SET);

  if (size <= 0) {
    fclose(f);
    return NULL;
  }

  char *json = malloc(size + 1);
  if (!json) {
    fclose(f);
    return NULL;
  }

  size_t read = fread(json, 1, size, f);
  fclose(f);

  if ((long)read != size) {
    free(json);
    return NULL;
  }

  json[size] = '\0';
  return json;
}
