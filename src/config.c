#include "fixed_buffer.h"
#include "log.h"
#include "pjson.h"
#include "pressured.h"
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
  if (buffer_copy(config->cgroup_path, sizeof(config->cgroup_path),
                  "/sys/fs/cgroup", "cgroup path") != 0) {
    pressured_config_free(config);
    return NULL;
  }
  config->poll_interval_ms = 1000;
  config->namespace_filter = NULL;
  config->label_selector = NULL;
  config->dry_run = false;
  config->log_level = strdup("info");

  if (!path) {
    return config;
  }

  // Read JSON config file
  char *text = pressured_config_load_json(path);
  if (!text) {
    log_warn("failed to read config file: %s", path);
    return config;
  }
  // pj_parse logs the parse error itself.
  yyjson_doc *doc = pj_parse(text, strlen(text), PJ_READ_CONFIG, path);
  free(text);
  if (!doc)
    return config;

  yyjson_val *root = yyjson_doc_get_root(doc);
  yyjson_val *source, *val;
  int n;

  // Thresholds
  yyjson_val *thresholds =
      pj_config_value(root, "", "thresholds", "an object", yyjson_is_obj);
  val = pj_config_value(thresholds, "thresholds", "warn_percent", "a number",
                        yyjson_is_num);
  if (val)
    config->warn_percent = yyjson_get_num(val) / 100.0;
  val = pj_config_value(thresholds, "thresholds", "critical_percent",
                        "a number", yyjson_is_num);
  if (val)
    config->critical_percent = yyjson_get_num(val) / 100.0;
  val = pj_config_value(thresholds, "thresholds", "hysteresis_percent",
                        "a number", yyjson_is_num);
  if (val)
    config->hysteresis_percent = yyjson_get_num(val) / 100.0;
  val = pj_config_value(thresholds, "thresholds", "cooldown_seconds",
                        "a number", yyjson_is_num);
  if (val && pj_int(val, &n))
    config->cooldown_seconds = n;

  // Source
  source = pj_config_value(root, "", "source", "an object", yyjson_is_obj);

  // Mode selection: "cgroup" or "kubelet"
  val = pj_config_value(source, "source", "mode", "a string", yyjson_is_str);
  if (val) {
    const char *mode = yyjson_get_str(val);
    if (strcmp(mode, "kubelet") == 0 || strcmp(mode, "cluster") == 0)
      config->source_mode = SOURCE_MODE_KUBELET;
    else
      config->source_mode = SOURCE_MODE_CGROUP;
  }

  // Poll interval (applies to both modes)
  val = pj_config_value(source, "source", "poll_interval_ms", "a number",
                        yyjson_is_num);
  if (val && pj_int(val, &n))
    config->poll_interval_ms = n;

  // Cgroup-specific settings
  yyjson_val *cgroup =
      pj_config_value(source, "source", "cgroup", "an object", yyjson_is_obj);
  val = pj_config_value(cgroup, "source.cgroup", "path", "a string",
                        yyjson_is_str);
  if (val) {
    if (buffer_copy(config->cgroup_path, sizeof(config->cgroup_path),
                    yyjson_get_str(val), "cgroup path") != 0) {
      yyjson_doc_free(doc);
      pressured_config_free(config);
      return NULL;
    }
  }
  val = pj_config_value(cgroup, "source.cgroup", "poll_interval_ms", "a number",
                        yyjson_is_num);
  if (val && pj_int(val, &n))
    config->poll_interval_ms = n;

  // Kubelet-specific settings
  yyjson_val *kubelet =
      pj_config_value(source, "source", "kubelet", "an object", yyjson_is_obj);
  val = pj_config_value(kubelet, "source.kubelet", "namespace_filter",
                        "a string", yyjson_is_str);
  if (val)
    config->namespace_filter = strdup(yyjson_get_str(val));
  val = pj_config_value(kubelet, "source.kubelet", "label_selector", "a string",
                        yyjson_is_str);
  if (val)
    config->label_selector = strdup(yyjson_get_str(val));
  val = pj_config_value(kubelet, "source.kubelet", "poll_interval_ms",
                        "a number", yyjson_is_num);
  if (val && pj_int(val, &n))
    config->poll_interval_ms = n;

  // General
  val = pj_config_value(root, "", "dry_run", "a boolean", yyjson_is_bool);
  if (val)
    config->dry_run = yyjson_get_bool(val);
  val = pj_config_value(root, "", "log_level", "a string", yyjson_is_str);
  if (val) {
    free(config->log_level);
    config->log_level = strdup(yyjson_get_str(val));
  }

  yyjson_doc_free(doc);

  log_info("config loaded from %s", path);
  return config;
}

void pressured_config_free(pressured_config_t *config) {
  if (config) {
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
