#define _GNU_SOURCE // for strptime and timegm
#include "fixed_buffer.h"
#include "internal.h"
#include "log.h"
#include "pjson.h"
#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_NODES 128
#define MAX_PODS 4096
#define MAX_URL 1024
#define MAX_TOKEN 8192
#define MAX_OOM_EVENTS 256

#define SA_TOKEN_PATH "/var/run/secrets/kubernetes.io/serviceaccount/token"
#define SA_CA_CERT_PATH "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
// The kubelet rotates the projected service account token file before the
// token expires, so it must be re-read periodically (client-go uses 1 min).
#define TOKEN_RELOAD_INTERVAL_SEC 60

// Pod limit cache entry
typedef struct {
  char key[512]; // namespace/pod/container
  uint64_t limit_bytes;
  char pod_ip[64];
  pressured_annotation_t
      *annotations;      // Pod annotations array (dynamically allocated)
  int annotations_count; // Number of annotations
} pod_limit_t;

// OOM event tracking (to avoid duplicate notifications)
typedef struct {
  char *uid;        // Full event or pod/container/restart identity
  time_t timestamp; // When we first saw this event
} oom_event_seen_t;

// Node info
typedef struct {
  char name[256];
  char address[256];
} node_info_t;

struct kubelet_source {
  // Kubernetes API config
  char *api_server;
  char token[MAX_TOKEN];
  char token_path[PATH_MAX]; // Empty in proxy mode
  time_t token_loaded_at;    // monotonic seconds of last token read
  char ca_cert_path[PATH_MAX];

  // Node discovery
  node_info_t nodes[MAX_NODES];
  int node_count;
  bool collection_healthy;

  // Pod limits cache
  pod_limit_t *pod_limits;
  int pod_limit_count;
  int pod_limit_capacity;

  // Reused per-cycle samples buffer (owned by the source)
  pressured_memory_sample_t *samples;
  int sample_count; // Entries written by the previous collect

  // OOM event tracking (to deduplicate K8s events)
  oom_event_seen_t seen_events[MAX_OOM_EVENTS];
  int seen_event_count;

  // Filters
  char *namespace_filter;
  char *label_selector;

  // HTTP client
  CURL *curl;
};

// HTTP response buffer
typedef struct {
  char *data;
  size_t size;
} http_buffer_t;

static size_t write_callback(void *contents, size_t size, size_t nmemb,
                             void *userp) {
  size_t realsize = size * nmemb;
  http_buffer_t *buf = (http_buffer_t *)userp;

  char *ptr = realloc(buf->data, buf->size + realsize + 1);
  if (!ptr)
    return 0;

  buf->data = ptr;
  memcpy(&buf->data[buf->size], contents, realsize);
  buf->size += realsize;
  buf->data[buf->size] = 0;

  return realsize;
}

static int read_token(const char *path, char *buffer, size_t size) {
  FILE *file = fopen(path, "r");
  if (!file)
    return -1;
  size_t length = fread(buffer, 1, size - 1, file);
  // Anything left over must be the trailing line ending trimmed below
  int extra;
  int too_long = 0;
  while ((extra = fgetc(file)) != EOF) {
    if (extra != '\n' && extra != '\r') {
      too_long = 1;
      break;
    }
  }
  int failed = ferror(file);
  fclose(file);
  if (too_long) {
    log_warn("service account token file too long (buffer size %zu)", size);
    return -1;
  }
  if (failed)
    return -1;
  while (length && (buffer[length - 1] == '\n' || buffer[length - 1] == '\r'))
    length--;
  buffer[length] = '\0';
  return 0;
}

static time_t monotonic_seconds(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec;
}

// Re-read the service account token, keeping the previous one on failure
static void reload_token(kubelet_source_t *source) {
  source->token_loaded_at = monotonic_seconds();

  char token[MAX_TOKEN];
  if (read_token(source->token_path, token, sizeof(token)) != 0 || !token[0]) {
    log_warn("failed to read service account token from %s",
             source->token_path);
    return;
  }
  if (strcmp(source->token, token) == 0)
    return;
  bool had_token = source->token[0] != '\0';
  if (buffer_copy(source->token, sizeof(source->token), token,
                  "service account token") != 0)
    return;
  if (had_token)
    log_info("service account token reloaded");
}

kubelet_source_t *kubelet_source_new(void) {
  kubelet_source_t *source = calloc(1, sizeof(kubelet_source_t));
  if (!source)
    return NULL;

  // Initialize pod limits cache
  source->pod_limit_capacity = 256;
  source->pod_limits = calloc(source->pod_limit_capacity, sizeof(pod_limit_t));
  if (!source->pod_limits) {
    free(source);
    return NULL;
  }

  // Allocate the per-cycle samples buffer once; kubelet_collect() reuses it.
  source->samples = calloc(MAX_PODS, sizeof(pressured_memory_sample_t));
  if (!source->samples) {
    free(source->pod_limits);
    free(source);
    return NULL;
  }

  // Try in-cluster config first
  const char *k8s_host = getenv("KUBERNETES_SERVICE_HOST");
  const char *k8s_port = getenv("KUBERNETES_SERVICE_PORT");

  if (k8s_host && k8s_port) {
    // In-cluster mode
    char api_url[512];
    if (buffer_format(api_url, sizeof(api_url), "API URL", "https://%s:%s",
                      k8s_host, k8s_port) != 0) {
      kubelet_source_free(source);
      return NULL;
    }
    source->api_server = strdup(api_url);
    if (buffer_copy(source->token_path, sizeof(source->token_path),
                    SA_TOKEN_PATH, "service account token path") != 0 ||
        buffer_copy(source->ca_cert_path, sizeof(source->ca_cert_path),
                    SA_CA_CERT_PATH, "service account CA path") != 0) {
      kubelet_source_free(source);
      return NULL;
    }
    reload_token(source);

    log_info("kubelet source: in-cluster mode api=%s", source->api_server);
  } else {
    // Try kubectl proxy (localhost:8001)
    source->api_server = strdup("http://localhost:8001");

    log_info("kubelet source: proxy mode api=%s", source->api_server);
  }

  source->curl = curl_easy_init();
  if (!source->curl) {
    log_error("failed to init curl");
    kubelet_source_free(source);
    return NULL;
  }

  return source;
}

// Helper to free annotations array
static void free_annotations(pressured_annotation_t *annotations, int count) {
  if (annotations) {
    for (int i = 0; i < count; i++) {
      free(annotations[i].key);
      free(annotations[i].value);
    }
    free(annotations);
  }
}

void kubelet_source_free(kubelet_source_t *source) {
  if (source) {
    free(source->api_server);
    free(source->namespace_filter);
    free(source->label_selector);
    // Free annotations in cached entries before freeing the array
    for (int i = 0; i < source->pod_limit_count; i++) {
      free_annotations(source->pod_limits[i].annotations,
                       source->pod_limits[i].annotations_count);
    }
    free(source->pod_limits);
    free(source->samples);
    for (int i = 0; i < source->seen_event_count; i++)
      free(source->seen_events[i].uid);
    if (source->curl)
      curl_easy_cleanup(source->curl);
    free(source);
  }
}

void kubelet_set_namespace_filter(kubelet_source_t *source,
                                  const char *namespaces) {
  free(source->namespace_filter);
  source->namespace_filter = namespaces ? strdup(namespaces) : NULL;
}

void kubelet_set_label_selector(kubelet_source_t *source,
                                const char *selector) {
  free(source->label_selector);
  source->label_selector = selector ? strdup(selector) : NULL;
}

// Make an authenticated API request
static char *api_request(kubelet_source_t *source, const char *path) {
  char url[MAX_URL];
  if (buffer_format(url, sizeof(url), "API URL", "%s%s", source->api_server,
                    path) != 0)
    return NULL;

  http_buffer_t buf = {0};
  struct curl_slist *headers = NULL;

  curl_easy_reset(source->curl);
  curl_easy_setopt(source->curl, CURLOPT_URL, url);
  curl_easy_setopt(source->curl, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(source->curl, CURLOPT_WRITEDATA, &buf);
  curl_easy_setopt(source->curl, CURLOPT_TIMEOUT, 10L);

  if (source->token_path[0] && monotonic_seconds() - source->token_loaded_at >=
                                   TOKEN_RELOAD_INTERVAL_SEC)
    reload_token(source);

  if (source->token[0]) {
    char auth_header[MAX_TOKEN + 32];
    if (buffer_format(auth_header, sizeof(auth_header), "authorization header",
                      "Authorization: Bearer %s", source->token) != 0)
      return NULL;
    headers = curl_slist_append(headers, auth_header);
    curl_easy_setopt(source->curl, CURLOPT_HTTPHEADER, headers);
  }

  if (source->ca_cert_path[0]) {
    curl_easy_setopt(source->curl, CURLOPT_CAINFO, source->ca_cert_path);
  } else {
    curl_easy_setopt(source->curl, CURLOPT_SSL_VERIFYPEER, 0L);
  }

  CURLcode res = curl_easy_perform(source->curl);
  curl_slist_free_all(headers);

  if (res != CURLE_OK) {
    log_error("API request failed: %s", curl_easy_strerror(res));
    free(buf.data);
    return NULL;
  }

  long http_code;
  curl_easy_getinfo(source->curl, CURLINFO_RESPONSE_CODE, &http_code);
  if (http_code >= 400) {
    log_error("API request returned %ld: %s", http_code, path);
    // Token may have been rotated since the last reload; pick it up now
    if (http_code == 401 && source->token_path[0])
      reload_token(source);
    free(buf.data);
    return NULL;
  }

  return buf.data;
}

static int kubelet_refresh_nodes(kubelet_source_t *source) {
  char *response = api_request(source, "/api/v1/nodes");
  if (!response)
    return -1;

  yyjson_doc *doc =
      pj_parse(response, strlen(response), PJ_READ_API, "nodes response");
  free(response);

  if (!doc) {
    log_error("failed to parse nodes response");
    return -1;
  }

  yyjson_val *root = yyjson_doc_get_root(doc);
  yyjson_val *items = yyjson_obj_get(root, "items");
  if (!yyjson_is_arr(items)) {
    yyjson_doc_free(doc);
    return -1;
  }
  source->node_count = 0;
  {
    size_t idx, max;
    yyjson_val *node;
    yyjson_arr_foreach(items, idx, max, node) {
      if (source->node_count >= MAX_NODES)
        break;

      yyjson_val *metadata = yyjson_obj_get(node, "metadata");
      const char *name = yyjson_get_str(yyjson_obj_get(metadata, "name"));
      if (!name)
        continue;

      node_info_t *ni = &source->nodes[source->node_count];
      strncpy(ni->name, name, sizeof(ni->name) - 1);

      // Get node address (prefer InternalIP)
      yyjson_val *addresses =
          yyjson_obj_get(yyjson_obj_get(node, "status"), "addresses");
      if (yyjson_is_arr(addresses)) {
        size_t addr_idx, addr_max;
        yyjson_val *addr;
        yyjson_arr_foreach(addresses, addr_idx, addr_max, addr) {
          const char *type = yyjson_get_str(yyjson_obj_get(addr, "type"));
          const char *address = yyjson_get_str(yyjson_obj_get(addr, "address"));
          if (type && address && strcmp(type, "InternalIP") == 0) {
            strncpy(ni->address, address, sizeof(ni->address) - 1);
            break;
          }
        }
      }

      source->node_count++;
    }
  }

  yyjson_doc_free(doc);
  log_info("discovered %d nodes", source->node_count);
  return 0;
}

// Parse Kubernetes quantity (e.g., "100Mi", "1Gi") to bytes
static uint64_t parse_quantity(const char *str) {
  if (!str)
    return UINT64_MAX;

  char *endptr;
  double value = strtod(str, &endptr);

  if (endptr == str)
    return UINT64_MAX;

  // Handle suffixes
  if (*endptr == 'K' || *endptr == 'k') {
    if (*(endptr + 1) == 'i')
      value *= 1024;
    else
      value *= 1000;
  } else if (*endptr == 'M' || *endptr == 'm') {
    if (*(endptr + 1) == 'i')
      value *= 1024 * 1024;
    else
      value *= 1000 * 1000;
  } else if (*endptr == 'G' || *endptr == 'g') {
    if (*(endptr + 1) == 'i')
      value *= 1024 * 1024 * 1024;
    else
      value *= 1000 * 1000 * 1000;
  } else if (*endptr == 'T' || *endptr == 't') {
    if (*(endptr + 1) == 'i')
      value *= (uint64_t)1024 * 1024 * 1024 * 1024;
    else
      value *= (uint64_t)1000 * 1000 * 1000 * 1000;
  }

  return (uint64_t)value;
}

// Helper to parse JSON annotations object into array
static pressured_annotation_t *parse_annotations(yyjson_val *annotations_obj,
                                                 int *count) {
  *count = 0;
  if (!yyjson_is_obj(annotations_obj))
    return NULL;

  size_t n = yyjson_obj_size(annotations_obj);
  if (n == 0)
    return NULL;

  pressured_annotation_t *annotations =
      calloc(n, sizeof(pressured_annotation_t));
  if (!annotations) {
    *count = -1;
    return NULL;
  }

  size_t idx, max;
  yyjson_val *key, *val;
  yyjson_obj_foreach(annotations_obj, idx, max, key, val) {
    const char *name = yyjson_get_str(key);
    const char *value = yyjson_get_str(val);

    annotations[*count].key = strdup(name);
    annotations[*count].value = value ? strdup(value) : strdup("");
    if (!annotations[*count].key || !annotations[*count].value) {
      free_annotations(annotations, *count + 1);
      *count = -1;
      return NULL;
    }
    (*count)++;
  }

  return annotations;
}

// Helper to copy annotations array
static pressured_annotation_t *
copy_annotations(const pressured_annotation_t *src, int count) {
  if (!src || count == 0)
    return NULL;

  pressured_annotation_t *dst = calloc(count, sizeof(pressured_annotation_t));
  if (!dst)
    return NULL;

  for (int i = 0; i < count; i++) {
    dst[i].key = src[i].key ? strdup(src[i].key) : NULL;
    dst[i].value = src[i].value ? strdup(src[i].value) : NULL;
    if ((src[i].key && !dst[i].key) || (src[i].value && !dst[i].value)) {
      free_annotations(dst, count);
      return NULL;
    }
  }

  return dst;
}

static int kubelet_refresh_pod_limits(kubelet_source_t *source) {
  // Build API path with optional namespace filter
  char path[MAX_URL];
  if (source->namespace_filter && source->namespace_filter[0]) {
    // Single namespace
    if (buffer_format(path, sizeof(path), "kubelet API path",
                      "/api/v1/namespaces/%s/pods",
                      source->namespace_filter) != 0)
      return -1;
  } else {
    if (buffer_format(path, sizeof(path), "kubelet API path", "/api/v1/pods") !=
        0)
      return -1;
  }

  if (source->label_selector && source->label_selector[0]) {
    char encoded[512];
    // Simple URL encoding for label selector
    if (buffer_format(encoded, sizeof(encoded), "kubelet API path",
                      "?labelSelector=%s", source->label_selector) != 0)
      return -1;
    size_t used = strnlen(path, sizeof(path));
    if (used >= sizeof(path) || buffer_copy(path + used, sizeof(path) - used,
                                            encoded, "pods API path") != 0)
      return -1;
  }

  char *response = api_request(source, path);
  if (!response)
    return -1;

  yyjson_doc *doc =
      pj_parse(response, strlen(response), PJ_READ_API, "pods response");
  free(response);

  if (!doc) {
    log_error("failed to parse pods response");
    return -1;
  }

  yyjson_val *root = yyjson_doc_get_root(doc);
  yyjson_val *items = yyjson_obj_get(root, "items");
  if (!yyjson_is_arr(items)) {
    yyjson_doc_free(doc);
    return -1;
  }

  kubelet_source_t replacement = {0};
  replacement.pod_limit_capacity = 256;
  replacement.pod_limits =
      calloc(replacement.pod_limit_capacity, sizeof(pod_limit_t));
  if (!replacement.pod_limits) {
    yyjson_doc_free(doc);
    return -1;
  }
  kubelet_source_t *original = source;
  source = &replacement;
  {
    size_t pod_idx, pod_max;
    yyjson_val *pod;
    yyjson_arr_foreach(items, pod_idx, pod_max, pod) {
      yyjson_val *metadata = yyjson_obj_get(pod, "metadata");
      yyjson_val *spec = yyjson_obj_get(pod, "spec");

      if (!metadata || !spec)
        continue;

      const char *ns = yyjson_get_str(yyjson_obj_get(metadata, "namespace"));
      const char *pod_name = yyjson_get_str(yyjson_obj_get(metadata, "name"));
      if (!ns || !pod_name)
        continue;

      // Get pod IP from status
      const char *pod_ip = yyjson_get_str(
          yyjson_obj_get(yyjson_obj_get(pod, "status"), "podIP"));

      yyjson_val *containers = yyjson_obj_get(spec, "containers");
      if (!yyjson_is_arr(containers))
        continue;

      size_t container_count = yyjson_arr_size(containers);
      if (container_count == 0)
        continue;

      // Parse pod annotations into array (only if we have containers to store
      // them)
      pressured_annotation_t *pod_annotations = NULL;
      int pod_annotations_count = 0;
      yyjson_val *annotations_obj = yyjson_obj_get(metadata, "annotations");
      if (annotations_obj) {
        pod_annotations =
            parse_annotations(annotations_obj, &pod_annotations_count);
        if (pod_annotations_count < 0)
          goto failed;
      }

      int annotations_consumed = 0; // Track if first container took ownership

      size_t container_idx, container_max;
      yyjson_val *container;
      yyjson_arr_foreach(containers, container_idx, container_max, container) {
        const char *container_name =
            yyjson_get_str(yyjson_obj_get(container, "name"));
        if (!container_name)
          continue;

        uint64_t limit = UINT64_MAX;
        yyjson_val *limits =
            yyjson_obj_get(yyjson_obj_get(container, "resources"), "limits");
        yyjson_val *mem_limit = yyjson_obj_get(limits, "memory");
        if (mem_limit)
          limit = parse_quantity(yyjson_get_str(mem_limit));

        // Add to cache
        if (source->pod_limit_count >= source->pod_limit_capacity) {
          int new_cap = source->pod_limit_capacity * 2;
          pod_limit_t *new_limits =
              realloc(source->pod_limits, new_cap * sizeof(pod_limit_t));
          if (!new_limits) {
            if (!annotations_consumed)
              free_annotations(pod_annotations, pod_annotations_count);
            goto failed;
          }
          source->pod_limits = new_limits;
          source->pod_limit_capacity = new_cap;
        }

        pod_limit_t *pl = &source->pod_limits[source->pod_limit_count];
        if (buffer_format(pl->key, sizeof(pl->key), "pod cache key", "%s/%s/%s",
                          ns, pod_name, container_name) != 0) {
          if (!annotations_consumed)
            free_annotations(pod_annotations, pod_annotations_count);
          goto failed;
        }
        source->pod_limit_count++;
        pl->limit_bytes = limit;
        if (pod_ip) {
          strncpy(pl->pod_ip, pod_ip, sizeof(pl->pod_ip) - 1);
          pl->pod_ip[sizeof(pl->pod_ip) - 1] = '\0';
        } else {
          pl->pod_ip[0] = '\0';
        }
        // Store annotations (first successful container takes ownership, others
        // copy)
        if (!annotations_consumed) {
          pl->annotations = pod_annotations;
          pl->annotations_count = pod_annotations_count;
          annotations_consumed = 1;
        } else {
          pl->annotations =
              copy_annotations(pod_annotations, pod_annotations_count);
          pl->annotations_count = pod_annotations_count;
          if (pod_annotations_count > 0 && !pl->annotations)
            goto failed;
        }
      }

      // Free annotations if no container consumed them (all containers failed
      // validation)
      if (!annotations_consumed) {
        free_annotations(pod_annotations, pod_annotations_count);
      }
    }
  }

  yyjson_doc_free(doc);
  for (int i = 0; i < original->pod_limit_count; i++)
    free_annotations(original->pod_limits[i].annotations,
                     original->pod_limits[i].annotations_count);
  free(original->pod_limits);
  original->pod_limits = replacement.pod_limits;
  original->pod_limit_count = replacement.pod_limit_count;
  original->pod_limit_capacity = replacement.pod_limit_capacity;
  log_debug("cached limits for %d containers", original->pod_limit_count);
  return 0;

failed:
  yyjson_doc_free(doc);
  for (int i = 0; i < replacement.pod_limit_count; i++)
    free_annotations(replacement.pod_limits[i].annotations,
                     replacement.pod_limits[i].annotations_count);
  free(replacement.pod_limits);
  return -1;
}

int kubelet_source_init(kubelet_source_t *source) {
  if (kubelet_refresh_nodes(source) != 0) {
    return -1;
  }

  if (kubelet_refresh_pod_limits(source) != 0) {
    log_warn("failed to cache pod limits, will use defaults");
  }

  log_info("kubelet source initialized nodes=%d cached_limits=%d",
           source->node_count, source->pod_limit_count);
  return 0;
}

static pod_limit_t *lookup_pod_info(kubelet_source_t *source, const char *ns,
                                    const char *pod, const char *container) {
  char key[512];
  if (buffer_format(key, sizeof(key), "pod cache key", "%s/%s/%s", ns, pod,
                    container) != 0)
    return NULL;

  for (int i = 0; i < source->pod_limit_count; i++) {
    if (strcmp(source->pod_limits[i].key, key) == 0) {
      return &source->pod_limits[i];
    }
  }

  return NULL;
}

// Find an existing sample in the samples array by container key
// Returns pointer to sample if found, NULL otherwise
static pressured_memory_sample_t *
find_existing_sample(pressured_memory_sample_t *samples, int count,
                     const char *ns, const char *pod, const char *container) {
  for (int i = 0; i < count; i++) {
    if (samples[i].namespace && samples[i].pod_name &&
        samples[i].container_name && strcmp(samples[i].namespace, ns) == 0 &&
        strcmp(samples[i].pod_name, pod) == 0 &&
        strcmp(samples[i].container_name, container) == 0) {
      return &samples[i];
    }
  }
  return NULL;
}

static int collect_from_node(kubelet_source_t *source, const char *node_name,
                             pressured_memory_sample_t *samples, int *count,
                             int max_count) {
  // Query kubelet via API server proxy
  char path[MAX_URL];
  if (buffer_format(path, sizeof(path), "kubelet API path",
                    "/api/v1/nodes/%s/proxy/stats/summary", node_name) != 0)
    return -1;

  char *response = api_request(source, path);
  if (!response) {
    log_warn("failed to get stats from node %s", node_name);
    return -1;
  }

  yyjson_doc *doc =
      pj_parse(response, strlen(response), PJ_READ_API, "stats response");
  free(response);

  if (!doc) {
    log_error("failed to parse stats response from %s", node_name);
    return -1;
  }

  yyjson_val *root = yyjson_doc_get_root(doc);
  yyjson_val *pods_array = yyjson_obj_get(root, "pods");
  if (!yyjson_is_arr(pods_array)) {
    yyjson_doc_free(doc);
    return -1;
  }

  size_t pod_idx, pod_max;
  yyjson_val *pod;
  yyjson_arr_foreach(pods_array, pod_idx, pod_max, pod) {
    if (*count >= max_count)
      break;

    yyjson_val *pod_ref = yyjson_obj_get(pod, "podRef");
    yyjson_val *containers_array = yyjson_obj_get(pod, "containers");
    if (!yyjson_is_obj(pod_ref) || !yyjson_is_arr(containers_array))
      continue;

    const char *ns = yyjson_get_str(yyjson_obj_get(pod_ref, "namespace"));
    const char *pod_name = yyjson_get_str(yyjson_obj_get(pod_ref, "name"));
    if (!ns || !pod_name)
      continue;

    // Apply namespace filter
    if (source->namespace_filter && source->namespace_filter[0]) {
      if (strcmp(ns, source->namespace_filter) != 0)
        continue;
    }

    size_t container_idx, container_max;
    yyjson_val *container;
    yyjson_arr_foreach(containers_array, container_idx, container_max,
                       container) {
      if (*count >= max_count)
        break;

      const char *container_name =
          yyjson_get_str(yyjson_obj_get(container, "name"));
      if (!container_name)
        continue;

      yyjson_val *memory_obj = yyjson_obj_get(container, "memory");
      if (!yyjson_is_obj(memory_obj))
        continue;

      int64_t working_set;
      if (!pj_int64(yyjson_obj_get(memory_obj, "workingSetBytes"),
                    &working_set))
        continue;

      uint64_t usage = (uint64_t)working_set;
      pod_limit_t *pod_info =
          lookup_pod_info(source, ns, pod_name, container_name);

      // Skip containers without limits
      if (!pod_info || pod_info->limit_bytes == UINT64_MAX ||
          pod_info->limit_bytes == 0)
        continue;

      pressured_memory_sample_t *sample = &samples[*count];
      sample->namespace = strdup(ns);
      sample->pod_name = strdup(pod_name);
      sample->container_name = strdup(container_name);
      sample->node_name = strdup(node_name);
      sample->pod_ip = pod_info->pod_ip[0] ? strdup(pod_info->pod_ip) : NULL;
      sample->annotations =
          copy_annotations(pod_info->annotations, pod_info->annotations_count);
      sample->annotations_count = pod_info->annotations_count;
      sample->usage_bytes = usage;
      sample->limit_bytes = pod_info->limit_bytes;
      sample->usage_percent = (double)usage / (double)pod_info->limit_bytes;
      sample->timestamp = time(NULL);

      (*count)++;

      log_trace("sample: %s/%s/%s usage=%.1f%%", ns, pod_name, container_name,
                sample->usage_percent * 100.0);
    }
  }

  yyjson_doc_free(doc);
  return 0;
}

// Check if we've already seen this OOM event UID
static int is_event_seen(const kubelet_source_t *source, const char *uid) {
  for (int i = 0; i < source->seen_event_count; i++) {
    if (strcmp(source->seen_events[i].uid, uid) == 0) {
      return 1;
    }
  }
  return 0;
}

// Mark an OOM event as seen
static void mark_event_seen(kubelet_source_t *source, const char *uid) {
  char *copy = strdup(uid);
  if (!copy)
    return;
  if (source->seen_event_count >= MAX_OOM_EVENTS) {
    // Evict oldest half of events (simple LRU approximation)
    int keep = MAX_OOM_EVENTS / 2;
    for (int i = 0; i < MAX_OOM_EVENTS - keep; i++)
      free(source->seen_events[i].uid);
    memmove(source->seen_events, &source->seen_events[MAX_OOM_EVENTS - keep],
            keep * sizeof(oom_event_seen_t));
    source->seen_event_count = keep;
  }

  oom_event_seen_t *entry = &source->seen_events[source->seen_event_count++];
  entry->uid = copy;
  entry->timestamp = time(NULL);
}

static bool parse_rfc3339(const char *text, time_t *timestamp) {
  if (!text || strlen(text) < 20)
    return false;
  const char *shape = "0000-00-00T00:00:00";
  for (size_t i = 0; i < 19; i++) {
    if (shape[i] == '0' ? !isdigit((unsigned char)text[i])
                        : text[i] != shape[i])
      return false;
  }
  struct tm tm = {0};
  const char *end = strptime(text, "%Y-%m-%dT%H:%M:%S", &tm);
  if (!end || tm.tm_sec > 60)
    return false;
  const int month_days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  int year = tm.tm_year + 1900;
  int days = month_days[tm.tm_mon];
  if (tm.tm_mon == 1 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))
    days++;
  if (tm.tm_mday > days)
    return false;
  if (*end == '.') {
    end++;
    if (!isdigit((unsigned char)*end))
      return false;
    while (isdigit((unsigned char)*end))
      end++;
  }
  int offset = 0;
  if (*end == 'Z' && end[1] == '\0') {
    // UTC needs no adjustment.
  } else if ((*end == '+' || *end == '-') && strlen(end) == 6 &&
             isdigit((unsigned char)end[1]) && isdigit((unsigned char)end[2]) &&
             end[3] == ':' && isdigit((unsigned char)end[4]) &&
             isdigit((unsigned char)end[5])) {
    int hours = (end[1] - '0') * 10 + end[2] - '0';
    int minutes = (end[4] - '0') * 10 + end[5] - '0';
    if (hours > 23 || minutes > 59)
      return false;
    offset = (hours * 60 + minutes) * 60;
    if (*end == '-')
      offset = -offset;
  } else {
    return false;
  }
  errno = 0;
  time_t utc = timegm(&tm);
  if (errno == EOVERFLOW)
    return false;
  *timestamp = utc - offset;
  return true;
}

static bool oom_event_is_old(yyjson_val *event, time_t now) {
  yyjson_val *series = yyjson_obj_get(event, "series");
  const char *fields[] = {"lastObservedTime", "lastTimestamp", "eventTime",
                          "firstTimestamp"};
  for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
    const char *text =
        yyjson_get_str(yyjson_obj_get(i == 0 ? series : event, fields[i]));
    time_t timestamp;
    if (parse_rfc3339(text, &timestamp))
      return difftime(now, timestamp) > 300;
  }
  return false;
}

// Collect OOM kill events from K8s Events API
// Returns the number of new OOM events added to the samples array
static int collect_oom_events(kubelet_source_t *source,
                              pressured_memory_sample_t *samples, int *count,
                              int max_count) {
  int new_events = 0;

  // Build events API path
  // Query for OOMKilling events (this is the reason kubelet sets for OOM kills)
  char path[MAX_URL];
  if (source->namespace_filter && source->namespace_filter[0]) {
    if (buffer_format(
            path, sizeof(path), "kubelet API path",
            "/api/v1/namespaces/%s/events?fieldSelector=reason=OOMKilling",
            source->namespace_filter) != 0)
      return -1;
  } else {
    if (buffer_format(path, sizeof(path), "kubelet API path",
                      "/api/v1/events?fieldSelector=reason=OOMKilling") != 0)
      return -1;
  }

  char *response = api_request(source, path);
  if (!response) {
    log_debug(
        "no OOM events response (this is normal if no OOM kills occurred)");
    return 0;
  }

  yyjson_doc *doc =
      pj_parse(response, strlen(response), PJ_READ_API, "events response");
  free(response);

  if (!doc) {
    log_warn("failed to parse events response");
    return 0;
  }

  yyjson_val *root = yyjson_doc_get_root(doc);
  yyjson_val *items = yyjson_obj_get(root, "items");
  if (!yyjson_is_arr(items)) {
    yyjson_doc_free(doc);
    return 0;
  }

  log_debug("found %d OOMKilling events", (int)yyjson_arr_size(items));

  size_t event_idx, event_max;
  yyjson_val *event;
  yyjson_arr_foreach(items, event_idx, event_max, event) {
    if (*count >= max_count)
      break;

    if (oom_event_is_old(event, time(NULL)))
      continue;

    yyjson_val *metadata = yyjson_obj_get(event, "metadata");
    yyjson_val *involved_object = yyjson_obj_get(event, "involvedObject");
    if (!yyjson_is_obj(metadata) || !yyjson_is_obj(involved_object))
      continue;

    // Get event UID for deduplication
    const char *uid = yyjson_get_str(yyjson_obj_get(metadata, "uid"));
    if (!uid)
      continue;

    // Skip if we've already seen this event
    if (is_event_seen(source, uid)) {
      continue;
    }

    // Get involved object details (the Pod)
    const char *kind = yyjson_get_str(yyjson_obj_get(involved_object, "kind"));
    const char *ns =
        yyjson_get_str(yyjson_obj_get(involved_object, "namespace"));
    const char *pod_name =
        yyjson_get_str(yyjson_obj_get(involved_object, "name"));
    if (!kind || !ns || !pod_name)
      continue;
    if (strcmp(kind, "Pod") != 0)
      continue; // Only care about Pod events

    // Get container name from fieldPath (e.g., "spec.containers{app}")
    const char *container_name = "unknown";
    const char *field_path =
        yyjson_get_str(yyjson_obj_get(involved_object, "fieldPath"));
    if (field_path) {
      // Parse "spec.containers{container_name}"
      static char container_buf[256];
      const char *start = strchr(field_path, '{');
      const char *end = strchr(field_path, '}');
      if (start && end && end > start + 1) {
        size_t len = end - start - 1;
        if (len < sizeof(container_buf)) {
          memcpy(container_buf, start + 1, len);
          container_buf[len] = '\0';
          container_name = container_buf;
        }
      }
    }

    // Mark as seen before creating sample
    mark_event_seen(source, uid);

    // Try to find existing sample from kubelet stats (preferred - has real
    // usage)
    pressured_memory_sample_t *existing =
        find_existing_sample(samples, *count, ns, pod_name, container_name);
    if (existing) {
      // Just mark existing sample as OOM killed, keep real usage data
      existing->oom_kill_count = 1;
      new_events++;
      log_info("OOM killed event: ns=%s pod=%s container=%s (updated existing "
               "sample)",
               ns, pod_name, container_name);
      continue;
    }

    // No existing sample - pod may have been deleted or not yet collected
    // Look up pod info for metadata
    pod_limit_t *pod_info =
        lookup_pod_info(source, ns, pod_name, container_name);

    // Skip if pod info not found - pod may have been deleted already
    if (!pod_info) {
      log_debug("OOM event but pod info not found, skipping: ns=%s pod=%s "
                "container=%s",
                ns, pod_name, container_name);
      continue;
    }

    // Create OOM-only sample with zero usage to avoid false memory_pressure
    // events The oom_kill_count field will trigger OOM_KILLED event in
    // event_generator
    pressured_memory_sample_t *sample = &samples[*count];
    sample->namespace = strdup(ns);
    sample->pod_name = strdup(pod_name);
    sample->container_name = strdup(container_name);
    sample->node_name = NULL;
    sample->pod_ip = pod_info->pod_ip[0] ? strdup(pod_info->pod_ip) : NULL;
    sample->annotations =
        copy_annotations(pod_info->annotations, pod_info->annotations_count);
    sample->annotations_count = pod_info->annotations_count;
    // Use zero usage to avoid triggering memory_pressure events
    // The OOM_KILLED event only checks oom_kill_count, not usage values
    sample->usage_bytes = 0;
    sample->limit_bytes = pod_info->limit_bytes;
    sample->usage_percent = 0.0;
    sample->oom_kill_count = 1;
    sample->timestamp = time(NULL);

    (*count)++;
    new_events++;

    log_info("OOM killed event: ns=%s pod=%s container=%s (no current sample)",
             ns, pod_name, container_name);
  }

  yyjson_doc_free(doc);
  return new_events;
}

// Collect OOM kill events from Pod Status API
// This is more reliable than Events API as it checks
// containerStatuses.lastState.terminated.reason Returns the number of new OOM
// events added to the samples array
static int collect_oom_from_pod_status(kubelet_source_t *source,
                                       pressured_memory_sample_t *samples,
                                       int *count, int max_count) {
  int new_events = 0;

  // Build pods API path
  char path[MAX_URL];
  if (source->namespace_filter && source->namespace_filter[0]) {
    if (buffer_format(path, sizeof(path), "kubelet API path",
                      "/api/v1/namespaces/%s/pods",
                      source->namespace_filter) != 0)
      return -1;
  } else {
    if (buffer_format(path, sizeof(path), "kubelet API path", "/api/v1/pods") !=
        0)
      return -1;
  }

  char *response = api_request(source, path);
  if (!response) {
    log_debug("no pods response for OOM status check");
    return 0;
  }

  yyjson_doc *doc =
      pj_parse(response, strlen(response), PJ_READ_API, "pods response");
  free(response);

  if (!doc) {
    log_warn("failed to parse pods response for OOM status check");
    return 0;
  }

  yyjson_val *root = yyjson_doc_get_root(doc);
  yyjson_val *items = yyjson_obj_get(root, "items");
  if (!yyjson_is_arr(items)) {
    yyjson_doc_free(doc);
    return 0;
  }

  size_t pod_idx, pod_max;
  yyjson_val *pod;
  yyjson_arr_foreach(items, pod_idx, pod_max, pod) {
    if (*count >= max_count)
      break;

    yyjson_val *metadata = yyjson_obj_get(pod, "metadata");
    yyjson_val *status = yyjson_obj_get(pod, "status");
    yyjson_val *spec = yyjson_obj_get(pod, "spec"); // Optional
    if (!yyjson_is_obj(metadata) || !yyjson_is_obj(status))
      continue;

    // Get pod info
    const char *ns = yyjson_get_str(yyjson_obj_get(metadata, "namespace"));
    const char *pod_name = yyjson_get_str(yyjson_obj_get(metadata, "name"));
    const char *pod_uid = yyjson_get_str(yyjson_obj_get(metadata, "uid"));
    if (!ns || !pod_name || !pod_uid)
      continue;

    // Get node name
    const char *node_name = yyjson_get_str(yyjson_obj_get(spec, "nodeName"));

    // Check containerStatuses for OOM kills
    yyjson_val *container_statuses =
        yyjson_obj_get(status, "containerStatuses");
    if (!yyjson_is_arr(container_statuses))
      continue;

    size_t cs_idx, cs_max;
    yyjson_val *cs;
    yyjson_arr_foreach(container_statuses, cs_idx, cs_max, cs) {
      if (*count >= max_count)
        break;

      const char *container_name = yyjson_get_str(yyjson_obj_get(cs, "name"));
      if (!container_name)
        continue;

      // Check lastState.terminated.reason == "OOMKilled"
      yyjson_val *terminated =
          yyjson_obj_get(yyjson_obj_get(cs, "lastState"), "terminated");
      if (!yyjson_is_obj(terminated))
        continue;

      const char *reason = yyjson_get_str(yyjson_obj_get(terminated, "reason"));
      if (!reason || strcmp(reason, "OOMKilled") != 0)
        continue;

      // Get finishedAt timestamp - skip old OOM events on startup
      const char *finished_at =
          yyjson_get_str(yyjson_obj_get(terminated, "finishedAt"));

      // Skip OOM events older than 5 minutes to avoid false positives on
      // restart The lastState persists until the next container termination, so
      // without this check, every pressured restart would re-report all
      // historical OOMs
      time_t event_time;
      if (parse_rfc3339(finished_at, &event_time)) {
        double age_seconds = difftime(time(NULL), event_time);
        if (age_seconds > 300) {
          log_debug("skipping old OOM event: ns=%s pod=%s container=%s "
                    "finished=%s age=%.0fs",
                    ns, pod_name, container_name, finished_at, age_seconds);
          continue;
        }
      }

      // Get restart count
      int restart_count = 0;
      pj_int(yyjson_obj_get(cs, "restartCount"), &restart_count);

      // Create unique ID for deduplication: pod_uid + container_name +
      // restart_count This ensures we only report each OOM kill once
      char *unique_id = NULL;
      if (asprintf(&unique_id, "%zu:%s:%s:%d", strlen(pod_uid), pod_uid,
                   container_name, restart_count) < 0)
        continue;

      if (is_event_seen(source, unique_id)) {
        free(unique_id);
        continue;
      }

      mark_event_seen(source, unique_id);
      free(unique_id);

      // Try to find existing sample from kubelet stats (preferred - has real
      // usage)
      pressured_memory_sample_t *existing =
          find_existing_sample(samples, *count, ns, pod_name, container_name);
      if (existing) {
        // Just mark existing sample as OOM killed, keep real usage data
        existing->oom_kill_count = 1;
        new_events++;
        log_info("OOM killed (from pod status): ns=%s pod=%s container=%s "
                 "restarts=%d finished=%s (updated existing sample)",
                 ns, pod_name, container_name, restart_count,
                 finished_at ? finished_at : "unknown");
        continue;
      }

      // No existing sample - look up pod info for metadata
      pod_limit_t *pod_info =
          lookup_pod_info(source, ns, pod_name, container_name);

      // Skip if pod info not found - pod may have been deleted already
      if (!pod_info) {
        log_debug("OOM killed but pod info not found, skipping: ns=%s pod=%s "
                  "container=%s",
                  ns, pod_name, container_name);
        continue;
      }

      // Create OOM-only sample with zero usage to avoid false memory_pressure
      // events
      pressured_memory_sample_t *sample = &samples[*count];
      sample->namespace = strdup(ns);
      sample->pod_name = strdup(pod_name);
      sample->container_name = strdup(container_name);
      sample->node_name = node_name ? strdup(node_name) : NULL;
      sample->pod_ip = pod_info->pod_ip[0] ? strdup(pod_info->pod_ip) : NULL;
      sample->annotations =
          copy_annotations(pod_info->annotations, pod_info->annotations_count);
      sample->annotations_count = pod_info->annotations_count;
      // Use zero usage to avoid triggering memory_pressure events
      sample->usage_bytes = 0;
      sample->limit_bytes = pod_info->limit_bytes;
      sample->usage_percent = 0.0;
      sample->oom_kill_count = 1;
      sample->timestamp = time(NULL);

      (*count)++;
      new_events++;

      log_info("OOM killed (from pod status): ns=%s pod=%s container=%s "
               "restarts=%d finished=%s (no current sample)",
               ns, pod_name, container_name, restart_count,
               finished_at ? finished_at : "unknown");
    }
  }

  yyjson_doc_free(doc);
  return new_events;
}

pressured_memory_sample_t *kubelet_collect(kubelet_source_t *source,
                                           int *count) {
  *count = 0;
  source->collection_healthy = false;

  // Refresh node list each cycle to handle dynamic cluster changes
  bool nodes_ok = kubelet_refresh_nodes(source) == 0;
  if (!nodes_ok) {
    log_warn("failed to refresh nodes, using cached list");
  }

  // Refresh pod limits each cycle to handle pod replacements (e.g., after OOM
  // kills)
  bool pods_ok = kubelet_refresh_pod_limits(source) == 0;
  if (!pods_ok) {
    log_warn("failed to refresh pod limits, using cached list");
  }

  // Reuse the buffer owned by the source and clear only the entries the
  // previous cycle wrote; the rest are still zero from the initial calloc. It
  // stays valid until the next kubelet_collect() or kubelet_source_free().
  pressured_memory_sample_t *samples = source->samples;
  memset(samples, 0,
         (size_t)source->sample_count * sizeof(pressured_memory_sample_t));

  // Collect memory usage samples from kubelet stats
  int successful_nodes = 0;
  for (int i = 0; i < source->node_count; i++) {
    if (collect_from_node(source, source->nodes[i].name, samples, count,
                          MAX_PODS) == 0)
      successful_nodes++;
  }
  if (successful_nodes < source->node_count)
    log_warn("stats collection succeeded for %d of %d nodes", successful_nodes,
             source->node_count);
  source->collection_healthy =
      nodes_ok && pods_ok && (source->node_count == 0 || successful_nodes > 0);

  // Collect OOM kill events from K8s Events API (works on some clusters)
  int oom_events = collect_oom_events(source, samples, count, MAX_PODS);
  if (oom_events > 0) {
    log_info("collected %d new OOM kill events from Events API", oom_events);
  }

  // Also collect OOM kills from Pod Status API (more reliable, works on all
  // clusters) This checks containerStatuses.lastState.terminated.reason ==
  // "OOMKilled"
  int oom_from_status =
      collect_oom_from_pod_status(source, samples, count, MAX_PODS);
  if (oom_from_status > 0) {
    log_info("collected %d new OOM kill events from Pod Status API",
             oom_from_status);
  }

  log_debug("collected %d samples from %d nodes", *count, source->node_count);
  source->sample_count = *count;
  return samples;
}

bool kubelet_collect_healthy(const kubelet_source_t *source) {
  return source && source->collection_healthy;
}
