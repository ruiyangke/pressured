#define _GNU_SOURCE // for strptime and timegm
#include "internal.h"
#include "log.h"
#include <curl/curl.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_NODES 128
#define MAX_PODS 4096
#define MAX_URL 1024
#define MAX_TOKEN 8192
#define MAX_OOM_EVENTS 256

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
  char uid[64];     // Event UID (unique per event)
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
  char *token;
  char *ca_cert_path;

  // Node discovery
  node_info_t nodes[MAX_NODES];
  int node_count;

  // Pod limits cache
  pod_limit_t *pod_limits;
  int pod_limit_count;
  int pod_limit_capacity;

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

static char *read_file(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f)
    return NULL;

  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  fseek(f, 0, SEEK_SET);

  char *buf = malloc(size + 1);
  if (!buf) {
    fclose(f);
    return NULL;
  }

  size_t read = fread(buf, 1, size, f);
  buf[read] = '\0';
  fclose(f);

  // Trim trailing newline
  while (read > 0 && (buf[read - 1] == '\n' || buf[read - 1] == '\r')) {
    buf[--read] = '\0';
  }

  return buf;
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

  // Try in-cluster config first
  const char *k8s_host = getenv("KUBERNETES_SERVICE_HOST");
  const char *k8s_port = getenv("KUBERNETES_SERVICE_PORT");

  if (k8s_host && k8s_port) {
    // In-cluster mode
    char api_url[512];
    snprintf(api_url, sizeof(api_url), "https://%s:%s", k8s_host, k8s_port);
    source->api_server = strdup(api_url);
    source->token =
        read_file("/var/run/secrets/kubernetes.io/serviceaccount/token");
    source->ca_cert_path =
        strdup("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt");

    log_info("kubelet source: in-cluster mode api=%s", source->api_server);
  } else {
    // Try kubectl proxy (localhost:8001)
    source->api_server = strdup("http://localhost:8001");
    source->token = NULL;
    source->ca_cert_path = NULL;

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
    free(source->token);
    free(source->ca_cert_path);
    free(source->namespace_filter);
    free(source->label_selector);
    // Free annotations in cached entries before freeing the array
    for (int i = 0; i < source->pod_limit_count; i++) {
      free_annotations(source->pod_limits[i].annotations,
                       source->pod_limits[i].annotations_count);
    }
    free(source->pod_limits);
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
  snprintf(url, sizeof(url), "%s%s", source->api_server, path);

  http_buffer_t buf = {0};
  struct curl_slist *headers = NULL;

  curl_easy_reset(source->curl);
  curl_easy_setopt(source->curl, CURLOPT_URL, url);
  curl_easy_setopt(source->curl, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(source->curl, CURLOPT_WRITEDATA, &buf);
  curl_easy_setopt(source->curl, CURLOPT_TIMEOUT, 10L);

  if (source->token) {
    char auth_header[MAX_TOKEN + 32];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s",
             source->token);
    headers = curl_slist_append(headers, auth_header);
    curl_easy_setopt(source->curl, CURLOPT_HTTPHEADER, headers);
  }

  if (source->ca_cert_path) {
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
    free(buf.data);
    return NULL;
  }

  return buf.data;
}

static int kubelet_refresh_nodes(kubelet_source_t *source) {
  char *response = api_request(source, "/api/v1/nodes");
  if (!response)
    return -1;

  struct json_object *root = json_tokener_parse(response);
  free(response);

  if (!root) {
    log_error("failed to parse nodes response");
    return -1;
  }

  source->node_count = 0;

  struct json_object *items;
  if (json_object_object_get_ex(root, "items", &items)) {
    int len = json_object_array_length(items);
    for (int i = 0; i < len && source->node_count < MAX_NODES; i++) {
      struct json_object *node = json_object_array_get_idx(items, i);
      struct json_object *metadata, *status, *name_obj;

      if (!json_object_object_get_ex(node, "metadata", &metadata))
        continue;
      if (!json_object_object_get_ex(metadata, "name", &name_obj))
        continue;

      const char *name = json_object_get_string(name_obj);
      node_info_t *ni = &source->nodes[source->node_count];
      strncpy(ni->name, name, sizeof(ni->name) - 1);

      // Get node address (prefer InternalIP)
      if (json_object_object_get_ex(node, "status", &status)) {
        struct json_object *addresses;
        if (json_object_object_get_ex(status, "addresses", &addresses)) {
          int addr_len = json_object_array_length(addresses);
          for (int j = 0; j < addr_len; j++) {
            struct json_object *addr = json_object_array_get_idx(addresses, j);
            struct json_object *type_obj, *addr_obj;
            if (json_object_object_get_ex(addr, "type", &type_obj) &&
                json_object_object_get_ex(addr, "address", &addr_obj)) {
              const char *type = json_object_get_string(type_obj);
              if (strcmp(type, "InternalIP") == 0) {
                strncpy(ni->address, json_object_get_string(addr_obj),
                        sizeof(ni->address) - 1);
                break;
              }
            }
          }
        }
      }

      source->node_count++;
    }
  }

  json_object_put(root);
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
static pressured_annotation_t *
parse_annotations(struct json_object *annotations_obj, int *count) {
  *count = 0;
  if (!annotations_obj)
    return NULL;

  int n = json_object_object_length(annotations_obj);
  if (n == 0)
    return NULL;

  pressured_annotation_t *annotations =
      calloc(n, sizeof(pressured_annotation_t));
  if (!annotations)
    return NULL;

  struct json_object_iterator it = json_object_iter_begin(annotations_obj);
  struct json_object_iterator end = json_object_iter_end(annotations_obj);

  while (!json_object_iter_equal(&it, &end)) {
    const char *key = json_object_iter_peek_name(&it);
    struct json_object *val = json_object_iter_peek_value(&it);
    const char *value = json_object_get_string(val);

    annotations[*count].key = strdup(key);
    annotations[*count].value = value ? strdup(value) : strdup("");
    (*count)++;

    json_object_iter_next(&it);
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
  }

  return dst;
}

static int kubelet_refresh_pod_limits(kubelet_source_t *source) {
  // Free any existing annotations before clearing
  for (int i = 0; i < source->pod_limit_count; i++) {
    free_annotations(source->pod_limits[i].annotations,
                     source->pod_limits[i].annotations_count);
    source->pod_limits[i].annotations = NULL;
    source->pod_limits[i].annotations_count = 0;
  }
  source->pod_limit_count = 0;

  // Build API path with optional namespace filter
  char path[MAX_URL];
  if (source->namespace_filter && strlen(source->namespace_filter) > 0) {
    // Single namespace
    snprintf(path, sizeof(path), "/api/v1/namespaces/%s/pods",
             source->namespace_filter);
  } else {
    snprintf(path, sizeof(path), "/api/v1/pods");
  }

  if (source->label_selector && strlen(source->label_selector) > 0) {
    char encoded[512];
    // Simple URL encoding for label selector
    snprintf(encoded, sizeof(encoded), "?labelSelector=%s",
             source->label_selector);
    strncat(path, encoded, sizeof(path) - strlen(path) - 1);
  }

  char *response = api_request(source, path);
  if (!response)
    return -1;

  struct json_object *root = json_tokener_parse(response);
  free(response);

  if (!root) {
    log_error("failed to parse pods response");
    return -1;
  }

  struct json_object *items;
  if (json_object_object_get_ex(root, "items", &items)) {
    int len = json_object_array_length(items);
    for (int i = 0; i < len; i++) {
      struct json_object *pod = json_object_array_get_idx(items, i);
      struct json_object *metadata, *spec;

      if (!json_object_object_get_ex(pod, "metadata", &metadata))
        continue;
      if (!json_object_object_get_ex(pod, "spec", &spec))
        continue;

      struct json_object *ns_obj, *name_obj;
      if (!json_object_object_get_ex(metadata, "namespace", &ns_obj))
        continue;
      if (!json_object_object_get_ex(metadata, "name", &name_obj))
        continue;

      const char *ns = json_object_get_string(ns_obj);
      const char *pod_name = json_object_get_string(name_obj);

      // Get pod IP from status
      const char *pod_ip = NULL;
      struct json_object *status;
      if (json_object_object_get_ex(pod, "status", &status)) {
        struct json_object *pod_ip_obj;
        if (json_object_object_get_ex(status, "podIP", &pod_ip_obj)) {
          pod_ip = json_object_get_string(pod_ip_obj);
        }
      }

      struct json_object *containers;
      if (!json_object_object_get_ex(spec, "containers", &containers))
        continue;

      int container_count = json_object_array_length(containers);
      if (container_count == 0)
        continue;

      // Parse pod annotations into array (only if we have containers to store
      // them)
      pressured_annotation_t *pod_annotations = NULL;
      int pod_annotations_count = 0;
      struct json_object *annotations_obj;
      if (json_object_object_get_ex(metadata, "annotations",
                                    &annotations_obj)) {
        pod_annotations =
            parse_annotations(annotations_obj, &pod_annotations_count);
      }

      int annotations_consumed = 0; // Track if first container took ownership

      for (int j = 0; j < container_count; j++) {
        struct json_object *container =
            json_object_array_get_idx(containers, j);
        struct json_object *container_name_obj, *resources;

        if (!json_object_object_get_ex(container, "name", &container_name_obj))
          continue;
        const char *container_name = json_object_get_string(container_name_obj);

        uint64_t limit = UINT64_MAX;
        if (json_object_object_get_ex(container, "resources", &resources)) {
          struct json_object *limits;
          if (json_object_object_get_ex(resources, "limits", &limits)) {
            struct json_object *mem_limit;
            if (json_object_object_get_ex(limits, "memory", &mem_limit)) {
              limit = parse_quantity(json_object_get_string(mem_limit));
            }
          }
        }

        // Add to cache
        if (source->pod_limit_count >= source->pod_limit_capacity) {
          int new_cap = source->pod_limit_capacity * 2;
          pod_limit_t *new_limits =
              realloc(source->pod_limits, new_cap * sizeof(pod_limit_t));
          if (!new_limits)
            continue;
          source->pod_limits = new_limits;
          source->pod_limit_capacity = new_cap;
        }

        pod_limit_t *pl = &source->pod_limits[source->pod_limit_count++];
        snprintf(pl->key, sizeof(pl->key), "%s/%s/%s", ns, pod_name,
                 container_name);
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
        }
      }

      // Free annotations if no container consumed them (all containers failed
      // validation)
      if (!annotations_consumed) {
        free_annotations(pod_annotations, pod_annotations_count);
      }
    }
  }

  json_object_put(root);
  log_debug("cached limits for %d containers", source->pod_limit_count);
  return 0;
}

int kubelet_source_init(kubelet_source_t *source) {
  if (kubelet_refresh_nodes(source) != 0) {
    return -1;
  }

  if (source->node_count == 0) {
    log_error("no nodes discovered");
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
  snprintf(key, sizeof(key), "%s/%s/%s", ns, pod, container);

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
  snprintf(path, sizeof(path), "/api/v1/nodes/%s/proxy/stats/summary",
           node_name);

  char *response = api_request(source, path);
  if (!response) {
    log_warn("failed to get stats from node %s", node_name);
    return -1;
  }

  struct json_object *root = json_tokener_parse(response);
  free(response);

  if (!root) {
    log_error("failed to parse stats response from %s", node_name);
    return -1;
  }

  struct json_object *pods_array;
  if (!json_object_object_get_ex(root, "pods", &pods_array)) {
    json_object_put(root);
    return 0;
  }

  int pod_count = json_object_array_length(pods_array);
  for (int i = 0; i < pod_count && *count < max_count; i++) {
    struct json_object *pod = json_object_array_get_idx(pods_array, i);
    struct json_object *pod_ref, *containers_array;

    if (!json_object_object_get_ex(pod, "podRef", &pod_ref))
      continue;
    if (!json_object_object_get_ex(pod, "containers", &containers_array))
      continue;

    struct json_object *ns_obj, *name_obj;
    if (!json_object_object_get_ex(pod_ref, "namespace", &ns_obj))
      continue;
    if (!json_object_object_get_ex(pod_ref, "name", &name_obj))
      continue;

    const char *ns = json_object_get_string(ns_obj);
    const char *pod_name = json_object_get_string(name_obj);

    // Apply namespace filter
    if (source->namespace_filter && strlen(source->namespace_filter) > 0) {
      if (strcmp(ns, source->namespace_filter) != 0)
        continue;
    }

    int container_count = json_object_array_length(containers_array);
    for (int j = 0; j < container_count && *count < max_count; j++) {
      struct json_object *container =
          json_object_array_get_idx(containers_array, j);
      struct json_object *container_name_obj, *memory_obj;

      if (!json_object_object_get_ex(container, "name", &container_name_obj))
        continue;
      if (!json_object_object_get_ex(container, "memory", &memory_obj))
        continue;

      const char *container_name = json_object_get_string(container_name_obj);

      struct json_object *working_set_obj;
      if (!json_object_object_get_ex(memory_obj, "workingSetBytes",
                                     &working_set_obj))
        continue;

      uint64_t usage = json_object_get_int64(working_set_obj);
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

  json_object_put(root);
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
  if (source->seen_event_count >= MAX_OOM_EVENTS) {
    // Evict oldest half of events (simple LRU approximation)
    int keep = MAX_OOM_EVENTS / 2;
    memmove(source->seen_events, &source->seen_events[MAX_OOM_EVENTS - keep],
            keep * sizeof(oom_event_seen_t));
    source->seen_event_count = keep;
  }

  oom_event_seen_t *entry = &source->seen_events[source->seen_event_count++];
  strncpy(entry->uid, uid, sizeof(entry->uid) - 1);
  entry->uid[sizeof(entry->uid) - 1] = '\0';
  entry->timestamp = time(NULL);
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
  if (source->namespace_filter && strlen(source->namespace_filter) > 0) {
    snprintf(path, sizeof(path),
             "/api/v1/namespaces/%s/events?fieldSelector=reason=OOMKilling",
             source->namespace_filter);
  } else {
    snprintf(path, sizeof(path),
             "/api/v1/events?fieldSelector=reason=OOMKilling");
  }

  char *response = api_request(source, path);
  if (!response) {
    log_debug(
        "no OOM events response (this is normal if no OOM kills occurred)");
    return 0;
  }

  struct json_object *root = json_tokener_parse(response);
  free(response);

  if (!root) {
    log_warn("failed to parse events response");
    return 0;
  }

  struct json_object *items;
  if (!json_object_object_get_ex(root, "items", &items)) {
    json_object_put(root);
    return 0;
  }

  int event_count = json_object_array_length(items);
  log_debug("found %d OOMKilling events", event_count);

  for (int i = 0; i < event_count && *count < max_count; i++) {
    struct json_object *event = json_object_array_get_idx(items, i);
    struct json_object *metadata, *involved_object;

    if (!json_object_object_get_ex(event, "metadata", &metadata))
      continue;
    if (!json_object_object_get_ex(event, "involvedObject", &involved_object))
      continue;

    // Get event UID for deduplication
    struct json_object *uid_obj;
    if (!json_object_object_get_ex(metadata, "uid", &uid_obj))
      continue;
    const char *uid = json_object_get_string(uid_obj);

    // Skip if we've already seen this event
    if (is_event_seen(source, uid)) {
      continue;
    }

    // Get involved object details (the Pod)
    struct json_object *kind_obj, *ns_obj, *name_obj;
    if (!json_object_object_get_ex(involved_object, "kind", &kind_obj))
      continue;
    if (!json_object_object_get_ex(involved_object, "namespace", &ns_obj))
      continue;
    if (!json_object_object_get_ex(involved_object, "name", &name_obj))
      continue;

    const char *kind = json_object_get_string(kind_obj);
    if (strcmp(kind, "Pod") != 0)
      continue; // Only care about Pod events

    const char *ns = json_object_get_string(ns_obj);
    const char *pod_name = json_object_get_string(name_obj);

    // Get container name from fieldPath (e.g., "spec.containers{app}")
    const char *container_name = "unknown";
    struct json_object *field_path_obj;
    if (json_object_object_get_ex(involved_object, "fieldPath",
                                  &field_path_obj)) {
      const char *field_path = json_object_get_string(field_path_obj);
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

  json_object_put(root);
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
  if (source->namespace_filter && strlen(source->namespace_filter) > 0) {
    snprintf(path, sizeof(path), "/api/v1/namespaces/%s/pods",
             source->namespace_filter);
  } else {
    snprintf(path, sizeof(path), "/api/v1/pods");
  }

  char *response = api_request(source, path);
  if (!response) {
    log_debug("no pods response for OOM status check");
    return 0;
  }

  struct json_object *root = json_tokener_parse(response);
  free(response);

  if (!root) {
    log_warn("failed to parse pods response for OOM status check");
    return 0;
  }

  struct json_object *items;
  if (!json_object_object_get_ex(root, "items", &items)) {
    json_object_put(root);
    return 0;
  }

  int pod_count = json_object_array_length(items);
  for (int i = 0; i < pod_count && *count < max_count; i++) {
    struct json_object *pod = json_object_array_get_idx(items, i);
    struct json_object *metadata, *status, *spec;

    if (!json_object_object_get_ex(pod, "metadata", &metadata))
      continue;
    if (!json_object_object_get_ex(pod, "status", &status))
      continue;
    json_object_object_get_ex(pod, "spec", &spec); // Optional

    // Get pod info
    struct json_object *ns_obj, *name_obj, *uid_obj;
    if (!json_object_object_get_ex(metadata, "namespace", &ns_obj))
      continue;
    if (!json_object_object_get_ex(metadata, "name", &name_obj))
      continue;
    if (!json_object_object_get_ex(metadata, "uid", &uid_obj))
      continue;

    const char *ns = json_object_get_string(ns_obj);
    const char *pod_name = json_object_get_string(name_obj);
    const char *pod_uid = json_object_get_string(uid_obj);
    (void)pod_uid; // May be used for deduplication in future

    // Get node name
    const char *node_name = NULL;
    if (spec) {
      struct json_object *node_name_obj;
      if (json_object_object_get_ex(spec, "nodeName", &node_name_obj)) {
        node_name = json_object_get_string(node_name_obj);
      }
    }

    // Check containerStatuses for OOM kills
    struct json_object *container_statuses;
    if (!json_object_object_get_ex(status, "containerStatuses",
                                   &container_statuses))
      continue;

    int cs_count = json_object_array_length(container_statuses);
    for (int j = 0; j < cs_count && *count < max_count; j++) {
      struct json_object *cs = json_object_array_get_idx(container_statuses, j);
      struct json_object *container_name_obj, *last_state, *restart_count_obj;

      if (!json_object_object_get_ex(cs, "name", &container_name_obj))
        continue;
      const char *container_name = json_object_get_string(container_name_obj);

      // Check lastState.terminated.reason == "OOMKilled"
      if (!json_object_object_get_ex(cs, "lastState", &last_state))
        continue;

      struct json_object *terminated;
      if (!json_object_object_get_ex(last_state, "terminated", &terminated))
        continue;

      struct json_object *reason_obj, *finished_at_obj;
      if (!json_object_object_get_ex(terminated, "reason", &reason_obj))
        continue;

      const char *reason = json_object_get_string(reason_obj);
      if (strcmp(reason, "OOMKilled") != 0)
        continue;

      // Get finishedAt timestamp - skip old OOM events on startup
      const char *finished_at = NULL;
      if (json_object_object_get_ex(terminated, "finishedAt",
                                    &finished_at_obj)) {
        finished_at = json_object_get_string(finished_at_obj);
      }

      // Skip OOM events older than 5 minutes to avoid false positives on
      // restart The lastState persists until the next container termination, so
      // without this check, every pressured restart would re-report all
      // historical OOMs
      if (finished_at) {
        struct tm tm = {0};
        // Parse ISO8601 format: "2025-12-12T21:08:37Z"
        if (strptime(finished_at, "%Y-%m-%dT%H:%M:%S", &tm)) {
          time_t event_time = timegm(&tm);
          time_t now = time(NULL);
          int age_seconds = (int)(now - event_time);
          if (age_seconds > 300) { // 5 minutes
            log_debug("skipping old OOM event: ns=%s pod=%s container=%s "
                      "finished=%s age=%ds",
                      ns, pod_name, container_name, finished_at, age_seconds);
            continue;
          }
        }
      }

      // Get restart count
      int restart_count = 0;
      if (json_object_object_get_ex(cs, "restartCount", &restart_count_obj)) {
        restart_count = json_object_get_int(restart_count_obj);
      }

      // Create unique ID for deduplication: pod_uid + container_name +
      // restart_count This ensures we only report each OOM kill once
      char unique_id[256];
      snprintf(unique_id, sizeof(unique_id), "%s-%s-%d", pod_uid,
               container_name, restart_count);

      if (is_event_seen(source, unique_id)) {
        continue;
      }

      // Mark as seen
      mark_event_seen(source, unique_id);

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

  json_object_put(root);
  return new_events;
}

pressured_memory_sample_t *kubelet_collect(kubelet_source_t *source,
                                           int *count) {
  *count = 0;

  // Refresh node list each cycle to handle dynamic cluster changes
  if (kubelet_refresh_nodes(source) != 0) {
    log_warn("failed to refresh nodes, using cached list");
  }

  // Refresh pod limits each cycle to handle pod replacements (e.g., after OOM
  // kills)
  if (kubelet_refresh_pod_limits(source) != 0) {
    log_warn("failed to refresh pod limits, using cached list");
  }

  pressured_memory_sample_t *samples =
      calloc(MAX_PODS, sizeof(pressured_memory_sample_t));
  if (!samples) {
    log_error("failed to allocate samples array");
    return NULL;
  }

  // Collect memory usage samples from kubelet stats
  for (int i = 0; i < source->node_count; i++) {
    collect_from_node(source, source->nodes[i].name, samples, count, MAX_PODS);
  }

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
  return samples;
}
