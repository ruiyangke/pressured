#ifndef INTERNAL_H
#define INTERNAL_H

/**
 * Internal header - not part of the public API.
 * Contains declarations for internal components.
 */

#include "pressured.h"

// ============================================================================
// Cgroup Source (sidecar mode)
// ============================================================================

typedef struct cgroup_source cgroup_source_t;

// Cgroup version constants
#define CGROUP_VERSION_UNKNOWN 0
#define CGROUP_VERSION_V1 1
#define CGROUP_VERSION_V2 2

cgroup_source_t *cgroup_source_new(const char *base_path);
void cgroup_source_free(cgroup_source_t *source);
pressured_memory_sample_t *cgroup_collect(cgroup_source_t *source, int *count);
void cgroup_samples_free(pressured_memory_sample_t *samples, int count);

// Memory reading functions (support both v1 and v2)
uint64_t cgroup_read_memory_current(const char *path);
uint64_t cgroup_read_memory_max(const char *path);

// Container info parsing
int cgroup_parse_container_info(const char *cgroup_path, char **namespace,
                                char **pod_name, char **container_name);

// Introspection (for testing)
const char *cgroup_source_get_discovered_path(cgroup_source_t *source);
int cgroup_source_get_version(const cgroup_source_t *source);

// ============================================================================
// Kubelet Source (cluster mode)
// ============================================================================

typedef struct kubelet_source kubelet_source_t;

kubelet_source_t *kubelet_source_new(void);
void kubelet_source_free(kubelet_source_t *source);
int kubelet_source_init(kubelet_source_t *source);
pressured_memory_sample_t *kubelet_collect(kubelet_source_t *source,
                                           int *count);
void kubelet_set_namespace_filter(kubelet_source_t *source,
                                  const char *namespaces);
void kubelet_set_label_selector(kubelet_source_t *source, const char *selector);

// ============================================================================
// Event Generator (converts samples to events based on thresholds)
// ============================================================================

typedef struct event_generator event_generator_t;

event_generator_t *event_generator_new(double warn_percent,
                                       double critical_percent,
                                       double hysteresis_percent,
                                       int cooldown_seconds);
void event_generator_free(event_generator_t *gen);
pressured_event_t *event_generator_process(event_generator_t *gen,
                                           pressured_memory_sample_t *samples,
                                           int sample_count, int *event_count);
void event_generator_events_free(pressured_event_t *events, int count);
pressured_severity_t event_generator_get_severity(event_generator_t *gen,
                                                  const char *namespace,
                                                  const char *pod_name,
                                                  const char *container_name);

// ============================================================================
// HTTP Client (internal utility)
// ============================================================================

char *http_get(const char *url);
char *http_post(const char *url, const char *body, const char *content_type);

#endif // INTERNAL_H
