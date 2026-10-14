#ifndef INTERNAL_H
#define INTERNAL_H

/**
 * Internal header - not part of the public API.
 * Contains declarations for internal components.
 */

#include "pressured.h"
#include <stdint.h>
#include <time.h>

const char *health_file_path(void);
int health_remove(const char *path);
int health_write(const char *path, time_t now);
const char *health_check(const char *path, time_t now, uintmax_t max_age);
int health_check_cli(int argc, char **argv);

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
// Ownership: the returned array is owned by the source and reused by the next
// cgroup_collect() call. The samples' strings and annotations are owned by the
// source and stay valid until its next collect call or until it is freed; the
// caller never frees anything in a sample, and must never free the array.
pressured_memory_sample_t *cgroup_collect(cgroup_source_t *source, int *count);
// True when the cgroup root was readable and memory usage was read.
bool cgroup_collect_healthy(const cgroup_source_t *source);

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
// Ownership: the returned array is owned by the source and reused by the next
// kubelet_collect() call. The samples' strings and annotations are owned by the
// source and stay valid until its next collect call or until it is freed; the
// caller never frees anything in a sample, and must never free the array.
pressured_memory_sample_t *kubelet_collect(kubelet_source_t *source,
                                           int *count);
// True only when node/pod discovery and at least one node stats request
// succeed. A successful empty node list requires no stats requests.
bool kubelet_collect_healthy(const kubelet_source_t *source);
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
                                       int cooldown_seconds,
                                       bool oom_count_cumulative);
void event_generator_free(event_generator_t *gen);
// Ownership: the returned events array is owned by the generator and reused by
// the next event_generator_process() call. Each event's sample shares the
// strings and annotations of the input sample it came from, so the events are
// valid only until those samples are freed or the next process call. The caller
// must never free the array or the events' contents.
pressured_event_t *event_generator_process(event_generator_t *gen,
                                           pressured_memory_sample_t *samples,
                                           int sample_count, int *event_count);
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
