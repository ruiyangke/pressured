#ifndef PRESSURED_H
#define PRESSURED_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define PRESSURED_VERSION "0.1.0"

// Event types
typedef enum {
  EVENT_TYPE_MEMORY_PRESSURE = 0, // Memory usage crossed threshold (predictive)
  EVENT_TYPE_OOM_KILLED = 1       // Container was OOM killed (reactive)
} pressured_event_type_t;

// Severity levels (for memory pressure events)
typedef enum {
  SEVERITY_OK = 0,
  SEVERITY_WARN = 1,
  SEVERITY_CRITICAL = 2
} pressured_severity_t;

// Annotation key-value pair
typedef struct {
  char *key;
  char *value;
} pressured_annotation_t;

// Memory sample from cgroup
typedef struct {
  char *namespace;
  char *pod_name;
  char *pod_uid;
  char *container_name;
  char *node_name;
  char *pod_ip;
  pressured_annotation_t *annotations; // Pod annotations array (NULL if none)
  int annotations_count;               // Number of annotations
  uint64_t usage_bytes;
  uint64_t limit_bytes;
  double usage_percent;
  uint64_t oom_kill_count; // From memory.events oom_kill counter
  time_t timestamp;
} pressured_memory_sample_t;

// Memory event (pressure or OOM killed)
typedef struct pressured_event {
  pressured_event_type_t event_type; // Type of event
  pressured_memory_sample_t sample;
  pressured_severity_t severity; // For memory pressure events
  pressured_severity_t previous_severity;
} pressured_event_t;

// Source mode
typedef enum {
  SOURCE_MODE_CGROUP = 0, // Sidecar mode: read cgroup files directly
  SOURCE_MODE_KUBELET = 1 // Cluster mode: query kubelet API via API server
} pressured_source_mode_t;

// Configuration
typedef struct {
  // Source mode selection
  pressured_source_mode_t source_mode;

  // Thresholds
  double warn_percent;
  double critical_percent;
  double hysteresis_percent;
  int cooldown_seconds;

  // Cgroup source settings
  char *cgroup_path;
  int poll_interval_ms;

  // Kubelet source settings
  char *namespace_filter; // Comma-separated list, NULL = all
  char *label_selector;   // e.g., "app=myapp"

  // General
  bool dry_run;
  char *log_level;
} pressured_config_t;

// Function declarations
pressured_config_t *pressured_config_load(const char *path);
char *pressured_config_load_json(
    const char *path); // Returns raw JSON, caller must free
void pressured_config_free(pressured_config_t *config);

void pressured_memory_sample_free(pressured_memory_sample_t *sample);
void pressured_event_free(pressured_event_t *event);

const char *pressured_severity_str(pressured_severity_t severity);
const char *pressured_event_type_str(pressured_event_type_t event_type);

#endif // PRESSURED_H
