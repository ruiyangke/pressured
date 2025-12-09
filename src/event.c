#include "pressured.h"
#include <stdlib.h>
#include <string.h>

const char *pressured_severity_str(pressured_severity_t severity) {
  switch (severity) {
  case SEVERITY_OK:
    return "ok";
  case SEVERITY_WARN:
    return "warn";
  case SEVERITY_CRITICAL:
    return "critical";
  default:
    return "unknown";
  }
}

const char *pressured_event_type_str(pressured_event_type_t event_type) {
  switch (event_type) {
  case EVENT_TYPE_MEMORY_PRESSURE:
    return "memory_pressure";
  case EVENT_TYPE_OOM_KILLED:
    return "oom_killed";
  default:
    return "unknown";
  }
}

void pressured_memory_sample_free(pressured_memory_sample_t *sample) {
  if (sample) {
    free(sample->namespace);
    free(sample->pod_name);
    free(sample->pod_uid);
    free(sample->container_name);
    free(sample->node_name);
    free(sample->pod_ip);
    // Free annotations array
    if (sample->annotations) {
      for (int i = 0; i < sample->annotations_count; i++) {
        free(sample->annotations[i].key);
        free(sample->annotations[i].value);
      }
      free(sample->annotations);
    }
  }
}

void pressured_event_free(pressured_event_t *event) {
  if (event) {
    pressured_memory_sample_free(&event->sample);
  }
}
