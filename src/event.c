#include "pressured.h"

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
