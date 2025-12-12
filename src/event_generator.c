#include "internal.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_TRACKED_CONTAINERS 1024
#define KEY_MAX_LEN 512

// State for a single container
typedef struct {
  char key[KEY_MAX_LEN];
  pressured_severity_t severity;
  time_t last_event_time;
  uint64_t last_oom_kill_count; // Track OOM kill counter to detect new kills
  uint64_t last_seen_cycle;     // Cycle number when container was last seen
} container_state_t;

struct event_generator {
  double warn_percent;
  double critical_percent;
  double hysteresis_percent;
  int cooldown_seconds;

  container_state_t *states;
  int state_count;
  int state_capacity;
  uint64_t current_cycle; // Incremented each process() call for pruning
};

event_generator_t *event_generator_new(double warn_percent,
                                       double critical_percent,
                                       double hysteresis_percent,
                                       int cooldown_seconds) {
  event_generator_t *gen = malloc(sizeof(event_generator_t));
  if (!gen)
    return NULL;

  gen->warn_percent = warn_percent;
  gen->critical_percent = critical_percent;
  gen->hysteresis_percent = hysteresis_percent;
  gen->cooldown_seconds = cooldown_seconds;

  gen->state_capacity = 64;
  gen->state_count = 0;
  gen->current_cycle = 0;
  gen->states = calloc(gen->state_capacity, sizeof(container_state_t));
  if (!gen->states) {
    free(gen);
    return NULL;
  }

  log_info("event_generator initialized warn=%.0f%% critical=%.0f%% "
           "hysteresis=%.0f%% "
           "cooldown=%ds",
           warn_percent * 100, critical_percent * 100, hysteresis_percent * 100,
           cooldown_seconds);

  return gen;
}

void event_generator_free(event_generator_t *gen) {
  if (gen) {
    free(gen->states);
    free(gen);
  }
}

static container_state_t *find_or_create_state(event_generator_t *gen,
                                               const char *namespace,
                                               const char *pod_name,
                                               const char *container_name) {
  char key[KEY_MAX_LEN];
  snprintf(key, sizeof(key), "%s/%s/%s", namespace, pod_name, container_name);

  // Find existing
  for (int i = 0; i < gen->state_count; i++) {
    if (strcmp(gen->states[i].key, key) == 0) {
      return &gen->states[i];
    }
  }

  // Create new - grow array if needed, but cap at MAX_TRACKED_CONTAINERS
  if (gen->state_count >= gen->state_capacity) {
    if (gen->state_capacity >= MAX_TRACKED_CONTAINERS) {
      log_warn("event_generator: max container states reached (%d), cannot "
               "track new container %s",
               MAX_TRACKED_CONTAINERS, key);
      return NULL;
    }
    int new_cap = gen->state_capacity * 2;
    if (new_cap > MAX_TRACKED_CONTAINERS) {
      new_cap = MAX_TRACKED_CONTAINERS;
    }
    container_state_t *new_states =
        realloc(gen->states, new_cap * sizeof(container_state_t));
    if (!new_states)
      return NULL;
    gen->states = new_states;
    gen->state_capacity = new_cap;
  }

  container_state_t *state = &gen->states[gen->state_count++];
  strncpy(state->key, key, KEY_MAX_LEN - 1);
  state->severity = SEVERITY_OK;
  state->last_event_time = 0;
  state->last_oom_kill_count = 0; // Will be initialized on first sample
  state->last_seen_cycle = gen->current_cycle;

  return state;
}

// Remove states not seen in the current cycle (stale containers)
static void prune_stale_states(event_generator_t *gen) {
  int write_idx = 0;
  int pruned = 0;

  for (int read_idx = 0; read_idx < gen->state_count; read_idx++) {
    if (gen->states[read_idx].last_seen_cycle == gen->current_cycle) {
      // Keep this state - copy if needed
      if (write_idx != read_idx) {
        gen->states[write_idx] = gen->states[read_idx];
      }
      write_idx++;
    } else {
      pruned++;
    }
  }

  if (pruned > 0) {
    log_debug("event_generator: pruned %d stale container states (%d -> %d)",
              pruned, gen->state_count, write_idx);
  }

  gen->state_count = write_idx;
}

static pressured_severity_t calculate_severity(const event_generator_t *gen,
                                               double usage_percent,
                                               pressured_severity_t current) {
  double warn = gen->warn_percent;
  double critical = gen->critical_percent;
  double hysteresis = gen->hysteresis_percent;

  // Apply hysteresis based on current severity
  if (current == SEVERITY_CRITICAL) {
    critical -= hysteresis;
    warn -= hysteresis;
  } else if (current == SEVERITY_WARN) {
    warn -= hysteresis;
  }

  if (usage_percent >= critical) {
    return SEVERITY_CRITICAL;
  } else if (usage_percent >= warn) {
    return SEVERITY_WARN;
  }
  return SEVERITY_OK;
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

// Helper to copy sample data into an event
static void copy_sample_to_event(pressured_event_t *event,
                                 pressured_memory_sample_t *sample) {
  event->sample.namespace = strdup(sample->namespace);
  event->sample.pod_name = strdup(sample->pod_name);
  event->sample.pod_uid = sample->pod_uid ? strdup(sample->pod_uid) : NULL;
  event->sample.container_name = strdup(sample->container_name);
  event->sample.node_name =
      sample->node_name ? strdup(sample->node_name) : NULL;
  event->sample.pod_ip = sample->pod_ip ? strdup(sample->pod_ip) : NULL;
  event->sample.annotations =
      copy_annotations(sample->annotations, sample->annotations_count);
  event->sample.annotations_count = sample->annotations_count;
  event->sample.usage_bytes = sample->usage_bytes;
  event->sample.limit_bytes = sample->limit_bytes;
  event->sample.usage_percent = sample->usage_percent;
  event->sample.oom_kill_count = sample->oom_kill_count;
  event->sample.timestamp = sample->timestamp;
}

pressured_event_t *event_generator_process(event_generator_t *gen,
                                           pressured_memory_sample_t *samples,
                                           int sample_count, int *event_count) {
  *event_count = 0;

  if (sample_count == 0) {
    return NULL;
  }

  // Increment cycle counter for state tracking
  gen->current_cycle++;

  // Allocate max possible events (2x for both pressure and OOM kill events)
  pressured_event_t *events =
      calloc(sample_count * 2, sizeof(pressured_event_t));
  if (!events) {
    log_error("failed to allocate events array");
    return NULL;
  }

  time_t now = time(NULL);

  for (int i = 0; i < sample_count; i++) {
    pressured_memory_sample_t *sample = &samples[i];

    container_state_t *state = find_or_create_state(
        gen, sample->namespace, sample->pod_name, sample->container_name);
    if (!state)
      continue;

    // Mark this state as seen in current cycle
    state->last_seen_cycle = gen->current_cycle;

    // Check for OOM kill events first (highest priority)
    // An increase in oom_kill_count means a new OOM kill occurred
    bool is_new_container =
        (state->last_oom_kill_count == 0 && sample->oom_kill_count > 0);
    bool oom_kill_increased =
        (sample->oom_kill_count > state->last_oom_kill_count);

    if (oom_kill_increased && !is_new_container) {
      // Emit OOM killed event
      pressured_event_t *event = &events[*event_count];
      copy_sample_to_event(event, sample);
      event->event_type = EVENT_TYPE_OOM_KILLED;
      event->severity = SEVERITY_CRITICAL; // OOM kills are always critical
      event->previous_severity = state->severity;

      (*event_count)++;

      log_info(
          "OOM killed event ns=%s pod=%s container=%s oom_kills=%lu (was %lu)",
          sample->namespace, sample->pod_name, sample->container_name,
          sample->oom_kill_count, state->last_oom_kill_count);
    }

    // Update OOM kill count tracking
    state->last_oom_kill_count = sample->oom_kill_count;

    // Check memory pressure events (threshold-based)
    pressured_severity_t new_severity =
        calculate_severity(gen, sample->usage_percent, state->severity);

    bool severity_changed = (new_severity != state->severity);
    bool in_cooldown = (now - state->last_event_time) < gen->cooldown_seconds;

    if (new_severity > SEVERITY_OK && (severity_changed || !in_cooldown)) {
      // Emit memory pressure event
      pressured_event_t *event = &events[*event_count];
      copy_sample_to_event(event, sample);
      event->event_type = EVENT_TYPE_MEMORY_PRESSURE;
      event->severity = new_severity;
      event->previous_severity = state->severity;

      (*event_count)++;

      log_info("memory pressure event type=%s severity=%s ns=%s pod=%s "
               "container=%s usage=%.1f%%",
               pressured_event_type_str(EVENT_TYPE_MEMORY_PRESSURE),
               pressured_severity_str(new_severity), sample->namespace,
               sample->pod_name, sample->container_name,
               sample->usage_percent * 100.0);

      state->last_event_time = now;
    }

    state->severity = new_severity;
  }

  // Prune states for containers not seen in this cycle
  prune_stale_states(gen);

  return events;
}

void event_generator_events_free(pressured_event_t *events, int count) {
  if (events) {
    for (int i = 0; i < count; i++) {
      pressured_event_free(&events[i]);
    }
    free(events);
  }
}

pressured_severity_t event_generator_get_severity(event_generator_t *gen,
                                                  const char *namespace,
                                                  const char *pod_name,
                                                  const char *container_name) {
  char key[KEY_MAX_LEN];
  snprintf(key, sizeof(key), "%s/%s/%s", namespace, pod_name, container_name);

  for (int i = 0; i < gen->state_count; i++) {
    if (strcmp(gen->states[i].key, key) == 0) {
      return gen->states[i].severity;
    }
  }

  return SEVERITY_OK;
}
