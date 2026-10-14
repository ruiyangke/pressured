/*
 * Event Generator Tests
 *
 * Tests OOM kill detection for both sample sources:
 *   - kubelet: oom_kill_count is 1 only in the cycle an OOM kill is detected
 *   - cgroup:  oom_kill_count is the cumulative memory.events oom_kill counter
 */

#include "internal.h"
#include "log.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static pressured_memory_sample_t make_sample(double usage_percent,
                                             uint64_t oom_kill_count) {
  pressured_memory_sample_t s = {0};
  s.namespace = "ns";
  s.pod_name = "pod";
  s.container_name = "app";
  s.limit_bytes = 1000;
  s.usage_bytes = (uint64_t)(usage_percent * 1000);
  s.usage_percent = usage_percent;
  s.oom_kill_count = oom_kill_count;
  return s;
}

// Process one sample and return the number of events of the given type
static int process(event_generator_t *gen, double usage_percent,
                   uint64_t oom_kill_count, pressured_event_type_t type) {
  pressured_memory_sample_t sample = make_sample(usage_percent, oom_kill_count);
  int event_count = 0;
  pressured_event_t *events =
      event_generator_process(gen, &sample, 1, &event_count);
  int matching = 0;
  for (int i = 0; i < event_count; i++) {
    if (events[i].event_type == type)
      matching++;
  }
  event_generator_events_clear(events, event_count);
  return matching;
}

static int oom_events(event_generator_t *gen, uint64_t oom_kill_count) {
  return process(gen, 0.5, oom_kill_count, EVENT_TYPE_OOM_KILLED);
}

static void test_kubelet_reports_each_detected_oom(void) {
  printf("  kubelet: each detected OOM kill is reported... ");
  event_generator_t *gen = event_generator_new(0.8, 0.9, 0.05, 60, false);
  assert(gen);

  assert(oom_events(gen, 0) == 0);
  assert(oom_events(gen, 1) == 1); // first OOM kill of a tracked container
  assert(oom_events(gen, 0) == 0);
  assert(oom_events(gen, 1) == 1); // and the next one

  event_generator_free(gen);
  printf("ok\n");
}

static void test_kubelet_reports_oom_for_untracked_container(void) {
  printf("  kubelet: OOM kill on first sample is reported... ");
  event_generator_t *gen = event_generator_new(0.8, 0.9, 0.05, 60, false);
  assert(gen);

  // OOM-only sample for a container that had no stats sample before
  assert(oom_events(gen, 1) == 1);

  event_generator_free(gen);
  printf("ok\n");
}

static void test_cgroup_ignores_historical_count(void) {
  printf("  cgroup: count on first sample is only the baseline... ");
  event_generator_t *gen = event_generator_new(0.8, 0.9, 0.05, 60, true);
  assert(gen);

  assert(oom_events(gen, 3) == 0); // kills from before we started watching
  assert(oom_events(gen, 3) == 0);
  assert(oom_events(gen, 4) == 1);
  assert(oom_events(gen, 4) == 0);

  event_generator_free(gen);
  printf("ok\n");
}

static void test_cgroup_reports_first_oom(void) {
  printf("  cgroup: first OOM kill (0 -> 1) is reported... ");
  event_generator_t *gen = event_generator_new(0.8, 0.9, 0.05, 60, true);
  assert(gen);

  assert(oom_events(gen, 0) == 0);
  assert(oom_events(gen, 1) == 1);
  assert(oom_events(gen, 1) == 0);

  event_generator_free(gen);
  printf("ok\n");
}

static void test_memory_pressure_still_reported(void) {
  printf("  memory pressure events unaffected... ");
  event_generator_t *gen = event_generator_new(0.8, 0.9, 0.05, 60, false);
  assert(gen);

  assert(process(gen, 0.5, 0, EVENT_TYPE_MEMORY_PRESSURE) == 0);
  assert(process(gen, 0.95, 0, EVENT_TYPE_MEMORY_PRESSURE) == 1);

  event_generator_free(gen);
  printf("ok\n");
}

// The events buffer is reused across calls: a second call with the same sample
// count must return the same buffer.
static void test_process_reuses_buffer(void) {
  printf("  event_generator_process reuses its buffer... ");
  event_generator_t *gen = event_generator_new(0.8, 0.9, 0.05, 60, false);
  assert(gen);

  pressured_memory_sample_t sample = make_sample(0.95, 0);
  int event_count = 0;
  pressured_event_t *first =
      event_generator_process(gen, &sample, 1, &event_count);
  assert(first != NULL);
  assert(event_count == 1);
  event_generator_events_clear(first, event_count);

  pressured_event_t *second =
      event_generator_process(gen, &sample, 1, &event_count);
  assert(second == first);
  event_generator_events_clear(second, event_count);

  event_generator_free(gen);
  printf("ok\n");
}

// A larger sample count must grow the reused buffer while still producing the
// expected events.
static void test_process_grows_buffer(void) {
  printf("  event_generator_process grows for more samples... ");
  event_generator_t *gen = event_generator_new(0.8, 0.9, 0.05, 60, false);
  assert(gen);

  pressured_memory_sample_t solo = make_sample(0.95, 0);
  int event_count = 0;
  pressured_event_t *single =
      event_generator_process(gen, &solo, 1, &event_count);
  assert(single != NULL);
  assert(event_count == 1);
  event_generator_events_clear(single, event_count);

  pressured_memory_sample_t samples[8];
  char names[8][16];
  for (int i = 0; i < 8; i++) {
    snprintf(names[i], sizeof(names[i]), "app-%d", i);
    samples[i] = make_sample(0.95, 0);
    samples[i].container_name = names[i];
  }

  pressured_event_t *grown =
      event_generator_process(gen, samples, 8, &event_count);
  assert(grown != NULL);
  assert(event_count == 8);
  for (int i = 0; i < event_count; i++)
    assert(grown[i].event_type == EVENT_TYPE_MEMORY_PRESSURE);
  event_generator_events_clear(grown, event_count);

  event_generator_free(gen);
  printf("ok\n");
}

int main(void) {
  log_init(LOG_WARN);

  printf("=== Event Generator Tests ===\n\n");

  test_kubelet_reports_each_detected_oom();
  test_kubelet_reports_oom_for_untracked_container();
  test_cgroup_ignores_historical_count();
  test_cgroup_reports_first_oom();
  test_memory_pressure_still_reported();
  test_process_reuses_buffer();
  test_process_grows_buffer();

  printf("\nAll event generator tests passed\n");
  return 0;
}
