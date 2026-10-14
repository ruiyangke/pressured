#define _GNU_SOURCE
#include <assert.h>
#include <curl/curl.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

static CURLcode fixture_setopt(CURL *curl, CURLoption option, ...);
static CURLcode fixture_perform(CURL *curl);
static CURLcode fixture_getinfo(CURL *curl, CURLINFO info, ...);
#undef curl_easy_setopt
#undef curl_easy_getinfo
#define curl_easy_setopt fixture_setopt
#define curl_easy_perform fixture_perform
#define curl_easy_getinfo fixture_getinfo
// Exercise the production parsers with JSON fixtures, including request
// failures.
#include "kubelet.c"

static int scenario = -1;
static int finished_cycles;
static int finish_cycle(useconds_t delay);
#define usleep finish_cycle
#define main pressured_main
#include "main.c"
#undef main
#undef usleep

static int finish_cycle(useconds_t delay) {
  (void)delay;
  if (scenario == 8 && finished_cycles++ == 0) {
    const char *path = getenv("PRESSURED_HEALTH_FILE");
    assert(unlink(path) == 0);
    return 0;
  }
  running = 0;
  return 0;
}

static const char *fixture_response = "{\"items\":[]}";
static http_buffer_t *response_buffer;
static char request_path[2048];
static int node_requests;
static long response_code = 200;
static long forced_response_code = 200;
static CURLcode fixture_setopt(CURL *curl, CURLoption option, ...) {
  (void)curl;
  va_list args;
  va_start(args, option);
  if (option == CURLOPT_URL)
    snprintf(request_path, sizeof(request_path), "%s", va_arg(args, char *));
  if (option == CURLOPT_WRITEDATA)
    response_buffer = va_arg(args, void *);
  va_end(args);
  return CURLE_OK;
}
static CURLcode fixture_perform(CURL *curl) {
  (void)curl;
  response_code = forced_response_code;
  if (scenario >= 0) {
    fixture_response = "{\"items\":[]}";
    if (strstr(request_path, "/stats/summary")) {
      fixture_response = "{\"pods\":[]}";
      if (scenario == 1 || (scenario == 2 && strstr(request_path, "/b/")) ||
          (scenario == 8 && finished_cycles > 0))
        fixture_response = NULL;
    } else if (strstr(request_path, "/nodes")) {
      node_requests++;
      fixture_response = "{\"items\":[{\"metadata\":{\"name\":\"a\"}},"
                         "{\"metadata\":{\"name\":\"b\"}}]}";
      if (scenario == 9)
        fixture_response = "{\"items\":[]}";
      if (node_requests > 1) {
        if (scenario == 3)
          fixture_response = NULL;
        else if (scenario == 5)
          fixture_response = "{\"items\":[]}";
        else if (scenario == 6)
          fixture_response = "{}";
      }
    } else if (strstr(request_path, "/pods") && scenario == 4) {
      fixture_response = NULL;
    }
    if (scenario == 7 && node_requests > 1)
      response_code = 401;
  }
  if (!fixture_response)
    return CURLE_HTTP_RETURNED_ERROR;
  write_callback((void *)fixture_response, 1, strlen(fixture_response),
                 response_buffer);
  return CURLE_OK;
}
static CURLcode fixture_getinfo(CURL *curl, CURLINFO info, ...) {
  (void)curl;
  assert(info == CURLINFO_RESPONSE_CODE);
  va_list args;
  va_start(args, info);
  *va_arg(args, long *) = response_code;
  va_end(args);
  return CURLE_OK;
}

static void test_dedupe(kubelet_source_t *source) {
  char id[1024];
  memset(id, 'x', sizeof(id) - 1);
  id[sizeof(id) - 1] = '\0';
  assert(!is_event_seen(source, id));
  mark_event_seen(source, id);
  assert(is_event_seen(source, id));
  id[900] = 'y';
  assert(!is_event_seen(source, id));
  mark_event_seen(source, id);
  assert(is_event_seen(source, id));
  char container[601];
  memset(container, 'c', sizeof(container) - 1);
  container[sizeof(container) - 1] = '\0';
  char fixture[2048];
  for (int i = 0; i < 2; i++) {
    container[500] = (char)('a' + i);
    snprintf(
        fixture, sizeof(fixture),
        "{\"items\":[{\"metadata\":{\"namespace\":\"ns\",\"name\":\"pod\","
        "\"uid\":\"uid\"},\"status\":{\"containerStatuses\":[{\"name\":\"%s\","
        "\"restartCount\":1,\"lastState\":{\"terminated\":{\"reason\":"
        "\"OOMKilled\"}}}]}}]}",
        container);
    fixture_response = fixture;
    pressured_memory_sample_t sample = {
        .namespace = "ns", .pod_name = "pod", .container_name = container};
    int count = 1;
    assert(collect_oom_from_pod_status(source, &sample, &count, 2) == 1);
    assert(collect_oom_from_pod_status(source, &sample, &count, 2) == 0);
  }
  // Exercise eviction and destruction of owned IDs.
  for (int i = 0; i < MAX_OOM_EVENTS * 2; i++) {
    snprintf(id, sizeof(id), "event-%d", i);
    mark_event_seen(source, id);
  }
  assert(is_event_seen(source, id));
}

static void test_collection(void) {
  char directory[] = "/tmp/pressured-collection-XXXXXX";
  assert(mkdtemp(directory));
  char config[512], heartbeat[512];
  snprintf(config, sizeof(config), "%s/config.json", directory);
  snprintf(heartbeat, sizeof(heartbeat), "%s/healthy", directory);
  FILE *file = fopen(config, "w");
  assert(file);
  fputs("{\"source\":{\"mode\":\"kubelet\"}}", file);
  int result = fclose(file);
  assert(result == 0);
  assert(setenv("PRESSURED_HEALTH_FILE", heartbeat, 1) == 0);
  unsetenv("PRESSURED_PLUGIN_DIR");
  for (scenario = 0; scenario < 10; scenario++) {
    node_requests = 0;
    finished_cycles = 0;
    running = 1;
    optind = 0;
    char *args[] = {"pressured", "-c", config, NULL};
    assert(pressured_main(3, args) == 0);
    bool expected =
        scenario == 0 || scenario == 2 || scenario == 5 || scenario == 9;
    assert((access(heartbeat, F_OK) == 0) == expected);
    if (expected)
      assert(unlink(heartbeat) == 0);
  }
  assert(unlink(config) == 0);
  assert(rmdir(directory) == 0);
}

static void test_cache(kubelet_source_t *source) {
  fixture_response =
      "{\"items\":[{\"metadata\":{\"namespace\":\"ns\",\"name\":\"pod\","
      "\"annotations\":{\"key\":\"value\"}},\"spec\":{\"containers\":["
      "{\"name\":\"app\",\"resources\":{\"limits\":{\"memory\":\"1Mi\"}}},"
      "{\"name\":\"sidecar\"}]}}]}";
  int result = kubelet_refresh_pod_limits(source);
  assert(result == 0);
  const char *failures[] = {NULL, "garbage", "{}", "{\"items\":{}}"};
  for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
    fixture_response = failures[i];
    result = kubelet_refresh_pod_limits(source);
    assert(result == -1);
    pod_limit_t *pod = lookup_pod_info(source, "ns", "pod", "app");
    assert(pod != NULL);
    assert(pod->limit_bytes == 1048576);
    assert(pod->annotations_count == 1);
    assert(strcmp(pod->annotations[0].value, "value") == 0);
  }
  fixture_response = "{\"items\":[]}";
  result = kubelet_refresh_pod_limits(source);
  assert(result == 0);
  assert(lookup_pod_info(source, "ns", "pod", "app") == NULL);
}

static void test_nodes(kubelet_source_t *source) {
  fixture_response =
      "{\"items\":["
      // ExternalIP listed before InternalIP: InternalIP must win.
      "{\"metadata\":{\"name\":\"node-a\"},\"status\":{\"addresses\":["
      "{\"type\":\"ExternalIP\",\"address\":\"10.0.0.1\"},"
      "{\"type\":\"InternalIP\",\"address\":\"192.168.1.1\"}]}},"
      // No InternalIP: the address stays empty because the node array is
      // freshly zeroed and a missing InternalIP is never cleared explicitly.
      "{\"metadata\":{\"name\":\"node-b\"},\"status\":{\"addresses\":["
      "{\"type\":\"ExternalIP\",\"address\":\"10.0.0.2\"}]}},"
      // No addresses at all.
      "{\"metadata\":{\"name\":\"node-c\"}}]}";
  int result = kubelet_refresh_nodes(source);
  assert(result == 0);
  assert(source->node_count == 3);
  assert(strcmp(source->nodes[0].name, "node-a") == 0);
  assert(strcmp(source->nodes[0].address, "192.168.1.1") == 0);
  assert(strcmp(source->nodes[1].name, "node-b") == 0);
  assert(source->nodes[1].address[0] == '\0');
  assert(strcmp(source->nodes[2].name, "node-c") == 0);
  assert(source->nodes[2].address[0] == '\0');

  // A null name is skipped and a null address type does not match InternalIP.
  fixture_response =
      "{\"items\":["
      "{\"metadata\":{\"name\":null}},"
      "{\"metadata\":{\"name\":\"node-d\"},\"status\":{\"addresses\":["
      "{\"type\":null,\"address\":\"1.1.1.1\"},"
      "{\"type\":\"InternalIP\",\"address\":\"2.2.2.2\"}]}}]}";
  result = kubelet_refresh_nodes(source);
  assert(result == 0);
  assert(source->node_count == 1);
  assert(strcmp(source->nodes[0].name, "node-d") == 0);
  assert(strcmp(source->nodes[0].address, "2.2.2.2") == 0);
}

static void test_stats(kubelet_source_t *source) {
  // Cache limits for the containers the stats response will reference.
  fixture_response =
      "{\"items\":["
      "{\"metadata\":{\"namespace\":\"ns\",\"name\":\"pod-a\"},\"spec\":{"
      "\"containers\":["
      "{\"name\":\"int\",\"resources\":{\"limits\":{\"memory\":\"1Mi\"}}},"
      "{\"name\":\"float\",\"resources\":{\"limits\":{\"memory\":\"1Mi\"}}},"
      "{\"name\":\"missing\",\"resources\":{\"limits\":{\"memory\":\"1Mi\"}}},"
      "{\"name\":\"nolimit\"}]}},"
      "{\"metadata\":{\"namespace\":\"ns\",\"name\":\"pod-b\"},\"spec\":{"
      "\"containers\":[{\"name\":\"big\",\"resources\":{\"limits\":{\"memory\":"
      "\"1Gi\"}}}]}}]}";
  int result = kubelet_refresh_pod_limits(source);
  assert(result == 0);

  fixture_response =
      "{\"pods\":["
      "{\"podRef\":{\"namespace\":\"ns\",\"name\":\"pod-a\"},\"containers\":["
      "{\"name\":\"int\",\"memory\":{\"workingSetBytes\":500}},"
      "{\"name\":\"float\",\"memory\":{\"workingSetBytes\":1048576.0}},"
      "{\"name\":\"missing\",\"memory\":{}},"
      "{\"name\":\"nolimit\",\"memory\":{\"workingSetBytes\":777}}]},"
      "{\"podRef\":{\"namespace\":\"ns\",\"name\":\"pod-b\"},\"containers\":["
      "{\"name\":\"big\",\"memory\":{\"workingSetBytes\":"
      "18446744073709551615}}]},"
      // pod-c has no cached limit, so its container must be skipped.
      "{\"podRef\":{\"namespace\":\"ns\",\"name\":\"pod-c\"},\"containers\":["
      "{\"name\":\"app\",\"memory\":{\"workingSetBytes\":42}}]}]}";
  pressured_memory_sample_t samples[8] = {0};
  int count = 0;
  assert(collect_from_node(source, "node-a", samples, &count, 8) == 0);
  assert(count == 3);

  assert(strcmp(samples[0].container_name, "int") == 0);
  assert(samples[0].usage_bytes == 500);
  assert(samples[0].limit_bytes == 1048576);
  assert(strcmp(samples[0].node_name, "node-a") == 0);

  // A JSON float is truncated to its integer value (1048576.0 -> 1048576).
  assert(strcmp(samples[1].container_name, "float") == 0);
  assert(samples[1].usage_bytes == 1048576);

  // An out-of-range integer clamps to INT64_MAX under json-c.
  assert(strcmp(samples[2].container_name, "big") == 0);
  assert(samples[2].usage_bytes == 9223372036854775807ULL);
  assert(samples[2].limit_bytes == 1073741824ULL);

  for (int i = 0; i < count; i++)
    pressured_memory_sample_free(&samples[i]);
}

static void test_pod_limits(kubelet_source_t *source) {
  // parse_annotations yields nothing for NULL or an empty object.
  int annotation_count = 7;
  pressured_annotation_t *parsed = parse_annotations(NULL, &annotation_count);
  assert(parsed == NULL);
  assert(annotation_count == 0);
  yyjson_doc *empty = pj_parse("{}", strlen("{}"), PJ_READ_API, "test");
  assert(empty);
  parsed = parse_annotations(yyjson_doc_get_root(empty), &annotation_count);
  assert(parsed == NULL);
  assert(annotation_count == 0);
  yyjson_doc_free(empty);

  fixture_response =
      "{\"items\":["
      "{\"metadata\":{\"namespace\":\"ns\",\"name\":\"pod-units\","
      "\"annotations\":{\"a\":\"1\",\"b\":\"2\"}},"
      "\"status\":{\"podIP\":\"10.1.2.3\"},\"spec\":{\"containers\":["
      "{\"name\":\"mi\",\"resources\":{\"limits\":{\"memory\":\"1Mi\"}}},"
      "{\"name\":\"gi\",\"resources\":{\"limits\":{\"memory\":\"1Gi\"}}},"
      "{\"name\":\"ki\",\"resources\":{\"limits\":{\"memory\":\"1Ki\"}}},"
      "{\"name\":\"m\",\"resources\":{\"limits\":{\"memory\":\"1M\"}}},"
      "{\"name\":\"bytes\",\"resources\":{\"limits\":{\"memory\":"
      "\"1048576\"}}},"
      "{\"name\":\"none\"}]}},"
      "{\"metadata\":{\"namespace\":\"ns\",\"name\":\"pod-noip\"},\"spec\":{"
      "\"containers\":[{\"name\":\"app\",\"resources\":{\"limits\":{\"memory\":"
      "\"2Mi\"}}}]}}]}";
  int result = kubelet_refresh_pod_limits(source);
  assert(result == 0);

  const struct {
    const char *container;
    uint64_t bytes;
  } cases[] = {
      {"mi", 1048576}, {"gi", 1073741824}, {"ki", 1024},
      {"m", 1000000},  {"bytes", 1048576}, {"none", UINT64_MAX},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    pod_limit_t *pod =
        lookup_pod_info(source, "ns", "pod-units", cases[i].container);
    assert(pod != NULL);
    assert(pod->limit_bytes == cases[i].bytes);
    assert(strcmp(pod->pod_ip, "10.1.2.3") == 0);
  }

  pod_limit_t *annotated = lookup_pod_info(source, "ns", "pod-units", "mi");
  assert(annotated->annotations != NULL);
  assert(annotated->annotations_count == 2);
  int saw_a = 0, saw_b = 0;
  for (int i = 0; i < annotated->annotations_count; i++) {
    if (strcmp(annotated->annotations[i].key, "a") == 0 &&
        strcmp(annotated->annotations[i].value, "1") == 0)
      saw_a = 1;
    if (strcmp(annotated->annotations[i].key, "b") == 0 &&
        strcmp(annotated->annotations[i].value, "2") == 0)
      saw_b = 1;
  }
  assert(saw_a && saw_b);

  // No annotations and no pod IP.
  pod_limit_t *noip = lookup_pod_info(source, "ns", "pod-noip", "app");
  assert(noip != NULL);
  assert(noip->limit_bytes == 2 * 1048576);
  assert(noip->annotations == NULL);
  assert(noip->annotations_count == 0);
  assert(noip->pod_ip[0] == '\0');

  // JSON null and wrong types behave as missing: a null namespace is skipped,
  // null/non-string annotations read as "", a null podIP is empty and a
  // null/numeric memory limit gives UINT64_MAX.
  fixture_response =
      "{\"items\":["
      "{\"metadata\":{\"namespace\":null,\"name\":\"pod-nullns\"},\"spec\":{"
      "\"containers\":[{\"name\":\"app\"}]}},"
      "{\"metadata\":{\"namespace\":\"ns\",\"name\":\"pod-odd\","
      "\"annotations\":{\"k\":null,\"n\":5,\"t\":\"x\"}},"
      "\"status\":{\"podIP\":null},\"spec\":{\"containers\":["
      "{\"name\":null},"
      "{\"name\":\"nolimit\",\"resources\":{\"limits\":{\"memory\":null}}},"
      "{\"name\":\"numeric\",\"resources\":{\"limits\":{\"memory\":1048576}}}]}"
      "}]}";
  result = kubelet_refresh_pod_limits(source);
  assert(result == 0);
  assert(source->pod_limit_count == 2);
  assert(lookup_pod_info(source, "ns", "pod-nullns", "app") == NULL);

  pod_limit_t *nolimit = lookup_pod_info(source, "ns", "pod-odd", "nolimit");
  assert(nolimit != NULL);
  assert(nolimit->limit_bytes == UINT64_MAX);
  assert(nolimit->pod_ip[0] == '\0');
  assert(lookup_pod_info(source, "ns", "pod-odd", "numeric")->limit_bytes ==
         UINT64_MAX);
  assert(nolimit->annotations_count == 3);
  int saw_k = 0, saw_n = 0, saw_t = 0;
  for (int i = 0; i < nolimit->annotations_count; i++) {
    const char *key = nolimit->annotations[i].key;
    const char *value = nolimit->annotations[i].value;
    if (strcmp(key, "k") == 0)
      saw_k = strcmp(value, "") == 0;
    if (strcmp(key, "n") == 0)
      saw_n = strcmp(value, "") == 0;
    if (strcmp(key, "t") == 0)
      saw_t = strcmp(value, "x") == 0;
  }
  assert(saw_k && saw_n && saw_t);
}

static void test_age(kubelet_source_t *source) {
  const char *fields[] = {"lastTimestamp", "eventTime", "firstTimestamp"};
  for (int f = 0; f < 3; f++) {
    for (int recent = 0; recent < 2; recent++) {
      time_t when = time(NULL) - (recent ? 30 : 600);
      char timestamp[64], fixture[1024];
      struct tm tm;
      gmtime_r(&when, &tm);
      strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm);
      snprintf(fixture, sizeof(fixture),
               "{\"items\":[{\"metadata\":{\"uid\":\"%d-%d\"},\"%s\":\"%s\","
               "\"involvedObject\":{\"kind\":\"Pod\",\"namespace\":\"ns\","
               "\"name\":\"pod\",\"fieldPath\":\"spec.containers{app}\"}}]}",
               f, recent, fields[f], timestamp);
      fixture_response = fixture;
      pressured_memory_sample_t sample = {
          .namespace = "ns", .pod_name = "pod", .container_name = "app"};
      int count = 1;
      assert(collect_oom_events(source, &sample, &count, 2) == recent);
      assert(sample.oom_kill_count == (uint64_t)recent);
      assert(collect_oom_events(source, &sample, &count, 2) == 0);
    }
  }
}

static void format_timestamp(char *buffer, size_t size, time_t when,
                             const char *suffix) {
  struct tm tm;
  assert(gmtime_r(&when, &tm));
  size_t length = strftime(buffer, size, "%Y-%m-%dT%H:%M:%S", &tm);
  assert(length > 0);
  assert(strlen(buffer) + strlen(suffix) < size);
  strcat(buffer, suffix);
}

static void test_series(void) {
  time_t now = time(NULL);
  char old[64], recent[64], fixture[1024];
  format_timestamp(old, sizeof(old), now - 600, "Z");
  format_timestamp(recent, sizeof(recent), now - 30, ".123456Z");
  for (int series_old = 0; series_old < 2; series_old++) {
    snprintf(fixture, sizeof(fixture),
             "{\"series\":{\"lastObservedTime\":\"%s\"},"
             "\"lastTimestamp\":\"%s\",\"eventTime\":\"%s\","
             "\"firstTimestamp\":\"%s\"}",
             series_old ? old : recent, series_old ? recent : old, old, old);
    struct json_object *event = json_tokener_parse(fixture);
    assert(event);
    assert(oom_event_is_old(event, now) == (bool)series_old);
    json_object_put(event);
  }
  const char *fields[] = {"lastTimestamp", "eventTime", "firstTimestamp"};
  for (int i = 0; i < 3; i++) {
    snprintf(fixture, sizeof(fixture),
             "{\"series\":{\"lastObservedTime\":null},\"%s\":\"%s\"}",
             fields[i], old);
    struct json_object *event = json_tokener_parse(fixture);
    assert(event);
    assert(oom_event_is_old(event, now));
    json_object_put(event);
  }
}

static void test_pod_status_oom(kubelet_source_t *source) {
  // Cache a limit so the OOM path can build a sample without an existing one.
  fixture_response =
      "{\"items\":[{\"metadata\":{\"namespace\":\"ns\",\"name\":\"pod\"},"
      "\"spec\":{\"containers\":[{\"name\":\"app\",\"resources\":{\"limits\":"
      "{\"memory\":\"1Mi\"}}}]}}]}";
  int result = kubelet_refresh_pod_limits(source);
  assert(result == 0);

  char finished[64];
  format_timestamp(finished, sizeof(finished), time(NULL) - 30, "Z");
  const char *format =
      "{\"items\":[{\"metadata\":{\"namespace\":\"ns\",\"name\":\"pod\","
      "\"uid\":\"%s\"},\"spec\":{\"nodeName\":\"node-a\"},"
      "\"status\":{\"containerStatuses\":[{\"name\":\"app\","
      "\"restartCount\":%s,\"lastState\":{\"terminated\":{\"reason\":"
      "\"OOMKilled\",\"finishedAt\":\"%s\"}}}]}}]}";
  char fixture[2048];
  pressured_memory_sample_t samples[4] = {0};
  int count;

  // restartCount as an integer creates one OOM sample.
  snprintf(fixture, sizeof(fixture), format, "uid-int", "1", finished);
  fixture_response = fixture;
  count = 0;
  assert(collect_oom_from_pod_status(source, samples, &count, 4) == 1);
  assert(count == 1);
  assert(strcmp(samples[0].container_name, "app") == 0);
  assert(strcmp(samples[0].node_name, "node-a") == 0);
  assert(samples[0].oom_kill_count == 1);
  assert(samples[0].usage_bytes == 0);
  assert(samples[0].limit_bytes == 1048576);
  pressured_memory_sample_free(&samples[0]);

  // The same UID and restart count is deduplicated.
  memset(samples, 0, sizeof(samples));
  count = 0;
  assert(collect_oom_from_pod_status(source, samples, &count, 4) == 0);
  assert(count == 0);

  // A different restart count is a new event.
  snprintf(fixture, sizeof(fixture), format, "uid-int", "2", finished);
  memset(samples, 0, sizeof(samples));
  count = 0;
  assert(collect_oom_from_pod_status(source, samples, &count, 4) == 1);
  assert(count == 1);
  pressured_memory_sample_free(&samples[0]);

  // A string restartCount is still read as its numeric value under json-c.
  snprintf(fixture, sizeof(fixture), format, "uid-str", "\"1\"", finished);
  memset(samples, 0, sizeof(samples));
  count = 0;
  assert(collect_oom_from_pod_status(source, samples, &count, 4) == 1);
  assert(count == 1);
  pressured_memory_sample_free(&samples[0]);
}

static void test_timestamps(kubelet_source_t *source, bool pod_status) {
  const struct {
    const char *suffix;
    int offset;
    bool valid;
  } cases[] = {
      {"Z", 0, true},
      {".123456Z", 0, true},
      {"+05:30", 19800, true},
      {"-07:00", -25200, true},
      {".123456+05:30", 19800, true},
      {".123456-07:00", -25200, true},
      {"Zgarbage", 0, false},
      {".123456Zgarbage", 0, false},
      {"+05:30garbage", 0, false},
      {"", 0, false},
      {".Z", 0, false},
      {"+24:00", 0, false},
      {"+00:60", 0, false},
      {"+5:30", 0, false},
      {"+05", 0, false},
      {"+0530", 0, false},
  };
  int failures = 0;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    for (int recent = 0; recent < 2; recent++) {
      char timestamp[128], fixture[2048];
      format_timestamp(timestamp, sizeof(timestamp),
                       time(NULL) - (recent ? 30 : 600) + cases[i].offset,
                       cases[i].suffix);
      if (pod_status)
        snprintf(
            fixture, sizeof(fixture),
            "{\"items\":[{\"metadata\":{\"namespace\":\"ns\",\"name\":\"pod\","
            "\"uid\":\"%zu-%d\"},\"status\":{\"containerStatuses\":[{\"name\":"
            "\"app\","
            "\"restartCount\":1,\"lastState\":{\"terminated\":{\"reason\":"
            "\"OOMKilled\",\"finishedAt\":\"%s\"}}}]}}]}",
            i, recent, timestamp);
      else
        snprintf(fixture, sizeof(fixture),
                 "{\"items\":[{\"metadata\":{\"uid\":\"%zu-%d\"},\"eventTime\":"
                 "\"%s\","
                 "\"involvedObject\":{\"kind\":\"Pod\",\"namespace\":\"ns\","
                 "\"name\":\"pod\",\"fieldPath\":\"spec.containers{app}\"}}]}",
                 i, recent, timestamp);
      fixture_response = fixture;
      pressured_memory_sample_t sample = {
          .namespace = "ns", .pod_name = "pod", .container_name = "app"};
      int count = 1;
      int expected = recent || !cases[i].valid;
      int collected =
          pod_status ? collect_oom_from_pod_status(source, &sample, &count, 2)
                     : collect_oom_events(source, &sample, &count, 2);
      if (collected != expected ||
          sample.oom_kill_count != (uint64_t)expected) {
        fprintf(stderr, "timestamp %s: expected %d OOM, got %d\n", timestamp,
                expected, collected);
        failures++;
      }
    }
  }
  assert(failures == 0);
}

static void write_token(const char *path, const char *token) {
  FILE *file = fopen(path, "w");
  assert(file);
  int result = fputs(token, file);
  assert(result >= 0);
  result = fclose(file);
  assert(result == 0);
}

static void test_token(kubelet_source_t *source) {
  char path[PATH_MAX] = "./token-bounds-XXXXXX";
  int fd = mkstemp(path);
  assert(fd >= 0);
  assert(close(fd) == 0);
  assert(buffer_copy(source->token_path, sizeof(source->token_path), path,
                     "test token path") == 0);
  FILE *messages = tmpfile();
  assert(messages);
  int saved = dup(STDERR_FILENO);
  assert(saved >= 0);
  assert(dup2(fileno(messages), STDERR_FILENO) >= 0);

  write_token(path, "previous\r\n");
  reload_token(source);
  assert(strcmp(source->token, "previous") == 0);
  reload_token(source);
  char token[MAX_TOKEN + 1];
  memset(token, 'x', sizeof(token) - 1);
  token[sizeof(token) - 1] = '\0';
  write_token(path, token);
  reload_token(source);
  assert(strcmp(source->token, "previous") == 0);
  token[MAX_TOKEN - 1] = '\0';
  write_token(path, token);
  reload_token(source);
  assert(strcmp(source->token, token) == 0);
  // An exact-fit token followed by a line ending still fits
  token[0] = 'y';
  char with_newline[MAX_TOKEN + 2];
  snprintf(with_newline, sizeof(with_newline), "%s\r\n", token);
  write_token(path, with_newline);
  reload_token(source);
  assert(strcmp(source->token, token) == 0);
  write_token(path, "rotated");
  source->token_loaded_at = monotonic_seconds() + 1;
  char *response = api_request(source, "/api/v1/pods");
  assert(response);
  free(response);
  assert(strcmp(source->token, token) == 0);
  source->token_loaded_at = monotonic_seconds() - TOKEN_RELOAD_INTERVAL_SEC;
  response = api_request(source, "/api/v1/pods");
  assert(response);
  free(response);
  assert(strcmp(source->token, "rotated") == 0);
  write_token(path, "after-401");
  forced_response_code = 401;
  assert(api_request(source, "/api/v1/pods") == NULL);
  forced_response_code = 200;
  assert(strcmp(source->token, "after-401") == 0);
  reload_token(source);
  write_token(path, "\r\n");
  reload_token(source);
  assert(strcmp(source->token, "after-401") == 0);
  assert(unlink(path) == 0);
  reload_token(source);
  assert(strcmp(source->token, "after-401") == 0);

  int result = fflush(stderr);
  assert(result == 0);
  assert(dup2(saved, STDERR_FILENO) >= 0);
  close(saved);
  rewind(messages);
  char message[1024];
  int reloads = 0, oversized = 0;
  while (fgets(message, sizeof(message), messages)) {
    if (strstr(message, "service account token reloaded"))
      reloads++;
    if (strstr(message, "WARN") && strstr(message, "too long"))
      oversized++;
  }
  assert(reloads == 4);
  assert(oversized == 1);
  result = fclose(messages);
  assert(result == 0);
}

int main(int argc, char **argv) {
  assert(argc == 2);
  unsetenv("KUBERNETES_SERVICE_HOST");
  kubelet_source_t *source = kubelet_source_new();
  assert(source);
  if (strcmp(argv[1], "token") == 0)
    test_token(source);
  else if (strcmp(argv[1], "dedupe") == 0)
    test_dedupe(source);
  else if (strcmp(argv[1], "cache") == 0)
    test_cache(source);
  else if (strcmp(argv[1], "nodes") == 0)
    test_nodes(source);
  else if (strcmp(argv[1], "stats") == 0)
    test_stats(source);
  else if (strcmp(argv[1], "pod_limits") == 0)
    test_pod_limits(source);
  else if (strcmp(argv[1], "pod_oom") == 0)
    test_pod_status_oom(source);
  else if (strcmp(argv[1], "age") == 0)
    test_age(source);
  else if (strcmp(argv[1], "series") == 0)
    test_series();
  else if (strcmp(argv[1], "timestamps") == 0)
    test_timestamps(source, false);
  else if (strcmp(argv[1], "pod_timestamps") == 0)
    test_timestamps(source, true);
  else if (strcmp(argv[1], "collection") == 0)
    test_collection();
  else
    assert(0);
  kubelet_source_free(source);
  return 0;
}
