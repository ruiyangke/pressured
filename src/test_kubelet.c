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
  response_code = 200;
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

int main(int argc, char **argv) {
  assert(argc == 2);
  unsetenv("KUBERNETES_SERVICE_HOST");
  kubelet_source_t *source = kubelet_source_new();
  assert(source);
  if (strcmp(argv[1], "dedupe") == 0)
    test_dedupe(source);
  else if (strcmp(argv[1], "cache") == 0)
    test_cache(source);
  else if (strcmp(argv[1], "age") == 0)
    test_age(source);
  else if (strcmp(argv[1], "collection") == 0)
    test_collection();
  else
    assert(0);
  kubelet_source_free(source);
  return 0;
}
