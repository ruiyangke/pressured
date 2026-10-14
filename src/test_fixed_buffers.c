#include "http.h"
#include "internal.h"
#include "plugin_manager.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void test_config_length(int length) {
  char filename[] = "./config-bounds-XXXXXX";
  int fd = mkstemp(filename);
  assert(fd >= 0);
  FILE *file = fdopen(fd, "w");
  assert(file);
  int result = fputs("{\"source\":{\"cgroup\":{\"path\":\"", file);
  assert(result >= 0);
  for (int i = 0; i < length; i++) {
    result = fputc('x', file);
    assert(result != EOF);
  }
  result = fputs("\"}}}", file);
  assert(result >= 0);
  result = fclose(file);
  assert(result == 0);
  pressured_config_t *config = pressured_config_load(filename);
  assert(unlink(filename) == 0);
  if (length >= PATH_MAX)
    assert(config == NULL);
  else {
    assert(config && strlen(config->cgroup_path) == (size_t)length);
    pressured_config_free(config);
  }
}

static void test_health(void) {
  char path[PATH_MAX + 1];
  memset(path, 'x', sizeof(path) - 1);
  path[sizeof(path) - 1] = '\0';
  assert(setenv("PRESSURED_HEALTH_FILE", path, 1) == 0);
  FILE *messages = tmpfile();
  assert(messages);
  int saved = dup(STDERR_FILENO);
  assert(saved >= 0);
  assert(dup2(fileno(messages), STDERR_FILENO) >= 0);
  int result = health_write(health_file_path(), 123);
  int flushed = fflush(stderr);
  assert(flushed == 0);
  assert(dup2(saved, STDERR_FILENO) >= 0);
  close(saved);
  assert(result == -1);
  rewind(messages);
  char message[1024];
  char *line = fgets(message, sizeof(message), messages);
  assert(line);
  assert(strstr(message, "too long"));
  result = fclose(messages);
  assert(result == 0);
  assert(access(path, F_OK) == -1);
}

static size_t discard(const void *data, size_t size, void *ctx) {
  (void)data;
  (void)ctx;
  return size;
}

int main(int argc, char **argv) {
  assert(argc == 2);
  char value[PATH_MAX + 1];
  memset(value, 'x', sizeof(value) - 1);
  value[sizeof(value) - 1] = '\0';
  if (strcmp(argv[1], "config") == 0)
    for (int length = PATH_MAX - 1; length <= PATH_MAX + 1; length++)
      test_config_length(length);
  else if (strcmp(argv[1], "health") == 0)
    test_health();
  else if (strcmp(argv[1], "cgroup") == 0)
    assert(cgroup_source_new(value) == NULL);
  else if (strcmp(argv[1], "pod_uid") == 0) {
    assert(setenv("POD_UID", value, 1) == 0);
    assert(cgroup_source_new("/sys/fs/cgroup") == NULL);
  } else if (strcmp(argv[1], "container_id") == 0) {
    char path[512];
    memset(path, 'x', sizeof(path));
    memcpy(path, "poduid/docker-", sizeof("poduid/docker-") - 1);
    memcpy(path + sizeof(path) - sizeof(".scope"), ".scope", sizeof(".scope"));
    char *ns, *pod, *container;
    assert(cgroup_parse_container_info(path, &ns, &pod, &container) == -1);
    assert(!ns && !pod && !container);
  } else if (strcmp(argv[1], "lua_script") == 0 ||
             strcmp(argv[1], "lua_scripts_dir") == 0) {
    /* value is a long path of ordinary path characters, so no JSON escaping
     * is needed */
    char json[PATH_MAX + 64];
    snprintf(json, sizeof(json), "{\"plugins\":{\"lua\":{\"%s\":\"%s\"}}}",
             argv[1] + 4, value);
    service_registry_t *registry = service_registry_new();
    assert(registry);
    plugin_manager_t *manager = plugin_manager_new(registry);
    assert(manager);
    assert(plugin_manager_load(manager, "plugins/lua.so", json) == 0);
    assert(plugin_manager_count(manager) == 0);
    plugin_manager_free(manager);
    service_registry_free(registry);
  } else if (strcmp(argv[1], "ca") == 0) {
    http_opts_t opts = {.ca_path = value};
    assert(http_client_new(&opts) == NULL);
    value[PATH_MAX - 1] = '\0';
    http_client_t *client = http_client_new(&opts);
    assert(client);
    http_client_free(client);
  } else {
    http_client_t *client = http_client_new(NULL);
    assert(client);
    http_request_t request = {.content_type = value};
    if (strcmp(argv[1], "content_type") == 0) {
      http_response_t *response =
          http_fetch(client, "GET", "file:///dev/null", &request);
      assert(response && response->error &&
             strstr(response->error, "too long"));
      http_response_free(response);
    } else {
      assert(strcmp(argv[1], "stream_content_type") == 0);
      assert(http_stream(client, "GET", "file:///dev/null", &request, discard,
                         NULL, NULL, NULL) == -1);
    }
    http_client_free(client);
  }
  return 0;
}
