#define _GNU_SOURCE
#include "internal.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char directory[] = "./pressured-health-XXXXXX";
static char heartbeat[512];
static const char *program;

static void write_file(const char *path, const char *text) {
  FILE *file = fopen(path, "w");
  assert(file);
  int result = fputs(text, file);
  assert(result >= 0);
  result = fclose(file);
  assert(result == 0);
}

static void write_time(time_t timestamp) {
  char text[64];
  snprintf(text, sizeof(text), "%lld\n", (long long)timestamp);
  write_file(heartbeat, text);
}

static void probe(const char *age, int expected) {
  int output[2];
  assert(pipe(output) == 0);
  pid_t child = fork();
  assert(child >= 0);
  if (child == 0) {
    close(output[0]);
    assert(dup2(output[1], STDERR_FILENO) >= 0);
    close(output[1]);
    execl(program, program, "--health-check", age, (char *)NULL);
    _exit(127);
  }
  close(output[1]);
  char message[4096];
  ssize_t size = read(output[0], message, sizeof(message) - 1);
  assert(size >= 0);
  message[size] = '\0';
  close(output[0]);
  int status;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == expected);
  if (expected == 0)
    assert(size == 0);
  else {
    assert(size > 0 && message[size - 1] == '\n');
    assert(strchr(message, '\n') == message + size - 1);
  }
}

static void test_probe(void) {
  probe(NULL, 1);
  write_file(heartbeat, "garbage\n");
  probe(NULL, 1);
  write_time(time(NULL) - 600);
  probe(NULL, 1);
  write_time(time(NULL) + 60);
  probe(NULL, 1);
  write_time(time(NULL));
  probe(NULL, 0);
  write_time(time(NULL) + 3);
  probe(NULL, 0);
  write_time(time(NULL) - 60);
  probe("120", 0);
  probe("10", 1);
  probe("-1", 1);
  probe("garbage", 1);
  probe("9999999999999999999999999999", 1);
  write_file(heartbeat, "123abc\n");
  probe(NULL, 1);
  write_file(heartbeat, "9999999999999999999999999999\n");
  probe(NULL, 1);
  write_file(heartbeat, "1\n2\n");
  probe(NULL, 1);
}

static void run_collector(const char *root, int expected) {
  char config[512], json[1024];
  snprintf(config, sizeof(config), "%s/config.json", directory);
  snprintf(json, sizeof(json),
           "{\"source\":{\"mode\":\"cgroup\",\"poll_interval_ms\":20,"
           "\"cgroup\":{\"path\":\"%s\"}}}",
           root);
  write_file(config, json);
  write_time(1);
  pid_t child = fork();
  assert(child >= 0);
  if (child == 0) {
    execl(program, program, "-c", config, "-l", "error", (char *)NULL);
    _exit(127);
  }
  // Allow a slow first start (cold cache, loaded CI runner); the loop ends
  // as soon as the expected state is reached
  int ready = 0;
  for (int i = 0; i < 1000; i++) {
    if (expected ? health_check(heartbeat, time(NULL), 60) == NULL
                 : access(heartbeat, F_OK) != 0) {
      ready = 1;
      break;
    }
    usleep(10000);
  }
  usleep(100000);
  assert(kill(child, SIGTERM) == 0);
  int status;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  assert(ready);
  assert((access(heartbeat, F_OK) == 0) == expected);
  if (expected)
    probe(NULL, 0);
  assert(unlink(config) == 0);
}

static void test_heartbeat(void) {
  char pod[512], container[512], usage[512], limit[512];
  snprintf(pod, sizeof(pod), "%s/kubepods", directory);
  assert(mkdir(pod, 0700) == 0);
  snprintf(pod, sizeof(pod), "%s/kubepods/podtest", directory);
  assert(mkdir(pod, 0700) == 0);
  snprintf(container, sizeof(container),
           "%s/kubepods/podtest/cri-containerd-app.scope", directory);
  assert(mkdir(container, 0700) == 0);
  snprintf(usage, sizeof(usage),
           "%s/kubepods/podtest/cri-containerd-app.scope/memory.current",
           directory);
  snprintf(limit, sizeof(limit),
           "%s/kubepods/podtest/cri-containerd-app.scope/memory.max",
           directory);
  for (int discovered = 0; discovered < 2; discovered++) {
    if (discovered)
      assert(setenv("POD_UID", "test", 1) == 0);
    else
      unsetenv("POD_UID");
    run_collector(directory, 0);
    write_file(usage, "garbage\n");
    write_file(limit, "10000000\n");
    run_collector(directory, 0);
    write_file(usage, "5000000\n");
    run_collector(directory, 1);
    write_file(usage, "0\n");
    write_file(limit, "max\n");
    run_collector(directory, 1);
    assert(unlink(usage) == 0);
    assert(unlink(limit) == 0);
    run_collector(directory, 0);
  }
  unsetenv("POD_UID");
  assert(rmdir(container) == 0);
  assert(rmdir(pod) == 0);
  snprintf(pod, sizeof(pod), "%s/kubepods", directory);
  assert(rmdir(pod) == 0);
}

static void test_missing(void) {
  char missing[512];
  snprintf(missing, sizeof(missing), "%s/missing", directory);
  run_collector(missing, 0);
}

static void test_write(void) {
  char temporary[520], victim[512], text[64];
  snprintf(temporary, sizeof(temporary), "%s.tmp", heartbeat);
  snprintf(victim, sizeof(victim), "%s/victim", directory);
  write_file(victim, "untouched\n");
  assert(symlink("victim", temporary) == 0);
  assert(health_write(heartbeat, 123) == 0);
  FILE *file = fopen(victim, "r");
  assert(file);
  char *line = fgets(text, sizeof(text), file);
  assert(line);
  int result = fclose(file);
  assert(result == 0);
  assert(strcmp(text, "untouched\n") == 0);
  struct stat st;
  assert(lstat(temporary, &st) == 0 && S_ISLNK(st.st_mode));
  assert(health_check(heartbeat, 123, 0) == NULL);
  assert(health_write(heartbeat, 456) == 0);
  assert(health_check(heartbeat, 456, 0) == NULL);
  assert(unlink(temporary) == 0);
  assert(unlink(victim) == 0);
  assert(unlink(heartbeat) == 0);
  assert(mkdir(heartbeat, 0700) == 0);
  assert(health_write(heartbeat, 789) == -1);
  assert(rmdir(heartbeat) == 0);
  DIR *dir = opendir(directory);
  assert(dir);
  const struct dirent *entry;
  while ((entry = readdir(dir)))
    assert(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0);
  assert(closedir(dir) == 0);
}

int main(int argc, char **argv) {
  assert(argc == 3);
  program = argv[1];
  assert(mkdtemp(directory));
  snprintf(heartbeat, sizeof(heartbeat), "%s/healthy", directory);
  assert(setenv("PRESSURED_HEALTH_FILE", heartbeat, 1) == 0);
  // A probe must exit without trying to load this plugin directory.
  assert(setenv("PRESSURED_PLUGIN_DIR", "/nonexistent/health-test", 1) == 0);
  if (strcmp(argv[2], "probe") == 0)
    test_probe();
  else if (strcmp(argv[2], "heartbeat") == 0)
    test_heartbeat();
  else if (strcmp(argv[2], "missing") == 0)
    test_missing();
  else if (strcmp(argv[2], "write") == 0)
    test_write();
  else
    assert(0);
  assert(unlink(heartbeat) == 0 || errno == ENOENT);
  assert(rmdir(directory) == 0);
  return 0;
}
