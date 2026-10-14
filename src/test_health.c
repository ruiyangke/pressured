#define _GNU_SOURCE
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char directory[] = "/tmp/pressured-health-XXXXXX";
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

static void test_heartbeat(void) {
  char config[512], temporary[520], json[1024];
  snprintf(config, sizeof(config), "%s/config.json", directory);
  snprintf(temporary, sizeof(temporary), "%s.tmp", heartbeat);
  snprintf(json, sizeof(json),
           "{\"source\":{\"mode\":\"cgroup\",\"poll_interval_ms\":20,"
           "\"cgroup\":{\"path\":\"%s\"}}}",
           directory);
  write_file(config, json);
  write_time(time(NULL));
  // Block writes to observe startup removal independently of first collection.
  assert(mkdir(temporary, 0700) == 0);
  pid_t child = fork();
  assert(child >= 0);
  if (child == 0) {
    execl(program, program, "-c", config, "-l", "error", (char *)NULL);
    _exit(127);
  }
  int removed = 0;
  for (int i = 0; i < 200; i++) {
    if (access(heartbeat, F_OK) != 0) {
      removed = 1;
      break;
    }
    usleep(10000);
  }
  assert(rmdir(temporary) == 0);
  int written = 0;
  for (int i = 0; i < 200; i++) {
    if (access(heartbeat, F_OK) == 0) {
      written = 1;
      break;
    }
    usleep(10000);
  }
  assert(kill(child, SIGTERM) == 0);
  int status;
  assert(waitpid(child, &status, 0) == child);
  assert(removed);
  assert(written);
  assert(access(temporary, F_OK) != 0);
  probe(NULL, 0);
  assert(unlink(config) == 0);
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
  else
    test_heartbeat();
  assert(unlink(heartbeat) == 0);
  assert(rmdir(directory) == 0);
  return 0;
}
