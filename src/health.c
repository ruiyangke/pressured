#include "internal.h"
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char *health_file_path(void) {
  const char *path = getenv("PRESSURED_HEALTH_FILE");
  return path ? path : "/tmp/pressured.healthy";
}

int health_remove(const char *path) {
  return unlink(path) == 0 || errno == ENOENT ? 0 : -1;
}

int health_write(const char *path, time_t now) {
  if (now < 0)
    return -1;
  char *temporary = malloc(strlen(path) + sizeof(".XXXXXX"));
  if (!temporary)
    return -1;
  sprintf(temporary, "%s.XXXXXX", path);
  int fd = mkstemp(temporary);
  if (fd < 0) {
    free(temporary);
    return -1;
  }
  FILE *file = fdopen(fd, "w");
  if (!file) {
    close(fd);
    unlink(temporary);
    free(temporary);
    return -1;
  }
  int result = fprintf(file, "%jd\n", (intmax_t)now) < 0 ? -1 : 0;
  if (fclose(file) != 0)
    result = -1;
  if (result == 0 && rename(temporary, path) != 0)
    result = -1;
  if (result != 0)
    unlink(temporary);
  free(temporary);
  return result;
}

static int parse_seconds(const char *text, uintmax_t *value) {
  if (!text || !isdigit((unsigned char)*text))
    return -1;
  errno = 0;
  char *end;
  *value = strtoumax(text, &end, 10);
  return errno == ERANGE || *end != '\0' ? -1 : 0;
}

const char *health_check(const char *path, time_t now, uintmax_t max_age) {
  FILE *file = fopen(path, "r");
  if (!file)
    return "heartbeat file is missing or unreadable";
  char text[64];
  size_t length = fread(text, 1, sizeof(text) - 1, file);
  int extra = fgetc(file);
  int failed = ferror(file);
  fclose(file);
  if (failed || extra != EOF || memchr(text, '\0', length))
    return "invalid heartbeat timestamp";
  while (length && isspace((unsigned char)text[length - 1]))
    length--;
  text[length] = '\0';
  uintmax_t timestamp;
  if (parse_seconds(text, &timestamp) != 0)
    return "invalid heartbeat timestamp";
  if (now < 0)
    return "cannot read current time";
  uintmax_t current = (uintmax_t)now;
  if (timestamp > current) {
    if (timestamp - current > 5)
      return "heartbeat timestamp is more than 5 seconds in the future";
  } else if (current - timestamp > max_age) {
    return "heartbeat is stale";
  }
  return NULL;
}

int health_check_cli(int argc, char **argv) {
  uintmax_t max_age = 300;
  if (argc > 1 || (argc == 1 && parse_seconds(argv[0], &max_age) != 0)) {
    fprintf(stderr, "max_age_seconds must be a nonnegative decimal integer\n");
    return 1;
  }
  const char *reason = health_check(health_file_path(), time(NULL), max_age);
  if (reason) {
    fprintf(stderr, "%s\n", reason);
    return 1;
  }
  return 0;
}
