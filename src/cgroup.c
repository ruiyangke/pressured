/*
 * Cgroup Source - Memory monitoring via cgroup filesystem
 *
 * Supports:
 * - Cgroup v1 and v2 auto-detection
 * - Auto-discovery via POD_UID environment variable (Kubernetes)
 * - Auto-discovery via /proc/self/cgroup (container mode)
 * - Manual path specification
 *
 * Priority for path discovery:
 * 1. Explicit path in config
 * 2. POD_UID environment variable (for Kubernetes sidecar)
 * 3. /proc/self/cgroup parsing (for containerized deployments)
 */

#include "fixed_buffer.h"
#include "internal.h"
#include "log.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_CONTAINERS 1024

// ─────────────────────────────────────────────────────────────────────────────
// Cgroup Version
// ─────────────────────────────────────────────────────────────────────────────

typedef enum {
  CGROUP_ERROR = -1,
  CGROUP_V1 = 1,
  CGROUP_V2 = 2,
  CGROUP_UNKNOWN = 0
} cgroup_version_t;

struct cgroup_source {
  char base_path[PATH_MAX];       // Root cgroup path (e.g., /sys/fs/cgroup)
  char discovered_path[PATH_MAX]; // Auto-discovered pod/container path
  cgroup_version_t version;
  bool collection_healthy;
  pressured_memory_sample_t *samples; // Reused per-cycle buffer (owned here)
  int sample_count;                   // Entries written by the previous collect
};

// ─────────────────────────────────────────────────────────────────────────────
// Cgroup Version Detection
// ─────────────────────────────────────────────────────────────────────────────

/*
 * Detect cgroup version at the given path.
 *
 * cgroup v2 indicators:
 * - cgroup.controllers file exists
 * - memory.current file exists (v2 unified hierarchy)
 *
 * cgroup v1 indicators:
 * - memory.usage_in_bytes file exists
 * - memory/ subdirectory with memory.usage_in_bytes
 */
static cgroup_version_t detect_cgroup_version(const char *path) {
  char check_path[PATH_MAX];

  // Check for v2 indicators
  if (buffer_format(check_path, sizeof(check_path), "cgroup path",
                    "%s/cgroup.controllers", path) != 0) {
    return CGROUP_ERROR;
  }
  if (access(check_path, F_OK) == 0) {
    log_debug("cgroup: detected v2 (cgroup.controllers exists)");
    return CGROUP_V2;
  }

  if (buffer_format(check_path, sizeof(check_path), "cgroup path",
                    "%s/memory.current", path) != 0) {
    return CGROUP_ERROR;
  }
  if (access(check_path, F_OK) == 0) {
    log_debug("cgroup: detected v2 (memory.current exists)");
    return CGROUP_V2;
  }

  // Check for v1 indicators
  if (buffer_format(check_path, sizeof(check_path), "cgroup path",
                    "%s/memory.usage_in_bytes", path) != 0) {
    return CGROUP_ERROR;
  }
  if (access(check_path, F_OK) == 0) {
    log_debug("cgroup: detected v1 (memory.usage_in_bytes exists)");
    return CGROUP_V1;
  }

  if (buffer_format(check_path, sizeof(check_path), "cgroup path",
                    "%s/memory/memory.usage_in_bytes", path) != 0) {
    return CGROUP_ERROR;
  }
  if (access(check_path, F_OK) == 0) {
    log_debug("cgroup: detected v1 (memory/ subdirectory exists)");
    return CGROUP_V1;
  }

  log_debug("cgroup: version unknown at %s", path);
  return CGROUP_UNKNOWN;
}

// ─────────────────────────────────────────────────────────────────────────────
// Container ID Extraction
// ─────────────────────────────────────────────────────────────────────────────

/*
 * Extract container ID from cgroup path.
 *
 * Patterns:
 * - cri-containerd-<id>.scope
 * - crio-<id>.scope
 * - docker-<id>.scope
 * - 64-char hex string
 */
// Returns 0 for an ID, 1 for no match, and -1 for overflow.
static int extract_container_id(const char *path, char *id, size_t size) {
  id[0] = '\0';
  if (!path)
    return 1;
  const char *name = strrchr(path, '/');
  name = name ? name + 1 : path;
  const char *prefixes[] = {"cri-containerd-", "crio-", "docker-"};
  for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
    size_t prefix_len = strlen(prefixes[i]);
    if (strncmp(name, prefixes[i], prefix_len) != 0)
      continue;
    const char *start = name + prefix_len;
    const char *end = strstr(start, ".scope");
    if (!end)
      continue;
    size_t length = (size_t)(end - start);
    if (length >= size) {
      log_error("cgroup container ID too long (buffer size %zu)", size);
      return -1;
    }
    memcpy(id, start, length);
    id[length] = '\0';
    return 0;
  }
  if (strnlen(name, 65) == 64) {
    for (int i = 0; i < 64; i++)
      if (!isxdigit((unsigned char)name[i]))
        return 1;
    return buffer_copy(id, size, name, "cgroup container ID");
  }
  return 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// Pod Cgroup Discovery via POD_UID
// ─────────────────────────────────────────────────────────────────────────────

/*
 * Discover pod cgroup path using POD_UID environment variable.
 *
 * Kubernetes uses different path formats based on QoS class:
 * - Burstable:
 * kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice
 * - BestEffort:
 * kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod<uid>.slice
 * - Guaranteed: kubepods.slice/kubepods-pod<uid>.slice
 *
 * The UID in the path has dashes replaced with underscores for systemd
 * compatibility.
 */
static int discover_pod_cgroup_by_uid(const char *base_path,
                                      const char *pod_uid, char *result,
                                      size_t size) {
  if (!base_path || !pod_uid)
    return 0;

  char uid_escaped[128];
  char uid_plain[128];

  // Create both formats: dashes -> underscores (systemd) and dashes removed
  // (cgroupfs)
  if (buffer_copy(uid_escaped, sizeof(uid_escaped), pod_uid, "pod UID") != 0)
    return -1;
  for (char *p = uid_escaped; *p; p++) {
    if (*p == '-')
      *p = '_';
  }

  if (buffer_copy(uid_plain, sizeof(uid_plain), pod_uid, "pod UID") != 0)
    return -1;
  char *dst = uid_plain;
  for (const char *src = uid_plain; *src; src++) {
    if (*src != '-')
      *dst++ = *src;
  }
  *dst = '\0';

  // QoS classes to try
  const char *qos_classes[] = {"burstable", "besteffort", NULL, NULL};

  for (int i = 0; i < 4; i++) {
    const char *qos = qos_classes[i];
    char path[PATH_MAX];

    if (qos) {
      // QoS-specific paths
      // systemd format: kubepods-<qos>.slice/kubepods-<qos>-pod<uid>.slice
      if (buffer_format(
              path, sizeof(path), "cgroup path",
              "%s/kubepods.slice/kubepods-%s.slice/kubepods-%s-pod%s.slice",
              base_path, qos, qos, uid_escaped) != 0)
        return -1;
      if (access(path, F_OK) == 0) {
        log_info("cgroup: discovered pod path (systemd %s): %s", qos, path);
        return buffer_copy(result, size, path, "discovered cgroup path") == 0
                   ? 1
                   : -1;
      }

      // cgroupfs format: kubepods/<qos>/pod<uid>
      if (buffer_format(path, sizeof(path), "cgroup path",
                        "%s/kubepods/%s/pod%s", base_path, qos,
                        uid_plain) != 0) {
        return -1;
      }
      if (access(path, F_OK) == 0) {
        log_info("cgroup: discovered pod path (cgroupfs %s): %s", qos, path);
        return buffer_copy(result, size, path, "discovered cgroup path") == 0
                   ? 1
                   : -1;
      }
    } else {
      // Guaranteed QoS (no intermediate directory)
      // systemd format: kubepods.slice/kubepods-pod<uid>.slice
      if (buffer_format(path, sizeof(path), "cgroup path",
                        "%s/kubepods.slice/kubepods-pod%s.slice", base_path,
                        uid_escaped) != 0) {
        return -1;
      }
      if (access(path, F_OK) == 0) {
        log_info("cgroup: discovered pod path (systemd guaranteed): %s", path);
        return buffer_copy(result, size, path, "discovered cgroup path") == 0
                   ? 1
                   : -1;
      }

      // cgroupfs format: kubepods/pod<uid>
      if (buffer_format(path, sizeof(path), "cgroup path", "%s/kubepods/pod%s",
                        base_path, uid_plain) != 0) {
        return -1;
      }
      if (access(path, F_OK) == 0) {
        log_info("cgroup: discovered pod path (cgroupfs guaranteed): %s", path);
        return buffer_copy(result, size, path, "discovered cgroup path") == 0
                   ? 1
                   : -1;
      }
    }
  }

  log_warn("cgroup: could not discover pod cgroup for UID %s", pod_uid);
  return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Self Cgroup Discovery via /proc/self/cgroup
// ─────────────────────────────────────────────────────────────────────────────

/*
 * Discover cgroup path from /proc/self/cgroup.
 *
 * Format (v1): <hierarchy-id>:<controller>:<cgroup-path>
 * Format (v2): 0::<cgroup-path>
 *
 * Returns the cgroup path for the memory controller (v1) or unified hierarchy
 * (v2).
 */
static int discover_self_cgroup(const char *base_path, char *result,
                                size_t size) {
  FILE *f = fopen("/proc/self/cgroup", "r");
  if (!f) {
    log_debug("cgroup: cannot open /proc/self/cgroup: %s", strerror(errno));
    return 0;
  }

  char line[PATH_MAX];
  int found = 0;

  while (fgets(line, sizeof(line), f)) {
    // Remove trailing newline
    size_t len = strnlen(line, sizeof(line));
    if (len == sizeof(line) - 1 && line[len - 1] != '\n') {
      log_error("self cgroup line too long");
      found = -1;
      break;
    }
    if (len > 0 && line[len - 1] == '\n') {
      line[len - 1] = '\0';
    }

    // Parse: hierarchy-id:controllers:path
    const char *hierarchy = strtok(line, ":");
    char *controllers = strtok(NULL, ":");
    const char *cgroup_path = strtok(NULL, ":");

    if (!hierarchy || !cgroup_path)
      continue;

    // v2 unified hierarchy (hierarchy-id = 0, empty controllers)
    if (strcmp(hierarchy, "0") == 0) {
      char full_path[PATH_MAX];
      if (buffer_format(full_path, sizeof(full_path), "cgroup path", "%s%s",
                        base_path, cgroup_path) != 0) {
        fclose(f);
        return -1;
      }
      if (access(full_path, F_OK) == 0) {
        found =
            buffer_copy(result, size, full_path, "discovered cgroup path") == 0
                ? 1
                : -1;
        log_info("cgroup: discovered self path (v2): %s", result);
        break;
      }
    }

    // v1 memory controller
    if (controllers && strstr(controllers, "memory")) {
      char full_path[PATH_MAX];
      if (buffer_format(full_path, sizeof(full_path), "cgroup path",
                        "%s/memory%s", base_path, cgroup_path) != 0) {
        fclose(f);
        return -1;
      }
      if (access(full_path, F_OK) == 0) {
        found =
            buffer_copy(result, size, full_path, "discovered cgroup path") == 0
                ? 1
                : -1;
        log_info("cgroup: discovered self path (v1 memory): %s", result);
        break;
      }
    }
  }

  fclose(f);
  return found;
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory Reading (v1 and v2)
// ─────────────────────────────────────────────────────────────────────────────

/*
 * Read memory usage (cgroup v2: memory.current, v1: memory.usage_in_bytes)
 */
static bool read_memory_current(const char *path, uint64_t *value) {
  const char *files[] = {"memory.current", "memory.usage_in_bytes",
                         "memory/memory.usage_in_bytes"};
  *value = 0;
  for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
    char filepath[PATH_MAX];
    if (buffer_format(filepath, sizeof(filepath), "cgroup path", "%s/%s", path,
                      files[i]) != 0) {
      return false;
    }
    FILE *file = fopen(filepath, "r");
    if (!file)
      continue;
    bool success = fscanf(file, "%lu", value) == 1 && !ferror(file);
    fclose(file);
    if (!success)
      *value = 0;
    return success;
  }
  log_trace("cgroup: cannot read memory usage at %s", path);
  return false;
}

uint64_t cgroup_read_memory_current(const char *path) {
  uint64_t value;
  read_memory_current(path, &value);
  return value;
}

/*
 * Read memory limit (cgroup v2: memory.max, v1: memory.limit_in_bytes)
 */
uint64_t cgroup_read_memory_max(const char *path) {
  char filepath[PATH_MAX];
  FILE *f;
  char buf[64];

  // Try v2 first
  if (buffer_format(filepath, sizeof(filepath), "cgroup path", "%s/memory.max",
                    path) != 0) {
    return UINT64_MAX;
  }
  f = fopen(filepath, "r");
  if (f) {
    if (fgets(buf, sizeof(buf), f)) {
      fclose(f);
      // v2: "max" means no limit
      if (strncmp(buf, "max", 3) == 0) {
        return UINT64_MAX;
      }
      return strtoull(buf, NULL, 10);
    }
    fclose(f);
  }

  // Try v1
  if (buffer_format(filepath, sizeof(filepath), "cgroup path",
                    "%s/memory.limit_in_bytes", path) != 0) {
    return UINT64_MAX;
  }
  f = fopen(filepath, "r");
  if (f) {
    if (fgets(buf, sizeof(buf), f)) {
      fclose(f);
      // v1: 9223372036854771712 is the default "unlimited" value
      uint64_t val = strtoull(buf, NULL, 10);
      if (val >= 9223372036854771712ULL) {
        return UINT64_MAX;
      }
      return val;
    }
    fclose(f);
  }

  // Try v1 with memory subdirectory
  if (buffer_format(filepath, sizeof(filepath), "cgroup path",
                    "%s/memory/memory.limit_in_bytes", path) != 0) {
    return UINT64_MAX;
  }
  f = fopen(filepath, "r");
  if (f) {
    if (fgets(buf, sizeof(buf), f)) {
      fclose(f);
      uint64_t val = strtoull(buf, NULL, 10);
      if (val >= 9223372036854771712ULL) {
        return UINT64_MAX;
      }
      return val;
    }
    fclose(f);
  }

  log_trace("cgroup: cannot read memory limit at %s", path);
  return UINT64_MAX;
}

/*
 * Read OOM kill count from memory.events (cgroup v2) or memory.oom_control (v1)
 *
 * cgroup v2 memory.events format:
 *   low <count>
 *   high <count>
 *   max <count>
 *   oom <count>
 *   oom_kill <count>    <- This is what we want
 *
 * cgroup v1 memory.oom_control format:
 *   oom_kill_disable <0|1>
 *   under_oom <0|1>
 *   oom_kill <count>    <- This is what we want
 */
static uint64_t cgroup_read_oom_kill_count(const char *path) {
  char filepath[PATH_MAX];
  char line[256];
  FILE *f;
  uint64_t oom_kill = 0;

  // Try cgroup v2 memory.events first
  if (buffer_format(filepath, sizeof(filepath), "cgroup path",
                    "%s/memory.events", path) != 0) {
    return 0;
  }
  f = fopen(filepath, "r");
  if (f) {
    while (fgets(line, sizeof(line), f)) {
      if (sscanf(line, "oom_kill %lu", &oom_kill) == 1) {
        fclose(f);
        return oom_kill;
      }
    }
    fclose(f);
    return 0; // File exists but no oom_kill line (count is 0)
  }

  // Try cgroup v1 memory.oom_control
  if (buffer_format(filepath, sizeof(filepath), "cgroup path",
                    "%s/memory.oom_control", path) != 0) {
    return 0;
  }
  f = fopen(filepath, "r");
  if (f) {
    while (fgets(line, sizeof(line), f)) {
      if (sscanf(line, "oom_kill %lu", &oom_kill) == 1) {
        fclose(f);
        return oom_kill;
      }
    }
    fclose(f);
    return 0;
  }

  // Try v1 with memory subdirectory
  if (buffer_format(filepath, sizeof(filepath), "cgroup path",
                    "%s/memory/memory.oom_control", path) != 0) {
    return 0;
  }
  f = fopen(filepath, "r");
  if (f) {
    while (fgets(line, sizeof(line), f)) {
      if (sscanf(line, "oom_kill %lu", &oom_kill) == 1) {
        fclose(f);
        return oom_kill;
      }
    }
    fclose(f);
    return 0;
  }

  log_trace("cgroup: cannot read oom_kill count at %s", path);
  return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Container Info Parsing
// ─────────────────────────────────────────────────────────────────────────────

/*
 * Parse Kubernetes cgroup path to extract pod info.
 *
 * Example paths:
 * - kubepods-burstable-pod<uid>.slice/cri-containerd-<id>.scope
 * - kubepods/burstable/pod<uid>/<container-id>
 */
int cgroup_parse_container_info(const char *cgroup_path, char **namespace,
                                char **pod_name, char **container_name) {
  // Initialize output pointers (only if not NULL)
  if (namespace)
    *namespace = NULL;
  if (pod_name)
    *pod_name = NULL;
  if (container_name)
    *container_name = NULL;

  if (!cgroup_path)
    return -1;

  // Look for pod UID pattern
  const char *pod_marker = strstr(cgroup_path, "pod");
  if (!pod_marker) {
    return -1;
  }

  // Extract pod UID
  const char *uid_start = pod_marker + 3;
  const char *uid_end = uid_start;

  // Find end of UID (. or / or end of string)
  while (*uid_end && *uid_end != '.' && *uid_end != '/') {
    uid_end++;
  }

  size_t uid_len = uid_end - uid_start;
  if (uid_len == 0)
    return -1;

  char pod_uid[128];
  if (uid_len >= sizeof(pod_uid)) {
    log_error("cgroup pod UID too long (buffer size %zu)", sizeof(pod_uid));
    return -1;
  }
  memcpy(pod_uid, uid_start, uid_len);
  pod_uid[uid_len] = '\0';

  // Convert underscores back to dashes for display
  for (char *p = pod_uid; *p; p++) {
    if (*p == '_')
      *p = '-';
  }

  // Use environment variables if available (Kubernetes Downward API)
  const char *env_ns = getenv("POD_NAMESPACE");
  const char *env_name = getenv("POD_NAME");

  if (namespace) {
    *namespace = strdup(env_ns ? env_ns : "unknown");
  }
  if (pod_name) {
    *pod_name = strdup(env_name ? env_name : pod_uid);
  }

  // Extract container name - prefer environment variable for sidecar mode
  if (container_name) {
    const char *env_container = getenv("CONTAINER_NAME");
    if (env_container && env_container[0]) {
      *container_name = strdup(env_container);
    } else {
      char id[NAME_MAX + 1];
      int result = extract_container_id(cgroup_path, id, sizeof(id));
      if (result < 0) {
        if (namespace) {
          free(*namespace);
          *namespace = NULL;
        }
        if (pod_name) {
          free(*pod_name);
          *pod_name = NULL;
        }
        return -1;
      }
      *container_name = strdup(result == 0 ? id : "main");
    }
  }

  return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Source Creation
// ─────────────────────────────────────────────────────────────────────────────

cgroup_source_t *cgroup_source_new(const char *cgroup_path) {
  cgroup_source_t *source = calloc(1, sizeof(cgroup_source_t));
  if (!source)
    return NULL;

  // Allocate the per-cycle samples buffer once; cgroup_collect() reuses it.
  source->samples = calloc(MAX_CONTAINERS, sizeof(pressured_memory_sample_t));
  if (!source->samples) {
    free(source);
    return NULL;
  }

  // Default base path
  if (buffer_copy(source->base_path, sizeof(source->base_path),
                  cgroup_path && cgroup_path[0] ? cgroup_path
                                                : "/sys/fs/cgroup",
                  "cgroup base path") != 0) {
    cgroup_source_free(source);
    return NULL;
  }

  // Detect cgroup version
  source->version = detect_cgroup_version(source->base_path);
  if (source->version == CGROUP_ERROR) {
    cgroup_source_free(source);
    return NULL;
  }

  // Auto-discover pod cgroup if explicit path is just the base
  const char *pod_uid = getenv("POD_UID");
  if (pod_uid && pod_uid[0]) {
    if (discover_pod_cgroup_by_uid(source->base_path, pod_uid,
                                   source->discovered_path,
                                   sizeof(source->discovered_path)) < 0) {
      cgroup_source_free(source);
      return NULL;
    }
    if (source->discovered_path[0]) {
      // Re-detect version at discovered path
      source->version = detect_cgroup_version(source->discovered_path);
      if (source->version == CGROUP_ERROR) {
        cgroup_source_free(source);
        return NULL;
      }
    }
  }

  // Fallback: try /proc/self/cgroup discovery
  if (!source->discovered_path[0]) {
    if (discover_self_cgroup(source->base_path, source->discovered_path,
                             sizeof(source->discovered_path)) < 0) {
      cgroup_source_free(source);
      return NULL;
    }
    if (source->discovered_path[0]) {
      source->version = detect_cgroup_version(source->discovered_path);
      if (source->version == CGROUP_ERROR) {
        cgroup_source_free(source);
        return NULL;
      }
    }
  }

  log_info("cgroup: source initialized base=%s discovered=%s version=%s",
           source->base_path,
           source->discovered_path[0] ? source->discovered_path : "(none)",
           source->version == CGROUP_V2   ? "v2"
           : source->version == CGROUP_V1 ? "v1"
                                          : "unknown");

  return source;
}

void cgroup_source_free(cgroup_source_t *source) {
  if (source) {
    free(source->samples);
    free(source);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Collection
// ─────────────────────────────────────────────────────────────────────────────

// Recursively find container cgroups; -2 indicates a path overflow.
static int find_container_cgroups(const char *base_path,
                                  cgroup_version_t version,
                                  pressured_memory_sample_t *samples,
                                  int *count, int max_count,
                                  bool *memory_read) {
  DIR *dir = opendir(base_path);
  if (!dir) {
    return -1;
  }

  const struct dirent *entry;
  while ((entry = readdir(dir)) != NULL && *count < max_count) {
    if (entry->d_name[0] == '.')
      continue;

    char path[PATH_MAX];
    if (buffer_format(path, sizeof(path), "cgroup path", "%s/%s", base_path,
                      entry->d_name) != 0) {
      closedir(dir);
      return -2;
    }

    struct stat st;
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
      continue;
    }

    // Check if this has memory stats
    uint64_t usage;
    bool read = read_memory_current(path, &usage);
    if (read && (strstr(path, "kubepods") || strstr(path, "pod")))
      *memory_read = true;
    if (usage > 0) {
      // Check if it's a Kubernetes pod
      if (strstr(path, "kubepods") != NULL || strstr(path, "pod") != NULL) {
        uint64_t limit = cgroup_read_memory_max(path);

        // Skip containers without limits
        if (limit == UINT64_MAX || limit == 0) {
          if (find_container_cgroups(path, version, samples, count, max_count,
                                     memory_read) == -2) {
            closedir(dir);
            return -2;
          }
          continue;
        }

        char *ns = NULL, *pod = NULL, *container = NULL;
        if (cgroup_parse_container_info(path, &ns, &pod, &container) == 0) {
          pressured_memory_sample_t *sample = &samples[*count];
          sample->namespace = ns;
          sample->pod_name = pod;
          sample->pod_uid = NULL; // Not available in cluster mode scan
          sample->container_name = container;
          sample->node_name = strdup("localhost");
          sample->usage_bytes = usage;
          sample->limit_bytes = limit;
          sample->usage_percent = (double)usage / (double)limit;
          sample->timestamp = time(NULL);

          log_debug(
              "cgroup: found container ns=%s pod=%s container=%s usage=%.1f%%",
              ns, pod, container, sample->usage_percent * 100.0);

          (*count)++;
        }
      }
    }

    // Recurse into subdirectories
    if (find_container_cgroups(path, version, samples, count, max_count,
                               memory_read) == -2) {
      closedir(dir);
      return -2;
    }
  }

  closedir(dir);
  return 0;
}

pressured_memory_sample_t *cgroup_collect(cgroup_source_t *source, int *count) {
  *count = 0;
  source->collection_healthy = false;

  // Reuse the buffer owned by the source and clear only the entries the
  // previous cycle wrote; the rest are still zero from the initial calloc. It
  // stays valid until the next cgroup_collect() or cgroup_source_free().
  pressured_memory_sample_t *samples = source->samples;
  memset(samples, 0,
         (size_t)source->sample_count * sizeof(pressured_memory_sample_t));

  // If we have a discovered path (single pod mode), collect from container
  // cgroups within it
  if (source->discovered_path[0]) {
    // Parse pod-level info from the discovered path
    char *ns = NULL, *pod = NULL, *pod_container = NULL;
    cgroup_parse_container_info(source->discovered_path, &ns, &pod,
                                &pod_container);

    // Enumerate container cgroups within the pod cgroup
    DIR *dir = opendir(source->discovered_path);
    bool root_readable = dir != NULL;
    if (dir) {
      struct dirent *entry;
      while ((entry = readdir(dir)) != NULL && *count < MAX_CONTAINERS) {
        // Skip . and ..
        if (entry->d_name[0] == '.')
          continue;

        // Look for container cgroup directories (cri-containerd-*.scope or
        // docker-*.scope)
        if (strstr(entry->d_name, "cri-containerd-") != NULL ||
            strstr(entry->d_name, "docker-") != NULL) {

          char container_path[PATH_MAX];
          if (buffer_format(container_path, sizeof(container_path),
                            "cgroup path", "%s/%s", source->discovered_path,
                            entry->d_name) != 0) {
            closedir(dir);
            free(ns);
            free(pod);
            free(pod_container);
            source->sample_count = *count;
            cgroup_samples_free(samples, *count);
            *count = 0;
            source->collection_healthy = false;
            return NULL;
          }

          uint64_t usage;
          if (read_memory_current(container_path, &usage))
            source->collection_healthy = true;
          uint64_t limit = cgroup_read_memory_max(container_path);

          // Skip containers with no limit (like sidecars with no resource
          // limits)
          if (usage == 0 || limit == 0 || limit == UINT64_MAX) {
            log_debug("cgroup: skipping container %s (no limit set)",
                      entry->d_name);
            continue;
          }

          // Extract container ID from the directory name
          char *container_id = NULL;
          char *container = NULL;
          cgroup_parse_container_info(container_path, NULL, NULL,
                                      &container_id);
          container = container_id ? container_id : strdup(entry->d_name);

          pressured_memory_sample_t *sample = &samples[*count];
          sample->namespace = ns ? strdup(ns) : strdup("default");
          sample->pod_name = pod ? strdup(pod) : strdup("unknown");
          // Get pod_uid from environment variable
          const char *env_pod_uid = getenv("POD_UID");
          sample->pod_uid =
              env_pod_uid && env_pod_uid[0] ? strdup(env_pod_uid) : NULL;
          sample->container_name = container;
          sample->node_name = strdup("localhost");
          sample->usage_bytes = usage;
          sample->limit_bytes = limit;
          sample->usage_percent = (double)usage / (double)limit;
          // Read oom_kill from pod-level cgroup (v2), not container-level
          // In K8s cgroup v2, oom_kill counter is tracked at pod level
          sample->oom_kill_count =
              cgroup_read_oom_kill_count(source->discovered_path);
          sample->timestamp = time(NULL);

          log_debug(
              "cgroup: container %s usage=%.1f%% (%lu/%lu bytes) oom_kills=%lu",
              container, sample->usage_percent * 100.0, usage, limit,
              sample->oom_kill_count);

          (*count)++;
        }
      }
      closedir(dir);
    }

    // Free the pod-level parsed info
    free(ns);
    free(pod);
    free(pod_container);

    // If no containers found, fall back to pod-level reading
    if (root_readable && *count == 0) {
      uint64_t usage;
      if (read_memory_current(source->discovered_path, &usage))
        source->collection_healthy = true;
      uint64_t limit = cgroup_read_memory_max(source->discovered_path);

      if (usage > 0 && limit != UINT64_MAX && limit > 0) {
        cgroup_parse_container_info(source->discovered_path, &ns, &pod,
                                    &pod_container);

        pressured_memory_sample_t *sample = &samples[0];
        sample->namespace = ns ? ns : strdup("default");
        sample->pod_name = pod ? pod : strdup("unknown");
        // Get pod_uid from environment variable
        const char *env_pod_uid = getenv("POD_UID");
        sample->pod_uid =
            env_pod_uid && env_pod_uid[0] ? strdup(env_pod_uid) : NULL;
        sample->container_name = pod_container ? pod_container : strdup("main");
        sample->node_name = strdup("localhost");
        sample->usage_bytes = usage;
        sample->limit_bytes = limit;
        sample->usage_percent = (double)usage / (double)limit;
        sample->oom_kill_count =
            cgroup_read_oom_kill_count(source->discovered_path);
        sample->timestamp = time(NULL);

        log_debug("cgroup: single-pod fallback mode usage=%.1f%% (%lu/%lu "
                  "bytes) oom_kills=%lu",
                  sample->usage_percent * 100.0, usage, limit,
                  sample->oom_kill_count);

        *count = 1;
      }
    }
  } else {
    // Cluster mode: scan all kubepods
    bool memory_read = false;
    int result =
        find_container_cgroups(source->base_path, source->version, samples,
                               count, MAX_CONTAINERS, &memory_read);
    if (result == -2) {
      source->sample_count = *count;
      cgroup_samples_free(samples, *count);
      *count = 0;
      return NULL;
    }
    source->collection_healthy = result == 0 && memory_read;
  }

  log_debug("cgroup: collected %d samples", *count);
  source->sample_count = *count;
  return samples;
}

bool cgroup_collect_healthy(const cgroup_source_t *source) {
  return source && source->collection_healthy;
}

// Free the contents of each sample. The samples array itself is owned by the
// cgroup source (see cgroup_source_free) and must not be freed here.
void cgroup_samples_free(pressured_memory_sample_t *samples, int count) {
  if (samples) {
    for (int i = 0; i < count; i++) {
      pressured_memory_sample_free(&samples[i]);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Exported functions for testing and external use
// ─────────────────────────────────────────────────────────────────────────────

const char *cgroup_source_get_discovered_path(cgroup_source_t *source) {
  return source && source->discovered_path[0] ? source->discovered_path : NULL;
}

int cgroup_source_get_version(const cgroup_source_t *source) {
  return source ? (int)source->version : 0;
}
