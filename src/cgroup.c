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

#include "internal.h"
#include "log.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_PATH 4096
#define MAX_CONTAINERS 1024

// ─────────────────────────────────────────────────────────────────────────────
// Cgroup Version
// ─────────────────────────────────────────────────────────────────────────────

typedef enum {
  CGROUP_V1 = 1,
  CGROUP_V2 = 2,
  CGROUP_UNKNOWN = 0
} cgroup_version_t;

struct cgroup_source {
  char *base_path;       // Root cgroup path (e.g., /sys/fs/cgroup)
  char *discovered_path; // Auto-discovered pod/container path
  cgroup_version_t version;
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
  char check_path[MAX_PATH];

  // Check for v2 indicators
  snprintf(check_path, sizeof(check_path), "%s/cgroup.controllers", path);
  if (access(check_path, F_OK) == 0) {
    log_debug("cgroup: detected v2 (cgroup.controllers exists)");
    return CGROUP_V2;
  }

  snprintf(check_path, sizeof(check_path), "%s/memory.current", path);
  if (access(check_path, F_OK) == 0) {
    log_debug("cgroup: detected v2 (memory.current exists)");
    return CGROUP_V2;
  }

  // Check for v1 indicators
  snprintf(check_path, sizeof(check_path), "%s/memory.usage_in_bytes", path);
  if (access(check_path, F_OK) == 0) {
    log_debug("cgroup: detected v1 (memory.usage_in_bytes exists)");
    return CGROUP_V1;
  }

  snprintf(check_path, sizeof(check_path), "%s/memory/memory.usage_in_bytes",
           path);
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
static char *extract_container_id(const char *path) {
  if (!path)
    return NULL;

  // Get the last component of the path
  const char *name = strrchr(path, '/');
  name = name ? name + 1 : path;

  // Pattern: cri-containerd-<id>.scope
  const char *prefix = "cri-containerd-";
  if (strncmp(name, prefix, strlen(prefix)) == 0) {
    const char *id_start = name + strlen(prefix);
    const char *id_end = strstr(id_start, ".scope");
    if (id_end) {
      size_t len = id_end - id_start;
      char *id = malloc(len + 1);
      if (id) {
        strncpy(id, id_start, len);
        id[len] = '\0';
        return id;
      }
    }
  }

  // Pattern: crio-<id>.scope
  prefix = "crio-";
  if (strncmp(name, prefix, strlen(prefix)) == 0) {
    const char *id_start = name + strlen(prefix);
    const char *id_end = strstr(id_start, ".scope");
    if (id_end) {
      size_t len = id_end - id_start;
      char *id = malloc(len + 1);
      if (id) {
        strncpy(id, id_start, len);
        id[len] = '\0';
        return id;
      }
    }
  }

  // Pattern: docker-<id>.scope
  prefix = "docker-";
  if (strncmp(name, prefix, strlen(prefix)) == 0) {
    const char *id_start = name + strlen(prefix);
    const char *id_end = strstr(id_start, ".scope");
    if (id_end) {
      size_t len = id_end - id_start;
      char *id = malloc(len + 1);
      if (id) {
        strncpy(id, id_start, len);
        id[len] = '\0';
        return id;
      }
    }
  }

  // Pattern: plain 64-char hex (container ID)
  if (strlen(name) == 64) {
    int is_hex = 1;
    for (int i = 0; i < 64 && is_hex; i++) {
      if (!isxdigit((unsigned char)name[i])) {
        is_hex = 0;
      }
    }
    if (is_hex) {
      return strdup(name);
    }
  }

  return NULL;
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
static char *discover_pod_cgroup_by_uid(const char *base_path,
                                        const char *pod_uid) {
  if (!base_path || !pod_uid)
    return NULL;

  char uid_escaped[128];
  char uid_plain[128];

  // Create both formats: dashes -> underscores (systemd) and dashes removed
  // (cgroupfs)
  strncpy(uid_escaped, pod_uid, sizeof(uid_escaped) - 1);
  uid_escaped[sizeof(uid_escaped) - 1] = '\0';
  for (char *p = uid_escaped; *p; p++) {
    if (*p == '-')
      *p = '_';
  }

  strncpy(uid_plain, pod_uid, sizeof(uid_plain) - 1);
  uid_plain[sizeof(uid_plain) - 1] = '\0';
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
    char path[MAX_PATH];

    if (qos) {
      // QoS-specific paths
      // systemd format: kubepods-<qos>.slice/kubepods-<qos>-pod<uid>.slice
      snprintf(path, sizeof(path),
               "%s/kubepods.slice/kubepods-%s.slice/kubepods-%s-pod%s.slice",
               base_path, qos, qos, uid_escaped);
      if (access(path, F_OK) == 0) {
        log_info("cgroup: discovered pod path (systemd %s): %s", qos, path);
        return strdup(path);
      }

      // cgroupfs format: kubepods/<qos>/pod<uid>
      snprintf(path, sizeof(path), "%s/kubepods/%s/pod%s", base_path, qos,
               uid_plain);
      if (access(path, F_OK) == 0) {
        log_info("cgroup: discovered pod path (cgroupfs %s): %s", qos, path);
        return strdup(path);
      }
    } else {
      // Guaranteed QoS (no intermediate directory)
      // systemd format: kubepods.slice/kubepods-pod<uid>.slice
      snprintf(path, sizeof(path), "%s/kubepods.slice/kubepods-pod%s.slice",
               base_path, uid_escaped);
      if (access(path, F_OK) == 0) {
        log_info("cgroup: discovered pod path (systemd guaranteed): %s", path);
        return strdup(path);
      }

      // cgroupfs format: kubepods/pod<uid>
      snprintf(path, sizeof(path), "%s/kubepods/pod%s", base_path, uid_plain);
      if (access(path, F_OK) == 0) {
        log_info("cgroup: discovered pod path (cgroupfs guaranteed): %s", path);
        return strdup(path);
      }
    }
  }

  log_warn("cgroup: could not discover pod cgroup for UID %s", pod_uid);
  return NULL;
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
static char *discover_self_cgroup(const char *base_path) {
  FILE *f = fopen("/proc/self/cgroup", "r");
  if (!f) {
    log_debug("cgroup: cannot open /proc/self/cgroup: %s", strerror(errno));
    return NULL;
  }

  char line[MAX_PATH];
  char *result = NULL;

  while (fgets(line, sizeof(line), f)) {
    // Remove trailing newline
    size_t len = strlen(line);
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
      char full_path[MAX_PATH];
      snprintf(full_path, sizeof(full_path), "%s%s", base_path, cgroup_path);
      if (access(full_path, F_OK) == 0) {
        result = strdup(full_path);
        log_info("cgroup: discovered self path (v2): %s", result);
        break;
      }
    }

    // v1 memory controller
    if (controllers && strstr(controllers, "memory")) {
      char full_path[MAX_PATH];
      snprintf(full_path, sizeof(full_path), "%s/memory%s", base_path,
               cgroup_path);
      if (access(full_path, F_OK) == 0) {
        result = strdup(full_path);
        log_info("cgroup: discovered self path (v1 memory): %s", result);
        break;
      }
    }
  }

  fclose(f);
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory Reading (v1 and v2)
// ─────────────────────────────────────────────────────────────────────────────

/*
 * Read memory usage (cgroup v2: memory.current, v1: memory.usage_in_bytes)
 */
uint64_t cgroup_read_memory_current(const char *path) {
  char filepath[MAX_PATH];
  FILE *f;
  uint64_t value = 0;

  // Try v2 first
  snprintf(filepath, sizeof(filepath), "%s/memory.current", path);
  f = fopen(filepath, "r");
  if (f) {
    if (fscanf(f, "%lu", &value) != 1)
      value = 0;
    fclose(f);
    return value;
  }

  // Try v1
  snprintf(filepath, sizeof(filepath), "%s/memory.usage_in_bytes", path);
  f = fopen(filepath, "r");
  if (f) {
    if (fscanf(f, "%lu", &value) != 1)
      value = 0;
    fclose(f);
    return value;
  }

  // Try v1 with memory subdirectory
  snprintf(filepath, sizeof(filepath), "%s/memory/memory.usage_in_bytes", path);
  f = fopen(filepath, "r");
  if (f) {
    if (fscanf(f, "%lu", &value) != 1)
      value = 0;
    fclose(f);
    return value;
  }

  log_trace("cgroup: cannot read memory usage at %s", path);
  return 0;
}

/*
 * Read memory limit (cgroup v2: memory.max, v1: memory.limit_in_bytes)
 */
uint64_t cgroup_read_memory_max(const char *path) {
  char filepath[MAX_PATH];
  FILE *f;
  char buf[64];

  // Try v2 first
  snprintf(filepath, sizeof(filepath), "%s/memory.max", path);
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
  snprintf(filepath, sizeof(filepath), "%s/memory.limit_in_bytes", path);
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
  snprintf(filepath, sizeof(filepath), "%s/memory/memory.limit_in_bytes", path);
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
  char filepath[MAX_PATH];
  char line[256];
  FILE *f;
  uint64_t oom_kill = 0;

  // Try cgroup v2 memory.events first
  snprintf(filepath, sizeof(filepath), "%s/memory.events", path);
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
  snprintf(filepath, sizeof(filepath), "%s/memory.oom_control", path);
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
  snprintf(filepath, sizeof(filepath), "%s/memory/memory.oom_control", path);
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

  char *pod_uid = malloc(uid_len + 1);
  if (!pod_uid)
    return -1;
  strncpy(pod_uid, uid_start, uid_len);
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
    *pod_name = env_name ? strdup(env_name) : pod_uid;
    if (env_name) {
      free(pod_uid);
    }
  } else {
    free(pod_uid);
  }

  // Extract container name - prefer environment variable for sidecar mode
  if (container_name) {
    const char *env_container = getenv("CONTAINER_NAME");
    if (env_container && env_container[0]) {
      *container_name = strdup(env_container);
    } else {
      *container_name = extract_container_id(cgroup_path);
      if (!*container_name) {
        *container_name = strdup("main");
      }
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

  // Default base path
  source->base_path = strdup(cgroup_path ? cgroup_path : "/sys/fs/cgroup");
  if (!source->base_path) {
    free(source);
    return NULL;
  }

  // Detect cgroup version
  source->version = detect_cgroup_version(source->base_path);

  // Auto-discover pod cgroup if explicit path is just the base
  const char *pod_uid = getenv("POD_UID");
  if (pod_uid && pod_uid[0]) {
    source->discovered_path =
        discover_pod_cgroup_by_uid(source->base_path, pod_uid);
    if (source->discovered_path) {
      // Re-detect version at discovered path
      source->version = detect_cgroup_version(source->discovered_path);
    }
  }

  // Fallback: try /proc/self/cgroup discovery
  if (!source->discovered_path) {
    source->discovered_path = discover_self_cgroup(source->base_path);
    if (source->discovered_path) {
      source->version = detect_cgroup_version(source->discovered_path);
    }
  }

  log_info("cgroup: source initialized base=%s discovered=%s version=%s",
           source->base_path,
           source->discovered_path ? source->discovered_path : "(none)",
           source->version == CGROUP_V2   ? "v2"
           : source->version == CGROUP_V1 ? "v1"
                                          : "unknown");

  return source;
}

void cgroup_source_free(cgroup_source_t *source) {
  if (source) {
    free(source->base_path);
    free(source->discovered_path);
    free(source);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Collection
// ─────────────────────────────────────────────────────────────────────────────

// Recursively find container cgroups
static int find_container_cgroups(const char *base_path,
                                  cgroup_version_t version,
                                  pressured_memory_sample_t *samples,
                                  int *count, int max_count) {
  DIR *dir = opendir(base_path);
  if (!dir) {
    return 0;
  }

  const struct dirent *entry;
  while ((entry = readdir(dir)) != NULL && *count < max_count) {
    if (entry->d_name[0] == '.')
      continue;

    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/%s", base_path, entry->d_name);

    struct stat st;
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
      continue;
    }

    // Check if this has memory stats
    uint64_t usage = cgroup_read_memory_current(path);
    if (usage > 0) {
      // Check if it's a Kubernetes pod
      if (strstr(path, "kubepods") != NULL || strstr(path, "pod") != NULL) {
        uint64_t limit = cgroup_read_memory_max(path);

        // Skip containers without limits
        if (limit == UINT64_MAX || limit == 0) {
          find_container_cgroups(path, version, samples, count, max_count);
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
    find_container_cgroups(path, version, samples, count, max_count);
  }

  closedir(dir);
  return 0;
}

pressured_memory_sample_t *cgroup_collect(cgroup_source_t *source, int *count) {
  *count = 0;

  pressured_memory_sample_t *samples =
      calloc(MAX_CONTAINERS, sizeof(pressured_memory_sample_t));
  if (!samples) {
    log_error("cgroup: failed to allocate samples array");
    return NULL;
  }

  // If we have a discovered path (single pod mode), collect from container
  // cgroups within it
  if (source->discovered_path) {
    // Parse pod-level info from the discovered path
    char *ns = NULL, *pod = NULL, *pod_container = NULL;
    cgroup_parse_container_info(source->discovered_path, &ns, &pod,
                                &pod_container);

    // Enumerate container cgroups within the pod cgroup
    DIR *dir = opendir(source->discovered_path);
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
          snprintf(container_path, sizeof(container_path), "%s/%s",
                   source->discovered_path, entry->d_name);

          uint64_t usage = cgroup_read_memory_current(container_path);
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
    if (*count == 0) {
      uint64_t usage = cgroup_read_memory_current(source->discovered_path);
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
    find_container_cgroups(source->base_path, source->version, samples, count,
                           MAX_CONTAINERS);
  }

  log_debug("cgroup: collected %d samples", *count);
  return samples;
}

void cgroup_samples_free(pressured_memory_sample_t *samples, int count) {
  if (samples) {
    for (int i = 0; i < count; i++) {
      pressured_memory_sample_free(&samples[i]);
    }
    free(samples);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Exported functions for testing and external use
// ─────────────────────────────────────────────────────────────────────────────

const char *cgroup_source_get_discovered_path(cgroup_source_t *source) {
  return source ? source->discovered_path : NULL;
}

int cgroup_source_get_version(const cgroup_source_t *source) {
  return source ? (int)source->version : 0;
}
