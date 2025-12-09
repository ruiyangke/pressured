/*
 * Cgroup Source Unit Tests
 *
 * Tests for:
 * - Cgroup v1/v2 detection
 * - Auto-discovery via POD_UID
 * - Auto-discovery via /proc/self/cgroup
 * - Memory reading for both versions
 * - Container info parsing
 */

#include "internal.h"
#include "log.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int tests_passed = 0;
static int tests_total = 0;

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name)                                                         \
  do {                                                                         \
    tests_total++;                                                             \
    printf("  %-50s", #name);                                                  \
    test_##name();                                                             \
    printf(" OK\n");                                                           \
    tests_passed++;                                                            \
  } while (0)

// ─────────────────────────────────────────────────────────────────────────────
// Test Fixtures - Create temporary cgroup structures
// ─────────────────────────────────────────────────────────────────────────────

static char test_dir[256] = {0};

static void setup_test_dir(void) {
  snprintf(test_dir, sizeof(test_dir), "/tmp/test_cgroup_%d", getpid());
  mkdir(test_dir, 0755);
}

static void cleanup_test_dir(void) {
  if (test_dir[0]) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
    int rc = system(cmd);
    (void)rc;
    test_dir[0] = '\0';
  }
}

static void create_file(const char *path, const char *content) {
  FILE *f = fopen(path, "w");
  if (f) {
    fputs(content, f);
    fclose(f);
  }
}

static void create_dir(const char *path) { mkdir(path, 0755); }

// ─────────────────────────────────────────────────────────────────────────────
// Version Detection Tests
// ─────────────────────────────────────────────────────────────────────────────

TEST(version_detection_v2) {
  // Create a v2 cgroup structure
  char v2_path[512];
  snprintf(v2_path, sizeof(v2_path), "%s/v2", test_dir);
  create_dir(v2_path);

  char file_path[512];
  snprintf(file_path, sizeof(file_path), "%s/memory.current", v2_path);
  create_file(file_path, "1234567\n");

  snprintf(file_path, sizeof(file_path), "%s/memory.max", v2_path);
  create_file(file_path, "10485760\n");

  cgroup_source_t *source = cgroup_source_new(v2_path);
  assert(source != NULL);
  assert(cgroup_source_get_version(source) == CGROUP_VERSION_V2);
  cgroup_source_free(source);
}

TEST(version_detection_v2_with_controllers) {
  // v2 indicated by cgroup.controllers file
  char v2_path[512];
  snprintf(v2_path, sizeof(v2_path), "%s/v2_ctrl", test_dir);
  create_dir(v2_path);

  char file_path[512];
  snprintf(file_path, sizeof(file_path), "%s/cgroup.controllers", v2_path);
  create_file(file_path, "cpu memory io\n");

  cgroup_source_t *source = cgroup_source_new(v2_path);
  assert(source != NULL);
  assert(cgroup_source_get_version(source) == CGROUP_VERSION_V2);
  cgroup_source_free(source);
}

TEST(version_detection_v1) {
  // Create a v1 cgroup structure with memory subdirectory
  char v1_path[512];
  snprintf(v1_path, sizeof(v1_path), "%s/v1", test_dir);
  create_dir(v1_path);

  char memory_path[512];
  snprintf(memory_path, sizeof(memory_path), "%s/memory", v1_path);
  create_dir(memory_path);

  char file_path[512];
  snprintf(file_path, sizeof(file_path), "%s/memory.usage_in_bytes",
           memory_path);
  create_file(file_path, "5678901\n");

  cgroup_source_t *source = cgroup_source_new(v1_path);
  assert(source != NULL);
  assert(cgroup_source_get_version(source) == CGROUP_VERSION_V1);
  cgroup_source_free(source);
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory Reading Tests
// ─────────────────────────────────────────────────────────────────────────────

TEST(read_memory_v2) {
  char v2_path[512];
  snprintf(v2_path, sizeof(v2_path), "%s/mem_v2", test_dir);
  create_dir(v2_path);

  char file_path[512];
  snprintf(file_path, sizeof(file_path), "%s/memory.current", v2_path);
  create_file(file_path, "12345678\n");

  snprintf(file_path, sizeof(file_path), "%s/memory.max", v2_path);
  create_file(file_path, "104857600\n");

  uint64_t usage = cgroup_read_memory_current(v2_path);
  assert(usage == 12345678);

  uint64_t limit = cgroup_read_memory_max(v2_path);
  assert(limit == 104857600);
}

TEST(read_memory_v2_max_unlimited) {
  char v2_path[512];
  snprintf(v2_path, sizeof(v2_path), "%s/mem_v2_max", test_dir);
  create_dir(v2_path);

  char file_path[512];
  snprintf(file_path, sizeof(file_path), "%s/memory.max", v2_path);
  create_file(file_path, "max\n");

  uint64_t limit = cgroup_read_memory_max(v2_path);
  assert(limit == UINT64_MAX);
}

TEST(read_memory_v1) {
  char v1_path[512];
  snprintf(v1_path, sizeof(v1_path), "%s/mem_v1", test_dir);
  create_dir(v1_path);

  char file_path[512];
  snprintf(file_path, sizeof(file_path), "%s/memory.usage_in_bytes", v1_path);
  create_file(file_path, "87654321\n");

  snprintf(file_path, sizeof(file_path), "%s/memory.limit_in_bytes", v1_path);
  create_file(file_path, "209715200\n");

  uint64_t usage = cgroup_read_memory_current(v1_path);
  assert(usage == 87654321);

  uint64_t limit = cgroup_read_memory_max(v1_path);
  assert(limit == 209715200);
}

TEST(read_memory_v1_unlimited) {
  char v1_path[512];
  snprintf(v1_path, sizeof(v1_path), "%s/mem_v1_unlim", test_dir);
  create_dir(v1_path);

  char file_path[512];
  snprintf(file_path, sizeof(file_path), "%s/memory.limit_in_bytes", v1_path);
  // v1 default unlimited value
  create_file(file_path, "9223372036854771712\n");

  uint64_t limit = cgroup_read_memory_max(v1_path);
  assert(limit == UINT64_MAX);
}

// ─────────────────────────────────────────────────────────────────────────────
// Container Info Parsing Tests
// ─────────────────────────────────────────────────────────────────────────────

TEST(parse_containerd_path) {
  // Container ID: 64 hex chars
  // (abcdef01234567890123456789012345abcdef01234567890123456789012345)
  const char *path =
      "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/"
      "kubepods-burstable-pod12345678_1234_1234_1234_123456789abc.slice/"
      "cri-containerd-"
      "abcdef01234567890123456789012345abcdef01234567890123456789012345.scope";

  char *ns = NULL, *pod = NULL, *container = NULL;
  int rc = cgroup_parse_container_info(path, &ns, &pod, &container);
  assert(rc == 0);
  assert(ns != NULL);
  assert(pod != NULL);
  assert(container != NULL);

  // Container ID should be extracted (64 hex chars)
  assert(strlen(container) == 64);

  free(ns);
  free(pod);
  free(container);
}

TEST(parse_cgroupfs_path) {
  // Container ID: 64 hex chars (plain hex, cgroupfs format)
  const char *path =
      "/sys/fs/cgroup/kubepods/burstable/"
      "pod12345678-1234-1234-1234-123456789abc/"
      "abcdef01234567890123456789012345abcdef01234567890123456789012345";

  char *ns = NULL, *pod = NULL, *container = NULL;
  int rc = cgroup_parse_container_info(path, &ns, &pod, &container);
  assert(rc == 0);
  assert(ns != NULL);
  assert(pod != NULL);
  assert(container != NULL);

  free(ns);
  free(pod);
  free(container);
}

TEST(parse_docker_path) {
  // Container ID: 64 hex chars (docker format)
  const char *path =
      "/sys/fs/cgroup/kubepods.slice/kubepods-pod1234.slice/"
      "docker-abcdef01234567890123456789012345abcdef01234567890123456789012345."
      "scope";

  char *ns = NULL, *pod = NULL, *container = NULL;
  int rc = cgroup_parse_container_info(path, &ns, &pod, &container);
  assert(rc == 0);
  assert(container != NULL);
  assert(strlen(container) == 64);

  free(ns);
  free(pod);
  free(container);
}

// ─────────────────────────────────────────────────────────────────────────────
// POD_UID Discovery Tests
// ─────────────────────────────────────────────────────────────────────────────

TEST(pod_uid_discovery_burstable) {
  // Create a burstable pod cgroup structure
  char base[512], qos[512], pod[512];
  snprintf(base, sizeof(base), "%s/pod_uid", test_dir);
  create_dir(base);

  snprintf(qos, sizeof(qos), "%s/kubepods.slice", base);
  create_dir(qos);

  snprintf(qos, sizeof(qos), "%s/kubepods.slice/kubepods-burstable.slice",
           base);
  create_dir(qos);

  // Pod UID with underscores (systemd format)
  snprintf(
      pod, sizeof(pod),
      "%s/kubepods.slice/kubepods-burstable.slice/"
      "kubepods-burstable-podabc123_def456_ghi789_jkl012_mno345678901.slice",
      base);
  create_dir(pod);

  // Add memory files
  char file_path[512];
  snprintf(file_path, sizeof(file_path), "%s/memory.current", pod);
  create_file(file_path, "1000000\n");
  snprintf(file_path, sizeof(file_path), "%s/memory.max", pod);
  create_file(file_path, "10000000\n");

  // Set POD_UID and test discovery
  setenv("POD_UID", "abc123-def456-ghi789-jkl012-mno345678901", 1);

  cgroup_source_t *source = cgroup_source_new(base);
  assert(source != NULL);

  const char *discovered = cgroup_source_get_discovered_path(source);
  assert(discovered != NULL);
  assert(strstr(discovered, "burstable") != NULL);

  unsetenv("POD_UID");
  cgroup_source_free(source);
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration Tests
// ─────────────────────────────────────────────────────────────────────────────

TEST(source_creation_default) {
  cgroup_source_t *source = cgroup_source_new("/sys/fs/cgroup");
  assert(source != NULL);
  cgroup_source_free(source);
}

TEST(collect_samples) {
  // Create a test pod structure
  char base[512], qos[512], pod[512], container[512];
  snprintf(base, sizeof(base), "%s/collect", test_dir);
  create_dir(base);

  snprintf(qos, sizeof(qos), "%s/kubepods.slice", base);
  create_dir(qos);
  snprintf(qos, sizeof(qos), "%s/kubepods.slice/kubepods-burstable.slice",
           base);
  create_dir(qos);
  snprintf(pod, sizeof(pod),
           "%s/kubepods.slice/kubepods-burstable.slice/"
           "kubepods-burstable-pod1234.slice",
           base);
  create_dir(pod);
  snprintf(container, sizeof(container), "%s/cri-containerd-abcd1234.scope",
           pod);
  create_dir(container);

  // Add memory files to container
  char file_path[512];
  snprintf(file_path, sizeof(file_path), "%s/memory.current", container);
  create_file(file_path, "5000000\n");
  snprintf(file_path, sizeof(file_path), "%s/memory.max", container);
  create_file(file_path, "10000000\n");

  cgroup_source_t *source = cgroup_source_new(base);
  assert(source != NULL);

  int count = 0;
  pressured_memory_sample_t *samples = cgroup_collect(source, &count);

  // Should find at least the container
  printf("(found %d samples) ", count);
  if (samples) {
    cgroup_samples_free(samples, count);
  }

  cgroup_source_free(source);
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

int main(void) {
  log_init(LOG_DEBUG);

  printf("test_cgroup: Cgroup Source Unit Tests\n");
  printf("======================================\n\n");

  setup_test_dir();

  printf("Version Detection:\n");
  RUN_TEST(version_detection_v2);
  RUN_TEST(version_detection_v2_with_controllers);
  RUN_TEST(version_detection_v1);

  printf("\nMemory Reading:\n");
  RUN_TEST(read_memory_v2);
  RUN_TEST(read_memory_v2_max_unlimited);
  RUN_TEST(read_memory_v1);
  RUN_TEST(read_memory_v1_unlimited);

  printf("\nContainer Info Parsing:\n");
  RUN_TEST(parse_containerd_path);
  RUN_TEST(parse_cgroupfs_path);
  RUN_TEST(parse_docker_path);

  printf("\nPOD_UID Discovery:\n");
  RUN_TEST(pod_uid_discovery_burstable);

  printf("\nIntegration:\n");
  RUN_TEST(source_creation_default);
  RUN_TEST(collect_samples);

  cleanup_test_dir();

  printf("\n======================================\n");
  printf("Results: %d/%d passed\n", tests_passed, tests_total);

  if (tests_passed != tests_total) {
    printf("test_cgroup: FAILED\n");
    return 1;
  }

  printf("test_cgroup: PASSED\n");
  return 0;
}
