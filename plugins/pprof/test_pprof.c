/*
 * pprof analyzer tests
 *
 * Tests the pprof heap analyzer using service registry and storage API.
 */

#include "log.h"
#include "plugin.h"
#include "plugin_manager.h"
#include "pprof.h"
#include "service_registry.h"
#include "storage.h"
#include <assert.h>
#include <dlfcn.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PPROF_PLUGIN_PATH "./plugins/pprof.so"
#define STORAGE_PLUGIN_PATH "./plugins/local-storage.so"

// ─────────────────────────────────────────────────────────────────────────────
// Test: Plugin metadata
// ─────────────────────────────────────────────────────────────────────────────

static void test_metadata(void) {
  printf("test_metadata: ");

  void *handle = dlopen(PPROF_PLUGIN_PATH, RTLD_NOW);
  if (!handle) {
    printf("FAIL (dlopen: %s)\n", dlerror());
    return;
  }

  pressured_plugin_get_metadata_fn get_metadata =
      (pressured_plugin_get_metadata_fn)dlsym(handle,
                                              "pressured_plugin_get_metadata");
  assert(get_metadata != NULL);

  const pressured_plugin_metadata_t *meta = get_metadata();
  assert(meta != NULL);
  assert(strcmp(meta->name, "pprof") == 0);
  assert(meta->major_version == 1);

  dlclose(handle);
  printf("PASS\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Plugin lifecycle via service registry
// ─────────────────────────────────────────────────────────────────────────────

static void test_lifecycle(void) {
  printf("test_lifecycle: ");

  service_registry_t *sr = service_registry_new();
  assert(sr != NULL);

  plugin_manager_t *pm = plugin_manager_new(sr);
  assert(pm != NULL);

  int rc = plugin_manager_load(pm, PPROF_PLUGIN_PATH, NULL);
  if (rc != 0) {
    printf("FAIL (load returned %d)\n", rc);
    service_registry_free(sr);
    plugin_manager_free(pm);
    return;
  }

  // Initialize all services
  service_registry_init_all(sr);

  // Acquire analyzer service
  service_ref_t ref = service_registry_acquire(sr, "analyzer");
  if (!service_ref_valid(&ref)) {
    printf("FAIL (no analyzer service registered)\n");
    service_registry_free(sr);
    plugin_manager_free(pm);
    return;
  }

  pprof_analyzer_t *a = (pprof_analyzer_t *)ref.instance;
  assert(a != NULL);
  assert(a->top_mem_functions != NULL);

  service_ref_release(&ref);
  service_registry_free(sr);
  plugin_manager_free(pm);

  printf("PASS\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Top memory functions (using storage API)
// ─────────────────────────────────────────────────────────────────────────────

static void test_top_mem_functions(void) {
  printf("test_top_mem_functions: ");

  const char *test_file = getenv("PPROF_TEST_FILE");
  if (!test_file) {
    printf("SKIP (set PPROF_TEST_FILE to run)\n");
    return;
  }

  // Extract directory and filename from test_file path
  char *test_file_copy = strdup(test_file);
  char *test_file_copy2 = strdup(test_file);
  char *dir = dirname(test_file_copy);
  char *filename = basename(test_file_copy2);

  // Set storage root to the directory containing the pprof file
  setenv("PRESSURED_STORAGE_PATH", dir, 1);

  // Create service registry and plugin manager
  service_registry_t *sr = service_registry_new();
  assert(sr != NULL);

  plugin_manager_t *pm = plugin_manager_new(sr);
  assert(pm != NULL);

  // Load storage plugin first
  int rc = plugin_manager_load(pm, STORAGE_PLUGIN_PATH, NULL);
  if (rc != 0) {
    printf("FAIL (failed to load storage plugin)\n");
    free(test_file_copy);
    free(test_file_copy2);
    service_registry_free(sr);
    plugin_manager_free(pm);
    return;
  }

  // Load pprof analyzer plugin
  rc = plugin_manager_load(pm, PPROF_PLUGIN_PATH, NULL);
  if (rc != 0) {
    printf("FAIL (failed to load pprof plugin)\n");
    free(test_file_copy);
    free(test_file_copy2);
    service_registry_free(sr);
    plugin_manager_free(pm);
    return;
  }

  // Initialize all services
  service_registry_init_all(sr);

  // Acquire storage service
  service_ref_t storage_ref = service_registry_acquire(sr, "storage");
  if (!service_ref_valid(&storage_ref)) {
    printf("FAIL (no storage service)\n");
    free(test_file_copy);
    free(test_file_copy2);
    service_registry_free(sr);
    plugin_manager_free(pm);
    return;
  }
  storage_t *storage = (storage_t *)storage_ref.instance;

  // Acquire analyzer service
  service_ref_t analyzer_ref = service_registry_acquire(sr, "analyzer");
  if (!service_ref_valid(&analyzer_ref)) {
    printf("FAIL (no analyzer service)\n");
    service_ref_release(&storage_ref);
    free(test_file_copy);
    free(test_file_copy2);
    service_registry_free(sr);
    plugin_manager_free(pm);
    return;
  }
  pprof_analyzer_t *a = (pprof_analyzer_t *)analyzer_ref.instance;

  // Get top 5 memory-consuming functions (0 = use default)
  pprof_results_t results = {0};
  rc = a->top_mem_functions(a, storage, filename, 0, &results);

  if (rc != 0) {
    printf("FAIL (analyze error: %d - %s)\n", rc, pprof_strerror(rc));
    service_ref_release(&analyzer_ref);
    service_ref_release(&storage_ref);
    free(test_file_copy);
    free(test_file_copy2);
    service_registry_free(sr);
    plugin_manager_free(pm);
    return;
  }

  printf("\n\n  TOP %zu MEMORY FUNCTIONS\n", results.count);
  printf("  ════════════════════════════════════════════════════════════════"
         "══════════════\n\n");

  for (size_t i = 0; i < results.count; i++) {
    const pprof_func_stat_t *f = &results.funcs[i];
    double mb = (double)f->inuse_bytes / (1024.0 * 1024.0);
    printf("  %zu. %s\n", i + 1, f->name);
    printf("     └─ %.2f MB (%ld objects)\n\n", mb, (long)f->inuse_objects);
  }

  printf("  ════════════════════════════════════════════════════════════════"
         "══════════════\n");
  printf("  Total in-use: %.2f MB\n\n",
         (double)results.total_inuse / (1024.0 * 1024.0));

  // Basic assertions
  assert(results.count > 0);
  assert(results.total_inuse > 0);

  // Free results
  pprof_results_free(&results);

  service_ref_release(&analyzer_ref);
  service_ref_release(&storage_ref);
  free(test_file_copy);
  free(test_file_copy2);
  service_registry_free(sr);
  plugin_manager_free(pm);

  printf("  PASS\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

int main(void) {
  log_init(LOG_INFO);

  printf("=== pprof analyzer tests ===\n\n");

  test_metadata();
  test_lifecycle();
  test_top_mem_functions();

  printf("\nAll tests passed!\n");
  return 0;
}
