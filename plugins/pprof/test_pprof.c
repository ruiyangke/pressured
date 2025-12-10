/*
 * pprof analyzer tests
 *
 * Tests the purpose-built pprof heap analyzer.
 */

#include "log.h"
#include "plugin.h"
#include "pprof.h"
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PPROF_PLUGIN_TYPE (1 << 2)

static void *plugin_handle = NULL;
static pressured_plugin_ctx_t *plugin_ctx = NULL;

// Plugin function pointers
static pressured_plugin_get_metadata_fn get_metadata;
static pressured_plugin_load_fn plugin_load;
static pressured_plugin_unload_fn plugin_unload;
static pressured_plugin_create_fn plugin_create;
static pressured_plugin_destroy_fn plugin_destroy;

// pprof-specific function - for freeing results
typedef void (*pprof_results_free_fn)(pprof_results_t *results);
static pprof_results_free_fn results_free;

static int load_plugin(void) {
  plugin_handle = dlopen("./plugins/pprof_plugin.so", RTLD_NOW);
  if (!plugin_handle) {
    fprintf(stderr, "Failed to load plugin: %s\n", dlerror());
    return -1;
  }

  get_metadata = (pressured_plugin_get_metadata_fn)dlsym(
      plugin_handle, "pressured_plugin_get_metadata");
  plugin_load =
      (pressured_plugin_load_fn)dlsym(plugin_handle, "pressured_plugin_load");
  plugin_unload =
      (pressured_plugin_unload_fn)dlsym(plugin_handle, "pressured_plugin_unload");
  plugin_create =
      (pressured_plugin_create_fn)dlsym(plugin_handle, "pressured_plugin_create");
  plugin_destroy =
      (pressured_plugin_destroy_fn)dlsym(plugin_handle, "pressured_plugin_destroy");

  // Load pprof-specific function for freeing results
  results_free =
      (pprof_results_free_fn)dlsym(plugin_handle, "pprof_results_free");

  if (!get_metadata || !plugin_load || !plugin_unload || !plugin_create ||
      !plugin_destroy || !results_free) {
    fprintf(stderr, "Failed to resolve plugin symbols\n");
    dlclose(plugin_handle);
    return -1;
  }

  return 0;
}

static void unload_plugin(void) {
  if (plugin_handle) {
    dlclose(plugin_handle);
    plugin_handle = NULL;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Plugin metadata
// ─────────────────────────────────────────────────────────────────────────────

static void test_metadata(void) {
  printf("test_metadata: ");

  const pressured_plugin_metadata_t *meta = get_metadata();
  assert(meta != NULL);
  assert(strcmp(meta->name, "pprof") == 0);
  assert(meta->types == PPROF_PLUGIN_TYPE);
  assert(meta->major_version == 1);

  printf("PASS\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Plugin lifecycle
// ─────────────────────────────────────────────────────────────────────────────

static void test_lifecycle(void) {
  printf("test_lifecycle: ");

  plugin_ctx = plugin_load(NULL);
  assert(plugin_ctx != NULL);

  pressured_plugin_handle_t *handle =
      plugin_create(plugin_ctx, PPROF_PLUGIN_TYPE);
  assert(handle != NULL);

  plugin_destroy(plugin_ctx, PPROF_PLUGIN_TYPE, handle);
  plugin_unload(plugin_ctx);
  plugin_ctx = NULL;

  printf("PASS\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Top memory functions
// ─────────────────────────────────────────────────────────────────────────────

static void test_top_mem_functions(void) {
  printf("test_top_mem_functions: ");

  const char *test_file = getenv("PPROF_TEST_FILE");
  if (!test_file) {
    printf("SKIP (set PPROF_TEST_FILE to run)\n");
    return;
  }

  plugin_ctx = plugin_load(NULL);
  assert(plugin_ctx != NULL);

  pressured_plugin_handle_t *handle =
      plugin_create(plugin_ctx, PPROF_PLUGIN_TYPE);
  assert(handle != NULL);

  // Cast to analyzer interface
  pprof_analyzer_t *a = (pprof_analyzer_t *)handle;

  // Get top 5 memory-consuming functions (0 = use default)
  pprof_results_t results = {0};
  int rc = a->top_mem_functions(a, test_file, 0, &results);

  if (rc != 0) {
    printf("FAIL (analyze error: %d)\n", rc);
    plugin_destroy(plugin_ctx, PPROF_PLUGIN_TYPE, handle);
    plugin_unload(plugin_ctx);
    return;
  }

  printf("\n\n  TOP %zu MEMORY FUNCTIONS\n", results.count);
  printf("  ════════════════════════════════════════════════════════════════════════════════\n\n");

  for (size_t i = 0; i < results.count; i++) {
    pprof_func_stat_t *f = &results.funcs[i];
    double mb = (double)f->inuse_bytes / (1024.0 * 1024.0);
    printf("  %zu. %s\n", i + 1, f->name);
    printf("     └─ %.2f MB (%ld objects)\n\n", mb, (long)f->inuse_objects);
  }

  printf("  ════════════════════════════════════════════════════════════════════════════════\n");
  printf("  Total in-use: %.2f MB\n\n", (double)results.total_inuse / (1024.0 * 1024.0));

  // Basic assertions
  assert(results.count > 0);
  assert(results.total_inuse > 0);

  // Free results
  results_free(&results);

  plugin_destroy(plugin_ctx, PPROF_PLUGIN_TYPE, handle);
  plugin_unload(plugin_ctx);
  plugin_ctx = NULL;

  printf("  PASS\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

int main(void) {
  printf("=== pprof analyzer tests ===\n\n");

  if (load_plugin() != 0) {
    fprintf(stderr, "Failed to load pprof plugin\n");
    return 1;
  }

  test_metadata();
  test_lifecycle();
  test_top_mem_functions();

  unload_plugin();

  printf("\nAll tests passed!\n");
  return 0;
}
