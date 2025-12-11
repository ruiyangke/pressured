/*
 * Service Registry Tests
 *
 * Tests for the metadata-driven service registry with handle-wrapped lifecycle.
 */

#include "log.h"
#include "service_registry.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Mock Services
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
  int (*get_value)(void *self);
  int value;
} mock_service_t;

static int mock_get_value(void *self) {
  mock_service_t *s = (mock_service_t *)self;
  return s->value;
}

static void *mock_factory(void *userdata) {
  int value = userdata ? *(int *)userdata : 0;
  mock_service_t *s = malloc(sizeof(*s));
  if (!s)
    return NULL;
  s->get_value = mock_get_value;
  s->value = value;
  return s;
}

static int destructor_called = 0;
static void mock_destructor(void *instance, void *userdata) {
  (void)userdata;
  destructor_called++;
  free(instance);
}

static void *failing_factory(void *userdata) {
  (void)userdata;
  return NULL;
}

static int factory_call_count = 0;
static void *counting_factory(void *userdata) {
  factory_call_count++;
  return mock_factory(userdata);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test Metadata
 * ═══════════════════════════════════════════════════════════════════════════ */

static const service_metadata_t basic_meta = {
    .type = "test",
    .provider = "basic",
    .version = "1.0.0",
    .priority = 100,
};

static const char *cloud_tags[] = {"cloud", "aws", NULL};
static const service_metadata_t s3_meta = {
    .type = "storage",
    .provider = "s3",
    .version = "2.0.0",
    .priority = 100,
    .tags = cloud_tags,
};

static const char *local_tags[] = {"local", "filesystem", NULL};
static const service_metadata_t local_meta = {
    .type = "storage",
    .provider = "local",
    .version = "1.0.0",
    .priority = 50,
    .tags = local_tags,
};

static const service_metadata_t gcs_meta = {
    .type = "storage",
    .provider = "gcs",
    .version = "1.5.0",
    .priority = 80,
    .tags = cloud_tags,
};

static const service_metadata_t transient_meta = {
    .type = "analyzer",
    .provider = "pprof",
    .version = "1.0.0",
    .priority = 100,
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Test: Basic Registration and Acquire
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_basic_registration(void) {
  printf("test_basic_registration: ");

  service_registry_t *sr = service_registry_new();
  assert(sr != NULL);

  int value = 42;
  int rc = service_registry_register(sr, &basic_meta, SERVICE_SCOPE_SINGLETON,
                                     mock_factory, mock_destructor, &value);
  assert(rc == 0);

  /* Check has */
  assert(service_registry_has(sr, "test") == 1);
  assert(service_registry_has(sr, "test:basic") == 1);
  assert(service_registry_has(sr, "nonexistent") == 0);

  /* Acquire */
  service_ref_t ref = service_registry_acquire(sr, "test");
  assert(service_ref_valid(&ref));
  mock_service_t *s = ref.instance;
  assert(s->get_value(s) == 42);

  /* Acquire again (should return same instance for singleton) */
  service_ref_t ref2 = service_registry_acquire(sr, "test");
  assert(ref2.instance == ref.instance);

  /* Release (no-op for singleton) */
  service_ref_release(&ref);
  service_ref_release(&ref2);

  /* Acquire nonexistent */
  service_ref_t none = service_registry_acquire(sr, "nonexistent");
  assert(!service_ref_valid(&none));

  destructor_called = 0;
  service_registry_free(sr);
  assert(destructor_called == 1);

  printf("PASS\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test: Priority-Based Selection
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_priority_selection(void) {
  printf("test_priority_selection: ");

  service_registry_t *sr = service_registry_new();

  int s3_val = 100, local_val = 50, gcs_val = 80;

  /* Register in non-priority order */
  service_registry_register(sr, &local_meta, SERVICE_SCOPE_SINGLETON,
                            mock_factory, mock_destructor, &local_val);
  service_registry_register(sr, &gcs_meta, SERVICE_SCOPE_SINGLETON,
                            mock_factory, mock_destructor, &gcs_val);
  service_registry_register(sr, &s3_meta, SERVICE_SCOPE_SINGLETON, mock_factory,
                            mock_destructor, &s3_val);

  /* Init all singletons */
  assert(service_registry_init_all(sr) == 0);

  /* Acquire by type (should get highest priority = s3) */
  service_ref_t ref = service_registry_acquire(sr, "storage");
  assert(service_ref_valid(&ref));
  mock_service_t *s = ref.instance;
  assert(s->value == 100); /* s3 has priority=100 */
  service_ref_release(&ref);

  /* Acquire specific provider */
  service_ref_t local_ref = service_registry_acquire(sr, "storage:local");
  assert(service_ref_valid(&local_ref));
  mock_service_t *local = local_ref.instance;
  assert(local->value == 50);
  service_ref_release(&local_ref);

  /* Acquire by tag */
  service_ref_t cloud_ref =
      service_registry_acquire_tagged(sr, "storage", "cloud");
  assert(service_ref_valid(&cloud_ref));
  mock_service_t *cloud = cloud_ref.instance;
  assert(cloud->value == 100); /* s3 is highest priority with "cloud" tag */
  service_ref_release(&cloud_ref);

  /* Acquire local tag */
  service_ref_t fs_ref =
      service_registry_acquire_tagged(sr, "storage", "filesystem");
  assert(service_ref_valid(&fs_ref));
  mock_service_t *fs = fs_ref.instance;
  assert(fs->value == 50);
  service_ref_release(&fs_ref);

  destructor_called = 0;
  service_registry_free(sr);
  assert(destructor_called == 3);

  printf("PASS\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test: Singleton vs Transient Scope
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_scope_behavior(void) {
  printf("test_scope_behavior: ");

  service_registry_t *sr = service_registry_new();

  int singleton_val = 1;
  int transient_val = 2;

  /* Register singleton */
  service_registry_register(sr, &basic_meta, SERVICE_SCOPE_SINGLETON,
                            mock_factory, mock_destructor, &singleton_val);

  /* Register transient */
  service_registry_register(sr, &transient_meta, SERVICE_SCOPE_TRANSIENT,
                            mock_factory, mock_destructor, &transient_val);

  /* Init singletons */
  service_registry_init_all(sr);

  /* Singleton: same instance on multiple acquires */
  service_ref_t s1 = service_registry_acquire(sr, "test");
  service_ref_t s2 = service_registry_acquire(sr, "test");
  assert(s1.instance == s2.instance);
  service_ref_release(&s1);
  service_ref_release(&s2);

  /* Transient: different instance on each acquire */
  service_ref_t t1 = service_registry_acquire(sr, "analyzer");
  service_ref_t t2 = service_registry_acquire(sr, "analyzer");
  assert(t1.instance != t2.instance);

  /* Transient: release destroys instance */
  destructor_called = 0;
  service_ref_release(&t1);
  assert(destructor_called == 1);
  service_ref_release(&t2);
  assert(destructor_called == 2);

  /* Cleanup */
  destructor_called = 0;
  service_registry_free(sr);
  assert(destructor_called == 1); /* Only singleton destroyed */

  printf("PASS\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test: Eager Initialization
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_eager_init(void) {
  printf("test_eager_init: ");

  service_registry_t *sr = service_registry_new();

  factory_call_count = 0;
  int value = 42;

  service_registry_register(sr, &basic_meta, SERVICE_SCOPE_SINGLETON,
                            counting_factory, NULL, &value);

  /* Factory not called yet */
  assert(factory_call_count == 0);

  /* init_all() calls factory */
  assert(service_registry_init_all(sr) == 0);
  assert(factory_call_count == 1);

  /* Subsequent acquires don't call factory */
  service_ref_t ref = service_registry_acquire(sr, "test");
  assert(service_ref_valid(&ref));
  assert(factory_call_count == 1);
  service_ref_release(&ref);

  /* Cleanup */
  free(((mock_service_t *)ref.instance)); /* No destructor registered */
  service_registry_free(sr);

  printf("PASS\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test: Acquire All
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_acquire_all(void) {
  printf("test_acquire_all: ");

  service_registry_t *sr = service_registry_new();

  int s3_val = 100, local_val = 50, gcs_val = 80;

  service_registry_register(sr, &s3_meta, SERVICE_SCOPE_SINGLETON, mock_factory,
                            mock_destructor, &s3_val);
  service_registry_register(sr, &local_meta, SERVICE_SCOPE_SINGLETON,
                            mock_factory, mock_destructor, &local_val);
  service_registry_register(sr, &gcs_meta, SERVICE_SCOPE_SINGLETON,
                            mock_factory, mock_destructor, &gcs_val);

  service_registry_init_all(sr);

  /* Count */
  assert(service_registry_count(sr, "storage") == 3);

  /* Acquire all */
  service_ref_t refs[4] = {0};
  size_t count = service_registry_acquire_all(sr, "storage", refs, 4);
  assert(count == 3);

  /* Verify all valid */
  int found_100 = 0, found_80 = 0, found_50 = 0;
  for (size_t i = 0; i < count; i++) {
    assert(service_ref_valid(&refs[i]));
    mock_service_t *s = refs[i].instance;
    if (s->value == 100)
      found_100 = 1;
    if (s->value == 80)
      found_80 = 1;
    if (s->value == 50)
      found_50 = 1;
  }
  assert(found_100 && found_80 && found_50);

  /* Release all */
  for (size_t i = 0; i < count; i++) {
    service_ref_release(&refs[i]);
  }

  service_registry_free(sr);

  printf("PASS\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test: Acquire All Tagged
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_acquire_all_tagged(void) {
  printf("test_acquire_all_tagged: ");

  service_registry_t *sr = service_registry_new();

  int s3_val = 100, local_val = 50, gcs_val = 80;

  service_registry_register(sr, &s3_meta, SERVICE_SCOPE_SINGLETON, mock_factory,
                            mock_destructor, &s3_val);
  service_registry_register(sr, &local_meta, SERVICE_SCOPE_SINGLETON,
                            mock_factory, mock_destructor, &local_val);
  service_registry_register(sr, &gcs_meta, SERVICE_SCOPE_SINGLETON,
                            mock_factory, mock_destructor, &gcs_val);

  service_registry_init_all(sr);

  /* Acquire all with "cloud" tag (s3 and gcs) */
  service_ref_t refs[4] = {0};
  size_t count =
      service_registry_acquire_all_tagged(sr, "storage", "cloud", refs, 4);
  assert(count == 2);

  int found_100 = 0, found_80 = 0;
  for (size_t i = 0; i < count; i++) {
    mock_service_t *s = refs[i].instance;
    if (s->value == 100)
      found_100 = 1;
    if (s->value == 80)
      found_80 = 1;
    service_ref_release(&refs[i]);
  }
  assert(found_100 && found_80);

  service_registry_free(sr);

  printf("PASS\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test: Factory Failure
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_factory_failure(void) {
  printf("test_factory_failure: ");

  service_registry_t *sr = service_registry_new();

  static const service_metadata_t fail_meta = {
      .type = "failing",
      .provider = "test",
  };

  service_registry_register(sr, &fail_meta, SERVICE_SCOPE_SINGLETON,
                            failing_factory, NULL, NULL);

  /* init_all returns failure */
  assert(service_registry_init_all(sr) == -1);

  /* Acquire returns invalid ref */
  service_ref_t ref = service_registry_acquire(sr, "failing");
  assert(!service_ref_valid(&ref));

  /* State is FAILED */
  assert(service_registry_state(sr, "failing") == SERVICE_STATE_FAILED);

  service_registry_free(sr);

  printf("PASS\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test: Metadata Query
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_metadata_query(void) {
  printf("test_metadata_query: ");

  service_registry_t *sr = service_registry_new();

  int val = 1;
  service_registry_register(sr, &s3_meta, SERVICE_SCOPE_SINGLETON, mock_factory,
                            mock_destructor, &val);

  /* Query metadata */
  const service_metadata_t *meta =
      service_registry_metadata(sr, "storage", "s3");
  assert(meta != NULL);
  assert(strcmp(meta->type, "storage") == 0);
  assert(strcmp(meta->provider, "s3") == 0);
  assert(strcmp(meta->version, "2.0.0") == 0);
  assert(meta->priority == 100);

  /* Query nonexistent */
  const service_metadata_t *none =
      service_registry_metadata(sr, "storage", "azure");
  assert(none == NULL);

  service_registry_free(sr);

  printf("PASS\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test: Iteration
 * ═══════════════════════════════════════════════════════════════════════════ */

static int type_count = 0;
static void count_types(const char *type, size_t provider_count,
                        void *userdata) {
  (void)type;
  (void)provider_count;
  (void)userdata;
  type_count++;
}

static int provider_count = 0;
static void count_providers(const service_metadata_t *meta, void *userdata) {
  (void)meta;
  (void)userdata;
  provider_count++;
}

static void test_iteration(void) {
  printf("test_iteration: ");

  service_registry_t *sr = service_registry_new();

  int val = 1;
  service_registry_register(sr, &s3_meta, SERVICE_SCOPE_SINGLETON, mock_factory,
                            mock_destructor, &val);
  service_registry_register(sr, &local_meta, SERVICE_SCOPE_SINGLETON,
                            mock_factory, mock_destructor, &val);
  service_registry_register(sr, &basic_meta, SERVICE_SCOPE_SINGLETON,
                            mock_factory, mock_destructor, &val);

  /* Count types (storage, test) */
  type_count = 0;
  service_registry_foreach_type(sr, count_types, NULL);
  assert(type_count == 2);

  /* Count storage providers */
  provider_count = 0;
  service_registry_foreach_provider(sr, "storage", count_providers, NULL);
  assert(provider_count == 2);

  service_registry_free(sr);

  printf("PASS\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test: Lifecycle Control
 * ═══════════════════════════════════════════════════════════════════════════ */

static int start_called = 0;
static int stop_called = 0;

static int mock_start(void *instance, void *userdata) {
  (void)instance;
  (void)userdata;
  start_called++;
  return 0;
}

static void mock_stop(void *instance, void *userdata) {
  (void)instance;
  (void)userdata;
  stop_called++;
}

static void test_lifecycle_control(void) {
  printf("test_lifecycle_control: ");

  service_registry_t *sr = service_registry_new();

  static const service_metadata_t lifecycle_meta = {
      .type = "lifecycle",
      .provider = "test",
  };

  service_callbacks_t callbacks = {
      .create = mock_factory,
      .destroy = mock_destructor,
      .start = mock_start,
      .stop = mock_stop,
  };

  int val = 1;
  service_registry_register_ex(sr, &lifecycle_meta, SERVICE_SCOPE_SINGLETON,
                               &callbacks, &val);

  /* Init creates instance but doesn't start */
  start_called = 0;
  stop_called = 0;
  service_registry_init_all(sr);
  assert(start_called == 0);
  assert(service_registry_state(sr, "lifecycle") == SERVICE_STATE_CREATED);

  /* Start */
  assert(service_registry_start(sr, "lifecycle") == 0);
  assert(start_called == 1);
  assert(service_registry_state(sr, "lifecycle") == SERVICE_STATE_RUNNING);

  /* Stop */
  assert(service_registry_stop(sr, "lifecycle") == 0);
  assert(stop_called == 1);
  assert(service_registry_state(sr, "lifecycle") == SERVICE_STATE_STOPPED);

  /* Restart */
  assert(service_registry_restart(sr, "lifecycle") == 0);
  assert(start_called == 2);

  service_registry_free(sr);

  printf("PASS\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test: Hash Table Resize
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_resize(void) {
  printf("test_resize: ");

  service_registry_t *sr = service_registry_new();

  /* Register many services to trigger resize */
  service_metadata_t metas[100];
  char types[100][32];
  char providers[100][32];
  int values[100];

  for (int i = 0; i < 100; i++) {
    snprintf(types[i], sizeof(types[i]), "type_%d", i);
    snprintf(providers[i], sizeof(providers[i]), "provider_%d", i);
    values[i] = i;

    metas[i] = (service_metadata_t){
        .type = types[i],
        .provider = providers[i],
        .priority = i,
    };

    int rc = service_registry_register(sr, &metas[i], SERVICE_SCOPE_SINGLETON,
                                       mock_factory, NULL, &values[i]);
    assert(rc == 0);
  }

  service_registry_init_all(sr);

  /* Verify all can be acquired */
  for (int i = 0; i < 100; i++) {
    service_ref_t ref = service_registry_acquire(sr, types[i]);
    assert(service_ref_valid(&ref));
    mock_service_t *s = ref.instance;
    assert(s->value == i);
    service_ref_release(&ref);
  }

  /* Cleanup - no destructor registered, instances leak but that's ok for test
   */
  service_registry_free(sr);

  printf("PASS\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test: NULL Safety
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_null_safety(void) {
  printf("test_null_safety: ");

  /* NULL registry */
  service_ref_t ref = service_registry_acquire(NULL, "test");
  assert(!service_ref_valid(&ref));
  assert(service_registry_has(NULL, "test") == 0);
  assert(service_registry_count(NULL, "test") == 0);

  service_registry_t *sr = service_registry_new();

  /* NULL type */
  ref = service_registry_acquire(sr, NULL);
  assert(!service_ref_valid(&ref));
  assert(service_registry_has(sr, NULL) == 0);
  assert(service_registry_register(sr, NULL, SERVICE_SCOPE_SINGLETON,
                                   mock_factory, NULL, NULL) == -1);

  /* NULL ref release (should not crash) */
  service_ref_release(NULL);
  service_ref_t empty = {0};
  service_ref_release(&empty);

  /* NULL-safe free */
  service_registry_free(NULL);

  service_registry_free(sr);

  printf("PASS\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Main
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(void) {
  log_init(LOG_WARN);

  printf("=== Service Registry Tests ===\n\n");

  test_basic_registration();
  test_priority_selection();
  test_scope_behavior();
  test_eager_init();
  test_acquire_all();
  test_acquire_all_tagged();
  test_factory_failure();
  test_metadata_query();
  test_iteration();
  test_lifecycle_control();
  test_resize();
  test_null_safety();

  printf("\nAll tests passed!\n");
  return 0;
}
