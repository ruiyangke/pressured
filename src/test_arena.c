/*
 * arena Tests
 *
 * Covers the chunked bump allocator in src/arena.c: alignment, strings, chunks
 * and reuse, oversize requests, bad sizes, free, and the AddressSanitizer
 * poisoning of dropped allocations.
 */

#include "arena.h"
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void test_alignment(void) {
  printf("  allocations are aligned, disjoint and keep their bytes... ");
  enum { count = 100 };
  arena_t a = {0};
  unsigned char *ptrs[count];
  for (int i = 0; i < count; i++) {
    size_t size = (size_t)i + 1;
    ptrs[i] = arena_alloc(&a, size);
    assert(ptrs[i]);
    assert((uintptr_t)ptrs[i] % _Alignof(max_align_t) == 0);
    memset(ptrs[i], i, size);
  }
  for (int i = 0; i < count; i++) {
    size_t size = (size_t)i + 1;
    uintptr_t start = (uintptr_t)ptrs[i];
    for (int j = i + 1; j < count; j++) {
      uintptr_t other_start = (uintptr_t)ptrs[j];
      size_t other_size = (size_t)j + 1;
      assert(start + size <= other_start || other_start + other_size <= start);
    }
    for (size_t k = 0; k < size; k++)
      assert(ptrs[i][k] == (unsigned char)i);
  }
  arena_free(&a);
  printf("ok\n");
}

static void test_strdup(void) {
  printf("  strdup copies text and handles NULL and empty... ");
  static const char text[] = "hello, arena";
  arena_t a = {0};
  char *copy = arena_strdup(&a, text);
  assert(copy);
  assert(copy != text);
  assert(strcmp(copy, text) == 0);
  assert(arena_strdup(&a, NULL) == NULL);
  char *empty = arena_strdup(&a, "");
  assert(empty && empty[0] == '\0');
  arena_free(&a);
  printf("ok\n");
}

static void test_chunks(void) {
  printf("  filling more than one chunk works... ");
  arena_t a = {0};
  char *first = arena_alloc(&a, 1);
  assert(first);
  assert(arena_capacity(&a) == ARENA_CHUNK_SIZE);
  char *second = arena_alloc(&a, 1);
  assert(second);
  assert(arena_capacity(&a) == ARENA_CHUNK_SIZE);
  // What is left of the first chunk cannot hold a full payload.
  char *third = arena_alloc(&a, ARENA_CHUNK_SIZE);
  assert(third);
  assert(arena_capacity(&a) == 2 * ARENA_CHUNK_SIZE);
  memset(third, 0x5a, ARENA_CHUNK_SIZE);
  assert((unsigned char)third[0] == 0x5a);
  assert((unsigned char)third[ARENA_CHUNK_SIZE - 1] == 0x5a);
  arena_free(&a);
  printf("ok\n");
}

static void test_reuse(void) {
  printf("  a reset reuses chunks without growing... ");
  arena_t a = {0};
  for (int i = 0; i < 3; i++) {
    char *p = arena_alloc(&a, ARENA_CHUNK_SIZE);
    assert(p);
    memset(p, i, ARENA_CHUNK_SIZE);
  }
  size_t capacity = arena_capacity(&a);
  assert(capacity == 3 * ARENA_CHUNK_SIZE);
  arena_reset(&a);
  for (int i = 0; i < 3; i++) {
    char *p = arena_alloc(&a, ARENA_CHUNK_SIZE);
    assert(p);
    memset(p, i, ARENA_CHUNK_SIZE);
  }
  assert(arena_capacity(&a) == capacity);
  arena_free(&a);
  printf("ok\n");
}

static void test_oversize(void) {
  printf("  oversize requests get their own chunk... ");
  arena_t a = {0};
  size_t before = arena_capacity(&a);
  size_t size = 3 * ARENA_CHUNK_SIZE;
  unsigned char *p = arena_alloc(&a, size);
  assert(p);
  assert(arena_capacity(&a) == before + size);
  memset(p, 0x7f, size);
  assert(p[0] == 0x7f);
  assert(p[size - 1] == 0x7f);
  arena_reset(&a);
  assert(arena_capacity(&a) == before);
  arena_free(&a);
  printf("ok\n");
}

// An oversize request between small ones must not leave the small ones on a
// fresh chunk each cycle: the capacity after every reset stays the same.
static void test_mixed_sizes(void) {
  printf("  oversize requests do not grow the standard chunks... ");
  arena_t a = {0};
  size_t settled = 0;
  for (int cycle = 0; cycle < 8; cycle++) {
    assert(arena_alloc(&a, 100));
    assert(arena_alloc(&a, 2 * ARENA_CHUNK_SIZE));
    for (int i = 0; i < 40; i++)
      assert(arena_alloc(&a, 1000));
    arena_reset(&a);
    if (cycle == 1)
      settled = arena_capacity(&a);
    else if (cycle > 1)
      assert(arena_capacity(&a) == settled);
  }
  assert(settled == 2 * ARENA_CHUNK_SIZE);
  arena_free(&a);
  printf("ok\n");
}

// A reset releases standard chunks the cycle before it did not reach.
static void test_shrink(void) {
  printf("  a smaller cycle releases unused chunks... ");
  arena_t a = {0};
  for (int i = 0; i < 3; i++)
    assert(arena_alloc(&a, ARENA_CHUNK_SIZE));
  arena_reset(&a);
  assert(arena_capacity(&a) == 3 * ARENA_CHUNK_SIZE);
  assert(arena_alloc(&a, 100));
  arena_reset(&a);
  assert(arena_capacity(&a) == ARENA_CHUNK_SIZE);
  arena_reset(&a);
  assert(arena_capacity(&a) == ARENA_CHUNK_SIZE);
  // A cycle that allocates nothing after a large one also shrinks.
  for (int i = 0; i < 3; i++)
    assert(arena_alloc(&a, ARENA_CHUNK_SIZE));
  arena_reset(&a);
  assert(arena_capacity(&a) == 3 * ARENA_CHUNK_SIZE);
  arena_reset(&a);
  assert(arena_capacity(&a) == ARENA_CHUNK_SIZE);
  arena_free(&a);
  printf("ok\n");
}

static void test_bad_sizes(void) {
  printf("  zero and overflowing sizes return NULL... ");
  arena_t a = {0};
  assert(arena_alloc(&a, 0) == NULL);
  assert(arena_alloc(&a, SIZE_MAX) == NULL);
  char *p = arena_alloc(&a, 16);
  assert(p);
  memset(p, 1, 16);
  assert((unsigned char)p[0] == 1);
  arena_free(&a);
  printf("ok\n");
}

static void test_free(void) {
  printf("  free empties the arena and it can be reused... ");
  arena_t a = {0};
  assert(arena_alloc(&a, ARENA_CHUNK_SIZE));
  assert(arena_alloc(&a, ARENA_CHUNK_SIZE));
  assert(arena_capacity(&a) == 2 * ARENA_CHUNK_SIZE);
  arena_free(&a);
  assert(arena_capacity(&a) == 0);
  char *p = arena_alloc(&a, 32);
  assert(p);
  assert(arena_capacity(&a) == ARENA_CHUNK_SIZE);
  memset(p, 3, 32);
  assert((unsigned char)p[0] == 3);
  arena_free(&a);
  printf("ok\n");
}

static void test_poison(void) {
  printf("  a dropped allocation is poisoned");
#if ARENA_HAVE_ASAN
  printf("... ");
  fflush(stdout);
  pid_t pid = fork();
  assert(pid >= 0);
  if (pid == 0) {
    // The ASan report is the expected outcome; keep it out of the test log.
    int null_fd = open("/dev/null", O_WRONLY);
    if (null_fd >= 0)
      dup2(null_fd, STDERR_FILENO);
    arena_t a = {0};
    char *text = arena_strdup(&a, "discarded");
    if (!text)
      _exit(2); // setup failed; must not count as the expected ASan report
    arena_reset(&a);
    volatile char byte = text[0];
    (void)byte;
    arena_free(&a);
    _exit(0);
  }
  int status = 0;
  assert(waitpid(pid, &status, 0) == pid);
  assert(!(WIFEXITED(status) &&
           (WEXITSTATUS(status) == 0 || WEXITSTATUS(status) == 2)));
  printf("ok\n");
#else
  printf("... skipped (built without AddressSanitizer)\n");
#endif
}

int main(void) {
  printf("=== arena Tests ===\n\n");

  test_alignment();
  test_strdup();
  test_chunks();
  test_reuse();
  test_oversize();
  test_mixed_sizes();
  test_shrink();
  test_bad_sizes();
  test_free();
  test_poison();

  printf("\nAll arena tests passed\n");
  return 0;
}
