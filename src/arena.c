#include "arena.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if ARENA_HAVE_ASAN
#include <sanitizer/asan_interface.h>
#define ARENA_POISON(ptr, size) ASAN_POISON_MEMORY_REGION((ptr), (size))
#define ARENA_UNPOISON(ptr, size) ASAN_UNPOISON_MEMORY_REGION((ptr), (size))
#else
#define ARENA_POISON(ptr, size) ((void)0)
#define ARENA_UNPOISON(ptr, size) ((void)0)
#endif

// The payload is a flexible array of max_align_t, so sizeof(arena_chunk_t) is a
// multiple of its alignment and a chunk's payload starts aligned.
struct arena_chunk {
  arena_chunk_t *next;
  size_t capacity; // payload bytes
  size_t used;     // payload bytes handed out
  max_align_t payload[];
};

// Allocate a chunk whose payload holds `payload` bytes. `payload` may be any
// nonzero size; NULL on overflow or out-of-memory.
static arena_chunk_t *chunk_new(size_t payload) {
  if (payload > SIZE_MAX - sizeof(arena_chunk_t))
    return NULL;
  arena_chunk_t *c = malloc(sizeof(arena_chunk_t) + payload);
  if (!c)
    return NULL;
  c->next = NULL;
  c->capacity = payload;
  c->used = 0;
  ARENA_POISON(c->payload, payload);
  return c;
}

static void chunks_free(arena_chunk_t *c) {
  while (c) {
    arena_chunk_t *next = c->next;
    ARENA_UNPOISON(c->payload, c->capacity);
    free(c);
    c = next;
  }
}

// Hand out `size` bytes from c, skipping alignment padding when `align` is set.
// NULL when the chunk has no room.
static void *chunk_bump(arena_chunk_t *c, size_t size, bool align) {
  size_t offset = c->used;
  if (align) {
    size_t misalign = offset % _Alignof(max_align_t);
    if (misalign)
      offset += _Alignof(max_align_t) - misalign;
  }
  if (offset > c->capacity || size > c->capacity - offset)
    return NULL;
  c->used = offset + size;
  return (char *)c->payload + offset;
}

static void *arena_alloc_impl(arena_t *a, size_t size, bool align) {
  if (!a || size == 0)
    return NULL;

  // A request larger than a standard chunk gets a chunk of its own, kept off
  // the fill path so the standard chunks after it are still reused.
  if (size > ARENA_CHUNK_SIZE) {
    arena_chunk_t *c = chunk_new(size);
    if (!c)
      return NULL;
    c->next = a->oversize;
    a->oversize = c;
    return chunk_bump(c, size, align);
  }

  // Standard chunks fill in list order: continue from `current` and move on to
  // chunks kept by an earlier reset before adding a new one at the tail.
  arena_chunk_t *tail = NULL;
  for (arena_chunk_t *c = a->current ? a->current : a->head; c;
       tail = c, c = c->next) {
    void *p = chunk_bump(c, size, align);
    if (p) {
      a->current = c;
      return p;
    }
  }

  arena_chunk_t *c = chunk_new(ARENA_CHUNK_SIZE);
  if (!c)
    return NULL;
  if (tail)
    tail->next = c;
  else
    a->head = c;
  a->current = c;
  return chunk_bump(c, size, align);
}

void *arena_alloc(arena_t *a, size_t size) {
  void *p = arena_alloc_impl(a, size, true);
  if (p)
    ARENA_UNPOISON(p, size);
  return p;
}

char *arena_strdup(arena_t *a, const char *s) {
  if (!s)
    return NULL;
  size_t length = strlen(s);
  if (length == SIZE_MAX)
    return NULL;
  size_t size = length + 1;
  char *copy = arena_alloc_impl(a, size, false);
  if (!copy)
    return NULL;
  ARENA_UNPOISON(copy, size);
  memcpy(copy, s, size);
  return copy;
}

void arena_reset(arena_t *a) {
  if (!a)
    return;
  chunks_free(a->oversize);
  a->oversize = NULL;
  // Chunks after `current` were not reached since the previous reset.
  if (a->current) {
    chunks_free(a->current->next);
    a->current->next = NULL;
  }
  for (arena_chunk_t *c = a->head; c; c = c->next) {
    c->used = 0;
    ARENA_POISON(c->payload, c->capacity);
  }
  a->current = a->head;
}

void arena_free(arena_t *a) {
  if (!a)
    return;
  chunks_free(a->head);
  chunks_free(a->oversize);
  a->head = NULL;
  a->current = NULL;
  a->oversize = NULL;
}

size_t arena_capacity(const arena_t *a) {
  size_t total = 0;
  if (!a)
    return 0;
  for (const arena_chunk_t *c = a->head; c; c = c->next)
    total += c->capacity;
  for (const arena_chunk_t *c = a->oversize; c; c = c->next)
    total += c->capacity;
  return total;
}
