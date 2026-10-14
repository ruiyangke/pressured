#ifndef PRESSURED_ARENA_H
#define PRESSURED_ARENA_H

#include <stddef.h>

// Payload of a standard chunk. A request that does not fit in one gets its own
// oversize chunk instead.
#define ARENA_CHUNK_SIZE ((size_t)32 * 1024)

// True when built with AddressSanitizer. The arena then poisons payload bytes
// between hand-outs, so a read of memory dropped by arena_reset() is reported.
#if defined(__SANITIZE_ADDRESS__)
#define ARENA_HAVE_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define ARENA_HAVE_ASAN 1
#endif
#endif
#ifndef ARENA_HAVE_ASAN
#define ARENA_HAVE_ASAN 0
#endif

typedef struct arena_chunk arena_chunk_t;

// A zero-initialized arena_t is ready to use. Chunks are never moved, so
// pointers stay valid until arena_reset() or arena_free(), whichever comes
// first.
typedef struct {
  arena_chunk_t *head;     // first standard chunk, NULL when empty
  arena_chunk_t *current;  // standard chunk being filled
  arena_chunk_t *oversize; // one chunk per oversize request
} arena_t;

// Memory aligned to _Alignof(max_align_t). NULL for size == 0 and on
// out-of-memory, including a size whose header or alignment would overflow.
void *arena_alloc(arena_t *a, size_t size);

// Copies s including its terminator, without alignment padding. NULL for NULL s
// and for out-of-memory.
char *arena_strdup(arena_t *a, const char *s);

// Forget every allocation. Standard chunks used since the previous reset are
// kept for reuse; standard chunks left unused and all oversize chunks are
// freed. The arena therefore holds what the last cycle needed: repeating the
// same allocations adds no chunks, and a smaller cycle releases memory.
void arena_reset(arena_t *a);

// Free every chunk. The arena is empty and reusable afterwards.
void arena_free(arena_t *a);

// Total payload bytes of all chunks currently held.
size_t arena_capacity(const arena_t *a);

#endif // PRESSURED_ARENA_H
