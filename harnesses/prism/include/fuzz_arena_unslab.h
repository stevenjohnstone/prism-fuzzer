#ifndef PRISM_FUZZ_ARENA_UNSLAB_H
#define PRISM_FUZZ_ARENA_UNSLAB_H

/*
 * When compiling Prism with -DPM_ARENA_INITIAL_SIZE=0 so every arena allocation
 * receives its own exact-sized heap block (giving ASan, MSan, LSan, and
 * PM_XALLOCATOR redzones and size checks around individual AST nodes and
 * buffers), turn pm_arena_reserve() into a no-op so callers do not pre-allocate
 * a shared bump slab in arena->current.
 */
#if defined(PM_ARENA_INITIAL_SIZE) && (PM_ARENA_INITIAL_SIZE == 0)
#  if defined(__has_include)
#    if __has_include("prism/internal/arena.h")
#      include "prism/internal/arena.h"
static inline void
pm_fuzz_arena_reserve_noop(pm_arena_t *arena, size_t capacity) {
    (void) arena;
    (void) capacity;
}
#      define pm_arena_reserve pm_fuzz_arena_reserve_noop
#    endif
#  endif
#endif

#endif
