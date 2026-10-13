/* Fixed-state native endpoint diagnostic; build as a separate macOS dylib.
 * Apple's interpose-section mechanism forwards calls from this image to the
 * original symbol. Public SDKs need not ship dyld-interposing.h.
 * Hooks never use allocation, TLS, formatting, locks, lookup or callbacks
 * except forwarding the original endpoint itself. Nested endpoints are kept.
 * This is a lock-free observation mechanism, not a wait-free timing promise.
 */
#include "np_api.h"
#include <limits.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <malloc/malloc.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

#if !defined(__APPLE__) || !defined(__LP64__) || defined(__arm64e__)
#error "The diagnostic supports ordinary 64-bit macOS, not arm64e pointer authentication"
#endif
_Static_assert(ATOMIC_LLONG_LOCK_FREE == 2 && ATOMIC_LONG_LOCK_FREE == 2,
               "64-bit atomics must always be lock-free");
_Static_assert(sizeof(uint64_t) == 8 && sizeof(size_t) == 8, "64-bit ABI required");
_Static_assert(sizeof(struct np_counter) == 24, "counter ABI changed");
_Static_assert(sizeof(struct np_snapshot) == 1584, "snapshot ABI changed");
_Static_assert(NP_VM_DEALLOCATE + 1 == NP_ENDPOINT_COUNT, "endpoint ABI changed");

struct atomic_counter { _Atomic uint64_t calls, bytes, failures; };
/* Low two bits are phase; upper bits count all in-flight nested hooks. A CAS
 * transition requires exactly the old phase (zero hooks), eliminating the
 * enter/end/snapshot ABA race of independent phase and in-flight counters.
 */
static _Atomic uint64_t state;
static _Atomic uint64_t invalid;
static _Atomic uint64_t transitions;
static struct atomic_counter counters[NP_PHASE_COUNT][NP_ENDPOINT_COUNT];

static void invalidate(uint64_t flag) {
    atomic_fetch_or_explicit(&invalid, flag, memory_order_relaxed);
}

static void add(_Atomic uint64_t *value, uint64_t amount) {
    uint64_t old = atomic_load_explicit(value, memory_order_relaxed);
    for (;;) {
        uint64_t next = old > UINT64_MAX - amount ? UINT64_MAX : old + amount;
        if (atomic_compare_exchange_weak_explicit(value, &old, next,
                memory_order_relaxed, memory_order_relaxed)) {
            if (next == UINT64_MAX && amount > UINT64_MAX - old)
                invalidate(NP_INVALID_OVERFLOW);
            return;
        }
    }
}

/* Returns SEALED for an untracked post-cutoff or invalid-overflow call. */
static uint64_t enter(enum np_endpoint endpoint, uint64_t bytes) {
    uint64_t old = atomic_load_explicit(&state, memory_order_acquire);
    for (;;) {
        if ((old & 3) == NP_SEALED) return NP_SEALED;
        if (old > UINT64_MAX - 4) {
            invalidate(NP_INVALID_OVERFLOW);
            return NP_SEALED;
        }
        if (atomic_compare_exchange_weak_explicit(&state, &old, old + 4,
                memory_order_acq_rel, memory_order_acquire)) {
            uint64_t phase = old & 3;
            add(&counters[phase][endpoint].calls, 1);
            add(&counters[phase][endpoint].bytes, bytes);
            return phase;
        }
    }
}

static void leave(uint64_t phase, enum np_endpoint endpoint, int failed) {
    if (phase == NP_SEALED) return;
    if (failed) add(&counters[phase][endpoint].failures, 1);
    atomic_fetch_sub_explicit(&state, 4, memory_order_release);
}

static uint64_t product(size_t count, size_t size) {
    if (size && count > UINT64_MAX / size) {
        invalidate(NP_INVALID_OVERFLOW);
        return UINT64_MAX;
    }
    return count * size;
}

static uint64_t enter_product(enum np_endpoint endpoint, size_t count, size_t size) {
    uint64_t phase = enter(endpoint, 0);
    if (phase != NP_SEALED) add(&counters[phase][endpoint].bytes, product(count, size));
    return phase;
}

uint64_t np_version(void) { return NP_ABI_VERSION; }
uint64_t np_state_identity(void) { return (uint64_t)(uintptr_t)&state; }
int np_lock_free(void) { return __atomic_always_lock_free(8, 0); }

int np_transition(uint64_t expected, uint64_t next) {
    if (!((expected == NP_SETUP && next == NP_CHARGED) ||
          (expected == NP_CHARGED && next == NP_TEARDOWN)) ||
        !atomic_compare_exchange_strong_explicit(&state, &expected, next,
            memory_order_acq_rel, memory_order_acquire)) {
        invalidate(NP_INVALID_TRANSITION);
        return 0;
    }
    atomic_fetch_or_explicit(&transitions, UINT64_C(1) << next, memory_order_release);
    return 1;
}

int np_snapshot(struct np_snapshot *out, uint64_t bytes) {
    if (!out || bytes != sizeof(*out)) {
        invalidate(NP_INVALID_SNAPSHOT);
        return 0;
    }
    uint64_t expected = atomic_load_explicit(&state, memory_order_acquire);
    uint64_t before = expected;
    if (expected >= NP_SEALED ||
        !atomic_compare_exchange_strong_explicit(&state, &expected, NP_SEALED,
            memory_order_acq_rel, memory_order_acquire)) {
        invalidate(NP_INVALID_SNAPSHOT);
        return 0;
    }
    atomic_fetch_or_explicit(&transitions, UINT64_C(1) << NP_SEALED, memory_order_release);
    out->abi_version = NP_ABI_VERSION;
    out->struct_bytes = sizeof(*out);
    out->endpoint_count = NP_ENDPOINT_COUNT;
    out->phase_count = NP_PHASE_COUNT;
    out->final_phase = NP_SEALED;
    out->inflight = 0;
    out->phase_before_seal = before;
    out->invalid_flags = atomic_load_explicit(&invalid, memory_order_acquire);
    out->transitions = atomic_load_explicit(&transitions, memory_order_acquire);
    for (size_t p = 0; p < NP_PHASE_COUNT; ++p)
        for (size_t e = 0; e < NP_ENDPOINT_COUNT; ++e) {
            out->counters[p][e].calls = atomic_load_explicit(&counters[p][e].calls, memory_order_relaxed);
            out->counters[p][e].requested_bytes = atomic_load_explicit(&counters[p][e].bytes, memory_order_relaxed);
            out->counters[p][e].failures = atomic_load_explicit(&counters[p][e].failures, memory_order_relaxed);
        }
    return out->invalid_flags == 0 && out->transitions == ((UINT64_C(1) << (before + 1)) - 2 + 8);
}

const char *np_endpoint_name(uint64_t index) {
    static const char *const names[NP_ENDPOINT_COUNT] = {
        "malloc", "calloc", "realloc", "free", "posix_memalign", "aligned_alloc", "valloc",
        "malloc_zone_malloc", "malloc_zone_calloc", "malloc_zone_realloc", "malloc_zone_free",
        "malloc_zone_memalign", "malloc_zone_valloc", "mmap", "munmap", "mach_vm_allocate",
        "mach_vm_map", "mach_vm_deallocate", "vm_allocate", "vm_map", "vm_deallocate"
    };
    return index < NP_ENDPOINT_COUNT ? names[index] : 0;
}

#ifdef NP_NO_INTERPOSE
#define INSTALL(replacement, original)
#else
/* The two-pointer loader record is described by Apple's primary header:
 * github.com/apple-oss-distributions/dyld/blob/
 * fd8d0c4d52320ebf64db34f3cb280310d905c5ae/include/mach-o/dyld-interposing.h
 * Authenticated-pointer targets are deliberately rejected above.
 */
#define INSTALL(replacement_fn, original_fn) \
    __attribute__((used, section("__DATA,__interpose"))) \
    static const struct { const void *replacement; const void *original; } \
    np_binding_##original_fn = { (const void *)&replacement_fn, (const void *)&original_fn };
#endif

#define POINTER_HOOK(name, endpoint, signature, args, bytes) \
    static void *probe_##name signature { \
        uint64_t phase = enter(endpoint, (bytes)); \
        void *result = name args; \
        leave(phase, endpoint, result == 0); \
        return result; \
    } \
    INSTALL(probe_##name, name)

POINTER_HOOK(malloc, NP_MALLOC, (size_t size), (size), size)
POINTER_HOOK(realloc, NP_REALLOC, (void *pointer, size_t size), (pointer, size), size)
POINTER_HOOK(aligned_alloc, NP_ALIGNED_ALLOC, (size_t alignment, size_t size), (alignment, size), size)
POINTER_HOOK(valloc, NP_VALLOC, (size_t size), (size), size)
POINTER_HOOK(malloc_zone_malloc, NP_ZONE_MALLOC, (malloc_zone_t *zone, size_t size), (zone, size), size)
POINTER_HOOK(malloc_zone_realloc, NP_ZONE_REALLOC, (malloc_zone_t *zone, void *pointer, size_t size), (zone, pointer, size), size)
POINTER_HOOK(malloc_zone_memalign, NP_ZONE_MEMALIGN, (malloc_zone_t *zone, size_t alignment, size_t size), (zone, alignment, size), size)
POINTER_HOOK(malloc_zone_valloc, NP_ZONE_VALLOC, (malloc_zone_t *zone, size_t size), (zone, size), size)

static void *probe_calloc(size_t count, size_t size) {
    uint64_t phase = enter_product(NP_CALLOC, count, size);
    void *result = calloc(count, size);
    leave(phase, NP_CALLOC, result == 0);
    return result;
}
INSTALL(probe_calloc, calloc)
static void *probe_malloc_zone_calloc(malloc_zone_t *zone, size_t count, size_t size) {
    uint64_t phase = enter_product(NP_ZONE_CALLOC, count, size);
    void *result = malloc_zone_calloc(zone, count, size);
    leave(phase, NP_ZONE_CALLOC, result == 0);
    return result;
}
INSTALL(probe_malloc_zone_calloc, malloc_zone_calloc)

static void probe_free(void *pointer) {
    uint64_t phase = enter(NP_FREE, 0);
    free(pointer);
    leave(phase, NP_FREE, 0);
}
INSTALL(probe_free, free)
static void probe_malloc_zone_free(malloc_zone_t *zone, void *pointer) {
    uint64_t phase = enter(NP_ZONE_FREE, 0);
    malloc_zone_free(zone, pointer);
    leave(phase, NP_ZONE_FREE, 0);
}
INSTALL(probe_malloc_zone_free, malloc_zone_free)
static int probe_posix_memalign(void **pointer, size_t alignment, size_t size) {
    uint64_t phase = enter(NP_POSIX_MEMALIGN, size);
    int result = posix_memalign(pointer, alignment, size);
    leave(phase, NP_POSIX_MEMALIGN, result != 0);
    return result;
}
INSTALL(probe_posix_memalign, posix_memalign)
static void *probe_mmap(void *address, size_t size, int protection, int flags, int fd, off_t offset) {
    uint64_t phase = enter(NP_MMAP, size);
    void *result = mmap(address, size, protection, flags, fd, offset);
    leave(phase, NP_MMAP, result == MAP_FAILED);
    return result;
}
INSTALL(probe_mmap, mmap)
static int probe_munmap(void *address, size_t size) {
    uint64_t phase = enter(NP_MUNMAP, size);
    int result = munmap(address, size);
    leave(phase, NP_MUNMAP, result != 0);
    return result;
}
INSTALL(probe_munmap, munmap)

#define MACH_HOOK(name, endpoint, signature, args) \
    static kern_return_t probe_##name signature { \
        uint64_t phase = enter(endpoint, size); \
        kern_return_t result = name args; \
        leave(phase, endpoint, result != KERN_SUCCESS); \
        return result; \
    } \
    INSTALL(probe_##name, name)
MACH_HOOK(mach_vm_allocate, NP_MACH_VM_ALLOCATE,
    (vm_map_t task, mach_vm_address_t *address, mach_vm_size_t size, int flags), (task, address, size, flags))
MACH_HOOK(mach_vm_deallocate, NP_MACH_VM_DEALLOCATE,
    (vm_map_t task, mach_vm_address_t address, mach_vm_size_t size), (task, address, size))
MACH_HOOK(vm_allocate, NP_VM_ALLOCATE,
    (vm_map_t task, vm_address_t *address, vm_size_t size, int flags), (task, address, size, flags))
MACH_HOOK(vm_deallocate, NP_VM_DEALLOCATE,
    (vm_map_t task, vm_address_t address, vm_size_t size), (task, address, size))
MACH_HOOK(mach_vm_map, NP_MACH_VM_MAP,
    (vm_map_t task, mach_vm_address_t *address, mach_vm_size_t size, mach_vm_offset_t mask,
     int flags, mem_entry_name_port_t object, memory_object_offset_t offset, boolean_t copy,
     vm_prot_t current, vm_prot_t maximum, vm_inherit_t inheritance),
    (task, address, size, mask, flags, object, offset, copy, current, maximum, inheritance))
MACH_HOOK(vm_map, NP_VM_MAP,
    (vm_map_t task, vm_address_t *address, vm_size_t size, vm_address_t mask,
     int flags, mem_entry_name_port_t object, vm_offset_t offset, boolean_t copy,
     vm_prot_t current, vm_prot_t maximum, vm_inherit_t inheritance),
    (task, address, size, mask, flags, object, offset, copy, current, maximum, inheritance))
