/* Fresh-process positive/negative controls for np_interpose.c.
 * Xcode clang C11, -fno-builtin, linked to the one interposer dylib.
 * Usage: np_controls ENDPOINT|empty|outside|unadmitted|terminal|failure
 * Each invocation seals before printing JSON; no formatting occurs in hooks.
 */
#include "np_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc/malloc.h>
#include <sys/mman.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

static void touch(void *pointer) {
    if (pointer) *(volatile unsigned char *)pointer = 23;
}

static int perform(unsigned endpoint, malloc_zone_t *zone, size_t page, mach_port_t task) {
    void *p = 0;
    switch (endpoint) {
        case NP_MALLOC: p = malloc(77); break;
        case NP_CALLOC: p = calloc(7, 11); break;
        case NP_REALLOC:
            p = malloc(19);
            if (!p) return 0;
            { void *q = realloc(p, 77); if (!q) { free(p); return 0; } p = q; }
            break;
        case NP_FREE: p = malloc(77); break;
        case NP_POSIX_MEMALIGN: if (posix_memalign(&p, 64, 128)) return 0; break;
        case NP_ALIGNED_ALLOC: p = aligned_alloc(64, 128); break;
        case NP_VALLOC: p = valloc(77); break;
        case NP_ZONE_MALLOC: p = malloc_zone_malloc(zone, 77); break;
        case NP_ZONE_CALLOC: p = malloc_zone_calloc(zone, 7, 11); break;
        case NP_ZONE_REALLOC:
            p = malloc_zone_malloc(zone, 19);
            if (!p) return 0;
            { void *q = malloc_zone_realloc(zone, p, 77); if (!q) { malloc_zone_free(zone, p); return 0; } p = q; }
            break;
        case NP_ZONE_FREE: p = malloc_zone_malloc(zone, 77); break;
        case NP_ZONE_MEMALIGN: p = malloc_zone_memalign(zone, 64, 128); break;
        case NP_ZONE_VALLOC: p = malloc_zone_valloc(zone, 77); break;
        case NP_MMAP:
        case NP_MUNMAP:
            p = mmap(0, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
            if (p == MAP_FAILED) return 0;
            touch(p);
            return munmap(p, page) == 0;
        case NP_MACH_VM_ALLOCATE:
        case NP_MACH_VM_MAP:
        case NP_MACH_VM_DEALLOCATE: {
            mach_vm_address_t address = 0;
            kern_return_t result = endpoint == NP_MACH_VM_MAP
                ? mach_vm_map(task, &address, page, 0, VM_FLAGS_ANYWHERE, MACH_PORT_NULL,
                              0, FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_ALL, VM_INHERIT_NONE)
                : mach_vm_allocate(task, &address, page, VM_FLAGS_ANYWHERE);
            if (result != KERN_SUCCESS) return 0;
            touch((void *)(uintptr_t)address);
            return mach_vm_deallocate(task, address, page) == KERN_SUCCESS;
        }
        case NP_VM_ALLOCATE:
        case NP_VM_MAP:
        case NP_VM_DEALLOCATE: {
            vm_address_t address = 0;
            kern_return_t result = endpoint == NP_VM_MAP
                ? vm_map(task, &address, page, 0, VM_FLAGS_ANYWHERE, MACH_PORT_NULL,
                         0, FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_ALL, VM_INHERIT_NONE)
                : vm_allocate(task, &address, page, VM_FLAGS_ANYWHERE);
            if (result != KERN_SUCCESS) return 0;
            touch((void *)(uintptr_t)address);
            return vm_deallocate(task, address, page) == KERN_SUCCESS;
        }
        default: return 0;
    }
    if (!p) return 0;
    touch(p);
    if (endpoint >= NP_ZONE_MALLOC && endpoint <= NP_ZONE_VALLOC) malloc_zone_free(zone, p);
    else free(p);
    return 1;
}

static uint64_t phase_calls(const struct np_snapshot *snapshot, size_t phase) {
    uint64_t total = 0;
    for (size_t i = 0; i < NP_ENDPOINT_COUNT; ++i) total += snapshot->counters[phase][i].calls;
    return total;
}

int main(int argc, char **argv) {
    if (argc != 2 || !strcmp(argv[1], "--help")) {
        puts("usage: np_controls ENDPOINT|empty|outside|unadmitted|terminal|failure");
        return argc == 2 ? 0 : 2;
    }
    int selected = -1;
    for (unsigned i = 0; i < NP_ENDPOINT_COUNT; ++i)
        if (!strcmp(argv[1], np_endpoint_name(i))) selected = (int)i;
    int empty = !strcmp(argv[1], "empty"), outside = !strcmp(argv[1], "outside");
    int unadmitted = !strcmp(argv[1], "unadmitted"), terminal = !strcmp(argv[1], "terminal");
    int failure = !strcmp(argv[1], "failure");
    if (selected < 0 && !empty && !outside && !unadmitted && !terminal && !failure) return 2;
    if (np_version() != NP_ABI_VERSION || !np_lock_free() || !np_state_identity()) return 3;
    /* Resolve control prerequisites during setup; this is not a cold-proof run. */
    malloc_zone_t *zone = malloc_default_zone();
    size_t page = (size_t)getpagesize();
    mach_port_t task = mach_task_self();
    int ok = 1;
    if (outside) ok &= perform(NP_MALLOC, zone, page, task);
    if (!unadmitted) ok &= np_transition(NP_SETUP, NP_CHARGED);
    if (selected >= 0) ok &= perform((unsigned)selected, zone, page, task);
    if (terminal) ok &= perform(NP_MALLOC, zone, page, task);
    if (failure) {
        void *p = mmap(0, 0, PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0);
        ok &= p == MAP_FAILED;
    }
    if (!unadmitted && !terminal) ok &= np_transition(NP_CHARGED, NP_TEARDOWN);
    if (outside) ok &= perform(NP_MALLOC, zone, page, task);
    struct np_snapshot snapshot = {0};
    ok &= np_snapshot(&snapshot, sizeof(snapshot));
    if (selected >= 0) ok &= snapshot.counters[NP_CHARGED][selected].calls > 0;
    if (empty || outside || unadmitted) ok &= phase_calls(&snapshot, NP_CHARGED) == 0;
    if (outside) ok &= snapshot.counters[NP_SETUP][NP_MALLOC].calls > 0
                       && snapshot.counters[NP_TEARDOWN][NP_MALLOC].calls > 0;
    if (failure) ok &= snapshot.counters[NP_CHARGED][NP_MMAP].failures == 1;
    if (terminal) ok &= snapshot.phase_before_seal == NP_CHARGED
                        && snapshot.counters[NP_CHARGED][NP_MALLOC].calls > 0;
    if (unadmitted) ok &= snapshot.phase_before_seal == NP_SETUP;
    /* Post-seal activity must not mutate retained counters. Counter internals
     * are opaque; a second snapshot is deliberately not an allowed API call. */
    printf("{\"case\":\"%s\",\"control_passed\":%s,\"abi_version\":%llu,"
           "\"phase_before_seal\":%llu,\"invalid_flags\":%llu,\"transitions\":%llu,"
           "\"profile_qualified\":false,\"endpoints\":[", argv[1], ok ? "true" : "false",
           (unsigned long long)snapshot.abi_version, (unsigned long long)snapshot.phase_before_seal,
           (unsigned long long)snapshot.invalid_flags, (unsigned long long)snapshot.transitions);
    for (size_t e = 0; e < NP_ENDPOINT_COUNT; ++e) {
        printf("%s{\"name\":\"%s\",\"phases\":[", e ? "," : "", np_endpoint_name(e));
        for (size_t p = 0; p < NP_PHASE_COUNT; ++p) {
            struct np_counter c = snapshot.counters[p][e];
            printf("%s[%llu,%llu,%llu]", p ? "," : "", (unsigned long long)c.calls,
                   (unsigned long long)c.requested_bytes, (unsigned long long)c.failures);
        }
        printf("]}");
    }
    puts("]}");
    return ok ? 0 : 1;
}
