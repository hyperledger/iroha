/* Experimental macOS named-endpoint observation ABI. Not a memory certificate.
 * Compile with Xcode clang, C11, on 64-bit macOS. No environment is read here.
 * One process owns one state in the dylib; there is no reset or thread filter.
 */
#ifndef PARLIAMENT_NATIVE_PROBE_API_H
#define PARLIAMENT_NATIVE_PROBE_API_H
#include <stddef.h>
#include <stdint.h>

#define NP_ABI_VERSION UINT64_C(1)
#define NP_PHASE_COUNT 3
#define NP_ENDPOINT_COUNT 21
#define NP_SETUP UINT64_C(0)
#define NP_CHARGED UINT64_C(1)
#define NP_TEARDOWN UINT64_C(2)
#define NP_SEALED UINT64_C(3)
#define NP_INVALID_OVERFLOW UINT64_C(1)
#define NP_INVALID_TRANSITION UINT64_C(2)
#define NP_INVALID_SNAPSHOT UINT64_C(4)

enum np_endpoint {
    NP_MALLOC, NP_CALLOC, NP_REALLOC, NP_FREE, NP_POSIX_MEMALIGN,
    NP_ALIGNED_ALLOC, NP_VALLOC, NP_ZONE_MALLOC, NP_ZONE_CALLOC,
    NP_ZONE_REALLOC, NP_ZONE_FREE, NP_ZONE_MEMALIGN, NP_ZONE_VALLOC,
    NP_MMAP, NP_MUNMAP, NP_MACH_VM_ALLOCATE, NP_MACH_VM_MAP,
    NP_MACH_VM_DEALLOCATE, NP_VM_ALLOCATE, NP_VM_MAP, NP_VM_DEALLOCATE
};

/* All fields are u64 and in the declared order: directly usable with repr(C).
 * Bytes are endpoint request arguments, including failed/realloc requests and
 * mapping-release sizes. Free has no size argument. They are NOT live bytes.
 * failures counts the endpoint's sentinel result: NULL for pointer-returning
 * allocators, MAP_FAILED for mmap, nonzero for POSIX/munmap, non-KERN_SUCCESS
 * for Mach. NULL for a zero-size allocation/realloc is implementation-defined
 * and is not necessarily a semantic allocation failure. No errno is accessed.
 */
struct np_counter { uint64_t calls, requested_bytes, failures; };
struct np_snapshot {
    uint64_t abi_version, struct_bytes, endpoint_count, phase_count;
    uint64_t final_phase, inflight, invalid_flags, transitions, phase_before_seal;
    struct np_counter counters[NP_PHASE_COUNT][NP_ENDPOINT_COUNT];
};

uint64_t np_version(void);
uint64_t np_state_identity(void); /* Process-local address; do not archive it. */
int np_lock_free(void);
/* Only 0->1 and 1->2, with no native hook in flight. Failure invalidates receipt.
 * Mark before ACTIVE=true and after ACTIVE=false; snapshot after worker join.
 */
int np_transition(uint64_t expected, uint64_t next);
/* Seals 0/1/2->3 with no in-flight hook, then copies immutable phase counters.
 * Phase 0 means no charged call; phase 1 is an incomplete/terminal charged
 * interval, e.g. an OOM exit. Only phase 2 denotes an ordinary completed call.
 * Marker/snapshot API calls must be serialized by the owning lifecycle.
 * Hooks after the seal forward normally but are outside the observation.
 * Return 1 means sealed and no invalid flag, NOT an ordinary completed call.
 * Even invalid sealed data is copied. Expected transition masks are 8/10/14
 * for phase_before_seal 0/1/2; callers must check their case's required phase.
 * Caller supplies a live writable struct; bytes must equal sizeof the struct.
 */
int np_snapshot(struct np_snapshot *out, uint64_t bytes);
const char *np_endpoint_name(uint64_t index); /* Static strings; outside hooks. */
#endif
