/* Internal fixed-counter controls. Fresh process per scenario; no interpose.
 * Build: clang -std=c11 -O2 -Wall -Wextra -Werror -Wno-unused-function
 * -fno-builtin np_unit.c -o np_unit. This tests accounting, not interception.
 */
#define NP_NO_INTERPOSE
#include "np_interpose.c"
#include <assert.h>
#include <pthread.h>
#include <string.h>

static void *concurrent(void *argument) {
    (void)argument;
    for (size_t i = 0; i < 10000; ++i) {
        uint64_t phase = enter(NP_MALLOC, 3);
        leave(phase, NP_MALLOC, i % 2 == 0);
    }
    return 0;
}

int main(int argc, char **argv) {
    assert(argc == 2 && np_lock_free() && np_version() == 1 && np_state_identity());
    assert(np_endpoint_name(NP_ENDPOINT_COUNT) == 0);
    struct np_snapshot result = {0};
    if (!strcmp(argv[1], "overflow")) {
        atomic_store(&counters[0][0].calls, UINT64_MAX);
        uint64_t phase = enter(NP_MALLOC, 3);
        leave(phase, NP_MALLOC, 0);
        assert(!np_snapshot(&result, sizeof(result)));
        assert(result.invalid_flags == NP_INVALID_OVERFLOW);
        assert(result.counters[0][0].calls == UINT64_MAX);
    } else if (!strcmp(argv[1], "product")) {
        uint64_t phase = enter_product(NP_CALLOC, SIZE_MAX, 2);
        leave(phase, NP_CALLOC, 1);
        assert(!np_snapshot(&result, sizeof(result)));
        assert(result.invalid_flags == NP_INVALID_OVERFLOW);
        assert(result.counters[0][NP_CALLOC].requested_bytes == UINT64_MAX);
    } else if (!strcmp(argv[1], "collision")) {
        uint64_t phase = enter(NP_MALLOC, 3);
        assert(!np_transition(0, 1));
        assert(!np_snapshot(&result, sizeof(result)));
        leave(phase, NP_MALLOC, 0);
        assert(!np_snapshot(&result, sizeof(result)));
        assert(result.invalid_flags == (NP_INVALID_TRANSITION | NP_INVALID_SNAPSHOT));
    } else if (!strcmp(argv[1], "wrong_order")) {
        assert(!np_transition(1, 2));
        assert(!np_transition(0, 2));
        assert(!np_snapshot(&result, sizeof(result) - 1));
        assert(!np_snapshot(&result, sizeof(result)));
        assert(result.invalid_flags == (NP_INVALID_TRANSITION | NP_INVALID_SNAPSHOT));
    } else if (!strcmp(argv[1], "sealed")) {
        assert(np_transition(0, 1) && np_transition(1, 2));
        assert(np_snapshot(&result, sizeof(result)));
        uint64_t phase = enter_product(NP_CALLOC, SIZE_MAX, SIZE_MAX);
        assert(phase == NP_SEALED);
        leave(phase, NP_CALLOC, 1);
        assert(atomic_load(&invalid) == 0 && atomic_load(&counters[1][NP_CALLOC].calls) == 0);
        assert(!np_snapshot(&result, sizeof(result)));
    } else if (!strcmp(argv[1], "concurrent")) {
        pthread_t threads[4];
        assert(np_transition(0, 1));
        for (size_t i = 0; i < 4; ++i) assert(pthread_create(&threads[i], 0, concurrent, 0) == 0);
        for (size_t i = 0; i < 4; ++i) assert(pthread_join(threads[i], 0) == 0);
        assert(np_transition(1, 2) && np_snapshot(&result, sizeof(result)));
        assert(result.counters[1][NP_MALLOC].calls == 40000);
        assert(result.counters[1][NP_MALLOC].requested_bytes == 120000);
        assert(result.counters[1][NP_MALLOC].failures == 20000);
    } else if (!strcmp(argv[1], "nested")) {
        assert(np_transition(0, 1));
        uint64_t a = enter(NP_MALLOC, 7), b = enter(NP_ZONE_MALLOC, 7);
        leave(b, NP_ZONE_MALLOC, 0);
        leave(a, NP_MALLOC, 0);
        assert(np_transition(1, 2) && np_snapshot(&result, sizeof(result)));
        assert(result.counters[1][NP_MALLOC].calls == 1 && result.counters[1][NP_ZONE_MALLOC].calls == 1);
        assert(result.transitions == 14 && result.phase_before_seal == 2);
    } else return 2;
    return 0;
}
