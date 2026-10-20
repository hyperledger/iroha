// SPDX-License-Identifier: Apache-2.0
// Minimal, deterministic CUDA backend for Goldilocks FFT / IFFT / LDE.
// Architecture requirement: SM80+ (Ampere or newer).

#include <cuda_runtime.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <atomic>
#include <chrono>
#include <mutex>
#include <new>
#include <string.h>
#include <thread>
#include <unordered_map>
#include <vector>

#ifndef FASTPQ_CUDA_ARCH_MIN
#define FASTPQ_CUDA_ARCH_MIN 800
#endif

static constexpr auto FASTPQ_CUDA_COMMAND_TIMEOUT = std::chrono::seconds(120);
static constexpr size_t FASTPQ_CUDA_MAX_GRID_X = 0x7fffffffull;

// A failed CUDA completion may still own device and pinned-host buffers.
// Releasing those buffers would race the device, so every uncertain completion
// deliberately abandons them. Quarantine the backend after the first such
// event so no new dispatch can add another unreclaimable allocation; work that
// was already in flight remains subject to the same fail-closed handling.
static std::atomic<bool>& cuda_backend_quarantined() {
    static std::atomic<bool> quarantined{false};
    return quarantined;
}
static void quarantine_cuda_backend() {
    cuda_backend_quarantined().store(true, std::memory_order_release);
}

static bool cuda_backend_is_quarantined() {
    return cuda_backend_quarantined().load(std::memory_order_acquire);
}

static bool async_status_requires_abandon(cudaError_t status) {
    return status != cudaSuccess;
}

#if defined(__CUDA_ARCH__) && (__CUDA_ARCH__ < FASTPQ_CUDA_ARCH_MIN)
#error "fastpq_cuda requires SM80+ (compute capability 8.0 or newer)."
#endif

// -----------------------------------------------------------------------------.
// Field constants (Goldilocks prime: 2^64 - 2^32 + 1).
// -----------------------------------------------------------------------------.
static __device__ __constant__ uint64_t FIELD_MODULUS = 18446744069414584321ull;
static __device__ __constant__ uint64_t FOLD_CONST = 0x00000000FFFFFFFFull; // 2^32 - 1

#define POSEIDON_STATE_WIDTH 3u
#define POSEIDON_RATE 2u
#define POSEIDON_FULL_ROUNDS_HALF 4u
#define POSEIDON_PARTIAL_ROUNDS 57u
#define BN254_LIMBS 4u

static constexpr uint32_t GOLDILOCKS_TWO_ADICITY = 32u;
static constexpr uint32_t BN254_TWO_ADICITY = 28u;

static __device__ __constant__ uint64_t BN254_MODULUS[BN254_LIMBS] = {
    0x43e1f593f0000001ull,
    0x2833e84879b97091ull,
    0xb85045b68181585dull,
    0x30644e72e131a029ull,
};
static __device__ __constant__ uint64_t BN254_MODULUS_INV = 0xc2e1f593efffffffull;
static __device__ __constant__ uint64_t BN254_R2[BN254_LIMBS] = {
    0x1bb8e645ae216da7ull,
    0x53fe3ab1e35c59e3ull,
    0x8c49833d53bb8085ull,
    0x0216d0b17f4e44a5ull,
};

struct PoseidonSlice {
    uint32_t offset;
    uint32_t len;
};

struct Bn254Value {
    uint64_t limbs[BN254_LIMBS];
};

struct TransformWorkspace {
    uint64_t* dense;
    uint64_t* coeffs;
    uint64_t* evals;
    uint64_t* bn254_twiddles;
    uint64_t* bn254_coset;
    uint64_t* host_dense;
    uint64_t* host_coeffs;
    uint64_t* host_evals;
    uint64_t* host_bn254_twiddles;
    uint64_t* host_bn254_coset;
    size_t dense_capacity_bytes;
    size_t coeff_capacity_bytes;
    size_t eval_capacity_bytes;
    size_t bn254_twiddle_capacity_bytes;
    size_t bn254_coset_capacity_bytes;
    size_t host_dense_capacity_bytes;
    size_t host_coeff_capacity_bytes;
    size_t host_eval_capacity_bytes;
    size_t host_bn254_twiddle_capacity_bytes;
    size_t host_bn254_coset_capacity_bytes;
    cudaStream_t stream;
    cudaEvent_t event;
    bool stream_ready;
    bool event_ready;

    TransformWorkspace()
        : dense(nullptr),
          coeffs(nullptr),
          evals(nullptr),
          bn254_twiddles(nullptr),
          bn254_coset(nullptr),
          host_dense(nullptr),
          host_coeffs(nullptr),
          host_evals(nullptr),
          host_bn254_twiddles(nullptr),
          host_bn254_coset(nullptr),
          dense_capacity_bytes(0),
          coeff_capacity_bytes(0),
          eval_capacity_bytes(0),
          bn254_twiddle_capacity_bytes(0),
          bn254_coset_capacity_bytes(0),
          host_dense_capacity_bytes(0),
          host_coeff_capacity_bytes(0),
          host_eval_capacity_bytes(0),
          host_bn254_twiddle_capacity_bytes(0),
          host_bn254_coset_capacity_bytes(0),
          stream(nullptr),
          event(nullptr),
          stream_ready(false),
          event_ready(false) {}
};

struct AsyncDispatchBuffers {
    int device;
    uint64_t* dense;
    uint64_t* coeffs;
    uint64_t* evals;
    uint64_t* host_dense;
    uint64_t* host_coeffs;
    uint64_t* host_evals;
    size_t dense_capacity_bytes;
    size_t coeff_capacity_bytes;
    size_t eval_capacity_bytes;
    size_t host_dense_capacity_bytes;
    size_t host_coeff_capacity_bytes;
    size_t host_eval_capacity_bytes;
    cudaStream_t stream;
    bool stream_ready;

    explicit AsyncDispatchBuffers(int device_in)
        : device(device_in),
          dense(nullptr),
          coeffs(nullptr),
          evals(nullptr),
          host_dense(nullptr),
          host_coeffs(nullptr),
          host_evals(nullptr),
          dense_capacity_bytes(0),
          coeff_capacity_bytes(0),
          eval_capacity_bytes(0),
          host_dense_capacity_bytes(0),
          host_coeff_capacity_bytes(0),
          host_eval_capacity_bytes(0),
          stream(nullptr),
          stream_ready(false) {}
};

struct PendingTransform {
    int device;
    cudaEvent_t event;
    AsyncDispatchBuffers* buffers;
    void* staging_output;
    size_t output_byte_len;

    PendingTransform(
        int device_in,
        cudaEvent_t event_in,
        AsyncDispatchBuffers* buffers_in,
        void* staging_output_in,
        size_t output_byte_len_in
    )
        : device(device_in),
          event(event_in),
          buffers(buffers_in),
          staging_output(staging_output_in),
          output_byte_len(output_byte_len_in) {}
};

struct PoseidonWorkspace {
    uint64_t* payloads;
    PoseidonSlice* slices;
    uint64_t* states;
    uint64_t* hashes;
    uint64_t* bn254_round_constants;
    uint64_t* bn254_mds;
    uint64_t* host_payloads;
    PoseidonSlice* host_slices;
    uint64_t* host_states;
    uint64_t* host_hashes;
    uint64_t* host_bn254_round_constants;
    uint64_t* host_bn254_mds;
    size_t payload_capacity_bytes;
    size_t slice_capacity_bytes;
    size_t state_capacity_bytes;
    size_t hash_capacity_bytes;
    size_t bn254_round_capacity_bytes;
    size_t bn254_mds_capacity_bytes;
    size_t host_payload_capacity_bytes;
    size_t host_slice_capacity_bytes;
    size_t host_state_capacity_bytes;
    size_t host_hash_capacity_bytes;
    size_t host_bn254_round_capacity_bytes;
    size_t host_bn254_mds_capacity_bytes;
    cudaStream_t stream;
    cudaEvent_t event;
    bool stream_ready;
    bool event_ready;

    PoseidonWorkspace()
        : payloads(nullptr),
          slices(nullptr),
          states(nullptr),
          hashes(nullptr),
          bn254_round_constants(nullptr),
          bn254_mds(nullptr),
          host_payloads(nullptr),
          host_slices(nullptr),
          host_states(nullptr),
          host_hashes(nullptr),
          host_bn254_round_constants(nullptr),
          host_bn254_mds(nullptr),
          payload_capacity_bytes(0),
          slice_capacity_bytes(0),
          state_capacity_bytes(0),
          hash_capacity_bytes(0),
          bn254_round_capacity_bytes(0),
          bn254_mds_capacity_bytes(0),
          host_payload_capacity_bytes(0),
          host_slice_capacity_bytes(0),
          host_state_capacity_bytes(0),
          host_hash_capacity_bytes(0),
          host_bn254_round_capacity_bytes(0),
          host_bn254_mds_capacity_bytes(0),
          stream(nullptr),
          event(nullptr),
          stream_ready(false),
          event_ready(false) {}
};

static std::mutex& transform_workspace_mutex() {
    static std::mutex mutex;
    return mutex;
}

static std::unordered_map<int, TransformWorkspace>& transform_workspaces() {
    static auto* workspaces = new std::unordered_map<int, TransformWorkspace>();
    return *workspaces;
}

static std::mutex& async_dispatch_pool_mutex() {
    static std::mutex mutex;
    return mutex;
}

static std::unordered_map<int, std::vector<AsyncDispatchBuffers*>>& async_dispatch_pools() {
    static auto* pools = new std::unordered_map<int, std::vector<AsyncDispatchBuffers*>>();
    return *pools;
}

static std::mutex& poseidon_workspace_mutex() {
    static std::mutex mutex;
    return mutex;
}

static std::unordered_map<int, PoseidonWorkspace>& poseidon_workspaces() {
    static auto* workspaces = new std::unordered_map<int, PoseidonWorkspace>();
    return *workspaces;
}

// Call only after completion proves exclusive host ownership of this region.
// Volatile writes keep the erase observable even immediately before release.
static void wipe_private_host_region(void* memory, size_t bytes) {
    volatile unsigned char* cursor = static_cast<volatile unsigned char*>(memory);
    for (size_t index = 0; index < bytes; ++index) cursor[index] = 0;
}

static cudaError_t clear_idle_device_region(void* memory, size_t bytes);

template <typename T>
static cudaError_t ensure_workspace_buffer(
    T** buffer,
    size_t* capacity_bytes,
    size_t need_bytes
) {
    if (need_bytes == 0) {
        return cudaSuccess;
    }
    if (*buffer != nullptr && *capacity_bytes >= need_bytes) {
        return cudaSuccess;
    }
    if (*buffer != nullptr) {
        // Every caller grows an idle workspace, never an in-flight allocation.
        // Require completion of the erase before releasing the old capacity.
        cudaError_t clear_status = clear_idle_device_region(*buffer, *capacity_bytes);
        if (clear_status != cudaSuccess) return clear_status;
        cudaError_t free_status = cudaFree(*buffer);
        if (free_status != cudaSuccess) {
            quarantine_cuda_backend();
            return free_status;
        }
        *buffer = nullptr;
        *capacity_bytes = 0;
    }
    cudaError_t status = cudaMalloc(reinterpret_cast<void**>(buffer), need_bytes);
    if (status == cudaSuccess) {
        *capacity_bytes = need_bytes;
    }
    return status;
}

template <typename T>
static cudaError_t ensure_pinned_workspace_buffer(
    T** buffer,
    size_t* capacity_bytes,
    size_t need_bytes
) {
    if (need_bytes == 0) {
        return cudaSuccess;
    }
    if (*buffer != nullptr && *capacity_bytes >= need_bytes) {
        return cudaSuccess;
    }
    if (*buffer != nullptr) {
        wipe_private_host_region(*buffer, *capacity_bytes);
        cudaError_t free_status = cudaFreeHost(*buffer);
        if (free_status != cudaSuccess) {
            quarantine_cuda_backend();
            return free_status;
        }
        *buffer = nullptr;
        *capacity_bytes = 0;
    }
    cudaError_t status = cudaHostAlloc(reinterpret_cast<void**>(buffer), need_bytes, cudaHostAllocDefault);
    if (status == cudaSuccess) {
        *capacity_bytes = need_bytes;
    }
    return status;
}

static cudaError_t ensure_async_dispatch_stream(AsyncDispatchBuffers* buffers) {
    if (buffers == nullptr) {
        return cudaErrorInvalidValue;
    }
    if (buffers->stream_ready) {
        return cudaSuccess;
    }
    cudaError_t status = cudaStreamCreateWithFlags(&buffers->stream, cudaStreamNonBlocking);
    if (status == cudaSuccess) {
        buffers->stream_ready = true;
    }
    return status;
}

static cudaError_t ensure_transform_stream(TransformWorkspace* workspace) {
    if (workspace == nullptr) {
        return cudaErrorInvalidValue;
    }
    if (workspace->stream_ready) {
        return cudaSuccess;
    }
    cudaError_t status = cudaStreamCreateWithFlags(&workspace->stream, cudaStreamNonBlocking);
    if (status == cudaSuccess) {
        workspace->stream_ready = true;
    }
    return status;
}

static cudaError_t ensure_transform_event(TransformWorkspace* workspace) {
    if (workspace == nullptr) {
        return cudaErrorInvalidValue;
    }
    if (workspace->event_ready) {
        return cudaSuccess;
    }
    cudaError_t status = cudaEventCreateWithFlags(&workspace->event, cudaEventDisableTiming);
    if (status == cudaSuccess) {
        workspace->event_ready = true;
    }
    return status;
}

static cudaError_t ensure_poseidon_stream(PoseidonWorkspace* workspace) {
    if (workspace == nullptr) {
        return cudaErrorInvalidValue;
    }
    if (workspace->stream_ready) {
        return cudaSuccess;
    }
    cudaError_t status = cudaStreamCreateWithFlags(&workspace->stream, cudaStreamNonBlocking);
    if (status == cudaSuccess) {
        workspace->stream_ready = true;
    }
    return status;
}

static cudaError_t ensure_poseidon_event(PoseidonWorkspace* workspace) {
    if (workspace == nullptr) {
        return cudaErrorInvalidValue;
    }
    if (workspace->event_ready) {
        return cudaSuccess;
    }
    cudaError_t status = cudaEventCreateWithFlags(&workspace->event, cudaEventDisableTiming);
    if (status == cudaSuccess) {
        workspace->event_ready = true;
    }
    return status;
}

template <typename QueryFn>
static cudaError_t wait_until_cuda_ready_for(
    std::chrono::milliseconds timeout,
    QueryFn query
) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        cudaError_t status = query();
        if (status == cudaSuccess) {
            return cudaSuccess;
        }
        if (status != cudaErrorNotReady) {
            return status;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            return cudaErrorLaunchTimeout;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

template <typename QueryFn>
static cudaError_t wait_until_cuda_ready(QueryFn query) {
    return wait_until_cuda_ready_for(
        std::chrono::duration_cast<std::chrono::milliseconds>(FASTPQ_CUDA_COMMAND_TIMEOUT),
        query
    );
}

static cudaError_t wait_for_event(cudaEvent_t event) {
    if (event == nullptr) {
        quarantine_cuda_backend();
        return cudaErrorInvalidValue;
    }
    cudaError_t status = wait_until_cuda_ready([event]() { return cudaEventQuery(event); });
    if (async_status_requires_abandon(status)) {
        quarantine_cuda_backend();
    }
    return status;
}

static cudaError_t wait_for_stream(cudaStream_t stream) {
    if (stream == nullptr) {
        quarantine_cuda_backend();
        return cudaErrorInvalidValue;
    }
    cudaError_t status = wait_until_cuda_ready([stream]() { return cudaStreamQuery(stream); });
    if (async_status_requires_abandon(status)) {
        quarantine_cuda_backend();
    }
    return status;
}

static cudaError_t clear_idle_device_region(void* memory, size_t bytes) {
    if (memory == nullptr || bytes == 0) return cudaSuccess;
    cudaStream_t stream = nullptr;
    cudaError_t status = cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking);
    if (status == cudaSuccess) status = cudaMemsetAsync(memory, 0, bytes, stream);
    if (status == cudaSuccess) status = wait_for_stream(stream);
    if (status != cudaSuccess) {
        // A failed erase may still own the allocation. Do not free it or its
        // stream, and prevent the caller from reusing the retained workspace.
        quarantine_cuda_backend();
        return status;
    }
    status = cudaStreamDestroy(stream);
    if (status != cudaSuccess) quarantine_cuda_backend();
    return status;
}

// TransformWorkspace and AsyncDispatchBuffers share these private regions.
// Precondition: the dispatch never started, or its completion was observed.
// The stream exists and belongs exclusively to this workspace. On error the
// caller abandons all resources; no erase failure can return a buffer to a pool.
template <typename Workspace>
static cudaError_t scrub_completed_transform(Workspace* workspace) {
    struct Region { void* memory; size_t bytes; };
    const Region host[] = {
        {workspace->host_dense, workspace->host_dense_capacity_bytes},
        {workspace->host_coeffs, workspace->host_coeff_capacity_bytes},
        {workspace->host_evals, workspace->host_eval_capacity_bytes},
    };
    const Region device[] = {
        {workspace->dense, workspace->dense_capacity_bytes},
        {workspace->coeffs, workspace->coeff_capacity_bytes},
        {workspace->evals, workspace->eval_capacity_bytes},
    };
    for (const Region& region : host) {
        if (region.memory != nullptr) wipe_private_host_region(region.memory, region.bytes);
    }
    bool queued = false;
    for (const Region& region : device) {
        if (region.memory == nullptr || region.bytes == 0) continue;
        cudaError_t status = cudaMemsetAsync(region.memory, 0, region.bytes, workspace->stream);
        if (status != cudaSuccess) {
            quarantine_cuda_backend();
            return status;
        }
        queued = true;
    }
    return queued ? wait_for_stream(workspace->stream) : cudaSuccess;
}

// The older permutation/hash endpoints also receive private prover words. Their
// public constants can stay cached, but payloads, slices and sponge states cannot.
static cudaError_t scrub_completed_poseidon(PoseidonWorkspace* workspace) {
    struct Region { void* device; size_t device_bytes; void* host; size_t host_bytes; };
    const Region regions[] = {
        {workspace->payloads, workspace->payload_capacity_bytes,
         workspace->host_payloads, workspace->host_payload_capacity_bytes},
        {workspace->slices, workspace->slice_capacity_bytes,
         workspace->host_slices, workspace->host_slice_capacity_bytes},
        {workspace->states, workspace->state_capacity_bytes,
         workspace->host_states, workspace->host_state_capacity_bytes},
        {workspace->hashes, workspace->hash_capacity_bytes,
         workspace->host_hashes, workspace->host_hash_capacity_bytes},
    };
    for (const Region& region : regions) {
        if (region.host != nullptr) wipe_private_host_region(region.host, region.host_bytes);
    }
    bool queued = false;
    for (const Region& region : regions) {
        if (region.device == nullptr || region.device_bytes == 0) continue;
        cudaError_t status = cudaMemsetAsync(region.device, 0, region.device_bytes, workspace->stream);
        if (status != cudaSuccess) {
            quarantine_cuda_backend();
            return status;
        }
        queued = true;
    }
    return queued ? wait_for_stream(workspace->stream) : cudaSuccess;
}

static void abandon_transform_workspace(TransformWorkspace* workspace) {
    if (workspace == nullptr) {
        return;
    }
    workspace->dense = nullptr;
    workspace->coeffs = nullptr;
    workspace->evals = nullptr;
    workspace->bn254_twiddles = nullptr;
    workspace->bn254_coset = nullptr;
    workspace->host_dense = nullptr;
    workspace->host_coeffs = nullptr;
    workspace->host_evals = nullptr;
    workspace->host_bn254_twiddles = nullptr;
    workspace->host_bn254_coset = nullptr;
    workspace->stream = nullptr;
    workspace->event = nullptr;
    workspace->dense_capacity_bytes = 0;
    workspace->coeff_capacity_bytes = 0;
    workspace->eval_capacity_bytes = 0;
    workspace->bn254_twiddle_capacity_bytes = 0;
    workspace->bn254_coset_capacity_bytes = 0;
    workspace->host_dense_capacity_bytes = 0;
    workspace->host_coeff_capacity_bytes = 0;
    workspace->host_eval_capacity_bytes = 0;
    workspace->host_bn254_twiddle_capacity_bytes = 0;
    workspace->host_bn254_coset_capacity_bytes = 0;
    workspace->stream_ready = false;
    workspace->event_ready = false;
}

static void abandon_poseidon_workspace(PoseidonWorkspace* workspace) {
    if (workspace == nullptr) {
        return;
    }
    workspace->payloads = nullptr;
    workspace->slices = nullptr;
    workspace->states = nullptr;
    workspace->hashes = nullptr;
    workspace->bn254_round_constants = nullptr;
    workspace->bn254_mds = nullptr;
    workspace->host_payloads = nullptr;
    workspace->host_slices = nullptr;
    workspace->host_states = nullptr;
    workspace->host_hashes = nullptr;
    workspace->host_bn254_round_constants = nullptr;
    workspace->host_bn254_mds = nullptr;
    workspace->stream = nullptr;
    workspace->event = nullptr;
    workspace->payload_capacity_bytes = 0;
    workspace->slice_capacity_bytes = 0;
    workspace->state_capacity_bytes = 0;
    workspace->hash_capacity_bytes = 0;
    workspace->bn254_round_capacity_bytes = 0;
    workspace->bn254_mds_capacity_bytes = 0;
    workspace->host_payload_capacity_bytes = 0;
    workspace->host_slice_capacity_bytes = 0;
    workspace->host_state_capacity_bytes = 0;
    workspace->host_hash_capacity_bytes = 0;
    workspace->host_bn254_round_capacity_bytes = 0;
    workspace->host_bn254_mds_capacity_bytes = 0;
    workspace->stream_ready = false;
    workspace->event_ready = false;
}

static cudaError_t fail_transform_dispatch(
    TransformWorkspace* workspace,
    cudaError_t status
) {
    if (status != cudaSuccess) {
        // Once work has been submitted, even an immediately reported failure
        // does not prove that earlier commands stopped using the workspace.
        quarantine_cuda_backend();
        abandon_transform_workspace(workspace);
    }
    return status;
}

static cudaError_t fail_poseidon_dispatch(
    PoseidonWorkspace* workspace,
    cudaError_t status
) {
    if (status != cudaSuccess) {
        quarantine_cuda_backend();
        abandon_poseidon_workspace(workspace);
    }
    return status;
}

static cudaError_t wait_for_transform_event_after_copy(TransformWorkspace* workspace) {
    if (workspace == nullptr) {
        quarantine_cuda_backend();
        return cudaErrorInvalidValue;
    }
    if (!workspace->event_ready || !workspace->stream_ready) {
        quarantine_cuda_backend();
        abandon_transform_workspace(workspace);
        return cudaErrorInvalidValue;
    }
    cudaError_t status = cudaEventRecord(workspace->event, workspace->stream);
    if (async_status_requires_abandon(status)) {
        quarantine_cuda_backend();
        abandon_transform_workspace(workspace);
        return status;
    }
    status = wait_for_event(workspace->event);
    if (async_status_requires_abandon(status)) {
        abandon_transform_workspace(workspace);
    }
    return status;
}

static cudaError_t wait_for_poseidon_event_after_copy(PoseidonWorkspace* workspace) {
    if (workspace == nullptr) {
        quarantine_cuda_backend();
        return cudaErrorInvalidValue;
    }
    if (!workspace->event_ready || !workspace->stream_ready) {
        quarantine_cuda_backend();
        abandon_poseidon_workspace(workspace);
        return cudaErrorInvalidValue;
    }
    cudaError_t status = cudaEventRecord(workspace->event, workspace->stream);
    if (async_status_requires_abandon(status)) {
        quarantine_cuda_backend();
        abandon_poseidon_workspace(workspace);
        return status;
    }
    status = wait_for_event(workspace->event);
    if (async_status_requires_abandon(status)) {
        abandon_poseidon_workspace(workspace);
    }
    return status;
}

static cudaError_t dense_buffer_bytes(size_t column_count, uint64_t column_len, size_t* byte_len) {
    if (byte_len == nullptr) {
        return cudaErrorInvalidValue;
    }
    size_t column_len_size = (size_t)column_len;
    if (column_len != (uint64_t)column_len_size) {
        return cudaErrorInvalidValue;
    }
    if (column_len_size != 0 && column_count > SIZE_MAX / column_len_size) {
        return cudaErrorInvalidValue;
    }
    size_t element_count = column_count * column_len_size;
    if (element_count > SIZE_MAX / sizeof(uint64_t)) {
        return cudaErrorInvalidValue;
    }
    *byte_len = element_count * sizeof(uint64_t);
    return cudaSuccess;
}

static cudaError_t limb_buffer_bytes(size_t limb_count, size_t* byte_len) {
    if (byte_len == nullptr) {
        return cudaErrorInvalidValue;
    }
    if (limb_count > SIZE_MAX / sizeof(uint64_t)) {
        return cudaErrorInvalidValue;
    }
    *byte_len = limb_count * sizeof(uint64_t);
    return cudaSuccess;
}

static cudaError_t bn254_dense_buffer_bytes(
    size_t column_count,
    uint64_t element_count,
    size_t* byte_len
) {
    if (element_count > UINT64_MAX / BN254_LIMBS) {
        return cudaErrorInvalidValue;
    }
    return dense_buffer_bytes(column_count, element_count * BN254_LIMBS, byte_len);
}

static bool checked_size_add(size_t lhs, size_t rhs, size_t* out) {
    if (out == nullptr || lhs > SIZE_MAX - rhs) {
        return false;
    }
    *out = lhs + rhs;
    return true;
}

static bool checked_size_mul(size_t lhs, size_t rhs, size_t* out) {
    if (out == nullptr || (rhs != 0 && lhs > SIZE_MAX / rhs)) {
        return false;
    }
    *out = lhs * rhs;
    return true;
}

static bool checked_grid_size(
    size_t item_count,
    unsigned int threads_per_block,
    unsigned int* grid_size
) {
    if (item_count == 0 || threads_per_block == 0 || grid_size == nullptr) {
        return false;
    }
    const size_t block_count = item_count / threads_per_block
        + (item_count % threads_per_block != 0 ? 1u : 0u);
    if (block_count == 0 || block_count > FASTPQ_CUDA_MAX_GRID_X) {
        return false;
    }
    *grid_size = (unsigned int)block_count;
    return true;
}

static bool checked_domain_len(uint32_t log_size, uint32_t max_log, uint64_t* len) {
    if (len == nullptr || log_size > max_log || log_size >= 64u) {
        return false;
    }
    *len = 1ull << log_size;
    return true;
}

static bool checked_eval_domain_lengths(
    uint32_t trace_log,
    uint32_t blowup_log,
    uint32_t max_log,
    uint64_t* trace_len,
    uint64_t* eval_len,
    uint32_t* eval_log
) {
    if (
        trace_len == nullptr || eval_len == nullptr || eval_log == nullptr || blowup_log == 0u
        || trace_log > max_log || blowup_log > max_log - trace_log
    ) {
        return false;
    }
    *eval_log = trace_log + blowup_log;
    return checked_domain_len(trace_log, max_log, trace_len)
        && checked_domain_len(*eval_log, max_log, eval_len);
}

static bool checked_bn254_twiddle_limb_len(
    uint32_t log_size,
    uint64_t domain_len,
    size_t* limb_len
) {
    size_t twiddle_count = 0;
    if (log_size == 0u || domain_len == 0u || domain_len - 1u > (uint64_t)SIZE_MAX) {
        return false;
    }
    twiddle_count = (size_t)(domain_len - 1u);
    return checked_size_mul(twiddle_count, (size_t)BN254_LIMBS, limb_len);
}

static bool validate_poseidon_column_slices(
    const PoseidonSlice* slices,
    size_t column_count,
    size_t block_count,
    size_t* payload_bytes
) {
    size_t elements_per_column = 0;
    if (
        slices == nullptr || payload_bytes == nullptr
        || !checked_size_mul(block_count, (size_t)POSEIDON_RATE, &elements_per_column)
        || elements_per_column > (size_t)UINT32_MAX
    ) {
        return false;
    }
    size_t expected_offset = 0;
    for (size_t column = 0; column < column_count; ++column) {
        const PoseidonSlice slice = slices[column];
        if ((size_t)slice.offset != expected_offset || (size_t)slice.len != elements_per_column) {
            return false;
        }
        if (!checked_size_add(expected_offset, elements_per_column, &expected_offset)) {
            return false;
        }
    }
    return checked_size_mul(expected_offset, sizeof(uint64_t), payload_bytes);
}

static bool validate_poseidon_word_slices(
    const PoseidonSlice* slices,
    size_t batch_count,
    size_t word_count
) {
    if (slices == nullptr) {
        return false;
    }
    for (size_t index = 0; index < batch_count; ++index) {
        size_t end = 0;
        if (
            !checked_size_add((size_t)slices[index].offset, (size_t)slices[index].len, &end)
            || end > word_count
        ) {
            return false;
        }
    }
    return true;
}

static TransformWorkspace* current_transform_workspace() {
    if (cuda_backend_is_quarantined()) {
        return nullptr;
    }
    int device = 0;
    if (cudaGetDevice(&device) != cudaSuccess) {
        return nullptr;
    }
    return &transform_workspaces()[device];
}

static AsyncDispatchBuffers* acquire_async_dispatch_buffers(int device) {
    if (cuda_backend_is_quarantined()) {
        return nullptr;
    }
    std::lock_guard<std::mutex> guard(async_dispatch_pool_mutex());
    // A failure can race a caller that was waiting for the pool lock. Recheck
    // after acquiring the lock so that waiter cannot start another allocation.
    if (cuda_backend_is_quarantined()) {
        return nullptr;
    }
    std::vector<AsyncDispatchBuffers*>& pool = async_dispatch_pools()[device];
    if (!pool.empty()) {
        AsyncDispatchBuffers* buffers = pool.back();
        pool.pop_back();
        return buffers;
    }
    return new (std::nothrow) AsyncDispatchBuffers(device);
}

static cudaError_t release_async_dispatch_buffers(AsyncDispatchBuffers* buffers) {
    if (buffers == nullptr) {
        return cudaSuccess;
    }
    if (cuda_backend_is_quarantined()) {
        // No destructor owns these raw resources. Preserve uncertain device
        // ownership by dropping only the small host descriptor.
        delete buffers;
        return cudaErrorUnknown;
    }
    cudaError_t status = ensure_async_dispatch_stream(buffers);
    if (status == cudaSuccess) status = scrub_completed_transform(buffers);
    if (status != cudaSuccess) {
        quarantine_cuda_backend();
        delete buffers;
        return status;
    }
    std::lock_guard<std::mutex> guard(async_dispatch_pool_mutex());
    if (cuda_backend_is_quarantined()) {
        delete buffers;
        return cudaErrorUnknown;
    }
    async_dispatch_pools()[buffers->device].push_back(buffers);
    return cudaSuccess;
}

static void abandon_pending_transform(PendingTransform* pending) {
    if (pending == nullptr) {
        return;
    }
    // The event and pooled workspace can still be owned by CUDA. Delete only
    // the small host-side handle and deliberately lose every CUDA resource
    // pointer so neither a destructor nor a later dispatch can reclaim it.
    pending->event = nullptr;
    pending->buffers = nullptr;
    pending->staging_output = nullptr;
    pending->output_byte_len = 0;
    delete pending;
}

static cudaError_t destroy_pending_transform(PendingTransform* pending) {
    if (pending == nullptr) {
        return cudaSuccess;
    }
    cudaError_t status = cudaSetDevice(pending->device);
    if (async_status_requires_abandon(status)) {
        quarantine_cuda_backend();
        abandon_pending_transform(pending);
        return status;
    }
    if (pending->buffers != nullptr && pending->buffers->stream_ready) {
        status = wait_for_stream(pending->buffers->stream);
        if (async_status_requires_abandon(status)) {
            abandon_pending_transform(pending);
            return status;
        }
    }
    if (pending->event != nullptr) {
        status = cudaEventDestroy(pending->event);
        if (async_status_requires_abandon(status)) {
            quarantine_cuda_backend();
            abandon_pending_transform(pending);
            return status;
        }
    }
    status = release_async_dispatch_buffers(pending->buffers);
    delete pending;
    return status;
}

static cudaError_t create_pending_transform(
    int device,
    AsyncDispatchBuffers* buffers,
    void* staging_output,
    size_t output_byte_len,
    PendingTransform** pending_out
) {
    if (pending_out == nullptr || buffers == nullptr) {
        return cudaErrorInvalidValue;
    }
    *pending_out = nullptr;
    cudaEvent_t event = nullptr;
    cudaError_t status = cudaEventCreateWithFlags(&event, cudaEventDisableTiming);
    if (status != cudaSuccess) {
        return status;
    }
    PendingTransform* pending = new (std::nothrow)
        PendingTransform(
            device,
            event,
            buffers,
            staging_output,
            output_byte_len
        );
    if (pending == nullptr) {
        (void)cudaEventDestroy(event);
        return cudaErrorMemoryAllocation;
    }
    *pending_out = pending;
    return cudaSuccess;
}

static PoseidonWorkspace* current_poseidon_workspace() {
    if (cuda_backend_is_quarantined()) {
        return nullptr;
    }
    int device = 0;
    if (cudaGetDevice(&device) != cudaSuccess) {
        return nullptr;
    }
    return &poseidon_workspaces()[device];
}

static __device__ __constant__ uint64_t POSEIDON_ROUND_CONSTANTS[POSEIDON_FULL_ROUNDS_HALF * 2u + POSEIDON_PARTIAL_ROUNDS][POSEIDON_STATE_WIDTH] = {
    {0x0355defb099bed96ull, 0xfcc55fb9681355e6ull, 0x931368d725f8720aull},
    {0x3b8752f81e4e100aull, 0x53b864ee53de1e7cull, 0xfccb110a3a839800ull},
    {0xfff0e99012e32773ull, 0xfca28ab2898eff49ull, 0xb02b1c854e99b411ull},
    {0x9c45a0b2adeddcddull, 0xab6bd8d6b4959cfaull, 0x32eb07eb92becca5ull},
    {0x02698cda7aa8674aull, 0xa6914454ffbbc85aull, 0x330402af7562de69ull},
    {0x6b9deb689731670aull, 0xb6acba1824052a6eull, 0x3ad181a6aaed99ecull},
    {0x871f25345b28b8e9ull, 0xcd88d358315eeec1ull, 0xe051da577c86be1dull},
    {0x153ad1817c0c125aull, 0x97461b442e8abe8cull, 0x86591af51639f5a9ull},
    {0xb5bbc2a445ce1d3cull, 0x3cf87df379503557ull, 0x69c87ef4b926f914ull},
    {0x941bba1e4ef7e9f5ull, 0x2f9b29b58901fe31ull, 0x49c95be066d4e00bull},
    {0xcdb4fa571ed16b7eull, 0x81526ee1686c1130ull, 0x9afe7622fd187b9dull},
    {0x1c6d3d32f5666a4aull, 0xbc714a509ed0c9e2ull, 0xdbd44f433d9bb989ull},
    {0x07f9a90b7e43d95cull, 0xbf0830bc8e11be74ull, 0x97f82d7658d424afull},
    {0x232d735bd912e717ull, 0x24c5847ca7491e7aull, 0x050e45f9ad018df7ull},
    {0x3d875e313e445623ull, 0xf0e765b8e6350e3aull, 0x24e1f73aacb2a5d8ull},
    {0xa2608cac4eddcbf6ull, 0xbb84373a14012579ull, 0x153ff026357ddb2eull},
    {0x31c51990051b2fceull, 0xc4326a6df1342061ull, 0x110ab731271e081dull},
    {0xd7d4ed983f738f7dull, 0x04c2243a9d2d2dd8ull, 0xec84bd9f09f4a4eeull},
    {0x459c6a91e8310f7dull, 0xbd5448db7b312560ull, 0x55405bc1d4841791ull},
    {0x9b29aa29d32ff2efull, 0x19b4882d7d91817dull, 0xff96eeff0d35d395ull},
    {0x725bee8d2e752ebaull, 0xb778a21c64310114ull, 0x9991cf6141e2878aull},
    {0x5baf8b23f6d30359ull, 0x17d0b954a0c24e6dull, 0x3050c4078053b0d5ull},
    {0xf9f52a3090efa474ull, 0xa598d52915f99806ull, 0xbf48572b618fbd61ull},
    {0xa34bfa5c0b92ec3eull, 0xab1115736057c63cull, 0x2f7d416846014aaaull},
    {0xe19f214292d3a546ull, 0xb48ced4361042203ull, 0xb64f6bfc1cfcbd92ull},
    {0xe0f48eecd39b7cbfull, 0xc4384583c0d6450dull, 0x7460cad33f436acaull},
    {0xa69f9eff5caf7223ull, 0x82acd34e811e340aull, 0xecb3d78f9881bedfull},
    {0x976760db1c85079aull, 0xa0d527128f5231caull, 0xa8823b80503c432bull},
    {0xc41afca19eb78258ull, 0x33b30793338e26eeull, 0x3369d80a26f26384ull},
    {0x4f5237b43fe7c081ull, 0x3e2e28d3737926d1ull, 0x9e9fd9449eafc854ull},
    {0xf6dbf8e50187050full, 0x0883a7372f01a7d2ull, 0xe85c8cbe6053fa56ull},
    {0x43e66dea535dce9dull, 0xff7445db745c243bull, 0xde5d71d4d7709458ull},
    {0xb14f0f45451d99f9ull, 0xfcdf81f971206fc3ull, 0x2508429ed0bbabfaull},
    {0x408115a6f42a57e8ull, 0xfcde33569c03693dull, 0x83926cc606241abdull},
    {0xfe6191419d8e0a84ull, 0x358d71362d234258ull, 0x3bfb29c64195c104ull},
    {0x0ed6b527fe034ad7ull, 0xcd1998fe841a698aull, 0x6ab890ebbfe772a9ull},
    {0x099a748ed5415721ull, 0x254b906a5a91bc8aull, 0x4d5130a30f0cbb72ull},
    {0xd0932ea3fa64d467ull, 0xbe72249d94aea218ull, 0x06215750fd6a29c5ull},
    {0xd79031484db89846ull, 0xdd89cad959ba24a4ull, 0xdc046dfa44871254ull},
    {0xb36f522bf4af2ef6ull, 0x92796eae38632589ull, 0x9796638178a01e39ull},
    {0xbe2c6a4f43121effull, 0x0c20942ea145116bull, 0xb6d21c3af9d7af98ull},
    {0x953af8c79c3e074eull, 0xc039153065b4a5c5ull, 0x9f51afaf415b8a55ull},
    {0x6198a82927569707ull, 0xa09366e5bb6a66c7ull, 0x68e710be9451ff59ull},
    {0x9226cca1e4988dddull, 0x27e15510153c0224ull, 0x8d6a3e1fc7c197f2ull},
    {0xfaa929e25257bc60ull, 0x6b37c307ac47aa83ull, 0x907b20a35cfe4fc2ull},
    {0x50350676383d204eull, 0x446c05dd253b59e8ull, 0x0f31889e23c5d5eaull},
    {0x38ec3e1c2e667720ull, 0x026fdf27b554ff10ull, 0x1ca82d95c6fafd39ull},
    {0xddd0bc056342e191ull, 0x2d315fb44b04ac30ull, 0xfd4b193bae11b94bull},
    {0x086df800b3489093ull, 0xf30fae7604b987e2ull, 0x10a19793fe69ebe8ull},
    {0x0c77141b7edf0449ull, 0x5ea875779328deb1ull, 0x0b674c79767e421full},
    {0x4a5a726d82f3258eull, 0x09e8c7a8be47b1deull, 0xfffa2ac085276013ull},
    {0xc09139324aa9d4f9ull, 0xb51a23205924fd17ull, 0xdcc8894949e02da4ull},
    {0x227483529222ad6eull, 0x65337b2101dfc3d8ull, 0xe19dfd7c78aaacc7ull},
    {0xf1b98df340a16ca6ull, 0x18d543123d27950dull, 0xc0c16b9b6007e396ull},
    {0xb90bc3c0d0605c8cull, 0xde108ac1d6c0bdcaull, 0x5ee8196b61146783ull},
    {0x2aaba85c6bbcf12full, 0x02ff605b73843154ull, 0x2c37fc5e4dfebb1eull},
    {0xcb1ca352a46e4d33ull, 0x187d0f76fc0fb4a3ull, 0xaeadcdfe0a66b1f1ull},
    {0xc12532bfb67e3436ull, 0x4b403b0bf220033eull, 0xe0dec1015d69cd0bull},
    {0x5d3eb71f9ef30c4aull, 0xf82d9fbcdf532aebull, 0xa362551d86bebd87ull},
    {0x6823e25802851126ull, 0x189ce62b77650805ull, 0xefc261ffa36bf041ull},
    {0x478863511cbaf173ull, 0x4f4bd042c56b7936ull, 0x5b4cf8cc8584ca9aull},
    {0xcc944e5f76063e0cull, 0xd29a0b002c783ca7ull, 0x2f59efce5cde182bull},
    {0x93a0767d9186685cull, 0xee2501a761ecf4e5ull, 0xe7514fa48b145686ull},
    {0x5e0f189e8c61d97cull, 0xebe9bd9bef0f5443ull, 0xd6cfe2a76189672aull},
    {0x38ff8f40252c1ab7ull, 0x3cf9c4c3804d8166ull, 0x512f1e3ac8d0ffe5ull},
};

static __device__ __constant__ uint64_t POSEIDON_MDS[POSEIDON_STATE_WIDTH][POSEIDON_STATE_WIDTH] = {
    {0x982513a23d22b592ull, 0xa3115db8cf1d9c90ull, 0x46ba684b9eee84b7ull},
    {0xbe3dce25491db768ull, 0xfb0a6f731943519full, 0xfce5bd953cde1896ull},
    {0xe624719c41eb1a09ull, 0xd2221b0f1aa2ebc4ull, 0x1ab5e60d03ad44bcull},
};

// -----------------------------------------------------------------------------.
// Utility helpers.
// -----------------------------------------------------------------------------
__device__ __forceinline__ uint64_t d_load(const uint64_t* ptr) {
    return __ldg(ptr);
}

__device__ __forceinline__ void d_store(uint64_t* ptr, uint64_t value) {
    *ptr = value;
}

__device__ __forceinline__ uint64_t field_reduce_u128(unsigned __int128 value) {
    // Repeatedly fold high limbs using 2^64 ≡ (2^32 - 1) (mod p) until the value fits in u64.
    const unsigned __int128 fold = (unsigned __int128)FOLD_CONST;
    while ((value >> 64) != 0) {
        uint64_t lo = (uint64_t)value;
        uint64_t hi = (uint64_t)(value >> 64);
        value = (unsigned __int128)lo + (unsigned __int128)hi * fold;
    }
    uint64_t reduced = (uint64_t)value;
    uint64_t p = FIELD_MODULUS;
    if (reduced >= p) reduced -= p;
    if (reduced >= p) reduced -= p;
    return reduced;
}

__device__ __forceinline__ uint64_t f_add(uint64_t a, uint64_t b) {
    return field_reduce_u128((unsigned __int128)a + (unsigned __int128)b);
}

__device__ __forceinline__ uint64_t f_sub(uint64_t a, uint64_t b) {
    return (a >= b) ? (a - b) : (a + FIELD_MODULUS - b);
}

__device__ __forceinline__ uint64_t f_mul(uint64_t a, uint64_t b) {
    return field_reduce_u128((unsigned __int128)a * (unsigned __int128)b);
}

__device__ uint64_t f_pow(uint64_t base, uint64_t exp) {
    uint64_t acc = 1ull;
    while (exp) {
        if (exp & 1ull) {
            acc = f_mul(acc, base);
        }
        base = f_mul(base, base);
        exp >>= 1ull;
    }
    return acc;
}

__device__ __forceinline__ uint64_t f_inv(uint64_t value) {
    return f_pow(value, FIELD_MODULUS - 2ull);
}

__device__ __forceinline__ Bn254Value bn254_load(const uint64_t* ptr) {
    Bn254Value value;
    #pragma unroll
    for (unsigned int idx = 0; idx < BN254_LIMBS; ++idx) {
        value.limbs[idx] = ptr[idx];
    }
    return value;
}

__device__ __forceinline__ Bn254Value bn254_zero() {
    Bn254Value value = {{0ull, 0ull, 0ull, 0ull}};
    return value;
}

__device__ __forceinline__ void bn254_store(uint64_t* ptr, const Bn254Value& value) {
    #pragma unroll
    for (unsigned int idx = 0; idx < BN254_LIMBS; ++idx) {
        ptr[idx] = value.limbs[idx];
    }
}

__device__ __forceinline__ bool bn254_ge_modulus(const Bn254Value& value) {
    for (int idx = (int)BN254_LIMBS - 1; idx >= 0; --idx) {
        if (value.limbs[idx] != BN254_MODULUS[idx]) {
            return value.limbs[idx] > BN254_MODULUS[idx];
        }
    }
    return true;
}

__device__ __forceinline__ uint64_t add_with_carry(
    uint64_t lhs,
    uint64_t rhs,
    uint64_t* carry
) {
    uint64_t sum = lhs + rhs;
    bool carry0 = sum < lhs;
    uint64_t result = sum + *carry;
    bool carry1 = result < sum;
    *carry = (carry0 || carry1) ? 1ull : 0ull;
    return result;
}

__device__ __forceinline__ uint64_t sub_with_borrow(
    uint64_t lhs,
    uint64_t rhs,
    uint64_t* borrow
) {
    uint64_t diff = lhs - rhs;
    bool borrow0 = lhs < rhs;
    uint64_t result = diff - *borrow;
    bool borrow1 = diff < *borrow;
    *borrow = (borrow0 || borrow1) ? 1ull : 0ull;
    return result;
}

__device__ __forceinline__ Bn254Value bn254_sub_modulus(const Bn254Value& value) {
    Bn254Value out;
    uint64_t borrow = 0ull;
    #pragma unroll
    for (unsigned int idx = 0; idx < BN254_LIMBS; ++idx) {
        out.limbs[idx] = sub_with_borrow(value.limbs[idx], BN254_MODULUS[idx], &borrow);
    }
    return out;
}

__device__ __forceinline__ Bn254Value bn254_add(const Bn254Value& a, const Bn254Value& b) {
    Bn254Value sum;
    uint64_t carry = 0ull;
    #pragma unroll
    for (unsigned int idx = 0; idx < BN254_LIMBS; ++idx) {
        sum.limbs[idx] = add_with_carry(a.limbs[idx], b.limbs[idx], &carry);
    }
    if (carry != 0ull || bn254_ge_modulus(sum)) {
        sum = bn254_sub_modulus(sum);
    }
    return sum;
}

__device__ __forceinline__ Bn254Value bn254_sub(const Bn254Value& a, const Bn254Value& b) {
    Bn254Value out;
    uint64_t borrow = 0ull;
    #pragma unroll
    for (unsigned int idx = 0; idx < BN254_LIMBS; ++idx) {
        out.limbs[idx] = sub_with_borrow(a.limbs[idx], b.limbs[idx], &borrow);
    }
    if (borrow != 0ull) {
        uint64_t carry = 0ull;
        #pragma unroll
        for (unsigned int idx = 0; idx < BN254_LIMBS; ++idx) {
            out.limbs[idx] = add_with_carry(out.limbs[idx], BN254_MODULUS[idx], &carry);
        }
    }
    return out;
}

__device__ __forceinline__ void bn254_mul_add(
    uint64_t x,
    uint64_t y,
    uint64_t* acc,
    uint64_t* carry
) {
    uint64_t lo = x * y;
    uint64_t hi = __umul64hi(x, y);

    uint64_t sum = *acc + lo;
    uint64_t carry0 = sum < *acc ? 1ull : 0ull;
    sum += *carry;
    uint64_t carry1 = sum < *carry ? 1ull : 0ull;

    *acc = sum;
    *carry = hi + carry0 + carry1;
}

__device__ __forceinline__ void bn254_montgomery_reduce(
    uint64_t t[8],
    uint64_t out[BN254_LIMBS]
) {
    for (unsigned int idx = 0; idx < BN254_LIMBS; ++idx) {
        uint64_t m = t[idx] * BN254_MODULUS_INV;
        uint64_t carry = 0ull;
        #pragma unroll
        for (unsigned int limb = 0; limb < BN254_LIMBS; ++limb) {
            bn254_mul_add(m, BN254_MODULUS[limb], &t[idx + limb], &carry);
        }
        unsigned int carry_idx = idx + BN254_LIMBS;
        uint64_t sum = t[carry_idx] + carry;
        uint64_t carry_out = sum < t[carry_idx] ? 1ull : 0ull;
        t[carry_idx] = sum;
        while (carry_out != 0ull) {
            ++carry_idx;
            uint64_t prior = t[carry_idx];
            t[carry_idx] += carry_out;
            carry_out = t[carry_idx] < prior ? 1ull : 0ull;
        }
    }

    Bn254Value candidate;
    #pragma unroll
    for (unsigned int idx = 0; idx < BN254_LIMBS; ++idx) {
        out[idx] = t[idx + BN254_LIMBS];
        candidate.limbs[idx] = out[idx];
    }
    if (bn254_ge_modulus(candidate)) {
        candidate = bn254_sub_modulus(candidate);
        #pragma unroll
        for (unsigned int idx = 0; idx < BN254_LIMBS; ++idx) {
            out[idx] = candidate.limbs[idx];
        }
    }
}

__device__ __forceinline__ Bn254Value bn254_montgomery_mul(
    const Bn254Value& a,
    const Bn254Value& b
) {
    uint64_t t[8] = {0ull, 0ull, 0ull, 0ull, 0ull, 0ull, 0ull, 0ull};
    for (unsigned int i = 0; i < BN254_LIMBS; ++i) {
        uint64_t carry = 0ull;
        for (unsigned int j = 0; j < BN254_LIMBS; ++j) {
            bn254_mul_add(a.limbs[i], b.limbs[j], &t[i + j], &carry);
        }
        unsigned int idx = i + BN254_LIMBS;
        uint64_t sum = t[idx] + carry;
        uint64_t carry_out = sum < t[idx] ? 1ull : 0ull;
        t[idx] = sum;
        while (carry_out != 0ull) {
            ++idx;
            uint64_t prior = t[idx];
            t[idx] += carry_out;
            carry_out = t[idx] < prior ? 1ull : 0ull;
        }
    }
    uint64_t reduced[BN254_LIMBS];
    bn254_montgomery_reduce(t, reduced);
    Bn254Value out;
    #pragma unroll
    for (unsigned int idx = 0; idx < BN254_LIMBS; ++idx) {
        out.limbs[idx] = reduced[idx];
    }
    return out;
}

__device__ __forceinline__ Bn254Value bn254_r2() {
    Bn254Value out;
    #pragma unroll
    for (unsigned int idx = 0; idx < BN254_LIMBS; ++idx) {
        out.limbs[idx] = BN254_R2[idx];
    }
    return out;
}

__device__ __forceinline__ Bn254Value bn254_from_canonical(const Bn254Value& raw);

__device__ __forceinline__ Bn254Value bn254_one_mont() {
    Bn254Value one = {{1ull, 0ull, 0ull, 0ull}};
    return bn254_from_canonical(one);
}

__device__ __forceinline__ Bn254Value bn254_from_canonical(const Bn254Value& raw) {
    return bn254_montgomery_mul(raw, bn254_r2());
}

__device__ __forceinline__ Bn254Value bn254_pow_u64(Bn254Value base, uint64_t exp) {
    Bn254Value acc = bn254_one_mont();
    while (exp != 0ull) {
        if ((exp & 1ull) != 0ull) {
            acc = bn254_montgomery_mul(acc, base);
        }
        base = bn254_montgomery_mul(base, base);
        exp >>= 1ull;
    }
    return acc;
}

__device__ __forceinline__ Bn254Value bn254_to_canonical(const Bn254Value& value) {
    uint64_t t[8] = {
        value.limbs[0],
        value.limbs[1],
        value.limbs[2],
        value.limbs[3],
        0ull,
        0ull,
        0ull,
        0ull,
    };
    uint64_t reduced[BN254_LIMBS];
    bn254_montgomery_reduce(t, reduced);
    Bn254Value out;
    #pragma unroll
    for (unsigned int idx = 0; idx < BN254_LIMBS; ++idx) {
        out.limbs[idx] = reduced[idx];
    }
    return out;
}

__device__ __forceinline__ uint64_t poseidon_pow7(uint64_t x) {
    uint64_t x2 = f_mul(x, x);
    uint64_t x4 = f_mul(x2, x2);
    return f_mul(f_mul(x4, x2), x);
}

__device__ void poseidon_apply_mds(uint64_t state[POSEIDON_STATE_WIDTH]) {
    uint64_t new_state[POSEIDON_STATE_WIDTH] = {0ull, 0ull, 0ull};
    for (unsigned int row = 0; row < POSEIDON_STATE_WIDTH; ++row) {
        uint64_t acc = 0ull;
        for (unsigned int col = 0; col < POSEIDON_STATE_WIDTH; ++col) {
            acc = f_add(acc, f_mul(POSEIDON_MDS[row][col], state[col]));
        }
        new_state[row] = acc;
    }
    for (unsigned int idx = 0; idx < POSEIDON_STATE_WIDTH; ++idx) {
        state[idx] = new_state[idx];
    }
}

__device__ void poseidon_full_round(
    uint64_t state[POSEIDON_STATE_WIDTH],
    const uint64_t rc[POSEIDON_STATE_WIDTH]
) {
    for (unsigned int idx = 0; idx < POSEIDON_STATE_WIDTH; ++idx) {
        state[idx] = poseidon_pow7(f_add(state[idx], rc[idx]));
    }
    poseidon_apply_mds(state);
}

__device__ void poseidon_partial_round(
    uint64_t state[POSEIDON_STATE_WIDTH],
    const uint64_t rc[POSEIDON_STATE_WIDTH]
) {
    for (unsigned int idx = 0; idx < POSEIDON_STATE_WIDTH; ++idx) {
        state[idx] = f_add(state[idx], rc[idx]);
    }
    state[0] = poseidon_pow7(state[0]);
    poseidon_apply_mds(state);
}

__device__ void poseidon_permute(uint64_t state[POSEIDON_STATE_WIDTH]) {
    unsigned int round = 0;
    for (unsigned int i = 0; i < POSEIDON_FULL_ROUNDS_HALF; ++i, ++round) {
        poseidon_full_round(state, POSEIDON_ROUND_CONSTANTS[round]);
    }
    for (unsigned int i = 0; i < POSEIDON_PARTIAL_ROUNDS; ++i, ++round) {
        poseidon_partial_round(state, POSEIDON_ROUND_CONSTANTS[round]);
    }
    for (unsigned int i = 0; i < POSEIDON_FULL_ROUNDS_HALF; ++i, ++round) {
        poseidon_full_round(state, POSEIDON_ROUND_CONSTANTS[round]);
    }
}

__device__ __forceinline__ uint64_t bit_reverse_index(uint64_t index, uint32_t log_n) {
    return __brevll(index) >> (64 - log_n);
}

// -----------------------------------------------------------------------------.
// In-place radix-2 FFT (and inverse FFT) over a single column.
// -----------------------------------------------------------------------------
__device__ void fft_inplace_device(
    uint64_t* data,
    uint64_t len,
    uint32_t log_len,
    uint64_t root,
    bool inverse
) {
    for (uint64_t i = 1; i < len - 1; ++i) {
        uint64_t j = bit_reverse_index(i, log_len);
        if (i < j) {
            uint64_t tmp = data[i];
            data[i] = data[j];
            data[j] = tmp;
        }
    }

    uint64_t omega = inverse ? f_inv(root) : root;

    for (uint64_t size = 2; size <= len; size <<= 1) {
        uint64_t step = len / size;
        uint64_t wlen = f_pow(omega, step);
        uint64_t half = size >> 1;

        for (uint64_t start = 0; start < len; start += size) {
            uint64_t w = 1ull;
            for (uint64_t j = 0; j < half; ++j) {
                uint64_t u = data[start + j];
                uint64_t v = f_mul(data[start + j + half], w);
                data[start + j] = f_add(u, v);
                data[start + j + half] = f_sub(u, v);
                w = f_mul(w, wlen);
            }
        }
    }

    if (inverse) {
        uint64_t inv_len = f_inv((uint64_t)len);
        for (uint64_t i = 0; i < len; ++i) {
            data[i] = f_mul(data[i], inv_len);
        }
    }
}

// -----------------------------------------------------------------------------.
// Coset low-degree extension (coefficient → evaluation domain).
// -----------------------------------------------------------------------------
__device__ void lde_eval_device(
    const uint64_t* coeffs,
    uint64_t* out,
    uint64_t trace_len,
    uint64_t eval_len,
    uint32_t eval_log,
    uint64_t eval_root,
    uint64_t coset
) {
    uint64_t coset_pow = 1ull;
    for (uint64_t i = 0; i < trace_len; ++i) {
        out[i] = f_mul(coeffs[i], coset_pow);
        coset_pow = f_mul(coset_pow, coset);
    }
    for (uint64_t i = trace_len; i < eval_len; ++i) {
        out[i] = 0ull;
    }
    fft_inplace_device(out, eval_len, eval_log, eval_root, false);
}

// -----------------------------------------------------------------------------.
// CUDA kernels - each column handled by a single thread for determinism.
// -----------------------------------------------------------------------------
__global__ void fastpq_fft_kernel(
    uint64_t* elements,
    size_t column_count,
    uint64_t column_len,
    uint32_t log_len,
    uint64_t root
) {
    uint64_t col = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    if ((size_t)col >= column_count) {
        return;
    }
    uint64_t* column = elements + col * column_len;
    fft_inplace_device(column, column_len, log_len, root, false);
}

__global__ void fastpq_ifft_kernel(
    uint64_t* elements,
    size_t column_count,
    uint64_t column_len,
    uint32_t log_len,
    uint64_t root
) {
    uint64_t col = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    if ((size_t)col >= column_count) {
        return;
    }
    uint64_t* column = elements + col * column_len;
    fft_inplace_device(column, column_len, log_len, root, true);
}

__global__ void fastpq_lde_kernel(
    const uint64_t* coeffs,
    uint64_t* out,
    uint64_t trace_len,
    uint64_t eval_len,
    uint32_t eval_log,
    uint64_t eval_root,
    uint64_t coset
) {
    uint64_t col = blockIdx.x;
    const uint64_t* column_coeffs = coeffs + col * trace_len;
    uint64_t* out_column = out + col * eval_len;
    lde_eval_device(column_coeffs, out_column, trace_len, eval_len, eval_log, eval_root, coset);
}

__global__ void fastpq_bn254_fft_kernel(
    uint64_t* elements,
    size_t column_count,
    uint64_t column_len,
    uint32_t log_len,
    const uint64_t* stage_twiddles
) {
    size_t col = (size_t)blockIdx.x;
    if (col >= column_count || stage_twiddles == nullptr) {
        return;
    }
    uint64_t* column = elements + col * column_len * BN254_LIMBS;
    for (uint64_t idx = threadIdx.x; idx < column_len; idx += blockDim.x) {
        Bn254Value value = bn254_load(column + idx * BN254_LIMBS);
        bn254_store(column + idx * BN254_LIMBS, bn254_from_canonical(value));
    }
    __syncthreads();

    for (uint64_t idx = threadIdx.x; idx < column_len; idx += blockDim.x) {
        const uint64_t reversed = bit_reverse_index(idx, log_len);
        if (idx < reversed) {
            const Bn254Value value = bn254_load(column + idx * BN254_LIMBS);
            const Bn254Value reversed_value =
                bn254_load(column + reversed * BN254_LIMBS);
            bn254_store(column + idx * BN254_LIMBS, reversed_value);
            bn254_store(column + reversed * BN254_LIMBS, value);
        }
    }
    __syncthreads();

    uint64_t stage_span = column_len >> 1;
    for (uint32_t stage = 0; stage < log_len; ++stage) {
        uint64_t len = 1ull << (stage + 1u);
        uint64_t half_len = len >> 1;
        uint64_t stage_offset = (1ull << stage) - 1ull;
        for (uint64_t pair_idx = threadIdx.x; pair_idx < stage_span; pair_idx += blockDim.x) {
            uint64_t block = pair_idx / half_len;
            uint64_t pair = pair_idx % half_len;
            uint64_t idx = block * len + pair;
            if (idx + half_len >= column_len) {
                continue;
            }
            Bn254Value twiddle = bn254_from_canonical(
                bn254_load(stage_twiddles + (stage_offset + pair) * BN254_LIMBS)
            );
            Bn254Value u = bn254_load(column + idx * BN254_LIMBS);
            Bn254Value v = bn254_montgomery_mul(
                bn254_load(column + (idx + half_len) * BN254_LIMBS),
                twiddle
            );
            bn254_store(column + idx * BN254_LIMBS, bn254_add(u, v));
            bn254_store(column + (idx + half_len) * BN254_LIMBS, bn254_sub(u, v));
        }
        __syncthreads();
    }

    for (uint64_t idx = threadIdx.x; idx < column_len; idx += blockDim.x) {
        Bn254Value value = bn254_load(column + idx * BN254_LIMBS);
        bn254_store(column + idx * BN254_LIMBS, bn254_to_canonical(value));
    }
}

__global__ void fastpq_bn254_lde_kernel(
    const uint64_t* coeffs,
    uint64_t* out,
    uint64_t trace_len,
    uint64_t eval_len,
    uint32_t trace_log,
    uint32_t blowup_log,
    const uint64_t* stage_twiddles,
    const uint64_t* coset_limbs
) {
    size_t col = (size_t)blockIdx.x;
    if (stage_twiddles == nullptr || coset_limbs == nullptr) {
        return;
    }
    const uint64_t* coeff_column = coeffs + col * trace_len * BN254_LIMBS;
    uint64_t* out_column = out + col * eval_len * BN254_LIMBS;
    for (uint64_t idx = threadIdx.x; idx < trace_len; idx += blockDim.x) {
        Bn254Value value = bn254_load(coeff_column + idx * BN254_LIMBS);
        bn254_store(out_column + idx * BN254_LIMBS, bn254_from_canonical(value));
    }
    for (uint64_t idx = threadIdx.x + trace_len; idx < eval_len; idx += blockDim.x) {
        Bn254Value zero = {{0ull, 0ull, 0ull, 0ull}};
        bn254_store(out_column + idx * BN254_LIMBS, zero);
    }
    __syncthreads();

    const uint32_t log_len = trace_log + blowup_log;
    const uint64_t stage_span = eval_len >> 1;
    const Bn254Value coset_mont = bn254_from_canonical(bn254_load(coset_limbs));
    for (uint64_t idx = threadIdx.x; idx < trace_len; idx += blockDim.x) {
        Bn254Value value = bn254_load(out_column + idx * BN254_LIMBS);
        Bn254Value coset_power = bn254_pow_u64(coset_mont, idx);
        bn254_store(
            out_column + idx * BN254_LIMBS,
            bn254_montgomery_mul(value, coset_power)
        );
    }
    __syncthreads();

    for (uint64_t idx = threadIdx.x; idx < eval_len; idx += blockDim.x) {
        const uint64_t reversed = bit_reverse_index(idx, log_len);
        if (idx < reversed) {
            const Bn254Value value = bn254_load(out_column + idx * BN254_LIMBS);
            const Bn254Value reversed_value =
                bn254_load(out_column + reversed * BN254_LIMBS);
            bn254_store(out_column + idx * BN254_LIMBS, reversed_value);
            bn254_store(out_column + reversed * BN254_LIMBS, value);
        }
    }
    __syncthreads();

    for (uint32_t stage = 0; stage < log_len; ++stage) {
        const uint64_t len = 1ull << (stage + 1u);
        const uint64_t half_len = len >> 1;
        const uint64_t stage_offset = (1ull << stage) - 1ull;
        for (uint64_t pair_idx = threadIdx.x; pair_idx < stage_span; pair_idx += blockDim.x) {
            const uint64_t block = pair_idx / half_len;
            const uint64_t pair = pair_idx % half_len;
            const uint64_t idx = block * len + pair;
            if (idx + half_len >= eval_len) {
                continue;
            }
            Bn254Value twiddle = bn254_from_canonical(
                bn254_load(stage_twiddles + (stage_offset + pair) * BN254_LIMBS)
            );
            Bn254Value u = bn254_load(out_column + idx * BN254_LIMBS);
            Bn254Value v = bn254_montgomery_mul(
                bn254_load(out_column + (idx + half_len) * BN254_LIMBS),
                twiddle
            );
            bn254_store(out_column + idx * BN254_LIMBS, bn254_add(u, v));
            bn254_store(out_column + (idx + half_len) * BN254_LIMBS, bn254_sub(u, v));
        }
        __syncthreads();
    }

    for (uint64_t idx = threadIdx.x; idx < eval_len; idx += blockDim.x) {
        Bn254Value value = bn254_load(out_column + idx * BN254_LIMBS);
        bn254_store(out_column + idx * BN254_LIMBS, bn254_to_canonical(value));
    }
}

// Six independently generated width-three lanes over the canonical prepared
// frame; all parameters come from the shared fastpq_isi parameter generator.
__device__ void digest384_permute_v1(uint64_t state[3], size_t lane, const uint64_t* parameters) {
    for (size_t round = 0; round < 65; ++round) {
        for (size_t column = 0; column < 3; ++column)
            state[column] = f_add(state[column], parameters[18 + (lane * 65 + round) * 3 + column]);
        state[0] = poseidon_pow7(state[0]);
        if (round < 4 || round >= 61) {
            state[1] = poseidon_pow7(state[1]);
            state[2] = poseidon_pow7(state[2]);
        }
        uint64_t mixed[3];
        for (size_t row = 0; row < 3; ++row) {
            mixed[row] = 0;
            for (size_t column = 0; column < 3; ++column)
                mixed[row] = f_add(mixed[row], f_mul(parameters[1188 + row * 3 + column], state[column]));
        }
        for (size_t column = 0; column < 3; ++column) state[column] = mixed[column];
    }
}
__global__ void fastpq_digest384_hash_frames_v1_kernel(
    const uint64_t* words, size_t word_count, const uint64_t* descriptors,
    size_t frame_count, const uint64_t* parameters, uint64_t* output
) {
    size_t tid = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    size_t frame = tid / 6;
    size_t lane = tid % 6;
    if (frame >= frame_count) return;
    uint64_t offset = descriptors[frame * 3];
    uint64_t length = descriptors[frame * 3 + 1];
    uint64_t lane_word = descriptors[frame * 3 + 2];
    if (length == 0 || (length & 1) != 0 || offset > word_count
        || length > word_count - offset || lane_word >= length) {
        output[tid] = FIELD_MODULUS;
        return;
    }
    uint64_t state[3];
    for (size_t column = 0; column < 3; ++column) state[column] = parameters[lane * 3 + column];
    for (size_t index = 0; index < length; index += 2) {
        state[0] = f_add(state[0], index == lane_word ? (uint64_t)lane : words[offset + index]);
        state[1] = f_add(state[1], index + 1 == lane_word ? (uint64_t)lane : words[offset + index + 1]);
        digest384_permute_v1(state, lane, parameters);
    }
    output[tid] = state[0];
}

__global__ void fastpq_poseidon_permute_kernel(uint64_t* states, size_t state_count) {
    size_t idx = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= state_count) {
        return;
    }
    uint64_t local_state[POSEIDON_STATE_WIDTH];
    uint64_t* base = states + idx * POSEIDON_STATE_WIDTH;
    for (unsigned int i = 0; i < POSEIDON_STATE_WIDTH; ++i) {
        local_state[i] = base[i];
    }
    poseidon_permute(local_state);
    for (unsigned int i = 0; i < POSEIDON_STATE_WIDTH; ++i) {
        base[i] = local_state[i];
    }
}

__global__ void fastpq_poseidon_hash_columns_kernel(
    const uint64_t* payloads,
    const PoseidonSlice* slices,
    size_t block_count,
    size_t column_count,
    uint64_t* out_states
) {
    size_t col = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (col >= column_count) {
        return;
    }
    PoseidonSlice slice = slices[col];
    const uint64_t* column_payload = payloads + (size_t)slice.offset;
    uint64_t local_state[POSEIDON_STATE_WIDTH] = {0ull, 0ull, 0ull};
    for (size_t block = 0; block < block_count; ++block) {
        const uint64_t* block_ptr = column_payload + block * POSEIDON_RATE;
        for (unsigned int lane = 0; lane < POSEIDON_RATE; ++lane) {
            local_state[lane] = f_add(local_state[lane], block_ptr[lane]);
        }
        poseidon_permute(local_state);
    }
    uint64_t* out = out_states + col * POSEIDON_STATE_WIDTH;
    for (unsigned int lane = 0; lane < POSEIDON_STATE_WIDTH; ++lane) {
        out[lane] = local_state[lane];
    }
}

static constexpr unsigned int BN254_POSEIDON_WIDTH = 3u;
static constexpr unsigned int BN254_POSEIDON_FULL_ROUNDS_HALF = 4u;
static constexpr unsigned int BN254_POSEIDON_PARTIAL_ROUNDS = 57u;
static constexpr unsigned int BN254_POSEIDON_TOTAL_ROUNDS =
    BN254_POSEIDON_FULL_ROUNDS_HALF * 2u + BN254_POSEIDON_PARTIAL_ROUNDS;

__device__ __forceinline__ Bn254Value bn254_from_u64(uint64_t value) {
    Bn254Value raw = {{value, 0ull, 0ull, 0ull}};
    return bn254_from_canonical(raw);
}

__device__ __forceinline__ Bn254Value bn254_one() {
    return bn254_from_u64(1ull);
}

__device__ __forceinline__ Bn254Value bn254_pow5(const Bn254Value& value) {
    Bn254Value squared = bn254_montgomery_mul(value, value);
    Bn254Value fourth = bn254_montgomery_mul(squared, squared);
    return bn254_montgomery_mul(fourth, value);
}

__device__ __forceinline__ Bn254Value bn254_poseidon_constant(
    const uint64_t* constants,
    unsigned int index
) {
    return bn254_from_canonical(bn254_load(constants + (size_t)index * BN254_LIMBS));
}

__device__ void bn254_poseidon_apply_mds(
    Bn254Value state[BN254_POSEIDON_WIDTH],
    const uint64_t* mds
) {
    Bn254Value next[BN254_POSEIDON_WIDTH] = {bn254_zero(), bn254_zero(), bn254_zero()};
    for (unsigned int row = 0; row < BN254_POSEIDON_WIDTH; ++row) {
        Bn254Value acc = bn254_zero();
        for (unsigned int col = 0; col < BN254_POSEIDON_WIDTH; ++col) {
            unsigned int index = row * BN254_POSEIDON_WIDTH + col;
            Bn254Value coeff = bn254_poseidon_constant(mds, index);
            acc = bn254_add(acc, bn254_montgomery_mul(coeff, state[col]));
        }
        next[row] = acc;
    }
    for (unsigned int idx = 0; idx < BN254_POSEIDON_WIDTH; ++idx) {
        state[idx] = next[idx];
    }
}

__device__ void bn254_poseidon_permute(
    Bn254Value state[BN254_POSEIDON_WIDTH],
    const uint64_t* round_constants,
    const uint64_t* mds
) {
    for (unsigned int round = 0; round < BN254_POSEIDON_FULL_ROUNDS_HALF; ++round) {
        for (unsigned int word = 0; word < BN254_POSEIDON_WIDTH; ++word) {
            unsigned int index = round * BN254_POSEIDON_WIDTH + word;
            state[word] = bn254_pow5(
                bn254_add(state[word], bn254_poseidon_constant(round_constants, index))
            );
        }
        bn254_poseidon_apply_mds(state, mds);
    }

    for (unsigned int idx = 0; idx < BN254_POSEIDON_PARTIAL_ROUNDS; ++idx) {
        unsigned int round = BN254_POSEIDON_FULL_ROUNDS_HALF + idx;
        for (unsigned int word = 0; word < BN254_POSEIDON_WIDTH; ++word) {
            unsigned int index = round * BN254_POSEIDON_WIDTH + word;
            state[word] = bn254_add(
                state[word],
                bn254_poseidon_constant(round_constants, index)
            );
        }
        state[0] = bn254_pow5(state[0]);
        bn254_poseidon_apply_mds(state, mds);
    }

    unsigned int tail_start = BN254_POSEIDON_FULL_ROUNDS_HALF + BN254_POSEIDON_PARTIAL_ROUNDS;
    for (unsigned int idx = 0; idx < BN254_POSEIDON_FULL_ROUNDS_HALF; ++idx) {
        unsigned int round = tail_start + idx;
        for (unsigned int word = 0; word < BN254_POSEIDON_WIDTH; ++word) {
            unsigned int index = round * BN254_POSEIDON_WIDTH + word;
            state[word] = bn254_pow5(
                bn254_add(state[word], bn254_poseidon_constant(round_constants, index))
            );
        }
        bn254_poseidon_apply_mds(state, mds);
    }
}

__device__ __forceinline__ void bn254_poseidon_absorb_pair(
    Bn254Value state[BN254_POSEIDON_WIDTH],
    const Bn254Value& first,
    const Bn254Value& second,
    const uint64_t* round_constants,
    const uint64_t* mds
) {
    state[0] = bn254_add(state[0], first);
    state[1] = bn254_add(state[1], second);
    bn254_poseidon_permute(state, round_constants, mds);
}

__device__ Bn254Value bn254_poseidon_hash_slice(
    const uint64_t* words,
    PoseidonSlice slice,
    const uint64_t* round_constants,
    const uint64_t* mds
) {
    Bn254Value state[BN254_POSEIDON_WIDTH] = {bn254_zero(), bn254_zero(), bn254_zero()};
    uint32_t cursor = 0u;
    while (cursor + 1u < slice.len) {
        Bn254Value first = bn254_from_u64(words[(size_t)slice.offset + cursor]);
        Bn254Value second = bn254_from_u64(words[(size_t)slice.offset + cursor + 1u]);
        bn254_poseidon_absorb_pair(state, first, second, round_constants, mds);
        cursor += 2u;
    }
    if (cursor < slice.len) {
        Bn254Value first = bn254_from_u64(words[(size_t)slice.offset + cursor]);
        bn254_poseidon_absorb_pair(state, first, bn254_one(), round_constants, mds);
    } else {
        bn254_poseidon_absorb_pair(state, bn254_one(), bn254_zero(), round_constants, mds);
    }
    return bn254_to_canonical(state[0]);
}

__global__ void fastpq_bn254_poseidon_hash_words_kernel(
    const uint64_t* words,
    const PoseidonSlice* slices,
    size_t batch_count,
    const uint64_t* round_constants,
    const uint64_t* mds,
    uint64_t* out_hashes
) {
    size_t index = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= batch_count) {
        return;
    }
    Bn254Value hash = bn254_poseidon_hash_slice(
        words,
        slices[index],
        round_constants,
        mds
    );
    bn254_store(out_hashes + index * BN254_LIMBS, hash);
}

// -----------------------------------------------------------------------------.
// Public C interface.
// -----------------------------------------------------------------------------
extern "C" int fastpq_cuda_backend_quarantined_cuda() {
    return cuda_backend_is_quarantined() ? 1 : 0;
}

extern "C" cudaError_t fastpq_test_wait_timeout_cuda(uint32_t timeout_ms) {
    if (timeout_ms == 0) {
        return cudaErrorInvalidValue;
    }
    return wait_until_cuda_ready_for(
        std::chrono::milliseconds(timeout_ms),
        []() { return cudaErrorNotReady; }
    );
}

extern "C" cudaError_t fastpq_pending_wait_cuda(
    void* handle,
    uint64_t* output,
    size_t output_len
) {
    PendingTransform* pending = reinterpret_cast<PendingTransform*>(handle);
    if (pending == nullptr) {
        return cudaErrorInvalidValue;
    }

    cudaError_t status = cudaSetDevice(pending->device);
    if (async_status_requires_abandon(status)) {
        quarantine_cuda_backend();
        abandon_pending_transform(pending);
        return status;
    }

    status = wait_for_event(pending->event);
    if (async_status_requires_abandon(status)) {
        // The event, stream, device buffers, and pinned host buffers may still
        // be in use. Drop only the host handle; intentionally abandon every
        // CUDA resource and avoid a second stream wait.
        abandon_pending_transform(pending);
        return status;
    }
    if (status == cudaSuccess && output != nullptr) {
        size_t output_byte_len = 0;
        if (
            pending->staging_output == nullptr
            || !checked_size_mul(output_len, sizeof(uint64_t), &output_byte_len)
            || output_byte_len != pending->output_byte_len
        ) {
            status = cudaErrorInvalidValue;
        } else {
            memcpy(output, pending->staging_output, pending->output_byte_len);
        }
    } else if (status == cudaSuccess && output_len != 0) {
        status = cudaErrorInvalidValue;
    }
    cudaError_t destroy_status = destroy_pending_transform(pending);
    if (status == cudaSuccess) {
        status = destroy_status;
    }
    return status;
}

extern "C" cudaError_t fastpq_fft_async_submit_cuda(
    uint64_t* elements,
    size_t column_count,
    uint32_t log_size,
    uint64_t root,
    void** out_handle
) {
    if (elements == nullptr || column_count == 0 || out_handle == nullptr) {
        return cudaErrorInvalidValue;
    }
    *out_handle = nullptr;
    uint64_t n = 0;
    if (!checked_domain_len(log_size, GOLDILOCKS_TWO_ADICITY, &n)) {
        return cudaErrorInvalidValue;
    }
    size_t byte_len = 0;
    cudaError_t status = dense_buffer_bytes(column_count, n, &byte_len);
    if (status != cudaSuccess) {
        return status;
    }
    const unsigned int threads_per_block = 128u;
    unsigned int grid_size = 0;
    if (!checked_grid_size(column_count, threads_per_block, &grid_size)) {
        return cudaErrorInvalidValue;
    }

    int device = 0;
    status = cudaGetDevice(&device);
    if (status != cudaSuccess) {
        return status;
    }
    AsyncDispatchBuffers* buffers = acquire_async_dispatch_buffers(device);
    if (buffers == nullptr) {
        return cudaErrorMemoryAllocation;
    }
    status = ensure_workspace_buffer(
        &buffers->dense,
        &buffers->dense_capacity_bytes,
        byte_len
    );
    if (status != cudaSuccess) {
        release_async_dispatch_buffers(buffers);
        return status;
    }
    status = ensure_pinned_workspace_buffer(
        &buffers->host_dense,
        &buffers->host_dense_capacity_bytes,
        byte_len
    );
    if (status != cudaSuccess) {
        release_async_dispatch_buffers(buffers);
        return status;
    }
    status = ensure_async_dispatch_stream(buffers);
    if (status != cudaSuccess) {
        release_async_dispatch_buffers(buffers);
        return status;
    }
    memcpy(buffers->host_dense, elements, byte_len);
    uint64_t* host_dense_io = buffers->host_dense;
    void* staging_output = buffers->host_dense;

    PendingTransform* pending = nullptr;
    status = create_pending_transform(
        device,
        buffers,
        staging_output,
        byte_len,
        &pending
    );
    if (status != cudaSuccess) {
        release_async_dispatch_buffers(buffers);
        return status;
    }

    status = cudaMemcpyAsync(
        buffers->dense,
        host_dense_io,
        byte_len,
        cudaMemcpyHostToDevice,
        buffers->stream
    );
    if (status != cudaSuccess) {
        destroy_pending_transform(pending);
        return status;
    }
    fastpq_fft_kernel<<<grid_size, threads_per_block, 0, buffers->stream>>>(
        buffers->dense,
        column_count,
        n,
        log_size,
        root
    );
    status = cudaGetLastError();
    if (status != cudaSuccess) {
        destroy_pending_transform(pending);
        return status;
    }
    status = cudaMemcpyAsync(
        staging_output,
        buffers->dense,
        byte_len,
        cudaMemcpyDeviceToHost,
        buffers->stream
    );
    if (status != cudaSuccess) {
        destroy_pending_transform(pending);
        return status;
    }
    status = cudaEventRecord(pending->event, buffers->stream);
    if (async_status_requires_abandon(status)) {
        quarantine_cuda_backend();
        abandon_pending_transform(pending);
        return status;
    }
    *out_handle = pending;
    return cudaSuccess;
}

extern "C" cudaError_t fastpq_ifft_async_submit_cuda(
    uint64_t* elements,
    size_t column_count,
    uint32_t log_size,
    uint64_t root,
    void** out_handle
) {
    if (elements == nullptr || column_count == 0 || out_handle == nullptr) {
        return cudaErrorInvalidValue;
    }
    *out_handle = nullptr;
    uint64_t n = 0;
    if (!checked_domain_len(log_size, GOLDILOCKS_TWO_ADICITY, &n)) {
        return cudaErrorInvalidValue;
    }
    size_t byte_len = 0;
    cudaError_t status = dense_buffer_bytes(column_count, n, &byte_len);
    if (status != cudaSuccess) {
        return status;
    }
    const unsigned int threads_per_block = 128u;
    unsigned int grid_size = 0;
    if (!checked_grid_size(column_count, threads_per_block, &grid_size)) {
        return cudaErrorInvalidValue;
    }

    int device = 0;
    status = cudaGetDevice(&device);
    if (status != cudaSuccess) {
        return status;
    }
    AsyncDispatchBuffers* buffers = acquire_async_dispatch_buffers(device);
    if (buffers == nullptr) {
        return cudaErrorMemoryAllocation;
    }
    status = ensure_workspace_buffer(
        &buffers->dense,
        &buffers->dense_capacity_bytes,
        byte_len
    );
    if (status != cudaSuccess) {
        release_async_dispatch_buffers(buffers);
        return status;
    }
    status = ensure_pinned_workspace_buffer(
        &buffers->host_dense,
        &buffers->host_dense_capacity_bytes,
        byte_len
    );
    if (status != cudaSuccess) {
        release_async_dispatch_buffers(buffers);
        return status;
    }
    status = ensure_async_dispatch_stream(buffers);
    if (status != cudaSuccess) {
        release_async_dispatch_buffers(buffers);
        return status;
    }
    memcpy(buffers->host_dense, elements, byte_len);
    uint64_t* host_dense_io = buffers->host_dense;
    void* staging_output = buffers->host_dense;

    PendingTransform* pending = nullptr;
    status = create_pending_transform(
        device,
        buffers,
        staging_output,
        byte_len,
        &pending
    );
    if (status != cudaSuccess) {
        release_async_dispatch_buffers(buffers);
        return status;
    }

    status = cudaMemcpyAsync(
        buffers->dense,
        host_dense_io,
        byte_len,
        cudaMemcpyHostToDevice,
        buffers->stream
    );
    if (status != cudaSuccess) {
        destroy_pending_transform(pending);
        return status;
    }
    fastpq_ifft_kernel<<<grid_size, threads_per_block, 0, buffers->stream>>>(
        buffers->dense,
        column_count,
        n,
        log_size,
        root
    );
    status = cudaGetLastError();
    if (status != cudaSuccess) {
        destroy_pending_transform(pending);
        return status;
    }
    status = cudaMemcpyAsync(
        staging_output,
        buffers->dense,
        byte_len,
        cudaMemcpyDeviceToHost,
        buffers->stream
    );
    if (status != cudaSuccess) {
        destroy_pending_transform(pending);
        return status;
    }
    status = cudaEventRecord(pending->event, buffers->stream);
    if (async_status_requires_abandon(status)) {
        quarantine_cuda_backend();
        abandon_pending_transform(pending);
        return status;
    }
    *out_handle = pending;
    return cudaSuccess;
}

extern "C" cudaError_t fastpq_lde_async_submit_cuda(
    const uint64_t* coeffs,
    size_t column_count,
    uint32_t trace_log,
    uint32_t blowup_log,
    uint64_t lde_root,
    uint64_t coset,
    uint64_t* out,
    void** out_handle
) {
    if (coeffs == nullptr || out == nullptr || column_count == 0 || out_handle == nullptr) {
        return cudaErrorInvalidValue;
    }
    *out_handle = nullptr;
    uint64_t trace_len = 0;
    uint64_t eval_len = 0;
    uint32_t eval_log = 0;
    if (!checked_eval_domain_lengths(
            trace_log,
            blowup_log,
            GOLDILOCKS_TWO_ADICITY,
            &trace_len,
            &eval_len,
            &eval_log
        )) {
        return cudaErrorInvalidValue;
    }

    size_t coeff_byte_len = 0;
    cudaError_t status = dense_buffer_bytes(column_count, trace_len, &coeff_byte_len);
    if (status != cudaSuccess) {
        return status;
    }
    size_t eval_byte_len = 0;
    status = dense_buffer_bytes(column_count, eval_len, &eval_byte_len);
    if (status != cudaSuccess) {
        return status;
    }
    unsigned int grid_size = 0;
    if (!checked_grid_size(column_count, 1u, &grid_size)) {
        return cudaErrorInvalidValue;
    }

    int device = 0;
    status = cudaGetDevice(&device);
    if (status != cudaSuccess) {
        return status;
    }
    AsyncDispatchBuffers* buffers = acquire_async_dispatch_buffers(device);
    if (buffers == nullptr) {
        return cudaErrorMemoryAllocation;
    }
    status = ensure_workspace_buffer(
        &buffers->coeffs,
        &buffers->coeff_capacity_bytes,
        coeff_byte_len
    );
    if (status != cudaSuccess) {
        release_async_dispatch_buffers(buffers);
        return status;
    }
    status = ensure_workspace_buffer(
        &buffers->evals,
        &buffers->eval_capacity_bytes,
        eval_byte_len
    );
    if (status != cudaSuccess) {
        release_async_dispatch_buffers(buffers);
        return status;
    }
    status = ensure_pinned_workspace_buffer(
        &buffers->host_coeffs,
        &buffers->host_coeff_capacity_bytes,
        coeff_byte_len
    );
    if (status != cudaSuccess) {
        release_async_dispatch_buffers(buffers);
        return status;
    }
    status = ensure_pinned_workspace_buffer(
        &buffers->host_evals,
        &buffers->host_eval_capacity_bytes,
        eval_byte_len
    );
    if (status != cudaSuccess) {
        release_async_dispatch_buffers(buffers);
        return status;
    }
    status = ensure_async_dispatch_stream(buffers);
    if (status != cudaSuccess) {
        release_async_dispatch_buffers(buffers);
        return status;
    }
    memcpy(buffers->host_coeffs, coeffs, coeff_byte_len);
    const uint64_t* host_coeff_input = buffers->host_coeffs;
    uint64_t* host_eval_output = buffers->host_evals;
    void* staging_output = buffers->host_evals;

    PendingTransform* pending = nullptr;
    status = create_pending_transform(
        device,
        buffers,
        staging_output,
        eval_byte_len,
        &pending
    );
    if (status != cudaSuccess) {
        release_async_dispatch_buffers(buffers);
        return status;
    }

    status = cudaMemcpyAsync(
        buffers->coeffs,
        host_coeff_input,
        coeff_byte_len,
        cudaMemcpyHostToDevice,
        buffers->stream
    );
    if (status != cudaSuccess) {
        destroy_pending_transform(pending);
        return status;
    }
    fastpq_lde_kernel<<<grid_size, 1, 0, buffers->stream>>>(
        buffers->coeffs,
        buffers->evals,
        trace_len,
        eval_len,
        eval_log,
        lde_root,
        coset
    );
    status = cudaGetLastError();
    if (status != cudaSuccess) {
        destroy_pending_transform(pending);
        return status;
    }
    status = cudaMemcpyAsync(
        host_eval_output,
        buffers->evals,
        eval_byte_len,
        cudaMemcpyDeviceToHost,
        buffers->stream
    );
    if (status != cudaSuccess) {
        destroy_pending_transform(pending);
        return status;
    }
    status = cudaEventRecord(pending->event, buffers->stream);
    if (async_status_requires_abandon(status)) {
        quarantine_cuda_backend();
        abandon_pending_transform(pending);
        return status;
    }
    *out_handle = pending;
    return cudaSuccess;
}

extern "C" cudaError_t fastpq_bn254_fft_cuda(
    uint64_t* elements,
    size_t column_count,
    uint32_t log_size,
    const uint64_t* stage_twiddles,
    size_t stage_twiddle_len
) {
    if (elements == nullptr || stage_twiddles == nullptr || column_count == 0 || stage_twiddle_len == 0) {
        return cudaErrorInvalidValue;
    }
    uint64_t n = 0;
    if (log_size == 0u || !checked_domain_len(log_size, BN254_TWO_ADICITY, &n)) {
        return cudaErrorInvalidValue;
    }
    size_t expected_twiddle_len = 0;
    if (
        !checked_bn254_twiddle_limb_len(log_size, n, &expected_twiddle_len)
        || stage_twiddle_len != expected_twiddle_len
    ) {
        return cudaErrorInvalidValue;
    }
    size_t dense_byte_len = 0;
    cudaError_t status = bn254_dense_buffer_bytes(column_count, n, &dense_byte_len);
    if (status != cudaSuccess) {
        return status;
    }
    size_t twiddle_byte_len = 0;
    status = limb_buffer_bytes(stage_twiddle_len, &twiddle_byte_len);
    if (status != cudaSuccess) {
        return status;
    }
    unsigned int grid_size = 0;
    if (!checked_grid_size(column_count, 1u, &grid_size)) {
        return cudaErrorInvalidValue;
    }
    std::lock_guard<std::mutex> guard(transform_workspace_mutex());
    TransformWorkspace* workspace = current_transform_workspace();
    if (workspace == nullptr) {
        return cudaErrorInvalidValue;
    }
    status = ensure_workspace_buffer(
        &workspace->dense,
        &workspace->dense_capacity_bytes,
        dense_byte_len
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_workspace_buffer(
        &workspace->bn254_twiddles,
        &workspace->bn254_twiddle_capacity_bytes,
        twiddle_byte_len
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_pinned_workspace_buffer(
        &workspace->host_dense,
        &workspace->host_dense_capacity_bytes,
        dense_byte_len
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_pinned_workspace_buffer(
        &workspace->host_bn254_twiddles,
        &workspace->host_bn254_twiddle_capacity_bytes,
        twiddle_byte_len
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_transform_stream(workspace);
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_transform_event(workspace);
    if (status != cudaSuccess) {
        return status;
    }
    memcpy(workspace->host_dense, elements, dense_byte_len);
    memcpy(workspace->host_bn254_twiddles, stage_twiddles, twiddle_byte_len);
    status = cudaMemcpyAsync(
        workspace->dense,
        workspace->host_dense,
        dense_byte_len,
        cudaMemcpyHostToDevice,
        workspace->stream
    );
    if (status != cudaSuccess) {
        return fail_transform_dispatch(workspace, status);
    }
    status = cudaMemcpyAsync(
        workspace->bn254_twiddles,
        workspace->host_bn254_twiddles,
        twiddle_byte_len,
        cudaMemcpyHostToDevice,
        workspace->stream
    );
    if (status != cudaSuccess) {
        return fail_transform_dispatch(workspace, status);
    }
    const unsigned int threads_per_block = 128u;
    fastpq_bn254_fft_kernel<<<grid_size, threads_per_block, 0, workspace->stream>>>(
        workspace->dense,
        column_count,
        n,
        log_size,
        workspace->bn254_twiddles
    );
    status = cudaGetLastError();
    if (status != cudaSuccess) {
        return fail_transform_dispatch(workspace, status);
    }
    status = cudaMemcpyAsync(
        workspace->host_dense,
        workspace->dense,
        dense_byte_len,
        cudaMemcpyDeviceToHost,
        workspace->stream
    );
    if (status != cudaSuccess) {
        return fail_transform_dispatch(workspace, status);
    }
    status = wait_for_transform_event_after_copy(workspace);
    if (status != cudaSuccess) {
        return status;
    }
    memcpy(elements, workspace->host_dense, dense_byte_len);
    status = scrub_completed_transform(workspace);
    return fail_transform_dispatch(workspace, status);
}

extern "C" cudaError_t fastpq_bn254_lde_cuda(
    const uint64_t* coeffs,
    size_t column_count,
    uint32_t trace_log,
    uint32_t blowup_log,
    const uint64_t* stage_twiddles,
    size_t stage_twiddle_len,
    const uint64_t* coset,
    uint64_t* out
) {
    if (
        coeffs == nullptr || stage_twiddles == nullptr || coset == nullptr || out == nullptr
        || column_count == 0 || stage_twiddle_len == 0
    ) {
        return cudaErrorInvalidValue;
    }
    uint64_t trace_len = 0;
    uint64_t eval_len = 0;
    uint32_t eval_log = 0;
    if (
        trace_log == 0u
        || !checked_eval_domain_lengths(
            trace_log,
            blowup_log,
            BN254_TWO_ADICITY,
            &trace_len,
            &eval_len,
            &eval_log
        )
    ) {
        return cudaErrorInvalidValue;
    }
    size_t expected_twiddle_len = 0;
    if (
        !checked_bn254_twiddle_limb_len(eval_log, eval_len, &expected_twiddle_len)
        || stage_twiddle_len != expected_twiddle_len
    ) {
        return cudaErrorInvalidValue;
    }
    size_t coeff_byte_len = 0;
    cudaError_t status = bn254_dense_buffer_bytes(column_count, trace_len, &coeff_byte_len);
    if (status != cudaSuccess) {
        return status;
    }
    size_t eval_byte_len = 0;
    status = bn254_dense_buffer_bytes(column_count, eval_len, &eval_byte_len);
    if (status != cudaSuccess) {
        return status;
    }
    size_t twiddle_byte_len = 0;
    status = limb_buffer_bytes(stage_twiddle_len, &twiddle_byte_len);
    if (status != cudaSuccess) {
        return status;
    }
    size_t coset_byte_len = 0;
    status = limb_buffer_bytes(BN254_LIMBS, &coset_byte_len);
    if (status != cudaSuccess) {
        return status;
    }
    unsigned int grid_size = 0;
    if (!checked_grid_size(column_count, 1u, &grid_size)) {
        return cudaErrorInvalidValue;
    }
    std::lock_guard<std::mutex> guard(transform_workspace_mutex());
    TransformWorkspace* workspace = current_transform_workspace();
    if (workspace == nullptr) {
        return cudaErrorInvalidValue;
    }
    status = ensure_workspace_buffer(
        &workspace->coeffs,
        &workspace->coeff_capacity_bytes,
        coeff_byte_len
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_workspace_buffer(
        &workspace->evals,
        &workspace->eval_capacity_bytes,
        eval_byte_len
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_workspace_buffer(
        &workspace->bn254_twiddles,
        &workspace->bn254_twiddle_capacity_bytes,
        twiddle_byte_len
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_workspace_buffer(
        &workspace->bn254_coset,
        &workspace->bn254_coset_capacity_bytes,
        coset_byte_len
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_pinned_workspace_buffer(
        &workspace->host_coeffs,
        &workspace->host_coeff_capacity_bytes,
        coeff_byte_len
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_pinned_workspace_buffer(
        &workspace->host_evals,
        &workspace->host_eval_capacity_bytes,
        eval_byte_len
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_pinned_workspace_buffer(
        &workspace->host_bn254_twiddles,
        &workspace->host_bn254_twiddle_capacity_bytes,
        twiddle_byte_len
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_pinned_workspace_buffer(
        &workspace->host_bn254_coset,
        &workspace->host_bn254_coset_capacity_bytes,
        coset_byte_len
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_transform_stream(workspace);
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_transform_event(workspace);
    if (status != cudaSuccess) {
        return status;
    }
    memcpy(workspace->host_coeffs, coeffs, coeff_byte_len);
    memcpy(workspace->host_bn254_twiddles, stage_twiddles, twiddle_byte_len);
    memcpy(workspace->host_bn254_coset, coset, coset_byte_len);
    status = cudaMemcpyAsync(
        workspace->coeffs,
        workspace->host_coeffs,
        coeff_byte_len,
        cudaMemcpyHostToDevice,
        workspace->stream
    );
    if (status != cudaSuccess) {
        return fail_transform_dispatch(workspace, status);
    }
    status = cudaMemcpyAsync(
        workspace->bn254_twiddles,
        workspace->host_bn254_twiddles,
        twiddle_byte_len,
        cudaMemcpyHostToDevice,
        workspace->stream
    );
    if (status != cudaSuccess) {
        return fail_transform_dispatch(workspace, status);
    }
    status = cudaMemcpyAsync(
        workspace->bn254_coset,
        workspace->host_bn254_coset,
        coset_byte_len,
        cudaMemcpyHostToDevice,
        workspace->stream
    );
    if (status != cudaSuccess) {
        return fail_transform_dispatch(workspace, status);
    }
    const unsigned int threads_per_block = 128u;
    fastpq_bn254_lde_kernel<<<grid_size, threads_per_block, 0, workspace->stream>>>(
        workspace->coeffs,
        workspace->evals,
        trace_len,
        eval_len,
        trace_log,
        blowup_log,
        workspace->bn254_twiddles,
        workspace->bn254_coset
    );
    status = cudaGetLastError();
    if (status != cudaSuccess) {
        return fail_transform_dispatch(workspace, status);
    }
    status = cudaMemcpyAsync(
        workspace->host_evals,
        workspace->evals,
        eval_byte_len,
        cudaMemcpyDeviceToHost,
        workspace->stream
    );
    if (status != cudaSuccess) {
        return fail_transform_dispatch(workspace, status);
    }
    status = wait_for_transform_event_after_copy(workspace);
    if (status != cudaSuccess) {
        return status;
    }
    memcpy(out, workspace->host_evals, eval_byte_len);
    status = scrub_completed_transform(workspace);
    return fail_transform_dispatch(workspace, status);
}

extern "C" cudaError_t fastpq_poseidon_permute_cuda(uint64_t* states, size_t state_count) {
    if (states == nullptr || state_count == 0) {
        return cudaErrorInvalidValue;
    }

    size_t byte_len = 0;
    cudaError_t status = dense_buffer_bytes(state_count, POSEIDON_STATE_WIDTH, &byte_len);
    if (status != cudaSuccess) {
        return status;
    }
    const unsigned int threads_per_block = 128u;
    unsigned int grid_size = 0;
    if (!checked_grid_size(state_count, threads_per_block, &grid_size)) {
        return cudaErrorInvalidValue;
    }

    std::lock_guard<std::mutex> guard(poseidon_workspace_mutex());
    PoseidonWorkspace* workspace = current_poseidon_workspace();
    if (workspace == nullptr) {
        return cudaErrorInvalidValue;
    }
    status = ensure_workspace_buffer(
        &workspace->states,
        &workspace->state_capacity_bytes,
        byte_len
    );
    if (status != cudaSuccess) {
        return status;
    }
    uint64_t* device_states = workspace->states;

    status = ensure_pinned_workspace_buffer(
        &workspace->host_states,
        &workspace->host_state_capacity_bytes,
        byte_len
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_poseidon_stream(workspace);
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_poseidon_event(workspace);
    if (status != cudaSuccess) {
        return status;
    }
    memcpy(workspace->host_states, states, byte_len);
    status = cudaMemcpyAsync(
        device_states,
        workspace->host_states,
        byte_len,
        cudaMemcpyHostToDevice,
        workspace->stream
    );
    if (status != cudaSuccess) {
        return fail_poseidon_dispatch(workspace, status);
    }

    fastpq_poseidon_permute_kernel<<<grid_size, threads_per_block, 0, workspace->stream>>>(
        device_states,
        state_count
    );
    status = cudaGetLastError();
    if (status != cudaSuccess) {
        return fail_poseidon_dispatch(workspace, status);
    }
    status = cudaMemcpyAsync(
        workspace->host_states,
        device_states,
        byte_len,
        cudaMemcpyDeviceToHost,
        workspace->stream
    );
    if (status != cudaSuccess) {
        return fail_poseidon_dispatch(workspace, status);
    }
    status = wait_for_poseidon_event_after_copy(workspace);
    if (status != cudaSuccess) {
        return status;
    }
    memcpy(states, workspace->host_states, byte_len);
    status = scrub_completed_poseidon(workspace);
    return fail_poseidon_dispatch(workspace, status);
}

extern "C" cudaError_t fastpq_poseidon_hash_columns_cuda(
    const uint64_t* payloads,
    const PoseidonSlice* slices,
    size_t column_count,
    size_t block_count,
    uint64_t* out_states
) {
    if (
        payloads == nullptr || slices == nullptr || out_states == nullptr || column_count == 0
        || block_count == 0
    ) {
        return cudaErrorInvalidValue;
    }
    size_t payload_bytes = 0;
    if (!validate_poseidon_column_slices(slices, column_count, block_count, &payload_bytes)) {
        return cudaErrorInvalidValue;
    }
    size_t state_bytes = 0;
    cudaError_t status = dense_buffer_bytes(column_count, POSEIDON_STATE_WIDTH, &state_bytes);
    if (status != cudaSuccess) {
        return status;
    }
    size_t slice_bytes = 0;
    if (!checked_size_mul(column_count, sizeof(PoseidonSlice), &slice_bytes)) {
        return cudaErrorInvalidValue;
    }
    const unsigned int threads_per_block = 128u;
    unsigned int grid_size = 0;
    if (!checked_grid_size(column_count, threads_per_block, &grid_size)) {
        return cudaErrorInvalidValue;
    }

    std::lock_guard<std::mutex> guard(poseidon_workspace_mutex());
    PoseidonWorkspace* workspace = current_poseidon_workspace();
    if (workspace == nullptr) {
        return cudaErrorInvalidValue;
    }
    status = ensure_workspace_buffer(
        &workspace->payloads,
        &workspace->payload_capacity_bytes,
        payload_bytes
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_workspace_buffer(
        &workspace->slices,
        &workspace->slice_capacity_bytes,
        slice_bytes
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_workspace_buffer(
        &workspace->states,
        &workspace->state_capacity_bytes,
        state_bytes
    );
    if (status != cudaSuccess) {
        return status;
    }
    uint64_t* device_payloads = workspace->payloads;
    PoseidonSlice* device_slices = workspace->slices;
    uint64_t* device_states = workspace->states;

    status = ensure_pinned_workspace_buffer(
        &workspace->host_payloads,
        &workspace->host_payload_capacity_bytes,
        payload_bytes
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_pinned_workspace_buffer(
        &workspace->host_slices,
        &workspace->host_slice_capacity_bytes,
        slice_bytes
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_pinned_workspace_buffer(
        &workspace->host_states,
        &workspace->host_state_capacity_bytes,
        state_bytes
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_poseidon_stream(workspace);
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_poseidon_event(workspace);
    if (status != cudaSuccess) {
        return status;
    }
    memcpy(workspace->host_payloads, payloads, payload_bytes);
    memcpy(workspace->host_slices, slices, slice_bytes);
    status = cudaMemcpyAsync(
        device_payloads,
        workspace->host_payloads,
        payload_bytes,
        cudaMemcpyHostToDevice,
        workspace->stream
    );
    if (status != cudaSuccess) {
        return fail_poseidon_dispatch(workspace, status);
    }
    status = cudaMemcpyAsync(
        device_slices,
        workspace->host_slices,
        slice_bytes,
        cudaMemcpyHostToDevice,
        workspace->stream
    );
    if (status != cudaSuccess) {
        return fail_poseidon_dispatch(workspace, status);
    }

    fastpq_poseidon_hash_columns_kernel<<<grid_size, threads_per_block, 0, workspace->stream>>>(
        device_payloads,
        device_slices,
        block_count,
        column_count,
        device_states
    );
    status = cudaGetLastError();
    if (status != cudaSuccess) {
        return fail_poseidon_dispatch(workspace, status);
    }
    status = cudaMemcpyAsync(
        workspace->host_states,
        device_states,
        state_bytes,
        cudaMemcpyDeviceToHost,
        workspace->stream
    );
    if (status != cudaSuccess) {
        return fail_poseidon_dispatch(workspace, status);
    }
    status = wait_for_poseidon_event_after_copy(workspace);
    if (status != cudaSuccess) {
        return status;
    }
    memcpy(out_states, workspace->host_states, state_bytes);
    status = scrub_completed_poseidon(workspace);
    return fail_poseidon_dispatch(workspace, status);
}

extern "C" cudaError_t fastpq_bn254_poseidon_hash_words_cuda(
    const uint64_t* words,
    size_t word_count,
    const PoseidonSlice* slices,
    size_t batch_count,
    const uint64_t* round_constants,
    size_t round_constant_len,
    const uint64_t* mds,
    size_t mds_len,
    uint64_t* out_hashes
) {
    if (
        words == nullptr || slices == nullptr || round_constants == nullptr || mds == nullptr
        || out_hashes == nullptr || batch_count == 0
        || round_constant_len != (size_t)BN254_POSEIDON_TOTAL_ROUNDS * BN254_POSEIDON_WIDTH * BN254_LIMBS
        || mds_len != (size_t)BN254_POSEIDON_WIDTH * BN254_POSEIDON_WIDTH * BN254_LIMBS
    ) {
        return cudaErrorInvalidValue;
    }

    if (!validate_poseidon_word_slices(slices, batch_count, word_count)) {
        return cudaErrorInvalidValue;
    }
    size_t word_bytes = 0;
    size_t slice_bytes = 0;
    size_t round_bytes = 0;
    size_t mds_bytes = 0;
    size_t output_elements = 0;
    size_t output_bytes = 0;
    if (
        !checked_size_mul(word_count, sizeof(uint64_t), &word_bytes)
        || !checked_size_mul(batch_count, sizeof(PoseidonSlice), &slice_bytes)
        || !checked_size_mul(round_constant_len, sizeof(uint64_t), &round_bytes)
        || !checked_size_mul(mds_len, sizeof(uint64_t), &mds_bytes)
        || !checked_size_mul(batch_count, (size_t)BN254_LIMBS, &output_elements)
        || !checked_size_mul(output_elements, sizeof(uint64_t), &output_bytes)
    ) {
        return cudaErrorInvalidValue;
    }
    const unsigned int threads_per_block = 128u;
    unsigned int grid_size = 0;
    if (!checked_grid_size(batch_count, threads_per_block, &grid_size)) {
        return cudaErrorInvalidValue;
    }

    std::lock_guard<std::mutex> guard(poseidon_workspace_mutex());
    PoseidonWorkspace* workspace = current_poseidon_workspace();
    if (workspace == nullptr) {
        return cudaErrorInvalidValue;
    }
    cudaError_t status = ensure_workspace_buffer(
        &workspace->payloads,
        &workspace->payload_capacity_bytes,
        word_bytes
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_workspace_buffer(
        &workspace->slices,
        &workspace->slice_capacity_bytes,
        slice_bytes
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_workspace_buffer(
        &workspace->bn254_round_constants,
        &workspace->bn254_round_capacity_bytes,
        round_bytes
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_workspace_buffer(
        &workspace->bn254_mds,
        &workspace->bn254_mds_capacity_bytes,
        mds_bytes
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_workspace_buffer(
        &workspace->hashes,
        &workspace->hash_capacity_bytes,
        output_bytes
    );
    if (status != cudaSuccess) {
        return status;
    }

    status = ensure_pinned_workspace_buffer(
        &workspace->host_payloads,
        &workspace->host_payload_capacity_bytes,
        word_bytes
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_pinned_workspace_buffer(
        &workspace->host_slices,
        &workspace->host_slice_capacity_bytes,
        slice_bytes
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_pinned_workspace_buffer(
        &workspace->host_bn254_round_constants,
        &workspace->host_bn254_round_capacity_bytes,
        round_bytes
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_pinned_workspace_buffer(
        &workspace->host_bn254_mds,
        &workspace->host_bn254_mds_capacity_bytes,
        mds_bytes
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_pinned_workspace_buffer(
        &workspace->host_hashes,
        &workspace->host_hash_capacity_bytes,
        output_bytes
    );
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_poseidon_stream(workspace);
    if (status != cudaSuccess) {
        return status;
    }
    status = ensure_poseidon_event(workspace);
    if (status != cudaSuccess) {
        return status;
    }

    memcpy(workspace->host_payloads, words, word_bytes);
    memcpy(workspace->host_slices, slices, slice_bytes);
    memcpy(workspace->host_bn254_round_constants, round_constants, round_bytes);
    memcpy(workspace->host_bn254_mds, mds, mds_bytes);
    status = cudaMemcpyAsync(
        workspace->payloads,
        workspace->host_payloads,
        word_bytes,
        cudaMemcpyHostToDevice,
        workspace->stream
    );
    if (status != cudaSuccess) {
        return fail_poseidon_dispatch(workspace, status);
    }
    status = cudaMemcpyAsync(
        workspace->slices,
        workspace->host_slices,
        slice_bytes,
        cudaMemcpyHostToDevice,
        workspace->stream
    );
    if (status != cudaSuccess) {
        return fail_poseidon_dispatch(workspace, status);
    }
    status = cudaMemcpyAsync(
        workspace->bn254_round_constants,
        workspace->host_bn254_round_constants,
        round_bytes,
        cudaMemcpyHostToDevice,
        workspace->stream
    );
    if (status != cudaSuccess) {
        return fail_poseidon_dispatch(workspace, status);
    }
    status = cudaMemcpyAsync(
        workspace->bn254_mds,
        workspace->host_bn254_mds,
        mds_bytes,
        cudaMemcpyHostToDevice,
        workspace->stream
    );
    if (status != cudaSuccess) {
        return fail_poseidon_dispatch(workspace, status);
    }
    fastpq_bn254_poseidon_hash_words_kernel<<<grid_size, threads_per_block, 0, workspace->stream>>>(
        workspace->payloads,
        workspace->slices,
        batch_count,
        workspace->bn254_round_constants,
        workspace->bn254_mds,
        workspace->hashes
    );
    status = cudaGetLastError();
    if (status != cudaSuccess) {
        return fail_poseidon_dispatch(workspace, status);
    }
    status = cudaMemcpyAsync(
        workspace->host_hashes,
        workspace->hashes,
        output_bytes,
        cudaMemcpyDeviceToHost,
        workspace->stream
    );
    if (status != cudaSuccess) {
        return fail_poseidon_dispatch(workspace, status);
    }
    status = wait_for_poseidon_event_after_copy(workspace);
    if (status != cudaSuccess) {
        return status;
    }
    memcpy(out_hashes, workspace->host_hashes, output_bytes);
    status = scrub_completed_poseidon(workspace);
    return fail_poseidon_dispatch(workspace, status);
}

// This path retains the exact failed workspace rather than discarding its
// allocation addresses. The shared Poseidon mutex permits at most one failed
// owner; global quarantine prevents another dispatch after an uncertain wait.
static cudaError_t retain_failed_digest384_workspace_v1(PoseidonWorkspace* workspace, cudaError_t status) {
    static PoseidonWorkspace retained;
    retained = *workspace;
    quarantine_cuda_backend();
    abandon_poseidon_workspace(workspace);
    return status;
}
static void wipe_digest384_host_region_v1(void* pointer, size_t bytes) {
    volatile unsigned char* cursor = static_cast<volatile unsigned char*>(pointer);
    while (bytes-- != 0) *cursor++ = 0;
    std::atomic_signal_fence(std::memory_order_seq_cst);
}
extern "C" cudaError_t fastpq_digest384_hash_frames_v1_cuda(
    const uint64_t* words, size_t word_count, const uint64_t* descriptors, size_t frame_count,
    const uint64_t* parameters, size_t parameter_count, uint64_t* output
) {
    if (words == nullptr || descriptors == nullptr || parameters == nullptr || output == nullptr
        || frame_count == 0 || frame_count > 65536 || word_count == 0 || word_count > 4194304
        || parameter_count != 1197) return cudaErrorInvalidValue;
    for (size_t frame = 0; frame < frame_count; ++frame) {
        uint64_t offset = descriptors[frame * 3], length = descriptors[frame * 3 + 1];
        if (length == 0 || (length & 1) != 0 || offset > word_count
            || length > word_count - offset || descriptors[frame * 3 + 2] >= length)
            return cudaErrorInvalidValue;
    }
    // Fixed dispatch caps above make all these products fit even 32-bit size_t.
    size_t word_bytes = word_count * sizeof(uint64_t);
    size_t descriptor_bytes = frame_count * 3 * sizeof(uint64_t);
    size_t parameter_bytes = parameter_count * sizeof(uint64_t);
    size_t output_bytes = frame_count * 6 * sizeof(uint64_t);
    unsigned int grid_size = 0;
    if (!checked_grid_size(frame_count * 6, 128, &grid_size)) return cudaErrorInvalidValue;
    std::lock_guard<std::mutex> guard(poseidon_workspace_mutex());
    PoseidonWorkspace* workspace = current_poseidon_workspace();
    if (workspace == nullptr) return cudaErrorInvalidValue;
    cudaError_t status;
    status = ensure_workspace_buffer(&workspace->payloads, &workspace->payload_capacity_bytes, word_bytes);
    if (status != cudaSuccess) return status;
    status = ensure_pinned_workspace_buffer(&workspace->host_payloads, &workspace->host_payload_capacity_bytes, word_bytes);
    if (status != cudaSuccess) return status;
    status = ensure_workspace_buffer(&workspace->slices, &workspace->slice_capacity_bytes, descriptor_bytes);
    if (status != cudaSuccess) return status;
    status = ensure_pinned_workspace_buffer(&workspace->host_slices, &workspace->host_slice_capacity_bytes, descriptor_bytes);
    if (status != cudaSuccess) return status;
    status = ensure_workspace_buffer(&workspace->states, &workspace->state_capacity_bytes, parameter_bytes);
    if (status != cudaSuccess) return status;
    status = ensure_pinned_workspace_buffer(&workspace->host_states, &workspace->host_state_capacity_bytes, parameter_bytes);
    if (status != cudaSuccess) return status;
    status = ensure_workspace_buffer(&workspace->hashes, &workspace->hash_capacity_bytes, output_bytes);
    if (status != cudaSuccess) return status;
    status = ensure_pinned_workspace_buffer(&workspace->host_hashes, &workspace->host_hash_capacity_bytes, output_bytes);
    if (status != cudaSuccess) return status;
    status = ensure_poseidon_stream(workspace);
    if (status != cudaSuccess) return status;
    status = ensure_poseidon_event(workspace);
    if (status != cudaSuccess) return status;
    memcpy(workspace->host_payloads, words, word_bytes);
    memcpy(workspace->host_slices, descriptors, descriptor_bytes);
    memcpy(workspace->host_states, parameters, parameter_bytes);
    struct Region { void* device; void* host; size_t bytes; };
    Region regions[] = {
        {workspace->payloads, workspace->host_payloads, word_bytes},
        {workspace->slices, workspace->host_slices, descriptor_bytes},
        {workspace->states, workspace->host_states, parameter_bytes},
        {workspace->hashes, workspace->host_hashes, output_bytes},
    };
    for (size_t index = 0; index < 3; ++index) {
        status = cudaMemcpyAsync(regions[index].device, regions[index].host, regions[index].bytes,
                                 cudaMemcpyHostToDevice, workspace->stream);
        if (status != cudaSuccess) return retain_failed_digest384_workspace_v1(workspace, status);
    }
    fastpq_digest384_hash_frames_v1_kernel<<<grid_size, 128, 0, workspace->stream>>>(
        workspace->payloads, word_count, reinterpret_cast<const uint64_t*>(workspace->slices),
        frame_count, workspace->states, workspace->hashes);
    status = cudaGetLastError();
    if (status != cudaSuccess) return retain_failed_digest384_workspace_v1(workspace, status);
    status = cudaMemcpyAsync(workspace->host_hashes, workspace->hashes, output_bytes,
                             cudaMemcpyDeviceToHost, workspace->stream);
    if (status != cudaSuccess) return retain_failed_digest384_workspace_v1(workspace, status);
    status = cudaEventRecord(workspace->event, workspace->stream);
    if (status == cudaSuccess) status = wait_for_event(workspace->event);
    if (status != cudaSuccess) return retain_failed_digest384_workspace_v1(workspace, status);
    memcpy(output, workspace->host_hashes, output_bytes);
    // Completion makes these pinned regions exclusively host-owned. Wipe all
    // used regions, then require a second completion before reusing device memory.
    for (const Region& region : regions) wipe_digest384_host_region_v1(region.host, region.bytes);
    for (const Region& region : regions) {
        status = cudaMemsetAsync(region.device, 0, region.bytes, workspace->stream);
        if (status != cudaSuccess) return retain_failed_digest384_workspace_v1(workspace, status);
    }
    status = cudaEventRecord(workspace->event, workspace->stream);
    if (status == cudaSuccess) status = wait_for_event(workspace->event);
    if (status != cudaSuccess) return retain_failed_digest384_workspace_v1(workspace, status);
    return cudaSuccess;
}
