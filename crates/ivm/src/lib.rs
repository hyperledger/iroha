//! # Iroha VM (IVM)
// Clippy hygiene: justified global allows
// - upper_case_acronyms: IVM is a proper name used pervasively in the API.
// - type_complexity: some internal tuples/locks intentionally carry rich types.
#![allow(clippy::upper_case_acronyms, clippy::type_complexity)]
//!
//! This library implements the production Iroha virtual machine.  The main
//! entry point is the [`IVM`] struct which can be instantiated and driven by a
//! host environment.  The code is split across a set of modules that roughly
//! follow the layout of the specification:
//!
//! * [`instruction`] – opcode constants and bit-field helpers
//! * [`decoder`] – fixed-width 32-bit instruction decoder
//! * [`memory`] – region based memory with permission checks
//! * [`gas`] – gas accounting utilities
//! * [`host`] – syscall trait and default implementation
//! * [`vector`] – SIMD helpers and crypto primitives
//! * [`zk`] – zero‑knowledge mode support
//!
//! Run `cargo doc --open` to build the API reference locally. Documentation for
//! the latest release is also hosted on <https://docs.rs/ivm>. Set
//! `RUSTDOCFLAGS="--document-private-items"` for a more exhaustive view. The
//! generated `instruction` module provides detailed
//! commentary on every opcode constant and is summarised in
//! [`docs/opcodes.md`](../docs/opcodes.md).
#[cfg(any(feature = "cuda", test))]
mod acceleration_cost;
mod aes;
pub mod analysis;
mod argument_record;
pub mod axt;
pub mod bn254_vec;
mod byte_merkle_tree;
pub mod cache_memory;
mod call_frame;
pub mod call_gas;
pub mod contract_artifact;
mod contract_return_stack;
mod core_host;
mod cuda;
#[cfg(any(feature = "cuda", test))]
#[path = "cuda_dispatch/cost.rs"]
mod cuda_cost;
#[cfg(feature = "cuda")]
mod cuda_dispatch;
// Exercise the production admission state machine without requiring PTX artifacts.
#[cfg(all(test, not(feature = "cuda")))]
#[path = "cuda_dispatch/admission.rs"]
mod cuda_admission_tests;
#[cfg(feature = "cuda")]
mod cuda_artifact;
#[cfg(any(feature = "cuda", test))]
mod cuda_build_policy;
#[cfg(test)]
mod cuda_bundle_files;
#[cfg(any(feature = "cuda", test))]
mod cuda_provenance;
mod decoder;
mod dev_env;
pub mod encoding;
pub mod error;
/// Parent-funded local diagnostic backing for step and memory recorders.
pub mod execution_diagnostics;
pub mod execution_memory;
/// Bounded local memory-transfer diagnostics, separate from proof admission.
pub mod execution_memory_recorder;
/// Sealed original native packets for a bounded root invocation component.
pub mod execution_packets;
/// Local, prepaid interpreter snapshots for diagnostic AIR development only.
pub mod execution_step_recorder;
mod execution_summary;
pub mod field;
pub mod field_dispatch;
#[cfg(test)]
mod frame_identity_tests;
pub mod gas;
pub mod host;
pub mod instruction;
pub mod iso20022;
mod ivm;
pub mod ivm_cache;
pub mod json;
pub mod limits;
pub mod list;
mod memory;
pub mod merkle_utils;
mod metadata;
/// Stable Kotodama V1 numeric ABI tags and register conventions.
pub mod numeric {
    pub use ivm_abi::numeric::*;
}
#[cfg(test)]
mod kotodama_v1_tests;
pub mod mock_wsv;
pub mod numeric_gas;
pub mod numeric_tlv;
pub mod numeric_v1;
mod pedersen;
pub mod pointer_abi;
mod poseidon;
mod prepared;
pub mod private_input;
mod private_memory_ranges;
/// ABI V1 whole-invocation semantic and proof-coverage inventory.
pub mod proof_coverage;
mod registers;
pub mod runtime;
pub mod schema_registry;
mod sha256_ref;
mod sha3;
pub mod signature;
pub mod stack_policy;
mod state_overlay;
/// Shared bounded live-keyset scan implementation for ABI V1 state hosts.
pub mod state_scan;
#[path = "state_value.rs"]
mod state_value_runtime;
pub mod sum;
pub mod syscall_metering;
pub mod syscalls;
mod vector;
pub mod zk;
mod zk_poseidon;
pub mod zk_verify;
use iroha_telemetry::metrics::{StackSettingsSnapshot, record_stack_limits};
use std::sync::{Mutex, OnceLock};
// Host concurrency policy and declared state access.
pub mod parallel;
/// Canonical host-independent builders for generated executor fixtures.
pub mod prebuilt_fixtures;
// Test/fixture helpers (public for tests and dev tools)
pub mod predecoder_fixtures;
// Re-export AES helpers used by benches and downstream users.
// Re-export main types for users of the crate
// Expose the instruction decoder helper at the crate root for tests.
pub use crate::core_host::CoreHost;
#[cfg(test)]
pub use crate::field_dispatch::{clear_field_impl_for_tests, set_field_impl_for_tests};
pub use crate::stack_policy::IvmStackPolicy;
// Publicly expose gas schedule helper for tests and tooling.
/// Shared canonical public value capture and rendering for returns, calls, and events.
pub mod value_record;
pub mod value_utilities;
pub use crate::argument_record::{
    PreparedArgumentRecord, argument_record_decode_count, prepare_argument_record_with_gas_limit,
    reset_argument_record_decode_count, validate_argument_record,
};
pub use crate::gas::{cost_of, cost_of_with_vector_len};
// Re-export stable mode bits so tests/users can import `ivm::ivm_mode::*`.
pub use crate::metadata::mode as ivm_mode;
// Re-export the canonical Merkle tree from iroha_crypto for general use.
pub use crate::contract_artifact::{
    ContractArtifactError, KotoTestHarnessContract, VerifiedContractArtifact, prepare_contract,
    prepare_contract_with_memory_budget, prepare_koto_test_contract, verify_contract_artifact,
    verify_contract_artifact_with_memory_budget,
};
pub use crate::metadata::{
    CONTRACT_DEBUG_SECTION_MAGIC, CONTRACT_FEATURE_BIT_VECTOR, CONTRACT_FEATURE_BIT_ZK,
    CONTRACT_FEATURE_KNOWN_BITS, EmbeddedContractDebugInfoV1, EmbeddedContractInterfaceV1,
    EmbeddedEntrypointDescriptor, EmbeddedFunctionBudgetReportV1, EmbeddedSourceLocation,
    EmbeddedSourceMapEntryV1, EmbeddedStateDescriptor, EmbeddedStateFieldDescriptor,
    EmbeddedStateType, HEADER_SIZE, LiteralKindV1, MAGIC as METADATA_MAGIC, ProgramMetadata,
    VECTOR_LENGTH_MAX, contract_code_hash, decode_literal_descriptor, encode_literal_descriptor,
};
pub use crate::prepared::PreparedContract;
pub use crate::signature::{Ed25519BatchItem, verify_ed25519_batch_items_into};
pub use crate::{
    aes::{
        aes128_decrypt_many_into, aes128_encrypt_many_into, aes128_expand_key, aesdec, aesdec_impl,
        aesdec_n_rounds_many_into, aesenc, aesenc_impl, aesenc_n_rounds_many_into, sbox,
    },
    byte_merkle_tree::ByteMerkleTree,
    cuda::{
        CudaCompletionError, CudaCompletionSnapshot, CudaKernel, aesdec_batch_cuda_into,
        aesdec_cuda, aesdec_rounds_batch_cuda_into, aesenc_batch_cuda_into, aesenc_cuda,
        aesenc_rounds_batch_cuda_into, bitonic_sort_pairs, bn254_add_batch_cuda_into,
        bn254_add_cuda, bn254_mul_batch_cuda_into, bn254_mul_cuda, bn254_sub_batch_cuda_into,
        bn254_sub_cuda, cuda_available, cuda_completion_snapshot, cuda_disabled,
        cuda_last_error_message, ed25519_verify_batch_cuda_into, ed25519_verify_cuda,
        keccak_f1600_cuda, poseidon2_cuda, poseidon2_cuda_many_into, poseidon6_cuda,
        poseidon6_cuda_many_into, reset_cuda_backend_for_tests, sha256_compress_cuda,
        sha256_leaves_cuda_into, sha256_pairs_reduce_cuda, vadd32_cuda_into, vadd64_cuda_into,
        vand_cuda_into, vor_cuda_into, vxor_cuda_into,
    },
    decoder::decode,
    error::{
        ExecutionDeferral, HostOutputResource, Perm, VMError, VmBudgetSnapshot, VmExecutionContext,
        VmExecutionDiagnostic, VmSourceLocation, VmTrapKind,
    },
    execution_summary::{EXECUTION_SUMMARY_VERSION_V1, ExecutionSummary},
    field_dispatch::{Avx2Field, Avx512Field, FieldArithmetic, NeonField, ScalarField, Sse2Field},
    host::IVMHost,
    iso20022::*,
    ivm::{
        IVM, RuntimeTemplate, RuntimeTemplateResetError, TraceMode, VmCycleBudget,
        set_banner_enabled,
    },
    ivm_cache::{
        CacheStats, DecodedOp, IvmCache, global_cache, global_counters, global_get, global_stats,
    },
    memory::{AccessRange, Memory, ReadLogSnapshot, WriteLogEntry, WriteLogSnapshot},
    pedersen::pedersen_commit,
    pointer_abi::{
        PointerType, Tlv, is_type_allowed_for_policy, render_pointer_types_markdown_table,
        validate_tlv_bytes,
    },
    poseidon::{
        poseidon2, poseidon2_many_into, poseidon2_simd, poseidon6, poseidon6_many_into,
        poseidon6_simd,
    },
    sha3::{keccak_f1600, sha3_absorb_block},
    zk_poseidon::{pair_hash_bytes, pair_hash_u64},
};
pub use crate::{
    mock_wsv::{AccountId, AssetDefinitionId, MockWorldStateView, PermissionToken, WsvHost},
    registers::{REGISTER_MERKLE_PATH_DEPTH, Registers},
    signature::{SignatureScheme, verify_signature},
    state_overlay::{DurableStateOverlay, DurableStateSnapshot},
    vector::{
        MetalKernel, SimdChoice, clear_forced_simd, clear_thread_forced_simd,
        forced_simd_test_lock, metal_available, metal_completed_dispatches, metal_disabled,
        release_metal_state, reset_metal_backend_for_tests, set_forced_simd,
        set_thread_forced_simd, sha256_compress, simd_backend, simd_bits, simd_choice, simd_lanes,
        vadd32, vadd32_auto_into, vadd64, vadd64_auto_into, vand, vand_auto_into, vector_supported,
        vor, vor_auto_into, vrot32, vrot32_auto_into, vxor, vxor_auto_into, zero_vector,
    },
    zk::{MemEvent, RegEvent, RegisterState},
};
pub use iroha_crypto::{MerkleProof, MerkleTree};
/// Syscall policy determined by `ProgramMetadata.abi_version`.
pub use ivm_abi::SyscallPolicy;
/// Canonical Kotodama V1 dynamic state-access hint validation.
pub use ivm_abi::access_hints;
/// Canonical V1 function call-table descriptors and limits.
pub use ivm_abi::call;
/// Canonical Norito framing helpers shared by ABI producers and consumers.
pub use ivm_abi::codec;
/// Stable V1 typed core-query tags, projections, and bounded page records.
pub use ivm_abi::core_query;
/// Exact schemas and typed nested-return records encoded at public contract boundaries.
pub use ivm_abi::entrypoint::{
    EntrypointArgumentSchemaV1, EntrypointReturnRecordV1, EntrypointValueAtomV1,
    EntrypointValueTypeV1,
};
/// Canonical compiler-owned nominal error descriptors.
pub use ivm_abi::error_types;
pub use ivm_abi::state_cursor;
/// Canonical schemas and records used for durable Kotodama V1 state values.
pub use ivm_abi::state_value;
/// Public Norito-typed request envelopes for VRF syscalls.
pub mod vrf;
/// Optional acceleration policy applied at runtime by hosts.
///
/// By default, the VM will use all available hardware backends (SIMD, Metal, CUDA) subject to
/// golden-vector self-tests. Hosts may call `set_acceleration_config` to override the availability
/// of certain backends or to cap the number of GPUs.
#[derive(Clone, Copy, Debug)]
pub struct AccelerationConfig {
    /// Enable SIMD acceleration (NEON/AVX/SSE) when available. When false, force scalar execution.
    pub enable_simd: bool,
    /// Enable Metal backend when available (macOS only). Default: true.
    pub enable_metal: bool,
    /// Enable CUDA backend when available (feature `cuda`). Default: true.
    pub enable_cuda: bool,
    /// Maximum number of GPUs to initialize (None = auto/no cap).
    pub max_gpus: Option<usize>,
    /// Minimum leaves for a Merkle GPU attempt (None = default, Some(0) = no floor).
    pub merkle_min_leaves_gpu: Option<usize>,
    /// Metal Merkle floor (None = inherit generic, Some(0) = no floor).
    pub merkle_min_leaves_metal: Option<usize>,
    /// CUDA Merkle floor (None = inherit generic, Some(0) = no floor).
    pub merkle_min_leaves_cuda: Option<usize>,
    /// Prefer available AArch64 CPU SHA2 through this leaf count; None restores the default.
    pub prefer_cpu_sha2_max_leaves_aarch64: Option<usize>,
    /// Prefer available x86 CPU SHA2 through this leaf count; None restores the default.
    pub prefer_cpu_sha2_max_leaves_x86: Option<usize>,
    /// Shared physical-owner ceilings; no omitted field means unlimited.
    pub resource_limits: iroha_accel::RegistryLimits,
}
impl Default for AccelerationConfig {
    fn default() -> Self {
        Self {
            resource_limits: iroha_accel::RegistryLimits::STANDARD,
            enable_simd: true,
            enable_metal: true,
            enable_cuda: true,
            max_gpus: None,
            merkle_min_leaves_gpu: None,
            merkle_min_leaves_metal: None,
            merkle_min_leaves_cuda: None,
            prefer_cpu_sha2_max_leaves_aarch64: None,
            prefer_cpu_sha2_max_leaves_x86: None,
        }
    }
}
fn acceleration_config_store() -> &'static Mutex<AccelerationConfig> {
    static STORE: OnceLock<Mutex<AccelerationConfig>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(AccelerationConfig::default()))
}
fn read_acceleration_config() -> AccelerationConfig {
    let guard = acceleration_config_store()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    *guard
}
fn write_acceleration_config(cfg: AccelerationConfig) {
    let mut guard = acceleration_config_store()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    *guard = cfg;
}
/// Apply acceleration configuration. Optional; when not called the VM
/// automatically uses all available hardware, subject to golden self-tests.
/// Metal discovery, qualification and calibration run when acceleration is requested,
/// rather than while applying policy. Each call replaces the complete policy;
/// omitted Merkle thresholds resolve to their defaults or generic inheritance.
pub fn set_acceleration_config(cfg: AccelerationConfig) {
    write_acceleration_config(cfg);
    iroha_accel::ProcessResources::install(cfg.resource_limits);
    // SIMD policy: force scalar when disabled, otherwise let runtime detection decide.
    crate::vector::set_simd_policy_enabled(cfg.enable_simd);
    // Metal policy
    #[cfg(all(target_os = "macos", feature = "metal"))]
    {
        crate::vector::set_metal_enabled(cfg.enable_metal);
    }
    // CUDA policy
    #[cfg(feature = "cuda")]
    {
        let installed = crate::cuda_artifact::eligible()
            && iroha_accel::cuda::CudaProcess::install(cfg.resource_limits).is_ok();
        crate::cuda_dispatch::configure(cfg.enable_cuda && installed, cfg.max_gpus);
        crate::cuda::set_cuda_enabled(cfg.enable_cuda);
    }
}
/// Return the most recently applied [`AccelerationConfig`]. When
/// `set_acceleration_config` has not been called, this returns the default.
#[must_use]
pub fn acceleration_config() -> AccelerationConfig {
    read_acceleration_config()
}
/// Native result owner funded by the original process acceleration envelope.
/// This owner is separate from a State execution lease and has no Vec conversion.
pub use iroha_accel::HostOutput as AccelerationOutput;
/// Typed local refusal while constructing a native result destination.
pub use iroha_accel::HostOutputError as AccelerationOutputError;

/// Allocate initialized native result storage before ordinary CPU/GPU execution.
/// The same process host charge survives through copying into a foreign runtime.
/// No driver is required and existing operator policy is never replaced by defaults.
/// State execution paths must use their original `ExecutionMemoryLease` instead.
pub fn try_acceleration_output<T: Copy + Default>(
    len: usize,
) -> Result<AccelerationOutput<T>, AccelerationOutputError> {
    iroha_accel::ProcessResources::get_or_initialize(acceleration_config().resource_limits)
        .try_host_output(len)
}

/// Runtime status for a single acceleration backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct BackendRuntimeStatus {
    /// Whether the backend is supported on this build/architecture.
    pub supported: bool,
    /// Whether the active configuration enables the backend.
    pub configured: bool,
    /// Whether the backend is currently available after applying policy and hardware checks.
    pub available: bool,
    /// Whether the backend is usable after policy, hardware detection, and
    /// parity/golden-vector self-tests.
    pub parity_ok: bool,
}
/// Runtime status for acceleration backends.
#[derive(Clone, Copy, Debug, Default)]
pub struct AccelerationRuntimeStatus {
    /// SIMD backend status (scalar vs. hardware vector).
    pub simd: BackendRuntimeStatus,
    /// Metal (macOS/iOS) backend status.
    pub metal: BackendRuntimeStatus,
    /// CUDA backend status.
    pub cuda: BackendRuntimeStatus,
}
/// Retrieve the latest acceleration runtime status including parity checks.
/// This explicit query may discover and qualify enabled hardware.
#[must_use]
pub fn acceleration_runtime_status() -> AccelerationRuntimeStatus {
    let cfg = acceleration_config();
    let mut status = AccelerationRuntimeStatus::default();
    // SIMD status (always compiled; may be forced to scalar).
    {
        let detected = crate::vector::detected_simd_choice();
        let choice = crate::vector::simd_choice();
        let simd_available = choice != crate::vector::SimdChoice::Scalar;
        status.simd = BackendRuntimeStatus {
            supported: detected != crate::vector::SimdChoice::Scalar,
            configured: cfg.enable_simd,
            available: cfg.enable_simd && simd_available,
            parity_ok: true,
        };
    }
    // Metal status (macOS + `metal` feature)
    #[cfg(all(target_os = "macos", feature = "metal"))]
    {
        // An enabled policy alone is not evidence of a qualified physical device.
        let available = crate::vector::metal_available();
        status.metal = BackendRuntimeStatus {
            supported: true,
            configured: cfg.enable_metal,
            available,
            parity_ok: available && crate::vector::metal_parity_ok(),
        };
    }
    #[cfg(not(all(target_os = "macos", feature = "metal")))]
    {
        status.metal = BackendRuntimeStatus {
            supported: false,
            configured: cfg.enable_metal,
            available: false,
            parity_ok: false,
        };
    }
    // CUDA status (`cuda` feature)
    #[cfg(feature = "cuda")]
    {
        let available = crate::cuda::cuda_available();
        status.cuda = BackendRuntimeStatus {
            supported: true,
            configured: cfg.enable_cuda,
            available,
            parity_ok: available,
        };
    }
    #[cfg(not(feature = "cuda"))]
    {
        status.cuda = BackendRuntimeStatus {
            supported: false,
            configured: cfg.enable_cuda,
            available: false,
            parity_ok: false,
        };
    }
    status
}
/// Last reported error or disable reason for each acceleration backend.
#[derive(Clone, Debug, Default)]
pub struct AccelerationErrorStatus {
    /// SIMD disable reason, if forced to scalar.
    pub simd: Option<String>,
    /// Most recent Metal error/disable message, if any.
    pub metal: Option<String>,
    /// Most recent CUDA error/disable message, if any.
    pub cuda: Option<String>,
}
/// Retrieve sticky error messages associated with acceleration backends.
///
/// These messages are cleared when the backend is re-enabled or reset via
/// [`set_acceleration_config`] / test reset helpers. They provide structured
/// diagnostics beyond the stderr banners.
#[must_use]
pub fn acceleration_runtime_errors() -> AccelerationErrorStatus {
    use crate::vector::SimdChoice;
    let simd_error = if !crate::vector::simd_policy_enabled() {
        Some("disabled by config".to_string())
    } else if matches!(
        crate::vector::forced_simd_choice(),
        Some(SimdChoice::Scalar)
    ) {
        Some("forced scalar override".to_string())
    } else {
        let detected = crate::vector::detected_simd_choice();
        let choice = crate::vector::simd_choice();
        if detected == SimdChoice::Scalar {
            Some("simd unsupported on hardware".to_string())
        } else if choice == SimdChoice::Scalar {
            Some("simd unavailable at runtime".to_string())
        } else {
            None
        }
    };
    let cuda_error = {
        let explicit = crate::cuda::cuda_last_error_message();
        if explicit.is_some() {
            explicit
        } else if cfg!(feature = "cuda") {
            let status = acceleration_runtime_status();
            if status.cuda.configured && !status.cuda.available {
                Some("cuda unavailable at runtime".to_string())
            } else {
                None
            }
        } else {
            None
        }
    };
    AccelerationErrorStatus {
        simd: simd_error,
        metal: crate::vector::metal_last_error_message(),
        cuda: cuda_error,
    }
}
/// Minimum native stack size applied to scheduler and prover workers.
pub const MIN_STACK_BYTES: usize = 64 * 1024;
/// Maximum native stack size applied to scheduler and prover workers.
pub const MAX_STACK_BYTES: usize = 1024 * 1024 * 1024;
/// Outcome of applying native worker stack configuration, including clamping flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StackSizeOutcome {
    /// Requested scheduler stack size (bytes).
    pub requested_scheduler_bytes: usize,
    /// Requested prover stack size (bytes).
    pub requested_prover_bytes: usize,
    /// Applied scheduler stack size (bytes) after clamping.
    pub scheduler_bytes: usize,
    /// Applied prover stack size (bytes) after clamping.
    pub prover_bytes: usize,
    /// Whether the scheduler stack request was clamped.
    pub scheduler_clamped: bool,
    /// Whether the prover stack request was clamped.
    pub prover_clamped: bool,
}
/// Configure the default scheduler thread limits used by `IVM::new`.
///
/// Hosts should call this early in process startup (before creating VMs) to
/// avoid oversubscription when multiple thread pools are present. Passing
/// `None` for a bound keeps the automatic value (number of physical cores).
/// After resolving "auto" bounds, `min <= max` is enforced by clamping `min` down.
pub fn set_scheduler_thread_limits(min_threads: Option<usize>, max_threads: Option<usize>) {
    crate::parallel::set_default_scheduler_limits(min_threads, max_threads);
}
/// Validate and apply native stack sizes for scheduler and prover pools.
///
/// Guest stack geometry is fixed by [`IvmStackPolicy::V1`] and is deliberately
/// not accepted by this operational configuration API.
pub fn apply_stack_sizes(scheduler_bytes: usize, prover_bytes: usize) -> StackSizeOutcome {
    let sched = scheduler_bytes.clamp(MIN_STACK_BYTES, MAX_STACK_BYTES);
    let prover = prover_bytes.clamp(MIN_STACK_BYTES, MAX_STACK_BYTES);
    let outcome = StackSizeOutcome {
        requested_scheduler_bytes: scheduler_bytes,
        requested_prover_bytes: prover_bytes,
        scheduler_bytes: sched,
        prover_bytes: prover,
        scheduler_clamped: sched != scheduler_bytes,
        prover_clamped: prover != prover_bytes,
    };
    set_scheduler_stack_size(sched);
    set_prover_stack_size(prover);
    let guest_policy = IvmStackPolicy::V1;
    record_stack_limits(StackSettingsSnapshot {
        requested_scheduler_bytes: outcome.requested_scheduler_bytes as u64,
        requested_prover_bytes: outcome.requested_prover_bytes as u64,
        requested_guest_bytes: guest_policy.maximum_stack_bytes(),
        scheduler_bytes: outcome.scheduler_bytes as u64,
        prover_bytes: outcome.prover_bytes as u64,
        guest_bytes: guest_policy.maximum_stack_bytes(),
        scheduler_clamped: outcome.scheduler_clamped,
        prover_clamped: outcome.prover_clamped,
        guest_clamped: false,
        pool_fallback_total: 0,
        budget_hit_total: 0,
        gas_to_stack_multiplier: guest_policy.bytes_per_gas(),
    });
    outcome
}
/// Initialize the global Rayon thread pool with `num_threads` workers.
///
/// Safe to call once; if a global pool already exists, the request returns
/// `GlobalPoolAlreadyInitialized`.
pub fn init_global_rayon(num_threads: usize) -> Result<(), rayon::ThreadPoolBuildError> {
    let n = num_threads.max(1);
    rayon::ThreadPoolBuilder::new()
        .num_threads(n)
        .stack_size(crate::parallel::thread_stack_size())
        .build_global()
}
/// Override the stack size used by scheduler Rayon pools.
pub fn set_scheduler_stack_size(bytes: usize) {
    crate::parallel::set_thread_stack_size(bytes);
}
/// Override the stack size used by prover Rayon pools.
pub fn set_prover_stack_size(bytes: usize) {
    crate::zk::set_prover_stack_size(bytes);
}

pub use crate::cuda::cuda_device_slots;
#[cfg(feature = "cuda-hardware-tests")]
pub use crate::cuda::{cuda_qualification_device, with_cuda_device_for_qualification};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn acceleration_runtime_errors_default_none_or_hw_reason() {
        let status = acceleration_runtime_status();
        let errors = acceleration_runtime_errors();
        if status.simd.supported {
            assert!(errors.simd.is_none());
        } else {
            assert_eq!(errors.simd.as_deref(), Some("simd unsupported on hardware"));
        }
        assert!(errors.metal.is_none());
        #[cfg(feature = "cuda")]
        {
            if status.cuda.available {
                assert!(errors.cuda.is_none());
            } else {
                assert!(
                    errors.cuda.is_some(),
                    "expected a CUDA disable/unavailable reason when the CUDA feature is enabled"
                );
            }
        }
        #[cfg(not(feature = "cuda"))]
        {
            assert!(errors.cuda.is_none());
        }
    }
    #[test]
    fn cuda_status_never_reports_parity_without_availability() {
        let status = acceleration_runtime_status();
        if !status.cuda.available {
            assert!(
                !status.cuda.parity_ok,
                "CUDA parity status must not be true when the backend is unavailable"
            );
        }
        if status.cuda.configured && status.cuda.supported && !status.cuda.available {
            assert!(
                acceleration_runtime_errors().cuda.is_some(),
                "configured CUDA should report a runtime reason when unavailable"
            );
        }
    }
    #[test]
    fn apply_stack_sizes_clamps_and_records_snapshot() {
        record_stack_limits(StackSettingsSnapshot::default());
        let outcome = apply_stack_sizes(1, usize::MAX);
        assert!(
            outcome.scheduler_clamped,
            "scheduler stack should clamp low values"
        );
        assert!(
            outcome.prover_clamped,
            "prover stack should clamp high values"
        );
        let snapshot = iroha_telemetry::metrics::stack_settings_snapshot();
        assert_eq!(
            snapshot.scheduler_bytes, MIN_STACK_BYTES as u64,
            "scheduler stack should clamp to minimum"
        );
        assert_eq!(
            snapshot.prover_bytes, MAX_STACK_BYTES as u64,
            "prover stack should clamp to maximum"
        );
        assert_eq!(
            snapshot.guest_bytes,
            IvmStackPolicy::V1.maximum_stack_bytes(),
            "telemetry must expose the fixed V1 guest-stack ceiling"
        );
        assert_eq!(
            snapshot.gas_to_stack_multiplier,
            IvmStackPolicy::V1.bytes_per_gas(),
            "telemetry must expose the fixed V1 gas policy"
        );
        let _ = apply_stack_sizes(32 * 1024 * 1024, 32 * 1024 * 1024);
    }
    #[test]
    fn init_global_rayon_reports_existing_pool() {
        let threads = num_cpus::get_physical().max(1);
        let first = init_global_rayon(threads);
        assert!(
            first.is_ok() || first.is_err(),
            "global pool init should either succeed or report an existing pool"
        );
        let second = init_global_rayon(threads);
        let err = second.expect_err("second init must fail because the global pool is singleton");
        assert!(
            err.to_string().contains("initialized"),
            "expected existing-pool error, got {err}"
        );
    }
    #[test]
    fn native_stack_settings_cannot_change_guest_policy() {
        let gas_limit = 100_000;
        let expected = IvmStackPolicy::V1.stack_limit_for_gas(gas_limit);
        let _ = apply_stack_sizes(MIN_STACK_BYTES, MAX_STACK_BYTES);
        assert_eq!(IvmStackPolicy::V1.stack_limit_for_gas(gas_limit), expected);
        let _ = apply_stack_sizes(MAX_STACK_BYTES, MIN_STACK_BYTES);
        assert_eq!(IvmStackPolicy::V1.stack_limit_for_gas(gas_limit), expected);
    }
    #[test]
    fn metal_api_exports_are_available_on_all_targets() {
        release_metal_state();
        reset_metal_backend_for_tests();
        assert_eq!(metal_available(), crate::vector::metal_available());
        assert_eq!(metal_disabled(), crate::vector::metal_disabled());
    }
}
