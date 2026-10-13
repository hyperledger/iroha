use crate::{Error, Result, field::GoldilocksFp4V1, gadgets::transfer_integer_air, overrides};
#[cfg(any(test, feature = "dev-tools"))]
use crate::{
    TransitionBatch,
    fft::Planner,
    proof::{AirConstraintOpening, FriQueryOpening, FriRoundOpening, PublicIO},
    trace::{PoseidonPipelinePolicy, build_trace, derive_polynomial_data},
};
use core::convert::TryFrom;
#[cfg(any(test, feature = "dev-tools"))]
use fastpq_isi::{
    FASTPQ_CATALOG_V1, FASTPQ_FINAL_V1_ID, GoldilocksDigest384DomainPrefixV1,
    GoldilocksDigest384V1, GoldilocksDigestDomainV1, StarkParameterSet, hash_bytes_384_v1,
};
#[cfg(any(test, feature = "dev-tools"))]
use iroha_data_model::privacy::GoldilocksDigest384V1 as WireGoldilocksDigest384V1;
#[cfg(all(feature = "fastpq-gpu", target_os = "macos"))]
use metal::{Device, MTLDeviceLocation};
#[cfg(any(test, feature = "dev-tools"))]
use rayon::prelude::*;
#[cfg(any(test, feature = "dev-tools"))]
use std::collections::BTreeSet;
#[cfg(windows)]
use std::env;
#[cfg(unix)]
use std::fs;
#[cfg(windows)]
use std::path::PathBuf;
use std::{
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock, TryLockError},
};
const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
/// Typed semantic AIR interface over the fixed q77 engine.
#[path = "backend/air.rs"]
pub mod air;
#[path = "backend/air_degree.rs"]
mod air_degree;
#[path = "backend/air_expression.rs"]
mod air_expression;
#[path = "backend/air_quotient.rs"]
#[cfg(any(test, feature = "dev-tools"))]
mod air_quotient;
#[cfg(test)]
#[path = "backend/coefficient_masking.rs"]
mod coefficient_masking;
#[path = "backend/masked_quotient.rs"]
mod masked_quotient;
#[path = "backend/polynomial_division.rs"]
mod polynomial_division;
#[path = "backend/polynomial_field.rs"]
mod polynomial_field;
#[cfg(test)]
#[path = "backend/polynomial_reference.rs"]
mod polynomial_reference;
#[path = "backend/polynomial_transform.rs"]
mod polynomial_transform;
#[path = "backend/quotient_pair_masking.rs"]
mod quotient_pair_masking;
#[path = "backend/secret_polynomial.rs"]
mod secret_polynomial;
#[cfg(any(test, feature = "dev-tools"))]
pub use air_quotient::{AirQuotientDomain, AirQuotientWeights};
#[path = "backend/joint_fri.rs"]
#[cfg(any(test, feature = "dev-tools"))]
mod joint_fri;
#[cfg(any(test, feature = "dev-tools"))]
pub use joint_fri::JointFriBatch;
#[path = "backend/merkle_cache.rs"]
#[cfg(any(test, feature = "dev-tools"))]
mod merkle_cache;
#[cfg(any(test, feature = "dev-tools"))]
pub use merkle_cache::MerkleNodeCache;
#[cfg(test)]
#[path = "backend/compact_axt_air.rs"]
mod compact_axt_air;
#[path = "backend/compact_axt_batch.rs"]
mod compact_axt_batch;
#[path = "backend/compact_axt_context.rs"]
mod compact_axt_context;
#[path = "backend/compact_bundle.rs"]
mod compact_bundle;
#[path = "backend/compact_execution_effect_batch.rs"]
mod compact_execution_effect_batch;
#[path = "backend/compact_hash_quotient.rs"]
mod compact_hash_quotient;
#[path = "backend/compact_model_statement.rs"]
mod compact_model_statement;
#[path = "backend/compact_protocol.rs"]
mod compact_protocol;
#[path = "backend/compact_prover_resources.rs"]
mod compact_prover_resources;
#[path = "backend/compact_public_api.rs"]
mod compact_public_api;
#[path = "backend/compact_public_batch.rs"]
mod compact_public_batch;
#[path = "backend/compact_public_columns.rs"]
mod compact_public_columns;
#[path = "backend/compact_public_transfer.rs"]
mod compact_public_transfer;
#[cfg(test)]
#[path = "backend/compact_quantity_diagnostic.rs"]
mod compact_quantity_diagnostic;
#[path = "backend/compact_quantity_producer.rs"]
mod compact_quantity_producer;

/// Retain the actual quantity-producer work permit for contention unit controls.
#[cfg(test)]
pub fn hold_quantity_producer_for_test() -> std::sync::MutexGuard<'static, ()> {
    compact_quantity_producer::hold_producer_for_test()
}
#[cfg(test)]
#[path = "backend/compact_quantity_tests.rs"]
mod compact_quantity_tests;
#[path = "backend/compact_sha3.rs"]
mod compact_sha3;
#[path = "backend/compact_smt_quotient.rs"]
mod compact_smt_quotient;
#[path = "backend/compact_transfer_air.rs"]
mod compact_transfer_air;
#[path = "backend/compact_value_domain.rs"]
mod compact_value_domain;
#[path = "backend/deep_binding.rs"]
mod deep_binding;
#[path = "backend/deep_coefficient_commitment.rs"]
mod deep_coefficient_commitment;
#[path = "backend/deep_coefficient_replay.rs"]
mod deep_coefficient_replay;
#[path = "backend/deep_composition.rs"]
mod deep_composition;
#[path = "backend/deep_engine.rs"]
mod deep_engine;
#[cfg(test)]
#[path = "backend/deep_fixture.rs"]
mod deep_fixture;
#[path = "backend/deep_geometry.rs"]
mod deep_geometry;
#[path = "backend/deep_leaf_batch.rs"]
mod deep_leaf_batch;
#[path = "backend/deep_masked_quotient.rs"]
mod deep_masked_quotient;
#[path = "backend/deep_masked_replay.rs"]
mod deep_masked_replay;
#[path = "backend/deep_node_cache.rs"]
mod deep_node_cache;
#[path = "backend/deep_parent_batch.rs"]
mod deep_parent_batch;
#[path = "backend/deep_polynomial.rs"]
mod deep_polynomial;
#[path = "backend/deep_proof.rs"]
mod deep_proof;
#[path = "backend/deep_prover.rs"]
mod deep_prover;
#[cfg(test)]
#[path = "backend/deep_prover_plan.rs"]
mod deep_prover_plan;
#[path = "backend/deep_relation.rs"]
mod deep_relation;
#[path = "backend/deep_striped_merkle.rs"]
mod deep_striped_merkle;
#[path = "backend/deep_trace_source.rs"]
mod deep_trace_source;
#[cfg(test)]
#[path = "backend/extension_trace.rs"]
mod extension_trace;
#[path = "backend/fixed_domain.rs"]
mod fixed_domain;
#[path = "backend/fixed_schedule.rs"]
mod fixed_schedule;
#[path = "backend/fri_fold.rs"]
mod fri_fold;
#[path = "backend/fri_openings.rs"]
#[cfg(any(test, feature = "dev-tools"))]
mod fri_openings;
#[cfg(test)]
#[path = "backend/frozen_record.rs"]
mod frozen_record;
#[path = "backend/merkle_multiproof.rs"]
mod merkle_multiproof;
#[path = "backend/offline_compact.rs"]
pub mod offline_compact;
#[cfg(test)]
#[path = "backend/phased_trace.rs"]
mod phased_trace;
#[path = "backend/public_table.rs"]
mod public_table;
#[path = "backend/transcript_profile.rs"]
mod transcript_profile;
const FIELD_ONE: u64 = 1;
#[cfg(any(test, feature = "dev-tools"))]
const TRACE_COMMITMENT_ROLE_V1: &[u8] = b"trace-commitment";
#[cfg(any(test, feature = "dev-tools"))]
const LDE_COMMITMENT_ROLE_V1: &[u8] = b"lde-commitment";
#[cfg(any(test, feature = "dev-tools"))]
const AIR_TRACE_COMMITMENT_ROLE_V1: &[u8] = b"air-trace-commitment";
#[cfg(any(test, feature = "dev-tools"))]
const AIR_COMPOSITION_COMMITMENT_ROLE_V1: &[u8] = b"air-composition-commitment";
#[cfg(any(test, feature = "dev-tools"))]
const FRI_COMMITMENT_ROLE_V1: &[u8] = b"fri-commitment";
#[cfg(any(test, feature = "dev-tools"))]
const TRANSCRIPT_ROLE_V1: &[u8] = b"fiat-shamir-transcript";
#[cfg(any(test, feature = "dev-tools"))]
const MERKLE_LEAF_PHASE_V1: &[u8] = b"leaf";
#[cfg(any(test, feature = "dev-tools"))]
const MERKLE_NODE_PHASE_V1: &[u8] = b"node";
#[cfg(any(test, feature = "dev-tools"))]
const MERKLE_EMPTY_PHASE_V1: &[u8] = b"empty-root";
/// Transcript domain for the permission lookup grand-product accumulator.
#[cfg(any(test, feature = "dev-tools"))]
pub const LOOKUP_PRODUCT_DOMAIN: &str = "fastpq:v1:lookup:product";

/// Typed native-STARK Merkle role; the role and FRI round are bound into every internal node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(any(test, feature = "dev-tools"))]
pub enum MerkleTreeRoleV1 {
    /// Base trace column-commitment tree.
    Trace,
    /// Random-column-combination LDE tree.
    Lde,
    /// Row-major AIR trace tree.
    AirTrace,
    /// AIR composition tree.
    AirComposition,
    /// One binary FRI layer and its zero-based round.
    Fri(u32),
}

#[cfg(any(test, feature = "dev-tools"))]
impl MerkleTreeRoleV1 {
    fn role(self) -> &'static [u8] {
        match self {
            Self::Trace => TRACE_COMMITMENT_ROLE_V1,
            Self::Lde => LDE_COMMITMENT_ROLE_V1,
            Self::AirTrace => AIR_TRACE_COMMITMENT_ROLE_V1,
            Self::AirComposition => AIR_COMPOSITION_COMMITMENT_ROLE_V1,
            Self::Fri(_) => FRI_COMMITMENT_ROLE_V1,
        }
    }

    fn counter(self) -> u64 {
        match self {
            Self::Fri(round) => u64::from(round),
            Self::Trace | Self::Lde | Self::AirTrace | Self::AirComposition => 0,
        }
    }
}
#[cfg(any(test, feature = "dev-tools"))]
const FRI_FINAL_DOMAIN: &str = "fastpq:v1:fri:final";
#[cfg(all(feature = "fastpq-gpu", target_os = "macos"))]
static DEBUG_METAL_ENUM_ENV: OnceLock<bool> = OnceLock::new();
#[cfg(all(feature = "fastpq-gpu", target_os = "macos"))]
fn warm_up_core_graphics_display() {}
static GPU_BACKEND: OnceLock<Option<GpuBackend>> = OnceLock::new();
static GPU_OVERRIDE: OnceLock<GpuOverride> = OnceLock::new();
static AUTO_RESOLVED_MODE: OnceLock<ExecutionMode> = OnceLock::new();
static GPU_WORKLOAD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
type ExecutionModeObserver =
    dyn Fn(ExecutionMode, ExecutionMode, Option<GpuBackend>) + Send + Sync + 'static;
static EXECUTION_MODE_OBSERVER: OnceLock<RwLock<Option<Arc<ExecutionModeObserver>>>> =
    OnceLock::new();
#[cfg(any(test, feature = "dev-tools"))]
pub const TRANSCRIPT_TAG_INIT: &str = "fastpq:v1:init";
#[cfg(any(test, feature = "dev-tools"))]
pub const TRANSCRIPT_TAG_ROOTS: &str = "fastpq:v1:roots";
#[cfg(any(test, feature = "dev-tools"))]
pub const TRANSCRIPT_TAG_TRACE_ROOT: &str = "fastpq:v1:trace_root";
#[cfg(any(test, feature = "dev-tools"))]
pub const TRANSCRIPT_TAG_COLUMN_MIX_PREFIX: &str = "fastpq:v1:column_mix";
/// Fiat–Shamir domain for the permission lookup challenge.
#[cfg(any(test, feature = "dev-tools"))]
pub const TRANSCRIPT_TAG_GAMMA: &str = "fastpq:v1:gamma";
#[cfg(any(test, feature = "dev-tools"))]
pub const TRANSCRIPT_TAG_ALPHA_PREFIX: &str = "fastpq:v1:alpha";
#[cfg(any(test, feature = "dev-tools"))]
pub const TRANSCRIPT_TAG_AIR_ROOTS: &str = "fastpq:v1:air_roots";
#[cfg(any(test, feature = "dev-tools"))]
pub const TRANSCRIPT_TAG_QUERY_INDEX: &str = "fastpq:v1:query_index";
#[cfg(any(test, feature = "dev-tools"))]
pub const TRANSCRIPT_TAG_BETA_PREFIX: &str = "fastpq:v1:beta";
#[cfg(any(test, feature = "dev-tools"))]
pub const TRANSCRIPT_TAG_FRI_LAYER_PREFIX: &str = "fastpq:v1:fri_layer";
const AIR_BOOLEAN_RESIDUE_COUNT: usize = 8;
const AIR_RELATION_RESIDUE_COUNT: usize = 4;
const AIR_STABLE_RESIDUE_COUNT: usize = crate::trace::METADATA_COMMITMENT_LIMBS + 2;
/// Number of V1 AIR composition challenges derived from the transcript.
///
/// Every constraint residue receives an independently derived coefficient. Reusing coefficients
/// lets equal-and-opposite residues at the same reuse offset cancel for every transcript.
pub const AIR_COMPOSITION_ALPHA_COUNT: usize = AIR_BOOLEAN_RESIDUE_COUNT
    + AIR_RELATION_RESIDUE_COUNT
    + AIR_STABLE_RESIDUE_COUNT
    + transfer_integer_air::CONSTRAINT_COUNT;
const _: () = assert!(
    AIR_COMPOSITION_ALPHA_COUNT == fastpq_isi::resource_limits::FASTPQ_REPLAY_AIR_ALPHA_COUNT_V1
);
/// Conservative exclusive quotient degree bound as a multiple of the trace length.
#[cfg(any(test, feature = "dev-tools"))]
pub const AIR_QUOTIENT_DEGREE_EXPANSION_V1: usize =
    fastpq_isi::FASTPQ_COMPOSITION_DEGREE_EXPANSION_V1 as usize;
/// Configuration for the FASTPQ backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    /// Run the prover using the scalar CPU implementation.
    Cpu,
    /// Require GPU execution; final-V1 proof construction rejects this until implemented.
    Gpu,
    /// Detect hardware support at runtime and pick the best available mode.
    Auto,
}
/// Poseidon pipeline execution override.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoseidonExecutionMode {
    /// Follow the primary execution mode (default).
    Auto,
    /// Force CPU hashing even if FFT/LDE use the GPU.
    Cpu,
    /// Attempt GPU hashing regardless of the primary execution mode.
    Gpu,
}
impl PoseidonExecutionMode {
    /// Return the poseidon override label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Cpu => "cpu",
            Self::Gpu => "gpu",
        }
    }
}
impl ExecutionMode {
    /// Return the execution mode as a lowercase label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Gpu => "gpu",
            Self::Auto => "auto",
        }
    }
    /// Resolve the execution mode, performing runtime detection when required.
    #[must_use]
    pub fn resolve(self) -> Self {
        let resolved = match self {
            Self::Auto => {
                if gpu_available() {
                    Self::Gpu
                } else {
                    Self::Cpu
                }
            }
            mode => mode,
        };
        log_execution_resolution(self, resolved);
        resolved
    }
}

/// Check GPU availability for the transparent batch-replay diagnostic only.
///
/// This fixture pipeline has no GPU dispatch. Canonical masked quantity artifacts
/// use their own explicit digest policy and required-device preflight; this helper
/// neither checks nor disables that implementation.
#[cfg(any(test, feature = "dev-tools"))]
#[must_use]
pub const fn preflight_native_v1_gpu_backend() -> bool {
    false
}
fn gpu_workload_mutex() -> &'static Mutex<()> {
    GPU_WORKLOAD_LOCK.get_or_init(|| Mutex::new(()))
}
pub fn try_acquire_gpu_lane() -> Option<MutexGuard<'static, ()>> {
    match gpu_workload_mutex().try_lock() {
        Ok(guard) => Some(guard),
        Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
        Err(TryLockError::WouldBlock) => None,
    }
}
#[cfg(any(test, feature = "fastpq-gpu"))]
pub fn acquire_gpu_lane() -> MutexGuard<'static, ()> {
    match gpu_workload_mutex().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
fn execution_mode_observer_slot() -> &'static RwLock<Option<Arc<ExecutionModeObserver>>> {
    EXECUTION_MODE_OBSERVER.get_or_init(|| RwLock::new(None))
}
fn replace_execution_mode_observer(replacement: Option<Arc<ExecutionModeObserver>>) {
    let previous = {
        let mut guard = match execution_mode_observer_slot().write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!(
                    target: "fastpq::planner",
                    "recovering poisoned execution mode observer registration lock"
                );
                let guard = poisoned.into_inner();
                execution_mode_observer_slot().clear_poison();
                guard
            }
        };
        core::mem::replace(&mut *guard, replacement)
    };
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(previous))).is_err() {
        tracing::warn!(
            target: "fastpq::planner",
            "execution mode observer destructor panicked"
        );
    }
}
fn notify_execution_mode_observer(
    requested: ExecutionMode,
    resolved: ExecutionMode,
    backend: Option<GpuBackend>,
) {
    let observer = match execution_mode_observer_slot().read() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => {
            tracing::warn!(
                target: "fastpq::planner",
                "recovering poisoned execution mode observer notification lock"
            );
            let guard = poisoned.into_inner();
            execution_mode_observer_slot().clear_poison();
            guard.clone()
        }
    };
    if let Some(callback) = observer {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            callback(requested, resolved, backend)
        }));
        let drop_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(callback)));
        if result.is_err() {
            tracing::warn!(
                target: "fastpq::planner",
                requested = requested.as_str(),
                resolved = resolved.as_str(),
                "execution mode observer callback panicked"
            );
        }
        if drop_result.is_err() {
            tracing::warn!(
                target: "fastpq::planner",
                "execution mode observer destructor panicked"
            );
        }
    }
}
/// Install a hook invoked whenever an execution mode resolves to the concrete mode used.
///
/// CPU resolutions report no GPU backend, even when an accelerator is available.
/// The hook runs without holding the registration lock, may replace or clear itself, and its
/// panics are caught and logged.
pub fn set_execution_mode_observer<F>(observer: F)
where
    F: Fn(ExecutionMode, ExecutionMode, Option<GpuBackend>) + Send + Sync + 'static,
{
    let observer: Arc<ExecutionModeObserver> = Arc::new(observer);
    replace_execution_mode_observer(Some(observer));
}
/// Remove the previously installed execution mode observer, if any.
pub fn clear_execution_mode_observer() {
    replace_execution_mode_observer(None);
}
fn gpu_available() -> bool {
    match gpu_override() {
        GpuOverride::ForceCpu => false,
        GpuOverride::ForceGpu => {
            let backend = GPU_BACKEND.get_or_init(|| {
                let detected = detect_gpu_backend();
                if detected.is_none() {
                    tracing::warn!(
                        target: "fastpq::planner",
                        "FASTPQ_GPU=gpu requested but no accelerator was detected"
                    );
                } else {
                    log_detected_backend(detected);
                }
                detected
            });
            usable_runtime_backend(*backend).is_some()
        }
        GpuOverride::Auto => {
            let backend = GPU_BACKEND.get_or_init(|| {
                let backend = detect_gpu_backend();
                log_detected_backend(backend);
                backend
            });
            usable_runtime_backend(*backend).is_some()
        }
    }
}
pub fn current_gpu_backend() -> Option<GpuBackend> {
    if GPU_BACKEND.get().is_none() {
        let _ = gpu_available();
    }
    usable_runtime_backend(GPU_BACKEND.get().and_then(|backend| *backend))
}
fn usable_runtime_backend(backend: Option<GpuBackend>) -> Option<GpuBackend> {
    #[cfg(all(feature = "fastpq-gpu", target_os = "macos"))]
    if matches!(backend, Some(GpuBackend::Metal)) && crate::metal::backend_quarantined() {
        return None;
    }
    #[cfg(any(test, feature = "fastpq-gpu"))]
    let cuda_quarantined =
        matches!(backend, Some(GpuBackend::Cuda)) && crate::fastpq_cuda::backend_quarantined();
    #[cfg(not(any(test, feature = "fastpq-gpu")))]
    let cuda_quarantined = false;
    runtime_backend(backend, cuda_quarantined)
}
fn runtime_backend(backend: Option<GpuBackend>, cuda_quarantined: bool) -> Option<GpuBackend> {
    match backend {
        Some(GpuBackend::Cuda) if cuda_quarantined => None,
        backend => backend,
    }
}
#[cfg(any(test, feature = "dev-tools"))]
fn default_batch_execution_mode() -> ExecutionMode {
    if current_gpu_backend().is_some() {
        ExecutionMode::Gpu
    } else {
        ExecutionMode::Cpu
    }
}
fn log_execution_resolution(requested: ExecutionMode, resolved: ExecutionMode) {
    // A discovered accelerator does not imply that this resolution uses it.
    // In particular, CPU-pinned runs must not be counted as GPU backend work.
    let backend = match resolved {
        ExecutionMode::Gpu => current_gpu_backend(),
        ExecutionMode::Cpu | ExecutionMode::Auto => None,
    };
    let backend_label = backend.map_or("none", GpuBackend::as_str);
    let planner_backend_label = backend.map_or("unknown", GpuBackend::as_str);
    tracing::info!(
        target: "telemetry::fastpq.execution_mode",
        requested = requested.as_str(),
        resolved = resolved.as_str(),
        backend = backend_label,
        "FASTPQ execution mode resolved"
    );
    notify_execution_mode_observer(requested, resolved, backend);
    if requested != ExecutionMode::Auto {
        return;
    }
    let _ = AUTO_RESOLVED_MODE.get_or_init(|| {
        match resolved {
            ExecutionMode::Gpu => {
                tracing::info!(
                    target: "fastpq::planner",
                    resolved_mode = "gpu",
                    backend = planner_backend_label,
                    "FASTPQ planner resolved to GPU execution mode"
                );
            }
            ExecutionMode::Cpu => {
                tracing::info!(
                    target: "fastpq::planner",
                    resolved_mode = "cpu",
                    "FASTPQ planner resolved to CPU execution mode; GPU acceleration unavailable"
                );
            }
            ExecutionMode::Auto => {
                tracing::debug!(
                    target: "fastpq::planner",
                    "ExecutionMode::Auto resolved without runtime detection"
                );
            }
        }
        resolved
    });
}
fn gpu_override() -> GpuOverride {
    *GPU_OVERRIDE.get_or_init(|| {
        let value = overrides::guard_env_override(|| overrides::debug_env_string("FASTPQ_GPU"));
        let parsed = value
            .as_deref()
            .and_then(parse_gpu_override)
            .unwrap_or(GpuOverride::Auto);
        if let Some(raw) = value {
            log_gpu_override(&raw, parsed);
        }
        parsed
    })
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GpuOverride {
    Auto,
    ForceCpu,
    ForceGpu,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuBackend {
    /// CUDA runtime is available.
    Cuda,
    /// Metal device discovered (macOS).
    Metal,
    /// `OpenCL` platforms discovered.
    OpenCl,
    /// Reused GPU detection from Norito compression backend.
    Norito,
}
impl GpuBackend {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cuda => "cuda",
            Self::Metal => "metal",
            Self::OpenCl => "opencl",
            Self::Norito => "norito",
        }
    }
}
#[derive(Debug, Clone, Copy, Default)]
struct BackendAvailability {
    bits: u8,
}
impl BackendAvailability {
    const CUDA_BIT: u8 = 1 << 0;
    const OPENCL_BIT: u8 = 1 << 1;
    const METAL_BIT: u8 = 1 << 2;
    const NORITO_BIT: u8 = 1 << 3;
    const fn empty() -> Self {
        Self { bits: 0 }
    }
    fn with(mut self, backend: GpuBackend, available: bool) -> Self {
        if available {
            self.bits |= Self::mask(backend);
        }
        self
    }
    fn has(self, backend: GpuBackend) -> bool {
        self.bits & Self::mask(backend) != 0
    }
    const fn mask(backend: GpuBackend) -> u8 {
        match backend {
            GpuBackend::Cuda => Self::CUDA_BIT,
            GpuBackend::Metal => Self::METAL_BIT,
            GpuBackend::OpenCl => Self::OPENCL_BIT,
            GpuBackend::Norito => Self::NORITO_BIT,
        }
    }
}
fn log_detected_backend(backend: Option<GpuBackend>) {
    if let Some(kind) = backend {
        tracing::info!(
            target: "fastpq::planner",
            backend = kind.as_str(),
            "GPU backend detected"
        );
    } else {
        tracing::info!(
            target: "fastpq::planner",
            "No supported GPU backend detected"
        );
    }
}
fn log_gpu_override(raw: &str, parsed: GpuOverride) {
    match parsed {
        GpuOverride::ForceCpu => tracing::info!(
            target: "fastpq::planner",
            override_value = %raw,
            "GPU override forcing CPU execution"
        ),
        GpuOverride::ForceGpu => tracing::info!(
            target: "fastpq::planner",
            override_value = %raw,
            "GPU override forcing GPU execution"
        ),
        GpuOverride::Auto => tracing::info!(
            target: "fastpq::planner",
            override_value = %raw,
            "GPU override set to auto detection"
        ),
    }
}
fn warn_unknown_override(raw: &str) {
    tracing::warn!(
        target: "fastpq::planner",
        override_value = %raw,
        "Unknown FASTPQ_GPU override; falling back to auto detection"
    );
}
fn detect_gpu_backend() -> Option<GpuBackend> {
    let cuda = cuda_available();
    let metal = metal_available();
    let opencl = opencl_available();
    let norito = norito_gpu_available();
    let availability = BackendAvailability::empty()
        .with(
            GpuBackend::Cuda,
            cuda && gpu_backend_supported_in_build(GpuBackend::Cuda),
        )
        .with(
            GpuBackend::OpenCl,
            opencl && gpu_backend_supported_in_build(GpuBackend::OpenCl),
        )
        .with(
            GpuBackend::Metal,
            metal && gpu_backend_supported_in_build(GpuBackend::Metal),
        )
        .with(
            GpuBackend::Norito,
            norito && gpu_backend_supported_in_build(GpuBackend::Norito),
        );
    resolve_backend(availability)
}
fn gpu_backend_supported_in_build(backend: GpuBackend) -> bool {
    match backend {
        GpuBackend::Cuda => cfg!(all(feature = "fastpq-gpu", not(fastpq_cuda_unavailable))),
        GpuBackend::Metal => cfg!(all(feature = "fastpq-gpu", target_os = "macos")),
        // FASTPQ currently has no OpenCL or Norito FFT/LDE execution backend, so probing host
        // support must not opt the prover into those modes.
        GpuBackend::OpenCl | GpuBackend::Norito => false,
    }
}
fn parse_gpu_override(raw: &str) -> Option<GpuOverride> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Some(GpuOverride::Auto);
    }
    match trimmed.to_ascii_lowercase().as_str() {
        "cpu" | "off" | "disable" | "disabled" | "0" => Some(GpuOverride::ForceCpu),
        "gpu" | "on" | "enable" | "enabled" | "1" => Some(GpuOverride::ForceGpu),
        "auto" | "detect" | "auto-detect" => Some(GpuOverride::Auto),
        _ => {
            warn_unknown_override(trimmed);
            None
        }
    }
}
fn resolve_backend(availability: BackendAvailability) -> Option<GpuBackend> {
    [
        GpuBackend::Cuda,
        GpuBackend::Metal,
        GpuBackend::OpenCl,
        GpuBackend::Norito,
    ]
    .into_iter()
    .find(|&backend| availability.has(backend))
}
fn norito_gpu_available() -> bool {
    norito::core::hw::has_gpu_compression()
}
fn cuda_available() -> bool {
    #[cfg(unix)]
    {
        if Path::new("/dev/nvidia0").exists() || Path::new("/dev/nvidiactl").exists() {
            return true;
        }
    }
    #[cfg(windows)]
    {
        if let Some(root) = system_root() {
            let system32 = root.join("System32").join("nvcuda.dll");
            let syswow64 = root.join("SysWOW64").join("nvcuda.dll");
            if system32.exists() || syswow64.exists() {
                return true;
            }
        }
    }
    if command_success(
        "nvidia-smi",
        &["--query-gpu=name", "--format=csv,noheader", "--id=0"],
    ) {
        return true;
    }
    if command_success("nvcc", &["--version"]) {
        return true;
    }
    false
}
fn opencl_available() -> bool {
    #[cfg(target_os = "macos")]
    {
        if Path::new("/System/Library/Frameworks/OpenCL.framework/OpenCL").exists()
            && macos_opencl_devices_present()
        {
            return true;
        }
    }
    #[cfg(unix)]
    {
        if has_icd_entries("/etc/OpenCL/vendors") {
            return true;
        }
    }
    #[cfg(windows)]
    {
        if let Some(root) = system_root() {
            let system32 = root.join("System32").join("OpenCL.dll");
            let syswow64 = root.join("SysWOW64").join("OpenCL.dll");
            if system32.exists() || syswow64.exists() {
                return true;
            }
        }
    }
    command_success("clinfo", &["--list"])
}
#[cfg(unix)]
fn has_icd_entries(dir: &str) -> bool {
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .any(|path| {
                    path.extension()
                        .and_then(|ext| ext.to_str())
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("icd"))
                })
        })
        .unwrap_or(false)
}
fn command_success(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}
#[cfg(target_os = "macos")]
fn run_command_capture(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}
#[cfg(windows)]
fn system_root() -> Option<PathBuf> {
    env::var_os("SystemRoot").map(PathBuf::from)
}
#[cfg(test)]
mod detection_tests {
    use super::*;
    fn availability(enabled: &[GpuBackend]) -> BackendAvailability {
        enabled
            .iter()
            .fold(BackendAvailability::empty(), |state, backend| {
                state.with(*backend, true)
            })
    }
    #[test]
    fn resolve_backend_prefers_cuda() {
        assert_eq!(
            resolve_backend(availability(&[
                GpuBackend::Cuda,
                GpuBackend::OpenCl,
                GpuBackend::Metal,
                GpuBackend::Norito,
            ])),
            Some(GpuBackend::Cuda)
        );
    }
    #[test]
    fn resolve_backend_prefers_metal_before_opencl() {
        assert_eq!(
            resolve_backend(availability(&[
                GpuBackend::OpenCl,
                GpuBackend::Metal,
                GpuBackend::Norito,
            ])),
            Some(GpuBackend::Metal)
        );
    }
    #[test]
    fn resolve_backend_prefers_opencl_when_metal_missing() {
        assert_eq!(
            resolve_backend(availability(&[GpuBackend::OpenCl, GpuBackend::Norito])),
            Some(GpuBackend::OpenCl)
        );
    }
    #[test]
    fn resolve_backend_falls_back_to_metal() {
        assert_eq!(
            resolve_backend(availability(&[GpuBackend::Metal, GpuBackend::Norito])),
            Some(GpuBackend::Metal)
        );
    }
    #[test]
    fn resolve_backend_uses_norito_last() {
        assert_eq!(
            resolve_backend(availability(&[GpuBackend::Norito])),
            Some(GpuBackend::Norito)
        );
    }
    #[test]
    fn resolve_backend_returns_none_when_unavailable() {
        assert_eq!(resolve_backend(availability(&[])), None);
    }
    #[test]
    fn quarantined_cuda_is_removed_from_cached_availability() {
        assert_eq!(runtime_backend(Some(GpuBackend::Cuda), true), None);
        assert_eq!(
            runtime_backend(Some(GpuBackend::Cuda), false),
            Some(GpuBackend::Cuda)
        );
        assert_eq!(
            runtime_backend(Some(GpuBackend::Metal), true),
            Some(GpuBackend::Metal)
        );
    }
    #[test]
    fn backend_support_map_excludes_unimplemented_backends() {
        assert!(!gpu_backend_supported_in_build(GpuBackend::OpenCl));
        assert!(!gpu_backend_supported_in_build(GpuBackend::Norito));
    }
    #[cfg(any(not(feature = "fastpq-gpu"), fastpq_cuda_unavailable))]
    #[test]
    fn cuda_backend_support_is_disabled_without_compiled_runtime() {
        assert!(!gpu_backend_supported_in_build(GpuBackend::Cuda));
    }
    #[test]
    fn parse_override_accepts_cpu_gpu_auto() {
        assert_eq!(parse_gpu_override("cpu"), Some(GpuOverride::ForceCpu));
        assert_eq!(parse_gpu_override("GPU"), Some(GpuOverride::ForceGpu));
        assert_eq!(parse_gpu_override("auto"), Some(GpuOverride::Auto));
        assert_eq!(parse_gpu_override("  detect  "), Some(GpuOverride::Auto));
    }
    #[test]
    fn parse_override_rejects_unknown_values() {
        assert_eq!(parse_gpu_override("unknown-mode"), None);
        assert_eq!(parse_gpu_override(""), Some(GpuOverride::Auto));
    }
    #[test]
    fn backend_config_defaults_to_cpu_execution_mode() {
        let params = fastpq_isi::CANONICAL_PARAMETER_SETS[0];
        let config = BackendConfig::new(params);
        assert_eq!(config.execution_mode(), ExecutionMode::Cpu);
        assert_eq!(config.poseidon_mode(), PoseidonExecutionMode::Cpu);
    }
}
#[cfg(test)]
mod observer_tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;
    static OBSERVER_TEST_LOCK: Mutex<()> = Mutex::new(());
    struct ExecutionModeObserverGuard;
    impl Drop for ExecutionModeObserverGuard {
        fn drop(&mut self) {
            clear_execution_mode_observer();
        }
    }
    struct PoseidonPipelineObserverGuard;
    impl Drop for PoseidonPipelineObserverGuard {
        fn drop(&mut self) {
            crate::trace::clear_poseidon_pipeline_observer();
        }
    }
    struct TraceMerkleModeObserverGuard;
    impl Drop for TraceMerkleModeObserverGuard {
        fn drop(&mut self) {
            crate::trace::clear_trace_merkle_mode_observer();
        }
    }
    #[test]
    fn execution_mode_observer_receives_resolution() {
        let _lock = OBSERVER_TEST_LOCK.lock().expect("observer test lock");
        clear_execution_mode_observer();
        let _observer_guard = ExecutionModeObserverGuard;
        let (tx, rx) = mpsc::channel();
        let test_thread = std::thread::current().id();
        set_execution_mode_observer(move |requested, resolved, backend| {
            if std::thread::current().id() == test_thread {
                let _ = tx.send((requested, resolved, backend));
            }
        });
        let resolved = ExecutionMode::Auto.resolve();
        let (requested, resolved_event, backend) = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("observer payload");
        assert_eq!(requested, ExecutionMode::Auto);
        assert_eq!(resolved_event, resolved);
        match resolved {
            ExecutionMode::Cpu => assert!(
                backend.is_none(),
                "CPU resolution should not report a GPU backend"
            ),
            ExecutionMode::Gpu => assert!(
                backend.is_some(),
                "GPU resolution should report the detected backend"
            ),
            ExecutionMode::Auto => unreachable!("resolution never returns Auto"),
        }
        clear_execution_mode_observer();
    }
    #[test]
    fn execution_mode_observer_reports_no_gpu_backend_for_cpu_resolution() {
        let _lock = OBSERVER_TEST_LOCK.lock().expect("observer test lock");
        clear_execution_mode_observer();
        let _observer_guard = ExecutionModeObserverGuard;
        let (tx, rx) = mpsc::channel();
        let test_thread = std::thread::current().id();
        set_execution_mode_observer(move |requested, resolved, backend| {
            if std::thread::current().id() == test_thread {
                let _ = tx.send((requested, resolved, backend));
            }
        });

        for requested in [ExecutionMode::Cpu, ExecutionMode::Auto, ExecutionMode::Gpu] {
            log_execution_resolution(requested, ExecutionMode::Cpu);
            assert_eq!(
                rx.recv_timeout(Duration::from_secs(2))
                    .expect("CPU resolution event"),
                (requested, ExecutionMode::Cpu, None),
                "CPU resolutions must report the route independently of available hardware"
            );
        }
    }
    #[test]
    fn execution_mode_observer_panic_does_not_escape_or_block_reregistration() {
        let _lock = OBSERVER_TEST_LOCK.lock().expect("observer test lock");
        clear_execution_mode_observer();
        let _observer_guard = ExecutionModeObserverGuard;
        let test_thread = std::thread::current().id();
        set_execution_mode_observer(move |_, _, _| {
            assert!(
                std::thread::current().id() != test_thread,
                "observer failure"
            );
        });

        let result = std::panic::catch_unwind(|| {
            notify_execution_mode_observer(ExecutionMode::Auto, ExecutionMode::Cpu, None);
        });
        assert!(result.is_ok(), "observer panic must not escape resolution");

        let (tx, rx) = mpsc::channel();
        set_execution_mode_observer(move |requested, resolved, backend| {
            let _ = tx.send((requested, resolved, backend));
        });
        notify_execution_mode_observer(ExecutionMode::Auto, ExecutionMode::Cpu, None);
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2))
                .expect("replacement observer payload"),
            (ExecutionMode::Auto, ExecutionMode::Cpu, None)
        );
    }
    #[test]
    fn execution_mode_observer_can_clear_itself_reentrantly() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let _lock = OBSERVER_TEST_LOCK.lock().expect("observer test lock");
        clear_execution_mode_observer();
        let _observer_guard = ExecutionModeObserverGuard;
        let observed = Arc::new(AtomicUsize::new(0));
        let observed_for_callback = Arc::clone(&observed);
        let test_thread = std::thread::current().id();
        set_execution_mode_observer(move |_, _, _| {
            if std::thread::current().id() == test_thread {
                observed_for_callback.fetch_add(1, Ordering::SeqCst);
                clear_execution_mode_observer();
            }
        });

        notify_execution_mode_observer(ExecutionMode::Auto, ExecutionMode::Cpu, None);
        notify_execution_mode_observer(ExecutionMode::Auto, ExecutionMode::Cpu, None);
        assert_eq!(observed.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn native_v1_proof_auto_reports_cpu_execution_and_poseidon() {
        let _lock = OBSERVER_TEST_LOCK.lock().expect("observer test lock");
        let _poseidon_lock = crate::trace::POSEIDON_PIPELINE_OBSERVER_TEST_LOCK
            .lock()
            .expect("Poseidon observer test lock");
        clear_execution_mode_observer();
        crate::trace::clear_poseidon_pipeline_observer();
        let _observer_guard = ExecutionModeObserverGuard;
        let _poseidon_observer_guard = PoseidonPipelineObserverGuard;

        let (execution_tx, execution_rx) = mpsc::channel();
        let test_thread = std::thread::current().id();
        set_execution_mode_observer(move |requested, resolved, backend| {
            if std::thread::current().id() == test_thread {
                let _ = execution_tx.send((requested, resolved, backend));
            }
        });
        let (poseidon_tx, poseidon_rx) = mpsc::channel();
        crate::trace::set_poseidon_pipeline_observer(move |policy, path, backend| {
            if std::thread::current().id() == test_thread {
                let _ = poseidon_tx.send((policy, path, backend));
            }
        });

        let params = fastpq_isi::CANONICAL_PARAMETER_SETS[0];
        let batch = TransitionBatch::new(params.name, crate::PublicInputs::default());
        for requested_poseidon in [PoseidonExecutionMode::Auto, PoseidonExecutionMode::Cpu] {
            let backend = StarkBackend::new(
                BackendConfig::new(params)
                    .with_execution_mode(ExecutionMode::Cpu)
                    .with_poseidon_mode(requested_poseidon),
            );
            backend
                .prove(&batch, &PublicIO::default(), 1)
                .expect("configured backend proof");

            let (requested, resolved, execution_backend) = execution_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("execution-mode event");
            assert_eq!(requested, ExecutionMode::Cpu);
            assert_eq!(resolved, ExecutionMode::Cpu);
            assert_eq!(execution_backend, None);
            let (policy, path, hashing_backend) = poseidon_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("native-STARK hashing event");
            assert_eq!(policy.requested(), requested_poseidon);
            assert_eq!(policy.resolved(), ExecutionMode::Cpu);
            assert_eq!(hashing_backend, None);
            assert_eq!(
                path,
                if requested_poseidon == PoseidonExecutionMode::Cpu {
                    "cpu_forced"
                } else {
                    "cpu_fallback"
                }
            );
            assert!(
                poseidon_rx.try_recv().is_err(),
                "one native hashing event per preparation"
            );
        }
    }
    #[test]
    fn canonical_commitment_derivation_forces_cpu_trace_merkle_levels() {
        let _lock = OBSERVER_TEST_LOCK.lock().expect("observer test lock");
        crate::trace::clear_trace_merkle_mode_observer();
        let _observer_guard = TraceMerkleModeObserverGuard;
        let (tx, rx) = mpsc::channel();
        let test_thread = std::thread::current().id();
        crate::trace::set_trace_merkle_mode_observer(move |mode| {
            if std::thread::current().id() == test_thread {
                let _ = tx.send(mode);
            }
        });
        let params = fastpq_isi::CANONICAL_PARAMETER_SETS[0];
        let batch = TransitionBatch::new(params.name, crate::PublicInputs::default());

        derive_batch_commitments(&params, &batch, &PublicIO::default(), 1)
            .expect("canonical commitments");

        let modes = rx.try_iter().collect::<Vec<_>>();
        assert!(!modes.is_empty(), "trace Merkle mode must be observed");
        assert!(
            modes.iter().all(|mode| *mode == ExecutionMode::Cpu),
            "canonical commitment derivation must keep trace Merkle levels on CPU: {modes:?}"
        );
    }
}
#[cfg(target_os = "macos")]
fn metal_available() -> bool {
    // Artifact identity is checked before device discovery. A visible device
    // cannot authorize absent, stale or refused compiled bytes.
    #[cfg(feature = "fastpq-gpu")]
    {
        crate::metal_artifact::admitted_bundle().is_ok() && metal_device_visible_via_api()
    }
    #[cfg(not(feature = "fastpq-gpu"))]
    {
        false
    }
}
#[cfg(target_os = "macos")]
fn macos_opencl_devices_present() -> bool {
    if let Some(result) = macos_system_profiler_opencl_devices() {
        return result;
    }
    if command_success("clinfo", &["-l"]) {
        return true;
    }
    macos_ioreg_reports_accelerator()
}
#[cfg(target_os = "macos")]
fn macos_system_profiler_opencl_devices() -> Option<bool> {
    let output = run_command_capture(
        "system_profiler",
        &["SPOpenCLDataType", "-detailLevel", "mini"],
    )?;
    let lowered = output.to_lowercase();
    if lowered.contains("no opencl devices") || lowered.contains("opencl software") {
        return Some(false);
    }
    if lowered.contains("devices:") || lowered.contains("device type:") {
        return Some(true);
    }
    None
}
#[cfg(target_os = "macos")]
fn macos_ioreg_reports_accelerator() -> bool {
    if let Some(output) = run_command_capture("ioreg", &["-l", "-w0", "-c", "IOAccelerator"]) {
        let lowered = output.to_lowercase();
        if lowered.contains("ioaccelerator") || lowered.contains("metalpluginclass") {
            return true;
        }
    }
    false
}
#[cfg(not(target_os = "macos"))]
fn metal_available() -> bool {
    false
}
#[cfg(all(feature = "fastpq-gpu", target_os = "macos"))]
fn metal_device_visible_via_api() -> bool {
    warm_up_core_graphics_display();
    let debug = fastpq_debug_metal_enum();
    if let Some(device) = Device::system_default() {
        if debug {
            eprintln!(
                "fastpq::planner: MTLCreateSystemDefaultDevice succeeded ({} / headless={} / low_power={})",
                device.name(),
                bool_flag(device.is_headless()),
                bool_flag(device.is_low_power())
            );
        }
        return true;
    }
    let devices = Device::all();
    if debug {
        eprintln!(
            "fastpq::planner: MTLCopyAllDevices returned {} device(s)",
            devices.len()
        );
        for (index, device) in devices.iter().enumerate() {
            eprintln!(
                "fastpq::planner:   device #{index}: name=\"{}\", location={}, headless={}, low_power={}",
                device.name(),
                device_location_label(device.location()),
                bool_flag(device.is_headless()),
                bool_flag(device.is_low_power())
            );
        }
    }
    !devices.is_empty()
}
#[cfg(all(feature = "fastpq-gpu", target_os = "macos"))]
fn fastpq_debug_metal_enum() -> bool {
    if let Some(enabled) = overrides::metal_debug_enum_override() {
        return enabled;
    }
    *DEBUG_METAL_ENUM_ENV.get_or_init(|| {
        overrides::guard_env_override(|| overrides::debug_env_bool("FASTPQ_DEBUG_METAL_ENUM"))
            .unwrap_or(false)
    })
}
#[cfg(all(feature = "fastpq-gpu", target_os = "macos"))]
fn bool_flag(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
#[cfg(all(feature = "fastpq-gpu", target_os = "macos"))]
fn device_location_label(location: MTLDeviceLocation) -> &'static str {
    match location {
        MTLDeviceLocation::BuiltIn => "built_in",
        MTLDeviceLocation::Slot => "slot",
        MTLDeviceLocation::External => "external",
        _ => "unknown",
    }
}
/// Internal backend configuration used by the FASTPQ prover.
#[derive(Debug, Clone, Copy)]
#[cfg(any(test, feature = "dev-tools"))]
pub struct BackendConfig {
    /// Canonical parameter set driving this backend instance.
    params: StarkParameterSet,
    /// Execution mode used for FFT/LDE computations.
    execution_mode: ExecutionMode,
    /// Poseidon pipeline override (defaults to [`ExecutionMode::Auto`]).
    poseidon_mode: PoseidonExecutionMode,
}
#[cfg(any(test, feature = "dev-tools"))]
impl BackendConfig {
    /// Construct a configuration from a canonical parameter set.
    pub(crate) fn new(params: StarkParameterSet) -> Self {
        Self {
            params,
            execution_mode: ExecutionMode::Cpu,
            poseidon_mode: PoseidonExecutionMode::Cpu,
        }
    }
    /// Override the execution mode used by the backend.
    #[must_use]
    pub(crate) fn with_execution_mode(mut self, mode: ExecutionMode) -> Self {
        self.execution_mode = mode;
        self
    }
    /// Override the Poseidon pipeline execution mode used by the backend.
    #[must_use]
    pub(crate) fn with_poseidon_mode(mut self, mode: PoseidonExecutionMode) -> Self {
        self.poseidon_mode = mode;
        self
    }
    /// Return the requested execution mode.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn execution_mode(&self) -> ExecutionMode {
        self.execution_mode
    }
    /// Return the configured Poseidon pipeline mode.
    #[must_use]
    pub(crate) fn poseidon_mode(&self) -> PoseidonExecutionMode {
        self.poseidon_mode
    }
    /// Reject requested proof execution paths that have no native-V1 implementation.
    pub(crate) fn validate_native_v1_modes(&self) -> Result<()> {
        if self.execution_mode == ExecutionMode::Gpu
            || self.poseidon_mode == PoseidonExecutionMode::Gpu
        {
            return Err(Error::NativeV1GpuUnavailable);
        }
        Ok(())
    }
    /// Resolve and report the execution path actually used by native-V1 proofs.
    fn resolve_native_v1_execution_mode(&self) -> Result<ExecutionMode> {
        self.validate_native_v1_modes()?;
        log_execution_resolution(self.execution_mode, ExecutionMode::Cpu);
        Ok(ExecutionMode::Cpu)
    }
}
/// Deterministic artifact emitted by the native STARK backend.
///
/// This mirrors the minimal data the verifier needs to
/// reconstruct the Fiat–Shamir transcript and query openings.
#[derive(Debug, Clone)]
#[cfg(any(test, feature = "dev-tools"))]
pub struct BackendArtifact {
    /// Canonical parameter set name.
    pub(crate) parameter: String,
    /// Canonical commitment over the parameterised trace.
    pub(crate) trace_commitment: WireGoldilocksDigest384V1,
    /// Poseidon Merkle root over column commitments.
    pub(crate) trace_root: GoldilocksDigest384V1,
    /// Poseidon Merkle root over row-major AIR trace openings.
    pub(crate) air_trace_root: GoldilocksDigest384V1,
    /// Poseidon Merkle root over AIR composition evaluations.
    pub(crate) air_composition_root: GoldilocksDigest384V1,
    /// Poseidon Merkle root over the low-degree extension leaf hashes.
    pub(crate) lde_root: GoldilocksDigest384V1,
    /// Number of evaluation rows committed under `lde_root`.
    pub(crate) lde_domain_size: u32,
    /// Permission accumulator over the canonical witness LDE.
    pub(crate) lookup_grand_product: u64,
    /// Transcript-derived permission accumulator challenge.
    pub(crate) lookup_challenge: u64,
    /// Fp4 composition challenges sampled after the trace roots and permission challenge.
    pub(crate) alphas: Vec<GoldilocksFp4V1>,
    /// Commitment to each joint FRI layer plus the terminal root.
    pub(crate) fri_layers: Vec<GoldilocksDigest384V1>,
    /// Fiat–Shamir challenges used for each FRI folding round.
    pub(crate) fri_betas: Vec<GoldilocksFp4V1>,
    /// Sampled query openings into the evaluation domain.
    pub(crate) query_openings: Vec<(u32, GoldilocksFp4V1)>,
    /// Full LDE leaf chunks containing each queried evaluation.
    pub(crate) query_chunks: Vec<Vec<GoldilocksFp4V1>>,
    /// Merkle authentication paths for each queried evaluation chunk.
    pub(crate) query_paths: Vec<Vec<GoldilocksDigest384V1>>,
    /// Sampled AIR row/composition openings.
    pub(crate) air_openings: Vec<AirConstraintOpening>,
    /// Per-round FRI openings for sampled query indices.
    pub(crate) fri_query_openings: Vec<FriQueryOpening>,
}
/// Concrete backend implementing the deterministic FASTPQ STARK pipeline.
#[derive(Debug, Clone)]
#[cfg(any(test, feature = "dev-tools"))]
pub struct StarkBackend {
    config: BackendConfig,
}
#[cfg(any(test, feature = "dev-tools"))]
impl StarkBackend {
    /// Create a backend from a canonical configuration.
    pub(crate) fn new(config: BackendConfig) -> Self {
        Self { config }
    }
    /// Expose the configured execution mode, primarily for tests.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn execution_mode(&self) -> ExecutionMode {
        self.config.execution_mode()
    }

    pub(crate) fn parameter_name(&self) -> &'static str {
        self.config.params.name
    }
    /// Validate proof execution before statement or witness preprocessing.
    pub(crate) fn validate_native_v1_modes(&self) -> Result<()> {
        self.config.validate_native_v1_modes()
    }
}

#[cfg(any(test, feature = "dev-tools"))]
fn digest_domain_v1<'a>(
    role: &'a [u8],
    phase: &'a [u8],
    level: usize,
    index: usize,
    counter: u64,
) -> Result<GoldilocksDigestDomainV1<'a>> {
    Ok(GoldilocksDigestDomainV1 {
        catalog: FASTPQ_CATALOG_V1.as_bytes(),
        protocol: FASTPQ_FINAL_V1_ID.as_bytes(),
        profile: FASTPQ_FINAL_V1_ID.as_bytes(),
        role,
        phase,
        level: u64::try_from(level).map_err(|_| Error::QueryIndexOverflow { index: level })?,
        index: u64::try_from(index).map_err(|_| Error::QueryIndexOverflow { index })?,
        counter,
    })
}

#[cfg(any(test, feature = "dev-tools"))]
fn hash_bytes_v1(
    role: &[u8],
    phase: &[u8],
    level: usize,
    index: usize,
    counter: u64,
    fields: &[&[u8]],
) -> Result<GoldilocksDigest384V1> {
    hash_bytes_384_v1(
        digest_domain_v1(role, phase, level, index, counter)?,
        fields,
    )
    .ok_or_else(|| Error::PayloadLengthOverflow {
        length: fields
            .iter()
            .fold(0_usize, |total, field| total.saturating_add(field.len())),
    })
}

#[cfg(any(test, feature = "dev-tools"))]
fn digest_domain_prefix_v1<'a>(
    role: &'a [u8],
    phase: &'a [u8],
    level: usize,
    counter: u64,
) -> Result<GoldilocksDigest384DomainPrefixV1<'a>> {
    GoldilocksDigest384DomainPrefixV1::new(digest_domain_v1(role, phase, level, 0, counter)?)
        .ok_or_else(|| Error::PayloadLengthOverflow {
            length: role.len().saturating_add(phase.len()),
        })
}

#[cfg(any(test, feature = "dev-tools"))]
fn hash_at_prefix_v1(
    prefix: &GoldilocksDigest384DomainPrefixV1<'_>,
    index: usize,
    fields: &[&[u8]],
) -> Result<GoldilocksDigest384V1> {
    prefix
        .hash_at(
            u64::try_from(index).map_err(|_| Error::QueryIndexOverflow { index })?,
            fields,
        )
        .ok_or_else(|| Error::PayloadLengthOverflow {
            length: fields
                .iter()
                .fold(0_usize, |total, field| total.saturating_add(field.len())),
        })
}

#[cfg(any(test, feature = "dev-tools"))]
fn hash_u64_values_v1(
    role: &[u8],
    phase: &[u8],
    level: usize,
    index: usize,
    counter: u64,
    values: &[u64],
) -> Result<GoldilocksDigest384V1> {
    let mut bytes = Vec::with_capacity(values.len().saturating_mul(8));
    for value in values {
        if *value >= GOLDILOCKS_MODULUS {
            return Err(Error::NonCanonicalGoldilocksElement {
                context: "native_stark_digest_input",
                indices: vec![index],
            });
        }
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    hash_bytes_v1(role, phase, level, index, counter, &[&bytes])
}
/// Hash the low-degree extension evaluations into Merkle leaves grouped by the
/// canonical chunk size derived from the FRI arity.
///
/// # Errors
/// Returns an error if hashing a chunk into the Merkle leaf domain fails.
#[cfg(any(test, feature = "dev-tools"))]
pub fn hash_lde_leaves(evaluations: &[u64], arity: u32) -> Result<Vec<GoldilocksDigest384V1>> {
    hash_lde_leaves_with_mode(evaluations, arity, default_batch_execution_mode())
}
#[cfg(any(test, feature = "dev-tools"))]
fn hash_lde_leaves_with_mode(
    evaluations: &[u64],
    arity: u32,
    mode: ExecutionMode,
) -> Result<Vec<GoldilocksDigest384V1>> {
    let chunk = lde_chunk_size(arity)?;
    let _ = mode;
    if evaluations.is_empty() {
        return Ok(Vec::new());
    }
    evaluations
        .chunks(chunk)
        .enumerate()
        .map(|(index, values)| {
            hash_u64_values_v1(
                LDE_COMMITMENT_ROLE_V1,
                MERKLE_LEAF_PHASE_V1,
                0,
                index,
                0,
                values,
            )
        })
        .collect()
}
/// Hash one LDE leaf chunk using the same domain as the batched LDE leaf commitment.
///
/// # Errors
/// Returns an error if the leaf index cannot be represented as a field limb.
#[cfg(test)]
pub fn hash_lde_chunk(leaf_index: usize, values: &[u64]) -> Result<GoldilocksDigest384V1> {
    hash_u64_values_v1(
        LDE_COMMITMENT_ROLE_V1,
        MERKLE_LEAF_PHASE_V1,
        0,
        leaf_index,
        0,
        values,
    )
}
/// Hash a complete mixed-trace Fp4 leaf in coefficient order.
///
/// # Errors
/// Returns an error for a noncanonical coefficient or invalid digest framing.
#[cfg(any(test, feature = "dev-tools"))]
pub fn hash_lde_chunk_fp4(
    leaf_index: usize,
    values: &[GoldilocksFp4V1],
) -> Result<GoldilocksDigest384V1> {
    hash_fp4_values_v1(LDE_COMMITMENT_ROLE_V1, 0, leaf_index, values)
}
#[cfg(any(test, feature = "dev-tools"))]
fn hash_fp4_values_v1(
    role: &[u8],
    level: usize,
    index: usize,
    values: &[GoldilocksFp4V1],
) -> Result<GoldilocksDigest384V1> {
    let mut bytes = Vec::with_capacity(values.len().saturating_mul(32));
    for (value_index, value) in values.iter().enumerate() {
        for (coefficient_index, coefficient) in value.coefficients().into_iter().enumerate() {
            if coefficient >= GOLDILOCKS_MODULUS {
                return Err(Error::NonCanonicalGoldilocksElement {
                    context: "native_stark_fp4_digest_input",
                    indices: vec![index, value_index, coefficient_index],
                });
            }
        }
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    hash_bytes_v1(role, MERKLE_LEAF_PHASE_V1, level, index, 0, &[&bytes])
}
#[cfg(any(test, feature = "dev-tools"))]
fn hash_lde_leaves_fp4(
    evaluations: &[GoldilocksFp4V1],
    arity: u32,
) -> Result<Vec<GoldilocksDigest384V1>> {
    evaluations
        .chunks(lde_chunk_size(arity)?)
        .enumerate()
        .map(|(index, values)| hash_lde_chunk_fp4(index, values))
        .collect()
}
/// Hash one row-major AIR trace opening.
///
/// # Errors
/// Returns an error if the row index cannot be represented as a field limb.
#[cfg(any(test, feature = "dev-tools"))]
pub fn hash_air_trace_row(row_index: usize, values: &[u64]) -> Result<GoldilocksDigest384V1> {
    hash_u64_values_v1(
        AIR_TRACE_COMMITMENT_ROLE_V1,
        MERKLE_LEAF_PHASE_V1,
        0,
        row_index,
        0,
        values,
    )
}
/// Hash one AIR composition leaf.
///
/// # Errors
/// Returns an error if the leaf index cannot be represented as a field limb.
#[cfg(any(test, feature = "dev-tools"))]
pub fn hash_air_composition_leaf(
    index: usize,
    value: GoldilocksFp4V1,
) -> Result<GoldilocksDigest384V1> {
    hash_fp4_values_v1(AIR_COMPOSITION_COMMITMENT_ROLE_V1, 0, index, &[value])
}
/// Hash all row-major AIR trace leaves.
///
/// # Errors
/// Returns a shape error before hashing, or the first failing row in index order.
#[cfg(any(test, feature = "dev-tools"))]
fn hash_air_trace_rows_with_mode(
    columns: &[Vec<u64>],
    mode: ExecutionMode,
) -> Result<Vec<GoldilocksDigest384V1>> {
    // Keep fewer than two 16-row jobs sequential. This avoids scheduling tiny
    // batches and reuses each job's canonical byte buffer across several hashes.
    const ROWS_PER_JOB: usize = 16;
    // Digest384 remains CPU-only for every requested mode. The caller reports
    // the requested policy and actual CPU route before building these leaves.
    let _ = mode;
    if columns.is_empty() {
        return Ok(Vec::new());
    }
    let row_count = columns[0].len();
    if !columns.iter().all(|column| column.len() == row_count) {
        return Err(Error::AirOpeningMismatch { index: 0 });
    }
    if row_count == 0 {
        return Ok(Vec::new());
    }
    // All rows share the exact typed domain through its tree-level field.
    // The immutable prefix still binds each full row index and payload; keep
    // hash_air_trace_row as the independent canonical one-shot oracle.
    let prefix = digest_domain_prefix_v1(AIR_TRACE_COMMITMENT_ROLE_V1, MERKLE_LEAF_PHASE_V1, 0, 0)?;
    let row_bytes = columns.len().saturating_mul(8);
    let hash_row = |bytes: &mut Vec<u8>, row_index: usize| {
        bytes.clear();
        for column in columns {
            let value = column[row_index];
            if value >= GOLDILOCKS_MODULUS {
                return Err(Error::NonCanonicalGoldilocksElement {
                    context: "native_stark_digest_input",
                    indices: vec![row_index],
                });
            }
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        hash_at_prefix_v1(&prefix, row_index, &[bytes.as_slice()])
    };
    if row_count < 2 * ROWS_PER_JOB {
        let mut bytes = Vec::with_capacity(row_bytes);
        return (0..row_count)
            .map(|row_index| hash_row(&mut bytes, row_index))
            .collect();
    }
    let results: Vec<Result<GoldilocksDigest384V1>> = (0..row_count)
        .into_par_iter()
        .with_min_len(ROWS_PER_JOB)
        .map_init(
            || Vec::with_capacity(row_bytes),
            |bytes, row_index| hash_row(bytes, row_index),
        )
        .collect();
    // Indexed collection preserves leaf order. Select errors serially as well:
    // a parallel Result reduction could report whichever malformed row finishes first.
    results.into_iter().collect()
}
/// Hash all AIR composition leaves.
///
/// # Errors
/// Returns an error if leaf hashing fails.
#[cfg(any(test, feature = "dev-tools"))]
fn hash_air_composition_leaves_with_mode(
    values: &[GoldilocksFp4V1],
    mode: ExecutionMode,
) -> Result<Vec<GoldilocksDigest384V1>> {
    let _ = mode;
    hash_fp4_single_leaves_with_role(AIR_COMPOSITION_COMMITMENT_ROLE_V1, values)
}

// One immutable typed prefix serves an entire natural-order oracle. Each leaf
// still binds its full index and all four canonical coordinates. Stack payloads
// avoid a tiny allocation per leaf; indexed jobs preserve deterministic errors.
#[cfg(any(test, feature = "dev-tools"))]
fn hash_fp4_single_leaves_with_role(
    role: &[u8],
    values: &[GoldilocksFp4V1],
) -> Result<Vec<GoldilocksDigest384V1>> {
    if values.is_empty() {
        return Ok(Vec::new());
    }
    let prefix = digest_domain_prefix_v1(role, MERKLE_LEAF_PHASE_V1, 0, 0)?;
    let hash_leaf = |(index, value): (usize, &GoldilocksFp4V1)| {
        for (coefficient_index, coefficient) in value.coefficients().into_iter().enumerate() {
            if coefficient >= GOLDILOCKS_MODULUS {
                return Err(Error::NonCanonicalGoldilocksElement {
                    context: "native_stark_fp4_digest_input",
                    indices: vec![index, 0, coefficient_index],
                });
            }
        }
        hash_at_prefix_v1(&prefix, index, &[&value.to_le_bytes()])
    };
    if values.len() < 32 {
        return values.iter().enumerate().map(hash_leaf).collect();
    }
    let results: Vec<Result<_>> = values.par_iter().enumerate().map(hash_leaf).collect();
    results.into_iter().collect()
}

#[derive(Debug)]
#[cfg(any(test, feature = "dev-tools"))]
struct AirColumnLayout {
    boolean_selectors: [usize; AIR_BOOLEAN_RESIDUE_COUNT],
    operation_selectors: [usize; 6],
    numeric_selectors: [usize; 3],
    permission_selectors: [usize; 2],
    s_active: usize,
    s_transfer: usize,
    s_perm: usize,
    perm_hash: usize,
    delta: usize,
    value_old_limbs: Vec<usize>,
    value_new_limbs: Vec<usize>,
    value_old_len: usize,
    value_new_len: usize,
    integer_auxiliary: Option<[usize; transfer_integer_air::AUXILIARY_COLUMN_COUNT]>,
    stable_columns: [usize; AIR_STABLE_RESIDUE_COUNT],
}

#[cfg(any(test, feature = "dev-tools"))]
impl AirColumnLayout {
    fn from_names<S: AsRef<str>>(column_names: &[S]) -> Result<Self> {
        let required = |name: &str| -> Result<usize> {
            column_names
                .iter()
                .position(|column| column.as_ref() == name)
                .ok_or_else(|| Error::MissingColumn(name.to_owned()))
        };
        let s_active = required("s_active")?;
        let s_transfer = required("s_transfer")?;
        let s_mint = required("s_mint")?;
        let s_burn = required("s_burn")?;
        let s_role_grant = required("s_role_grant")?;
        let s_role_revoke = required("s_role_revoke")?;
        let s_meta_set = required("s_meta_set")?;
        let s_perm = required("s_perm")?;
        let perm_hash = required("perm_hash")?;
        let delta = required("delta")?;
        let mut stable_columns = [0usize; AIR_STABLE_RESIDUE_COUNT];
        for (limb, column) in stable_columns[..crate::trace::METADATA_COMMITMENT_LIMBS]
            .iter_mut()
            .enumerate()
        {
            *column = required(&format!("metadata_hash_limb_{limb}"))?;
        }
        stable_columns[crate::trace::METADATA_COMMITMENT_LIMBS] = required("dsid")?;
        stable_columns[crate::trace::METADATA_COMMITMENT_LIMBS + 1] = required("slot")?;
        let integer_names = transfer_integer_air::auxiliary_column_names();
        let has_integer_columns = integer_names
            .iter()
            .any(|name| column_names.iter().any(|column| column.as_ref() == name));
        let integer_auxiliary = if has_integer_columns {
            let mut columns = [0; transfer_integer_air::AUXILIARY_COLUMN_COUNT];
            for (column, name) in columns.iter_mut().zip(&integer_names) {
                *column = required(name)?;
            }
            Some(columns)
        } else {
            None
        };
        Ok(Self {
            boolean_selectors: [
                s_active,
                s_transfer,
                s_mint,
                s_burn,
                s_role_grant,
                s_role_revoke,
                s_meta_set,
                s_perm,
            ],
            operation_selectors: [
                s_transfer,
                s_mint,
                s_burn,
                s_role_grant,
                s_role_revoke,
                s_meta_set,
            ],
            numeric_selectors: [s_transfer, s_mint, s_burn],
            permission_selectors: [s_role_grant, s_role_revoke],
            s_active,
            s_transfer,
            s_perm,
            perm_hash,
            delta,
            value_old_limbs: contiguous_limb_columns(column_names, "value_old_limb_"),
            value_new_limbs: contiguous_limb_columns(column_names, "value_new_limb_"),
            value_old_len: required("value_old_len")?,
            value_new_len: required("value_new_len")?,
            integer_auxiliary,
            stable_columns,
        })
    }

    fn residue_count(&self) -> usize {
        AIR_COMPOSITION_ALPHA_COUNT
            + self.value_old_limbs.len().saturating_sub(2)
            + self.value_new_limbs.len().saturating_sub(2)
    }
}

/// Number of independent coefficients required by the canonical column schema.
#[cfg(any(test, feature = "dev-tools"))]
pub fn air_composition_alpha_count<S: AsRef<str>>(column_names: &[S]) -> usize {
    AIR_COMPOSITION_ALPHA_COUNT
        + contiguous_limb_columns(column_names, "value_old_limb_")
            .len()
            .saturating_sub(2)
        + contiguous_limb_columns(column_names, "value_new_limb_")
            .len()
            .saturating_sub(2)
}

#[cfg(any(test, feature = "dev-tools"))]
fn contiguous_limb_columns<S: AsRef<str>>(column_names: &[S], prefix: &str) -> Vec<usize> {
    let mut columns = Vec::new();
    for limb in 0usize.. {
        let name = format!("{prefix}{limb}");
        let Some(index) = column_names
            .iter()
            .position(|column| column.as_ref() == name.as_str())
        else {
            break;
        };
        columns.push(index);
    }
    columns
}

#[cfg(any(test, feature = "dev-tools"))]
fn packed_column_value_at<F>(columns: &[usize], value_at: &F) -> u64
where
    F: Fn(usize) -> u64,
{
    let mut value = 0u64;
    let mut radix_power = FIELD_ONE;
    let limb_radix = 1u64 << 56;
    for &column in columns {
        value = add_mod(value, mul_mod(value_at(column), radix_power));
        radix_power = mul_mod(radix_power, limb_radix);
    }
    value
}

#[cfg(any(test, feature = "dev-tools"))]
fn air_constraint_residues_with_layout<C, N>(
    layout: &AirColumnLayout,
    current: C,
    next: N,
    residues: &mut [u64],
) where
    C: Fn(usize) -> u64,
    N: Fn(usize) -> u64,
{
    debug_assert_eq!(residues.len(), layout.residue_count());
    let mut residue_index = 0;
    for &selector in &layout.boolean_selectors {
        residues[residue_index] = mul_mod(current(selector), sub_mod(current(selector), FIELD_ONE));
        residue_index += 1;
    }
    let operation_sum = layout
        .operation_selectors
        .iter()
        .fold(0u64, |sum, &selector| add_mod(sum, current(selector)));
    residues[residue_index] = sub_mod(current(layout.s_active), operation_sum);
    residue_index += 1;
    let permission_sum = layout
        .permission_selectors
        .iter()
        .fold(0u64, |sum, &selector| add_mod(sum, current(selector)));
    residues[residue_index] = sub_mod(current(layout.s_perm), permission_sum);
    residue_index += 1;
    residues[residue_index] = mul_mod(
        next(layout.s_active),
        sub_mod(FIELD_ONE, current(layout.s_active)),
    );
    residue_index += 1;
    let value_old = packed_column_value_at(&layout.value_old_limbs, &current);
    let value_new = packed_column_value_at(&layout.value_new_limbs, &current);
    let expected_delta = sub_mod(value_new, value_old);
    let numeric_selector = layout
        .numeric_selectors
        .iter()
        .fold(0u64, |sum, &selector| add_mod(sum, current(selector)));
    residues[residue_index] = mul_mod(
        numeric_selector,
        sub_mod(expected_delta, current(layout.delta)),
    );
    residue_index += 1;
    for &stable in &layout.stable_columns {
        residues[residue_index] = sub_mod(current(stable), next(stable));
        residue_index += 1;
    }
    // Metadata-only schemas omit the transfer auxiliary columns. Their
    // canonical transfer witness is the identically-zero polynomial.
    let auxiliary = layout.integer_auxiliary.map_or(
        [0; transfer_integer_air::AUXILIARY_COLUMN_COUNT],
        |columns| columns.map(&current),
    );
    let before = core::array::from_fn(|limb| {
        layout
            .value_old_limbs
            .get(limb)
            .map_or(0, |&column| current(column))
    });
    let after = core::array::from_fn(|limb| {
        layout
            .value_new_limbs
            .get(limb)
            .map_or(0, |&column| current(column))
    });
    let witness =
        transfer_integer_air::TransferIntegerWitness::from_auxiliary(before, after, &auxiliary);
    let integer_residues = transfer_integer_air::constraint_residues(
        current(layout.s_transfer),
        current(layout.value_old_len),
        current(layout.value_new_len),
        &witness,
    );
    residues[residue_index..residue_index + integer_residues.len()]
        .copy_from_slice(&integer_residues);
    residue_index += integer_residues.len();
    for &column in layout
        .value_old_limbs
        .iter()
        .skip(2)
        .chain(layout.value_new_limbs.iter().skip(2))
    {
        residues[residue_index] = mul_mod(current(layout.s_transfer), current(column));
        residue_index += 1;
    }
    debug_assert_eq!(residue_index, residues.len());
}

#[cfg(any(test, feature = "dev-tools"))]
fn air_constraint_residues_for_rows(
    column_names: &[String],
    current: &[u64],
    next: &[u64],
) -> Result<Vec<u64>> {
    if current.len() != column_names.len() || next.len() != column_names.len() {
        return Err(Error::AirOpeningMismatch {
            index: current.len(),
        });
    }
    let layout = AirColumnLayout::from_names(column_names)?;
    let mut residues = vec![0; layout.residue_count()];
    air_constraint_residues_with_layout(
        &layout,
        |column| current[column],
        |column| next[column],
        &mut residues,
    );
    Ok(residues)
}

/// Field operations needed to combine base-field AIR residues.
#[cfg(any(test, feature = "dev-tools"))]
pub trait AirCombinationField: Copy {
    /// Additive identity.
    const ZERO: Self;
    /// Add one combined residue.
    fn add(self, rhs: Self) -> Self;
    /// Scale by a base-field residue or zerofier weight.
    fn mul_base(self, rhs: u64) -> Self;
}
#[cfg(any(test, feature = "dev-tools"))]
impl AirCombinationField for u64 {
    const ZERO: Self = 0;
    fn add(self, rhs: Self) -> Self {
        add_mod(self, rhs)
    }
    fn mul_base(self, rhs: u64) -> Self {
        mul_mod(self, rhs)
    }
}
#[cfg(any(test, feature = "dev-tools"))]
impl AirCombinationField for GoldilocksFp4V1 {
    const ZERO: Self = Self::ZERO;
    fn add(self, rhs: Self) -> Self {
        self.add(rhs)
    }
    fn mul_base(self, rhs: u64) -> Self {
        self.mul_base(rhs)
    }
}
#[cfg(any(test, feature = "dev-tools"))]
fn validate_air_composition_alphas<F>(alphas: &[F], expected: usize) -> Result<()> {
    if alphas.len() != expected {
        return Err(Error::AirChallengeCountMismatch {
            expected,
            actual: alphas.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
fn combine_air_constraint_residues<F: AirCombinationField>(alphas: &[F], residues: &[u64]) -> F {
    alphas
        .iter()
        .zip(residues)
        .fold(F::ZERO, |acc, (&alpha, &residue)| {
            acc.add(alpha.mul_base(residue))
        })
}

#[cfg(any(test, feature = "dev-tools"))]
fn combine_air_quotients<F: AirCombinationField>(
    alphas: &[F],
    residues: &[u64],
    weights: AirQuotientWeights,
) -> F {
    let mut rows = F::ZERO;
    let mut transitions = F::ZERO;
    for (index, (&alpha, &residue)) in alphas.iter().zip(residues).enumerate() {
        let weighted = alpha.mul_base(residue);
        // Prefix shape and stability relate adjacent rows. Their zerofier
        // excludes the last row; all other constraints hold at every row.
        if index == AIR_BOOLEAN_RESIDUE_COUNT + 2
            || (AIR_BOOLEAN_RESIDUE_COUNT + AIR_RELATION_RESIDUE_COUNT
                ..AIR_BOOLEAN_RESIDUE_COUNT + AIR_RELATION_RESIDUE_COUNT + AIR_STABLE_RESIDUE_COUNT)
                .contains(&index)
        {
            transitions = transitions.add(weighted);
        } else {
            rows = rows.add(weighted);
        }
    }
    rows.mul_base(weights.all_rows)
        .add(transitions.mul_base(weights.transitions))
}

/// Evaluate the quotient relation at a sampled authenticated coset point.
#[cfg(any(test, feature = "dev-tools"))]
pub fn air_quotient_value_for_rows<F: AirCombinationField>(
    column_names: &[String],
    current: &[u64],
    next: &[u64],
    alphas: &[F],
    weights: AirQuotientWeights,
) -> Result<F> {
    validate_air_composition_alphas(alphas, air_composition_alpha_count(column_names))?;
    let residues = air_constraint_residues_for_rows(column_names, current, next)?;
    Ok(combine_air_quotients(alphas, &residues, weights))
}

/// Evaluate the sampled FASTPQ AIR composition value for two adjacent rows.
///
/// # Errors
/// Returns an error when the advertised column schema is missing mandatory columns, the
/// challenge count differs from the residue count, or row widths do not match the schema.
#[cfg(test)]
pub fn air_composition_value_for_rows(
    column_names: &[String],
    current: &[u64],
    next: &[u64],
    alphas: &[u64],
) -> Result<u64> {
    validate_air_composition_alphas(alphas, air_composition_alpha_count(column_names))?;
    let residues = air_constraint_residues_for_rows(column_names, current, next)?;
    Ok(combine_air_constraint_residues(alphas, &residues))
}
/// Evaluate FASTPQ AIR composition values over all row openings.
///
/// # Errors
/// Returns an error when columns have inconsistent lengths or the schema is malformed.
#[cfg(test)]
pub fn air_composition_values(
    column_names: &[String],
    columns: &[Vec<u64>],
    alphas: &[u64],
    next_step: usize,
) -> Result<Vec<u64>> {
    air_values(column_names, columns, alphas, next_step, None)
}

#[cfg(any(test, feature = "dev-tools"))]
fn air_quotient_values<F: AirCombinationField>(
    params: &StarkParameterSet,
    column_names: &[String],
    columns: &[Vec<u64>],
    alphas: &[F],
) -> Result<Vec<F>> {
    let row_count = columns.first().map_or(0, Vec::len);
    let domain = AirQuotientDomain::new(params, row_count)?;
    let next_step =
        usize::try_from(params.fri.blowup_factor).expect("FRI blowup factor fits usize");
    air_values(column_names, columns, alphas, next_step, Some(&domain))
}

#[cfg(any(test, feature = "dev-tools"))]
fn air_values<F: AirCombinationField>(
    column_names: &[String],
    columns: &[Vec<u64>],
    alphas: &[F],
    next_step: usize,
    quotient: Option<&AirQuotientDomain>,
) -> Result<Vec<F>> {
    if columns.is_empty() {
        return Ok(Vec::new());
    }
    let row_count = columns[0].len();
    if !columns.iter().all(|column| column.len() == row_count) {
        return Err(Error::AirOpeningMismatch { index: 0 });
    }
    if row_count != 0 && next_step == 0 {
        return Err(Error::QueryIndexOutOfRange {
            index: 0,
            len: row_count,
        });
    }
    if row_count == 0 {
        return Ok(Vec::new());
    }
    validate_air_composition_alphas(alphas, air_composition_alpha_count(column_names))?;
    if columns.len() != column_names.len() {
        return Err(Error::AirOpeningMismatch {
            index: columns.len(),
        });
    }
    let layout = AirColumnLayout::from_names(column_names)?;
    let next_step = next_step % row_count;
    let mut values = Vec::with_capacity(row_count);
    let mut quotient_weights = quotient.map(AirQuotientDomain::weights);
    let mut residues = vec![0; layout.residue_count()];
    for index in 0..row_count {
        let next_index = (index + next_step) % row_count;
        air_constraint_residues_with_layout(
            &layout,
            |column| columns[column][index],
            |column| columns[column][next_index],
            &mut residues,
        );
        if let Some(weights) = quotient_weights.as_mut().and_then(Iterator::next) {
            values.push(combine_air_quotients(alphas, &residues, weights));
        } else {
            #[cfg(test)]
            values.push(combine_air_constraint_residues(alphas, &residues));
            #[cfg(not(test))]
            return Err(Error::AirOpeningMismatch { index });
        }
    }
    Ok(values)
}
#[cfg(any(test, feature = "dev-tools"))]
fn air_row_at(columns: &[Vec<u64>], row_index: usize) -> Result<Vec<u64>> {
    columns
        .iter()
        .map(|column| {
            column
                .get(row_index)
                .copied()
                .ok_or(Error::QueryIndexOutOfRange {
                    index: row_index,
                    len: column.len(),
                })
        })
        .collect()
}

#[cfg(any(test, feature = "dev-tools"))]
fn ensure_base_trace_constraints(trace: &crate::trace::Trace) -> Result<()> {
    if trace.padded_len == 0 {
        return Ok(());
    }
    let column_names = trace
        .columns
        .iter()
        .map(|column| column.name.as_str())
        .collect::<Vec<_>>();
    let layout = AirColumnLayout::from_names(&column_names)?;
    let mut residues = vec![0; layout.residue_count()];
    for row_index in 0..trace.padded_len {
        let next_index = row_index
            .checked_add(1)
            .filter(|next| *next < trace.padded_len)
            .unwrap_or(row_index);
        air_constraint_residues_with_layout(
            &layout,
            |column| trace.columns[column].values[row_index],
            |column| trace.columns[column].values[next_index],
            &mut residues,
        );
        if residues.iter().any(|value| *value != 0) {
            return Err(Error::AirConstraintMismatch { index: row_index });
        }
    }
    Ok(())
}

/// Open sampled AIR rows and composition values.
///
/// # Errors
/// Returns an error when any sampled index is outside the AIR domain.
#[cfg(any(test, feature = "dev-tools"))]
fn open_air_constraint_openings_with_mode(
    columns: &[Vec<u64>],
    air_trace_leaves: &[GoldilocksDigest384V1],
    composition_values: &[GoldilocksFp4V1],
    composition_leaves: &[GoldilocksDigest384V1],
    query_indices: &[usize],
    next_step: usize,
    mode: ExecutionMode,
) -> Result<Vec<AirConstraintOpening>> {
    if columns.is_empty() {
        return Ok(Vec::new());
    }
    let row_count = columns[0].len();
    if next_step == 0 {
        return Err(Error::QueryIndexOutOfRange {
            index: 0,
            len: row_count,
        });
    }
    let row_paths = merkle_paths_for_leaf_indices(
        air_trace_leaves,
        query_indices,
        MerkleTreeRoleV1::AirTrace,
        mode,
    )?;
    let next_indices: Vec<usize> = query_indices
        .iter()
        .map(|index| (index + next_step) % row_count)
        .collect();
    let next_paths = merkle_paths_for_leaf_indices(
        air_trace_leaves,
        &next_indices,
        MerkleTreeRoleV1::AirTrace,
        mode,
    )?;
    let composition_paths = merkle_paths_for_leaf_indices(
        composition_leaves,
        query_indices,
        MerkleTreeRoleV1::AirComposition,
        mode,
    )?;
    query_indices
        .iter()
        .copied()
        .zip(row_paths)
        .zip(next_indices.into_iter().zip(next_paths))
        .zip(composition_paths)
        .map(
            |(((index, current_row_path), (next_index, next_row_path)), composition_path)| {
                let compact =
                    u32::try_from(index).map_err(|_| Error::QueryIndexOverflow { index })?;
                Ok(AirConstraintOpening {
                    index: compact,
                    current_row: air_row_at(columns, index)?,
                    next_row: air_row_at(columns, next_index)?,
                    current_row_path: current_row_path
                        .into_iter()
                        .map(WireGoldilocksDigest384V1::from)
                        .collect(),
                    next_row_path: next_row_path
                        .into_iter()
                        .map(WireGoldilocksDigest384V1::from)
                        .collect(),
                    composition_value: *composition_values.get(index).ok_or(
                        Error::QueryIndexOutOfRange {
                            index,
                            len: composition_values.len(),
                        },
                    )?,
                    composition_path: composition_path
                        .into_iter()
                        .map(WireGoldilocksDigest384V1::from)
                        .collect(),
                })
            },
        )
        .collect()
}
/// Hash one FRI round leaf with domain separation from LDE openings.
///
/// # Errors
/// Returns an error if the leaf coordinates cannot be represented.
#[cfg(any(test, feature = "dev-tools"))]
pub fn hash_fri_chunk(
    round: usize,
    leaf_index: usize,
    values: &[GoldilocksFp4V1],
) -> Result<GoldilocksDigest384V1> {
    let mut bytes = Vec::with_capacity(values.len().saturating_mul(32));
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    hash_bytes_v1(
        FRI_COMMITMENT_ROLE_V1,
        MERKLE_LEAF_PHASE_V1,
        round,
        leaf_index,
        0,
        &[&bytes],
    )
}
/// Return the V1 chunk size (number of evaluations per LDE leaf hash).
///
/// # Errors
/// Returns [`Error::FriArity`] unless `arity` is the sole V1 binary-FRI arity.
#[cfg(any(test, feature = "dev-tools"))]
pub fn lde_chunk_size(arity: u32) -> Result<usize> {
    ensure_binary_fri_arity(arity)?;
    Ok(fastpq_isi::resource_limits::FASTPQ_LDE_CHUNK_VALUES_V1)
}

#[cfg(any(test, feature = "dev-tools"))]
fn ensure_binary_fri_arity(arity: u32) -> Result<()> {
    if arity == 2 {
        Ok(())
    } else {
        Err(Error::FriArity(arity))
    }
}

#[cfg(any(test, feature = "dev-tools"))]
fn fri_chunk_size(arity: u32) -> Result<usize> {
    ensure_binary_fri_arity(arity)?;
    Ok(2)
}
/// Open the full LDE leaf chunks that contain the supplied query indices.
///
/// # Errors
/// Returns an error when any query index is outside the evaluation domain.
#[cfg(any(test, feature = "dev-tools"))]
pub fn open_query_chunks<F: Copy>(
    evaluations: &[F],
    query_indices: &[usize],
    arity: u32,
) -> Result<Vec<Vec<F>>> {
    let chunk_size = lde_chunk_size(arity)?;
    let mut chunks = Vec::with_capacity(query_indices.len());
    for &query_index in query_indices {
        if query_index >= evaluations.len() {
            return Err(Error::QueryIndexOutOfRange {
                index: query_index,
                len: evaluations.len(),
            });
        }
        let start = (query_index / chunk_size) * chunk_size;
        let end = start.saturating_add(chunk_size).min(evaluations.len());
        chunks.push(evaluations[start..end].to_vec());
    }
    Ok(chunks)
}
/// Compute Merkle authentication paths for the supplied query indices over the provided leaf set.
///
/// The query indices are expressed in terms of evaluation positions; internally they are grouped
/// into leaf chunks using the canonical chunk size derived from the FRI arity.
///
/// # Errors
/// Returns an error if hashing an internal Merkle level fails.
#[cfg(any(test, feature = "dev-tools"))]
pub fn merkle_paths_for_queries(
    leaves: &[GoldilocksDigest384V1],
    query_indices: &[usize],
    arity: u32,
    evaluation_len: usize,
) -> Result<Vec<Vec<GoldilocksDigest384V1>>> {
    merkle_paths_for_queries_with_mode(
        leaves,
        query_indices,
        arity,
        evaluation_len,
        MerkleTreeRoleV1::Lde,
        default_batch_execution_mode(),
    )
}
#[cfg(any(test, feature = "dev-tools"))]
fn merkle_paths_for_queries_with_mode(
    leaves: &[GoldilocksDigest384V1],
    query_indices: &[usize],
    arity: u32,
    evaluation_len: usize,
    role: MerkleTreeRoleV1,
    mode: ExecutionMode,
) -> Result<Vec<Vec<GoldilocksDigest384V1>>> {
    let chunk_size = lde_chunk_size(arity)?;
    if query_indices.is_empty() {
        return Ok(Vec::new());
    }
    if evaluation_len == 0 || leaves.is_empty() {
        return Err(Error::QueryIndexOutOfRange {
            index: query_indices[0],
            len: evaluation_len,
        });
    }
    let levels = build_merkle_levels_with_mode(leaves, role, mode)?;
    let leaf_level = levels
        .first()
        .expect("non-empty levels for non-empty leaves");
    let leaf_count = leaf_level.len();
    let mut paths = Vec::with_capacity(query_indices.len());
    for &query_index in query_indices {
        if query_index >= evaluation_len {
            return Err(Error::QueryIndexOutOfRange {
                index: query_index,
                len: evaluation_len,
            });
        }
        let mut leaf_index = query_index / chunk_size;
        if leaf_index >= leaf_count {
            return Err(Error::QueryIndexOutOfRange {
                index: query_index,
                len: evaluation_len,
            });
        }
        let mut path = Vec::with_capacity(levels.len().saturating_sub(1));
        for level in levels.iter().take(levels.len().saturating_sub(1)) {
            let sibling_idx = if leaf_index.is_multiple_of(2) {
                leaf_index + 1
            } else {
                leaf_index.saturating_sub(1)
            };
            let sibling = level
                .get(sibling_idx)
                .copied()
                .unwrap_or_else(|| level[leaf_index]);
            path.push(sibling);
            leaf_index /= 2;
        }
        paths.push(path);
    }
    Ok(paths)
}
#[cfg(any(test, feature = "dev-tools"))]
fn merkle_paths_for_leaf_indices(
    leaves: &[GoldilocksDigest384V1],
    leaf_indices: &[usize],
    role: MerkleTreeRoleV1,
    mode: ExecutionMode,
) -> Result<Vec<Vec<GoldilocksDigest384V1>>> {
    if leaf_indices.is_empty() {
        return Ok(Vec::new());
    }
    if leaves.is_empty() {
        return Err(Error::QueryIndexOutOfRange {
            index: leaf_indices[0],
            len: 0,
        });
    }
    let levels = build_merkle_levels_with_mode(leaves, role, mode)?;
    let leaf_count = levels
        .first()
        .expect("non-empty levels for non-empty leaves")
        .len();
    let mut paths = Vec::with_capacity(leaf_indices.len());
    for &leaf_index in leaf_indices {
        if leaf_index >= leaf_count {
            return Err(Error::QueryIndexOutOfRange {
                index: leaf_index,
                len: leaf_count,
            });
        }
        let mut index = leaf_index;
        let mut path = Vec::with_capacity(levels.len().saturating_sub(1));
        for level in levels.iter().take(levels.len().saturating_sub(1)) {
            let sibling_idx = if index.is_multiple_of(2) {
                index + 1
            } else {
                index.saturating_sub(1)
            };
            let sibling = level
                .get(sibling_idx)
                .copied()
                .unwrap_or_else(|| level[index]);
            path.push(sibling);
            index /= 2;
        }
        paths.push(path);
    }
    Ok(paths)
}
/// Verify a Merkle authentication path over FASTPQ Poseidon field leaves.
///
/// # Errors
/// Returns an error if an internal node hash cannot be computed.
#[cfg(test)]
#[allow(clippy::unnecessary_wraps)]
pub fn verify_merkle_path(
    root: GoldilocksDigest384V1,
    leaf: GoldilocksDigest384V1,
    leaf_index: usize,
    path: &[GoldilocksDigest384V1],
) -> Result<bool> {
    verify_merkle_path_for_role(MerkleTreeRoleV1::Lde, root, leaf, leaf_index, path)
}

/// Verify a Merkle authentication path under an explicit native-STARK tree role.
///
/// # Errors
/// Returns an error when a typed internal-node digest cannot be framed.
#[cfg(test)]
pub fn verify_merkle_path_for_role(
    role: MerkleTreeRoleV1,
    root: GoldilocksDigest384V1,
    leaf: GoldilocksDigest384V1,
    leaf_index: usize,
    path: &[GoldilocksDigest384V1],
) -> Result<bool> {
    // FASTPQ's canonical tree duplicates a sole leaf and therefore always has
    // at least one authentication level. Accepting an empty path would treat a
    // raw leaf as a root even though the tree builder never emits that shape.
    if path.is_empty() {
        return Ok(false);
    }
    let mut current = leaf;
    let mut index = leaf_index;
    for (level, &sibling) in path.iter().enumerate() {
        let parent_index = index / 2;
        current = if index.is_multiple_of(2) {
            merkle_node_hash(role, level + 1, parent_index, current, sibling)?
        } else {
            merkle_node_hash(role, level + 1, parent_index, sibling, current)?
        };
        index /= 2;
    }
    // Reject indices whose high bits lie above the authenticated tree depth.
    // Without this check, `i` and `i + k * 2^path.len()` select identical
    // left/right branches and therefore accept the same path.
    Ok(index == 0 && current == root)
}
#[cfg(any(test, feature = "dev-tools"))]
fn merkle_digest_execution_v1(
    mode: ExecutionMode,
) -> Result<crate::digest_executor::DigestExecutionV1> {
    use crate::digest_executor::DigestExecutionV1;
    match mode {
        ExecutionMode::Cpu | ExecutionMode::Auto => Ok(DigestExecutionV1::Cpu),
        ExecutionMode::Gpu => {
            #[cfg(feature = "fastpq-gpu")]
            {
                use crate::digest384_gpu::Digest384GpuBackendV1;
                let backend = match current_gpu_backend() {
                    Some(GpuBackend::Metal) => Digest384GpuBackendV1::Metal,
                    Some(GpuBackend::Cuda) => Digest384GpuBackendV1::Cuda,
                    _ => {
                        return Err(Error::NativeDigestExecution {
                            details: "no supported explicit six-lane device backend".into(),
                        });
                    }
                };
                Ok(DigestExecutionV1::Device(backend))
            }
            #[cfg(not(feature = "fastpq-gpu"))]
            {
                Err(Error::NativeDigestExecution {
                    details: "six-lane device support is not compiled".into(),
                })
            }
        }
    }
}

#[cfg(any(test, feature = "dev-tools"))]
fn build_merkle_levels_with_mode(
    leaves: &[GoldilocksDigest384V1],
    role: MerkleTreeRoleV1,
    mode: ExecutionMode,
) -> Result<Vec<Vec<GoldilocksDigest384V1>>> {
    build_merkle_levels_with_execution_v1(leaves, role, merkle_digest_execution_v1(mode)?)
}

#[cfg(any(test, feature = "dev-tools"))]
fn build_merkle_levels_with_execution_v1(
    leaves: &[GoldilocksDigest384V1],
    role: MerkleTreeRoleV1,
    execution: crate::digest_executor::DigestExecutionV1,
) -> Result<Vec<Vec<GoldilocksDigest384V1>>> {
    let levels = build_merkle_levels_with_executor_v1(leaves, role, &mut |frames| {
        crate::digest_executor::execute_digest384_frames_v1(frames, execution)
    })?;
    #[cfg(test)]
    if !leaves.is_empty() {
        use crate::digest_executor::DigestExecutionV1;
        crate::trace::notify_trace_merkle_mode_observer(match execution {
            DigestExecutionV1::Cpu => ExecutionMode::Cpu,
            #[cfg(feature = "fastpq-gpu")]
            DigestExecutionV1::Device(_) => ExecutionMode::Gpu,
        });
    }
    Ok(levels)
}

#[cfg(any(test, feature = "dev-tools"))]
fn build_merkle_levels_with_executor_v1(
    leaves: &[GoldilocksDigest384V1],
    role: MerkleTreeRoleV1,
    execute: &mut impl FnMut(
        &[fastpq_isi::GoldilocksDigest384FrameV1<'_>],
    ) -> Result<Vec<GoldilocksDigest384V1>>,
) -> Result<Vec<Vec<GoldilocksDigest384V1>>> {
    if leaves.is_empty() {
        return Ok(Vec::new());
    }
    let mut levels = Vec::new();
    let mut current = leaves.to_vec();
    loop {
        if !current.len().is_multiple_of(2) {
            current.push(*current.last().expect("non-empty Merkle level"));
        }
        levels.push(current.clone());
        let level = levels.len();
        let next = crate::digest_executor::hash_digest384_pairs_v1(
            &current,
            |index| {
                digest_domain_v1(
                    role.role(),
                    MERKLE_NODE_PHASE_V1,
                    level,
                    index,
                    role.counter(),
                )
            },
            execute,
        )?;
        if next.len() == 1 {
            levels.push(next);
            break;
        }
        current = next;
    }
    Ok(levels)
}

#[cfg(any(test, feature = "dev-tools"))]
fn merkle_root_with_mode(
    leaves: &[GoldilocksDigest384V1],
    role: MerkleTreeRoleV1,
    mode: ExecutionMode,
) -> Result<GoldilocksDigest384V1> {
    merkle_root_with_execution_v1(leaves, role, merkle_digest_execution_v1(mode)?)
}

#[cfg(any(test, feature = "dev-tools"))]
fn merkle_root_with_execution_v1(
    leaves: &[GoldilocksDigest384V1],
    role: MerkleTreeRoleV1,
    execution: crate::digest_executor::DigestExecutionV1,
) -> Result<GoldilocksDigest384V1> {
    let levels = build_merkle_levels_with_execution_v1(leaves, role, execution)?;
    if let Some(root) = levels.last().and_then(|level| level.first()).copied() {
        Ok(root)
    } else {
        let frame = fastpq_isi::GoldilocksDigest384FrameV1::new(
            digest_domain_v1(role.role(), MERKLE_EMPTY_PHASE_V1, 0, 0, role.counter())?,
            &[],
        )
        .ok_or(Error::PayloadLengthOverflow { length: 0 })?;
        let result = crate::digest_executor::execute_digest384_frames_v1(&[frame], execution)?;
        Ok(result[0])
    }
}

#[cfg(test)]
pub fn merkle_root_for_role(
    leaves: &[GoldilocksDigest384V1],
    role: MerkleTreeRoleV1,
) -> Result<GoldilocksDigest384V1> {
    merkle_root_with_mode(leaves, role, ExecutionMode::Cpu)
}
#[cfg(any(test, feature = "dev-tools"))]
fn merkle_node_hash(
    role: MerkleTreeRoleV1,
    level: usize,
    index: usize,
    left: GoldilocksDigest384V1,
    right: GoldilocksDigest384V1,
) -> Result<GoldilocksDigest384V1> {
    hash_bytes_v1(
        role.role(),
        MERKLE_NODE_PHASE_V1,
        level,
        index,
        role.counter(),
        &[&left.to_le_bytes(), &right.to_le_bytes()],
    )
}

/// Compute the Fiat–Shamir lookup grand-product accumulator over canonical
/// Goldilocks selector and witness evaluations.
///
/// Every non-zero `s_perm` evaluation selects the matching `perm_hash`
/// evaluation. The accumulator therefore multiplies `(perm_hash + γ)` for
/// exactly those selected positions, using the committed LDE columns rather
/// than the unextended trace.
///
/// TODO: Before permission operations can enter the production semantic
/// profile, extend this commitment with a table-side product plus a running
/// product trace constrained at both boundaries and bind that table to the
/// permission root. This deterministic accumulator alone is not a membership
/// or non-membership proof.
///
/// # Errors
///
/// Returns [`Error::LookupColumnLengthMismatch`] when the columns have
/// different lengths, or [`Error::NonCanonicalGoldilocksElement`] when the
/// challenge or an evaluation is outside the canonical field range.
#[cfg(any(test, feature = "dev-tools"))]
pub fn compute_lookup_grand_product(
    selector_values: &[u64],
    witness_values: &[u64],
    gamma: u64,
) -> Result<u64> {
    if selector_values.len() != witness_values.len() {
        return Err(Error::LookupColumnLengthMismatch {
            selector_len: selector_values.len(),
            witness_len: witness_values.len(),
        });
    }
    if gamma >= GOLDILOCKS_MODULUS {
        return Err(Error::NonCanonicalGoldilocksElement {
            context: "lookup_challenge",
            indices: Vec::new(),
        });
    }

    let mut accumulator = FIELD_ONE;
    for (index, (&selector, &witness)) in selector_values
        .iter()
        .zip(witness_values.iter())
        .enumerate()
    {
        if selector >= GOLDILOCKS_MODULUS {
            return Err(Error::NonCanonicalGoldilocksElement {
                context: "lookup_selector",
                indices: vec![index],
            });
        }
        if witness >= GOLDILOCKS_MODULUS {
            return Err(Error::NonCanonicalGoldilocksElement {
                context: "lookup_witness",
                indices: vec![index],
            });
        }
        if selector != 0 {
            accumulator = mul_mod(accumulator, add_mod(witness, gamma));
        }
    }
    Ok(accumulator)
}

#[cfg(test)]
pub fn fold_with_fri(
    evaluations: &[u64],
    arity: u32,
    max_reductions: u32,
    lde_root: u64,
    lde_log_size: u32,
    domain_offset: u64,
    transcript: &mut Transcript,
) -> Result<(Vec<GoldilocksDigest384V1>, Vec<GoldilocksFp4V1>)> {
    if arity != 2 {
        return Err(Error::FriArity(arity));
    }
    if evaluations.is_empty() {
        let root = merkle_root_with_mode(&[], MerkleTreeRoleV1::Fri(0), ExecutionMode::Cpu)?;
        transcript.append_fri_final(root);
        return Ok((vec![root], Vec::new()));
    }
    let leaf_arity = arity;
    let arity = usize::try_from(arity).expect("FRI arity fits usize");
    let max_rounds = usize::try_from(max_reductions).expect("FRI reduction bound fits usize");
    let mut current = evaluations
        .iter()
        .copied()
        .map(|value| GoldilocksFp4V1::from_base(value).expect("evaluations are canonical"))
        .collect::<Vec<_>>();
    let mut domain =
        FriDomain::from_lde_parameters(lde_root, lde_log_size, current.len(), domain_offset)?;
    let mut layers = Vec::new();
    let mut betas = Vec::new();
    let mut round = 0usize;
    while current.len() > fastpq_isi::FASTPQ_FRI_TERMINAL_DOMAIN_SIZE_V1 as usize
        && round < max_rounds
    {
        let span = tracing::info_span!("fastpq_fri_round", round, layer_len = current.len(), arity);
        let _enter = span.enter();
        let leaves = hash_fri_leaves_with_mode(round, &current, leaf_arity, ExecutionMode::Cpu)?;
        let root = merkle_root_with_mode(
            &leaves,
            MerkleTreeRoleV1::Fri(
                u32::try_from(round).map_err(|_| Error::QueryIndexOverflow { index: round })?,
            ),
            ExecutionMode::Cpu,
        )?;
        transcript.append_fri_layer(round, root);
        layers.push(root);
        let beta = transcript.challenge_beta(round);
        betas.push(beta);
        let round_arity = fri_round_arity(current.len(), arity)?;
        tracing::debug!(
            round,
            layer_len = current.len(),
            round_arity,
            "folding FRI layer with beta"
        );
        let next = fold_round(&current, arity, beta, domain)?;
        let next_len = next.len();
        tracing::info!(
            round,
            ?root,
            ?beta,
            layer_len = current.len(),
            round_arity,
            next_len,
            "fri round committed"
        );
        current = next;
        domain = domain.folded(round_arity);
        round += 1;
    }
    if current.len() > fastpq_isi::FASTPQ_FRI_TERMINAL_DOMAIN_SIZE_V1 as usize {
        return Err(Error::FriReductionLimit {
            max_reductions,
            remaining: current.len(),
            arity,
        });
    }
    let final_leaves = hash_fri_terminal_leaves(round, &current)?;
    let final_root = merkle_root_with_mode(
        &final_leaves,
        MerkleTreeRoleV1::Fri(
            u32::try_from(round).map_err(|_| Error::QueryIndexOverflow { index: round })?,
        ),
        ExecutionMode::Cpu,
    )?;
    transcript.append_fri_final(final_root);
    tracing::info!(round, ?final_root, "final FRI layer commitment");
    layers.push(final_root);
    Ok((layers, betas))
}
#[cfg(any(test, feature = "dev-tools"))]
struct FriOpeningLayers {
    layer_values: Vec<Vec<GoldilocksFp4V1>>,
    roots: Vec<GoldilocksDigest384V1>,
    betas: Vec<GoldilocksFp4V1>,
    opening_trees: Option<fri_openings::FriOpeningTrees>,
}

#[cfg(any(test, feature = "dev-tools"))]
impl FriOpeningLayers {
    /// Open this exact committed owner without rebuilding any FRI leaves or trees.
    fn open_query_chains(
        &mut self,
        query_indices: &[usize],
        arity: u32,
    ) -> Result<Vec<FriQueryOpening>> {
        let arity_usize = fri_chunk_size(arity)?;
        if let Some(trees) = &mut self.opening_trees {
            open_fri_query_chains_with_trees(&self.layer_values, query_indices, arity_usize, trees)
        } else {
            // Preserve the legacy empty-input branch and its terminal-shape
            // error, including when there are no queries. No valid nonempty
            // commitment takes this fallback.
            open_fri_query_chains(&self.layer_values, query_indices, arity, ExecutionMode::Cpu)
        }
    }
}

#[cfg(any(test, feature = "dev-tools"))]
fn fold_with_fri_opening_layers(
    evaluations: &[GoldilocksFp4V1],
    params: &StarkParameterSet,
    transcript: &mut Transcript,
    mode: ExecutionMode,
) -> Result<FriOpeningLayers> {
    let arity = params.fri.arity;
    if arity != 2 {
        return Err(Error::FriArity(arity));
    }
    if evaluations.is_empty() {
        let root = merkle_root_with_mode(&[], MerkleTreeRoleV1::Fri(0), mode)?;
        transcript.append_fri_final(root);
        return Ok(FriOpeningLayers {
            layer_values: vec![Vec::new()],
            roots: vec![root],
            betas: Vec::new(),
            opening_trees: None,
        });
    }
    let arity_usize = usize::try_from(arity).expect("FRI arity fits usize");
    let max_rounds =
        usize::try_from(params.fri.max_reductions).expect("FRI reduction bound fits usize");
    let mut current = evaluations.to_vec();
    let mut domain = FriDomain::from_lde_parameters(
        params.lde_root,
        params.lde_log_size,
        current.len(),
        params.omega_coset,
    )?;
    let mut layer_values = Vec::new();
    let mut roots = Vec::new();
    let mut opening_levels = Vec::new();
    let mut betas = Vec::new();
    let mut round = 0usize;
    while current.len() > fastpq_isi::FASTPQ_FRI_TERMINAL_DOMAIN_SIZE_V1 as usize
        && round < max_rounds
    {
        let leaves = hash_fri_leaves_with_mode(round, &current, arity, mode)?;
        let levels = build_merkle_levels_with_mode(
            &leaves,
            MerkleTreeRoleV1::Fri(
                u32::try_from(round).map_err(|_| Error::QueryIndexOverflow { index: round })?,
            ),
            mode,
        )?;
        let root = levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .expect("nonempty FRI leaves produce one root");
        opening_levels.push(levels);
        drop(leaves); // The first retained level already owns these digests.
        transcript.append_fri_layer(round, root);
        roots.push(root);
        let beta = transcript.challenge_beta(round);
        betas.push(beta);
        let round_arity = fri_round_arity(current.len(), arity_usize)?;
        let next = fold_round(&current, arity_usize, beta, domain)?;
        layer_values.push(current);
        current = next;
        domain = domain.folded(round_arity);
        round += 1;
    }
    if current.len() > fastpq_isi::FASTPQ_FRI_TERMINAL_DOMAIN_SIZE_V1 as usize {
        return Err(Error::FriReductionLimit {
            max_reductions: params.fri.max_reductions,
            remaining: current.len(),
            arity: arity_usize,
        });
    }
    let leaves = hash_fri_terminal_leaves(round, &current)?;
    let levels = build_merkle_levels_with_mode(
        &leaves,
        MerkleTreeRoleV1::Fri(
            u32::try_from(round).map_err(|_| Error::QueryIndexOverflow { index: round })?,
        ),
        mode,
    )?;
    let final_root = levels
        .last()
        .and_then(|level| level.first())
        .copied()
        .expect("the complete terminal leaf produces one duplicated-node root");
    opening_levels.push(levels);
    drop(leaves);
    transcript.append_fri_final(final_root);
    roots.push(final_root);
    layer_values.push(current);
    Ok(FriOpeningLayers {
        layer_values,
        roots,
        betas,
        opening_trees: Some(fri_openings::FriOpeningTrees::from_levels(
            opening_levels,
            mode,
        )?),
    })
}
#[cfg(any(test, feature = "dev-tools"))]
fn hash_fri_leaves_with_mode(
    round: usize,
    values: &[GoldilocksFp4V1],
    arity: u32,
    mode: ExecutionMode,
) -> Result<Vec<GoldilocksDigest384V1>> {
    let configured_arity = fri_chunk_size(arity)?;
    let _ = mode;
    if values.is_empty() {
        return Ok(Vec::new());
    }
    let round_arity = fri_round_arity(values.len(), configured_arity)?;
    let output_len = values.len() / round_arity;
    let prefix = digest_domain_prefix_v1(FRI_COMMITMENT_ROLE_V1, MERKLE_LEAF_PHASE_V1, round, 0)?;
    let hash_leaf = |leaf_index: usize| {
        let mut bytes = [0; 64];
        for position in 0..round_arity {
            bytes[position * 32..(position + 1) * 32]
                .copy_from_slice(&values[leaf_index + position * output_len].to_le_bytes());
        }
        hash_at_prefix_v1(&prefix, leaf_index, &[&bytes[..round_arity * 32]])
    };
    if output_len < 32 {
        return (0..output_len).map(hash_leaf).collect();
    }
    let results: Vec<Result<_>> = (0..output_len).into_par_iter().map(hash_leaf).collect();
    results.into_iter().collect()
}
// The complete terminal domain is a single ordered leaf. Binary strided leaves
// are only appropriate while another fold follows: a terminal subset would not
// suffice to interpolate and check the final polynomial's degree.
#[cfg(any(test, feature = "dev-tools"))]
fn hash_fri_terminal_leaves(
    round: usize,
    values: &[GoldilocksFp4V1],
) -> Result<Vec<GoldilocksDigest384V1>> {
    let terminal_size = fastpq_isi::FASTPQ_FRI_TERMINAL_DOMAIN_SIZE_V1 as usize;
    if !values.len().is_power_of_two() || values.len() > terminal_size {
        return Err(Error::FriDomainSize {
            length: values.len(),
            arity: terminal_size,
        });
    }
    Ok(vec![hash_fri_chunk(round, 0, values)?])
}

#[cfg(any(test, feature = "dev-tools"))]
fn open_fri_query_chains(
    layer_values: &[Vec<GoldilocksFp4V1>],
    query_indices: &[usize],
    arity: u32,
    mode: ExecutionMode,
) -> Result<Vec<FriQueryOpening>> {
    let arity_usize = fri_chunk_size(arity)?;
    if layer_values.is_empty() {
        return Ok(Vec::new());
    }
    let mut round_leaves = Vec::with_capacity(layer_values.len());
    for (round, values) in layer_values.iter().enumerate() {
        round_leaves.push(if round + 1 == layer_values.len() {
            hash_fri_terminal_leaves(round, values)?
        } else {
            hash_fri_leaves_with_mode(round, values, arity, mode)?
        });
    }
    // Retain each layer's read-only levels across all queries. Building lazily
    // preserves the existing coordinate checks and avoids work for no queries.
    let mut trees = fri_openings::FriOpeningTrees::new(round_leaves, mode);
    let mut openings = Vec::with_capacity(query_indices.len());
    for &initial_index in query_indices {
        let initial_index_u32 =
            u32::try_from(initial_index).map_err(|_| Error::QueryIndexOverflow {
                index: initial_index,
            })?;
        let mut index = initial_index;
        let mut rounds = Vec::with_capacity(layer_values.len().saturating_sub(1));
        for round in 0..layer_values.len().saturating_sub(1) {
            let values = &layer_values[round];
            if index >= values.len() {
                return Err(Error::QueryIndexOutOfRange {
                    index,
                    len: values.len(),
                });
            }
            let round_arity = fri_round_arity(values.len(), arity_usize)?;
            let output_len = values.len() / round_arity;
            let leaf_index = index % output_len;
            let group = (0..round_arity)
                .map(|position| values[leaf_index + position * output_len])
                .collect::<Vec<_>>();
            let path = trees.path(round, leaf_index)?;
            let folded_index = leaf_index;
            let folded_value = layer_values
                .get(round + 1)
                .and_then(|next| next.get(folded_index))
                .copied()
                .ok_or_else(|| Error::QueryIndexOutOfRange {
                    index: folded_index,
                    len: layer_values.get(round + 1).map_or(0, Vec::len),
                })?;
            rounds.push(FriRoundOpening {
                round: u32::try_from(round)
                    .map_err(|_| Error::QueryIndexOverflow { index: round })?,
                index: u32::try_from(index).map_err(|_| Error::QueryIndexOverflow { index })?,
                values: group,
                folded_value,
                merkle_path: path
                    .into_iter()
                    .map(WireGoldilocksDigest384V1::from)
                    .collect(),
            });
            index = folded_index;
        }
        let final_values = layer_values
            .last()
            .expect("non-empty layer values")
            .as_slice();
        if index >= final_values.len() {
            return Err(Error::QueryIndexOutOfRange {
                index,
                len: final_values.len(),
            });
        }
        let final_leaf_index = 0;
        let final_group = final_values.to_vec();
        let final_path = trees.path(layer_values.len() - 1, final_leaf_index)?;
        openings.push(FriQueryOpening {
            initial_index: initial_index_u32,
            rounds,
            final_index: u32::try_from(index).map_err(|_| Error::QueryIndexOverflow { index })?,
            final_values: final_group,
            final_merkle_path: final_path
                .into_iter()
                .map(WireGoldilocksDigest384V1::from)
                .collect(),
        });
    }
    Ok(openings)
}

#[cfg(any(test, feature = "dev-tools"))]
fn open_fri_query_chains_with_trees(
    layer_values: &[Vec<GoldilocksFp4V1>],
    query_indices: &[usize],
    arity_usize: usize,
    trees: &mut fri_openings::FriOpeningTrees,
) -> Result<Vec<FriQueryOpening>> {
    let mut openings = Vec::with_capacity(query_indices.len());
    for &initial_index in query_indices {
        let initial_index_u32 =
            u32::try_from(initial_index).map_err(|_| Error::QueryIndexOverflow {
                index: initial_index,
            })?;
        let mut index = initial_index;
        let mut rounds = Vec::with_capacity(layer_values.len().saturating_sub(1));
        for round in 0..layer_values.len().saturating_sub(1) {
            let values = &layer_values[round];
            if index >= values.len() {
                return Err(Error::QueryIndexOutOfRange {
                    index,
                    len: values.len(),
                });
            }
            let round_arity = fri_round_arity(values.len(), arity_usize)?;
            let output_len = values.len() / round_arity;
            let leaf_index = index % output_len;
            let group = (0..round_arity)
                .map(|position| values[leaf_index + position * output_len])
                .collect::<Vec<_>>();
            let path = trees.path(round, leaf_index)?;
            let folded_index = leaf_index;
            let folded_value = layer_values
                .get(round + 1)
                .and_then(|next| next.get(folded_index))
                .copied()
                .ok_or_else(|| Error::QueryIndexOutOfRange {
                    index: folded_index,
                    len: layer_values.get(round + 1).map_or(0, Vec::len),
                })?;
            rounds.push(FriRoundOpening {
                round: u32::try_from(round)
                    .map_err(|_| Error::QueryIndexOverflow { index: round })?,
                index: u32::try_from(index).map_err(|_| Error::QueryIndexOverflow { index })?,
                values: group,
                folded_value,
                merkle_path: path
                    .into_iter()
                    .map(WireGoldilocksDigest384V1::from)
                    .collect(),
            });
            index = folded_index;
        }
        let final_values = layer_values
            .last()
            .expect("non-empty layer values")
            .as_slice();
        if index >= final_values.len() {
            return Err(Error::QueryIndexOutOfRange {
                index,
                len: final_values.len(),
            });
        }
        let final_leaf_index = 0;
        let final_group = final_values.to_vec();
        let final_path = trees.path(layer_values.len() - 1, final_leaf_index)?;
        openings.push(FriQueryOpening {
            initial_index: initial_index_u32,
            rounds,
            final_index: u32::try_from(index).map_err(|_| Error::QueryIndexOverflow { index })?,
            final_values: final_group,
            final_merkle_path: final_path
                .into_iter()
                .map(WireGoldilocksDigest384V1::from)
                .collect(),
        });
    }
    Ok(openings)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FriDomain {
    generator: u64,
    offset: u64,
}

impl FriDomain {
    pub fn from_lde_parameters(
        lde_root: u64,
        lde_log_size: u32,
        domain_size: usize,
        offset: u64,
    ) -> Result<Self> {
        if domain_size == 0 || !domain_size.is_power_of_two() {
            return Err(Error::FriDomainSize {
                length: domain_size,
                arity: 1,
            });
        }
        let domain_log = domain_size.ilog2();
        if domain_log > lde_log_size {
            return Err(Error::FriDomainSize {
                length: domain_size,
                arity: 1usize << lde_log_size,
            });
        }
        let root_stride = 1u64 << (lde_log_size - domain_log);
        Ok(Self {
            generator: field_pow(lde_root, root_stride),
            offset,
        })
    }

    pub fn point(self, index: usize) -> u64 {
        mul_mod(
            self.offset,
            field_pow(
                self.generator,
                u64::try_from(index).expect("FRI domain index fits u64"),
            ),
        )
    }

    pub fn coset_generator(self, output_len: usize) -> u64 {
        field_pow(
            self.generator,
            u64::try_from(output_len).expect("FRI output length fits u64"),
        )
    }

    pub fn folded(self, arity: usize) -> Self {
        let exponent = u64::try_from(arity).expect("FRI arity fits u64");
        Self {
            generator: field_pow(self.generator, exponent),
            offset: field_pow(self.offset, exponent),
        }
    }

    /// Return whether evaluations on this domain encode a polynomial below
    /// the exclusive degree bound.
    pub(crate) fn evaluations_have_degree_below(
        self,
        values: &[GoldilocksFp4V1],
        degree_bound: usize,
    ) -> Result<bool> {
        if values.is_empty() || !values.len().is_power_of_two() {
            return Err(Error::FriDomainSize {
                length: values.len(),
                arity: 1,
            });
        }
        if degree_bound == 0 || degree_bound > values.len() {
            return Err(Error::FriTerminalDegreeBound {
                degree_bound,
                domain_len: values.len(),
            });
        }
        let inverse_len =
            field_inverse(
                u64::try_from(values.len()).map_err(|_| Error::FriDomainSize {
                    length: values.len(),
                    arity: values.len(),
                })?,
            );
        let inverse_generator = field_inverse(self.generator);
        let mut inverse_frequency = field_pow(
            inverse_generator,
            u64::try_from(degree_bound).expect("terminal FRI degree bound fits u64"),
        );
        for _degree in degree_bound..values.len() {
            let mut coefficient = GoldilocksFp4V1::ZERO;
            let mut twiddle = FIELD_ONE;
            for &value in values {
                coefficient = coefficient.add(value.mul_base(twiddle));
                twiddle = mul_mod(twiddle, inverse_frequency);
            }
            if !coefficient.mul_base(inverse_len).is_zero() {
                return Ok(false);
            }
            inverse_frequency = mul_mod(inverse_frequency, inverse_generator);
        }
        Ok(true)
    }
}

#[cfg(any(test, feature = "dev-tools"))]
pub fn fri_round_arity(length: usize, configured_arity: usize) -> Result<usize> {
    if configured_arity != 2 {
        return Err(Error::FriArity(
            u32::try_from(configured_arity).unwrap_or(u32::MAX),
        ));
    }
    if length == 0 {
        return Err(Error::FriDomainSize {
            length,
            arity: configured_arity,
        });
    }
    let round_arity = configured_arity.min(length);
    if !length.is_multiple_of(round_arity) {
        return Err(Error::FriDomainSize {
            length,
            arity: round_arity,
        });
    }
    Ok(round_arity)
}

#[cfg(any(test, feature = "dev-tools"))]
pub fn fold_fri_coset(
    values: &[GoldilocksFp4V1],
    challenge: GoldilocksFp4V1,
    x: u64,
    coset_generator: u64,
) -> Result<GoldilocksFp4V1> {
    if values.len() != 2 || x == 0 || coset_generator != GOLDILOCKS_MODULUS - 1 {
        return Err(Error::FriDomainSize {
            length: values.len(),
            arity: 2,
        });
    }
    let inverse_two = field_inverse(2);
    let even = values[0].add(values[1]).mul_base(inverse_two);
    let odd = values[0]
        .sub(values[1])
        .mul_base(mul_mod(inverse_two, field_inverse(x)));
    Ok(even.add(challenge.mul(odd)))
}

#[cfg(any(test, feature = "dev-tools"))]
fn fold_round(
    values: &[GoldilocksFp4V1],
    configured_arity: usize,
    challenge: GoldilocksFp4V1,
    domain: FriDomain,
) -> Result<Vec<GoldilocksFp4V1>> {
    let round_arity = fri_round_arity(values.len(), configured_arity)?;
    let output_len = values.len() / round_arity;
    let coset_generator = domain.coset_generator(output_len);
    let mut group = Vec::with_capacity(round_arity);
    let mut next = Vec::with_capacity(output_len);
    for leaf_index in 0..output_len {
        group.clear();
        for position in 0..round_arity {
            group.push(values[leaf_index + position * output_len]);
        }
        next.push(fold_fri_coset(
            &group,
            challenge,
            domain.point(leaf_index),
            coset_generator,
        )?);
    }
    Ok(next)
}
// Deterministic engineering work limits, not a completion-probability or
// cryptographic-security claim. They must not vary with operator configuration.
#[cfg(any(test, feature = "dev-tools"))]
const QUERY_MIN_DIGEST_DRAWS: u32 = 64;
#[cfg(any(test, feature = "dev-tools"))]
const QUERY_DIGEST_DRAWS_PER_INDEX: u32 = 8;

/// Sample sorted unique indices with a deterministic per-attempt draw budget.
///
/// Successful transcripts within the budget retain the existing tags, digest
/// lane order, rejection rule and exact transcript state. Each draw consumes six
/// canonical field candidates. Exhaustion returns no partial indices; callers
/// must discard the failed attempt instead of resuming the advanced transcript.
/// The finite budget bounds work and does not guarantee sampling completion.
///
/// # Errors
/// Returns an error for unsupported nonempty geometry, an unsupported requested
/// cardinality, an exhausted transcript counter, or an exhausted draw budget.
#[cfg(any(test, feature = "dev-tools"))]
pub fn sample_queries(
    domain_size: usize,
    target: usize,
    transcript: &mut Transcript,
) -> Result<Vec<usize>> {
    sample_queries_from(domain_size, target, |counter| {
        // Preserve a successful final draw that advances MAX-1 to MAX while
        // preventing the existing challenge implementation's checked-add panic.
        if transcript.counter == u64::MAX {
            return Err(Error::QuerySamplingTranscriptCounterExhausted);
        }
        let tag = format!("{TRANSCRIPT_TAG_QUERY_INDEX}:{counter}");
        Ok(transcript.challenge_digest(&tag))
    })
}

#[cfg(any(test, feature = "dev-tools"))]
fn sample_queries_from(
    domain_size: usize,
    target: usize,
    mut draw: impl FnMut(u32) -> Result<GoldilocksDigest384V1>,
) -> Result<Vec<usize>> {
    if domain_size == 0 || target == 0 {
        return Ok(Vec::new());
    }
    let domain = u64::try_from(domain_size)
        .map_err(|_| Error::QuerySamplingDomainUnsupported { domain_size })?;
    if domain > GOLDILOCKS_MODULUS {
        return Err(Error::QuerySamplingDomainUnsupported { domain_size });
    }
    let desired = target.min(domain_size);
    let max_queries = usize::try_from(fastpq_isi::FASTPQ_MAX_QUERY_COUNT_V1)
        .map_err(|_| Error::QuerySamplingDomainUnsupported { domain_size })?;
    if desired > max_queries {
        return Err(Error::VerifierLimitExceeded {
            limit: "max_sampled_queries",
            actual: desired,
            max: max_queries,
        });
    }
    let desired_u32 = u32::try_from(desired)
        .map_err(|_| Error::QuerySamplingDomainUnsupported { domain_size })?;
    let draw_limit = desired_u32
        .checked_mul(QUERY_DIGEST_DRAWS_PER_INDEX)
        .ok_or(Error::QuerySamplingDomainUnsupported { domain_size })?
        .max(QUERY_MIN_DIGEST_DRAWS);
    let rejection_limit = GOLDILOCKS_MODULUS - GOLDILOCKS_MODULUS % domain;
    let mut indices = BTreeSet::new();
    for counter in 0..draw_limit {
        let digest = draw(counter)?;
        for candidate in digest.words() {
            if indices.len() == desired {
                break;
            }
            if candidate >= rejection_limit {
                continue;
            }
            let index = usize::try_from(candidate % domain)
                .map_err(|_| Error::QuerySamplingDomainUnsupported { domain_size })?;
            indices.insert(index);
        }
        if indices.len() == desired {
            return Ok(indices.into_iter().collect());
        }
    }
    Err(Error::QuerySamplingExhausted {
        domain_size,
        requested: desired,
        selected: indices.len(),
        draws: draw_limit,
    })
}

#[cfg(any(test, feature = "dev-tools"))]
pub fn open_queries<F: Copy>(evaluations: &[F], indices: &[usize]) -> Result<Vec<(u32, F)>> {
    let mut openings = Vec::with_capacity(indices.len());
    for &index in indices {
        let value = evaluations
            .get(index)
            .copied()
            .ok_or(Error::QueryIndexOutOfRange {
                index,
                len: evaluations.len(),
            })?;
        let compact_index =
            u32::try_from(index).map_err(|_| Error::QueryIndexOverflow { index })?;
        openings.push((compact_index, value));
    }
    Ok(openings)
}

#[cfg(any(test, feature = "dev-tools"))]
struct BatchPreparationContext<'a> {
    params: &'a StarkParameterSet,
    batch: &'a TransitionBatch,
    public_io: &'a PublicIO,
    protocol_version: u16,
    transcript_trace_root: Option<GoldilocksDigest384V1>,
    poseidon_policy: PoseidonPipelinePolicy,
}

#[derive(Debug)]
#[cfg(any(test, feature = "dev-tools"))]
struct PreparedBatch {
    trace_commitment: WireGoldilocksDigest384V1,
    trace_root: GoldilocksDigest384V1,
    air_trace_root: GoldilocksDigest384V1,
    air_composition_root: GoldilocksDigest384V1,
    lde_root: GoldilocksDigest384V1,
    lde_domain_size: u32,
    lookup_grand_product: u64,
    lookup_challenge: u64,
    alphas: Vec<GoldilocksFp4V1>,
    lde_columns: Vec<Vec<u64>>,
    lde_values: Vec<GoldilocksFp4V1>,
    lde_hashes: Vec<GoldilocksDigest384V1>,
    air_trace_leaves: Vec<GoldilocksDigest384V1>,
    air_composition_values: Vec<GoldilocksFp4V1>,
    air_composition_leaves: Vec<GoldilocksDigest384V1>,
    transcript: Transcript,
}

/// Batch-derived commitments which a proof is required to advertise exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(test, feature = "dev-tools"))]
pub struct BatchDerivedCommitments {
    /// Canonical commitment over the parameterised trace.
    pub trace_commitment: WireGoldilocksDigest384V1,
    /// Canonical base-trace commitment.
    pub trace_root: GoldilocksDigest384V1,
    /// Canonical commitment to the LDE trace rows used by AIR openings.
    pub air_trace_root: GoldilocksDigest384V1,
    /// Canonical commitment to the AIR composition evaluations.
    pub air_composition_root: GoldilocksDigest384V1,
    /// Canonical LDE commitment.
    pub lde_root: GoldilocksDigest384V1,
    /// Canonical LDE evaluation-domain size.
    pub lde_domain_size: u32,
    /// Canonical permission lookup grand-product accumulator.
    pub lookup_grand_product: u64,
    /// Canonical transcript-derived permission lookup challenge.
    pub lookup_challenge: u64,
}

#[cfg(any(test, feature = "dev-tools"))]
fn hash_trace_columns_v1(
    column_names: &[String],
    coefficients: &[Vec<u64>],
) -> Result<Vec<GoldilocksDigest384V1>> {
    if column_names.len() != coefficients.len() {
        return Err(Error::InvalidTraceShape {
            details: "column-name and coefficient counts differ".to_owned(),
        });
    }
    column_names
        .iter()
        .zip(coefficients)
        .enumerate()
        .map(|(index, (name, values))| {
            let mut bytes = Vec::with_capacity(values.len().saturating_mul(8));
            for value in values {
                if *value >= GOLDILOCKS_MODULUS {
                    return Err(Error::NonCanonicalGoldilocksElement {
                        context: "trace_column_coefficients",
                        indices: vec![index],
                    });
                }
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            hash_bytes_v1(
                TRACE_COMMITMENT_ROLE_V1,
                MERKLE_LEAF_PHASE_V1,
                0,
                index,
                0,
                &[name.as_bytes(), &bytes],
            )
        })
        .collect()
}

#[cfg(any(test, feature = "dev-tools"))]
fn combine_lde_columns_v1(
    columns: &[Vec<u64>],
    coefficients: &[GoldilocksFp4V1],
) -> Result<Vec<GoldilocksFp4V1>> {
    if columns.len() != coefficients.len() || columns.is_empty() {
        return Err(Error::InvalidTraceShape {
            details: "LDE columns and post-commitment coefficients differ".to_owned(),
        });
    }
    let row_count = columns[0].len();
    if !columns.iter().all(|column| column.len() == row_count) {
        return Err(Error::InvalidTraceShape {
            details: "LDE columns have inconsistent row counts".to_owned(),
        });
    }
    Ok((0..row_count)
        .map(|row| {
            columns.iter().zip(coefficients).fold(
                GoldilocksFp4V1::ZERO,
                |accumulator, (column, coefficient)| {
                    accumulator.add(coefficient.mul_base(column[row]))
                },
            )
        })
        .collect())
}

#[allow(clippy::too_many_lines)]
#[cfg(any(test, feature = "dev-tools"))]
fn prepare_batch(context: &BatchPreparationContext<'_>) -> Result<PreparedBatch> {
    let &BatchPreparationContext {
        params,
        batch,
        public_io,
        protocol_version,
        transcript_trace_root,
        poseidon_policy,
    } = context;
    if params.name != batch.parameter {
        return Err(Error::ParameterMismatch {
            expected: params.name.to_string(),
            actual: batch.parameter.clone(),
        });
    }
    crate::digest::ensure_trace_capacity(params, batch.transitions.len())?;
    crate::trace::ensure_trace_schema_limit(batch, crate::trace::DEFAULT_MAX_TRACE_COLUMNS)?;
    let trace = build_trace(batch)?;
    ensure_base_trace_constraints(&trace)?;
    let column_names = trace
        .columns
        .iter()
        .map(|column| column.name.clone())
        .collect::<Vec<_>>();
    let air_layout = AirColumnLayout::from_names(&column_names)?;
    let planner = Planner::new(params);
    let poseidon_mode = ExecutionMode::Cpu;
    let polynomial_data = derive_polynomial_data(&trace, &planner);
    let transfer_plan = polynomial_data.transfer_plan().clone();
    if transfer_plan.total_deltas() > 0 {
        tracing::debug!(
            target: "fastpq::transfer",
            batches = transfer_plan.batch_count(),
            deltas = transfer_plan.total_deltas(),
            estimated_rows = transfer_plan.estimated_row_budget(),
            "transfer gadget witnesses planned"
        );
    }
    crate::trace::notify_native_stark_cpu_hashing(poseidon_policy);
    let trace_column_leaves = hash_trace_columns_v1(&column_names, &polynomial_data.coefficients)?;
    let derived_trace_root =
        merkle_root_with_mode(&trace_column_leaves, MerkleTreeRoleV1::Trace, poseidon_mode)?;
    let trace_commitment = crate::digest::trace_commitment_from_trace(params, &trace)?;
    let trace_root = transcript_trace_root.unwrap_or(derived_trace_root);
    let lde_columns = polynomial_data.into_lde_columns();
    let mut transcript = Transcript::initialise(
        public_io,
        params.name,
        protocol_version,
        TRANSCRIPT_TAG_INIT,
    )?;
    let air_trace_leaves = hash_air_trace_rows_with_mode(&lde_columns, poseidon_mode)?;
    let air_trace_root =
        merkle_root_with_mode(&air_trace_leaves, MerkleTreeRoleV1::AirTrace, poseidon_mode)?;
    let lde_domain_size = u32::try_from(lde_columns.first().map_or(0, Vec::len))
        .map_err(|_| Error::TraceLengthOverflow { rows: usize::MAX })?;
    transcript.append_trace_oracles(
        trace_root,
        air_trace_root,
        lde_domain_size,
        column_names.len(),
    )?;
    let column_mix = (0..lde_columns.len())
        .map(|index| {
            transcript.challenge_extension(&format!("{TRANSCRIPT_TAG_COLUMN_MIX_PREFIX}:{index}"))
        })
        .collect::<Vec<_>>();
    let lde_values = combine_lde_columns_v1(&lde_columns, &column_mix)?;
    let lde_hashes = hash_lde_leaves_fp4(&lde_values, params.fri.arity)?;
    let lde_root = merkle_root_with_mode(&lde_hashes, MerkleTreeRoleV1::Lde, poseidon_mode)?;

    transcript.append_message(
        TRANSCRIPT_TAG_ROOTS,
        &[lde_root.to_le_bytes(), trace_root.to_le_bytes()].concat(),
    );
    let lookup_challenge = transcript.challenge_field(TRANSCRIPT_TAG_GAMMA);
    let lookup_grand_product = compute_lookup_grand_product(
        &lde_columns[air_layout.s_perm],
        &lde_columns[air_layout.perm_hash],
        lookup_challenge,
    )?;
    let alpha_count = air_composition_alpha_count(&column_names);
    let mut alphas = Vec::with_capacity(alpha_count);
    for idx in 0..alpha_count {
        let tag = format!("{TRANSCRIPT_TAG_ALPHA_PREFIX}:{idx}");
        alphas.push(transcript.challenge_extension(&tag));
    }
    let air_composition_values = air_quotient_values(params, &column_names, &lde_columns, &alphas)?;
    let air_composition_leaves =
        hash_air_composition_leaves_with_mode(&air_composition_values, poseidon_mode)?;
    let air_composition_root = merkle_root_with_mode(
        &air_composition_leaves,
        MerkleTreeRoleV1::AirComposition,
        poseidon_mode,
    )?;
    transcript.append_message(
        TRANSCRIPT_TAG_AIR_ROOTS,
        &[
            air_trace_root.to_le_bytes(),
            air_composition_root.to_le_bytes(),
        ]
        .concat(),
    );
    transcript.append_message(LOOKUP_PRODUCT_DOMAIN, &lookup_grand_product.to_le_bytes());
    Ok(PreparedBatch {
        trace_commitment,
        trace_root,
        air_trace_root,
        air_composition_root,
        lde_root,
        lde_domain_size,
        lookup_grand_product,
        lookup_challenge,
        alphas,
        lde_columns,
        lde_values,
        lde_hashes,
        air_trace_leaves,
        air_composition_values,
        air_composition_leaves,
        transcript,
    })
}

/// Recompute every proof-carried root and lookup value that is deterministic
/// from the batch.
#[cfg(any(test, feature = "dev-tools"))]
pub fn derive_batch_commitments(
    params: &StarkParameterSet,
    batch: &TransitionBatch,
    public_io: &PublicIO,
    protocol_version: u16,
) -> Result<BatchDerivedCommitments> {
    let prepared = prepare_batch(&BatchPreparationContext {
        params,
        batch,
        public_io,
        protocol_version,
        transcript_trace_root: None,
        poseidon_policy: PoseidonPipelinePolicy::for_mode(ExecutionMode::Cpu),
    })?;
    Ok(BatchDerivedCommitments {
        trace_commitment: prepared.trace_commitment,
        trace_root: prepared.trace_root,
        air_trace_root: prepared.air_trace_root,
        air_composition_root: prepared.air_composition_root,
        lde_root: prepared.lde_root,
        lde_domain_size: prepared.lde_domain_size,
        lookup_grand_product: prepared.lookup_grand_product,
        lookup_challenge: prepared.lookup_challenge,
    })
}

#[cfg(any(test, feature = "dev-tools"))]
impl StarkBackend {
    pub(crate) fn prove(
        &self,
        batch: &TransitionBatch,
        public_io: &PublicIO,
        protocol_version: u16,
    ) -> Result<BackendArtifact> {
        self.prove_inner(batch, public_io, protocol_version, None)
    }

    #[allow(clippy::too_many_lines)]
    fn prove_inner(
        &self,
        batch: &TransitionBatch,
        public_io: &PublicIO,
        protocol_version: u16,
        transcript_trace_root: Option<GoldilocksDigest384V1>,
    ) -> Result<BackendArtifact> {
        let execution_mode = self.config.resolve_native_v1_execution_mode()?;
        let poseidon_policy =
            PoseidonPipelinePolicy::new(self.config.poseidon_mode(), execution_mode);
        // Native Digest384 commitments and opening paths currently run on CPU.
        // prepare_batch reports this actual route with the requested policy.
        let poseidon_mode = ExecutionMode::Cpu;
        let PreparedBatch {
            trace_commitment,
            trace_root,
            air_trace_root,
            air_composition_root,
            lde_root,
            lde_domain_size,
            lookup_grand_product,
            lookup_challenge,
            alphas,
            lde_columns,
            lde_values,
            lde_hashes,
            air_trace_leaves,
            air_composition_values,
            air_composition_leaves,
            mut transcript,
        } = prepare_batch(&BatchPreparationContext {
            params: &self.config.params,
            batch,
            public_io,
            protocol_version,
            transcript_trace_root,
            poseidon_policy,
        })?;
        let next_step = usize::try_from(self.config.params.fri.blowup_factor)
            .expect("FRI blowup factor fits usize")
            .max(1);
        let joint_fri =
            JointFriBatch::from_transcript(&self.config.params, lde_values.len(), &mut transcript)?;
        let joint_values = joint_fri.values(&air_composition_values, &lde_values)?;
        let mut fri = fold_with_fri_opening_layers(
            &joint_values,
            &self.config.params,
            &mut transcript,
            poseidon_mode,
        )?;
        drop(joint_values); // The retained FRI owner has its own first layer.
        let query_indices = sample_queries(
            lde_values.len(),
            usize::try_from(self.config.params.fri.queries).expect("query count fits usize"),
            &mut transcript,
        )?;
        let query_openings = open_queries(&lde_values, &query_indices)?;
        let query_chunks =
            open_query_chunks(&lde_values, &query_indices, self.config.params.fri.arity)?;
        let query_paths = merkle_paths_for_queries_with_mode(
            &lde_hashes,
            &query_indices,
            self.config.params.fri.arity,
            lde_values.len(),
            MerkleTreeRoleV1::Lde,
            poseidon_mode,
        )?;
        let air_openings = open_air_constraint_openings_with_mode(
            &lde_columns,
            &air_trace_leaves,
            &air_composition_values,
            &air_composition_leaves,
            &query_indices,
            next_step,
            poseidon_mode,
        )?;
        let fri_query_openings =
            fri.open_query_chains(&query_indices, self.config.params.fri.arity)?;
        let FriOpeningLayers {
            roots: fri_layers,
            betas: fri_betas,
            ..
        } = fri;
        Ok(BackendArtifact {
            parameter: self.config.params.name.to_string(),
            trace_commitment,
            trace_root,
            air_trace_root,
            air_composition_root,
            lde_root,
            lde_domain_size,
            lookup_grand_product,
            lookup_challenge,
            alphas,
            fri_layers,
            fri_betas,
            query_openings,
            query_chunks,
            query_paths,
            air_openings,
            fri_query_openings,
        })
    }

    #[cfg(test)]
    pub(crate) fn prove_with_transcript_trace_root(
        &self,
        batch: &TransitionBatch,
        public_io: &PublicIO,
        protocol_version: u16,
        trace_root: GoldilocksDigest384V1,
    ) -> Result<BackendArtifact> {
        self.prove_inner(batch, public_io, protocol_version, Some(trace_root))
    }
}
#[derive(Debug, Clone)]
#[cfg(any(test, feature = "dev-tools"))]
pub struct Transcript {
    state: GoldilocksDigest384V1,
    counter: u64,
}
#[cfg(any(test, feature = "dev-tools"))]
impl Transcript {
    pub fn initialise(
        public_io: &PublicIO,
        parameter: &str,
        protocol_version: u16,
        tag: &str,
    ) -> Result<Self> {
        // This first-release schema binds the quotient and exact-u64 AIR layout,
        // Fp4 aggregation, joint trace degree check and complete terminal opening. It is not a security-review
        // or production-qualification identifier.
        const SCHEMA: &str = "fastpq:v1:balance-key-v1:six-operation-air:air-quotient-exact-u64:fp4-oracles:joint-trace-degree:fri-terminal4";
        let params = fastpq_isi::FASTPQ_FINAL_V1;
        let field_and_hash = (
            params.field.name,
            params.field.modulus_decimal,
            params.field.extension_degree,
            params.field.extension_polynomial,
            params.hash.trace_commitment,
            params.hash.transcript,
            params.hash.digest_bytes,
        );
        let polynomial_profile = (
            params.trace_log_size,
            params.trace_root,
            params.lde_log_size,
            params.lde_root,
            params.omega_coset,
            params.fri.arity,
            params.fri.blowup_factor,
            params.fri.max_reductions,
            params.fri.queries,
            fastpq_isi::FASTPQ_COMPOSITION_DEGREE_EXPANSION_V1,
            fastpq_isi::FASTPQ_FRI_TERMINAL_DOMAIN_SIZE_V1,
        );
        // Transcript bytes cannot inherit an unrelated caller's Norito layout.
        let _canonical_flags =
            norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let payload = norito::core::to_bytes(&(
            protocol_version,
            parameter,
            SCHEMA,
            params.name,
            params.grinding_bits,
            field_and_hash,
            polynomial_profile,
            *public_io,
        ))?;
        let state = hash_bytes_v1(
            TRANSCRIPT_ROLE_V1,
            b"initialise",
            0,
            0,
            0,
            &[tag.as_bytes(), &payload],
        )?;
        Ok(Self { state, counter: 1 })
    }
    /// Bind both trace commitments and their exact geometry before aggregation challenges.
    pub(crate) fn append_trace_oracles(
        &mut self,
        trace_root: GoldilocksDigest384V1,
        air_trace_root: GoldilocksDigest384V1,
        domain_size: u32,
        columns: usize,
    ) -> Result<()> {
        let columns =
            u32::try_from(columns).map_err(|_| Error::TraceLengthOverflow { rows: columns })?;
        // Transcript bytes cannot inherit an unrelated caller's Norito layout.
        let _canonical_flags =
            norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let payload = norito::core::to_bytes(&(
            trace_root.to_le_bytes(),
            air_trace_root.to_le_bytes(),
            domain_size,
            columns,
        ))?;
        self.append_message(TRANSCRIPT_TAG_TRACE_ROOT, &payload);
        Ok(())
    }
    /// Sample one full extension-field aggregation coefficient.
    pub(crate) fn challenge_extension(&mut self, tag: &str) -> GoldilocksFp4V1 {
        GoldilocksFp4V1::from_digest(self.challenge_digest(tag))
    }
    pub fn append_message(&mut self, tag: &str, message: &[u8]) {
        self.state = hash_bytes_v1(
            TRANSCRIPT_ROLE_V1,
            b"append-message",
            0,
            0,
            self.counter,
            &[&self.state.to_le_bytes(), tag.as_bytes(), message],
        )
        .expect("bounded FASTPQ transcript message framing");
        self.counter = self
            .counter
            .checked_add(1)
            .expect("FASTPQ transcript counter overflow");
    }
    pub fn append_fri_layer(&mut self, round: usize, root: GoldilocksDigest384V1) {
        let tag = format!("{TRANSCRIPT_TAG_FRI_LAYER_PREFIX}:{round}");
        self.append_message(&tag, &root.to_le_bytes());
    }
    pub fn append_fri_final(&mut self, root: GoldilocksDigest384V1) {
        self.append_message(FRI_FINAL_DOMAIN, &root.to_le_bytes());
    }
    pub fn challenge_beta(&mut self, round: usize) -> GoldilocksFp4V1 {
        let tag = format!("{TRANSCRIPT_TAG_BETA_PREFIX}:{round}");
        GoldilocksFp4V1::from_digest(self.challenge_digest(&tag))
    }
    pub fn challenge_field(&mut self, tag: &str) -> u64 {
        self.challenge_digest(tag).words()[0]
    }

    fn challenge_digest(&mut self, tag: &str) -> GoldilocksDigest384V1 {
        let digest = hash_bytes_v1(
            TRANSCRIPT_ROLE_V1,
            b"challenge",
            0,
            0,
            self.counter,
            &[&self.state.to_le_bytes(), tag.as_bytes()],
        )
        .expect("bounded FASTPQ transcript challenge framing");
        self.state = digest;
        self.counter = self
            .counter
            .checked_add(1)
            .expect("FASTPQ transcript counter overflow");
        digest
    }
}
#[inline]
fn add_mod(a: u64, b: u64) -> u64 {
    crate::field::add_base(a, b)
}
#[inline]
fn sub_mod(a: u64, b: u64) -> u64 {
    crate::field::sub_base(a, b)
}
#[inline]
fn mul_mod(a: u64, b: u64) -> u64 {
    crate::field::mul_base(a, b)
}
fn field_pow(mut base: u64, mut exponent: u64) -> u64 {
    let mut result = FIELD_ONE;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = mul_mod(result, base);
        }
        base = mul_mod(base, base);
        exponent >>= 1;
    }
    result
}
fn field_inverse(value: u64) -> u64 {
    debug_assert_ne!(value, 0, "zero has no Goldilocks multiplicative inverse");
    field_pow(value, GOLDILOCKS_MODULUS - 2)
}
#[cfg(test)]
mod tests;
