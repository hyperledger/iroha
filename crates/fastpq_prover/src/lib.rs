//! FASTPQ lane prover.
//!
//! This crate implements the FASTPQ-ISI prover and verifier with deterministic
//! commitments and the sole first-release V1 parameter set. Canonical transfer
//! artifacts use masked DEEP proofs and bounded verification in every build.
//! Node and standalone callers share the same implementation and independently
//! bind authenticated public statements, finality and replay policy.
//! Validation evidence is recorded in `specs/fastpq_production_readiness.md`.
//!
//! The public API is intentionally narrow and uses Norito-friendly types so
//! callers can persist artifacts without pulling in Serde.
//!
//! Relations are described against the typed [`air`] interface. The committed
//! engine accepts only its sealed transfer relations through it; every other
//! relation has an uncommitted algebraic reference there, which is not a proof.

#![cfg_attr(
    not(feature = "dev-tools"),
    doc = r"
Transparent batch-replay fixtures are excluded from the normal library API.
Canonical quantity artifacts use [`offline_compact`]; AXT batches may use
[`prove_axt_bound_batch`]. The retired normal replay surface is unavailable:

```compile_fail
use fastpq_prover::Prover;
```

```compile_fail
use fastpq_prover::Proof;
```

```compile_fail
use fastpq_prover::verify;
```

```compile_fail
use fastpq_prover::verify_with_limits;
```

```compile_fail
use fastpq_prover::preflight_native_v1_gpu_backend;
```
"
)]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![allow(unexpected_cfgs)]
mod axt_binding;
mod backend;
mod batch;
#[cfg(any(test, feature = "dev-tools"))]
mod benchmark_geometry;
#[cfg(any(test, feature = "dev-tools", feature = "fastpq-gpu"))]
mod bn254;
mod bn254_poseidon;
#[cfg(feature = "fastpq-gpu")]
mod bn254_poseidon_params;
mod cyclotomic;
mod digest;
mod digest384_batch;
#[cfg(any(test, feature = "dev-tools"))]
mod digest384_benchmark;
#[cfg(feature = "fastpq-gpu")]
mod digest384_gpu;
#[cfg(all(test, feature = "fastpq-gpu"))]
mod digest384_indexed_gpu;
mod digest_executor;
mod error;
#[cfg(any(test, feature = "dev-tools", feature = "fastpq-gpu"))]
mod fastpq_cuda;
mod fft;
mod field;
#[cfg(test)]
mod frame_tests;
pub mod gadgets;
/// Exact-root, bounded-column Goldilocks arithmetic with deterministic fallback.
pub mod goldilocks_transform;
#[cfg(feature = "fastpq-gpu")]
#[path = "gpu.rs"]
mod gpu;
#[cfg(not(feature = "fastpq-gpu"))]
#[path = "gpu_stub.rs"]
mod gpu;
mod gpu_memory;
#[cfg(feature = "fastpq-gpu")]
mod gpu_secret;
mod keccak_batch;
#[cfg(feature = "fastpq-gpu")]
mod keccak_gpu;
#[cfg(all(feature = "fastpq-gpu", target_os = "macos"))]
mod metal;
#[cfg(any(test, all(feature = "fastpq-gpu", target_os = "macos")))]
mod metal_artifact;
mod metal_config;
mod ordering;
pub(crate) mod overrides;
mod packing;
mod poseidon;
mod poseidon_manifest;
mod proof;
mod semantics;
// Development-only State commitment candidates of ZK delivery plan task G.2.
// TODO(G.3): delete with the selection of the State commitment construction.
#[cfg(any(test, feature = "dev-tools"))]
pub mod state_commitment_prototypes;
mod trace;
pub use axt_binding::{
    AXT_FASTPQ_BATCH_SEAL_METADATA_KEY, AXT_FASTPQ_BINDING_METADATA_KEY,
    AXT_FASTPQ_COMMITTED_AMOUNT_METADATA_KEY, AXT_FASTPQ_DA_COMMITMENT_METADATA_KEY,
    AXT_FASTPQ_EXPIRY_SLOT_METADATA_KEY, AXT_FASTPQ_MANIFEST_ROOT_METADATA_KEY,
    AXT_FASTPQ_REMOTE_SPEND_CLAIMS_METADATA_KEY,
    AXT_FASTPQ_SOURCE_TRANSFER_OCCURRENCES_METADATA_KEY, AxtVerifiedProof,
    DEFAULT_PARAMETER as AXT_DEFAULT_PARAMETER, MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES,
    axt_proof_blob_from_bound_batch, axt_proof_envelope_from_bound_batch, batch_manifest_sha256,
    bind_axt_batch, bind_axt_batch_with_committed_amount, bind_axt_batch_with_proof_metadata,
    canonicalize_binding, embedded_axt_binding, encode_axt_fastpq_payload, prove_axt_bound_batch,
    set_axt_remote_spend_claims, set_axt_source_transfer_occurrences, transition_batch_from_model,
    transition_batch_to_model, validate_axt_transfer_claim_binding, verify_axt_bound_batch,
    verify_axt_proof_blob, verify_axt_proof_envelope,
    verify_axt_proof_envelope_against_anchor_and_claimed_source_v1,
    verify_axt_proof_envelope_with_outer_metadata,
};
/// Typed semantic AIR, field, public-IO, work-limit and observer interface.
pub use backend::air;
/// Canonical masked quantity-artifact production and bounded verification.
pub use backend::offline_compact;
#[cfg(any(test, feature = "dev-tools"))]
pub use backend::preflight_native_v1_gpu_backend;
pub use backend::{
    ExecutionMode, PoseidonExecutionMode, clear_execution_mode_observer,
    set_execution_mode_observer,
};
#[cfg(feature = "dev-tools")]
#[doc(hidden)]
pub use backend::{
    compute_lookup_grand_product, hash_lde_leaves, lde_chunk_size, merkle_paths_for_queries,
};
pub use batch::{
    OperationKind, PublicInputs, StateTransition, TRANSITION_BATCH_SCHEMA_NAME, TransitionBatch,
};
#[cfg(feature = "dev-tools")]
#[doc(hidden)]
pub use benchmark_geometry::{BenchmarkGeometryV1, preflight_benchmark_geometry_v1};
pub use bn254_poseidon::{
    Bn254PoseidonBatchSlice, PendingBn254PoseidonWordBatch, preflight_bn254_poseidon_word_batches,
    try_hash_bn254_poseidon_word_batches, try_submit_bn254_poseidon_word_batches,
};
pub use digest::trace_commitment;
pub use digest_executor::{
    DigestExecutionV1, MAX_DIGEST384_BATCH_FRAMES_V1, MAX_DIGEST384_BATCH_WORDS_V1,
    execute_digest384_frames_v1, hash_digest384_pairs_v1,
};
#[cfg(feature = "fastpq-gpu")]
pub use digest384_batch::preflight_digest384_continuation_v1;
#[cfg(feature = "dev-tools")]
#[doc(hidden)]
pub use digest384_benchmark::{
    Digest384BenchmarkDeviceV1, Digest384BenchmarkInputV1, Digest384BenchmarkReportV1,
    benchmark_digest384_v1,
};
#[cfg(feature = "fastpq-gpu")]
pub use digest384_gpu::{Digest384GpuBackendV1, Digest384GpuErrorV1, try_hash_digest384_frames_v1};
pub use error::{Error, Result};
#[cfg(feature = "dev-tools")]
#[doc(hidden)]
pub use fastpq_cuda::{CudaBackendError, fastpq_bn254_fft, fastpq_bn254_lde};
pub use fft::Planner;
pub use field::{GOLDILOCKS_MODULUS_V1, GoldilocksFp4V1};
#[cfg(all(feature = "fastpq-gpu", target_os = "macos"))]
pub use metal::{
    AdaptiveScheduleSnapshot, BatchHeuristicSnapshot, ColumnStagingPhase, ColumnStagingPhaseStats,
    ColumnStagingSample, ColumnStagingStats, CommandLimitSnapshot, CommandLimitSource, KernelKind,
    KernelStatsSample, LdeHostStats, MetalKernelDescriptor, PostTileSample, QueueDepthStats,
    QueueLaneStats, TwiddleCacheStats, adaptive_schedule_snapshot, enable_kernel_stats,
    enable_lde_host_stats, enable_post_tile_stats, enable_queue_depth_stats,
    enable_twiddle_cache_stats, fft_tuning_snapshot, metal_kernel_descriptors,
    poseidon_tuning_snapshot, set_metal_queue_policy, snapshot_queue_depth_stats,
    take_column_staging_stats, take_kernel_stats, take_lde_host_stats, take_post_tile_stats,
    take_queue_depth_stats, take_twiddle_cache_stats,
};
pub use metal_config::{FftTuning, PoseidonTuning};
pub use ordering::ordering_hash;
pub use overrides::{MetalOverrides, apply_metal_overrides};
pub use packing::{LIMB_BYTES, PackedBytes, pack_bytes};
#[cfg(feature = "fastpq-gpu")]
pub use poseidon::preflight_gpu_backend as preflight_poseidon_gpu_backend;
pub use poseidon::{FIELD_MODULUS, PoseidonSponge, hash_field_elements};
pub use proof::VerifyLimits;
#[cfg(any(test, feature = "dev-tools"))]
pub use proof::{Proof, Prover, verify, verify_with_limits};
#[cfg(any(test, feature = "dev-tools"))]
pub use proof::{verify_raw_statement, verify_raw_statement_with_limits};
pub use semantics::{ProofSemantics, validate_batch_semantics};
pub use trace::{
    PoseidonPipelinePolicy, RowUsage, Trace, TraceColumn, build_trace,
    clear_poseidon_gpu_event_observer, clear_poseidon_pipeline_observer,
    set_poseidon_gpu_event_observer, set_poseidon_pipeline_observer,
};
#[cfg(not(all(feature = "fastpq-gpu", target_os = "macos")))]
/// No-op when the Metal backend is unavailable.
///
/// # Errors
/// This stub never errors because the Metal backend is disabled at compile time and
/// runtime overrides are ignored on unsupported targets.
#[allow(clippy::unnecessary_wraps)]
pub fn set_metal_queue_policy(
    _fanout: Option<usize>,
    _column_threshold: Option<u32>,
) -> std::result::Result<(), &'static str> {
    Ok(())
}
pub use poseidon_manifest::{
    PoseidonManifest, poseidon_manifest, poseidon_manifest_sha256, poseidon_profile_id,
    poseidon_profile_sha256,
};

#[cfg(test)]
use crate as test_prover;
#[cfg(test)]
#[path = "../tests/support/producer_funding.rs"]
mod test_producer_funding;
