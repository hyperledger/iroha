//! Canonical proof construction for public deterministic diagnostic fixtures.
//!
//! This test-only helper uses the same q77 producer, clearing source owner and
//! self-check as ordinary artifacts. Fixed fixture entropy is never a production
//! RNG. No alternate proof layout, transcript or verifier is implemented here.

use rand::{SeedableRng, rngs::StdRng};

use super::{
    air::q77::{ProducerLimits, VerifierLimits},
    deep_proof,
    deep_prover::ProducerPlan,
    deep_relation::DeepRelation,
    deep_trace_source::OwnedTraceSource,
};
use crate::{Result, VerifyLimits};

/// Prove one complete public fixture using explicit deterministic test entropy.
pub(super) fn prove(
    relation: &impl DeepRelation,
    source: OwnedTraceSource,
    seed: u64,
) -> Result<Vec<u8>> {
    ProducerPlan::new(
        relation,
        ProducerLimits {
            max_proof_bytes: deep_proof::PROOF_BYTE_TARGET,
            ..ProducerLimits::default()
        },
    )?
    .build(source, &mut StdRng::seed_from_u64(seed))
}

/// Exact admitted child-frame and query geometry within the unchanged ceilings.
pub(super) fn verification_limits() -> VerifyLimits {
    VerifyLimits {
        max_proof_bytes: deep_proof::MAX_FRAME_BYTES,
        max_queries: super::deep_geometry::QUERY_COUNT,
        ..VerifyLimits::default()
    }
}

/// The same facade policy as the engine's typed verifier limits, with the
/// 32 MiB decode allocation ceiling the engine fixtures use.
pub(super) fn engine_verification_limits() -> VerifierLimits {
    VerifierLimits::for_segment(verification_limits(), 32 * 1024 * 1024)
}

#[cfg(test)]
#[path = "deep_fixture/retirement_tests.rs"]
mod retirement_tests;

#[cfg(test)]
#[path = "deep_fixture/frozen_tests.rs"]
mod frozen_tests;
