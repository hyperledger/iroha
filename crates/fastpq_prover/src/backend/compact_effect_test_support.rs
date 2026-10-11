//! Shared synthetic source facts and exact real backend entry points for fixture migration.

use crate as prover;
#[path = "../../tests/support/complete_effect_fixture.rs"]
pub(in crate::backend) mod fixture;
use super::*;
use crate::backend::offline_compact::{BundleVerificationLimits, VerificationLimits};
pub(in crate::backend) use fixture::EffectFixture;
use iroha_allocation::AllocationBudget;

pub(in crate::backend) fn policy(limits: ArtifactLimits) -> VerificationLimits {
    let b = limits.bundle;
    VerificationLimits {
        transport: limits.transport,
        public_statement: limits.public_statement,
        max_segment_decode_allocation_charges: limits.max_segment_decode_allocation_charges,
        total_decode: limits.total_decode,
        bundle: BundleVerificationLimits {
            max_segments: b.max_segments,
            max_wire_bytes: b.max_wire_bytes,
            max_total_segment_bytes: b.max_total_segment_bytes,
            max_total_statement_bytes: b.max_total_statement_bytes,
            max_total_queries: b.max_total_queries,
            max_total_decode_allocation_charges: b.max_total_decode_allocation_charges,
            segment: b.segment,
        },
    }
}
pub(in crate::backend) fn verify(
    bytes: &[u8],
    expected: &EffectFixture,
    limits: ArtifactLimits,
) -> Result<VerifiedArtifact, ArtifactError> {
    verify_expected(bytes, expected, expected.expected(), limits)
}
pub(in crate::backend) fn verify_expected(
    bytes: &[u8],
    funding_fixture: &EffectFixture,
    expected: crate::offline_compact::ExpectedExecutionEffects<'_>,
    limits: ArtifactLimits,
) -> Result<VerifiedArtifact, ArtifactError> {
    let generous = fixture::limits(VerificationLimits::default());
    let demand = crate::offline_compact::quantity_ordinary_verification_allocation_bytes(
        &funding_fixture.statement.effects,
        &generous,
    )?;
    let budget = AllocationBudget::new(demand);
    let mut reservation = budget.try_reserve_bytes(demand).map_err(Error::from)?;
    let result = execution_effect::verify(
        bytes,
        expected,
        &fixture::limits(policy(limits)),
        &budget,
        &mut reservation,
    );
    drop(reservation);
    assert_eq!(budget.reserved_bytes(), 0);
    result
}
