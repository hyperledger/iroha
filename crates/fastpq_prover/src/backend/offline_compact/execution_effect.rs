//! Ordinary complete-effect facade with independent source identity and original credit.

use super::*;
use crate::gadgets::{
    compact_smt_air::PublicStatement,
    public_transfer_statement::execution_effect::{
        ExecutionEffectExpectations, ExecutionEffectLimits, SourceExecutionEffectStatement,
        preparation_allocation_bytes,
    },
};
use iroha_allocation::AllocationRefusal;
use iroha_data_model::fastpq::{FastpqExecutionEffectsV1, FastpqOrdinarySourceStatementLeafV1};
use std::alloc::Layout;

/// Full source opening and complete statement facts from the caller's authenticated state.
/// D7 authenticates complete original effects and source context. Derive the touched-key
/// SMT roots and full statement digest from the original `CapturedQuantityEntry` loan
/// using the finite source materializer; ledger World roots are a different commitment.
/// Never copy expectations from offered artifact bytes. Neither these data fields nor
/// local materialization manufacture finalized authority.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedExecutionEffects<'a> {
    /// Independently authenticated complete D7 source leaf, including its ordered position.
    pub source: &'a FastpqOrdinarySourceStatementLeafV1,
    /// Independent original effect digest, complete statement digest and public roots/context.
    pub statement: ExecutionEffectExpectations,
}

/// Explicit complete-effect preparation and inherited whole-artifact proof/decode ceilings.
/// Proving and verification borrow this read-only policy across the complete operation.
#[derive(Debug, Clone, Copy)]
pub struct ExecutionEffectVerificationLimits {
    /// Canonical model transport limits, including its complete opaque carrier.
    pub transport: FastpqCompactArtifactDecodeLimits,
    /// Canonical complete-effect preparation limits; fixed defaults remain upper bounds.
    pub public_statement: ExecutionEffectLimits,
    /// Ordered carrier and per-child verification limits.
    pub bundle: BundleVerificationLimits,
    /// Allocation charges for each complete child proof decode.
    pub max_segment_decode_allocation_charges: usize,
    /// One cumulative scope spanning model, carrier and all child proof decodes.
    pub total_decode: DecodeLimits,
}
impl Default for ExecutionEffectVerificationLimits {
    fn default() -> Self {
        let shared = VerificationLimits::default();
        Self {
            transport: shared.transport,
            public_statement: ExecutionEffectLimits::default(),
            bundle: shared.bundle,
            max_segment_decode_allocation_charges: shared.max_segment_decode_allocation_charges,
            total_decode: shared.total_decode,
        }
    }
}
impl ExecutionEffectVerificationLimits {
    /// Reuse only the physical proof/transport policy; transfer preparation is never called.
    pub(in crate::backend) fn proof_policy(&self) -> VerificationLimits {
        VerificationLimits {
            transport: self.transport,
            public_statement: PublicTransferLimits::default(),
            bundle: self.bundle,
            max_segment_decode_allocation_charges: self.max_segment_decode_allocation_charges,
            total_decode: self.total_decode,
        }
    }
    pub(in crate::backend) fn public_policy(&self) -> ExecutionEffectLimits {
        let fixed = ExecutionEffectLimits::default();
        ExecutionEffectLimits {
            max_effects: self.public_statement.max_effects.min(fixed.max_effects),
            max_rows: self.public_statement.max_rows.min(fixed.max_rows),
            max_public_bytes: self
                .public_statement
                .max_public_bytes
                .min(fixed.max_public_bytes),
            max_unique_keys: self
                .public_statement
                .max_unique_keys
                .min(fixed.max_unique_keys),
            max_allocation_steps: self
                .public_statement
                .max_allocation_steps
                .min(fixed.max_allocation_steps),
        }
    }
}
fn add(left: usize, right: usize) -> crate::Result<usize> {
    left.checked_add(right)
        .ok_or_else(|| AllocationRefusal::DemandOverflow.into())
}
fn array_bytes<T>(count: usize) -> crate::Result<usize> {
    Layout::array::<T>(count)
        .map(|v| v.size())
        .map_err(|_| AllocationRefusal::DemandOverflow.into())
}
fn count(
    effects: &FastpqExecutionEffectsV1,
    policy: &ExecutionEffectVerificationLimits,
) -> crate::Result<usize> {
    let count = effects.effects.len();
    let max = policy
        .public_policy()
        .max_effects
        .min(policy.bundle.max_segments);
    if count == 0 {
        return Err(Error::TransferInvariant {
            details: "ordinary effect artifact requires a nonempty complete entry".into(),
        });
    }
    if count > max {
        return Err(Error::VerifierLimitExceeded {
            limit: "max_compact_bundle_segments",
            actual: count,
            max,
        });
    }
    Ok(count)
}

/// Conservative original-credit demand for one ordinary verification's public preparation.
/// This covers normalized preparation, retained public ports and complete batch context.
/// Context demand uses the unchanged inclusive total-statement ceiling. Canonical decoder
/// charges, bounded AIR scratch and proof/output buffers retain their separate original caps.
/// This helper reserves nothing and grants no source authority.
/// # Errors
/// Rejects empty/over-limit tapes, malformed sizes and checked layout/arithmetic overflow.
pub fn quantity_ordinary_verification_allocation_bytes(
    effects: &FastpqExecutionEffectsV1,
    limits: &ExecutionEffectVerificationLimits,
) -> crate::Result<usize> {
    let count = count(effects, limits)?;
    add(
        preparation_allocation_bytes(effects, limits.public_policy())?,
        add(
            array_bytes::<PublicStatement>(count)?,
            limits.bundle.max_total_statement_bytes,
        )?,
    )
}

/// Conservative total consumed original credit for proving and mandatory self-verification.
/// Add source materialization's separate demand before reserving once from its original pool.
/// The sum includes each preparation invocation even after its owner is dropped, because
/// released allocations do not replenish the caller's existing reservation. Private tree,
/// retained intermediate roots, both batch contexts and public ports are included. Existing
/// proof payload, codec and process-memory policies remain separate; this is not an RSS bound.
/// # Errors
/// Rejects tape/public/tree limits and every checked count, layout or byte overflow.
pub fn quantity_ordinary_allocation_bytes(
    effects: &FastpqExecutionEffectsV1,
    proving: ProvingLimits,
    limits: &ExecutionEffectVerificationLimits,
) -> crate::Result<usize> {
    let count = count(effects, limits)?;
    let rows = count
        .checked_mul(2)
        .ok_or(AllocationRefusal::DemandOverflow)?;
    let public = limits.public_policy();
    let keys = rows
        .min(public.max_unique_keys)
        .min(proving.private_smt.max_unique_keys);
    let preparation = preparation_allocation_bytes(effects, public)?;
    let tree = proving.private_smt.allocation_bytes(rows, keys)?;
    let batch = quantity_ordinary_verification_allocation_bytes(effects, limits)?;
    add(
        add(preparation, tree)?,
        add(array_bytes::<[u8; 32]>(count - 1)?, add(batch, batch)?)?,
    )
}

/// Distinct complete-effect ordinary profile; it cannot select the AXT transfer route.
pub fn execution_effect_profile_id() -> FastpqCompactProfileIdV1 {
    candidate_artifact::execution_effect_profile_id()
}

/// Canonical ordinary output retaining its successful mandatory verifier result.
/// Private fields prevent callers from manufacturing this owner from advertised metadata.
/// This proves consistency with the supplied expectations, not their source authority.
#[derive(Debug)]
pub struct ProducedExecutionEffectArtifact {
    bytes: Vec<u8>,
    verified: VerifiedArtifact,
}
impl ProducedExecutionEffectArtifact {
    /// Borrow the exact canonical output bytes verified by this producer invocation.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Borrow the complete successful result for these exact bytes.
    #[must_use]
    pub const fn verified(&self) -> &VerifiedArtifact {
        &self.verified
    }
    /// Move both original allocations to the caller without another proof verification.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, VerifiedArtifact) {
        (self.bytes, self.verified)
    }
}

/// Produce an ordinary artifact from the original borrowed complete-effect statement.
/// The full independent source leaf and all statement expectations are checked before
/// private work. Preparation and tree/context backing consume only the supplied original
/// reservation. Every child and the final public verifier must succeed before bytes return.
/// # Errors
/// Rejects foreign/insufficient credit, source or statement substitution, public/arithmetic
/// failures, existing work/output limits, concurrent production and final verification failure.
pub fn prove_quantity_ordinary_artifact(
    statement: &SourceExecutionEffectStatement<'_>,
    expected: ExpectedExecutionEffects<'_>,
    proving: ProvingLimits,
    verification: &ExecutionEffectVerificationLimits,
    budget: &AllocationBudget,
    reservation: &mut AllocationReservation,
) -> Result<ProducedExecutionEffectArtifact, ProvingError> {
    super::super::compact_quantity_producer::execution_effect::prove(
        statement,
        expected,
        proving,
        verification,
        budget,
        reservation,
    )
    .map(|(bytes, verified)| ProducedExecutionEffectArtifact { bytes, verified })
}

/// Verify ordinary model bytes against the entire independently authenticated source leaf.
/// Source equality precedes public preparation and child decoding. The offered artifact
/// never supplies its own authority or expected digest, and partial bundles yield no success.
/// # Errors
/// Rejects transport/profile/credit failures, full source or statement mismatches, invalid
/// complete effects and any malformed, missing or invalid child under cumulative ceilings.
pub fn verify_quantity_ordinary_artifact(
    bytes: &[u8],
    expected: ExpectedExecutionEffects<'_>,
    limits: &ExecutionEffectVerificationLimits,
    budget: &AllocationBudget,
    reservation: &mut AllocationReservation,
) -> Result<VerifiedArtifact, VerificationError> {
    candidate_artifact::execution_effect::verify(bytes, expected, limits, budget, reservation)
        .map(|inner| VerifiedArtifact { inner })
        .map_err(Into::into)
}

#[cfg(test)]
#[path = "execution_effect/tests.rs"]
mod tests;
