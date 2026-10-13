//! SCCP L3 stake-release gates over original generation and closed offence custody.
//!
//! These read-only guards add to native tenure and unbond-delay checks. They do not
//! authenticate or publish evidence. Pending SCCP generations must remain retained until
//! their penalties apply (§4.11); current pruning deliberately retains all generations.

use super::{original_read::OriginalRead, store};
use crate::state::{
    WorldReadOnly,
    sccp_forgery_custody::{ForgeryStorageError, OffenceKey},
};
use iroha_allocation::AllocationBudget;
use iroha_crypto::Hash;
use iroha_data_model::{
    block::consensus::{EvidencePenaltyStatus, EvidenceScope, RecordedEvidenceV1},
    nexus::PublicLaneValidatorRecord,
};
use mv::storage::StorageReadOnly as _;

/// Deterministic reasons L3 retains the original validator registration or its stake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReleaseBlocker {
    /// An original generation remains liable for the stake being released.
    LiabilityActive,
    /// An exact recorded SCCP offence still awaits its penalty.
    PenaltyPending,
}

/// Inspect at most the retained generations, using their exact captured registration.
///
/// `parent` supplies generation membership/current generation/destination clearance.
/// `current` supplies the block-start liability clock and pending penalty disposition.
/// A replacement or pruning passes `None`; an unbond passes its exact liability height.
/// The original caller pool funds each temporary canonical query key before any account
/// graph copy. No permanent evidence-history scan or present-day peer-key lookup occurs.
///
/// # Errors
/// Preserves original key-copy resource refusals. Inconsistent offence-to-record joins
/// refuse as source invariants; they are never interpreted as absence or applied penalties.
/// TODO: the full evidence handler and pruning owner must preserve the pending-generation
/// retention invariant before SubmitSccpForgeryEvidence can be enabled.
pub(crate) fn release_blocker<'a>(
    parent: impl OriginalRead<'a> + 'a,
    current: &(impl WorldReadOnly + ?Sized),
    validator: &PublicLaneValidatorRecord,
    slashable_through_height: Option<u64>,
    budget: &AllocationBudget,
) -> Result<Option<ReleaseBlocker>, ForgeryStorageError> {
    let current_generation = parent.committee_current();
    let clock = *store::liability_clock::get(current);
    for (generation, record) in parent.generations() {
        if !record.members.iter().flatten().any(|member| {
            member.lane_id == validator.lane_id
                && member.validator == validator.validator
                && member.activation_height == validator.activation_height
        }) {
            continue;
        }
        if *generation != record.generation || !record.is_well_formed() {
            return Err(ForgeryStorageError::Invalid);
        }
        if slashable_through_height.is_none_or(|height| record.start_height <= height)
            && record.is_liable(current_generation, clock)
        {
            return Ok(Some(ReleaseBlocker::LiabilityActive));
        }
        let key =
            OffenceKey::try_copy(*generation, validator.lane_id, &validator.validator, budget)?;
        let Some(evidence_id) = store::forgery_offences::get(current, &key) else {
            continue;
        };
        let retained = current
            .consensus_evidence()
            .get(&Hash::prehashed(*evidence_id))
            .ok_or(ForgeryStorageError::Invalid)?;
        let RecordedEvidenceV1::SccpForgery(forgery) = &retained.evidence else {
            return Err(ForgeryStorageError::Invalid);
        };
        if retained.sccp_evidence_id() != Some(*evidence_id)
            || retained.attribution.scope
                != (EvidenceScope::SccpGeneration {
                    generation: *generation,
                })
            || retained.attribution.height != record.start_height
            || retained.attribution.authority_generation != record.committee_root
            || forgery.generation != *generation
            || forgery.start_height != record.start_height
            || !forgery.offenders.iter().any(|offender| {
                offender.lane_id == validator.lane_id
                    && offender.validator == validator.validator
                    && offender.activation_height == validator.activation_height
                    && usize::try_from(offender.signer)
                        .ok()
                        .and_then(|index| record.members.get(index))
                        .and_then(Option::as_ref)
                        .is_some_and(|member| {
                            member.lane_id == validator.lane_id
                                && member.validator == validator.validator
                                && member.activation_height == validator.activation_height
                        })
            })
        {
            return Err(ForgeryStorageError::Invalid);
        }
        if retained.penalty_status == EvidencePenaltyStatus::Pending {
            return Ok(Some(ReleaseBlocker::PenaltyPending));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests;
