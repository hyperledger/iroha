//! Resolve an original native committee seat to its exact retained primary-lane tenure.
//!
//! This is the borrowed G6 prerequisite, not a generation writer or finality authenticator.
//! The caller authenticates the enclosing original epoch and resolves its seats in order.
//! Mutable consensus-key/PoP registries are deliberately absent from this interface. A later
//! writer must fund the copied account graph and persist these bindings with the generation.

use iroha_data_model::{
    account::AccountId, nexus::PublicLaneValidatorRecord,
    sumeragi::epoch::ValidatorCommitteeMemberV1,
};
use iroha_model_base::topology::LaneId;

use crate::{
    smartcontracts::isi::staking::validator_tenure_contains_height,
    state::public_lane_validator_record_matches_key,
};

/// A retained staking source cannot unambiguously bind an original native committee seat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SccpMemberBindingError {
    /// Storage key and retained validator identity disagree.
    #[error("SCCP member source has a noncanonical primary-lane store identity")]
    StoreIdentity,
    /// More than one primary-lane record names the same immutable consensus peer.
    #[error("SCCP member source repeats an original primary-lane consensus peer")]
    DuplicatePeer,
    /// Activation, deactivation or pending status does not define a canonical tenure.
    #[error("SCCP member source has an inconsistent retained validator tenure")]
    Tenure,
    /// Generation heights start at the nonzero genesis height.
    #[error("SCCP generation member height is zero")]
    Height,
}

/// Borrow the exact primary-lane registration of one original committee seat at its start.
///
/// Missing or out-of-tenure records return `None`, the explicit G6 unslashable outcome. A
/// malformed or ambiguous source refuses instead of selecting the first row. Selection exit
/// and current lifecycle status cannot revoke a frozen seat's retained tenure. Other lanes
/// cannot replace the primary-lane record used by native global committee election.
///
/// `records` must come from the frozen execution source cut at block `h`. The tenure
/// coordinate is `start_height`, which is `h + 1` for G2 and `h` for genesis/resync. A
/// pending activation at `h + 1` can cover a G2 successor; a deactivation at `h + 1`
/// cannot. Checking tenure at the source-cut height would select the wrong registration
/// and disagree with the generation's slashing offence height (§4.8 L2, §4.9 step 9).
///
/// This allocates nothing and keeps the resolved record borrowed from the same source cut.
/// It neither validates the seat's PoP nor grants finality authority; the original epoch
/// owner establishes both before invoking the generation transition.
///
/// # Errors
/// Rejects zero height, malformed primary identities/tenure, or duplicate primary peers.
pub fn resolve_generation_member<'a>(
    original: &ValidatorCommitteeMemberV1,
    start_height: u64,
    records: impl IntoIterator<Item = (&'a (LaneId, AccountId), &'a PublicLaneValidatorRecord)>,
) -> Result<Option<&'a PublicLaneValidatorRecord>, SccpMemberBindingError> {
    if start_height == 0 {
        return Err(SccpMemberBindingError::Height);
    }
    let mut selected = None;
    for (key, record) in records {
        if key.0 != LaneId::SINGLE && record.lane_id != LaneId::SINGLE {
            continue;
        }
        if !public_lane_validator_record_matches_key(key, record) {
            return Err(SccpMemberBindingError::StoreIdentity);
        }
        if record.peer_id != original.validator {
            continue;
        }
        if selected.replace(record).is_some() {
            return Err(SccpMemberBindingError::DuplicatePeer);
        }
    }
    let Some(record) = selected else {
        return Ok(None);
    };
    let contains = validator_tenure_contains_height(record, start_height)
        .map_err(|_| SccpMemberBindingError::Tenure)?;
    Ok(contains.then_some(record))
}

#[cfg(test)]
#[path = "member_binding/tests.rs"]
mod tests;
