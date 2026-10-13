//! Deterministic consumers of the retained SCCP pause State (§4.14.2, §4.14.7).
//!
//! This module grants no pause authority. The endorsement/enactment producer and the
//! forgery evidence publication remain separate authority owners.

use super::store;
use crate::state::{StateReadOnly, WorldReadOnly};
use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::registry::{SccpRouteActivationV1, SccpRouteRevisionV1},
};

/// Whether the immutable forgery floor or permanent quarantine holds a route revision.
/// Reconciliation remains separately authenticated; no activation or pause clears this gate.
pub(super) fn forgery_or_quarantine(
    world: &(impl WorldReadOnly + ?Sized),
    revision: &SccpRouteRevisionV1,
) -> bool {
    (!cfg!(all(test, sumeragi_core_mutation = "HC323"))
        && revision.forgery_held(store::forgery_max_generation(world)))
        || revision.quarantine.is_some()
}

/// A committed timestamp must belong to this exact captured original history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SccpCommittedTimeError {
    /// Positive-height history has no original executed tip.
    #[error("SCCP committed history has no original executed time")]
    Missing,
    /// The retained original tip and captured history disagree.
    #[error("SCCP committed time belongs to a different original history")]
    SourceMismatch,
}

/// Read the time of the original committed prefix, without consulting the wall clock,
/// liability clock, executing header or another State publication.
///
/// # Errors
/// Returns a typed source failure for an absent or conflicting positive-height tip.
/// The genuinely empty predecessor has no time; timestamp zero remains `Some(0)`.
pub fn committed_time_ms(
    state: &(impl StateReadOnly + ?Sized),
) -> Result<Option<u64>, SccpCommittedTimeError> {
    let original = captured_time_ms(state.block_hashes(), state.native_execution_tip())?;
    if cfg!(all(test, sumeragi_core_mutation = "HC242")) {
        // Mutation-only replacement of the original receipt time by executing header time.
        return Ok(state.authenticated_query_ledger_time_ms());
    }
    Ok(original)
}

fn captured_time_ms(
    hashes: &dyn crate::state::BlockHashRead,
    tip: Option<crate::state::NativeExecutionTip>,
) -> Result<Option<u64>, SccpCommittedTimeError> {
    let Some(tip) = tip else {
        return if hashes.is_empty() {
            Ok(None)
        } else {
            Err(SccpCommittedTimeError::Missing)
        };
    };
    let height =
        usize::try_from(tip.height()).map_err(|_| SccpCommittedTimeError::SourceMismatch)?;
    if height == 0 || height != hashes.len() || hashes.get(height - 1) != Some(&tip.iroha_hash()) {
        return Err(SccpCommittedTimeError::SourceMismatch);
    }
    Ok(Some(tip.creation_time_ms()))
}

/// Whether the persisted Taira half holds every revision of `network` at the supplied
/// original time. With no original time an existing Taira pause cannot be expired safely.
#[must_use]
pub fn fast_taira(
    world: &(impl WorldReadOnly + ?Sized),
    network: SccpNetworkV1,
    timestamp_ms: Option<u64>,
) -> bool {
    active_fast_taira(store::fast_pauses::get(world, &network), timestamp_ms)
}

/// Whether the destination half pauses this exact revision at executing ledger time.
/// It does not hold inbound settlement or bounce (§4.12.5).
#[must_use]
pub fn fast_destination(
    world: &(impl WorldReadOnly + ?Sized),
    network: SccpNetworkV1,
    revision: u32,
    timestamp_ms: u64,
) -> bool {
    if cfg!(all(test, sumeragi_core_mutation = "HC241")) {
        return false;
    }
    store::fast_pauses::get(world, &network)
        .is_some_and(|pause| pause.destination_expiry(revision, timestamp_ms) != 0)
}

/// The currently represented Taira hold predicate. Activation and `enabled` remain
/// independent persisted facts; no consumer rewrites either when a fast pause expires.
///
/// Forgery, permanent quarantine and the two pause tracks retain their independent gates.
#[must_use]
pub fn taira(
    world: &(impl WorldReadOnly + ?Sized),
    network: SccpNetworkV1,
    revision: u32,
    timestamp_ms: Option<u64>,
) -> bool {
    store::routes::get(world, &network)
        .and_then(|route| route.revisions.get(&revision))
        .is_some_and(|record| {
            !super::reconciliation::is_reconciled(world, network, revision)
                && forgery_or_quarantine(world, record)
        })
        || taira_from_parts(
            store::parameters::get(world)
                .as_ref()
                .is_some_and(|params| params.enabled),
            store::routes::get(world, &network)
                .and_then(|route| route.revisions.get(&revision))
                .map(|r| r.activation),
            store::fast_pauses::get(world, &network),
            timestamp_ms,
        )
}

/// One exact hold kernel over borrowed current or pre-block facts.
pub(crate) fn taira_from_parts(
    enabled: bool,
    activation: Option<SccpRouteActivationV1>,
    pause: Option<&super::pause_record::RetainedSccpFastPause>,
    timestamp_ms: Option<u64>,
) -> bool {
    !enabled
        || activation.is_none_or(|activation| activation == SccpRouteActivationV1::Paused)
        || active_fast_taira(pause, timestamp_ms)
}

fn active_fast_taira(
    pause: Option<&super::pause_record::RetainedSccpFastPause>,
    timestamp_ms: Option<u64>,
) -> bool {
    if cfg!(all(test, sumeragi_core_mutation = "HC240")) {
        return false;
    }
    pause
        .is_some_and(|pause| pause.taira && timestamp_ms.is_none_or(|time| pause.holds_taira(time)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        smartcontracts::isi::sccp::test_support::{
            blank_state, header, install_consumer_fast_pause,
        },
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };

    #[test]
    fn committed_pause_time_binds_original_native_prefix_and_ignores_executing_header() {
        let first = CertifiedTestChain::start(TestChainConfig::new(World::default(), 1_000))
            .expect("genuine applied genesis");
        let second = CertifiedTestChain::start(TestChainConfig::new(World::default(), 2_000))
            .expect("different genuine applied genesis");
        let original = first.state().view();
        let other = second.state().view();
        let tip = original
            .native_execution_tip()
            .expect("original execution receipt");
        assert_eq!(
            committed_time_ms(&original),
            Ok(Some(tip.creation_time_ms()))
        );
        assert_eq!(
            captured_time_ms(original.block_hashes(), other.native_execution_tip()),
            Err(SccpCommittedTimeError::SourceMismatch)
        );
        assert_eq!(
            captured_time_ms(original.block_hashes(), None),
            Err(SccpCommittedTimeError::Missing)
        );
        let empty = blank_state();
        let empty_view = empty.view();
        assert_eq!(committed_time_ms(&empty_view), Ok(None));
        assert_eq!(
            captured_time_ms(empty_view.block_hashes(), Some(tip)),
            Err(SccpCommittedTimeError::SourceMismatch)
        );
        drop(other);
        drop(original);
        let mut block = first.state().block(header(2));
        assert_ne!(block.query_ledger_time_ms(), tip.creation_time_ms());
        assert_eq!(
            committed_time_ms(&block),
            Ok(Some(tip.creation_time_ms())),
            "pause expiry must use the original native prefix time, not the executing header"
        );
        let stx = block.transaction();
        assert_eq!(committed_time_ms(&stx), Ok(Some(tip.creation_time_ms())));
    }

    #[test]
    fn retained_pause_consumers_borrow_at_full_pool_without_clone_or_refund() {
        let state = blank_state();
        let budget = state.view().execution_budget();
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        let network = SccpNetworkV1::EthereumMainnet;
        let now = stx.block_unix_timestamp_ms();
        install_consumer_fast_pause(&mut stx, network, true, vec![2], now + 1);
        let original = store::fast_pauses::get(&*stx.world, &network).unwrap();
        let pointer = original.revisions.as_ptr();
        let occupied = budget.reserved_bytes();
        let outside = budget
            .try_reserve_bytes(budget.limit_bytes() - occupied)
            .unwrap();
        let allocated = crate::test_allocations::allocations_during(|| {
            assert!(fast_taira(&*stx.world, network, Some(now)));
            assert!(fast_taira(&*stx.world, network, None));
            assert!(!fast_taira(&*stx.world, network, Some(now + 1)));
            assert!(!fast_taira(
                &*stx.world,
                SccpNetworkV1::TonMainnet,
                Some(now)
            ));
            assert!(!fast_destination(&*stx.world, network, 1, now));
            assert!(fast_destination(&*stx.world, network, 2, now));
            assert!(!fast_destination(&*stx.world, network, 2, now + 1));
        });
        assert_eq!(allocated, 0);
        assert_eq!(
            store::fast_pauses::get(&*stx.world, &network)
                .unwrap()
                .revisions
                .as_ptr(),
            pointer
        );
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        drop(outside);
        assert_eq!(budget.reserved_bytes(), occupied);
        drop(stx);
        assert!(store::fast_pauses::is_empty(&block.world));
        assert!(
            budget.reserved_bytes() < occupied,
            "retired graph returns original credit"
        );
    }
}

#[cfg(test)]
#[path = "hold/forgery_tests.rs"]
mod forgery_tests;
