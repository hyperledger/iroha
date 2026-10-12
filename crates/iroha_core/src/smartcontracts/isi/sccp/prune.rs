//! Native SCCP post-execution retention and destination clearance (§4.8, §4.11).
//!
//! Light-client retention preserves its existing deletion budget. Generation and anchor deletion
//! requires their complete native forgery/anchor custody; until supplied it is explicitly
//! deferred without deleting records or changing consensus validity. L5 runs afterward and
//! retains every lifecycle copy in the original execution pool before editing the table.

use super::{
    committee_owner::{CommitteeOwnerError, RetainedSccpCommitteeGeneration as Retained},
    generation_error::SccpGenerationLocalError,
    light_clients, store,
};
use crate::{
    block::BlockValidationError,
    state::{StateReadOnly, StateStorageAdmissionError, StateTransaction, WorldReadOnly},
};
use iroha_data_model::sccp::{
    events::{SccpEvent, SccpGenerationDestinationClearedV1},
    registry::{SCCP_ROUTE_NETWORKS_V1, SccpRouteActivationV1},
};
use mv::storage::StorageReadOnly;

#[path = "prune_plan.rs"]
pub mod plan;

/// Existing per-pass deletion budget of light-client sets/checkpoints (§4.13.1).
pub const MAX_LIGHT_CLIENT_DELETIONS_PER_BLOCK: usize = 1_024;

/// Native state custody still required before any generation or anchor can be deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativePruningPrerequisite {
    /// Original pending forgery records and completed/open anchor owners are not integrated.
    ForgeryRecordsAndAnchors,
}

/// Local implementation progress, never a block-validity or finality verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativePruningStatus {
    /// Every native generation and anchor stays retained pending the named state owner.
    Deferred(NativePruningPrerequisite),
}

/// Report why native deletion is deferred rather than pretending pending penalties are absent.
#[must_use]
pub const fn native_pruning_status() -> NativePruningStatus {
    // TODO: connect the real permanent forgery records/offences and admitted anchor stores;
    // then apply plan::generations/anchors against those original sources, at most 8 each.
    NativePruningStatus::Deferred(NativePruningPrerequisite::ForgeryRecordsAndAnchors)
}

fn local_owner_error(
    state: &mut StateTransaction<'_, '_>,
    error: CommitteeOwnerError,
) -> BlockValidationError {
    let local = SccpGenerationLocalError::from_owner(&error).unwrap_or(
        SccpGenerationLocalError::Invariant("invalid retained generation during L5 lifecycle copy"),
    );
    let original = StateStorageAdmissionError::SccpGeneration(local);
    state.arm_local_storage_refusal(original.clone());
    BlockValidationError::StateStorageAdmission(original)
}

fn invariant(state: &mut StateTransaction<'_, '_>, reason: &'static str) -> BlockValidationError {
    let original =
        StateStorageAdmissionError::SccpGeneration(SccpGenerationLocalError::Invariant(reason));
    state.arm_local_storage_refusal(original.clone());
    BlockValidationError::StateStorageAdmission(original)
}

fn destination_progress(world: &(impl WorldReadOnly + ?Sized)) -> [plan::DestinationProgress; 3] {
    SCCP_ROUTE_NETWORKS_V1.map(|network| {
        let relevant = store::routes::get(world, &network).is_some_and(|route| {
            route
                .revisions
                .values()
                .any(|revision| revision.activation != SccpRouteActivationV1::Retired)
        });
        if !relevant {
            return plan::DestinationProgress::Irrelevant;
        }
        // The active installed head is the authenticated finalized-time owner, including
        // TON (whose ordinary checkpoints need not be retained). Frozen/missing clients
        // block clearance. Wall-clock age and unfinalized headers are not L5 progress.
        store::light_clients::get(world, &network)
            .filter(|client| !client.is_frozen())
            .map_or(plan::DestinationProgress::Unavailable, |client| {
                plan::DestinationProgress::Finalized(client.head.latest_finalized.source_time_ms)
            })
    })
}

/// Apply L5 to at most 64 ended, uncleared generations in ascending order.
///
/// Every selected immutable owner is funded before the first map edit. Any local refusal
/// sticks to the enclosing transaction; its caller must abandon that whole transaction.
/// Events are emitted only after all selected admitted map writes succeed.
///
/// # Errors
/// Preserves original local owner/map refusal and refuses inconsistent retained source state.
pub(crate) fn clear_destinations(
    state: &mut StateTransaction<'_, '_>,
) -> Result<usize, BlockValidationError> {
    state
        .require_storage_admission()
        .map_err(BlockValidationError::StateStorageAdmission)?;
    let selected = plan::clearances(
        state
            .world
            .sccp_committee_generations
            .iter()
            .map(|(_, owner)| owner.record()),
        &destination_progress(&*state.world),
    )
    .map_err(|_| invariant(state, "non-ascending L5 generation source"))?;
    let lc = *state.world.sccp_liability_clock.get();
    let budget = state.execution_budget();
    let mut owners: [Option<Retained>; plan::MAX_CLEARANCE_VISITS] = std::array::from_fn(|_| None);
    for (slot, generation) in owners.iter_mut().zip(selected.as_slice()) {
        let Some(source) = state.world.sccp_committee_generations.get(generation) else {
            return Err(invariant(state, "selected L5 generation disappeared"));
        };
        *slot = Some(
            source
                .with_lifecycle(source.end, Some(lc), &budget)
                .map_err(|error| local_owner_error(state, error))?,
        );
    }
    for owner in owners.iter().flatten() {
        if let Err((_, original)) = state
            .world
            .sccp_committee_generations
            .try_insert_admitted(owner.generation, owner.clone())
        {
            let original = StateStorageAdmissionError::World(original);
            state.arm_local_storage_refusal(original.clone());
            return Err(BlockValidationError::StateStorageAdmission(original));
        }
    }
    for generation in selected.as_slice() {
        state
            .world
            .emit_events(Some(SccpEvent::GenerationDestinationCleared(
                SccpGenerationDestinationClearedV1 {
                    generation: *generation,
                    lc,
                },
            )));
    }
    Ok(selected.as_slice().len())
}

/// Run available pruning, then L5 after the generation/anchor post-execution step.
/// Missing native pruning custody is harmless retention, never `Invalid` or degradation.
///
/// # Errors
/// Returns an original sticky local storage/resource refusal; discard the enclosing transaction.
pub(crate) fn post_generation_work(
    state: &mut StateTransaction<'_, '_>,
) -> Result<(), BlockValidationError> {
    if store::parameters::get(&*state.world).is_none() {
        return Ok(());
    }
    match native_pruning_status() {
        NativePruningStatus::Deferred(_) => {}
    }
    light_clients::prune(state, MAX_LIGHT_CLIENT_DELETIONS_PER_BLOCK);
    clear_destinations(state)?;
    Ok(())
}

#[cfg(test)]
#[path = "prune_tests.rs"]
mod tests;
