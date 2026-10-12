//! Native G1/G2/G6/G7 owner preparation and admitted transaction publication.
//!
//! The retained schedule supplies original epoch credentials. Mutable key registrations and
//! legacy bridge rosters are never authority. Preparation leaves World untouched; a caller
//! must discard its entire transaction after any apply refusal, preserving current and undo.
//! The post-execution hook binds the G5 signing row to fixed X and the canonical result.
//! Destination launch still requires the separately tracked evidence and reconciliation owners.

use super::{
    committee_owner::{CommitteeOwnerError, RetainedSccpCommitteeGeneration as Retained},
    generation_error::SccpGenerationLocalError,
    generation_plan::{self, CurrentGeneration, GenerationPlan, HeightFacts},
    member_binding::resolve_generation_member,
};
use crate::state::{
    NativeExecutionTip, StateReadOnly, StateStorageAdmissionError, StateTransaction, WorldReadOnly,
};
use iroha_allocation::AllocationBudget;
use iroha_data_model::{
    NetworkId,
    nexus::PublicLaneValidatorRecord,
    parameter::system::ConsensusMode,
    sccp::{
        committee::{SccpGenerationCauseV1, SccpGenerationStartV1},
        events::{
            SccpCommitteeGenerationCreatedV1, SccpCommitteeResyncV1, SccpEvent,
            SccpFinalityDegradedReasonV1 as Degraded, SccpFinalityDegradedV1,
            SccpGenerationMemberUnslashableV1,
        },
        params::SccpParametersV1,
    },
    sumeragi::epoch::ValidatorEpochContextV1,
    sumeragi_finality::certified_result::context_committee_root,
};
use mv::storage::StorageReadOnly;

/// Exact local owner/storage failure is separate from deterministic degraded SCCP state.
#[derive(Debug, thiserror::Error)]
pub(crate) enum GenerationWriteError {
    /// Original finite custody refused an immutable owner.
    #[error(transparent)]
    Owner(#[from] CommitteeOwnerError),
    /// Original admitted map refused an edit; abandon the enclosing transaction.
    #[error(transparent)]
    Storage(#[from] mv::storage::AdmittedStorageError),
    /// Preparation was applied to a different original execution cut.
    #[error("native SCCP generation preparation does not belong to this execution cut")]
    SourceCut,
}

impl GenerationWriteError {
    pub(crate) fn into_block_error(self) -> crate::block::BlockValidationError {
        use crate::block::BlockValidationError;
        match self {
            Self::Storage(original) => BlockValidationError::StateStorageAdmission(
                StateStorageAdmissionError::World(original),
            ),
            Self::SourceCut => BlockValidationError::StateStorageAdmission(
                StateStorageAdmissionError::SccpGeneration(SccpGenerationLocalError::Invariant(
                    "generation source cut changed",
                )),
            ),
            Self::Owner(original) => match SccpGenerationLocalError::from_owner(&original) {
                Some(local) => BlockValidationError::StateStorageAdmission(
                    StateStorageAdmissionError::SccpGeneration(local),
                ),
                None => BlockValidationError::LocalStorageRecoveryRequired {
                    reason: format!("stored SCCP generation is inconsistent: {original}"),
                },
            },
        }
    }
}

/// A fixed-size plan retains at most three complete owners, all funded by one original pool.
pub(crate) struct PreparedGenerationStep {
    height: u64,
    timestamp_ms: u64,
    network: NetworkId,
    parameters: SccpParametersV1,
    source_schedule: crate::sumeragi::schedule::RetainedConsensusSchedule,
    degraded_run: u32,
    original: Option<Retained>,
    current: u64,
    lc: u64,
    rows: [Option<Retained>; 3],
    plan: Option<GenerationPlan>,
    degraded: Option<Degraded>,
}

fn creation(
    world: &(impl WorldReadOnly + ?Sized),
    start: SccpGenerationStartV1,
    parameters: &SccpParametersV1,
    epoch: &ValidatorEpochContextV1,
    budget: &AllocationBudget,
    require_all_members: bool,
) -> Result<Result<Retained, Degraded>, GenerationWriteError> {
    if !iroha_data_model::block::consensus::is_valid_committee_size(epoch.committee.len()) {
        return Ok(Err(Degraded::InvalidHeightInputs));
    }
    let mut members: [Option<&PublicLaneValidatorRecord>; 31] = [None; 31];
    for (index, seat) in epoch.committee.iter().enumerate() {
        let Ok(member) =
            resolve_generation_member(seat, start.height, world.public_lane_validators().iter())
        else {
            return Ok(Err(Degraded::InconsistentGenerationState));
        };
        if require_all_members && member.is_none() {
            return Ok(Err(Degraded::InconsistentGenerationState));
        }
        members[index] = member;
    }
    match Retained::admit_new(
        start,
        parameters,
        epoch,
        &members[..epoch.committee.len()],
        budget,
    ) {
        Ok(owner) => Ok(Ok(owner)),
        Err(CommitteeOwnerError::Invalid(
            iroha_data_model::sccp::committee::SccpGenerationError::Overflow,
        )) => Ok(Err(Degraded::ArithmeticOverflow)),
        Err(CommitteeOwnerError::Invalid(_)) => Ok(Err(Degraded::InvalidHeightInputs)),
        Err(local) => Err(local.into()),
    }
}

/// Create G1 only from the private token captured by signed-genesis execution.
pub(crate) fn prepare_genesis(
    world: &(impl WorldReadOnly + ?Sized),
    source: crate::sumeragi::schedule::SccpGenesisSource<'_>,
    parameters: &SccpParametersV1,
    network: NetworkId,
    timestamp_ms: u64,
    budget: &AllocationBudget,
) -> Result<Result<Retained, Degraded>, GenerationWriteError> {
    let epoch = source.epoch();
    if epoch.mode != ConsensusMode::Npos
        || epoch.network_id != network
        || world.sccp_committee_current() != 0
        || world.sccp_committee_generations().iter().next().is_some()
    {
        return Ok(Err(Degraded::InconsistentGenerationState));
    }
    creation(
        world,
        SccpGenerationStartV1 {
            generation: 1,
            cause: SccpGenerationCauseV1::Genesis,
            height: 1,
            timestamp_ms,
            liability_clock: timestamp_ms,
        },
        parameters,
        epoch,
        budget,
        true,
    )
}

/// Stage the already funded G1 owner. The caller stages parameters/nonce/escrows in this
/// same transaction and publishes only after every initialization obligation succeeds.
pub(crate) fn install_genesis(
    state: &mut StateTransaction<'_, '_>,
    owner: Retained,
    budget: &AllocationBudget,
) -> Result<(), GenerationWriteError> {
    if !owner.belongs_to(budget)
        || owner.generation != 1
        || owner.cause != SccpGenerationCauseV1::Genesis
        || owner.start_height != 1
        || owner.members.iter().any(Option::is_none)
        || *state.world.sccp_committee_current.get() != 0
        || state
            .world
            .sccp_committee_generations
            .iter()
            .next()
            .is_some()
    {
        state.arm_local_storage_refusal(StateStorageAdmissionError::SccpGeneration(
            SccpGenerationLocalError::Invariant("genesis generation source cut changed"),
        ));
        return Err(GenerationWriteError::SourceCut);
    }
    let lc = owner.start_lc;
    if let Err((_, original)) = state
        .world
        .sccp_committee_generations
        .try_insert_admitted(1, owner)
    {
        state.arm_local_storage_refusal(StateStorageAdmissionError::World(original.clone()));
        return Err(GenerationWriteError::Storage(original));
    }
    *state.world.sccp_committee_current.get_mut() = 1;
    *state.world.sccp_liability_clock.get_mut() = lc;
    *state.world.sccp_degraded_run.get_mut() = 0;
    Ok(())
}

/// Prepare a native post-execution transition without publishing any field or event.
pub(crate) fn prepare(
    world: &(impl WorldReadOnly + ?Sized),
    parameters: &SccpParametersV1,
    network: NetworkId,
    height: u64,
    timestamp_ms: u64,
    parent: Option<NativeExecutionTip>,
    inputs: Option<&super::height::SccpHeightInputsV1>,
    begin_failure: Option<Degraded>,
    budget: &AllocationBudget,
) -> Result<PreparedGenerationStep, GenerationWriteError> {
    let current = world.sccp_committee_current();
    let lc = world.sccp_liability_clock();
    let original = world.sccp_committee_generations().get(&current).cloned();
    let mut prepared = PreparedGenerationStep {
        height,
        timestamp_ms,
        network,
        parameters: *parameters,
        source_schedule: world.consensus_schedule().clone(),
        degraded_run: world.sccp_degraded_run(),
        original,
        current,
        lc,
        rows: [None, None, None],
        plan: None,
        degraded: None,
    };
    macro_rules! degraded {
        ($reason:expr) => {{
            prepared.degraded = Some($reason);
            return Ok(prepared);
        }};
    }
    if let Some(reason) = begin_failure {
        degraded!(reason);
    }
    let Some(original) = prepared.original.as_ref() else {
        degraded!(Degraded::MissingCurrentGeneration);
    };
    if !original.belongs_to(budget) {
        return Err(GenerationWriteError::SourceCut);
    }
    let Some(inputs) = inputs else {
        degraded!(Degraded::MissingHeightInputs);
    };
    if inputs.height() != height || !inputs.matches_source(world) {
        degraded!(Degraded::InvalidHeightInputs);
    }
    let Ok((epoch, next_epoch)) = inputs.epochs() else {
        degraded!(Degraded::InvalidHeightInputs);
    };
    let boundary = inputs.is_boundary();
    if epoch.network_id != network
        || next_epoch.network_id != network
        || epoch.mode != ConsensusMode::Npos
        || next_epoch.mode != ConsensusMode::Npos
        || height < epoch.authorization.first_height
        || height > epoch.authorization.last_height
    {
        degraded!(Degraded::InvalidHeightInputs);
    }
    let (Some(root), Some(next_root)) = (
        context_committee_root(epoch),
        context_committee_root(next_epoch),
    ) else {
        degraded!(Degraded::InvalidHeightInputs);
    };
    let record = original.record();
    let plan = match generation_plan::plan(
        CurrentGeneration {
            generation: record.generation,
            committee_root: record.committee_root,
            start_height: record.start_height,
            start_timestamp_ms: record.start_timestamp_ms,
            start_lc: record.start_lc,
            ended: record.end.is_some(),
        },
        HeightFacts {
            height,
            timestamp_ms,
            liability_clock: lc,
            committee_root: root,
            next_committee_root: next_root,
            boundary,
            parent: parent.map(|tip| (tip.height(), tip.creation_time_ms())),
            heartbeat_ms: parameters.committee_heartbeat_ms,
            validity_ms: parameters.committee_validity_ms,
        },
    ) {
        Ok(plan) => plan,
        Err(reason) => {
            degraded!(reason);
        }
    };
    let mut current_owner = original.clone();
    let mut index = 0;
    for (change, source) in [(plan.resync, epoch), (plan.rotation, next_epoch)] {
        let Some(change) = change else {
            continue;
        };
        let owner = match creation(world, change.start, parameters, source, budget, false)? {
            Ok(owner) => owner,
            Err(reason) => {
                degraded!(reason);
            }
        };
        let closed = current_owner.with_lifecycle(
            Some(change.end),
            current_owner.dest_cleared_lc,
            budget,
        )?;
        prepared.rows[index] = Some(closed);
        index += 1;
        current_owner = owner;
    }
    if index != 0 {
        prepared.rows[index] = Some(current_owner);
    }
    prepared.plan = Some(plan);
    Ok(prepared)
}

fn emit_created(state: &mut StateTransaction<'_, '_>, owner: &Retained) {
    let record = owner.record();
    let event = if record.cause == SccpGenerationCauseV1::Resync {
        SccpEvent::CommitteeResync(SccpCommitteeResyncV1 {
            generation: record.generation,
            committee_root: record.committee_root,
            start_height: record.start_height,
        })
    } else {
        SccpEvent::CommitteeGenerationCreated(SccpCommitteeGenerationCreatedV1 {
            generation: record.generation,
            cause: record.cause,
            committee_root: record.committee_root,
            start_height: record.start_height,
            deadline_ms: record.deadline_ms,
        })
    };
    state.world.emit_events(Some(event));
    for (index, member) in record.members.iter().enumerate() {
        if member.is_none() {
            state
                .world
                .emit_events(Some(SccpEvent::GenerationMemberUnslashable(
                    SccpGenerationMemberUnslashableV1 {
                        generation: record.generation,
                        index: index as u8,
                    },
                )));
        }
    }
}

impl PreparedGenerationStep {
    /// Stage complete funded records and matching events in one private transaction.
    /// Any refusal requires the caller to drop this transaction; no partial step may apply.
    pub(crate) fn apply(
        self,
        state: &mut StateTransaction<'_, '_>,
        budget: &AllocationBudget,
    ) -> Result<Option<u64>, GenerationWriteError> {
        if state._curr_block.height().get() != self.height
            || state._curr_block.creation_time_ms != self.timestamp_ms
            || *state.network_id() != self.network
            || *state.world.sccp_parameters.get() != Some(self.parameters)
            || *state.world.sccp_degraded_run.get() != self.degraded_run
            || !std::ptr::eq(
                self.source_schedule.canonical(),
                state.world.consensus_schedule().canonical(),
            )
            || *state.world.sccp_committee_current.get() != self.current
            || *state.world.sccp_liability_clock.get() != self.lc
            || match (
                self.original.as_ref(),
                state.world.sccp_committee_generations.get(&self.current),
            ) {
                (Some(original), Some(actual)) => !std::ptr::eq(original.record(), actual.record()),
                (None, None) => false,
                _ => true,
            }
        {
            state.arm_local_storage_refusal(StateStorageAdmissionError::SccpGeneration(
                SccpGenerationLocalError::Invariant("generation preparation source cut changed"),
            ));
            return Err(GenerationWriteError::SourceCut);
        }
        if let Some(reason) = self.degraded {
            *state.world.sccp_degraded_run.get_mut() =
                state.world.sccp_degraded_run.get().saturating_add(1);
            state
                .world
                .emit_events(Some(SccpEvent::FinalityDegraded(SccpFinalityDegradedV1 {
                    height: self.height,
                    reason,
                })));
            return Ok(None);
        }
        let Some(plan) = self.plan else {
            state.arm_local_storage_refusal(StateStorageAdmissionError::SccpGeneration(
                SccpGenerationLocalError::Invariant("missing generation plan"),
            ));
            return Err(GenerationWriteError::SourceCut);
        };
        if self
            .rows
            .iter()
            .flatten()
            .any(|owner| !owner.belongs_to(budget))
        {
            state.arm_local_storage_refusal(StateStorageAdmissionError::SccpGeneration(
                SccpGenerationLocalError::Invariant("foreign generation owner pool"),
            ));
            return Err(GenerationWriteError::SourceCut);
        }
        for owner in self.rows.iter().flatten() {
            if let Err((_, original)) = state
                .world
                .sccp_committee_generations
                .try_insert_admitted(owner.generation, owner.clone())
            {
                state
                    .arm_local_storage_refusal(StateStorageAdmissionError::World(original.clone()));
                return Err(GenerationWriteError::Storage(original));
            }
        }
        for owner in self
            .rows
            .iter()
            .flatten()
            .filter(|owner| owner.generation > self.current)
        {
            emit_created(state, owner);
        }
        *state.world.sccp_committee_current.get_mut() = plan
            .rotation
            .map_or(plan.signing_generation, |change| change.start.generation);
        *state.world.sccp_degraded_run.get_mut() = 0;
        Ok(Some(plan.signing_generation))
    }
}

#[cfg(test)]
#[path = "generation/tests.rs"]
mod tests;
