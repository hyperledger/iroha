//! Original-prestate capture and atomic native epoch application inside the output seal.

use super::{ChainParamsRecord, NativeExecutionInputs, ScheduleError};
use crate::{
    execution_attempt::ExecutionAttemptError,
    state::{
        BlockHashRead, GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, StateBlock, StateReadOnly,
        WorldReadOnly,
    },
    sumeragi::{
        epoch_beacon,
        epoch_election::{self, FrozenEpochBoundary},
    },
};
use iroha_allocation::RetainedPayload;
use iroha_data_model::{
    block::SignedBlock,
    consensus::{FinalizedGlobalThresholdBeaconPulseV1, GlobalThresholdBeaconPulseContextV1},
};
use mv::storage::StorageReadOnly;
use std::fmt;

/// A sealed original capture stays alive through every local post-execution refusal.
pub(crate) enum CapturedExecution {
    Boundary(FrozenEpochBoundary),
    Ordinary(RetainedPayload<NativeExecutionInputs>),
}
impl CapturedExecution {
    fn inputs(&self) -> &NativeExecutionInputs {
        match self {
            Self::Boundary(boundary) => boundary.execution_inputs(),
            Self::Ordinary(inputs) => inputs.get(),
        }
    }
    #[allow(
        unsafe_code,
        reason = "moves the unchanged retained canonical graph and assigns only fixed-size fields"
    )]
    #[expect(
        clippy::large_types_passed_by_value,
        reason = "the pulse is transferred into the retained native execution inputs"
    )]
    fn finish(
        self,
        params: ChainParamsRecord,
        pulse: Option<FinalizedGlobalThresholdBeaconPulseV1>,
    ) -> RetainedPayload<NativeExecutionInputs> {
        match self {
            Self::Boundary(boundary) => boundary.into_execution_inputs(params, pulse),
            Self::Ordinary(inputs) => {
                // SAFETY: every original nested allocation moves unchanged. Only fixed-size
                // post-state lag-two parameters and verified pulse fields are assigned.
                unsafe {
                    inputs.map_payload(|mut inputs| {
                        if inputs.schedule.height == 1 {
                            set_params(&mut inputs.schedule.next, params);
                        }
                        set_params(&mut inputs.schedule.after_next, params);
                        inputs.beacon = pulse;
                        inputs
                    })
                }
            }
        }
    }
}
fn set_params(slot: &mut super::ScheduledSlot, next: ChainParamsRecord) {
    match slot {
        super::ScheduledSlot::Ready(config) => config.params = next,
        super::ScheduledSlot::PendingBoundary { params, .. } => *params = next,
    }
}

/// One native block's sealed schedule lifecycle. The original owner is never recreated on retry.
#[derive(Default)]
pub(crate) enum ScheduleStep {
    /// This overlay has no native consensus execution request.
    #[default]
    Off,
    /// Captured from the exact pristine original State before block-start or transaction effects.
    Requested {
        /// Original complete context, guards and same-pool nested allocations.
        captured: CapturedExecution,
        /// Original root scope authenticated before transaction effects, retained on retry.
        root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
        /// Fixed-width transported proof authenticated against that same original cut.
        pulse: epoch_beacon::VerifiedEpochPulse,
    },
    /// Exact canonical inputs moved into the result after all finalizer checks succeeded.
    Done(RetainedPayload<NativeExecutionInputs>),
}
impl fmt::Debug for ScheduleStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => f.write_str("Off"),
            Self::Requested { captured, .. } => f
                .debug_tuple("Requested")
                .field(&captured.inputs().schedule.height)
                .finish(),
            Self::Done(inputs) => f
                .debug_tuple("Done")
                .field(&inputs.get().schedule.height)
                .finish(),
        }
    }
}
impl ScheduleStep {
    /// Borrow the scope authenticated for this exact uncompleted native execution.
    /// An absent or completed request cannot grant block-start lifecycle authority.
    pub(crate) fn original_root_scope(
        &self,
    ) -> Option<iroha_data_model::block::consensus::SumeragiRootScope> {
        match self {
            Self::Requested { root_scope, .. } => Some(*root_scope),
            Self::Off | Self::Done(_) => None,
        }
    }
    /// Fixed authenticated pulse from this original global execution, before finalization.
    /// Consensus verifies it at the pre-boundary carrying height; the committee
    /// boundary itself is one block later. Lanes and absent/completed captures
    /// cannot grant a panel draw, and ordinary heights carry no verified pulse.
    pub(crate) fn original_native_pulse(&self) -> Option<FinalizedGlobalThresholdBeaconPulseV1> {
        match self {
            Self::Requested {
                captured,
                root_scope: iroha_data_model::block::consensus::SumeragiRootScope::Global,
                pulse,
            } => {
                if cfg!(all(test, sumeragi_core_mutation = "HC303"))
                    && !matches!(captured, CapturedExecution::Boundary(_))
                {
                    return None;
                }
                pulse.pulse()
            }
            _ => None,
        }
    }
    /// Borrow the original signed genesis authority before any transaction effects.
    /// The completed or absent lifecycle cannot grant initialization authority.
    pub(crate) fn original_genesis_context(
        &self,
    ) -> Option<&iroha_data_model::sumeragi::epoch::ValidatorEpochContextV1> {
        match self {
            Self::Requested {
                captured,
                root_scope: iroha_data_model::block::consensus::SumeragiRootScope::Global,
                ..
            } if captured.inputs().schedule.height == 1 => {
                Some(&captured.inputs().schedule.current)
            }
            _ => None,
        }
    }
    pub(crate) fn frozen_boundary(&self) -> Option<&FrozenEpochBoundary> {
        match self {
            Self::Requested {
                captured: CapturedExecution::Boundary(boundary),
                ..
            } => Some(boundary),
            _ => None,
        }
    }
}

/// Authenticate a successor's original native context at one committed State cut.
/// Reused before event attribution and by the pristine writer before schedule effects.
pub(crate) fn authenticate_successor_context(
    state: &(impl StateReadOnly + ?Sized),
    header: &iroha_data_model::block::BlockHeader,
    expected: &GlobalThresholdBeaconPulseContextV1,
) -> Result<(), ExecutionAttemptError<ScheduleError>> {
    let height = header.height().get();
    if height <= 1
        || u64::try_from(state.block_hashes().hash_count())
            .ok()
            .and_then(|cut| cut.checked_add(1))
            != Some(height)
        || header.prev_block_hash()
            != state
                .block_hashes()
                .hash_count()
                .checked_sub(1)
                .and_then(|index| state.block_hashes().hash_at(index))
                .copied()
    {
        return Err(ScheduleError::Epoch(
            "native successor differs from its original committed header/parent cut".into(),
        )
        .into());
    }
    // Canonical committed reads exclude differences in local QC signer subsets.
    let parent = crate::sumeragi::certified_chain::committed_block(state, height - 1)
        .map_err(|error| error.map_rejection(ScheduleError::from))?;
    // The executed parent above supplies original current R. Root identity needs
    // only this cut's independently authenticated durable signed genesis, never
    // its unsigned result-only preimage or another full historical reverse walk.
    #[cfg(all(test, sumeragi_core_mutation = "HC139"))]
    let instance = {
        let genesis = crate::sumeragi::certified_chain::committed_block(state, 1)
            .map_err(|error| error.map_rejection(ScheduleError::from))?;
        crate::sumeragi::node::root_instance(genesis.block(), &state.chain_id().to_string())
            .map_err(|error| error.map_rejection(ScheduleError::Epoch))?
    };
    #[cfg(not(all(test, sumeragi_core_mutation = "HC139")))]
    let instance = crate::sumeragi::certified_chain::CertifiedChain::new(state)
        .map_err(|error| error.map_rejection(ScheduleError::from))?
        .instance();
    let current = &state.world().consensus_schedule().ready(height)?.epoch;
    expected
        .validate()
        .map_err(|error| ScheduleError::Epoch(error.into()))?;
    if expected.instance != instance.0
        || expected.parent_consensus_hash != parent.core_hash().0
        || expected.parent_result != parent.result().0
        || expected.epoch != current.authorization.epoch
        || expected.epoch_context_id != current.context_id().map_err(ScheduleError::Epoch)?
    {
        return Err(ScheduleError::Epoch(
            "native control differs from the pristine committed instance/parent/result/epoch"
                .into(),
        )
        .into());
    }
    Ok(())
}

impl StateBlock<'_> {
    /// Capture the exact authenticated source in the pristine constructor callback, after
    /// source-generation/header validation and before any schedule or execution effect.
    /// Missing mandatory transported beacon work is refused; local aggregation is irrelevant.
    #[expect(
        clippy::large_types_passed_by_value,
        reason = "the supplied pulse is validated and transferred into the retained native schedule result"
    )]
    pub(crate) fn request_sumeragi_schedule(
        &mut self,
        genesis_height: u64,
        source: &SignedBlock,
        supplied_pulse: Option<FinalizedGlobalThresholdBeaconPulseV1>,
        expected_context: Option<GlobalThresholdBeaconPulseContextV1>,
    ) -> Result<(), ExecutionAttemptError<ScheduleError>> {
        if !matches!(self.sumeragi_schedule, ScheduleStep::Off) {
            return Err(
                ScheduleError::Epoch("native schedule capture already exists".into()).into(),
            );
        }
        let height = self._curr_block.height().get();
        if genesis_height != 1
            || source.header() != self._curr_block
            || u64::try_from(self.block_hashes().hash_count())
                .ok()
                .and_then(|cut| cut.checked_add(1))
                != Some(height)
            || source.header().prev_block_hash()
                != self
                    .block_hashes()
                    .hash_count()
                    .checked_sub(1)
                    .and_then(|index| self.block_hashes().hash_at(index))
                    .copied()
        {
            return Err(ScheduleError::Epoch(
                "native schedule request differs from its pristine original header/parent cut"
                    .into(),
            )
            .into());
        }
        if height == genesis_height {
            if expected_context.is_some() || supplied_pulse.is_some() {
                return Err(ScheduleError::Epoch(
                    "signed genesis cannot carry native successor control".into(),
                )
                .into());
            }
        } else {
            let expected = expected_context.as_ref().ok_or_else(|| {
                ScheduleError::Epoch(
                    "native successor lacks its authenticated header context".into(),
                )
            })?;
            authenticate_successor_context(self, &self._curr_block, expected)?;
        }
        let root_scope = if height == genesis_height {
            iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(source)
                .map_err(|error| {
                    crate::execution_attempt::genesis_read_attempt_error(error, |error| {
                        ScheduleError::Epoch(error.to_string())
                    })
                })?
                .sumeragi_context
                .root_scope
        } else {
            crate::sumeragi::lanes::routing::committed_root_scope(&self.world).ok_or_else(|| {
                ScheduleError::Epoch("native control requires immutable root scope".into())
            })?
        };
        let budget = self.pipeline_ivm_prepared_cache.execution_budget();
        let params = ChainParamsRecord::from_parameters(self.world.parameters().sumeragi());
        let (captured, pulse) = if height == genesis_height {
            if !self.world.consensus_schedule().entries().is_empty() {
                return Err(ScheduleError::Epoch(
                    "genesis cannot replace retained native authority".into(),
                )
                .into());
            }
            let epoch = crate::sumeragi::epoch::authenticated_genesis(source)
                .map(|genesis| genesis.into_parts().0)
                .map_err(|error| {
                    crate::execution_attempt::genesis_read_attempt_error(error, |error| {
                        ScheduleError::Epoch(error.to_string())
                    })
                })?;
            let pulse = epoch_beacon::capture(
                root_scope,
                &self.world,
                self.block_hashes(),
                &epoch,
                height,
                supplied_pulse,
                expected_context,
            )
            .map_err(ScheduleError::Epoch)?;
            let inputs = epoch_election::capture_continuation(&epoch, height, None, params, budget)
                .map_err(ScheduleError::from)?;
            (CapturedExecution::Ordinary(inputs), pulse)
        } else {
            let schedule = self.world.consensus_schedule();
            if schedule.tip().and_then(|tip| tip.checked_add(1)) != Some(height) {
                return Err(ScheduleError::Malformed.into());
            }
            let current = &schedule.ready(height)?.epoch;
            let pulse = epoch_beacon::capture(
                root_scope,
                &self.world,
                self.block_hashes(),
                current,
                height,
                supplied_pulse,
                expected_context,
            )
            .map_err(ScheduleError::Epoch)?;
            let captured = if current.mode
                == iroha_data_model::parameter::system::ConsensusMode::Npos
                && height == current.authorization.last_height
            {
                let parameters = self
                    .world
                    .sumeragi_npos_parameters()
                    .map_err(|error| error.map_rejection(ScheduleError::Epoch))?
                    .ok_or_else(|| {
                        ScheduleError::Epoch("boundary lacks signed NPoS policy".into())
                    })?;
                let policy =
                    iroha_data_model::nexus::ValidatorElectionPolicyV1::from_npos_parameters(
                        &parameters,
                    )
                    .map_err(ScheduleError::Epoch)?;
                let frozen = epoch_election::freeze_boundary(
                    &self.world,
                    self.block_hashes(),
                    current,
                    &policy,
                    height,
                    budget,
                )
                .map_err(boundary_capture_attempt_error)?
                .ok_or_else(|| {
                    ScheduleError::Epoch("required native boundary was not captured".into())
                })?;
                CapturedExecution::Boundary(frozen)
            } else {
                CapturedExecution::Ordinary(
                    epoch_election::capture_continuation(
                        current,
                        height,
                        schedule.get(height.checked_add(1).ok_or(ScheduleError::HeightOverflow)?),
                        params,
                        budget,
                    )
                    .map_err(ScheduleError::from)?,
                )
            };
            (captured, pulse)
        };
        // All source/proof/custody and complete retained allocation checks preceded any write.
        // This consensus-native pulse is a mandatory original block-start effect. Stored here, it
        // is readable by later transactions of this same block (governance consumes it by its
        // own transition and never demands it); failure/drop discards its journal with the block.
        if let (Some(value), Some(link)) = (pulse.pulse(), pulse.link()) {
            let slot = (
                iroha_data_model::governance::types::BeaconSessionId::for_network_v1(
                    &value.network_id,
                ),
                value.height,
            );
            self.world
                .global_beacon_pulses
                .insert(value.pulse_id, value);
            self.world
                .global_beacon_pulse_slots
                .insert(slot, value.pulse_id);
            self.world
                .global_beacon_latest_pulse
                .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, link);
        }
        self.sumeragi_schedule = ScheduleStep::Requested {
            captured,
            pulse,
            root_scope,
        };
        Ok(())
    }

    /// Finalize within the exact original output seal. Every fallible preparation precedes
    /// writes; a local refusal restores the same capture for retry instead of recomputation.
    pub(crate) fn advance_requested_sumeragi_schedule(
        &mut self,
    ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ScheduleError>> {
        let step = std::mem::take(&mut self.sumeragi_schedule);
        let ScheduleStep::Requested {
            captured,
            pulse,
            root_scope,
        } = step
        else {
            self.sumeragi_schedule = step;
            return Ok(());
        };
        let prepare = (|| {
            let source = &captured.inputs().schedule;
            let params = ChainParamsRecord::from_parameters(self.world.parameters().sumeragi());
            params.validate().map_err(ScheduleError::Params)?;
            let current_params = if source.height == 1 {
                validate_executed_genesis(&self.world, &source.current)?;
                params
            } else {
                crate::resource_coherence::validate_final_policy(&self.world, source.height)
                    .map_err(|error| ScheduleError::Epoch(error.to_string()))?;
                self.world.consensus_schedule().ready(source.height)?.params
            };
            let graph = epoch_election::retain_outcome_schedule(
                source,
                current_params,
                params,
                self.pipeline_ivm_prepared_cache.execution_budget(),
            )
            .map_err(boundary_capture_attempt_error)?;
            if let CapturedExecution::Boundary(boundary) = &captured {
                self.finalize_validator_committee_boundary(boundary)
                    .map_err(|error| error.map_rejection(ScheduleError::Epoch))?;
            }
            Ok::<_, crate::execution_attempt::ExecutionAttemptError<ScheduleError>>((graph, params))
        })();
        match prepare {
            Err(error) => {
                self.sumeragi_schedule = ScheduleStep::Requested {
                    captured,
                    pulse,
                    root_scope,
                };
                Err(error)
            }
            Ok((graph, params)) => {
                *self.world.consensus_schedule.get_mut() = graph;
                self.sumeragi_schedule = ScheduleStep::Done(captured.finish(params, pulse.pulse()));
                Ok(())
            }
        }
    }

    /// Move the exact canonical fields and original allocation ledger into execution-result
    /// custody. The result builder retains this owner across validation, publication and replay.
    pub(crate) fn take_sumeragi_execution_inputs(
        &mut self,
    ) -> Result<RetainedPayload<NativeExecutionInputs>, ScheduleError> {
        let step = std::mem::take(&mut self.sumeragi_schedule);
        match step {
            ScheduleStep::Done(inputs) => Ok(inputs),
            other => {
                self.sumeragi_schedule = other;
                Err(ScheduleError::NotAdvanced)
            }
        }
    }
}

/// Retain local boundary refusal evidence before projecting deterministic schedule failures.
fn boundary_capture_attempt_error(
    error: impl Into<
        crate::execution_attempt::ExecutionAttemptError<epoch_election::BoundaryCaptureError>,
    >,
) -> crate::execution_attempt::ExecutionAttemptError<ScheduleError> {
    use crate::execution_attempt::ExecutionAttemptError;
    let error = match error.into() {
        ExecutionAttemptError::Deferred(reason) => return ExecutionAttemptError::Deferred(reason),
        ExecutionAttemptError::Rejected(error) => error,
    };
    match error {
        epoch_election::BoundaryCaptureError::Admission(refusal) => {
            ExecutionAttemptError::Deferred(refusal.into())
        }
        epoch_election::BoundaryCaptureError::Allocator { .. } => ExecutionAttemptError::Deferred(
            ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
        ),
        epoch_election::BoundaryCaptureError::Invalid(message) => {
            ExecutionAttemptError::Rejected(ScheduleError::Epoch(message))
        }
    }
}

/// Reconcile signed genesis authority with the actual executed registration state. Later
/// epochs deliberately do not reread mutable validity when retaining original credentials.
pub(crate) fn validate_executed_genesis(
    world: &impl WorldReadOnly,
    context: &iroha_data_model::sumeragi::epoch::ValidatorEpochContextV1,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<ScheduleError>> {
    use iroha_data_model::{consensus::ConsensusKeyRole, parameter::system::ConsensusMode};
    context.validate().map_err(ScheduleError::Epoch)?;
    iroha_data_model::parameter::system::validate_max_clock_drift_ms(
        world.parameters().sumeragi().max_clock_drift_ms(),
    )
    .map_err(|error| ScheduleError::Epoch(error.to_string()))?;
    crate::smartcontracts::isi::sccp::keepalive::clock_parameters(world)
        .map_err(|error| ScheduleError::Epoch(error.into()))?;
    crate::resource_coherence::validate_final_policy(world, 1)
        .map_err(|error| ScheduleError::Epoch(error.to_string()))?;
    crate::executor::private_fees::policy(world).map_err(|error| {
        error.map_rejection(|error| {
            ScheduleError::Epoch(format!(
                "executed genesis fee policy is invalid: {}",
                error.reason()
            ))
        })
    })?;
    if context.authorization.epoch != 0 || context.authorization.first_height != 1 {
        return Err(ScheduleError::Epoch("executed genesis has a non-genesis epoch".into()).into());
    }
    for member in &context.committee {
        if !world.peers().iter().any(|peer| peer == &member.validator)
            || !world.consensus_keys().iter().any(|(id, record)| {
                id == &record.id
                    && id.role == ConsensusKeyRole::Validator
                    && record.public_key == *member.validator.public_key()
                    && record.is_live_at(1, 0, 0)
                    && record.pop.as_deref() == Some(member.proof_of_possession.as_slice())
            })
        {
            return Err(ScheduleError::Epoch(
                "executed genesis omits an exact signed validator registration".into(),
            )
            .into());
        }
    }
    for peer in world.peers().iter() {
        if world.consensus_keys().iter().any(|(id, record)| {
            id == &record.id
                && id.role == ConsensusKeyRole::Validator
                && record.public_key == *peer.public_key()
                && record.is_live_at(1, 0, 0)
        }) && !context
            .committee
            .iter()
            .any(|member| &member.validator == peer)
        {
            return Err(ScheduleError::Epoch(
                "executed genesis introduces an unsigned voting registration".into(),
            )
            .into());
        }
    }
    if context.mode == ConsensusMode::Npos {
        let parameters = world
            .sumeragi_npos_parameters()
            .map_err(|error| error.map_rejection(ScheduleError::Epoch))?
            .ok_or_else(|| {
                ScheduleError::Epoch("executed NPoS genesis omits signed parameters".into())
            })?;
        if parameters.epoch_length_blocks.get() != context.authorization.last_height
            || parameters.epoch_seed != context.leader_seed
        {
            return Err(ScheduleError::Epoch(
                "executed genesis changes signed epoch geometry or seed".into(),
            )
            .into());
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "execution_tests.rs"]
mod tests;
