//! Authenticated SCCP generation transitions and destination progress (§4.2, §4.8).
//!
//! Planning borrows the original committee and staking registrations and admits every new
//! immutable payload before publishing lifecycle writes. A structural inconsistency degrades
//! SCCP only; original local refusals stay retryable and never become invalid blocks.

use super::{
    generation_record::{GenerationRecordError, MemberRef, RetainedSccpGeneration},
    height::SccpHeightInputsV1,
    store,
};
use crate::{
    execution_attempt::{ExecutionAttemptError, ExecutionDeferred, norito_decode_attempt_error},
    state::{
        StateReadOnly, StateTransaction, WorldReadOnly, public_lane_validator_record_matches_key,
    },
};
use iroha_allocation::{AllocationBudget, AllocationRefusal, AllocationReservation};
use iroha_data_model::{
    block::BlockHeader,
    parameter::system::ConsensusMode,
    sccp::{
        events::{
            SccpCommitteeGenerationCreatedV1, SccpCommitteeResyncV1, SccpEvent,
            SccpFinalityDegradedReasonV1 as Degraded, SccpGenerationDestinationClearedV1,
            SccpGenerationMemberUnslashableV1,
        },
        generation::{SccpCommitteeGenerationV1, SccpGenerationCauseV1, SccpGenerationEndV1},
        params::{SCCP_MIN_EPOCH_MS_V1, SccpParametersV1},
        registry::SccpRouteActivationV1,
    },
    sumeragi_finality::certified_result::committee_root,
};
use iroha_model_base::peer::PeerId;
use ivm::error::ExecutionDeferral;
use mv::storage::StorageReadOnly;

/// Whether the proposed chain timing meets the SCCP generation-rate guard (§4.2.2).
#[must_use]
pub fn epoch_duration_is_valid(epoch_length_blocks: u64, block_cadence_ms: u64) -> bool {
    epoch_length_blocks.saturating_mul(block_cadence_ms) >= SCCP_MIN_EPOCH_MS_V1
}

/// Distinguish fail-closed SCCP state from retryable original local resource failure.
#[derive(Debug)]
pub(super) enum GenerationError {
    Degraded(Degraded),
    Deferred(ExecutionDeferred),
}
impl From<GenerationRecordError> for GenerationError {
    fn from(error: GenerationRecordError) -> Self {
        match error {
            GenerationRecordError::Invalid(_) => Self::Degraded(Degraded::InvalidGeneration),
            GenerationRecordError::Admission(original) => Self::Deferred(original.into()),
            GenerationRecordError::Allocator { .. } => {
                Self::Deferred(ExecutionDeferral::AllocationUnavailable.into())
            }
            GenerationRecordError::Account(error) => {
                match norito_decode_attempt_error(error, |_| ()) {
                    ExecutionAttemptError::Deferred(original) => Self::Deferred(original),
                    ExecutionAttemptError::Rejected(()) => {
                        Self::Degraded(Degraded::InvalidGeneration)
                    }
                }
            }
        }
    }
}

/// Fixed scratch for at most the protocol's 31 original voting peers; no copied peer graph.
struct Committee<'a> {
    peers: [Option<&'a PeerId>; 31],
    keys: [[u8; 48]; 31],
    len: usize,
    root: [u8; 32],
}
impl<'a> Committee<'a> {
    fn read(peers: impl IntoIterator<Item = &'a PeerId>) -> Result<Self, GenerationError> {
        let mut out = Self {
            peers: [None; 31],
            keys: [[0; 48]; 31],
            len: 0,
            root: [0; 32],
        };
        for peer in peers {
            let Some(slot) = out.keys.get_mut(out.len) else {
                return Err(GenerationError::Degraded(Degraded::InvalidInputs));
            };
            let (algorithm, bytes) = peer
                .public_key()
                .try_to_bytes()
                .map_err(|_| GenerationError::Degraded(Degraded::InvalidInputs))?;
            if algorithm != iroha_crypto::Algorithm::BlsNormal {
                return Err(GenerationError::Degraded(Degraded::InvalidInputs));
            }
            *slot = bytes
                .try_into()
                .map_err(|_| GenerationError::Degraded(Degraded::InvalidInputs))?;
            out.peers[out.len] = Some(peer);
            out.len += 1;
        }
        if !iroha_data_model::block::consensus::is_valid_committee_size(out.len)
            || !out.keys[..out.len].is_sorted_by(|a, b| a < b)
        {
            return Err(GenerationError::Degraded(Degraded::InvalidInputs));
        }
        out.root = committee_root(&out.keys[..out.len])
            .ok_or(GenerationError::Degraded(Degraded::InvalidInputs))?;
        Ok(out)
    }
}

/// Same registration identity, active root lane and inclusive activation/exclusive exit
/// predicates as the penalty pipeline, evaluated at the new generation's start height.
/// Registrations are borrowed from the original State at executing h, including a handoff
/// to h + 1. More than one qualifying registration is unresolved:
/// no map iteration order may choose who bears another registration's liability.
fn member_for_peer<'a>(
    stx: &'a StateTransaction<'_, '_>,
    peer: &PeerId,
    height: u64,
) -> Option<MemberRef<'a>> {
    let mut matches = stx
        .world
        .public_lane_validators()
        .iter()
        .filter(|(key, record)| {
            &record.peer_id == peer
                && public_lane_validator_record_matches_key(key, record)
                && stx.is_lane_active_for_authority(record.lane_id)
                && stx.staking_authority_lane(record.lane_id) == Some(record.lane_id)
                && record.activation_height <= height
                && record.deactivation_height.is_none_or(|end| height < end)
        });
    let (_, first) = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(MemberRef {
        lane_id: first.lane_id,
        validator: &first.validator,
        activation_height: first.activation_height,
    })
}

#[derive(Clone, Copy)]
struct Creation {
    generation: u64,
    cause: SccpGenerationCauseV1,
    start_height: u64,
    timestamp_ms: u64,
    liability_clock: u64,
}
struct RecordDraft<'a> {
    metadata: SccpCommitteeGenerationV1,
    keys: [[u8; 48]; 31],
    members: [Option<MemberRef<'a>>; 31],
    len: usize,
}
impl RecordDraft<'_> {
    fn demand(&self) -> Result<usize, GenerationError> {
        RetainedSccpGeneration::allocation_demand(&self.keys[..self.len], &self.members[..self.len])
            .map_err(Into::into)
    }
    fn materialize(
        self,
        budget: &AllocationBudget,
        reservation: &mut AllocationReservation,
    ) -> Result<RetainedSccpGeneration, GenerationError> {
        RetainedSccpGeneration::from_members_prepaid(
            &self.metadata,
            &self.keys[..self.len],
            &self.members[..self.len],
            budget,
            reservation,
        )
        .map_err(Into::into)
    }
}
#[cfg(test)]
fn prepare_record(
    stx: &StateTransaction<'_, '_>,
    committee: &Committee<'_>,
    creation: Creation,
    parameters: &SccpParametersV1,
) -> Result<RetainedSccpGeneration, GenerationError> {
    let draft = draft_record(stx, committee, creation, parameters)?;
    let budget = stx.execution_budget();
    let mut reservation = budget
        .try_reserve_bytes(draft.demand()?)
        .map_err(|e| GenerationError::Deferred(e.into()))?;
    draft.materialize(&budget, &mut reservation)
}
fn draft_record<'a>(
    stx: &'a StateTransaction<'_, '_>,
    committee: &Committee<'_>,
    creation: Creation,
    parameters: &SccpParametersV1,
) -> Result<RecordDraft<'a>, GenerationError> {
    let mut members = [None; 31];
    for (slot, peer) in members.iter_mut().zip(&committee.peers[..committee.len]) {
        *slot = member_for_peer(
            stx,
            peer.expect("filled original committee slot"),
            if cfg!(all(test, sumeragi_core_mutation = "HC230")) {
                stx._curr_block.height().get()
            } else {
                creation.start_height
            },
        );
    }
    let metadata = SccpCommitteeGenerationV1 {
        generation: creation.generation,
        committee_root: committee.root,
        keys: Vec::new(),
        members: Vec::new(),
        cause: creation.cause,
        start_height: creation.start_height,
        start_timestamp_ms: creation.timestamp_ms,
        start_lc: creation.liability_clock,
        validity_ms: parameters.committee_validity_ms,
        deadline_ms: creation
            .timestamp_ms
            .saturating_add(parameters.committee_validity_ms),
        grace_ms: parameters.forgery_evidence_grace_ms,
        progress_cap_ms: parameters.destination_progress_cap_ms,
        liable_until_lc: creation
            .liability_clock
            .saturating_add(parameters.committee_validity_ms)
            .saturating_add(parameters.forgery_evidence_grace_ms),
        dest_cleared_lc: None,
        end: None,
    };
    let out = RecordDraft {
        metadata,
        keys: committee.keys,
        members,
        len: committee.len,
    };
    // Structural checks happen without constructing a payload. The canonical retained
    // constructor repeats its complete validation before any record can be published.
    if creation.generation == 0
        || creation.start_height == 0
        || creation.liability_clock > creation.timestamp_ms
        || (creation.generation == 1) != (creation.cause == SccpGenerationCauseV1::Genesis)
    {
        return Err(GenerationError::Degraded(Degraded::InvalidGeneration));
    }
    Ok(out)
}

/// Prepare G1 from the original authenticated, pre-transaction genesis context.
pub(super) fn prepare_genesis(
    stx: &StateTransaction<'_, '_>,
    parameters: &SccpParametersV1,
) -> Result<RetainedSccpGeneration, GenerationError> {
    let context = stx
        .native_genesis_context
        .ok_or(GenerationError::Degraded(Degraded::MissingInputs))?;
    if !stx._curr_block.is_genesis()
        || context.mode != ConsensusMode::Npos
        || !store::committee_generations::is_empty(&*stx.world)
        || *store::committee_current::get(&*stx.world) != 0
    {
        return Err(GenerationError::Degraded(Degraded::InvalidInputs));
    }
    let committee = Committee::read(context.committee.iter().map(|member| &member.validator))?;
    let time = timestamp_ms(&stx._curr_block);
    let draft = draft_record(
        stx,
        &committee,
        Creation {
            generation: 1,
            cause: SccpGenerationCauseV1::Genesis,
            start_height: stx._curr_block.height().get(),
            timestamp_ms: time,
            liability_clock: time,
        },
        parameters,
    )?;
    RetainedSccpGeneration::from_members(
        &draft.metadata,
        &draft.keys[..draft.len],
        &draft.members[..draft.len],
        &stx.execution_budget(),
    )
    .map_err(Into::into)
}

fn created_events(
    stx: &mut StateTransaction<'_, '_>,
    generation: &RetainedSccpGeneration,
    resync: bool,
) {
    if resync {
        stx.world
            .emit_events(Some(SccpEvent::CommitteeResync(SccpCommitteeResyncV1 {
                generation: generation.generation,
                committee_root: generation.committee_root,
                start_height: generation.start_height,
            })));
    } else {
        stx.world
            .emit_events(Some(SccpEvent::CommitteeGenerationCreated(
                SccpCommitteeGenerationCreatedV1 {
                    generation: generation.generation,
                    cause: generation.cause,
                    committee_root: generation.committee_root,
                    start_height: generation.start_height,
                    deadline_ms: generation.deadline_ms,
                },
            )));
    }
    for (index, member) in generation.members.iter().enumerate() {
        if member.is_none() {
            stx.world
                .emit_events(Some(SccpEvent::GenerationMemberUnslashable(
                    SccpGenerationMemberUnslashableV1 {
                        generation: generation.generation,
                        index: u8::try_from(index).expect("at most 31 members"),
                    },
                )));
        }
    }
}

/// Publish the already funded G1 in the same initialization transaction.
pub(super) fn install_genesis(
    stx: &mut StateTransaction<'_, '_>,
    generation: RetainedSccpGeneration,
) {
    store::liability_clock::set(stx, generation.start_lc);
    store::committee_current::set(stx, generation.generation);
    created_events(stx, &generation, false);
    stx.world
        .sccp_committee_generations
        .insert(generation.generation, generation);
}

/// Borrowed whole transition demand, before any new retained generation allocation.
pub(super) struct GenerationDraft<'a> {
    old_end: Option<RetainedSccpGeneration>,
    resync: Option<RecordDraft<'a>>,
    rotation: Option<RecordDraft<'a>>,
    generation: u64,
    committee_root: [u8; 32],
    next_committee_root: [u8; 32],
    validity_ms: u64,
}
impl GenerationDraft<'_> {
    pub(super) fn demand(&self) -> Result<usize, GenerationError> {
        self.resync
            .iter()
            .chain(&self.rotation)
            .try_fold(0usize, |bytes, record| {
                bytes.checked_add(record.demand()?).ok_or_else(|| {
                    GenerationError::Deferred(AllocationRefusal::DemandOverflow.into())
                })
            })
    }
    pub(super) fn materialize(
        self,
        budget: &AllocationBudget,
        reservation: &mut AllocationReservation,
    ) -> Result<GenerationPlan, GenerationError> {
        let resync = self
            .resync
            .map(|record| record.materialize(budget, reservation))
            .transpose()?;
        let rotation = self
            .rotation
            .map(|record| record.materialize(budget, reservation))
            .transpose()?;
        Ok(GenerationPlan {
            old_end: self.old_end,
            resync,
            rotation,
            generation: self.generation,
            committee_root: self.committee_root,
            next_committee_root: self.next_committee_root,
            validity_ms: self.validity_ms,
        })
    }
}

/// Fully admitted G4/G7/G2 plan. At most two new payloads; scalar clones share original custody.
#[derive(Debug)]
pub(super) struct GenerationPlan {
    old_end: Option<RetainedSccpGeneration>,
    resync: Option<RetainedSccpGeneration>,
    rotation: Option<RetainedSccpGeneration>,
    pub generation: u64,
    pub committee_root: [u8; 32],
    pub next_committee_root: [u8; 32],
    pub validity_ms: u64,
}
impl GenerationPlan {
    pub(super) fn publish(self, stx: &mut StateTransaction<'_, '_>) {
        let mut current = self.generation;
        if let Some(old) = self.old_end {
            stx.world
                .sccp_committee_generations
                .insert(old.generation, old);
        }
        if let Some(resync) = self.resync {
            created_events(stx, &resync, true);
            stx.world
                .sccp_committee_generations
                .insert(resync.generation, resync);
        }
        if let Some(rotation) = self.rotation {
            current = rotation.generation;
            created_events(stx, &rotation, false);
            stx.world
                .sccp_committee_generations
                .insert(rotation.generation, rotation);
        }
        store::committee_current::set(stx, current);
        store::degraded_run::set(stx, 0);
    }
}

/// Validate the original height inputs and prepare both possible transitions before any write.
pub(super) fn draft<'a>(
    stx: &'a StateTransaction<'_, '_>,
    header: &BlockHeader,
    inputs: Option<&SccpHeightInputsV1<'_>>,
) -> Result<GenerationDraft<'a>, GenerationError> {
    let inputs = inputs.ok_or(GenerationError::Degraded(Degraded::MissingInputs))?;
    let height = header.height().get();
    if inputs.mode != ConsensusMode::Npos
        || inputs.height != height
        || inputs.epoch_end_height < height
        || inputs.is_boundary() != inputs.next_roster.is_some()
    {
        return Err(GenerationError::Degraded(Degraded::InvalidInputs));
    }
    let committee = Committee::read(inputs.roster.iter())?;
    let next = Committee::read(inputs.next_roster.as_ref().unwrap_or(&inputs.roster).iter())?;
    let parameters = store::parameters::get(&*stx.world)
        .as_ref()
        .ok_or(GenerationError::Degraded(Degraded::InvalidGeneration))?;
    let id = *store::committee_current::get(&*stx.world);
    let original = store::committee_generations::get(&*stx.world, &id)
        .ok_or(GenerationError::Degraded(Degraded::MissingGeneration))?;
    let time = timestamp_ms(header);
    let lc = *store::liability_clock::get(&*stx.world);
    if original.generation != id
        || !original.is_well_formed()
        || original.end.is_some()
        || original.start_height > height
        || original.start_timestamp_ms > time
        || lc > time
    {
        return Err(GenerationError::Degraded(Degraded::InvalidGeneration));
    }
    let mut out = GenerationDraft {
        old_end: None,
        resync: None,
        rotation: None,
        generation: id,
        committee_root: committee.root,
        next_committee_root: [0; 32],
        validity_ms: 0,
    };
    if original.committee_root != committee.root {
        let parent = stx
            .native_execution_tip()
            .filter(|tip| tip.height().checked_add(1) == Some(height))
            .ok_or(GenerationError::Degraded(Degraded::MissingParent))?;
        if original.start_height > parent.height()
            || original.start_timestamp_ms > parent.creation_time_ms()
        {
            return Err(GenerationError::Degraded(Degraded::InvalidGeneration));
        }
        let id = id
            .checked_add(1)
            .ok_or(GenerationError::Degraded(Degraded::CounterExhausted))?;
        if store::committee_generations::contains(&*stx.world, &id) {
            return Err(GenerationError::Degraded(Degraded::InvalidGeneration));
        }
        let mut old = original.clone();
        old.end = Some(SccpGenerationEndV1 {
            end_height: parent.height(),
            end_timestamp_ms: if cfg!(all(test, sumeragi_core_mutation = "HC227")) {
                time
            } else {
                parent.creation_time_ms()
            },
            next_committee_root: committee.root,
            successor_validity_ms: parameters.committee_validity_ms,
        });
        out.old_end = Some(old);
        out.resync = Some(draft_record(
            stx,
            &committee,
            Creation {
                generation: id,
                cause: SccpGenerationCauseV1::Resync,
                start_height: height,
                timestamp_ms: time,
                liability_clock: lc,
            },
            parameters,
        )?);
        out.generation = id;
    }
    let current = out
        .resync
        .as_ref()
        .map_or(&**original, |record| &record.metadata);
    let key = inputs.is_boundary() && next.root != current.committee_root;
    let beat = time
        >= current
            .start_timestamp_ms
            .saturating_add(parameters.committee_heartbeat_ms);
    if key || beat {
        let id = current
            .generation
            .checked_add(1)
            .ok_or(GenerationError::Degraded(Degraded::CounterExhausted))?;
        let start_height = height
            .checked_add(1)
            .ok_or(GenerationError::Degraded(Degraded::CounterExhausted))?;
        if store::committee_generations::contains(&*stx.world, &id) {
            return Err(GenerationError::Degraded(Degraded::InvalidGeneration));
        }
        let end = SccpGenerationEndV1 {
            end_height: height,
            end_timestamp_ms: time,
            next_committee_root: next.root,
            successor_validity_ms: parameters.committee_validity_ms,
        };
        let rotation = draft_record(
            stx,
            &next,
            Creation {
                generation: id,
                cause: if key {
                    SccpGenerationCauseV1::KeyChange
                } else {
                    SccpGenerationCauseV1::Heartbeat
                },
                start_height,
                timestamp_ms: time,
                liability_clock: lc,
            },
            parameters,
        )?;
        out.validity_ms = rotation.metadata.validity_ms;
        out.next_committee_root = next.root;
        if let Some(resync) = out.resync.as_mut() {
            resync.metadata.end = Some(end);
        } else {
            let mut ended = original.clone();
            ended.end = Some(end);
            out.old_end = Some(ended);
        }
        out.rotation = Some(rotation);
    }
    Ok(out)
}

#[cfg(test)]
fn plan(
    stx: &StateTransaction<'_, '_>,
    header: &BlockHeader,
    inputs: Option<&SccpHeightInputsV1<'_>>,
) -> Result<GenerationPlan, GenerationError> {
    let draft = draft(stx, header, inputs)?;
    let budget = stx.execution_budget();
    let mut reservation = budget
        .try_reserve_bytes(draft.demand()?)
        .map_err(|e| GenerationError::Deferred(e.into()))?;
    draft.materialize(&budget, &mut reservation)
}

/// Header times are u64 milliseconds by construction; no wall clock is consulted.
pub(super) fn timestamp_ms(header: &BlockHeader) -> u64 {
    u64::try_from(header.creation_time().as_millis()).expect("BlockHeader stores u64 milliseconds")
}

/// First 64 ended, uncleared generations, in ascending map order, share the post-block clock.
pub(super) fn clear_destinations(stx: &mut StateTransaction<'_, '_>) {
    let mut selected = [0; 64];
    let mut count = 0;
    for (id, generation) in store::committee_generations::iter(&*stx.world)
        .filter(|(_, generation)| generation.end.is_some() && generation.dest_cleared_lc.is_none())
        .take(64)
    {
        let cleared = store::routes::iter(&*stx.world).all(|(network, route)| {
            !route
                .revisions
                .values()
                .any(|revision| revision.activation != SccpRouteActivationV1::Retired)
                || store::light_clients::get(&*stx.world, network).is_some_and(|client| {
                    !client.is_frozen()
                        && client.head.latest_finalized.source_time_ms > generation.deadline_ms
                })
        });
        if cleared {
            selected[count] = *id;
            count += 1;
        }
    }
    let lc = *store::liability_clock::get(&*stx.world);
    for id in &selected[..count] {
        let mut generation = store::committee_generations::get(&*stx.world, id)
            .expect("selected original generation")
            .clone();
        generation.dest_cleared_lc = Some(lc);
        stx.world.sccp_committee_generations.insert(*id, generation);
        stx.world
            .emit_events(Some(SccpEvent::GenerationDestinationCleared(
                SccpGenerationDestinationClearedV1 {
                    generation: *id,
                    lc,
                },
            )));
    }
}

/// Pure bounded selection for §4.11; caller must supply the actual Pending-forgery owner.
/// Production deliberately does not call this until WP-S6 integrates that State/instruction
/// owner. An absent pending owner must never be represented by an invented empty set.
#[cfg(test)]
fn prune_selection<'a>(
    generations: impl IntoIterator<Item = (&'a u64, &'a RetainedSccpGeneration)>,
    current: u64,
    lc: u64,
    pending_generations: &std::collections::BTreeSet<u64>,
) -> ([u64; 8], usize) {
    let mut selected = [0; 8];
    let mut count = 0;
    for (id, generation) in generations {
        if *id < current && !generation.is_liable(current, lc) && !pending_generations.contains(id)
        {
            selected[count] = *id;
            count += 1;
            if count == selected.len() {
                break;
            }
        }
    }
    (selected, count)
}

#[cfg(test)]
mod tests;
