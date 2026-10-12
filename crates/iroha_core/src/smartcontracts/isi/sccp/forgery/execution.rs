//! Executing-parent forgery recheck and one-child evidence/offence/hold publication.
//!
//! The direct signed entrypoint owner must consume its exact sole-instruction binding
//! before calling this module. Queue prechecks are never execution authority. All
//! protocol decisions and fallible payload preparation precede writes; any original
//! local publication refusal poisons the outer transaction, which cannot be applied.

use super::{
    ForgeryVerificationError, Observation, VerificationControl, original_source, params, store,
    verify_observation,
};
use crate::{
    state::{
        EvidencePreparationError, StateReadOnly, StateStorageAdmissionError, StateTransaction,
        WorldReadOnly,
        sccp_forgery_custody::{ForgeryStorageError, OffenceKey},
    },
    sumeragi::evidence::record::{PreparedSccpRecord, RetainedEvidenceRecord, prepare_sccp_claim},
};
use iroha_crypto::Hash;
use iroha_data_model::{
    block::consensus::RecordedEvidenceV1,
    isi::{error::InstructionExecutionError, sccp::SubmitSccpForgeryEvidenceV1},
    sccp::{
        events::{
            SccpEvent, SccpForgeryEvidenceRecordedV1, SccpForgeryOffenderUnslashableV1,
            SccpRevisionForgeryHeldV1,
        },
        native::SccpForgeryOffenderV1,
    },
    sumeragi_finality::certified_result::SccpFinalityHeaderV1,
};
use mv::storage::StorageReadOnly as _;

/// A protocol rejection is distinct from a retained local storage/source refusal.
#[derive(Clone, Debug, thiserror::Error)]
#[allow(
    variant_size_differences,
    reason = "retain original inline resource/refusal owners without a new allocation"
)]
pub(crate) enum ForgeryExecutionError {
    /// Recomputed exact parent relation, never an ingress admission receipt.
    #[error(transparent)]
    Verification(#[from] ForgeryVerificationError),
    /// Every slashable G6 member already has a permanent offence for this generation.
    #[error("SCCP forgery evidence duplicate")]
    EvidenceDuplicate,
    /// Original fixed-pool map/key admission or source join refusal.
    #[error(transparent)]
    Storage(#[from] ForgeryStorageError),
    /// Original record/event payload preparation refused before publication.
    #[error(transparent)]
    Preparation(#[from] EvidencePreparationError),
}

impl ForgeryExecutionError {
    /// Retain local failure before crossing the model-owned instruction error boundary.
    /// The outer output owner checks these sticky sources before deterministic R-EX.
    pub(crate) fn into_instruction_error(
        self,
        stx: &mut StateTransaction<'_, '_>,
    ) -> InstructionExecutionError {
        let message = self.to_string();
        if let Ok(local) = self.into_local_refusal() {
            stx.arm_local_storage_refusal(local);
        }
        InstructionExecutionError::InvariantViolation(message.into())
    }

    /// Only deterministic signed-content/parent verdicts may be dropped by an honest builder.
    pub(crate) fn is_protocol_rejection(&self) -> bool {
        matches!(
            self,
            Self::EvidenceDuplicate
                | Self::Verification(
                    ForgeryVerificationError::NotEvidence
                        | ForgeryVerificationError::EvidenceExpired
                        | ForgeryVerificationError::EvidenceUnknownGeneration
                        | ForgeryVerificationError::BadSignature
                        | ForgeryVerificationError::WitnessRequired
                        | ForgeryVerificationError::BadWitness
                )
        )
    }

    /// Extract the unchanged local refusal without requiring a transaction or allocating
    /// a diagnostic. Protocol failures are returned intact for the caller's drop policy.
    pub(crate) fn into_local_refusal(self) -> Result<StateStorageAdmissionError, Self> {
        match self {
            Self::Storage(error) => Ok(StateStorageAdmissionError::SccpForgery(error)),
            Self::Preparation(error) => Ok(StateStorageAdmissionError::SccpEvidence(error)),
            Self::Verification(ForgeryVerificationError::Allocation(error)) => {
                Ok(StateStorageAdmissionError::SccpEvidence(
                    EvidencePreparationError::Admission(error),
                ))
            }
            Self::Verification(
                ForgeryVerificationError::Unavailable(_)
                | ForgeryVerificationError::UnsupportedScope
                | ForgeryVerificationError::Cancelled
                | ForgeryVerificationError::Deadline,
            ) => {
                // No synchronous caller can acquire a read deadline or stop condition.
                // An inconsistent original source is local recovery, never bad evidence.
                Ok(StateStorageAdmissionError::SccpForgery(
                    ForgeryStorageError::Invalid,
                ))
            }
            protocol => Err(protocol),
        }
    }
}

struct PreparedExecution {
    keys: [Option<OffenceKey>; 31],
    record: RetainedEvidenceRecord,
    evidence_id: [u8; 32],
    events: Vec<SccpEvent>,
}

/// Reverify the exact original parent and atomically publish one pending SCCP record.
/// This function cannot be substituted for the sole-signed direct entrypoint binding.
/// Penalties consume Pending later under their immutable delay; L3 and holds become
/// visible immediately through the same committed record/offence/max transaction.
pub(crate) fn execute_forgery(
    evidence: &SubmitSccpForgeryEvidenceV1,
    stx: &mut StateTransaction<'_, '_>,
) -> Result<(), ForgeryExecutionError> {
    let prepared = prepare_execution(evidence, stx)?;
    publish(prepared, stx)
}

fn prepare_execution(
    evidence: &SubmitSccpForgeryEvidenceV1,
    stx: &StateTransaction<'_, '_>,
) -> Result<PreparedExecution, ForgeryExecutionError> {
    let parent_world = stx.sccp_parent_world_view();
    let parameters =
        params::parameters(&parent_world).ok_or(ForgeryVerificationError::NotEvidence)?;
    let header = SccpFinalityHeaderV1::parse(&evidence.header)
        .map_err(|_| ForgeryVerificationError::NotEvidence)?;
    if !header.is_active() || header.network_id() != *stx.network_id().as_bytes() {
        return Err(ForgeryVerificationError::NotEvidence.into());
    }
    let (parent, instance) = original_source(stx)?;
    let executing = &stx._curr_block;
    let execution_height =
        parent
            .height()
            .checked_add(1)
            .ok_or(ForgeryVerificationError::Unavailable(
                "next height overflows",
            ))?;
    if executing.height().get() != execution_height
        || executing.prev_block_hash() != Some(parent.iroha_hash())
        || executing.creation_time_ms <= parent.creation_time_ms()
    {
        return Err(ForgeryVerificationError::Unavailable(
            "execution header differs from original parent",
        )
        .into());
    }
    let liability_clock = super::super::generation::advance_liability_clock(
        *store::liability_clock::get(&parent_world),
        parent.creation_time_ms(),
        executing.creation_time_ms,
        parameters.committee_heartbeat_ms,
    );
    if *store::liability_clock::get(&*stx.world) != liability_clock {
        return Err(ForgeryVerificationError::Unavailable(
            "original S0 liability clock is absent or changed",
        )
        .into());
    }
    let candidate = verify_observation(
        &parent_world,
        evidence,
        header,
        Observation {
            parent,
            instance,
            execution_height,
            liability_clock,
        },
        stx.sccp_evidence_preparation_budget(),
        VerificationControl::Synchronous,
    )?;
    let mut keys: [Option<OffenceKey>; 31] = std::array::from_fn(|_| None);
    let new_signers = super::new_signers(
        &*stx.world,
        candidate.generation(),
        candidate.qc().signers,
        stx.world.sccp_forgery_offences.allocation_budget(),
    )?;
    if new_signers == 0 {
        return Err(ForgeryExecutionError::EvidenceDuplicate);
    }
    let mut unslashable = 0_u32;
    for (signer, _, member) in candidate.signers() {
        let Some(member) = member else {
            unslashable |= 1_u32 << signer;
            continue;
        };
        if new_signers & (1_u32 << signer) == 0 {
            continue;
        }
        let key = OffenceKey::try_copy(
            candidate.generation().generation,
            member.lane_id,
            &member.validator,
            stx.world.sccp_forgery_offences.allocation_budget(),
        )?;
        // Exact signer geometry was checked by the native relation before this cast.
        let index = usize::try_from(signer).map_err(|_| EvidencePreparationError::Invariant)?;
        keys[index] = Some(key);
    }
    let prepared: PreparedSccpRecord = prepare_sccp_claim(
        &candidate,
        new_signers,
        stx.sccp_evidence_preparation_budget(),
    )?;
    let evidence_id = prepared.evidence_id();
    if stx
        .world
        .consensus_evidence
        .get(&Hash::prehashed(evidence_id))
        .is_some()
    {
        // This identifier fixes g/message/full signer bitmap. A retained record with a
        // newly absent permanent offence contradicts atomic source custody; never overwrite.
        return Err(ForgeryStorageError::Invalid.into());
    }
    let RecordedEvidenceV1::SccpForgery(record) = &prepared.fields().evidence else {
        return Err(EvidencePreparationError::Invariant.into());
    };
    let events = prepare_events(
        &*stx.world,
        evidence_id,
        header.height(),
        record,
        unslashable,
    )?;
    let record = prepared.into_record(stx)?;
    Ok(PreparedExecution {
        keys,
        record,
        evidence_id,
        events,
    })
}

fn try_vec<T>(count: usize) -> Result<Vec<T>, EvidencePreparationError> {
    let requested_bytes = std::alloc::Layout::array::<T>(count)
        .map_err(|_| {
            EvidencePreparationError::Admission(iroha_allocation::AllocationRefusal::DemandOverflow)
        })?
        .size();
    let mut value = Vec::new();
    value
        .try_reserve_exact(count)
        .map_err(|_| EvidencePreparationError::Allocator { requested_bytes })?;
    Ok(value)
}

fn prepare_events(
    world: &impl WorldReadOnly,
    evidence_id: [u8; 32],
    height: u64,
    record: &iroha_data_model::sccp::native::SccpForgeryRecordV1,
    unslashable: u32,
) -> Result<Vec<SccpEvent>, EvidencePreparationError> {
    let previous = store::forgery_max_generation(world);
    let maximum = Some(previous.map_or(record.generation, |g| g.max(record.generation)));
    let mut count = usize::try_from(unslashable.count_ones())
        .map_err(|_| EvidencePreparationError::Invariant)?
        + 1;
    for (_, route) in store::routes::iter(world) {
        for revision in route.revisions.values() {
            if !revision.forgery_held(previous) && revision.forgery_held(maximum) {
                count = count
                    .checked_add(1)
                    .ok_or(EvidencePreparationError::Admission(
                        iroha_allocation::AllocationRefusal::DemandOverflow,
                    ))?;
            }
        }
    }
    let mut events = try_vec(count)?;
    for signer in 0..31_u32 {
        if unslashable & (1_u32 << signer) != 0 {
            events.push(SccpEvent::ForgeryOffenderUnslashable(
                SccpForgeryOffenderUnslashableV1 {
                    generation: record.generation,
                    signer,
                },
            ));
        }
    }
    let mut offenders = try_vec(record.offenders.len())?;
    for offender in &record.offenders {
        let validator = offender
            .validator
            .try_clone_for_admission()
            .map_err(|error| {
                error.decode_resource_error().map_or(
                    EvidencePreparationError::Invariant,
                    EvidencePreparationError::DecodeResource,
                )
            })?;
        offenders.push(SccpForgeryOffenderV1 {
            signer: offender.signer,
            lane_id: offender.lane_id,
            validator,
            activation_height: offender.activation_height,
        });
    }
    events.push(SccpEvent::ForgeryEvidenceRecorded(
        SccpForgeryEvidenceRecordedV1 {
            evidence_id,
            generation: record.generation,
            height,
            rule: record.rule,
            offenders,
        },
    ));
    for (network, route) in store::routes::iter(world) {
        for (revision, value) in &route.revisions {
            if !value.forgery_held(previous) && value.forgery_held(maximum) {
                events.push(SccpEvent::RevisionForgeryHeld(SccpRevisionForgeryHeldV1 {
                    network: *network,
                    revision: *revision,
                    forgery_floor: value.forgery_floor,
                    generation: maximum.ok_or(EvidencePreparationError::Invariant)?,
                }));
            }
        }
    }
    Ok(events)
}

fn publish(
    prepared: PreparedExecution,
    stx: &mut StateTransaction<'_, '_>,
) -> Result<(), ForgeryExecutionError> {
    let PreparedExecution {
        keys,
        record,
        evidence_id,
        events,
    } = prepared;
    for key in keys.into_iter().flatten() {
        match store::forgery_offences::insert_new(stx, key, evidence_id) {
            Ok(true) => {}
            Ok(false) => {
                stx.arm_local_storage_refusal(StateStorageAdmissionError::SccpForgery(
                    ForgeryStorageError::Invalid,
                ));
                return Err(ForgeryStorageError::Invalid.into());
            }
            Err((_key, error)) => {
                stx.arm_local_storage_refusal(StateStorageAdmissionError::SccpForgery(
                    ForgeryStorageError::Storage(error.clone()),
                ));
                return Err(ForgeryStorageError::Storage(error).into());
            }
        }
    }
    if stx
        .world
        .consensus_evidence
        .insert(Hash::prehashed(evidence_id), record)
        .is_some()
    {
        stx.arm_local_storage_refusal(StateStorageAdmissionError::SccpForgery(
            ForgeryStorageError::Invalid,
        ));
        return Err(ForgeryStorageError::Invalid.into());
    }
    // Same canonical event owner used by the retained SCCP instructions. Payload graph
    // allocation happened before writes; the generic World sink retains its existing
    // Arc/Vec allocation boundary, not a new claim of fully admitted event storage.
    stx.world.emit_events(events);
    Ok(())
}

#[cfg(test)]
mod tests;
