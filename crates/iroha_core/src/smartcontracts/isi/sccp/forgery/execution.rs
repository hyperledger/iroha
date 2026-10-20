//! Executing-parent forgery recheck and one-child evidence/offence/hold publication.
//!
//! The direct signed entrypoint owner must consume its exact sole-instruction binding
//! before calling this module. Queue prechecks are never execution authority. All
//! protocol decisions and fallible payload preparation precede writes; any original
//! local publication refusal poisons the outer transaction, which cannot be applied.

use crate::smartcontracts::isi::sccp::{
    eligibility::{EligibilityRead, TransactionParent},
    original_read::OriginalRead,
};

use super::{
    ForgeryVerificationError, Observation, VerificationControl, original_source, store,
    verify_observation,
};
use crate::{
    state::{
        EvidencePreparationError, StateReadOnly, StateStorageAdmissionError, StateTransaction,
        sccp_forgery_custody::{ForgeryStorageError, OffenceKey},
    },
    sumeragi::evidence::record::{PreparedSccpRecord, RetainedEvidenceRecord, prepare_sccp_claim},
};
use iroha_crypto::Hash;
use iroha_data_model::{
    block::consensus::RecordedEvidenceV1,
    isi::{error::InstructionExecutionError, sccp::SubmitSccpForgeryEvidenceV1},
    sumeragi_finality::certified_result::SccpFinalityHeaderV1,
};
use mv::storage::StorageReadOnly as _;

mod event_graph;
use event_graph::prepare_events;
#[cfg(test)]
use iroha_data_model::sccp::events::SccpEvent;

/// A protocol rejection is distinct from a retained local storage/source refusal.
#[derive(Debug, thiserror::Error)]
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
        match self.into_local_refusal() {
            Ok(local) => {
                // The original local cause lives outside deterministic instruction errors.
                // Its sticky owner rejects the carrier before receipts or apply; even a
                // diagnostic allocation here could fail while reporting allocator refusal.
                #[cfg(all(test, sumeragi_core_mutation = "HC907"))]
                let message = local.to_string().into_boxed_str();
                #[cfg(not(all(test, sumeragi_core_mutation = "HC907")))]
                let message = Box::<str>::default();
                stx.arm_local_storage_refusal(local);
                InstructionExecutionError::InvariantViolation(message)
            }
            Err(protocol) => {
                InstructionExecutionError::InvariantViolation(protocol.to_string().into())
            }
        }
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
            // The pairing scratch is the only physical allocation of verification: a local
            // allocator refusal of its exact admitted layout, never a protocol rejection.
            // TODO(S8): retain the original move-only AllocatorRefusal once the preparation
            // error owns it.
            Self::Verification(ForgeryVerificationError::PhysicalAllocation(_)) => {
                Ok(StateStorageAdmissionError::SccpEvidence(
                    EvidencePreparationError::Allocator {
                        requested_bytes:
                            iroha_crypto::bls::consensus::ConsensusAggregateScratch::<()>::backing_layout()
                                .size(),
                    },
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
    events: event_graph::FundedForgeryEvents,
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
    let parent_world = TransactionParent(&stx.world);
    let parameters = parent_world
        .parameters()
        .ok_or(ForgeryVerificationError::NotEvidence)?;
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
    let liability_clock = iroha_data_model::sccp::generation::next_liability_clock_v1(
        parent_world.liability_clock(),
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
        parent_world,
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
        stx.sccp_evidence_preparation_budget(),
    )?;
    let record = prepared.into_record(stx)?;
    Ok(PreparedExecution {
        keys,
        record,
        evidence_id,
        events,
    })
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
    stx.world.emit_sccp_forgery_events(events.iter());
    Ok(())
}

#[cfg(test)]
mod tests;
