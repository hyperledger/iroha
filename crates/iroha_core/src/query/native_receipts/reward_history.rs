//! Deterministic reward history reads from the original committed execution archive.

use super::ordinary_writes::{self, WriteDecodeError};
use crate::{
    execution_attempt::{
        ExecutionAttemptError, canonical_decode_attempt_error, kura_read_attempt_error,
        norito_decode_attempt_error,
    },
    query::native_context_archive::{NativeContextArchive, NativeContextArchiveError},
    state::StateReadOnly,
    sumeragi::certified_chain::committed_block,
};
use iroha_allocation::{ChargedBufferError, PrepaidBufferError, RetainedPayload};
use iroha_crypto::Hash;
use iroha_data_model::{
    block::consensus::ExecWitness,
    fee_evidence::FeeEvidenceBlockProofV1,
    sumeragi_finality::{NativeLaneStateProof, NativeLaneStateProofError},
    validation_fee_rewards::{
        MAX_REWARD_EXPOSURE_ARCHIVE_BYTES, ValidationFeeExposureArchive, validate_exposure_archive,
        validation_fee_exposure_archive_witness_key,
    },
};
use iroha_model_base::state_path::StatePath;
use ivm::error::ExecutionDeferral;

type Attempt<T> = Result<T, ExecutionAttemptError<String>>;

fn unavailable() -> ExecutionAttemptError<String> {
    ExecutionAttemptError::Deferred(ExecutionDeferral::CanonicalHistoryUnavailable.into())
}

fn allocation(error: ChargedBufferError) -> ExecutionAttemptError<String> {
    ExecutionAttemptError::Deferred(match error {
        ChargedBufferError::Admission(original) => original.into(),
        ChargedBufferError::Allocator { .. } => ExecutionDeferral::AllocationUnavailable.into(),
    })
}

fn archive_error(error: NativeContextArchiveError) -> ExecutionAttemptError<String> {
    match error {
        NativeContextArchiveError::Allocation(error) => allocation(error),
        NativeContextArchiveError::Storage(error) => match kura_read_attempt_error(error, |_| ()) {
            ExecutionAttemptError::Deferred(original) => ExecutionAttemptError::Deferred(original),
            ExecutionAttemptError::Rejected(()) => unavailable(),
        },
        NativeContextArchiveError::Proof(error) => lane_error(error),
        NativeContextArchiveError::Codec(error) => archive_codec_error(error),
        // Missing, oversized or corrupt local custody is never a protocol verdict.
        NativeContextArchiveError::Io(_)
        // CaptureAdmission is produced only by isolated target-tape writes, never
        // by this historical reward reader. It supplies no missing reward fact.
        | NativeContextArchiveError::CaptureAdmission(_)
        | NativeContextArchiveError::CaptureFailure(_)
        | NativeContextArchiveError::Limit { .. }
        | NativeContextArchiveError::Source(_) => unavailable(),
    }
}

fn archive_codec_error(error: norito::Error) -> ExecutionAttemptError<String> {
    match norito_decode_attempt_error(error, |_| ()) {
        ExecutionAttemptError::Deferred(original) => ExecutionAttemptError::Deferred(original),
        ExecutionAttemptError::Rejected(()) => unavailable(),
    }
}

fn write_error(error: WriteDecodeError) -> ExecutionAttemptError<String> {
    match error {
        WriteDecodeError::Admission(original) => ExecutionAttemptError::Deferred(original.into()),
        WriteDecodeError::Materialization(PrepaidBufferError::Allocation(error)) => {
            allocation(error)
        }
        WriteDecodeError::Materialization(PrepaidBufferError::Reservation(_))
        | WriteDecodeError::ForeignPool
        | WriteDecodeError::PlanChanged => {
            ExecutionAttemptError::Deferred(ExecutionDeferral::LocalInvariantViolation.into())
        }
        WriteDecodeError::Codec(error) => archive_codec_error(error),
    }
}

fn lane_error(error: NativeLaneStateProofError) -> ExecutionAttemptError<String> {
    match error {
        NativeLaneStateProofError::Scratch(error) => allocation(error),
        NativeLaneStateProofError::Decode(error) => {
            match canonical_decode_attempt_error(error, |_| ()) {
                ExecutionAttemptError::Deferred(original) => {
                    ExecutionAttemptError::Deferred(original)
                }
                ExecutionAttemptError::Rejected(()) => unavailable(),
            }
        }
        NativeLaneStateProofError::Codec(error) => archive_codec_error(error),
        NativeLaneStateProofError::Malformed(_) => unavailable(),
    }
}

struct CommittedWrites {
    root: Hash,
    witness: RetainedPayload<ExecWitness>,
}

/// Authenticate the complete original ordinary-write graph without reading a local quorum.
fn committed_writes(view: &impl StateReadOnly, height: u64) -> Attempt<CommittedWrites> {
    if height < 2
        || usize::try_from(height)
            .ok()
            .is_none_or(|h| h > view.block_hashes().len())
    {
        return Err("reward history height is not a committed non-genesis block".into());
    }
    let committed = committed_block(view, height).map_err(|error| match error {
        ExecutionAttemptError::Deferred(original) => ExecutionAttemptError::Deferred(original),
        ExecutionAttemptError::Rejected(_) => unavailable(),
    })?;
    let budget = view.prepared_contract_cache().execution_budget().clone();
    let archive = NativeContextArchive::open_existing(
        view.kura(),
        budget.clone(),
        view.kura().native_context_archive_max_bytes(),
    )
    .map_err(archive_error)?;
    let bytes = archive
        .read_exact(height, committed.block_hash())
        .map_err(archive_error)?;
    let projection = ordinary_writes::decode_projection(&bytes, &budget).map_err(write_error)?;
    if projection.carrier_height != height || projection.carrier_hash != committed.block_hash() {
        return Err(unavailable());
    }
    let root = committed.commitment().execution.ordinary_writes_root;
    let path = NativeLaneStateProof::from_witness(projection.witness.get(), &budget)
        .map_err(lane_error)?;
    if !path.verify(*view.network_id(), height, root)
        || !path
            .matches_state_payload(*view.network_id(), height, projection.lane_payload)
            .map_err(archive_codec_error)?
    {
        return Err(unavailable());
    }
    archive.recheck_namespace().map_err(archive_error)?;
    Ok(CommittedWrites {
        root,
        witness: projection.witness,
    })
}

/// Read the complete original fee corpus before deterministic monetary-history compaction.
///
/// # Errors
/// Local archival availability, corruption and original allocation refusals defer execution.
/// A fee corpus inconsistent with its authenticated original execution is rejected.
pub(crate) fn committed_fee_evidence(
    view: &impl StateReadOnly,
    height: u64,
) -> Attempt<FeeEvidenceBlockProofV1> {
    let source = committed_writes(view, height)?;
    let (proof, root, evaluated_height) =
        crate::receiver_snapshot::fee_evidence_block_proof_attempt_v1(source.witness.get())?;
    // The typed builder has verified the full fixed-key SMT path and complete
    // corpus against this root. Reuse its once-decoded authenticated height;
    // boolean/String proof helpers would erase a later local decode refusal.
    if root != source.root || evaluated_height != height {
        return Err("original fee corpus differs from its committed execution".into());
    }
    Ok(proof)
}

/// Read one exact bounded historical exposure wrapper from committed original writes.
///
/// The expected hash covers the complete canonical wrapper, including its predecessor.
/// Current World state and local quorum certificates never supply historical authority.
///
/// # Errors
/// Local archival availability, corruption and original allocation refusals defer execution.
/// Authenticated absent, substituted, malformed or nonchronological source records reject.
pub(crate) fn committed_reward_exposure(
    view: &impl StateReadOnly,
    height: u64,
    key: &StatePath,
    expected_hash: Hash,
) -> Attempt<ValidationFeeExposureArchive> {
    let source = committed_writes(view, height)?;
    let witness_key = validation_fee_exposure_archive_witness_key(key);
    let mut matching = source
        .witness
        .get()
        .writes
        .iter()
        .filter(|write| write.key == witness_key);
    let value = &matching
        .next()
        .ok_or("original reward exposure source is absent")?
        .value;
    if matching.next().is_some() {
        return Err("original reward exposure source key is duplicated".into());
    }
    if value.len() > MAX_REWARD_EXPOSURE_ARCHIVE_BYTES || Hash::new(value) != expected_hash {
        return Err("original reward exposure size or wrapper hash differs".into());
    }
    let decoded: ValidationFeeExposureArchive = norito::decode_canonical_with_limits(
        value,
        norito::canonical_decode_limits(MAX_REWARD_EXPOSURE_ARCHIVE_BYTES),
    )
    .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))?;
    validate_exposure_archive(&decoded).map_err(ExecutionAttemptError::Rejected)?;
    if decoded
        .previous
        .as_ref()
        .is_some_and(|previous| previous.recorded_at_height >= height)
    {
        return Err("reward exposure predecessor is not earlier than its carrier".into());
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests;
