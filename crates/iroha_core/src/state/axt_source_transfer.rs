//! Read-only confirmation of one finalized AXT source execution and transfer.

use std::num::NonZeroUsize;

use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    block::BlockHeader,
    fastpq::FastpqPublicTransferDeltaV1,
    nexus::{
        AxtSourceTransferOccurrenceV1, MAX_REMOTE_SPEND_INTENT_COMMITMENTS_V1,
        axt_source_transfer_digest_v1,
    },
};
use thiserror::Error;

use super::State;

/// Facts read from a canonical, QC-authenticated source block.
///
/// This value confirms successful Network execution and the physical transfer
/// coordinate only. It does not authenticate a successful-execution receipt,
/// a complete State root, an issuer, or a remote spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct FinalizedAxtSourceTransferFactV1 {
    /// Canonical height that owns the source execution.
    pub(crate) height: u64,
    /// Header hash selected by the State-owned canonical history.
    pub(crate) block_header_hash: HashOf<BlockHeader>,
    /// Exact execution-call identity present once in the block.
    pub(crate) source_tx_commitment: [u8; 32],
    /// Exact Network input position.
    pub(crate) source_tx_index: u32,
    /// Exact ordered transfer transcript position.
    pub(crate) transcript_index: u32,
    /// Exact delta position in that transcript.
    pub(crate) delta_index: u32,
    /// Exact flattened transfer position across the source execution.
    pub(crate) pair_ordinal: u32,
    /// Digest of the complete public transfer facts at that position.
    pub(crate) transfer_digest: [u8; 32],
}

/// Failure to confirm a claimed physical transfer against finalized execution.
#[derive(Debug, Error)]
#[allow(dead_code)]
pub(crate) enum FinalizedAxtSourceTransferErrorV1 {
    /// The original finalized-history read is unfinished because its local resources are occupied.
    #[error("AXT finalized source history deferred: {0}")]
    Deferred(crate::execution_attempt::ExecutionDeferred),
    /// The claim is structurally malformed or its height cannot be indexed.
    #[error("AXT source transfer claim has invalid coordinates or digests")]
    InvalidClaim,
    /// Canonical history, its finality, or its executed body was unavailable or invalid.
    #[error("AXT finalized source carrier is unavailable or invalid")]
    FinalizedCarrier,
    /// The claimed source transaction is absent from the canonical input position.
    #[error("AXT source execution differs from the finalized input")]
    SourceExecution,
    /// One execution-call identity occurs more than once in the finalized block.
    #[error("AXT source execution is not unique in the finalized block")]
    DuplicateSourceExecution,
    /// The exact source input did not execute successfully.
    #[error("AXT finalized source execution was rejected")]
    RejectedExecution,
    /// No retained transfer transcripts belong to the source execution.
    #[error("AXT finalized source transfer transcripts are absent")]
    MissingTranscripts,
    /// A retained transcript is miskeyed or exceeds the V1 transfer bound.
    #[error("AXT finalized source transfer transcript inventory is invalid")]
    InvalidTranscripts,
    /// The claimed transcript, delta, and pair ordinal do not select one transfer.
    #[error("AXT finalized source transfer coordinate differs from the claim")]
    TransferCoordinate,
    /// The transfer at the selected physical coordinate has different facts.
    #[error("AXT finalized source transfer facts differ from the claim")]
    TransferFacts,
}

impl State {
    /// Confirm one source execution and exact transfer against retained finality.
    ///
    /// The State-owned height/hash journal selects the source body. The finalized
    /// carrier reader verifies its QC, exact wire and output cache before this
    /// method checks the Network result and retained ordered transfer facts.
    /// Receipt digest and remote-spend claim commitment remain unverified here.
    ///
    /// TODO: Complete State-owned pre/post roots and a complete ordered-effect
    /// digest must be published and authenticated before a source-success
    /// receipt or finalized AXT anchor can be resolved for admission.
    ///
    /// # Errors
    /// Rejects an unavailable or changed finalized carrier, rejected or
    /// ambiguous execution, and any mismatch in the exact transfer coordinate.
    #[allow(dead_code)]
    pub(crate) fn resolve_finalized_axt_source_transfer_v1(
        &self,
        finalized_height: u64,
        claimed: &AxtSourceTransferOccurrenceV1,
        max_work: u64,
        max_bytes: u64,
    ) -> Result<FinalizedAxtSourceTransferFactV1, FinalizedAxtSourceTransferErrorV1> {
        claimed
            .validate()
            .map_err(|_| FinalizedAxtSourceTransferErrorV1::InvalidClaim)?;
        let height = usize::try_from(finalized_height)
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or(FinalizedAxtSourceTransferErrorV1::InvalidClaim)?;
        let carrier = self
            .read_finalized_execution_carrier(height, max_work, max_bytes)
            .map_err(|error| match error {
                crate::execution_attempt::ExecutionAttemptError::Deferred(original) => {
                    FinalizedAxtSourceTransferErrorV1::Deferred(original)
                }
                crate::execution_attempt::ExecutionAttemptError::Rejected(_) => {
                    FinalizedAxtSourceTransferErrorV1::FinalizedCarrier
                }
            })?;
        let block = carrier.block();
        let source = block
            .network_entrypoint_at(claimed.source_tx_index as usize)
            .ok_or(FinalizedAxtSourceTransferErrorV1::SourceExecution)?;
        let source_hash = source.execution_call_hash();
        if source_hash.as_ref() != &claimed.source_tx_commitment {
            return Err(FinalizedAxtSourceTransferErrorV1::SourceExecution);
        }
        if block
            .network_entrypoints()
            .filter(|entry| entry.execution_call_hash() == source_hash)
            .take(2)
            .count()
            != 1
        {
            return Err(FinalizedAxtSourceTransferErrorV1::DuplicateSourceExecution);
        }
        let (_, output) = block
            .network_output_at(claimed.source_tx_index)
            .ok_or(FinalizedAxtSourceTransferErrorV1::SourceExecution)?;
        if !output.result.is_ok() {
            return Err(FinalizedAxtSourceTransferErrorV1::RejectedExecution);
        }
        let source_hash = Hash::from(source_hash);
        let transcripts = block
            .fastpq_transcripts()
            .get(&source_hash)
            .ok_or(FinalizedAxtSourceTransferErrorV1::MissingTranscripts)?;
        let mut pair_ordinal = 0_usize;
        let mut selected = false;
        for (transcript_index, transcript) in transcripts.iter().enumerate() {
            if transcript.batch_hash != source_hash {
                return Err(FinalizedAxtSourceTransferErrorV1::InvalidTranscripts);
            }
            for (delta_index, delta) in transcript.deltas.iter().enumerate() {
                if pair_ordinal >= MAX_REMOTE_SPEND_INTENT_COMMITMENTS_V1 {
                    return Err(FinalizedAxtSourceTransferErrorV1::InvalidTranscripts);
                }
                if transcript_index == claimed.transcript_index as usize
                    && delta_index == claimed.delta_index as usize
                {
                    if pair_ordinal != claimed.pair_ordinal as usize {
                        return Err(FinalizedAxtSourceTransferErrorV1::TransferCoordinate);
                    }
                    let public_delta = FastpqPublicTransferDeltaV1::from(delta);
                    if axt_source_transfer_digest_v1(&public_delta) != claimed.transfer_digest {
                        return Err(FinalizedAxtSourceTransferErrorV1::TransferFacts);
                    }
                    selected = true;
                }
                pair_ordinal += 1;
            }
        }
        if !selected {
            return Err(FinalizedAxtSourceTransferErrorV1::TransferCoordinate);
        }
        Ok(FinalizedAxtSourceTransferFactV1 {
            height: finalized_height,
            block_header_hash: block.hash(),
            source_tx_commitment: claimed.source_tx_commitment,
            source_tx_index: claimed.source_tx_index,
            transcript_index: claimed.transcript_index,
            delta_index: claimed.delta_index,
            pair_ordinal: claimed.pair_ordinal,
            transfer_digest: claimed.transfer_digest,
        })
    }
}
