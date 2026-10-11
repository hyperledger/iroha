//! FASTPQ-specific transcript helpers shared across the host.
pub(crate) mod finalized_source;
pub mod lane;
pub(crate) mod permission_context;
#[cfg(test)]
pub(crate) mod quantity_fixture;
mod quantity_statement;
#[cfg(test)]
pub(crate) use quantity_statement::{
    quantity_materializer_invocations_for_testing,
    quantity_statement_from_finalized_transcripts_for_testing,
};
mod source_capture;
pub(crate) mod source_prefix_lengths;
pub(crate) mod source_reservation;
pub(crate) use source_capture::FastpqSourceTranscriptUsage;
mod source_context;
pub use quantity_statement::{
    FastpqQuantityStatement, quantity_statement_from_finalized_transcripts,
};
pub use source_capture::{FastpqSourceExecutionEntryV1, FastpqSourceStatementBuildLimits};
#[cfg(test)]
pub(crate) use source_capture::{
    TransferArchiveDiagnostic, TransferEntryDiagnostic, measure_fastpq_source_statement_usage,
    preflight_fastpq_source_transcripts, prepare_transfer_archive_diagnostic,
};
pub(crate) use source_context::{FastpqBlockStartSourceContext, FastpqSourceCaptureAccumulator};
pub use source_context::{
    FastpqCapturedSourceRoute, FastpqCapturedTranscriptSource, FastpqSourceCaptureError,
};
#[cfg(test)]
mod digest_backend_tests;
#[cfg(test)]
mod source_statement_tests;
pub use crate::receiver_snapshot::FastpqSourceOpeningBuildLimits;
#[cfg(test)]
pub use crate::receiver_snapshot::{
    fastpq_ordinary_source_statement_archive_v1, fastpq_ordinary_source_statement_opening_v1,
};
use fastpq_prover::{
    Bn254PoseidonBatchSlice, OperationKind, PendingBn254PoseidonWordBatch, PublicInputs,
    StateTransition, TransitionBatch, gadgets::transfer::attach_transfer_smt_witnesses,
    try_hash_bn254_poseidon_word_batches, try_submit_bn254_poseidon_word_batches,
};
#[cfg(test)]
use iroha_config::parameters::actual::FastpqExecutionMode;
#[cfg(any(test, feature = "fastpq-gpu"))]
use iroha_config::parameters::actual::{Fastpq, FastpqPoseidonMode};
use iroha_crypto::Hash;
#[cfg(test)]
use iroha_data_model::account::AccountId;
#[cfg(test)]
use iroha_data_model::fastpq::{FastpqPublicTransferStatementV1, FastpqPublicTransferTranscriptV1};
use iroha_data_model::{
    asset::id::AssetDefinitionId,
    block::{BlockHeader, consensus::ExecWitness},
    fastpq::{
        FastpqOperationKind, FastpqPublicInputs, FastpqRolePermissionDelta, FastpqStateTransition,
        FastpqTransitionBatch, TRANSFER_TRANSCRIPTS_METADATA_KEY, TransferDeltaTranscript,
        TransferTranscript, TransferTranscriptBundle, normalized_numeric_to_u64,
        transfer_asset_scales, transfer_balance_key as balance_key,
    },
    role::{Role, RoleId},
};
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::numeric::Quantity;
use iroha_zkp_halo2::poseidon as halo2_poseidon;
use norito::{codec::Encode as NoritoEncode, to_bytes};
use std::{
    collections::BTreeMap,
    io::{self, Write},
    sync::atomic::{AtomicBool, Ordering},
};
use thiserror::Error;
const PERMISSION_TABLE_ROOT_DOMAIN: &[u8] = b"fastpq:v1:permission-table:blake2b-256";
/// Metadata key storing the originating entry hash for a batch.
pub const ENTRY_HASH_METADATA_KEY: &str = "entry_hash";
/// Metadata key storing the transcript count embedded in a batch.
pub const TRANSCRIPT_COUNT_METADATA_KEY: &str = "transcript_count";
/// Canonical FASTPQ parameter name used across the host and CLI helpers.
pub const FASTPQ_CANONICAL_PARAMETER_SET: &str = fastpq_isi::FASTPQ_FINAL_V1_ID;
/// Production rejection shared by host and block admission for unanchored remote spends.
pub(crate) const AXT_UNANCHORED_REMOTE_SPEND_REJECTION: &str = "handle-backed FASTPQ remote spend is unavailable until authoritative finalized source roots and transaction set, and fresh issuer authorization of the exact intent, proof, and effective amount, are authenticated";
const DIGEST_FINALIZE_PARALLEL_THRESHOLD: usize = 32;
const DIGEST_FINALIZE_GPU_THRESHOLD: usize = 64;
const POSEIDON_DIGEST_WORDS_PER_TRANSCRIPT_HINT: usize = 24;
static DIGEST_ACCELERATION_ENABLED: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static DIGEST_ACCELERATION_TEST_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(()));
/// Serialize tests that inspect digest acceleration or start a lane that changes it.
/// Keep this guard alive until the lane's worker and backend initialization finish.
#[cfg(test)]
struct DigestAccelerationTestGuard {
    previous: bool,
    _lock: std::sync::MutexGuard<'static, ()>,
}
#[cfg(test)]
impl DigestAccelerationTestGuard {
    fn new() -> Self {
        let lock = DIGEST_ACCELERATION_TEST_LOCK
            .lock()
            .expect("digest acceleration test lock poisoned");
        Self {
            previous: poseidon_digest_acceleration_enabled(),
            _lock: lock,
        }
    }
}
#[cfg(test)]
impl Drop for DigestAccelerationTestGuard {
    fn drop(&mut self) {
        set_poseidon_digest_acceleration_enabled(self.previous);
    }
}
/// Base fields for FASTPQ public inputs shared across batches in a block.
#[derive(Debug, Clone, Copy)]
pub struct FastpqPublicInputsTemplate {
    /// Data-space identifier (little-endian UUID bytes).
    pub dsid: [u8; 16],
    /// Slot timestamp (nanoseconds since epoch).
    pub slot: u64,
    /// Sparse Merkle tree root before executing the batch.
    pub old_root: [u8; 32],
    /// Sparse Merkle tree root after executing the batch.
    pub new_root: [u8; 32],
    /// Permission table commitment for this slot.
    pub perm_root: [u8; 32],
}
/// Local context needed to build FASTPQ batches outside the consensus commit path.
#[derive(Debug, Clone, Default)]
pub(crate) struct FastpqWitnessContext {
    /// Public-input fields shared by every FASTPQ batch in the witness.
    pub(crate) public_inputs: Option<FastpqPublicInputsTemplate>,
    /// Authoritative ordered canonical transaction-wire commitment from block execution.
    pub(crate) tx_set_hash: Option<[u8; 32]>,
    /// Per-source dataspaces keyed by execution-call or typed native-purpose identity.
    pub(crate) entry_dataspaces: BTreeMap<Hash, [u8; 16]>,
    /// Keep the validator-owned inventory alive through background queue processing.
    /// Ownership retention is the purpose of this field; batch construction uses the
    /// already-verified projections above. This grants no source-finality or admission authority.
    pub(crate) _source_inventory: Option<std::sync::Arc<crate::state::FastpqSourceInventoryV1>>,
}
impl FastpqPublicInputsTemplate {
    /// Build full public inputs using a precomputed transaction set hash.
    #[must_use]
    pub const fn with_tx_set_hash(self, tx_set_hash: [u8; 32]) -> FastpqPublicInputs {
        FastpqPublicInputs {
            dsid: self.dsid,
            slot: self.slot,
            old_root: self.old_root,
            new_root: self.new_root,
            perm_root: self.perm_root,
            tx_set_hash,
        }
    }
}
#[cfg(any(test, feature = "fastpq-gpu"))]
pub(crate) fn poseidon_digest_acceleration_configured(cfg: &Fastpq) -> bool {
    match cfg.poseidon_mode {
        FastpqPoseidonMode::Cpu => false,
        FastpqPoseidonMode::Gpu => true,
    }
}
pub(crate) fn set_poseidon_digest_acceleration_enabled(enabled: bool) {
    DIGEST_ACCELERATION_ENABLED.store(enabled, Ordering::Release);
}
pub(crate) fn axt_proof_payload_exceeds_decode_limit(payload: &[u8]) -> bool {
    payload.len() > fastpq_prover::MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES
}
#[inline]
fn poseidon_digest_acceleration_enabled() -> bool {
    DIGEST_ACCELERATION_ENABLED.load(Ordering::Acquire)
}
/// Errors that can occur while mapping transfer transcripts into FASTPQ transition batches.
#[derive(Debug, Error)]
pub enum TranscriptBatchError {
    /// Encountered a quantity that cannot be normalized into FASTPQ witness units.
    #[error("quantity `{value}` cannot be normalized into 64-bit FASTPQ witness units")]
    NumericEncoding {
        /// Quantity that fell outside the FASTPQ prover's supported range.
        value: Quantity,
    },
    /// Norito serialization of a canonical balance key or transcript metadata failed.
    #[error("failed to encode canonical transfer identity or transcript metadata")]
    MetadataEncoding {
        /// Underlying Norito error.
        #[from]
        source: norito::core::Error,
    },
    /// Transfer SMT witness materialization failed.
    #[error("failed to attach transfer SMT witnesses")]
    TransferWitness {
        /// Underlying FASTPQ prover error.
        source: fastpq_prover::Error,
    },
    /// Ordering commitment for a produced public statement failed.
    #[error("failed to commit the complete public transition ordering")]
    PublicStatementOrdering {
        /// Underlying FASTPQ ordering commitment error.
        source: fastpq_prover::Error,
    },
    /// Execution witness does not carry precomputed FASTPQ batches.
    #[error("execution witness missing fastpq batches with public inputs")]
    MissingFastpqBatches,
    /// Block execution did not supply a non-zero ordered canonical transaction-wire commitment.
    #[error("execution witness missing authoritative ordered transaction-wire commitment")]
    MissingTransactionSetCommitment,
    /// Precomputed batches do not align one-for-one with transcript bundles.
    #[error(
        "execution witness FASTPQ batch cardinality mismatch: {bundle_count} bundles, {batch_count} batches"
    )]
    FastpqBatchCardinality {
        /// Number of transcript bundles in the witness.
        bundle_count: usize,
        /// Number of precomputed batches in the witness.
        batch_count: usize,
    },
    /// A precomputed batch does not prove the transcript bundle at the same position.
    #[error("execution witness FASTPQ batch {batch_index} is not bound to its transcript bundle")]
    FastpqBatchBinding {
        /// Position of the malformed batch in the witness.
        batch_index: usize,
    },
}
/// Canonical model-owned FASTPQ authority preimage, shared with portable readers.
pub use iroha_data_model::block::proofs::fastpq_authority_digest_v1 as authority_digest;
/// Compute the Poseidon digest of a transfer delta preimage.
#[inline(always)]
#[must_use]
pub fn poseidon_preimage_digest(delta: &TransferDeltaTranscript, batch_hash: &Hash) -> Hash {
    let mut scratch = PoseidonDigestScratch::default();
    poseidon_preimage_digest_with_scratch(delta, batch_hash, &mut scratch)
}
/// Reusable scratch space for canonical single-transfer Poseidon digests.
#[derive(Debug, Default)]
pub(crate) struct PoseidonDigestScratch {
    words: Vec<u64>,
}
/// Compute the canonical Poseidon digest using caller-owned scratch storage.
#[inline(always)]
#[must_use]
pub(crate) fn poseidon_preimage_digest_with_scratch(
    delta: &TransferDeltaTranscript,
    batch_hash: &Hash,
    scratch: &mut PoseidonDigestScratch,
) -> Hash {
    scratch.words.clear();
    scratch
        .words
        .reserve(POSEIDON_DIGEST_WORDS_PER_TRANSCRIPT_HINT);
    append_transfer_digest_words(&mut scratch.words, delta, batch_hash);
    Hash::prehashed(halo2_poseidon::hash_u64_words_bytes(&scratch.words))
}
#[inline(always)]
fn append_encoded_words<W, T>(writer: &mut W, value: &T)
where
    W: Write,
    T: NoritoEncode,
{
    value.encode_to(writer);
}
#[inline(always)]
fn u64_from_le_bytes(bytes: &[u8]) -> u64 {
    debug_assert!(bytes.len() >= 8);
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}
#[inline(always)]
fn partial_u64_from_le_bytes(bytes: &[u8; 8], len: usize) -> u64 {
    debug_assert!(len <= bytes.len());
    let word = u64::from_le_bytes(*bytes);
    match len {
        0 => 0,
        8 => word,
        _ => word & ((1u64 << (len * 8)) - 1),
    }
}
#[derive(Debug)]
struct PoseidonWordPacker<'a> {
    words: &'a mut Vec<u64>,
    pending_bytes: [u8; 8],
    pending_len: usize,
}
impl<'a> PoseidonWordPacker<'a> {
    #[inline]
    fn new(words: &'a mut Vec<u64>) -> Self {
        Self {
            words,
            pending_bytes: [0; 8],
            pending_len: 0,
        }
    }
    #[inline]
    fn update(&mut self, mut bytes: &[u8]) {
        if self.pending_len > 0 {
            let needed = self.pending_bytes.len() - self.pending_len;
            let take = needed.min(bytes.len());
            self.pending_bytes[self.pending_len..self.pending_len + take]
                .copy_from_slice(&bytes[..take]);
            self.pending_len += take;
            bytes = &bytes[take..];
            if self.pending_len == self.pending_bytes.len() {
                self.words.push(u64::from_le_bytes(self.pending_bytes));
                self.pending_len = 0;
            }
        }
        let mut chunks = bytes.chunks_exact(8);
        for chunk in &mut chunks {
            self.words.push(u64_from_le_bytes(chunk));
        }
        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            self.pending_bytes[..remainder.len()].copy_from_slice(remainder);
            self.pending_len = remainder.len();
        }
    }
    #[inline]
    fn finish(self) {
        let delimiter_word = partial_u64_from_le_bytes(&self.pending_bytes, self.pending_len)
            | (1u64 << (self.pending_len * 8));
        self.words.push(delimiter_word);
    }
}
impl Write for PoseidonWordPacker<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[cfg(test)]
fn transfer_digest_words(delta: &TransferDeltaTranscript, batch_hash: &Hash) -> Vec<u64> {
    let mut words = Vec::with_capacity(POSEIDON_DIGEST_WORDS_PER_TRANSCRIPT_HINT);
    append_transfer_digest_words(&mut words, delta, batch_hash);
    words
}
fn append_transfer_digest_words(
    words: &mut Vec<u64>,
    delta: &TransferDeltaTranscript,
    batch_hash: &Hash,
) {
    let mut packer = PoseidonWordPacker::new(words);
    append_encoded_words(&mut packer, &delta.from_account);
    append_encoded_words(&mut packer, &delta.to_account);
    append_encoded_words(&mut packer, &delta.asset_definition);
    append_encoded_words(&mut packer, &delta.amount);
    packer.update(batch_hash.as_ref());
    packer.finish();
}
#[derive(Debug, Default, PartialEq, Eq)]
struct PoseidonDigestBatch {
    words: Vec<u64>,
    slices: Vec<Bn254PoseidonBatchSlice>,
}
impl PoseidonDigestBatch {
    fn with_capacity(digest_count: usize) -> Self {
        Self {
            words: Vec::with_capacity(
                digest_count.saturating_mul(POSEIDON_DIGEST_WORDS_PER_TRANSCRIPT_HINT),
            ),
            slices: Vec::with_capacity(digest_count),
        }
    }
    fn push(&mut self, delta: &TransferDeltaTranscript, batch_hash: &Hash) {
        let offset = self.words.len();
        append_transfer_digest_words(&mut self.words, delta, batch_hash);
        self.slices.push(Bn254PoseidonBatchSlice::new(
            offset,
            self.words.len() - offset,
        ));
    }
    fn try_hash_gpu(&self) -> Option<Vec<Hash>> {
        self.try_gpu_batch(try_hash_bn254_poseidon_word_batches)
            .and_then(|digests| self.accept_gpu_digests(Some(digests)))
    }
    fn try_gpu_batch<T>(
        &self,
        submit: impl FnOnce(&[u64], &[Bn254PoseidonBatchSlice]) -> Option<T>,
    ) -> Option<T> {
        if self.slices.len() < DIGEST_FINALIZE_GPU_THRESHOLD
            || !poseidon_digest_acceleration_enabled()
        {
            return None;
        }
        match submit(&self.words, &self.slices) {
            Some(output) => Some(output),
            None => {
                set_poseidon_digest_acceleration_enabled(false);
                None
            }
        }
    }
    // Never install a prefix or ignore trailing accelerator output. A cardinality
    // failure quarantines acceleration; the caller recomputes the entire batch.
    fn accept_gpu_digests(&self, digests: Option<Vec<[u8; 32]>>) -> Option<Vec<Hash>> {
        match digests {
            Some(digests) if digests.len() == self.slices.len() => {
                Some(digests.into_iter().map(Hash::prehashed).collect())
            }
            _ => {
                set_poseidon_digest_acceleration_enabled(false);
                None
            }
        }
    }
    fn resolve_pending_or_cpu(
        &self,
        current: &Self,
        wait: impl FnOnce() -> Option<Vec<[u8; 32]>>,
    ) -> Vec<Hash> {
        // Count equality alone does not bind a pending result to its current
        // preimages. Compare all packed words and ordered slice boundaries.
        if self != current {
            // Drop the unused pending handle before CPU work. Metal's owned handle
            // waits for completion before releasing staged buffers, without reading
            // stale digest bytes; this is safe cleanup, not asynchronous cancellation.
            drop(wait);
            return current.hash_cpu();
        }
        current
            .accept_gpu_digests(wait())
            .unwrap_or_else(|| current.hash_cpu())
    }
    fn hash_cpu_or_gpu(&self) -> Vec<Hash> {
        self.try_hash_gpu().unwrap_or_else(|| self.hash_cpu())
    }
    fn try_submit_gpu(&self) -> Option<PendingBn254PoseidonWordBatch> {
        self.try_gpu_batch(try_submit_bn254_poseidon_word_batches)
    }
    fn hash_cpu(&self) -> Vec<Hash> {
        if self.slices.len() >= DIGEST_FINALIZE_PARALLEL_THRESHOLD {
            use rayon::prelude::*;
            return self
                .slices
                .par_iter()
                .map(|slice| {
                    let offset = slice.offset();
                    let end = offset + slice.len();
                    Hash::prehashed(halo2_poseidon::hash_u64_words_bytes(
                        &self.words[offset..end],
                    ))
                })
                .collect();
        }
        self.slices
            .iter()
            .map(|slice| {
                let offset = slice.offset();
                let end = offset + slice.len();
                Hash::prehashed(halo2_poseidon::hash_u64_words_bytes(
                    &self.words[offset..end],
                ))
            })
            .collect()
    }
}
/// Pending FASTPQ transfer transcript digest batch.
pub(crate) struct PendingTransferTranscriptDigests {
    batch: PoseidonDigestBatch,
    pending: PendingBn254PoseidonWordBatch,
}
impl PendingTransferTranscriptDigests {
    fn into_digests(self, current: &PoseidonDigestBatch) -> Vec<Hash> {
        let Self { batch, pending } = self;
        batch.resolve_pending_or_cpu(current, || pending.wait())
    }
}
/// Fill missing single-delta transcript digests before block or witness data is exposed.
pub(crate) fn finalize_transfer_transcript_digests_in_map(
    transcripts: &mut BTreeMap<Hash, Vec<TransferTranscript>>,
) {
    let pending = try_submit_transfer_transcript_digests_in_map(transcripts);
    finalize_transfer_transcript_digests_in_map_with_pending(transcripts, pending);
}
/// Fill missing single-delta transcript digests using a previously submitted GPU batch.
pub(crate) fn finalize_transfer_transcript_digests_in_map_with_pending(
    transcripts: &mut BTreeMap<Hash, Vec<TransferTranscript>>,
    pending: Option<PendingTransferTranscriptDigests>,
) {
    #[cfg(debug_assertions)]
    for entries in transcripts.values() {
        debug_assert_precomputed_transfer_transcript_digests(entries);
    }
    let digest_count = transcripts
        .values()
        .map(|entries| missing_single_delta_transcript_count(entries))
        .sum::<usize>();
    if digest_count == 0 {
        return;
    }
    if let Some(pending) = pending {
        let mut current = PoseidonDigestBatch::with_capacity(digest_count);
        for entries in transcripts.values() {
            collect_transfer_transcript_digests(entries, &mut current);
        }
        let digests = pending.into_digests(&current);
        if apply_transfer_transcript_digests_in_map(transcripts, digests) {
            return;
        }
    }
    if digest_count >= DIGEST_FINALIZE_PARALLEL_THRESHOLD
        && try_finalize_transfer_transcript_digests_in_map_batched(transcripts, digest_count)
    {
        return;
    }
    if digest_count >= DIGEST_FINALIZE_PARALLEL_THRESHOLD {
        use rayon::prelude::*;
        transcripts
            .values_mut()
            .collect::<Vec<_>>()
            .into_par_iter()
            .for_each(|entries| finalize_transfer_transcripts_serial(entries));
    } else {
        for entries in transcripts.values_mut() {
            finalize_transfer_transcripts_serial(entries);
        }
    }
}
/// Submit missing single-delta transcript digests without waiting for completion.
pub(crate) fn try_submit_transfer_transcript_digests_in_map(
    transcripts: &BTreeMap<Hash, Vec<TransferTranscript>>,
) -> Option<PendingTransferTranscriptDigests> {
    if !poseidon_digest_acceleration_enabled() {
        return None;
    }
    let digest_count = transcripts
        .values()
        .map(|entries| missing_single_delta_transcript_count(entries))
        .sum::<usize>();
    if digest_count < DIGEST_FINALIZE_GPU_THRESHOLD {
        return None;
    }
    let mut batch = PoseidonDigestBatch::with_capacity(digest_count);
    for entries in transcripts.values() {
        collect_transfer_transcript_digests(entries, &mut batch);
    }
    let pending = batch.try_submit_gpu()?;
    Some(PendingTransferTranscriptDigests { batch, pending })
}
/// Fill missing single-delta transcript digests in witness bundles.
#[cfg(any(test, feature = "telemetry"))]
pub(crate) fn finalize_transfer_transcript_bundle_digests_in_place(
    bundles: &mut [TransferTranscriptBundle],
) {
    #[cfg(debug_assertions)]
    for bundle in bundles.iter() {
        debug_assert_precomputed_transfer_transcript_digests(&bundle.transcripts);
    }
    let digest_count = bundles
        .iter()
        .map(|bundle| missing_single_delta_transcript_count(&bundle.transcripts))
        .sum::<usize>();
    if digest_count == 0 {
        return;
    }
    if digest_count >= DIGEST_FINALIZE_PARALLEL_THRESHOLD
        && try_finalize_transfer_transcript_bundle_digests_batched(bundles, digest_count)
    {
        return;
    }
    if digest_count >= DIGEST_FINALIZE_PARALLEL_THRESHOLD {
        use rayon::prelude::*;
        bundles
            .par_iter_mut()
            .for_each(|bundle| finalize_transfer_transcripts_serial(&mut bundle.transcripts));
    } else {
        for bundle in bundles {
            finalize_transfer_transcripts_serial(&mut bundle.transcripts);
        }
    }
}
fn try_finalize_transfer_transcript_digests_in_map_batched(
    transcripts: &mut BTreeMap<Hash, Vec<TransferTranscript>>,
    digest_count: usize,
) -> bool {
    debug_assert!(digest_count >= DIGEST_FINALIZE_PARALLEL_THRESHOLD);
    let mut batch = PoseidonDigestBatch::with_capacity(digest_count);
    for entries in transcripts.values() {
        collect_transfer_transcript_digests(entries, &mut batch);
    }
    let digests = batch.hash_cpu_or_gpu();
    apply_transfer_transcript_digests_in_map(transcripts, digests)
}
#[cfg(any(test, feature = "telemetry"))]
fn try_finalize_transfer_transcript_bundle_digests_batched(
    bundles: &mut [TransferTranscriptBundle],
    digest_count: usize,
) -> bool {
    debug_assert!(digest_count >= DIGEST_FINALIZE_PARALLEL_THRESHOLD);
    let mut batch = PoseidonDigestBatch::with_capacity(digest_count);
    for bundle in bundles.iter() {
        collect_transfer_transcript_digests(&bundle.transcripts, &mut batch);
    }
    let digests = batch.hash_cpu_or_gpu();
    apply_transfer_transcript_bundle_digests(bundles, digests)
}
fn missing_single_delta_transcript_count(transcripts: &[TransferTranscript]) -> usize {
    transcripts
        .iter()
        .filter(|transcript| needs_transfer_transcript_digest(transcript))
        .count()
}
fn is_single_delta_transcript(transcript: &TransferTranscript) -> bool {
    matches!(transcript.deltas.as_slice(), [_])
}
fn needs_transfer_transcript_digest(transcript: &TransferTranscript) -> bool {
    transcript.poseidon_preimage_digest.is_none() && is_single_delta_transcript(transcript)
}
fn collect_transfer_transcript_digests(
    transcripts: &[TransferTranscript],
    batch: &mut PoseidonDigestBatch,
) {
    for transcript in transcripts {
        if transcript.poseidon_preimage_digest.is_some() {
            continue;
        }
        let [delta] = transcript.deltas.as_slice() else {
            continue;
        };
        batch.push(delta, &transcript.batch_hash);
    }
}
fn apply_transfer_transcript_digests_in_map(
    transcripts: &mut BTreeMap<Hash, Vec<TransferTranscript>>,
    digests: Vec<Hash>,
) -> bool {
    let expected = transcripts.values().try_fold(0usize, |count, entries| {
        count.checked_add(missing_single_delta_transcript_count(entries))
    });
    if expected != Some(digests.len()) {
        return false;
    }
    let mut digests = digests.into_iter();
    for entries in transcripts.values_mut() {
        if !apply_transfer_transcript_digests(entries, &mut digests) {
            return false;
        }
    }
    digests.len() == 0
}
#[cfg(any(test, feature = "telemetry"))]
fn apply_transfer_transcript_bundle_digests(
    bundles: &mut [TransferTranscriptBundle],
    digests: Vec<Hash>,
) -> bool {
    let expected = bundles.iter().try_fold(0usize, |count, bundle| {
        count.checked_add(missing_single_delta_transcript_count(&bundle.transcripts))
    });
    if expected != Some(digests.len()) {
        return false;
    }
    let mut digests = digests.into_iter();
    for bundle in bundles {
        if !apply_transfer_transcript_digests(&mut bundle.transcripts, &mut digests) {
            return false;
        }
    }
    digests.len() == 0
}
fn apply_transfer_transcript_digests(
    transcripts: &mut [TransferTranscript],
    digests: &mut std::vec::IntoIter<Hash>,
) -> bool {
    // The concrete Vec iterator has an exact remaining length. Check it before
    // any mutation, even when this helper is used independently of a whole batch.
    if digests.len() < missing_single_delta_transcript_count(transcripts) {
        return false;
    }
    for transcript in transcripts {
        if needs_transfer_transcript_digest(transcript) {
            let Some(digest) = digests.next() else {
                return false;
            };
            set_transfer_transcript_digest(transcript, digest);
        }
    }
    true
}
fn finalize_transfer_transcripts_serial(transcripts: &mut [TransferTranscript]) {
    let mut scratch = PoseidonDigestScratch::default();
    for transcript in transcripts {
        finalize_transfer_transcript_digest_with_scratch(transcript, &mut scratch);
    }
}
fn finalize_transfer_transcript_digest_with_scratch(
    transcript: &mut TransferTranscript,
    scratch: &mut PoseidonDigestScratch,
) {
    let [delta] = transcript.deltas.as_slice() else {
        return;
    };
    if transcript.poseidon_preimage_digest.is_some() {
        #[cfg(debug_assertions)]
        {
            let existing = transcript
                .poseidon_preimage_digest
                .expect("digest presence checked above");
            debug_assert_eq!(
                existing,
                poseidon_preimage_digest_with_scratch(delta, &transcript.batch_hash, scratch),
                "precomputed FASTPQ transfer transcript digest must match canonical digest",
            );
        }
        return;
    }
    let digest = poseidon_preimage_digest_with_scratch(delta, &transcript.batch_hash, scratch);
    set_transfer_transcript_digest(transcript, digest);
}
fn set_transfer_transcript_digest(transcript: &mut TransferTranscript, digest: Hash) {
    if let Some(existing) = transcript.poseidon_preimage_digest {
        debug_assert_eq!(
            existing, digest,
            "precomputed FASTPQ transfer transcript digest must match canonical digest",
        );
    } else {
        transcript.poseidon_preimage_digest = Some(digest);
    }
}
#[cfg(debug_assertions)]
fn debug_assert_precomputed_transfer_transcript_digests(transcripts: &[TransferTranscript]) {
    let mut scratch = PoseidonDigestScratch::default();
    for transcript in transcripts {
        let Some(existing) = transcript.poseidon_preimage_digest else {
            continue;
        };
        let [delta] = transcript.deltas.as_slice() else {
            continue;
        };
        debug_assert_eq!(
            existing,
            poseidon_preimage_digest_with_scratch(delta, &transcript.batch_hash, &mut scratch),
            "precomputed FASTPQ transfer transcript digest must match canonical digest",
        );
    }
}
/// Validate supplied single-delta digests before sealing owned source transcripts.
///
/// This check never repairs or mutates a supplied digest. Missing digests retain
/// the existing finalizer path; the strict producer owns multi-delta digest policy.
/// Canonical CPU hashing is intentional here, independently of acceleration mode.
///
/// # Errors
/// Rejects a supplied single-delta digest that differs from its canonical preimage.
pub(crate) fn validate_precomputed_transfer_transcript_digests_in_map(
    transcripts: &BTreeMap<Hash, Vec<TransferTranscript>>,
) -> Result<(), String> {
    let mut scratch = PoseidonDigestScratch::default();
    for transcript in transcripts.values().flatten() {
        let Some(existing) = transcript.poseidon_preimage_digest else {
            continue;
        };
        let [delta] = transcript.deltas.as_slice() else {
            continue;
        };
        if existing
            != poseidon_preimage_digest_with_scratch(delta, &transcript.batch_hash, &mut scratch)
        {
            return Err(
                "FASTPQ precomputed transfer transcript digest differs from its canonical preimage"
                    .into(),
            );
        }
    }
    Ok(())
}
/// Build a FASTPQ public input template for the supplied block witness.
#[must_use]
pub fn public_inputs_template_from_block(
    header: &BlockHeader,
    witness: &ExecWitness,
    perm_root: [u8; 32],
) -> FastpqPublicInputsTemplate {
    let creation_ms = u64::try_from(header.creation_time().as_millis()).unwrap_or(u64::MAX);
    let slot = creation_ms.saturating_mul(1_000_000);
    let old_root = crate::exec_witness::roots::parent_state_from_witness(witness);
    let new_root = crate::exec_witness::roots::post_state_from_witness(witness);
    FastpqPublicInputsTemplate {
        dsid: dataspace_id_bytes(DataSpaceId::UNIVERSAL),
        slot,
        old_root: old_root.into(),
        new_root: new_root.into(),
        perm_root,
    }
}
pub(crate) fn dataspace_id_bytes(dsid: DataSpaceId) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&dsid.as_u64().to_le_bytes());
    out
}
pub(crate) fn permission_table_root<'a, I>(roles: I) -> [u8; 32]
where
    I: IntoIterator<Item = (&'a RoleId, &'a Role)>,
{
    let mut entries = Vec::new();
    for (role_id, role) in roles {
        let role_bytes = hash_encoded(role_id);
        for permission in &role.permissions {
            let epoch = role.permission_epoch(permission).unwrap_or_default();
            entries.push(PermissionTableEntry {
                role_bytes,
                permission_bytes: hash_encoded(permission),
                epoch_bytes: epoch.to_le_bytes(),
            });
        }
    }
    if entries.is_empty() {
        return [0u8; 32];
    }
    entries.sort_unstable_by(|left, right| {
        (left.role_bytes, left.permission_bytes, left.epoch_bytes).cmp(&(
            right.role_bytes,
            right.permission_bytes,
            right.epoch_bytes,
        ))
    });
    // Every entry has the fixed width 32 + 32 + 8. Bind the number of entries
    // as well as their order, without a scalar-field projection or duplicate-last
    // Merkle padding. This is contextual public input; the transfer AIR does not
    // establish permission membership or authorization from this commitment.
    let mut payload = Vec::new();
    payload.extend_from_slice(PERMISSION_TABLE_ROOT_DOMAIN);
    payload.extend_from_slice(
        &u64::try_from(entries.len())
            .expect("permission entry count fits u64")
            .to_le_bytes(),
    );
    for entry in entries {
        payload.extend_from_slice(&entry.role_bytes);
        payload.extend_from_slice(&entry.permission_bytes);
        payload.extend_from_slice(&entry.epoch_bytes);
    }
    Hash::new(payload).into()
}
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_field_names)]
struct PermissionTableEntry {
    role_bytes: [u8; 32],
    permission_bytes: [u8; 32],
    epoch_bytes: [u8; 8],
}
fn hash_encoded<T: NoritoEncode>(value: &T) -> [u8; 32] {
    let hash = Hash::new(value.encode());
    hash.into()
}
#[cfg(test)]
fn public_inputs_from_template(
    template: FastpqPublicInputsTemplate,
    tx_set_hash: [u8; 32],
) -> FastpqPublicInputs {
    template.with_tx_set_hash(tx_set_hash)
}
/// Convert a collection of transfer transcripts into a canonical FASTPQ transition batch.
///
/// The caller is responsible for supplying `public_inputs` and threading metadata
/// (entry hash, transcript count, etc.) into the returned batch if required by downstream consumers.
///
/// # Errors
/// Returns [`TranscriptBatchError`] if any transcript fails to append to the batch.
pub fn batch_from_transcripts<'a, I>(
    parameter_set: impl Into<String>,
    public_inputs: FastpqPublicInputs,
    transcripts: I,
) -> Result<TransitionBatch, TranscriptBatchError>
where
    I: IntoIterator<Item = &'a TransferTranscript>,
{
    build_transfer_batch_with_projection(parameter_set, public_inputs, transcripts, |_| ())
        .map(|(batch, ())| batch)
}
#[cfg(test)]
/// Produce a private prover batch and its separate, path-free public statement.
///
/// The public statement is projected directly from the same finalized in-memory
/// transcript occurrences used by the batch, before private metadata encoding.
/// It retains their order and multiplicity, the complete sorted transition table,
/// and all seven public inputs, including an independently computed ordering hash.
///
/// These are producer outputs, not authenticated claims or verification results.
/// As in [`batch_from_transcripts`], SMT attachment replaces captured repeated-key
/// balance quantities with the chained quantities and replaces the supplied old/new
/// roots with touched-tree roots. The statement describes those produced values;
/// it does not attest that they equal the captured balances or finalized ledger
/// state. The caller's input transcripts remain unchanged.
///
/// This helper neither selects an admitted compact profile nor applies its public
/// statement limits. Consumers must perform bounded public preparation and obtain
/// trusted source-state expectations separately. This transfer-only factory does
/// not accept existing batches or their metadata effects. An empty transcript collection
/// keeps the existing empty-batch behavior; it is not silently admitted as a proof.
///
/// # Errors
/// Returns the same construction errors as [`batch_from_transcripts`], or
/// [`TranscriptBatchError::PublicStatementOrdering`] if ordering commitment fails.
pub fn batch_and_public_statement_from_transcripts<'a, I>(
    parameter_set: impl Into<String>,
    public_inputs: FastpqPublicInputs,
    transcripts: I,
) -> Result<(TransitionBatch, FastpqPublicTransferStatementV1), TranscriptBatchError>
where
    I: IntoIterator<Item = &'a TransferTranscript>,
{
    let (batch, transcripts) = build_transfer_batch_with_projection(
        parameter_set,
        public_inputs,
        transcripts,
        |finalized| {
            finalized
                .iter()
                .map(FastpqPublicTransferTranscriptV1::from)
                .collect::<Vec<_>>()
        },
    )?;
    let ordering_hash = fastpq_prover::ordering_hash(&batch)
        .map_err(|source| TranscriptBatchError::PublicStatementOrdering { source })?
        .into();
    let statement = FastpqPublicTransferStatementV1 {
        public_inputs: public_inputs_to_dto(&batch.public_inputs),
        ordering_hash,
        transitions: batch
            .transitions
            .iter()
            .map(state_transition_to_dto)
            .collect(),
        transcripts,
    };
    Ok((batch, statement))
}
#[cfg(test)]
/// Failure to produce an exact public projection of finalized transfer facts.
#[derive(Debug, Error)]
pub enum FinalizedPublicStatementError {
    /// The existing private batch/public statement construction failed.
    #[error(transparent)]
    Batch(#[from] TranscriptBatchError),
    /// SMT chaining or digest finalization changed an original public occurrence.
    #[error("finalized FASTPQ public transcript changed at occurrence {transcript_index}")]
    ProjectionMismatch {
        /// First differing occurrence, or the first missing/extra occurrence.
        transcript_index: usize,
    },
}

#[cfg(test)]
/// Produce a private batch and an exact public projection of finalized transcripts.
///
/// Unlike the repair-capable producer, this entry point rejects any change to original
/// quantities, account/asset identities, occurrence order, authority digests or optional
/// preimage digests. Callers must finalize single-delta digests before invoking it. Private
/// SMT paths may be rebuilt; old/new public roots still describe the touched-balance tree,
/// and all other caller public inputs retain the existing producer semantics.
///
/// This is a local construction check, not authentication of ledger balances, caller
/// authority or source finality. It neither qualifies a compact profile nor installs
/// production proof admission. Empty input retains the existing empty-batch behavior;
/// the caller must represent empty source manifests separately from admitted proofs.
///
/// # Errors
/// Returns the underlying batch error, or the first original public occurrence changed
/// by construction. No batch or public statement is returned on a mismatch.
pub fn batch_and_public_statement_from_finalized_transcripts<'a, I>(
    parameter_set: impl Into<String>,
    public_inputs: FastpqPublicInputs,
    transcripts: I,
) -> Result<(TransitionBatch, FastpqPublicTransferStatementV1), FinalizedPublicStatementError>
where
    I: IntoIterator<Item = &'a TransferTranscript>,
{
    let originals = transcripts.into_iter().collect::<Vec<_>>();
    let (batch, statement) = batch_and_public_statement_from_transcripts(
        parameter_set,
        public_inputs,
        originals.iter().copied(),
    )?;
    validate_finalized_public_transcript_projection(&originals, &statement.transcripts)?;
    Ok((batch, statement))
}

#[cfg(test)]
fn validate_finalized_public_transcript_projection(
    originals: &[&TransferTranscript],
    projected: &[FastpqPublicTransferTranscriptV1],
) -> Result<(), FinalizedPublicStatementError> {
    for (transcript_index, (original, produced)) in originals.iter().zip(projected).enumerate() {
        let same_header = original.batch_hash == produced.batch_hash
            && original.authority_digest == produced.authority_digest
            && original.poseidon_preimage_digest == produced.poseidon_preimage_digest;
        let same_deltas = original.deltas.len() == produced.deltas.len()
            && original
                .deltas
                .iter()
                .zip(&produced.deltas)
                .all(|(left, right)| {
                    left.from_account == right.from_account
                        && left.to_account == right.to_account
                        && left.asset_definition == right.asset_definition
                        && left.amount == right.amount
                        && left.from_balance_before == right.from_balance_before
                        && left.from_balance_after == right.from_balance_after
                        && left.to_balance_before == right.to_balance_before
                        && left.to_balance_after == right.to_balance_after
                });
        if !same_header || !same_deltas {
            return Err(FinalizedPublicStatementError::ProjectionMismatch { transcript_index });
        }
    }
    if originals.len() != projected.len() {
        return Err(FinalizedPublicStatementError::ProjectionMismatch {
            transcript_index: originals.len().min(projected.len()),
        });
    }
    Ok(())
}

/// Share the exact construction sequence across production batch projections.
fn build_transfer_batch_with_projection<'a, I, P>(
    parameter_set: impl Into<String>,
    public_inputs: FastpqPublicInputs,
    transcripts: I,
    project_finalized: impl FnOnce(&[TransferTranscript]) -> P,
) -> Result<(TransitionBatch, P), TranscriptBatchError>
where
    I: IntoIterator<Item = &'a TransferTranscript>,
{
    let mut transcripts: Vec<TransferTranscript> = transcripts.into_iter().cloned().collect();
    let asset_scales = transfer_asset_scales(&transcripts);
    let transfer_roots = if transcripts.is_empty() {
        None
    } else {
        Some(
            attach_transfer_smt_witnesses(&mut transcripts)
                .map_err(|source| TranscriptBatchError::TransferWitness { source })?,
        )
    };
    finalize_transfer_transcripts_serial(&mut transcripts);
    let mut batch = TransitionBatch::new(parameter_set, public_inputs_from_dto(&public_inputs));
    if let Some((old_root, new_root)) = transfer_roots {
        batch.public_inputs.old_root = old_root;
        batch.public_inputs.new_root = new_root;
    }
    for transcript in &transcripts {
        append_transcript(&mut batch, transcript, &asset_scales)?;
    }
    let projection = project_finalized(&transcripts);
    attach_transcript_metadata(&mut batch, transcripts)?;
    batch.sort();
    Ok((batch, projection))
}
/// Build a FASTPQ batch from a committed transcript bundle and attach the entry-level metadata
/// required by AXT proof binding.
///
/// This is the public reconstruction form used by recovery surfaces when compact sidecars retain
/// public inputs but omit transition rows.
///
/// # Errors
/// Returns [`TranscriptBatchError`] if any transcript fails to append to the batch.
pub fn batch_from_transcript_bundle(
    parameter_set: impl Into<String>,
    public_inputs: PublicInputs,
    entry_hash: Hash,
    transcripts: &[TransferTranscript],
) -> Result<TransitionBatch, TranscriptBatchError> {
    let mut batch = batch_from_transcripts(
        parameter_set,
        public_inputs_to_dto(&public_inputs),
        transcripts,
    )?;
    annotate_metadata(&mut batch, &entry_hash, transcripts.len());
    Ok(batch)
}
fn append_transcript(
    batch: &mut TransitionBatch,
    transcript: &TransferTranscript,
    asset_scales: &BTreeMap<AssetDefinitionId, u32>,
) -> Result<(), TranscriptBatchError> {
    for delta in &transcript.deltas {
        let target_scale = asset_scales
            .get(&delta.asset_definition)
            .copied()
            .unwrap_or_else(|| delta.normalized_scale());
        push_transfer_delta(batch, delta, target_scale)?;
    }
    Ok(())
}
#[allow(clippy::needless_pass_by_value)]
fn attach_transcript_metadata(
    batch: &mut TransitionBatch,
    transcripts: Vec<TransferTranscript>,
) -> Result<(), TranscriptBatchError> {
    if transcripts.is_empty() {
        return Ok(());
    }
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let encoded = to_bytes(&transcripts)?;
    batch
        .metadata
        .insert(TRANSFER_TRANSCRIPTS_METADATA_KEY.into(), encoded);
    Ok(())
}
fn push_transfer_delta(
    batch: &mut TransitionBatch,
    delta: &TransferDeltaTranscript,
    target_scale: u32,
) -> Result<(), TranscriptBatchError> {
    let from_key = balance_key(&delta.asset_definition, &delta.from_account)?;
    let to_key = balance_key(&delta.asset_definition, &delta.to_account)?;
    let from_pre = encode_numeric_le(&delta.from_balance_before, target_scale)?;
    let from_post = encode_numeric_le(&delta.from_balance_after, target_scale)?;
    let to_pre = encode_numeric_le(&delta.to_balance_before, target_scale)?;
    let to_post = encode_numeric_le(&delta.to_balance_after, target_scale)?;
    batch.push(StateTransition::new(
        from_key,
        from_pre,
        from_post,
        OperationKind::Transfer,
    ));
    batch.push(StateTransition::new(
        to_key,
        to_pre,
        to_post,
        OperationKind::Transfer,
    ));
    Ok(())
}
fn encode_numeric_le(value: &Quantity, target_scale: u32) -> Result<Vec<u8>, TranscriptBatchError> {
    let integer = normalized_numeric_to_u64(value.as_numeric(), target_scale).ok_or_else(|| {
        TranscriptBatchError::NumericEncoding {
            value: value.clone(),
        }
    })?;
    Ok(integer.to_le_bytes().to_vec())
}
/// Convert the FASTPQ batches stored in an [`ExecWitness`] into prover batches.
///
/// # Errors
/// Returns [`TranscriptBatchError::MissingFastpqBatches`] when transcripts are present
/// without prebuilt batches.
pub fn batches_from_exec_witness(
    witness: &ExecWitness,
) -> Result<Vec<TransitionBatch>, TranscriptBatchError> {
    if !witness.fastpq_batches.is_empty() {
        let batches = witness
            .fastpq_batches
            .iter()
            .map(transition_batch_from_dto)
            .collect::<Vec<_>>();
        validate_prebuilt_batch_bindings(&witness.fastpq_transcripts, &batches)?;
        return Ok(batches);
    }
    if witness.fastpq_transcripts.is_empty() {
        return Ok(Vec::new());
    }
    Err(TranscriptBatchError::MissingFastpqBatches)
}

fn validate_prebuilt_batch_bindings(
    bundles: &[TransferTranscriptBundle],
    batches: &[TransitionBatch],
) -> Result<(), TranscriptBatchError> {
    // Transcript-free witnesses are a supported proof-only audit surface, so there is no outer
    // bundle identity to validate in that form.
    if bundles.is_empty() {
        return Ok(());
    }
    if bundles.len() != batches.len() {
        return Err(TranscriptBatchError::FastpqBatchCardinality {
            bundle_count: bundles.len(),
            batch_count: batches.len(),
        });
    }
    for (batch_index, (bundle, batch)) in bundles.iter().zip(batches).enumerate() {
        let expected = batch_from_transcript_bundle(
            batch.parameter.clone(),
            batch.public_inputs,
            bundle.entry_hash,
            &bundle.transcripts,
        )?;
        let required_metadata_matches = expected.metadata.iter().all(|(key, value)| {
            batch
                .metadata
                .get(key)
                .is_some_and(|actual| actual == value)
        });
        if batch.public_inputs != expected.public_inputs
            || batch.transitions != expected.transitions
            || !required_metadata_matches
        {
            return Err(TranscriptBatchError::FastpqBatchBinding { batch_index });
        }
    }
    Ok(())
}
#[cfg(test)]
/// Convert transcript bundles into FASTPQ batches, preserving execution order.
///
/// # Errors
/// Returns [`TranscriptBatchError`] if constructing a batch fails.
pub fn batches_from_bundles<'a, I>(
    parameter_set: &str,
    public_inputs: FastpqPublicInputsTemplate,
    tx_set_hash: [u8; 32],
    bundles: I,
) -> Result<Vec<TransitionBatch>, TranscriptBatchError>
where
    I: IntoIterator<Item = &'a TransferTranscriptBundle>,
{
    let mut batches = Vec::new();
    let public_inputs = public_inputs_from_template(public_inputs, tx_set_hash);
    for bundle in bundles {
        let mut batch = batch_from_transcripts(
            parameter_set.to_string(),
            public_inputs,
            &bundle.transcripts,
        )?;
        annotate_metadata(&mut batch, &bundle.entry_hash, bundle.transcripts.len());
        batches.push(batch);
    }
    Ok(batches)
}
fn annotate_metadata(batch: &mut TransitionBatch, entry_hash: &Hash, transcript_count: usize) {
    batch
        .metadata
        .insert(ENTRY_HASH_METADATA_KEY.into(), entry_hash.as_ref().to_vec());
    batch.metadata.insert(
        TRANSCRIPT_COUNT_METADATA_KEY.into(),
        (transcript_count as u64).to_le_bytes().to_vec(),
    );
}
#[cfg(test)]
/// Convert a map of transcripts grouped by entry hash into DTO batches.
///
/// # Errors
/// Returns [`TranscriptBatchError`] if constructing the batches fails.
pub fn dto_batches_from_transcripts(
    parameter_set: &str,
    public_inputs: FastpqPublicInputsTemplate,
    tx_set_hash: [u8; 32],
    transcripts: &BTreeMap<Hash, Vec<TransferTranscript>>,
) -> Result<Vec<FastpqTransitionBatch>, TranscriptBatchError> {
    let bundles: Vec<_> = transcripts
        .iter()
        .map(|(entry_hash, entries)| TransferTranscriptBundle {
            entry_hash: *entry_hash,
            transcripts: entries.clone(),
        })
        .collect();
    let batches = batches_from_bundles(parameter_set, public_inputs, tx_set_hash, bundles.iter())?;
    Ok(batches.iter().map(transition_batch_to_dto).collect())
}
#[cfg(test)]
/// Convert a prover batch into its DTO representation suitable for `ExecWitness`.
#[must_use]
pub fn transition_batch_to_dto(batch: &TransitionBatch) -> FastpqTransitionBatch {
    transition_batch_to_dto_ref(batch)
}
#[cfg(test)]
/// Convert a prover batch reference into a DTO (borrowing-friendly helper).
#[must_use]
pub fn transition_batch_to_dto_ref(batch: &TransitionBatch) -> FastpqTransitionBatch {
    let transitions = batch
        .transitions
        .iter()
        .map(state_transition_to_dto)
        .collect();
    FastpqTransitionBatch {
        parameter: batch.parameter.clone(),
        public_inputs: public_inputs_to_dto(&batch.public_inputs),
        transitions,
        metadata: batch.metadata.clone(),
    }
}
/// Convert a DTO batch back into the prover representation.
#[must_use]
pub fn transition_batch_from_dto(dto: &FastpqTransitionBatch) -> TransitionBatch {
    let mut batch = TransitionBatch::new(
        dto.parameter.clone(),
        public_inputs_from_dto(&dto.public_inputs),
    );
    for transition in &dto.transitions {
        batch.push(StateTransition::new(
            transition.key.clone(),
            transition.pre_value.clone(),
            transition.post_value.clone(),
            operation_from_dto(&transition.operation),
        ));
    }
    batch.metadata = dto.metadata.clone();
    batch
}
fn public_inputs_to_dto(inputs: &PublicInputs) -> FastpqPublicInputs {
    FastpqPublicInputs {
        dsid: inputs.dsid,
        slot: inputs.slot,
        old_root: inputs.old_root,
        new_root: inputs.new_root,
        perm_root: inputs.perm_root,
        tx_set_hash: inputs.tx_set_hash,
    }
}
fn public_inputs_from_dto(inputs: &FastpqPublicInputs) -> PublicInputs {
    PublicInputs {
        dsid: inputs.dsid,
        slot: inputs.slot,
        old_root: inputs.old_root,
        new_root: inputs.new_root,
        perm_root: inputs.perm_root,
        tx_set_hash: inputs.tx_set_hash,
    }
}
fn state_transition_to_dto(transition: &StateTransition) -> FastpqStateTransition {
    FastpqStateTransition {
        key: transition.key.clone(),
        pre_value: transition.pre_value.clone(),
        post_value: transition.post_value.clone(),
        operation: operation_to_dto(&transition.operation),
    }
}
fn operation_to_dto(operation: &OperationKind) -> FastpqOperationKind {
    match operation {
        OperationKind::Transfer => FastpqOperationKind::Transfer,
        OperationKind::Mint => FastpqOperationKind::Mint,
        OperationKind::Burn => FastpqOperationKind::Burn,
        OperationKind::RoleGrant {
            role_id,
            permission_id,
            epoch,
        } => FastpqOperationKind::RoleGrant(FastpqRolePermissionDelta {
            role_id: *role_id,
            permission_id: *permission_id,
            epoch: *epoch,
        }),
        OperationKind::RoleRevoke {
            role_id,
            permission_id,
            epoch,
        } => FastpqOperationKind::RoleRevoke(FastpqRolePermissionDelta {
            role_id: *role_id,
            permission_id: *permission_id,
            epoch: *epoch,
        }),
        OperationKind::MetaSet => FastpqOperationKind::MetaSet,
    }
}
fn operation_from_dto(operation: &FastpqOperationKind) -> OperationKind {
    match operation {
        FastpqOperationKind::Transfer => OperationKind::Transfer,
        FastpqOperationKind::Mint => OperationKind::Mint,
        FastpqOperationKind::Burn => OperationKind::Burn,
        FastpqOperationKind::RoleGrant(delta) => OperationKind::RoleGrant {
            role_id: delta.role_id,
            permission_id: delta.permission_id,
            epoch: delta.epoch,
        },
        FastpqOperationKind::RoleRevoke(delta) => OperationKind::RoleRevoke {
            role_id: delta.role_id,
            permission_id: delta.permission_id,
            epoch: delta.epoch,
        },
        FastpqOperationKind::MetaSet => OperationKind::MetaSet,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::{
        Registrable,
        block::{
            BlockHeader,
            consensus::{ExecKv, ExecWitness},
        },
        fastpq::{TransferTranscript, TransferTranscriptBundle},
        permission::Permission,
        role::{Role, RoleId},
    };
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::json::Json;
    use iroha_test_samples::{ALICE_ID, BOB_ID};
    use norito::decode_from_bytes;
    use std::{collections::BTreeMap, num::NonZeroU64};
    #[test]
    fn authority_digest_matches_known_vector() {
        let digest = authority_digest(&ALICE_ID);
        assert_eq!(
            hex::encode(digest.as_ref()),
            "e1e0bb25f044ba013bfb99711a2f409472d1f941b68e6716a677ac6d1bcd5fcb"
        );
    }
    #[test]
    fn poseidon_digest_matches_known_vector() {
        let asset = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let delta = TransferDeltaTranscript {
            from_account: (*ALICE_ID).clone(),
            to_account: (*BOB_ID).clone(),
            asset_definition: asset,
            amount: Quantity::from(42u32),
            from_balance_before: Quantity::from(200u32),
            from_balance_after: Quantity::from(158u32),
            to_balance_before: Quantity::from(1u32),
            to_balance_after: Quantity::from(43u32),
            from_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
            to_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
        };
        let batch_hash = Hash::prehashed([0x11; 32]);
        let mut encoded_preimage = Vec::new();
        encoded_preimage.extend_from_slice(&delta.from_account.encode());
        encoded_preimage.extend_from_slice(&delta.to_account.encode());
        encoded_preimage.extend_from_slice(&delta.asset_definition.encode());
        encoded_preimage.extend_from_slice(&delta.amount.encode());
        encoded_preimage.extend_from_slice(batch_hash.as_ref());
        let mut streamed_preimage = Vec::new();
        delta.from_account.encode_to(&mut streamed_preimage);
        delta.to_account.encode_to(&mut streamed_preimage);
        delta.asset_definition.encode_to(&mut streamed_preimage);
        delta.amount.encode_to(&mut streamed_preimage);
        streamed_preimage.extend_from_slice(batch_hash.as_ref());
        assert_eq!(streamed_preimage, encoded_preimage);
        let digest = poseidon_preimage_digest(&delta, &batch_hash);
        assert_eq!(
            digest,
            Hash::prehashed(halo2_poseidon::hash_bytes(&encoded_preimage))
        );
        assert_eq!(
            hex::encode(digest.as_ref()),
            "6cb8fd166f7fc8eb87a2af9601a37189a517891e0884f0efe0916a5a51c10f25"
        );
    }
    #[test]
    fn poseidon_digest_scratch_matches_canonical_oracle() {
        let asset = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let delta = TransferDeltaTranscript {
            from_account: (*ALICE_ID).clone(),
            to_account: (*BOB_ID).clone(),
            asset_definition: asset,
            amount: Quantity::from(42u32),
            from_balance_before: Quantity::from(200u32),
            from_balance_after: Quantity::from(158u32),
            to_balance_before: Quantity::from(1u32),
            to_balance_after: Quantity::from(43u32),
            from_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
            to_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
        };
        let mut scratch = PoseidonDigestScratch::default();
        let first_hash = Hash::prehashed([0x11; 32]);
        let second_hash = Hash::prehashed([0x22; 32]);
        assert_eq!(
            poseidon_preimage_digest_with_scratch(&delta, &first_hash, &mut scratch),
            poseidon_preimage_digest(&delta, &first_hash)
        );
        assert_eq!(
            poseidon_preimage_digest_with_scratch(&delta, &second_hash, &mut scratch),
            poseidon_preimage_digest(&delta, &second_hash)
        );
    }
    #[test]
    fn poseidon_word_packer_matches_delimited_little_endian_chunks() {
        for len in [0usize, 1, 7, 8, 9, 15, 16, 17, 63, 64, 65] {
            let input = (0..len)
                .map(|idx| (idx as u8).wrapping_mul(17).wrapping_add(3))
                .collect::<Vec<_>>();
            let mut words = Vec::new();
            {
                let mut packer = PoseidonWordPacker::new(&mut words);
                for chunk in input.chunks(5) {
                    packer.update(chunk);
                }
                packer.finish();
            }
            let mut expected = input
                .chunks(8)
                .map(|chunk| {
                    let mut word = [0u8; 8];
                    word[..chunk.len()].copy_from_slice(chunk);
                    u64::from_le_bytes(word)
                })
                .collect::<Vec<_>>();
            if input.len().is_multiple_of(8) {
                expected.push(1);
            } else {
                let last = expected
                    .last_mut()
                    .expect("a partial input chunk produces one packed word");
                *last |= 1u64 << ((input.len() % 8) * 8);
            }
            assert_eq!(words, expected, "len {len}");
        }
    }
    #[test]
    fn transfer_digest_word_writer_matches_streaming_oracle() {
        let transcript = sample_transcript();
        let delta = &transcript.deltas[0];
        let encoded_preimage = encoded_transfer_digest_preimage(delta, &transcript.batch_hash);
        let words = transfer_digest_words(delta, &transcript.batch_hash);
        assert_eq!(
            halo2_poseidon::hash_u64_words_bytes(&words),
            halo2_poseidon::hash_bytes(&encoded_preimage)
        );
        assert_eq!(
            poseidon_preimage_digest(delta, &transcript.batch_hash),
            Hash::prehashed(halo2_poseidon::hash_bytes(&encoded_preimage))
        );
    }
    #[test]
    fn poseidon_digest_batch_cpu_hash_matches_single_digest() {
        let transcript = sample_transcript();
        let delta = &transcript.deltas[0];
        let mut batch = PoseidonDigestBatch::with_capacity(1);
        batch.push(delta, &transcript.batch_hash);
        assert_eq!(
            batch.hash_cpu(),
            vec![poseidon_preimage_digest(delta, &transcript.batch_hash)]
        );
        assert!(
            batch.try_hash_gpu().is_none(),
            "single digest should stay below the GPU threshold"
        );
    }
    #[test]
    fn poseidon_digest_batch_parallel_cpu_preserves_input_order() {
        let mut batch = PoseidonDigestBatch::with_capacity(DIGEST_FINALIZE_PARALLEL_THRESHOLD);
        let mut expected = Vec::with_capacity(DIGEST_FINALIZE_PARALLEL_THRESHOLD);
        for idx in 0..DIGEST_FINALIZE_PARALLEL_THRESHOLD {
            let mut transcript = sample_transcript();
            transcript.batch_hash = Hash::prehashed([idx as u8; Hash::LENGTH]);
            let delta = &transcript.deltas[0];
            expected.push(poseidon_preimage_digest(delta, &transcript.batch_hash));
            batch.push(delta, &transcript.batch_hash);
        }
        assert_eq!(batch.hash_cpu(), expected);
    }
    #[test]
    fn poseidon_digest_batch_cpu_or_gpu_matches_ordered_cpu_output() {
        let _guard = DigestAccelerationTestGuard::new();
        set_poseidon_digest_acceleration_enabled(true);
        let mut batch = PoseidonDigestBatch::with_capacity(DIGEST_FINALIZE_GPU_THRESHOLD);
        for idx in 0..DIGEST_FINALIZE_GPU_THRESHOLD {
            let mut transcript = sample_transcript();
            transcript.batch_hash = Hash::prehashed([idx as u8; Hash::LENGTH]);
            batch.push(&transcript.deltas[0], &transcript.batch_hash);
        }
        assert_eq!(batch.hash_cpu_or_gpu(), batch.hash_cpu());
    }
    #[test]
    fn poseidon_digest_batch_failed_gpu_submission_disables_acceleration() {
        let _guard = DigestAccelerationTestGuard::new();
        set_poseidon_digest_acceleration_enabled(true);
        let mut batch = PoseidonDigestBatch::with_capacity(DIGEST_FINALIZE_GPU_THRESHOLD);
        for idx in 0..DIGEST_FINALIZE_GPU_THRESHOLD {
            let mut transcript = sample_transcript();
            transcript.batch_hash = Hash::prehashed([idx as u8; Hash::LENGTH]);
            batch.push(&transcript.deltas[0], &transcript.batch_hash);
        }
        let attempts = std::cell::Cell::new(0);
        let accelerated: Option<Vec<Hash>> = batch.try_gpu_batch(|words, slices| {
            attempts.set(attempts.get() + 1);
            assert_eq!(words, batch.words);
            assert_eq!(slices, batch.slices);
            None
        });
        assert_eq!(
            attempts.get(),
            1,
            "the enabled batch must attempt submission"
        );
        assert_eq!(
            accelerated.unwrap_or_else(|| batch.hash_cpu()),
            batch.hash_cpu()
        );
        assert!(
            !poseidon_digest_acceleration_enabled(),
            "failed GPU submission should latch the core digest gate off"
        );
        let retried: Option<Vec<Hash>> = batch.try_gpu_batch(|_, _| {
            attempts.set(attempts.get() + 1);
            None
        });
        assert!(retried.is_none());
        assert_eq!(attempts.get(), 1, "the disabled gate must suppress a retry");
    }
    #[test]
    fn digest_acceleration_respects_configured_modes() {
        let explicit_gpu = fastpq_cfg(FastpqExecutionMode::Cpu, FastpqPoseidonMode::Gpu);
        assert!(poseidon_digest_acceleration_configured(&explicit_gpu));
        let poseidon_cpu = fastpq_cfg(FastpqExecutionMode::Gpu, FastpqPoseidonMode::Cpu);
        assert!(!poseidon_digest_acceleration_configured(&poseidon_cpu));
        let cpu = fastpq_cfg(FastpqExecutionMode::Cpu, FastpqPoseidonMode::Cpu);
        assert!(!poseidon_digest_acceleration_configured(&cpu));
    }
    #[test]
    fn axt_proof_payload_decode_limit_is_inclusive() {
        let at_limit = vec![0u8; fastpq_prover::MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES];
        assert!(!axt_proof_payload_exceeds_decode_limit(&at_limit));
        let over_limit = vec![0u8; fastpq_prover::MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES + 1];
        assert!(axt_proof_payload_exceeds_decode_limit(&over_limit));
    }
    #[test]
    fn finalize_transfer_transcripts_fills_only_single_delta_digests() {
        let mut single = sample_transcript();
        let expected = poseidon_preimage_digest(&single.deltas[0], &single.batch_hash);
        let mut multi = sample_transcript();
        multi.deltas.push(multi.deltas[0].clone());
        let mut map = BTreeMap::new();
        map.insert(
            Hash::prehashed([0x77; 32]),
            vec![single.clone(), multi.clone()],
        );
        finalize_transfer_transcript_digests_in_map(&mut map);
        let entries = map.values().next().expect("entries");
        assert_eq!(entries[0].poseidon_preimage_digest, Some(expected));
        assert!(entries[1].poseidon_preimage_digest.is_none());
        single.poseidon_preimage_digest = Some(expected);
        let mut bundles = vec![TransferTranscriptBundle {
            entry_hash: Hash::prehashed([0x78; 32]),
            transcripts: vec![single],
        }];
        finalize_transfer_transcript_bundle_digests_in_place(&mut bundles);
        assert_eq!(
            bundles[0].transcripts[0].poseidon_preimage_digest,
            Some(expected)
        );
    }
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(
        expected = "precomputed FASTPQ transfer transcript digest must match canonical digest"
    )]
    fn finalize_transfer_transcripts_debug_asserts_precomputed_mismatch() {
        let mut single = sample_transcript();
        single.poseidon_preimage_digest = Some(Hash::prehashed([0xEE; Hash::LENGTH]));
        let mut map = BTreeMap::from([(Hash::prehashed([0x7A; Hash::LENGTH]), vec![single])]);
        finalize_transfer_transcript_digests_in_map(&mut map);
    }
    #[test]
    fn finalize_transfer_transcripts_batched_cpu_matches_canonical_oracle() {
        let _guard = DigestAccelerationTestGuard::new();
        set_poseidon_digest_acceleration_enabled(false);
        let mut entries = Vec::with_capacity(DIGEST_FINALIZE_PARALLEL_THRESHOLD);
        let mut expected = Vec::with_capacity(DIGEST_FINALIZE_PARALLEL_THRESHOLD);
        for idx in 0..DIGEST_FINALIZE_PARALLEL_THRESHOLD {
            let mut transcript = sample_transcript();
            transcript.batch_hash = Hash::prehashed([idx as u8; Hash::LENGTH]);
            transcript.poseidon_preimage_digest = None;
            expected.push(poseidon_preimage_digest(
                &transcript.deltas[0],
                &transcript.batch_hash,
            ));
            entries.push(transcript);
        }
        let mut map = BTreeMap::from([(Hash::prehashed([0x79; Hash::LENGTH]), entries)]);
        finalize_transfer_transcript_digests_in_map(&mut map);
        let actual = map
            .values()
            .next()
            .expect("entries")
            .iter()
            .map(|transcript| transcript.poseidon_preimage_digest)
            .collect::<Vec<_>>();
        assert_eq!(actual, expected.into_iter().map(Some).collect::<Vec<_>>());
    }
    #[test]
    fn missing_single_delta_transcript_count_ignores_precomputed_and_multi_delta() {
        let mut precomputed = sample_transcript();
        precomputed.poseidon_preimage_digest = Some(poseidon_preimage_digest(
            &precomputed.deltas[0],
            &precomputed.batch_hash,
        ));
        let missing = sample_transcript();
        let mut multi = sample_transcript();
        multi.deltas.push(multi.deltas[0].clone());
        assert_eq!(
            missing_single_delta_transcript_count(&[precomputed, missing, multi]),
            1
        );
    }
    #[test]
    fn permission_table_root_is_order_independent() {
        let perm_a = Permission::new("perm_a".to_string(), Json::new(()));
        let perm_b = Permission::new("perm_b".to_string(), Json::new(()));
        let role_a: RoleId = "role_a".parse().expect("role id");
        let role_b: RoleId = "role_b".parse().expect("role id");
        let role_a = Role::new(role_a.clone(), (*ALICE_ID).clone())
            .add_permission(perm_a.clone())
            .add_permission(perm_b)
            .build(&ALICE_ID);
        let role_b = Role::new(role_b.clone(), (*ALICE_ID).clone())
            .add_permission(perm_a)
            .build(&ALICE_ID);
        let first = [
            (role_b.id.clone(), role_b.clone()),
            (role_a.id.clone(), role_a.clone()),
        ];
        let second = [
            (role_a.id.clone(), role_a.clone()),
            (role_b.id.clone(), role_b.clone()),
        ];
        let root_first = permission_table_root(first.iter().map(|(id, role)| (id, role)));
        let root_second = permission_table_root(second.iter().map(|(id, role)| (id, role)));
        assert_eq!(root_first, root_second);
        assert_ne!(root_first, [0u8; 32]);
    }
    #[test]
    fn permission_table_root_preserves_full_digest_width_and_cardinality() {
        let role_id: RoleId = "width_test".parse().expect("role id");
        let role = Role::new(role_id.clone(), (*ALICE_ID).clone())
            .add_permission(Permission::new("permission".to_owned(), Json::new(())))
            .build(&ALICE_ID);
        let three = permission_table_root(std::iter::repeat_n((&role_id, &role), 3));
        let four = permission_table_root(std::iter::repeat_n((&role_id, &role), 4));
        assert_ne!(three[8..], [0; 24], "the root must not be a padded u64");
        assert_ne!(
            three, four,
            "duplicate-last tree padding must not alias cardinality"
        );
        assert_eq!(permission_table_root(std::iter::empty()), [0; 32]);
    }
    #[test]
    fn permission_table_root_tracks_permission_epochs() {
        let perm = Permission::new("perm_epoch".to_string(), Json::new(()));
        let role_id: RoleId = "role_epoch".parse().expect("role id");
        let role_epoch_0 = Role::new(role_id.clone(), (*ALICE_ID).clone())
            .add_permission_with_epoch(perm.clone(), 0)
            .build(&ALICE_ID);
        let role_epoch_7 = Role::new(role_id.clone(), (*ALICE_ID).clone())
            .add_permission_with_epoch(perm.clone(), 7)
            .build(&ALICE_ID);
        let root_epoch_0 = permission_table_root(
            [(role_id.clone(), role_epoch_0)]
                .iter()
                .map(|(id, role)| (id, role)),
        );
        let root_epoch_7 = permission_table_root(
            [(role_id.clone(), role_epoch_7)]
                .iter()
                .map(|(id, role)| (id, role)),
        );
        assert_ne!(root_epoch_0, root_epoch_7);
    }
    #[test]
    fn public_inputs_template_from_block_uses_header_and_roots() {
        let header = BlockHeader::new(NonZeroU64::new(1).expect("height"), None, None, 123, 0);
        let witness = ExecWitness {
            reads: vec![ExecKv {
                key: b"key".to_vec(),
                value: b"old".to_vec(),
            }],
            writes: vec![ExecKv {
                key: b"key".to_vec(),
                value: b"new".to_vec(),
            }],
            fastpq_transcripts: Vec::new(),
            fastpq_batches: Vec::new(),
        };
        let perm_root = [0x11; 32];
        let template = public_inputs_template_from_block(&header, &witness, perm_root);
        let mut expected_dsid = [0u8; 16];
        expected_dsid[..8].copy_from_slice(&DataSpaceId::UNIVERSAL.as_u64().to_le_bytes());
        assert_eq!(template.dsid, expected_dsid);
        assert_eq!(template.slot, 123_000_000);
        assert_eq!(template.perm_root, perm_root);
        assert_eq!(
            template.old_root,
            <[u8; 32]>::from(crate::exec_witness::roots::parent_state_from_witness(
                &witness
            ))
        );
        assert_eq!(
            template.new_root,
            <[u8; 32]>::from(crate::exec_witness::roots::post_state_from_witness(
                &witness
            ))
        );
    }
    #[test]
    fn public_inputs_from_template_uses_tx_set_hash() {
        let template = sample_template();
        let tx_set_hash = [0x22; 32];
        let inputs = public_inputs_from_template(template, tx_set_hash);
        assert_eq!(inputs.tx_set_hash, tx_set_hash);
        assert_eq!(inputs.dsid, template.dsid);
        assert_eq!(inputs.slot, template.slot);
        assert_eq!(inputs.old_root, template.old_root);
        assert_eq!(inputs.new_root, template.new_root);
        assert_eq!(inputs.perm_root, template.perm_root);
    }
    fn exact_finalized_transcript_pair() -> [TransferTranscript; 2] {
        let mut first = sample_transcript();
        first.poseidon_preimage_digest = Some(poseidon_preimage_digest(
            &first.deltas[0],
            &first.batch_hash,
        ));
        let mut second = sample_transcript();
        let delta = &mut second.deltas[0];
        delta.amount = "0.5".parse().unwrap();
        delta.from_balance_before = Quantity::from(158_u32);
        delta.from_balance_after = "157.5".parse().unwrap();
        delta.to_balance_before = Quantity::from(43_u32);
        delta.to_balance_after = "43.5".parse().unwrap();
        second.poseidon_preimage_digest = Some(poseidon_preimage_digest(
            &second.deltas[0],
            &second.batch_hash,
        ));
        [first, second]
    }

    #[test]
    fn finalized_public_producer_preserves_exact_mixed_scale_duplicate_occurrences() {
        let captured = exact_finalized_transcript_pair();
        let before = norito::encode_canonical(&captured).unwrap();
        let inputs = sample_public_inputs();
        let (batch, statement) = batch_and_public_statement_from_finalized_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            inputs,
            &captured,
        )
        .expect("already chained finalized facts");
        assert_eq!(
            statement.transcripts,
            captured
                .iter()
                .map(FastpqPublicTransferTranscriptV1::from)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            statement.transcripts.len(),
            2,
            "equal batch hashes preserve occurrences"
        );
        assert_eq!(
            statement.public_inputs,
            public_inputs_to_dto(&batch.public_inputs)
        );
        assert_eq!(statement.public_inputs.tx_set_hash, inputs.tx_set_hash);
        assert_eq!(statement.public_inputs.dsid, inputs.dsid);
        assert_eq!(statement.public_inputs.perm_root, inputs.perm_root);
        assert_eq!(statement.public_inputs.slot, inputs.slot);
        assert_eq!(norito::encode_canonical(&captured).unwrap(), before);
    }

    #[test]
    fn finalized_public_producer_rejects_stale_balances_and_missing_final_digest() {
        let original = exact_finalized_transcript_pair();
        let mut stale = original.clone();
        stale[1] = original[0].clone();
        let mut precision_stale = original.clone();
        let delta = &mut precision_stale[1].deltas[0];
        delta.from_balance_before = "158.001".parse().unwrap();
        delta.from_balance_after = "157.501".parse().unwrap();
        delta.to_balance_before = "43.001".parse().unwrap();
        delta.to_balance_after = "43.501".parse().unwrap();
        for captured in [stale, precision_stale] {
            let before = norito::encode_canonical(&captured).unwrap();
            assert!(matches!(
                batch_and_public_statement_from_finalized_transcripts(
                    FASTPQ_CANONICAL_PARAMETER_SET,
                    sample_public_inputs(),
                    &captured
                ),
                Err(FinalizedPublicStatementError::ProjectionMismatch {
                    transcript_index: 1
                })
            ));
            assert_eq!(norito::encode_canonical(&captured).unwrap(), before);
        }
        let missing = sample_transcript();
        assert!(matches!(
            batch_and_public_statement_from_finalized_transcripts(
                FASTPQ_CANONICAL_PARAMETER_SET,
                sample_public_inputs(),
                [&missing]
            ),
            Err(FinalizedPublicStatementError::ProjectionMismatch {
                transcript_index: 0
            })
        ));
    }

    #[test]
    fn finalized_public_producer_keeps_multi_delta_zero_and_empty_semantics() {
        let pair = exact_finalized_transcript_pair();
        let mut multi = pair[0].clone();
        multi.deltas.push(pair[1].deltas[0].clone());
        multi.poseidon_preimage_digest = None;
        let mut zero = sample_transcript();
        zero.deltas[0].amount = Quantity::zero();
        zero.deltas[0].from_balance_after = zero.deltas[0].from_balance_before.clone();
        zero.deltas[0].to_balance_after = zero.deltas[0].to_balance_before.clone();
        zero.poseidon_preimage_digest =
            Some(poseidon_preimage_digest(&zero.deltas[0], &zero.batch_hash));
        for captured in [vec![multi], vec![zero], Vec::new()] {
            let (_, statement) = batch_and_public_statement_from_finalized_transcripts(
                FASTPQ_CANONICAL_PARAMETER_SET,
                sample_public_inputs(),
                &captured,
            )
            .expect("exact supported construction");
            assert_eq!(
                statement.transcripts,
                captured
                    .iter()
                    .map(FastpqPublicTransferTranscriptV1::from)
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn finalized_public_projection_rejects_every_public_field_and_occurrence_substitution() {
        let captured = exact_finalized_transcript_pair();
        let originals = captured.iter().collect::<Vec<_>>();
        let public = captured
            .iter()
            .map(FastpqPublicTransferTranscriptV1::from)
            .collect::<Vec<_>>();
        validate_finalized_public_transcript_projection(&originals, &public).unwrap();
        for field in 0..11 {
            let mut changed = public.clone();
            let item = &mut changed[0];
            match field {
                0 => item.batch_hash = Hash::prehashed([0x91; 32]),
                1 => item.authority_digest = Hash::prehashed([0x92; 32]),
                2 => item.poseidon_preimage_digest = None,
                3 => item.deltas[0].from_account = (*BOB_ID).clone(),
                4 => item.deltas[0].to_account = (*ALICE_ID).clone(),
                5 => {
                    item.deltas[0].asset_definition = AssetDefinitionId::derive_from_components(
                        DomainId::try_new("wonderland", "universal").unwrap(),
                        "different".parse().unwrap(),
                    )
                }
                6 => item.deltas[0].amount = Quantity::from(1_u32),
                7 => item.deltas[0].from_balance_before = Quantity::from(1_u32),
                8 => item.deltas[0].from_balance_after = Quantity::from(1_u32),
                9 => item.deltas[0].to_balance_before = Quantity::from(2_u32),
                10 => item.deltas[0].to_balance_after = Quantity::from(1_u32),
                _ => unreachable!(),
            }
            assert!(
                matches!(
                    validate_finalized_public_transcript_projection(&originals, &changed),
                    Err(FinalizedPublicStatementError::ProjectionMismatch {
                        transcript_index: 0
                    })
                ),
                "field {field}"
            );
        }
        let mut reversed = public.clone();
        reversed.reverse();
        assert!(validate_finalized_public_transcript_projection(&originals, &reversed).is_err());
        assert!(matches!(
            validate_finalized_public_transcript_projection(&originals, &public[..1]),
            Err(FinalizedPublicStatementError::ProjectionMismatch {
                transcript_index: 1
            })
        ));
        assert!(matches!(
            validate_finalized_public_transcript_projection(&originals[..1], &public),
            Err(FinalizedPublicStatementError::ProjectionMismatch {
                transcript_index: 1
            })
        ));
        let mut missing_delta = public.clone();
        missing_delta[0].deltas.clear();
        assert!(
            validate_finalized_public_transcript_projection(&originals, &missing_delta).is_err()
        );
    }

    #[test]
    fn finalized_public_producer_self_transfer_keeps_intermediate_balances_and_roots() {
        let mut captured = sample_transcript();
        let delta = &mut captured.deltas[0];
        delta.to_account = delta.from_account.clone();
        delta.to_balance_before = Quantity::from(158_u32);
        delta.to_balance_after = Quantity::from(200_u32);
        captured.poseidon_preimage_digest = Some(poseidon_preimage_digest(
            &captured.deltas[0],
            &captured.batch_hash,
        ));
        let before = norito::encode_canonical(&captured).unwrap();
        let (_, statement) = batch_and_public_statement_from_finalized_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_public_inputs(),
            [&captured],
        )
        .expect("exact finalized self-transfer");
        assert_eq!(
            statement.transcripts,
            vec![FastpqPublicTransferTranscriptV1::from(&captured)]
        );
        assert_eq!(
            statement.public_inputs.old_root,
            statement.public_inputs.new_root
        );
        assert_eq!(statement.transitions.len(), 2);
        assert_eq!(norito::encode_canonical(&captured).unwrap(), before);
        let mut stale = captured;
        stale.deltas[0].to_balance_before = Quantity::from(200_u32);
        stale.deltas[0].to_balance_after = Quantity::from(242_u32);
        assert!(matches!(
            batch_and_public_statement_from_finalized_transcripts(
                FASTPQ_CANONICAL_PARAMETER_SET,
                sample_public_inputs(),
                [&stale]
            ),
            Err(FinalizedPublicStatementError::Batch(
                TranscriptBatchError::TransferWitness {
                    source: fastpq_prover::Error::TransferInvariant { .. }
                }
            ))
        ));
    }

    #[test]
    fn finalized_public_producer_preserves_original_construction_errors() {
        let mut empty = sample_transcript();
        empty.deltas.clear();
        assert!(matches!(
            batch_and_public_statement_from_finalized_transcripts(
                FASTPQ_CANONICAL_PARAMETER_SET,
                sample_public_inputs(),
                [&empty]
            ),
            Err(FinalizedPublicStatementError::Batch(
                TranscriptBatchError::TransferWitness { .. }
            ))
        ));
    }

    #[test]
    fn public_producer_preserves_finalized_duplicate_occurrences() {
        let captured = vec![sample_transcript(), sample_transcript()];
        let captured_before = norito::encode_canonical(&captured).unwrap();
        let inputs = FastpqPublicInputs {
            dsid: [0x11; 16],
            slot: 37,
            old_root: [0x22; 32],
            new_root: [0x33; 32],
            perm_root: [0x44; 32],
            tx_set_hash: [0x55; 32],
        };
        let expected_batch =
            batch_from_transcripts(FASTPQ_CANONICAL_PARAMETER_SET, inputs, &captured)
                .expect("batch");
        let (private, public) = batch_and_public_statement_from_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            inputs,
            &captured,
        )
        .expect("producer pair");
        assert_eq!(
            norito::encode_canonical(&private).unwrap(),
            norito::encode_canonical(&expected_batch).unwrap()
        );
        assert_eq!(
            norito::encode_canonical(&captured).unwrap(),
            captured_before
        );
        assert_eq!(
            public.public_inputs,
            public_inputs_to_dto(&private.public_inputs)
        );
        assert_eq!(public.public_inputs.dsid, inputs.dsid);
        assert_eq!(public.public_inputs.slot, inputs.slot);
        assert_eq!(public.public_inputs.perm_root, inputs.perm_root);
        assert_eq!(public.public_inputs.tx_set_hash, inputs.tx_set_hash);
        assert_ne!(public.public_inputs.old_root, inputs.old_root);
        assert_ne!(public.public_inputs.new_root, inputs.new_root);
        assert_eq!(public.transitions, dto_transitions(&private.transitions));
        assert_eq!(public.transitions.len(), 4);
        let delta = &captured[0].deltas[0];
        let mut expected_rows: Vec<_> = [
            (&delta.from_account, 200_u64, 158_u64),
            (&delta.to_account, 1, 43),
            (&delta.from_account, 158, 116),
            (&delta.to_account, 43, 85),
        ]
        .into_iter()
        .map(|(account, before, after)| FastpqStateTransition {
            key: balance_key(&delta.asset_definition, account).unwrap(),
            pre_value: before.to_le_bytes().to_vec(),
            post_value: after.to_le_bytes().to_vec(),
            operation: FastpqOperationKind::Transfer,
        })
        .collect();
        expected_rows.sort_by(|left, right| left.key.cmp(&right.key));
        assert_eq!(public.transitions, expected_rows);
        let encoded_rows = norito::encode_canonical(&private.transitions).unwrap();
        let expected_ordering: [u8; 32] =
            Hash::new_from_chunks(&[b"fastpq:v1:ordering", &encoded_rows]).into();
        assert_eq!(public.ordering_hash, expected_ordering);
        assert_eq!(public.transcripts.len(), 2);
        assert_eq!(
            public.transcripts[0].batch_hash,
            public.transcripts[1].batch_hash
        );
        assert_eq!(public.transcripts[0].deltas.len(), 1);
        assert_eq!(public.transcripts[1].deltas.len(), 1);
        let second = &public.transcripts[1].deltas[0];
        assert_eq!(second.amount, Quantity::from(42_u32));
        assert_eq!(second.from_balance_before, Quantity::from(158_u32));
        assert_eq!(second.from_balance_after, Quantity::from(116_u32));
        assert_eq!(second.to_balance_before, Quantity::from(43_u32));
        assert_eq!(second.to_balance_after, Quantity::from(85_u32));
        assert_eq!(
            captured[1].deltas[0].from_balance_before,
            Quantity::from(200_u32)
        );
        // Private decoding occurs only in this test as an independent check of
        // the exact finalized occurrences actually embedded by the batch producer.
        let finalized: Vec<TransferTranscript> = decode_from_bytes(
            private
                .metadata
                .get(TRANSFER_TRANSCRIPTS_METADATA_KEY)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            public.transcripts,
            finalized
                .iter()
                .map(FastpqPublicTransferTranscriptV1::from)
                .collect::<Vec<_>>()
        );
        assert!(
            public
                .transcripts
                .iter()
                .all(|t| t.poseidon_preimage_digest.is_some())
        );
    }

    #[test]
    fn public_producer_keeps_multi_delta_and_transcript_order() {
        let mut grouped = sample_transcript();
        grouped.deltas.push(grouped.deltas[0].clone());
        let mut last = sample_transcript();
        last.batch_hash = Hash::prehashed([0xBB; 32]);
        last.authority_digest = Hash::prehashed([0xBC; 32]);
        let captured = [grouped, last];
        let (private, public) = batch_and_public_statement_from_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_public_inputs(),
            &captured,
        )
        .unwrap();
        assert_eq!(public.transcripts.len(), 2);
        assert_eq!(public.transcripts[0].batch_hash, captured[0].batch_hash);
        assert_eq!(public.transcripts[1].batch_hash, captured[1].batch_hash);
        assert_eq!(
            public.transcripts[1].authority_digest,
            captured[1].authority_digest
        );
        assert_eq!(public.transcripts[0].deltas.len(), 2);
        assert_eq!(
            public.transcripts[0].deltas[0].from_balance_before,
            Quantity::from(200_u32)
        );
        assert_eq!(
            public.transcripts[0].deltas[1].from_balance_before,
            Quantity::from(158_u32)
        );
        assert!(public.transcripts[0].poseidon_preimage_digest.is_none());
        assert!(public.transcripts[1].poseidon_preimage_digest.is_some());
        assert_eq!(public.transitions.len(), 6);
        assert_eq!(
            public.transcripts[1].deltas[0].from_balance_before,
            Quantity::from(116_u32)
        );
        let (reverse_private, reverse_public) = batch_and_public_statement_from_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_public_inputs(),
            captured.iter().rev(),
        )
        .unwrap();
        assert_eq!(
            reverse_public.transcripts[0].batch_hash,
            captured[1].batch_hash
        );
        assert_eq!(
            reverse_public.transcripts[1].batch_hash,
            captured[0].batch_hash
        );
        assert_ne!(public.transcripts, reverse_public.transcripts);
        assert_eq!(public.transitions, dto_transitions(&private.transitions));
        assert_eq!(
            reverse_public.transitions,
            dto_transitions(&reverse_private.transitions)
        );
        assert_eq!(public.public_inputs, reverse_public.public_inputs);
        // Equal transfer effects can leave equal roots, but do not merge or
        // reorder the public transcript occurrences describing those effects.
        assert_ne!(
            norito::encode_canonical(&public).unwrap(),
            norito::encode_canonical(&reverse_public).unwrap()
        );
    }

    #[test]
    fn public_producer_preserves_self_transfer_zero_and_empty_cases() {
        let mut self_transfer = sample_transcript();
        let delta = &mut self_transfer.deltas[0];
        delta.to_account = delta.from_account.clone();
        delta.to_balance_before = Quantity::from(158_u32);
        delta.to_balance_after = Quantity::from(200_u32);
        let mut zero = sample_transcript();
        let delta = &mut zero.deltas[0];
        delta.amount = Quantity::zero();
        delta.from_balance_after = delta.from_balance_before.clone();
        delta.to_balance_after = delta.to_balance_before.clone();
        for captured in [vec![self_transfer], vec![zero], Vec::new()] {
            let inputs = sample_public_inputs();
            let expected_batch =
                batch_from_transcripts("producer-fixture-parameter", inputs, &captured).unwrap();
            let (private, public) = batch_and_public_statement_from_transcripts(
                "producer-fixture-parameter",
                inputs,
                &captured,
            )
            .unwrap();
            assert_eq!(
                norito::encode_canonical(&private).unwrap(),
                norito::encode_canonical(&expected_batch).unwrap()
            );
            assert_eq!(private.parameter, "producer-fixture-parameter");
            assert_eq!(public.public_inputs.old_root, public.public_inputs.new_root);
            assert_eq!(public.transcripts.len(), captured.len());
            assert_eq!(public.transitions.len(), captured.len() * 2);
            if captured.is_empty() {
                assert_eq!(public.public_inputs, inputs);
                assert!(private.metadata.is_empty());
            } else {
                assert_eq!(
                    public.transcripts[0].deltas[0].amount,
                    captured[0].deltas[0].amount
                );
                assert_eq!(
                    public.transcripts[0].deltas[0].from_account,
                    captured[0].deltas[0].from_account
                );
                assert_eq!(
                    public.transcripts[0].deltas[0].to_account,
                    captured[0].deltas[0].to_account
                );
            }
        }
    }

    #[test]
    fn public_producer_reports_repaired_precision_without_rewriting_capture() {
        let first = sample_transcript();
        let mut stale = sample_transcript();
        stale.batch_hash = Hash::prehashed([0x5A; 32]);
        let delta = &mut stale.deltas[0];
        delta.amount = "0.5".parse().unwrap();
        delta.from_balance_before = "158.001".parse().unwrap();
        delta.from_balance_after = "157.501".parse().unwrap();
        delta.to_balance_before = "43.001".parse().unwrap();
        delta.to_balance_after = "43.501".parse().unwrap();
        let captured = [first, stale];
        let (private, public) = batch_and_public_statement_from_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_public_inputs(),
            &captured,
        )
        .unwrap();
        let produced = &public.transcripts[1].deltas[0];
        assert_eq!(produced.amount, captured[1].deltas[0].amount);
        assert_eq!(produced.from_balance_before, Quantity::from(158_u32));
        assert_eq!(
            produced.from_balance_after,
            "157.5".parse::<Quantity>().unwrap()
        );
        assert_eq!(produced.to_balance_before, Quantity::from(43_u32));
        assert_eq!(
            produced.to_balance_after,
            "43.5".parse::<Quantity>().unwrap()
        );
        assert_eq!(
            captured[1].deltas[0].from_balance_before,
            "158.001".parse::<Quantity>().unwrap()
        );
        assert_eq!(public.transitions, dto_transitions(&private.transitions));
    }

    #[test]
    fn public_producer_is_independent_of_supplied_private_paths_and_outlives_batch() {
        let captured = sample_transcript();
        let (_, expected) = batch_and_public_statement_from_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_public_inputs(),
            [&captured],
        )
        .unwrap();
        let mut changed = captured.clone();
        let delta = &mut changed.deltas[0];
        for witness in [&mut delta.from_smt_witness, &mut delta.to_smt_witness] {
            witness.root_before = [0x11; 32];
            witness.root_after = [0x22; 32];
            witness.path_bits = vec![0xFF; 5];
            witness.siblings = vec![[0x33; 32]; 7];
        }
        let (mut private, public) = batch_and_public_statement_from_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_public_inputs(),
            [&changed],
        )
        .unwrap();
        assert_eq!(public, expected);
        assert_eq!(changed.deltas[0].from_smt_witness.path_bits.len(), 5);
        let before = norito::encode_canonical(&public).unwrap();
        private.metadata.clear();
        private.transitions.clear();
        drop(private);
        drop(changed);
        drop(captured);
        let restored: FastpqPublicTransferStatementV1 = decode_from_bytes(&before).unwrap();
        assert_eq!(restored, public);
        assert_eq!(norito::encode_canonical(&public).unwrap(), before);
    }

    #[test]
    fn public_producer_preserves_construction_errors_before_projection() {
        let mut empty = sample_transcript();
        empty.deltas.clear();
        let mut stale = sample_transcript();
        stale.poseidon_preimage_digest = Some(Hash::prehashed([0xEE; 32]));
        let mut invalid_balance = sample_transcript();
        invalid_balance.deltas[0].from_balance_after = Quantity::from(199_u32);
        let mut invalid_multi = sample_transcript();
        invalid_multi.deltas.push(invalid_multi.deltas[0].clone());
        invalid_multi.poseidon_preimage_digest = Some(Hash::prehashed([0xDD; 32]));
        for invalid in [empty, stale, invalid_balance, invalid_multi] {
            let valid = sample_transcript();
            let inputs = sample_public_inputs();
            let old =
                batch_from_transcripts(FASTPQ_CANONICAL_PARAMETER_SET, inputs, [&invalid, &valid])
                    .unwrap_err();
            let new = batch_and_public_statement_from_transcripts(
                FASTPQ_CANONICAL_PARAMETER_SET,
                inputs,
                [&invalid, &valid],
            )
            .unwrap_err();
            assert_eq!(format!("{new:?}"), format!("{old:?}"));
            let called = std::cell::Cell::new(false);
            let result = build_transfer_batch_with_projection(
                FASTPQ_CANONICAL_PARAMETER_SET,
                inputs,
                [&invalid, &valid],
                |_| {
                    called.set(true);
                },
            );
            assert!(result.is_err());
            assert!(
                !called.get(),
                "invalid captured relation must fail before public copying"
            );
        }
    }
    #[test]
    fn batch_from_transcripts_builds_transfer_rows() {
        let transcript = sample_transcript();
        let batch = batch_from_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_public_inputs(),
            [&transcript],
        )
        .unwrap();
        assert_eq!(batch.transitions.len(), 2);
        let delta = &transcript.deltas[0];
        let sender_key =
            balance_key(&delta.asset_definition, &delta.from_account).expect("sender key");
        let receiver_key =
            balance_key(&delta.asset_definition, &delta.to_account).expect("receiver key");
        let sender_row = batch
            .transitions
            .iter()
            .find(|row| row.key == sender_key.as_slice())
            .expect("sender row present");
        assert_eq!(sender_row.operation_rank(), OperationKind::Transfer.rank());
        assert_eq!(decode_le(&sender_row.pre_value), 200);
        assert_eq!(decode_le(&sender_row.post_value), 158);
        let receiver_row = batch
            .transitions
            .iter()
            .find(|row| row.key == receiver_key.as_slice())
            .expect("receiver row present");
        assert_eq!(decode_le(&receiver_row.pre_value), 1);
        assert_eq!(decode_le(&receiver_row.post_value), 43);
    }
    #[test]
    fn balance_key_batches_ignore_account_display_discriminant() {
        use iroha_data_model::account::address::ChainDiscriminantGuard;
        let transcript = sample_transcript();
        let expected = batch_from_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_public_inputs(),
            [&transcript],
        )
        .unwrap();
        for discriminant in [0, 369, 753, 65_535] {
            let _display = ChainDiscriminantGuard::enter(discriminant);
            for flags in [0, 1, 2, 3, 4, 5, 6, 7, 0x1b, 0x3f] {
                let _layout = norito::core::DecodeFlagsGuard::enter(flags);
                let actual = batch_from_transcripts(
                    FASTPQ_CANONICAL_PARAMETER_SET,
                    sample_public_inputs(),
                    [&transcript],
                )
                .unwrap();
                assert_eq!(actual, expected);
            }
        }
    }
    #[test]
    fn balance_key_matches_all_controller_golden_frames() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/fastpq/balance_key_v1.json");
        let fixture: norito::json::Value =
            norito::json::from_slice(&std::fs::read(path).expect("balance key fixture"))
                .expect("canonical fixture JSON");
        assert_eq!(
            fixture.get("schema").unwrap().as_str(),
            Some("iroha.fastpq.balance-key.v1")
        );
        assert_eq!(fixture.get("layout_flags").unwrap().as_u64(), Some(2));
        let uuid: [u8; 16] = hex::decode(fixture.get("asset_uuid_hex").unwrap().as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let asset = AssetDefinitionId::from_uuid_bytes(uuid).unwrap();
        let cases = fixture.get("positive").unwrap().as_array().unwrap();
        assert_eq!(
            cases.len(),
            16,
            "all eleven algorithms and five complete policies"
        );
        let _display = iroha_data_model::account::address::ChainDiscriminantGuard::enter(0);
        let _layout = norito::core::DecodeFlagsGuard::enter(0);
        for case in cases {
            let account: AccountId = norito::decode_canonical(
                &hex::decode(case.get("account_id_frame_hex").unwrap().as_str().unwrap()).unwrap(),
            )
            .unwrap();
            let expected =
                hex::decode(case.get("key_frame_hex").unwrap().as_str().unwrap()).unwrap();
            assert_eq!(
                balance_key(&asset, &account).unwrap(),
                expected,
                "{}",
                case.get("name").unwrap().as_str().unwrap()
            );
        }
    }
    #[test]
    fn batch_from_transcripts_rejects_empty_transcript_in_mixed_input() {
        let mut empty = sample_transcript();
        empty.deltas.clear();
        empty.poseidon_preimage_digest = None;
        let nonempty = sample_transcript();

        let err = batch_from_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_public_inputs(),
            [&empty, &nonempty],
        )
        .expect_err("every present transcript must contain a delta");
        assert!(matches!(
            err,
            TranscriptBatchError::TransferWitness {
                source: fastpq_prover::Error::TransferInvariant { details },
            } if details.contains("at least one delta")
        ));
    }
    #[test]
    fn batch_from_transcripts_rejects_invalid_supplied_digest_policy() {
        let mut stale = sample_transcript();
        stale.poseidon_preimage_digest = Some(Hash::prehashed([0xEE; Hash::LENGTH]));
        let err = batch_from_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_public_inputs(),
            [&stale],
        )
        .expect_err("stale single-delta digest must fail construction");
        assert!(matches!(
            err,
            TranscriptBatchError::TransferWitness {
                source: fastpq_prover::Error::TransferInvariant { details },
            } if details.contains("poseidon digest mismatch")
        ));

        let mut multi = sample_transcript();
        multi.deltas.push(multi.deltas[0].clone());
        multi.poseidon_preimage_digest = Some(Hash::prehashed([0xDD; Hash::LENGTH]));
        let err = batch_from_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_public_inputs(),
            [&multi],
        )
        .expect_err("multi-delta transcript cannot carry one aggregate digest");
        assert!(matches!(
            err,
            TranscriptBatchError::TransferWitness {
                source: fastpq_prover::Error::TransferInvariant { details },
            } if details.contains("multi-delta transcripts must omit")
        ));
    }
    #[test]
    fn batch_from_transcripts_embeds_transfer_metadata() {
        let transcript = sample_transcript();
        let batch = batch_from_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_public_inputs(),
            [&transcript],
        )
        .unwrap();
        let encoded = batch
            .metadata
            .get(TRANSFER_TRANSCRIPTS_METADATA_KEY)
            .expect("transfer metadata");
        let decoded: Vec<TransferTranscript> =
            decode_from_bytes(encoded).expect("decode transcripts");
        let mut expected = transcript;
        fastpq_prover::gadgets::transfer::attach_transfer_smt_witnesses(std::slice::from_mut(
            &mut expected,
        ))
        .expect("attach expected witnesses");
        expected.poseidon_preimage_digest = Some(poseidon_preimage_digest(
            &expected.deltas[0],
            &expected.batch_hash,
        ));
        assert_eq!(decoded, vec![expected]);
    }
    #[test]
    fn batch_from_transcripts_attaches_transfer_smt_witnesses() {
        let transcript = sample_transcript();
        let batch = batch_from_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_public_inputs(),
            [&transcript],
        )
        .expect("batch");
        let encoded = batch
            .metadata
            .get(TRANSFER_TRANSCRIPTS_METADATA_KEY)
            .expect("transfer metadata");
        let decoded: Vec<TransferTranscript> =
            decode_from_bytes(encoded).expect("decode transcripts");
        let delta = &decoded[0].deltas[0];
        assert_eq!(delta.from_smt_witness.path_bits.len(), 4);
        assert_eq!(delta.from_smt_witness.siblings.len(), 32);
        assert_eq!(delta.to_smt_witness.path_bits.len(), 4);
        assert_eq!(delta.to_smt_witness.siblings.len(), 32);
        assert_ne!(batch.public_inputs.old_root, [0; 32]);
        assert_ne!(batch.public_inputs.new_root, [0; 32]);
        fastpq_prover::gadgets::transfer::verify_transcripts(&batch.transitions, &decoded)
            .expect("transfer transcript rows verify");
        fastpq_prover::gadgets::transfer::transcripts_to_witnesses(
            &decoded,
            &batch.public_inputs.old_root,
            &batch.public_inputs.new_root,
        )
        .expect("transfer SMT witnesses verify");
    }
    #[test]
    fn batch_from_transcripts_chains_repeated_balance_keys() {
        let first = sample_transcript();
        let second = sample_transcript();
        let batch = batch_from_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_public_inputs(),
            [&first, &second],
        )
        .expect("batch");
        let encoded = batch
            .metadata
            .get(TRANSFER_TRANSCRIPTS_METADATA_KEY)
            .expect("transfer metadata");
        let decoded: Vec<TransferTranscript> =
            decode_from_bytes(encoded).expect("decode transcripts");
        let second_delta = &decoded[1].deltas[0];
        assert_eq!(second_delta.from_balance_before, Quantity::from(158u32));
        assert_eq!(second_delta.from_balance_after, Quantity::from(116u32));
        assert_eq!(second_delta.to_balance_before, Quantity::from(43u32));
        assert_eq!(second_delta.to_balance_after, Quantity::from(85u32));
        fastpq_prover::gadgets::transfer::verify_transcripts(&batch.transitions, &decoded)
            .expect("transfer transcript rows verify");
        fastpq_prover::gadgets::transfer::transcripts_to_witnesses(
            &decoded,
            &batch.public_inputs.old_root,
            &batch.public_inputs.new_root,
        )
        .expect("transfer SMT witnesses verify");
    }

    #[test]
    fn batch_from_transcripts_repairs_stale_precision_at_one_asset_scale() {
        let first = sample_transcript();
        let mut second = sample_transcript();
        second.batch_hash = Hash::prehashed([0x5A; 32]);
        let delta = &mut second.deltas[0];
        delta.amount = "0.5".parse().expect("non-negative FASTPQ quantity");
        delta.from_balance_before = "158.001".parse().expect("non-negative FASTPQ quantity");
        delta.from_balance_after = "157.501".parse().expect("non-negative FASTPQ quantity");
        delta.to_balance_before = "43.001".parse().expect("non-negative FASTPQ quantity");
        delta.to_balance_after = "43.501".parse().expect("non-negative FASTPQ quantity");
        delta.from_smt_witness = Default::default();
        delta.to_smt_witness = Default::default();
        second.poseidon_preimage_digest = None;

        let batch = batch_from_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_public_inputs(),
            [&first, &second],
        )
        .expect("mixed-scale repeated balances build");
        let encoded = batch
            .metadata
            .get(TRANSFER_TRANSCRIPTS_METADATA_KEY)
            .expect("transfer metadata");
        let decoded: Vec<TransferTranscript> =
            decode_from_bytes(encoded).expect("decode transcripts");
        let second_delta = &decoded[1].deltas[0];
        assert_eq!(second_delta.from_balance_before, Quantity::from(158_u64));
        assert_eq!(
            second_delta.from_balance_after,
            "157.5"
                .parse::<Quantity>()
                .expect("non-negative FASTPQ quantity")
        );
        assert_eq!(second_delta.to_balance_before, Quantity::from(43_u64));
        assert_eq!(
            second_delta.to_balance_after,
            "43.5"
                .parse::<Quantity>()
                .expect("non-negative FASTPQ quantity")
        );

        let sender_key = balance_key(&second_delta.asset_definition, &second_delta.from_account)
            .expect("canonical balance key");
        let sender_rows = batch
            .transitions
            .iter()
            .filter(|row| row.key == sender_key)
            .collect::<Vec<_>>();
        assert_eq!(sender_rows.len(), 2);
        assert_eq!(decode_le(&sender_rows[0].pre_value), 2_000);
        assert_eq!(decode_le(&sender_rows[0].post_value), 1_580);
        assert_eq!(decode_le(&sender_rows[1].pre_value), 1_580);
        assert_eq!(decode_le(&sender_rows[1].post_value), 1_575);

        fastpq_prover::gadgets::transfer::verify_transcripts(&batch.transitions, &decoded)
            .expect("mixed-scale transition rows verify");
        fastpq_prover::gadgets::transfer::transcripts_to_witnesses(
            &decoded,
            &batch.public_inputs.old_root,
            &batch.public_inputs.new_root,
        )
        .expect("mixed-scale SMT witnesses verify");
    }
    #[test]
    fn batch_from_transcripts_normalizes_mixed_scale_values() {
        let mut transcript = sample_transcript();
        transcript.deltas[0].amount = "0.5".parse().expect("non-negative FASTPQ quantity");
        transcript.deltas[0].from_balance_before = Quantity::from(1_u64);
        transcript.deltas[0].from_balance_after =
            "0.5".parse().expect("non-negative FASTPQ quantity");
        transcript.deltas[0].to_balance_before = Quantity::from(0_u64);
        transcript.deltas[0].to_balance_after =
            "0.5".parse().expect("non-negative FASTPQ quantity");
        let batch = batch_from_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_public_inputs(),
            [&transcript],
        )
        .expect("batch");
        let sender_row = batch
            .transitions
            .iter()
            .find(|row| {
                row.key
                    == balance_key(
                        &transcript.deltas[0].asset_definition,
                        &transcript.deltas[0].from_account,
                    )
                    .expect("canonical balance key")
            })
            .expect("sender row");
        let receiver_row = batch
            .transitions
            .iter()
            .find(|row| {
                row.key
                    == balance_key(
                        &transcript.deltas[0].asset_definition,
                        &transcript.deltas[0].to_account,
                    )
                    .expect("canonical balance key")
            })
            .expect("receiver row");
        assert_eq!(decode_le(&sender_row.pre_value), 10);
        assert_eq!(decode_le(&sender_row.post_value), 5);
        assert_eq!(decode_le(&receiver_row.pre_value), 0);
        assert_eq!(decode_le(&receiver_row.post_value), 5);
    }
    #[test]
    fn batch_from_transcripts_trims_padded_balance_scale() {
        let mut transcript = sample_transcript();
        transcript.deltas[0].amount = "0.011".parse().expect("non-negative FASTPQ quantity");
        transcript.deltas[0].from_balance_before = Quantity::from(120_000_u64);
        transcript.deltas[0].from_balance_after =
            "119999.989".parse().expect("non-negative FASTPQ quantity");
        transcript.deltas[0].to_balance_before = Quantity::zero();
        transcript.deltas[0].to_balance_after =
            "0.011".parse().expect("non-negative FASTPQ quantity");
        let batch = batch_from_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_public_inputs(),
            [&transcript],
        )
        .expect("batch");
        let sender_row = batch
            .transitions
            .iter()
            .find(|row| {
                row.key
                    == balance_key(
                        &transcript.deltas[0].asset_definition,
                        &transcript.deltas[0].from_account,
                    )
                    .expect("canonical balance key")
            })
            .expect("sender row");
        let receiver_row = batch
            .transitions
            .iter()
            .find(|row| {
                row.key
                    == balance_key(
                        &transcript.deltas[0].asset_definition,
                        &transcript.deltas[0].to_account,
                    )
                    .expect("canonical balance key")
            })
            .expect("receiver row");
        assert_eq!(decode_le(&sender_row.pre_value), 120_000_000);
        assert_eq!(decode_le(&sender_row.post_value), 119_999_989);
        assert_eq!(decode_le(&receiver_row.pre_value), 0);
        assert_eq!(decode_le(&receiver_row.post_value), 11);
    }
    #[test]
    fn batches_from_bundles_add_metadata() {
        let bundle = sample_bundle(Hash::prehashed([0x33; 32]));
        let batches = batches_from_bundles(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_template(),
            sample_tx_set_hash(),
            [&bundle],
        )
        .expect("batches");
        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        let entry_hex = batch
            .metadata
            .get(ENTRY_HASH_METADATA_KEY)
            .map(hex::encode)
            .expect("entry hash metadata");
        assert_eq!(entry_hex, hex::encode(bundle.entry_hash.as_ref()));
        let transcript_count_bytes = batch
            .metadata
            .get(TRANSCRIPT_COUNT_METADATA_KEY)
            .expect("transcript count metadata");
        assert_eq!(
            decode_le(transcript_count_bytes),
            bundle.transcripts.len() as u64
        );
    }
    #[test]
    fn batch_from_transcript_bundle_adds_axt_entry_metadata() {
        let bundle = sample_bundle(Hash::prehashed([0x34; 32]));
        let batch = batch_from_transcript_bundle(
            FASTPQ_CANONICAL_PARAMETER_SET,
            public_inputs_from_dto(&sample_public_inputs()),
            bundle.entry_hash,
            &bundle.transcripts,
        )
        .expect("batch");
        assert_eq!(batch.transitions.len(), 2);
        let entry_hex = batch
            .metadata
            .get(ENTRY_HASH_METADATA_KEY)
            .map(hex::encode)
            .expect("entry hash metadata");
        assert_eq!(entry_hex, hex::encode(bundle.entry_hash.as_ref()));
        assert!(
            batch
                .metadata
                .contains_key(TRANSFER_TRANSCRIPTS_METADATA_KEY)
        );
    }
    #[test]
    fn batches_from_exec_witness_match_bundle_order() {
        let bundle_a = sample_bundle(Hash::prehashed([0x41; 32]));
        let bundle_b = sample_bundle(Hash::prehashed([0x42; 32]));
        let bundles = [&bundle_a, &bundle_b];
        let built = batches_from_bundles(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_template(),
            sample_tx_set_hash(),
            bundles,
        )
        .expect("batches");
        let witness = ExecWitness {
            reads: Vec::new(),
            writes: Vec::new(),
            fastpq_transcripts: vec![bundle_a.clone(), bundle_b.clone()],
            fastpq_batches: built.iter().map(transition_batch_to_dto).collect(),
        };
        let batches = batches_from_exec_witness(&witness).expect("batches");
        assert_eq!(batches.len(), 2);
        let first_entry = hex::encode(
            batches[0]
                .metadata
                .get(ENTRY_HASH_METADATA_KEY)
                .expect("metadata"),
        );
        let second_entry = hex::encode(
            batches[1]
                .metadata
                .get(ENTRY_HASH_METADATA_KEY)
                .expect("metadata"),
        );
        assert_eq!(first_entry, hex::encode(bundle_a.entry_hash.as_ref()));
        assert_eq!(second_entry, hex::encode(bundle_b.entry_hash.as_ref()));
    }
    #[test]
    fn batches_from_exec_witness_rejects_bundle_batch_cardinality_mismatch() {
        let bundle_a = sample_bundle(Hash::prehashed([0x51; 32]));
        let bundle_b = sample_bundle(Hash::prehashed([0x52; 32]));
        let built = batches_from_bundles(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_template(),
            sample_tx_set_hash(),
            [&bundle_a],
        )
        .expect("batch");
        let witness = ExecWitness {
            fastpq_transcripts: vec![bundle_a, bundle_b],
            fastpq_batches: built.iter().map(transition_batch_to_dto).collect(),
            ..ExecWitness::default()
        };

        assert!(matches!(
            batches_from_exec_witness(&witness),
            Err(TranscriptBatchError::FastpqBatchCardinality {
                bundle_count: 2,
                batch_count: 1,
            })
        ));
    }
    #[test]
    fn batches_from_exec_witness_rejects_batch_not_bound_to_indexed_bundle() {
        let bundle = sample_bundle(Hash::prehashed([0x53; 32]));
        let mut built = batches_from_bundles(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_template(),
            sample_tx_set_hash(),
            [&bundle],
        )
        .expect("batch");
        built[0].transitions[0].post_value[0] ^= 0x01;
        let witness = ExecWitness {
            fastpq_transcripts: vec![bundle],
            fastpq_batches: built.iter().map(transition_batch_to_dto).collect(),
            ..ExecWitness::default()
        };

        assert!(matches!(
            batches_from_exec_witness(&witness),
            Err(TranscriptBatchError::FastpqBatchBinding { batch_index: 0 })
        ));
    }
    #[test]
    fn batches_from_exec_witness_rejects_missing_batches() {
        let bundle = sample_bundle(Hash::prehashed([0x43; 32]));
        let witness = ExecWitness {
            reads: Vec::new(),
            writes: Vec::new(),
            fastpq_transcripts: vec![bundle],
            fastpq_batches: Vec::new(),
        };
        let err = batches_from_exec_witness(&witness).expect_err("missing batches");
        assert!(matches!(err, TranscriptBatchError::MissingFastpqBatches));
    }
    #[test]
    fn batches_from_exec_witness_prefers_prebuilt_batches() {
        let transcript = sample_transcript();
        let batch = batch_from_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_public_inputs(),
            [&transcript],
        )
        .unwrap();
        let dto = transition_batch_to_dto(&batch);
        let witness = ExecWitness {
            reads: Vec::new(),
            writes: Vec::new(),
            fastpq_transcripts: Vec::new(),
            fastpq_batches: vec![dto],
        };
        let batches = batches_from_exec_witness(&witness).expect("batches");
        assert_eq!(batches.len(), 1);
        assert_eq!(
            dto_transitions(&batches[0].transitions),
            dto_transitions(&batch.transitions)
        );
    }
    #[test]
    fn transition_batch_dto_roundtrip_preserves_all_operation_payloads_and_metadata() {
        let transcript = sample_transcript();
        let mut batch = batch_from_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_public_inputs(),
            [&transcript],
        )
        .unwrap();
        batch.public_inputs = PublicInputs {
            dsid: [0x11; 16],
            slot: 42,
            old_root: [0x22; 32],
            new_root: [0x33; 32],
            perm_root: [0x44; 32],
            tx_set_hash: [0x55; 32],
        };
        for (index, operation) in [
            OperationKind::Mint,
            OperationKind::Burn,
            OperationKind::RoleGrant {
                role_id: [0x11; 32],
                permission_id: [0x22; 32],
                epoch: 7,
            },
            OperationKind::RoleRevoke {
                role_id: [0x33; 32],
                permission_id: [0x44; 32],
                epoch: 8,
            },
            OperationKind::MetaSet,
        ]
        .into_iter()
        .enumerate()
        {
            // This is deliberately a codec/conversion fixture. Semantic tests
            // construct canonical tree keys and membership leaves in the
            // prover crate before attempting to build a trace.
            let value = u8::try_from(index).expect("operation fixture index fits u8");
            batch.push(StateTransition::new(
                format!("roundtrip/{index}").into_bytes(),
                vec![value],
                vec![value + 1],
                operation,
            ));
        }
        batch.metadata.insert("test".into(), vec![0xAA, 0xBB, 0xCC]);
        let dto = transition_batch_to_dto(&batch);
        let restored = transition_batch_from_dto(&dto);
        assert_eq!(restored.parameter, batch.parameter);
        assert_eq!(
            dto_transitions(&restored.transitions),
            dto_transitions(&batch.transitions)
        );
        assert_eq!(restored.public_inputs, batch.public_inputs);
        assert_eq!(restored.metadata, batch.metadata);
    }
    #[test]
    fn dto_batches_from_transcripts_embed_entry_hash() {
        let bundle = sample_bundle(Hash::prehashed([0x24; 32]));
        let mut map = BTreeMap::new();
        map.insert(bundle.entry_hash, bundle.transcripts.clone());
        let batches = dto_batches_from_transcripts(
            FASTPQ_CANONICAL_PARAMETER_SET,
            sample_template(),
            sample_tx_set_hash(),
            &map,
        )
        .expect("dto");
        assert_eq!(batches.len(), 1);
        let entry_hex = hex::encode(
            batches[0]
                .metadata
                .get(ENTRY_HASH_METADATA_KEY)
                .expect("entry metadata"),
        );
        assert_eq!(entry_hex, hex::encode(Hash::prehashed([0x24; 32]).as_ref()));
    }
    fn dto_transitions(transitions: &[StateTransition]) -> Vec<FastpqStateTransition> {
        transitions.iter().map(state_transition_to_dto).collect()
    }
    fn decode_le(bytes: &[u8]) -> u64 {
        let mut chunk = [0u8; 8];
        chunk[..bytes.len()].copy_from_slice(bytes);
        u64::from_le_bytes(chunk)
    }
    fn fastpq_cfg(
        execution_mode: FastpqExecutionMode,
        poseidon_mode: FastpqPoseidonMode,
    ) -> Fastpq {
        Fastpq {
            execution_mode,
            poseidon_mode,
            proof_sidecar_queue_cap:
                iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_QUEUE_CAP,
            proof_sidecar_max_bytes:
                iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_MAX_BYTES,
            proof_sidecar_max_retries:
                iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_MAX_RETRIES,
            device_class: None,
            chip_family: None,
            gpu_kind: None,
            metal_queue_fanout: None,
            metal_queue_column_threshold: None,
            metal_max_in_flight: None,
            metal_threadgroup_width: None,
            metal_trace: iroha_config::parameters::defaults::zk::fastpq::METAL_TRACE,
            metal_debug_enum: iroha_config::parameters::defaults::zk::fastpq::METAL_DEBUG_ENUM,
        }
    }
    fn sample_template() -> FastpqPublicInputsTemplate {
        FastpqPublicInputsTemplate {
            dsid: [0u8; 16],
            slot: 0,
            old_root: [0u8; 32],
            new_root: [0u8; 32],
            perm_root: [0u8; 32],
        }
    }
    fn sample_public_inputs() -> FastpqPublicInputs {
        sample_template().with_tx_set_hash(sample_tx_set_hash())
    }
    fn sample_tx_set_hash() -> [u8; 32] {
        [0xCC; 32]
    }
    fn sample_transcript() -> TransferTranscript {
        let asset = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        TransferTranscript {
            batch_hash: Hash::prehashed([0xAA; 32]),
            deltas: vec![TransferDeltaTranscript {
                from_account: (*ALICE_ID).clone(),
                to_account: (*BOB_ID).clone(),
                asset_definition: asset,
                amount: Quantity::from(42u32),
                from_balance_before: Quantity::from(200u32),
                from_balance_after: Quantity::from(158u32),
                to_balance_before: Quantity::from(1u32),
                to_balance_after: Quantity::from(43u32),
                from_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
                to_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
            }],
            authority_digest: authority_digest(&ALICE_ID),
            poseidon_preimage_digest: None,
        }
    }
    fn encoded_transfer_digest_preimage(
        delta: &TransferDeltaTranscript,
        batch_hash: &Hash,
    ) -> Vec<u8> {
        let mut encoded = Vec::new();
        delta.from_account.encode_to(&mut encoded);
        delta.to_account.encode_to(&mut encoded);
        delta.asset_definition.encode_to(&mut encoded);
        delta.amount.encode_to(&mut encoded);
        encoded.extend_from_slice(batch_hash.as_ref());
        encoded
    }
    fn sample_bundle(entry_hash: Hash) -> TransferTranscriptBundle {
        TransferTranscriptBundle {
            entry_hash,
            transcripts: vec![sample_transcript()],
        }
    }
}
