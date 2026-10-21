//! Bounded, authenticated outcome of one exact committed Network transaction.
//!
//! A status read needs one transaction's committed result, not its whole block. This reader
//! authenticates exactly that result without decoding any transaction body, so its memory and
//! decoding depend on the walked headers and certificates, the block's Network input and output
//! counts and the one matched output, never on the size of a transaction.
//!
//! What authenticates what:
//! - the target's Iroha header must hash to the State hash journal entry; its `merkle_root`
//!   commits the ordered Network input hashes. The block's execution context repeats those
//!   hashes in the same order (a block is valid only when they agree, see
//!   `block.rs::validate_execution_context_alignment`), so recomputing the root from the
//!   context authenticates the list and the target's index without reading the inputs;
//! - the target's certified result `R` is reached by the same descending walk as
//!   [`CanonicalHistorySource::visit_executed_backwards_from_checkpoints`]: it starts at the
//!   captured State native tip or at a checkpoint that the hash journal confirms, and every
//!   walked height checks its Iroha hash against the journal and its core hash and `R` against
//!   the parent links of its successor. Only the walked headers and certificates are read;
//! - the preimage of `R` commits the root and count of every typed output hash. Each output's
//!   canonical bytes are streamed into its hash and the root is recomputed; only matched
//!   outputs are decoded, and a decoded output must hash to its leaf;
//! - a sealed reveal is also indexed by its inner signed transaction. That alias hash is
//!   streamed from the reveal's inner payload bytes, never decoded, in the same pass that
//!   hashes the whole reveal against its committed Network input hash, so an alias is derived
//!   only from authenticated bytes.
//!
//! The certificate's binding of the core header to the proposal wire (`payload_hash`) is not
//! recomputed: it would need every body byte, and no value this reader returns depends on those
//! bytes. Every returned outcome is bound by a hash to the journal or to `R`. This is a
//! positive-membership reader: it refuses an unresolved identity instead of asserting absence,
//! because the skipped non-reveal bodies and their variant tags do not authenticate absence.
//!
//! Every byte comes from one exact window of the durable slot (`NativeFrameRead::read_window`).
//! A window is charged only to the caller's physical frame pool and released before the next,
//! and all windows together are charged to the caller's history byte allowance. Decoded pieces
//! charge the caller's cumulative decoder context. A piece larger than the caller's frame pool
//! is refused by that pool as a demand that can never fit.

use std::{collections::BTreeSet, num::NonZeroUsize};

use iroha_crypto::{Hash, HashOf, MerkleTree, MerkleTreeCommitment};
use iroha_data_model::{
    block::{
        BlockHeader, CommitCertificate, SignedBlock,
        execution_context::{BlockExecutionContextBundle, ExternalExecutionContext},
        execution_output::ExecutionOutputV1,
    },
    query::error::{CanonicalHistoryError, QueryExecutionFail},
    sumeragi_finality::{CertifiedResultError, CertifiedResultV1, EpochValidationScope},
    transaction::{TransactionEntrypoint, error::TransactionRejectionReason},
};
use iroha_sumeragi::types::Hash32;

use super::{CanonicalHistoryReadBudget, CanonicalHistorySource, WalkStart};
use crate::{
    execution_attempt::{ExecutionAttemptError, canonical_decode_attempt_error},
    kura::history_checkpoints::HistoryCheckpoint,
    smartcontracts::isi::tx::CommittedNetworkOutcome,
    sumeragi::certified_chain::ChainReadError,
};

type ReadError = super::CommittedOutcomeReadError;

fn invalid(message: impl Into<String>) -> ReadError {
    QueryExecutionFail::Conversion(message.into()).into()
}

fn chain_error(error: &ChainReadError) -> ReadError {
    invalid(error.to_string())
}

fn decode_error(error: norito::core::DecodeAttemptError) -> ReadError {
    canonical_decode_attempt_error(error, |error| {
        QueryExecutionFail::Conversion(error.to_string())
    })
    .into()
}

// Same classification as `certified_chain::frame_result_error`: an original decoder budget
// refusal stays local; every completed result defect is a malformed certificate.
fn certified_result_error(height: u64, error: CertifiedResultError) -> ReadError {
    match error {
        CertifiedResultError::Body(crate::sumeragi::commitment::CommitmentError::Resource(
            error,
        )) => canonical_decode_attempt_error(error, |error| {
            QueryExecutionFail::Conversion(
                ChainReadError::Malformed {
                    height,
                    reason: error.to_string(),
                }
                .to_string(),
            )
        })
        .into(),
        completed => chain_error(&ChainReadError::Malformed {
            height,
            reason: completed.to_string(),
        }),
    }
}

/// Positions of the derived `SignedBlock` record fields this reader uses (declaration order).
#[derive(Clone, Copy)]
enum BlockField {
    Payload = 1,
    Result = 2,
    Certificate = 3,
}

/// Positions of the derived `BlockPayload` record fields this reader uses (declaration order).
/// `ExecutionContext` is the last of its eight fields.
#[derive(Clone, Copy)]
enum PayloadField {
    Header = 0,
    ExternalEntrypoints = 1,
    ExecutionContext = 7,
}

/// Leading fields of the derived records this reader enters (declaration order).
#[derive(Clone, Copy)]
enum RecordField {
    /// `BlockResult::outputs`.
    First = 0,
    /// `BlockExecutionContextBundle::external`, `SealedTransactionReveal::signed_transaction`
    /// and `SignedTransaction::payload`; the field before each is read only as a prefix.
    Second = 1,
}

/// Variant tags of the derived `TransactionEntrypoint` enum (canonical little-endian `u32`).
#[derive(Clone, Copy)]
enum EntrypointTag {
    External = 0,
    SealedCommitment = 1,
    SealedReveal = 2,
    /// Signerless carrier; tag 3 is retired and remains invalid.
    AnonymousBallot = 4,
}

impl EntrypointTag {
    fn wire(self) -> [u8; size_of::<u32>()] {
        (self as u32).to_le_bytes()
    }
}

/// Bytes of the longest canonical compact length of a `u64`: seven payload bits per byte.
fn longest_compact_len_prefix() -> usize {
    usize::try_from(u64::BITS.div_ceil(7)).unwrap_or(usize::MAX)
}

/// Decode one canonical compact length (`COMPACT_LEN` varint) from the front of `bytes`.
///
/// Returns the value and the prefix length. Overlong, overflowing and truncated encodings are
/// refused, exactly as the Norito decoder refuses them; no decoder budget is charged, because
/// the length only positions the next read and every value read there is authenticated.
fn decode_compact_len(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0_u64;
    for (index, byte) in bytes.iter().copied().enumerate() {
        let shift = u32::try_from(index).ok()?.checked_mul(7)?;
        let part = u64::from(byte & 0x7f);
        let shifted = part.checked_shl(shift)?;
        if shifted.checked_shr(shift) != Some(part) {
            return None;
        }
        value |= shifted;
        if byte & 0x80 == 0 {
            if index != 0 && byte == 0 {
                return None;
            }
            return Some((value, index.checked_add(1)?));
        }
    }
    None
}

/// Exact `[offset, offset + len)` range of the original frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Span {
    offset: u64,
    len: u64,
}

impl Span {
    fn end(self) -> Result<u64, ReadError> {
        self.offset
            .checked_add(self.len)
            .ok_or_else(|| invalid("frame span exceeds the addressable range"))
    }

    // A sub-range that must lie inside `self`.
    fn within(self, offset: u64, len: u64) -> Result<Self, ReadError> {
        let inner = Self { offset, len };
        if offset < self.offset || inner.end()? > self.end()? {
            return Err(invalid("frame field exceeds its enclosing record"));
        }
        Ok(inner)
    }
}

/// Finite source allowance of one read: walked frames and window bytes.
struct SourceWork {
    blocks: u64,
    bytes: u64,
    max_blocks: u64,
    max_bytes: u64,
}

impl SourceWork {
    fn block(&mut self) -> Result<(), ReadError> {
        self.blocks = self
            .blocks
            .checked_add(1)
            .filter(|blocks| *blocks <= self.max_blocks)
            .ok_or(QueryExecutionFail::GasBudgetExceeded)?;
        Ok(())
    }

    fn bytes(&mut self, len: u64) -> Result<(), ReadError> {
        self.bytes = self
            .bytes
            .checked_add(len)
            .filter(|bytes| *bytes <= self.max_bytes)
            .ok_or(QueryExecutionFail::GasBudgetExceeded)?;
        Ok(())
    }

    // Only authenticated target commitments establish work that checkpoints cannot remove.
    fn certified_target_rows(&self, inputs: u64, outputs: u64) -> Result<(), ReadError> {
        let required = inputs
            .max(outputs)
            .max(1)
            .checked_add(1)
            .ok_or_else(|| invalid("certified target work exceeds the addressable range"))?;
        if required > self.max_blocks {
            return Err(ReadError::TargetWorkBudgetExceeded {
                required,
                limit: self.max_blocks,
            });
        }
        Ok(())
    }

    // The target's observed validation work: Network inputs and every typed output
    // (at least one), after all walked source frames. Raw sequence prefixes alone do
    // not establish a permanent target demand.
    fn rows(&self, inputs: u64, outputs: u64) -> Result<(), ReadError> {
        inputs
            .max(outputs)
            .max(1)
            .checked_add(self.blocks)
            .filter(|work| *work <= self.max_blocks)
            .ok_or(QueryExecutionFail::GasBudgetExceeded)?;
        Ok(())
    }
}

/// Top-level record spans of one frame.
struct BlockLayout {
    payload: Span,
    result: Span,
    certificate: Span,
}

/// Bounded windows of one admitted original frame slot.
struct FrameWindows<'a> {
    source: crate::kura::NativeFrameRead<'a>,
    height: u64,
    expected: HashOf<BlockHeader>,
    pool: &'a iroha_allocation::AllocationBudget,
    work: &'a mut SourceWork,
}

impl<'a> FrameWindows<'a> {
    // Capture the original slot exactly as `block_with_original_admission` does: a missing or
    // unavailable journal is body unavailability; every other storage error keeps its class.
    fn open(
        history: &'a CanonicalHistorySource<'_>,
        index: NonZeroUsize,
        height: u64,
        expected: HashOf<BlockHeader>,
        work: &'a mut SourceWork,
    ) -> Result<Self, ReadError> {
        if history.kura.is_canonical_body_missing(index) {
            return Err(missing(height, expected));
        }
        let source = history
            .kura
            .native_frame_read(height, expected)
            .map_err(|error| storage_error(height, expected, error))?
            .ok_or_else(|| missing(height, expected))?;
        Ok(Self {
            source,
            height,
            expected,
            pool: &history.budget,
            work,
        })
    }

    fn wire_len(&self) -> u64 {
        self.source.wire_len()
    }

    /// Read exactly `span` into one window charged to the caller's frame pool.
    fn read(&mut self, span: Span) -> Result<crate::kura::NativeFrameBytes, ReadError> {
        self.work.bytes(span.len)?;
        let len = usize::try_from(span.len).map_err(|_| QueryExecutionFail::GasBudgetExceeded)?;
        self.source
            .read_window(self.wire_len(), span.offset, len, self.pool)
            .map_err(|error| storage_error(self.height, self.expected, error))?
            .ok_or_else(|| missing(self.height, self.expected))
    }

    /// Read at most `lead` fixed bytes plus one compact length at `offset`, within `bound`.
    fn probe(
        &mut self,
        offset: u64,
        bound: Span,
        lead: usize,
    ) -> Result<crate::kura::NativeFrameBytes, ReadError> {
        let remaining = bound.end()?.checked_sub(offset).unwrap_or_default();
        let wanted = u64::try_from(lead.saturating_add(longest_compact_len_prefix()))
            .map_err(|_| invalid("frame probe exceeds the addressable range"))?;
        let len = remaining.min(wanted);
        if len == 0 {
            return Err(invalid("frame field prefix is truncated"));
        }
        self.read(bound.within(offset, len)?)
    }

    /// The `[len]` prefixed payload starting at `offset` inside `bound`.
    fn prefixed(&mut self, offset: u64, bound: Span) -> Result<Span, ReadError> {
        let probe = self.probe(offset, bound, 0)?;
        let (len, used) = decode_compact_len(probe.as_slice())
            .ok_or_else(|| invalid("frame field has a non-canonical length prefix"))?;
        let start = offset
            .checked_add(u64::try_from(used).map_err(|_| invalid("frame prefix overflows"))?)
            .ok_or_else(|| invalid("frame prefix overflows"))?;
        bound.within(start, len)
    }

    /// Spans of the first `N` fields of the derived record `record`.
    fn fields<const N: usize>(&mut self, record: Span) -> Result<[Span; N], ReadError> {
        let mut spans = [Span { offset: 0, len: 0 }; N];
        let mut at = record.offset;
        for span in &mut spans {
            *span = self.prefixed(at, record)?;
            at = span.end()?;
        }
        Ok(spans)
    }

    /// Like [`Self::fields`], also requiring that the `N` fields fill `record` exactly.
    fn exact_fields<const N: usize>(&mut self, record: Span) -> Result<[Span; N], ReadError> {
        let spans = self.fields::<N>(record)?;
        let end = match spans.last() {
            Some(last) => last.end()?,
            None => record.offset,
        };
        if end != record.end()? {
            return Err(invalid("frame record holds bytes after its last field"));
        }
        Ok(spans)
    }

    /// The payload of an `Option` field: `None` is `[0]`, `Some` is `[1][len][payload]`.
    fn option(&mut self, field: Span) -> Result<Option<Span>, ReadError> {
        let probe = self.probe(field.offset, field, size_of::<u8>())?;
        let bytes = probe.as_slice();
        match bytes.first().copied() {
            Some(0) if field.len == 1 => Ok(None),
            Some(1) => {
                let (len, used) = decode_compact_len(&bytes[1..])
                    .ok_or_else(|| invalid("frame option has a non-canonical length prefix"))?;
                let start = field
                    .offset
                    .checked_add(1)
                    .and_then(|offset| offset.checked_add(u64::try_from(used).ok()?))
                    .ok_or_else(|| invalid("frame option prefix overflows"))?;
                let inner = field.within(start, len)?;
                if inner.end()? != field.end()? {
                    return Err(invalid("frame option holds bytes after its value"));
                }
                Ok(Some(inner))
            }
            _ => Err(invalid("frame option has an invalid tag")),
        }
    }

    /// The element count and first element offset of a derived `Vec<T>` field.
    fn sequence(&mut self, field: Span) -> Result<(u64, u64), ReadError> {
        let count_len = u64::try_from(size_of::<u64>()).unwrap_or(u64::MAX);
        let bytes = self.read(field.within(field.offset, count_len)?)?;
        let count = <[u8; size_of::<u64>()]>::try_from(bytes.as_slice())
            .map(u64::from_le_bytes)
            .map_err(|_| invalid("frame sequence count is truncated"))?;
        let first = field
            .offset
            .checked_add(count_len)
            .ok_or_else(|| invalid("frame sequence overflows"))?;
        Ok((count, first))
    }

    /// Decode `span` as the bare canonical payload of `T` under the active decoder context.
    fn decode<T>(&mut self, span: Span) -> Result<T, ReadError>
    where
        T: for<'de> norito::core::DeserializePayload<'de> + norito::core::SerializePayload,
    {
        let bytes = self.read(span)?;
        norito::core::classify_decode_attempt(|| {
            norito::codec::decode_adaptive::<T>(bytes.as_slice())
        })
        .map_err(decode_error)
    }

    /// Pass the bytes of `span` to `sink` with their frame offsets, in windows no larger than
    /// the frame pool currently admits; the bytes are never retained together.
    fn stream(
        &mut self,
        span: Span,
        sink: &mut dyn FnMut(u64, &[u8]) -> std::io::Result<()>,
    ) -> Result<(), ReadError> {
        let end = span.end()?;
        let mut at = span.offset;
        while at != end {
            let available = self
                .pool
                .limit_bytes()
                .saturating_sub(self.pool.reserved_bytes());
            let chunk = u64::try_from(available.max(1))
                .unwrap_or(u64::MAX)
                .min(end - at);
            let window = self.read(Span {
                offset: at,
                len: chunk,
            })?;
            sink(at, window.as_slice())
                .map_err(|error| invalid(format!("frame hash failed: {error}")))?;
            at += chunk;
        }
        Ok(())
    }

    /// Hash `lead` followed by the bytes of `span`, streamed (see [`Self::stream`]).
    fn hash(&mut self, lead: &[u8], span: Span) -> Result<Hash, ReadError> {
        let mut failure = None;
        let hash = Hash::new_from_writer(|writer| {
            writer.write_all(lead)?;
            if let Err(error) = self.stream(span, &mut |_, bytes| writer.write_all(bytes)) {
                failure = Some(error);
                return Err(std::io::Error::other("frame window refused"));
            }
            Ok(())
        });
        if let Some(error) = failure {
            return Err(error);
        }
        hash.map_err(|error| invalid(format!("frame hash failed: {error}")))
    }

    /// Hash `span`, and in the same single pass `part_lead` followed by the bytes of `part`
    /// (which lies inside `span`): a part is then derived only from bytes whose whole is
    /// authenticated, and those bytes are read once.
    fn hash_with_part(
        &mut self,
        span: Span,
        part_lead: &[u8],
        part: Span,
    ) -> Result<(Hash, Hash), ReadError> {
        let part = span.within(part.offset, part.len)?;
        let part_end = part.end()?;
        let mut failure = None;
        let mut part_hash = None;
        let whole = Hash::new_from_writer(|whole| {
            let inner = Hash::new_from_writer(|inner| {
                inner.write_all(part_lead)?;
                let streamed = self.stream(span, &mut |at, bytes| {
                    whole.write_all(bytes)?;
                    let len = u64::try_from(bytes.len()).map_err(std::io::Error::other)?;
                    let window_end = at.checked_add(len).ok_or_else(|| {
                        std::io::Error::other("frame window exceeds the addressable range")
                    })?;
                    let from = part.offset.max(at);
                    let to = part_end.min(window_end);
                    if from < to {
                        let start = usize::try_from(from - at).map_err(std::io::Error::other)?;
                        let stop = usize::try_from(to - at).map_err(std::io::Error::other)?;
                        inner.write_all(&bytes[start..stop])?;
                    }
                    Ok(())
                });
                if let Err(error) = streamed {
                    failure = Some(error);
                    return Err(std::io::Error::other("frame window refused"));
                }
                Ok(())
            })?;
            part_hash = Some(inner);
            Ok(())
        });
        if let Some(error) = failure {
            return Err(error);
        }
        let whole = whole.map_err(|error| invalid(format!("frame hash failed: {error}")))?;
        let part = part_hash.ok_or_else(|| invalid("frame part hash is missing"))?;
        Ok((whole, part))
    }

    /// Spans of the `SignedBlock` record after checking the version byte and Norito header.
    fn layout(&mut self) -> Result<BlockLayout, ReadError> {
        let head_len = norito::core::Header::SIZE
            .checked_add(size_of::<u8>())
            .ok_or_else(|| invalid("frame head overflows"))?;
        let head_len = u64::try_from(head_len).map_err(|_| invalid("frame head overflows"))?;
        let frame = Span {
            offset: 0,
            len: self.wire_len(),
        };
        let head = self.read(frame.within(0, head_len)?)?;
        let (&version, header) = head
            .as_slice()
            .split_first()
            .ok_or_else(|| invalid("frame is empty"))?;
        if version != SignedBlock::WIRE_VERSION {
            return Err(invalid("frame has an unsupported block wire version"));
        }
        let header = norito::core::Header::read(header)
            .map_err(|error| invalid(format!("frame header is invalid: {error}")))?;
        if !matches!(header.compression, norito::core::Compression::None)
            || header.schema != norito::schema::identity::frame_hash::<SignedBlock>()
            || header.flags != norito::core::default_encode_flags()
        {
            return Err(invalid("frame header is not the canonical block layout"));
        }
        let payload = frame.within(head_len, header.length)?;
        if payload.end()? != frame.end()? {
            return Err(invalid(
                "frame payload length differs from its durable slot",
            ));
        }
        let fields = self.exact_fields::<{ BlockField::Certificate as usize + 1 }>(payload)?;
        Ok(BlockLayout {
            payload: fields[BlockField::Payload as usize],
            result: fields[BlockField::Result as usize],
            certificate: fields[BlockField::Certificate as usize],
        })
    }

    /// The Iroha header, authenticated against the journal like `authenticate_canonical_block`.
    fn header(&mut self, layout: &BlockLayout) -> Result<BlockHeader, ReadError> {
        let [header] = self.fields::<{ PayloadField::Header as usize + 1 }>(layout.payload)?;
        let header: BlockHeader = self.decode(header)?;
        let actual = header.hash();
        if actual != self.expected {
            return Err(QueryExecutionFail::CanonicalHistory(
                CanonicalHistoryError::BlockHashMismatch {
                    height: self.height,
                    expected_hash: self.expected,
                    actual_hash: actual,
                },
            )
            .into());
        }
        if header.height().get() != self.height {
            return Err(QueryExecutionFail::CanonicalHistory(
                CanonicalHistoryError::BlockHeightMismatch {
                    height: self.height,
                    actual_height: header.height().get(),
                },
            )
            .into());
        }
        Ok(header)
    }

    /// The node-local commit certificate of a committed non-genesis block.
    fn certificate(&mut self, layout: &BlockLayout) -> Result<CommitCertificate, ReadError> {
        let certificate = self.option(layout.certificate)?.ok_or_else(|| {
            chain_error(&ChainReadError::MissingCertificate {
                height: self.height,
            })
        })?;
        self.decode(certificate)
    }

    /// Network input hashes from the execution context, checked against the Iroha header's
    /// `merkle_root` and the certified input commitment.
    fn input_hashes(
        &mut self,
        payload: &[Span],
        header: &BlockHeader,
        commitment: Option<MerkleTreeCommitment<TransactionEntrypoint>>,
    ) -> Result<Vec<HashOf<TransactionEntrypoint>>, ReadError> {
        let context = self.option(payload[PayloadField::ExecutionContext as usize])?;
        let hashes = match context {
            None => Vec::new(),
            Some(bundle) => {
                let [version, external] =
                    self.fields::<{ RecordField::Second as usize + 1 }>(bundle)?;
                let version: u8 = self.decode(version)?;
                if version != BlockExecutionContextBundle::VERSION {
                    return Err(invalid("execution context has an unsupported version"));
                }
                // Admit the input-row work before decoding or inspecting those rows.
                let (count, _) = self.sequence(external)?;
                self.work.rows(count, 0)?;
                let contexts: Vec<ExternalExecutionContext> = self.decode(external)?;
                contexts
                    .into_iter()
                    .map(|context| context.entrypoint_hash)
                    .collect()
            }
        };
        let root =
            MerkleTree::<TransactionEntrypoint>::root_from_typed_leaves(hashes.iter().copied());
        if root != header.merkle_root() {
            return Err(invalid(
                "execution context differs from the Network inputs committed by the header",
            ));
        }
        let count = u64::try_from(hashes.len()).map_err(|_| invalid("Network count overflows"))?;
        let certified =
            commitment.map(|commitment| (*commitment.root(), commitment.leaf_count().get()));
        if certified != root.map(|root| (root, count)) {
            return Err(invalid(
                "certified input commitment differs from the committed Network inputs",
            ));
        }
        Ok(hashes)
    }

    /// Indices of sealed reveals whose inner signed transaction has the alias `identity`.
    ///
    /// Every sealed reveal is hashed whole against its committed Network input hash in the
    /// same pass that hashes its alias, so an alias comes only from authenticated bytes.
    fn reveal_aliases(
        &mut self,
        entrypoints: Span,
        inputs: &[HashOf<TransactionEntrypoint>],
        identity: &HashOf<TransactionEntrypoint>,
        matches: &mut BTreeSet<u32>,
    ) -> Result<(), ReadError> {
        let (count, mut at) = self.sequence(entrypoints)?;
        if usize::try_from(count).ok() != Some(inputs.len()) {
            return Err(invalid(
                "Network input count differs from its execution context",
            ));
        }
        let tag_len = u64::try_from(size_of::<u32>()).unwrap_or(u64::MAX);
        for index in 0..count {
            let element = self.prefixed(at, entrypoints)?;
            at = element.end()?;
            let tag = self.read(element.within(element.offset, tag_len)?)?;
            let tag = tag.as_slice();
            if tag != EntrypointTag::SealedReveal.wire() {
                if tag != EntrypointTag::External.wire()
                    && tag != EntrypointTag::SealedCommitment.wire()
                    && tag != EntrypointTag::AnonymousBallot.wire()
                {
                    return Err(invalid("Network input has an unknown variant"));
                }
                continue;
            }
            let variant_start = element
                .offset
                .checked_add(tag_len)
                .ok_or_else(|| invalid("Network input overflows"))?;
            let reveal = self.prefixed(variant_start, element)?;
            if reveal.end()? != element.end()? {
                return Err(invalid("sealed reveal holds bytes after its value"));
            }
            let [_, signed] = self.fields::<{ RecordField::Second as usize + 1 }>(reveal)?;
            let [signature, payload] =
                self.fields::<{ RecordField::Second as usize + 1 }>(signed)?;
            // `[len][TransactionPayload]` exactly as `ExternalEntrypointRef` writes it.
            let framed_payload = signed.within(
                signature.end()?,
                payload
                    .end()?
                    .checked_sub(signature.end()?)
                    .unwrap_or_default(),
            )?;
            let (whole, alias) =
                self.hash_with_part(element, &EntrypointTag::External.wire(), framed_payload)?;
            let committed = usize::try_from(index)
                .ok()
                .and_then(|index| inputs.get(index));
            if committed != Some(&HashOf::from_untyped_unchecked(whole)) {
                return Err(invalid(
                    "sealed reveal differs from its committed Network input hash",
                ));
            }
            let alias = HashOf::<TransactionEntrypoint>::from_untyped_unchecked(alias);
            if &alias == identity {
                matches
                    .insert(u32::try_from(index).map_err(|_| invalid("Network index overflows"))?);
            }
        }
        if at != entrypoints.end()? {
            return Err(invalid(
                "Network input sequence holds bytes after its elements",
            ));
        }
        Ok(())
    }

    /// Results of the matched Network inputs, after streaming every output hash into the
    /// certified output commitment.
    fn matched_results(
        &mut self,
        layout: &BlockLayout,
        inputs: usize,
        matches: &BTreeSet<u32>,
        commitment: Option<MerkleTreeCommitment<ExecutionOutputV1>>,
    ) -> Result<Vec<Result<(), TransactionRejectionReason>>, ReadError> {
        let result = self
            .option(layout.result)?
            .ok_or_else(|| invalid("finalized carrier holds no execution outputs"))?;
        let [outputs] = self.fields::<{ RecordField::First as usize + 1 }>(result)?;
        let (count, first) = self.sequence(outputs)?;
        let inputs = u64::try_from(inputs).map_err(|_| invalid("Network count overflows"))?;
        self.work.rows(inputs, count)?;
        let mut results = Vec::new();
        let mut failure = None;
        let mut at = first;
        let mut index = 0_u64;
        let root = {
            let leaves = std::iter::from_fn(|| {
                if failure.is_some() || index == count {
                    return None;
                }
                match self.output_leaf(&mut at, outputs, index, matches, &mut results) {
                    Ok(leaf) => {
                        index += 1;
                        Some(leaf)
                    }
                    Err(error) => {
                        failure = Some(error);
                        None
                    }
                }
            });
            MerkleTree::<ExecutionOutputV1>::root_from_typed_leaves(leaves)
        };
        if let Some(error) = failure {
            return Err(error);
        }
        if at != outputs.end()? {
            return Err(invalid(
                "execution output sequence holds bytes after its elements",
            ));
        }
        let certified = commitment.map(|commitment| (*commitment.root(), commitment.leaf_count()));
        if certified.map(|(root, count)| (root, count.get())) != root.map(|root| (root, count)) {
            return Err(invalid(
                "execution outputs differ from the certified output commitment",
            ));
        }
        if u64::try_from(results.len()).ok() != u64::try_from(matches.len()).ok() {
            return Err(invalid("a matched Network input has no execution output"));
        }
        Ok(results)
    }

    // Hash one output element; decode it only when its index is matched.
    fn output_leaf(
        &mut self,
        at: &mut u64,
        outputs: Span,
        index: u64,
        matches: &BTreeSet<u32>,
        results: &mut Vec<Result<(), TransactionRejectionReason>>,
    ) -> Result<HashOf<ExecutionOutputV1>, ReadError> {
        let element = self.prefixed(*at, outputs)?;
        *at = element.end()?;
        let selected = u32::try_from(index)
            .ok()
            .is_some_and(|index| matches.contains(&index));
        if !selected {
            return Ok(HashOf::from_untyped_unchecked(self.hash(&[], element)?));
        }
        let output: ExecutionOutputV1 = self.decode(element)?;
        let leaf = HashOf::new(&output);
        if HashOf::from_untyped_unchecked(self.hash(&[], element)?) != leaf {
            return Err(invalid("matched execution output is not canonical"));
        }
        let ExecutionOutputV1::Network(row) = output else {
            return Err(invalid("matched Network input has no Network output"));
        };
        if u64::from(row.input_index) != index {
            return Err(invalid("matched Network output names another input"));
        }
        results.push(row.result.0.map(drop));
        Ok(leaf)
    }
}

fn missing(height: u64, expected: HashOf<BlockHeader>) -> ReadError {
    QueryExecutionFail::CanonicalHistory(CanonicalHistoryError::BodyUnavailable {
        height,
        expected_hash: expected,
    })
    .into()
}

// The storage classification of `block_with_original_admission`.
fn storage_error(
    height: u64,
    expected: HashOf<BlockHeader>,
    error: crate::kura::Error,
) -> ReadError {
    if matches!(&error, crate::kura::Error::NativeJournalUnavailable(_, _)) {
        return missing(height, expected);
    }
    crate::execution_attempt::kura_read_attempt_error(error, |error| {
        let reason = match error {
            crate::kura::Error::NoritoFrame(error) => error.to_string(),
            crate::kura::Error::CodecAttempt(error) => error.to_string(),
            error => error.to_string(),
        };
        QueryExecutionFail::Conversion(reason)
    })
    .into()
}

// The canonical core header of a non-genesis certificate, as `checked_frame_header` decodes it.
fn core_header(
    certificate: &CommitCertificate,
    height: u64,
) -> Result<(iroha_sumeragi::message::BlockHeader, Hash32), ReadError> {
    let header: iroha_sumeragi::message::BlockHeader =
        norito::core::classify_decode_attempt(|| {
            norito::decode_canonical(certificate.consensus_header())
        })
        .map_err(|error| {
            canonical_decode_attempt_error(error, |error| {
                QueryExecutionFail::Conversion(
                    ChainReadError::Malformed {
                        height,
                        reason: error.to_string(),
                    }
                    .to_string(),
                )
            })
        })?;
    if certificate.availability().is_empty() || header.height != height {
        return Err(chain_error(&ChainReadError::HeaderMismatch { height }));
    }
    let core_hash = header.hash(&crate::sumeragi::crypto::BlsCrypto::new());
    Ok((header, core_hash))
}

/// Authenticate one exact Network transaction outcome at `height` (see the module docs).
fn read_outcome(
    history: &CanonicalHistorySource<'_>,
    height: NonZeroUsize,
    identity: &HashOf<TransactionEntrypoint>,
    work: &mut SourceWork,
) -> Result<CommittedNetworkOutcome, ReadError> {
    let tip = history.walk_tip(height, height)?;
    let target = u64::try_from(height.get()).map_err(|_| QueryExecutionFail::GasBudgetExceeded)?;
    let start = history
        .checkpoint_start(target, tip.height())
        .unwrap_or_else(|| WalkStart::tip(tip));
    if start.height < target {
        return Err(invalid(
            "requested execution lies beyond the walk's starting height",
        ));
    }
    let scope = tip.root_scope();
    let checkpoints = history.kura.history_checkpoints();
    let mut expected_iroha = start.iroha;
    let mut expected_core = start.core;
    let mut expected_result = start.result;
    for source_height in (target..=start.height).rev() {
        let index = usize::try_from(source_height)
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or(QueryExecutionFail::GasBudgetExceeded)?;
        let journal_hash = history
            .expected_hash(index)
            .map_err(QueryExecutionFail::CanonicalHistory)?;
        if journal_hash != expected_iroha {
            return Err(invalid(format!(
                "native execution parent contradicts State hash at {source_height}"
            )));
        }
        work.block()?;
        // A checkpoint can omit newer ancestry, but it never replaces the target's
        // own frame or certificate. Preserve that distinction on the original refusal.
        let source_refusal = |error| match error {
            ReadError::Execution(ExecutionAttemptError::Deferred(original)) => {
                ReadError::Execution(ExecutionAttemptError::Deferred(
                    if source_height == target {
                        original.at_history_target()
                    } else {
                        original.at_history_ancestry()
                    },
                ))
            }
            rejected => rejected,
        };
        let mut frame = FrameWindows::open(history, index, source_height, journal_hash, work)
            .map_err(source_refusal)?;
        let layout = frame.layout().map_err(source_refusal)?;
        let header = frame.header(&layout).map_err(source_refusal)?;
        let certificate = frame.certificate(&layout).map_err(source_refusal)?;
        let (core, core_hash) = core_header(&certificate, source_height).map_err(source_refusal)?;
        let result = crate::sumeragi::commitment::result_of_preimage(certificate.result_preimage())
            .ok_or_else(|| {
                chain_error(&ChainReadError::ResultMismatch {
                    height: source_height,
                })
            })?;
        if core_hash != expected_core || result != expected_result {
            return Err(invalid(format!(
                "native header or R differs from authenticated execution ancestry at {source_height}"
            )));
        }
        checkpoints.record(
            source_height,
            HistoryCheckpoint {
                iroha_hash: journal_hash,
                core_hash: expected_core,
                result: expected_result,
            },
        );
        if source_height == target {
            let results =
                target_outcome(&mut frame, &layout, &header, &certificate, scope, identity)
                    .map_err(source_refusal)?;
            return Ok(CommittedNetworkOutcome { header, results });
        }
        expected_core = core.parent_hash;
        expected_result = core.parent_result;
        expected_iroha = header
            .prev_block_hash()
            .ok_or_else(|| invalid("native successor omits Iroha parent hash"))?;
    }
    Err(invalid(
        "requested execution lies beyond the original native tip",
    ))
}

// The outcome kernel at the authenticated target: certified result, inputs, aliases, outputs.
// Returns the results of the matched Network inputs, in input order.
fn target_outcome(
    frame: &mut FrameWindows<'_>,
    layout: &BlockLayout,
    header: &BlockHeader,
    certificate: &CommitCertificate,
    scope: iroha_data_model::block::consensus::SumeragiRootScope,
    identity: &HashOf<TransactionEntrypoint>,
) -> Result<Vec<Result<(), TransactionRejectionReason>>, ReadError> {
    let height = frame.height;
    let certified = CertifiedResultV1::decode_with_validation(
        certificate.result_preimage(),
        scope.into(),
        &mut EpochValidationScope::new(),
    )
    .map_err(|error| certified_result_error(height, error))?;
    let timestamp_ms = u64::try_from(header.creation_time().as_millis())
        .map_err(|_| invalid("block time exceeds u64 milliseconds"))?;
    certified
        .check_block(height, timestamp_ms)
        .map_err(|error| certified_result_error(height, error))?;
    let execution = &certified.commitment().execution;
    if certified.commitment().height != height {
        return Err(chain_error(&ChainReadError::ExecutionMismatch { height }));
    }
    execution.validate().map_err(|error| {
        chain_error(&ChainReadError::Malformed {
            height,
            reason: error.to_string(),
        })
    })?;
    // `read_outcome` bound this exact preimage to authenticated R and the State journal.
    // Counts in that validated commitment, unlike raw sequence prefixes, establish the
    // minimum target work even before its necessarily over-budget rows can be inspected.
    frame.work.certified_target_rows(
        execution
            .transaction_input_commitment
            .map_or(0, |value| value.leaf_count().get()),
        execution
            .transaction_output_commitment
            .map_or(0, |value| value.leaf_count().get()),
    )?;
    let payload =
        frame.exact_fields::<{ PayloadField::ExecutionContext as usize + 1 }>(layout.payload)?;
    let inputs = frame.input_hashes(&payload, header, execution.transaction_input_commitment)?;
    let mut matches = BTreeSet::new();
    for (index, hash) in inputs.iter().enumerate() {
        if hash == identity {
            matches.insert(u32::try_from(index).map_err(|_| invalid("Network index overflows"))?);
        }
    }
    frame.reveal_aliases(
        payload[PayloadField::ExternalEntrypoints as usize],
        &inputs,
        identity,
        &mut matches,
    )?;
    if matches.is_empty() {
        return Err(invalid(
            "committed Network identity has no authenticated outcome",
        ));
    }
    frame.matched_results(
        layout,
        inputs.len(),
        &matches,
        execution.transaction_output_commitment,
    )
}

impl crate::state::State {
    /// Authenticate the committed outcome of the exact Network transaction `identity` at
    /// `height` for an off-chain reader, reading only bounded windows of the block's frame.
    ///
    /// `identity` is a committed membership identity: a Network input hash or the signed alias
    /// of a sealed reveal. A successful read establishes at least one authenticated match;
    /// this reader cannot establish absence and refuses an unresolved identity. The capture
    /// and recheck of the State hash journal and native tip are those of
    /// [`Self::read_executed_carrier_from_checkpoints`]; the walk starts at a verified
    /// checkpoint at or above `height`, so its source work depends on node-local checkpoints and
    /// on-chain readers must not use it. `max_work` bounds walked frames plus the larger of
    /// the target's Network input count and all typed outputs (Network, Pipeline and Time),
    /// with at least one row. Authenticated target counts that cannot fit even one target
    /// frame are a permanent work refusal; cumulative ancestry work remains a query-budget
    /// rejection because closer checkpoints may shorten a retry. `max_bytes` bounds all
    /// window bytes. Genesis outcomes require
    /// their actual H2 successor and are read by the full-prefix reader instead.
    ///
    /// # Errors
    /// Rejects an unresolved identity, absent or replaced history, a substituted or malformed
    /// authenticated value, exceeded `max_work` or `max_bytes`, and genesis. A window or decoded
    /// piece the caller's read budget cannot hold is a local refusal that keeps its original
    /// allocation cause.
    pub fn read_committed_network_outcome(
        &self,
        height: NonZeroUsize,
        identity: &HashOf<TransactionEntrypoint>,
        max_work: u64,
        max_bytes: u64,
        read_budget: &CanonicalHistoryReadBudget,
    ) -> Result<CommittedNetworkOutcome, ReadError> {
        if max_work == 0 || max_bytes == 0 {
            return Err(QueryExecutionFail::GasBudgetExceeded.into());
        }
        if height == NonZeroUsize::MIN {
            return Err(invalid(
                "a genesis outcome requires its actual height-two successor",
            ));
        }
        let (hashes, tip) = loop {
            let before = self.state_view_generation();
            if !before.is_multiple_of(2) {
                std::thread::yield_now();
                continue;
            }
            let hashes = self.block_hashes.view();
            let tip = *self.native_execution_tip.view().get();
            if crate::state::is_stable_state_view_generation(before, self.state_view_generation()) {
                break (hashes, tip);
            }
            drop(hashes);
            std::thread::yield_now();
        };
        let expected = hashes.get(height.get() - 1).copied();
        let history =
            CanonicalHistorySource::new(&self.kura, &hashes, tip, read_budget.frames().clone());
        let mut work = SourceWork {
            blocks: 0,
            bytes: 0,
            max_blocks: max_work,
            max_bytes,
        };
        let outcome = read_budget.with(|| read_outcome(&history, height, identity, &mut work));
        // A permanent refusal describes this exact canonical target, just like a positive
        // outcome. Recheck its identity before exporting that classification; retain every
        // pre-existing execution refusal and its original owner unchanged.
        if matches!(
            &outcome,
            Ok(_) | Err(ReadError::TargetWorkBudgetExceeded { .. })
        ) && self.block_hashes.view().get(height.get() - 1).copied() != expected
        {
            return Err(QueryExecutionFail::Conversion(
                "canonical carrier changed during finalized read".into(),
            )
            .into());
        }
        outcome
    }
}

#[cfg(test)]
#[path = "committed_outcome_tests.rs"]
mod tests;
