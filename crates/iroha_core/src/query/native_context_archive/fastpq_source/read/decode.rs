//! Original-pool, retained canonical source destination; no aggregate decode estimate.

use super::*;
use iroha_crypto::Hash;
use iroha_data_model::fastpq::{
    AllocatedFastpqEffectsV1, FastpqEffectsDecodeError, PendingFastpqEffectsDecodeV1,
    decode_fastpq_source_entry_payload_v1, decode_fastpq_source_leaf_payload_v1,
    decode_fastpq_source_manifest_payload_v1,
};
use ncore::{CanonicalField, DecodeField, DecodeIntoError, FieldDestination};

pub(super) struct FundedRecord {
    pub(super) height: u64,
    pub(super) carrier: HashOf<BlockHeader>,
    pub(super) manifest: FastpqOrdinarySourceStatementManifestV1,
    pub(super) entries: ChargedBuffer<FastpqSourceExecutionEntryV1>,
    pub(super) leaves: ChargedBuffer<FastpqOrdinarySourceStatementLeafV1>,
    pub(super) tapes: ChargedBuffer<AllocatedFastpqEffectsV1>,
}
impl FundedRecord {
    pub(super) fn belongs_to(&self, pool: &AllocationBudget) -> bool {
        self.entries.belongs_to(pool)
            && self.leaves.belongs_to(pool)
            && self.tapes.belongs_to(pool)
            && self
                .tapes
                .as_slice()
                .iter()
                .all(|tape| tape.belongs_to(pool))
    }
    pub(super) fn allocation_bytes(&self) -> Option<usize> {
        let arrays =
            std::alloc::Layout::array::<FastpqSourceExecutionEntryV1>(self.entries.capacity())
                .ok()?
                .size()
                .checked_add(
                    std::alloc::Layout::array::<FastpqOrdinarySourceStatementLeafV1>(
                        self.leaves.capacity(),
                    )
                    .ok()?
                    .size(),
                )?
                .checked_add(
                    std::alloc::Layout::array::<AllocatedFastpqEffectsV1>(self.tapes.capacity())
                        .ok()?
                        .size(),
                )?;
        self.tapes
            .as_slice()
            .iter()
            .try_fold(arrays, |n, tape| n.checked_add(tape.allocation_bytes()?))
    }
}

pub(super) struct SourceDestination {
    pool: AllocationBudget,
    limits: SourceReadLimits,
    height: Option<u64>,
    carrier: Option<HashOf<BlockHeader>>,
    manifest: Option<FastpqOrdinarySourceStatementManifestV1>,
    entry_spans: ncore::RetainedElementSequence,
    leaf_spans: ncore::RetainedElementSequence,
    tape_spans: ncore::RetainedElementSequence,
    entries: Option<ChargedBuffer<FastpqSourceExecutionEntryV1>>,
    leaves: Option<ChargedBuffer<FastpqOrdinarySourceStatementLeafV1>>,
    pending: Option<ChargedBuffer<PendingFastpqEffectsDecodeV1>>,
    tapes: Option<ChargedBuffer<AllocatedFastpqEffectsV1>>,
    source: Option<(usize, usize, Hash)>,
    valid: bool,
}
impl SourceDestination {
    pub(super) fn new(pool: &AllocationBudget, limits: SourceReadLimits) -> Self {
        Self {
            pool: pool.clone(),
            limits,
            height: None,
            carrier: None,
            manifest: None,
            entry_spans: ncore::RetainedElementSequence::new(pool),
            leaf_spans: ncore::RetainedElementSequence::new(pool),
            tape_spans: ncore::RetainedElementSequence::new(pool),
            entries: None,
            leaves: None,
            pending: None,
            tapes: None,
            source: None,
            valid: false,
        }
    }
    pub(super) fn decode(
        &mut self,
        bytes: &ChargedBuffer<u8>,
        workspace: &mut PreparedDecodeWorkspace,
    ) -> Result<(), SourceReadError> {
        if !bytes.belongs_to(&self.pool) {
            return Err(SourceReadError::Source("foreign tape byte pool"));
        }
        let identity = (
            bytes.as_slice().as_ptr() as usize,
            bytes.as_slice().len(),
            Hash::new(bytes.as_slice()),
        );
        if self.source.is_some_and(|source| source != identity) {
            return Err(SourceReadError::Source(
                "original source record bytes changed",
            ));
        }
        self.source = Some(identity);
        workspace
            .decode_canonical_into::<SourceRecord, _>(
                bytes.as_slice(),
                norito::canonical_decode_limits(bytes.as_slice().len()),
                self,
            )
            .map_err(prepared_error)
    }
    /// Move only an already complete graph. All backing for the final tape owners
    /// was admitted before decoding; this transition performs no allocation.
    pub(super) fn take_complete(&mut self) -> Result<FundedRecord, SourceReadError> {
        let incomplete = || SourceReadError::Source("incomplete retained source destination");
        if !self.valid {
            return Err(incomplete());
        }
        let height = self.height.ok_or_else(incomplete)?;
        let carrier = self.carrier.ok_or_else(incomplete)?;
        let manifest = self.manifest.ok_or_else(incomplete)?;
        let pending = self.pending.as_mut().ok_or_else(incomplete)?;
        let tapes = self.tapes.as_mut().ok_or_else(incomplete)?;
        let count = pending.capacity();
        if self.entries.is_none()
            || self.leaves.is_none()
            || tapes.capacity() != count
            || pending.as_slice().len().checked_add(tapes.as_slice().len()) != Some(count)
            || !pending
                .as_slice()
                .iter()
                .all(PendingFastpqEffectsDecodeV1::is_complete)
        {
            return Err(incomplete());
        }
        // Pop in reverse order so an unexpected unfinished owner can be restored
        // without dropping any other pending source or completed physical graph.
        while let Some(original) = pending.pop() {
            match original.finish() {
                Ok(tape) => tapes.push_reserved(tape),
                Err(original) => {
                    pending.push_reserved(original);
                    return Err(incomplete());
                }
            }
        }
        tapes.as_mut_slice().reverse();
        self.valid = false;
        Ok(FundedRecord {
            height,
            carrier,
            manifest,
            entries: self.entries.take().ok_or_else(incomplete)?,
            leaves: self.leaves.take().ok_or_else(incomplete)?,
            tapes: self.tapes.take().ok_or_else(incomplete)?,
        })
    }
}

fn destination(error: SourceReadError) -> DecodeIntoError<SourceReadError> {
    match error {
        SourceReadError::Codec(error) => DecodeIntoError::Codec(error),
        SourceReadError::Effects(FastpqEffectsDecodeError::Codec(error)) => {
            DecodeIntoError::Codec(error)
        }
        error => DecodeIntoError::Destination(error),
    }
}
fn sequence_error(error: ncore::RetainedSequenceError) -> SourceReadError {
    match error {
        ncore::RetainedSequenceError::Admission(ncore::SequenceAdmissionError::Codec(error)) => {
            SourceReadError::Codec(error)
        }
        ncore::RetainedSequenceError::Admission(ncore::SequenceAdmissionError::Allocation(
            error,
        )) => SourceReadError::Buffer(error),
        ncore::RetainedSequenceError::SourceMismatch => {
            SourceReadError::Source("original source sequence changed")
        }
        ncore::RetainedSequenceError::Incomplete => {
            SourceReadError::Source("unfinished original source sequence")
        }
    }
}
pub(super) fn prepared_error(
    error: ncore::PreparedDecodeError<SourceReadError>,
) -> SourceReadError {
    match error {
        ncore::PreparedDecodeError::Codec(error) => SourceReadError::Decode(error),
        ncore::PreparedDecodeError::Destination(error) => error,
        ncore::PreparedDecodeError::Scope(error) => SourceReadError::Workspace(error),
    }
}
impl FieldDestination for SourceDestination {
    type Error = SourceReadError;
}
macro_rules! scalar {
    ($index:literal, $name:ident, $type:ty) => {
        impl DecodeField<$index, $type> for SourceDestination {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, $type>,
            ) -> Result<(), DecodeIntoError<SourceReadError>> {
                self.$name = Some(field.with_payload(|bytes| {
                    let (value, used) =
                        <$type as ncore::DecodeFromSlice<'_>>::decode_from_slice(bytes)?;
                    if used != bytes.len() {
                        return Err(norito::Error::LengthMismatch.into());
                    }
                    ncore::finish_context_fields(bytes.as_ptr(), used)?;
                    Ok(value)
                })?);
                Ok(())
            }
        }
    };
}
scalar!(0, height, u64);
scalar!(1, carrier, HashOf<BlockHeader>);
impl DecodeField<2, FastpqOrdinarySourceStatementManifestV1> for SourceDestination {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, FastpqOrdinarySourceStatementManifestV1>,
    ) -> Result<(), DecodeIntoError<SourceReadError>> {
        self.manifest = Some(field.with_payload(|bytes| {
            decode_fastpq_source_manifest_payload_v1(bytes).map_err(|e| destination(e.into()))
        })?);
        Ok(())
    }
}

// The fixed element DTOs contain no nested heap allocations. Each real Vec and
// retained canonical span table is prepaid separately in the original pool.
macro_rules! fixed_sequence {
    ($index:literal, $member:ident, $spans:ident, $limit:ident, $type:ty, $decode:path) => {
        impl DecodeField<$index, Vec<$type>> for SourceDestination {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, Vec<$type>>,
            ) -> Result<(), DecodeIntoError<SourceReadError>> {
                field.with_payload(|bytes| {
                    let (count, _) = ncore::inspect_seq_len_slice(bytes)?;
                    if count > self.limits.$limit as usize {
                        return Err(destination(SourceReadError::Limit {
                            kind: stringify!($member),
                            actual: count,
                            maximum: self.limits.$limit as usize,
                        }));
                    }
                    self.$spans
                        .prepare(bytes)
                        .map_err(|e| destination(sequence_error(e)))?;
                    let prepared = self
                        .$spans
                        .as_prepared(bytes)
                        .map_err(|e| destination(sequence_error(e)))?;
                    if prepared.used() != bytes.len() || prepared.len() != count {
                        return Err(norito::Error::LengthMismatch.into());
                    }
                    if self.$member.is_none() {
                        self.$member = Some(
                            ChargedBuffer::new(count, &self.pool)
                                .map_err(|e| destination(e.into()))?,
                        );
                    }
                    let values = self.$member.as_mut().ok_or_else(|| {
                        destination(SourceReadError::Source("missing fixed source backing"))
                    })?;
                    if values.capacity() != count {
                        return Err(destination(SourceReadError::Source(
                            "fixed source capacity changed",
                        )));
                    }
                    prepared.decode_elements::<$type, SourceReadError>(|index, field| {
                        let value = field.with_payload(|bytes| {
                            $decode(bytes).map_err(|e| destination(e.into()))
                        })?;
                        if let Some(cached) = values.as_slice().get(index) {
                            if cached != &value {
                                return Err(destination(SourceReadError::Source(
                                    "original fixed source entry changed",
                                )));
                            }
                        } else if index == values.as_slice().len() {
                            values.push_reserved(value);
                        } else {
                            return Err(destination(SourceReadError::Source(
                                "fixed source skipped original index",
                            )));
                        }
                        Ok(())
                    })
                })
            }
        }
    };
}
fixed_sequence!(
    3,
    entries,
    entry_spans,
    max_entries,
    FastpqSourceExecutionEntryV1,
    decode_fastpq_source_entry_payload_v1
);
fixed_sequence!(
    4,
    leaves,
    leaf_spans,
    max_statements,
    FastpqOrdinarySourceStatementLeafV1,
    decode_fastpq_source_leaf_payload_v1
);
impl DecodeField<5, Vec<FastpqExecutionEffectsV1>> for SourceDestination {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, Vec<FastpqExecutionEffectsV1>>,
    ) -> Result<(), DecodeIntoError<SourceReadError>> {
        field.with_payload(|bytes| {
            let (count, _) = ncore::inspect_seq_len_slice(bytes)?;
            if count > self.limits.max_statements as usize {
                return Err(destination(SourceReadError::Limit {
                    kind: "tapes",
                    actual: count,
                    maximum: self.limits.max_statements as usize,
                }));
            }
            self.tape_spans
                .prepare(bytes)
                .map_err(|e| destination(sequence_error(e)))?;
            let prepared = self
                .tape_spans
                .as_prepared(bytes)
                .map_err(|e| destination(sequence_error(e)))?;
            if prepared.used() != bytes.len() || prepared.len() != count {
                return Err(norito::Error::LengthMismatch.into());
            }
            if self.pending.is_none() {
                self.pending =
                    Some(ChargedBuffer::new(count, &self.pool).map_err(|e| destination(e.into()))?);
            }
            if self.tapes.is_none() {
                self.tapes =
                    Some(ChargedBuffer::new(count, &self.pool).map_err(|e| destination(e.into()))?);
            }
            let pending = self.pending.as_mut().ok_or_else(|| {
                destination(SourceReadError::Source("missing tape destination backing"))
            })?;
            if pending.capacity() != count {
                return Err(destination(SourceReadError::Source(
                    "tape destination capacity changed",
                )));
            }
            prepared.decode_elements::<FastpqExecutionEffectsV1, SourceReadError>(
                |index, field| {
                    if index == pending.as_slice().len() {
                        pending.push_reserved(PendingFastpqEffectsDecodeV1::new(
                            &self.pool,
                            self.limits.max_effects_per_statement,
                        ));
                    }
                    let original = pending.as_mut_slice().get_mut(index).ok_or_else(|| {
                        destination(SourceReadError::Source(
                            "tape sequence skipped original index",
                        ))
                    })?;
                    field.with_payload(|bytes| {
                        original
                            .decode_payload(bytes)
                            .map_err(|e| destination(e.into()))
                    })
                },
            )?;
            self.valid = true;
            Ok(())
        })
    }
}

#[derive(norito::Encode)]
struct PendingRef<'a> {
    height: u64,
    carrier: HashOf<BlockHeader>,
    manifest: Field<'a, FastpqOrdinarySourceStatementManifestV1>,
    entries: Sequence<'a, FastpqSourceExecutionEntryV1>,
    leaves: Sequence<'a, FastpqOrdinarySourceStatementLeafV1>,
    tapes: Sequence<'a, PendingFastpqEffectsDecodeV1>,
}
impl norito::SerializePayload for SourceDestination {
    fn serialize(&self, writer: &mut ncore::Encoder<'_>) -> Result<(), norito::Error> {
        if !self.valid {
            return Err(norito::Error::LengthMismatch);
        }
        let value = PendingRef {
            height: self.height.ok_or(norito::Error::LengthMismatch)?,
            carrier: self.carrier.ok_or(norito::Error::LengthMismatch)?,
            manifest: Field(
                self.manifest
                    .as_ref()
                    .ok_or(norito::Error::LengthMismatch)?,
            ),
            entries: Sequence(
                self.entries
                    .as_ref()
                    .ok_or(norito::Error::LengthMismatch)?
                    .as_slice(),
            ),
            leaves: Sequence(
                self.leaves
                    .as_ref()
                    .ok_or(norito::Error::LengthMismatch)?
                    .as_slice(),
            ),
            tapes: Sequence(
                self.pending
                    .as_ref()
                    .ok_or(norito::Error::LengthMismatch)?
                    .as_slice(),
            ),
        };
        norito::SerializePayload::serialize(&value, writer)
    }
}
impl ncore::PreparedRecordDestination<SourceRecord> for SourceDestination {
    fn reset(&mut self) {
        self.valid = false;
    }
}
