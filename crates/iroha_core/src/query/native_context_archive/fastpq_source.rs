//! Original complete FASTPQ tape projection in Kura's bounded artifact outbox.
//!
//! The `.fqs` file is an untrusted transport, not a second authority journal. Its
//! absence leaves proof work unresolved. Readers join every field to the native
//! execution and its mandatory D7 write before issuing a fresh opaque source.

mod read;
pub(crate) use read::{
    AuthenticatedRecoveredFastpqSource, NativeFastpqSourceRead, SourceReadError, SourceReadLimits,
};

use super::*;
use crate::state::{AdmittedQuantityArchive, CapturedExecWitness};
use iroha_data_model::fastpq::{
    FastpqExecutionEffectsV1, FastpqOrdinarySourceStatementLeafV1,
    FastpqOrdinarySourceStatementManifestV1, FastpqSourceExecutionEntryV1,
};

/// Canonical untrusted file. This type deliberately has no source-authority API.
#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::fastpq::NativeFastpqSourceV1")]
#[norito(decode_fields)]
struct SourceRecord {
    height: u64,
    carrier: HashOf<BlockHeader>,
    manifest: FastpqOrdinarySourceStatementManifestV1,
    entries: Vec<FastpqSourceExecutionEntryV1>,
    leaves: Vec<FastpqOrdinarySourceStatementLeafV1>,
    tapes: Vec<FastpqExecutionEffectsV1>,
}

// Existing fields serialize through their canonical payload owner. No cloned
// tape/controller/quantity graph, replacement witness or extra schema is created.
struct Field<'a, T: ?Sized>(&'a T);
impl<T: norito::core::SerializePayload + ?Sized> norito::core::SerializePayload for Field<'_, T> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        self.0.serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.0.encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.encoded_len_exact()
    }
}
struct Sequence<'a, T>(&'a [T]);
impl<T: norito::core::SerializePayload> norito::core::SerializePayload for Sequence<'_, T> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::write_element_sequence::<T, _>(writer, self.0.iter())
    }
}
struct Tapes<'a> {
    original: &'a AdmittedQuantityArchive,
    count: usize,
}
struct TapeIterator<'a> {
    original: &'a AdmittedQuantityArchive,
    next: usize,
    end: usize,
}
impl<'a> Iterator for TapeIterator<'a> {
    type Item = Field<'a, FastpqExecutionEffectsV1>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.end {
            return None;
        }
        // The immutable archive has already verified every exact index. A
        // mismatch shortens the iterator, which the canonical writer rejects.
        let entry = self.original.entry(self.next).ok()?;
        self.next += 1;
        Some(Field(entry.effects()))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.end - self.next;
        (remaining, Some(remaining))
    }
}
impl ExactSizeIterator for TapeIterator<'_> {}
impl norito::core::SerializePayload for Tapes<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::write_element_sequence::<Field<'_, FastpqExecutionEffectsV1>, _>(
            writer,
            TapeIterator {
                original: self.original,
                next: 0,
                end: self.count,
            },
        )
    }
}
#[derive(norito::Encode)]
struct SourceRef<'a> {
    height: u64,
    carrier: HashOf<BlockHeader>,
    manifest: Field<'a, FastpqOrdinarySourceStatementManifestV1>,
    entries: Sequence<'a, FastpqSourceExecutionEntryV1>,
    leaves: Sequence<'a, FastpqOrdinarySourceStatementLeafV1>,
    tapes: Tapes<'a>,
}
impl norito::NoritoSchema for SourceRef<'_> {
    fn nominal_name() -> String {
        <SourceRecord as norito::NoritoSchema>::nominal_name()
    }
    fn static_frame_name() -> Option<&'static str> {
        <SourceRecord as norito::NoritoSchema>::static_frame_name()
    }
}
const _: () =
    assert!(std::mem::align_of::<SourceRef<'static>>() == std::mem::align_of::<SourceRecord>());

impl NativeContextArchive {
    /// Stream only actual captured tapes before retiring their original execution.
    /// A missing optional capture remains explicitly unresolved; it never marks a
    /// source statement complete or changes the certified coverage commitment.
    pub(crate) fn prepare_fastpq_source(
        &self,
        original: &mut PreparedNativeContext,
        executed: &SignedBlock,
        result: &RetainedPayload<CertifiedResultV1>,
        witness: &CapturedExecWitness,
    ) -> Result<(), NativeContextArchiveError> {
        self.recheck_namespace()?;
        if !self.writable
            || !original.bytes.belongs_to(&self.budget)
            || !result.belongs_to(&self.budget)
            || !witness.pool().same_pool(&self.budget)
            || original.height != executed.header().height().get()
            || original.carrier_hash != executed.hash()
            || !witness
                .matches_original_native_execution(executed, &result.get().commitment().execution)
        {
            return Err(NativeContextArchiveError::Source(
                "FASTPQ projection lost original source or pool",
            ));
        }
        if original.fastpq_capture_complete {
            return Ok(());
        }
        if witness.verify_source_binding().is_err() {
            return Err(NativeContextArchiveError::Source(
                "FASTPQ original capture binding differs",
            ));
        }
        let Ok(archive) = witness.admit_quantity_archive() else {
            // Capture is optional for native validity. The mandatory D7 write and
            // complete canonical input history remain durable recovery authority.
            // No `.fqs` file is a durable completion or negative fact.
            original.fastpq_capture_complete = true;
            return Ok(());
        };
        let projection = SourceRef {
            height: original.height,
            carrier: original.carrier_hash,
            manifest: Field(witness.manifest()),
            entries: Sequence(witness.source_entries()),
            leaves: Sequence(witness.leaves()),
            tapes: Tapes {
                original: &archive,
                count: witness.leaves().len(),
            },
        };
        let length = norito::canonical_frame_len(&projection)?;
        let maximum = self
            .fastpq_maximum
            .ok_or(NativeContextArchiveError::Source(
                "optional source capture has no original Kura policy",
            ))?
            .get();
        if length > maximum {
            // The full source remains committed by native D7. Optional transport
            // must not prevent native publication when its separate cap is smaller.
            original.fastpq_capture_complete = true;
            return Ok(());
        }
        let mut bytes = match ChargedBuffer::new(length, &self.budget) {
            Ok(bytes) => bytes,
            Err(
                ChargedBufferError::Admission(
                    iroha_allocation::AllocationRefusal::Capacity { .. }
                    | iroha_allocation::AllocationRefusal::ExceedsLimit { .. },
                )
                | ChargedBufferError::Allocator { .. },
            ) => {
                original.fastpq_capture_complete = true;
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        norito::core::write_canonical_to_writer(&projection, &mut BufferWriter(&mut bytes))?;
        if bytes.as_slice().len() != length {
            return Err(norito::Error::LengthMismatch.into());
        }
        original.fastpq_source = Some(bytes);
        original.fastpq_capture_complete = true;
        Ok(())
    }

    /// Select one exact original tape descriptor; absence remains a typed I/O
    /// refusal, never source completion or permission to advance a cursor.
    pub(crate) fn fastpq_source_read_job(
        self,
        height: u64,
        carrier: HashOf<BlockHeader>,
    ) -> NativeContextRead {
        NativeContextRead::new_named(self, RecordName::fastpq(height, carrier, false))
    }
}
