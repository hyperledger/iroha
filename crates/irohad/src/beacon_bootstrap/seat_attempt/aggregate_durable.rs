//! Original aggregate intent, ciphertext and final head with exact held file owners.
//!
//! The fixed records are decoded into their prepaid scalar owners. Raw files
//! select only bounded source preparation; Core authentication and actual native
//! ancestry must precede private restore, export adoption or claim authentication.
//! TODO: independently authenticated rollback-resistant head storage remains a
//! qualification boundary; local owner-private files cannot detect suffix deletion.

use super::durable::{Bytes, Loaded, open_original_file, read_file};
use super::*;
use iroha_crypto::threshold_bls::aggregate_checkpoint::DkgAggregateCheckpointBindingV1;
use norito::core::{
    CanonicalField, DecodeField, DecodeFromSlice, DecodeIntoError, DecodeRecordFields, Encoder,
    FieldDestination, PreparedDecodeWorkspace, PreparedRecordDestination, SerializePayload,
};
use norito::{NoritoDeserialize, NoritoSchema, NoritoSerialize};
use std::{alloc::Layout, convert::Infallible};

const INTENT: &str = "producer-extraction-intent.norito";
const CHECKPOINT: &str = "private-aggregate-checkpoint.norito";
const HEAD: &str = "aggregate-head.norito";
const SOURCE_FILES: [(&str, bool); 9] = [
    (CHECKPOINT, true),
    ("input-final-session.norito", true),
    ("proof-final-session.norito", true),
    ("phase-head-3.norito", true),
    ("private-checkpoint-3.norito", true),
    ("session-input-consumption.norito", true),
    ("proof-deliveries.norito", true),
    ("producer-3-intent.norito", true),
    ("acceptances.norito", false),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito(decode_fields)]
#[norito_schema(name = "irohad::beacon_bootstrap::seat_attempt::AggregateProducerIntentV1")]
pub(super) struct AggregateIntent {
    version: u16,
    binding: DkgAggregateCheckpointBindingV1,
    pub(super) expiry: DurableDeadline,
    pub(super) claim_identity: [u64; 4],
    pub(super) claim_path_hash: [u8; 32],
    pub(super) fifo_identity: [u64; 4],
    source_hashes: [[u8; 32]; 2],
    pub(super) stream_generations: [u64; 2],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito(decode_fields)]
#[norito_schema(name = "irohad::beacon_bootstrap::seat_attempt::AggregateDurableHeadV1")]
pub(super) struct AggregateHead {
    version: u16,
    pub(super) binding: DkgAggregateCheckpointBindingV1,
    checkpoint_hash: [u8; 32],
}
fn empty_binding() -> DkgAggregateCheckpointBindingV1 {
    DkgAggregateCheckpointBindingV1 {
        network_id: [0; 32],
        attempt_id: [0; 32],
        authority_generation: 0,
        session_id: [0; 32],
        roster_hash: [0; 32],
        seat_index: 0,
        lifecycle_key_hash: [0; 32],
        provider_handle_hash: [0; 32],
        provider_revision: 0,
        start_height: 0,
        commitments_end_height: 0,
        deliveries_end_height: 0,
        acceptances_end_height: 0,
        finalized_at_height: 0,
        source: durable::empty_context().source,
        cutoff_height: 0,
        public_session_hash: [0; 32],
        transcript_hash: [0; 32],
        accepted_checkpoint_hash: [0; 32],
        accepted_head_hash: [0; 32],
        extraction_intent_hash: [0; 32],
    }
}
impl AggregateIntent {
    fn empty(expiry: DurableDeadline) -> Self {
        Self {
            version: 0,
            binding: empty_binding(),
            expiry,
            claim_identity: [0; 4],
            claim_path_hash: [0; 32],
            fifo_identity: [0; 4],
            source_hashes: [[0; 32]; 2],
            stream_generations: [0; 2],
        }
    }
}
impl AggregateHead {
    fn empty() -> Self {
        Self {
            version: 0,
            binding: empty_binding(),
            checkpoint_hash: [0; 32],
        }
    }
}
struct Destination {
    intent: ChargedBuffer<AggregateIntent>,
    head: ChargedBuffer<AggregateHead>,
}
struct View<'a, T> {
    owner: &'a mut Destination,
    expiry: DurableDeadline,
    marker: std::marker::PhantomData<T>,
}
impl<T> FieldDestination for View<'_, T> {
    type Error = Infallible;
}
struct Inline<'a, T>(&'a mut T);
impl<T> FieldDestination for Inline<'_, T> {
    type Error = Infallible;
}
macro_rules! fixed_field {
    ($record:ty,$owner:ident,$index:literal,[u8; $length:expr],$name:ident) => {
        impl DecodeField<$index, [u8; $length]> for View<'_, $record> {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, [u8; $length]>,
            ) -> std::result::Result<(), DecodeIntoError<Infallible>> {
                self.owner.$owner.as_mut_slice()[0].$name =
                    field.decode_owned().map_err(DecodeIntoError::Codec)?;
                Ok(())
            }
        }
    };
    ($record:ty,$owner:ident,$index:literal,$ty:ty,$name:ident) => {
        impl DecodeField<$index, $ty> for View<'_, $record> {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, $ty>,
            ) -> std::result::Result<(), DecodeIntoError<Infallible>> {
                self.owner.$owner.as_mut_slice()[0].$name = field.with_payload(|bytes| {
                    let (value, used) = <$ty as DecodeFromSlice>::decode_from_slice(bytes)?;
                    if used != bytes.len() {
                        return Err(norito::Error::LengthMismatch.into());
                    }
                    Ok(value)
                })?;
                Ok(())
            }
        }
    };
}
macro_rules! inline_field {
    ($record:ty,$index:literal,[u8; $length:expr],$name:ident) => {
        impl DecodeField<$index, [u8; $length]> for Inline<'_, $record> {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, [u8; $length]>,
            ) -> std::result::Result<(), DecodeIntoError<Infallible>> {
                self.0.$name = field.decode_owned().map_err(DecodeIntoError::Codec)?;
                Ok(())
            }
        }
    };
    ($record:ty,$index:literal,$ty:ty,$name:ident) => {
        impl DecodeField<$index, $ty> for Inline<'_, $record> {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, $ty>,
            ) -> std::result::Result<(), DecodeIntoError<Infallible>> {
                self.0.$name = field.with_payload(|bytes| {
                    let (value, used) = <$ty as DecodeFromSlice>::decode_from_slice(bytes)?;
                    if used != bytes.len() {
                        return Err(norito::Error::LengthMismatch.into());
                    }
                    Ok(value)
                })?;
                Ok(())
            }
        }
    };
}
macro_rules! nested_field {
    ($record:ty,$owner:ident,$index:literal,$ty:ty,$name:ident) => {
        impl DecodeField<$index, $ty> for View<'_, $record> {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, $ty>,
            ) -> std::result::Result<(), DecodeIntoError<Infallible>> {
                field.with_payload(|bytes| {
                    let (_, used) = <$ty as DecodeRecordFields<_>>::decode_fields(
                        bytes,
                        &mut Inline(&mut self.owner.$owner.as_mut_slice()[0].$name),
                    )?;
                    if used != bytes.len() {
                        return Err(norito::Error::LengthMismatch.into());
                    }
                    Ok(())
                })
            }
        }
    };
}
inline_field!(DkgAggregateCheckpointBindingV1, 0, [u8; 32], network_id);
inline_field!(DkgAggregateCheckpointBindingV1, 1, [u8; 32], attempt_id);
inline_field!(
    DkgAggregateCheckpointBindingV1,
    2,
    u64,
    authority_generation
);
inline_field!(DkgAggregateCheckpointBindingV1, 3, [u8; 32], session_id);
inline_field!(DkgAggregateCheckpointBindingV1, 4, [u8; 32], roster_hash);
inline_field!(DkgAggregateCheckpointBindingV1, 5, u16, seat_index);
inline_field!(
    DkgAggregateCheckpointBindingV1,
    6,
    [u8; 32],
    lifecycle_key_hash
);
inline_field!(
    DkgAggregateCheckpointBindingV1,
    7,
    [u8; 32],
    provider_handle_hash
);
inline_field!(DkgAggregateCheckpointBindingV1, 8, u64, provider_revision);
inline_field!(DkgAggregateCheckpointBindingV1, 9, u64, start_height);
inline_field!(
    DkgAggregateCheckpointBindingV1,
    10,
    u64,
    commitments_end_height
);
inline_field!(
    DkgAggregateCheckpointBindingV1,
    11,
    u64,
    deliveries_end_height
);
inline_field!(
    DkgAggregateCheckpointBindingV1,
    12,
    u64,
    acceptances_end_height
);
inline_field!(
    DkgAggregateCheckpointBindingV1,
    13,
    u64,
    finalized_at_height
);
impl DecodeField<14, iroha_crypto::threshold_bls::checkpoint::DkgCheckpointSourceV1>
    for Inline<'_, DkgAggregateCheckpointBindingV1>
{
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, iroha_crypto::threshold_bls::checkpoint::DkgCheckpointSourceV1>,
    ) -> std::result::Result<(), DecodeIntoError<Infallible>> {
        self.0.source = field.with_payload(|bytes| {
            let (value, used) =
                iroha_crypto::threshold_bls::checkpoint::DkgCheckpointSourceV1::decode_fields(
                    bytes,
                    &mut durable::SourceFields,
                )?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            Ok(value)
        })?;
        Ok(())
    }
}
inline_field!(DkgAggregateCheckpointBindingV1, 15, u64, cutoff_height);
inline_field!(
    DkgAggregateCheckpointBindingV1,
    16,
    [u8; 32],
    public_session_hash
);
inline_field!(
    DkgAggregateCheckpointBindingV1,
    17,
    [u8; 32],
    transcript_hash
);
inline_field!(
    DkgAggregateCheckpointBindingV1,
    18,
    [u8; 32],
    accepted_checkpoint_hash
);
inline_field!(
    DkgAggregateCheckpointBindingV1,
    19,
    [u8; 32],
    accepted_head_hash
);
inline_field!(
    DkgAggregateCheckpointBindingV1,
    20,
    [u8; 32],
    extraction_intent_hash
);
inline_field!(DurableDeadline, 0, [u8; 32], boot);
inline_field!(DurableDeadline, 1, u128, origin_nanos);
inline_field!(DurableDeadline, 2, u128, expiry_nanos);
fixed_field!(AggregateIntent, intent, 0, u16, version);
nested_field!(
    AggregateIntent,
    intent,
    1,
    DkgAggregateCheckpointBindingV1,
    binding
);
nested_field!(AggregateIntent, intent, 2, DurableDeadline, expiry);
fixed_field!(AggregateIntent, intent, 3, [u64; 4], claim_identity);
fixed_field!(AggregateIntent, intent, 4, [u8; 32], claim_path_hash);
fixed_field!(AggregateIntent, intent, 5, [u64; 4], fifo_identity);
fixed_field!(AggregateIntent, intent, 6, [[u8; 32]; 2], source_hashes);
fixed_field!(AggregateIntent, intent, 7, [u64; 2], stream_generations);
fixed_field!(AggregateHead, head, 0, u16, version);
nested_field!(
    AggregateHead,
    head,
    1,
    DkgAggregateCheckpointBindingV1,
    binding
);
fixed_field!(AggregateHead, head, 2, [u8; 32], checkpoint_hash);
impl SerializePayload for View<'_, AggregateIntent> {
    fn serialize(&self, e: &mut Encoder<'_>) -> std::result::Result<(), norito::Error> {
        self.owner.intent.as_slice()[0].serialize(e)
    }
}
impl SerializePayload for View<'_, AggregateHead> {
    fn serialize(&self, e: &mut Encoder<'_>) -> std::result::Result<(), norito::Error> {
        self.owner.head.as_slice()[0].serialize(e)
    }
}
impl PreparedRecordDestination<AggregateIntent> for View<'_, AggregateIntent> {
    fn reset(&mut self) {
        self.owner.intent.as_mut_slice()[0] = AggregateIntent::empty(self.expiry);
    }
}
impl PreparedRecordDestination<AggregateHead> for View<'_, AggregateHead> {
    fn reset(&mut self) {
        self.owner.head.as_mut_slice()[0] = AggregateHead::empty();
    }
}

/// Fixed publication controls belong to the original attempt before claim or RNG.
/// Reload raw extents are independent original-source banks admitted as a set.
pub(super) struct PreparedAggregateDurable {
    expiry: DurableDeadline,
    intent: ChargedBuffer<u8>,
    head: ChargedBuffer<u8>,
    read_intent: ChargedBuffer<u8>,
    read_head: ChargedBuffer<u8>,
    intent_record: Option<AggregateIntent>,
    head_record: Option<AggregateHead>,
    intent_progress: seat_export::FileProgress,
    checkpoint_progress: seat_export::FileProgress,
    head_progress: seat_export::FileProgress,
    checkpoint_source: Option<(usize, usize, [u8; 32])>,
    terminal: bool,
    directory_synced: bool,
    loaded: [Loaded; 11],
    sources: [Option<ChargedBuffer<u8>>; 9],
    destination: Destination,
    workspace: PreparedDecodeWorkspace,
    budget: AllocationBudget,
}
impl PreparedAggregateDurable {
    pub(super) fn new(
        expiry: DurableDeadline,
        budget: &AllocationBudget,
    ) -> std::result::Result<Self, AttemptError> {
        let intent_len = norito::canonical_frame_len(&AggregateIntent::empty(expiry))
            .map_err(seat_export::ExportError::from)?;
        let head_len = norito::canonical_frame_len(&AggregateHead::empty())
            .map_err(seat_export::ExportError::from)?;
        let controls = PreparedDecodeWorkspace::allocation_layouts();
        let layouts = [
            Layout::array::<u8>(intent_len).map_err(|_| AllocationRefusal::DemandOverflow)?,
            Layout::array::<u8>(head_len).map_err(|_| AllocationRefusal::DemandOverflow)?,
            Layout::array::<u8>(intent_len).map_err(|_| AllocationRefusal::DemandOverflow)?,
            Layout::array::<u8>(head_len).map_err(|_| AllocationRefusal::DemandOverflow)?,
            Layout::new::<AggregateIntent>(),
            Layout::new::<AggregateHead>(),
            controls[0],
            controls[1],
        ];
        let mut reservation = budget.try_reserve_layouts(layouts)?;
        let intent = ChargedBuffer::from_reservation(intent_len, &mut reservation)?;
        let head = ChargedBuffer::from_reservation(head_len, &mut reservation)?;
        let read_intent = ChargedBuffer::from_reservation(intent_len, &mut reservation)?;
        let read_head = ChargedBuffer::from_reservation(head_len, &mut reservation)?;
        let mut intent_slot = ChargedBuffer::from_reservation(1, &mut reservation)?;
        intent_slot.push_reserved(AggregateIntent::empty(expiry));
        let mut head_slot = ChargedBuffer::from_reservation(1, &mut reservation)?;
        head_slot.push_reserved(AggregateHead::empty());
        let workspace = PreparedDecodeWorkspace::from_reservation(budget, &mut reservation)
            .map_err(AttemptError::DurableScope)?;
        if reservation.remaining_bytes() != 0 {
            return Err(AttemptError::Phase);
        }
        Ok(Self {
            expiry,
            intent,
            head,
            read_intent,
            read_head,
            intent_record: None,
            head_record: None,
            intent_progress: Default::default(),
            checkpoint_progress: Default::default(),
            head_progress: Default::default(),
            checkpoint_source: None,
            terminal: false,
            directory_synced: false,
            loaded: std::array::from_fn(|_| Default::default()),
            sources: std::array::from_fn(|_| None),
            destination: Destination {
                intent: intent_slot,
                head: head_slot,
            },
            workspace,
            budget: budget.clone(),
        })
    }
    pub(super) fn tightened_deadline(
        &self,
        deadline: Instant,
    ) -> std::result::Result<Instant, AttemptError> {
        self.intent_record
            .map_or(self.expiry, |intent| intent.expiry)
            .restore(deadline)
    }
    pub(super) fn prepare_intent(
        &mut self,
        binding: &DkgAggregateCheckpointBindingV1,
        claim_identity: [u64; 4],
        claim_path_hash: [u8; 32],
        fifo_identity: [u64; 4],
        source_hashes: [[u8; 32]; 2],
        stream_generations: [u64; 2],
    ) -> std::result::Result<(), AttemptError> {
        if binding.extraction_intent_hash != [0; 32]
            || binding.accepted_head_hash == [0; 32]
            || binding.accepted_checkpoint_hash == [0; 32]
            || source_hashes.iter().any(|hash| *hash == [0; 32])
            || stream_generations[0] != 2
        {
            return Err(AttemptError::Binding);
        }
        let record = AggregateIntent {
            version: 1,
            binding: *binding,
            expiry: self.expiry,
            claim_identity,
            claim_path_hash,
            fifo_identity,
            source_hashes,
            stream_generations,
        };
        if self.intent_record.is_some() {
            return if self.intent_record == Some(record) {
                Ok(())
            } else {
                Err(AttemptError::Binding)
            };
        }
        if !self.intent.as_slice().is_empty() {
            return Err(AttemptError::Phase);
        }
        norito::core::write_canonical_to_writer(&record, &mut Bytes(&mut self.intent))
            .map_err(seat_export::ExportError::from)?;
        self.intent_record = Some(record);
        Ok(())
    }
    pub(super) fn intent_hash(&self) -> std::result::Result<[u8; 32], AttemptError> {
        if self.intent_record.is_none() {
            return Err(AttemptError::Phase);
        }
        let bytes = if self.intent.as_slice().is_empty() {
            self.read_intent.as_slice()
        } else {
            self.intent.as_slice()
        };
        if bytes.is_empty() {
            return Err(AttemptError::Phase);
        }
        Ok(Hash::new(bytes).into())
    }
    pub(super) fn publish_intent(
        &mut self,
        directory: &Directory,
    ) -> std::result::Result<(), AttemptError> {
        if self.intent_record.is_none() {
            return Err(AttemptError::Phase);
        }
        seat_export::publish_file(
            directory,
            INTENT,
            true,
            self.intent.as_slice(),
            &mut self.intent_progress,
        )?;
        Ok(())
    }
    pub(super) fn publish_checkpoint(
        &mut self,
        directory: &Directory,
        binding: &DkgAggregateCheckpointBindingV1,
        encrypted: &[u8],
    ) -> std::result::Result<(), AttemptError> {
        let mut original = *binding;
        original.extraction_intent_hash = [0; 32];
        if self.terminal
            || !self.intent_progress.complete()
            || encrypted.is_empty()
            || self
                .intent_record
                .is_none_or(|intent| intent.binding != original)
            || binding.extraction_intent_hash != self.intent_hash()?
        {
            return Err(AttemptError::Binding);
        }
        let source = (
            encrypted.as_ptr().addr(),
            encrypted.len(),
            Hash::new(encrypted).into(),
        );
        if self.checkpoint_source.is_some_and(|old| old != source) {
            self.terminal = true;
            return Err(AttemptError::Binding);
        }
        self.checkpoint_source = Some(source);
        seat_export::publish_file(
            directory,
            CHECKPOINT,
            true,
            encrypted,
            &mut self.checkpoint_progress,
        )?;
        Ok(())
    }
    fn prepare_head_record(
        &mut self,
        binding: &DkgAggregateCheckpointBindingV1,
    ) -> std::result::Result<(), AttemptError> {
        if self.terminal || !self.checkpoint_progress.complete() {
            return Err(AttemptError::Phase);
        }
        let checkpoint_hash = self.checkpoint_source.ok_or(AttemptError::Phase)?.2;
        let record = AggregateHead {
            version: 1,
            binding: *binding,
            checkpoint_hash,
        };
        if self.head_record.is_some_and(|old| old != record) {
            return Err(AttemptError::Binding);
        }
        if self.head_record.is_none() {
            norito::core::write_canonical_to_writer(&record, &mut Bytes(&mut self.head))
                .map_err(seat_export::ExportError::from)?;
            self.head_record = Some(record);
        }
        Ok(())
    }
    pub(super) fn publish_head(
        &mut self,
        directory: &Directory,
        binding: &DkgAggregateCheckpointBindingV1,
    ) -> std::result::Result<(), AttemptError> {
        self.prepare_head_record(binding)?;
        seat_export::publish_file(
            directory,
            HEAD,
            true,
            self.head.as_slice(),
            &mut self.head_progress,
        )?;
        Ok(())
    }
    pub(super) fn complete(&self) -> bool {
        !self.terminal
            && self.intent_progress.complete()
            && self.checkpoint_progress.complete()
            && self.head_progress.complete()
    }
    /// Metadata alone never authenticates this completed phase or creates a private owner.
    pub(super) fn present(directory: &Directory) -> std::result::Result<bool, AttemptError> {
        durable::file_present(directory, HEAD)
    }
    /// Admit every exact original source extent before reading or private restoration.
    pub(super) fn prepare_restore(
        &mut self,
        directory: &Directory,
        bounds: [usize; 9],
    ) -> std::result::Result<(), AttemptError> {
        seat_export::revalidate_directory(directory)?;
        for (slot, (name, private)) in SOURCE_FILES.iter().enumerate() {
            open_original_file(
                directory,
                name,
                *private,
                bounds[slot],
                &mut self.loaded[slot + 2],
            )?;
        }
        let mut layouts = [Layout::new::<u8>(); 9];
        for (slot, loaded) in self.loaded[2..].iter().enumerate() {
            let length =
                usize::try_from(loaded.identity.as_ref().ok_or(AttemptError::Phase)?.len())
                    .map_err(|_| AttemptError::Binding)?;
            layouts[slot] =
                Layout::array::<u8>(length).map_err(|_| AllocationRefusal::DemandOverflow)?;
            if let Some(source) = &self.sources[slot] {
                if source.capacity() != length || !source.belongs_to(&self.budget) {
                    return Err(AttemptError::Binding);
                }
            }
        }
        if self.sources.iter().all(Option::is_none) {
            let mut reservation = self.budget.try_reserve_layouts(layouts)?;
            let mut sources = std::array::from_fn(|_| None);
            for (slot, layout) in layouts.iter().enumerate() {
                sources[slot] = Some(ChargedBuffer::from_reservation(
                    layout.size(),
                    &mut reservation,
                )?)
            }
            if reservation.remaining_bytes() != 0 {
                return Err(AttemptError::Phase);
            }
            self.sources = sources;
        } else if self.sources.iter().any(Option::is_none) {
            return Err(AttemptError::Binding);
        }
        seat_export::revalidate_directory(directory)?;
        Ok(())
    }
    pub(super) fn load(
        &mut self,
        directory: &Directory,
    ) -> std::result::Result<(AggregateIntent, AggregateHead), AttemptError> {
        read_file(
            directory,
            INTENT,
            true,
            &mut self.read_intent,
            &mut self.loaded[0],
        )?;
        read_file(
            directory,
            HEAD,
            true,
            &mut self.read_head,
            &mut self.loaded[1],
        )?;
        self.workspace
            .decode_canonical_into::<AggregateIntent, _>(
                self.read_intent.as_slice(),
                norito::canonical_decode_limits(self.read_intent.as_slice().len()),
                &mut View::<AggregateIntent> {
                    owner: &mut self.destination,
                    expiry: self.expiry,
                    marker: std::marker::PhantomData,
                },
            )
            .map_err(AttemptError::DurableDecode)?;
        let intent = self.destination.intent.as_slice()[0];
        self.workspace
            .decode_canonical_into::<AggregateHead, _>(
                self.read_head.as_slice(),
                norito::canonical_decode_limits(self.read_head.as_slice().len()),
                &mut View::<AggregateHead> {
                    owner: &mut self.destination,
                    expiry: self.expiry,
                    marker: std::marker::PhantomData,
                },
            )
            .map_err(AttemptError::DurableDecode)?;
        let head = self.destination.head.as_slice()[0];
        let mut original = head.binding;
        original.extraction_intent_hash = [0; 32];
        if intent.version != 1
            || head.version != 1
            || intent.binding != original
            || intent.binding.extraction_intent_hash != [0; 32]
            || head.binding.extraction_intent_hash
                != <[u8; 32]>::from(Hash::new(self.read_intent.as_slice()))
            || intent.stream_generations[0] != 2
        {
            return Err(AttemptError::Binding);
        }
        for (slot, (name, private)) in SOURCE_FILES.iter().enumerate() {
            read_file(
                directory,
                name,
                *private,
                self.sources[slot].as_mut().ok_or(AttemptError::Phase)?,
                &mut self.loaded[slot + 2],
            )?;
        }
        let hash = |slot: usize| -> std::result::Result<[u8; 32], AttemptError> {
            Ok(Hash::new(self.source(slot)?).into())
        };
        if head.checkpoint_hash != hash(0)?
            || intent.source_hashes != [hash(1)?, hash(2)?]
            || head.binding.accepted_head_hash != hash(3)?
            || head.binding.accepted_checkpoint_hash != hash(4)?
        {
            return Err(AttemptError::Binding);
        }
        if self.intent_record.is_some_and(|old| old != intent)
            || self.head_record.is_some_and(|old| old != head)
        {
            return Err(AttemptError::Binding);
        }
        self.intent_record = Some(intent);
        self.head_record = Some(head);
        Ok((intent, head))
    }
    pub(super) fn source(&self, slot: usize) -> std::result::Result<&[u8], AttemptError> {
        Ok(self.charged_source(slot)?.as_slice())
    }
    /// Borrow the original on-disk source bank without erasing its charged backing owner.
    /// Complete authenticated head/context and durability checks remain the caller's duty.
    pub(super) fn charged_source(
        &self,
        slot: usize,
    ) -> std::result::Result<&ChargedBuffer<u8>, AttemptError> {
        self.sources
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(AttemptError::Phase)
    }
    /// Same held source bytes and named inode are checked on both sides of every sync.
    /// The directory barrier completes before any caller adopts private/export custody.
    pub(super) fn sync_restored(
        &mut self,
        directory: &Directory,
    ) -> std::result::Result<(), AttemptError> {
        self.sync_restored_with(directory, |file| file.sync_all())
    }
    fn sync_restored_with(
        &mut self,
        directory: &Directory,
        mut sync: impl FnMut(&File) -> std::io::Result<()>,
    ) -> std::result::Result<(), AttemptError> {
        if self.intent_record.is_none() || self.head_record.is_none() {
            return Err(AttemptError::Phase);
        }
        self.directory_synced = false;
        for slot in [7, 3, 4, 5, 6, 8, 9, 10, 0, 2, 1] {
            let (name, private, bytes) = match slot {
                0 => (INTENT, true, &mut self.read_intent),
                1 => (HEAD, true, &mut self.read_head),
                _ => {
                    let (name, private) = SOURCE_FILES[slot - 2];
                    (
                        name,
                        private,
                        self.sources[slot - 2].as_mut().ok_or(AttemptError::Phase)?,
                    )
                }
            };
            read_file(directory, name, private, bytes, &mut self.loaded[slot])?;
            if !self.loaded[slot].synced {
                sync(
                    self.loaded[slot]
                        .descriptor
                        .as_ref()
                        .ok_or(AttemptError::Phase)?,
                )
                .map_err(seat_export::ExportError::Io)?;
                self.loaded[slot].synced = true;
            }
            read_file(directory, name, private, bytes, &mut self.loaded[slot])?;
        }
        sync(&directory.file).map_err(seat_export::ExportError::Io)?;
        seat_export::revalidate_directory(directory)?;
        // The directory barrier may block. Recheck every retained byte/inode after it.
        read_file(
            directory,
            INTENT,
            true,
            &mut self.read_intent,
            &mut self.loaded[0],
        )?;
        read_file(
            directory,
            HEAD,
            true,
            &mut self.read_head,
            &mut self.loaded[1],
        )?;
        for (slot, (name, private)) in SOURCE_FILES.iter().enumerate() {
            read_file(
                directory,
                name,
                *private,
                self.sources[slot].as_mut().ok_or(AttemptError::Phase)?,
                &mut self.loaded[slot + 2],
            )?;
        }
        self.directory_synced = true;
        Ok(())
    }
    pub(super) fn restored_sources_synced(&self) -> bool {
        self.directory_synced
            && self.intent_record.is_some()
            && self.head_record.is_some()
            && self.loaded.iter().all(|file| file.synced)
    }
    /// Exact already-open original raw source descriptors; preparation refusal retains all.
    #[cfg(test)]
    pub(super) fn source_descriptor_ids(&self) -> [Option<std::os::fd::RawFd>; 9] {
        use std::os::fd::AsRawFd as _;
        std::array::from_fn(|slot| {
            self.loaded[slot + 2]
                .descriptor
                .as_ref()
                .map(|file| file.as_raw_fd())
        })
    }
    /// No raw extent may become an initialized private owner during aggregate reservation refusal.
    #[cfg(test)]
    pub(super) fn sources_unadmitted(&self) -> bool {
        self.sources.iter().all(Option::is_none)
    }

    pub(super) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.budget.same_pool(budget)
            && self.intent.belongs_to(budget)
            && self.head.belongs_to(budget)
            && self.read_intent.belongs_to(budget)
            && self.read_head.belongs_to(budget)
            && self.destination.intent.belongs_to(budget)
            && self.destination.head.belongs_to(budget)
            && self.workspace.belongs_to(budget)
            && self
                .sources
                .iter()
                .flatten()
                .all(|source| source.belongs_to(budget))
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod raw_field_adapter_tests {
    use super::*;

    fn check_raw_record<const N: usize, E: std::fmt::Debug>(
        value: &impl SerializePayload,
        raw_indices: &[usize],
        start: usize,
        mut decode: impl FnMut(&[u8]) -> std::result::Result<usize, DecodeIntoError<E>>,
    ) {
        let mut payload = Vec::new();
        norito::core::serialize_to_writer(value, &mut payload).unwrap();
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32);
        let (decoded, usage) =
            norito::core::with_decode_limits_measured(limits, || decode(&payload));
        assert_eq!(decoded.unwrap(), payload.len());
        assert_eq!(usage.total_allocated_bytes(), 0);
        for &index in raw_indices {
            let mut offset = start;
            let mut frame_start = 0;
            let mut body_start = 0;
            for _ in 0..=index {
                frame_start = offset;
                let (length, prefix) =
                    norito::core::inspect_len_from_slice(&payload[offset..]).unwrap();
                body_start = offset + prefix;
                offset = body_start + length;
            }
            let raw: [u8; N] = payload[body_start..offset].try_into().unwrap();
            let mut generic = Vec::new();
            norito::core::serialize_to_writer(&raw, &mut generic).unwrap();
            assert_ne!(generic.len(), N);
            let mut long = raw.to_vec();
            long.push(0xa5);
            for body in [raw[..N - 1].to_vec(), long, generic] {
                let mut malformed = payload[..frame_start].to_vec();
                norito::core::write_len_header_to_vec(&mut malformed, body.len() as u64);
                malformed.extend_from_slice(&body);
                malformed.extend_from_slice(&payload[offset..]);
                let (decoded, usage) =
                    norito::core::with_decode_limits_measured(limits, || decode(&malformed));
                assert!(matches!(
                    decoded,
                    Err(DecodeIntoError::Codec(norito::Error::LengthMismatch))
                ));
                assert_eq!(usage.total_allocated_bytes(), 0);
            }
        }
    }

    fn hash(seed: u8) -> [u8; 32] {
        std::array::from_fn(|i| (i as u8).wrapping_add(seed))
    }

    #[test]
    fn aggregate_raw_fields_keep_both_layouts_original_credit_and_generic_source_arrays() {
        for flags in [0, norito::core::header_flags::COMPACT_LEN] {
            let _flags = norito::core::DecodeFlagsGuard::enter(flags);
            let expiry = DurableDeadline {
                boot: hash(0x41),
                origin_nanos: 100,
                expiry_nanos: 200,
            };
            let mut binding = empty_binding();
            binding.network_id = hash(0x11);
            binding.attempt_id = hash(0x12);
            binding.session_id = hash(0x13);
            binding.roster_hash = hash(0x14);
            binding.lifecycle_key_hash = hash(0x15);
            binding.provider_handle_hash = hash(0x16);
            binding.public_session_hash = hash(0x17);
            binding.transcript_hash = hash(0x18);
            binding.accepted_checkpoint_hash = hash(0x19);
            binding.accepted_head_hash = hash(0x1a);
            binding.extraction_intent_hash = hash(0x1b);
            binding.source =
                iroha_crypto::threshold_bls::checkpoint::DkgCheckpointSourceV1::ExecutedNativeTip {
                    height: 9,
                    block_hash: hash(0x21),
                    core_hash: hash(0x22),
                    result_hash: hash(0x23),
                };
            let mut decoded_binding = empty_binding();
            check_raw_record::<32, _>(
                &binding,
                &[0, 1, 3, 4, 6, 7, 16, 17, 18, 19, 20],
                0,
                |bytes| {
                    DkgAggregateCheckpointBindingV1::decode_fields(
                        bytes,
                        &mut Inline(&mut decoded_binding),
                    )
                    .map(|(_, used)| used)
                },
            );
            assert_eq!(decoded_binding, binding);
            let mut decoded_expiry = DurableDeadline {
                boot: [0; 32],
                ..expiry
            };
            check_raw_record::<32, _>(&expiry, &[0], 0, |bytes| {
                DurableDeadline::decode_fields(bytes, &mut Inline(&mut decoded_expiry))
                    .map(|(_, used)| used)
            });
            assert_eq!(decoded_expiry, expiry);
            let mut intent = AggregateIntent::empty(expiry);
            intent.binding = binding;
            intent.claim_identity = [17, 18, 19, 20];
            intent.claim_path_hash = hash(0x51);
            intent.fifo_identity = [21, 22, 23, 24];
            intent.source_hashes = [hash(0x61), hash(0x71)];
            intent.stream_generations = [25, 26];
            let head = AggregateHead {
                version: 1,
                binding,
                checkpoint_hash: hash(0x81),
            };
            let pool = AllocationBudget::new(1 << 20);
            let mut destination = Destination {
                intent: ChargedBuffer::new(1, &pool).unwrap(),
                head: ChargedBuffer::new(1, &pool).unwrap(),
            };
            destination
                .intent
                .push_reserved(AggregateIntent::empty(expiry));
            destination.head.push_reserved(AggregateHead::empty());
            let pointers = (
                destination.intent.as_slice().as_ptr(),
                destination.head.as_slice().as_ptr(),
            );
            let blocker = pool
                .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
                .unwrap();
            check_raw_record::<32, _>(&intent, &[4], 0, |bytes| {
                AggregateIntent::decode_fields(
                    bytes,
                    &mut View::<AggregateIntent> {
                        owner: &mut destination,
                        expiry,
                        marker: std::marker::PhantomData,
                    },
                )
                .map(|(_, used)| used)
            });
            assert_eq!(destination.intent.as_slice()[0], intent);
            check_raw_record::<32, _>(&head, &[2], 0, |bytes| {
                AggregateHead::decode_fields(
                    bytes,
                    &mut View::<AggregateHead> {
                        owner: &mut destination,
                        expiry,
                        marker: std::marker::PhantomData,
                    },
                )
                .map(|(_, used)| used)
            });
            assert_eq!(destination.head.as_slice()[0], head);
            assert_eq!(destination.intent.as_slice().as_ptr(), pointers.0);
            assert_eq!(destination.head.as_slice().as_ptr(), pointers.1);
            assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
            drop(destination);
            assert_eq!(pool.reserved_bytes(), blocker.remaining_bytes());
            drop(blocker);
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}
