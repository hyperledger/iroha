//! Immutable producer intents, private checkpoints and complete durable phase heads.
//!
//! Complete later heads require their exact original input/proof prefix. Partial
//! FIFO reads, producer intents or extraction cannot reopen a preceding phase.
//! TODO: restore aggregate/extraction owners and an independently authenticated rollback-resistant
//! head before qualifying all-phase or all-seat restart. Owner-private local files
//! plus AEAD authenticate content; they do not detect deletion of an entire suffix.

use super::durable_deadline::DurableDeadline;
use super::*;
use iroha_crypto::threshold_bls::checkpoint::{DkgCheckpointBindingV1, DkgCheckpointSourceV1};
use norito::core::{
    CanonicalField, DecodeField, DecodeFromSlice, DecodeIntoError, DecodeRecordFields, Encoder,
    FieldDestination, PreparedDecodeWorkspace, PreparedRecordDestination, SerializePayload,
};
use norito::{NoritoDeserialize, NoritoSchema, NoritoSerialize};
use std::{alloc::Layout, convert::Infallible, result::Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito(decode_fields)]
#[norito_schema(name = "irohad::beacon_bootstrap::seat_attempt::ProducerIntentV1")]
pub(super) struct Intent {
    version: u16,
    operation: u16,
    context: DkgCheckpointBindingV1,
    pub(super) expiry: DurableDeadline,
    pub(super) claim_identity: [u64; 4],
    pub(super) claim_path_hash: [u8; 32],
    pub(super) fifo_identity: [u64; 4],
    previous_head_hash: [u8; 32],
    continuation_hash: [u8; 32],
    continuation_source: DkgCheckpointSourceV1,
    source_hashes: [[u8; 32]; 2],
    pub(super) stream_generations: [u64; 2],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito(decode_fields)]
#[norito_schema(name = "irohad::beacon_bootstrap::seat_attempt::DurableDkgHeadV1")]
pub(super) struct Head {
    version: u16,
    pub(super) context: DkgCheckpointBindingV1,
    pub(super) checkpoint_hash: [u8; 32],
    previous_head_hash: [u8; 32],
}
pub(super) fn empty_context() -> DkgCheckpointBindingV1 {
    DkgCheckpointBindingV1 {
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
        source: DkgCheckpointSourceV1::ExecutedNativeTip {
            height: 0,
            block_hash: [0; 32],
            core_hash: [0; 32],
            result_hash: [0; 32],
        },
        cutoff_height: 0,
        phase: 0,
        public_output_hash: [0; 32],
        phase_input_hash: [0; 32],
        producer_intent_hash: [0; 32],
        previous_checkpoint_hash: [0; 32],
    }
}
impl Intent {
    fn empty(expiry: DurableDeadline) -> Self {
        Self {
            version: 0,
            operation: 0,
            context: empty_context(),
            expiry,
            claim_identity: [0; 4],
            claim_path_hash: [0; 32],
            fifo_identity: [0; 4],
            previous_head_hash: [0; 32],
            continuation_hash: [0; 32],
            continuation_source: empty_context().source,
            source_hashes: [[0; 32]; 2],
            stream_generations: [0; 2],
        }
    }
}
impl Head {
    fn empty() -> Self {
        Self {
            version: 0,
            context: empty_context(),
            checkpoint_hash: [0; 32],
            previous_head_hash: [0; 32],
        }
    }
}
struct Destination {
    intent: ChargedBuffer<Intent>,
    head: ChargedBuffer<Head>,
}
impl FieldDestination for Destination {
    type Error = Infallible;
}
macro_rules! field {
    ($record:ty,$owner:ident,$index:literal,[u8; $length:expr],$name:ident) => {
        impl DecodeField<$index, [u8; $length]> for DestinationFor<'_, $record> {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, [u8; $length]>,
            ) -> Result<(), DecodeIntoError<Infallible>> {
                self.owner.$owner.as_mut_slice()[0].$name =
                    field.decode_owned().map_err(DecodeIntoError::Codec)?;
                Ok(())
            }
        }
    };
    ($record:ty,$owner:ident,$index:literal,$ty:ty,$name:ident) => {
        impl DecodeField<$index, $ty> for DestinationFor<'_, $record> {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, $ty>,
            ) -> Result<(), DecodeIntoError<Infallible>> {
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
struct DestinationFor<'a, T> {
    owner: &'a mut Destination,
    expiry: DurableDeadline,
    marker: std::marker::PhantomData<T>,
}
impl<T> FieldDestination for DestinationFor<'_, T> {
    type Error = Infallible;
}
// Nested fixed records are filled in the original inline charged record. No
// owned/archived leaf decoder, alignment copy or replacement buffer is used.
struct InlineFor<'a, T>(&'a mut T);
impl<T> FieldDestination for InlineFor<'_, T> {
    type Error = Infallible;
}
macro_rules! inline_field {
    ($record:ty,$index:literal,[u8; $length:expr],$name:ident) => {
        impl DecodeField<$index, [u8; $length]> for InlineFor<'_, $record> {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, [u8; $length]>,
            ) -> Result<(), DecodeIntoError<Infallible>> {
                self.0.$name = field.decode_owned().map_err(DecodeIntoError::Codec)?;
                Ok(())
            }
        }
    };
    ($record:ty,$index:literal,$ty:ty,$name:ident) => {
        impl DecodeField<$index, $ty> for InlineFor<'_, $record> {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, $ty>,
            ) -> Result<(), DecodeIntoError<Infallible>> {
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
inline_field!(DkgCheckpointBindingV1, 0, [u8; 32], network_id);
inline_field!(DkgCheckpointBindingV1, 1, [u8; 32], attempt_id);
inline_field!(DkgCheckpointBindingV1, 2, u64, authority_generation);
inline_field!(DkgCheckpointBindingV1, 3, [u8; 32], session_id);
inline_field!(DkgCheckpointBindingV1, 4, [u8; 32], roster_hash);
inline_field!(DkgCheckpointBindingV1, 5, u16, seat_index);
inline_field!(DkgCheckpointBindingV1, 6, [u8; 32], lifecycle_key_hash);
inline_field!(DkgCheckpointBindingV1, 7, [u8; 32], provider_handle_hash);
inline_field!(DkgCheckpointBindingV1, 8, u64, provider_revision);
inline_field!(DkgCheckpointBindingV1, 9, u64, start_height);
inline_field!(DkgCheckpointBindingV1, 10, u64, commitments_end_height);
inline_field!(DkgCheckpointBindingV1, 11, u64, deliveries_end_height);
inline_field!(DkgCheckpointBindingV1, 12, u64, acceptances_end_height);
inline_field!(DkgCheckpointBindingV1, 14, u64, cutoff_height);
inline_field!(DkgCheckpointBindingV1, 15, u16, phase);
inline_field!(DkgCheckpointBindingV1, 16, [u8; 32], public_output_hash);
inline_field!(DkgCheckpointBindingV1, 17, [u8; 32], phase_input_hash);
inline_field!(DkgCheckpointBindingV1, 18, [u8; 32], producer_intent_hash);
inline_field!(
    DkgCheckpointBindingV1,
    19,
    [u8; 32],
    previous_checkpoint_hash
);
inline_field!(DurableDeadline, 0, [u8; 32], boot);
inline_field!(DurableDeadline, 1, u128, origin_nanos);
inline_field!(DurableDeadline, 2, u128, expiry_nanos);

// Only the five fixed scalar/array source slots can use this stack destination.
pub(super) struct SourceFields;
impl FieldDestination for SourceFields {
    type Error = Infallible;
}
macro_rules! source_field {
    ($index:literal,[u8; $length:expr]) => {
        impl DecodeField<$index, [u8; $length]> for SourceFields {
            type Value = [u8; $length];
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, [u8; $length]>,
            ) -> Result<[u8; $length], DecodeIntoError<Infallible>> {
                field.decode_owned().map_err(DecodeIntoError::Codec)
            }
        }
    };
    ($index:literal,$ty:ty) => {
        impl DecodeField<$index, $ty> for SourceFields {
            type Value = $ty;
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, $ty>,
            ) -> Result<$ty, DecodeIntoError<Infallible>> {
                field.with_payload(|bytes| {
                    let (value, used) = <$ty as DecodeFromSlice>::decode_from_slice(bytes)?;
                    if used != bytes.len() {
                        return Err(norito::Error::LengthMismatch.into());
                    }
                    Ok(value)
                })
            }
        }
    };
}
source_field!(0, [u8; 32]);
source_field!(1, u64);
source_field!(2, [u8; 32]);
source_field!(3, [u8; 32]);
source_field!(4, [u8; 32]);
impl DecodeField<13, DkgCheckpointSourceV1> for InlineFor<'_, DkgCheckpointBindingV1> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, DkgCheckpointSourceV1>,
    ) -> Result<(), DecodeIntoError<Infallible>> {
        self.0.source = field.with_payload(|bytes| {
            let (value, used) = DkgCheckpointSourceV1::decode_fields(bytes, &mut SourceFields)?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            Ok(value)
        })?;
        Ok(())
    }
}
macro_rules! nested_field {
    ($record:ty,$owner:ident,$index:literal,$ty:ty,$name:ident) => {
        impl DecodeField<$index, $ty> for DestinationFor<'_, $record> {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, $ty>,
            ) -> Result<(), DecodeIntoError<Infallible>> {
                let mut destination = InlineFor(&mut self.owner.$owner.as_mut_slice()[0].$name);
                field.with_payload(|bytes| {
                    let (_, used) =
                        <$ty as DecodeRecordFields<_>>::decode_fields(bytes, &mut destination)?;
                    if used != bytes.len() {
                        return Err(norito::Error::LengthMismatch.into());
                    }
                    Ok(())
                })
            }
        }
    };
}
field!(Intent, intent, 0, u16, version);
field!(Intent, intent, 1, u16, operation);
nested_field!(Intent, intent, 2, DkgCheckpointBindingV1, context);
nested_field!(Intent, intent, 3, DurableDeadline, expiry);
field!(Intent, intent, 4, [u64; 4], claim_identity);
field!(Intent, intent, 5, [u8; 32], claim_path_hash);
field!(Intent, intent, 6, [u64; 4], fifo_identity);
field!(Intent, intent, 7, [u8; 32], previous_head_hash);
field!(Intent, intent, 8, [u8; 32], continuation_hash);
impl DecodeField<9, DkgCheckpointSourceV1> for DestinationFor<'_, Intent> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, DkgCheckpointSourceV1>,
    ) -> Result<(), DecodeIntoError<Infallible>> {
        self.owner.intent.as_mut_slice()[0].continuation_source = field.with_payload(|bytes| {
            let (value, used) = DkgCheckpointSourceV1::decode_fields(bytes, &mut SourceFields)?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            Ok(value)
        })?;
        Ok(())
    }
}
field!(Intent, intent, 10, [[u8; 32]; 2], source_hashes);
field!(Intent, intent, 11, [u64; 2], stream_generations);
field!(Head, head, 0, u16, version);
nested_field!(Head, head, 1, DkgCheckpointBindingV1, context);
field!(Head, head, 2, [u8; 32], checkpoint_hash);
field!(Head, head, 3, [u8; 32], previous_head_hash);
impl SerializePayload for DestinationFor<'_, Intent> {
    fn serialize(&self, e: &mut Encoder<'_>) -> Result<(), norito::Error> {
        self.owner.intent.as_slice()[0].serialize(e)
    }
}
impl SerializePayload for DestinationFor<'_, Head> {
    fn serialize(&self, e: &mut Encoder<'_>) -> Result<(), norito::Error> {
        self.owner.head.as_slice()[0].serialize(e)
    }
}
impl PreparedRecordDestination<Intent> for DestinationFor<'_, Intent> {
    fn reset(&mut self) {
        // The original admitted deadline is retained by this borrowed stack view,
        // even when a later field refuses after overwriting the decoded expiry.
        self.owner.intent.as_mut_slice()[0] = Intent::empty(self.expiry);
    }
}
impl PreparedRecordDestination<Head> for DestinationFor<'_, Head> {
    fn reset(&mut self) {
        self.owner.head.as_mut_slice()[0] = Head::empty();
    }
}
pub(super) struct Bytes<'a>(pub(super) &'a mut ChargedBuffer<u8>);
impl std::io::Write for Bytes<'_> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.append(b)?;
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
const INTENT_FILES: [&str; 6] = [
    "producer-1-intent.norito",
    "producer-2-intent.norito",
    "producer-3-intent.norito",
    "input-consumption.norito",
    "delivery-input-consumption.norito",
    "session-input-consumption.norito",
];
// Extraction has its own final aggregate intent; no retired phase4 format,
// encoder, source bank or writer remains in this phase1..3 owner.
fn intent_index(operation: u16) -> Result<usize, AttemptError> {
    match operation {
        1..=3 => Ok(usize::from(operation - 1)),
        5..=7 => Ok(usize::from(operation - 2)),
        _ => Err(AttemptError::Phase),
    }
}
const CHECKPOINT_FILES: [&str; 3] = [
    "private-checkpoint-1.norito",
    "private-checkpoint-2.norito",
    "private-checkpoint-3.norito",
];
const HEAD_FILES: [&str; 3] = [
    "phase-head-1.norito",
    "phase-head-2.norito",
    "phase-head-3.norito",
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CheckpointSource {
    address: usize,
    length: usize,
    digest: Hash,
}
impl CheckpointSource {
    fn of(bytes: &[u8]) -> Self {
        Self {
            address: bytes.as_ptr().addr(),
            length: bytes.len(),
            digest: Hash::new(bytes),
        }
    }
}
#[derive(Default)]
pub(super) struct Loaded {
    pub(super) descriptor: Option<File>,
    pub(super) identity: Option<fs::Metadata>,
    pub(super) synced: bool,
}

/// Held source extents for one completed later phase. Controls are inline in the
/// prepaid receiver; exact regular-file byte extents are admitted before reads.
struct LaterLoaded {
    files: [Loaded; 7],
    // Original output, private checkpoint, public input and full native proof.
    bytes: [Option<ChargedBuffer<u8>>; 4],
    record: Option<(Intent, Head)>,
}
impl Default for LaterLoaded {
    fn default() -> Self {
        Self {
            files: std::array::from_fn(|_| Loaded::default()),
            bytes: std::array::from_fn(|_| None),
            record: None,
        }
    }
}
const LATER_FILES: [[(&str, bool); 7]; 2] = [
    [
        ("producer-2-intent.norito", true),
        ("phase-head-2.norito", true),
        ("deliveries.norito", false),
        ("private-checkpoint-2.norito", true),
        ("input-commitments.norito", true),
        ("proof-commitments.norito", true),
        ("input-consumption.norito", true),
    ],
    [
        ("producer-3-intent.norito", true),
        ("phase-head-3.norito", true),
        ("acceptances.norito", false),
        ("private-checkpoint-3.norito", true),
        ("input-deliveries.norito", true),
        ("proof-deliveries.norito", true),
        ("delivery-input-consumption.norito", true),
    ],
];

/// All byte arrays, fixed records and canonical control owners precede claim/RNG.
pub(super) struct PreparedDurableDkg {
    expiry: DurableDeadline,
    intents: [ChargedBuffer<u8>; 6],
    intent_records: [Option<Intent>; 6],
    heads: [ChargedBuffer<u8>; 3],
    head_records: [Option<Head>; 3],
    intent_progress: [seat_export::FileProgress; 5],
    checkpoint_progress: [seat_export::FileProgress; 3],
    checkpoint_sources: [Option<CheckpointSource>; 3],
    checkpoint_terminal: [bool; 3],
    head_progress: [seat_export::FileProgress; 3],
    read_intent: ChargedBuffer<u8>,
    read_head: ChargedBuffer<u8>,
    public_source: ChargedBuffer<u8>,
    private_source: ChargedBuffer<u8>,
    loaded: [Loaded; 4],
    later: [LaterLoaded; 2],
    restore_phase: Option<u16>,
    restored_directory_synced: bool,
    destination: Destination,
    workspace: PreparedDecodeWorkspace,
    budget: AllocationBudget,
}
impl PreparedDurableDkg {
    pub(super) fn new(
        expiry: DurableDeadline,
        public_bound: usize,
        private_bound: usize,
        budget: &AllocationBudget,
    ) -> Result<Self, AttemptError> {
        let intent_len = norito::canonical_frame_len(&Intent::empty(expiry))
            .map_err(seat_export::ExportError::from)?;
        let head_len =
            norito::canonical_frame_len(&Head::empty()).map_err(seat_export::ExportError::from)?;
        let controls = PreparedDecodeWorkspace::allocation_layouts();
        let mut layouts = [Layout::new::<u8>(); 17];
        for slot in &mut layouts[..6] {
            *slot =
                Layout::array::<u8>(intent_len).map_err(|_| AllocationRefusal::DemandOverflow)?;
        }
        for slot in &mut layouts[6..9] {
            *slot = Layout::array::<u8>(head_len).map_err(|_| AllocationRefusal::DemandOverflow)?;
        }
        layouts[9] = layouts[0];
        layouts[10] = layouts[6];
        layouts[11] =
            Layout::array::<u8>(public_bound).map_err(|_| AllocationRefusal::DemandOverflow)?;
        layouts[12] =
            Layout::array::<u8>(private_bound).map_err(|_| AllocationRefusal::DemandOverflow)?;
        layouts[13] = Layout::array::<Intent>(1).map_err(|_| AllocationRefusal::DemandOverflow)?;
        layouts[14] = Layout::array::<Head>(1).map_err(|_| AllocationRefusal::DemandOverflow)?;
        layouts[15] = controls[0];
        layouts[16] = controls[1];
        let mut reservation = budget.try_reserve_layouts(layouts)?;
        let mut make = |capacity| ChargedBuffer::from_reservation(capacity, &mut reservation);
        let intents = [
            make(intent_len)?,
            make(intent_len)?,
            make(intent_len)?,
            make(intent_len)?,
            make(intent_len)?,
            make(intent_len)?,
        ];
        let heads = [make(head_len)?, make(head_len)?, make(head_len)?];
        let read_intent = make(intent_len)?;
        let read_head = make(head_len)?;
        let public_source = make(public_bound)?;
        let private_source = make(private_bound)?;
        let mut intent = ChargedBuffer::from_reservation(1, &mut reservation)?;
        intent.push_reserved(Intent::empty(expiry));
        let mut head = ChargedBuffer::from_reservation(1, &mut reservation)?;
        head.push_reserved(Head::empty());
        let workspace = PreparedDecodeWorkspace::from_reservation(budget, &mut reservation)
            .map_err(AttemptError::DurableScope)?;
        if reservation.remaining_bytes() != 0 {
            return Err(AttemptError::Phase);
        }
        Ok(Self {
            expiry,
            intents,
            intent_records: [None; 6],
            heads,
            head_records: [None; 3],
            intent_progress: std::array::from_fn(|_| seat_export::FileProgress::default()),
            checkpoint_progress: std::array::from_fn(|_| seat_export::FileProgress::default()),
            checkpoint_sources: [None; 3],
            checkpoint_terminal: [false; 3],
            head_progress: std::array::from_fn(|_| seat_export::FileProgress::default()),
            read_intent,
            read_head,
            public_source,
            private_source,
            loaded: std::array::from_fn(|_| Loaded::default()),
            later: std::array::from_fn(|_| LaterLoaded::default()),
            restore_phase: None,
            restored_directory_synced: false,
            destination: Destination { intent, head },
            workspace,
            budget: budget.clone(),
        })
    }
    pub(super) fn tightened_deadline(&self, deadline: Instant) -> Result<Instant, AttemptError> {
        self.expiry.restore(deadline)
    }
    pub(super) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.budget.same_pool(budget)
            && self.intents.iter().all(|b| b.belongs_to(budget))
            && self.heads.iter().all(|b| b.belongs_to(budget))
            && self.read_intent.belongs_to(budget)
            && self.read_head.belongs_to(budget)
            && self.public_source.belongs_to(budget)
            && self.private_source.belongs_to(budget)
            && self
                .later
                .iter()
                .all(|phase| phase.bytes.iter().flatten().all(|b| b.belongs_to(budget)))
            && self.destination.intent.belongs_to(budget)
            && self.destination.head.belongs_to(budget)
            && self.workspace.belongs_to(budget)
    }
    pub(super) fn prepare_intent(
        &mut self,
        operation: u16,
        context: &DkgCheckpointBindingV1,
        claim_identity: [u64; 4],
        claim_path_hash: [u8; 32],
        fifo_identity: [u64; 4],
        continuation: Option<([u8; 32], DkgCheckpointSourceV1)>,
        source_hashes: [[u8; 32]; 2],
        stream_generations: [u64; 2],
    ) -> Result<(), AttemptError> {
        let index = intent_index(operation)?;
        let previous_head_hash = if operation == 1 {
            [0; 32]
        } else {
            self.latest_head_hash()?
        };
        let (continuation_hash, continuation_source) =
            continuation.unwrap_or(([0; 32], context.source));
        let record = Intent {
            version: 1,
            operation,
            context: *context,
            expiry: self.expiry,
            claim_identity,
            claim_path_hash,
            fifo_identity,
            previous_head_hash,
            continuation_hash,
            continuation_source,
            source_hashes,
            stream_generations,
        };
        if let Some(original) = self.intent_records[index] {
            if original != record {
                return Err(AttemptError::Binding);
            }
            return Ok(());
        }
        if !self.intents[index].as_slice().is_empty() {
            return Err(AttemptError::Phase);
        }
        norito::core::write_canonical_to_writer(&record, &mut Bytes(&mut self.intents[index]))
            .map_err(seat_export::ExportError::from)?;
        self.intent_records[index] = Some(record);
        Ok(())
    }
    pub(super) fn intent_bytes(&self, operation: u16) -> Result<&[u8], AttemptError> {
        let index = intent_index(operation)?;
        self.intents
            .get(index)
            .filter(|b| !b.as_slice().is_empty())
            .map(ChargedBuffer::as_slice)
            .ok_or(AttemptError::Phase)
    }
    pub(super) fn intent_hash(&self, operation: u16) -> Result<[u8; 32], AttemptError> {
        Ok(Hash::new(self.intent_bytes(operation)?).into())
    }
    pub(super) fn publish_intent(
        &mut self,
        directory: &Directory,
        operation: u16,
    ) -> Result<(), AttemptError> {
        if operation == 1 {
            return Err(AttemptError::Phase);
        }
        let index = intent_index(operation)?;
        let bytes = self.intent_bytes(operation)?;
        // Split immutable source and original descriptor progress without copying bytes.
        let _ = bytes;
        seat_export::publish_file(
            directory,
            INTENT_FILES[index],
            true,
            self.intents[index].as_slice(),
            &mut self.intent_progress[index - 1],
        )?;
        Ok(())
    }
    pub(super) fn publish_checkpoint(
        &mut self,
        directory: &Directory,
        phase: u16,
        encrypted: &[u8],
    ) -> Result<(), AttemptError> {
        if !(1..=3).contains(&phase) {
            return Err(AttemptError::Phase);
        }
        let index = usize::from(phase - 1);
        if self.checkpoint_terminal[index] || encrypted.is_empty() {
            return Err(AttemptError::Binding);
        }
        let source = CheckpointSource::of(encrypted);
        if let Some(original) = self.checkpoint_sources[index] {
            if original != source {
                self.checkpoint_terminal[index] = true;
                return Err(AttemptError::Binding);
            }
        } else {
            self.checkpoint_sources[index] = Some(source);
        }
        let result = seat_export::publish_file(
            directory,
            CHECKPOINT_FILES[index],
            true,
            encrypted,
            &mut self.checkpoint_progress[index],
        );
        if matches!(result, Err(seat_export::ExportError::Custody)) {
            self.checkpoint_terminal[index] = true;
        }
        result?;
        Ok(())
    }
    fn prepare_head(
        &mut self,
        context: &DkgCheckpointBindingV1,
        encrypted_hash: [u8; 32],
    ) -> Result<usize, AttemptError> {
        let phase = context.phase;
        if !(1..=3).contains(&phase) || context.producer_intent_hash != self.intent_hash(phase)? {
            return Err(AttemptError::Binding);
        }
        let index = usize::from(phase - 1);
        if !self.checkpoint_progress[index].complete()
            || self.checkpoint_terminal[index]
            || !self.checkpoint_sources[index]
                .is_some_and(|source| <[u8; 32]>::from(source.digest) == encrypted_hash)
        {
            return Err(AttemptError::Binding);
        }
        let previous_head_hash = if phase == 1 {
            [0; 32]
        } else {
            Hash::new(self.heads[index - 1].as_slice()).into()
        };
        let record = Head {
            version: 1,
            context: *context,
            checkpoint_hash: encrypted_hash,
            previous_head_hash,
        };
        if let Some(original) = self.head_records[index] {
            if original != record {
                return Err(AttemptError::Binding);
            }
        } else {
            if !self.heads[index].as_slice().is_empty() {
                return Err(AttemptError::Phase);
            }
            norito::core::write_canonical_to_writer(&record, &mut Bytes(&mut self.heads[index]))
                .map_err(seat_export::ExportError::from)?;
            self.head_records[index] = Some(record);
        }
        Ok(index)
    }
    pub(super) fn publish_head(
        &mut self,
        directory: &Directory,
        context: &DkgCheckpointBindingV1,
        encrypted_hash: [u8; 32],
    ) -> Result<(), AttemptError> {
        let index = self.prepare_head(context, encrypted_hash)?;
        seat_export::publish_file(
            directory,
            HEAD_FILES[index],
            true,
            self.heads[index].as_slice(),
            &mut self.head_progress[index],
        )?;
        Ok(())
    }
    #[cfg(test)]
    fn stop_generation_head_before_sync(
        &mut self,
        directory: &Directory,
        context: &DkgCheckpointBindingV1,
        encrypted_hash: [u8; 32],
    ) -> Result<(), AttemptError> {
        let index = self.prepare_head(context, encrypted_hash)?;
        seat_export::prepare_file_bytes(
            directory,
            HEAD_FILES[index],
            true,
            self.heads[index].as_slice(),
            &mut self.head_progress[index],
        )?;
        Ok(())
    }
    pub(super) fn aggregate_prefix_record_bounds(&self) -> [usize; 2] {
        [self.read_head.capacity(), self.read_intent.capacity()]
    }
    pub(super) fn verify_aggregate_accepted_prefix(
        &mut self,
        intent: &super::aggregate_durable::AggregateIntent,
        binding: &iroha_crypto::threshold_bls::aggregate_checkpoint::DkgAggregateCheckpointBindingV1,
        head_bytes: &[u8],
        checkpoint_bytes: &[u8],
        marker_bytes: &[u8],
        intent_bytes: &[u8],
        output_bytes: &[u8],
    ) -> Result<Head, AttemptError> {
        self.workspace
            .decode_canonical_into::<Head, _>(
                head_bytes,
                norito::canonical_decode_limits(head_bytes.len()),
                &mut DestinationFor::<Head> {
                    owner: &mut self.destination,
                    expiry: self.expiry,
                    marker: std::marker::PhantomData,
                },
            )
            .map_err(AttemptError::DurableDecode)?;
        let head = self.destination.head.as_slice()[0];
        let mut decode = |bytes: &[u8]| -> Result<Intent, AttemptError> {
            self.workspace
                .decode_canonical_into::<Intent, _>(
                    bytes,
                    norito::canonical_decode_limits(bytes.len()),
                    &mut DestinationFor::<Intent> {
                        owner: &mut self.destination,
                        expiry: self.expiry,
                        marker: std::marker::PhantomData,
                    },
                )
                .map_err(AttemptError::DurableDecode)?;
            Ok(self.destination.intent.as_slice()[0])
        };
        let marker = decode(marker_bytes)?;
        let original_intent = decode(intent_bytes)?;
        let head_hash: [u8; 32] = Hash::new(head_bytes).into();
        let mut original = head.context;
        original.public_output_hash = [0; 32];
        original.producer_intent_hash = [0; 32];
        if head.version != 1
            || head.context.phase != 3
            || head_hash != binding.accepted_head_hash
            || head.checkpoint_hash != binding.accepted_checkpoint_hash
            || head.checkpoint_hash != <[u8; 32]>::from(Hash::new(checkpoint_bytes))
            || head.context.public_output_hash != <[u8; 32]>::from(Hash::new(output_bytes))
            || head.context.producer_intent_hash != <[u8; 32]>::from(Hash::new(intent_bytes))
            || original_intent.version != 1
            || original_intent.operation != 3
            || original_intent.context != original
            || original_intent.previous_head_hash != head.previous_head_hash
            || original_intent.expiry != intent.expiry
            || original_intent.claim_identity != intent.claim_identity
            || original_intent.claim_path_hash != intent.claim_path_hash
            || original_intent.fifo_identity != intent.fifo_identity
            || original_intent.stream_generations[0] != 1
            || marker.version != 1
            || marker.operation != 7
            || marker.context != head.context
            || marker.previous_head_hash != head_hash
            || marker.expiry != intent.expiry
            || marker.claim_identity != intent.claim_identity
            || marker.claim_path_hash != intent.claim_path_hash
            || marker.fifo_identity != intent.fifo_identity
            || marker.source_hashes != [[0; 32]; 2]
            || marker.continuation_hash != [0; 32]
            || marker.continuation_source != head.context.source
            || marker.stream_generations[0] != 2
            || marker.stream_generations[1] != original_intent.stream_generations[1]
            || intent.stream_generations[1] <= marker.stream_generations[1]
        {
            return Err(AttemptError::Binding);
        }
        Ok(head)
    }

    pub(super) fn latest_context(&self) -> Result<&DkgCheckpointBindingV1, AttemptError> {
        self.head_records
            .iter()
            .rev()
            .flatten()
            .next()
            .map(|h| &h.context)
            .ok_or(AttemptError::Phase)
    }
    pub(super) fn previous_checkpoint_hash(&self, phase: u16) -> Result<[u8; 32], AttemptError> {
        if phase == 1 {
            Ok([0; 32])
        } else {
            self.head_records
                .get(usize::from(phase - 2))
                .and_then(Option::as_ref)
                .map(|h| h.checkpoint_hash)
                .ok_or(AttemptError::Phase)
        }
    }
    pub(super) fn latest_head_hash(&self) -> Result<[u8; 32], AttemptError> {
        self.heads
            .iter()
            .rev()
            .find(|b| !b.as_slice().is_empty())
            .map(|b| Hash::new(b.as_slice()).into())
            .ok_or(AttemptError::Phase)
    }
    /// A held owner-private directory may select bounded reload preparation.
    /// A head name is not a phase/source authorization; complete canonical/AEAD
    /// and native evidence must still authenticate every selected prefix.
    pub(super) fn restore_phase_hint(directory: &Directory) -> Result<u16, AttemptError> {
        seat_export::revalidate_directory(directory)?;
        let phase = if file_present(directory, HEAD_FILES[2])? {
            3
        } else if file_present(directory, HEAD_FILES[1])? {
            2
        } else {
            1
        };
        seat_export::revalidate_directory(directory)?;
        Ok(phase)
    }
    /// Discover a complete original prefix and physically admit every later raw
    /// source before the first private owner is restored. Presence is only custody;
    /// canonical intents/heads and genuine native ancestry are checked afterwards.
    pub(super) fn prepare_restore(
        &mut self,
        directory: &Directory,
        input_bounds: [usize; 3],
        proof_bound: usize,
    ) -> Result<u16, AttemptError> {
        seat_export::revalidate_directory(directory)?;
        let phase = Self::restore_phase_hint(directory)?;
        if self.restore_phase.is_some_and(|old| old != phase) {
            return Err(AttemptError::Binding);
        }
        // No partial next read/producer, extraction or output may be reinterpreted
        // as the preceding head. All complete later phases require their full prefix.
        #[cfg(not(all(test, sumeragi_daemon_mutation = "HC111")))]
        for name in [
            "producer-extraction-intent.norito",
            INTENT_FILES[5],
            "private-aggregate-checkpoint.norito",
            "aggregate-head.norito",
            "input-final-session.norito",
            "proof-final-session.norito",
            "public-session.norito",
            "provider.json",
            GLOBAL_BEACON_PARTIAL_SIGNER_CREDENTIAL_NAME_V1,
            ROTATION_PENDING_SHARE_NAME,
        ] {
            if file_present(directory, name)? {
                return Err(AttemptError::Binding);
            }
        }
        #[cfg(not(all(test, sumeragi_daemon_mutation = "HC105")))]
        let check_prefix = true;
        #[cfg(all(test, sumeragi_daemon_mutation = "HC105"))]
        let check_prefix = phase != 1;
        if check_prefix {
            for index in 0..2 {
                let included = index < usize::from(phase - 1);
                for (name, _) in LATER_FILES[index] {
                    if file_present(directory, name)? != included {
                        return Err(AttemptError::Binding);
                    }
                }
            }
        }
        self.restore_phase = Some(phase);
        // Pin original descriptors before allocation. A pool/backing refusal keeps
        // those same descriptors and validates their extents again on retry.
        for index in 0..usize::from(phase - 1) {
            let bounds = [
                input_bounds[index + 1],
                self.private_source.capacity(),
                input_bounds[index],
                proof_bound,
            ];
            for slot in 0..4 {
                let (name, private) = LATER_FILES[index][slot + 2];
                open_original_file(
                    directory,
                    name,
                    private,
                    bounds[slot],
                    &mut self.later[index].files[slot + 2],
                )?;
            }
        }
        let mut layouts = [Layout::new::<u8>(); 8];
        let mut count = 0;
        for later in self.later.iter().take(usize::from(phase - 1)) {
            for slot in 0..4 {
                if later.bytes[slot].is_none() {
                    let length = usize::try_from(
                        later.files[slot + 2]
                            .identity
                            .as_ref()
                            .ok_or(AttemptError::Phase)?
                            .len(),
                    )
                    .map_err(|_| AttemptError::Binding)?;
                    layouts[count] = Layout::array::<u8>(length)
                        .map_err(|_| AllocationRefusal::DemandOverflow)?;
                    count += 1;
                }
            }
        }
        if count != 0 {
            let mut reservation = self
                .budget
                .try_reserve_layouts(layouts[..count].iter().copied())?;
            for later in self.later.iter_mut().take(usize::from(phase - 1)) {
                for slot in 0..4 {
                    if later.bytes[slot].is_none() {
                        let length = usize::try_from(
                            later.files[slot + 2]
                                .identity
                                .as_ref()
                                .ok_or(AttemptError::Phase)?
                                .len(),
                        )
                        .map_err(|_| AttemptError::Binding)?;
                        later.bytes[slot] =
                            Some(ChargedBuffer::from_reservation(length, &mut reservation)?);
                    }
                }
            }
            if reservation.remaining_bytes() != 0 {
                return Err(AttemptError::Phase);
            }
        }
        Ok(phase)
    }
    #[cfg(test)]
    pub(super) fn load_generation(
        &mut self,
        directory: &Directory,
    ) -> Result<(Intent, Head), AttemptError> {
        self.load_generation_through(directory, 1)
    }
    pub(super) fn load_generation_through(
        &mut self,
        directory: &Directory,
        phase: u16,
    ) -> Result<(Intent, Head), AttemptError> {
        seat_export::revalidate_directory(directory)?;
        if phase != 1 && self.restore_phase != Some(phase) {
            return Err(AttemptError::Binding);
        }
        #[cfg(not(all(test, sumeragi_daemon_mutation = "HC105")))]
        if phase == 1 {
            for name in INTENT_FILES
                .iter()
                .skip(1)
                .chain(HEAD_FILES.iter().skip(1))
                .chain(CHECKPOINT_FILES.iter().skip(1))
                .chain(
                    [
                        "deliveries.norito",
                        "acceptances.norito",
                        "input-commitments.norito",
                        "input-deliveries.norito",
                        "input-final-session.norito",
                        "proof-commitments.norito",
                        "proof-deliveries.norito",
                        "proof-final-session.norito",
                        "public-session.norito",
                        "provider.json",
                        GLOBAL_BEACON_PARTIAL_SIGNER_CREDENTIAL_NAME_V1,
                        ROTATION_PENDING_SHARE_NAME,
                    ]
                    .iter(),
                )
            {
                if file_present(directory, name)? {
                    return Err(AttemptError::Binding);
                }
            }
        }
        read_file(
            directory,
            INTENT_FILES[0],
            true,
            &mut self.read_intent,
            &mut self.loaded[0],
        )?;
        read_file(
            directory,
            HEAD_FILES[0],
            true,
            &mut self.read_head,
            &mut self.loaded[1],
        )?;
        let mut destination = DestinationFor::<Intent> {
            owner: &mut self.destination,
            expiry: self.expiry,
            marker: std::marker::PhantomData,
        };
        self.workspace
            .decode_canonical_into::<Intent, _>(
                self.read_intent.as_slice(),
                norito::canonical_decode_limits(self.read_intent.as_slice().len()),
                &mut destination,
            )
            .map_err(AttemptError::DurableDecode)?;
        let mut destination = DestinationFor::<Head> {
            owner: &mut self.destination,
            expiry: self.expiry,
            marker: std::marker::PhantomData,
        };
        self.workspace
            .decode_canonical_into::<Head, _>(
                self.read_head.as_slice(),
                norito::canonical_decode_limits(self.read_head.as_slice().len()),
                &mut destination,
            )
            .map_err(AttemptError::DurableDecode)?;
        let intent = self.destination.intent.as_slice()[0];
        let head = self.destination.head.as_slice()[0];
        let mut original = head.context;
        original.public_output_hash = [0; 32];
        original.producer_intent_hash = [0; 32];
        if intent.version != 1
            || intent.operation != 1
            || head.version != 1
            || head.context.phase != 1
            || intent.continuation_hash != [0; 32]
            || intent.continuation_source != intent.context.source
            || intent.source_hashes != [[0; 32]; 2]
            || intent.stream_generations != [0; 2]
            || intent.previous_head_hash != [0; 32]
            || head.previous_head_hash != [0; 32]
            || intent.context != original
            || head.context.producer_intent_hash
                != <[u8; 32]>::from(Hash::new(self.read_intent.as_slice()))
            || head.checkpoint_hash == [0; 32]
        {
            return Err(AttemptError::Binding);
        }
        read_file(
            directory,
            "publication.norito",
            false,
            &mut self.public_source,
            &mut self.loaded[2],
        )?;
        read_file(
            directory,
            CHECKPOINT_FILES[0],
            true,
            &mut self.private_source,
            &mut self.loaded[3],
        )?;
        if head.context.public_output_hash
            != <[u8; 32]>::from(Hash::new(self.public_source.as_slice()))
            || head.checkpoint_hash != <[u8; 32]>::from(Hash::new(self.private_source.as_slice()))
        {
            return Err(AttemptError::Binding);
        }
        Ok((intent, head))
    }
    /// Complete the original file and directory durability barriers before claim adoption.
    /// The read owners remain installed across every actual sync refusal.
    pub(super) fn sync_restored_generation(
        &mut self,
        directory: &Directory,
    ) -> Result<(), AttemptError> {
        #[cfg(all(test, sumeragi_daemon_mutation = "HC109"))]
        return Ok(());
        self.sync_restored_generation_with(directory, |file| file.sync_all())
    }
    fn sync_restored_generation_with(
        &mut self,
        directory: &Directory,
        mut sync: impl FnMut(&File) -> std::io::Result<()>,
    ) -> Result<(), AttemptError> {
        // Recheck the complete original sources/names through their same read owners.
        let [intent, head, public, private_checkpoint] = &mut self.loaded;
        for (name, private, bytes, loaded) in [
            (INTENT_FILES[0], true, &mut self.read_intent, intent),
            (
                CHECKPOINT_FILES[0],
                true,
                &mut self.private_source,
                private_checkpoint,
            ),
            ("publication.norito", false, &mut self.public_source, public),
            (HEAD_FILES[0], true, &mut self.read_head, head),
        ] {
            read_file(directory, name, private, bytes, loaded)?;
            if !loaded.synced {
                sync(loaded.descriptor.as_ref().ok_or(AttemptError::Phase)?)
                    .map_err(seat_export::ExportError::Io)?;
                loaded.synced = true;
            }
            read_file(directory, name, private, bytes, loaded)?;
        }
        if !self.restored_directory_synced {
            sync(&directory.file).map_err(seat_export::ExportError::Io)?;
            self.restored_directory_synced = true;
        }
        seat_export::revalidate_directory(directory)?;
        Ok(())
    }
    /// Decode the next immutable intent/head and validate the exact complete
    /// original predecessor, read marker and raw source commitments.
    pub(super) fn load_later(
        &mut self,
        directory: &Directory,
        phase: u16,
    ) -> Result<(Intent, Head), AttemptError> {
        if !(2..=3).contains(&phase) || self.restore_phase.is_none_or(|last| phase > last) {
            return Err(AttemptError::Phase);
        }
        let index = usize::from(phase - 2);
        let previous = self.head_records[index].ok_or(AttemptError::Phase)?;
        let previous_intent = self.intent_records[index].ok_or(AttemptError::Phase)?;
        let (name, private) = LATER_FILES[index][0];
        read_file(
            directory,
            name,
            private,
            &mut self.intents[index + 1],
            &mut self.later[index].files[0],
        )?;
        let (name, private) = LATER_FILES[index][1];
        read_file(
            directory,
            name,
            private,
            &mut self.heads[index + 1],
            &mut self.later[index].files[1],
        )?;
        let marker_index = intent_index(phase + 3)?;
        let (name, private) = LATER_FILES[index][6];
        read_file(
            directory,
            name,
            private,
            &mut self.intents[marker_index],
            &mut self.later[index].files[6],
        )?;
        let expiry = self.expiry;
        let decode_intent = |workspace: &mut PreparedDecodeWorkspace,
                             destination: &mut Destination,
                             bytes: &[u8]| {
            workspace
                .decode_canonical_into::<Intent, _>(
                    bytes,
                    norito::canonical_decode_limits(bytes.len()),
                    &mut DestinationFor::<Intent> {
                        owner: destination,
                        expiry,
                        marker: std::marker::PhantomData,
                    },
                )
                .map_err(AttemptError::DurableDecode)?;
            Ok::<_, AttemptError>(destination.intent.as_slice()[0])
        };
        let intent = decode_intent(
            &mut self.workspace,
            &mut self.destination,
            self.intents[index + 1].as_slice(),
        )?;
        let marker = decode_intent(
            &mut self.workspace,
            &mut self.destination,
            self.intents[marker_index].as_slice(),
        )?;
        self.workspace
            .decode_canonical_into::<Head, _>(
                self.heads[index + 1].as_slice(),
                norito::canonical_decode_limits(self.heads[index + 1].as_slice().len()),
                &mut DestinationFor::<Head> {
                    owner: &mut self.destination,
                    expiry: self.expiry,
                    marker: std::marker::PhantomData,
                },
            )
            .map_err(AttemptError::DurableDecode)?;
        let head = self.destination.head.as_slice()[0];
        let previous_head_hash: [u8; 32] = Hash::new(self.heads[index].as_slice()).into();
        let mut original = head.context;
        original.public_output_hash = [0; 32];
        original.producer_intent_hash = [0; 32];
        let expected_public_generation = u64::from(phase - 2);
        if intent.version != 1
            || intent.operation != phase
            || head.version != 1
            || head.context.phase != phase
            || intent.context != original
            || intent.previous_head_hash != previous_head_hash
            || head.previous_head_hash != previous_head_hash
            || head.context.previous_checkpoint_hash != previous.checkpoint_hash
            || head.context.producer_intent_hash
                != <[u8; 32]>::from(Hash::new(self.intents[index + 1].as_slice()))
            || intent.continuation_hash != [0; 32]
            || intent.continuation_source != intent.context.source
            || intent.expiry != previous_intent.expiry
            || intent.claim_identity != previous_intent.claim_identity
            || intent.claim_path_hash != previous_intent.claim_path_hash
            || intent.fifo_identity != previous_intent.fifo_identity
            || intent.stream_generations[0] != expected_public_generation
            || intent.stream_generations[1] <= previous_intent.stream_generations[1]
            || marker.version != 1
            || marker.operation != phase + 3
            || marker.context != previous.context
            || marker.expiry != previous_intent.expiry
            || marker.claim_identity != previous_intent.claim_identity
            || marker.claim_path_hash != previous_intent.claim_path_hash
            || marker.fifo_identity != previous_intent.fifo_identity
            || marker.previous_head_hash != previous_head_hash
            || marker.continuation_hash != [0; 32]
            || marker.continuation_source != previous.context.source
            || marker.source_hashes != [[0; 32]; 2]
            || marker.stream_generations[0] != expected_public_generation
            || marker.stream_generations[1] != previous_intent.stream_generations[1]
        {
            return Err(AttemptError::Binding);
        }
        for slot in 0..4 {
            let (name, private) = LATER_FILES[index][slot + 2];
            let later = &mut self.later[index];
            read_file(
                directory,
                name,
                private,
                later.bytes[slot].as_mut().ok_or(AttemptError::Phase)?,
                &mut later.files[slot + 2],
            )?;
        }
        let later = &mut self.later[index];
        let hash = |slot: usize| -> Result<[u8; 32], AttemptError> {
            Ok(Hash::new(
                later.bytes[slot]
                    .as_ref()
                    .ok_or(AttemptError::Phase)?
                    .as_slice(),
            )
            .into())
        };
        if head.context.public_output_hash != hash(0)?
            || head.checkpoint_hash != hash(1)?
            || intent.source_hashes != [hash(2)?, hash(3)?]
            || intent.source_hashes.iter().any(|h| *h == [0; 32])
        {
            return Err(AttemptError::Binding);
        }
        if later.record.is_some_and(|old| old != (intent, head)) {
            return Err(AttemptError::Binding);
        }
        later.record = Some((intent, head));
        self.intent_records[marker_index] = Some(marker);
        Ok((intent, head))
    }
    pub(super) fn later_sources(
        &self,
        phase: u16,
    ) -> Result<(&[u8], &[u8], &[u8], &ChargedBuffer<u8>), AttemptError> {
        let index = usize::from(phase.checked_sub(2).ok_or(AttemptError::Phase)?);
        let later = self.later.get(index).ok_or(AttemptError::Phase)?;
        if later.record.is_none() {
            return Err(AttemptError::Phase);
        }
        let source = |slot: usize| {
            later.bytes[slot]
                .as_ref()
                .map(ChargedBuffer::as_slice)
                .ok_or(AttemptError::Phase)
        };
        Ok((
            source(0)?,
            source(1)?,
            source(2)?,
            later.bytes[3].as_ref().ok_or(AttemptError::Phase)?,
        ))
    }
    pub(super) fn sync_restored_later(
        &mut self,
        directory: &Directory,
        phase: u16,
    ) -> Result<(), AttemptError> {
        self.sync_restored_later_with(directory, phase, |file| file.sync_all())
    }
    fn sync_restored_later_with(
        &mut self,
        directory: &Directory,
        phase: u16,
        mut sync: impl FnMut(&File) -> std::io::Result<()>,
    ) -> Result<(), AttemptError> {
        let index = usize::from(phase.checked_sub(2).ok_or(AttemptError::Phase)?);
        let later = self.later.get_mut(index).ok_or(AttemptError::Phase)?;
        if later.record.is_none() {
            return Err(AttemptError::Phase);
        }
        // Read marker and original input/proof precede producer intent, private
        // checkpoint, signed output and complete head, through the same held fds.
        for slot in [6, 4, 5, 0, 3, 2, 1] {
            let (name, private) = LATER_FILES[index][slot];
            let bytes = match slot {
                0 => &mut self.intents[index + 1],
                1 => &mut self.heads[index + 1],
                6 => &mut self.intents[intent_index(phase + 3)?],
                _ => later.bytes[slot - 2].as_mut().ok_or(AttemptError::Phase)?,
            };
            read_file(directory, name, private, bytes, &mut later.files[slot])?;
            if !later.files[slot].synced {
                sync(
                    later.files[slot]
                        .descriptor
                        .as_ref()
                        .ok_or(AttemptError::Phase)?,
                )
                .map_err(seat_export::ExportError::Io)?;
                later.files[slot].synced = true;
            }
            read_file(directory, name, private, bytes, &mut later.files[slot])?;
        }
        sync(&directory.file).map_err(seat_export::ExportError::Io)?;
        seat_export::revalidate_directory(directory)?;
        Ok(())
    }
    /// Install only after Core authenticated the complete original public/private
    /// phase and actual native ancestry, and all original file barriers completed.
    pub(super) fn retain_restored_later(
        &mut self,
        phase: u16,
        intent: Intent,
        head: Head,
    ) -> Result<(), AttemptError> {
        let index = usize::from(phase.checked_sub(1).ok_or(AttemptError::Phase)?);
        if index == 0
            || index >= 3
            || self.later[index - 1].record != Some((intent, head))
            || self.later[index - 1].files.iter().any(|file| !file.synced)
        {
            return Err(AttemptError::Binding);
        }
        if self.intent_records[index].is_some_and(|old| old != intent)
            || self.head_records[index].is_some_and(|old| old != head)
        {
            return Err(AttemptError::Binding);
        }
        self.intent_records[index] = Some(intent);
        self.head_records[index] = Some(head);
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn later_descriptor_ids(
        &self,
        phase: u16,
    ) -> Result<[std::os::fd::RawFd; 4], AttemptError> {
        use std::os::fd::AsRawFd;
        let index = usize::from(phase.checked_sub(2).ok_or(AttemptError::Phase)?);
        let later = self.later.get(index).ok_or(AttemptError::Phase)?;
        let descriptor = |slot: usize| {
            later.files[slot + 2]
                .descriptor
                .as_ref()
                .map(AsRawFd::as_raw_fd)
                .ok_or(AttemptError::Phase)
        };
        Ok([
            descriptor(0)?,
            descriptor(1)?,
            descriptor(2)?,
            descriptor(3)?,
        ])
    }
    #[cfg(test)]
    pub(super) fn later_sources_unadmitted(&self, phase: u16) -> Result<bool, AttemptError> {
        let index = usize::from(phase.checked_sub(2).ok_or(AttemptError::Phase)?);
        Ok(self
            .later
            .get(index)
            .ok_or(AttemptError::Phase)?
            .bytes
            .iter()
            .all(Option::is_none))
    }
    pub(super) fn public_source(&self) -> &[u8] {
        self.public_source.as_slice()
    }
    pub(super) fn private_source(&self) -> &[u8] {
        self.private_source.as_slice()
    }
    /// Called only after Core authenticated the private owners and complete original context.
    pub(super) fn retain_restored_generation(
        &mut self,
        intent: Intent,
        head: Head,
    ) -> Result<(), AttemptError> {
        if self.intent_records[0].is_some() || self.head_records[0].is_some() {
            if self.intent_records[0] == Some(intent) && self.head_records[0] == Some(head) {
                return Ok(());
            }
            return Err(AttemptError::Binding);
        }
        self.intents[0]
            .append(self.read_intent.as_slice())
            .map_err(|_| AttemptError::Phase)?;
        self.heads[0]
            .append(self.read_head.as_slice())
            .map_err(|_| AttemptError::Phase)?;
        self.intent_records[0] = Some(intent);
        self.head_records[0] = Some(head);
        self.expiry = intent.expiry;
        Ok(())
    }
}
pub(super) fn file_present(directory: &Directory, name: &str) -> Result<bool, AttemptError> {
    match rustix::fs::statat(&directory.file, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Ok(_) => Ok(true),
        Err(error) => Err(seat_export::ExportError::Io(error.into()).into()),
    }
}
pub(super) fn open_original_file(
    directory: &Directory,
    name: &'static str,
    private: bool,
    bound: usize,
    loaded: &mut Loaded,
) -> Result<(), AttemptError> {
    seat_export::revalidate_directory(directory)?;
    if loaded.descriptor.is_none() {
        let file = File::from(
            rustix::fs::openat(
                &directory.file,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| seat_export::ExportError::Io(error.into()))?,
        );
        let identity = file.metadata().map_err(seat_export::ExportError::Io)?;
        if !identity.is_file()
            || identity.uid() != rustix::process::geteuid().as_raw()
            || identity.nlink() != 1
            || identity.mode() & 0o7777 != if private { 0o600 } else { 0o644 }
            || identity.len() == 0
            || usize::try_from(identity.len())
                .ok()
                .is_none_or(|size| size > bound)
        {
            return Err(AttemptError::Binding);
        }
        loaded.identity = Some(identity);
        loaded.descriptor = Some(file);
    }
    let original = loaded.identity.as_ref().ok_or(AttemptError::Phase)?;
    let descriptor = loaded.descriptor.as_ref().ok_or(AttemptError::Phase)?;
    if !same_file(
        original,
        &descriptor
            .metadata()
            .map_err(seat_export::ExportError::Io)?,
    ) || usize::try_from(original.len())
        .ok()
        .is_none_or(|size| size > bound)
    {
        return Err(AttemptError::Binding);
    }
    let named = File::from(
        rustix::fs::openat(
            &directory.file,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| seat_export::ExportError::Io(error.into()))?,
    );
    if !same_file(
        original,
        &named.metadata().map_err(seat_export::ExportError::Io)?,
    ) {
        return Err(AttemptError::Binding);
    }
    seat_export::revalidate_directory(directory)?;
    Ok(())
}
pub(super) fn read_file(
    directory: &Directory,
    name: &'static str,
    private: bool,
    bytes: &mut ChargedBuffer<u8>,
    loaded: &mut Loaded,
) -> Result<(), AttemptError> {
    seat_export::revalidate_directory(directory)?;
    if loaded.descriptor.is_none() {
        let file = File::from(
            rustix::fs::openat(
                &directory.file,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|e| {
                if e == rustix::io::Errno::NOENT {
                    AttemptError::Claim(ClaimError::AlreadyClaimed(
                        std::io::ErrorKind::AlreadyExists.into(),
                    ))
                } else {
                    AttemptError::Export(seat_export::ExportError::Io(e.into()))
                }
            })?,
        );
        let identity = file.metadata().map_err(seat_export::ExportError::Io)?;
        if !identity.is_file()
            || identity.uid() != rustix::process::geteuid().as_raw()
            || identity.nlink() != 1
            || identity.mode() & 0o7777 != if private { 0o600 } else { 0o644 }
            || identity.len() == 0
            || usize::try_from(identity.len())
                .ok()
                .is_none_or(|n| n > bytes.capacity())
        {
            return Err(AttemptError::Binding);
        }
        loaded.identity = Some(identity);
        loaded.descriptor = Some(file);
    }
    let file = loaded.descriptor.as_ref().ok_or(AttemptError::Phase)?;
    let identity = loaded.identity.as_ref().ok_or(AttemptError::Phase)?;
    if !same_file(
        identity,
        &file.metadata().map_err(seat_export::ExportError::Io)?,
    ) {
        return Err(AttemptError::Binding);
    }
    let len = usize::try_from(identity.len()).map_err(|_| AttemptError::Binding)?;
    use std::os::unix::fs::FileExt as _;
    let mut scratch = [0u8; 4096];
    let mut offset = 0usize;
    while offset < len {
        let retained = bytes.as_slice().len();
        let boundary = if offset < retained { retained } else { len };
        let n = (boundary - offset).min(scratch.len());
        let read = file
            .read_at(
                &mut scratch[..n],
                u64::try_from(offset).map_err(|_| AttemptError::Binding)?,
            )
            .map_err(seat_export::ExportError::Io)?;
        if read == 0 {
            return Err(AttemptError::Binding);
        }
        if offset < bytes.as_slice().len() {
            if bytes.as_slice().get(offset..offset + read) != Some(&scratch[..read]) {
                return Err(AttemptError::Binding);
            }
        } else {
            bytes
                .append(&scratch[..read])
                .map_err(|_| AttemptError::Phase)?;
        }
        offset += read;
    }
    if bytes.as_slice().len() != len
        || !same_file(
            identity,
            &file.metadata().map_err(seat_export::ExportError::Io)?,
        )
    {
        return Err(AttemptError::Binding);
    }
    let named = File::from(
        rustix::fs::openat(
            &directory.file,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|e| seat_export::ExportError::Io(e.into()))?,
    );
    if !same_file(
        identity,
        &named.metadata().map_err(seat_export::ExportError::Io)?,
    ) {
        return Err(AttemptError::Binding);
    }
    seat_export::revalidate_directory(directory)?;
    Ok(())
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
    fn durable_raw_fields_keep_both_layouts_original_credit_and_generic_source_arrays() {
        for flags in [0, norito::core::header_flags::COMPACT_LEN] {
            let _flags = norito::core::DecodeFlagsGuard::enter(flags);
            let expiry = DurableDeadline {
                boot: hash(0x41),
                origin_nanos: 100,
                expiry_nanos: 200,
            };
            let mut binding = empty_context();
            binding.network_id = hash(0x11);
            binding.attempt_id = hash(0x12);
            binding.session_id = hash(0x13);
            binding.roster_hash = hash(0x14);
            binding.lifecycle_key_hash = hash(0x15);
            binding.provider_handle_hash = hash(0x16);
            binding.public_output_hash = hash(0x17);
            binding.phase_input_hash = hash(0x18);
            binding.producer_intent_hash = hash(0x19);
            binding.previous_checkpoint_hash = hash(0x1a);
            binding.source = DkgCheckpointSourceV1::ExecutedNativeTip {
                height: 9,
                block_hash: hash(0x21),
                core_hash: hash(0x22),
                result_hash: hash(0x23),
            };
            let mut decoded_binding = empty_context();
            check_raw_record::<32, _>(&binding, &[0, 1, 3, 4, 6, 7, 16, 17, 18, 19], 0, |bytes| {
                DkgCheckpointBindingV1::decode_fields(bytes, &mut InlineFor(&mut decoded_binding))
                    .map(|(_, used)| used)
            });
            assert_eq!(decoded_binding, binding);
            let mut decoded_expiry = DurableDeadline {
                boot: [0; 32],
                ..expiry
            };
            check_raw_record::<32, _>(&expiry, &[0], 0, |bytes| {
                DurableDeadline::decode_fields(bytes, &mut InlineFor(&mut decoded_expiry))
                    .map(|(_, used)| used)
            });
            assert_eq!(decoded_expiry, expiry);
            for (source, indices) in [
                (
                    DkgCheckpointSourceV1::SignedGenesisAuthorization {
                        genesis_hash: hash(0x31),
                    },
                    &[0][..],
                ),
                (binding.source, &[1, 2, 3][..]),
            ] {
                check_raw_record::<32, _>(&source, indices, 4, |bytes| {
                    DkgCheckpointSourceV1::decode_fields(bytes, &mut SourceFields).map(
                        |(decoded, used)| {
                            assert_eq!(decoded, source);
                            used
                        },
                    )
                });
            }
            let mut intent = Intent::empty(expiry);
            intent.context = binding;
            intent.claim_identity = [17, 18, 19, 20];
            intent.claim_path_hash = hash(0x51);
            intent.fifo_identity = [21, 22, 23, 24];
            intent.previous_head_hash = hash(0x52);
            intent.continuation_hash = hash(0x53);
            intent.continuation_source = binding.source;
            intent.source_hashes = [hash(0x61), hash(0x71)];
            intent.stream_generations = [25, 26];
            let head = Head {
                version: 1,
                context: binding,
                checkpoint_hash: hash(0x81),
                previous_head_hash: hash(0x91),
            };
            let pool = AllocationBudget::new(1 << 20);
            let mut destination = Destination {
                intent: ChargedBuffer::new(1, &pool).unwrap(),
                head: ChargedBuffer::new(1, &pool).unwrap(),
            };
            destination.intent.push_reserved(Intent::empty(expiry));
            destination.head.push_reserved(Head::empty());
            let pointers = (
                destination.intent.as_slice().as_ptr(),
                destination.head.as_slice().as_ptr(),
            );
            let blocker = pool
                .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
                .unwrap();
            check_raw_record::<32, _>(&intent, &[5, 7, 8], 0, |bytes| {
                Intent::decode_fields(
                    bytes,
                    &mut DestinationFor::<Intent> {
                        owner: &mut destination,
                        expiry,
                        marker: std::marker::PhantomData,
                    },
                )
                .map(|(_, used)| used)
            });
            assert_eq!(destination.intent.as_slice()[0], intent);
            check_raw_record::<32, _>(&head, &[2, 3], 0, |bytes| {
                Head::decode_fields(
                    bytes,
                    &mut DestinationFor::<Head> {
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
