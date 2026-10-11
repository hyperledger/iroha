//! Source-bound original commitment-array, UTF-8/signature leaf and immutable control preparation.

use super::{CanonicalParts, DaCommitmentBundle, DaCommitmentRecord, Storage};
use crate::da::commitment::{DaProofScheme, PreparationPhase};
use crate::inline_fields::DecodedField;
use crate::{
    da::types::{BlobDigest, GovernanceTag, RetentionPolicy, StorageTicketId},
    sorafs::pin_registry::{ManifestDigest, StorageClass},
};
use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, ChargedBuffer,
    ChargedBufferFromChargeError, ChargedShared, ReservedChargedShared, RetainedPayload,
    SharedFromChargeError,
};
use iroha_crypto::{
    BorrowedSignaturePayloadError, ChargedSignature, Hash, PreparedCryptoDecodeError, Signature,
};
use iroha_model_base::topology::LaneId;
use norito::core::{
    CanonicalField, DecodeField, DecodeFromSlice, DecodeIntoError, DecodeRecordFields,
    FieldDestination, SequenceSpan,
};
use std::{alloc::Layout, mem::ManuallyDrop};

/// Original commitment source, canonical cause or actual physical custody refusal.
#[derive(Debug, thiserror::Error)]
pub enum DaCommitmentCustodyError {
    /// The exact source or one original retained owner belongs to another pool.
    #[error("DA commitment source belongs to another original pool")]
    ForeignPool,
    /// Complete original source address, extent, bytes or selected range changed.
    #[error("DA commitment retry changed its complete original source")]
    SourceChanged,
    /// The selected commitment payload is outside initialized original source bytes.
    #[error("DA commitment field is outside its original source")]
    SourceRange,
    /// The canonical parent has not installed its advertised layout.
    #[error("DA commitment preparation requires its original advertised layout")]
    MissingLayout,
    /// An unchanged source was retried under another advertised layout.
    #[error("DA commitment retry changed its original advertised layout")]
    LayoutChanged,
    /// Original canonical or active logical-limit refusal, with enclosing provenance.
    #[error(transparent)]
    Decode(#[from] norito::core::DecodeAttemptError),
    /// Original atomic admission of actual planning or payload/control layouts failed.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// The physical allocator refused one exact original prepaid array or tag.
    #[error(transparent)]
    Buffer(#[from] ChargedBufferFromChargeError),
    /// The physical allocator refused the original prepaid immutable control.
    #[error(transparent)]
    Control(#[from] SharedFromChargeError),
    /// Complete canonical filling has not succeeded for this original source.
    #[error("DA commitment preparation is incomplete")]
    Incomplete,
    /// Original fixed signature-payload or local destination geometry cause.
    #[error(transparent)]
    Signature(PreparedCryptoDecodeError),
}
struct Identity {
    address: usize,
    length: usize,
    hash: Hash,
}
impl Identity {
    fn of(bytes: &[u8]) -> Self {
        Self {
            address: bytes.as_ptr().addr(),
            length: bytes.len(),
            hash: Hash::new(bytes),
        }
    }
    fn matches(&self, bytes: &[u8]) -> bool {
        self.address == bytes.as_ptr().addr()
            && self.length == bytes.len()
            && self.hash == Hash::new(bytes)
    }
}
struct Slot<T> {
    charge: Option<AllocationCharge>,
    value: Option<ChargedBuffer<T>>,
}
impl<T> Default for Slot<T> {
    fn default() -> Self {
        Self {
            charge: None,
            value: None,
        }
    }
}
impl<T> Slot<T> {
    fn allocate(&mut self, count: usize) -> Result<(), DaCommitmentCustodyError> {
        if self.value.is_none() {
            let charge = self
                .charge
                .take()
                .expect("same original prepaid backing charge");
            match ChargedBuffer::try_from_charge(count, charge) {
                Ok(value) => self.value = Some(value),
                Err((charge, error)) => {
                    self.charge = Some(charge);
                    return Err(error.into());
                }
            }
        }
        Ok(())
    }
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.charge
            .as_ref()
            .is_none_or(|owner| owner.belongs_to(budget))
            && self
                .value
                .as_ref()
                .is_none_or(|owner| owner.belongs_to(budget))
    }
}
#[derive(Default)]
struct Row {
    lane: Option<LaneId>,
    epoch: Option<u64>,
    sequence: Option<u64>,
    blob: Option<BlobDigest>,
    manifest: Option<ManifestDigest>,
    scheme: Option<DaProofScheme>,
    chunk_root: Option<Hash>,
    proof_digest: DecodedField<Option<Hash>>,
    hot: Option<u64>,
    cold: Option<u64>,
    replicas: Option<u16>,
    storage_class: Option<StorageClass>,
    ticket: Option<StorageTicketId>,
    tag: Option<SequenceSpan>,
    signature: Option<SequenceSpan>,
    signature_len: Option<usize>,
    buffer: Slot<u8>,
    signature_buffer: Slot<u8>,
}
struct Inline<T>(Option<T>);
impl<T> FieldDestination for Inline<T> {
    type Error = std::convert::Infallible;
}
impl<T: for<'a> DecodeFromSlice<'a>> DecodeField<0, T> for Inline<T> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, T>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        field.with_payload(|bytes| {
            let (value, used) = T::decode_from_slice(bytes)?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            self.0 = Some(value);
            Ok(())
        })
    }
}
fn inline_lane(bytes: &[u8]) -> Result<LaneId, norito::Error> {
    let mut fields = Inline::<u32>(None);
    let (_, used) =
        LaneId::decode_fields(bytes, &mut fields).map_err(DecodeIntoError::into_codec)?;
    if used != bytes.len() {
        return Err(norito::Error::LengthMismatch);
    }
    Ok(LaneId::new(fields.0.ok_or(norito::Error::LengthMismatch)?))
}
fn fixed_tuple<T>(bytes: &[u8]) -> Result<[u8; 32], norito::Error>
where
    T: DecodeRecordFields<Inline<[u8; 32]>, Values = ((),)>,
{
    let mut fields = Inline::<[u8; 32]>(None);
    let (_, used) = T::decode_fields(bytes, &mut fields).map_err(DecodeIntoError::into_codec)?;
    if used != bytes.len() {
        return Err(norito::Error::LengthMismatch);
    }
    fields.0.ok_or(norito::Error::LengthMismatch)
}
struct HeaderPlan<'a> {
    source: &'a [u8],
    version: Option<u16>,
    sequence: Option<SequenceSpan>,
    count: Option<usize>,
}
impl FieldDestination for HeaderPlan<'_> {
    type Error = std::convert::Infallible;
}
impl DecodeField<0, u16> for HeaderPlan<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, u16>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        field.with_payload(|bytes| {
            let (value, used) = u16::decode_from_slice(bytes)?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            self.version = Some(value);
            Ok(())
        })
    }
}
impl DecodeField<1, Vec<DaCommitmentRecord>> for HeaderPlan<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, Vec<DaCommitmentRecord>>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        field.with_payload(|bytes| {
            let (count, used) = norito::core::inspect_element_sequence(bytes)?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            self.sequence = Some(source_span(self.source, bytes)?);
            self.count = Some(count);
            Ok(())
        })
    }
}
fn source_span(source: &[u8], bytes: &[u8]) -> Result<SequenceSpan, norito::Error> {
    let start = bytes
        .as_ptr()
        .addr()
        .checked_sub(source.as_ptr().addr())
        .ok_or(norito::Error::LengthMismatch)?;
    let end = start
        .checked_add(bytes.len())
        .ok_or(norito::Error::LengthMismatch)?;
    let span = SequenceSpan { start, end };
    if span.get(source)? != bytes {
        return Err(norito::Error::LengthMismatch);
    }
    Ok(span)
}
struct RecordFields<'a> {
    row: &'a mut Row,
    source: &'a [u8],
    filling: bool,
}
impl FieldDestination for RecordFields<'_> {
    type Error = DaCommitmentCustodyError;
}
macro_rules! scalar_record_field {
    ($index:literal,$ty:ty,$name:ident) => {
        impl DecodeField<$index, $ty> for RecordFields<'_> {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, $ty>,
            ) -> Result<(), DecodeIntoError<Self::Error>> {
                field.with_payload(|bytes| {
                    let (value, used) = <$ty>::decode_from_slice(bytes)?;
                    if used != bytes.len() {
                        return Err(norito::Error::LengthMismatch.into());
                    }
                    self.row.$name = Some(value);
                    Ok(())
                })
            }
        }
    };
}
impl DecodeField<0, LaneId> for RecordFields<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, LaneId>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        field.with_payload(|bytes| {
            self.row.lane = Some(inline_lane(bytes)?);
            Ok(())
        })
    }
}
scalar_record_field!(1, u64, epoch);
scalar_record_field!(2, u64, sequence);
macro_rules! digest_record_field {
    ($index:literal,$ty:ty,$name:ident) => {
        impl DecodeField<$index, $ty> for RecordFields<'_> {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, $ty>,
            ) -> Result<(), DecodeIntoError<Self::Error>> {
                field.with_payload(|bytes| {
                    self.row.$name = Some(<$ty>::new(fixed_tuple::<$ty>(bytes)?));
                    Ok(())
                })
            }
        }
    };
}
digest_record_field!(3, BlobDigest, blob);
digest_record_field!(4, ManifestDigest, manifest);
scalar_record_field!(5, DaProofScheme, scheme);
scalar_record_field!(6, Hash, chunk_root);
impl DecodeField<7, Option<Hash>> for RecordFields<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, Option<Hash>>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        let value = field.decode_optional(|field| {
            field.with_payload(|bytes| {
                let (value, used) = Hash::decode_from_slice(bytes)?;
                if used != bytes.len() {
                    return Err(norito::Error::LengthMismatch.into());
                }
                Ok(value)
            })
        })?;
        self.row.proof_digest = DecodedField::Decoded(value);
        Ok(())
    }
}
impl DecodeField<8, RetentionPolicy> for RecordFields<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, RetentionPolicy>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        field.with_payload(|bytes| {
            let mut fields = RetentionFields {
                row: self.row,
                source: self.source,
                filling: self.filling,
            };
            let (_, used) = RetentionPolicy::decode_fields(bytes, &mut fields)?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            Ok(())
        })
    }
}
digest_record_field!(9, StorageTicketId, ticket);
fn signature_failure(
    error: BorrowedSignaturePayloadError,
) -> DecodeIntoError<DaCommitmentCustodyError> {
    match error {
        BorrowedSignaturePayloadError::Decode(PreparedCryptoDecodeError::Codec(error)) => {
            DecodeIntoError::Codec(error)
        }
        BorrowedSignaturePayloadError::Decode(error) => {
            DecodeIntoError::Destination(DaCommitmentCustodyError::Signature(error))
        }
        BorrowedSignaturePayloadError::LayoutChanged { .. } => {
            DecodeIntoError::Destination(DaCommitmentCustodyError::LayoutChanged)
        }
    }
}
impl DecodeField<10, Signature> for RecordFields<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, Signature>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        field.with_payload(|bytes| {
            let original = Signature::borrow_canonical_payload(bytes).map_err(signature_failure)?;
            let span = source_span(self.source, bytes)?;
            if self.filling {
                if self.row.signature != Some(span)
                    || self.row.signature_len != Some(original.len())
                {
                    return Err(norito::Error::LengthMismatch.into());
                }
                let buffer = self
                    .row
                    .signature_buffer
                    .value
                    .as_mut()
                    .ok_or(norito::Error::LengthMismatch)?;
                original
                    .fill_into(buffer.as_mut_slice())
                    .map_err(signature_failure)?;
            } else {
                self.row.signature = Some(span);
                self.row.signature_len = Some(original.len());
            }
            Ok(())
        })
    }
}
struct RetentionFields<'a> {
    row: &'a mut Row,
    source: &'a [u8],
    filling: bool,
}
impl FieldDestination for RetentionFields<'_> {
    type Error = DaCommitmentCustodyError;
}
macro_rules! scalar_retention_field {
    ($index:literal,$ty:ty,$name:ident) => {
        impl DecodeField<$index, $ty> for RetentionFields<'_> {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, $ty>,
            ) -> Result<(), DecodeIntoError<Self::Error>> {
                field.with_payload(|bytes| {
                    let (value, used) = <$ty>::decode_from_slice(bytes)?;
                    if used != bytes.len() {
                        return Err(norito::Error::LengthMismatch.into());
                    }
                    self.row.$name = Some(value);
                    Ok(())
                })
            }
        }
    };
}
scalar_retention_field!(0, u64, hot);
scalar_retention_field!(1, u64, cold);
scalar_retention_field!(2, u16, replicas);
scalar_retention_field!(3, StorageClass, storage_class);
impl DecodeField<4, GovernanceTag> for RetentionFields<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, GovernanceTag>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        field.with_payload(|bytes| {
            let mut fields = TagFields {
                row: self.row,
                source: self.source,
                filling: self.filling,
            };
            let (_, used) = GovernanceTag::decode_fields(bytes, &mut fields)?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            Ok(())
        })
    }
}
struct TagFields<'a> {
    row: &'a mut Row,
    source: &'a [u8],
    filling: bool,
}
impl FieldDestination for TagFields<'_> {
    type Error = DaCommitmentCustodyError;
}
impl DecodeField<0, String> for TagFields<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, String>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        field.with_payload(|bytes| {
            let (tag, used) = norito::core::borrow_canonical_string(bytes)?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            let span = source_span(self.source, tag.as_bytes())?;
            if self.filling {
                if self.row.tag != Some(span) {
                    return Err(norito::Error::LengthMismatch.into());
                }
                let buffer = self
                    .row
                    .buffer
                    .value
                    .as_mut()
                    .ok_or(norito::Error::LengthMismatch)?;
                buffer.as_mut_slice().copy_from_slice(tag.as_bytes());
            } else {
                self.row.tag = Some(span);
            }
            Ok(())
        })
    }
}

/// One move-only original source plan retaining all partially allocated children.
///
/// The canonical parent installs the advertised flags and checks its entire frame.
/// This owner prepares the complete two-field commitment bundle and all original record/retention leaves, never other DA,
/// transaction, result or native finality graphs. No input is consumed or secret
/// work repeated by construction, refusal, filling or unchanged-source retry.
pub struct PreparedDaCommitmentBundle {
    source: Identity,
    sequence: SequenceSpan,
    flags: u8,
    count: usize,
    version: u16,
    rows: Slot<Row>,
    spans: Slot<SequenceSpan>,
    values: Slot<DaCommitmentRecord>,
    ledger: Slot<AllocationCharge>,
    shell_charge: Option<AllocationCharge>,
    shell: Option<ReservedChargedShared<RetainedPayload<CanonicalParts>>>,
    phase: PreparationPhase,
    budget: AllocationBudget,
}
impl PreparedDaCommitmentBundle {
    /// Borrow the unchanged source and inspect only complete canonical record/element framing.
    /// No physical destination or commitment value is allocated by this constructor.
    ///
    /// # Errors
    /// Returns exact original source/layout/canonical/logical-limit causes.
    pub fn from_source(
        input: &ChargedBuffer<u8>,
        span: SequenceSpan,
        budget: &AllocationBudget,
    ) -> Result<Self, DaCommitmentCustodyError> {
        if !input.belongs_to(budget) {
            return Err(DaCommitmentCustodyError::ForeignPool);
        }
        let flags = norito::core::effective_decode_flags()
            .ok_or(DaCommitmentCustodyError::MissingLayout)?;
        let bytes = span
            .get(input.as_slice())
            .map_err(|_| DaCommitmentCustodyError::SourceRange)?;
        let (version, sequence, count) = norito::core::classify_decode_attempt(|| {
            let mut fields = HeaderPlan {
                source: input.as_slice(),
                version: None,
                sequence: None,
                count: None,
            };
            let (_, used) = DaCommitmentBundle::decode_fields(bytes, &mut fields)
                .map_err(DecodeIntoError::into_codec)?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch);
            }
            Ok((
                fields.version.ok_or(norito::Error::LengthMismatch)?,
                fields.sequence.ok_or(norito::Error::LengthMismatch)?,
                fields.count.ok_or(norito::Error::LengthMismatch)?,
            ))
        })?;
        Ok(Self {
            source: Identity::of(input.as_slice()),
            sequence,
            flags,
            count,
            version,
            rows: Slot::default(),
            spans: Slot::default(),
            values: Slot::default(),
            ledger: Slot::default(),
            shell_charge: None,
            shell: None,
            phase: PreparationPhase::Unadmitted,
            budget: budget.clone(),
        })
    }
    fn check(&self, input: &ChargedBuffer<u8>) -> Result<(), DaCommitmentCustodyError> {
        if !input.belongs_to(&self.budget) {
            return Err(DaCommitmentCustodyError::ForeignPool);
        }
        if !self.source.matches(input.as_slice()) {
            return Err(DaCommitmentCustodyError::SourceChanged);
        }
        let flags = norito::core::effective_decode_flags()
            .ok_or(DaCommitmentCustodyError::MissingLayout)?;
        if flags != self.flags {
            return Err(DaCommitmentCustodyError::LayoutChanged);
        }
        Ok(())
    }
    /// Whether every original partial backing, pending charge and control uses this pool.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.budget.same_pool(budget)
            && self.rows.belongs_to(budget)
            && self.spans.belongs_to(budget)
            && self.values.belongs_to(budget)
            && self.ledger.belongs_to(budget)
            && self
                .shell_charge
                .as_ref()
                .is_none_or(|owner| owner.belongs_to(budget))
            && self
                .shell
                .as_ref()
                .is_none_or(|owner| owner.belongs_to(budget))
            && self.rows.value.as_ref().is_none_or(|rows| {
                rows.as_slice().iter().all(|row| {
                    row.buffer.belongs_to(budget) && row.signature_buffer.belongs_to(budget)
                })
            })
    }
    /// Actual planning-array layouts, derived from the original checked count.
    ///
    /// # Errors
    /// Returns layout overflow before admitting or allocating any metadata array.
    pub fn planning_layouts(&self) -> Result<[Layout; 2], AllocationRefusal> {
        Ok([
            Layout::array::<Row>(self.count).map_err(|_| AllocationRefusal::DemandOverflow)?,
            Layout::array::<SequenceSpan>(self.count)
                .map_err(|_| AllocationRefusal::DemandOverflow)?,
        ])
    }
    /// Exact commitment-array, ledger and immutable-control layouts, excluding planning
    /// scaffolding and the separately charged original tag/signature bodies.
    ///
    /// # Errors
    /// Returns checked count/layout overflow without allocation or admission.
    pub fn payload_layouts(&self) -> Result<[Layout; 3], AllocationRefusal> {
        let ledger_count = self
            .count
            .checked_mul(2)
            .and_then(|count| count.checked_add(1))
            .ok_or(AllocationRefusal::DemandOverflow)?;
        Ok([
            Layout::array::<DaCommitmentRecord>(self.count)
                .map_err(|_| AllocationRefusal::DemandOverflow)?,
            Layout::array::<AllocationCharge>(ledger_count)
                .map_err(|_| AllocationRefusal::DemandOverflow)?,
            DaCommitmentBundle::allocation_layout(),
        ])
    }
    /// Borrow one initialized original tag backing without moving its custody.
    /// Partial refusals retain every previously allocated sibling and pending charge.
    ///
    /// # Errors
    /// Rejects a changed original source/layout or an out-of-range original row.
    pub fn initialized_tag<'a>(
        &'a self,
        input: &ChargedBuffer<u8>,
        index: usize,
    ) -> Result<Option<&'a [u8]>, DaCommitmentCustodyError> {
        self.check(input)?;
        if index >= self.count {
            return Err(DaCommitmentCustodyError::SourceRange);
        }
        Ok(self
            .rows
            .value
            .as_ref()
            .and_then(|rows| rows.as_slice().get(index))
            .and_then(|row| row.buffer.value.as_ref())
            .map(ChargedBuffer::as_slice))
    }
    /// Borrow the initialized original signature backing without moving its custody.
    /// # Errors
    /// Rejects any changed source/layout or out-of-range original row.
    pub fn initialized_signature<'a>(
        &'a self,
        input: &ChargedBuffer<u8>,
        index: usize,
    ) -> Result<Option<&'a [u8]>, DaCommitmentCustodyError> {
        self.check(input)?;
        if index >= self.count {
            return Err(DaCommitmentCustodyError::SourceRange);
        }
        Ok(self
            .rows
            .value
            .as_ref()
            .and_then(|rows| rows.as_slice().get(index))
            .and_then(|row| row.signature_buffer.value.as_ref())
            .map(ChargedBuffer::as_slice))
    }
    fn walk_rows(
        &mut self,
        input: &ChargedBuffer<u8>,
        filling: bool,
    ) -> Result<(), DaCommitmentCustodyError> {
        let bytes = self
            .sequence
            .get(input.as_slice())
            .map_err(|_| DaCommitmentCustodyError::SourceRange)?;
        let spans = self
            .spans
            .value
            .as_mut()
            .expect("original span planning allocation")
            .as_mut_slice();
        let rows = self
            .rows
            .value
            .as_mut()
            .expect("original row planning allocation")
            .as_mut_slice();
        let mut destination_error = None;
        norito::core::classify_decode_attempt(|| {
            let sequence = norito::core::prepare_element_sequence(bytes, spans).map_err(
                |error| match error {
                    norito::core::SequenceDestinationError::Codec(error) => error,
                    norito::core::SequenceDestinationError::Storage { .. } => {
                        norito::Error::LengthMismatch
                    }
                },
            )?;
            if sequence.used() != bytes.len() {
                return Err(norito::Error::LengthMismatch);
            }
            if sequence.len() != rows.len() {
                return Err(norito::Error::LengthMismatch);
            }
            let result = sequence.decode_elements::<DaCommitmentRecord, DaCommitmentCustodyError>(
                |index, field| {
                    field.with_payload(|bytes| {
                        let mut fields = RecordFields {
                            row: &mut rows[index],
                            source: input.as_slice(),
                            filling,
                        };
                        let (_, used) = DaCommitmentRecord::decode_fields(bytes, &mut fields)?;
                        if used != bytes.len() {
                            return Err(norito::Error::LengthMismatch.into());
                        }
                        Ok(())
                    })
                },
            );
            match result {
                Ok(()) => Ok(()),
                Err(DecodeIntoError::Codec(error)) => Err(error),
                Err(DecodeIntoError::Destination(error)) => {
                    destination_error = Some(error);
                    Ok(())
                }
            }
        })?;
        if let Some(error) = destination_error {
            return Err(error);
        }
        Ok(())
    }
    /// Preadmit actual planning and child layouts, retain physical refusals, then fill originals.
    /// All physical arrays/UTF-8/signature leaves/control exist before any exposed commitment value.
    ///
    /// # Errors
    /// Retains every allocated sibling and original pending charge through exact refusal/retry.
    pub fn prepare(&mut self, input: &ChargedBuffer<u8>) -> Result<(), DaCommitmentCustodyError> {
        self.check(input)?;
        if self.phase == PreparationPhase::Ready {
            return Ok(());
        }
        if self.phase < PreparationPhase::MetadataAdmitted {
            let layouts = self.planning_layouts()?;
            let mut reservation = self.budget.try_reserve_layouts(layouts)?;
            self.rows.charge = Some(
                reservation
                    .try_split(layouts[0])
                    .expect("exact admitted row layout"),
            );
            self.spans.charge = Some(
                reservation
                    .try_split(layouts[1])
                    .expect("exact admitted span layout"),
            );
            self.phase = PreparationPhase::MetadataAdmitted;
        }
        self.rows.allocate(self.count)?;
        self.spans.allocate(self.count)?;
        let rows = self.rows.value.as_mut().expect("original rows");
        while rows.as_slice().len() < self.count {
            rows.push_reserved(Row::default());
        }
        let spans = self.spans.value.as_mut().expect("original spans");
        while spans.as_slice().len() < self.count {
            spans.push_reserved(SequenceSpan { start: 0, end: 0 });
        }
        if self.phase < PreparationPhase::Planned {
            self.walk_rows(input, false)?;
            self.phase = PreparationPhase::Planned;
        }
        if self.phase < PreparationPhase::PayloadAdmitted {
            let layouts = self.payload_layouts()?;
            let rows = self
                .rows
                .value
                .as_mut()
                .expect("complete original plans")
                .as_mut_slice();
            let mut total = layouts.iter().try_fold(0_usize, |sum, layout| {
                sum.checked_add(layout.size())
                    .ok_or(AllocationRefusal::DemandOverflow)
            })?;
            for row in rows.iter() {
                total = total
                    .checked_add(
                        Layout::array::<u8>(row.tag.expect("complete tag plan").len())
                            .map_err(|_| AllocationRefusal::DemandOverflow)?
                            .size(),
                    )
                    .ok_or(AllocationRefusal::DemandOverflow)?;
                total = total
                    .checked_add(
                        Layout::array::<u8>(
                            row.signature_len.expect("complete original signature plan"),
                        )
                        .map_err(|_| AllocationRefusal::DemandOverflow)?
                        .size(),
                    )
                    .ok_or(AllocationRefusal::DemandOverflow)?;
            }
            let mut reservation = self.budget.try_reserve_bytes(total)?;
            self.values.charge = Some(
                reservation
                    .try_split(layouts[0])
                    .expect("exact original commitment array"),
            );
            self.ledger.charge = Some(
                reservation
                    .try_split(layouts[1])
                    .expect("exact original complete ledger"),
            );
            self.shell_charge = Some(
                reservation
                    .try_split(layouts[2])
                    .expect("exact original immutable control"),
            );
            for row in rows.iter_mut() {
                row.buffer.charge = Some(
                    reservation
                        .try_split(
                            Layout::array::<u8>(row.tag.expect("complete tag plan").len())
                                .expect("checked exact tag layout"),
                        )
                        .expect("exact original tag charge"),
                );
                row.signature_buffer.charge = Some(
                    reservation
                        .try_split(
                            Layout::array::<u8>(
                                row.signature_len.expect("complete original signature plan"),
                            )
                            .expect("checked original signature layout"),
                        )
                        .expect("exact original signature charge"),
                );
            }
            self.phase = PreparationPhase::PayloadAdmitted;
        }
        self.values.allocate(self.count)?;
        self.ledger.allocate(
            self.count
                .checked_mul(2)
                .and_then(|count| count.checked_add(1))
                .ok_or(AllocationRefusal::DemandOverflow)?,
        )?;
        for row in self
            .rows
            .value
            .as_mut()
            .expect("complete original plans")
            .as_mut_slice()
        {
            row.buffer
                .allocate(row.tag.expect("complete tag plan").len())?;
            row.signature_buffer
                .allocate(row.signature_len.expect("complete signature plan"))?;
        }
        if self.shell.is_none() {
            let charge = self
                .shell_charge
                .take()
                .expect("same original control charge");
            match ChargedShared::reserve_from_charge(charge) {
                Ok(shell) => self.shell = Some(shell),
                Err((charge, error)) => {
                    self.shell_charge = Some(charge);
                    return Err(error.into());
                }
            }
        }
        for row in self
            .rows
            .value
            .as_mut()
            .expect("complete original rows")
            .as_mut_slice()
        {
            let buffer = row
                .buffer
                .value
                .as_mut()
                .expect("every original tag exists");
            while buffer.as_slice().len() < buffer.capacity() {
                buffer.push_reserved(0);
            }
            let signature = row
                .signature_buffer
                .value
                .as_mut()
                .expect("every original signature exists");
            while signature.as_slice().len() < signature.capacity() {
                signature.push_reserved(0);
            }
        }
        self.walk_rows(input, true)?;
        self.phase = PreparationPhase::Ready;
        Ok(())
    }
    /// Move the identical complete original array, UTF-8/signature allocations and ledger into its shell.
    /// Planning scaffolding retires only after the immutable physical owner takes every child.
    ///
    /// # Errors
    /// Returns the exact original prepared owner for changed source/layout or incomplete fill.
    #[expect(
        clippy::result_large_err,
        reason = "returns every original child/charge without allocation"
    )]
    #[allow(unsafe_code)]
    pub fn finish(
        mut self,
        input: &ChargedBuffer<u8>,
    ) -> Result<DaCommitmentBundle, (Self, DaCommitmentCustodyError)> {
        if let Err(error) = self.check(input) {
            return Err((self, error));
        }
        if self.phase != PreparationPhase::Ready || self.shell.is_none() {
            return Err((self, DaCommitmentCustodyError::Incomplete));
        }
        // All required fields are checked before moving an allocation or its charge.
        // A partial decode can never create an exposed commitment or enter this assembly.
        if self
            .rows
            .value
            .as_ref()
            .expect("complete original rows")
            .as_slice()
            .iter()
            .any(|row| {
                row.lane.is_none()
                    || row.epoch.is_none()
                    || row.sequence.is_none()
                    || row.blob.is_none()
                    || row.manifest.is_none()
                    || row.scheme.is_none()
                    || row.chunk_root.is_none()
                    || row.proof_digest.is_missing()
                    || row.hot.is_none()
                    || row.cold.is_none()
                    || row.replicas.is_none()
                    || row.storage_class.is_none()
                    || row.ticket.is_none()
                    || row.tag.is_none()
                    || row.signature.is_none()
                    || row.signature_len.is_none()
                    || row.buffer.value.is_none()
                    || row.signature_buffer.value.as_ref().is_none_or(|buffer| {
                        !buffer.belongs_to(&self.budget)
                            || buffer.as_slice().len() != buffer.capacity()
                            || Some(buffer.capacity()) != row.signature_len
                    })
            })
        {
            return Err((self, DaCommitmentCustodyError::Incomplete));
        }
        let values = self
            .values
            .value
            .take()
            .expect("complete original commitment array");
        let mut ledger = self
            .ledger
            .value
            .take()
            .expect("complete original charge ledger");
        // SAFETY: the empty original commitment array keeps its exact capacity. Its
        // original charge moves immediately to the preallocated ledger; the
        // assembly guard destroys every initialized commitment before refunding it.
        let (commitments, charge) = unsafe { values.into_allocation_parts() };
        ledger.push_reserved(charge);
        let mut assembly = Assembly {
            parts: ManuallyDrop::new(CanonicalParts {
                version: self.version,
                commitments,
            }),
            ledger: ManuallyDrop::new(ledger),
        };
        for row in self
            .rows
            .value
            .as_mut()
            .expect("complete original rows")
            .as_mut_slice()
        {
            let tag = row
                .buffer
                .value
                .take()
                .expect("complete original UTF-8 tag");
            // SAFETY: validated UTF-8 bytes move unchanged into String without growth,
            // cloning or fallible work. The exact charge moves immediately into the
            // original ledger, which remains retained through any assembly unwind.
            let (bytes, charge) = unsafe { tag.into_allocation_parts() };
            assembly.ledger.push_reserved(charge);
            let tag = unsafe { String::from_utf8_unchecked(bytes) };
            assert!(
                assembly.parts.commitments.len() < assembly.parts.commitments.capacity(),
                "exact original commitment capacity"
            );
            let original_signature = row
                .signature_buffer
                .value
                .take()
                .expect("checked complete original signature");
            let original_signature =
                ChargedSignature::try_from_preallocated(&self.budget, original_signature)
                    .unwrap_or_else(|(_, error)| {
                        panic!("checked original signature ownership: {error}")
                    });
            // SAFETY: the immutable record retains the unchanged original payload;
            // its exact original charge immediately joins the preallocated ledger.
            let (signature, charge) = unsafe { original_signature.into_allocation_parts() };
            assembly.ledger.push_reserved(charge);
            assembly.parts.commitments.push(DaCommitmentRecord {
                lane_id: row.lane.expect("checked lane"),
                epoch: row.epoch.expect("checked epoch"),
                sequence: row.sequence.expect("checked sequence"),
                client_blob_id: row.blob.expect("checked blob"),
                manifest_hash: row.manifest.expect("checked manifest"),
                proof_scheme: row.scheme.expect("checked scheme"),
                chunk_root: row.chunk_root.expect("checked root"),
                proof_digest: row
                    .proof_digest
                    .into_value()
                    .expect("checked optional digest"),
                retention_class: RetentionPolicy {
                    hot_retention_secs: row.hot.expect("checked hot"),
                    cold_retention_secs: row.cold.expect("checked cold"),
                    required_replicas: row.replicas.expect("checked replicas"),
                    storage_class: row.storage_class.expect("checked class"),
                    governance_tag: GovernanceTag(tag),
                },
                storage_ticket: row.ticket.expect("checked ticket"),
                acknowledgement_sig: signature,
            });
            #[cfg(test)]
            if ASSEMBLY_PANIC_AFTER
                .with(|point| point.get() == Some(assembly.parts.commitments.len()))
            {
                panic!("injected original commitment assembly interruption");
            }
        }
        let retained = assembly.retain(&self.budget);
        let owner = self
            .shell
            .take()
            .expect("original immutable shell")
            .initialize(retained);
        Ok(DaCommitmentBundle {
            storage: Storage::Admitted(owner),
        })
    }
}

// Local assembly owns the same array and every transferred tag before a shared
// reader exists. Payload destruction precedes ledger refunds even if unwinding
// interrupts transfer or destruction. No caller can mutate or extract this guard.
struct Assembly {
    parts: ManuallyDrop<CanonicalParts>,
    ledger: ManuallyDrop<ChargedBuffer<AllocationCharge>>,
}
impl Assembly {
    #[allow(unsafe_code)]
    fn retain(self, budget: &AllocationBudget) -> RetainedPayload<CanonicalParts> {
        let mut original = ManuallyDrop::new(self);
        // SAFETY: all exact original children have moved into private CanonicalParts;
        // the one original ledger is transferred with them. No fallible allocation,
        // callback or commitment mutation occurs in this ownership movement.
        let parts = unsafe { ManuallyDrop::take(&mut original.parts) };
        let ledger = unsafe { ManuallyDrop::take(&mut original.ledger) };
        // SAFETY: the commitment array plus every String have exact original charges,
        // including zero layouts, and remain behind borrowing-only immutable storage.
        match unsafe { RetainedPayload::try_new(parts, ledger, budget) } {
            Ok(retained) => retained,
            Err((parts, ledger, _)) => {
                // Preserve allocation-before-charge destruction even on an internal
                // pool-invariant violation; a malformed source cannot reach this path.
                drop(Self {
                    parts: ManuallyDrop::new(parts),
                    ledger: ManuallyDrop::new(ledger),
                });
                unreachable!("all original charges retain one verified pool")
            }
        }
    }
}
impl Drop for Assembly {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: original tags and array cannot escape. If destruction unwinds,
        // the ManuallyDrop ledger stays retained instead of granting fictitious credit.
        unsafe { ManuallyDrop::drop(&mut self.parts) };
        // SAFETY: all original payload allocations have been destroyed above.
        unsafe { ManuallyDrop::drop(&mut self.ledger) };
    }
}

#[cfg(test)]
thread_local! { static ASSEMBLY_PANIC_AFTER: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) }; }
#[cfg(test)]
mod tests;
