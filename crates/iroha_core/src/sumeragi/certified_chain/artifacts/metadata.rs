//! Exact original-pool ownership for canonical certificate header and quorum metadata.
//!
//! This is the sole decoder of a stored certificate's header and `CommitQC` frames. Prefix
//! reads take funded immutable owners; the native body reader takes ordinary owners from the
//! same frame, bound, leaf and exact canonical checks, so every reader returns one verdict.
//!
//! Structural decoding grants no authority. The original certificate verifier still checks
//! source, exact quorum, signature and availability relations over these immutable values.
//!
//! A bounded, noncharging shape plan sizes exact backing. The sole authoritative
//! traversal is the generated canonical record walk, including its original root
//! depth and scope. Invalid shape plans allocate no payload graph and still enter
//! that traversal, so a tight root ceiling keeps ordinary decoder precedence.

use std::{alloc::Layout, ops::Deref};

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, AllocationReservation, ChargedBuffer,
    ChargedBufferError, ChargedShared, PrepaidBufferError, RetainedPayload,
};
use iroha_sumeragi::{
    message::{BlockHeader, ByteAdmissionError, MAX_BITMAP_BYTES, Qc, VoteKind},
    types::{
        AggregateSignature, Bitmap, ControlWitness, EpochId, Hash32, MAX_COMMITTEE_SIZE,
        MAX_PUBLIC_KEY_LEN, PublicKey,
    },
};
use norito::core as ncore;

mod destination;

use crate::sumeragi::{
    block_store::certificate_read::CertificateReadError, durable_qc_codec::MAX_QC_METADATA_BYTES,
    durable_record_codec::MAX_HEADER_METADATA_BYTES,
};

// Observe the existing single decode traversal while its enclosing counter owner is live.
// Preserve typed destination/pool failures unchanged. Keep both terminal classification and
// original enclosing-budget refusal ownership across scope retirement. Only raw public
// allocator reports retain their existing mapping; they authenticate no physical cause.
fn capture_decode<T>(
    decode: impl FnOnce() -> Result<T, CertificateReadError>,
) -> Result<T, CertificateReadError> {
    match ncore::classify_decode_attempt(|| match decode() {
        Err(CertificateReadError::Decode(error)) => Err(error),
        result => Ok(result),
    }) {
        Ok(result) => result,
        Err(original) => Err(captured(original)),
    }
}

/// Immutable canonical metadata and every original backing, ledger and sharing control.
pub(in crate::sumeragi) struct FundedMetadata<T>(ChargedShared<RetainedPayload<T>>);

impl<T> Clone for FundedMetadata<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Deref for FundedMetadata<T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.0.get()
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for FundedMetadata<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.deref().fmt(formatter)
    }
}

impl<T> FundedMetadata<T> {
    /// Check both the sharing control and every retained payload charge by pool identity.
    pub(in crate::sumeragi) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.0.belongs_to(budget) && self.0.deref().belongs_to(budget)
    }

    /// Whether both handles share exactly this original immutable graph.
    pub(in crate::sumeragi) fn same_owner(&self, other: &Self) -> bool {
        ChargedShared::ptr_eq(&self.0, &other.0)
    }

    #[cfg(test)]
    /// Exact live backing, ownership ledger and sharing-control bytes retained by this graph.
    pub(in crate::sumeragi::certified_chain) fn allocation_bytes(&self) -> usize {
        self.0.allocation_bytes().expect("checked original layouts")
            + ChargedShared::<RetainedPayload<T>>::allocation_layout().size()
    }
}

fn captured(original: ncore::DecodeAttemptError) -> CertificateReadError {
    if matches!(original.error(), norito::Error::AllocationFailed { .. }) {
        return CertificateReadError::Decode(original.into_error());
    }
    if original.kind() == ncore::DecodeAttemptErrorKind::EnclosingLimit
        && cfg!(all(test, sumeragi_core_mutation = "HC967"))
    {
        return CertificateReadError::Decode(original.into_error());
    }
    CertificateReadError::Canonical(original)
}

fn frame_bound(raw: &[u8], cap: usize) -> Result<(), CertificateReadError> {
    if raw.len() > cap + ncore::Header::SIZE {
        return Err(CertificateReadError::Decode(
            norito::Error::FieldLengthExceeded {
                length: raw.len() as u64,
                limit: (cap + ncore::Header::SIZE) as u64,
            },
        ));
    }
    Ok(())
}

// No ambient resource check, accounting, value decoding or allocation belongs in
// this sizing plan. Intrinsic frame bounds precede it; all input extents are checked.
struct Frame<'a, const N: usize> {
    payload: &'a [u8],
    fields: [std::ops::Range<usize>; N],
    flags: u8,
}
impl<'a, const N: usize> Frame<'a, N> {
    fn parse<T: norito::NoritoSchema>(raw: &'a [u8]) -> Result<Self, norito::Error> {
        let view = ncore::from_bytes_view(raw)?;
        if view.schema() != norito::schema::identity::frame_hash::<T>() {
            return Err(norito::Error::SchemaMismatch);
        }
        let payload = view.as_bytes();
        let mut offset = 0;
        let mut fields = std::array::from_fn(|_| 0..0);
        for field in &mut fields {
            *field = shape_field(payload, &mut offset, view.flags())?;
        }
        if offset != payload.len() {
            return Err(norito::Error::LengthMismatch);
        }
        Ok(Self {
            payload,
            fields,
            flags: view.flags(),
        })
    }
    fn field(&self, index: usize) -> &'a [u8] {
        &self.payload[self.fields[index].clone()]
    }
}
fn shape_field(
    bytes: &[u8],
    offset: &mut usize,
    flags: u8,
) -> Result<std::ops::Range<usize>, norito::Error> {
    let tail = bytes.get(*offset..).ok_or(norito::Error::LengthMismatch)?;
    let (length, prefix) = ncore::inspect_raw_len_from_slice_with_flags(tail, flags)?;
    let start = offset
        .checked_add(prefix)
        .ok_or(norito::Error::LengthMismatch)?;
    let end = start
        .checked_add(length)
        .ok_or(norito::Error::LengthMismatch)?;
    bytes.get(start..end).ok_or(norito::Error::LengthMismatch)?;
    *offset = end;
    Ok(start..end)
}
// Intrinsic SCCP bounds are terminal before resource scopes in every reader.
// Malformed/truncated geometry must instead reach the ordinary canonical root.
#[derive(Debug)]
enum ShapeError {
    Malformed(norito::Error),
    Intrinsic,
}
impl From<norito::Error> for ShapeError {
    fn from(error: norito::Error) -> Self {
        Self::Malformed(error)
    }
}
fn shape_bytes(bytes: &[u8], flags: u8, min: usize, max: usize) -> Result<&[u8], ShapeError> {
    let mut offset = 0;
    let range = shape_field(bytes, &mut offset, flags)?;
    if offset != bytes.len() {
        return Err(norito::Error::LengthMismatch.into());
    }
    let field = &bytes[range];
    let (count, start) = ncore::inspect_raw_seq_len_slice(field)?;
    if count != field.len().saturating_sub(start) {
        return Err(norito::Error::LengthMismatch.into());
    }
    if !(min..=max).contains(&count) {
        return Err(ShapeError::Intrinsic);
    }
    Ok(&field[start..])
}
struct HeaderPlan {
    count: usize,
    backing: usize,
}
impl HeaderPlan {
    fn new(raw: &[u8]) -> Result<Self, ShapeError> {
        let frame = Frame::<12>::parse::<BlockHeader>(raw)?;
        let keys = frame.field(10);
        let (count, mut offset) = ncore::inspect_raw_seq_len_slice(keys)?;
        // An impossible count is malformed before it can be called an intrinsic
        // committee overflow. Every element needs at least one framing byte.
        if count > keys.len().saturating_sub(offset) {
            return Err(norito::Error::LengthMismatch.into());
        }
        if count > MAX_COMMITTEE_SIZE {
            return Err(ShapeError::Intrinsic);
        }
        let mut backing = Layout::array::<PublicKey>(count)
            .map_err(|_| norito::Error::LengthMismatch)?
            .size();
        for _ in 0..count {
            let range = shape_field(keys, &mut offset, frame.flags)?;
            let bytes = shape_bytes(&keys[range], frame.flags, 1, MAX_PUBLIC_KEY_LEN)?;
            backing = backing
                .checked_add(bytes.len())
                .ok_or(norito::Error::LengthMismatch)?;
        }
        if offset != keys.len() {
            return Err(norito::Error::LengthMismatch.into());
        }
        Ok(Self { count, backing })
    }
}
struct QcPlan {
    backing: usize,
}
impl QcPlan {
    fn new(raw: &[u8]) -> Result<Self, ShapeError> {
        // A complete unknown discriminant is an intrinsic domain violation,
        // including when later fields or a suffix are malformed. Reject it before
        // ordinary enum decoding could allocate its unknown-tag diagnostic.
        let view = ncore::from_bytes_view(raw)?;
        if view.schema() != norito::schema::identity::frame_hash::<Qc>() {
            return Err(norito::Error::SchemaMismatch.into());
        }
        let mut offset = 0;
        let kind = shape_field(view.as_bytes(), &mut offset, view.flags())?;
        if let Some(tag) = view.as_bytes()[kind].get(..4) {
            let tag = u32::from_le_bytes(tag.try_into().expect("complete scalar tag"));
            if tag > 1 {
                return Err(ShapeError::Intrinsic);
            }
        }
        let frame = Frame::<9>::parse::<Qc>(raw)?;
        let bytes = shape_bytes(frame.field(7), frame.flags, 0, MAX_BITMAP_BYTES)?;
        Ok(Self {
            backing: bytes.len(),
        })
    }
}
fn shape_result<T>(plan: Result<T, ShapeError>) -> Result<Option<T>, CertificateReadError> {
    match plan {
        Ok(plan) => Ok(Some(plan)),
        Err(ShapeError::Intrinsic) => Err(CertificateReadError::Decode(
            norito::Error::NonCanonicalEncoding,
        )),
        // Preserve no source-less fake resource diagnosis. The authoritative
        // traversal rediscovers the actual malformed cause at its proper order.
        Err(ShapeError::Malformed(_original)) => Ok(None),
    }
}

// These are total fixed-width/inline leaf decoders. The derived record kernel still
// owns their canonical field order; no arbitrary decoder or process-lived panic-hook
// allocation is needed to inspect these bounded metadata fields.
trait InlineLeaf: Sized {
    fn decode(bytes: &[u8]) -> Result<Self, norito::Error>;
}

struct InlineFields;
impl ncore::FieldDestination for InlineFields {
    type Error = std::convert::Infallible;
}
impl<const INDEX: usize, T: InlineLeaf> ncore::DecodeField<INDEX, T> for InlineFields {
    type Value = T;
    fn decode_field(
        &mut self,
        field: ncore::CanonicalField<'_, T>,
    ) -> Result<T, ncore::DecodeIntoError<Self::Error>> {
        field.with_payload(|bytes| T::decode(bytes).map_err(ncore::DecodeIntoError::Codec))
    }
}
impl<const N: usize> InlineLeaf for [u8; N] {
    fn decode(bytes: &[u8]) -> Result<Self, norito::Error> {
        bytes.try_into().map_err(|_| norito::Error::LengthMismatch)
    }
}
impl InlineLeaf for u64 {
    fn decode(bytes: &[u8]) -> Result<Self, norito::Error> {
        Ok(Self::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| norito::Error::LengthMismatch)?,
        ))
    }
}
impl InlineLeaf for u32 {
    fn decode(bytes: &[u8]) -> Result<Self, norito::Error> {
        Ok(Self::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| norito::Error::LengthMismatch)?,
        ))
    }
}
impl InlineLeaf for Hash32 {
    fn decode(bytes: &[u8]) -> Result<Self, norito::Error> {
        let ((value,), _) = <Self as ncore::DecodeRecordFields<InlineFields>>::decode_fields(
            bytes,
            &mut InlineFields,
        )
        .map_err(ncore::DecodeIntoError::into_codec)?;
        Ok(Self(value))
    }
}
impl InlineLeaf for AggregateSignature {
    fn decode(bytes: &[u8]) -> Result<Self, norito::Error> {
        let ((value,), _) = <Self as ncore::DecodeRecordFields<InlineFields>>::decode_fields(
            bytes,
            &mut InlineFields,
        )
        .map_err(ncore::DecodeIntoError::into_codec)?;
        Ok(Self(value))
    }
}
impl InlineLeaf for EpochId {
    fn decode(bytes: &[u8]) -> Result<Self, norito::Error> {
        let ((epoch, context), _) =
            <Self as ncore::DecodeRecordFields<InlineFields>>::decode_fields(
                bytes,
                &mut InlineFields,
            )
            .map_err(ncore::DecodeIntoError::into_codec)?;
        Ok(Self { epoch, context })
    }
}
impl ncore::EnumFieldDestination for InlineFields {
    fn begin_variant(&mut self, _variant: u32) -> Result<(), Self::Error> {
        Ok(())
    }
}
impl ncore::DecodeValueDestination<VoteKind> for InlineFields {
    fn restore_value(&mut self, _value: VoteKind) {}
}
impl InlineLeaf for VoteKind {
    fn decode(bytes: &[u8]) -> Result<Self, norito::Error> {
        // The derived enum kernel's unknown-tag diagnostic owns a String. Reject
        // the two-case scalar domain before entering it, with a fixed-shape error.
        if u32::decode(bytes)? > 1 {
            return Err(norito::Error::NonCanonicalEncoding);
        }
        <Self as ncore::DecodeValueFields<InlineFields>>::decode_value_fields(
            bytes,
            &mut InlineFields,
        )
        .map(|(value, _)| value)
        .map_err(ncore::DecodeIntoError::into_codec)
    }
}
impl InlineLeaf for ControlWitness {
    fn decode(bytes: &[u8]) -> Result<Self, norito::Error> {
        // This original inline codec owns count/depth/bound ordering without
        // allocating an ordinary heap value or inventing a parallel parser.
        let (value, used) = <Self as ncore::DecodeFromSlice>::decode_from_slice(bytes)?;
        if used != bytes.len() {
            return Err(norito::Error::LengthMismatch);
        }
        Ok(value)
    }
}

fn with_wrapped_bytes<R>(
    bytes: &[u8],
    min: usize,
    max: usize,
    visit: impl FnOnce(&[u8]) -> Result<R, ncore::DecodeIntoError<CertificateReadError>>,
) -> Result<R, ncore::DecodeIntoError<CertificateReadError>> {
    let mut offset = 0;
    let field = ncore::framed_field::<Vec<u8>>(bytes, &mut offset)?;
    let result = field.with_payload(|bytes| {
        let (count, start) = ncore::read_seq_len_slice(bytes)?;
        // Match raw Vec's source extent check before its backing charge.
        let end = start
            .checked_add(count)
            .ok_or(norito::Error::LengthMismatch)?;
        let source = bytes.get(start..end).ok_or(norito::Error::LengthMismatch)?;
        ncore::reserve_decode_allocation(count)?;
        if end != bytes.len() {
            return Err(norito::Error::LengthMismatch.into());
        }
        if !(min..=max).contains(&count) {
            return Err(norito::Error::NonCanonicalEncoding.into());
        }
        visit(source)
    })?;
    if offset != bytes.len() {
        return Err(norito::Error::LengthMismatch.into());
    }
    Ok(result)
}

fn demand<T>(count: usize, backing: usize) -> Result<usize, CertificateReadError> {
    let ledger = Layout::array::<AllocationCharge>(count)
        .map_err(|_| admission(AllocationRefusal::DemandOverflow))?;
    backing
        .checked_add(workspace_bytes()?)
        .and_then(|bytes| bytes.checked_add(ledger.size()))
        .and_then(|bytes| {
            bytes.checked_add(ChargedShared::<RetainedPayload<T>>::allocation_layout().size())
        })
        .ok_or_else(|| admission(AllocationRefusal::DemandOverflow))
}

fn admission(error: AllocationRefusal) -> CertificateReadError {
    CertificateReadError::Admission(ByteAdmissionError::Buffer(ChargedBufferError::Admission(
        error,
    )))
}

fn prepaid(error: PrepaidBufferError) -> CertificateReadError {
    match error {
        PrepaidBufferError::Allocation(error) => {
            CertificateReadError::Admission(ByteAdmissionError::Buffer(error))
        }
        // Every child layout was summed before this reservation. A disagreement is
        // an internal checked-layout failure, never evidence of pool exhaustion.
        PrepaidBufferError::Reservation(_) => admission(AllocationRefusal::DemandOverflow),
    }
}

fn byte_backing(
    bytes: &[u8],
    reservation: &mut AllocationReservation,
) -> Result<ChargedBuffer<u8>, CertificateReadError> {
    let mut output = ChargedBuffer::from_reservation(bytes.len(), reservation).map_err(prepaid)?;
    for byte in bytes {
        output.push_reserved(*byte);
    }
    Ok(output)
}

fn workspace_bytes() -> Result<usize, CertificateReadError> {
    ncore::PreparedDecodeWorkspace::allocation_layouts()
        .iter()
        .try_fold(0_usize, |sum, layout| sum.checked_add(layout.size()))
        .ok_or_else(|| admission(AllocationRefusal::DemandOverflow))
}
fn workspace(
    budget: &AllocationBudget,
    reservation: &mut AllocationReservation,
) -> Result<ncore::PreparedDecodeWorkspace, CertificateReadError> {
    ncore::PreparedDecodeWorkspace::from_reservation(budget, reservation).map_err(scope_error)
}
fn scope_error(error: ncore::PreparedDecodeScopeError) -> CertificateReadError {
    match error {
        ncore::PreparedDecodeScopeError::Allocation(error) => {
            CertificateReadError::Admission(ByteAdmissionError::ControlAllocation(error))
        }
        ncore::PreparedDecodeScopeError::ForeignPool => CertificateReadError::ForeignBudget,
        ncore::PreparedDecodeScopeError::Reservation(_)
        | ncore::PreparedDecodeScopeError::AttemptExhausted => {
            admission(AllocationRefusal::DemandOverflow)
        }
    }
}
fn prepared_error(error: ncore::PreparedDecodeError<CertificateReadError>) -> CertificateReadError {
    match error {
        ncore::PreparedDecodeError::Codec(original) => captured(original),
        ncore::PreparedDecodeError::Destination(original) => original,
        ncore::PreparedDecodeError::Scope(original) => scope_error(original),
    }
}

/// Decode canonical header metadata with its original workspace and immutable graph.
pub(in crate::sumeragi) fn header(
    raw: &[u8],
    budget: &AllocationBudget,
) -> Result<FundedMetadata<BlockHeader>, CertificateReadError> {
    capture_decode(|| {
        frame_bound(raw, MAX_HEADER_METADATA_BYTES)?;
        #[cfg(all(test, sumeragi_core_mutation = "HC960"))]
        let substituted = AllocationBudget::new(budget.limit_bytes());
        #[cfg(all(test, sumeragi_core_mutation = "HC960"))]
        let budget = &substituted;
        destination::header(raw, shape_result(HeaderPlan::new(raw))?, budget)
    })
}

/// Decode the same header into the native reader's ordinary ownership API.
/// TODO: BodyRestoration still takes a bare header graph; its shared handoff migration
/// is separate from canonical scope/depth parity at this reader boundary.
pub(in crate::sumeragi) fn decoded_header(raw: &[u8]) -> Result<BlockHeader, CertificateReadError> {
    capture_decode(|| {
        frame_bound(raw, MAX_HEADER_METADATA_BYTES)?;
        let shape = shape_result(HeaderPlan::new(raw))?;
        #[cfg(all(test, sumeragi_core_mutation = "HC961"))]
        let value = norito::decode_from_bytes(raw).map_err(CertificateReadError::Decode)?;
        #[cfg(not(all(test, sumeragi_core_mutation = "HC961")))]
        let value = norito::decode_canonical(raw).map_err(CertificateReadError::Decode)?;
        if shape.is_none() {
            return Err(CertificateReadError::Decode(norito::Error::LengthMismatch));
        }
        Ok(value)
    })
}

/// Decode canonical quorum metadata with its original workspace and immutable graph.
pub(in crate::sumeragi) fn qc(
    raw: &[u8],
    budget: &AllocationBudget,
) -> Result<FundedMetadata<Qc>, CertificateReadError> {
    capture_decode(|| {
        frame_bound(raw, MAX_QC_METADATA_BYTES)?;
        destination::qc(raw, shape_result(QcPlan::new(raw))?, budget)
    })
}

/// Decode the same quorum metadata into the native reader's ordinary bitmap owner.
/// TODO: migrate the bare QC handoff with BodyRestoration's shared owner.
pub(in crate::sumeragi) fn decoded_qc(raw: &[u8]) -> Result<Qc, CertificateReadError> {
    capture_decode(|| {
        frame_bound(raw, MAX_QC_METADATA_BYTES)?;
        let shape = shape_result(QcPlan::new(raw))?;
        #[cfg(all(test, sumeragi_core_mutation = "HC961"))]
        let value = norito::decode_from_bytes(raw).map_err(CertificateReadError::Decode)?;
        #[cfg(not(all(test, sumeragi_core_mutation = "HC961")))]
        let value = norito::decode_canonical(raw).map_err(CertificateReadError::Decode)?;
        if shape.is_none() {
            return Err(CertificateReadError::Decode(norito::Error::LengthMismatch));
        }
        Ok(value)
    })
}

#[cfg(test)]
thread_local! {
    static PANIC_AFTER_KEY: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static REFUSE_KEY: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

fn key_backing(
    index: usize,
    bytes: &[u8],
    reservation: &mut AllocationReservation,
) -> Result<ChargedBuffer<u8>, CertificateReadError> {
    #[cfg(test)]
    if REFUSE_KEY.with(|selected| selected.get() == Some(index)) {
        REFUSE_KEY.with(|selected| selected.set(None));
        let (result, observed) = crate::test_allocations::refuse_one_layout_during(
            Layout::array::<u8>(bytes.len()).expect("bounded original key layout"),
            || byte_backing(bytes, reservation),
        );
        assert!(observed, "selected original key allocation must be refused");
        return result;
    }
    #[cfg(not(test))]
    let _ = index;
    byte_backing(bytes, reservation)
}

#[cfg(test)]
fn checkpoint(index: usize) {
    PANIC_AFTER_KEY.with(|enabled| {
        if enabled.get() == Some(index) {
            enabled.set(None);
            panic!("injected original metadata construction unwind");
        }
    });
}

#[cfg(test)]
mod tests;
