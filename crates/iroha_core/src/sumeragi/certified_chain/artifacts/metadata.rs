//! Exact original-pool ownership for canonical certificate header and quorum metadata.
//!
//! This is the sole decoder of a stored certificate's header and `CommitQC` frames. Prefix
//! reads take funded immutable owners; the native body reader takes ordinary owners from the
//! same frame, bound, leaf and exact canonical checks, so every reader returns one verdict.
//!
//! Structural decoding grants no authority. The original certificate verifier still checks
//! source, exact quorum, signature and availability relations over these immutable values.
//!
//! TODO(S8): enable the canonical BlockHeader generated field destination in its shared
//! owner, then use PreparedDecodeWorkspace for original top-record depth/scope parity.
//! Nested fields already use the shared canonical field and inherited resource gates.

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

use crate::sumeragi::{
    block_store::certificate_read::CertificateReadError,
    durable_qc_codec::MAX_QC_METADATA_BYTES,
    durable_record_codec::{MAX_HEADER_METADATA_BYTES, byte_range, field_range},
};

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

struct Frame<'a, const N: usize> {
    payload: &'a [u8],
    fields: [std::ops::Range<usize>; N],
    schema: [u8; 16],
    flags: u8,
}

impl<'a, const N: usize> Frame<'a, N> {
    fn parse<T: norito::NoritoSchema>(raw: &'a [u8], cap: usize) -> Result<Self, norito::Error> {
        if raw.len() > cap + ncore::Header::SIZE {
            return Err(norito::Error::FieldLengthExceeded {
                length: raw.len() as u64,
                limit: (cap + ncore::Header::SIZE) as u64,
            });
        }
        let view = ncore::from_bytes_view(raw)?;
        if view.schema() != norito::schema::identity::frame_hash::<T>() {
            return Err(norito::Error::SchemaMismatch);
        }
        let payload = view.as_bytes();
        let _context = ncore::PayloadCtxGuard::enter_with_schema_and_flags(
            payload,
            view.schema(),
            view.flags(),
        );
        let mut offset = 0;
        let mut fields = std::array::from_fn(|_| 0..0);
        for field in &mut fields {
            *field = field_range(payload, &mut offset)?;
        }
        if offset != payload.len() {
            return Err(norito::Error::LengthMismatch);
        }
        Ok(Self {
            payload,
            fields,
            schema: view.schema(),
            flags: view.flags(),
        })
    }

    fn context(&self) -> ncore::PayloadCtxGuard {
        ncore::PayloadCtxGuard::enter_with_schema_and_flags(self.payload, self.schema, self.flags)
    }

    fn field(&self, index: usize) -> &'a [u8] {
        &self.payload[self.fields[index].clone()]
    }

    fn leaf<T>(&self, index: usize) -> Result<T, norito::Error>
    where
        T: InlineLeaf + for<'de> ncore::DeserializePayload<'de> + ncore::SerializePayload,
    {
        self.with_field::<T, _>(index, T::decode)
    }

    fn with_field<T, R>(
        &self,
        index: usize,
        decode: impl FnOnce(&[u8]) -> Result<R, norito::Error>,
    ) -> Result<R, norito::Error>
    where
        T: for<'de> ncore::DeserializePayload<'de> + ncore::SerializePayload,
    {
        let mut offset = if index == 0 {
            0
        } else {
            self.fields[index - 1].end
        };
        ncore::framed_field::<T>(self.payload, &mut offset)?
            .with_payload(|bytes| decode(bytes).map_err(ncore::DecodeIntoError::Codec))
            .map_err(ncore::DecodeIntoError::<std::convert::Infallible>::into_codec)
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
        let (length, start) = ncore::read_seq_len_slice(bytes)?;
        if length != bytes.len().saturating_sub(start) {
            return Err(norito::Error::LengthMismatch);
        }
        Self::try_from_slice(&bytes[start..]).map_err(|_| norito::Error::NonCanonicalEncoding)
    }
}

fn wrapped_bytes(bytes: &[u8], min: usize, max: usize) -> Result<&[u8], norito::Error> {
    let mut offset = 0;
    let field = field_range(bytes, &mut offset)?;
    if offset != bytes.len() {
        return Err(norito::Error::LengthMismatch);
    }
    let range = byte_range(bytes, field, min, max)?;
    Ok(&bytes[range])
}

// Keep inherited cumulative codec limits as well as physical pool custody. The
// borrowed preflight allocates no decoder plan, so only the eventual byte graph
// needs accounting; the exact metadata owner separately funds its private ledger.
fn with_wrapped_bytes<R>(
    bytes: &[u8],
    min: usize,
    max: usize,
    visit: impl FnOnce(&[u8]) -> Result<R, norito::Error>,
) -> Result<R, norito::Error> {
    let mut offset = 0;
    let field = ncore::framed_field::<Vec<u8>>(bytes, &mut offset)?;
    if offset != bytes.len() {
        return Err(norito::Error::LengthMismatch);
    }
    field
        .with_payload(|bytes| {
            let (count, start) = ncore::read_seq_len_slice(bytes)?;
            if !(min..=max).contains(&count) || count != bytes.len().saturating_sub(start) {
                return Err(ncore::DecodeIntoError::Codec(
                    norito::Error::NonCanonicalEncoding,
                ));
            }
            ncore::reserve_decode_allocation(count)?;
            visit(&bytes[start..]).map_err(ncore::DecodeIntoError::Codec)
        })
        .map_err(ncore::DecodeIntoError::<std::convert::Infallible>::into_codec)
}

fn demand<T>(count: usize, backing: usize) -> Result<usize, CertificateReadError> {
    let ledger = Layout::array::<AllocationCharge>(count)
        .map_err(|_| admission(AllocationRefusal::DemandOverflow))?;
    backing
        .checked_add(ledger.size())
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

// During construction the values precede their ledger, so every success, rejection
// and unwind destroys the physical payload before releasing its exact original charge.
struct HeaderConstruction {
    keys: ChargedBuffer<PublicKey>,
    ledger: ChargedBuffer<AllocationCharge>,
}

// A key store rejects key bytes through its outer codec error. Its inner error is a local
// destination refusal that stops construction before any later key is materialized.
type KeyStored = Result<Result<(), CertificateReadError>, norito::Error>;

// The sole canonical header decoder before any destination allocation: frame, field,
// committee, key-shape, leaf and inherited-limit checks. Funded and native destinations
// differ only in who owns the key backing; both end with the same exact canonical check.
struct HeaderPlan<'a> {
    frame: Frame<'a, 12>,
    count: usize,
    backing: usize,
    value: BlockHeader,
}

impl<'a> HeaderPlan<'a> {
    fn new(raw: &'a [u8]) -> Result<Self, CertificateReadError> {
        let frame = Frame::<12>::parse::<BlockHeader>(raw, MAX_HEADER_METADATA_BYTES)
            .map_err(CertificateReadError::Decode)?;
        let _context = frame.context();
        let keys = frame.field(10);
        let (count, _) =
            ncore::inspect_seq_len_slice(keys).map_err(CertificateReadError::Decode)?;
        // Protocol bounds are terminal shape rejections, never a resource ceiling that an
        // enclosing decode scope could coincidentally match and turn into a local refusal.
        if count > MAX_COMMITTEE_SIZE {
            return Err(CertificateReadError::Decode(
                norito::Error::NonCanonicalEncoding,
            ));
        }
        let array = Layout::array::<PublicKey>(count)
            .map_err(|_| admission(AllocationRefusal::DemandOverflow))?;
        let mut backing = array.size();
        frame
            .with_field::<Vec<PublicKey>, _>(10, |keys| {
                let (admitted, mut offset) = ncore::read_seq_len_slice(keys)?;
                if admitted != count {
                    return Err(norito::Error::LengthMismatch);
                }
                ncore::reserve_decode_allocation(array.size())?;
                for _ in 0..count {
                    ncore::framed_field::<PublicKey>(keys, &mut offset)?
                        .with_payload(|bytes| {
                            with_wrapped_bytes(bytes, 1, MAX_PUBLIC_KEY_LEN, |bytes| {
                                backing = backing
                                    .checked_add(bytes.len())
                                    .ok_or(norito::Error::LengthMismatch)?;
                                Ok(())
                            })
                            .map_err(ncore::DecodeIntoError::Codec)
                        })
                        .map_err(ncore::DecodeIntoError::<std::convert::Infallible>::into_codec)?;
                }
                if offset != keys.len() {
                    return Err(norito::Error::LengthMismatch);
                }
                Ok(())
            })
            .map_err(CertificateReadError::Decode)?;
        // All leaves are inline values; no metadata allocation occurs before the exact
        // source shape has been checked and a destination has admitted its key graph.
        let value = BlockHeader {
            instance: frame.leaf(0).map_err(CertificateReadError::Decode)?,
            epoch: frame.leaf(1).map_err(CertificateReadError::Decode)?,
            height: frame.leaf(2).map_err(CertificateReadError::Decode)?,
            origin_view: frame.leaf(3).map_err(CertificateReadError::Decode)?,
            parent_hash: frame.leaf(4).map_err(CertificateReadError::Decode)?,
            parent_result: frame.leaf(5).map_err(CertificateReadError::Decode)?,
            payload_hash: frame.leaf(6).map_err(CertificateReadError::Decode)?,
            availability_digest: frame.leaf(7).map_err(CertificateReadError::Decode)?,
            payload_len: frame.leaf(8).map_err(CertificateReadError::Decode)?,
            proposer: frame.leaf(9).map_err(CertificateReadError::Decode)?,
            skipped_leaders: Vec::new(),
            control_witness: frame
                .leaf::<ControlWitness>(11)
                .map_err(CertificateReadError::Decode)?,
        };
        Ok(Self {
            frame,
            count,
            backing,
            value,
        })
    }

    // Visit every bounded canonical key in order through one destination store.
    fn visit_keys(
        &self,
        mut store: impl FnMut(usize, &[u8]) -> KeyStored,
    ) -> Result<(), CertificateReadError> {
        let keys = self.frame.field(10);
        let mut failure = None;
        let mut key_index = 0;
        ncore::visit_binary_sequence_with_count(keys, self.frame.flags, self.count, |span| {
            if failure.is_some() {
                return Ok(());
            }
            let bytes = wrapped_bytes(span.get(keys)?, 1, MAX_PUBLIC_KEY_LEN)?;
            if let Err(error) = store(key_index, bytes)? {
                failure = Some(error);
                return Ok(());
            }
            #[cfg(test)]
            checkpoint(key_index);
            key_index += 1;
            Ok(())
        })
        .map_err(CertificateReadError::Decode)?;
        failure.map_or(Ok(()), Err)
    }

    // Complete the decoded header with the destination's own key vector. Each destination
    // then applies the shared exact canonical relation before publishing its value.
    fn finish(self, keys: Vec<PublicKey>) -> BlockHeader {
        let mut value = self.value;
        value.skipped_leaders = keys;
        value
    }
}

/// Decode canonical header metadata into its exact original immutable graph.
#[allow(
    unsafe_code,
    reason = "canonical Vec fields only receive the unchanged prepaid allocations; the private owner retains every charge until payload destruction"
)]
pub(in crate::sumeragi) fn header(
    raw: &[u8],
    budget: &AllocationBudget,
) -> Result<FundedMetadata<BlockHeader>, CertificateReadError> {
    #[cfg(all(test, sumeragi_core_mutation = "HC960"))]
    let substituted_pool = AllocationBudget::new(budget.limit_bytes());
    #[cfg(all(test, sumeragi_core_mutation = "HC960"))]
    let budget = &substituted_pool;
    #[cfg(not(all(test, sumeragi_core_mutation = "HC960")))]
    let budget = budget;
    let plan = HeaderPlan::new(raw)?;
    let _context = plan.frame.context();
    let mut reservation = budget
        .try_reserve_bytes(demand::<BlockHeader>(plan.count + 1, plan.backing)?)
        .map_err(admission)?;
    let shell = ChargedShared::<RetainedPayload<BlockHeader>>::reserve_from(&mut reservation)
        .map_err(|error| {
            CertificateReadError::Admission(ByteAdmissionError::ControlAllocation(error))
        })?;
    let ledger =
        ChargedBuffer::from_reservation(plan.count + 1, &mut reservation).map_err(prepaid)?;
    let mut construction = HeaderConstruction {
        keys: ChargedBuffer::from_reservation(plan.count, &mut reservation).map_err(prepaid)?,
        ledger,
    };
    plan.visit_keys(|index, bytes| {
        let bytes = match key_backing(index, bytes, &mut reservation) {
            Ok(bytes) => bytes,
            Err(error) => return Ok(Err(error)),
        };
        // SAFETY: PublicKey::new consumes this exact byte Vec without copying or
        // growth. Its charge is installed before any subsequent fallible work.
        let (bytes, charge) = unsafe { bytes.into_allocation_parts() };
        construction.ledger.push_reserved(charge);
        let key = PublicKey::new(bytes).map_err(|_| norito::Error::NonCanonicalEncoding)?;
        construction.keys.push_reserved(key);
        Ok(Ok(()))
    })?;
    // SAFETY: this moves the same exact vector into the canonical header. The
    // newly moved payload and its ledger immediately enter the audited owner.
    let (keys, charge) = unsafe { construction.keys.into_allocation_parts() };
    construction.ledger.push_reserved(charge);
    let value = plan.finish(keys);
    let owned = match unsafe { RetainedPayload::try_new(value, construction.ledger, budget) } {
        Ok(owned) => owned,
        Err((value, ledger, _)) => {
            drop(value);
            drop(ledger);
            return Err(CertificateReadError::ForeignBudget);
        }
    };
    canonical(owned.get(), raw)?;
    debug_assert_eq!(reservation.remaining_bytes(), 0);
    Ok(FundedMetadata(shell.initialize(owned)))
}

/// Decode the same canonical header into ordinary owners for the native body handoff.
/// TODO: BodyRestoration still takes a bare header graph; once its shared handoff accepts
/// funded metadata, this destination should become `header` with the reader's pool.
pub(in crate::sumeragi) fn decoded_header(raw: &[u8]) -> Result<BlockHeader, CertificateReadError> {
    let plan = HeaderPlan::new(raw)?;
    let _context = plan.frame.context();
    // Ordinary owners keep the generic Norito sequence growth (`try_reserve`), so the native
    // body readers' physical allocations and refusals match their former decoder exactly.
    let mut keys = Vec::new();
    keys.try_reserve(plan.count).map_err(|_| {
        allocation_failed(
            Layout::array::<PublicKey>(plan.count).map_or(usize::MAX, |array| array.size()),
        )
    })?;
    plan.visit_keys(|_, bytes| {
        let mut owned = Vec::new();
        if owned.try_reserve(bytes.len()).is_err() {
            return Ok(Err(allocation_failed(bytes.len())));
        }
        owned.extend_from_slice(bytes);
        keys.push(PublicKey::new(owned).map_err(|_| norito::Error::NonCanonicalEncoding)?);
        Ok(Ok(()))
    })?;
    let value = plan.finish(keys);
    canonical(&value, raw)?;
    Ok(value)
}

// The canonical quorum fields before destination allocation of the signer bitmap.
struct QcPlan<'a> {
    frame: Frame<'a, 9>,
    bitmap: &'a [u8],
    value: Qc,
}

impl<'a> QcPlan<'a> {
    fn new(raw: &'a [u8]) -> Result<Self, CertificateReadError> {
        let frame = Frame::<9>::parse::<Qc>(raw, MAX_QC_METADATA_BYTES)
            .map_err(CertificateReadError::Decode)?;
        let _context = frame.context();
        // The canonical field bound rejects an oversized bitmap as a terminal shape error
        // before its borrowed bytes are located.
        frame
            .with_field::<Bitmap, _>(7, |bytes| {
                with_wrapped_bytes(bytes, 0, MAX_BITMAP_BYTES, |_| Ok(()))
            })
            .map_err(CertificateReadError::Decode)?;
        let bitmap = wrapped_bytes(frame.field(7), 0, MAX_BITMAP_BYTES)
            .map_err(CertificateReadError::Decode)?;
        let value = Qc {
            kind: frame.leaf(0).map_err(CertificateReadError::Decode)?,
            instance: frame.leaf(1).map_err(CertificateReadError::Decode)?,
            epoch: frame.leaf(2).map_err(CertificateReadError::Decode)?,
            height: frame.leaf(3).map_err(CertificateReadError::Decode)?,
            view: frame.leaf(4).map_err(CertificateReadError::Decode)?,
            block_hash: frame.leaf(5).map_err(CertificateReadError::Decode)?,
            result: frame.leaf(6).map_err(CertificateReadError::Decode)?,
            signers: Bitmap::from_bytes(Vec::new()),
            agg_sig: frame.leaf(8).map_err(CertificateReadError::Decode)?,
        };
        Ok(Self {
            frame,
            bitmap,
            value,
        })
    }

    fn finish(self, signers: Vec<u8>) -> Qc {
        let mut value = self.value;
        value.signers = Bitmap::from_bytes(signers);
        value
    }
}

/// Decode canonical quorum metadata without a temporary signer bitmap or decode plan.
#[allow(
    unsafe_code,
    reason = "the canonical bitmap receives the unchanged prepaid allocation and the immutable owner retains its exact charge through last-reader destruction"
)]
pub(in crate::sumeragi) fn qc(
    raw: &[u8],
    budget: &AllocationBudget,
) -> Result<FundedMetadata<Qc>, CertificateReadError> {
    let plan = QcPlan::new(raw)?;
    let _context = plan.frame.context();
    let mut reservation = budget
        .try_reserve_bytes(demand::<Qc>(1, plan.bitmap.len())?)
        .map_err(admission)?;
    let shell =
        ChargedShared::<RetainedPayload<Qc>>::reserve_from(&mut reservation).map_err(|error| {
            CertificateReadError::Admission(ByteAdmissionError::ControlAllocation(error))
        })?;
    let mut ledger = ChargedBuffer::from_reservation(1, &mut reservation).map_err(prepaid)?;
    let bytes = byte_backing(plan.bitmap, &mut reservation)?;
    // SAFETY: the original bitmap Vec and charge immediately enter one immutable
    // payload owner. No fallible or allocating operation separates their movement.
    let (bytes, charge) = unsafe { bytes.into_allocation_parts() };
    ledger.push_reserved(charge);
    let value = plan.finish(bytes);
    let owned = match unsafe { RetainedPayload::try_new(value, ledger, budget) } {
        Ok(owned) => owned,
        Err((value, ledger, _)) => {
            drop(value);
            drop(ledger);
            return Err(CertificateReadError::ForeignBudget);
        }
    };
    canonical(owned.get(), raw)?;
    debug_assert_eq!(reservation.remaining_bytes(), 0);
    Ok(FundedMetadata(shell.initialize(owned)))
}

/// Decode the same canonical quorum metadata into an ordinary signer bitmap owner.
/// TODO: the native body reader still returns a bare QC; migrate it with BodyRestoration.
pub(in crate::sumeragi) fn decoded_qc(raw: &[u8]) -> Result<Qc, CertificateReadError> {
    let plan = QcPlan::new(raw)?;
    let _context = plan.frame.context();
    let mut signers = Vec::new();
    signers
        .try_reserve(plan.bitmap.len())
        .map_err(|_| allocation_failed(plan.bitmap.len()))?;
    signers.extend_from_slice(plan.bitmap);
    let value = plan.finish(signers);
    canonical(&value, raw)?;
    Ok(value)
}

// The sole exact canonical relation of both destinations: an accepted frame is exactly
// the canonical frame of its decoded value, so no alternate layout, redundant length
// form or suffix can decode to a value that a canonical reader would reject.
fn canonical<T: ncore::NoritoSerialize>(value: &T, raw: &[u8]) -> Result<(), CertificateReadError> {
    #[cfg(all(test, sumeragi_core_mutation = "HC961"))]
    {
        let _ = (value, raw);
        Ok(())
    }
    #[cfg(not(all(test, sumeragi_core_mutation = "HC961")))]
    norito::verify_exact_canonical_frame(value, raw).map_err(CertificateReadError::Decode)
}

fn allocation_failed(bytes: usize) -> CertificateReadError {
    CertificateReadError::Decode(norito::Error::AllocationFailed {
        bytes: u64::try_from(bytes).unwrap_or(u64::MAX),
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
