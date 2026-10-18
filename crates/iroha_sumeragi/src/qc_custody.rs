//! Physical custody of the current nine-field canonical QC and its original source.
//!
//! A canonical transport QC grants no vote, signature, epoch, quorum or finality authority.
//! The structural bitmap bound remains 1024 seats; actual committee authentication keeps
//! its separate global 3f+1, 4..31-seat policy. No retired witness/attestation table exists.

use crate::{
    message::{CodecError, Qc, VoteKind, check_qc},
    types::{AggregateSignature, Bitmap, EpochId, Hash32},
};
use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, ChargedBuffer, ChargedBufferError,
    ChargedBufferFromChargeError, ChargedShared, PrepaidBufferError, PrepaidSharedError,
    ReservedChargedShared, RetainedPayload, RetainedPayloadError,
};
use norito::core::{
    CanonicalField, DecodeField, DecodeFromSlice, DecodeIntoError, DecodeLimits,
    DecodeRecordFields, PreparedDecodeError, PreparedDecodeScopeError, PreparedDecodeWorkspace,
    PreparedRecordDestination, SequenceSpan, SerializePayload,
};
use std::{alloc::Layout, fmt};
mod inline;

/// Original finite-pool, canonical-frame or structural transport refusal.
#[derive(Debug)]
pub enum QcCustodyError {
    /// The same actual finite pool refused fixed control prepayment.
    Admission(AllocationRefusal),
    /// Physical construction of original decoder controls failed.
    Scope(PreparedDecodeScopeError),
    /// Physical prepaid source-independent control or ledger construction failed.
    Control(PrepaidSharedError),
    /// Physical prepaid ledger construction failed.
    Ledger(PrepaidBufferError),
    /// The original codec, logical scope or bitmap backing refused the full field walk.
    Decode(PreparedDecodeError<QcFieldError>),
    /// Complete canonical framing succeeded, then the original structural validator rejected.
    Structural(CodecError),
    /// Input, pool or exact original borrowed range differs from this owner.
    Source,
    /// Incomplete fields confer no QC view or extraction authority.
    Incomplete,
    /// Internal ledger provenance failed closed without replacing either original owner.
    Retention(RetainedPayloadError),
}
impl fmt::Display for QcCustodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(e) => e.fmt(f),
            Self::Scope(e) => e.fmt(f),
            Self::Control(e) => e.fmt(f),
            Self::Ledger(e) => e.fmt(f),
            Self::Decode(e) => e.fmt(f),
            Self::Structural(e) => e.fmt(f),
            Self::Source => f.write_str("QC custody source or original finite pool changed"),
            Self::Incomplete => {
                f.write_str("QC custody has not completed canonical authentication")
            }
            Self::Retention(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for QcCustodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Admission(original) => Some(original),
            Self::Scope(original) => Some(original),
            Self::Control(original) => Some(original),
            Self::Ledger(original) => Some(original),
            Self::Decode(original) => Some(original),
            Self::Structural(original) => Some(original),
            Self::Retention(original) => Some(original),
            Self::Source | Self::Incomplete => None,
        }
    }
}

/// Exact original bitmap allocation refusal retained outside codec classification.
#[derive(Debug)]
pub enum QcFieldError {
    /// Original bitmap backing could not be admitted or physically allocated.
    Bitmap(ChargedBufferError),
    /// The original admitted bitmap charge stays retained for same-source retry.
    BitmapBacking(ChargedBufferFromChargeError),
    /// Same-source replay cannot resize or substitute the original bitmap allocation.
    Geometry,
}
impl fmt::Display for QcFieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bitmap(e) => e.fmt(f),
            Self::BitmapBacking(e) => e.fmt(f),
            Self::Geometry => f.write_str("QC bitmap changed its original allocation geometry"),
        }
    }
}
impl std::error::Error for QcFieldError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bitmap(original) => Some(original),
            Self::BitmapBacking(original) => Some(original),
            Self::Geometry => None,
        }
    }
}

// Actual record storage owns the Qc before its ledger; abandonment frees the
// Bitmap Vec before refunding its backing or original ledger control.
pub(crate) struct QcFields {
    payload: Qc,
    ledger: ChargedBuffer<AllocationCharge>,
    bitmap: QcBitmapAllocation,
    pool: AllocationBudget,
}

// Parents retain this inline state and their actual Qc Option slot across later
// sibling failures. It owns no second QC root, scope or charge ledger.
#[derive(Default)]
pub(crate) struct QcBitmapAllocation {
    pending_charge: Option<AllocationCharge>,
    initialized: bool,
}

pub(crate) fn empty_qc() -> Qc {
    Qc {
        kind: VoteKind::Prepare,
        instance: Hash32::ZERO,
        epoch: EpochId {
            epoch: 0,
            context: Hash32::ZERO,
        },
        height: 0,
        view: 0,
        block_hash: Hash32::ZERO,
        result: Hash32::ZERO,
        signers: Bitmap::default(),
        agg_sig: AggregateSignature([0; crate::types::SIGNATURE_LEN]),
    }
}
impl QcFields {
    pub(crate) fn new(pool: &AllocationBudget, ledger: ChargedBuffer<AllocationCharge>) -> Self {
        Self {
            payload: empty_qc(),
            ledger,
            bitmap: QcBitmapAllocation::default(),
            pool: pool.clone(),
        }
    }
    fn destination(&mut self) -> QcFieldDestination<'_> {
        QcFieldDestination {
            payload: &mut self.payload,
            ledger: &mut self.ledger,
            bitmap: &mut self.bitmap,
            pool: &self.pool,
        }
    }
}

// The sole private prepared visitor writes directly into its caller's actual Qc
// field and original complete ledger. The generated walk supplies field order
// and framing; no moving extraction or separately framed child exists.
pub(crate) struct QcFieldDestination<'a> {
    payload: &'a mut Qc,
    ledger: &'a mut ChargedBuffer<AllocationCharge>,
    bitmap: &'a mut QcBitmapAllocation,
    pool: &'a AllocationBudget,
}
// Use only under real parent CanonicalField<Qc>::with_payload and its original
// outer scope. This grants neither canonical outer-frame nor QC authority.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: production enclosing TC/Proposal/Evidence custody must reuse this kernel"
    )
)]
pub(crate) fn decode_qc_payload(
    payload: &mut Qc,
    ledger: &mut ChargedBuffer<AllocationCharge>,
    bitmap: &mut QcBitmapAllocation,
    pool: &AllocationBudget,
    bytes: &[u8],
) -> Result<(), DecodeIntoError<QcFieldError>> {
    if !ledger.belongs_to(pool) {
        return Err(DecodeIntoError::Destination(QcFieldError::Geometry));
    }
    let mut destination = QcFieldDestination {
        payload,
        ledger,
        bitmap,
        pool,
    };
    let (_, used) = Qc::decode_fields(bytes, &mut destination)?;
    if used != bytes.len() {
        return Err(norito::Error::LengthMismatch.into());
    }
    Ok(())
}
impl norito::core::FieldDestination for QcFields {
    type Error = QcFieldError;
}
impl norito::core::FieldDestination for QcFieldDestination<'_> {
    type Error = QcFieldError;
}
macro_rules! field {
    ($index:literal, $ty:ty, $slot:ident) => {
        impl DecodeField<$index, $ty> for QcFieldDestination<'_> {
            type Value = ();
            fn decode_field(
                &mut self,
                value: CanonicalField<'_, $ty>,
            ) -> Result<(), DecodeIntoError<QcFieldError>> {
                self.payload.$slot = inline::read_field(value).map_err(|e| match e {
                    DecodeIntoError::Codec(e) => DecodeIntoError::Codec(e),
                    DecodeIntoError::Destination(never) => match never {},
                })?;
                Ok(())
            }
        }
        impl DecodeField<$index, $ty> for QcFields {
            type Value = ();
            fn decode_field(
                &mut self,
                value: CanonicalField<'_, $ty>,
            ) -> Result<(), DecodeIntoError<QcFieldError>> {
                <QcFieldDestination<'_> as DecodeField<$index, $ty>>::decode_field(
                    &mut self.destination(),
                    value,
                )
            }
        }
    };
}
field!(0, VoteKind, kind);
field!(1, Hash32, instance);
field!(2, EpochId, epoch);
field!(3, u64, height);
field!(4, u64, view);
field!(5, Hash32, block_hash);
field!(6, Hash32, result);
field!(8, AggregateSignature, agg_sig);
struct BitmapFields<'a, 'b>(&'a mut QcFieldDestination<'b>);
impl norito::core::FieldDestination for BitmapFields<'_, '_> {
    type Error = QcFieldError;
}
impl DecodeField<0, Vec<u8>> for BitmapFields<'_, '_> {
    type Value = ();
    #[allow(unsafe_code)]
    fn decode_field(
        &mut self,
        value: CanonicalField<'_, Vec<u8>>,
    ) -> Result<(), DecodeIntoError<QcFieldError>> {
        value.with_payload(|bytes| {
            // This is the original raw Vec<u8> framing/count kernel. It runs
            // once; no second sequence read, element spans or alignment copy.
            let (raw, used) = <&[u8] as DecodeFromSlice>::decode_from_slice(bytes)?;
            // Same nominal u8 backing work as the owning raw Vec specialization.
            norito::core::reserve_decode_allocation(raw.len())?;
            if !self.0.bitmap.initialized {
                if self.0.ledger.as_slice().len() >= self.0.ledger.capacity() {
                    return Err(DecodeIntoError::Destination(QcFieldError::Geometry));
                }
                if self.0.bitmap.pending_charge.is_none() {
                    let layout = Layout::array::<u8>(raw.len()).map_err(|_| {
                        DecodeIntoError::Destination(QcFieldError::Bitmap(
                            ChargedBufferError::Admission(AllocationRefusal::DemandOverflow),
                        ))
                    })?;
                    let mut reservation = self.0.pool.try_reserve(layout).map_err(|e| {
                        DecodeIntoError::Destination(QcFieldError::Bitmap(
                            ChargedBufferError::Admission(e),
                        ))
                    })?;
                    self.0.bitmap.pending_charge = Some(
                        reservation
                            .try_split(layout)
                            .expect("exact original bitmap layout"),
                    );
                }
                let charge = self
                    .0
                    .bitmap
                    .pending_charge
                    .take()
                    .expect("original bitmap charge");
                let mut storage = match ChargedBuffer::<u8>::try_from_charge(raw.len(), charge) {
                    Ok(storage) => storage,
                    Err((charge, error)) => {
                        // An allocator refusal is not abandonment. Keep the same
                        // admitted charge even if the finite pool later shrinks.
                        self.0.bitmap.pending_charge = Some(charge);
                        return Err(DecodeIntoError::Destination(QcFieldError::BitmapBacking(
                            error,
                        )));
                    }
                };
                // Fixed allocation is fully initialized before transfer into the
                // sole actual Bitmap. No growth or clone separates its charge.
                for byte in raw {
                    storage.push_reserved(*byte);
                }
                // SAFETY: every original u8 is initialized. The Vec moves into
                // payload before its charge moves into the existing fixed ledger;
                // both are private and always dropped allocation-before-charge.
                let (values, charge) = unsafe { storage.into_allocation_parts() };
                self.0.payload.signers = Bitmap::from_bytes(values);
                self.0.ledger.push_reserved(charge);
                self.0.bitmap.initialized = true;
            } else {
                if self.0.payload.signers.as_bytes().len() != raw.len() {
                    return Err(DecodeIntoError::Destination(QcFieldError::Geometry));
                }
                self.0
                    .payload
                    .signers
                    .original_bytes_mut()
                    .copy_from_slice(raw);
            }
            // Original owning raw Vec storage is accounted and constructed
            // before its containing field rejects trailing bytes. Preserve the
            // enclosing-limit-before-trailer error precedence.
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            Ok(())
        })
    }
}
impl DecodeField<7, Bitmap> for QcFieldDestination<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        value: CanonicalField<'_, Bitmap>,
    ) -> Result<(), DecodeIntoError<QcFieldError>> {
        value.with_payload(|bytes| {
            let (_, used) = Bitmap::decode_fields(bytes, &mut BitmapFields(self))?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            Ok(())
        })
    }
}
impl DecodeField<7, Bitmap> for QcFields {
    type Value = ();
    fn decode_field(
        &mut self,
        value: CanonicalField<'_, Bitmap>,
    ) -> Result<(), DecodeIntoError<QcFieldError>> {
        <QcFieldDestination<'_> as DecodeField<7, Bitmap>>::decode_field(
            &mut self.destination(),
            value,
        )
    }
}
impl SerializePayload for QcFields {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        // The sole original Qc serializer owns field order, prefixes, nominal
        // children and array layout. There is no parallel borrowed wire record.
        self.payload.serialize(writer)
    }
}
impl PreparedRecordDestination<Qc> for QcFields {
    fn reset(&mut self) {}
}

struct QcOwner<'source> {
    payload: RetainedPayload<Qc>,
    source: &'source ChargedBuffer<u8>,
    range: SequenceSpan,
    // Keep the originally allocated protocol counters through every QC reader.
    _workspace: PreparedDecodeWorkspace,
}
/// Immutable QC transport retaining the same original source and every paid allocation.
///
/// A live decoded reader prevents its original charged source from being dropped:
///
/// ```compile_fail
/// use iroha_allocation::{AllocationBudget, ChargedBuffer};
/// use iroha_sumeragi::qc_custody::PreparedQc;
/// use norito::core::{DecodeLimits, SequenceSpan};
/// let pool = AllocationBudget::new(4096);
/// let source = ChargedBuffer::<u8>::new(0, &pool).unwrap();
/// let mut prepared = PreparedQc::new(&source, SequenceSpan { start: 0, end: 0 }, &pool).unwrap();
/// prepared.prepare(&source, SequenceSpan { start: 0, end: 0 }, DecodeLimits::new(4096,4096,4096,4096,64)).unwrap();
/// let reader = prepared.finish().unwrap();
/// drop(source);
/// let _ = reader.source_bytes();
/// ```
///
/// Cloning retains only the existing shared root. No Qc clone, mutable escape or
/// extraction API is supplied. Borrowed Qc clones made independently by a caller
/// remain that caller's separately funded obligation. This grants no authority.
pub struct NativeQc<'source>(ChargedShared<QcOwner<'source>>);
impl Clone for NativeQc<'_> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl NativeQc<'_> {
    /// Borrow the exact original decoded value, with its ledger still retained.
    pub fn get(&self) -> &Qc {
        self.0.payload.get()
    }
    /// Borrow its exact original initialized source range.
    pub fn source_bytes(&self) -> &[u8] {
        self.0
            .range
            .get(self.0.source.as_slice())
            .expect("retained original range")
    }
    /// Exact original shared root identity, independent of value equality.
    pub fn ptr_eq(left: &Self, right: &Self) -> bool {
        ChargedShared::ptr_eq(&left.0, &right.0)
    }
    /// Whether payload, ledger and root remain funded by this exact original pool.
    pub fn belongs_to(&self, pool: &AllocationBudget) -> bool {
        self.0.belongs_to(pool) && self.0.payload.belongs_to(pool) && self.0.source.belongs_to(pool)
    }
}
impl fmt::Debug for NativeQc<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(f)
    }
}

/// One source-bound incomplete QC field graph and its prepaid canonical controls.
///
/// Refusal preserves actual bitmap storage and its ledger for the same source.
/// The immutable source borrow lasts through this owner and all completed readers.
/// The original source cannot be mutated while an incomplete reader retains it:
///
/// ```compile_fail
/// use iroha_allocation::{AllocationBudget, ChargedBuffer};
/// use iroha_sumeragi::qc_custody::PreparedQc;
/// use norito::core::SequenceSpan;
/// let pool = AllocationBudget::new(4096);
/// let mut source = ChargedBuffer::<u8>::new(1, &pool).unwrap();
/// source.push_reserved(0);
/// let prepared = PreparedQc::new(&source, SequenceSpan { start: 0, end: 1 }, &pool).unwrap();
/// source.as_mut_slice()[0] = 1;
/// drop(prepared);
/// ```
///
/// TODO: compose this private field kernel into real TC/Proposal/Evidence/complete
/// field5 owners and production validation/publication/apply/recovery; this leaf
/// alone does not fund or qualify those enclosing graphs or caller heap placement.
pub struct PreparedQc<'source> {
    fields: QcFields,
    workspace: PreparedDecodeWorkspace,
    root: ReservedChargedShared<QcOwner<'source>>,
    source: &'source ChargedBuffer<u8>,
    range: SequenceSpan,
    authenticated: bool,
}
impl fmt::Debug for PreparedQc<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedQc")
            .field("range", &self.range)
            .field("authenticated", &self.authenticated)
            .finish_non_exhaustive()
    }
}
impl<'source> PreparedQc<'source> {
    /// Concrete ledger, shared root and two original protocol counter layouts.
    pub fn control_layouts() -> [Layout; 4] {
        let controls = PreparedDecodeWorkspace::allocation_layouts();
        [
            Layout::array::<AllocationCharge>(1).expect("one bounded charge"),
            ChargedShared::<QcOwner<'source>>::allocation_layout(),
            controls[0],
            controls[1],
        ]
    }
    /// Bind the exact original initialized input/range and prepay controls before decoding.
    ///
    /// # Errors
    /// Returns original finite-pool or physical control refusal, without consuming input.
    pub fn new(
        source: &'source ChargedBuffer<u8>,
        range: SequenceSpan,
        pool: &AllocationBudget,
    ) -> Result<Self, QcCustodyError> {
        if !source.belongs_to(pool) || range.get(source.as_slice()).is_err() {
            return Err(QcCustodyError::Source);
        }
        let mut reservation = pool
            .try_reserve_layouts(Self::control_layouts())
            .map_err(QcCustodyError::Admission)?;
        let ledger =
            ChargedBuffer::from_reservation(1, &mut reservation).map_err(QcCustodyError::Ledger)?;
        let root =
            ChargedShared::reserve_from(&mut reservation).map_err(QcCustodyError::Control)?;
        let workspace = PreparedDecodeWorkspace::from_reservation(pool, &mut reservation)
            .map_err(QcCustodyError::Scope)?;
        debug_assert_eq!(reservation.remaining_bytes(), 0);
        Ok(Self {
            fields: QcFields::new(pool, ledger),
            workspace,
            root,
            source,
            range,
            authenticated: false,
        })
    }
    /// Authenticate the complete original frame, then run the unchanged structural validator.
    ///
    /// # Errors
    /// Source/range substitution, original codec/scope/backing refusal, or structural limit.
    pub fn prepare(
        &mut self,
        source: &'source ChargedBuffer<u8>,
        range: SequenceSpan,
        limits: DecodeLimits,
    ) -> Result<(), QcCustodyError> {
        self.authenticated = false;
        if !std::ptr::eq(source, self.source)
            || range != self.range
            || !source.belongs_to(&self.fields.pool)
        {
            return Err(QcCustodyError::Source);
        }
        let frame = range
            .get(source.as_slice())
            .map_err(|_| QcCustodyError::Source)?;
        self.workspace
            .decode_canonical_into::<Qc, _>(frame, limits, &mut self.fields)
            .map_err(QcCustodyError::Decode)?;
        // Full header, checksum, schema, padding, consumed length and exact
        // canonical reserialization all succeeded before this check runs.
        check_qc(&self.fields.payload).map_err(QcCustodyError::Structural)?;
        self.authenticated = true;
        Ok(())
    }
    /// Publish the same original graph and charges into its already paid immutable root.
    ///
    /// # Errors
    /// Incomplete authentication or foreign charge ledger; no new allocation is made.
    #[allow(unsafe_code)]
    pub fn finish(self) -> Result<NativeQc<'source>, (Self, QcCustodyError)> {
        if !self.authenticated {
            return Err((self, QcCustodyError::Incomplete));
        }
        let Self {
            fields,
            workspace,
            root,
            source,
            range,
            authenticated,
        } = self;
        let QcFields {
            payload,
            ledger,
            bitmap,
            pool,
        } = fields;
        debug_assert!(bitmap.pending_charge.is_none());
        debug_assert!(bitmap.initialized);
        // SAFETY: the sole heap field is the original exact fixed Bitmap Vec,
        // paired with one original ledger charge; both remain private and no
        // mutation/extraction can separate them after sharing.
        match unsafe { RetainedPayload::try_new(payload, ledger, &pool) } {
            Ok(payload) => Ok(NativeQc(root.initialize(QcOwner {
                payload,
                source,
                range,
                _workspace: workspace,
            }))),
            Err((payload, ledger, error)) => Err((
                Self {
                    fields: QcFields {
                        payload,
                        ledger,
                        bitmap,
                        pool,
                    },
                    workspace,
                    root,
                    source,
                    range,
                    authenticated,
                },
                QcCustodyError::Retention(error),
            )),
        }
    }
}

#[cfg(test)]
mod tests;
