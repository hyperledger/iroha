//! Canonical binary and JSON Quantity decoding into exact original prepaid native digits.
//!
//! This leaf is not a frame authenticator or an admission decision. The enclosing
//! prepared record walker must preserve the advertised flags, decode scope and
//! exact canonical frame check. Planning never constructs a `BigInt` or normalizes
//! a mantissa; the final concrete owner has no Clone or safe extraction API.

use core::convert::Infallible;
use iroha_allocation::{
    AllocationBudget, AllocationCharge, ChargedBuffer, ChargedBufferError,
    ChargedBufferFromChargeError,
};
use norito::core::{
    CanonicalField, DecodeField, DecodeIntoError, DecodeRecordFields, FieldDestination,
};

use super::*;

mod funded_arithmetic;

/// Inline geometry obtained from the sole canonical numeric field kernel.
///
/// This is non-authorizing scratch. It cannot certify a signed input, source
/// identity, fee intent or original bytes. Each actual fill rechecks those bytes.
#[derive(Clone, Copy, Debug)]
pub struct QuantityDecodePlan {
    magnitude: [u8; MAX_MANTISSA_BYTES],
    digit_count: usize,
    scale: u32,
}

type MantissaRetainer<'retain, E> = dyn FnMut(&[u8]) -> Result<(), DecodeIntoError<E>> + 'retain;

struct NumericPlanFields<'retain, E> {
    magnitude: [u8; MAX_MANTISSA_BYTES],
    magnitude_len: usize,
    negative: bool,
    signed_len: usize,
    scale: u32,
    retain_mantissa: &'retain mut MantissaRetainer<'retain, E>,
}
impl<'retain, E> NumericPlanFields<'retain, E> {
    fn new(retain_mantissa: &'retain mut MantissaRetainer<'retain, E>) -> Self {
        Self {
            magnitude: [0; MAX_MANTISSA_BYTES],
            magnitude_len: 0,
            negative: false,
            signed_len: 0,
            scale: 0,
            retain_mantissa,
        }
    }
}
impl<E> FieldDestination for NumericPlanFields<'_, E> {
    type Error = E;
}
impl<E> DecodeField<0, BigInt> for NumericPlanFields<'_, E> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, BigInt>,
    ) -> Result<(), DecodeIntoError<E>> {
        field.with_payload(|bytes| {
            let (payload, used) = crate::bigint::canonical_twos_payload(bytes)?;
            if used != bytes.len() {
                return Err(Error::LengthMismatch.into());
            }
            // The shared field relation reaches this synchronous owner boundary
            // before scale or numeric-domain validation. No complete-value preview
            // can move a later deterministic error ahead of original admission.
            (self.retain_mantissa)(payload)?;
            self.signed_len = payload.len();
            self.negative = payload.last().is_some_and(|byte| *byte & 0x80 != 0);
            // A wider canonical BigInt must survive through scale decoding: the
            // ordinary Numeric decoder checks scale before its 512-bit domain.
            if payload.len() <= MAX_MANTISSA_BYTES {
                self.magnitude[..payload.len()].copy_from_slice(payload);
                if self.negative {
                    let mut carry = true;
                    for byte in &mut self.magnitude[..payload.len()] {
                        let (next, overflow) = (!*byte).overflowing_add(u8::from(carry));
                        *byte = next;
                        carry = overflow;
                    }
                }
                self.magnitude_len = self
                    .magnitude
                    .iter()
                    .rposition(|&byte| byte != 0)
                    .map_or(0, |index| index + 1);
            }
            Ok(())
        })
    }
}
impl<E> DecodeField<1, u32> for NumericPlanFields<'_, E> {
    type Value = ();
    fn decode_field(&mut self, field: CanonicalField<'_, u32>) -> Result<(), DecodeIntoError<E>> {
        self.scale = field.with_payload(|bytes| {
            let (scale, used) = <u32 as norito::core::DecodeFromSlice>::decode_from_slice(bytes)?;
            if used != bytes.len() {
                return Err(Error::LengthMismatch.into());
            }
            Ok(scale)
        })?;
        Ok(())
    }
}

impl QuantityDecodePlan {
    /// Plan one complete canonical Quantity payload without constructing its graph.
    ///
    /// The caller supplies the original field context, flags and bounded decoder
    /// scope. Borrowed framing checks the inherited field-length and depth limits
    /// without charging storage. Planning neither constructs nor admits
    /// native-digit backing; filling admits its actual layout in that same scope.
    /// This rejects, rather than normalizes, negative quantities, excess
    /// scale/width, fractional trailing zeroes and malformed field framing.
    ///
    /// # Errors
    /// Returns the original field/decoder cause or the same ordinary scalar
    /// rejection. Complete outer frame authentication is the caller's obligation.
    pub fn decode_payload(bytes: &[u8]) -> Result<Self, Error> {
        Self::decode_payload_with_probe(bytes, false)
    }
    fn decode_payload_with_probe(bytes: &[u8], probe_backing: bool) -> Result<Self, Error> {
        let mut retain_mantissa = |payload: &[u8]| {
            if probe_backing {
                crate::bigint::CanonicalNativeDigits::from_payload(payload)
                    .reserve_decode_backing()?;
            }
            Ok::<_, DecodeIntoError<Infallible>>(())
        };
        let mut fields = NumericPlanFields::new(&mut retain_mantissa);
        let (_, used) = scale_::NumericScaleHelper::decode_fields(bytes, &mut fields)
            .map_err(DecodeIntoError::into_codec)?;
        if used != bytes.len() {
            return Err(Error::LengthMismatch);
        }
        fields.finish()
    }

    /// Exact final native-digit layout; zero keeps a zero-byte original charge.
    #[must_use]
    pub fn allocation_layout(&self) -> Layout {
        Layout::array::<NativeBigDigit>(self.digit_count)
            .expect("the bounded 512-bit native-digit array is representable")
    }
}

impl<E> NumericPlanFields<'_, E> {
    // The original Quantity plan and the one-pass owner use exactly this scalar
    // relation. Canonical failures still own their existing diagnostic String;
    // this primitive does not claim physical admission for that error storage.
    fn finish(self) -> Result<QuantityDecodePlan, Error> {
        if self.scale > MAX_DECIMAL_SCALE {
            return Err(Error::Message(format!(
                "invalid numeric: {}",
                NumericError::ScaleTooLarge
            )));
        }
        if self.signed_len > MAX_MANTISSA_BYTES {
            return Err(Error::Message(format!(
                "invalid numeric: {}",
                NumericError::MantissaTooLarge
            )));
        }
        let mut words = [0_u64; MAX_MANTISSA_BYTES / core::mem::size_of::<u64>()];
        for (word, bytes) in words.iter_mut().zip(self.magnitude.chunks_exact(8)) {
            *word = u64::from_le_bytes(bytes.try_into().expect("fixed eight-byte chunk"));
        }
        let limbs = self.magnitude_len.div_ceil(8).max(1);
        infallible_observed(validate_decimal_parts_observed(
            self.scale,
            self.magnitude_len == 0,
            u16::try_from(limbs).expect("512-bit domain fits limb count"),
            || magnitude_divisible_by_ten(words.iter().rev().copied()),
            &mut |_| Ok::<_, Infallible>(()),
        ))
        .map_err(|error| Error::Message(format!("invalid numeric: {error}")))?;
        if self.negative {
            return Err(Error::Message(
                NumericOperationError::NegativeQuantity.to_string(),
            ));
        }
        Ok(QuantityDecodePlan {
            magnitude: self.magnitude,
            digit_count: self.magnitude_len.div_ceil(UNBOUNDED_BIGINT_DIGIT_BYTES),
            scale: self.scale,
        })
    }
}

/// Canonical Quantity failure or original-pool admission at its mantissa boundary.
#[derive(Debug)]
pub enum QuantityDecodeAdmissionError {
    /// Original field, cumulative work or scalar validation cause.
    Codec(Error),
    /// Exact native-digit backing could not be admitted or physically allocated.
    Allocation(ChargedBufferError),
    /// A complete derived field walk did not initialize its mantissa destination.
    /// This is a local invariant failure, not a protocol-invalid scalar.
    Incomplete,
}
impl From<Error> for QuantityDecodeAdmissionError {
    fn from(error: Error) -> Self {
        Self::Codec(error)
    }
}
impl From<DecodeIntoError<ChargedBufferError>> for QuantityDecodeAdmissionError {
    fn from(error: DecodeIntoError<ChargedBufferError>) -> Self {
        match error {
            DecodeIntoError::Codec(error) => Self::Codec(error),
            DecodeIntoError::Destination(error) => Self::Allocation(error),
        }
    }
}
impl core::fmt::Display for QuantityDecodeAdmissionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Codec(error) => error.fmt(formatter),
            Self::Allocation(error) => error.fmt(formatter),
            Self::Incomplete => formatter.write_str("unfinished one-pass quantity destination"),
        }
    }
}
impl std::error::Error for QuantityDecodeAdmissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Codec(error) => Some(error),
            Self::Allocation(error) => Some(error),
            Self::Incomplete => None,
        }
    }
}

/// Original JSON decoder cause or original-pool backing admission refusal.
///
/// The text and native digits use the caller's same finite pool. This local error
/// retains the original physical release observation; it is not protocol rejection.
#[derive(Debug)]
pub enum QuantityJsonAdmissionError {
    /// Original string, cumulative decode-work or decimal-domain failure.
    Json(json::Error),
    /// Exact temporary text or native-digit allocation could not be admitted.
    Allocation(ChargedBufferError),
}
impl From<json::Error> for QuantityJsonAdmissionError {
    fn from(error: json::Error) -> Self {
        Self::Json(error)
    }
}
impl From<ChargedBufferError> for QuantityJsonAdmissionError {
    fn from(error: ChargedBufferError) -> Self {
        Self::Allocation(error)
    }
}
impl core::fmt::Display for QuantityJsonAdmissionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Json(error) => core::fmt::Display::fmt(error, formatter),
            Self::Allocation(error) => core::fmt::Display::fmt(error, formatter),
        }
    }
}
impl std::error::Error for QuantityJsonAdmissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Allocation(error) => Some(error),
        }
    }
}

struct QuantityJsonText(ChargedBuffer<u8>);
impl AsMut<[u8]> for QuantityJsonText {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

/// Original-pool or exact-layout refusal before any Quantity field is decoded.
///
/// The constructor returns this inline cause beside the unchanged original charge.
/// Canonical decoding and destination geometry errors belong to the later fill.
#[derive(Clone, Copy, Debug)]
pub enum QuantityBackingError {
    /// The retained physical allocation is charged to a different finite pool.
    ForeignPool,
    /// Exact-layout validation or physical allocator refusal, without reacquisition.
    Allocation(ChargedBufferFromChargeError),
}
impl core::fmt::Display for QuantityBackingError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ForeignPool => formatter.write_str("quantity backing belongs to another pool"),
            Self::Allocation(error) => error.fmt(formatter),
        }
    }
}
impl std::error::Error for QuantityBackingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Allocation(error) => Some(error),
            Self::ForeignPool => None,
        }
    }
}

/// Exact canonical decoding refusal or mismatch with the retained destination.
#[derive(Debug)]
pub enum QuantityDestinationError {
    /// Canonical scalar/decode-scope cause, left intact for the enclosing observer.
    Codec(Error),
    /// The actual input cannot fill this exact previously admitted backing.
    Geometry {
        /// Previously admitted native-digit count.
        admitted_digits: usize,
        /// Exact count required by the original canonical mantissa.
        required_digits: usize,
    },
}
impl core::fmt::Display for QuantityDestinationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Codec(error) => error.fmt(formatter),
            Self::Geometry {
                admitted_digits,
                required_digits,
            } => write!(
                formatter,
                "quantity requires {required_digits} native digits, admitted {admitted_digits}"
            ),
        }
    }
}
impl std::error::Error for QuantityDestinationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Codec(error) => Some(error),
            Self::Geometry { .. } => None,
        }
    }
}

/// Fully prepaid destination whose final native backing never grows or is replaced.
///
/// A failed fill clears validity only and retains the original pointer, layout
/// and pool charge. Its contents are never interpreted until the sole canonical
/// field relation succeeds. Caller-supplied partial records retain this owner on
/// refusal and retry against the same source bytes without refunding its charge.
pub struct PreparedQuantityDecode {
    digits: ChargedBuffer<NativeBigDigit>,
    scale: Option<u32>,
}
impl PreparedQuantityDecode {
    /// Decode once and retain exact native digits from the original finite pool.
    ///
    /// The sole canonical field walk validates the signed mantissa and consumes
    /// its nominal storage work, then prepays and fills its actual native-digit
    /// backing before visiting scale. Later scale/domain failure destroys those
    /// digits before physical refund; successful prefix logical work is never
    /// reset or refunded. No whole-Quantity preview or second decode is used.
    ///
    /// The caller supplies the original flags/field context and retains the
    /// enclosing source, decoder controls and any complete diagnostic owner.
    /// In particular existing `Error::Message` strings are not funded here. A
    /// refusal retains no prepared backing across a later execution attempt;
    /// retry uses the same borrowed source and consumes new cumulative work.
    ///
    /// # Errors
    /// Preserves the original codec cause or distinct physical admission failure.
    /// An incomplete derived walk is a local invariant failure.
    pub fn try_decode_payload(
        bytes: &[u8],
        budget: &AllocationBudget,
    ) -> Result<ChargedQuantity, QuantityDecodeAdmissionError> {
        let mut retained = None;
        Self::decode_payload_retained(bytes, budget, &mut retained)?;
        retained
            .ok_or(QuantityDecodeAdmissionError::Incomplete)?
            .finish()
            .map_err(|_| QuantityDecodeAdmissionError::Incomplete)
    }

    /// Recheck canonical Quantity fields without replacing retained native digits.
    ///
    /// Uses the same scalar walk and nominal backing admission as an original
    /// attempt. The enclosing owner authenticates its unchanged source and keeps
    /// the original Quantity allocation; this function creates no value graph.
    ///
    /// # Errors
    /// Preserves every original field, cumulative-work and numeric-domain error.
    pub fn recheck_payload(bytes: &[u8]) -> Result<(), Error> {
        QuantityDecodePlan::decode_payload_with_probe(bytes, true).map(|_| ())
    }

    /// Fill or resume the original mantissa backing through the canonical field walk.
    ///
    /// Admission remains before scale/domain validation. A later refusal leaves
    /// the exact digits in `destination`, without refund, clone or replacement.
    /// Re-entry consumes the ordinary logical work in the enclosing original
    /// context; it does not reset counters or change any ceiling. The enclosing
    /// record owner must authenticate the unchanged source before each call.
    ///
    /// # Errors
    /// Returns the unchanged codec, physical admission or destination cause.
    pub fn decode_payload_retained(
        bytes: &[u8],
        budget: &AllocationBudget,
        destination: &mut Option<Self>,
    ) -> Result<(), QuantityDecodeAdmissionError> {
        if let Some(retained) = destination.as_mut() {
            if !retained.belongs_to(budget) {
                return Err(QuantityDecodeAdmissionError::Incomplete);
            }
            retained.reset();
        }
        let plan = {
            let mut retain_mantissa = |payload: &[u8]| {
                let canonical = crate::bigint::CanonicalNativeDigits::from_payload(payload);
                canonical.reserve_decode_backing()?;
                if destination.is_none() {
                    let digits = ChargedBuffer::new(canonical.as_slice().len(), budget)
                        .map_err(DecodeIntoError::Destination)?;
                    *destination = Some(Self {
                        digits,
                        scale: None,
                    });
                }
                let retained = destination
                    .as_mut()
                    .ok_or_else(|| DecodeIntoError::Codec(Error::LengthMismatch))?;
                if retained.digits.capacity() != canonical.as_slice().len() {
                    return Err(DecodeIntoError::Codec(Error::LengthMismatch));
                }
                if retained.digits.as_slice().is_empty() {
                    for &digit in canonical.as_slice() {
                        retained.digits.push_reserved(digit);
                    }
                } else if retained.digits.as_slice() != canonical.as_slice() {
                    return Err(DecodeIntoError::Codec(Error::LengthMismatch));
                }
                Ok::<_, DecodeIntoError<ChargedBufferError>>(())
            };
            let mut fields = NumericPlanFields::new(&mut retain_mantissa);
            let (_, used) = scale_::NumericScaleHelper::decode_fields(bytes, &mut fields)
                .map_err(QuantityDecodeAdmissionError::from)?;
            if used != bytes.len() {
                return Err(Error::LengthMismatch.into());
            }
            fields.finish()?
        };
        destination
            .as_mut()
            .ok_or(QuantityDecodeAdmissionError::Incomplete)?
            .scale = Some(plan.scale);
        Ok(())
    }

    /// Physically allocate the exact final magnitude before decoding a value.
    ///
    /// # Errors
    /// Returns the same charge on foreign-pool, layout or allocator refusal. No
    /// canonical value has been consumed, cloned or materialized on failure.
    pub fn try_from_charge(
        plan: &QuantityDecodePlan,
        budget: &AllocationBudget,
        charge: AllocationCharge,
    ) -> Result<Self, (AllocationCharge, QuantityBackingError)> {
        if !charge.belongs_to(budget) {
            return Err((charge, QuantityBackingError::ForeignPool));
        }
        let mut digits = ChargedBuffer::try_from_charge(plan.digit_count, charge)
            .map_err(|(charge, error)| (charge, QuantityBackingError::Allocation(error)))?;
        // Initialize every fixed native digit before exposing its original slice;
        // append remains inside exact admitted capacity and invokes no graph Clone.
        let zeroes = [0 as NativeBigDigit; MAX_MANTISSA_BYTES / UNBOUNDED_BIGINT_DIGIT_BYTES];
        digits
            .append(&zeroes[..plan.digit_count])
            .expect("fixed native-digit initialization fills exact admitted capacity");
        Ok(Self {
            digits,
            scale: None,
        })
    }

    /// Decode into the same fixed backing; no proof/signature/fee checks are bypassed.
    ///
    /// # Errors
    /// Preserves canonical/decoder causes and exact storage geometry. Validity is
    /// cleared before every attempt; any failure keeps all original physical custody.
    pub fn decode_payload(&mut self, bytes: &[u8]) -> Result<(), QuantityDestinationError> {
        self.scale = None;
        let plan = QuantityDecodePlan::decode_payload_with_probe(bytes, true)
            .map_err(QuantityDestinationError::Codec)?;
        if plan.digit_count != self.digits.capacity() {
            return Err(QuantityDestinationError::Geometry {
                admitted_digits: self.digits.capacity(),
                required_digits: plan.digit_count,
            });
        }
        // The sole mantissa-field probe already consumed the inherited logical
        // scope exactly once. Planning/physical backing do not mint logical credit.
        for (digit, bytes) in self
            .digits
            .as_mut_slice()
            .iter_mut()
            .zip(plan.magnitude.chunks(UNBOUNDED_BIGINT_DIGIT_BYTES))
        {
            let mut native = [0_u8; UNBOUNDED_BIGINT_DIGIT_BYTES];
            native.copy_from_slice(bytes);
            *digit = NativeBigDigit::from_le_bytes(native);
        }
        debug_assert!(
            self.digits
                .as_slice()
                .last()
                .is_none_or(|&digit| digit != 0)
        );
        self.scale = Some(plan.scale);
        Ok(())
    }

    /// Clear semantic validity while retaining every original allocation and charge.
    pub fn reset(&mut self) {
        self.scale = None;
    }

    /// Whether the same original finite pool owns this prepared backing.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.digits.belongs_to(budget)
    }

    /// Move the original complete backing into its concrete canonical Quantity owner.
    ///
    /// # Errors
    /// Returns the unchanged destination unless a complete canonical fill succeeded.
    /// No normalization, conversion allocation, refund or new admission occurs here.
    pub fn finish(self) -> Result<ChargedQuantity, Self> {
        let Some(scale) = self.scale else {
            return Err(self);
        };
        let Self { digits, scale: _ } = self;
        Ok(Self::bind_complete(digits, scale))
    }

    #[allow(unsafe_code)]
    fn bind_complete(digits: ChargedBuffer<NativeBigDigit>, scale: u32) -> ChargedQuantity {
        // SAFETY: filled digits are minimal and fill exact capacity. The pinned
        // native-digit constructor therefore preserves this Vec allocation. The
        // concrete immutable value and original charge are immediately paired;
        // no fallible work follows transfer. Field order drops value before charge.
        let (digits, charge) = unsafe { digits.into_allocation_parts() };
        let mantissa = BigInt::from_prepared_quantity_digits(digits);
        let value = Quantity(Numeric { mantissa, scale });
        ChargedQuantity { value, charge }
    }
}

/// Immutable Quantity with the original charge for its actual native-digit allocation.
///
/// The value is destroyed before its charge. Independent ordinary clones from a
/// borrow are unfunded; this concrete owner itself does not implement Clone.
pub struct ChargedQuantity {
    value: Quantity,
    charge: AllocationCharge,
}
impl ChargedQuantity {
    /// Decode one JSON Quantity into its actual original-pool native-digit owner.
    ///
    /// The existing string/escape and decimal kernels keep their syntax and logical
    /// work order. Exact text and native digits are admitted before allocation; the
    /// temporary text retires before return and the immutable value owns its digits'
    /// original charge. Zero has no digit allocation and keeps a zero-sized charge.
    /// No ordinary Quantity decode, graph clone or binary reencoding occurs here.
    ///
    /// The caller retains the enclosing source, keys, record/control storage and same
    /// cumulative decoder context. It must defer refunds beyond any State or storage
    /// guards. This leaf retains no partially parsed text/digits on failure and does
    /// not close the admitted `NPoS` record/key or later authority-graph obligations.
    ///
    /// # Errors
    /// Preserves the original JSON/resource cause or exact pool/allocator refusal.
    #[allow(unsafe_code)]
    pub fn try_decode_json(
        parser: &mut json::Parser<'_>,
        budget: &AllocationBudget,
    ) -> Result<Self, QuantityJsonAdmissionError> {
        let mut preflight = *parser;
        preflight.skip_string_bounded(MAX_CANONICAL_QUANTITY_TEXT_BYTES)?;
        // Declare the ledger before text/value so every failure destroys physical
        // storage before its original charge. No charge is inferred after decoding.
        let mut digit_charge = None;
        let text = parser.parse_string_with_buffer(|length| {
            let mut bytes = ChargedBuffer::new(length, budget)?;
            for _ in 0..length {
                bytes.push_reserved(0);
            }
            Ok::<_, QuantityJsonAdmissionError>(QuantityJsonText(bytes))
        })?;
        let source = core::str::from_utf8(text.0.as_slice())
            .expect("the shared JSON string decoder produces valid UTF-8");
        let value = Quantity::from_canonical_json_text_with(source, |magnitude| {
            let allocate = |layout: Layout| {
                let mut reservation = budget
                    .try_reserve(layout)
                    .map_err(ChargedBufferError::Admission)?;
                let charge = reservation
                    .try_split(layout)
                    .expect("the original reservation covers its exact native-digit layout");
                // SAFETY: the shared mantissa kernel supplies the checked nonzero
                // exact native-digit layout. Credit already covers this allocator
                // request; the kernel immediately takes the pointer into its Vec.
                let pointer = unsafe { std::alloc::alloc(layout) };
                if pointer.is_null() {
                    return Err(ChargedBufferError::Allocator {
                        requested_bytes: layout.size(),
                    }
                    .into());
                }
                digit_charge = Some(charge);
                Ok::<_, QuantityJsonAdmissionError>(pointer)
            };
            // SAFETY: the callback returns precisely the original admitted global
            // allocation, or its typed refusal before supplying a pointer. The
            // unchanged kernel fills and owns it without growth or replacement.
            unsafe { quantity_mantissa_from_canonical_le_bytes_with(magnitude, allocate) }
        })?;
        let charge = if let Some(charge) = digit_charge {
            charge
        } else {
            debug_assert!(value.is_zero());
            let empty = ChargedBuffer::<NativeBigDigit>::new(0, budget)?;
            // SAFETY: zero owns no allocation; pair its same-pool zero charge
            // immediately with the already allocation-free canonical zero.
            let (_, charge) = unsafe { empty.into_allocation_parts() };
            charge
        };
        Ok(Self { value, charge })
    }

    /// Borrow the canonical value without separating backing and credit custody.
    #[must_use]
    pub fn get(&self) -> &Quantity {
        &self.value
    }

    /// Check exact original pool identity, independent of equal configured limits.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.charge.belongs_to(budget)
    }

    /// Transfer this concrete Quantity and its original charge into a closed ledger.
    ///
    /// # Safety
    /// Immediately pair both in a move-only owner. The original canonical mantissa
    /// backing must never be replaced, grown or cloned while reusing this charge.
    /// Destroy the complete value before refund, including all refusal/unwind paths.
    #[allow(unsafe_code)]
    pub unsafe fn into_allocation_parts(self) -> (Quantity, AllocationCharge) {
        let Self { value, charge } = self;
        (value, charge)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "prepared_quantity/json_tests.rs"]
mod json_tests;
