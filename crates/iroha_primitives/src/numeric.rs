//! Exact decimal arithmetic with a signed 512-bit mantissa and bounded scale.
//!
//! This replaces the previous fixed-width, non-negative decimal. Mantissas are
//! stored in [`crate::bigint::BigInt`] and allow negative values; scale counts
//! fractional digits (e.g., `1.88` => mantissa `188`, scale `2`).
//!
//! Encoding note: `Numeric` serializes as a helper carrying `(mantissa, scale)`.
//! The mantissa is a raw [`crate::bigint::BigInt`] integer (no decimal scale
//! is embedded in the integer), and the scale is stored separately as a `u32`.
use crate::bigint::{BigInt, BigIntAdmissionCloneError};
mod prepared_quantity;
use core::{cmp::Ordering, str::FromStr};
pub use iroha_primitives_derive::numeric;
use norito::{
    Archived, DeserializePayload, Error, SerializePayload,
    json::{self, FastJsonWrite, JsonDeserialize, JsonSerialize},
};
use num_bigint::{BigInt as UnboundedBigInt, BigUint as UnboundedBigUint, Sign as UnboundedSign};
use num_traits::{One as _, Signed as _, Zero as _};
pub use prepared_quantity::{
    ChargedQuantity, PreparedQuantityDecode, QuantityBackingError, QuantityDecodeAdmissionError,
    QuantityDecodePlan, QuantityDestinationError, QuantityJsonAdmissionError,
};
use std::{
    alloc::Layout,
    string::{String, ToString},
    vec::Vec,
};
/// Width of the signed two's-complement domain shared by Kotodama `int`,
/// `decimal` mantissas, and `quantity` mantissas.
pub const MAX_MANTISSA_BITS: usize = 512;
/// Maximum canonical two's-complement mantissa payload length.
pub const MAX_MANTISSA_BYTES: usize = MAX_MANTISSA_BITS / 8;
/// Maximum number of fractional decimal digits in a canonical decimal.
pub const MAX_DECIMAL_SCALE: u32 = 28;
/// Decimal digits needed to spell the positive half of the signed 512-bit mantissa domain.
const MAX_QUANTITY_MANTISSA_DECIMAL_DIGITS: usize = 154;
/// Longest canonical quantity text: 154 mantissa digits and one decimal point.
const MAX_CANONICAL_QUANTITY_TEXT_BYTES: usize = MAX_QUANTITY_MANTISSA_DECIMAL_DIGITS + 1;
// The pinned `num-bigint` fork stores magnitude digits as u64 on 64-bit targets
// and u32 otherwise. Use that exact native type for a charged decode allocation.
#[cfg(target_pointer_width = "64")]
type NativeBigDigit = u64;
#[cfg(not(target_pointer_width = "64"))]
type NativeBigDigit = u32;
const UNBOUNDED_BIGINT_DIGIT_BYTES: usize = core::mem::size_of::<NativeBigDigit>();
/// Maximum number of factors accepted by aggregate decimal-product helpers.
///
/// Each factor is individually bounded to a 512-bit canonical mantissa, but the helpers
/// deliberately retain an unbounded conceptual intermediate until their single final normalization
/// or rounding step. Bounding the factor inventory prevents attacker-controlled iterators from
/// growing that intermediate without limit.
pub const MAX_DECIMAL_PRODUCT_FACTORS: usize = 64;
/// Canonical exact decimal with a bounded signed mantissa and scale.
///
/// The finite set of values of type [`Numeric`] are of the form $m / 10^e$, where `m` is in
/// `-2^511..=2^511-1` and `e` is in `[0, 28]`. The mantissa `m` is stored as a
/// [`crate::bigint::BigInt`], while the scale `e` is carried separately. Public constructors strip
/// fractional trailing zeroes, including reducing every zero to scale zero, so equality, ordering,
/// hashing, map keys, and serialization all observe one representation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, norito::NoritoSchema)]
#[norito_schema(name = "iroha_primitives::numeric::Numeric")]
pub struct Numeric {
    mantissa: BigInt,
    scale: u32,
}
/// Canonical non-negative decimal for asset and resource quantities.
///
/// `Quantity` is nominal: it cannot contain negative values or noncanonical decimal
/// representations, so ledger-domain mistakes are rejected before a value reaches storage or
/// hashing. The name deliberately does not imply currency: an Iroha asset may represent money, a
/// commodity, a vote, or a right.
#[repr(transparent)]
#[derive(Clone, Debug, PartialEq, Eq, Hash, norito::NoritoSchema)]
#[norito_schema(name = "iroha_primitives::numeric::Quantity")]
pub struct Quantity(Numeric);

#[path = "numeric/quantity_accumulator.rs"]
mod quantity_accumulator;
pub use quantity_accumulator::QuantityAccumulator;
/// Maximum number of fractional digits accepted for XOR-denominated values.
///
/// XOR's ledger definition permits nanounit precision. Keeping this limit in the nominal type
/// prevents independent services from silently choosing incompatible fixed-unit conventions.
pub const XOR_QUANTITY_SCALE: u32 = 9;
/// Canonical XOR-denominated quantity.
///
/// This wrapper carries the same exact decimal value as [`Quantity`] while enforcing XOR's scale
/// policy at every construction and wire-decoding boundary. It is intentionally unit-neutral:
/// callers exchange decimal XOR values, never an implicit micro- or nano-unit integer.
#[repr(transparent)]
#[derive(Clone, Debug, PartialEq, Eq, Hash, norito::NoritoSchema)]
#[norito_schema(name = "iroha_primitives::numeric::XorQuantity")]
pub struct XorQuantity(Quantity);
/// Define maximum precision and scale for given number.
///
/// Runtime-supplied fractional scales must use [`NumericSpec::try_fractional`];
/// there is deliberately no infallible `From<Option<u32>>` escape hatch.
///
/// ```compile_fail
/// use iroha_primitives::numeric::NumericSpec;
///
/// let _invalid: NumericSpec = Some(29_u32).into();
/// ```
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    Hash,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_primitives::numeric::NumericSpec")]
pub struct NumericSpec {
    /// Count of decimal digits in the fractional part.
    /// Currently only positive scale up to 28 decimal points is supported.
    scale: Option<u32>,
}

impl SerializePayload for NumericSpec {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), Error> {
        SerializePayload::serialize(&self.scale, writer)
    }
}
// Bridge Norito slice-based decoding for Numeric through the same helper used
// by its codec implementation. Decoding the helper directly preserves the
// exact prefix length when Numeric is embedded in a larger packed record.
impl<'a> norito::core::DecodeFromSlice<'a> for Numeric {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let (helper, used) =
            <scale_::NumericScaleHelper as norito::core::DecodeFromSlice>::decode_from_slice(
                bytes,
            )?;
        let value = Self::try_new_raw(helper.mantissa, helper.scale)
            .map_err(|error| norito::core::Error::Message(format!("invalid numeric: {error}")))?;
        value
            .validate_decimal()
            .map_err(|error| norito::core::Error::Message(format!("invalid numeric: {error}")))?;
        Ok((value, used))
    }
}

impl<'a> DeserializePayload<'a> for NumericSpec {
    fn deserialize(archived: &'a Archived<NumericSpec>) -> Self {
        Self::try_deserialize(archived).expect("invalid numeric specification")
    }
    fn try_deserialize(archived: &'a Archived<NumericSpec>) -> Result<Self, Error> {
        let scale_arch: &Archived<Option<u32>> = archived.cast();
        let scale = <Option<u32> as DeserializePayload>::try_deserialize(scale_arch)?;
        Self::try_from_scale(scale)
            .map_err(|error| Error::Message(format!("invalid numeric specification: {error}")))
    }
}
impl FastJsonWrite for NumericSpec {
    fn write_json(&self, out: &mut String) {
        out.push('{');
        out.push_str("\"scale\":");
        if let Some(scale) = self.scale {
            scale.json_serialize(out);
        } else {
            out.push_str("null");
        }
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), json::BoundedJsonError> {
            out.push_str("{\"scale\":")?;
            self.scale.json_serialize_to(out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}
impl JsonDeserialize for NumericSpec {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let mut visitor = json::MapVisitor::new(parser)?;
        let mut scale: Option<Option<u32>> = None;
        while let Some(key) = visitor.next_key()? {
            match key {
                json::KeyRef::Borrowed("scale") => {
                    if scale.is_some() {
                        return Err(json::Error::duplicate_field("scale"));
                    }
                    let value = visitor.parse_value::<Option<u32>>()?;
                    scale = Some(value);
                }
                json::KeyRef::Owned(ref key) if key == "scale" => {
                    if scale.is_some() {
                        return Err(json::Error::duplicate_field("scale"));
                    }
                    let value = visitor.parse_value::<Option<u32>>()?;
                    scale = Some(value);
                }
                _ => visitor.skip_value()?,
            }
        }
        visitor.finish()?;
        NumericSpec::try_from_scale(scale.unwrap_or(None)).map_err(|error| {
            json::Error::InvalidField {
                field: "scale".into(),
                message: error.to_string(),
            }
        })
    }
}
/// Error occurred during creation of [`Numeric`]
#[derive(Debug, Clone, Copy, PartialEq, Eq, displaydoc::Display, thiserror::Error)]
pub enum NumericError {
    /// Mantissa exceeds allowed range
    MantissaTooLarge,
    /// Scale exceeds allowed range
    ScaleTooLarge,
    /// Malformed: expecting number with optional decimal point (10, 10.02)
    Malformed,
}
/// Consensus-visible failures produced by exact decimal and quantity operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, displaydoc::Display, thiserror::Error)]
pub enum NumericOperationError {
    /// Canonical result mantissa is outside `-2^511..=2^511-1`
    MantissaOverflow,
    /// Canonical exact result needs a scale greater than 28
    ScaleOverflow,
    /// Divisor is zero
    DivisionByZero,
    /// Exact quotient is a repeating decimal
    RepeatingDecimal,
    /// Exact terminating quotient needs more than 28 fractional digits
    ExactDivisionScaleOverflow,
    /// Requested output scale is outside `0..=28`
    InvalidScale,
    /// Conversion would discard a nonzero fractional part
    InexactConversion,
    /// Decimal is not in its unique canonical representation
    NonCanonical,
    /// Quantity cannot be negative
    NegativeQuantity,
    /// Quantity subtraction would produce a negative result
    QuantityUnderflow,
    /// Integer square root received a negative operand
    NegativeSquareRoot,
}
/// Failures produced while multiplying a quantity by aggregate decimal factors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecimalProductError {
    /// Aggregate decimal product contains more than 64 factors.
    #[error("aggregate decimal product contains more than 64 factors")]
    TooManyFactors,
    /// An exact decimal or quantity operation failed.
    #[error(transparent)]
    Numeric(#[from] NumericOperationError),
}
/// Errors raised while constructing or manipulating XOR quantities.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum XorQuantityError {
    /// Arithmetic result exceeds the bounded exact-decimal domain.
    #[error("XOR quantity overflow")]
    Overflow,
    /// Subtraction would produce a negative quantity.
    #[error("XOR quantity underflow")]
    Underflow,
    /// A signed decimal cannot be used as an XOR quantity.
    #[error("XOR quantity cannot be negative")]
    NegativeQuantity,
    /// Projection to an explicitly requested micro-XOR representation is inexact.
    #[error("XOR quantity cannot be represented exactly in micro-XOR")]
    InexactMicroProjection,
    /// XOR values may carry at most nine fractional digits.
    #[error("XOR quantity scale {scale} exceeds maximum {max}")]
    ScaleOverflow {
        /// Observed fractional digit count.
        scale: u32,
        /// Maximum accepted fractional digit count.
        max: u32,
    },
}
/// Deterministic rounding policies supported by decimal operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RoundingMode {
    /// Discard the fractional remainder.
    TowardZero = 0,
    /// Increase the absolute value whenever a remainder exists.
    AwayFromZero = 1,
    /// Round toward negative infinity.
    Floor = 2,
    /// Round toward positive infinity.
    Ceil = 3,
    /// Round to nearest, resolving ties to an even output mantissa.
    NearestEven = 4,
    /// Round to nearest, resolving ties away from zero.
    NearestAway = 5,
    /// Round to nearest, resolving ties toward zero.
    NearestTowardZero = 6,
}
/// A division-like work unit reported before arithmetic begins.
///
/// The VM uses these callbacks to debit deterministic logical work before it
/// performs the corresponding division. Widths count 64-bit logical limbs and
/// are never derived from a host bigint implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumericWorkStep {
    /// Compare two conceptual integers in signed order.
    Compare {
        /// Left operand width.
        lhs_limbs: u16,
        /// Right operand width.
        rhs_limbs: u16,
    },
    /// One canonicality probe dividing a nonzero scaled mantissa by ten.
    CanonicalityProbe {
        /// Width of the mantissa before the probe.
        mantissa_limbs: u16,
        /// Scale carried by the value being validated.
        scale: u8,
    },
    /// Scale a conceptual integer by a decimal power before alignment.
    ScaleByPowerOfTen {
        /// Width of the unscaled value.
        value_limbs: u16,
        /// Decimal exponent.
        exponent: u8,
    },
    /// Materialize one unchanged conceptual integer into an owned temporary.
    Materialize {
        /// Width of the value being copied.
        value_limbs: u16,
    },
    /// Negate one conceptual integer.
    Negate {
        /// Operand width.
        value_limbs: u16,
    },
    /// Add two aligned conceptual integers.
    Add {
        /// Left operand width.
        lhs_limbs: u16,
        /// Right operand width.
        rhs_limbs: u16,
    },
    /// Subtract two aligned conceptual integers.
    Subtract {
        /// Left operand width.
        lhs_limbs: u16,
        /// Right operand width.
        rhs_limbs: u16,
    },
    /// Multiply two conceptual integers.
    Multiply {
        /// Left operand width.
        lhs_limbs: u16,
        /// Right operand width.
        rhs_limbs: u16,
    },
    /// One canonical trailing-zero probe and, when divisible, division by ten.
    Normalize {
        /// Width of the mantissa before the division.
        mantissa_limbs: u16,
        /// Scale before the division.
        remaining_scale: u8,
    },
    /// One exact-division attempt at a candidate output scale.
    ExactDivisionAttempt {
        /// Width of the conceptual scaled numerator.
        numerator_limbs: u16,
        /// Width of the conceptual scaled denominator.
        denominator_limbs: u16,
        /// Candidate output scale.
        output_scale: u8,
    },
    /// One Euclidean or prime-factor classification division.
    DivisionClassification {
        /// Width of the dividend before the division.
        dividend_limbs: u16,
        /// Width of the divisor before the division.
        divisor_limbs: u16,
    },
    /// Prepare absolute numerator/denominator values for exact classification.
    DivisionClassificationPrepare {
        /// Width of the numerator copied into the Euclidean state.
        numerator_limbs: u16,
        /// Width of the denominator copied into both the Euclidean state and
        /// the later reduced-denominator state.
        denominator_limbs: u16,
    },
    /// One quotient/remainder operation used for explicit rounding or conversion.
    RoundedDivision {
        /// Width of the conceptual numerator.
        numerator_limbs: u16,
        /// Width of the conceptual denominator.
        denominator_limbs: u16,
        /// Requested output scale.
        output_scale: u8,
    },
    /// Scan and validate one final conceptual value before bounding it.
    Finalize {
        /// Width of the final conceptual value.
        value_limbs: u16,
    },
}
/// Error from an observed numeric operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservedNumericError<E> {
    /// Arithmetic or domain failure.
    Numeric(NumericOperationError),
    /// Observer rejected the work before it began.
    Observer(E),
}
/// Mathematical classification of an exact decimal quotient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExactDivisionClass {
    /// The quotient has an exact representation at or below scale 28.
    Representable {
        /// Minimum scale of the reduced terminating quotient before final
        /// trailing-zero canonicalization.
        minimum_scale: u8,
    },
    /// The reduced denominator has a prime factor other than two or five.
    Repeating,
    /// The quotient terminates, but its minimum scale is greater than 28.
    ScaleOverflow,
}
/// The error type returned when a numeric conversion fails.
#[derive(Debug, Clone, Copy, displaydoc::Display, thiserror::Error)]
pub struct TryFromNumericError;
/// Error occurred while checking if number satisfy given spec
#[derive(Clone, Copy, Debug, displaydoc::Display, thiserror::Error)]
pub enum NumericSpecError {
    /// Given number has scale higher than allowed by spec.
    ScaleTooHigh,
}
/// Error occurred while checking if number satisfy given spec
#[derive(Clone, Debug, displaydoc::Display, thiserror::Error)]
pub enum NumericSpecParseError {
    /// String representation should start with Numeric
    StartWithNumeric,
    /// Numeric should be followed by optional scale wrapped in braces
    WrappedInBraces,
    /// Scale should be valid integer value: {_0}
    InvalidScale(#[source] <u32 as FromStr>::Err),
}
impl Numeric {
    /// Zero numeric value
    pub fn zero() -> Self {
        Self::new(BigInt::zero(), 0)
    }
    /// One numeric value
    pub fn one() -> Self {
        Self::new(BigInt::one(), 0)
    }
    /// Create a canonical numeric from a mantissa and scale.
    ///
    /// # Panics
    /// Panics in cases where [`Self::try_new`] would return error.
    #[inline]
    pub fn new<T: Into<BigInt>>(mantissa: T, scale: u32) -> Self {
        match Self::try_new(mantissa, scale) {
            Ok(numeric) => numeric,
            Err(NumericError::ScaleTooLarge) => panic!("failed to create numeric: scale too large"),
            Err(NumericError::MantissaTooLarge) => {
                panic!("failed to create numeric: mantissa too large")
            }
            Err(NumericError::Malformed) => unreachable!(),
        }
    }
    /// Try to create a canonical numeric from a mantissa and scale.
    ///
    /// # Errors
    /// - if mantissa leaves the signed 512-bit domain
    /// - if the canonical scale remains greater than 28 after trailing-zero removal
    #[inline]
    pub fn try_new<T: Into<BigInt>>(mantissa: T, scale: u32) -> Result<Self, NumericError> {
        let mantissa = mantissa.into();
        if mantissa.is_zero() {
            return Ok(Self { mantissa, scale: 0 });
        }
        let value = Self { mantissa, scale }.trim_trailing_zeros();
        if value.scale > MAX_DECIMAL_SCALE {
            return Err(NumericError::ScaleTooLarge);
        }
        // The input type is already bounded, but keeping the final-width check
        // after normalization mirrors the conceptual-unbounded arithmetic and
        // text-construction paths and makes the consensus ordering explicit.
        if !mantissa_fits_numeric_domain(&value.mantissa) {
            return Err(NumericError::MantissaTooLarge);
        }
        Ok(value)
    }
    /// Construct raw fields for strict decoders that must detect and reject a
    /// noncanonical representation rather than silently normalize it.
    pub(crate) fn try_new_raw<T: Into<BigInt>>(
        mantissa: T,
        scale: u32,
    ) -> Result<Self, NumericError> {
        if scale > MAX_DECIMAL_SCALE {
            return Err(NumericError::ScaleTooLarge);
        }
        let mantissa = mantissa.into();
        if !mantissa_fits_numeric_domain(&mantissa) {
            return Err(NumericError::MantissaTooLarge);
        }
        Ok(Self { mantissa, scale })
    }
    /// Return mantissa of number (signed).
    #[inline]
    pub fn mantissa(&self) -> &BigInt {
        &self.mantissa
    }
    /// Try to view mantissa as u128 (fails on negative or too-wide values).
    #[inline]
    pub fn try_mantissa_u128(&self) -> Option<u128> {
        if self.mantissa.is_negative() {
            None
        } else {
            self.mantissa.to_string().parse::<u128>().ok()
        }
    }
    /// Try to view mantissa as i128 (fails if too wide).
    #[inline]
    pub fn try_mantissa_i128(&self) -> Option<i128> {
        self.mantissa.to_string().parse::<i128>().ok()
    }
    /// Return scale of number
    #[inline]
    pub const fn scale(&self) -> u32 {
        self.scale
    }
    /// Reduce the scale by stripping trailing zero fractional digits.
    #[must_use]
    pub fn trim_trailing_zeros(mut self) -> Self {
        let ten = BigInt::from_i128(10);
        while self.scale > 0 {
            match self.mantissa.checked_div_rem(&ten) {
                Ok((quotient, remainder)) if remainder.is_zero() => {
                    self.mantissa = quotient;
                    self.scale -= 1;
                }
                _ => break,
            }
        }
        self
    }
    /// Return this value in its unique canonical decimal representation.
    ///
    /// Canonicalization strips fractional trailing zeroes and represents every zero as `(0, 0)`.
    ///
    /// # Errors
    /// Returns [`NumericOperationError::MantissaOverflow`] if the normalized
    /// result leaves the signed domain. (Values created through [`Numeric`]
    /// cannot currently trigger this error, but conceptual intermediates can.)
    pub fn canonicalize_decimal(self) -> Result<Self, NumericOperationError> {
        infallible_observed(canonical_decimal_from_unbounded_observed(
            self.mantissa.inner().clone(),
            self.scale,
            &mut |_| Ok::<_, core::convert::Infallible>(()),
        ))
    }
    /// Canonicalize while reporting every normalization division before it begins.
    ///
    /// # Errors
    /// Returns an arithmetic error or propagates an observer rejection before
    /// the corresponding division is performed.
    pub fn canonicalize_decimal_observed<E, F>(
        self,
        observer: &mut F,
    ) -> Result<Self, ObservedNumericError<E>>
    where
        F: FnMut(NumericWorkStep) -> Result<(), E>,
    {
        canonical_decimal_from_unbounded_observed(
            self.mantissa.inner().clone(),
            self.scale,
            observer,
        )
    }
    /// Validate the unique canonical decimal representation.
    ///
    /// # Errors
    /// Returns [`NumericOperationError::NonCanonical`] for zero at nonzero
    /// scale or for a mantissa divisible by ten while scale is nonzero.
    pub fn validate_decimal(&self) -> Result<(), NumericOperationError> {
        infallible_observed(
            self.validate_decimal_observed(&mut |_| Ok::<_, core::convert::Infallible>(())),
        )
    }
    /// Validate canonicality while reporting the divisibility probe first.
    ///
    /// Zero at nonzero scale is rejected without bigint division. Every other
    /// nonzero-scale value emits exactly one [`NumericWorkStep::CanonicalityProbe`]
    /// before its exact divisibility-by-ten probe.
    ///
    /// # Errors
    /// Returns noncanonical input or propagates an observer rejection before
    /// the divisibility probe begins.
    pub fn validate_decimal_observed<E, F>(
        &self,
        observer: &mut F,
    ) -> Result<(), ObservedNumericError<E>>
    where
        F: FnMut(NumericWorkStep) -> Result<(), E>,
    {
        validate_decimal_parts_observed(
            self.scale,
            self.mantissa.is_zero(),
            logical_limbs(self.mantissa.inner()),
            || magnitude_divisible_by_ten(self.mantissa.inner().iter_u64_digits().rev()),
            observer,
        )
    }
    /// Checked canonical decimal negation.
    ///
    /// # Errors
    /// Rejects noncanonical input and a result outside the signed domain.
    pub fn try_decimal_neg(&self) -> Result<Self, NumericOperationError> {
        infallible_observed(
            self.try_decimal_neg_observed(&mut |_| Ok::<_, core::convert::Infallible>(())),
        )
    }
    /// Negate while reporting normalization divisions before work.
    ///
    /// # Errors
    /// Returns an arithmetic error or propagates an observer rejection.
    pub fn try_decimal_neg_observed<E, F>(
        &self,
        observer: &mut F,
    ) -> Result<Self, ObservedNumericError<E>>
    where
        F: FnMut(NumericWorkStep) -> Result<(), E>,
    {
        self.validate_decimal_observed(observer)?;
        observer(NumericWorkStep::Negate {
            value_limbs: logical_limbs(self.mantissa.inner()),
        })
        .map_err(ObservedNumericError::Observer)?;
        canonical_decimal_from_unbounded_observed(-self.mantissa.inner(), self.scale, observer)
    }
    /// Add two canonical decimals using an unbounded conceptual intermediate.
    ///
    /// # Errors
    /// Rejects noncanonical operands or an unrepresentable canonical result.
    pub fn try_decimal_add(&self, other: &Self) -> Result<Self, NumericOperationError> {
        infallible_observed(
            self.try_decimal_add_observed(other, &mut |_| Ok::<_, core::convert::Infallible>(())),
        )
    }
    /// Add while reporting normalization divisions before work.
    ///
    /// # Errors
    /// Returns an arithmetic error or propagates an observer rejection.
    pub fn try_decimal_add_observed<E, F>(
        &self,
        other: &Self,
        observer: &mut F,
    ) -> Result<Self, ObservedNumericError<E>>
    where
        F: FnMut(NumericWorkStep) -> Result<(), E>,
    {
        self.validate_decimal_observed(observer)?;
        other.validate_decimal_observed(observer)?;
        let target_scale = self.scale.max(other.scale);
        let lhs =
            scale_unbounded_observed(self.mantissa.inner(), target_scale - self.scale, observer)?;
        let rhs =
            scale_unbounded_observed(other.mantissa.inner(), target_scale - other.scale, observer)?;
        observer(NumericWorkStep::Add {
            lhs_limbs: logical_limbs(&lhs),
            rhs_limbs: logical_limbs(&rhs),
        })
        .map_err(ObservedNumericError::Observer)?;
        canonical_decimal_from_unbounded_observed(lhs + rhs, target_scale, observer)
    }
    /// Subtract two canonical decimals using an unbounded conceptual intermediate.
    ///
    /// # Errors
    /// Rejects noncanonical operands or an unrepresentable canonical result.
    pub fn try_decimal_sub(&self, other: &Self) -> Result<Self, NumericOperationError> {
        infallible_observed(
            self.try_decimal_sub_observed(other, &mut |_| Ok::<_, core::convert::Infallible>(())),
        )
    }
    /// Subtract while reporting normalization divisions before work.
    ///
    /// # Errors
    /// Returns an arithmetic error or propagates an observer rejection.
    pub fn try_decimal_sub_observed<E, F>(
        &self,
        other: &Self,
        observer: &mut F,
    ) -> Result<Self, ObservedNumericError<E>>
    where
        F: FnMut(NumericWorkStep) -> Result<(), E>,
    {
        self.validate_decimal_observed(observer)?;
        other.validate_decimal_observed(observer)?;
        let target_scale = self.scale.max(other.scale);
        let lhs =
            scale_unbounded_observed(self.mantissa.inner(), target_scale - self.scale, observer)?;
        let rhs =
            scale_unbounded_observed(other.mantissa.inner(), target_scale - other.scale, observer)?;
        observer(NumericWorkStep::Subtract {
            lhs_limbs: logical_limbs(&lhs),
            rhs_limbs: logical_limbs(&rhs),
        })
        .map_err(ObservedNumericError::Observer)?;
        canonical_decimal_from_unbounded_observed(lhs - rhs, target_scale, observer)
    }
    /// Multiply two canonical decimals exactly.
    ///
    /// The conceptual product may be wider than 512 bits and may initially have scale 56. Trailing
    /// decimal zeroes are removed before the final signed-width and scale bounds are checked.
    ///
    /// # Errors
    /// Rejects noncanonical operands or an unrepresentable canonical result.
    pub fn try_decimal_mul(&self, other: &Self) -> Result<Self, NumericOperationError> {
        infallible_observed(
            self.try_decimal_mul_observed(other, &mut |_| Ok::<_, core::convert::Infallible>(())),
        )
    }
    /// Multiply two decimals while reporting normalization divisions before work.
    ///
    /// # Errors
    /// Returns an arithmetic error or propagates an observer rejection.
    pub fn try_decimal_mul_observed<E, F>(
        &self,
        other: &Self,
        observer: &mut F,
    ) -> Result<Self, ObservedNumericError<E>>
    where
        F: FnMut(NumericWorkStep) -> Result<(), E>,
    {
        self.validate_decimal_observed(observer)?;
        other.validate_decimal_observed(observer)?;
        let scale = self
            .scale
            .checked_add(other.scale)
            .ok_or(ObservedNumericError::Numeric(
                NumericOperationError::ScaleOverflow,
            ))?;
        observer(NumericWorkStep::Multiply {
            lhs_limbs: logical_limbs(self.mantissa.inner()),
            rhs_limbs: logical_limbs(other.mantissa.inner()),
        })
        .map_err(ObservedNumericError::Observer)?;
        canonical_decimal_from_unbounded_observed(
            self.mantissa.inner() * other.mantissa.inner(),
            scale,
            observer,
        )
    }
    /// Multiply by one decimal and divide exactly by another using one conceptual intermediate.
    ///
    /// The mathematical product remains unbounded until after the quotient is
    /// reduced and canonicalized. A wide temporary therefore cannot reject an
    /// exact final result that fits the public decimal domain.
    ///
    /// # Errors
    /// Rejects noncanonical operands, a zero divisor, a repeating or over-scale
    /// quotient, or a final result outside the canonical decimal domain.
    pub fn try_decimal_mul_div_exact(
        &self,
        multiplier: &Self,
        divisor: &Self,
    ) -> Result<Self, NumericOperationError> {
        infallible_observed(self.try_decimal_mul_div_exact_observed(
            multiplier,
            divisor,
            &mut |_| Ok::<_, core::convert::Infallible>(()),
        ))
    }
    /// Fused exact multiply/divide while reporting every logical work phase before it begins.
    ///
    /// # Errors
    /// Returns an arithmetic failure or propagates an observer rejection.
    pub fn try_decimal_mul_div_exact_observed<E, F>(
        &self,
        multiplier: &Self,
        divisor: &Self,
        observer: &mut F,
    ) -> Result<Self, ObservedNumericError<E>>
    where
        F: FnMut(NumericWorkStep) -> Result<(), E>,
    {
        self.validate_decimal_observed(observer)?;
        multiplier.validate_decimal_observed(observer)?;
        divisor.validate_decimal_observed(observer)?;
        if divisor.mantissa.is_zero() {
            return Err(ObservedNumericError::Numeric(
                NumericOperationError::DivisionByZero,
            ));
        }
        let product_scale =
            self.scale
                .checked_add(multiplier.scale)
                .ok_or(ObservedNumericError::Numeric(
                    NumericOperationError::ScaleOverflow,
                ))?;
        observer(NumericWorkStep::Multiply {
            lhs_limbs: logical_limbs(self.mantissa.inner()),
            rhs_limbs: logical_limbs(multiplier.mantissa.inner()),
        })
        .map_err(ObservedNumericError::Observer)?;
        let product = self.mantissa.inner() * multiplier.mantissa.inner();
        let (numerator, denominator) = decimal_product_division_operands_observed(
            &product,
            product_scale,
            divisor,
            0,
            observer,
        )?;
        let class = classify_exact_rational_observed(&numerator, &denominator, observer)?;
        match class {
            ExactDivisionClass::Representable { minimum_scale } => {
                exact_product_division_at_scale_observed(
                    &product,
                    product_scale,
                    divisor,
                    u32::from(minimum_scale),
                    observer,
                )?
                .ok_or_else(|| ObservedNumericError::Numeric(NumericOperationError::NonCanonical))
            }
            ExactDivisionClass::Repeating => Err(ObservedNumericError::Numeric(
                NumericOperationError::RepeatingDecimal,
            )),
            ExactDivisionClass::ScaleOverflow => Err(ObservedNumericError::Numeric(
                NumericOperationError::ExactDivisionScaleOverflow,
            )),
        }
    }
    /// Multiply by one decimal and divide by another with a single rounded conceptual intermediate.
    ///
    /// This operation is intentionally fused: the mathematical product is
    /// kept unbounded until after division, so a temporary wider than 512 bits
    /// cannot make an otherwise representable final result fail.
    ///
    /// # Errors
    /// Rejects noncanonical operands, a zero divisor, an invalid output scale,
    /// or a final result outside the canonical decimal domain.
    pub fn try_decimal_mul_div_round(
        &self,
        multiplier: &Self,
        divisor: &Self,
        output_scale: u32,
        mode: RoundingMode,
    ) -> Result<Self, NumericOperationError> {
        infallible_observed(self.try_decimal_mul_div_round_observed(
            multiplier,
            divisor,
            output_scale,
            mode,
            &mut |_| Ok::<_, core::convert::Infallible>(()),
        ))
    }
    /// Fused multiply/divide while reporting every logical work phase before it begins.
    ///
    /// # Errors
    /// Returns an arithmetic failure or propagates an observer rejection.
    pub fn try_decimal_mul_div_round_observed<E, F>(
        &self,
        multiplier: &Self,
        divisor: &Self,
        output_scale: u32,
        mode: RoundingMode,
        observer: &mut F,
    ) -> Result<Self, ObservedNumericError<E>>
    where
        F: FnMut(NumericWorkStep) -> Result<(), E>,
    {
        self.validate_decimal_observed(observer)?;
        multiplier.validate_decimal_observed(observer)?;
        divisor.validate_decimal_observed(observer)?;
        if output_scale > MAX_DECIMAL_SCALE {
            return Err(ObservedNumericError::Numeric(
                NumericOperationError::InvalidScale,
            ));
        }
        if divisor.mantissa.is_zero() {
            return Err(ObservedNumericError::Numeric(
                NumericOperationError::DivisionByZero,
            ));
        }
        let product_scale =
            self.scale
                .checked_add(multiplier.scale)
                .ok_or(ObservedNumericError::Numeric(
                    NumericOperationError::ScaleOverflow,
                ))?;
        observer(NumericWorkStep::Multiply {
            lhs_limbs: logical_limbs(self.mantissa.inner()),
            rhs_limbs: logical_limbs(multiplier.mantissa.inner()),
        })
        .map_err(ObservedNumericError::Observer)?;
        let product = self.mantissa.inner() * multiplier.mantissa.inner();
        let (numerator, denominator) = decimal_product_division_operands_observed(
            &product,
            product_scale,
            divisor,
            output_scale,
            observer,
        )?;
        observer(NumericWorkStep::RoundedDivision {
            numerator_limbs: logical_limbs(&numerator),
            denominator_limbs: logical_limbs(&denominator),
            output_scale: u8::try_from(output_scale).expect("validated scale fits u8"),
        })
        .map_err(ObservedNumericError::Observer)?;
        let quotient = rounded_quotient(&numerator, &denominator, mode);
        canonical_decimal_from_unbounded_observed(quotient, output_scale, observer)
    }
    /// Attempt exact division at one explicit output scale.
    ///
    /// `Ok(None)` means the quotient has a nonzero remainder at this scale. This method is useful
    /// to runtimes that stage one metered attempt at a time.
    ///
    /// # Errors
    /// Rejects invalid scale, noncanonical operands, division by zero, observer
    /// rejection, or an exact result outside the canonical domain.
    pub fn try_decimal_div_exact_at_scale_observed<E, F>(
        &self,
        divisor: &Self,
        output_scale: u32,
        observer: &mut F,
    ) -> Result<Option<Self>, ObservedNumericError<E>>
    where
        F: FnMut(NumericWorkStep) -> Result<(), E>,
    {
        self.validate_decimal_observed(observer)?;
        divisor.validate_decimal_observed(observer)?;
        if output_scale > MAX_DECIMAL_SCALE {
            return Err(ObservedNumericError::Numeric(
                NumericOperationError::InvalidScale,
            ));
        }
        if divisor.mantissa.is_zero() {
            return Err(ObservedNumericError::Numeric(
                NumericOperationError::DivisionByZero,
            ));
        }
        exact_division_at_scale_observed(self, divisor, output_scale, observer)
    }
    /// Attempt exact division at one explicit output scale without an observer.
    ///
    /// # Errors
    /// See [`Self::try_decimal_div_exact_at_scale_observed`].
    pub fn try_decimal_div_exact_at_scale(
        &self,
        divisor: &Self,
        output_scale: u32,
    ) -> Result<Option<Self>, NumericOperationError> {
        infallible_observed(self.try_decimal_div_exact_at_scale_observed(
            divisor,
            output_scale,
            &mut |_| Ok::<_, core::convert::Infallible>(()),
        ))
    }
    /// Classify the mathematical quotient after reducing its denominator.
    ///
    /// Every Euclidean and prime-factor division is reported to `observer` before it begins.
    ///
    /// # Errors
    /// Rejects noncanonical operands, division by zero, or observer rejection.
    pub fn classify_exact_division_observed<E, F>(
        &self,
        divisor: &Self,
        observer: &mut F,
    ) -> Result<ExactDivisionClass, ObservedNumericError<E>>
    where
        F: FnMut(NumericWorkStep) -> Result<(), E>,
    {
        self.validate_decimal_observed(observer)?;
        divisor.validate_decimal_observed(observer)?;
        if divisor.mantissa.is_zero() {
            return Err(ObservedNumericError::Numeric(
                NumericOperationError::DivisionByZero,
            ));
        }
        classify_exact_division_inner(self, divisor, observer)
    }
    /// Classify an exact quotient without an observer.
    ///
    /// # Errors
    /// Rejects noncanonical operands or division by zero.
    pub fn classify_exact_division(
        &self,
        divisor: &Self,
    ) -> Result<ExactDivisionClass, NumericOperationError> {
        infallible_observed(self.classify_exact_division_observed(divisor, &mut |_| {
            Ok::<_, core::convert::Infallible>(())
        }))
    }
    /// Divide exactly, selecting the smallest representable output scale.
    ///
    /// The reduced denominator is classified first. A terminating quotient is
    /// then attempted exactly once at its proven minimum scale; repeating and
    /// over-scale quotients fail without speculative division attempts.
    ///
    /// # Errors
    /// Returns the precise arithmetic failure or an observer rejection.
    pub fn try_decimal_div_exact_observed<E, F>(
        &self,
        divisor: &Self,
        observer: &mut F,
    ) -> Result<Self, ObservedNumericError<E>>
    where
        F: FnMut(NumericWorkStep) -> Result<(), E>,
    {
        self.validate_decimal_observed(observer)?;
        divisor.validate_decimal_observed(observer)?;
        if divisor.mantissa.is_zero() {
            return Err(ObservedNumericError::Numeric(
                NumericOperationError::DivisionByZero,
            ));
        }
        let class = classify_exact_division_inner(self, divisor, observer)?;
        match class {
            ExactDivisionClass::Representable { minimum_scale } => {
                exact_division_at_scale_observed(self, divisor, u32::from(minimum_scale), observer)?
                    .ok_or_else(|| {
                        // Classification reduced the exact mathematical quotient
                        // and proved this scale sufficient. A remainder here would
                        // indicate an internal arithmetic invariant violation, not
                        // a user-triggerable inexact result.
                        ObservedNumericError::Numeric(NumericOperationError::NonCanonical)
                    })
            }
            ExactDivisionClass::Repeating => Err(ObservedNumericError::Numeric(
                NumericOperationError::RepeatingDecimal,
            )),
            ExactDivisionClass::ScaleOverflow => Err(ObservedNumericError::Numeric(
                NumericOperationError::ExactDivisionScaleOverflow,
            )),
        }
    }
    /// Divide exactly without an observer.
    ///
    /// # Errors
    /// See [`Self::try_decimal_div_exact_observed`].
    pub fn try_decimal_div_exact(&self, divisor: &Self) -> Result<Self, NumericOperationError> {
        infallible_observed(self.try_decimal_div_exact_observed(divisor, &mut |_| {
            Ok::<_, core::convert::Infallible>(())
        }))
    }
    /// Divide with an explicit output scale and deterministic rounding mode.
    ///
    /// # Errors
    /// Returns the precise arithmetic failure or an observer rejection.
    pub fn try_decimal_div_round_observed<E, F>(
        &self,
        divisor: &Self,
        output_scale: u32,
        mode: RoundingMode,
        observer: &mut F,
    ) -> Result<Self, ObservedNumericError<E>>
    where
        F: FnMut(NumericWorkStep) -> Result<(), E>,
    {
        self.validate_decimal_observed(observer)?;
        divisor.validate_decimal_observed(observer)?;
        if output_scale > MAX_DECIMAL_SCALE {
            return Err(ObservedNumericError::Numeric(
                NumericOperationError::InvalidScale,
            ));
        }
        if divisor.mantissa.is_zero() {
            return Err(ObservedNumericError::Numeric(
                NumericOperationError::DivisionByZero,
            ));
        }
        let (numerator, denominator) =
            decimal_division_operands_observed(self, divisor, output_scale, observer)?;
        observer(NumericWorkStep::RoundedDivision {
            numerator_limbs: logical_limbs(&numerator),
            denominator_limbs: logical_limbs(&denominator),
            output_scale: u8::try_from(output_scale).expect("validated scale fits u8"),
        })
        .map_err(ObservedNumericError::Observer)?;
        let quotient = rounded_quotient(&numerator, &denominator, mode);
        canonical_decimal_from_unbounded_observed(quotient, output_scale, observer)
    }
    /// Divide with explicit rounding without an observer.
    ///
    /// # Errors
    /// See [`Self::try_decimal_div_round_observed`].
    pub fn try_decimal_div_round(
        &self,
        divisor: &Self,
        output_scale: u32,
        mode: RoundingMode,
    ) -> Result<Self, NumericOperationError> {
        infallible_observed(self.try_decimal_div_round_observed(
            divisor,
            output_scale,
            mode,
            &mut |_| Ok::<_, core::convert::Infallible>(()),
        ))
    }
    /// Convert to an integer only when the decimal has no fractional value.
    ///
    /// # Errors
    /// Rejects noncanonical input or a nonzero fractional remainder.
    pub fn try_decimal_to_int_exact(&self) -> Result<BigInt, NumericOperationError> {
        infallible_observed(
            self.try_decimal_to_int_exact_observed(&mut |_| Ok::<_, core::convert::Infallible>(())),
        )
    }
    /// Convert exactly while reporting the quotient/remainder work first.
    ///
    /// # Errors
    /// Returns the precise conversion failure or an observer rejection.
    pub fn try_decimal_to_int_exact_observed<E, F>(
        &self,
        observer: &mut F,
    ) -> Result<BigInt, ObservedNumericError<E>>
    where
        F: FnMut(NumericWorkStep) -> Result<(), E>,
    {
        self.validate_decimal_observed(observer)?;
        if self.scale == 0 {
            observer(NumericWorkStep::Finalize {
                value_limbs: logical_limbs(self.mantissa.inner()),
            })
            .map_err(ObservedNumericError::Observer)?;
            return Ok(self.mantissa.clone());
        }
        let divisor = scale_unbounded_observed(&UnboundedBigInt::one(), self.scale, observer)?;
        observer(NumericWorkStep::RoundedDivision {
            numerator_limbs: logical_limbs(self.mantissa.inner()),
            denominator_limbs: logical_limbs(&divisor),
            output_scale: 0,
        })
        .map_err(ObservedNumericError::Observer)?;
        let (quotient, remainder) = quotient_remainder(self.mantissa.inner(), &divisor);
        if !remainder.is_zero() {
            return Err(ObservedNumericError::Numeric(
                NumericOperationError::InexactConversion,
            ));
        }
        finalize_bigint_observed(quotient, observer)
    }
    /// Convert to an integer by truncating toward zero.
    ///
    /// # Errors
    /// Rejects noncanonical input or an unrepresentable result.
    pub fn decimal_to_int_trunc(&self) -> Result<BigInt, NumericOperationError> {
        infallible_observed(
            self.decimal_to_int_trunc_observed(&mut |_| Ok::<_, core::convert::Infallible>(())),
        )
    }
    /// Truncate to an integer while reporting the division before work.
    ///
    /// # Errors
    /// Returns the precise conversion failure or an observer rejection.
    pub fn decimal_to_int_trunc_observed<E, F>(
        &self,
        observer: &mut F,
    ) -> Result<BigInt, ObservedNumericError<E>>
    where
        F: FnMut(NumericWorkStep) -> Result<(), E>,
    {
        self.validate_decimal_observed(observer)?;
        if self.scale == 0 {
            observer(NumericWorkStep::Finalize {
                value_limbs: logical_limbs(self.mantissa.inner()),
            })
            .map_err(ObservedNumericError::Observer)?;
            return Ok(self.mantissa.clone());
        }
        let divisor = scale_unbounded_observed(&UnboundedBigInt::one(), self.scale, observer)?;
        observer(NumericWorkStep::RoundedDivision {
            numerator_limbs: logical_limbs(self.mantissa.inner()),
            denominator_limbs: logical_limbs(&divisor),
            output_scale: 0,
        })
        .map_err(ObservedNumericError::Observer)?;
        finalize_bigint_observed(
            quotient_remainder(self.mantissa.inner(), &divisor).0,
            observer,
        )
    }
    /// Convert to an integer using an explicit deterministic rounding mode.
    ///
    /// # Errors
    /// Rejects noncanonical input or an unrepresentable rounded result.
    pub fn decimal_to_int_round(
        &self,
        mode: RoundingMode,
    ) -> Result<BigInt, NumericOperationError> {
        infallible_observed(
            self.decimal_to_int_round_observed(mode, &mut |_| {
                Ok::<_, core::convert::Infallible>(())
            }),
        )
    }
    /// Round to an integer while reporting the division before work.
    ///
    /// # Errors
    /// Returns the precise conversion failure or an observer rejection.
    pub fn decimal_to_int_round_observed<E, F>(
        &self,
        mode: RoundingMode,
        observer: &mut F,
    ) -> Result<BigInt, ObservedNumericError<E>>
    where
        F: FnMut(NumericWorkStep) -> Result<(), E>,
    {
        self.validate_decimal_observed(observer)?;
        if self.scale == 0 {
            observer(NumericWorkStep::Finalize {
                value_limbs: logical_limbs(self.mantissa.inner()),
            })
            .map_err(ObservedNumericError::Observer)?;
            return Ok(self.mantissa.clone());
        }
        let divisor = scale_unbounded_observed(&UnboundedBigInt::one(), self.scale, observer)?;
        observer(NumericWorkStep::RoundedDivision {
            numerator_limbs: logical_limbs(self.mantissa.inner()),
            denominator_limbs: logical_limbs(&divisor),
            output_scale: 0,
        })
        .map_err(ObservedNumericError::Observer)?;
        finalize_bigint_observed(
            rounded_quotient(self.mantissa.inner(), &divisor, mode),
            observer,
        )
    }
    /// Checked addition. Computes `self + other`, returning `None` if overflow occurred
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the consuming API deliberately mirrors primitive checked operator methods"
    )]
    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.try_decimal_add(&other).ok()
    }
    /// Checked subtraction. Computes `self - other`, returning `None` if overflow occurred
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the consuming API deliberately mirrors primitive checked operator methods"
    )]
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.try_decimal_sub(&other).ok()
    }
    /// Quantize this value to at most `output_scale` fractional digits using
    /// an explicit deterministic rounding mode.
    ///
    /// Canonical values do not preserve insignificant trailing zeroes, so a
    /// requested scale greater than the current canonical scale returns the
    /// same value rather than manufacturing a second representation.
    ///
    /// # Errors
    /// Returns [`NumericOperationError::InvalidScale`] above scale 28 or a
    /// canonical result-domain failure.
    pub fn try_quantize(
        &self,
        output_scale: u32,
        mode: RoundingMode,
    ) -> Result<Self, NumericOperationError> {
        self.validate_decimal()?;
        if output_scale > MAX_DECIMAL_SCALE {
            return Err(NumericOperationError::InvalidScale);
        }
        if output_scale >= self.scale {
            return Ok(self.clone());
        }
        let factor = UnboundedBigInt::from(10_u8).pow(self.scale - output_scale);
        infallible_observed(canonical_decimal_from_unbounded_observed(
            rounded_quotient(self.mantissa.inner(), &factor, mode),
            output_scale,
            &mut |_| Ok::<_, core::convert::Infallible>(()),
        ))
    }
    /// Quantize to an optional asset scale with an explicit rounding mode.
    ///
    /// An unconstrained specification returns the value unchanged.
    ///
    /// # Errors
    /// Returns the same failures as [`Self::try_quantize`].
    pub fn try_quantize_to_spec(
        &self,
        spec: NumericSpec,
        mode: RoundingMode,
    ) -> Result<Self, NumericOperationError> {
        spec.scale
            .map_or_else(|| Ok(self.clone()), |scale| self.try_quantize(scale, mode))
    }
    /// Convert [`Numeric`] to [`f64`] with possible loss of precision.
    ///
    /// This conversion is intended only for non-consensus consumers such as
    /// telemetry and approximate presentation metrics. Consensus and ledger
    /// code must retain the exact decimal representation.
    #[must_use]
    pub fn to_f64_lossy(&self) -> f64 {
        self.to_string()
            .parse()
            .expect("every bounded canonical Numeric value is representable as a finite f64")
    }
    /// Check if number is zero
    pub fn is_zero(&self) -> bool {
        self.mantissa.is_zero()
    }
}
fn invalid_quantity_json(message: &'static str) -> json::Error {
    json::Error::WithPos {
        msg: message,
        byte: 0,
        line: 1,
        col: 1,
    }
}
/// Build a canonical positive quantity mantissa from little-endian bytes.
///
/// The decimal parser supplies a minimal, nonzero magnitude. Validate that
/// shape again so callers cannot reach an allocation with excess width.
///
/// # Safety
/// If `allocate` succeeds with non-null, it must return an owned pointer allocated
/// with the requested `Layout`, aligned for `NativeBigDigit`, that can be
/// transferred to `Vec` and deallocated by the global allocator. A null
/// pointer is allowed. A typed refusal supplies no pointer. The callback is not
/// called for invalid or zero layouts.
#[allow(unsafe_code)]
unsafe fn quantity_mantissa_from_canonical_le_bytes_with<E: From<json::Error>>(
    bytes: &[u8],
    allocate: impl FnOnce(Layout) -> Result<*mut u8, E>,
) -> Result<BigInt, E> {
    let Some(&high_byte) = bytes.last() else {
        return Err(invalid_quantity_json("noncanonical quantity").into());
    };
    if high_byte == 0
        || bytes.len() > MAX_MANTISSA_BYTES
        || (bytes.len() == MAX_MANTISSA_BYTES && high_byte & 0x80 != 0)
    {
        return Err(
            invalid_quantity_json("quantity mantissa exceeds the signed 512-bit domain").into(),
        );
    }
    let digit_count = bytes.len().div_ceil(UNBOUNDED_BIGINT_DIGIT_BYTES);
    let layout = Layout::array::<NativeBigDigit>(digit_count)
        .map_err(|_| json::Error::DecodeResourceLimit)?;
    if layout.size() == 0 {
        return Err(json::Error::DecodeResourceLimit.into());
    }
    norito::core::reserve_decode_allocation(layout.size())
        .map_err(json::Error::from_decode_resource)?;
    let pointer = allocate(layout)?;
    if pointer.is_null() {
        return Err(json::Error::AllocationFailed.into());
    }
    let digit_pointer = core::ptr::NonNull::new(pointer)
        .expect("the allocation pointer was checked non-null")
        .cast::<NativeBigDigit>()
        .as_ptr();
    // SAFETY: `pointer` owns exactly `layout`, whose element count is
    // `digit_count`; the nonzero layout has the alignment of NativeBigDigit.
    // The Vec starts empty, each push remains within capacity, and it owns
    // the allocation on all exit paths.
    let mut digits = unsafe { Vec::from_raw_parts(digit_pointer, 0, digit_count) };
    for chunk in bytes.chunks(UNBOUNDED_BIGINT_DIGIT_BYTES) {
        let mut native_bytes = [0_u8; UNBOUNDED_BIGINT_DIGIT_BYTES];
        native_bytes[..chunk.len()].copy_from_slice(chunk);
        digits.push(NativeBigDigit::from_le_bytes(native_bytes));
    }
    debug_assert_eq!(digits.len(), digits.capacity());
    debug_assert_ne!(digits.last(), Some(&0));
    // The pinned fork adopts this canonical, full-capacity Vec unchanged;
    // `from_biguint` and the signed-width check do not allocate.
    let inner = UnboundedBigInt::from_biguint(
        UnboundedSign::Plus,
        UnboundedBigUint::from_native_digits(digits),
    );
    BigInt::from_inner(inner).map_err(|_| {
        invalid_quantity_json("quantity mantissa exceeds the signed 512-bit domain").into()
    })
}
#[allow(unsafe_code)]
fn quantity_mantissa_from_canonical_le_bytes(bytes: &[u8]) -> Result<BigInt, json::Error> {
    // SAFETY: `std::alloc::alloc` returns a global-allocator-owned pointer for
    // exactly the requested nonzero layout, or null on refusal.
    let allocate = |layout| Ok::<_, json::Error>(unsafe { std::alloc::alloc(layout) });
    unsafe { quantity_mantissa_from_canonical_le_bytes_with(bytes, allocate) }
}
// Each nonnegative 512-bit-domain mantissa is below 2^511. Aligning at most 28
// decimal places adds fewer than 94 bits; summing two aligned values fits in
// at most 606 bits. Ten u64 limbs therefore cover the full conceptual sum.
const QUANTITY_SUM_RELATION_LIMBS: usize = 10;
const _: () = assert!(MAX_MANTISSA_BITS == 512 && MAX_DECIMAL_SCALE == 28);

fn aligned_quantity_sum_limbs(
    quantity: &Quantity,
    common_scale: u32,
) -> Option<[u64; QUANTITY_SUM_RELATION_LIMBS]> {
    if common_scale < quantity.scale() || common_scale > MAX_DECIMAL_SCALE {
        return None;
    }
    let mut limbs = [0_u64; QUANTITY_SUM_RELATION_LIMBS];
    for (index, digit) in quantity
        .mantissa()
        .inner()
        .magnitude()
        .iter_u64_digits()
        .enumerate()
    {
        *limbs.get_mut(index)? = digit;
    }
    for _ in quantity.scale()..common_scale {
        let mut carry = 0_u128;
        for limb in &mut limbs {
            let product = u128::from(*limb) * 10 + carry;
            *limb = u64::try_from(product & u128::from(u64::MAX))
                .expect("masked decimal limb fits u64");
            carry = product >> 64;
        }
        if carry != 0 {
            return None;
        }
    }
    Some(limbs)
}

impl Quantity {
    fn from_canonical_json_text(source: &str) -> Result<Self, json::Error> {
        Self::from_canonical_json_text_with(source, quantity_mantissa_from_canonical_le_bytes)
    }

    // Ordinary and admitted JSON share every decimal syntax/domain check. Only
    // the final exact native-digit destination differs; no second parser runs.
    fn from_canonical_json_text_with<E: From<json::Error>>(
        source: &str,
        make_mantissa: impl FnOnce(&[u8]) -> Result<BigInt, E>,
    ) -> Result<Self, E> {
        if source.len() > MAX_CANONICAL_QUANTITY_TEXT_BYTES {
            return Err(
                invalid_quantity_json("quantity text exceeds the signed 512-bit domain").into(),
            );
        }
        let (integer, fraction) = match source.split_once('.') {
            Some((integer, fraction)) => (integer, Some(fraction)),
            None => (source, None),
        };
        if integer.is_empty() || !integer.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid_quantity_json("malformed quantity").into());
        }
        if integer.len() > 1 && integer.starts_with('0') {
            return Err(invalid_quantity_json("noncanonical quantity").into());
        }
        let scale = if let Some(fraction) = fraction {
            if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid_quantity_json("malformed quantity").into());
            }
            if fraction.len() > MAX_DECIMAL_SCALE as usize {
                return Err(invalid_quantity_json("quantity scale exceeds 28 digits").into());
            }
            if fraction.ends_with('0') {
                return Err(invalid_quantity_json("noncanonical quantity").into());
            }
            u32::try_from(fraction.len()).expect("validated quantity scale fits u32")
        } else {
            0
        };
        let digit_count = integer
            .len()
            .checked_add(fraction.map_or(0, str::len))
            .ok_or_else(|| invalid_quantity_json("quantity text length overflow"))?;
        if digit_count > MAX_QUANTITY_MANTISSA_DECIMAL_DIGITS {
            return Err(invalid_quantity_json(
                "quantity mantissa exceeds the signed 512-bit domain",
            )
            .into());
        }
        if integer == "0" && fraction.is_none() {
            return Ok(Self::zero());
        }

        // Parse base ten directly into the final 512-bit magnitude shape. This keeps all parsing
        // scratch on the stack and avoids constructing a decimal String or an unbounded bigint
        // intermediate that would need guessed allocation accounting.
        let mut magnitude = [0_u8; MAX_MANTISSA_BYTES];
        let mut magnitude_len = 0usize;
        for digit in integer
            .bytes()
            .chain(fraction.into_iter().flat_map(str::bytes))
        {
            let mut carry = u16::from(digit - b'0');
            for byte in &mut magnitude[..magnitude_len] {
                let product = u16::from(*byte) * 10 + carry;
                let [low, high] = product.to_le_bytes();
                *byte = low;
                carry = u16::from(high);
            }
            while carry != 0 {
                if magnitude_len == magnitude.len() {
                    return Err(invalid_quantity_json(
                        "quantity mantissa exceeds the signed 512-bit domain",
                    )
                    .into());
                }
                let [low, high] = carry.to_le_bytes();
                magnitude[magnitude_len] = low;
                magnitude_len += 1;
                carry = u16::from(high);
            }
        }
        if magnitude_len == MAX_MANTISSA_BYTES && magnitude[MAX_MANTISSA_BYTES - 1] & 0x80 != 0 {
            return Err(invalid_quantity_json(
                "quantity mantissa exceeds the signed 512-bit domain",
            )
            .into());
        }
        debug_assert!(magnitude_len != 0, "canonical nonzero quantity");

        // Charge and create the exact native-digit allocation before handing it
        // to the pinned bigint fork; byte-slice constructors do not promise an
        // exact-capacity Vec or a fallible allocator path.
        let mantissa = make_mantissa(&magnitude[..magnitude_len])?;
        Ok(Self(Numeric { mantissa, scale }))
    }
    /// Zero quantity.
    #[must_use]
    pub fn zero() -> Self {
        Self(Numeric::zero())
    }
    /// One quantity.
    #[must_use]
    pub fn one() -> Self {
        Self(Numeric::one())
    }
    /// Exact native-digit backing layout of one cloned quantity.
    ///
    /// The caller can reserve this layout from its original allocation pool
    /// before cloning. A zero quantity needs no heap allocation.
    ///
    /// # Errors
    /// Rejects an unrepresentable native-digit layout.
    pub fn admission_clone_layout(&self) -> Result<Layout, BigIntAdmissionCloneError> {
        self.mantissa().admission_clone_layout()
    }
    /// Fallibly clone this quantity through one exact native-digit allocation.
    ///
    /// The caller retains the original-pool charge until the clone drops;
    /// this method does not acquire or transfer a pool charge.
    ///
    /// # Errors
    /// Rejects an unrepresentable layout or physical allocator refusal.
    pub fn try_clone_for_admission(&self) -> Result<Self, BigIntAdmissionCloneError> {
        Ok(Self(Numeric {
            mantissa: self.mantissa().try_clone_for_admission()?,
            scale: self.scale(),
        }))
    }
    /// Canonicalize and validate a decimal as a non-negative quantity.
    ///
    /// # Errors
    /// Returns [`NumericOperationError::NegativeQuantity`] for a negative
    /// value or a canonicalization domain failure.
    pub fn try_from_numeric(value: Numeric) -> Result<Self, NumericOperationError> {
        let value = value.canonicalize_decimal()?;
        Self::from_canonical_numeric(value)
    }
    /// Wrap an already canonical decimal as a non-negative quantity.
    ///
    /// Every publicly constructible [`Numeric`] already carries the canonical
    /// representation invariant. Strict wire decoders validate that invariant
    /// before constructing `Numeric`, so this boundary only needs to enforce
    /// the additional nominal sign rule and performs no hidden bigint pass.
    ///
    /// # Errors
    /// Rejects a negative input.
    pub fn from_canonical_numeric(value: Numeric) -> Result<Self, NumericOperationError> {
        if value.mantissa.is_negative() {
            return Err(NumericOperationError::NegativeQuantity);
        }
        Ok(Self(value))
    }
    /// Borrow the canonical decimal representation.
    #[must_use]
    pub fn as_numeric(&self) -> &Numeric {
        &self.0
    }
    /// Borrow the signed-domain mantissa (always non-negative for a quantity).
    #[must_use]
    pub fn mantissa(&self) -> &BigInt {
        self.0.mantissa()
    }
    /// Return the canonical decimal scale.
    #[must_use]
    pub const fn scale(&self) -> u32 {
        self.0.scale()
    }
    /// Return whether this quantity is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
    /// Consume this quantity and return its canonical decimal representation.
    #[must_use]
    pub fn into_numeric(self) -> Numeric {
        self.0
    }
    /// Add two quantities exactly.
    ///
    /// # Errors
    /// Returns a canonical result-domain failure.
    pub fn try_add(&self, other: &Self) -> Result<Self, NumericOperationError> {
        Self::from_canonical_numeric(self.0.try_decimal_add(&other.0)?)
    }
    /// Alias for [`Self::try_add`] emphasizing checked domain arithmetic.
    ///
    /// # Errors
    /// Returns a canonical result-domain failure.
    pub fn checked_add(&self, other: &Self) -> Result<Self, NumericOperationError> {
        self.try_add(other)
    }
    /// Test one exact quantity addition without allocating arithmetic scratch.
    ///
    /// Returns `false` when the mathematical sum differs from `expected` or
    /// would leave the canonical quantity domain. The comparison aligns all
    /// three nonnegative mantissas at their greatest decimal scale on bounded
    /// stack limbs, so it also covers canonicalization of trailing zeroes.
    #[must_use]
    pub fn checked_add_equals(&self, other: &Self, expected: &Self) -> bool {
        let common_scale = self.scale().max(other.scale()).max(expected.scale());
        let Some(mut sum) = aligned_quantity_sum_limbs(self, common_scale) else {
            return false;
        };
        let Some(rhs) = aligned_quantity_sum_limbs(other, common_scale) else {
            return false;
        };
        let Some(expected) = aligned_quantity_sum_limbs(expected, common_scale) else {
            return false;
        };
        let mut carry = 0_u128;
        for (sum_limb, rhs_limb) in sum.iter_mut().zip(rhs) {
            let value = u128::from(*sum_limb) + u128::from(rhs_limb) + carry;
            *sum_limb =
                u64::try_from(value & u128::from(u64::MAX)).expect("masked addition limb fits u64");
            carry = value >> 64;
        }
        carry == 0 && sum == expected
    }
    /// Subtract quantities, rejecting a negative result as underflow.
    ///
    /// # Errors
    /// Returns [`NumericOperationError::QuantityUnderflow`] when `other` is
    /// greater than `self`, or another result-domain failure.
    pub fn try_sub(&self, other: &Self) -> Result<Self, NumericOperationError> {
        let result = self.0.try_decimal_sub(&other.0)?;
        if result.mantissa().is_negative() {
            return Err(NumericOperationError::QuantityUnderflow);
        }
        Self::from_canonical_numeric(result)
    }
    /// Alias for [`Self::try_sub`] emphasizing checked domain arithmetic.
    ///
    /// # Errors
    /// Returns quantity underflow or another canonical result-domain failure.
    pub fn checked_sub(&self, other: &Self) -> Result<Self, NumericOperationError> {
        self.try_sub(other)
    }
    /// Multiply a quantity by an exact decimal factor.
    ///
    /// # Errors
    /// Rejects negative or unrepresentable results.
    pub fn try_mul_decimal(&self, factor: &Numeric) -> Result<Self, NumericOperationError> {
        Self::from_canonical_numeric(self.0.try_decimal_mul(factor)?)
    }
    /// Multiply and divide exactly with one unbounded conceptual intermediate.
    ///
    /// # Errors
    /// Returns the precise exact-decimal failure and rejects negative results.
    pub fn try_mul_div_decimal_exact(
        &self,
        multiplier: &Numeric,
        divisor: &Numeric,
    ) -> Result<Self, NumericOperationError> {
        Self::from_canonical_numeric(self.0.try_decimal_mul_div_exact(multiplier, divisor)?)
    }
    /// Multiply and divide with one unbounded conceptual intermediate and an
    /// explicit final rounding policy.
    ///
    /// # Errors
    /// Returns the precise decimal failure and rejects negative results.
    pub fn try_mul_div_decimal_round(
        &self,
        multiplier: &Numeric,
        divisor: &Numeric,
        output_scale: u32,
        mode: RoundingMode,
    ) -> Result<Self, NumericOperationError> {
        Self::from_canonical_numeric(self.0.try_decimal_mul_div_round(
            multiplier,
            divisor,
            output_scale,
            mode,
        )?)
    }
    /// Compute a weighted average with unbounded conceptual intermediates.
    ///
    /// Each input contributes `value * weight` to the numerator. Products and their sum are not
    /// narrowed to the public 512-bit mantissa domain before division, so a representable average
    /// cannot fail merely because an intermediate weighted sum is wider than the final result.
    /// Zero-weight entries are accepted but do not make an otherwise empty denominator valid.
    ///
    /// This is a domain-aggregation primitive rather than a Kotodama numeric
    /// operator; VM opcodes continue to use the observed scalar operations.
    ///
    /// # Errors
    /// Rejects an output scale above 28, a zero total weight, a noncanonical
    /// input, or a final result outside the canonical quantity domain.
    pub fn try_weighted_average_round<'a, I>(
        values: I,
        output_scale: u32,
        mode: RoundingMode,
    ) -> Result<Self, NumericOperationError>
    where
        I: IntoIterator<Item = (&'a Self, u64)>,
    {
        if output_scale > MAX_DECIMAL_SCALE {
            return Err(NumericOperationError::InvalidScale);
        }
        let mut common_scale = 0_u32;
        let mut weighted_sum = UnboundedBigInt::zero();
        let mut total_weight = UnboundedBigInt::zero();
        for (value, weight) in values {
            value.0.validate_decimal()?;
            if weight == 0 {
                continue;
            }
            if value.scale() > common_scale {
                weighted_sum *= UnboundedBigInt::from(10_u8).pow(value.scale() - common_scale);
                common_scale = value.scale();
            }
            let mut contribution = value.mantissa().inner() * UnboundedBigInt::from(weight);
            if value.scale() < common_scale {
                contribution *= UnboundedBigInt::from(10_u8).pow(common_scale - value.scale());
            }
            weighted_sum += contribution;
            total_weight += UnboundedBigInt::from(weight);
        }
        if total_weight.is_zero() {
            return Err(NumericOperationError::DivisionByZero);
        }
        let (numerator, denominator) = if output_scale >= common_scale {
            (
                weighted_sum * UnboundedBigInt::from(10_u8).pow(output_scale - common_scale),
                total_weight,
            )
        } else {
            (
                weighted_sum,
                total_weight * UnboundedBigInt::from(10_u8).pow(common_scale - output_scale),
            )
        };
        let quotient = rounded_quotient(&numerator, &denominator, mode);
        Self::from_canonical_numeric(infallible_observed(
            canonical_decimal_from_unbounded_observed(quotient, output_scale, &mut |_| {
                Ok::<_, core::convert::Infallible>(())
            }),
        )?)
    }
    /// Multiply this quantity by a sequence of decimal factors using one
    /// unbounded conceptual product.
    ///
    /// This helper is for domain formulas whose factors are defined as one aggregate product. It
    /// deliberately differs from evaluating a source expression as repeated `quantity * decimal`
    /// operators, where every operator produces and checks its own public-domain result. Exact
    /// trailing-zero normalization is allowed between factors because it does not change the
    /// mathematical product.
    ///
    /// # Errors
    /// Rejects more than 64 factors, a noncanonical factor, or a canonical final result outside the
    /// decimal scale, signed-mantissa, or non-negative quantity domain.
    pub fn try_product_decimals<'a, I>(&self, factors: I) -> Result<Self, DecimalProductError>
    where
        I: IntoIterator<Item = &'a Numeric>,
    {
        self.0.validate_decimal()?;
        let ten = UnboundedBigInt::from(10_u8);
        let mut product = self.mantissa().inner().clone();
        let mut scale = u128::from(self.scale());
        for (index, factor) in factors.into_iter().enumerate() {
            if index >= MAX_DECIMAL_PRODUCT_FACTORS {
                return Err(DecimalProductError::TooManyFactors);
            }
            factor.validate_decimal()?;
            product *= factor.mantissa().inner();
            if product.is_zero() {
                scale = 0;
                continue;
            }
            scale = scale
                .checked_add(u128::from(factor.scale()))
                .ok_or(NumericOperationError::ScaleOverflow)?;
            while scale > 0 {
                let (quotient, remainder) = quotient_remainder(&product, &ten);
                if !remainder.is_zero() {
                    break;
                }
                product = quotient;
                scale -= 1;
            }
        }
        if scale > u128::from(MAX_DECIMAL_SCALE) {
            return Err(NumericOperationError::ScaleOverflow.into());
        }
        let scale = u32::try_from(scale).expect("validated decimal scale fits u32");
        Ok(Self::from_canonical_numeric(infallible_observed(
            canonical_decimal_from_unbounded_observed(product, scale, &mut |_| {
                Ok::<_, core::convert::Infallible>(())
            }),
        )?)?)
    }
    /// Multiply this quantity by decimal factors as one unbounded conceptual
    /// product, then round the aggregate once at `output_scale`.
    ///
    /// This is the rounded counterpart to [`Self::try_product_decimals`]. Intermediate products are
    /// never narrowed to the public mantissa or scale domain, so deterministic final rounding is
    /// independent of factor grouping.
    ///
    /// # Errors
    /// Rejects more than 64 factors, a scale above 28, a noncanonical factor,
    /// an aggregate scale that cannot be bounded safely, or a rounded result
    /// outside the canonical non-negative quantity domain.
    pub fn try_product_decimals_round<'a, I>(
        &self,
        factors: I,
        output_scale: u32,
        mode: RoundingMode,
    ) -> Result<Self, DecimalProductError>
    where
        I: IntoIterator<Item = &'a Numeric>,
    {
        if output_scale > MAX_DECIMAL_SCALE {
            return Err(NumericOperationError::InvalidScale.into());
        }
        self.0.validate_decimal()?;
        let ten = UnboundedBigInt::from(10_u8);
        let mut product = self.mantissa().inner().clone();
        let mut scale = u128::from(self.scale());
        for (index, factor) in factors.into_iter().enumerate() {
            if index >= MAX_DECIMAL_PRODUCT_FACTORS {
                return Err(DecimalProductError::TooManyFactors);
            }
            factor.validate_decimal()?;
            product *= factor.mantissa().inner();
            if product.is_zero() {
                scale = 0;
                continue;
            }
            scale = scale
                .checked_add(u128::from(factor.scale()))
                .ok_or(NumericOperationError::ScaleOverflow)?;
            while scale > 0 {
                let (quotient, remainder) = quotient_remainder(&product, &ten);
                if !remainder.is_zero() {
                    break;
                }
                product = quotient;
                scale -= 1;
            }
        }
        let output_scale_wide = u128::from(output_scale);
        let rounded = if scale > output_scale_wide {
            let reduction = u32::try_from(scale - output_scale_wide)
                .map_err(|_| NumericOperationError::ScaleOverflow)?;
            rounded_quotient(&product, &ten.pow(reduction), mode)
        } else {
            let expansion = u32::try_from(output_scale_wide - scale)
                .expect("validated output scale difference fits u32");
            product * ten.pow(expansion)
        };
        Ok(Self::from_canonical_numeric(infallible_observed(
            canonical_decimal_from_unbounded_observed(rounded, output_scale, &mut |_| {
                Ok::<_, core::convert::Infallible>(())
            }),
        )?)?)
    }
    /// Compare `self * self_multiplier` with `other * other_multiplier`.
    ///
    /// Products and decimal alignment are conceptual unbounded intermediates, so comparisons at the
    /// public mantissa boundary remain exact instead of failing merely because one side cannot be
    /// materialized as a standalone [`Quantity`].
    #[must_use]
    pub fn cmp_mul_u64(
        &self,
        self_multiplier: u64,
        other: &Self,
        other_multiplier: u64,
    ) -> Ordering {
        let common_scale = self.scale().max(other.scale());
        let lhs = self.mantissa().inner()
            * UnboundedBigInt::from(self_multiplier)
            * UnboundedBigInt::from(10_u8).pow(common_scale - self.scale());
        let rhs = other.mantissa().inner()
            * UnboundedBigInt::from(other_multiplier)
            * UnboundedBigInt::from(10_u8).pow(common_scale - other.scale());
        lhs.cmp(&rhs)
    }
    /// Divide a quantity by a decimal factor exactly.
    ///
    /// # Errors
    /// Returns the precise decimal failure and rejects negative results.
    pub fn try_div_decimal_exact(&self, divisor: &Numeric) -> Result<Self, NumericOperationError> {
        Self::from_canonical_numeric(self.0.try_decimal_div_exact(divisor)?)
    }
    /// Divide a quantity by a decimal factor with explicit rounding.
    ///
    /// # Errors
    /// Returns the precise decimal failure and rejects negative results.
    pub fn try_div_decimal_round(
        &self,
        divisor: &Numeric,
        output_scale: u32,
        mode: RoundingMode,
    ) -> Result<Self, NumericOperationError> {
        Self::from_canonical_numeric(self.0.try_decimal_div_round(divisor, output_scale, mode)?)
    }
    /// Compute the exact dimensionless ratio of two quantities.
    ///
    /// # Errors
    /// Returns the precise exact-decimal division failure.
    pub fn try_ratio_exact(&self, divisor: &Self) -> Result<Numeric, NumericOperationError> {
        self.0.try_decimal_div_exact(&divisor.0)
    }
    /// Compute a rounded dimensionless ratio of two quantities.
    ///
    /// # Errors
    /// Returns the precise rounded-decimal division failure.
    pub fn try_ratio_round(
        &self,
        divisor: &Self,
        output_scale: u32,
        mode: RoundingMode,
    ) -> Result<Numeric, NumericOperationError> {
        self.0.try_decimal_div_round(&divisor.0, output_scale, mode)
    }
}
impl Default for Quantity {
    fn default() -> Self {
        Self::zero()
    }
}
impl PartialOrd for Quantity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Quantity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}
impl core::fmt::Display for Quantity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt_numeric_decimal(&self.0, f)
    }
}
impl core::str::FromStr for Quantity {
    type Err = NumericOperationError;
    fn from_str(source: &str) -> Result<Self, Self::Err> {
        let value = source.parse::<Numeric>().map_err(|error| match error {
            NumericError::ScaleTooLarge => NumericOperationError::ScaleOverflow,
            NumericError::MantissaTooLarge | NumericError::Malformed => {
                NumericOperationError::MantissaOverflow
            }
        })?;
        Self::try_from_numeric(value)
    }
}
impl TryFrom<Numeric> for Quantity {
    type Error = NumericOperationError;
    fn try_from(value: Numeric) -> Result<Self, Self::Error> {
        Self::try_from_numeric(value)
    }
}
impl From<Quantity> for Numeric {
    fn from(value: Quantity) -> Self {
        value.0
    }
}
impl From<u32> for Quantity {
    fn from(value: u32) -> Self {
        Self(Numeric::from(value))
    }
}
impl From<u64> for Quantity {
    fn from(value: u64) -> Self {
        Self(Numeric::from(value))
    }
}
impl From<u128> for Quantity {
    fn from(value: u128) -> Self {
        Self(Numeric::new(BigInt::from(value), 0))
    }
}

impl SerializePayload for Quantity {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), Error> {
        self.0.serialize(writer)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.encoded_len_exact()
    }
}

impl<'a> DeserializePayload<'a> for Quantity {
    fn deserialize(archived: &'a Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("invalid canonical quantity")
    }
    fn try_deserialize(archived: &'a Archived<Self>) -> Result<Self, Error> {
        let numeric = Numeric::try_deserialize(archived.cast::<Numeric>())?;
        Self::from_canonical_numeric(numeric)
            .map_err(|error| Error::Message(format!("invalid quantity: {error}")))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for Quantity {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let (numeric, used) = <Numeric as norito::core::DecodeFromSlice>::decode_from_slice(bytes)?;
        let quantity = Self::from_canonical_numeric(numeric)
            .map_err(|error| norito::core::Error::Message(error.to_string()))?;
        Ok((quantity, used))
    }
}
impl FastJsonWrite for Quantity {
    fn write_json(&self, out: &mut String) {
        json::write_json_string(&self.to_string(), out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        json::write_json_display_to(self, out)
    }
}
impl JsonDeserialize for Quantity {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let mut preflight = *parser;
        preflight.skip_string_bounded(MAX_CANONICAL_QUANTITY_TEXT_BYTES)?;
        let value = parser.parse_string()?;
        Self::from_canonical_json_text(&value)
    }
    fn json_from_value(value: &json::Value) -> Result<Self, json::Error> {
        let source = value
            .as_str()
            .ok_or_else(|| invalid_quantity_json("expected quantity string"))?;
        Self::from_canonical_json_text(source)
    }
}
impl json::JsonObjectKey for Quantity {
    fn visit_json_key_text<E>(
        &self,
        mut visitor: impl FnMut(&str) -> Result<(), E>,
    ) -> Result<(), E> {
        let canonical = self.to_string();
        visitor(&canonical)
    }

    fn visit_json_key_text_checked(
        &self,
        visitor: impl FnMut(&str) -> Result<(), json::BoundedJsonError>,
    ) -> Result<(), json::BoundedJsonError> {
        json::visit_json_display_text(self, visitor)
    }
}
impl json::JsonObjectKeyOwned for Quantity {
    fn from_json_key_text(key: &str) -> Result<Self, json::Error> {
        Self::from_canonical_json_text(key)
    }
}

impl XorQuantity {
    /// Validate and wrap a canonical non-negative XOR quantity.
    ///
    /// # Errors
    /// Rejects values carrying more than [`XOR_QUANTITY_SCALE`] fractional digits.
    pub fn try_from_quantity(quantity: Quantity) -> Result<Self, XorQuantityError> {
        if quantity.scale() > XOR_QUANTITY_SCALE {
            return Err(XorQuantityError::ScaleOverflow {
                scale: quantity.scale(),
                max: XOR_QUANTITY_SCALE,
            });
        }
        Ok(Self(quantity))
    }
    /// Construct from an exact micro-XOR projection.
    ///
    /// This is an explicit adapter for versioned external formats that define their value in
    /// micro-XOR. New public APIs should accept decimal XOR quantities directly.
    ///
    /// # Errors
    /// Returns an error if construction exceeds the bounded decimal domain.
    pub fn try_from_micro(micro: u128) -> Result<Self, XorQuantityError> {
        let numeric = Numeric::try_new(micro, 6).map_err(|_| XorQuantityError::Overflow)?;
        Quantity::from_canonical_numeric(numeric)
            .map_err(XorQuantityError::from)
            .and_then(Self::try_from_quantity)
    }
    /// Borrow the canonical quantity.
    #[must_use]
    pub const fn as_quantity(&self) -> &Quantity {
        &self.0
    }
    /// Consume the nominal wrapper.
    #[must_use]
    pub fn into_quantity(self) -> Quantity {
        self.0
    }
    /// Return the zero amount.
    #[must_use]
    pub fn zero() -> Self {
        Self(Quantity::zero())
    }
    /// Whether the amount is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
    /// Project to micro-XOR exactly.
    ///
    /// This is an explicit adapter for versioned external formats. It never rounds or saturates.
    ///
    /// # Errors
    /// Rejects sub-micro precision and values wider than `u128`.
    pub fn try_to_micro(&self) -> Result<u128, XorQuantityError> {
        let scaled = self
            .0
            .try_mul_decimal(&Numeric::from(1_000_000_u64))
            .map_err(XorQuantityError::from)?;
        if scaled.scale() != 0 {
            return Err(XorQuantityError::InexactMicroProjection);
        }
        scaled
            .as_numeric()
            .try_mantissa_u128()
            .ok_or(XorQuantityError::Overflow)
    }
    /// Add two XOR amounts exactly.
    ///
    /// # Errors
    /// Returns a bounded-domain or XOR-scale failure.
    pub fn checked_add(&self, rhs: &Self) -> Result<Self, XorQuantityError> {
        self.0
            .checked_add(&rhs.0)
            .map_err(XorQuantityError::from)
            .and_then(Self::try_from_quantity)
    }
    /// Subtract two XOR amounts exactly.
    ///
    /// # Errors
    /// Returns underflow when `rhs` is greater than `self`.
    pub fn checked_sub(&self, rhs: &Self) -> Result<Self, XorQuantityError> {
        self.0
            .checked_sub(&rhs.0)
            .map_err(XorQuantityError::from)
            .and_then(Self::try_from_quantity)
    }
    /// Return the smaller amount.
    #[must_use]
    pub fn min(&self, other: &Self) -> Self {
        if self <= other {
            self.clone()
        } else {
            other.clone()
        }
    }
    /// Multiply by an unsigned 64-bit scalar.
    ///
    /// # Errors
    /// Returns a bounded-domain or XOR-scale failure.
    pub fn checked_mul_u64(&self, multiplier: u64) -> Result<Self, XorQuantityError> {
        self.checked_mul_u128(u128::from(multiplier))
    }
    /// Multiply by an unsigned 128-bit scalar.
    ///
    /// # Errors
    /// Returns a bounded-domain or XOR-scale failure.
    pub fn checked_mul_u128(&self, multiplier: u128) -> Result<Self, XorQuantityError> {
        self.0
            .try_mul_decimal(&Numeric::new(multiplier, 0))
            .map_err(XorQuantityError::from)
            .and_then(Self::try_from_quantity)
    }
    /// Divide by a positive integer with explicit output scale and rounding.
    ///
    /// # Errors
    /// Returns a bounded-domain or XOR-scale failure.
    pub fn checked_div_u64_round(
        &self,
        divisor: core::num::NonZeroU64,
        output_scale: u32,
        rounding: RoundingMode,
    ) -> Result<Self, XorQuantityError> {
        if output_scale > XOR_QUANTITY_SCALE {
            return Err(XorQuantityError::ScaleOverflow {
                scale: output_scale,
                max: XOR_QUANTITY_SCALE,
            });
        }
        self.0
            .try_div_decimal_round(&Numeric::from(divisor.get()), output_scale, rounding)
            .map_err(XorQuantityError::from)
            .and_then(Self::try_from_quantity)
    }
    /// Apply a basis-point ratio (`basis_points / 10_000`) toward zero.
    ///
    /// # Errors
    /// Returns a bounded-domain or XOR-scale failure.
    pub fn checked_mul_basis_points(&self, basis_points: u16) -> Result<Self, XorQuantityError> {
        self.checked_mul_basis_points_u32(u32::from(basis_points))
    }
    /// Apply a basis-point ratio whose numerator may exceed `u16`.
    ///
    /// # Errors
    /// Returns a bounded-domain or XOR-scale failure.
    pub fn checked_mul_basis_points_u32(
        &self,
        basis_points: u32,
    ) -> Result<Self, XorQuantityError> {
        self.checked_mul_ratio(
            u64::from(basis_points),
            core::num::NonZeroU64::new(10_000).expect("basis-point denominator is non-zero"),
        )
    }
    /// Multiply by an unsigned rational factor, rounding toward zero at XOR's maximum scale.
    ///
    /// # Errors
    /// Returns a bounded-domain or XOR-scale failure.
    pub fn checked_mul_ratio(
        &self,
        numerator: u64,
        denominator: core::num::NonZeroU64,
    ) -> Result<Self, XorQuantityError> {
        self.checked_mul_ratio_round(
            numerator,
            denominator,
            XOR_QUANTITY_SCALE,
            RoundingMode::TowardZero,
        )
    }
    /// Multiply by an unsigned rational factor using an explicit rounding policy and output scale.
    ///
    /// # Errors
    /// Returns a bounded-domain or XOR-scale failure.
    pub fn checked_mul_ratio_round(
        &self,
        numerator: u64,
        denominator: core::num::NonZeroU64,
        output_scale: u32,
        rounding: RoundingMode,
    ) -> Result<Self, XorQuantityError> {
        if output_scale > XOR_QUANTITY_SCALE {
            return Err(XorQuantityError::ScaleOverflow {
                scale: output_scale,
                max: XOR_QUANTITY_SCALE,
            });
        }
        self.0
            .try_mul_div_decimal_round(
                &Numeric::from(numerator),
                &Numeric::from(denominator.get()),
                output_scale,
                rounding,
            )
            .map_err(XorQuantityError::from)
            .and_then(Self::try_from_quantity)
    }
}
impl Default for XorQuantity {
    fn default() -> Self {
        Self::zero()
    }
}
impl PartialOrd for XorQuantity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for XorQuantity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}
impl core::fmt::Display for XorQuantity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(formatter)
    }
}
impl core::str::FromStr for XorQuantity {
    type Err = XorQuantityError;
    fn from_str(source: &str) -> Result<Self, Self::Err> {
        source
            .parse::<Quantity>()
            .map_err(XorQuantityError::from)
            .and_then(Self::try_from_quantity)
    }
}
impl TryFrom<Quantity> for XorQuantity {
    type Error = XorQuantityError;
    fn try_from(value: Quantity) -> Result<Self, Self::Error> {
        Self::try_from_quantity(value)
    }
}
impl From<XorQuantity> for Quantity {
    fn from(value: XorQuantity) -> Self {
        value.0
    }
}

impl SerializePayload for XorQuantity {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), Error> {
        self.0.serialize(writer)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.encoded_len_exact()
    }
}

impl<'a> DeserializePayload<'a> for XorQuantity {
    fn deserialize(archived: &'a Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("invalid canonical XOR quantity")
    }
    fn try_deserialize(archived: &'a Archived<Self>) -> Result<Self, Error> {
        let quantity = Quantity::try_deserialize(archived.cast::<Quantity>())?;
        Self::try_from_quantity(quantity)
            .map_err(|error| Error::Message(format!("invalid XOR quantity: {error}")))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for XorQuantity {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let (quantity, used) =
            <Quantity as norito::core::DecodeFromSlice>::decode_from_slice(bytes)?;
        let value = Self::try_from_quantity(quantity)
            .map_err(|error| norito::core::Error::Message(error.to_string()))?;
        Ok((value, used))
    }
}
impl FastJsonWrite for XorQuantity {
    fn write_json(&self, out: &mut String) {
        self.0.write_json(out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        self.0.write_json_to(out)
    }
}
impl JsonDeserialize for XorQuantity {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let quantity = Quantity::json_deserialize(parser)?;
        Self::try_from_quantity(quantity).map_err(|error| json::Error::InvalidField {
            field: "xor_quantity".into(),
            message: error.to_string(),
        })
    }
}
impl From<NumericOperationError> for XorQuantityError {
    fn from(value: NumericOperationError) -> Self {
        match value {
            NumericOperationError::QuantityUnderflow => Self::Underflow,
            NumericOperationError::NegativeQuantity => Self::NegativeQuantity,
            NumericOperationError::InexactConversion => Self::InexactMicroProjection,
            NumericOperationError::MantissaOverflow
            | NumericOperationError::ScaleOverflow
            | NumericOperationError::DivisionByZero
            | NumericOperationError::RepeatingDecimal
            | NumericOperationError::ExactDivisionScaleOverflow
            | NumericOperationError::InvalidScale
            | NumericOperationError::NegativeSquareRoot
            | NumericOperationError::NonCanonical => Self::Overflow,
        }
    }
}
fn infallible_observed<T>(
    result: Result<T, ObservedNumericError<core::convert::Infallible>>,
) -> Result<T, NumericOperationError> {
    match result {
        Ok(value) => Ok(value),
        Err(ObservedNumericError::Numeric(error)) => Err(error),
        Err(ObservedNumericError::Observer(never)) => match never {},
    }
}
/// Shared exact canonicality decision; the observer still precedes all probe work.
fn validate_decimal_parts_observed<E>(
    scale: u32,
    zero: bool,
    mantissa_limbs: u16,
    divisible_by_ten: impl FnOnce() -> bool,
    observer: &mut impl FnMut(NumericWorkStep) -> Result<(), E>,
) -> Result<(), ObservedNumericError<E>> {
    if scale == 0 {
        return Ok(());
    }
    if zero {
        return Err(ObservedNumericError::Numeric(
            NumericOperationError::NonCanonical,
        ));
    }
    observer(NumericWorkStep::CanonicalityProbe {
        mantissa_limbs,
        scale: u8::try_from(scale).expect("validated scale fits u8"),
    })
    .map_err(ObservedNumericError::Observer)?;
    if divisible_by_ten() {
        return Err(ObservedNumericError::Numeric(
            NumericOperationError::NonCanonical,
        ));
    }
    Ok(())
}
/// Exact unsigned-magnitude remainder, highest u64 digit first, without scratch.
/// Sign does not affect whether a signed mantissa is divisible by ten.
fn magnitude_divisible_by_ten(digits: impl Iterator<Item = u64>) -> bool {
    digits.fold(0_u128, |remainder, digit| {
        ((remainder << 64) | u128::from(digit)) % 10
    }) == 0
}
fn logical_limbs(value: &UnboundedBigInt) -> u16 {
    let bits = value.bits();
    let limbs = bits.max(1).div_ceil(64);
    u16::try_from(limbs).unwrap_or(u16::MAX)
}
fn quotient_remainder(
    numerator: &UnboundedBigInt,
    denominator: &UnboundedBigInt,
) -> (UnboundedBigInt, UnboundedBigInt) {
    let quotient = numerator / denominator;
    let remainder = numerator - (&quotient * denominator);
    (quotient, remainder)
}
fn canonical_decimal_from_unbounded_observed<E, F>(
    mut mantissa: UnboundedBigInt,
    mut scale: u32,
    observer: &mut F,
) -> Result<Numeric, ObservedNumericError<E>>
where
    F: FnMut(NumericWorkStep) -> Result<(), E>,
{
    let ten = UnboundedBigInt::from(10_u8);
    if mantissa.is_zero() {
        // Zero has a dedicated canonicalization rule and needs no
        // divide-by-ten probe: `(0, s)` becomes `(0, 0)` directly.
        scale = 0;
    }
    while scale > 0 {
        observer(NumericWorkStep::Normalize {
            mantissa_limbs: logical_limbs(&mantissa),
            remaining_scale: u8::try_from(scale).unwrap_or(u8::MAX),
        })
        .map_err(ObservedNumericError::Observer)?;
        let (quotient, remainder) = quotient_remainder(&mantissa, &ten);
        if !remainder.is_zero() {
            break;
        }
        mantissa = quotient;
        scale -= 1;
    }
    if scale > MAX_DECIMAL_SCALE {
        return Err(ObservedNumericError::Numeric(
            NumericOperationError::ScaleOverflow,
        ));
    }
    let mantissa = finalize_bigint_observed(mantissa, observer)?;
    Numeric::try_new_raw(mantissa, scale).map_err(|error| {
        ObservedNumericError::Numeric(match error {
            NumericError::MantissaTooLarge => NumericOperationError::MantissaOverflow,
            NumericError::ScaleTooLarge => NumericOperationError::ScaleOverflow,
            NumericError::Malformed => unreachable!("structured numeric fields are well formed"),
        })
    })
}
fn finalize_bigint_observed<E, F>(
    value: UnboundedBigInt,
    observer: &mut F,
) -> Result<BigInt, ObservedNumericError<E>>
where
    F: FnMut(NumericWorkStep) -> Result<(), E>,
{
    observer(NumericWorkStep::Finalize {
        value_limbs: logical_limbs(&value),
    })
    .map_err(ObservedNumericError::Observer)?;
    BigInt::from_inner(value)
        .map_err(|_| ObservedNumericError::Numeric(NumericOperationError::MantissaOverflow))
}
fn mantissa_fits_numeric_domain(value: &BigInt) -> bool {
    value.twos_byte_len() <= MAX_MANTISSA_BYTES
}
fn decimal_division_operands_observed<E, F>(
    dividend: &Numeric,
    divisor: &Numeric,
    output_scale: u32,
    observer: &mut F,
) -> Result<(UnboundedBigInt, UnboundedBigInt), ObservedNumericError<E>>
where
    F: FnMut(NumericWorkStep) -> Result<(), E>,
{
    let numerator_scale = divisor.scale + output_scale;
    let (numerator_delta, denominator_delta) = if numerator_scale >= dividend.scale {
        (numerator_scale - dividend.scale, 0)
    } else {
        (0, dividend.scale - numerator_scale)
    };
    let numerator = scale_unbounded_observed(dividend.mantissa.inner(), numerator_delta, observer)?;
    let denominator =
        scale_unbounded_observed(divisor.mantissa.inner(), denominator_delta, observer)?;
    Ok((numerator, denominator))
}
fn decimal_product_division_operands_observed<E, F>(
    product: &UnboundedBigInt,
    product_scale: u32,
    divisor: &Numeric,
    output_scale: u32,
    observer: &mut F,
) -> Result<(UnboundedBigInt, UnboundedBigInt), ObservedNumericError<E>>
where
    F: FnMut(NumericWorkStep) -> Result<(), E>,
{
    let numerator_scale =
        divisor
            .scale
            .checked_add(output_scale)
            .ok_or(ObservedNumericError::Numeric(
                NumericOperationError::ScaleOverflow,
            ))?;
    let (numerator_delta, denominator_delta) = if numerator_scale >= product_scale {
        (numerator_scale - product_scale, 0)
    } else {
        (0, product_scale - numerator_scale)
    };
    let numerator = scale_unbounded_observed(product, numerator_delta, observer)?;
    let denominator =
        scale_unbounded_observed(divisor.mantissa.inner(), denominator_delta, observer)?;
    Ok((numerator, denominator))
}
fn exact_division_at_scale_observed<E, F>(
    dividend: &Numeric,
    divisor: &Numeric,
    output_scale: u32,
    observer: &mut F,
) -> Result<Option<Numeric>, ObservedNumericError<E>>
where
    F: FnMut(NumericWorkStep) -> Result<(), E>,
{
    let (numerator, denominator) =
        decimal_division_operands_observed(dividend, divisor, output_scale, observer)?;
    observer(NumericWorkStep::ExactDivisionAttempt {
        numerator_limbs: logical_limbs(&numerator),
        denominator_limbs: logical_limbs(&denominator),
        output_scale: u8::try_from(output_scale).expect("validated scale fits u8"),
    })
    .map_err(ObservedNumericError::Observer)?;
    let (quotient, remainder) = quotient_remainder(&numerator, &denominator);
    if !remainder.is_zero() {
        return Ok(None);
    }
    canonical_decimal_from_unbounded_observed(quotient, output_scale, observer).map(Some)
}
fn exact_product_division_at_scale_observed<E, F>(
    product: &UnboundedBigInt,
    product_scale: u32,
    divisor: &Numeric,
    output_scale: u32,
    observer: &mut F,
) -> Result<Option<Numeric>, ObservedNumericError<E>>
where
    F: FnMut(NumericWorkStep) -> Result<(), E>,
{
    let (numerator, denominator) = decimal_product_division_operands_observed(
        product,
        product_scale,
        divisor,
        output_scale,
        observer,
    )?;
    observer(NumericWorkStep::ExactDivisionAttempt {
        numerator_limbs: logical_limbs(&numerator),
        denominator_limbs: logical_limbs(&denominator),
        output_scale: u8::try_from(output_scale).expect("validated scale fits u8"),
    })
    .map_err(ObservedNumericError::Observer)?;
    let (quotient, remainder) = quotient_remainder(&numerator, &denominator);
    if !remainder.is_zero() {
        return Ok(None);
    }
    canonical_decimal_from_unbounded_observed(quotient, output_scale, observer).map(Some)
}
fn classification_division<E, F>(
    dividend: &UnboundedBigInt,
    divisor: &UnboundedBigInt,
    observer: &mut F,
) -> Result<(UnboundedBigInt, UnboundedBigInt), ObservedNumericError<E>>
where
    F: FnMut(NumericWorkStep) -> Result<(), E>,
{
    observer(NumericWorkStep::DivisionClassification {
        dividend_limbs: logical_limbs(dividend),
        divisor_limbs: logical_limbs(divisor),
    })
    .map_err(ObservedNumericError::Observer)?;
    Ok(quotient_remainder(dividend, divisor))
}
fn classify_exact_division_inner<E, F>(
    dividend: &Numeric,
    divisor: &Numeric,
    observer: &mut F,
) -> Result<ExactDivisionClass, ObservedNumericError<E>>
where
    F: FnMut(NumericWorkStep) -> Result<(), E>,
{
    let (numerator, denominator) =
        decimal_division_operands_observed(dividend, divisor, 0, observer)?;
    classify_exact_rational_observed(&numerator, &denominator, observer)
}
fn classify_exact_rational_observed<E, F>(
    numerator: &UnboundedBigInt,
    denominator: &UnboundedBigInt,
    observer: &mut F,
) -> Result<ExactDivisionClass, ObservedNumericError<E>>
where
    F: FnMut(NumericWorkStep) -> Result<(), E>,
{
    observer(NumericWorkStep::DivisionClassificationPrepare {
        numerator_limbs: logical_limbs(numerator),
        denominator_limbs: logical_limbs(denominator),
    })
    .map_err(ObservedNumericError::Observer)?;
    let absolute_denominator = denominator.abs();
    let mut lhs = numerator.abs();
    let mut rhs = absolute_denominator.clone();
    while !rhs.is_zero() {
        let (_, remainder) = classification_division(&lhs, &rhs, observer)?;
        lhs = rhs;
        rhs = remainder;
    }
    let mut reduced_denominator = if lhs.is_one() {
        absolute_denominator
    } else {
        classification_division(&absolute_denominator, &lhs, observer)?.0
    };
    let mut factors_two = 0_u32;
    let mut factors_five = 0_u32;
    for (prime, count) in [
        (UnboundedBigInt::from(2_u8), &mut factors_two),
        (UnboundedBigInt::from(5_u8), &mut factors_five),
    ] {
        while reduced_denominator > UnboundedBigInt::one() {
            let (quotient, remainder) =
                classification_division(&reduced_denominator, &prime, observer)?;
            if !remainder.is_zero() {
                break;
            }
            reduced_denominator = quotient;
            *count += 1;
        }
    }
    if reduced_denominator != UnboundedBigInt::one() {
        return Ok(ExactDivisionClass::Repeating);
    }
    let minimum_scale = factors_two.max(factors_five);
    if minimum_scale > MAX_DECIMAL_SCALE {
        return Ok(ExactDivisionClass::ScaleOverflow);
    }
    Ok(ExactDivisionClass::Representable {
        minimum_scale: u8::try_from(minimum_scale).expect("bounded minimum scale"),
    })
}
fn rounded_quotient(
    numerator: &UnboundedBigInt,
    denominator: &UnboundedBigInt,
    mode: RoundingMode,
) -> UnboundedBigInt {
    let (mut quotient, remainder) = quotient_remainder(numerator, denominator);
    if remainder.is_zero() {
        return quotient;
    }
    let direction = if numerator.is_negative() == denominator.is_negative() {
        UnboundedBigInt::one()
    } else {
        -UnboundedBigInt::one()
    };
    let increment = match mode {
        RoundingMode::TowardZero => false,
        RoundingMode::AwayFromZero => true,
        RoundingMode::Floor => direction.is_negative(),
        RoundingMode::Ceil => direction.is_positive(),
        RoundingMode::NearestEven | RoundingMode::NearestAway | RoundingMode::NearestTowardZero => {
            let doubled_remainder: UnboundedBigInt = remainder.abs() << 1_usize;
            match doubled_remainder.cmp(&denominator.abs()) {
                Ordering::Less => false,
                Ordering::Greater => true,
                Ordering::Equal => match mode {
                    RoundingMode::NearestEven => !(&quotient & UnboundedBigInt::one()).is_zero(),
                    RoundingMode::NearestAway => true,
                    RoundingMode::NearestTowardZero => false,
                    _ => unreachable!("matched nearest rounding modes"),
                },
            }
        }
    };
    if increment {
        quotient += direction;
    }
    quotient
}
fn scale_unbounded_observed<E, F>(
    value: &UnboundedBigInt,
    decimal_places: u32,
    observer: &mut F,
) -> Result<UnboundedBigInt, ObservedNumericError<E>>
where
    F: FnMut(NumericWorkStep) -> Result<(), E>,
{
    if decimal_places == 0 || value.is_zero() {
        observer(NumericWorkStep::Materialize {
            value_limbs: logical_limbs(value),
        })
        .map_err(ObservedNumericError::Observer)?;
        return Ok(value.clone());
    }
    observer(NumericWorkStep::ScaleByPowerOfTen {
        value_limbs: logical_limbs(value),
        exponent: u8::try_from(decimal_places).unwrap_or(u8::MAX),
    })
    .map_err(ObservedNumericError::Observer)?;
    Ok(value * decimal_power_unbounded(decimal_places))
}
fn scale_unbounded(value: &UnboundedBigInt, decimal_places: u32) -> UnboundedBigInt {
    if decimal_places == 0 || value.is_zero() {
        return value.clone();
    }
    value * decimal_power_unbounded(decimal_places)
}
fn decimal_power_unbounded(decimal_places: u32) -> UnboundedBigInt {
    let ten = UnboundedBigInt::from(10_u8);
    let mut power = UnboundedBigInt::one();
    for _ in 0..decimal_places {
        power *= &ten;
    }
    power
}
impl Numeric {
    /// Encode this `Numeric` into Norito bytes.
    pub fn encode(&self) -> Vec<u8> {
        let helper = scale_::NumericScaleHelper {
            mantissa: self.mantissa.clone(),
            scale: self.scale(),
        };
        norito::codec::Encode::encode(&helper)
    }
    /// Decode `Numeric` from Norito-encoded input.
    ///
    /// # Errors
    /// Returns an error if the input does not contain a valid [`Numeric`]
    /// representation or if its mantissa or scale exceed supported limits.
    pub fn decode<I: norito::codec::Input>(input: &mut I) -> Result<Self, norito::Error> {
        let scale_::NumericScaleHelper { mantissa, scale } =
            <scale_::NumericScaleHelper as norito::codec::Decode>::decode(input)?;
        match Numeric::try_new_raw(mantissa, scale) {
            Ok(numeric) => {
                numeric.validate_decimal().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "error decoding numeric: noncanonical representation",
                    )
                })?;
                Ok(numeric)
            }
            Err(NumericError::MantissaTooLarge) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "error decoding numeric: mantissa too large",
            )
            .into()),
            Err(NumericError::ScaleTooLarge) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "error decoding numeric: scale too large",
            )
            .into()),
            Err(NumericError::Malformed) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "error decoding numeric: malformed",
            )
            .into()),
        }
    }
}

impl SerializePayload for Numeric {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), Error> {
        scale_::NumericScaleHelperView {
            mantissa: scale_::BigIntView(&self.mantissa),
            scale: self.scale(),
        }
        .serialize(writer)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        scale_::NumericScaleHelperView {
            mantissa: scale_::BigIntView(&self.mantissa),
            scale: self.scale(),
        }
        .encoded_len_exact()
    }
}

impl<'a> DeserializePayload<'a> for Numeric {
    fn deserialize(archived: &'a Archived<Numeric>) -> Self {
        Self::try_deserialize(archived).expect("invalid numeric")
    }
    fn try_deserialize(archived: &'a Archived<Numeric>) -> Result<Self, Error> {
        let helper_align = norito::core::archived_payload_align::<scale_::NumericScaleHelper>();
        let numeric_align = norito::core::archived_payload_align::<Numeric>();
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let aligned = numeric_align >= helper_align || (ptr as usize).is_multiple_of(helper_align);
        if aligned {
            let helper_arch: &Archived<scale_::NumericScaleHelper> = archived.cast();
            let helper = scale_::NumericScaleHelper::try_deserialize(helper_arch)?;
            let value = Numeric::try_new_raw(helper.mantissa, helper.scale)
                .map_err(|err| Error::Message(format!("invalid numeric: {err}")))?;
            value
                .validate_decimal()
                .map_err(|err| Error::Message(format!("invalid numeric: {err}")))?;
            Ok(value)
        } else {
            let slice = norito::core::payload_slice_from_ptr(ptr)?;
            let (value, _) = <Numeric as norito::core::DecodeFromSlice>::decode_from_slice(slice)?;
            Ok(value)
        }
    }
}
impl FastJsonWrite for Numeric {
    fn write_json(&self, out: &mut String) {
        json::write_json_string(&self.to_string(), out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        json::write_json_display_to(self, out)
    }
}
impl JsonDeserialize for Numeric {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value = parser.parse_string()?;
        let parsed = value
            .parse::<Numeric>()
            .map_err(|err| json::Error::InvalidField {
                field: "numeric".into(),
                message: format!("invalid numeric `{value}`: {err}"),
            })?;
        if parsed.to_string() != value {
            return Err(json::Error::InvalidField {
                field: "numeric".into(),
                message: format!("noncanonical numeric `{value}`"),
            });
        }
        Ok(parsed)
    }
}
impl From<u32> for Numeric {
    fn from(value: u32) -> Self {
        Self::new(BigInt::from(i128::from(value)), 0)
    }
}
impl From<u64> for Numeric {
    fn from(value: u64) -> Self {
        Self::new(BigInt::from(i128::from(value)), 0)
    }
}
impl From<i64> for Numeric {
    fn from(value: i64) -> Self {
        Self::new(BigInt::from(i128::from(value)), 0)
    }
}
impl TryFrom<Numeric> for u32 {
    type Error = TryFromNumericError;
    fn try_from(value: Numeric) -> Result<Self, Self::Error> {
        value
            .to_string()
            .parse::<u32>()
            .map_err(|_| TryFromNumericError)
    }
}
impl TryFrom<Numeric> for u64 {
    type Error = TryFromNumericError;
    fn try_from(value: Numeric) -> Result<Self, Self::Error> {
        value
            .to_string()
            .parse::<u64>()
            .map_err(|_| TryFromNumericError)
    }
}
impl Ord for Numeric {
    fn cmp(&self, other: &Self) -> Ordering {
        let target_scale = self.scale.max(other.scale);
        let lhs = scale_unbounded(self.mantissa.inner(), target_scale - self.scale);
        let rhs = scale_unbounded(other.mantissa.inner(), target_scale - other.scale);
        lhs.cmp(&rhs)
    }
}
impl PartialOrd for Numeric {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl NumericSpec {
    fn try_from_scale(scale: Option<u32>) -> Result<Self, NumericSpecError> {
        if scale.is_some_and(|scale| scale > MAX_DECIMAL_SCALE) {
            return Err(NumericSpecError::ScaleTooHigh);
        }
        Ok(Self { scale })
    }
    /// Check if given numeric satisfy constrains
    ///
    /// # Errors
    /// If given number has precision or scale higher than specified by spec.
    pub fn check(self, numeric: &Numeric) -> Result<(), NumericSpecError> {
        if let Some(allowed_scale) = self.scale {
            let actual_scale = numeric.scale();
            if actual_scale <= allowed_scale {
                return Ok(());
            }
            // Allow higher-scale representations when the extra fractional digits are all zero
            // (e.g., "1.00" should satisfy an integer-only spec).
            let trim = actual_scale - allowed_scale;
            let factor = BigInt::pow10(trim).ok_or(NumericSpecError::ScaleTooHigh)?;
            if numeric
                .mantissa()
                .clone()
                .checked_div_rem(&factor)
                .is_ok_and(|(_, rem)| rem.is_zero())
            {
                return Ok(());
            }
            return Err(NumericSpecError::ScaleTooHigh);
        }
        Ok(())
    }
    /// Create [`NumericSpec`] which accepts any numeric value
    #[inline]
    pub const fn unconstrained() -> Self {
        NumericSpec { scale: None }
    }
    /// Create [`NumericSpec`] which accepts only integer values
    #[inline]
    pub const fn integer() -> Self {
        Self { scale: Some(0) }
    }
    /// Try to create a specification accepting at most `scale` decimal places.
    ///
    /// # Errors
    /// Returns [`NumericSpecError::ScaleTooHigh`] when `scale` exceeds the V1
    /// numeric-domain maximum of 28.
    #[inline]
    pub const fn try_fractional(scale: u32) -> Result<Self, NumericSpecError> {
        if scale > MAX_DECIMAL_SCALE {
            return Err(NumericSpecError::ScaleTooHigh);
        }
        Ok(Self { scale: Some(scale) })
    }
    /// Create [`NumericSpec`] which accepts numeric values with scale up to given decimal places.
    ///
    /// # Panics
    /// Panics when `scale` exceeds the V1 numeric-domain maximum of 28. Use
    /// [`Self::try_fractional`] for untrusted or runtime-supplied scales.
    #[inline]
    pub const fn fractional(scale: u32) -> Self {
        assert!(
            scale <= MAX_DECIMAL_SCALE,
            "numeric specification scale exceeds the V1 maximum of 28"
        );
        Self { scale: Some(scale) }
    }
    /// Get the scale
    #[inline]
    pub const fn scale(self) -> Option<u32> {
        self.scale
    }
}
impl core::str::FromStr for Numeric {
    type Err = NumericError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(NumericError::Malformed);
        }
        let (negative, digits) = match trimmed.as_bytes().first() {
            Some(b'-') => (true, &trimmed[1..]),
            Some(b'+') => (false, &trimmed[1..]),
            _ => (false, trimmed),
        };
        let mut scale = 0u32;
        let mut mantissa_str = String::new();
        let mut seen_dot = false;
        for ch in digits.chars() {
            if ch == '.' {
                if seen_dot {
                    return Err(NumericError::Malformed);
                }
                seen_dot = true;
                continue;
            }
            if !ch.is_ascii_digit() {
                return Err(NumericError::Malformed);
            }
            mantissa_str.push(ch);
            if seen_dot {
                scale = scale.saturating_add(1);
            }
        }
        while scale > 0 && mantissa_str.ends_with('0') {
            mantissa_str.pop();
            scale -= 1;
        }
        if mantissa_str.is_empty() {
            return Err(NumericError::Malformed);
        }
        if mantissa_str.bytes().all(|byte| byte == b'0') {
            return Ok(Numeric::zero());
        }
        if negative {
            mantissa_str.insert(0, '-');
        }
        let unbounded = mantissa_str
            .parse::<UnboundedBigInt>()
            .map_err(|_| NumericError::Malformed)?;
        let mantissa = BigInt::from_inner(unbounded).map_err(|_| NumericError::MantissaTooLarge)?;
        Numeric::try_new(mantissa, scale)
    }
}
impl core::fmt::Display for NumericSpec {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Numeric")?;
        if let Some(scale) = self.scale {
            write!(f, "({scale})")?;
        }
        Ok(())
    }
}
fn fmt_numeric_decimal(
    value: &Numeric,
    formatter: &mut core::fmt::Formatter<'_>,
) -> core::fmt::Result {
    const MAX_U64_LIMBS: usize = MAX_MANTISSA_BYTES / core::mem::size_of::<u64>();
    const FRACTIONAL_ZEROES: &str = "0000000000000000000000000000";

    let mut limbs = [0_u64; MAX_U64_LIMBS];
    let mut limb_count = 0usize;
    for limb in value.mantissa.inner().magnitude().iter_u64_digits() {
        let slot = limbs.get_mut(limb_count).ok_or(core::fmt::Error)?;
        *slot = limb;
        limb_count += 1;
    }

    let mut digits = [0_u8; MAX_QUANTITY_MANTISSA_DECIMAL_DIGITS];
    let mut digit_start = digits.len();
    while limb_count != 0 {
        let mut remainder = 0_u128;
        for limb in limbs[..limb_count].iter_mut().rev() {
            let dividend = (remainder << 64) | u128::from(*limb);
            *limb = u64::try_from(dividend / 10).expect("base-ten quotient fits u64");
            remainder = dividend % 10;
        }
        while limb_count != 0 && limbs[limb_count - 1] == 0 {
            limb_count -= 1;
        }
        digit_start = digit_start.checked_sub(1).ok_or(core::fmt::Error)?;
        digits[digit_start] =
            b'0' + u8::try_from(remainder).expect("base-ten remainder is one digit");
    }
    if digit_start == digits.len() {
        digit_start -= 1;
        digits[digit_start] = b'0';
    }
    let digits = core::str::from_utf8(&digits[digit_start..]).map_err(|_| core::fmt::Error)?;
    let scale = usize::try_from(value.scale).map_err(|_| core::fmt::Error)?;
    if scale > FRACTIONAL_ZEROES.len() {
        return Err(core::fmt::Error);
    }
    if value.mantissa.is_negative() {
        formatter.write_str("-")?;
    }
    if scale == 0 {
        return formatter.write_str(digits);
    }
    if digits.len() > scale {
        let split = digits.len() - scale;
        formatter.write_str(&digits[..split])?;
        formatter.write_str(".")?;
        formatter.write_str(&digits[split..])
    } else {
        formatter.write_str("0.")?;
        formatter.write_str(&FRACTIONAL_ZEROES[..scale - digits.len()])?;
        formatter.write_str(digits)
    }
}
impl core::fmt::Display for Numeric {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt_numeric_decimal(self, f)
    }
}
mod scale_ {
    /// Borrowed wire-compatible view of a numeric mantissa.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_primitives::numeric::scale_::BigIntView",
        frame = "iroha_primitives::bigint::BigInt"
    )]
    pub(super) struct BigIntView<'a>(
        /// Canonical bounded integer serialized by the view.
        pub(super) &'a crate::bigint::BigInt,
    );

    impl norito::core::SerializePayload for BigIntView<'_> {
        fn serialize(
            &self,
            writer: &mut norito::core::Encoder<'_>,
        ) -> Result<(), norito::core::Error> {
            norito::core::SerializePayload::serialize(self.0, writer)
        }
        fn encoded_len_hint(&self) -> Option<usize> {
            norito::core::SerializePayload::encoded_len_hint(self.0)
        }
        fn encoded_len_exact(&self) -> Option<usize> {
            norito::core::SerializePayload::encoded_len_exact(self.0)
        }
    }
    #[allow(unexpected_cfgs)]
    #[derive(norito::Encode, norito::Decode)]
    #[norito(decode_fields, decode_from_slice)]
    /// Internal helper used to encode/decode Numeric as `(mantissa, scale)`.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_primitives::numeric::scale_::NumericScaleHelper")]
    pub(super) struct NumericScaleHelper {
        /// Mantissa carried by the numeric helper.
        #[codec(compact)]
        pub(super) mantissa: crate::bigint::BigInt,
        /// Scale carried by the numeric helper.
        #[codec(compact)]
        pub(super) scale: u32,
    }
    #[allow(unexpected_cfgs)]
    #[derive(norito::Encode)]
    /// Borrowed wire-compatible view used to serialize and size a canonical numeric.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_primitives::numeric::scale_::NumericScaleHelperView")]
    pub(super) struct NumericScaleHelperView<'a> {
        /// Borrowed canonical mantissa.
        #[codec(compact)]
        pub(super) mantissa: BigIntView<'a>,
        /// Canonical decimal scale.
        #[codec(compact)]
        pub(super) scale: u32,
    }
}
mod schema_ {
    use super::*;
    use iroha_schema::{
        Compact, Declaration, Ident, IntoSchema, MetaMap, Metadata, NamedFieldsMeta, TypeId,
    };
    impl TypeId for Numeric {
        fn id() -> Ident {
            "Numeric".to_string()
        }
    }
    impl IntoSchema for Numeric {
        fn type_name() -> Ident {
            "Numeric".to_string()
        }
        fn update_schema_map(metamap: &mut MetaMap) {
            if !metamap.contains_key::<Self>() {
                <crate::bigint::BigInt as iroha_schema::IntoSchema>::update_schema_map(metamap);
                <Compact<u32> as iroha_schema::IntoSchema>::update_schema_map(metamap);
                metamap.insert::<Self>(Metadata::Struct(NamedFieldsMeta {
                    declarations: vec![
                        Declaration {
                            name: "mantissa".to_string(),
                            ty: core::any::TypeId::of::<crate::bigint::BigInt>(),
                        },
                        Declaration {
                            name: "scale".to_string(),
                            ty: core::any::TypeId::of::<Compact<u32>>(),
                        },
                    ],
                }));
            }
        }
    }
    impl TypeId for Quantity {
        fn id() -> Ident {
            "Quantity".to_string()
        }
    }
    impl IntoSchema for Quantity {
        fn type_name() -> Ident {
            "Quantity".to_string()
        }
        fn update_schema_map(metamap: &mut MetaMap) {
            if !metamap.contains_key::<Self>() {
                <Numeric as IntoSchema>::update_schema_map(metamap);
                metamap.insert::<Self>(Metadata::Struct(NamedFieldsMeta {
                    declarations: vec![Declaration {
                        name: "value".to_string(),
                        ty: core::any::TypeId::of::<Numeric>(),
                    }],
                }));
            }
        }
    }
    impl TypeId for XorQuantity {
        fn id() -> Ident {
            "XorQuantity".to_string()
        }
    }
    impl IntoSchema for XorQuantity {
        fn type_name() -> Ident {
            "XorQuantity".to_string()
        }
        fn update_schema_map(metamap: &mut MetaMap) {
            if !metamap.contains_key::<Self>() {
                <Quantity as IntoSchema>::update_schema_map(metamap);
                metamap.insert::<Self>(Metadata::Struct(NamedFieldsMeta {
                    declarations: vec![Declaration {
                        name: "value".to_string(),
                        ty: core::any::TypeId::of::<Quantity>(),
                    }],
                }));
            }
        }
    }
}
#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "schema_identity/numeric.rs"]
pub(crate) mod schema_identity;
