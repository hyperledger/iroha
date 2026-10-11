//! Canonical Quantity decoding into its original exact prepaid native-digit backing.
//!
//! This leaf is not a frame authenticator or an admission decision. The enclosing
//! prepared record walker must preserve the advertised flags, decode scope and
//! exact canonical frame check. Planning never constructs a `BigInt` or normalizes
//! a mantissa; the final concrete owner has no Clone or safe extraction API.

use core::convert::Infallible;
use iroha_allocation::{
    AllocationBudget, AllocationCharge, ChargedBuffer, ChargedBufferFromChargeError,
};
use norito::core::{
    CanonicalField, DecodeField, DecodeIntoError, DecodeRecordFields, FieldDestination,
};

use super::*;

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

struct NumericPlanFields {
    magnitude: [u8; MAX_MANTISSA_BYTES],
    magnitude_len: usize,
    negative: bool,
    signed_len: usize,
    scale: u32,
    probe_backing: bool,
}
impl Default for NumericPlanFields {
    fn default() -> Self {
        Self {
            magnitude: [0; MAX_MANTISSA_BYTES],
            magnitude_len: 0,
            negative: false,
            signed_len: 0,
            scale: 0,
            probe_backing: false,
        }
    }
}
impl FieldDestination for NumericPlanFields {
    type Error = Infallible;
}
impl DecodeField<0, BigInt> for NumericPlanFields {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, BigInt>,
    ) -> Result<(), DecodeIntoError<Infallible>> {
        field.with_payload(|bytes| {
            let (payload, used) = crate::bigint::canonical_twos_payload(bytes)?;
            if used != bytes.len() {
                return Err(Error::LengthMismatch.into());
            }
            if self.probe_backing {
                crate::bigint::CanonicalNativeDigits::from_payload(payload)
                    .reserve_decode_backing()?;
            }
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
impl DecodeField<1, u32> for NumericPlanFields {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, u32>,
    ) -> Result<(), DecodeIntoError<Infallible>> {
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
    /// scope. Canonical field framing still debits that inherited logical scope;
    /// planning neither constructs nor admits native-digit backing.
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
        let mut fields = NumericPlanFields {
            probe_backing,
            ..NumericPlanFields::default()
        };
        let (_, used) = scale_::NumericScaleHelper::decode_fields(bytes, &mut fields)
            .map_err(DecodeIntoError::into_codec)?;
        if used != bytes.len() {
            return Err(Error::LengthMismatch);
        }
        if fields.scale > MAX_DECIMAL_SCALE {
            return Err(Error::Message(format!(
                "invalid numeric: {}",
                NumericError::ScaleTooLarge
            )));
        }
        if fields.signed_len > MAX_MANTISSA_BYTES {
            return Err(Error::Message(format!(
                "invalid numeric: {}",
                NumericError::MantissaTooLarge
            )));
        }
        let mut words = [0_u64; MAX_MANTISSA_BYTES / core::mem::size_of::<u64>()];
        for (word, bytes) in words.iter_mut().zip(fields.magnitude.chunks_exact(8)) {
            *word = u64::from_le_bytes(bytes.try_into().expect("fixed eight-byte chunk"));
        }
        let limbs = fields.magnitude_len.div_ceil(8).max(1);
        infallible_observed(validate_decimal_parts_observed(
            fields.scale,
            fields.magnitude_len == 0,
            u16::try_from(limbs).expect("512-bit domain fits limb count"),
            || magnitude_divisible_by_ten(words.iter().rev().copied()),
            &mut |_| Ok::<_, Infallible>(()),
        ))
        .map_err(|error| Error::Message(format!("invalid numeric: {error}")))?;
        if fields.negative {
            return Err(Error::Message(
                NumericOperationError::NegativeQuantity.to_string(),
            ));
        }
        Ok(Self {
            magnitude: fields.magnitude,
            digit_count: fields.magnitude_len.div_ceil(UNBOUNDED_BIGINT_DIGIT_BYTES),
            scale: fields.scale,
        })
    }

    /// Exact final native-digit layout; zero keeps a zero-byte original charge.
    #[must_use]
    pub fn allocation_layout(&self) -> Layout {
        Layout::array::<NativeBigDigit>(self.digit_count)
            .expect("the bounded 512-bit native-digit array is representable")
    }
}

/// Original prepared backing or exact canonical decoding refusal.
#[derive(Debug)]
pub enum QuantityDestinationError {
    /// The retained physical allocation is charged to a different finite pool.
    ForeignPool,
    /// Exact-layout validation or physical allocator refusal, without reacquisition.
    Allocation(ChargedBufferFromChargeError),
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
            Self::ForeignPool => formatter.write_str("quantity backing belongs to another pool"),
            Self::Allocation(error) => error.fmt(formatter),
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
            Self::Allocation(error) => Some(error),
            Self::Codec(error) => Some(error),
            Self::ForeignPool | Self::Geometry { .. } => None,
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
    /// Physically allocate the exact final magnitude before decoding a value.
    ///
    /// # Errors
    /// Returns the same charge on foreign-pool, layout or allocator refusal. No
    /// canonical value has been consumed, cloned or materialized on failure.
    pub fn try_from_charge(
        plan: &QuantityDecodePlan,
        budget: &AllocationBudget,
        charge: AllocationCharge,
    ) -> Result<Self, (AllocationCharge, QuantityDestinationError)> {
        if !charge.belongs_to(budget) {
            return Err((charge, QuantityDestinationError::ForeignPool));
        }
        let mut digits = ChargedBuffer::try_from_charge(plan.digit_count, charge)
            .map_err(|(charge, error)| (charge, QuantityDestinationError::Allocation(error)))?;
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
    #[allow(unsafe_code)]
    pub fn finish(self) -> Result<ChargedQuantity, Self> {
        let Some(scale) = self.scale else {
            return Err(self);
        };
        let Self { digits, scale: _ } = self;
        // SAFETY: filled digits are minimal and fill exact capacity. The pinned
        // native-digit constructor therefore preserves this Vec allocation. The
        // concrete immutable value and original charge are immediately paired;
        // no fallible work follows transfer. Field order drops value before charge.
        let (digits, charge) = unsafe { digits.into_allocation_parts() };
        let mantissa = BigInt::from_prepared_quantity_digits(digits);
        let value = Quantity(Numeric { mantissa, scale });
        Ok(ChargedQuantity { value, charge })
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
