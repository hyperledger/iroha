//! Shared decimal scanning and exact original-pool signed mantissa custody.

use std::alloc::Layout;

use iroha_allocation::{AllocationBudget, AllocationCharge, ChargedBuffer, ChargedBufferError};

use super::{
    BigInt, MAX_DECIMAL_SCALE, MAX_MANTISSA_BYTES, NativeBigDigit, Numeric, NumericError,
    UNBOUNDED_BIGINT_DIGIT_BYTES, UnboundedBigInt, UnboundedBigUint, UnboundedSign,
};

/// Original decimal-domain, decoder-budget or physical-allocation refusal.
#[derive(Debug, thiserror::Error)]
pub enum NumericDecimalAdmissionError {
    /// The unchanged semantic error from the shared decimal scanner.
    #[error(transparent)]
    Numeric(#[from] NumericError),
    /// Original cumulative decoder refusal before native mantissa allocation.
    #[error(transparent)]
    Decode(#[from] norito::Error),
    /// Exact original finite-pool or global allocator refusal.
    #[error(transparent)]
    Allocation(#[from] ChargedBufferError),
}

/// A canonical signed decimal retaining its exact original compact mantissa charge.
///
/// The value retires before its charge. This owner does not retain the caller's
/// decimal text or enclosing record/storage control; those remain caller-owned.
/// No Clone or mutable accessor can replace this original admitted backing.
pub struct ChargedNumeric {
    value: Numeric,
    charge: AllocationCharge,
}
impl ChargedNumeric {
    /// Scan borrowed decimal text and allocate only the final normalized mantissa.
    ///
    /// The ordinary [`Numeric`] parser uses this same lexical, normalization and
    /// signed-domain relation. Existing whitespace/sign/trailing-zero handling is
    /// preserved; this is the source-decimal relation, not strict canonical JSON.
    /// Parsing scratch has a fixed bound and the input is never copied. Positive
    /// gas-rate validation belongs to its caller; negative and zero numerics remain
    /// valid here. The caller retains the original decoder context and text owner.
    ///
    /// # Errors
    /// Preserves exact [`NumericError`] ordering and original decoder/pool/allocator
    /// refusals. No partially allocated mantissa escapes a refusal.
    #[allow(unsafe_code)]
    pub fn try_from_decimal(
        source: &str,
        budget: &AllocationBudget,
    ) -> Result<Self, NumericDecimalAdmissionError> {
        let parts = scan_decimal(source)?;
        let count = parts.magnitude_len.div_ceil(UNBOUNDED_BIGINT_DIGIT_BYTES);
        let layout =
            Layout::array::<NativeBigDigit>(count).map_err(|_| norito::Error::LengthMismatch)?;
        norito::core::reserve_decode_allocation(layout.size())?;
        let mut digits = ChargedBuffer::new(count, budget)?;
        parts.visit_native_digits(|digit| digits.push_reserved(digit));
        // SAFETY: the pinned bigint constructor adopts this exact full-capacity
        // native-digit Vec without growth. All semantic checks precede extraction;
        // the value and charge immediately form one immutable value-first owner.
        let (digits, charge) = unsafe { digits.into_allocation_parts() };
        let value = parts.into_value(digits);
        Ok(Self { value, charge })
    }

    /// Borrow the exact normalized decimal while retaining its original custody.
    #[must_use]
    pub fn get(&self) -> &Numeric {
        &self.value
    }

    /// Check exact allocation-pool identity, including the no-allocation zero case.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.charge.belongs_to(budget)
    }

    /// Move the original decimal and charge into a pre-funded enclosing owner.
    ///
    /// # Safety
    /// Pair both immediately in one immutable owner that drops the value before
    /// its charge on all paths. Do not clone, grow or replace mantissa backing
    /// while reusing the original charge; defer refunds beyond State/storage guards.
    #[allow(unsafe_code)]
    pub unsafe fn into_allocation_parts(self) -> (Numeric, AllocationCharge) {
        (self.value, self.charge)
    }
}
impl core::fmt::Debug for ChargedNumeric {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("ChargedNumeric")
            .field(self.get())
            .finish()
    }
}

struct DecimalParts {
    magnitude: [u8; MAX_MANTISSA_BYTES],
    magnitude_len: usize,
    negative: bool,
    scale: u32,
}
impl DecimalParts {
    fn visit_native_digits(&self, mut visit: impl FnMut(NativeBigDigit)) {
        for chunk in self.magnitude[..self.magnitude_len].chunks(UNBOUNDED_BIGINT_DIGIT_BYTES) {
            let mut bytes = [0_u8; UNBOUNDED_BIGINT_DIGIT_BYTES];
            bytes[..chunk.len()].copy_from_slice(chunk);
            visit(NativeBigDigit::from_le_bytes(bytes));
        }
    }

    fn into_value(self, digits: Vec<NativeBigDigit>) -> Numeric {
        debug_assert_eq!(
            digits.len(),
            self.magnitude_len.div_ceil(UNBOUNDED_BIGINT_DIGIT_BYTES)
        );
        debug_assert_eq!(digits.len(), digits.capacity());
        let sign = if self.negative {
            UnboundedSign::Minus
        } else {
            UnboundedSign::Plus
        };
        let inner =
            UnboundedBigInt::from_biguint(sign, UnboundedBigUint::from_native_digits(digits));
        let mantissa = BigInt::from_inner(inner)
            .expect("shared scanner validated the narrower signed 512-bit domain");
        // The shared scanner already removed precisely the fractional trailing
        // zeros and normalized zero. Calling try_new here would allocate redundant
        // arithmetic scratch and sever exact original backing custody.
        Numeric {
            mantissa,
            scale: self.scale,
        }
    }
}

pub(super) fn parse_ordinary(source: &str) -> Result<Numeric, NumericError> {
    let parts = scan_decimal(source)?;
    // FromStr's established authoring API has semantic errors only. The admitted
    // destination above instead funds and attempts this exact allocation fallibly.
    let mut digits = Vec::with_capacity(parts.magnitude_len.div_ceil(UNBOUNDED_BIGINT_DIGIT_BYTES));
    parts.visit_native_digits(|digit| digits.push(digit));
    Ok(parts.into_value(digits))
}

// Refactored from Numeric::from_str: validate the complete syntax first, remove
// fractional trailing zeroes, recognize zero, then enforce the original generic
// BigInt boundary before the decimal scale and narrower Numeric boundary. The
// latter ordering matters for malformed/oversized mixed cases. No second grammar
// or unbounded intermediate is introduced by the admitted destination.
fn scan_decimal(source: &str) -> Result<DecimalParts, NumericError> {
    let trimmed = source.trim();
    if trimmed.is_empty() {
        return Err(NumericError::Malformed);
    }
    let (negative, digits) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, &trimmed[1..]),
        Some(b'+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    let mut scale = 0_u32;
    let mut digit_count = 0_usize;
    let mut trailing_zeroes = 0_usize;
    let mut seen_dot = false;
    for byte in digits.bytes() {
        if byte == b'.' {
            if seen_dot {
                return Err(NumericError::Malformed);
            }
            seen_dot = true;
            continue;
        }
        if !byte.is_ascii_digit() {
            return Err(NumericError::Malformed);
        }
        digit_count += 1;
        if seen_dot {
            scale = scale.saturating_add(1);
        }
        trailing_zeroes = if byte == b'0' { trailing_zeroes + 1 } else { 0 };
    }
    let removed = trailing_zeroes.min(usize::try_from(scale).expect("u32 fits supported usize"));
    let retained_digits = digit_count - removed;
    scale -= u32::try_from(removed).expect("removed zeroes are bounded by scale");
    if retained_digits == 0 {
        return Err(NumericError::Malformed);
    }

    // The historical parser first constructs generic BigInt (4096 signed bits)
    // before checking Numeric's scale and signed 512-bit range. Fixed stack scratch
    // preserves that failure precedence even for a wide mantissa with excess scale.
    let mut magnitude = [0_u8; crate::bigint::MAX_ENCODED_BYTES];
    let mut length = 0_usize;
    for digit in digits
        .bytes()
        .filter(|byte| *byte != b'.')
        .take(retained_digits)
    {
        let mut carry = u16::from(digit - b'0');
        for byte in &mut magnitude[..length] {
            let product = u16::from(*byte) * 10 + carry;
            let [low, high] = product.to_le_bytes();
            *byte = low;
            carry = u16::from(high);
        }
        if carry != 0 {
            if length == magnitude.len() {
                return Err(NumericError::MantissaTooLarge);
            }
            magnitude[length] =
                u8::try_from(carry).expect("one decimal digit creates at most one base256 limb");
            length += 1;
        }
    }
    if !fits_signed(
        &magnitude[..length],
        crate::bigint::MAX_ENCODED_BYTES,
        negative,
    ) {
        return Err(NumericError::MantissaTooLarge);
    }
    if length == 0 {
        scale = 0;
    }
    if scale > MAX_DECIMAL_SCALE {
        return Err(NumericError::ScaleTooLarge);
    }
    if !fits_signed(&magnitude[..length], MAX_MANTISSA_BYTES, negative) {
        return Err(NumericError::MantissaTooLarge);
    }
    let mut compact = [0_u8; MAX_MANTISSA_BYTES];
    compact[..length].copy_from_slice(&magnitude[..length]);
    Ok(DecimalParts {
        magnitude: compact,
        magnitude_len: length,
        negative: negative && length != 0,
        scale,
    })
}
fn fits_signed(magnitude: &[u8], maximum_bytes: usize, negative: bool) -> bool {
    if magnitude.len() != maximum_bytes {
        return magnitude.len() < maximum_bytes;
    }
    let high = magnitude[maximum_bytes - 1];
    high < 0x80
        || (high == 0x80
            && negative
            && magnitude[..maximum_bytes - 1].iter().all(|byte| *byte == 0))
}

#[cfg(test)]
#[path = "prepared_numeric/tests.rs"]
mod tests;
