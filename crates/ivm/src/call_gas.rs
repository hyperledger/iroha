//! Consensus work charges for authenticated V1 argument/result tables.

use crate::VMError;

/// Version binding charge ordering, logical work and private fixed-size validation.
pub const FORMULA_VERSION: u64 = 1;
/// Charge per initialized, copied, or validated logical byte.
pub const PER_BYTE: u64 = 1;
/// Fixed public pointer validation charge preceding checksum and canonical decoding.
pub const POINTER_BASE: u64 = 16;
/// Number of tracked memory bytes covered by one initialization bitmap byte.
pub const BITMAP_COVERAGE: u64 = 8;
/// Validation cost for one aligned table slot or sum tag.
pub const WORD: u64 = ivm_abi::call::CALL_WORD_BYTES_V1 as u64 * PER_BYTE;

/// Charge before visiting each authenticated schema node, including inline products.
pub const NODE: u64 = 1;

/// Reserve the initialization bitmaps for a fresh frame and its result table.
pub fn frame(frame_bytes: u32, result_words: usize) -> Result<u64, VMError> {
    u64::from(frame_bytes)
        .div_ceil(BITMAP_COVERAGE)
        .checked_add(u64::try_from(result_words).map_err(|_| VMError::GasCostOverflow)?)
        .and_then(|bytes| bytes.checked_mul(PER_BYTE))
        .ok_or(VMError::GasCostOverflow)
}

/// Charge the complete canonical envelope; secret callers supply the public type's maximum.
pub fn pointer(payload_bytes: u64) -> Result<u64, VMError> {
    payload_bytes
        .checked_add(7 + iroha_crypto::Hash::LENGTH as u64)
        .and_then(|bytes| bytes.checked_mul(PER_BYTE))
        .and_then(|bytes| bytes.checked_add(POINTER_BASE))
        .ok_or(VMError::GasCostOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frame_cost_covers_each_allocation_byte_at_the_v1_bounds() {
        assert!(matches!(frame(16, 1), Ok(3)));
        assert!(matches!(
            frame(
                ivm_abi::call::MAX_CALL_FRAME_BYTES_V1,
                ivm_abi::call::MAX_CALL_WORDS_V1
            ),
            Ok(532_480)
        ));
        assert!(matches!(frame(0, 0), Ok(0)));
    }
    #[test]
    fn pointer_cost_is_byte_linear_and_overflow_checked() {
        assert!(matches!(pointer(0), Ok(55)));
        assert!(matches!(pointer(1), Ok(56)));
        assert!(matches!(pointer(u64::MAX), Err(VMError::GasCostOverflow)));
    }
}
