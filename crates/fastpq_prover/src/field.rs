//! Canonical Goldilocks scalar arithmetic and degree-four extension for FASTPQ FRI.

use fastpq_isi::GoldilocksDigest384V1;
use norito::{DeserializePayload, SerializePayload};

/// Goldilocks prime `2^64 - 2^32 + 1`.
pub const GOLDILOCKS_MODULUS_V1: u64 = 0xffff_ffff_0000_0001;
/// Non-residue in the irreducible extension polynomial `X^4 - 7`.
const FP4_NON_RESIDUE_V1: u64 = 7;

/// Canonically encoded element of `Goldilocks[X] / (X^4 - 7)`.
///
/// The Norito payload is exactly four little-endian field limbs, without an
/// inner struct length or field table. Both archive and slice readers reject
/// coefficients outside the base field before constructing this type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "fastpq_prover::field::GoldilocksFp4V1")]
pub struct GoldilocksFp4V1 {
    coefficients: [u64; 4],
}

impl zeroize::Zeroize for GoldilocksFp4V1 {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.coefficients);
    }
}

impl GoldilocksFp4V1 {
    /// Exact byte length of the final V1 polynomial-basis encoding.
    pub const BYTES: usize = 32;
    /// Additive identity.
    pub const ZERO: Self = Self {
        coefficients: [0; 4],
    };
    /// Multiplicative identity.
    pub const ONE: Self = Self {
        coefficients: [1, 0, 0, 0],
    };

    /// Construct an element only when all four coefficients are canonical.
    #[must_use]
    pub fn new(coefficients: [u64; 4]) -> Option<Self> {
        coefficients
            .iter()
            .all(|coefficient| *coefficient < GOLDILOCKS_MODULUS_V1)
            .then_some(Self { coefficients })
    }

    /// Embed one base-field element into the extension.
    #[must_use]
    pub fn from_base(value: u64) -> Option<Self> {
        (value < GOLDILOCKS_MODULUS_V1).then_some(Self {
            coefficients: [value, 0, 0, 0],
        })
    }

    /// Derive an extension element from the first four independent digest lanes.
    #[must_use]
    pub fn from_digest(digest: GoldilocksDigest384V1) -> Self {
        let words = digest.words();
        Self {
            coefficients: [words[0], words[1], words[2], words[3]],
        }
    }

    /// Return the four canonical polynomial-basis coefficients.
    #[must_use]
    pub const fn coefficients(self) -> [u64; 4] {
        self.coefficients
    }

    /// Return whether this is the additive identity.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    /// Encode four canonical little-endian field coefficients.
    #[must_use]
    pub fn to_le_bytes(self) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        for (index, coefficient) in self.coefficients.iter().enumerate() {
            bytes[index * 8..index * 8 + 8].copy_from_slice(&coefficient.to_le_bytes());
        }
        bytes
    }

    /// Decode four canonical little-endian field coefficients.
    #[must_use]
    pub fn from_le_bytes(bytes: [u8; 32]) -> Option<Self> {
        let mut coefficients = [0_u64; 4];
        for (coefficient, chunk) in coefficients.iter_mut().zip(bytes.chunks_exact(8)) {
            *coefficient = u64::from_le_bytes(chunk.try_into().expect("chunk length is eight"));
        }
        Self::new(coefficients)
    }

    #[cfg(test)]
    pub(crate) const fn from_coefficients_unchecked_for_test(coefficients: [u64; 4]) -> Self {
        Self { coefficients }
    }

    /// Add two extension elements.
    #[must_use]
    #[allow(
        clippy::should_implement_trait,
        reason = "re-exported inherent field API called as `.add` across the crate; \
                  switching to `core::ops::Add` would change the public surface"
    )]
    pub fn add(self, other: Self) -> Self {
        Self {
            coefficients: core::array::from_fn(|index| {
                add_base(self.coefficients[index], other.coefficients[index])
            }),
        }
    }

    /// Subtract two extension elements.
    #[must_use]
    #[allow(
        clippy::should_implement_trait,
        reason = "re-exported inherent field API called as `.sub` across the crate; \
                  switching to `core::ops::Sub` would change the public surface"
    )]
    pub fn sub(self, other: Self) -> Self {
        Self {
            coefficients: core::array::from_fn(|index| {
                sub_base(self.coefficients[index], other.coefficients[index])
            }),
        }
    }

    /// Multiply two extension elements modulo `X^4 - 7`.
    #[must_use]
    #[allow(
        clippy::should_implement_trait,
        reason = "re-exported inherent field API called as `.mul` across the crate; \
                  switching to `core::ops::Mul` would change the public surface"
    )]
    pub fn mul(self, other: Self) -> Self {
        let mut product = [0_u64; 7];
        for left in 0..4 {
            for right in 0..4 {
                product[left + right] = add_base(
                    product[left + right],
                    mul_base(self.coefficients[left], other.coefficients[right]),
                );
            }
        }
        for degree in (4..=6).rev() {
            product[degree - 4] = add_base(
                product[degree - 4],
                mul_base(product[degree], FP4_NON_RESIDUE_V1),
            );
        }
        Self {
            coefficients: [product[0], product[1], product[2], product[3]],
        }
    }

    /// Multiply every coefficient by one base-field element.
    #[must_use]
    pub fn mul_base(self, scalar: u64) -> Self {
        debug_assert!(scalar < GOLDILOCKS_MODULUS_V1);
        Self {
            coefficients: self.coefficients.map(|value| mul_base(value, scalar)),
        }
    }
}

impl SerializePayload for GoldilocksFp4V1 {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        writer.write_all(&self.to_le_bytes())?;
        Ok(())
    }

    fn encoded_len_hint(&self) -> Option<usize> {
        Some(Self::BYTES)
    }

    fn encoded_len_exact(&self) -> Option<usize> {
        Some(Self::BYTES)
    }
}

impl<'de> DeserializePayload<'de> for GoldilocksFp4V1 {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("canonical GoldilocksFp4V1 decode")
    }

    fn try_deserialize(archived: &'de norito::core::Archived<Self>) -> Result<Self, norito::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let mut offset = 0;
        let bytes = norito::core::decode_context_byte_array::<{ Self::BYTES }>(ptr, &mut offset)?;
        norito::core::finish_context_fields(ptr, offset)?;
        Self::from_le_bytes(bytes).ok_or_else(|| {
            norito::Error::Message("non-canonical GoldilocksFp4V1 coefficient".into())
        })
    }
}

impl<'de> norito::core::DecodeFromSlice<'de> for GoldilocksFp4V1 {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), norito::Error> {
        let prefix = bytes
            .get(..Self::BYTES)
            .ok_or(norito::Error::LengthMismatch)?;
        let mut encoded = [0_u8; Self::BYTES];
        encoded.copy_from_slice(prefix);
        let value = Self::from_le_bytes(encoded).ok_or_else(|| {
            norito::Error::Message("non-canonical GoldilocksFp4V1 coefficient".into())
        })?;
        norito::core::note_payload_access(bytes, Self::BYTES);
        Ok((value, Self::BYTES))
    }
}

/// Add arbitrary u64 representatives and return their canonical field sum.
///
/// This is arithmetic normalization, not admission of noncanonical proof cells.
#[inline]
pub fn add_base(left: u64, right: u64) -> u64 {
    let left = reduce_base(left);
    let right = reduce_base(right);
    let sum = left.wrapping_add(right);
    let mut reduced = sum;
    if sum < left {
        // The reviewed Poseidon carry correction uses 2^64 = 2^32-1 (mod p).
        // Canonical inputs bound the carried sum below 2^64-2*(2^32-1),
        // so adding this correction cannot itself overflow.
        reduced = reduced.wrapping_sub(GOLDILOCKS_MODULUS_V1);
    }
    reduce_base(reduced)
}

/// Subtract arbitrary u64 representatives with a canonical, nonnegative result.
#[inline]
pub fn sub_base(left: u64, right: u64) -> u64 {
    let left = reduce_base(left);
    let right = reduce_base(right);
    if left >= right {
        left - right
    } else {
        // The positive difference is at most p-1; neither subtraction can wrap.
        GOLDILOCKS_MODULUS_V1 - (right - left)
    }
}

/// Multiply arbitrary u64 representatives and return their canonical field product.
#[inline]
pub fn mul_base(left: u64, right: u64) -> u64 {
    reduce_wide(u128::from(left) * u128::from(right))
}

#[inline]
fn reduce_base(value: u64) -> u64 {
    // Every u64 is less than 2p, so at most one subtraction is needed.
    if value >= GOLDILOCKS_MODULUS_V1 {
        value - GOLDILOCKS_MODULUS_V1
    } else {
        value
    }
}

#[inline]
fn reduce_wide(value: u128) -> u64 {
    // Same bounded pseudo-Mersenne fold as
    // fastpq_isi::poseidon_digest384::reduce_wide_v1. With high = h0+2^32*h1,
    // 2^64 = 2^32-1 and 2^96 = -1 (mod p), giving low+(2^32-1)*h0-h1.
    let low =
        u64::try_from(value & u128::from(u64::MAX)).expect("masked low product word fits u64");
    let high = u64::try_from(value >> 64).expect("high product word fits u64");
    let high_low = i128::from(high & 0xffff_ffff);
    let high_high = i128::from(high >> 32);
    let mut accumulated = i128::from(low) + (high_low << 32) - high_low - high_high;
    let modulus = i128::from(GOLDILOCKS_MODULUS_V1);
    // For every u128 input, -(2^32-1) <= accumulated <= 2p-2. These signed
    // operations fit i128; one correction in each direction gives [0,p).
    if accumulated < 0 {
        accumulated += modulus;
    }
    if accumulated >= modulus {
        accumulated -= modulus;
    }
    u64::try_from(accumulated).expect("Goldilocks reduction is canonical")
}

#[cfg(test)]
mod tests {

    #[test]
    fn zeroize_clears_every_extension_coordinate() {
        let mut value = super::GoldilocksFp4V1::new([17, 31, 47, 61]).unwrap();
        zeroize::Zeroize::zeroize(&mut value);
        assert_eq!(value, super::GoldilocksFp4V1::ZERO);
        assert_eq!(value.coefficients(), [0; 4]);
    }
    use super::*;
    use norito::{codec::Encode, core::DecodeFromSlice};

    #[test]
    fn norito_wire_is_exactly_four_little_endian_limbs() {
        let value = GoldilocksFp4V1::new([1, 2, 3, GOLDILOCKS_MODULUS_V1 - 1]).unwrap();
        assert_eq!(value.encode(), value.to_le_bytes());
        assert_eq!(value.encoded_len_exact(), Some(GoldilocksFp4V1::BYTES));
        assert_eq!(value.encoded_len_hint(), Some(GoldilocksFp4V1::BYTES));
        let encoded = norito::core::to_bytes(&value).expect("encode extension element");
        assert_eq!(
            norito::decode_from_bytes::<GoldilocksFp4V1>(&encoded).unwrap(),
            value
        );
        for flags in [0, norito::core::default_encode_flags()] {
            let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
            assert_eq!(value.encode(), value.to_le_bytes());
        }
    }

    #[test]
    fn norito_archive_rejects_each_noncanonical_coefficient() {
        for coefficient in 0..4 {
            for invalid in [GOLDILOCKS_MODULUS_V1, u64::MAX] {
                let mut coefficients = [1, 2, 3, 4];
                coefficients[coefficient] = invalid;
                let invalid = GoldilocksFp4V1::from_coefficients_unchecked_for_test(coefficients);
                let encoded = norito::core::to_bytes(&invalid).expect("encode adversarial fixture");
                assert!(
                    norito::decode_from_bytes::<GoldilocksFp4V1>(&encoded).is_err(),
                    "noncanonical coefficient {coefficient} must not enter the typed field"
                );
            }
        }
    }

    #[test]
    fn norito_rejects_the_retired_struct_framing() {
        #[derive(norito::NoritoSerialize, norito::NoritoSchema)]
        #[norito_schema(
            name = "fastpq_prover::field::tests::norito_rejects_the_retired_struct_framing::RetiredStructFrame",
            frame = "fastpq_prover::field::GoldilocksFp4V1"
        )]
        struct RetiredStructFrame {
            coefficients: [u64; 4],
        }

        assert_eq!(
            norito::schema::identity::frame_hash::<RetiredStructFrame>(),
            norito::schema::identity::frame_hash::<GoldilocksFp4V1>(),
            "exercise payload rejection under the same field schema"
        );
        let retired = RetiredStructFrame {
            coefficients: [1, 2, 3, 4],
        };
        let encoded = norito::core::to_bytes(&retired).expect("encode retired struct fixture");
        assert!(norito::decode_from_bytes::<GoldilocksFp4V1>(&encoded).is_err());
    }

    #[test]
    fn norito_slice_decode_is_bounded_and_canonical() {
        let value = GoldilocksFp4V1::new([1, 2, 3, 4]).unwrap();
        let encoded = value.to_le_bytes();
        for length in 0..GoldilocksFp4V1::BYTES {
            assert!(GoldilocksFp4V1::decode_from_slice(&encoded[..length]).is_err());
        }
        let mut with_suffix = encoded.to_vec();
        with_suffix.extend_from_slice(&[0xA5; 8]);
        assert_eq!(
            GoldilocksFp4V1::decode_from_slice(&with_suffix).unwrap(),
            (value, GoldilocksFp4V1::BYTES)
        );
        for coefficient in 0..4 {
            let mut invalid = encoded;
            invalid[coefficient * 8..coefficient * 8 + 8]
                .copy_from_slice(&GOLDILOCKS_MODULUS_V1.to_le_bytes());
            assert!(GoldilocksFp4V1::decode_from_slice(&invalid).is_err());
        }
    }

    /// Narrow a residue modulo the Goldilocks prime, which always fits `u64`.
    fn oracle_residue(value: u128) -> u64 {
        u64::try_from(value % u128::from(GOLDILOCKS_MODULUS_V1)).expect("residue is below p")
    }

    fn oracle_add(left: u64, right: u64) -> u64 {
        oracle_residue(u128::from(left) + u128::from(right))
    }

    fn oracle_sub(left: u64, right: u64) -> u64 {
        oracle_residue(u128::from(left) + 2 * u128::from(GOLDILOCKS_MODULUS_V1) - u128::from(right))
    }

    fn oracle_mul(left: u64, right: u64) -> u64 {
        oracle_residue(u128::from(left) * u128::from(right))
    }

    fn check_base(left: u64, right: u64) {
        for (actual, expected, operation) in [
            (add_base(left, right), oracle_add(left, right), "addition"),
            (
                sub_base(left, right),
                oracle_sub(left, right),
                "subtraction",
            ),
            (
                mul_base(left, right),
                oracle_mul(left, right),
                "multiplication",
            ),
        ] {
            assert_eq!(actual, expected, "{operation}: {left:#018x}, {right:#018x}");
            assert!(actual < GOLDILOCKS_MODULUS_V1);
        }
    }

    fn next_word(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn scalar_arithmetic_matches_modulo_across_every_boundary_and_carry() {
        let values = [
            0,
            1,
            2,
            (1 << 32) - 2,
            (1 << 32) - 1,
            1 << 32,
            (1 << 32) + 1,
            (1 << 63) - 1,
            1 << 63,
            (1 << 63) + 1,
            GOLDILOCKS_MODULUS_V1 / 2,
            GOLDILOCKS_MODULUS_V1 - 2,
            GOLDILOCKS_MODULUS_V1 - 1,
            GOLDILOCKS_MODULUS_V1,
            GOLDILOCKS_MODULUS_V1 + 1,
            u64::MAX - 1,
            u64::MAX,
        ];
        for left in values {
            assert_eq!(reduce_base(left), oracle_residue(u128::from(left)));
            for right in values {
                check_base(left, right);
            }
        }
        // Noncanonical representatives require normalization before the canonical
        // carry shortcut; otherwise MAX+MAX can lose a second 2^64 carry.
        assert_eq!(add_base(u64::MAX, u64::MAX), (1_u64 << 33) - 4);
        assert_eq!(
            sub_base(0, u64::MAX),
            GOLDILOCKS_MODULUS_V1 - ((1_u64 << 32) - 2)
        );
    }

    #[test]
    fn wide_reduction_matches_modulo_for_all_high_low_boundary_pairs() {
        let words = [
            0,
            1,
            (1 << 32) - 1,
            1 << 32,
            GOLDILOCKS_MODULUS_V1 - 1,
            u64::MAX,
        ];
        let modulus = u128::from(GOLDILOCKS_MODULUS_V1);
        for high in words {
            for low in words {
                let value = (u128::from(high) << 64) | u128::from(low);
                assert_eq!(
                    u128::from(reduce_wide(value)),
                    value % modulus,
                    "wide {value:#034x}"
                );
            }
        }
        for value in [
            0,
            1,
            modulus - 1,
            modulus,
            modulus + 1,
            (1_u128 << 96) - 1,
            1_u128 << 96,
            (1_u128 << 96) + 1,
            modulus * modulus - 1,
            modulus * modulus,
            modulus * modulus + 1,
            u128::MAX - 1,
            u128::MAX,
        ] {
            assert_eq!(u128::from(reduce_wide(value)), value % modulus);
        }
    }

    #[test]
    fn seeded_full_width_inputs_match_independent_modulo_oracles() {
        let mut state = 0x6a09_e667_f3bc_c908;
        for _ in 0..65_536 {
            let left = next_word(&mut state);
            let right = next_word(&mut state);
            check_base(left, right);
            let wide = (u128::from(left) << 64) | u128::from(right);
            assert_eq!(
                u128::from(reduce_wide(wide)),
                wide % u128::from(GOLDILOCKS_MODULUS_V1)
            );
        }
    }

    #[test]
    fn extension_arithmetic_matches_oracle_convolution_and_field_algebra() {
        let mut state = 0xbb67_ae85_84ca_a73b;
        for _ in 0..256 {
            let mut sample = || {
                GoldilocksFp4V1::new(core::array::from_fn(|_| {
                    oracle_residue(u128::from(next_word(&mut state)))
                }))
                .unwrap()
            };
            let left = sample();
            let right = sample();
            let third = sample();
            let a = left.coefficients();
            let b = right.coefficients();
            let mut expected = [0; 4];
            for i in 0..4 {
                for j in 0..4 {
                    let factor = if i + j >= 4 { 7 } else { 1 };
                    expected[(i + j) % 4] = oracle_add(
                        expected[(i + j) % 4],
                        oracle_mul(oracle_mul(a[i], b[j]), factor),
                    );
                }
            }
            assert_eq!(left.mul(right).coefficients(), expected);
            assert_eq!(
                left.add(right).coefficients(),
                core::array::from_fn(|i| oracle_add(a[i], b[i]))
            );
            assert_eq!(
                left.sub(right).coefficients(),
                core::array::from_fn(|i| oracle_sub(a[i], b[i]))
            );
            assert_eq!(left.add(right).sub(right), left);
            assert_eq!(left.mul(right), right.mul(left));
            assert_eq!(left.mul(right).mul(third), left.mul(right.mul(third)));
            assert_eq!(
                left.mul(right.add(third)),
                left.mul(right).add(left.mul(third))
            );
            assert_eq!(
                left.mul_base(a[0]).coefficients(),
                a.map(|value| oracle_mul(value, a[0]))
            );
        }
    }

    #[test]
    fn canonical_wire_round_trip_and_rejection() {
        let value = GoldilocksFp4V1::new([1, 2, 3, 4]).expect("canonical element");
        assert_eq!(
            GoldilocksFp4V1::from_le_bytes(value.to_le_bytes()),
            Some(value)
        );
        let mut invalid = value.to_le_bytes();
        invalid[8..16].copy_from_slice(&GOLDILOCKS_MODULUS_V1.to_le_bytes());
        assert!(GoldilocksFp4V1::from_le_bytes(invalid).is_none());
    }

    #[test]
    fn multiplication_reduces_x_four_to_seven() {
        let x = GoldilocksFp4V1::new([0, 1, 0, 0]).expect("canonical element");
        let x_squared = x.mul(x);
        assert_eq!(x_squared.coefficients(), [0, 0, 1, 0]);
        assert_eq!(x_squared.mul(x_squared).coefficients(), [7, 0, 0, 0]);
    }

    #[test]
    fn base_embedding_obeys_field_identities() {
        let value = GoldilocksFp4V1::new([9, 8, 7, 6]).expect("canonical element");
        assert_eq!(value.add(GoldilocksFp4V1::ZERO), value);
        assert_eq!(value.mul(GoldilocksFp4V1::ONE), value);
        assert_eq!(value.sub(value), GoldilocksFp4V1::ZERO);
        assert_eq!(
            value.mul_base(3),
            value.mul(GoldilocksFp4V1::from_base(3).unwrap())
        );
    }
}

#[cfg(test)]
mod goldilocks_fp4_raw_wire_tests {
    use super::*;

    #[test]
    fn goldilocks_fp4_keeps_sole_raw_wire_and_zero_storage_charge() {
        #[repr(align(16))]
        struct Aligned([u8; 512]);
        let value = GoldilocksFp4V1::new([1, 2, 3, 4]).unwrap();
        let raw = value.to_le_bytes();
        for flags in [0, norito::core::header_flags::COMPACT_LEN] {
            let _flags = norito::core::DecodeFlagsGuard::enter(flags);
            let mut encoded = Vec::new();
            norito::core::serialize_to_buffer(&value, &mut encoded).unwrap();
            assert_eq!(encoded, raw);
            let mut aligned = Aligned([0; 512]);
            aligned.0[..encoded.len()].copy_from_slice(&encoded);
            let bytes = &aligned.0[..encoded.len()];
            let zero = norito::DecodeLimits::new(0, usize::MAX, 0, 0, 8);
            let (decoded, usage) = norito::core::with_decode_limits_measured(zero, || {
                let _context = norito::core::PayloadCtxGuard::enter(bytes);
                let decoded = norito::core::decode_field_canonical::<GoldilocksFp4V1>(bytes)?;
                assert_eq!(
                    norito::core::payload_ctx(),
                    Some((bytes.as_ptr() as usize, bytes.len()))
                );
                Ok::<_, norito::Error>(decoded)
            });
            assert_eq!(decoded.unwrap(), (value, bytes.len()));
            assert_eq!(usage.total_allocated_bytes(), 0);
            assert_eq!(usage.total_elements(), 0);
            let mut alternate = Vec::new();
            norito::core::serialize_to_buffer(&raw, &mut alternate).unwrap();
            let mut extra = raw.to_vec();
            extra.push(0);
            for invalid in [&raw[..raw.len() - 1], &extra[..], &alternate[..]] {
                aligned.0[..invalid.len()].copy_from_slice(invalid);
                let bytes = &aligned.0[..invalid.len()];
                let (decoded, usage) = norito::core::with_decode_limits_measured(zero, || {
                    norito::core::decode_field_canonical::<GoldilocksFp4V1>(bytes)
                });
                assert!(matches!(decoded, Err(norito::Error::LengthMismatch)));
                assert_eq!(usage.total_allocated_bytes(), 0);
                assert_eq!(usage.total_elements(), 0);
            }
        }
    }
}
