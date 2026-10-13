//! Polynomials over `GF(2)` as bit vectors: multiplication, reduction, and the
//! enumeration of small irreducible polynomials.
//!
//! A polynomial with `n` coefficients occupies `ceil(n / 8)` bytes; bit `i mod 8` of
//! byte `i / 8` is the coefficient of `x^i`. Bits of the last byte at or above `n`
//! are ignored on input and zero on output.
//!
//! [`poly_mul`] and [`poly_reduce`] run a sequence of operations fixed by the
//! declared lengths and, for [`poly_reduce`], by the modulus, which is public. The
//! coefficient values of the other operands drive neither branches nor indices.

use zeroize::Zeroizing;

use super::FieldError;

/// Largest degree accepted by [`is_irreducible`] and [`smallest_irreducibles`].
pub const MAX_IRREDUCIBLE_DEGREE: u32 = 16;

fn byte_len(bits: usize) -> usize {
    bits.div_ceil(8)
}

/// Check that `bytes` is the encoding of a polynomial with `bits` coefficients.
fn check_len(bytes: &[u8], bits: usize) -> Result<(), FieldError> {
    if bits == 0 {
        return Err(FieldError::EmptyPolynomial);
    }
    if bytes.len() != byte_len(bits) {
        return Err(FieldError::InvalidLength {
            expected: byte_len(bits),
            actual: bytes.len(),
        });
    }
    Ok(())
}

/// Mask selecting the coefficients below `bits` in the last byte of an encoding.
fn last_byte_mask(bits: usize) -> u8 {
    0xff >> ((8 - bits % 8) % 8)
}

/// Byte `index` of an encoding of `bits` coefficients with the unused bits cleared.
fn masked_byte(bytes: &[u8], bits: usize, index: usize) -> u8 {
    if index + 1 == bytes.len() {
        bytes[index] & last_byte_mask(bits)
    } else {
        bytes[index]
    }
}

/// All-ones if coefficient `index` of `bytes` is set, zero otherwise.
fn bit_mask(bytes: &[u8], index: usize) -> u8 {
    0u8.wrapping_sub((bytes[index / 8] >> (index % 8)) & 1)
}

/// `out ^= (source << shift) & mask`, where `source` has `bits` coefficients.
/// Product bytes that fall beyond `out` are dropped.
fn xor_shifted(out: &mut [u8], source: &[u8], bits: usize, shift: usize, mask: u8) {
    let base = shift / 8;
    let offset = shift % 8;
    for index in 0..source.len() {
        let value = u16::from(masked_byte(source, bits, index) & mask) << offset;
        let [low, high] = value.to_le_bytes();
        if let Some(slot) = out.get_mut(base + index) {
            *slot ^= low;
        }
        if let Some(slot) = out.get_mut(base + index + 1) {
            *slot ^= high;
        }
    }
}

/// Multiply two polynomials over `GF(2)`: `out = lhs * rhs`.
///
/// `lhs` has `lhs_bits` coefficients and `rhs` has `rhs_bits`; the product has
/// `lhs_bits + rhs_bits - 1`.
///
/// # Errors
/// Returns [`FieldError::EmptyPolynomial`] if either length is zero and
/// [`FieldError::InvalidLength`] unless `lhs`, `rhs` and `out` are exactly
/// `ceil(lhs_bits / 8)`, `ceil(rhs_bits / 8)` and
/// `ceil((lhs_bits + rhs_bits - 1) / 8)` bytes long.
pub fn poly_mul(
    out: &mut [u8],
    lhs: &[u8],
    lhs_bits: usize,
    rhs: &[u8],
    rhs_bits: usize,
) -> Result<(), FieldError> {
    check_len(lhs, lhs_bits)?;
    check_len(rhs, rhs_bits)?;
    let out_bits = lhs_bits
        .checked_add(rhs_bits - 1)
        .ok_or(FieldError::InvalidLength {
            expected: usize::MAX,
            actual: out.len(),
        })?;
    check_len(out, out_bits)?;
    out.fill(0);
    for index in 0..lhs_bits {
        xor_shifted(out, rhs, rhs_bits, index, bit_mask(lhs, index));
    }
    Ok(())
}

/// Reduce a polynomial over `GF(2)`: `out = value mod modulus`.
///
/// `value` has `value_bits` coefficients. `modulus` has `modulus_bits` coefficients,
/// the highest of which must be set, so its degree is `modulus_bits - 1`; the
/// remainder has `modulus_bits - 1` coefficients. The modulus is treated as public.
///
/// # Errors
/// Returns [`FieldError::EmptyPolynomial`] if `value_bits` is zero,
/// [`FieldError::InvalidModulus`] if `modulus_bits < 2` or the leading coefficient
/// of the modulus is clear, and [`FieldError::InvalidLength`] unless `value`,
/// `modulus` and `out` are exactly `ceil(value_bits / 8)`, `ceil(modulus_bits / 8)`
/// and `ceil((modulus_bits - 1) / 8)` bytes long.
pub fn poly_reduce(
    out: &mut [u8],
    value: &[u8],
    value_bits: usize,
    modulus: &[u8],
    modulus_bits: usize,
) -> Result<(), FieldError> {
    check_len(value, value_bits)?;
    if modulus_bits < 2 {
        return Err(FieldError::InvalidModulus);
    }
    check_len(modulus, modulus_bits)?;
    let degree = modulus_bits - 1;
    if bit_mask(modulus, degree) == 0 {
        return Err(FieldError::InvalidModulus);
    }
    check_len(out, degree)?;

    let mut work = Zeroizing::new(value.to_vec());
    if let Some(last) = work.last_mut() {
        *last &= last_byte_mask(value_bits);
    }
    for index in (degree..value_bits).rev() {
        let mask = bit_mask(&work, index);
        xor_shifted(&mut work, modulus, modulus_bits, index - degree, mask);
    }
    out.fill(0);
    for (slot, byte) in out.iter_mut().zip(work.iter()) {
        *slot = *byte;
    }
    if let Some(last) = out.last_mut() {
        *last &= last_byte_mask(degree);
    }
    Ok(())
}

/// Degree of a non-zero polynomial given as an integer (bit `i` is the coefficient
/// of `x^i`).
fn degree_of(poly: u32) -> u32 {
    31 - poly.leading_zeros()
}

/// Remainder of `value` modulo the non-zero `modulus`, both as integers.
fn rem_small(mut value: u32, modulus: u32) -> u32 {
    let degree = degree_of(modulus);
    while value != 0 && degree_of(value) >= degree {
        value ^= modulus << (degree_of(value) - degree);
    }
    value
}

/// Whether `poly`, an integer whose bit `i` is the coefficient of `x^i`, is an
/// irreducible polynomial over `GF(2)` of degree in `[1, MAX_IRREDUCIBLE_DEGREE]`.
///
/// The argument is public data; the run time depends on it.
pub fn is_irreducible(poly: u32) -> bool {
    if poly < 2 {
        return false;
    }
    let degree = degree_of(poly);
    if degree > MAX_IRREDUCIBLE_DEGREE {
        return false;
    }
    // A reducible polynomial has a factor of degree at most half its own.
    (2..(1u32 << (degree / 2 + 1))).all(|divisor| rem_small(poly, divisor) != 0)
}

/// The `count` smallest irreducible polynomials of exactly `degree` over `GF(2)`, in
/// increasing order as integers (bit `i` is the coefficient of `x^i`).
///
/// This is the order in which FAEST v3.0 Appendix B picks the moduli of the CRT
/// tree for one small-VOLE bit length.
///
/// # Errors
/// Returns [`FieldError::UnsupportedDegree`] unless `degree` is in
/// `[1, MAX_IRREDUCIBLE_DEGREE]` and [`FieldError::NotEnoughIrreducibles`] if fewer
/// than `count` irreducible polynomials of that degree exist.
pub fn smallest_irreducibles(degree: u32, count: usize) -> Result<Vec<u32>, FieldError> {
    if degree == 0 || degree > MAX_IRREDUCIBLE_DEGREE {
        return Err(FieldError::UnsupportedDegree {
            degree,
            max: MAX_IRREDUCIBLE_DEGREE,
        });
    }
    let found: Vec<u32> = ((1u32 << degree)..(1u32 << (degree + 1)))
        .filter(|poly| is_irreducible(*poly))
        .take(count)
        .collect();
    if found.len() < count {
        return Err(FieldError::NotEnoughIrreducibles {
            requested: count,
            available: found.len(),
        });
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Schoolbook product of integer-encoded polynomials.
    fn mul_u128(a: u64, b: u64) -> u128 {
        let mut acc = 0u128;
        for i in 0..64 {
            if (b >> i) & 1 == 1 {
                acc ^= u128::from(a) << i;
            }
        }
        acc
    }

    fn rem_u128(mut value: u128, modulus: u128) -> u128 {
        let degree = 127 - modulus.leading_zeros();
        while value != 0 && 127 - value.leading_zeros() >= degree {
            value ^= modulus << (127 - value.leading_zeros() - degree);
        }
        value
    }

    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn length_helpers() {
        assert_eq!(byte_len(1), 1);
        assert_eq!(byte_len(8), 1);
        assert_eq!(byte_len(9), 2);
        assert_eq!(last_byte_mask(8), 0xff);
        assert_eq!(last_byte_mask(1), 0x01);
        assert_eq!(last_byte_mask(13), 0x1f);
        assert_eq!(masked_byte(&[0xff, 0xff], 13, 0), 0xff);
        assert_eq!(masked_byte(&[0xff, 0xff], 13, 1), 0x1f);
        assert_eq!(bit_mask(&[0x00, 0x02], 9), 0xff);
        assert_eq!(bit_mask(&[0xff, 0xfd], 9), 0x00);
        assert_eq!(check_len(&[0], 0), Err(FieldError::EmptyPolynomial));
        assert_eq!(
            check_len(&[0], 9),
            Err(FieldError::InvalidLength {
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(check_len(&[0, 0], 9), Ok(()));
    }

    #[test]
    fn xor_shifted_shifts_masks_and_truncates() {
        let mut out = [0u8; 3];
        xor_shifted(&mut out, &[0xff, 0xff], 12, 5, 0xff);
        // 0x0fff << 5 = 0x1ffe0.
        assert_eq!(out, [0xe0, 0xff, 0x01]);
        xor_shifted(&mut out, &[0xff, 0xff], 12, 5, 0x00);
        assert_eq!(out, [0xe0, 0xff, 0x01]);
        let mut short = [0u8; 2];
        xor_shifted(&mut short, &[0xff, 0xff], 12, 5, 0xff);
        assert_eq!(short, [0xe0, 0xff]);
    }

    #[test]
    fn poly_mul_matches_the_integer_product() {
        let mut state = 0x1234_5678_9abc_def1;
        for (lhs_bits, rhs_bits) in [(1, 1), (7, 122), (8, 64), (12, 53), (64, 64), (3, 9)] {
            for _ in 0..20 {
                let a = next(&mut state) & (u64::MAX >> (64 - lhs_bits.min(64)));
                let b = next(&mut state) & (u64::MAX >> (64 - rhs_bits.min(64)));
                let lhs = &a.to_le_bytes()[..byte_len(lhs_bits)];
                let mut rhs = vec![0u8; byte_len(rhs_bits)];
                let copied = rhs.len().min(8);
                rhs[..copied].copy_from_slice(&b.to_le_bytes()[..copied]);
                let mut out = vec![0xaa; byte_len(lhs_bits + rhs_bits - 1)];
                poly_mul(&mut out, lhs, lhs_bits, &rhs, rhs_bits).expect("valid lengths");
                let expected = mul_u128(a, b).to_le_bytes();
                let common = out.len().min(16);
                assert_eq!(out[..common], expected[..common]);
                assert!(out[common..].iter().all(|byte| *byte == 0));
            }
        }
    }

    #[test]
    fn poly_mul_ignores_bits_above_the_declared_length() {
        let mut clean = [0u8; 2];
        poly_mul(&mut clean, &[0x05], 3, &[0x13, 0x01], 9).expect("valid lengths");
        let mut dirty = [0u8; 2];
        poly_mul(&mut dirty, &[0xfd], 3, &[0x13, 0xff], 9).expect("valid lengths");
        assert_eq!(clean, dirty);
    }

    #[test]
    fn poly_mul_rejects_wrong_lengths() {
        let mut out = [0u8; 2];
        assert_eq!(
            poly_mul(&mut out, &[1], 0, &[1], 8),
            Err(FieldError::EmptyPolynomial)
        );
        assert_eq!(
            poly_mul(&mut out, &[1], 8, &[1], 0),
            Err(FieldError::EmptyPolynomial)
        );
        assert_eq!(
            poly_mul(&mut out, &[1, 2], 8, &[1], 8),
            Err(FieldError::InvalidLength {
                expected: 1,
                actual: 2
            })
        );
        assert_eq!(
            poly_mul(&mut out, &[1], 8, &[1, 2, 3], 9),
            Err(FieldError::InvalidLength {
                expected: 2,
                actual: 3
            })
        );
        assert_eq!(
            poly_mul(&mut out, &[1], 8, &[1, 2], 10),
            Err(FieldError::InvalidLength {
                expected: 3,
                actual: 2
            })
        );
        assert_eq!(poly_mul(&mut out, &[1], 8, &[1, 2], 9), Ok(()));
    }

    #[test]
    fn poly_reduce_matches_the_integer_remainder() {
        let mut state = 0x0fed_cba9_8765_4321;
        for (value_bits, modulus_bits) in [(16, 9), (24, 13), (22, 12), (64, 8), (5, 9), (9, 9)] {
            for _ in 0..20 {
                let value = next(&mut state) & (u64::MAX >> (64 - value_bits));
                let modulus = (next(&mut state) & ((1 << (modulus_bits - 1)) - 1))
                    | (1 << (modulus_bits - 1));
                let mut out = vec![0xaa; byte_len(modulus_bits - 1)];
                poly_reduce(
                    &mut out,
                    &value.to_le_bytes()[..byte_len(value_bits)],
                    value_bits,
                    &modulus.to_le_bytes()[..byte_len(modulus_bits)],
                    modulus_bits,
                )
                .expect("valid lengths");
                let expected = rem_u128(u128::from(value), u128::from(modulus)).to_le_bytes();
                assert_eq!(out[..], expected[..out.len()]);
            }
        }
    }

    #[test]
    fn poly_reduce_rejects_bad_moduli_and_lengths() {
        let mut out = [0u8; 1];
        assert_eq!(
            poly_reduce(&mut out, &[1], 0, &[0x1b, 1], 9),
            Err(FieldError::EmptyPolynomial)
        );
        assert_eq!(
            poly_reduce(&mut out, &[1], 8, &[1], 1),
            Err(FieldError::InvalidModulus)
        );
        assert_eq!(
            poly_reduce(&mut out, &[1], 8, &[0x1b, 0], 9),
            Err(FieldError::InvalidModulus)
        );
        assert_eq!(
            poly_reduce(&mut out, &[1], 8, &[0x1b], 9),
            Err(FieldError::InvalidLength {
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(
            poly_reduce(&mut [0u8; 2], &[1], 8, &[0x1b, 1], 9),
            Err(FieldError::InvalidLength {
                expected: 1,
                actual: 2
            })
        );
        assert_eq!(
            poly_reduce(&mut out, &[1, 2], 8, &[0x1b, 1], 9),
            Err(FieldError::InvalidLength {
                expected: 1,
                actual: 2
            })
        );
        // x^8 mod (x^8 + x^4 + x^3 + x + 1).
        assert_eq!(poly_reduce(&mut out, &[0, 1], 9, &[0x1b, 1], 9), Ok(()));
        assert_eq!(out, [0x1b]);
    }

    #[test]
    fn small_integer_helpers() {
        assert_eq!(degree_of(1), 0);
        assert_eq!(degree_of(0x11b), 8);
        assert_eq!(rem_small(0x100, 0x11b), 0x1b);
        assert_eq!(rem_small(0x1b, 0x11b), 0x1b);
        assert_eq!(rem_small(0, 0x11b), 0);
        assert_eq!(rem_small(0b110, 0b11), 0);
    }

    #[test]
    fn irreducibility_and_enumeration() {
        assert!(!is_irreducible(0));
        assert!(!is_irreducible(1));
        assert!(is_irreducible(0b10));
        assert!(is_irreducible(0b11));
        assert!(is_irreducible(0b111));
        assert!(!is_irreducible(0b101));
        assert!(is_irreducible(0x11b));
        assert!(!is_irreducible(0x11a));
        assert!(!is_irreducible(1 << 17));
        // Number of irreducible polynomials of degree n over GF(2).
        for (degree, count) in [
            (1, 2),
            (2, 1),
            (3, 2),
            (4, 3),
            (5, 6),
            (6, 9),
            (7, 18),
            (8, 30),
        ] {
            let all = smallest_irreducibles(degree, count).expect("that many exist");
            assert_eq!(all.len(), count);
            assert!(all.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(all.iter().all(|poly| degree_of(*poly) == degree));
            assert_eq!(
                smallest_irreducibles(degree, count + 1),
                Err(FieldError::NotEnoughIrreducibles {
                    requested: count + 1,
                    available: count
                })
            );
        }
        assert_eq!(smallest_irreducibles(8, 1), Ok(vec![0x11b]));
        assert_eq!(smallest_irreducibles(3, 2), Ok(vec![0b1011, 0b1101]));
        assert_eq!(
            smallest_irreducibles(0, 1),
            Err(FieldError::UnsupportedDegree { degree: 0, max: 16 })
        );
        assert_eq!(
            smallest_irreducibles(17, 1),
            Err(FieldError::UnsupportedDegree {
                degree: 17,
                max: 16
            })
        );
    }
}
