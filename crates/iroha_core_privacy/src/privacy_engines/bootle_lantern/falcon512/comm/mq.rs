#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
//! # Computations modulo q = 12289
//!
//! External callers should only see polynomials modulo `X^n+1` and modulo q. Such polynomials use
//! slices of `u16`. There are three distinct representations:
//!
//!   - External representation: plain coefficients, in the `[0,q-1]` range.
//!
//!   - Internal representation: plain coefficients, but with a storage
//!     convention that may differ from the external representation.
//!
//!   - NTT representation: NTT format, coefficients may also have an
//!     internal range that differs from the external representation.
//!
//! Appropriate functions are provided to convert between these representations.
use super::super::table_assets::read_u16_le;
// In the code below, the internal representation uses the q range,
// and Montgomery multiplications use R = 2^32 instead of the usual
// R = 2^16. This representation speeds up operations, because if:
//   1 <= x <= q
//   1 <= y <= q
// then a Montgomery multiplication computes:
//   a <- x*y
//   b <- -a/q mod 2^32  (computed with a product with constant -1/q mod 2^32)
//   c <- (b >> 16)*q
//   d <- (c >> 16) + 1
// and this ensures that:
//   d = x*y/2^32 mod q
//   1 <= d <= q
// In other words, there is no need for a conditional subtraction of the
// modulus. Also note that the c value above is obtained as a 16x16 product,
// only the high 16 bits of which are actually needed.
/// Check whether the provided polynomial with small coefficient is
/// invertible modulo `X^n+1` and modulo q.
pub fn mqpoly_small_is_invertible(logn: u32, f: &[i8], tmp: &mut [u16]) -> bool {
    let n = 1usize << logn;
    mqpoly_small_to_int(logn, f, tmp);
    mqpoly_int_to_NTT(logn, tmp);
    let mut r = 0xFFFF_FFFF;
    for &coefficient in &tmp[..n] {
        r &= u32::from(coefficient).wrapping_sub(Q);
    }
    (r >> 16) != 0
}
/// Compute `h = g/f mod X^n+1 mod q`.
///
/// This function assumes that `f` is invertible. Output is in external
/// representation (coefficients are in `[0,q-1]`).
pub fn mqpoly_div_small(logn: u32, f: &[i8], g: &[i8], h: &mut [u16], tmp: &mut [u16]) {
    let n = 1usize << logn;
    mqpoly_small_to_int(logn, f, tmp);
    mqpoly_small_to_int(logn, g, h);
    mqpoly_int_to_NTT(logn, tmp);
    mqpoly_int_to_NTT(logn, h);
    for i in 0..n {
        h[i] = read_u16_le(&mq_div(u32::from(h[i]), u32::from(tmp[i])).to_le_bytes(), 0);
    }
    mqpoly_NTT_to_int(logn, h);
    mqpoly_int_to_ext(logn, h);
}
const Q: u32 = 12289;
// -1/q mod 2^32
const Q1I: u32 = 4_143_984_639;
// 2^64 mod q
const R2: u32 = 5664;
// Addition modulo q (internal representation).
#[inline]
fn mq_add(x: u32, y: u32) -> u32 {
    // a = q - (x + y)
    // -q <= a <= q - 2  (represented as u32)
    let a = Q.wrapping_sub(x + y);
    // If a < 0, add q.
    // b = -(x + y) mod q
    // 0 <= b <= q - 1
    let b = a.wrapping_add(Q & (a >> 16));
    // q - b = x + y mod q
    // 1 <= q - b <= q
    Q - b
}
// Subtraction modulo q (internal representation).
#[inline]
fn mq_sub(x: u32, y: u32) -> u32 {
    // -(q - 1) <= a <= q - 1
    let a = y.wrapping_sub(x);
    // 0 <= b <= q - 1
    let b = a.wrapping_add(Q & (a >> 16));
    Q - b
}
// Halving modulo q (internal representation).
#[inline]
fn mq_half(x: u32) -> u32 {
    (x + ((x & 1).wrapping_neg() & Q)) >> 1
}
// mq_mred(x) computes x/2^32 mod q, without output in the [1,q] range.
// Input must be such that 1 <= x <= 3489673216. Note that this means
// that we can add up to 23 products together, and mutualize their
// reduction.
#[inline]
fn mq_mred(x: u32) -> u32 {
    let b = x.wrapping_mul(Q1I);
    let c = (b >> 16) * Q;
    (c >> 16) + 1
}
// Montgomery multiplication modulo q (internal representation).
#[inline]
fn mq_mmul(x: u32, y: u32) -> u32 {
    mq_mred(x * y)
}
// Division modulo q (internal representation). If the divisor is zero
// (represented by q), then the result is zero.
fn mq_div(x: u32, y: u32) -> u32 {
    // Convert y to Montgomery representation.
    let y = mq_mmul(y, R2);
    // 1/y = y^(q-2), with a custom addition chain.
    let y2 = mq_mmul(y, y);
    let y3 = mq_mmul(y2, y);
    let y5 = mq_mmul(y3, y2);
    let y10 = mq_mmul(y5, y5);
    let y20 = mq_mmul(y10, y10);
    let y40 = mq_mmul(y20, y20);
    let y80 = mq_mmul(y40, y40);
    let power_160 = mq_mmul(y80, y80);
    let y163 = mq_mmul(power_160, y3);
    let y323 = mq_mmul(y163, power_160);
    let y646 = mq_mmul(y323, y323);
    let y1292 = mq_mmul(y646, y646);
    let y1455 = mq_mmul(y1292, y163);
    let y2910 = mq_mmul(y1455, y1455);
    let y5820 = mq_mmul(y2910, y2910);
    let y6143 = mq_mmul(y5820, y323);
    let y12286 = mq_mmul(y6143, y6143);
    let iy = mq_mmul(y12286, y);
    // Multiply by x to get x/y. 1/y is in Montgomery representation but
    // x is not, so the product is in normal (internal) representation.
    mq_mmul(x, iy)
}
/// Given a polynomial with small coefficients, convert it to internal representation.
///
/// Converted polynomial is written into `d`.
pub fn mqpoly_small_to_int(logn: u32, f: &[i8], d: &mut [u16]) {
    for i in 0..(1usize << logn) {
        let x = (-i32::from(f[i])).cast_unsigned();
        d[i] = read_u16_le(&(Q - x.wrapping_add((x >> 16) & Q)).to_le_bytes(), 0);
    }
}
/// Given a polynomial in internal representation, convert it to external representation (in-place).
pub fn mqpoly_int_to_ext(logn: u32, a: &mut [u16]) {
    for coefficient in &mut a[..(1usize << logn)] {
        // External representation is the same as internal, except that
        // zero is represented by 0 instead of q.
        let x = u32::from(*coefficient).wrapping_sub(Q);
        *coefficient = read_u16_le(&x.wrapping_add(Q & (x >> 16)).to_le_bytes(), 0);
    }
}
/// Convert a polynomial from internal representation to NTT (in-place).
pub fn mqpoly_int_to_NTT(logn: u32, a: &mut [u16]) {
    if logn == 0 {
        return;
    }
    let mut t = 1usize << logn;
    for lm in 0..logn {
        let m = 1 << lm;
        let ht = t >> 1;
        let mut j0 = 0;
        for i in 0..m {
            let s = u32::from(GM[i + m]);
            for j in 0..ht {
                let j1 = j0 + j;
                let j2 = j1 + ht;
                let x1 = u32::from(a[j1]);
                let x2 = mq_mmul(u32::from(a[j2]), s);
                a[j1] = read_u16_le(&mq_add(x1, x2).to_le_bytes(), 0);
                a[j2] = read_u16_le(&mq_sub(x1, x2).to_le_bytes(), 0);
            }
            j0 += t;
        }
        t = ht;
    }
}
/// Convert a polynomial from NTT to internal representation (in-place).
pub fn mqpoly_NTT_to_int(logn: u32, a: &mut [u16]) {
    if logn == 0 {
        return;
    }
    let mut t = 1;
    for lm in 0..logn {
        let hm = 1 << (logn - 1 - lm);
        let dt = t << 1;
        let mut j0 = 0;
        for i in 0..hm {
            let s = u32::from(iGM[i + hm]);
            for j in 0..t {
                let j1 = j0 + j;
                let j2 = j1 + t;
                let x1 = u32::from(a[j1]);
                let x2 = u32::from(a[j2]);
                a[j1] = read_u16_le(&mq_half(mq_add(x1, x2)).to_le_bytes(), 0);
                a[j2] = read_u16_le(&mq_mmul(mq_sub(x1, x2), s).to_le_bytes(), 0);
            }
            j0 += dt;
        }
        t = dt;
    }
}
// NTT factors: if rev10() is the bit-reversal function over 10 bits,
// then:
//   GM[i] = (g^rev10(i))*2^32 mod q         (in [1,q])
//   iGM[i] = ((1/g)^rev10(i))*2^31 mod q    (in [1,q])
// where g is a primitive 2048-th root of 1 modulo q (i.e. g^1024 = -1 mod q).
// The factor 2^32 in GM[i] means that the value is in Montgomery
// representation; the factor 2^31 for iGM[i] implies the same, with an
// extra halving already injected in the computation.
const MQ_NTT_BYTES: &[u8; 4_096] = include_bytes!("../assets/comm_ntt_u16le_v1.bin");
const fn decode_mq_ntt(bytes: &[u8; 4_096]) -> ([u16; 1024], [u16; 1024]) {
    let mut gm = [0_u16; 1024];
    let mut inverse_gm = [0_u16; 1024];
    let mut index = 0;
    while index < gm.len() {
        gm[index] = read_u16_le(bytes, index * 2);
        inverse_gm[index] = read_u16_le(bytes, 2_048 + index * 2);
        index += 1;
    }
    (gm, inverse_gm)
}
const MQ_NTT_TABLES: ([u16; 1024], [u16; 1024]) = decode_mq_ntt(MQ_NTT_BYTES);
pub const GM: [u16; 1024] = MQ_NTT_TABLES.0;
pub const iGM: [u16; 1024] = MQ_NTT_TABLES.1;

#[cfg(test)]
mod arithmetic_tests {
    use super::*;

    fn internal(value: i64) -> u32 {
        let residue = value.rem_euclid(i64::from(Q));
        if residue == 0 {
            Q
        } else {
            u32::try_from(residue).expect("residue below q")
        }
    }

    fn power(mut base: u64, mut exponent: u64) -> u64 {
        let modulus = u64::from(Q);
        let mut result = 1;
        while exponent != 0 {
            if exponent & 1 != 0 {
                result = result * base % modulus;
            }
            base = base * base % modulus;
            exponent >>= 1;
        }
        result
    }

    fn negacyclic_product(left: &[i64], right: &[i64]) -> Vec<i64> {
        assert_eq!(left.len(), right.len());
        let degree = left.len();
        let mut product = vec![0; degree];
        for (left_index, &left_value) in left.iter().enumerate() {
            for (right_index, &right_value) in right.iter().enumerate() {
                let index = left_index + right_index;
                let term = left_value * right_value;
                if index < degree {
                    product[index] += term;
                } else {
                    product[index - degree] -= term;
                }
            }
        }
        product
    }

    #[test]
    fn internal_modular_arithmetic_matches_integer_remainders_and_inverses() {
        let values = [1, 2, Q / 2, Q / 2 + 1, Q - 1, Q];
        let inverse_radix = i64::try_from(power((1u64 << 32) % u64::from(Q), u64::from(Q - 2)))
            .expect("residue below q");
        for left in values {
            for right in values {
                assert_eq!(
                    mq_add(left, right),
                    internal(i64::from(left) + i64::from(right))
                );
                assert_eq!(
                    mq_sub(left, right),
                    internal(i64::from(left) - i64::from(right))
                );
                assert_eq!(
                    mq_mmul(left, right),
                    internal(i64::from(left) * i64::from(right) * inverse_radix)
                );
            }
            assert_eq!(
                mq_half(left),
                internal(i64::from(left) * i64::from(Q.div_ceil(2)))
            );
        }
        // Include both ends of the documented reduction domain and the
        // permitted batch of 23 maximum internal-representation products.
        for value in [1, Q - 1, Q, Q + 1, Q * Q, 23 * Q * Q, 3_489_673_216] {
            assert_eq!(mq_mred(value), internal(i64::from(value) * inverse_radix));
        }
        // Every possible divisor, including zero represented by q, is checked
        // against independent ordinary modular exponentiation.
        for divisor in 1..=Q {
            let inverse = i64::try_from(power(u64::from(divisor), u64::from(Q - 2)))
                .expect("residue below q");
            for numerator in [1, Q / 2, Q] {
                assert_eq!(
                    mq_div(numerator, divisor),
                    internal(i64::from(numerator) * inverse)
                );
            }
        }
    }

    #[test]
    fn signed_conversion_and_external_zero_preserve_original_slice_prefixes() {
        let coefficients: Vec<_> = (i8::MIN..=i8::MAX).collect();
        let mut encoded = vec![0xA5A5_u16; coefficients.len() + 2];
        mqpoly_small_to_int(8, &coefficients, &mut encoded);
        for (&actual, &coefficient) in encoded[..coefficients.len()].iter().zip(&coefficients) {
            assert_eq!(u32::from(actual), internal(i64::from(coefficient)));
        }
        assert_eq!(&encoded[coefficients.len()..], &[0xA5A5; 2]);
        mqpoly_int_to_ext(8, &mut encoded);
        for (&actual, &coefficient) in encoded[..coefficients.len()].iter().zip(&coefficients) {
            assert_eq!(
                i64::from(actual),
                i64::from(coefficient).rem_euclid(i64::from(Q))
            );
        }
        assert_eq!(&encoded[coefficients.len()..], &[0xA5A5; 2]);
    }

    #[test]
    fn ntt_roundtrips_and_products_match_schoolbook_negacyclic_arithmetic() {
        for logn in 0..=10 {
            let degree = 1usize << logn;
            let input_left: Vec<_> = (0..degree)
                .map(|index| i8::try_from(index % 17).expect("small coefficient") - 8)
                .collect();
            let input_right: Vec<_> = (0..degree)
                .map(|index| i8::try_from(index % 11).expect("small coefficient") - 5)
                .collect();
            let mut left = vec![0xA5A5_u16; degree + 2];
            let mut right = vec![0xA5A5_u16; degree + 2];
            mqpoly_small_to_int(logn, &input_left, &mut left);
            mqpoly_small_to_int(logn, &input_right, &mut right);
            mqpoly_int_to_NTT(logn, &mut left);
            mqpoly_int_to_NTT(logn, &mut right);
            assert_eq!(&left[degree..], &[0xA5A5; 2]);
            assert_eq!(&right[degree..], &[0xA5A5; 2]);
            let mut product = vec![0xA5A5_u16; degree + 2];
            for ((destination, &left_value), &right_value) in product[..degree]
                .iter_mut()
                .zip(&left[..degree])
                .zip(&right[..degree])
            {
                *destination = u16::try_from(mq_mmul(
                    mq_mmul(u32::from(left_value), u32::from(right_value)),
                    R2,
                ))
                .expect("internal residue below q");
            }
            mqpoly_NTT_to_int(logn, &mut product);
            mqpoly_int_to_ext(logn, &mut product);
            let wide_left: Vec<_> = input_left.iter().copied().map(i64::from).collect();
            let wide_right: Vec<_> = input_right.iter().copied().map(i64::from).collect();
            let expected = negacyclic_product(&wide_left, &wide_right);
            for (&actual, expected_coefficient) in product[..degree].iter().zip(expected) {
                assert_eq!(
                    i64::from(actual),
                    expected_coefficient.rem_euclid(i64::from(Q))
                );
            }
            assert_eq!(&product[degree..], &[0xA5A5; 2]);
            mqpoly_NTT_to_int(logn, &mut left);
            mqpoly_int_to_ext(logn, &mut left);
            for (&actual, expected_coefficient) in left[..degree].iter().zip(wide_left) {
                assert_eq!(
                    i64::from(actual),
                    expected_coefficient.rem_euclid(i64::from(Q))
                );
            }
            assert_eq!(&left[degree..], &[0xA5A5; 2]);
        }
    }

    #[test]
    fn monomial_division_and_invertibility_preserve_equations_and_tail_custody() {
        for logn in 0..=10 {
            let degree = 1usize << logn;
            let mut divisor = vec![0_i8; degree];
            divisor[usize::from(degree > 1)] = -1;
            let numerator: Vec<_> = (0..degree)
                .map(|index| i8::try_from(index % 31).expect("small coefficient") - 15)
                .collect();
            let mut temporary = vec![0xA5A5_u16; degree + 2];
            let mut quotient = vec![0xA5A5_u16; degree + 2];
            assert!(mqpoly_small_is_invertible(logn, &divisor, &mut temporary));
            assert_eq!(&temporary[degree..], &[0xA5A5; 2]);
            mqpoly_div_small(logn, &divisor, &numerator, &mut quotient, &mut temporary);
            assert!(quotient[..degree].iter().all(|value| u32::from(*value) < Q));
            assert_eq!(&quotient[degree..], &[0xA5A5; 2]);
            assert_eq!(&temporary[degree..], &[0xA5A5; 2]);
            let wide_divisor: Vec<_> = divisor.iter().copied().map(i64::from).collect();
            let wide_quotient: Vec<_> = quotient[..degree].iter().copied().map(i64::from).collect();
            let product = negacyclic_product(&wide_divisor, &wide_quotient);
            for (actual, expected) in product.into_iter().zip(numerator) {
                assert_eq!(
                    actual.rem_euclid(i64::from(Q)),
                    i64::from(expected).rem_euclid(i64::from(Q))
                );
            }
            divisor.fill(0);
            assert!(!mqpoly_small_is_invertible(logn, &divisor, &mut temporary));
            assert_eq!(&temporary[degree..], &[0xA5A5; 2]);
        }
    }
}
