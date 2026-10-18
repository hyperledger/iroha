#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
use super::fxp::{Fxc, Fxr, GM_TAB};
// ========================================================================
// Fixed-point vector operations
// ========================================================================
// In FFT representation, we only keep half of the coefficients, because
// all our vectors are real in non-FFT; thus, the FFT representation is
// redundant. For 0 <= k < n/2, f[k] contains the real part, and f[k + n/2]
// the imaginary part of the complex value.
// Convert a (real) vector to its FFT representation.
pub fn vect_FFT(logn: u32, values: &mut [Fxr]) {
    let hn = 1usize << (logn - 1);
    let mut span = hn;
    for lm in 1..logn {
        let blocks = 1usize << lm;
        let ht = span >> 1;
        let mut j0 = 0;
        for i in 0..(blocks >> 1) {
            let twiddle = GM_TAB[blocks + i];
            for j in j0..(j0 + ht) {
                let left = Fxc {
                    re: values[j],
                    im: values[j + hn],
                };
                let right = Fxc {
                    re: values[j + ht],
                    im: values[j + ht + hn],
                };
                let product = twiddle * right;
                let w1 = left + product;
                values[j] = w1.re;
                values[j + hn] = w1.im;
                let w2 = left - product;
                values[j + ht] = w2.re;
                values[j + ht + hn] = w2.im;
            }
            j0 += span;
        }
        span = ht;
    }
}
// Convert back from FFT representation into a real vector.
//
// Note: in the final outer iteration:
//
//  - f[j] and f[j+hn] are set to the half of a complex number. Fixed point
//    values are held in integers in the [-2^63..+2^63-1] range (in signed
//    interpretation) and halving is done by adding 1 and then an
//    arithmetic right shift, thus with an output necessarily in the
//    [-2^62..+2^62-1] range (addition of 1 to 2^63-1 "wraps around" in that
//    +2^63 is interpreted as -2^63 instead).
//
//  - f[j+ht] and f[j+ht+hn] are set to the product of the half of a
//    complex number, and the complex sqrt(2)-i*sqrt(2). Value sqrt(2)
//    is represented by the fixed point 3037000500. Following the steps
//    in fxc_mul():
//       r1, i1:           -2^62 .. +2^62-1
//       r2:               +3037000500
//       i2:               -3037000500
//       t0:               -3260954456358912000 .. +3260954456358911999
//       t1:               -3260954456358912000 .. +3260954456358912000
//       fxr_add(r1, i1):  -2^63 .. +2^63-2
//       fxr_add(r2, i2):  always zero
//       t2:               always zero
//       fxr_sub(t0, t1):  -6521908912717824000 .. +6521908912717823999
//       fxr_add(t0, t1):  -6521908912717824000 .. +6521908912717823999
//    Thus, the obtained output values must be in the
//    [-6521908912717824000..+6521908912717824000] range.
//
// If the output of vect_iFFT() is then rounded to integers, then the
// maximum range for any output value after rounding is
// [-1518500250..+1518500250], regardless of the contents of the source
// vector. In particular, this is a smaller range than signed 32-bit integers
// in general, and it avoids the troublesome values such as -2^31.
pub fn vect_iFFT(logn: u32, values: &mut [Fxr]) {
    let hn = 1usize << (logn - 1);
    let mut ht = 1;
    for lm in (1..logn).rev() {
        let blocks = 1usize << lm;
        let span = ht << 1;
        let mut j0 = 0;
        for i in 0..(blocks >> 1) {
            let twiddle = GM_TAB[blocks + i].conj();
            for j in j0..(j0 + ht) {
                let left = Fxc {
                    re: values[j],
                    im: values[j + hn],
                };
                let right = Fxc {
                    re: values[j + ht],
                    im: values[j + ht + hn],
                };
                let z1 = (left + right).half();
                values[j] = z1.re;
                values[j + hn] = z1.im;
                let z2 = twiddle * (left - right).half();
                values[j + ht] = z2.re;
                values[j + ht + hn] = z2.im;
            }
            j0 += span;
        }
        ht = span;
    }
}
// Set vector d to the value of polynomial f.
pub fn vect_to_fxr(logn: u32, d: &mut [Fxr], f: &[i8]) {
    for i in 0..(1usize << logn) {
        d[i] = Fxr::from_i32(i32::from(f[i]));
    }
}
// Add vector b to vector a. This works in both real and FFT representations.
pub fn vect_add(logn: u32, a: &mut [Fxr], b: &[Fxr]) {
    for i in 0..(1usize << logn) {
        a[i] += b[i];
    }
}
// Multiply vector a by constant c. This works in both real and FFT
// representations.
pub fn vect_mul_realconst(logn: u32, a: &mut [Fxr], c: Fxr) {
    for coefficient in &mut a[..(1usize << logn)] {
        *coefficient *= c;
    }
}
// Multiply vector a by 2^e. Exponent e should be in the [0,30] range.
pub fn vect_mul2e(logn: u32, a: &mut [Fxr], e: u32) {
    for coefficient in &mut a[..(1usize << logn)] {
        coefficient.set_mul2e(e);
    }
}
// Multiply vector a by vector b. The vectors must be in FFT representation,
// and the result is in FFT representation.
pub fn vect_mul_fft(logn: u32, left: &mut [Fxr], right: &[Fxr]) {
    let hn = 1usize << (logn - 1);
    for i in 0..hn {
        let left_complex = Fxc {
            re: left[i],
            im: left[i + hn],
        };
        let right_complex = Fxc {
            re: right[i],
            im: right[i + hn],
        };
        let product = left_complex * right_complex;
        left[i] = product.re;
        left[i + hn] = product.im;
    }
}
// Convert a vector into its Hermitian adjoint (in FFT representation).
pub fn vect_adj_fft(logn: u32, a: &mut [Fxr]) {
    for coefficient in &mut a[(1usize << (logn - 1))..(1usize << logn)] {
        coefficient.set_neg();
    }
}
// Multiply vector a by the self-adjoint vector b. Both vectors are in FFT
// representation. Since the FFT representation of a self-adjoint vector
// contains only real numbers, the second half of b contains only zeros and
// thus is not accessed (the slice may be half length).
pub fn vect_mul_selfadj_fft(logn: u32, a: &mut [Fxr], b: &[Fxr]) {
    let hn = 1usize << (logn - 1);
    for i in 0..hn {
        let c = b[i];
        a[i] *= c;
        a[i + hn] *= c;
    }
}
// Divide vector a by the self-adjoint vector b. Both vectors are in FFT
// representation. Since the FFT representation of a self-adjoint vector
// contains only real numbers, the second half of b contains only zeros and
// thus is not accessed (the slice may be half length).
pub fn vect_div_selfadj_fft(logn: u32, a: &mut [Fxr], b: &[Fxr]) {
    let hn = 1usize << (logn - 1);
    for i in 0..hn {
        // We do not compute 1/c separately because that would deviate from
        // the specification, and lose too much precision; we need to
        // perform the two divisions.
        let c = b[i];
        a[i] /= c;
        a[i + hn] /= c;
    }
}
// Compute d = a*adj(a) + b*adj(b). Polynomials are in FFT representation.
// Since d is self-adjoint, it is half-size (only the low half is set, the
// high half is implicitly zero).
pub fn vect_norm_fft(logn: u32, d: &mut [Fxr], a: &[Fxr], b: &[Fxr]) {
    let hn = 1usize << (logn - 1);
    for i in 0..hn {
        d[i] = a[i].sqr() + a[i + hn].sqr() + b[i].sqr() + b[i + hn].sqr();
    }
}
// Compute d = (2^e)/(a*adj(a) + b*adj(b)). Polynomials are in FFT
// representation. Since d is self-adjoint, it is half-size (only the
// low half is set, the high half is implicitly zero).
pub fn vect_invnorm_fft(logn: u32, output: &mut [Fxr], left: &[Fxr], right: &[Fxr], exponent: u32) {
    let hn = 1usize << (logn - 1);
    let numerator = Fxr::from_i32(1i32 << exponent);
    for i in 0..hn {
        let z1 = left[i].sqr() + left[i + hn].sqr();
        let z2 = right[i].sqr() + right[i + hn].sqr();
        output[i] = numerator / (z1 + z2);
    }
}
// ========================================================================

#[cfg(test)]
mod arithmetic_tests {
    use super::*;

    #[test]
    fn scalar_scaling_and_adjoint_preserve_exact_bits_and_slice_tails() {
        let source = [-3, -1, 0, 7, 91, -93].map(Fxr::from_i32);
        let mut scaled = source;
        vect_mul_realconst(2, &mut scaled, Fxr::from_i32(-3));
        assert_eq!(scaled, [9, 3, 0, -21, 91, -93].map(Fxr::from_i32));
        let raw = [0, 1, u64::MAX, 1 << 63, 91, 93];
        for exponent in [0, 1, 30] {
            let mut shifted = raw.map(Fxr::from_u64_scaled32);
            vect_mul2e(2, &mut shifted, exponent);
            for (index, actual) in shifted.iter().enumerate() {
                let expected = if index < 4 {
                    raw[index].wrapping_shl(exponent)
                } else {
                    raw[index]
                };
                assert_eq!(actual.0, expected);
            }
        }
        let mut adjoint = raw.map(Fxr::from_u64_scaled32);
        vect_adj_fft(2, &mut adjoint);
        for (index, actual) in adjoint.iter().enumerate() {
            let expected = if (2..4).contains(&index) {
                raw[index].wrapping_neg()
            } else {
                raw[index]
            };
            assert_eq!(actual.0, expected);
        }
    }

    #[test]
    fn fft_products_match_integer_negacyclic_convolution_at_every_degree() {
        for logn in 1..=10 {
            let degree = 1_usize << logn;
            let left: Vec<_> = (0..degree)
                .map(|index| i32::try_from(index % 5).expect("small residue") - 2)
                .collect();
            let right: Vec<_> = (0..degree)
                .map(|index| i32::try_from(index % 7).expect("small residue") - 3)
                .collect();
            let mut expected = vec![0_i64; degree];
            for (left_index, &left_value) in left.iter().enumerate() {
                for (right_index, &right_value) in right.iter().enumerate() {
                    let index = left_index + right_index;
                    let product = i64::from(left_value) * i64::from(right_value);
                    if index < degree {
                        expected[index] += product;
                    } else {
                        expected[index - degree] -= product;
                    }
                }
            }
            let tail = [Fxr::from_i32(91), Fxr::from_i32(-93)];
            let mut transformed_left: Vec<_> = left.iter().copied().map(Fxr::from_i32).collect();
            let mut transformed_right: Vec<_> = right.iter().copied().map(Fxr::from_i32).collect();
            transformed_left.extend(tail);
            transformed_right.extend(tail);
            vect_FFT(logn, &mut transformed_left);
            vect_FFT(logn, &mut transformed_right);
            assert_eq!(&transformed_left[degree..], &tail);
            assert_eq!(&transformed_right[degree..], &tail);
            let mut roundtrip = transformed_left.clone();
            vect_iFFT(logn, &mut roundtrip);
            for (actual, &integer) in roundtrip[..degree].iter().zip(&left) {
                assert_eq!(actual.round(), integer, "logn={logn}");
            }
            assert_eq!(&roundtrip[degree..], &tail);
            vect_mul_fft(logn, &mut transformed_left, &transformed_right);
            assert_eq!(&transformed_left[degree..], &tail);
            vect_iFFT(logn, &mut transformed_left);
            for (actual, integer) in transformed_left[..degree].iter().zip(expected) {
                assert_eq!(i64::from(actual.round()), integer, "logn={logn}");
            }
            assert_eq!(&transformed_left[degree..], &tail);
        }
    }

    #[test]
    fn inverse_norm_uses_both_complex_halves_and_only_writes_the_real_prefix() {
        let left = [1, 0, 1, 0].map(Fxr::from_i32);
        let right = [0, 2, 0, 2].map(Fxr::from_i32);
        for exponent in [0, 3, 30] {
            let mut output = [Fxr::from_i32(-91); 4];
            vect_invnorm_fft(2, &mut output, &left, &right, exponent);
            let numerator = 1_u64 << (32 + exponent);
            assert_eq!(output[0].0, numerator / 2);
            assert_eq!(output[1].0, numerator / 8);
            assert_eq!(&output[2..], &[Fxr::from_i32(-91); 2]);
        }
    }
}
