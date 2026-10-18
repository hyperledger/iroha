#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
use super::super::table_assets::read_u64_le;
use super::flr::Flr;
// ========================================================================
// Floating-point polynomials
// ========================================================================
// We consider here polynomials in R[X]/(X^n+1), for n a power of two
// between 4 and 1024. We express n = 2^logn for logn in [2, 10]. For
// each such polynomial:
//
//   - The "normal representation" of f = \sum_{i=0}^{n-1} f_i*X^i is
//     the sequence (f_0, f_1, f_2, ... f_{n-1}) as a slice of size n.
//     Elements are Flr instances.
//
//   - The "FFT representation" consists of n/2 complex numbers; the
//     first n/2 elements are the real parts, and for i = 0 to n/2-1,
//     the element i+n/2 in the slice contains the imaginary part
//     corresponding to element i in the slice. Only n/2 complex numbers
//     are needed for the FFT representation because all polynomials
//     are real (in normal representation), making the FFT representation
//     redundant.
//
//   - If a polynomial is self-adjoint then its FFT representation itself
//     contains only real numbers, and the corresponding slice only
//     has n/2 elements; the remaining n/2 (the imaginary parts of the
//     FFT coefficients) are implicitly zero and are omitted.
// Complex multiplication.
#[inline]
pub fn flc_mul(x_re: Flr, x_im: Flr, y_re: Flr, y_im: Flr) -> (Flr, Flr) {
    (x_re * y_re - x_im * y_im, x_re * y_im + x_im * y_re)
}
// Convert a polynomial from normal representation to FFT.
pub fn FFT(logn: u32, f: &mut [Flr]) {
    // First iteration of the FFT algorithm would compute
    // f[j] + i*f[j + n/2] for all j < n/2; since this is exactly our
    // storage format for complex numbers in the FFT representation,
    // that first iteration is a no-op, hence we can start the computation
    // at the second iteration.
    {
        assert!(logn >= 1);
        let n = 1usize << logn;
        let hn = n >> 1;
        let mut t = hn;
        for lm in 1..logn {
            let m = 1 << lm;
            let hm = m >> 1;
            let ht = t >> 1;
            let mut j0 = 0;
            for i in 0..hm {
                let s_re = GM[(m + i) << 1];
                let s_im = GM[((m + i) << 1) + 1];
                for j in 0..ht {
                    let j1 = j0 + j;
                    let j2 = j1 + ht;
                    let x_re = f[j1];
                    let x_im = f[j1 + hn];
                    let y_re = f[j2];
                    let y_im = f[j2 + hn];
                    let (z_re, z_im) = flc_mul(y_re, y_im, s_re, s_im);
                    f[j1] = x_re + z_re;
                    f[j1 + hn] = x_im + z_im;
                    f[j2] = x_re - z_re;
                    f[j2 + hn] = x_im - z_im;
                }
                j0 += t;
            }
            t = ht;
        }
    }
}
// Convert a polynomial from FFT representation to normal.
pub fn iFFT(logn: u32, f: &mut [Flr]) {
    // This is the reverse of FFT. We use the fact that if
    // w = exp(i*k*pi/N), then 1/w is the conjugate of w; thus, we can
    // get inverses from the table GM[] itself by simply negating the
    // imaginary part.
    //
    // The last iteration is a no-op (like the first iteration in FFT).
    // Since the last iteration is skipped, we have to perform only
    // a division by n/2 at the end.
    {
        assert!(logn >= 1);
        let n = 1usize << logn;
        let hn = n >> 1;
        let mut t = 1;
        for lm in 1..logn {
            let hm = 1 << (logn - lm);
            let dt = t << 1;
            let mut j0 = 0;
            for i in 0..(hm >> 1) {
                let s_re = GM[(hm + i) << 1];
                let s_im = -GM[((hm + i) << 1) + 1];
                for j in 0..t {
                    let j1 = j0 + j;
                    let j2 = j1 + t;
                    let x_re = f[j1];
                    let x_im = f[j1 + hn];
                    let y_re = f[j2];
                    let y_im = f[j2 + hn];
                    f[j1] = x_re + y_re;
                    f[j1 + hn] = x_im + y_im;
                    let x_re = x_re - y_re;
                    let x_im = x_im - y_im;
                    let (z_re, z_im) = flc_mul(x_re, x_im, s_re, s_im);
                    f[j2] = z_re;
                    f[j2 + hn] = z_im;
                }
                j0 += dt;
            }
            t = dt;
        }
        // We have logn-1 delayed halvings to perform, i.e. we must divide
        // all returned values by n/2.
        Flr::slice_div2e(&mut f[..n], logn - 1);
    }
}
// Set polynomial d from polynomial f with small coefficients.
pub fn poly_set_small(logn: u32, d: &mut [Flr], f: &[i8]) {
    {
        for i in 0..(1usize << logn) {
            d[i] = Flr::from_i32(i32::from(f[i]));
        }
    }
}
// Add polynomial b to polynomial a.
pub fn poly_add(logn: u32, a: &mut [Flr], b: &[Flr]) {
    {
        for i in 0..(1usize << logn) {
            a[i] += b[i];
        }
    }
}
// Subtract polynomial b from polynomial a.
pub fn poly_sub(logn: u32, a: &mut [Flr], b: &[Flr]) {
    {
        for i in 0..(1usize << logn) {
            a[i] -= b[i];
        }
    }
}
// Negate polynomial a.
pub fn poly_neg(logn: u32, a: &mut [Flr]) {
    {
        for coefficient in &mut a[..(1usize << logn)] {
            *coefficient = -*coefficient;
        }
    }
}
// Multiply polynomial a with polynomial b. The polynomials must be in
// FFT representation.
pub fn poly_mul_fft(logn: u32, a: &mut [Flr], b: &[Flr]) {
    {
        let hn = 1usize << (logn - 1);
        for i in 0..hn {
            let (re, im) = flc_mul(a[i], a[i + hn], b[i], b[i + hn]);
            a[i] = re;
            a[i + hn] = im;
        }
    }
}
// Multiply polynomial a with the adjoint of polynomial b. The polynomials
// must be in FFT representation.
pub fn poly_muladj_fft(logn: u32, a: &mut [Flr], b: &[Flr]) {
    {
        let hn = 1usize << (logn - 1);
        for i in 0..hn {
            let (re, im) = flc_mul(a[i], a[i + hn], b[i], -b[i + hn]);
            a[i] = re;
            a[i + hn] = im;
        }
    }
}
// Multiply polynomial a with its own adjoint. The polynomial must be in
// FFT representation. Since the result is a self-adjoint polynomial,
// coefficients n/2 to n-1 are set to zero.
pub fn poly_mulownadj_fft(logn: u32, a: &mut [Flr]) {
    {
        let hn = 1usize << (logn - 1);
        for i in 0..hn {
            a[i] = a[i].square() + a[i + hn].square();
            a[i + hn] = Flr::ZERO;
        }
    }
}
// Multiply polynomial a with a real constant x.
pub fn poly_mulconst(logn: u32, a: &mut [Flr], x: Flr) {
    {
        for coefficient in &mut a[..(1usize << logn)] {
            *coefficient *= x;
        }
    }
}
// Perform an LDL decomposition of a self-adjoint matrix G. The matrix
// is G = [[g00, g01], [adj(g01), g11]]; g00 and g11 are self-adjoint
// polynomials. The decomposition is G = L*D*adj(L), with:
//    D = [[g00, 0], [0, d11]]
//    L = [[1, 0], [l10, 1]]
// The output polynomials l10 and d11 are written over g01 and g11,
// respectively. Like g11, d11 is self-adjoint and uses only n/2
// coefficients. g00 is unmodified. All polynomials are in FFT
// representation.
pub fn poly_LDL_fft(logn: u32, g00: &[Flr], g01: &mut [Flr], g11: &mut [Flr]) {
    {
        let hn = 1usize << (logn - 1);
        for i in 0..hn {
            // g00 and g11 are self-adjoint
            let g00_re = g00[i];
            let (g01_re, g01_im) = (g01[i], g01[i + hn]);
            let g11_re = g11[i];
            let inv_g00_re = Flr::ONE / g00_re;
            let (mu_re, mu_im) = (g01_re * inv_g00_re, g01_im * inv_g00_re);
            let zo_re = mu_re * g01_re + mu_im * g01_im;
            g11[i] = g11_re - zo_re;
            g01[i] = mu_re;
            g01[i + hn] = -mu_im;
        }
    }
}
// Split operation on a polynomial: for input polynomial f, half-size
// polynomials f0 and f1 (modulo X^(n/2)+1) are such that
// f = f0(x^2) + x*f1(x^2). All polynomials are in FFT representation.
pub fn poly_split_fft(logn: u32, f0: &mut [Flr], f1: &mut [Flr], f: &[Flr]) {
    // If logn = 1 then the loop is entirely skipped.
    if logn == 1 {
        f0[0] = f[0];
        f1[0] = f[1];
        return;
    }
    {
        let hn = 1usize << (logn - 1);
        let qn = hn >> 1;
        for i in 0..qn {
            let (a_re, a_im) = (f[i << 1], f[(i << 1) + hn]);
            let (b_re, b_im) = (f[(i << 1) + 1], f[(i << 1) + 1 + hn]);
            let (t_re, t_im) = (a_re + b_re, a_im + b_im);
            f0[i] = t_re.half();
            f0[i + qn] = t_im.half();
            let (t_re, t_im) = (a_re - b_re, a_im - b_im);
            let (u_re, u_im) = flc_mul(t_re, t_im, GM[(i + hn) << 1], -GM[((i + hn) << 1) + 1]);
            f1[i] = u_re.half();
            f1[i + qn] = u_im.half();
        }
    }
}
// Specialized version of poly_split_fft() when the source polynomial
// is self-adjoint (i.e. all its FFT coefficients are real). On output,
// f0 is self-adjoint, but f1 is not necessarily self-adjoint.
pub fn poly_split_selfadj_fft(logn: u32, f0: &mut [Flr], f1: &mut [Flr], f: &[Flr]) {
    // If logn = 1 then the loop is entirely skipped.
    if logn == 1 {
        f0[0] = f[0];
        f1[0] = Flr::ZERO;
        return;
    }
    {
        let hn = 1usize << (logn - 1);
        let qn = hn >> 1;
        for i in 0..qn {
            let a_re = f[i << 1];
            let b_re = f[(i << 1) + 1];
            let t_re = a_re + b_re;
            f0[i] = t_re.half();
            f0[i + qn] = Flr::ZERO;
            let t_re = (a_re - b_re).half();
            f1[i] = t_re * GM[(i + hn) << 1];
            f1[i + qn] = t_re * -GM[((i + hn) << 1) + 1];
        }
    }
}
// Merge operation on a polynomial: for input half-size polynomials f0
// and f1 (modulo X^(n/2)+1), compute f = f0(x^2) + x*f1(x^2). All
// polynomials are in FFT representation.
pub fn poly_merge_fft(logn: u32, f: &mut [Flr], f0: &[Flr], f1: &[Flr]) {
    // If logn = 1 then the loop is entirely skipped.
    if logn == 1 {
        f[0] = f0[0];
        f[1] = f1[0];
        return;
    }
    {
        let hn = 1usize << (logn - 1);
        let qn = hn >> 1;
        for i in 0..qn {
            let (a_re, a_im) = (f0[i], f0[i + qn]);
            let (b_re, b_im) = flc_mul(
                f1[i],
                f1[i + qn],
                GM[(i + hn) << 1],
                GM[((i + hn) << 1) + 1],
            );
            f[i << 1] = a_re + b_re;
            f[(i << 1) + hn] = a_im + b_im;
            f[(i << 1) + 1] = a_re - b_re;
            f[(i << 1) + 1 + hn] = a_im - b_im;
        }
    }
}
// Table of constants for FFT. For k = 1 to 1023, define j = rev10(k), with
// rev10() being the bit-reversal function over 10 bits. Then:
//   GM[2*k + 0] = cos(k*pi/1024)
//   GM[2*k + 1] = sin(k*pi/1024)
// Here, all values are computed from integer approximations which were
// obtained from Sage, which employs sufficient precision to get an exact
// rounding. Specifically, we round x = cos(j*pi/1024) by looking for the
// integer n such that abs(x)*2^n is in [2^52, 2^53[, and make the value
// as round(x*2^n)/2^n (with Flr::scaled()).
// A test makes sure that the generated Flr constants have exactly the
// expected values.
//
// GM[0] and GM[1] (corresponding to k = 0) are unused and left to zero.
const fn mkflr(bits: u64) -> Flr {
    Flr::from_bits(bits)
}
const SIGN_GM_BYTES: &[u8; 16_384] = include_bytes!("../assets/sign_gm_binary64le_v1.bin");
const fn decode_gm(bytes: &[u8; 16_384]) -> [Flr; 2048] {
    let mut table = [Flr::ZERO; 2048];
    let mut index = 0;
    while index < table.len() {
        table[index] = mkflr(read_u64_le(bytes, index * 8));
        index += 1;
    }
    table
}
pub const GM: [Flr; 2048] = decode_gm(SIGN_GM_BYTES);

#[cfg(test)]
mod arithmetic_tests {
    use super::*;

    fn assert_integers(actual: &[Flr], expected: &[i32]) {
        assert_eq!(actual.len(), expected.len());
        for (value, &integer) in actual.iter().zip(expected) {
            assert_eq!(value.rint(), i64::from(integer));
        }
    }

    #[test]
    fn complex_products_and_prefix_scaling_match_independent_integer_arithmetic() {
        for left in [-3, -1, 0, 2, 7] {
            for right in [-5, -1, 0, 1, 4] {
                let (real, imaginary) = flc_mul(
                    Flr::from_i32(left),
                    Flr::from_i32(-left),
                    Flr::from_i32(right),
                    Flr::from_i32(right + 1),
                );
                assert_eq!(real.rint(), i64::from(left) * i64::from(2 * right + 1));
                assert_eq!(imaginary.rint(), i64::from(left));
            }
        }
        let mut coefficients = [-32768, -2, 0, 3, 91, -93].map(Flr::from_i32);
        poly_neg(2, &mut coefficients);
        assert_integers(&coefficients, &[32768, 2, 0, -3, 91, -93]);
        poly_mulconst(2, &mut coefficients, Flr::from_i32(-3));
        assert_integers(&coefficients, &[-98304, -6, 0, 9, 91, -93]);
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
            let mut transformed_left: Vec<_> = left.iter().copied().map(Flr::from_i32).collect();
            let mut transformed_right: Vec<_> = right.iter().copied().map(Flr::from_i32).collect();
            transformed_left.extend([Flr::from_i32(91), Flr::from_i32(-93)]);
            transformed_right.extend([Flr::from_i32(91), Flr::from_i32(-93)]);
            FFT(logn, &mut transformed_left);
            FFT(logn, &mut transformed_right);
            assert_integers(&transformed_left[degree..], &[91, -93]);
            assert_integers(&transformed_right[degree..], &[91, -93]);
            let mut roundtrip = transformed_left.clone();
            iFFT(logn, &mut roundtrip);
            assert_integers(&roundtrip[..degree], &left);
            assert_integers(&roundtrip[degree..], &[91, -93]);
            poly_mul_fft(logn, &mut transformed_left, &transformed_right);
            assert_integers(&transformed_left[degree..], &[91, -93]);
            iFFT(logn, &mut transformed_left);
            for (actual, integer) in transformed_left[..degree].iter().zip(expected) {
                assert_eq!(actual.rint(), integer, "logn={logn}");
            }
            assert_integers(&transformed_left[degree..], &[91, -93]);
        }
    }

    #[test]
    fn fft_split_and_merge_preserve_even_odd_coefficients_and_all_tails() {
        for logn in 2..=10 {
            let degree = 1_usize << logn;
            let half = degree / 2;
            let coefficients: Vec<_> = (0..degree)
                .map(|index| i32::try_from(index % 9).expect("small residue") - 4)
                .collect();
            let mut transformed: Vec<_> = coefficients.iter().copied().map(Flr::from_i32).collect();
            transformed.push(Flr::from_i32(91));
            FFT(logn, &mut transformed);
            let mut even = vec![Flr::from_i32(-93); half + 1];
            let mut odd = vec![Flr::from_i32(95); half + 1];
            poly_split_fft(logn, &mut even, &mut odd, &transformed);
            assert_integers(&even[half..], &[-93]);
            assert_integers(&odd[half..], &[95]);
            let mut merged = vec![Flr::from_i32(-97); degree + 1];
            poly_merge_fft(logn, &mut merged, &even, &odd);
            iFFT(logn, &mut merged);
            assert_integers(&merged[..degree], &coefficients);
            assert_integers(&merged[degree..], &[-97]);
            iFFT(logn - 1, &mut even);
            iFFT(logn - 1, &mut odd);
            let expected_even: Vec<_> = coefficients.iter().copied().step_by(2).collect();
            let expected_odd: Vec<_> = coefficients.iter().copied().skip(1).step_by(2).collect();
            assert_integers(&even[..half], &expected_even);
            assert_integers(&odd[..half], &expected_odd);
            assert_integers(&even[half..], &[-93]);
            assert_integers(&odd[half..], &[95]);
            assert_integers(&transformed[degree..], &[91]);
        }
    }

    #[test]
    fn selfadjoint_split_matches_full_split_and_retains_real_spectral_values() {
        for logn in 1..=10 {
            let degree = 1_usize << logn;
            let half = degree / 2;
            let real: Vec<_> = (0..half)
                .map(|index| i32::try_from(index % 7).expect("small residue") - 3)
                .collect();
            let mut full: Vec<_> = real.iter().copied().map(Flr::from_i32).collect();
            full.resize(degree, Flr::ZERO);
            let mut even = vec![Flr::from_i32(91); half + 1];
            let mut odd = vec![Flr::from_i32(-93); half + 1];
            let mut general_even = even.clone();
            let mut general_odd = odd.clone();
            poly_split_selfadj_fft(logn, &mut even, &mut odd, &full[..half]);
            poly_split_fft(logn, &mut general_even, &mut general_odd, &full);
            for (actual, general) in even[..half].iter().zip(&general_even[..half]) {
                assert_eq!(actual.rint(), general.rint());
            }
            for (actual, general) in odd[..half].iter().zip(&general_odd[..half]) {
                assert_eq!(actual.rint(), general.rint());
            }
            let mut merged = vec![Flr::from_i32(95); degree + 1];
            poly_merge_fft(logn, &mut merged, &even, &odd);
            assert_integers(&merged[..half], &real);
            assert_integers(&merged[half..degree], &vec![0; half]);
            assert_integers(&merged[degree..], &[95]);
            assert_integers(&even[half..], &[91]);
            assert_integers(&odd[half..], &[-93]);
        }
    }
}
