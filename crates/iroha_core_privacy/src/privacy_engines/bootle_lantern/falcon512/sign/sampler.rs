#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
use super::super::{comm::PRNG, table_assets::read_u32_le};
use super::flr::Flr;
use super::poly::*;
// ========================================================================
// Gaussian sampling
// ========================================================================
// The sampler generates random integer values that follow a Gaussian
// distribution. The centre and standard deviation of that distribution
// are not integral, vary within each signature generation, and are
// secret.
// A sampler state includes a PRNG, from which random bytes are obtained,
// and the (logarithmic) degree for the overall scheme (some constants
// depend on the used degree).
pub struct Sampler<T: PRNG> {
    rng: T,
    logn: u32,
    remaining_proposals: u32,
}
// Borrowed Gram-matrix storage for one recursive sampling level. The caller
// retains every allocation and zeroization owner; this view only groups its
// two diagonal polynomials and the off-diagonal polynomial.
struct GramMatrixMut<'a> {
    g00: &'a mut [Flr],
    g01: &'a mut [Flr],
    g11: &'a mut [Flr],
}
pub(super) const MAX_PROPOSALS_PER_COEFFICIENT: u32 = 256;
impl<T: PRNG> core::fmt::Debug for Sampler<T> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Falcon512Sampler(<redacted>)")
    }
}
impl<T: PRNG> Drop for Sampler<T> {
    fn drop(&mut self) {
        self.rng.zeroize();
        self.logn = 0;
        self.remaining_proposals = 0;
    }
}
// 1/(2*(1.8205^2))
const INV_2SQRSIGMA0: Flr = Flr::scaled(5_435_486_223_186_882, -55);
// For logn = 1 to 10, n = 2^logn:
//    q = 12289
//    gs_norm = (117/100)*sqrt(q)
//    bitsec = max(2, n/4)
//    eps = 1/sqrt(bitsec*2^64)
//    smoothz2n = sqrt(log(4*n*(1 + 1/eps))/pi)/sqrt(2*pi)
//    sigma = smoothz2n*gs_norm
//    sigma_min = sigma/gs_norm = smoothz2n
// We store precomputed values for 1/sigma and for sigma_min, indexed by logn.
//
// Note: the fpr_inv_sigma[] constants used in the reference C code used
// these expressions, except that "117/100" was written "1.17". It turns out
// that in Sage (at least version 10.4), this silently degrades the precision
// to 53 bits, and the result is a bit off; namely, for all INV_SIGMA[]
// values, the corresponding constant in the C code is 1 bit higher than
// here.
const INV_SIGMA: [Flr; 11] = [
    Flr::ZERO,                               // unused
    Flr::scaled(7_961_475_618_707_097, -60), // 0.0069054793295940881528
    Flr::scaled(7_851_656_902_127_320, -60), // 0.0068102267767177965681
    Flr::scaled(7_746_260_754_658_859, -60), // 0.0067188101910722700565
    Flr::scaled(7_595_833_604_889_141, -60), // 0.0065883354370073655600
    Flr::scaled(7_453_842_886_538_220, -60), // 0.0064651781207602890978
    Flr::scaled(7_319_528_409_832_599, -60), // 0.0063486788828078985744
    Flr::scaled(7_192_222_552_237_877, -60), // 0.0062382586529084365056
    Flr::scaled(7_071_336_252_758_509, -60), // 0.0061334065020930252290
    Flr::scaled(6_956_347_512_113_097, -60), // 0.0060336696681577231923
    Flr::scaled(6_846_791_885_593_314, -60), // 0.0059386453095331150985
];
const SIGMA_MIN: [Flr; 11] = [
    Flr::ZERO,                               // unused
    Flr::scaled(5_028_307_297_130_123, -52), // 1.1165085072329102589
    Flr::scaled(5_098_636_688_852_518, -52), // 1.1321247692325272406
    Flr::scaled(5_168_009_084_304_506, -52), // 1.1475285353733668685
    Flr::scaled(5_270_355_833_453_349, -52), // 1.1702540788534828940
    Flr::scaled(5_370_752_584_786_614, -52), // 1.1925466358390344011
    Flr::scaled(5_469_306_724_145_091, -52), // 1.2144300507766139921
    Flr::scaled(5_566_116_128_735_780, -52), // 1.2359260567719808790
    Flr::scaled(5_661_270_305_715_104, -52), // 1.2570545284063214163
    Flr::scaled(5_754_851_361_258_101, -52), // 1.2778336969128335860
    Flr::scaled(5_846_934_829_975_396, -52), // 1.2982803343442918540
];
// Distribution for gaussian0() (this is the RCDT table from the
// specification, expressed in base 2^24).
const GAUSS0: [[u32; 3]; 18] = [
    [10_745_844, 3_068_844, 3_741_698],
    [5_559_083, 1_580_863, 8_248_194],
    [2_260_429, 13_669_192, 2_736_639],
    [708_981, 4_421_575, 10_046_180],
    [169_348, 7_122_675, 4_136_815],
    [30538, 13_063_405, 7_650_655],
    [4132, 14_505_003, 7_826_148],
    [417, 16_768_101, 11_363_290],
    [31, 8_444_042, 8_086_568],
    [1, 12_844_466, 265_321],
    [0, 1_232_676, 13_644_283],
    [0, 38047, 9_111_839],
    [0, 870, 6_138_264],
    [0, 14, 12_545_723],
    [0, 0, 3_104_126],
    [0, 0, 28824],
    [0, 0, 198],
    [0, 0, 1],
];
// log(2)
const LOG2: Flr = Flr::scaled(6_243_314_768_165_359, -53);
// 1/log(2)
const INV_LOG2: Flr = Flr::scaled(6_497_320_848_556_798, -52);
impl<T: PRNG> Sampler<T> {
    pub(crate) fn new(logn: u32, seed: &[u8], total_proposal_budget: u32) -> Self {
        let rng = T::new(seed);
        Self {
            rng,
            logn,
            remaining_proposals: total_proposal_budget,
        }
    }
    // SSE2 variant of next() (for 32-bit x86).
    // Sample the next small integer, using the proper Gaussian
    // distribution with centre mu and inverse of the standard
    // deviation isigma.
    pub(crate) fn next(&mut self, mu: Flr, isigma: Flr) -> Option<i32> {
        // Centre is mu. We split it into s + r, for an integer
        // s, and 0 <= r < 1.
        let centre_floor = mu.floor();
        let residual = mu - Flr::from_i64(centre_floor);
        let centre_floor = read_u32_le(&centre_floor.to_le_bytes(), 0).cast_signed();
        // dss = 1/(2*sigma^2) = 0.5*(isigma^2)
        let dss = isigma.square().half();
        // ccs = sigma_min / sigma = sigma_min * isigma
        let ccs = isigma * SIGMA_MIN[self.logn as usize];
        // We need to sample on centre r.
        for _ in 0..MAX_PROPOSALS_PER_COEFFICIENT {
            self.remaining_proposals = self.remaining_proposals.checked_sub(1)?;
            // Sample z for a Gaussian distribution, then get a random
            // bit b to turn the sampling into a bimodal distribution:
            // if b = 1, we use z+1, otherwise we use -z. We thus have
            // two situations:
            //
            //  - b = 1: z >= 1 and sampled against a Gaussian
            //    distribution centred on 1.
            //  - b = 0: z <= 0 and sampled against a Gaussian
            //    distribution centred on 0.
            let z0 = self.gaussian0();
            let sign_bit = i32::from(self.rng.next_u8()) & 1;
            let proposal = sign_bit + ((sign_bit << 1) - 1) * z0;
            // Rejection sampling. We want a Gaussian centred on r,
            // but we sampled against a bimodal Gaussian (with "centres"
            // at 0 and 1). However, we know that z is always in the
            // range where our sampling distribution is greater than the
            // Gaussian distribution, so rejection works.
            //
            // We got z with distribution:
            //    G(z) = exp(-((z-b)^2)/(2*sigma0^2))
            // We target distribution:
            //    S(z) = exp(-((z-r)^2)/(2*sigma^2))
            // Rejection sampling works by keeping the value z with
            // probability S(z)/G(z), and starting again otherwise.
            // This requires S(z) <= G(z), which is the case here. Thus,
            // we simply need to keep our z with probability:
            //    P = exp(-x)
            // where:
            //    x = ((z-r)^2)/(2*sigma^2) - ((z-b)^2)/(2*sigma0^2)
            //
            // Here, we scale up the Bernouilli distribution, which makes
            // rejection more probable, but also makes the rejection rate
            // sufficiently decorrelated from the Gaussian centre and
            // standard deviation that the measurement of the rejection
            // rate leaks no usable information for attackers (and thus
            // makes the whole sampler nominally "constant-time").
            let mut rejection_exponent =
                (Flr::from_i64(i64::from(proposal)) - residual).square() * dss;
            rejection_exponent -= Flr::from_i64(i64::from(z0 * z0)) * INV_2SQRSIGMA0;
            if self.ber_exp(rejection_exponent, ccs) {
                // Rejection sampling was centred on r, but the actual
                // centre is mu = s + r.
                return Some(centre_floor + proposal);
            }
        }
        None
    }
    // Sample a value from a given half-Gaussian centred on zero; only
    // non-negative values are returned. 72 bits from the random source
    // are used.
    fn gaussian0(&mut self) -> i32 {
        // Get a random 72-bit value, into three 24-bit limbs v0..v2.
        let lo = self.rng.next_u64();
        let hi = self.rng.next_u8();
        let v0 = read_u32_le(&lo.to_le_bytes(), 0) & 0x00FF_FFFF;
        let v1 = read_u32_le(&(lo >> 24).to_le_bytes(), 0) & 0x00FF_FFFF;
        let v2 = ((lo >> 48) as u32) | (u32::from(hi) << 16);
        // Sampled value is z, such that v0..v2 is lower than the first
        // z elements of the table.
        let mut z = 0;
        for threshold in &GAUSS0 {
            let cc = v0.wrapping_sub(threshold[2]) >> 31;
            let cc = v1.wrapping_sub(threshold[1]).wrapping_sub(cc) >> 31;
            let cc = v2.wrapping_sub(threshold[0]).wrapping_sub(cc) >> 31;
            z += cc.cast_signed();
        }
        z
    }
    // Sample a bit with probability ccs*exp(-x) (with x >= 0).
    fn ber_exp(&mut self, exponent: Flr, ccs: Flr) -> bool {
        // Reduce x modulo log(2): x = s*log(2) + r, with s an integer,
        // and 0 <= r < log(2). We can use trunc() because x >= 0
        // (trunc() is presumably a bit faster than floor()).
        let binary_exponent = (exponent * INV_LOG2).trunc();
        let residual = exponent - Flr::from_i64(binary_exponent) * LOG2;
        // If s >= 64, sigma = 1.2, r = 0 and b = 1, then we get s >= 64
        // if the half-Gaussian produced z >= 13, which happens with
        // probability about 2^(-32). When s >= 64, ber_exp() will return
        // true with probability less than 2^(-64), so we can simply
        // saturate s at 63 (i.e. the bias introduced here is lower than
        // 2^(-96) and would require something like 2^192 samplings to
        // be simply detectable in any way, while the number of signatures
        // is bounded at 2^64 and each will involve less than 2^16 calls
        // to ber_exp()).
        let sw = read_u32_le(&binary_exponent.to_le_bytes(), 0);
        let binary_exponent = (sw | (63u32.wrapping_sub(sw) >> 16)) & 63;
        // Compute ccs*exp(-x). Since x = s*log(2) + r, we compute
        // ccs*exp(-r)/2^s. We know that 0 <= r < log(2) at this
        // point, so we can use Flr::expm_p63(), which yields a result
        // scaled by 63 bits. We scale it up 1 bit further (to 64 bits),
        // then right-shift by s bits to account for the division by 2^s.
        //
        // The "-1" operation makes sure that the value fits on 64 bits
        // (i.e. if r = 0 then we may get 2^64 and we prefer 2^64-1 in
        // that case). The bias is neligible since expm_p63() only
        // computes with 51 bits of precision or so.
        //
        // Since the shift is over a 64-bit value and the shift count is
        // nominally secret, we should use a special shift process because
        // some 32-bit architecture employ a non-constant-time routine
        // in that case.
        let probability = residual.expm_p63(ccs);
        // A zero Q63 probability must remain zero: wrapping subtraction would
        // otherwise turn it into MAX. Keep the existing threshold for every
        // positive value, including the 2^63 unit endpoint, without branching.
        let nonzero_mask = ((probability | probability.wrapping_neg()) >> 63).wrapping_neg();
        let threshold = ((probability << 1).wrapping_sub(1)) & nonzero_mask;
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm64ec",
            target_arch = "riscv64"
        ))]
        let threshold = threshold >> binary_exponent;
        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm64ec",
            target_arch = "riscv64"
        )))]
        let threshold = (threshold
            ^ ((threshold ^ (threshold >> 32)) & u64::from(binary_exponent >> 5).wrapping_neg()))
            >> (binary_exponent & 31);
        // Sample a bit with probability ccs*exp(-x). We lazily compare
        // the value z with a uniform 64-bit integer, consuming only as
        // many bytes as necessary. Note that since the PRNG is good
        // (uniform, and information on output bytes cannot be inferred
        // from the value of other output bytes), we leak no more
        // information with lazy comparison than the fact that we already
        // leak or not, i.e. whether the value was rejected or accepted.
        for i in 0..8 {
            let draw = self.rng.next_u8();
            let bz = (threshold >> (56 - (i << 3))).to_le_bytes()[0];
            if draw != bz {
                return draw < bz;
            }
        }
        false
    }
    // Variant of ber_exp() for 32-bit x86 with SSE2.
    // Variant of expm_p63() for 32-bit x86 with SSE2.
    // Fast Fourier Sampling.
    // The target vector is t, provided as two polynomials t0 and t1.
    // The Gram matrix is provided (G = [[g00, g01], [adj(g01), g11]]).
    // The sampled vector is written over (t0,t1) and the Gram matrix
    // is also modified. The temporary buffer (tmp) must have room for
    // four extra polynomials. All polynomials are in FFT representation.
    pub(crate) fn ffsamp_fft(
        &mut self,
        t0: &mut [Flr],
        t1: &mut [Flr],
        g00: &mut [Flr],
        g01: &mut [Flr],
        g11: &mut [Flr],
        tmp: &mut [Flr],
    ) -> bool {
        self.ffsamp_fft_inner(self.logn, t0, t1, GramMatrixMut { g00, g01, g11 }, tmp)
    }
    // Inner function for Fast Fourier Sampling (recursive). The
    // degree at this level is provided as the 'logn' parameter (the
    // overall degree is in self.logn).
    fn ffsamp_fft_inner(
        &mut self,
        logn: u32,
        t0: &mut [Flr],
        t1: &mut [Flr],
        gram: GramMatrixMut<'_>,
        tmp: &mut [Flr],
    ) -> bool {
        let GramMatrixMut { g00, g01, g11 } = gram;
        // When logn = 1, arrays have length 2; we unroll the last steps.
        if logn == 1 {
            // Decompose G into LDL. g00 and g11 are self-adjoint and thus
            // use one coefficient each.
            let g00_re = g00[0];
            let (g01_re, g01_im) = (g01[0], g01[1]);
            let g11_re = g11[0];
            let inv_g00_re = Flr::ONE / g00_re;
            let (mu_re, mu_im) = (g01_re * inv_g00_re, g01_im * inv_g00_re);
            let zo_re = mu_re * g01_re + mu_im * g01_im;
            let d00_re = g00_re;
            let l01_re = mu_re;
            let l01_im = -mu_im;
            let d11_re = g11_re - zo_re;
            // No split on d00 and d11, since they have a single coefficient.
            // The half-size Gram matrices for the recursive LDL tree
            // exploration are now:
            //   - left sub-tree:   d00_re, zero, d00_re
            //   - right sub-tree:  d11_re, zero, d11_re
            // t1 split is trivial, since logn = 1.
            let w0 = t1[0];
            let w1 = t1[1];
            // Recursive call on the two halves, using the right sub-tree.
            let leaf = d11_re.sqrt() * INV_SIGMA[self.logn as usize];
            let Some(y0) = self.next(w0, leaf).map(Flr::from_i32) else {
                return false;
            };
            let Some(y1) = self.next(w1, leaf).map(Flr::from_i32) else {
                return false;
            };
            // Merge is trivial, since logn = 1.
            // At this point:
            //   t0 and t1 are unmodified; t1 is also [w0, w1]
            //   l10 is in [l01_re, l01_im]
            //   z1 is [y0, y1]
            // Compute tb0 = t0 + (t1 - z1)*l10 (into [x0, x1]).
            // z1 is moved into t1.
            let (a_re, a_im) = (w0 - y0, w1 - y1);
            let (b_re, b_im) = flc_mul(a_re, a_im, l01_re, l01_im);
            let (x0, x1) = (t0[0] + b_re, t0[1] + b_im);
            t1[0] = y0;
            t1[1] = y1;
            // Second recursive invocation, on the split tb0, using the
            // left sub-tree. tb0 is [x0, x1] and its split is trivial
            // since logn = 1.
            let leaf = d00_re.sqrt() * INV_SIGMA[self.logn as usize];
            let Some(y0) = self.next(x0, leaf).map(Flr::from_i32) else {
                return false;
            };
            let Some(y1) = self.next(x1, leaf).map(Flr::from_i32) else {
                return false;
            };
            t0[0] = y0;
            t0[1] = y1;
            return true;
        }
        // General case: logn >= 2.
        let n = 1usize << logn;
        let hn = n >> 1;
        // Decompose G into LDL; the decomposed matrix replaces G.
        poly_LDL_fft(logn, &*g00, g01, g11);
        // Split d00 and d11 (currently in g00 and g11) and expand them
        // into half-size quasi-cyclic Gram matrices. We also
        // save l10 (in g01) into tmp.
        if logn > 1 {
            // If n = 2 then the two splits below are no-ops.
            let (w0, w1) = tmp.split_at_mut(hn);
            poly_split_selfadj_fft(logn, w0, w1, &*g00);
            g00[0..hn].copy_from_slice(&w0[0..hn]);
            g00[hn..n].copy_from_slice(&w1[0..hn]);
            poly_split_selfadj_fft(logn, w0, w1, &*g11);
            g11[0..hn].copy_from_slice(&w0[0..hn]);
            g11[hn..n].copy_from_slice(&w1[0..hn]);
        }
        tmp[0..n].copy_from_slice(&g01[0..n]);
        g01[0..hn].copy_from_slice(&g00[0..hn]);
        g01[hn..n].copy_from_slice(&g11[0..hn]);
        // The half-size Gram matrices for the recursive LDL tree
        // exploration are now:
        //   - left sub-tree:   g00[0..hn], g00[hn..n], g01[0..hn]
        //   - right sub-tree:  g11[0..hn], g11[hn..n], g01[hn..n]
        // l10 is in tmp[0..n].
        let (left_00, left_01) = g00.split_at_mut(hn);
        let (right_00, right_01) = g11.split_at_mut(hn);
        let (left_11, right_11) = g01.split_at_mut(hn);
        // We split t1 and use the first recursive call on the two
        // halves, using the right sub-tree. The result is merged
        // back into tmp[2*n..3*n].
        {
            let (_, tmp) = tmp.split_at_mut(n);
            let (w0, tmp) = tmp.split_at_mut(hn);
            let (w1, tmp) = tmp.split_at_mut(hn);
            poly_split_fft(logn, w0, w1, &*t1);
            if !self.ffsamp_fft_inner(
                logn - 1,
                w0,
                w1,
                GramMatrixMut {
                    g00: right_00,
                    g01: right_01,
                    g11: right_11,
                },
                tmp,
            ) {
                return false;
            }
            poly_merge_fft(logn, tmp, &*w0, &*w1);
        }
        // At this point:
        //   t0 and t1 are unmodified
        //   l10 is in tmp[0..n]
        //   z1 is in tmp[2*n..3*n]
        // Compute tb0 = t0 + (t1 - z1)*l10.
        // tb0 is written over t0.
        // z1 is moved into t1.
        // l10 is scratched.
        {
            let (l10, tmp) = tmp.split_at_mut(n);
            let (w, z1) = tmp.split_at_mut(n);
            w[0..n].copy_from_slice(&t1[0..n]);
            poly_sub(logn, w, &*z1);
            t1[0..n].copy_from_slice(&z1[0..n]);
            poly_mul_fft(logn, l10, &*w);
            poly_add(logn, t0, &*l10);
        }
        // Second recursive invocation, on the split tb0 (currently in t0),
        // using the left sub-tree.
        // tmp is free at this point.
        {
            let (w0, tmp) = tmp.split_at_mut(hn);
            let (w1, tmp) = tmp.split_at_mut(hn);
            poly_split_fft(logn, w0, w1, &*t0);
            if !self.ffsamp_fft_inner(
                logn - 1,
                w0,
                w1,
                GramMatrixMut {
                    g00: left_00,
                    g01: left_01,
                    g11: left_11,
                },
                tmp,
            ) {
                return false;
            }
            poly_merge_fft(logn, t0, &*w0, &*w1);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct RejectingPrng;
    impl PRNG for RejectingPrng {
        fn new(_seed: &[u8]) -> Self {
            Self
        }
        fn next_u8(&mut self) -> u8 {
            u8::MAX
        }
        fn next_u16(&mut self) -> u16 {
            u16::MAX
        }
        fn next_u64(&mut self) -> u64 {
            u64::MAX
        }
        fn zeroize(&mut self) {}
    }
    #[test]
    fn one_coefficient_stops_after_exact_public_proposal_cap() {
        let mut sampler = Sampler::<RejectingPrng>::new(9, &[], MAX_PROPOSALS_PER_COEFFICIENT + 1);
        assert!(sampler.next(Flr::ZERO, INV_SIGMA[9]).is_none());
        assert_eq!(sampler.remaining_proposals, 1);
    }
    #[test]
    fn unit_scale_nonzero_residual_does_not_accept_full_range() {
        // 0xC0 as the first random byte is above the threshold for exp(-1/2).
        // The broken unit-factor conversion returned zero; the sampler's
        // wrapping subtraction then produced MAX and incorrectly accepted it.
        struct UpperQuarterPrng;
        impl PRNG for UpperQuarterPrng {
            fn new(_seed: &[u8]) -> Self {
                Self
            }
            fn next_u8(&mut self) -> u8 {
                0xC0
            }
            fn next_u16(&mut self) -> u16 {
                0xC0C0
            }
            fn next_u64(&mut self) -> u64 {
                0xC0C0_C0C0_C0C0_C0C0
            }
            fn zeroize(&mut self) {}
        }
        let mut sampler = Sampler::<UpperQuarterPrng>::new(9, &[], 1);
        assert!(!sampler.ber_exp(Flr::scaled(1, -1), Flr::ONE));
    }

    struct RepeatedBytePrng {
        byte: u8,
    }
    impl PRNG for RepeatedBytePrng {
        fn new(seed: &[u8]) -> Self {
            Self { byte: seed[0] }
        }
        fn next_u8(&mut self) -> u8 {
            self.byte
        }
        fn next_u16(&mut self) -> u16 {
            u16::from_le_bytes([self.byte; 2])
        }
        fn next_u64(&mut self) -> u64 {
            u64::from_le_bytes([self.byte; 8])
        }
        fn zeroize(&mut self) {
            self.byte = 0;
        }
    }

    #[test]
    fn zero_scale_never_accepts_either_zero_sign() {
        for scale in [Flr::ZERO, Flr::from_bits(1u64 << 63)] {
            for residual in [Flr::ZERO, Flr::scaled(1, -1)] {
                for byte in [0, 1, 0xC0, u8::MAX] {
                    let mut sampler = Sampler::<RepeatedBytePrng>::new(9, &[byte], 1);
                    assert!(!sampler.ber_exp(residual, scale));
                }
            }
        }
    }

    #[test]
    fn quantized_zero_probability_never_wraps_to_full_range() {
        // These positive factors are too small to retain one Q63 unit.
        for scale in [Flr::scaled(1, -64), Flr::scaled(1, -476)] {
            for residual in [Flr::ZERO, Flr::scaled(1, -1)] {
                assert_eq!(residual.expm_p63(scale), 0);
                for byte in [0, 1, 0xC0, u8::MAX] {
                    let mut sampler = Sampler::<RepeatedBytePrng>::new(9, &[byte], 1);
                    assert!(!sampler.ber_exp(residual, scale));
                }
            }
        }
    }

    #[test]
    fn smallest_positive_probability_retains_exact_comparison_boundary() {
        // One Q63 unit becomes the existing integer threshold of one. Zero
        // draws remain accepted; any repeated positive byte remains rejected.
        let scale = Flr::scaled(1, -63);
        assert_eq!(Flr::ZERO.expm_p63(scale), 1);
        for byte in [0, 1, 0xC0, u8::MAX] {
            let mut sampler = Sampler::<RepeatedBytePrng>::new(9, &[byte], 1);
            assert_eq!(sampler.ber_exp(Flr::ZERO, scale), byte == 0);
        }
    }

    struct WordDrawPrng {
        low: u64,
        high: u8,
        word_calls: usize,
        byte_calls: usize,
    }
    impl PRNG for WordDrawPrng {
        fn new(seed: &[u8]) -> Self {
            assert_eq!(seed.len(), 9);
            Self {
                low: u64::from_le_bytes(seed[..8].try_into().expect("eight draw bytes")),
                high: seed[8],
                word_calls: 0,
                byte_calls: 0,
            }
        }
        fn next_u8(&mut self) -> u8 {
            self.byte_calls += 1;
            self.high
        }
        fn next_u16(&mut self) -> u16 {
            panic!("half-Gaussian draw uses one word followed by one byte")
        }
        fn next_u64(&mut self) -> u64 {
            assert_eq!(self.byte_calls, 0, "word precedes high byte");
            self.word_calls += 1;
            self.low
        }
        fn zeroize(&mut self) {
            self.low = 0;
            self.high = 0;
        }
    }

    #[test]
    fn half_gaussian_matches_independent_72_bit_thresholds_and_draw_counts() {
        let thresholds: Vec<_> = GAUSS0
            .iter()
            .map(|words| {
                (u128::from(words[0]) << 48) | (u128::from(words[1]) << 24) | u128::from(words[2])
            })
            .collect();
        let mut draws = vec![0, (1_u128 << 72) - 1];
        for &threshold in &thresholds {
            draws.extend([threshold - 1, threshold, threshold + 1]);
        }
        for draw in draws {
            let seed = draw.to_le_bytes();
            let mut sampler = Sampler::<WordDrawPrng>::new(9, &seed[..9], 1);
            let expected = i32::try_from(
                thresholds
                    .iter()
                    .filter(|&&threshold| draw < threshold)
                    .count(),
            )
            .expect("eighteen thresholds");
            assert_eq!(sampler.gaussian0(), expected, "draw={draw}");
            assert_eq!(sampler.rng.word_calls, 1);
            assert_eq!(sampler.rng.byte_calls, 1);
            assert_eq!(sampler.remaining_proposals, 1);
        }
    }

    struct ByteDrawPrng {
        bytes: [u8; 8],
        byte_calls: usize,
        word_calls: usize,
    }
    impl PRNG for ByteDrawPrng {
        fn new(seed: &[u8]) -> Self {
            Self {
                bytes: seed.try_into().expect("eight comparison bytes"),
                byte_calls: 0,
                word_calls: 0,
            }
        }
        fn next_u8(&mut self) -> u8 {
            let byte = self.bytes[self.byte_calls];
            self.byte_calls += 1;
            byte
        }
        fn next_u16(&mut self) -> u16 {
            panic!("sampler uses words and bytes")
        }
        fn next_u64(&mut self) -> u64 {
            self.word_calls += 1;
            u64::MAX
        }
        fn zeroize(&mut self) {
            self.bytes.fill(0);
        }
    }

    #[test]
    fn bernoulli_comparison_preserves_each_byte_boundary_and_lazy_draw_count() {
        for exponent in [0, 1, 8, 31, 32, 55, 56, 63] {
            let scale = Flr::scaled(1, -exponent);
            let probability = 1_u64 << (63 - exponent);
            let threshold = (probability << 1).wrapping_sub(1);
            let mut draws = vec![0, threshold - 1, threshold];
            if let Some(above) = threshold.checked_add(1) {
                draws.push(above);
            }
            let threshold_bytes = threshold.to_be_bytes();
            for draw in draws {
                let bytes = draw.to_be_bytes();
                let mut sampler = Sampler::<ByteDrawPrng>::new(9, &bytes, 1);
                assert_eq!(sampler.ber_exp(Flr::ZERO, scale), draw < threshold);
                let expected_calls = bytes
                    .iter()
                    .zip(threshold_bytes)
                    .position(|(&actual, expected)| actual != expected)
                    .map_or(8, |index| index + 1);
                assert_eq!(sampler.rng.byte_calls, expected_calls);
                assert_eq!(sampler.rng.word_calls, 0);
                assert_eq!(sampler.remaining_proposals, 1);
            }
        }
    }

    #[test]
    fn accepted_proposal_preserves_integer_centre_and_exact_random_draw_order() {
        for centre in [i32::MIN, -1, 0, 1, i32::MAX] {
            // Maximal 72-bit half-Gaussian input yields zero; the sign bit is
            // zero, and the final zero comparison byte accepts this proposal.
            let mut sampler = Sampler::<ByteDrawPrng>::new(9, &[u8::MAX, 0, 0, 0, 0, 0, 0, 0], 2);
            let mean = Flr::from_i32(centre) + Flr::scaled(1, -2);
            assert_eq!(sampler.next(mean, Flr::scaled(3, -2)), Some(centre));
            assert_eq!(sampler.rng.word_calls, 1);
            assert_eq!(sampler.rng.byte_calls, 3);
            assert_eq!(sampler.remaining_proposals, 1);
        }
    }

    #[test]
    fn recursive_zero_budget_preserves_targets_and_all_caller_slice_tails() {
        for logn in [1, 2, 9] {
            let degree = 1_usize << logn;
            let mut target_left = vec![Flr::from_i32(2); degree + 1];
            let mut target_right = vec![Flr::from_i32(-3); degree + 1];
            let mut diagonal_left = vec![Flr::ONE; degree + 1];
            let mut off_diagonal = vec![Flr::ZERO; degree + 1];
            let mut diagonal_right = vec![Flr::ONE; degree + 1];
            diagonal_left[degree] = Flr::from_i32(91);
            off_diagonal[degree] = Flr::from_i32(-93);
            diagonal_right[degree] = Flr::from_i32(95);
            let mut temporary = vec![Flr::ZERO; 4 * degree + 1];
            temporary[4 * degree] = Flr::from_i32(-97);
            let mut sampler = Sampler::<ByteDrawPrng>::new(logn, &[0; 8], 0);
            assert!(!sampler.ffsamp_fft(
                &mut target_left,
                &mut target_right,
                &mut diagonal_left,
                &mut off_diagonal,
                &mut diagonal_right,
                &mut temporary,
            ));
            assert!(target_left.iter().all(|value| value.rint() == 2));
            assert!(target_right.iter().all(|value| value.rint() == -3));
            assert_eq!(diagonal_left[degree].rint(), 91);
            assert_eq!(off_diagonal[degree].rint(), -93);
            assert_eq!(diagonal_right[degree].rint(), 95);
            assert_eq!(temporary[4 * degree].rint(), -97);
            assert_eq!(sampler.rng.byte_calls, 0);
            assert_eq!(sampler.rng.word_calls, 0);
            assert_eq!(sampler.remaining_proposals, 0);
        }
    }
}
