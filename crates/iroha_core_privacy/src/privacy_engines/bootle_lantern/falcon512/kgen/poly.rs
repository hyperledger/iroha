#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
use super::super::table_assets::read_u32_le;
use super::fxp::*;
use super::mp31::*;
use super::zint31::*;
// ========================================================================
// Operations on polynomials modulo X^n+1
// ========================================================================
// Compute the roots for NTT and inverse NTT.
// Inputs:
//    logn   wanted degree (logarithmic, 0 to 10)
//    g      primitive 2048-th root of 1 modulo p (Montgomery representation)
//    ig     inverse of g modulo p (Montgomery representation)
//    p      modulus
//    p0i    -1/p mod 2^32
// Outputs are written into gm[] and igm[]; in both slices, exactly
// n = 2^logn values are written. Output values are in Montgomery
// representation.
pub fn mp_mkgmigm(logn: u32, g: u32, ig: u32, p: u32, p0i: u32, gm: &mut [u32], igm: &mut [u32]) {
    // We want a primitive 2n-th root of 1; we have a primitive 2048-th root
    // of 1, so we must square it a few times if logn < 10.
    let mut g = g;
    let mut ig = ig;
    for _ in logn..10 {
        g = mp_mmul(g, g, p, p0i);
        ig = mp_mmul(ig, ig, p, p0i);
    }
    let k = 10 - logn;
    let mut x1 = mp_R(p);
    let mut x2 = mp_hR(p);
    for i in 0..(1 << logn) {
        let v = REV10[i << k] as usize;
        gm[v] = x1;
        igm[v] = x2;
        x1 = mp_mmul(x1, g, p, p0i);
        x2 = mp_mmul(x2, ig, p, p0i);
    }
}
// Specialized version of mp_mkgmigm() when only the forward values (gm[])
// are needed.
pub fn mp_mkgm(logn: u32, g: u32, p: u32, p0i: u32, gm: &mut [u32]) {
    let mut g = g;
    for _ in logn..10 {
        g = mp_mmul(g, g, p, p0i);
    }
    let k = 10 - logn;
    let mut x1 = mp_R(p);
    for i in 0..(1 << logn) {
        let v = REV10[i << k] as usize;
        gm[v] = x1;
        x1 = mp_mmul(x1, g, p, p0i);
    }
}
// Specialized version of mp_mkgmigm() when only the reverse values (igm[])
// are needed.
pub fn mp_mkigm(logn: u32, ig: u32, p: u32, p0i: u32, igm: &mut [u32]) {
    let mut ig = ig;
    for _ in logn..10 {
        ig = mp_mmul(ig, ig, p, p0i);
    }
    let k = 10 - logn;
    let mut x2 = mp_hR(p);
    for i in 0..(1 << logn) {
        let v = REV10[i << k] as usize;
        igm[v] = x2;
        x2 = mp_mmul(x2, ig, p, p0i);
    }
}
// Apply NTT over a polynomial in GF(p)[X]/(X^n+1). Input coefficients are
// expected in unsigned representation. The polynomial is modified in place.
// The number of coefficients is n = 2^logn, with 0 <= logn <= 10. The gm[]
// table must have been initialized with mp_mkgm() (or mp_mkgmigm()) with
// at least n elements.
pub fn mp_NTT(logn: u32, coefficients: &mut [u32], gm: &[u32], modulus: u32, p0i: u32) {
    if logn == 0 {
        return;
    }
    let mut span = 1 << logn;
    for lm in 0..logn {
        let groups = 1 << lm;
        let ht = span >> 1;
        let mut j0 = 0;
        for i in 0..groups {
            let twiddle = gm[i + groups];
            for j in 0..ht {
                let j1 = j0 + j;
                let j2 = j1 + ht;
                let x1 = coefficients[j1];
                let x2 = mp_mmul(coefficients[j2], twiddle, modulus, p0i);
                coefficients[j1] = mp_add(x1, x2, modulus);
                coefficients[j2] = mp_sub(x1, x2, modulus);
            }
            j0 += span;
        }
        span = ht;
    }
}
// Apply inverse NTT over a polynomial in GF(p)[X]/(X^n+1). Input
// coefficients are expected in unsigned representation. The polynomial is
// modified in place. The number of coefficients is n = 2^logn, with
// 0 <= logn <= 10. The igm[] table must have been initialized with
// mp_mkigm() (or mp_mkgmigm()) with at least n elements.
pub fn mp_iNTT(logn: u32, a: &mut [u32], igm: &[u32], p: u32, p0i: u32) {
    if logn == 0 {
        return;
    }
    let mut t = 1;
    for lm in 0..logn {
        let hm = 1 << (logn - 1 - lm);
        let dt = t << 1;
        let mut j0 = 0;
        for i in 0..hm {
            let s = igm[i + hm];
            for j in 0..t {
                let j1 = j0 + j;
                let j2 = j1 + t;
                let x1 = a[j1];
                let x2 = a[j2];
                a[j1] = mp_half(mp_add(x1, x2, p), p);
                a[j2] = mp_mmul(mp_sub(x1, x2, p), s, p, p0i);
            }
            j0 += dt;
        }
        t = dt;
    }
}
// Set polynomial d to the RNS representation (modulo p) of the polynomial
// with small coefficients f.
pub fn poly_mp_set_small(logn: u32, f: &[i8], p: u32, d: &mut [u32]) {
    for i in 0..(1usize << logn) {
        d[i] = mp_set(i32::from(f[i]), p);
    }
}
// Set polynomial f to its RNS representation (modulo p); the converted
// value overwrites the source. The source is assumed to use signed
// representation.
pub fn poly_mp_set(logn: u32, f: &mut [u32], p: u32) {
    for coefficient in &mut f[..(1usize << logn)] {
        let x = *coefficient;
        *coefficient = mp_set((x | ((x & 0x4000_0000) << 1)).cast_signed(), p);
    }
}
// Convert a polynomial from RNS to plain, signed representation, 1 word
// per coefficient. Note: the returned 32-bit values are NOT truncated to
// 31 bits; they are full-size signed 32-bit values, cast to u32 type.
pub fn poly_mp_norm(logn: u32, f: &mut [u32], p: u32) {
    for coefficient in &mut f[..(1usize << logn)] {
        *coefficient = mp_norm(*coefficient, p).cast_unsigned();
    }
}
// Get the maximum bitlength of the coefficients of the provided polynomial
// (degree 2^logn, coefficients in plain representation, xlen words per
// coefficient).
pub fn poly_max_bitlength(logn: u32, coefficients: &[u32], xlen: usize) -> u32 {
    let degree = 1usize << logn;
    let mut top_word = 0u32;
    let mut tk = 0u32;
    for i in 0..degree {
        // Extend sign bit into a 31-bit mask.
        let sign_mask = (coefficients[i + ((xlen - 1) << logn)] >> 30).wrapping_neg() & 0x7FFF_FFFF;
        // Get top non-zero sign-adjusted word, with index.
        //   c    top non-zero word
        //   ck   index at which c was found
        let mut candidate = 0u32;
        let mut ck = 0u32;
        for j in 0..xlen {
            // Sign-adjust the word.
            let word = coefficients[i + (j << logn)] ^ sign_mask;
            // If the word is non-zero, then update c and ck.
            let nz = (word.wrapping_sub(1) >> 31).wrapping_sub(1);
            candidate ^= nz & (candidate ^ word);
            ck ^= nz & (ck ^ (read_u32_le(&j.to_le_bytes(), 0)));
        }
        // If ck > tk, or ck == tk but c > t, then (c,ck) must replace
        // (t,tk) as current candidate.
        let nz1 = tk.wrapping_sub(ck);
        let nz2 = (tk ^ ck).wrapping_sub(1) & top_word.wrapping_sub(candidate);
        let nz = tbmask(nz1 | nz2);
        top_word ^= nz & (top_word ^ candidate);
        tk ^= nz & (tk ^ ck);
    }
    31 * tk + bitlength(top_word)
}
// Return (q, r) where q = x / 31 and r = x % 31. This function works for
// any integer x up to 63487 (inclusive).
#[inline]
pub const fn divrem31(x: u32) -> (u32, u32) {
    let q = x.wrapping_mul(67651) >> 21;
    let r = x - 31 * q;
    (q, r)
}
// Convert a polynomial to a fixed-point approximation, with scaling.
// Source coefficients of f have length flen words. For each coefficient x,
// the computed approximation is x/2^sc.
//
// This function assumes that |x| < 2^(30+sc). The length of each
// coefficient must be less than 2^16 words.
//
// This function is constant-time with regard to both the coefficient
// contents and the scaling factor sc.
pub fn poly_big_to_fixed(logn: u32, source: &[u32], flen: usize, sc: u32, destination: &mut [Fxr]) {
    let degree = 1usize << logn;
    if flen == 0 {
        destination[..degree].fill(Fxr::ZERO);
        return;
    }
    // We split sc into sch and scl such that:
    //   sc = 31*sch + scl
    // We also want scl in the 1..31 range, not 0..30. If sc == 0, then
    // this will imply that sch "wraps around" to 2^32-1, which is harmless.
    let (mut sch, mut scl) = divrem31(sc);
    let selector = scl.wrapping_sub(1) >> 5;
    sch = sch.wrapping_sub(selector & 1);
    scl |= selector & 31;
    // For each coefficient, we want three words, each with a given left
    // shift (negative for a right shift):
    //    sch-1   1 - scl
    //    sch     32 - scl
    //    sch+1   63 - scl
    let t0 = sch.wrapping_sub(1) & 0xFFFF;
    let t1 = sch & 0xFFFF;
    let t2 = sch.wrapping_add(1) & 0xFFFF;
    for i in 0..degree {
        // Get the relevant upper words.
        let mut w0 = 0u32;
        let mut w1 = 0u32;
        let mut w2 = 0u32;
        for j in 0..flen {
            let word = source[i + (j << logn)];
            let selector = read_u32_le(&j.to_le_bytes(), 0);
            w0 |= word & (((selector ^ t0).wrapping_sub(1).cast_signed() >> 16).cast_unsigned());
            w1 |= word & (((selector ^ t1).wrapping_sub(1).cast_signed() >> 16).cast_unsigned());
            w2 |= word & (((selector ^ t2).wrapping_sub(1).cast_signed() >> 16).cast_unsigned());
        }
        // If there are not enough words for the requested scaling, then
        // we must supply copies with the proper sign.
        let ws = (source[i + ((flen - 1) << logn)] >> 30).wrapping_neg() >> 1;
        let ff = read_u32_le(&flen.to_le_bytes(), 0)
            .wrapping_sub(sch)
            .cast_signed();
        w0 |= ws & (ff >> 31).cast_unsigned();
        w1 |= ws & (ff.wrapping_sub(1) >> 31).cast_unsigned();
        w2 |= ws & (ff.wrapping_sub(2) >> 31).cast_unsigned();
        // Assemble the 64-bit value with the shifts. We assume that
        // shifts on 32-bit values are constant-time with regard to
        // the shift count (the last notable architecture on which this
        // was not true was the Willamette and Northwood cores in the
        // Pentium IV).
        w2 |= (w2 & 0x4000_0000) << 1;
        let xl = (w0 >> (scl - 1)) | (w1 << (32 - scl));
        let xh = (w1 >> scl) | (w2 << (31 - scl));
        destination[i] = Fxr::from_u64_scaled32(u64::from(xl) | (u64::from(xh) << 32));
    }
}
// Subtract f*k*2^scale_k from F. Coefficients of F and f use Flen and flen
// words, respectively, and are in plain signed representation. Coefficients
// from k are signed 32-bit integers (provided in u32 slots).
pub fn poly_sub_scaled(
    logn: u32,
    F: &mut [u32],
    Flen: usize,
    f: &[u32],
    flen: usize,
    k: &[u32],
    sc: u32,
) {
    if flen == 0 {
        return;
    }
    let (sch, scl) = divrem31(sc);
    if (sch as usize) >= Flen {
        return;
    }
    let flen = core::cmp::min(flen, Flen - (sch as usize));
    // TODO: optimize cases with logn <= 3
    let n = 1usize << logn;
    for i in 0..n {
        let kf = k[i].wrapping_neg().cast_signed();
        for j in i..n {
            zint_add_scaled_mul_small(
                &mut F[j..],
                Flen,
                &f[(j - i)..],
                flen,
                n,
                kf,
                ZintShift {
                    words: sch,
                    bits: scl,
                },
            );
        }
        let kf = kf.wrapping_neg();
        for j in 0..i {
            zint_add_scaled_mul_small(
                &mut F[j..],
                Flen,
                &f[((j + n) - i)..],
                flen,
                n,
                kf,
                ZintShift {
                    words: sch,
                    bits: scl,
                },
            );
        }
    }
}
/// A borrowed polynomial with signed 31-bit coefficients interleaved by degree.
pub struct LimbPolynomialMut<'a> {
    /// Original mutable coefficient storage; no allocation or copy is owned here.
    pub coefficients: &'a mut [u32],
    /// Number of 31-bit words per coefficient.
    pub words: usize,
}
/// The borrowed pair of NTRU solution polynomials with a shared limb width.
pub struct NtruSolutionMut<'a> {
    /// Original storage for the first solution polynomial.
    pub first: &'a mut [u32],
    /// Original storage for the second solution polynomial.
    pub second: &'a mut [u32],
    /// Number of 31-bit words per coefficient in either polynomial.
    pub words: usize,
}
// Subtract f*k*2^scale_k from F. This is similar to poly_sub_scaled(),
// except that:
//   - f is in RNS+NTT, and over flen+1 words (even though the plain
//     representation was over flen words).
//   - An extra temporary array is provided, with at least n*(flen+4) free
//     words.
// The multiplication f*k is internally computed using the NTT; this is
// faster at large degree.
// The value of logn MUST be at least 3.
pub fn poly_sub_scaled_ntt(
    logn: u32,
    destination: LimbPolynomialMut<'_>,
    f: &[u32],
    flen: usize,
    k: &[u32],
    sc: u32,
    tmp: &mut [u32],
) {
    let LimbPolynomialMut {
        coefficients: F,
        words: Flen,
    } = destination;
    assert!(logn >= 3);
    let n = 1usize << logn;
    let tlen = flen + 1;
    // Compute k*f into a temporary area in RNS format, flen+1 words.
    let (gm, work) = tmp.split_at_mut(n);
    let (igm, work) = work.split_at_mut(n);
    let (fk, t1) = work.split_at_mut(tlen * n);
    for i in 0..tlen {
        let p = PRIMES[i].p;
        let p0i = PRIMES[i].p0i;
        let R2 = PRIMES[i].R2;
        mp_mkgmigm(logn, PRIMES[i].g, PRIMES[i].ig, p, p0i, gm, igm);
        for j in 0..n {
            t1[j] = mp_set(k[j].cast_signed(), p);
        }
        mp_NTT(logn, t1, gm, p, p0i);
        let fs = &f[(i << logn)..];
        let ff = &mut fk[(i << logn)..];
        for j in 0..n {
            ff[j] = mp_mmul(mp_mmul(t1[j], fs[j], p, p0i), R2, p, p0i);
        }
        mp_iNTT(logn, ff, igm, p, p0i);
    }
    // Rebuild k*f in plain representation.
    zint_rebuild_CRT(fk, tlen, n, 1, true, t1);
    // Subtract k*f, with scaling, from F.
    let (sch, scl) = divrem31(sc);
    for i in 0..n {
        zint_sub_scaled(
            &mut F[i..],
            Flen,
            &fk[i..],
            tlen,
            n,
            ZintShift {
                words: sch,
                bits: scl,
            },
        );
    }
}
// Subtract (k*2^scale_k_*(f,g) from (F,G). This is a specialized function
// for NTRU solving at depth 1, because we really want to use the NTT (degree
// is large) but we do not have enough room in our buffers to keep (f,g)
// in RNS+NTT modulo enough primes. Instead, we recompute them dynamically
// here.
pub fn poly_sub_kfg_scaled_depth1(
    logn_top: u32,
    solution: NtruSolutionMut<'_>,
    multiplier: &mut [u32],
    sc: u32,
    source_left: &[i8],
    source_right: &[i8],
    tmp: &mut [u32],
) {
    let NtruSolutionMut {
        first: target_left,
        second: target_right,
        words: FGlen,
    } = solution;
    let logn = logn_top - 1;
    let degree = 1usize << logn;
    let hn = degree >> 1;
    let (gm, tmp) = tmp.split_at_mut(degree);
    let (t1, t2) = tmp.split_at_mut(degree);
    // Convert F and G to RNS. Normally, FGlen is equal to 2; the code
    // below also covers the case FGlen = 1, which could be used in some
    // algorithms leveraging the same kind of NTRU lattice.
    if FGlen == 1 {
        let modulus = PRIMES[0].p;
        for i in 0..degree {
            let xf = target_left[i];
            let xg = target_right[i];
            let xf = xf | ((xf & 0x4000_0000) << 1);
            let xg = xg | ((xg & 0x4000_0000) << 1);
            target_left[i] = mp_set(xf.cast_signed(), modulus);
            target_right[i] = mp_set(xg.cast_signed(), modulus);
        }
    } else {
        assert!(FGlen == 2);
        let p0 = PRIMES[0].p;
        let p0_0i = PRIMES[0].p0i;
        let z0 = mp_half(PRIMES[0].R2, p0);
        let p1 = PRIMES[1].p;
        let p1_0i = PRIMES[1].p0i;
        let z1 = mp_half(PRIMES[1].R2, p1);
        for i in 0..degree {
            let xl = target_left[i];
            let xh = target_left[i + degree] | ((target_left[i + degree] & 0x4000_0000) << 1);
            let yl0 = mp_set_u(xl, p0);
            let yh0 = mp_set(xh.cast_signed(), p0);
            let r0 = mp_add(yl0, mp_mmul(yh0, z0, p0, p0_0i), p0);
            let yl1 = mp_set_u(xl, p1);
            let yh1 = mp_set(xh.cast_signed(), p1);
            let r1 = mp_add(yl1, mp_mmul(yh1, z1, p1, p1_0i), p1);
            target_left[i] = r0;
            target_left[i + degree] = r1;
            let xl = target_right[i];
            let xh = target_right[i + degree] | ((target_right[i + degree] & 0x4000_0000) << 1);
            let yl0 = mp_set_u(xl, p0);
            let yh0 = mp_set(xh.cast_signed(), p0);
            let r0 = mp_add(yl0, mp_mmul(yh0, z0, p0, p0_0i), p0);
            let yl1 = mp_set_u(xl, p1);
            let yh1 = mp_set(xh.cast_signed(), p1);
            let r1 = mp_add(yl1, mp_mmul(yh1, z1, p1, p1_0i), p1);
            target_right[i] = r0;
            target_right[i + degree] = r1;
        }
    }
    // For FGlen small primes, convert F and G to RNS+NTT, and subtract
    // (2^sc)*(ft,gt). ft and gt are computed dynamically from the
    // top-level (f,g).
    for i in 0..FGlen {
        let modulus = PRIMES[i].p;
        let p0i = PRIMES[i].p0i;
        let R2 = PRIMES[i].R2;
        let R3 = mp_mmul(R2, R2, modulus, p0i);
        mp_mkgm(logn, PRIMES[i].g, modulus, p0i, gm);
        // k <- (2^sc)*k (and into NTT).
        // We modify k in place because we do not have enough room to make
        // a copy.
        let mut scv = mp_mmul(1u32 << (sc & 31), R2, modulus, p0i);
        for _ in 0..(sc >> 5) {
            scv = mp_mmul(scv, R2, modulus, p0i);
        }
        for coefficient in &mut multiplier[..degree] {
            let residue = mp_set(coefficient.cast_signed(), modulus);
            *coefficient = mp_mmul(scv, residue, modulus, p0i);
        }
        mp_NTT(logn, multiplier, gm, modulus, p0i);
        // Convert F and G to NTT.
        let Fu = &mut target_left[(i << logn)..];
        let Gu = &mut target_right[(i << logn)..];
        mp_NTT(logn, Fu, gm, modulus, p0i);
        mp_NTT(logn, Gu, gm, modulus, p0i);
        // Given the top-level f, we obtain ft = N(f) with:
        //    f = f_e(X^2) + X*f_o(X^2)
        // with f_e and f_o being modulo X^n+1 (with n = 2^logn) while
        // f is modulo X^(2*n)+1 (with 2*n = 2^logn_top). Then:
        //    N(f) = f_e^2 - X*f_o^2
        // The NTT representation of X is obtained from the gm[] tab:
        //    NTT(X)[2*j + 0] = gm[j + n/2]
        //    NTT(X)[2*j + 1] = -NTT(X)[2*j + 0]
        // Note: the values in gm[] are in Montgomery representation.
        for j in 0..degree {
            t1[j] = mp_set(i32::from(source_left[j << 1]), modulus);
            t2[j] = mp_set(i32::from(source_left[(j << 1) + 1]), modulus);
        }
        mp_NTT(logn, t1, gm, modulus, p0i);
        mp_NTT(logn, t2, gm, modulus, p0i);
        for j in 0..hn {
            let xe0 = t1[j << 1];
            let xe1 = t1[(j << 1) + 1];
            let xo0 = t2[j << 1];
            let xo1 = t2[(j << 1) + 1];
            let xv0 = gm[j + hn];
            let xv1 = modulus - xv0; // values in gm[] are non-zero
            let xe0 = mp_mmul(xe0, xe0, modulus, p0i);
            let xe1 = mp_mmul(xe1, xe1, modulus, p0i);
            let xo0 = mp_mmul(xo0, xo0, modulus, p0i);
            let xo1 = mp_mmul(xo1, xo1, modulus, p0i);
            let xf0 = mp_sub(xe0, mp_mmul(xo0, xv0, modulus, p0i), modulus);
            let xf1 = mp_sub(xe1, mp_mmul(xo1, xv1, modulus, p0i), modulus);
            let product_left_even = mp_mmul(
                mp_mmul(xf0, multiplier[j << 1], modulus, p0i),
                R3,
                modulus,
                p0i,
            );
            let product_left_odd = mp_mmul(
                mp_mmul(xf1, multiplier[(j << 1) + 1], modulus, p0i),
                R3,
                modulus,
                p0i,
            );
            Fu[j << 1] = mp_sub(Fu[j << 1], product_left_even, modulus);
            Fu[(j << 1) + 1] = mp_sub(Fu[(j << 1) + 1], product_left_odd, modulus);
        }
        // Same treatment for G and gt.
        for j in 0..degree {
            t1[j] = mp_set(i32::from(source_right[j << 1]), modulus);
            t2[j] = mp_set(i32::from(source_right[(j << 1) + 1]), modulus);
        }
        mp_NTT(logn, t1, gm, modulus, p0i);
        mp_NTT(logn, t2, gm, modulus, p0i);
        for j in 0..hn {
            let xe0 = t1[j << 1];
            let xe1 = t1[(j << 1) + 1];
            let xo0 = t2[j << 1];
            let xo1 = t2[(j << 1) + 1];
            let xv0 = gm[j + hn];
            let xv1 = modulus - xv0; // values in gm[] are non-zero
            let xe0 = mp_mmul(xe0, xe0, modulus, p0i);
            let xe1 = mp_mmul(xe1, xe1, modulus, p0i);
            let xo0 = mp_mmul(xo0, xo0, modulus, p0i);
            let xo1 = mp_mmul(xo1, xo1, modulus, p0i);
            let xg0 = mp_sub(xe0, mp_mmul(xo0, xv0, modulus, p0i), modulus);
            let xg1 = mp_sub(xe1, mp_mmul(xo1, xv1, modulus, p0i), modulus);
            let product_right_even = mp_mmul(
                mp_mmul(xg0, multiplier[j << 1], modulus, p0i),
                R3,
                modulus,
                p0i,
            );
            let product_right_odd = mp_mmul(
                mp_mmul(xg1, multiplier[(j << 1) + 1], modulus, p0i),
                R3,
                modulus,
                p0i,
            );
            Gu[j << 1] = mp_sub(Gu[j << 1], product_right_even, modulus);
            Gu[(j << 1) + 1] = mp_sub(Gu[(j << 1) + 1], product_right_odd, modulus);
        }
        // Convert back F and G to RNS.
        mp_mkigm(logn, PRIMES[i].ig, modulus, p0i, t1);
        mp_iNTT(logn, Fu, t1, modulus, p0i);
        mp_iNTT(logn, Gu, t1, modulus, p0i);
        // We replaced k (plain 32-bit) with (2^sc)*k (NTT); we must
        // put it back to its initial value for the next iteration.
        if (i + 1) < FGlen {
            mp_iNTT(logn, multiplier, t1, modulus, p0i);
            scv = 1u32 << (sc.wrapping_neg() & 31);
            // This inverse scale is in Montgomery representation. A zero
            // residual shift needs R, not the ordinary integer one.
            let zero_residual_mask = ((sc & 31).wrapping_sub(1) >> 31).wrapping_neg();
            scv ^= (scv ^ mp_R(modulus)) & zero_residual_mask;
            for _ in 0..(sc >> 5) {
                scv = mp_mmul(scv, 1, modulus, p0i);
            }
            for coefficient in &mut multiplier[..degree] {
                *coefficient =
                    mp_norm(mp_mmul(scv, *coefficient, modulus, p0i), modulus).cast_unsigned();
            }
        }
    }
    // F and G are in RNS (non-NTT), but we want plain integers.
    if FGlen == 1 {
        let modulus = PRIMES[0].p;
        for i in 0..degree {
            target_left[i] = mp_norm(target_left[i], modulus).cast_unsigned() & 0x7FFF_FFFF;
            target_right[i] = mp_norm(target_right[i], modulus).cast_unsigned() & 0x7FFF_FFFF;
        }
    } else {
        let p0 = PRIMES[0].p;
        let p1 = PRIMES[1].p;
        let p1_0i = PRIMES[1].p0i;
        let crt_inverse = PRIMES[1].s;
        let pp = u64::from(p0) * u64::from(p1);
        let hpp = pp >> 1;
        for i in 0..degree {
            let x0 = target_left[i];
            let x1 = target_left[i + degree];
            let x0m1 = x0.wrapping_sub(p1 & !tbmask(x0.wrapping_sub(p1)));
            let correction = mp_mmul(mp_sub(x1, x0m1, p1), crt_inverse, p1, p1_0i);
            let reconstructed = u64::from(x0) + u64::from(p0) * u64::from(correction);
            let reconstructed = reconstructed
                .wrapping_sub(pp & (hpp.wrapping_sub(reconstructed) >> 63).wrapping_neg());
            target_left[i] = read_u32_le(&reconstructed.to_le_bytes(), 0) & 0x7FFF_FFFF;
            target_left[i + degree] =
                read_u32_le(&(reconstructed >> 31).to_le_bytes(), 0) & 0x7FFF_FFFF;
        }
        for i in 0..degree {
            let x0 = target_right[i];
            let x1 = target_right[i + degree];
            let x0m1 = x0.wrapping_sub(p1 & !tbmask(x0.wrapping_sub(p1)));
            let correction = mp_mmul(mp_sub(x1, x0m1, p1), crt_inverse, p1, p1_0i);
            let reconstructed = u64::from(x0) + u64::from(p0) * u64::from(correction);
            let reconstructed = reconstructed
                .wrapping_sub(pp & (hpp.wrapping_sub(reconstructed) >> 63).wrapping_neg());
            target_right[i] = read_u32_le(&reconstructed.to_le_bytes(), 0) & 0x7FFF_FFFF;
            target_right[i + degree] =
                read_u32_le(&(reconstructed >> 31).to_le_bytes(), 0) & 0x7FFF_FFFF;
        }
    }
}

#[cfg(test)]
mod polynomial_tests {
    use super::*;

    const RADIX: i128 = 1 << 31;

    fn encode(coefficients: &[i128], words: usize) -> Vec<u32> {
        let degree = coefficients.len();
        let mut limbs = vec![0; degree * words];
        for (index, &value) in coefficients.iter().enumerate() {
            let mut quotient = value;
            for word in 0..words {
                limbs[index + word * degree] =
                    u32::try_from(quotient.rem_euclid(RADIX)).expect("31-bit limb");
                quotient = quotient.div_euclid(RADIX);
            }
        }
        limbs
    }

    fn decode(limbs: &[u32], degree: usize, words: usize) -> Vec<i128> {
        let modulus = RADIX.pow(u32::try_from(words).expect("small fixture width"));
        (0..degree)
            .map(|index| {
                let mut value = 0;
                for word in (0..words).rev() {
                    let limb = limbs[index + word * degree];
                    assert!(limb < 1 << 31);
                    value = value * RADIX + i128::from(limb);
                }
                if value >= modulus / 2 {
                    value - modulus
                } else {
                    value
                }
            })
            .collect()
    }

    fn convolution(left: &[i128], right: &[i128]) -> Vec<i128> {
        assert_eq!(left.len(), right.len());
        let degree = left.len();
        let mut result = vec![0; degree];
        for (left_index, &left_value) in left.iter().enumerate() {
            for (right_index, &right_value) in right.iter().enumerate() {
                let index = left_index + right_index;
                let product = left_value * right_value;
                if index < degree {
                    result[index] += product;
                } else {
                    result[index - degree] -= product;
                }
            }
        }
        result
    }

    fn norm(source: &[i8]) -> Vec<i128> {
        let even: Vec<_> = source
            .iter()
            .step_by(2)
            .map(|&value| i128::from(value))
            .collect();
        let odd: Vec<_> = source
            .iter()
            .skip(1)
            .step_by(2)
            .map(|&value| i128::from(value))
            .collect();
        let mut result = convolution(&even, &even);
        let odd_square = convolution(&odd, &odd);
        result[0] += odd_square[odd_square.len() - 1];
        for index in 1..result.len() {
            result[index] -= odd_square[index - 1];
        }
        result
    }

    fn power(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
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

    #[test]
    fn ntt_evaluations_and_products_match_independent_negacyclic_arithmetic() {
        for prime in &PRIMES[..2] {
            let modulus = u64::from(prime.p);
            let inverse_radix = power((1u64 << 32) % modulus, modulus - 2, modulus);
            let primitive_root = u64::from(prime.g) * inverse_radix % modulus;
            for logn in 0..=5 {
                let degree = 1usize << logn;
                let mut forward = vec![0; degree];
                let mut reverse = vec![0; degree];
                mp_mkgmigm(
                    logn,
                    prime.g,
                    prime.ig,
                    prime.p,
                    prime.p0i,
                    &mut forward,
                    &mut reverse,
                );
                let mut single = vec![0; degree];
                mp_mkgm(logn, prime.g, prime.p, prime.p0i, &mut single);
                assert_eq!(single, forward);
                mp_mkigm(logn, prime.ig, prime.p, prime.p0i, &mut single);
                assert_eq!(single, reverse);
                let source: Vec<_> = (0..degree)
                    .map(|index| i128::try_from(index % 7).expect("small index") - 3)
                    .collect();
                let mut transformed: Vec<_> = source
                    .iter()
                    .map(|value| {
                        u32::try_from(value.rem_euclid(i128::from(prime.p))).expect("residue")
                    })
                    .collect();
                mp_NTT(logn, &mut transformed, &forward, prime.p, prime.p0i);
                let root = power(primitive_root, 1 << (10 - logn), modulus);
                for (index, &actual) in transformed.iter().enumerate() {
                    let reversed =
                        (0..logn).fold(0usize, |bits, shift| (bits << 1) | ((index >> shift) & 1));
                    let evaluation_point = power(
                        root,
                        u64::try_from(2 * reversed + 1).expect("small exponent"),
                        modulus,
                    );
                    let expected = source.iter().rev().fold(0i128, |value, coefficient| {
                        (value * i128::from(evaluation_point) + coefficient)
                            .rem_euclid(i128::from(prime.p))
                    });
                    assert_eq!(i128::from(actual), expected);
                }
                let mut squared: Vec<_> = transformed
                    .iter()
                    .map(|&value| {
                        u32::try_from(u64::from(value) * u64::from(value) % modulus)
                            .expect("residue")
                    })
                    .collect();
                mp_iNTT(logn, &mut squared, &reverse, prime.p, prime.p0i);
                for (actual, expected) in squared.iter().zip(convolution(&source, &source)) {
                    assert_eq!(
                        i128::from(*actual),
                        expected.rem_euclid(i128::from(prime.p))
                    );
                }
                mp_iNTT(logn, &mut transformed, &reverse, prime.p, prime.p0i);
                for (actual, expected) in transformed.iter().zip(&source) {
                    assert_eq!(
                        i128::from(*actual),
                        expected.rem_euclid(i128::from(prime.p))
                    );
                }
            }
        }
    }

    #[test]
    fn signed_limb_residues_and_maximum_bitlength_match_integer_oracles() {
        let values = [-RADIX / 2, -1, 0, RADIX / 2 - 1];
        for prime in &PRIMES[..2] {
            let mut limbs = encode(&values, 1);
            limbs.push(0xA55A_1234);
            poly_mp_set(2, &mut limbs, prime.p);
            for (actual, expected) in limbs[..4].iter().zip(values) {
                assert_eq!(
                    i128::from(*actual),
                    expected.rem_euclid(i128::from(prime.p))
                );
            }
            poly_mp_norm(2, &mut limbs, prime.p);
            for (actual, original) in limbs[..4].iter().zip(values) {
                let residue = original.rem_euclid(i128::from(prime.p));
                let expected = if residue > i128::from(prime.p / 2) {
                    residue - i128::from(prime.p)
                } else {
                    residue
                };
                assert_eq!(i128::from(actual.cast_signed()), expected);
            }
            assert_eq!(limbs[4], 0xA55A_1234);
        }
        for values in [
            [0, -1, 0, -1],
            [RADIX - 1, -RADIX, RADIX, -RADIX - 1],
            [(1i128 << 92) - 1, -(1i128 << 92), 1, -2],
        ] {
            let expected = values
                .iter()
                .map(|&value| {
                    let magnitude = u128::try_from(if value < 0 { !value } else { value })
                        .expect("nonnegative sign-adjusted magnitude");
                    128 - magnitude.leading_zeros()
                })
                .max()
                .expect("nonempty coefficients");
            assert_eq!(poly_max_bitlength(2, &encode(&values, 3), 3), expected);
        }
    }

    #[test]
    fn fixed_point_extraction_preserves_signed_floor_at_limb_boundaries() {
        for scaling in [0u32, 1, 30, 31, 32, 61, 62, 63, 92, 93, 127, 128, 63_487] {
            let magnitude = (1i128 << (29 + scaling).min(92)) - 1;
            let values = [magnitude, -magnitude, 1, -1];
            let mut fixed = vec![Fxr::from_i32(7); 5];
            poly_big_to_fixed(2, &encode(&values, 3), 3, scaling, &mut fixed);
            for (actual, value) in fixed[..4].iter().zip(values) {
                let numerator = value * (1i128 << 32);
                let expected = if scaling >= 127 {
                    i128::from(numerator < 0).wrapping_neg()
                } else {
                    numerator.div_euclid(1i128 << scaling)
                };
                assert_eq!(
                    actual.0,
                    u64::try_from(expected.rem_euclid(1i128 << 64))
                        .expect("64-bit fixed representation")
                );
            }
            assert_eq!(fixed[4], Fxr::from_i32(7));
        }
        let mut empty_source = [Fxr::from_i32(7); 5];
        poly_big_to_fixed(2, &[], 0, 0, &mut empty_source);
        assert_eq!(&empty_source[..4], &[Fxr::ZERO; 4]);
        assert_eq!(empty_source[4], Fxr::from_i32(7));
        for value in 0..=63_487 {
            assert_eq!(divrem31(value), (value / 31, value % 31));
        }
    }

    #[test]
    fn plain_and_ntt_scaled_subtraction_match_signed_integer_convolution() {
        let logn = 3;
        let degree = 1usize << logn;
        let source = [-3, 2, -1, 0, 1, -2, 3, 1];
        let multiplier = [1, -2, 0, 3, -1, 1 << 20, -(1 << 20), 2];
        let original = [1 << 45, -(1 << 45), 0, -1, 1, 1 << 30, -(1 << 30), 7];
        let product = convolution(&source, &multiplier);
        let multiplier_bits: Vec<_> = multiplier
            .iter()
            .map(|&value| {
                i32::try_from(value)
                    .expect("signed multiplier")
                    .cast_unsigned()
            })
            .collect();
        let mut rns = vec![0; 2 * degree];
        for (index, prime) in PRIMES[..2].iter().enumerate() {
            let mut forward = vec![0; degree];
            mp_mkgm(logn, prime.g, prime.p, prime.p0i, &mut forward);
            for (slot, value) in rns[index * degree..(index + 1) * degree]
                .iter_mut()
                .zip(source)
            {
                *slot = u32::try_from(value.rem_euclid(i128::from(prime.p))).expect("residue");
            }
            mp_NTT(
                logn,
                &mut rns[index * degree..(index + 1) * degree],
                &forward,
                prime.p,
                prime.p0i,
            );
        }
        let modulus = RADIX.pow(3);
        for scaling in [0, 1, 30, 31, 32, 62, 93] {
            let mut plain = encode(&original, 3);
            poly_sub_scaled(
                logn,
                &mut plain,
                3,
                &encode(&source, 1),
                1,
                &multiplier_bits,
                scaling,
            );
            let mut transformed = encode(&original, 3);
            poly_sub_scaled_ntt(
                logn,
                LimbPolynomialMut {
                    coefficients: &mut transformed,
                    words: 3,
                },
                &rns,
                1,
                &multiplier_bits,
                scaling,
                &mut vec![0; 5 * degree],
            );
            let expected: Vec<_> = original
                .iter()
                .zip(&product)
                .map(|(&value, &delta)| {
                    let residue = (value - delta * (1i128 << scaling)).rem_euclid(modulus);
                    if residue >= modulus / 2 {
                        residue - modulus
                    } else {
                        residue
                    }
                })
                .collect();
            assert_eq!(decode(&plain, degree, 3), expected);
            assert_eq!(decode(&transformed, degree, 3), expected);
        }
    }

    #[test]
    fn depth_one_nonzero_residual_scales_match_independent_polynomial_norms() {
        let source_left = [1i8, -2, 3, 0, -1, 2, -3, 1, 2, 1, 0, -2, 3, -1, 1, 2];
        let source_right = [-2i8, 1, 0, 3, 2, -1, 1, -3, 0, 2, -2, 1, 1, 0, -1, 3];
        let multiplier = [1, -2, 0, 3, -1, 1, -3, 2];
        let original_left = [100, -200, 0, 1, -1, 50, -60, 70];
        let original_right = [-80, 90, 0, -1, 1, -40, 30, -20];
        let left_product = convolution(&norm(&source_left), &multiplier);
        let right_product = convolution(&norm(&source_right), &multiplier);
        for words in [1, 2] {
            for scaling in [1, 3, 10] {
                let mut first = encode(&original_left, words);
                let mut second = encode(&original_right, words);
                let mut scratch_multiplier: Vec<_> = multiplier
                    .iter()
                    .map(|&value| {
                        i32::try_from(value)
                            .expect("small multiplier")
                            .cast_unsigned()
                    })
                    .collect();
                poly_sub_kfg_scaled_depth1(
                    4,
                    NtruSolutionMut {
                        first: &mut first,
                        second: &mut second,
                        words,
                    },
                    &mut scratch_multiplier,
                    scaling,
                    &source_left,
                    &source_right,
                    &mut [0; 24],
                );
                let expected_left: Vec<_> = original_left
                    .iter()
                    .zip(&left_product)
                    .map(|(&value, &delta)| value - delta * (1i128 << scaling))
                    .collect();
                let expected_right: Vec<_> = original_right
                    .iter()
                    .zip(&right_product)
                    .map(|(&value, &delta)| value - delta * (1i128 << scaling))
                    .collect();
                assert_eq!(decode(&first, 8, words), expected_left);
                assert_eq!(decode(&second, 8, words), expected_right);
            }
        }
    }
}

#[cfg(test)]
mod restoration_tests {
    use super::super::super::LOG_DEGREE;
    use super::*;

    fn constant_norm_update_matches_exact_integer_result(scaling: u32) {
        let degree = 1usize << (LOG_DEGREE - 1);
        let mut source_left = vec![0i8; 2 * degree];
        let mut source_right = vec![0i8; 2 * degree];
        source_left[0] = 1;
        source_right[0] = 2;
        let mut multiplier = vec![0; degree];
        multiplier[0] = 1;
        let mut first = vec![0; 2 * degree];
        let mut second = vec![0; 2 * degree];
        let scale = 1i128 << scaling;
        let crt_product = i128::from(PRIMES[0].p) * i128::from(PRIMES[1].p);
        assert!(
            4 * scale < crt_product / 2,
            "expected results must fit the centered CRT interval"
        );
        poly_sub_kfg_scaled_depth1(
            LOG_DEGREE,
            NtruSolutionMut {
                first: &mut first,
                second: &mut second,
                words: 2,
            },
            &mut multiplier,
            scaling,
            &source_left,
            &source_right,
            &mut vec![0; 3 * degree],
        );
        // N(1) = 1 and N(2) = 4. Multiplication by the constant polynomial
        // k = 1 therefore changes only the constant coefficients.
        for (actual, constant) in [(&first, -scale), (&second, -4 * scale)] {
            let encoded = constant.rem_euclid(1i128 << 62);
            let mut expected = vec![0; 2 * degree];
            expected[0] = u32::try_from(encoded % (1i128 << 31)).expect("31-bit low limb");
            expected[degree] = u32::try_from(encoded / (1i128 << 31)).expect("31-bit high limb");
            assert_eq!(
                actual, &expected,
                "scale {scaling} must preserve the multiplier across prime passes"
            );
        }
    }

    #[test]
    fn depth_one_zero_scale_preserves_multiplier_between_two_prime_passes() {
        constant_norm_update_matches_exact_integer_result(0);
    }

    #[test]
    fn depth_one_word_scale_preserves_multiplier_between_two_prime_passes() {
        constant_norm_update_matches_exact_integer_result(32);
    }

    #[test]
    fn depth_one_nonmultiple_scale_preserves_existing_restoration() {
        for scaling in [1, 31, 33] {
            constant_norm_update_matches_exact_integer_result(scaling);
        }
    }
}
