#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
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
pub(crate) fn mp_mkgmigm(
    logn: u32,
    g: u32,
    ig: u32,
    p: u32,
    p0i: u32,
    gm: &mut [u32],
    igm: &mut [u32],
) {
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
pub(crate) fn mp_mkgm(logn: u32, g: u32, p: u32, p0i: u32, gm: &mut [u32]) {
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
pub(crate) fn mp_mkigm(logn: u32, ig: u32, p: u32, p0i: u32, igm: &mut [u32]) {
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
pub(crate) fn mp_NTT(logn: u32, a: &mut [u32], gm: &[u32], p: u32, p0i: u32) {
    if logn == 0 {
        return;
    }
    let mut t = 1 << logn;
    for lm in 0..logn {
        let m = 1 << lm;
        let ht = t >> 1;
        let mut j0 = 0;
        for i in 0..m {
            let s = gm[i + m];
            for j in 0..ht {
                let j1 = j0 + j;
                let j2 = j1 + ht;
                let x1 = a[j1];
                let x2 = mp_mmul(a[j2], s, p, p0i);
                a[j1] = mp_add(x1, x2, p);
                a[j2] = mp_sub(x1, x2, p);
            }
            j0 += t;
        }
        t = ht;
    }
}
// Apply inverse NTT over a polynomial in GF(p)[X]/(X^n+1). Input
// coefficients are expected in unsigned representation. The polynomial is
// modified in place. The number of coefficients is n = 2^logn, with
// 0 <= logn <= 10. The igm[] table must have been initialized with
// mp_mkigm() (or mp_mkgmigm()) with at least n elements.
pub(crate) fn mp_iNTT(logn: u32, a: &mut [u32], igm: &[u32], p: u32, p0i: u32) {
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
pub(crate) fn poly_mp_set_small(logn: u32, f: &[i8], p: u32, d: &mut [u32]) {
    for i in 0..(1usize << logn) {
        d[i] = mp_set(f[i] as i32, p);
    }
}
// Set polynomial f to its RNS representation (modulo p); the converted
// value overwrites the source. The source is assumed to use signed
// representation.
pub(crate) fn poly_mp_set(logn: u32, f: &mut [u32], p: u32) {
    for i in 0..(1usize << logn) {
        let x = f[i];
        f[i] = mp_set((x | ((x & 0x4000_0000) << 1)) as i32, p);
    }
}
// Convert a polynomial from RNS to plain, signed representation, 1 word
// per coefficient. Note: the returned 32-bit values are NOT truncated to
// 31 bits; they are full-size signed 32-bit values, cast to u32 type.
pub(crate) fn poly_mp_norm(logn: u32, f: &mut [u32], p: u32) {
    for i in 0..(1usize << logn) {
        f[i] = mp_norm(f[i], p) as u32;
    }
}
// Get the maximum bitlength of the coefficients of the provided polynomial
// (degree 2^logn, coefficients in plain representation, xlen words per
// coefficient).
pub(crate) fn poly_max_bitlength(logn: u32, x: &[u32], xlen: usize) -> u32 {
    let n = 1usize << logn;
    let mut t = 0u32;
    let mut tk = 0u32;
    for i in 0..n {
        // Extend sign bit into a 31-bit mask.
        let m = (x[i + ((xlen - 1) << logn)] >> 30).wrapping_neg() & 0x7FFF_FFFF;
        // Get top non-zero sign-adjusted word, with index.
        //   c    top non-zero word
        //   ck   index at which c was found
        let mut c = 0u32;
        let mut ck = 0u32;
        for j in 0..xlen {
            // Sign-adjust the word.
            let w = x[i + (j << logn)] ^ m;
            // If the word is non-zero, then update c and ck.
            let nz = (w.wrapping_sub(1) >> 31).wrapping_sub(1);
            c ^= nz & (c ^ w);
            ck ^= nz & (ck ^ (j as u32));
        }
        // If ck > tk, or ck == tk but c > t, then (c,ck) must replace
        // (t,tk) as current candidate.
        let nz1 = tk.wrapping_sub(ck);
        let nz2 = (tk ^ ck).wrapping_sub(1) & t.wrapping_sub(c);
        let nz = tbmask(nz1 | nz2);
        t ^= nz & (t ^ c);
        tk ^= nz & (tk ^ ck);
    }
    31 * tk + bitlength(t)
}
// Return (q, r) where q = x / 31 and r = x % 31. This function works for
// any integer x up to 63487 (inclusive).
#[inline(always)]
pub(crate) const fn divrem31(x: u32) -> (u32, u32) {
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
pub(crate) fn poly_big_to_fixed(logn: u32, f: &[u32], flen: usize, sc: u32, d: &mut [FXR]) {
    let n = 1usize << logn;
    if flen == 0 {
        for i in 0..n {
            d[i] = FXR::ZERO;
        }
        return;
    }
    // We split sc into sch and scl such that:
    //   sc = 31*sch + scl
    // We also want scl in the 1..31 range, not 0..30. If sc == 0, then
    // this will imply that sch "wraps around" to 2^32-1, which is harmless.
    let (mut sch, mut scl) = divrem31(sc);
    let t = scl.wrapping_sub(1) >> 5;
    sch = sch.wrapping_sub(t & 1);
    scl |= t & 31;
    // For each coefficient, we want three words, each with a given left
    // shift (negative for a right shift):
    //    sch-1   1 - scl
    //    sch     32 - scl
    //    sch+1   63 - scl
    let t0 = sch.wrapping_sub(1) & 0xFFFF;
    let t1 = sch & 0xFFFF;
    let t2 = sch.wrapping_add(1) & 0xFFFF;
    for i in 0..n {
        // Get the relevant upper words.
        let mut w0 = 0u32;
        let mut w1 = 0u32;
        let mut w2 = 0u32;
        for j in 0..flen {
            let w = f[i + (j << logn)];
            let t = j as u32;
            w0 |= w & ((((t ^ t0).wrapping_sub(1) as i32) >> 16) as u32);
            w1 |= w & ((((t ^ t1).wrapping_sub(1) as i32) >> 16) as u32);
            w2 |= w & ((((t ^ t2).wrapping_sub(1) as i32) >> 16) as u32);
        }
        // If there are not enough words for the requested scaling, then
        // we must supply copies with the proper sign.
        let ws = (f[i + ((flen - 1) << logn)] >> 30).wrapping_neg() >> 1;
        let ff = (flen as u32).wrapping_sub(sch) as i32;
        w0 |= ws & ((ff >> 31) as u32);
        w1 |= ws & ((ff.wrapping_sub(1) >> 31) as u32);
        w2 |= ws & ((ff.wrapping_sub(2) >> 31) as u32);
        // Assemble the 64-bit value with the shifts. We assume that
        // shifts on 32-bit values are constant-time with regard to
        // the shift count (the last notable architecture on which this
        // was not true was the Willamette and Northwood cores in the
        // Pentium IV).
        w2 |= (w2 & 0x4000_0000) << 1;
        let xl = (w0 >> (scl - 1)) | (w1 << (32 - scl));
        let xh = (w1 >> scl) | (w2 << (31 - scl));
        d[i] = FXR::from_u64_scaled32((xl as u64) | ((xh as u64) << 32));
    }
}
// Subtract f*k*2^scale_k from F. Coefficients of F and f use Flen and flen
// words, respectively, and are in plain signed representation. Coefficients
// from k are signed 32-bit integers (provided in u32 slots).
pub(crate) fn poly_sub_scaled(
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
        let kf = k[i].wrapping_neg() as i32;
        for j in i..n {
            zint_add_scaled_mul_small(&mut F[j..], Flen, &f[(j - i)..], flen, n, kf, sch, scl);
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
                sch,
                scl,
            );
        }
    }
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
pub(crate) fn poly_sub_scaled_ntt(
    logn: u32,
    F: &mut [u32],
    Flen: usize,
    f: &[u32],
    flen: usize,
    k: &[u32],
    sc: u32,
    tmp: &mut [u32],
) {
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
            t1[j] = mp_set(k[j] as i32, p);
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
        zint_sub_scaled(&mut F[i..], Flen, &fk[i..], tlen, n, sch, scl);
    }
}
// Subtract (k*2^scale_k_*(f,g) from (F,G). This is a specialized function
// for NTRU solving at depth 1, because we really want to use the NTT (degree
// is large) but we do not have enough room in our buffers to keep (f,g)
// in RNS+NTT modulo enough primes. Instead, we recompute them dynamically
// here.
pub(crate) fn poly_sub_kfg_scaled_depth1(
    logn_top: u32,
    F: &mut [u32],
    G: &mut [u32],
    FGlen: usize,
    k: &mut [u32],
    sc: u32,
    f: &[i8],
    g: &[i8],
    tmp: &mut [u32],
) {
    let logn = logn_top - 1;
    let n = 1usize << logn;
    let hn = n >> 1;
    let (gm, tmp) = tmp.split_at_mut(n);
    let (t1, t2) = tmp.split_at_mut(n);
    // Convert F and G to RNS. Normally, FGlen is equal to 2; the code
    // below also covers the case FGlen = 1, which could be used in some
    // algorithms leveraging the same kind of NTRU lattice.
    if FGlen == 1 {
        let p = PRIMES[0].p;
        for i in 0..n {
            let xf = F[i];
            let xg = G[i];
            let xf = xf | ((xf & 0x4000_0000) << 1);
            let xg = xg | ((xg & 0x4000_0000) << 1);
            F[i] = mp_set(xf as i32, p);
            G[i] = mp_set(xg as i32, p);
        }
    } else {
        assert!(FGlen == 2);
        let p0 = PRIMES[0].p;
        let p0_0i = PRIMES[0].p0i;
        let z0 = mp_half(PRIMES[0].R2, p0);
        let p1 = PRIMES[1].p;
        let p1_0i = PRIMES[1].p0i;
        let z1 = mp_half(PRIMES[1].R2, p1);
        for i in 0..n {
            let xl = F[i];
            let xh = F[i + n] | ((F[i + n] & 0x4000_0000) << 1);
            let yl0 = mp_set_u(xl, p0);
            let yh0 = mp_set(xh as i32, p0);
            let r0 = mp_add(yl0, mp_mmul(yh0, z0, p0, p0_0i), p0);
            let yl1 = mp_set_u(xl, p1);
            let yh1 = mp_set(xh as i32, p1);
            let r1 = mp_add(yl1, mp_mmul(yh1, z1, p1, p1_0i), p1);
            F[i] = r0;
            F[i + n] = r1;
            let xl = G[i];
            let xh = G[i + n] | ((G[i + n] & 0x4000_0000) << 1);
            let yl0 = mp_set_u(xl, p0);
            let yh0 = mp_set(xh as i32, p0);
            let r0 = mp_add(yl0, mp_mmul(yh0, z0, p0, p0_0i), p0);
            let yl1 = mp_set_u(xl, p1);
            let yh1 = mp_set(xh as i32, p1);
            let r1 = mp_add(yl1, mp_mmul(yh1, z1, p1, p1_0i), p1);
            G[i] = r0;
            G[i + n] = r1;
        }
    }
    // For FGlen small primes, convert F and G to RNS+NTT, and subtract
    // (2^sc)*(ft,gt). ft and gt are computed dynamically from the
    // top-level (f,g).
    for i in 0..FGlen {
        let p = PRIMES[i].p;
        let p0i = PRIMES[i].p0i;
        let R2 = PRIMES[i].R2;
        let R3 = mp_mmul(R2, R2, p, p0i);
        mp_mkgm(logn, PRIMES[i].g, p, p0i, gm);
        // k <- (2^sc)*k (and into NTT).
        // We modify k in place because we do not have enough room to make
        // a copy.
        let mut scv = mp_mmul(1u32 << (sc & 31), R2, p, p0i);
        for _ in 0..(sc >> 5) {
            scv = mp_mmul(scv, R2, p, p0i);
        }
        for j in 0..n {
            let x = mp_set(k[j] as i32, p);
            k[j] = mp_mmul(scv, x, p, p0i);
        }
        mp_NTT(logn, k, gm, p, p0i);
        // Convert F and G to NTT.
        let Fu = &mut F[(i << logn)..];
        let Gu = &mut G[(i << logn)..];
        mp_NTT(logn, Fu, gm, p, p0i);
        mp_NTT(logn, Gu, gm, p, p0i);
        // Given the top-level f, we obtain ft = N(f) with:
        //    f = f_e(X^2) + X*f_o(X^2)
        // with f_e and f_o being modulo X^n+1 (with n = 2^logn) while
        // f is modulo X^(2*n)+1 (with 2*n = 2^logn_top). Then:
        //    N(f) = f_e^2 - X*f_o^2
        // The NTT representation of X is obtained from the gm[] tab:
        //    NTT(X)[2*j + 0] = gm[j + n/2]
        //    NTT(X)[2*j + 1] = -NTT(X)[2*j + 0]
        // Note: the values in gm[] are in Montgomery representation.
        for j in 0..n {
            t1[j] = mp_set(f[(j << 1) + 0] as i32, p);
            t2[j] = mp_set(f[(j << 1) + 1] as i32, p);
        }
        mp_NTT(logn, t1, gm, p, p0i);
        mp_NTT(logn, t2, gm, p, p0i);
        for j in 0..hn {
            let xe0 = t1[(j << 1) + 0];
            let xe1 = t1[(j << 1) + 1];
            let xo0 = t2[(j << 1) + 0];
            let xo1 = t2[(j << 1) + 1];
            let xv0 = gm[j + hn];
            let xv1 = p - xv0; // values in gm[] are non-zero
            let xe0 = mp_mmul(xe0, xe0, p, p0i);
            let xe1 = mp_mmul(xe1, xe1, p, p0i);
            let xo0 = mp_mmul(xo0, xo0, p, p0i);
            let xo1 = mp_mmul(xo1, xo1, p, p0i);
            let xf0 = mp_sub(xe0, mp_mmul(xo0, xv0, p, p0i), p);
            let xf1 = mp_sub(xe1, mp_mmul(xo1, xv1, p, p0i), p);
            let xkf0 = mp_mmul(mp_mmul(xf0, k[(j << 1) + 0], p, p0i), R3, p, p0i);
            let xkf1 = mp_mmul(mp_mmul(xf1, k[(j << 1) + 1], p, p0i), R3, p, p0i);
            Fu[(j << 1) + 0] = mp_sub(Fu[(j << 1) + 0], xkf0, p);
            Fu[(j << 1) + 1] = mp_sub(Fu[(j << 1) + 1], xkf1, p);
        }
        // Same treatment for G and gt.
        for j in 0..n {
            t1[j] = mp_set(g[(j << 1) + 0] as i32, p);
            t2[j] = mp_set(g[(j << 1) + 1] as i32, p);
        }
        mp_NTT(logn, t1, gm, p, p0i);
        mp_NTT(logn, t2, gm, p, p0i);
        for j in 0..hn {
            let xe0 = t1[(j << 1) + 0];
            let xe1 = t1[(j << 1) + 1];
            let xo0 = t2[(j << 1) + 0];
            let xo1 = t2[(j << 1) + 1];
            let xv0 = gm[j + hn];
            let xv1 = p - xv0; // values in gm[] are non-zero
            let xe0 = mp_mmul(xe0, xe0, p, p0i);
            let xe1 = mp_mmul(xe1, xe1, p, p0i);
            let xo0 = mp_mmul(xo0, xo0, p, p0i);
            let xo1 = mp_mmul(xo1, xo1, p, p0i);
            let xg0 = mp_sub(xe0, mp_mmul(xo0, xv0, p, p0i), p);
            let xg1 = mp_sub(xe1, mp_mmul(xo1, xv1, p, p0i), p);
            let xkg0 = mp_mmul(mp_mmul(xg0, k[(j << 1) + 0], p, p0i), R3, p, p0i);
            let xkg1 = mp_mmul(mp_mmul(xg1, k[(j << 1) + 1], p, p0i), R3, p, p0i);
            Gu[(j << 1) + 0] = mp_sub(Gu[(j << 1) + 0], xkg0, p);
            Gu[(j << 1) + 1] = mp_sub(Gu[(j << 1) + 1], xkg1, p);
        }
        // Convert back F and G to RNS.
        mp_mkigm(logn, PRIMES[i].ig, p, p0i, t1);
        mp_iNTT(logn, Fu, t1, p, p0i);
        mp_iNTT(logn, Gu, t1, p, p0i);
        // We replaced k (plain 32-bit) with (2^sc)*k (NTT); we must
        // put it back to its initial value for the next iteration.
        if (i + 1) < FGlen {
            mp_iNTT(logn, k, t1, p, p0i);
            scv = 1u32 << (sc.wrapping_neg() & 31);
            for _ in 0..(sc >> 5) {
                scv = mp_mmul(scv, 1, p, p0i);
            }
            for j in 0..n {
                k[j] = mp_norm(mp_mmul(scv, k[j], p, p0i), p) as u32;
            }
        }
    }
    // F and G are in RNS (non-NTT), but we want plain integers.
    if FGlen == 1 {
        let p = PRIMES[0].p;
        for i in 0..n {
            F[i] = (mp_norm(F[i], p) as u32) & 0x7FFF_FFFF;
            G[i] = (mp_norm(G[i], p) as u32) & 0x7FFF_FFFF;
        }
    } else {
        let p0 = PRIMES[0].p;
        let p1 = PRIMES[1].p;
        let p1_0i = PRIMES[1].p0i;
        let s = PRIMES[1].s;
        let pp = (p0 as u64) * (p1 as u64);
        let hpp = pp >> 1;
        for i in 0..n {
            let x0 = F[i];
            let x1 = F[i + n];
            let x0m1 = x0.wrapping_sub(p1 & !tbmask(x0.wrapping_sub(p1)));
            let y = mp_mmul(mp_sub(x1, x0m1, p1), s, p1, p1_0i);
            let z = (x0 as u64) + (p0 as u64) * (y as u64);
            let z = z.wrapping_sub(pp & (hpp.wrapping_sub(z) >> 63).wrapping_neg());
            F[i] = (z as u32) & 0x7FFF_FFFF;
            F[i + n] = ((z >> 31) as u32) & 0x7FFF_FFFF;
        }
        for i in 0..n {
            let x0 = G[i];
            let x1 = G[i + n];
            let x0m1 = x0.wrapping_sub(p1 & !tbmask(x0.wrapping_sub(p1)));
            let y = mp_mmul(mp_sub(x1, x0m1, p1), s, p1, p1_0i);
            let z = (x0 as u64) + (p0 as u64) * (y as u64);
            let z = z.wrapping_sub(pp & (hpp.wrapping_sub(z) >> 63).wrapping_neg());
            G[i] = (z as u32) & 0x7FFF_FFFF;
            G[i + n] = ((z >> 31) as u32) & 0x7FFF_FFFF;
        }
    }
}
