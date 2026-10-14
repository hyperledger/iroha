#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
use super::fxp::*;
use super::mp31::*;
use super::poly::*;
use super::vect::*;
use super::zint31::*;
// ========================================================================
// Solving the NTRU equation
// ========================================================================
// Check that (f,g) has an acceptable orthogonalized norm.
// If this function returns false, then the (f,g) pair should be
// rejected.
// tmp min size: 2.5*n
pub(crate) fn check_ortho_norm(logn: u32, f: &[i8], g: &[i8], tmp: &mut [FXR]) -> bool {
    let n = 1usize << logn;
    let (fx, tmp) = tmp.split_at_mut(n);
    let (gx, rt3) = tmp.split_at_mut(n);
    vect_to_fxr(logn, fx, f);
    vect_to_fxr(logn, gx, g);
    vect_FFT(logn, fx);
    vect_FFT(logn, gx);
    vect_invnorm_fft(logn, rt3, fx, gx, 0);
    vect_adj_fft(logn, fx);
    vect_adj_fft(logn, gx);
    vect_mul_realconst(logn, fx, FXR::from_i32(Q as i32));
    vect_mul_realconst(logn, gx, FXR::from_i32(Q as i32));
    vect_mul_selfadj_fft(logn, fx, rt3);
    vect_mul_selfadj_fft(logn, gx, rt3);
    vect_iFFT(logn, fx);
    vect_iFFT(logn, gx);
    let mut sn = FXR::ZERO;
    for i in 0..n {
        sn += fx[i].sqr() + gx[i].sqr();
    }
    sn < FXR::from_u64_scaled32(72_251_709_809_335)
}
const Q: u32 = 12289;
// At recursion depth d, with:
//   slen = MOD_SMALL_BL[d]
//   llen = MOD_LARGE_BL[d]
//   tlen = MOD_SMALL_BL[d + 1]
// then:
//   (f, g) at this level use slen words for each coefficient
//   (F', G') from deeper level use tlen words for each coefficient
//   unreduced (F, G) at this level use llen words for each coefficient
//   output (F, G) use slen words for each coefficient
const MOD_SMALL_BL: [usize; 11] = [1, 1, 2, 3, 4, 8, 14, 27, 53, 104, 207];
const MOD_LARGE_BL: [usize; 10] = [1, 2, 3, 6, 11, 21, 40, 78, 155, 308];
// Minimum depth for which intermediate (f,g) values are saved.
const MIN_SAVE_FG: [u32; 11] = [0, 0, 1, 2, 2, 2, 2, 2, 2, 3, 3];
// When log(n) >= MIN_LOGN_FGNTT, we use the NTT to subtract (k*f,k*g)
// from (F,G) during the reduction.
const MIN_LOGN_FGNTT: u32 = 4;
// Number of top words to consider during reduction.
const WORD_WIN: [usize; 10] = [1, 1, 2, 2, 2, 3, 3, 4, 5, 7];
// Number of bits gained per each round of reduction.
const REDUCE_BITS: [u32; 11] = [16, 16, 16, 16, 16, 16, 16, 16, 16, 13, 11];
// Given polynomials f and g (modulo X^n+1 with n = 2^logn), find
// polynomials F and G such that:
//    -127 <= F[i], G[i] <= +127   for all i in [0, n-1]
//    f*G - g*F = q  mod X^n+1     (with q = 12289)
// Returned value is true on success, false on error. If the function does
// not succeed, then the contents of F and G are not modified.
// All four slices f, g, F and G must have length exactly 2^logn.
// tmp_u32 min size: 6*n
// tmp_fxr min size: 2.5*n
pub(crate) fn solve_NTRU(
    logn: u32,
    f: &[i8],
    g: &[i8],
    F: &mut [i8],
    G: &mut [i8],
    tmp_u32: &mut [u32],
    tmp_fxr: &mut [FXR],
) -> bool {
    assert!(1 <= logn && logn <= 10);
    let n = 1usize << logn;
    assert!(f.len() == n && g.len() == n);
    assert!(F.len() == n && G.len() == n);
    if !solve_NTRU_deepest(logn, f, g, tmp_u32) {
        return false;
    }
    for depth in (1..logn).rev() {
        if !solve_NTRU_intermediate(logn, f, g, depth, tmp_u32, tmp_fxr) {
            return false;
        }
    }
    if !solve_NTRU_depth0(logn, f, g, tmp_u32, tmp_fxr) {
        return false;
    }
    // Solution is in the first 2*n slots of tmp_u32.
    // We must check that all coefficients are in [-127,+127].
    for i in 0..(2 * n) {
        let z = tmp_u32[i] as i32;
        if z < -127 || z > 127 {
            return false;
        }
    }
    // Success! Return the result.
    for i in 0..n {
        F[i] = (tmp_u32[i] as i32) as i8;
        G[i] = (tmp_u32[i + n] as i32) as i8;
    }
    return true;
}
// Solving the NTRU equation, deepest level.
// This computes the integers F and G such that:
//   Res(f,X^n+1)*G - Res(g,X^n+1)*F = q
// The two integers are written into tmp[], over MOD_SMALL_BL[logn]
// words each.
fn solve_NTRU_deepest(logn: u32, f: &[i8], g: &[i8], tmp: &mut [u32]) -> bool {
    let slen = MOD_SMALL_BL[logn as usize];
    // Get (f,g) at the deepest level. Obtained (f,g) are in RNS+NTT;
    // since degree is 1 at the deepest level, then NTT is a no-op and
    // we have (f,g) in RNS.
    if !make_fg_deepest(logn, f, g, tmp) {
        // f is not invertible modulo X^n+1 and modulo P0, we reject
        // that case.
        return false;
    }
    // Reorganize work area:
    //   Fp   output F (slen)
    //   Gp   output G (slen)
    //   fp   Res(f, X^n+1) (slen)
    //   gp   Res(g, X^n+1) (slen)
    //   t1   rest of temporary
    tmp.copy_within(0..(2 * slen), 2 * slen);
    let (Fp, tmp) = tmp.split_at_mut(slen);
    let (Gp, tmp) = tmp.split_at_mut(slen);
    let (fgp, t1) = tmp.split_at_mut(2 * slen);
    // Convert the resultants into plain integers. The resultants are always
    // non-negative, hence we do not normalize to signed.
    zint_rebuild_CRT(fgp, slen, 1, 2, false, t1);
    let (fp, gp) = fgp.split_at_mut(slen);
    // Apply the binary GCD to get (F, G).
    if zint_bezout(Gp, Fp, fp, gp, t1) != 0xFFFF_FFFF {
        // Resultants are not coprime to each other; we reject that case
        // (note: we also reject the case where the GCD is exactly q = 12289,
        // even though that case could be handled.
        return false;
    }
    // Multiply the obtained (F,G) by q to get a solution f*G - g*F = q.
    if zint_mul_small(Fp, Q) != 0 || zint_mul_small(Gp, Q) != 0 {
        // If either multiplication overflows, we reject.
        return false;
    }
    return true;
}
// Solving the NTRU equation, intermediate level.
fn solve_NTRU_intermediate(
    logn_top: u32,
    f: &[i8],
    g: &[i8],
    depth: u32,
    tmp_u32: &mut [u32],
    tmp_fxr: &mut [FXR],
) -> bool {
    let logn = logn_top - depth;
    let n = 1usize << logn;
    let hn = n >> 1;
    // slen   size for (f,g) at this level (and also output (F,G))
    // llen   size for unreduced (F,G) at this level
    // tlen   size for (F,G) from the deeper level
    // Note: we always have llen >= tlen
    let slen = MOD_SMALL_BL[depth as usize];
    let llen = MOD_LARGE_BL[depth as usize];
    let tlen = MOD_SMALL_BL[(depth + 1) as usize];
    // Input layout:
    //   Fd   F from deeper level (tlen * hn)
    //   Gd   G from deeper level (tlen * hn)
    // Fd and Gd are in plain representation.
    // Get (f,g) for this level.
    let min_sav = MIN_SAVE_FG[logn_top as usize];
    if depth < min_sav {
        // (f,g) were not saved previously, recompute them.
        make_fg_intermediate(logn_top, f, g, depth, &mut tmp_u32[(2 * tlen * hn)..]);
    } else {
        // (f,g) were saved previously, get them.
        let mut sav_off = tmp_u32.len();
        for d in min_sav..(depth + 1) {
            sav_off -= MOD_SMALL_BL[d as usize] << (logn_top + 1 - d);
        }
        tmp_u32.copy_within(sav_off..(sav_off + 2 * slen * n), 2 * tlen * hn);
    }
    // Current layout:
    //   Fd   F from deeper level (tlen * hn)
    //   Gd   G from deeper level (tlen * hn)
    //   ft   f from this level (slen * n)
    //   gt   g from this level (slen * n)
    // We now move things to this layout:
    //   Ft   F from this level (unreduced) (llen * n)
    //   Gt   G from this level (unreduced) (llen * n)
    //   ft   f from this level (slen * n) (RNS+NTT)
    //   gt   g from this level (slen * n) (RNS+NTT)
    //   Fd   F from deeper level (tlen * hn) (plain)
    //   Gd   G from deeper level (tlen * hn) (plain)
    tmp_u32.copy_within(0..(2 * tlen * hn), 2 * (llen + slen) * n);
    tmp_u32.copy_within(
        (2 * tlen * hn)..(2 * tlen * hn + 2 * slen * n),
        2 * llen * n,
    );
    // Convert Fd and Gd to RNS, with output temporarily stored in (Ft, Gt).
    // Fd and Gd have degree hn only; we store the values for each modulus p
    // in the _last_ hn slots of the n-word line for that modulus.
    {
        let (Ft, work) = tmp_u32[..].split_at_mut(llen * n);
        let (Gt, work) = work.split_at_mut(llen * n);
        let (_, work) = work.split_at_mut(2 * slen * n); // ft and gt
        let (Fd, work) = work.split_at_mut(tlen * hn);
        let (Gd, _) = work.split_at_mut(tlen * hn);
        for i in 0..llen {
            let p = PRIMES[i].p;
            let p0i = PRIMES[i].p0i;
            let R2 = PRIMES[i].R2;
            let Rx = mp_Rx31(tlen as u32, p, p0i, R2);
            let kt = i * n + hn;
            for j in 0..hn {
                Ft[kt + j] = zint_mod_small_signed(&Fd[j..], tlen, hn, p, p0i, R2, Rx);
                Gt[kt + j] = zint_mod_small_signed(&Gd[j..], tlen, hn, p, p0i, R2, Rx);
            }
        }
    }
    // Fd and Gd are no longer needed.
    // Compute (F,G) (unreduced) modulo sufficiently many small primes.
    // We also un-NTT (f,g) as we go; when slen primes have been processed,
    // we have (f,g) in RNS, and we apply the CRT to get (f,g) in plain
    // representation.
    {
        let (FGt, work) = tmp_u32[..].split_at_mut(2 * llen * n);
        let (fgt, work) = work.split_at_mut(2 * slen * n); // ft and gt
        for i in 0..llen {
            let p = PRIMES[i].p;
            let p0i = PRIMES[i].p0i;
            let R2 = PRIMES[i].R2;
            // Memory layout:
            //   Ft    (n * llen)
            //   Gt    (n * llen)
            //   ft    (n * slen)
            //   gt    (n * slen)
            //   gm    NTT support (n)
            //   igm   iNTT support (n)
            //   fx    temporary f mod p (NTT) (n)
            //   gx    temporary g mod p (NTT) (n)
            {
                let (Ft, Gt) = FGt.split_at_mut(llen * n);
                let (ft, gt) = fgt.split_at_mut(slen * n);
                let (gm, work) = work.split_at_mut(n);
                let (igm, work) = work.split_at_mut(n);
                let (fx, work) = work.split_at_mut(n);
                let (gx, _) = work.split_at_mut(n);
                mp_mkgmigm(logn, PRIMES[i].g, PRIMES[i].ig, p, p0i, gm, igm);
                if i < slen {
                    fx.copy_from_slice(&ft[(i * n)..((i + 1) * n)]);
                    gx.copy_from_slice(&gt[(i * n)..((i + 1) * n)]);
                    mp_iNTT(logn, &mut ft[(i * n)..((i + 1) * n)], igm, p, p0i);
                    mp_iNTT(logn, &mut gt[(i * n)..((i + 1) * n)], igm, p, p0i);
                } else {
                    let Rx = mp_Rx31(slen as u32, p, p0i, R2);
                    for j in 0..n {
                        fx[j] = zint_mod_small_signed(&ft[j..], slen, n, p, p0i, R2, Rx);
                        gx[j] = zint_mod_small_signed(&gt[j..], slen, n, p, p0i, R2, Rx);
                    }
                    mp_NTT(logn, fx, gm, p, p0i);
                    mp_NTT(logn, gx, gm, p, p0i);
                }
                // We have (F,G) in RNS in Ft and Gt; we apply the NTT
                // modulo p. Note that we can use gm (generated for degree
                // n) for an NTT with degree hn = n/2.
                let kt = i * n + hn;
                mp_NTT(logn - 1, &mut Ft[kt..(kt + hn)], gm, p, p0i);
                mp_NTT(logn - 1, &mut Gt[kt..(kt + hn)], gm, p, p0i);
                // Compute F and G (unreduced) modulo p.
                let kt = i * n;
                for j in 0..hn {
                    let fa = fx[2 * j + 0];
                    let fb = fx[2 * j + 1];
                    let ga = gx[2 * j + 0];
                    let gb = gx[2 * j + 1];
                    let mFp = mp_mmul(Ft[kt + hn + j], R2, p, p0i);
                    let mGp = mp_mmul(Gt[kt + hn + j], R2, p, p0i);
                    Ft[kt + 2 * j + 0] = mp_mmul(gb, mFp, p, p0i);
                    Ft[kt + 2 * j + 1] = mp_mmul(ga, mFp, p, p0i);
                    Gt[kt + 2 * j + 0] = mp_mmul(fb, mGp, p, p0i);
                    Gt[kt + 2 * j + 1] = mp_mmul(fa, mGp, p, p0i);
                }
                mp_iNTT(logn, &mut Ft[kt..(kt + n)], igm, p, p0i);
                mp_iNTT(logn, &mut Gt[kt..(kt + n)], igm, p, p0i);
            }
            if (i + 1) == slen {
                // (f,g) are now in RNS, convert them to plain.
                zint_rebuild_CRT(fgt, slen, n, 2, true, work);
            }
        }
        // (Ft, Gt) are in RNS, we want them in plain representation.
        zint_rebuild_CRT(FGt, llen, n, 2, true, work);
    }
    // Current memory lauout:
    //   Ft   F from this level (unreduced) (llen * n) (plain)
    //   Gt   G from this level (unreduced) (llen * n) (plain)
    //   ft   f from this level (slen * n) (plain)
    //   gt   g from this level (slen * n) (plain)
    // We now reduce these (F,G) with Babai's nearest plane algorithm.
    // The reduction conceptually goes as follows:
    //   k <- round((F*adj(f) + G*adj(g))/(f*adj(f) + g*adj(g)))
    //   (F, G) <- (F - k*f, G - k*g)
    // We use fixed-point approximations of (f,g) and (F, G) to get
    // a value k as a small polynomial with scaling; we then apply
    // k on the full-width polynomial. Each iteration "shaves" a
    // a few bits off F and G.
    //
    // We apply the process sufficiently many times to reduce (F, G)
    // to the size of (f, g) with a reasonable probability of success.
    // Since we want full constant-time processing, the number of
    // iterations and the accessed slots work on some assumptions on
    // the sizes of values (sizes have been measured over many samples,
    // and a margin of 5 times the standard deviation).
    // If depth is at least 2, and we will use the NTT to subtract
    // (k*f,k*g) from (F,G), then we will need to convert (f,g) to
    // NTT over slen+1 words, which requires an extra word to ft and gt.
    let use_sub_ntt = depth > 1 && logn >= MIN_LOGN_FGNTT;
    if use_sub_ntt {
        tmp_u32[..].copy_within(
            (2 * llen * n + slen * n)..(2 * llen * n + 2 * slen * n),
            2 * llen * n + (slen + 1) * n,
        );
    }
    let slen_adj = if use_sub_ntt { slen + 1 } else { slen };
    // Current memory layout:
    //   Ft    F from this level (unreduced) (llen * n) (plain)
    //   Gt    G from this level (unreduced) (llen * n) (plain)
    //   ft    f from this level (slen * n, +n if use_sub_ntt) (plain)
    //   gt    g from this level (slen * n, +n if use_sub_ntt) (plain)
    // For the reduction, we will consider only the top rlen words
    // of (f,g).
    let rlen = WORD_WIN[depth as usize];
    let blen = slen - rlen;
    // We are going to convert f and g into fixed-point approximations,
    // in rt3 and rt4, respectively. The values will be scaled down by
    // 2^(scale_fg + scale_x). scale_fg is a public value, but scale_x
    // is set according to the current values of f and g, and therefore
    // it is secret. scale_x is set such that the largest coefficient
    // is close to, but lower than, some limit t (in absolute value).
    // The limit t is chosen so that f*adj(f) + g*adj(g) does not
    // overflow, i.e. all coefficients must remain below 2^31.
    //
    // Let n be the degree (n <= 2^10). The squared norm of a polynomial
    // is the sum of the squared norms of the coefficients, with the
    // squared norm of a complex number being the product of that number
    // with its complex conjugate. If all coefficients of f are less
    // than t (in absolute value), then the squared norm of f is less
    // than n*t^2. The squared norm of FFT(f) (f in FFT representation)
    // is exactly n times the squared norm of f, so this leads to
    // n^2*t^2 as a maximum bound. adj(f) has the same norm as f. This
    // implies that each complex coefficient of FFT(f) has a maximum
    // squared norm of n^2*t^2 (with a maximally imbalanced polynomial
    // with all coefficient but one being zero). The computation of
    // f*adj(f) exactly is, in FFT representation, the product of each
    // coefficient with its conjugate; thus, the coefficients of
    // f*adj(f), in FFT representation, are at most n^2*t^2.
    //
    // Since we want the coefficients of f*adj(f) + g*adj(g) not to
    // exceed 2^31, we need n^2*t^2 <= 2^30, i.e. n*t <= 2^15. We can
    // adjust t accordingly (called scale_t in the code below). We also
    // need to take care that t must not exceed scale_x. Approximation
    // of f and g are extracted with scale scale_fg + scale_x - scale_t,
    // and later fixed by dividing them by 2^scale_t.
    let scale_fg = 31 * (blen as u32);
    let mut scale_FG = 31 * (llen as u32);
    let scale_x;
    {
        let (_, work) = tmp_u32.split_at_mut(2 * n * llen);
        let (ft, gt) = work.split_at_mut(n * slen_adj);
        // FXR values:
        //   rt3   n
        //   rt4   n
        //   rt1   n/2
        // TODO: share (rt3,rt4,rt1) with space just after gt
        let (rt3, rttmp) = tmp_fxr.split_at_mut(n);
        let (rt4, rt1) = rttmp.split_at_mut(n);
        // scale_x is the maximum bit length of f and g (beyond scale_fg)
        let scale_xf = poly_max_bitlength(logn, &ft[(n * blen)..], rlen);
        let scale_xg = poly_max_bitlength(logn, &gt[(n * blen)..], rlen);
        scale_x = scale_xf ^ ((scale_xf ^ scale_xg) & tbmask(scale_xf.wrapping_sub(scale_xg)));
        // scale_t is from logn, but not greater than scale_x
        let scale_t = 15 - logn;
        let scale_t = scale_t ^ ((scale_t ^ scale_x) & tbmask(scale_x.wrapping_sub(scale_t)));
        let scdiff = scale_x - scale_t;
        // Extract the approximations of f and g (scaled).
        poly_big_to_fixed(logn, &ft[(n * blen)..], rlen, scdiff, rt3);
        poly_big_to_fixed(logn, &gt[(n * blen)..], rlen, scdiff, rt4);
        // Compute adj(f)/(f*adj(f) + g*adj(g)) into rt3 (FFT).
        // Compute adj(g)/(f*adj(f) + g*adj(g)) into rt4 (FFT).
        vect_FFT(logn, rt3);
        vect_FFT(logn, rt4);
        vect_norm_fft(logn, rt1, rt3, rt4);
        vect_mul2e(logn, rt3, scale_t);
        vect_mul2e(logn, rt4, scale_t);
        for i in 0..hn {
            // Note: four independent divisions; we do not mutualize the
            // inversion of rt1[i] since that would lose too much precision.
            rt3[i] /= rt1[i];
            rt3[i + hn] = (-rt3[i + hn]) / rt1[i];
            rt4[i] /= rt1[i];
            rt4[i + hn] = (-rt4[i + hn]) / rt1[i];
        }
    }
    // New layout:
    //   Ft    F from this level (unreduced) (llen * n)
    //   Gt    G from this level (unreduced) (llen * n)
    //   ft    f from this level (slen_adj * n)
    //   gt    g from this level (slen_adj * n)
    //   k     n
    //   t2    3*n
    //
    //   rt3   n (FXR)
    //   rt4   n (FXR)
    //   rt1   n (FXR)
    //   rt2   n (FXR)
    //
    // TODO: merge the FXR space with the u32 space:
    //   rt3 starts right after gt
    //   k,t2 can share the same space as rt1,rt2
    //   at depth 1 we should also remove ft and gt
    {
        let (Ft, work) = tmp_u32.split_at_mut(llen * n);
        let (Gt, work) = work.split_at_mut(llen * n);
        let fgt_size = if depth == 1 { 0 } else { 2 * slen_adj * n };
        let (fgt, work) = work.split_at_mut(fgt_size);
        let (k, t2) = work.split_at_mut(n);
        let (rt3, work) = tmp_fxr.split_at_mut(n);
        let (rt4, work) = work.split_at_mut(n);
        let (rt1, work) = work.split_at_mut(n);
        let (rt2, _) = work.split_at_mut(n);
        // Ft, Gt, ft, gt, rt3 and rt4 are already set.
        // If we use poly_sub_scaled_ntt(), then we convert f and g to
        // NTT.
        if use_sub_ntt {
            let (ft, gt) = fgt.split_at_mut(slen_adj * n);
            let (gm, tn) = t2.split_at_mut(n);
            for i in 0..slen_adj {
                let p = PRIMES[i].p;
                let p0i = PRIMES[i].p0i;
                let R2 = PRIMES[i].R2;
                let Rx = mp_Rx31(slen as u32, p, p0i, R2);
                mp_mkgm(logn, PRIMES[i].g, p, p0i, gm);
                for j in 0..n {
                    tn[(i << logn) + j] = zint_mod_small_signed(&ft[j..], slen, n, p, p0i, R2, Rx);
                }
                mp_NTT(logn, &mut tn[(i << logn)..], gm, p, p0i);
            }
            ft.copy_from_slice(&tn[..(slen_adj * n)]);
            for i in 0..slen_adj {
                let p = PRIMES[i].p;
                let p0i = PRIMES[i].p0i;
                let R2 = PRIMES[i].R2;
                let Rx = mp_Rx31(slen as u32, p, p0i, R2);
                mp_mkgm(logn, PRIMES[i].g, p, p0i, gm);
                for j in 0..n {
                    tn[(i << logn) + j] = zint_mod_small_signed(&gt[j..], slen, n, p, p0i, R2, Rx);
                }
                mp_NTT(logn, &mut tn[(i << logn)..], gm, p, p0i);
            }
            gt.copy_from_slice(&tn[..(slen_adj * n)]);
        }
        // Reduce F and G repeatedly.
        // Each iteration is expected to reduce the size of the coefficients
        // by reduce_bits.
        let mut FGlen = llen;
        let reduce_bits = REDUCE_BITS[logn_top as usize];
        loop {
            // Convert F and G into fixed-point. We want to apply scaling
            // scale_FG + scale_x.
            let (sch, coff) = divrem31(scale_FG);
            let clen = sch as usize;
            poly_big_to_fixed(logn, &Ft[(clen * n)..], FGlen - clen, scale_x + coff, rt1);
            poly_big_to_fixed(logn, &Gt[(clen * n)..], FGlen - clen, scale_x + coff, rt2);
            // rt2 <- (F*adj(f) + G*adj(g)) / (f*adj(f) + g*adj(g))
            vect_FFT(logn, rt1);
            vect_FFT(logn, rt2);
            vect_mul_fft(logn, rt1, rt3);
            vect_mul_fft(logn, rt2, rt4);
            vect_add(logn, rt2, rt1);
            vect_iFFT(logn, rt2);
            // k <- round(rt2)  (i32 elements, stored in u32 slice)
            for i in 0..n {
                k[i] = rt2[i].round() as u32;
            }
            // (f,g) are scaled by scale_fg + scale_x
            // (F,G) are scaled by scale_FG + scale_x
            // Thus, k is scaled by scale_FG - scale_fg, which is public.
            let scale_k = scale_FG - scale_fg;
            if depth == 1 {
                poly_sub_kfg_scaled_depth1(logn_top, Ft, Gt, FGlen, k, scale_k, f, g, t2);
            } else if use_sub_ntt {
                let (ft, gt) = fgt.split_at_mut(slen_adj * n);
                poly_sub_scaled_ntt(logn, Ft, FGlen, ft, slen, k, scale_k, t2);
                poly_sub_scaled_ntt(logn, Gt, FGlen, gt, slen, k, scale_k, t2);
            } else {
                let (ft, gt) = fgt.split_at_mut(slen_adj * n);
                poly_sub_scaled(logn, Ft, FGlen, ft, slen, k, scale_k);
                poly_sub_scaled(logn, Gt, FGlen, gt, slen, k, scale_k);
            }
            // We now assume that F and G have shrunk by at least
            // reduce_bits.
            if scale_FG <= scale_fg {
                break;
            }
            if scale_FG <= (scale_fg + reduce_bits) {
                scale_FG = scale_fg;
            } else {
                scale_FG -= reduce_bits;
            }
            while FGlen > slen && 31 * ((FGlen - slen) as u32) > scale_FG - scale_fg + 30 {
                FGlen -= 1;
            }
        }
    }
    // Output F is already in the right place; G must be moved.
    tmp_u32.copy_within((llen * n)..((llen + slen) * n), slen * n);
    // Reduction is done. We test the current solution modulo a single
    // prime.
    // Exception: this is not done if depth == 1 (the reference C code
    // did not keep (ft,gt) in that case). In any case, the depth-0
    // test will cover it.
    // If use_sub_ntt is true, then ft and gt are already in NTT
    // representation.
    if depth == 1 {
        return true;
    }
    // Move (ft,gt) right after the reduced G.
    // If use_sub_ntt is false, then slen_adj == slen.
    // If use_sub_ntt is true, then slen_adj == slen + 1, but (ft,gt) are
    // already in NTT representation and we only need the first coefficient.
    if use_sub_ntt {
        // ft mod p0 (NTT)
        tmp_u32.copy_within(((2 * llen) * n)..((2 * llen + 1) * n), 2 * slen * n);
        // gt mod p0 (NTT)
        tmp_u32.copy_within(
            ((2 * llen + slen_adj) * n)..((2 * llen + slen_adj + 1) * n),
            (2 * slen + slen) * n,
        );
    } else {
        tmp_u32.copy_within((2 * llen * n)..(2 * (llen + slen) * n), 2 * slen * n);
    }
    {
        let (Ft, work) = tmp_u32.split_at_mut(slen * n);
        let (Gt, work) = work.split_at_mut(slen * n);
        let (ft, work) = work.split_at_mut(slen * n);
        let (gt, work) = work.split_at_mut(slen * n);
        let (t1, work) = work.split_at_mut(slen * n);
        let (t2, gm) = work.split_at_mut(slen * n);
        let p = P0.p;
        let p0i = P0.p0i;
        let R2 = P0.R2;
        let Rx = mp_Rx31(slen as u32, p, p0i, R2);
        mp_mkgm(logn, P0.g, p, p0i, gm);
        // ft <- NTT(f)
        // gt <- NTT(g)
        // This is already done if use_sub_ntt is true
        if !use_sub_ntt {
            for i in 0..n {
                ft[i] = zint_mod_small_signed(&ft[i..], slen, n, p, p0i, R2, Rx);
                gt[i] = zint_mod_small_signed(&gt[i..], slen, n, p, p0i, R2, Rx);
            }
            mp_NTT(logn, ft, gm, p, p0i);
            mp_NTT(logn, gt, gm, p, p0i);
        }
        // t1 <- NTT(F)
        // t2 <- NTT(G)
        for i in 0..n {
            t1[i] = zint_mod_small_signed(&Ft[i..], slen, n, p, p0i, R2, Rx);
            t2[i] = zint_mod_small_signed(&Gt[i..], slen, n, p, p0i, R2, Rx);
        }
        mp_NTT(logn, t1, gm, p, p0i);
        mp_NTT(logn, t2, gm, p, p0i);
        // Compute f*G - g*F, in NTT representation. If the solution is
        // correct, then this should yield the constant polynomial q,
        // whose NTT coefficients are all equal to q. Since we are
        // going to use Montgomery multiplications, we need to compare
        // the results with q/R mod p_0.
        let rv = mp_mmul(Q, 1, p, p0i);
        for i in 0..n {
            let x = mp_mmul(ft[i], t2[i], p, p0i);
            let y = mp_mmul(gt[i], t1[i], p, p0i);
            if rv != mp_sub(x, y, p) {
                return false;
            }
        }
    }
    return true;
}
// Solving the NTRU equation, top-level.
fn solve_NTRU_depth0(
    logn: u32,
    f: &[i8],
    g: &[i8],
    tmp_u32: &mut [u32],
    tmp_fxr: &mut [FXR],
) -> bool {
    let n = 1usize << logn;
    let hn = n >> 1;
    // Normally, (F,G) from depth 1 should use one word per coefficient.
    // The code in this function assumes it.
    assert!(MOD_SMALL_BL[1] == 1);
    // At depth 0, all values fit on 30 bits, so we work with a single
    // modulus p.
    let p = P0.p;
    let p0i = P0.p0i;
    let R2 = P0.R2;
    {
        // Layout:
        //   Fd   F from upper level (hn)
        //   Gd   G from upper level (hn)
        //   ft   f (n)
        //   gt   g (n)
        //   gm   helper for NTT
        let (Fd, work) = tmp_u32.split_at_mut(hn);
        let (Gd, work) = work.split_at_mut(hn);
        let (ft, work) = work.split_at_mut(n);
        let (gt, work) = work.split_at_mut(n);
        let (gm, _) = work.split_at_mut(n);
        // Load f and g, convert to RNS+NTT
        mp_mkgm(logn, P0.g, p, p0i, gm);
        poly_mp_set_small(logn, f, p, ft);
        poly_mp_set_small(logn, g, p, gt);
        mp_NTT(logn, ft, gm, p, p0i);
        mp_NTT(logn, gt, gm, p, p0i);
        // Convert Fd and Gd to RNS+NTT
        poly_mp_set(logn - 1, Fd, p);
        poly_mp_set(logn - 1, Gd, p);
        mp_NTT(logn - 1, Fd, gm, p, p0i);
        mp_NTT(logn - 1, Gd, gm, p, p0i);
        // Build the unreduced (F,G) into ft and gt
        for i in 0..hn {
            let fa = ft[(i << 1) + 0];
            let fb = ft[(i << 1) + 1];
            let ga = gt[(i << 1) + 0];
            let gb = gt[(i << 1) + 1];
            let mFd = mp_mmul(Fd[i], R2, p, p0i);
            let mGd = mp_mmul(Gd[i], R2, p, p0i);
            ft[(i << 1) + 0] = mp_mmul(gb, mFd, p, p0i);
            ft[(i << 1) + 1] = mp_mmul(ga, mFd, p, p0i);
            gt[(i << 1) + 0] = mp_mmul(fb, mGd, p, p0i);
            gt[(i << 1) + 1] = mp_mmul(fa, mGd, p, p0i);
        }
    }
    // Reorganize buffers:
    //   Fp   unreduced F (n) (RNS+NTT)
    //   Gp   unreduced G (n) (RNS+NTT)
    //   t1   free (n)
    //   t2   NTT support (gm) (n)
    //   t3   free (n)
    //   t4   free (n)
    tmp_u32.copy_within(n..(3 * n), 0);
    {
        let (Fp, work) = tmp_u32.split_at_mut(n);
        let (Gp, work) = work.split_at_mut(n);
        let (t1, work) = work.split_at_mut(n);
        let (t2, work) = work.split_at_mut(n);
        let (t3, t4) = work.split_at_mut(n);
        // t4 <- f (RNS+NTT)
        poly_mp_set_small(logn, f, p, t4);
        mp_NTT(logn, t4, t2, p, p0i);
        // t1 <- F*adj(f) (RNS+NTT)
        // t3 <- f*adj(f) (RNS+NTT)
        for i in 0..n {
            let w = mp_mmul(t4[(n - 1) - i], R2, p, p0i);
            t1[i] = mp_mmul(w, Fp[i], p, p0i);
            t3[i] = mp_mmul(w, t4[i], p, p0i);
        }
        // t4 <- g (RNS+NTT)
        poly_mp_set_small(logn, g, p, t4);
        mp_NTT(logn, t4, t2, p, p0i);
        // t1 <- t1 + G*adj(g) (RNS+NTT)
        // t3 <- t3 + g*adj(g) (RNS+NTT)
        for i in 0..n {
            let w = mp_mmul(t4[(n - 1) - i], R2, p, p0i);
            t1[i] = mp_add(t1[i], mp_mmul(w, Gp[i], p, p0i), p);
            t3[i] = mp_add(t3[i], mp_mmul(w, t4[i], p, p0i), p);
        }
        // Convert back F*adj(f) + G*adj(g) and f*adj(f) + g*adj(g) to
        // plain representation, and also move f*adj(f) + g*adj(g) to t2.
        mp_mkigm(logn, P0.ig, p, p0i, t4);
        mp_iNTT(logn, t1, t4, p, p0i);
        mp_iNTT(logn, t3, t4, p, p0i);
        for i in 0..n {
            // Note: we do not truncate to 31 bits.
            t1[i] = mp_norm(t1[i], p) as u32;
            t2[i] = mp_norm(t3[i], p) as u32;
        }
    }
    // Current layout:
    //   Fp   unreduced F (RNS+NTT) (n)
    //   Gp   unreduced G (RNS+NTT) (n)
    //   t1   F*adj(f) + G*adj(g) (plain, 32-bit) (n)
    //   t2   f*adj(f) + g*adj(g) (plain, 32-bit) (n)
    // We need to divide t1 by t2, and round the result. We convert
    // them to FFT representation, downscaled by 2^10 (to avoid overflows).
    // We first convert f*adj(f) + g*adj(g), which is self-adjoint;
    // this, its FFT representation only has half-size.
    {
        let (_, work) = tmp_u32.split_at_mut(n);
        let (_, work) = work.split_at_mut(n);
        let (t1, t2) = work.split_at_mut(n);
        let (rt2, rt3) = tmp_fxr.split_at_mut(hn);
        // rt2 <- f*adj(f) + g*adj(g) (FFT, self-adjoint, scaled)
        for i in 0..n {
            let x = ((t2[i] as i32) as i64) << 22;
            rt3[i] = FXR::from_u64_scaled32(x as u64);
        }
        vect_FFT(logn, rt3);
        rt2.copy_from_slice(&rt3[..hn]);
        // rt3 <- F*adj(f) + G*adj(g) (FFT, scaled)
        for i in 0..n {
            let x = ((t1[i] as i32) as i64) << 22;
            rt3[i] = FXR::from_u64_scaled32(x as u64);
        }
        vect_FFT(logn, rt3);
        // Divide F*adj(f) + G*adj(g) by f*adj(f) + g*adj(g), and round
        // the result into t1, with conversion to RNS.
        vect_div_selfadj_fft(logn, rt3, rt2);
        vect_iFFT(logn, rt3);
        for i in 0..n {
            t1[i] = mp_set(rt3[i].round(), p);
        }
    }
    // Current layout:
    //   Fp   unreduced F (RNS+NTT) (n)
    //   Gp   unreduced G (RNS+NTT) (n)
    //   t1   k (RNS) (n)
    //   t2   free (n)
    //   t3   free (n)
    //   t4   free (n)
    {
        let (Fp, work) = tmp_u32.split_at_mut(n);
        let (Gp, work) = work.split_at_mut(n);
        let (t1, work) = work.split_at_mut(n);
        let (t2, work) = work.split_at_mut(n);
        let (t3, t4) = work.split_at_mut(n);
        // Convert k to RNS+NTT.
        mp_mkgm(logn, P0.g, p, p0i, t4);
        mp_NTT(logn, t1, t4, p, p0i);
        // Subtract k*f from F and k*G from G.
        // We also compute f*G - g*F (in RNS+NTT) to check that the solution
        // is correct.
        poly_mp_set_small(logn, f, p, t2);
        poly_mp_set_small(logn, g, p, t3);
        mp_NTT(logn, t2, t4, p, p0i);
        mp_NTT(logn, t3, t4, p, p0i);
        let rv = mp_mmul(Q, 1, p, p0i);
        for i in 0..n {
            let kv = mp_mmul(t1[i], R2, p, p0i);
            Fp[i] = mp_sub(Fp[i], mp_mmul(kv, t2[i], p, p0i), p);
            Gp[i] = mp_sub(Gp[i], mp_mmul(kv, t3[i], p, p0i), p);
            let x = mp_sub(
                mp_mmul(t2[i], Gp[i], p, p0i),
                mp_mmul(t3[i], Fp[i], p, p0i),
                p,
            );
            if x != rv {
                return false;
            }
        }
        // Convert back F and G into normal representation.
        mp_mkigm(logn, P0.ig, p, p0i, t4);
        mp_iNTT(logn, Fp, t4, p, p0i);
        mp_iNTT(logn, Gp, t4, p, p0i);
        poly_mp_norm(logn, Fp, p);
        poly_mp_norm(logn, Gp, p);
    }
    return true;
}
// Inject (f,g) at the top-level: f and g are converted to NTT and
// written into the first 2*n words of tmp[].
fn make_fg_depth0(logn: u32, f: &[i8], g: &[i8], tmp: &mut [u32]) {
    let n = 1usize << logn;
    let p = P0.p;
    let p0i = P0.p0i;
    let (ft, tmp) = tmp.split_at_mut(n);
    let (gt, tmp) = tmp.split_at_mut(n);
    let (gm, _) = tmp.split_at_mut(n);
    poly_mp_set_small(logn, f, p, ft);
    poly_mp_set_small(logn, g, p, gt);
    mp_mkgm(logn, P0.g, p, p0i, gm);
    mp_NTT(logn, ft, gm, p, p0i);
    mp_NTT(logn, gt, gm, p, p0i);
}
// One step of computing (f,g) at a given depth.
// Input: (f,g) of degree 2^(logn_top - depth)
// Output: (f',g') of degree 2^(logn_top - (depth+1))
fn make_fg_step(logn_top: u32, depth: u32, work: &mut [u32]) {
    let logn = logn_top - depth;
    let n = 1usize << logn;
    let hn = n >> 1;
    let slen = MOD_SMALL_BL[depth as usize];
    let tlen = MOD_SMALL_BL[(depth + 1) as usize];
    // Prepare buffers:
    //   fd, gd: output polynomials
    //   fs, gs: source polynomials
    //   gm, igm: buffers for NTT support arrays
    //   data: remaining slots (used for CRT)
    let data = work;
    data.copy_within(0..(2 * n * slen), 2 * hn * tlen);
    let (fd, data) = data.split_at_mut(hn * tlen);
    let (gd, data) = data.split_at_mut(hn * tlen);
    let (fgs, data) = data.split_at_mut(2 * n * slen);
    // First slen words: we use the input values directly, and apply
    // inverse NTT as we go, so that we get the sources in RNS (non-NTT).
    {
        let (fs, gs) = fgs.split_at_mut(n * slen);
        let (igm, _) = data.split_at_mut(n);
        for i in 0..slen {
            let p = PRIMES[i].p;
            let p0i = PRIMES[i].p0i;
            let R2 = PRIMES[i].R2;
            let ks = i * n;
            let kd = i * hn;
            for j in 0..hn {
                fd[kd + j] = mp_mmul(
                    mp_mmul(fs[ks + 2 * j], fs[ks + 2 * j + 1], p, p0i),
                    R2,
                    p,
                    p0i,
                );
                gd[kd + j] = mp_mmul(
                    mp_mmul(gs[ks + 2 * j], gs[ks + 2 * j + 1], p, p0i),
                    R2,
                    p,
                    p0i,
                );
            }
            mp_mkigm(logn, PRIMES[i].ig, p, p0i, igm);
            mp_iNTT(logn, &mut fs[ks..], igm, p, p0i);
            mp_iNTT(logn, &mut gs[ks..], igm, p, p0i);
        }
    }
    // Remaining output words.
    if tlen > slen {
        // fs and gs are in RNS, rebuild them into plain integer coefficients.
        zint_rebuild_CRT(fgs, slen, n, 2, true, data);
        let (fs, gs) = fgs.split_at_mut(n * slen);
        let (gm, data) = data.split_at_mut(n);
        let (t2, _) = data.split_at_mut(n);
        for i in slen..tlen {
            let p = PRIMES[i].p;
            let p0i = PRIMES[i].p0i;
            let R2 = PRIMES[i].R2;
            let Rx = mp_Rx31(slen as u32, p, p0i, R2);
            mp_mkgm(logn, PRIMES[i].g, p, p0i, gm);
            let kd = i * hn;
            for j in 0..n {
                t2[j] = zint_mod_small_signed(&fs[j..], slen, n, p, p0i, R2, Rx);
            }
            mp_NTT(logn, t2, gm, p, p0i);
            for j in 0..hn {
                fd[kd + j] = mp_mmul(mp_mmul(t2[2 * j], t2[2 * j + 1], p, p0i), R2, p, p0i);
            }
            for j in 0..n {
                t2[j] = zint_mod_small_signed(&gs[j..], slen, n, p, p0i, R2, Rx);
            }
            mp_NTT(logn, t2, gm, p, p0i);
            for j in 0..hn {
                gd[kd + j] = mp_mmul(mp_mmul(t2[2 * j], t2[2 * j + 1], p, p0i), R2, p, p0i);
            }
        }
    }
}
// Recompute (f,g) at a given depth.
fn make_fg_intermediate(logn_top: u32, f: &[i8], g: &[i8], depth: u32, work: &mut [u32]) {
    make_fg_depth0(logn_top, f, g, work);
    for d in 0..depth {
        make_fg_step(logn_top, d, work);
    }
}
// Recompute (f, g) at the deepest level. Intermediate (f,g) values
// (below the save threshold) are copied at the end of the work area.
//
// If f is not invertible modulo X^n+1 and modulo p = 2147473409,
// then this function returns false (but everything else is still
// computed); otherwise, this function returns true. There is no such
// test on g.
fn make_fg_deepest(logn: u32, f: &[i8], g: &[i8], mut work: &mut [u32]) -> bool {
    make_fg_depth0(logn, f, g, work);
    // f is now in RNS+NTT; we can test its invertibility by checking
    // that all its NTT coefficients are non-zero.
    let n = 1usize << logn;
    let mut b = 0;
    for i in 0..n {
        b |= work[i].wrapping_sub(1);
    }
    let r = (b >> 31) == 0;
    // Compute all the reduced (f,g) values, saving the intermediate
    // values (except that the highest levels).
    for d in 0..logn {
        make_fg_step(logn, d, work);
        let d2 = d + 1;
        if d2 < logn && d2 >= MIN_SAVE_FG[logn as usize] {
            let slen = MOD_SMALL_BL[d2 as usize];
            let fglen = slen << (logn + 1 - d2);
            let sav_off = work.len() - fglen;
            work.copy_within(0..fglen, sav_off);
            work = &mut work[..sav_off];
        }
    }
    r
}
