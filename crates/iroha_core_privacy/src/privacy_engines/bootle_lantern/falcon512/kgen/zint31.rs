#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
// ========================================================================
// Big integers.
// ========================================================================
// We implement some support for big integers that are represented either
// in base 2^31, or in RNS notation, i.e. modulo a given set of 31-bit
// primes. Both representations use a given, fixed number of words (limbs,
// moduli), set under some heuristic assumptions on how large the numbers
// can get. In base 2^31 representation, limb order is little-endian, and
// two's complement is used for negative numbers. In RNS representation,
// the prime moduli are the first j primes from the mp31::PRIMES table.
//
// The words that make up a big integer are not necessarily consecutive
// in RAM. For some function parameters, a "stride" argument must be
// provided, which is the amount to add to the index of a word in order
// to access the next word in that integer. When a stride is provided for
// a parameter, then the number of words in that value is NOT the size
// of its slice, but inferred from another function parameter (usually,
// the number of words matches the size of the slice of another big
// integer which uses stride 1).
use super::super::table_assets::read_u32_le;
use super::mp31::{PRIMES, mp_add, mp_half, mp_mmul, mp_set_u, mp_sub, tbmask};
// Multiply m by the small value x (non-negative). x MUST be less than 2^31.
// The integer m uses base 2^31 with stride 1, and is modified to receive
// the result. The carry word is returned.
pub fn zint_mul_small(m: &mut [u32], x: u32) -> u32 {
    let mut cc = 0u32;
    for mw in m.iter_mut() {
        let z = u64::from(*mw) * u64::from(x) + u64::from(cc);
        *mw = read_u32_le(&z.to_le_bytes(), 0) & 0x7FFF_FFFF;
        cc = read_u32_le(&(z >> 31).to_le_bytes(), 0);
    }
    cc
}
// Reduce a big integer d modulo a small integer p.
//   d uses base 2^31 with stride 'dstride', dlen elements
//   d is considered unsigned
//   p is prime
//   1.34*2^30 < p < 2^31
//   p0i = -1/p mod 2^32
//   R2 = 2^64 mod p
pub fn zint_mod_small_unsigned(
    digits: &[u32],
    dlen: usize,
    dstride: usize,
    modulus: u32,
    p0i: u32,
    R2: u32,
) -> u32 {
    let mut remainder = 0u32;
    let radix_montgomery = mp_half(R2, modulus); // 2^63 = Montgomery representation of 2^31
    let mut offset = dlen * dstride;
    while offset > 0 {
        offset -= dstride;
        remainder = mp_mmul(remainder, radix_montgomery, modulus, p0i);
        remainder = mp_add(remainder, mp_set_u(digits[offset], modulus), modulus);
    }
    remainder
}
// Reduce a big integer d modulo a small integer p.
//   d uses base 2^31 with stride 'dstride', dlen elements
//   d is considered signed
//   p is prime
//   1.34*2^30 < p < 2^31
//   p0i = -1/p mod 2^32
//   R2 = 2^64 mod p
//   Rx = 2^(31*len(d)) mod p
pub fn zint_mod_small_signed(
    d: &[u32],
    dlen: usize,
    dstride: usize,
    p: u32,
    p0i: u32,
    R2: u32,
    Rx: u32,
) -> u32 {
    if dlen == 0 {
        return 0;
    }
    let r = zint_mod_small_unsigned(d, dlen, dstride, p, p0i, R2);
    mp_sub(r, Rx & (d[dstride * (dlen - 1)] >> 30).wrapping_neg(), p)
}
// Add a*s to d.
//   d uses base 2^31, stride 'dstride', unsigned
//   a uses base 2^31, stride 1, unsigned
//   0 <= s < 2^31
// On input, d[] contains the same number of elements as a[], but it has
// room for one extra word, which is set by this function.
pub fn zint_add_mul_small(
    destination: &mut [u32],
    dstride: usize,
    multiplicand: &[u32],
    scalar: u32,
) {
    let mut cc = 0u32;
    let mut offset = 0;
    for &limb in multiplicand {
        let product =
            u64::from(scalar) * u64::from(limb) + u64::from(destination[offset]) + u64::from(cc);
        destination[offset] = read_u32_le(&product.to_le_bytes(), 0) & 0x7FFF_FFFF;
        offset += dstride;
        cc = read_u32_le(&(product >> 31).to_le_bytes(), 0);
    }
    destination[offset] = cc;
}
// Normalize a modular big integer around 0: if x > floor(m/2), then x is
// replaced with x - m; otherwise, x is untouched. Source x should be
// non-negative and lower than m.
// x has stride 'xstride'. m has stride 1. Both values contain the same
// number of elements.
pub fn zint_norm_zero(value: &mut [u32], xstride: usize, modulus: &[u32]) {
    let mut comparison = 0u32;
    let mut bb = 0u32;
    let mut offset = modulus.len() * xstride;
    let mut index = modulus.len();
    while index > 0 {
        // Get next word of m/2.
        index -= 1;
        let mw = modulus[index];
        let hmw = (mw >> 1) | (bb << 30);
        bb = mw & 1;
        // Get next word of x.
        offset -= xstride;
        let xw = value[offset];
        // We set cc to -1, 0 or 1, depending on whether hmw is lower than,
        // equal to, or greater than xw.
        let cc = hmw.wrapping_sub(xw);
        let cc = (cc.wrapping_neg() >> 31) | tbmask(cc);
        // If comparison != 0 then it is either 1 or -1, and we keep its value
        // (comparison result has already been ascertained). Otherwise,
        // we replace it with cc.
        comparison |= cc & ((comparison & 1).wrapping_sub(1));
    }
    // At this point, comparison = -1, 0 or 1, depending on whether (m-1)/2 is
    // lower than, equal to, or greater than x. We subtract m from x
    // if and only if comparison < 0.
    let mut cc = 0;
    let mk = tbmask(comparison);
    offset = 0;
    for &limb in modulus {
        let xw = value[offset].wrapping_sub(limb & mk).wrapping_sub(cc);
        value[offset] = xw & 0x7FFF_FFFF;
        offset += xstride;
        cc = xw >> 31;
    }
}
// Rebuild several integers from their RNS representation. There are
// 'num_sets' sets of 'n' integers. Within each set, the n integers
// are interleaved, so that words of a given integer occur every n
// slots in RAM (i.e. each integer has stride 'n'). The sets are
// consecutive in RAM. Each integer has xlen elements. Thus, the
// input/output data uses num_sets*n*xlen words in total.
//
// If 'normalized_signed' is true, then the output values are normalized
// into the [-m/2, +m/2] interval (where m is the product of all small
// prime moduli); otherwise, returned values are in [0, m-1].
//
// tmp[] is used to store temporary values and must have size at least
// xlen elements.
pub fn zint_rebuild_CRT(
    xx: &mut [u32],
    xlen: usize,
    n: usize,
    num_sets: usize,
    normalize_signed: bool,
    tmp: &mut [u32],
) {
    tmp[0] = PRIMES[0].p;
    for i in 1..xlen {
        // At entry of each iteration:
        //  - the first i words of each integer have been converted
        //  - the first i words of tmp[] contain the product of the
        //    first i prime moduli (denoted q in later comments)
        let p = PRIMES[i].p;
        let p0i = PRIMES[i].p0i;
        let R2 = PRIMES[i].R2;
        let s = PRIMES[i].s;
        for j in 0..num_sets {
            let set_base = j * (n * xlen);
            for k in 0..n {
                // We are processing x (integer number k in set j).
                // x starts at offset j*(n*xlen) + k and has stride n.
                //
                // Let q_i = prod_{m<i} p_m (the products of the
                // previous primes). At this point, we have rebuilt
                // xq_i = x mod q_i, in the first i elements of x. In
                // element i we have xp_i = x mod p_i. We compute x
                // modulo q_{i+1} as:
                //   xq_{i+1} = xq_i + q_i*(s_i*(xp_i - xq_i) mod p_i)
                // with s_i = 1/q_i mod p_i.
                let xq = &mut xx[set_base + k..];
                let xp = xq[i * n];
                let xr = zint_mod_small_unsigned(xq, i, n, p, p0i, R2);
                let xt = mp_mmul(s, mp_sub(xp, xr, p), p, p0i);
                zint_add_mul_small(xq, n, &tmp[..i], xt);
            }
        }
        // Multiply xq_i (in tmp[]) with p_i to prepare for the next
        // iteration (this is also useful for the last iteration: the
        // product of all small primes is used for signed normalization).
        tmp[i] = zint_mul_small(&mut tmp[0..i], p);
    }
    // Apply signed normalization if requested.
    if normalize_signed {
        for j in 0..num_sets {
            for k in 0..n {
                zint_norm_zero(&mut xx[j * n * xlen + k..], n, &tmp[..xlen]);
            }
        }
    }
}
// Negate a big integer conditionally: value a is replaced with -a if
// ctl == 0xFFFFFFFF; if ctl == 0, then a is unchanged. a[] is in base 2^31,
// stride 1, unsigned.
fn zint_negate(a: &mut [u32], ctl: u32) {
    let m = ctl >> 1;
    let mut cc = ctl & 1;
    for aw in a.iter_mut() {
        let z = (*aw ^ m).wrapping_add(cc);
        cc = z >> 31;
        *aw = z & 0x7FFF_FFFF;
    }
}
// Coefficients of the two outputs of one linear update.
#[derive(Clone, Copy)]
struct LinearFactors {
    xa: i64,
    xb: i64,
    ya: i64,
    yb: i64,
}
// Replace a and b with (a*xa + b*xb)/2^31 and (a*ya + b*yb)/2^31,
// respectively. The low bits are dropped.
// The two values are then replaced with their respective absolute values.
// Returned are (nega, negb):
//   nega    0xFFFFFFFF if (a*xa + b*xb)/2^31 < 0, 0 otherwise
//   negb    0xFFFFFFFF if (a*ya + b*yb)/2^31 < 0, 0 otherwise
// Coefficients xa, xb, ya and yb may range up to 2^31 in absolute value
// (i.e. they are in [-2^31,+2^31], with both limits included).
fn zint_co_lin_div31_abs(a: &mut [u32], b: &mut [u32], factors: LinearFactors) -> (u32, u32) {
    let LinearFactors { xa, xb, ya, yb } = factors;
    let mut cca = 0i64;
    let mut ccb = 0i64;
    let nlen = a.len();
    for i in 0..nlen {
        let aw = a[i];
        let bw = b[i];
        let za = u64::from(aw)
            .wrapping_mul(xa.cast_unsigned())
            .wrapping_add(u64::from(bw).wrapping_mul(xb.cast_unsigned()))
            .wrapping_add(cca.cast_unsigned());
        let zb = u64::from(aw)
            .wrapping_mul(ya.cast_unsigned())
            .wrapping_add(u64::from(bw).wrapping_mul(yb.cast_unsigned()))
            .wrapping_add(ccb.cast_unsigned());
        if i > 0 {
            a[i - 1] = read_u32_le(&za.to_le_bytes(), 0) & 0x7FFF_FFFF;
            b[i - 1] = read_u32_le(&zb.to_le_bytes(), 0) & 0x7FFF_FFFF;
        }
        cca = za.cast_signed() >> 31;
        ccb = zb.cast_signed() >> 31;
    }
    a[nlen - 1] = read_u32_le(&cca.to_le_bytes(), 0) & 0x7FFF_FFFF;
    b[nlen - 1] = read_u32_le(&ccb.to_le_bytes(), 0) & 0x7FFF_FFFF;
    let negative_left = read_u32_le(&(cca >> 63).to_le_bytes(), 0);
    let negative_right = read_u32_le(&(ccb >> 63).to_le_bytes(), 0);
    zint_negate(a, negative_left);
    zint_negate(b, negative_right);
    (negative_left, negative_right)
}
// Finish modular reduction. Rules:
//   if neg == 0xFFFFFFFF, then -m <= a < 0
//   if neg == 0x00000000, then 0 <= a < 2*m
// If neg == 0, then the top word of a[] is allowed to use 32 bits.
fn zint_finish_mod(a: &mut [u32], m: &[u32], neg: u32) {
    // First pass: compare a with m (assuming that neg == 0); cc
    // is set to 1 if a < m, 0 otherwise. Note: if the top word of a
    // uses 32 bits, then subtracting m must yield a 31-bit value,
    // since a < 2*m.
    let mut cc = 0u32;
    for (aw, mw) in a.iter().zip(m) {
        cc = aw.wrapping_sub(*mw).wrapping_sub(cc) >> 31;
    }
    // If neg == 0xFFFFFFFF, then we must add m (regardless of cc).
    // If neg == 0x00000000 and cc == 0, then we must subtract m.
    // If neg == 0x00000000 and cc == 1, then we must do nothing.
    //
    // The loop below conditionally subtracts either m or -m from a.
    // If neg != 0, then the XOR of m[] with 0x7FFFFFFF and the initial
    // carry of 1 turn m into -m in the subtraction, with the net effect
    // of adding m. If neg == 0 and cc == 0, then ym == 0xFFFFFFFF and
    // we subtract m. If neg == 0 and cc == 1, then ym == 0 and the
    // initial carry is 0, hence the value is not modified.
    let xm = neg >> 1;
    let ym = neg | cc.wrapping_sub(1);
    cc = neg & 1;
    for (aw, mw) in a.iter_mut().zip(m) {
        let z = aw.wrapping_sub((*mw ^ xm) & ym).wrapping_sub(cc);
        *aw = z & 0x7FFF_FFFF;
        cc = z >> 31;
    }
}
// Replace a and b with (a*xa + b*xb)/2^31 mod m and
// (a*ya + b*yb)/2^31 mod m, respectively. Modulus m must be odd;
// m0i = -1/m[0] mod 2^31. Coefficients xa, xb, ya and yb must be
// such that:
//    -2^31 <= xa <= +2^31
//    -2^31 <= xb <= +2^31
//    -2^31 <= ya <= +2^31
//    -2^31 <= yb <= +2^31
//    -2^31 <= xa + xb <= +2^31
//    -2^31 <= ya + yb <= +2^31
fn zint_co_lin_mod(a: &mut [u32], b: &mut [u32], m: &[u32], m0i: u32, factors: LinearFactors) {
    let LinearFactors { xa, xb, ya, yb } = factors;
    // These operations are actually four combined Montgomery multiplications.
    let mut cca = 0i64;
    let mut ccb = 0i64;
    let fa = a[0]
        .wrapping_mul(read_u32_le(&xa.to_le_bytes(), 0))
        .wrapping_add(b[0].wrapping_mul(read_u32_le(&xb.to_le_bytes(), 0)))
        .wrapping_mul(m0i)
        & 0x7FFF_FFFF;
    let fb = a[0]
        .wrapping_mul(read_u32_le(&ya.to_le_bytes(), 0))
        .wrapping_add(b[0].wrapping_mul(read_u32_le(&yb.to_le_bytes(), 0)))
        .wrapping_mul(m0i)
        & 0x7FFF_FFFF;
    let nlen = a.len();
    for i in 0..nlen {
        let aw = u64::from(a[i]);
        let bw = u64::from(b[i]);
        let mw = u64::from(m[i]);
        let za = aw
            .wrapping_mul(xa.cast_unsigned())
            .wrapping_add(bw.wrapping_mul(xb.cast_unsigned()))
            .wrapping_add(mw.wrapping_mul(u64::from(fa)))
            .wrapping_add(cca.cast_unsigned());
        let zb = aw
            .wrapping_mul(ya.cast_unsigned())
            .wrapping_add(bw.wrapping_mul(yb.cast_unsigned()))
            .wrapping_add(mw.wrapping_mul(u64::from(fb)))
            .wrapping_add(ccb.cast_unsigned());
        if i > 0 {
            a[i - 1] = read_u32_le(&za.to_le_bytes(), 0) & 0x7FFF_FFFF;
            b[i - 1] = read_u32_le(&zb.to_le_bytes(), 0) & 0x7FFF_FFFF;
        }
        cca = za.cast_signed() >> 31;
        ccb = zb.cast_signed() >> 31;
    }
    a[nlen - 1] = read_u32_le(&cca.to_le_bytes(), 0);
    b[nlen - 1] = read_u32_le(&ccb.to_le_bytes(), 0);
    // The loop computed in a[]:
    //   a*xa + b*xb + m*fa
    // with:
    //   0 <= a <= m-1
    //   0 <= b <= m-1
    //   -2^31 <= xa <= +2^31
    //   -2^31 <= xb <= +2^31
    //   0 <= m <= 2^(31*n)-1
    //   0 <= fa <= 2^31-1
    // For a result z such that:
    //   -2^31*(m-1) <= z <= 2^31*m + (2^31-1)*m
    // and also:
    //   z = 0 mod 2^31
    // yielding a result z/2^31 such that:
    //   -(m - 1) <= z/2^31 <= 2*m - 1
    // Thus, we only need to add m or subtract m once in order to get
    // a fully reduced result (in [0,m-1]).
    zint_finish_mod(a, m, read_u32_le(&(cca >> 63).to_le_bytes(), 0));
    zint_finish_mod(b, m, read_u32_le(&(ccb >> 63).to_le_bytes(), 0));
}
// Given x (odd), compute -1/x mod 2^31.
fn ninv31(x: u32) -> u32 {
    let y = 2u32.wrapping_sub(x);
    let y = y.wrapping_mul(2u32.wrapping_sub(x.wrapping_mul(y)));
    let y = y.wrapping_mul(2u32.wrapping_sub(x.wrapping_mul(y)));
    let y = y.wrapping_mul(2u32.wrapping_sub(x.wrapping_mul(y)));
    let y = y.wrapping_mul(2u32.wrapping_sub(x.wrapping_mul(y)));
    y.wrapping_neg() & 0x7FFF_FFFF
}
// Extended GCD between two positive integers x and y. The two
// integers must be odd. Returned value is 0xFFFFFFFF if the GCD is 1, 0
// otherwise. When 0xFFFFFFFF is returned, arrays u and v are filled with
// values such that:
//   0 <= u <= y
//   0 <= v <= x
//   x*u - y*v = 1
// (Note: u == y is possible only if y == 1; similarly, v == x may
// happen only if x == 1.)
// x and y must use the same number of words.
// The temporary array tmp[] must be large enough to accommodate 4
// extra values with the same size as x and y.
pub fn zint_bezout(u: &mut [u32], v: &mut [u32], x: &[u32], y: &[u32], tmp: &mut [u32]) -> u32 {
    let nlen = x.len();
    if nlen == 0 {
        return 0;
    }
    // Algorithm is basically the optimized binary GCD as described in:
    //    https://eprint.iacr.org/2020/972
    // The paper shows that with registers of size 2*k bits, one can do
    // k-1 inner iterations and get a reduction by k-1 bits. In fact, it
    // also works with registers of 2*k-1 bits (though not 2*k-2; the
    // "upper half" of the approximation must have at least one extra
    // bit). Here, we want to perform 31 inner iterations (since that maps
    // well to Montgomery reduction with our 31-bit words) so we must use
    // 63-bit approximations.
    //
    // We also slightly expand the original algorithm by maintaining four
    // coefficients (u0, u1, v0 and v1) instead of the two coefficients
    // (u, v), because we want a full Bezout relation, not just a modular
    // inverse.
    // We set up integers u0, v0, u1, v1, a and b. Throughout the algorithm,
    // they maintain the following invariants:
    //   a = x*u0 - y*v0
    //   b = x*u1 - y*v1
    //   0 <= a <= x
    //   0 <= b <= y
    //   0 <= u0 < y
    //   0 <= v0 < x
    //   0 <= u1 <= y
    //   0 <= v1 < x
    let u1 = u;
    let v1 = v;
    let (u0, tmp) = tmp.split_at_mut(nlen);
    let (v0, tmp) = tmp.split_at_mut(nlen);
    let (remaining_left, tmp) = tmp.split_at_mut(nlen);
    let (remaining_right, _) = tmp.split_at_mut(nlen);
    // Initial values:
    //   a = x   u0 = 1   v0 = 0
    //   b = y   u1 = y   v1 = x - 1
    remaining_left.copy_from_slice(x);
    remaining_right.copy_from_slice(y);
    u0.fill(0);
    u0[0] = 1;
    u1.copy_from_slice(y);
    v0.fill(0);
    v1.copy_from_slice(x);
    v1[0] = x[0] - 1; // x is odd, so no possible overflow
    // Coefficients for Montgomery reduction.
    let x0i = ninv31(x[0]);
    let y0i = ninv31(y[0]);
    // Each operand is up to 31*nlen bits, and the total is reduced by
    // at least 31 bits at each outer iteration.
    let mut num = 62 * nlen + 31;
    while num >= 31 {
        num -= 31;
        // Extract the top 32 bits of a and b: if j is such that:
        //   2^(j-1) <= max(a,b) < 2^j
        // then we want:
        //   xa = (2^31)*floor(a / 2^(j-32)) + (a mod 2^31)
        //   xb = (2^31)*floor(a / 2^(j-32)) + (b mod 2^31)
        // (if j < 63 then xa = a and xb = b).
        let mut c0 = 0xFFFF_FFFF_u32;
        let mut c1 = 0xFFFF_FFFF_u32;
        let mut cp = 0xFFFF_FFFF_u32;
        let mut a0 = 0u32;
        let mut a1 = 0u32;
        let mut b0 = 0u32;
        let mut b1 = 0u32;
        // Ideally we should use a.iter().zip(b).rev(), but it makes the
        // borrower unhappy later on.
        for i in (0..remaining_left.len()).rev() {
            let aw = remaining_left[i];
            let bw = remaining_right[i];
            a1 ^= c1 & (a1 ^ aw);
            a0 ^= c0 & (a0 ^ aw);
            b1 ^= c1 & (b1 ^ bw);
            b0 ^= c0 & (b0 ^ bw);
            cp = c0;
            c0 = c1;
            c1 &= (((aw | bw) + 0x7FFF_FFFF) >> 31).wrapping_sub(1);
        }
        // Possible situations:
        //   cp = 0, c0 = 0, c1 = 0
        //     j >= 63, top words of a and b are in a0:a1 and b0:b1
        //     (a1 and b1 are highest, a1|b1 != 0)
        //
        //   cp = -1, c0 = 0, c1 = 0
        //     32 <= j <= 62, a0:a1 and b0:b1 contain a and b, exactly
        //
        //   cp = -1, c0 = -1, c1 = 0
        //     j <= 31, a0 and a1 both contain a, b0 and b1 both contain b
        //
        // When j >= 63, we align the top words to ensure that we get the
        // full 32 bits. We also take care to always call lzcnt() with a
        // non-zero operand.
        let leading_shift = lzcnt(a1 | b1 | ((cp & c0) >> 1));
        let ha = (a1 << leading_shift) | (a0 >> (31 - leading_shift));
        let hb = (b1 << leading_shift) | (b0 >> (31 - leading_shift));
        // If j <= 62, then we instead use the non-aligned bits.
        let ha = ha ^ (cp & (ha ^ a1));
        let hb = hb ^ (cp & (hb ^ b1));
        // If j <= 31, then all of the above was bad, and we simply
        // clear the upper bits.
        let ha = ha & !c0;
        let hb = hb & !c0;
        // Assemble the approximate values xa and xb (63 bits each).
        let mut xa = (u64::from(ha) << 31) | u64::from(remaining_left[0]);
        let mut xb = (u64::from(hb) << 31) | u64::from(remaining_right[0]);
        // Compute reduction factors:
        //   a' = a*f0 + b*g0
        //   b' = a*f1 + b*g1
        // such that a' and b' are both multiples of 2^31, but are only
        // marginally larger than a and b.
        // Each coefficient is in the -(2^31-1)..+2^31 range. To keep them
        // on 32-bit values, we compute pa+(2^31-1)... and so on.
        // As noted in the paper (section A.1), after 31 iterations,
        // we have |f0| + |g0| <= 2^31, and also |f1| + |g1| <= 2^31,
        // which fits in the usage conditions of zint_co_lin_div31_abs()
        // and zint_co_lin_mod().
        let mut fg0 = 1u64;
        let mut fg1 = 1u64 << 32;
        for _ in 0..31 {
            let a_odd = (xa & 1).wrapping_neg();
            let swap = a_odd & ((xa.wrapping_sub(xb).cast_signed() >> 63).cast_unsigned());
            let t1 = swap & (xa ^ xb);
            xa ^= t1;
            xb ^= t1;
            let t2 = swap & (fg0 ^ fg1);
            fg0 ^= t2;
            fg1 ^= t2;
            xa = xa.wrapping_sub(a_odd & xb);
            fg0 = fg0.wrapping_sub(a_odd & fg1);
            xa >>= 1;
            fg1 <<= 1;
        }
        // Split update factors.
        fg0 = fg0.wrapping_add(0x7FFF_FFFF_7FFF_FFFF);
        fg1 = fg1.wrapping_add(0x7FFF_FFFF_7FFF_FFFF);
        let f0 = i64::from(read_u32_le(&fg0.to_le_bytes(), 0)) - 0x7FFF_FFFF;
        let g0 = i64::from(read_u32_le(&fg0.to_le_bytes(), 4)) - 0x7FFF_FFFF;
        let f1 = i64::from(read_u32_le(&fg1.to_le_bytes(), 0)) - 0x7FFF_FFFF;
        let g1 = i64::from(read_u32_le(&fg1.to_le_bytes(), 4)) - 0x7FFF_FFFF;
        // Apply the update factors.
        let (negative_left, negative_right) = zint_co_lin_div31_abs(
            remaining_left,
            remaining_right,
            LinearFactors {
                xa: f0,
                xb: g0,
                ya: f1,
                yb: g1,
            },
        );
        let f0 = f0 - ((f0 + f0) & (i64::from(negative_left) | (i64::from(negative_left) << 32)));
        let g0 = g0 - ((g0 + g0) & (i64::from(negative_left) | (i64::from(negative_left) << 32)));
        let f1 = f1 - ((f1 + f1) & (i64::from(negative_right) | (i64::from(negative_right) << 32)));
        let g1 = g1 - ((g1 + g1) & (i64::from(negative_right) | (i64::from(negative_right) << 32)));
        zint_co_lin_mod(
            u0,
            u1,
            y,
            y0i,
            LinearFactors {
                xa: f0,
                xb: g0,
                ya: f1,
                yb: g1,
            },
        );
        zint_co_lin_mod(
            v0,
            v1,
            x,
            x0i,
            LinearFactors {
                xa: f0,
                xb: g0,
                ya: f1,
                yb: g1,
            },
        );
    }
    // b contains GCD(x,y), provided that x and y were indeed odd.
    // Result is correct if the GCD is 1.
    let mut status = remaining_right[0] ^ 1;
    let mut right_nonunit = y[0] ^ 1;
    for (&limb, &right_limb) in remaining_right[1..].iter().zip(&y[1..]) {
        status |= limb;
        right_nonunit |= right_limb;
    }
    // Reduction modulo one erases u, but the integer Bezout relation still
    // needs u = 1 and v = x - 1. Select those coefficients without branching
    // on the secret inputs; all nonunit results retain their original values.
    let right_unit = ((right_nonunit | right_nonunit.wrapping_neg()) >> 31).wrapping_sub(1);
    u1[0] ^= right_unit & (u1[0] ^ 1);
    v1[0] ^= right_unit & (v1[0] ^ (x[0] - 1));
    for ((u_limb, v_limb), &left_limb) in u1[1..].iter_mut().zip(&mut v1[1..]).zip(&x[1..]) {
        *u_limb &= !right_unit;
        *v_limb ^= right_unit & (*v_limb ^ left_limb);
    }
    status |= (x[0] & y[0] & 1) ^ 1;
    ((status | status.wrapping_neg()) >> 31).wrapping_sub(1)
}
// lzcnt(x) returns the number of leading zero bits of x. This function
// assumes that x != 0. There are dedicated opcodes for this operation
// on x86 (bsr and lzcnt) and aarch64 (clz); they are constant-time for
// all CPUs we care about. On other architectures, we use a slower but
// safe function. On RISC-V, there is an appropriate opcode in the Zbb
// extension, which is not part of the default riscv64 architecture.
//
// Note: on x86 without lzcnt, x.leading_zeros() uses bsr but has a
// conditional for the case of a zero input, that bsr does not handle
// properly; since we always use it with a non-zero input, this does not
// contradict constant-time discipline.
#[cfg(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm64ec"
))]
const fn lzcnt(x: u32) -> u32 {
    x.leading_zeros()
}
#[cfg(not(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm64ec"
)))]
const fn lzcnt(x: u32) -> u32 {
    lzcnt_portable(x)
}
#[cfg(any(
    test,
    not(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "arm64ec"
    ))
))]
const fn lzcnt_portable(x: u32) -> u32 {
    let m = tbmask((x >> 16).wrapping_sub(1));
    let s = m & 16;
    let x = (x >> 16) ^ (m & (x ^ (x >> 16)));
    let m = tbmask((x >> 8).wrapping_sub(1));
    let s = s | (m & 8);
    let x = (x >> 8) ^ (m & (x ^ (x >> 8)));
    let m = tbmask((x >> 4).wrapping_sub(1));
    let s = s | (m & 4);
    let x = (x >> 4) ^ (m & (x ^ (x >> 4)));
    let m = tbmask((x >> 2).wrapping_sub(1));
    let s = s | (m & 2);
    let x = (x >> 2) ^ (m & (x ^ (x >> 2)));
    // At this point, x fits on 2 bits. Number of leading zeros is then:
    //   x = 0   -> 2
    //   x = 1   -> 1
    //   x = 2   -> 0
    //   x = 3   -> 0
    s.wrapping_add(2u32.wrapping_sub(x) & (x.wrapping_sub(3) >> 2))
}
// bitlength(x) returns the length of x, in bits. The bit length of
// zero is zero.
//
// On recent x86, the lzcnt opcode can be used; it can be assumed to be
// constant-time, and it properly handles an input of zero. We access that
// opcode through the standard leading_zeros() function. Similarly, on
// aarch64, the clz opcode is appropriate.
//
// On older x86, the bsr opcode is used, but it does not support an input
// of zero, and we thus have to use an extra trick to handle that case.
//
// On systems which are neither x86 nor aarch64, we fallback to our generic
// lzcnt() function.
#[cfg(any(
    all(target_arch = "x86", target_feature = "lzcnt"),
    all(target_arch = "x86_64", target_feature = "lzcnt"),
    target_arch = "aarch64",
    target_arch = "arm64ec",
))]
pub const fn bitlength(x: u32) -> u32 {
    32 - x.leading_zeros()
}
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    not(target_feature = "lzcnt")
))]
pub const fn bitlength(x: u32) -> u32 {
    (31 + ((x | x.wrapping_neg()) >> 31)) - (x | 1).leading_zeros()
}
#[cfg(not(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm64ec"
)))]
pub const fn bitlength(x: u32) -> u32 {
    32 - lzcnt(x)
}
/// A binary shift split at the 31-bit limb boundary.
#[derive(Clone, Copy)]
pub struct ZintShift {
    /// Number of whole 31-bit limbs.
    pub words: u32,
    /// Remaining shift, from 0 through 30 bits.
    pub bits: u32,
}
// Add k*(2^sc)*y to x. Slices x and y do not necessarily have the same
// length, but x MUST NOT be shorter than y. Result is truncated (if
// needed) to the size of x. Scale factor sc is provided by shift, with
// sc = 31*shift.words + shift.bits and shift.bits in the 0 to 30 range.
//
// x and y are considered signed (using two's complement). They do not
// necessarily have the same length, but they share the same stride
// ('xystride'). Factor k is itself signed.
pub fn zint_add_scaled_mul_small(
    destination: &mut [u32],
    xlen: usize,
    source: &[u32],
    ylen: usize,
    xystride: usize,
    factor: i32,
    shift: ZintShift,
) {
    let ZintShift {
        words: sch,
        bits: scl,
    } = shift;
    let sch = sch as usize;
    if ylen == 0 || sch >= xlen {
        return;
    }
    let ysign = (source[(ylen - 1) * xystride] >> 30).wrapping_neg() >> 1;
    let mut tw = 0u32;
    let mut cc = 0i32;
    let ija = sch * xystride;
    let mut offset = ija;
    for u in sch..xlen {
        let source_offset = offset - ija;
        let wy = if u < (sch + ylen) {
            source[source_offset]
        } else {
            ysign
        };
        let wys = ((wy << scl) & 0x7FFF_FFFF) | tw;
        tw = wy >> (31 - scl);
        let sum =
            i64::from(wys) * i64::from(factor) + i64::from(destination[offset]) + i64::from(cc);
        destination[offset] = read_u32_le(&sum.to_le_bytes(), 0) & 0x7FFF_FFFF;
        cc = read_u32_le(&(sum >> 31).to_le_bytes(), 0).cast_signed();
        offset += xystride;
    }
}
// Subtract (2^sc)*y from x. Slices x and y do not necessarily have the same
// length, but x MUST NOT be shorter than y. x and y share the same stride
// ('xystride'). Result is truncated (if needed) to the size of x. Scale
// factor sc is provided by shift, with sc = 31*shift.words + shift.bits
// and shift.bits in the 0 to 30 range.
//
// x and y are considered signed (using two's complement).
pub fn zint_sub_scaled(
    destination: &mut [u32],
    xlen: usize,
    source: &[u32],
    ylen: usize,
    xystride: usize,
    shift: ZintShift,
) {
    let ZintShift {
        words: sch,
        bits: scl,
    } = shift;
    let sch = sch as usize;
    if ylen == 0 || sch >= xlen {
        return;
    }
    let ysign = (source[(ylen - 1) * xystride] >> 30).wrapping_neg() >> 1;
    let mut tw = 0u32;
    let mut cc = 0u32;
    let ija = sch * xystride;
    let mut offset = ija;
    for u in sch..xlen {
        let source_offset = offset - ija;
        let wy = if u < (sch + ylen) {
            source[source_offset]
        } else {
            ysign
        };
        let wys = ((wy << scl) & 0x7FFF_FFFF) | tw;
        tw = wy >> (31 - scl);
        let difference = destination[offset].wrapping_sub(wys).wrapping_sub(cc);
        destination[offset] = difference & 0x7FFF_FFFF;
        cc = difference >> 31;
        offset += xystride;
    }
}
// ========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const RADIX: i128 = 1 << 31;
    const SENTINEL: u32 = 0xA55A_1234;

    fn encode(value: i128, count: usize, stride: usize) -> Vec<u32> {
        let mut encoded = vec![SENTINEL; count * stride];
        let mut quotient = value;
        for index in 0..count {
            encoded[index * stride] =
                u32::try_from(quotient.rem_euclid(RADIX)).expect("31-bit limb");
            quotient = quotient.div_euclid(RADIX);
        }
        encoded
    }

    fn unsigned(encoded: &[u32], count: usize, stride: usize) -> i128 {
        (0..count).rev().fold(0, |value, index| {
            let limb = encoded[index * stride];
            assert!(limb < 1 << 31);
            value * RADIX + i128::from(limb)
        })
    }

    fn signed(encoded: &[u32], count: usize, stride: usize) -> i128 {
        let value = unsigned(encoded, count, stride);
        if encoded[(count - 1) * stride] & (1 << 30) == 0 {
            value
        } else {
            value - RADIX.pow(u32::try_from(count).expect("small test width"))
        }
    }

    fn gcd(mut left: i128, mut right: i128) -> i128 {
        while right != 0 {
            (left, right) = (right, left % right);
        }
        left
    }

    fn inverse(value: i128, modulus: i128) -> i128 {
        let (mut previous, mut current) = (modulus, value);
        let (mut previous_coefficient, mut current_coefficient) = (0, 1);
        while current != 0 {
            let quotient = previous / current;
            (previous, current) = (current, previous - quotient * current);
            (previous_coefficient, current_coefficient) = (
                current_coefficient,
                previous_coefficient - quotient * current_coefficient,
            );
        }
        assert_eq!(previous, 1);
        previous_coefficient.rem_euclid(modulus)
    }

    fn factors() -> [LinearFactors; 5] {
        let radix = i64::try_from(RADIX).expect("31-bit radix");
        [
            LinearFactors {
                xa: radix,
                xb: 0,
                ya: 0,
                yb: radix,
            },
            LinearFactors {
                xa: -radix,
                xb: 0,
                ya: 0,
                yb: -radix,
            },
            LinearFactors {
                xa: 1,
                xb: -1,
                ya: -1,
                yb: 1,
            },
            LinearFactors {
                xa: radix / 2,
                xb: -radix / 2,
                ya: -radix / 2,
                yb: radix / 2,
            },
            LinearFactors {
                xa: 0,
                xb: radix,
                ya: radix,
                yb: 0,
            },
        ]
    }

    #[test]
    fn small_products_and_strided_accumulation_match_wide_integer_carries() {
        let modulus = RADIX.pow(3);
        for value in [0, 1, RADIX - 1, RADIX, RADIX.pow(2) - 1, modulus - 1] {
            for scalar in [0, 1, 2, 0x3FFF_FFFF, 0x7FFF_FFFF] {
                let mut limbs = encode(value, 3, 1);
                let carry = zint_mul_small(&mut limbs, scalar);
                let expected = value * i128::from(scalar);
                assert_eq!(unsigned(&limbs, 3, 1), expected % modulus);
                assert_eq!(i128::from(carry), expected / modulus);
                let mut destination = encode(modulus - 1, 4, 2);
                zint_add_mul_small(&mut destination, 2, &encode(value, 3, 1), scalar);
                assert_eq!(unsigned(&destination, 4, 2), modulus - 1 + expected);
                assert!(
                    destination
                        .iter()
                        .skip(1)
                        .step_by(2)
                        .all(|&limb| limb == SENTINEL)
                );
            }
        }
        assert_eq!(zint_mul_small(&mut [], 0x7FFF_FFFF), 0);
        let mut extra_word = [SENTINEL];
        zint_add_mul_small(&mut extra_word, 1, &[], 0x7FFF_FFFF);
        assert_eq!(extra_word, [0]);
    }

    #[test]
    fn signed_moduli_normalization_and_interleaved_crt_match_integer_remainders() {
        let product: i128 = PRIMES[..3]
            .iter()
            .map(|prime| i128::from(prime.p))
            .product();
        let values = [0, 1, product / 2, product / 2 + 1, product - 2, product - 1];
        let mut residues = vec![0; 18];
        for (index, &value) in values.iter().enumerate() {
            for (limb, prime) in PRIMES[..3].iter().enumerate() {
                residues[(index / 3) * 9 + limb * 3 + index % 3] =
                    u32::try_from(value % i128::from(prime.p)).expect("prime residue");
            }
            let mut normalized = encode(value, 3, 2);
            zint_norm_zero(&mut normalized, 2, &encode(product, 3, 1));
            let expected = if value > product / 2 {
                value - product
            } else {
                value
            };
            assert_eq!(signed(&normalized, 3, 2), expected);
            assert!(
                normalized
                    .iter()
                    .skip(1)
                    .step_by(2)
                    .all(|&limb| limb == SENTINEL)
            );
            for prime in &PRIMES[..3] {
                let rx = u32::try_from(RADIX.pow(3) % i128::from(prime.p)).expect("radix residue");
                assert_eq!(
                    i128::from(zint_mod_small_signed(
                        &normalized,
                        3,
                        2,
                        prime.p,
                        prime.p0i,
                        prime.R2,
                        rx
                    )),
                    expected.rem_euclid(i128::from(prime.p)),
                );
                assert_eq!(
                    i128::from(zint_mod_small_unsigned(
                        &encode(value, 3, 2),
                        3,
                        2,
                        prime.p,
                        prime.p0i,
                        prime.R2
                    )),
                    value % i128::from(prime.p),
                );
            }
        }
        for normalize in [false, true] {
            let mut rebuilt = residues.clone();
            let mut temporary = [0; 3];
            zint_rebuild_CRT(&mut rebuilt, 3, 3, 2, normalize, &mut temporary);
            assert_eq!(unsigned(&temporary, 3, 1), product);
            for (index, &value) in values.iter().enumerate() {
                let slice = &rebuilt[(index / 3) * 9 + index % 3..];
                if normalize {
                    let expected = if value > product / 2 {
                        value - product
                    } else {
                        value
                    };
                    assert_eq!(signed(slice, 3, 3), expected);
                } else {
                    assert_eq!(unsigned(slice, 3, 3), value);
                }
            }
        }
    }

    #[test]
    fn conditional_negation_propagates_carry_across_zero_limbs() {
        for width in 1..=4 {
            let modulus = RADIX.pow(u32::try_from(width).expect("small test width"));
            for value in [0, 1, RADIX - 1, RADIX, RADIX.pow(2), modulus - 1] {
                let value = value % modulus;
                for control in [0, u32::MAX] {
                    let mut limbs = encode(value, width, 1);
                    zint_negate(&mut limbs, control);
                    let expected = if control == 0 {
                        value
                    } else {
                        (-value).rem_euclid(modulus)
                    };
                    assert_eq!(
                        unsigned(&limbs, width, 1),
                        expected,
                        "width={width}, value={value}, control={control}"
                    );
                }
            }
        }
    }

    #[test]
    fn linear_updates_preserve_signed_quotients_and_modular_inverses() {
        for left in [0, 1, RADIX - 1, RADIX, RADIX.pow(2) - 1] {
            for right in [0, 1, RADIX - 1, RADIX + 1, RADIX.pow(2) - 1] {
                for transform in factors() {
                    let mut first = encode(left, 2, 1);
                    let mut second = encode(right, 2, 1);
                    let expected_first = (left * i128::from(transform.xa)
                        + right * i128::from(transform.xb))
                    .div_euclid(RADIX);
                    let expected_second = (left * i128::from(transform.ya)
                        + right * i128::from(transform.yb))
                    .div_euclid(RADIX);
                    let signs = zint_co_lin_div31_abs(&mut first, &mut second, transform);
                    assert_eq!(
                        unsigned(&first, 2, 1),
                        expected_first.abs(),
                        "left={left}, right={right}, xa={}, xb={}",
                        transform.xa,
                        transform.xb
                    );
                    assert_eq!(
                        unsigned(&second, 2, 1),
                        expected_second.abs(),
                        "left={left}, right={right}, ya={}, yb={}",
                        transform.ya,
                        transform.yb
                    );
                    assert_eq!(
                        signs,
                        (
                            u32::from(expected_first < 0).wrapping_neg(),
                            u32::from(expected_second < 0).wrapping_neg()
                        )
                    );
                }
            }
        }
        for modulus in [3, RADIX - 1, RADIX + 1, RADIX.pow(2) - 1] {
            let inverse_radix = inverse(RADIX, modulus);
            let modulus_limbs = encode(modulus, 2, 1);
            let m0i = ninv31(modulus_limbs[0]);
            assert_eq!(
                (u64::from(modulus_limbs[0]) * u64::from(m0i) + 1) % (1 << 31),
                0
            );
            for left in [0, 1, modulus - 1] {
                for right in [0, 1, modulus - 1] {
                    for transform in factors() {
                        let mut first = encode(left, 2, 1);
                        let mut second = encode(right, 2, 1);
                        let expected_first = (left * i128::from(transform.xa)
                            + right * i128::from(transform.xb))
                        .rem_euclid(modulus)
                            * inverse_radix
                            % modulus;
                        let expected_second = (left * i128::from(transform.ya)
                            + right * i128::from(transform.yb))
                        .rem_euclid(modulus)
                            * inverse_radix
                            % modulus;
                        zint_co_lin_mod(&mut first, &mut second, &modulus_limbs, m0i, transform);
                        assert_eq!(unsigned(&first, 2, 1), expected_first);
                        assert_eq!(unsigned(&second, 2, 1), expected_second);
                    }
                }
            }
        }
    }

    #[test]
    fn bezout_masks_and_coefficients_match_independent_euclidean_gcd() {
        let values = [
            1,
            3,
            5,
            15,
            RADIX - 1,
            RADIX + 1,
            RADIX.pow(2) - 3,
            RADIX.pow(2) - 1,
        ];
        for left in values {
            for right in values {
                let mut first = [0; 2];
                let mut second = [0; 2];
                let mut temporary = [0; 8];
                let mask = zint_bezout(
                    &mut first,
                    &mut second,
                    &encode(left, 2, 1),
                    &encode(right, 2, 1),
                    &mut temporary,
                );
                let coprime = gcd(left, right) == 1;
                assert_eq!(mask, u32::from(coprime).wrapping_neg());
                if coprime {
                    let first_value = unsigned(&first, 2, 1);
                    let second_value = unsigned(&second, 2, 1);
                    assert!(first_value <= right);
                    assert!(second_value <= left);
                    assert_eq!(
                        left * first_value - right * second_value,
                        1,
                        "left={left}, right={right}, u={first_value}, v={second_value}"
                    );
                }
            }
        }
        assert_eq!(zint_bezout(&mut [], &mut [], &[], &[], &mut []), 0);
    }

    #[test]
    fn split_shifts_preserve_signed_extension_truncation_and_stride() {
        let modulus = RADIX.pow(3);
        for source_value in [-RADIX / 2, -1, 0, 1, RADIX / 2 - 1] {
            let source = encode(source_value, 1, 2);
            for destination_value in [-modulus / 2, -1, 0, 1, modulus / 2 - 1] {
                for (words, bits) in [(0, 0), (0, 30), (1, 0), (1, 30), (2, 0), (3, 0)] {
                    let shift = ZintShift { words, bits };
                    let scaled = if words < 3 {
                        source_value * (1i128 << (31 * words + bits))
                    } else {
                        0
                    };
                    for factor in [i32::MIN, -1, 0, 1, i32::MAX] {
                        let mut destination = encode(destination_value, 3, 2);
                        zint_add_scaled_mul_small(
                            &mut destination,
                            3,
                            &source,
                            1,
                            2,
                            factor,
                            shift,
                        );
                        assert_eq!(
                            unsigned(&destination, 3, 2),
                            (destination_value + scaled * i128::from(factor)).rem_euclid(modulus)
                        );
                        assert!(
                            destination
                                .iter()
                                .skip(1)
                                .step_by(2)
                                .all(|&limb| limb == SENTINEL)
                        );
                    }
                    let mut destination = encode(destination_value, 3, 2);
                    zint_sub_scaled(&mut destination, 3, &source, 1, 2, shift);
                    assert_eq!(
                        unsigned(&destination, 3, 2),
                        (destination_value - scaled).rem_euclid(modulus)
                    );
                    assert!(
                        destination
                            .iter()
                            .skip(1)
                            .step_by(2)
                            .all(|&limb| limb == SENTINEL)
                    );
                }
            }
        }
        let initial = encode(-1, 3, 2);
        let mut destination = initial.clone();
        zint_add_scaled_mul_small(
            &mut destination,
            3,
            &[],
            0,
            2,
            i32::MIN,
            ZintShift { words: 0, bits: 30 },
        );
        zint_sub_scaled(
            &mut destination,
            3,
            &[],
            0,
            2,
            ZintShift { words: 0, bits: 30 },
        );
        assert_eq!(destination, initial);
    }

    #[test]
    fn portable_leading_zero_body_and_selected_bitlength_match_bit_boundaries() {
        assert_eq!(bitlength(0), 0);
        assert_eq!(32 - lzcnt_portable(0), 0);
        for bit in 0..32 {
            for value in [1u32 << bit, (1u32 << bit) | 1, u32::MAX >> bit] {
                assert_eq!(lzcnt_portable(value), value.leading_zeros());
                assert_eq!(lzcnt(value), value.leading_zeros());
                assert_eq!(bitlength(value), 32 - value.leading_zeros());
            }
        }
    }
}
