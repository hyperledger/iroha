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
    for i in 0..n {
        r &= (tmp[i] as u32).wrapping_sub(Q);
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
        h[i] = mq_div(h[i] as u32, tmp[i] as u32) as u16;
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
#[inline(always)]
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
#[inline(always)]
fn mq_sub(x: u32, y: u32) -> u32 {
    // -(q - 1) <= a <= q - 1
    let a = y.wrapping_sub(x);
    // 0 <= b <= q - 1
    let b = a.wrapping_add(Q & (a >> 16));
    Q - b
}
// Halving modulo q (internal representation).
#[inline(always)]
fn mq_half(x: u32) -> u32 {
    (x + ((x & 1).wrapping_neg() & Q)) >> 1
}
// mq_mred(x) computes x/2^32 mod q, without output in the [1,q] range.
// Input must be such that 1 <= x <= 3489673216. Note that this means
// that we can add up to 23 products together, and mutualize their
// reduction.
#[inline(always)]
fn mq_mred(x: u32) -> u32 {
    let b = x.wrapping_mul(Q1I);
    let c = (b >> 16) * Q;
    (c >> 16) + 1
}
// Montgomery multiplication modulo q (internal representation).
#[inline(always)]
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
    let y160 = mq_mmul(y80, y80);
    let y163 = mq_mmul(y160, y3);
    let y323 = mq_mmul(y163, y160);
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
        let x = (-(f[i] as i32)) as u32;
        d[i] = (Q - x.wrapping_add((x >> 16) & Q)) as u16;
    }
}
/// Given a polynomial in internal representation, convert it to external representation (in-place).
pub fn mqpoly_int_to_ext(logn: u32, a: &mut [u16]) {
    for i in 0..(1usize << logn) {
        // External representation is the same as internal, except that
        // zero is represented by 0 instead of q.
        let x = (a[i] as u32).wrapping_sub(Q);
        a[i] = x.wrapping_add(Q & (x >> 16)) as u16;
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
            let s = GM[i + m] as u32;
            for j in 0..ht {
                let j1 = j0 + j;
                let j2 = j1 + ht;
                let x1 = a[j1] as u32;
                let x2 = mq_mmul(a[j2] as u32, s);
                a[j1] = mq_add(x1, x2) as u16;
                a[j2] = mq_sub(x1, x2) as u16;
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
            let s = iGM[i + hm] as u32;
            for j in 0..t {
                let j1 = j0 + j;
                let j2 = j1 + t;
                let x1 = a[j1] as u32;
                let x2 = a[j2] as u32;
                a[j1] = mq_half(mq_add(x1, x2)) as u16;
                a[j2] = mq_mmul(mq_sub(x1, x2), s) as u16;
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
pub(crate) const GM: [u16; 1024] = MQ_NTT_TABLES.0;
pub(crate) const iGM: [u16; 1024] = MQ_NTT_TABLES.1;
