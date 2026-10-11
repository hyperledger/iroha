//! BN254 field arithmetic with optional SIMD acceleration.
//!
//! Field elements are represented as four little-endian 64-bit limbs. At runtime
//! [`field_dispatch::field_impl`] selects an implementation based on the host CPU features (SSE2,
//! AVX2, AVX-512 or NEON). The scalar routines serve as a portable fallback.
#[path = "bn254_vec/batch.rs"]
mod batch;
#[cfg(any(feature = "cuda", test))]
pub(crate) use batch::BATCH_SIZES;
pub(crate) use batch::BatchOperation;
#[cfg(feature = "cuda")]
pub(crate) use batch::cpu_batch_into;
pub use batch::{add_batch_into, mul_batch_into, sub_batch_into};
#[cfg(feature = "cuda")]
pub(crate) use batch::{canonical, valid_batch};

use crate::field_dispatch::field_impl;
use halo2curves::{bn256::Fr, ff::PrimeField};
/// BN254 field modulus in little-endian limb form.
pub const MODULUS: [u64; 4] = [
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];
/// Field element represented as four 64-bit limbs (little-endian).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElem(pub [u64; 4]);
impl FieldElem {
    /// Whether these limbs are the canonical encoding of a BN254 field value.
    pub fn is_canonical(&self) -> bool {
        batch::canonical(&self.0)
    }
    /// Convert from an `Fr` element.
    pub fn from_fr(f: Fr) -> Self {
        let repr = f.to_repr();
        let bytes = repr.as_ref();
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let mut limb_bytes = [0u8; 8];
            limb_bytes.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            *limb = u64::from_le_bytes(limb_bytes);
        }
        FieldElem(limbs)
    }
    /// Create a field element from a 64-bit value.
    pub fn from_u64(v: u64) -> Self {
        Self::from_fr(Fr::from(v))
    }
    /// Convert back to `Fr`.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_fr(&self) -> Fr {
        let mut bytes = [0u8; 32];
        for (i, limb) in self.0.iter().enumerate() {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        Fr::from_repr(bytes.into()).expect("valid field element")
    }
    /// Convert to a 64-bit value by truncating the field representation.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_u64(&self) -> u64 {
        let fr = self.to_fr();
        let repr = fr.to_repr();
        let b = repr.as_ref();
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    }
}
/// Add two field elements using a portable scalar routine.
///
/// This function is intentionally simple and only meant to provide
/// a baseline implementation until real SIMD versions are available.
pub fn add_scalar(a: FieldElem, b: FieldElem) -> FieldElem {
    let mut out = [0u64; 4];
    let mut carry = 0u128;
    for (i, t) in out.iter_mut().enumerate() {
        let sum = a.0[i] as u128 + b.0[i] as u128 + carry;
        *t = sum as u64;
        carry = sum >> 64;
    }
    reduce_mod(&mut out);
    FieldElem(out)
}
/// Subtract two field elements using a portable scalar routine.
pub fn sub_scalar(a: FieldElem, b: FieldElem) -> FieldElem {
    let mut out = [0u64; 4];
    let mut borrow = 0u128;
    for (i, t) in out.iter_mut().enumerate() {
        let tmp = (a.0[i] as u128).wrapping_sub(b.0[i] as u128 + borrow);
        *t = tmp as u64;
        borrow = (tmp >> 127) & 1;
    }
    let mask = (borrow as u64).wrapping_neg();
    let mut carry = 0u128;
    for i in 0..4 {
        let sum = out[i] as u128 + ((MODULUS[i] & mask) as u128) + carry;
        out[i] = sum as u64;
        carry = sum >> 64;
    }
    FieldElem(out)
}
/// Multiply two field elements using the halo2curves implementation.
pub fn mul_scalar(a: FieldElem, b: FieldElem) -> FieldElem {
    FieldElem::from_fr(a.to_fr() * b.to_fr())
}
/// Multiply two field elements and return the unreduced 512-bit result.
pub fn wide_mul(a: FieldElem, b: FieldElem) -> [u64; 8] {
    let mut acc = [0u128; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let idx = i + j;
            let t = acc[idx] + (a.0[i] as u128) * (b.0[j] as u128) + carry;
            acc[idx] = t & 0xffff_ffff_ffff_ffff;
            carry = t >> 64;
        }
        acc[i + 4] += carry;
    }
    for i in 0..7 {
        let carry = acc[i] >> 64;
        acc[i] &= 0xffff_ffff_ffff_ffff;
        if i + 1 < 8 {
            acc[i + 1] += carry;
        }
    }
    let mut out = [0u64; 8];
    for (o, a) in out.iter_mut().zip(acc.iter()) {
        *o = *a as u64;
    }
    out
}
/// Reduce a 512-bit value modulo the BN254 prime.
pub fn reduce_wide(val: [u64; 8]) -> [u64; 4] {
    // Convert to a 512-bit integer and reduce with the existing variable-time routine.
    use crypto_bigint::{Encoding, NonZero, U256, U512};
    const MOD_BYTES: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
    const MODULUS: U256 = U256::from_be_hex(MOD_BYTES);
    let mut bytes = [0u8; 64];
    for i in 0..8 {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&val[i].to_le_bytes());
    }
    let wide = U512::from_le_bytes(bytes);
    let (lo, hi) = wide.split();
    let modulus_nz = NonZero::new(MODULUS).expect("BN254 modulus must be non-zero");
    let reduced = U256::rem_wide_vartime((lo, hi), &modulus_nz);
    // crypto_bigint words follow the target pointer width. Preserve our four-u64
    // representation on both 32-bit and 64-bit targets through its byte encoding.
    let bytes = reduced.to_le_bytes();
    let mut limbs = [0u64; 4];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
        let mut encoded = [0u8; 8];
        encoded.copy_from_slice(chunk);
        *limb = u64::from_le_bytes(encoded);
    }
    limbs
}
/// Add one field-element pair on the selected CPU/SIMD backend.
///
/// A single operation cannot amortize CUDA transfer and launch costs. CUDA
/// is selected automatically by the caller-owned batch helpers.
pub fn add(a: FieldElem, b: FieldElem) -> FieldElem {
    field_impl().add(a, b)
}
/// Subtract two field elements using the selected SIMD backend.
pub fn sub(a: FieldElem, b: FieldElem) -> FieldElem {
    field_impl().sub(a, b)
}
/// Multiply two field elements using the selected SIMD backend.
pub fn mul(a: FieldElem, b: FieldElem) -> FieldElem {
    field_impl().mul(a, b)
}
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn add_sse2(a: FieldElem, b: FieldElem) -> FieldElem {
    // Load two 128-bit chunks and add them with SSE2. Carry is propagated
    // separately to assemble the full 256-bit sum.
    use std::arch::x86_64::*;
    let mut tmp = [0u64; 4];
    unsafe {
        let lo_a = _mm_loadu_si128(a.0.as_ptr() as *const __m128i);
        let lo_b = _mm_loadu_si128(b.0.as_ptr() as *const __m128i);
        let hi_a = _mm_loadu_si128(a.0.as_ptr().add(2) as *const __m128i);
        let hi_b = _mm_loadu_si128(b.0.as_ptr().add(2) as *const __m128i);
        let lo = _mm_add_epi64(lo_a, lo_b);
        let hi = _mm_add_epi64(hi_a, hi_b);
        _mm_storeu_si128(tmp.as_mut_ptr() as *mut __m128i, lo);
        _mm_storeu_si128(tmp.as_mut_ptr().add(2) as *mut __m128i, hi);
    }
    let mut carry = 0u64;
    for (i, limb) in tmp.iter_mut().enumerate() {
        let partial = *limb;
        let carry_ab = (partial < a.0[i]) as u64;
        let (sum_with_carry, carry_prev) = partial.overflowing_add(carry);
        *limb = sum_with_carry;
        carry = carry_ab | (carry_prev as u64);
    }
    if geq(&tmp, &MODULUS) {
        sub_mod(&mut tmp, &MODULUS);
    }
    FieldElem(tmp)
}
// Compute a borrow chain and conditionally add the modulus when the
// result underflows.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn sub_sse2(a: FieldElem, b: FieldElem) -> FieldElem {
    use std::arch::x86_64::*;
    let mut tmp = [0u64; 4];
    unsafe {
        let lo_a = _mm_loadu_si128(a.0.as_ptr() as *const __m128i);
        let lo_b = _mm_loadu_si128(b.0.as_ptr() as *const __m128i);
        let hi_a = _mm_loadu_si128(a.0.as_ptr().add(2) as *const __m128i);
        let hi_b = _mm_loadu_si128(b.0.as_ptr().add(2) as *const __m128i);
        let lo = _mm_sub_epi64(lo_a, lo_b);
        let hi = _mm_sub_epi64(hi_a, hi_b);
        _mm_storeu_si128(tmp.as_mut_ptr() as *mut __m128i, lo);
        _mm_storeu_si128(tmp.as_mut_ptr().add(2) as *mut __m128i, hi);
    }
    let mut borrow = 0u64;
    for (i, limb) in tmp.iter_mut().enumerate() {
        let partial = *limb;
        let borrow_ab = (a.0[i] < b.0[i]) as u64;
        let (adjusted, borrow_prev) = partial.overflowing_sub(borrow);
        *limb = adjusted;
        borrow = borrow_ab | (borrow_prev as u64);
    }
    if borrow != 0 {
        let mut carry = 0u128;
        for i in 0..4 {
            let sum = tmp[i] as u128 + MODULUS[i] as u128 + carry;
            tmp[i] = sum as u64;
            carry = sum >> 64;
        }
    }
    FieldElem(tmp)
}
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn mul_sse2(a: FieldElem, b: FieldElem) -> FieldElem {
    use std::arch::x86_64::*;
    #[inline(always)]
    fn mul_u64(x: u64, y: u64) -> u128 {
        unsafe {
            let xl = _mm_cvtsi64_si128(x as i64);
            let yl = _mm_cvtsi64_si128(y as i64);
            let xh = _mm_srli_epi64(xl, 32);
            let yh = _mm_srli_epi64(yl, 32);
            let ll = _mm_mul_epu32(xl, yl);
            let lh = _mm_mul_epu32(xl, yh);
            let hl = _mm_mul_epu32(xh, yl);
            let hh = _mm_mul_epu32(xh, yh);
            let ll_u = _mm_cvtsi128_si64(ll) as u64;
            let lh_u = _mm_cvtsi128_si64(lh) as u64;
            let hl_u = _mm_cvtsi128_si64(hl) as u64;
            let hh_u = _mm_cvtsi128_si64(hh) as u64;
            (ll_u as u128)
                + ((lh_u as u128) << 32)
                + ((hl_u as u128) << 32)
                + ((hh_u as u128) << 64)
        }
    }
    let mut acc = [0u128; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let idx = i + j;
            let prod = mul_u64(a.0[i], b.0[j]);
            let t = acc[idx] + prod + carry;
            acc[idx] = t & 0xffff_ffff_ffff_ffff;
            carry = t >> 64;
        }
        acc[i + 4] += carry;
    }
    for i in 0..7 {
        let carry = acc[i] >> 64;
        acc[i] &= 0xffff_ffff_ffff_ffff;
        if i + 1 < 8 {
            acc[i + 1] += carry;
        }
    }
    let mut out = [0u64; 8];
    for i in 0..8 {
        out[i] = acc[i] as u64;
    }
    let reduced = FieldElem(reduce_wide(out));
    let scalar = mul_scalar(a, b);
    assert_eq!(reduced, scalar);
    reduced
}
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn add_avx2(a: FieldElem, b: FieldElem) -> FieldElem {
    use std::arch::x86_64::*;
    let mut tmp = [0u64; 4];
    unsafe {
        let va = _mm256_loadu_si256(a.0.as_ptr() as *const __m256i);
        // Use 256-bit AVX2 vectors to add all limbs in parallel.
        // The scalar carry chain guarantees the result fits in 256 bits.
        let vb = _mm256_loadu_si256(b.0.as_ptr() as *const __m256i);
        let sum = _mm256_add_epi64(va, vb);
        _mm256_storeu_si256(tmp.as_mut_ptr() as *mut __m256i, sum);
    }
    let mut carry = 0u64;
    for (i, t) in tmp.iter_mut().enumerate().take(4) {
        let partial = *t;
        let carry_ab = (partial < a.0[i]) as u64;
        let (sum_with_carry, carry_prev) = partial.overflowing_add(carry);
        *t = sum_with_carry;
        carry = carry_ab | (carry_prev as u64);
    }
    if geq(&tmp, &MODULUS) {
        sub_mod(&mut tmp, &MODULUS);
    }
    FieldElem(tmp)
}
// After the vector subtraction borrow is resolved in scalar and the modulus
// is added back if needed.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn sub_avx2(a: FieldElem, b: FieldElem) -> FieldElem {
    use std::arch::x86_64::*;
    let mut tmp = [0u64; 4];
    unsafe {
        let va = _mm256_loadu_si256(a.0.as_ptr() as *const __m256i);
        let vb = _mm256_loadu_si256(b.0.as_ptr() as *const __m256i);
        let diff = _mm256_sub_epi64(va, vb);
        _mm256_storeu_si256(tmp.as_mut_ptr() as *mut __m256i, diff);
    }
    let mut borrow = 0u64;
    for (i, t) in tmp.iter_mut().enumerate().take(4) {
        let partial = *t;
        let borrow_ab = (a.0[i] < b.0[i]) as u64;
        let (adjusted, borrow_prev) = partial.overflowing_sub(borrow);
        *t = adjusted;
        borrow = borrow_ab | (borrow_prev as u64);
    }
    if borrow != 0 {
        let mut carry = 0u128;
        for i in 0..4 {
            let s = tmp[i] as u128 + MODULUS[i] as u128 + carry;
            tmp[i] = s as u64;
            carry = s >> 64;
        }
    }
    FieldElem(tmp)
}
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn mul_avx2(a: FieldElem, b: FieldElem) -> FieldElem {
    // Reuse SSE2 implementation; AVX2 lacks 64-bit multiply.
    unsafe { mul_sse2(a, b) }
}
#[cfg(target_arch = "x86_64")]
unsafe fn add_avx512(a: FieldElem, b: FieldElem) -> FieldElem {
    // AVX-512 intrinsics are unstable on stable Rust. Use the AVX2 path.
    unsafe { add_avx2(a, b) }
}
#[cfg(target_arch = "x86_64")]
unsafe fn sub_avx512(a: FieldElem, b: FieldElem) -> FieldElem {
    // AVX-512 intrinsics are unstable on stable Rust. Use the AVX2 path.
    unsafe { sub_avx2(a, b) }
}
#[cfg(target_arch = "x86_64")]
unsafe fn mul_avx512(a: FieldElem, b: FieldElem) -> FieldElem {
    // Use SSE2 path for AVX-512 as well.
    unsafe { mul_sse2(a, b) }
}
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
// Two 128-bit NEON vectors handle the four limbs; carries are fixed up in scalar.
unsafe fn add_neon(a: FieldElem, b: FieldElem) -> FieldElem {
    use std::arch::aarch64::*;
    let mut tmp = [0u64; 4];
    unsafe {
        let va = vld1q_u64(a.0.as_ptr());
        let vb = vld1q_u64(b.0.as_ptr());
        let sum0 = vaddq_u64(va, vb);
        vst1q_u64(tmp.as_mut_ptr(), sum0);
        let va1 = vld1q_u64(a.0.as_ptr().add(2));
        let vb1 = vld1q_u64(b.0.as_ptr().add(2));
        let sum1 = vaddq_u64(va1, vb1);
        vst1q_u64(tmp.as_mut_ptr().add(2), sum1);
    }
    let mut carry = 0u64;
    for (i, t) in tmp.iter_mut().enumerate().take(4) {
        let partial = *t;
        let carry_ab = (partial < a.0[i]) as u64;
        let (sum_with_carry, carry_prev) = partial.overflowing_add(carry);
        *t = sum_with_carry;
        carry = carry_ab | (carry_prev as u64);
    }
    reduce_mod(&mut tmp);
    FieldElem(tmp)
}
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
// Subtract using NEON then correct the result with a scalar borrow chain.
unsafe fn sub_neon(a: FieldElem, b: FieldElem) -> FieldElem {
    use std::arch::aarch64::*;
    let mut tmp = [0u64; 4];
    unsafe {
        let va = vld1q_u64(a.0.as_ptr());
        let vb = vld1q_u64(b.0.as_ptr());
        let diff0 = vsubq_u64(va, vb);
        vst1q_u64(tmp.as_mut_ptr(), diff0);
        let va1 = vld1q_u64(a.0.as_ptr().add(2));
        let vb1 = vld1q_u64(b.0.as_ptr().add(2));
        let diff1 = vsubq_u64(va1, vb1);
        vst1q_u64(tmp.as_mut_ptr().add(2), diff1);
    }
    let mut borrow = 0u64;
    for (i, t) in tmp.iter_mut().enumerate().take(4) {
        let partial = *t;
        let borrow_ab = (a.0[i] < b.0[i]) as u64;
        let (adjusted, borrow_prev) = partial.overflowing_sub(borrow);
        *t = adjusted;
        borrow = borrow_ab | (borrow_prev as u64);
    }
    // Resolve borrow and add the modulus if the subtraction underflowed.
    let mask = borrow.wrapping_neg();
    let mut carry = 0u128;
    for i in 0..4 {
        let s = tmp[i] as u128 + ((MODULUS[i] & mask) as u128) + carry;
        tmp[i] = s as u64;
        carry = s >> 64;
    }
    FieldElem(tmp)
}
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn mul_neon(a: FieldElem, b: FieldElem) -> FieldElem {
    use std::arch::aarch64::*;
    #[inline(always)]
    unsafe fn mul_u64_neon(x: u64, y: u64) -> u128 {
        let x_parts = [x as u32, (x >> 32) as u32];
        let y_parts = [y as u32, (y >> 32) as u32];
        let vx = unsafe { vld1_u32(x_parts.as_ptr()) };
        let vy = unsafe { vld1_u32(y_parts.as_ptr()) };
        let prod = unsafe { vmull_u32(vx, vy) };
        let cross = unsafe { vmull_u32(vx, vrev64_u32(vy)) };
        let ll = unsafe { vgetq_lane_u64(prod, 0) };
        let hh = unsafe { vgetq_lane_u64(prod, 1) };
        let cross0 = unsafe { vgetq_lane_u64(cross, 0) };
        let cross1 = unsafe { vgetq_lane_u64(cross, 1) };
        (ll as u128) + ((u128::from(cross0) + u128::from(cross1)) << 32) + ((hh as u128) << 64)
    }
    const MASK: u128 = 0xffff_ffff_ffff_ffff;
    let mut acc = [0u128; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let idx = i + j;
            let prod = unsafe { mul_u64_neon(a.0[i], b.0[j]) };
            let tmp = acc[idx] + prod + carry;
            acc[idx] = tmp & MASK;
            carry = tmp >> 64;
        }
        acc[i + 4] += carry;
    }
    for limb in 0..7 {
        let carry = acc[limb] >> 64;
        acc[limb] &= MASK;
        if limb + 1 < 8 {
            acc[limb + 1] += carry;
        }
    }
    let mut wide = [0u64; 8];
    for (dst, src) in wide.iter_mut().zip(acc.iter()) {
        *dst = *src as u64;
    }
    FieldElem(reduce_wide(wide))
}
#[cfg(target_arch = "x86_64")]
fn geq(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] {
            return true;
        } else if a[i] < b[i] {
            return false;
        }
    }
    true
}
#[cfg(target_arch = "x86_64")]
fn sub_mod(target: &mut [u64; 4], modulus: &[u64; 4]) {
    let mut borrow = 0u128;
    for i in 0..4 {
        let tmp = (target[i] as u128).wrapping_sub(modulus[i] as u128 + borrow);
        target[i] = tmp as u64;
        borrow = (tmp >> 127) & 1; // high bit indicates borrow
    }
}
fn sub_mod_checked(a: &[u64; 4], modulus: &[u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0u64; 4];
    let mut borrow = 0u128;
    for i in 0..4 {
        let tmp = (a[i] as u128).wrapping_sub(modulus[i] as u128 + borrow);
        out[i] = tmp as u64;
        borrow = (tmp >> 127) & 1;
    }
    (out, borrow as u64)
}
fn reduce_mod(a: &mut [u64; 4]) {
    let (tmp, borrow) = sub_mod_checked(a, &MODULUS);
    let mask = borrow.wrapping_sub(1);
    for i in 0..4 {
        a[i] = (tmp[i] & mask) | (a[i] & !mask);
    }
}
#[cfg(target_arch = "aarch64")]
use crate::NeonField;
use crate::{Avx2Field, Avx512Field, FieldArithmetic, ScalarField, Sse2Field};
impl FieldArithmetic for ScalarField {
    fn add(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        add_scalar(a, b)
    }
    fn sub(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        sub_scalar(a, b)
    }
    fn mul(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        mul_scalar(a, b)
    }
}
#[cfg(target_arch = "x86_64")]
impl FieldArithmetic for Sse2Field {
    fn add(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        unsafe { add_sse2(a, b) }
    }
    fn sub(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        unsafe { sub_sse2(a, b) }
    }
    fn mul(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        unsafe { mul_sse2(a, b) }
    }
}
#[cfg(not(target_arch = "x86_64"))]
impl FieldArithmetic for Sse2Field {
    fn add(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        // SSE2 intrinsics are unavailable on this architecture.
        // Use the scalar fallback implementation.
        add_scalar(a, b)
    }
    fn sub(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        sub_scalar(a, b)
    }
    fn mul(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        mul_scalar(a, b)
    }
}
#[cfg(target_arch = "x86_64")]
impl FieldArithmetic for Avx2Field {
    fn add(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        unsafe { add_avx2(a, b) }
    }
    fn sub(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        unsafe { sub_avx2(a, b) }
    }
    fn mul(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        unsafe { mul_avx2(a, b) }
    }
}
#[cfg(not(target_arch = "x86_64"))]
impl FieldArithmetic for Avx2Field {
    fn add(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        // AVX2 is not available on this architecture; using scalar fallback.
        add_scalar(a, b)
    }
    fn sub(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        sub_scalar(a, b)
    }
    fn mul(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        mul_scalar(a, b)
    }
}
#[cfg(target_arch = "x86_64")]
impl FieldArithmetic for Avx512Field {
    fn add(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        unsafe { add_avx512(a, b) }
    }
    fn sub(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        unsafe { sub_avx512(a, b) }
    }
    fn mul(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        unsafe { mul_avx512(a, b) }
    }
}
#[cfg(not(target_arch = "x86_64"))]
impl FieldArithmetic for Avx512Field {
    fn add(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        // AVX-512 is unavailable on this architecture, so we use the
        // scalar implementation instead.
        add_scalar(a, b)
    }
    fn sub(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        sub_scalar(a, b)
    }
    fn mul(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        mul_scalar(a, b)
    }
}
#[cfg(target_arch = "aarch64")]
impl FieldArithmetic for NeonField {
    fn add(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        unsafe { add_neon(a, b) }
    }
    fn sub(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        unsafe { sub_neon(a, b) }
    }
    fn mul(&self, a: FieldElem, b: FieldElem) -> FieldElem {
        unsafe { mul_neon(a, b) }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_arch = "aarch64")]
    use halo2curves::bn256::Fr;
    #[cfg(target_arch = "aarch64")]
    use rand_core::{RngCore, impls::fill_bytes_via_next};
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn mul_sse2_matches_scalar() {
        if std::is_x86_feature_detected!("sse2") {
            let a = FieldElem::from_u64(5);
            let b = FieldElem::from_u64(7);
            assert_eq!(unsafe { mul_sse2(a, b) }, mul_scalar(a, b));
        }
    }
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn mul_avx2_matches_scalar() {
        if std::is_x86_feature_detected!("avx2") {
            let a = FieldElem::from_u64(9);
            let b = FieldElem::from_u64(11);
            assert_eq!(unsafe { mul_avx2(a, b) }, mul_scalar(a, b));
        }
    }
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn mul_avx512_matches_scalar() {
        if std::is_x86_feature_detected!("avx512f") {
            let a = FieldElem::from_u64(13);
            let b = FieldElem::from_u64(15);
            assert_eq!(unsafe { mul_avx512(a, b) }, mul_scalar(a, b));
        }
    }
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn mul_neon_matches_scalar() {
        if !std::arch::is_aarch64_feature_detected!("neon") {
            return;
        }
        let specials = [
            FieldElem([0, 0, 0, 0]),
            FieldElem::from_u64(1),
            FieldElem::from_fr(-Fr::one()),
            FieldElem::from_fr(Fr::from(17u64)),
            FieldElem::from_fr(Fr::from(u64::MAX)),
        ];
        for &lhs in &specials {
            for &rhs in &specials {
                assert_eq!(
                    unsafe { mul_neon(lhs, rhs) },
                    mul_scalar(lhs, rhs),
                    "lhs={lhs:?} rhs={rhs:?}"
                );
            }
        }
        struct DeterministicRng(u64);
        impl RngCore for DeterministicRng {
            fn next_u32(&mut self) -> u32 {
                self.next_u64() as u32
            }
            fn next_u64(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x << 7;
                x ^= x >> 9;
                x = x.wrapping_mul(0x9e37_79b9_7f4a_7c15);
                self.0 = x;
                x
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                fill_bytes_via_next(self, dest);
            }
        }
        let mut rng = DeterministicRng(0xdecafbad_d00df00d);
        for _ in 0..128 {
            let a = FieldElem::from_fr(Fr::from(rng.next_u64()));
            let b = FieldElem::from_fr(Fr::from(rng.next_u64()));
            assert_eq!(
                unsafe { mul_neon(a, b) },
                mul_scalar(a, b),
                "lhs={a:?} rhs={b:?}"
            );
        }
    }
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn add_sse2_carry_matches_scalar() {
        if std::is_x86_feature_detected!("sse2") {
            let a = FieldElem([u64::MAX, u64::MAX, 1, 0]);
            let b = FieldElem([1, 0, u64::MAX, 0]);
            assert_eq!(unsafe { add_sse2(a, b) }, add_scalar(a, b));
        }
    }
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sub_sse2_borrow_matches_scalar() {
        if std::is_x86_feature_detected!("sse2") {
            let a = FieldElem([0, 0, 1, 0]);
            let b = FieldElem([1, 0, 0, 0]);
            assert_eq!(unsafe { sub_sse2(a, b) }, sub_scalar(a, b));
        }
    }
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn add_neon_carry_matches_scalar() {
        if std::arch::is_aarch64_feature_detected!("neon") {
            let a = FieldElem([u64::MAX, u64::MAX, 5, 0]);
            let b = FieldElem([1, 0, u64::MAX, 0]);
            assert_eq!(unsafe { add_neon(a, b) }, add_scalar(a, b));
        }
    }
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn sub_neon_borrow_matches_scalar() {
        if std::arch::is_aarch64_feature_detected!("neon") {
            let a = FieldElem([0, 1, 0, 0]);
            let b = FieldElem([1, 1, 0, 0]);
            assert_eq!(unsafe { sub_neon(a, b) }, sub_scalar(a, b));
        }
    }
}
