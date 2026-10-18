//! Strict-positive `u64` amount proofs for FCMP++ outputs.
//!
//! FCMP++ proves full-chain membership and rerandomization of consumed
//! commitments; it does not itself prove that newly created commitments encode
//! bounded amounts.  This module supplies the missing `RingCT` relation with one
//! aggregate Monero Bulletproofs+ proof.  For every output commitment `C` the
//! proof contains both `C` and `C - H` in its ordered public statement.  A
//! 64-bit range proof for both points proves that the hidden amount is in `1..=u64::MAX`: the first
//! relation establishes the upper bound and the second excludes zero.
//!
//! The equations and Monero generator derivation are a native port of the
//! MIT-licensed `monero-bulletproofs` implementation by Luke Parker at Serai
//! commit `971951a1a66014fce5a943b4c78fc24c63187dbb`.  Iroha adds an explicit
//! transcript domain, the complete typed-statement digest, and the ordered
//! output commitments before the standard Figure-3 challenges.  Proofs cannot
//! therefore be transplanted across pools, assets, roots, transactions, or output orderings.
use super::{
    FCMP_MAX_OUTPUTS_NATIVE_V1, FcmpNativeErrorV1, FcmpOutputTupleV1,
    field::{
        Field25519, decode_edwards_point, encode_field25519, field25519_from_u64,
        field25519_is_zero, invert_field25519, monero_varint, validate_edwards_scalar,
    },
};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::{Identity as _, IsIdentity as _, MultiscalarMul as _, VartimeMultiscalarMul as _},
};
use p256::elliptic_curve::bigint::{Encoding as _, U256};
use rand_core_06::{CryptoRng, RngCore};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;
use std::{
    ops::{Deref, DerefMut},
    sync::OnceLock,
};
use zeroize::{Zeroize, Zeroizing};
/// Upstream revision used for the native Bulletproofs+ equation port.
pub const FCMP_BP_PLUS_UPSTREAM_REVISION_V1: &str = "971951a1a66014fce5a943b4c78fc24c63187dbb";
/// SHA-256 digest of the complete ordered Monero Bulletproofs+ generator
/// basis used by the bounded first-release profile.
pub const FCMP_BP_PLUS_GENERATOR_DIGEST_V1: [u8; 32] = [
    0xd9, 0xb3, 0xb5, 0xf3, 0x69, 0xf0, 0xa5, 0x91, 0x21, 0xe0, 0xb8, 0x5b, 0xdf, 0xba, 0x17, 0x14,
    0xd7, 0x65, 0xd0, 0xa2, 0x86, 0x7d, 0x6e, 0x9b, 0x17, 0x46, 0x4e, 0xbf, 0x84, 0x5d, 0xba, 0x13,
];
/// Exact hidden amount width.
pub const FCMP_AMOUNT_BITS_V1: usize = 64;
/// Each output contributes `C` and `C-H` to exclude zero.
pub const FCMP_RANGE_COMMITMENTS_PER_OUTPUT_V1: usize = 2;
/// Maximum public commitments in the strict-positive aggregate proof.
pub const FCMP_MAX_RANGE_COMMITMENTS_V1: usize =
    FCMP_MAX_OUTPUTS_NATIVE_V1 * FCMP_RANGE_COMMITMENTS_PER_OUTPUT_V1;
const BP_PLUS_GENERATOR_DOMAIN_V1: &[u8] = b"bulletproof_plus";
const BP_PLUS_TRANSCRIPT_DOMAIN_V1: &[u8] = b"bulletproof_plus_transcript";
const IROHA_RANGE_BINDING_DOMAIN_V1: &[u8] = b"iroha.privacy.fcmp.bp-plus.strict-positive-u64.v1";
const GENERATOR_DIGEST_DOMAIN_V1: &[u8] = b"iroha.privacy.fcmp.bp-plus.generator-basis.v1";
const MAX_SCALAR_SAMPLING_ATTEMPTS_V1: usize = 128;
const MAX_PROVER_RESTARTS_V1: usize = 128;
struct RangeSecretCopyValueV1<T: Copy + Zeroize>(T);
struct BorrowedRangeCopySlotV1<'a, T: Copy + Zeroize>(&'a mut T);
impl<T: Copy + Zeroize> BorrowedRangeCopySlotV1<'_, T> {
    fn expose_copy(&self) -> T {
        *self.0
    }
}
impl<T: Copy + Zeroize> Drop for BorrowedRangeCopySlotV1<'_, T> {
    fn drop(&mut self) {
        self.0.zeroize();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(&mut *self.0);
    }
}
impl<T: Copy + Zeroize> RangeSecretCopyValueV1<T> {
    fn new(mut value: T) -> Self {
        Self::take(&mut value)
    }
    fn copy_from_ref(value: &T) -> Self {
        Self::from_copy(*value)
    }
    fn from_copy(mut value: T) -> Self {
        Self::take(&mut value)
    }
    fn take(value: &mut T) -> Self {
        let incoming = BorrowedRangeCopySlotV1(value);
        let owned = Self(incoming.expose_copy());
        drop(incoming);
        owned
    }
    fn expose_copy(&self) -> T {
        self.0
    }
    fn expose_ref(&self) -> &T {
        &self.0
    }
}
impl<T: Copy + Zeroize> Drop for RangeSecretCopyValueV1<T> {
    fn drop(&mut self) {
        self.0.zeroize();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(&mut self.0);
        #[cfg(test)]
        let _ = RANGE_SECRET_COPY_OWNER_DROPS_V1.try_with(|drops| {
            drops.set(drops.get().saturating_add(1));
        });
    }
}
#[cfg(test)]
std::thread_local! {
    #[cfg(test)]
    static RANGE_SECRET_COPY_OWNER_DROPS_V1: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}
// Monero's amount generator H.
const MONERO_H_BYTES_V1: [u8; 32] = [
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
];
/// Pending insertion guard for one private value not yet owned by a vector.
struct PendingZeroizingValue<T: Zeroize>(Option<T>);
impl<T: Zeroize> PendingZeroizingValue<T> {
    fn new(value: T) -> Self {
        Self(Some(value))
    }
    fn take(&mut self) -> Result<T, FcmpNativeErrorV1> {
        self.0
            .take()
            .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)
    }
}
impl<T: Zeroize> Drop for PendingZeroizingValue<T> {
    fn drop(&mut self) {
        if let Some(value) = &mut self.0 {
            value.zeroize();
        }
    }
}
/// Exact-capacity owner for prover-secret vectors.
///
/// Storage is reserved before the first secret copy is accepted. The logical capacity is public
/// proof-shape data; the separately remembered allocation capacity lets every insertion assert that
/// no reallocation occurred. Drop clears the complete allocation on success, error, and unwind.
struct ExactSizeZeroizingVec<T: Zeroize> {
    values: Vec<T>,
    exact_capacity: usize,
    allocation_capacity: usize,
}
impl<T: Zeroize> ExactSizeZeroizingVec<T> {
    fn new(exact_capacity: usize) -> Result<Self, FcmpNativeErrorV1> {
        let mut values = Vec::new();
        values
            .try_reserve_exact(exact_capacity)
            .map_err(|_| FcmpNativeErrorV1::RangeArithmeticInvariant)?;
        let allocation_capacity = values.capacity();
        if allocation_capacity < exact_capacity {
            return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
        }
        Ok(Self {
            values,
            exact_capacity,
            allocation_capacity,
        })
    }
    fn len(&self) -> usize {
        self.values.len()
    }
    fn is_full(&self) -> bool {
        self.len() == self.exact_capacity
    }
    fn push_owned(&mut self, value: T) -> Result<(), FcmpNativeErrorV1> {
        let mut value = PendingZeroizingValue::new(value);
        if self.len() >= self.exact_capacity {
            return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
        }
        debug_assert_eq!(self.values.capacity(), self.allocation_capacity);
        self.values.push(value.take()?);
        debug_assert_eq!(self.values.capacity(), self.allocation_capacity);
        Ok(())
    }
    fn extend_from_slice(&mut self, values: &[T]) -> Result<(), FcmpNativeErrorV1>
    where
        T: Copy,
    {
        let end = self
            .len()
            .checked_add(values.len())
            .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
        if end > self.exact_capacity {
            return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
        }
        debug_assert_eq!(self.values.capacity(), self.allocation_capacity);
        self.values.extend_from_slice(values);
        debug_assert_eq!(self.values.capacity(), self.allocation_capacity);
        Ok(())
    }
}
impl<T: Copy + Zeroize> ExactSizeZeroizingVec<T> {
    fn push_copy(&mut self, mut value: T) -> Result<(), FcmpNativeErrorV1> {
        let value = RangeSecretCopyValueV1::take(&mut value);
        if self.len() >= self.exact_capacity {
            return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
        }
        debug_assert_eq!(self.values.capacity(), self.allocation_capacity);
        self.values.push(value.expose_copy());
        debug_assert_eq!(self.values.capacity(), self.allocation_capacity);
        drop(value);
        Ok(())
    }
}
impl<T: Zeroize> Deref for ExactSizeZeroizingVec<T> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
impl<T: Zeroize> DerefMut for ExactSizeZeroizingVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.values
    }
}
impl<T: Zeroize> Drop for ExactSizeZeroizingVec<T> {
    fn drop(&mut self) {
        // `Vec::zeroize` clears every initialized element and the complete
        // allocation capacity. Keeping that stronger guarantee matters when
        // an allocator grants more than the requested exact logical shape.
        self.values.zeroize();
    }
}
struct ScalarVector(ExactSizeZeroizingVec<Scalar>);
impl ScalarVector {
    fn with_capacity(len: usize) -> Result<Self, FcmpNativeErrorV1> {
        ExactSizeZeroizingVec::new(len).map(Self)
    }
    fn from_slice(values: &[Scalar]) -> Result<Self, FcmpNativeErrorV1> {
        let mut result = Self::with_capacity(values.len())?;
        result.0.extend_from_slice(values)?;
        Ok(result)
    }
    fn try_clone(&self) -> Result<Self, FcmpNativeErrorV1> {
        Self::from_slice(&self.0)
    }
    fn zero(len: usize) -> Result<Self, FcmpNativeErrorV1> {
        let mut vector = Self::with_capacity(len)?;
        for _ in 0..len {
            vector.0.push_copy(Scalar::ZERO)?;
        }
        Ok(vector)
    }
    fn powers(mut value: Scalar, len: usize) -> Result<Self, FcmpNativeErrorV1> {
        let value = RangeSecretCopyValueV1::take(&mut value);
        if len == 0 {
            return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
        }
        let mut powers = Self::with_capacity(len)?;
        powers.0.push_copy(Scalar::ONE)?;
        for index in 1..len {
            powers
                .0
                .push_copy(&powers.0[index - 1] * value.expose_ref())?;
        }
        Ok(powers)
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn add_scalar(mut self, mut scalar: Scalar) -> Self {
        let scalar = RangeSecretCopyValueV1::take(&mut scalar);
        for value in self.0.iter_mut() {
            *value = &*value + scalar.expose_ref();
        }
        self
    }
    fn sub_scalar(mut self, mut scalar: Scalar) -> Self {
        let scalar = RangeSecretCopyValueV1::take(&mut scalar);
        for value in self.0.iter_mut() {
            *value = &*value - scalar.expose_ref();
        }
        self
    }
    fn mul_scalar(mut self, mut scalar: Scalar) -> Self {
        let scalar = RangeSecretCopyValueV1::take(&mut scalar);
        for value in self.0.iter_mut() {
            *value = &*value * scalar.expose_ref();
        }
        self
    }
    fn add_vector(mut self, other: &Self) -> Result<Self, FcmpNativeErrorV1> {
        if self.len() != other.len() {
            return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
        }
        for (left, right) in self.0.iter_mut().zip(other.0.iter()) {
            *left += right;
        }
        Ok(self)
    }
    fn mul_vector(mut self, other: &Self) -> Result<Self, FcmpNativeErrorV1> {
        if self.len() != other.len() {
            return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
        }
        for (left, right) in self.0.iter_mut().zip(other.0.iter()) {
            *left *= right;
        }
        Ok(self)
    }
    fn sum(&self) -> Zeroizing<Scalar> {
        let mut sum = Zeroizing::new(Scalar::ZERO);
        for value in self.0.iter() {
            *sum += value;
        }
        sum
    }
    fn weighted_inner_product(
        self,
        other: &Self,
        weights: &Self,
    ) -> Result<Zeroizing<Scalar>, FcmpNativeErrorV1> {
        Ok(self.mul_vector(other)?.mul_vector(weights)?.sum())
    }
    fn truncate(&mut self, len: usize) -> Result<(), FcmpNativeErrorV1> {
        if len > self.len() {
            return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
        }
        if len != self.len() {
            // Allocate the new public final size before copying its secret
            // prefix. Replacing `self` then clears the complete old allocation
            // through Drop, including the discarded suffix.
            *self = Self::from_slice(&self.0[..len])?;
        }
        Ok(())
    }
    fn split(self) -> Result<(Self, Self), FcmpNativeErrorV1> {
        if self.len() <= 1 || self.len() % 2 != 0 {
            return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
        }
        let half = self.len() / 2;
        // Reserve both public final sizes before copying either secret half.
        let mut left = Self::with_capacity(half)?;
        let mut right = Self::with_capacity(half)?;
        left.0.extend_from_slice(&self.0[..half])?;
        right.0.extend_from_slice(&self.0[half..])?;
        Ok((left, right))
    }
}
#[derive(Clone)]
struct PointVector(Vec<EdwardsPoint>);
impl PointVector {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn split(mut self) -> Result<(Self, Self), FcmpNativeErrorV1> {
        if self.len() <= 1 || self.len() % 2 != 0 {
            return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
        }
        let right = self.0.split_off(self.len() / 2);
        Ok((self, Self(right)))
    }
}
#[derive(Clone)]
struct BpPlusGenerators {
    g_bold: Vec<EdwardsPoint>,
    h_bold: Vec<EdwardsPoint>,
}
impl BpPlusGenerators {
    fn reduce(&self, count: usize) -> Result<Self, FcmpNativeErrorV1> {
        let count = count
            .max(1)
            .checked_next_power_of_two()
            .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
        if count > self.g_bold.len() || count > self.h_bold.len() {
            return Err(FcmpNativeErrorV1::RangeOutputCount {
                actual: count / FCMP_AMOUNT_BITS_V1,
                max: FCMP_MAX_OUTPUTS_NATIVE_V1,
            });
        }
        Ok(Self {
            g_bold: self.g_bold[..count].to_vec(),
            h_bold: self.h_bold[..count].to_vec(),
        })
    }
    fn len(&self) -> usize {
        self.g_bold.len()
    }
}
static AMOUNT_GENERATOR: OnceLock<Result<EdwardsPoint, FcmpNativeErrorV1>> = OnceLock::new();
static BP_PLUS_GENERATORS: OnceLock<Result<BpPlusGenerators, FcmpNativeErrorV1>> = OnceLock::new();
static BP_PLUS_TRANSCRIPT_PREFIX: OnceLock<Result<[u8; 32], FcmpNativeErrorV1>> = OnceLock::new();
pub(super) fn amount_generator() -> Result<EdwardsPoint, FcmpNativeErrorV1> {
    *AMOUNT_GENERATOR.get_or_init(|| decode_edwards_point(MONERO_H_BYTES_V1, false))
}
fn keccak256(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}
fn hash_to_scalar(parts: &[&[u8]]) -> Result<Scalar, FcmpNativeErrorV1> {
    let mut hasher = Keccak256::new();
    for part in parts {
        hasher.update(part);
    }
    let scalar = Scalar::from_bytes_mod_order(hasher.finalize().into());
    if scalar == Scalar::ZERO {
        return Err(FcmpNativeErrorV1::RangeChallengeZero);
    }
    Ok(scalar)
}
/// Monero's historical `hash_to_ec`, retained exactly for its BP+ basis.
fn monero_hash_to_point(bytes: [u8; 32]) -> Result<EdwardsPoint, FcmpNativeErrorV1> {
    let mut hashed_bytes = keccak256(&bytes);
    let high_bit = hashed_bytes[31] >> 7;
    hashed_bytes[31] &= 0x7f;
    let mut reduced = U256::from_le_bytes(hashed_bytes);
    if high_bit == 1 {
        // 2^255 = 19 (mod 2^255-19).
        reduced = reduced.wrapping_add(&U256::from(19_u8));
    }
    let modulus =
        U256::from_be_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
    if reduced >= modulus {
        reduced = reduced.wrapping_sub(&modulus);
    }
    let square = Field25519::new(&reduced).square();
    let v = square + square;
    let w = v + Field25519::ONE;
    let a = field25519_from_u64(486_662);
    let x_polynomial = w.square() - (a.square() * v);
    // The upstream construction deliberately shadows `v` with the
    // denominator polynomial inside this block.  Using the hash-derived
    // `v` here instead maps to an invalid Edwards encoding.
    let polynomial_v = x_polynomial;
    let v3 = polynomial_v * polynomial_v * polynomial_v;
    let uv3 = w * v3;
    let v7 = v3 * v3 * polynomial_v;
    let uv7 = w * v7;
    let inverse_eight = invert_field25519(field25519_from_u64(8))
        .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
    let exponent = (-field25519_from_u64(5) * inverse_eight).retrieve();
    let x_candidate = uv3 * uv7.pow(&exponent);
    let x = x_candidate.square() * x_polynomial;
    let first_y = w - x;
    let alternate_y = w + x;
    let sign = !field25519_is_zero(first_y) && !field25519_is_zero(alternate_y);
    let z = -a * if sign { Field25519::ONE } else { v };
    let denominator = z + w;
    let y = (z - w)
        * invert_field25519(denominator).ok_or(FcmpNativeErrorV1::RangeGeneratorDerivation)?;
    let mut encoded = encode_field25519(y);
    encoded[31] |= u8::from(sign) << 7;
    let point = CompressedEdwardsY(encoded)
        .decompress()
        .ok_or(FcmpNativeErrorV1::RangeGeneratorDerivation)?
        .mul_by_cofactor();
    if point.is_identity() || !point.is_torsion_free() {
        return Err(FcmpNativeErrorV1::RangeGeneratorDerivation);
    }
    Ok(point)
}
fn derive_bp_plus_generators() -> Result<BpPlusGenerators, FcmpNativeErrorV1> {
    let amount = amount_generator()?;
    let mut preimage = amount.compress().to_bytes().to_vec();
    preimage.extend_from_slice(BP_PLUS_GENERATOR_DOMAIN_V1);
    let count = FCMP_MAX_RANGE_COMMITMENTS_V1
        .checked_mul(FCMP_AMOUNT_BITS_V1)
        .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
    let mut g_bold = Vec::with_capacity(count);
    let mut h_bold = Vec::with_capacity(count);
    for index in 0..count {
        let doubled = index
            .checked_mul(2)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
        let mut even = preimage.clone();
        even.extend(monero_varint(doubled));
        h_bold.push(monero_hash_to_point(keccak256(&even))?);
        let mut odd = preimage.clone();
        odd.extend(monero_varint(
            doubled
                .checked_add(1)
                .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?,
        ));
        g_bold.push(monero_hash_to_point(keccak256(&odd))?);
    }
    Ok(BpPlusGenerators { g_bold, h_bold })
}
fn bp_plus_generators() -> Result<&'static BpPlusGenerators, FcmpNativeErrorV1> {
    BP_PLUS_GENERATORS
        .get_or_init(derive_bp_plus_generators)
        .as_ref()
        .map_err(Clone::clone)
}
fn transcript_prefix() -> Result<[u8; 32], FcmpNativeErrorV1> {
    *BP_PLUS_TRANSCRIPT_PREFIX.get_or_init(|| {
        monero_hash_to_point(keccak256(BP_PLUS_TRANSCRIPT_DOMAIN_V1))
            .map(|point| point.compress().to_bytes())
    })
}
/// Digest the complete Monero BP+ basis used by the FCMP profile.
pub fn fcmp_bp_plus_generator_digest_v1() -> Result<[u8; 32], FcmpNativeErrorV1> {
    let generators = bp_plus_generators()?;
    let mut hasher = Sha256::new();
    hasher.update(GENERATOR_DIGEST_DOMAIN_V1);
    hasher.update(MONERO_H_BYTES_V1);
    hasher.update(
        u64::try_from(generators.len())
            .map_err(|_| FcmpNativeErrorV1::RangeArithmeticInvariant)?
            .to_be_bytes(),
    );
    for (g, h) in generators.g_bold.iter().zip(&generators.h_bold) {
        hasher.update(g.compress().to_bytes());
        hasher.update(h.compress().to_bytes());
    }
    Ok(hasher.finalize().into())
}
/// Secret opening of one newly created FCMP amount commitment.
pub struct FcmpOutputCommitmentOpeningV1 {
    output: FcmpOutputTupleV1,
    amount: u64,
    mask: Scalar,
}
impl core::fmt::Debug for FcmpOutputCommitmentOpeningV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FcmpOutputCommitmentOpeningV1")
            .field("output", &self.output)
            .finish_non_exhaustive()
    }
}
impl Zeroize for FcmpOutputCommitmentOpeningV1 {
    fn zeroize(&mut self) {
        self.amount.zeroize();
        self.mask.zeroize();
    }
}
impl Drop for FcmpOutputCommitmentOpeningV1 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl FcmpOutputCommitmentOpeningV1 {
    /// Construct one strict-positive `u64` commitment opening.
    pub fn new(
        output: FcmpOutputTupleV1,
        mut amount: u64,
        mut mask: [u8; 32],
    ) -> Result<Self, FcmpNativeErrorV1> {
        let amount = RangeSecretCopyValueV1::take(&mut amount);
        let mask_bytes = RangeSecretCopyValueV1::take(&mut mask);
        Self::from_secret_owners_v1(output, amount, mask_bytes)
    }
    /// Construct an opening from borrowed secrets without creating raw
    /// by-value copies in the caller.
    pub fn new_borrowed(
        output: FcmpOutputTupleV1,
        amount: &u64,
        mask: &[u8; 32],
    ) -> Result<Self, FcmpNativeErrorV1> {
        let amount = RangeSecretCopyValueV1::copy_from_ref(amount);
        let mask_bytes = RangeSecretCopyValueV1::copy_from_ref(mask);
        Self::from_secret_owners_v1(output, amount, mask_bytes)
    }
    fn from_secret_owners_v1(
        output: FcmpOutputTupleV1,
        amount: RangeSecretCopyValueV1<u64>,
        mask_bytes: RangeSecretCopyValueV1<[u8; 32]>,
    ) -> Result<Self, FcmpNativeErrorV1> {
        let mut decoded_mask =
            Option::<Scalar>::from(Scalar::from_canonical_bytes(*mask_bytes.expose_ref()))
                .ok_or(FcmpNativeErrorV1::ScalarEncoding)?;
        let mask = RangeSecretCopyValueV1::take(&mut decoded_mask);
        // Zero is excluded from the amount relation itself. A zero mask is a
        // valid Pedersen opening (although wallets should randomize masks);
        // rejecting it only in this constructor would not create a
        // verifier-enforced property and would make the API disagree with the
        // proof relation.
        if *amount.expose_ref() == 0 {
            return Err(FcmpNativeErrorV1::RangeWitnessOutOfRange);
        }
        let amount_scalar = RangeSecretCopyValueV1::new(Scalar::from(*amount.expose_ref()));
        let amount_component = Zeroizing::new(&amount_generator()? * amount_scalar.expose_ref());
        let mask_component = Zeroizing::new(&ED25519_BASEPOINT_POINT * mask.expose_ref());
        let commitment = Zeroizing::new(&*amount_component + &*mask_component);
        if commitment.compress().to_bytes() != output.components().2 {
            return Err(FcmpNativeErrorV1::RangeCommitmentOpeningMismatch);
        }
        Ok(Self {
            output,
            amount: amount.expose_copy(),
            mask: mask.expose_copy(),
        })
    }
    /// Public tuple opened by this witness.
    #[must_use]
    pub const fn output(&self) -> FcmpOutputTupleV1 {
        self.output
    }
    /// Hidden positive amount.
    #[must_use]
    pub const fn amount(&self) -> &u64 {
        &self.amount
    }
    /// Canonical hidden commitment mask in an owned zeroizing boundary.
    #[must_use]
    pub fn commitment_mask(&self) -> Zeroizing<[u8; 32]> {
        let mut mask_bytes = self.mask.to_bytes();
        let mask_bytes = RangeSecretCopyValueV1::take(&mut mask_bytes);
        let mut owned = Zeroizing::new([0_u8; 32]);
        owned.copy_from_slice(mask_bytes.expose_ref());
        owned
    }
}
/// Canonical aggregate FCMP Bulletproofs+ payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FcmpRangeProofV1 {
    a: [u8; 32],
    wip_a: [u8; 32],
    wip_b: [u8; 32],
    r_answer: [u8; 32],
    s_answer: [u8; 32],
    delta_answer: [u8; 32],
    l: Vec<[u8; 32]>,
    r: Vec<[u8; 32]>,
}
fn padded_range_commitment_count(outputs: usize) -> Result<usize, FcmpNativeErrorV1> {
    if outputs == 0 || outputs > FCMP_MAX_OUTPUTS_NATIVE_V1 {
        return Err(FcmpNativeErrorV1::RangeOutputCount {
            actual: outputs,
            max: FCMP_MAX_OUTPUTS_NATIVE_V1,
        });
    }
    outputs
        .checked_mul(FCMP_RANGE_COMMITMENTS_PER_OUTPUT_V1)
        .and_then(usize::checked_next_power_of_two)
        .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)
}
fn range_lr_len(outputs: usize) -> Result<usize, FcmpNativeErrorV1> {
    let generators = padded_range_commitment_count(outputs)?
        .checked_mul(FCMP_AMOUNT_BITS_V1)
        .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
    if !generators.is_power_of_two() {
        return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
    }
    Ok(usize::try_from(generators.ilog2())
        .map_err(|_| FcmpNativeErrorV1::RangeArithmeticInvariant)?)
}
/// Exact aggregate range-proof byte width for `outputs`.
pub fn fcmp_range_proof_size_v1(outputs: usize) -> Result<usize, FcmpNativeErrorV1> {
    let lr = range_lr_len(outputs)?;
    6_usize
        .checked_add(
            2_usize
                .checked_mul(lr)
                .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?,
        )
        .and_then(|fields| fields.checked_mul(32))
        .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)
}
impl FcmpRangeProofV1 {
    fn from_parts(
        a: EdwardsPoint,
        wip_a: EdwardsPoint,
        wip_b: EdwardsPoint,
        r_answer: &Scalar,
        s_answer: &Scalar,
        delta_answer: &Scalar,
        l: Vec<EdwardsPoint>,
        r: Vec<EdwardsPoint>,
    ) -> Result<Self, FcmpNativeErrorV1> {
        let encode_point = |point: EdwardsPoint| {
            if point.is_identity() || !point.is_torsion_free() {
                Err(FcmpNativeErrorV1::RangeProofPoint)
            } else {
                Ok(point.compress().to_bytes())
            }
        };
        Ok(Self {
            a: encode_point(a)?,
            wip_a: encode_point(wip_a)?,
            wip_b: encode_point(wip_b)?,
            r_answer: r_answer.to_bytes(),
            s_answer: s_answer.to_bytes(),
            delta_answer: delta_answer.to_bytes(),
            l: l.into_iter().map(encode_point).collect::<Result<_, _>>()?,
            r: r.into_iter().map(encode_point).collect::<Result<_, _>>()?,
        })
    }
    /// Decode one exact fixed-shape range proof.
    pub fn decode(bytes: &[u8], outputs: usize) -> Result<Self, FcmpNativeErrorV1> {
        let expected = fcmp_range_proof_size_v1(outputs)?;
        if bytes.len() != expected {
            return Err(FcmpNativeErrorV1::RangeProofLength {
                actual: bytes.len(),
                expected,
            });
        }
        let lr = range_lr_len(outputs)?;
        let mut cursor = 0_usize;
        let mut take = || -> Result<[u8; 32], FcmpNativeErrorV1> {
            let end = cursor
                .checked_add(32)
                .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
            let value = bytes
                .get(cursor..end)
                .ok_or(FcmpNativeErrorV1::RangeProofLength {
                    actual: bytes.len(),
                    expected: end,
                })?;
            let mut array = [0_u8; 32];
            array.copy_from_slice(value);
            cursor = end;
            Ok(array)
        };
        let a = take()?;
        let wip_a = take()?;
        let wip_b = take()?;
        let r_answer = take()?;
        let s_answer = take()?;
        let delta_answer = take()?;
        let mut l = Vec::with_capacity(lr);
        let mut r = Vec::with_capacity(lr);
        for _ in 0..lr {
            l.push(take()?);
        }
        for _ in 0..lr {
            r.push(take()?);
        }
        drop(take);
        if cursor != bytes.len() {
            return Err(FcmpNativeErrorV1::RangeProofLength {
                actual: bytes.len(),
                expected: cursor,
            });
        }
        for point in [a, wip_a, wip_b]
            .into_iter()
            .chain(l.iter().copied())
            .chain(r.iter().copied())
        {
            decode_edwards_point(point, false)?;
        }
        for scalar in [r_answer, s_answer, delta_answer] {
            validate_edwards_scalar(scalar)?;
        }
        Ok(Self {
            a,
            wip_a,
            wip_b,
            r_answer,
            s_answer,
            delta_answer,
            l,
            r,
        })
    }
    /// Encode without attacker-selected vector lengths.
    pub fn encode(&self, outputs: usize) -> Result<Vec<u8>, FcmpNativeErrorV1> {
        if self.l.len() != range_lr_len(outputs)? || self.r.len() != self.l.len() {
            return Err(FcmpNativeErrorV1::RangeProofShape);
        }
        let mut bytes = Vec::with_capacity(fcmp_range_proof_size_v1(outputs)?);
        for field in [
            self.a,
            self.wip_a,
            self.wip_b,
            self.r_answer,
            self.s_answer,
            self.delta_answer,
        ] {
            bytes.extend_from_slice(&field);
        }
        for point in &self.l {
            bytes.extend_from_slice(point);
        }
        for point in &self.r {
            bytes.extend_from_slice(point);
        }
        if bytes.len() != fcmp_range_proof_size_v1(outputs)? {
            return Err(FcmpNativeErrorV1::RangeProofShape);
        }
        Ok(bytes)
    }
}
struct RangeWitnessCommitment {
    mask: Scalar,
    amount: u64,
}
impl Zeroize for RangeWitnessCommitment {
    fn zeroize(&mut self) {
        self.mask.zeroize();
        self.amount.zeroize();
    }
}
impl Drop for RangeWitnessCommitment {
    fn drop(&mut self) {
        self.zeroize();
    }
}
fn range_witness_matches_public_commitment_v1(
    amount_generator: &EdwardsPoint,
    point: &EdwardsPoint,
    witness: &RangeWitnessCommitment,
) -> bool {
    let amount_scalar = RangeSecretCopyValueV1::new(Scalar::from(witness.amount));
    let amount_component =
        RangeSecretCopyValueV1::new(amount_generator * amount_scalar.expose_ref());
    let mask_component = RangeSecretCopyValueV1::new(&ED25519_BASEPOINT_POINT * &witness.mask);
    let expected_owner =
        RangeSecretCopyValueV1::new(amount_component.expose_ref() + mask_component.expose_ref());
    expected_owner.expose_ref() == point
}
fn strict_public_commitments(
    outputs: &[FcmpOutputTupleV1],
) -> Result<Vec<EdwardsPoint>, FcmpNativeErrorV1> {
    if outputs.is_empty() || outputs.len() > FCMP_MAX_OUTPUTS_NATIVE_V1 {
        return Err(FcmpNativeErrorV1::RangeOutputCount {
            actual: outputs.len(),
            max: FCMP_MAX_OUTPUTS_NATIVE_V1,
        });
    }
    let amount_generator = amount_generator()?;
    let mut commitments = Vec::with_capacity(
        outputs
            .len()
            .checked_mul(FCMP_RANGE_COMMITMENTS_PER_OUTPUT_V1)
            .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?,
    );
    for output in outputs {
        let commitment = decode_edwards_point(output.components().2, false)?;
        let minus_one = commitment - amount_generator;
        // C-H is itself an external BP+ statement point. Identity would make
        // the strict-positive relation degenerate and is never canonical.
        if minus_one.is_identity() || !minus_one.is_torsion_free() {
            return Err(FcmpNativeErrorV1::RangeAdjustedCommitment);
        }
        commitments.extend([commitment, minus_one]);
    }
    Ok(commitments)
}
fn strict_witness_commitments(
    openings: &[FcmpOutputCommitmentOpeningV1],
    exact_capacity: usize,
) -> Result<ExactSizeZeroizingVec<RangeWitnessCommitment>, FcmpNativeErrorV1> {
    if openings.is_empty() || openings.len() > FCMP_MAX_OUTPUTS_NATIVE_V1 {
        return Err(FcmpNativeErrorV1::RangeOutputCount {
            actual: openings.len(),
            max: FCMP_MAX_OUTPUTS_NATIVE_V1,
        });
    }
    let witness_count = openings
        .len()
        .checked_mul(FCMP_RANGE_COMMITMENTS_PER_OUTPUT_V1)
        .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
    if exact_capacity < witness_count {
        return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
    }
    let mut witnesses = ExactSizeZeroizingVec::new(exact_capacity)?;
    for opening in openings {
        let amount = Zeroizing::new(opening.amount);
        let mask = Zeroizing::new(opening.mask);
        let predecessor = Zeroizing::new(
            amount
                .checked_sub(1)
                .ok_or(FcmpNativeErrorV1::RangeWitnessOutOfRange)?,
        );
        witnesses.push_owned(RangeWitnessCommitment {
            mask: *mask,
            amount: *amount,
        })?;
        witnesses.push_owned(RangeWitnessCommitment {
            mask: *mask,
            amount: *predecessor,
        })?;
    }
    while !witnesses.is_full() {
        witnesses.push_owned(RangeWitnessCommitment {
            mask: Scalar::ZERO,
            amount: 0,
        })?;
    }
    Ok(witnesses)
}
fn multiexp_vartime(terms: &[(Scalar, EdwardsPoint)]) -> EdwardsPoint {
    EdwardsPoint::vartime_multiscalar_mul(
        terms.iter().map(|(scalar, _)| *scalar),
        terms.iter().map(|(_, point)| *point),
    )
}
struct SecretMultiexpTerm {
    scalar: Scalar,
    point: EdwardsPoint,
}
impl Zeroize for SecretMultiexpTerm {
    fn zeroize(&mut self) {
        self.scalar.zeroize();
        self.point.zeroize();
    }
}
impl Drop for SecretMultiexpTerm {
    fn drop(&mut self) {
        self.scalar.zeroize();
        #[cfg(test)]
        let _ = RANGE_SECRET_MSM_TERM_SCALAR_CLEARS_V1.try_with(|clears| {
            clears.set(clears.get().saturating_add(1));
        });
        self.point.zeroize();
        #[cfg(test)]
        let _ = RANGE_SECRET_MSM_TERM_POINT_CLEARS_V1.try_with(|clears| {
            clears.set(clears.get().saturating_add(1));
        });
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(&mut self.scalar);
        let _ = core::hint::black_box(&mut self.point);
    }
}
/// Unwind-safe eraser for the private by-value secret-MSM input slots.
///
/// `Scalar` and `EdwardsPoint` are `Copy`, so retaining a term cannot consume
/// the named parameter slots. This guard clears both of those slots after a
/// successful insertion and on every error or unwind path.
struct BorrowedSecretMultiexpTermSlotsV1<'a> {
    scalar: &'a mut Scalar,
    point: &'a mut EdwardsPoint,
}
impl<'a> BorrowedSecretMultiexpTermSlotsV1<'a> {
    fn new(scalar: &'a mut Scalar, point: &'a mut EdwardsPoint) -> Self {
        Self { scalar, point }
    }
    fn scalar_copy(&self) -> Scalar {
        *self.scalar
    }
    fn point_copy(&self) -> EdwardsPoint {
        *self.point
    }
}
impl Drop for BorrowedSecretMultiexpTermSlotsV1<'_> {
    fn drop(&mut self) {
        self.scalar.zeroize();
        #[cfg(test)]
        let _ = RANGE_SECRET_MSM_CALLEE_SCALAR_CLEARS_V1.try_with(|clears| {
            clears.set(clears.get().saturating_add(1));
        });
        self.point.zeroize();
        #[cfg(test)]
        let _ = RANGE_SECRET_MSM_CALLEE_POINT_CLEARS_V1.try_with(|clears| {
            clears.set(clears.get().saturating_add(1));
        });
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(&mut *self.scalar);
        let _ = core::hint::black_box(&mut *self.point);
    }
}
#[cfg(test)]
std::thread_local! {
    #[cfg(test)]
    static RANGE_SECRET_MSM_CALLEE_SCALAR_CLEARS_V1: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    #[cfg(test)]
    static RANGE_SECRET_MSM_CALLEE_POINT_CLEARS_V1: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    #[cfg(test)]
    static RANGE_SECRET_MSM_TERM_SCALAR_CLEARS_V1: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    #[cfg(test)]
    static RANGE_SECRET_MSM_TERM_POINT_CLEARS_V1: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}
/// Exact-capacity owner for prover-secret multiscalar-multiplication terms.
struct SecretMultiexpBuilder {
    terms: ExactSizeZeroizingVec<SecretMultiexpTerm>,
}
impl SecretMultiexpBuilder {
    fn new(exact_capacity: usize) -> Result<Self, FcmpNativeErrorV1> {
        Ok(Self {
            terms: ExactSizeZeroizingVec::new(exact_capacity)?,
        })
    }
    fn push(&mut self, scalar: &Scalar, point: &EdwardsPoint) -> Result<(), FcmpNativeErrorV1> {
        self.push_copy(*scalar, *point)
    }
    fn push_copy(
        &mut self,
        mut scalar: Scalar,
        mut point: EdwardsPoint,
    ) -> Result<(), FcmpNativeErrorV1> {
        let incoming = BorrowedSecretMultiexpTermSlotsV1::new(&mut scalar, &mut point);
        if self.terms.is_full() {
            return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
        }
        self.terms.push_owned(SecretMultiexpTerm {
            scalar: incoming.scalar_copy(),
            point: incoming.point_copy(),
        })?;
        // Clear both successful by-value parameter slots before returning.
        // The same guard runs if insertion errors or unwinds.
        drop(incoming);
        Ok(())
    }
    fn evaluate(self) -> Result<EdwardsPoint, FcmpNativeErrorV1> {
        if !self.terms.is_full() {
            return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
        }
        Ok(EdwardsPoint::multiscalar_mul(
            self.terms.iter().map(|term| term.scalar),
            self.terms.iter().map(|term| term.point),
        ))
    }
}
fn random_nonzero_scalar(
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Zeroizing<Scalar>, FcmpNativeErrorV1> {
    for _ in 0..MAX_SCALAR_SAMPLING_ATTEMPTS_V1 {
        let mut wide = Zeroizing::new([0_u8; 64]);
        if rng.try_fill_bytes(&mut *wide).is_err() {
            return Err(FcmpNativeErrorV1::RandomnessUnavailable);
        }
        let scalar = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&wide));
        if *scalar != Scalar::ZERO {
            return Ok(scalar);
        }
    }
    Err(FcmpNativeErrorV1::ProverRandomnessExhausted)
}
#[derive(Clone, Copy)]
enum TranscriptMode {
    Iroha([u8; 32]),
    #[cfg(test)]
    PinnedUpstream,
}
struct RangeTranscript {
    state: Scalar,
}
impl RangeTranscript {
    fn new(
        mode: TranscriptMode,
        outputs: &[FcmpOutputTupleV1],
        transcript_commitments: &[EdwardsPoint],
    ) -> Result<Self, FcmpNativeErrorV1> {
        let mut commitments_hasher = Keccak256::new();
        for commitment in transcript_commitments {
            commitments_hasher.update(commitment.compress().to_bytes());
        }
        // Monero reduces this first Keccak digest to a scalar before hashing
        // it into the transcript prefix. Hashing the unreduced 32 bytes is a
        // different protocol for the overwhelming majority of digests.
        let commitments_hash = Scalar::from_bytes_mod_order(commitments_hasher.finalize().into());
        if commitments_hash == Scalar::ZERO {
            return Err(FcmpNativeErrorV1::RangeChallengeZero);
        }
        let commitments_digest = commitments_hash.to_bytes();
        let prefix = transcript_prefix()?;
        let state = match mode {
            TranscriptMode::Iroha(context_hash) => {
                let mut binding_hasher = Keccak256::new();
                binding_hasher.update(IROHA_RANGE_BINDING_DOMAIN_V1);
                binding_hasher.update(context_hash);
                binding_hasher.update(
                    u32::try_from(outputs.len())
                        .map_err(|_| FcmpNativeErrorV1::RangeArithmeticInvariant)?
                        .to_be_bytes(),
                );
                for output in outputs {
                    binding_hasher.update(output.encode());
                }
                let binding: [u8; 32] = binding_hasher.finalize().into();
                hash_to_scalar(&[&prefix, &binding, &commitments_digest])?
            }
            #[cfg(test)]
            TranscriptMode::PinnedUpstream => hash_to_scalar(&[&prefix, &commitments_digest])?,
        };
        Ok(Self { state })
    }
    fn append_a(&mut self, a: EdwardsPoint) -> Result<(Scalar, Scalar), FcmpNativeErrorV1> {
        let a = a.compress().to_bytes();
        let y = hash_to_scalar(&[&self.state.to_bytes(), &a])?;
        let z = hash_to_scalar(&[&y.to_bytes()])?;
        self.state = z;
        Ok((y, z))
    }
    fn append_lr(
        &mut self,
        left: EdwardsPoint,
        right: EdwardsPoint,
    ) -> Result<Scalar, FcmpNativeErrorV1> {
        let challenge = hash_to_scalar(&[
            &self.state.to_bytes(),
            &left.compress().to_bytes(),
            &right.compress().to_bytes(),
        ])?;
        self.state = challenge;
        Ok(challenge)
    }
    fn append_ab(&mut self, a: EdwardsPoint, b: EdwardsPoint) -> Result<Scalar, FcmpNativeErrorV1> {
        let challenge = hash_to_scalar(&[
            &self.state.to_bytes(),
            &a.compress().to_bytes(),
            &b.compress().to_bytes(),
        ])?;
        self.state = challenge;
        Ok(challenge)
    }
}
fn d_j(index: usize, commitments: usize) -> Result<ScalarVector, FcmpNativeErrorV1> {
    if index == 0 || index > commitments {
        return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
    }
    let total = commitments
        .checked_mul(FCMP_AMOUNT_BITS_V1)
        .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
    let mut vector = ScalarVector::zero(total)?;
    let start = (index - 1)
        .checked_mul(FCMP_AMOUNT_BITS_V1)
        .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
    let powers = ScalarVector::powers(Scalar::from(2_u8), FCMP_AMOUNT_BITS_V1)?;
    vector
        .0
        .get_mut(start..start + FCMP_AMOUNT_BITS_V1)
        .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?
        .copy_from_slice(&powers.0[..]);
    Ok(vector)
}
struct AHatComputation {
    y: Scalar,
    z: Scalar,
    d_descending_y_plus_z: ScalarVector,
    y_mn_plus_one: Scalar,
    z_pow: ScalarVector,
    a_hat: EdwardsPoint,
}
fn compute_a_hat(
    mut commitments: PointVector,
    generators: &BpPlusGenerators,
    transcript: &mut RangeTranscript,
    a: EdwardsPoint,
) -> Result<AHatComputation, FcmpNativeErrorV1> {
    let (y, z) = transcript.append_a(a)?;
    let a = a.mul_by_cofactor();
    let padded = commitments
        .len()
        .max(1)
        .checked_next_power_of_two()
        .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
    commitments.0.resize(padded, EdwardsPoint::identity());
    let mn = commitments
        .len()
        .checked_mul(FCMP_AMOUNT_BITS_V1)
        .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
    if mn != generators.len() {
        return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
    }
    let z_squared = z * z;
    let z_pow = ScalarVector::powers(z_squared, commitments.len())?.mul_scalar(z_squared);
    let mut d = ScalarVector::zero(mn)?;
    for index in 1..=commitments.len() {
        d = d.add_vector(&d_j(index, commitments.len())?.mul_scalar(z_pow.0[index - 1]))?;
    }
    let ascending_y = ScalarVector::powers(y, d.len())?.mul_scalar(y);
    let y_pows = ascending_y.sum();
    let d_sum = d.sum();
    let mut descending_y = ascending_y.try_clone()?;
    descending_y.0.reverse();
    let d_descending_y = d.try_clone()?.mul_vector(&descending_y)?;
    let d_descending_y_plus_z = d_descending_y.add_scalar(z);
    let y_mn_plus_one = descending_y
        .0
        .first()
        .copied()
        .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?
        * y;
    let mut commitment_accumulator = EdwardsPoint::identity();
    for (commitment, power) in commitments.0.iter().zip(z_pow.0.iter()) {
        commitment_accumulator += commitment * power;
    }
    let mut terms = Vec::with_capacity(
        generators
            .len()
            .checked_mul(2)
            .and_then(|value| value.checked_add(2))
            .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?,
    );
    for (index, d_y_z) in d_descending_y_plus_z.0.iter().copied().enumerate() {
        terms.push((-z, generators.g_bold[index]));
        terms.push((d_y_z, generators.h_bold[index]));
    }
    terms.push((y_mn_plus_one, commitment_accumulator));
    terms.push((
        (&*y_pows * z) - (&*d_sum * y_mn_plus_one * z) - (&*y_pows * z_squared),
        amount_generator()?,
    ));
    let a_hat = a + multiexp_vartime(&terms);
    terms.zeroize();
    Ok(AHatComputation {
        y,
        z,
        d_descending_y_plus_z,
        y_mn_plus_one,
        z_pow,
        a_hat,
    })
}
struct WipWitness {
    a: ScalarVector,
    b: ScalarVector,
    alpha: Scalar,
}
impl Drop for WipWitness {
    fn drop(&mut self) {
        self.alpha.zeroize();
    }
}
struct WipProof {
    l: Vec<EdwardsPoint>,
    r: Vec<EdwardsPoint>,
    a: EdwardsPoint,
    b: EdwardsPoint,
    r_answer: RangeSecretCopyValueV1<Scalar>,
    s_answer: RangeSecretCopyValueV1<Scalar>,
    delta_answer: RangeSecretCopyValueV1<Scalar>,
}
fn wip_y_vector(y: Scalar, len: usize) -> Result<ScalarVector, FcmpNativeErrorV1> {
    ScalarVector::powers(y, len).map(|powers| powers.mul_scalar(y))
}
fn next_wip_generators(
    transcript: &mut RangeTranscript,
    mut g_1: PointVector,
    mut g_2: PointVector,
    mut h_1: PointVector,
    mut h_2: PointVector,
    left: EdwardsPoint,
    right: EdwardsPoint,
    y_inverse_n_hat: Scalar,
) -> Result<(Scalar, Scalar, Scalar, Scalar, PointVector, PointVector), FcmpNativeErrorV1> {
    if g_1.len() != g_2.len() || h_1.len() != h_2.len() || g_1.len() != h_1.len() {
        return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
    }
    let challenge = transcript.append_lr(left, right)?;
    let inverse = challenge.invert();
    let mut g = Vec::with_capacity(g_1.len());
    for (first, second) in g_1.0.drain(..).zip(g_2.0.drain(..)) {
        g.push(multiexp_vartime(&[
            (inverse, first),
            (challenge * y_inverse_n_hat, second),
        ]));
    }
    let mut h = Vec::with_capacity(h_1.len());
    for (first, second) in h_1.0.drain(..).zip(h_2.0.drain(..)) {
        h.push(multiexp_vartime(&[(challenge, first), (inverse, second)]));
    }
    Ok((
        challenge,
        inverse,
        challenge * challenge,
        inverse * inverse,
        PointVector(g),
        PointVector(h),
    ))
}
fn prove_wip(
    rng: &mut (impl RngCore + CryptoRng),
    generators: BpPlusGenerators,
    p: EdwardsPoint,
    y: Scalar,
    transcript: &mut RangeTranscript,
    witness: WipWitness,
) -> Result<WipProof, FcmpNativeErrorV1> {
    #[cfg(not(debug_assertions))]
    let _ = p;
    if generators.len() == 0
        || !generators.len().is_power_of_two()
        || generators.len() != witness.a.len()
        || witness.a.len() != witness.b.len()
    {
        return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
    }
    let lr_len = usize::try_from(generators.len().ilog2())
        .map_err(|_| FcmpNativeErrorV1::RangeArithmeticInvariant)?;
    let mut l_proof = Zeroizing::new(Vec::new());
    l_proof
        .try_reserve_exact(lr_len)
        .map_err(|_| FcmpNativeErrorV1::RangeArithmeticInvariant)?;
    let l_proof_allocation_capacity = l_proof.capacity();
    let mut r_proof = Zeroizing::new(Vec::new());
    r_proof
        .try_reserve_exact(lr_len)
        .map_err(|_| FcmpNativeErrorV1::RangeArithmeticInvariant)?;
    let r_proof_allocation_capacity = r_proof.capacity();
    let mut y_vector = wip_y_vector(y, generators.len())?;
    let mut g_bold = PointVector(generators.g_bold);
    let mut h_bold = PointVector(generators.h_bold);
    let mut inverses = Zeroizing::new(Vec::new());
    inverses
        .try_reserve_exact(lr_len)
        .map_err(|_| FcmpNativeErrorV1::RangeArithmeticInvariant)?;
    let mut index = 1;
    while index < g_bold.len() {
        let value = y_vector
            .0
            .get(index - 1)
            .copied()
            .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
        if value == Scalar::ZERO {
            return Err(FcmpNativeErrorV1::RangeChallengeZero);
        }
        inverses.push(value.invert());
        index = index
            .checked_mul(2)
            .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
    }
    let amount_generator = amount_generator()?;
    #[cfg(debug_assertions)]
    {
        let term_count = witness
            .a
            .len()
            .checked_mul(2)
            .and_then(|count| count.checked_add(2))
            .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
        let mut terms = SecretMultiexpBuilder::new(term_count)?;
        for (scalar, point) in witness.a.0.iter().zip(g_bold.0.iter()) {
            terms.push(scalar, point)?;
        }
        for (scalar, point) in witness.b.0.iter().zip(h_bold.0.iter()) {
            terms.push(scalar, point)?;
        }
        let inner_product = witness
            .a
            .try_clone()?
            .weighted_inner_product(&witness.b, &y_vector)?;
        terms.push(&inner_product, &amount_generator)?;
        terms.push(&witness.alpha, &ED25519_BASEPOINT_POINT)?;
        if terms.evaluate()? != p {
            return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
        }
    }
    let mut a = witness.a.try_clone()?;
    let mut b = witness.b.try_clone()?;
    let mut alpha = Zeroizing::new(witness.alpha);
    let inverse_eight = Scalar::from(8_u8).invert();
    while g_bold.len() > 1 {
        let (a_1, a_2) = a.split()?;
        let (b_1, b_2) = b.split()?;
        let (g_1, g_2) = g_bold.split()?;
        let (h_1, h_2) = h_bold.split()?;
        let n_hat = g_1.len();
        if n_hat == 0
            || a_1.len() != n_hat
            || a_2.len() != n_hat
            || b_1.len() != n_hat
            || b_2.len() != n_hat
            || h_1.len() != n_hat
            || h_2.len() != n_hat
        {
            return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
        }
        let y_n_hat = y_vector
            .0
            .get(n_hat - 1)
            .copied()
            .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
        y_vector.truncate(n_hat)?;
        let d_l = random_nonzero_scalar(rng)?;
        let d_r = random_nonzero_scalar(rng)?;
        let c_l = a_1.try_clone()?.weighted_inner_product(&b_2, &y_vector)?;
        let c_r = a_2
            .try_clone()?
            .mul_scalar(y_n_hat)
            .weighted_inner_product(&b_1, &y_vector)?;
        let y_inverse_n_hat = inverses
            .pop()
            .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
        let round_term_count = n_hat
            .checked_mul(2)
            .and_then(|count| count.checked_add(2))
            .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
        let left_a = a_1.try_clone()?.mul_scalar(y_inverse_n_hat);
        let mut left_terms = SecretMultiexpBuilder::new(round_term_count)?;
        for (scalar, point) in left_a.0.iter().zip(g_2.0.iter()) {
            left_terms.push(scalar, point)?;
        }
        for (scalar, point) in b_2.0.iter().zip(h_1.0.iter()) {
            left_terms.push(scalar, point)?;
        }
        left_terms.push(&c_l, &amount_generator)?;
        left_terms.push(&d_l, &ED25519_BASEPOINT_POINT)?;
        let left = left_terms.evaluate()? * inverse_eight;
        let right_a = a_2.try_clone()?.mul_scalar(y_n_hat);
        let mut right_terms = SecretMultiexpBuilder::new(round_term_count)?;
        for (scalar, point) in right_a.0.iter().zip(g_1.0.iter()) {
            right_terms.push(scalar, point)?;
        }
        for (scalar, point) in b_1.0.iter().zip(h_2.0.iter()) {
            right_terms.push(scalar, point)?;
        }
        right_terms.push(&c_r, &amount_generator)?;
        right_terms.push(&d_r, &ED25519_BASEPOINT_POINT)?;
        let right = right_terms.evaluate()? * inverse_eight;
        if left.is_identity() || right.is_identity() {
            return Err(FcmpNativeErrorV1::RangeProofPoint);
        }
        debug_assert_eq!(l_proof.capacity(), l_proof_allocation_capacity);
        debug_assert_eq!(r_proof.capacity(), r_proof_allocation_capacity);
        l_proof.push(left);
        r_proof.push(right);
        debug_assert_eq!(l_proof.capacity(), l_proof_allocation_capacity);
        debug_assert_eq!(r_proof.capacity(), r_proof_allocation_capacity);
        let (challenge, inverse, challenge_squared, inverse_squared, next_g, next_h) =
            next_wip_generators(transcript, g_1, g_2, h_1, h_2, left, right, y_inverse_n_hat)?;
        g_bold = next_g;
        h_bold = next_h;
        a = a_1
            .mul_scalar(challenge)
            .add_vector(&a_2.mul_scalar(y_n_hat * inverse))?;
        b = b_1
            .mul_scalar(inverse)
            .add_vector(&b_2.mul_scalar(challenge))?;
        *alpha += (*d_l * challenge_squared) + (*d_r * inverse_squared);
    }
    if g_bold.len() != 1
        || h_bold.len() != 1
        || a.len() != 1
        || b.len() != 1
        || l_proof.len() != lr_len
        || r_proof.len() != lr_len
    {
        return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
    }
    let r = random_nonzero_scalar(rng)?;
    let s = random_nonzero_scalar(rng)?;
    let delta = random_nonzero_scalar(rng)?;
    let eta = random_nonzero_scalar(rng)?;
    let r_y = Zeroizing::new(*r * y_vector.0[0]);
    let mut a_terms = SecretMultiexpBuilder::new(4)?;
    a_terms.push(&r, &g_bold.0[0])?;
    a_terms.push(&s, &h_bold.0[0])?;
    let proof_a_amount = Zeroizing::new((*r_y * b.0[0]) + (*s * y_vector.0[0] * a.0[0]));
    a_terms.push(&proof_a_amount, &amount_generator)?;
    a_terms.push(&delta, &ED25519_BASEPOINT_POINT)?;
    let proof_a = a_terms.evaluate()? * inverse_eight;
    let mut b_terms = SecretMultiexpBuilder::new(2)?;
    let proof_b_amount = Zeroizing::new(*r_y * *s);
    b_terms.push(&proof_b_amount, &amount_generator)?;
    b_terms.push(&eta, &ED25519_BASEPOINT_POINT)?;
    let proof_b = b_terms.evaluate()? * inverse_eight;
    if proof_a.is_identity() || proof_b.is_identity() {
        return Err(FcmpNativeErrorV1::RangeProofPoint);
    }
    let challenge = transcript.append_ab(proof_a, proof_b)?;
    Ok(WipProof {
        l: core::mem::take(&mut *l_proof),
        r: core::mem::take(&mut *r_proof),
        a: proof_a,
        b: proof_b,
        r_answer: RangeSecretCopyValueV1::new(*r + (a.0[0] * challenge)),
        s_answer: RangeSecretCopyValueV1::new(*s + (b.0[0] * challenge)),
        delta_answer: RangeSecretCopyValueV1::new(
            *eta + (*delta * challenge) + (*alpha * challenge * challenge),
        ),
    })
}
fn challenge_products(challenges: &[(Scalar, Scalar)]) -> Result<Vec<Scalar>, FcmpNativeErrorV1> {
    let len = 1_usize
        .checked_shl(
            u32::try_from(challenges.len())
                .map_err(|_| FcmpNativeErrorV1::RangeArithmeticInvariant)?,
        )
        .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
    let mut products = vec![Scalar::ONE; len];
    if let Some(first) = challenges.first() {
        products[0] = first.1;
        products[1] = first.0;
        for (column, challenge) in challenges.iter().enumerate().skip(1) {
            let mut slots = (1_usize
                .checked_shl(
                    u32::try_from(column + 1)
                        .map_err(|_| FcmpNativeErrorV1::RangeArithmeticInvariant)?,
                )
                .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?)
            .checked_sub(1)
            .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
            while slots > 0 {
                products[slots] = products[slots / 2] * challenge.0;
                products[slots - 1] = products[slots / 2] * challenge.1;
                slots = slots.saturating_sub(2);
            }
        }
    }
    if products.iter().any(|value| *value == Scalar::ZERO) {
        return Err(FcmpNativeErrorV1::RangeChallengeZero);
    }
    Ok(products)
}
fn decode_scalar(bytes: [u8; 32]) -> Result<Scalar, FcmpNativeErrorV1> {
    validate_edwards_scalar(bytes)?;
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .ok_or(FcmpNativeErrorV1::ScalarEncoding)
}
fn verify_wip(
    generators: BpPlusGenerators,
    p: EdwardsPoint,
    y: Scalar,
    transcript: &mut RangeTranscript,
    proof: &FcmpRangeProofV1,
) -> Result<(), FcmpNativeErrorV1> {
    let expected_lr = usize::try_from(generators.len().ilog2())
        .map_err(|_| FcmpNativeErrorV1::RangeArithmeticInvariant)?;
    if !generators.len().is_power_of_two()
        || proof.l.len() != expected_lr
        || proof.r.len() != expected_lr
    {
        return Err(FcmpNativeErrorV1::RangeProofShape);
    }
    let y_vector = wip_y_vector(y, generators.len())?;
    let inverse_y = y.invert();
    let mut inverse_y_powers = Vec::with_capacity(generators.len());
    let mut running = inverse_y;
    for _ in 0..generators.len() {
        inverse_y_powers.push(running);
        running *= inverse_y;
    }
    let mut l = Vec::with_capacity(proof.l.len());
    let mut r = Vec::with_capacity(proof.r.len());
    let mut challenges = Vec::with_capacity(proof.l.len());
    for (left, right) in proof.l.iter().copied().zip(proof.r.iter().copied()) {
        let left_point = decode_edwards_point(left, false)?;
        let right_point = decode_edwards_point(right, false)?;
        let challenge = transcript.append_lr(left_point, right_point)?;
        challenges.push((challenge, challenge.invert()));
        l.push(left_point.mul_by_cofactor());
        r.push(right_point.mul_by_cofactor());
    }
    let proof_a = decode_edwards_point(proof.wip_a, false)?;
    let proof_b = decode_edwards_point(proof.wip_b, false)?;
    let challenge = transcript.append_ab(proof_a, proof_b)?;
    let proof_a = proof_a.mul_by_cofactor();
    let proof_b = proof_b.mul_by_cofactor();
    let challenge_squared = challenge * challenge;
    let products = challenge_products(&challenges)?;
    if products.len() != generators.len() {
        return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
    }
    let r_answer = decode_scalar(proof.r_answer)?;
    let s_answer = decode_scalar(proof.s_answer)?;
    let delta_answer = decode_scalar(proof.delta_answer)?;
    let mut terms = Vec::with_capacity(
        4_usize
            .checked_add(l.len().saturating_mul(2))
            .and_then(|value| value.checked_add(generators.len().saturating_mul(2)))
            .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?,
    );
    terms.push((-challenge_squared, p));
    for (((challenge_i, inverse_i), left), right) in challenges.iter().copied().zip(l).zip(r) {
        terms.push((-challenge_squared * challenge_i * challenge_i, left));
        terms.push((-challenge_squared * inverse_i * inverse_i, right));
    }
    let r_e = r_answer * challenge;
    for (index, generator) in generators.g_bold.iter().copied().enumerate() {
        let mut scalar = products[index] * r_e;
        if index > 0 {
            scalar *= inverse_y_powers[index - 1];
        }
        terms.push((scalar, generator));
    }
    let s_e = s_answer * challenge;
    for (index, generator) in generators.h_bold.iter().copied().enumerate() {
        terms.push((s_e * products[products.len() - 1 - index], generator));
    }
    terms.push((-challenge, proof_a));
    terms.push((r_answer * y_vector.0[0] * s_answer, amount_generator()?));
    terms.push((delta_answer, ED25519_BASEPOINT_POINT));
    terms.push((-Scalar::ONE, proof_b));
    let valid = multiexp_vartime(&terms).is_identity();
    terms.zeroize();
    if !valid {
        return Err(FcmpNativeErrorV1::RangeProofEquation);
    }
    Ok(())
}
fn prove_range_once(
    rng: &mut (impl RngCore + CryptoRng),
    mode: TranscriptMode,
    openings: &[FcmpOutputCommitmentOpeningV1],
) -> Result<FcmpRangeProofV1, FcmpNativeErrorV1> {
    let outputs = openings
        .iter()
        .map(FcmpOutputCommitmentOpeningV1::output)
        .collect::<Vec<_>>();
    let public_commitments = strict_public_commitments(&outputs)?;
    let witness_count = openings
        .len()
        .checked_mul(FCMP_RANGE_COMMITMENTS_PER_OUTPUT_V1)
        .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
    let padded_commitments = padded_range_commitment_count(openings.len())?;
    let witnesses = strict_witness_commitments(openings, padded_commitments)?;
    if public_commitments.len() != witness_count || witnesses.len() != padded_commitments {
        return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
    }
    let amount_generator = amount_generator()?;
    for (point, witness) in public_commitments.iter().zip(witnesses.iter()) {
        if !range_witness_matches_public_commitment_v1(&amount_generator, point, witness) {
            return Err(FcmpNativeErrorV1::RangeCommitmentOpeningMismatch);
        }
    }
    let inverse_eight = Scalar::from(8_u8).invert();
    let transcript_commitments = public_commitments
        .iter()
        .map(|point| point * inverse_eight)
        .collect::<Vec<_>>();
    let mut transcript = RangeTranscript::new(mode, &outputs, &transcript_commitments)?;
    let mut commitments = transcript_commitments
        .iter()
        .map(EdwardsPoint::mul_by_cofactor)
        .collect::<Vec<_>>();
    commitments.resize(padded_commitments, EdwardsPoint::identity());
    let generator_count = padded_commitments
        .checked_mul(FCMP_AMOUNT_BITS_V1)
        .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
    let generators = bp_plus_generators()?.reduce(generator_count)?;
    let mut a_l = ScalarVector::with_capacity(generator_count)?;
    for witness in witnesses.iter() {
        for bit in 0..FCMP_AMOUNT_BITS_V1 {
            a_l.0.push_copy(Scalar::from((witness.amount >> bit) & 1))?;
        }
    }
    if !a_l.0.is_full() {
        return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
    }
    let a_r = a_l.try_clone()?.sub_scalar(Scalar::ONE);
    let alpha = random_nonzero_scalar(rng)?;
    let a_term_count = generator_count
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
    let mut a_terms = SecretMultiexpBuilder::new(a_term_count)?;
    for (index, value) in a_l.0.iter().enumerate() {
        a_terms.push(value, &generators.g_bold[index])?;
    }
    for (index, value) in a_r.0.iter().enumerate() {
        a_terms.push(value, &generators.h_bold[index])?;
    }
    a_terms.push(&alpha, &ED25519_BASEPOINT_POINT)?;
    let proof_a = a_terms.evaluate()? * inverse_eight;
    if proof_a.is_identity() {
        return Err(FcmpNativeErrorV1::RangeProofPoint);
    }
    let AHatComputation {
        y,
        z,
        d_descending_y_plus_z,
        y_mn_plus_one,
        z_pow,
        a_hat,
    } = compute_a_hat(
        PointVector(commitments),
        &generators,
        &mut transcript,
        proof_a,
    )?;
    let a_l = a_l.sub_scalar(z);
    let a_r = a_r.add_vector(&d_descending_y_plus_z)?;
    let mut alpha_hat = Zeroizing::new(*alpha);
    for (index, witness) in witnesses.iter().enumerate() {
        *alpha_hat += z_pow.0[index] * witness.mask * y_mn_plus_one;
    }
    let wip = prove_wip(
        rng,
        generators,
        a_hat,
        y,
        &mut transcript,
        WipWitness {
            a: a_l,
            b: a_r,
            alpha: *alpha_hat,
        },
    )?;
    let WipProof {
        l,
        r,
        a,
        b,
        r_answer,
        s_answer,
        delta_answer,
    } = wip;
    FcmpRangeProofV1::from_parts(
        proof_a,
        a,
        b,
        r_answer.expose_ref(),
        s_answer.expose_ref(),
        delta_answer.expose_ref(),
        l,
        r,
    )
}
#[cfg(test)]
fn preflight_fcmp_range_v1(
    openings: &[FcmpOutputCommitmentOpeningV1],
) -> Result<Vec<FcmpOutputTupleV1>, FcmpNativeErrorV1> {
    let outputs = openings
        .iter()
        .map(FcmpOutputCommitmentOpeningV1::output)
        .collect::<Vec<_>>();
    let public_commitments = strict_public_commitments(&outputs)?;
    let witness_count = openings
        .len()
        .checked_mul(FCMP_RANGE_COMMITMENTS_PER_OUTPUT_V1)
        .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
    let witnesses = strict_witness_commitments(openings, witness_count)?;
    if public_commitments.len() != witnesses.len() {
        return Err(FcmpNativeErrorV1::RangeArithmeticInvariant);
    }
    let amount_generator = amount_generator()?;
    for (point, witness) in public_commitments.iter().zip(witnesses.iter()) {
        if !range_witness_matches_public_commitment_v1(&amount_generator, point, witness) {
            return Err(FcmpNativeErrorV1::RangeCommitmentOpeningMismatch);
        }
    }
    Ok(outputs)
}
#[cfg(test)]
/// Produce the sole aggregate strict-positive `u64` output range proof.
pub fn prove_fcmp_range_v1(
    rng: &mut (impl RngCore + CryptoRng),
    context_hash: [u8; 32],
    openings: &[FcmpOutputCommitmentOpeningV1],
) -> Result<FcmpRangeProofV1, FcmpNativeErrorV1> {
    let outputs = preflight_fcmp_range_v1(openings)?;
    let mut checked_rng = super::health_checked_fcmp_rng_v1(rng)?;
    let proof = prove_fcmp_range_with_checked_rng_v1(&mut checked_rng, context_hash, openings)?;
    verify_fcmp_range_v1(context_hash, &outputs, &proof)
        .map_err(|_| FcmpNativeErrorV1::ProverSelfCheckFailed)?;
    Ok(proof)
}
pub(super) fn prove_fcmp_range_with_checked_rng_v1(
    rng: &mut (impl RngCore + CryptoRng),
    context_hash: [u8; 32],
    openings: &[FcmpOutputCommitmentOpeningV1],
) -> Result<FcmpRangeProofV1, FcmpNativeErrorV1> {
    retry_range_prover_v1(|| prove_range_once(rng, TranscriptMode::Iroha(context_hash), openings))
}
fn retry_range_prover_v1<T>(
    mut prove_once: impl FnMut() -> Result<T, FcmpNativeErrorV1>,
) -> Result<T, FcmpNativeErrorV1> {
    for _ in 0..MAX_PROVER_RESTARTS_V1 {
        match prove_once() {
            Ok(proof) => return Ok(proof),
            Err(FcmpNativeErrorV1::RangeProofPoint | FcmpNativeErrorV1::RangeChallengeZero) => {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Err(FcmpNativeErrorV1::RangeProverRestartExhausted)
}
fn verify_range_with_mode(
    mode: TranscriptMode,
    outputs: &[FcmpOutputTupleV1],
    proof: &FcmpRangeProofV1,
) -> Result<(), FcmpNativeErrorV1> {
    let public_commitments = strict_public_commitments(outputs)?;
    let inverse_eight = Scalar::from(8_u8).invert();
    let transcript_commitments = public_commitments
        .iter()
        .map(|point| point * inverse_eight)
        .collect::<Vec<_>>();
    let mut transcript = RangeTranscript::new(mode, outputs, &transcript_commitments)?;
    let commitments = transcript_commitments
        .iter()
        .map(EdwardsPoint::mul_by_cofactor)
        .collect::<Vec<_>>();
    let generator_count = commitments
        .len()
        .max(1)
        .checked_next_power_of_two()
        .and_then(|count| count.checked_mul(FCMP_AMOUNT_BITS_V1))
        .ok_or(FcmpNativeErrorV1::RangeArithmeticInvariant)?;
    let generators = bp_plus_generators()?.reduce(generator_count)?;
    let proof_a = decode_edwards_point(proof.a, false)?;
    let AHatComputation { y, a_hat, .. } = compute_a_hat(
        PointVector(commitments),
        &generators,
        &mut transcript,
        proof_a,
    )?;
    verify_wip(generators, a_hat, y, &mut transcript, proof)
}
/// Verify the aggregate range proof against the ordered new commitments.
pub fn verify_fcmp_range_v1(
    context_hash: [u8; 32],
    outputs: &[FcmpOutputTupleV1],
    proof: &FcmpRangeProofV1,
) -> Result<(), FcmpNativeErrorV1> {
    if proof.l.len() != range_lr_len(outputs.len())? || proof.r.len() != proof.l.len() {
        return Err(FcmpNativeErrorV1::RangeProofShape);
    }
    verify_range_with_mode(TranscriptMode::Iroha(context_hash), outputs, proof)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::fcmp_plus_plus::FailingRngV1;
    use rand_08::{SeedableRng as _, rngs::StdRng};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    static RANGE_COPY_CLEARS: AtomicUsize = AtomicUsize::new(0);
    #[derive(Clone, Copy)]
    struct TrackingCopy(u64);
    impl Zeroize for TrackingCopy {
        fn zeroize(&mut self) {
            self.0 = 0;
            RANGE_COPY_CLEARS.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn reset_range_secret_copy_owner_drops() {
        RANGE_SECRET_COPY_OWNER_DROPS_V1.with(|drops| drops.set(0));
    }
    fn range_secret_copy_owner_drops() -> usize {
        RANGE_SECRET_COPY_OWNER_DROPS_V1.with(std::cell::Cell::get)
    }
    fn reset_secret_multiexp_tracking() {
        RANGE_SECRET_MSM_CALLEE_SCALAR_CLEARS_V1.with(|clears| clears.set(0));
        RANGE_SECRET_MSM_CALLEE_POINT_CLEARS_V1.with(|clears| clears.set(0));
        RANGE_SECRET_MSM_TERM_SCALAR_CLEARS_V1.with(|clears| clears.set(0));
        RANGE_SECRET_MSM_TERM_POINT_CLEARS_V1.with(|clears| clears.set(0));
    }
    fn secret_multiexp_tracking() -> (usize, usize, usize, usize) {
        (
            RANGE_SECRET_MSM_CALLEE_SCALAR_CLEARS_V1.with(std::cell::Cell::get),
            RANGE_SECRET_MSM_CALLEE_POINT_CLEARS_V1.with(std::cell::Cell::get),
            RANGE_SECRET_MSM_TERM_SCALAR_CLEARS_V1.with(std::cell::Cell::get),
            RANGE_SECRET_MSM_TERM_POINT_CLEARS_V1.with(std::cell::Cell::get),
        )
    }
    struct PeriodicRng {
        period: usize,
        cursor: usize,
    }
    struct TrackingSecret {
        value: u64,
        clear_calls: Arc<AtomicUsize>,
    }
    impl TrackingSecret {
        fn new(value: u64, clear_calls: &Arc<AtomicUsize>) -> Self {
            Self {
                value,
                clear_calls: Arc::clone(clear_calls),
            }
        }
    }
    impl Zeroize for TrackingSecret {
        fn zeroize(&mut self) {
            self.value = 0;
            self.clear_calls.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[test]
    fn range_copy_owner_clears_transfer_success_and_unwind_slots() {
        RANGE_COPY_CLEARS.store(0, Ordering::SeqCst);
        let mut source = TrackingCopy(7);
        let owner = RangeSecretCopyValueV1::take(&mut source);
        assert_eq!(source.0, 0);
        assert_eq!(owner.expose_ref().0, 7);
        assert_eq!(RANGE_COPY_CLEARS.load(Ordering::SeqCst), 1);
        drop(owner);
        assert_eq!(RANGE_COPY_CLEARS.load(Ordering::SeqCst), 2);
        RANGE_COPY_CLEARS.store(0, Ordering::SeqCst);
        let borrowed = TrackingCopy(9);
        let owner = RangeSecretCopyValueV1::copy_from_ref(&borrowed);
        assert_eq!(borrowed.0, 9);
        assert_eq!(owner.expose_ref().0, 9);
        assert_eq!(RANGE_COPY_CLEARS.load(Ordering::SeqCst), 1);
        drop(owner);
        assert_eq!(RANGE_COPY_CLEARS.load(Ordering::SeqCst), 2);
        RANGE_COPY_CLEARS.store(0, Ordering::SeqCst);
        assert!(
            std::panic::catch_unwind(|| {
                let _owner = RangeSecretCopyValueV1::new(TrackingCopy(11));
                panic!("tracking unwind");
            })
            .is_err()
        );
        assert_eq!(RANGE_COPY_CLEARS.load(Ordering::SeqCst), 2);
    }
    #[test]
    fn exact_size_copy_insertion_clears_success_overflow_and_unwind_slots() {
        RANGE_COPY_CLEARS.store(0, Ordering::SeqCst);
        let mut values = ExactSizeZeroizingVec::new(1).expect("one fixed copy slot");
        values.push_copy(TrackingCopy(17)).expect("sole copy fits");
        assert_eq!(RANGE_COPY_CLEARS.load(Ordering::SeqCst), 2);
        assert_eq!(
            values.push_copy(TrackingCopy(19)),
            Err(FcmpNativeErrorV1::RangeArithmeticInvariant)
        );
        assert_eq!(RANGE_COPY_CLEARS.load(Ordering::SeqCst), 4);
        drop(values);
        assert_eq!(RANGE_COPY_CLEARS.load(Ordering::SeqCst), 5);
        RANGE_COPY_CLEARS.store(0, Ordering::SeqCst);
        assert!(
            std::panic::catch_unwind(|| {
                let mut values = ExactSizeZeroizingVec::new(1).expect("one unwind slot");
                values
                    .push_copy(TrackingCopy(23))
                    .expect("sole unwind copy fits");
                panic!("exercise exact-copy-vector unwind");
            })
            .is_err()
        );
        assert_eq!(RANGE_COPY_CLEARS.load(Ordering::SeqCst), 3);
        let source = include_str!("range.rs");
        let exact_vector = source
            .split_once("impl<T: Zeroize> ExactSizeZeroizingVec<T> {")
            .expect("owned exact vector")
            .1
            .split_once("impl<T: Copy + Zeroize> ExactSizeZeroizingVec<T> {")
            .expect("copy boundary")
            .0;
        assert!(exact_vector.contains("fn push_owned(&mut self, value: T)"));
        assert!(!exact_vector.contains("fn push(&mut self, value: T)"));
        let copy_vector = source
            .split_once("impl<T: Copy + Zeroize> ExactSizeZeroizingVec<T> {")
            .expect("guarded exact copy vector")
            .1
            .split_once("impl<T: Zeroize> Deref for ExactSizeZeroizingVec<T>")
            .expect("copy vector boundary")
            .0;
        let take = copy_vector
            .find("RangeSecretCopyValueV1::take(&mut value)")
            .expect("incoming copy take");
        let capacity = copy_vector
            .find("if self.len() >= self.exact_capacity")
            .expect("capacity guard");
        let push = copy_vector
            .find("self.values.push(value.expose_copy())")
            .expect("retained final copy");
        let drop = copy_vector.find("drop(value)").expect("owner drop");
        assert!(take < capacity && capacity < push && push < drop);
        assert!(!source.contains(concat!("vector.0.push(", "Scalar::")));
        assert!(!source.contains(concat!("a_l.0.push(", "Scalar::")));
        assert!(source.contains("witnesses.push_owned(RangeWitnessCommitment {"));
        assert!(source.contains("self.terms.push_owned(SecretMultiexpTerm {"));
        let scalar_vector = source
            .split_once("impl ScalarVector {")
            .expect("scalar-vector impl")
            .1
            .split_once("struct PointVector(")
            .expect("scalar-vector boundary")
            .0;
        assert_eq!(
            scalar_vector
                .matches("RangeSecretCopyValueV1::take(&mut")
                .count(),
            4
        );
        assert!(scalar_vector.contains("&powers.0[index - 1] * value.expose_ref()"));
        assert!(scalar_vector.contains("*value = &*value + scalar.expose_ref()"));
        assert!(scalar_vector.contains("*value = &*value - scalar.expose_ref()"));
        assert!(scalar_vector.contains("*value = &*value * scalar.expose_ref()"));
        let sum = scalar_vector
            .split_once("fn sum(&self) -> Zeroizing<Scalar>")
            .expect("scalar-vector sum")
            .1
            .split_once("fn weighted_inner_product")
            .expect("sum boundary")
            .0;
        assert!(sum.contains("for value in self.0.iter()"));
        assert!(sum.contains("*sum += value"));
        assert!(!sum.contains(".iter().copied()"));
        assert!(!scalar_vector.contains("Zeroizing::new(value)"));
        assert!(!scalar_vector.contains("Zeroizing::new(scalar)"));
    }
    #[test]
    fn scalar_vector_accumulators_keep_zeroizing_result_owners() {
        let summands = ScalarVector::from_slice(&[
            Scalar::from(2_u64),
            Scalar::from(3_u64),
            Scalar::from(5_u64),
        ])
        .expect("fixed summands");
        let sum = summands.sum();
        let _: &Zeroizing<Scalar> = &sum;
        assert_eq!(*sum, Scalar::from(10_u64));
        let left = ScalarVector::from_slice(&[
            Scalar::from(2_u64),
            Scalar::from(3_u64),
            Scalar::from(5_u64),
        ])
        .expect("fixed left vector");
        let right = ScalarVector::from_slice(&[
            Scalar::from(7_u64),
            Scalar::from(11_u64),
            Scalar::from(13_u64),
        ])
        .expect("fixed right vector");
        let weights = ScalarVector::from_slice(&[
            Scalar::from(17_u64),
            Scalar::from(19_u64),
            Scalar::from(23_u64),
        ])
        .expect("fixed weight vector");
        let inner_product = left
            .weighted_inner_product(&right, &weights)
            .expect("matching fixed vectors");
        let _: &Zeroizing<Scalar> = &inner_product;
        assert_eq!(*inner_product, Scalar::from(2_360_u64));
        let source = include_str!("range.rs");
        let scalar_vector = source
            .split_once("impl ScalarVector {")
            .expect("scalar-vector impl")
            .1
            .split_once("struct PointVector(")
            .expect("scalar-vector boundary")
            .0;
        let sum = scalar_vector
            .split_once("fn sum(&self) -> Zeroizing<Scalar>")
            .expect("owned scalar-vector sum")
            .1
            .split_once("fn weighted_inner_product")
            .expect("sum boundary")
            .0;
        assert!(sum.contains("let mut sum = Zeroizing::new(Scalar::ZERO)"));
        assert!(sum.contains("\n        sum\n"));
        assert!(!sum.contains("\n        *sum\n"));
        let weighted_inner_product = scalar_vector
            .split_once("fn weighted_inner_product(")
            .expect("weighted inner product")
            .1
            .split_once("fn truncate")
            .expect("weighted inner-product boundary")
            .0;
        assert!(
            weighted_inner_product.contains(") -> Result<Zeroizing<Scalar>, FcmpNativeErrorV1>")
        );
        let compute_a_hat = source
            .split_once("fn compute_a_hat(")
            .expect("A-hat computation")
            .1
            .split_once("struct WipWitness")
            .expect("A-hat boundary")
            .0;
        assert!(compute_a_hat.contains("let y_pows = ascending_y.sum();"));
        assert!(compute_a_hat.contains("let d_sum = d.sum();"));
        assert!(compute_a_hat.contains("&*y_pows"));
        assert!(compute_a_hat.contains("&*d_sum"));
        assert!(!compute_a_hat.contains("d.sum() *"));
        let prove_wip = source
            .split_once("fn prove_wip(")
            .expect("WIP prover")
            .1
            .split_once("fn challenge_products(")
            .expect("WIP prover boundary")
            .0;
        assert!(!prove_wip.contains("let c_l = Zeroizing::new("));
        assert!(!prove_wip.contains("let c_r = Zeroizing::new("));
        assert!(prove_wip.contains("terms.push(&inner_product, &amount_generator)?"));
        assert!(prove_wip.contains("left_terms.push(&c_l, &amount_generator)?"));
        assert!(prove_wip.contains("right_terms.push(&c_r, &amount_generator)?"));
    }
    #[test]
    fn wip_responses_remain_owned_until_borrowed_final_encoding() {
        let source = include_str!("range.rs");
        let wip = source
            .split_once("struct WipProof {")
            .expect("WIP proof owner")
            .1
            .split_once("fn wip_y_vector")
            .expect("WIP owner boundary")
            .0;
        assert_eq!(wip.matches("RangeSecretCopyValueV1<Scalar>").count(), 3);
        assert!(!wip.contains("r_answer: Scalar"));
        assert!(!wip.contains("s_answer: Scalar"));
        assert!(!wip.contains("delta_answer: Scalar"));
        let prove_wip = source
            .split_once("fn prove_wip(")
            .expect("WIP prover")
            .1
            .split_once("fn challenge_products(")
            .expect("WIP prover boundary")
            .0;
        assert_eq!(prove_wip.matches("RangeSecretCopyValueV1::new(").count(), 3);
        let response_owner = prove_wip
            .find("r_answer: RangeSecretCopyValueV1::new(")
            .expect("first response owner");
        let return_end = prove_wip.rfind("})").expect("WIP publication");
        assert!(response_owner < return_end);
        let from_parts = source
            .split_once("    fn from_parts(")
            .expect("range proof encoder")
            .1
            .split_once("    /// Decode one exact fixed-shape range proof")
            .expect("encoder boundary")
            .0;
        for response in ["r_answer", "s_answer", "delta_answer"] {
            assert!(from_parts.contains(&format!("{response}: &Scalar")));
            assert!(!from_parts.contains(&format!("{response}: Scalar")));
            assert!(from_parts.contains(&format!("{response}: {response}.to_bytes()")));
        }
        let prove_range = source
            .split_once("fn prove_range_once(")
            .expect("range prover")
            .1
            .split_once("fn preflight_fcmp_range_v1(")
            .expect("range prover boundary")
            .0;
        assert!(prove_range.contains("let WipProof {"));
        assert!(prove_range.contains("r_answer.expose_ref(),"));
        assert!(prove_range.contains("s_answer.expose_ref(),"));
        assert!(prove_range.contains("delta_answer.expose_ref(),"));
        assert!(!prove_range.contains("wip.r_answer"));
        assert!(!prove_range.contains("wip.s_answer"));
        assert!(!prove_range.contains("wip.delta_answer"));
    }
    #[test]
    fn range_opening_owns_inputs_and_products_before_fallible_checks() {
        let source = include_str!("range.rs");
        let constructor = source
            .split_once("impl FcmpOutputCommitmentOpeningV1 {")
            .expect("opening impl")
            .1
            .split_once("/// Canonical aggregate FCMP Bulletproofs+ payload")
            .expect("opening boundary")
            .0;
        let amount_take = constructor
            .find("RangeSecretCopyValueV1::take(&mut amount)")
            .expect("amount take");
        let mask_take = constructor
            .find("RangeSecretCopyValueV1::take(&mut mask)")
            .expect("mask take");
        let decode = constructor
            .find("Scalar::from_canonical_bytes(")
            .expect("canonical mask decode");
        assert!(amount_take < decode && mask_take < decode);
        let decoded_take = constructor
            .find("RangeSecretCopyValueV1::take(&mut decoded_mask)")
            .expect("decoded mask take");
        assert!(decode < decoded_take);
        let generator = constructor.find("amount_generator()?").expect("generator");
        assert!(decoded_take < generator);
        assert!(constructor.contains("&amount_generator()? * amount_scalar.expose_ref()"));
        assert!(constructor.contains("&ED25519_BASEPOINT_POINT * mask.expose_ref()"));
        assert!(constructor.contains("Zeroizing::new(&*amount_component + &*mask_component)"));
        let compare = constructor
            .find("commitment.compress().to_bytes()")
            .expect("owned commitment comparison");
        let publish = constructor.find("Ok(Self {").expect("final publication");
        assert!(generator < compare && compare < publish);
        assert!(!constructor.contains("Zeroizing::new(amount)"));
        assert!(!constructor.contains("Zeroizing::new(mask)"));
        assert!(!constructor.contains("ED25519_BASEPOINT_POINT * *mask"));
        let borrowed_constructor = constructor
            .find("pub fn new_borrowed(")
            .expect("borrowed opening constructor");
        let borrowed_amount = constructor
            .find("RangeSecretCopyValueV1::copy_from_ref(amount)")
            .expect("borrowed amount owner");
        let borrowed_mask = constructor
            .find("RangeSecretCopyValueV1::copy_from_ref(mask)")
            .expect("borrowed mask owner");
        let owned_validation = constructor
            .find("fn from_secret_owners_v1(")
            .expect("owned validation boundary");
        assert!(borrowed_constructor < borrowed_amount);
        assert!(borrowed_amount < borrowed_mask && borrowed_mask < owned_validation);
        let accessors = constructor
            .split_once("/// Public tuple opened by this witness.")
            .expect("opening accessors")
            .1;
        assert!(accessors.contains("pub const fn amount(&self) -> &u64"));
        assert!(accessors.contains("pub fn commitment_mask(&self) -> Zeroizing<[u8; 32]>"));
        let mask_accessor = accessors
            .split_once("pub fn commitment_mask(&self)")
            .expect("mask accessor")
            .1;
        let mask_copy = mask_accessor
            .find("let mut mask_bytes = self.mask.to_bytes()")
            .expect("canonical mask bytes");
        let mask_take = mask_accessor
            .find("RangeSecretCopyValueV1::take(&mut mask_bytes)")
            .expect("immediate mask-byte owner");
        let output_owner = mask_accessor
            .find("let mut owned = Zeroizing::new([0_u8; 32])")
            .expect("zeroizing output owner");
        let output_copy = mask_accessor
            .find("owned.copy_from_slice(mask_bytes.expose_ref())")
            .expect("owned mask publication");
        assert!(mask_copy < mask_take && mask_take < output_owner && output_owner < output_copy);
        assert!(!mask_accessor.contains("Zeroizing::new(self.mask.to_bytes())"));
    }
    #[test]
    fn range_witness_check_keeps_secret_products_owned_and_borrowed_in_order() {
        let source = include_str!("range.rs");
        let check = source
            .split_once("fn range_witness_matches_public_commitment_v1(")
            .expect("owned range-witness check")
            .1
            .split_once("fn strict_public_commitments(")
            .expect("range-witness check boundary")
            .0;
        assert!(check.contains("amount_generator: &EdwardsPoint"));
        assert!(check.contains("point: &EdwardsPoint"));
        assert!(check.contains("witness: &RangeWitnessCommitment"));
        assert_eq!(check.matches("RangeSecretCopyValueV1::new(").count(), 4);
        let amount_owner = check
            .find("let amount_scalar = RangeSecretCopyValueV1::new(")
            .expect("owned amount scalar");
        let amount_component = check
            .find("let amount_component =")
            .expect("owned amount component");
        let mask_component = check
            .find("let mask_component =")
            .expect("owned mask component");
        let expected_owner = check
            .find("let expected_owner =")
            .expect("owned final commitment");
        let comparison = check
            .find("expected_owner.expose_ref() == point")
            .expect("borrowed final comparison");
        assert!(
            amount_owner < amount_component
                && amount_component < mask_component
                && mask_component < expected_owner
                && expected_owner < comparison
        );
        assert!(check.contains("amount_generator * amount_scalar.expose_ref()"));
        assert!(check.contains("&ED25519_BASEPOINT_POINT * &witness.mask"));
        assert!(check.contains("amount_component.expose_ref() + mask_component.expose_ref()"));
        assert!(!check.contains("let expected ="));
        assert!(!check.contains("* witness.mask"));
        let prove_range = source
            .split_once("fn prove_range_once(")
            .expect("range prover")
            .1
            .split_once("fn preflight_fcmp_range_v1(")
            .expect("range prover boundary")
            .0;
        let owned_check = prove_range
            .find("if !range_witness_matches_public_commitment_v1(")
            .expect("owned witness validation");
        let mismatch = prove_range
            .find("return Err(FcmpNativeErrorV1::RangeCommitmentOpeningMismatch);")
            .expect("fail-closed mismatch");
        assert!(owned_check < mismatch);
        assert!(!prove_range.contains("amount_generator * Scalar::from(witness.amount)"));
    }
    #[test]
    fn range_witness_check_drops_every_owner_before_match_and_mismatch_return() {
        let matching_opening = opening(0, 7, 29);
        let public_commitments = strict_public_commitments(&[matching_opening.output()])
            .expect("public commitment pair");
        let witnesses = strict_witness_commitments(std::slice::from_ref(&matching_opening), 2)
            .expect("secret witness pair");
        let amount_generator = amount_generator().expect("amount generator");
        reset_range_secret_copy_owner_drops();
        assert!(range_witness_matches_public_commitment_v1(
            &amount_generator,
            &public_commitments[0],
            &witnesses[0],
        ));
        assert_eq!(range_secret_copy_owner_drops(), 4);
        reset_range_secret_copy_owner_drops();
        assert!(!range_witness_matches_public_commitment_v1(
            &amount_generator,
            &public_commitments[0],
            &witnesses[1],
        ));
        assert_eq!(range_secret_copy_owner_drops(), 4);
        let mut mismatched = opening(1, 7, 29);
        mismatched.mask = Scalar::from(31_u64);
        reset_range_secret_copy_owner_drops();
        assert_eq!(
            prove_range_once(
                &mut FailingRngV1,
                TranscriptMode::Iroha([0x56; 32]),
                &[mismatched],
            ),
            Err(FcmpNativeErrorV1::RangeCommitmentOpeningMismatch)
        );
        assert_eq!(range_secret_copy_owner_drops(), 4);
    }
    #[test]
    fn range_preflight_reuses_owned_witness_check_before_public_rng_health_check() {
        let source = include_str!("range.rs");
        let preflight = source
            .split_once("fn preflight_fcmp_range_v1(")
            .expect("range preflight")
            .1
            .split_once("/// Produce the sole aggregate strict-positive")
            .expect("range preflight boundary")
            .0;
        let owned_check = preflight
            .find("if !range_witness_matches_public_commitment_v1(")
            .expect("owned preflight witness validation");
        let mismatch = preflight
            .find("return Err(FcmpNativeErrorV1::RangeCommitmentOpeningMismatch);")
            .expect("fail-closed preflight mismatch");
        assert!(owned_check < mismatch);
        assert!(!preflight.contains("amount_generator * Scalar::from(witness.amount)"));
        assert!(!preflight.contains("ED25519_BASEPOINT_POINT * witness.mask"));
        assert!(!preflight.contains("let expected ="));
        let public_entry = source
            .split_once("pub fn prove_fcmp_range_v1(")
            .expect("public range prover")
            .1
            .split_once("pub(super) fn prove_fcmp_range_with_checked_rng_v1(")
            .expect("public range prover boundary")
            .0;
        let preflight_call = public_entry
            .find("let outputs = preflight_fcmp_range_v1(openings)?;")
            .expect("preflight before RNG admission");
        let rng_health_check = public_entry
            .find("super::health_checked_fcmp_rng_v1(rng)?")
            .expect("RNG health check");
        let proof = public_entry
            .find("prove_fcmp_range_with_checked_rng_v1(")
            .expect("checked range prover");
        assert!(preflight_call < rng_health_check && rng_health_check < proof);
    }
    #[test]
    fn range_preflight_mismatch_drops_owned_products_before_public_rng_use() {
        let mut mismatched = opening(2, 7, 29);
        mismatched.mask = Scalar::from(31_u64);
        reset_range_secret_copy_owner_drops();
        assert_eq!(
            preflight_fcmp_range_v1(std::slice::from_ref(&mismatched)),
            Err(FcmpNativeErrorV1::RangeCommitmentOpeningMismatch)
        );
        assert_eq!(range_secret_copy_owner_drops(), 4);
        reset_range_secret_copy_owner_drops();
        assert_eq!(
            prove_fcmp_range_v1(
                &mut FailingRngV1,
                [0x57; 32],
                std::slice::from_ref(&mismatched),
            ),
            Err(FcmpNativeErrorV1::RangeCommitmentOpeningMismatch)
        );
        assert_eq!(range_secret_copy_owner_drops(), 4);
    }
    #[test]
    fn range_opening_amount_borrows_storage_and_mask_bytes_stay_owned() {
        let opening = opening(0, 7, 29);
        assert!(core::ptr::eq(opening.amount(), &raw const opening.amount));
        let mask = opening.commitment_mask();
        assert_eq!(&*mask, &Scalar::from(29_u64).to_bytes());
        assert_eq!(opening.output(), opening.output);
    }
    const ZERO_REDUCTION_BLOCK_V1: [u8; 64] = [
        // l, the Ed25519 scalar order, in little-endian form.
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
        // 2l in little-endian form. The complete 512-bit integer is divisible by l.
        0xda, 0xa7, 0xeb, 0xb9, 0x34, 0xc6, 0x24, 0xb0, 0xac, 0x39, 0xef, 0x45, 0xbd, 0xf3, 0xbd,
        0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x20,
    ];
    #[derive(Default)]
    struct ZeroReductionRng {
        try_fill_calls: usize,
        bytes_filled: usize,
    }
    impl RngCore for PeriodicRng {
        fn next_u32(&mut self) -> u32 {
            panic!("FCMP++ range prover must reject the periodic prefix")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("FCMP++ range prover must reject the periodic prefix")
        }
        fn fill_bytes(&mut self, _destination: &mut [u8]) {
            panic!("FCMP++ range prover must use fallible entropy")
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core_06::Error> {
            for byte in destination {
                *byte = ((self.cursor % self.period) as u8)
                    .wrapping_mul(59)
                    .wrapping_add(13);
                self.cursor += 1;
            }
            Ok(())
        }
    }
    impl CryptoRng for PeriodicRng {}
    impl RngCore for ZeroReductionRng {
        fn next_u32(&mut self) -> u32 {
            panic!("FCMP++ range prover must use fallible entropy")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("FCMP++ range prover must use fallible entropy")
        }
        fn fill_bytes(&mut self, _destination: &mut [u8]) {
            panic!("FCMP++ range prover must use fallible entropy")
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core_06::Error> {
            assert_eq!(
                destination.len(),
                ZERO_REDUCTION_BLOCK_V1.len(),
                "every bounded scalar draw and the health prefix must consume one exact block"
            );
            destination.copy_from_slice(&ZERO_REDUCTION_BLOCK_V1);
            self.try_fill_calls += 1;
            self.bytes_filled += destination.len();
            Ok(())
        }
    }
    impl CryptoRng for ZeroReductionRng {}
    fn hex32(value: &str) -> [u8; 32] {
        assert_eq!(value.len(), 64);
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .expect("test vector is hexadecimal");
        }
        bytes
    }
    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        (0..value.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&value[index..index + 2], 16)
                    .expect("test vector is hexadecimal")
            })
            .collect()
    }
    fn opening(ordinal: u64, amount: u64, mask: u64) -> FcmpOutputCommitmentOpeningV1 {
        let commitment = amount_generator().expect("amount generator") * Scalar::from(amount)
            + ED25519_BASEPOINT_POINT * Scalar::from(mask);
        let output = FcmpOutputTupleV1::new(
            (ED25519_BASEPOINT_POINT * Scalar::from(100 + ordinal))
                .compress()
                .to_bytes(),
            (ED25519_BASEPOINT_POINT * Scalar::from(200 + ordinal))
                .compress()
                .to_bytes(),
            commitment.compress().to_bytes(),
        )
        .expect("canonical output");
        FcmpOutputCommitmentOpeningV1::new(output, amount, Scalar::from(mask).to_bytes())
            .expect("valid opening")
    }
    #[test]
    fn exact_size_secret_vector_keeps_capacity_and_clears_success_and_error_paths() {
        let clear_calls = Arc::new(AtomicUsize::new(0));
        let mut secrets = ExactSizeZeroizingVec::new(2).expect("fixed secret capacity");
        let allocation = secrets.values.as_ptr();
        let allocation_capacity = secrets.values.capacity();
        assert_eq!(secrets.exact_capacity, 2);
        assert!(allocation_capacity >= secrets.exact_capacity);
        secrets
            .push_owned(TrackingSecret::new(11, &clear_calls))
            .expect("first secret fits");
        assert_eq!(secrets.values.as_ptr(), allocation);
        assert_eq!(secrets.values.capacity(), allocation_capacity);
        secrets
            .push_owned(TrackingSecret::new(13, &clear_calls))
            .expect("second secret fits");
        assert_eq!(secrets.values.as_ptr(), allocation);
        assert_eq!(secrets.values.capacity(), allocation_capacity);
        assert_eq!(
            secrets.push_owned(TrackingSecret::new(17, &clear_calls)),
            Err(FcmpNativeErrorV1::RangeArithmeticInvariant)
        );
        assert_eq!(clear_calls.load(Ordering::SeqCst), 1);
        assert_eq!(secrets.values.as_ptr(), allocation);
        assert_eq!(secrets.values.capacity(), allocation_capacity);
        drop(secrets);
        assert_eq!(clear_calls.load(Ordering::SeqCst), 3);
    }
    #[test]
    fn exact_size_secret_vector_clears_initialized_prefix_during_unwind() {
        let clear_calls = Arc::new(AtomicUsize::new(0));
        let unwind_clear_calls = Arc::clone(&clear_calls);
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let mut secrets = ExactSizeZeroizingVec::new(3).expect("fixed unwind-test capacity");
            secrets
                .push_owned(TrackingSecret::new(19, &unwind_clear_calls))
                .expect("first secret fits");
            secrets
                .push_owned(TrackingSecret::new(23, &unwind_clear_calls))
                .expect("second secret fits");
            panic!("exercise secret-vector unwind cleanup");
        }));
        assert!(unwind.is_err());
        assert_eq!(clear_calls.load(Ordering::SeqCst), 2);
    }
    #[test]
    fn secret_multiexp_builder_clears_successful_push_and_drop_slots() {
        reset_secret_multiexp_tracking();
        let scalar = Scalar::from(3_u8);
        let point = ED25519_BASEPOINT_POINT;
        let mut terms = SecretMultiexpBuilder::new(1).expect("one-term secret MSM");
        terms.push(&scalar, &point).expect("sole term fits");
        assert_eq!(secret_multiexp_tracking(), (1, 1, 0, 0));
        drop(terms);
        assert_eq!(secret_multiexp_tracking(), (1, 1, 1, 1));
    }
    #[test]
    fn secret_multiexp_builder_clears_overflow_slots_without_reallocation() {
        reset_secret_multiexp_tracking();
        let first_scalar = Scalar::from(7_u8);
        let overflow_scalar = Scalar::from(11_u8);
        let first_point = ED25519_BASEPOINT_POINT;
        let overflow_point = amount_generator().expect("amount generator");
        let mut terms = SecretMultiexpBuilder::new(1).expect("one-term secret MSM");
        terms
            .push(&first_scalar, &first_point)
            .expect("sole term fits");
        let allocation = terms.terms.values.as_ptr();
        let allocation_capacity = terms.terms.values.capacity();
        assert_eq!(
            terms.push(&overflow_scalar, &overflow_point),
            Err(FcmpNativeErrorV1::RangeArithmeticInvariant)
        );
        assert_eq!(terms.terms.values.as_ptr(), allocation);
        assert_eq!(terms.terms.values.capacity(), allocation_capacity);
        assert_eq!(secret_multiexp_tracking(), (2, 2, 0, 0));
        drop(terms);
        assert_eq!(secret_multiexp_tracking(), (2, 2, 1, 1));
    }
    #[test]
    fn secret_multiexp_builder_clears_incomplete_evaluation_terms() {
        reset_secret_multiexp_tracking();
        let scalar = Scalar::from(13_u8);
        let point = ED25519_BASEPOINT_POINT;
        let mut terms = SecretMultiexpBuilder::new(2).expect("two-term secret MSM");
        terms.push(&scalar, &point).expect("first term fits");
        assert_eq!(
            terms.evaluate(),
            Err(FcmpNativeErrorV1::RangeArithmeticInvariant)
        );
        assert_eq!(secret_multiexp_tracking(), (1, 1, 1, 1));
    }
    #[test]
    fn secret_multiexp_builder_clears_complete_evaluation_terms() {
        reset_secret_multiexp_tracking();
        let first_scalar = Scalar::from(3_u8);
        let second_scalar = Scalar::from(5_u8);
        let first_point = ED25519_BASEPOINT_POINT;
        let second_point = amount_generator().expect("amount generator");
        let mut terms = SecretMultiexpBuilder::new(2).expect("two-term secret MSM");
        terms
            .push(&first_scalar, &first_point)
            .expect("first term fits");
        terms
            .push(&second_scalar, &second_point)
            .expect("second term fits");
        assert_eq!(
            terms.evaluate().expect("complete secret MSM"),
            first_point * first_scalar + second_point * second_scalar
        );
        assert_eq!(secret_multiexp_tracking(), (2, 2, 2, 2));
    }
    #[test]
    fn secret_multiexp_guards_clear_during_unwind() {
        reset_secret_multiexp_tracking();
        let mut scalar_slot = Scalar::from(17_u8);
        let mut point_slot = ED25519_BASEPOINT_POINT;
        let guard_unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _incoming =
                BorrowedSecretMultiexpTermSlotsV1::new(&mut scalar_slot, &mut point_slot);
            panic!("exercise private secret-MSM input guard");
        }));
        assert!(guard_unwind.is_err());
        assert_eq!(secret_multiexp_tracking(), (1, 1, 0, 0));
        reset_secret_multiexp_tracking();
        let builder_unwind = std::panic::catch_unwind(|| {
            let scalar = Scalar::from(19_u8);
            let point = ED25519_BASEPOINT_POINT;
            let mut terms = SecretMultiexpBuilder::new(1).expect("one-term secret MSM");
            terms.push(&scalar, &point).expect("sole term fits");
            panic!("exercise retained secret-MSM term owner");
        });
        assert!(builder_unwind.is_err());
        assert_eq!(secret_multiexp_tracking(), (1, 1, 1, 1));
    }
    #[test]
    fn secret_multiexp_source_boundary_stays_borrowed_guarded_and_owned() {
        let source = include_str!("range.rs");
        let builder = source
            .split_once("struct SecretMultiexpTerm {")
            .expect("secret MSM term")
            .1
            .split_once("fn random_nonzero_scalar(")
            .expect("secret MSM implementation boundary")
            .0;
        assert!(builder.contains("impl Drop for SecretMultiexpTerm"));
        assert!(builder.contains("self.scalar.zeroize();"));
        assert!(builder.contains("self.point.zeroize();"));
        assert!(builder.contains("fn push(&mut self, scalar: &Scalar, point: &EdwardsPoint)"));
        assert!(builder.contains("self.push_copy(*scalar, *point)"));
        assert!(builder.contains("fn push_copy("));
        assert!(builder.contains("mut scalar: Scalar,"));
        assert!(builder.contains("mut point: EdwardsPoint,"));
        let guard = builder
            .find("BorrowedSecretMultiexpTermSlotsV1::new(&mut scalar, &mut point)")
            .expect("private input guard");
        let capacity_check = builder
            .find("if self.terms.is_full()")
            .expect("pre-insertion capacity check");
        let insertion = builder
            .find("self.terms.push_owned(SecretMultiexpTerm {")
            .expect("owned term insertion");
        let guard_drop = builder
            .find("drop(incoming);")
            .expect("explicit guard drop");
        assert!(guard < capacity_check && capacity_check < insertion && insertion < guard_drop);
        assert!(!builder.contains("fn push(&mut self, scalar: Scalar, point: EdwardsPoint)"));
        let prove_wip = source
            .split_once("fn prove_wip(")
            .expect("WIP prover")
            .1
            .split_once("fn challenge_products(")
            .expect("WIP prover boundary")
            .0;
        assert!(!prove_wip.contains(".iter().copied().zip("));
        assert!(!prove_wip.contains("terms.push(*inner_product"));
        assert!(!prove_wip.contains("left_terms.push(*"));
        assert!(!prove_wip.contains("right_terms.push(*"));
        assert!(!prove_wip.contains("a_terms.push(*"));
        assert!(!prove_wip.contains("b_terms.push(*"));
        assert!(prove_wip.contains("let proof_a_amount = Zeroizing::new("));
        assert!(prove_wip.contains("a_terms.push(&proof_a_amount, &amount_generator)"));
        assert!(prove_wip.contains("let proof_b_amount = Zeroizing::new("));
        assert!(prove_wip.contains("b_terms.push(&proof_b_amount, &amount_generator)"));
        let prove_range = source
            .split_once("fn prove_range_once(")
            .expect("range prover")
            .1
            .split_once("#[cfg(test)]\nfn preflight_fcmp_range_v1(")
            .expect("range prover boundary")
            .0;
        assert!(!prove_range.contains("a_l.0.iter().copied()"));
        assert!(!prove_range.contains("a_r.0.iter().copied()"));
        assert!(!prove_range.contains("a_terms.push(*alpha"));
    }
    #[test]
    fn padded_witness_vector_uses_public_final_capacity_before_secret_insertion() {
        let openings = [opening(1, 3, 5), opening(2, 7, 11), opening(3, 13, 17)];
        let padded = padded_range_commitment_count(openings.len()).expect("public padded count");
        assert_eq!(padded, 8);
        let witnesses = strict_witness_commitments(&openings, padded).expect("padded witnesses");
        assert_eq!(witnesses.exact_capacity, padded);
        assert_eq!(witnesses.len(), padded);
        assert_eq!(witnesses.values.capacity(), witnesses.allocation_capacity);
        assert_eq!(
            witnesses
                .iter()
                .skip(openings.len() * FCMP_RANGE_COMMITMENTS_PER_OUTPUT_V1)
                .map(|witness| (witness.amount, witness.mask))
                .collect::<Vec<_>>(),
            vec![(0, Scalar::ZERO); 2]
        );
    }
    #[test]
    fn range_rng_unavailability_fails_without_calling_infallible_rng_methods() {
        assert_eq!(
            prove_fcmp_range_v1(&mut FailingRngV1, [0x31; 32], &[]),
            Err(FcmpNativeErrorV1::RangeOutputCount {
                actual: 0,
                max: FCMP_MAX_OUTPUTS_NATIVE_V1,
            })
        );
        assert_eq!(
            random_nonzero_scalar(&mut FailingRngV1),
            Err(FcmpNativeErrorV1::RandomnessUnavailable)
        );
        assert_eq!(
            prove_fcmp_range_v1(&mut FailingRngV1, [0x31; 32], &[opening(1, 5, 7)]),
            Err(FcmpNativeErrorV1::RandomnessUnavailable)
        );
    }
    #[test]
    fn scalar_sampler_returns_a_zeroizing_owner_without_a_raw_round_trip() {
        let mut rng = PeriodicRng {
            period: 1,
            cursor: 0,
        };
        let scalar = random_nonzero_scalar(&mut rng).expect("constant nonzero reduction");
        let _: &Zeroizing<Scalar> = &scalar;
        assert!(core::mem::needs_drop::<Zeroizing<Scalar>>());
        assert_ne!(*scalar, Scalar::ZERO);
        assert_eq!(rng.cursor, 64, "one scalar draw consumes one exact block");
        let source = include_str!("range.rs");
        let sampler = source
            .split_once("fn random_nonzero_scalar(")
            .expect("bounded scalar sampler")
            .1
            .split_once("#[derive(Clone, Copy)]")
            .expect("scalar sampler boundary")
            .0;
        assert!(sampler.contains(") -> Result<Zeroizing<Scalar>, FcmpNativeErrorV1>"));
        assert!(sampler.contains("return Ok(scalar);"));
        assert!(!sampler.contains("return Ok(*scalar);"));
        let prove_wip = source
            .split_once("fn prove_wip(")
            .expect("WIP prover")
            .1
            .split_once("fn challenge_products(")
            .expect("WIP prover boundary")
            .0;
        for owner in ["d_l", "d_r", "r", "s", "delta", "eta"] {
            assert!(prove_wip.contains(&format!("let {owner} = random_nonzero_scalar(rng)?;")));
        }
        assert!(!prove_wip.contains("Zeroizing::new(random_nonzero_scalar(rng)?)"));
        let prove_range = source
            .split_once("fn prove_range_once(")
            .expect("range prover")
            .1
            .split_once("#[cfg(test)]\nfn preflight_fcmp_range_v1(")
            .expect("range prover boundary")
            .0;
        assert!(prove_range.contains("let alpha = random_nonzero_scalar(rng)?;"));
        assert!(!prove_range.contains("Zeroizing::new(random_nonzero_scalar(rng)?)"));
    }
    #[test]
    fn range_public_prover_rejects_every_prohibited_short_period_prefix() {
        let opening = opening(1, 5, 7);
        for period in [1, 2, 4, 8, 16, 32] {
            assert_eq!(
                prove_fcmp_range_v1(
                    &mut PeriodicRng { period, cursor: 0 },
                    [0x32; 32],
                    std::slice::from_ref(&opening),
                ),
                Err(FcmpNativeErrorV1::RandomnessHealthCheckFailed),
                "period-{period} range entropy was not rejected"
            );
        }
    }
    #[test]
    fn scalar_sampling_exhaustion_is_distinct_from_full_proof_restarts() {
        assert_eq!(
            Scalar::from_bytes_mod_order_wide(&ZERO_REDUCTION_BLOCK_V1),
            Scalar::ZERO
        );
        let mut rng = ZeroReductionRng::default();
        assert_eq!(
            prove_fcmp_range_v1(&mut rng, [0x33; 32], &[opening(1, 5, 7)]),
            Err(FcmpNativeErrorV1::ProverRandomnessExhausted)
        );
        assert_eq!(
            rng.try_fill_calls, MAX_SCALAR_SAMPLING_ATTEMPTS_V1,
            "the checked prefix is replayed as the first scalar attempt"
        );
        assert_eq!(
            rng.bytes_filled,
            MAX_SCALAR_SAMPLING_ATTEMPTS_V1 * ZERO_REDUCTION_BLOCK_V1.len()
        );
        assert_eq!(MAX_SCALAR_SAMPLING_ATTEMPTS_V1, 128);
    }
    #[test]
    fn range_restarts_only_transcript_dependent_honest_aborts_at_a_fixed_bound() {
        let mut attempts = 0;
        let recovered = retry_range_prover_v1(|| {
            attempts += 1;
            match attempts {
                1 => Err(FcmpNativeErrorV1::RangeProofPoint),
                2 => Err(FcmpNativeErrorV1::RangeChallengeZero),
                _ => Ok(23_u8),
            }
        })
        .expect("third attempt succeeds");
        assert_eq!(recovered, 23);
        assert_eq!(attempts, 3);
        for retryable in [
            FcmpNativeErrorV1::RangeProofPoint,
            FcmpNativeErrorV1::RangeChallengeZero,
        ] {
            attempts = 0;
            assert_eq!(
                retry_range_prover_v1::<()>(|| {
                    attempts += 1;
                    Err(retryable)
                }),
                Err(FcmpNativeErrorV1::RangeProverRestartExhausted)
            );
            assert_eq!(attempts, MAX_PROVER_RESTARTS_V1);
        }
        assert_eq!(MAX_PROVER_RESTARTS_V1, 128);
        attempts = 0;
        assert_eq!(
            retry_range_prover_v1::<()>(|| {
                attempts += 1;
                Err(FcmpNativeErrorV1::RangeArithmeticInvariant)
            }),
            Err(FcmpNativeErrorV1::RangeArithmeticInvariant)
        );
        assert_eq!(attempts, 1);
    }
    #[test]
    fn monero_hash_to_point_and_generator_basis_match_pinned_vectors() {
        assert_eq!(
            amount_generator()
                .expect("pinned amount generator")
                .compress()
                .to_bytes(),
            MONERO_H_BYTES_V1
        );
        assert_eq!(
            monero_hash_to_point(hex32(
                "75274bfd79bf33eb2f9ab046d34528af9a71811e7e3d55c20eb049c81ac692d8"
            ))
            .expect("Monero hash_to_ec")
            .compress()
            .to_bytes(),
            hex32("cb93c850e36896fe6626e97c53652af6736ec3ba0641c7765d0cca2bad2352de")
        );
        let generators = bp_plus_generators().expect("pinned generator basis");
        assert_eq!(generators.len(), 512);
        assert_ne!(generators.g_bold[0], generators.h_bold[0]);
        assert_eq!(
            fcmp_bp_plus_generator_digest_v1().expect("basis digest"),
            FCMP_BP_PLUS_GENERATOR_DIGEST_V1
        );
    }
    #[test]
    fn pinned_serai_bulletproofs_plus_vector_verifies_natively() {
        // Generated by monero-bulletproofs at the pinned revision with
        // ChaCha20Rng seed 0x71*32 and witnesses (mask=17, amount=9) and
        // (mask=17, amount=8). Those are exactly C and C-H for one strict
        // positive output with amount 9.
        const PROOF: &str = concat!(
            "5868bc7fc212e1d9ae5dbebc3c3fc69ae1ea0c767aeaab86a493c35eda1f518c85d08b4c96d469029dbf00a5f3161123",
            "f8f0f537fc491b7ad86810d264ccadaa6d95e3cf6f7df084e653b1b0b71e5993304d8e29b8bb220161acc5fa05b58051",
            "16e279fbf0d4a050f51443e04603d4c1ac0c79c4d6d42997736b99c2f19c2a0259f4ef85025d9150b92295bd89a0721f",
            "569bca35eafd6828d50894536ee51409bd4262ce8061278ca1abf61a6adb93203b42cd683f23d7fe2cb652a54e31d700",
            "589875f6eae58e855a404ad61cc25992746af443a338460edbd30e236cc408e7b5a60504f1eeb4c17e3e2a9442df2064",
            "2d97c872f3d3439ccb1f26cc7dfabdadfffe16837aecbbc4e03b6618ab2f96699e9a02667d0f9f9f780cd64c99e6b8fc",
            "22a6644da389f195e3b89f39f3449406547b337caa227340000557a1f8c56b8bfdc62d7a6c22fcd39c9a2d00c6e6de38",
            "23002a21253fdbd8ccec1b0f53ea298c65f33ed0cc838faa8c3270872baf44ea9ca428ed095e959a1f4cec1bb90a3a35",
            "f89baa4a4f4f35dcf05c1e1a33ffa801a8f359a362ce5df91377d0c2049ae1eb20e475f8f5cc9a5b7adc077e89ea156a",
            "23a4db76105ee4037a8ede5d9eb9c4d9bb0198ec90320708ddea43111e86239f067956b3528d0c099938828b4872af7e",
            "df00da63fddcba77c4ead4a6141424f9794755375ee7c4670157376a5d6453454f0f9a7ea2afa1b203cc0aeb2fc3e327",
            "6017564e247c816ed3efb65b4806f8f57ca45e851d9cf3b10236993813ffa2254625c7509131c2c7747586094b2b86b4",
            "363b2de00e6b7edb13cb90ff365c094806079068e4a8d5de713b81b5823fa97cc8041aa3d6f99908a220a8408a2ba508",
            "c1d67ce76ed89047df8393296286f04a",
        );
        let commitment = amount_generator().expect("amount generator") * Scalar::from(9_u64)
            + ED25519_BASEPOINT_POINT * Scalar::from(17_u64);
        let output = FcmpOutputTupleV1::new(
            (ED25519_BASEPOINT_POINT * Scalar::from(101_u64))
                .compress()
                .to_bytes(),
            (ED25519_BASEPOINT_POINT * Scalar::from(103_u64))
                .compress()
                .to_bytes(),
            commitment.compress().to_bytes(),
        )
        .expect("canonical output");
        let proof = FcmpRangeProofV1::decode(&decode_hex(PROOF), 1).expect("pinned proof encoding");
        verify_range_with_mode(TranscriptMode::PinnedUpstream, &[output], &proof)
            .expect("pinned upstream BP+ proof");
    }
    #[test]
    fn native_standard_transcript_proof_is_upstream_compatible() {
        let opening = opening(1, 9, 17);
        let output = opening.output();
        let mut rng = StdRng::seed_from_u64(0x0fcb_0000);
        let proof = prove_range_once(&mut rng, TranscriptMode::PinnedUpstream, &[opening])
            .expect("native standard-transcript proof");
        verify_range_with_mode(TranscriptMode::PinnedUpstream, &[output], &proof)
            .expect("native proof verifies");
        let encoded = proof.encode(1).expect("canonical encoding");
        let encoded_digest: [u8; 32] = Sha256::digest(&encoded).into();
        // The corresponding 640-byte proof was parsed by pinned Serai
        // `Bulletproof::read_plus` (after adding the two standard vector-length
        // prefixes omitted by Monero's signature wire) and accepted by its
        // verifier against commitments (mask=17, amount=9) and
        // (mask=17, amount=8).
        assert_eq!(
            encoded_digest,
            [
                0x77, 0x48, 0x9e, 0x96, 0x20, 0x35, 0xd6, 0x0b, 0x04, 0xa1, 0xae, 0xf7, 0xcb, 0xda,
                0x5d, 0xf3, 0x8d, 0x4b, 0xe6, 0x21, 0x02, 0x68, 0xb7, 0xe5, 0x2d, 0x0a, 0xfa, 0xed,
                0x71, 0x74, 0x53, 0xc6,
            ]
        );
    }
    #[test]
    fn strict_positive_u64_range_round_trips_and_binds_every_public_dimension() {
        let openings = [opening(1, 1, 17), opening(2, u64::MAX, 19)];
        let outputs = openings
            .iter()
            .map(FcmpOutputCommitmentOpeningV1::output)
            .collect::<Vec<_>>();
        let context = [0x52; 32];
        let mut rng = StdRng::seed_from_u64(0x0fcb_0001);
        let proof =
            prove_fcmp_range_v1(&mut rng, context, &openings).expect("valid aggregate proof");
        assert_eq!(
            proof
                .encode(outputs.len())
                .expect("canonical encoding")
                .len(),
            fcmp_range_proof_size_v1(outputs.len()).expect("fixed size")
        );
        verify_fcmp_range_v1(context, &outputs, &proof).expect("valid aggregate proof");
        let mut wrong_context = context;
        wrong_context[0] ^= 1;
        assert!(verify_fcmp_range_v1(wrong_context, &outputs, &proof).is_err());
        let mut reordered = outputs.clone();
        reordered.swap(0, 1);
        assert!(verify_fcmp_range_v1(context, &reordered, &proof).is_err());
        let substituted = opening(3, 2, 23).output();
        let mut changed = outputs.clone();
        changed[1] = substituted;
        assert!(verify_fcmp_range_v1(context, &changed, &proof).is_err());
        let encoded = proof.encode(outputs.len()).expect("canonical encoding");
        for offset in [0, 32, 64, 96, encoded.len() / 2, encoded.len() - 1] {
            let mut mutation = encoded.clone();
            mutation[offset] ^= 1;
            assert!(
                FcmpRangeProofV1::decode(&mutation, outputs.len())
                    .and_then(|proof| verify_fcmp_range_v1(context, &outputs, &proof))
                    .is_err(),
                "mutated range field at byte {offset} was accepted"
            );
        }
        assert!(FcmpRangeProofV1::decode(&encoded[..encoded.len() - 1], outputs.len()).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(FcmpRangeProofV1::decode(&trailing, outputs.len()).is_err());
    }
    #[test]
    fn zero_overflow_opening_substitution_and_balancing_points_fail_closed() {
        let valid = opening(1, 7, 29);
        assert_eq!(
            FcmpOutputCommitmentOpeningV1::new(valid.output(), 0, Scalar::from(29_u64).to_bytes())
                .expect_err("zero amount is outside the strict range"),
            FcmpNativeErrorV1::RangeWitnessOutOfRange
        );
        assert_eq!(
            FcmpOutputCommitmentOpeningV1::new(valid.output(), 7, Scalar::from(31_u64).to_bytes())
                .expect_err("mask substitution must not open C"),
            FcmpNativeErrorV1::RangeCommitmentOpeningMismatch
        );
        assert!(u64::MAX.checked_add(1).is_none());
        let zero_mask_commitment =
            amount_generator().expect("amount generator") * Scalar::from(2_u64);
        let zero_mask_output = FcmpOutputTupleV1::new(
            (ED25519_BASEPOINT_POINT * Scalar::from(271_u64))
                .compress()
                .to_bytes(),
            (ED25519_BASEPOINT_POINT * Scalar::from(277_u64))
                .compress()
                .to_bytes(),
            zero_mask_commitment.compress().to_bytes(),
        )
        .expect("canonical zero-mask commitment");
        FcmpOutputCommitmentOpeningV1::new(zero_mask_output, 2, Scalar::ZERO.to_bytes())
            .expect("zero masks are part of the verifier relation");
        let context = [0x53; 32];
        let mut rng = StdRng::seed_from_u64(0x0fcb_0002);
        let proof =
            prove_fcmp_range_v1(&mut rng, context, &[valid]).expect("valid strict-positive proof");
        // C = mask*G + 2^64*H is the first integer outside the u64 range.
        let two_pow_64 = (0..64).fold(Scalar::ONE, |value, _| value + value);
        let overflow_commitment = ED25519_BASEPOINT_POINT * Scalar::from(37_u64)
            + amount_generator().expect("amount generator") * two_pow_64;
        let overflow = FcmpOutputTupleV1::new(
            (ED25519_BASEPOINT_POINT * Scalar::from(301_u64))
                .compress()
                .to_bytes(),
            (ED25519_BASEPOINT_POINT * Scalar::from(302_u64))
                .compress()
                .to_bytes(),
            overflow_commitment.compress().to_bytes(),
        )
        .expect("canonical arbitrary commitment");
        assert!(verify_fcmp_range_v1(context, &[overflow], &proof).is_err());
        // A transaction can always manufacture a public point that makes a
        // group-balance equation hold. It cannot manufacture its bounded
        // opening or transplant a proof for a different point.
        let arbitrary_balancing = FcmpOutputTupleV1::new(
            (ED25519_BASEPOINT_POINT * Scalar::from(401_u64))
                .compress()
                .to_bytes(),
            (ED25519_BASEPOINT_POINT * Scalar::from(402_u64))
                .compress()
                .to_bytes(),
            (ED25519_BASEPOINT_POINT * Scalar::from(987_654_u64))
                .compress()
                .to_bytes(),
        )
        .expect("canonical arbitrary group point");
        assert!(verify_fcmp_range_v1(context, &[arbitrary_balancing], &proof).is_err());
        let c_equals_h = FcmpOutputTupleV1::new(
            (ED25519_BASEPOINT_POINT * Scalar::from(501_u64))
                .compress()
                .to_bytes(),
            (ED25519_BASEPOINT_POINT * Scalar::from(502_u64))
                .compress()
                .to_bytes(),
            amount_generator()
                .expect("amount generator")
                .compress()
                .to_bytes(),
        )
        .expect("C itself is canonical");
        assert_eq!(
            strict_public_commitments(&[c_equals_h]).expect_err("C-H identity is forbidden"),
            FcmpNativeErrorV1::RangeAdjustedCommitment
        );
    }
}
