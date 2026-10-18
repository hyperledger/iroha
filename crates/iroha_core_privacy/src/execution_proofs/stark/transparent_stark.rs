//! Native execution proof driver; privacy proofs use their separate implementation.
//! Protocol-neutral transparent Goldilocks STARK primitives.
//!
//! This module contains only proof-system substrate: canonical Goldilocks base and
//! quartic-extension arithmetic, FFT/coset evaluation, zero-knowledge trace masking, framed
//! Fiat–Shamir, six-lane Goldilocks Poseidon-x7 Merkle commitments, binary FRI folding, grinding,
//! and exact byte readers/writers. This retained module accepts execution contexts only. Privacy protocols keep
//! their own wire implementation and use the same canonical six-lane hash owner. This
//! execution suite remains unqualified.
//!
//! The historical generic `crate::zk_stark` development envelope is not used: its query schedule
//! does not establish knowledge of the witness-bearing row. Callers of this substrate must commit
//! and query every masked witness column, bind composition quotients to those same openings, and
//! perform the complete FRI terminal-degree check.
pub use fastpq_isi::GoldilocksDigest384V1;
#[cfg(test)]
use fastpq_isi::{GoldilocksDigest384LastFieldStreamErrorV1, GoldilocksDigest384LastFieldStreamV1};
use fastpq_isi::{GoldilocksDigestDomainV1, hash_bytes_384_v1};
use rand::TryRngCore;
use rayon::prelude::*;
use sha2::Digest as _;
use std::collections::BTreeMap;
use thiserror::Error;
/// Goldilocks prime `2^64 - 2^32 + 1`.
pub const GOLDILOCKS_MODULUS_V1: u64 = 0xffff_ffff_0000_0001;
/// Canonical generator used for every compiled domain and coset.
pub const GOLDILOCKS_GENERATOR_V1: u64 = 7;
/// Two-adicity of the Goldilocks multiplicative group.
pub const GOLDILOCKS_TWO_ADICITY_V1: u32 = 32;
const TRANSCRIPT_INIT_DOMAIN_V1: &[u8] = b"iroha:execution:transparent-stark:init:v1";
const TRANSCRIPT_ABSORB_DOMAIN_V1: &[u8] = b"iroha:execution:transparent-stark:absorb:v1";
const TRANSCRIPT_CHALLENGE_DOMAIN_V1: &[u8] = b"iroha:execution:transparent-stark:challenge:v1";
const TRANSCRIPT_FP4_CHALLENGE_DOMAIN_V1: &[u8] =
    b"iroha:execution:transparent-stark:challenge:goldilocks-fp4:v1";
const QUERY_INDEX_DOMAIN_V1: &[u8] = b"iroha:execution:transparent-stark:query-index:v1";
const GRINDING_DOMAIN_V1: &[u8] = b"iroha:execution:transparent-stark:grinding:v1";
const MERKLE_NODE_PHASE_V1: &[u8] = b"binary-merkle-node";
/// Avoid Rayon dispatch overhead once a Merkle level becomes small.
const MERKLE_PARALLEL_PARENT_THRESHOLD_V1: usize = 256;
/// Avoid parallel dispatch for tiny development/test grinding targets.
const GRINDING_PARALLEL_MIN_BITS_V1: u8 = 12;
/// Search canonical nonce intervals in this fixed order while parallelizing within each interval.
const GRINDING_PARALLEL_CHUNK_SIZE_V1: u64 = 4_096;
/// Fixed rejection budget for canonical field and transcript sampling.
pub const MAX_FIELD_REJECTION_ATTEMPTS_V1: u64 = 16;
/// Fixed rejection budget for each unbiased query-index range sample.
const MAX_QUERY_INDEX_REJECTION_ATTEMPTS_V1: u64 = 256;

/// Exact catalog/protocol/profile context for every native-STARK digest.
///
/// The execution catalog commitment is pinned internally, so a caller cannot
/// substitute a different catalog while retaining the same protocol and
/// profile labels. This type represents only execution contexts. Identifiers are distinct
/// fields and never concatenated into an ambiguous free-form domain string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransparentStarkDigestContextV1 {
    profile: &'static [u8],
}
impl TransparentStarkDigestContextV1 {
    /// Native execution proofs occupy a separate catalog and protocol namespace.
    pub(crate) const fn execution_v1(profile: &'static [u8]) -> Self {
        Self { profile }
    }
    /// Execution proof byte ceiling, independent of cryptographic geometry.
    pub(crate) const fn maximum_proof_bytes_v1(self) -> usize {
        iroha_data_model::execution_proofs::EXECUTION_PROOF_MAX_ENVELOPE_BYTES_V1
    }
    fn catalog_v1(self) -> [u8; 48] {
        sha2::Sha384::digest(b"iroha:execution:catalog:v1:goldilocks-poseidon-x7-six-lane").into()
    }
    fn protocol_label_v1(self) -> &'static [u8] {
        b"native-execution-v1"
    }
    pub(crate) fn validate(self) -> Result<(), TransparentStarkErrorV1> {
        if self.profile.is_empty() || u16::try_from(self.profile.len()).is_err() {
            return Err(TransparentStarkErrorV1::InvalidDigestDomain);
        }
        Ok(())
    }
}
/// Checked zero-knowledge masking geometry for the canonical DEEP-ALI flow.
///
/// `minimum_mask_coefficients` is the dimension `h` of the randomizer space
/// `Fp[X]_<h`; consequently its largest permitted monomial degree is `h - 1`.
/// Keeping those two quantities distinct prevents the consensus profile from
/// acquiring an off-by-one error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransparentStarkZkMaskGeometryV1 {
    /// Reduced AIR degree (`d_air - 1` in Haböck--Al Kindi).
    pub(crate) reduced_air_degree: usize,
    /// Degree of the challenge field over the trace base field.
    pub(crate) extension_degree: usize,
    /// Number of extension-field DEEP samples.
    pub(crate) deep_query_count: usize,
    /// Number of base-domain FRI queries exposed for each witness oracle.
    pub(crate) fri_query_count: usize,
    /// Exact lower bound on the number of randomizer coefficients.
    pub(crate) minimum_mask_coefficients: usize,
    /// Largest degree of a minimum-size randomizer polynomial.
    pub(crate) minimum_mask_degree: usize,
}
pub use crate::privacy_engines::transparent_stark::{GoldilocksFieldV1, GoldilocksFp4V1};
/// Failure in protocol-neutral transparent-proof machinery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum TransparentStarkErrorV1 {
    /// A catalog-bound protocol/profile/role/phase digest domain is invalid.
    #[error("transparent STARK digest domain is invalid")]
    InvalidDigestDomain,
    /// A power-of-two domain shape or degree bound is invalid.
    #[error("transparent STARK domain shape is invalid")]
    InvalidDomain,
    /// The requested FFT domain exceeds Goldilocks two-adicity.
    #[error("transparent STARK domain exceeds Goldilocks two-adicity")]
    DomainTooLarge,
    /// A required inverse does not exist.
    #[error("transparent STARK attempted to invert zero")]
    DivisionByZero,
    /// An encoded field value is not canonical.
    #[error("transparent STARK field encoding is non-canonical")]
    NonCanonicalField,
    /// A Merkle tree or opening has an invalid shape.
    #[error("transparent STARK Merkle shape is invalid")]
    InvalidMerkleShape,
    /// Canonical transcript framing overflowed.
    #[error("transparent STARK transcript frame length overflow")]
    FrameLengthOverflow,
    /// Fiat–Shamir sampling exhausted its fixed rejection bound.
    #[error("transparent STARK Fiat-Shamir rejection bound exhausted")]
    ChallengeSamplingExhausted,
    /// Unique query-index derivation exhausted its fixed work bound.
    #[error("transparent STARK query-index derivation exhausted")]
    QuerySamplingExhausted,
    /// The operating-system or injected random source failed.
    #[error("transparent STARK masking randomness is unavailable")]
    RandomnessUnavailable,
    /// A complete terminal polynomial exceeds the required degree.
    #[error("transparent STARK FRI terminal degree is too high")]
    FriDegree,
    /// A proof byte stream is truncated or has a trailing suffix.
    #[error("transparent STARK proof bytes are malformed")]
    MalformedProof,
    /// Exact bounded allocation failed.
    #[error("transparent STARK bounded allocation failed")]
    AllocationFailure,
    /// The configured grinding nonce does not meet its bit target.
    #[error("transparent STARK grinding nonce is invalid")]
    InvalidGrinding,
}
/// Derive the exact minimum Protocol-3 masking geometry.
///
/// This is Equation (3) of Haböck--Al Kindi, ePrint 2024/1037:
///
/// `2 * d * (e * n_DEEP + n_FRI) + n_FRI <= h`.
///
/// Here `h` counts coefficients because the sampled randomizer belongs to
/// `Fp[X]_<h`. A DEEP-free local subproof may pass zero for
/// `deep_query_count`; FRI still requires at least one query.
pub fn transparent_stark_zk_mask_geometry_v1(
    reduced_air_degree: usize,
    extension_degree: usize,
    deep_query_count: usize,
    fri_query_count: usize,
) -> Result<TransparentStarkZkMaskGeometryV1, TransparentStarkErrorV1> {
    if reduced_air_degree == 0 || extension_degree == 0 || fri_query_count == 0 {
        return Err(TransparentStarkErrorV1::InvalidDomain);
    }
    let extension_deep_queries = extension_degree
        .checked_mul(deep_query_count)
        .ok_or(TransparentStarkErrorV1::InvalidDomain)?;
    let revealed_queries = extension_deep_queries
        .checked_add(fri_query_count)
        .ok_or(TransparentStarkErrorV1::InvalidDomain)?;
    let minimum_mask_coefficients = 2_usize
        .checked_mul(reduced_air_degree)
        .and_then(|factor| factor.checked_mul(revealed_queries))
        .and_then(|implicit| implicit.checked_add(fri_query_count))
        .ok_or(TransparentStarkErrorV1::InvalidDomain)?;
    let minimum_mask_degree = minimum_mask_coefficients
        .checked_sub(1)
        .ok_or(TransparentStarkErrorV1::InvalidDomain)?;
    Ok(TransparentStarkZkMaskGeometryV1 {
        reduced_air_degree,
        extension_degree,
        deep_query_count,
        fri_query_count,
        minimum_mask_coefficients,
        minimum_mask_degree,
    })
}
/// Compute the primitive root for an exact power-of-two order.
pub fn goldilocks_primitive_root_v1(
    log_size: u8,
) -> Result<GoldilocksFieldV1, TransparentStarkErrorV1> {
    if u32::from(log_size) > GOLDILOCKS_TWO_ADICITY_V1 {
        return Err(TransparentStarkErrorV1::DomainTooLarge);
    }
    let order = 1_u128 << log_size;
    let root = GoldilocksFieldV1(GOLDILOCKS_GENERATOR_V1)
        .pow((u128::from(GOLDILOCKS_MODULUS_V1) - 1) / order);
    if root.pow(order) != GoldilocksFieldV1::ONE
        || (order > 1 && root.pow(order / 2) == GoldilocksFieldV1::ONE)
    {
        return Err(TransparentStarkErrorV1::InvalidDomain);
    }
    Ok(root)
}
/// In-place radix-two FFT.
pub fn goldilocks_fft_v1(
    values: &mut [GoldilocksFieldV1],
    root: GoldilocksFieldV1,
) -> Result<(), TransparentStarkErrorV1> {
    let size = values.len();
    if size == 0
        || !size.is_power_of_two()
        || root.0 >= GOLDILOCKS_MODULUS_V1
        || root.pow(size as u128) != GoldilocksFieldV1::ONE
        || (size > 1 && root.pow((size / 2) as u128) == GoldilocksFieldV1::ONE)
    {
        return Err(TransparentStarkErrorV1::InvalidDomain);
    }
    if values.iter().any(|value| value.0 >= GOLDILOCKS_MODULUS_V1) {
        return Err(TransparentStarkErrorV1::NonCanonicalField);
    }
    let mut reversed = 0_usize;
    for index in 1..size {
        let mut bit = size >> 1;
        while reversed & bit != 0 {
            reversed ^= bit;
            bit >>= 1;
        }
        reversed ^= bit;
        if index < reversed {
            values.swap(index, reversed);
        }
    }
    let mut width = 2_usize;
    while width <= size {
        let step = root.pow((size / width) as u128);
        for chunk in values.chunks_exact_mut(width) {
            let mut twiddle = GoldilocksFieldV1::ONE;
            let (left, right) = chunk.split_at_mut(width / 2);
            for (even, odd) in left.iter_mut().zip(right.iter_mut()) {
                let scaled_odd = (*odd).mul(twiddle);
                let original_even = *even;
                *even = original_even.add(scaled_odd);
                *odd = original_even.sub(scaled_odd);
                twiddle = twiddle.mul(step);
            }
        }
        width <<= 1;
    }
    Ok(())
}
/// In-place inverse radix-two FFT.
pub fn goldilocks_ifft_v1(
    values: &mut [GoldilocksFieldV1],
    root: GoldilocksFieldV1,
) -> Result<(), TransparentStarkErrorV1> {
    if root.0 >= GOLDILOCKS_MODULUS_V1 {
        return Err(TransparentStarkErrorV1::InvalidDomain);
    }
    goldilocks_fft_v1(
        values,
        root.inv().ok_or(TransparentStarkErrorV1::DivisionByZero)?,
    )?;
    let inverse_size = GoldilocksFieldV1::reduce(values.len() as u128)
        .inv()
        .ok_or(TransparentStarkErrorV1::DivisionByZero)?;
    for value in values {
        *value = value.mul(inverse_size);
    }
    Ok(())
}
/// Evaluate coefficients over one shifted radix-two domain.
pub fn goldilocks_evaluate_coset_v1(
    coefficients: &[GoldilocksFieldV1],
    size: usize,
    root: GoldilocksFieldV1,
    shift: GoldilocksFieldV1,
) -> Result<Vec<GoldilocksFieldV1>, TransparentStarkErrorV1> {
    if coefficients.len() > size
        || size == 0
        || !size.is_power_of_two()
        || shift == GoldilocksFieldV1::ZERO
        || shift.0 >= GOLDILOCKS_MODULUS_V1
    {
        return Err(TransparentStarkErrorV1::InvalidDomain);
    }
    if coefficients
        .iter()
        .any(|coefficient| coefficient.0 >= GOLDILOCKS_MODULUS_V1)
    {
        return Err(TransparentStarkErrorV1::NonCanonicalField);
    }
    let mut evaluations = vec![GoldilocksFieldV1::ZERO; size];
    let mut shift_power = GoldilocksFieldV1::ONE;
    for (target, coefficient) in evaluations.iter_mut().zip(coefficients.iter().copied()) {
        *target = coefficient.mul(shift_power);
        shift_power = shift_power.mul(shift);
    }
    goldilocks_fft_v1(&mut evaluations, root)?;
    Ok(evaluations)
}
/// In-place radix-two FFT over the quartic Goldilocks extension.
///
/// The evaluation domain remains in the base field, so roots and twiddles are
/// embedded rather than sampled from the extension.
pub fn goldilocks_fp4_fft_v1(
    values: &mut [GoldilocksFp4V1],
    root: GoldilocksFieldV1,
) -> Result<(), TransparentStarkErrorV1> {
    let size = values.len();
    if size == 0
        || !size.is_power_of_two()
        || root.0 >= GOLDILOCKS_MODULUS_V1
        || root.pow(size as u128) != GoldilocksFieldV1::ONE
        || (size > 1 && root.pow((size / 2) as u128) == GoldilocksFieldV1::ONE)
    {
        return Err(TransparentStarkErrorV1::InvalidDomain);
    }
    if values.iter().any(|value| !value.is_canonical()) {
        return Err(TransparentStarkErrorV1::NonCanonicalField);
    }
    let mut reversed = 0_usize;
    for index in 1..size {
        let mut bit = size >> 1;
        while reversed & bit != 0 {
            reversed ^= bit;
            bit >>= 1;
        }
        reversed ^= bit;
        if index < reversed {
            values.swap(index, reversed);
        }
    }
    let mut width = 2_usize;
    while width <= size {
        let step = root.pow((size / width) as u128);
        for chunk in values.chunks_exact_mut(width) {
            let mut twiddle = GoldilocksFieldV1::ONE;
            let (left, right) = chunk.split_at_mut(width / 2);
            for (even, odd) in left.iter_mut().zip(right.iter_mut()) {
                let scaled_odd = (*odd).mul_base(twiddle);
                let original_even = *even;
                *even = original_even.add(scaled_odd);
                *odd = original_even.sub(scaled_odd);
                twiddle = twiddle.mul(step);
            }
        }
        width <<= 1;
    }
    Ok(())
}
/// In-place inverse radix-two FFT over the quartic Goldilocks extension.
pub fn goldilocks_fp4_ifft_v1(
    values: &mut [GoldilocksFp4V1],
    root: GoldilocksFieldV1,
) -> Result<(), TransparentStarkErrorV1> {
    if root.0 >= GOLDILOCKS_MODULUS_V1 {
        return Err(TransparentStarkErrorV1::InvalidDomain);
    }
    goldilocks_fp4_fft_v1(
        values,
        root.inv().ok_or(TransparentStarkErrorV1::DivisionByZero)?,
    )?;
    let inverse_size = GoldilocksFieldV1::reduce(values.len() as u128)
        .inv()
        .ok_or(TransparentStarkErrorV1::DivisionByZero)?;
    for value in values {
        *value = value.mul_base(inverse_size);
    }
    Ok(())
}
/// Evaluate quartic-extension coefficients over one shifted base-field domain.
pub fn goldilocks_fp4_evaluate_coset_v1(
    coefficients: &[GoldilocksFp4V1],
    size: usize,
    root: GoldilocksFieldV1,
    shift: GoldilocksFieldV1,
) -> Result<Vec<GoldilocksFp4V1>, TransparentStarkErrorV1> {
    if coefficients.len() > size
        || size == 0
        || !size.is_power_of_two()
        || shift == GoldilocksFieldV1::ZERO
        || shift.0 >= GOLDILOCKS_MODULUS_V1
    {
        return Err(TransparentStarkErrorV1::InvalidDomain);
    }
    if coefficients.iter().any(|value| !value.is_canonical()) {
        return Err(TransparentStarkErrorV1::NonCanonicalField);
    }
    let mut evaluations = vec![GoldilocksFp4V1::ZERO; size];
    let mut shift_power = GoldilocksFieldV1::ONE;
    for (target, coefficient) in evaluations.iter_mut().zip(coefficients.iter().copied()) {
        *target = coefficient.mul_base(shift_power);
        shift_power = shift_power.mul(shift);
    }
    goldilocks_fp4_fft_v1(&mut evaluations, root)?;
    Ok(evaluations)
}
/// Batch-invert a non-empty collection using one field inversion.
pub fn goldilocks_batch_invert_v1(
    values: &mut [GoldilocksFieldV1],
) -> Result<(), TransparentStarkErrorV1> {
    if values.is_empty() {
        return Err(TransparentStarkErrorV1::InvalidDomain);
    }
    if values.iter().any(|value| value.0 >= GOLDILOCKS_MODULUS_V1) {
        return Err(TransparentStarkErrorV1::NonCanonicalField);
    }
    let mut prefixes = Vec::new();
    prefixes
        .try_reserve_exact(values.len())
        .map_err(|_| TransparentStarkErrorV1::AllocationFailure)?;
    let mut product = GoldilocksFieldV1::ONE;
    for value in values.iter().copied() {
        if value == GoldilocksFieldV1::ZERO {
            return Err(TransparentStarkErrorV1::DivisionByZero);
        }
        prefixes.push(product);
        product = product.mul(value);
    }
    let mut inverse = product
        .inv()
        .ok_or(TransparentStarkErrorV1::DivisionByZero)?;
    for index in (0..values.len()).rev() {
        let value = values[index];
        values[index] = inverse.mul(prefixes[index]);
        inverse = inverse.mul(value);
    }
    Ok(())
}
/// Draw one unbiased canonical Goldilocks field element.
pub fn random_goldilocks_v1<R: TryRngCore>(
    rng: &mut R,
) -> Result<GoldilocksFieldV1, TransparentStarkErrorV1> {
    for _ in 0..MAX_FIELD_REJECTION_ATTEMPTS_V1 {
        let mut bytes = [0_u8; 8];
        rng.try_fill_bytes(&mut bytes)
            .map_err(|_| TransparentStarkErrorV1::RandomnessUnavailable)?;
        if let Some(value) = GoldilocksFieldV1::canonical(u64::from_le_bytes(bytes)) {
            return Ok(value);
        }
    }
    Err(TransparentStarkErrorV1::RandomnessUnavailable)
}
/// Draw one uniform quartic-extension element, including zero.
pub fn random_goldilocks_fp4_v1<R: TryRngCore>(
    rng: &mut R,
) -> Result<GoldilocksFp4V1, TransparentStarkErrorV1> {
    GoldilocksFp4V1::from_coefficients([
        random_goldilocks_v1(rng)?,
        random_goldilocks_v1(rng)?,
        random_goldilocks_v1(rng)?,
        random_goldilocks_v1(rng)?,
    ])
    .ok_or(TransparentStarkErrorV1::NonCanonicalField)
}
/// Interpolate one native trace column and apply an exact replayable mask.
///
/// For a native domain of size `n`, the returned polynomial is `T(X) + r(X) * (X^n - 1)`. Its
/// ascending coefficient vector has exactly `n + r.len()` entries, including canonical trailing
/// zero coefficients. Keeping this operation separate from coset evaluation lets bounded provers
/// retain the much smaller polynomial while replaying commitments on more than one verifier-derived
/// evaluation domain.
pub fn masked_trace_coefficients_with_mask_v1(
    base_column: &[GoldilocksFieldV1],
    base_log_size: u8,
    mask: &[GoldilocksFieldV1],
) -> Result<Vec<GoldilocksFieldV1>, TransparentStarkErrorV1> {
    if mask.is_empty() {
        return Err(TransparentStarkErrorV1::InvalidDomain);
    }
    if mask
        .iter()
        .any(|coefficient| coefficient.0 >= GOLDILOCKS_MODULUS_V1)
    {
        return Err(TransparentStarkErrorV1::NonCanonicalField);
    }
    let base_size = 1_usize
        .checked_shl(u32::from(base_log_size))
        .ok_or(TransparentStarkErrorV1::InvalidDomain)?;
    let coefficient_count = base_size
        .checked_add(mask.len())
        .ok_or(TransparentStarkErrorV1::InvalidDomain)?;
    if base_column.len() != base_size {
        return Err(TransparentStarkErrorV1::InvalidDomain);
    }
    let base_root = goldilocks_primitive_root_v1(base_log_size)?;
    let mut coefficients = ZeroizingGoldilocksValuesV1(Vec::new());
    coefficients
        .try_reserve_exact(coefficient_count)
        .map_err(|_| TransparentStarkErrorV1::AllocationFailure)?;
    coefficients.extend_from_slice(base_column);
    goldilocks_ifft_v1(&mut coefficients, base_root)?;
    coefficients.resize(coefficient_count, GoldilocksFieldV1::ZERO);
    for (degree, random) in mask.iter().copied().enumerate() {
        coefficients[degree] = coefficients[degree].sub(random);
        coefficients[base_size + degree] = coefficients[base_size + degree].add(random);
    }
    Ok(coefficients.into_inner())
}
/// Evaluate retained masked trace coefficients on one canonical generator coset.
///
/// The evaluation domain may be smaller than the eventual commitment domain,
/// but it must contain every coefficient and remain disjoint from both the
/// native trace subgroup and its own evaluation subgroup.
pub fn masked_trace_coefficients_on_coset_v1(
    coefficients: &[GoldilocksFieldV1],
    base_log_size: u8,
    evaluation_log_size: u8,
) -> Result<Vec<GoldilocksFieldV1>, TransparentStarkErrorV1> {
    let base_size = 1_usize
        .checked_shl(u32::from(base_log_size))
        .ok_or(TransparentStarkErrorV1::InvalidDomain)?;
    let evaluation_size = 1_usize
        .checked_shl(u32::from(evaluation_log_size))
        .ok_or(TransparentStarkErrorV1::InvalidDomain)?;
    if coefficients.is_empty()
        || coefficients.len() > evaluation_size
        || evaluation_size <= base_size
    {
        return Err(TransparentStarkErrorV1::InvalidDomain);
    }
    let evaluation_root = goldilocks_primitive_root_v1(evaluation_log_size)?;
    let shift = GoldilocksFieldV1(GOLDILOCKS_GENERATOR_V1);
    if shift.pow(base_size as u128) == GoldilocksFieldV1::ONE
        || shift.pow(evaluation_size as u128) == GoldilocksFieldV1::ONE
    {
        return Err(TransparentStarkErrorV1::InvalidDomain);
    }
    goldilocks_evaluate_coset_v1(coefficients, evaluation_size, evaluation_root, shift)
}
/// Interpolate and mask one trace column before evaluating its LDE.
///
/// The mask is `r(X) * (X^n - 1)`, so every base-domain trace value is unchanged while all queried
/// coset values are randomized. `mask_degree` is inclusive.
pub fn masked_trace_lde_column_with_mask_v1(
    base_column: &[GoldilocksFieldV1],
    base_log_size: u8,
    lde_log_size: u8,
    mask: &[GoldilocksFieldV1],
) -> Result<Vec<GoldilocksFieldV1>, TransparentStarkErrorV1> {
    let coefficients = ZeroizingGoldilocksValuesV1(masked_trace_coefficients_with_mask_v1(
        base_column,
        base_log_size,
        mask,
    )?);
    // These coefficients interpolate the native witness. The guard wipes them on success,
    // ordinary failure, and unwind before a Rayon worker can return allocator storage to a
    // long-lived pool.
    masked_trace_coefficients_on_coset_v1(&coefficients, base_log_size, lde_log_size)
}
struct ZeroizingGoldilocksValuesV1(Vec<GoldilocksFieldV1>);
impl ZeroizingGoldilocksValuesV1 {
    fn into_inner(mut self) -> Vec<GoldilocksFieldV1> {
        core::mem::take(&mut self.0)
    }
}
impl core::ops::Deref for ZeroizingGoldilocksValuesV1 {
    type Target = Vec<GoldilocksFieldV1>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl core::ops::DerefMut for ZeroizingGoldilocksValuesV1 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for ZeroizingGoldilocksValuesV1 {
    fn drop(&mut self) {
        for coefficient in &mut self.0 {
            coefficient.zeroize_v1();
        }
    }
}
/// Replayable zero-knowledge mask for one streamed trace column.
pub struct ReplayableTraceMaskV1 {
    coefficients: Vec<GoldilocksFieldV1>,
}
impl ReplayableTraceMaskV1 {
    /// Exact coefficients in ascending degree order.
    pub(crate) fn coefficients(&self) -> &[GoldilocksFieldV1] {
        &self.coefficients
    }
}
impl Drop for ReplayableTraceMaskV1 {
    fn drop(&mut self) {
        for coefficient in &mut self.coefficients {
            coefficient.zeroize_v1();
        }
    }
}
/// Sample and retain the exact mask coefficients for one replayable column.
///
/// Streaming provers keep these few coefficients until post-query openings are reconstructed,
/// instead of retaining the entire LDE column. Callers should drop them as soon as proof
/// construction completes; [`Drop`] overwrites the backing allocation before release.
pub fn sample_trace_mask_v1<R: TryRngCore>(
    mask_degree: usize,
    rng: &mut R,
) -> Result<ReplayableTraceMaskV1, TransparentStarkErrorV1> {
    let mask_len = mask_degree
        .checked_add(1)
        .ok_or(TransparentStarkErrorV1::InvalidDomain)?;
    let mut mask = Vec::new();
    mask.try_reserve_exact(mask_len)
        .map_err(|_| TransparentStarkErrorV1::AllocationFailure)?;
    for _ in 0..mask_len {
        mask.push(random_goldilocks_v1(rng)?);
    }
    Ok(ReplayableTraceMaskV1 { coefficients: mask })
}
/// Hash one fully typed native-STARK frame with the canonical six-lane Goldilocks Poseidon-x7 digest.
pub fn goldilocks_digest384_frame_v1(
    context: TransparentStarkDigestContextV1,
    role: &[u8],
    phase: &[u8],
    level: u64,
    index: u64,
    counter: u64,
    fields: &[&[u8]],
) -> Result<GoldilocksDigest384V1, TransparentStarkErrorV1> {
    context.validate()?;
    if role.is_empty()
        || phase.is_empty()
        || u16::try_from(role.len()).is_err()
        || u16::try_from(phase.len()).is_err()
    {
        return Err(TransparentStarkErrorV1::InvalidDigestDomain);
    }
    let catalog = context.catalog_v1();
    hash_bytes_384_v1(
        GoldilocksDigestDomainV1 {
            catalog: &catalog,
            protocol: context.protocol_label_v1(),
            profile: context.profile,
            role,
            phase,
            level,
            index,
            counter,
        },
        fields,
    )
    .ok_or(TransparentStarkErrorV1::FrameLengthOverflow)
}

/// Start a bounded digest stream whose final framed field is supplied incrementally.
#[cfg(test)]
pub fn goldilocks_digest384_last_field_stream_v1(
    context: TransparentStarkDigestContextV1,
    role: &[u8],
    phase: &[u8],
    level: u64,
    index: u64,
    counter: u64,
    prefix_fields: &[&[u8]],
    final_field_len: usize,
) -> Result<GoldilocksDigest384LastFieldStreamV1, TransparentStarkErrorV1> {
    context.validate()?;
    if role.is_empty()
        || phase.is_empty()
        || u16::try_from(role.len()).is_err()
        || u16::try_from(phase.len()).is_err()
    {
        return Err(TransparentStarkErrorV1::InvalidDigestDomain);
    }
    let catalog = context.catalog_v1();
    GoldilocksDigest384LastFieldStreamV1::new(
        GoldilocksDigestDomainV1 {
            catalog: &catalog,
            protocol: context.protocol_label_v1(),
            profile: context.profile,
            role,
            phase,
            level,
            index,
            counter,
        },
        prefix_fields,
        final_field_len,
    )
    .map_err(|_| TransparentStarkErrorV1::FrameLengthOverflow)
}

/// Map a canonical digest-stream failure without exposing an alternate hash path.
#[cfg(test)]
pub const fn map_digest_stream_error_v1(
    error: GoldilocksDigest384LastFieldStreamErrorV1,
) -> TransparentStarkErrorV1 {
    match error {
        GoldilocksDigest384LastFieldStreamErrorV1::FramingLimitExceeded
        | GoldilocksDigest384LastFieldStreamErrorV1::InputOverrun { .. }
        | GoldilocksDigest384LastFieldStreamErrorV1::InputUnderrun { .. } => {
            TransparentStarkErrorV1::FrameLengthOverflow
        }
    }
}

/// Domain-separated binary six-lane Goldilocks Poseidon-x7 Merkle tree.
#[derive(Clone, Debug)]
pub struct GoldilocksMerkleTreeV1 {
    levels: Vec<Vec<GoldilocksDigest384V1>>,
}
impl GoldilocksMerkleTreeV1 {
    /// Commit a non-empty power-of-two leaf vector.
    pub(crate) fn from_leaves(
        leaves: Vec<GoldilocksDigest384V1>,
        context: TransparentStarkDigestContextV1,
        node_role: &'static [u8],
    ) -> Result<Self, TransparentStarkErrorV1> {
        context.validate()?;
        if leaves.is_empty()
            || !leaves.len().is_power_of_two()
            || node_role.is_empty()
            || u16::try_from(node_role.len()).is_err()
        {
            return Err(TransparentStarkErrorV1::InvalidMerkleShape);
        }
        let mut levels = Vec::new();
        levels
            .try_reserve_exact(
                usize::try_from(leaves.len().ilog2())
                    .ok()
                    .and_then(|depth| depth.checked_add(1))
                    .ok_or(TransparentStarkErrorV1::InvalidMerkleShape)?,
            )
            .map_err(|_| TransparentStarkErrorV1::AllocationFailure)?;
        levels.push(leaves);
        while levels.last().map_or(0, Vec::len) > 1 {
            let parent_level = u64::try_from(levels.len())
                .map_err(|_| TransparentStarkErrorV1::InvalidMerkleShape)?;
            let previous = levels
                .last()
                .ok_or(TransparentStarkErrorV1::InvalidMerkleShape)?;
            let parent_count = previous.len() / 2;
            let mut next = Vec::new();
            next.try_reserve_exact(parent_count)
                .map_err(|_| TransparentStarkErrorV1::AllocationFailure)?;
            next.resize(parent_count, GoldilocksDigest384V1::default());
            // Every node is domain-separated by its canonical level and index. An indexed
            // parallel write therefore changes only scheduling: the resulting vector and root
            // are byte-identical for every Rayon pool width and hardware topology.
            let hash_parent =
                |index: usize| -> Result<GoldilocksDigest384V1, TransparentStarkErrorV1> {
                    let child_index = index
                        .checked_mul(2)
                        .ok_or(TransparentStarkErrorV1::InvalidMerkleShape)?;
                    goldilocks_merkle_node_v1(
                        context,
                        node_role,
                        parent_level,
                        u64::try_from(index)
                            .map_err(|_| TransparentStarkErrorV1::InvalidMerkleShape)?,
                        previous[child_index],
                        previous[child_index + 1],
                    )
                };
            if parent_count >= MERKLE_PARALLEL_PARENT_THRESHOLD_V1 {
                next.par_iter_mut().enumerate().try_for_each(
                    |(index, parent)| -> Result<(), TransparentStarkErrorV1> {
                        *parent = hash_parent(index)?;
                        Ok(())
                    },
                )?;
            } else {
                for (index, parent) in next.iter_mut().enumerate() {
                    *parent = hash_parent(index)?;
                }
            }
            levels.push(next);
        }
        Ok(Self { levels })
    }
    /// Root digest.
    pub(crate) fn root(&self) -> GoldilocksDigest384V1 {
        self.levels[self.levels.len() - 1][0]
    }
    /// Leaf-to-root sibling path.
    pub(crate) fn path(
        &self,
        mut index: usize,
    ) -> Result<Vec<GoldilocksDigest384V1>, TransparentStarkErrorV1> {
        if index >= self.levels[0].len() {
            return Err(TransparentStarkErrorV1::InvalidMerkleShape);
        }
        let mut path = Vec::new();
        path.try_reserve_exact(self.levels.len() - 1)
            .map_err(|_| TransparentStarkErrorV1::AllocationFailure)?;
        for level in &self.levels[..self.levels.len() - 1] {
            path.push(level[index ^ 1]);
            index >>= 1;
        }
        Ok(path)
    }
}
/// Hash one binary Merkle node with an engine-fixed role domain.
pub fn goldilocks_merkle_node_v1(
    context: TransparentStarkDigestContextV1,
    node_role: &[u8],
    level: u64,
    index: u64,
    left: GoldilocksDigest384V1,
    right: GoldilocksDigest384V1,
) -> Result<GoldilocksDigest384V1, TransparentStarkErrorV1> {
    goldilocks_digest384_frame_v1(
        context,
        node_role,
        MERKLE_NODE_PHASE_V1,
        level,
        index,
        0,
        &[&left.to_le_bytes(), &right.to_le_bytes()],
    )
}
/// Stateful framed Fiat–Shamir transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransparentTranscriptV1 {
    context: TransparentStarkDigestContextV1,
    state: GoldilocksDigest384V1,
    challenge_counter: u64,
}
impl TransparentTranscriptV1 {
    /// Initialize with the engine suite, complete profile digest, and exact public-input digest.
    pub(crate) fn new(
        context: TransparentStarkDigestContextV1,
        engine_suite: &[u8],
        profile_digest: &GoldilocksDigest384V1,
        public_input_digest: &GoldilocksDigest384V1,
    ) -> Result<Self, TransparentStarkErrorV1> {
        if engine_suite.is_empty() {
            return Err(TransparentStarkErrorV1::FrameLengthOverflow);
        }
        let profile_digest = profile_digest.to_le_bytes();
        let public_input_digest = public_input_digest.to_le_bytes();
        Ok(Self {
            context,
            state: goldilocks_digest384_frame_v1(
                context,
                TRANSCRIPT_INIT_DOMAIN_V1,
                b"initialize",
                0,
                0,
                0,
                &[engine_suite, &profile_digest, &public_input_digest],
            )?,
            challenge_counter: 0,
        })
    }
    /// Absorb one labeled message and reset the local challenge counter.
    pub(crate) fn absorb(
        &mut self,
        label: &[u8],
        fields: &[&[u8]],
    ) -> Result<(), TransparentStarkErrorV1> {
        if label.is_empty() {
            return Err(TransparentStarkErrorV1::InvalidDigestDomain);
        }
        let message = goldilocks_digest384_frame_v1(
            self.context,
            b"transcript-message",
            label,
            0,
            0,
            self.challenge_counter,
            fields,
        )?;
        self.state = goldilocks_digest384_frame_v1(
            self.context,
            TRANSCRIPT_ABSORB_DOMAIN_V1,
            label,
            0,
            0,
            self.challenge_counter,
            &[&self.state.to_le_bytes(), &message.to_le_bytes()],
        )?;
        self.challenge_counter = 0;
        Ok(())
    }
    /// Current transcript state for query/grinding derivation.
    pub(crate) const fn state(&self) -> GoldilocksDigest384V1 {
        self.state
    }
    /// Exact catalog/protocol/profile context bound to this transcript.
    pub(crate) const fn context(&self) -> TransparentStarkDigestContextV1 {
        self.context
    }
    /// Derive one unbiased nonzero Goldilocks challenge.
    pub(crate) fn challenge_field(
        &mut self,
        label: &[u8],
    ) -> Result<GoldilocksFieldV1, TransparentStarkErrorV1> {
        for attempt in 0..MAX_FIELD_REJECTION_ATTEMPTS_V1 {
            let digest = goldilocks_digest384_frame_v1(
                self.context,
                TRANSCRIPT_CHALLENGE_DOMAIN_V1,
                label,
                0,
                attempt,
                self.challenge_counter,
                &[&self.state.to_le_bytes()],
            )?;
            let candidate = digest.words()[0];
            if let Some(field) = GoldilocksFieldV1::canonical(candidate)
                && field != GoldilocksFieldV1::ZERO
            {
                let accepted_counter = self.challenge_counter;
                self.challenge_counter = self
                    .challenge_counter
                    .checked_add(1)
                    .ok_or(TransparentStarkErrorV1::ChallengeSamplingExhausted)?;
                self.state = goldilocks_digest384_frame_v1(
                    self.context,
                    TRANSCRIPT_ABSORB_DOMAIN_V1,
                    label,
                    0,
                    0,
                    accepted_counter,
                    &[&self.state.to_le_bytes(), &digest.to_le_bytes()],
                )?;
                return Ok(field);
            }
        }
        Err(TransparentStarkErrorV1::ChallengeSamplingExhausted)
    }
    /// Derive one uniform challenge in the quartic Goldilocks extension.
    ///
    /// Four independent canonical digest lanes supply the fixed-order coefficients. FRI and
    /// polynomial identity theorems sample the whole challenge field, including zero; callers that
    /// need an invertible or out-of-domain value state that as a predicate via
    /// [`Self::challenge_fp4_where`].
    pub(crate) fn challenge_fp4(
        &mut self,
        label: &[u8],
    ) -> Result<GoldilocksFp4V1, TransparentStarkErrorV1> {
        self.challenge_fp4_where(label, |_| true)
    }
    /// Derive a uniform quartic challenge satisfying an additional deterministic public predicate.
    ///
    /// DEEP protocols use this to exclude their base and evaluation domains
    /// without absorbing a rejected candidate or introducing modulo bias.
    pub(crate) fn challenge_fp4_where(
        &mut self,
        label: &[u8],
        predicate: impl FnMut(GoldilocksFp4V1) -> bool,
    ) -> Result<GoldilocksFp4V1, TransparentStarkErrorV1> {
        let context = self.context;
        self.challenge_fp4_with_oracle_and_predicate(
            label,
            |state, label, counter, attempt| {
                goldilocks_digest384_frame_v1(
                    context,
                    TRANSCRIPT_FP4_CHALLENGE_DOMAIN_V1,
                    label,
                    0,
                    attempt,
                    counter,
                    &[&state.to_le_bytes()],
                )
            },
            predicate,
        )
    }
    fn challenge_fp4_with_oracle_and_predicate(
        &mut self,
        label: &[u8],
        mut oracle: impl FnMut(
            GoldilocksDigest384V1,
            &[u8],
            u64,
            u64,
        ) -> Result<GoldilocksDigest384V1, TransparentStarkErrorV1>,
        mut predicate: impl FnMut(GoldilocksFp4V1) -> bool,
    ) -> Result<GoldilocksFp4V1, TransparentStarkErrorV1> {
        for attempt in 0..MAX_FIELD_REJECTION_ATTEMPTS_V1 {
            let digest = oracle(self.state, label, self.challenge_counter, attempt)?;
            let words = digest.words();
            let field = GoldilocksFp4V1::canonical([words[0], words[1], words[2], words[3]])
                .expect("digest lanes are canonical Goldilocks elements");
            if predicate(field) {
                let accepted_counter = self.challenge_counter;
                self.challenge_counter = self
                    .challenge_counter
                    .checked_add(1)
                    .ok_or(TransparentStarkErrorV1::ChallengeSamplingExhausted)?;
                self.state = goldilocks_digest384_frame_v1(
                    self.context,
                    TRANSCRIPT_ABSORB_DOMAIN_V1,
                    label,
                    0,
                    0,
                    accepted_counter,
                    &[&self.state.to_le_bytes(), &digest.to_le_bytes()],
                )?;
                return Ok(field);
            }
        }
        Err(TransparentStarkErrorV1::ChallengeSamplingExhausted)
    }
}
/// Derive unique unbiased query indices for a power-of-two domain.
pub fn derive_unique_query_indices_v1(
    context: TransparentStarkDigestContextV1,
    seed: &GoldilocksDigest384V1,
    domain_size: usize,
    query_count: usize,
) -> Result<Vec<usize>, TransparentStarkErrorV1> {
    context.validate()?;
    if domain_size == 0
        || !domain_size.is_power_of_two()
        || query_count == 0
        || query_count > domain_size
    {
        return Err(TransparentStarkErrorV1::InvalidDomain);
    }
    let mut indices = Vec::new();
    indices
        .try_reserve_exact(query_count)
        .map_err(|_| TransparentStarkErrorV1::AllocationFailure)?;
    // A sparse swap table implements the first `query_count` steps of a Fisher--Yates shuffle
    // without allocating the complete domain. This gives every ordered set of distinct indices
    // the same probability and cannot exhibit coupon-collector exhaustion for dense queries.
    let mut swaps = BTreeMap::new();
    let mut counter = 0_u64;
    for query_number in 0..query_count {
        let remaining = domain_size
            .checked_sub(query_number)
            .ok_or(TransparentStarkErrorV1::InvalidDomain)?;
        let offset =
            derive_bounded_query_offset_v1(context, seed, query_number, &mut counter, remaining)?;
        let draw = query_number
            .checked_add(offset)
            .ok_or(TransparentStarkErrorV1::InvalidDomain)?;
        let selected = swaps.get(&draw).copied().unwrap_or(draw);
        let replacement = swaps.get(&query_number).copied().unwrap_or(query_number);
        swaps.insert(draw, replacement);
        indices.push(selected);
    }
    Ok(indices)
}
fn derive_bounded_query_offset_v1(
    context: TransparentStarkDigestContextV1,
    seed: &GoldilocksDigest384V1,
    query_number: usize,
    counter: &mut u64,
    bound: usize,
) -> Result<usize, TransparentStarkErrorV1> {
    if bound == 0 {
        return Err(TransparentStarkErrorV1::InvalidDomain);
    }
    let bound = bound as u128;
    let source_space = u128::from(GOLDILOCKS_MODULUS_V1);
    let acceptance_limit = source_space - source_space % bound;
    for _ in 0..MAX_QUERY_INDEX_REJECTION_ATTEMPTS_V1 {
        let digest = goldilocks_digest384_frame_v1(
            context,
            QUERY_INDEX_DOMAIN_V1,
            b"fisher-yates-offset",
            0,
            u64::try_from(query_number).map_err(|_| TransparentStarkErrorV1::InvalidDomain)?,
            *counter,
            &[
                &seed.to_le_bytes(),
                &u64::try_from(bound)
                    .map_err(|_| TransparentStarkErrorV1::InvalidDomain)?
                    .to_le_bytes(),
            ],
        )?;
        *counter = counter
            .checked_add(1)
            .ok_or(TransparentStarkErrorV1::QuerySamplingExhausted)?;
        let raw = u128::from(digest.words()[0]);
        if raw < acceptance_limit {
            return usize::try_from(raw % bound)
                .map_err(|_| TransparentStarkErrorV1::InvalidDomain);
        }
    }
    Err(TransparentStarkErrorV1::QuerySamplingExhausted)
}
/// Compute one binary FRI fold over the quartic Goldilocks extension.
pub fn fri_fold_pair_fp4_v1(
    low: GoldilocksFp4V1,
    high: GoldilocksFp4V1,
    beta: GoldilocksFp4V1,
    x: GoldilocksFieldV1,
) -> Result<GoldilocksFp4V1, TransparentStarkErrorV1> {
    if x.0 >= GOLDILOCKS_MODULUS_V1 {
        return Err(TransparentStarkErrorV1::NonCanonicalField);
    }
    let inverse_x = x.inv().ok_or(TransparentStarkErrorV1::DivisionByZero)?;
    fri_fold_pair_with_inverse_x_fp4_v1(low, high, beta, inverse_x)
}
/// Compute one quartic-extension FRI fold with a tracked base-domain `x^-1`.
pub fn fri_fold_pair_with_inverse_x_fp4_v1(
    low: GoldilocksFp4V1,
    high: GoldilocksFp4V1,
    beta: GoldilocksFp4V1,
    inverse_x: GoldilocksFieldV1,
) -> Result<GoldilocksFp4V1, TransparentStarkErrorV1> {
    if !low.is_canonical()
        || !high.is_canonical()
        || !beta.is_canonical()
        || inverse_x.0 >= GOLDILOCKS_MODULUS_V1
    {
        return Err(TransparentStarkErrorV1::NonCanonicalField);
    }
    if inverse_x == GoldilocksFieldV1::ZERO {
        return Err(TransparentStarkErrorV1::DivisionByZero);
    }
    let inverse_two = GoldilocksFieldV1(2)
        .inv()
        .ok_or(TransparentStarkErrorV1::DivisionByZero)?;
    let even = low.add(high).mul_base(inverse_two);
    let odd = low.sub(high).mul_base(inverse_two).mul_base(inverse_x);
    Ok(even.add(beta.mul(odd)))
}
/// Check an entire quartic-extension FRI terminal against an exact degree.
pub fn ensure_fri_terminal_degree_fp4_v1(
    values: &[GoldilocksFp4V1],
    log_size: u8,
    degree_bound: usize,
) -> Result<(), TransparentStarkErrorV1> {
    let expected = 1_usize
        .checked_shl(u32::from(log_size))
        .ok_or(TransparentStarkErrorV1::InvalidDomain)?;
    if values.len() != expected || degree_bound >= expected {
        return Err(TransparentStarkErrorV1::InvalidDomain);
    }
    if values.iter().any(|value| !value.is_canonical()) {
        return Err(TransparentStarkErrorV1::NonCanonicalField);
    }
    let root = goldilocks_primitive_root_v1(log_size)?;
    let mut coefficients = values.to_vec();
    goldilocks_fp4_ifft_v1(&mut coefficients, root)?;
    if coefficients[degree_bound + 1..]
        .iter()
        .any(|coefficient| *coefficient != GoldilocksFp4V1::ZERO)
    {
        return Err(TransparentStarkErrorV1::FriDegree);
    }
    Ok(())
}
/// Search for the smallest nonce meeting an exact leading-zero-bit target.
pub fn grind_nonce_v1(
    context: TransparentStarkDigestContextV1,
    transcript_seed: &GoldilocksDigest384V1,
    grinding_bits: u8,
) -> Result<u64, TransparentStarkErrorV1> {
    if grinding_bits > 63 {
        return Err(TransparentStarkErrorV1::InvalidGrinding);
    }
    if grinding_bits < GRINDING_PARALLEL_MIN_BITS_V1 {
        return grind_nonce_serial_v1(context, transcript_seed, grinding_bits);
    }
    first_nonce_in_ordered_parallel_chunks_v1(|nonce| {
        verify_grinding_nonce_v1(context, transcript_seed, grinding_bits, nonce).is_ok()
    })
    .ok_or(TransparentStarkErrorV1::InvalidGrinding)
}
fn first_nonce_in_ordered_parallel_chunks_v1<Accept>(accept: Accept) -> Option<u64>
where
    Accept: Fn(u64) -> bool + Sync,
{
    let mut chunk_start = 0_u64;
    loop {
        let chunk_end = chunk_start.saturating_add(GRINDING_PARALLEL_CHUNK_SIZE_V1 - 1);
        if let Some(nonce) = (chunk_start..=chunk_end)
            .into_par_iter()
            .filter(|nonce| accept(*nonce))
            .min()
        {
            return Some(nonce);
        }
        if chunk_end == u64::MAX {
            return None;
        }
        chunk_start = chunk_end + 1;
    }
}
fn grind_nonce_serial_v1(
    context: TransparentStarkDigestContextV1,
    transcript_seed: &GoldilocksDigest384V1,
    grinding_bits: u8,
) -> Result<u64, TransparentStarkErrorV1> {
    for nonce in 0..=u64::MAX {
        if verify_grinding_nonce_v1(context, transcript_seed, grinding_bits, nonce).is_ok() {
            return Ok(nonce);
        }
    }
    Err(TransparentStarkErrorV1::InvalidGrinding)
}
/// Verify a transcript grinding nonce.
pub fn verify_grinding_nonce_v1(
    context: TransparentStarkDigestContextV1,
    transcript_seed: &GoldilocksDigest384V1,
    grinding_bits: u8,
    nonce: u64,
) -> Result<(), TransparentStarkErrorV1> {
    if grinding_bits > 63 {
        return Err(TransparentStarkErrorV1::InvalidGrinding);
    }
    let digest = goldilocks_digest384_frame_v1(
        context,
        GRINDING_DOMAIN_V1,
        b"proof-of-work-nonce",
        0,
        nonce,
        0,
        &[&transcript_seed.to_le_bytes()],
    )?;
    if leading_zero_bits_v1(&digest.to_le_bytes()) < u32::from(grinding_bits) {
        return Err(TransparentStarkErrorV1::InvalidGrinding);
    }
    Ok(())
}
fn leading_zero_bits_v1(bytes: &[u8]) -> u32 {
    let mut count = 0_u32;
    for byte in bytes {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}
/// Strict fixed-shape proof reader.
pub struct ExactProofReaderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> ExactProofReaderV1<'a> {
    /// Construct over one size-capped proof slice.
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    /// Read an exact byte array.
    pub(crate) fn take<const N: usize>(&mut self) -> Result<[u8; N], TransparentStarkErrorV1> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(TransparentStarkErrorV1::MalformedProof)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(TransparentStarkErrorV1::MalformedProof)?;
        self.offset = end;
        bytes
            .try_into()
            .map_err(|_| TransparentStarkErrorV1::MalformedProof)
    }
    /// Read big-endian `u16`.
    pub(crate) fn u16(&mut self) -> Result<u16, TransparentStarkErrorV1> {
        self.take().map(u16::from_be_bytes)
    }
    /// Read big-endian `u32`.
    pub(crate) fn u32(&mut self) -> Result<u32, TransparentStarkErrorV1> {
        self.take().map(u32::from_be_bytes)
    }
    /// Read big-endian `u64`.
    pub(crate) fn u64(&mut self) -> Result<u64, TransparentStarkErrorV1> {
        self.take().map(u64::from_be_bytes)
    }
    /// Read one canonical Goldilocks value.
    pub(crate) fn field(&mut self) -> Result<GoldilocksFieldV1, TransparentStarkErrorV1> {
        GoldilocksFieldV1::canonical(self.u64()?).ok_or(TransparentStarkErrorV1::NonCanonicalField)
    }
    /// Read one canonically encoded quartic-extension value.
    pub(crate) fn fp4(&mut self) -> Result<GoldilocksFp4V1, TransparentStarkErrorV1> {
        GoldilocksFp4V1::from_coefficients([
            self.field()?,
            self.field()?,
            self.field()?,
            self.field()?,
        ])
        .ok_or(TransparentStarkErrorV1::NonCanonicalField)
    }
    /// Require exact end-of-input.
    pub(crate) fn finish(self) -> Result<(), TransparentStarkErrorV1> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(TransparentStarkErrorV1::MalformedProof)
        }
    }
}
/// Append big-endian fixed integers to a canonical proof.
pub fn append_u16_v1(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_be_bytes());
}
/// Append big-endian fixed integers to a canonical proof.
pub fn append_u32_v1(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}
/// Append big-endian fixed integers to a canonical proof.
pub fn append_u64_v1(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
#[path = "transparent_stark_digest_tests.rs"]
mod digest_tests;
