//! Infinity-norm recurrence and retained collective-ingress certificate.
//!
//! `noise_feasibility` binds this recurrence to distinct actual/prospective
//! evaluated-key constructions. This retained certificate alone does not account
//! for the actual evaluated-key CKS residual or establish release readiness.
//!
//! A bound of `b` means that every centered coefficient has absolute value
//! strictly smaller than `2^b`.  The rules below intentionally use only
//! triangle inequality and the exact `N`-term negacyclic convolution bound;
//! no heuristic Gaussian cancellation is credited to correctness.
use super::{ZkAmsMkheErrorV1, phase23_max_composed_rotation_key_switch_count};
/// Exact symbolic certificate for the Phase-II/III ciphertext path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsMkheNoiseCertificateV1 {
    /// Cyclotomic degree used by every convolution rule.
    pub ring_degree: u32,
    /// Number of parties in the fixed governed roster.
    pub party_count: u8,
    /// Number of streamed RNS/hybrid limbs.
    pub hybrid_limb_count: u8,
    /// Conservative upper bound on nonzero terms in any sparse map row.
    pub sparse_map_fan_in: u32,
    /// Exact minimum coefficient sampled by every CBD-eta RLWE/key error.
    pub sampled_rlwe_error_min: i16,
    /// Exact maximum coefficient sampled by every CBD-eta RLWE/key error.
    pub sampled_rlwe_error_max: i16,
    /// Maximum absolute sampled RLWE/key error coefficient.
    pub sampled_rlwe_error_max_abs: u8,
    /// `b` such that every sampled RLWE/key error has absolute value `< 2^b`.
    pub sampled_rlwe_error_bound_bits: u8,
    /// Minimum natural-lift proof witness `e0' = e0 - h`, where upper-half
    /// correction `h` is exactly zero or one.
    pub natural_lift_effective_error_min: i16,
    /// Maximum canonical-natural-lift proof witness `e0'`.
    pub natural_lift_effective_error_max: i16,
    /// Symmetric verifier maximum absolute value admitted for `e0'`.
    pub natural_lift_effective_error_verifier_max_abs: u8,
    /// `b` such that every verifier-admitted `e0'` is `< 2^b` in magnitude.
    pub natural_lift_effective_error_bound_bits: u8,
    /// Minimum canonical-natural-to-centered upper-half correction.
    pub natural_lift_upper_half_correction_min: u8,
    /// Maximum canonical-natural-to-centered upper-half correction.
    pub natural_lift_upper_half_correction_max: u8,
    /// Residual bound of a fresh proof-admitted independently keyed encryption.
    pub independent_fresh_residual_bits: u16,
    /// Per-party statistically hiding CKS-smudge quotient bound.
    pub cks_smudge_quotient_bits: u16,
    /// Residual after proof-bound collective ingress and CKS smudging.
    pub collective_ingress_residual_bits: u16,
    /// Residual in one collective `s^2` relinearization-key equation.
    pub collective_rkg_residual_bits: u16,
    /// Residual introduced by one streamed hybrid key switch.
    pub hybrid_key_switch_residual_bits: u16,
    /// Maximum number of constituent key switches in one canonical signed- binary packed rotation.
    pub max_composed_rotation_key_switch_count: u8,
    /// Residual after the longest canonical signed-binary packed rotation.
    pub composed_rotation_residual_bits: u16,
    /// Residual after one sparse packed linear map.
    pub mapped_fresh_residual_bits: u16,
    /// Residual in the final level-zero `x/u/W/rW` accumulators.
    pub linear_accumulator_residual_bits: u16,
    /// Residual after one encrypted multiplication and relinearization.
    pub cross_product_residual_bits: u16,
    /// Residual after the four-product Equation (6) cross term.
    pub equation_6_cross_term_residual_bits: u16,
    /// Residual in the final level-one `E/rE` accumulators.
    pub level_one_accumulator_residual_bits: u16,
    /// Residual in the Equation (7) encrypted commitment path.
    pub encrypted_commitment_residual_bits: u16,
    /// Per-party statistically hiding decryption-smudge quotient bound.
    pub decryption_smudge_quotient_bits: u16,
    /// Final residual after all-roster partial-decryption share fusion.
    pub final_decryption_residual_bits: u16,
    /// Bit length of the frozen ciphertext modulus product.
    pub ciphertext_modulus_bits: u16,
    /// Strict headroom below the centered `Q/2` correctness boundary.
    pub correctness_margin_bits: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Bound(u16);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IngressErrorBoundsV1 {
    sampled_min: i16,
    sampled_max: i16,
    sampled_max_abs: u8,
    sampled_bound_bits: u8,
    effective_min: i16,
    effective_max: i16,
    effective_verifier_max_abs: u8,
    effective_bound_bits: u8,
    upper_half_correction_min: u8,
    upper_half_correction_max: u8,
}
fn derive_ingress_error_bounds_v1(
    sampled_error_eta: u8,
) -> Result<IngressErrorBoundsV1, ZkAmsMkheErrorV1> {
    if !(1..=32).contains(&sampled_error_eta) {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    let sampled_max = i16::from(sampled_error_eta);
    let sampled_min = -sampled_max;
    let sampled_max_abs = sampled_error_eta;
    let upper_half_correction_min = 0_u8;
    let upper_half_correction_max = 1_u8;
    let effective_min = sampled_min
        .checked_sub(i16::from(upper_half_correction_max))
        .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    let effective_max = sampled_max
        .checked_sub(i16::from(upper_half_correction_min))
        .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    let effective_verifier_max_abs = u8::try_from(
        effective_min
            .unsigned_abs()
            .max(effective_max.unsigned_abs()),
    )
    .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?;
    let sampled_bound_bits = strict_magnitude_bound_bits(sampled_max_abs)?;
    let effective_bound_bits = strict_magnitude_bound_bits(effective_verifier_max_abs)?;
    let bounds = IngressErrorBoundsV1 {
        sampled_min,
        sampled_max,
        sampled_max_abs,
        sampled_bound_bits,
        effective_min,
        effective_max,
        effective_verifier_max_abs,
        effective_bound_bits,
        upper_half_correction_min,
        upper_half_correction_max,
    };
    validate_ingress_error_bounds_v1(bounds, sampled_error_eta)?;
    Ok(bounds)
}
fn validate_ingress_error_bounds_v1(
    bounds: IngressErrorBoundsV1,
    sampled_error_eta: u8,
) -> Result<(), ZkAmsMkheErrorV1> {
    if !(1..=32).contains(&sampled_error_eta) {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    let eta = i16::from(sampled_error_eta);
    let sampled_power = 1_u32
        .checked_shl(u32::from(bounds.sampled_bound_bits))
        .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    let effective_power = 1_u32
        .checked_shl(u32::from(bounds.effective_bound_bits))
        .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    let expected_effective_min = bounds
        .sampled_min
        .checked_sub(i16::from(bounds.upper_half_correction_max))
        .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    let expected_effective_max = bounds
        .sampled_max
        .checked_sub(i16::from(bounds.upper_half_correction_min))
        .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    if bounds.sampled_min != -eta
        || bounds.sampled_max != eta
        || bounds.sampled_max_abs != sampled_error_eta
        || bounds.upper_half_correction_min != 0
        || bounds.upper_half_correction_max != 1
        || bounds.effective_min != expected_effective_min
        || bounds.effective_max != expected_effective_max
        || u16::from(bounds.effective_verifier_max_abs)
            != bounds
                .effective_min
                .unsigned_abs()
                .max(bounds.effective_max.unsigned_abs())
        || u32::from(bounds.sampled_max_abs) >= sampled_power
        || u32::from(bounds.effective_verifier_max_abs) >= effective_power
        || bounds.sampled_bound_bits != strict_magnitude_bound_bits(bounds.sampled_max_abs)?
        || bounds.effective_bound_bits
            != strict_magnitude_bound_bits(bounds.effective_verifier_max_abs)?
    {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    Ok(())
}
fn strict_magnitude_bound_bits(max_abs: u8) -> Result<u8, ZkAmsMkheErrorV1> {
    let exclusive = usize::from(max_abs)
        .checked_add(1)
        .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    u8::try_from(ceil_log2(exclusive)?).map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)
}
impl Bound {
    fn add(self, rhs: Self) -> Result<Self, ZkAmsMkheErrorV1> {
        Ok(Self(
            self.0
                .max(rhs.0)
                .checked_add(1)
                .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?,
        ))
    }
    fn sum(self, count: usize) -> Result<Self, ZkAmsMkheErrorV1> {
        if count == 0 {
            return Err(ZkAmsMkheErrorV1::InvalidProfile);
        }
        Ok(Self(
            self.0
                .checked_add(ceil_log2(count)?)
                .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?,
        ))
    }
    fn scalar_mul(self, rhs: Self) -> Result<Self, ZkAmsMkheErrorV1> {
        Ok(Self(
            self.0
                .checked_add(rhs.0)
                .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?,
        ))
    }
    fn polynomial_mul(self, rhs: Self, log_ring_degree: u16) -> Result<Self, ZkAmsMkheErrorV1> {
        Ok(Self(
            self.0
                .checked_add(rhs.0)
                .and_then(|bits| bits.checked_add(log_ring_degree))
                .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?,
        ))
    }
}
/// Parameters for the one shared Phase-II/III norm recurrence.
#[derive(Clone, Copy, Debug)]
pub(super) struct NoisePathInputsV1 {
    pub ring_degree: usize,
    pub party_count: usize,
    pub sparse_map_fan_in: usize,
    pub max_batch_size: usize,
    pub ingress_bits: u16,
    pub rotation_switch_bits: u16,
    pub relinearization_switch_bits: u16,
    pub terminal_overhead_bits: u16,
}
/// Bounds only; neither correctness nor admission is implied by this result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NoisePathBoundsV1 {
    pub max_composed_rotation_key_switch_count: usize,
    pub composed_rotation_residual: u16,
    pub mapped_fresh: u16,
    pub linear_accumulator: u16,
    pub cross_product: u16,
    pub equation_6_cross_term: u16,
    pub level_one_accumulator: u16,
    pub encrypted_commitment: u16,
    pub decryption_smudge_quotient: u16,
    pub final_decryption_residual: u16,
}
/// Evaluate the actual norm recurrence with distinct rotation and relinearization inputs.
pub(super) fn derive_noise_path_v1(
    inputs: NoisePathInputsV1,
) -> Result<NoisePathBoundsV1, ZkAmsMkheErrorV1> {
    let NoisePathInputsV1 {
        ring_degree,
        party_count,
        sparse_map_fan_in,
        max_batch_size,
        ingress_bits,
        rotation_switch_bits,
        relinearization_switch_bits,
        terminal_overhead_bits,
    } = inputs;
    if ring_degree < 2
        || !ring_degree.is_power_of_two()
        || !(2..=8).contains(&party_count)
        || sparse_map_fan_in == 0
        || !(1..=8).contains(&max_batch_size)
        || terminal_overhead_bits < 129
    {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    let log_n = ring_degree.trailing_zeros() as u16;
    let plaintext = Bound(255);
    let plaintext_modulus = Bound(256);
    let collective_ingress_residual = Bound(ingress_bits);
    let rotation_switch = Bound(rotation_switch_bits);
    let relinearization_switch = Bound(relinearization_switch_bits);
    let slot_count = ring_degree / 2;
    let max_composed_rotation_key_switch_count =
        phase23_max_composed_rotation_key_switch_count(slot_count)?;
    // A canonical arbitrary rotation is a sequence of binary automorphisms.
    // Automorphisms preserve the infinity norm, so its residual is the source
    // plus one complete switch residual for every constituent key switch.
    let composed_rotation_residual = if max_composed_rotation_key_switch_count == 0 {
        collective_ingress_residual
    } else {
        collective_ingress_residual
            .add(rotation_switch.sum(max_composed_rotation_key_switch_count)?)?
    };
    let mapped_fresh = composed_rotation_residual
        .polynomial_mul(plaintext, log_n)?
        .sum(sparse_map_fan_in)?;
    // Replicated-U ingress is a fresh collective ciphertext and linear folds
    // preserve that shape. Equation (6) consumes it directly, so it adds no
    // expansion phase or expansion-specific residual.
    let phase23_fresh_operand = Bound(mapped_fresh.0.max(collective_ingress_residual.0));
    let challenge_times_mapped = mapped_fresh.polynomial_mul(plaintext, log_n)?;
    let linear_accumulator = challenge_times_mapped.sum(max_batch_size)?;
    // Multiplication of phases `(m1+r1)(m2+r2)` includes the exact plaintext
    // reduction quotient, both mixed terms, and the residual product.
    let plaintext_product_quotient = plaintext.polynomial_mul(plaintext, log_n)?.add(plaintext)?;
    let first_mixed = plaintext.polynomial_mul(phase23_fresh_operand, log_n)?;
    let second_mixed = plaintext.polynomial_mul(linear_accumulator, log_n)?;
    let residual_product = linear_accumulator.polynomial_mul(phase23_fresh_operand, log_n)?;
    let cross_product = Bound(
        plaintext_product_quotient
            .0
            .max(first_mixed.0)
            .max(second_mixed.0)
            .max(residual_product.0),
    )
    .sum(4)?
    .add(relinearization_switch)?;
    let equation_6_cross_term = cross_product.sum(4)?;
    let challenge_times_cross = equation_6_cross_term.polynomial_mul(plaintext, log_n)?;
    let fresh_product = Bound(
        plaintext_product_quotient.0.max(first_mixed.0).max(
            phase23_fresh_operand
                .polynomial_mul(phase23_fresh_operand, log_n)?
                .0,
        ),
    )
    .sum(4)?
    .add(relinearization_switch)?;
    let challenge_squared_times_fresh = fresh_product.polynomial_mul(plaintext, log_n)?;
    let per_row_level_one = challenge_times_cross.add(challenge_squared_times_fresh)?;
    let level_one_accumulator = per_row_level_one.sum(max_batch_size)?;
    // Equation (7) applies one additional public sparse map but no encrypted
    // multiplication; it is tracked separately even though E/rE dominate it.
    let encrypted_commitment = linear_accumulator
        .add(rotation_switch)?
        .polynomial_mul(plaintext, log_n)?
        .sum(sparse_map_fan_in)?;
    // Public partial-decryption shares must statistically hide the full
    // evaluated quotient.  Since p > 2^255, division by p loses at least 255
    // bits.  Smudging is summed over every roster member before decoding.
    let evaluated_residual = level_one_accumulator.0.max(encrypted_commitment.0);
    let evaluated_quotient = evaluated_residual
        .checked_sub(255)
        .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    let decryption_smudge_quotient = Bound(
        evaluated_quotient
            .checked_add(terminal_overhead_bits)
            .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?,
    );
    let aggregate_decryption_smudge = decryption_smudge_quotient.sum(party_count)?;
    let aggregate_decryption_smudge_residual =
        plaintext_modulus.scalar_mul(aggregate_decryption_smudge)?;
    let final_decryption_residual =
        Bound(evaluated_residual).add(aggregate_decryption_smudge_residual)?;
    Ok(NoisePathBoundsV1 {
        max_composed_rotation_key_switch_count,
        composed_rotation_residual: composed_rotation_residual.0,
        mapped_fresh: mapped_fresh.0,
        linear_accumulator: linear_accumulator.0,
        cross_product: cross_product.0,
        equation_6_cross_term: equation_6_cross_term.0,
        level_one_accumulator: level_one_accumulator.0,
        encrypted_commitment: encrypted_commitment.0,
        decryption_smudge_quotient: decryption_smudge_quotient.0,
        final_decryption_residual: final_decryption_residual.0,
    })
}
/// Derive the complete conservative schedule for the frozen construction.
#[allow(clippy::too_many_arguments)]
pub(super) fn derive_noise_certificate_v1(
    ring_degree: usize,
    party_count: usize,
    hybrid_limb_count: usize,
    sparse_map_fan_in: usize,
    max_batch_size: usize,
    ciphertext_modulus_bits: usize,
    statistical_security_bits: u16,
    sampled_error_eta: u8,
) -> Result<ZkAmsMkheNoiseCertificateV1, ZkAmsMkheErrorV1> {
    if ring_degree < 2
        || !ring_degree.is_power_of_two()
        || !(2..=8).contains(&party_count)
        || hybrid_limb_count == 0
        || sparse_map_fan_in == 0
        || !(1..=8).contains(&max_batch_size)
        || statistical_security_bits < 128
        || !(1..=32).contains(&sampled_error_eta)
    {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    let error_bounds = derive_ingress_error_bounds_v1(sampled_error_eta)?;
    let log_n = u16::try_from(ring_degree.trailing_zeros())
        .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?;
    let plaintext_modulus = Bound(256);
    let ternary = Bound(1);
    let sampled_rlwe_error = Bound(u16::from(error_bounds.sampled_bound_bits));
    let natural_lift_effective_error = Bound(u16::from(error_bounds.effective_bound_bits));
    // Key error and c1 encryption error retain the actual CBD-eta sampling
    // distribution. Only the c0 proof witness uses the canonical natural-lift
    // effective bound, derived above from `e0' = e0 - h` rather than silently
    // reusing the sampler's eta.
    let independent_key_error_times_ephemeral =
        sampled_rlwe_error.polynomial_mul(ternary, log_n)?;
    let independent_encryption_error_times_secret =
        sampled_rlwe_error.polynomial_mul(ternary, log_n)?;
    let independent_fresh_quotient = independent_key_error_times_ephemeral
        .0
        .max(natural_lift_effective_error.0)
        .max(independent_encryption_error_times_secret.0);
    let independent_fresh_quotient = Bound(independent_fresh_quotient).sum(3)?;
    let independent_fresh_residual = plaintext_modulus.scalar_mul(independent_fresh_quotient)?;
    // CKS samples a quotient error at least 2^(lambda+1) wider than the
    // complete source quotient.  All roster contributions are included.
    let cks_smudge_quotient = Bound(
        independent_fresh_quotient
            .0
            .checked_add(statistical_security_bits)
            .and_then(|bits| bits.checked_add(1))
            .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?,
    );
    let aggregate_cks_smudge = cks_smudge_quotient.sum(party_count)?;
    let cks_smudge_residual = plaintext_modulus.scalar_mul(aggregate_cks_smudge)?;
    let collective_ingress_residual = independent_fresh_residual.add(cks_smudge_residual)?;
    // The three-round collective RKG terms are bounded as
    // s*sum(e0), (sum(u)-s)*sum(e2), and sum(e1/e3).
    let collective_secret = ternary.sum(party_count)?;
    let collective_error = sampled_rlwe_error.sum(party_count)?;
    let secret_times_error = collective_secret.polynomial_mul(collective_error, log_n)?;
    let ephemeral_minus_secret = collective_secret.add(collective_secret)?;
    let difference_times_error = ephemeral_minus_secret.polynomial_mul(collective_error, log_n)?;
    let rkg_quotient = Bound(
        secret_times_error
            .0
            .max(difference_times_error.0)
            .max(collective_error.0),
    )
    .sum(3)?;
    let collective_rkg_residual = plaintext_modulus.scalar_mul(rkg_quotient)?;
    // Each hybrid digit is one centered ~60-bit RNS limb and is consumed,
    // multiplied, and released before the next limb is expanded.
    let hybrid_digit = Bound(60);
    let hybrid_key_switch_residual = hybrid_digit
        .polynomial_mul(collective_rkg_residual, log_n)?
        .sum(hybrid_limb_count)?;
    let path = derive_noise_path_v1(NoisePathInputsV1 {
        ring_degree,
        party_count,
        sparse_map_fan_in,
        max_batch_size,
        ingress_bits: collective_ingress_residual.0,
        rotation_switch_bits: hybrid_key_switch_residual.0,
        relinearization_switch_bits: hybrid_key_switch_residual.0,
        terminal_overhead_bits: statistical_security_bits
            .checked_add(1)
            .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?,
    })?;
    let max_composed_rotation_key_switch_count = path.max_composed_rotation_key_switch_count;
    let composed_rotation_residual = Bound(path.composed_rotation_residual);
    let mapped_fresh = Bound(path.mapped_fresh);
    let linear_accumulator = Bound(path.linear_accumulator);
    let cross_product = Bound(path.cross_product);
    let equation_6_cross_term = Bound(path.equation_6_cross_term);
    let level_one_accumulator = Bound(path.level_one_accumulator);
    let encrypted_commitment = Bound(path.encrypted_commitment);
    let decryption_smudge_quotient = Bound(path.decryption_smudge_quotient);
    let final_decryption_residual = Bound(path.final_decryption_residual);
    let ciphertext_modulus_bits =
        u16::try_from(ciphertext_modulus_bits).map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?;
    let centered_capacity = ciphertext_modulus_bits
        .checked_sub(1)
        .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    let correctness_margin_bits = centered_capacity
        .checked_sub(final_decryption_residual.0)
        .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    Ok(ZkAmsMkheNoiseCertificateV1 {
        ring_degree: u32::try_from(ring_degree).map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        party_count: u8::try_from(party_count).map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        hybrid_limb_count: u8::try_from(hybrid_limb_count)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        sparse_map_fan_in: u32::try_from(sparse_map_fan_in)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        sampled_rlwe_error_min: error_bounds.sampled_min,
        sampled_rlwe_error_max: error_bounds.sampled_max,
        sampled_rlwe_error_max_abs: error_bounds.sampled_max_abs,
        sampled_rlwe_error_bound_bits: error_bounds.sampled_bound_bits,
        natural_lift_effective_error_min: error_bounds.effective_min,
        natural_lift_effective_error_max: error_bounds.effective_max,
        natural_lift_effective_error_verifier_max_abs: error_bounds.effective_verifier_max_abs,
        natural_lift_effective_error_bound_bits: error_bounds.effective_bound_bits,
        natural_lift_upper_half_correction_min: error_bounds.upper_half_correction_min,
        natural_lift_upper_half_correction_max: error_bounds.upper_half_correction_max,
        independent_fresh_residual_bits: independent_fresh_residual.0,
        cks_smudge_quotient_bits: cks_smudge_quotient.0,
        collective_ingress_residual_bits: collective_ingress_residual.0,
        collective_rkg_residual_bits: collective_rkg_residual.0,
        hybrid_key_switch_residual_bits: hybrid_key_switch_residual.0,
        max_composed_rotation_key_switch_count: u8::try_from(
            max_composed_rotation_key_switch_count,
        )
        .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        composed_rotation_residual_bits: composed_rotation_residual.0,
        mapped_fresh_residual_bits: mapped_fresh.0,
        linear_accumulator_residual_bits: linear_accumulator.0,
        cross_product_residual_bits: cross_product.0,
        equation_6_cross_term_residual_bits: equation_6_cross_term.0,
        level_one_accumulator_residual_bits: level_one_accumulator.0,
        encrypted_commitment_residual_bits: encrypted_commitment.0,
        decryption_smudge_quotient_bits: decryption_smudge_quotient.0,
        final_decryption_residual_bits: final_decryption_residual.0,
        ciphertext_modulus_bits,
        correctness_margin_bits,
    })
}
fn ceil_log2(value: usize) -> Result<u16, ZkAmsMkheErrorV1> {
    if value == 0 {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    u16::try_from(usize::BITS - (value - 1).leading_zeros())
        .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn release_schedule_has_strict_margin_and_every_phase_is_monotone() {
        let certificate = derive_noise_certificate_v1(131_072, 8, 38, 524_378, 8, 2_280, 128, 2)
            .expect("frozen conservative schedule");
        assert_eq!(certificate.sampled_rlwe_error_min, -2);
        assert_eq!(certificate.sampled_rlwe_error_max, 2);
        assert_eq!(certificate.sampled_rlwe_error_max_abs, 2);
        assert_eq!(certificate.sampled_rlwe_error_bound_bits, 2);
        assert_eq!(certificate.natural_lift_effective_error_min, -3);
        assert_eq!(certificate.natural_lift_effective_error_max, 2);
        assert_eq!(certificate.natural_lift_effective_error_verifier_max_abs, 3);
        assert_eq!(certificate.natural_lift_effective_error_bound_bits, 2);
        assert_eq!(certificate.natural_lift_upper_half_correction_min, 0);
        assert_eq!(certificate.natural_lift_upper_half_correction_max, 1);
        // Although the exact integer intervals differ, both are strictly
        // below 2^2. The frozen end-to-end result therefore stays unchanged.
        assert_eq!(certificate.final_decryption_residual_bits, 2_115);
        assert_eq!(certificate.correctness_margin_bits, 164);
        assert!(certificate.correctness_margin_bits >= 64);
        assert!(
            certificate.independent_fresh_residual_bits
                < certificate.collective_ingress_residual_bits
        );
        assert_eq!(certificate.cks_smudge_quotient_bits, 151);
        assert_eq!(certificate.max_composed_rotation_key_switch_count, 8);
        assert_eq!(certificate.composed_rotation_residual_bits, 412);
        assert!(
            certificate.collective_ingress_residual_bits
                < certificate.composed_rotation_residual_bits
        );
        assert!(
            certificate.mapped_fresh_residual_bits < certificate.linear_accumulator_residual_bits
        );
        assert!(
            certificate.cross_product_residual_bits
                < certificate.equation_6_cross_term_residual_bits
        );
        assert!(
            certificate.level_one_accumulator_residual_bits
                < certificate.final_decryption_residual_bits
        );
    }
    #[test]
    fn sampled_and_natural_lift_error_bounds_cross_power_boundaries_exactly() {
        let eta_one = derive_ingress_error_bounds_v1(1).unwrap();
        assert_eq!(eta_one.sampled_min, -1);
        assert_eq!(eta_one.sampled_max, 1);
        assert_eq!(eta_one.sampled_bound_bits, 1);
        assert_eq!(eta_one.effective_min, -2);
        assert_eq!(eta_one.effective_max, 1);
        assert_eq!(eta_one.effective_verifier_max_abs, 2);
        assert_eq!(eta_one.effective_bound_bits, 2);
        let eta_two = derive_ingress_error_bounds_v1(2).unwrap();
        assert_eq!(eta_two.sampled_bound_bits, 2);
        assert_eq!(eta_two.effective_bound_bits, 2);
        let eta_three = derive_ingress_error_bounds_v1(3).unwrap();
        assert_eq!(eta_three.sampled_min, -3);
        assert_eq!(eta_three.sampled_max, 3);
        assert_eq!(eta_three.sampled_bound_bits, 2);
        assert_eq!(eta_three.effective_min, -4);
        assert_eq!(eta_three.effective_max, 3);
        assert_eq!(eta_three.effective_verifier_max_abs, 4);
        assert_eq!(eta_three.effective_bound_bits, 3);
        for (maximum, expected_bits) in [(0, 0), (1, 1), (2, 2), (3, 2), (4, 3)] {
            assert_eq!(strict_magnitude_bound_bits(maximum), Ok(expected_bits));
        }
        for invalid_eta in [0, 33, u8::MAX] {
            assert_eq!(
                derive_ingress_error_bounds_v1(invalid_eta),
                Err(ZkAmsMkheErrorV1::InvalidProfile)
            );
        }
    }
    #[test]
    fn every_error_bound_or_correction_splice_fails_invariant_validation() {
        let expected = derive_ingress_error_bounds_v1(2).unwrap();
        for invalid in [
            IngressErrorBoundsV1 {
                sampled_min: -3,
                ..expected
            },
            IngressErrorBoundsV1 {
                sampled_max: 3,
                ..expected
            },
            IngressErrorBoundsV1 {
                sampled_max_abs: 3,
                ..expected
            },
            IngressErrorBoundsV1 {
                sampled_bound_bits: 1,
                ..expected
            },
            IngressErrorBoundsV1 {
                effective_min: -2,
                ..expected
            },
            IngressErrorBoundsV1 {
                effective_max: 3,
                ..expected
            },
            IngressErrorBoundsV1 {
                effective_verifier_max_abs: 2,
                ..expected
            },
            IngressErrorBoundsV1 {
                effective_bound_bits: 1,
                ..expected
            },
            IngressErrorBoundsV1 {
                upper_half_correction_min: 1,
                ..expected
            },
            IngressErrorBoundsV1 {
                upper_half_correction_max: 0,
                ..expected
            },
            IngressErrorBoundsV1 {
                upper_half_correction_max: 2,
                ..expected
            },
        ] {
            assert_eq!(
                validate_ingress_error_bounds_v1(invalid, 2),
                Err(ZkAmsMkheErrorV1::InvalidProfile)
            );
        }
    }
    #[test]
    fn one_bit_less_than_required_modulus_is_rejected() {
        let baseline = derive_noise_certificate_v1(131_072, 8, 38, 524_378, 8, 2_280, 128, 2)
            .expect("baseline schedule");
        assert_eq!(
            derive_noise_certificate_v1(
                131_072,
                8,
                38,
                524_378,
                8,
                usize::from(baseline.final_decryption_residual_bits),
                128,
                2,
            ),
            Err(ZkAmsMkheErrorV1::InvalidProfile)
        );
    }
    #[test]
    fn adversarial_fan_in_roster_and_statistical_downgrades_fail_closed() {
        for invalid in [
            derive_noise_certificate_v1(131_072, 1, 38, 524_378, 8, 2_280, 128, 2),
            derive_noise_certificate_v1(131_072, 9, 38, 524_378, 8, 2_280, 128, 2),
            derive_noise_certificate_v1(131_072, 8, 0, 524_378, 8, 2_280, 128, 2),
            derive_noise_certificate_v1(131_072, 8, 38, 0, 8, 2_280, 128, 2),
            derive_noise_certificate_v1(131_072, 8, 38, 524_378, 9, 2_280, 128, 2),
            derive_noise_certificate_v1(131_072, 8, 38, 524_378, 8, 2_280, 127, 2),
            derive_noise_certificate_v1(131_072, 8, 38, 524_378, 8, 2_280, 128, 0),
            derive_noise_certificate_v1(131_072, 8, 38, 524_378, 8, 2_280, 128, 33),
        ] {
            assert_eq!(invalid, Err(ZkAmsMkheErrorV1::InvalidProfile));
        }
    }
    #[test]
    fn signed_binary_composition_counts_cover_every_power_of_two_boundary() {
        for (slots, expected_composed) in [
            (1, 0),
            (2, 1),
            (4, 1),
            (8, 2),
            (16, 2),
            (32, 3),
            (65_536, 8),
        ] {
            assert_eq!(
                phase23_max_composed_rotation_key_switch_count(slots),
                Ok(expected_composed)
            );
        }
        for invalid in [0, 3, 6, 65_535, 65_537] {
            assert_eq!(
                phase23_max_composed_rotation_key_switch_count(invalid),
                Err(ZkAmsMkheErrorV1::InvalidProfile)
            );
        }
    }
}
