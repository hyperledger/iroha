//! Construction-specific, non-authorizing noise and resource diagnostics.
//!
//! This owner uses the shared norm recurrence, but supplies the actual weighted
//! pair RKG/Galois source bounds and accounts for evaluated-key CKS separately
//! from ingress CKS. Raw weighted keys and direct three-round keys are distinct
//! unadmitted alternatives; selecting either does not install a key or bypass
//! the opaque complete-key-set admission boundary.
//!
//! The optional vector/query allocation is a sufficient finite-uniform-box TV
//! calculation, conditional on the stated coordinate shifts and query census.
//! It is not a malicious-party extraction or whole-protocol simulation theorem.
//! TODO: Bind the enforced session census, coalition model and exact proof
//! extraction to this calculation before using any result for admission.

use core::cmp::Ordering;

use super::{
    ZkAmsMkheErrorV1,
    decryption::{
        DECRYPTION_MAX_WIDE_BITS_V1, DECRYPTION_PROOF_HEADER_BYTES_V1,
        DECRYPTION_SIGNED_SMALL_BYTES_V1, WIDE_RELATION_MASK_SLACK_LOG2_V1,
        wide_relation_challenge_weight,
    },
    manifest::{
        ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1, ZK_AMS_MKHE_SPARSE_MAP_FAN_IN_CEILING_V1,
        ZK_AMS_MKHE_STATISTICAL_SECURITY_BITS_V1, release_profile_v1,
        zk_ams_mkhe_noise_certificate_v1,
    },
    noise::{NoisePathInputsV1, derive_noise_path_v1},
    packing::ZK_AMS_T256_GALOIS_KEY_COUNT_V1,
    wire::ZK_AMS_MKHE_MAX_PROOF_BYTES_V1,
};

/// Exact algebraic source family whose residuals are being counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAmsMkheNoiseConstructionV1 {
    /// Existing honest-source generator: weighted pair RKG and Galois, then CKS.
    WeightedPairWithCks,
    /// The weighted pair algebra before CKS; not an admitted compact key format.
    RawWeightedPairAlternative,
    /// Direct three-round normalization algebra; complete proof admission is absent.
    DirectThreeRoundAlternative,
}

/// Widths to diagnose, without changing any actual sampler or protocol parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAmsMkheNoiseAccountingV1 {
    /// Record the existing 151-bit CKS widths and coefficient-only terminal rule.
    RecordedCoefficientWidths,
    /// Hypothetical widths sufficient for the explicit finite-box query allocation.
    ConditionalVectorQueryAllocation,
}

/// The missing admission condition associated with a construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAmsMkheNoiseAdmissionV1 {
    /// Honest-source bounds do not prove malicious evaluated-key admission.
    HonestWeightedSourcesOnly,
    /// Removing CKS does not produce an admitted equivalent of the current keys.
    RawWeightedAlternativeUnadmitted,
    /// No complete 32-key, 38-digit proof admission exists for the direct path.
    CompleteDirectKeySetUnavailable,
}

/// Maximum public full-polynomial smudge vectors in the proposed session.
///
/// Count every party, digit, key, repeated invocation and epoch. These are caller
/// assumptions, not enforced protocol counters. There is deliberately no default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsMkheSmudgeQueriesV1 {
    /// Independently keyed ingress CKS share vectors.
    pub ingress_vectors: u64,
    /// Evaluated relinearization-key CKS share vectors.
    pub rkg_vectors: u64,
    /// Evaluated Galois-key CKS share vectors.
    pub galois_vectors: u64,
    /// Public terminal partial-decryption smudge vectors.
    pub terminal_vectors: u64,
}

/// Different plaintext-quotient sources must not share an ingress-derived input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAmsMkheSmudgePurposeV1 {
    /// Independent fresh encryption under the ingress proof bounds.
    IndependentIngress,
    /// Weighted-pair RKG output before compaction.
    EvaluatedRelinearizationKey,
    /// All-party Galois source before compaction.
    EvaluatedGaloisKey,
}

/// A derived CKS input; it is diagnostic data, not an admission receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsMkheCksNoiseInputV1 {
    /// Owner of the pre-CKS quotient bound.
    pub purpose: ZkAmsMkheSmudgePurposeV1,
    /// Every source coefficient has magnitude strictly below this power of two.
    pub source_quotient_bits: u16,
    /// Width of each party's smudge, counted independently for this purpose.
    pub per_party_smudge_bits: u16,
    /// Full p-scaled residual after all eight smudges and the original source.
    pub output_residual_bits: u16,
}

/// Conditional union allocation for finite uniform-box translations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsMkheFailureAllocationV1 {
    /// Requested upper bound on the sum of the counted TV distances.
    pub target_security_bits: u16,
    /// Complete explicit query assumptions, including all parties and epochs.
    pub queries: ZkAmsMkheSmudgeQueriesV1,
    /// Ring degree times the sum of the four vector counts.
    pub exposed_coordinates: u128,
    /// Ceiling of log2(exposed_coordinates), with no floating-point rounding.
    pub union_overhead_bits: u16,
    /// Minimum smudge-minus-source-minus-one across all counted purposes.
    pub minimum_coefficient_security_bits: u16,
    /// Conditional session TV is at most 2^-this value under the stated shifts.
    pub conditional_session_security_bits: u16,
    /// Whether the sufficient box bound reaches the requested target.
    pub conditional_target_met: bool,
    /// Always false: the protocol simulation/extraction theorem is still missing.
    pub protocol_privacy_established: bool,
}

/// One shared downstream norm recurrence, with purpose-specific key inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsMkhePhaseNoiseBoundsV1 {
    /// Full residual after ingress CKS.
    pub ingress_residual_bits: u16,
    /// Residual added by one Galois key switch.
    pub rotation_switch_bits: u16,
    /// Residual added by one relinearization key switch.
    pub relinearization_switch_bits: u16,
    /// Source plus the longest composed rotation.
    pub composed_rotation_bits: u16,
    /// Sparse linear-map output.
    pub mapped_bits: u16,
    /// Level-zero accumulator.
    pub linear_bits: u16,
    /// One encrypted cross product, including relinearization.
    pub cross_bits: u16,
    /// Four-product Equation (6) cross term.
    pub equation_six_bits: u16,
    /// Level-one accumulator.
    pub level_one_bits: u16,
    /// Equation (7) commitment path.
    pub encrypted_commitment_bits: u16,
    /// Each party's terminal smudge quotient width.
    pub terminal_smudge_bits: u16,
    /// Final full residual after all-roster decryption.
    pub final_residual_bits: u16,
}

/// Exact arithmetic and byte accounting, independent of admission qualification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkAmsMkheTerminalFeasibilityV1 {
    /// Exact retained modulus product, least-significant u64 word first.
    pub exact_modulus_le_words: Vec<u64>,
    /// Exact bit length of that product.
    pub modulus_bits: u16,
    /// Exact comparison `2 * (2^final_bits - 1) < Q`.
    pub centered_correctness_bound_fits: bool,
    /// Exact bit length of `(2^smudge_bits - 1) * weight * 2^slack`.
    pub wide_mask_bits: u16,
    /// Includes the signed response bit; no runtime wide-capacity truncation.
    pub response_coefficient_bytes: u16,
    /// Existing arithmetic capacity; this diagnostic never raises it.
    pub governed_wide_capacity_bits: u16,
    /// Both mask arithmetic and signed fixed-width response fit existing limits.
    pub wide_arithmetic_fits: bool,
    /// Two small responses, one wide response per coefficient, and actual header.
    pub proof_payload_bytes: u64,
    /// Existing governed proof ceiling.
    pub governed_proof_bytes: u64,
    /// Whether the exact payload fits that ceiling.
    pub proof_payload_fits: bool,
    /// Native combine requires the eight source and one output RNS payloads.
    pub native_combine_residency_lower_bound_bytes: u64,
    /// Existing governed native workspace ceiling.
    pub governed_workspace_bytes: u64,
    /// Necessary byte check only; not a peak-residency certificate.
    pub native_combine_lower_bound_fits: bool,
}

/// Construction and assumptions are inseparable from this non-authorizing report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkAmsMkheNoiseFeasibilityV1 {
    /// Exact algebraic construction being diagnosed.
    pub construction: ZkAmsMkheNoiseConstructionV1,
    /// Recorded sampler widths or explicitly hypothetical allocated widths.
    pub accounting: ZkAmsMkheNoiseAccountingV1,
    /// Missing source/proof admission condition.
    pub admission: ZkAmsMkheNoiseAdmissionV1,
    /// Current retained profile identity, not a new parameter certificate.
    pub profile_digest: [u8; 32],
    /// Inclusive honest-source relinearization quotient bound.
    pub rkg_source_max_abs: u64,
    /// Inclusive honest-source Galois quotient bound.
    pub galois_source_max_abs: u64,
    /// Independent ingress CKS input.
    pub ingress: ZkAmsMkheCksNoiseInputV1,
    /// Present only when evaluated RKG keys actually undergo CKS.
    pub evaluated_rkg: Option<ZkAmsMkheCksNoiseInputV1>,
    /// Present only when evaluated Galois keys actually undergo CKS.
    pub evaluated_galois: Option<ZkAmsMkheCksNoiseInputV1>,
    /// Explicit conditional vector/query calculation.
    pub allocation: ZkAmsMkheFailureAllocationV1,
    /// Result from the shared downstream recurrence.
    pub phases: ZkAmsMkhePhaseNoiseBoundsV1,
    /// Exact Q, proof and workspace comparisons.
    pub terminal: ZkAmsMkheTerminalFeasibilityV1,
    /// Always false; this report cannot authorize any operational entry point.
    pub authorizes_release: bool,
}

fn checked(value: Option<u64>) -> Result<u64, ZkAmsMkheErrorV1> {
    value.ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
}

fn bit_sum(a: u16, b: u16) -> Result<u16, ZkAmsMkheErrorV1> {
    a.checked_add(b).ok_or(ZkAmsMkheErrorV1::InvalidProfile)
}

fn ceil_log2(value: u128) -> Result<u16, ZkAmsMkheErrorV1> {
    if value == 0 {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    Ok((u128::BITS - (value - 1).leading_zeros()) as u16)
}

fn strict_bits(maximum: u64) -> u16 {
    (u64::BITS - maximum.leading_zeros()) as u16
}

fn cks_input(
    purpose: ZkAmsMkheSmudgePurposeV1,
    source_bits: u16,
    width: u16,
    parties: u64,
) -> Result<ZkAmsMkheCksNoiseInputV1, ZkAmsMkheErrorV1> {
    let aggregate = bit_sum(width, ceil_log2(u128::from(parties))?)?;
    Ok(ZkAmsMkheCksNoiseInputV1 {
        purpose,
        source_quotient_bits: source_bits,
        per_party_smudge_bits: width,
        output_residual_bits: bit_sum(256, bit_sum(source_bits.max(aggregate), 1)?)?,
    })
}

fn hybrid_switch(bits: u16, log_n: u16, limbs: usize) -> Result<u16, ZkAmsMkheErrorV1> {
    bit_sum(
        bit_sum(bit_sum(60, bits)?, log_n)?,
        ceil_log2(limbs as u128)?,
    )
}

/// Small exact non-secret diagnostic arithmetic, separate from runtime samplers.
///
/// This can represent a refused mask so its size can be reported; it does not
/// change `WideMagnitudeV1`, any codec, or any governed runtime capacity.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactNatural(Vec<u64>);

impl ExactNatural {
    fn max_for_bits(bits: u16) -> Self {
        let mut words = vec![u64::MAX; usize::from(bits).div_ceil(64).max(1)];
        if bits == 0 {
            words[0] = 0;
        } else if !bits.is_multiple_of(64) {
            *words.last_mut().expect("nonempty diagnostic magnitude") = (1 << (bits % 64)) - 1;
        }
        Self(words)
    }

    fn multiply(&mut self, scalar: u64) {
        let mut carry = 0_u128;
        for word in &mut self.0 {
            let product = u128::from(*word) * u128::from(scalar) + carry;
            *word = product as u64;
            carry = product >> 64;
        }
        if carry != 0 {
            self.0.push(carry as u64);
        }
        while self.0.len() > 1 && self.0.last() == Some(&0) {
            self.0.pop();
        }
    }

    fn bit_len(&self) -> u16 {
        ((self.0.len() - 1) * 64 + (64 - self.0.last().unwrap().leading_zeros()) as usize) as u16
    }

    fn compare(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.iter().rev().cmp(other.0.iter().rev()))
    }
}

fn terminal_feasibility(
    final_bits: u16,
    smudge_bits: u16,
) -> Result<ZkAmsMkheTerminalFeasibilityV1, ZkAmsMkheErrorV1> {
    let profile = release_profile_v1();
    let mut modulus = ExactNatural(vec![1]);
    for &limb in profile.moduli {
        modulus.multiply(limb);
    }
    let mut twice_bound = ExactNatural::max_for_bits(final_bits);
    twice_bound.multiply(2);
    let mut mask = ExactNatural::max_for_bits(smudge_bits);
    mask.multiply(wide_relation_challenge_weight(profile.ring_degree)? as u64);
    mask.multiply(1 << WIDE_RELATION_MASK_SLACK_LOG2_V1);
    let response_bytes = bit_sum(mask.bit_len(), 1)?.div_ceil(8);
    let per_coefficient = checked(
        (2 * DECRYPTION_SIGNED_SMALL_BYTES_V1 as u64).checked_add(u64::from(response_bytes)),
    )?;
    let proof_bytes = checked(
        checked((profile.ring_degree as u64).checked_mul(per_coefficient))?
            .checked_add(DECRYPTION_PROOF_HEADER_BYTES_V1 as u64),
    )?;
    let residency = checked(
        (profile.ring_degree as u64)
            .checked_mul(profile.moduli.len() as u64)
            .and_then(|n| n.checked_mul(size_of::<u64>() as u64))
            .and_then(|n| n.checked_mul(ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 as u64 + 1)),
    )?;
    Ok(ZkAmsMkheTerminalFeasibilityV1 {
        modulus_bits: modulus.bit_len(),
        centered_correctness_bound_fits: twice_bound.compare(&modulus) == Ordering::Less,
        exact_modulus_le_words: modulus.0,
        wide_mask_bits: mask.bit_len(),
        response_coefficient_bytes: response_bytes,
        governed_wide_capacity_bits: DECRYPTION_MAX_WIDE_BITS_V1 as u16,
        wide_arithmetic_fits: usize::from(mask.bit_len()) <= DECRYPTION_MAX_WIDE_BITS_V1
            && usize::from(response_bytes) <= DECRYPTION_MAX_WIDE_BITS_V1 / 8,
        proof_payload_bytes: proof_bytes,
        governed_proof_bytes: ZK_AMS_MKHE_MAX_PROOF_BYTES_V1 as u64,
        proof_payload_fits: proof_bytes <= ZK_AMS_MKHE_MAX_PROOF_BYTES_V1 as u64,
        native_combine_residency_lower_bound_bytes: residency,
        governed_workspace_bytes: profile.max_workspace_bytes as u64,
        native_combine_lower_bound_fits: residency <= profile.max_workspace_bytes as u64,
    })
}

/// Diagnose one explicitly chosen construction under an explicit query census.
///
/// Counts must include at least one all-party ingress and terminal vector set.
/// The current CKS construction additionally requires all 38 relinearization
/// digits and all 31×38 Galois digits, each with all eight party responses.
/// Alternatives require zero evaluated-key CKS queries: silently reusing the
/// current construction's query census would describe different mathematics.
///
/// For a coordinate source bound `|x| < 2^b`, two translations differ by less
/// than `2^(b+1)`. A uniform integer smudge on `[-B,B]`, `B=2^w-1`, has TV at
/// most `|delta|/(2B+1)`. Summing over the explicit coordinates is therefore
/// bounded by `2^(b+1-w+ceil(log2(coordinates)))`. This conditional calculation
/// proves neither the stated malicious-source bound nor the protocol simulator.
pub fn zk_ams_mkhe_noise_feasibility_v1(
    construction: ZkAmsMkheNoiseConstructionV1,
    accounting: ZkAmsMkheNoiseAccountingV1,
    queries: ZkAmsMkheSmudgeQueriesV1,
) -> Result<ZkAmsMkheNoiseFeasibilityV1, ZkAmsMkheErrorV1> {
    let profile = release_profile_v1();
    profile.validate()?;
    let n = profile.ring_degree as u64;
    let parties = ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 as u64;
    let limbs = profile.moduli.len();
    let has_cks = construction == ZkAmsMkheNoiseConstructionV1::WeightedPairWithCks;
    let rkg_queries = checked(parties.checked_mul(limbs as u64))?;
    let galois_queries = checked(rkg_queries.checked_mul(ZK_AMS_T256_GALOIS_KEY_COUNT_V1 as u64))?;
    if queries.ingress_vectors < parties
        || queries.terminal_vectors < parties
        || (has_cks
            && (queries.rkg_vectors < rkg_queries || queries.galois_vectors < galois_queries))
        || (!has_cks && (queries.rkg_vectors != 0 || queries.galois_vectors != 0))
    {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    let vectors = u128::from(queries.ingress_vectors)
        + u128::from(queries.rkg_vectors)
        + u128::from(queries.galois_vectors)
        + u128::from(queries.terminal_vectors);
    let coordinates = vectors * u128::from(n);
    let union_bits = ceil_log2(coordinates)?;
    let lambda = ZK_AMS_MKHE_STATISTICAL_SECURITY_BITS_V1;
    let coefficient_overhead = bit_sum(lambda, 1)?;
    let allocated_overhead = bit_sum(coefficient_overhead, union_bits)?;
    let overhead = match accounting {
        ZkAmsMkheNoiseAccountingV1::RecordedCoefficientWidths => coefficient_overhead,
        ZkAmsMkheNoiseAccountingV1::ConditionalVectorQueryAllocation => allocated_overhead,
    };
    let ingress_source_bits =
        zk_ams_mkhe_noise_certificate_v1()?.independent_fresh_residual_bits - 256;
    let recorded_width = bit_sum(ingress_source_bits, coefficient_overhead)?;
    let width = |source| match accounting {
        ZkAmsMkheNoiseAccountingV1::RecordedCoefficientWidths => Ok(recorded_width),
        ZkAmsMkheNoiseAccountingV1::ConditionalVectorQueryAllocation => bit_sum(source, overhead),
    };
    let ingress = cks_input(
        ZkAmsMkheSmudgePurposeV1::IndependentIngress,
        ingress_source_bits,
        width(ingress_source_bits)?,
        parties,
    )?;
    let aggregate_error = checked(parties.checked_mul(u64::from(profile.error_eta)))?;
    let (rkg_max, galois_max, admission) = match construction {
        ZkAmsMkheNoiseConstructionV1::WeightedPairWithCks
        | ZkAmsMkheNoiseConstructionV1::RawWeightedPairAlternative => {
            // Per pair: E0*s_right + E1*U + E2. Diagonal weight one and
            // off-diagonal weight two sum to parties², not unordered-pair count.
            let pair = checked(
                n.checked_mul(aggregate_error)
                    .and_then(|v| v.checked_mul(parties + 1))
                    .and_then(|v| v.checked_add(aggregate_error)),
            )?;
            let rkg = checked(
                pair.checked_mul(parties)
                    .and_then(|v| v.checked_mul(parties)),
            )?;
            let galois = checked(
                n.checked_mul(2)
                    .and_then(|v| v.checked_add(1))
                    .and_then(|v| v.checked_mul(u64::from(profile.error_eta)))
                    .and_then(|v| v.checked_mul(parties)),
            )?;
            (
                rkg,
                galois,
                if has_cks {
                    ZkAmsMkheNoiseAdmissionV1::HonestWeightedSourcesOnly
                } else {
                    ZkAmsMkheNoiseAdmissionV1::RawWeightedAlternativeUnadmitted
                },
            )
        }
        ZkAmsMkheNoiseConstructionV1::DirectThreeRoundAlternative => {
            // E0*S + E1*U + E2 + E3; seeded-final-a normalization adds E3.
            let rkg = checked(
                n.checked_mul(aggregate_error)
                    .and_then(|v| v.checked_mul(parties))
                    .and_then(|v| v.checked_mul(2))
                    .and_then(|v| v.checked_add(2 * aggregate_error)),
            )?;
            (
                rkg,
                aggregate_error,
                ZkAmsMkheNoiseAdmissionV1::CompleteDirectKeySetUnavailable,
            )
        }
    };
    let rkg_bits = strict_bits(rkg_max);
    let galois_bits = strict_bits(galois_max);
    let evaluated_rkg = has_cks
        .then(|| {
            cks_input(
                ZkAmsMkheSmudgePurposeV1::EvaluatedRelinearizationKey,
                rkg_bits,
                width(rkg_bits)?,
                parties,
            )
        })
        .transpose()?;
    let evaluated_galois = has_cks
        .then(|| {
            cks_input(
                ZkAmsMkheSmudgePurposeV1::EvaluatedGaloisKey,
                galois_bits,
                width(galois_bits)?,
                parties,
            )
        })
        .transpose()?;
    let log_n = profile.ring_degree.trailing_zeros() as u16;
    let rkg_residual =
        evaluated_rkg.map_or(bit_sum(256, rkg_bits), |v| Ok(v.output_residual_bits))?;
    let galois_residual =
        evaluated_galois.map_or(bit_sum(256, galois_bits), |v| Ok(v.output_residual_bits))?;
    let rotation_switch = hybrid_switch(galois_residual, log_n, limbs)?;
    let relin_switch = hybrid_switch(rkg_residual, log_n, limbs)?;
    let path = derive_noise_path_v1(NoisePathInputsV1 {
        ring_degree: profile.ring_degree,
        party_count: parties as usize,
        sparse_map_fan_in: ZK_AMS_MKHE_SPARSE_MAP_FAN_IN_CEILING_V1,
        max_batch_size: 8,
        ingress_bits: ingress.output_residual_bits,
        rotation_switch_bits: rotation_switch,
        relinearization_switch_bits: relin_switch,
        terminal_overhead_bits: overhead,
    })?;
    let mut minimum_coefficient_bits = overhead - 1;
    for input in [Some(ingress), evaluated_rkg, evaluated_galois]
        .into_iter()
        .flatten()
    {
        minimum_coefficient_bits = minimum_coefficient_bits.min(
            input
                .per_party_smudge_bits
                .saturating_sub(bit_sum(input.source_quotient_bits, 1)?),
        );
    }
    let session_bits = minimum_coefficient_bits.saturating_sub(union_bits);
    Ok(ZkAmsMkheNoiseFeasibilityV1 {
        construction,
        accounting,
        admission,
        profile_digest: profile.digest()?,
        rkg_source_max_abs: rkg_max,
        galois_source_max_abs: galois_max,
        ingress,
        evaluated_rkg,
        evaluated_galois,
        allocation: ZkAmsMkheFailureAllocationV1 {
            target_security_bits: lambda,
            queries,
            exposed_coordinates: coordinates,
            union_overhead_bits: union_bits,
            minimum_coefficient_security_bits: minimum_coefficient_bits,
            conditional_session_security_bits: session_bits,
            conditional_target_met: session_bits >= lambda,
            protocol_privacy_established: false,
        },
        phases: ZkAmsMkhePhaseNoiseBoundsV1 {
            ingress_residual_bits: ingress.output_residual_bits,
            rotation_switch_bits: rotation_switch,
            relinearization_switch_bits: relin_switch,
            composed_rotation_bits: path.composed_rotation_residual,
            mapped_bits: path.mapped_fresh,
            linear_bits: path.linear_accumulator,
            cross_bits: path.cross_product,
            equation_six_bits: path.equation_6_cross_term,
            level_one_bits: path.level_one_accumulator,
            encrypted_commitment_bits: path.encrypted_commitment,
            terminal_smudge_bits: path.decryption_smudge_quotient,
            final_residual_bits: path.final_decryption_residual,
        },
        terminal: terminal_feasibility(
            path.final_decryption_residual,
            path.decryption_smudge_quotient,
        )?,
        authorizes_release: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queries(construction: ZkAmsMkheNoiseConstructionV1) -> ZkAmsMkheSmudgeQueriesV1 {
        let has_cks = construction == ZkAmsMkheNoiseConstructionV1::WeightedPairWithCks;
        ZkAmsMkheSmudgeQueriesV1 {
            ingress_vectors: 8,
            rkg_vectors: if has_cks { 8 * 38 } else { 0 },
            galois_vectors: if has_cks { 8 * 38 * 31 } else { 0 },
            terminal_vectors: 8,
        }
    }

    #[test]
    fn actual_cks_residual_reproduces_the_retained_refusal_without_capacity_changes() {
        let construction = ZkAmsMkheNoiseConstructionV1::WeightedPairWithCks;
        let value = zk_ams_mkhe_noise_feasibility_v1(
            construction,
            ZkAmsMkheNoiseAccountingV1::RecordedCoefficientWidths,
            queries(construction),
        )
        .unwrap();
        assert_eq!(
            (value.rkg_source_max_abs, value.galois_source_max_abs),
            (1_207_960_576, 4_194_320)
        );
        assert_eq!(value.ingress.source_quotient_bits, 22);
        let rkg = value.evaluated_rkg.unwrap();
        let galois = value.evaluated_galois.unwrap();
        assert_eq!(
            (rkg.source_quotient_bits, galois.source_quotient_bits),
            (31, 23)
        );
        assert_eq!(
            (rkg.per_party_smudge_bits, galois.per_party_smudge_bits),
            (151, 151)
        );
        assert_ne!(rkg.purpose, value.ingress.purpose);
        assert_ne!(galois.purpose, rkg.purpose);
        let p = value.phases;
        assert_eq!(
            (p.rotation_switch_bits, p.relinearization_switch_bits),
            (494, 494)
        );
        assert_eq!(
            (p.composed_rotation_bits, p.mapped_bits, p.linear_bits),
            (498, 790, 1065)
        );
        assert_eq!(
            (p.cross_bits, p.equation_six_bits, p.level_one_bits),
            (1875, 1877, 2153)
        );
        assert_eq!(
            (p.terminal_smudge_bits, p.final_residual_bits),
            (2027, 2287)
        );
        let t = value.terminal;
        assert_eq!(
            (
                t.modulus_bits,
                t.wide_mask_bits,
                t.response_coefficient_bytes
            ),
            (2280, 2056, 258)
        );
        assert_eq!(t.proof_payload_bytes, 35_913_783);
        assert_eq!(
            t.native_combine_residency_lower_bound_bytes,
            342 * 1024 * 1024
        );
        assert_eq!(t.governed_workspace_bytes, 160 * 1024 * 1024);
        assert_eq!(t.governed_wide_capacity_bits, 2048);
        assert_eq!(t.governed_proof_bytes, 32 * 1024 * 1024);
        assert!(
            !t.centered_correctness_bound_fits
                && !t.wide_arithmetic_fits
                && !t.proof_payload_fits
                && !t.native_combine_lower_bound_fits
        );
        assert!(!value.allocation.conditional_target_met);
        assert!(!value.allocation.protocol_privacy_established && !value.authorizes_release);
    }

    #[test]
    fn raw_and_direct_contracts_are_distinct_and_cannot_authorize_current_keys() {
        for construction in [
            ZkAmsMkheNoiseConstructionV1::RawWeightedPairAlternative,
            ZkAmsMkheNoiseConstructionV1::DirectThreeRoundAlternative,
        ] {
            let value = zk_ams_mkhe_noise_feasibility_v1(
                construction,
                ZkAmsMkheNoiseAccountingV1::RecordedCoefficientWidths,
                queries(construction),
            )
            .unwrap();
            assert!(value.evaluated_rkg.is_none() && value.evaluated_galois.is_none());
            assert_eq!(value.phases.final_residual_bits, 2115);
            assert!(value.terminal.centered_correctness_bound_fits);
            assert!(!value.terminal.native_combine_lower_bound_fits);
            assert!(!value.authorizes_release);
            if construction == ZkAmsMkheNoiseConstructionV1::DirectThreeRoundAlternative {
                assert_eq!(
                    (value.rkg_source_max_abs, value.galois_source_max_abs),
                    (33_554_464, 16)
                );
                assert_eq!(
                    value.admission,
                    ZkAmsMkheNoiseAdmissionV1::CompleteDirectKeySetUnavailable
                );
                let existing = super::super::direct_collective_eval_ceremony::zk_ams_mkhe_direct_noise_integration_certificate_v1().unwrap();
                assert!(!existing.direct_phase23_noise_schedule_applies);
            } else {
                assert_eq!(
                    value.admission,
                    ZkAmsMkheNoiseAdmissionV1::RawWeightedAlternativeUnadmitted
                );
            }
        }
    }

    #[test]
    fn complete_vector_query_allocation_is_purpose_specific_and_monotone() {
        let construction = ZkAmsMkheNoiseConstructionV1::WeightedPairWithCks;
        let base_queries = queries(construction);
        let value = zk_ams_mkhe_noise_feasibility_v1(
            construction,
            ZkAmsMkheNoiseAccountingV1::ConditionalVectorQueryAllocation,
            base_queries,
        )
        .unwrap();
        let allocation = value.allocation;
        assert_eq!(
            allocation.exposed_coordinates,
            131_072 * (8 + 304 + 9424 + 8)
        );
        assert_eq!(allocation.union_overhead_bits, 31);
        assert_eq!(allocation.conditional_session_security_bits, 128);
        assert!(allocation.conditional_target_met);
        assert!(!allocation.protocol_privacy_established);
        assert_eq!(value.ingress.per_party_smudge_bits, 182);
        assert_eq!(value.evaluated_rkg.unwrap().per_party_smudge_bits, 191);
        assert_eq!(value.evaluated_galois.unwrap().per_party_smudge_bits, 183);
        assert_eq!(
            (
                value.phases.rotation_switch_bits,
                value.phases.relinearization_switch_bits
            ),
            (526, 534)
        );
        assert_eq!(
            (
                value.phases.terminal_smudge_bits,
                value.phases.final_residual_bits
            ),
            (2122, 2382)
        );
        assert_eq!(value.terminal.proof_payload_bytes, 37_355_575);
        assert!(!value.terminal.centered_correctness_bound_fits);
        let doubled = ZkAmsMkheSmudgeQueriesV1 {
            ingress_vectors: base_queries.ingress_vectors * 2,
            rkg_vectors: base_queries.rkg_vectors * 2,
            galois_vectors: base_queries.galois_vectors * 2,
            terminal_vectors: base_queries.terminal_vectors * 2,
        };
        let next = zk_ams_mkhe_noise_feasibility_v1(
            construction,
            ZkAmsMkheNoiseAccountingV1::ConditionalVectorQueryAllocation,
            doubled,
        )
        .unwrap();
        assert_eq!(
            next.allocation.union_overhead_bits,
            allocation.union_overhead_bits + 1
        );
        assert_eq!(
            next.ingress.per_party_smudge_bits,
            value.ingress.per_party_smudge_bits + 1
        );
        assert!(next.phases.final_residual_bits >= value.phases.final_residual_bits);
        assert!(!next.authorizes_release);
    }

    #[test]
    fn shared_path_keeps_rotation_and_relinearization_inputs_distinct() {
        let inputs = NoisePathInputsV1 {
            ring_degree: 131_072,
            party_count: 8,
            sparse_map_fan_in: 524_378,
            max_batch_size: 8,
            ingress_bits: 411,
            rotation_switch_bits: 494,
            relinearization_switch_bits: 494,
            terminal_overhead_bits: 129,
        };
        let base = derive_noise_path_v1(inputs).unwrap();
        let rotated = derive_noise_path_v1(NoisePathInputsV1 {
            rotation_switch_bits: 514,
            ..inputs
        })
        .unwrap();
        let multiplied = derive_noise_path_v1(NoisePathInputsV1 {
            relinearization_switch_bits: 3000,
            ..inputs
        })
        .unwrap();
        assert_eq!(base.mapped_fresh, 790);
        assert_eq!(rotated.mapped_fresh, 810);
        assert_eq!(multiplied.mapped_fresh, base.mapped_fresh);
        assert_eq!(multiplied.cross_product, 3001);
        assert_eq!(
            derive_noise_path_v1(NoisePathInputsV1 {
                terminal_overhead_bits: 128,
                ..inputs
            }),
            Err(ZkAmsMkheErrorV1::InvalidProfile)
        );
    }

    #[test]
    fn missing_party_digit_key_or_wrong_construction_census_is_rejected() {
        let construction = ZkAmsMkheNoiseConstructionV1::WeightedPairWithCks;
        let q = queries(construction);
        for bad in [
            ZkAmsMkheSmudgeQueriesV1 {
                ingress_vectors: 7,
                ..q
            },
            ZkAmsMkheSmudgeQueriesV1 {
                terminal_vectors: 7,
                ..q
            },
            ZkAmsMkheSmudgeQueriesV1 {
                rkg_vectors: 303,
                ..q
            },
            ZkAmsMkheSmudgeQueriesV1 {
                galois_vectors: 9423,
                ..q
            },
        ] {
            assert_eq!(
                zk_ams_mkhe_noise_feasibility_v1(
                    construction,
                    ZkAmsMkheNoiseAccountingV1::ConditionalVectorQueryAllocation,
                    bad
                ),
                Err(ZkAmsMkheErrorV1::InvalidProfile)
            );
        }
        assert_eq!(
            zk_ams_mkhe_noise_feasibility_v1(
                ZkAmsMkheNoiseConstructionV1::DirectThreeRoundAlternative,
                ZkAmsMkheNoiseAccountingV1::RecordedCoefficientWidths,
                q
            ),
            Err(ZkAmsMkheErrorV1::InvalidProfile)
        );
    }

    #[test]
    fn exact_integer_helpers_cover_carries_zero_and_same_bit_length_boundaries() {
        for bits in [0, 1, 3, 63, 64, 65, 120] {
            for scalar in [0_u64, 1, 2, 7] {
                let mut value = ExactNatural::max_for_bits(bits);
                value.multiply(scalar);
                let expected = ((1_u128 << bits) - 1) * u128::from(scalar);
                let actual = u128::from(value.0[0])
                    + (u128::from(value.0.get(1).copied().unwrap_or(0)) << 64);
                assert_eq!(actual, expected);
                assert_eq!(value.bit_len(), (128 - expected.leading_zeros()) as u16);
            }
        }
        let mut bound = ExactNatural::max_for_bits(3);
        bound.multiply(2);
        assert_eq!(bound.compare(&ExactNatural(vec![15])), Ordering::Less);
        assert_eq!(bound.compare(&ExactNatural(vec![9])), Ordering::Greater);
        assert_eq!(bound.compare(&ExactNatural(vec![14])), Ordering::Equal);
        assert_eq!(ceil_log2(0), Err(ZkAmsMkheErrorV1::InvalidProfile));
        assert_eq!(ceil_log2(1), Ok(0));
        assert_eq!(ceil_log2(1 << 64), Ok(64));
        assert_eq!(
            checked(None),
            Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
        );
        assert_eq!(bit_sum(u16::MAX, 1), Err(ZkAmsMkheErrorV1::InvalidProfile));
        assert_eq!(strict_bits(16), 5);
        let q = terminal_feasibility(2278, 1855).unwrap();
        assert!(q.centered_correctness_bound_fits);
        let original_q = super::super::modulus_product(release_profile_v1().moduli).unwrap();
        assert_eq!(
            q.exact_modulus_le_words,
            original_q.limbs[..usize::from(q.modulus_bits).div_ceil(64)]
        );
        assert!(
            !terminal_feasibility(2279, 1855)
                .unwrap()
                .centered_correctness_bound_fits
        );
    }

    #[test]
    fn exact_finite_box_translation_controls_support_only_the_stated_union_bound() {
        // Exhaustively count two-coordinate finite-box overlap, independently of
        // the logarithmic schedule; shifts beyond the box must have TV exactly 1.
        for bound in 1_i64..=4 {
            let width = 2 * bound + 1;
            for dx in 0..=width + 1 {
                for dy in 0..=width + 1 {
                    let mut overlap = 0_i64;
                    for x in -bound..=bound {
                        for y in -bound..=bound {
                            if (-bound..=bound).contains(&(x - dx))
                                && (-bound..=bound).contains(&(y - dy))
                            {
                                overlap += 1;
                            }
                        }
                    }
                    let product = (width - dx).max(0) * (width - dy).max(0);
                    assert_eq!(overlap, product);
                    assert!(width * width - overlap <= (dx + dy) * width);
                }
            }
        }
    }

    fn add(left: &[i128], right: &[i128]) -> Vec<i128> {
        assert_eq!(left.len(), right.len());
        left.iter().zip(right).map(|(a, b)| a + b).collect()
    }

    fn scale(poly: &[i128], scalar: i128) -> Vec<i128> {
        poly.iter().map(|value| value * scalar).collect()
    }

    fn multiply(left: &[i128], right: &[i128]) -> Vec<i128> {
        assert_eq!(left.len(), right.len());
        let n = left.len();
        let mut result = vec![0; n];
        for (i, a) in left.iter().enumerate() {
            for (j, b) in right.iter().enumerate() {
                result[(i + j) % n] += if i + j < n { a * b } else { -a * b };
            }
        }
        result
    }

    fn sum(polys: &[Vec<i128>], n: usize) -> Vec<i128> {
        polys.iter().fold(vec![0; n], |a, b| add(&a, b))
    }

    fn polynomial(state: &mut u64, n: usize, radius: i128) -> Vec<i128> {
        (0..n)
            .map(|_| {
                // Test-only fixed integer sequence; no cryptographic randomness claim.
                *state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                i128::from(*state >> 32) % (2 * radius + 1) - radius
            })
            .collect()
    }

    #[test]
    fn weighted_pair_cks_and_direct_algebra_hold_over_96_exact_negacyclic_cases() {
        let mut cases = 0;
        let mut detected_omissions = 0;
        for n in [4, 8] {
            for parties in [2, 3, 4] {
                for seed in 0..16 {
                    let mut state = (n * 65536 + parties * 256 + seed) as u64;
                    let secrets: Vec<_> =
                        (0..parties).map(|_| polynomial(&mut state, n, 1)).collect();
                    let secret = sum(&secrets, n);
                    let mut constant = vec![0; n];
                    let mut linear = vec![0; n];
                    let mut error = vec![0; n];
                    for left in 0..parties {
                        for right in left..parties {
                            let a = polynomial(&mut state, n, 13);
                            let u: Vec<_> =
                                (0..parties).map(|_| polynomial(&mut state, n, 1)).collect();
                            let e: Vec<Vec<_>> = (0..3)
                                .map(|_| {
                                    (0..parties).map(|_| polynomial(&mut state, n, 2)).collect()
                                })
                                .collect();
                            let h0 = sum(
                                &(0..parties)
                                    .map(|i| {
                                        add(
                                            &add(
                                                &scale(&multiply(&a, &u[i]), -1),
                                                &if i == left {
                                                    scale(&secrets[i], 256)
                                                } else {
                                                    vec![0; n]
                                                },
                                            ),
                                            &scale(&e[0][i], 17),
                                        )
                                    })
                                    .collect::<Vec<_>>(),
                                n,
                            );
                            let h1 = sum(
                                &(0..parties)
                                    .map(|i| {
                                        add(
                                            &if i == right {
                                                multiply(&a, &secrets[i])
                                            } else {
                                                vec![0; n]
                                            },
                                            &scale(&e[1][i], 17),
                                        )
                                    })
                                    .collect::<Vec<_>>(),
                                n,
                            );
                            let k = sum(
                                &(0..parties)
                                    .map(|i| {
                                        add(
                                            &add(
                                                &if i == right {
                                                    multiply(&h0, &secrets[i])
                                                } else {
                                                    vec![0; n]
                                                },
                                                &multiply(
                                                    &h1,
                                                    &add(&u[i], &scale(&secrets[i], -1)),
                                                ),
                                            ),
                                            &scale(&e[2][i], 17),
                                        )
                                    })
                                    .collect::<Vec<_>>(),
                                n,
                            );
                            let quotient = add(
                                &add(
                                    &multiply(&sum(&e[0], n), &secrets[right]),
                                    &multiply(&sum(&e[1], n), &sum(&u, n)),
                                ),
                                &sum(&e[2], n),
                            );
                            assert_eq!(
                                add(&k, &multiply(&h1, &secret)),
                                add(
                                    &scale(&multiply(&secrets[left], &secrets[right]), 256),
                                    &scale(&quotient, 17)
                                )
                            );
                            let weight = if left == right { 1 } else { 2 };
                            constant = add(&constant, &scale(&k, weight));
                            linear = add(&linear, &scale(&h1, weight));
                            error = add(&error, &scale(&quotient, weight));
                        }
                    }
                    let raw_phase =
                        add(&scale(&multiply(&secret, &secret), 256), &scale(&error, 17));
                    assert_eq!(add(&constant, &multiply(&linear, &secret)), raw_phase);
                    let target_a = polynomial(&mut state, n, 31);
                    // A nonzero legal test smudge forces the omitted-CKS mutant to fail.
                    let mut smudges = vec![vec![0; n]; parties];
                    smudges[0][0] = 1;
                    let contributions: Vec<_> = (0..parties)
                        .map(|i| {
                            add(
                                &multiply(&add(&linear, &scale(&target_a, -1)), &secrets[i]),
                                &scale(&smudges[i], 17),
                            )
                        })
                        .collect();
                    let compact = add(
                        &add(&constant, &sum(&contributions, n)),
                        &multiply(&target_a, &secret),
                    );
                    assert_eq!(compact, add(&raw_phase, &scale(&sum(&smudges, n), 17)));
                    assert_ne!(compact, raw_phase);
                    detected_omissions += 1;
                    let u: Vec<_> = (0..parties).map(|_| polynomial(&mut state, n, 1)).collect();
                    let e: Vec<Vec<_>> = (0..4)
                        .map(|_| (0..parties).map(|_| polynomial(&mut state, n, 2)).collect())
                        .collect();
                    let a = polynomial(&mut state, n, 13);
                    let h0 = sum(
                        &(0..parties)
                            .map(|i| {
                                add(
                                    &add(
                                        &scale(&multiply(&a, &u[i]), -1),
                                        &scale(&secrets[i], 256),
                                    ),
                                    &scale(&e[0][i], 17),
                                )
                            })
                            .collect::<Vec<_>>(),
                        n,
                    );
                    let h1 = sum(
                        &(0..parties)
                            .map(|i| add(&multiply(&a, &secrets[i]), &scale(&e[1][i], 17)))
                            .collect::<Vec<_>>(),
                        n,
                    );
                    let k = sum(
                        &(0..parties)
                            .map(|i| {
                                add(
                                    &add(
                                        &multiply(&h0, &secrets[i]),
                                        &multiply(&h1, &add(&u[i], &scale(&secrets[i], -1))),
                                    ),
                                    &scale(&e[2][i], 17),
                                )
                            })
                            .collect::<Vec<_>>(),
                        n,
                    );
                    let normalized = sum(
                        &(0..parties)
                            .map(|i| {
                                add(
                                    &multiply(&add(&h1, &scale(&target_a, -1)), &secrets[i]),
                                    &scale(&e[3][i], 17),
                                )
                            })
                            .collect::<Vec<_>>(),
                        n,
                    );
                    let direct_error = add(
                        &add(
                            &multiply(&sum(&e[0], n), &secret),
                            &multiply(&sum(&e[1], n), &sum(&u, n)),
                        ),
                        &add(&sum(&e[2], n), &sum(&e[3], n)),
                    );
                    assert_eq!(
                        add(&add(&k, &normalized), &multiply(&target_a, &secret)),
                        add(
                            &scale(&multiply(&secret, &secret), 256),
                            &scale(&direct_error, 17)
                        )
                    );
                    cases += 1;
                }
            }
        }
        assert_eq!((cases, detected_omissions), (96, 96));
    }
}
