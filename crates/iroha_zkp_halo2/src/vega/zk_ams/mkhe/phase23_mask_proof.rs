//! Fail-closed audit boundary for a Phase-II/III hidden-mask proof.
//!
//! A useful *per-full-ciphertext-chunk* algebraic primitive was found, but it
//! is not a release construction.  For the release ring
//! `R = Z[X]/(X^N + 1)`, use the sigma-fixed challenges
//! `c_i = X^i + X^-i` with `i = 32*k`, `0 <= k < 4096`.  For distinct
//! challenges,
//!
//! ```text
//! delta = c_i - c_j
//!       = X^-i (X^(i-j) - 1) (X^(i+j) - 1).
//! ```
//!
//! If `d = gcd(k, N)`, `L = N/d`, and
//! `G_k = sum_(t=0)^(L-1) X^(k*t)`, then `(X^k - 1)G_k = -2` in `R`.
//! Hence `h = X^i G_(i-j) G_(i+j)` satisfies `h*delta = 4`.  Every challenge
//! index is a multiple of 32, so both geometric sums have at most 4096 terms
//! and `norm_1(h) <= 4096^2 = 2^24`.  This certifies extraction of a bounded
//! opening of the *physical scale-four ciphertext*.  It does not justify
//! dividing a raw ciphertext by four: there are short witnesses divisible by
//! two but not four that answer all challenges.  Scale four therefore has to
//! be a first-class, digest-bound ciphertext family throughout the protocol.
//!
//! Eleven jointly Fiat--Shamir-derived 12-bit challenges give a 132-bit
//! challenge space.  The four local witnesses are `(r, e0', e1, M)`, with
//! `M` sampled in the sigma-fixed subspace and encoded by its `N/2`
//! independent coefficients.  The exact response payload is 3.75 MiB per
//! repetition and 41.25 MiB per full ciphertext chunk.
//!
//! The primitive is rejected for release for four independently decisive reasons:
//!
//! 1. Correctly including evaluated-key CKS smudging gives a final residual
//!    lower bound of 2287 bits, above the 2279-bit centered capacity.  The
//!    associated terminal wide-response proof is already at least 35,913,783
//!    bytes, also above its 32 MiB proof ceiling.  Increasing CKS/RKG smudging
//!    to its required statistical target can only increase these bounds.
//! 2. `W` alone occupies eight full ciphertext chunks.  Its response payload
//!    is therefore at least 346,030,080 bytes (330 MiB), while 64 MiB governs
//!    the complete party contribution, not each fragment.
//! 3. No proof binds the BGV plaintext opening to the existing Hyrax strict-
//!    witness commitment.  A digest of each artifact is not an equality proof.
//! 4. The sigma-fixed full-chunk codec does not prove canonical zero padding
//!    for partial `U`, `rE`, and `rW` chunks.
//!
//! Plausible next designs are recorded by
//! [`ZkAmsPhase23MaskNextDesignOptionV1`].  None is implemented here.  This
//! module deliberately exposes no accepting prover, verifier, codec, manifest
//! flag, or readiness gate.  Every operational entry point fails with
//! [`ZkAmsMkheErrorV1::ReleaseUnavailable`] before inspecting attacker bytes.

#![allow(dead_code)]
use super::{BgvProfile, PlaintextModulus, ZkAmsMkheErrorV1};
#[cfg(test)]
use core::convert::Infallible;
const RELEASE_RING_DEGREE_V1: usize = 131_072;
const SIGMA_FIXED_INDEPENDENT_COEFFICIENTS_V1: usize = RELEASE_RING_DEGREE_V1 / 2;
const CHALLENGE_STRIDE_V1: usize = 32;
const CHALLENGE_PARENT_COUNT_V1: usize = RELEASE_RING_DEGREE_V1 / CHALLENGE_STRIDE_V1;
const CHALLENGE_BITS_PER_REPETITION_V1: usize = 12;
const CHALLENGE_REPETITIONS_V1: usize = 11;
const CHALLENGE_SPACE_BITS_V1: usize = CHALLENGE_BITS_PER_REPETITION_V1 * CHALLENGE_REPETITIONS_V1;
const EXTRACTION_SCALE_V1: usize = 4;
const EXTRACTOR_L1_BOUND_V1: usize = CHALLENGE_PARENT_COUNT_V1 * CHALLENGE_PARENT_COUNT_V1;
const SMALL_WITNESS_COUNT_V1: usize = 3;
const SMALL_RESPONSE_COEFFICIENT_BYTES_V1: usize = 4;
const MESSAGE_RESPONSE_COEFFICIENT_BYTES_V1: usize = 36;
const RESPONSE_PAYLOAD_PER_REPETITION_V1: usize =
    SMALL_WITNESS_COUNT_V1 * RELEASE_RING_DEGREE_V1 * SMALL_RESPONSE_COEFFICIENT_BYTES_V1
        + SIGMA_FIXED_INDEPENDENT_COEFFICIENTS_V1 * MESSAGE_RESPONSE_COEFFICIENT_BYTES_V1;
const RESPONSE_PAYLOAD_PER_FULL_CHUNK_V1: usize =
    RESPONSE_PAYLOAD_PER_REPETITION_V1 * CHALLENGE_REPETITIONS_V1;
const RESPONSE_PAYLOAD_SIX_REPETITIONS_V1: usize = RESPONSE_PAYLOAD_PER_REPETITION_V1 * 6;
const RESPONSE_PAYLOAD_FIVE_REPETITIONS_V1: usize = RESPONSE_PAYLOAD_PER_REPETITION_V1 * 5;
const W_SCALAR_COUNT_V1: usize = 524_288;
const SCALARS_PER_FULL_CIPHERTEXT_CHUNK_V1: usize = 65_536;
const W_FULL_CIPHERTEXT_CHUNKS_V1: usize = W_SCALAR_COUNT_V1 / SCALARS_PER_FULL_CIPHERTEXT_CHUNK_V1;
const W_RESPONSE_PAYLOAD_LOWER_BOUND_V1: usize =
    W_FULL_CIPHERTEXT_CHUNKS_V1 * RESPONSE_PAYLOAD_PER_FULL_CHUNK_V1;
const CORRECTED_SWITCH_RESIDUAL_BITS_V1: usize = 494;
const CORRECTED_COMPOSED_RESIDUAL_BITS_V1: usize = 498;
const CORRECTED_MAPPED_RESIDUAL_BITS_V1: usize = 790;
const CORRECTED_LINEAR_RESIDUAL_BITS_V1: usize = 1_065;
const CORRECTED_CROSS_RESIDUAL_BITS_V1: usize = 1_875;
const CORRECTED_EQUATION_SIX_RESIDUAL_BITS_V1: usize = 1_877;
const CORRECTED_LEVEL_ONE_RESIDUAL_BITS_V1: usize = 2_153;
const CORRECTED_DECRYPTION_SMUDGE_QUOTIENT_BITS_V1: usize = 2_027;
const CORRECTED_FINAL_RESIDUAL_BITS_V1: usize = 2_287;
const CENTERED_CAPACITY_BITS_V1: usize = 2_279;
const CORRECTED_TERMINAL_WIDE_RESPONSE_COEFFICIENT_BYTES_V1: usize = 258;
const SIGNED_SMALL_RESPONSE_COEFFICIENT_BYTES_V1: usize = 8;
const TERMINAL_PROOF_HEADER_BYTES_V1: usize = 55;
const CORRECTED_TERMINAL_PROOF_BYTES_V1: usize = RELEASE_RING_DEGREE_V1
    * (2 * SIGNED_SMALL_RESPONSE_COEFFICIENT_BYTES_V1
        + CORRECTED_TERMINAL_WIDE_RESPONSE_COEFFICIENT_BYTES_V1)
    + TERMINAL_PROOF_HEADER_BYTES_V1;
const GOVERNED_PROOF_CEILING_BYTES_V1: usize = 32 * 1024 * 1024;
const EXTRACTED_EPHEMERAL_BOUND_BITS_V1: usize = 50;
const EXTRACTED_ERROR_BOUND_BITS_V1: usize = 51;
const EXTRACTED_MESSAGE_BOUND_BITS_V1: usize = 305;
const EXTRACTED_CENTERED_QUOTIENT_BOUND_BITS_V1: usize = 49;
const CANDIDATE_FRESH_RESIDUAL_BITS_V1: usize = 71;
const CANDIDATE_WORK_UNITS_PER_FULL_CHUNK_V1: u64 = 1_972_371_456;
const BLOCKER_CORRECTED_NOISE_V1: u8 = 1 << 0;
const BLOCKER_COMPLETE_PARTY_TRANSPORT_V1: u8 = 1 << 1;
const BLOCKER_HYRAX_EQUALITY_V1: u8 = 1 << 2;
const BLOCKER_PARTIAL_PADDING_V1: u8 = 1 << 3;
const ALL_RELEASE_BLOCKERS_V1: u8 = BLOCKER_CORRECTED_NOISE_V1
    | BLOCKER_COMPLETE_PARTY_TRANSPORT_V1
    | BLOCKER_HYRAX_EQUALITY_V1
    | BLOCKER_PARTIAL_PADDING_V1;
const AUDIT_DIGEST_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase23.mask-proof.fail-closed-audit";
const _: () = {
    assert!(CHALLENGE_PARENT_COUNT_V1 == 4_096);
    assert!(CHALLENGE_BITS_PER_REPETITION_V1 == CHALLENGE_PARENT_COUNT_V1.ilog2() as usize);
    assert!(CHALLENGE_SPACE_BITS_V1 == 132);
    assert!(EXTRACTOR_L1_BOUND_V1 == 1 << 24);
    assert!(RESPONSE_PAYLOAD_PER_REPETITION_V1 == 3_932_160);
    assert!(RESPONSE_PAYLOAD_PER_FULL_CHUNK_V1 == 43_253_760);
    assert!(RESPONSE_PAYLOAD_SIX_REPETITIONS_V1 == 23_592_960);
    assert!(RESPONSE_PAYLOAD_FIVE_REPETITIONS_V1 == 19_660_800);
    assert!(W_FULL_CIPHERTEXT_CHUNKS_V1 == 8);
    assert!(W_RESPONSE_PAYLOAD_LOWER_BOUND_V1 == 346_030_080);
    assert!(CORRECTED_FINAL_RESIDUAL_BITS_V1 > CENTERED_CAPACITY_BITS_V1);
    assert!(CORRECTED_TERMINAL_PROOF_BYTES_V1 == 35_913_783);
    assert!(CORRECTED_TERMINAL_PROOF_BYTES_V1 > GOVERNED_PROOF_CEILING_BYTES_V1);
    assert!(ALL_RELEASE_BLOCKERS_V1 == 0b1111);
};
/// A concrete direction that could replace the rejected linear-response
/// transport.  Every option still requires a complete security and resource
/// review; the variants are not release endorsements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum ZkAmsPhase23MaskNextDesignOptionV1 {
    /// Build a succinct cross-commitment proof that one canonical T256 vector
    /// opens both the packed BGV ciphertexts and the existing Hyrax points.
    /// It must bind scale-family metadata and exact partial-chunk padding.
    HyraxBgvCrossCommitment = 1,
    /// Add a streaming RNS-native succinct argument with CRT carry/range
    /// constraints and proof aggregation.  The current native-T256 arithmetic
    /// circuit cannot express the required `p*e` and RNS cross-binding.
    RnsNativeSuccinctArgument = 2,
    /// First repair CKS/RKG and terminal-decryption noise accounting, then
    /// choose a profile and compact terminal bounded-relation proof that fit
    /// both correctness and the governed proof ceiling.
    NoiseProfileAndTerminalProofRedesign = 3,
}
/// Ordered design directions retained by this audit.
pub(super) const ZK_AMS_PHASE23_MASK_NEXT_DESIGN_OPTIONS_V1: [ZkAmsPhase23MaskNextDesignOptionV1;
    3] = [
    ZkAmsPhase23MaskNextDesignOptionV1::HyraxBgvCrossCommitment,
    ZkAmsPhase23MaskNextDesignOptionV1::RnsNativeSuccinctArgument,
    ZkAmsPhase23MaskNextDesignOptionV1::NoiseProfileAndTerminalProofRedesign,
];
/// Machine-readable separation between the locally valid scale-four algebra
/// and the globally invalid release construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ZkAmsPhase23MaskProofAuditV1 {
    /// Release negacyclic ring degree.
    pub ring_degree: u32,
    /// Distance between allowed challenge exponents.
    pub challenge_stride: u32,
    /// Number of sigma-fixed challenges per repetition.
    pub challenge_parent_count: u32,
    /// Independently derived challenge repetitions.
    pub challenge_repetitions: u8,
    /// Lower bound on the joint challenge-space bits.
    pub challenge_space_bits: u16,
    /// Physical ciphertext scale certified by fork extraction.
    pub extraction_scale: u8,
    /// Certified upper bound on the extractor multiplier's `l1` norm.
    pub extractor_l1_bound: u32,
    /// Extracted ephemeral-opening magnitude bit bound.
    pub extracted_ephemeral_bound_bits: u16,
    /// Extracted error-opening magnitude bit bound.
    pub extracted_error_bound_bits: u16,
    /// Extracted message-opening magnitude bit bound.
    pub extracted_message_bound_bits: u16,
    /// Extracted centered plaintext-quotient magnitude bit bound.
    pub extracted_centered_quotient_bound_bits: u16,
    /// Candidate fresh-encryption residual width before global evaluation.
    pub candidate_fresh_residual_bits: u16,
    /// Exact response payload bytes for one repetition and one full chunk.
    pub response_payload_per_repetition: u64,
    /// Exact response payload bytes for eleven repetitions and one full chunk.
    pub response_payload_per_full_chunk: u64,
    /// Exact lower bound for all eight full chunks of `W`, before framing.
    pub complete_w_response_payload_lower_bound: u64,
    /// Governed ceiling for the complete party contribution.
    pub governed_complete_party_ceiling: u64,
    /// Candidate work units for one full ciphertext chunk.
    pub work_units_per_full_chunk: u64,
    /// Audited lower bound on the corrected evaluated-key switch residual.
    pub corrected_switch_residual_bits: u16,
    /// Audited lower bound on the corrected post-composition residual.
    pub corrected_composed_residual_bits: u16,
    /// Audited lower bound on the corrected mapped residual.
    pub corrected_mapped_residual_bits: u16,
    /// Audited lower bound on the corrected linear-accumulator residual.
    pub corrected_linear_residual_bits: u16,
    /// Audited lower bound on the corrected cross-term residual.
    pub corrected_cross_residual_bits: u16,
    /// Audited lower bound on the corrected Equation-(6) residual.
    pub corrected_equation_six_residual_bits: u16,
    /// Audited lower bound on the corrected final level-one residual.
    pub corrected_level_one_residual_bits: u16,
    /// Audited lower bound on the corrected terminal smudging quotient.
    pub corrected_decryption_smudge_quotient_bits: u16,
    /// Audited lower bound on the corrected final residual.
    pub corrected_final_residual_bits: u16,
    /// Centered coefficient capacity of the release modulus product.
    pub centered_capacity_bits: u16,
    /// Exact terminal proof payload at the audited minimum smudging width.
    pub corrected_terminal_proof_bytes: u64,
    /// Governed proof-payload ceiling.
    pub governed_proof_ceiling_bytes: u64,
    /// True only for the local per-full-chunk scale-four algebra.
    pub per_full_chunk_scale_four_primitive_certified: bool,
    /// Whether the corrected global noise schedule fits centered decoding.
    pub corrected_global_noise_fits: bool,
    /// Whether the corrected terminal proof fits its governed payload ceiling.
    pub corrected_terminal_proof_fits: bool,
    /// Whether all `W` responses fit the complete-party ceiling.
    pub complete_w_transport_fits: bool,
    /// Whether BGV plaintexts are proven equal to the Hyrax openings.
    pub hyrax_bgv_equality_certified: bool,
    /// Whether all unused slots in every partial family are proven zero.
    pub partial_padding_certified: bool,
    /// Bit set of the four decisive release blockers.
    pub blocker_mask: u8,
    /// Always false until every blocker is resolved in one construction.
    pub release_available: bool,
    /// T256 digest of every preceding field and the ordered next-design list.
    pub digest: [u8; 32],
}
/// Return the fail-closed audit for the release-shape profile.
pub(super) fn zk_ams_phase23_mask_proof_audit_v1(
    profile: &BgvProfile,
) -> Result<ZkAmsPhase23MaskProofAuditV1, ZkAmsMkheErrorV1> {
    require_candidate_profile_shape(profile)?;
    let corrected_global_noise_fits = CORRECTED_FINAL_RESIDUAL_BITS_V1 <= CENTERED_CAPACITY_BITS_V1;
    let corrected_terminal_proof_fits =
        CORRECTED_TERMINAL_PROOF_BYTES_V1 <= GOVERNED_PROOF_CEILING_BYTES_V1;
    let complete_w_transport_fits = W_RESPONSE_PAYLOAD_LOWER_BOUND_V1 <= profile.max_share_bytes;
    let hyrax_bgv_equality_certified = false;
    let partial_padding_certified = false;
    let per_full_chunk_scale_four_primitive_certified = true;
    let mut blocker_mask = 0_u8;
    for (complete, blocker) in [
        (
            corrected_global_noise_fits && corrected_terminal_proof_fits,
            BLOCKER_CORRECTED_NOISE_V1,
        ),
        (
            complete_w_transport_fits,
            BLOCKER_COMPLETE_PARTY_TRANSPORT_V1,
        ),
        (hyrax_bgv_equality_certified, BLOCKER_HYRAX_EQUALITY_V1),
        (partial_padding_certified, BLOCKER_PARTIAL_PADDING_V1),
    ] {
        if !complete {
            blocker_mask |= blocker;
        }
    }
    let release_available = per_full_chunk_scale_four_primitive_certified && blocker_mask == 0;
    let mut audit = ZkAmsPhase23MaskProofAuditV1 {
        ring_degree: as_u32(RELEASE_RING_DEGREE_V1)?,
        challenge_stride: as_u32(CHALLENGE_STRIDE_V1)?,
        challenge_parent_count: as_u32(CHALLENGE_PARENT_COUNT_V1)?,
        challenge_repetitions: as_u8(CHALLENGE_REPETITIONS_V1)?,
        challenge_space_bits: as_u16(CHALLENGE_SPACE_BITS_V1)?,
        extraction_scale: as_u8(EXTRACTION_SCALE_V1)?,
        extractor_l1_bound: as_u32(EXTRACTOR_L1_BOUND_V1)?,
        extracted_ephemeral_bound_bits: as_u16(EXTRACTED_EPHEMERAL_BOUND_BITS_V1)?,
        extracted_error_bound_bits: as_u16(EXTRACTED_ERROR_BOUND_BITS_V1)?,
        extracted_message_bound_bits: as_u16(EXTRACTED_MESSAGE_BOUND_BITS_V1)?,
        extracted_centered_quotient_bound_bits: as_u16(EXTRACTED_CENTERED_QUOTIENT_BOUND_BITS_V1)?,
        candidate_fresh_residual_bits: as_u16(CANDIDATE_FRESH_RESIDUAL_BITS_V1)?,
        response_payload_per_repetition: as_u64(RESPONSE_PAYLOAD_PER_REPETITION_V1)?,
        response_payload_per_full_chunk: as_u64(RESPONSE_PAYLOAD_PER_FULL_CHUNK_V1)?,
        complete_w_response_payload_lower_bound: as_u64(W_RESPONSE_PAYLOAD_LOWER_BOUND_V1)?,
        governed_complete_party_ceiling: as_u64(profile.max_share_bytes)?,
        work_units_per_full_chunk: CANDIDATE_WORK_UNITS_PER_FULL_CHUNK_V1,
        corrected_switch_residual_bits: as_u16(CORRECTED_SWITCH_RESIDUAL_BITS_V1)?,
        corrected_composed_residual_bits: as_u16(CORRECTED_COMPOSED_RESIDUAL_BITS_V1)?,
        corrected_mapped_residual_bits: as_u16(CORRECTED_MAPPED_RESIDUAL_BITS_V1)?,
        corrected_linear_residual_bits: as_u16(CORRECTED_LINEAR_RESIDUAL_BITS_V1)?,
        corrected_cross_residual_bits: as_u16(CORRECTED_CROSS_RESIDUAL_BITS_V1)?,
        corrected_equation_six_residual_bits: as_u16(CORRECTED_EQUATION_SIX_RESIDUAL_BITS_V1)?,
        corrected_level_one_residual_bits: as_u16(CORRECTED_LEVEL_ONE_RESIDUAL_BITS_V1)?,
        corrected_decryption_smudge_quotient_bits: as_u16(
            CORRECTED_DECRYPTION_SMUDGE_QUOTIENT_BITS_V1,
        )?,
        corrected_final_residual_bits: as_u16(CORRECTED_FINAL_RESIDUAL_BITS_V1)?,
        centered_capacity_bits: as_u16(CENTERED_CAPACITY_BITS_V1)?,
        corrected_terminal_proof_bytes: as_u64(CORRECTED_TERMINAL_PROOF_BYTES_V1)?,
        governed_proof_ceiling_bytes: as_u64(GOVERNED_PROOF_CEILING_BYTES_V1)?,
        per_full_chunk_scale_four_primitive_certified,
        corrected_global_noise_fits,
        corrected_terminal_proof_fits,
        complete_w_transport_fits,
        hyrax_bgv_equality_certified,
        partial_padding_certified,
        blocker_mask,
        release_available,
        digest: [0; 32],
    };
    audit.digest = audit_digest(audit);
    Ok(audit)
}
/// Uninhabited proof type.  Safe code cannot construct release evidence while
/// the audit has unresolved blockers.
#[cfg(test)]
pub(super) enum ZkAmsPhase23MaskProofV1 {}
/// Fail closed for proving, verification, encoding, or decoding.
#[cfg(test)]
pub(super) fn preflight_zk_ams_phase23_mask_proof_v1(
    profile: &BgvProfile,
) -> Result<Infallible, ZkAmsMkheErrorV1> {
    let audit = zk_ams_phase23_mask_proof_audit_v1(profile)?;
    debug_assert!(!audit.release_available);
    Err(ZkAmsMkheErrorV1::ReleaseUnavailable)
}
/// Reject candidate manifest bytes before parsing attacker-controlled input.
#[cfg(test)]
pub(super) fn decode_zk_ams_phase23_mask_manifest_v1(
    profile: &BgvProfile,
    _encoded: &[u8],
) -> Result<ZkAmsPhase23MaskProofV1, ZkAmsMkheErrorV1> {
    match preflight_zk_ams_phase23_mask_proof_v1(profile) {
        Ok(never) => match never {},
        Err(error) => Err(error),
    }
}
/// Reject candidate record bytes before parsing attacker-controlled input.
#[cfg(test)]
pub(super) fn decode_zk_ams_phase23_mask_record_v1(
    profile: &BgvProfile,
    _encoded: &[u8],
) -> Result<ZkAmsPhase23MaskProofV1, ZkAmsMkheErrorV1> {
    match preflight_zk_ams_phase23_mask_proof_v1(profile) {
        Ok(never) => match never {},
        Err(error) => Err(error),
    }
}
fn require_candidate_profile_shape(profile: &BgvProfile) -> Result<(), ZkAmsMkheErrorV1> {
    profile.validate()?;
    if profile.ring_degree != RELEASE_RING_DEGREE_V1
        || profile.plaintext_modulus != PlaintextModulus::T256
        || profile.error_eta != 2
        || profile.moduli.is_empty()
        || profile.moduli.len() != profile.negacyclic_roots.len()
    {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    Ok(())
}
fn audit_digest(audit: ZkAmsPhase23MaskProofAuditV1) -> [u8; 32] {
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Release,
        AUDIT_DIGEST_DOMAIN_V1,
        30 + ZK_AMS_PHASE23_MASK_NEXT_DESIGN_OPTIONS_V1.len(),
    );
    hash.push_field(&audit.ring_degree.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&audit.challenge_stride.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&audit.challenge_parent_count.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[audit.challenge_repetitions])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&audit.challenge_space_bits.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[audit.extraction_scale])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&audit.extractor_l1_bound.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    for bits in [
        audit.extracted_ephemeral_bound_bits,
        audit.extracted_error_bound_bits,
        audit.extracted_message_bound_bits,
        audit.extracted_centered_quotient_bound_bits,
        audit.candidate_fresh_residual_bits,
    ] {
        hash.push_field(&bits.to_be_bytes())
            .expect("fixed bounded MKHE identity field");
    }
    for bytes in [
        audit.response_payload_per_repetition,
        audit.response_payload_per_full_chunk,
        audit.complete_w_response_payload_lower_bound,
        audit.governed_complete_party_ceiling,
        audit.work_units_per_full_chunk,
    ] {
        hash.push_field(&bytes.to_be_bytes())
            .expect("fixed bounded MKHE identity field");
    }
    for bits in [
        audit.corrected_switch_residual_bits,
        audit.corrected_composed_residual_bits,
        audit.corrected_mapped_residual_bits,
        audit.corrected_linear_residual_bits,
        audit.corrected_cross_residual_bits,
        audit.corrected_equation_six_residual_bits,
        audit.corrected_level_one_residual_bits,
        audit.corrected_decryption_smudge_quotient_bits,
        audit.corrected_final_residual_bits,
        audit.centered_capacity_bits,
    ] {
        hash.push_field(&bits.to_be_bytes())
            .expect("fixed bounded MKHE identity field");
    }
    hash.push_field(&audit.corrected_terminal_proof_bytes.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&audit.governed_proof_ceiling_bytes.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[
        audit.per_full_chunk_scale_four_primitive_certified.into(),
        audit.corrected_global_noise_fits.into(),
        audit.corrected_terminal_proof_fits.into(),
        audit.complete_w_transport_fits.into(),
        audit.hyrax_bgv_equality_certified.into(),
        audit.partial_padding_certified.into(),
        audit.blocker_mask,
        audit.release_available.into(),
    ])
    .expect("fixed bounded MKHE identity field");
    for option in ZK_AMS_PHASE23_MASK_NEXT_DESIGN_OPTIONS_V1 {
        hash.push_field(&[option as u8])
            .expect("fixed bounded MKHE identity field");
    }
    *hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes()
}
fn as_u8(value: usize) -> Result<u8, ZkAmsMkheErrorV1> {
    u8::try_from(value).map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)
}
fn as_u16(value: usize) -> Result<u16, ZkAmsMkheErrorV1> {
    u16::try_from(value).map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)
}
fn as_u32(value: usize) -> Result<u32, ZkAmsMkheErrorV1> {
    u32::try_from(value).map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)
}
fn as_u64(value: usize) -> Result<u64, ZkAmsMkheErrorV1> {
    u64::try_from(value).map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vega::zk_ams::mkhe::manifest::release_profile_v1;
    #[test]
    fn per_full_chunk_scale_four_primitive_is_locally_certified() {
        let audit = zk_ams_phase23_mask_proof_audit_v1(&release_profile_v1()).unwrap();
        assert!(audit.per_full_chunk_scale_four_primitive_certified);
        assert_eq!(audit.challenge_parent_count, 4_096);
        assert_eq!(audit.challenge_repetitions, 11);
        assert_eq!(audit.challenge_space_bits, 132);
        assert_eq!(audit.extraction_scale, 4);
        assert_eq!(audit.extractor_l1_bound, 1 << 24);
        assert_eq!(audit.extracted_ephemeral_bound_bits, 50);
        assert_eq!(audit.extracted_error_bound_bits, 51);
        assert_eq!(audit.extracted_message_bound_bits, 305);
        assert_eq!(audit.extracted_centered_quotient_bound_bits, 49);
        assert_eq!(audit.candidate_fresh_residual_bits, 71);
        assert_eq!(audit.work_units_per_full_chunk, 1_972_371_456);
    }
    #[test]
    fn factor_four_identity_and_sigma_fixity_hold_in_a_negacyclic_oracle() {
        const N: usize = 32;
        let i = 4_i64;
        let j = 12_i64;
        let delta = subtract(&fixed_challenge(N, i), &fixed_challenge(N, j));
        let h = multiply(
            &monomial(N, i),
            &multiply(&geometric_sum(N, i - j), &geometric_sum(N, i + j)),
        );
        let mut four = vec![0_i64; N];
        four[0] = 4;
        assert_eq!(multiply(&h, &delta), four);
        assert_eq!(sigma(&h), h);
        assert_eq!(sigma(&fixed_challenge(N, i)), fixed_challenge(N, i));
        assert_eq!(sigma(&fixed_challenge(N, j)), fixed_challenge(N, j));
    }
    #[test]
    fn sigma_fixed_codec_has_exactly_half_degree_and_rejects_non_subfield_values() {
        const N: usize = 16;
        let independent = [11_i64, -2, 3, -4, 5, -6, 7, -8];
        let packed = reconstruct_sigma_fixed::<N>(&independent).unwrap();
        assert_eq!(sigma(&packed), packed);
        assert_eq!(packed[N / 2], 0);
        let mut invalid_midpoint = packed.clone();
        invalid_midpoint[N / 2] = 1;
        assert_ne!(sigma(&invalid_midpoint), invalid_midpoint);
        let mut invalid_pair = packed;
        invalid_pair[N - 1] = invalid_pair[1];
        assert_ne!(sigma(&invalid_pair), invalid_pair);
    }
    #[test]
    fn exact_local_payload_still_fails_complete_party_transport() {
        let audit = zk_ams_phase23_mask_proof_audit_v1(&release_profile_v1()).unwrap();
        assert_eq!(audit.response_payload_per_repetition, 3_932_160);
        assert_eq!(audit.response_payload_per_full_chunk, 43_253_760);
        assert_eq!(RESPONSE_PAYLOAD_SIX_REPETITIONS_V1, 23_592_960);
        assert_eq!(RESPONSE_PAYLOAD_FIVE_REPETITIONS_V1, 19_660_800);
        assert_eq!(audit.complete_w_response_payload_lower_bound, 346_030_080);
        assert_eq!(audit.governed_complete_party_ceiling, 67_108_864);
        assert!(!audit.complete_w_transport_fits);
    }
    #[test]
    fn corrected_noise_and_terminal_proof_are_over_their_caps() {
        let audit = zk_ams_phase23_mask_proof_audit_v1(&release_profile_v1()).unwrap();
        assert_eq!(audit.corrected_switch_residual_bits, 494);
        assert_eq!(audit.corrected_composed_residual_bits, 498);
        assert_eq!(audit.corrected_mapped_residual_bits, 790);
        assert_eq!(audit.corrected_linear_residual_bits, 1_065);
        assert_eq!(audit.corrected_cross_residual_bits, 1_875);
        assert_eq!(audit.corrected_equation_six_residual_bits, 1_877);
        assert_eq!(audit.corrected_level_one_residual_bits, 2_153);
        assert_eq!(audit.corrected_decryption_smudge_quotient_bits, 2_027);
        assert_eq!(audit.corrected_final_residual_bits, 2_287);
        assert_eq!(audit.centered_capacity_bits, 2_279);
        assert!(!audit.corrected_global_noise_fits);
        assert_eq!(audit.corrected_terminal_proof_bytes, 35_913_783);
        assert_eq!(audit.governed_proof_ceiling_bytes, 33_554_432);
        assert!(!audit.corrected_terminal_proof_fits);
    }
    #[test]
    fn missing_cross_commitment_and_padding_bindings_keep_release_closed() {
        let audit = zk_ams_phase23_mask_proof_audit_v1(&release_profile_v1()).unwrap();
        assert!(!audit.hyrax_bgv_equality_certified);
        assert!(!audit.partial_padding_certified);
        assert_eq!(audit.blocker_mask, 0b1111);
        assert!(!audit.release_available);
        assert_ne!(audit.digest, [0; 32]);
        let mut forged = audit;
        forged.hyrax_bgv_equality_certified = true;
        assert_ne!(audit_digest(forged), audit.digest);
        forged = audit;
        forged.release_available = true;
        assert_ne!(audit_digest(forged), audit.digest);
        forged = audit;
        forged.blocker_mask ^= BLOCKER_HYRAX_EQUALITY_V1;
        assert_ne!(audit_digest(forged), audit.digest);
    }
    #[test]
    fn every_operational_path_fails_closed_before_decoding() {
        let profile = release_profile_v1();
        assert_eq!(
            preflight_zk_ams_phase23_mask_proof_v1(&profile),
            Err(ZkAmsMkheErrorV1::ReleaseUnavailable)
        );
        for encoded in [&[][..], &b"ZAMP"[..], &b"ZAPR trailing bytes"[..]] {
            assert!(matches!(
                decode_zk_ams_phase23_mask_manifest_v1(&profile, encoded),
                Err(ZkAmsMkheErrorV1::ReleaseUnavailable)
            ));
            assert!(matches!(
                decode_zk_ams_phase23_mask_record_v1(&profile, encoded),
                Err(ZkAmsMkheErrorV1::ReleaseUnavailable)
            ));
        }
    }
    fn reconstruct_sigma_fixed<const N: usize>(independent: &[i64]) -> Option<Vec<i64>> {
        if N < 2 || !N.is_power_of_two() || independent.len() != N / 2 {
            return None;
        }
        let mut polynomial = vec![0_i64; N];
        polynomial[0] = independent[0];
        for index in 1..N / 2 {
            polynomial[index] = independent[index];
            polynomial[N - index] = -independent[index];
        }
        Some(polynomial)
    }
    fn fixed_challenge(degree: usize, exponent: i64) -> Vec<i64> {
        add(&monomial(degree, exponent), &monomial(degree, -exponent))
    }
    fn geometric_sum(degree: usize, exponent: i64) -> Vec<i64> {
        let divisor = gcd(exponent.unsigned_abs() as usize, degree);
        let length = degree / divisor;
        let mut sum = vec![0_i64; degree];
        for index in 0..length {
            sum = add(&sum, &monomial(degree, exponent * index as i64));
        }
        sum
    }
    fn sigma(polynomial: &[i64]) -> Vec<i64> {
        let mut result = vec![0_i64; polynomial.len()];
        for (exponent, coefficient) in polynomial.iter().copied().enumerate() {
            let inverse = monomial(polynomial.len(), -(exponent as i64));
            for (target, sign) in result.iter_mut().zip(inverse) {
                *target += coefficient * sign;
            }
        }
        result
    }
    fn monomial(degree: usize, exponent: i64) -> Vec<i64> {
        let period = (2 * degree) as i64;
        let reduced = exponent.rem_euclid(period) as usize;
        let mut polynomial = vec![0_i64; degree];
        if reduced < degree {
            polynomial[reduced] = 1;
        } else {
            polynomial[reduced - degree] = -1;
        }
        polynomial
    }
    fn add(lhs: &[i64], rhs: &[i64]) -> Vec<i64> {
        lhs.iter().zip(rhs).map(|(lhs, rhs)| lhs + rhs).collect()
    }
    fn subtract(lhs: &[i64], rhs: &[i64]) -> Vec<i64> {
        lhs.iter().zip(rhs).map(|(lhs, rhs)| lhs - rhs).collect()
    }
    fn multiply(lhs: &[i64], rhs: &[i64]) -> Vec<i64> {
        let degree = lhs.len();
        assert_eq!(rhs.len(), degree);
        let mut product = vec![0_i64; degree];
        for (lhs_index, lhs_coefficient) in lhs.iter().copied().enumerate() {
            for (rhs_index, rhs_coefficient) in rhs.iter().copied().enumerate() {
                let exponent = lhs_index + rhs_index;
                let coefficient = lhs_coefficient * rhs_coefficient;
                if exponent < degree {
                    product[exponent] += coefficient;
                } else {
                    product[exponent - degree] -= coefficient;
                }
            }
        }
        product
    }
    fn gcd(mut lhs: usize, mut rhs: usize) -> usize {
        while rhs != 0 {
            let remainder = lhs % rhs;
            lhs = rhs;
            rhs = remainder;
        }
        lhs
    }
}
