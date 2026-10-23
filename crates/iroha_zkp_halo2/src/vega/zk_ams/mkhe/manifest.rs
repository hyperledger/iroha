//! Frozen ZK-AMS MKHE release parameters and fail-closed readiness gates.
use super::{
    BgvProfile, PlaintextModulus, ZkAmsMkheErrorV1,
    active_exact_binding::exact_binding_release_state_v1,
    decryption::zk_ams_mkhe_decryption_resource_evidence_v1,
    modulus_product_bit_len,
    noise::{ZkAmsMkheNoiseCertificateV1, derive_noise_certificate_v1},
    packing::zk_ams_t256_release_packing_certificate_v1,
    phase23::{
        zk_ams_phase23_equation_certificate_digest_v1, zk_ams_phase23_equation_certificate_v1,
    },
    receipt_capability_audit::zk_ams_mkhe_receipt_capability_audit_v1,
    release_evidence::{
        ZkAmsMkheReleaseKatEvidenceV1, ZkAmsMkheResourceEvidenceV1, ZkAmsMkheWireEvidenceV1,
        frozen_release_kat_evidence_v1, frozen_resource_evidence_v1, frozen_wire_evidence_v1,
    },
    resource::{ZkAmsMkheResourceCertificateV1, derive_resource_certificate_v1},
    rns_native_profile::{
        ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1, ZK_AMS_MKHE_RNS_NATIVE_NEGACYCLIC_ROOTS_V1,
    },
    security::{
        ZkAmsMkheSecurityCandidateV1, ZkAmsMkheSecurityCertificateV1, derive_security_candidate_v1,
        frozen_security_certificate_v1, security_candidate_input_digest_v1,
    },
};
/// Frozen power-of-two cyclotomic degree of the collective-ingress candidate.
pub const ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1: usize = 131_072;
/// Exact number of T256 base-field values packed through conjugate `Fp2` slots.
pub const ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1: usize = 65_536;
/// Fixed governed roster size; this is not an on-the-fly MKHE key union.
pub const ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1: usize = 8;
/// Target classical security strength for activation.
pub const ZK_AMS_MKHE_TARGET_SECURITY_BITS_V1: u16 = 128;
/// Statistical hiding strength for CKS and final-share smudging.
pub const ZK_AMS_MKHE_STATISTICAL_SECURITY_BITS_V1: u16 = 128;
/// Exact bit length of the full 38-prime ciphertext modulus product.
pub const ZK_AMS_MKHE_CIPHERTEXT_MODULUS_BITS_V1: u16 = 2_280;
/// Conservative upper bound on the final centered decryption residual.
pub const ZK_AMS_MKHE_FINAL_DECRYPTION_BOUND_BITS_V1: u16 = 2_115;
/// Strict headroom between the symbolic final bound and `Q/2`.
pub const ZK_AMS_MKHE_CORRECTNESS_MARGIN_BITS_V1: u16 = 164;
/// Maximum possible nonzero count of one compiled sparse R1CS row.
pub const ZK_AMS_MKHE_SPARSE_MAP_FAN_IN_CEILING_V1: usize = 524_378;
const RELEASE_PROFILE_ID_V1: [u8; 32] = [
    0x26, 0x07, 0xf2, 0x03, 0x92, 0x5d, 0x98, 0xf4, 0xfb, 0xed, 0x1d, 0x27, 0xbb, 0xef, 0x1b, 0x09,
    0x56, 0xb2, 0x01, 0x67, 0xf3, 0x02, 0x16, 0x3b, 0x2b, 0x14, 0x31, 0x3f, 0x7d, 0x48, 0x9f, 0xd5,
];
pub(super) const RELEASE_MODULI_V1: [u64; 38] = {
    // The prior release geometry remains unavailable to native40 publication.
    // Its ordered values are sourced from the single governed full chain.
    let mut values = [0; 38];
    let mut index = 0;
    while index < values.len() {
        values[index] = ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1[index];
        index += 1;
    }
    values
};
pub(super) const RELEASE_NEGACYCLIC_ROOTS_V1: [u64; 38] = {
    // The prior release geometry remains unavailable to native40 publication.
    // Its ordered values are sourced from the single governed full chain.
    let mut values = [0; 38];
    let mut index = 0;
    while index < values.len() {
        values[index] = ZK_AMS_MKHE_RNS_NATIVE_NEGACYCLIC_ROOTS_V1[index];
        index += 1;
    }
    values
};
/// Frozen, consensus-digestible MKHE release manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsMkheReleaseManifestV1 {
    /// Manifest schema version.
    pub version: u8,
    /// Exact native parameter identifier.
    pub profile_id: [u8; 32],
    /// Power-of-two cyclotomic degree.
    pub ring_degree: u32,
    /// Number of conjugate-pair T256 slots.
    pub slot_count: u32,
    /// Fixed governed roster size.
    pub roster_size: u8,
    /// Digest of the explicit collective-ingress-hybrid semantics.
    pub construction_digest: [u8; 32],
    /// Number of frozen RNS primes.
    pub rns_limb_count: u8,
    /// Bit width of the product of all RNS primes.
    pub ciphertext_modulus_bits: u16,
    /// Centered bit ceiling for each streamed hybrid RNS digit.
    pub hybrid_digit_bits: u8,
    /// Exact number of streamed hybrid digits.
    pub hybrid_digit_count: u8,
    /// Centered-binomial parameter used only by actual RLWE/key sampling.
    pub error_eta: u8,
    /// Exact minimum coefficient sampled by actual RLWE/key errors.
    pub sampled_rlwe_error_min: i16,
    /// Exact maximum coefficient sampled by actual RLWE/key errors.
    pub sampled_rlwe_error_max: i16,
    /// Maximum absolute coefficient sampled by actual RLWE/key errors.
    pub sampled_rlwe_error_max_abs: u8,
    /// Strict power-of-two magnitude bound for sampled RLWE/key errors.
    pub sampled_rlwe_error_bound_bits: u8,
    /// Exact asymmetric minimum of canonical-natural-lift proof witness `e0'`.
    pub natural_lift_effective_error_min: i16,
    /// Exact asymmetric maximum of canonical-natural-lift proof witness `e0'`.
    pub natural_lift_effective_error_max: i16,
    /// Symmetric verifier maximum absolute value admitted for `e0'`.
    pub natural_lift_effective_error_verifier_max_abs: u8,
    /// Strict power-of-two magnitude bound for verifier-admitted `e0'`.
    pub natural_lift_effective_error_bound_bits: u8,
    /// Minimum natural-to-centered upper-half correction bit.
    pub natural_lift_upper_half_correction_min: u8,
    /// Maximum natural-to-centered upper-half correction bit.
    pub natural_lift_upper_half_correction_max: u8,
    /// Claimed target classical security strength.
    pub target_security_bits: u16,
    /// Statistical CKS/share-hiding strength.
    pub statistical_security_bits: u16,
    /// Independently certified classical security strength; zero means absent.
    pub certified_security_bits: u16,
    /// Maximum RLWE samples admitted under one secret and governed epoch.
    pub max_samples_per_secret_epoch: u64,
    /// Symbolic final centered decryption residual in bits.
    pub final_decryption_bound_bits: u16,
    /// Strict remaining correctness headroom in bits.
    pub correctness_margin_bits: u16,
    /// Per-ciphertext canonical byte ceiling.
    pub max_ciphertext_bytes: u64,
    /// Per-evaluated-key canonical byte ceiling.
    pub max_evaluated_key_bytes: u64,
    /// Per-round canonical byte ceiling.
    pub max_round_bytes: u64,
    /// Per-decryption-share canonical byte ceiling.
    pub max_share_bytes: u64,
    /// Per-operation canonical workspace ceiling.
    pub max_workspace_bytes: u64,
    /// Per-operation abstract work-unit ceiling.
    pub max_work_units: u64,
    /// Reproducible estimator certificate digest; zero means absent.
    pub security_certificate_digest: [u8; 32],
    /// Digest of the exact estimator inputs; this is not a security result.
    pub security_candidate_input_digest: [u8; 32],
    /// Digest of exact static resource accounting; this is not runtime evidence.
    pub resource_certificate_digest: [u8; 32],
    /// Digest of measured proof-size, transport, work, and peak-memory evidence.
    pub resource_validation_evidence_digest: [u8; 32],
    /// Digest of canonical positive/adversarial coverage for every MKHE codec.
    pub wire_evidence_digest: [u8; 32],
    /// Digest of the exact release-degree positive and adversarial packing KAT.
    pub packing_certificate_digest: [u8; 32],
    /// Digest of Equations (6)--(11), finalization semantics, and closure bits.
    pub phase23_equation_certificate_digest: [u8; 32],
    /// Digest of the exact small-witness active-binding audit and blocker set.
    pub active_exact_binding_audit_digest: [u8; 32],
    /// Digest of the exact split-decryption resource and transport evidence.
    pub decryption_resource_evidence_digest: [u8; 32],
    /// Digest of the exact verified-receipt capability graph and open handoffs.
    pub receipt_capability_audit_digest: [u8; 32],
    /// Exact open verified-receipt handoff bit set.
    pub receipt_capability_blocker_mask: u16,
    /// True only when every mandatory verified-receipt handoff closes together.
    pub receipt_capability_release_available: bool,
    /// Release-size execution KAT digest; zero means absent.
    pub release_kat_digest: [u8; 32],
    /// Digest of the versioned release-KAT evidence record, including absence.
    pub release_kat_evidence_digest: [u8; 32],
}
/// Native readiness result. Every field is bound by the readiness digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsMkheReadinessV1 {
    /// Frozen profile validates natively.
    pub parameter_gate: bool,
    /// A reproducible 128-bit RLWE estimator certificate is pinned and verified.
    pub security_gate: bool,
    /// The symbolic correctness/noise schedule validates with strict headroom.
    pub noise_gate: bool,
    /// Release-size byte/work/peak-memory evidence fits every Taira ceiling.
    pub resource_gate: bool,
    /// Canonical wire/pre-decode coverage is complete.
    pub wire_gate: bool,
    /// Governed roster and contribution well-formedness checks are complete.
    pub malicious_party_gate: bool,
    /// Full-set authenticated partial decryption and share PoK are complete.
    pub decryption_share_gate: bool,
    /// Exact T256 `Fp2` packing, padding, and rotations are complete.
    pub packing_gate: bool,
    /// Sparse A/B/C and Phase II/III orchestration are complete.
    pub phase23_gate: bool,
    /// Every operational path consumes the required opaque verified receipts.
    pub receipt_capability_gate: bool,
    /// Exact open verified-receipt handoff bit set; readiness requires zero.
    pub receipt_capability_blocker_mask: u16,
    /// A full release-parameter KAT completed and matches its governed digest.
    pub release_kat_gate: bool,
}
impl ZkAmsMkheReadinessV1 {
    /// Return true only when every release obligation is closed.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        self.parameter_gate
            && self.security_gate
            && self.noise_gate
            && self.resource_gate
            && self.wire_gate
            && self.malicious_party_gate
            && self.decryption_share_gate
            && self.packing_gate
            && self.phase23_gate
            && self.receipt_capability_gate
            && self.receipt_capability_blocker_mask == 0
            && self.release_kat_gate
    }
}
pub(super) fn release_profile_v1() -> BgvProfile {
    BgvProfile {
        profile_id: RELEASE_PROFILE_ID_V1,
        ring_degree: ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1,
        moduli: &RELEASE_MODULI_V1,
        negacyclic_roots: &RELEASE_NEGACYCLIC_ROOTS_V1,
        plaintext_modulus: PlaintextModulus::T256,
        error_eta: 2,
        hybrid_rns_decomposition: true,
        gadget_base_log: 60,
        gadget_digits: RELEASE_MODULI_V1.len(),
        max_ciphertext_bytes: 96 * 1024 * 1024,
        max_evaluated_key_bytes: 2 * 1024 * 1024 * 1024,
        max_round_bytes: 64 * 1024 * 1024,
        max_share_bytes: 64 * 1024 * 1024,
        max_workspace_bytes: 160 * 1024 * 1024,
        max_work_units: 100_000_000_000,
    }
}
const COLLECTIVE_INGRESS_CONSTRUCTION_V1: &[u8] = b"iroha.zk-ams.v1.collective-ingress-hybrid:not-cdks19:on-entry-independent-owner-key:fixed-roster-sum-secret:proof-bound-cks:collective-s2-rkg:all-roster-decryption:transparent-seeded-a:sampled-cbd-error:canonical-natural-lift-effective-error";
fn collective_ingress_construction_digest_v1(noise: ZkAmsMkheNoiseCertificateV1) -> [u8; 32] {
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Parameter,
        COLLECTIVE_INGRESS_CONSTRUCTION_V1,
        6,
    );
    hash.push_field(&noise.sampled_rlwe_error_min.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&noise.sampled_rlwe_error_max.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[
        noise.sampled_rlwe_error_max_abs,
        noise.sampled_rlwe_error_bound_bits,
    ])
    .expect("fixed bounded MKHE identity field");
    hash.push_field(&noise.natural_lift_effective_error_min.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&noise.natural_lift_effective_error_max.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[
        noise.natural_lift_effective_error_verifier_max_abs,
        noise.natural_lift_effective_error_bound_bits,
        noise.natural_lift_upper_half_correction_min,
        noise.natural_lift_upper_half_correction_max,
    ])
    .expect("fixed bounded MKHE identity field");
    *hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes()
}
/// Return the machine-checked conservative Phase-II/III noise certificate.
pub fn zk_ams_mkhe_noise_certificate_v1() -> Result<ZkAmsMkheNoiseCertificateV1, ZkAmsMkheErrorV1> {
    derive_noise_certificate_v1(
        ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1,
        ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1,
        RELEASE_MODULI_V1.len(),
        ZK_AMS_MKHE_SPARSE_MAP_FAN_IN_CEILING_V1,
        8,
        usize::from(ZK_AMS_MKHE_CIPHERTEXT_MODULUS_BITS_V1),
        ZK_AMS_MKHE_STATISTICAL_SECURITY_BITS_V1,
        release_profile_v1().error_eta,
    )
}
/// Return exact static byte/work accounting and explicit open evidence bits.
pub fn zk_ams_mkhe_resource_certificate_v1()
-> Result<ZkAmsMkheResourceCertificateV1, ZkAmsMkheErrorV1> {
    derive_resource_certificate_v1(&release_profile_v1(), ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1)
}
/// Return the consensus digest of exact resource accounting and evidence state.
pub fn zk_ams_mkhe_resource_certificate_digest_v1() -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let profile = release_profile_v1();
    let certificate = zk_ams_mkhe_resource_certificate_v1()?;
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Release,
        b"iroha.zk-ams.v1.mkhe.resource-certificate",
        21,
    );
    hash.push_field(&profile.resource_policy_digest()?)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.governed_roster_wire_bytes.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.ring_degree.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[
        certificate.rns_limb_count,
        certificate.max_composed_rotation_key_switch_count,
        certificate.collective_evaluated_key_count,
    ])
    .expect("fixed bounded MKHE identity field");
    for value in [
        certificate.rns_polynomial_wire_bytes,
        certificate.compact_collective_ciphertext_wire_bytes,
        certificate.multiplication_triple_wire_bytes,
        certificate.seeded_collective_relinearization_key_wire_bytes,
        certificate.total_collective_evaluated_key_artifact_bytes,
        certificate.streamed_contribution_base_wire_bytes,
        certificate.proof_envelope_header_wire_bytes,
        certificate.max_round_contribution_proof_bytes,
        certificate.max_decryption_share_proof_bytes,
        certificate.streamed_hybrid_workspace_bytes,
        certificate.ring_multiplication_work_units,
        certificate.hybrid_key_switch_decomposition_work_units,
        certificate.hybrid_key_switch_ntt_work_units,
        certificate.hybrid_key_switch_accumulator_work_units,
        certificate.hybrid_key_switch_work_units,
        certificate.max_composed_rotation_work_units,
    ] {
        hash.push_field(&value.to_be_bytes())
            .expect("fixed bounded MKHE identity field");
    }
    hash.push_field(&[
        certificate.ciphertext_ceiling_met.into(),
        certificate.per_evaluated_key_ceiling_met.into(),
        certificate.workspace_ceiling_met.into(),
        certificate.composed_rotation_work_ceiling_met.into(),
        certificate.contribution_proof_sizes_certified.into(),
        certificate
            .evaluated_key_artifact_transport_certified
            .into(),
        certificate.phase23_work_measured.into(),
        certificate.release_peak_memory_measured.into(),
    ])
    .expect("fixed bounded MKHE identity field");
    Ok(*hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes())
}
/// Return canonical coverage evidence for the complete MKHE wire surface.
///
/// The frozen record is structurally valid but incomplete until governed
/// positive and adversarial fixture artifacts are installed together.
pub fn zk_ams_mkhe_wire_evidence_v1() -> Result<ZkAmsMkheWireEvidenceV1, ZkAmsMkheErrorV1> {
    frozen_wire_evidence_v1(&release_profile_v1())
}
/// Return canonical measured resource evidence for the release profile.
///
/// Static byte formulas do not populate this record. It closes only when the
/// proof-size, SoraFS transport, Phase-II/III work, and peak-memory artifacts
/// are all digest-bound to the same validator binary.
pub fn zk_ams_mkhe_resource_evidence_v1() -> Result<ZkAmsMkheResourceEvidenceV1, ZkAmsMkheErrorV1> {
    frozen_resource_evidence_v1(&release_profile_v1())
}
/// Return canonical release-size positive/adversarial KAT evidence.
///
/// A nonzero output digest alone is insufficient: fixture, expected and
/// observed output, transcript, rejection counts, size, and validator identity
/// must validate as one record.
pub fn zk_ams_mkhe_release_kat_evidence_v1()
-> Result<ZkAmsMkheReleaseKatEvidenceV1, ZkAmsMkheErrorV1> {
    frozen_release_kat_evidence_v1(&release_profile_v1())
}
/// Return the exact frozen RLWE estimator inputs.
pub fn zk_ams_mkhe_security_candidate_v1() -> Result<ZkAmsMkheSecurityCandidateV1, ZkAmsMkheErrorV1>
{
    derive_security_candidate_v1(&release_profile_v1(), ZK_AMS_MKHE_TARGET_SECURITY_BITS_V1)
}
/// Return the consensus digest of the exact estimator inputs.
///
/// The accepted estimator output is deliberately excluded. It belongs in
/// `security_certificate_digest`, so publishing a result cannot mutate the
/// parameter/input identity that the result certifies.
pub fn zk_ams_mkhe_security_candidate_input_digest_v1() -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let candidate = zk_ams_mkhe_security_candidate_v1()?;
    Ok(security_candidate_input_digest_v1(candidate))
}
/// Return the immutable estimator result for the exact release profile.
///
/// The returned value has no public constructor or mutable result fields. Its
/// private validator checks the exact profile/input digest, estimator and Sage
/// provenance, ordered attack records, minimum cost, and certificate digest.
pub fn zk_ams_mkhe_security_certificate_v1()
-> Result<ZkAmsMkheSecurityCertificateV1, ZkAmsMkheErrorV1> {
    frozen_security_certificate_v1(zk_ams_mkhe_security_candidate_v1()?)
}
/// Return and natively validate the frozen candidate release manifest.
pub fn zk_ams_mkhe_release_manifest_v1() -> Result<ZkAmsMkheReleaseManifestV1, ZkAmsMkheErrorV1> {
    let profile = release_profile_v1();
    profile.validate()?;
    let modulus_bits = u16::try_from(modulus_product_bit_len(profile.moduli)?)
        .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?;
    let noise = zk_ams_mkhe_noise_certificate_v1()?;
    let security = zk_ams_mkhe_security_candidate_v1()?;
    let security_certificate = zk_ams_mkhe_security_certificate_v1()?;
    let wire_evidence = zk_ams_mkhe_wire_evidence_v1()?;
    let resource_evidence = zk_ams_mkhe_resource_evidence_v1()?;
    let release_kat_evidence = zk_ams_mkhe_release_kat_evidence_v1()?;
    let active_exact_binding = exact_binding_release_state_v1(&profile)?;
    let decryption = zk_ams_mkhe_decryption_resource_evidence_v1()?;
    let receipt_capability = zk_ams_mkhe_receipt_capability_audit_v1();
    receipt_capability.validate()?;
    let sampled_eta = i16::from(profile.error_eta);
    if modulus_bits != ZK_AMS_MKHE_CIPHERTEXT_MODULUS_BITS_V1
        || profile.error_eta != 2
        || noise.sampled_rlwe_error_min != -sampled_eta
        || noise.sampled_rlwe_error_max != sampled_eta
        || noise.sampled_rlwe_error_max_abs != profile.error_eta
        || noise.sampled_rlwe_error_bound_bits != 2
        || noise.natural_lift_effective_error_min != -sampled_eta - 1
        || noise.natural_lift_effective_error_max != sampled_eta
        || noise.natural_lift_effective_error_verifier_max_abs != profile.error_eta + 1
        || noise.natural_lift_effective_error_bound_bits != 2
        || noise.natural_lift_upper_half_correction_min != 0
        || noise.natural_lift_upper_half_correction_max != 1
        || noise.final_decryption_residual_bits != ZK_AMS_MKHE_FINAL_DECRYPTION_BOUND_BITS_V1
        || noise.correctness_margin_bits != ZK_AMS_MKHE_CORRECTNESS_MARGIN_BITS_V1
    {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    Ok(ZkAmsMkheReleaseManifestV1 {
        version: 1,
        profile_id: profile.profile_id,
        ring_degree: u32::try_from(profile.ring_degree)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        slot_count: u32::try_from(ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        roster_size: u8::try_from(ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        construction_digest: collective_ingress_construction_digest_v1(noise),
        rns_limb_count: u8::try_from(profile.moduli.len())
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        ciphertext_modulus_bits: modulus_bits,
        hybrid_digit_bits: profile.gadget_base_log,
        hybrid_digit_count: u8::try_from(profile.gadget_digits)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        error_eta: profile.error_eta,
        sampled_rlwe_error_min: noise.sampled_rlwe_error_min,
        sampled_rlwe_error_max: noise.sampled_rlwe_error_max,
        sampled_rlwe_error_max_abs: noise.sampled_rlwe_error_max_abs,
        sampled_rlwe_error_bound_bits: noise.sampled_rlwe_error_bound_bits,
        natural_lift_effective_error_min: noise.natural_lift_effective_error_min,
        natural_lift_effective_error_max: noise.natural_lift_effective_error_max,
        natural_lift_effective_error_verifier_max_abs: noise
            .natural_lift_effective_error_verifier_max_abs,
        natural_lift_effective_error_bound_bits: noise.natural_lift_effective_error_bound_bits,
        natural_lift_upper_half_correction_min: noise.natural_lift_upper_half_correction_min,
        natural_lift_upper_half_correction_max: noise.natural_lift_upper_half_correction_max,
        target_security_bits: ZK_AMS_MKHE_TARGET_SECURITY_BITS_V1,
        statistical_security_bits: ZK_AMS_MKHE_STATISTICAL_SECURITY_BITS_V1,
        certified_security_bits: security_certificate.minimum_security_bits(),
        max_samples_per_secret_epoch: security.max_samples_per_secret_epoch,
        final_decryption_bound_bits: noise.final_decryption_residual_bits,
        correctness_margin_bits: ZK_AMS_MKHE_CORRECTNESS_MARGIN_BITS_V1,
        max_ciphertext_bytes: profile.max_ciphertext_bytes as u64,
        max_evaluated_key_bytes: profile.max_evaluated_key_bytes as u64,
        max_round_bytes: profile.max_round_bytes as u64,
        max_share_bytes: profile.max_share_bytes as u64,
        max_workspace_bytes: profile.max_workspace_bytes as u64,
        max_work_units: profile.max_work_units,
        security_certificate_digest: security_certificate.certificate_digest(),
        security_candidate_input_digest: zk_ams_mkhe_security_candidate_input_digest_v1()?,
        resource_certificate_digest: zk_ams_mkhe_resource_certificate_digest_v1()?,
        resource_validation_evidence_digest: resource_evidence.evidence_digest,
        wire_evidence_digest: wire_evidence.evidence_digest,
        packing_certificate_digest: zk_ams_t256_release_packing_certificate_v1()?.digest,
        phase23_equation_certificate_digest: zk_ams_phase23_equation_certificate_digest_v1(),
        active_exact_binding_audit_digest: active_exact_binding.audit_digest,
        decryption_resource_evidence_digest: decryption.evidence_digest,
        receipt_capability_audit_digest: receipt_capability.digest,
        receipt_capability_blocker_mask: receipt_capability.blocker_mask,
        receipt_capability_release_available: receipt_capability.release_available,
        release_kat_digest: [0; 32],
        release_kat_evidence_digest: release_kat_evidence.evidence_digest,
    })
}
/// Return the consensus digest of the exact release manifest and prime/root chain.
pub fn zk_ams_mkhe_manifest_digest_v1() -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let manifest = zk_ams_mkhe_release_manifest_v1()?;
    Ok(release_manifest_digest_v1(manifest))
}
fn release_manifest_digest_v1(manifest: ZkAmsMkheReleaseManifestV1) -> [u8; 32] {
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Release,
        b"iroha.zk-ams.v1.mkhe.release-manifest",
        41 + 2 * RELEASE_MODULI_V1.len(),
    );
    hash.push_field(&[manifest.version])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.profile_id)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.ring_degree.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.slot_count.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[manifest.roster_size])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.construction_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[manifest.rns_limb_count])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.ciphertext_modulus_bits.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[
        manifest.hybrid_digit_bits,
        manifest.hybrid_digit_count,
        manifest.error_eta,
    ])
    .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.sampled_rlwe_error_min.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.sampled_rlwe_error_max.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[
        manifest.sampled_rlwe_error_max_abs,
        manifest.sampled_rlwe_error_bound_bits,
    ])
    .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.natural_lift_effective_error_min.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.natural_lift_effective_error_max.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[
        manifest.natural_lift_effective_error_verifier_max_abs,
        manifest.natural_lift_effective_error_bound_bits,
        manifest.natural_lift_upper_half_correction_min,
        manifest.natural_lift_upper_half_correction_max,
    ])
    .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.target_security_bits.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.statistical_security_bits.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.certified_security_bits.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.max_samples_per_secret_epoch.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.final_decryption_bound_bits.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.correctness_margin_bits.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    for value in [
        manifest.max_ciphertext_bytes,
        manifest.max_evaluated_key_bytes,
        manifest.max_round_bytes,
        manifest.max_share_bytes,
        manifest.max_workspace_bytes,
        manifest.max_work_units,
    ] {
        hash.push_field(&value.to_be_bytes())
            .expect("fixed bounded MKHE identity field");
    }
    for (&modulus, root) in RELEASE_MODULI_V1.iter().zip(RELEASE_NEGACYCLIC_ROOTS_V1) {
        hash.push_field(&modulus.to_be_bytes())
            .expect("fixed bounded MKHE identity field");
        hash.push_field(&root.to_be_bytes())
            .expect("fixed bounded MKHE identity field");
    }
    hash.push_field(&manifest.security_certificate_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.security_candidate_input_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.resource_certificate_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.resource_validation_evidence_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.wire_evidence_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.packing_certificate_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.phase23_equation_certificate_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.active_exact_binding_audit_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.decryption_resource_evidence_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.receipt_capability_audit_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.receipt_capability_blocker_mask.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[manifest.receipt_capability_release_available.into()])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.release_kat_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&manifest.release_kat_evidence_digest)
        .expect("fixed bounded MKHE identity field");
    *hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes()
}
fn resource_evidence_gate_v1(
    manifest: ZkAmsMkheReleaseManifestV1,
    certificate: ZkAmsMkheResourceCertificateV1,
    evidence: ZkAmsMkheResourceEvidenceV1,
    expected_certificate_digest: [u8; 32],
) -> bool {
    certificate.ciphertext_ceiling_met
        && certificate.per_evaluated_key_ceiling_met
        && certificate.workspace_ceiling_met
        && certificate.composed_rotation_work_ceiling_met
        && evidence.closes_gate(&release_profile_v1(), certificate)
        && manifest.resource_certificate_digest == expected_certificate_digest
        && manifest.resource_validation_evidence_digest == evidence.evidence_digest
}
fn wire_evidence_gate_v1(
    manifest: ZkAmsMkheReleaseManifestV1,
    evidence: ZkAmsMkheWireEvidenceV1,
) -> bool {
    evidence.validate_for_profile(&release_profile_v1()).is_ok()
        && evidence.is_complete()
        && manifest.wire_evidence_digest == evidence.evidence_digest
}
fn release_kat_evidence_gate_v1(
    manifest: ZkAmsMkheReleaseManifestV1,
    evidence: ZkAmsMkheReleaseKatEvidenceV1,
) -> bool {
    evidence.closes_gate(&release_profile_v1())
        && manifest.release_kat_evidence_digest == evidence.evidence_digest
        && manifest.release_kat_digest == evidence.observed_output_digest
}
/// Evaluate every release-readiness gate without silently downgrading.
pub fn zk_ams_mkhe_readiness_v1() -> Result<ZkAmsMkheReadinessV1, ZkAmsMkheErrorV1> {
    let manifest = zk_ams_mkhe_release_manifest_v1()?;
    let noise = zk_ams_mkhe_noise_certificate_v1()?;
    let resource = zk_ams_mkhe_resource_certificate_v1()?;
    let resource_evidence = zk_ams_mkhe_resource_evidence_v1()?;
    let wire_evidence = zk_ams_mkhe_wire_evidence_v1()?;
    let release_kat_evidence = zk_ams_mkhe_release_kat_evidence_v1()?;
    let packing = zk_ams_t256_release_packing_certificate_v1()?;
    let phase23 = zk_ams_phase23_equation_certificate_v1();
    let security = zk_ams_mkhe_security_certificate_v1()?;
    let active_exact_binding = exact_binding_release_state_v1(&release_profile_v1())?;
    let decryption = zk_ams_mkhe_decryption_resource_evidence_v1()?;
    let receipt_capability = zk_ams_mkhe_receipt_capability_audit_v1();
    receipt_capability.validate()?;
    let active_exact_binding_gate = active_exact_binding.release_available
        && active_exact_binding.blocker_mask == 0
        && active_exact_binding.audit_digest != [0; 32];
    let receipt_capability_gate = receipt_capability.release_available
        && receipt_capability.blocker_mask == 0
        && receipt_capability.digest != [0; 32]
        && manifest.receipt_capability_release_available
        && manifest.receipt_capability_blocker_mask == 0
        && manifest.receipt_capability_audit_digest == receipt_capability.digest;
    Ok(ZkAmsMkheReadinessV1 {
        parameter_gate: true,
        security_gate: security.security_parameters_digest()
            == release_profile_v1().security_parameters_digest()?
            && security.candidate_input_digest() == manifest.security_candidate_input_digest
            && security.minimum_security_bits() == manifest.certified_security_bits
            && security.target_security_bits() == manifest.target_security_bits
            && security.certificate_digest() == manifest.security_certificate_digest,
        noise_gate: noise.final_decryption_residual_bits == manifest.final_decryption_bound_bits
            && noise.correctness_margin_bits == manifest.correctness_margin_bits
            && manifest.error_eta == release_profile_v1().error_eta
            && manifest.construction_digest == collective_ingress_construction_digest_v1(noise)
            && manifest.sampled_rlwe_error_min == noise.sampled_rlwe_error_min
            && manifest.sampled_rlwe_error_max == noise.sampled_rlwe_error_max
            && manifest.sampled_rlwe_error_max_abs == noise.sampled_rlwe_error_max_abs
            && manifest.sampled_rlwe_error_bound_bits == noise.sampled_rlwe_error_bound_bits
            && manifest.natural_lift_effective_error_min == noise.natural_lift_effective_error_min
            && manifest.natural_lift_effective_error_max == noise.natural_lift_effective_error_max
            && manifest.natural_lift_effective_error_verifier_max_abs
                == noise.natural_lift_effective_error_verifier_max_abs
            && manifest.natural_lift_effective_error_bound_bits
                == noise.natural_lift_effective_error_bound_bits
            && manifest.natural_lift_upper_half_correction_min
                == noise.natural_lift_upper_half_correction_min
            && manifest.natural_lift_upper_half_correction_max
                == noise.natural_lift_upper_half_correction_max
            && manifest.sampled_rlwe_error_min == -i16::from(manifest.error_eta)
            && manifest.sampled_rlwe_error_max == i16::from(manifest.error_eta)
            && manifest.natural_lift_effective_error_min
                == manifest.sampled_rlwe_error_min
                    - i16::from(manifest.natural_lift_upper_half_correction_max)
            && manifest.natural_lift_effective_error_max
                == manifest.sampled_rlwe_error_max
                    - i16::from(manifest.natural_lift_upper_half_correction_min)
            && manifest.correctness_margin_bits >= 64,
        resource_gate: resource_evidence_gate_v1(
            manifest,
            resource,
            resource_evidence,
            zk_ams_mkhe_resource_certificate_digest_v1()?,
        ),
        wire_gate: wire_evidence_gate_v1(manifest, wire_evidence),
        malicious_party_gate: active_exact_binding_gate
            && active_exact_binding.audit_digest == manifest.active_exact_binding_audit_digest,
        decryption_share_gate: active_exact_binding_gate
            && active_exact_binding.split_decryption_wide_relation_certified
            && decryption.split_transport_ready
            && decryption.evidence_digest == manifest.decryption_resource_evidence_digest,
        packing_gate: packing.profile_digest == release_profile_v1().digest()?
            && packing.ring_degree == manifest.ring_degree
            && packing.slot_count == manifest.slot_count
            && packing.digest == manifest.packing_certificate_digest,
        phase23_gate: phase23.is_complete()
            && manifest.phase23_equation_certificate_digest
                == zk_ams_phase23_equation_certificate_digest_v1(),
        receipt_capability_gate,
        receipt_capability_blocker_mask: receipt_capability.blocker_mask,
        release_kat_gate: release_kat_evidence_gate_v1(manifest, release_kat_evidence),
    })
}
/// Return a consensus digest binding the manifest and every readiness bit.
pub fn zk_ams_mkhe_readiness_digest_v1() -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let readiness = zk_ams_mkhe_readiness_v1()?;
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Release,
        b"iroha.zk-ams.v1.mkhe.release-readiness",
        4,
    );
    hash.push_field(&zk_ams_mkhe_manifest_digest_v1()?)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[
        readiness.parameter_gate.into(),
        readiness.security_gate.into(),
        readiness.noise_gate.into(),
        readiness.resource_gate.into(),
        readiness.wire_gate.into(),
        readiness.malicious_party_gate.into(),
        readiness.decryption_share_gate.into(),
        readiness.packing_gate.into(),
        readiness.phase23_gate.into(),
        readiness.receipt_capability_gate.into(),
    ])
    .expect("fixed bounded MKHE identity field");
    hash.push_field(&readiness.receipt_capability_blocker_mask.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[readiness.release_kat_gate.into()])
        .expect("fixed bounded MKHE identity field");
    Ok(*hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes())
}
pub(in crate::vega::zk_ams) fn require_release_ready_v1() -> Result<(), ZkAmsMkheErrorV1> {
    if !zk_ams_mkhe_readiness_v1()?.is_ready() {
        return Err(ZkAmsMkheErrorV1::ReleaseUnavailable);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn governed_manifest_digests_stream_without_heap_frames() {
        let production = include_str!("manifest.rs")
            .split_once("#[cfg(test)]\nmod tests")
            .expect("production manifest source")
            .0;
        for (start, end) in [
            (
                "fn collective_ingress_construction_digest_v1(",
                "/// Return the machine-checked conservative Phase-II/III noise certificate.",
            ),
            (
                "pub fn zk_ams_mkhe_resource_certificate_digest_v1(",
                "/// Return the exact frozen RLWE estimator inputs.",
            ),
            (
                "fn release_manifest_digest_v1(",
                "/// Evaluate every release-readiness gate without silently downgrading.",
            ),
            (
                "pub fn zk_ams_mkhe_readiness_digest_v1(",
                "pub(in crate::vega::zk_ams) fn require_release_ready_v1(",
            ),
        ] {
            let digest = production
                .split_once(start)
                .expect("digest helper")
                .1
                .split_once(end)
                .expect("digest helper boundary")
                .0;
            assert!(digest.contains("let mut hash = super::native_outer_identity_v1("));
            assert!(digest.contains("hash.push_field("));
            assert!(digest.contains(".finish()"));
            assert!(digest.contains("exact MKHE outer identity field count"));
            assert!(!digest.contains("Keccak256"));
            for forbidden in ["Vec::", "with_capacity", "keccak256("] {
                assert!(!digest.contains(forbidden), "found {forbidden} in {start}");
            }
        }
    }
    #[test]
    fn manifest_distinguishes_sampled_eta_two_from_natural_lift_effective_error() {
        let noise = zk_ams_mkhe_noise_certificate_v1().unwrap();
        let manifest = zk_ams_mkhe_release_manifest_v1().unwrap();
        assert_eq!(manifest.error_eta, 2);
        assert_eq!(manifest.sampled_rlwe_error_min, -2);
        assert_eq!(manifest.sampled_rlwe_error_max, 2);
        assert_eq!(manifest.sampled_rlwe_error_max_abs, 2);
        assert_eq!(manifest.sampled_rlwe_error_bound_bits, 2);
        assert_eq!(manifest.natural_lift_effective_error_min, -3);
        assert_eq!(manifest.natural_lift_effective_error_max, 2);
        assert_eq!(manifest.natural_lift_effective_error_verifier_max_abs, 3);
        assert_eq!(manifest.natural_lift_effective_error_bound_bits, 2);
        assert_eq!(manifest.natural_lift_upper_half_correction_min, 0);
        assert_eq!(manifest.natural_lift_upper_half_correction_max, 1);
        assert_eq!(
            manifest.construction_digest,
            collective_ingress_construction_digest_v1(noise)
        );
        assert_eq!(manifest.final_decryption_bound_bits, 2_115);
        assert_eq!(manifest.correctness_margin_bits, 164);
        let readiness = zk_ams_mkhe_readiness_v1().unwrap();
        assert!(readiness.noise_gate);
        assert!(readiness.packing_gate);
    }
    #[test]
    fn construction_and_manifest_digests_bind_every_error_bound_axis() {
        let noise = zk_ams_mkhe_noise_certificate_v1().unwrap();
        let construction_digest = collective_ingress_construction_digest_v1(noise);
        for changed in [
            ZkAmsMkheNoiseCertificateV1 {
                sampled_rlwe_error_min: noise.sampled_rlwe_error_min - 1,
                ..noise
            },
            ZkAmsMkheNoiseCertificateV1 {
                sampled_rlwe_error_max: noise.sampled_rlwe_error_max + 1,
                ..noise
            },
            ZkAmsMkheNoiseCertificateV1 {
                sampled_rlwe_error_max_abs: noise.sampled_rlwe_error_max_abs + 1,
                ..noise
            },
            ZkAmsMkheNoiseCertificateV1 {
                sampled_rlwe_error_bound_bits: noise.sampled_rlwe_error_bound_bits + 1,
                ..noise
            },
            ZkAmsMkheNoiseCertificateV1 {
                natural_lift_effective_error_min: noise.natural_lift_effective_error_min - 1,
                ..noise
            },
            ZkAmsMkheNoiseCertificateV1 {
                natural_lift_effective_error_max: noise.natural_lift_effective_error_max + 1,
                ..noise
            },
            ZkAmsMkheNoiseCertificateV1 {
                natural_lift_effective_error_verifier_max_abs: noise
                    .natural_lift_effective_error_verifier_max_abs
                    + 1,
                ..noise
            },
            ZkAmsMkheNoiseCertificateV1 {
                natural_lift_effective_error_bound_bits: noise
                    .natural_lift_effective_error_bound_bits
                    + 1,
                ..noise
            },
            ZkAmsMkheNoiseCertificateV1 {
                natural_lift_upper_half_correction_min: 1,
                ..noise
            },
            ZkAmsMkheNoiseCertificateV1 {
                natural_lift_upper_half_correction_max: 0,
                ..noise
            },
        ] {
            assert_ne!(
                collective_ingress_construction_digest_v1(changed),
                construction_digest
            );
        }
        let manifest = zk_ams_mkhe_release_manifest_v1().unwrap();
        let manifest_digest = release_manifest_digest_v1(manifest);
        for changed in [
            ZkAmsMkheReleaseManifestV1 {
                error_eta: manifest.error_eta + 1,
                ..manifest
            },
            ZkAmsMkheReleaseManifestV1 {
                sampled_rlwe_error_min: manifest.sampled_rlwe_error_min - 1,
                ..manifest
            },
            ZkAmsMkheReleaseManifestV1 {
                sampled_rlwe_error_max: manifest.sampled_rlwe_error_max + 1,
                ..manifest
            },
            ZkAmsMkheReleaseManifestV1 {
                sampled_rlwe_error_max_abs: manifest.sampled_rlwe_error_max_abs + 1,
                ..manifest
            },
            ZkAmsMkheReleaseManifestV1 {
                sampled_rlwe_error_bound_bits: manifest.sampled_rlwe_error_bound_bits + 1,
                ..manifest
            },
            ZkAmsMkheReleaseManifestV1 {
                natural_lift_effective_error_min: manifest.natural_lift_effective_error_min - 1,
                ..manifest
            },
            ZkAmsMkheReleaseManifestV1 {
                natural_lift_effective_error_max: manifest.natural_lift_effective_error_max + 1,
                ..manifest
            },
            ZkAmsMkheReleaseManifestV1 {
                natural_lift_effective_error_verifier_max_abs: manifest
                    .natural_lift_effective_error_verifier_max_abs
                    + 1,
                ..manifest
            },
            ZkAmsMkheReleaseManifestV1 {
                natural_lift_effective_error_bound_bits: manifest
                    .natural_lift_effective_error_bound_bits
                    + 1,
                ..manifest
            },
            ZkAmsMkheReleaseManifestV1 {
                natural_lift_upper_half_correction_min: 1,
                ..manifest
            },
            ZkAmsMkheReleaseManifestV1 {
                natural_lift_upper_half_correction_max: 0,
                ..manifest
            },
            ZkAmsMkheReleaseManifestV1 {
                construction_digest: [0; 32],
                ..manifest
            },
            ZkAmsMkheReleaseManifestV1 {
                packing_certificate_digest: [0; 32],
                ..manifest
            },
            ZkAmsMkheReleaseManifestV1 {
                resource_validation_evidence_digest: [0; 32],
                ..manifest
            },
            ZkAmsMkheReleaseManifestV1 {
                wire_evidence_digest: [0; 32],
                ..manifest
            },
            ZkAmsMkheReleaseManifestV1 {
                active_exact_binding_audit_digest: [0; 32],
                ..manifest
            },
            ZkAmsMkheReleaseManifestV1 {
                decryption_resource_evidence_digest: [0; 32],
                ..manifest
            },
            ZkAmsMkheReleaseManifestV1 {
                receipt_capability_audit_digest: [0; 32],
                ..manifest
            },
            ZkAmsMkheReleaseManifestV1 {
                receipt_capability_blocker_mask: 0,
                ..manifest
            },
            ZkAmsMkheReleaseManifestV1 {
                receipt_capability_release_available: true,
                ..manifest
            },
            ZkAmsMkheReleaseManifestV1 {
                release_kat_evidence_digest: [0; 32],
                ..manifest
            },
        ] {
            assert_ne!(release_manifest_digest_v1(changed), manifest_digest);
        }
    }
    #[test]
    fn estimator_input_identity_binds_every_input_class() {
        let candidate = zk_ams_mkhe_security_candidate_v1().expect("security candidate");
        let expected = security_candidate_input_digest_v1(candidate);
        for changed in [
            ZkAmsMkheSecurityCandidateV1 {
                security_parameters_digest: [7; 32],
                ..candidate
            },
            ZkAmsMkheSecurityCandidateV1 {
                ciphertext_modulus_bits: candidate.ciphertext_modulus_bits + 1,
                ..candidate
            },
            ZkAmsMkheSecurityCandidateV1 {
                max_samples_per_secret_epoch: candidate.max_samples_per_secret_epoch + 1,
                ..candidate
            },
            ZkAmsMkheSecurityCandidateV1 {
                target_security_bits: candidate.target_security_bits + 1,
                ..candidate
            },
        ] {
            assert_ne!(security_candidate_input_digest_v1(changed), expected);
        }
    }
    #[test]
    fn exact_estimator_evidence_closes_only_the_security_gate() {
        let certificate = zk_ams_mkhe_security_certificate_v1().expect("security certificate");
        let manifest = zk_ams_mkhe_release_manifest_v1().expect("manifest");
        let readiness = zk_ams_mkhe_readiness_v1().expect("readiness");
        assert_eq!(manifest.certified_security_bits, 172);
        assert_eq!(manifest.target_security_bits, 128);
        assert_eq!(
            manifest.security_candidate_input_digest,
            certificate.candidate_input_digest()
        );
        assert_eq!(
            manifest.security_certificate_digest,
            certificate.certificate_digest()
        );
        assert!(readiness.security_gate);
        assert!(!readiness.is_ready());
        assert_eq!(
            require_release_ready_v1(),
            Err(ZkAmsMkheErrorV1::ReleaseUnavailable)
        );
    }
    #[test]
    fn typed_wire_resource_and_kat_evidence_remain_fail_closed() {
        let manifest = zk_ams_mkhe_release_manifest_v1().expect("release manifest");
        let wire = zk_ams_mkhe_wire_evidence_v1().expect("wire evidence");
        let resource = zk_ams_mkhe_resource_evidence_v1().expect("resource evidence");
        let resource_certificate =
            zk_ams_mkhe_resource_certificate_v1().expect("resource certificate");
        let kat = zk_ams_mkhe_release_kat_evidence_v1().expect("release KAT evidence");

        assert_ne!(wire.evidence_digest, [0; 32]);
        assert_ne!(resource.evidence_digest, [0; 32]);
        assert_ne!(kat.evidence_digest, [0; 32]);
        assert_eq!(manifest.wire_evidence_digest, wire.evidence_digest);
        assert_eq!(
            manifest.resource_validation_evidence_digest,
            resource.evidence_digest
        );
        assert_eq!(manifest.release_kat_evidence_digest, kat.evidence_digest);
        assert!(!wire_evidence_gate_v1(manifest, wire));
        let forged_wire = ZkAmsMkheWireEvidenceV1 {
            covered_codec_count: wire.required_codec_count,
            canonical_case_count: u32::from(wire.required_codec_count),
            adversarial_case_count: u32::from(wire.required_codec_count),
            max_observed_artifact_bytes: 1,
            canonical_fixture_digest: [1; 32],
            adversarial_fixture_digest: [2; 32],
            validator_binary_digest: [3; 32],
            evidence_digest: [4; 32],
            ..wire
        };
        assert!(forged_wire.is_complete());
        assert!(!wire_evidence_gate_v1(
            ZkAmsMkheReleaseManifestV1 {
                wire_evidence_digest: forged_wire.evidence_digest,
                ..manifest
            },
            forged_wire,
        ));
        assert!(!resource_evidence_gate_v1(
            manifest,
            resource_certificate,
            resource,
            zk_ams_mkhe_resource_certificate_digest_v1().unwrap(),
        ));
        assert!(!release_kat_evidence_gate_v1(manifest, kat));

        let nonzero_shortcut = ZkAmsMkheReleaseManifestV1 {
            release_kat_digest: [7; 32],
            ..manifest
        };
        assert!(!release_kat_evidence_gate_v1(nonzero_shortcut, kat));
    }
    #[test]
    fn readiness_derives_active_and_decryption_gates_from_exact_audits() {
        let profile = release_profile_v1();
        let active = exact_binding_release_state_v1(&profile).expect("active exact-binding audit");
        let decryption =
            zk_ams_mkhe_decryption_resource_evidence_v1().expect("decryption resource evidence");
        let readiness = zk_ams_mkhe_readiness_v1().expect("readiness");
        // Bit zero is the still-open external-membership security theorem
        // blocker; only the generator-basis KAT at bit one is green.
        assert_eq!(active.blocker_mask, 0b1111_1101);
        assert_ne!(active.audit_digest, [0; 32]);
        assert!(!active.split_decryption_wide_relation_certified);
        assert!(!active.release_available);
        assert!(!decryption.split_transport_ready);
        assert!(!readiness.malicious_party_gate);
        assert!(!readiness.decryption_share_gate);
    }
    #[test]
    fn receipt_capability_blockers_are_manifest_bound_and_fail_readiness_closed() {
        let audit = zk_ams_mkhe_receipt_capability_audit_v1();
        audit
            .validate()
            .expect("receipt capability audit validates");
        let manifest = zk_ams_mkhe_release_manifest_v1().expect("release manifest");
        let readiness = zk_ams_mkhe_readiness_v1().expect("readiness");
        assert_eq!(audit.blocker_mask, 0xf0);
        assert!(!audit.release_available);
        assert_eq!(manifest.receipt_capability_audit_digest, audit.digest);
        assert_eq!(manifest.receipt_capability_blocker_mask, 0xf0);
        assert!(!manifest.receipt_capability_release_available);
        assert_eq!(readiness.receipt_capability_blocker_mask, 0xf0);
        assert!(!readiness.receipt_capability_gate);
        assert!(!readiness.is_ready());
        assert_eq!(
            require_release_ready_v1(),
            Err(ZkAmsMkheErrorV1::ReleaseUnavailable)
        );
    }
}
