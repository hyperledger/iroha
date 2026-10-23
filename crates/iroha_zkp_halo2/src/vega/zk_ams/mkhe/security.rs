//! Frozen RLWE-estimator evidence for the collective-ingress release profile.
//!
//! Candidate inputs and certified results are deliberately different types.
//! The input descriptor remains caller-constructible because it has no release
//! authority.  The result certificate has private fields, no public
//! constructor, and validates only the byte-pinned evidence for the exact
//! release profile.  Consequently an input object, a copied estimate, or a
//! caller-supplied result cannot close the manifest security gate.
use super::{BgvProfile, ZkAmsMkheErrorV1, modulus_product_bit_len};
const LATTICE_ESTIMATOR_COMMIT_V1: [u8; 20] = [
    0x3e, 0x48, 0xef, 0x42, 0x1e, 0xc2, 0x56, 0xaf, 0xdd, 0xb3, 0xe7, 0xd2, 0x24, 0x9a, 0x77, 0xea,
    0xb6, 0xe9, 0xba, 0x12,
];
const SAGE_BINDER_ENVIRONMENT_COMMIT_V1: [u8; 20] = [
    0xf7, 0x41, 0xd5, 0xd9, 0x48, 0xbb, 0xa2, 0x21, 0x41, 0x5b, 0x07, 0x4e, 0x55, 0x05, 0x5e, 0xdd,
    0x33, 0x71, 0x70, 0xb6,
];
const FROZEN_SECURITY_PARAMETERS_DIGEST_V1: [u8; 32] =
    decode_hex_32(b"6647854418ea19d581808f9d0f362dd8b7de4feb6f592a477583292e2c276e72");
const FROZEN_CANDIDATE_INPUT_DIGEST_V1: [u8; 32] =
    decode_hex_32(b"8070af3c33fd60e92ff387ea6679b362215eb0c50be0b91b6beec42b2e6d58c4");
const SAGE_DMG_SHA256_V1: [u8; 32] =
    decode_hex_32(b"84f78143db3fb7c251f6eea906c6efb7793d26e96a3fbdb2104c1f9bb4b1827e");
const ESTIMATOR_RUNNER_SHA256_V1: [u8; 32] =
    decode_hex_32(b"9d883a0bfeebe7c2ba93c86766286dab0eb0f7d89685059cb2a1ab0566e6eed7");
const ESTIMATOR_TRANSCRIPT_SHA256_V1: [u8; 32] =
    decode_hex_32(b"75ead52dc7589176bd9fe4b809c9507bc771af7abe3a55f40c2396ccc80391fe");
const SECURITY_GUIDELINE_SHA256_V1: [u8; 32] =
    decode_hex_32(b"9c48bdef18f6e459d1d50bd5f250c89c740f87c9b9fbd98d1cd59f0d5c25d32e");
const SECURITY_CERTIFICATE_DIGEST_V1: [u8; 32] =
    decode_hex_32(b"74327a84b64f341bc1b6ee80233f4082598f9dd2f7c48353b69f6e2f5ecf3f75");
const SAGE_VERSION_MAJOR_V1: u16 = 10;
const SAGE_VERSION_MINOR_V1: u16 = 9;
const FROZEN_MINIMUM_SECURITY_BITS_V1: u16 = 172;
const FROZEN_TARGET_SECURITY_BITS_V1: u16 = 128;
const SECURITY_GUIDELINE_IDENTITY_V1: &str = concat!(
    "doi:10.62056/anxra69p1:section-5.1:",
    "primal-usvp+primal-bdd+dual-hybrid:hybrid-bdd-only-through-2^14"
);
const fn decode_hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("frozen digest contains non-lowercase-hex input"),
    }
}
const fn decode_hex_32(hex: &[u8; 64]) -> [u8; 32] {
    let mut output = [0_u8; 32];
    let mut index = 0;
    while index < output.len() {
        output[index] =
            (decode_hex_nibble(hex[index * 2]) << 4) | decode_hex_nibble(hex[index * 2 + 1]);
        index += 1;
    }
    output
}
/// Exact estimator inputs. This descriptor is not a security result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsMkheSecurityCandidateV1 {
    /// Digest of the exact algebraic/distribution parameters certified by the
    /// estimator. Deployment resource ceilings are intentionally excluded.
    pub security_parameters_digest: [u8; 32],
    /// Power-of-two RLWE ring degree.
    pub ring_degree: u32,
    /// Exact bit length of the full RNS modulus product.
    pub ciphertext_modulus_bits: u16,
    /// Operational ceiling on RLWE samples under one long-term secret/epoch.
    pub max_samples_per_secret_epoch: u64,
    /// Numerator of the dense ternary secret variance (`2/3`).
    pub secret_variance_numerator: u8,
    /// Denominator of the dense ternary secret variance (`2/3`).
    pub secret_variance_denominator: u8,
    /// Centered-binomial error parameter; eta two has variance one.
    pub error_centered_binomial_eta: u8,
    /// Requested classical security strength.
    pub target_security_bits: u16,
    /// Pinned upstream `lattice-estimator` revision.
    pub lattice_estimator_commit: [u8; 20],
    /// Pinned Sage/Binder execution-environment revision.
    pub sage_environment_commit: [u8; 20],
}
/// Estimator family that produced one frozen attack record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ZkAmsMkheSecurityEstimatorSuiteV1 {
    /// Upstream conservative `LWE.estimate.rough` model.
    Rough = 1,
    /// HE Security Guidelines section 5.1 attack/model selection.
    Guideline = 2,
}
/// Exact attack identity within one estimator family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ZkAmsMkheSecurityAttackV1 {
    /// Primal unique-SVP attack.
    PrimalUsvp = 1,
    /// Primal bounded-distance-decoding attack.
    PrimalBdd = 2,
    /// Non-hybrid dual attack retained as a dominance regression.
    Dual = 3,
    /// Dual-hybrid attack required by the guidelines.
    DualHybrid = 4,
}
/// One exact, transcript-pinned estimator result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsMkheSecurityAttackRecordV1 {
    suite: ZkAmsMkheSecurityEstimatorSuiteV1,
    attack: ZkAmsMkheSecurityAttackV1,
    rop_log2: &'static str,
    rop_log2_floor: u16,
    result_repr_sha256: [u8; 32],
}
impl ZkAmsMkheSecurityAttackRecordV1 {
    /// Estimator family used for this result.
    #[cfg(test)]
    #[must_use]
    pub const fn suite(self) -> ZkAmsMkheSecurityEstimatorSuiteV1 {
        self.suite
    }
    /// Exact attack identity.
    #[cfg(test)]
    #[must_use]
    pub const fn attack(self) -> ZkAmsMkheSecurityAttackV1 {
        self.attack
    }
    /// Exact 50-digit estimator output for `log2(rop)`.
    #[cfg(test)]
    #[must_use]
    pub const fn rop_log2(self) -> &'static str {
        self.rop_log2
    }
    /// Conservative integral security strength used by admission.
    #[cfg(test)]
    #[must_use]
    pub const fn rop_log2_floor(self) -> u16 {
        self.rop_log2_floor
    }
    /// SHA-256 of the estimator's exact canonical result representation.
    #[cfg(test)]
    #[must_use]
    pub const fn result_repr_sha256(self) -> [u8; 32] {
        self.result_repr_sha256
    }
}
const FROZEN_ATTACKS_V1: [ZkAmsMkheSecurityAttackRecordV1; 6] = [
    ZkAmsMkheSecurityAttackRecordV1 {
        suite: ZkAmsMkheSecurityEstimatorSuiteV1::Rough,
        attack: ZkAmsMkheSecurityAttackV1::PrimalUsvp,
        rop_log2: "172.57200000000000279731978392482254410520999110210",
        rop_log2_floor: 172,
        result_repr_sha256: decode_hex_32(
            b"013e911de66c6b3bc1b2604f0899dcac5bfd32ea022afca2e4316b32487b6ce3",
        ),
    },
    ZkAmsMkheSecurityAttackRecordV1 {
        suite: ZkAmsMkheSecurityEstimatorSuiteV1::Rough,
        attack: ZkAmsMkheSecurityAttackV1::DualHybrid,
        rop_log2: "172.57200000000000279731978392482254410520999110210",
        rop_log2_floor: 172,
        result_repr_sha256: decode_hex_32(
            b"1359c7ae8d90a980e78f268e264640c9ef907ce5b1d8bd4a4843a61836d9a4c7",
        ),
    },
    ZkAmsMkheSecurityAttackRecordV1 {
        suite: ZkAmsMkheSecurityEstimatorSuiteV1::Guideline,
        attack: ZkAmsMkheSecurityAttackV1::PrimalUsvp,
        rop_log2: "204.01634672237682094474650845299994633040168928286",
        rop_log2_floor: 204,
        result_repr_sha256: decode_hex_32(
            b"a7ff7bde951e97b872aa4496d99cd49cab5cc06e463669cbb5ec5634500b5f12",
        ),
    },
    ZkAmsMkheSecurityAttackRecordV1 {
        suite: ZkAmsMkheSecurityEstimatorSuiteV1::Guideline,
        attack: ZkAmsMkheSecurityAttackV1::PrimalBdd,
        rop_log2: "227.93964402855136658440008043812104961906491316109",
        rop_log2_floor: 227,
        result_repr_sha256: decode_hex_32(
            b"7a0c2fc8c3a425547abaecf15f6250a4a7749cfc675d3dd32ff699ebedecec36",
        ),
    },
    ZkAmsMkheSecurityAttackRecordV1 {
        suite: ZkAmsMkheSecurityEstimatorSuiteV1::Guideline,
        attack: ZkAmsMkheSecurityAttackV1::Dual,
        rop_log2: "205.05287975600834972625508498621780649886736164881",
        rop_log2_floor: 205,
        result_repr_sha256: decode_hex_32(
            b"40e996426784d765b902f896b4b13c9f9b77da7f34e701c642eb96c196be4d32",
        ),
    },
    ZkAmsMkheSecurityAttackRecordV1 {
        suite: ZkAmsMkheSecurityEstimatorSuiteV1::Guideline,
        attack: ZkAmsMkheSecurityAttackV1::DualHybrid,
        rop_log2: "205.05248798268494445442270576691637946508081474447",
        rop_log2_floor: 205,
        result_repr_sha256: decode_hex_32(
            b"d974f0225ecf320a6c7b6759f07582ef00cc89c2e8f593c272f329c158868185",
        ),
    },
];
/// Frozen, non-caller-constructible security result for the release profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsMkheSecurityCertificateV1 {
    version: u8,
    security_parameters_digest: [u8; 32],
    candidate_input_digest: [u8; 32],
    lattice_estimator_commit: [u8; 20],
    sage_environment_commit: [u8; 20],
    sage_version_major: u16,
    sage_version_minor: u16,
    sage_machine: &'static str,
    sage_distribution: &'static str,
    sage_dmg_sha256: [u8; 32],
    estimator_runner_sha256: [u8; 32],
    estimator_transcript_sha256: [u8; 32],
    security_guideline_identity: &'static str,
    security_guideline_sha256: [u8; 32],
    attacks: [ZkAmsMkheSecurityAttackRecordV1; 6],
    minimum_security_bits: u16,
    target_security_bits: u16,
    certificate_digest: [u8; 32],
}
impl ZkAmsMkheSecurityCertificateV1 {
    /// Certificate schema version.
    #[cfg(test)]
    #[must_use]
    pub const fn version(self) -> u8 {
        self.version
    }
    /// Exact security-parameter digest certified by the estimator transcript.
    #[must_use]
    pub const fn security_parameters_digest(self) -> [u8; 32] {
        self.security_parameters_digest
    }
    /// Digest of every exact estimator input.
    #[must_use]
    pub const fn candidate_input_digest(self) -> [u8; 32] {
        self.candidate_input_digest
    }
    /// Pinned upstream lattice-estimator revision.
    #[cfg(test)]
    #[must_use]
    pub const fn lattice_estimator_commit(self) -> [u8; 20] {
        self.lattice_estimator_commit
    }
    /// SHA-256 of the verified official SageMath disk image.
    #[cfg(test)]
    #[must_use]
    pub const fn sage_dmg_sha256(self) -> [u8; 32] {
        self.sage_dmg_sha256
    }
    /// SHA-256 of the exact fail-closed estimator runner.
    #[cfg(test)]
    #[must_use]
    pub const fn estimator_runner_sha256(self) -> [u8; 32] {
        self.estimator_runner_sha256
    }
    /// SHA-256 of the canonical estimator transcript.
    #[cfg(test)]
    #[must_use]
    pub const fn estimator_transcript_sha256(self) -> [u8; 32] {
        self.estimator_transcript_sha256
    }
    /// Exact ordered attack results.
    #[cfg(test)]
    #[must_use]
    pub const fn attacks(&self) -> &[ZkAmsMkheSecurityAttackRecordV1; 6] {
        &self.attacks
    }
    /// Minimum floored `log2(rop)` over every required attack result.
    #[must_use]
    pub const fn minimum_security_bits(self) -> u16 {
        self.minimum_security_bits
    }
    /// Required classical security target.
    #[must_use]
    pub const fn target_security_bits(self) -> u16 {
        self.target_security_bits
    }
    /// Consensus digest of every certificate field except this digest itself.
    #[must_use]
    pub const fn certificate_digest(self) -> [u8; 32] {
        self.certificate_digest
    }
    fn validate_for(
        &self,
        candidate: ZkAmsMkheSecurityCandidateV1,
    ) -> Result<(), ZkAmsMkheErrorV1> {
        let minimum = self
            .attacks
            .iter()
            .map(|record| record.rop_log2_floor)
            .min()
            .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
        if *self != FROZEN_SECURITY_CERTIFICATE_V1
            || candidate.security_parameters_digest != FROZEN_SECURITY_PARAMETERS_DIGEST_V1
            || candidate.lattice_estimator_commit != LATTICE_ESTIMATOR_COMMIT_V1
            || candidate.sage_environment_commit != SAGE_BINDER_ENVIRONMENT_COMMIT_V1
            || security_candidate_input_digest_v1(candidate) != FROZEN_CANDIDATE_INPUT_DIGEST_V1
            || self.security_parameters_digest != candidate.security_parameters_digest
            || self.candidate_input_digest != FROZEN_CANDIDATE_INPUT_DIGEST_V1
            || self.sage_version_major != SAGE_VERSION_MAJOR_V1
            || self.sage_version_minor != SAGE_VERSION_MINOR_V1
            || self.sage_machine != "arm64"
            || self.sage_distribution != "SageMath-10.9_arm64.dmg"
            || self.security_guideline_identity != SECURITY_GUIDELINE_IDENTITY_V1
            || self.attacks != FROZEN_ATTACKS_V1
            || minimum != self.minimum_security_bits
            || self.minimum_security_bits < self.target_security_bits
            || self.target_security_bits != candidate.target_security_bits
            || self.certificate_digest == [0; 32]
            || security_certificate_digest_v1(self) != self.certificate_digest
        {
            return Err(ZkAmsMkheErrorV1::InvalidProfile);
        }
        Ok(())
    }
}
const FROZEN_SECURITY_CERTIFICATE_V1: ZkAmsMkheSecurityCertificateV1 =
    ZkAmsMkheSecurityCertificateV1 {
        version: 1,
        security_parameters_digest: FROZEN_SECURITY_PARAMETERS_DIGEST_V1,
        candidate_input_digest: FROZEN_CANDIDATE_INPUT_DIGEST_V1,
        lattice_estimator_commit: LATTICE_ESTIMATOR_COMMIT_V1,
        sage_environment_commit: SAGE_BINDER_ENVIRONMENT_COMMIT_V1,
        sage_version_major: SAGE_VERSION_MAJOR_V1,
        sage_version_minor: SAGE_VERSION_MINOR_V1,
        sage_machine: "arm64",
        sage_distribution: "SageMath-10.9_arm64.dmg",
        sage_dmg_sha256: SAGE_DMG_SHA256_V1,
        estimator_runner_sha256: ESTIMATOR_RUNNER_SHA256_V1,
        estimator_transcript_sha256: ESTIMATOR_TRANSCRIPT_SHA256_V1,
        security_guideline_identity: SECURITY_GUIDELINE_IDENTITY_V1,
        security_guideline_sha256: SECURITY_GUIDELINE_SHA256_V1,
        attacks: FROZEN_ATTACKS_V1,
        minimum_security_bits: FROZEN_MINIMUM_SECURITY_BITS_V1,
        target_security_bits: FROZEN_TARGET_SECURITY_BITS_V1,
        certificate_digest: SECURITY_CERTIFICATE_DIGEST_V1,
    };
pub(super) fn derive_security_candidate_v1(
    profile: &BgvProfile,
    target_security_bits: u16,
) -> Result<ZkAmsMkheSecurityCandidateV1, ZkAmsMkheErrorV1> {
    profile.validate()?;
    if target_security_bits < 128 || profile.error_eta != 2 {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    let ring_degree =
        u32::try_from(profile.ring_degree).map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?;
    let ciphertext_modulus_bits = u16::try_from(modulus_product_bit_len(profile.moduli)?)
        .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?;
    let max_samples_per_secret_epoch = u64::from(ring_degree)
        .checked_mul(512)
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    Ok(ZkAmsMkheSecurityCandidateV1 {
        security_parameters_digest: profile.security_parameters_digest()?,
        ring_degree,
        ciphertext_modulus_bits,
        max_samples_per_secret_epoch,
        secret_variance_numerator: 2,
        secret_variance_denominator: 3,
        error_centered_binomial_eta: profile.error_eta,
        target_security_bits,
        lattice_estimator_commit: LATTICE_ESTIMATOR_COMMIT_V1,
        sage_environment_commit: SAGE_BINDER_ENVIRONMENT_COMMIT_V1,
    })
}
pub(super) fn security_candidate_input_digest_v1(
    candidate: ZkAmsMkheSecurityCandidateV1,
) -> [u8; 32] {
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Release,
        b"iroha.zk-ams.v1.mkhe.security-candidate-input",
        10,
    );
    hash.push_field(&candidate.security_parameters_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&candidate.ring_degree.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&candidate.ciphertext_modulus_bits.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&candidate.max_samples_per_secret_epoch.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[candidate.secret_variance_numerator])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[candidate.secret_variance_denominator])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[candidate.error_centered_binomial_eta])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&candidate.target_security_bits.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&candidate.lattice_estimator_commit)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&candidate.sage_environment_commit)
        .expect("fixed bounded MKHE identity field");
    *hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes()
}
// Native identity pins bind the exact 38-limb input and genuine Sage 10.9
// estimator transcript. They do not certify the separate native40 replacement.
pub(super) fn frozen_security_certificate_v1(
    candidate: ZkAmsMkheSecurityCandidateV1,
) -> Result<ZkAmsMkheSecurityCertificateV1, ZkAmsMkheErrorV1> {
    FROZEN_SECURITY_CERTIFICATE_V1.validate_for(candidate)?;
    Ok(FROZEN_SECURITY_CERTIFICATE_V1)
}
fn security_certificate_digest_v1(certificate: &ZkAmsMkheSecurityCertificateV1) -> [u8; 32] {
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Release,
        b"iroha.zk-ams.v1.mkhe.security-certificate",
        47,
    );
    hash.push_field(&[certificate.version])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.security_parameters_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.candidate_input_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.lattice_estimator_commit)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.sage_environment_commit)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.sage_version_major.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.sage_version_minor.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    for value in [certificate.sage_machine, certificate.sage_distribution] {
        hash.push_field(value.as_bytes())
            .expect("fixed bounded MKHE identity field");
    }
    hash.push_field(&certificate.sage_dmg_sha256)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.estimator_runner_sha256)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.estimator_transcript_sha256)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(certificate.security_guideline_identity.as_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.security_guideline_sha256)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[certificate.attacks.len() as u8])
        .expect("fixed bounded MKHE identity field");
    for record in &certificate.attacks {
        hash.push_field(&[record.suite as u8])
            .expect("fixed bounded MKHE identity field");
        hash.push_field(&[record.attack as u8])
            .expect("fixed bounded MKHE identity field");
        hash.push_field(record.rop_log2.as_bytes())
            .expect("fixed bounded MKHE identity field");
        hash.push_field(&record.rop_log2_floor.to_be_bytes())
            .expect("fixed bounded MKHE identity field");
        hash.push_field(&record.result_repr_sha256)
            .expect("fixed bounded MKHE identity field");
    }
    hash.push_field(&certificate.minimum_security_bits.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.target_security_bits.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    *hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn exact_candidate() -> ZkAmsMkheSecurityCandidateV1 {
        derive_security_candidate_v1(&super::super::manifest::release_profile_v1(), 128)
            .expect("estimator inputs")
    }
    #[test]
    fn security_parameters_and_resource_policy_have_independent_identities() {
        let baseline = super::super::manifest::release_profile_v1();
        let baseline_security = baseline.security_parameters_digest().unwrap();
        let baseline_resources = baseline.resource_policy_digest().unwrap();
        let mut raised_work_ceiling = baseline.clone();
        raised_work_ceiling.max_work_units += 1;
        assert_eq!(
            raised_work_ceiling.security_parameters_digest().unwrap(),
            baseline_security,
            "an operational ceiling must not invalidate RLWE estimator evidence"
        );
        assert_ne!(
            raised_work_ceiling.resource_policy_digest().unwrap(),
            baseline_resources
        );
        assert_ne!(
            raised_work_ceiling.digest().unwrap(),
            baseline.digest().unwrap()
        );
        let mut changed_distribution = baseline;
        changed_distribution.error_eta = 3;
        assert_ne!(
            changed_distribution.security_parameters_digest().unwrap(),
            baseline_security
        );
        assert_eq!(
            changed_distribution.resource_policy_digest().unwrap(),
            baseline_resources
        );
    }
    #[test]
    fn frozen_estimator_inputs_bind_the_exact_profile_and_have_no_result_surface() {
        let candidate = exact_candidate();
        assert_eq!(
            candidate.security_parameters_digest,
            FROZEN_SECURITY_PARAMETERS_DIGEST_V1
        );
        assert_eq!(candidate.ring_degree, 131_072);
        assert_eq!(candidate.ciphertext_modulus_bits, 2_280);
        assert_eq!(candidate.max_samples_per_secret_epoch, 67_108_864);
        assert_eq!(candidate.secret_variance_numerator, 2);
        assert_eq!(candidate.secret_variance_denominator, 3);
        assert_eq!(candidate.error_centered_binomial_eta, 2);
        assert_eq!(candidate.target_security_bits, 128);
        assert_eq!(
            candidate.lattice_estimator_commit,
            LATTICE_ESTIMATOR_COMMIT_V1
        );
        assert_eq!(
            candidate.sage_environment_commit,
            SAGE_BINDER_ENVIRONMENT_COMMIT_V1
        );
        assert_eq!(
            security_candidate_input_digest_v1(candidate),
            FROZEN_CANDIDATE_INPUT_DIGEST_V1
        );
    }
    #[test]
    fn estimator_input_downgrades_and_same_q_bit_profile_splices_fail_closed() {
        let profile = super::super::manifest::release_profile_v1();
        assert_eq!(
            derive_security_candidate_v1(&profile, 127),
            Err(ZkAmsMkheErrorV1::InvalidProfile)
        );
        let mut wrong_error = profile;
        wrong_error.error_eta = 3;
        assert_eq!(
            derive_security_candidate_v1(&wrong_error, 128),
            Err(ZkAmsMkheErrorV1::InvalidProfile)
        );
        let candidate = exact_candidate();
        let expected = security_candidate_input_digest_v1(candidate);
        let mutations = [
            ZkAmsMkheSecurityCandidateV1 {
                security_parameters_digest: [9; 32],
                ..candidate
            },
            ZkAmsMkheSecurityCandidateV1 {
                ring_degree: candidate.ring_degree + 1,
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
                secret_variance_numerator: 1,
                ..candidate
            },
            ZkAmsMkheSecurityCandidateV1 {
                secret_variance_denominator: 4,
                ..candidate
            },
            ZkAmsMkheSecurityCandidateV1 {
                error_centered_binomial_eta: 3,
                ..candidate
            },
            ZkAmsMkheSecurityCandidateV1 {
                target_security_bits: candidate.target_security_bits + 1,
                ..candidate
            },
            ZkAmsMkheSecurityCandidateV1 {
                lattice_estimator_commit: [1; 20],
                ..candidate
            },
            ZkAmsMkheSecurityCandidateV1 {
                sage_environment_commit: [2; 20],
                ..candidate
            },
        ];
        for mutation in mutations {
            assert_ne!(security_candidate_input_digest_v1(mutation), expected);
            assert_eq!(
                frozen_security_certificate_v1(mutation),
                Err(ZkAmsMkheErrorV1::InvalidProfile)
            );
        }
    }
    #[test]
    fn frozen_certificate_binds_exact_environment_attacks_and_minimum() {
        let certificate = frozen_security_certificate_v1(exact_candidate()).expect("certificate");
        assert_eq!(certificate.version(), 1);
        assert_eq!(
            certificate.security_parameters_digest(),
            FROZEN_SECURITY_PARAMETERS_DIGEST_V1
        );
        assert_eq!(
            certificate.candidate_input_digest(),
            FROZEN_CANDIDATE_INPUT_DIGEST_V1
        );
        assert_eq!(certificate.minimum_security_bits(), 172);
        assert_eq!(certificate.target_security_bits(), 128);
        assert_eq!(certificate.attacks(), &FROZEN_ATTACKS_V1);
        assert_eq!(certificate.sage_dmg_sha256(), SAGE_DMG_SHA256_V1);
        assert_eq!(
            certificate.estimator_runner_sha256(),
            ESTIMATOR_RUNNER_SHA256_V1
        );
        assert_eq!(
            certificate.estimator_transcript_sha256(),
            ESTIMATOR_TRANSCRIPT_SHA256_V1
        );
        assert_eq!(
            certificate.certificate_digest(),
            security_certificate_digest_v1(&certificate)
        );
    }
    #[test]
    fn every_certificate_evidence_class_is_immutable_and_fail_closed() {
        let candidate = exact_candidate();
        let baseline = FROZEN_SECURITY_CERTIFICATE_V1;
        let mut mutations = Vec::new();
        macro_rules! mutate {
            ($field:ident, $value:expr) => {{
                let mut changed = baseline;
                changed.$field = $value;
                mutations.push(changed);
            }};
        }
        mutate!(version, 2);
        mutate!(security_parameters_digest, [1; 32]);
        mutate!(candidate_input_digest, [2; 32]);
        mutate!(lattice_estimator_commit, [3; 20]);
        mutate!(sage_environment_commit, [4; 20]);
        mutate!(sage_version_major, 11);
        mutate!(sage_version_minor, 8);
        mutate!(sage_machine, "x86_64");
        mutate!(sage_distribution, "unverified.dmg");
        mutate!(sage_dmg_sha256, [5; 32]);
        mutate!(estimator_runner_sha256, [6; 32]);
        mutate!(estimator_transcript_sha256, [7; 32]);
        mutate!(security_guideline_identity, "wrong-guideline");
        mutate!(security_guideline_sha256, [8; 32]);
        mutate!(minimum_security_bits, 171);
        mutate!(target_security_bits, 127);
        mutate!(certificate_digest, [9; 32]);
        for mutation in mutations {
            assert_eq!(
                mutation.validate_for(candidate),
                Err(ZkAmsMkheErrorV1::InvalidProfile)
            );
        }
    }
    #[test]
    fn attack_reorder_duplicate_downgrade_and_record_mutations_fail_closed() {
        let candidate = exact_candidate();
        let baseline = FROZEN_SECURITY_CERTIFICATE_V1;
        let mut mutations = Vec::new();
        let mut reordered = baseline;
        reordered.attacks.swap(0, 1);
        mutations.push(reordered);
        let mut duplicate = baseline;
        duplicate.attacks[1] = duplicate.attacks[0];
        mutations.push(duplicate);
        let mut suite = baseline;
        suite.attacks[0].suite = ZkAmsMkheSecurityEstimatorSuiteV1::Guideline;
        mutations.push(suite);
        let mut attack = baseline;
        attack.attacks[0].attack = ZkAmsMkheSecurityAttackV1::PrimalBdd;
        mutations.push(attack);
        let mut exact_value = baseline;
        exact_value.attacks[0].rop_log2 = "172.572";
        mutations.push(exact_value);
        let mut floor = baseline;
        floor.attacks[0].rop_log2_floor = 127;
        mutations.push(floor);
        let mut representation = baseline;
        representation.attacks[0].result_repr_sha256[0] ^= 1;
        mutations.push(representation);
        for mutation in mutations {
            assert_eq!(
                mutation.validate_for(candidate),
                Err(ZkAmsMkheErrorV1::InvalidProfile)
            );
        }
    }
    #[test]
    fn governed_security_digests_are_streamed_without_heap_frames() {
        let production = include_str!("security.rs")
            .split_once("#[cfg(test)]\nmod tests")
            .expect("production security source")
            .0;
        let candidate = production
            .split_once("pub(super) fn security_candidate_input_digest_v1(")
            .expect("candidate digest")
            .1
            .split_once("pub(super) fn frozen_security_certificate_v1(")
            .expect("candidate digest boundary")
            .0;
        let certificate = production
            .split_once("fn security_certificate_digest_v1(")
            .expect("certificate digest")
            .1;
        for digest in [candidate, certificate] {
            assert!(digest.contains("let mut hash = super::native_outer_identity_v1("));
            assert!(digest.contains("hash.push_field("));
            assert!(digest.contains(".finish()"));
            assert!(digest.contains("exact MKHE outer identity field count"));
            assert!(!digest.contains("Keccak256"));
            assert!(!digest.contains("Vec::"));
            assert!(!digest.contains("with_capacity"));
            assert!(!digest.contains("keccak256("));
        }
        assert!(
            candidate.find("security_parameters_digest").unwrap()
                < candidate.find("ring_degree.to_be_bytes()").unwrap()
        );
        assert!(
            certificate.find("certificate.version").unwrap()
                < certificate.find("certificate.attacks").unwrap()
        );
    }
}
