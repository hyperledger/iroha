//! Shared pre-auxiliary Fiat--Shamir schedule for the X5S1 credential proof.
//!
//! The MAIN and compact-CA traces compare grand-product terminals. Those products are meaningful
//! only when both subproofs use the same tuple challenges. MAIN's projection products have the same
//! base-before-auxiliary chronology requirement. This module samples every credential challenge
//! family only after the joined MAIN base root and the compact-CA base root have been committed, then
//! supplies an opaque phase token to MAIN and a binding that each local subproof absorbs before its
//! auxiliary commitments.
#[cfg(test)]
use super::proof_instance::TEST_PROOF_INSTANCE_V1;
use super::proof_instance::ZkX509ProofInstanceV1;
#[cfg(test)]
use super::stark::ZK_X509_DIGEST_CONTEXT_V1;
use super::{
    der_stark::{ZkX509DerStarkChallengesV1, derive_zk_x509_der_stark_challenges_v1},
    io_air::{ZkX509IoChallengesV1, derive_zk_x509_io_challenges_v1},
    p256_aggregate_adapter::{
        P256ArithmeticCopyChallengesV1, derive_p256_arithmetic_copy_challenges_v1,
    },
    p256_cross_trace_bus::{
        P256CrossTraceChallengesV1, derive_zk_x509_p256_cross_trace_challenges_v1,
    },
    p256_scalar_bit_bus::{
        P256ScalarBitBusChallengesV1, derive_zk_x509_p256_scalar_bit_bus_challenges_v1,
    },
    p256_value_bus::{P256ValueBusChallengesV1, derive_zk_x509_p256_value_bus_challenges_v1},
    profile::{ZK_X509_PROOF_VERSION_V1, ZK_X509_SUITE_V1},
    projection_air::{
        ZK_X509_PROJECTION_CHALLENGE_LABELS_V1, ZK_X509_PROJECTION_COPY_LANES_V1,
        ZkX509ProjectionChallengesV1, ZkX509ProjectionCompactionChallengesV1,
        ZkX509ProjectionCopyChallengesV1,
    },
    rfc5280_stark::{ZkX509Rfc5280StarkChallengesV1, derive_zk_x509_rfc5280_stark_challenges_v1},
    sha_call_bus_stark::{ZkX509ShaCallBusChallengesV1, derive_zk_x509_sha_call_bus_challenges_v1},
    sha_word_stark::{
        ZkX509ShaWordStarkChallengesV1, derive_zk_x509_sha_word_base_folding_challenges_v1,
        validate_zk_x509_sha_word_stark_challenges_v1,
    },
    sha256_word_air::{ZkX509WordMemoryChallengesV1, derive_sha256_word_memory_challenges_v1},
};
use crate::privacy_engines::transparent_stark::{
    GoldilocksFieldV1 as F, PrivacyOuterDigestV1, TransparentStarkErrorV1, TransparentTranscriptV1,
    append_u16_v1, privacy_outer_digest_frame_v1,
};
use thiserror::Error;
const CREDENTIAL_PRE_AUX_MAGIC_V1: [u8; 4] = *b"X5B1";
const CREDENTIAL_PRE_AUX_PROFILE_DOMAIN_V1: &[u8] =
    b"iroha:privacy:zk-x509:credential-pre-aux:profile:v1";
const CREDENTIAL_PRE_AUX_PUBLIC_DOMAIN_V1: &[u8] =
    b"iroha:privacy:zk-x509:credential-pre-aux:public:v1";
const CREDENTIAL_PRE_AUX_ROOTS_DOMAIN_V1: &[u8] =
    b"iroha:privacy:zk-x509:credential-pre-aux:base-roots:v1";
const CREDENTIAL_PRE_AUX_LOCAL_BINDING_DOMAIN_V1: &[u8] =
    b"iroha:privacy:zk-x509:credential-pre-aux:local-binding:v1";
const MAIN_ROOT_KIND_V1: u8 = 1;
const CA_ROOT_KIND_V1: u8 = 2;
/// Consensus-critical framing and sampling order for the joint challenge set.
pub const ZK_X509_CREDENTIAL_PRE_AUX_DESCRIPTOR_V1: &[u8] =
    b"zk-x509-credential-pre-aux-v1:X5B1:version1:profile=main-profile-digest+ca-profile-digest:public=consensus-context-digest+ca-public-digest:base-roots=exact-main1-joined-ordered-native-log5,8,15,16,18,19-then-ca1-log12:post-base-challenges=exact272-goldilocks-fields:01-sha-call=4lanes*(beta,call,role,slot,kind,word,value)=28:02-rfc=4lanes*tuple12=48:03-projection=4lanes*(copy-beta,copy-gamma,compaction-active,compaction-invocation,compaction-position,compaction-value,compaction-gamma)=28:04-io=4lanes*(beta,channel,offset,value,is-write)=20:05-der=4lanes*(tuple12-then-byte-lookup)=52:06-sha-word-memory=4lanes*(beta,address,value,is-write)=16:07-sha-word-base-fold=4:08-p256-value=4lanes*7=28:09-p256-cross=4lanes*4=16:10-p256-scalar=4lanes*5=20:11-p256-arithmetic-copy=4lanes*3=12:lane-major-within-each-family:one-private-opaque-main-post-base-capability:no-raw-constructor:bind-post-challenge-state-and-all272-canonical-challenges-into-each-local-transcript-before-aux-roots:no-caller-selected-binding";
const SHA_CALL_CHALLENGE_FIELDS_V1: usize = 28;
const RFC5280_CHALLENGE_FIELDS_V1: usize = 48;
const PROJECTION_CHALLENGE_FIELDS_V1: usize = 28;
const IO_CHALLENGE_FIELDS_V1: usize = 20;
const DER_CHALLENGE_FIELDS_V1: usize = 52;
const SHA_WORD_MEMORY_CHALLENGE_FIELDS_V1: usize = 16;
const SHA_WORD_BASE_FOLD_CHALLENGE_FIELDS_V1: usize = 4;
const P256_VALUE_CHALLENGE_FIELDS_V1: usize = 28;
const P256_CROSS_CHALLENGE_FIELDS_V1: usize = 16;
const P256_SCALAR_CHALLENGE_FIELDS_V1: usize = 20;
const P256_ARITHMETIC_COPY_CHALLENGE_FIELDS_V1: usize = 12;
/// Exact number of base-field challenges in the canonical MAIN post-base phase.
pub const ZK_X509_CREDENTIAL_MAIN_POST_BASE_CHALLENGE_FIELDS_V1: usize =
    SHA_CALL_CHALLENGE_FIELDS_V1
        + RFC5280_CHALLENGE_FIELDS_V1
        + PROJECTION_CHALLENGE_FIELDS_V1
        + IO_CHALLENGE_FIELDS_V1
        + DER_CHALLENGE_FIELDS_V1
        + SHA_WORD_MEMORY_CHALLENGE_FIELDS_V1
        + SHA_WORD_BASE_FOLD_CHALLENGE_FIELDS_V1
        + P256_VALUE_CHALLENGE_FIELDS_V1
        + P256_CROSS_CHALLENGE_FIELDS_V1
        + P256_SCALAR_CHALLENGE_FIELDS_V1
        + P256_ARITHMETIC_COPY_CHALLENGE_FIELDS_V1;
/// Exact number of physical joined MAIN base roots in the first release.
pub const ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1: usize = 1;
const _: () = {
    assert!(ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1 == 1);
    assert!(ZK_X509_CREDENTIAL_MAIN_POST_BASE_CHALLENGE_FIELDS_V1 == 272);
};
/// MAIN-owned input to the joint pre-auxiliary challenge schedule.
///
/// The outer verifier constructs this only after decoding the canonical MAIN layout. The fixed-size
/// root array makes omission, excess, and a caller-selected root count unrepresentable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509CredentialMainPreAuxV1 {
    proof_instance: ZkX509ProofInstanceV1,
    /// Digest of the complete verifier-owned statement and genesis context.
    consensus_context_digest: [u8; 32],
    /// Digest of the canonical first-release MAIN profile.
    main_profile_digest: [u8; 32],
    /// One root authenticating all six ordered MAIN base column groups.
    main_base_roots: [PrivacyOuterDigestV1; ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1],
}
impl ZkX509CredentialMainPreAuxV1 {
    pub(crate) const fn proof_instance_v1(&self) -> ZkX509ProofInstanceV1 {
        self.proof_instance
    }
    /// Mint MAIN pre-auxiliary state from the completed canonical commitment
    /// session. No production API accepts raw roots or a partial session.
    pub(super) fn from_completed_main_base_session_v1(
        completed: super::stark::ZkX509CompletedMainBaseCommitmentSessionV1,
    ) -> Self {
        let (proof_instance, consensus_context_digest, main_profile_digest, main_base_roots) =
            completed.into_pre_aux_parts_v1();
        Self {
            proof_instance,
            consensus_context_digest,
            main_profile_digest,
            main_base_roots,
        }
    }
}
#[cfg(test)]
impl ZkX509CredentialMainPreAuxV1 {
    /// Construct deliberately raw pre-auxiliary state for crate-local tests.
    ///
    /// Production code has no corresponding constructor: the canonical MAIN
    /// session must eventually mint this value from its validated layout.
    pub(crate) const fn fixture_for_test_v1(
        consensus_context_digest: [u8; 32],
        main_profile_digest: [u8; 32],
        main_base_roots: [PrivacyOuterDigestV1; ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1],
    ) -> Self {
        Self {
            proof_instance: TEST_PROOF_INSTANCE_V1,
            consensus_context_digest,
            main_profile_digest,
            main_base_roots,
        }
    }
    /// Return the fixture consensus-context digest.
    pub(crate) const fn consensus_context_digest_for_test_v1(self) -> [u8; 32] {
        self.consensus_context_digest
    }
    /// Return mutable fixture-only access to the consensus-context digest.
    pub(crate) fn consensus_context_digest_mut_for_test_v1(&mut self) -> &mut [u8; 32] {
        &mut self.consensus_context_digest
    }
    /// Return the fixture MAIN profile digest.
    pub(crate) const fn main_profile_digest_for_test_v1(self) -> [u8; 32] {
        self.main_profile_digest
    }
    /// Return mutable fixture-only access to the MAIN profile digest.
    pub(crate) fn main_profile_digest_mut_for_test_v1(&mut self) -> &mut [u8; 32] {
        &mut self.main_profile_digest
    }
    /// Return the fixture MAIN roots in their asserted canonical order.
    pub(crate) const fn main_base_roots_for_test_v1(
        self,
    ) -> [PrivacyOuterDigestV1; ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1] {
        self.main_base_roots
    }
    /// Return mutable fixture-only access to the ordered MAIN roots.
    pub(crate) fn main_base_roots_mut_for_test_v1(
        &mut self,
    ) -> &mut [PrivacyOuterDigestV1; ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1] {
        &mut self.main_base_roots
    }
}
/// MAIN challenge phase available only after every X5S1 base commitment.
///
/// Prover and verifier adapters accept this opaque token instead of raw challenge structures. Its
/// fields and construction stay private to this module, so an adapter cannot fabricate the
/// pre-auxiliary phase or sample any auxiliary challenge before X5B1 has bound both roots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509CredentialMainPostBaseChallengesV1 {
    projection: ZkX509ProjectionChallengesV1,
    sha: ZkX509ShaCallBusChallengesV1,
    rfc5280: ZkX509Rfc5280StarkChallengesV1,
    io: ZkX509IoChallengesV1,
    der: ZkX509DerStarkChallengesV1,
    sha_word_memory: ZkX509WordMemoryChallengesV1,
    sha_word_base_folding: [F; SHA_WORD_BASE_FOLD_CHALLENGE_FIELDS_V1],
    p256_value: P256ValueBusChallengesV1,
    p256_cross: P256CrossTraceChallengesV1,
    p256_scalar: P256ScalarBitBusChallengesV1,
    p256_arithmetic_copy: P256ArithmeticCopyChallengesV1,
    transcript_state: PrivacyOuterDigestV1,
}
impl ZkX509CredentialMainPostBaseChallengesV1 {
    /// MAIN projection copy and compaction challenges.
    pub(crate) const fn projection(self) -> ZkX509ProjectionChallengesV1 {
        self.projection
    }
    /// Shared SHA address/value grand-product challenges.
    pub(crate) const fn sha(self) -> ZkX509ShaCallBusChallengesV1 {
        self.sha
    }
    /// Borrow the shared RFC output grand-product challenges from this phase.
    pub(crate) const fn rfc5280(&self) -> &ZkX509Rfc5280StarkChallengesV1 {
        &self.rfc5280
    }
    /// Cross-segment byte-memory challenges.
    pub(crate) const fn io(self) -> ZkX509IoChallengesV1 {
        self.io
    }
    /// Strict-DER tuple and byte-lookup challenges.
    pub(crate) const fn der(self) -> ZkX509DerStarkChallengesV1 {
        self.der
    }
    /// SHA word-memory and base-error-folding challenges.
    pub(crate) const fn sha_word(self) -> ZkX509ShaWordStarkChallengesV1 {
        ZkX509ShaWordStarkChallengesV1 {
            memory: self.sha_word_memory,
            base_folding: self.sha_word_base_folding,
        }
    }
    /// P-256 value-memory challenges.
    pub(crate) const fn p256_value(self) -> P256ValueBusChallengesV1 {
        self.p256_value
    }
    /// P-256 cross-trace challenges.
    pub(crate) const fn p256_cross(self) -> P256CrossTraceChallengesV1 {
        self.p256_cross
    }
    /// P-256 scalar-bit challenges.
    pub(crate) const fn p256_scalar(self) -> P256ScalarBitBusChallengesV1 {
        self.p256_scalar
    }
    /// P-256 arithmetic-copy challenges.
    pub(crate) const fn p256_arithmetic_copy(self) -> P256ArithmeticCopyChallengesV1 {
        self.p256_arithmetic_copy
    }
    /// Post-challenge state bound into both local subproof transcripts.
    pub(crate) const fn transcript_state(&self) -> PrivacyOuterDigestV1 {
        self.transcript_state
    }
}
/// Challenges jointly derived from all X5S1 base commitments.
///
/// Fields are private so another adapter cannot assemble a caller-selected
/// state/challenge combination. Verifiers always recompute this value from
/// decoded roots and verifier-owned profile/public digests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509CredentialPreAuxBindingV1 {
    /// Exact MAIN commitment phase from which the joint schedule was derived.
    ///
    /// Retaining this typed provenance lets the consuming MAIN phase reject a valid X5B1 capability
    /// minted for another joined-root phase before any challenge-dependent child is mutated. It is
    /// deliberately not exposed as raw roots or digests.
    main_pre_aux: ZkX509CredentialMainPreAuxV1,
    main_post_base: ZkX509CredentialMainPostBaseChallengesV1,
}
impl ZkX509CredentialPreAuxBindingV1 {
    pub(crate) const fn proof_instance_v1(&self) -> ZkX509ProofInstanceV1 {
        self.main_pre_aux.proof_instance_v1()
    }
    /// Test exact typed provenance without exposing its component roots.
    pub(crate) fn matches_main_pre_aux_v1(self, expected: ZkX509CredentialMainPreAuxV1) -> bool {
        self.main_pre_aux == expected
    }
    /// Opaque phase token shared by all MAIN prover or verifier providers.
    pub(crate) const fn main_post_base(self) -> ZkX509CredentialMainPostBaseChallengesV1 {
        self.main_post_base
    }
    /// Shared SHA address/value grand-product challenges.
    pub(crate) const fn sha(self) -> ZkX509ShaCallBusChallengesV1 {
        self.main_post_base.sha()
    }
    /// SHA word-memory and base-error-folding challenges.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) const fn sha_word(self) -> ZkX509ShaWordStarkChallengesV1 {
        self.main_post_base.sha_word()
    }
    /// Borrow the shared RFC output grand-product challenges from the retained MAIN phase.
    pub(crate) const fn rfc5280(&self) -> &ZkX509Rfc5280StarkChallengesV1 {
        self.main_post_base.rfc5280()
    }
    /// Post-challenge state bound into both local subproof transcripts.
    pub(crate) const fn transcript_state(&self) -> PrivacyOuterDigestV1 {
        self.main_post_base.transcript_state()
    }
}
/// Joint transcript construction or challenge validation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[doc(hidden)]
pub enum ZkX509CredentialPreAuxErrorV1 {
    /// A framed transcript operation failed.
    #[error("zk-X509 credential pre-auxiliary transcript is invalid")]
    Transcript,
    /// A derived bus or projection challenge family failed canonical validation.
    #[error("zk-X509 credential pre-auxiliary challenges are invalid")]
    Challenge,
    /// Checked framing allocation failed.
    #[error("zk-X509 credential pre-auxiliary framing exceeded its resource envelope")]
    Resource,
}
impl From<TransparentStarkErrorV1> for ZkX509CredentialPreAuxErrorV1 {
    fn from(_: TransparentStarkErrorV1) -> Self {
        Self::Transcript
    }
}
fn pre_aux_profile_digest_v1(
    proof_instance: ZkX509ProofInstanceV1,
    main_profile_digest: [u8; 32],
    ca_profile_digest: PrivacyOuterDigestV1,
) -> Result<PrivacyOuterDigestV1, ZkX509CredentialPreAuxErrorV1> {
    let ca_profile_digest = ca_profile_digest.to_bytes();
    privacy_outer_digest_frame_v1(
        proof_instance.joint_context_v1(),
        CREDENTIAL_PRE_AUX_PROFILE_DOMAIN_V1,
        b"credential-profile",
        0,
        0,
        0,
        &[
            &CREDENTIAL_PRE_AUX_MAGIC_V1,
            &ZK_X509_PROOF_VERSION_V1.to_be_bytes(),
            ZK_X509_CREDENTIAL_PRE_AUX_DESCRIPTOR_V1,
            &main_profile_digest,
            &ca_profile_digest,
        ],
    )
    .map_err(Into::into)
}
fn pre_aux_public_digest_v1(
    proof_instance: ZkX509ProofInstanceV1,
    consensus_context_digest: [u8; 32],
    ca_public_digest: PrivacyOuterDigestV1,
) -> Result<PrivacyOuterDigestV1, ZkX509CredentialPreAuxErrorV1> {
    let ca_public_digest = ca_public_digest.to_bytes();
    privacy_outer_digest_frame_v1(
        proof_instance.joint_context_v1(),
        CREDENTIAL_PRE_AUX_PUBLIC_DOMAIN_V1,
        b"credential-public",
        0,
        0,
        0,
        &[
            &CREDENTIAL_PRE_AUX_MAGIC_V1,
            &ZK_X509_PROOF_VERSION_V1.to_be_bytes(),
            &consensus_context_digest,
            &ca_public_digest,
        ],
    )
    .map_err(Into::into)
}
fn encode_pre_aux_roots_v1(
    main_base_roots: [PrivacyOuterDigestV1; ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1],
    ca_base_root: PrivacyOuterDigestV1,
) -> Result<Vec<u8>, ZkX509CredentialPreAuxErrorV1> {
    const ROOT_RECORD_BYTES_V1: usize = 1 + 2 + 48;
    let exact = 4 + 2 + 2 + (ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1 + 1) * ROOT_RECORD_BYTES_V1;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(exact)
        .map_err(|_| ZkX509CredentialPreAuxErrorV1::Resource)?;
    encoded.extend_from_slice(&CREDENTIAL_PRE_AUX_MAGIC_V1);
    append_u16_v1(&mut encoded, ZK_X509_PROOF_VERSION_V1);
    append_u16_v1(
        &mut encoded,
        u16::try_from(ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1)
            .map_err(|_| ZkX509CredentialPreAuxErrorV1::Resource)?,
    );
    for (index, root) in main_base_roots.into_iter().enumerate() {
        encoded.push(MAIN_ROOT_KIND_V1);
        append_u16_v1(
            &mut encoded,
            u16::try_from(index).map_err(|_| ZkX509CredentialPreAuxErrorV1::Resource)?,
        );
        encoded.extend_from_slice(&root.to_bytes());
    }
    encoded.push(CA_ROOT_KIND_V1);
    append_u16_v1(&mut encoded, 0);
    encoded.extend_from_slice(&ca_base_root.to_bytes());
    if encoded.len() != exact {
        return Err(ZkX509CredentialPreAuxErrorV1::Resource);
    }
    Ok(encoded)
}
fn derive_credential_projection_challenges_v1(
    transcript: &mut TransparentTranscriptV1,
) -> Result<ZkX509ProjectionChallengesV1, ZkX509CredentialPreAuxErrorV1> {
    let mut sampled = [F::ZERO; ZK_X509_PROJECTION_COPY_LANES_V1 * 7];
    for (index, challenge) in sampled.iter_mut().enumerate() {
        let label = ZK_X509_PROJECTION_CHALLENGE_LABELS_V1[index / 7][index % 7];
        *challenge = transcript.challenge_field(label)?;
    }
    let challenges = ZkX509ProjectionChallengesV1 {
        copy: core::array::from_fn(|lane| ZkX509ProjectionCopyChallengesV1 {
            beta: sampled[lane * 7],
            gamma: sampled[lane * 7 + 1],
        }),
        compaction: core::array::from_fn(|lane| ZkX509ProjectionCompactionChallengesV1 {
            active: sampled[lane * 7 + 2],
            invocation: sampled[lane * 7 + 3],
            position: sampled[lane * 7 + 4],
            value: sampled[lane * 7 + 5],
            gamma: sampled[lane * 7 + 6],
        }),
    };
    challenges
        .validate()
        .map_err(|_| ZkX509CredentialPreAuxErrorV1::Challenge)?;
    Ok(challenges)
}
fn validate_main_post_base_challenges_v1(
    phase: ZkX509CredentialMainPostBaseChallengesV1,
) -> Result<(), ZkX509CredentialPreAuxErrorV1> {
    phase
        .sha
        .validate()
        .map_err(|_| ZkX509CredentialPreAuxErrorV1::Challenge)?;
    phase
        .rfc5280
        .validate()
        .map_err(|_| ZkX509CredentialPreAuxErrorV1::Challenge)?;
    phase
        .projection
        .validate()
        .map_err(|_| ZkX509CredentialPreAuxErrorV1::Challenge)?;
    phase
        .io
        .validate()
        .map_err(|_| ZkX509CredentialPreAuxErrorV1::Challenge)?;
    phase
        .der
        .validate()
        .map_err(|_| ZkX509CredentialPreAuxErrorV1::Challenge)?;
    validate_zk_x509_sha_word_stark_challenges_v1(phase.sha_word())
        .map_err(|_| ZkX509CredentialPreAuxErrorV1::Challenge)?;
    phase
        .p256_value
        .validate()
        .map_err(|_| ZkX509CredentialPreAuxErrorV1::Challenge)?;
    phase
        .p256_cross
        .validate()
        .map_err(|_| ZkX509CredentialPreAuxErrorV1::Challenge)?;
    phase
        .p256_scalar
        .validate_v1()
        .map_err(|_| ZkX509CredentialPreAuxErrorV1::Challenge)?;
    phase
        .p256_arithmetic_copy
        .validate_v1()
        .map_err(|_| ZkX509CredentialPreAuxErrorV1::Challenge)
}
fn append_challenge_field_v1(encoded: &mut Vec<u8>, value: F) {
    encoded.extend_from_slice(&value.0.to_be_bytes());
}
fn encode_pre_aux_challenges_v1(
    binding: ZkX509CredentialPreAuxBindingV1,
) -> Result<Vec<u8>, ZkX509CredentialPreAuxErrorV1> {
    let phase = binding.main_post_base;
    validate_main_post_base_challenges_v1(phase)?;
    let exact = ZK_X509_CREDENTIAL_MAIN_POST_BASE_CHALLENGE_FIELDS_V1
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or(ZkX509CredentialPreAuxErrorV1::Resource)?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(exact)
        .map_err(|_| ZkX509CredentialPreAuxErrorV1::Resource)?;
    for lane in phase.sha.lanes {
        for value in lane.terms {
            append_challenge_field_v1(&mut encoded, value);
        }
    }
    for lane in phase.rfc5280.tuple {
        for value in lane {
            append_challenge_field_v1(&mut encoded, value);
        }
    }
    for lane in 0..ZK_X509_PROJECTION_COPY_LANES_V1 {
        let copy = phase.projection.copy[lane];
        let compaction = phase.projection.compaction[lane];
        for value in [
            copy.beta,
            copy.gamma,
            compaction.active,
            compaction.invocation,
            compaction.position,
            compaction.value,
            compaction.gamma,
        ] {
            append_challenge_field_v1(&mut encoded, value);
        }
    }
    for lane in phase.io.lanes {
        for value in [
            lane.beta,
            lane.channel,
            lane.offset,
            lane.value,
            lane.is_write,
        ] {
            append_challenge_field_v1(&mut encoded, value);
        }
    }
    for lane in 0..phase.der.tuple.len() {
        for value in phase.der.tuple[lane] {
            append_challenge_field_v1(&mut encoded, value);
        }
        append_challenge_field_v1(&mut encoded, phase.der.byte_lookup[lane]);
    }
    for lane in phase.sha_word_memory.lanes {
        for value in [lane.beta, lane.address, lane.value, lane.is_write] {
            append_challenge_field_v1(&mut encoded, value);
        }
    }
    for value in phase.sha_word_base_folding {
        append_challenge_field_v1(&mut encoded, value);
    }
    for lane in phase.p256_value.lanes {
        for value in lane.terms {
            append_challenge_field_v1(&mut encoded, value);
        }
    }
    for lane in phase.p256_cross.lanes {
        for value in lane.terms {
            append_challenge_field_v1(&mut encoded, value);
        }
    }
    for lane in phase.p256_scalar.lanes {
        for value in lane.terms {
            append_challenge_field_v1(&mut encoded, value);
        }
    }
    for lane in phase.p256_arithmetic_copy.lanes {
        for value in lane.terms {
            append_challenge_field_v1(&mut encoded, value);
        }
    }
    if encoded.len() != exact {
        return Err(ZkX509CredentialPreAuxErrorV1::Resource);
    }
    Ok(encoded)
}
/// Derive the sole shared X5S1 post-base-root challenge phase.
///
/// The compact-CA root is supplied separately because it is decoded from (or
/// produced by) the X5C1 subproof. The caller never supplies a challenge or
/// post-challenge state. MAIN and compact-CA verifiers must each compare their
/// own decoded base roots with the roots used here before accepting the proof.
pub fn derive_zk_x509_credential_pre_aux_binding_v1(
    main: ZkX509CredentialMainPreAuxV1,
    ca_profile_digest: PrivacyOuterDigestV1,
    ca_public_digest: PrivacyOuterDigestV1,
    ca_base_root: PrivacyOuterDigestV1,
) -> Result<ZkX509CredentialPreAuxBindingV1, ZkX509CredentialPreAuxErrorV1> {
    let proof_instance = main.proof_instance_v1();
    let profile_digest =
        pre_aux_profile_digest_v1(proof_instance, main.main_profile_digest, ca_profile_digest)?;
    let public_digest = pre_aux_public_digest_v1(
        proof_instance,
        main.consensus_context_digest,
        ca_public_digest,
    )?;
    let roots = encode_pre_aux_roots_v1(main.main_base_roots, ca_base_root)?;
    let mut transcript = TransparentTranscriptV1::new(
        proof_instance.joint_context_v1(),
        ZK_X509_SUITE_V1,
        &profile_digest,
        &public_digest,
    )?;
    transcript.absorb(CREDENTIAL_PRE_AUX_ROOTS_DOMAIN_V1, &[&roots])?;
    let sha = derive_zk_x509_sha_call_bus_challenges_v1(&mut transcript)?;
    let rfc5280 = derive_zk_x509_rfc5280_stark_challenges_v1(&mut transcript)?;
    let projection = derive_credential_projection_challenges_v1(&mut transcript)?;
    let io = derive_zk_x509_io_challenges_v1(&mut transcript)?;
    let der = derive_zk_x509_der_stark_challenges_v1(&mut transcript)?;
    let sha_word_memory = derive_sha256_word_memory_challenges_v1(&mut transcript)?;
    let sha_word_base_folding =
        derive_zk_x509_sha_word_base_folding_challenges_v1(&mut transcript)?;
    let p256_value = derive_zk_x509_p256_value_bus_challenges_v1(&mut transcript)?;
    let p256_cross = derive_zk_x509_p256_cross_trace_challenges_v1(&mut transcript)?;
    let p256_scalar = derive_zk_x509_p256_scalar_bit_bus_challenges_v1(&mut transcript)?;
    let p256_arithmetic_copy = derive_p256_arithmetic_copy_challenges_v1(&mut transcript)?;
    let main_post_base = ZkX509CredentialMainPostBaseChallengesV1 {
        projection,
        sha,
        rfc5280,
        io,
        der,
        sha_word_memory,
        sha_word_base_folding,
        p256_value,
        p256_cross,
        p256_scalar,
        p256_arithmetic_copy,
        transcript_state: transcript.state(),
    };
    validate_main_post_base_challenges_v1(main_post_base)?;
    Ok(ZkX509CredentialPreAuxBindingV1 {
        main_pre_aux: main,
        main_post_base,
    })
}
/// Bind a recomputed joint pre-auxiliary schedule into one local transcript.
///
/// This call belongs immediately after that subproof's own base-root frame and immediately before
/// its auxiliary-root frame. Encoding the challenges as well as the post-challenge state makes
/// accidental state/challenge mixing fail closed even inside crate-private integration code.
pub fn absorb_zk_x509_credential_pre_aux_binding_v1(
    transcript: &mut TransparentTranscriptV1,
    binding: ZkX509CredentialPreAuxBindingV1,
) -> Result<(), ZkX509CredentialPreAuxErrorV1> {
    binding
        .proof_instance_v1()
        .check_local_transcript_v1(transcript)?;
    let challenges = encode_pre_aux_challenges_v1(binding)?;
    let transcript_state = binding.transcript_state().to_bytes();
    transcript
        .absorb(
            CREDENTIAL_PRE_AUX_LOCAL_BINDING_DOMAIN_V1,
            &[
                &CREDENTIAL_PRE_AUX_MAGIC_V1,
                &ZK_X509_PROOF_VERSION_V1.to_be_bytes(),
                &transcript_state,
                &challenges,
            ],
        )
        .map_err(Into::into)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn test_digest_v1(value: u8) -> PrivacyOuterDigestV1 {
        PrivacyOuterDigestV1::from_bytes([value; 48])
    }
    fn mutate_digest_byte_v1(digest: &mut PrivacyOuterDigestV1, byte: usize) {
        let mut bytes = digest.to_bytes();
        bytes[byte] ^= 1;
        *digest = PrivacyOuterDigestV1::from_bytes(bytes);
    }
    fn main_pre_aux_v1() -> ZkX509CredentialMainPreAuxV1 {
        ZkX509CredentialMainPreAuxV1::fixture_for_test_v1(
            [0x11; 32],
            [0x22; 32],
            core::array::from_fn(|index| {
                test_digest_v1(u8::try_from(0x30 + index).expect("fixture byte"))
            }),
        )
    }
    fn derive_v1(main: ZkX509CredentialMainPreAuxV1) -> ZkX509CredentialPreAuxBindingV1 {
        derive_zk_x509_credential_pre_aux_binding_v1(
            main,
            test_digest_v1(0x44),
            test_digest_v1(0x55),
            test_digest_v1(0x66),
        )
        .expect("joint pre-auxiliary binding")
    }
    fn transcript_after_roots_v1(
        main: ZkX509CredentialMainPreAuxV1,
        roots_domain: &[u8],
    ) -> TransparentTranscriptV1 {
        let profile_digest = pre_aux_profile_digest_v1(
            TEST_PROOF_INSTANCE_V1,
            main.main_profile_digest_for_test_v1(),
            test_digest_v1(0x44),
        )
        .expect("profile digest");
        let public_digest = pre_aux_public_digest_v1(
            TEST_PROOF_INSTANCE_V1,
            main.consensus_context_digest_for_test_v1(),
            test_digest_v1(0x55),
        )
        .expect("public digest");
        let roots =
            encode_pre_aux_roots_v1(main.main_base_roots_for_test_v1(), test_digest_v1(0x66))
                .expect("joined MAIN and CA roots");
        let mut transcript = TransparentTranscriptV1::new(
            TEST_PROOF_INSTANCE_V1.joint_context_v1(),
            ZK_X509_SUITE_V1,
            &profile_digest,
            &public_digest,
        )
        .expect("credential transcript");
        transcript
            .absorb(roots_domain, &[&roots])
            .expect("root frame");
        transcript
    }
    fn derive_family_for_order_test_v1(transcript: &mut TransparentTranscriptV1, family: usize) {
        match family {
            0 => {
                derive_zk_x509_sha_call_bus_challenges_v1(transcript).expect("SHA-call challenges");
            }
            1 => {
                derive_zk_x509_rfc5280_stark_challenges_v1(transcript).expect("RFC challenges");
            }
            2 => {
                derive_credential_projection_challenges_v1(transcript)
                    .expect("projection challenges");
            }
            3 => {
                derive_zk_x509_io_challenges_v1(transcript).expect("I/O challenges");
            }
            4 => {
                derive_zk_x509_der_stark_challenges_v1(transcript).expect("DER challenges");
            }
            5 => {
                derive_sha256_word_memory_challenges_v1(transcript)
                    .expect("SHA word-memory challenges");
            }
            6 => {
                derive_zk_x509_sha_word_base_folding_challenges_v1(transcript)
                    .expect("SHA base-folding challenges");
            }
            7 => {
                derive_zk_x509_p256_value_bus_challenges_v1(transcript)
                    .expect("P-256 value challenges");
            }
            8 => {
                derive_zk_x509_p256_cross_trace_challenges_v1(transcript)
                    .expect("P-256 cross-trace challenges");
            }
            9 => {
                derive_zk_x509_p256_scalar_bit_bus_challenges_v1(transcript)
                    .expect("P-256 scalar-bit challenges");
            }
            10 => {
                derive_p256_arithmetic_copy_challenges_v1(transcript)
                    .expect("P-256 arithmetic-copy challenges");
            }
            _ => panic!("unknown post-base challenge family"),
        }
    }
    fn state_after_family_order_v1(
        main: ZkX509CredentialMainPreAuxV1,
        order: &[usize],
    ) -> PrivacyOuterDigestV1 {
        let mut transcript = transcript_after_roots_v1(main, CREDENTIAL_PRE_AUX_ROOTS_DOMAIN_V1);
        for family in order {
            derive_family_for_order_test_v1(&mut transcript, *family);
        }
        transcript.state()
    }
    fn fields_in_binding_order_v1(phase: ZkX509CredentialMainPostBaseChallengesV1) -> Vec<F> {
        let mut fields = Vec::with_capacity(ZK_X509_CREDENTIAL_MAIN_POST_BASE_CHALLENGE_FIELDS_V1);
        for lane in phase.sha.lanes {
            fields.extend(lane.terms);
        }
        for lane in phase.rfc5280.tuple {
            fields.extend(lane);
        }
        for lane in 0..ZK_X509_PROJECTION_COPY_LANES_V1 {
            let copy = phase.projection.copy[lane];
            let compaction = phase.projection.compaction[lane];
            fields.extend([
                copy.beta,
                copy.gamma,
                compaction.active,
                compaction.invocation,
                compaction.position,
                compaction.value,
                compaction.gamma,
            ]);
        }
        for lane in phase.io.lanes {
            fields.extend([
                lane.beta,
                lane.channel,
                lane.offset,
                lane.value,
                lane.is_write,
            ]);
        }
        for lane in 0..phase.der.tuple.len() {
            fields.extend(phase.der.tuple[lane]);
            fields.push(phase.der.byte_lookup[lane]);
        }
        for lane in phase.sha_word_memory.lanes {
            fields.extend([lane.beta, lane.address, lane.value, lane.is_write]);
        }
        fields.extend(phase.sha_word_base_folding);
        for lane in phase.p256_value.lanes {
            fields.extend(lane.terms);
        }
        for lane in phase.p256_cross.lanes {
            fields.extend(lane.terms);
        }
        for lane in phase.p256_scalar.lanes {
            fields.extend(lane.terms);
        }
        for lane in phase.p256_arithmetic_copy.lanes {
            fields.extend(lane.terms);
        }
        fields
    }
    fn local_state_for_encoded_challenges_v1(
        binding: ZkX509CredentialPreAuxBindingV1,
        encoded: &[u8],
    ) -> PrivacyOuterDigestV1 {
        let mut transcript = TransparentTranscriptV1::new(
            ZK_X509_DIGEST_CONTEXT_V1,
            b"local",
            &test_digest_v1(0x71),
            &test_digest_v1(0x72),
        )
        .expect("local");
        let transcript_state = binding.transcript_state().to_bytes();
        transcript
            .absorb(
                CREDENTIAL_PRE_AUX_LOCAL_BINDING_DOMAIN_V1,
                &[
                    &CREDENTIAL_PRE_AUX_MAGIC_V1,
                    &ZK_X509_PROOF_VERSION_V1.to_be_bytes(),
                    &transcript_state,
                    encoded,
                ],
            )
            .expect("encoded local binding");
        transcript.state()
    }
    #[test]
    fn proof_instance_is_original_pre_aux_custody_and_checks_local_scope() {
        let original = main_pre_aux_v1();
        let baseline = derive_v1(original);
        let mut changed = original;
        changed.proof_instance = ZkX509ProofInstanceV1::new_v1([0xa7; 32]);
        let changed_binding = derive_v1(changed);
        assert_eq!(changed_binding.proof_instance_v1(), changed.proof_instance);
        assert_ne!(
            baseline.transcript_state(),
            changed_binding.transcript_state()
        );
        assert!(!baseline.matches_main_pre_aux_v1(changed));
        assert!(!changed_binding.matches_main_pre_aux_v1(original));
        for context in [
            changed.proof_instance.main_context_v1(),
            changed.proof_instance.ca_context_v1(),
        ] {
            let mut transcript = TransparentTranscriptV1::new(
                context,
                b"scope-control",
                &test_digest_v1(1),
                &test_digest_v1(2),
            )
            .unwrap();
            let before = transcript.state();
            assert!(
                absorb_zk_x509_credential_pre_aux_binding_v1(&mut transcript, baseline).is_err()
            );
            assert_eq!(transcript.state(), before);
            absorb_zk_x509_credential_pre_aux_binding_v1(&mut transcript, changed_binding).unwrap();
            assert_ne!(transcript.state(), before);
        }
        let mut joint = TransparentTranscriptV1::new(
            changed.proof_instance.joint_context_v1(),
            b"scope-control",
            &test_digest_v1(1),
            &test_digest_v1(2),
        )
        .unwrap();
        let before = joint.state();
        assert!(absorb_zk_x509_credential_pre_aux_binding_v1(&mut joint, changed_binding).is_err());
        assert_eq!(joint.state(), before);
    }

    #[test]
    fn rfc_accessors_borrow_the_original_phase_challenge_owner() {
        let binding = derive_v1(main_pre_aux_v1());
        let phase = &binding.main_post_base;
        let from_phase: &ZkX509Rfc5280StarkChallengesV1 = phase.rfc5280();
        let from_binding: &ZkX509Rfc5280StarkChallengesV1 = binding.rfc5280();
        assert!(core::ptr::eq(from_phase, &raw const phase.rfc5280));
        assert!(core::ptr::eq(from_binding, from_phase));
        from_binding
            .validate()
            .expect("validated retained challenges");
    }

    #[test]
    fn explicitly_copied_rfc_challenges_outlive_the_phase_owner() {
        let retained = {
            let mut binding = derive_v1(main_pre_aux_v1());
            let retained = *binding.rfc5280();
            assert_eq!(&retained, binding.rfc5280());
            binding.main_post_base.rfc5280.tuple[0][0] = F::ZERO;
            assert_ne!(&retained, binding.rfc5280());
            assert!(binding.rfc5280().validate().is_err());
            retained
        };
        retained
            .validate()
            .expect("independently retained challenges");
    }

    #[test]
    fn exact_two_root_schedule_is_deterministic_and_valid() {
        let binding = derive_v1(main_pre_aux_v1());
        assert_eq!(binding, derive_v1(main_pre_aux_v1()));
        assert!(binding.matches_main_pre_aux_v1(main_pre_aux_v1()));
        let main_phase = binding.main_post_base();
        validate_main_post_base_challenges_v1(main_phase).expect("all eleven challenge families");
        assert_eq!(main_phase.sha(), binding.sha());
        assert_eq!(main_phase.rfc5280(), binding.rfc5280());
        assert_eq!(main_phase.transcript_state(), binding.transcript_state());
        assert_eq!(main_phase.sha_word().memory, main_phase.sha_word_memory);
        assert_eq!(
            main_phase.sha_word().base_folding,
            main_phase.sha_word_base_folding
        );
        assert_ne!(binding.transcript_state(), PrivacyOuterDigestV1::default());
    }
    #[test]
    fn opaque_binding_rejects_every_main_phase_provenance_substitution() {
        let canonical_main = main_pre_aux_v1();
        let binding = derive_v1(canonical_main);
        assert!(binding.matches_main_pre_aux_v1(canonical_main));
        for byte in 0..32 {
            let mut changed = canonical_main;
            changed.consensus_context_digest_mut_for_test_v1()[byte] ^= 1;
            assert!(
                !binding.matches_main_pre_aux_v1(changed),
                "consensus-context substitution at byte {byte}"
            );
            let mut changed = canonical_main;
            changed.main_profile_digest_mut_for_test_v1()[byte] ^= 1;
            assert!(
                !binding.matches_main_pre_aux_v1(changed),
                "MAIN-profile substitution at byte {byte}"
            );
        }
        for root in 0..ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1 {
            for byte in 0..48 {
                let mut changed = canonical_main;
                mutate_digest_byte_v1(&mut changed.main_base_roots_mut_for_test_v1()[root], byte);
                assert!(
                    !binding.matches_main_pre_aux_v1(changed),
                    "MAIN root {root} substitution at byte {byte}"
                );
            }
        }
        // CA material belongs to the outer X5S1 phase. A binding derived with
        // different CA inputs still records the same exact MAIN provenance;
        // the credential orchestrator separately enforces the typed CA hook.
        let changed_ca = derive_zk_x509_credential_pre_aux_binding_v1(
            canonical_main,
            test_digest_v1(0x45),
            test_digest_v1(0x56),
            test_digest_v1(0x67),
        )
        .expect("alternative typed CA phase");
        assert!(changed_ca.matches_main_pre_aux_v1(canonical_main));
        assert_ne!(changed_ca, binding);
    }
    #[test]
    fn exact_two_root_schedule_has_a_stable_known_answer() {
        let binding = derive_v1(main_pre_aux_v1());
        let phase = binding.main_post_base();
        validate_main_post_base_challenges_v1(phase).expect("canonical challenge phase");
        let encoded =
            encode_pre_aux_challenges_v1(binding).expect("canonical 272-field challenge encoding");
        assert_eq!(encoded.len(), 272 * core::mem::size_of::<u64>());
        let challenge_digest = privacy_outer_digest_frame_v1(
            ZK_X509_DIGEST_CONTEXT_V1,
            b"iroha:privacy:zk-x509:credential-pre-aux:challenge-kat:v1",
            b"ordered-challenges",
            0,
            0,
            0,
            &[&encoded],
        )
        .expect("challenge KAT frame");
        // Emit both native values before either old-pin assertion can stop diagnostics.
        eprintln!(
            "X509_PRE_AUX_CHALLENGE_KAT_V1={}",
            hex::encode(challenge_digest.to_bytes())
        );
        eprintln!(
            "X509_PRE_AUX_TRANSCRIPT_KAT_V1={}",
            hex::encode(binding.transcript_state().to_bytes())
        );
        assert_eq!(
            hex::encode(challenge_digest.to_bytes()),
            "12aab996200e37d217d8883ba45745ed327c94271d58fdade39e834120204218915d30d60fef9e380fd266ee8bdf7987"
        );
        assert_eq!(
            hex::encode(binding.transcript_state().to_bytes()),
            "18f3950d69fb451b3c8746e481a23a7de9fab93014d0d7286d5f8938bb60a7be610a0fe32be8684c5e8989e42c21e449"
        );
    }
    #[test]
    fn all_eleven_family_positions_are_order_bound() {
        const FAMILY_COUNT_V1: usize = 11;
        let main = main_pre_aux_v1();
        let canonical_order = (0..FAMILY_COUNT_V1).collect::<Vec<_>>();
        let canonical_state = derive_v1(main).transcript_state();
        assert_eq!(
            state_after_family_order_v1(main, &canonical_order),
            canonical_state
        );
        for from in 0..FAMILY_COUNT_V1 {
            for to in 0..FAMILY_COUNT_V1 {
                if from == to {
                    continue;
                }
                let mut moved = canonical_order.clone();
                let family = moved.remove(from);
                moved.insert(to, family);
                assert_ne!(
                    state_after_family_order_v1(main, &moved),
                    canonical_state,
                    "moving challenge family {from} to position {to} must change the transcript"
                );
            }
        }
    }
    #[test]
    fn challenge_binding_encoding_is_exact_lane_major_and_complete() {
        let binding = derive_v1(main_pre_aux_v1());
        let fields = fields_in_binding_order_v1(binding.main_post_base());
        assert_eq!(
            fields.len(),
            ZK_X509_CREDENTIAL_MAIN_POST_BASE_CHALLENGE_FIELDS_V1
        );
        let encoded = encode_pre_aux_challenges_v1(binding).expect("canonical challenge encoding");
        let decoded = encoded
            .chunks_exact(core::mem::size_of::<u64>())
            .map(|bytes| {
                F(u64::from_be_bytes(
                    bytes.try_into().expect("one encoded Goldilocks field"),
                ))
            })
            .collect::<Vec<_>>();
        assert!(
            encoded
                .chunks_exact(core::mem::size_of::<u64>())
                .remainder()
                .is_empty()
        );
        assert_eq!(decoded, fields);
        let family_counts = [
            SHA_CALL_CHALLENGE_FIELDS_V1,
            RFC5280_CHALLENGE_FIELDS_V1,
            PROJECTION_CHALLENGE_FIELDS_V1,
            IO_CHALLENGE_FIELDS_V1,
            DER_CHALLENGE_FIELDS_V1,
            SHA_WORD_MEMORY_CHALLENGE_FIELDS_V1,
            SHA_WORD_BASE_FOLD_CHALLENGE_FIELDS_V1,
            P256_VALUE_CHALLENGE_FIELDS_V1,
            P256_CROSS_CHALLENGE_FIELDS_V1,
            P256_SCALAR_CHALLENGE_FIELDS_V1,
            P256_ARITHMETIC_COPY_CHALLENGE_FIELDS_V1,
        ];
        assert_eq!(family_counts.iter().sum::<usize>(), 272);
        let mut start = 0;
        for count in family_counts {
            let end = start + count;
            assert!(
                fields[start..end].iter().all(|field| *field != F::ZERO),
                "family at field range {start}..{end}"
            );
            start = end;
        }
        assert_eq!(start, fields.len());
    }
    #[test]
    fn every_byte_of_all_272_encoded_challenges_is_locally_bound() {
        let binding = derive_v1(main_pre_aux_v1());
        let encoded = encode_pre_aux_challenges_v1(binding).expect("canonical challenge encoding");
        let canonical_state = local_state_for_encoded_challenges_v1(binding, &encoded);
        for byte in 0..encoded.len() {
            let mut changed = encoded.clone();
            changed[byte] ^= 1;
            assert_ne!(
                local_state_for_encoded_challenges_v1(binding, &changed),
                canonical_state,
                "encoded challenge byte {byte}"
            );
        }
    }
    #[test]
    fn every_challenge_family_rejects_a_raw_zero_coordinate() {
        let canonical = derive_v1(main_pre_aux_v1());
        let mut invalid = Vec::new();
        let mut changed = canonical;
        changed.main_post_base.sha.lanes[0].terms[0] = F::ZERO;
        invalid.push(("SHA call", changed));
        let mut changed = canonical;
        changed.main_post_base.rfc5280.tuple[0][0] = F::ZERO;
        invalid.push(("RFC", changed));
        let mut changed = canonical;
        changed.main_post_base.projection.copy[0].beta = F::ZERO;
        invalid.push(("projection", changed));
        let mut changed = canonical;
        changed.main_post_base.io.lanes[0].beta = F::ZERO;
        invalid.push(("I/O", changed));
        let mut changed = canonical;
        changed.main_post_base.der.tuple[0][0] = F::ZERO;
        invalid.push(("DER", changed));
        let mut changed = canonical;
        changed.main_post_base.sha_word_memory.lanes[0].beta = F::ZERO;
        invalid.push(("SHA word memory", changed));
        let mut changed = canonical;
        changed.main_post_base.sha_word_base_folding[0] = F::ZERO;
        invalid.push(("SHA base folding", changed));
        let mut changed = canonical;
        changed.main_post_base.p256_value.lanes[0].terms[0] = F::ZERO;
        invalid.push(("P-256 value", changed));
        let mut changed = canonical;
        changed.main_post_base.p256_cross.lanes[0].terms[0] = F::ZERO;
        invalid.push(("P-256 cross", changed));
        let mut changed = canonical;
        changed.main_post_base.p256_scalar.lanes[0].terms[0] = F::ZERO;
        invalid.push(("P-256 scalar", changed));
        let mut changed = canonical;
        changed.main_post_base.p256_arithmetic_copy.lanes[0].terms[0] = F::ZERO;
        invalid.push(("P-256 arithmetic copy", changed));
        for (family, changed) in invalid {
            assert_eq!(
                encode_pre_aux_challenges_v1(changed),
                Err(ZkX509CredentialPreAuxErrorV1::Challenge),
                "{family}"
            );
        }
    }
    #[test]
    fn every_byte_of_every_public_profile_and_base_root_input_is_bound() {
        let canonical_main = main_pre_aux_v1();
        let canonical = derive_v1(canonical_main);
        for byte in 0..32 {
            let mut changed = canonical_main;
            changed.consensus_context_digest_mut_for_test_v1()[byte] ^= 1;
            assert_ne!(derive_v1(changed), canonical, "consensus byte {byte}");
            let mut changed = canonical_main;
            changed.main_profile_digest_mut_for_test_v1()[byte] ^= 1;
            assert_ne!(derive_v1(changed), canonical, "MAIN profile byte {byte}");
            for root in 0..ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1 {
                let mut changed = canonical_main;
                mutate_digest_byte_v1(&mut changed.main_base_roots_mut_for_test_v1()[root], byte);
                assert_ne!(
                    derive_v1(changed),
                    canonical,
                    "MAIN root {root} byte {byte}"
                );
            }
            let mut ca_profile = test_digest_v1(0x44);
            mutate_digest_byte_v1(&mut ca_profile, byte);
            let changed = derive_zk_x509_credential_pre_aux_binding_v1(
                canonical_main,
                ca_profile,
                test_digest_v1(0x55),
                test_digest_v1(0x66),
            )
            .expect("changed CA profile");
            assert_ne!(changed, canonical, "CA profile byte {byte}");
            let mut ca_public = test_digest_v1(0x55);
            mutate_digest_byte_v1(&mut ca_public, byte);
            let changed = derive_zk_x509_credential_pre_aux_binding_v1(
                canonical_main,
                test_digest_v1(0x44),
                ca_public,
                test_digest_v1(0x66),
            )
            .expect("changed CA public");
            assert_ne!(changed, canonical, "CA public byte {byte}");
            let mut ca_root = test_digest_v1(0x66);
            mutate_digest_byte_v1(&mut ca_root, byte);
            let changed = derive_zk_x509_credential_pre_aux_binding_v1(
                canonical_main,
                test_digest_v1(0x44),
                test_digest_v1(0x55),
                ca_root,
            )
            .expect("changed CA root");
            assert_ne!(changed, canonical, "CA root byte {byte}");
        }
    }
    #[test]
    fn main_root_order_and_local_binding_state_are_domain_bound() {
        let canonical_main = main_pre_aux_v1();
        let canonical = derive_v1(canonical_main);
        assert_eq!(ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1, 1);
        let mut swapped = canonical_main;
        let original_main_root = swapped.main_base_roots_for_test_v1()[0];
        swapped.main_base_roots_mut_for_test_v1()[0] = test_digest_v1(0x66);
        let swapped_binding = derive_zk_x509_credential_pre_aux_binding_v1(
            swapped,
            test_digest_v1(0x44),
            test_digest_v1(0x55),
            original_main_root,
        )
        .expect("both roots remain well formed after exchanging roles");
        assert_ne!(
            swapped_binding, canonical,
            "joined MAIN and CA roots are role-bound"
        );
        let mut left = TransparentTranscriptV1::new(
            ZK_X509_DIGEST_CONTEXT_V1,
            b"local",
            &test_digest_v1(0x71),
            &test_digest_v1(0x72),
        )
        .expect("left transcript");
        let mut right = left;
        absorb_zk_x509_credential_pre_aux_binding_v1(&mut left, canonical)
            .expect("canonical local binding");
        let mut hostile = canonical;
        mutate_digest_byte_v1(&mut hostile.main_post_base.transcript_state, 0);
        absorb_zk_x509_credential_pre_aux_binding_v1(&mut right, hostile)
            .expect("hostile local binding");
        assert_ne!(left.state(), right.state());
    }
    #[test]
    fn projection_phase_changes_for_pre_root_reordered_and_mutated_transcripts() {
        let main = main_pre_aux_v1();
        let canonical = derive_v1(main).main_post_base().projection();
        let profile_digest = pre_aux_profile_digest_v1(
            TEST_PROOF_INSTANCE_V1,
            main.main_profile_digest_for_test_v1(),
            test_digest_v1(0x44),
        )
        .expect("profile digest");
        let public_digest = pre_aux_public_digest_v1(
            TEST_PROOF_INSTANCE_V1,
            main.consensus_context_digest_for_test_v1(),
            test_digest_v1(0x55),
        )
        .expect("public digest");
        let mut before_roots = TransparentTranscriptV1::new(
            TEST_PROOF_INSTANCE_V1.joint_context_v1(),
            ZK_X509_SUITE_V1,
            &profile_digest,
            &public_digest,
        )
        .expect("pre-root transcript");
        let premature = derive_credential_projection_challenges_v1(&mut before_roots)
            .expect("premature projection schedule");
        assert_ne!(premature, canonical);
        let mut reordered = transcript_after_roots_v1(main, CREDENTIAL_PRE_AUX_ROOTS_DOMAIN_V1);
        let projection_first = derive_credential_projection_challenges_v1(&mut reordered)
            .expect("projection-first schedule");
        assert_ne!(projection_first, canonical);
        let mut wrong_domain = transcript_after_roots_v1(
            main,
            b"iroha:privacy:zk-x509:credential-pre-aux:base-roots:v2",
        );
        let _ = derive_zk_x509_sha_call_bus_challenges_v1(&mut wrong_domain)
            .expect("wrong-domain SHA challenges");
        let _ = derive_zk_x509_rfc5280_stark_challenges_v1(&mut wrong_domain)
            .expect("wrong-domain RFC challenges");
        let wrong_domain_projection = derive_credential_projection_challenges_v1(&mut wrong_domain)
            .expect("wrong-domain projection challenges");
        assert_ne!(wrong_domain_projection, canonical);
        let mut injected = transcript_after_roots_v1(main, CREDENTIAL_PRE_AUX_ROOTS_DOMAIN_V1);
        injected
            .absorb(b"hostile-between-roots-and-challenges", &[b"injected"])
            .expect("hostile frame");
        let _ = derive_zk_x509_sha_call_bus_challenges_v1(&mut injected)
            .expect("injected SHA challenges");
        let _ = derive_zk_x509_rfc5280_stark_challenges_v1(&mut injected)
            .expect("injected RFC challenges");
        let injected_projection = derive_credential_projection_challenges_v1(&mut injected)
            .expect("injected projection challenges");
        assert_ne!(injected_projection, canonical);
    }
    #[test]
    fn local_binding_encodes_all_challenges_and_enforces_order() {
        let canonical = derive_v1(main_pre_aux_v1());
        assert_eq!(
            encode_pre_aux_challenges_v1(canonical)
                .expect("canonical challenge encoding")
                .len(),
            ZK_X509_CREDENTIAL_MAIN_POST_BASE_CHALLENGE_FIELDS_V1 * core::mem::size_of::<u64>()
        );
        let mut changed_projection = canonical;
        changed_projection.main_post_base.projection.copy[0].beta =
            changed_projection.main_post_base.projection.copy[0]
                .beta
                .add(F::ONE);
        changed_projection
            .main_post_base
            .projection
            .validate()
            .expect("mutated projection remains canonical");
        assert_eq!(
            changed_projection.transcript_state(),
            canonical.transcript_state(),
            "only the encoded projection challenge changes"
        );
        let local = TransparentTranscriptV1::new(
            ZK_X509_DIGEST_CONTEXT_V1,
            b"local",
            &test_digest_v1(0x71),
            &test_digest_v1(0x72),
        )
        .expect("local");
        let mut canonical_local = local;
        let mut changed_local = local;
        absorb_zk_x509_credential_pre_aux_binding_v1(&mut canonical_local, canonical)
            .expect("canonical local binding");
        absorb_zk_x509_credential_pre_aux_binding_v1(&mut changed_local, changed_projection)
            .expect("changed local binding");
        assert_ne!(canonical_local.state(), changed_local.state());
        let local_base_root = test_digest_v1(0x81).to_bytes();
        let mut correct_order = local;
        correct_order
            .absorb(b"local-base-roots", &[&local_base_root])
            .expect("local base roots");
        absorb_zk_x509_credential_pre_aux_binding_v1(&mut correct_order, canonical)
            .expect("post-base binding");
        let mut reversed_order = local;
        absorb_zk_x509_credential_pre_aux_binding_v1(&mut reversed_order, canonical)
            .expect("premature binding");
        reversed_order
            .absorb(b"local-base-roots", &[&local_base_root])
            .expect("late local base roots");
        assert_ne!(correct_order.state(), reversed_order.state());
    }
}
