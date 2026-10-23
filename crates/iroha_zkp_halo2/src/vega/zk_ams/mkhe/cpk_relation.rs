//! Canonical native proof for the exact CPK relation.
//!
//! The verifier in this module fixes the release dimensions, content-addressed
//! object roles, statement and proof wire formats, transcript order, exact
//! common-box response construction, and role-separated membership inputs.  It
//! then authenticates both complete direct objects, reconstructs the T256
//! commitment first messages, and streams the party-local `b` polynomial once
//! while checking every release RNS limb in all four challenge repetitions.
//! Only that complete path can mint the move-only relation receipt.
//!
//! The complete relation will combine bound-one membership evidence for the persistent secret with
//! bound-two membership evidence for the public error and the native polynomial Sigma equations
//!
//! ```text
//! b_l = -a_l*s + (t mod q_l)*e                      (mod q_l, X^N + 1)
//! D_s = Com(z_s; rho_s) - c*Com(s; r_s)
//! D_e = Com(z_e; rho_e) - c*Com(e; r_e)
//! U_l = -a_l*z_s + (t mod q_l)*z_e - c*b_l          (mod q_l, X^N + 1).
//! ```
//!
//! Generalized Bulletproofs are used only for exact coefficient membership.
//! Their scalar field is the T256 plaintext field, so encoding the full BGV
//! equation in that field would erase `t*e`.  No membership-only path in this
//! module can construct a relation receipt or contribution capability.
use super::{
    ArtifactAuthentication, BgvProfile, MAX_RANDOM_REJECTION_ATTEMPTS_V1, MKHE_VERSION_V1,
    ZkAmsMkhePartyIdV1,
    active::{ZkAmsMkheActivePartySecretV1, ZkAmsMkheGovernedActiveRosterV1},
    direct_object_transport::{
        ZK_AMS_MKHE_DIRECT_OBJECT_POINTER_BYTES_V1, ZK_AMS_MKHE_DIRECT_OBJECT_READ_BYTES_V1,
        ZkAmsMkheDirectObjectKindV1, ZkAmsMkheDirectObjectPointerV1,
        ZkAmsMkheDirectObjectReadAtProviderV1, ZkAmsMkheDirectObjectReadReceiptV1,
        ZkAmsMkheDirectObjectReadTransactionV1,
    },
    exact_eight_chunk_membership::{
        CpkErrorMembershipRoleV1, ExactEightChunkMembershipContextV1,
        ExactEightChunkMembershipErrorV1 as ExactError, ExactEightChunkMembershipEvidenceV1,
        VerifiedExactEightChunkMembershipV1, ZK_AMS_MKHE_CPK_ERROR_MEMBERSHIP_WIRE_BYTES_V1,
    },
    manifest::{
        ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1, release_profile_v1, zk_ams_mkhe_security_certificate_v1,
    },
    mod_add, mod_mul, mod_sub, negacyclic_multiply,
    persistent_membership_evidence::{
        ZK_AMS_MKHE_PERSISTENT_MEMBERSHIP_WIRE_BYTES_V1, ZkAmsMkhePersistentMembershipContextV1,
        ZkAmsMkhePersistentMembershipEvidenceV1, ZkAmsMkheVerifiedPersistentMembershipV1,
    },
    signed_mod,
    wire::ZkAmsMkheAuthenticationWireV1,
};
use crate::{
    generalized_bulletproof::{
        GeneralizedBulletproofErrorV1 as BpError, ProofRandomSource, ProofSuite,
        try_exact_capacity_vec_v1, try_exact_multiexp_v1,
    },
    vega::{
        MaskedRelaxedRandomSourceV1, VegaT256PointV1 as Point, VegaT256ScalarV1 as Scalar,
        bulletproof_t256::{
            ZK_AMS_MEMBERSHIP_CHUNK_COEFFICIENTS_V1, ZK_AMS_T256_BP_GENERATOR_BASIS_DIGEST_V1,
            ZkAmsT256BulletproofSuiteV1, ZkAmsT256MembershipErrorV1 as MembershipError,
            ZkAmsT256MembershipProofV1,
        },
        sponge::{Keccak256, Shake256Reader},
    },
};
use core::{
    fmt,
    sync::atomic::{Ordering, compiler_fence},
};
use thiserror::Error;
#[path = "cpk_relation_common_a.rs"]
mod common_a;
#[path = "cpk_relation/state_owned_creator_v1.rs"]
mod state_owned_creator_v1;
#[path = "cpk_relation/state_owned_secret_adapter_v1.rs"]
pub(super) mod state_owned_secret_adapter_v1;
pub(super) use common_a::{
    ZkAmsMkhePreparedCollectivePublicAContextV1, active_collective_public_a_limb_frame_bytes_v1,
    prepare_active_collective_public_a_v1,
};
pub(super) use state_owned_creator_v1::publish_canonical_cpk_relation_proof_v1;
const CPK_SHARE_STATEMENT_MAGIC_V1: [u8; 4] = *b"ZCPS";
const CPK_RELATION_PROOF_MAGIC_V1: [u8; 4] = *b"ZCPR";
const CPK_RELATION_ALGORITHM_V1: u8 = 1;
const CPK_PUBLIC_A_DERIVATION_ALGORITHM_V1: u8 = 1;
const CPK_RELATION_FLAGS_V1: u16 = 0;
/// Sealed direct-object tag for the exact party-local CPK `b` polynomial.
pub(super) const ZK_AMS_MKHE_CPK_PARTY_B_OBJECT_TAG_V1: u8 =
    ZkAmsMkheDirectObjectKindV1::CpkPartyB as u8;
/// Sealed direct-object tag for the exact native CPK relation proof.
pub(super) const ZK_AMS_MKHE_CPK_RELATION_PROOF_OBJECT_TAG_V1: u8 =
    ZkAmsMkheDirectObjectKindV1::CpkRelationProof as u8;
/// Exact release ring degree.
pub(super) const ZK_AMS_MKHE_CPK_RING_DEGREE_V1: usize = 131_072;
/// Exact release RNS-limb count.
pub(super) const ZK_AMS_MKHE_CPK_RNS_LIMBS_V1: usize = 38;
/// Exact coefficients in one membership/commitment chunk.
pub(super) const ZK_AMS_MKHE_CPK_CHUNK_COEFFICIENTS_V1: usize =
    ZK_AMS_MEMBERSHIP_CHUNK_COEFFICIENTS_V1;
/// Exact chunks for each secret or error polynomial.
pub(super) const ZK_AMS_MKHE_CPK_CHUNKS_V1: usize = 8;
/// Secret and error are the two relation witnesses.
pub(super) const ZK_AMS_MKHE_CPK_RELATION_WITNESSES_V1: usize = 2;
/// Four parallel 32-bit challenge coordinates give 128-bit soundness.
pub(super) const ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1: usize = 4;
/// Exact bits in each challenge coordinate.
pub(super) const ZK_AMS_MKHE_CPK_CHALLENGE_BITS_V1: usize = 32;
/// Largest possible shift `c*w` for `c <= u32::MAX` and `|w| <= 2`.
pub(super) const ZK_AMS_MKHE_CPK_CHALLENGE_SHIFT_BOUND_V1: i64 = 8_589_934_590;
/// Exact uniform mask interval is `[-M, M]`.
pub(super) const ZK_AMS_MKHE_CPK_MASK_BOUND_V1: i64 = 144_115_188_042_301_440;
/// Exact common response interval is `[-B, B]`.
pub(super) const ZK_AMS_MKHE_CPK_RESPONSE_BOUND_V1: i64 = 144_115_179_452_366_850;
/// Largest integer difference that must lift uniquely in a two-fork extractor.
pub(super) const ZK_AMS_MKHE_CPK_MAX_FORK_LIFT_DIFFERENCE_V1: i64 =
    2 * ZK_AMS_MKHE_CPK_RESPONSE_BOUND_V1 + ZK_AMS_MKHE_CPK_CHALLENGE_SHIFT_BOUND_V1;
/// Hard whole-attempt retry ceiling.  The ordinal is never transcript material.
pub(super) const ZK_AMS_MKHE_CPK_OUTER_RETRY_CEILING_V1: usize = 128;
const CPK_INTEGER_SAMPLER_RETRY_CEILING_V1: usize = 128;
const CPK_SIGNED_RESPONSE_BYTES_V1: usize = 8;
const CPK_T256_SCALAR_BYTES_V1: usize = 32;
const CPK_T256_POINT_BYTES_V1: usize = 33;
const CPK_CHALLENGE_SEED_BYTES_V1: usize = 32;
/// Exact canonical party-`b` payload length: `u32 || 38*131072*u64`.
pub(super) const ZK_AMS_MKHE_CPK_PARTY_B_OBJECT_BYTES_V1: usize =
    4 + ZK_AMS_MKHE_CPK_RNS_LIMBS_V1 * ZK_AMS_MKHE_CPK_RING_DEGREE_V1 * 8;
/// Existing content-addressed pointer-frame width.
pub(super) const ZK_AMS_MKHE_CPK_OBJECT_POINTER_BYTES_V1: usize =
    ZK_AMS_MKHE_DIRECT_OBJECT_POINTER_BYTES_V1;
/// Exact canonical CPK share-statement width.
pub(super) const ZK_AMS_MKHE_CPK_SHARE_STATEMENT_BYTES_V1: usize = 362;
/// Exact canonical fixed relation-proof header width.
pub(super) const ZK_AMS_MKHE_CPK_RELATION_HEADER_BYTES_V1: usize = 208;
/// Exact canonical signed-response payload width.
pub(super) const ZK_AMS_MKHE_CPK_RESPONSE_PAYLOAD_BYTES_V1: usize =
    ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1
        * ZK_AMS_MKHE_CPK_RELATION_WITNESSES_V1
        * ZK_AMS_MKHE_CPK_RING_DEGREE_V1
        * CPK_SIGNED_RESPONSE_BYTES_V1;
/// Exact canonical response-blinding payload width.
pub(super) const ZK_AMS_MKHE_CPK_BLIND_RESPONSE_PAYLOAD_BYTES_V1: usize =
    ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1
        * ZK_AMS_MKHE_CPK_RELATION_WITNESSES_V1
        * ZK_AMS_MKHE_CPK_CHUNKS_V1
        * CPK_T256_SCALAR_BYTES_V1;
/// Exact proof body: seed, signed responses, and T256 response blindings.
pub(super) const ZK_AMS_MKHE_CPK_RELATION_BODY_BYTES_V1: usize = CPK_CHALLENGE_SEED_BYTES_V1
    + ZK_AMS_MKHE_CPK_RESPONSE_PAYLOAD_BYTES_V1
    + ZK_AMS_MKHE_CPK_BLIND_RESPONSE_PAYLOAD_BYTES_V1;
/// Exact complete relation-proof object width.
pub(super) const ZK_AMS_MKHE_CPK_RELATION_PROOF_BYTES_V1: usize =
    ZK_AMS_MKHE_CPK_RELATION_HEADER_BYTES_V1 + ZK_AMS_MKHE_CPK_RELATION_BODY_BYTES_V1;
/// Exact bound-one persistent-secret membership evidence width.
pub(super) const ZK_AMS_MKHE_CPK_SECRET_MEMBERSHIP_BYTES_V1: usize =
    ZK_AMS_MKHE_PERSISTENT_MEMBERSHIP_WIRE_BYTES_V1;
/// Exact analogous bound-two public-error membership evidence width.
pub(super) const ZK_AMS_MKHE_CPK_ERROR_MEMBERSHIP_BYTES_V1: usize =
    ZK_AMS_MKHE_CPK_ERROR_MEMBERSHIP_WIRE_BYTES_V1;
/// Admission stays closed until the complete verifier is connected to the collective-key runtime.
pub(super) const ZK_AMS_MKHE_CPK_RELATION_VERIFICATION_GATE_V1: bool = false;
const CPK_SHARE_STATEMENT_DIGEST_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.cpk-share-statement";
const CPK_SECRET_MEMBERSHIP_WIRE_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.cpk-secret-membership-wire";
const CPK_ERROR_MEMBERSHIP_WIRE_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.cpk-error-membership-wire";
const CPK_COMMITMENT_FIRST_MESSAGE_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.cpk-relation.commitment-first-message";
const CPK_RNS_FIRST_MESSAGE_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.cpk-relation.rns-first-message";
const CPK_CHALLENGE_VECTOR_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.cpk-relation.challenge-vector";
const CPK_CHALLENGE_COORDINATE_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.cpk-relation.challenge-coordinate";
const CPK_VERIFIED_RELATION_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.cpk-relation.verified-receipt";
const CPK_PUBLIC_A_CONTEXT_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.cpk-relation.public-a-context";
// This is the frozen domain consumed by `active::derive_active_collective_public_a`.
// The release KAT below compares the streamed limb derivation with that canonical
// whole-polynomial implementation so the two paths cannot silently diverge.
const ACTIVE_COLLECTIVE_PUBLIC_A_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.active-collective-public-a";
const CPK_CONTRIBUTION_AUTH_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.cpk-relation.authenticated-contribution";
const CPK_COMPLETE_CONTRIBUTION_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.cpk-relation.complete-contribution";
const CPK_AUTHENTICATION_WIRE_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.cpk-relation.authentication-wire";
const _: () = {
    assert!(ZK_AMS_MKHE_CPK_PARTY_B_OBJECT_TAG_V1 == 9);
    assert!(ZK_AMS_MKHE_CPK_RELATION_PROOF_OBJECT_TAG_V1 == 10);
    assert!(ZK_AMS_MKHE_CPK_RING_DEGREE_V1 == 1 << 17);
    assert!(ZK_AMS_MKHE_CPK_CHUNK_COEFFICIENTS_V1 == 1 << 14);
    assert!(
        ZK_AMS_MKHE_CPK_CHUNKS_V1 * ZK_AMS_MKHE_CPK_CHUNK_COEFFICIENTS_V1
            == ZK_AMS_MKHE_CPK_RING_DEGREE_V1
    );
    assert!(ZK_AMS_MKHE_CPK_CHALLENGE_SHIFT_BOUND_V1 == 2 * u32::MAX as i64);
    assert!(ZK_AMS_MKHE_CPK_MASK_BOUND_V1 == ZK_AMS_MKHE_CPK_CHALLENGE_SHIFT_BOUND_V1 * (1 << 24));
    assert!(
        ZK_AMS_MKHE_CPK_RESPONSE_BOUND_V1
            == ZK_AMS_MKHE_CPK_MASK_BOUND_V1 - ZK_AMS_MKHE_CPK_CHALLENGE_SHIFT_BOUND_V1
    );
    assert!(ZK_AMS_MKHE_CPK_MAX_FORK_LIFT_DIFFERENCE_V1 == 288_230_367_494_668_290);
    assert!(ZK_AMS_MKHE_CPK_MAX_FORK_LIFT_DIFFERENCE_V1 < (1_i64 << 59));
    assert!(ZK_AMS_MKHE_CPK_PARTY_B_OBJECT_BYTES_V1 == 39_845_892);
    assert!(ZK_AMS_MKHE_CPK_OBJECT_POINTER_BYTES_V1 == 78);
    assert!(ZK_AMS_MKHE_CPK_SHARE_STATEMENT_BYTES_V1 == 362);
    assert!(ZK_AMS_MKHE_CPK_RELATION_HEADER_BYTES_V1 == 208);
    assert!(ZK_AMS_MKHE_CPK_RESPONSE_PAYLOAD_BYTES_V1 == 8_388_608);
    assert!(ZK_AMS_MKHE_CPK_BLIND_RESPONSE_PAYLOAD_BYTES_V1 == 2_048);
    assert!(ZK_AMS_MKHE_CPK_RELATION_BODY_BYTES_V1 == 8_390_688);
    assert!(ZK_AMS_MKHE_CPK_RELATION_PROOF_BYTES_V1 == 8_390_896);
    assert!(ZK_AMS_MKHE_CPK_RELATION_PROOF_BYTES_V1 < 32 * 1024 * 1024);
    assert!(!ZK_AMS_MKHE_CPK_RELATION_VERIFICATION_GATE_V1);
};
// TODO: Connect the complete native receipt below to the collective-key share
// admission/runtime and archive its release-size four-peer KAT before opening
// `ZK_AMS_MKHE_CPK_RELATION_VERIFICATION_GATE_V1`.
/// Stable errors at the exact native CPK relation boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(super) enum ZkAmsMkheCpkRelationErrorV1 {
    /// A content-addressed object pointer is malformed or has the wrong sealed role.
    #[error("invalid canonical ZK-AMS CPK object pointer")]
    ObjectPointer,
    /// A canonical share statement is malformed or omits a required source axis.
    #[error("invalid canonical ZK-AMS CPK share statement")]
    ShareStatement,
    /// A relation-proof header is malformed or inconsistent with its statement/evidence.
    #[error("invalid canonical ZK-AMS CPK relation header")]
    RelationHeader,
    /// A relation-proof body is truncated, extended, malformed, or non-canonical.
    #[error("invalid canonical ZK-AMS CPK relation body")]
    RelationBody,
    /// A signed response lies outside the exact common box.
    #[error("ZK-AMS CPK response rejected outside the exact common box")]
    ResponseRejected,
    /// An honestly reconstructed commitment first message was the identity.
    #[error("ZK-AMS CPK commitment first message rejected at the identity")]
    FirstMessageRejected,
    /// A secret or error witness does not have the exact release shape/range.
    #[error("invalid ZK-AMS CPK witness shape or coefficient")]
    Witness,
    /// One role-specific membership frame or proof set is invalid.
    #[error("invalid ZK-AMS CPK secret/error membership evidence")]
    MembershipEvidence,
    /// Independently governed profile, roster, party, epoch, or transcript axes disagree.
    #[error("invalid independently governed ZK-AMS CPK relation context")]
    GovernedContext,
    /// A direct-object provider failed, drifted, or supplied bytes outside the content address.
    #[error("invalid ZK-AMS CPK direct-object transaction")]
    DirectObject,
    /// A native polynomial equation failed or used a malformed canonical polynomial.
    #[error("invalid ZK-AMS CPK native RNS relation")]
    NativeRelation,
    /// The governed party authentication does not bind the complete contribution.
    #[error("invalid ZK-AMS CPK contribution authentication")]
    Authentication,
    /// The cryptographic random source failed or exhausted unbiased sampling retries.
    #[error("ZK-AMS CPK cryptographic random source unavailable")]
    RandomUnavailable,
    /// Every bounded Fiat--Shamir-with-aborts attempt was rejected.
    #[error("ZK-AMS CPK whole-attempt retry ceiling exhausted")]
    RetryExhausted,
    /// Transcript axes, ordering, or challenge reconstruction are inconsistent.
    #[error("invalid ZK-AMS CPK relation transcript")]
    Transcript,
    /// An RNS first-message stream is malformed, reordered, or non-canonical.
    #[error("invalid ZK-AMS CPK RNS first-message stream")]
    RnsFirstMessage,
    /// A checked allocation or size computation exceeded the governed shape.
    #[error("ZK-AMS CPK relation resource ceiling exceeded")]
    ResourceCeiling,
}
/// Sealed exact pointer to a party-local CPK `b` object (direct-object tag 9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ZkAmsMkheCpkPartyBPointerV1(ZkAmsMkheDirectObjectPointerV1);
impl ZkAmsMkheCpkPartyBPointerV1 {
    /// Construct the sole party-`b` pointer shape from a complete content hash.
    pub(super) fn new(payload_blake3: [u8; 32]) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        ZkAmsMkheDirectObjectPointerV1::new(
            ZkAmsMkheDirectObjectKindV1::CpkPartyB,
            ZK_AMS_MKHE_CPK_PARTY_B_OBJECT_BYTES_V1 as u64,
            payload_blake3,
        )
        .map(Self)
        .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ObjectPointer)
    }
    /// Decode exactly one tag-9 pointer; tags 1--8 and 10 are never aliases.
    pub(super) fn from_wire_bytes_exact(bytes: &[u8]) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        let pointer = ZkAmsMkheDirectObjectPointerV1::decode_exact(
            ZkAmsMkheDirectObjectKindV1::CpkPartyB,
            bytes,
        )
        .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ObjectPointer)?;
        if pointer.payload_bytes() != ZK_AMS_MKHE_CPK_PARTY_B_OBJECT_BYTES_V1 as u64 {
            return Err(ZkAmsMkheCpkRelationErrorV1::ObjectPointer);
        }
        Ok(Self(pointer))
    }
    /// Encode the existing 78-byte direct-object pointer frame.
    #[must_use]
    pub(super) fn to_wire_bytes(self) -> [u8; ZK_AMS_MKHE_CPK_OBJECT_POINTER_BYTES_V1] {
        self.0.encode()
    }
    /// Complete BLAKE3 content address of the exact party-`b` object.
    #[must_use]
    pub(super) const fn payload_blake3(self) -> [u8; 32] {
        self.0.payload_blake3()
    }
    /// Keccak binding of kind, exact length, and content address.
    #[must_use]
    pub(super) const fn pointer_digest(self) -> [u8; 32] {
        self.0.pointer_digest()
    }
    /// Exact direct-object pointer retained by the verified CPK statement.
    ///
    /// This remains crate-private: a bare pointer is public data, not a CPK
    /// verification capability.
    #[must_use]
    pub(super) const fn direct_object_pointer(self) -> ZkAmsMkheDirectObjectPointerV1 {
        self.0
    }
}
/// Sealed exact pointer to one CPK relation proof object (direct-object tag 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ZkAmsMkheCpkRelationProofPointerV1(ZkAmsMkheDirectObjectPointerV1);
impl ZkAmsMkheCpkRelationProofPointerV1 {
    /// Construct the sole relation-proof pointer shape from a complete content hash.
    pub(super) fn new(payload_blake3: [u8; 32]) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        ZkAmsMkheDirectObjectPointerV1::new(
            ZkAmsMkheDirectObjectKindV1::CpkRelationProof,
            ZK_AMS_MKHE_CPK_RELATION_PROOF_BYTES_V1 as u64,
            payload_blake3,
        )
        .map(Self)
        .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ObjectPointer)
    }
    /// Decode exactly one tag-10 pointer; no generic proof tag is accepted.
    pub(super) fn from_wire_bytes_exact(bytes: &[u8]) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        let pointer = ZkAmsMkheDirectObjectPointerV1::decode_exact(
            ZkAmsMkheDirectObjectKindV1::CpkRelationProof,
            bytes,
        )
        .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ObjectPointer)?;
        if pointer.payload_bytes() != ZK_AMS_MKHE_CPK_RELATION_PROOF_BYTES_V1 as u64 {
            return Err(ZkAmsMkheCpkRelationErrorV1::ObjectPointer);
        }
        Ok(Self(pointer))
    }
    /// Encode the existing 78-byte direct-object pointer frame.
    #[must_use]
    pub(super) fn to_wire_bytes(self) -> [u8; ZK_AMS_MKHE_CPK_OBJECT_POINTER_BYTES_V1] {
        self.0.encode()
    }
    /// Complete BLAKE3 content address of the exact proof object.
    #[must_use]
    pub(super) const fn payload_blake3(self) -> [u8; 32] {
        self.0.payload_blake3()
    }
    /// Keccak binding of kind, exact length, and content address.
    #[must_use]
    pub(super) const fn pointer_digest(self) -> [u8; 32] {
        self.0.pointer_digest()
    }
}
/// Complete stable statement that precedes membership and relation evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ZkAmsMkheCpkShareStatementV1 {
    generator_basis_digest: [u8; 32],
    profile_digest: [u8; 32],
    security_certificate_digest: [u8; 32],
    roster_digest: [u8; 32],
    key_material_digest: [u8; 32],
    cpk_transcript_digest: [u8; 32],
    /// Statement binding only.  It is non-authoritative until the verifier
    /// recomputes the versioned per-limb public-`a` derivation from trusted axes.
    public_a_context_digest: [u8; 32],
    party: ZkAmsMkhePartyIdV1,
    party_index: u8,
    epoch: u64,
    party_b_pointer: ZkAmsMkheCpkPartyBPointerV1,
}
impl ZkAmsMkheCpkShareStatementV1 {
    /// Construct a canonical source statement from already governed axes.
    ///
    /// The eventual verifier must obtain these digests from its trusted
    /// profile, certificate, roster, and deterministic public-`a` context.  A
    /// decoded statement is not itself authority for those values.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        profile_digest: [u8; 32],
        security_certificate_digest: [u8; 32],
        roster_digest: [u8; 32],
        key_material_digest: [u8; 32],
        cpk_transcript_digest: [u8; 32],
        public_a_context_digest: [u8; 32],
        party: ZkAmsMkhePartyIdV1,
        party_index: u8,
        epoch: u64,
        party_b_pointer: ZkAmsMkheCpkPartyBPointerV1,
    ) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        let statement = Self {
            generator_basis_digest: ZK_AMS_T256_BP_GENERATOR_BASIS_DIGEST_V1,
            profile_digest,
            security_certificate_digest,
            roster_digest,
            key_material_digest,
            cpk_transcript_digest,
            public_a_context_digest,
            party,
            party_index,
            epoch,
            party_b_pointer,
        };
        statement.validate()?;
        Ok(statement)
    }
    /// Construct the sole statement accepted under an independently governed roster.
    ///
    /// Profile, security-certificate, roster, key-material, epoch, party, and deterministic
    /// public-`a` axes are derived here instead of copied from an untrusted proof envelope.
    pub(super) fn from_governed_roster(
        roster: &ZkAmsMkheGovernedActiveRosterV1,
        cpk_transcript_digest: [u8; 32],
        party_index: usize,
        party_b_pointer: ZkAmsMkheCpkPartyBPointerV1,
    ) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        roster
            .validate()
            .map_err(|_| ZkAmsMkheCpkRelationErrorV1::GovernedContext)?;
        if cpk_transcript_digest == [0; 32] || party_index >= ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 {
            return Err(ZkAmsMkheCpkRelationErrorV1::GovernedContext);
        }
        let profile = release_profile_v1();
        let security_certificate_digest = zk_ams_mkhe_security_certificate_v1()
            .map_err(|_| ZkAmsMkheCpkRelationErrorV1::GovernedContext)?
            .certificate_digest();
        let party = roster.participants()[party_index].party();
        Self::new(
            profile
                .digest()
                .map_err(|_| ZkAmsMkheCpkRelationErrorV1::GovernedContext)?,
            security_certificate_digest,
            roster.roster_digest(),
            roster.key_material_digest(),
            cpk_transcript_digest,
            cpk_public_a_context_digest_v1(&profile, roster, cpk_transcript_digest)?,
            party,
            u8::try_from(party_index).map_err(|_| ZkAmsMkheCpkRelationErrorV1::GovernedContext)?,
            roster.epoch(),
            party_b_pointer,
        )
    }
    fn validate(self) -> Result<(), ZkAmsMkheCpkRelationErrorV1> {
        if self.generator_basis_digest != ZK_AMS_T256_BP_GENERATOR_BASIS_DIGEST_V1
            || [
                self.profile_digest,
                self.security_certificate_digest,
                self.roster_digest,
                self.key_material_digest,
                self.cpk_transcript_digest,
                self.public_a_context_digest,
                self.party.to_bytes(),
            ]
            .contains(&[0; 32])
            || usize::from(self.party_index) >= 8
            || self.epoch == 0
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::ShareStatement);
        }
        if self.party_b_pointer.0.kind() != ZkAmsMkheDirectObjectKindV1::CpkPartyB
            || self.party_b_pointer.0.payload_bytes()
                != ZK_AMS_MKHE_CPK_PARTY_B_OBJECT_BYTES_V1 as u64
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::ShareStatement);
        }
        Ok(())
    }
    fn validate_against_governed_roster(
        self,
        roster: &ZkAmsMkheGovernedActiveRosterV1,
        expected_cpk_transcript_digest: [u8; 32],
    ) -> Result<BgvProfile, ZkAmsMkheCpkRelationErrorV1> {
        self.validate()?;
        roster
            .validate()
            .map_err(|_| ZkAmsMkheCpkRelationErrorV1::GovernedContext)?;
        let profile = release_profile_v1();
        let party_index = usize::from(self.party_index);
        let expected_security = zk_ams_mkhe_security_certificate_v1()
            .map_err(|_| ZkAmsMkheCpkRelationErrorV1::GovernedContext)?
            .certificate_digest();
        if expected_cpk_transcript_digest == [0; 32]
            || self.profile_digest
                != profile
                    .digest()
                    .map_err(|_| ZkAmsMkheCpkRelationErrorV1::GovernedContext)?
            || self.security_certificate_digest != expected_security
            || self.roster_digest != roster.roster_digest()
            || self.key_material_digest != roster.key_material_digest()
            || self.cpk_transcript_digest != expected_cpk_transcript_digest
            || self.epoch != roster.epoch()
            || party_index >= ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1
            || self.party != roster.participants()[party_index].party()
            || self.public_a_context_digest
                != cpk_public_a_context_digest_v1(&profile, roster, expected_cpk_transcript_digest)?
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::GovernedContext);
        }
        Ok(profile)
    }
    /// Encode the unique 362-byte, big-endian statement frame.
    pub(super) fn to_wire_bytes(
        self,
    ) -> Result<[u8; ZK_AMS_MKHE_CPK_SHARE_STATEMENT_BYTES_V1], ZkAmsMkheCpkRelationErrorV1> {
        self.validate()?;
        let mut bytes = [0_u8; ZK_AMS_MKHE_CPK_SHARE_STATEMENT_BYTES_V1];
        bytes[..4].copy_from_slice(&CPK_SHARE_STATEMENT_MAGIC_V1);
        bytes[4] = MKHE_VERSION_V1;
        bytes[5] = CPK_RELATION_ALGORITHM_V1;
        bytes[6] = CPK_PUBLIC_A_DERIVATION_ALGORITHM_V1;
        bytes[7] = 0;
        bytes[8..12].copy_from_slice(&(ZK_AMS_MKHE_CPK_RING_DEGREE_V1 as u32).to_be_bytes());
        bytes[12..14].copy_from_slice(&(ZK_AMS_MKHE_CPK_RNS_LIMBS_V1 as u16).to_be_bytes());
        bytes[14..18]
            .copy_from_slice(&(ZK_AMS_MKHE_CPK_CHUNK_COEFFICIENTS_V1 as u32).to_be_bytes());
        bytes[18] = ZK_AMS_MKHE_CPK_CHUNKS_V1 as u8;
        bytes[19] = self.party_index;
        bytes[20..28].copy_from_slice(&self.epoch.to_be_bytes());
        bytes[28..60].copy_from_slice(&self.generator_basis_digest);
        bytes[60..92].copy_from_slice(&self.profile_digest);
        bytes[92..124].copy_from_slice(&self.security_certificate_digest);
        bytes[124..156].copy_from_slice(&self.roster_digest);
        bytes[156..188].copy_from_slice(&self.key_material_digest);
        bytes[188..220].copy_from_slice(&self.cpk_transcript_digest);
        bytes[220..252].copy_from_slice(&self.public_a_context_digest);
        bytes[252..284].copy_from_slice(&self.party.to_bytes());
        bytes[284..362].copy_from_slice(&self.party_b_pointer.to_wire_bytes());
        Ok(bytes)
    }
    /// Decode exactly one statement and reject all alternate dimensions or reserved bytes.
    pub(super) fn from_wire_bytes_exact(bytes: &[u8]) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        if bytes.len() != ZK_AMS_MKHE_CPK_SHARE_STATEMENT_BYTES_V1
            || bytes[..4] != CPK_SHARE_STATEMENT_MAGIC_V1
            || bytes[4] != MKHE_VERSION_V1
            || bytes[5] != CPK_RELATION_ALGORITHM_V1
            || bytes[6] != CPK_PUBLIC_A_DERIVATION_ALGORITHM_V1
            || bytes[7] != 0
            || u32::from_be_bytes(array_at::<4>(bytes, 8)?) != ZK_AMS_MKHE_CPK_RING_DEGREE_V1 as u32
            || u16::from_be_bytes(array_at::<2>(bytes, 12)?) != ZK_AMS_MKHE_CPK_RNS_LIMBS_V1 as u16
            || u32::from_be_bytes(array_at::<4>(bytes, 14)?)
                != ZK_AMS_MKHE_CPK_CHUNK_COEFFICIENTS_V1 as u32
            || bytes[18] != ZK_AMS_MKHE_CPK_CHUNKS_V1 as u8
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::ShareStatement);
        }
        let statement = Self {
            generator_basis_digest: array_at::<32>(bytes, 28)?,
            profile_digest: array_at::<32>(bytes, 60)?,
            security_certificate_digest: array_at::<32>(bytes, 92)?,
            roster_digest: array_at::<32>(bytes, 124)?,
            key_material_digest: array_at::<32>(bytes, 156)?,
            cpk_transcript_digest: array_at::<32>(bytes, 188)?,
            public_a_context_digest: array_at::<32>(bytes, 220)?,
            party: ZkAmsMkhePartyIdV1::new(array_at::<32>(bytes, 252)?)
                .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ShareStatement)?,
            party_index: bytes[19],
            epoch: u64::from_be_bytes(array_at::<8>(bytes, 20)?),
            party_b_pointer: ZkAmsMkheCpkPartyBPointerV1::from_wire_bytes_exact(&bytes[284..362])
                .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ShareStatement)?,
        };
        statement.validate()?;
        Ok(statement)
    }
    /// Stable digest of the complete canonical statement, excluding no source axis.
    pub(super) fn statement_digest(self) -> Result<[u8; 32], ZkAmsMkheCpkRelationErrorV1> {
        let wire = self.to_wire_bytes()?;
        Ok(framed_wire_digest(
            CPK_SHARE_STATEMENT_DIGEST_DOMAIN_V1,
            &wire,
        ))
    }
    /// Exact content-addressed party-`b` pointer bound by this statement.
    #[must_use]
    pub(super) const fn party_b_pointer(self) -> ZkAmsMkheCpkPartyBPointerV1 {
        self.party_b_pointer
    }
    /// Exact governed contributor.
    #[must_use]
    pub(super) const fn party(self) -> ZkAmsMkhePartyIdV1 {
        self.party
    }
    /// Exact governed roster position.
    #[must_use]
    pub(super) const fn party_index(self) -> usize {
        self.party_index as usize
    }
}
/// Complete role-separated context for the public CPK error polynomial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ZkAmsMkheCpkErrorMembershipContextV1 {
    inner: ExactEightChunkMembershipContextV1<CpkErrorMembershipRoleV1>,
}
impl ZkAmsMkheCpkErrorMembershipContextV1 {
    /// Derive all seven repeated axes plus the digest of the complete CPK statement.
    pub(super) fn from_share_statement(
        statement: ZkAmsMkheCpkShareStatementV1,
    ) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        statement.validate()?;
        ExactEightChunkMembershipContextV1::new(
            statement.profile_digest,
            statement.roster_digest,
            statement.key_material_digest,
            statement.epoch,
            statement.cpk_transcript_digest,
            statement.party,
            statement.statement_digest()?,
        )
        .map(|inner| Self { inner })
        .map_err(|_| ZkAmsMkheCpkRelationErrorV1::MembershipEvidence)
    }
    #[must_use]
    pub(super) const fn profile_digest(self) -> [u8; 32] {
        self.inner.profile_digest()
    }
    #[must_use]
    pub(super) const fn roster_digest(self) -> [u8; 32] {
        self.inner.roster_digest()
    }
    #[must_use]
    pub(super) const fn key_material_digest(self) -> [u8; 32] {
        self.inner.key_material_digest()
    }
    #[must_use]
    pub(super) const fn epoch(self) -> u64 {
        self.inner.epoch()
    }
    #[must_use]
    pub(super) const fn cpk_transcript_digest(self) -> [u8; 32] {
        self.inner.cpk_transcript_digest()
    }
    #[must_use]
    pub(super) const fn party(self) -> ZkAmsMkhePartyIdV1 {
        self.inner.party()
    }
    #[must_use]
    pub(super) const fn share_statement_digest(self) -> [u8; 32] {
        self.inner.share_statement_digest()
    }
    /// Error-role transcript context digest.
    #[must_use]
    pub(super) fn context_digest(self) -> [u8; 32] {
        self.inner.context_digest()
    }
}
fn map_membership_prover_error_v1(error: MembershipError) -> ZkAmsMkheCpkRelationErrorV1 {
    use BpError::{ProverRandomnessExhausted, RandomnessUnavailable, ResourceOverflow};
    use MembershipError::Backend;
    use ZkAmsMkheCpkRelationErrorV1 as Error;
    match error {
        Backend(RandomnessUnavailable | ProverRandomnessExhausted) => Error::RandomUnavailable,
        Backend(ResourceOverflow) => Error::ResourceCeiling,
        _ => Error::MembershipEvidence,
    }
}
fn map_exact_membership_error_v1(error: ExactError) -> ZkAmsMkheCpkRelationErrorV1 {
    let ExactError::Membership(error) = error else {
        return ZkAmsMkheCpkRelationErrorV1::MembershipEvidence;
    };
    map_membership_prover_error_v1(error)
}
/// Canonical eight-chunk bound-two evidence for the public CPK error polynomial.
///
/// This type is not interchangeable with persistent-secret membership even
/// though both use the same T256 generator basis and release chunk geometry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ZkAmsMkheCpkErrorMembershipEvidenceV1 {
    inner: ExactEightChunkMembershipEvidenceV1<CpkErrorMembershipRoleV1>,
}
impl ZkAmsMkheCpkErrorMembershipEvidenceV1 {
    /// Prove and locally verify all eight bound-two error chunks.
    pub(super) fn prove<R: ProofRandomSource>(
        context: ZkAmsMkheCpkErrorMembershipContextV1,
        coefficients: &[i8],
        blindings: &[Scalar; ZK_AMS_MKHE_CPK_CHUNKS_V1],
        random: &mut R,
    ) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        ExactEightChunkMembershipEvidenceV1::prove(context.inner, coefficients, blindings, random)
            .map(|inner| Self { inner })
            .map_err(map_exact_membership_error_v1)
    }
    /// Verify and assemble eight externally supplied bound-two chunks.
    pub(super) fn from_proof_chunks_verified(
        context: ZkAmsMkheCpkErrorMembershipContextV1,
        chunks: [ZkAmsT256MembershipProofV1; ZK_AMS_MKHE_CPK_CHUNKS_V1],
    ) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        ExactEightChunkMembershipEvidenceV1::from_proof_chunks_verified(context.inner, chunks)
            .map(|inner| Self { inner })
            .map_err(|_| ZkAmsMkheCpkRelationErrorV1::MembershipEvidence)
    }
    /// Strictly decode exactly 12,819 bytes with the `ZCEM` role frame.
    pub(super) fn from_wire_bytes_exact(bytes: &[u8]) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        ExactEightChunkMembershipEvidenceV1::from_wire_bytes_exact(bytes)
            .map(|inner| Self { inner })
            .map_err(|_| ZkAmsMkheCpkRelationErrorV1::MembershipEvidence)
    }
    /// Encode the unique 12,819-byte CPK-error membership frame.
    pub(super) fn to_wire_bytes(&self) -> Result<Vec<u8>, ZkAmsMkheCpkRelationErrorV1> {
        self.inner
            .to_wire_bytes()
            .map_err(map_exact_membership_error_v1)
    }
    pub(super) fn into_wire_bytes(self) -> Result<Vec<u8>, ZkAmsMkheCpkRelationErrorV1> {
        self.to_wire_bytes()
    }
    /// Replay all eight bound-two proofs without retaining a capability.
    pub(super) fn verify(&self) -> Result<(), ZkAmsMkheCpkRelationErrorV1> {
        self.inner
            .verify()
            .map_err(|_| ZkAmsMkheCpkRelationErrorV1::MembershipEvidence)
    }
    /// Consume the evidence and return a move-only membership-only receipt.
    pub(super) fn into_verified(
        self,
    ) -> Result<ZkAmsMkheVerifiedCpkErrorMembershipV1, ZkAmsMkheCpkRelationErrorV1> {
        self.inner
            .into_verified()
            .map(|inner| ZkAmsMkheVerifiedCpkErrorMembershipV1 { inner })
            .map_err(|_| ZkAmsMkheCpkRelationErrorV1::MembershipEvidence)
    }
    #[must_use]
    pub(super) const fn context(&self) -> ZkAmsMkheCpkErrorMembershipContextV1 {
        ZkAmsMkheCpkErrorMembershipContextV1 {
            inner: self.inner.context(),
        }
    }
    #[must_use]
    pub(super) const fn chunks(&self) -> &[ZkAmsT256MembershipProofV1; ZK_AMS_MKHE_CPK_CHUNKS_V1] {
        self.inner.chunks()
    }
    #[must_use]
    pub(super) fn commitments(&self) -> [Point; ZK_AMS_MKHE_CPK_CHUNKS_V1] {
        self.inner.commitments()
    }
    #[must_use]
    pub(super) const fn generator_basis_digest(&self) -> [u8; 32] {
        self.inner.generator_basis_digest()
    }
    #[must_use]
    pub(super) const fn commitment_set_digest(&self) -> [u8; 32] {
        self.inner.commitment_set_digest()
    }
    #[must_use]
    pub(super) const fn proof_set_digest(&self) -> [u8; 32] {
        self.inner.proof_set_digest()
    }
    #[must_use]
    pub(super) const fn verifier_transcript_digest(&self) -> [u8; 32] {
        self.inner.verifier_transcript_digest()
    }
}
/// Move-only proof-verified membership receipt for the CPK error role.
///
/// It is deliberately membership-only and cannot construct a relation receipt
/// or active persistent-witness binding.
pub(super) struct ZkAmsMkheVerifiedCpkErrorMembershipV1 {
    inner: VerifiedExactEightChunkMembershipV1<CpkErrorMembershipRoleV1>,
}
impl ZkAmsMkheVerifiedCpkErrorMembershipV1 {
    #[must_use]
    pub(super) const fn context(&self) -> ZkAmsMkheCpkErrorMembershipContextV1 {
        ZkAmsMkheCpkErrorMembershipContextV1 {
            inner: self.inner.context(),
        }
    }
    #[must_use]
    pub(super) const fn commitments(&self) -> &[Point; ZK_AMS_MKHE_CPK_CHUNKS_V1] {
        self.inner.commitments()
    }
    #[must_use]
    pub(super) const fn generator_basis_digest(&self) -> [u8; 32] {
        self.inner.generator_basis_digest()
    }
    #[must_use]
    pub(super) const fn commitment_set_digest(&self) -> [u8; 32] {
        self.inner.commitment_set_digest()
    }
    #[must_use]
    pub(super) const fn proof_set_digest(&self) -> [u8; 32] {
        self.inner.proof_set_digest()
    }
    #[must_use]
    pub(super) const fn verifier_transcript_digest(&self) -> [u8; 32] {
        self.inner.verifier_transcript_digest()
    }
}
impl fmt::Debug for ZkAmsMkheVerifiedCpkErrorMembershipV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZkAmsMkheVerifiedCpkErrorMembershipV1")
            .field(
                "commitment_set_digest",
                &hex::encode(self.commitment_set_digest()),
            )
            .field(
                "verifier_transcript_digest",
                &hex::encode(self.verifier_transcript_digest()),
            )
            .finish_non_exhaustive()
    }
}
/// Move-only, fail-closed input scaffold consumed by the complete CPK verifier.
///
/// Possession establishes the two role-specific membership proof sets and
/// their common statement context only.  It cannot mint
/// [`VerifiedZkAmsMkheCpkRelationReceiptV1`] or any active-binding lineage.
pub(super) struct ZkAmsMkheVerifiedCpkMembershipInputsV1 {
    secret: ZkAmsMkheVerifiedPersistentMembershipV1,
    error: ZkAmsMkheVerifiedCpkErrorMembershipV1,
}
impl fmt::Debug for ZkAmsMkheVerifiedCpkMembershipInputsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZkAmsMkheVerifiedCpkMembershipInputsV1")
            .field(
                "secret_commitment_set_digest",
                &hex::encode(self.secret.commitment_set_digest()),
            )
            .field(
                "error_commitment_set_digest",
                &hex::encode(self.error.commitment_set_digest()),
            )
            .finish_non_exhaustive()
    }
}
/// Fixed canonical header for one complete CPK relation proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ZkAmsMkheCpkRelationHeaderV1 {
    statement_digest: [u8; 32],
    generator_basis_digest: [u8; 32],
    secret_membership_wire_digest: [u8; 32],
    error_membership_wire_digest: [u8; 32],
    party_b_pointer_digest: [u8; 32],
}
impl ZkAmsMkheCpkRelationHeaderV1 {
    /// Bind the exact canonical statement and both complete membership wires.
    pub(super) fn new(
        statement: ZkAmsMkheCpkShareStatementV1,
        secret_membership_wire: &[u8],
        error_membership_wire: &[u8],
    ) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        if secret_membership_wire.len() != ZK_AMS_MKHE_CPK_SECRET_MEMBERSHIP_BYTES_V1
            || error_membership_wire.len() != ZK_AMS_MKHE_CPK_ERROR_MEMBERSHIP_BYTES_V1
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::RelationHeader);
        }
        statement.validate()?;
        let header = Self {
            statement_digest: statement.statement_digest()?,
            generator_basis_digest: ZK_AMS_T256_BP_GENERATOR_BASIS_DIGEST_V1,
            secret_membership_wire_digest: framed_wire_digest(
                CPK_SECRET_MEMBERSHIP_WIRE_DIGEST_DOMAIN_V1,
                secret_membership_wire,
            ),
            error_membership_wire_digest: framed_wire_digest(
                CPK_ERROR_MEMBERSHIP_WIRE_DIGEST_DOMAIN_V1,
                error_membership_wire,
            ),
            party_b_pointer_digest: statement.party_b_pointer().pointer_digest(),
        };
        header.validate()?;
        Ok(header)
    }
    fn validate(self) -> Result<(), ZkAmsMkheCpkRelationErrorV1> {
        if self.generator_basis_digest != ZK_AMS_T256_BP_GENERATOR_BASIS_DIGEST_V1
            || [
                self.statement_digest,
                self.secret_membership_wire_digest,
                self.error_membership_wire_digest,
                self.party_b_pointer_digest,
            ]
            .contains(&[0; 32])
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::RelationHeader);
        }
        Ok(())
    }
    fn validate_against(
        self,
        statement: ZkAmsMkheCpkShareStatementV1,
        secret_membership_wire: &[u8],
        error_membership_wire: &[u8],
    ) -> Result<(), ZkAmsMkheCpkRelationErrorV1> {
        self.validate()?;
        if secret_membership_wire.len() != ZK_AMS_MKHE_CPK_SECRET_MEMBERSHIP_BYTES_V1
            || error_membership_wire.len() != ZK_AMS_MKHE_CPK_ERROR_MEMBERSHIP_BYTES_V1
            || self.statement_digest != statement.statement_digest()?
            || self.secret_membership_wire_digest
                != framed_wire_digest(
                    CPK_SECRET_MEMBERSHIP_WIRE_DIGEST_DOMAIN_V1,
                    secret_membership_wire,
                )
            || self.error_membership_wire_digest
                != framed_wire_digest(
                    CPK_ERROR_MEMBERSHIP_WIRE_DIGEST_DOMAIN_V1,
                    error_membership_wire,
                )
            || self.party_b_pointer_digest != statement.party_b_pointer().pointer_digest()
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::RelationHeader);
        }
        Ok(())
    }
    /// Encode the fully enumerated 208-byte header.
    pub(super) fn to_wire_bytes(
        self,
    ) -> Result<[u8; ZK_AMS_MKHE_CPK_RELATION_HEADER_BYTES_V1], ZkAmsMkheCpkRelationErrorV1> {
        self.validate()?;
        let mut bytes = [0_u8; ZK_AMS_MKHE_CPK_RELATION_HEADER_BYTES_V1];
        bytes[..4].copy_from_slice(&CPK_RELATION_PROOF_MAGIC_V1);
        bytes[4] = MKHE_VERSION_V1;
        bytes[5] = CPK_RELATION_ALGORITHM_V1;
        bytes[6..8].copy_from_slice(&CPK_RELATION_FLAGS_V1.to_be_bytes());
        bytes[8..12].copy_from_slice(&(ZK_AMS_MKHE_CPK_RING_DEGREE_V1 as u32).to_be_bytes());
        bytes[12..16]
            .copy_from_slice(&(ZK_AMS_MKHE_CPK_CHUNK_COEFFICIENTS_V1 as u32).to_be_bytes());
        bytes[16] = ZK_AMS_MKHE_CPK_CHUNKS_V1 as u8;
        bytes[17] = ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1 as u8;
        bytes[18] = ZK_AMS_MKHE_CPK_RELATION_WITNESSES_V1 as u8;
        bytes[19] = ZK_AMS_MKHE_CPK_CHALLENGE_BITS_V1 as u8;
        bytes[20] = CPK_SIGNED_RESPONSE_BYTES_V1 as u8;
        bytes[21] = CPK_T256_SCALAR_BYTES_V1 as u8;
        bytes[22..24].fill(0);
        bytes[24..32].copy_from_slice(&ZK_AMS_MKHE_CPK_MASK_BOUND_V1.to_be_bytes());
        bytes[32..40].copy_from_slice(&ZK_AMS_MKHE_CPK_RESPONSE_BOUND_V1.to_be_bytes());
        bytes[40..44]
            .copy_from_slice(&(ZK_AMS_MKHE_CPK_RELATION_BODY_BYTES_V1 as u32).to_be_bytes());
        bytes[44..76].copy_from_slice(&self.statement_digest);
        bytes[76..108].copy_from_slice(&self.generator_basis_digest);
        bytes[108..140].copy_from_slice(&self.secret_membership_wire_digest);
        bytes[140..172].copy_from_slice(&self.error_membership_wire_digest);
        bytes[172..204].copy_from_slice(&self.party_b_pointer_digest);
        bytes[204..208].fill(0);
        Ok(bytes)
    }
    /// Decode one exact header and reject all alternate dimensions or reserved bits.
    pub(super) fn from_wire_bytes_exact(bytes: &[u8]) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        if bytes.len() != ZK_AMS_MKHE_CPK_RELATION_HEADER_BYTES_V1
            || bytes[..4] != CPK_RELATION_PROOF_MAGIC_V1
            || bytes[4] != MKHE_VERSION_V1
            || bytes[5] != CPK_RELATION_ALGORITHM_V1
            || u16::from_be_bytes(array_at::<2>(bytes, 6)?) != CPK_RELATION_FLAGS_V1
            || u32::from_be_bytes(array_at::<4>(bytes, 8)?) != ZK_AMS_MKHE_CPK_RING_DEGREE_V1 as u32
            || u32::from_be_bytes(array_at::<4>(bytes, 12)?)
                != ZK_AMS_MKHE_CPK_CHUNK_COEFFICIENTS_V1 as u32
            || bytes[16] != ZK_AMS_MKHE_CPK_CHUNKS_V1 as u8
            || bytes[17] != ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1 as u8
            || bytes[18] != ZK_AMS_MKHE_CPK_RELATION_WITNESSES_V1 as u8
            || bytes[19] != ZK_AMS_MKHE_CPK_CHALLENGE_BITS_V1 as u8
            || bytes[20] != CPK_SIGNED_RESPONSE_BYTES_V1 as u8
            || bytes[21] != CPK_T256_SCALAR_BYTES_V1 as u8
            || bytes[22..24] != [0; 2]
            || i64::from_be_bytes(array_at::<8>(bytes, 24)?) != ZK_AMS_MKHE_CPK_MASK_BOUND_V1
            || i64::from_be_bytes(array_at::<8>(bytes, 32)?) != ZK_AMS_MKHE_CPK_RESPONSE_BOUND_V1
            || u32::from_be_bytes(array_at::<4>(bytes, 40)?)
                != ZK_AMS_MKHE_CPK_RELATION_BODY_BYTES_V1 as u32
            || bytes[204..208] != [0; 4]
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::RelationHeader);
        }
        let header = Self {
            statement_digest: array_at::<32>(bytes, 44)?,
            generator_basis_digest: array_at::<32>(bytes, 76)?,
            secret_membership_wire_digest: array_at::<32>(bytes, 108)?,
            error_membership_wire_digest: array_at::<32>(bytes, 140)?,
            party_b_pointer_digest: array_at::<32>(bytes, 172)?,
        };
        header.validate()?;
        Ok(header)
    }
}
fn validate_cpk_membership_context_axes_v1(
    statement: ZkAmsMkheCpkShareStatementV1,
    secret_context: ZkAmsMkhePersistentMembershipContextV1,
    error_context: ZkAmsMkheCpkErrorMembershipContextV1,
) -> Result<(), ZkAmsMkheCpkRelationErrorV1> {
    statement.validate()?;
    let statement_digest = statement.statement_digest()?;
    let expected_secret = ZkAmsMkhePersistentMembershipContextV1::from_relation_axes(
        statement.profile_digest,
        statement.roster_digest,
        statement.key_material_digest,
        statement.epoch,
        statement.cpk_transcript_digest,
        statement.party,
        statement_digest,
    )
    .map_err(|_| ZkAmsMkheCpkRelationErrorV1::MembershipEvidence)?;
    let expected_error = ZkAmsMkheCpkErrorMembershipContextV1::from_share_statement(statement)?;
    if secret_context != expected_secret || error_context != expected_error {
        return Err(ZkAmsMkheCpkRelationErrorV1::MembershipEvidence);
    }
    Ok(())
}
/// Verify both exact membership inputs while keeping the native CPK equation fail closed.
///
/// The returned object is only an input scaffold.  It does not read party `b`,
/// verify the streamed RNS relation or authentication, or construct a relation
/// receipt.  Secret membership alone therefore cannot enter the active exact-
/// binding graph.
pub(super) fn verify_zk_ams_mkhe_cpk_membership_inputs_v1(
    statement: ZkAmsMkheCpkShareStatementV1,
    header: ZkAmsMkheCpkRelationHeaderV1,
    secret_membership_wire: &[u8],
    error_membership_wire: &[u8],
) -> Result<ZkAmsMkheVerifiedCpkMembershipInputsV1, ZkAmsMkheCpkRelationErrorV1> {
    header.validate_against(statement, secret_membership_wire, error_membership_wire)?;
    let secret =
        ZkAmsMkhePersistentMembershipEvidenceV1::from_wire_bytes_exact(secret_membership_wire)
            .map_err(|_| ZkAmsMkheCpkRelationErrorV1::MembershipEvidence)?;
    let error =
        ZkAmsMkheCpkErrorMembershipEvidenceV1::from_wire_bytes_exact(error_membership_wire)?;
    validate_cpk_membership_context_axes_v1(statement, secret.context(), error.context())?;
    let secret = secret
        .into_verified()
        .map_err(|_| ZkAmsMkheCpkRelationErrorV1::MembershipEvidence)?;
    let error = error.into_verified()?;
    Ok(ZkAmsMkheVerifiedCpkMembershipInputsV1 { secret, error })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CpkRelationShapeV1 {
    repetitions: usize,
    witnesses: usize,
    degree: usize,
    chunks: usize,
}
impl CpkRelationShapeV1 {
    const RELEASE: Self = Self {
        repetitions: ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1,
        witnesses: ZK_AMS_MKHE_CPK_RELATION_WITNESSES_V1,
        degree: ZK_AMS_MKHE_CPK_RING_DEGREE_V1,
        chunks: ZK_AMS_MKHE_CPK_CHUNKS_V1,
    };
    fn validate(self) -> Result<(), ZkAmsMkheCpkRelationErrorV1> {
        if self.repetitions != ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1
            || self.witnesses != ZK_AMS_MKHE_CPK_RELATION_WITNESSES_V1
            || self.degree == 0
            || self.chunks == 0
            || !self.degree.is_multiple_of(self.chunks)
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::Witness);
        }
        Ok(())
    }
    fn response_count(self) -> Result<usize, ZkAmsMkheCpkRelationErrorV1> {
        self.validate()?;
        self.repetitions
            .checked_mul(self.witnesses)
            .and_then(|value| value.checked_mul(self.degree))
            .ok_or(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)
    }
    fn blind_response_count(self) -> Result<usize, ZkAmsMkheCpkRelationErrorV1> {
        self.validate()?;
        self.repetitions
            .checked_mul(self.witnesses)
            .and_then(|value| value.checked_mul(self.chunks))
            .ok_or(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)
    }
    fn body_bytes(self) -> Result<usize, ZkAmsMkheCpkRelationErrorV1> {
        CPK_CHALLENGE_SEED_BYTES_V1
            .checked_add(
                self.response_count()?
                    .checked_mul(CPK_SIGNED_RESPONSE_BYTES_V1)
                    .ok_or(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?,
            )
            .and_then(|value| {
                value.checked_add(
                    self.blind_response_count()
                        .ok()?
                        .checked_mul(CPK_T256_SCALAR_BYTES_V1)?,
                )
            })
            .ok_or(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)
    }
}
#[derive(PartialEq, Eq)]
struct CpkRelationBodyV1 {
    challenge_seed: [u8; 32],
    responses: Vec<i64>,
    blind_responses: Vec<Scalar>,
}
impl fmt::Debug for CpkRelationBodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CpkRelationBodyV1")
            .field("challenge_seed", &hex::encode(self.challenge_seed))
            .field("responses", &self.responses.len())
            .field("blind_responses", &self.blind_responses.len())
            .finish()
    }
}
impl CpkRelationBodyV1 {
    fn validate(&self, shape: CpkRelationShapeV1) -> Result<(), ZkAmsMkheCpkRelationErrorV1> {
        if self.responses.len() != shape.response_count()?
            || self.blind_responses.len() != shape.blind_response_count()?
            || self
                .responses
                .iter()
                .any(|response| response.unsigned_abs() > ZK_AMS_MKHE_CPK_RESPONSE_BOUND_V1 as u64)
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::RelationBody);
        }
        Ok(())
    }
    fn to_wire_bytes(
        &self,
        shape: CpkRelationShapeV1,
    ) -> Result<Vec<u8>, ZkAmsMkheCpkRelationErrorV1> {
        self.validate(shape)?;
        let expected = shape.body_bytes()?;
        let mut bytes = try_exact_capacity_vec_v1(expected)
            .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
        bytes.extend_from_slice(&self.challenge_seed);
        for response in &self.responses {
            bytes.extend_from_slice(&response.to_be_bytes());
        }
        for response in &self.blind_responses {
            bytes.extend_from_slice(&response.to_le_bytes());
        }
        if bytes.len() != expected {
            return Err(ZkAmsMkheCpkRelationErrorV1::RelationBody);
        }
        Ok(bytes)
    }
    fn from_wire_bytes_exact(
        shape: CpkRelationShapeV1,
        bytes: &[u8],
    ) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        if bytes.len() != shape.body_bytes()? {
            return Err(ZkAmsMkheCpkRelationErrorV1::RelationBody);
        }
        let response_count = shape.response_count()?;
        let blind_response_count = shape.blind_response_count()?;
        let mut responses = try_exact_capacity_vec_v1(response_count)
            .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
        let mut cursor = CPK_CHALLENGE_SEED_BYTES_V1;
        for _ in 0..response_count {
            let response = i64::from_be_bytes(array_at::<8>(bytes, cursor)?);
            if response.unsigned_abs() > ZK_AMS_MKHE_CPK_RESPONSE_BOUND_V1 as u64 {
                return Err(ZkAmsMkheCpkRelationErrorV1::RelationBody);
            }
            responses.push(response);
            cursor += CPK_SIGNED_RESPONSE_BYTES_V1;
        }
        let mut blind_responses = try_exact_capacity_vec_v1(blind_response_count)
            .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
        for _ in 0..blind_response_count {
            let encoded = array_at::<32>(bytes, cursor)?;
            let scalar = Scalar::from_le_bytes_exact(encoded)
                .map_err(|_| ZkAmsMkheCpkRelationErrorV1::RelationBody)?;
            blind_responses.push(scalar);
            cursor += CPK_T256_SCALAR_BYTES_V1;
        }
        if cursor != bytes.len() {
            return Err(ZkAmsMkheCpkRelationErrorV1::RelationBody);
        }
        let body = Self {
            challenge_seed: array_at::<32>(bytes, 0)?,
            responses,
            blind_responses,
        };
        body.validate(shape)?;
        Ok(body)
    }
}
/// Canonical in-memory proof container.  Parsing it never verifies the relation.
pub(super) struct ZkAmsMkheCpkRelationProofV1 {
    header: ZkAmsMkheCpkRelationHeaderV1,
    body: CpkRelationBodyV1,
}
impl fmt::Debug for ZkAmsMkheCpkRelationProofV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZkAmsMkheCpkRelationProofV1")
            .field("header", &self.header)
            .field("body", &self.body)
            .finish()
    }
}
impl ZkAmsMkheCpkRelationProofV1 {
    /// Combine a bound header with common-box prover responses.
    pub(super) fn from_prover_response(
        header: ZkAmsMkheCpkRelationHeaderV1,
        response: ZkAmsMkheCpkProverResponseV1,
    ) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        header.validate()?;
        response.body.validate(CpkRelationShapeV1::RELEASE)?;
        Ok(Self {
            header,
            body: response.body,
        })
    }
    /// Encode the unique fixed-size proof object.
    pub(super) fn to_wire_bytes(&self) -> Result<Vec<u8>, ZkAmsMkheCpkRelationErrorV1> {
        let header = self.header.to_wire_bytes()?;
        let body = self.body.to_wire_bytes(CpkRelationShapeV1::RELEASE)?;
        let mut wire = try_exact_capacity_vec_v1(ZK_AMS_MKHE_CPK_RELATION_PROOF_BYTES_V1)
            .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&body);
        if wire.len() != ZK_AMS_MKHE_CPK_RELATION_PROOF_BYTES_V1 {
            return Err(ZkAmsMkheCpkRelationErrorV1::RelationBody);
        }
        Ok(wire)
    }
    /// Decode the exact complete proof object without minting verification authority.
    pub(super) fn from_wire_bytes_exact(bytes: &[u8]) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        if bytes.len() != ZK_AMS_MKHE_CPK_RELATION_PROOF_BYTES_V1 {
            return Err(ZkAmsMkheCpkRelationErrorV1::RelationBody);
        }
        let header = ZkAmsMkheCpkRelationHeaderV1::from_wire_bytes_exact(
            &bytes[..ZK_AMS_MKHE_CPK_RELATION_HEADER_BYTES_V1],
        )?;
        let body = CpkRelationBodyV1::from_wire_bytes_exact(
            CpkRelationShapeV1::RELEASE,
            &bytes[ZK_AMS_MKHE_CPK_RELATION_HEADER_BYTES_V1..],
        )?;
        Ok(Self { header, body })
    }
    /// Bound header; its digests still require membership and statement verification.
    #[must_use]
    pub(super) const fn header(&self) -> ZkAmsMkheCpkRelationHeaderV1 {
        self.header
    }
    /// Stored seed used only to reconstruct challenges before recomputing the transcript.
    #[must_use]
    pub(super) const fn challenge_seed(&self) -> [u8; 32] {
        self.body.challenge_seed
    }
    /// Exact signed response arena in repetition/role/coefficient order.
    #[must_use]
    pub(super) fn responses(&self) -> &[i64] {
        &self.body.responses
    }
    /// Exact response blindings in repetition/role/chunk order.
    #[must_use]
    pub(super) fn blind_responses(&self) -> &[Scalar] {
        &self.body.blind_responses
    }
}
/// Owned named integer copies that receive best-effort erasure on drop.
///
/// Rust does not guarantee erasure of compiler-created copies or registers,
/// and destructors do not run after process abort.
struct BestEffortErasingI64VecV1(Vec<i64>);
impl BestEffortErasingI64VecV1 {
    fn as_slice(&self) -> &[i64] {
        &self.0
    }
    fn as_mut_slice(&mut self) -> &mut [i64] {
        &mut self.0
    }
    fn into_public(mut self) -> Vec<i64> {
        core::mem::take(&mut self.0)
    }
}
impl Drop for BestEffortErasingI64VecV1 {
    fn drop(&mut self) {
        let values = core::hint::black_box(&mut self.0);
        values.fill(0);
        compiler_fence(Ordering::SeqCst);
        let _ = core::hint::black_box(&mut *values);
    }
}
/// Owned named scalar copies that receive best-effort erasure on drop.
///
/// `Scalar` is `Copy`, so arithmetic can still create compiler temporaries and
/// register copies outside this owner's reach.
struct BestEffortErasingScalarVecV1(Vec<Scalar>);
impl BestEffortErasingScalarVecV1 {
    fn as_slice(&self) -> &[Scalar] {
        &self.0
    }
    fn as_mut_slice(&mut self) -> &mut [Scalar] {
        &mut self.0
    }
    fn into_public(mut self) -> Vec<Scalar> {
        core::mem::take(&mut self.0)
    }
}
impl Drop for BestEffortErasingScalarVecV1 {
    fn drop(&mut self) {
        let values = core::hint::black_box(&mut self.0);
        for scalar in values.iter_mut() {
            scalar.clear_secret();
        }
        compiler_fence(Ordering::SeqCst);
        let _ = core::hint::black_box(&mut *values);
    }
}
/// Fixed-size secret byte owner with best-effort named-copy erasure on drop.
///
/// The owner must be constructed before handing its buffer to a fallible or
/// panicking entropy source. Decoders borrow its array so the guarded entropy
/// is not first duplicated into an unmanaged stack array.
struct BestEffortErasingBytesV1<const N: usize>([u8; N]);
impl<const N: usize> BestEffortErasingBytesV1<N> {
    fn zeroed() -> Self {
        Self([0; N])
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
    fn as_array(&self) -> &[u8; N] {
        &self.0
    }
}
impl<const N: usize> Drop for BestEffortErasingBytesV1<N> {
    fn drop(&mut self) {
        let bytes = core::hint::black_box(&mut self.0);
        bytes.fill(0);
        compiler_fence(Ordering::SeqCst);
        let _ = core::hint::black_box(&mut *bytes);
        #[cfg(test)]
        if bytes.iter().all(|byte| *byte == 0) {
            CPK_FIXED_BYTES_ERASURE_DROP_CALLS_V1.fetch_add(1, Ordering::SeqCst);
        }
    }
}
/// One secret-derived named scalar copy erased best-effort on every exit path.
///
/// `Scalar` is `Copy`, so the arithmetic operand exposed to `AddAssign` and
/// compiler-created register temporaries remain outside this owner's reach.
struct BestEffortErasingScalarCopyV1(Scalar);
impl BestEffortErasingScalarCopyV1 {
    fn new(value: Scalar) -> Self {
        Self(value)
    }
    fn expose_copy(&self) -> Scalar {
        self.0
    }
}
impl Drop for BestEffortErasingScalarCopyV1 {
    fn drop(&mut self) {
        let scalar = core::hint::black_box(&mut self.0);
        scalar.clear_secret();
        compiler_fence(Ordering::SeqCst);
        let _ = core::hint::black_box(&mut *scalar);
        #[cfg(test)]
        if scalar.is_zero() {
            CPK_SCALAR_COPY_ERASURE_DROP_CALLS_V1.fetch_add(1, Ordering::SeqCst);
        }
    }
}
#[cfg(test)]
static CPK_FIXED_BYTES_ERASURE_DROP_CALLS_V1: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static CPK_SCALAR_COPY_ERASURE_DROP_CALLS_V1: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
/// One unpublished set of common-box masks and commitment blindings.
///
/// Its owned named copies receive best-effort erasure on drop. Compiler-created
/// copies, register temporaries, and process-abort paths cannot be guaranteed.
struct ZkAmsMkheCpkRelationMaskAttemptV1 {
    shape: CpkRelationShapeV1,
    masks: BestEffortErasingI64VecV1,
    blind_masks: BestEffortErasingScalarVecV1,
}
impl fmt::Debug for ZkAmsMkheCpkRelationMaskAttemptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZkAmsMkheCpkRelationMaskAttemptV1")
            .field("shape", &self.shape)
            .field("masks", &"REDACTED")
            .field("blind_masks", &"REDACTED")
            .finish()
    }
}
impl ZkAmsMkheCpkRelationMaskAttemptV1 {
    fn sample_for_shape<R: MaskedRelaxedRandomSourceV1>(
        shape: CpkRelationShapeV1,
        random: &mut R,
    ) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        shape.validate()?;
        let response_count = shape.response_count()?;
        let blind_count = shape.blind_response_count()?;
        let mut masks = BestEffortErasingI64VecV1(
            try_exact_capacity_vec_v1(response_count)
                .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?,
        );
        let masks_allocation = masks.0.as_ptr();
        for _ in 0..response_count {
            masks.0.push(sample_exact_uniform_signed_box_v1(
                random,
                ZK_AMS_MKHE_CPK_MASK_BOUND_V1,
            )?);
        }
        if masks.0.len() != response_count || masks.0.as_ptr() != masks_allocation {
            return Err(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling);
        }
        let mut blind_masks = BestEffortErasingScalarVecV1(
            try_exact_capacity_vec_v1(blind_count)
                .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?,
        );
        let blind_masks_allocation = blind_masks.0.as_ptr();
        for _ in 0..blind_count {
            blind_masks.0.push(sample_t256_scalar_v1(random)?);
        }
        if blind_masks.0.len() != blind_count || blind_masks.0.as_ptr() != blind_masks_allocation {
            return Err(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling);
        }
        Ok(Self {
            shape,
            masks,
            blind_masks,
        })
    }
    /// Signed masks in repetition/role/coefficient order for first-message algebra.
    #[must_use]
    fn masks(&self) -> &[i64] {
        self.masks.as_slice()
    }
    /// Scalar masks in repetition/role/chunk order for commitment first messages.
    #[must_use]
    fn blind_masks(&self) -> &[Scalar] {
        self.blind_masks.as_slice()
    }
    /// Consume one attempt into public responses or reject it.
    ///
    /// Rejected attempts retain no externally reachable partial response, and
    /// their owned named mask copies receive best-effort erasure during drop.
    #[allow(clippy::too_many_arguments)]
    fn into_responses(
        mut self,
        challenge_seed: [u8; 32],
        challenges: [u32; ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1],
        secret: &[i8],
        error: &[i8],
        secret_blindings: &[Scalar],
        error_blindings: &[Scalar],
    ) -> Result<ZkAmsMkheCpkProverResponseV1, ZkAmsMkheCpkRelationErrorV1> {
        self.shape.validate()?;
        if challenges != cpk_challenges_from_seed_v1(challenge_seed) {
            return Err(ZkAmsMkheCpkRelationErrorV1::Transcript);
        }
        if self.masks.as_slice().len() != self.shape.response_count()?
            || self.blind_masks.as_slice().len() != self.shape.blind_response_count()?
            || self
                .masks
                .as_slice()
                .iter()
                .any(|mask| mask.unsigned_abs() > ZK_AMS_MKHE_CPK_MASK_BOUND_V1 as u64)
            || secret.len() != self.shape.degree
            || error.len() != self.shape.degree
            || secret_blindings.len() != self.shape.chunks
            || error_blindings.len() != self.shape.chunks
            || secret
                .iter()
                .any(|coefficient| coefficient.unsigned_abs() > 1)
            || error
                .iter()
                .any(|coefficient| coefficient.unsigned_abs() > 2)
            || secret_blindings
                .iter()
                .chain(error_blindings.iter())
                .any(|blinding| blinding.is_zero())
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::Witness);
        }
        let masks_allocation = self.masks.0.as_ptr();
        let blind_masks_allocation = self.blind_masks.0.as_ptr();
        for (repetition, &challenge) in challenges.iter().enumerate() {
            let challenge = i64::from(challenge);
            for role in 0..self.shape.witnesses {
                let witness = if role == 0 { secret } else { error };
                for (coefficient, witness_coefficient) in witness.iter().enumerate() {
                    let index = response_index(self.shape, repetition, role, coefficient)?;
                    let shift = challenge
                        .checked_mul(i64::from(*witness_coefficient))
                        .ok_or(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
                    let response = self.masks.as_slice()[index]
                        .checked_add(shift)
                        .ok_or(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
                    if response.unsigned_abs() > ZK_AMS_MKHE_CPK_RESPONSE_BOUND_V1 as u64 {
                        return Err(ZkAmsMkheCpkRelationErrorV1::ResponseRejected);
                    }
                    self.masks.as_mut_slice()[index] = response;
                }
            }
        }
        for (repetition, &challenge) in challenges.iter().enumerate() {
            let mut challenge_scalar = Scalar::from_u64(u64::from(challenge));
            for role in 0..self.shape.witnesses {
                let blindings = if role == 0 {
                    secret_blindings
                } else {
                    error_blindings
                };
                for (chunk, witness_blinding) in blindings.iter().enumerate() {
                    let index = blind_response_index(self.shape, repetition, role, chunk)?;
                    let shifted =
                        BestEffortErasingScalarCopyV1::new(challenge_scalar * *witness_blinding);
                    self.blind_masks.as_mut_slice()[index] += shifted.expose_copy();
                }
            }
            challenge_scalar.clear_secret();
        }
        if self.masks.0.len() != self.shape.response_count()?
            || self.masks.0.capacity() != self.shape.response_count()?
            || self.masks.0.as_ptr() != masks_allocation
            || self.blind_masks.0.len() != self.shape.blind_response_count()?
            || self.blind_masks.0.capacity() != self.shape.blind_response_count()?
            || self.blind_masks.0.as_ptr() != blind_masks_allocation
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling);
        }
        let responses = self.masks.into_public();
        let blind_responses = self.blind_masks.into_public();
        let body = CpkRelationBodyV1 {
            challenge_seed,
            responses,
            blind_responses,
        };
        body.validate(self.shape)?;
        Ok(ZkAmsMkheCpkProverResponseV1 { body })
    }
}
/// Public `z`/`rho` response material produced only after a complete common-box attempt accepts.
///
/// Unlike unpublished named mask copies, accepted proof responses are public
/// and intentionally receive no best-effort erasure when this container drops.
#[derive(PartialEq, Eq)]
pub(super) struct ZkAmsMkheCpkProverResponseV1 {
    body: CpkRelationBodyV1,
}
impl fmt::Debug for ZkAmsMkheCpkProverResponseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZkAmsMkheCpkProverResponseV1")
            .field("body", &self.body)
            .finish()
    }
}
/// Sample and reject complete attempts, delegating only actual first-message algebra.
///
/// The callback must compute all commitment and RNS first messages from the supplied masks and
/// return the reconstructed seed and its four coordinates. An identity commitment first message
/// must return `FirstMessageRejected`; that signal and only response-box rejection consume another
/// bounded attempt. Malformed transcript, RNS-stream, and provider errors remain terminal. Retry
/// ordinals are intentionally absent from both callback input and wire.
#[allow(clippy::too_many_arguments)]
fn construct_zk_ams_mkhe_cpk_responses_with_aborts_v1<R, F>(
    secret: &[i8],
    error: &[i8],
    secret_blindings: &[Scalar],
    error_blindings: &[Scalar],
    random: &mut R,
    mut derive_challenges: F,
) -> Result<ZkAmsMkheCpkProverResponseV1, ZkAmsMkheCpkRelationErrorV1>
where
    R: MaskedRelaxedRandomSourceV1,
    F: FnMut(
        &ZkAmsMkheCpkRelationMaskAttemptV1,
    ) -> Result<
        ([u8; 32], [u32; ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1]),
        ZkAmsMkheCpkRelationErrorV1,
    >,
{
    construct_cpk_responses_with_aborts_for_shape_v1(
        CpkRelationShapeV1::RELEASE,
        secret,
        error,
        secret_blindings,
        error_blindings,
        random,
        &mut derive_challenges,
    )
}
#[allow(clippy::too_many_arguments)]
fn construct_cpk_responses_with_aborts_for_shape_v1<R, F>(
    shape: CpkRelationShapeV1,
    secret: &[i8],
    error: &[i8],
    secret_blindings: &[Scalar],
    error_blindings: &[Scalar],
    random: &mut R,
    derive_challenges: &mut F,
) -> Result<ZkAmsMkheCpkProverResponseV1, ZkAmsMkheCpkRelationErrorV1>
where
    R: MaskedRelaxedRandomSourceV1,
    F: FnMut(
        &ZkAmsMkheCpkRelationMaskAttemptV1,
    ) -> Result<
        ([u8; 32], [u32; ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1]),
        ZkAmsMkheCpkRelationErrorV1,
    >,
{
    shape.validate()?;
    for _ in 0..ZK_AMS_MKHE_CPK_OUTER_RETRY_CEILING_V1 {
        let attempt = ZkAmsMkheCpkRelationMaskAttemptV1::sample_for_shape(shape, random)?;
        let (seed, challenges) = match derive_challenges(&attempt) {
            Ok(challenge) => challenge,
            Err(ZkAmsMkheCpkRelationErrorV1::FirstMessageRejected) => continue,
            Err(error) => return Err(error),
        };
        match attempt.into_responses(
            seed,
            challenges,
            secret,
            error,
            secret_blindings,
            error_blindings,
        ) {
            Ok(response) => return Ok(response),
            Err(ZkAmsMkheCpkRelationErrorV1::ResponseRejected) => {}
            Err(error) => return Err(error),
        }
    }
    Err(ZkAmsMkheCpkRelationErrorV1::RetryExhausted)
}
fn sample_exact_uniform_signed_box_v1<R: MaskedRelaxedRandomSourceV1>(
    random: &mut R,
    bound: i64,
) -> Result<i64, ZkAmsMkheCpkRelationErrorV1> {
    if bound <= 0 || bound > ZK_AMS_MKHE_CPK_MASK_BOUND_V1 {
        return Err(ZkAmsMkheCpkRelationErrorV1::Witness);
    }
    let bound = u128::try_from(bound).map_err(|_| ZkAmsMkheCpkRelationErrorV1::Witness)?;
    let width = bound
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .ok_or(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
    let threshold = width.wrapping_neg() % width;
    for _ in 0..CPK_INTEGER_SAMPLER_RETRY_CEILING_V1 {
        let mut bytes = BestEffortErasingBytesV1::<16>::zeroed();
        random
            .fill_bytes(bytes.as_mut_slice())
            .map_err(|_| ZkAmsMkheCpkRelationErrorV1::RandomUnavailable)?;
        let sample = bytes
            .as_array()
            .iter()
            .fold(0_u128, |value, byte| (value << 8) | u128::from(*byte));
        if sample < threshold {
            continue;
        }
        let residue = sample % width;
        let signed = i128::try_from(residue)
            .ok()
            .and_then(|value| value.checked_sub(i128::try_from(bound).ok()?))
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
        return Ok(signed);
    }
    Err(ZkAmsMkheCpkRelationErrorV1::RandomUnavailable)
}
fn sample_t256_scalar_v1<R: MaskedRelaxedRandomSourceV1>(
    random: &mut R,
) -> Result<Scalar, ZkAmsMkheCpkRelationErrorV1> {
    let mut uniform = BestEffortErasingBytesV1::<64>::zeroed();
    random
        .fill_bytes(uniform.as_mut_slice())
        .map_err(|_| ZkAmsMkheCpkRelationErrorV1::RandomUnavailable)?;
    Ok(Scalar::from_uniform_le_bytes_ref(uniform.as_array()))
}
fn response_index(
    shape: CpkRelationShapeV1,
    repetition: usize,
    role: usize,
    coefficient: usize,
) -> Result<usize, ZkAmsMkheCpkRelationErrorV1> {
    if repetition >= shape.repetitions || role >= shape.witnesses || coefficient >= shape.degree {
        return Err(ZkAmsMkheCpkRelationErrorV1::Witness);
    }
    repetition
        .checked_mul(shape.witnesses)
        .and_then(|value| value.checked_add(role))
        .and_then(|value| value.checked_mul(shape.degree))
        .and_then(|value| value.checked_add(coefficient))
        .ok_or(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)
}
fn blind_response_index(
    shape: CpkRelationShapeV1,
    repetition: usize,
    role: usize,
    chunk: usize,
) -> Result<usize, ZkAmsMkheCpkRelationErrorV1> {
    if repetition >= shape.repetitions || role >= shape.witnesses || chunk >= shape.chunks {
        return Err(ZkAmsMkheCpkRelationErrorV1::Witness);
    }
    repetition
        .checked_mul(shape.witnesses)
        .and_then(|value| value.checked_add(role))
        .and_then(|value| value.checked_mul(shape.chunks))
        .and_then(|value| value.checked_add(chunk))
        .ok_or(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)
}
/// Typed digest reconstructed from actual commitment first-message points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ZkAmsMkheCpkCommitmentFirstMessageDigestV1([u8; 32]);
impl ZkAmsMkheCpkCommitmentFirstMessageDigestV1 {
    /// Hash one repetition in strict secret-chunks-then-error-chunks order.
    pub(super) fn from_reconstructed_points(
        repetition: usize,
        secret: &[Point; ZK_AMS_MKHE_CPK_CHUNKS_V1],
        error: &[Point; ZK_AMS_MKHE_CPK_CHUNKS_V1],
    ) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        Self::from_reconstructed_points_for_shape(repetition, secret, error)
    }
    fn from_reconstructed_points_for_shape(
        repetition: usize,
        secret: &[Point],
        error: &[Point],
    ) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        if repetition >= ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1 {
            return Err(ZkAmsMkheCpkRelationErrorV1::Transcript);
        }
        if secret.is_empty() || secret.len() != error.len() || secret.len() > u8::MAX.into() {
            return Err(ZkAmsMkheCpkRelationErrorV1::Transcript);
        }
        let mut hash = Keccak256::new();
        hash.update(CPK_COMMITMENT_FIRST_MESSAGE_DOMAIN_V1);
        hash.update(&[
            MKHE_VERSION_V1,
            repetition as u8,
            ZK_AMS_MKHE_CPK_RELATION_WITNESSES_V1 as u8,
            secret.len() as u8,
        ]);
        for (role, points) in [secret, error].into_iter().enumerate() {
            hash.update(&[role as u8]);
            for (chunk, point) in points.iter().enumerate() {
                hash.update(&[chunk as u8]);
                if point.is_identity() {
                    return Err(ZkAmsMkheCpkRelationErrorV1::FirstMessageRejected);
                }
                hash.update(
                    &point
                        .to_non_identity_wire_bytes()
                        .map_err(|_| ZkAmsMkheCpkRelationErrorV1::Transcript)?,
                );
            }
        }
        Ok(Self(hash.finalize()))
    }
}
/// Incremental, poisoning hash of one actual RNS first-message polynomial set.
pub(super) struct ZkAmsMkheCpkRnsFirstMessageDigestBuilderV1 {
    shape: CpkRnsDigestShapeV1,
    repetition: usize,
    next_limb: usize,
    next_coefficient: usize,
    current_modulus: Option<u64>,
    hash: Keccak256,
    failed: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CpkRnsDigestShapeV1 {
    limbs: usize,
    degree: usize,
}
impl ZkAmsMkheCpkRnsFirstMessageDigestBuilderV1 {
    /// Begin one release-shape repetition digest before reading any limb.
    pub(super) fn new(repetition: usize) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        Self::new_for_shape(
            repetition,
            CpkRnsDigestShapeV1 {
                limbs: ZK_AMS_MKHE_CPK_RNS_LIMBS_V1,
                degree: ZK_AMS_MKHE_CPK_RING_DEGREE_V1,
            },
        )
    }
    fn new_for_shape(
        repetition: usize,
        shape: CpkRnsDigestShapeV1,
    ) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        if repetition >= ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1
            || shape.limbs == 0
            || shape.degree == 0
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::RnsFirstMessage);
        }
        let mut hash = Keccak256::new();
        hash.update(CPK_RNS_FIRST_MESSAGE_DOMAIN_V1);
        hash.update(&[MKHE_VERSION_V1, repetition as u8]);
        hash.update(
            &u16::try_from(shape.limbs)
                .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?
                .to_be_bytes(),
        );
        hash.update(
            &u32::try_from(shape.degree)
                .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?
                .to_be_bytes(),
        );
        Ok(Self {
            shape,
            repetition,
            next_limb: 0,
            next_coefficient: 0,
            current_modulus: None,
            hash,
            failed: false,
        })
    }
    /// Begin exactly the next limb and bind its ordinal and prime modulus.
    pub(super) fn begin_limb(
        &mut self,
        limb: usize,
        modulus: u64,
    ) -> Result<(), ZkAmsMkheCpkRelationErrorV1> {
        if self.failed
            || self.current_modulus.is_some()
            || limb != self.next_limb
            || limb >= self.shape.limbs
            || modulus <= u64::from(u32::MAX)
        {
            self.failed = true;
            return Err(ZkAmsMkheCpkRelationErrorV1::RnsFirstMessage);
        }
        self.hash.update(
            &u16::try_from(limb)
                .map_err(|_| {
                    self.failed = true;
                    ZkAmsMkheCpkRelationErrorV1::ResourceCeiling
                })?
                .to_be_bytes(),
        );
        self.hash.update(&modulus.to_be_bytes());
        self.current_modulus = Some(modulus);
        self.next_coefficient = 0;
        Ok(())
    }
    /// Absorb a nonempty canonical residue chunk without making chunking transcript-visible.
    pub(super) fn update_residues(
        &mut self,
        residues: &[u64],
    ) -> Result<(), ZkAmsMkheCpkRelationErrorV1> {
        let Some(modulus) = self.current_modulus else {
            self.failed = true;
            return Err(ZkAmsMkheCpkRelationErrorV1::RnsFirstMessage);
        };
        let end = self
            .next_coefficient
            .checked_add(residues.len())
            .ok_or_else(|| {
                self.failed = true;
                ZkAmsMkheCpkRelationErrorV1::ResourceCeiling
            })?;
        if self.failed
            || residues.is_empty()
            || end > self.shape.degree
            || residues.iter().any(|residue| *residue >= modulus)
        {
            self.failed = true;
            return Err(ZkAmsMkheCpkRelationErrorV1::RnsFirstMessage);
        }
        for residue in residues {
            self.hash.update(&residue.to_be_bytes());
        }
        self.next_coefficient = end;
        Ok(())
    }
    /// Finish one limb only after all exact coefficients were absorbed.
    pub(super) fn finish_limb(&mut self) -> Result<(), ZkAmsMkheCpkRelationErrorV1> {
        if self.failed
            || self.current_modulus.is_none()
            || self.next_coefficient != self.shape.degree
        {
            self.failed = true;
            return Err(ZkAmsMkheCpkRelationErrorV1::RnsFirstMessage);
        }
        self.current_modulus = None;
        self.next_coefficient = 0;
        self.next_limb += 1;
        Ok(())
    }
    /// Finalize only after all 38 release limbs (or the internal test shape) complete.
    pub(super) fn finish(
        self,
    ) -> Result<ZkAmsMkheCpkRnsFirstMessageDigestV1, ZkAmsMkheCpkRelationErrorV1> {
        if self.failed
            || self.current_modulus.is_some()
            || self.next_limb != self.shape.limbs
            || self.next_coefficient != 0
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::RnsFirstMessage);
        }
        let _ = self.repetition;
        Ok(ZkAmsMkheCpkRnsFirstMessageDigestV1(self.hash.finalize()))
    }
}
/// Typed digest obtained only by completing an ordered canonical RNS stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ZkAmsMkheCpkRnsFirstMessageDigestV1([u8; 32]);
/// Reconstruct the global seed and four ordinal-bound challenges from actual evidence axes.
///
/// Both membership wires must already have passed their respective proof
/// verifiers before this primitive can participate in capability minting.
pub(super) fn reconstruct_zk_ams_mkhe_cpk_challenges_v1(
    statement: ZkAmsMkheCpkShareStatementV1,
    secret_membership_wire: &[u8],
    error_membership_wire: &[u8],
    header: ZkAmsMkheCpkRelationHeaderV1,
    commitment_first_messages: [ZkAmsMkheCpkCommitmentFirstMessageDigestV1;
        ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1],
    rns_first_messages: [ZkAmsMkheCpkRnsFirstMessageDigestV1;
        ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1],
) -> Result<([u8; 32], [u32; ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1]), ZkAmsMkheCpkRelationErrorV1>
{
    header.validate_against(statement, secret_membership_wire, error_membership_wire)?;
    if commitment_first_messages
        .iter()
        .map(|digest| digest.0)
        .chain(rns_first_messages.iter().map(|digest| digest.0))
        .any(|digest| digest == [0; 32])
    {
        return Err(ZkAmsMkheCpkRelationErrorV1::Transcript);
    }
    let statement_wire = statement.to_wire_bytes()?;
    let header_wire = header.to_wire_bytes()?;
    let mut hash = Keccak256::new();
    hash.update(CPK_CHALLENGE_VECTOR_DOMAIN_V1);
    hash.update(&[MKHE_VERSION_V1, CPK_RELATION_ALGORITHM_V1]);
    hash.update(&(statement_wire.len() as u32).to_be_bytes());
    hash.update(&statement_wire);
    hash.update(&(secret_membership_wire.len() as u32).to_be_bytes());
    hash.update(secret_membership_wire);
    hash.update(&(error_membership_wire.len() as u32).to_be_bytes());
    hash.update(error_membership_wire);
    hash.update(&(header_wire.len() as u16).to_be_bytes());
    hash.update(&header_wire);
    for (repetition, digest) in commitment_first_messages.iter().enumerate() {
        hash.update(&[repetition as u8]);
        hash.update(&digest.0);
    }
    for (repetition, digest) in rns_first_messages.iter().enumerate() {
        hash.update(&[repetition as u8]);
        hash.update(&digest.0);
    }
    let seed = hash.finalize();
    Ok((seed, cpk_challenges_from_seed_v1(seed)))
}
/// Derive all four coordinates without rejection; zero is a canonical challenge.
fn cpk_challenges_from_seed_v1(seed: [u8; 32]) -> [u32; ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1] {
    core::array::from_fn(|repetition| {
        let mut hash = Keccak256::new();
        hash.update(CPK_CHALLENGE_COORDINATE_DOMAIN_V1);
        hash.update(&seed);
        hash.update(&[repetition as u8]);
        let digest = hash.finalize();
        u32::from_be_bytes(digest[..4].try_into().expect("four-byte challenge prefix"))
    })
}
fn active_collective_public_a_context_v1(
    roster: &ZkAmsMkheGovernedActiveRosterV1,
    cpk_transcript_digest: [u8; 32],
) -> Result<[u8; 1 + 32 + 8 + 32], ZkAmsMkheCpkRelationErrorV1> {
    roster
        .validate()
        .map_err(|_| ZkAmsMkheCpkRelationErrorV1::GovernedContext)?;
    if cpk_transcript_digest == [0; 32] {
        return Err(ZkAmsMkheCpkRelationErrorV1::GovernedContext);
    }
    let mut context = [0_u8; 1 + 32 + 8 + 32];
    context[0] = MKHE_VERSION_V1;
    context[1..33].copy_from_slice(&roster.roster_digest());
    context[33..41].copy_from_slice(&roster.epoch().to_be_bytes());
    context[41..].copy_from_slice(&cpk_transcript_digest);
    Ok(context)
}
fn cpk_public_a_context_digest_v1(
    profile: &BgvProfile,
    roster: &ZkAmsMkheGovernedActiveRosterV1,
    cpk_transcript_digest: [u8; 32],
) -> Result<[u8; 32], ZkAmsMkheCpkRelationErrorV1> {
    profile
        .validate()
        .map_err(|_| ZkAmsMkheCpkRelationErrorV1::GovernedContext)?;
    let derivation_context = active_collective_public_a_context_v1(roster, cpk_transcript_digest)?;
    let mut hash = Keccak256::new();
    hash.update(CPK_PUBLIC_A_CONTEXT_DOMAIN_V1);
    hash.update(&[MKHE_VERSION_V1, CPK_PUBLIC_A_DERIVATION_ALGORITHM_V1]);
    hash.update(
        &profile
            .digest()
            .map_err(|_| ZkAmsMkheCpkRelationErrorV1::GovernedContext)?,
    );
    hash.update(&roster.roster_digest());
    hash.update(&roster.key_material_digest());
    hash.update(&roster.epoch().to_be_bytes());
    hash.update(&(derivation_context.len() as u32).to_be_bytes());
    hash.update(&derivation_context);
    Ok(hash.finalize())
}
fn t256_scalar_from_signed_i64_v1(value: i64) -> Scalar {
    let magnitude = Scalar::from_u64(value.unsigned_abs());
    if value < 0 {
        Scalar::zero() - magnitude
    } else {
        magnitude
    }
}
fn reconstruct_cpk_commitment_first_messages_for_shape_v1(
    shape: CpkRelationShapeV1,
    body: &CpkRelationBodyV1,
    challenges: [u32; ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1],
    secret_commitments: &[Point],
    error_commitments: &[Point],
) -> Result<
    [ZkAmsMkheCpkCommitmentFirstMessageDigestV1; ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1],
    ZkAmsMkheCpkRelationErrorV1,
> {
    shape.validate()?;
    body.validate(shape)?;
    if secret_commitments.len() != shape.chunks
        || error_commitments.len() != shape.chunks
        || secret_commitments
            .iter()
            .chain(error_commitments)
            .any(|point| point.is_identity())
    {
        return Err(ZkAmsMkheCpkRelationErrorV1::MembershipEvidence);
    }
    let chunk_coefficients = shape
        .degree
        .checked_div(shape.chunks)
        .ok_or(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
    let generators = ZkAmsT256BulletproofSuiteV1::generators();
    if chunk_coefficients == 0 || chunk_coefficients > generators.g_bold.len() {
        return Err(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling);
    }
    let mut digests = [ZkAmsMkheCpkCommitmentFirstMessageDigestV1([0; 32]);
        ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1];
    for (repetition, challenge) in challenges.iter().copied().enumerate() {
        let challenge_scalar = Scalar::from_u64(u64::from(challenge));
        let negative_challenge = Scalar::zero() - challenge_scalar;
        let mut role_points = [
            try_exact_capacity_vec_v1(shape.chunks)
                .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?,
            try_exact_capacity_vec_v1(shape.chunks)
                .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?,
        ];
        for (role, commitments) in [secret_commitments, error_commitments]
            .into_iter()
            .enumerate()
        {
            for (chunk, commitment) in commitments.iter().copied().enumerate() {
                let exact_terms = chunk_coefficients
                    .checked_add(2)
                    .ok_or(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
                let mut terms = try_exact_capacity_vec_v1(exact_terms)
                    .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
                let coefficient_start = chunk
                    .checked_mul(chunk_coefficients)
                    .ok_or(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
                for local_coefficient in 0..chunk_coefficients {
                    let coefficient = coefficient_start
                        .checked_add(local_coefficient)
                        .ok_or(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
                    let response =
                        body.responses[response_index(shape, repetition, role, coefficient)?];
                    terms.push((
                        t256_scalar_from_signed_i64_v1(response),
                        generators.g_bold[local_coefficient],
                    ));
                }
                terms.push((
                    body.blind_responses[blind_response_index(shape, repetition, role, chunk)?],
                    generators.h,
                ));
                terms.push((negative_challenge, commitment));
                if terms.len() != exact_terms || terms.capacity() != exact_terms {
                    return Err(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling);
                }
                let point = try_exact_multiexp_v1::<ZkAmsT256BulletproofSuiteV1>(&terms)
                    .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
                if point.is_identity() {
                    return Err(ZkAmsMkheCpkRelationErrorV1::FirstMessageRejected);
                }
                role_points[role].push(point);
            }
        }
        if role_points
            .iter()
            .any(|points| points.len() != shape.chunks || points.capacity() != shape.chunks)
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling);
        }
        digests[repetition] =
            ZkAmsMkheCpkCommitmentFirstMessageDigestV1::from_reconstructed_points_for_shape(
                repetition,
                &role_points[0],
                &role_points[1],
            )?;
    }
    Ok(digests)
}
#[allow(clippy::too_many_arguments)]
fn reconstruct_cpk_rns_first_messages_for_shape_v1<DA, RB>(
    relation_shape: CpkRelationShapeV1,
    rns_shape: CpkRnsDigestShapeV1,
    moduli: &[u64],
    negacyclic_roots: &[u64],
    plaintext_modulus_residues: &[u64],
    body: &CpkRelationBodyV1,
    challenges: [u32; ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1],
    mut derive_public_a_limb: DA,
    mut read_party_b_limb: RB,
) -> Result<
    [ZkAmsMkheCpkRnsFirstMessageDigestV1; ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1],
    ZkAmsMkheCpkRelationErrorV1,
>
where
    DA: FnMut(usize, u64) -> Result<Vec<u64>, ZkAmsMkheCpkRelationErrorV1>,
    RB: FnMut(usize, u64) -> Result<Vec<u64>, ZkAmsMkheCpkRelationErrorV1>,
{
    relation_shape.validate()?;
    body.validate(relation_shape)?;
    if rns_shape.degree != relation_shape.degree
        || rns_shape.degree == 0
        || rns_shape.degree > ZK_AMS_MKHE_CPK_RING_DEGREE_V1
        || rns_shape.limbs == 0
        || rns_shape.limbs > ZK_AMS_MKHE_CPK_RNS_LIMBS_V1
        || moduli.len() != rns_shape.limbs
        || negacyclic_roots.len() != rns_shape.limbs
        || plaintext_modulus_residues.len() != rns_shape.limbs
        || moduli
            .iter()
            .zip(negacyclic_roots)
            .zip(plaintext_modulus_residues)
            .any(|((&modulus, &root), &plaintext)| {
                modulus <= u64::from(u32::MAX)
                    || root <= 1
                    || root >= modulus
                    || plaintext == 0
                    || plaintext >= modulus
            })
    {
        return Err(ZkAmsMkheCpkRelationErrorV1::NativeRelation);
    }
    let mut builders = try_exact_capacity_vec_v1(relation_shape.repetitions)
        .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
    for repetition in 0..relation_shape.repetitions {
        builders.push(ZkAmsMkheCpkRnsFirstMessageDigestBuilderV1::new_for_shape(
            repetition, rns_shape,
        )?);
    }
    if builders.len() != relation_shape.repetitions
        || builders.capacity() != relation_shape.repetitions
    {
        return Err(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling);
    }
    for (limb, ((&modulus, &root), &plaintext_modulus)) in moduli
        .iter()
        .zip(negacyclic_roots)
        .zip(plaintext_modulus_residues)
        .enumerate()
    {
        let public_a = derive_public_a_limb(limb, modulus)?;
        let party_b = read_party_b_limb(limb, modulus)?;
        if public_a.len() != rns_shape.degree
            || party_b.len() != rns_shape.degree
            || public_a
                .iter()
                .chain(&party_b)
                .any(|value| *value >= modulus)
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::NativeRelation);
        }
        for builder in &mut builders {
            builder.begin_limb(limb, modulus)?;
        }
        for (repetition, (&challenge, builder)) in challenges.iter().zip(&mut builders).enumerate()
        {
            let secret_start = response_index(relation_shape, repetition, 0, 0)?;
            let error_start = response_index(relation_shape, repetition, 1, 0)?;
            let secret_end = secret_start
                .checked_add(rns_shape.degree)
                .ok_or(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
            let error_end = error_start
                .checked_add(rns_shape.degree)
                .ok_or(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
            let secret_responses = body
                .responses
                .get(secret_start..secret_end)
                .ok_or(ZkAmsMkheCpkRelationErrorV1::RelationBody)?;
            let error_responses = body
                .responses
                .get(error_start..error_end)
                .ok_or(ZkAmsMkheCpkRelationErrorV1::RelationBody)?;
            let mut secret_residues = try_exact_capacity_vec_v1(rns_shape.degree)
                .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
            secret_residues.extend(
                secret_responses
                    .iter()
                    .copied()
                    .map(|response| signed_mod(response, modulus)),
            );
            if secret_residues.len() != rns_shape.degree
                || secret_residues.capacity() != rns_shape.degree
            {
                return Err(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling);
            }
            let mut first_message = negacyclic_multiply(&public_a, &secret_residues, modulus, root)
                .map_err(|error| match error {
                    super::ZkAmsMkheErrorV1::ResourceCeilingExceeded => {
                        ZkAmsMkheCpkRelationErrorV1::ResourceCeiling
                    }
                    _ => ZkAmsMkheCpkRelationErrorV1::NativeRelation,
                })?;
            for (coefficient, value) in first_message.iter_mut().enumerate() {
                let negated_product = mod_sub(0, *value, modulus);
                let scaled_error = mod_mul(
                    plaintext_modulus,
                    signed_mod(error_responses[coefficient], modulus),
                    modulus,
                );
                let challenged_b = mod_mul(u64::from(challenge), party_b[coefficient], modulus);
                *value = mod_sub(
                    mod_add(negated_product, scaled_error, modulus),
                    challenged_b,
                    modulus,
                );
            }
            builder.update_residues(&first_message)?;
            builder.finish_limb()?;
        }
    }
    let mut digests =
        [ZkAmsMkheCpkRnsFirstMessageDigestV1([0; 32]); ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1];
    for (repetition, builder) in builders.into_iter().enumerate() {
        digests[repetition] = builder.finish()?;
    }
    Ok(digests)
}
struct CpkPartyBStreamReaderV1<'a, P: ?Sized> {
    provider: &'a mut P,
    transaction: ZkAmsMkheDirectObjectReadTransactionV1,
    shape: CpkRnsDigestShapeV1,
    next_limb: usize,
}
impl<'a, P> CpkPartyBStreamReaderV1<'a, P>
where
    P: ZkAmsMkheDirectObjectReadAtProviderV1 + ?Sized,
{
    fn begin(
        pointer: ZkAmsMkheDirectObjectPointerV1,
        shape: CpkRnsDigestShapeV1,
        provider: &'a mut P,
    ) -> Result<Self, ZkAmsMkheCpkRelationErrorV1> {
        if shape.limbs == 0
            || shape.limbs > ZK_AMS_MKHE_CPK_RNS_LIMBS_V1
            || shape.degree == 0
            || shape.degree > ZK_AMS_MKHE_CPK_RING_DEGREE_V1
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::NativeRelation);
        }
        let coefficient_count = shape
            .limbs
            .checked_mul(shape.degree)
            .ok_or(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
        let expected_bytes = coefficient_count
            .checked_mul(8)
            .and_then(|value| value.checked_add(4))
            .ok_or(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
        if pointer.kind() != ZkAmsMkheDirectObjectKindV1::CpkPartyB
            || usize::try_from(pointer.payload_bytes()).ok() != Some(expected_bytes)
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::ObjectPointer);
        }
        let transaction = ZkAmsMkheDirectObjectReadTransactionV1::begin(
            ZkAmsMkheDirectObjectKindV1::CpkPartyB,
            pointer,
            provider,
        )
        .map_err(|_| ZkAmsMkheCpkRelationErrorV1::DirectObject)?;
        let mut reader = Self {
            provider,
            transaction,
            shape,
            next_limb: 0,
        };
        let mut count = [0_u8; 4];
        if reader
            .transaction
            .read_next(reader.provider, &mut count)
            .map_err(|_| ZkAmsMkheCpkRelationErrorV1::DirectObject)?
            != count.len()
            || usize::try_from(u32::from_be_bytes(count)).ok() != Some(coefficient_count)
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::NativeRelation);
        }
        Ok(reader)
    }
    fn read_limb(
        &mut self,
        limb: usize,
        modulus: u64,
    ) -> Result<Vec<u64>, ZkAmsMkheCpkRelationErrorV1> {
        if limb != self.next_limb || limb >= self.shape.limbs || modulus <= u64::from(u32::MAX) {
            return Err(ZkAmsMkheCpkRelationErrorV1::NativeRelation);
        }
        let mut values = try_exact_capacity_vec_v1(self.shape.degree)
            .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
        let mut buffer = [0_u8; ZK_AMS_MKHE_DIRECT_OBJECT_READ_BYTES_V1];
        while values.len() != self.shape.degree {
            let remaining_coefficients = self.shape.degree - values.len();
            let take_coefficients = remaining_coefficients.min(buffer.len() / 8);
            let take_bytes = take_coefficients
                .checked_mul(8)
                .ok_or(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
            let read = self
                .transaction
                .read_next(self.provider, &mut buffer[..take_bytes])
                .map_err(|_| ZkAmsMkheCpkRelationErrorV1::DirectObject)?;
            if read != take_bytes {
                return Err(ZkAmsMkheCpkRelationErrorV1::DirectObject);
            }
            for encoded in buffer[..read].chunks_exact(8) {
                let residue = u64::from_be_bytes(
                    encoded
                        .try_into()
                        .map_err(|_| ZkAmsMkheCpkRelationErrorV1::NativeRelation)?,
                );
                if residue >= modulus {
                    return Err(ZkAmsMkheCpkRelationErrorV1::NativeRelation);
                }
                values.push(residue);
            }
        }
        self.next_limb += 1;
        Ok(values)
    }
    fn finish(self) -> Result<ZkAmsMkheDirectObjectReadReceiptV1, ZkAmsMkheCpkRelationErrorV1> {
        if self.next_limb != self.shape.limbs || self.transaction.remaining_bytes() != 0 {
            return Err(ZkAmsMkheCpkRelationErrorV1::NativeRelation);
        }
        self.transaction
            .finish(self.provider)
            .map_err(|_| ZkAmsMkheCpkRelationErrorV1::DirectObject)
    }
}
fn read_cpk_relation_proof_object_v1<P>(
    pointer: ZkAmsMkheCpkRelationProofPointerV1,
    provider: &mut P,
) -> Result<
    (
        ZkAmsMkheCpkRelationProofV1,
        ZkAmsMkheDirectObjectReadReceiptV1,
    ),
    ZkAmsMkheCpkRelationErrorV1,
>
where
    P: ZkAmsMkheDirectObjectReadAtProviderV1 + ?Sized,
{
    let mut transaction = ZkAmsMkheDirectObjectReadTransactionV1::begin(
        ZkAmsMkheDirectObjectKindV1::CpkRelationProof,
        pointer.0,
        provider,
    )
    .map_err(|_| ZkAmsMkheCpkRelationErrorV1::DirectObject)?;
    let mut wire = try_exact_capacity_vec_v1(ZK_AMS_MKHE_CPK_RELATION_PROOF_BYTES_V1)
        .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
    let mut buffer = [0_u8; ZK_AMS_MKHE_DIRECT_OBJECT_READ_BYTES_V1];
    while transaction.remaining_bytes() != 0 {
        let read = transaction
            .read_next(provider, &mut buffer)
            .map_err(|_| ZkAmsMkheCpkRelationErrorV1::DirectObject)?;
        if read == 0 {
            return Err(ZkAmsMkheCpkRelationErrorV1::DirectObject);
        }
        wire.extend_from_slice(&buffer[..read]);
    }
    let receipt = transaction
        .finish(provider)
        .map_err(|_| ZkAmsMkheCpkRelationErrorV1::DirectObject)?;
    if wire.len() != ZK_AMS_MKHE_CPK_RELATION_PROOF_BYTES_V1 {
        return Err(ZkAmsMkheCpkRelationErrorV1::RelationBody);
    }
    let proof = ZkAmsMkheCpkRelationProofV1::from_wire_bytes_exact(&wire)?;
    Ok((proof, receipt))
}
fn direct_object_receipts_share_snapshot_v1(
    left: &ZkAmsMkheDirectObjectReadReceiptV1,
    right: &ZkAmsMkheDirectObjectReadReceiptV1,
) -> bool {
    left.snapshot().provider_identity() == right.snapshot().provider_identity()
        && left.snapshot().snapshot_identity() == right.snapshot().snapshot_identity()
}
fn complete_cpk_contribution_digest_v1(
    statement: ZkAmsMkheCpkShareStatementV1,
    header: ZkAmsMkheCpkRelationHeaderV1,
    secret_membership_wire: &[u8],
    error_membership_wire: &[u8],
    relation_proof_pointer: ZkAmsMkheCpkRelationProofPointerV1,
) -> Result<[u8; 32], ZkAmsMkheCpkRelationErrorV1> {
    header.validate_against(statement, secret_membership_wire, error_membership_wire)?;
    let statement_wire = statement.to_wire_bytes()?;
    let header_wire = header.to_wire_bytes()?;
    let mut hash = Keccak256::new();
    hash.update(CPK_COMPLETE_CONTRIBUTION_DOMAIN_V1);
    hash.update(&[MKHE_VERSION_V1, CPK_RELATION_ALGORITHM_V1]);
    hash.update(&(statement_wire.len() as u16).to_be_bytes());
    hash.update(&statement_wire);
    hash.update(&(header_wire.len() as u16).to_be_bytes());
    hash.update(&header_wire);
    hash.update(&statement.party_b_pointer().to_wire_bytes());
    hash.update(&relation_proof_pointer.to_wire_bytes());
    hash.update(&framed_wire_digest(
        CPK_SECRET_MEMBERSHIP_WIRE_DIGEST_DOMAIN_V1,
        secret_membership_wire,
    ));
    hash.update(&framed_wire_digest(
        CPK_ERROR_MEMBERSHIP_WIRE_DIGEST_DOMAIN_V1,
        error_membership_wire,
    ));
    Ok(hash.finalize())
}
fn authentication_from_wire_v1(
    authentication: ZkAmsMkheAuthenticationWireV1,
) -> ArtifactAuthentication {
    ArtifactAuthentication {
        version: MKHE_VERSION_V1,
        party: authentication.party(),
        public_key: authentication.public_key(),
        signature: authentication.signature(),
    }
}
fn cpk_authentication_wire_digest_v1(authentication: ZkAmsMkheAuthenticationWireV1) -> [u8; 32] {
    let mut hash = Keccak256::new();
    hash.update(CPK_AUTHENTICATION_WIRE_DOMAIN_V1);
    hash.update(&[MKHE_VERSION_V1]);
    hash.update(&authentication.party().to_bytes());
    hash.update(&authentication.public_key());
    hash.update(&authentication.signature());
    hash.finalize()
}
/// Authenticate exact public inputs after proof publication without exposing the signing scalar.
#[allow(clippy::too_many_arguments)]
pub(super) fn authenticate_zk_ams_mkhe_cpk_contribution_v1<R: MaskedRelaxedRandomSourceV1>(
    statement: ZkAmsMkheCpkShareStatementV1,
    header: ZkAmsMkheCpkRelationHeaderV1,
    secret_membership_wire: &[u8],
    error_membership_wire: &[u8],
    relation_proof_pointer: ZkAmsMkheCpkRelationProofPointerV1,
    party_secret: &ZkAmsMkheActivePartySecretV1,
    random: &mut R,
) -> Result<ZkAmsMkheAuthenticationWireV1, ZkAmsMkheCpkRelationErrorV1> {
    use ZkAmsMkheCpkRelationErrorV1::{Authentication, RandomUnavailable};
    let contribution_digest = complete_cpk_contribution_digest_v1(
        statement,
        header,
        secret_membership_wire,
        error_membership_wire,
        relation_proof_pointer,
    )?;
    let authentication = party_secret
        .authenticate_artifact(CPK_CONTRIBUTION_AUTH_DOMAIN_V1, contribution_digest, random)
        .map_err(|error| match error {
            super::ZkAmsMkheErrorV1::RandomUnavailable => RandomUnavailable,
            _ => Authentication,
        })?;
    if authentication.party != statement.party() {
        return Err(ZkAmsMkheCpkRelationErrorV1::Authentication);
    }
    ZkAmsMkheAuthenticationWireV1::new(
        authentication.party,
        authentication.public_key,
        authentication.signature,
    )
    .map_err(|_| ZkAmsMkheCpkRelationErrorV1::Authentication)
}
fn verify_cpk_contribution_authentication_v1(
    roster: &ZkAmsMkheGovernedActiveRosterV1,
    statement: ZkAmsMkheCpkShareStatementV1,
    contribution_digest: [u8; 32],
    authentication: ZkAmsMkheAuthenticationWireV1,
) -> Result<ArtifactAuthentication, ZkAmsMkheCpkRelationErrorV1> {
    let party_index = statement.party_index();
    if contribution_digest == [0; 32]
        || party_index >= ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1
        || authentication.party() != statement.party()
        || authentication.public_key()
            != roster.participants()[party_index].authentication_public_key()
    {
        return Err(ZkAmsMkheCpkRelationErrorV1::Authentication);
    }
    let authentication = authentication_from_wire_v1(authentication);
    authentication
        .verify(CPK_CONTRIBUTION_AUTH_DOMAIN_V1, contribution_digest)
        .map_err(|_| ZkAmsMkheCpkRelationErrorV1::Authentication)?;
    Ok(authentication)
}
/// Verify the complete native CPK relation under an independently governed roster.
///
/// Both direct objects must be served by the same immutable provider snapshot.
/// The proof object is authenticated before membership or ring work; the party
/// `b` object is then consumed in one canonical limb-major pass.  Success
/// consumes both membership receipts, both read receipts, and the verified
/// contribution authentication into one move-only relation receipt.
#[allow(clippy::too_many_arguments)]
pub(super) fn verify_zk_ams_mkhe_cpk_relation_v1<P>(
    roster: &ZkAmsMkheGovernedActiveRosterV1,
    expected_cpk_transcript_digest: [u8; 32],
    statement: ZkAmsMkheCpkShareStatementV1,
    secret_membership_wire: &[u8],
    error_membership_wire: &[u8],
    relation_proof_pointer: ZkAmsMkheCpkRelationProofPointerV1,
    authentication_wire: ZkAmsMkheAuthenticationWireV1,
    provider: &mut P,
) -> Result<VerifiedZkAmsMkheCpkRelationReceiptV1, ZkAmsMkheCpkRelationErrorV1>
where
    P: ZkAmsMkheDirectObjectReadAtProviderV1 + ?Sized,
{
    let profile =
        statement.validate_against_governed_roster(roster, expected_cpk_transcript_digest)?;
    let (proof, relation_proof_read_receipt) =
        read_cpk_relation_proof_object_v1(relation_proof_pointer, provider)?;
    let header = proof.header();
    header.validate_against(statement, secret_membership_wire, error_membership_wire)?;
    let complete_contribution_digest = complete_cpk_contribution_digest_v1(
        statement,
        header,
        secret_membership_wire,
        error_membership_wire,
        relation_proof_pointer,
    )?;
    let authentication = verify_cpk_contribution_authentication_v1(
        roster,
        statement,
        complete_contribution_digest,
        authentication_wire,
    )?;
    let membership_inputs = verify_zk_ams_mkhe_cpk_membership_inputs_v1(
        statement,
        header,
        secret_membership_wire,
        error_membership_wire,
    )?;
    let challenges = cpk_challenges_from_seed_v1(proof.challenge_seed());
    let commitment_first_messages = reconstruct_cpk_commitment_first_messages_for_shape_v1(
        CpkRelationShapeV1::RELEASE,
        &proof.body,
        challenges,
        membership_inputs.secret.commitments(),
        membership_inputs.error.commitments(),
    )?;
    let rns_shape = CpkRnsDigestShapeV1 {
        limbs: ZK_AMS_MKHE_CPK_RNS_LIMBS_V1,
        degree: ZK_AMS_MKHE_CPK_RING_DEGREE_V1,
    };
    let mut party_b_reader =
        CpkPartyBStreamReaderV1::begin(statement.party_b_pointer().0, rns_shape, provider)?;
    let mut plaintext_modulus_residues = try_exact_capacity_vec_v1(profile.moduli.len())
        .map_err(|_| ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
    plaintext_modulus_residues.extend(
        profile
            .moduli
            .iter()
            .map(|modulus| profile.plaintext_modulus.residue(*modulus)),
    );
    if plaintext_modulus_residues.len() != profile.moduli.len()
        || plaintext_modulus_residues.capacity() != profile.moduli.len()
    {
        return Err(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling);
    }
    let prepared_public_a =
        prepare_active_collective_public_a_v1(&profile, roster, expected_cpk_transcript_digest)?;
    let mut remaining_public_a_candidates =
        prepared_public_a.candidate_budget_for_limbs_v1(profile.moduli.len())?;
    let rns_first_messages = reconstruct_cpk_rns_first_messages_for_shape_v1(
        CpkRelationShapeV1::RELEASE,
        rns_shape,
        profile.moduli,
        profile.negacyclic_roots,
        &plaintext_modulus_residues,
        &proof.body,
        challenges,
        |limb, modulus| {
            if profile.moduli.get(limb).copied() != Some(modulus) {
                return Err(ZkAmsMkheCpkRelationErrorV1::NativeRelation);
            }
            prepared_public_a.derive_limb_budgeted_v1(limb, &mut remaining_public_a_candidates)
        },
        |limb, modulus| party_b_reader.read_limb(limb, modulus),
    )?;
    let party_b_read_receipt = party_b_reader.finish()?;
    if !direct_object_receipts_share_snapshot_v1(
        &relation_proof_read_receipt,
        &party_b_read_receipt,
    ) {
        return Err(ZkAmsMkheCpkRelationErrorV1::DirectObject);
    }
    let (reconstructed_seed, reconstructed_challenges) = reconstruct_zk_ams_mkhe_cpk_challenges_v1(
        statement,
        secret_membership_wire,
        error_membership_wire,
        header,
        commitment_first_messages,
        rns_first_messages,
    )?;
    if reconstructed_seed != proof.challenge_seed() || reconstructed_challenges != challenges {
        return Err(ZkAmsMkheCpkRelationErrorV1::Transcript);
    }
    let mut receipt = VerifiedZkAmsMkheCpkRelationReceiptV1 {
        _seal: CpkRelationVerificationSealV1,
        _membership_inputs: membership_inputs,
        _party_b_read_receipt: party_b_read_receipt,
        _relation_proof_read_receipt: relation_proof_read_receipt,
        _authentication: authentication,
        statement,
        statement_digest: statement.statement_digest()?,
        secret_membership_wire_digest: framed_wire_digest(
            CPK_SECRET_MEMBERSHIP_WIRE_DIGEST_DOMAIN_V1,
            secret_membership_wire,
        ),
        error_membership_wire_digest: framed_wire_digest(
            CPK_ERROR_MEMBERSHIP_WIRE_DIGEST_DOMAIN_V1,
            error_membership_wire,
        ),
        party_b_payload_blake3: statement.party_b_pointer().payload_blake3(),
        relation_proof_payload_blake3: relation_proof_pointer.payload_blake3(),
        complete_contribution_digest,
        authentication_wire_digest: cpk_authentication_wire_digest_v1(authentication_wire),
        verification_digest: [0; 32],
    };
    receipt.verification_digest = verified_relation_digest(&receipt);
    if receipt.verification_digest == [0; 32] {
        return Err(ZkAmsMkheCpkRelationErrorV1::Transcript);
    }
    Ok(receipt)
}
/// Non-serializable receipt constructed only by the complete native verifier.
///
/// It is intentionally neither `Clone` nor `Copy` and has no decoder or
/// membership-only constructor.  The owned capabilities prove that both
/// membership proofs, both complete direct-object reads, native ring equations,
/// transcript, and governed party authentication succeeded together.
pub(super) struct VerifiedZkAmsMkheCpkRelationReceiptV1 {
    _seal: CpkRelationVerificationSealV1,
    _membership_inputs: ZkAmsMkheVerifiedCpkMembershipInputsV1,
    _party_b_read_receipt: ZkAmsMkheDirectObjectReadReceiptV1,
    _relation_proof_read_receipt: ZkAmsMkheDirectObjectReadReceiptV1,
    _authentication: ArtifactAuthentication,
    statement: ZkAmsMkheCpkShareStatementV1,
    statement_digest: [u8; 32],
    secret_membership_wire_digest: [u8; 32],
    error_membership_wire_digest: [u8; 32],
    party_b_payload_blake3: [u8; 32],
    relation_proof_payload_blake3: [u8; 32],
    complete_contribution_digest: [u8; 32],
    authentication_wire_digest: [u8; 32],
    verification_digest: [u8; 32],
}
struct CpkRelationVerificationSealV1;
impl fmt::Debug for VerifiedZkAmsMkheCpkRelationReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedZkAmsMkheCpkRelationReceiptV1")
            .field(
                "verification_digest",
                &hex::encode(self.verification_digest),
            )
            .finish_non_exhaustive()
    }
}
/// Move-only contribution capability obtainable only from a complete relation receipt.
pub(super) struct VerifiedZkAmsMkheCpkContributionV1 {
    receipt: VerifiedZkAmsMkheCpkRelationReceiptV1,
}
impl VerifiedZkAmsMkheCpkContributionV1 {
    /// Consume a complete relation receipt.  No membership evidence can call this directly.
    pub(super) fn from_verified_relation(receipt: VerifiedZkAmsMkheCpkRelationReceiptV1) -> Self {
        Self { receipt }
    }
    /// Deterministic verification provenance; never a replacement for the capability.
    #[must_use]
    pub(super) const fn verification_digest(&self) -> [u8; 32] {
        self.receipt.verification_digest
    }
    /// Consume the complete contribution into the sole lineage accepted by
    /// collective-key-share admission.
    ///
    /// This deliberately repeats every state/share axis at the transition: possession of a
    /// previously verified relation is insufficient when its roster, transcript, party position, or
    /// canonical `b_i` object does not match the state being admitted.
    pub(super) fn into_collective_binding_source(
        self,
        roster: &ZkAmsMkheGovernedActiveRosterV1,
        expected_cpk_transcript_digest: [u8; 32],
        expected_party_index: usize,
        expected_party_b_payload_blake3: [u8; 32],
    ) -> Result<VerifiedZkAmsMkheCpkBindingSourceV1, ZkAmsMkheCpkRelationErrorV1> {
        let source = self.into_compact_decryption_source(
            roster,
            expected_cpk_transcript_digest,
            expected_party_index,
        )?;
        if expected_party_b_payload_blake3 == [0; 32]
            || source.party_b_pointer().payload_blake3() != expected_party_b_payload_blake3
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::GovernedContext);
        }
        Ok(source.into_binding_source())
    }
    /// Consume the complete verifier capability for bounded decryption setup.
    ///
    /// Unlike the legacy admission adapter, this transition does not accept a caller-supplied
    /// content hash. It carries the exact governed pointer and the verifier's owned complete-read
    /// receipt forward with the move-only secret-commitment lineage. The bounded ceremony must
    /// subsequently match and republish the canonical public share at this pointer.
    pub(super) fn into_compact_decryption_source(
        self,
        roster: &ZkAmsMkheGovernedActiveRosterV1,
        expected_cpk_transcript_digest: [u8; 32],
        expected_party_index: usize,
    ) -> Result<VerifiedZkAmsMkheCompactDecryptionSourceV1, ZkAmsMkheCpkRelationErrorV1> {
        let receipt = self.receipt;
        receipt
            .statement
            .validate_against_governed_roster(roster, expected_cpk_transcript_digest)?;
        if expected_party_index >= ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1
            || receipt.statement.party_index() != expected_party_index
            || receipt.statement.party_b_pointer().payload_blake3() == [0; 32]
            || receipt.statement.party_b_pointer().payload_blake3()
                != receipt.party_b_payload_blake3
            || receipt.statement.statement_digest()? != receipt.statement_digest
            || receipt.verification_digest == [0; 32]
            || receipt.verification_digest != verified_relation_digest(&receipt)
        {
            return Err(ZkAmsMkheCpkRelationErrorV1::GovernedContext);
        }
        validate_cpk_membership_context_axes_v1(
            receipt.statement,
            receipt._membership_inputs.secret.context(),
            receipt._membership_inputs.error.context(),
        )?;
        let secret = &receipt._membership_inputs.secret;
        let binding_source = VerifiedZkAmsMkheCpkBindingSourceV1 {
            profile_digest: receipt.statement.profile_digest,
            security_certificate_digest: receipt.statement.security_certificate_digest,
            roster_digest: receipt.statement.roster_digest,
            key_material_digest: receipt.statement.key_material_digest,
            epoch: receipt.statement.epoch,
            cpk_transcript_digest: receipt.statement.cpk_transcript_digest,
            party_index: receipt.statement.party_index,
            party: receipt.statement.party,
            party_b_payload_blake3: receipt.party_b_payload_blake3,
            generator_basis_digest: secret.generator_basis_digest(),
            commitments: *secret.commitments(),
            commitment_set_digest: secret.commitment_set_digest(),
            membership_proof_digest: secret.proof_set_digest(),
            verifier_transcript_digest: secret.verifier_transcript_digest(),
            relation_verification_digest: receipt.verification_digest,
        };
        Ok(VerifiedZkAmsMkheCompactDecryptionSourceV1 {
            binding_source,
            party_b_pointer: receipt.statement.party_b_pointer(),
            party_b_read_receipt: receipt._party_b_read_receipt,
        })
    }
}
impl fmt::Debug for VerifiedZkAmsMkheCpkContributionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedZkAmsMkheCpkContributionV1")
            .field(
                "verification_digest",
                &hex::encode(self.verification_digest()),
            )
            .finish_non_exhaustive()
    }
}
/// Move-only CPK lineage plus exact direct-object provenance for decryption.
///
/// There is no decoder, raw-pointer constructor, or `Clone` implementation. Only the complete
/// native CPK verifier can create the contribution consumed into this value.
pub(super) struct VerifiedZkAmsMkheCompactDecryptionSourceV1 {
    binding_source: VerifiedZkAmsMkheCpkBindingSourceV1,
    party_b_pointer: ZkAmsMkheCpkPartyBPointerV1,
    party_b_read_receipt: ZkAmsMkheDirectObjectReadReceiptV1,
}
impl VerifiedZkAmsMkheCompactDecryptionSourceV1 {
    #[must_use]
    pub(super) const fn party_b_pointer(&self) -> ZkAmsMkheDirectObjectPointerV1 {
        self.party_b_pointer.direct_object_pointer()
    }
    pub(super) fn into_parts(
        self,
    ) -> (
        VerifiedZkAmsMkheCpkBindingSourceV1,
        ZkAmsMkheDirectObjectPointerV1,
        ZkAmsMkheDirectObjectReadReceiptV1,
    ) {
        (
            self.binding_source,
            self.party_b_pointer.direct_object_pointer(),
            self.party_b_read_receipt,
        )
    }
    fn into_binding_source(self) -> VerifiedZkAmsMkheCpkBindingSourceV1 {
        self.binding_source
    }
}
impl fmt::Debug for VerifiedZkAmsMkheCompactDecryptionSourceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedZkAmsMkheCompactDecryptionSourceV1")
            .field("party_b_pointer", &self.party_b_pointer)
            .finish_non_exhaustive()
    }
}
/// Move-only secret-commitment lineage sealed by the complete CPK verifier.
///
/// The fields are private to this module and there is no decoder or public
/// constructor.  In particular, the membership-only receipts cannot produce
/// this type; it is obtained only by consuming
/// [`VerifiedZkAmsMkheCpkContributionV1`] at the exact collective share axes.
pub(super) struct VerifiedZkAmsMkheCpkBindingSourceV1 {
    profile_digest: [u8; 32],
    security_certificate_digest: [u8; 32],
    roster_digest: [u8; 32],
    key_material_digest: [u8; 32],
    epoch: u64,
    cpk_transcript_digest: [u8; 32],
    party_index: u8,
    party: ZkAmsMkhePartyIdV1,
    party_b_payload_blake3: [u8; 32],
    generator_basis_digest: [u8; 32],
    commitments: [Point; ZK_AMS_MKHE_CPK_CHUNKS_V1],
    commitment_set_digest: [u8; 32],
    membership_proof_digest: [u8; 32],
    verifier_transcript_digest: [u8; 32],
    relation_verification_digest: [u8; 32],
}
impl VerifiedZkAmsMkheCpkBindingSourceV1 {
    pub(super) const fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest
    }
    pub(super) const fn security_certificate_digest(&self) -> [u8; 32] {
        self.security_certificate_digest
    }
    pub(super) const fn roster_digest(&self) -> [u8; 32] {
        self.roster_digest
    }
    pub(super) const fn key_material_digest(&self) -> [u8; 32] {
        self.key_material_digest
    }
    pub(super) const fn epoch(&self) -> u64 {
        self.epoch
    }
    pub(super) const fn cpk_transcript_digest(&self) -> [u8; 32] {
        self.cpk_transcript_digest
    }
    pub(super) const fn party_index(&self) -> usize {
        self.party_index as usize
    }
    pub(super) const fn party(&self) -> ZkAmsMkhePartyIdV1 {
        self.party
    }
    pub(super) const fn party_b_payload_blake3(&self) -> [u8; 32] {
        self.party_b_payload_blake3
    }
    pub(super) const fn generator_basis_digest(&self) -> [u8; 32] {
        self.generator_basis_digest
    }
    pub(super) const fn commitments(&self) -> &[Point; ZK_AMS_MKHE_CPK_CHUNKS_V1] {
        &self.commitments
    }
    pub(super) const fn commitment_set_digest(&self) -> [u8; 32] {
        self.commitment_set_digest
    }
    pub(super) const fn membership_proof_digest(&self) -> [u8; 32] {
        self.membership_proof_digest
    }
    pub(super) const fn verifier_transcript_digest(&self) -> [u8; 32] {
        self.verifier_transcript_digest
    }
    pub(super) const fn relation_verification_digest(&self) -> [u8; 32] {
        self.relation_verification_digest
    }
}
impl fmt::Debug for VerifiedZkAmsMkheCpkBindingSourceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedZkAmsMkheCpkBindingSourceV1")
            .field(
                "relation_verification_digest",
                &hex::encode(self.relation_verification_digest),
            )
            .finish_non_exhaustive()
    }
}
fn verified_relation_digest(receipt: &VerifiedZkAmsMkheCpkRelationReceiptV1) -> [u8; 32] {
    let mut hash = Keccak256::new();
    hash.update(CPK_VERIFIED_RELATION_DOMAIN_V1);
    hash.update(&receipt.statement_digest);
    hash.update(&receipt.secret_membership_wire_digest);
    hash.update(&receipt.error_membership_wire_digest);
    hash.update(&receipt.party_b_payload_blake3);
    hash.update(&receipt.relation_proof_payload_blake3);
    hash.update(&receipt.complete_contribution_digest);
    hash.update(&receipt.authentication_wire_digest);
    hash.update(&receipt._party_b_read_receipt.receipt_digest());
    hash.update(&receipt._relation_proof_read_receipt.receipt_digest());
    hash.finalize()
}
fn framed_wire_digest(domain: &[u8], wire: &[u8]) -> [u8; 32] {
    let mut hash = Keccak256::new();
    hash.update(domain);
    hash.update(&[MKHE_VERSION_V1]);
    hash.update(&(wire.len() as u64).to_be_bytes());
    hash.update(wire);
    hash.finalize()
}
fn array_at<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], ZkAmsMkheCpkRelationErrorV1> {
    let end = offset
        .checked_add(N)
        .ok_or(ZkAmsMkheCpkRelationErrorV1::ResourceCeiling)?;
    bytes
        .get(offset..end)
        .ok_or(ZkAmsMkheCpkRelationErrorV1::RelationBody)?
        .try_into()
        .map_err(|_| ZkAmsMkheCpkRelationErrorV1::RelationBody)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::generalized_bulletproof::multiexp;
    use crate::vega::{
        MaskedRelaxedRandomErrorV1, VEGA_T256_SCALAR_MODULUS_BE_V1, derive_t256_generators_v1,
        sponge::keccak256,
    };
    fn digest(label: &[u8], axis: &[u8]) -> [u8; 32] {
        let mut hash = Keccak256::new();
        hash.update(b"iroha.zk-ams.v1.mkhe.cpk-relation.test-axis");
        hash.update(&(label.len() as u32).to_be_bytes());
        hash.update(label);
        hash.update(&(axis.len() as u32).to_be_bytes());
        hash.update(axis);
        hash.finalize()
    }
    fn share_statement_fixture(label: &[u8]) -> ZkAmsMkheCpkShareStatementV1 {
        ZkAmsMkheCpkShareStatementV1::new(
            digest(label, b"profile"),
            digest(label, b"security"),
            digest(label, b"roster"),
            digest(label, b"key-material"),
            digest(label, b"cpk-transcript"),
            digest(label, b"public-a-context"),
            ZkAmsMkhePartyIdV1::new(digest(label, b"party")).expect("test party"),
            3,
            17,
            ZkAmsMkheCpkPartyBPointerV1::new(digest(label, b"party-b-content"))
                .expect("test party-b pointer"),
        )
        .expect("test statement")
    }
    fn membership_wires(label: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let secret_block = digest(label, b"secret-membership");
        let error_block = digest(label, b"error-membership");
        let secret = (0..ZK_AMS_MKHE_CPK_SECRET_MEMBERSHIP_BYTES_V1)
            .map(|index| secret_block[index % secret_block.len()])
            .collect();
        let error = (0..ZK_AMS_MKHE_CPK_ERROR_MEMBERSHIP_BYTES_V1)
            .map(|index| error_block[index % error_block.len()])
            .collect();
        (secret, error)
    }
    fn synthetic_error_membership(
        statement: ZkAmsMkheCpkShareStatementV1,
        label: &[u8],
    ) -> ZkAmsMkheCpkErrorMembershipEvidenceV1 {
        let context = ZkAmsMkheCpkErrorMembershipContextV1::from_share_statement(statement)
            .expect("error context");
        let points = derive_t256_generators_v1(
            b"iroha.zk-ams.v1.mkhe.cpk-error-membership.test-points",
            ZK_AMS_MKHE_CPK_CHUNKS_V1,
        )
        .expect("test points");
        let chunks = core::array::from_fn(|index| {
            let mut proof = vec![index as u8; 1_513];
            proof[..32].copy_from_slice(&context.context_digest());
            proof[32..34].copy_from_slice(&(index as u16).to_be_bytes());
            let mut wire = Vec::with_capacity(1_560);
            wire.extend_from_slice(b"ZMBP");
            wire.push(1);
            wire.push(2);
            wire.extend_from_slice(&(index as u16).to_be_bytes());
            wire.extend_from_slice(&(ZK_AMS_MKHE_CPK_CHUNK_COEFFICIENTS_V1 as u32).to_be_bytes());
            wire.extend_from_slice(
                &points[index]
                    .to_non_identity_wire_bytes()
                    .expect("test point"),
            );
            wire.extend_from_slice(&(proof.len() as u16).to_be_bytes());
            wire.extend_from_slice(&proof);
            ZkAmsT256MembershipProofV1::from_wire_bytes_exact(&wire).expect("synthetic chunk")
        });
        let transcripts = core::array::from_fn(|index| {
            let mut hash = Keccak256::new();
            hash.update(b"iroha.zk-ams.v1.mkhe.cpk-error-membership.test-transcript");
            hash.update(label);
            hash.update(&context.context_digest());
            hash.update(&(index as u16).to_be_bytes());
            hash.update(&chunks[index].to_wire_bytes());
            hash.finalize()
        });
        let inner = ExactEightChunkMembershipEvidenceV1::assemble_for_test(
            context.inner,
            chunks,
            transcripts,
        )
        .expect("synthetic error evidence");
        ZkAmsMkheCpkErrorMembershipEvidenceV1 { inner }
    }
    fn header_fixture(
        label: &[u8],
    ) -> (
        ZkAmsMkheCpkShareStatementV1,
        Vec<u8>,
        Vec<u8>,
        ZkAmsMkheCpkRelationHeaderV1,
    ) {
        let statement = share_statement_fixture(label);
        let (secret, error) = membership_wires(label);
        let header =
            ZkAmsMkheCpkRelationHeaderV1::new(statement, &secret, &error).expect("test header");
        (statement, secret, error, header)
    }
    fn tiny_relation_shape() -> CpkRelationShapeV1 {
        CpkRelationShapeV1 {
            repetitions: ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1,
            witnesses: ZK_AMS_MKHE_CPK_RELATION_WITNESSES_V1,
            degree: 4,
            chunks: 2,
        }
    }
    fn tiny_body() -> CpkRelationBodyV1 {
        let shape = tiny_relation_shape();
        let mut responses = vec![0; shape.response_count().expect("tiny response count")];
        responses[0] = -ZK_AMS_MKHE_CPK_RESPONSE_BOUND_V1;
        let last = responses.len() - 1;
        responses[last] = ZK_AMS_MKHE_CPK_RESPONSE_BOUND_V1;
        let blind_responses = (0..shape
            .blind_response_count()
            .expect("tiny blind response count"))
            .map(|index| Scalar::from_u64(index as u64 + 1))
            .collect();
        CpkRelationBodyV1 {
            challenge_seed: digest(b"tiny-body", b"seed"),
            responses,
            blind_responses,
        }
    }
    fn tiny_public_vector_commitment(values: &[i64], blinding: Scalar) -> Point {
        let generators = ZkAmsT256BulletproofSuiteV1::generators();
        let mut terms = values
            .iter()
            .copied()
            .zip(generators.g_bold.iter().copied())
            .map(|(value, generator)| (t256_scalar_from_signed_i64_v1(value), generator))
            .collect::<Vec<_>>();
        terms.push((blinding, generators.h));
        multiexp::<ZkAmsT256BulletproofSuiteV1>(&terms)
    }
    #[derive(Clone)]
    struct TinyObjectProvider {
        pointer: ZkAmsMkheDirectObjectPointerV1,
        bytes: Vec<u8>,
        provider_identity: [u8; 32],
        snapshot_identity: [u8; 32],
    }
    impl TinyObjectProvider {
        fn cpk_party_b(bytes: Vec<u8>) -> Self {
            let pointer = ZkAmsMkheDirectObjectPointerV1::from_payload(
                ZkAmsMkheDirectObjectKindV1::CpkPartyB,
                &bytes,
            )
            .expect("tiny content address");
            Self {
                pointer,
                bytes,
                provider_identity: digest(b"tiny-provider", b"provider"),
                snapshot_identity: digest(b"tiny-provider", b"snapshot"),
            }
        }
    }
    impl ZkAmsMkheDirectObjectReadAtProviderV1 for TinyObjectProvider {
        fn provider_identity(&mut self) -> Result<[u8; 32], super::super::ZkAmsMkheErrorV1> {
            Ok(self.provider_identity)
        }
        fn snapshot_identity(&mut self) -> Result<[u8; 32], super::super::ZkAmsMkheErrorV1> {
            Ok(self.snapshot_identity)
        }
        fn object_len(
            &mut self,
            pointer: ZkAmsMkheDirectObjectPointerV1,
        ) -> Result<u64, super::super::ZkAmsMkheErrorV1> {
            if pointer != self.pointer {
                return Err(super::super::ZkAmsMkheErrorV1::InvalidWireEncoding);
            }
            u64::try_from(self.bytes.len())
                .map_err(|_| super::super::ZkAmsMkheErrorV1::ResourceCeilingExceeded)
        }
        fn read_at(
            &mut self,
            pointer: ZkAmsMkheDirectObjectPointerV1,
            absolute_offset: u64,
            destination: &mut [u8],
        ) -> Result<usize, super::super::ZkAmsMkheErrorV1> {
            if pointer != self.pointer {
                return Err(super::super::ZkAmsMkheErrorV1::InvalidWireEncoding);
            }
            let start = usize::try_from(absolute_offset)
                .map_err(|_| super::super::ZkAmsMkheErrorV1::InvalidWireEncoding)?;
            let end = start
                .checked_add(destination.len())
                .ok_or(super::super::ZkAmsMkheErrorV1::InvalidWireEncoding)?;
            let source = self
                .bytes
                .get(start..end)
                .ok_or(super::super::ZkAmsMkheErrorV1::InvalidWireEncoding)?;
            destination.copy_from_slice(source);
            Ok(destination.len())
        }
    }
    fn tiny_party_b_wire(limbs: &[Vec<u64>]) -> Vec<u8> {
        let count = limbs.iter().map(Vec::len).sum::<usize>();
        let mut bytes = Vec::with_capacity(4 + count * 8);
        bytes.extend_from_slice(&(count as u32).to_be_bytes());
        for limb in limbs {
            for residue in limb {
                bytes.extend_from_slice(&residue.to_be_bytes());
            }
        }
        bytes
    }
    struct StreamRandom {
        seed: [u8; 32],
        counter: u64,
    }
    impl StreamRandom {
        fn new(label: &[u8]) -> Self {
            Self {
                seed: keccak256(label),
                counter: 0,
            }
        }
    }
    impl MaskedRelaxedRandomSourceV1 for StreamRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), MaskedRelaxedRandomErrorV1> {
            let mut written = 0;
            while written < destination.len() {
                let mut hash = Keccak256::new();
                hash.update(&self.seed);
                hash.update(&self.counter.to_be_bytes());
                let block = hash.finalize();
                self.counter = self.counter.wrapping_add(1);
                let take = (destination.len() - written).min(block.len());
                destination[written..written + take].copy_from_slice(&block[..take]);
                written += take;
            }
            Ok(())
        }
    }
    struct ExactBlockRandom {
        blocks: Vec<[u8; 16]>,
        next: usize,
    }
    impl MaskedRelaxedRandomSourceV1 for ExactBlockRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), MaskedRelaxedRandomErrorV1> {
            if destination.len() != 16 {
                return Err(MaskedRelaxedRandomErrorV1::Unavailable);
            }
            let block = self
                .blocks
                .get(self.next)
                .ok_or(MaskedRelaxedRandomErrorV1::Unavailable)?;
            destination.copy_from_slice(block);
            self.next += 1;
            Ok(())
        }
    }
    struct FailingRandom;
    impl MaskedRelaxedRandomSourceV1 for FailingRandom {
        fn fill_bytes(
            &mut self,
            _destination: &mut [u8],
        ) -> Result<(), MaskedRelaxedRandomErrorV1> {
            Err(MaskedRelaxedRandomErrorV1::Unavailable)
        }
    }
    struct PanickingRandom;
    impl MaskedRelaxedRandomSourceV1 for PanickingRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), MaskedRelaxedRandomErrorV1> {
            destination.fill(0xa5);
            panic!("injected entropy-source panic after writing secret bytes")
        }
    }
    struct EndpointRandom {
        signed_block: [u8; 16],
    }
    impl MaskedRelaxedRandomSourceV1 for EndpointRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), MaskedRelaxedRandomErrorV1> {
            match destination.len() {
                16 => destination.copy_from_slice(&self.signed_block),
                64 => {
                    for (index, byte) in destination.iter_mut().enumerate() {
                        *byte = (index as u8).wrapping_add(1);
                    }
                }
                _ => return Err(MaskedRelaxedRandomErrorV1::Unavailable),
            }
            Ok(())
        }
    }
    fn manual_attempt(
        shape: CpkRelationShapeV1,
        mask: i64,
        blind_mask: Scalar,
    ) -> ZkAmsMkheCpkRelationMaskAttemptV1 {
        ZkAmsMkheCpkRelationMaskAttemptV1 {
            shape,
            masks: BestEffortErasingI64VecV1(vec![
                mask;
                shape
                    .response_count()
                    .expect("manual response count")
            ]),
            blind_masks: BestEffortErasingScalarVecV1(vec![
                blind_mask;
                shape
                    .blind_response_count()
                    .expect("manual blind count")
            ]),
        }
    }
    fn commitment_point_arrays() -> (
        [Point; ZK_AMS_MKHE_CPK_CHUNKS_V1],
        [Point; ZK_AMS_MKHE_CPK_CHUNKS_V1],
    ) {
        let points = derive_t256_generators_v1(
            b"iroha.zk-ams.v1.mkhe.cpk-relation.test-first-message-points",
            16,
        )
        .expect("test points");
        let secret: [Point; ZK_AMS_MKHE_CPK_CHUNKS_V1] =
            core::array::from_fn(|index| points[index]);
        let error: [Point; ZK_AMS_MKHE_CPK_CHUNKS_V1] =
            core::array::from_fn(|index| points[ZK_AMS_MKHE_CPK_CHUNKS_V1 + index]);
        (secret, error)
    }
    fn commitment_digests()
    -> [ZkAmsMkheCpkCommitmentFirstMessageDigestV1; ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1] {
        let (secret, error) = commitment_point_arrays();
        core::array::from_fn(|repetition| {
            ZkAmsMkheCpkCommitmentFirstMessageDigestV1::from_reconstructed_points(
                repetition, &secret, &error,
            )
            .expect("commitment digest")
        })
    }
    fn rns_digests()
    -> [ZkAmsMkheCpkRnsFirstMessageDigestV1; ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1] {
        core::array::from_fn(|repetition| {
            let mut builder = ZkAmsMkheCpkRnsFirstMessageDigestBuilderV1::new_for_shape(
                repetition,
                CpkRnsDigestShapeV1 {
                    limbs: 2,
                    degree: 4,
                },
            )
            .expect("tiny RNS builder");
            for limb in 0..2 {
                let modulus = 4_294_967_311_u64 + 2 * limb as u64;
                builder.begin_limb(limb, modulus).expect("begin limb");
                let residues = core::array::from_fn::<_, 4, _>(|coefficient| {
                    repetition as u64 * 100 + limb as u64 * 10 + coefficient as u64
                });
                builder.update_residues(&residues[..2]).expect("first half");
                builder
                    .update_residues(&residues[2..])
                    .expect("second half");
                builder.finish_limb().expect("finish limb");
            }
            builder.finish().expect("RNS digest")
        })
    }
    #[test]
    fn sealed_object_kinds_are_exact_and_never_alias_existing_tags() {
        assert_eq!(ZK_AMS_MKHE_CPK_PARTY_B_OBJECT_TAG_V1, 9);
        assert_eq!(ZK_AMS_MKHE_CPK_RELATION_PROOF_OBJECT_TAG_V1, 10);
        assert_eq!(ZK_AMS_MKHE_CPK_PARTY_B_OBJECT_BYTES_V1, 39_845_892);
        assert_eq!(ZK_AMS_MKHE_CPK_RELATION_PROOF_BYTES_V1, 8_390_896);
        let party_b = ZkAmsMkheCpkPartyBPointerV1::new(digest(b"pointer", b"party-b"))
            .expect("party-b pointer");
        let wire = party_b.to_wire_bytes();
        assert_eq!(wire.len(), 78);
        assert_eq!(wire[5], 9);
        assert_eq!(
            u64::from_be_bytes(wire[6..14].try_into().unwrap()),
            39_845_892
        );
        assert_eq!(
            ZkAmsMkheCpkPartyBPointerV1::from_wire_bytes_exact(&wire),
            Ok(party_b)
        );
        for end in 0..wire.len() {
            assert!(ZkAmsMkheCpkPartyBPointerV1::from_wire_bytes_exact(&wire[..end]).is_err());
        }
        let mut trailing = wire.to_vec();
        trailing.push(0);
        assert!(ZkAmsMkheCpkPartyBPointerV1::from_wire_bytes_exact(&trailing).is_err());
        for occupied in 1..=8 {
            let mut aliased = wire;
            aliased[5] = occupied;
            assert!(ZkAmsMkheCpkPartyBPointerV1::from_wire_bytes_exact(&aliased).is_err());
        }
        let proof = ZkAmsMkheCpkRelationProofPointerV1::new(digest(b"pointer", b"proof"))
            .expect("proof pointer");
        let proof_wire = proof.to_wire_bytes();
        assert_eq!(proof_wire[5], 10);
        assert_eq!(
            u64::from_be_bytes(proof_wire[6..14].try_into().unwrap()),
            8_390_896
        );
        assert_eq!(
            ZkAmsMkheCpkRelationProofPointerV1::from_wire_bytes_exact(&proof_wire),
            Ok(proof)
        );
        assert!(ZkAmsMkheCpkPartyBPointerV1::from_wire_bytes_exact(&proof_wire).is_err());
        assert!(ZkAmsMkheCpkRelationProofPointerV1::from_wire_bytes_exact(&wire).is_err());
        let mut wrong_length = wire;
        wrong_length[13] ^= 1;
        assert!(ZkAmsMkheCpkPartyBPointerV1::from_wire_bytes_exact(&wrong_length).is_err());
        let mut wrong_content = wire;
        wrong_content[14] ^= 1;
        assert!(ZkAmsMkheCpkPartyBPointerV1::from_wire_bytes_exact(&wrong_content).is_err());
        let mut wrong_binding = wire;
        wrong_binding[77] ^= 1;
        assert!(ZkAmsMkheCpkPartyBPointerV1::from_wire_bytes_exact(&wrong_binding).is_err());
        assert_eq!(
            ZkAmsMkheCpkPartyBPointerV1::new([0; 32]),
            Err(ZkAmsMkheCpkRelationErrorV1::ObjectPointer)
        );
    }
    #[test]
    fn statement_codec_is_exact_and_binds_every_governed_axis() {
        let statement = share_statement_fixture(b"canonical-statement");
        let wire = statement.to_wire_bytes().expect("statement wire");
        assert_eq!(wire.len(), ZK_AMS_MKHE_CPK_SHARE_STATEMENT_BYTES_V1);
        assert_eq!(
            ZkAmsMkheCpkShareStatementV1::from_wire_bytes_exact(&wire),
            Ok(statement)
        );
        for end in 0..wire.len() {
            assert!(ZkAmsMkheCpkShareStatementV1::from_wire_bytes_exact(&wire[..end]).is_err());
        }
        let mut trailing = wire.to_vec();
        trailing.extend_from_slice(&[0, 0]);
        assert!(ZkAmsMkheCpkShareStatementV1::from_wire_bytes_exact(&trailing).is_err());
        for offset in [0, 4, 5, 6, 7, 8, 12, 14, 18, 28, 284] {
            let mut changed = wire;
            changed[offset] ^= 1;
            assert!(
                ZkAmsMkheCpkShareStatementV1::from_wire_bytes_exact(&changed).is_err(),
                "structural byte {offset} was accepted"
            );
        }
        let mut bad_index = wire;
        bad_index[19] = 8;
        assert!(ZkAmsMkheCpkShareStatementV1::from_wire_bytes_exact(&bad_index).is_err());
        let mut zero_epoch = wire;
        zero_epoch[20..28].fill(0);
        assert!(ZkAmsMkheCpkShareStatementV1::from_wire_bytes_exact(&zero_epoch).is_err());
        let baseline_digest = statement.statement_digest().expect("statement digest");
        for offset in [60, 92, 124, 156, 188, 220, 252] {
            let mut changed = wire;
            changed[offset] ^= 1;
            let changed = ZkAmsMkheCpkShareStatementV1::from_wire_bytes_exact(&changed)
                .expect("changed nonzero axis remains structurally canonical");
            assert_ne!(changed.statement_digest().unwrap(), baseline_digest);
        }
        for offset in [60, 92, 124, 156, 188, 220, 252] {
            let mut zero = wire;
            zero[offset..offset + 32].fill(0);
            assert!(ZkAmsMkheCpkShareStatementV1::from_wire_bytes_exact(&zero).is_err());
        }
        let different_pointer = share_statement_fixture(b"different-pointer");
        assert_ne!(
            different_pointer.statement_digest().unwrap(),
            baseline_digest
        );
    }
    #[test]
    fn cpk_error_membership_context_binds_every_complete_statement_axis() {
        let statement = share_statement_fixture(b"membership-context-axes");
        let statement_digest = statement.statement_digest().expect("statement digest");
        let secret = ZkAmsMkhePersistentMembershipContextV1::from_relation_axes(
            statement.profile_digest,
            statement.roster_digest,
            statement.key_material_digest,
            statement.epoch,
            statement.cpk_transcript_digest,
            statement.party,
            statement_digest,
        )
        .expect("secret context");
        let error = ZkAmsMkheCpkErrorMembershipContextV1::from_share_statement(statement)
            .expect("error context");
        validate_cpk_membership_context_axes_v1(statement, secret, error)
            .expect("matching membership contexts");
        assert_eq!(error.profile_digest(), statement.profile_digest);
        assert_eq!(error.roster_digest(), statement.roster_digest);
        assert_eq!(error.key_material_digest(), statement.key_material_digest);
        assert_eq!(error.epoch(), statement.epoch);
        assert_eq!(
            error.cpk_transcript_digest(),
            statement.cpk_transcript_digest
        );
        assert_eq!(error.party(), statement.party);
        assert_eq!(error.share_statement_digest(), statement_digest);
        for axis in 0..10 {
            let mut changed = statement;
            match axis {
                0 => changed.profile_digest[0] ^= 1,
                1 => changed.security_certificate_digest[0] ^= 1,
                2 => changed.roster_digest[0] ^= 1,
                3 => changed.key_material_digest[0] ^= 1,
                4 => changed.cpk_transcript_digest[0] ^= 1,
                5 => changed.public_a_context_digest[0] ^= 1,
                6 => {
                    let mut party = changed.party.to_bytes();
                    party[0] ^= 1;
                    changed.party = ZkAmsMkhePartyIdV1::new(party).expect("changed party");
                }
                7 => changed.party_index = (changed.party_index + 1) % 8,
                8 => changed.epoch += 1,
                9 => {
                    changed.party_b_pointer = ZkAmsMkheCpkPartyBPointerV1::new(digest(
                        b"membership-context-axes",
                        b"changed-party-b",
                    ))
                    .expect("changed pointer");
                }
                _ => unreachable!(),
            }
            changed
                .validate()
                .expect("changed statement remains canonical");
            let changed_error = ZkAmsMkheCpkErrorMembershipContextV1::from_share_statement(changed)
                .expect("changed error context");
            assert_ne!(
                changed_error.context_digest(),
                error.context_digest(),
                "statement axis {axis} was not error-context bound"
            );
            assert_eq!(
                validate_cpk_membership_context_axes_v1(changed, secret, error),
                Err(ZkAmsMkheCpkRelationErrorV1::MembershipEvidence),
                "statement axis {axis} accepted stale membership contexts"
            );
        }
    }
    #[test]
    fn cpk_error_membership_facade_is_exact_strict_and_role_separated() {
        let statement = share_statement_fixture(b"error-membership-wire");
        let evidence = synthetic_error_membership(statement, b"error-membership-wire");
        let wire = evidence.to_wire_bytes().expect("error wire");
        assert_eq!(wire.len(), ZK_AMS_MKHE_CPK_ERROR_MEMBERSHIP_BYTES_V1);
        assert_eq!(&wire[..4], b"ZCEM");
        assert_eq!(wire[4], 1);
        assert_eq!(wire[5], 2);
        assert_eq!(wire[6], 8);
        assert_eq!(evidence.chunks().len(), 8);
        assert!(
            evidence
                .chunks()
                .iter()
                .all(|chunk| chunk.proof_bytes().len() == 1_513)
        );
        assert_eq!(evidence.commitments().len(), 8);
        assert_eq!(
            evidence.generator_basis_digest(),
            ZK_AMS_T256_BP_GENERATOR_BASIS_DIGEST_V1
        );
        assert_ne!(evidence.commitment_set_digest(), [0; 32]);
        assert_ne!(evidence.proof_set_digest(), [0; 32]);
        assert_ne!(evidence.verifier_transcript_digest(), [0; 32]);
        let decoded =
            ZkAmsMkheCpkErrorMembershipEvidenceV1::from_wire_bytes_exact(&wire).expect("decode");
        assert_eq!(decoded, evidence);
        assert_eq!(decoded.to_wire_bytes().expect("re-encode"), wire);
        for end in 0..wire.len() {
            assert_eq!(
                ZkAmsMkheCpkErrorMembershipEvidenceV1::from_wire_bytes_exact(&wire[..end]),
                Err(ZkAmsMkheCpkRelationErrorV1::MembershipEvidence),
                "truncation at {end} was accepted"
            );
        }
        for trailing_len in [1, 2, 32, 1_560] {
            let mut trailing = wire.clone();
            trailing.resize(wire.len() + trailing_len, 0);
            assert_eq!(
                ZkAmsMkheCpkErrorMembershipEvidenceV1::from_wire_bytes_exact(&trailing),
                Err(ZkAmsMkheCpkRelationErrorV1::MembershipEvidence)
            );
        }
        for offset in [0, 4, 5, 6, 7, 11, 43, 339, 344, 351, 384, 386] {
            let mut changed = wire.clone();
            changed[offset] ^= 1;
            assert_eq!(
                ZkAmsMkheCpkErrorMembershipEvidenceV1::from_wire_bytes_exact(&changed),
                Err(ZkAmsMkheCpkRelationErrorV1::MembershipEvidence),
                "mutation at {offset} was accepted"
            );
        }
        let mut disguised_as_secret = wire[..ZK_AMS_MKHE_CPK_SECRET_MEMBERSHIP_BYTES_V1].to_vec();
        disguised_as_secret[..4].copy_from_slice(b"ZPME");
        disguised_as_secret[5] = 1;
        assert!(
            ZkAmsMkhePersistentMembershipEvidenceV1::from_wire_bytes_exact(&disguised_as_secret)
                .is_err()
        );
        const { assert!(!ZK_AMS_MKHE_CPK_RELATION_VERIFICATION_GATE_V1) };
    }
    #[test]
    fn relation_header_codec_rejects_alternate_shapes_reserved_bytes_and_splices() {
        let (statement, secret, error, header) = header_fixture(b"header-codec");
        let wire = header.to_wire_bytes().expect("header wire");
        assert_eq!(wire.len(), 208);
        assert_eq!(
            ZkAmsMkheCpkRelationHeaderV1::from_wire_bytes_exact(&wire),
            Ok(header)
        );
        header
            .validate_against(statement, &secret, &error)
            .expect("header bindings");
        for end in 0..wire.len() {
            assert!(ZkAmsMkheCpkRelationHeaderV1::from_wire_bytes_exact(&wire[..end]).is_err());
        }
        let mut trailing = wire.to_vec();
        trailing.push(0);
        assert!(ZkAmsMkheCpkRelationHeaderV1::from_wire_bytes_exact(&trailing).is_err());
        for offset in [
            0, 4, 5, 6, 8, 12, 16, 17, 18, 19, 20, 21, 22, 23, 24, 32, 40, 76, 204, 207,
        ] {
            let mut changed = wire;
            changed[offset] ^= 1;
            assert!(
                ZkAmsMkheCpkRelationHeaderV1::from_wire_bytes_exact(&changed).is_err(),
                "header structural byte {offset} was accepted"
            );
        }
        for offset in [44, 108, 140, 172] {
            let mut zero = wire;
            zero[offset..offset + 32].fill(0);
            assert!(ZkAmsMkheCpkRelationHeaderV1::from_wire_bytes_exact(&zero).is_err());
        }
        let mut changed_secret = secret.clone();
        changed_secret[0] ^= 1;
        assert_eq!(
            header.validate_against(statement, &changed_secret, &error),
            Err(ZkAmsMkheCpkRelationErrorV1::RelationHeader)
        );
        let mut changed_error = error.clone();
        let last_error_byte = changed_error.len() - 1;
        changed_error[last_error_byte] ^= 1;
        assert_eq!(
            header.validate_against(statement, &secret, &changed_error),
            Err(ZkAmsMkheCpkRelationErrorV1::RelationHeader)
        );
        assert!(
            header
                .validate_against(share_statement_fixture(b"other-statement"), &secret, &error)
                .is_err()
        );
        assert!(
            ZkAmsMkheCpkRelationHeaderV1::new(statement, &secret[..secret.len() - 1], &error)
                .is_err()
        );
        assert!(
            ZkAmsMkheCpkRelationHeaderV1::new(statement, &secret, &error[..error.len() - 1])
                .is_err()
        );
    }
    #[test]
    fn small_shape_body_codec_is_canonical_at_every_boundary() {
        let shape = tiny_relation_shape();
        let body = tiny_body();
        let wire = body.to_wire_bytes(shape).expect("tiny body wire");
        assert_eq!(wire.len(), shape.body_bytes().unwrap());
        let decoded = CpkRelationBodyV1::from_wire_bytes_exact(shape, &wire).expect("tiny decode");
        assert_eq!(decoded.to_wire_bytes(shape).unwrap(), wire);
        assert_eq!(decoded.responses[0], -ZK_AMS_MKHE_CPK_RESPONSE_BOUND_V1);
        assert_eq!(
            decoded.responses[decoded.responses.len() - 1],
            ZK_AMS_MKHE_CPK_RESPONSE_BOUND_V1
        );
        for end in 0..wire.len() {
            assert!(CpkRelationBodyV1::from_wire_bytes_exact(shape, &wire[..end]).is_err());
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(CpkRelationBodyV1::from_wire_bytes_exact(shape, &trailing).is_err());
        for (index, invalid) in [
            ZK_AMS_MKHE_CPK_RESPONSE_BOUND_V1 + 1,
            -ZK_AMS_MKHE_CPK_RESPONSE_BOUND_V1 - 1,
            i64::MIN,
        ]
        .into_iter()
        .enumerate()
        {
            let mut changed = wire.clone();
            let offset = CPK_CHALLENGE_SEED_BYTES_V1 + index * 8;
            changed[offset..offset + 8].copy_from_slice(&invalid.to_be_bytes());
            assert!(CpkRelationBodyV1::from_wire_bytes_exact(shape, &changed).is_err());
        }
        let scalar_offset = CPK_CHALLENGE_SEED_BYTES_V1 + shape.response_count().unwrap() * 8;
        let mut modulus_le = VEGA_T256_SCALAR_MODULUS_BE_V1;
        modulus_le.reverse();
        let mut noncanonical = wire.clone();
        noncanonical[scalar_offset..scalar_offset + 32].copy_from_slice(&modulus_le);
        assert!(CpkRelationBodyV1::from_wire_bytes_exact(shape, &noncanonical).is_err());
        let mut modulus_minus_one = VEGA_T256_SCALAR_MODULUS_BE_V1;
        modulus_minus_one[31] -= 1;
        modulus_minus_one.reverse();
        let mut canonical_max = wire.clone();
        canonical_max[scalar_offset..scalar_offset + 32].copy_from_slice(&modulus_minus_one);
        assert!(CpkRelationBodyV1::from_wire_bytes_exact(shape, &canonical_max).is_ok());
        let mut invalid_body = tiny_body();
        invalid_body.responses[1] = ZK_AMS_MKHE_CPK_RESPONSE_BOUND_V1 + 1;
        assert_eq!(
            invalid_body.to_wire_bytes(shape),
            Err(ZkAmsMkheCpkRelationErrorV1::RelationBody)
        );
    }
    #[test]
    fn commitment_digest_binds_repetition_role_chunk_and_actual_point() {
        let points = derive_t256_generators_v1(
            b"iroha.zk-ams.v1.mkhe.cpk-relation.commitment-order-test",
            17,
        )
        .expect("test points");
        let secret: [Point; 8] = core::array::from_fn(|index| points[index]);
        let error: [Point; 8] = core::array::from_fn(|index| points[8 + index]);
        let baseline = ZkAmsMkheCpkCommitmentFirstMessageDigestV1::from_reconstructed_points(
            0, &secret, &error,
        )
        .expect("baseline");
        let next_repetition =
            ZkAmsMkheCpkCommitmentFirstMessageDigestV1::from_reconstructed_points(
                1, &secret, &error,
            )
            .expect("next repetition");
        assert_ne!(baseline, next_repetition);
        let mut reordered = secret;
        reordered.swap(0, 1);
        assert_ne!(
            ZkAmsMkheCpkCommitmentFirstMessageDigestV1::from_reconstructed_points(
                0, &reordered, &error,
            )
            .unwrap(),
            baseline
        );
        let mut changed = secret;
        changed[7] = points[16];
        assert_ne!(
            ZkAmsMkheCpkCommitmentFirstMessageDigestV1::from_reconstructed_points(
                0, &changed, &error,
            )
            .unwrap(),
            baseline
        );
        assert_ne!(
            ZkAmsMkheCpkCommitmentFirstMessageDigestV1::from_reconstructed_points(
                0, &error, &secret,
            )
            .unwrap(),
            baseline
        );
        let mut identity = secret;
        identity[0] = Point::identity();
        assert_eq!(
            ZkAmsMkheCpkCommitmentFirstMessageDigestV1::from_reconstructed_points(
                0, &identity, &error,
            ),
            Err(ZkAmsMkheCpkRelationErrorV1::FirstMessageRejected)
        );
    }
    #[test]
    fn rns_digest_builder_is_chunking_independent_ordered_and_poisoning() {
        let shape = CpkRnsDigestShapeV1 {
            limbs: 2,
            degree: 4,
        };
        let q0 = 4_294_967_311_u64;
        let q1 = 4_294_967_357_u64;
        let build = |split: bool| {
            let mut builder =
                ZkAmsMkheCpkRnsFirstMessageDigestBuilderV1::new_for_shape(2, shape).unwrap();
            for (limb, modulus, residues) in [(0, q0, [1, 2, 3, 4]), (1, q1, [5, 6, 7, 8])] {
                builder.begin_limb(limb, modulus).unwrap();
                if split {
                    builder.update_residues(&residues[..1]).unwrap();
                    builder.update_residues(&residues[1..3]).unwrap();
                    builder.update_residues(&residues[3..]).unwrap();
                } else {
                    builder.update_residues(&residues).unwrap();
                }
                builder.finish_limb().unwrap();
            }
            builder.finish().unwrap()
        };
        assert_eq!(build(false), build(true));
        let mut wrong_order =
            ZkAmsMkheCpkRnsFirstMessageDigestBuilderV1::new_for_shape(0, shape).unwrap();
        assert!(wrong_order.begin_limb(1, q0).is_err());
        assert!(wrong_order.begin_limb(0, q0).is_err());
        let mut no_limb =
            ZkAmsMkheCpkRnsFirstMessageDigestBuilderV1::new_for_shape(0, shape).unwrap();
        assert!(no_limb.update_residues(&[1]).is_err());
        let mut empty =
            ZkAmsMkheCpkRnsFirstMessageDigestBuilderV1::new_for_shape(0, shape).unwrap();
        empty.begin_limb(0, q0).unwrap();
        assert!(empty.update_residues(&[]).is_err());
        let mut short =
            ZkAmsMkheCpkRnsFirstMessageDigestBuilderV1::new_for_shape(0, shape).unwrap();
        short.begin_limb(0, q0).unwrap();
        short.update_residues(&[1, 2, 3]).unwrap();
        assert!(short.finish_limb().is_err());
        let mut overrun =
            ZkAmsMkheCpkRnsFirstMessageDigestBuilderV1::new_for_shape(0, shape).unwrap();
        overrun.begin_limb(0, q0).unwrap();
        assert!(overrun.update_residues(&[1, 2, 3, 4, 5]).is_err());
        let mut noncanonical =
            ZkAmsMkheCpkRnsFirstMessageDigestBuilderV1::new_for_shape(0, shape).unwrap();
        noncanonical.begin_limb(0, q0).unwrap();
        assert!(noncanonical.update_residues(&[0, 1, q0, 3]).is_err());
        let mut small_modulus =
            ZkAmsMkheCpkRnsFirstMessageDigestBuilderV1::new_for_shape(0, shape).unwrap();
        assert!(small_modulus.begin_limb(0, u64::from(u32::MAX)).is_err());
    }
    #[test]
    fn global_transcript_binds_all_evidence_before_all_challenges() {
        let (statement, secret, error, header) = header_fixture(b"global-transcript");
        let commitments = commitment_digests();
        let rns = rns_digests();
        let baseline = reconstruct_zk_ams_mkhe_cpk_challenges_v1(
            statement,
            &secret,
            &error,
            header,
            commitments,
            rns,
        )
        .expect("baseline transcript");
        assert_eq!(baseline.1, cpk_challenges_from_seed_v1(baseline.0));
        let repeated = reconstruct_zk_ams_mkhe_cpk_challenges_v1(
            statement,
            &secret,
            &error,
            header,
            commitments,
            rns,
        )
        .expect("repeated transcript");
        assert_eq!(repeated, baseline);
        let mut changed_secret = secret.clone();
        let middle_secret_byte = changed_secret.len() / 2;
        changed_secret[middle_secret_byte] ^= 1;
        assert!(
            reconstruct_zk_ams_mkhe_cpk_challenges_v1(
                statement,
                &changed_secret,
                &error,
                header,
                commitments,
                rns,
            )
            .is_err()
        );
        let changed_header =
            ZkAmsMkheCpkRelationHeaderV1::new(statement, &changed_secret, &error).unwrap();
        let changed = reconstruct_zk_ams_mkhe_cpk_challenges_v1(
            statement,
            &changed_secret,
            &error,
            changed_header,
            commitments,
            rns,
        )
        .unwrap();
        assert_ne!(changed, baseline);
        let mut reordered_commitments = commitments;
        reordered_commitments.swap(0, 3);
        assert_ne!(
            reconstruct_zk_ams_mkhe_cpk_challenges_v1(
                statement,
                &secret,
                &error,
                header,
                reordered_commitments,
                rns,
            )
            .unwrap(),
            baseline
        );
        let mut reordered_rns = rns;
        reordered_rns.swap(1, 2);
        assert_ne!(
            reconstruct_zk_ams_mkhe_cpk_challenges_v1(
                statement,
                &secret,
                &error,
                header,
                commitments,
                reordered_rns,
            )
            .unwrap(),
            baseline
        );
        let other_statement = share_statement_fixture(b"global-transcript-other");
        let other_header =
            ZkAmsMkheCpkRelationHeaderV1::new(other_statement, &secret, &error).unwrap();
        assert_ne!(
            reconstruct_zk_ams_mkhe_cpk_challenges_v1(
                other_statement,
                &secret,
                &error,
                other_header,
                commitments,
                rns,
            )
            .unwrap(),
            baseline
        );
    }
    #[test]
    fn exact_signed_sampler_hits_both_endpoints_and_rejects_biased_prefixes() {
        let bound = ZK_AMS_MKHE_CPK_MASK_BOUND_V1 as u128;
        let width = 2 * bound + 1;
        let threshold = width.wrapping_neg() % width;
        assert_ne!(threshold, 0);
        let mut minimum = ExactBlockRandom {
            blocks: vec![width.to_be_bytes()],
            next: 0,
        };
        assert_eq!(
            sample_exact_uniform_signed_box_v1(&mut minimum, ZK_AMS_MKHE_CPK_MASK_BOUND_V1,)
                .unwrap(),
            -ZK_AMS_MKHE_CPK_MASK_BOUND_V1
        );
        let mut maximum = ExactBlockRandom {
            blocks: vec![(width - 1).to_be_bytes()],
            next: 0,
        };
        assert_eq!(
            sample_exact_uniform_signed_box_v1(&mut maximum, ZK_AMS_MKHE_CPK_MASK_BOUND_V1,)
                .unwrap(),
            ZK_AMS_MKHE_CPK_MASK_BOUND_V1
        );
        let mut rejected = ExactBlockRandom {
            blocks: vec![[0; 16]; CPK_INTEGER_SAMPLER_RETRY_CEILING_V1],
            next: 0,
        };
        assert_eq!(
            sample_exact_uniform_signed_box_v1(&mut rejected, ZK_AMS_MKHE_CPK_MASK_BOUND_V1,),
            Err(ZkAmsMkheCpkRelationErrorV1::RandomUnavailable)
        );
        assert_eq!(
            sample_exact_uniform_signed_box_v1(&mut FailingRandom, ZK_AMS_MKHE_CPK_MASK_BOUND_V1,),
            Err(ZkAmsMkheCpkRelationErrorV1::RandomUnavailable)
        );
        assert_eq!(
            sample_exact_uniform_signed_box_v1(&mut FailingRandom, 0),
            Err(ZkAmsMkheCpkRelationErrorV1::Witness)
        );
        assert_eq!(
            sample_exact_uniform_signed_box_v1(
                &mut FailingRandom,
                ZK_AMS_MKHE_CPK_MASK_BOUND_V1 + 1,
            ),
            Err(ZkAmsMkheCpkRelationErrorV1::Witness)
        );
    }
    #[test]
    fn sampler_byte_owners_erase_named_copies_during_unwind() {
        let before_integer = CPK_FIXED_BYTES_ERASURE_DROP_CALLS_V1.load(Ordering::SeqCst);
        let integer_unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = sample_exact_uniform_signed_box_v1(
                &mut PanickingRandom,
                ZK_AMS_MKHE_CPK_MASK_BOUND_V1,
            );
        }));
        assert!(integer_unwind.is_err());
        assert!(
            CPK_FIXED_BYTES_ERASURE_DROP_CALLS_V1.load(Ordering::SeqCst) > before_integer,
            "the 16-byte sampler owner must observe its erased named copy during unwind"
        );
        let before_scalar = CPK_FIXED_BYTES_ERASURE_DROP_CALLS_V1.load(Ordering::SeqCst);
        let scalar_unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = sample_t256_scalar_v1(&mut PanickingRandom);
        }));
        assert!(scalar_unwind.is_err());
        assert!(
            CPK_FIXED_BYTES_ERASURE_DROP_CALLS_V1.load(Ordering::SeqCst) > before_scalar,
            "the 64-byte sampler owner must observe its erased named copy during unwind"
        );
    }
    #[test]
    fn secret_derived_scalar_owner_erases_its_named_copy_during_unwind() {
        let before = CPK_SCALAR_COPY_ERASURE_DROP_CALLS_V1.load(Ordering::SeqCst);
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let shifted =
                BestEffortErasingScalarCopyV1::new(Scalar::from_u64(7) * Scalar::from_u64(11));
            assert!(!shifted.expose_copy().is_zero());
            panic!("injected panic while the secret-derived scalar owner is live")
        }));
        assert!(unwind.is_err());
        assert!(
            CPK_SCALAR_COPY_ERASURE_DROP_CALLS_V1.load(Ordering::SeqCst) > before,
            "the scalar owner must observe its erased named copy during unwind"
        );
    }
    #[test]
    fn identity_first_message_rejection_retries_once_then_succeeds() {
        let shape = tiny_relation_shape();
        let seed = digest(b"identity-first-message-retry", b"seed");
        let challenges = cpk_challenges_from_seed_v1(seed);
        let secret = [-1, 0, 1, 1];
        let error = [-2, -1, 0, 2];
        let secret_blindings = [Scalar::from_u64(7), Scalar::from_u64(11)];
        let error_blindings = [Scalar::from_u64(13), Scalar::from_u64(17)];
        let bound = ZK_AMS_MKHE_CPK_MASK_BOUND_V1 as u128;
        let width = 2 * bound + 1;
        let mut random = EndpointRandom {
            // `bound + width` is accepted by the unbiased sampler and maps to
            // an exact zero mask, making response acceptance deterministic.
            signed_block: (bound + width).to_be_bytes(),
        };
        let (mut identity_secret, commitment_error) = commitment_point_arrays();
        identity_secret[0] = Point::identity();
        let mut callback_calls = 0;
        let mut derive = |_attempt: &ZkAmsMkheCpkRelationMaskAttemptV1| {
            callback_calls += 1;
            if callback_calls == 1 {
                let rejection =
                    ZkAmsMkheCpkCommitmentFirstMessageDigestV1::from_reconstructed_points(
                        0,
                        &identity_secret,
                        &commitment_error,
                    )
                    .expect_err("identity first message must be rejected");
                return Err(rejection);
            }
            Ok((seed, challenges))
        };
        let response = construct_cpk_responses_with_aborts_for_shape_v1(
            shape,
            &secret,
            &error,
            &secret_blindings,
            &error_blindings,
            &mut random,
            &mut derive,
        )
        .expect("the fresh attempt after identity rejection must succeed");
        assert_eq!(callback_calls, 2);
        response.body.validate(shape).expect("valid response body");
    }
    #[test]
    fn identity_first_message_rejections_exhaust_exact_outer_bound() {
        let shape = tiny_relation_shape();
        let secret = [-1, 0, 1, 1];
        let error = [-2, -1, 0, 2];
        let secret_blindings = [Scalar::from_u64(7), Scalar::from_u64(11)];
        let error_blindings = [Scalar::from_u64(13), Scalar::from_u64(17)];
        let bound = ZK_AMS_MKHE_CPK_MASK_BOUND_V1 as u128;
        let width = 2 * bound + 1;
        let mut random = EndpointRandom {
            signed_block: (bound + width).to_be_bytes(),
        };
        let (mut identity_secret, commitment_error) = commitment_point_arrays();
        identity_secret[0] = Point::identity();
        let mut callback_calls = 0;
        let mut derive = |_attempt: &ZkAmsMkheCpkRelationMaskAttemptV1| {
            callback_calls += 1;
            let rejection = ZkAmsMkheCpkCommitmentFirstMessageDigestV1::from_reconstructed_points(
                0,
                &identity_secret,
                &commitment_error,
            )
            .expect_err("identity first message must be rejected");
            Err(rejection)
        };
        assert_eq!(
            construct_cpk_responses_with_aborts_for_shape_v1(
                shape,
                &secret,
                &error,
                &secret_blindings,
                &error_blindings,
                &mut random,
                &mut derive,
            ),
            Err(ZkAmsMkheCpkRelationErrorV1::RetryExhausted)
        );
        assert_eq!(callback_calls, ZK_AMS_MKHE_CPK_OUTER_RETRY_CEILING_V1);
    }
    #[test]
    fn unrelated_transcript_error_is_terminal_without_retry() {
        let shape = tiny_relation_shape();
        let secret = [-1, 0, 1, 1];
        let error = [-2, -1, 0, 2];
        let secret_blindings = [Scalar::from_u64(7), Scalar::from_u64(11)];
        let error_blindings = [Scalar::from_u64(13), Scalar::from_u64(17)];
        let bound = ZK_AMS_MKHE_CPK_MASK_BOUND_V1 as u128;
        let width = 2 * bound + 1;
        let mut random = EndpointRandom {
            signed_block: (bound + width).to_be_bytes(),
        };
        let (commitment_secret, commitment_error) = commitment_point_arrays();
        let mut callback_calls = 0;
        let mut derive = |_attempt: &ZkAmsMkheCpkRelationMaskAttemptV1| {
            callback_calls += 1;
            let transcript_error =
                ZkAmsMkheCpkCommitmentFirstMessageDigestV1::from_reconstructed_points(
                    ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1,
                    &commitment_secret,
                    &commitment_error,
                )
                .expect_err("out-of-range repetition must be a transcript error");
            Err(transcript_error)
        };
        assert_eq!(
            construct_cpk_responses_with_aborts_for_shape_v1(
                shape,
                &secret,
                &error,
                &secret_blindings,
                &error_blindings,
                &mut random,
                &mut derive,
            ),
            Err(ZkAmsMkheCpkRelationErrorV1::Transcript)
        );
        assert_eq!(callback_calls, 1);
    }
    #[test]
    fn response_construction_is_exact_atomic_and_whole_attempt_bounded() {
        let shape = tiny_relation_shape();
        let seed = digest(b"response-construction", b"seed");
        let challenges = cpk_challenges_from_seed_v1(seed);
        let secret = [-1, 0, 1, 1];
        let error = [-2, -1, 0, 2];
        let secret_blindings = [Scalar::from_u64(7), Scalar::from_u64(11)];
        let error_blindings = [Scalar::from_u64(13), Scalar::from_u64(17)];
        let blind_mask = Scalar::from_u64(5);
        let response = manual_attempt(shape, 0, blind_mask)
            .into_responses(
                seed,
                challenges,
                &secret,
                &error,
                &secret_blindings,
                &error_blindings,
            )
            .expect("accepted common-box response");
        response.body.validate(shape).unwrap();
        for (repetition, &challenge) in challenges.iter().enumerate().take(shape.repetitions) {
            for role in 0..shape.witnesses {
                let witness = if role == 0 { &secret } else { &error };
                for (coefficient, value) in witness.iter().enumerate() {
                    let index = response_index(shape, repetition, role, coefficient).unwrap();
                    assert_eq!(
                        response.body.responses[index],
                        i64::from(challenge) * i64::from(*value)
                    );
                }
                let witness_blindings = if role == 0 {
                    &secret_blindings
                } else {
                    &error_blindings
                };
                for (chunk, blinding) in witness_blindings.iter().enumerate() {
                    let index = blind_response_index(shape, repetition, role, chunk).unwrap();
                    assert_eq!(
                        response.body.blind_responses[index],
                        blind_mask + Scalar::from_u64(u64::from(challenge)) * *blinding
                    );
                }
            }
        }
        let mut wrong_challenges = challenges;
        wrong_challenges[0] ^= 1;
        assert_eq!(
            manual_attempt(shape, 0, blind_mask).into_responses(
                seed,
                wrong_challenges,
                &secret,
                &error,
                &secret_blindings,
                &error_blindings,
            ),
            Err(ZkAmsMkheCpkRelationErrorV1::Transcript)
        );
        assert_eq!(
            manual_attempt(shape, ZK_AMS_MKHE_CPK_MASK_BOUND_V1, blind_mask).into_responses(
                seed,
                challenges,
                &secret,
                &error,
                &secret_blindings,
                &error_blindings,
            ),
            Err(ZkAmsMkheCpkRelationErrorV1::ResponseRejected)
        );
        let mut invalid_secret = secret;
        invalid_secret[0] = 2;
        assert_eq!(
            manual_attempt(shape, 0, blind_mask).into_responses(
                seed,
                challenges,
                &invalid_secret,
                &error,
                &secret_blindings,
                &error_blindings,
            ),
            Err(ZkAmsMkheCpkRelationErrorV1::Witness)
        );
        let mut invalid_error = error;
        invalid_error[3] = 3;
        assert_eq!(
            manual_attempt(shape, 0, blind_mask).into_responses(
                seed,
                challenges,
                &secret,
                &invalid_error,
                &secret_blindings,
                &error_blindings,
            ),
            Err(ZkAmsMkheCpkRelationErrorV1::Witness)
        );
        let zero_blindings = [Scalar::zero(); 2];
        assert_eq!(
            manual_attempt(shape, 0, blind_mask).into_responses(
                seed,
                challenges,
                &secret,
                &error,
                &zero_blindings,
                &error_blindings,
            ),
            Err(ZkAmsMkheCpkRelationErrorV1::Witness)
        );
        let bound = ZK_AMS_MKHE_CPK_MASK_BOUND_V1 as u128;
        let width = 2 * bound + 1;
        let mut endpoint_random = EndpointRandom {
            signed_block: (width - 1).to_be_bytes(),
        };
        let mut closure = |_attempt: &ZkAmsMkheCpkRelationMaskAttemptV1| Ok((seed, challenges));
        assert!(matches!(
            construct_cpk_responses_with_aborts_for_shape_v1(
                shape,
                &secret,
                &error,
                &secret_blindings,
                &error_blindings,
                &mut endpoint_random,
                &mut closure,
            ),
            Err(ZkAmsMkheCpkRelationErrorV1::RetryExhausted)
        ));
    }
    #[test]
    fn tiny_attempt_sampling_has_exact_shape_and_rng_failures_are_atomic() {
        let shape = tiny_relation_shape();
        let mut random = StreamRandom::new(b"tiny-attempt-sampling");
        let attempt = ZkAmsMkheCpkRelationMaskAttemptV1::sample_for_shape(shape, &mut random)
            .expect("tiny attempt");
        assert_eq!(attempt.masks().len(), shape.response_count().unwrap());
        assert_eq!(attempt.masks.0.capacity(), shape.response_count().unwrap());
        assert_eq!(
            attempt.blind_masks().len(),
            shape.blind_response_count().unwrap()
        );
        assert_eq!(
            attempt.blind_masks.0.capacity(),
            shape.blind_response_count().unwrap()
        );
        assert!(
            attempt
                .masks()
                .iter()
                .all(|value| value.unsigned_abs() <= ZK_AMS_MKHE_CPK_MASK_BOUND_V1 as u64)
        );
        assert_eq!(
            ZkAmsMkheCpkRelationMaskAttemptV1::sample_for_shape(shape, &mut FailingRandom)
                .unwrap_err(),
            ZkAmsMkheCpkRelationErrorV1::RandomUnavailable
        );
    }
    #[test]
    fn reconstructed_commitment_messages_match_masks_and_bind_every_public_axis() {
        let shape = tiny_relation_shape();
        let secret = [-1_i64, 0, 1, 1];
        let error = [-2_i64, -1, 0, 2];
        let secret_blindings = [Scalar::from_u64(7), Scalar::from_u64(11)];
        let error_blindings = [Scalar::from_u64(13), Scalar::from_u64(17)];
        let secret_commitments = [
            tiny_public_vector_commitment(&secret[..2], secret_blindings[0]),
            tiny_public_vector_commitment(&secret[2..], secret_blindings[1]),
        ];
        let error_commitments = [
            tiny_public_vector_commitment(&error[..2], error_blindings[0]),
            tiny_public_vector_commitment(&error[2..], error_blindings[1]),
        ];
        let challenges = [3_u32, 5, 7, 11];
        let mut responses = vec![0_i64; shape.response_count().unwrap()];
        let mut blind_responses = vec![Scalar::zero(); shape.blind_response_count().unwrap()];
        let mut expected = Vec::new();
        for (repetition, challenge) in challenges.iter().copied().enumerate() {
            let challenge_i64 = i64::from(challenge);
            let secret_masks = core::array::from_fn::<_, 4, _>(|coefficient| {
                19 + repetition as i64 * 7 + coefficient as i64
            });
            let error_masks = core::array::from_fn::<_, 4, _>(|coefficient| {
                -31 - repetition as i64 * 5 - coefficient as i64
            });
            let secret_blind_masks = [
                Scalar::from_u64(101 + repetition as u64),
                Scalar::from_u64(109 + repetition as u64),
            ];
            let error_blind_masks = [
                Scalar::from_u64(127 + repetition as u64),
                Scalar::from_u64(131 + repetition as u64),
            ];
            for role in 0..2 {
                let witness = if role == 0 { &secret } else { &error };
                let masks = if role == 0 {
                    &secret_masks
                } else {
                    &error_masks
                };
                let witness_blindings = if role == 0 {
                    &secret_blindings
                } else {
                    &error_blindings
                };
                let blind_masks = if role == 0 {
                    &secret_blind_masks
                } else {
                    &error_blind_masks
                };
                for coefficient in 0..shape.degree {
                    responses[response_index(shape, repetition, role, coefficient).unwrap()] =
                        masks[coefficient] + challenge_i64 * witness[coefficient];
                }
                for chunk in 0..shape.chunks {
                    blind_responses
                        [blind_response_index(shape, repetition, role, chunk).unwrap()] =
                        blind_masks[chunk]
                            + Scalar::from_u64(u64::from(challenge)) * witness_blindings[chunk];
                }
            }
            let expected_secret = [
                tiny_public_vector_commitment(&secret_masks[..2], secret_blind_masks[0]),
                tiny_public_vector_commitment(&secret_masks[2..], secret_blind_masks[1]),
            ];
            let expected_error = [
                tiny_public_vector_commitment(&error_masks[..2], error_blind_masks[0]),
                tiny_public_vector_commitment(&error_masks[2..], error_blind_masks[1]),
            ];
            expected.push(
                ZkAmsMkheCpkCommitmentFirstMessageDigestV1::from_reconstructed_points_for_shape(
                    repetition,
                    &expected_secret,
                    &expected_error,
                )
                .unwrap(),
            );
        }
        let body = CpkRelationBodyV1 {
            challenge_seed: digest(b"tiny-commitment-reconstruction", b"seed"),
            responses,
            blind_responses,
        };
        let expected: [_; ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1] = expected.try_into().unwrap();
        let reconstructed = reconstruct_cpk_commitment_first_messages_for_shape_v1(
            shape,
            &body,
            challenges,
            &secret_commitments,
            &error_commitments,
        )
        .unwrap();
        assert_eq!(reconstructed, expected);
        let mut changed_response = CpkRelationBodyV1 {
            challenge_seed: body.challenge_seed,
            responses: body.responses.clone(),
            blind_responses: body.blind_responses.clone(),
        };
        changed_response.responses[0] += 1;
        assert_ne!(
            reconstruct_cpk_commitment_first_messages_for_shape_v1(
                shape,
                &changed_response,
                challenges,
                &secret_commitments,
                &error_commitments,
            )
            .unwrap(),
            expected
        );
        let mut changed_blind = CpkRelationBodyV1 {
            challenge_seed: body.challenge_seed,
            responses: body.responses.clone(),
            blind_responses: body.blind_responses.clone(),
        };
        changed_blind.blind_responses[0] += Scalar::one();
        assert_ne!(
            reconstruct_cpk_commitment_first_messages_for_shape_v1(
                shape,
                &changed_blind,
                challenges,
                &secret_commitments,
                &error_commitments,
            )
            .unwrap(),
            expected
        );
        let mut changed_commitments = secret_commitments;
        changed_commitments[0] += ZkAmsT256BulletproofSuiteV1::generators().g;
        assert_ne!(
            reconstruct_cpk_commitment_first_messages_for_shape_v1(
                shape,
                &body,
                challenges,
                &changed_commitments,
                &error_commitments,
            )
            .unwrap(),
            expected
        );
        assert_eq!(
            reconstruct_cpk_commitment_first_messages_for_shape_v1(
                shape,
                &body,
                challenges,
                &secret_commitments[..1],
                &error_commitments,
            ),
            Err(ZkAmsMkheCpkRelationErrorV1::MembershipEvidence)
        );
    }
    #[test]
    fn streamed_native_relation_matches_mask_equation_and_detects_adversarial_changes() {
        use super::super::manifest::{RELEASE_MODULI_V1, RELEASE_NEGACYCLIC_ROOTS_V1};
        let relation_shape = tiny_relation_shape();
        let rns_shape = CpkRnsDigestShapeV1 {
            limbs: 2,
            degree: relation_shape.degree,
        };
        let moduli = [RELEASE_MODULI_V1[0], RELEASE_MODULI_V1[1]];
        let roots = core::array::from_fn::<_, 2, _>(|limb| {
            super::super::mod_pow(
                RELEASE_NEGACYCLIC_ROOTS_V1[limb],
                (ZK_AMS_MKHE_CPK_RING_DEGREE_V1 / relation_shape.degree) as u64,
                moduli[limb],
            )
        });
        let plaintext = [7_u64, 11];
        let public_a = [vec![2_u64, 3, 5, 7], vec![11_u64, 13, 17, 19]];
        let secret = [-1_i64, 0, 1, 1];
        let error = [-2_i64, -1, 0, 2];
        let mut party_b = Vec::new();
        for limb in 0..rns_shape.limbs {
            let modulus = moduli[limb];
            let secret_residues = secret
                .iter()
                .copied()
                .map(|value| signed_mod(value, modulus))
                .collect::<Vec<_>>();
            let product =
                negacyclic_multiply(&public_a[limb], &secret_residues, modulus, roots[limb])
                    .unwrap();
            party_b.push(
                product
                    .iter()
                    .enumerate()
                    .map(|(coefficient, product)| {
                        mod_add(
                            mod_sub(0, *product, modulus),
                            mod_mul(
                                plaintext[limb],
                                signed_mod(error[coefficient], modulus),
                                modulus,
                            ),
                            modulus,
                        )
                    })
                    .collect::<Vec<_>>(),
            );
        }
        let challenges = [17_u32, 19, 23, 29];
        let mut responses = vec![0_i64; relation_shape.response_count().unwrap()];
        let mut secret_masks = [[0_i64; 4]; 4];
        let mut error_masks = [[0_i64; 4]; 4];
        for (repetition, challenge) in challenges.iter().copied().enumerate() {
            for coefficient in 0..relation_shape.degree {
                secret_masks[repetition][coefficient] =
                    37 + repetition as i64 * 11 + coefficient as i64;
                error_masks[repetition][coefficient] =
                    -41 - repetition as i64 * 13 - coefficient as i64;
                responses[response_index(relation_shape, repetition, 0, coefficient).unwrap()] =
                    secret_masks[repetition][coefficient]
                        + i64::from(challenge) * secret[coefficient];
                responses[response_index(relation_shape, repetition, 1, coefficient).unwrap()] =
                    error_masks[repetition][coefficient]
                        + i64::from(challenge) * error[coefficient];
            }
        }
        let body = CpkRelationBodyV1 {
            challenge_seed: digest(b"tiny-native-relation", b"seed"),
            responses,
            blind_responses: vec![Scalar::zero(); relation_shape.blind_response_count().unwrap()],
        };
        let mut expected = Vec::new();
        for repetition in 0..relation_shape.repetitions {
            let mut builder =
                ZkAmsMkheCpkRnsFirstMessageDigestBuilderV1::new_for_shape(repetition, rns_shape)
                    .unwrap();
            for limb in 0..rns_shape.limbs {
                let modulus = moduli[limb];
                let mask_residues = secret_masks[repetition]
                    .iter()
                    .copied()
                    .map(|value| signed_mod(value, modulus))
                    .collect::<Vec<_>>();
                let product =
                    negacyclic_multiply(&public_a[limb], &mask_residues, modulus, roots[limb])
                        .unwrap();
                let first_message = product
                    .iter()
                    .enumerate()
                    .map(|(coefficient, product)| {
                        mod_add(
                            mod_sub(0, *product, modulus),
                            mod_mul(
                                plaintext[limb],
                                signed_mod(error_masks[repetition][coefficient], modulus),
                                modulus,
                            ),
                            modulus,
                        )
                    })
                    .collect::<Vec<_>>();
                builder.begin_limb(limb, modulus).unwrap();
                builder.update_residues(&first_message).unwrap();
                builder.finish_limb().unwrap();
            }
            expected.push(builder.finish().unwrap());
        }
        let expected: [_; ZK_AMS_MKHE_CPK_CHALLENGE_REPETITIONS_V1] = expected.try_into().unwrap();
        let reconstructed = reconstruct_cpk_rns_first_messages_for_shape_v1(
            relation_shape,
            rns_shape,
            &moduli,
            &roots,
            &plaintext,
            &body,
            challenges,
            |limb, _| Ok(public_a[limb].clone()),
            |limb, _| Ok(party_b[limb].clone()),
        )
        .unwrap();
        assert_eq!(reconstructed, expected);
        let mut changed_b = party_b.clone();
        changed_b[0][0] = mod_add(changed_b[0][0], 1, moduli[0]);
        assert_ne!(
            reconstruct_cpk_rns_first_messages_for_shape_v1(
                relation_shape,
                rns_shape,
                &moduli,
                &roots,
                &plaintext,
                &body,
                challenges,
                |limb, _| Ok(public_a[limb].clone()),
                |limb, _| Ok(changed_b[limb].clone()),
            )
            .unwrap(),
            expected
        );
        let mut changed_body = CpkRelationBodyV1 {
            challenge_seed: body.challenge_seed,
            responses: body.responses.clone(),
            blind_responses: body.blind_responses.clone(),
        };
        changed_body.responses[0] += 1;
        assert_ne!(
            reconstruct_cpk_rns_first_messages_for_shape_v1(
                relation_shape,
                rns_shape,
                &moduli,
                &roots,
                &plaintext,
                &changed_body,
                challenges,
                |limb, _| Ok(public_a[limb].clone()),
                |limb, _| Ok(party_b[limb].clone()),
            )
            .unwrap(),
            expected
        );
        let mut noncanonical_b = party_b.clone();
        noncanonical_b[0][0] = moduli[0];
        assert_eq!(
            reconstruct_cpk_rns_first_messages_for_shape_v1(
                relation_shape,
                rns_shape,
                &moduli,
                &roots,
                &plaintext,
                &body,
                challenges,
                |limb, _| Ok(public_a[limb].clone()),
                |limb, _| Ok(noncanonical_b[limb].clone()),
            ),
            Err(ZkAmsMkheCpkRelationErrorV1::NativeRelation)
        );
    }
    #[test]
    fn canonical_party_b_reader_is_single_pass_exact_and_fail_closed() {
        use super::super::manifest::RELEASE_MODULI_V1;
        let shape = CpkRnsDigestShapeV1 {
            limbs: 2,
            degree: 4,
        };
        let limbs = [vec![1_u64, 2, 3, 4], vec![5_u64, 6, 7, 8]];
        let mut provider = TinyObjectProvider::cpk_party_b(tiny_party_b_wire(&limbs));
        let pointer = provider.pointer;
        let mut reader = CpkPartyBStreamReaderV1::begin(pointer, shape, &mut provider).unwrap();
        assert_eq!(reader.read_limb(0, RELEASE_MODULI_V1[0]).unwrap(), limbs[0]);
        assert_eq!(reader.read_limb(1, RELEASE_MODULI_V1[1]).unwrap(), limbs[1]);
        let receipt = reader.finish().unwrap();
        assert_eq!(receipt.payload_blake3(), pointer.payload_blake3());
        assert_eq!(receipt.canonical_bytes(), pointer.payload_bytes());
        let mut wrong_count_wire = tiny_party_b_wire(&limbs);
        wrong_count_wire[..4].copy_from_slice(&7_u32.to_be_bytes());
        let mut wrong_count = TinyObjectProvider::cpk_party_b(wrong_count_wire);
        assert!(matches!(
            CpkPartyBStreamReaderV1::begin(wrong_count.pointer, shape, &mut wrong_count),
            Err(ZkAmsMkheCpkRelationErrorV1::NativeRelation)
        ));
        let mut noncanonical_limbs = limbs.clone();
        noncanonical_limbs[0][2] = RELEASE_MODULI_V1[0];
        let mut noncanonical =
            TinyObjectProvider::cpk_party_b(tiny_party_b_wire(&noncanonical_limbs));
        let mut reader =
            CpkPartyBStreamReaderV1::begin(noncanonical.pointer, shape, &mut noncanonical).unwrap();
        assert_eq!(
            reader.read_limb(0, RELEASE_MODULI_V1[0]),
            Err(ZkAmsMkheCpkRelationErrorV1::NativeRelation)
        );
        let mut trailing_wire = tiny_party_b_wire(&limbs);
        trailing_wire.extend_from_slice(&0_u64.to_be_bytes());
        let mut trailing = TinyObjectProvider::cpk_party_b(trailing_wire);
        assert!(matches!(
            CpkPartyBStreamReaderV1::begin(trailing.pointer, shape, &mut trailing),
            Err(ZkAmsMkheCpkRelationErrorV1::ObjectPointer)
        ));
    }
    #[test]
    fn production_capability_boundary_stays_fail_closed() {
        const { assert!(!ZK_AMS_MKHE_CPK_RELATION_VERIFICATION_GATE_V1) };
        assert_eq!(ZK_AMS_MKHE_CPK_RELATION_HEADER_BYTES_V1, 208);
        assert_eq!(ZK_AMS_MKHE_CPK_RELATION_BODY_BYTES_V1, 8_390_688);
        assert_eq!(ZK_AMS_MKHE_CPK_SECRET_MEMBERSHIP_BYTES_V1, 12_291);
        assert_eq!(ZK_AMS_MKHE_CPK_ERROR_MEMBERSHIP_BYTES_V1, 12_819);
        let statement = share_statement_fixture(b"membership-input-fail-closed");
        let (invalid_secret, _) = membership_wires(b"membership-input-fail-closed");
        let error = synthetic_error_membership(statement, b"membership-input-fail-closed")
            .to_wire_bytes()
            .expect("synthetic error wire");
        let header = ZkAmsMkheCpkRelationHeaderV1::new(statement, &invalid_secret, &error)
            .expect("shape-bound header");
        assert!(matches!(
            verify_zk_ams_mkhe_cpk_membership_inputs_v1(statement, header, &invalid_secret, &error,),
            Err(ZkAmsMkheCpkRelationErrorV1::MembershipEvidence)
        ));

        // The membership-input scaffold still has no relation-receipt
        // constructor or active-binding conversion. Only the complete
        // governed provider/authentication verifier can consume it.
    }
    #[test]
    fn state_owned_cpk_capacity_precursor_is_closed_without_opening_a_gate() {
        let relation = include_str!("cpk_relation.rs")
            .rsplit_once("\n#[cfg(test)]\nmod tests {")
            .unwrap()
            .0;
        let creator = include_str!("cpk_relation/state_owned_creator_v1.rs");
        let common_a = include_str!("cpk_relation_common_a.rs");
        let lease = include_str!("../../bulletproof_t256_workspace_lease_v1.rs");
        let mkhe = include_str!("../mkhe.rs");
        let profile = mkhe
            .split("impl BgvProfile {")
            .nth(1)
            .unwrap()
            .split("struct RnsPolynomial")
            .next()
            .unwrap();
        let multiply = mkhe
            .split_once("fn negacyclic_multiply(")
            .unwrap()
            .1
            .split_once("fn bytes_mod_u64")
            .unwrap()
            .0;
        let masks = relation
            .split("fn sample_for_shape")
            .nth(1)
            .unwrap()
            .split("fn masks(&self)")
            .next()
            .unwrap();
        assert_eq!(masks.matches("try_exact_capacity_vec_v1(").count(), 2);
        assert_eq!(masks.matches(".as_ptr()").count(), 4);
        assert_eq!(masks.matches(".len() !=").count(), 2);
        assert!(!masks.contains("try_reserve_exact"));
        assert!(relation.contains("self.masks.0.capacity() != self.shape.response_count()?"));
        assert!(relation.contains("self.masks.0.as_ptr() != masks_allocation"));
        assert!(relation.contains("self.blind_masks.0.as_ptr() != blind_masks_allocation"));
        assert!(relation.contains("let mut values = try_exact_capacity_vec_v1(self.shape.degree)"));
        assert!(relation.contains("let mut wire = try_exact_capacity_vec_v1("));
        let commitment_reconstruction = relation
            .split_once("fn reconstruct_cpk_commitment_first_messages_for_shape_v1(")
            .unwrap()
            .1
            .split_once("fn reconstruct_cpk_rns_first_messages_for_shape_v1")
            .unwrap()
            .0;
        assert!(commitment_reconstruction.contains("let mut digests = ["));
        assert!(commitment_reconstruction.contains("digests[repetition] ="));
        assert_eq!(
            commitment_reconstruction
                .matches("try_exact_capacity_vec_v1(shape.chunks)")
                .count(),
            2
        );
        assert!(
            commitment_reconstruction
                .contains("let mut terms = try_exact_capacity_vec_v1(exact_terms)")
        );
        assert!(
            commitment_reconstruction
                .contains("try_exact_multiexp_v1::<ZkAmsT256BulletproofSuiteV1>(&terms)")
        );
        assert!(!commitment_reconstruction.contains("digests.push("));
        assert!(!commitment_reconstruction.contains("try_reserve_exact(shape.repetitions)"));
        assert!(!commitment_reconstruction.contains("try_reserve_exact(shape.chunks)"));
        assert!(relation.contains("try_exact_capacity_vec_v1(profile.moduli.len())"));
        assert!(relation.contains("plaintext_modulus_residues.capacity() != profile.moduli.len()"));
        assert!(relation.contains("try_exact_capacity_vec_v1(relation_shape.repetitions)"));
        assert!(relation.contains("builders.capacity() != relation_shape.repetitions"));
        assert!(relation.contains("try_exact_capacity_vec_v1(rns_shape.degree)"));
        assert!(relation.contains("secret_residues.capacity() != rns_shape.degree"));
        assert!(relation.contains("super::ZkAmsMkheErrorV1::ResourceCeilingExceeded =>"));
        assert!(relation.contains("let mut digests = ["));
        assert!(relation.contains("digests[repetition] = builder.finish()?;"));
        assert!(!relation.contains("try_reserve_exact(builders.len())"));
        let mut prior = 0;
        for needle in [
            "statement.validate_against_governed_roster(",
            "ZkAmsMkheCpkRelationHeaderV1::new(",
            "let _workspace = acquire_zk_ams_t256_cpk_workspace_v1()",
            "construct_zk_ams_mkhe_cpk_responses_with_aborts_v1(",
            "ZkAmsMkheCpkRelationProofV1::from_prover_response(",
        ] {
            prior += creator[prior..].find(needle).unwrap() + needle.len();
        }
        assert!(!creator.contains("drop(_workspace)"));
        assert!(creator.contains("let mut digests = ["));
        assert!(creator.contains("let mut builders = ["));
        assert!(!creator.contains("Vec::with_capacity"));
        assert!(!creator.contains("collect::<Result<Vec"));
        assert!(common_a.contains("frame_prefix: [u8;"));
        assert!(common_a.contains("let mut frame = [0_u8;"));
        assert!(common_a.contains("try_exact_capacity_vec_v1(self.profile.ring_degree)"));
        assert!(!common_a.contains("Vec::new"));
        assert!(lease.contains("fn acquire_zk_ams_t256_cpk_workspace_v1()"));
        assert!(lease.contains("T256MembershipWorkspaceRoleV1::Commitment"));
        // Profile identities stream bounded fields into three native hash owners;
        // they must not restore the former three buffered frame allocations.
        assert_eq!(profile.matches("try_exact_capacity_vec_v1(").count(), 0);
        assert_eq!(
            profile
                .matches("let mut hash = native_outer_identity_v1(")
                .count(),
            3
        );
        assert_eq!(
            profile
                .matches("NativeOuterIdentityRoleV1::Parameter,")
                .count(),
            3
        );
        assert_eq!(profile.matches(".finish()").count(), 3);
        assert!(!profile.contains("Vec::with_capacity"));
        assert_eq!(multiply.matches("try_exact_capacity_vec_v1(").count(), 2);
        assert!(multiply.contains("left_twisted.capacity() != left.len()"));
        assert!(multiply.contains("right_twisted.capacity() != right.len()"));
        assert!(!multiply.contains("Vec::with_capacity"));
        const { assert!(!ZK_AMS_MKHE_CPK_RELATION_VERIFICATION_GATE_V1) };
    }
}
