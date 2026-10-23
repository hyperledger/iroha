//! Fail-closed audit for an exact small-coefficient active-party proof.
//!
//! The sparse ring challenge used by the current active RKG proof is not an
//! exact coefficient-binding mechanism: two accepting transcripts need not
//! yield a unit challenge difference in the negacyclic ring.  This module
//! records a replacement whose *small-witness* algebra is exact, without
//! exposing it to release admission.
//!
//! Each witness polynomial is split into 16,384-coefficient chunks.  A chunk
//! is bound by one transparent T256 vector-Pedersen commitment and an external
//! generalized-Bulletproof relation proves every committed coefficient is in
//! either `{-1, 0, 1}` or `{-2, -1, 0, 1, 2}`.  The proposed linear proof then
//! uses four parallel 32-bit scalar challenges.  For challenge `c_j`, mask
//! `y_j`, witness `w`, commitment blindings `s_j, r`, and response blindings
//! `rho_j`, the verifier reconstructs
//!
//! ```text
//! z_j       = y_j + c_j*w
//! rho_j     = s_j + c_j*r                  (mod p_T256)
//! T_com,j   = Com(z_j; rho_j) - c_j*Com(w; r)
//! T_rns,j   = A*z_j - c_j*u                (mod every q_i).
//! ```
//!
//! All eight reconstructed first-message digests are absorbed before any of
//! the four ordinal-bound challenges is derived.  In a random-oracle fork,
//! two challenge vectors differ in at least one coordinate.  There
//! `0 < |d| < 2^32 < q_i`, so `d` is invertible in every prime RNS limb.  The
//! same range-bound commitment appears in all four rounds.  Conditional on an
//! external-commitment argument of knowledge extracting the bounded opening,
//! full-basis multi-representation binding gives `z_j-z'_j = d*w` in the T256
//! scalar field; the explicit integer bounds below make that equality lift
//! uniquely to `Z`.  Subtracting the RNS equations and cancelling `d` then
//! gives the exact claimed relation `A*w = u` in every limb.  In the ideal
//! model where the four coordinates are jointly uniform, guessing all four
//! challenges has probability exactly `2^-128`; zero is deliberately one of
//! the `2^32` challenges.  The extraction, binding, and composite-ROM steps
//! remain independent false-gated obligations below.
//!
//! The Fiat--Shamir-with-aborts distribution uses a fixed common box, not an
//! emitted shifted box.  Let `S=(2^32-1)*2`, `M=S*2^24`, and `B=M-S`.  Sample
//! every `y` exactly uniformly from `[-M,M]`, form `z=y+c*w`, and accept the
//! whole attempt only when every response is in `[-B,B]`.  For every public
//! `c` and every `|w|<=2`, `z -> y=z-c*w` is a bijection from the same
//! `[-B,B]` into `[-M,M]`.  Conditional responses are therefore exactly
//! witness-independent.  Per-coordinate rejection is
//! `2*S/(2*M+1) < 2^-24`; across `4*6*2^17 = 3*2^20` coordinates the union
//! bound is below `3/16`, and 128 whole-attempt failures are below `2^-309`.
//! The retry count is geometric with a witness-independent parameter and is
//! independent of the final accepted response.
//!
//! A candidate ROM simulator samples `c_j`, `z_j`, and `rho_j` and reconstructs
//! the two first messages with the subtraction equations above.  Its
//! distribution still requires simulation of the external membership proof
//! and a proof of the composite master-seed plus four-coordinate programming
//! conditions.  The integer-only sampler below removes modulo bias using the
//! standard `2^128 mod width` rejection threshold.
//!
//! This is still not a release proof.  The native T256 generalized-
//! Bulletproof backend, its pinned generator basis, and exact chunked
//! membership evidence now exist and are consumed by the complete CPK
//! relation.  The state-owned decryption graph now requires the ordered CPK
//! binding set and commits its actual party points to the existing shared-
//! secret RNS proof transcript without copying the approximately 1,855-bit
//! smudge response.  The transitive short-solution/SIS equality claim still
//! lacks an independently pinned certificate and release-size KAT.  The six-
//! witness direct-relation wire and its implementation-derived managed-memory
//! ledger also remain incomplete.  No manifest bit or readiness gate is
//! opened here.

#![allow(dead_code)]
use super::{BgvProfile, PlaintextModulus, ZkAmsMkheErrorV1, wire::ZK_AMS_MKHE_MAX_PROOF_BYTES_V1};
#[cfg(test)]
use super::{
    MKHE_VERSION_V1, ZkAmsMkhePartyIdV1,
    active::ZkAmsMkheGovernedActiveRosterV1,
    cpk_relation::VerifiedZkAmsMkheCpkBindingSourceV1,
    direct_collective_eval_ceremony::{
        ZkAmsMkheDirectCeremonyContextV1, ZkAmsMkheDirectCeremonyRoundV1,
    },
    direct_rkg_ephemeral_membership::ZkAmsMkheDirectRkgEphemeralMembershipContextV1,
    manifest::ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1,
};
use crate::vega::bulletproof_t256::ZK_AMS_T256_BP_GENERATOR_BASIS_DIGEST_V1;
#[cfg(test)]
use crate::vega::{
    MaskedRelaxedRandomSourceV1, VegaT256PointV1 as Point, VegaT256ScalarV1 as Scalar,
    sponge::{Keccak256, keccak256},
};
#[cfg(test)]
use core::convert::Infallible;
#[cfg(test)]
#[path = "active_exact_binding/direct_common_a_v1.rs"]
mod direct_common_a_v1;
#[cfg(test)]
#[path = "active_exact_binding/direct_galois_target_a_v1.rs"]
mod direct_galois_target_a_v1;
#[path = "active_exact_binding/direct_relation_wire_v1.rs"]
mod direct_relation_wire_v1;
#[cfg(test)]
#[path = "active_exact_binding/direct_rkg_one_creator_adapter_v1.rs"]
mod direct_rkg_one_creator_adapter_v1;
#[cfg(test)]
pub(in crate::vega::zk_ams::mkhe) use direct_relation_wire_v1::PreparedDirectRkgOneStatementCoreV1;
#[cfg(test)]
pub(in crate::vega::zk_ams::mkhe) use direct_relation_wire_v1::{
    DirectPolynomialObjectV1, DirectRelationPublicObjectsV1, PublishedDirectRkgOneProofOwnerV2,
    RkgH0ObjectRoleV1, RkgH1ObjectRoleV1, SealedDirectRkgOneProofOwnerV1,
    seal_direct_rkg_one_proof_owner_v1,
};
#[cfg(test)]
pub(in crate::vega::zk_ams::mkhe) use direct_rkg_one_creator_adapter_v1::{
    CompletedDirectRkgOneCreatorV1, DirectRkgOneCreatorH0ReadyV1, DirectRkgOneCreatorH1ReadyV1,
    FinalizedDirectRkgOneCapabilityV1, PreparedDirectRkgOneCreatorPermitV1,
    prepare_direct_rkg_one_creator_h0_v1, prepare_direct_rkg_one_statement_permit_v1,
};
const RELEASE_RING_DEGREE_V1: usize = 131_072;
const MAX_RELATION_WITNESSES_V1: usize = 6;
const MAX_BOUND_ONE_WITNESSES_V1: usize = 2;
const MAX_BOUND_TWO_WITNESSES_V1: usize = 4;
const WITNESS_CHUNK_COEFFICIENTS_V1: usize = 16_384;
const CHUNKS_PER_WITNESS_V1: usize = RELEASE_RING_DEGREE_V1 / WITNESS_CHUNK_COEFFICIENTS_V1;
const MAX_CHUNK_COMMITMENTS_V1: usize = MAX_RELATION_WITNESSES_V1 * CHUNKS_PER_WITNESS_V1;
const CHALLENGE_REPETITIONS_V1: usize = 4;
const CHALLENGE_BITS_PER_REPETITION_V1: usize = 32;
const JOINT_CHALLENGE_BITS_V1: usize = CHALLENGE_REPETITIONS_V1 * CHALLENGE_BITS_PER_REPETITION_V1;
const MAX_CHALLENGE_V1: u64 = u32::MAX as u64;
const MAX_WITNESS_COEFFICIENT_V1: i64 = 2;
const BOX_SLACK_FACTOR_V1: i64 = 1 << 24;
const CHALLENGE_SHIFT_BOUND_V1: i64 = (MAX_CHALLENGE_V1 as i64) * MAX_WITNESS_COEFFICIENT_V1;
const MASK_COEFFICIENT_BOUND_V1: i64 = CHALLENGE_SHIFT_BOUND_V1 * BOX_SLACK_FACTOR_V1;
const RESPONSE_COEFFICIENT_BOUND_V1: i64 = MASK_COEFFICIENT_BOUND_V1 - CHALLENGE_SHIFT_BOUND_V1;
const MAX_FORK_INTEGER_LIFT_DIFFERENCE_V1: i64 =
    2 * RESPONSE_COEFFICIENT_BOUND_V1 + CHALLENGE_SHIFT_BOUND_V1;
const MINIMUM_RELEASE_RNS_MODULUS_V1: u64 = 1_152_921_504_409_190_401;
const WHOLE_ATTEMPT_RESPONSE_COORDINATES_V1: usize =
    CHALLENGE_REPETITIONS_V1 * MAX_RELATION_WITNESSES_V1 * RELEASE_RING_DEGREE_V1;
const OUTER_RETRY_CEILING_V1: usize = 128;
const OUTER_RETRY_EXHAUSTION_BITS_V1: usize = 309;
const INTEGER_SAMPLER_RETRY_CEILING_V1: usize = 128;
const INTEGER_SAMPLER_UNION_EXHAUSTION_BITS_V1: usize = 8_800;
const SIGNED_RESPONSE_BYTES_V1: usize = 8;
const T256_SCALAR_BYTES_V1: usize = 32;
const T256_POINT_BYTES_V1: usize = 33;
const CHALLENGE_SEED_BYTES_V1: usize = 32;
const RESPONSE_PAYLOAD_BYTES_V1: usize = CHALLENGE_REPETITIONS_V1
    * MAX_RELATION_WITNESSES_V1
    * RELEASE_RING_DEGREE_V1
    * SIGNED_RESPONSE_BYTES_V1;
const BLIND_RESPONSE_PAYLOAD_BYTES_V1: usize =
    CHALLENGE_REPETITIONS_V1 * MAX_CHUNK_COMMITMENTS_V1 * T256_SCALAR_BYTES_V1;
const CHUNK_COMMITMENT_PAYLOAD_BYTES_V1: usize = MAX_CHUNK_COMMITMENTS_V1 * T256_POINT_BYTES_V1;
// A generalized-Bulletproof membership proof with one external vector
// commitment has AI/AO/S (3 points), six committed non-constant t(X)
// coefficients, two points per IPA round, and tau_x/u/t_hat/a/b (5 scalars).
const BOUND_ONE_BOOLEAN_GATES_PER_COEFFICIENT_V1: usize = 2;
const BOUND_TWO_BOOLEAN_GATES_PER_COEFFICIENT_V1: usize = 3;
const BOUND_ONE_CONSTRAINTS_PER_COEFFICIENT_V1: usize = 5;
const BOUND_TWO_CONSTRAINTS_PER_COEFFICIENT_V1: usize = 7;
const BOUND_ONE_GATES_PER_CHUNK_V1: usize =
    WITNESS_CHUNK_COEFFICIENTS_V1 * BOUND_ONE_BOOLEAN_GATES_PER_COEFFICIENT_V1;
const BOUND_TWO_GATES_PER_CHUNK_V1: usize =
    WITNESS_CHUNK_COEFFICIENTS_V1 * BOUND_TWO_BOOLEAN_GATES_PER_COEFFICIENT_V1;
const BOUND_ONE_PADDED_GATES_V1: usize = 32_768;
const BOUND_TWO_PADDED_GATES_V1: usize = 65_536;
// The opening occupies the complete padded generator basis.  In addition to
// each visible coefficient's membership equations, one constraint fixes every
// remaining committed coordinate to zero.
const BOUND_ONE_CONSTRAINTS_PER_CHUNK_V1: usize = WITNESS_CHUNK_COEFFICIENTS_V1
    * BOUND_ONE_CONSTRAINTS_PER_COEFFICIENT_V1
    + (BOUND_ONE_PADDED_GATES_V1 - WITNESS_CHUNK_COEFFICIENTS_V1);
const BOUND_TWO_CONSTRAINTS_PER_CHUNK_V1: usize = WITNESS_CHUNK_COEFFICIENTS_V1
    * BOUND_TWO_CONSTRAINTS_PER_COEFFICIENT_V1
    + (BOUND_TWO_PADDED_GATES_V1 - WITNESS_CHUNK_COEFFICIENTS_V1);
const BOUND_ONE_IPA_ROUNDS_V1: usize = 15;
const BOUND_TWO_IPA_ROUNDS_V1: usize = 16;
const MEMBERSHIP_FIXED_POINTS_V1: usize = 9;
const MEMBERSHIP_FIXED_SCALARS_V1: usize = 5;
const BOUND_ONE_MEMBERSHIP_CORE_BYTES_V1: usize =
    (MEMBERSHIP_FIXED_POINTS_V1 + 2 * BOUND_ONE_IPA_ROUNDS_V1) * T256_POINT_BYTES_V1
        + MEMBERSHIP_FIXED_SCALARS_V1 * T256_SCALAR_BYTES_V1;
const BOUND_TWO_MEMBERSHIP_CORE_BYTES_V1: usize =
    (MEMBERSHIP_FIXED_POINTS_V1 + 2 * BOUND_TWO_IPA_ROUNDS_V1) * T256_POINT_BYTES_V1
        + MEMBERSHIP_FIXED_SCALARS_V1 * T256_SCALAR_BYTES_V1;
const MAX_MEMBERSHIP_CORE_PAYLOAD_BYTES_V1: usize =
    MAX_BOUND_ONE_WITNESSES_V1 * CHUNKS_PER_WITNESS_V1 * BOUND_ONE_MEMBERSHIP_CORE_BYTES_V1
        + MAX_BOUND_TWO_WITNESSES_V1 * CHUNKS_PER_WITNESS_V1 * BOUND_TWO_MEMBERSHIP_CORE_BYTES_V1;
// Current authenticated active-evidence framing, counted separately from the
// still-undefined replacement proof framing.
const CURRENT_ACTIVE_EVIDENCE_HEADER_BYTES_V1: usize = 4 + 1 + 32 + 1 + 4;
const CURRENT_ACTIVE_AUTHENTICATION_BYTES_V1: usize =
    1 + 32 + 32 + 8 + 32 + 1 + 4 + 32 + 32 + 1 + 32 + 33 + 65;
const KNOWN_PAYLOAD_LOWER_BOUND_BYTES_V1: usize = RESPONSE_PAYLOAD_BYTES_V1
    + BLIND_RESPONSE_PAYLOAD_BYTES_V1
    + CHUNK_COMMITMENT_PAYLOAD_BYTES_V1
    + MAX_MEMBERSHIP_CORE_PAYLOAD_BYTES_V1
    + CHALLENGE_SEED_BYTES_V1
    + CURRENT_ACTIVE_EVIDENCE_HEADER_BYTES_V1
    + CURRENT_ACTIVE_AUTHENTICATION_BYTES_V1;
const KNOWN_PAYLOAD_HEADROOM_BYTES_V1: usize =
    ZK_AMS_MKHE_MAX_PROOF_BYTES_V1 - KNOWN_PAYLOAD_LOWER_BOUND_BYTES_V1;
const PERSISTENT_COMMITMENT_CHUNKS_V1: usize = CHUNKS_PER_WITNESS_V1;
const PERSISTENT_COMMITMENT_POINT_BYTES_V1: usize =
    PERSISTENT_COMMITMENT_CHUNKS_V1 * T256_POINT_BYTES_V1;
const PERSISTENT_COMMITMENT_BLINDING_STATE_BYTES_V1: usize =
    PERSISTENT_COMMITMENT_CHUNKS_V1 * T256_SCALAR_BYTES_V1;
const PERSISTENT_BOUND_ONE_MEMBERSHIP_CORE_BYTES_V1: usize =
    PERSISTENT_COMMITMENT_CHUNKS_V1 * BOUND_ONE_MEMBERSHIP_CORE_BYTES_V1;
const SECRET_CONSUMER_CPK_V1: u8 = 1 << 0;
const SECRET_CONSUMER_RKG_ONE_V1: u8 = 1 << 1;
const SECRET_CONSUMER_RKG_TWO_V1: u8 = 1 << 2;
const SECRET_CONSUMER_GALOIS_V1: u8 = 1 << 3;
const SECRET_CONSUMER_DECRYPTION_V1: u8 = 1 << 4;
const SECRET_REQUIRED_CONSUMERS_V1: u8 = SECRET_CONSUMER_CPK_V1
    | SECRET_CONSUMER_RKG_ONE_V1
    | SECRET_CONSUMER_RKG_TWO_V1
    | SECRET_CONSUMER_GALOIS_V1
    | SECRET_CONSUMER_DECRYPTION_V1;
const EPHEMERAL_CONSUMER_RKG_ONE_V1: u8 = 1 << 0;
const EPHEMERAL_CONSUMER_RKG_TWO_V1: u8 = 1 << 1;
const EPHEMERAL_REQUIRED_CONSUMERS_V1: u8 =
    EPHEMERAL_CONSUMER_RKG_ONE_V1 | EPHEMERAL_CONSUMER_RKG_TWO_V1;
// The allocation pattern of the existing generalized-Bulletproof code keeps
// at least eight l/r vectors, three witness vectors, y, and y^-1 alive at
// once.  At the unchunked eta=2 dimension this scalar-only lower bound already
// exceeds 160 MiB.  It does not include generators, constraints, MSM terms, or
// buckets.  Chunking is therefore mandatory, but the chunked total still needs
// an implementation-derived ledger.
const DIRECT_BP_SIMULTANEOUS_SCALAR_VECTORS_V1: usize = 13;
const UNCHUNKED_BOUND_TWO_PADDED_GATES_V1: usize = 524_288;
const UNCHUNKED_SCALAR_VECTOR_LOWER_BOUND_BYTES_V1: usize = DIRECT_BP_SIMULTANEOUS_SCALAR_VECTORS_V1
    * UNCHUNKED_BOUND_TWO_PADDED_GATES_V1
    * T256_SCALAR_BYTES_V1;
const CHUNKED_SCALAR_VECTOR_LOWER_BOUND_BYTES_V1: usize =
    DIRECT_BP_SIMULTANEOUS_SCALAR_VECTORS_V1 * BOUND_TWO_PADDED_GATES_V1 * T256_SCALAR_BYTES_V1;
const GOVERNED_WORKSPACE_CEILING_BYTES_V1: usize = 160 * 1024 * 1024;
const BLOCKER_T256_MEMBERSHIP_SECURITY_V1: u16 = 1 << 0;
const BLOCKER_GENERATOR_BASIS_KAT_V1: u16 = 1 << 1;
const BLOCKER_CANONICAL_WIRE_V1: u16 = 1 << 2;
const BLOCKER_WORKSPACE_LEDGER_V1: u16 = 1 << 3;
const BLOCKER_SAMPLER_RUNTIME_INTEGRATION_V1: u16 = 1 << 4;
const BLOCKER_PERSISTENT_GRAPH_RUNTIME_V1: u16 = 1 << 5;
const BLOCKER_SPLIT_DECRYPTION_WIDE_RELATION_V1: u16 = 1 << 6;
const BLOCKER_RELEASE_KAT_V1: u16 = 1 << 7;
const ALL_RELEASE_BLOCKERS_V1: u16 = BLOCKER_T256_MEMBERSHIP_SECURITY_V1
    | BLOCKER_GENERATOR_BASIS_KAT_V1
    | BLOCKER_CANONICAL_WIRE_V1
    | BLOCKER_WORKSPACE_LEDGER_V1
    | BLOCKER_SAMPLER_RUNTIME_INTEGRATION_V1
    | BLOCKER_PERSISTENT_GRAPH_RUNTIME_V1
    | BLOCKER_SPLIT_DECRYPTION_WIDE_RELATION_V1
    | BLOCKER_RELEASE_KAT_V1;
const AUDIT_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.active-exact-small-binding.fail-closed-audit";
#[cfg(test)]
const PERSISTENT_IDENTITY_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.active-exact-small-binding.persistent-identity";
#[cfg(test)]
const PERSISTENT_VERIFICATION_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.active-exact-small-binding.persistent-verification";
#[cfg(test)]
const PERSISTENT_COMMITMENT_SET_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.active-exact-small-binding.persistent-commitment-set";
#[cfg(test)]
const PERSISTENT_ORDERED_SET_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.active-exact-small-binding.persistent-ordered-set";
#[cfg(test)]
const PERSISTENT_DIRECT_RELATION_USE_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.active-exact-small-binding.persistent-direct-relation-use";
#[cfg(test)]
const CHALLENGE_VECTOR_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.active-exact-small-binding.challenge-vector";
#[cfg(test)]
const CHALLENGE_COORDINATE_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.mkhe.active-exact-small-binding.challenge-coordinate";
const _: () = {
    assert!(RELEASE_RING_DEGREE_V1 == 1 << 17);
    assert!(CHUNKS_PER_WITNESS_V1 == 8);
    assert!(MAX_CHUNK_COMMITMENTS_V1 == 48);
    assert!(JOINT_CHALLENGE_BITS_V1 == 128);
    assert!(CHALLENGE_SHIFT_BOUND_V1 == 8_589_934_590);
    assert!(MASK_COEFFICIENT_BOUND_V1 == 144_115_188_042_301_440);
    assert!(RESPONSE_COEFFICIENT_BOUND_V1 == 144_115_179_452_366_850);
    assert!(MAX_FORK_INTEGER_LIFT_DIFFERENCE_V1 == 288_230_367_494_668_290);
    assert!(RESPONSE_COEFFICIENT_BOUND_V1 < i64::MAX);
    assert!(MAX_FORK_INTEGER_LIFT_DIFFERENCE_V1 < (1_i64 << 58));
    assert!(RESPONSE_COEFFICIENT_BOUND_V1 < ((MINIMUM_RELEASE_RNS_MODULUS_V1 - 1) / 2) as i64);
    assert!(WHOLE_ATTEMPT_RESPONSE_COORDINATES_V1 == 3 * (1 << 20));
    assert!(RESPONSE_PAYLOAD_BYTES_V1 == 25_165_824);
    assert!(BLIND_RESPONSE_PAYLOAD_BYTES_V1 == 6_144);
    assert!(CHUNK_COMMITMENT_PAYLOAD_BYTES_V1 == 1_584);
    assert!(BOUND_ONE_GATES_PER_CHUNK_V1 == BOUND_ONE_PADDED_GATES_V1);
    assert!(BOUND_TWO_GATES_PER_CHUNK_V1 == 49_152);
    assert!(BOUND_TWO_PADDED_GATES_V1 == 65_536);
    assert!(BOUND_ONE_CONSTRAINTS_PER_CHUNK_V1 == 98_304);
    assert!(BOUND_TWO_CONSTRAINTS_PER_CHUNK_V1 == 163_840);
    assert!(BOUND_ONE_MEMBERSHIP_CORE_BYTES_V1 == 1_447);
    assert!(BOUND_TWO_MEMBERSHIP_CORE_BYTES_V1 == 1_513);
    assert!(MAX_MEMBERSHIP_CORE_PAYLOAD_BYTES_V1 == 71_568);
    assert!(CURRENT_ACTIVE_EVIDENCE_HEADER_BYTES_V1 == 42);
    assert!(CURRENT_ACTIVE_AUTHENTICATION_BYTES_V1 == 305);
    assert!(KNOWN_PAYLOAD_LOWER_BOUND_BYTES_V1 == 25_245_499);
    assert!(KNOWN_PAYLOAD_HEADROOM_BYTES_V1 == 8_308_933);
    assert!(PERSISTENT_COMMITMENT_POINT_BYTES_V1 == 264);
    assert!(PERSISTENT_COMMITMENT_BLINDING_STATE_BYTES_V1 == 256);
    assert!(PERSISTENT_BOUND_ONE_MEMBERSHIP_CORE_BYTES_V1 == 11_576);
    assert!(SECRET_REQUIRED_CONSUMERS_V1 == 0b1_1111);
    assert!(EPHEMERAL_REQUIRED_CONSUMERS_V1 == 0b11);
    assert!(UNCHUNKED_SCALAR_VECTOR_LOWER_BOUND_BYTES_V1 == 218_103_808);
    assert!(UNCHUNKED_SCALAR_VECTOR_LOWER_BOUND_BYTES_V1 > GOVERNED_WORKSPACE_CEILING_BYTES_V1);
    assert!(CHUNKED_SCALAR_VECTOR_LOWER_BOUND_BYTES_V1 == 27_262_976);
    assert!(ALL_RELEASE_BLOCKERS_V1 == 0xff);
};
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum PersistentWitnessRoleV1 {
    SecretEpoch = 1,
    RkgEphemeral = 2,
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PersistentCommitmentIdentityV1 {
    profile_digest: [u8; 32],
    roster_digest: [u8; 32],
    key_material_digest: [u8; 32],
    epoch: u64,
    party: [u8; 32],
    role: PersistentWitnessRoleV1,
    record_index: u32,
    commitment_set_digest: [u8; 32],
    membership_proof_digest: [u8; 32],
    consumer_mask: u8,
    identity_digest: [u8; 32],
}
#[cfg(test)]
impl PersistentCommitmentIdentityV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        profile_digest: [u8; 32],
        roster_digest: [u8; 32],
        key_material_digest: [u8; 32],
        epoch: u64,
        party: [u8; 32],
        role: PersistentWitnessRoleV1,
        record_index: u32,
        commitment_set_digest: [u8; 32],
        membership_proof_digest: [u8; 32],
        consumer_mask: u8,
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        let mut identity = Self {
            profile_digest,
            roster_digest,
            key_material_digest,
            epoch,
            party,
            role,
            record_index,
            commitment_set_digest,
            membership_proof_digest,
            consumer_mask,
            identity_digest: [0; 32],
        };
        identity.validate_fields()?;
        identity.identity_digest = persistent_identity_digest(identity);
        Ok(identity)
    }
    fn validate(self) -> Result<(), ZkAmsMkheErrorV1> {
        self.validate_fields()?;
        if self.identity_digest == [0; 32]
            || self.identity_digest != persistent_identity_digest(self)
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        Ok(())
    }
    fn validate_fields(self) -> Result<(), ZkAmsMkheErrorV1> {
        let expected_consumers = match self.role {
            PersistentWitnessRoleV1::SecretEpoch => SECRET_REQUIRED_CONSUMERS_V1,
            PersistentWitnessRoleV1::RkgEphemeral => EPHEMERAL_REQUIRED_CONSUMERS_V1,
        };
        if self.profile_digest == [0; 32]
            || self.roster_digest == [0; 32]
            || self.key_material_digest == [0; 32]
            || self.epoch == 0
            || self.party == [0; 32]
            || self.commitment_set_digest == [0; 32]
            || self.membership_proof_digest == [0; 32]
            || self.consumer_mask != expected_consumers
            || (self.role == PersistentWitnessRoleV1::SecretEpoch && self.record_index != 0)
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        Ok(())
    }
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PersistentCommitmentGraphV1 {
    secret_identity: [u8; 32],
    cpk_secret: [u8; 32],
    rkg_one_secret: [u8; 32],
    rkg_two_secret: [u8; 32],
    galois_secret: [u8; 32],
    decryption_secret: [u8; 32],
    ephemeral_identity: [u8; 32],
    rkg_one_ephemeral: [u8; 32],
    rkg_two_ephemeral: [u8; 32],
}
#[cfg(test)]
impl PersistentCommitmentGraphV1 {
    fn new(
        secret: PersistentCommitmentIdentityV1,
        ephemeral: PersistentCommitmentIdentityV1,
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        secret.validate()?;
        ephemeral.validate()?;
        if secret.role != PersistentWitnessRoleV1::SecretEpoch
            || ephemeral.role != PersistentWitnessRoleV1::RkgEphemeral
            || secret.profile_digest != ephemeral.profile_digest
            || secret.roster_digest != ephemeral.roster_digest
            || secret.key_material_digest != ephemeral.key_material_digest
            || secret.epoch != ephemeral.epoch
            || secret.party != ephemeral.party
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        Ok(Self {
            secret_identity: secret.identity_digest,
            cpk_secret: secret.identity_digest,
            rkg_one_secret: secret.identity_digest,
            rkg_two_secret: secret.identity_digest,
            galois_secret: secret.identity_digest,
            decryption_secret: secret.identity_digest,
            ephemeral_identity: ephemeral.identity_digest,
            rkg_one_ephemeral: ephemeral.identity_digest,
            rkg_two_ephemeral: ephemeral.identity_digest,
        })
    }
    fn validate(self) -> Result<(), ZkAmsMkheErrorV1> {
        if self.secret_identity == [0; 32]
            || self.ephemeral_identity == [0; 32]
            || [
                self.cpk_secret,
                self.rkg_one_secret,
                self.rkg_two_secret,
                self.galois_secret,
                self.decryption_secret,
            ]
            .iter()
            .any(|identity| *identity != self.secret_identity)
            || [self.rkg_one_ephemeral, self.rkg_two_ephemeral]
                .iter()
                .any(|identity| *identity != self.ephemeral_identity)
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        Ok(())
    }
    fn digest(self) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
        self.validate()?;
        let mut frame = Vec::with_capacity(32 * 9 + 64);
        frame.extend_from_slice(b"iroha.zk-ams.v1.mkhe.active-exact-persistent-graph");
        for digest in [
            self.secret_identity,
            self.cpk_secret,
            self.rkg_one_secret,
            self.rkg_two_secret,
            self.galois_secret,
            self.decryption_secret,
            self.ephemeral_identity,
            self.rkg_one_ephemeral,
            self.rkg_two_ephemeral,
        ] {
            frame.extend_from_slice(&digest);
        }
        Ok(keccak256(&frame))
    }
}
/// Protocol consumer which must reuse an already verified persistent witness.
///
/// This is crate-private because callers outside the native MKHE proof stack
/// never select a lineage role.  `RkgNormalize` deliberately shares the
/// round-two secret bit: it is the continuation of the same RKG relation.  A
/// separate RKG-ephemeral token has no normalization bit and is rejected.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum PersistentWitnessConsumerV1 {
    CollectivePublicKey = 1,
    RkgRoundOne = 2,
    RkgRoundTwo = 3,
    RkgNormalize = 4,
    Galois = 5,
    Decryption = 6,
}
/// RKG round which consumes the separate persistent ephemeral witness `u_i`.
///
/// This is intentionally a distinct enum from the secret consumer mask: the
/// bit positions have different meanings and must never be interchanged.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum PersistentRkgEphemeralConsumerV1 {
    RoundOne = 1,
    RoundTwo = 2,
}
#[cfg(test)]
impl PersistentRkgEphemeralConsumerV1 {
    const fn mask(self) -> u8 {
        match self {
            Self::RoundOne => EPHEMERAL_CONSUMER_RKG_ONE_V1,
            Self::RoundTwo => EPHEMERAL_CONSUMER_RKG_TWO_V1,
        }
    }
}
#[cfg(test)]
impl PersistentWitnessConsumerV1 {
    const fn mask(self) -> u8 {
        match self {
            Self::CollectivePublicKey => SECRET_CONSUMER_CPK_V1,
            Self::RkgRoundOne => SECRET_CONSUMER_RKG_ONE_V1,
            Self::RkgRoundTwo | Self::RkgNormalize => SECRET_CONSUMER_RKG_TWO_V1,
            Self::Galois => SECRET_CONSUMER_GALOIS_V1,
            Self::Decryption => SECRET_CONSUMER_DECRYPTION_V1,
        }
    }
}
/// Private normalized lineage used by the binding constructor.
///
/// Production code obtains these fields only by consuming the sealed complete
/// CPK relation source.  Tests construct fixtures inside this module so that
/// every immutable binding axis can be mutation-tested without an eight-million
/// byte relation proof.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactMembershipVerificationReceiptV1 {
    role: PersistentWitnessRoleV1,
    source_context_digest: [u8; 32],
    source_statement_digest: [u8; 32],
    generator_basis_digest: [u8; 32],
    commitments: [Point; PERSISTENT_COMMITMENT_CHUNKS_V1],
    commitment_set_digest: [u8; 32],
    membership_proof_digest: [u8; 32],
    verifier_transcript_digest: [u8; 32],
    source_verification_digest: [u8; 32],
}
/// Opaque proof-verified capability for one persistent witness commitment.
///
/// There is no decoder and no visible constructor.  Consumers can inspect an
/// identity only after role-specific validation has checked the complete source context. The
/// identity excludes randomized membership-proof and consumer-purpose metadata. A secret-epoch
/// identity therefore remains stable across every consumer; an RKG-ephemeral identity additionally
/// binds the verifier-certified direct context and wrapper statement.
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(super) struct VerifiedPersistentWitnessBindingV1 {
    version: u8,
    profile_digest: [u8; 32],
    security_certificate_digest: [u8; 32],
    roster_digest: [u8; 32],
    key_material_digest: [u8; 32],
    epoch: u64,
    cpk_transcript_digest: [u8; 32],
    party_index: u8,
    party: ZkAmsMkhePartyIdV1,
    cpk_share_digest: [u8; 32],
    role: PersistentWitnessRoleV1,
    record_index: u32,
    source_context_digest: [u8; 32],
    source_statement_digest: [u8; 32],
    generator_basis_digest: [u8; 32],
    commitments: [Point; PERSISTENT_COMMITMENT_CHUNKS_V1],
    commitment_set_digest: [u8; 32],
    membership_proof_digest: [u8; 32],
    verifier_transcript_digest: [u8; 32],
    source_verification_digest: [u8; 32],
    consumer_mask: u8,
    identity_digest: [u8; 32],
    verification_digest: [u8; 32],
}
#[cfg(test)]
impl VerifiedPersistentWitnessBindingV1 {
    /// Split one verified fact into its two purpose-bound ceremony successors.
    ///
    /// This is deliberately not a `Clone` implementation: staged CPK is the
    /// only production corridor allowed to retain one successor in the party
    /// state while the verifier retains the other. The binding is compact and
    /// immutable; no polynomial, witness, or proof owner is duplicated.
    pub(super) fn fork_for_state_and_verifier_v1(self) -> (Self, Self) {
        let verifier = Self {
            version: self.version,
            profile_digest: self.profile_digest,
            security_certificate_digest: self.security_certificate_digest,
            roster_digest: self.roster_digest,
            key_material_digest: self.key_material_digest,
            epoch: self.epoch,
            cpk_transcript_digest: self.cpk_transcript_digest,
            party_index: self.party_index,
            party: self.party,
            cpk_share_digest: self.cpk_share_digest,
            role: self.role,
            record_index: self.record_index,
            source_context_digest: self.source_context_digest,
            source_statement_digest: self.source_statement_digest,
            generator_basis_digest: self.generator_basis_digest,
            commitments: self.commitments,
            commitment_set_digest: self.commitment_set_digest,
            membership_proof_digest: self.membership_proof_digest,
            verifier_transcript_digest: self.verifier_transcript_digest,
            source_verification_digest: self.source_verification_digest,
            consumer_mask: self.consumer_mask,
            identity_digest: self.identity_digest,
            verification_digest: self.verification_digest,
        };
        (self, verifier)
    }
    #[allow(clippy::too_many_arguments)]
    fn from_verified_membership(
        roster: &ZkAmsMkheGovernedActiveRosterV1,
        security_certificate_digest: [u8; 32],
        cpk_transcript_digest: [u8; 32],
        party_index: usize,
        cpk_share_digest: [u8; 32],
        record_index: u32,
        receipt: ExactMembershipVerificationReceiptV1,
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        roster.validate()?;
        if party_index >= ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1
            || security_certificate_digest == [0; 32]
            || cpk_transcript_digest == [0; 32]
            || cpk_share_digest == [0; 32]
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        validate_membership_receipt(&receipt)?;
        let consumer_mask = match receipt.role {
            PersistentWitnessRoleV1::SecretEpoch => SECRET_REQUIRED_CONSUMERS_V1,
            PersistentWitnessRoleV1::RkgEphemeral => EPHEMERAL_REQUIRED_CONSUMERS_V1,
        };
        if (receipt.role == PersistentWitnessRoleV1::SecretEpoch && record_index != 0)
            || (receipt.role == PersistentWitnessRoleV1::RkgEphemeral && record_index == 0)
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        let mut binding = Self {
            version: MKHE_VERSION_V1,
            profile_digest: roster.profile_digest(),
            security_certificate_digest,
            roster_digest: roster.roster_digest(),
            key_material_digest: roster.key_material_digest(),
            epoch: roster.epoch(),
            cpk_transcript_digest,
            party_index: u8::try_from(party_index)
                .map_err(|_| ZkAmsMkheErrorV1::InvalidKeyMaterial)?,
            party: roster.participants()[party_index].party(),
            cpk_share_digest,
            role: receipt.role,
            record_index,
            source_context_digest: receipt.source_context_digest,
            source_statement_digest: receipt.source_statement_digest,
            generator_basis_digest: receipt.generator_basis_digest,
            commitments: receipt.commitments,
            commitment_set_digest: receipt.commitment_set_digest,
            membership_proof_digest: receipt.membership_proof_digest,
            verifier_transcript_digest: receipt.verifier_transcript_digest,
            source_verification_digest: receipt.source_verification_digest,
            consumer_mask,
            identity_digest: [0; 32],
            verification_digest: [0; 32],
        };
        binding.identity_digest = verified_binding_identity_digest(&binding)?;
        binding.verification_digest = verified_binding_verification_digest(&binding)?;
        match binding.role {
            PersistentWitnessRoleV1::SecretEpoch => binding.validate_for(
                roster,
                cpk_transcript_digest,
                party_index,
                cpk_share_digest,
                PersistentWitnessConsumerV1::CollectivePublicKey,
            )?,
            PersistentWitnessRoleV1::RkgEphemeral => binding.validate_ephemeral_for(
                roster,
                cpk_transcript_digest,
                party_index,
                cpk_share_digest,
                PersistentRkgEphemeralConsumerV1::RoundOne,
            )?,
        }
        Ok(binding)
    }
    /// Stable source-commitment identity.  This is evidence metadata, never a
    /// substitute for possession of this opaque verified type.
    pub(super) const fn identity_digest(&self) -> [u8; 32] {
        self.identity_digest
    }
    /// Canonical commitment-set digest certified by the exact membership
    /// verifier.  Consumers which need group arithmetic use `commitments`, not
    /// a caller-supplied digest.
    pub(super) const fn commitment_set_digest(&self) -> [u8; 32] {
        self.commitment_set_digest
    }
    /// Direct-ceremony context certified by the role-specific membership
    /// wrapper. Secret-epoch bindings deliberately retain the all-zero value.
    pub(super) const fn source_context_digest(&self) -> [u8; 32] {
        self.source_context_digest
    }
    /// Canonical wrapper statement certified by the exact verifier. This is
    /// nonzero only for an RKG-ephemeral binding.
    pub(super) const fn source_statement_digest(&self) -> [u8; 32] {
        self.source_statement_digest
    }
    pub(super) const fn commitments(&self) -> &[Point; PERSISTENT_COMMITMENT_CHUNKS_V1] {
        &self.commitments
    }
    /// Validate every immutable source axis before one protocol consumes the
    /// capability.  The requested purpose is checked against the sealed mask
    /// but is not folded into the stable identity.
    pub(super) fn validate_for(
        &self,
        roster: &ZkAmsMkheGovernedActiveRosterV1,
        cpk_transcript_digest: [u8; 32],
        party_index: usize,
        cpk_share_digest: [u8; 32],
        required_consumer: PersistentWitnessConsumerV1,
    ) -> Result<(), ZkAmsMkheErrorV1> {
        roster.validate()?;
        if party_index >= ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1
            || self.version != MKHE_VERSION_V1
            || self.profile_digest != roster.profile_digest()
            || self.roster_digest != roster.roster_digest()
            || self.key_material_digest != roster.key_material_digest()
            || self.epoch != roster.epoch()
            || self.cpk_transcript_digest != cpk_transcript_digest
            || usize::from(self.party_index) != party_index
            || self.party != roster.participants()[party_index].party()
            || self.cpk_share_digest != cpk_share_digest
            || self.role != PersistentWitnessRoleV1::SecretEpoch
            || self.record_index != 0
            || self.source_context_digest != [0; 32]
            || self.source_statement_digest != [0; 32]
            || self.consumer_mask != SECRET_REQUIRED_CONSUMERS_V1
            || self.consumer_mask & required_consumer.mask() == 0
            || self.source_verification_digest == [0; 32]
            || self.identity_digest == [0; 32]
            || self.identity_digest != verified_binding_identity_digest(self)?
            || self.verification_digest == [0; 32]
            || self.verification_digest != verified_binding_verification_digest(self)?
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        validate_canonical_commitment_set(
            self.generator_basis_digest,
            &self.commitments,
            self.commitment_set_digest,
        )
    }
    /// Validate the separate RKG-ephemeral commitment for one exact round.
    pub(super) fn validate_ephemeral_for(
        &self,
        roster: &ZkAmsMkheGovernedActiveRosterV1,
        cpk_transcript_digest: [u8; 32],
        party_index: usize,
        cpk_share_digest: [u8; 32],
        required_consumer: PersistentRkgEphemeralConsumerV1,
    ) -> Result<(), ZkAmsMkheErrorV1> {
        roster.validate()?;
        if party_index >= ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1
            || self.version != MKHE_VERSION_V1
            || self.profile_digest != roster.profile_digest()
            || self.roster_digest != roster.roster_digest()
            || self.key_material_digest != roster.key_material_digest()
            || self.epoch != roster.epoch()
            || self.cpk_transcript_digest != cpk_transcript_digest
            || usize::from(self.party_index) != party_index
            || self.party != roster.participants()[party_index].party()
            || self.cpk_share_digest != cpk_share_digest
            || self.role != PersistentWitnessRoleV1::RkgEphemeral
            || self.record_index == 0
            || self.source_context_digest == [0; 32]
            || self.source_statement_digest == [0; 32]
            || self.consumer_mask != EPHEMERAL_REQUIRED_CONSUMERS_V1
            || self.consumer_mask & required_consumer.mask() == 0
            || self.identity_digest == [0; 32]
            || self.identity_digest != verified_binding_identity_digest(self)?
            || self.verification_digest == [0; 32]
            || self.verification_digest != verified_binding_verification_digest(self)?
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        validate_canonical_commitment_set(
            self.generator_basis_digest,
            &self.commitments,
            self.commitment_set_digest,
        )
    }
}
/// Exact ordered eight-party set of opaque verified secret bindings.
///
/// Construction accepts capabilities, not digests.  The stored root is stable
/// across consumers; role authorization remains an explicit validation step.
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(super) struct VerifiedPersistentWitnessBindingSetV1 {
    profile_digest: [u8; 32],
    security_certificate_digest: [u8; 32],
    roster_digest: [u8; 32],
    key_material_digest: [u8; 32],
    epoch: u64,
    cpk_transcript_digest: [u8; 32],
    collective_public_key_digest: [u8; 32],
    cpk_share_digests: [[u8; 32]; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
    parties: [ZkAmsMkhePartyIdV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
    identity_digests: [[u8; 32]; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
    generator_basis_digests: [[u8; 32]; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
    commitment_set_digests: [[u8; 32]; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
    commitment_sets: [[Point; PERSISTENT_COMMITMENT_CHUNKS_V1]; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
    set_root: [u8; 32],
}
#[cfg(test)]
impl VerifiedPersistentWitnessBindingSetV1 {
    pub(super) fn new(
        roster: &ZkAmsMkheGovernedActiveRosterV1,
        cpk_transcript_digest: [u8; 32],
        collective_public_key_digest: [u8; 32],
        cpk_share_digests: [[u8; 32]; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
        bindings: [&VerifiedPersistentWitnessBindingV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        roster.validate()?;
        if cpk_transcript_digest == [0; 32]
            || collective_public_key_digest == [0; 32]
            || cpk_share_digests.contains(&[0; 32])
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        for (index, binding) in bindings.iter().enumerate() {
            binding.validate_for(
                roster,
                cpk_transcript_digest,
                index,
                cpk_share_digests[index],
                PersistentWitnessConsumerV1::CollectivePublicKey,
            )?;
            if binding.security_certificate_digest != bindings[0].security_certificate_digest
                || binding.generator_basis_digest != bindings[0].generator_basis_digest
            {
                return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
            }
        }
        let parties = roster.participants().map(|participant| participant.party());
        let identity_digests = core::array::from_fn(|index| bindings[index].identity_digest);
        let generator_basis_digests =
            core::array::from_fn(|index| bindings[index].generator_basis_digest);
        let commitment_set_digests =
            core::array::from_fn(|index| bindings[index].commitment_set_digest);
        if identity_digests
            .iter()
            .enumerate()
            .any(|(index, digest)| identity_digests[..index].contains(digest))
            || commitment_set_digests
                .iter()
                .enumerate()
                .any(|(index, digest)| commitment_set_digests[..index].contains(digest))
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        let commitment_sets = core::array::from_fn(|index| bindings[index].commitments);
        let mut set = Self {
            profile_digest: roster.profile_digest(),
            security_certificate_digest: bindings[0].security_certificate_digest,
            roster_digest: roster.roster_digest(),
            key_material_digest: roster.key_material_digest(),
            epoch: roster.epoch(),
            cpk_transcript_digest,
            collective_public_key_digest,
            cpk_share_digests,
            parties,
            identity_digests,
            generator_basis_digests,
            commitment_set_digests,
            commitment_sets,
            set_root: [0; 32],
        };
        set.set_root = verified_binding_set_root(&set)?;
        set.validate_for_consumer(roster, PersistentWitnessConsumerV1::CollectivePublicKey)?;
        Ok(set)
    }
    pub(super) const fn identity_digests(&self) -> &[[u8; 32]; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1] {
        &self.identity_digests
    }
    pub(super) const fn set_root(&self) -> [u8; 32] {
        self.set_root
    }
    pub(super) const fn cpk_transcript_digest(&self) -> [u8; 32] {
        self.cpk_transcript_digest
    }
    pub(super) const fn collective_public_key_digest(&self) -> [u8; 32] {
        self.collective_public_key_digest
    }
    pub(super) fn aggregate_commitments(&self) -> [Point; PERSISTENT_COMMITMENT_CHUNKS_V1] {
        core::array::from_fn(|chunk| {
            self.commitment_sets
                .iter()
                .map(|commitments| commitments[chunk])
                .reduce(|left, right| left + right)
                .expect("release roster is nonempty")
        })
    }
    pub(super) fn validate_for_consumer(
        &self,
        roster: &ZkAmsMkheGovernedActiveRosterV1,
        required_consumer: PersistentWitnessConsumerV1,
    ) -> Result<(), ZkAmsMkheErrorV1> {
        roster.validate()?;
        if self.profile_digest != roster.profile_digest()
            || self.security_certificate_digest == [0; 32]
            || self.roster_digest != roster.roster_digest()
            || self.key_material_digest != roster.key_material_digest()
            || self.epoch != roster.epoch()
            || self.cpk_transcript_digest == [0; 32]
            || self.collective_public_key_digest == [0; 32]
            || self.parties != roster.participants().map(|participant| participant.party())
            || self.cpk_share_digests.contains(&[0; 32])
            || self.identity_digests.contains(&[0; 32])
            || self.generator_basis_digests.contains(&[0; 32])
            || self
                .generator_basis_digests
                .iter()
                .any(|digest| *digest != self.generator_basis_digests[0])
            || self.commitment_set_digests.contains(&[0; 32])
            || self.set_root == [0; 32]
            || self.set_root != verified_binding_set_root(self)?
            || !matches!(
                required_consumer,
                PersistentWitnessConsumerV1::CollectivePublicKey
                    | PersistentWitnessConsumerV1::RkgRoundOne
                    | PersistentWitnessConsumerV1::RkgRoundTwo
                    | PersistentWitnessConsumerV1::RkgNormalize
                    | PersistentWitnessConsumerV1::Galois
                    | PersistentWitnessConsumerV1::Decryption
            )
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        for index in 0..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 {
            validate_canonical_commitment_set(
                self.generator_basis_digests[index],
                &self.commitment_sets[index],
                self.commitment_set_digests[index],
            )?;
        }
        Ok(())
    }
    /// Copy one party's public commitment material out of this consumed, proof-verified set. The
    /// sibling decryption module retains the authority; this tuple is never accepted from a caller.
    #[allow(
        clippy::type_complexity,
        reason = "fixed decryption material tuple preserves reviewed digest and commitment order"
    )]
    pub(super) fn decryption_party_material(
        &self,
        party_index: usize,
    ) -> Result<
        (
            [u8; 32],
            [u8; 32],
            [u8; 32],
            [Point; PERSISTENT_COMMITMENT_CHUNKS_V1],
        ),
        ZkAmsMkheErrorV1,
    > {
        if party_index >= ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 {
            return Err(ZkAmsMkheErrorV1::InvalidPartySet);
        }
        Ok((
            self.identity_digests[party_index],
            self.generator_basis_digests[party_index],
            self.commitment_set_digests[party_index],
            self.commitment_sets[party_index],
        ))
    }
    /// Validate one retained RKG-ephemeral binding at its exact direct context.
    ///
    /// The caller receives no security-certificate or CPK-share digest. Those
    /// provenance axes stay inside this verified set and are checked here
    /// together with the role-separated two-round consumer mask.
    pub(super) fn validate_rkg_ephemeral_binding_for_direct_context(
        &self,
        roster: &ZkAmsMkheGovernedActiveRosterV1,
        context: &ZkAmsMkheDirectCeremonyContextV1,
        party_index: usize,
        binding: &VerifiedPersistentWitnessBindingV1,
        round: ZkAmsMkheDirectCeremonyRoundV1,
    ) -> Result<(), ZkAmsMkheErrorV1> {
        context.validate_rkg_ephemeral_membership_axes(roster, self)?;
        if party_index >= ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 {
            return Err(ZkAmsMkheErrorV1::InvalidPartySet);
        }
        let consumer = match round {
            ZkAmsMkheDirectCeremonyRoundV1::RkgRoundOne => {
                PersistentRkgEphemeralConsumerV1::RoundOne
            }
            ZkAmsMkheDirectCeremonyRoundV1::RkgRoundTwo => {
                PersistentRkgEphemeralConsumerV1::RoundTwo
            }
            ZkAmsMkheDirectCeremonyRoundV1::RkgNormalize
            | ZkAmsMkheDirectCeremonyRoundV1::Galois => {
                return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
            }
        };
        binding.validate_ephemeral_for(
            roster,
            self.cpk_transcript_digest,
            party_index,
            self.cpk_share_digests[party_index],
            consumer,
        )?;
        let expected_context =
            ZkAmsMkheDirectRkgEphemeralMembershipContextV1::from_verified_binding_set(
                roster,
                self,
                context,
                party_index,
            )?;
        if binding.security_certificate_digest != self.security_certificate_digest
            || binding.generator_basis_digest != self.generator_basis_digests[party_index]
            || binding.identity_digest == self.identity_digests[party_index]
            || binding.commitment_set_digest == self.commitment_set_digests[party_index]
            || binding.record_index != expected_context.record_index()
            || binding.source_context_digest != context.digest()
            || binding.source_context_digest != expected_context.direct_context_digest()
            || binding.source_statement_digest != expected_context.statement_digest()
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        Ok(())
    }
    /// Bind one party's actual persistent commitment points to one exact
    /// direct-ceremony relation.  A lineage digest is never accepted here.
    pub(super) fn bind_direct_relation_use(
        &self,
        roster: &ZkAmsMkheGovernedActiveRosterV1,
        party_index: usize,
        ephemeral: Option<&VerifiedPersistentWitnessBindingV1>,
        selector: PersistentDirectRelationUseSelectorV1,
    ) -> Result<VerifiedPersistentWitnessDirectRelationUseV1, ZkAmsMkheErrorV1> {
        selector.validate()?;
        let secret_consumer = selector.relation.secret_consumer();
        self.validate_for_consumer(roster, secret_consumer)?;
        if party_index >= ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 {
            return Err(ZkAmsMkheErrorV1::InvalidPartySet);
        }
        let expected_ephemeral = selector.relation.ephemeral_consumer();
        match (expected_ephemeral, ephemeral) {
            (Some(required), Some(binding)) => {
                binding.validate_ephemeral_for(
                    roster,
                    self.cpk_transcript_digest,
                    party_index,
                    self.cpk_share_digests[party_index],
                    required,
                )?;
                if binding.identity_digest == self.identity_digests[party_index]
                    || binding.generator_basis_digest != self.generator_basis_digests[party_index]
                    || binding.commitment_set_digest == self.commitment_set_digests[party_index]
                    || binding.source_context_digest != selector.context_digest
                {
                    return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
                }
            }
            (None, None) => {}
            _ => return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial),
        }
        let mut capability = VerifiedPersistentWitnessDirectRelationUseV1 {
            binding_set_root: self.set_root,
            collective_public_key_digest: self.collective_public_key_digest,
            party_index: u8::try_from(party_index)
                .map_err(|_| ZkAmsMkheErrorV1::InvalidPartySet)?,
            party: self.parties[party_index],
            secret_identity_digest: self.identity_digests[party_index],
            secret_generator_basis_digest: self.generator_basis_digests[party_index],
            secret_commitment_set_digest: self.commitment_set_digests[party_index],
            secret_commitments: self.commitment_sets[party_index],
            ephemeral_identity_digest: ephemeral.map_or([0; 32], |binding| binding.identity_digest),
            ephemeral_commitment_set_digest: ephemeral
                .map_or([0; 32], |binding| binding.commitment_set_digest),
            ephemeral_source_context_digest: ephemeral
                .map_or([0; 32], |binding| binding.source_context_digest),
            ephemeral_source_statement_digest: ephemeral
                .map_or([0; 32], |binding| binding.source_statement_digest),
            ephemeral_record_index: ephemeral.map_or(0, |binding| binding.record_index),
            ephemeral_commitments: ephemeral.map(|binding| binding.commitments),
            selector,
            use_digest: [0; 32],
        };
        capability.use_digest = persistent_direct_relation_use_digest(&capability)?;
        capability.validate()?;
        Ok(capability)
    }
}
/// Exact direct-ceremony equation which consumes a persistent witness.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum PersistentDirectRelationV1 {
    RkgRoundOne = 1,
    RkgRoundTwo = 2,
    RkgNormalize = 3,
    Galois = 4,
}
#[cfg(test)]
impl PersistentDirectRelationV1 {
    const fn secret_consumer(self) -> PersistentWitnessConsumerV1 {
        match self {
            Self::RkgRoundOne => PersistentWitnessConsumerV1::RkgRoundOne,
            Self::RkgRoundTwo => PersistentWitnessConsumerV1::RkgRoundTwo,
            Self::RkgNormalize => PersistentWitnessConsumerV1::RkgNormalize,
            Self::Galois => PersistentWitnessConsumerV1::Galois,
        }
    }
    const fn ephemeral_consumer(self) -> Option<PersistentRkgEphemeralConsumerV1> {
        match self {
            Self::RkgRoundOne => Some(PersistentRkgEphemeralConsumerV1::RoundOne),
            Self::RkgRoundTwo => Some(PersistentRkgEphemeralConsumerV1::RoundTwo),
            Self::RkgNormalize | Self::Galois => None,
        }
    }
}
/// Canonical public-statement axes for one direct relation proof.
///
/// Every digest is computed from a validated polynomial statement or stream
/// receipt by the direct ceremony.  Prior-round digests are context only and
/// are never accepted as substitutes for the explicit aggregate-polynomial statement digests below.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PersistentDirectRelationUseSelectorV1 {
    relation: PersistentDirectRelationV1,
    context_digest: [u8; 32],
    prior_round_digest: [u8; 32],
    evaluated_key_ordinal: u8,
    digit_index: u8,
    galois_exponent: u32,
    common_a_statement_digest: [u8; 32],
    target_a_statement_digest: [u8; 32],
    aggregate_h0_statement_digest: [u8; 32],
    aggregate_h1_statement_digest: [u8; 32],
    contribution_statement_digest: [u8; 32],
    proof_commitment_transcript_digest: [u8; 32],
}
#[cfg(test)]
impl PersistentDirectRelationUseSelectorV1 {
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(super) fn new(
        relation: PersistentDirectRelationV1,
        context_digest: [u8; 32],
        prior_round_digest: [u8; 32],
        evaluated_key_ordinal: u8,
        digit_index: u8,
        galois_exponent: u32,
        common_a_statement_digest: [u8; 32],
        target_a_statement_digest: [u8; 32],
        aggregate_h0_statement_digest: [u8; 32],
        aggregate_h1_statement_digest: [u8; 32],
        contribution_statement_digest: [u8; 32],
        proof_commitment_transcript_digest: [u8; 32],
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        let selector = Self {
            relation,
            context_digest,
            prior_round_digest,
            evaluated_key_ordinal,
            digit_index,
            galois_exponent,
            common_a_statement_digest,
            target_a_statement_digest,
            aggregate_h0_statement_digest,
            aggregate_h1_statement_digest,
            contribution_statement_digest,
            proof_commitment_transcript_digest,
        };
        selector.validate()?;
        Ok(selector)
    }
    fn validate(self) -> Result<(), ZkAmsMkheErrorV1> {
        if self.context_digest == [0; 32]
            || self.prior_round_digest == [0; 32]
            || self.contribution_statement_digest == [0; 32]
            || self.proof_commitment_transcript_digest == [0; 32]
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        let zero = [0; 32];
        let shape_is_valid = match self.relation {
            PersistentDirectRelationV1::RkgRoundOne => {
                self.evaluated_key_ordinal == 0
                    && self.galois_exponent == 0
                    && self.common_a_statement_digest != zero
                    && self.target_a_statement_digest == zero
                    && self.aggregate_h0_statement_digest == zero
                    && self.aggregate_h1_statement_digest == zero
            }
            PersistentDirectRelationV1::RkgRoundTwo => {
                self.evaluated_key_ordinal == 0
                    && self.galois_exponent == 0
                    && self.common_a_statement_digest != zero
                    && self.target_a_statement_digest == zero
                    && self.aggregate_h0_statement_digest != zero
                    && self.aggregate_h1_statement_digest != zero
            }
            PersistentDirectRelationV1::RkgNormalize => {
                self.evaluated_key_ordinal == 0
                    && self.galois_exponent == 0
                    && self.common_a_statement_digest == zero
                    && self.target_a_statement_digest != zero
                    && self.aggregate_h0_statement_digest == zero
                    && self.aggregate_h1_statement_digest != zero
            }
            PersistentDirectRelationV1::Galois => {
                self.evaluated_key_ordinal != 0
                    && self.galois_exponent > 1
                    && self.galois_exponent % 2 == 1
                    && self.common_a_statement_digest == zero
                    && self.target_a_statement_digest != zero
                    && self.aggregate_h0_statement_digest == zero
                    && self.aggregate_h1_statement_digest == zero
            }
        };
        if !shape_is_valid {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        Ok(())
    }
}
/// Mint the only production Galois selector from exact CPK authority.
///
/// The target-`a` seed, schedule coordinates, and prior-round digest are inherited from the
/// reconstructed ceremony context. Only the two party-local statement digests remain caller inputs,
/// and no derived digest or authority object leaves the private target-`a` module.
#[cfg(test)]
pub(super) fn mint_galois_selector_v1(
    roster: &ZkAmsMkheGovernedActiveRosterV1,
    bindings: &VerifiedPersistentWitnessBindingSetV1,
    context: ZkAmsMkheDirectCeremonyContextV1,
    contribution_statement_digest: [u8; 32],
    proof_commitment_transcript_digest: [u8; 32],
) -> Result<PersistentDirectRelationUseSelectorV1, ZkAmsMkheErrorV1> {
    direct_galois_target_a_v1::mint_galois_selector_v1(
        roster,
        bindings,
        context,
        contribution_statement_digest,
        proof_commitment_transcript_digest,
    )
}
/// Non-serializable, single-use authorization for one exact direct relation.
///
/// This type is deliberately not `Clone`.  It retains the actual commitment
/// points so the proof adapter cannot replace them with caller-selected lineage metadata.
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(super) struct VerifiedPersistentWitnessDirectRelationUseV1 {
    binding_set_root: [u8; 32],
    collective_public_key_digest: [u8; 32],
    party_index: u8,
    party: ZkAmsMkhePartyIdV1,
    secret_identity_digest: [u8; 32],
    secret_generator_basis_digest: [u8; 32],
    secret_commitment_set_digest: [u8; 32],
    secret_commitments: [Point; PERSISTENT_COMMITMENT_CHUNKS_V1],
    ephemeral_identity_digest: [u8; 32],
    ephemeral_commitment_set_digest: [u8; 32],
    ephemeral_source_context_digest: [u8; 32],
    ephemeral_source_statement_digest: [u8; 32],
    ephemeral_record_index: u32,
    ephemeral_commitments: Option<[Point; PERSISTENT_COMMITMENT_CHUNKS_V1]>,
    selector: PersistentDirectRelationUseSelectorV1,
    use_digest: [u8; 32],
}
#[cfg(test)]
impl VerifiedPersistentWitnessDirectRelationUseV1 {
    fn validate(&self) -> Result<(), ZkAmsMkheErrorV1> {
        self.selector.validate()?;
        validate_canonical_commitment_set(
            self.secret_generator_basis_digest,
            &self.secret_commitments,
            self.secret_commitment_set_digest,
        )?;
        let ephemeral_required = self.selector.relation.ephemeral_consumer().is_some();
        if self.binding_set_root == [0; 32]
            || self.collective_public_key_digest == [0; 32]
            || self.secret_identity_digest == [0; 32]
            || self.use_digest == [0; 32]
            || ephemeral_required != self.ephemeral_commitments.is_some()
            || ephemeral_required != (self.ephemeral_identity_digest != [0; 32])
            || ephemeral_required != (self.ephemeral_commitment_set_digest != [0; 32])
            || ephemeral_required != (self.ephemeral_source_context_digest != [0; 32])
            || ephemeral_required != (self.ephemeral_source_statement_digest != [0; 32])
            || ephemeral_required != (self.ephemeral_record_index != 0)
            || (ephemeral_required
                && self.ephemeral_source_context_digest != self.selector.context_digest)
            || self.use_digest != persistent_direct_relation_use_digest(self)?
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        if let Some(commitments) = &self.ephemeral_commitments {
            validate_canonical_commitment_set(
                self.secret_generator_basis_digest,
                commitments,
                self.ephemeral_commitment_set_digest,
            )?;
        }
        Ok(())
    }
    pub(super) const fn use_digest(&self) -> [u8; 32] {
        self.use_digest
    }
    pub(super) const fn secret_identity_digest(&self) -> [u8; 32] {
        self.secret_identity_digest
    }
    pub(super) const fn ephemeral_identity_digest(&self) -> [u8; 32] {
        self.ephemeral_identity_digest
    }
    pub(super) const fn secret_commitments(&self) -> &[Point; PERSISTENT_COMMITMENT_CHUNKS_V1] {
        &self.secret_commitments
    }
    pub(super) const fn ephemeral_commitments(
        &self,
    ) -> Option<&[Point; PERSISTENT_COMMITMENT_CHUNKS_V1]> {
        self.ephemeral_commitments.as_ref()
    }
}
/// Opaque receipt returned only after the exact direct-relation verifier has
/// consumed the single-use commitment capability and accepted the proof.
///
/// No decoder or constructor is exposed to sibling modules.  The direct
/// ceremony may inspect the sealed selectors and proof identities, but cannot
/// mint this receipt from digests.
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(super) struct VerifiedDirectRelationProofReceiptV1 {
    relation: PersistentDirectRelationV1,
    context_digest: [u8; 32],
    prior_round_digest: [u8; 32],
    evaluated_key_ordinal: u8,
    digit_index: u8,
    galois_exponent: u32,
    party_index: u8,
    party: ZkAmsMkhePartyIdV1,
    secret_identity_digest: [u8; 32],
    ephemeral_identity_digest: [u8; 32],
    contribution_statement_digest: [u8; 32],
    relation_use_digest: [u8; 32],
    proof_digest: [u8; 32],
    verifier_transcript_digest: [u8; 32],
    evidence_set_digest: [u8; 32],
    receipt_digest: [u8; 32],
}
#[cfg(test)]
impl VerifiedDirectRelationProofReceiptV1 {
    pub(super) fn validate(&self) -> Result<(), ZkAmsMkheErrorV1> {
        let ephemeral_required = self.relation.ephemeral_consumer().is_some();
        if self.context_digest == [0; 32]
            || self.prior_round_digest == [0; 32]
            || self.secret_identity_digest == [0; 32]
            || self.contribution_statement_digest == [0; 32]
            || self.relation_use_digest == [0; 32]
            || self.proof_digest == [0; 32]
            || self.verifier_transcript_digest == [0; 32]
            || self.evidence_set_digest == [0; 32]
            || self.receipt_digest == [0; 32]
            || ephemeral_required != (self.ephemeral_identity_digest != [0; 32])
            || self.receipt_digest != verified_direct_relation_receipt_digest(self)
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        Ok(())
    }
    pub(super) const fn relation(&self) -> PersistentDirectRelationV1 {
        self.relation
    }
    pub(super) const fn context_digest(&self) -> [u8; 32] {
        self.context_digest
    }
    pub(super) const fn prior_round_digest(&self) -> [u8; 32] {
        self.prior_round_digest
    }
    pub(super) const fn evaluated_key_ordinal(&self) -> u8 {
        self.evaluated_key_ordinal
    }
    pub(super) const fn digit_index(&self) -> u8 {
        self.digit_index
    }
    pub(super) const fn galois_exponent(&self) -> u32 {
        self.galois_exponent
    }
    pub(super) const fn party_index(&self) -> u8 {
        self.party_index
    }
    pub(super) const fn party(&self) -> ZkAmsMkhePartyIdV1 {
        self.party
    }
    pub(super) const fn secret_identity_digest(&self) -> [u8; 32] {
        self.secret_identity_digest
    }
    pub(super) const fn ephemeral_identity_digest(&self) -> [u8; 32] {
        self.ephemeral_identity_digest
    }
    pub(super) const fn contribution_statement_digest(&self) -> [u8; 32] {
        self.contribution_statement_digest
    }
    pub(super) const fn relation_use_digest(&self) -> [u8; 32] {
        self.relation_use_digest
    }
    pub(super) const fn proof_digest(&self) -> [u8; 32] {
        self.proof_digest
    }
    pub(super) const fn evidence_set_digest(&self) -> [u8; 32] {
        self.evidence_set_digest
    }
}
/// Sole exact direct-relation verification boundary.
///
/// The neutral generalized-Bulletproof backend and T256 relation circuit must
/// replace the final fail-closed return.  Preflight validates the opaque
/// capability before inspecting attacker-controlled proof bytes.
#[cfg(test)]
pub(super) fn verify_and_consume_direct_relation_use_v1(
    capability: VerifiedPersistentWitnessDirectRelationUseV1,
    _proof_bytes: &[u8],
) -> Result<VerifiedDirectRelationProofReceiptV1, ZkAmsMkheErrorV1> {
    capability.validate()?;
    Err(ZkAmsMkheErrorV1::ReleaseUnavailable)
}
/// Sole production minting boundary for a collective party's persistent secret.
///
/// The input is move-only and can only be produced by the complete native CPK
/// verifier after membership, streamed RNS equations, authentication, direct
/// object reads, and transcript replay all succeed together.  Raw state-secret
/// coefficients and caller-supplied digests are not accepted by this API.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn mint_collective_secret_binding_from_verified_cpk_v1(
    roster: &ZkAmsMkheGovernedActiveRosterV1,
    cpk_transcript_digest: [u8; 32],
    party_index: usize,
    cpk_share_digest: [u8; 32],
    source: VerifiedZkAmsMkheCpkBindingSourceV1,
) -> Result<VerifiedPersistentWitnessBindingV1, ZkAmsMkheErrorV1> {
    roster.validate()?;
    if cpk_transcript_digest == [0; 32]
        || cpk_share_digest == [0; 32]
        || party_index >= ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1
        || source.profile_digest() != roster.profile_digest()
        || source.security_certificate_digest() == [0; 32]
        || source.roster_digest() != roster.roster_digest()
        || source.key_material_digest() != roster.key_material_digest()
        || source.epoch() != roster.epoch()
        || source.cpk_transcript_digest() != cpk_transcript_digest
        || source.party_index() != party_index
        || source.party() != roster.participants()[party_index].party()
        || source.party_b_payload_blake3() == [0; 32]
        || source.relation_verification_digest() == [0; 32]
    {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    VerifiedPersistentWitnessBindingV1::from_verified_membership(
        roster,
        source.security_certificate_digest(),
        cpk_transcript_digest,
        party_index,
        cpk_share_digest,
        0,
        ExactMembershipVerificationReceiptV1 {
            role: PersistentWitnessRoleV1::SecretEpoch,
            source_context_digest: [0; 32],
            source_statement_digest: [0; 32],
            generator_basis_digest: source.generator_basis_digest(),
            commitments: *source.commitments(),
            commitment_set_digest: source.commitment_set_digest(),
            membership_proof_digest: source.membership_proof_digest(),
            verifier_transcript_digest: source.verifier_transcript_digest(),
            source_verification_digest: source.relation_verification_digest(),
        },
    )
}
/// Test-only stand-in for the complete CPK verifier.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn mint_test_state_owned_collective_secret_binding_v1(
    roster: &ZkAmsMkheGovernedActiveRosterV1,
    security_certificate_digest: [u8; 32],
    cpk_transcript_digest: [u8; 32],
    party_index: usize,
    cpk_share_digest: [u8; 32],
    commitments: [Point; PERSISTENT_COMMITMENT_CHUNKS_V1],
) -> Result<VerifiedPersistentWitnessBindingV1, ZkAmsMkheErrorV1> {
    let commitment_set_digest =
        persistent_commitment_set_digest(ZK_AMS_T256_BP_GENERATOR_BASIS_DIGEST_V1, &commitments)?;
    let mut frame = Vec::new();
    frame.extend_from_slice(b"iroha.zk-ams.v1.mkhe.test-only-state-owned-cpk-binding");
    frame.extend_from_slice(&roster.roster_digest());
    frame.extend_from_slice(&roster.epoch().to_be_bytes());
    frame.extend_from_slice(
        &u32::try_from(party_index)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidPartySet)?
            .to_be_bytes(),
    );
    frame.extend_from_slice(&cpk_share_digest);
    frame.extend_from_slice(&commitment_set_digest);
    let membership_proof_digest = keccak256(&[frame.as_slice(), b".membership"].concat());
    let verifier_transcript_digest = keccak256(&[frame.as_slice(), b".transcript"].concat());
    let source_verification_digest = keccak256(&[frame.as_slice(), b".relation"].concat());
    VerifiedPersistentWitnessBindingV1::from_verified_membership(
        roster,
        security_certificate_digest,
        cpk_transcript_digest,
        party_index,
        cpk_share_digest,
        0,
        ExactMembershipVerificationReceiptV1 {
            role: PersistentWitnessRoleV1::SecretEpoch,
            source_context_digest: [0; 32],
            source_statement_digest: [0; 32],
            generator_basis_digest: ZK_AMS_T256_BP_GENERATOR_BASIS_DIGEST_V1,
            commitments,
            commitment_set_digest,
            membership_proof_digest,
            verifier_transcript_digest,
            source_verification_digest,
        },
    )
}
#[cfg(test)]
fn validate_membership_receipt(
    receipt: &ExactMembershipVerificationReceiptV1,
) -> Result<(), ZkAmsMkheErrorV1> {
    let source_wrapper_is_valid = match receipt.role {
        PersistentWitnessRoleV1::SecretEpoch => {
            receipt.source_context_digest == [0; 32] && receipt.source_statement_digest == [0; 32]
        }
        PersistentWitnessRoleV1::RkgEphemeral => {
            receipt.source_context_digest != [0; 32] && receipt.source_statement_digest != [0; 32]
        }
    };
    if !source_wrapper_is_valid
        || receipt.membership_proof_digest == [0; 32]
        || receipt.verifier_transcript_digest == [0; 32]
        || receipt.source_verification_digest == [0; 32]
    {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    validate_canonical_commitment_set(
        receipt.generator_basis_digest,
        &receipt.commitments,
        receipt.commitment_set_digest,
    )
}
#[cfg(test)]
fn validate_canonical_commitment_set(
    generator_basis_digest: [u8; 32],
    commitments: &[Point; PERSISTENT_COMMITMENT_CHUNKS_V1],
    expected_digest: [u8; 32],
) -> Result<(), ZkAmsMkheErrorV1> {
    if generator_basis_digest == [0; 32]
        || expected_digest == [0; 32]
        || commitments.iter().any(|point| point.is_identity())
        || persistent_commitment_set_digest(generator_basis_digest, commitments)? != expected_digest
    {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn persistent_commitment_set_digest(
    generator_basis_digest: [u8; 32],
    commitments: &[Point; PERSISTENT_COMMITMENT_CHUNKS_V1],
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let mut hash = Keccak256::new();
    hash.update(PERSISTENT_COMMITMENT_SET_DOMAIN_V1);
    hash.update(&generator_basis_digest);
    hash.update(
        &u32::try_from(WITNESS_CHUNK_COEFFICIENTS_V1)
            .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?
            .to_be_bytes(),
    );
    hash.update(&[PERSISTENT_COMMITMENT_CHUNKS_V1 as u8]);
    for (index, point) in commitments.iter().enumerate() {
        hash.update(
            &u32::try_from(index)
                .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?
                .to_be_bytes(),
        );
        hash.update(
            &point
                .to_non_identity_wire_bytes()
                .map_err(|_| ZkAmsMkheErrorV1::InvalidKeyMaterial)?,
        );
    }
    Ok(hash.finalize())
}
#[cfg(test)]
fn verified_binding_identity_digest(
    binding: &VerifiedPersistentWitnessBindingV1,
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    validate_canonical_commitment_set(
        binding.generator_basis_digest,
        &binding.commitments,
        binding.commitment_set_digest,
    )?;
    let mut hash = Keccak256::new();
    hash.update(PERSISTENT_IDENTITY_DOMAIN_V1);
    hash.update(&[binding.version]);
    hash.update(&binding.profile_digest);
    hash.update(&binding.security_certificate_digest);
    hash.update(&binding.roster_digest);
    hash.update(&binding.key_material_digest);
    hash.update(&binding.epoch.to_be_bytes());
    hash.update(&binding.cpk_transcript_digest);
    hash.update(&[binding.party_index]);
    hash.update(&binding.party.to_bytes());
    hash.update(&binding.cpk_share_digest);
    hash.update(&[binding.role as u8]);
    hash.update(&binding.record_index.to_be_bytes());
    if binding.role == PersistentWitnessRoleV1::RkgEphemeral {
        hash.update(&binding.source_context_digest);
        hash.update(&binding.source_statement_digest);
    }
    hash.update(&binding.generator_basis_digest);
    hash.update(&binding.commitment_set_digest);
    Ok(hash.finalize())
}
#[cfg(test)]
fn verified_binding_verification_digest(
    binding: &VerifiedPersistentWitnessBindingV1,
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    if binding.membership_proof_digest == [0; 32]
        || binding.verifier_transcript_digest == [0; 32]
        || binding.source_verification_digest == [0; 32]
    {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    let mut hash = Keccak256::new();
    hash.update(PERSISTENT_VERIFICATION_DOMAIN_V1);
    hash.update(&verified_binding_identity_digest(binding)?);
    hash.update(&binding.membership_proof_digest);
    hash.update(&binding.verifier_transcript_digest);
    hash.update(&binding.source_verification_digest);
    if binding.role == PersistentWitnessRoleV1::RkgEphemeral {
        hash.update(&binding.source_context_digest);
        hash.update(&binding.source_statement_digest);
    }
    hash.update(&[binding.consumer_mask]);
    Ok(hash.finalize())
}
#[cfg(test)]
fn verified_binding_set_root(
    set: &VerifiedPersistentWitnessBindingSetV1,
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let mut hash = Keccak256::new();
    hash.update(PERSISTENT_ORDERED_SET_DOMAIN_V1);
    hash.update(&set.profile_digest);
    hash.update(&set.security_certificate_digest);
    hash.update(&set.roster_digest);
    hash.update(&set.key_material_digest);
    hash.update(&set.epoch.to_be_bytes());
    hash.update(&set.cpk_transcript_digest);
    hash.update(&set.collective_public_key_digest);
    hash.update(&[ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 as u8]);
    for index in 0..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 {
        hash.update(
            &u32::try_from(index)
                .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?
                .to_be_bytes(),
        );
        hash.update(&set.parties[index].to_bytes());
        hash.update(&set.cpk_share_digests[index]);
        hash.update(&set.identity_digests[index]);
        hash.update(&set.generator_basis_digests[index]);
        hash.update(&set.commitment_set_digests[index]);
    }
    Ok(hash.finalize())
}
#[cfg(test)]
fn persistent_direct_relation_use_digest(
    capability: &VerifiedPersistentWitnessDirectRelationUseV1,
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    capability.selector.validate()?;
    let mut hash = Keccak256::new();
    hash.update(PERSISTENT_DIRECT_RELATION_USE_DOMAIN_V1);
    hash.update(&capability.binding_set_root);
    hash.update(&capability.collective_public_key_digest);
    hash.update(&[capability.party_index]);
    hash.update(&capability.party.to_bytes());
    hash.update(&capability.secret_identity_digest);
    hash.update(&capability.secret_generator_basis_digest);
    hash.update(&capability.secret_commitment_set_digest);
    hash.update(&capability.ephemeral_identity_digest);
    hash.update(&capability.ephemeral_commitment_set_digest);
    hash.update(&capability.ephemeral_source_context_digest);
    hash.update(&capability.ephemeral_source_statement_digest);
    hash.update(&capability.ephemeral_record_index.to_be_bytes());
    hash.update(&[capability.selector.relation as u8]);
    hash.update(&capability.selector.context_digest);
    hash.update(&capability.selector.prior_round_digest);
    hash.update(&[
        capability.selector.evaluated_key_ordinal,
        capability.selector.digit_index,
    ]);
    hash.update(&capability.selector.galois_exponent.to_be_bytes());
    for digest in [
        capability.selector.common_a_statement_digest,
        capability.selector.target_a_statement_digest,
        capability.selector.aggregate_h0_statement_digest,
        capability.selector.aggregate_h1_statement_digest,
        capability.selector.contribution_statement_digest,
        capability.selector.proof_commitment_transcript_digest,
    ] {
        hash.update(&digest);
    }
    for (role, points) in [
        (0_u8, Some(&capability.secret_commitments)),
        (1_u8, capability.ephemeral_commitments.as_ref()),
    ] {
        hash.update(&[role, u8::from(points.is_some())]);
        if let Some(points) = points {
            for (index, point) in points.iter().enumerate() {
                hash.update(
                    &u32::try_from(index)
                        .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?
                        .to_be_bytes(),
                );
                hash.update(
                    &point
                        .to_non_identity_wire_bytes()
                        .map_err(|_| ZkAmsMkheErrorV1::InvalidKeyMaterial)?,
                );
            }
        }
    }
    Ok(hash.finalize())
}
#[cfg(test)]
fn verified_direct_relation_receipt_digest(
    receipt: &VerifiedDirectRelationProofReceiptV1,
) -> [u8; 32] {
    let mut hash = Keccak256::new();
    hash.update(b"iroha.zk-ams.v1.mkhe.active-exact-small-binding.direct-relation-receipt");
    hash.update(&[receipt.relation as u8]);
    hash.update(&receipt.context_digest);
    hash.update(&receipt.prior_round_digest);
    hash.update(&[receipt.evaluated_key_ordinal, receipt.digit_index]);
    hash.update(&receipt.galois_exponent.to_be_bytes());
    hash.update(&[receipt.party_index]);
    hash.update(&receipt.party.to_bytes());
    hash.update(&receipt.secret_identity_digest);
    hash.update(&receipt.ephemeral_identity_digest);
    hash.update(&receipt.contribution_statement_digest);
    hash.update(&receipt.relation_use_digest);
    hash.update(&receipt.proof_digest);
    hash.update(&receipt.verifier_transcript_digest);
    hash.update(&receipt.evidence_set_digest);
    hash.finalize()
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactBindingTranscriptContextV1 {
    profile_digest: [u8; 32],
    roster_digest: [u8; 32],
    key_material_digest: [u8; 32],
    epoch: u64,
    protocol_transcript_digest: [u8; 32],
    round_tag: u8,
    party_index: u8,
    party: [u8; 32],
    record_index: u32,
    relation_index: u32,
    statement_digest: [u8; 32],
    commitment_set_digest: [u8; 32],
    membership_proof_set_digest: [u8; 32],
    persistent_graph_digest: [u8; 32],
}
#[cfg(test)]
impl ExactBindingTranscriptContextV1 {
    fn validate(self) -> Result<(), ZkAmsMkheErrorV1> {
        if self.profile_digest == [0; 32]
            || self.roster_digest == [0; 32]
            || self.key_material_digest == [0; 32]
            || self.epoch == 0
            || self.protocol_transcript_digest == [0; 32]
            || self.round_tag == 0
            || usize::from(self.party_index) >= 8
            || self.party == [0; 32]
            || self.statement_digest == [0; 32]
            || self.commitment_set_digest == [0; 32]
            || self.membership_proof_set_digest == [0; 32]
            || self.persistent_graph_digest == [0; 32]
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactBindingAuditV1 {
    ring_degree: u32,
    max_relation_witnesses: u8,
    witness_chunk_coefficients: u32,
    chunks_per_witness: u8,
    max_chunk_commitments: u8,
    challenge_repetitions: u8,
    challenge_bits_per_repetition: u8,
    joint_challenge_bits: u16,
    max_challenge: u64,
    max_witness_coefficient: i64,
    challenge_shift_bound: i64,
    mask_coefficient_bound: i64,
    response_coefficient_bound: i64,
    max_fork_integer_lift_difference: i64,
    minimum_rns_modulus: u64,
    response_coordinates_per_attempt: u64,
    outer_retry_ceiling: u16,
    outer_retry_exhaustion_bits: u16,
    integer_sampler_retry_ceiling: u16,
    integer_sampler_union_exhaustion_bits: u16,
    response_payload_bytes: u64,
    blind_response_payload_bytes: u64,
    chunk_commitment_payload_bytes: u64,
    bound_one_gates_per_chunk: u32,
    bound_two_gates_per_chunk: u32,
    bound_one_constraints_per_chunk: u32,
    bound_two_constraints_per_chunk: u32,
    bound_one_membership_core_bytes: u32,
    bound_two_membership_core_bytes: u32,
    max_membership_core_payload_bytes: u64,
    known_payload_lower_bound_bytes: u64,
    governed_proof_ceiling_bytes: u64,
    unallocated_proof_headroom_bytes: u64,
    persistent_commitment_point_bytes: u32,
    persistent_blinding_state_bytes: u32,
    persistent_bound_one_membership_core_bytes: u32,
    secret_consumer_mask: u8,
    ephemeral_consumer_mask: u8,
    unchunked_scalar_vector_lower_bound_bytes: u64,
    chunked_scalar_vector_lower_bound_bytes: u64,
    governed_workspace_ceiling_bytes: u64,
    exact_common_box_hiding_certified: bool,
    retry_timing_distribution_witness_independent: bool,
    integer_sampler_unbiased: bool,
    signed_t256_lift_certified: bool,
    fork_difference_invertible_in_every_rns_limb: bool,
    membership_constraint_sets_exact: bool,
    persistent_graph_specified: bool,
    t256_membership_backend_implemented: bool,
    generator_basis_kat_pinned: bool,
    external_commitment_provenance_certified: bool,
    full_basis_mrep_crs_certified: bool,
    membership_argument_of_knowledge_certified: bool,
    membership_zero_knowledge_certified: bool,
    composite_rom_forking_certified: bool,
    full_ceremony_10_336_instance_composition_certified: bool,
    canonical_complete_wire_certified: bool,
    chunked_workspace_certified: bool,
    sampler_wired_to_runtime: bool,
    persistent_graph_wired_to_runtime: bool,
    split_decryption_wide_relation_certified: bool,
    release_kat_pinned: bool,
    blocker_mask: u16,
    release_available: bool,
    digest: [u8; 32],
}
fn exact_binding_audit_v1(profile: &BgvProfile) -> Result<ExactBindingAuditV1, ZkAmsMkheErrorV1> {
    require_release_profile_shape(profile)?;
    let exact_common_box_hiding_certified = true;
    let retry_timing_distribution_witness_independent = true;
    let integer_sampler_unbiased = true;
    let signed_t256_lift_certified = MAX_FORK_INTEGER_LIFT_DIFFERENCE_V1 < (1_i64 << 58)
        && RESPONSE_COEFFICIENT_BOUND_V1 < ((MINIMUM_RELEASE_RNS_MODULUS_V1 - 1) / 2) as i64;
    let fork_difference_invertible_in_every_rns_limb = profile
        .moduli
        .iter()
        .all(|modulus| *modulus > MAX_CHALLENGE_V1);
    let membership_constraint_sets_exact = true;
    let persistent_graph_specified = true;
    // The native T256 membership backend and its release generator basis are
    // now implemented and consumed by the complete CPK relation.  Keep every
    // downstream direct-relation/runtime/evidence obligation independent:
    // these two facts alone cannot open an operational path.
    let t256_membership_backend_implemented = ZK_AMS_T256_BP_GENERATOR_BASIS_DIGEST_V1 != [0; 32];
    let generator_basis_kat_pinned = ZK_AMS_T256_BP_GENERATOR_BASIS_DIGEST_V1 != [0; 32];
    // The standalone game-based precursor records why these obligations are
    // necessary. It is neither a proof nor a certificate, so every security
    // gate stays independently false. In particular, a straight-line AGM
    // route is not available to a later independent prover that receives an
    // opaque external commitment without creator-side algebraic provenance.
    let external_commitment_provenance_certified = false;
    let full_basis_mrep_crs_certified = false;
    let membership_argument_of_knowledge_certified = false;
    let membership_zero_knowledge_certified = false;
    let composite_rom_forking_certified = false;
    let full_ceremony_10_336_instance_composition_certified = false;
    let t256_membership_security_certified = t256_membership_backend_implemented
        && external_commitment_provenance_certified
        && full_basis_mrep_crs_certified
        && membership_argument_of_knowledge_certified
        && membership_zero_knowledge_certified
        && composite_rom_forking_certified
        && full_ceremony_10_336_instance_composition_certified;
    let canonical_complete_wire_certified = false;
    let chunked_workspace_certified = false;
    let sampler_wired_to_runtime = false;
    let persistent_graph_wired_to_runtime = false;
    let split_decryption_wide_relation_certified = false;
    let release_kat_pinned = false;
    let mut blocker_mask = 0_u16;
    for (complete, blocker) in [
        (
            t256_membership_security_certified,
            BLOCKER_T256_MEMBERSHIP_SECURITY_V1,
        ),
        (generator_basis_kat_pinned, BLOCKER_GENERATOR_BASIS_KAT_V1),
        (canonical_complete_wire_certified, BLOCKER_CANONICAL_WIRE_V1),
        (chunked_workspace_certified, BLOCKER_WORKSPACE_LEDGER_V1),
        (
            sampler_wired_to_runtime,
            BLOCKER_SAMPLER_RUNTIME_INTEGRATION_V1,
        ),
        (
            persistent_graph_wired_to_runtime,
            BLOCKER_PERSISTENT_GRAPH_RUNTIME_V1,
        ),
        (
            split_decryption_wide_relation_certified,
            BLOCKER_SPLIT_DECRYPTION_WIDE_RELATION_V1,
        ),
        (release_kat_pinned, BLOCKER_RELEASE_KAT_V1),
    ] {
        if !complete {
            blocker_mask |= blocker;
        }
    }
    let release_available = exact_common_box_hiding_certified
        && retry_timing_distribution_witness_independent
        && integer_sampler_unbiased
        && signed_t256_lift_certified
        && fork_difference_invertible_in_every_rns_limb
        && membership_constraint_sets_exact
        && persistent_graph_specified
        && t256_membership_backend_implemented
        && generator_basis_kat_pinned
        && external_commitment_provenance_certified
        && full_basis_mrep_crs_certified
        && membership_argument_of_knowledge_certified
        && membership_zero_knowledge_certified
        && composite_rom_forking_certified
        && full_ceremony_10_336_instance_composition_certified
        && canonical_complete_wire_certified
        && chunked_workspace_certified
        && sampler_wired_to_runtime
        && persistent_graph_wired_to_runtime
        && split_decryption_wide_relation_certified
        && release_kat_pinned;
    let mut audit = ExactBindingAuditV1 {
        ring_degree: as_u32(RELEASE_RING_DEGREE_V1)?,
        max_relation_witnesses: as_u8(MAX_RELATION_WITNESSES_V1)?,
        witness_chunk_coefficients: as_u32(WITNESS_CHUNK_COEFFICIENTS_V1)?,
        chunks_per_witness: as_u8(CHUNKS_PER_WITNESS_V1)?,
        max_chunk_commitments: as_u8(MAX_CHUNK_COMMITMENTS_V1)?,
        challenge_repetitions: as_u8(CHALLENGE_REPETITIONS_V1)?,
        challenge_bits_per_repetition: as_u8(CHALLENGE_BITS_PER_REPETITION_V1)?,
        joint_challenge_bits: as_u16(JOINT_CHALLENGE_BITS_V1)?,
        max_challenge: MAX_CHALLENGE_V1,
        max_witness_coefficient: MAX_WITNESS_COEFFICIENT_V1,
        challenge_shift_bound: CHALLENGE_SHIFT_BOUND_V1,
        mask_coefficient_bound: MASK_COEFFICIENT_BOUND_V1,
        response_coefficient_bound: RESPONSE_COEFFICIENT_BOUND_V1,
        max_fork_integer_lift_difference: MAX_FORK_INTEGER_LIFT_DIFFERENCE_V1,
        minimum_rns_modulus: MINIMUM_RELEASE_RNS_MODULUS_V1,
        response_coordinates_per_attempt: as_u64(WHOLE_ATTEMPT_RESPONSE_COORDINATES_V1)?,
        outer_retry_ceiling: as_u16(OUTER_RETRY_CEILING_V1)?,
        outer_retry_exhaustion_bits: as_u16(OUTER_RETRY_EXHAUSTION_BITS_V1)?,
        integer_sampler_retry_ceiling: as_u16(INTEGER_SAMPLER_RETRY_CEILING_V1)?,
        integer_sampler_union_exhaustion_bits: as_u16(INTEGER_SAMPLER_UNION_EXHAUSTION_BITS_V1)?,
        response_payload_bytes: as_u64(RESPONSE_PAYLOAD_BYTES_V1)?,
        blind_response_payload_bytes: as_u64(BLIND_RESPONSE_PAYLOAD_BYTES_V1)?,
        chunk_commitment_payload_bytes: as_u64(CHUNK_COMMITMENT_PAYLOAD_BYTES_V1)?,
        bound_one_gates_per_chunk: as_u32(BOUND_ONE_GATES_PER_CHUNK_V1)?,
        bound_two_gates_per_chunk: as_u32(BOUND_TWO_GATES_PER_CHUNK_V1)?,
        bound_one_constraints_per_chunk: as_u32(BOUND_ONE_CONSTRAINTS_PER_CHUNK_V1)?,
        bound_two_constraints_per_chunk: as_u32(BOUND_TWO_CONSTRAINTS_PER_CHUNK_V1)?,
        bound_one_membership_core_bytes: as_u32(BOUND_ONE_MEMBERSHIP_CORE_BYTES_V1)?,
        bound_two_membership_core_bytes: as_u32(BOUND_TWO_MEMBERSHIP_CORE_BYTES_V1)?,
        max_membership_core_payload_bytes: as_u64(MAX_MEMBERSHIP_CORE_PAYLOAD_BYTES_V1)?,
        known_payload_lower_bound_bytes: as_u64(KNOWN_PAYLOAD_LOWER_BOUND_BYTES_V1)?,
        governed_proof_ceiling_bytes: as_u64(ZK_AMS_MKHE_MAX_PROOF_BYTES_V1)?,
        unallocated_proof_headroom_bytes: as_u64(KNOWN_PAYLOAD_HEADROOM_BYTES_V1)?,
        persistent_commitment_point_bytes: as_u32(PERSISTENT_COMMITMENT_POINT_BYTES_V1)?,
        persistent_blinding_state_bytes: as_u32(PERSISTENT_COMMITMENT_BLINDING_STATE_BYTES_V1)?,
        persistent_bound_one_membership_core_bytes: as_u32(
            PERSISTENT_BOUND_ONE_MEMBERSHIP_CORE_BYTES_V1,
        )?,
        secret_consumer_mask: SECRET_REQUIRED_CONSUMERS_V1,
        ephemeral_consumer_mask: EPHEMERAL_REQUIRED_CONSUMERS_V1,
        unchunked_scalar_vector_lower_bound_bytes: as_u64(
            UNCHUNKED_SCALAR_VECTOR_LOWER_BOUND_BYTES_V1,
        )?,
        chunked_scalar_vector_lower_bound_bytes: as_u64(
            CHUNKED_SCALAR_VECTOR_LOWER_BOUND_BYTES_V1,
        )?,
        governed_workspace_ceiling_bytes: as_u64(GOVERNED_WORKSPACE_CEILING_BYTES_V1)?,
        exact_common_box_hiding_certified,
        retry_timing_distribution_witness_independent,
        integer_sampler_unbiased,
        signed_t256_lift_certified,
        fork_difference_invertible_in_every_rns_limb,
        membership_constraint_sets_exact,
        persistent_graph_specified,
        t256_membership_backend_implemented,
        generator_basis_kat_pinned,
        external_commitment_provenance_certified,
        full_basis_mrep_crs_certified,
        membership_argument_of_knowledge_certified,
        membership_zero_knowledge_certified,
        composite_rom_forking_certified,
        full_ceremony_10_336_instance_composition_certified,
        canonical_complete_wire_certified,
        chunked_workspace_certified,
        sampler_wired_to_runtime,
        persistent_graph_wired_to_runtime,
        split_decryption_wide_relation_certified,
        release_kat_pinned,
        blocker_mask,
        release_available,
        digest: [0; 32],
    };
    audit.digest = audit_digest(audit);
    Ok(audit)
}
/// Compact release state consumed by the canonical MKHE readiness compiler.
///
/// This does not expose partially verified proof artifacts. It reports only
/// the digest-bound result of the complete fail-closed audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ZkAmsMkheActiveExactBindingReleaseStateV1 {
    /// Exact open-blocker bit set.
    pub(super) blocker_mask: u16,
    /// Whether every external commitment has extractor-visible provenance.
    pub(super) external_commitment_provenance_certified: bool,
    /// Whether the full T256 basis and its CRS model have a reviewed MRep bound.
    pub(super) full_basis_mrep_crs_certified: bool,
    /// Whether the exact external-commitment membership proof is an AoK.
    pub(super) membership_argument_of_knowledge_certified: bool,
    /// Whether the exact external-commitment membership proof is ZK.
    pub(super) membership_zero_knowledge_certified: bool,
    /// Whether the seed-plus-four-coordinate ROM fork is certified.
    pub(super) composite_rom_forking_certified: bool,
    /// Whether the fixed 10,336-proof composition is certified.
    pub(super) full_ceremony_10_336_instance_composition_certified: bool,
    /// Whether split decryption reuses the exact persistent secret binding.
    pub(super) split_decryption_wide_relation_certified: bool,
    /// Whether every exact-binding obligation has closed together.
    pub(super) release_available: bool,
    /// Digest of the complete underlying audit.
    pub(super) audit_digest: [u8; 32],
}
/// Evaluate the exact-binding proof state for one governed profile.
pub(super) fn exact_binding_release_state_v1(
    profile: &BgvProfile,
) -> Result<ZkAmsMkheActiveExactBindingReleaseStateV1, ZkAmsMkheErrorV1> {
    let audit = exact_binding_audit_v1(profile)?;
    Ok(ZkAmsMkheActiveExactBindingReleaseStateV1 {
        blocker_mask: audit.blocker_mask,
        external_commitment_provenance_certified: audit.external_commitment_provenance_certified,
        full_basis_mrep_crs_certified: audit.full_basis_mrep_crs_certified,
        membership_argument_of_knowledge_certified: audit
            .membership_argument_of_knowledge_certified,
        membership_zero_knowledge_certified: audit.membership_zero_knowledge_certified,
        composite_rom_forking_certified: audit.composite_rom_forking_certified,
        full_ceremony_10_336_instance_composition_certified: audit
            .full_ceremony_10_336_instance_composition_certified,
        split_decryption_wide_relation_certified: audit.split_decryption_wide_relation_certified,
        release_available: audit.release_available,
        audit_digest: audit.digest,
    })
}
#[cfg(test)]
fn sample_exact_uniform_signed_box<R: MaskedRelaxedRandomSourceV1>(
    random: &mut R,
    bound: i64,
) -> Result<i64, ZkAmsMkheErrorV1> {
    if bound <= 0 || bound > MASK_COEFFICIENT_BOUND_V1 {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    let bound = u128::try_from(bound).map_err(|_| ZkAmsMkheErrorV1::InvalidKeyMaterial)?;
    let width = bound
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    // `wrapping_neg(width) == 2^128-width`; reducing it modulo `width`
    // yields `2^128 mod width`.  Every value at or above this threshold lies
    // in an interval whose cardinality is an exact multiple of `width`.
    let threshold = width.wrapping_neg() % width;
    for _ in 0..INTEGER_SAMPLER_RETRY_CEILING_V1 {
        let mut bytes = [0_u8; 16];
        random
            .fill_bytes(&mut bytes)
            .map_err(|_| ZkAmsMkheErrorV1::RandomUnavailable)?;
        let sample = u128::from_be_bytes(bytes);
        bytes.fill(0);
        if sample < threshold {
            continue;
        }
        let residue = sample % width;
        let signed = i128::try_from(residue)
            .ok()
            .and_then(|value| value.checked_sub(i128::try_from(bound).ok()?))
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
        return Ok(signed);
    }
    Err(ZkAmsMkheErrorV1::RandomUnavailable)
}
#[cfg(test)]
fn signed_response_to_t256(response: i64, bound: i64) -> Result<Scalar, ZkAmsMkheErrorV1> {
    if bound <= 0 || response.unsigned_abs() > bound as u64 {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    let magnitude = Scalar::from_u64(response.unsigned_abs());
    Ok(if response < 0 { -magnitude } else { magnitude })
}
#[cfg(test)]
fn bound_one_constraint_value(positive: u8, negative: u8) -> Option<i64> {
    ([positive, negative].iter().all(|bit| *bit <= 1))
        .then_some(i64::from(positive) - i64::from(negative))
}
#[cfg(test)]
fn bound_two_constraint_value(low: u8, high: u8, negative_two: u8) -> Option<i64> {
    ([low, high, negative_two].iter().all(|bit| *bit <= 1))
        .then_some(i64::from(low) + i64::from(high) - 2 * i64::from(negative_two))
}
#[cfg(test)]
fn is_exact_small_member(value: i64, bound: i64) -> bool {
    match bound {
        1 => (-1..=1).contains(&value),
        2 => (-2..=2).contains(&value),
        _ => false,
    }
}
#[cfg(test)]
fn challenge_vector(
    context: ExactBindingTranscriptContextV1,
    rns_first_message_digests: [[u8; 32]; CHALLENGE_REPETITIONS_V1],
    commitment_first_message_digests: [[u8; 32]; CHALLENGE_REPETITIONS_V1],
) -> Result<([u8; 32], [u32; CHALLENGE_REPETITIONS_V1]), ZkAmsMkheErrorV1> {
    context.validate()?;
    if rns_first_message_digests
        .iter()
        .chain(commitment_first_message_digests.iter())
        .any(|digest| *digest == [0; 32])
    {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    let mut frame = Vec::with_capacity(1_024);
    frame.extend_from_slice(CHALLENGE_VECTOR_DOMAIN_V1);
    frame.extend_from_slice(&context.profile_digest);
    frame.extend_from_slice(&context.roster_digest);
    frame.extend_from_slice(&context.key_material_digest);
    frame.extend_from_slice(&context.epoch.to_be_bytes());
    frame.extend_from_slice(&context.protocol_transcript_digest);
    frame.push(context.round_tag);
    frame.push(context.party_index);
    frame.extend_from_slice(&context.party);
    frame.extend_from_slice(&context.record_index.to_be_bytes());
    frame.extend_from_slice(&context.relation_index.to_be_bytes());
    frame.extend_from_slice(&context.statement_digest);
    frame.extend_from_slice(&context.commitment_set_digest);
    frame.extend_from_slice(&context.membership_proof_set_digest);
    frame.extend_from_slice(&context.persistent_graph_digest);
    for ordinal in 0..CHALLENGE_REPETITIONS_V1 {
        frame.push(ordinal as u8);
        frame.extend_from_slice(&rns_first_message_digests[ordinal]);
        frame.extend_from_slice(&commitment_first_message_digests[ordinal]);
    }
    let seed = keccak256(&frame);
    let challenges = core::array::from_fn(|ordinal| {
        let mut coordinate = Vec::with_capacity(CHALLENGE_COORDINATE_DOMAIN_V1.len() + 33);
        coordinate.extend_from_slice(CHALLENGE_COORDINATE_DOMAIN_V1);
        coordinate.extend_from_slice(&seed);
        coordinate.push(ordinal as u8);
        let digest = keccak256(&coordinate);
        u32::from_be_bytes(digest[..4].try_into().expect("four-byte challenge prefix"))
    });
    Ok((seed, challenges))
}
#[cfg(test)]
fn persistent_identity_digest(identity: PersistentCommitmentIdentityV1) -> [u8; 32] {
    let mut frame = Vec::with_capacity(PERSISTENT_IDENTITY_DOMAIN_V1.len() + 256);
    frame.extend_from_slice(PERSISTENT_IDENTITY_DOMAIN_V1);
    frame.extend_from_slice(&identity.profile_digest);
    frame.extend_from_slice(&identity.roster_digest);
    frame.extend_from_slice(&identity.key_material_digest);
    frame.extend_from_slice(&identity.epoch.to_be_bytes());
    frame.extend_from_slice(&identity.party);
    frame.push(identity.role as u8);
    frame.extend_from_slice(&identity.record_index.to_be_bytes());
    frame.extend_from_slice(&identity.commitment_set_digest);
    frame.extend_from_slice(&identity.membership_proof_digest);
    frame.push(identity.consumer_mask);
    keccak256(&frame)
}
fn audit_digest(audit: ExactBindingAuditV1) -> [u8; 32] {
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Release,
        AUDIT_DIGEST_DOMAIN_V1,
        39,
    );
    hash.push_field(&audit.ring_degree.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[
        audit.max_relation_witnesses,
        audit.chunks_per_witness,
        audit.max_chunk_commitments,
        audit.challenge_repetitions,
        audit.challenge_bits_per_repetition,
    ])
    .expect("fixed bounded MKHE identity field");
    hash.push_field(&audit.witness_chunk_coefficients.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&audit.joint_challenge_bits.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&audit.max_challenge.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    for value in [
        audit.max_witness_coefficient,
        audit.challenge_shift_bound,
        audit.mask_coefficient_bound,
        audit.response_coefficient_bound,
        audit.max_fork_integer_lift_difference,
    ] {
        hash.push_field(&value.to_be_bytes())
            .expect("fixed bounded MKHE identity field");
    }
    hash.push_field(&audit.minimum_rns_modulus.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&audit.response_coordinates_per_attempt.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    for value in [
        audit.outer_retry_ceiling,
        audit.outer_retry_exhaustion_bits,
        audit.integer_sampler_retry_ceiling,
        audit.integer_sampler_union_exhaustion_bits,
    ] {
        hash.push_field(&value.to_be_bytes())
            .expect("fixed bounded MKHE identity field");
    }
    for value in [
        audit.response_payload_bytes,
        audit.blind_response_payload_bytes,
        audit.chunk_commitment_payload_bytes,
        audit.max_membership_core_payload_bytes,
        audit.known_payload_lower_bound_bytes,
        audit.governed_proof_ceiling_bytes,
        audit.unallocated_proof_headroom_bytes,
        audit.unchunked_scalar_vector_lower_bound_bytes,
        audit.chunked_scalar_vector_lower_bound_bytes,
        audit.governed_workspace_ceiling_bytes,
    ] {
        hash.push_field(&value.to_be_bytes())
            .expect("fixed bounded MKHE identity field");
    }
    for value in [
        audit.bound_one_gates_per_chunk,
        audit.bound_two_gates_per_chunk,
        audit.bound_one_constraints_per_chunk,
        audit.bound_two_constraints_per_chunk,
        audit.bound_one_membership_core_bytes,
        audit.bound_two_membership_core_bytes,
        audit.persistent_commitment_point_bytes,
        audit.persistent_blinding_state_bytes,
        audit.persistent_bound_one_membership_core_bytes,
    ] {
        hash.push_field(&value.to_be_bytes())
            .expect("fixed bounded MKHE identity field");
    }
    hash.push_field(&[audit.secret_consumer_mask, audit.ephemeral_consumer_mask])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[
        audit.exact_common_box_hiding_certified.into(),
        audit.retry_timing_distribution_witness_independent.into(),
        audit.integer_sampler_unbiased.into(),
        audit.signed_t256_lift_certified.into(),
        audit.fork_difference_invertible_in_every_rns_limb.into(),
        audit.membership_constraint_sets_exact.into(),
        audit.persistent_graph_specified.into(),
        audit.t256_membership_backend_implemented.into(),
        audit.generator_basis_kat_pinned.into(),
        audit.external_commitment_provenance_certified.into(),
        audit.full_basis_mrep_crs_certified.into(),
        audit.membership_argument_of_knowledge_certified.into(),
        audit.membership_zero_knowledge_certified.into(),
        audit.composite_rom_forking_certified.into(),
        audit
            .full_ceremony_10_336_instance_composition_certified
            .into(),
        audit.canonical_complete_wire_certified.into(),
        audit.chunked_workspace_certified.into(),
        audit.sampler_wired_to_runtime.into(),
        audit.persistent_graph_wired_to_runtime.into(),
        audit.split_decryption_wide_relation_certified.into(),
        audit.release_kat_pinned.into(),
    ])
    .expect("fixed bounded MKHE identity field");
    hash.push_field(&audit.blocker_mask.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[audit.release_available.into()])
        .expect("fixed bounded MKHE identity field");
    *hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes()
}
fn require_release_profile_shape(profile: &BgvProfile) -> Result<(), ZkAmsMkheErrorV1> {
    profile.validate()?;
    if profile.ring_degree != RELEASE_RING_DEGREE_V1
        || profile.plaintext_modulus != PlaintextModulus::T256
        || profile.error_eta != 2
        || profile.moduli.len() != 38
        || profile.moduli.iter().copied().min() != Some(MINIMUM_RELEASE_RNS_MODULUS_V1)
        || profile.max_workspace_bytes != GOVERNED_WORKSPACE_CEILING_BYTES_V1
    {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    Ok(())
}
#[cfg(test)]
fn preflight_exact_binding_v1(profile: &BgvProfile) -> Result<Infallible, ZkAmsMkheErrorV1> {
    let audit = exact_binding_audit_v1(profile)?;
    debug_assert!(!audit.release_available);
    Err(ZkAmsMkheErrorV1::ReleaseUnavailable)
}
#[cfg(test)]
fn decode_exact_binding_proof_v1(
    profile: &BgvProfile,
    _attacker_bytes: &[u8],
) -> Result<Infallible, ZkAmsMkheErrorV1> {
    preflight_exact_binding_v1(profile)
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
    use crate::vega::{
        MaskedRelaxedRandomErrorV1, VEGA_T256_SCALAR_MODULUS_BE_V1, derive_t256_generators_v1,
        zk_ams::mkhe::active::ZkAmsMkheActivePartySecretV1,
        zk_ams::mkhe::manifest::release_profile_v1,
    };
    #[derive(Clone)]
    struct BlockRandom {
        blocks: Vec<[u8; 16]>,
        cursor: usize,
    }
    impl BlockRandom {
        fn new(blocks: Vec<[u8; 16]>) -> Self {
            Self { blocks, cursor: 0 }
        }
    }
    impl MaskedRelaxedRandomSourceV1 for BlockRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), MaskedRelaxedRandomErrorV1> {
            let block = self
                .blocks
                .get(self.cursor)
                .ok_or(MaskedRelaxedRandomErrorV1::Unavailable)?;
            if destination.len() != block.len() {
                return Err(MaskedRelaxedRandomErrorV1::Unavailable);
            }
            destination.copy_from_slice(block);
            self.cursor += 1;
            Ok(())
        }
    }
    struct StreamRandom {
        seed: Vec<u8>,
        counter: u64,
    }
    impl StreamRandom {
        fn new(seed: &[u8]) -> Self {
            Self {
                seed: seed.to_vec(),
                counter: 0,
            }
        }
    }
    impl MaskedRelaxedRandomSourceV1 for StreamRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), MaskedRelaxedRandomErrorV1> {
            let mut written = 0;
            while written < destination.len() {
                let mut frame = self.seed.clone();
                frame.extend_from_slice(&self.counter.to_be_bytes());
                let block = keccak256(&frame);
                let take = (destination.len() - written).min(block.len());
                destination[written..written + take].copy_from_slice(&block[..take]);
                written += take;
                self.counter = self.counter.wrapping_add(1);
            }
            Ok(())
        }
    }
    fn governed_roster_fixture(
        label: &[u8],
    ) -> (
        ZkAmsMkheGovernedActiveRosterV1,
        Vec<ZkAmsMkheActivePartySecretV1>,
    ) {
        let mut random = StreamRandom::new(label);
        let mut secrets = (0..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1)
            .map(|_| ZkAmsMkheActivePartySecretV1::generate(&mut random).unwrap())
            .collect::<Vec<_>>();
        secrets.sort_by_key(|secret| secret.party().unwrap());
        let references: [&ZkAmsMkheActivePartySecretV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1] =
            secrets.iter().collect::<Vec<_>>().try_into().unwrap();
        let roster = ZkAmsMkheGovernedActiveRosterV1::new(77, references, &mut random).unwrap();
        (roster, secrets)
    }
    fn membership_receipt_fixture(
        label: &[u8],
        proof_variant: u8,
    ) -> ExactMembershipVerificationReceiptV1 {
        let generator_basis_digest = keccak256(b"exact-binding-test-global-generator-basis");
        let commitments: [Point; PERSISTENT_COMMITMENT_CHUNKS_V1] =
            derive_t256_generators_v1(label, PERSISTENT_COMMITMENT_CHUNKS_V1)
                .unwrap()
                .try_into()
                .unwrap();
        let commitment_set_digest =
            persistent_commitment_set_digest(generator_basis_digest, &commitments).unwrap();
        let mut proof_frame = label.to_vec();
        proof_frame.extend_from_slice(b"-membership-proof");
        proof_frame.push(proof_variant);
        let mut transcript_frame = label.to_vec();
        transcript_frame.extend_from_slice(b"-verifier-transcript");
        transcript_frame.push(proof_variant);
        let mut relation_frame = label.to_vec();
        relation_frame.extend_from_slice(b"-complete-cpk-relation");
        relation_frame.push(proof_variant);
        ExactMembershipVerificationReceiptV1 {
            role: PersistentWitnessRoleV1::SecretEpoch,
            source_context_digest: [0; 32],
            source_statement_digest: [0; 32],
            generator_basis_digest,
            commitments,
            commitment_set_digest,
            membership_proof_digest: keccak256(&proof_frame),
            verifier_transcript_digest: keccak256(&transcript_frame),
            source_verification_digest: keccak256(&relation_frame),
        }
    }
    fn verified_binding_fixture(
        roster: &ZkAmsMkheGovernedActiveRosterV1,
        cpk_transcript_digest: [u8; 32],
        party_index: usize,
        cpk_share_digest: [u8; 32],
        label: &[u8],
        proof_variant: u8,
    ) -> VerifiedPersistentWitnessBindingV1 {
        VerifiedPersistentWitnessBindingV1::from_verified_membership(
            roster,
            keccak256(b"release-security-certificate"),
            cpk_transcript_digest,
            party_index,
            cpk_share_digest,
            0,
            membership_receipt_fixture(label, proof_variant),
        )
        .unwrap()
    }
    fn legacy_secret_binding_digests(
        binding: &VerifiedPersistentWitnessBindingV1,
    ) -> ([u8; 32], [u8; 32]) {
        let mut identity = Keccak256::new();
        identity.update(PERSISTENT_IDENTITY_DOMAIN_V1);
        identity.update(&[binding.version]);
        identity.update(&binding.profile_digest);
        identity.update(&binding.security_certificate_digest);
        identity.update(&binding.roster_digest);
        identity.update(&binding.key_material_digest);
        identity.update(&binding.epoch.to_be_bytes());
        identity.update(&binding.cpk_transcript_digest);
        identity.update(&[binding.party_index]);
        identity.update(&binding.party.to_bytes());
        identity.update(&binding.cpk_share_digest);
        identity.update(&[binding.role as u8]);
        identity.update(&binding.record_index.to_be_bytes());
        identity.update(&binding.generator_basis_digest);
        identity.update(&binding.commitment_set_digest);
        let identity = identity.finalize();
        let mut verification = Keccak256::new();
        verification.update(PERSISTENT_VERIFICATION_DOMAIN_V1);
        verification.update(&identity);
        verification.update(&binding.membership_proof_digest);
        verification.update(&binding.verifier_transcript_digest);
        verification.update(&binding.source_verification_digest);
        verification.update(&[binding.consumer_mask]);
        (identity, verification.finalize())
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "fixture mirrors the exact persistent-binding input axes"
    )]
    fn verified_ephemeral_binding_fixture(
        roster: &ZkAmsMkheGovernedActiveRosterV1,
        cpk_transcript_digest: [u8; 32],
        party_index: usize,
        cpk_share_digest: [u8; 32],
        basis_label: &[u8],
        record_index: u32,
        source_context_digest: [u8; 32],
        source_statement_digest: [u8; 32],
    ) -> VerifiedPersistentWitnessBindingV1 {
        let mut receipt = membership_receipt_fixture(basis_label, 9);
        receipt.role = PersistentWitnessRoleV1::RkgEphemeral;
        receipt.source_context_digest = source_context_digest;
        receipt.source_statement_digest = source_statement_digest;
        let mut commitment_label = basis_label.to_vec();
        commitment_label.extend_from_slice(b"-rkg-u");
        receipt.commitments =
            derive_t256_generators_v1(&commitment_label, PERSISTENT_COMMITMENT_CHUNKS_V1)
                .unwrap()
                .try_into()
                .unwrap();
        receipt.commitment_set_digest =
            persistent_commitment_set_digest(receipt.generator_basis_digest, &receipt.commitments)
                .unwrap();
        VerifiedPersistentWitnessBindingV1::from_verified_membership(
            roster,
            keccak256(b"release-security-certificate"),
            cpk_transcript_digest,
            party_index,
            cpk_share_digest,
            record_index,
            receipt,
        )
        .unwrap()
    }
    #[test]
    fn staged_binding_fork_preserves_both_validated_successors() {
        let (roster, _secrets) = governed_roster_fixture(b"exact-binding-fork-roster");
        let transcript = keccak256(b"exact-binding-fork-transcript");
        let share = keccak256(b"exact-binding-fork-share");
        let binding =
            verified_binding_fixture(&roster, transcript, 0, share, b"exact-binding-fork", 1);
        let identity = binding.identity_digest();
        let (state, verifier) = binding.fork_for_state_and_verifier_v1();
        for successor in [&state, &verifier] {
            successor
                .validate_for(
                    &roster,
                    transcript,
                    0,
                    share,
                    PersistentWitnessConsumerV1::Decryption,
                )
                .unwrap();
            assert_eq!(successor.identity_digest(), identity);
        }
    }
    #[test]
    fn release_audit_pins_exact_algebra_and_stays_closed() {
        let audit = exact_binding_audit_v1(&release_profile_v1()).unwrap();
        assert_eq!(audit.ring_degree, 131_072);
        assert_eq!(audit.max_relation_witnesses, 6);
        assert_eq!(audit.witness_chunk_coefficients, 16_384);
        assert_eq!(audit.chunks_per_witness, 8);
        assert_eq!(audit.max_chunk_commitments, 48);
        assert_eq!(audit.challenge_repetitions, 4);
        assert_eq!(audit.challenge_bits_per_repetition, 32);
        assert_eq!(audit.joint_challenge_bits, 128);
        assert_eq!(audit.challenge_shift_bound, 8_589_934_590);
        assert_eq!(audit.mask_coefficient_bound, 144_115_188_042_301_440);
        assert_eq!(audit.response_coefficient_bound, 144_115_179_452_366_850);
        assert_eq!(
            audit.max_fork_integer_lift_difference,
            288_230_367_494_668_290
        );
        assert!(audit.max_fork_integer_lift_difference < (1_i64 << 58));
        assert_eq!(audit.minimum_rns_modulus, 1_152_921_504_409_190_401);
        assert!(audit.exact_common_box_hiding_certified);
        assert!(audit.retry_timing_distribution_witness_independent);
        assert!(audit.integer_sampler_unbiased);
        assert!(audit.signed_t256_lift_certified);
        assert!(audit.fork_difference_invertible_in_every_rns_limb);
        assert!(audit.membership_constraint_sets_exact);
        assert!(audit.persistent_graph_specified);
        assert!(audit.t256_membership_backend_implemented);
        assert!(audit.generator_basis_kat_pinned);
        assert!(!audit.external_commitment_provenance_certified);
        assert!(!audit.full_basis_mrep_crs_certified);
        assert!(!audit.membership_argument_of_knowledge_certified);
        assert!(!audit.membership_zero_knowledge_certified);
        assert!(!audit.composite_rom_forking_certified);
        assert!(!audit.full_ceremony_10_336_instance_composition_certified);
        assert_eq!(
            audit.blocker_mask,
            ALL_RELEASE_BLOCKERS_V1 & !BLOCKER_GENERATOR_BASIS_KAT_V1
        );
        assert_eq!(audit.blocker_mask, 0xfd);
        assert!(!audit.release_available);
        assert_ne!(audit.digest, [0; 32]);
        let source = include_str!("active_exact_binding.rs");
        assert!(!source.contains(concat!("candidate_membership_union_", "soundness_bits")));
        assert!(!source.contains(concat!("BLOCKER_T256_MEMBERSHIP_", "BACKEND_V1")));
        for forged in [
            ExactBindingAuditV1 {
                t256_membership_backend_implemented: false,
                ..audit
            },
            ExactBindingAuditV1 {
                generator_basis_kat_pinned: false,
                ..audit
            },
            ExactBindingAuditV1 {
                external_commitment_provenance_certified: true,
                ..audit
            },
            ExactBindingAuditV1 {
                full_basis_mrep_crs_certified: true,
                ..audit
            },
            ExactBindingAuditV1 {
                membership_argument_of_knowledge_certified: true,
                ..audit
            },
            ExactBindingAuditV1 {
                membership_zero_knowledge_certified: true,
                ..audit
            },
            ExactBindingAuditV1 {
                composite_rom_forking_certified: true,
                ..audit
            },
            ExactBindingAuditV1 {
                full_ceremony_10_336_instance_composition_certified: true,
                ..audit
            },
            ExactBindingAuditV1 {
                blocker_mask: audit.blocker_mask ^ BLOCKER_CANONICAL_WIRE_V1,
                ..audit
            },
            ExactBindingAuditV1 {
                release_available: true,
                ..audit
            },
        ] {
            assert_ne!(audit_digest(forged), audit.digest);
        }
    }
    #[test]
    fn fixed_common_box_is_exactly_witness_and_challenge_independent() {
        // Exhaust a tiny analogue of the release construction.  Every
        // witness/challenge pair has the same accepted z support, exactly one
        // mask preimage for each z, and the same rejected-mask count.
        const C_MAX: i64 = 3;
        const W_MAX: i64 = 2;
        const SHIFT: i64 = C_MAX * W_MAX;
        const M: i64 = SHIFT * 4;
        const B: i64 = M - SHIFT;
        let expected = (-B..=B).collect::<Vec<_>>();
        for witness in -W_MAX..=W_MAX {
            for challenge in 0..=C_MAX {
                let mut accepted = Vec::new();
                let mut rejected = 0;
                for mask in -M..=M {
                    let response = mask + challenge * witness;
                    if (-B..=B).contains(&response) {
                        accepted.push(response);
                    } else {
                        rejected += 1;
                    }
                }
                accepted.sort_unstable();
                assert_eq!(accepted, expected);
                assert_eq!(rejected, 2 * SHIFT);
            }
        }
        assert_eq!(WHOLE_ATTEMPT_RESPONSE_COORDINATES_V1, 3 * (1 << 20));
        // p_coord < 2^-24 and D=3*2^20, hence D*p_coord < 3/16.
        assert_eq!(
            MASK_COEFFICIENT_BOUND_V1,
            CHALLENGE_SHIFT_BOUND_V1 * (1 << 24)
        );
        // 3^41 < 2^65 and 3^5 < 2^8 imply
        // 3^128=(3^41)^3*3^5 < 2^203.  Therefore
        // (3/16)^128 < 2^(203-512)=2^-309 without floating point.
        assert!(3_u128.pow(41) < (1_u128 << 65));
        assert!(3_u16.pow(5) < (1_u16 << 8));
        assert_eq!(OUTER_RETRY_EXHAUSTION_BITS_V1, 309);
    }
    #[test]
    fn integer_sampler_uses_exact_u128_rejection_zone_and_signed_range() {
        let bound = MASK_COEFFICIENT_BOUND_V1;
        let width = 2_u128 * bound as u128 + 1;
        let threshold = width.wrapping_neg() % width;
        assert!(threshold < width);
        // One value in the incomplete low prefix is rejected; the next
        // canonical block is accepted.  No modulo-reduced low-prefix bias is
        // possible.
        let rejected = threshold.saturating_sub(1).to_be_bytes();
        let accepted = threshold.to_be_bytes();
        let mut random = BlockRandom::new(vec![rejected, accepted]);
        let sampled = sample_exact_uniform_signed_box(&mut random, bound).unwrap();
        assert!((-bound..=bound).contains(&sampled));
        assert_eq!(random.cursor, if threshold == 0 { 1 } else { 2 });
        let mut unavailable = BlockRandom::new(Vec::new());
        assert_eq!(
            sample_exact_uniform_signed_box(&mut unavailable, bound),
            Err(ZkAmsMkheErrorV1::RandomUnavailable)
        );
        assert_eq!(INTEGER_SAMPLER_UNION_EXHAUSTION_BITS_V1, 8_800);
    }
    #[test]
    fn signed_t256_encoding_and_fork_lifts_are_unique() {
        for response in [
            -RESPONSE_COEFFICIENT_BOUND_V1,
            -1,
            0,
            1,
            RESPONSE_COEFFICIENT_BOUND_V1,
        ] {
            let scalar = signed_response_to_t256(response, RESPONSE_COEFFICIENT_BOUND_V1).unwrap();
            assert!(scalar.to_be_bytes() < VEGA_T256_SCALAR_MODULUS_BE_V1);
            assert_eq!(
                Scalar::from_be_bytes_exact(scalar.to_be_bytes()).unwrap(),
                scalar
            );
        }
        assert!(
            signed_response_to_t256(
                RESPONSE_COEFFICIENT_BOUND_V1 + 1,
                RESPONSE_COEFFICIENT_BOUND_V1
            )
            .is_err()
        );
        const { assert!(MAX_FORK_INTEGER_LIFT_DIFFERENCE_V1 < (1_i64 << 59)) };
        assert!(RESPONSE_COEFFICIENT_BOUND_V1 < ((MINIMUM_RELEASE_RNS_MODULUS_V1 - 1) / 2) as i64);
    }
    #[test]
    fn membership_constraints_have_exact_small_integer_images() {
        let mut bound_one = Vec::new();
        for positive in 0..=1 {
            for negative in 0..=1 {
                bound_one.push(bound_one_constraint_value(positive, negative).unwrap());
            }
        }
        bound_one.sort_unstable();
        bound_one.dedup();
        assert_eq!(bound_one, vec![-1, 0, 1]);
        let mut bound_two = Vec::new();
        for low in 0..=1 {
            for high in 0..=1 {
                for negative_two in 0..=1 {
                    bound_two.push(bound_two_constraint_value(low, high, negative_two).unwrap());
                }
            }
        }
        bound_two.sort_unstable();
        bound_two.dedup();
        assert_eq!(bound_two, vec![-2, -1, 0, 1, 2]);
        assert!(bound_one_constraint_value(2, 0).is_none());
        assert!(bound_two_constraint_value(0, 0, 2).is_none());
        // The scaled-language attack chooses a huge field representative that
        // satisfies a scalar equation after inversion.  Exact committed-set
        // membership rejects it before the linear proof is considered.
        for invalid in [-3, 3, i64::MAX] {
            assert!(!is_exact_small_member(invalid, 2));
        }
    }
    #[test]
    fn membership_core_wire_formula_comes_from_actual_ipa_round_counts() {
        assert_eq!(BOUND_ONE_PADDED_GATES_V1.ilog2(), 15);
        assert_eq!(BOUND_TWO_PADDED_GATES_V1.ilog2(), 16);
        assert_eq!(
            BOUND_ONE_MEMBERSHIP_CORE_BYTES_V1,
            (9 + 2 * 15) * 33 + 5 * 32
        );
        assert_eq!(
            BOUND_TWO_MEMBERSHIP_CORE_BYTES_V1,
            (9 + 2 * 16) * 33 + 5 * 32
        );
        assert_eq!(MAX_MEMBERSHIP_CORE_PAYLOAD_BYTES_V1, 71_568);
        assert_eq!(RESPONSE_PAYLOAD_BYTES_V1, 25_165_824);
        assert_eq!(BLIND_RESPONSE_PAYLOAD_BYTES_V1, 6_144);
        assert_eq!(CHUNK_COMMITMENT_PAYLOAD_BYTES_V1, 1_584);
        assert_eq!(KNOWN_PAYLOAD_LOWER_BOUND_BYTES_V1, 25_245_499);
        assert_eq!(KNOWN_PAYLOAD_HEADROOM_BYTES_V1, 8_308_933);
        // This is only a lower bound until canonical per-chunk and outer
        // framing is implemented; the audit must not promote it to a wire
        // certificate.
        let audit = exact_binding_audit_v1(&release_profile_v1()).unwrap();
        assert!(!audit.canonical_complete_wire_certified);
    }
    #[test]
    fn unchunked_existing_bp_allocation_pattern_already_breaks_memory_gate() {
        assert_eq!(UNCHUNKED_SCALAR_VECTOR_LOWER_BOUND_BYTES_V1, 218_103_808);
        const { assert!(UNCHUNKED_SCALAR_VECTOR_LOWER_BOUND_BYTES_V1 > 160 * 1024 * 1024) };
        assert_eq!(CHUNKED_SCALAR_VECTOR_LOWER_BOUND_BYTES_V1, 27_262_976);
        let audit = exact_binding_audit_v1(&release_profile_v1()).unwrap();
        assert!(!audit.chunked_workspace_certified);
    }
    fn identity_fixture(
        role: PersistentWitnessRoleV1,
        record_index: u32,
    ) -> PersistentCommitmentIdentityV1 {
        PersistentCommitmentIdentityV1::new(
            keccak256(b"profile"),
            keccak256(b"roster"),
            keccak256(b"key-material"),
            77,
            keccak256(b"party"),
            role,
            record_index,
            keccak256(&[b"commitments".as_slice(), &[role as u8]].concat()),
            keccak256(&[b"membership".as_slice(), &[role as u8]].concat()),
            match role {
                PersistentWitnessRoleV1::SecretEpoch => SECRET_REQUIRED_CONSUMERS_V1,
                PersistentWitnessRoleV1::RkgEphemeral => EPHEMERAL_REQUIRED_CONSUMERS_V1,
            },
        )
        .unwrap()
    }
    #[test]
    fn persistent_secret_and_ephemeral_graph_rejects_every_substitution() {
        let secret = identity_fixture(PersistentWitnessRoleV1::SecretEpoch, 0);
        let ephemeral = identity_fixture(PersistentWitnessRoleV1::RkgEphemeral, 91);
        let graph = PersistentCommitmentGraphV1::new(secret, ephemeral).unwrap();
        graph.validate().unwrap();
        assert_ne!(graph.digest().unwrap(), [0; 32]);
        assert_eq!(PERSISTENT_COMMITMENT_POINT_BYTES_V1, 264);
        assert_eq!(PERSISTENT_COMMITMENT_BLINDING_STATE_BYTES_V1, 256);
        assert_eq!(PERSISTENT_BOUND_ONE_MEMBERSHIP_CORE_BYTES_V1, 11_576);
        for mutate in 0..7 {
            let mut forged = graph;
            match mutate {
                0 => forged.cpk_secret = ephemeral.identity_digest,
                1 => forged.rkg_one_secret = ephemeral.identity_digest,
                2 => forged.rkg_two_secret = ephemeral.identity_digest,
                3 => forged.galois_secret = ephemeral.identity_digest,
                4 => forged.decryption_secret = ephemeral.identity_digest,
                5 => forged.rkg_one_ephemeral = secret.identity_digest,
                6 => forged.rkg_two_ephemeral = secret.identity_digest,
                _ => unreachable!(),
            }
            assert_eq!(forged.validate(), Err(ZkAmsMkheErrorV1::InvalidKeyMaterial));
        }
    }
    #[test]
    fn opaque_verified_binding_has_no_digest_mint_and_rejects_every_axis_splice() {
        let (roster, _secrets) = governed_roster_fixture(b"exact-binding-token-roster");
        let transcript = keccak256(b"exact-binding-cpk-transcript");
        let share = keccak256(b"exact-binding-cpk-share-0");
        let label = b"exact-binding-party-0";
        let binding = verified_binding_fixture(&roster, transcript, 0, share, label, 1);
        let legacy_digests = legacy_secret_binding_digests(&binding);
        assert_eq!(binding.source_context_digest(), [0; 32]);
        assert_eq!(binding.source_statement_digest(), [0; 32]);
        assert_eq!(binding.identity_digest(), legacy_digests.0);
        assert_eq!(binding.verification_digest, legacy_digests.1);
        for consumer in [
            PersistentWitnessConsumerV1::CollectivePublicKey,
            PersistentWitnessConsumerV1::RkgRoundOne,
            PersistentWitnessConsumerV1::RkgRoundTwo,
            PersistentWitnessConsumerV1::RkgNormalize,
            PersistentWitnessConsumerV1::Galois,
            PersistentWitnessConsumerV1::Decryption,
        ] {
            binding
                .validate_for(&roster, transcript, 0, share, consumer)
                .unwrap();
        }
        // Membership proofs may be freshly randomized without changing the
        // persistent source-commitment identity.
        let reproved = verified_binding_fixture(&roster, transcript, 0, share, label, 2);
        assert_eq!(binding.identity_digest(), reproved.identity_digest());
        assert_ne!(binding.verification_digest, reproved.verification_digest);
        for mutation in 0..22 {
            let mut forged = verified_binding_fixture(&roster, transcript, 0, share, label, 1);
            match mutation {
                0 => forged.version ^= 1,
                1 => forged.profile_digest[0] ^= 1,
                2 => forged.security_certificate_digest[0] ^= 1,
                3 => forged.roster_digest[0] ^= 1,
                4 => forged.key_material_digest[0] ^= 1,
                5 => forged.epoch += 1,
                6 => forged.cpk_transcript_digest[0] ^= 1,
                7 => forged.party_index = 1,
                8 => forged.party = roster.participants()[1].party(),
                9 => forged.cpk_share_digest[0] ^= 1,
                10 => forged.role = PersistentWitnessRoleV1::RkgEphemeral,
                11 => forged.record_index = 1,
                12 => forged.generator_basis_digest[0] ^= 1,
                13 => {
                    forged.commitments[0] =
                        derive_t256_generators_v1(b"exact-binding-substitute-point", 1).unwrap()[0]
                }
                14 => forged.commitment_set_digest[0] ^= 1,
                15 => forged.membership_proof_digest[0] ^= 1,
                16 => forged.verifier_transcript_digest[0] ^= 1,
                17 => forged.consumer_mask ^= SECRET_CONSUMER_DECRYPTION_V1,
                18 => forged.source_verification_digest[0] ^= 1,
                19 => forged.identity_digest[0] ^= 1,
                20 => forged.source_context_digest[0] ^= 1,
                21 => forged.source_statement_digest[0] ^= 1,
                _ => unreachable!(),
            }
            assert_eq!(
                forged.validate_for(
                    &roster,
                    transcript,
                    0,
                    share,
                    PersistentWitnessConsumerV1::Decryption,
                ),
                Err(ZkAmsMkheErrorV1::InvalidKeyMaterial),
                "mutation {mutation} must fail"
            );
        }
        let mut forged = reproved;
        forged.verification_digest[0] ^= 1;
        assert_eq!(
            forged.validate_for(
                &roster,
                transcript,
                0,
                share,
                PersistentWitnessConsumerV1::RkgRoundOne,
            ),
            Err(ZkAmsMkheErrorV1::InvalidKeyMaterial)
        );
        let mut identity_point = membership_receipt_fixture(b"identity-point-receipt", 1);
        identity_point.commitments[0] = Point::identity();
        assert!(
            VerifiedPersistentWitnessBindingV1::from_verified_membership(
                &roster,
                keccak256(b"release-security-certificate"),
                transcript,
                0,
                share,
                0,
                identity_point,
            )
            .is_err()
        );
    }
    #[test]
    fn ordered_verified_set_rejects_duplicate_reordered_and_mixed_lineage() {
        let (roster, _secrets) = governed_roster_fixture(b"exact-binding-set-roster");
        let transcript = keccak256(b"exact-binding-set-transcript");
        let collective_key = keccak256(b"exact-binding-set-collective-key");
        let shares: [[u8; 32]; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1] =
            core::array::from_fn(|index| keccak256(&[b's', b'h', b'a', b'r', b'e', index as u8]));
        let bindings = (0..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1)
            .map(|index| {
                let mut label = b"exact-binding-set-party-".to_vec();
                label.push(index as u8);
                verified_binding_fixture(&roster, transcript, index, shares[index], &label, 1)
            })
            .collect::<Vec<_>>();
        let references: [&VerifiedPersistentWitnessBindingV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1] =
            bindings.iter().collect::<Vec<_>>().try_into().unwrap();
        let set = VerifiedPersistentWitnessBindingSetV1::new(
            &roster,
            transcript,
            collective_key,
            shares,
            references,
        )
        .unwrap();
        assert_ne!(set.set_root(), [0; 32]);
        assert_eq!(set.identity_digests()[0], bindings[0].identity_digest());
        let stable_root = set.set_root();
        for consumer in [
            PersistentWitnessConsumerV1::CollectivePublicKey,
            PersistentWitnessConsumerV1::RkgRoundOne,
            PersistentWitnessConsumerV1::RkgRoundTwo,
            PersistentWitnessConsumerV1::RkgNormalize,
            PersistentWitnessConsumerV1::Galois,
            PersistentWitnessConsumerV1::Decryption,
        ] {
            set.validate_for_consumer(&roster, consumer).unwrap();
            assert_eq!(set.set_root(), stable_root);
        }
        let mut reordered = references;
        reordered.swap(0, 1);
        assert!(
            VerifiedPersistentWitnessBindingSetV1::new(
                &roster,
                transcript,
                collective_key,
                shares,
                reordered,
            )
            .is_err()
        );
        let mut duplicate = references;
        duplicate[3] = duplicate[2];
        assert!(
            VerifiedPersistentWitnessBindingSetV1::new(
                &roster,
                transcript,
                collective_key,
                shares,
                duplicate,
            )
            .is_err()
        );
        let mut wrong_shares = shares;
        wrong_shares.swap(4, 5);
        assert!(
            VerifiedPersistentWitnessBindingSetV1::new(
                &roster,
                transcript,
                collective_key,
                wrong_shares,
                references,
            )
            .is_err()
        );
        let mut mixed_label = b"exact-binding-set-party-".to_vec();
        mixed_label.push(6);
        let mut mixed_security =
            verified_binding_fixture(&roster, transcript, 6, shares[6], &mixed_label, 1);
        mixed_security.security_certificate_digest = keccak256(b"other-security-certificate");
        mixed_security.identity_digest = verified_binding_identity_digest(&mixed_security).unwrap();
        mixed_security.verification_digest =
            verified_binding_verification_digest(&mixed_security).unwrap();
        assert!(
            mixed_security
                .validate_for(
                    &roster,
                    transcript,
                    6,
                    shares[6],
                    PersistentWitnessConsumerV1::CollectivePublicKey,
                )
                .is_ok()
        );
        let mut mixed_references = references;
        mixed_references[6] = &mixed_security;
        assert!(
            VerifiedPersistentWitnessBindingSetV1::new(
                &roster,
                transcript,
                collective_key,
                shares,
                mixed_references,
            )
            .is_err()
        );
    }
    #[test]
    fn direct_relation_capability_binds_actual_secret_and_ephemeral_points() {
        let (roster, _secrets) = governed_roster_fixture(b"exact-binding-direct-roster");
        let transcript = keccak256(b"exact-binding-direct-transcript");
        let collective_key = keccak256(b"exact-binding-direct-collective-key");
        let shares: [[u8; 32]; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1] =
            core::array::from_fn(|index| keccak256(&[b'd', b'i', b'r', index as u8]));
        let labels = (0..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1)
            .map(|index| {
                let mut label = b"exact-binding-direct-party-".to_vec();
                label.push(index as u8);
                label
            })
            .collect::<Vec<_>>();
        let bindings = (0..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1)
            .map(|index| {
                verified_binding_fixture(
                    &roster,
                    transcript,
                    index,
                    shares[index],
                    &labels[index],
                    1,
                )
            })
            .collect::<Vec<_>>();
        let references: [&VerifiedPersistentWitnessBindingV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1] =
            bindings.iter().collect::<Vec<_>>().try_into().unwrap();
        let mut set = VerifiedPersistentWitnessBindingSetV1::new(
            &roster,
            transcript,
            collective_key,
            shares,
            references,
        )
        .unwrap();
        let direct_context = super::super::direct_collective_eval_ceremony::ZkAmsMkheDirectCeremonyContextV1::from_verified_binding_set(
            &roster,
            &set,
            super::super::direct_collective_eval_ceremony::ZkAmsMkheDirectEvaluatedKeyTargetV1::Relinearization,
            3,
        )
        .unwrap();
        assert_eq!(direct_context.transcript_digest(), transcript);
        assert_eq!(
            direct_context.collective_public_key_digest(),
            collective_key
        );
        assert_eq!(direct_context.secret_lineage_root(), set.set_root());
        let wrapper_context =
            ZkAmsMkheDirectRkgEphemeralMembershipContextV1::from_verified_binding_set(
                &roster,
                &set,
                &direct_context,
                0,
            )
            .unwrap();
        let ephemeral = verified_ephemeral_binding_fixture(
            &roster,
            transcript,
            0,
            shares[0],
            &labels[0],
            25,
            wrapper_context.direct_context_digest(),
            wrapper_context.statement_digest(),
        );
        for consumer in [
            PersistentRkgEphemeralConsumerV1::RoundOne,
            PersistentRkgEphemeralConsumerV1::RoundTwo,
        ] {
            ephemeral
                .validate_ephemeral_for(&roster, transcript, 0, shares[0], consumer)
                .unwrap();
        }
        for round in [
            ZkAmsMkheDirectCeremonyRoundV1::RkgRoundOne,
            ZkAmsMkheDirectCeremonyRoundV1::RkgRoundTwo,
        ] {
            set.validate_rkg_ephemeral_binding_for_direct_context(
                &roster,
                &direct_context,
                0,
                &ephemeral,
                round,
            )
            .unwrap();
        }
        let other_digit_context = super::super::direct_collective_eval_ceremony::ZkAmsMkheDirectCeremonyContextV1::from_verified_binding_set(
            &roster,
            &set,
            super::super::direct_collective_eval_ceremony::ZkAmsMkheDirectEvaluatedKeyTargetV1::Relinearization,
            4,
        )
        .unwrap();
        assert_ne!(other_digit_context.digest(), direct_context.digest());
        assert_eq!(
            set.validate_rkg_ephemeral_binding_for_direct_context(
                &roster,
                &other_digit_context,
                0,
                &ephemeral,
                ZkAmsMkheDirectCeremonyRoundV1::RkgRoundOne,
            ),
            Err(ZkAmsMkheErrorV1::InvalidKeyMaterial)
        );
        let mut altered_record = verified_ephemeral_binding_fixture(
            &roster,
            transcript,
            0,
            shares[0],
            &labels[0],
            25,
            wrapper_context.direct_context_digest(),
            wrapper_context.statement_digest(),
        );
        altered_record.record_index = 26;
        altered_record.identity_digest = verified_binding_identity_digest(&altered_record).unwrap();
        altered_record.verification_digest =
            verified_binding_verification_digest(&altered_record).unwrap();
        altered_record
            .validate_ephemeral_for(
                &roster,
                transcript,
                0,
                shares[0],
                PersistentRkgEphemeralConsumerV1::RoundOne,
            )
            .unwrap();
        assert_eq!(
            set.validate_rkg_ephemeral_binding_for_direct_context(
                &roster,
                &direct_context,
                0,
                &altered_record,
                ZkAmsMkheDirectCeremonyRoundV1::RkgRoundOne,
            ),
            Err(ZkAmsMkheErrorV1::InvalidKeyMaterial)
        );
        let other_wrapper_context =
            ZkAmsMkheDirectRkgEphemeralMembershipContextV1::from_verified_binding_set(
                &roster,
                &set,
                &other_digit_context,
                0,
            )
            .unwrap();
        let context_specific = verified_ephemeral_binding_fixture(
            &roster,
            transcript,
            0,
            shares[0],
            &labels[0],
            33,
            other_wrapper_context.direct_context_digest(),
            other_wrapper_context.statement_digest(),
        );
        assert_ne!(
            ephemeral.identity_digest(),
            context_specific.identity_digest()
        );
        assert_ne!(
            ephemeral.verification_digest,
            context_specific.verification_digest
        );
        let digest = |label: &[u8]| keccak256(label);
        let profile = release_profile_v1();
        let mut common_a_workspace = vec![0_u64; profile.ring_degree];
        let mut h0 = direct_common_a_v1::prepare_direct_common_a_creator_h0_v1(
            &roster,
            &set,
            direct_context,
        )
        .unwrap()
        .begin_h0_v1()
        .unwrap();
        for _ in 0..profile.moduli.len() {
            h0.derive_next_limb_into(&mut common_a_workspace).unwrap();
        }
        let mut h1 = h0.finish_h0_v1().unwrap().begin_h1_v1().unwrap();
        for _ in 0..profile.moduli.len() {
            h1.derive_next_limb_into(&mut common_a_workspace).unwrap();
        }
        let rkg_one = direct_common_a_v1::consume_completed_creator_authority_v1(
            h1.finish_h1_v1().unwrap(),
            digest(b"direct-prior-one"),
            digest(b"direct-h0-h1-statement"),
            digest(b"direct-rkg-one-proof-commitments"),
        )
        .unwrap();
        let mut wrong_context_selector = rkg_one;
        wrong_context_selector.context_digest = other_digit_context.digest();
        assert_eq!(
            set.bind_direct_relation_use(&roster, 0, Some(&ephemeral), wrong_context_selector,),
            Err(ZkAmsMkheErrorV1::InvalidKeyMaterial)
        );
        let capability = set
            .bind_direct_relation_use(&roster, 0, Some(&ephemeral), rkg_one)
            .unwrap();
        assert_ne!(capability.use_digest(), [0; 32]);
        assert_eq!(
            capability.secret_identity_digest(),
            bindings[0].identity_digest()
        );
        assert_eq!(
            capability.ephemeral_identity_digest(),
            ephemeral.identity_digest()
        );
        assert_eq!(capability.secret_commitments(), bindings[0].commitments());
        assert_eq!(
            capability.ephemeral_commitments(),
            Some(ephemeral.commitments())
        );
        assert_eq!(
            capability.ephemeral_source_context_digest,
            wrapper_context.direct_context_digest()
        );
        assert_eq!(
            capability.ephemeral_source_statement_digest,
            wrapper_context.statement_digest()
        );
        assert_eq!(capability.ephemeral_record_index, 25);
        assert!(
            direct_common_a_v1::DirectCommonAReplayV1::begin(other_digit_context, &capability,)
                .is_err()
        );
        let mut wrong_digit = set
            .bind_direct_relation_use(&roster, 0, Some(&ephemeral), rkg_one)
            .unwrap();
        wrong_digit.selector.digit_index = wrong_digit.selector.digit_index.wrapping_add(1);
        wrong_digit.use_digest = persistent_direct_relation_use_digest(&wrong_digit).unwrap();
        assert!(
            direct_common_a_v1::DirectCommonAReplayV1::begin(direct_context, &wrong_digit).is_err()
        );
        assert_eq!(
            direct_common_a_v1::DirectCommonAReplayV1::begin(direct_context, &capability)
                .unwrap()
                .finish()
                .map(|_| ()),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        let mut poisoned =
            direct_common_a_v1::DirectCommonAReplayV1::begin(direct_context, &capability).unwrap();
        assert_eq!(
            poisoned.derive_next_limb_into(&mut [0_u64; 1]),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        let mut replay_workspace = vec![0_u64; RELEASE_RING_DEGREE_V1];
        assert_eq!(
            poisoned.derive_next_limb_into(&mut replay_workspace),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        assert_eq!(
            poisoned.finish().map(|_| ()),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        let mut unwind_replay =
            direct_common_a_v1::DirectCommonAReplayV1::begin(direct_context, &capability).unwrap();
        unwind_replay.inject_unwind_on_next_derive_for_test();
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            unwind_replay
                .derive_next_limb_into(&mut replay_workspace)
                .unwrap();
        }));
        assert!(unwind.is_err());
        assert_eq!(
            unwind_replay.derive_next_limb_into(&mut replay_workspace),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        assert_eq!(
            unwind_replay.finish().map(|_| ()),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        let mut replay =
            direct_common_a_v1::DirectCommonAReplayV1::begin(direct_context, &capability).unwrap();
        for _ in 0..38 {
            replay.derive_next_limb_into(&mut replay_workspace).unwrap();
        }
        replay.finish().unwrap();
        let mut wrong_expected = set
            .bind_direct_relation_use(&roster, 0, Some(&ephemeral), rkg_one)
            .unwrap();
        wrong_expected.selector.common_a_statement_digest[0] ^= 1;
        wrong_expected.use_digest = persistent_direct_relation_use_digest(&wrong_expected).unwrap();
        let mut replay =
            direct_common_a_v1::DirectCommonAReplayV1::begin(direct_context, &wrong_expected)
                .unwrap();
        for _ in 0..38 {
            replay.derive_next_limb_into(&mut replay_workspace).unwrap();
        }
        assert_eq!(
            replay.finish().map(|_| ()),
            Err(ZkAmsMkheErrorV1::InvalidKeyMaterial)
        );
        assert_eq!(
            verify_and_consume_direct_relation_use_v1(capability, &[0xff; 64]),
            Err(ZkAmsMkheErrorV1::ReleaseUnavailable)
        );
        let rkg_two = PersistentDirectRelationUseSelectorV1::new(
            PersistentDirectRelationV1::RkgRoundTwo,
            direct_context.digest(),
            digest(b"direct-prior-two"),
            0,
            3,
            0,
            digest(b"direct-common-a"),
            [0; 32],
            digest(b"direct-aggregate-h0"),
            digest(b"direct-aggregate-h1"),
            digest(b"direct-k-statement"),
            digest(b"direct-rkg-two-proof-commitments"),
        )
        .unwrap();
        let rkg_two_capability = set
            .bind_direct_relation_use(&roster, 0, Some(&ephemeral), rkg_two)
            .unwrap();
        assert!(
            direct_common_a_v1::DirectCommonAReplayV1::begin(direct_context, &rkg_two_capability,)
                .is_err()
        );
        let normalize = PersistentDirectRelationUseSelectorV1::new(
            PersistentDirectRelationV1::RkgNormalize,
            digest(b"direct-context"),
            digest(b"direct-prior-normalize"),
            0,
            3,
            0,
            [0; 32],
            digest(b"direct-final-a"),
            [0; 32],
            digest(b"direct-aggregate-h1"),
            digest(b"direct-normalization-statement"),
            digest(b"direct-normalization-proof-commitments"),
        )
        .unwrap();
        assert!(
            set.bind_direct_relation_use(&roster, 0, None, normalize)
                .is_ok()
        );
        let galois = PersistentDirectRelationUseSelectorV1::new(
            PersistentDirectRelationV1::Galois,
            digest(b"direct-galois-context"),
            digest(b"direct-galois-prior"),
            1,
            3,
            5,
            [0; 32],
            digest(b"direct-galois-a"),
            [0; 32],
            [0; 32],
            digest(b"direct-galois-b-statement"),
            digest(b"direct-galois-proof-commitments"),
        )
        .unwrap();
        assert!(
            set.bind_direct_relation_use(&roster, 0, None, galois)
                .is_ok()
        );
        assert!(
            set.bind_direct_relation_use(&roster, 0, Some(&ephemeral), normalize)
                .is_err()
        );
        assert!(
            set.bind_direct_relation_use(&roster, 0, None, rkg_one)
                .is_err()
        );
        // The set root now binds the generator basis and the actual points,
        // rather than merely accepting the stored commitment digest.
        set.commitment_sets[0][0] =
            derive_t256_generators_v1(b"direct-substituted-point", 1).unwrap()[0];
        assert_eq!(
            set.validate_for_consumer(&roster, PersistentWitnessConsumerV1::RkgRoundOne),
            Err(ZkAmsMkheErrorV1::InvalidKeyMaterial)
        );
    }
    #[test]
    fn membership_only_receipt_cannot_mint_without_complete_cpk_relation_provenance() {
        let (roster, _secrets) = governed_roster_fixture(b"exact-binding-mint-roster");
        let security = keccak256(b"exact-binding-mint-security");
        let transcript = keccak256(b"exact-binding-mint-transcript");
        let share = keccak256(b"exact-binding-mint-share");
        let mut membership_only = membership_receipt_fixture(b"membership-only", 1);
        membership_only.source_verification_digest = [0; 32];
        assert_eq!(
            VerifiedPersistentWitnessBindingV1::from_verified_membership(
                &roster,
                security,
                transcript,
                0,
                share,
                0,
                membership_only,
            ),
            Err(ZkAmsMkheErrorV1::InvalidKeyMaterial)
        );
    }
    fn transcript_fixture(graph_digest: [u8; 32]) -> ExactBindingTranscriptContextV1 {
        ExactBindingTranscriptContextV1 {
            profile_digest: keccak256(b"profile"),
            roster_digest: keccak256(b"roster"),
            key_material_digest: keccak256(b"key-material"),
            epoch: 77,
            protocol_transcript_digest: keccak256(b"transcript"),
            round_tag: 3,
            party_index: 2,
            party: keccak256(b"party"),
            record_index: 91,
            relation_index: 12,
            statement_digest: keccak256(b"statement"),
            commitment_set_digest: keccak256(b"commitments"),
            membership_proof_set_digest: keccak256(b"membership"),
            persistent_graph_digest: graph_digest,
        }
    }
    #[test]
    fn challenge_vector_binds_every_context_replay_and_round_axis() {
        let graph = PersistentCommitmentGraphV1::new(
            identity_fixture(PersistentWitnessRoleV1::SecretEpoch, 0),
            identity_fixture(PersistentWitnessRoleV1::RkgEphemeral, 91),
        )
        .unwrap();
        let context = transcript_fixture(graph.digest().unwrap());
        let rns = core::array::from_fn(|index| keccak256(&[b'r', index as u8]));
        let commitments = core::array::from_fn(|index| keccak256(&[b'c', index as u8]));
        let baseline = challenge_vector(context, rns, commitments).unwrap();
        assert_ne!(baseline.0, [0; 32]);
        for mutate in 0..14 {
            let mut changed = context;
            match mutate {
                0 => changed.profile_digest[0] ^= 1,
                1 => changed.roster_digest[0] ^= 1,
                2 => changed.key_material_digest[0] ^= 1,
                3 => changed.epoch += 1,
                4 => changed.protocol_transcript_digest[0] ^= 1,
                5 => changed.round_tag += 1,
                6 => changed.party_index += 1,
                7 => changed.party[0] ^= 1,
                8 => changed.record_index += 1,
                9 => changed.relation_index += 1,
                10 => changed.statement_digest[0] ^= 1,
                11 => changed.commitment_set_digest[0] ^= 1,
                12 => changed.membership_proof_set_digest[0] ^= 1,
                13 => changed.persistent_graph_digest[0] ^= 1,
                _ => unreachable!(),
            }
            assert_ne!(
                challenge_vector(changed, rns, commitments).unwrap(),
                baseline
            );
        }
        for ordinal in 0..CHALLENGE_REPETITIONS_V1 {
            let mut changed_rns = rns;
            changed_rns[ordinal][0] ^= 1;
            assert_ne!(
                challenge_vector(context, changed_rns, commitments).unwrap(),
                baseline
            );
            let mut changed_commitments = commitments;
            changed_commitments[ordinal][0] ^= 1;
            assert_ne!(
                challenge_vector(context, rns, changed_commitments).unwrap(),
                baseline
            );
        }
    }
    #[test]
    fn one_differing_scalar_coordinate_extracts_the_exact_relation() {
        const Q: i64 = 1_000_003;
        const A: i64 = 37;
        let witness = -2_i64;
        let target = (A * witness).rem_euclid(Q);
        let mask = 123_456_i64;
        let first_blinding = 41_i64;
        let commitment_blinding = 73_i64;
        let challenges = [0_i64, 17, 99, i64::from(u32::MAX)];
        let forked = [0_i64, 17, 100, i64::from(u32::MAX)];
        let responses = challenges.map(|challenge| mask + challenge * witness);
        let response_blindings =
            challenges.map(|challenge| first_blinding + challenge * commitment_blinding);
        let forked_responses = forked.map(|challenge| mask + challenge * witness);
        let forked_blindings =
            forked.map(|challenge| first_blinding + challenge * commitment_blinding);
        let differing = challenges
            .iter()
            .zip(forked)
            .position(|(left, right)| *left != right)
            .unwrap();
        let d = challenges[differing] - forked[differing];
        assert_ne!(d, 0);
        assert!(d.unsigned_abs() < 1_u64 << 32);
        assert!(d.unsigned_abs() < Q as u64);
        let extracted = (responses[differing] - forked_responses[differing]) / d;
        let extracted_blinding = (response_blindings[differing] - forked_blindings[differing]) / d;
        assert_eq!(extracted, witness);
        assert_eq!(extracted_blinding, commitment_blinding);
        assert_eq!((A * extracted).rem_euclid(Q), target);
        // Simulator reconstruction agrees with the honest first messages.
        for ((challenge, response), rho) in challenges
            .into_iter()
            .zip(responses)
            .zip(response_blindings)
        {
            let commitment_first = response - challenge * witness;
            let blinding_first = rho - challenge * commitment_blinding;
            let rns_first = (A * response - challenge * target).rem_euclid(Q);
            assert_eq!(commitment_first, mask);
            assert_eq!(blinding_first, first_blinding);
            assert_eq!(rns_first, (A * mask).rem_euclid(Q));
        }
    }
    #[test]
    fn split_decryption_and_all_operational_paths_remain_fail_closed() {
        let profile = release_profile_v1();
        let audit = exact_binding_audit_v1(&profile).unwrap();
        assert!(!audit.split_decryption_wide_relation_certified);
        assert!(audit.t256_membership_backend_implemented);
        assert!(audit.generator_basis_kat_pinned);
        assert!(!audit.external_commitment_provenance_certified);
        assert!(!audit.full_basis_mrep_crs_certified);
        assert!(!audit.membership_argument_of_knowledge_certified);
        assert!(!audit.membership_zero_knowledge_certified);
        assert!(!audit.composite_rom_forking_certified);
        assert!(!audit.full_ceremony_10_336_instance_composition_certified);
        assert!(!audit.canonical_complete_wire_certified);
        assert!(!audit.sampler_wired_to_runtime);
        assert!(!audit.persistent_graph_wired_to_runtime);
        assert!(!audit.release_kat_pinned);
        assert_eq!(
            preflight_exact_binding_v1(&profile),
            Err(ZkAmsMkheErrorV1::ReleaseUnavailable)
        );
        for bytes in [&[][..], &b"ZAEB"[..], &b"valid-looking trailing bytes"[..]] {
            assert_eq!(
                decode_exact_binding_proof_v1(&profile, bytes),
                Err(ZkAmsMkheErrorV1::ReleaseUnavailable)
            );
        }
    }
}
