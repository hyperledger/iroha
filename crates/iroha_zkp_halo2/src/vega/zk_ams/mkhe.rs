//! Native, fail-closed multi-key RNS-BGV substrate for ZK-AMS Phase II.
//!
//! This module deliberately keeps the release profile separate from the tiny
//! arithmetic profile used by its known-answer tests.  A profile is admitted
//! only after every modulus/root, byte bound, work bound, and decryption-noise
//! inequality has been checked.  In particular, none of these routines fall
//! back to plaintext execution when an evaluated key or decryption share is absent.
//!
//! Outer parameter, release and source-receipt identities use the canonical
//! native BLAKE3 frame and retain every payload field. Proof challenges, entropy
//! expansion and the fixed SHAKE packing-root derivation have separate owners.
//! TODO: qualify current source-bound estimator and packing evidence for these
//! native identities before release admission; historical evidence stays frozen.
#[cfg(test)]
use super::super::sponge::{keccak256, shake256};
use super::super::{VEGA_T256_SCALAR_MODULUS_BE_V1, VegaT256ScalarV1 as Scalar};
#[cfg(test)]
use super::super::{
    VegaT256PointV1, derive_t256_generators_v1,
    sponge::{Keccak256, Shake256Reader},
};
#[cfg(test)]
use super::MaskedRelaxedRandomSourceV1;
#[cfg(test)]
use crate::generalized_bulletproof::try_exact_capacity_vec_v1;
#[cfg(test)]
use core::cmp::Ordering;
#[cfg(test)]
use core::fmt;
#[cfg(test)]
use once_cell::sync::Lazy;
use thiserror::Error;

/// Semantic roles of native outer identities, separate from proof transcripts.
#[derive(Clone, Copy)]
pub(super) enum NativeOuterIdentityRoleV1 {
    /// Algebraic parameters, resource policies and packing layouts.
    Parameter,
    /// Release descriptors and their evidence/readiness identities.
    Release,
    /// Source binding, arena context and source receipts.
    SourceReceipt,
}

/// Begin an exact native frame after the producer has admitted its fixed schema.
/// Every phase is a static producer domain; no release digest is used as the
/// catalog label, which would make parameter/profile construction circular.
pub(super) fn native_outer_identity_v1(
    role: NativeOuterIdentityRoleV1,
    phase: &'static [u8],
    field_count: usize,
) -> iroha_crypto::native_commitment::NativeCommitmentBuilderV1 {
    use iroha_crypto::native_commitment::{NativeCommitmentBuilderV1, NativeCommitmentDomainV1};
    let role: &[u8] = match role {
        NativeOuterIdentityRoleV1::Parameter => b"parameter-identity",
        NativeOuterIdentityRoleV1::Release => b"release-identity",
        NativeOuterIdentityRoleV1::SourceReceipt => b"source-receipt-identity",
    };
    NativeCommitmentBuilderV1::new(
        NativeCommitmentDomainV1 {
            catalog: b"iroha.zk-ams.v1.mkhe",
            protocol: b"iroha.zk-ams.v1",
            role,
            phase,
            level: 0,
            index: 0,
            counter: 0,
        },
        field_count,
    )
    .expect("MKHE native identity has a fixed bounded domain and admitted field count")
}

/// Bind one fixed algebra/equation descriptor under its distinct release phase.
pub(super) fn native_outer_schema_v1(phase: &'static [u8], schema: &'static [u8]) -> [u8; 32] {
    let mut identity = native_outer_identity_v1(NativeOuterIdentityRoleV1::Release, phase, 1);
    identity
        .push_field(schema)
        .expect("fixed bounded MKHE algebra descriptor");
    *identity
        .finish()
        .expect("one complete MKHE algebra descriptor")
        .as_bytes()
}

/// Fixed-size entropy owner erased on success, error, and unwind.
///
/// Callers borrow the fixed array during decoding so no unmanaged array copy
/// is created before this owner is cleared.
#[cfg(test)]
struct ZeroizingRandomBytesV1<const N: usize>([u8; N]);
#[cfg(test)]
impl<const N: usize> ZeroizingRandomBytesV1<N> {
    const fn zeroed() -> Self {
        Self([0; N])
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
    const fn as_array(&self) -> &[u8; N] {
        &self.0
    }
}
#[cfg(test)]
impl<const N: usize> Drop for ZeroizingRandomBytesV1<N> {
    fn drop(&mut self) {
        let bytes = core::hint::black_box(&mut self.0);
        bytes.fill(0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(&mut *bytes);
    }
}
#[cfg(test)]
type ZeroizingScalarEntropyV1 = ZeroizingRandomBytesV1<64>;
/// Move-only owner for one named secret scalar.
#[cfg(test)]
struct ZeroizingScalarV1(Scalar);
#[cfg(test)]
impl ZeroizingScalarV1 {
    const fn new(value: Scalar) -> Self {
        Self(value)
    }
    const fn as_ref(&self) -> &Scalar {
        &self.0
    }
    const fn expose_copy(&self) -> Scalar {
        self.0
    }
}
#[cfg(test)]
impl Drop for ZeroizingScalarV1 {
    fn drop(&mut self) {
        let scalar = core::hint::black_box(&mut self.0);
        scalar.clear_secret();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(&mut *scalar);
    }
}
#[path = "mkhe/active.rs"]
mod active;
#[path = "mkhe/active_exact_binding.rs"]
mod active_exact_binding;
#[cfg(test)]
#[path = "mkhe/cks.rs"]
mod cks;
#[path = "mkhe/collective.rs"]
mod collective;
#[allow(
    dead_code,
    reason = "the evaluated-key runtime remains fail-closed pending stronger cross-set algebraic certification"
)]
#[path = "mkhe/collective_eval_keys.rs"]
mod collective_eval_keys;
#[cfg(test)]
#[path = "mkhe/collective_keys.rs"]
mod collective_keys;
#[cfg(test)]
#[path = "mkhe/cpk_ceremony.rs"]
mod cpk_ceremony;
// TODO: Remove both CPK dead-code allowances (relation and persistent membership
// evidence) when the complete streamed RNS/authentication verifier is connected.
#[cfg(test)]
#[allow(
    dead_code,
    reason = "native CPK relation remains private and fail-closed until the complete streamed RNS/auth verifier is wired"
)]
#[path = "mkhe/cpk_relation.rs"]
mod cpk_relation;
#[path = "mkhe/decryption.rs"]
mod decryption;
#[path = "mkhe/direct_collective_eval_ceremony.rs"]
mod direct_collective_eval_ceremony;
#[path = "mkhe/direct_object_transport.rs"]
mod direct_object_transport;
#[cfg(test)]
#[allow(
    dead_code,
    reason = "the RKG-ephemeral opening is retained fail-closed until the exact direct relation prover consumes it"
)]
#[path = "mkhe/direct_rkg_ephemeral_membership.rs"]
mod direct_rkg_ephemeral_membership;
#[path = "mkhe/exact_eight_chunk_membership.rs"]
mod exact_eight_chunk_membership;
#[path = "mkhe/global_lookup_statement_v1.rs"]
mod global_lookup_statement_v1;
#[path = "mkhe/manifest.rs"]
mod manifest;
#[path = "mkhe/noise.rs"]
mod noise;
#[path = "mkhe/noise_feasibility.rs"]
mod noise_feasibility;
#[path = "mkhe/packing.rs"]
mod packing;
#[path = "mkhe/persistent_decryption_equality.rs"]
mod persistent_decryption_equality;
#[allow(
    dead_code,
    reason = "native CPK relation remains private and fail-closed until the complete streamed RNS/auth verifier is wired"
)]
#[path = "mkhe/persistent_membership_evidence.rs"]
mod persistent_membership_evidence;
#[path = "mkhe/phase23.rs"]
mod phase23;
#[path = "mkhe/phase23_encrypted.rs"]
mod phase23_encrypted;
#[cfg(test)]
#[path = "mkhe/phase23_ingress.rs"]
mod phase23_ingress;
#[path = "mkhe/phase23_mask_proof.rs"]
mod phase23_mask_proof;
#[cfg(test)]
#[path = "mkhe/phase23_materialized_wire.rs"]
mod phase23_materialized_wire;
#[path = "mkhe/phase23_rns_link.rs"]
mod phase23_rns_link;
#[path = "mkhe/receipt_capability_audit.rs"]
mod receipt_capability_audit;
#[path = "mkhe/release_evidence.rs"]
mod release_evidence;
#[path = "mkhe/resource.rs"]
mod resource;
#[cfg(test)]
#[path = "mkhe/rns_native_bulletproof_common.rs"]
mod rns_native_bulletproof_common;
#[path = "mkhe/rns_native_centering_subtraction_relation.rs"]
mod rns_native_centering_subtraction_relation;
#[cfg(test)]
#[allow(
    dead_code,
    reason = "the sealed claimed-successor carrier is inactive until the direct chronology is wired"
)]
#[path = "mkhe/rns_native_claimed_successor.rs"]
mod rns_native_claimed_successor;
#[path = "mkhe/rns_native_comparator_product.rs"]
mod rns_native_comparator_product;
#[path = "mkhe/rns_native_comparator_range_carry_product.rs"]
mod rns_native_comparator_range_carry_product;
#[cfg(test)]
#[path = "mkhe/rns_native_composite_verifier.rs"]
mod rns_native_composite_verifier;
#[path = "mkhe/rns_native_cross_field_inventory.rs"]
mod rns_native_cross_field_inventory;
#[path = "mkhe/rns_native_cross_field_rlwe_direct.rs"]
mod rns_native_cross_field_rlwe_direct;
#[cfg(test)]
#[allow(
    dead_code,
    reason = "the private direct/membership handoff remains non-authorizing until authenticated numeric, replay, and mask owners exist"
)]
#[path = "mkhe/rns_native_direct_global_membership_handoff.rs"]
mod rns_native_direct_global_membership_handoff;
#[path = "mkhe/rns_native_existing_radix_commitment_view.rs"]
mod rns_native_existing_radix_commitment_view;
#[cfg(test)]
#[path = "mkhe/rns_native_global_lookup_z_commitment_view.rs"]
mod rns_native_global_lookup_z_commitment_view;
#[path = "mkhe/rns_native_profile.rs"]
mod rns_native_profile;
#[path = "mkhe/rns_native_proof_hash.rs"]
mod rns_native_proof_hash;
#[cfg(test)]
#[path = "mkhe/rns_native_proof_sampling.rs"]
mod rns_native_proof_sampling;
#[cfg(test)]
#[path = "mkhe/rns_native_public_polynomial_publisher.rs"]
mod rns_native_public_polynomial_publisher;
#[path = "mkhe/rns_native_public_polynomial_reader.rs"]
mod rns_native_public_polynomial_reader;
#[path = "mkhe/rns_native_q_mask_linear_relations.rs"]
mod rns_native_q_mask_linear_relations;
#[path = "mkhe/rns_native_qpcs_field_wire.rs"]
mod rns_native_qpcs_field_wire;
#[path = "mkhe/rns_native_qpcs_fri_complete.rs"]
mod rns_native_qpcs_fri_complete;
#[path = "mkhe/rns_native_qpcs_initial.rs"]
mod rns_native_qpcs_initial;
#[cfg(test)]
#[path = "mkhe/rns_native_qpcs_leaf.rs"]
mod rns_native_qpcs_leaf;
#[cfg(test)]
#[path = "mkhe/rns_native_qpcs_opening_work.rs"]
mod rns_native_qpcs_opening_work;
#[path = "mkhe/rns_native_qpcs_prefix.rs"]
mod rns_native_qpcs_prefix;
#[cfg(test)]
#[path = "mkhe/rns_native_resource_budget.rs"]
mod rns_native_resource_budget;
// Prototype tree construction is exercised by internal fixtures; production uses the verifier.
#[path = "mkhe/rns_native_qpcs_tree.rs"]
#[cfg(test)]
mod rns_native_qpcs_tree;
#[path = "mkhe/rns_native_radix_complement_linear_relation.rs"]
mod rns_native_radix_complement_linear_relation;
#[path = "mkhe/rns_native_rlwe_source_statement.rs"]
mod rns_native_rlwe_source_statement;
#[path = "mkhe/rns_native_section_codec.rs"]
mod rns_native_section_codec;
#[path = "mkhe/rns_native_small_sign_disjointness_product.rs"]
mod rns_native_small_sign_disjointness_product;
#[path = "mkhe/rns_native_source.rs"]
mod rns_native_source;
#[cfg(test)]
#[path = "mkhe/rns_native_source_packing_same_opening.rs"]
mod rns_native_source_packing_same_opening;
#[cfg(test)]
#[allow(
    dead_code,
    reason = "the private source/terminal prerequisite remains non-authorizing until the cross-field/global-lookup proof verifier consumes it"
)]
#[path = "mkhe/rns_native_source_terminal_cross_field.rs"]
mod rns_native_source_terminal_cross_field;
#[cfg(test)]
#[path = "mkhe/rns_native_terminal_cross_basis.rs"]
mod rns_native_terminal_cross_basis;
#[allow(
    dead_code,
    reason = "private staged transcript seams remain unreachable while composite verification is fail-closed"
)]
#[path = "mkhe/rns_native_transcript.rs"]
mod rns_native_transcript;
#[cfg(test)]
#[path = "mkhe/rns_native_u15_msm.rs"]
mod rns_native_u15_msm;
#[path = "mkhe/rns_native_wire.rs"]
mod rns_native_wire;
#[path = "mkhe/security.rs"]
mod security;
#[path = "mkhe/terminal.rs"]
mod terminal;
#[cfg(test)]
#[allow(
    dead_code,
    reason = "cross-basis kernel remains source-and-packing sealed until its consuming owner is wired"
)]
#[path = "mkhe/terminal_cross_basis_ipa.rs"]
mod terminal_cross_basis_ipa;
#[path = "mkhe/wire.rs"]
mod wire;
#[cfg(test)]
pub use active::{
    ZkAmsMkheAbortReasonV1, ZkAmsMkheActiveCollectivePublicKeyStatementV1,
    ZkAmsMkheActiveCollectivePublicKeyWitnessV1, ZkAmsMkheActiveContributionV1,
    ZkAmsMkheActivePartySecretV1, ZkAmsMkheActiveRkgLinearProofSecurityV1,
    ZkAmsMkheActiveRkgProofV1, ZkAmsMkheActiveRoundReceiptV1, ZkAmsMkheActiveRoundV1,
    ZkAmsMkheGovernedActiveRosterV1, ZkAmsMkheGovernedCollectiveKeyMaterialIdentityV1,
    ZkAmsMkheGovernedParticipantV1, ZkAmsMkheIdentifiableAbortV1, ZkAmsMkheRosterKeyProofV1,
    prove_zk_ams_mkhe_active_collective_public_key_v1,
    verify_zk_ams_mkhe_active_collective_public_key_v1, zk_ams_mkhe_active_collective_public_a_v1,
    zk_ams_mkhe_active_rkg_linear_proof_security_v1, zk_ams_mkhe_collect_active_round_v1,
};
#[cfg(test)]
pub use cks::{
    ZkAmsMkheCksProofV1, ZkAmsMkheCksResourceEvidenceV1, zk_ams_mkhe_cks_resource_evidence_v1,
};
#[cfg(test)]
pub use collective::{
    ZkAmsMkheCollectiveCiphertextV1, ZkAmsMkheCollectiveLevelOneV1, ZkAmsMkheCollectivePublicKeyV1,
};
#[cfg(test)]
pub use collective::{
    ZkAmsMkheCollectivePartyStateV1, ZkAmsMkheCollectivePublicKeyShareV1,
    generate_zk_ams_mkhe_collective_party_state_with_prepared_public_a_v1,
};
#[cfg(test)]
pub use collective::{
    ZkAmsMkhePreparedCollectivePublicAV1, ZkAmsMkheStreamingCollectiveCiphertextV1,
    ZkAmsMkheStreamingCollectiveEncryptionKeyAuthorityV1,
    encrypt_zk_ams_mkhe_collective_packed_streaming_v1, prepare_zk_ams_mkhe_collective_public_a_v1,
};
#[cfg(test)]
pub use collective_eval_keys::{
    ZK_AMS_MKHE_EVIDENCE_CHUNK_BYTES_V1, ZkAmsMkheCollectiveEvaluatedKeyEvidenceSinkV1,
    ZkAmsMkheCollectiveEvaluatedKeyProviderV1, ZkAmsMkheCollectiveEvaluatedKeyPublicationFooterV1,
    ZkAmsMkheCollectiveEvaluatedKeyPublicationHeaderV1,
    ZkAmsMkheCollectiveEvaluatedKeyPublicationSinkV1, ZkAmsMkheCollectiveEvaluatedKeyRuntimeV1,
    ZkAmsMkheCollectiveEvidenceRecordFooterV1, ZkAmsMkheCollectiveEvidenceRecordHeaderV1,
    ZkAmsMkheCollectiveEvidenceRecordKindV1, ZkAmsMkheCollectiveEvidenceSetFooterV1,
    ZkAmsMkheCollectiveEvidenceSetHeaderV1, ZkAmsMkheCollectiveEvidenceSetKindV1,
    ZkAmsMkheOwnedCollectiveCksDigitEvidenceV1, ZkAmsMkheTrustedCksContextV1,
    ZkAmsMkheValidatedCollectiveEvaluatedKeyV1,
    zk_ams_mkhe_compact_key_switch_ring_multiplications_v1,
    zk_ams_mkhe_seekable_evaluated_key_accounting_v1,
};
#[cfg(test)]
pub use collective_eval_keys::{
    ZkAmsMkheSeekableEvaluatedKeyAccountingV1,
    ZkAmsMkheStreamingCollectiveAutomorphismAccountingV1, ZkAmsMkheTrustedSourceContextV1,
    ZkAmsMkheValidatedCollectiveSourceEvidenceReceiptV1,
    ZkAmsMkheVerifiedEvaluatedKeyEvidenceSetV1,
    automorphism_switch_zk_ams_mkhe_collective_streaming_v1,
    verify_zk_ams_mkhe_evaluated_key_evidence_set_v1,
    zk_ams_mkhe_streaming_collective_automorphism_accounting_v1,
};
#[cfg(test)]
pub use collective_keys::{
    ZkAmsMkheCollectiveEvaluatedKeyEntryV1, ZkAmsMkheCollectiveEvaluatedKeyManifestV1,
    ZkAmsMkheCollectiveEvaluatedKeyPurposeV1, ZkAmsMkheEvaluatedKeySorafsPointerV1,
};
#[cfg(test)]
pub use cpk_ceremony::ZK_AMS_MKHE_CPK_ERROR_MEMBERSHIP_WIRE_BYTES_V1;
#[cfg(test)]
pub use cpk_ceremony::{
    ZK_AMS_MKHE_CPK_SECRET_MEMBERSHIP_WIRE_BYTES_V1, ZkAmsMkheAdmittedCpkPartyV1,
    ZkAmsMkheCpkCeremonyResidencyEvidenceV1, ZkAmsMkheCpkCeremonyV1, ZkAmsMkheCpkPartyInputV1,
    ZkAmsMkheCpkRuntimeV1, ZkAmsMkheFinalizedCpkCeremonyV1,
    zk_ams_mkhe_cpk_ceremony_residency_evidence_v1,
};
#[cfg(test)]
pub use decryption::{
    ZK_AMS_MKHE_DECRYPTION_SPLIT_MANIFEST_BYTES_V1,
    ZK_AMS_MKHE_DECRYPTION_SPLIT_RELEASE_KAT_DIGEST_V1,
    ZK_AMS_MKHE_DECRYPTION_STREAMING_RESIDENCY_CERTIFICATE_DIGEST_V1,
    ZkAmsMkheDecryptionProofViewV1, ZkAmsMkheDecryptionResourceEvidenceV1,
    ZkAmsMkheDecryptionStreamingResidencyEvidenceV1, ZkAmsMkheDecryptionStreamingSnapshotV1,
    ZkAmsMkheStagedDecryptionShareV1, ZkAmsMkheStreamingDecryptionStatementV1,
    ZkAmsMkheStreamingFullRosterDecryptionResultV1, prove_zk_ams_mkhe_decryption_share_staged_v1,
    verify_combine_decode_zk_ams_mkhe_decryption_streaming_v1,
    zk_ams_mkhe_decryption_resource_evidence_v1,
    zk_ams_mkhe_decryption_streaming_residency_evidence_v1,
};
#[cfg(test)]
pub use decryption::{
    ZkAmsMkheDecryptedPlaintextV1, ZkAmsMkheDecryptionAbortReasonV1,
    ZkAmsMkheDecryptionTransportComponentKindV1, ZkAmsMkheDecryptionTransportManifestV1,
    ZkAmsMkheDecryptionTransportPointerV1, ZkAmsMkheFullRosterDecryptionResultV1,
    ZkAmsMkheIdentifiableDecryptionAbortV1,
};
#[cfg(test)]
pub use direct_collective_eval_ceremony::{
    ZkAmsMkheDirectAdmittedContributionSetV1, ZkAmsMkheDirectCeremonyContextV1,
    ZkAmsMkheDirectCoordinatorV1, ZkAmsMkheDirectEvaluatedKeySetAdmissionV1,
    ZkAmsMkheDirectEvaluatedKeyTargetV1, ZkAmsMkheDirectNoiseCertificateV1,
    ZkAmsMkheDirectNoiseIntegrationCertificateV1, ZkAmsMkheDirectPolynomialStreamReceiptV1,
    ZkAmsMkheDirectPolynomialStreamV1, ZkAmsMkheDirectProofAuditV1,
    ZkAmsMkheDirectResourceCertificateV1, ZkAmsMkheDirectVerifiedContributionProviderV1,
    ZkAmsMkheDirectVerifiedContributionV1, admit_zk_ams_mkhe_direct_contribution_set_v1,
    zk_ams_mkhe_direct_noise_certificate_v1, zk_ams_mkhe_direct_noise_integration_certificate_v1,
    zk_ams_mkhe_direct_noise_integration_for_admitted_keys_v1, zk_ams_mkhe_direct_proof_audit_v1,
    zk_ams_mkhe_direct_resource_certificate_v1,
};
#[cfg(test)]
pub use direct_collective_eval_ceremony::{
    ZkAmsMkheDirectCeremonyRoundV1, ZkAmsMkheDirectPolynomialRoleV1,
};
#[cfg(test)]
pub use direct_object_transport::ZkAmsMkheDirectObjectKindV1;
#[cfg(test)]
pub use direct_object_transport::{
    ZK_AMS_MKHE_DIRECT_OBJECT_POINTER_BYTES_V1, ZK_AMS_MKHE_DIRECT_OBJECT_READ_BYTES_V1,
    ZkAmsMkheDirectObjectPointerV1, ZkAmsMkheDirectObjectPublicationReceiptV1,
    ZkAmsMkheDirectObjectPublishedBindingV1, ZkAmsMkheDirectObjectReadReceiptV1,
};
#[cfg(test)]
pub use direct_object_transport::{
    ZkAmsMkheDirectObjectCasPublicationV1, ZkAmsMkheDirectObjectPublicationTransactionV1,
    ZkAmsMkheDirectObjectReadAtProviderV1, ZkAmsMkheDirectObjectSealTokenV1,
    ZkAmsMkheDirectObjectStagingTokenV1, validate_zk_ams_mkhe_direct_object_v1,
};
/// Frozen width of one V2 direct-RKG1 lifecycle record.
#[cfg(test)]
pub const ZK_AMS_MKHE_DIRECT_RKG_ONE_LIFECYCLE_RECORD_BYTES_V2: usize = 640;
/// Actual atomic value width observed at the stable direct-RKG1 lifecycle key.
#[cfg(test)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "only the test backend constructs outcomes")
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAmsMkheDirectRkgOneLifecycleStoredWidthV2 {
    /// The stable key has no committed value.
    Absent,
    /// The key contains one complete V2 640-byte lifecycle record.
    Lifecycle640,
}
/// Linearizable result of inserting one V2 lifecycle value at an absent stable key.
#[cfg(test)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "only the test backend constructs outcomes")
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAmsMkheDirectRkgOneLifecyclePutOutcomeV2 {
    /// This exact call inserted the value.
    InsertedByThisCall,
    /// A value was already present; this call changed nothing.
    AlreadyPresent,
}
/// Linearizable result of one exact V2 lifecycle compare-exchange.
#[cfg(test)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "only the test backend constructs outcomes")
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAmsMkheDirectRkgOneLifecycleCasOutcomeV2 {
    /// This exact call replaced the expected value.
    ExchangedByThisCall,
    /// The exact desired value was already committed; this call changed nothing.
    ExactReplay,
    /// A different value was committed; this call changed nothing.
    Conflict,
}
/// Raw durable backend for the authority-neutral direct-RKG1 lifecycle journal.
///
/// `load_exact_v2` must bypass caches and obtain the committed value width from backend metadata;
/// zero padding alone is not a width discriminator. `Absent` zeros all 640 output bytes and
/// `Lifecycle640` writes all bytes. The supplied key is the stable direct-RKG1 transaction hash,
/// with no schema-specific namespace.
/// Mutations are atomic, linearizable, and crash-durable before a successful return. This raw API
/// additionally requires one protected singleton root plus global same-key fencing and
/// rollback-resistant absence/CAS state: rollback to `Absent` could otherwise mint a second Fresh
/// permit. A host-local checkpoint alone does not meet this contract. This raw API carries no
/// publication permit, proof receipt, verifier result, binding, or release authority.
#[cfg(test)]
pub trait ZkAmsMkheDirectRkgOneLifecycleStoreV2 {
    /// Load the exact committed value and its independently observed width.
    fn load_exact_v2(
        &mut self,
        storage_key: &[u8; 32],
        record: &mut [u8; ZK_AMS_MKHE_DIRECT_RKG_ONE_LIFECYCLE_RECORD_BYTES_V2],
    ) -> Result<ZkAmsMkheDirectRkgOneLifecycleStoredWidthV2, ZkAmsMkheErrorV1>;

    /// Insert exactly one V2 record without overwriting any existing-width value.
    /// An error or unwind may follow a committed write and never proves caller ownership.
    fn put_if_absent_exact_v2(
        &mut self,
        storage_key: &[u8; 32],
        record: &[u8; ZK_AMS_MKHE_DIRECT_RKG_ONE_LIFECYCLE_RECORD_BYTES_V2],
    ) -> Result<ZkAmsMkheDirectRkgOneLifecyclePutOutcomeV2, ZkAmsMkheErrorV1>;

    /// Replace exactly one V2 value only when every expected byte matches.
    /// An error or unwind may follow a committed replacement and never proves caller ownership.
    fn compare_exchange_exact_v2(
        &mut self,
        storage_key: &[u8; 32],
        expected: &[u8; ZK_AMS_MKHE_DIRECT_RKG_ONE_LIFECYCLE_RECORD_BYTES_V2],
        replacement: &[u8; ZK_AMS_MKHE_DIRECT_RKG_ONE_LIFECYCLE_RECORD_BYTES_V2],
    ) -> Result<ZkAmsMkheDirectRkgOneLifecycleCasOutcomeV2, ZkAmsMkheErrorV1>;
}
pub(super) use manifest::require_release_ready_v1;
pub use manifest::{
    ZkAmsMkheReadinessV1, zk_ams_mkhe_manifest_digest_v1, zk_ams_mkhe_readiness_digest_v1,
    zk_ams_mkhe_readiness_v1,
};
#[cfg(test)]
pub use manifest::{
    ZkAmsMkheReleaseManifestV1, zk_ams_mkhe_noise_certificate_v1,
    zk_ams_mkhe_release_kat_evidence_v1, zk_ams_mkhe_release_manifest_v1,
    zk_ams_mkhe_resource_certificate_digest_v1, zk_ams_mkhe_resource_certificate_v1,
    zk_ams_mkhe_resource_evidence_v1, zk_ams_mkhe_security_candidate_input_digest_v1,
    zk_ams_mkhe_security_candidate_v1, zk_ams_mkhe_security_certificate_v1,
    zk_ams_mkhe_wire_evidence_v1,
};
#[cfg(test)]
pub use noise::ZkAmsMkheNoiseCertificateV1;
pub use noise_feasibility::{
    ZkAmsMkheCksNoiseInputV1, ZkAmsMkheFailureAllocationV1, ZkAmsMkheNoiseAccountingV1,
    ZkAmsMkheNoiseAdmissionV1, ZkAmsMkheNoiseConstructionV1, ZkAmsMkheNoiseFeasibilityV1,
    ZkAmsMkhePhaseNoiseBoundsV1, ZkAmsMkheSmudgePurposeV1, ZkAmsMkheSmudgeQueriesV1,
    ZkAmsMkheTerminalFeasibilityV1, zk_ams_mkhe_noise_feasibility_v1,
};
#[cfg(test)]
pub use packing::{
    ZK_AMS_T256_GALOIS_KEY_COUNT_V1, ZK_AMS_T256_GALOIS_KEY_SCHEDULE_DIGEST_V1,
    ZK_AMS_T256_MAX_LOGICAL_VALUES_V1, ZK_AMS_T256_RELEASE_PACKED_INPUT_KAT_DIGEST_V1,
    ZK_AMS_T256_RELEASE_PACKED_OUTPUT_KAT_DIGEST_V1,
    ZK_AMS_T256_RELEASE_PACKING_NEGATIVE_CASE_COUNT_V1,
    ZK_AMS_T256_RELEASE_PACKING_NEGATIVE_KAT_DIGEST_V1,
    ZK_AMS_T256_RELEASE_ROTATION_CERTIFICATE_KAT_DIGEST_V1,
    ZK_AMS_T256_RELEASE_TRANSFORMED_RNS_KAT_DIGEST_V1, ZkAmsT256GaloisKeyScheduleEntryV1,
    ZkAmsT256GaloisKeyScheduleV1, ZkAmsT256PackingLayoutV1, ZkAmsT256ReleasePackingCertificateV1,
    ZkAmsT256RotationDirectionV1, ZkAmsT256RotationV1, zk_ams_t256_galois_key_schedule_v1,
    zk_ams_t256_packed_subfield_conjugation_exponent_v1, zk_ams_t256_packing_layout_v1,
    zk_ams_t256_release_packing_certificate_v1, zk_ams_t256_rotation_exponent_for_direction_v1,
    zk_ams_t256_rotation_v1,
};
#[cfg(test)]
pub use packing::{
    ZkAmsT256PackedPlaintextV1, ZkAmsT256RotationCertificateV1,
    decode_zk_ams_t256_packed_plaintext_v1, encode_zk_ams_t256_packed_plaintext_v1,
    permute_zk_ams_t256_slots_v1, rotate_zk_ams_t256_packed_plaintext_v1,
    validate_zk_ams_t256_galois_key_exponents_v1, validate_zk_ams_t256_galois_key_schedule_v1,
    zk_ams_t256_rotation_certificate_v1, zk_ams_t256_rotation_exponent_v1,
    zk_ams_t256_rotation_key_plan_v1,
};
#[cfg(test)]
pub use persistent_decryption_equality::{
    ZkAmsMkhePersistentDecryptionPartyUseV1, ZkAmsMkhePersistentDecryptionVerificationContextV1,
    ZkAmsMkheStreamingDecryptionAuthorityV1,
};
#[cfg(test)]
pub use phase23::{
    ZkAmsPhase23EquationCertificateV1, zk_ams_phase23_equation_certificate_digest_v1,
    zk_ams_phase23_equation_certificate_v1,
};
#[cfg(test)]
pub use phase23::{
    zk_ams_phase23_cross_term_v1, zk_ams_phase23_fold_linear_v1, zk_ams_phase23_fold_quadratic_v1,
};
#[cfg(test)]
pub use phase23_encrypted::{
    ZK_AMS_PHASE23_MAX_CANONICAL_SPARSE_ENTRIES_V1,
    ZK_AMS_PHASE23_RELEASE_ERROR_COMMITMENT_ROWS_V1, ZK_AMS_PHASE23_RELEASE_PUBLIC_INPUT_COUNT_V1,
    ZK_AMS_PHASE23_RELEASE_WITNESS_COMMITMENT_ROWS_V1, ZkAmsPhase23EncryptedImplementationV1,
    zk_ams_phase23_encrypted_implementation_v1,
};
#[cfg(test)]
pub use phase23_encrypted::{
    ZK_AMS_PHASE23_RELEASE_MAP_SET_KAT_DIGEST_V1, ZkAmsPhase23AccumulatorShapeV1,
    ZkAmsPhase23CommitmentPreimageLayoutV1, ZkAmsPhase23CrossTermCommitmentV1,
    ZkAmsPhase23EncryptedBindingV1, ZkAmsPhase23MapKindV1, ZkAmsPhase23MaterializedAccumulatorsV1,
    ZkAmsPhase23PublicAccumulatorV1, ZkAmsPhase23PublicFoldHistoryV1,
    ZkAmsPhase23PublicFoldRecordV1, ZkAmsPhase23ReleaseMapManifestV1,
    ZkAmsPhase23SparseMapManifestV1, ZkAmsPhase23SparseMapV1, ZkAmsPhase23StrictPublicInstanceV1,
    zk_ams_phase23_materialize_release_accumulator_chunks_v1,
    zk_ams_phase23_release_map_manifest_v1, zk_ams_phase23_release_map_set_digest_v1,
};
#[cfg(test)]
pub use phase23_ingress::{
    ZK_AMS_PHASE23_FRESHNESS_CERTIFIES_HIDDEN_MASK_SHARES_V1,
    ZK_AMS_PHASE23_FRESHNESS_COMMIT_WIRE_BYTES_V1, ZK_AMS_PHASE23_FRESHNESS_RECEIPT_WIRE_BYTES_V1,
    ZK_AMS_PHASE23_FRESHNESS_REVEAL_WIRE_BYTES_V1, ZkAmsPhase23FreshnessCommitV1,
    ZkAmsPhase23FreshnessContextV1, ZkAmsPhase23FreshnessPhaseV1, ZkAmsPhase23FreshnessReceiptV1,
    ZkAmsPhase23FreshnessRevealV1, ZkAmsPhase23PendingRevealV1,
    ZkAmsPhase23PublicChallengeFamilyV1, ZkAmsPhase23PublicChallengeRoleV1,
    ZkAmsPhase23PublicChallengeV1, ZkAmsPhase23VerifiedCommitSetV1,
    commit_zk_ams_phase23_freshness_v1, finalize_zk_ams_phase23_freshness_v1,
    open_zk_ams_phase23_freshness_reveal_v1,
};
#[cfg(test)]
pub use phase23_materialized_wire::{
    read_zk_ams_phase23_materialized_accumulators_canonical_exact_v1,
    write_zk_ams_phase23_materialized_accumulators_canonical_v1,
};
#[cfg(test)]
pub use release_evidence::{
    ZK_AMS_MKHE_RELEASE_KAT_EVIDENCE_BYTES_V1, ZK_AMS_MKHE_RESOURCE_EVIDENCE_BYTES_V1,
    ZK_AMS_MKHE_WIRE_EVIDENCE_BYTES_V1,
};
#[cfg(test)]
pub use release_evidence::{
    ZkAmsMkheReleaseKatEvidenceV1, ZkAmsMkheResourceEvidenceV1, ZkAmsMkheWireEvidenceV1,
};
#[cfg(test)]
pub use resource::ZkAmsMkheResourceCertificateV1;
#[cfg(test)]
pub use rns_native_composite_verifier::{
    ZK_AMS_MKHE_RNS_NATIVE_COMPOSITE_VERIFICATION_VERSION_V1,
    ZkAmsMkheRnsNativeCompositeCandidateReceiptV1, ZkAmsMkheRnsNativeCompositeVerificationErrorV1,
    ZkAmsMkheRnsNativeVerificationStageV1, verify_zk_ams_mkhe_rns_native_composite_v1,
};
#[cfg(test)]
pub use rns_native_profile::{
    ZK_AMS_MKHE_RNS_NATIVE_CENTERED_CAPACITY_BITS_V1,
    ZK_AMS_MKHE_RNS_NATIVE_CORRELATED_FRI_MAX_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_CROSS_FIELD_POINT_COUNT_V1, ZK_AMS_MKHE_RNS_NATIVE_FAMILY_COUNT_V1,
    ZK_AMS_MKHE_RNS_NATIVE_FAMILY_ORDER_V1, ZK_AMS_MKHE_RNS_NATIVE_FRI_ROUNDS_V1,
    ZK_AMS_MKHE_RNS_NATIVE_HEADROOM_BITS_V1,
    ZK_AMS_MKHE_RNS_NATIVE_INITIAL_MULTIPROOF_MAX_BYTES_V1, ZK_AMS_MKHE_RNS_NATIVE_IO_MAX_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_LDE_DOMAIN_LOG2_V1, ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1,
    ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1, ZK_AMS_MKHE_RNS_NATIVE_MODULUS_BITS_V1,
    ZK_AMS_MKHE_RNS_NATIVE_NEGACYCLIC_ROOTS_V1, ZK_AMS_MKHE_RNS_NATIVE_OPENING_COUNT_V1,
    ZK_AMS_MKHE_RNS_NATIVE_PROOF_MAX_BYTES_V1, ZK_AMS_MKHE_RNS_NATIVE_QPCS_MAX_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_QUERY_COUNT_V1, ZK_AMS_MKHE_RNS_NATIVE_QUOTIENT_BITS_V1,
    ZK_AMS_MKHE_RNS_NATIVE_RADIX_LOG2_V1, ZK_AMS_MKHE_RNS_NATIVE_RESIDUAL_BITS_V1,
    ZK_AMS_MKHE_RNS_NATIVE_RLWE_EQUATION_COUNT_V1, ZK_AMS_MKHE_RNS_NATIVE_SPOOL_MAX_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SUMCHECK_ROUNDS_V1, ZK_AMS_MKHE_RNS_NATIVE_TARGET_SECURITY_BITS_V1,
    ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1, ZK_AMS_MKHE_RNS_NATIVE_WORKSPACE_MAX_BYTES_V1,
    ZkAmsMkheRnsNativeFamilyV1, ZkAmsMkheRnsNativeProfileV1, ZkAmsMkheRnsNativeTopologyV1,
};
#[cfg(test)]
pub use rns_native_profile::{
    ZK_AMS_MKHE_RNS_NATIVE_PROFILE_MANIFEST_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_WIDE_RESPONSE_BYTES_V1, ZkAmsMkheRnsNativeProfileManifestV1,
    zk_ams_mkhe_rns_native_profile_manifest_v1,
};
pub use rns_native_profile::{
    zk_ams_mkhe_rns_native_profile_v1, zk_ams_mkhe_rns_native_topology_v1,
};
pub use rns_native_proof_hash::RnsNativeProofDigestV1;
#[cfg(test)]
pub use rns_native_section_codec::{
    ZK_AMS_MKHE_RNS_NATIVE_SECTION_CODEC_VERSION_V1,
    ZkAmsMkheRnsNativeCrossFieldGlobalLookupSectionV1, ZkAmsMkheRnsNativeRnsRelationQpcsSectionV1,
    ZkAmsMkheRnsNativeSectionCodecErrorV1, ZkAmsMkheRnsNativeTerminalBridgeSectionV1,
};
#[cfg(test)]
pub use rns_native_source::{
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_MAIN_BLOCKS_PER_OPENING_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_MAIN_FILE_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_MAIN_PLAINTEXT_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_MAIN_SLOTS_V1, ZK_AMS_MKHE_RNS_NATIVE_SOURCE_NONCE_FILE_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_NONCE_PLAINTEXT_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_NONCE_SLOTS_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_TOTAL_FILE_BYTES_V1, ZK_AMS_MKHE_RNS_NATIVE_SOURCE_VERSION_V1,
    ZkAmsMkheRnsNativeSourceReceiptV1,
};
pub use rns_native_source::{
    ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1, ZkAmsMkheRnsNativeSecretChunkV1,
    ZkAmsMkheRnsNativeSourceArenaV1, ZkAmsMkheRnsNativeSourceErrorV1,
    ZkAmsMkheRnsNativeSourceLayoutV1, ZkAmsMkheRnsNativeSourceProviderV1,
    ZkAmsMkheRnsNativeSourceSnapshotV1, ZkAmsMkheRnsNativeSourceWriterV1,
};
pub use rns_native_transcript::ZkAmsMkheRnsNativeTerminalRootsV1;
#[cfg(test)]
pub use rns_native_transcript::{
    ZK_AMS_MKHE_RNS_NATIVE_QPCS_ROOT_COUNT_V1,
    ZK_AMS_MKHE_RNS_NATIVE_TRANSCRIPT_CHALLENGE_COUNT_V1, ZkAmsMkheRnsNativeChallengeSeedsV1,
    ZkAmsMkheRnsNativeOpeningCommitmentV1, ZkAmsMkheRnsNativeQpcsFriRootV1,
    ZkAmsMkheRnsNativeTranscriptErrorV1,
};
#[cfg(test)]
pub use rns_native_transcript::{
    ZK_AMS_MKHE_RNS_NATIVE_TRANSCRIPT_VERSION_V1, ZkAmsMkheRnsNativeCommitmentsBoundTranscriptV1,
    ZkAmsMkheRnsNativeOpeningCommitmentsV1, ZkAmsMkheRnsNativePublicContextV1,
    ZkAmsMkheRnsNativeQpcsBoundTranscriptV1, ZkAmsMkheRnsNativeQpcsRootsV1,
    ZkAmsMkheRnsNativeTerminalBoundTranscriptV1, ZkAmsMkheRnsNativeTerminalBridgeV1,
    ZkAmsMkheRnsNativeTranscriptV1,
};
#[cfg(test)]
pub use rns_native_wire::{
    ZK_AMS_MKHE_RNS_NATIVE_CROSS_FIELD_LOOKUP_SECTION_MAX_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_PROOF_ENVELOPE_HEADER_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_PROOF_ENVELOPE_MAX_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_PROOF_SECTION_COUNT_V1,
    ZK_AMS_MKHE_RNS_NATIVE_RNS_RELATION_QPCS_SECTION_MAX_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_TERMINAL_BRIDGE_SECTION_MAX_BYTES_V1,
    ZkAmsMkheRnsNativeProofSectionKindV1,
};
#[cfg(test)]
pub use rns_native_wire::{
    ZK_AMS_MKHE_RNS_NATIVE_PROOF_ENVELOPE_VERSION_V1,
    ZK_AMS_MKHE_RNS_NATIVE_PROOF_SECTION_ORDER_V1, ZkAmsMkheRnsNativeProofEnvelopeV1,
    ZkAmsMkheRnsNativeProofSectionDescriptorV1,
};
#[cfg(test)]
pub use security::{
    ZkAmsMkheSecurityAttackRecordV1, ZkAmsMkheSecurityAttackV1, ZkAmsMkheSecurityCandidateV1,
    ZkAmsMkheSecurityCertificateV1, ZkAmsMkheSecurityEstimatorSuiteV1,
};
#[cfg(test)]
pub use terminal::{
    ZK_AMS_PHASE3_MAX_TERMINAL_PROOF_BYTES_V1, ZkAmsPhase3TerminalImplementationV1,
    zk_ams_phase3_terminal_implementation_v1,
};
#[cfg(test)]
pub use terminal::{
    ZkAmsPhase3BatchAnchorV1, ZkAmsPhase3FoldHistoryV1, ZkAmsPhase3GovernedBatchV1,
    ZkAmsPhase3TerminalContextV1, ZkAmsPhase3TerminalProverOutputV1, ZkAmsPhase3TerminalReceiptV1,
    prove_zk_ams_phase3_terminal_v1, verify_zk_ams_phase3_terminal_v1,
    zk_ams_phase3_nifs_verifier_digest_v1, zk_ams_phase3_ordered_public_inputs_digest_v1,
};
#[cfg(test)]
pub use wire::ZK_AMS_MKHE_MAX_PROOF_BYTES_V1;
#[cfg(test)]
pub use wire::{
    ZkAmsMkheAuthenticationWireV1, ZkAmsMkheCksContributionWireV1,
    ZkAmsMkheCollectiveCiphertextWireV1, ZkAmsMkheGovernedRosterWireV1,
    ZkAmsMkheProofEnvelopeWireV1, ZkAmsMkheProofKindV1, ZkAmsMkheRnsPolynomialWireV1,
    ZkAmsMkheWireBindingV1, zk_ams_mkhe_cks_statement_digest_v1,
};
const MKHE_VERSION_V1: u8 = 1;
const MAX_PARTIES_V1: usize = 8;
const MAX_RNS_LIMBS_V1: usize = 64;
const MAX_RING_DEGREE_V1: usize = 1 << 21;
const MAX_GADGET_DIGITS_V1: usize = 128;
const PARTY_ID_BYTES_V1: usize = 32;
#[cfg(test)]
const SCHNORR_SIGNATURE_BYTES_V1: usize = 65;
const MAX_RANDOM_REJECTION_ATTEMPTS_V1: usize = 128;
#[cfg(test)]
const MAX_TERNARY_SAMPLE_BYTES_PER_COEFFICIENT_V1: usize = 16;
#[cfg(test)]
const AUTH_GENERATOR_LABEL_V1: &[u8] = b"iroha.zk-ams.v1.mkhe-auth-t256";
#[cfg(test)]
const AUTHENTICATION_CHALLENGE_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.schnorr-authentication";
#[cfg(test)]
const AUTHENTICATION_CHALLENGE_MAX_FRAME_BYTES_V1: usize =
    AUTHENTICATION_CHALLENGE_DOMAIN_V1.len() + 1 + u8::MAX as usize + 32 + 32 + 33 + 33;
#[cfg(test)]
const T256_CENTERED_MAX_BE_V1: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];
#[cfg(test)]
static MKHE_AUTH_GENERATOR: Lazy<Result<VegaT256PointV1, ZkAmsMkheErrorV1>> = Lazy::new(|| {
    derive_t256_generators_v1(AUTH_GENERATOR_LABEL_V1, 1)
        .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
        .into_iter()
        .next()
        .ok_or(ZkAmsMkheErrorV1::InvalidProfile)
});
/// Failure at the canonical ZK-AMS multi-key BGV boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ZkAmsMkheErrorV1 {
    /// A governed profile is structurally or algebraically invalid.
    #[error("invalid ZK-AMS MKHE profile")]
    InvalidProfile,
    /// A count, byte length, or work estimate exceeds a governed ceiling.
    #[error("ZK-AMS MKHE resource ceiling exceeded")]
    ResourceCeilingExceeded,
    /// A party set is empty, unsorted, duplicated, or exceeds the party cap.
    #[error("invalid canonical ZK-AMS MKHE party set")]
    InvalidPartySet,
    /// A polynomial has a wrong dimension or a non-canonical RNS residue.
    #[error("invalid canonical ZK-AMS MKHE RNS polynomial")]
    InvalidPolynomial,
    /// Key material is malformed or bound to a different profile/party set.
    #[error("invalid or mismatched ZK-AMS MKHE key material")]
    InvalidKeyMaterial,
    /// Ciphertexts are malformed, mismatched, or at an unsupported level.
    #[error("invalid or mismatched ZK-AMS MKHE ciphertext")]
    InvalidCiphertext,
    /// Required key-extension or relinearization material is absent.
    #[error("missing ZK-AMS MKHE evaluated key material")]
    MissingEvaluatedKey,
    /// An authenticated artifact has a malformed or invalid signature.
    #[error("invalid ZK-AMS MKHE artifact authentication")]
    InvalidAuthentication,
    /// A partial-decryption proof is malformed or does not verify.
    #[error("invalid ZK-AMS MKHE decryption-share proof")]
    InvalidShareProof,
    /// A collective-key-switch proof is malformed or does not verify.
    #[error("invalid ZK-AMS MKHE collective-key-switch proof")]
    InvalidCksProof,
    /// A required collective-key-switch contribution is absent, duplicated, or spliced.
    #[error("invalid ZK-AMS MKHE collective-key-switch contribution set")]
    InvalidCksSet,
    /// A required party share is missing, duplicated, or spliced from another transcript.
    #[error("invalid ZK-AMS MKHE decryption-share set")]
    InvalidShareSet,
    /// The exact centered decryption representative exceeds the proven bound.
    #[error("ZK-AMS MKHE decryption correctness bound exceeded")]
    DecryptionBoundExceeded,
    /// Phase-II/III vectors, commitments, or transcript bindings are malformed.
    #[error("invalid ZK-AMS Phase-II/III fold")]
    InvalidPhase23Fold,
    /// The caller-provided cryptographic random source failed.
    #[error("ZK-AMS MKHE cryptographic random source unavailable")]
    RandomUnavailable,
    /// The complete governed Phase II/III release gates have not all closed.
    #[error("ZK-AMS MKHE Phase II/III release profile is unavailable")]
    ReleaseUnavailable,
    /// Canonical MKHE wire bytes are malformed, non-canonical, or mismatched.
    #[error("invalid canonical ZK-AMS MKHE wire encoding")]
    InvalidWireEncoding,
    /// An MKHE wire artifact exceeds its exact governed byte ceiling.
    #[error("ZK-AMS MKHE wire artifact exceeds its governed byte ceiling")]
    WireTooLarge,
}
/// Canonical participant identifier used to order every multi-key component.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZkAmsMkhePartyIdV1([u8; PARTY_ID_BYTES_V1]);
#[cfg(test)]
impl ZkAmsMkhePartyIdV1 {
    /// Construct a nonzero participant identifier.
    pub fn new(bytes: [u8; PARTY_ID_BYTES_V1]) -> Result<Self, ZkAmsMkheErrorV1> {
        if bytes == [0; PARTY_ID_BYTES_V1] {
            return Err(ZkAmsMkheErrorV1::InvalidPartySet);
        }
        Ok(Self(bytes))
    }
    /// Return the exact identifier bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; PARTY_ID_BYTES_V1] {
        self.0
    }
    fn from_authentication_key(public_key: &[u8; 33]) -> Result<Self, ZkAmsMkheErrorV1> {
        let mut hash = Keccak256::new();
        hash.update(b"iroha.zk-ams.v1.mkhe.authentication-party-id");
        hash.update(public_key);
        Self::new(hash.finalize())
    }
}
#[cfg(test)]
impl fmt::Debug for ZkAmsMkhePartyIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ZkAmsMkhePartyIdV1")
            .field(&hex::encode(self.0))
            .finish()
    }
}
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct PartySet {
    parties: Vec<ZkAmsMkhePartyIdV1>,
    digest: [u8; 32],
}
#[cfg(test)]
impl PartySet {
    fn new(parties: Vec<ZkAmsMkhePartyIdV1>) -> Result<Self, ZkAmsMkheErrorV1> {
        if parties.is_empty()
            || parties.len() > MAX_PARTIES_V1
            || parties.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ZkAmsMkheErrorV1::InvalidPartySet);
        }
        let digest = party_set_digest(&parties)?;
        Ok(Self { parties, digest })
    }
    #[cfg(test)]
    fn singleton(party: ZkAmsMkhePartyIdV1) -> Self {
        Self::new(vec![party]).expect("one nonzero party is canonical")
    }
    #[cfg(test)]
    fn union(&self, rhs: &Self) -> Result<Self, ZkAmsMkheErrorV1> {
        let mut parties = Vec::with_capacity(self.parties.len() + rhs.parties.len());
        let mut left = self.parties.iter().copied().peekable();
        let mut right = rhs.parties.iter().copied().peekable();
        loop {
            match (left.peek().copied(), right.peek().copied()) {
                (Some(a), Some(b)) => match a.cmp(&b) {
                    Ordering::Less => {
                        parties.push(a);
                        left.next();
                    }
                    Ordering::Greater => {
                        parties.push(b);
                        right.next();
                    }
                    Ordering::Equal => {
                        parties.push(a);
                        left.next();
                        right.next();
                    }
                },
                (Some(a), None) => {
                    parties.push(a);
                    left.next();
                }
                (None, Some(b)) => {
                    parties.push(b);
                    right.next();
                }
                (None, None) => break,
            }
        }
        Self::new(parties)
    }
    fn index_of(&self, party: ZkAmsMkhePartyIdV1) -> Option<usize> {
        self.parties.binary_search(&party).ok()
    }
}
#[cfg(test)]
fn party_set_digest(parties: &[ZkAmsMkhePartyIdV1]) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let count = u8::try_from(parties.len()).map_err(|_| ZkAmsMkheErrorV1::InvalidPartySet)?;
    let mut hash = Keccak256::new();
    hash.update(b"iroha.zk-ams.v1.mkhe.ordered-party-set");
    hash.update(&[count]);
    for party in parties {
        hash.update(&party.0);
    }
    Ok(hash.finalize())
}
#[cfg(test)]
struct AuthenticationSecret {
    scalar_be: [u8; 32],
}
#[cfg(test)]
impl AuthenticationSecret {
    fn generate<R: MaskedRelaxedRandomSourceV1>(random: &mut R) -> Result<Self, ZkAmsMkheErrorV1> {
        for _ in 0..MAX_RANDOM_REJECTION_ATTEMPTS_V1 {
            let scalar = random_scalar(random)?;
            if !scalar.as_ref().is_zero() {
                return Ok(Self {
                    scalar_be: scalar.expose_copy().to_be_bytes(),
                });
            }
        }
        Err(ZkAmsMkheErrorV1::RandomUnavailable)
    }
    fn scalar(&self) -> Result<ZeroizingScalarV1, ZkAmsMkheErrorV1> {
        Scalar::from_be_bytes_exact(self.scalar_be)
            .map(ZeroizingScalarV1::new)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidAuthentication)
    }
    fn public_key(&self) -> Result<[u8; 33], ZkAmsMkheErrorV1> {
        let scalar = self.scalar()?;
        auth_generator()?
            .mul_scalar(scalar.expose_copy())
            .to_non_identity_wire_bytes()
            .map_err(|_| ZkAmsMkheErrorV1::InvalidAuthentication)
    }
    fn party_id(&self) -> Result<ZkAmsMkhePartyIdV1, ZkAmsMkheErrorV1> {
        ZkAmsMkhePartyIdV1::from_authentication_key(&self.public_key()?)
    }
}
#[cfg(test)]
impl Drop for AuthenticationSecret {
    fn drop(&mut self) {
        let bytes = core::hint::black_box(&mut self.scalar_be);
        bytes.fill(0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(&mut *bytes);
    }
}
#[cfg(test)]
impl fmt::Debug for AuthenticationSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticationSecret([REDACTED])")
    }
}
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct ArtifactAuthentication {
    version: u8,
    party: ZkAmsMkhePartyIdV1,
    public_key: [u8; 33],
    signature: [u8; SCHNORR_SIGNATURE_BYTES_V1],
}
#[cfg(test)]
impl ArtifactAuthentication {
    fn sign<R: MaskedRelaxedRandomSourceV1>(
        domain: &[u8],
        transcript_digest: [u8; 32],
        secret: &AuthenticationSecret,
        random: &mut R,
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        if domain.is_empty() || domain.len() > u8::MAX.into() || transcript_digest == [0; 32] {
            return Err(ZkAmsMkheErrorV1::InvalidAuthentication);
        }
        let public_key = secret.public_key()?;
        let party = secret.party_id()?;
        let mut nonce = None;
        for _ in 0..MAX_RANDOM_REJECTION_ATTEMPTS_V1 {
            let candidate = random_scalar(random)?;
            if !candidate.as_ref().is_zero() {
                nonce = Some(candidate);
                break;
            }
        }
        let nonce = nonce.ok_or(ZkAmsMkheErrorV1::RandomUnavailable)?;
        let commitment = auth_generator()?.mul_scalar(nonce.expose_copy());
        let commitment_bytes = commitment
            .to_non_identity_wire_bytes()
            .map_err(|_| ZkAmsMkheErrorV1::InvalidAuthentication)?;
        let challenge = authentication_challenge(
            domain,
            transcript_digest,
            party,
            &public_key,
            &commitment_bytes,
        )?;
        let secret_scalar = secret.scalar()?;
        let response = nonce.expose_copy() + challenge * secret_scalar.expose_copy();
        let mut signature = [0_u8; SCHNORR_SIGNATURE_BYTES_V1];
        signature[..33].copy_from_slice(&commitment_bytes);
        signature[33..].copy_from_slice(&response.to_be_bytes());
        let authentication = Self {
            version: MKHE_VERSION_V1,
            party,
            public_key,
            signature,
        };
        authentication.verify(domain, transcript_digest)?;
        Ok(authentication)
    }
    fn verify(&self, domain: &[u8], transcript_digest: [u8; 32]) -> Result<(), ZkAmsMkheErrorV1> {
        if self.version != MKHE_VERSION_V1
            || domain.is_empty()
            || domain.len() > u8::MAX.into()
            || transcript_digest == [0; 32]
            || self.party != ZkAmsMkhePartyIdV1::from_authentication_key(&self.public_key)?
        {
            return Err(ZkAmsMkheErrorV1::InvalidAuthentication);
        }
        let public_key = VegaT256PointV1::from_non_identity_wire_bytes_exact(&self.public_key)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidAuthentication)?;
        let commitment = VegaT256PointV1::from_non_identity_wire_bytes_exact(&self.signature[..33])
            .map_err(|_| ZkAmsMkheErrorV1::InvalidAuthentication)?;
        let response_bytes: [u8; 32] = self.signature[33..]
            .try_into()
            .map_err(|_| ZkAmsMkheErrorV1::InvalidAuthentication)?;
        let response = Scalar::from_be_bytes_exact(response_bytes)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidAuthentication)?;
        let challenge = authentication_challenge(
            domain,
            transcript_digest,
            self.party,
            &self.public_key,
            &self.signature[..33]
                .try_into()
                .map_err(|_| ZkAmsMkheErrorV1::InvalidAuthentication)?,
        )?;
        if auth_generator()?.mul_scalar(response) != commitment + public_key.mul_scalar(challenge) {
            return Err(ZkAmsMkheErrorV1::InvalidAuthentication);
        }
        Ok(())
    }
}
#[cfg(test)]
fn auth_generator() -> Result<VegaT256PointV1, ZkAmsMkheErrorV1> {
    MKHE_AUTH_GENERATOR
        .as_ref()
        .copied()
        .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)
}
#[cfg(test)]
fn authentication_challenge(
    domain: &[u8],
    transcript_digest: [u8; 32],
    party: ZkAmsMkhePartyIdV1,
    public_key: &[u8; 33],
    commitment: &[u8; 33],
) -> Result<Scalar, ZkAmsMkheErrorV1> {
    let domain_len =
        u8::try_from(domain.len()).map_err(|_| ZkAmsMkheErrorV1::InvalidAuthentication)?;
    let domain_len = [domain_len];
    let mut frame = [0_u8; AUTHENTICATION_CHALLENGE_MAX_FRAME_BYTES_V1];
    let mut cursor = 0;
    for bytes in [
        AUTHENTICATION_CHALLENGE_DOMAIN_V1,
        &domain_len,
        domain,
        &transcript_digest,
        &party.0,
        public_key,
        commitment,
    ] {
        let end = cursor + bytes.len();
        frame[cursor..end].copy_from_slice(bytes);
        cursor = end;
    }
    let mut uniform = [0_u8; 64];
    Shake256Reader::new(&frame[..cursor]).read(&mut uniform);
    Ok(Scalar::from_uniform_le_bytes(uniform))
}
#[cfg(test)]
fn random_scalar<R: MaskedRelaxedRandomSourceV1>(
    random: &mut R,
) -> Result<ZeroizingScalarV1, ZkAmsMkheErrorV1> {
    let mut uniform = ZeroizingScalarEntropyV1::zeroed();
    random
        .fill_bytes(uniform.as_mut_slice())
        .map_err(|_| ZkAmsMkheErrorV1::RandomUnavailable)?;
    Ok(ZeroizingScalarV1::new(Scalar::from_uniform_le_bytes_ref(
        uniform.as_array(),
    )))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PlaintextModulus {
    T256,
    #[cfg(test)]
    Tiny(u64),
}
impl PlaintextModulus {
    fn digest_bytes(self) -> [u8; 32] {
        match self {
            Self::T256 => VEGA_T256_SCALAR_MODULUS_BE_V1,
            #[cfg(test)]
            Self::Tiny(value) => {
                let mut bytes = [0_u8; 32];
                bytes[24..].copy_from_slice(&value.to_be_bytes());
                bytes
            }
        }
    }
    fn residue(self, modulus: u64) -> u64 {
        match self {
            Self::T256 => iroha_fhe::modular::reduce_be_bytes_mod_u64(
                &VEGA_T256_SCALAR_MODULUS_BE_V1,
                modulus,
            ),
            #[cfg(test)]
            Self::Tiny(value) => value % modulus,
        }
    }
}
#[derive(Clone, Debug)]
struct BgvProfile {
    profile_id: [u8; 32],
    ring_degree: usize,
    moduli: &'static [u64],
    negacyclic_roots: &'static [u64],
    plaintext_modulus: PlaintextModulus,
    error_eta: u8,
    hybrid_rns_decomposition: bool,
    gadget_base_log: u8,
    gadget_digits: usize,
    max_ciphertext_bytes: usize,
    max_evaluated_key_bytes: usize,
    max_round_bytes: usize,
    max_share_bytes: usize,
    max_workspace_bytes: usize,
    max_work_units: u64,
}
impl BgvProfile {
    fn validate(&self) -> Result<(), ZkAmsMkheErrorV1> {
        if self.profile_id == [0; 32]
            || self.ring_degree < 2
            || self.ring_degree > MAX_RING_DEGREE_V1
            || !self.ring_degree.is_power_of_two()
            || self.moduli.is_empty()
            || self.moduli.len() > MAX_RNS_LIMBS_V1
            || self.moduli.len() != self.negacyclic_roots.len()
            || self.error_eta == 0
            || self.error_eta > 32
            || !(2..=60).contains(&self.gadget_base_log)
            || self.gadget_digits == 0
            || self.gadget_digits > MAX_GADGET_DIGITS_V1
            || self.max_ciphertext_bytes == 0
            || self.max_evaluated_key_bytes == 0
            || self.max_round_bytes == 0
            || self.max_share_bytes == 0
            || self.max_workspace_bytes == 0
            || self.max_work_units == 0
        {
            return Err(ZkAmsMkheErrorV1::InvalidProfile);
        }
        let twice_degree = u64::try_from(self.ring_degree)
            .ok()
            .and_then(|degree| degree.checked_mul(2))
            .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
        for (index, (&modulus, &root)) in self.moduli.iter().zip(self.negacyclic_roots).enumerate()
        {
            if !(3..(1_u64 << 62)).contains(&modulus)
                || modulus % twice_degree != 1
                || !iroha_fhe::modular::is_prime_u64(modulus)
                || root <= 1
                || root >= modulus
                || iroha_fhe::modular::mod_pow_u64(root, twice_degree, modulus) != 1
                || iroha_fhe::modular::mod_pow_u64(
                    root,
                    u64::try_from(self.ring_degree)
                        .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
                    modulus,
                ) != modulus - 1
                || self.moduli[..index].contains(&modulus)
                || self.plaintext_modulus.residue(modulus) == 0
            {
                return Err(ZkAmsMkheErrorV1::InvalidProfile);
            }
        }
        if checked_linear_ciphertext_bytes(self, 1)? > self.max_ciphertext_bytes {
            return Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded);
        }
        let minimum_digits = if self.hybrid_rns_decomposition {
            if self.gadget_base_log != 60 {
                return Err(ZkAmsMkheErrorV1::InvalidProfile);
            }
            self.moduli.len()
        } else {
            modulus_product_bit_len(self.moduli)?.div_ceil(usize::from(self.gadget_base_log))
        };
        if self.gadget_digits != minimum_digits {
            return Err(ZkAmsMkheErrorV1::InvalidProfile);
        }
        let workspace_bytes = if self.hybrid_rns_decomposition {
            checked_hybrid_streaming_workspace_bytes(self)?
        } else {
            checked_gadget_decomposition_workspace_bytes(self)?
        };
        if workspace_bytes > self.max_workspace_bytes {
            return Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded);
        }
        Ok(())
    }
    fn digest(&self) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
        self.validate()?;
        let mut hash = native_outer_identity_v1(
            NativeOuterIdentityRoleV1::Parameter,
            b"iroha.zk-ams.v1.mkhe.rns-bgv-profile",
            14 + 2 * self.moduli.len(),
        );
        hash.push_field(&self.profile_id)
            .expect("fixed bounded MKHE identity field");
        hash.push_field(
            &u32::try_from(self.ring_degree)
                .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
                .to_be_bytes(),
        )
        .expect("fixed bounded MKHE identity field");
        hash.push_field(&[
            u8::try_from(self.moduli.len()).map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
        ])
        .expect("fixed bounded MKHE identity field");
        for (&modulus, &root) in self.moduli.iter().zip(self.negacyclic_roots) {
            hash.push_field(&modulus.to_be_bytes())
                .expect("fixed bounded MKHE identity field");
            hash.push_field(&root.to_be_bytes())
                .expect("fixed bounded MKHE identity field");
        }
        hash.push_field(&self.plaintext_modulus.digest_bytes())
            .expect("fixed bounded MKHE identity field");
        hash.push_field(&[self.error_eta])
            .expect("fixed bounded MKHE identity field");
        hash.push_field(&[self.hybrid_rns_decomposition.into()])
            .expect("fixed bounded MKHE identity field");
        hash.push_field(&[self.gadget_base_log])
            .expect("fixed bounded MKHE identity field");
        hash.push_field(
            &u16::try_from(self.gadget_digits)
                .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
                .to_be_bytes(),
        )
        .expect("fixed bounded MKHE identity field");
        hash.push_field(
            &u64::try_from(self.max_ciphertext_bytes)
                .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
                .to_be_bytes(),
        )
        .expect("fixed bounded MKHE identity field");
        hash.push_field(
            &u64::try_from(self.max_evaluated_key_bytes)
                .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
                .to_be_bytes(),
        )
        .expect("fixed bounded MKHE identity field");
        hash.push_field(
            &u64::try_from(self.max_round_bytes)
                .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
                .to_be_bytes(),
        )
        .expect("fixed bounded MKHE identity field");
        hash.push_field(
            &u64::try_from(self.max_share_bytes)
                .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
                .to_be_bytes(),
        )
        .expect("fixed bounded MKHE identity field");
        hash.push_field(
            &u64::try_from(self.max_workspace_bytes)
                .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
                .to_be_bytes(),
        )
        .expect("fixed bounded MKHE identity field");
        hash.push_field(&self.max_work_units.to_be_bytes())
            .expect("fixed bounded MKHE identity field");
        Ok(*hash
            .finish()
            .expect("exact MKHE outer identity field count")
            .as_bytes())
    }
    /// Digest only the algebraic and distribution parameters consumed by the
    /// concrete RLWE security analysis.
    ///
    /// Operational byte, memory, and work ceilings are deliberately excluded: changing a deployment
    /// limit must not invalidate an estimator result for unchanged mathematics. The complete
    /// wire/profile identity remains [`Self::digest`].
    fn security_parameters_digest(&self) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
        self.validate()?;
        let mut hash = native_outer_identity_v1(
            NativeOuterIdentityRoleV1::Parameter,
            b"iroha.zk-ams.v1.mkhe.rns-bgv-security-parameters",
            8 + 2 * self.moduli.len(),
        );
        hash.push_field(&self.profile_id)
            .expect("fixed bounded MKHE identity field");
        hash.push_field(
            &u32::try_from(self.ring_degree)
                .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
                .to_be_bytes(),
        )
        .expect("fixed bounded MKHE identity field");
        hash.push_field(&[
            u8::try_from(self.moduli.len()).map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
        ])
        .expect("fixed bounded MKHE identity field");
        for (&modulus, &root) in self.moduli.iter().zip(self.negacyclic_roots) {
            hash.push_field(&modulus.to_be_bytes())
                .expect("fixed bounded MKHE identity field");
            hash.push_field(&root.to_be_bytes())
                .expect("fixed bounded MKHE identity field");
        }
        hash.push_field(&self.plaintext_modulus.digest_bytes())
            .expect("fixed bounded MKHE identity field");
        hash.push_field(&[self.error_eta])
            .expect("fixed bounded MKHE identity field");
        hash.push_field(&[self.hybrid_rns_decomposition.into()])
            .expect("fixed bounded MKHE identity field");
        hash.push_field(&[self.gadget_base_log])
            .expect("fixed bounded MKHE identity field");
        hash.push_field(
            &u16::try_from(self.gadget_digits)
                .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
                .to_be_bytes(),
        )
        .expect("fixed bounded MKHE identity field");
        Ok(*hash
            .finish()
            .expect("exact MKHE outer identity field count")
            .as_bytes())
    }
    /// Digest only the governed deployment resource ceilings.
    fn resource_policy_digest(&self) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
        self.validate()?;
        let mut hash = native_outer_identity_v1(
            NativeOuterIdentityRoleV1::Parameter,
            b"iroha.zk-ams.v1.mkhe.resource-policy",
            7,
        );
        hash.push_field(&self.profile_id)
            .expect("fixed bounded MKHE identity field");
        for ceiling in [
            self.max_ciphertext_bytes,
            self.max_evaluated_key_bytes,
            self.max_round_bytes,
            self.max_share_bytes,
            self.max_workspace_bytes,
        ] {
            hash.push_field(
                &u64::try_from(ceiling)
                    .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
                    .to_be_bytes(),
            )
            .expect("fixed bounded MKHE identity field");
        }
        hash.push_field(&self.max_work_units.to_be_bytes())
            .expect("fixed bounded MKHE identity field");
        Ok(*hash
            .finish()
            .expect("exact MKHE outer identity field count")
            .as_bytes())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct RnsPolynomial {
    coefficients: Vec<u64>,
}
impl RnsPolynomial {
    #[cfg(test)]
    fn zero(profile: &BgvProfile) -> Self {
        Self {
            coefficients: vec![0; profile.ring_degree * profile.moduli.len()],
        }
    }
    /// Test whether every stored residue is zero without allocating a
    /// release-sized comparison polynomial.
    #[cfg(test)]
    fn is_zero(&self) -> bool {
        self.coefficients
            .iter()
            .all(|coefficient| *coefficient == 0)
    }
    #[cfg(test)]
    fn from_flat(profile: &BgvProfile, coefficients: Vec<u64>) -> Result<Self, ZkAmsMkheErrorV1> {
        profile.validate()?;
        if coefficients.len() != profile.ring_degree * profile.moduli.len() {
            return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
        }
        for (limb, values) in coefficients.chunks_exact(profile.ring_degree).enumerate() {
            if values.iter().any(|&value| value >= profile.moduli[limb]) {
                return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
            }
        }
        Ok(Self { coefficients })
    }
    #[cfg(test)]
    fn from_signed(profile: &BgvProfile, values: &[i64]) -> Result<Self, ZkAmsMkheErrorV1> {
        if values.len() != profile.ring_degree {
            return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
        }
        let mut coefficients = Vec::with_capacity(profile.ring_degree * profile.moduli.len());
        for &modulus in profile.moduli {
            coefficients.extend(
                values
                    .iter()
                    .copied()
                    .map(|value| signed_mod(value, modulus)),
            );
        }
        Self::from_flat(profile, coefficients)
    }
    #[cfg(test)]
    fn from_unsigned(profile: &BgvProfile, values: &[u64]) -> Result<Self, ZkAmsMkheErrorV1> {
        if values.len() != profile.ring_degree {
            return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
        }
        let mut coefficients = Vec::with_capacity(profile.ring_degree * profile.moduli.len());
        for &modulus in profile.moduli {
            coefficients.extend(values.iter().map(|value| value % modulus));
        }
        Self::from_flat(profile, coefficients)
    }
    #[cfg(test)]
    fn from_t256_plaintext_bytes(
        profile: &BgvProfile,
        values: &[[u8; 32]],
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        if profile.plaintext_modulus != PlaintextModulus::T256
            || values.len() != profile.ring_degree
            || values
                .iter()
                .any(|value| *value >= VEGA_T256_SCALAR_MODULUS_BE_V1)
        {
            return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
        }
        checked_coefficient_work(profile, profile.moduli.len())?;
        let mut coefficients = Vec::with_capacity(profile.ring_degree * profile.moduli.len());
        for &modulus in profile.moduli {
            let plaintext_modulus_residue = bytes_mod_u64(&VEGA_T256_SCALAR_MODULUS_BE_V1, modulus);
            coefficients.extend(values.iter().map(|value| {
                t256_centered_residue_with_modulus_residue(
                    value,
                    modulus,
                    plaintext_modulus_residue,
                )
            }));
        }
        Self::from_flat(profile, coefficients)
    }
    #[cfg(test)]
    fn from_test_plaintext(profile: &BgvProfile, values: &[u64]) -> Result<Self, ZkAmsMkheErrorV1> {
        let PlaintextModulus::Tiny(plaintext_modulus) = profile.plaintext_modulus else {
            return Err(ZkAmsMkheErrorV1::InvalidProfile);
        };
        if values.len() != profile.ring_degree
            || values.iter().any(|&value| value >= plaintext_modulus)
        {
            return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
        }
        let mut coefficients = Vec::with_capacity(profile.ring_degree * profile.moduli.len());
        for &modulus in profile.moduli {
            coefficients.extend(values.iter().map(|value| value % modulus));
        }
        Self::from_flat(profile, coefficients)
    }
    #[cfg(test)]
    fn limb<'a>(&'a self, profile: &BgvProfile, index: usize) -> &'a [u64] {
        let start = index * profile.ring_degree;
        &self.coefficients[start..start + profile.ring_degree]
    }
    #[cfg(test)]
    fn add(&self, rhs: &Self, profile: &BgvProfile) -> Result<Self, ZkAmsMkheErrorV1> {
        self.binary(rhs, profile, mod_add)
    }
    #[cfg(test)]
    fn sub(&self, rhs: &Self, profile: &BgvProfile) -> Result<Self, ZkAmsMkheErrorV1> {
        self.binary(rhs, profile, mod_sub)
    }
    #[cfg(test)]
    fn negate(&self, profile: &BgvProfile) -> Result<Self, ZkAmsMkheErrorV1> {
        self.validate(profile)?;
        let mut output = self.clone();
        for (limb, values) in output
            .coefficients
            .chunks_exact_mut(profile.ring_degree)
            .enumerate()
        {
            let modulus = profile.moduli[limb];
            for value in values {
                *value = if *value == 0 { 0 } else { modulus - *value };
            }
        }
        Ok(output)
    }
    #[cfg(test)]
    fn scale_gadget(&self, digit: usize, profile: &BgvProfile) -> Result<Self, ZkAmsMkheErrorV1> {
        self.validate(profile)?;
        if digit >= profile.gadget_digits {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        let mut output = self.clone();
        for (limb, values) in output
            .coefficients
            .chunks_exact_mut(profile.ring_degree)
            .enumerate()
        {
            let modulus = profile.moduli[limb];
            let scalar = mod_pow(
                mod_pow(2, u64::from(profile.gadget_base_log), modulus),
                u64::try_from(digit).map_err(|_| ZkAmsMkheErrorV1::InvalidKeyMaterial)?,
                modulus,
            );
            for value in values {
                *value = mod_mul(*value, scalar, modulus);
            }
        }
        Ok(output)
    }
    #[cfg(test)]
    fn scale_plaintext_modulus(&self, profile: &BgvProfile) -> Result<Self, ZkAmsMkheErrorV1> {
        self.validate(profile)?;
        let mut output = self.clone();
        for (limb, values) in output
            .coefficients
            .chunks_exact_mut(profile.ring_degree)
            .enumerate()
        {
            let modulus = profile.moduli[limb];
            let reduced = profile.plaintext_modulus.residue(modulus);
            for value in values {
                *value = mod_mul(*value, reduced, modulus);
            }
        }
        Ok(output)
    }
    #[cfg(test)]
    fn mul(&self, rhs: &Self, profile: &BgvProfile) -> Result<Self, ZkAmsMkheErrorV1> {
        self.validate(profile)?;
        rhs.validate(profile)?;
        let work = u64::try_from(profile.ring_degree)
            .ok()
            .and_then(|degree| {
                degree.checked_mul(u64::from(profile.ring_degree.trailing_zeros()) + 1)
            })
            .and_then(|work| work.checked_mul(profile.moduli.len() as u64))
            .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
        if work > profile.max_work_units {
            return Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded);
        }
        let mut coefficients = Vec::with_capacity(self.coefficients.len());
        for limb in 0..profile.moduli.len() {
            coefficients.extend(negacyclic_multiply(
                self.limb(profile, limb),
                rhs.limb(profile, limb),
                profile.moduli[limb],
                profile.negacyclic_roots[limb],
            )?);
        }
        Self::from_flat(profile, coefficients)
    }
    #[cfg(test)]
    fn automorphism(
        &self,
        exponent: usize,
        profile: &BgvProfile,
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        self.validate(profile)?;
        let twice_degree = profile
            .ring_degree
            .checked_mul(2)
            .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
        if exponent == 0 || exponent >= twice_degree || exponent.is_multiple_of(2) {
            return Err(ZkAmsMkheErrorV1::InvalidCiphertext);
        }
        let mut output = Self::zero(profile);
        for limb in 0..profile.moduli.len() {
            let modulus = profile.moduli[limb];
            for (index, &value) in self.limb(profile, limb).iter().enumerate() {
                let mapped = index * exponent % twice_degree;
                let (destination, coefficient) = if mapped >= profile.ring_degree {
                    (
                        mapped - profile.ring_degree,
                        if value == 0 { 0 } else { modulus - value },
                    )
                } else {
                    (mapped, value)
                };
                output.coefficients[limb * profile.ring_degree + destination] = coefficient;
            }
        }
        Ok(output)
    }
    #[cfg(test)]
    fn validate(&self, profile: &BgvProfile) -> Result<(), ZkAmsMkheErrorV1> {
        profile.validate()?;
        if self.coefficients.len() != profile.ring_degree * profile.moduli.len() {
            return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
        }
        for (limb, values) in self
            .coefficients
            .chunks_exact(profile.ring_degree)
            .enumerate()
        {
            if values.iter().any(|&value| value >= profile.moduli[limb]) {
                return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
            }
        }
        Ok(())
    }
    #[cfg(test)]
    fn binary(
        &self,
        rhs: &Self,
        profile: &BgvProfile,
        operation: fn(u64, u64, u64) -> u64,
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        self.validate(profile)?;
        rhs.validate(profile)?;
        let mut output = Vec::with_capacity(self.coefficients.len());
        for limb in 0..profile.moduli.len() {
            let modulus = profile.moduli[limb];
            output.extend(
                self.limb(profile, limb)
                    .iter()
                    .copied()
                    .zip(rhs.limb(profile, limb).iter().copied())
                    .map(|(left, right)| operation(left, right, modulus)),
            );
        }
        Self::from_flat(profile, output)
    }
}
#[cfg(test)]
struct SecretPolynomial {
    coefficients: Vec<i64>,
}
#[cfg(test)]
impl SecretPolynomial {
    fn sample_ternary<R: MaskedRelaxedRandomSourceV1>(
        profile: &BgvProfile,
        random: &mut R,
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        let mut owner = Self {
            coefficients: Vec::new(),
        };
        owner
            .coefficients
            .try_reserve_exact(profile.ring_degree)
            .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
        let max_bytes = profile
            .ring_degree
            .checked_mul(MAX_TERNARY_SAMPLE_BYTES_PER_COEFFICIENT_V1)
            .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
        checked_rng_bytes(profile, max_bytes)?;
        for _ in 0..max_bytes {
            let byte = random_byte(random)?;
            for shift in [0, 2, 4, 6] {
                match (byte >> shift) & 0x03 {
                    0 => owner.coefficients.push(-1),
                    1 => owner.coefficients.push(0),
                    2 => owner.coefficients.push(1),
                    _ => continue,
                }
                if owner.coefficients.len() == profile.ring_degree {
                    return Ok(owner);
                }
            }
        }
        Err(ZkAmsMkheErrorV1::RandomUnavailable)
    }
    fn sample_error<R: MaskedRelaxedRandomSourceV1>(
        profile: &BgvProfile,
        random: &mut R,
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        let max_bytes = profile
            .ring_degree
            .checked_mul(usize::from(profile.error_eta))
            .and_then(|value| value.checked_mul(2))
            .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
        checked_rng_bytes(profile, max_bytes)?;
        let mut owner = Self {
            coefficients: Vec::new(),
        };
        owner
            .coefficients
            .try_reserve_exact(profile.ring_degree)
            .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
        for _ in 0..profile.ring_degree {
            let mut positive = 0_i64;
            let mut negative = 0_i64;
            for _ in 0..profile.error_eta {
                positive += i64::from(random_byte(random)? & 1);
                negative += i64::from(random_byte(random)? & 1);
            }
            owner.coefficients.push(positive - negative);
        }
        Ok(owner)
    }
    #[cfg(test)]
    fn as_rns(&self, profile: &BgvProfile) -> Result<RnsPolynomial, ZkAmsMkheErrorV1> {
        RnsPolynomial::from_signed(profile, &self.coefficients)
    }
    fn sub(&self, rhs: &Self) -> Result<Self, ZkAmsMkheErrorV1> {
        if self.coefficients.len() != rhs.coefficients.len() {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        Ok(Self {
            coefficients: self
                .coefficients
                .iter()
                .copied()
                .zip(rhs.coefficients.iter().copied())
                .map(|(left, right)| left - right)
                .collect(),
        })
    }
    fn automorphism(
        &self,
        exponent: usize,
        profile: &BgvProfile,
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        if self.coefficients.len() != profile.ring_degree {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        let twice_degree = profile
            .ring_degree
            .checked_mul(2)
            .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
        if exponent == 0 || exponent >= twice_degree || exponent.is_multiple_of(2) {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        let mut coefficients = vec![0_i64; profile.ring_degree];
        for (index, &value) in self.coefficients.iter().enumerate() {
            let mapped = index * exponent % twice_degree;
            if mapped >= profile.ring_degree {
                coefficients[mapped - profile.ring_degree] = -value;
            } else {
                coefficients[mapped] = value;
            }
        }
        Ok(Self { coefficients })
    }
}
#[cfg(test)]
impl Drop for SecretPolynomial {
    fn drop(&mut self) {
        let coefficients = core::hint::black_box(&mut self.coefficients);
        coefficients.fill(0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(&mut *coefficients);
    }
}
#[cfg(test)]
impl fmt::Debug for SecretPolynomial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretPolynomial([REDACTED])")
    }
}
#[cfg(test)]
struct IndependentSecretKey {
    party: ZkAmsMkhePartyIdV1,
    profile_digest: [u8; 32],
    secret: SecretPolynomial,
}
#[cfg(test)]
impl fmt::Debug for IndependentSecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IndependentSecretKey")
            .field("party", &self.party)
            .field("profile_digest", &hex::encode(self.profile_digest))
            .field("secret", &self.secret)
            .finish()
    }
}
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct IndependentPublicKey {
    version: u8,
    profile_digest: [u8; 32],
    party: ZkAmsMkhePartyIdV1,
    a: RnsPolynomial,
    b: RnsPolynomial,
}
#[cfg(test)]
fn independent_keygen<R: MaskedRelaxedRandomSourceV1>(
    profile: &BgvProfile,
    party: ZkAmsMkhePartyIdV1,
    random: &mut R,
) -> Result<(IndependentSecretKey, IndependentPublicKey), ZkAmsMkheErrorV1> {
    profile.validate()?;
    let profile_digest = profile.digest()?;
    let secret = SecretPolynomial::sample_ternary(profile, random)?;
    let error = SecretPolynomial::sample_error(profile, random)?;
    let a = sample_uniform_rns(profile, random)?;
    let b = a
        .mul(&secret.as_rns(profile)?, profile)?
        .negate(profile)?
        .add(
            &error.as_rns(profile)?.scale_plaintext_modulus(profile)?,
            profile,
        )?;
    let public = IndependentPublicKey {
        version: MKHE_VERSION_V1,
        profile_digest,
        party,
        a,
        b,
    };
    validate_public_key(profile, &public)?;
    Ok((
        IndependentSecretKey {
            party,
            profile_digest,
            secret,
        },
        public,
    ))
}
#[cfg(test)]
fn validate_public_key(
    profile: &BgvProfile,
    public: &IndependentPublicKey,
) -> Result<(), ZkAmsMkheErrorV1> {
    if public.version != MKHE_VERSION_V1 || public.profile_digest != profile.digest()? {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    public.a.validate(profile)?;
    public.b.validate(profile)?;
    if public.a.is_zero() || public.b.is_zero() {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    Ok(())
}
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct LinearCiphertext {
    version: u8,
    profile_digest: [u8; 32],
    party_set: PartySet,
    level: u8,
    constant: RnsPolynomial,
    linear: Vec<RnsPolynomial>,
}
#[cfg(test)]
impl LinearCiphertext {
    fn validate(&self, profile: &BgvProfile) -> Result<(), ZkAmsMkheErrorV1> {
        if self.version != MKHE_VERSION_V1
            || self.profile_digest != profile.digest()?
            || self.level > 1
            || self.linear.len() != self.party_set.parties.len()
            || self.party_set.digest != party_set_digest(&self.party_set.parties)?
        {
            return Err(ZkAmsMkheErrorV1::InvalidCiphertext);
        }
        self.constant.validate(profile)?;
        for component in &self.linear {
            component.validate(profile)?;
        }
        if checked_linear_ciphertext_bytes(profile, self.party_set.parties.len())?
            > profile.max_ciphertext_bytes
        {
            return Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded);
        }
        Ok(())
    }
    fn extend(&self, target: &PartySet, profile: &BgvProfile) -> Result<Self, ZkAmsMkheErrorV1> {
        self.validate(profile)?;
        if self
            .party_set
            .parties
            .iter()
            .any(|party| target.index_of(*party).is_none())
        {
            return Err(ZkAmsMkheErrorV1::InvalidPartySet);
        }
        let mut linear = vec![RnsPolynomial::zero(profile); target.parties.len()];
        for (party, component) in self.party_set.parties.iter().zip(&self.linear) {
            let index = target
                .index_of(*party)
                .ok_or(ZkAmsMkheErrorV1::InvalidPartySet)?;
            linear[index] = component.clone();
        }
        Ok(Self {
            version: self.version,
            profile_digest: self.profile_digest,
            party_set: target.clone(),
            level: self.level,
            constant: self.constant.clone(),
            linear,
        })
    }
    fn add(&self, rhs: &Self, profile: &BgvProfile) -> Result<Self, ZkAmsMkheErrorV1> {
        self.validate(profile)?;
        rhs.validate(profile)?;
        if self.level != rhs.level {
            return Err(ZkAmsMkheErrorV1::InvalidCiphertext);
        }
        let union = self.party_set.union(&rhs.party_set)?;
        checked_coefficient_work(profile, 3 * (union.parties.len() + 1))?;
        let left = self.extend(&union, profile)?;
        let right = rhs.extend(&union, profile)?;
        let linear = left
            .linear
            .iter()
            .zip(&right.linear)
            .map(|(left, right)| left.add(right, profile))
            .collect::<Result<Vec<_>, _>>()?;
        let output = Self {
            version: MKHE_VERSION_V1,
            profile_digest: profile.digest()?,
            party_set: union,
            level: self.level,
            constant: left.constant.add(&right.constant, profile)?,
            linear,
        };
        output.validate(profile)?;
        Ok(output)
    }
    fn mul_plaintext(
        &self,
        plaintext: &RnsPolynomial,
        profile: &BgvProfile,
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        self.validate(profile)?;
        plaintext.validate(profile)?;
        Ok(Self {
            version: self.version,
            profile_digest: self.profile_digest,
            party_set: self.party_set.clone(),
            level: self.level,
            constant: self.constant.mul(plaintext, profile)?,
            linear: self
                .linear
                .iter()
                .map(|component| component.mul(plaintext, profile))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
    fn mul(
        &self,
        rhs: &Self,
        profile: &BgvProfile,
    ) -> Result<QuadraticCiphertext, ZkAmsMkheErrorV1> {
        self.validate(profile)?;
        rhs.validate(profile)?;
        if self.level != 0 || rhs.level != 0 {
            return Err(ZkAmsMkheErrorV1::InvalidCiphertext);
        }
        let union = self.party_set.union(&rhs.party_set)?;
        let party_count = union.parties.len();
        let ring_multiplications = party_count
            .checked_mul(party_count)
            .and_then(|value| value.checked_add(2 * party_count + 1))
            .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
        checked_ring_multiplication_work(profile, ring_multiplications)?;
        let left = self.extend(&union, profile)?;
        let right = rhs.extend(&union, profile)?;
        let mut linear = Vec::with_capacity(union.parties.len());
        for index in 0..union.parties.len() {
            linear.push(
                left.constant
                    .mul(&right.linear[index], profile)?
                    .add(&right.constant.mul(&left.linear[index], profile)?, profile)?,
            );
        }
        let mut quadratic = Vec::with_capacity(union.parties.len() * (union.parties.len() + 1) / 2);
        for left_index in 0..union.parties.len() {
            for right_index in left_index..union.parties.len() {
                let value = if left_index == right_index {
                    left.linear[left_index].mul(&right.linear[right_index], profile)?
                } else {
                    left.linear[left_index]
                        .mul(&right.linear[right_index], profile)?
                        .add(
                            &left.linear[right_index].mul(&right.linear[left_index], profile)?,
                            profile,
                        )?
                };
                quadratic.push(QuadraticComponent {
                    left: union.parties[left_index],
                    right: union.parties[right_index],
                    value,
                });
            }
        }
        let output = QuadraticCiphertext {
            version: MKHE_VERSION_V1,
            profile_digest: profile.digest()?,
            party_set: union,
            level: 1,
            constant: left.constant.mul(&right.constant, profile)?,
            linear,
            quadratic,
        };
        output.validate(profile)?;
        Ok(output)
    }
}
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct QuadraticComponent {
    left: ZkAmsMkhePartyIdV1,
    right: ZkAmsMkhePartyIdV1,
    value: RnsPolynomial,
}
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct QuadraticCiphertext {
    version: u8,
    profile_digest: [u8; 32],
    party_set: PartySet,
    level: u8,
    constant: RnsPolynomial,
    linear: Vec<RnsPolynomial>,
    quadratic: Vec<QuadraticComponent>,
}
#[cfg(test)]
impl QuadraticCiphertext {
    fn validate(&self, profile: &BgvProfile) -> Result<(), ZkAmsMkheErrorV1> {
        if self.version != MKHE_VERSION_V1
            || self.profile_digest != profile.digest()?
            || self.level != 1
            || self.linear.len() != self.party_set.parties.len()
            || self.quadratic.len()
                != self.party_set.parties.len() * (self.party_set.parties.len() + 1) / 2
        {
            return Err(ZkAmsMkheErrorV1::InvalidCiphertext);
        }
        self.constant.validate(profile)?;
        for component in &self.linear {
            component.validate(profile)?;
        }
        let mut cursor = 0;
        for left in 0..self.party_set.parties.len() {
            for right in left..self.party_set.parties.len() {
                let component = self
                    .quadratic
                    .get(cursor)
                    .ok_or(ZkAmsMkheErrorV1::InvalidCiphertext)?;
                if component.left != self.party_set.parties[left]
                    || component.right != self.party_set.parties[right]
                {
                    return Err(ZkAmsMkheErrorV1::InvalidCiphertext);
                }
                component.value.validate(profile)?;
                cursor += 1;
            }
        }
        if checked_quadratic_ciphertext_bytes(profile, self.party_set.parties.len())?
            > profile.max_ciphertext_bytes
        {
            return Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded);
        }
        Ok(())
    }
}
#[cfg(test)]
const RKG_ROUND_ONE_AUTH_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.rkg-round-one";
#[cfg(test)]
const RKG_ROUND_TWO_AUTH_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.rkg-round-two";
#[cfg(test)]
const GALOIS_KEY_AUTH_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.galois-key";
#[cfg(test)]
struct RkgEphemeralState {
    profile_digest: [u8; 32],
    party_set_digest: [u8; 32],
    transcript_digest: [u8; 32],
    left: ZkAmsMkhePartyIdV1,
    right: ZkAmsMkhePartyIdV1,
    party: ZkAmsMkhePartyIdV1,
    round_one_contribution_digest: [u8; 32],
    integrity_digest: [u8; 32],
    ephemeral: Vec<SecretPolynomial>,
}
#[cfg(test)]
impl fmt::Debug for RkgEphemeralState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RkgEphemeralState")
            .field("profile_digest", &hex::encode(self.profile_digest))
            .field("party_set_digest", &hex::encode(self.party_set_digest))
            .field("transcript_digest", &hex::encode(self.transcript_digest))
            .field("left", &self.left)
            .field("right", &self.right)
            .field("party", &self.party)
            .field(
                "round_one_contribution_digest",
                &hex::encode(self.round_one_contribution_digest),
            )
            .field("ephemeral", &"[REDACTED]")
            .finish()
    }
}
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct RkgRoundOneEntry {
    h0: RnsPolynomial,
    h1: RnsPolynomial,
}
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct RkgRoundOneContribution {
    version: u8,
    profile_digest: [u8; 32],
    party_set: PartySet,
    transcript_digest: [u8; 32],
    left: ZkAmsMkhePartyIdV1,
    right: ZkAmsMkhePartyIdV1,
    party: ZkAmsMkhePartyIdV1,
    entries: Vec<RkgRoundOneEntry>,
    authentication: ArtifactAuthentication,
}
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct RkgRoundOneAggregate {
    version: u8,
    profile_digest: [u8; 32],
    party_set: PartySet,
    transcript_digest: [u8; 32],
    left: ZkAmsMkhePartyIdV1,
    right: ZkAmsMkhePartyIdV1,
    entries: Vec<RkgRoundOneEntry>,
    contribution_digests: Vec<[u8; 32]>,
    digest: [u8; 32],
}
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct RkgRoundTwoContribution {
    version: u8,
    profile_digest: [u8; 32],
    party_set: PartySet,
    transcript_digest: [u8; 32],
    round_one_digest: [u8; 32],
    left: ZkAmsMkhePartyIdV1,
    right: ZkAmsMkhePartyIdV1,
    party: ZkAmsMkhePartyIdV1,
    k0: Vec<RnsPolynomial>,
    authentication: ArtifactAuthentication,
}
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProductRelinearizationKey {
    version: u8,
    profile_digest: [u8; 32],
    left: ZkAmsMkhePartyIdV1,
    right: ZkAmsMkhePartyIdV1,
    target_set: PartySet,
    transcript_digest: [u8; 32],
    round_one_digest: [u8; 32],
    contribution_digests: Vec<[u8; 32]>,
    digits: Vec<LinearCiphertext>,
    digest: [u8; 32],
}
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct GaloisKey {
    version: u8,
    profile_digest: [u8; 32],
    transcript_digest: [u8; 32],
    party: ZkAmsMkhePartyIdV1,
    exponent: usize,
    digits: Vec<LinearCiphertext>,
    authentication: ArtifactAuthentication,
}
#[cfg(test)]
fn generate_galois_key<R: MaskedRelaxedRandomSourceV1>(
    profile: &BgvProfile,
    transcript_digest: [u8; 32],
    exponent: usize,
    secret: &IndependentSecretKey,
    public: &IndependentPublicKey,
    authentication_secret: &AuthenticationSecret,
    random: &mut R,
) -> Result<GaloisKey, ZkAmsMkheErrorV1> {
    validate_public_key(profile, public)?;
    let twice_degree = profile
        .ring_degree
        .checked_mul(2)
        .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    if transcript_digest == [0; 32]
        || exponent == 0
        || exponent >= twice_degree
        || exponent.is_multiple_of(2)
        || secret.party != public.party
        || secret.profile_digest != profile.digest()?
        || authentication_secret.party_id()? != secret.party
        || checked_galois_key_bytes(profile)? > profile.max_evaluated_key_bytes
    {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    let transformed_secret = secret.secret.automorphism(exponent, profile)?;
    let transformed_secret = transformed_secret.as_rns(profile)?;
    let mut digits = Vec::with_capacity(profile.gadget_digits);
    for digit in 0..profile.gadget_digits {
        digits.push(encrypt(
            profile,
            public,
            &transformed_secret.scale_gadget(digit, profile)?,
            random,
        )?);
    }
    let mut key = GaloisKey {
        version: MKHE_VERSION_V1,
        profile_digest: profile.digest()?,
        transcript_digest,
        party: secret.party,
        exponent,
        digits,
        authentication: ArtifactAuthentication {
            version: 0,
            party: secret.party,
            public_key: [0; 33],
            signature: [0; SCHNORR_SIGNATURE_BYTES_V1],
        },
    };
    let digest = galois_key_digest(&key, profile)?;
    key.authentication = ArtifactAuthentication::sign(
        GALOIS_KEY_AUTH_DOMAIN_V1,
        digest,
        authentication_secret,
        random,
    )?;
    validate_galois_key(profile, &key)?;
    Ok(key)
}
#[cfg(test)]
fn validate_galois_key(profile: &BgvProfile, key: &GaloisKey) -> Result<(), ZkAmsMkheErrorV1> {
    let twice_degree = profile
        .ring_degree
        .checked_mul(2)
        .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    if key.version != MKHE_VERSION_V1
        || key.profile_digest != profile.digest()?
        || key.transcript_digest == [0; 32]
        || key.exponent == 0
        || key.exponent >= twice_degree
        || key.exponent.is_multiple_of(2)
        || key.digits.len() != profile.gadget_digits
        || key.authentication.party != key.party
        || checked_galois_key_bytes(profile)? > profile.max_evaluated_key_bytes
    {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    let singleton = PartySet::singleton(key.party);
    for digit in &key.digits {
        digit.validate(profile)?;
        if digit.party_set != singleton || digit.level != 0 {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
    }
    key.authentication
        .verify(GALOIS_KEY_AUTH_DOMAIN_V1, galois_key_digest(key, profile)?)
}
#[cfg(test)]
fn rotate_ciphertext(
    profile: &BgvProfile,
    ciphertext: &LinearCiphertext,
    exponent: usize,
    keys: &[GaloisKey],
) -> Result<LinearCiphertext, ZkAmsMkheErrorV1> {
    ciphertext.validate(profile)?;
    if keys.len() != ciphertext.party_set.parties.len() {
        return Err(ZkAmsMkheErrorV1::MissingEvaluatedKey);
    }
    let mut ordered = vec![None; ciphertext.party_set.parties.len()];
    for key in keys {
        validate_galois_key(profile, key)?;
        if key.exponent != exponent {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        let index = ciphertext
            .party_set
            .index_of(key.party)
            .ok_or(ZkAmsMkheErrorV1::InvalidKeyMaterial)?;
        if ordered[index].replace(key).is_some() {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
    }
    let ordered = ordered
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(ZkAmsMkheErrorV1::MissingEvaluatedKey)?;
    let ring_multiplications = ciphertext
        .party_set
        .parties
        .len()
        .checked_mul(profile.gadget_digits)
        .and_then(|value| value.checked_mul(2))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    checked_ring_multiplication_work(profile, ring_multiplications)?;
    let mut constant = ciphertext.constant.automorphism(exponent, profile)?;
    let mut linear = vec![RnsPolynomial::zero(profile); ciphertext.party_set.parties.len()];
    for ((component, key), _) in ciphertext.linear.iter().zip(ordered).zip(0..) {
        let transformed = component.automorphism(exponent, profile)?;
        let decomposition = gadget_decompose(profile, &transformed)?;
        for (digit, plaintext_digit) in decomposition.iter().enumerate() {
            let evaluated = key.digits[digit]
                .extend(&ciphertext.party_set, profile)?
                .mul_plaintext(plaintext_digit, profile)?;
            constant = constant.add(&evaluated.constant, profile)?;
            for (output, contribution) in linear.iter_mut().zip(&evaluated.linear) {
                *output = output.add(contribution, profile)?;
            }
        }
    }
    let output = LinearCiphertext {
        version: MKHE_VERSION_V1,
        profile_digest: profile.digest()?,
        party_set: ciphertext.party_set.clone(),
        level: ciphertext.level,
        constant,
        linear,
    };
    output.validate(profile)?;
    Ok(output)
}
#[cfg(test)]
#[expect(
    clippy::too_many_arguments,
    reason = "explicit RKG round-one equation inputs"
)]
fn rkg_round_one<R: MaskedRelaxedRandomSourceV1>(
    profile: &BgvProfile,
    party_set: &PartySet,
    transcript_digest: [u8; 32],
    left: ZkAmsMkhePartyIdV1,
    right: ZkAmsMkhePartyIdV1,
    secret: &IndependentSecretKey,
    authentication_secret: &AuthenticationSecret,
    random: &mut R,
) -> Result<(RkgEphemeralState, RkgRoundOneContribution), ZkAmsMkheErrorV1> {
    profile.validate()?;
    if transcript_digest == [0; 32]
        || left > right
        || party_set.index_of(left).is_none()
        || party_set.index_of(right).is_none()
        || secret.profile_digest != profile.digest()?
        || party_set.index_of(secret.party).is_none()
        || authentication_secret.party_id()? != secret.party
    {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    let round_bytes = checked_rkg_round_one_contribution_bytes(profile)?;
    if round_bytes > profile.max_round_bytes {
        return Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded);
    }
    checked_ring_multiplication_work(profile, 2 * profile.gadget_digits)?;
    let secret_rns = secret.secret.as_rns(profile)?;
    let left_secret = if secret.party == left {
        secret_rns.clone()
    } else {
        RnsPolynomial::zero(profile)
    };
    let right_secret = if secret.party == right {
        secret_rns
    } else {
        RnsPolynomial::zero(profile)
    };
    let mut ephemeral = Vec::with_capacity(profile.gadget_digits);
    let mut entries = Vec::with_capacity(profile.gadget_digits);
    for digit in 0..profile.gadget_digits {
        let common_a =
            derive_rkg_common_a(profile, party_set, transcript_digest, left, right, digit)?;
        let ephemeral_secret = SecretPolynomial::sample_ternary(profile, random)?;
        let error_zero = SecretPolynomial::sample_error(profile, random)?;
        let error_one = SecretPolynomial::sample_error(profile, random)?;
        let ephemeral_rns = ephemeral_secret.as_rns(profile)?;
        let h0 = common_a
            .mul(&ephemeral_rns, profile)?
            .negate(profile)?
            .add(&left_secret.scale_gadget(digit, profile)?, profile)?
            .add(
                &error_zero
                    .as_rns(profile)?
                    .scale_plaintext_modulus(profile)?,
                profile,
            )?;
        let h1 = common_a.mul(&right_secret, profile)?.add(
            &error_one
                .as_rns(profile)?
                .scale_plaintext_modulus(profile)?,
            profile,
        )?;
        ephemeral.push(ephemeral_secret);
        entries.push(RkgRoundOneEntry { h0, h1 });
    }
    let mut contribution = RkgRoundOneContribution {
        version: MKHE_VERSION_V1,
        profile_digest: profile.digest()?,
        party_set: party_set.clone(),
        transcript_digest,
        left,
        right,
        party: secret.party,
        entries,
        authentication: ArtifactAuthentication {
            version: 0,
            party: secret.party,
            public_key: [0; 33],
            signature: [0; SCHNORR_SIGNATURE_BYTES_V1],
        },
    };
    let digest = rkg_round_one_contribution_digest(&contribution, profile)?;
    contribution.authentication = ArtifactAuthentication::sign(
        RKG_ROUND_ONE_AUTH_DOMAIN_V1,
        digest,
        authentication_secret,
        random,
    )?;
    validate_rkg_round_one_contribution(profile, &contribution)?;
    let mut state = RkgEphemeralState {
        profile_digest: profile.digest()?,
        party_set_digest: party_set.digest,
        transcript_digest,
        left,
        right,
        party: secret.party,
        round_one_contribution_digest: digest,
        integrity_digest: [0; 32],
        ephemeral,
    };
    state.integrity_digest = rkg_state_integrity_digest(&state, profile)?;
    Ok((state, contribution))
}
#[cfg(test)]
fn validate_rkg_round_one_contribution(
    profile: &BgvProfile,
    contribution: &RkgRoundOneContribution,
) -> Result<(), ZkAmsMkheErrorV1> {
    if contribution.version != MKHE_VERSION_V1
        || contribution.profile_digest != profile.digest()?
        || contribution.transcript_digest == [0; 32]
        || contribution.left > contribution.right
        || contribution.party_set.index_of(contribution.left).is_none()
        || contribution
            .party_set
            .index_of(contribution.right)
            .is_none()
        || contribution
            .party_set
            .index_of(contribution.party)
            .is_none()
        || contribution.entries.len() != profile.gadget_digits
        || contribution.authentication.party != contribution.party
        || contribution.party_set.digest != party_set_digest(&contribution.party_set.parties)?
        || checked_rkg_round_one_contribution_bytes(profile)? > profile.max_round_bytes
    {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    for entry in &contribution.entries {
        entry.h0.validate(profile)?;
        entry.h1.validate(profile)?;
    }
    contribution.authentication.verify(
        RKG_ROUND_ONE_AUTH_DOMAIN_V1,
        rkg_round_one_contribution_digest(contribution, profile)?,
    )
}
#[cfg(test)]
fn aggregate_rkg_round_one(
    profile: &BgvProfile,
    party_set: &PartySet,
    transcript_digest: [u8; 32],
    left: ZkAmsMkhePartyIdV1,
    right: ZkAmsMkhePartyIdV1,
    contributions: &[RkgRoundOneContribution],
) -> Result<RkgRoundOneAggregate, ZkAmsMkheErrorV1> {
    if contributions.len() != party_set.parties.len()
        || transcript_digest == [0; 32]
        || left > right
        || party_set.index_of(left).is_none()
        || party_set.index_of(right).is_none()
    {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    checked_coefficient_work(profile, 2 * profile.gadget_digits * contributions.len())?;
    for (expected_party, contribution) in party_set.parties.iter().zip(contributions) {
        validate_rkg_round_one_contribution(profile, contribution)?;
        if contribution.party_set != *party_set
            || contribution.transcript_digest != transcript_digest
            || contribution.left != left
            || contribution.right != right
            || contribution.party != *expected_party
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
    }
    let mut entries = vec![
        RkgRoundOneEntry {
            h0: RnsPolynomial::zero(profile),
            h1: RnsPolynomial::zero(profile),
        };
        profile.gadget_digits
    ];
    let mut contribution_digests = Vec::with_capacity(contributions.len());
    for contribution in contributions {
        contribution_digests.push(rkg_round_one_contribution_digest(contribution, profile)?);
        for (aggregate, entry) in entries.iter_mut().zip(&contribution.entries) {
            aggregate.h0 = aggregate.h0.add(&entry.h0, profile)?;
            aggregate.h1 = aggregate.h1.add(&entry.h1, profile)?;
        }
    }
    let mut aggregate = RkgRoundOneAggregate {
        version: MKHE_VERSION_V1,
        profile_digest: profile.digest()?,
        party_set: party_set.clone(),
        transcript_digest,
        left,
        right,
        entries,
        contribution_digests,
        digest: [0; 32],
    };
    aggregate.digest = rkg_round_one_aggregate_digest(&aggregate, profile)?;
    validate_rkg_round_one_aggregate(profile, &aggregate)?;
    Ok(aggregate)
}
#[cfg(test)]
fn validate_rkg_round_one_aggregate(
    profile: &BgvProfile,
    aggregate: &RkgRoundOneAggregate,
) -> Result<(), ZkAmsMkheErrorV1> {
    if aggregate.version != MKHE_VERSION_V1
        || aggregate.profile_digest != profile.digest()?
        || aggregate.transcript_digest == [0; 32]
        || aggregate.left > aggregate.right
        || aggregate.party_set.index_of(aggregate.left).is_none()
        || aggregate.party_set.index_of(aggregate.right).is_none()
        || aggregate.entries.len() != profile.gadget_digits
        || aggregate.contribution_digests.len() != aggregate.party_set.parties.len()
        || aggregate.contribution_digests.contains(&[0; 32])
        || aggregate.digest == [0; 32]
        || aggregate.digest != rkg_round_one_aggregate_digest(aggregate, profile)?
    {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    for entry in &aggregate.entries {
        entry.h0.validate(profile)?;
        entry.h1.validate(profile)?;
    }
    Ok(())
}
#[cfg(test)]
fn rkg_round_two<R: MaskedRelaxedRandomSourceV1>(
    profile: &BgvProfile,
    aggregate: &RkgRoundOneAggregate,
    state: RkgEphemeralState,
    secret: &IndependentSecretKey,
    authentication_secret: &AuthenticationSecret,
    random: &mut R,
) -> Result<RkgRoundTwoContribution, ZkAmsMkheErrorV1> {
    validate_rkg_round_one_aggregate(profile, aggregate)?;
    let party_index = aggregate
        .party_set
        .index_of(secret.party)
        .ok_or(ZkAmsMkheErrorV1::InvalidKeyMaterial)?;
    let expected_round_one_digest = aggregate
        .contribution_digests
        .get(party_index)
        .ok_or(ZkAmsMkheErrorV1::InvalidKeyMaterial)?;
    if state.profile_digest != profile.digest()?
        || state.party_set_digest != aggregate.party_set.digest
        || state.transcript_digest != aggregate.transcript_digest
        || state.left != aggregate.left
        || state.right != aggregate.right
        || state.party != secret.party
        || state.round_one_contribution_digest != *expected_round_one_digest
        || state.integrity_digest == [0; 32]
        || state.integrity_digest != rkg_state_integrity_digest(&state, profile)?
        || state.ephemeral.len() != profile.gadget_digits
        || secret.profile_digest != profile.digest()?
        || aggregate.party_set.index_of(secret.party).is_none()
        || authentication_secret.party_id()? != secret.party
    {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    if checked_rkg_round_two_contribution_bytes(profile)? > profile.max_round_bytes {
        return Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded);
    }
    checked_ring_multiplication_work(profile, 2 * profile.gadget_digits)?;
    let secret_rns = secret.secret.as_rns(profile)?;
    let right_secret = if secret.party == aggregate.right {
        secret_rns
    } else {
        RnsPolynomial::zero(profile)
    };
    let mut k0 = Vec::with_capacity(profile.gadget_digits);
    for ((entry, ephemeral), _) in aggregate.entries.iter().zip(&state.ephemeral).zip(0..) {
        let error = SecretPolynomial::sample_error(profile, random)?;
        let difference = ephemeral.sub(&secret.secret)?.as_rns(profile)?;
        k0.push(
            entry
                .h0
                .mul(&right_secret, profile)?
                .add(&entry.h1.mul(&difference, profile)?, profile)?
                .add(
                    &error.as_rns(profile)?.scale_plaintext_modulus(profile)?,
                    profile,
                )?,
        );
    }
    let mut contribution = RkgRoundTwoContribution {
        version: MKHE_VERSION_V1,
        profile_digest: profile.digest()?,
        party_set: aggregate.party_set.clone(),
        transcript_digest: aggregate.transcript_digest,
        round_one_digest: aggregate.digest,
        left: aggregate.left,
        right: aggregate.right,
        party: secret.party,
        k0,
        authentication: ArtifactAuthentication {
            version: 0,
            party: secret.party,
            public_key: [0; 33],
            signature: [0; SCHNORR_SIGNATURE_BYTES_V1],
        },
    };
    let digest = rkg_round_two_contribution_digest(&contribution, profile)?;
    contribution.authentication = ArtifactAuthentication::sign(
        RKG_ROUND_TWO_AUTH_DOMAIN_V1,
        digest,
        authentication_secret,
        random,
    )?;
    validate_rkg_round_two_contribution(profile, aggregate, &contribution)?;
    Ok(contribution)
}
#[cfg(test)]
fn validate_rkg_round_two_contribution(
    profile: &BgvProfile,
    aggregate: &RkgRoundOneAggregate,
    contribution: &RkgRoundTwoContribution,
) -> Result<(), ZkAmsMkheErrorV1> {
    if contribution.version != MKHE_VERSION_V1
        || contribution.profile_digest != profile.digest()?
        || contribution.party_set != aggregate.party_set
        || contribution.transcript_digest != aggregate.transcript_digest
        || contribution.round_one_digest != aggregate.digest
        || contribution.left != aggregate.left
        || contribution.right != aggregate.right
        || contribution
            .party_set
            .index_of(contribution.party)
            .is_none()
        || contribution.k0.len() != profile.gadget_digits
        || contribution.authentication.party != contribution.party
        || checked_rkg_round_two_contribution_bytes(profile)? > profile.max_round_bytes
    {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    for polynomial in &contribution.k0 {
        polynomial.validate(profile)?;
    }
    contribution.authentication.verify(
        RKG_ROUND_TWO_AUTH_DOMAIN_V1,
        rkg_round_two_contribution_digest(contribution, profile)?,
    )
}
#[cfg(test)]
fn aggregate_rkg_round_two(
    profile: &BgvProfile,
    aggregate: &RkgRoundOneAggregate,
    contributions: &[RkgRoundTwoContribution],
) -> Result<ProductRelinearizationKey, ZkAmsMkheErrorV1> {
    validate_rkg_round_one_aggregate(profile, aggregate)?;
    if contributions.len() != aggregate.party_set.parties.len() {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    checked_coefficient_work(profile, profile.gadget_digits * contributions.len())?;
    for (expected_party, contribution) in aggregate.party_set.parties.iter().zip(contributions) {
        validate_rkg_round_two_contribution(profile, aggregate, contribution)?;
        if contribution.party != *expected_party {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
    }
    let mut digits = Vec::with_capacity(profile.gadget_digits);
    for digit in 0..profile.gadget_digits {
        let mut constant = RnsPolynomial::zero(profile);
        for contribution in contributions {
            constant = constant.add(&contribution.k0[digit], profile)?;
        }
        digits.push(LinearCiphertext {
            version: MKHE_VERSION_V1,
            profile_digest: profile.digest()?,
            party_set: aggregate.party_set.clone(),
            level: 0,
            constant,
            linear: vec![aggregate.entries[digit].h1.clone(); aggregate.party_set.parties.len()],
        });
    }
    let contribution_digests = contributions
        .iter()
        .map(|contribution| rkg_round_two_contribution_digest(contribution, profile))
        .collect::<Result<Vec<_>, _>>()?;
    let mut key = ProductRelinearizationKey {
        version: MKHE_VERSION_V1,
        profile_digest: profile.digest()?,
        left: aggregate.left,
        right: aggregate.right,
        target_set: aggregate.party_set.clone(),
        transcript_digest: aggregate.transcript_digest,
        round_one_digest: aggregate.digest,
        contribution_digests,
        digits,
        digest: [0; 32],
    };
    key.digest = product_relinearization_key_digest(&key, profile)?;
    validate_product_relinearization_key(profile, &key)?;
    Ok(key)
}
#[cfg(test)]
fn validate_product_relinearization_key(
    profile: &BgvProfile,
    key: &ProductRelinearizationKey,
) -> Result<(), ZkAmsMkheErrorV1> {
    if key.version != MKHE_VERSION_V1
        || key.profile_digest != profile.digest()?
        || key.left > key.right
        || key.target_set.index_of(key.left).is_none()
        || key.target_set.index_of(key.right).is_none()
        || key.target_set.parties.len() != usize::from(key.left != key.right) + 1
        || key.transcript_digest == [0; 32]
        || key.round_one_digest == [0; 32]
        || key.contribution_digests.len() != key.target_set.parties.len()
        || key.contribution_digests.contains(&[0; 32])
        || key.digits.len() != profile.gadget_digits
        || key.digest == [0; 32]
        || key.digest != product_relinearization_key_digest(key, profile)?
        || checked_product_relinearization_key_bytes(profile, key.target_set.parties.len())?
            > profile.max_evaluated_key_bytes
    {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    for digit in &key.digits {
        digit.validate(profile)?;
        if digit.party_set != key.target_set || digit.level != 0 {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
    }
    Ok(())
}
#[cfg(test)]
fn relinearize(
    profile: &BgvProfile,
    ciphertext: &QuadraticCiphertext,
    keys: &[ProductRelinearizationKey],
) -> Result<LinearCiphertext, ZkAmsMkheErrorV1> {
    ciphertext.validate(profile)?;
    if keys.len() != ciphertext.quadratic.len() {
        return Err(ZkAmsMkheErrorV1::MissingEvaluatedKey);
    }
    let mut ordered = vec![None; ciphertext.quadratic.len()];
    for key in keys {
        validate_product_relinearization_key(profile, key)?;
        if key
            .target_set
            .parties
            .iter()
            .any(|party| ciphertext.party_set.index_of(*party).is_none())
        {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
        let index = ciphertext
            .quadratic
            .iter()
            .position(|component| component.left == key.left && component.right == key.right)
            .ok_or(ZkAmsMkheErrorV1::InvalidKeyMaterial)?;
        if ordered[index].replace(key).is_some() {
            return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
        }
    }
    let ordered = ordered
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(ZkAmsMkheErrorV1::MissingEvaluatedKey)?;
    let ring_multiplications = ciphertext
        .quadratic
        .len()
        .checked_mul(profile.gadget_digits)
        .and_then(|value| value.checked_mul(ciphertext.party_set.parties.len() + 1))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    checked_ring_multiplication_work(profile, ring_multiplications)?;
    let mut constant = ciphertext.constant.clone();
    let mut linear = ciphertext.linear.clone();
    for (component, key) in ciphertext.quadratic.iter().zip(ordered) {
        let decomposition = gadget_decompose(profile, &component.value)?;
        for (digit, plaintext_digit) in decomposition.iter().enumerate() {
            let evaluated = key.digits[digit]
                .extend(&ciphertext.party_set, profile)?
                .mul_plaintext(plaintext_digit, profile)?;
            constant = constant.add(&evaluated.constant, profile)?;
            for (output, contribution) in linear.iter_mut().zip(&evaluated.linear) {
                *output = output.add(contribution, profile)?;
            }
        }
    }
    let output = LinearCiphertext {
        version: MKHE_VERSION_V1,
        profile_digest: profile.digest()?,
        party_set: ciphertext.party_set.clone(),
        level: 1,
        constant,
        linear,
    };
    output.validate(profile)?;
    Ok(output)
}
#[cfg(test)]
fn gadget_decompose(
    profile: &BgvProfile,
    polynomial: &RnsPolynomial,
) -> Result<Vec<RnsPolynomial>, ZkAmsMkheErrorV1> {
    polynomial.validate(profile)?;
    if checked_gadget_decomposition_workspace_bytes(profile)? > profile.max_workspace_bytes {
        return Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded);
    }
    // Account separately for Garner reconstruction, centering and the final
    // carry check, per-digit balanced carry propagation, and materialization
    // of every signed digit into every RNS limb.
    let passes = profile
        .moduli
        .len()
        .checked_add(2)
        .and_then(|passes| {
            profile
                .gadget_digits
                .checked_mul(2)
                .and_then(|digit_passes| passes.checked_add(digit_passes))
        })
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    checked_coefficient_work(profile, passes)?;
    let ciphertext_modulus = modulus_product(profile.moduli)?;
    let half_modulus = ciphertext_modulus.shr_one();
    let base = 1_u64
        .checked_shl(u32::from(profile.gadget_base_log))
        .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    let half_base = base / 2;
    let mut digits = vec![vec![0_i64; profile.ring_degree]; profile.gadget_digits];
    for coefficient in 0..profile.ring_degree {
        let residues = (0..profile.moduli.len())
            .map(|limb| polynomial.limb(profile, limb)[coefficient])
            .collect::<Vec<_>>();
        let canonical = WideUint::crt(&residues, profile.moduli)?;
        let (negative, magnitude) = if canonical > half_modulus {
            (
                true,
                ciphertext_modulus
                    .checked_sub(canonical)
                    .ok_or(ZkAmsMkheErrorV1::InvalidPolynomial)?,
            )
        } else {
            (false, canonical)
        };
        let mut carry = 0_u64;
        for (digit, output) in digits.iter_mut().enumerate() {
            let chunk = magnitude.bits_at(
                digit * usize::from(profile.gadget_base_log),
                usize::from(profile.gadget_base_log),
            )?;
            let with_carry = chunk
                .checked_add(carry)
                .ok_or(ZkAmsMkheErrorV1::InvalidPolynomial)?;
            let (balanced, next_carry) = if with_carry >= half_base {
                (
                    i64::try_from(with_carry).map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
                        - i64::try_from(base).map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
                    1,
                )
            } else {
                (
                    i64::try_from(with_carry).map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
                    0,
                )
            };
            output[coefficient] = if negative { -balanced } else { balanced };
            carry = next_carry;
        }
        if carry != 0 {
            return Err(ZkAmsMkheErrorV1::InvalidProfile);
        }
    }
    digits
        .iter()
        .map(|values| RnsPolynomial::from_signed(profile, values))
        .collect()
}
#[cfg(test)]
fn derive_rkg_common_a(
    profile: &BgvProfile,
    party_set: &PartySet,
    transcript_digest: [u8; 32],
    left: ZkAmsMkhePartyIdV1,
    right: ZkAmsMkhePartyIdV1,
    digit: usize,
) -> Result<RnsPolynomial, ZkAmsMkheErrorV1> {
    if transcript_digest == [0; 32]
        || left > right
        || party_set.index_of(left).is_none()
        || party_set.index_of(right).is_none()
        || digit >= profile.gadget_digits
    {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    let mut context = Vec::with_capacity(130);
    context.extend_from_slice(&party_set.digest);
    context.extend_from_slice(&transcript_digest);
    context.extend_from_slice(&left.0);
    context.extend_from_slice(&right.0);
    context.extend_from_slice(
        &u16::try_from(digit)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidKeyMaterial)?
            .to_be_bytes(),
    );
    derive_uniform_rns_from_context(profile, b"iroha.zk-ams.v1.mkhe.rkg-common-a", &context)
}
#[cfg(test)]
fn derive_uniform_rns_from_context(
    profile: &BgvProfile,
    domain: &[u8],
    context: &[u8],
) -> Result<RnsPolynomial, ZkAmsMkheErrorV1> {
    profile.validate()?;
    if domain.is_empty() || context.is_empty() {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    let maximum_xof_bytes = profile
        .ring_degree
        .checked_mul(profile.moduli.len())
        .and_then(|value| value.checked_mul(MAX_RANDOM_REJECTION_ATTEMPTS_V1))
        .and_then(|value| value.checked_mul(core::mem::size_of::<u64>()))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    checked_rng_bytes(profile, maximum_xof_bytes)?;
    let profile_digest = profile.digest()?;
    let mut coefficients = Vec::with_capacity(profile.ring_degree * profile.moduli.len());
    for (limb, &modulus) in profile.moduli.iter().enumerate() {
        let mut frame = Vec::with_capacity(domain.len() + context.len() + 48);
        frame.extend_from_slice(domain);
        frame.extend_from_slice(&profile_digest);
        frame.extend_from_slice(
            &u32::try_from(context.len())
                .map_err(|_| ZkAmsMkheErrorV1::InvalidKeyMaterial)?
                .to_be_bytes(),
        );
        frame.extend_from_slice(context);
        frame.extend_from_slice(
            &u16::try_from(limb)
                .map_err(|_| ZkAmsMkheErrorV1::InvalidKeyMaterial)?
                .to_be_bytes(),
        );
        let mut stream = Shake256Reader::new(&frame);
        let zone = u64::MAX - u64::MAX % modulus;
        for _ in 0..profile.ring_degree {
            let mut accepted = None;
            for _ in 0..MAX_RANDOM_REJECTION_ATTEMPTS_V1 {
                let mut bytes = [0_u8; 8];
                stream.read(&mut bytes);
                let candidate = u64::from_le_bytes(bytes);
                if candidate < zone {
                    accepted = Some(candidate % modulus);
                    break;
                }
            }
            coefficients.push(accepted.ok_or(ZkAmsMkheErrorV1::InvalidProfile)?);
        }
    }
    RnsPolynomial::from_flat(profile, coefficients)
}
#[cfg(test)]
fn checked_rkg_round_one_contribution_bytes(
    profile: &BgvProfile,
) -> Result<usize, ZkAmsMkheErrorV1> {
    let polynomial_bytes = checked_rns_polynomial_bytes(profile)?;
    1_usize
        .checked_add(32 + 32 + 32 + 3 * PARTY_ID_BYTES_V1 + SCHNORR_SIGNATURE_BYTES_V1 + 33 + 4)
        .and_then(|bytes| bytes.checked_add(2 * profile.gadget_digits * polynomial_bytes))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
}
#[cfg(test)]
fn checked_rkg_round_two_contribution_bytes(
    profile: &BgvProfile,
) -> Result<usize, ZkAmsMkheErrorV1> {
    let polynomial_bytes = checked_rns_polynomial_bytes(profile)?;
    1_usize
        .checked_add(
            32 + 32 + 32 + 32 + 3 * PARTY_ID_BYTES_V1 + SCHNORR_SIGNATURE_BYTES_V1 + 33 + 4,
        )
        .and_then(|bytes| bytes.checked_add(profile.gadget_digits * polynomial_bytes))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
}
#[cfg(test)]
fn checked_product_relinearization_key_bytes(
    profile: &BgvProfile,
    party_count: usize,
) -> Result<usize, ZkAmsMkheErrorV1> {
    1_usize
        .checked_add(32 + 2 * PARTY_ID_BYTES_V1 + 32 + 32 + 32 + 32 + 4)
        .and_then(|bytes| bytes.checked_add(party_count * 32))
        .and_then(|bytes| {
            bytes.checked_add(
                profile.gadget_digits
                    * checked_linear_ciphertext_bytes(profile, party_count).ok()?,
            )
        })
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
}
#[cfg(test)]
fn checked_galois_key_bytes(profile: &BgvProfile) -> Result<usize, ZkAmsMkheErrorV1> {
    1_usize
        .checked_add(32 + 32 + PARTY_ID_BYTES_V1 + 4 + 33 + SCHNORR_SIGNATURE_BYTES_V1 + 4)
        .and_then(|bytes| {
            bytes.checked_add(
                profile.gadget_digits * checked_linear_ciphertext_bytes(profile, 1).ok()?,
            )
        })
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
}
#[cfg(test)]
fn rkg_round_one_contribution_digest(
    contribution: &RkgRoundOneContribution,
    profile: &BgvProfile,
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let mut hash = super::super::sponge::Keccak256::new();
    hash.update(b"iroha.zk-ams.v1.mkhe.rkg-round-one-contribution");
    hash.update(&[contribution.version]);
    hash.update(&contribution.profile_digest);
    hash.update(&contribution.party_set.digest);
    hash.update(&contribution.transcript_digest);
    hash.update(&contribution.left.0);
    hash.update(&contribution.right.0);
    hash.update(&contribution.party.0);
    hash_rkg_entries(&mut hash, &contribution.entries, profile)?;
    Ok(hash.finalize())
}
#[cfg(test)]
fn rkg_state_integrity_digest(
    state: &RkgEphemeralState,
    profile: &BgvProfile,
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    if state.ephemeral.len() != profile.gadget_digits
        || state
            .ephemeral
            .iter()
            .any(|polynomial| polynomial.coefficients.len() != profile.ring_degree)
        || state.round_one_contribution_digest == [0; 32]
    {
        return Err(ZkAmsMkheErrorV1::InvalidKeyMaterial);
    }
    let mut hash = super::super::sponge::Keccak256::new();
    hash.update(b"iroha.zk-ams.v1.mkhe.rkg-ephemeral-state-integrity");
    hash.update(&state.profile_digest);
    hash.update(&state.party_set_digest);
    hash.update(&state.transcript_digest);
    hash.update(&state.left.0);
    hash.update(&state.right.0);
    hash.update(&state.party.0);
    hash.update(&state.round_one_contribution_digest);
    for polynomial in &state.ephemeral {
        for coefficient in &polynomial.coefficients {
            hash.update(&coefficient.to_be_bytes());
        }
    }
    Ok(hash.finalize())
}
#[cfg(test)]
fn rkg_round_one_aggregate_digest(
    aggregate: &RkgRoundOneAggregate,
    profile: &BgvProfile,
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let mut hash = super::super::sponge::Keccak256::new();
    hash.update(b"iroha.zk-ams.v1.mkhe.rkg-round-one-aggregate");
    hash.update(&[aggregate.version]);
    hash.update(&aggregate.profile_digest);
    hash.update(&aggregate.party_set.digest);
    hash.update(&aggregate.transcript_digest);
    hash.update(&aggregate.left.0);
    hash.update(&aggregate.right.0);
    for digest in &aggregate.contribution_digests {
        hash.update(digest);
    }
    hash_rkg_entries(&mut hash, &aggregate.entries, profile)?;
    Ok(hash.finalize())
}
#[cfg(test)]
fn rkg_round_two_contribution_digest(
    contribution: &RkgRoundTwoContribution,
    profile: &BgvProfile,
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let mut hash = super::super::sponge::Keccak256::new();
    hash.update(b"iroha.zk-ams.v1.mkhe.rkg-round-two-contribution");
    hash.update(&[contribution.version]);
    hash.update(&contribution.profile_digest);
    hash.update(&contribution.party_set.digest);
    hash.update(&contribution.transcript_digest);
    hash.update(&contribution.round_one_digest);
    hash.update(&contribution.left.0);
    hash.update(&contribution.right.0);
    hash.update(&contribution.party.0);
    for polynomial in &contribution.k0 {
        hash_rns_polynomial(&mut hash, polynomial, profile)?;
    }
    Ok(hash.finalize())
}
#[cfg(test)]
fn product_relinearization_key_digest(
    key: &ProductRelinearizationKey,
    profile: &BgvProfile,
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let mut hash = super::super::sponge::Keccak256::new();
    hash.update(b"iroha.zk-ams.v1.mkhe.product-relinearization-key");
    hash.update(&[key.version]);
    hash.update(&key.profile_digest);
    hash.update(&key.left.0);
    hash.update(&key.right.0);
    hash.update(&key.target_set.digest);
    hash.update(&key.transcript_digest);
    hash.update(&key.round_one_digest);
    for digest in &key.contribution_digests {
        hash.update(digest);
    }
    for digit in &key.digits {
        hash_linear_ciphertext(&mut hash, digit, profile)?;
    }
    Ok(hash.finalize())
}
#[cfg(test)]
fn galois_key_digest(key: &GaloisKey, profile: &BgvProfile) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let mut hash = super::super::sponge::Keccak256::new();
    hash.update(b"iroha.zk-ams.v1.mkhe.galois-key");
    hash.update(&[key.version]);
    hash.update(&key.profile_digest);
    hash.update(&key.transcript_digest);
    hash.update(&key.party.0);
    hash.update(
        &u32::try_from(key.exponent)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidKeyMaterial)?
            .to_be_bytes(),
    );
    for digit in &key.digits {
        hash_linear_ciphertext(&mut hash, digit, profile)?;
    }
    Ok(hash.finalize())
}
#[cfg(test)]
fn hash_rkg_entries(
    hash: &mut super::super::sponge::Keccak256,
    entries: &[RkgRoundOneEntry],
    profile: &BgvProfile,
) -> Result<(), ZkAmsMkheErrorV1> {
    hash.update(
        &u16::try_from(entries.len())
            .map_err(|_| ZkAmsMkheErrorV1::InvalidKeyMaterial)?
            .to_be_bytes(),
    );
    for entry in entries {
        hash_rns_polynomial(hash, &entry.h0, profile)?;
        hash_rns_polynomial(hash, &entry.h1, profile)?;
    }
    Ok(())
}
#[cfg(test)]
fn hash_linear_ciphertext(
    hash: &mut super::super::sponge::Keccak256,
    ciphertext: &LinearCiphertext,
    profile: &BgvProfile,
) -> Result<(), ZkAmsMkheErrorV1> {
    ciphertext.validate(profile)?;
    hash.update(&[ciphertext.version]);
    hash.update(&ciphertext.profile_digest);
    hash.update(&ciphertext.party_set.digest);
    hash.update(&[ciphertext.level]);
    hash_rns_polynomial(hash, &ciphertext.constant, profile)?;
    for component in &ciphertext.linear {
        hash_rns_polynomial(hash, component, profile)?;
    }
    Ok(())
}
#[cfg(test)]
fn hash_rns_polynomial(
    hash: &mut super::super::sponge::Keccak256,
    polynomial: &RnsPolynomial,
    profile: &BgvProfile,
) -> Result<(), ZkAmsMkheErrorV1> {
    polynomial.validate(profile)?;
    hash.update(
        &u32::try_from(polynomial.coefficients.len())
            .map_err(|_| ZkAmsMkheErrorV1::InvalidPolynomial)?
            .to_be_bytes(),
    );
    for coefficient in &polynomial.coefficients {
        hash.update(&coefficient.to_be_bytes());
    }
    Ok(())
}
fn checked_rns_polynomial_bytes(profile: &BgvProfile) -> Result<usize, ZkAmsMkheErrorV1> {
    // Four bytes encode the exact flat coefficient count in the canonical
    // wire, followed by limb-major u64 residues.
    profile
        .ring_degree
        .checked_mul(profile.moduli.len())
        .and_then(|words| words.checked_mul(core::mem::size_of::<u64>()))
        .and_then(|bytes| bytes.checked_add(core::mem::size_of::<u32>()))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
}
fn checked_gadget_decomposition_workspace_bytes(
    profile: &BgvProfile,
) -> Result<usize, ZkAmsMkheErrorV1> {
    // Canonical accounted working set: the signed coefficient matrix remains
    // live while all RNS digit polynomials are materialized, alongside the
    // per-coefficient CRT residues and two fixed-width reconstruction values.
    // Allocator metadata is deliberately excluded from the governed portable
    // bound because its size is target-specific.
    let signed_digits = profile
        .gadget_digits
        .checked_mul(profile.ring_degree)
        .and_then(|words| words.checked_mul(core::mem::size_of::<i64>()))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let rns_digits = profile
        .gadget_digits
        .checked_mul(profile.ring_degree)
        .and_then(|words| words.checked_mul(profile.moduli.len()))
        .and_then(|words| words.checked_mul(core::mem::size_of::<u64>()))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let residues = profile
        .moduli
        .len()
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let reconstruction = 2_usize
        .checked_mul(WIDE_LIMBS)
        .and_then(|words| words.checked_mul(core::mem::size_of::<u64>()))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    signed_digits
        .checked_add(rns_digits)
        .and_then(|bytes| bytes.checked_add(residues))
        .and_then(|bytes| bytes.checked_add(reconstruction))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
}
fn checked_hybrid_streaming_workspace_bytes(
    profile: &BgvProfile,
) -> Result<usize, ZkAmsMkheErrorV1> {
    // The release path keeps the input, one basis-extended output, and one
    // accumulator polynomial live.  Only two degree-N limb buffers and one
    // signed coefficient buffer accompany them; no vector of all digits is
    // ever materialized.
    let polynomial = checked_rns_polynomial_bytes(profile)?;
    let three_polynomials = polynomial
        .checked_mul(3)
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let limb_scratch = profile
        .ring_degree
        .checked_mul(2)
        .and_then(|words| words.checked_mul(core::mem::size_of::<u64>()))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let signed_scratch = profile
        .ring_degree
        .checked_mul(core::mem::size_of::<i64>())
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    three_polynomials
        .checked_add(limb_scratch)
        .and_then(|bytes| bytes.checked_add(signed_scratch))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
}
fn checked_linear_ciphertext_bytes(
    profile: &BgvProfile,
    party_count: usize,
) -> Result<usize, ZkAmsMkheErrorV1> {
    if party_count == 0 || party_count > MAX_PARTIES_V1 {
        return Err(ZkAmsMkheErrorV1::InvalidPartySet);
    }
    let polynomial_count = party_count
        .checked_add(1)
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    // version, profile digest, party-set digest, level, party count, exact
    // ordered party identifiers, polynomial count, and flat polynomials.
    1_usize
        .checked_add(32)
        .and_then(|bytes| bytes.checked_add(32))
        .and_then(|bytes| bytes.checked_add(1 + 1 + 4))
        .and_then(|bytes| bytes.checked_add(party_count * PARTY_ID_BYTES_V1))
        .and_then(|bytes| {
            bytes.checked_add(polynomial_count * checked_rns_polynomial_bytes(profile).ok()?)
        })
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
}
#[cfg(test)]
fn checked_quadratic_ciphertext_bytes(
    profile: &BgvProfile,
    party_count: usize,
) -> Result<usize, ZkAmsMkheErrorV1> {
    if party_count == 0 || party_count > MAX_PARTIES_V1 {
        return Err(ZkAmsMkheErrorV1::InvalidPartySet);
    }
    let quadratic_count = party_count
        .checked_mul(party_count + 1)
        .and_then(|value| value.checked_div(2))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let polynomial_count = 1_usize
        .checked_add(party_count)
        .and_then(|value| value.checked_add(quadratic_count))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    // Each quadratic component repeats its canonical ordered pair IDs so a
    // decoder cannot reinterpret component position under another key set.
    1_usize
        .checked_add(32)
        .and_then(|bytes| bytes.checked_add(32))
        .and_then(|bytes| bytes.checked_add(1 + 1 + 4))
        .and_then(|bytes| bytes.checked_add(party_count * PARTY_ID_BYTES_V1))
        .and_then(|bytes| bytes.checked_add(quadratic_count * 2 * PARTY_ID_BYTES_V1))
        .and_then(|bytes| {
            bytes.checked_add(polynomial_count * checked_rns_polynomial_bytes(profile).ok()?)
        })
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
}
fn ring_multiplication_work(profile: &BgvProfile) -> Result<u64, ZkAmsMkheErrorV1> {
    u64::try_from(profile.ring_degree)
        .ok()
        .and_then(|degree| degree.checked_mul(u64::from(profile.ring_degree.trailing_zeros()) + 1))
        .and_then(|work| work.checked_mul(profile.moduli.len() as u64))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
}
fn phase23_max_composed_rotation_key_switch_count(
    slot_count: usize,
) -> Result<usize, ZkAmsMkheErrorV1> {
    if slot_count == 0 || !slot_count.is_power_of_two() {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    usize::try_from(slot_count.trailing_zeros())
        .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?
        .checked_add(1)
        .map(|value| value / 2)
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
}
#[cfg(test)]
fn phase23_rotation_ring_multiplication_count(
    profile: &BgvProfile,
    party_count: usize,
    key_switch_count: usize,
) -> Result<usize, ZkAmsMkheErrorV1> {
    if party_count == 0 {
        return Err(ZkAmsMkheErrorV1::InvalidPartySet);
    }
    party_count
        .checked_mul(profile.gadget_digits)
        .and_then(|value| value.checked_mul(2))
        .and_then(|value| value.checked_mul(key_switch_count))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
}
#[cfg(test)]
fn checked_ring_multiplication_work(
    profile: &BgvProfile,
    multiplication_count: usize,
) -> Result<(), ZkAmsMkheErrorV1> {
    let work = ring_multiplication_work(profile)?
        .checked_mul(
            u64::try_from(multiplication_count)
                .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?,
        )
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    if work > profile.max_work_units {
        return Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded);
    }
    Ok(())
}
#[cfg(test)]
fn checked_coefficient_work(
    profile: &BgvProfile,
    polynomial_passes: usize,
) -> Result<(), ZkAmsMkheErrorV1> {
    let work = profile
        .ring_degree
        .checked_mul(profile.moduli.len())
        .and_then(|value| value.checked_mul(polynomial_passes))
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    if work > profile.max_work_units {
        return Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded);
    }
    Ok(())
}
#[cfg(test)]
fn checked_rng_bytes(profile: &BgvProfile, maximum_bytes: usize) -> Result<(), ZkAmsMkheErrorV1> {
    let work =
        u64::try_from(maximum_bytes).map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    if work > profile.max_work_units {
        return Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded);
    }
    Ok(())
}
#[cfg(test)]
fn encrypt<R: MaskedRelaxedRandomSourceV1>(
    profile: &BgvProfile,
    public: &IndependentPublicKey,
    message: &RnsPolynomial,
    random: &mut R,
) -> Result<LinearCiphertext, ZkAmsMkheErrorV1> {
    validate_public_key(profile, public)?;
    message.validate(profile)?;
    let ephemeral = SecretPolynomial::sample_ternary(profile, random)?;
    let error_zero = SecretPolynomial::sample_error(profile, random)?;
    let error_one = SecretPolynomial::sample_error(profile, random)?;
    let ephemeral = ephemeral.as_rns(profile)?;
    let constant = public
        .b
        .mul(&ephemeral, profile)?
        .add(
            &error_zero
                .as_rns(profile)?
                .scale_plaintext_modulus(profile)?,
            profile,
        )?
        .add(message, profile)?;
    let linear = public.a.mul(&ephemeral, profile)?.add(
        &error_one
            .as_rns(profile)?
            .scale_plaintext_modulus(profile)?,
        profile,
    )?;
    let output = LinearCiphertext {
        version: MKHE_VERSION_V1,
        profile_digest: profile.digest()?,
        party_set: PartySet::singleton(public.party),
        level: 0,
        constant,
        linear: vec![linear],
    };
    output.validate(profile)?;
    Ok(output)
}
#[cfg(test)]
fn decrypt_polynomial(
    profile: &BgvProfile,
    ciphertext: &LinearCiphertext,
    secrets: &[&IndependentSecretKey],
) -> Result<RnsPolynomial, ZkAmsMkheErrorV1> {
    ciphertext.validate(profile)?;
    if secrets.len() != ciphertext.party_set.parties.len() {
        return Err(ZkAmsMkheErrorV1::InvalidShareSet);
    }
    let mut value = ciphertext.constant.clone();
    for ((party, component), secret) in ciphertext
        .party_set
        .parties
        .iter()
        .zip(&ciphertext.linear)
        .zip(secrets)
    {
        if *party != secret.party || secret.profile_digest != profile.digest()? {
            return Err(ZkAmsMkheErrorV1::InvalidShareSet);
        }
        value = value.add(
            &component.mul(&secret.secret.as_rns(profile)?, profile)?,
            profile,
        )?;
    }
    Ok(value)
}
#[cfg(test)]
fn decrypt_test_plaintext(
    profile: &BgvProfile,
    ciphertext: &LinearCiphertext,
    secrets: &[&IndependentSecretKey],
) -> Result<Vec<u64>, ZkAmsMkheErrorV1> {
    let polynomial = decrypt_polynomial(profile, ciphertext, secrets)?;
    reduce_test_polynomial(profile, &polynomial)
}
#[cfg(test)]
fn decrypt_quadratic_test_plaintext(
    profile: &BgvProfile,
    ciphertext: &QuadraticCiphertext,
    secrets: &[&IndependentSecretKey],
) -> Result<Vec<u64>, ZkAmsMkheErrorV1> {
    ciphertext.validate(profile)?;
    if secrets.len() != ciphertext.party_set.parties.len()
        || ciphertext
            .party_set
            .parties
            .iter()
            .zip(secrets)
            .any(|(party, secret)| {
                *party != secret.party || secret.profile_digest != ciphertext.profile_digest
            })
    {
        return Err(ZkAmsMkheErrorV1::InvalidShareSet);
    }
    let secret_polynomials = secrets
        .iter()
        .map(|secret| secret.secret.as_rns(profile))
        .collect::<Result<Vec<_>, _>>()?;
    let mut value = ciphertext.constant.clone();
    for (component, secret) in ciphertext.linear.iter().zip(&secret_polynomials) {
        value = value.add(&component.mul(secret, profile)?, profile)?;
    }
    for component in &ciphertext.quadratic {
        let left = ciphertext
            .party_set
            .index_of(component.left)
            .ok_or(ZkAmsMkheErrorV1::InvalidCiphertext)?;
        let right = ciphertext
            .party_set
            .index_of(component.right)
            .ok_or(ZkAmsMkheErrorV1::InvalidCiphertext)?;
        let secret_product = secret_polynomials[left].mul(&secret_polynomials[right], profile)?;
        value = value.add(&component.value.mul(&secret_product, profile)?, profile)?;
    }
    reduce_test_polynomial(profile, &value)
}
#[cfg(test)]
fn assert_test_evaluation_key_equation(
    profile: &BgvProfile,
    ciphertext: &LinearCiphertext,
    secrets: &[&IndependentSecretKey],
    expected_raw: &RnsPolynomial,
    noise_bound: u64,
) {
    let PlaintextModulus::Tiny(plaintext_modulus) = profile.plaintext_modulus else {
        panic!("the exact small-noise oracle is restricted to the tiny test profile");
    };
    let decrypted = decrypt_polynomial(profile, ciphertext, secrets).unwrap();
    let difference = decrypted.sub(expected_raw, profile).unwrap();
    let ciphertext_modulus = modulus_product(profile.moduli).unwrap();
    let half_modulus = ciphertext_modulus.shr_one();
    for coefficient in 0..profile.ring_degree {
        let residues = (0..profile.moduli.len())
            .map(|limb| difference.limb(profile, limb)[coefficient])
            .collect::<Vec<_>>();
        let reconstructed = WideUint::crt(&residues, profile.moduli).unwrap();
        let magnitude = if reconstructed > half_modulus {
            ciphertext_modulus.checked_sub(reconstructed).unwrap()
        } else {
            reconstructed
        };
        assert_eq!(
            magnitude.mod_u64(plaintext_modulus),
            0,
            "evaluation-key coefficient {coefficient} must differ from its exact RNS relation only by t times bounded noise"
        );
        assert!(
            magnitude.limbs[1..].iter().all(|limb| *limb == 0),
            "tiny-profile noise magnitude must fit u64"
        );
        assert!(
            magnitude.limbs[0] / plaintext_modulus <= noise_bound,
            "evaluation-key coefficient {coefficient} exceeds the derived noise bound"
        );
    }
}
#[cfg(test)]
fn test_bilinear_key_noise_bound(profile: &BgvProfile, party_count: u64) -> u64 {
    let degree = u64::try_from(profile.ring_degree).unwrap();
    let eta = u64::from(profile.error_eta);
    let left_error_times_right = degree
        .checked_mul(party_count)
        .and_then(|bound| bound.checked_mul(eta))
        .unwrap();
    let right_error_times_ephemeral = degree
        .checked_mul(party_count)
        .and_then(|bound| bound.checked_mul(party_count))
        .and_then(|bound| bound.checked_mul(eta))
        .unwrap();
    left_error_times_right
        .checked_add(right_error_times_ephemeral)
        .and_then(|bound| {
            party_count
                .checked_mul(eta)
                .and_then(|fresh_error| bound.checked_add(fresh_error))
        })
        .unwrap()
}
#[cfg(test)]
fn reduce_test_polynomial(
    profile: &BgvProfile,
    polynomial: &RnsPolynomial,
) -> Result<Vec<u64>, ZkAmsMkheErrorV1> {
    let PlaintextModulus::Tiny(plaintext_modulus) = profile.plaintext_modulus else {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    };
    polynomial.validate(profile)?;
    let ciphertext_modulus = modulus_product(profile.moduli)?;
    let half_modulus = ciphertext_modulus.shr_one();
    (0..profile.ring_degree)
        .map(|coefficient| {
            let residues = (0..profile.moduli.len())
                .map(|limb| polynomial.limb(profile, limb)[coefficient])
                .collect::<Vec<_>>();
            let reconstructed = WideUint::crt(&residues, profile.moduli)?;
            if reconstructed > half_modulus {
                let magnitude = ciphertext_modulus
                    .checked_sub(reconstructed)
                    .ok_or(ZkAmsMkheErrorV1::DecryptionBoundExceeded)?;
                let reduced = magnitude.mod_u64(plaintext_modulus);
                Ok(if reduced == 0 {
                    0
                } else {
                    plaintext_modulus - reduced
                })
            } else {
                Ok(reconstructed.mod_u64(plaintext_modulus))
            }
        })
        .collect()
}
#[cfg(test)]
fn sample_uniform_rns<R: MaskedRelaxedRandomSourceV1>(
    profile: &BgvProfile,
    random: &mut R,
) -> Result<RnsPolynomial, ZkAmsMkheErrorV1> {
    let max_bytes = profile
        .ring_degree
        .checked_mul(profile.moduli.len())
        .and_then(|value| value.checked_mul(MAX_RANDOM_REJECTION_ATTEMPTS_V1))
        .and_then(|value| value.checked_mul(core::mem::size_of::<u64>()))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    checked_rng_bytes(profile, max_bytes)?;
    let mut coefficients = Vec::with_capacity(profile.ring_degree * profile.moduli.len());
    for &modulus in profile.moduli {
        for _ in 0..profile.ring_degree {
            coefficients.push(sample_below(modulus, random)?);
        }
    }
    RnsPolynomial::from_flat(profile, coefficients)
}
#[cfg(test)]
fn random_byte<R: MaskedRelaxedRandomSourceV1>(random: &mut R) -> Result<u8, ZkAmsMkheErrorV1> {
    let mut byte = ZeroizingRandomBytesV1::<1>::zeroed();
    random
        .fill_bytes(byte.as_mut_slice())
        .map_err(|_| ZkAmsMkheErrorV1::RandomUnavailable)?;
    Ok(byte.as_array()[0])
}
#[cfg(test)]
fn sample_below<R: MaskedRelaxedRandomSourceV1>(
    modulus: u64,
    random: &mut R,
) -> Result<u64, ZkAmsMkheErrorV1> {
    let zone = u64::MAX - u64::MAX % modulus;
    for _ in 0..MAX_RANDOM_REJECTION_ATTEMPTS_V1 {
        let mut bytes = ZeroizingRandomBytesV1::<8>::zeroed();
        random
            .fill_bytes(bytes.as_mut_slice())
            .map_err(|_| ZkAmsMkheErrorV1::RandomUnavailable)?;
        let candidate = bytes
            .as_array()
            .iter()
            .enumerate()
            .fold(0_u64, |value, (index, byte)| {
                value | (u64::from(*byte) << (index * 8))
            });
        if candidate < zone {
            return Ok(candidate % modulus);
        }
    }
    Err(ZkAmsMkheErrorV1::RandomUnavailable)
}
#[cfg(test)]
fn signed_mod(value: i64, modulus: u64) -> u64 {
    if value >= 0 {
        value as u64 % modulus
    } else {
        let magnitude = value.unsigned_abs() % modulus;
        if magnitude == 0 {
            0
        } else {
            modulus - magnitude
        }
    }
}
// The scalar and wide-integer helpers below are test-only references. Production code takes this
// arithmetic from `iroha_fhe`; the references stay independent of it so the test-only ring
// arithmetic keeps its own derivation.
#[cfg(test)]
fn mod_add(left: u64, right: u64, modulus: u64) -> u64 {
    let sum = left + right;
    let (reduced, borrow) = sum.overflowing_sub(modulus);
    let mask = 0_u64.wrapping_sub(u64::from(borrow));
    (reduced & !mask) | (sum & mask)
}
#[cfg(test)]
fn mod_sub(left: u64, right: u64, modulus: u64) -> u64 {
    let (difference, borrow) = left.overflowing_sub(right);
    difference.wrapping_add(modulus & 0_u64.wrapping_sub(u64::from(borrow)))
}
#[cfg(test)]
fn mod_mul(left: u64, right: u64, modulus: u64) -> u64 {
    ((u128::from(left) * u128::from(right)) % u128::from(modulus)) as u64
}
#[cfg(test)]
fn mod_pow(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1_u64;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = mod_mul(result, base, modulus);
        }
        base = mod_mul(base, base, modulus);
        exponent >>= 1;
    }
    result
}
#[cfg(test)]
fn mod_inverse(value: u64, modulus: u64) -> Option<u64> {
    if value == 0 || modulus < 2 {
        return None;
    }
    Some(mod_pow(value, modulus - 2, modulus))
}
#[cfg(test)]
fn is_prime_u64(value: u64) -> bool {
    if value < 2 {
        return false;
    }
    for prime in [2_u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if value == prime {
            return true;
        }
        if value.is_multiple_of(prime) {
            return false;
        }
    }
    let mut d = value - 1;
    let s = d.trailing_zeros();
    d >>= s;
    for base in [2_u64, 325, 9_375, 28_178, 450_775, 9_780_504, 1_795_265_022] {
        if base.is_multiple_of(value) {
            continue;
        }
        let mut x = mod_pow(base % value, d, value);
        if x == 1 || x == value - 1 {
            continue;
        }
        let mut composite = true;
        for _ in 1..s {
            x = mod_mul(x, x, value);
            if x == value - 1 {
                composite = false;
                break;
            }
        }
        if composite {
            return false;
        }
    }
    true
}
#[cfg(test)]
fn bit_reverse_permute(values: &mut [u64]) {
    let mut target = 0_usize;
    for index in 1..values.len() {
        let mut bit = values.len() >> 1;
        while target & bit != 0 {
            target ^= bit;
            bit >>= 1;
        }
        target ^= bit;
        if index < target {
            values.swap(index, target);
        }
    }
}
// TODO: Keep this and the staged/packing NTT corridors on fixed-order scalar
// implementations and fail closed until a feature-gated parallel, SIMD/NEON,
// Metal, or CUDA path passes release-shape output/KAT parity, secret-handling
// review, and implementation-derived peak-RSS accounting; do not select or
// claim an accelerated backend before those gates close.
#[cfg(test)]
fn cyclic_ntt(values: &mut [u64], root: u64, modulus: u64) {
    bit_reverse_permute(values);
    let mut width = 2;
    while width <= values.len() {
        let twiddle_step = mod_pow(root, (values.len() / width) as u64, modulus);
        for block in values.chunks_exact_mut(width) {
            let mut twiddle = 1_u64;
            for offset in 0..width / 2 {
                let even = block[offset];
                let odd = mod_mul(block[offset + width / 2], twiddle, modulus);
                block[offset] = mod_add(even, odd, modulus);
                block[offset + width / 2] = mod_sub(even, odd, modulus);
                twiddle = mod_mul(twiddle, twiddle_step, modulus);
            }
        }
        width <<= 1;
    }
}
#[cfg(test)]
fn inverse_cyclic_ntt(values: &mut [u64], root: u64, modulus: u64) -> Result<(), ZkAmsMkheErrorV1> {
    let inverse_root = mod_inverse(root, modulus).ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    cyclic_ntt(values, inverse_root, modulus);
    let inverse_degree =
        mod_inverse(values.len() as u64, modulus).ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    for value in values {
        *value = mod_mul(*value, inverse_degree, modulus);
    }
    Ok(())
}
#[cfg(test)]
fn negacyclic_multiply(
    left: &[u64],
    right: &[u64],
    modulus: u64,
    psi: u64,
) -> Result<Vec<u64>, ZkAmsMkheErrorV1> {
    if left.len() != right.len() || left.is_empty() || !left.len().is_power_of_two() {
        return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
    }
    let mut left_twisted = try_exact_capacity_vec_v1(left.len())
        .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let mut right_twisted = try_exact_capacity_vec_v1(right.len())
        .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let mut twist = 1_u64;
    for (&left, &right) in left.iter().zip(right) {
        left_twisted.push(mod_mul(left, twist, modulus));
        right_twisted.push(mod_mul(right, twist, modulus));
        twist = mod_mul(twist, psi, modulus);
    }
    if left_twisted.len() != left.len()
        || left_twisted.capacity() != left.len()
        || right_twisted.len() != right.len()
        || right_twisted.capacity() != right.len()
    {
        return Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded);
    }
    let root = mod_mul(psi, psi, modulus);
    cyclic_ntt(&mut left_twisted, root, modulus);
    cyclic_ntt(&mut right_twisted, root, modulus);
    for (left, right) in left_twisted.iter_mut().zip(right_twisted) {
        *left = mod_mul(*left, right, modulus);
    }
    inverse_cyclic_ntt(&mut left_twisted, root, modulus)?;
    let inverse_psi = mod_inverse(psi, modulus).ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    let mut untwist = 1_u64;
    for value in &mut left_twisted {
        *value = mod_mul(*value, untwist, modulus);
        untwist = mod_mul(untwist, inverse_psi, modulus);
    }
    Ok(left_twisted)
}
#[cfg(test)]
fn bytes_mod_u64(bytes: &[u8], modulus: u64) -> u64 {
    bytes.iter().fold(0_u64, |accumulator, byte| {
        mod_add(
            mod_mul(accumulator, 256 % modulus, modulus),
            u64::from(*byte) % modulus,
            modulus,
        )
    })
}
#[cfg(test)]
fn t256_centered_residue_with_modulus_residue(
    value: &[u8; 32],
    modulus: u64,
    plaintext_modulus_residue: u64,
) -> u64 {
    let residue = bytes_mod_u64(value, modulus);
    if *value <= T256_CENTERED_MAX_BE_V1 {
        residue
    } else {
        // Canonical scalars above `(p - 1) / 2` denote the negative integer
        // `value - p`.  This centered lift is what makes reduction commute
        // exactly with the `X -> X^k` sign changes of ring automorphisms.
        mod_sub(residue, plaintext_modulus_residue, modulus)
    }
}
/// Word width of one fixed-width reconstruction value in the governed workspace accounting.
const WIDE_LIMBS: usize = MAX_RNS_LIMBS_V1;
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct WideUint {
    limbs: [u64; WIDE_LIMBS],
}
#[cfg(test)]
impl WideUint {
    #[cfg(test)]
    const fn zero() -> Self {
        Self {
            limbs: [0; WIDE_LIMBS],
        }
    }
    const fn one() -> Self {
        let mut limbs = [0; WIDE_LIMBS];
        limbs[0] = 1;
        Self { limbs }
    }
    fn checked_mul_u64(self, rhs: u64) -> Option<Self> {
        let mut output = [0_u64; WIDE_LIMBS];
        let mut carry = 0_u128;
        for (destination, value) in output.iter_mut().zip(self.limbs) {
            let product = u128::from(value) * u128::from(rhs) + carry;
            *destination = product as u64;
            carry = product >> 64;
        }
        (carry == 0).then_some(Self { limbs: output })
    }
    #[cfg(test)]
    fn checked_add_mul_u64(self, multiplicand: Self, scalar: u64) -> Option<Self> {
        let product = multiplicand.checked_mul_u64(scalar)?;
        let mut output = [0_u64; WIDE_LIMBS];
        let mut carry = 0_u128;
        for (index, destination) in output.iter_mut().enumerate() {
            let sum = u128::from(self.limbs[index]) + u128::from(product.limbs[index]) + carry;
            *destination = sum as u64;
            carry = sum >> 64;
        }
        (carry == 0).then_some(Self { limbs: output })
    }
    #[cfg(test)]
    fn checked_sub(self, rhs: Self) -> Option<Self> {
        let mut output = [0_u64; WIDE_LIMBS];
        let mut borrow = false;
        for (index, destination) in output.iter_mut().enumerate() {
            let (first, first_borrow) = self.limbs[index].overflowing_sub(rhs.limbs[index]);
            let (second, second_borrow) = first.overflowing_sub(u64::from(borrow));
            *destination = second;
            borrow = first_borrow || second_borrow;
        }
        (!borrow).then_some(Self { limbs: output })
    }
    #[cfg(test)]
    fn shr_one(self) -> Self {
        let mut output = [0_u64; WIDE_LIMBS];
        let mut carry = 0_u64;
        for index in (0..WIDE_LIMBS).rev() {
            output[index] = (self.limbs[index] >> 1) | carry;
            carry = self.limbs[index] << 63;
        }
        Self { limbs: output }
    }
    #[cfg(test)]
    fn mod_u64(self, modulus: u64) -> u64 {
        self.limbs.iter().rev().fold(0_u64, |remainder, limb| {
            ((u128::from(remainder) << 64 | u128::from(*limb)) % u128::from(modulus)) as u64
        })
    }
    fn bit_len(self) -> usize {
        self.limbs
            .iter()
            .rposition(|value| *value != 0)
            .map_or(0, |index| {
                index * 64 + (64 - self.limbs[index].leading_zeros() as usize)
            })
    }
    #[cfg(test)]
    #[allow(
        dead_code,
        reason = "used by the private fail-closed seekable evaluated-key runtime"
    )]
    fn bits_at(self, offset: usize, width: usize) -> Result<u64, ZkAmsMkheErrorV1> {
        let bit_capacity = WIDE_LIMBS
            .checked_mul(64)
            .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
        if width == 0
            || width > 63
            || offset
                .checked_add(width)
                .is_none_or(|end| end > bit_capacity)
        {
            return Err(ZkAmsMkheErrorV1::InvalidProfile);
        }
        let limb = offset / 64;
        let shift = offset % 64;
        let mut value = self.limbs[limb] >> shift;
        if shift + width > 64 {
            let high = self
                .limbs
                .get(limb + 1)
                .copied()
                .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
            value |= high << (64 - shift);
        }
        Ok(value & ((1_u64 << width) - 1))
    }
    #[cfg(test)]
    fn crt(residues: &[u64], moduli: &[u64]) -> Result<Self, ZkAmsMkheErrorV1> {
        if residues.is_empty() || residues.len() != moduli.len() || residues.len() > WIDE_LIMBS {
            return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
        }
        let mut value = Self::zero();
        let mut product = Self::one();
        for (&residue, &modulus) in residues.iter().zip(moduli) {
            if residue >= modulus {
                return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
            }
            let current = value.mod_u64(modulus);
            let product_residue = product.mod_u64(modulus);
            let inverse =
                mod_inverse(product_residue, modulus).ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
            let correction = mod_mul(mod_sub(residue, current, modulus), inverse, modulus);
            value = value
                .checked_add_mul_u64(product, correction)
                .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
            product = product
                .checked_mul_u64(modulus)
                .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
        }
        Ok(value)
    }
}
fn modulus_product_bit_len(moduli: &[u64]) -> Result<usize, ZkAmsMkheErrorV1> {
    iroha_fhe::rns::modulus_product_bit_len(moduli, MAX_RNS_LIMBS_V1)
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
}
#[cfg(test)]
fn modulus_product(moduli: &[u64]) -> Result<WideUint, ZkAmsMkheErrorV1> {
    let mut product = WideUint::one();
    for &modulus in moduli {
        product = product
            .checked_mul_u64(modulus)
            .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    }
    Ok(product)
}
#[cfg(test)]
mod tests {
    use super::super::MaskedRelaxedRandomErrorV1;
    use super::*;
    const TEST_MODULI: [u64; 2] = [2_013_265_921, 1_811_939_329];
    const TEST_ROOTS: [u64; 2] = [1_400_279_418, 677_356_115];
    fn test_profile() -> BgvProfile {
        BgvProfile {
            profile_id: [0x51; 32],
            ring_degree: 8,
            moduli: &TEST_MODULI,
            negacyclic_roots: &TEST_ROOTS,
            plaintext_modulus: PlaintextModulus::Tiny(17),
            error_eta: 2,
            hybrid_rns_decomposition: false,
            gadget_base_log: 8,
            gadget_digits: 8,
            max_ciphertext_bytes: 1 << 20,
            max_evaluated_key_bytes: 16 << 20,
            max_round_bytes: 16 << 20,
            max_share_bytes: 4 << 20,
            max_workspace_bytes: 16 << 20,
            max_work_units: 1 << 20,
        }
    }

    #[test]
    fn native_outer_tiny_profile_matches_independent_full_frame_kats() {
        // Expected full32 values use independent Python BLAKE3 and complete labelled frames.
        // These tiny arithmetic cases do not qualify the retained release/security evidence.
        let profile = test_profile();
        assert_eq!(
            profile.digest().unwrap(),
            [
                0x4c, 0x2e, 0xa8, 0x22, 0x02, 0xea, 0xad, 0x19, 0x02, 0x61, 0x2b, 0x48, 0x18, 0xd5,
                0x60, 0xeb, 0x13, 0x7a, 0x89, 0x2e, 0x61, 0xbd, 0xcc, 0xd9, 0x4b, 0x2c, 0xa9, 0x84,
                0x8d, 0x31, 0x22, 0xce
            ]
        );
        assert_eq!(
            profile.security_parameters_digest().unwrap(),
            [
                0xd5, 0x4e, 0x33, 0xcd, 0xd7, 0xa7, 0xe5, 0x60, 0xd4, 0x99, 0x91, 0x84, 0xee, 0x32,
                0xe4, 0xb9, 0x89, 0x2d, 0x01, 0x34, 0x46, 0xfe, 0x9f, 0xb3, 0x28, 0xc8, 0x6c, 0x32,
                0xf8, 0x7e, 0xb5, 0x42
            ]
        );
        assert_eq!(
            profile.resource_policy_digest().unwrap(),
            [
                0x76, 0x19, 0x5e, 0x27, 0x13, 0x43, 0xc1, 0xe3, 0x65, 0x72, 0xda, 0xc8, 0xc3, 0x84,
                0x54, 0x69, 0x95, 0x7e, 0x8f, 0xed, 0x43, 0x87, 0x9d, 0xc8, 0xd7, 0x87, 0x9a, 0xe6,
                0x3d, 0xa8, 0x98, 0x9a
            ]
        );
        for resource in 0..6 {
            let mut changed = profile.clone();
            match resource {
                0 => changed.max_ciphertext_bytes += 1,
                1 => changed.max_evaluated_key_bytes += 1,
                2 => changed.max_round_bytes += 1,
                3 => changed.max_share_bytes += 1,
                4 => changed.max_workspace_bytes += 1,
                5 => changed.max_work_units += 1,
                _ => unreachable!("six resource fields"),
            }
            assert_ne!(changed.digest().unwrap(), profile.digest().unwrap());
            assert_ne!(
                changed.resource_policy_digest().unwrap(),
                profile.resource_policy_digest().unwrap()
            );
            assert_eq!(
                changed.security_parameters_digest().unwrap(),
                profile.security_parameters_digest().unwrap()
            );
        }
        for index in 0..32 {
            let mut changed = profile.clone();
            changed.profile_id[index] ^= 1;
            assert_ne!(changed.digest().unwrap(), profile.digest().unwrap());
            assert_ne!(
                changed.security_parameters_digest().unwrap(),
                profile.security_parameters_digest().unwrap()
            );
            assert_ne!(
                changed.resource_policy_digest().unwrap(),
                profile.resource_policy_digest().unwrap()
            );
        }
    }

    #[test]
    fn native_outer_role_and_schema_domains_match_independent_full_frame_kats() {
        let word = 0x0102_0304_0506_0708_u64.to_be_bytes();
        let fields: [&[u8]; 3] = [b"\0\xff", b"", &word];
        let roles = [
            (
                NativeOuterIdentityRoleV1::Parameter,
                [
                    0x41, 0xde, 0x2b, 0x86, 0x83, 0x68, 0x87, 0x69, 0x5f, 0xdc, 0x9a, 0xca, 0x79,
                    0x9c, 0xc3, 0x0b, 0x35, 0x74, 0xf5, 0x9b, 0x1e, 0x47, 0xca, 0x03, 0xe8, 0x41,
                    0xd0, 0x93, 0x1b, 0x36, 0x6f, 0x00,
                ],
            ),
            (
                NativeOuterIdentityRoleV1::Release,
                [
                    0x5a, 0xbc, 0xbc, 0x46, 0xca, 0xa1, 0x71, 0xcc, 0x3a, 0xa7, 0x04, 0xa5, 0x75,
                    0xa8, 0x40, 0xe5, 0xda, 0xc0, 0xa4, 0x13, 0x7f, 0x46, 0x70, 0x94, 0x21, 0x33,
                    0x00, 0x38, 0x0c, 0xaf, 0x45, 0xfe,
                ],
            ),
            (
                NativeOuterIdentityRoleV1::SourceReceipt,
                [
                    0xbf, 0x19, 0xb6, 0xd2, 0xa1, 0x08, 0x13, 0xc6, 0xf6, 0x30, 0x2a, 0x51, 0x38,
                    0x9d, 0x51, 0x5c, 0xd3, 0xfc, 0xdc, 0xae, 0x89, 0xc9, 0xea, 0xfb, 0x94, 0x2c,
                    0xd2, 0x88, 0xde, 0xbe, 0x0e, 0x09,
                ],
            ),
        ];
        for (role, expected) in roles {
            let mut identity = native_outer_identity_v1(
                role,
                b"iroha.zk-ams.v1.mkhe.resource-policy",
                fields.len(),
            );
            for field in fields {
                identity.push_field(field).unwrap();
            }
            assert_eq!(*identity.finish().unwrap().as_bytes(), expected);
            let mut changed = native_outer_identity_v1(
                role,
                b"iroha.zk-ams.v1.mkhe.resource-policy-altered",
                fields.len(),
            );
            for field in fields {
                changed.push_field(field).unwrap();
            }
            assert_ne!(*changed.finish().unwrap().as_bytes(), expected);
        }
        let schema =
            b"T=(AZ_acc)*(BZ_i)+(AZ_i)*(BZ_acc)-u_acc*(CZ_i)-u_i*(CZ_acc):componentwise:t256";
        let phase = b"iroha.zk-ams.v1.phase23.equation-6-schema";
        assert_eq!(
            native_outer_schema_v1(phase, schema),
            [
                0x18, 0x64, 0x7c, 0x90, 0xd8, 0x60, 0xb9, 0xe0, 0x05, 0x7d, 0x5e, 0x58, 0x0a, 0x7a,
                0xcb, 0xaf, 0xcb, 0x24, 0x66, 0xfa, 0xab, 0x1d, 0x45, 0x72, 0xb0, 0xfd, 0x3a, 0x26,
                0xbf, 0x4b, 0xef, 0x54
            ]
        );
        assert_ne!(
            native_outer_schema_v1(b"iroha.zk-ams.v1.phase23.equation-7-schema", schema),
            [
                0x18, 0x64, 0x7c, 0x90, 0xd8, 0x60, 0xb9, 0xe0, 0x05, 0x7d, 0x5e, 0x58, 0x0a, 0x7a,
                0xcb, 0xaf, 0xcb, 0x24, 0x66, 0xfa, 0xab, 0x1d, 0x45, 0x72, 0xb0, 0xfd, 0x3a, 0x26,
                0xbf, 0x4b, 0xef, 0x54
            ]
        );
        assert_ne!(
            native_outer_schema_v1(phase, b"T=(AZ_acc)*(BZ_i)"),
            [
                0x18, 0x64, 0x7c, 0x90, 0xd8, 0x60, 0xb9, 0xe0, 0x05, 0x7d, 0x5e, 0x58, 0x0a, 0x7a,
                0xcb, 0xaf, 0xcb, 0x24, 0x66, 0xfa, 0xab, 0x1d, 0x45, 0x72, 0xb0, 0xfd, 0x3a, 0x26,
                0xbf, 0x4b, 0xef, 0x54
            ]
        );
    }

    struct KatRandom {
        state: [u8; 32],
        counter: u64,
    }
    impl KatRandom {
        fn new(label: &[u8]) -> Self {
            Self {
                state: keccak256(label),
                counter: 0,
            }
        }
    }
    impl MaskedRelaxedRandomSourceV1 for KatRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), MaskedRelaxedRandomErrorV1> {
            let mut written = 0;
            while written < destination.len() {
                let mut frame = Vec::with_capacity(40);
                frame.extend_from_slice(&self.state);
                frame.extend_from_slice(&self.counter.to_be_bytes());
                let block = shake256(&frame, 64);
                let take = (destination.len() - written).min(block.len());
                destination[written..written + take].copy_from_slice(&block[..take]);
                self.state = keccak256(&block);
                self.counter = self.counter.wrapping_add(1);
                written += take;
            }
            Ok(())
        }
    }
    fn schoolbook_negacyclic(left: &[u64], right: &[u64], modulus: u64) -> Vec<u64> {
        let mut output = vec![0_u64; left.len()];
        for (left_index, &left_value) in left.iter().enumerate() {
            for (right_index, &right_value) in right.iter().enumerate() {
                let product = mod_mul(left_value, right_value, modulus);
                let position = left_index + right_index;
                if position < left.len() {
                    output[position] = mod_add(output[position], product, modulus);
                } else {
                    output[position - left.len()] =
                        mod_sub(output[position - left.len()], product, modulus);
                }
            }
        }
        output
    }
    fn generate_product_key(
        profile: &BgvProfile,
        party_set: &PartySet,
        transcript_digest: [u8; 32],
        left: ZkAmsMkhePartyIdV1,
        right: ZkAmsMkhePartyIdV1,
        participants: &[(&IndependentSecretKey, &AuthenticationSecret)],
        random: &mut KatRandom,
    ) -> ProductRelinearizationKey {
        let mut ordered = participants.to_vec();
        ordered.sort_by_key(|(secret, _)| secret.party);
        let mut states = Vec::with_capacity(ordered.len());
        let mut first = Vec::with_capacity(ordered.len());
        for &(secret, authentication) in &ordered {
            let (state, contribution) = rkg_round_one(
                profile,
                party_set,
                transcript_digest,
                left,
                right,
                secret,
                authentication,
                random,
            )
            .expect("valid round-one contribution");
            states.push(state);
            first.push(contribution);
        }
        let aggregate =
            aggregate_rkg_round_one(profile, party_set, transcript_digest, left, right, &first)
                .expect("complete round one");
        let second = states
            .into_iter()
            .zip(ordered)
            .map(|(state, (secret, authentication))| {
                rkg_round_two(profile, &aggregate, state, secret, authentication, random)
                    .expect("valid round-two contribution")
            })
            .collect::<Vec<_>>();
        aggregate_rkg_round_two(profile, &aggregate, &second).expect("complete product key")
    }
    #[test]
    fn profile_primality_roots_and_crt_are_exact() {
        let profile = test_profile();
        profile.validate().expect("closed tiny profile");
        assert_eq!(modulus_product_bit_len(profile.moduli).unwrap(), 62);
        let value = 0x0123_4567_89ab_cdef_u64;
        let residues = profile
            .moduli
            .iter()
            .map(|modulus| value % modulus)
            .collect::<Vec<_>>();
        assert_eq!(
            WideUint::crt(&residues, profile.moduli).unwrap().limbs[0],
            value
        );
    }
    #[test]
    fn wide_bit_extraction_accepts_1_through_63_and_rejects_every_boundary_overrun() {
        let mut value = WideUint::zero();
        value.limbs[0] = 0xfedc_ba98_7654_3211;
        value.limbs[1] = 0x0123_4567_89ab_cdef;
        value.limbs[WIDE_LIMBS - 1] = 1_u64 << 63;
        let expected = |offset: usize, width: usize| {
            let limb = offset / 64;
            let shift = offset % 64;
            let mut bits = value.limbs[limb] >> shift;
            if shift + width > 64 {
                bits |= value.limbs[limb + 1] << (64 - shift);
            }
            bits & ((1_u64 << width) - 1)
        };
        for (offset, width) in [(0, 1), (4, 32), (4, 60), (63, 63), (64, 32)] {
            assert_eq!(
                value.bits_at(offset, width).unwrap(),
                expected(offset, width)
            );
        }
        let last_bit = WIDE_LIMBS * 64 - 1;
        assert_eq!(value.bits_at(last_bit, 1).unwrap(), 1);
        assert_eq!(value.bits_at(0, 0), Err(ZkAmsMkheErrorV1::InvalidProfile));
        assert_eq!(value.bits_at(0, 64), Err(ZkAmsMkheErrorV1::InvalidProfile));
        assert_eq!(
            value.bits_at(last_bit, 2),
            Err(ZkAmsMkheErrorV1::InvalidProfile)
        );
        assert_eq!(
            value.bits_at(WIDE_LIMBS * 64, 1),
            Err(ZkAmsMkheErrorV1::InvalidProfile)
        );
    }
    #[test]
    fn centered_t256_lift_boundaries_and_automorphism_are_exact() {
        const HALF: [u8; 32] = T256_CENTERED_MAX_BE_V1;
        const HALF_PLUS_ONE: [u8; 32] = [
            0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        const P_MINUS_ONE: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xfe,
        ];
        let zero = [0_u8; 32];
        let mut one = [0_u8; 32];
        one[31] = 1;
        for &modulus in manifest::RELEASE_MODULI_V1.iter() {
            let p_residue = bytes_mod_u64(&VEGA_T256_SCALAR_MODULUS_BE_V1, modulus);
            assert_eq!(
                t256_centered_residue_with_modulus_residue(&zero, modulus, p_residue),
                0
            );
            assert_eq!(
                t256_centered_residue_with_modulus_residue(&one, modulus, p_residue),
                1
            );
            assert_eq!(
                t256_centered_residue_with_modulus_residue(&HALF, modulus, p_residue),
                bytes_mod_u64(&HALF, modulus)
            );
            assert_eq!(
                t256_centered_residue_with_modulus_residue(&HALF_PLUS_ONE, modulus, p_residue,),
                mod_sub(bytes_mod_u64(&HALF_PLUS_ONE, modulus), p_residue, modulus)
            );
            assert_eq!(
                t256_centered_residue_with_modulus_residue(&P_MINUS_ONE, modulus, p_residue,),
                modulus - 1
            );
            assert_eq!(
                mod_add(
                    t256_centered_residue_with_modulus_residue(&HALF, modulus, p_residue),
                    t256_centered_residue_with_modulus_residue(&HALF_PLUS_ONE, modulus, p_residue,),
                    modulus,
                ),
                0,
                "the two centered boundary representatives must be exact negatives"
            );
        }
        let mut profile = test_profile();
        profile.plaintext_modulus = PlaintextModulus::T256;
        let values = [
            zero,
            one,
            HALF,
            HALF_PLUS_ONE,
            P_MINUS_ONE,
            Scalar::from_u64(2).to_be_bytes(),
            Scalar::from_u64(3).to_be_bytes(),
            Scalar::from_u64(4).to_be_bytes(),
        ];
        let lifted = RnsPolynomial::from_t256_plaintext_bytes(&profile, &values).unwrap();
        for (limb, &modulus) in profile.moduli.iter().enumerate() {
            let p_residue = bytes_mod_u64(&VEGA_T256_SCALAR_MODULUS_BE_V1, modulus);
            for (index, value) in values.iter().enumerate() {
                assert_eq!(
                    lifted.limb(&profile, limb)[index],
                    t256_centered_residue_with_modulus_residue(value, modulus, p_residue)
                );
            }
        }
        let exponent = 5_usize;
        let mut transformed_values = [[0_u8; 32]; 8];
        for (index, value) in values.iter().enumerate() {
            let mapped = index * exponent % 16;
            let scalar = Scalar::from_be_bytes_exact(*value).unwrap();
            if mapped >= 8 {
                transformed_values[mapped - 8] = (-scalar).to_be_bytes();
            } else {
                transformed_values[mapped] = scalar.to_be_bytes();
            }
        }
        assert_eq!(
            lifted.automorphism(exponent, &profile).unwrap(),
            RnsPolynomial::from_t256_plaintext_bytes(&profile, &transformed_values).unwrap()
        );
        let mut noncanonical = [zero; 8];
        noncanonical[0] = VEGA_T256_SCALAR_MODULUS_BE_V1;
        assert_eq!(
            RnsPolynomial::from_t256_plaintext_bytes(&profile, &noncanonical),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        noncanonical[0] = [0xff; 32];
        assert_eq!(
            RnsPolynomial::from_t256_plaintext_bytes(&profile, &noncanonical),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
    }
    #[test]
    fn frozen_release_manifest_validates_with_certified_security_but_open_release_gates() {
        let manifest = zk_ams_mkhe_release_manifest_v1().unwrap();
        assert_eq!(manifest.ring_degree, 131_072);
        assert_eq!(manifest.slot_count, 65_536);
        assert_eq!(manifest.roster_size, 8);
        assert_ne!(manifest.construction_digest, [0; 32]);
        assert_eq!(manifest.rns_limb_count, 38);
        assert_eq!(manifest.ciphertext_modulus_bits, 2_280);
        assert_eq!(manifest.hybrid_digit_bits, 60);
        assert_eq!(manifest.hybrid_digit_count, 38);
        assert_eq!(manifest.final_decryption_bound_bits, 2_115);
        assert_eq!(manifest.correctness_margin_bits, 164);
        assert_eq!(manifest.target_security_bits, 128);
        assert_eq!(manifest.statistical_security_bits, 128);
        assert_eq!(manifest.certified_security_bits, 172);
        assert_eq!(manifest.max_samples_per_secret_epoch, 67_108_864);
        assert_ne!(manifest.security_certificate_digest, [0; 32]);
        assert_ne!(manifest.security_candidate_input_digest, [0; 32]);
        assert_ne!(manifest.resource_certificate_digest, [0; 32]);
        assert_ne!(manifest.phase23_equation_certificate_digest, [0; 32]);
        assert_ne!(manifest.active_exact_binding_audit_digest, [0; 32]);
        assert_ne!(manifest.decryption_resource_evidence_digest, [0; 32]);
        assert_eq!(manifest.release_kat_digest, [0; 32]);
        let noise = zk_ams_mkhe_noise_certificate_v1().unwrap();
        assert_eq!(noise.independent_fresh_residual_bits, 278);
        assert_eq!(noise.collective_ingress_residual_bits, 411);
        assert_eq!(noise.collective_rkg_residual_bits, 285);
        assert_eq!(noise.hybrid_key_switch_residual_bits, 368);
        assert_eq!(noise.max_composed_rotation_key_switch_count, 8);
        assert_eq!(noise.composed_rotation_residual_bits, 412);
        assert_eq!(noise.mapped_fresh_residual_bits, 704);
        assert_eq!(noise.linear_accumulator_residual_bits, 979);
        assert_eq!(noise.cross_product_residual_bits, 1_703);
        assert_eq!(noise.equation_6_cross_term_residual_bits, 1_705);
        assert_eq!(noise.level_one_accumulator_residual_bits, 1_981);
        assert_eq!(noise.encrypted_commitment_residual_bits, 1_272);
        assert_eq!(noise.decryption_smudge_quotient_bits, 1_855);
        assert_eq!(noise.final_decryption_residual_bits, 2_115);
        assert_eq!(noise.correctness_margin_bits, 164);
        let security = zk_ams_mkhe_security_candidate_v1().unwrap();
        assert_eq!(security.ring_degree, 131_072);
        assert_eq!(security.ciphertext_modulus_bits, 2_280);
        assert_eq!(security.max_samples_per_secret_epoch, 67_108_864);
        assert_eq!(security.secret_variance_numerator, 2);
        assert_eq!(security.secret_variance_denominator, 3);
        assert_eq!(security.error_centered_binomial_eta, 2);
        assert_eq!(security.target_security_bits, 128);
        assert_ne!(security.lattice_estimator_commit, [0; 20]);
        assert_ne!(security.sage_environment_commit, [0; 20]);
        assert_eq!(
            manifest.security_candidate_input_digest,
            zk_ams_mkhe_security_candidate_input_digest_v1().unwrap()
        );
        let resource = zk_ams_mkhe_resource_certificate_v1().unwrap();
        assert_eq!(resource.governed_roster_wire_bytes, 302);
        assert_eq!(resource.rns_polynomial_wire_bytes, 39_845_892);
        assert_eq!(
            resource.compact_collective_ciphertext_wire_bytes,
            79_691_906
        );
        assert_eq!(
            resource.seeded_collective_relinearization_key_wire_bytes,
            1_514_144_113
        );
        assert_eq!(resource.collective_evaluated_key_count, 32);
        assert_eq!(
            resource.total_collective_evaluated_key_artifact_bytes,
            48_452_611_616
        );
        assert_eq!(resource.proof_envelope_header_wire_bytes, 151);
        assert_eq!(resource.streamed_hybrid_workspace_bytes, 87_042_112);
        assert_eq!(resource.max_composed_rotation_work_units, 83_915_440_128);
        assert!(resource.composed_rotation_work_ceiling_met);
        assert!(!resource.evaluated_key_artifact_transport_certified);
        assert!(!resource.is_release_ready());
        assert_eq!(
            manifest.resource_certificate_digest,
            zk_ams_mkhe_resource_certificate_digest_v1().unwrap()
        );
        let phase23 = zk_ams_phase23_equation_certificate_v1();
        assert!(phase23.encrypted_sparse_maps_complete);
        assert!(phase23.encrypted_cross_term_complete);
        assert!(phase23.encrypted_commitment_complete);
        assert!(phase23.accumulator_materialization_complete);
        assert!(phase23.padding_and_final_proof_complete);
        assert!(!phase23.hidden_mask_proof_complete);
        assert_eq!(phase23.hidden_mask_proof_blocker_mask, 0b1111);
        assert_ne!(phase23.hidden_mask_proof_audit_digest, [0; 32]);
        assert!(!phase23.is_complete());
        assert_ne!(zk_ams_mkhe_manifest_digest_v1().unwrap(), [0; 32]);
        assert_ne!(zk_ams_mkhe_readiness_digest_v1().unwrap(), [0; 32]);
        let readiness = zk_ams_mkhe_readiness_v1().unwrap();
        assert!(readiness.parameter_gate);
        assert!(readiness.noise_gate);
        assert!(readiness.security_gate);
        assert!(!readiness.resource_gate);
        assert!(!readiness.wire_gate);
        assert!(!readiness.malicious_party_gate);
        assert!(!readiness.decryption_share_gate);
        assert!(readiness.packing_gate);
        assert!(!readiness.phase23_gate);
        assert!(!readiness.receipt_capability_gate);
        assert_eq!(readiness.receipt_capability_blocker_mask, 0xf0);
        assert!(!readiness.release_kat_gate);
        assert!(!readiness.is_ready());
        assert_eq!(
            manifest::require_release_ready_v1(),
            Err(ZkAmsMkheErrorV1::ReleaseUnavailable)
        );
    }
    #[test]
    fn ntt_matches_independent_schoolbook_negacyclic_kat() {
        let profile = test_profile();
        let left = [1, 2, 3, 4, 5, 6, 7, 8];
        let right = [8, 7, 6, 5, 4, 3, 2, 1];
        for ((&modulus, &root), limb) in
            profile.moduli.iter().zip(profile.negacyclic_roots).zip(0..)
        {
            assert_eq!(
                negacyclic_multiply(&left, &right, modulus, root).unwrap(),
                schoolbook_negacyclic(&left, &right, modulus),
                "limb {limb}"
            );
        }
    }
    #[test]
    fn centered_balanced_gadget_decomposition_reconstructs_every_digit() {
        let profile = test_profile();
        let signed = [
            -0x0101_0101_0101_0101_i64,
            -1,
            -127,
            -128,
            -129,
            127,
            128,
            129,
        ];
        let polynomial = RnsPolynomial::from_signed(&profile, &signed).unwrap();
        let ciphertext_modulus = modulus_product(profile.moduli).unwrap();
        let first_canonical = WideUint::crt(
            &(0..profile.moduli.len())
                .map(|limb| polynomial.limb(&profile, limb)[0])
                .collect::<Vec<_>>(),
            profile.moduli,
        )
        .unwrap();
        assert!(
            first_canonical > ciphertext_modulus.shr_one(),
            "negative centered coefficients must exercise the canonical interval above Q/2"
        );
        let decomposition = gadget_decompose(&profile, &polynomial).unwrap();
        assert_eq!(decomposition.len(), profile.gadget_digits);
        for (digit, polynomial_digit) in decomposition.iter().enumerate() {
            polynomial_digit.validate(&profile).unwrap();
            for (limb, &modulus) in profile.moduli.iter().enumerate() {
                assert_eq!(
                    polynomial_digit.limb(&profile, limb)[0],
                    modulus - 1,
                    "coefficient zero must exercise balanced digit {digit}"
                );
            }
        }
        let base = 1_u64 << profile.gadget_base_log;
        for (limb, &modulus) in profile.moduli.iter().enumerate() {
            let mut power = 1_u64;
            let mut reconstructed = vec![0_u64; profile.ring_degree];
            for polynomial_digit in &decomposition {
                for (coefficient, output) in reconstructed.iter_mut().enumerate() {
                    *output = mod_add(
                        *output,
                        mod_mul(
                            polynomial_digit.limb(&profile, limb)[coefficient],
                            power,
                            modulus,
                        ),
                        modulus,
                    );
                }
                power = mod_mul(power, base % modulus, modulus);
            }
            assert_eq!(
                reconstructed,
                polynomial.limb(&profile, limb),
                "independent base-power reconstruction must match RNS limb {limb}"
            );
        }
    }
    #[test]
    fn artifact_authentication_binds_party_domain_and_transcript() {
        let mut random = KatRandom::new(b"zk-ams-mkhe-authentication-kat");
        let secret = AuthenticationSecret::generate(&mut random).unwrap();
        let digest = keccak256(b"canonical artifact");
        let authentication = ArtifactAuthentication::sign(
            b"zk-ams-mkhe-test-artifact",
            digest,
            &secret,
            &mut random,
        )
        .unwrap();
        authentication
            .verify(b"zk-ams-mkhe-test-artifact", digest)
            .unwrap();
        let mut altered_signature = authentication.clone();
        altered_signature.signature[64] ^= 1;
        assert_eq!(
            altered_signature.verify(b"zk-ams-mkhe-test-artifact", digest),
            Err(ZkAmsMkheErrorV1::InvalidAuthentication)
        );
        assert_eq!(
            authentication.verify(b"zk-ams-mkhe-other-artifact", digest),
            Err(ZkAmsMkheErrorV1::InvalidAuthentication)
        );
        assert_eq!(
            authentication.verify(b"zk-ams-mkhe-test-artifact", keccak256(b"spliced artifact")),
            Err(ZkAmsMkheErrorV1::InvalidAuthentication)
        );
        let mut altered_party = authentication.clone();
        altered_party.party = ZkAmsMkhePartyIdV1::new([0x7f; 32]).unwrap();
        assert_eq!(
            altered_party.verify(b"zk-ams-mkhe-test-artifact", digest),
            Err(ZkAmsMkheErrorV1::InvalidAuthentication)
        );
    }
    #[test]
    fn bilinear_rkg_rejects_incomplete_reordered_spliced_and_rogue_rounds() {
        let profile = test_profile();
        let mut random = KatRandom::new(b"zk-ams-mkhe-bilinear-rkg-negative-kat");
        let authentication_a = AuthenticationSecret::generate(&mut random).unwrap();
        let authentication_b = AuthenticationSecret::generate(&mut random).unwrap();
        let party_a = authentication_a.party_id().unwrap();
        let party_b = authentication_b.party_id().unwrap();
        let (secret_a, _) = independent_keygen(&profile, party_a, &mut random).unwrap();
        let (secret_b, _) = independent_keygen(&profile, party_b, &mut random).unwrap();
        let target_set = PartySet::singleton(party_a)
            .union(&PartySet::singleton(party_b))
            .unwrap();
        let (left, right) = if party_a < party_b {
            (party_a, party_b)
        } else {
            (party_b, party_a)
        };
        let transcript_digest = keccak256(b"bilinear-rkg-negative-transcript");
        let mut participants = vec![
            (&secret_a, &authentication_a),
            (&secret_b, &authentication_b),
        ];
        participants.sort_by_key(|(secret, _)| secret.party);
        let mut states = Vec::new();
        let mut first = Vec::new();
        for &(secret, authentication) in &participants {
            let (state, contribution) = rkg_round_one(
                &profile,
                &target_set,
                transcript_digest,
                left,
                right,
                secret,
                authentication,
                &mut random,
            )
            .unwrap();
            states.push(state);
            first.push(contribution);
        }
        assert!(
            aggregate_rkg_round_one(
                &profile,
                &target_set,
                transcript_digest,
                left,
                right,
                &first[..1],
            )
            .is_err(),
            "missing round-one party must fail"
        );
        assert!(
            aggregate_rkg_round_one(
                &profile,
                &target_set,
                transcript_digest,
                left,
                right,
                &[first[0].clone(), first[0].clone()],
            )
            .is_err(),
            "duplicate round-one party must fail"
        );
        let mut reordered = first.clone();
        reordered.reverse();
        assert!(
            aggregate_rkg_round_one(
                &profile,
                &target_set,
                transcript_digest,
                left,
                right,
                &reordered,
            )
            .is_err(),
            "noncanonical round-one order must fail"
        );
        let mut cross_transcript = first.clone();
        cross_transcript[0].transcript_digest = keccak256(b"spliced transcript");
        assert!(
            aggregate_rkg_round_one(
                &profile,
                &target_set,
                transcript_digest,
                left,
                right,
                &cross_transcript,
            )
            .is_err(),
            "cross-transcript contribution must fail"
        );
        let mut cross_set = first.clone();
        cross_set[0].party_set = PartySet::singleton(left);
        assert!(
            aggregate_rkg_round_one(
                &profile,
                &target_set,
                transcript_digest,
                left,
                right,
                &cross_set,
            )
            .is_err(),
            "cross-set contribution must fail"
        );
        let mut cross_digit = first.clone();
        cross_digit[0].entries.swap(0, 1);
        assert!(
            aggregate_rkg_round_one(
                &profile,
                &target_set,
                transcript_digest,
                left,
                right,
                &cross_digit,
            )
            .is_err(),
            "cross-digit contribution must fail"
        );
        let mut malformed_h = first.clone();
        malformed_h[0].entries[0].h0.coefficients[0] = profile.moduli[0];
        assert!(
            aggregate_rkg_round_one(
                &profile,
                &target_set,
                transcript_digest,
                left,
                right,
                &malformed_h,
            )
            .is_err(),
            "noncanonical H residue must fail"
        );
        let aggregate = aggregate_rkg_round_one(
            &profile,
            &target_set,
            transcript_digest,
            left,
            right,
            &first,
        )
        .unwrap();
        states[0].ephemeral[0].coefficients[0] += 1;
        let rogue_state = states.remove(0);
        let (rogue_secret, rogue_authentication) = participants[0];
        assert_eq!(
            rkg_round_two(
                &profile,
                &aggregate,
                rogue_state,
                rogue_secret,
                rogue_authentication,
                &mut random,
            ),
            Err(ZkAmsMkheErrorV1::InvalidKeyMaterial),
            "round-two must reject an ephemeral U state altered after its authenticated round one"
        );
    }
    #[test]
    fn independent_keys_encrypt_add_multiply_and_enforce_canonical_key_union() {
        let profile = test_profile();
        let party_a = ZkAmsMkhePartyIdV1::new([0x11; 32]).unwrap();
        let party_b = ZkAmsMkhePartyIdV1::new([0x22; 32]).unwrap();
        let mut random = KatRandom::new(b"zk-ams-mkhe-independent-key-kat");
        let (secret_a, public_a) = independent_keygen(&profile, party_a, &mut random).unwrap();
        let (secret_b, public_b) = independent_keygen(&profile, party_b, &mut random).unwrap();
        let message_a =
            RnsPolynomial::from_test_plaintext(&profile, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let message_b =
            RnsPolynomial::from_test_plaintext(&profile, &[8, 7, 6, 5, 4, 3, 2, 1]).unwrap();
        let ciphertext_a = encrypt(&profile, &public_a, &message_a, &mut random).unwrap();
        let ciphertext_b = encrypt(&profile, &public_b, &message_b, &mut random).unwrap();
        assert_eq!(
            decrypt_test_plaintext(&profile, &ciphertext_a, &[&secret_a]).unwrap(),
            vec![1, 2, 3, 4, 5, 6, 7, 8]
        );
        let sum = ciphertext_b.add(&ciphertext_a, &profile).unwrap();
        assert_eq!(sum.party_set.parties, vec![party_a, party_b]);
        assert_eq!(
            decrypt_test_plaintext(&profile, &sum, &[&secret_a, &secret_b]).unwrap(),
            vec![9; 8]
        );
        let product = ciphertext_a.mul(&ciphertext_b, &profile).unwrap();
        assert_eq!(product.party_set.parties, vec![party_a, party_b]);
        assert_eq!(product.quadratic.len(), 3);
        assert_eq!(product.quadratic[0].left, party_a);
        assert_eq!(product.quadratic[0].right, party_a);
        assert_eq!(product.quadratic[1].left, party_a);
        assert_eq!(product.quadratic[1].right, party_b);
        assert_eq!(product.quadratic[2].left, party_b);
        assert_eq!(product.quadratic[2].right, party_b);
    }
    #[test]
    fn authenticated_bilinear_rkg_relinearizes_self_and_pair_products_exactly() {
        let profile = test_profile();
        let mut random = KatRandom::new(b"zk-ams-mkhe-pair-rkg-kat");
        let authentication_a = AuthenticationSecret::generate(&mut random).unwrap();
        let authentication_b = AuthenticationSecret::generate(&mut random).unwrap();
        let party_a = authentication_a.party_id().unwrap();
        let party_b = authentication_b.party_id().unwrap();
        let (secret_a, public_a) = independent_keygen(&profile, party_a, &mut random).unwrap();
        let (secret_b, public_b) = independent_keygen(&profile, party_b, &mut random).unwrap();
        let set_a = PartySet::singleton(party_a);
        let set_b = PartySet::singleton(party_b);
        let set_ab = set_a.union(&set_b).unwrap();
        let key_aa = generate_product_key(
            &profile,
            &set_a,
            keccak256(b"product-aa"),
            party_a,
            party_a,
            &[(&secret_a, &authentication_a)],
            &mut random,
        );
        let key_bb = generate_product_key(
            &profile,
            &set_b,
            keccak256(b"product-bb"),
            party_b,
            party_b,
            &[(&secret_b, &authentication_b)],
            &mut random,
        );
        let (left_party, right_party) = if party_a < party_b {
            (party_a, party_b)
        } else {
            (party_b, party_a)
        };
        let key_ab = generate_product_key(
            &profile,
            &set_ab,
            keccak256(b"product-ab"),
            left_party,
            right_party,
            &[
                (&secret_a, &authentication_a),
                (&secret_b, &authentication_b),
            ],
            &mut random,
        );
        let ordered_secrets = if party_a < party_b {
            vec![&secret_a, &secret_b]
        } else {
            vec![&secret_b, &secret_a]
        };
        let expected_aa = secret_a
            .secret
            .as_rns(&profile)
            .unwrap()
            .mul(&secret_a.secret.as_rns(&profile).unwrap(), &profile)
            .unwrap();
        let expected_ab = secret_a
            .secret
            .as_rns(&profile)
            .unwrap()
            .mul(&secret_b.secret.as_rns(&profile).unwrap(), &profile)
            .unwrap();
        let expected_bb = secret_b
            .secret
            .as_rns(&profile)
            .unwrap()
            .mul(&secret_b.secret.as_rns(&profile).unwrap(), &profile)
            .unwrap();
        let singleton_noise = test_bilinear_key_noise_bound(&profile, 1);
        let pair_noise = test_bilinear_key_noise_bound(&profile, 2);
        for digit in 0..profile.gadget_digits {
            let expected_raw_aa = expected_aa.scale_gadget(digit, &profile).unwrap();
            assert_test_evaluation_key_equation(
                &profile,
                &key_aa.digits[digit],
                &[&secret_a],
                &expected_raw_aa,
                singleton_noise,
            );
            let expected_raw_ab = expected_ab.scale_gadget(digit, &profile).unwrap();
            assert_test_evaluation_key_equation(
                &profile,
                &key_ab.digits[digit],
                &ordered_secrets,
                &expected_raw_ab,
                pair_noise,
            );
            let expected_raw_bb = expected_bb.scale_gadget(digit, &profile).unwrap();
            assert_test_evaluation_key_equation(
                &profile,
                &key_bb.digits[digit],
                &[&secret_b],
                &expected_raw_bb,
                singleton_noise,
            );
        }
        assert_eq!(
            decrypt_test_plaintext(&profile, &key_aa.digits[0], &[&secret_a]).unwrap(),
            reduce_test_polynomial(&profile, &expected_aa).unwrap(),
            "self-square RKG digit zero is within the proven no-wrap bound"
        );
        assert_eq!(
            decrypt_test_plaintext(&profile, &key_ab.digits[0], &ordered_secrets).unwrap(),
            reduce_test_polynomial(&profile, &expected_ab).unwrap(),
            "pair-product RKG digit zero is within the proven no-wrap bound"
        );
        assert_eq!(
            decrypt_test_plaintext(&profile, &key_bb.digits[0], &[&secret_b]).unwrap(),
            reduce_test_polynomial(&profile, &expected_bb).unwrap(),
            "right self-square RKG digit zero is within the proven no-wrap bound"
        );
        let left_values = [1, 2, 3, 4, 5, 6, 7, 8];
        let right_values = [8, 7, 6, 5, 4, 3, 2, 1];
        let left = encrypt(
            &profile,
            &public_a,
            &RnsPolynomial::from_test_plaintext(&profile, &left_values).unwrap(),
            &mut random,
        )
        .unwrap();
        let right = encrypt(
            &profile,
            &public_b,
            &RnsPolynomial::from_test_plaintext(&profile, &right_values).unwrap(),
            &mut random,
        )
        .unwrap();
        let raw_product = left.mul(&right, &profile).unwrap();
        let expected_product = schoolbook_negacyclic(&left_values, &right_values, 17);
        assert_eq!(
            decrypt_quadratic_test_plaintext(&profile, &raw_product, &ordered_secrets).unwrap(),
            expected_product,
            "raw quadratic multiplication must be correct before relinearization"
        );
        let relinearized = relinearize(&profile, &raw_product, &[key_aa, key_ab, key_bb]).unwrap();
        assert_eq!(relinearized.level, 1);
        assert_eq!(
            decrypt_test_plaintext(&profile, &relinearized, &ordered_secrets).unwrap(),
            expected_product,
            "direct bilinear RKG must relinearize without any division in R_Q"
        );
    }
    #[test]
    fn authenticated_galois_key_rotates_and_rejects_missing_duplicate_or_spliced_keys() {
        let profile = test_profile();
        let mut random = KatRandom::new(b"zk-ams-mkhe-galois-kat");
        let authentication = AuthenticationSecret::generate(&mut random).unwrap();
        let party = authentication.party_id().unwrap();
        let (secret, public) = independent_keygen(&profile, party, &mut random).unwrap();
        let transcript_digest = keccak256(b"galois transcript");
        let key = generate_galois_key(
            &profile,
            transcript_digest,
            3,
            &secret,
            &public,
            &authentication,
            &mut random,
        )
        .unwrap();
        let values = [1, 2, 3, 4, 5, 6, 7, 8];
        let message = RnsPolynomial::from_test_plaintext(&profile, &values).unwrap();
        let ciphertext = encrypt(&profile, &public, &message, &mut random).unwrap();
        let rotated =
            rotate_ciphertext(&profile, &ciphertext, 3, std::slice::from_ref(&key)).unwrap();
        let expected_rns = message.automorphism(3, &profile).unwrap();
        let expected_ciphertext = LinearCiphertext {
            version: MKHE_VERSION_V1,
            profile_digest: profile.digest().unwrap(),
            party_set: PartySet::singleton(party),
            level: 0,
            constant: expected_rns,
            linear: vec![RnsPolynomial::zero(&profile)],
        };
        assert_eq!(
            decrypt_test_plaintext(&profile, &rotated, &[&secret]).unwrap(),
            decrypt_test_plaintext(&profile, &expected_ciphertext, &[&secret]).unwrap()
        );
        assert_eq!(
            rotate_ciphertext(&profile, &ciphertext, 3, &[]),
            Err(ZkAmsMkheErrorV1::MissingEvaluatedKey)
        );
        assert_eq!(
            rotate_ciphertext(&profile, &ciphertext, 3, &[key.clone(), key.clone()]),
            Err(ZkAmsMkheErrorV1::MissingEvaluatedKey)
        );
        let mut spliced = key;
        spliced.transcript_digest = keccak256(b"other transcript");
        assert_eq!(
            rotate_ciphertext(&profile, &ciphertext, 3, &[spliced]),
            Err(ZkAmsMkheErrorV1::InvalidAuthentication)
        );
    }
    struct ConstantRandom(u8);
    impl MaskedRelaxedRandomSourceV1 for ConstantRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), MaskedRelaxedRandomErrorV1> {
            destination.fill(self.0);
            Ok(())
        }
    }
    #[test]
    fn hostile_constant_entropy_hits_hard_retry_ceilings() {
        let profile = test_profile();
        assert!(matches!(
            AuthenticationSecret::generate(&mut ConstantRandom(0)),
            Err(ZkAmsMkheErrorV1::RandomUnavailable)
        ));
        assert!(matches!(
            SecretPolynomial::sample_ternary(&profile, &mut ConstantRandom(0xff)),
            Err(ZkAmsMkheErrorV1::RandomUnavailable)
        ));
        assert_eq!(
            sample_below(TEST_MODULI[0], &mut ConstantRandom(0xff)),
            Err(ZkAmsMkheErrorV1::RandomUnavailable)
        );
    }
    #[test]
    fn malformed_profiles_polynomials_and_party_sets_fail_closed() {
        let profile = test_profile();
        assert_eq!(
            PartySet::new(vec![
                ZkAmsMkhePartyIdV1::new([2; 32]).unwrap(),
                ZkAmsMkhePartyIdV1::new([1; 32]).unwrap(),
            ]),
            Err(ZkAmsMkheErrorV1::InvalidPartySet)
        );
        assert_eq!(
            PartySet::new(vec![
                ZkAmsMkhePartyIdV1::new([1; 32]).unwrap(),
                ZkAmsMkhePartyIdV1::new([1; 32]).unwrap(),
            ]),
            Err(ZkAmsMkheErrorV1::InvalidPartySet)
        );
        assert_eq!(
            RnsPolynomial::from_flat(&profile, vec![0; 1]),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        let mut residues = vec![0; profile.ring_degree * profile.moduli.len()];
        residues[0] = profile.moduli[0];
        assert_eq!(
            RnsPolynomial::from_flat(&profile, residues),
            Err(ZkAmsMkheErrorV1::InvalidPolynomial)
        );
        let mut invalid_root = profile.clone();
        invalid_root.negacyclic_roots = &[2, 3];
        assert_eq!(
            invalid_root.validate(),
            Err(ZkAmsMkheErrorV1::InvalidProfile)
        );
        let mut insufficient_gadget = profile.clone();
        insufficient_gadget.gadget_digits = 7;
        assert_eq!(
            insufficient_gadget.validate(),
            Err(ZkAmsMkheErrorV1::InvalidProfile),
            "a profile unable to represent every centered coefficient in exactly its declared digits must be rejected"
        );
        let mut insufficient_workspace = profile.clone();
        insufficient_workspace.max_workspace_bytes =
            checked_gadget_decomposition_workspace_bytes(&profile).unwrap() - 1;
        assert_eq!(
            insufficient_workspace.validate(),
            Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
        );
    }
    /// The test-only scalar and wide-integer references share no code with `iroha_fhe`, which
    /// production profile validation uses; they must agree on every profile modulus.
    #[test]
    fn test_only_scalar_references_agree_with_the_shared_owner() {
        let profile = test_profile();
        for &modulus in profile.moduli.iter().chain(&[3_u64, (1 << 62) - 57]) {
            for (left, right) in [
                (0, 0),
                (1, modulus - 1),
                (modulus - 1, modulus - 1),
                (modulus / 2, modulus / 2 + 1),
            ] {
                assert_eq!(
                    mod_add(left, right, modulus),
                    iroha_fhe::modular::add_mod_u64(left, right, modulus)
                );
                assert_eq!(
                    mod_sub(left, right, modulus),
                    iroha_fhe::modular::sub_mod_u64(left, right, modulus)
                );
                assert_eq!(
                    mod_mul(left, right, modulus),
                    iroha_fhe::modular::mul_mod_u64(left, right, modulus)
                );
            }
            assert_eq!(
                mod_pow(3, modulus - 1, modulus),
                iroha_fhe::modular::mod_pow_u64(3, modulus - 1, modulus)
            );
            assert_eq!(
                bytes_mod_u64(&VEGA_T256_SCALAR_MODULUS_BE_V1, modulus),
                iroha_fhe::modular::reduce_be_bytes_mod_u64(
                    &VEGA_T256_SCALAR_MODULUS_BE_V1,
                    modulus
                )
            );
        }
        for candidate in (0..2_048_u64).chain([3_215_031_751, 2_013_265_921, u64::MAX - 58]) {
            assert_eq!(
                is_prime_u64(candidate),
                iroha_fhe::modular::is_prime_u64(candidate),
                "candidate {candidate}"
            );
        }
        assert_eq!(
            modulus_product(profile.moduli).unwrap().bit_len(),
            modulus_product_bit_len(profile.moduli).unwrap()
        );
        let too_wide = [u64::MAX; MAX_RNS_LIMBS_V1 + 1];
        assert_eq!(
            modulus_product_bit_len(&too_wide),
            Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
        );
        assert_eq!(
            modulus_product(&too_wide),
            Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
        );
        let widest = [u64::MAX; MAX_RNS_LIMBS_V1];
        assert_eq!(
            modulus_product(&widest).unwrap().bit_len(),
            modulus_product_bit_len(&widest).unwrap()
        );
    }
    /// The test-only ring oracle and the shared negacyclic kernel are independent
    /// implementations of the same product.
    #[test]
    fn test_only_ring_oracle_agrees_with_the_shared_negacyclic_kernel() {
        let profile = test_profile();
        for (&modulus, &psi) in profile.moduli.iter().zip(profile.negacyclic_roots) {
            let left: Vec<u64> = (0..profile.ring_degree as u64)
                .map(|index| (index * 0x9E37_79B9 + 17) % modulus)
                .collect();
            let right: Vec<u64> = (0..profile.ring_degree as u64)
                .map(|index| (index * 0x0100_01B3 + 29) % modulus)
                .collect();
            assert_eq!(
                negacyclic_multiply(&left, &right, modulus, psi).unwrap(),
                iroha_fhe::ntt::negacyclic_multiply_ntt(&left, &right, psi, modulus).unwrap()
            );
        }
    }
}
