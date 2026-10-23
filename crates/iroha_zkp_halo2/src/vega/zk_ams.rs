//! Exact setup-free masked R1CS relation for Iroha ZK-AMS admission.
//!
//! Each strict instance proves one canonical fixed PHC preimage, its SHA-256 digest, one canonical
//! low-s ES256 issuer signature, and one deterministic registry-root transition. A full random
//! relaxed assignment masks the sequential Nova fold before the terminal Spartan proof.
#![allow(unexpected_cfgs)]
use super::{
    VEGA_T256_BASE_MODULUS_BE_V1, VegaT256ScalarV1 as Scalar,
    circuit::{
        CircuitAssignment, CircuitBuilder, CircuitDimensions, CircuitError, CircuitProfile,
        LinearCombination,
    },
    derive_t256_generators_v1,
    masked_relaxed::{
        MAX_MASKED_RELAXED_STRICT_INSTANCES_V1, MaskedRelaxedDimensionsV1, MaskedRelaxedErrorV1,
        MaskedRelaxedProofWireV1, MaskedRelaxedRandomErrorV1, MaskedRelaxedRandomSourceV1,
        MaskedRelaxedStreamConfigV1, precompute_masked_relaxed_stream_v1,
        prove_masked_relaxed_precomputation_v1, verify_masked_relaxed_v1,
    },
    p256::{public_compressed_point, verify_es256_low_s},
    r1cs::{R1csError, Shape},
    sha256::{
        ByteVar, WordVar, allocate_byte, allocate_bytes, enforce_byte_constant, public_word, sha256,
    },
    sponge::keccak256,
};
use core::fmt;
use once_cell::sync::Lazy;
use std::sync::Arc;
use thiserror::Error;
#[path = "zk_ams/mkhe.rs"]
mod mkhe;
pub use mkhe::RnsNativeProofDigestV1;
#[cfg(test)]
pub use mkhe::ZK_AMS_MKHE_CPK_ERROR_MEMBERSHIP_WIRE_BYTES_V1;
#[cfg(test)]
pub use mkhe::ZkAmsMkheDirectObjectKindV1;
pub use mkhe::ZkAmsMkheRnsNativeTerminalRootsV1;
#[cfg(test)]
pub use mkhe::{
    ZK_AMS_MKHE_CPK_SECRET_MEMBERSHIP_WIRE_BYTES_V1, ZK_AMS_MKHE_EVIDENCE_CHUNK_BYTES_V1,
    ZK_AMS_MKHE_RELEASE_KAT_EVIDENCE_BYTES_V1, ZK_AMS_MKHE_RESOURCE_EVIDENCE_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_PROFILE_MANIFEST_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_WIDE_RESPONSE_BYTES_V1, ZK_AMS_MKHE_WIRE_EVIDENCE_BYTES_V1,
    ZK_AMS_PHASE23_FRESHNESS_CERTIFIES_HIDDEN_MASK_SHARES_V1,
    ZK_AMS_PHASE23_FRESHNESS_COMMIT_WIRE_BYTES_V1, ZK_AMS_PHASE23_FRESHNESS_RECEIPT_WIRE_BYTES_V1,
    ZK_AMS_PHASE23_FRESHNESS_REVEAL_WIRE_BYTES_V1, ZK_AMS_PHASE23_RELEASE_MAP_SET_KAT_DIGEST_V1,
    ZkAmsMkheAbortReasonV1, ZkAmsMkheActiveCollectivePublicKeyStatementV1,
    ZkAmsMkheActiveCollectivePublicKeyWitnessV1, ZkAmsMkheActiveContributionV1,
    ZkAmsMkheActivePartySecretV1, ZkAmsMkheActiveRkgLinearProofSecurityV1,
    ZkAmsMkheActiveRkgProofV1, ZkAmsMkheActiveRoundReceiptV1, ZkAmsMkheActiveRoundV1,
    ZkAmsMkheAdmittedCpkPartyV1, ZkAmsMkheAuthenticationWireV1, ZkAmsMkheCksContributionWireV1,
    ZkAmsMkheCksProofV1, ZkAmsMkheCksResourceEvidenceV1, ZkAmsMkheCollectiveCiphertextWireV1,
    ZkAmsMkheCollectiveEvaluatedKeyEntryV1, ZkAmsMkheCollectiveEvaluatedKeyEvidenceSinkV1,
    ZkAmsMkheCollectiveEvaluatedKeyManifestV1, ZkAmsMkheCollectiveEvaluatedKeyProviderV1,
    ZkAmsMkheCollectiveEvaluatedKeyPublicationFooterV1,
    ZkAmsMkheCollectiveEvaluatedKeyPublicationHeaderV1,
    ZkAmsMkheCollectiveEvaluatedKeyPublicationSinkV1, ZkAmsMkheCollectiveEvaluatedKeyPurposeV1,
    ZkAmsMkheCollectiveEvaluatedKeyRuntimeV1, ZkAmsMkheCollectiveEvidenceRecordFooterV1,
    ZkAmsMkheCollectiveEvidenceRecordHeaderV1, ZkAmsMkheCollectiveEvidenceRecordKindV1,
    ZkAmsMkheCollectiveEvidenceSetFooterV1, ZkAmsMkheCollectiveEvidenceSetHeaderV1,
    ZkAmsMkheCollectiveEvidenceSetKindV1, ZkAmsMkheCollectivePartyStateV1,
    ZkAmsMkheCollectivePublicKeyShareV1, ZkAmsMkheCpkCeremonyResidencyEvidenceV1,
    ZkAmsMkheCpkCeremonyV1, ZkAmsMkheCpkPartyInputV1, ZkAmsMkheCpkRuntimeV1,
    ZkAmsMkheDecryptedPlaintextV1, ZkAmsMkheDecryptionAbortReasonV1,
    ZkAmsMkheDecryptionTransportComponentKindV1, ZkAmsMkheDecryptionTransportManifestV1,
    ZkAmsMkheDecryptionTransportPointerV1, ZkAmsMkheDirectAdmittedContributionSetV1,
    ZkAmsMkheDirectCeremonyContextV1, ZkAmsMkheDirectCoordinatorV1,
    ZkAmsMkheDirectEvaluatedKeySetAdmissionV1, ZkAmsMkheDirectEvaluatedKeyTargetV1,
    ZkAmsMkheDirectNoiseCertificateV1, ZkAmsMkheDirectNoiseIntegrationCertificateV1,
    ZkAmsMkheDirectPolynomialStreamReceiptV1, ZkAmsMkheDirectPolynomialStreamV1,
    ZkAmsMkheDirectProofAuditV1, ZkAmsMkheDirectResourceCertificateV1,
    ZkAmsMkheDirectVerifiedContributionProviderV1, ZkAmsMkheDirectVerifiedContributionV1,
    ZkAmsMkheEvaluatedKeySorafsPointerV1, ZkAmsMkheFinalizedCpkCeremonyV1,
    ZkAmsMkheFullRosterDecryptionResultV1, ZkAmsMkheGovernedActiveRosterV1,
    ZkAmsMkheGovernedCollectiveKeyMaterialIdentityV1, ZkAmsMkheGovernedParticipantV1,
    ZkAmsMkheGovernedRosterWireV1, ZkAmsMkheIdentifiableAbortV1,
    ZkAmsMkheIdentifiableDecryptionAbortV1, ZkAmsMkheOwnedCollectiveCksDigitEvidenceV1,
    ZkAmsMkhePersistentDecryptionPartyUseV1, ZkAmsMkhePersistentDecryptionVerificationContextV1,
    ZkAmsMkheProofEnvelopeWireV1, ZkAmsMkheProofKindV1, ZkAmsMkheRnsNativeProfileManifestV1,
    ZkAmsMkheRnsPolynomialWireV1, ZkAmsMkheRosterKeyProofV1,
    ZkAmsMkheStreamingDecryptionAuthorityV1, ZkAmsMkheTrustedCksContextV1,
    ZkAmsMkheValidatedCollectiveEvaluatedKeyV1, ZkAmsMkheWireBindingV1, ZkAmsPhase3BatchAnchorV1,
    ZkAmsPhase3FoldHistoryV1, ZkAmsPhase3GovernedBatchV1, ZkAmsPhase3TerminalContextV1,
    ZkAmsPhase3TerminalProverOutputV1, ZkAmsPhase3TerminalReceiptV1,
    ZkAmsPhase23AccumulatorShapeV1, ZkAmsPhase23CommitmentPreimageLayoutV1,
    ZkAmsPhase23CrossTermCommitmentV1, ZkAmsPhase23EncryptedBindingV1,
    ZkAmsPhase23FreshnessCommitV1, ZkAmsPhase23FreshnessContextV1, ZkAmsPhase23FreshnessPhaseV1,
    ZkAmsPhase23FreshnessReceiptV1, ZkAmsPhase23FreshnessRevealV1, ZkAmsPhase23MapKindV1,
    ZkAmsPhase23MaterializedAccumulatorsV1, ZkAmsPhase23PendingRevealV1,
    ZkAmsPhase23PublicAccumulatorV1, ZkAmsPhase23PublicChallengeFamilyV1,
    ZkAmsPhase23PublicChallengeRoleV1, ZkAmsPhase23PublicChallengeV1,
    ZkAmsPhase23PublicFoldHistoryV1, ZkAmsPhase23PublicFoldRecordV1,
    ZkAmsPhase23ReleaseMapManifestV1, ZkAmsPhase23SparseMapManifestV1, ZkAmsPhase23SparseMapV1,
    ZkAmsPhase23StrictPublicInstanceV1, ZkAmsPhase23VerifiedCommitSetV1,
    ZkAmsT256PackedPlaintextV1, ZkAmsT256RotationCertificateV1,
    admit_zk_ams_mkhe_direct_contribution_set_v1, commit_zk_ams_phase23_freshness_v1,
    decode_zk_ams_t256_packed_plaintext_v1, encode_zk_ams_t256_packed_plaintext_v1,
    finalize_zk_ams_phase23_freshness_v1,
    generate_zk_ams_mkhe_collective_party_state_with_prepared_public_a_v1,
    open_zk_ams_phase23_freshness_reveal_v1, permute_zk_ams_t256_slots_v1,
    prove_zk_ams_mkhe_active_collective_public_key_v1, prove_zk_ams_phase3_terminal_v1,
    read_zk_ams_phase23_materialized_accumulators_canonical_exact_v1,
    rotate_zk_ams_t256_packed_plaintext_v1, validate_zk_ams_t256_galois_key_exponents_v1,
    validate_zk_ams_t256_galois_key_schedule_v1,
    verify_zk_ams_mkhe_active_collective_public_key_v1, verify_zk_ams_phase3_terminal_v1,
    write_zk_ams_phase23_materialized_accumulators_canonical_v1,
    zk_ams_mkhe_active_collective_public_a_v1, zk_ams_mkhe_active_rkg_linear_proof_security_v1,
    zk_ams_mkhe_cks_resource_evidence_v1, zk_ams_mkhe_cks_statement_digest_v1,
    zk_ams_mkhe_collect_active_round_v1, zk_ams_mkhe_compact_key_switch_ring_multiplications_v1,
    zk_ams_mkhe_cpk_ceremony_residency_evidence_v1, zk_ams_mkhe_direct_noise_certificate_v1,
    zk_ams_mkhe_direct_noise_integration_certificate_v1,
    zk_ams_mkhe_direct_noise_integration_for_admitted_keys_v1, zk_ams_mkhe_direct_proof_audit_v1,
    zk_ams_mkhe_direct_resource_certificate_v1, zk_ams_mkhe_rns_native_profile_manifest_v1,
    zk_ams_mkhe_seekable_evaluated_key_accounting_v1, zk_ams_phase3_nifs_verifier_digest_v1,
    zk_ams_phase3_ordered_public_inputs_digest_v1, zk_ams_phase23_cross_term_v1,
    zk_ams_phase23_fold_linear_v1, zk_ams_phase23_fold_quadratic_v1,
    zk_ams_phase23_materialize_release_accumulator_chunks_v1,
    zk_ams_phase23_release_map_manifest_v1, zk_ams_phase23_release_map_set_digest_v1,
    zk_ams_t256_rotation_certificate_v1, zk_ams_t256_rotation_exponent_v1,
    zk_ams_t256_rotation_key_plan_v1,
};
#[cfg(test)]
pub use mkhe::{
    ZK_AMS_MKHE_DECRYPTION_SPLIT_MANIFEST_BYTES_V1,
    ZK_AMS_MKHE_DECRYPTION_SPLIT_RELEASE_KAT_DIGEST_V1, ZK_AMS_MKHE_MAX_PROOF_BYTES_V1,
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
    ZK_AMS_MKHE_RNS_NATIVE_RLWE_EQUATION_COUNT_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_MAIN_BLOCKS_PER_OPENING_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_MAIN_FILE_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_MAIN_PLAINTEXT_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_MAIN_SLOTS_V1, ZK_AMS_MKHE_RNS_NATIVE_SOURCE_NONCE_FILE_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_NONCE_PLAINTEXT_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_NONCE_SLOTS_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_TOTAL_FILE_BYTES_V1, ZK_AMS_MKHE_RNS_NATIVE_SOURCE_VERSION_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SPOOL_MAX_BYTES_V1, ZK_AMS_MKHE_RNS_NATIVE_SUMCHECK_ROUNDS_V1,
    ZK_AMS_MKHE_RNS_NATIVE_TARGET_SECURITY_BITS_V1, ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1,
    ZK_AMS_MKHE_RNS_NATIVE_WORKSPACE_MAX_BYTES_V1, ZK_AMS_PHASE3_MAX_TERMINAL_PROOF_BYTES_V1,
    ZK_AMS_PHASE23_MAX_CANONICAL_SPARSE_ENTRIES_V1,
    ZK_AMS_PHASE23_RELEASE_ERROR_COMMITMENT_ROWS_V1, ZK_AMS_PHASE23_RELEASE_PUBLIC_INPUT_COUNT_V1,
    ZK_AMS_PHASE23_RELEASE_WITNESS_COMMITMENT_ROWS_V1, ZK_AMS_T256_GALOIS_KEY_COUNT_V1,
    ZK_AMS_T256_GALOIS_KEY_SCHEDULE_DIGEST_V1, ZK_AMS_T256_MAX_LOGICAL_VALUES_V1,
    ZK_AMS_T256_RELEASE_PACKED_INPUT_KAT_DIGEST_V1,
    ZK_AMS_T256_RELEASE_PACKED_OUTPUT_KAT_DIGEST_V1,
    ZK_AMS_T256_RELEASE_PACKING_NEGATIVE_CASE_COUNT_V1,
    ZK_AMS_T256_RELEASE_PACKING_NEGATIVE_KAT_DIGEST_V1,
    ZK_AMS_T256_RELEASE_ROTATION_CERTIFICATE_KAT_DIGEST_V1,
    ZK_AMS_T256_RELEASE_TRANSFORMED_RNS_KAT_DIGEST_V1, ZkAmsMkheDecryptionResourceEvidenceV1,
    ZkAmsMkheDirectCeremonyRoundV1, ZkAmsMkheDirectPolynomialRoleV1, ZkAmsMkheErrorV1,
    ZkAmsMkheNoiseCertificateV1, ZkAmsMkheReleaseKatEvidenceV1, ZkAmsMkheReleaseManifestV1,
    ZkAmsMkheResourceCertificateV1, ZkAmsMkheResourceEvidenceV1, ZkAmsMkheRnsNativeFamilyV1,
    ZkAmsMkheRnsNativeProfileV1, ZkAmsMkheRnsNativeSourceReceiptV1, ZkAmsMkheRnsNativeTopologyV1,
    ZkAmsMkheSecurityAttackRecordV1, ZkAmsMkheSecurityAttackV1, ZkAmsMkheSecurityCandidateV1,
    ZkAmsMkheSecurityCertificateV1, ZkAmsMkheSecurityEstimatorSuiteV1,
    ZkAmsMkheSeekableEvaluatedKeyAccountingV1, ZkAmsMkheWireEvidenceV1,
    ZkAmsPhase3TerminalImplementationV1, ZkAmsPhase23EncryptedImplementationV1,
    ZkAmsPhase23EquationCertificateV1, ZkAmsT256GaloisKeyScheduleEntryV1,
    ZkAmsT256GaloisKeyScheduleV1, ZkAmsT256PackingLayoutV1, ZkAmsT256ReleasePackingCertificateV1,
    ZkAmsT256RotationDirectionV1, ZkAmsT256RotationV1, zk_ams_mkhe_decryption_resource_evidence_v1,
    zk_ams_mkhe_noise_certificate_v1, zk_ams_mkhe_release_kat_evidence_v1,
    zk_ams_mkhe_release_manifest_v1, zk_ams_mkhe_resource_certificate_digest_v1,
    zk_ams_mkhe_resource_certificate_v1, zk_ams_mkhe_resource_evidence_v1,
    zk_ams_mkhe_security_candidate_input_digest_v1, zk_ams_mkhe_security_candidate_v1,
    zk_ams_mkhe_security_certificate_v1, zk_ams_mkhe_wire_evidence_v1,
    zk_ams_phase3_terminal_implementation_v1, zk_ams_phase23_encrypted_implementation_v1,
    zk_ams_phase23_equation_certificate_digest_v1, zk_ams_phase23_equation_certificate_v1,
    zk_ams_t256_galois_key_schedule_v1, zk_ams_t256_packed_subfield_conjugation_exponent_v1,
    zk_ams_t256_packing_layout_v1, zk_ams_t256_release_packing_certificate_v1,
    zk_ams_t256_rotation_exponent_for_direction_v1, zk_ams_t256_rotation_v1,
};
#[cfg(test)]
pub use mkhe::{
    ZK_AMS_MKHE_DECRYPTION_STREAMING_RESIDENCY_CERTIFICATE_DIGEST_V1,
    ZkAmsMkheDecryptionProofViewV1, ZkAmsMkheDecryptionStreamingResidencyEvidenceV1,
    ZkAmsMkheDecryptionStreamingSnapshotV1, ZkAmsMkhePreparedCollectivePublicAV1,
    ZkAmsMkheStagedDecryptionShareV1, ZkAmsMkheStreamingCollectiveAutomorphismAccountingV1,
    ZkAmsMkheStreamingCollectiveCiphertextV1, ZkAmsMkheStreamingCollectiveEncryptionKeyAuthorityV1,
    ZkAmsMkheStreamingDecryptionStatementV1, ZkAmsMkheStreamingFullRosterDecryptionResultV1,
    ZkAmsMkheTrustedSourceContextV1, ZkAmsMkheValidatedCollectiveSourceEvidenceReceiptV1,
    ZkAmsMkheVerifiedEvaluatedKeyEvidenceSetV1,
    automorphism_switch_zk_ams_mkhe_collective_streaming_v1,
    encrypt_zk_ams_mkhe_collective_packed_streaming_v1, prepare_zk_ams_mkhe_collective_public_a_v1,
    prove_zk_ams_mkhe_decryption_share_staged_v1,
    verify_combine_decode_zk_ams_mkhe_decryption_streaming_v1,
    verify_zk_ams_mkhe_evaluated_key_evidence_set_v1,
    zk_ams_mkhe_decryption_streaming_residency_evidence_v1,
    zk_ams_mkhe_streaming_collective_automorphism_accounting_v1,
};
#[cfg(test)]
pub use mkhe::{
    ZK_AMS_MKHE_DIRECT_OBJECT_POINTER_BYTES_V1, ZK_AMS_MKHE_DIRECT_OBJECT_READ_BYTES_V1,
    ZkAmsMkheDirectObjectPointerV1, ZkAmsMkheDirectObjectPublicationReceiptV1,
    ZkAmsMkheDirectObjectPublishedBindingV1, ZkAmsMkheDirectObjectReadReceiptV1,
};
#[cfg(test)]
pub use mkhe::{
    ZK_AMS_MKHE_RNS_NATIVE_COMPOSITE_VERIFICATION_VERSION_V1,
    ZkAmsMkheRnsNativeCompositeCandidateReceiptV1, ZkAmsMkheRnsNativeCompositeVerificationErrorV1,
    ZkAmsMkheRnsNativeVerificationStageV1, verify_zk_ams_mkhe_rns_native_composite_v1,
};
#[cfg(test)]
pub use mkhe::{
    ZK_AMS_MKHE_RNS_NATIVE_CROSS_FIELD_LOOKUP_SECTION_MAX_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_PROOF_ENVELOPE_HEADER_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_PROOF_ENVELOPE_MAX_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_PROOF_SECTION_COUNT_V1,
    ZK_AMS_MKHE_RNS_NATIVE_RNS_RELATION_QPCS_SECTION_MAX_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_TERMINAL_BRIDGE_SECTION_MAX_BYTES_V1,
    ZkAmsMkheRnsNativeProofSectionKindV1,
};
#[cfg(test)]
pub use mkhe::{
    ZK_AMS_MKHE_RNS_NATIVE_PROOF_ENVELOPE_VERSION_V1,
    ZK_AMS_MKHE_RNS_NATIVE_PROOF_SECTION_ORDER_V1, ZkAmsMkheRnsNativeProofEnvelopeV1,
    ZkAmsMkheRnsNativeProofSectionDescriptorV1,
};
#[cfg(test)]
pub use mkhe::{
    ZK_AMS_MKHE_RNS_NATIVE_QPCS_ROOT_COUNT_V1,
    ZK_AMS_MKHE_RNS_NATIVE_TRANSCRIPT_CHALLENGE_COUNT_V1, ZkAmsMkheRnsNativeChallengeSeedsV1,
    ZkAmsMkheRnsNativeOpeningCommitmentV1, ZkAmsMkheRnsNativeQpcsFriRootV1,
    ZkAmsMkheRnsNativeTranscriptErrorV1,
};
#[cfg(test)]
pub use mkhe::{
    ZK_AMS_MKHE_RNS_NATIVE_SECTION_CODEC_VERSION_V1,
    ZkAmsMkheRnsNativeCrossFieldGlobalLookupSectionV1, ZkAmsMkheRnsNativeRnsRelationQpcsSectionV1,
    ZkAmsMkheRnsNativeSectionCodecErrorV1, ZkAmsMkheRnsNativeTerminalBridgeSectionV1,
};
#[cfg(test)]
pub use mkhe::{
    ZK_AMS_MKHE_RNS_NATIVE_TRANSCRIPT_VERSION_V1, ZkAmsMkheRnsNativeCommitmentsBoundTranscriptV1,
    ZkAmsMkheRnsNativeOpeningCommitmentsV1, ZkAmsMkheRnsNativePublicContextV1,
    ZkAmsMkheRnsNativeQpcsBoundTranscriptV1, ZkAmsMkheRnsNativeQpcsRootsV1,
    ZkAmsMkheRnsNativeTerminalBoundTranscriptV1, ZkAmsMkheRnsNativeTerminalBridgeV1,
    ZkAmsMkheRnsNativeTranscriptV1,
};
pub use mkhe::{
    ZkAmsMkheCksNoiseInputV1, ZkAmsMkheFailureAllocationV1, ZkAmsMkheNoiseAccountingV1,
    ZkAmsMkheNoiseAdmissionV1, ZkAmsMkheNoiseConstructionV1, ZkAmsMkheNoiseFeasibilityV1,
    ZkAmsMkhePhaseNoiseBoundsV1, ZkAmsMkheSmudgePurposeV1, ZkAmsMkheSmudgeQueriesV1,
    ZkAmsMkheTerminalFeasibilityV1, zk_ams_mkhe_noise_feasibility_v1,
};
#[cfg(test)]
pub use mkhe::{
    ZkAmsMkheCollectiveCiphertextV1, ZkAmsMkheCollectiveLevelOneV1, ZkAmsMkheCollectivePublicKeyV1,
};
#[cfg(test)]
pub use mkhe::{
    ZkAmsMkheDirectObjectCasPublicationV1, ZkAmsMkheDirectObjectPublicationTransactionV1,
    ZkAmsMkheDirectObjectReadAtProviderV1, ZkAmsMkheDirectObjectSealTokenV1,
    ZkAmsMkheDirectObjectStagingTokenV1, validate_zk_ams_mkhe_direct_object_v1,
};
pub use mkhe::{
    ZkAmsMkheReadinessV1, ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1,
    ZkAmsMkheRnsNativeSecretChunkV1, ZkAmsMkheRnsNativeSourceArenaV1,
    ZkAmsMkheRnsNativeSourceErrorV1, ZkAmsMkheRnsNativeSourceLayoutV1,
    ZkAmsMkheRnsNativeSourceProviderV1, ZkAmsMkheRnsNativeSourceSnapshotV1,
    ZkAmsMkheRnsNativeSourceWriterV1, zk_ams_mkhe_manifest_digest_v1,
    zk_ams_mkhe_readiness_digest_v1, zk_ams_mkhe_readiness_v1, zk_ams_mkhe_rns_native_profile_v1,
    zk_ams_mkhe_rns_native_topology_v1,
};
/// Exact number of public T256 scalars in one admission relation instance.
pub const ZK_AMS_ADMISSION_PUBLIC_INPUTS_V1: usize = 89;
/// Hard cap checked before Norito decoding of a batch relation proof.
pub const MAX_ZK_AMS_ADMISSION_RELATION_PROOF_BYTES_V1: usize = 2 * 1024 * 1024;
/// Exact canonical fixed PHC payload width.
pub const ZK_AMS_PHC_CANONICAL_PAYLOAD_BYTES_V1: usize = 161;
/// Sole privacy-action index admitted by the first-release ZK-AMS profile.
pub const ZK_AMS_ACTION_INDEX_V1: u32 = 0;
const PROOF_VERSION_V1: u8 = 1;
const MAX_CHAIN_ID_BYTES_V1: usize = 255;
const COMPOSITION_DOMAIN_V1: &[u8] = b"iroha-zk-ams-v1:batch-admission:masked-relaxed-spartan-t256";
const COMMITMENT_KEY_LABEL_V1: &[u8] = b"iroha.zk-ams.v1.batch-admission.hyrax-t256";
const PROFILE_DESCRIPTOR_V1: &[u8] = b"iroha.zk-ams.v1.batch-admission.canonical-phc-es256-root-transition.homogeneous-lineage.unique-anchors";
const SOURCE_PROFILE_V1: &[u8] = b"arxiv:2602.16130v2:algorithms-1-4:appendices-a-c";
const PHC_HASH_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-ams:phc:v1";
const REGISTRY_TRANSITION_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-ams:registry-transition:v1";
const ISSUER_X_INDEX: usize = 0;
const ISSUER_Y_INDEX: usize = 1;
const ISSUER_PREFIX_INDEX: usize = 2;
const ISSUER_ID_WORD_START: usize = 3;
const POLICY_ID_WORD_START: usize = 11;
const ISSUER_POLICY_RECORD_WORD_START: usize = 19;
const REGISTRY_ID_WORD_START: usize = 27;
const REGISTRY_RECORD_WORD_START: usize = 35;
const POLICY_DIGEST_WORD_START: usize = 43;
const PHC_HASH_WORD_START: usize = 51;
const SEED_KEY_WORD_START: usize = 59;
const PRIOR_ROOT_WORD_START: usize = 67;
const NEXT_ROOT_WORD_START: usize = 75;
const CURRENT_EPOCH_HIGH_INDEX: usize = 83;
const CURRENT_EPOCH_LOW_INDEX: usize = 84;
const NEXT_EPOCH_HIGH_INDEX: usize = 85;
const NEXT_EPOCH_LOW_INDEX: usize = 86;
const BATCH_SIZE_INDEX: usize = 87;
const ANCHOR_INDEX: usize = 88;
static CANONICAL_PROFILE: Lazy<Result<Arc<CircuitProfile>, CircuitError>> =
    Lazy::new(build_canonical_profile);
static CANONICAL_SHAPE: Lazy<Result<Arc<Shape>, CircuitError>> = Lazy::new(build_canonical_shape);
static T256_GENERATOR_DIGEST: Lazy<[u8; 32]> = Lazy::new(|| {
    let points = derive_t256_generators_v1(
        COMMITMENT_KEY_LABEL_V1,
        super::masked_relaxed::MASKED_RELAXED_COMMITMENT_COLUMNS_V1 + 1,
    )
    .expect("released ZK-AMS T256 generator basis must derive");
    let mut frame = Vec::with_capacity(64 + points.len() * 64);
    frame.extend_from_slice(b"iroha.zk-ams.v1.t256-generator-basis");
    frame.extend_from_slice(
        &u32::try_from(points.len())
            .expect("released generator count fits u32")
            .to_be_bytes(),
    );
    for point in points {
        frame.extend_from_slice(
            &point
                .to_transcript_bytes()
                .expect("derived generator is nonidentity"),
        );
    }
    keccak256(&frame)
});
/// Full consensus binding absorbed before all Nova and Spartan material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsProofContextV1<'a> {
    /// Exact chain identifier.
    pub chain_id: &'a [u8],
    /// Independently trusted genesis digest.
    pub genesis_hash: [u8; 32],
    /// Zero-based privacy action index.
    pub action_index: u32,
    /// Digest of the complete typed public statement.
    pub statement_digest: [u8; 32],
    /// Governed parameter identifier.
    pub parameter_id: [u8; 32],
    /// Governed parameter digest.
    pub parameter_digest: [u8; 32],
    /// Exact verifier-artifact digest.
    pub verifier_digest: [u8; 32],
    /// Typed statement-schema digest.
    pub statement_schema_digest: [u8; 32],
    /// Native engine-manifest digest.
    pub engine_manifest_digest: [u8; 32],
    /// Combined Ristretto/T256 generator-basis digest.
    pub generator_digest: [u8; 32],
}
/// Public values for one ordered credential and registry transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsAdmissionPublicInputV1 {
    /// Canonical issuer P-256 x-coordinate.
    pub issuer_key_x: [u8; 32],
    /// Canonical issuer P-256 y-coordinate.
    pub issuer_key_y: [u8; 32],
    /// Canonical compressed SEC1 prefix (`0x02` or `0x03`).
    pub issuer_key_prefix: u8,
    /// Exact issuer identifier embedded in the PHC.
    pub issuer_id: [u8; 32],
    /// Exact policy identifier embedded in the PHC.
    pub policy_id: [u8; 32],
    /// Authoritative issuer-policy-record digest.
    pub issuer_policy_record_digest: [u8; 32],
    /// Registry namespace.
    pub registry_id: [u8; 32],
    /// Authoritative registry-snapshot-record digest.
    pub registry_record_digest: [u8; 32],
    /// Exact governed admission-policy digest.
    pub policy_digest: [u8; 32],
    /// Public hash of the canonical PHC.
    pub phc_hash: [u8; 32],
    /// Exact compressed Ristretto seed key embedded in the PHC.
    pub seed_public_key: [u8; 32],
    /// Root before this ordered anchor.
    pub prior_registry_root: [u8; 32],
    /// Root after this ordered anchor.
    pub next_registry_root: [u8; 32],
    /// Authoritative current registry epoch.
    pub current_registry_epoch: u64,
    /// Exact successor registry epoch.
    pub next_registry_epoch: u64,
    /// Total anchors in this atomic batch.
    pub batch_size: u32,
    /// Zero-based position of this anchor.
    pub anchor_index: u32,
}
impl ZkAmsAdmissionPublicInputV1 {
    fn to_scalars(self) -> Result<Vec<Scalar>, ZkAmsAdmissionRelationErrorV1> {
        self.validate()?;
        let mut values = Vec::with_capacity(ZK_AMS_ADMISSION_PUBLIC_INPUTS_V1);
        values.push(
            Scalar::from_be_bytes_exact(self.issuer_key_x)
                .map_err(|_| ZkAmsAdmissionRelationErrorV1::InvalidPublicInput)?,
        );
        values.push(
            Scalar::from_be_bytes_exact(self.issuer_key_y)
                .map_err(|_| ZkAmsAdmissionRelationErrorV1::InvalidPublicInput)?,
        );
        values.push(Scalar::from_u64(u64::from(self.issuer_key_prefix)));
        for bytes in [
            self.issuer_id,
            self.policy_id,
            self.issuer_policy_record_digest,
            self.registry_id,
            self.registry_record_digest,
            self.policy_digest,
            self.phc_hash,
            self.seed_public_key,
            self.prior_registry_root,
            self.next_registry_root,
        ] {
            push_digest_words(&mut values, bytes);
        }
        values.push(Scalar::from_u64(self.current_registry_epoch >> 32));
        values.push(Scalar::from_u64(self.current_registry_epoch & 0xffff_ffff));
        values.push(Scalar::from_u64(self.next_registry_epoch >> 32));
        values.push(Scalar::from_u64(self.next_registry_epoch & 0xffff_ffff));
        values.push(Scalar::from_u64(u64::from(self.batch_size)));
        values.push(Scalar::from_u64(u64::from(self.anchor_index)));
        if values.len() != ZK_AMS_ADMISSION_PUBLIC_INPUTS_V1 {
            return Err(ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile);
        }
        Ok(values)
    }
    fn validate(self) -> Result<(), ZkAmsAdmissionRelationErrorV1> {
        if !matches!(self.issuer_key_prefix, 0x02 | 0x03)
            || self.issuer_key_x >= VEGA_T256_BASE_MODULUS_BE_V1
            || self.issuer_key_y >= VEGA_T256_BASE_MODULUS_BE_V1
            || self.batch_size == 0
            || self.batch_size as usize > MAX_MASKED_RELAXED_STRICT_INSTANCES_V1
            || self.anchor_index >= self.batch_size
            || self
                .current_registry_epoch
                .checked_add(1)
                .is_none_or(|next| next != self.next_registry_epoch)
            || [
                self.issuer_id,
                self.policy_id,
                self.issuer_policy_record_digest,
                self.registry_id,
                self.registry_record_digest,
                self.policy_digest,
                self.phc_hash,
                self.seed_public_key,
                self.prior_registry_root,
                self.next_registry_root,
            ]
            .into_iter()
            .any(|bytes| bytes == [0; 32])
        {
            return Err(ZkAmsAdmissionRelationErrorV1::InvalidPublicInput);
        }
        Ok(())
    }
}
/// Private witness for one exact canonical PHC and issuer signature.
#[derive(Clone, Copy)]
pub struct ZkAmsAdmissionRelationWitnessV1<'a> {
    subject_commitment: &'a [u8; 32],
    credential_nonce: &'a [u8; 32],
    issuer_signature_r: &'a [u8; 32],
    issuer_signature_s: &'a [u8; 32],
    signature_recovery_x: &'a [u8; 32],
    signature_recovery_y: &'a [u8; 32],
}
impl<'a> ZkAmsAdmissionRelationWitnessV1<'a> {
    /// Construct a borrowed witness. Algebraic and canonical checks occur in
    /// the exact circuit; this constructor rejects zero hidden PHC fields.
    pub fn new(
        subject_commitment: &'a [u8; 32],
        credential_nonce: &'a [u8; 32],
        issuer_signature_r: &'a [u8; 32],
        issuer_signature_s: &'a [u8; 32],
        signature_recovery_x: &'a [u8; 32],
        signature_recovery_y: &'a [u8; 32],
    ) -> Result<Self, ZkAmsAdmissionRelationErrorV1> {
        if *subject_commitment == [0; 32] || *credential_nonce == [0; 32] {
            return Err(ZkAmsAdmissionRelationErrorV1::InvalidWitness);
        }
        Ok(Self {
            subject_commitment,
            credential_nonce,
            issuer_signature_r,
            issuer_signature_s,
            signature_recovery_x,
            signature_recovery_y,
        })
    }
}
impl fmt::Debug for ZkAmsAdmissionRelationWitnessV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ZkAmsAdmissionRelationWitnessV1([REDACTED])")
    }
}
/// Explicit bounded native prover configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsMaskedProverConfigV1 {
    worker_count: usize,
}
impl ZkAmsMaskedProverConfigV1 {
    /// Select a deterministic commitment worker count in `1..=20`.
    pub const fn new(worker_count: usize) -> Result<Self, ZkAmsAdmissionRelationErrorV1> {
        if worker_count == 0 || worker_count > 20 {
            return Err(ZkAmsAdmissionRelationErrorV1::InvalidWorkerCount {
                actual: worker_count,
            });
        }
        Ok(Self { worker_count })
    }
    /// Return the exact selected worker count.
    #[must_use]
    pub const fn worker_count(self) -> usize {
        self.worker_count
    }
}
/// Frozen compiled proof dimensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsAdmissionRelationDimensionsV1 {
    /// Padded private variable count.
    pub variable_count: usize,
    /// Padded constraint count.
    pub constraint_count: usize,
    /// Exact public input count.
    pub public_input_count: usize,
    /// T256 points in each strict witness commitment.
    pub witness_commitment_points: usize,
    /// T256 points in each mask/cross-term error commitment.
    pub error_commitment_points: usize,
    /// Outer Spartan rounds.
    pub outer_sumcheck_rounds: usize,
    /// Inner Spartan rounds.
    pub inner_sumcheck_rounds: usize,
}
/// Failure at the exact ZK-AMS admission relation boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ZkAmsAdmissionRelationErrorV1 {
    /// A public relation value is malformed or outside the closed profile.
    #[error("invalid ZK-AMS admission public input")]
    InvalidPublicInput,
    /// Private PHC/signature material is malformed or unsatisfied.
    #[error("invalid or unsatisfied ZK-AMS admission witness")]
    InvalidWitness,
    /// Consensus transcript context is empty, oversized, or zero.
    #[error("invalid ZK-AMS admission consensus context")]
    InvalidContext,
    /// Batch and witness vector lengths differ or are outside `1..=8`.
    #[error("invalid ZK-AMS admission batch size {actual}")]
    InvalidBatchSize {
        /// Supplied number of strict instances.
        actual: usize,
    },
    /// Batch rows do not share one issuer, policy, registry, and epoch lineage.
    #[error("inconsistent ZK-AMS admission batch lineage")]
    InconsistentBatchLineage,
    /// Two batch rows reuse the same canonical credential digest.
    #[error("duplicate ZK-AMS admission credential digest")]
    DuplicateCredentialDigest,
    /// Two batch rows reuse the same admitted seed public key.
    #[error("duplicate ZK-AMS admission seed public key")]
    DuplicateSeedPublicKey,
    /// Commitment worker count is outside `1..=20`.
    #[error("invalid ZK-AMS admission worker count {actual}")]
    InvalidWorkerCount {
        /// Supplied worker count.
        actual: usize,
    },
    /// Deterministic circuit synthesis drifted from the released shape.
    #[error("invalid ZK-AMS compiled admission profile")]
    InvalidCompiledProfile,
    /// Proof bytes exceed the pre-decode cap.
    #[error("ZK-AMS admission proof length {actual} exceeds {max}")]
    ProofTooLarge {
        /// Actual supplied byte length.
        actual: usize,
        /// Exact hard maximum.
        max: usize,
    },
    /// Norito or algebraic proof encoding is not exact and canonical.
    #[error("invalid canonical ZK-AMS admission proof encoding")]
    InvalidProofEncoding,
    /// Nova/Spartan verification or prover self-check failed.
    #[error("ZK-AMS admission relation verification failed")]
    VerificationFailed,
    /// Cryptographic randomness was unavailable.
    #[error("ZK-AMS admission cryptographic random source unavailable")]
    RandomUnavailable,
    /// Cryptographic randomness was degenerate.
    #[error("ZK-AMS admission cryptographic randomness is degenerate")]
    DegenerateRandomness,
}
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
#[norito(decode_from_slice)]
struct ZkAmsAdmissionProofWireV1 {
    version: u8,
    relation: MaskedRelaxedProofWireV1,
}
/// Encode the sole canonical admission-relation wire. Phase-III terminal producers use this helper
/// so transaction proof bytes cannot drift into a second outer schema.
pub(super) fn encode_zk_ams_admission_relation_wire_v1(
    relation: MaskedRelaxedProofWireV1,
) -> Result<Vec<u8>, ZkAmsAdmissionRelationErrorV1> {
    let proof = ZkAmsAdmissionProofWireV1 {
        version: PROOF_VERSION_V1,
        relation,
    };
    let encoded = norito::codec::encode_adaptive(&proof);
    if encoded.len() > MAX_ZK_AMS_ADMISSION_RELATION_PROOF_BYTES_V1 {
        return Err(ZkAmsAdmissionRelationErrorV1::ProofTooLarge {
            actual: encoded.len(),
            max: MAX_ZK_AMS_ADMISSION_RELATION_PROOF_BYTES_V1,
        });
    }
    Ok(encoded)
}
/// Decode and canonicalize the sole admission-relation wire under the exact
/// expected strict-instance count.
pub(super) fn decode_zk_ams_admission_relation_wire_v1(
    expected_instances: usize,
    proof_bytes: &[u8],
) -> Result<MaskedRelaxedProofWireV1, ZkAmsAdmissionRelationErrorV1> {
    if proof_bytes.len() > MAX_ZK_AMS_ADMISSION_RELATION_PROOF_BYTES_V1 {
        return Err(ZkAmsAdmissionRelationErrorV1::ProofTooLarge {
            actual: proof_bytes.len(),
            max: MAX_ZK_AMS_ADMISSION_RELATION_PROOF_BYTES_V1,
        });
    }
    let shape = canonical_shape()?;
    let dimensions = MaskedRelaxedDimensionsV1::from_shape(&shape)
        .map_err(|_| ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile)?;
    let decode_limits = dimensions
        .proof_decode_limits(
            expected_instances,
            proof_bytes.len(),
            MAX_ZK_AMS_ADMISSION_RELATION_PROOF_BYTES_V1,
        )
        .map_err(map_composition_error)?;
    let proof = norito::codec::decode_exact_from_slice_with_limits::<ZkAmsAdmissionProofWireV1>(
        proof_bytes,
        decode_limits,
    )
    .map_err(|_| ZkAmsAdmissionRelationErrorV1::InvalidProofEncoding)?;
    if proof.version != PROOF_VERSION_V1 || norito::codec::encode_adaptive(&proof) != proof_bytes {
        return Err(ZkAmsAdmissionRelationErrorV1::InvalidProofEncoding);
    }
    Ok(proof.relation)
}
/// Return the exact compiled relation dimensions.
pub fn zk_ams_admission_relation_dimensions_v1()
-> Result<ZkAmsAdmissionRelationDimensionsV1, ZkAmsAdmissionRelationErrorV1> {
    let shape = canonical_shape()?;
    let dimensions = MaskedRelaxedDimensionsV1::from_shape(&shape)
        .map_err(|_| ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile)?;
    Ok(ZkAmsAdmissionRelationDimensionsV1 {
        variable_count: dimensions.variable_count,
        constraint_count: dimensions.constraint_count,
        public_input_count: dimensions.public_input_count,
        witness_commitment_points: dimensions.witness_commitment_points,
        error_commitment_points: dimensions.error_commitment_points,
        outer_sumcheck_rounds: dimensions.outer_sumcheck_rounds,
        inner_sumcheck_rounds: dimensions.inner_sumcheck_rounds,
    })
}
/// Return the digest of the exact circuit/composer profile admitted by governance.
pub fn zk_ams_compiled_profile_digest_v1() -> Result<[u8; 32], ZkAmsAdmissionRelationErrorV1> {
    let readiness = zk_ams_mkhe_readiness_v1()
        .map_err(|_| ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile)?;
    compiled_profile_digest_for_readiness_v1(readiness)
}
fn compiled_profile_digest_for_readiness_v1(
    readiness: ZkAmsMkheReadinessV1,
) -> Result<[u8; 32], ZkAmsAdmissionRelationErrorV1> {
    if !readiness.is_ready() {
        return Err(ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile);
    }
    Ok(compiled_profile_digest_unchecked_v1())
}
fn compiled_profile_digest_unchecked_v1() -> [u8; 32] {
    let shape = canonical_shape().expect("released ZK-AMS shape must synthesize");
    let dimensions =
        MaskedRelaxedDimensionsV1::from_shape(&shape).expect("released dimensions must be valid");
    profile_digest(&shape, dimensions).expect("released profile is fixed and bounded")
}
/// Return the digest of every independently derived T256 commitment generator,
/// including the hiding generator.
#[must_use]
pub fn zk_ams_t256_generator_digest_v1() -> [u8; 32] {
    *T256_GENERATOR_DIGEST
}
/// Prove an ordered batch and self-verify the exact canonical output.
pub fn prove_zk_ams_admission_relation_v1<R: MaskedRelaxedRandomSourceV1>(
    context: &ZkAmsProofContextV1<'_>,
    public_inputs: &[ZkAmsAdmissionPublicInputV1],
    witnesses: &[ZkAmsAdmissionRelationWitnessV1<'_>],
    config: ZkAmsMaskedProverConfigV1,
    random: &mut R,
) -> Result<Vec<u8>, ZkAmsAdmissionRelationErrorV1> {
    validate_context(context)?;
    validate_batch(public_inputs, witnesses.len())?;
    require_mkhe_release_ready_v1()?;
    prove_zk_ams_admission_relation_inner_v1(context, public_inputs, witnesses, config, random)
}
fn prove_zk_ams_admission_relation_inner_v1<R: MaskedRelaxedRandomSourceV1>(
    context: &ZkAmsProofContextV1<'_>,
    public_inputs: &[ZkAmsAdmissionPublicInputV1],
    witnesses: &[ZkAmsAdmissionRelationWitnessV1<'_>],
    config: ZkAmsMaskedProverConfigV1,
    random: &mut R,
) -> Result<Vec<u8>, ZkAmsAdmissionRelationErrorV1> {
    let shape = canonical_shape()?;
    let strict_public_inputs = public_inputs
        .iter()
        .copied()
        .map(ZkAmsAdmissionPublicInputV1::to_scalars)
        .collect::<Result<Vec<_>, _>>()?;
    let context_frame = context_frame(context)?;
    let assignment_shape = Arc::clone(&shape);
    let precomputation = precompute_masked_relaxed_stream_v1(
        MaskedRelaxedStreamConfigV1::new(
            COMPOSITION_DOMAIN_V1,
            &context_frame,
            COMMITMENT_KEY_LABEL_V1,
            shape,
            &strict_public_inputs,
            config.worker_count,
        ),
        |index| {
            synthesize_admission_with_shape(
                public_inputs[index],
                &witnesses[index],
                Arc::clone(&assignment_shape),
            )
            .map_err(map_circuit_synthesis_error)
        },
        random,
    )
    .map_err(map_composition_error)?;
    let relation = prove_masked_relaxed_precomputation_v1(
        COMPOSITION_DOMAIN_V1,
        &context_frame,
        COMMITMENT_KEY_LABEL_V1,
        &precomputation,
        config.worker_count,
    )
    .map_err(map_composition_error)?;
    let encoded = encode_zk_ams_admission_relation_wire_v1(relation)?;
    verify_zk_ams_admission_relation_inner_v1(context, public_inputs, &encoded)?;
    Ok(encoded)
}
/// Verify one bounded, exact-canonical batch relation proof.
pub fn verify_zk_ams_admission_relation_v1(
    context: &ZkAmsProofContextV1<'_>,
    public_inputs: &[ZkAmsAdmissionPublicInputV1],
    proof_bytes: &[u8],
) -> Result<(), ZkAmsAdmissionRelationErrorV1> {
    validate_context(context)?;
    validate_batch(public_inputs, public_inputs.len())?;
    require_mkhe_release_ready_v1()?;
    verify_zk_ams_admission_relation_inner_v1(context, public_inputs, proof_bytes)
}
fn verify_zk_ams_admission_relation_inner_v1(
    context: &ZkAmsProofContextV1<'_>,
    public_inputs: &[ZkAmsAdmissionPublicInputV1],
    proof_bytes: &[u8],
) -> Result<(), ZkAmsAdmissionRelationErrorV1> {
    let shape = canonical_shape()?;
    let relation = decode_zk_ams_admission_relation_wire_v1(public_inputs.len(), proof_bytes)?;
    let strict_public_inputs = public_inputs
        .iter()
        .copied()
        .map(ZkAmsAdmissionPublicInputV1::to_scalars)
        .collect::<Result<Vec<_>, _>>()?;
    let context_frame = context_frame(context)?;
    verify_masked_relaxed_v1(
        COMPOSITION_DOMAIN_V1,
        &context_frame,
        COMMITMENT_KEY_LABEL_V1,
        &shape,
        &strict_public_inputs,
        &relation,
    )
    .map_err(map_composition_error)
}
fn require_mkhe_release_ready_v1() -> Result<(), ZkAmsAdmissionRelationErrorV1> {
    mkhe::require_release_ready_v1()
        .map_err(|_| ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile)
}
fn map_circuit_synthesis_error(error: CircuitError) -> MaskedRelaxedErrorV1 {
    match error {
        CircuitError::InvalidAssignment | CircuitError::R1cs(R1csError::Unsatisfied) => {
            MaskedRelaxedErrorV1::UnsatisfiedWitness
        }
        CircuitError::InvalidDimension
        | CircuitError::ShapeMismatch
        | CircuitError::R1cs(
            R1csError::InvalidDimension
            | R1csError::CsrStorageOverflow
            | R1csError::CsrStorageAllocation
            | R1csError::CsrEntryCountMismatch
            | R1csError::NonCanonicalMatrix,
        ) => MaskedRelaxedErrorV1::InvalidProfile,
    }
}
/// Count first, then compile the canonical relation directly into CSR rows.
///
/// The canonical profile deliberately uses dummy values that need not satisfy
/// every relation constraint, so this path pins topology and dimensions only.
fn synthesize_admission_count_then_compile(
    public: ZkAmsAdmissionPublicInputV1,
    witness: &ZkAmsAdmissionRelationWitnessV1<'_>,
) -> Result<(CircuitAssignment, CircuitDimensions), CircuitError> {
    let public_scalars = public
        .to_scalars()
        .map_err(|_| CircuitError::InvalidAssignment)?;
    let mut counter = CircuitBuilder::new_counting(public_scalars.clone())?;
    synthesize_admission_inner(&mut counter, witness)?;
    let dimensions = counter.finish_counting()?;
    let mut compiler = CircuitBuilder::new_compiling(public_scalars, dimensions)?;
    synthesize_admission_inner(&mut compiler, witness)?;
    Ok((compiler.finalize_compiled()?, dimensions))
}
/// Synthesize a fixed admission witness directly against the canonical shape.
/// The caller obtains `shape` only from the canonical shape cache, so no
/// per-witness sparse matrix reconstruction is needed.
fn synthesize_admission_with_shape(
    public: ZkAmsAdmissionPublicInputV1,
    witness: &ZkAmsAdmissionRelationWitnessV1<'_>,
    shape: Arc<Shape>,
) -> Result<CircuitAssignment, CircuitError> {
    let public_scalars = public
        .to_scalars()
        .map_err(|_| CircuitError::InvalidAssignment)?;
    let profile = canonical_profile().map_err(|_| CircuitError::ShapeMismatch)?;
    if !Arc::ptr_eq(profile.shape(), &shape) {
        return Err(CircuitError::ShapeMismatch);
    }
    let mut builder = CircuitBuilder::new_with_profile(public_scalars, Arc::clone(profile))?;
    synthesize_admission_inner(&mut builder, witness)?;
    builder.finalize_with_shape()
}
fn synthesize_admission_inner(
    builder: &mut CircuitBuilder,
    witness: &ZkAmsAdmissionRelationWitnessV1<'_>,
) -> Result<(), CircuitError> {
    let issuer_key =
        public_compressed_point(builder, ISSUER_X_INDEX, ISSUER_Y_INDEX, ISSUER_PREFIX_INDEX)?;
    let issuer_id = public_digest_bytes(builder, ISSUER_ID_WORD_START)?;
    let policy_id = public_digest_bytes(builder, POLICY_ID_WORD_START)?;
    let seed_key = public_digest_bytes(builder, SEED_KEY_WORD_START)?;
    let phc_hash = public_digest_words(builder, PHC_HASH_WORD_START)?;
    let mut phc_message = constant_bytes(builder, PHC_HASH_DOMAIN_V1)?;
    phc_message.extend(constant_bytes(
        builder,
        &(ZK_AMS_PHC_CANONICAL_PAYLOAD_BYTES_V1 as u64).to_le_bytes(),
    )?);
    phc_message.push(constant_byte(builder, 1)?);
    phc_message.extend_from_slice(&issuer_id);
    phc_message.extend_from_slice(&policy_id);
    let subject = allocate_bytes(builder, witness.subject_commitment)?;
    enforce_nonzero_bytes(builder, &subject)?;
    phc_message.extend_from_slice(&subject);
    phc_message.extend_from_slice(&seed_key);
    let nonce = allocate_bytes(builder, witness.credential_nonce)?;
    enforce_nonzero_bytes(builder, &nonce)?;
    phc_message.extend_from_slice(&nonce);
    let computed_phc_hash = sha256(builder, &phc_message)?;
    bind_digest_words(builder, computed_phc_hash, phc_hash)?;
    verify_es256_low_s(
        builder,
        computed_phc_hash,
        &issuer_key,
        *witness.issuer_signature_r,
        *witness.issuer_signature_s,
        *witness.signature_recovery_x,
        *witness.signature_recovery_y,
    )?;
    // Record/policy digests are deliberately public inputs even though the
    // circuit does not derive state. Runtime matches them to authoritative
    // records; Nova and the transcript still bind their exact values.
    for start in [
        ISSUER_POLICY_RECORD_WORD_START,
        REGISTRY_RECORD_WORD_START,
        POLICY_DIGEST_WORD_START,
    ] {
        let _ = public_digest_words(builder, start)?;
    }
    let registry_id = public_digest_bytes(builder, REGISTRY_ID_WORD_START)?;
    let prior_root = public_digest_bytes(builder, PRIOR_ROOT_WORD_START)?;
    let next_root = public_digest_words(builder, NEXT_ROOT_WORD_START)?;
    let current_epoch =
        public_u64_bytes(builder, CURRENT_EPOCH_HIGH_INDEX, CURRENT_EPOCH_LOW_INDEX)?;
    let next_epoch = public_u64_bytes(builder, NEXT_EPOCH_HIGH_INDEX, NEXT_EPOCH_LOW_INDEX)?;
    enforce_successor_epoch(
        builder,
        CURRENT_EPOCH_HIGH_INDEX,
        CURRENT_EPOCH_LOW_INDEX,
        NEXT_EPOCH_HIGH_INDEX,
        NEXT_EPOCH_LOW_INDEX,
    )?;
    let batch_size = public_word(builder, BATCH_SIZE_INDEX)?;
    let anchor_index = public_word(builder, ANCHOR_INDEX)?;
    let mut transition = constant_bytes(builder, REGISTRY_TRANSITION_DOMAIN_V1)?;
    transition.extend_from_slice(&registry_id);
    transition.extend_from_slice(&prior_root);
    transition.extend_from_slice(&current_epoch);
    transition.extend_from_slice(&next_epoch);
    transition.extend_from_slice(&batch_size.to_be_bytes());
    transition.extend_from_slice(&anchor_index.to_be_bytes());
    transition.extend_from_slice(
        &phc_hash
            .into_iter()
            .flat_map(WordVar::to_be_bytes)
            .collect::<Vec<_>>(),
    );
    transition.extend_from_slice(&seed_key);
    let computed_next = sha256(builder, &transition)?;
    bind_digest_words(builder, computed_next, next_root)?;
    Ok(())
}
fn build_canonical_profile() -> Result<Arc<CircuitProfile>, CircuitError> {
    let mut public = ZkAmsAdmissionPublicInputV1 {
        issuer_key_x: [1; 32],
        issuer_key_y: [1; 32],
        issuer_key_prefix: 3,
        issuer_id: [2; 32],
        policy_id: [3; 32],
        issuer_policy_record_digest: [4; 32],
        registry_id: [5; 32],
        registry_record_digest: [6; 32],
        policy_digest: [7; 32],
        phc_hash: [8; 32],
        seed_public_key: [9; 32],
        prior_registry_root: [10; 32],
        next_registry_root: [11; 32],
        current_registry_epoch: 1,
        next_registry_epoch: 2,
        batch_size: 1,
        anchor_index: 0,
    };
    // Coordinates need only be canonical for deterministic synthesis; curve
    // membership is a constraint and does not alter shape.
    public.issuer_key_x[0] = 0;
    public.issuer_key_y[0] = 0;
    let one = [1_u8; 32];
    let witness = ZkAmsAdmissionRelationWitnessV1::new(&one, &one, &one, &one, &one, &one)
        .map_err(|_| CircuitError::InvalidAssignment)?;
    let (assignment, dimensions) = synthesize_admission_count_then_compile(public, &witness)?;
    Ok(Arc::new(CircuitProfile::new(
        Arc::clone(&assignment.shape),
        dimensions.emitted_private_value_count,
        dimensions.emitted_constraint_count,
    )?))
}
fn build_canonical_shape() -> Result<Arc<Shape>, CircuitError> {
    match &*CANONICAL_PROFILE {
        Ok(profile) => Ok(Arc::clone(profile.shape())),
        Err(error) => Err(*error),
    }
}
#[cfg(test)]
pub(super) fn canonical_shape_ref() -> Result<&'static Shape, ZkAmsAdmissionRelationErrorV1> {
    match &*CANONICAL_SHAPE {
        Ok(shape) => Ok(shape.as_ref()),
        Err(_) => Err(ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile),
    }
}
fn canonical_profile() -> Result<&'static Arc<CircuitProfile>, ZkAmsAdmissionRelationErrorV1> {
    match &*CANONICAL_PROFILE {
        Ok(profile) => Ok(profile),
        Err(_) => Err(ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile),
    }
}
fn canonical_shape() -> Result<Arc<Shape>, ZkAmsAdmissionRelationErrorV1> {
    match &*CANONICAL_SHAPE {
        Ok(shape) => Ok(Arc::clone(shape)),
        Err(_) => Err(ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile),
    }
}
fn validate_batch(
    public_inputs: &[ZkAmsAdmissionPublicInputV1],
    witness_count: usize,
) -> Result<(), ZkAmsAdmissionRelationErrorV1> {
    if public_inputs.is_empty()
        || public_inputs.len() > MAX_MASKED_RELAXED_STRICT_INSTANCES_V1
        || public_inputs.len() != witness_count
    {
        return Err(ZkAmsAdmissionRelationErrorV1::InvalidBatchSize {
            actual: public_inputs.len(),
        });
    }
    let count = u32::try_from(public_inputs.len()).map_err(|_| {
        ZkAmsAdmissionRelationErrorV1::InvalidBatchSize {
            actual: public_inputs.len(),
        }
    })?;
    let lineage = public_inputs[0];
    for (index, public) in public_inputs.iter().copied().enumerate() {
        public.validate()?;
        if public.batch_size != count
            || public.anchor_index
                != u32::try_from(index)
                    .map_err(|_| ZkAmsAdmissionRelationErrorV1::InvalidPublicInput)?
        {
            return Err(ZkAmsAdmissionRelationErrorV1::InvalidPublicInput);
        }
        if index > 0 {
            if !same_batch_lineage(lineage, public) {
                return Err(ZkAmsAdmissionRelationErrorV1::InconsistentBatchLineage);
            }
            if public.prior_registry_root != public_inputs[index - 1].next_registry_root {
                return Err(ZkAmsAdmissionRelationErrorV1::InvalidPublicInput);
            }
            if public_inputs[..index]
                .iter()
                .any(|prior| prior.phc_hash == public.phc_hash)
            {
                return Err(ZkAmsAdmissionRelationErrorV1::DuplicateCredentialDigest);
            }
            if public_inputs[..index]
                .iter()
                .any(|prior| prior.seed_public_key == public.seed_public_key)
            {
                return Err(ZkAmsAdmissionRelationErrorV1::DuplicateSeedPublicKey);
            }
        }
    }
    Ok(())
}
fn same_batch_lineage(
    expected: ZkAmsAdmissionPublicInputV1,
    actual: ZkAmsAdmissionPublicInputV1,
) -> bool {
    actual.issuer_key_x == expected.issuer_key_x
        && actual.issuer_key_y == expected.issuer_key_y
        && actual.issuer_key_prefix == expected.issuer_key_prefix
        && actual.issuer_id == expected.issuer_id
        && actual.policy_id == expected.policy_id
        && actual.issuer_policy_record_digest == expected.issuer_policy_record_digest
        && actual.registry_id == expected.registry_id
        && actual.registry_record_digest == expected.registry_record_digest
        && actual.policy_digest == expected.policy_digest
        && actual.current_registry_epoch == expected.current_registry_epoch
        && actual.next_registry_epoch == expected.next_registry_epoch
}
fn validate_context(
    context: &ZkAmsProofContextV1<'_>,
) -> Result<(), ZkAmsAdmissionRelationErrorV1> {
    if context.action_index != ZK_AMS_ACTION_INDEX_V1
        || context.chain_id.is_empty()
        || context.chain_id.len() > MAX_CHAIN_ID_BYTES_V1
        || [
            context.genesis_hash,
            context.statement_digest,
            context.parameter_id,
            context.parameter_digest,
            context.verifier_digest,
            context.statement_schema_digest,
            context.engine_manifest_digest,
            context.generator_digest,
        ]
        .into_iter()
        .any(|digest| digest == [0; 32])
    {
        return Err(ZkAmsAdmissionRelationErrorV1::InvalidContext);
    }
    Ok(())
}
fn context_frame(
    context: &ZkAmsProofContextV1<'_>,
) -> Result<Vec<u8>, ZkAmsAdmissionRelationErrorV1> {
    validate_context(context)?;
    let mut frame = Vec::with_capacity(512 + context.chain_id.len());
    push_frame(&mut frame, 0, COMPOSITION_DOMAIN_V1)?;
    push_frame(&mut frame, 1, SOURCE_PROFILE_V1)?;
    push_frame(&mut frame, 2, context.chain_id)?;
    push_frame(&mut frame, 3, &context.genesis_hash)?;
    push_frame(&mut frame, 4, &context.action_index.to_be_bytes())?;
    push_frame(&mut frame, 5, &context.statement_digest)?;
    push_frame(&mut frame, 6, &context.parameter_id)?;
    push_frame(&mut frame, 7, &context.parameter_digest)?;
    push_frame(&mut frame, 8, &context.verifier_digest)?;
    push_frame(&mut frame, 9, &context.statement_schema_digest)?;
    push_frame(&mut frame, 10, &context.engine_manifest_digest)?;
    push_frame(&mut frame, 11, &context.generator_digest)?;
    push_frame(&mut frame, 12, &compiled_profile_digest_unchecked_v1())?;
    Ok(frame)
}
fn profile_digest(
    shape: &Shape,
    dimensions: MaskedRelaxedDimensionsV1,
) -> Result<[u8; 32], ZkAmsAdmissionRelationErrorV1> {
    let mut identity = mkhe::native_outer_identity_v1(
        mkhe::NativeOuterIdentityRoleV1::Release,
        b"iroha.zk-ams.v1.compiled-profile",
        19,
    );
    for value in [
        PROFILE_DESCRIPTOR_V1,
        SOURCE_PROFILE_V1,
        COMPOSITION_DOMAIN_V1,
        COMMITMENT_KEY_LABEL_V1,
        PHC_HASH_DOMAIN_V1,
        REGISTRY_TRANSITION_DOMAIN_V1,
    ] {
        identity
            .push_field(value)
            .map_err(|_| ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile)?;
    }
    for value in [
        PROOF_VERSION_V1 as u64,
        ZK_AMS_PHC_CANONICAL_PAYLOAD_BYTES_V1 as u64,
        shape.variable_count() as u64,
        shape.constraint_count() as u64,
        shape.public_input_count() as u64,
        dimensions.witness_commitment_points as u64,
        dimensions.error_commitment_points as u64,
        dimensions.outer_sumcheck_rounds as u64,
        dimensions.inner_sumcheck_rounds as u64,
        MAX_MASKED_RELAXED_STRICT_INSTANCES_V1 as u64,
        MAX_ZK_AMS_ADMISSION_RELATION_PROOF_BYTES_V1 as u64,
    ] {
        identity
            .push_field(&value.to_be_bytes())
            .map_err(|_| ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile)?;
    }
    identity
        .push_field(
            &zk_ams_mkhe_manifest_digest_v1()
                .map_err(|_| ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile)?,
        )
        .map_err(|_| ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile)?;
    identity
        .push_field(
            &zk_ams_mkhe_readiness_digest_v1()
                .map_err(|_| ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile)?,
        )
        .map_err(|_| ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile)?;
    Ok(*identity
        .finish()
        .map_err(|_| ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile)?
        .as_bytes())
}
fn push_frame(
    output: &mut Vec<u8>,
    tag: u8,
    value: &[u8],
) -> Result<(), ZkAmsAdmissionRelationErrorV1> {
    output.push(tag);
    output.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}
fn public_digest_words(
    builder: &mut CircuitBuilder,
    start: usize,
) -> Result<[WordVar; 8], CircuitError> {
    (0..8)
        .map(|offset| public_word(builder, start + offset))
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| CircuitError::InvalidDimension)
}
fn public_digest_bytes(
    builder: &mut CircuitBuilder,
    start: usize,
) -> Result<[ByteVar; 32], CircuitError> {
    public_digest_words(builder, start)?
        .into_iter()
        .flat_map(WordVar::to_be_bytes)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| CircuitError::InvalidDimension)
}
fn public_u64_bytes(
    builder: &mut CircuitBuilder,
    high_index: usize,
    low_index: usize,
) -> Result<[ByteVar; 8], CircuitError> {
    let high = public_word(builder, high_index)?;
    let low = public_word(builder, low_index)?;
    high.to_be_bytes()
        .into_iter()
        .chain(low.to_be_bytes())
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| CircuitError::InvalidDimension)
}
fn bind_digest_words(
    builder: &mut CircuitBuilder,
    actual: [WordVar; 8],
    expected: [WordVar; 8],
) -> Result<(), CircuitError> {
    for (actual, expected) in actual.into_iter().zip(expected) {
        builder.enforce_equal(actual.lc(), expected.lc())?;
    }
    Ok(())
}
fn constant_bytes(
    builder: &mut CircuitBuilder,
    bytes: &[u8],
) -> Result<Vec<ByteVar>, CircuitError> {
    bytes
        .iter()
        .copied()
        .map(|byte| constant_byte(builder, byte))
        .collect()
}
fn constant_byte(builder: &mut CircuitBuilder, value: u8) -> Result<ByteVar, CircuitError> {
    let byte = allocate_byte(builder, value)?;
    enforce_byte_constant(builder, byte, value)?;
    Ok(byte)
}
fn enforce_nonzero_bytes(
    builder: &mut CircuitBuilder,
    bytes: &[ByteVar],
) -> Result<(), CircuitError> {
    let mut all_zero = builder.is_zero(bytes[0].lc())?;
    for byte in &bytes[1..] {
        let zero = builder.is_zero(byte.lc())?;
        all_zero = builder.and(all_zero, zero)?;
    }
    builder.enforce_zero(all_zero.lc())
}
fn enforce_successor_epoch(
    builder: &mut CircuitBuilder,
    current_high: usize,
    current_low: usize,
    next_high: usize,
    next_low: usize,
) -> Result<(), CircuitError> {
    let two_32 = Scalar::from_u64(1_u64 << 32);
    let current = LinearCombination::from(builder.public(current_high)?)
        .scaled(two_32)
        .plus(&builder.public(current_low)?.into());
    let next = LinearCombination::from(builder.public(next_high)?)
        .scaled(two_32)
        .plus(&builder.public(next_low)?.into());
    builder.enforce_equal(
        next,
        current.plus(&LinearCombination::constant(Scalar::one())),
    )
}
fn push_digest_words(values: &mut Vec<Scalar>, bytes: [u8; 32]) {
    values.extend(bytes.chunks_exact(4).map(|word| {
        Scalar::from_u64(u64::from(u32::from_be_bytes(
            word.try_into().expect("exact four-byte word"),
        )))
    }));
}
fn map_composition_error(error: MaskedRelaxedErrorV1) -> ZkAmsAdmissionRelationErrorV1 {
    match error {
        MaskedRelaxedErrorV1::InvalidInstanceCount { actual, .. } => {
            ZkAmsAdmissionRelationErrorV1::InvalidBatchSize { actual }
        }
        MaskedRelaxedErrorV1::InvalidWorkerCount { actual, .. } => {
            ZkAmsAdmissionRelationErrorV1::InvalidWorkerCount { actual }
        }
        MaskedRelaxedErrorV1::InvalidProfile => {
            ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile
        }
        MaskedRelaxedErrorV1::UnsatisfiedWitness => ZkAmsAdmissionRelationErrorV1::InvalidWitness,
        MaskedRelaxedErrorV1::InvalidProofEncoding => {
            ZkAmsAdmissionRelationErrorV1::InvalidProofEncoding
        }
        MaskedRelaxedErrorV1::VerificationFailed => {
            ZkAmsAdmissionRelationErrorV1::VerificationFailed
        }
        MaskedRelaxedErrorV1::DegenerateRandomness => {
            ZkAmsAdmissionRelationErrorV1::DegenerateRandomness
        }
        MaskedRelaxedErrorV1::Random(MaskedRelaxedRandomErrorV1::Unavailable) => {
            ZkAmsAdmissionRelationErrorV1::RandomUnavailable
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vega::{
        VegaPointWireV1, VegaScalarWireV1,
        masked_relaxed::{MASKED_RELAXED_COMMITMENT_COLUMNS_V1, MaskedRelaxedCommitmentWireV1},
    };
    use hex_literal::hex;
    struct NeverRandom;
    impl MaskedRelaxedRandomSourceV1 for NeverRandom {
        fn fill_bytes(
            &mut self,
            _destination: &mut [u8],
        ) -> Result<(), MaskedRelaxedRandomErrorV1> {
            panic!("invalid ZK-AMS context must fail before prover randomness")
        }
    }
    #[test]
    fn canonical_shape_source_uses_shared_ownership_and_streamed_assignments() {
        let source = include_str!("zk_ams.rs");
        let production = source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("production ZK-AMS source");
        assert!(
            production.contains("static CANONICAL_SHAPE: Lazy<Result<Arc<Shape>, CircuitError>>")
        );
        assert!(
            production.contains(
                "static CANONICAL_PROFILE: Lazy<Result<Arc<CircuitProfile>, CircuitError>>"
            )
        );
        assert!(production.contains("fn canonical_shape() -> Result<Arc<Shape>"));
        assert!(production.contains(
            "#[cfg(test)]\npub(super) fn canonical_shape_ref() -> Result<&'static Shape"
        ));
        assert!(production.contains("precompute_masked_relaxed_stream_v1("));
        assert!(production.contains("synthesize_admission_with_shape("));
        assert!(production.contains("CircuitBuilder::new_counting("));
        assert!(production.contains("CircuitBuilder::new_compiling("));
        assert!(production.contains("compiler.finalize_compiled()?"));
        assert!(production.contains("CircuitProfile::new("));
        assert!(!production.contains("Vec::with_capacity(public_inputs.len())"));
        let canonical_build = production
            .split("fn build_canonical_profile")
            .nth(1)
            .and_then(|tail| tail.split("fn build_canonical_shape").next())
            .expect("canonical profile build");
        assert!(canonical_build.contains("synthesize_admission_count_then_compile"));
        assert!(!canonical_build.contains("validate_strict_assignment"));
        assert!(!canonical_build.contains("CircuitBuilder::new("));
    }
    fn proof_context() -> ZkAmsProofContextV1<'static> {
        ZkAmsProofContextV1 {
            chain_id: b"taira-zk-ams-test",
            genesis_hash: [0x11; 32],
            action_index: ZK_AMS_ACTION_INDEX_V1,
            statement_digest: [0x12; 32],
            parameter_id: [0x13; 32],
            parameter_digest: [0x14; 32],
            verifier_digest: [0x15; 32],
            statement_schema_digest: [0x16; 32],
            engine_manifest_digest: [0x17; 32],
            generator_digest: [0x18; 32],
        }
    }
    #[derive(Clone)]
    struct AdmissionAssignmentFixture {
        public: ZkAmsAdmissionPublicInputV1,
        subject_commitment: [u8; 32],
        credential_nonce: [u8; 32],
        signature_r: [u8; 32],
        signature_s: [u8; 32],
        recovery_x: [u8; 32],
        recovery_y: [u8; 32],
    }
    impl AdmissionAssignmentFixture {
        fn witness(&self) -> ZkAmsAdmissionRelationWitnessV1<'_> {
            ZkAmsAdmissionRelationWitnessV1::new(
                &self.subject_commitment,
                &self.credential_nonce,
                &self.signature_r,
                &self.signature_s,
                &self.recovery_x,
                &self.recovery_y,
            )
            .expect("nonzero fixed witness")
        }
    }
    fn admission_assignment_fixture() -> AdmissionAssignmentFixture {
        AdmissionAssignmentFixture {
            public: ZkAmsAdmissionPublicInputV1 {
                issuer_key_x: hex!(
                    "8e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a3"
                ),
                issuer_key_y: hex!(
                    "73eb1dbde03318366d069f83a6f5900053c73633cb041b21c55e1a86c1f400b4"
                ),
                issuer_key_prefix: 0x02,
                issuer_id: [0x31; 32],
                policy_id: [0x35; 32],
                issuer_policy_record_digest: [0x32; 32],
                registry_id: [0x33; 32],
                registry_record_digest: [0x34; 32],
                policy_digest: [0x36; 32],
                phc_hash: hex!("9383ba61dc82dee66ba0210e99a86d9bc45c6ed62c717a111239991e347a3edd"),
                seed_public_key: [0x51; 32],
                prior_registry_root: [0x37; 32],
                next_registry_root: hex!(
                    "84e0c6b4ab07ab28b71ad3828e3896e68aa821816c413bba257082df1238a586"
                ),
                current_registry_epoch: 9,
                next_registry_epoch: 10,
                batch_size: 1,
                anchor_index: 0,
            },
            subject_commitment: [0x41; 32],
            credential_nonce: [0x61; 32],
            signature_r: hex!("3ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21d1"),
            signature_s: hex!("06d6d7ac6abd44d90dbdf7da0a16796a7228576114ad79a8e8d5ba374fb6a016"),
            recovery_x: hex!("3ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21d1"),
            recovery_y: hex!("9099209accc4c8a224c843afa4f4c68a090d04da5e9889dae2f8eefce82a3740"),
        }
    }
    fn synthesize_fixture(fixture: &AdmissionAssignmentFixture) -> CircuitAssignment {
        let shape = canonical_shape().expect("canonical fixture shape");
        assert!(core::ptr::eq(
            shape.as_ref(),
            canonical_shape_ref().expect("borrowed canonical fixture shape")
        ));
        synthesize_admission_with_shape(fixture.public, &fixture.witness(), shape)
            .expect("fixed-shape admission synthesis")
    }
    fn coherent_two_anchor_batch() -> [ZkAmsAdmissionPublicInputV1; 2] {
        let mut first = admission_assignment_fixture().public;
        first.batch_size = 2;
        first.anchor_index = 0;
        let mut second = first;
        second.phc_hash = [0x71; 32];
        second.seed_public_key = [0x72; 32];
        second.prior_registry_root = first.next_registry_root;
        second.next_registry_root = [0x73; 32];
        second.anchor_index = 1;
        [first, second]
    }
    fn assignment_is_satisfied(assignment: &CircuitAssignment) -> bool {
        assignment
            .shape
            .validate_strict_assignment(&assignment.witness, &assignment.public_inputs)
            .is_ok()
    }
    fn synthetic_dimensions() -> MaskedRelaxedDimensionsV1 {
        MaskedRelaxedDimensionsV1 {
            variable_count: 524_288,
            constraint_count: 1_048_576,
            public_input_count: ZK_AMS_ADMISSION_PUBLIC_INPUTS_V1,
            witness_commitment_points: 512,
            error_commitment_points: 1_024,
            outer_sumcheck_rounds: 20,
            inner_sumcheck_rounds: 20,
        }
    }
    fn empty_relation() -> MaskedRelaxedProofWireV1 {
        let scalar = VegaScalarWireV1::from_raw_bytes_for_test([0; 32]);
        MaskedRelaxedProofWireV1 {
            version: 1,
            strict_instance_count: 1,
            mask_witness_commitment: MaskedRelaxedCommitmentWireV1 { points: Vec::new() },
            mask_error_commitment: MaskedRelaxedCommitmentWireV1 { points: Vec::new() },
            mask_relaxation: scalar,
            mask_public_inputs: Vec::new(),
            strict_witness_commitments: Vec::new(),
            cross_term_commitments: Vec::new(),
            outer_sumcheck_rounds: Vec::new(),
            outer_claims: [scalar; 3],
            inner_sumcheck_rounds: Vec::new(),
            witness_opening: Vec::new(),
            witness_opening_blinding: scalar,
            error_opening: Vec::new(),
            error_opening_blinding: scalar,
        }
    }
    fn empty_proof() -> ZkAmsAdmissionProofWireV1 {
        ZkAmsAdmissionProofWireV1 {
            version: PROOF_VERSION_V1,
            relation: empty_relation(),
        }
    }
    #[test]
    fn admission_batch_rejects_every_mixed_governance_and_epoch_lineage() {
        type PublicInputMutation = (&'static str, fn(&mut ZkAmsAdmissionPublicInputV1));
        let canonical = coherent_two_anchor_batch();
        validate_batch(&canonical, canonical.len()).expect("coherent two-anchor lineage");
        let mutations: [PublicInputMutation; 11] = [
            ("issuer-key-x", |row| row.issuer_key_x[31] ^= 1),
            ("issuer-key-y", |row| row.issuer_key_y[31] ^= 1),
            ("issuer-key-prefix", |row| row.issuer_key_prefix ^= 1),
            ("issuer-id", |row| row.issuer_id[31] ^= 1),
            ("policy-id", |row| row.policy_id[31] ^= 1),
            ("issuer-policy-record", |row| {
                row.issuer_policy_record_digest[31] ^= 1;
            }),
            ("registry-id", |row| row.registry_id[31] ^= 1),
            ("registry-record", |row| {
                row.registry_record_digest[31] ^= 1;
            }),
            ("policy-digest", |row| row.policy_digest[31] ^= 1),
            ("current-epoch", |row| {
                row.current_registry_epoch += 1;
                row.next_registry_epoch += 1;
            }),
            ("next-epoch", |row| {
                row.current_registry_epoch -= 1;
                row.next_registry_epoch -= 1;
            }),
        ];
        for (label, mutate) in mutations {
            let mut adversarial = canonical;
            mutate(&mut adversarial[1]);
            assert_eq!(
                validate_batch(&adversarial, adversarial.len()),
                Err(ZkAmsAdmissionRelationErrorV1::InconsistentBatchLineage),
                "mixed {label} lineage must fail before proof work"
            );
        }
    }
    #[test]
    fn public_prover_and_verifier_reject_nonzero_action_index_before_work() {
        let mut invalid = proof_context();
        invalid.action_index = 1;
        let fixture = admission_assignment_fixture();
        let witness = fixture.witness();
        assert_eq!(
            prove_zk_ams_admission_relation_v1(
                &invalid,
                core::slice::from_ref(&fixture.public),
                core::slice::from_ref(&witness),
                ZkAmsMaskedProverConfigV1::new(1).expect("one worker"),
                &mut NeverRandom,
            ),
            Err(ZkAmsAdmissionRelationErrorV1::InvalidContext),
        );
        assert_eq!(
            verify_zk_ams_admission_relation_v1(
                &invalid,
                core::slice::from_ref(&fixture.public),
                &[],
            ),
            Err(ZkAmsAdmissionRelationErrorV1::InvalidContext),
        );
    }
    #[test]
    fn every_mkhe_release_gate_fails_compilation_independently() {
        let all_ready = ZkAmsMkheReadinessV1 {
            parameter_gate: true,
            security_gate: true,
            noise_gate: true,
            resource_gate: true,
            wire_gate: true,
            malicious_party_gate: true,
            decryption_share_gate: true,
            packing_gate: true,
            phase23_gate: true,
            receipt_capability_gate: true,
            receipt_capability_blocker_mask: 0,
            release_kat_gate: true,
        };
        assert!(compiled_profile_digest_for_readiness_v1(all_ready).is_ok());
        for gate in 0..12 {
            let mut adversarial = all_ready;
            match gate {
                0 => adversarial.parameter_gate = false,
                1 => adversarial.security_gate = false,
                2 => adversarial.noise_gate = false,
                3 => adversarial.resource_gate = false,
                4 => adversarial.wire_gate = false,
                5 => adversarial.malicious_party_gate = false,
                6 => adversarial.decryption_share_gate = false,
                7 => adversarial.packing_gate = false,
                8 => adversarial.phase23_gate = false,
                9 => adversarial.receipt_capability_gate = false,
                10 => adversarial.receipt_capability_blocker_mask = 1,
                11 => adversarial.release_kat_gate = false,
                _ => unreachable!("the release has exactly twelve readiness conditions"),
            }
            assert_eq!(
                compiled_profile_digest_for_readiness_v1(adversarial),
                Err(ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile),
                "gate {gate} must independently prevent profile compilation"
            );
        }
    }
    #[test]
    fn unavailable_mkhe_release_has_no_public_prove_or_verify_bypass() {
        assert_eq!(
            zk_ams_compiled_profile_digest_v1(),
            Err(ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile)
        );
        let context = proof_context();
        let fixture = admission_assignment_fixture();
        let witness = fixture.witness();
        assert_eq!(
            prove_zk_ams_admission_relation_v1(
                &context,
                core::slice::from_ref(&fixture.public),
                core::slice::from_ref(&witness),
                ZkAmsMaskedProverConfigV1::new(1).expect("one worker"),
                &mut NeverRandom,
            ),
            Err(ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile)
        );
        assert_eq!(
            verify_zk_ams_admission_relation_v1(
                &context,
                core::slice::from_ref(&fixture.public),
                &[],
            ),
            Err(ZkAmsAdmissionRelationErrorV1::InvalidCompiledProfile)
        );
    }
    #[test]
    fn admission_batch_rejects_duplicate_anchors_and_broken_ordering() {
        let canonical = coherent_two_anchor_batch();
        let mut duplicate_credential = canonical;
        duplicate_credential[1].phc_hash = duplicate_credential[0].phc_hash;
        assert_eq!(
            validate_batch(&duplicate_credential, duplicate_credential.len()),
            Err(ZkAmsAdmissionRelationErrorV1::DuplicateCredentialDigest)
        );
        let mut duplicate_seed = canonical;
        duplicate_seed[1].seed_public_key = duplicate_seed[0].seed_public_key;
        assert_eq!(
            validate_batch(&duplicate_seed, duplicate_seed.len()),
            Err(ZkAmsAdmissionRelationErrorV1::DuplicateSeedPublicKey)
        );
        let mut broken_root_chain = canonical;
        broken_root_chain[1].prior_registry_root = [0x74; 32];
        assert_eq!(
            validate_batch(&broken_root_chain, broken_root_chain.len()),
            Err(ZkAmsAdmissionRelationErrorV1::InvalidPublicInput)
        );
        let mut repeated_index = canonical;
        repeated_index[1].anchor_index = 0;
        assert_eq!(
            validate_batch(&repeated_index, repeated_index.len()),
            Err(ZkAmsAdmissionRelationErrorV1::InvalidPublicInput)
        );
        let mut false_batch_size = canonical;
        false_batch_size[1].batch_size = 1;
        assert_eq!(
            validate_batch(&false_batch_size, false_batch_size.len()),
            Err(ZkAmsAdmissionRelationErrorV1::InvalidPublicInput)
        );
    }
    #[test]
    fn admission_batch_bounds_and_unsatisfied_witness_errors_are_exact() {
        assert_eq!(
            validate_batch(&[], 0),
            Err(ZkAmsAdmissionRelationErrorV1::InvalidBatchSize { actual: 0 })
        );
        let canonical = coherent_two_anchor_batch();
        assert_eq!(
            validate_batch(&canonical, 1),
            Err(ZkAmsAdmissionRelationErrorV1::InvalidBatchSize {
                actual: canonical.len(),
            })
        );
        let oversized_len = MAX_MASKED_RELAXED_STRICT_INSTANCES_V1 + 1;
        let oversized_batch_size = u32::try_from(oversized_len).expect("bounded hostile batch");
        let mut oversized = vec![canonical[0]; oversized_len];
        for (index, row) in oversized.iter_mut().enumerate() {
            row.batch_size = oversized_batch_size;
            row.anchor_index = u32::try_from(index).expect("bounded hostile index");
        }
        assert_eq!(
            validate_batch(&oversized, oversized.len()),
            Err(ZkAmsAdmissionRelationErrorV1::InvalidBatchSize {
                actual: MAX_MASKED_RELAXED_STRICT_INSTANCES_V1 + 1,
            })
        );
        assert_eq!(
            map_composition_error(MaskedRelaxedErrorV1::UnsatisfiedWitness),
            ZkAmsAdmissionRelationErrorV1::InvalidWitness,
            "attacker-controlled witness failure must not be reported as profile drift"
        );
        assert_eq!(
            map_circuit_synthesis_error(CircuitError::InvalidAssignment),
            MaskedRelaxedErrorV1::UnsatisfiedWitness,
            "attacker-controlled synthesis failures must not be reported as profile drift"
        );
        for error in [
            R1csError::CsrStorageOverflow,
            R1csError::CsrStorageAllocation,
            R1csError::CsrEntryCountMismatch,
        ] {
            assert_eq!(
                map_circuit_synthesis_error(CircuitError::R1cs(error)),
                MaskedRelaxedErrorV1::InvalidProfile,
                "canonical CSR construction failures are profile failures"
            );
        }
    }
    #[test]
    fn admission_decoder_preflights_oversized_and_forged_nested_counts() {
        let dimensions = synthetic_dimensions();
        let point = VegaPointWireV1::from_raw_bytes_for_test([1; 33]);
        let mut proof = empty_proof();
        proof.relation.mask_witness_commitment.points =
            vec![point; MASKED_RELAXED_COMMITMENT_COLUMNS_V1 + 1];
        let encoded = norito::codec::encode_adaptive(&proof);
        let limits = dimensions
            .proof_decode_limits(
                1,
                encoded.len(),
                MAX_ZK_AMS_ADMISSION_RELATION_PROOF_BYTES_V1,
            )
            .expect("released relation limits");
        assert!(matches!(
            norito::codec::decode_exact_from_slice_with_limits::<ZkAmsAdmissionProofWireV1>(
                &encoded, limits
            ),
            Err(norito::Error::SequenceLengthExceeded {
                length: 1_025,
                limit: 1_024
            })
        ));
        let encoded_count = 1_025_u32.to_le_bytes();
        let count_offset = encoded
            .windows(encoded_count.len())
            .rposition(|window| window == encoded_count)
            .expect("oversized nested count is present in canonical wire");
        let mut forged = encoded;
        forged[count_offset..count_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let limits = dimensions
            .proof_decode_limits(
                1,
                forged.len(),
                MAX_ZK_AMS_ADMISSION_RELATION_PROOF_BYTES_V1,
            )
            .expect("released relation limits");
        let forged_error = norito::codec::decode_exact_from_slice_with_limits::<
            ZkAmsAdmissionProofWireV1,
        >(&forged, limits)
        .expect_err("forged nested count must fail before allocation");
        assert!(
            matches!(forged_error, norito::Error::SequenceLengthExceeded { length, limit }
                if length == u64::from(u32::MAX)
                    && limit <= MAX_ZK_AMS_ADMISSION_RELATION_PROOF_BYTES_V1 as u64
                    && limit < length),
            "unexpected forged-count rejection: {forged_error:?}"
        );
    }
    #[test]
    fn admission_decoder_rejects_truncation_trailing_and_alternate_layout() {
        let proof = empty_proof();
        let canonical = norito::codec::encode_adaptive(&proof);
        let decode = |bytes: &[u8]| {
            let limits = synthetic_dimensions()
                .proof_decode_limits(1, bytes.len(), MAX_ZK_AMS_ADMISSION_RELATION_PROOF_BYTES_V1)
                .expect("released relation limits");
            norito::codec::decode_exact_from_slice_with_limits::<ZkAmsAdmissionProofWireV1>(
                bytes, limits,
            )
        };
        assert_eq!(decode(&canonical).expect("canonical wire"), proof);
        assert!(decode(&canonical[..canonical.len() - 1]).is_err());
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
        let mut alternate = Vec::new();
        {
            let flags =
                norito::core::default_encode_flags() & !norito::core::header_flags::COMPACT_LEN;
            let _flags = norito::core::DecodeFlagsGuard::enter(flags);
            norito::core::serialize_to_buffer(&proof, &mut alternate)
                .expect("encode alternate length layout");
        }
        assert_ne!(alternate, canonical);
        assert!(decode(&alternate).is_err());
    }
    #[test]
    fn admission_assignment_accepts_low_s_and_rejects_malleability_and_rebinding() {
        // Independent P-256 arithmetic fixture: private key 7, nonce 11. The
        // high-s signature below is the valid `n-s` counterpart and uses `-R`,
        // so only the canonical low-s constraint distinguishes the two.
        let fixture = admission_assignment_fixture();
        let low_s = synthesize_fixture(&fixture);
        assert!(
            assignment_is_satisfied(&low_s),
            "canonical low-s admission assignment must satisfy every constraint"
        );
        for public_index in [PHC_HASH_WORD_START, NEXT_ROOT_WORD_START] {
            let mut rebound_public = low_s.public_inputs.clone();
            rebound_public[public_index] += Scalar::one();
            assert!(
                low_s
                    .shape
                    .validate_strict_assignment(&low_s.witness, &rebound_public)
                    .is_err(),
                "mutating a statement-bound public value must fail"
            );
        }
        drop(low_s);
        let mut high_s_fixture = fixture.clone();
        high_s_fixture.signature_s =
            hex!("f92928529542bb27f2420825f5e986954abea34c926a24dc0ae4108bacac853b");
        high_s_fixture.recovery_y =
            hex!("6f66df64333b375edb37bc505b0b3975f6f2fb26a16776251d07110317d5c8bf");
        assert!(
            synthesize_admission_with_shape(
                high_s_fixture.public,
                &high_s_fixture.witness(),
                canonical_shape().expect("canonical fixture shape"),
            )
            .is_err(),
            "the algebraically valid high-s counterpart must fail canonical synthesis"
        );
        let mut changed_witness = fixture;
        changed_witness.subject_commitment[0] ^= 1;
        assert!(
            synthesize_admission_with_shape(
                changed_witness.public,
                &changed_witness.witness(),
                canonical_shape().expect("canonical fixture shape"),
            )
            .is_err(),
            "a hidden PHC-field mutation must fail canonical synthesis"
        );
    }
}
