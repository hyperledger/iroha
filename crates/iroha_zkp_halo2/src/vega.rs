//! Native field and curve adapters for the pinned Microsoft Vega profile.
//!
//! Vega's canonical engine uses the T256 group. Its scalar field is exactly
//! the P-256 base field, which lets the mDL circuit ingest issuer-key
//! coordinates without non-native reduction. This module keeps that identity
//! explicit and exposes only canonical, non-reducing encodings to callers.
//!
//! The protocol source is Microsoft `vega-prover` commit
//! `c0ee259053cd12eaf43ed71b5cde375452b3ee4d`, licensed under MIT.
pub use crate::vega_constants::*;
use core::{
    fmt,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use halo2curves::{
    ff::{Field, FromUniformBytes, PrimeField},
    t256::Fq,
};
use thiserror::Error;
#[path = "vega/algebra.rs"]
mod algebra;
#[path = "vega/bulletproof_t256.rs"]
mod bulletproof_t256;
#[path = "vega/canonical_mc_exact.rs"]
mod canonical_mc;
#[path = "vega/circuit.rs"]
mod circuit;
#[path = "vega/commitment.rs"]
mod commitment;
#[path = "vega/curve.rs"]
mod curve;
#[path = "vega/date.rs"]
mod date;
#[path = "vega/engine.rs"]
mod engine;
#[path = "vega/figure9.rs"]
mod figure9;
#[path = "vega/figure9_layout.rs"]
mod figure9_layout;
#[path = "vega/hyrax.rs"]
mod hyrax;
#[path = "vega/masked_relaxed.rs"]
mod masked_relaxed;
#[path = "vega/microsoft_mc.rs"]
mod microsoft_mc;
#[path = "vega/nifs.rs"]
mod nifs;
#[path = "vega/p256.rs"]
mod p256;
#[path = "vega/r1cs.rs"]
mod r1cs;
#[cfg(feature = "bench")]
#[path = "vega/secret_msm_timing.rs"]
mod secret_msm_timing;
#[path = "vega/sha256.rs"]
mod sha256;
#[cfg(feature = "bench")]
#[doc(hidden)]
pub use secret_msm_timing::run_vega_secret_msm_timing_screen;
#[path = "vega/spartan.rs"]
mod spartan;
#[path = "vega/sponge.rs"]
mod sponge;
#[path = "vega/sumcheck.rs"]
mod sumcheck;
#[path = "vega/transcript.rs"]
mod transcript;
#[path = "vega/wire.rs"]
mod wire;
#[path = "vega/zk_ams.rs"]
mod zk_ams;
pub(super) use curve::{
    VEGA_T256_BASE_MODULUS_BE_V1, VegaCurveError, VegaT256PointV1, derive_t256_generators_v1,
};
pub use engine::{
    MAX_VEGA_PROVER_WORKERS_V1, VEGA_EXISTING_CREDENTIAL_PROTOCOL_LABEL_V1,
    VEGA_INTERNAL_TRANSCRIPT_PERSONA_V1, VEGA_MDL_ACTION_INDEX_V1,
    VEGA_MDL_CANONICAL_RELATION_DIGEST_V1, VEGA_MDL_CANONICAL_VERIFIER_DIGEST_V1,
    VEGA_MDL_COMPILED_PROFILE_DIGEST_V1, VEGA_MDL_COMPILED_PROFILE_MANIFEST_V1,
    VEGA_MDL_MC_STEP_COUNT_V1, VegaMdlProofContextV1, VegaMdlProofDimensionsV1,
    VegaMdlProofErrorV1, VegaMdlProverConfigV1, VegaRandomSourceErrorV1, VegaRandomSourceV1,
    install_vega_mdl_figure9_prover_artifacts_v1, install_vega_mdl_figure9_verifier_key_v1,
    prove_vega_mdl_figure9_v1, vega_mdl_canonical_relation_digest_v1,
    vega_mdl_compiled_profile_digest_v1, vega_mdl_proof_dimensions_v1, vega_mdl_verifier_digest_v1,
    verify_vega_mdl_figure9_v1,
};
pub use figure9::{
    VEGA_MDL_FIGURE9_PUBLIC_INPUTS_V1, VegaMdlFigure9ErrorV1, VegaMdlFigure9WitnessV1,
    validate_vega_mdl_figure9_encoding_v1, validate_vega_mdl_figure9_relation_v1,
};
pub use masked_relaxed::{MaskedRelaxedRandomErrorV1, MaskedRelaxedRandomSourceV1};
pub(super) use transcript::{VegaTranscriptError, VegaTranscriptV1};
pub(super) use wire::{VegaPointWireV1, VegaScalarWireV1};
pub use zk_ams::RnsNativeProofDigestV1;
#[cfg(test)]
pub use zk_ams::ZK_AMS_MKHE_CPK_ERROR_MEMBERSHIP_WIRE_BYTES_V1;
#[cfg(test)]
pub use zk_ams::ZkAmsMkheDirectObjectKindV1;
pub use zk_ams::ZkAmsMkheRnsNativeTerminalRootsV1;
pub use zk_ams::{
    MAX_ZK_AMS_ADMISSION_RELATION_PROOF_BYTES_V1, ZK_AMS_ACTION_INDEX_V1,
    ZK_AMS_ADMISSION_PUBLIC_INPUTS_V1, ZK_AMS_PHC_CANONICAL_PAYLOAD_BYTES_V1,
    ZkAmsAdmissionPublicInputV1, ZkAmsAdmissionRelationDimensionsV1, ZkAmsAdmissionRelationErrorV1,
    ZkAmsAdmissionRelationWitnessV1, ZkAmsMaskedProverConfigV1,
    ZkAmsMkheRnsNativeRepeatableSourceSnapshotV1, ZkAmsMkheRnsNativeSecretChunkV1,
    ZkAmsMkheRnsNativeSourceArenaV1, ZkAmsMkheRnsNativeSourceErrorV1,
    ZkAmsMkheRnsNativeSourceLayoutV1, ZkAmsMkheRnsNativeSourceProviderV1,
    ZkAmsMkheRnsNativeSourceSnapshotV1, ZkAmsMkheRnsNativeSourceWriterV1, ZkAmsProofContextV1,
    prove_zk_ams_admission_relation_v1, verify_zk_ams_admission_relation_v1,
    zk_ams_admission_relation_dimensions_v1, zk_ams_compiled_profile_digest_v1,
    zk_ams_mkhe_readiness_v1, zk_ams_mkhe_rns_native_profile_v1,
    zk_ams_mkhe_rns_native_topology_v1, zk_ams_t256_generator_digest_v1,
};
#[cfg(test)]
pub use zk_ams::{
    ZK_AMS_MKHE_CPK_SECRET_MEMBERSHIP_WIRE_BYTES_V1,
    ZK_AMS_MKHE_DECRYPTION_SPLIT_MANIFEST_BYTES_V1,
    ZK_AMS_MKHE_DECRYPTION_SPLIT_RELEASE_KAT_DIGEST_V1,
    ZK_AMS_MKHE_DECRYPTION_STREAMING_RESIDENCY_CERTIFICATE_DIGEST_V1,
    ZK_AMS_MKHE_EVIDENCE_CHUNK_BYTES_V1, ZK_AMS_MKHE_MAX_PROOF_BYTES_V1,
    ZK_AMS_MKHE_RELEASE_KAT_EVIDENCE_BYTES_V1, ZK_AMS_MKHE_RESOURCE_EVIDENCE_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_CENTERED_CAPACITY_BITS_V1,
    ZK_AMS_MKHE_RNS_NATIVE_CORRELATED_FRI_MAX_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_CROSS_FIELD_POINT_COUNT_V1, ZK_AMS_MKHE_RNS_NATIVE_FAMILY_COUNT_V1,
    ZK_AMS_MKHE_RNS_NATIVE_FAMILY_ORDER_V1, ZK_AMS_MKHE_RNS_NATIVE_FRI_ROUNDS_V1,
    ZK_AMS_MKHE_RNS_NATIVE_HEADROOM_BITS_V1,
    ZK_AMS_MKHE_RNS_NATIVE_INITIAL_MULTIPROOF_MAX_BYTES_V1, ZK_AMS_MKHE_RNS_NATIVE_IO_MAX_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_LDE_DOMAIN_LOG2_V1, ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1,
    ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1, ZK_AMS_MKHE_RNS_NATIVE_MODULUS_BITS_V1,
    ZK_AMS_MKHE_RNS_NATIVE_NEGACYCLIC_ROOTS_V1, ZK_AMS_MKHE_RNS_NATIVE_OPENING_COUNT_V1,
    ZK_AMS_MKHE_RNS_NATIVE_PROFILE_MANIFEST_BYTES_V1, ZK_AMS_MKHE_RNS_NATIVE_PROOF_MAX_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_QPCS_MAX_BYTES_V1, ZK_AMS_MKHE_RNS_NATIVE_QUERY_COUNT_V1,
    ZK_AMS_MKHE_RNS_NATIVE_QUOTIENT_BITS_V1, ZK_AMS_MKHE_RNS_NATIVE_RADIX_LOG2_V1,
    ZK_AMS_MKHE_RNS_NATIVE_RESIDUAL_BITS_V1, ZK_AMS_MKHE_RNS_NATIVE_RLWE_EQUATION_COUNT_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_MAIN_BLOCKS_PER_OPENING_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_MAIN_FILE_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_MAIN_PLAINTEXT_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_MAIN_SLOTS_V1, ZK_AMS_MKHE_RNS_NATIVE_SOURCE_NONCE_FILE_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_NONCE_PLAINTEXT_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_NONCE_SLOTS_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SOURCE_TOTAL_FILE_BYTES_V1, ZK_AMS_MKHE_RNS_NATIVE_SOURCE_VERSION_V1,
    ZK_AMS_MKHE_RNS_NATIVE_SPOOL_MAX_BYTES_V1, ZK_AMS_MKHE_RNS_NATIVE_SUMCHECK_ROUNDS_V1,
    ZK_AMS_MKHE_RNS_NATIVE_TARGET_SECURITY_BITS_V1, ZK_AMS_MKHE_RNS_NATIVE_WIDE_RESPONSE_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1, ZK_AMS_MKHE_RNS_NATIVE_WORKSPACE_MAX_BYTES_V1,
    ZK_AMS_MKHE_WIRE_EVIDENCE_BYTES_V1, ZK_AMS_PHASE3_MAX_TERMINAL_PROOF_BYTES_V1,
    ZK_AMS_PHASE23_FRESHNESS_CERTIFIES_HIDDEN_MASK_SHARES_V1,
    ZK_AMS_PHASE23_FRESHNESS_COMMIT_WIRE_BYTES_V1, ZK_AMS_PHASE23_FRESHNESS_RECEIPT_WIRE_BYTES_V1,
    ZK_AMS_PHASE23_FRESHNESS_REVEAL_WIRE_BYTES_V1, ZK_AMS_PHASE23_MAX_CANONICAL_SPARSE_ENTRIES_V1,
    ZK_AMS_PHASE23_RELEASE_ERROR_COMMITMENT_ROWS_V1, ZK_AMS_PHASE23_RELEASE_MAP_SET_KAT_DIGEST_V1,
    ZK_AMS_PHASE23_RELEASE_PUBLIC_INPUT_COUNT_V1,
    ZK_AMS_PHASE23_RELEASE_WITNESS_COMMITMENT_ROWS_V1, ZK_AMS_T256_GALOIS_KEY_COUNT_V1,
    ZK_AMS_T256_GALOIS_KEY_SCHEDULE_DIGEST_V1, ZK_AMS_T256_MAX_LOGICAL_VALUES_V1,
    ZK_AMS_T256_RELEASE_PACKED_INPUT_KAT_DIGEST_V1,
    ZK_AMS_T256_RELEASE_PACKED_OUTPUT_KAT_DIGEST_V1,
    ZK_AMS_T256_RELEASE_PACKING_NEGATIVE_CASE_COUNT_V1,
    ZK_AMS_T256_RELEASE_PACKING_NEGATIVE_KAT_DIGEST_V1,
    ZK_AMS_T256_RELEASE_ROTATION_CERTIFICATE_KAT_DIGEST_V1,
    ZK_AMS_T256_RELEASE_TRANSFORMED_RNS_KAT_DIGEST_V1, ZkAmsMkheAbortReasonV1,
    ZkAmsMkheActiveCollectivePublicKeyStatementV1, ZkAmsMkheActiveCollectivePublicKeyWitnessV1,
    ZkAmsMkheActiveContributionV1, ZkAmsMkheActivePartySecretV1,
    ZkAmsMkheActiveRkgLinearProofSecurityV1, ZkAmsMkheActiveRkgProofV1,
    ZkAmsMkheActiveRoundReceiptV1, ZkAmsMkheActiveRoundV1, ZkAmsMkheAdmittedCpkPartyV1,
    ZkAmsMkheAuthenticationWireV1, ZkAmsMkheCksContributionWireV1, ZkAmsMkheCksProofV1,
    ZkAmsMkheCksResourceEvidenceV1, ZkAmsMkheCollectiveCiphertextWireV1,
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
    ZkAmsMkheDecryptionProofViewV1, ZkAmsMkheDecryptionResourceEvidenceV1,
    ZkAmsMkheDecryptionStreamingResidencyEvidenceV1, ZkAmsMkheDecryptionStreamingSnapshotV1,
    ZkAmsMkheDecryptionTransportComponentKindV1, ZkAmsMkheDecryptionTransportManifestV1,
    ZkAmsMkheDecryptionTransportPointerV1, ZkAmsMkheDirectAdmittedContributionSetV1,
    ZkAmsMkheDirectCeremonyContextV1, ZkAmsMkheDirectCeremonyRoundV1, ZkAmsMkheDirectCoordinatorV1,
    ZkAmsMkheDirectEvaluatedKeySetAdmissionV1, ZkAmsMkheDirectEvaluatedKeyTargetV1,
    ZkAmsMkheDirectNoiseCertificateV1, ZkAmsMkheDirectNoiseIntegrationCertificateV1,
    ZkAmsMkheDirectPolynomialRoleV1, ZkAmsMkheDirectPolynomialStreamReceiptV1,
    ZkAmsMkheDirectPolynomialStreamV1, ZkAmsMkheDirectProofAuditV1,
    ZkAmsMkheDirectResourceCertificateV1, ZkAmsMkheDirectVerifiedContributionProviderV1,
    ZkAmsMkheDirectVerifiedContributionV1, ZkAmsMkheErrorV1, ZkAmsMkheEvaluatedKeySorafsPointerV1,
    ZkAmsMkheFinalizedCpkCeremonyV1, ZkAmsMkheFullRosterDecryptionResultV1,
    ZkAmsMkheGovernedActiveRosterV1, ZkAmsMkheGovernedCollectiveKeyMaterialIdentityV1,
    ZkAmsMkheGovernedParticipantV1, ZkAmsMkheGovernedRosterWireV1, ZkAmsMkheIdentifiableAbortV1,
    ZkAmsMkheIdentifiableDecryptionAbortV1, ZkAmsMkheNoiseCertificateV1,
    ZkAmsMkheOwnedCollectiveCksDigitEvidenceV1, ZkAmsMkhePersistentDecryptionPartyUseV1,
    ZkAmsMkhePersistentDecryptionVerificationContextV1, ZkAmsMkhePreparedCollectivePublicAV1,
    ZkAmsMkheProofEnvelopeWireV1, ZkAmsMkheProofKindV1, ZkAmsMkheReadinessV1,
    ZkAmsMkheReleaseKatEvidenceV1, ZkAmsMkheReleaseManifestV1, ZkAmsMkheResourceCertificateV1,
    ZkAmsMkheResourceEvidenceV1, ZkAmsMkheRnsNativeFamilyV1, ZkAmsMkheRnsNativeProfileManifestV1,
    ZkAmsMkheRnsNativeProfileV1, ZkAmsMkheRnsNativeSourceReceiptV1, ZkAmsMkheRnsNativeTopologyV1,
    ZkAmsMkheRnsPolynomialWireV1, ZkAmsMkheRosterKeyProofV1, ZkAmsMkheSecurityAttackRecordV1,
    ZkAmsMkheSecurityAttackV1, ZkAmsMkheSecurityCandidateV1, ZkAmsMkheSecurityCertificateV1,
    ZkAmsMkheSecurityEstimatorSuiteV1, ZkAmsMkheSeekableEvaluatedKeyAccountingV1,
    ZkAmsMkheStagedDecryptionShareV1, ZkAmsMkheStreamingCollectiveAutomorphismAccountingV1,
    ZkAmsMkheStreamingCollectiveCiphertextV1, ZkAmsMkheStreamingCollectiveEncryptionKeyAuthorityV1,
    ZkAmsMkheStreamingDecryptionAuthorityV1, ZkAmsMkheStreamingDecryptionStatementV1,
    ZkAmsMkheStreamingFullRosterDecryptionResultV1, ZkAmsMkheTrustedCksContextV1,
    ZkAmsMkheTrustedSourceContextV1, ZkAmsMkheValidatedCollectiveEvaluatedKeyV1,
    ZkAmsMkheValidatedCollectiveSourceEvidenceReceiptV1,
    ZkAmsMkheVerifiedEvaluatedKeyEvidenceSetV1, ZkAmsMkheWireBindingV1, ZkAmsMkheWireEvidenceV1,
    ZkAmsPhase3BatchAnchorV1, ZkAmsPhase3FoldHistoryV1, ZkAmsPhase3GovernedBatchV1,
    ZkAmsPhase3TerminalContextV1, ZkAmsPhase3TerminalImplementationV1,
    ZkAmsPhase3TerminalProverOutputV1, ZkAmsPhase3TerminalReceiptV1,
    ZkAmsPhase23AccumulatorShapeV1, ZkAmsPhase23CommitmentPreimageLayoutV1,
    ZkAmsPhase23CrossTermCommitmentV1, ZkAmsPhase23EncryptedBindingV1,
    ZkAmsPhase23EncryptedImplementationV1, ZkAmsPhase23EquationCertificateV1,
    ZkAmsPhase23FreshnessCommitV1, ZkAmsPhase23FreshnessContextV1, ZkAmsPhase23FreshnessPhaseV1,
    ZkAmsPhase23FreshnessReceiptV1, ZkAmsPhase23FreshnessRevealV1, ZkAmsPhase23MapKindV1,
    ZkAmsPhase23MaterializedAccumulatorsV1, ZkAmsPhase23PendingRevealV1,
    ZkAmsPhase23PublicAccumulatorV1, ZkAmsPhase23PublicChallengeFamilyV1,
    ZkAmsPhase23PublicChallengeRoleV1, ZkAmsPhase23PublicChallengeV1,
    ZkAmsPhase23PublicFoldHistoryV1, ZkAmsPhase23PublicFoldRecordV1,
    ZkAmsPhase23ReleaseMapManifestV1, ZkAmsPhase23SparseMapManifestV1, ZkAmsPhase23SparseMapV1,
    ZkAmsPhase23StrictPublicInstanceV1, ZkAmsPhase23VerifiedCommitSetV1,
    ZkAmsT256GaloisKeyScheduleEntryV1, ZkAmsT256GaloisKeyScheduleV1, ZkAmsT256PackedPlaintextV1,
    ZkAmsT256PackingLayoutV1, ZkAmsT256ReleasePackingCertificateV1, ZkAmsT256RotationCertificateV1,
    ZkAmsT256RotationDirectionV1, ZkAmsT256RotationV1,
    admit_zk_ams_mkhe_direct_contribution_set_v1,
    automorphism_switch_zk_ams_mkhe_collective_streaming_v1, commit_zk_ams_phase23_freshness_v1,
    decode_zk_ams_t256_packed_plaintext_v1, encode_zk_ams_t256_packed_plaintext_v1,
    encrypt_zk_ams_mkhe_collective_packed_streaming_v1, finalize_zk_ams_phase23_freshness_v1,
    generate_zk_ams_mkhe_collective_party_state_with_prepared_public_a_v1,
    open_zk_ams_phase23_freshness_reveal_v1, permute_zk_ams_t256_slots_v1,
    prepare_zk_ams_mkhe_collective_public_a_v1, prove_zk_ams_mkhe_active_collective_public_key_v1,
    prove_zk_ams_mkhe_decryption_share_staged_v1, prove_zk_ams_phase3_terminal_v1,
    read_zk_ams_phase23_materialized_accumulators_canonical_exact_v1,
    rotate_zk_ams_t256_packed_plaintext_v1, validate_zk_ams_t256_galois_key_exponents_v1,
    validate_zk_ams_t256_galois_key_schedule_v1,
    verify_combine_decode_zk_ams_mkhe_decryption_streaming_v1,
    verify_zk_ams_mkhe_active_collective_public_key_v1,
    verify_zk_ams_mkhe_evaluated_key_evidence_set_v1, verify_zk_ams_phase3_terminal_v1,
    write_zk_ams_phase23_materialized_accumulators_canonical_v1,
    zk_ams_mkhe_active_collective_public_a_v1, zk_ams_mkhe_active_rkg_linear_proof_security_v1,
    zk_ams_mkhe_cks_resource_evidence_v1, zk_ams_mkhe_cks_statement_digest_v1,
    zk_ams_mkhe_collect_active_round_v1, zk_ams_mkhe_compact_key_switch_ring_multiplications_v1,
    zk_ams_mkhe_cpk_ceremony_residency_evidence_v1, zk_ams_mkhe_decryption_resource_evidence_v1,
    zk_ams_mkhe_decryption_streaming_residency_evidence_v1,
    zk_ams_mkhe_direct_noise_certificate_v1, zk_ams_mkhe_direct_noise_integration_certificate_v1,
    zk_ams_mkhe_direct_noise_integration_for_admitted_keys_v1, zk_ams_mkhe_direct_proof_audit_v1,
    zk_ams_mkhe_direct_resource_certificate_v1, zk_ams_mkhe_manifest_digest_v1,
    zk_ams_mkhe_noise_certificate_v1, zk_ams_mkhe_readiness_digest_v1,
    zk_ams_mkhe_release_kat_evidence_v1, zk_ams_mkhe_release_manifest_v1,
    zk_ams_mkhe_resource_certificate_digest_v1, zk_ams_mkhe_resource_certificate_v1,
    zk_ams_mkhe_resource_evidence_v1, zk_ams_mkhe_rns_native_profile_manifest_v1,
    zk_ams_mkhe_security_candidate_input_digest_v1, zk_ams_mkhe_security_candidate_v1,
    zk_ams_mkhe_security_certificate_v1, zk_ams_mkhe_seekable_evaluated_key_accounting_v1,
    zk_ams_mkhe_streaming_collective_automorphism_accounting_v1, zk_ams_mkhe_wire_evidence_v1,
    zk_ams_phase3_nifs_verifier_digest_v1, zk_ams_phase3_ordered_public_inputs_digest_v1,
    zk_ams_phase3_terminal_implementation_v1, zk_ams_phase23_cross_term_v1,
    zk_ams_phase23_encrypted_implementation_v1, zk_ams_phase23_equation_certificate_digest_v1,
    zk_ams_phase23_equation_certificate_v1, zk_ams_phase23_fold_linear_v1,
    zk_ams_phase23_fold_quadratic_v1, zk_ams_phase23_materialize_release_accumulator_chunks_v1,
    zk_ams_phase23_release_map_manifest_v1, zk_ams_phase23_release_map_set_digest_v1,
    zk_ams_t256_galois_key_schedule_v1, zk_ams_t256_packed_subfield_conjugation_exponent_v1,
    zk_ams_t256_packing_layout_v1, zk_ams_t256_release_packing_certificate_v1,
    zk_ams_t256_rotation_certificate_v1, zk_ams_t256_rotation_exponent_for_direction_v1,
    zk_ams_t256_rotation_exponent_v1, zk_ams_t256_rotation_key_plan_v1, zk_ams_t256_rotation_v1,
};
#[cfg(test)]
pub use zk_ams::{
    ZK_AMS_MKHE_DIRECT_OBJECT_POINTER_BYTES_V1, ZK_AMS_MKHE_DIRECT_OBJECT_READ_BYTES_V1,
    ZkAmsMkheDirectObjectCasPublicationV1, ZkAmsMkheDirectObjectPointerV1,
    ZkAmsMkheDirectObjectPublicationReceiptV1, ZkAmsMkheDirectObjectPublicationTransactionV1,
    ZkAmsMkheDirectObjectPublishedBindingV1, ZkAmsMkheDirectObjectReadAtProviderV1,
    ZkAmsMkheDirectObjectReadReceiptV1, ZkAmsMkheDirectObjectSealTokenV1,
    ZkAmsMkheDirectObjectStagingTokenV1, validate_zk_ams_mkhe_direct_object_v1,
};
#[cfg(test)]
pub use zk_ams::{
    ZK_AMS_MKHE_RNS_NATIVE_COMPOSITE_VERIFICATION_VERSION_V1,
    ZkAmsMkheRnsNativeCompositeCandidateReceiptV1, ZkAmsMkheRnsNativeCompositeVerificationErrorV1,
    ZkAmsMkheRnsNativeVerificationStageV1, verify_zk_ams_mkhe_rns_native_composite_v1,
};
#[cfg(test)]
pub use zk_ams::{
    ZK_AMS_MKHE_RNS_NATIVE_CROSS_FIELD_LOOKUP_SECTION_MAX_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_PROOF_ENVELOPE_HEADER_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_PROOF_ENVELOPE_MAX_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_PROOF_ENVELOPE_VERSION_V1,
    ZK_AMS_MKHE_RNS_NATIVE_PROOF_SECTION_COUNT_V1, ZK_AMS_MKHE_RNS_NATIVE_PROOF_SECTION_ORDER_V1,
    ZK_AMS_MKHE_RNS_NATIVE_RNS_RELATION_QPCS_SECTION_MAX_BYTES_V1,
    ZK_AMS_MKHE_RNS_NATIVE_TERMINAL_BRIDGE_SECTION_MAX_BYTES_V1, ZkAmsMkheRnsNativeProofEnvelopeV1,
    ZkAmsMkheRnsNativeProofSectionDescriptorV1, ZkAmsMkheRnsNativeProofSectionKindV1,
};
#[cfg(test)]
pub use zk_ams::{
    ZK_AMS_MKHE_RNS_NATIVE_QPCS_ROOT_COUNT_V1,
    ZK_AMS_MKHE_RNS_NATIVE_TRANSCRIPT_CHALLENGE_COUNT_V1,
    ZK_AMS_MKHE_RNS_NATIVE_TRANSCRIPT_VERSION_V1, ZkAmsMkheRnsNativeChallengeSeedsV1,
    ZkAmsMkheRnsNativeCommitmentsBoundTranscriptV1, ZkAmsMkheRnsNativeOpeningCommitmentV1,
    ZkAmsMkheRnsNativeOpeningCommitmentsV1, ZkAmsMkheRnsNativePublicContextV1,
    ZkAmsMkheRnsNativeQpcsBoundTranscriptV1, ZkAmsMkheRnsNativeQpcsFriRootV1,
    ZkAmsMkheRnsNativeQpcsRootsV1, ZkAmsMkheRnsNativeTerminalBoundTranscriptV1,
    ZkAmsMkheRnsNativeTerminalBridgeV1, ZkAmsMkheRnsNativeTranscriptErrorV1,
    ZkAmsMkheRnsNativeTranscriptV1,
};
#[cfg(test)]
pub use zk_ams::{
    ZK_AMS_MKHE_RNS_NATIVE_SECTION_CODEC_VERSION_V1,
    ZkAmsMkheRnsNativeCrossFieldGlobalLookupSectionV1, ZkAmsMkheRnsNativeRnsRelationQpcsSectionV1,
    ZkAmsMkheRnsNativeSectionCodecErrorV1, ZkAmsMkheRnsNativeTerminalBridgeSectionV1,
};
pub use zk_ams::{
    ZkAmsMkheCksNoiseInputV1, ZkAmsMkheFailureAllocationV1, ZkAmsMkheNoiseAccountingV1,
    ZkAmsMkheNoiseAdmissionV1, ZkAmsMkheNoiseConstructionV1, ZkAmsMkheNoiseFeasibilityV1,
    ZkAmsMkhePhaseNoiseBoundsV1, ZkAmsMkheSmudgePurposeV1, ZkAmsMkheSmudgeQueriesV1,
    ZkAmsMkheTerminalFeasibilityV1, zk_ams_mkhe_noise_feasibility_v1,
};
#[cfg(test)]
pub use zk_ams::{
    ZkAmsMkheCollectiveCiphertextV1, ZkAmsMkheCollectiveLevelOneV1, ZkAmsMkheCollectivePublicKeyV1,
};
/// Tight first-release cap for one canonical Norito Vega proof.
///
/// A 512 KiB ceiling leaves room for the exact 368-byte Figure 9 relation and Norito framing while
/// preventing this engine from inheriting the much broader per-action opaque-byte allowance.
pub const MAX_VEGA_PROOF_BYTES_V1: usize = 512 * 1024;
/// Big-endian modulus of the canonical T256 scalar field.
///
/// This is also the base-field modulus of NIST P-256.
pub const VEGA_T256_SCALAR_MODULUS_BE_V1: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];
struct ZeroizingVegaScalarBytesV1([u8; 32]);
impl Drop for ZeroizingVegaScalarBytesV1 {
    fn drop(&mut self) {
        let bytes = core::hint::black_box(&mut self.0);
        bytes.fill(0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(&mut *bytes);
    }
}
/// Failure while translating canonical Vega field material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum VegaFieldError {
    /// The supplied big-endian integer is not smaller than the T256 scalar modulus.
    #[error("integer is not a canonical T256 scalar")]
    NonCanonicalScalar,
    /// The zero scalar does not have a multiplicative inverse.
    #[error("cannot invert the zero T256 scalar")]
    InversionOfZero,
}
/// Canonical T256 scalar used by Vega public inputs and proof-system algebra.
///
/// Construction is deliberately non-reducing: byte strings at or above the modulus are rejected
/// rather than silently mapped into the field. Secret scalars must be converted to explicit wire
/// types before crossing a serialization boundary:
///
/// ```compile_fail
/// use iroha_zkp_halo2::vega::VegaT256ScalarV1;
/// use norito::codec::Encode as _;
///
/// let secret = VegaT256ScalarV1::from_u64(42);
/// let _encoded = secret.encode();
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VegaT256ScalarV1(Fq);
impl VegaT256ScalarV1 {
    /// Return the additive identity.
    #[must_use]
    pub const fn zero() -> Self {
        Self(Fq::ZERO)
    }
    /// Return the multiplicative identity.
    #[must_use]
    pub const fn one() -> Self {
        Self(Fq::ONE)
    }
    /// Parse one canonical 32-byte big-endian scalar without modular reduction.
    ///
    /// # Errors
    ///
    /// Returns [`VegaFieldError::NonCanonicalScalar`] when `bytes` represents
    /// an integer greater than or equal to the scalar modulus.
    pub fn from_be_bytes_exact(bytes: [u8; 32]) -> Result<Self, VegaFieldError> {
        Self::from_be_bytes_exact_ref(&bytes)
    }
    /// Parse a borrowed canonical big-endian scalar while wiping the sole
    /// little-endian representation scratch on every exit.
    pub(crate) fn from_be_bytes_exact_ref(bytes: &[u8; 32]) -> Result<Self, VegaFieldError> {
        if bytes >= &VEGA_T256_SCALAR_MODULUS_BE_V1 {
            return Err(VegaFieldError::NonCanonicalScalar);
        }
        // `halo2curves` 0.9 exposes the P-256 base-field representation in
        // little-endian order. Keep that implementation detail behind this
        // explicitly big-endian Vega boundary.
        let mut repr = ZeroizingVegaScalarBytesV1(*bytes);
        repr.0.reverse();
        let value = Option::<Fq>::from(Fq::from_repr(repr.0.into()))
            .ok_or(VegaFieldError::NonCanonicalScalar)?;
        Ok(Self(value))
    }
    /// Parse one canonical 32-byte little-endian proof scalar without modular reduction.
    ///
    /// # Errors
    ///
    /// Returns [`VegaFieldError::NonCanonicalScalar`] when `bytes` represents
    /// an integer greater than or equal to the scalar modulus.
    pub fn from_le_bytes_exact(mut bytes: [u8; 32]) -> Result<Self, VegaFieldError> {
        bytes.reverse();
        Self::from_be_bytes_exact(bytes)
    }
    /// Reduce an exact 64-byte little-endian uniform string as specified by
    /// the pinned Vega Fiat--Shamir transcript.
    #[must_use]
    pub fn from_uniform_le_bytes(bytes: [u8; 64]) -> Self {
        Self::from_uniform_le_bytes_ref(&bytes)
    }
    /// Reduce a borrowed exact 64-byte little-endian uniform string.
    ///
    /// Secret-entropy owners should use this form so scalar reduction does not
    /// first create an unmanaged by-value copy of their zeroized buffer.
    #[must_use]
    pub fn from_uniform_le_bytes_ref(bytes: &[u8; 64]) -> Self {
        Self(Fq::from_uniform_bytes(bytes))
    }
    /// Construct a scalar from an unsigned 64-bit integer.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        Self(Fq::from(value))
    }
    /// Return the exact canonical 32-byte big-endian representation.
    #[must_use]
    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut bytes: [u8; 32] = self.0.to_repr().into();
        bytes.reverse();
        bytes
    }
    /// Return the exact canonical 32-byte little-endian proof encoding.
    #[must_use]
    pub fn to_le_bytes(self) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        self.write_le_bytes_ref(&mut bytes);
        bytes
    }
    /// Write a borrowed scalar directly into a caller-owned canonical
    /// little-endian proof-encoding slot.
    fn write_le_bytes_ref(&self, destination: &mut [u8; 32]) {
        *destination = self.0.to_repr().into();
    }
    /// Return whether this field element is zero.
    #[must_use]
    pub fn is_zero(self) -> bool {
        bool::from(self.0.is_zero())
    }
    /// Return the multiplicative inverse.
    ///
    /// # Errors
    ///
    /// Returns [`VegaFieldError::InversionOfZero`] for the additive identity.
    pub fn inverse(self) -> Result<Self, VegaFieldError> {
        Option::<Fq>::from(self.0.invert())
            .map(Self)
            .ok_or(VegaFieldError::InversionOfZero)
    }
    /// Square this scalar.
    #[must_use]
    pub fn square(self) -> Self {
        Self(self.0.square())
    }
    /// Replace this scalar instance with exact zero using a safe best-effort wipe.
    ///
    /// This scalar is [`Copy`]; callers must separately clear every independent copy that contains
    /// secret material. Rust also does not guarantee erasure of compiler-created temporaries.
    pub fn clear_secret(&mut self) {
        *self = Self::zero();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(&mut *self);
    }
}
impl Default for VegaT256ScalarV1 {
    fn default() -> Self {
        Self::zero()
    }
}
impl Add for VegaT256ScalarV1 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}
impl AddAssign for VegaT256ScalarV1 {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}
impl Sub for VegaT256ScalarV1 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}
impl SubAssign for VegaT256ScalarV1 {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}
impl Mul for VegaT256ScalarV1 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}
impl MulAssign for VegaT256ScalarV1 {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 *= rhs.0;
    }
}
impl Neg for VegaT256ScalarV1 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}
impl fmt::Debug for VegaT256ScalarV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VegaT256ScalarV1(REDACTED)")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use halo2curves::ff::PrimeField;
    #[test]
    fn t256_scalar_modulus_is_exactly_the_p256_base_modulus() {
        assert_eq!(
            Fq::MODULUS,
            "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
        );
        let mut below = VEGA_T256_SCALAR_MODULUS_BE_V1;
        below[31] -= 1;
        let parsed = VegaT256ScalarV1::from_be_bytes_exact(below).expect("q - 1 is canonical");
        assert_eq!(parsed.to_be_bytes(), below);
        assert_eq!(
            VegaT256ScalarV1::from_be_bytes_exact(VEGA_T256_SCALAR_MODULUS_BE_V1),
            Err(VegaFieldError::NonCanonicalScalar)
        );
        assert_eq!(
            VegaT256ScalarV1::from_be_bytes_exact([0xff; 32]),
            Err(VegaFieldError::NonCanonicalScalar)
        );
    }
    #[test]
    fn t256_scalar_big_endian_boundary_does_not_reduce() {
        for value in [0_u64, 1, 255, 256, u32::MAX.into(), u64::MAX] {
            let scalar = VegaT256ScalarV1::from_u64(value);
            let mut expected = [0_u8; 32];
            expected[24..].copy_from_slice(&value.to_be_bytes());
            assert_eq!(scalar.to_be_bytes(), expected);
            assert_eq!(VegaT256ScalarV1::from_be_bytes_exact(expected), Ok(scalar));
        }
    }
    #[test]
    fn t256_scalar_clear_secret_replaces_nonzero_with_exact_zero() {
        let mut secret = VegaT256ScalarV1::from_be_bytes_exact([0x5a; 32])
            .expect("fixture is below the T256 scalar modulus");
        assert!(!secret.is_zero());
        secret.clear_secret();
        assert!(secret.is_zero());
        assert_eq!(secret, VegaT256ScalarV1::zero());
        assert_eq!(secret.to_be_bytes(), [0; 32]);
    }
    #[test]
    fn t256_scalar_debug_does_not_expose_secret_material() {
        let secret = VegaT256ScalarV1::from_u64(0x0123_4567_89ab_cdef);
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "VegaT256ScalarV1(REDACTED)");
        assert!(!rendered.contains("0123456789abcdef"));
    }
}
