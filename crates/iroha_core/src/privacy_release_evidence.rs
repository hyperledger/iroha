//! Deterministic, non-shipping native privacy release evidence.
//!
//! This module is deliberately behind the non-default `privacy-release-evidence` feature. It is
//! compiled only into explicit release runners and opt-in integration gates, never into `irohad`.
//! The deterministic entropy below is suitable only for reproducible release fixtures; neither its
//! seed nor any witness byte is exposed by the public evidence types. Canonical proof bytes do
//! cross the release-evidence boundary so release gates can authenticate, persist, and
//! exact-compare what production verified.
/// Pure governed final Kaigi proof fixtures; ledger installation belongs to signed network instructions.
#[cfg(feature = "zk-halo2")]
pub mod kaigi;
mod network_actions;
mod retained_native;
mod vega;
mod zk_x509;
pub use network_actions::{
    PrivacyReleaseAnonymousPgcNetworkActionV1, PrivacyReleaseBootleLanternNetworkActionV1,
    PrivacyReleaseFcmpNetworkActionV1, PrivacyReleaseIvmPrivateNoteNetworkActionV1,
    PrivacyReleaseJindoNetworkActionV1, PrivacyReleaseOrchardNetworkActionV1,
    PrivacyReleasePqMaspNetworkActionsV1, PrivacyReleaseTransactionContextV1,
    PrivacyReleaseVeRangeNetworkActionV1, PrivacyReleaseVegaNetworkActionV1,
    PrivacyReleaseZkAceNetworkActionV1, build_privacy_release_anonymous_pgc_network_action_v1,
    build_privacy_release_bootle_lantern_network_action_v1,
    build_privacy_release_fcmp_network_action_v1,
    build_privacy_release_ivm_private_note_network_action_v1,
    build_privacy_release_jindo_network_action_v1, build_privacy_release_orchard_network_action_v1,
    build_privacy_release_pq_masp_network_actions_v1, build_privacy_release_vega_network_action_v1,
    build_privacy_release_verange_network_action_v1,
    build_privacy_release_zk_ace_network_action_v1,
};
use retained_native::{run_ivm_private_note_stage_v1, run_pq_masp_stage_v1};
#[cfg(test)]
use vega::{
    VEGA_RELEASE_ACTION_INDEX_V1, VEGA_RELEASE_CREATION_TIME_MS_V1, VEGA_RELEASE_NONCE_V1,
    VEGA_RELEASE_TRUSTED_TIMESTAMP_MS_V1, refresh_vega_device_authentication_digest_v1,
    require_vega_release_production_native_rejection_v1, vega_release_fixture_v1,
    vega_release_transaction_context_v1, verify_vega_release_production_envelope_v1,
};
use vega::{
    VEGA_RELEASE_MC_MAX_CIRCUIT_VARIABLES_V1, VEGA_RELEASE_MC_RELAXED_SUMCHECK_ROUNDS_V1,
    VEGA_RELEASE_MC_TOTAL_APP_CONSTRAINTS_V1, run_vega_stage_v1,
};
use zk_x509::run_zk_x509_stage_v1;
pub use zk_x509::{
    PrivacyReleaseZkX509NetworkActionsV1, PrivacyReleaseZkX509ResourceCertificateV1,
    PrivacyReleaseZkX509ResourceEnvironmentV1, PrivacyReleaseZkX509ResourceObservationV1,
    PrivacyReleaseZkX509ResourceProcessLimitsV1, PrivacyReleaseZkX509SemanticReplayV1,
    build_privacy_release_zk_x509_network_actions_v1,
    build_privacy_release_zk_x509_resource_certificate_v1,
    build_privacy_release_zk_x509_semantic_replay_v1, privacy_release_expectation_capture_open_v1,
    privacy_release_expectation_fixture_matches_v1, privacy_release_process_profile_v1,
    privacy_release_zk_x509_resource_certificate_matches_source_v1,
    privacy_release_zk_x509_resource_environment_v1,
    validate_privacy_release_zk_x509_resource_capture_v1,
};
#[cfg(test)]
use zk_x509::{
    ZK_X509_RELEASE_PUBLIC_MATERIAL_DOMAIN_V1, zk_x509_release_public_statement_material_v1,
};
fn release_network_id_from_genesis_hash(hash: [u8; 32]) -> iroha_data_model::NetworkId {
    iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
        iroha_data_model::block::BlockHeader,
    >::from_untyped_unchecked(Hash::prehashed(
        hash,
    )))
}
use crate::privacy_engines::{
    anonymous_pgc::{
        AnonymousPgcParametersV1, AnonymousPgcPoolInvariantV1, TwistedElGamalCiphertextV1,
        TwistedElGamalKeyPairV1, TwistedElGamalPublicKeyV1,
        bootstrap::{
            AnonymousPgcBootstrapStatementV1, AnonymousPgcBootstrapWitnessV1,
            MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1, PGC_BOOTSTRAP_INITIAL_EPOCH_V1, prove_bootstrap,
            verify_bootstrap_encoded,
        },
        decrypt_u32, encrypt_with_randomness,
        payment::{
            AnonymousPgcPaymentStatementV1, AnonymousPgcPaymentWitnessV1,
            MAX_PGC_PAYMENT_PROOF_BYTES_V1, PGC_PAYMENT_MAX_RECIPIENTS_V1,
            encrypt_signed_with_randomness, prove_payment, verify_payment_encoded,
        },
    },
    bootle_lantern::{
        codec::PROOF_BYTES_V1 as BOOTLE_PROOF_BYTES_V1,
        issuer::{
            BootleLanternBlindIssuanceResponseV1, BootleLanternFileIssuanceStoreV1,
            BootleLanternIssuanceAuthorizationV1, BootleLanternIssuanceStoreConfigV1,
            BootleLanternIssuerKeyPairV1, BootleLanternIssuerPolicyMetadataV1,
            holder_finalize_blind_issuance_v1, holder_prepare_blind_issuance_with_rng_v1,
            issuer_authorize_blind_issuance_with_rng_v1,
            issuer_blind_issue_once_encoded_with_rng_v1,
        },
        prove_bound_presentation_v1, verify_bound_presentation_encoded_v1,
    },
    fcmp_plus_plus::{
        FCMP_MAX_INPUTS_NATIVE_V1, FCMP_MAX_OUTPUTS_NATIVE_V1, FCMP_MAX_PROOF_WIRE_BYTES_V1,
        FCMP_MAX_TREE_LAYERS_V1, FCMP_MIN_PROOF_WIRE_BYTES_V1, FCMP_PROOF_INPUT_BYTES_V1,
        FCMP_PROOF_WIRE_HEADER_BYTES_V1, FcmpOutputTupleV1, FcmpProofInputPublicV1, FcmpTreeRootV1,
        build_fcmp_frontier_v1, prove_fcmp_plus_plus_v1,
        release_evidence_access::{fcmp_release_fixture_v1, fcmp_release_invalid_path_fixture_v1},
        verify_fcmp_transaction_v1,
    },
    ivm_private_note::{
        IVM_PRIVATE_NOTE_MAX_PROOF_BYTES_V1, PRIVATE_NOTE_MAX_INPUTS_V1,
        PRIVATE_NOTE_MAX_OUTPUTS_V1, PRIVATE_NOTE_TREE_DEPTH_V1,
        ivm_private_note_release_fixture_v1, ivm_private_note_release_invalid_path_fixture_v1,
        prove_ivm_private_note_v1_with_rng, verify_ivm_private_note_v1,
    },
    jindo::{
        JINDO_MAX_BATCH_SIZE_V1, JINDO_MAX_COEFFICIENTS_V1, JINDO_NATIVE_PROOF_BYTES_V1,
        JINDO_RING_DEGREE_V1, JindoPrivacyActionTransactionContextV1, JindoPrivacyActionWitnessV1,
        jindo_crs_digest_v1, prepare_jindo_privacy_action_with_rng_v1,
        verify_batched_evaluation_v1,
    },
    orchard::{
        MerklePath, Note, ORCHARD_MAX_ACTIONS_V1, ORCHARD_TREE_DEPTH_V1, OrchardBundleDraftV1,
        OrchardBundlePublicV1, OrchardChangeProverInputV1, OrchardSpendProverInputV1, Scope,
        SpendingKey, authorize_orchard_bundle_v1, orchard_authorization_wire_size_v1,
        orchard_empty_root_v1, prepare_orchard_bundle_v1_with_rng, verify_orchard_bundle_v1,
    },
    p256::{SecretScalarV1, TranscriptBindingV1},
    pq_masp::{
        PQ_MASP_AUTHORIZATION_HEADER_BYTES_V1, PQ_MASP_INPUT_BOUND_V1,
        PQ_MASP_MAX_AUTHORIZATION_PROOF_BYTES_V1, PQ_MASP_OUTPUT_BOUND_V1, PQ_MASP_TREE_DEPTH_V1,
        pq_masp_release_fixture_v1, pq_masp_release_invalid_path_fixture_v1,
        pq_masp_release_successor_replay_fixture_v1, prove_pq_masp_v1_with_rng, verify_pq_masp_v1,
    },
    vega::{
        VEGA_MDL_PUBLIC_INPUT_COUNT_V1, VEGA_PRIVACY_ACTION_INDEX_V1, VegaMdlConsensusBindingV1,
        VegaMdlWitnessV1, VegaPrivacyActionPublicInputV1, VegaPrivacyActionTransactionContextV1,
        VegaPrivacyActionWitnessMaterialV1, derive_device_authentication_digest_v1,
        prepare_vega_privacy_action_with_rng_v1, prove_mdl_figure9_v1, verify_mdl_figure9_v1,
    },
    verange::{
        MAX_VERANGE_TYPE1_BATCH_COMMITMENTS_V1, MAX_VERANGE_TYPE1_BATCH_PROOF_BYTES_V1,
        VeRangeBitLengthV1, VeRangeParametersV1, VeRangeType1BatchStatementV1, commit, prove_batch,
        verify_batch_encoded,
    },
    zk_ace::{
        ZK_ACE_PRIVACY_MAX_PROOF_BYTES_V1, ZkAcePrivacyWitnessV1, prove_zk_ace_privacy_v1_with_rng,
        verify_zk_ace_privacy_v1,
    },
    zk_ace_stark::{
        FRI_ROUNDS as ZK_ACE_FRI_ROUNDS_V1, QUERY_COUNT as ZK_ACE_QUERY_COUNT_V1,
        TRACE_LOG2 as ZK_ACE_TRACE_LOG2_V1,
    },
    zk_ams::{
        MAX_ZK_AMS_BATCH_ADMISSION_PROOF_BYTES_V1, MAX_ZK_AMS_LSAG_PROOF_BYTES_V1,
        ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1, ZK_AMS_MAX_RING_SIZE_V1, ZK_AMS_MIN_RING_SIZE_V1,
        ZK_AMS_PRIVACY_ACTION_INDEX_V1, ZkAmsBatchCredentialWitnessV1,
        ZkAmsPreparedPrivacyActionV1, ZkAmsPrivacyActionEffectV1, ZkAmsPrivacyActionGovernanceV1,
        ZkAmsPrivacyActionTransactionContextV1, ZkAmsSeedSecretV1,
        prepare_zk_ams_batch_admission_privacy_action_with_rng_v1,
        prepare_zk_ams_provision_account_transaction_intent_v1,
        prepare_zk_ams_provision_privacy_action_with_rng_v1,
        sign_prepared_zk_ams_privacy_action_v1,
        validate_zk_ams_privacy_action_transaction_intent_v1, verify_zk_ams_batch_admission_v1,
        verify_zk_ams_provision_statement_v1, zk_ams_batch_admission_adversarial_wires_v1,
        zk_ams_generator_digest_v1, zk_ams_key_image_v1, zk_ams_registry_transition_root_v1,
        zk_ams_seed_public_key_v1,
    },
    zk_x509::{
        engine::{prove_zk_x509_credential_proof_v1_with_rng, verify_zk_x509_credential_proof_v1},
        profile::{
            ZK_X509_MAX_CHAIN_DEPTH_V1, ZK_X509_MAX_CRL_ENTRIES_V1,
            ZK_X509_MAXIMUM_ENCODED_X5S1_BYTES_V1, ZK_X509_PROVER_ADDRESS_SPACE_CEILING_BYTES_V1,
            ZK_X509_PROVER_PEAK_MEMORY_BYTES_V1, ZK_X509_PROVER_TARGET_SECONDS_V1,
        },
        relation::release_fixture::{
            ZkX509ReleaseResourceShapeV1, build_zk_x509_release_fixture_v1,
        },
    },
};
use crate::{
    privacy_profiles::{CompiledPrivacyProfileV1, compiled_privacy_profile_v1},
    privacy_state::{PrivacyZkX509AuthoritativeStateV1, compute_privacy_pgc_account_state_root_v1},
    privacy_verifier::{
        PrivacyVerificationContextV1, PrivacyVerificationErrorV1, PrivacyZkX509VerificationStateV1,
        VerifiedPrivacyLedgerEffectsV1, VerifiedZkX509CertificateEffectV1,
        validate_vega_authoritative_issuer_binding_v1, verify_privacy_envelope_v1,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use core::{
    fmt,
    mem::size_of,
    num::{NonZeroU32, NonZeroU64},
    time::Duration,
};
use incrementalmerkletree::{Hashable as _, Level};
use iroha_crypto::{Algorithm, Hash, KeyPair};
pub use iroha_data_model::privacy::{
    PrivacyExact12FixtureErrorV1, PrivacyExact12TypedEnvelopeRowV1,
    privacy_exact12_matrix_bytes_v1, privacy_exact12_typed_envelope_rows_v1,
};
use iroha_data_model::{
    isi::privacy::SubmitPrivacyProofV1,
    prelude::{AccountId, AssetDefinitionId, NetworkId},
    privacy::{
        BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1, BOOTLE_LANTERN_MAX_ALLOWED_VALUES_PER_ATTRIBUTE_V1,
        BOOTLE_LANTERN_MAX_DISCLOSED_ATTRIBUTES_V1, BootleLanternAllowedAttributeValuesV1,
        BootleLanternAttributeValueV1, BootleLanternDisclosedAttributeV1,
        IrohaBootleLanternAnoncredStatementV1, IrohaZkAmsProofV1, IrohaZkAmsStatementV1,
        IrohaZkX509StarkP256StatementV1, OrchardHalo2ActionsStatementV1, PrivacyActiveLifecycleV1,
        PrivacyChallengeV1, PrivacyConsensusLimitsV1, PrivacyCredentialDocumentTypeV1,
        PrivacyEngineIdV1, PrivacyIssuerIdV1, PrivacyJindoFieldElementV1, PrivacyNamespaceScopeV1,
        PrivacyNamespaceV1, PrivacyNativeConsensusBindingV1, PrivacyOrchardActionV1,
        PrivacyP256CiphertextV1, PrivacyP256PointV1, PrivacyParameterIdV1,
        PrivacyPgcAccountBootstrapV1, PrivacyPgcAccountV1, PrivacyPgcBootstrapProofBytesV1,
        PrivacyPolicyDigestV1, PrivacyPolicyIdV1, PrivacyPoolIdV1, PrivacyPoolNamespaceV1,
        PrivacyProofBytesV1, PrivacyProofEnvelopeV1, PrivacyProofSystemIdV1, PrivacyProofV1,
        PrivacyProtocolActivationLimitsV1, PrivacyProtocolActivationRecordV1, PrivacyProtocolIdV1,
        PrivacyProtocolLifecycleV1, PrivacyRootV1, PrivacySessionTranscriptDigestV1,
        PrivacyStatementContextV1, PrivacyStatementV1, PrivacyTransactionIntentDigestV1,
        PrivacyValueBalanceDirectionV1, PrivacyValueBalanceV1, PrivacyVegaIssuerRecordLifecycleV1,
        PrivacyVegaIssuerRecordV1, PrivacyVegaMdlDateV1, PrivacyVegaMdlDigestAlgorithmV1,
        PrivacyVegaMdlNamespaceV1, PrivacyVegaMdlSignatureAlgorithmV1, PrivacyZkAmsActionV1,
        PrivacyZkAmsAdmissionAnchorV1, PrivacyZkAmsBatchAdmissionV1, PrivacyZkAmsCredentialNonceV1,
        PrivacyZkAmsKeyImageV1, PrivacyZkAmsPersonhoodCredentialV1, PrivacyZkAmsProvisionAccountV1,
        PrivacyZkAmsRegistryIdV1, PrivacyZkAmsRegistryRecordDigestV1, PrivacyZkAmsSeedPublicKeyV1,
        PrivacyZkAmsSubjectCommitmentV1, TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1,
        VegaExistingCredentialStatementV1, ZK_AMS_PHC_VERSION_V1,
        ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1, ZkAcePqAuthorizationStatementV1,
        zk_ams_issuer_policy_record_digest_v1, zk_ams_registry_record_digest_v1,
    },
    transaction::{FeePaymentIntent, TransactionBuilder, TransactionPayload},
    zk::{ZkAcePrivacyPublicInputsV1, derive_zk_ace_privacy_authorization_digest},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_zkp_halo2::vega::{
    MAX_VEGA_PROOF_BYTES_V1, VegaMdlProverConfigV1, ZkAmsMaskedProverConfigV1,
    vega_mdl_proof_dimensions_v1,
};
use norito::{
    codec::{Decode, Encode},
    derive::{JsonDeserialize, JsonSerialize},
};
use orchard::{
    keys::FullViewingKey,
    note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho},
    tree::MerkleHashOrchard,
    value::NoteValue,
};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, signature::hazmat::PrehashSigner as _,
};
use p256::elliptic_curve::PrimeField as _;
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core_06::{CryptoRng, Error as RngError06, RngCore};
use sha2::{Digest, Sha256};
/// Evidence schema version. Any incompatible change requires a new version.
pub const PRIVACY_RELEASE_EVIDENCE_SCHEMA_VERSION_V1: u16 = 1;
/// Four mandatory stages for each protocol in the exact-12 registry.
pub const PRIVACY_RELEASE_CASE_COUNT_V1: usize = 4;
/// Exact eagerly initialized Rayon worker count for every isolated stage.
pub const PRIVACY_RELEASE_RAYON_THREAD_COUNT_V1: u16 = 4;
/// Exact stack allocation for every isolated-stage thread.
pub const PRIVACY_RELEASE_STAGE_STACK_BYTES_V1: usize = 8 * 1024 * 1024;
/// Exact number of mandatory first-release evidence stages.
pub const PRIVACY_RELEASE_STAGE_COUNT_V1: usize =
    PrivacyProtocolIdV1::COUNT * PRIVACY_RELEASE_CASE_COUNT_V1;
/// Largest ordered proof-artifact collection admitted by one release stage.
pub const PRIVACY_RELEASE_MAX_PROOF_ARTIFACTS_V1: usize = 2;
/// Exact number of proof artifacts in the complete exact-12 evidence matrix.
///
/// There is one artifact per stage plus a second, state-lineage artifact for
/// both positive/maximum anonymous-PGC stages and all four ZK-AMS stages.
pub const PRIVACY_RELEASE_PROOF_ARTIFACT_COUNT_V1: usize = PRIVACY_RELEASE_STAGE_COUNT_V1 + 6;
/// Canonical protocol-specific process profile for one isolated release stage.
///
/// Resident-set and virtual-address-space ceilings describe different
/// operating-system bounds. A fixed profile carries both so the release runner
/// cannot substitute a broader or narrower `RLIMIT_AS` containment limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivacyReleaseProcessProfileV1 {
    /// Protocol whose isolated stages must use this exact profile.
    pub protocol_id: PrivacyProtocolIdV1,
    /// Exact wall-clock ceiling for one stage, in milliseconds.
    pub elapsed_ceiling_millis: u64,
    /// Exact resident-set high-water ceiling for one stage, in bytes.
    pub peak_rss_ceiling_bytes: u64,
    /// Exact virtual-address-space containment ceiling for one stage, in bytes.
    pub address_space_ceiling_bytes: u64,
}
/// Failure to establish the one immutable release-evidence Rayon topology.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivacyReleaseRayonPoolErrorV1 {
    /// Another caller initialized the process-global pool, or a worker could
    /// not be created. Either condition makes the release topology ambiguous.
    InitializationRejected,
    /// The calling stage leader was already executing as a Rayon worker.
    LeaderIsWorker,
    /// The initialized pool did not expose the exact four-worker width.
    WorkerCountMismatch,
    /// Not every exact worker reached the post-initialization barrier once.
    WorkerBarrierMismatch,
}
impl fmt::Display for PrivacyReleaseRayonPoolErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InitializationRejected => {
                "release Rayon global pool was already initialized or could not start"
            }
            Self::LeaderIsWorker => "release stage leader is already a Rayon worker",
            Self::WorkerCountMismatch => "release Rayon pool has a noncanonical worker count",
            Self::WorkerBarrierMismatch => {
                "release Rayon workers did not reach the exact initialization barrier"
            }
        })
    }
}
impl std::error::Error for PrivacyReleaseRayonPoolErrorV1 {}
/// Initialize and attest the one process-global pool used by release proofs.
///
/// This must be the first Rayon operation in a freshly executed hidden stage. A second call fails
/// closed even when the first call used the correct width, preventing a caller from treating an
/// inherited or preinitialized pool as canonical. Successful return proves that all four distinct
/// workers reached a barrier and that the stage leader is outside the worker set.
pub fn initialize_privacy_release_rayon_pool_v1() -> Result<(), PrivacyReleaseRayonPoolErrorV1> {
    let expected_threads = usize::from(PRIVACY_RELEASE_RAYON_THREAD_COUNT_V1);
    rayon::ThreadPoolBuilder::new()
        .num_threads(expected_threads)
        .stack_size(PRIVACY_RELEASE_STAGE_STACK_BYTES_V1)
        .build_global()
        .map_err(|_| PrivacyReleaseRayonPoolErrorV1::InitializationRejected)?;
    if rayon::current_thread_index().is_some() {
        return Err(PrivacyReleaseRayonPoolErrorV1::LeaderIsWorker);
    }
    if rayon::current_num_threads() != expected_threads {
        return Err(PrivacyReleaseRayonPoolErrorV1::WorkerCountMismatch);
    }
    let mut worker_indices = rayon::broadcast(|context| context.index());
    worker_indices.sort_unstable();
    if worker_indices != (0..expected_threads).collect::<Vec<_>>() {
        return Err(PrivacyReleaseRayonPoolErrorV1::WorkerBarrierMismatch);
    }
    Ok(())
}
/// Global outer fail-closed ceiling for any one proof artifact declared by evidence.
///
/// The widening conversion is lossless and intentionally binds release
/// evidence to the same consensus constant used by Taira action admission.
/// Protocol-local canonical decoder ceilings may be strictly smaller.
pub const PRIVACY_RELEASE_MAX_PROOF_ARTIFACT_BYTES_V1: u64 =
    TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1 as u64;
/// Maximum total canonical proof bytes in a complete exact-12 evidence matrix.
pub const PRIVACY_RELEASE_MAX_TOTAL_PROOF_ARTIFACT_BYTES_V1: u64 =
    match PRIVACY_RELEASE_MAX_PROOF_ARTIFACT_BYTES_V1
        .checked_mul(PRIVACY_RELEASE_PROOF_ARTIFACT_COUNT_V1 as u64)
    {
        Some(total) => total,
        None => panic!("privacy release aggregate proof-byte ceiling overflow"),
    };
/// Mandatory evidence cases, in canonical per-protocol order.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::privacy_release_evidence::PrivacyReleaseCaseKindV1")]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    JsonSerialize,
    JsonDeserialize,
)]
#[norito(
    tag = "case",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum PrivacyReleaseCaseKindV1 {
    /// A canonical public statement is proved and independently verified.
    PositiveCanonicalEndToEnd,
    /// A structurally valid semantic public-input mutation rejects the proof.
    PublicStatementBindingMutation,
    /// Header corruption, interior corruption, and exact truncation all reject.
    ProofCorruptionAndTruncation,
    /// The closed first-release maximum relation shape is proved and verified.
    MaximumShapeResource,
}
impl PrivacyReleaseCaseKindV1 {
    /// Every mandatory case in frozen order.
    pub const ALL: [Self; PRIVACY_RELEASE_CASE_COUNT_V1] = [
        Self::PositiveCanonicalEndToEnd,
        Self::PublicStatementBindingMutation,
        Self::ProofCorruptionAndTruncation,
        Self::MaximumShapeResource,
    ];
    /// Exact stable case label used by release artifacts and child invocation.
    #[must_use]
    pub const fn canonical_label(self) -> &'static str {
        match self {
            Self::PositiveCanonicalEndToEnd => "positive-canonical-end-to-end",
            Self::PublicStatementBindingMutation => "public-statement-binding-mutation",
            Self::ProofCorruptionAndTruncation => "proof-corruption-and-truncation",
            Self::MaximumShapeResource => "maximum-shape-resource",
        }
    }
    /// Parse one exact case label. Aliases and case folding are rejected.
    #[must_use]
    pub const fn from_canonical_label(label: &str) -> Option<Self> {
        match label.as_bytes() {
            b"positive-canonical-end-to-end" => Some(Self::PositiveCanonicalEndToEnd),
            b"public-statement-binding-mutation" => Some(Self::PublicStatementBindingMutation),
            b"proof-corruption-and-truncation" => Some(Self::ProofCorruptionAndTruncation),
            b"maximum-shape-resource" => Some(Self::MaximumShapeResource),
            _ => None,
        }
    }
}
/// One frozen coordinate in the exact first-release evidence schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivacyReleaseStageCoordinateV1 {
    /// Exact zero-based position in the 48-stage schedule.
    pub stage_ordinal: u16,
    /// Protocol exercised at this position.
    pub protocol_id: PrivacyProtocolIdV1,
    /// Evidence case exercised at this position.
    pub case_kind: PrivacyReleaseCaseKindV1,
}
const fn privacy_release_stage_coordinate_v1(
    stage_ordinal: u16,
    protocol_id: PrivacyProtocolIdV1,
    case_kind: PrivacyReleaseCaseKindV1,
) -> PrivacyReleaseStageCoordinateV1 {
    PrivacyReleaseStageCoordinateV1 {
        stage_ordinal,
        protocol_id,
        case_kind,
    }
}
/// Sole explicit declaration of the canonical 48-stage release schedule.
///
/// The declaration is intentionally written out rather than reconstructed at runtime.
/// `validate_privacy_release_stage_coordinates_v1` independently derives the protocol-by-case
/// product from the closed enums and rejects any drift in this frozen list.
pub const PRIVACY_RELEASE_STAGE_COORDINATES_V1: [PrivacyReleaseStageCoordinateV1;
    PRIVACY_RELEASE_STAGE_COUNT_V1] = [
    privacy_release_stage_coordinate_v1(
        0,
        PrivacyProtocolIdV1::ZkAcePqAuthorizationV1,
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd,
    ),
    privacy_release_stage_coordinate_v1(
        1,
        PrivacyProtocolIdV1::ZkAcePqAuthorizationV1,
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation,
    ),
    privacy_release_stage_coordinate_v1(
        2,
        PrivacyProtocolIdV1::ZkAcePqAuthorizationV1,
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation,
    ),
    privacy_release_stage_coordinate_v1(
        3,
        PrivacyProtocolIdV1::ZkAcePqAuthorizationV1,
        PrivacyReleaseCaseKindV1::MaximumShapeResource,
    ),
    privacy_release_stage_coordinate_v1(
        4,
        PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd,
    ),
    privacy_release_stage_coordinate_v1(
        5,
        PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation,
    ),
    privacy_release_stage_coordinate_v1(
        6,
        PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation,
    ),
    privacy_release_stage_coordinate_v1(
        7,
        PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
        PrivacyReleaseCaseKindV1::MaximumShapeResource,
    ),
    privacy_release_stage_coordinate_v1(
        8,
        PrivacyProtocolIdV1::VeRangeTransparentRangeV1,
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd,
    ),
    privacy_release_stage_coordinate_v1(
        9,
        PrivacyProtocolIdV1::VeRangeTransparentRangeV1,
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation,
    ),
    privacy_release_stage_coordinate_v1(
        10,
        PrivacyProtocolIdV1::VeRangeTransparentRangeV1,
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation,
    ),
    privacy_release_stage_coordinate_v1(
        11,
        PrivacyProtocolIdV1::VeRangeTransparentRangeV1,
        PrivacyReleaseCaseKindV1::MaximumShapeResource,
    ),
    privacy_release_stage_coordinate_v1(
        12,
        PrivacyProtocolIdV1::IrohaZkAmsV1,
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd,
    ),
    privacy_release_stage_coordinate_v1(
        13,
        PrivacyProtocolIdV1::IrohaZkAmsV1,
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation,
    ),
    privacy_release_stage_coordinate_v1(
        14,
        PrivacyProtocolIdV1::IrohaZkAmsV1,
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation,
    ),
    privacy_release_stage_coordinate_v1(
        15,
        PrivacyProtocolIdV1::IrohaZkAmsV1,
        PrivacyReleaseCaseKindV1::MaximumShapeResource,
    ),
    privacy_release_stage_coordinate_v1(
        16,
        PrivacyProtocolIdV1::VegaExistingCredentialZkV1,
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd,
    ),
    privacy_release_stage_coordinate_v1(
        17,
        PrivacyProtocolIdV1::VegaExistingCredentialZkV1,
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation,
    ),
    privacy_release_stage_coordinate_v1(
        18,
        PrivacyProtocolIdV1::VegaExistingCredentialZkV1,
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation,
    ),
    privacy_release_stage_coordinate_v1(
        19,
        PrivacyProtocolIdV1::VegaExistingCredentialZkV1,
        PrivacyReleaseCaseKindV1::MaximumShapeResource,
    ),
    privacy_release_stage_coordinate_v1(
        20,
        PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd,
    ),
    privacy_release_stage_coordinate_v1(
        21,
        PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation,
    ),
    privacy_release_stage_coordinate_v1(
        22,
        PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation,
    ),
    privacy_release_stage_coordinate_v1(
        23,
        PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
        PrivacyReleaseCaseKindV1::MaximumShapeResource,
    ),
    privacy_release_stage_coordinate_v1(
        24,
        PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1,
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd,
    ),
    privacy_release_stage_coordinate_v1(
        25,
        PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1,
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation,
    ),
    privacy_release_stage_coordinate_v1(
        26,
        PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1,
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation,
    ),
    privacy_release_stage_coordinate_v1(
        27,
        PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1,
        PrivacyReleaseCaseKindV1::MaximumShapeResource,
    ),
    privacy_release_stage_coordinate_v1(
        28,
        PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1,
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd,
    ),
    privacy_release_stage_coordinate_v1(
        29,
        PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1,
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation,
    ),
    privacy_release_stage_coordinate_v1(
        30,
        PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1,
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation,
    ),
    privacy_release_stage_coordinate_v1(
        31,
        PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1,
        PrivacyReleaseCaseKindV1::MaximumShapeResource,
    ),
    privacy_release_stage_coordinate_v1(
        32,
        PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd,
    ),
    privacy_release_stage_coordinate_v1(
        33,
        PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation,
    ),
    privacy_release_stage_coordinate_v1(
        34,
        PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation,
    ),
    privacy_release_stage_coordinate_v1(
        35,
        PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
        PrivacyReleaseCaseKindV1::MaximumShapeResource,
    ),
    privacy_release_stage_coordinate_v1(
        36,
        PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1,
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd,
    ),
    privacy_release_stage_coordinate_v1(
        37,
        PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1,
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation,
    ),
    privacy_release_stage_coordinate_v1(
        38,
        PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1,
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation,
    ),
    privacy_release_stage_coordinate_v1(
        39,
        PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1,
        PrivacyReleaseCaseKindV1::MaximumShapeResource,
    ),
    privacy_release_stage_coordinate_v1(
        40,
        PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd,
    ),
    privacy_release_stage_coordinate_v1(
        41,
        PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation,
    ),
    privacy_release_stage_coordinate_v1(
        42,
        PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation,
    ),
    privacy_release_stage_coordinate_v1(
        43,
        PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
        PrivacyReleaseCaseKindV1::MaximumShapeResource,
    ),
    privacy_release_stage_coordinate_v1(
        44,
        PrivacyProtocolIdV1::PqMaspStarkV1,
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd,
    ),
    privacy_release_stage_coordinate_v1(
        45,
        PrivacyProtocolIdV1::PqMaspStarkV1,
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation,
    ),
    privacy_release_stage_coordinate_v1(
        46,
        PrivacyProtocolIdV1::PqMaspStarkV1,
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation,
    ),
    privacy_release_stage_coordinate_v1(
        47,
        PrivacyProtocolIdV1::PqMaspStarkV1,
        PrivacyReleaseCaseKindV1::MaximumShapeResource,
    ),
];
const _: () = assert!(PRIVACY_RELEASE_STAGE_COUNT_V1 == 48);
/// Check a purported stage declaration against the independently derived
/// protocol-by-case enum product.
#[must_use]
pub fn validate_privacy_release_stage_coordinates_v1(
    coordinates: &[PrivacyReleaseStageCoordinateV1],
) -> bool {
    if coordinates.len() != PRIVACY_RELEASE_STAGE_COUNT_V1 {
        return false;
    }
    let mut index = 0_usize;
    for protocol_id in PrivacyProtocolIdV1::ALL {
        for case_kind in PrivacyReleaseCaseKindV1::ALL {
            let Some(coordinate) = coordinates.get(index) else {
                return false;
            };
            let Ok(stage_ordinal) = u16::try_from(index) else {
                return false;
            };
            if coordinate.stage_ordinal != stage_ordinal
                || coordinate.protocol_id != protocol_id
                || coordinate.case_kind != case_kind
            {
                return false;
            }
            index += 1;
        }
    }
    index == coordinates.len()
}
/// Stable classification of the expected verifier failure exercised by a successful evidence stage.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::privacy_release_evidence::PrivacyReleaseFailureClassV1")]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    JsonSerialize,
    JsonDeserialize,
)]
#[norito(
    tag = "failure_class",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum PrivacyReleaseFailureClassV1 {
    /// The positive or maximum-shape proof verified successfully.
    NotApplicable,
    /// A semantically bound, structurally valid public statement was rejected.
    PublicStatementBindingRejected,
    /// Header/interior corruption and a one-byte truncation were all rejected.
    CanonicalWireCorruptionAndTruncationRejected,
}
/// Closed numeric resource facts. Unit semantics are frozen in the protocol
/// descriptor; unbounded caller-selected labels are intentionally absent.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::privacy_release_evidence::PrivacyReleaseResourceFactsV1")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, JsonSerialize, JsonDeserialize)]
pub struct PrivacyReleaseResourceFactsV1 {
    /// Primary relation dimension actually exercised.
    pub primary_units: u64,
    /// Governed ceiling for `primary_units`.
    pub primary_ceiling: u64,
    /// Secondary relation dimension actually exercised.
    pub secondary_units: u64,
    /// Governed ceiling for `secondary_units`.
    pub secondary_ceiling: u64,
    /// Tree, circuit, or recursion depth actually exercised.
    pub relation_depth: u64,
    /// Governed ceiling for `relation_depth`.
    pub relation_depth_ceiling: u64,
}
impl PrivacyReleaseResourceFactsV1 {
    fn validate(&self) -> bool {
        self.primary_units > 0
            && self.primary_units <= self.primary_ceiling
            && self.secondary_units <= self.secondary_ceiling
            && self.relation_depth <= self.relation_depth_ceiling
    }
}
/// Return the frozen resource facts for one implemented release stage.
///
/// `None` is reserved for a protocol whose closed implementation does not define the selected
/// stage. Every exact-12 first-release coordinate has a frozen resource profile.
#[must_use]
pub fn privacy_release_resource_facts_v1(
    protocol_id: PrivacyProtocolIdV1,
    case_kind: PrivacyReleaseCaseKindV1,
) -> Option<PrivacyReleaseResourceFactsV1> {
    let maximum = case_kind == PrivacyReleaseCaseKindV1::MaximumShapeResource;
    let facts = match protocol_id {
        PrivacyProtocolIdV1::ZkAcePqAuthorizationV1 => PrivacyReleaseResourceFactsV1 {
            primary_units: ZK_ACE_RELEASE_TRACE_ROWS_V1,
            primary_ceiling: ZK_ACE_RELEASE_TRACE_ROWS_V1,
            secondary_units: ZK_ACE_RELEASE_QUERY_COUNT_V1,
            secondary_ceiling: ZK_ACE_RELEASE_QUERY_COUNT_V1,
            relation_depth: ZK_ACE_RELEASE_FRI_ROUNDS_V1,
            relation_depth_ceiling: ZK_ACE_RELEASE_FRI_ROUNDS_V1,
        },
        PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1 => PrivacyReleaseResourceFactsV1 {
            primary_units: if maximum { 64 } else { 16 },
            primary_ceiling: 64,
            secondary_units: if maximum {
                u64::try_from(PGC_PAYMENT_MAX_RECIPIENTS_V1).ok()?
            } else {
                2
            },
            secondary_ceiling: u64::try_from(PGC_PAYMENT_MAX_RECIPIENTS_V1).ok()?,
            relation_depth: 32,
            relation_depth_ceiling: 32,
        },
        PrivacyProtocolIdV1::VeRangeTransparentRangeV1 => PrivacyReleaseResourceFactsV1 {
            primary_units: if maximum { 8 } else { 1 },
            primary_ceiling: u64::try_from(MAX_VERANGE_TYPE1_BATCH_COMMITMENTS_V1).ok()?,
            secondary_units: if maximum { 64 } else { 32 },
            secondary_ceiling: 64,
            relation_depth: if maximum { 8 } else { 6 },
            relation_depth_ceiling: 8,
        },
        PrivacyProtocolIdV1::IrohaZkAmsV1 => {
            let ring_size = if maximum {
                ZK_AMS_MAX_RING_SIZE_V1
            } else {
                ZK_AMS_MIN_RING_SIZE_V1
            };
            let ring_size = u64::try_from(ring_size).ok()?;
            let batch_ceiling = u64::try_from(ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1).ok()?;
            PrivacyReleaseResourceFactsV1 {
                primary_units: ring_size,
                primary_ceiling: u64::try_from(ZK_AMS_MAX_RING_SIZE_V1).ok()?,
                secondary_units: batch_ceiling,
                secondary_ceiling: batch_ceiling,
                relation_depth: ring_size,
                relation_depth_ceiling: u64::try_from(ZK_AMS_MAX_RING_SIZE_V1).ok()?,
            }
        }
        PrivacyProtocolIdV1::VegaExistingCredentialZkV1 => PrivacyReleaseResourceFactsV1 {
            primary_units: VEGA_RELEASE_MC_TOTAL_APP_CONSTRAINTS_V1,
            primary_ceiling: VEGA_RELEASE_MC_TOTAL_APP_CONSTRAINTS_V1,
            secondary_units: VEGA_RELEASE_MC_MAX_CIRCUIT_VARIABLES_V1,
            secondary_ceiling: VEGA_RELEASE_MC_MAX_CIRCUIT_VARIABLES_V1,
            relation_depth: VEGA_RELEASE_MC_RELAXED_SUMCHECK_ROUNDS_V1,
            relation_depth_ceiling: VEGA_RELEASE_MC_RELAXED_SUMCHECK_ROUNDS_V1,
        },
        PrivacyProtocolIdV1::IrohaZkX509StarkP256V1 => PrivacyReleaseResourceFactsV1 {
            primary_units: if maximum {
                u64::try_from(ZK_X509_MAX_CHAIN_DEPTH_V1).ok()?
            } else {
                2
            },
            primary_ceiling: u64::try_from(ZK_X509_MAX_CHAIN_DEPTH_V1).ok()?,
            secondary_units: if maximum {
                u64::try_from(ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1).ok()?
            } else {
                1
            },
            secondary_ceiling: u64::try_from(ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1).ok()?,
            relation_depth: if maximum {
                u64::try_from(ZK_X509_MAX_CRL_ENTRIES_V1).ok()?
            } else {
                0
            },
            relation_depth_ceiling: u64::try_from(ZK_X509_MAX_CRL_ENTRIES_V1).ok()?,
        },
        PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1 => {
            let ring_degree = u64::try_from(JINDO_RING_DEGREE_V1).ok()?;
            PrivacyReleaseResourceFactsV1 {
                primary_units: u64::try_from(JINDO_MAX_BATCH_SIZE_V1).ok()?,
                primary_ceiling: u64::try_from(JINDO_MAX_BATCH_SIZE_V1).ok()?,
                secondary_units: if maximum {
                    u64::try_from(JINDO_MAX_COEFFICIENTS_V1).ok()?
                } else {
                    4
                },
                secondary_ceiling: u64::try_from(JINDO_MAX_COEFFICIENTS_V1).ok()?,
                relation_depth: ring_degree,
                relation_depth_ceiling: ring_degree,
            }
        }
        PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1 => PrivacyReleaseResourceFactsV1 {
            primary_units: if maximum {
                u64::from(BOOTLE_LANTERN_MAX_DISCLOSED_ATTRIBUTES_V1)
            } else {
                1
            },
            primary_ceiling: u64::from(BOOTLE_LANTERN_MAX_DISCLOSED_ATTRIBUTES_V1),
            secondary_units: if maximum {
                u64::from(BOOTLE_LANTERN_MAX_ALLOWED_VALUES_PER_ATTRIBUTE_V1)
            } else {
                1
            },
            secondary_ceiling: u64::from(BOOTLE_LANTERN_MAX_ALLOWED_VALUES_PER_ATTRIBUTE_V1),
            relation_depth: 8,
            relation_depth_ceiling: 8,
        },
        PrivacyProtocolIdV1::OrchardHalo2ActionsV1 => PrivacyReleaseResourceFactsV1 {
            primary_units: if maximum {
                u64::try_from(ORCHARD_MAX_ACTIONS_V1).ok()?
            } else {
                1
            },
            primary_ceiling: u64::try_from(ORCHARD_MAX_ACTIONS_V1).ok()?,
            secondary_units: if maximum {
                u64::try_from(ORCHARD_MAX_ACTIONS_V1).ok()?
            } else {
                0
            },
            secondary_ceiling: u64::try_from(ORCHARD_MAX_ACTIONS_V1).ok()?,
            relation_depth: u64::from(ORCHARD_TREE_DEPTH_V1),
            relation_depth_ceiling: u64::from(ORCHARD_TREE_DEPTH_V1),
        },
        PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1 => PrivacyReleaseResourceFactsV1 {
            primary_units: if maximum {
                u64::try_from(FCMP_MAX_INPUTS_NATIVE_V1).ok()?
            } else {
                1
            },
            primary_ceiling: u64::try_from(FCMP_MAX_INPUTS_NATIVE_V1).ok()?,
            secondary_units: if maximum {
                u64::try_from(FCMP_MAX_OUTPUTS_NATIVE_V1).ok()?
            } else {
                1
            },
            secondary_ceiling: u64::try_from(FCMP_MAX_OUTPUTS_NATIVE_V1).ok()?,
            relation_depth: if maximum {
                u64::from(FCMP_MAX_TREE_LAYERS_V1)
            } else {
                1
            },
            relation_depth_ceiling: u64::from(FCMP_MAX_TREE_LAYERS_V1),
        },
        PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1 => {
            let units = if maximum { 2 } else { 1 };
            PrivacyReleaseResourceFactsV1 {
                primary_units: units,
                primary_ceiling: u64::try_from(PRIVATE_NOTE_MAX_INPUTS_V1).ok()?,
                secondary_units: units,
                secondary_ceiling: u64::try_from(PRIVATE_NOTE_MAX_OUTPUTS_V1).ok()?,
                relation_depth: u64::try_from(PRIVATE_NOTE_TREE_DEPTH_V1).ok()?,
                relation_depth_ceiling: u64::try_from(PRIVATE_NOTE_TREE_DEPTH_V1).ok()?,
            }
        }
        PrivacyProtocolIdV1::PqMaspStarkV1 => {
            let units = if maximum { 2 } else { 1 };
            PrivacyReleaseResourceFactsV1 {
                primary_units: units,
                primary_ceiling: u64::try_from(PQ_MASP_INPUT_BOUND_V1).ok()?,
                secondary_units: units,
                secondary_ceiling: u64::try_from(PQ_MASP_OUTPUT_BOUND_V1).ok()?,
                relation_depth: u64::try_from(PQ_MASP_TREE_DEPTH_V1).ok()?,
                relation_depth_ceiling: u64::try_from(PQ_MASP_TREE_DEPTH_V1).ok()?,
            }
        }
    };
    Some(facts)
}
/// One canonical proof artifact produced and independently verified in a stage.
///
/// Artifact semantics and order are frozen by the typed protocol/case pair and
/// its protocol descriptor. No caller-selected label can alter that meaning.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::privacy_release_evidence::PrivacyReleaseProofArtifactEvidenceV1"
)]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct PrivacyReleaseProofArtifactEvidenceV1 {
    /// Zero-based ordinal, contiguous in collection order.
    pub artifact_ordinal: u8,
    /// Exact canonical proof bytes accepted by the production verifier.
    #[norito(with = "privacy_release_base64_bytes_v1")]
    pub canonical_proof_bytes: Vec<u8>,
    /// SHA-256 of the valid canonical proof before adversarial mutation.
    pub proof_sha256: [u8; 32],
    /// Governed canonical decoder ceiling for this artifact.
    pub proof_bytes_ceiling: u64,
}
mod privacy_release_base64_bytes_v1 {
    use super::*;
    use norito::json::{JsonSerialize as _, Parser};
    pub fn serialize(bytes: &[u8], out: &mut String) {
        BASE64_STANDARD.encode(bytes).json_serialize(out);
    }
    pub fn deserialize(parser: &mut Parser<'_>) -> Result<Vec<u8>, norito::json::Error> {
        let encoded = parser.parse_string()?;
        let maximum_encoded_bytes = PRIVACY_RELEASE_MAX_PROOF_ARTIFACT_BYTES_V1
            .div_ceil(3)
            .checked_mul(4)
            .ok_or_else(|| {
                norito::json::Error::Message("canonical proof base64 ceiling overflowed".to_owned())
            })?;
        let encoded_bytes = u64::try_from(encoded.len()).map_err(|_| {
            norito::json::Error::Message("canonical proof base64 length exceeds u64".to_owned())
        })?;
        if encoded_bytes > maximum_encoded_bytes {
            return Err(norito::json::Error::Message(
                "canonical proof base64 exceeds the Taira artifact ceiling".to_owned(),
            ));
        }
        let bytes = BASE64_STANDARD
            .decode(encoded.as_bytes())
            .map_err(|error| norito::json::Error::Message(error.to_string()))?;
        let decoded_bytes = u64::try_from(bytes.len()).map_err(|_| {
            norito::json::Error::Message("canonical proof byte length exceeds u64".to_owned())
        })?;
        if decoded_bytes > PRIVACY_RELEASE_MAX_PROOF_ARTIFACT_BYTES_V1 {
            return Err(norito::json::Error::Message(
                "canonical proof bytes exceed the Taira artifact ceiling".to_owned(),
            ));
        }
        if BASE64_STANDARD.encode(&bytes) != encoded {
            return Err(norito::json::Error::Message(
                "canonical proof bytes use padded standard base64".to_owned(),
            ));
        }
        Ok(bytes)
    }
}
/// One complete native stage result. It contains exact canonical proofs, their hashes, and public
/// resource facts; witness material never crosses this API.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::privacy_release_evidence::PrivacyReleaseStageEvidenceV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, JsonSerialize, JsonDeserialize)]
pub struct PrivacyReleaseStageEvidenceV1 {
    /// Evidence schema version.
    pub schema_version: u16,
    /// Exact global ordinal: protocol discriminant order, then case order.
    pub stage_ordinal: u16,
    /// Protocol under test.
    pub protocol_id: PrivacyProtocolIdV1,
    /// Mandatory case under test.
    pub case_kind: PrivacyReleaseCaseKindV1,
    /// Exact relation/prover/verifier/resource semantics for this protocol.
    pub protocol_descriptor: String,
    /// SHA-256 of the exact canonical public statement material exercised.
    pub public_statement_sha256: [u8; 32],
    /// Bounded ordered canonical proofs produced and independently verified.
    pub proof_artifacts: Vec<PrivacyReleaseProofArtifactEvidenceV1>,
    /// Expected verifier failure class, if this is an adversarial stage.
    pub failure_class: PrivacyReleaseFailureClassV1,
    /// Bounded relation resource facts; proof resources live per artifact.
    pub resources: PrivacyReleaseResourceFactsV1,
}
/// Stable fail-closed error category returned by the native evidence API.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::privacy_release_evidence::PrivacyReleaseEvidenceErrorClassV1")]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    JsonSerialize,
    JsonDeserialize,
)]
#[norito(
    tag = "error_class",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum PrivacyReleaseEvidenceErrorClassV1 {
    /// The production engine or its complete release fixture is not available.
    ProtocolUnavailable,
    /// Canonical public inputs or the maximum-shape witness could not be built.
    FixtureConstructionFailed,
    /// The public production prover rejected the valid fixture.
    NativeProverRejected,
    /// The independent public production verifier rejected the valid proof.
    NativeVerifierRejected,
    /// The verifier accepted a semantically mutated public statement.
    PublicStatementMutationAccepted,
    /// The public prover accepted a path that does not resolve to the supplied root.
    InvalidWitnessPathAccepted,
    /// The public prover accepted a malleable or otherwise non-canonical witness.
    NonCanonicalWitnessAccepted,
    /// The strict decoder/verifier accepted a corrupt proof wire.
    ProofCorruptionAccepted,
    /// The strict decoder/verifier accepted a truncated proof wire.
    ProofTruncationAccepted,
    /// A measured relation or proof dimension exceeded its governed ceiling.
    ResourceCeilingExceeded,
    /// Internal order, count, or evidence-shape invariant failed.
    EvidenceInvariant,
    /// Production envelope admission rejected a valid native fixture before
    /// reaching the selected protocol verifier.
    ProductionEnvelopeRejected,
}
/// Fail-closed native stage error without secret-bearing engine diagnostics.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::privacy_release_evidence::PrivacyReleaseEvidenceErrorV1")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, JsonSerialize, JsonDeserialize)]
pub struct PrivacyReleaseEvidenceErrorV1 {
    /// Protocol whose evidence failed.
    pub protocol_id: PrivacyProtocolIdV1,
    /// Case whose evidence failed.
    pub case_kind: PrivacyReleaseCaseKindV1,
    /// Stable, non-secret failure category.
    pub class: PrivacyReleaseEvidenceErrorClassV1,
}
impl fmt::Display for PrivacyReleaseEvidenceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "privacy release stage {}/{} failed: {:?}",
            self.protocol_id.canonical_label(),
            self.case_kind.canonical_label(),
            self.class
        )
    }
}
impl std::error::Error for PrivacyReleaseEvidenceErrorV1 {}
/// Return the exact global stage ordinal from the frozen release declaration.
#[must_use]
pub fn privacy_release_stage_ordinal_v1(
    protocol_id: PrivacyProtocolIdV1,
    case_kind: PrivacyReleaseCaseKindV1,
) -> u16 {
    assert!(
        validate_privacy_release_stage_coordinates_v1(&PRIVACY_RELEASE_STAGE_COORDINATES_V1),
        "frozen release stages must equal the closed protocol-by-case product"
    );
    PRIVACY_RELEASE_STAGE_COORDINATES_V1
        .iter()
        .find(|coordinate| {
            coordinate.protocol_id == protocol_id && coordinate.case_kind == case_kind
        })
        .map(|coordinate| coordinate.stage_ordinal)
        .expect("closed protocol/case coordinate is present in the frozen release declaration")
}
/// Return the exact number of canonical proof artifacts required by a stage.
#[must_use]
pub const fn privacy_release_proof_artifact_count_v1(
    protocol_id: PrivacyProtocolIdV1,
    case_kind: PrivacyReleaseCaseKindV1,
) -> u8 {
    if matches!(protocol_id, PrivacyProtocolIdV1::IrohaZkAmsV1)
        || (matches!(protocol_id, PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1)
            && matches!(
                case_kind,
                PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd
                    | PrivacyReleaseCaseKindV1::MaximumShapeResource
            ))
    {
        2
    } else {
        1
    }
}
/// Return the sole protocol bound for one ordered proof artifact.
///
/// `None` means that the ordinal is not part of the typed protocol/case stage.
/// For supported shapes, this repeats the production verifier's protocol-local
/// cap so a receipt cannot substitute a broader cap. An unavailable shape may
/// retain a projected wire bound above the global consensus cap; the artifact
/// validator rejects that shape regardless of the supplied artifact's size.
#[must_use]
pub fn privacy_release_proof_artifact_ceiling_v1(
    protocol_id: PrivacyProtocolIdV1,
    case_kind: PrivacyReleaseCaseKindV1,
    artifact_ordinal: u8,
) -> Option<u64> {
    match (protocol_id, case_kind, artifact_ordinal) {
        (
            PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
            PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd
            | PrivacyReleaseCaseKindV1::MaximumShapeResource,
            0,
        ) => u64::try_from(MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1).ok(),
        (
            PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
            PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd
            | PrivacyReleaseCaseKindV1::MaximumShapeResource,
            1,
        )
        | (PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1, _, 0) => {
            u64::try_from(MAX_PGC_PAYMENT_PROOF_BYTES_V1).ok()
        }
        (PrivacyProtocolIdV1::VeRangeTransparentRangeV1, _, 0) => {
            u64::try_from(MAX_VERANGE_TYPE1_BATCH_PROOF_BYTES_V1).ok()
        }
        (PrivacyProtocolIdV1::IrohaZkAmsV1, _, 0) => {
            u64::try_from(MAX_ZK_AMS_BATCH_ADMISSION_PROOF_BYTES_V1).ok()
        }
        (PrivacyProtocolIdV1::IrohaZkAmsV1, _, 1) => {
            u64::try_from(MAX_ZK_AMS_LSAG_PROOF_BYTES_V1).ok()
        }
        (PrivacyProtocolIdV1::VegaExistingCredentialZkV1, _, 0) => {
            u64::try_from(MAX_VEGA_PROOF_BYTES_V1).ok()
        }
        (PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1, _, 0) => {
            u64::try_from(JINDO_NATIVE_PROOF_BYTES_V1).ok()
        }
        (PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1, _, 0) => {
            u64::try_from(BOOTLE_PROOF_BYTES_V1).ok()
        }
        (PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1, _, 0) => {
            u64::try_from(FCMP_MAX_PROOF_WIRE_BYTES_V1).ok()
        }
        (PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1, _, 0) => {
            u64::try_from(IVM_PRIVATE_NOTE_MAX_PROOF_BYTES_V1).ok()
        }
        (PrivacyProtocolIdV1::PqMaspStarkV1, _, 0) => {
            u64::try_from(PQ_MASP_MAX_AUTHORIZATION_PROOF_BYTES_V1).ok()
        }
        (PrivacyProtocolIdV1::OrchardHalo2ActionsV1, _, 0) => {
            orchard_authorization_wire_size_v1(ORCHARD_MAX_ACTIONS_V1)
                .and_then(|ceiling| u64::try_from(ceiling).ok())
        }
        (PrivacyProtocolIdV1::ZkAcePqAuthorizationV1, _, 0) => {
            Some(u64::from(ZK_ACE_PRIVACY_MAX_PROOF_BYTES_V1))
        }
        (PrivacyProtocolIdV1::IrohaZkX509StarkP256V1, _, 0) => {
            Some(u64::from(ZK_X509_MAXIMUM_ENCODED_X5S1_BYTES_V1))
        }
        _ => None,
    }
}
/// Validate the complete ordered proof-artifact shape for one typed stage.
///
/// This rejects missing, extra, reordered, non-contiguous, empty, hash-mismatched,
/// over-ceiling, substituted-ceiling, and globally unbounded artifacts.
#[must_use]
pub fn validate_privacy_release_proof_artifacts_v1(
    protocol_id: PrivacyProtocolIdV1,
    case_kind: PrivacyReleaseCaseKindV1,
    artifacts: &[PrivacyReleaseProofArtifactEvidenceV1],
) -> bool {
    let expected = usize::from(privacy_release_proof_artifact_count_v1(
        protocol_id,
        case_kind,
    ));
    if artifacts.len() != expected || artifacts.len() > PRIVACY_RELEASE_MAX_PROOF_ARTIFACTS_V1 {
        return false;
    }
    let mut total_bytes = 0_u64;
    for (index, artifact) in artifacts.iter().enumerate() {
        let Ok(artifact_ordinal) = u8::try_from(index) else {
            return false;
        };
        let Some(expected_ceiling) =
            privacy_release_proof_artifact_ceiling_v1(protocol_id, case_kind, artifact_ordinal)
        else {
            return false;
        };
        let Ok(proof_bytes) = u64::try_from(artifact.canonical_proof_bytes.len()) else {
            return false;
        };
        let Some(next_total_bytes) = total_bytes.checked_add(proof_bytes) else {
            return false;
        };
        total_bytes = next_total_bytes;
        if artifact.artifact_ordinal != artifact_ordinal
            || artifact.canonical_proof_bytes.is_empty()
            || artifact.proof_sha256 == [0; 32]
            || artifact.proof_sha256 != sha256_v1(&artifact.canonical_proof_bytes)
            || proof_bytes > expected_ceiling
            || artifact.proof_bytes_ceiling != expected_ceiling
            || expected_ceiling > PRIVACY_RELEASE_MAX_PROOF_ARTIFACT_BYTES_V1
        {
            return false;
        }
    }
    true
}
/// Execute one mandatory native prove/verify or adversarial stage.
///
/// The selected engine must perform its public production prover and verifier path. Missing
/// complete implementations fail closed; no placeholder result can be encoded as passing evidence.
pub fn run_privacy_release_stage_v1(
    protocol_id: PrivacyProtocolIdV1,
    case_kind: PrivacyReleaseCaseKindV1,
) -> Result<PrivacyReleaseStageEvidenceV1, PrivacyReleaseEvidenceErrorV1> {
    let material = match protocol_id {
        PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1 => run_anonymous_pgc_stage_v1(case_kind)
            .map_err(|class| PrivacyReleaseEvidenceErrorV1 {
                protocol_id,
                case_kind,
                class,
            })?,
        PrivacyProtocolIdV1::VeRangeTransparentRangeV1 => {
            run_verange_stage_v1(case_kind).map_err(|class| PrivacyReleaseEvidenceErrorV1 {
                protocol_id,
                case_kind,
                class,
            })?
        }
        PrivacyProtocolIdV1::OrchardHalo2ActionsV1 => {
            run_orchard_stage_v1(case_kind).map_err(|class| PrivacyReleaseEvidenceErrorV1 {
                protocol_id,
                case_kind,
                class,
            })?
        }
        PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1 => run_jindo_stage_v1(case_kind)
            .map_err(|class| PrivacyReleaseEvidenceErrorV1 {
                protocol_id,
                case_kind,
                class,
            })?,
        PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1 => run_bootle_lantern_stage_v1(case_kind)
            .map_err(|class| PrivacyReleaseEvidenceErrorV1 {
                protocol_id,
                case_kind,
                class,
            })?,
        PrivacyProtocolIdV1::IrohaZkAmsV1 => {
            run_zk_ams_stage_v1(case_kind).map_err(|class| PrivacyReleaseEvidenceErrorV1 {
                protocol_id,
                case_kind,
                class,
            })?
        }
        PrivacyProtocolIdV1::ZkAcePqAuthorizationV1 => {
            run_zk_ace_stage_v1(case_kind).map_err(|class| PrivacyReleaseEvidenceErrorV1 {
                protocol_id,
                case_kind,
                class,
            })?
        }
        PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1 => run_fcmp_plus_plus_stage_v1(case_kind)
            .map_err(|class| PrivacyReleaseEvidenceErrorV1 {
                protocol_id,
                case_kind,
                class,
            })?,
        PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1 => run_ivm_private_note_stage_v1(case_kind)
            .map_err(|class| PrivacyReleaseEvidenceErrorV1 {
                protocol_id,
                case_kind,
                class,
            })?,
        PrivacyProtocolIdV1::PqMaspStarkV1 => {
            run_pq_masp_stage_v1(case_kind).map_err(|class| PrivacyReleaseEvidenceErrorV1 {
                protocol_id,
                case_kind,
                class,
            })?
        }
        PrivacyProtocolIdV1::VegaExistingCredentialZkV1 => {
            run_vega_stage_v1(case_kind).map_err(|class| PrivacyReleaseEvidenceErrorV1 {
                protocol_id,
                case_kind,
                class,
            })?
        }
        PrivacyProtocolIdV1::IrohaZkX509StarkP256V1 => {
            run_zk_x509_stage_v1(case_kind).map_err(|class| PrivacyReleaseEvidenceErrorV1 {
                protocol_id,
                case_kind,
                class,
            })?
        }
    };
    let expected_resources = privacy_release_resource_facts_v1(protocol_id, case_kind).ok_or(
        PrivacyReleaseEvidenceErrorV1 {
            protocol_id,
            case_kind,
            class: PrivacyReleaseEvidenceErrorClassV1::ProtocolUnavailable,
        },
    )?;
    if material.resources != expected_resources {
        return Err(PrivacyReleaseEvidenceErrorV1 {
            protocol_id,
            case_kind,
            class: PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant,
        });
    }
    if !material.resources.validate() {
        return Err(PrivacyReleaseEvidenceErrorV1 {
            protocol_id,
            case_kind,
            class: PrivacyReleaseEvidenceErrorClassV1::ResourceCeilingExceeded,
        });
    }
    let expected_artifact_count = usize::from(privacy_release_proof_artifact_count_v1(
        protocol_id,
        case_kind,
    ));
    if material.proof_artifacts.len() != expected_artifact_count
        || material.proof_artifacts.len() > PRIVACY_RELEASE_MAX_PROOF_ARTIFACTS_V1
        || material
            .proof_artifacts
            .iter()
            .any(|artifact| artifact.proof.is_empty() || artifact.proof_bytes_ceiling == 0)
    {
        return Err(PrivacyReleaseEvidenceErrorV1 {
            protocol_id,
            case_kind,
            class: PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant,
        });
    }
    let proof_artifacts = material
        .proof_artifacts
        .into_iter()
        .enumerate()
        .map(|(index, artifact)| {
            let proof_sha256 = sha256_v1(&artifact.proof);
            Ok(PrivacyReleaseProofArtifactEvidenceV1 {
                artifact_ordinal: u8::try_from(index)
                    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
                canonical_proof_bytes: artifact.proof,
                proof_sha256,
                proof_bytes_ceiling: artifact.proof_bytes_ceiling,
            })
        })
        .collect::<Result<Vec<_>, PrivacyReleaseEvidenceErrorClassV1>>()
        .map_err(|class| PrivacyReleaseEvidenceErrorV1 {
            protocol_id,
            case_kind,
            class,
        })?;
    if !validate_privacy_release_proof_artifacts_v1(protocol_id, case_kind, &proof_artifacts) {
        return Err(PrivacyReleaseEvidenceErrorV1 {
            protocol_id,
            case_kind,
            class: PrivacyReleaseEvidenceErrorClassV1::ResourceCeilingExceeded,
        });
    }
    let public_statement_sha256 = sha256_v1(&material.public_statement_material);
    if public_statement_sha256 == [0; 32] {
        return Err(PrivacyReleaseEvidenceErrorV1 {
            protocol_id,
            case_kind,
            class: PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant,
        });
    }
    Ok(PrivacyReleaseStageEvidenceV1 {
        schema_version: PRIVACY_RELEASE_EVIDENCE_SCHEMA_VERSION_V1,
        stage_ordinal: privacy_release_stage_ordinal_v1(protocol_id, case_kind),
        protocol_id,
        case_kind,
        protocol_descriptor: privacy_release_protocol_descriptor_v1(protocol_id).to_owned(),
        public_statement_sha256,
        proof_artifacts,
        failure_class: material.failure_class,
        resources: material.resources,
    })
}
struct ProofArtifactMaterialV1 {
    proof: Vec<u8>,
    proof_bytes_ceiling: u64,
}
struct StageMaterialV1 {
    public_statement_material: Vec<u8>,
    proof_artifacts: Vec<ProofArtifactMaterialV1>,
    failure_class: PrivacyReleaseFailureClassV1,
    resources: PrivacyReleaseResourceFactsV1,
}
fn single_proof_artifact_v1(
    proof: Vec<u8>,
    proof_bytes_ceiling: u64,
) -> Vec<ProofArtifactMaterialV1> {
    vec![ProofArtifactMaterialV1 {
        proof,
        proof_bytes_ceiling,
    }]
}
fn ordered_public_statement_material_v1(
    protocol_id: PrivacyProtocolIdV1,
    statements: &[&[u8]],
) -> Result<Vec<u8>, PrivacyReleaseEvidenceErrorClassV1> {
    if statements.len() != PRIVACY_RELEASE_MAX_PROOF_ARTIFACTS_V1
        || statements.iter().any(|statement| statement.is_empty())
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let mut material = Vec::new();
    material.extend_from_slice(b"iroha.privacy.release.ordered-public-statements.v1");
    let protocol_label = protocol_id.canonical_label().as_bytes();
    material.extend_from_slice(
        &u16::try_from(protocol_label.len())
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
            .to_be_bytes(),
    );
    material.extend_from_slice(protocol_label);
    material.push(
        u8::try_from(statements.len())
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
    );
    for (index, statement) in statements.iter().enumerate() {
        material.push(
            u8::try_from(index)
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
        );
        material.extend_from_slice(
            &u64::try_from(statement.len())
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
                .to_be_bytes(),
        );
        material.extend_from_slice(statement);
    }
    Ok(material)
}
fn release_statement_context_from_compiled_profile_v1(
    profile: &CompiledPrivacyProfileV1,
    network_id: NetworkId,
    action_index: u32,
    transaction_intent_digest: PrivacyTransactionIntentDigestV1,
) -> PrivacyStatementContextV1 {
    PrivacyStatementContextV1 {
        network_id,
        action_index,
        transaction_intent_digest,
        parameter_id: profile.parameter_id,
        parameter_digest: profile.parameter_digest,
        verifier_digest: profile.verifier_digest,
        statement_schema_digest: profile.statement_schema_digest,
        engine_manifest_digest: profile.engine_manifest_digest,
    }
}
const ZK_ACE_RELEASE_TRACE_ROWS_V1: u64 = 4_096;
const ZK_ACE_RELEASE_QUERY_COUNT_V1: u64 = 136;
const ZK_ACE_RELEASE_FRI_ROUNDS_V1: u64 = 11;
fn run_zk_ace_stage_v1(
    case_kind: PrivacyReleaseCaseKindV1,
) -> Result<StageMaterialV1, PrivacyReleaseEvidenceErrorClassV1> {
    let (public_inputs, witness) = zk_ace_fixture_v1()?;
    let mut rng = EvidenceRng09::new(stage_seed_v1(
        PrivacyProtocolIdV1::ZkAcePqAuthorizationV1,
        case_kind,
    ));
    let proof = prove_zk_ace_privacy_v1_with_rng(&public_inputs, &witness, &mut rng)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    verify_zk_ace_privacy_v1(&public_inputs, &proof, ZK_ACE_PRIVACY_MAX_PROOF_BYTES_V1)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected)?;
    let trace_rows = 1_u64
        .checked_shl(u32::from(ZK_ACE_TRACE_LOG2_V1))
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let query_count = u64::try_from(ZK_ACE_QUERY_COUNT_V1)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let fri_rounds = u64::try_from(ZK_ACE_FRI_ROUNDS_V1)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let proof_bytes = u64::try_from(proof.len())
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let proof_ceiling = u64::from(ZK_ACE_PRIVACY_MAX_PROOF_BYTES_V1);
    if trace_rows != ZK_ACE_RELEASE_TRACE_ROWS_V1
        || query_count != ZK_ACE_RELEASE_QUERY_COUNT_V1
        || fri_rounds != ZK_ACE_RELEASE_FRI_ROUNDS_V1
        || proof_bytes != proof_ceiling
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let original_material = norito::encode_canonical(&public_inputs)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let (public_statement_material, failure_class) = match case_kind {
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd
        | PrivacyReleaseCaseKindV1::MaximumShapeResource => (
            original_material,
            PrivacyReleaseFailureClassV1::NotApplicable,
        ),
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation => {
            let mut cross_network = public_inputs.clone();
            cross_network.statement.context.network_id =
                release_network_id_from_genesis_hash([0x9f; 32]);
            let mut cross_genesis = public_inputs.clone();
            cross_genesis.genesis_hash[0] ^= 0x80;
            let mut wrong_policy_id = public_inputs.clone();
            let mut policy_id = *wrong_policy_id.statement.policy_id.as_bytes();
            policy_id[0] ^= 0x80;
            wrong_policy_id.statement.policy_id = PrivacyPolicyIdV1::new(policy_id);
            let mut wrong_policy_digest = public_inputs.clone();
            let mut policy_digest = *wrong_policy_digest.statement.policy_digest.as_bytes();
            policy_digest[0] ^= 0x80;
            wrong_policy_digest.statement.policy_digest = PrivacyPolicyDigestV1::new(policy_digest);
            let mut malformed_version = public_inputs.clone();
            malformed_version.version = 2;
            let mut malformed_statement = public_inputs.clone();
            malformed_statement.statement.amount = 0;
            for mutation in [
                &cross_network,
                &cross_genesis,
                &wrong_policy_id,
                &wrong_policy_digest,
                &malformed_version,
                &malformed_statement,
            ] {
                if verify_zk_ace_privacy_v1(mutation, &proof, ZK_ACE_PRIVACY_MAX_PROOF_BYTES_V1)
                    .is_ok()
                {
                    return Err(
                        PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted,
                    );
                }
            }
            (
                norito::encode_canonical(&cross_network)
                    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
                PrivacyReleaseFailureClassV1::PublicStatementBindingRejected,
            )
        }
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation => {
            let mut corrupt_header = proof.clone();
            let first = corrupt_header
                .first_mut()
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *first ^= 0x80;
            if verify_zk_ace_privacy_v1(
                &public_inputs,
                &corrupt_header,
                ZK_ACE_PRIVACY_MAX_PROOF_BYTES_V1,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
            }
            let mut tampered = proof.clone();
            let middle = tampered.len() / 2;
            let middle_byte = tampered
                .get_mut(middle)
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *middle_byte ^= 0x01;
            if verify_zk_ace_privacy_v1(
                &public_inputs,
                &tampered,
                ZK_ACE_PRIVACY_MAX_PROOF_BYTES_V1,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
            }
            let truncated = proof
                .get(..proof.len().saturating_sub(1))
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            if verify_zk_ace_privacy_v1(
                &public_inputs,
                truncated,
                ZK_ACE_PRIVACY_MAX_PROOF_BYTES_V1,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofTruncationAccepted);
            }
            (
                original_material,
                PrivacyReleaseFailureClassV1::CanonicalWireCorruptionAndTruncationRejected,
            )
        }
    };
    Ok(StageMaterialV1 {
        public_statement_material,
        proof_artifacts: single_proof_artifact_v1(proof, proof_ceiling),
        failure_class,
        resources: PrivacyReleaseResourceFactsV1 {
            primary_units: trace_rows,
            primary_ceiling: ZK_ACE_RELEASE_TRACE_ROWS_V1,
            secondary_units: query_count,
            secondary_ceiling: ZK_ACE_RELEASE_QUERY_COUNT_V1,
            relation_depth: fri_rounds,
            relation_depth_ceiling: ZK_ACE_RELEASE_FRI_ROUNDS_V1,
        },
    })
}
fn zk_ace_fixture_v1()
-> Result<(ZkAcePrivacyPublicInputsV1, ZkAcePrivacyWitnessV1), PrivacyReleaseEvidenceErrorClassV1> {
    let witness = ZkAcePrivacyWitnessV1::try_new([0x91; 32], [0x92; 32], [0x93; 32])
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let network_id = release_network_id_from_genesis_hash([0x9E; 32]);
    let domain_id = DomainId::try_new("privacy", "universal")
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let asset_name = "zkace"
        .parse()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let profile = compiled_privacy_profile_v1(PrivacyProtocolIdV1::ZkAcePqAuthorizationV1)
        .map_err(|error| match error {
            crate::privacy_profiles::CompiledPrivacyProfileErrorV1::EngineUnavailable {
                ..
            } => PrivacyReleaseEvidenceErrorClassV1::ProtocolUnavailable,
            _ => PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed,
        })?;
    let statement = ZkAcePqAuthorizationStatementV1 {
        context: release_statement_context_from_compiled_profile_v1(
            &profile,
            network_id,
            0,
            PrivacyTransactionIntentDigestV1::new([0x94; 32]),
        ),
        identity_commitment: witness.identity_commitment_v1(),
        policy_id: PrivacyPolicyIdV1::new([0x9A; 32]),
        policy_digest: PrivacyPolicyDigestV1::new([0x9B; 32]),
        source: privacy_release_account_v1(0x9C)?,
        destination: privacy_release_account_v1(0x9D)?,
        asset_definition_id: AssetDefinitionId::derive_from_components(domain_id, asset_name),
        public_balance_scope: iroha_data_model::asset::AssetBalanceScope::Global,
        amount: 19,
        authorization_epoch: 7,
        replay_nullifier: Default::default(),
    };
    let mut public_inputs = ZkAcePrivacyPublicInputsV1::new(statement, [0x9E; 32]);
    let authorization_digest = derive_zk_ace_privacy_authorization_digest(&public_inputs)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    public_inputs.statement.replay_nullifier =
        witness.replay_nullifier_v1(&authorization_digest, &network_id);
    Ok((public_inputs, witness))
}
fn run_fcmp_plus_plus_stage_v1(
    case_kind: PrivacyReleaseCaseKindV1,
) -> Result<StageMaterialV1, PrivacyReleaseEvidenceErrorClassV1> {
    let maximum = case_kind == PrivacyReleaseCaseKindV1::MaximumShapeResource;
    let (inputs, output_openings, root) = fcmp_release_fixture_v1(maximum)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let new_outputs = output_openings
        .iter()
        .map(|opening| opening.output())
        .collect::<Vec<_>>();
    let profile = compiled_privacy_profile_v1(PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let context_hash = fcmp_release_context_hash_v1(&profile)?;
    let mut rng = EvidenceRng06::new(stage_seed_v1(
        PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1,
        case_kind,
    ));
    let bundle = prove_fcmp_plus_plus_v1(&mut rng, context_hash, &inputs, &output_openings, root)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    verify_fcmp_transaction_v1(
        context_hash,
        bundle.proof_wire(),
        bundle.public_inputs(),
        &new_outputs,
        root,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected)?;
    let (proof, public_inputs) = bundle.into_parts();
    let expected_inputs = if maximum {
        FCMP_MAX_INPUTS_NATIVE_V1
    } else {
        1
    };
    let expected_outputs = if maximum {
        FCMP_MAX_OUTPUTS_NATIVE_V1
    } else {
        1
    };
    let expected_layers = if maximum { FCMP_MAX_TREE_LAYERS_V1 } else { 1 };
    let expected_wire_bytes = if maximum {
        FCMP_MAX_PROOF_WIRE_BYTES_V1
    } else {
        FCMP_MIN_PROOF_WIRE_BYTES_V1
    };
    if inputs.len() != expected_inputs
        || public_inputs.len() != expected_inputs
        || new_outputs.len() != expected_outputs
        || root.layers() != expected_layers
        || proof.len() != expected_wire_bytes
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let original_material =
        fcmp_statement_material_v1(context_hash, &public_inputs, &new_outputs, root)?;
    let (public_statement_material, failure_class) = match case_kind {
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd
        | PrivacyReleaseCaseKindV1::MaximumShapeResource => (
            original_material,
            PrivacyReleaseFailureClassV1::NotApplicable,
        ),
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation => {
            let mut cross_context = context_hash;
            cross_context[0] ^= 0x80;
            if verify_fcmp_transaction_v1(cross_context, &proof, &public_inputs, &new_outputs, root)
                .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted);
            }
            let mut changed_key_image = public_inputs.clone();
            let first_input = changed_key_image
                .first_mut()
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            first_input.key_image = if first_input.key_image != first_input.pseudo_out {
                first_input.pseudo_out
            } else {
                first_input.output_key_tilde
            };
            if verify_fcmp_transaction_v1(
                context_hash,
                &proof,
                &changed_key_image,
                &new_outputs,
                root,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted);
            }
            let alternate_root = build_fcmp_frontier_v1(&new_outputs)
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?
                .root;
            if alternate_root == root {
                return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
            }
            if verify_fcmp_transaction_v1(
                context_hash,
                &proof,
                &public_inputs,
                &new_outputs,
                alternate_root,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted);
            }
            (
                fcmp_statement_material_v1(cross_context, &public_inputs, &new_outputs, root)?,
                PrivacyReleaseFailureClassV1::PublicStatementBindingRejected,
            )
        }
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation => {
            let (invalid_inputs, invalid_outputs, invalid_root) =
                fcmp_release_invalid_path_fixture_v1()
                    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
            let mut invalid_path_rng = EvidenceRng06::new(stage_seed_v1(
                PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1,
                PrivacyReleaseCaseKindV1::MaximumShapeResource,
            ));
            if prove_fcmp_plus_plus_v1(
                &mut invalid_path_rng,
                context_hash,
                &invalid_inputs,
                &invalid_outputs,
                invalid_root,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::InvalidWitnessPathAccepted);
            }
            let mut corrupt_header = proof.clone();
            let first = corrupt_header
                .first_mut()
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *first ^= 0x80;
            if verify_fcmp_transaction_v1(
                context_hash,
                &corrupt_header,
                &public_inputs,
                &new_outputs,
                root,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
            }
            let circuit_start = FCMP_PROOF_WIRE_HEADER_BYTES_V1
                .checked_add(
                    public_inputs
                        .len()
                        .checked_mul(FCMP_PROOF_INPUT_BYTES_V1)
                        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
                )
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            let mut path_proof_tamper = proof.clone();
            let path_byte = path_proof_tamper
                .get_mut(circuit_start)
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *path_byte ^= 0x01;
            if verify_fcmp_transaction_v1(
                context_hash,
                &path_proof_tamper,
                &public_inputs,
                &new_outputs,
                root,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
            }
            let mut interior_tamper = proof.clone();
            let interior = interior_tamper.len() / 2;
            let interior_byte = interior_tamper
                .get_mut(interior)
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *interior_byte ^= 0x80;
            if verify_fcmp_transaction_v1(
                context_hash,
                &interior_tamper,
                &public_inputs,
                &new_outputs,
                root,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
            }
            let truncated = proof
                .get(..proof.len().saturating_sub(1))
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            if verify_fcmp_transaction_v1(
                context_hash,
                truncated,
                &public_inputs,
                &new_outputs,
                root,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofTruncationAccepted);
            }
            (
                original_material,
                PrivacyReleaseFailureClassV1::CanonicalWireCorruptionAndTruncationRejected,
            )
        }
    };
    Ok(StageMaterialV1 {
        public_statement_material,
        proof_artifacts: single_proof_artifact_v1(
            proof,
            u64::try_from(FCMP_MAX_PROOF_WIRE_BYTES_V1)
                .expect("closed FCMP++ proof ceiling fits u64"),
        ),
        failure_class,
        resources: PrivacyReleaseResourceFactsV1 {
            primary_units: u64::try_from(inputs.len())
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
            primary_ceiling: u64::try_from(FCMP_MAX_INPUTS_NATIVE_V1)
                .expect("closed FCMP++ input ceiling fits u64"),
            secondary_units: u64::try_from(new_outputs.len())
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
            secondary_ceiling: u64::try_from(FCMP_MAX_OUTPUTS_NATIVE_V1)
                .expect("closed FCMP++ output ceiling fits u64"),
            relation_depth: u64::from(root.layers()),
            relation_depth_ceiling: u64::from(FCMP_MAX_TREE_LAYERS_V1),
        },
    })
}
fn fcmp_statement_material_v1(
    context_hash: [u8; 32],
    public_inputs: &[FcmpProofInputPublicV1],
    new_outputs: &[FcmpOutputTupleV1],
    root: FcmpTreeRootV1,
) -> Result<Vec<u8>, PrivacyReleaseEvidenceErrorClassV1> {
    let profile = compiled_privacy_profile_v1(PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let mut material =
        Vec::with_capacity(384 + (public_inputs.len() * 5 * 32) + (new_outputs.len() * 3 * 32));
    material.extend_from_slice(b"iroha.privacy.release.fcmp-plus-plus.public-statement.v1");
    append_fcmp_compiled_profile_tuple_v1(&mut material, &profile)?;
    material.extend_from_slice(&context_hash);
    material.push(root.layers());
    material.extend_from_slice(&root.point());
    material.extend_from_slice(
        &u32::try_from(public_inputs.len())
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
            .to_be_bytes(),
    );
    for public_input in public_inputs {
        for point in [
            public_input.output_key_tilde,
            public_input.linking_tag_generator_tilde,
            public_input.rerandomization_commitment,
            public_input.pseudo_out,
            public_input.key_image,
        ] {
            material.extend_from_slice(&point);
        }
    }
    material.extend_from_slice(
        &u32::try_from(new_outputs.len())
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
            .to_be_bytes(),
    );
    for output in new_outputs {
        material.extend_from_slice(&output.encode());
    }
    Ok(material)
}
fn append_fcmp_compiled_profile_tuple_v1(
    material: &mut Vec<u8>,
    profile: &CompiledPrivacyProfileV1,
) -> Result<(), PrivacyReleaseEvidenceErrorClassV1> {
    if profile.protocol_id != PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1 {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    const DOMAIN: &[u8] = b"iroha.privacy.release.fcmp-plus-plus.compiled-profile-tuple.v1";
    let domain_length = u16::try_from(DOMAIN.len())
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    material.extend_from_slice(&domain_length.to_be_bytes());
    material.extend_from_slice(DOMAIN);
    material.extend_from_slice(&5_u16.to_be_bytes());
    for digest in [
        profile.parameter_id.as_bytes().as_slice(),
        profile.parameter_digest.as_bytes().as_slice(),
        profile.verifier_digest.as_bytes().as_slice(),
        profile.statement_schema_digest.as_bytes().as_slice(),
        profile.engine_manifest_digest.as_bytes().as_slice(),
    ] {
        let digest_length = u64::try_from(digest.len())
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
        material.extend_from_slice(&digest_length.to_be_bytes());
        material.extend_from_slice(digest);
    }
    Ok(())
}
fn fcmp_release_context_hash_v1(
    profile: &CompiledPrivacyProfileV1,
) -> Result<[u8; 32], PrivacyReleaseEvidenceErrorClassV1> {
    let mut tuple = Vec::with_capacity(256);
    append_fcmp_compiled_profile_tuple_v1(&mut tuple, profile)?;
    let tuple_length = u64::try_from(tuple.len())
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let mut hash = Sha256::new();
    hash.update(b"iroha.privacy.release.fcmp-plus-plus.context-hash.v1");
    hash.update(tuple_length.to_be_bytes());
    hash.update(&tuple);
    Ok(hash.finalize().into())
}
fn run_anonymous_pgc_stage_v1(
    case_kind: PrivacyReleaseCaseKindV1,
) -> Result<StageMaterialV1, PrivacyReleaseEvidenceErrorClassV1> {
    let maximum = case_kind == PrivacyReleaseCaseKindV1::MaximumShapeResource;
    let anonymity_set_size = if maximum { 64_usize } else { 16 };
    let recipient_count = if maximum {
        PGC_PAYMENT_MAX_RECIPIENTS_V1
    } else {
        2
    };
    let base_secret = if maximum { 1_000_u64 } else { 2 };
    let mut key_pairs = (base_secret
        ..base_secret
            .checked_add(
                u64::try_from(anonymity_set_size)
                    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
            )
            .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?)
        .map(|value| {
            TwistedElGamalKeyPairV1::from_secret(evidence_secret_scalar_v1(value))
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    key_pairs.sort_by_key(TwistedElGamalKeyPairV1::public_key);
    let public_keys = key_pairs
        .iter()
        .map(TwistedElGamalKeyPairV1::public_key)
        .collect::<Vec<_>>();
    let sender_index = if maximum { 31 } else { 7 };
    let recipient_indices: &[usize] = if maximum {
        &[0, 1, 2, 3, 4, 5, 6, 7]
    } else {
        &[2, 12]
    };
    let mut transfer_values = vec![0_i64; anonymity_set_size];
    if maximum {
        for index in recipient_indices {
            transfer_values[*index] = 1;
        }
        transfer_values[sender_index] = -i64::try_from(recipient_count)
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    } else {
        transfer_values[recipient_indices[0]] = 20;
        transfer_values[recipient_indices[1]] = 30;
        transfer_values[sender_index] = -50;
    }
    let transfer_randomness = (0..anonymity_set_size)
        .map(|index| {
            evidence_secret_scalar_v1(
                (if maximum { 2_000 } else { 100 })
                    + u64::try_from(index).expect("closed PGC index fits u64"),
            )
        })
        .collect::<Vec<_>>();
    let transfers = public_keys
        .iter()
        .copied()
        .zip(&transfer_values)
        .zip(&transfer_randomness)
        .map(|((key, value), randomness)| {
            encrypt_signed_with_randomness(key, *value, randomness)
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let opening_balance = if maximum { 10_u32 } else { 100 };
    let current_balance_randomness = (0..anonymity_set_size)
        .map(|index| {
            evidence_secret_scalar_v1(
                (if maximum { 3_000 } else { 200 })
                    + u64::try_from(index).expect("closed PGC index fits u64"),
            )
        })
        .collect::<Vec<_>>();
    let current_balances = public_keys
        .iter()
        .copied()
        .zip(&current_balance_randomness)
        .map(|(key, randomness)| {
            encrypt_with_randomness(key, opening_balance, randomness)
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let opening_balances = vec![opening_balance; anonymity_set_size];
    let total_supply = opening_balance
        .checked_mul(
            u32::try_from(anonymity_set_size)
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
        )
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let bootstrap = anonymous_pgc_bootstrap_material_v1(
        &public_keys,
        &current_balances,
        &opening_balances,
        &current_balance_randomness,
        total_supply,
        case_kind,
    )?;
    let bootstrap_digest = bootstrap.bootstrap_digest;
    let bootstrap_proof_digest = bootstrap.bootstrap_proof_digest;
    let pool_invariant =
        AnonymousPgcPoolInvariantV1::new(total_supply, bootstrap_digest, bootstrap_proof_digest)
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    if pool_invariant.total_supply() != total_supply
        || pool_invariant.bootstrap_digest() != bootstrap_digest
        || pool_invariant.bootstrap_proof_digest() != bootstrap_proof_digest
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let binding = anonymous_pgc_binding_v1([0x82; 32])?;
    let statement = AnonymousPgcPaymentStatementV1::new(
        &public_keys,
        &transfers,
        &current_balances,
        recipient_count,
        pool_invariant,
        binding,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let witness = AnonymousPgcPaymentWitnessV1 {
        transfer_values: &transfer_values,
        transfer_randomness: &transfer_randomness,
        sender_index,
        sender_secret: key_pairs[sender_index].secret_scalar(),
    };
    let mut rng = EvidenceRng06::new(stage_seed_v1(
        PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
        case_kind,
    ));
    let proof = prove_payment(&statement, &witness, &mut rng)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let proof_bytes = proof.encode();
    let verified_payment = verify_payment_encoded(&statement, &proof_bytes)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected)?;
    if verified_payment.next_balance_ciphertexts().len() != anonymity_set_size {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    for (index, (key_pair, ciphertext)) in key_pairs
        .iter()
        .zip(verified_payment.next_balance_ciphertexts())
        .enumerate()
    {
        let expected = i64::from(opening_balance)
            .checked_add(transfer_values[index])
            .and_then(|balance| u32::try_from(balance).ok())
            .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
        let observed = decrypt_u32(key_pair.secret_scalar(), *ciphertext)
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected)?;
        if observed != expected {
            return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
        }
    }
    let authoritative_current_accounts =
        anonymous_pgc_account_table_v1(&public_keys, &current_balances)?;
    if authoritative_current_accounts != bootstrap.accounts {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let successor_accounts =
        anonymous_pgc_account_table_v1(&public_keys, verified_payment.next_balance_ciphertexts())?;
    let successor_epoch = bootstrap
        .initial_epoch
        .checked_add(1)
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let successor_root = compute_privacy_pgc_account_state_root_v1(
        bootstrap.namespace,
        successor_epoch,
        total_supply,
        &successor_accounts,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    if successor_root.is_zero() || successor_root == bootstrap.initial_root {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let mut payment_statement_material = anonymous_pgc_statement_material_v1(&statement, &binding);
    let namespace_encoding = norito::encode_canonical(&bootstrap.namespace)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    payment_statement_material
        .extend_from_slice(b"iroha.privacy.release.anonymous-pgc.account-root-effect.v1");
    payment_statement_material.extend_from_slice(
        &u32::try_from(namespace_encoding.len())
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
            .to_be_bytes(),
    );
    payment_statement_material.extend_from_slice(&namespace_encoding);
    payment_statement_material.extend_from_slice(&bootstrap.initial_epoch.to_be_bytes());
    payment_statement_material.extend_from_slice(bootstrap.initial_root.as_bytes());
    payment_statement_material.extend_from_slice(&successor_epoch.to_be_bytes());
    payment_statement_material.extend_from_slice(successor_root.as_bytes());
    payment_statement_material.extend_from_slice(&total_supply.to_be_bytes());
    let payment_proof_ceiling = u64::try_from(MAX_PGC_PAYMENT_PROOF_BYTES_V1)
        .expect("closed PGC payment proof ceiling fits u64");
    let (public_statement_material, proof_artifacts, failure_class) = match case_kind {
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd
        | PrivacyReleaseCaseKindV1::MaximumShapeResource => {
            let public_statement_material = ordered_public_statement_material_v1(
                PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
                &[
                    bootstrap.public_statement_material.as_slice(),
                    payment_statement_material.as_slice(),
                ],
            )?;
            (
                public_statement_material,
                vec![
                    ProofArtifactMaterialV1 {
                        proof: bootstrap.proof,
                        proof_bytes_ceiling: u64::try_from(MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1)
                            .expect("closed PGC bootstrap proof ceiling fits u64"),
                    },
                    ProofArtifactMaterialV1 {
                        proof: proof_bytes,
                        proof_bytes_ceiling: payment_proof_ceiling,
                    },
                ],
                PrivacyReleaseFailureClassV1::NotApplicable,
            )
        }
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation => {
            let mut mutated_digest = binding.statement_digest;
            mutated_digest[0] ^= 0x80;
            let mutated_binding = anonymous_pgc_binding_v1(mutated_digest)?;
            let mutated = AnonymousPgcPaymentStatementV1::new(
                &public_keys,
                &transfers,
                &current_balances,
                recipient_count,
                pool_invariant,
                mutated_binding,
            )
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
            if verify_payment_encoded(&mutated, &proof_bytes).is_ok() {
                return Err(PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted);
            }
            (
                anonymous_pgc_statement_material_v1(&mutated, &mutated_binding),
                single_proof_artifact_v1(proof_bytes, payment_proof_ceiling),
                PrivacyReleaseFailureClassV1::PublicStatementBindingRejected,
            )
        }
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation => {
            let mut corrupt = proof_bytes.clone();
            let first = corrupt
                .first_mut()
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *first ^= 0x80;
            if verify_payment_encoded(&statement, &corrupt).is_ok() {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
            }
            let mut corrupt_interior = proof_bytes.clone();
            let interior_index = corrupt_interior.len() / 2;
            let interior = corrupt_interior
                .get_mut(interior_index)
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *interior ^= 0x01;
            if verify_payment_encoded(&statement, &corrupt_interior).is_ok() {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
            }
            let truncated = proof_bytes
                .get(..proof_bytes.len().saturating_sub(1))
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            if verify_payment_encoded(&statement, truncated).is_ok() {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofTruncationAccepted);
            }
            (
                payment_statement_material,
                single_proof_artifact_v1(proof_bytes, payment_proof_ceiling),
                PrivacyReleaseFailureClassV1::CanonicalWireCorruptionAndTruncationRejected,
            )
        }
    };
    Ok(StageMaterialV1 {
        public_statement_material,
        proof_artifacts,
        resources: PrivacyReleaseResourceFactsV1 {
            primary_units: u64::try_from(anonymity_set_size)
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
            primary_ceiling: 64,
            secondary_units: u64::try_from(recipient_count)
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
            secondary_ceiling: u64::try_from(PGC_PAYMENT_MAX_RECIPIENTS_V1)
                .expect("closed PGC recipient ceiling fits u64"),
            relation_depth: 32,
            relation_depth_ceiling: 32,
        },
        failure_class,
    })
}
struct AnonymousPgcBootstrapMaterialV1 {
    public_statement_material: Vec<u8>,
    proof: Vec<u8>,
    bootstrap_digest: [u8; 32],
    bootstrap_proof_digest: [u8; 32],
    namespace: PrivacyNamespaceV1,
    initial_epoch: u64,
    initial_root: PrivacyRootV1,
    accounts: Vec<PrivacyPgcAccountV1>,
}
fn anonymous_pgc_account_table_v1(
    public_keys: &[TwistedElGamalPublicKeyV1],
    encrypted_balances: &[TwistedElGamalCiphertextV1],
) -> Result<Vec<PrivacyPgcAccountV1>, PrivacyReleaseEvidenceErrorClassV1> {
    if public_keys.len() != encrypted_balances.len() {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    Ok(public_keys
        .iter()
        .zip(encrypted_balances)
        .map(|(public_key, encrypted_balance)| PrivacyPgcAccountV1 {
            public_key: PrivacyP256PointV1::new(*public_key.as_point().as_bytes()),
            encrypted_balance: PrivacyP256CiphertextV1 {
                left: PrivacyP256PointV1::new(*encrypted_balance.left().as_bytes()),
                right: PrivacyP256PointV1::new(*encrypted_balance.right().as_bytes()),
            },
        })
        .collect())
}
fn anonymous_pgc_bootstrap_material_v1(
    public_keys: &[TwistedElGamalPublicKeyV1],
    encrypted_balances: &[TwistedElGamalCiphertextV1],
    balances: &[u32],
    randomness: &[SecretScalarV1],
    total_supply: u32,
    case_kind: PrivacyReleaseCaseKindV1,
) -> Result<AnonymousPgcBootstrapMaterialV1, PrivacyReleaseEvidenceErrorClassV1> {
    const MAXIMUM_ACCOUNT_COUNT: usize = 64;
    let account_count = public_keys.len();
    if account_count == 0
        || account_count > MAXIMUM_ACCOUNT_COUNT
        || encrypted_balances.len() != account_count
        || balances.len() != account_count
        || randomness.len() != account_count
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let observed_supply = balances
        .iter()
        .try_fold(0_u64, |sum, balance| sum.checked_add(u64::from(*balance)))
        .and_then(|sum| u32::try_from(sum).ok())
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    if observed_supply != total_supply {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let namespace = PrivacyNamespaceV1::new(
        PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
        PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 {
            pool_id: PrivacyPoolIdV1::new([0x89; 32]),
        }),
    );
    let accounts = anonymous_pgc_account_table_v1(public_keys, encrypted_balances)?;
    let initial_root = compute_privacy_pgc_account_state_root_v1(
        namespace,
        PGC_BOOTSTRAP_INITIAL_EPOCH_V1,
        total_supply,
        &accounts,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    if initial_root.is_zero() {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let bootstrap = PrivacyPgcAccountBootstrapV1 {
        namespace,
        initial_root,
        initial_epoch: PGC_BOOTSTRAP_INITIAL_EPOCH_V1,
        total_supply,
        accounts: accounts.clone(),
    };
    bootstrap
        .validate()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let bootstrap_digest = bootstrap
        .digest()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let namespace_encoding = norito::to_bytes(&namespace)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let compiled = compiled_privacy_profile_v1(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let parameters = AnonymousPgcParametersV1::get()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let binding = TranscriptBindingV1 {
        network_id: &[0x81; 32],
        genesis_hash: [0x81; 32],
        action_index: 0,
        statement_digest: *bootstrap_digest.as_bytes(),
        parameter_id: *compiled.parameter_id.as_bytes(),
        parameter_digest: *compiled.parameter_digest.as_bytes(),
        verifier_digest: *compiled.verifier_digest.as_bytes(),
        statement_schema_digest: *compiled.statement_schema_digest.as_bytes(),
        engine_manifest_digest: *compiled.engine_manifest_digest.as_bytes(),
        generator_digest: parameters.generator_digest(),
    };
    let statement = AnonymousPgcBootstrapStatementV1::new(
        &namespace_encoding,
        *initial_root.as_bytes(),
        PGC_BOOTSTRAP_INITIAL_EPOCH_V1,
        total_supply,
        public_keys,
        encrypted_balances,
        binding,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let witness = AnonymousPgcBootstrapWitnessV1 {
        balances,
        randomness,
    };
    let mut rng = EvidenceRng06::new(stage_purpose_seed_v1(
        PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
        case_kind,
        b"account-bootstrap-proof",
    )?);
    let proof = prove_bootstrap(&statement, &witness, &mut rng)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?
        .encode();
    let proof = PrivacyPgcBootstrapProofBytesV1::new(proof);
    let effect = verify_bootstrap_encoded(&statement, proof.as_bytes())
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected)?;
    let bootstrap_proof_digest = proof
        .digest()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let recomputed_root = compute_privacy_pgc_account_state_root_v1(
        bootstrap.namespace,
        bootstrap.initial_epoch,
        bootstrap.total_supply,
        &bootstrap.accounts,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    if recomputed_root != bootstrap.initial_root
        || statement.initial_root() != *bootstrap.initial_root.as_bytes()
        || statement.initial_epoch() != bootstrap.initial_epoch
        || statement.total_supply() != bootstrap.total_supply
        || statement.account_count() != bootstrap.accounts.len()
        || statement.bootstrap_table_digest() == [0; 32]
        || effect.total_supply() != bootstrap.total_supply
        || effect.account_count() != bootstrap.accounts.len()
        || effect.bootstrap_table_digest() != statement.bootstrap_table_digest()
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let canonical_bootstrap = norito::encode_canonical(&bootstrap)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let mut public_statement_material = Vec::new();
    public_statement_material
        .extend_from_slice(b"iroha.privacy.release.anonymous-pgc.bootstrap-public-statement.v1");
    public_statement_material.extend_from_slice(
        &u64::try_from(canonical_bootstrap.len())
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
            .to_be_bytes(),
    );
    public_statement_material.extend_from_slice(&canonical_bootstrap);
    append_p256_binding_material_v1(&mut public_statement_material, &binding);
    Ok(AnonymousPgcBootstrapMaterialV1 {
        public_statement_material,
        proof: proof.bytes,
        bootstrap_digest: *bootstrap_digest.as_bytes(),
        bootstrap_proof_digest: *bootstrap_proof_digest.as_bytes(),
        namespace,
        initial_epoch: PGC_BOOTSTRAP_INITIAL_EPOCH_V1,
        initial_root,
        accounts,
    })
}
fn anonymous_pgc_binding_v1(
    statement_digest: [u8; 32],
) -> Result<TranscriptBindingV1<'static>, PrivacyReleaseEvidenceErrorClassV1> {
    let parameters = AnonymousPgcParametersV1::get()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let compiled = compiled_privacy_profile_v1(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    if compiled.parameter_digest.as_bytes() != &parameters.parameter_digest() {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    Ok(TranscriptBindingV1 {
        network_id: &[0x81; 32],
        genesis_hash: [0x81; 32],
        action_index: 0,
        statement_digest,
        parameter_id: *compiled.parameter_id.as_bytes(),
        parameter_digest: *compiled.parameter_digest.as_bytes(),
        verifier_digest: *compiled.verifier_digest.as_bytes(),
        statement_schema_digest: *compiled.statement_schema_digest.as_bytes(),
        engine_manifest_digest: *compiled.engine_manifest_digest.as_bytes(),
        generator_digest: parameters.generator_digest(),
    })
}
fn anonymous_pgc_statement_material_v1(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    binding: &TranscriptBindingV1<'_>,
) -> Vec<u8> {
    let mut material = Vec::with_capacity(384);
    material.extend_from_slice(b"iroha.privacy.release.anonymous-pgc.public-statement.v1");
    material.extend_from_slice(
        &u32::try_from(statement.anonymity_set_size())
            .expect("closed PGC anonymity-set size fits u32")
            .to_be_bytes(),
    );
    material.extend_from_slice(
        &u32::try_from(statement.recipient_count())
            .expect("closed PGC recipient count fits u32")
            .to_be_bytes(),
    );
    material.extend_from_slice(&statement.memo_and_ledger_digest());
    append_p256_binding_material_v1(&mut material, binding);
    material
}
fn evidence_secret_scalar_v1(value: u64) -> SecretScalarV1 {
    let mut bytes = [0_u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    SecretScalarV1::from_bytes(bytes).expect("non-zero closed evidence scalar is canonical")
}
fn append_p256_binding_material_v1(material: &mut Vec<u8>, binding: &TranscriptBindingV1<'_>) {
    material.extend_from_slice(binding.network_id);
    material.extend_from_slice(&binding.genesis_hash);
    material.extend_from_slice(&binding.action_index.to_be_bytes());
    material.extend_from_slice(&binding.statement_digest);
    material.extend_from_slice(&binding.parameter_id);
    material.extend_from_slice(&binding.parameter_digest);
    material.extend_from_slice(&binding.verifier_digest);
    material.extend_from_slice(&binding.statement_schema_digest);
    material.extend_from_slice(&binding.engine_manifest_digest);
    material.extend_from_slice(&binding.generator_digest);
}
fn run_bootle_lantern_stage_v1(
    case_kind: PrivacyReleaseCaseKindV1,
) -> Result<StageMaterialV1, PrivacyReleaseEvidenceErrorClassV1> {
    const GENESIS_HASH: [u8; 32] = [0x32; 32];
    let protocol_id = PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1;
    let maximum = case_kind == PrivacyReleaseCaseKindV1::MaximumShapeResource;
    let profile = compiled_privacy_profile_v1(protocol_id)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let mut attributes = [[0_u8; 8]; BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1];
    if maximum {
        for (index, attribute) in attributes.iter_mut().enumerate() {
            *attribute = [u8::try_from(index + 1)
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
                8];
        }
    } else {
        attributes[1] = [1; 8];
    }
    let required_disclosure_bitmap = if maximum { u8::MAX } else { 0b0000_0010 };
    let allowed_value_ceiling = usize::try_from(BOOTLE_LANTERN_MAX_ALLOWED_VALUES_PER_ATTRIBUTE_V1)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let allowed_values = attributes
        .iter()
        .copied()
        .enumerate()
        .map(|(index, attribute)| {
            let values = if required_disclosure_bitmap & (1_u8 << index) != 0 {
                if maximum {
                    (1..=allowed_value_ceiling)
                        .map(|ordinal| {
                            let byte = u8::try_from(ordinal).map_err(|_| {
                                PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant
                            })?;
                            Ok(BootleLanternAttributeValueV1::new([byte; 8]))
                        })
                        .collect::<Result<Vec<_>, _>>()?
                } else {
                    vec![BootleLanternAttributeValueV1::new(attribute)]
                }
            } else {
                Vec::new()
            };
            Ok(BootleLanternAllowedAttributeValuesV1 { values })
        })
        .collect::<Result<Vec<_>, PrivacyReleaseEvidenceErrorClassV1>>()?;
    let context = release_statement_context_from_compiled_profile_v1(
        &profile,
        "taira-privacy-release-evidence-v1"
            .parse()
            .expect("closed evidence chain ID is canonical"),
        3,
        PrivacyTransactionIntentDigestV1::new([1; 32]),
    );
    let mut keygen_rng = EvidenceRng06::new(stage_purpose_seed_v1(
        protocol_id,
        case_kind,
        b"bootle-issuer-keygen",
    )?);
    let issuer_key_pair = BootleLanternIssuerKeyPairV1::generate_with_rng_v1(
        PrivacyParameterIdV1::new([13; 32]),
        &mut keygen_rng,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let policy = issuer_key_pair
        .active_policy_v1(BootleLanternIssuerPolicyMetadataV1 {
            issuer_id: PrivacyIssuerIdV1::new([11; 32]),
            policy_id: PrivacyPolicyIdV1::new([12; 32]),
            epoch: 1,
            required_disclosure_bitmap,
            allowed_values,
        })
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let issuance_store_directory = tempfile::tempdir()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let issuance_store_root = issuance_store_directory
        .path()
        .join("bootle-issuance-store");
    let issuance_store = BootleLanternFileIssuanceStoreV1::open(
        &issuance_store_root,
        BootleLanternIssuanceStoreConfigV1::default(),
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let mut authorization_rng = EvidenceRng06::new(stage_purpose_seed_v1(
        protocol_id,
        case_kind,
        b"bootle-issuer-authorization",
    )?);
    let authorization = issuer_authorize_blind_issuance_with_rng_v1(
        &issuer_key_pair,
        &context,
        GENESIS_HASH,
        &policy,
        [0xA1; 32],
        10,
        20,
        &issuance_store,
        &mut authorization_rng,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let authorization = BootleLanternIssuanceAuthorizationV1::decode_exact(
        &authorization
            .encode()
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    if maximum
        && (policy.allowed_values.len() != BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1
            || policy
                .allowed_values
                .iter()
                .any(|allowed| allowed.values.len() != allowed_value_ceiling))
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let disclosures = attributes
        .iter()
        .copied()
        .enumerate()
        .filter(|(index, _)| required_disclosure_bitmap & (1_u8 << index) != 0)
        .map(|(index, attribute)| BootleLanternDisclosedAttributeV1 {
            index: u8::try_from(index).expect("closed Bootle attribute index fits u8"),
            value: BootleLanternAttributeValueV1::new(attribute),
        })
        .collect::<Vec<_>>();
    let mut holder_issuance_rng = EvidenceRng06::new(stage_purpose_seed_v1(
        protocol_id,
        case_kind,
        b"bootle-holder-issuance-master",
    )?);
    let (issuance_request, issuance_state) = holder_prepare_blind_issuance_with_rng_v1(
        &context,
        GENESIS_HASH,
        &policy,
        &authorization,
        attributes,
        &mut holder_issuance_rng,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let issuance_request_wire = issuance_request
        .encode()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let mut issuer_issuance_rng = EvidenceRng06::new(stage_purpose_seed_v1(
        protocol_id,
        case_kind,
        b"bootle-issuer-issuance-master",
    )?);
    let issuance_response = issuer_blind_issue_once_encoded_with_rng_v1(
        &issuer_key_pair,
        &context,
        GENESIS_HASH,
        &policy,
        &authorization,
        &issuance_request_wire,
        10,
        &issuance_store,
        &mut issuer_issuance_rng,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let issuance_response_wire = issuance_response
        .encode()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    drop(issuance_store);
    let issuance_store = BootleLanternFileIssuanceStoreV1::open(
        &issuance_store_root,
        BootleLanternIssuanceStoreConfigV1::default(),
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let mut unavailable_issuance_rng = UnavailableIssuanceRngV1;
    let cached_response = issuer_blind_issue_once_encoded_with_rng_v1(
        &issuer_key_pair,
        &context,
        GENESIS_HASH,
        &policy,
        &authorization,
        &issuance_request_wire,
        21,
        &issuance_store,
        &mut unavailable_issuance_rng,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    if cached_response
        .encode()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
        != issuance_response_wire
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let issuance_response =
        BootleLanternBlindIssuanceResponseV1::decode_exact(&issuance_response_wire)
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let credential = holder_finalize_blind_issuance_v1(
        issuance_state,
        &context,
        GENESIS_HASH,
        &policy,
        issuance_response,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let statement = IrohaBootleLanternAnoncredStatementV1 {
        context,
        issuer_id: policy.issuer_id,
        policy_id: policy.policy_id,
        issuer_policy_epoch: policy.epoch,
        issuer_policy_record_digest: policy.record_digest,
        issuer_parameter_id: policy.issuer_parameter_id,
        issuer_parameter_digest: policy.issuer_parameter_digest,
        disclosures,
    };
    let witness = credential
        .presentation_witness_v1(&statement, &policy, GENESIS_HASH)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let mut rng = EvidenceRng06::new(stage_purpose_seed_v1(
        protocol_id,
        case_kind,
        b"bootle-presentation-proof",
    )?);
    let proof = prove_bound_presentation_v1(&statement, &policy, GENESIS_HASH, &witness, &mut rng)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let proof_bytes = proof.encode();
    let proof_cap = u32::try_from(BOOTLE_PROOF_BYTES_V1)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    verify_bound_presentation_encoded_v1(
        &statement,
        &policy,
        GENESIS_HASH,
        &proof_bytes,
        proof_cap,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected)?;
    let original_typed = PrivacyStatementV1::IrohaBootleLanternAnoncredV1(statement.clone());
    let original_material = norito::encode_canonical(&original_typed)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let (public_statement_material, failure_class) = match case_kind {
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd
        | PrivacyReleaseCaseKindV1::MaximumShapeResource => (
            original_material,
            PrivacyReleaseFailureClassV1::NotApplicable,
        ),
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation => {
            let mut mutated = statement.clone();
            let mut intent = *mutated.context.transaction_intent_digest.as_bytes();
            intent[0] ^= 0x80;
            mutated.context.transaction_intent_digest =
                PrivacyTransactionIntentDigestV1::new(intent);
            if verify_bound_presentation_encoded_v1(
                &mutated,
                &policy,
                [0x32; 32],
                &proof_bytes,
                proof_cap,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted);
            }
            (
                norito::encode_canonical(&PrivacyStatementV1::IrohaBootleLanternAnoncredV1(
                    mutated,
                ))
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
                PrivacyReleaseFailureClassV1::PublicStatementBindingRejected,
            )
        }
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation => {
            let mut corrupt_header = proof_bytes.clone();
            let first = corrupt_header
                .first_mut()
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *first ^= 0x80;
            if verify_bound_presentation_encoded_v1(
                &statement,
                &policy,
                [0x32; 32],
                &corrupt_header,
                proof_cap,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
            }
            let mut corrupt_interior = proof_bytes.clone();
            let interior_index = corrupt_interior.len() / 2;
            let interior = corrupt_interior
                .get_mut(interior_index)
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *interior ^= 0x01;
            if verify_bound_presentation_encoded_v1(
                &statement,
                &policy,
                [0x32; 32],
                &corrupt_interior,
                proof_cap,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
            }
            let truncated = proof_bytes
                .get(..proof_bytes.len().saturating_sub(1))
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            if verify_bound_presentation_encoded_v1(
                &statement, &policy, [0x32; 32], truncated, proof_cap,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofTruncationAccepted);
            }
            (
                original_material,
                PrivacyReleaseFailureClassV1::CanonicalWireCorruptionAndTruncationRejected,
            )
        }
    };
    let disclosed_count = u64::try_from(statement.disclosures.len())
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let maximum_allowed_value_count = policy
        .allowed_values
        .iter()
        .map(|allowed| allowed.values.len())
        .max()
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    Ok(StageMaterialV1 {
        public_statement_material,
        proof_artifacts: single_proof_artifact_v1(
            proof_bytes,
            u64::try_from(BOOTLE_PROOF_BYTES_V1).expect("closed Bootle proof size fits u64"),
        ),
        resources: PrivacyReleaseResourceFactsV1 {
            primary_units: disclosed_count,
            primary_ceiling: u64::from(BOOTLE_LANTERN_MAX_DISCLOSED_ATTRIBUTES_V1),
            secondary_units: u64::try_from(maximum_allowed_value_count)
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
            secondary_ceiling: u64::from(BOOTLE_LANTERN_MAX_ALLOWED_VALUES_PER_ATTRIBUTE_V1),
            relation_depth: 8,
            relation_depth_ceiling: 8,
        },
        failure_class,
    })
}
const ZK_AMS_RELEASE_GENESIS_HASH_V1: [u8; 32] = [0x11; 32];
const ZK_AMS_RELEASE_BLOCK_TIMESTAMP_MS_V1: u64 = 1_785_024_000_000;
const ZK_AMS_RELEASE_ADMISSION_ACTION_INDEX_V1: u32 = ZK_AMS_PRIVACY_ACTION_INDEX_V1;
const ZK_AMS_RELEASE_PROVISION_ACTION_INDEX_V1: u32 = ZK_AMS_PRIVACY_ACTION_INDEX_V1;
const ZK_AMS_RELEASE_ADMISSION_CREATION_TIME_MS_V1: u64 = ZK_AMS_RELEASE_BLOCK_TIMESTAMP_MS_V1 - 2;
const ZK_AMS_RELEASE_PROVISION_CREATION_TIME_MS_V1: u64 = ZK_AMS_RELEASE_BLOCK_TIMESTAMP_MS_V1 - 1;
const ZK_AMS_RELEASE_ADMISSION_NONCE_V1: u32 = 21;
const ZK_AMS_RELEASE_PROVISION_NONCE_V1: u32 = 22;
fn run_zk_ams_stage_v1(
    case_kind: PrivacyReleaseCaseKindV1,
) -> Result<StageMaterialV1, PrivacyReleaseEvidenceErrorClassV1> {
    let maximum = case_kind == PrivacyReleaseCaseKindV1::MaximumShapeResource;
    let ring_size = if maximum {
        ZK_AMS_MAX_RING_SIZE_V1
    } else {
        ZK_AMS_MIN_RING_SIZE_V1
    };
    let ring = zk_ams_sorted_ring_v1(ring_size)?;
    let admission =
        zk_ams_admission_lineage_material_v1(&ring, ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1, case_kind)?;
    let signer_index = if maximum { ring_size / 2 } else { 5 };
    let signer_secret = &ring
        .get(signer_index)
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
        .1;
    let key_image = zk_ams_key_image_v1(signer_secret)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let expected_statement = zk_ams_provision_statement_v1(
        &ring,
        key_image,
        admission.next_root,
        admission.next_epoch,
        admission.next_registry_record_digest,
    )?;
    let governance = ZkAmsPrivacyActionGovernanceV1 {
        issuer_id: expected_statement.issuer_id,
        issuer_public_key: expected_statement.issuer_public_key,
        issuer_policy_record_digest: expected_statement.issuer_policy_record_digest,
        registry_id: expected_statement.registry_id,
        registry_record_digest: expected_statement.registry_record_digest,
        policy_id: expected_statement.policy_id,
        policy_digest: expected_statement.policy_digest,
    };
    let PrivacyZkAmsActionV1::ProvisionAccount(provision_action) =
        expected_statement.action.clone()
    else {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    };
    let provision_context = zk_ams_provision_transaction_context_v1()?;
    let admission_intent = validate_zk_ams_privacy_action_transaction_intent_v1(
        &zk_ams_admission_transaction_context_v1()?,
        &admission.statement,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let provision_intent = validate_zk_ams_privacy_action_transaction_intent_v1(
        &provision_context,
        &expected_statement,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    if admission_intent == provision_intent {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let mut rng = EvidenceRng06::new(stage_seed_v1(PrivacyProtocolIdV1::IrohaZkAmsV1, case_kind));
    let prepared = prepare_zk_ams_provision_privacy_action_with_rng_v1(
        provision_context,
        governance,
        provision_action,
        signer_index,
        signer_secret,
        ZK_AMS_RELEASE_GENESIS_HASH_V1,
        &mut rng,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let (statement, provision_proof_bytes) = zk_ams_prepared_release_material_v1(
        prepared,
        ZkAmsPrivacyActionEffectV1::ProvisionAccount,
    )?;
    if statement != expected_statement {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let binding = zk_ams_binding_v1(&statement)?;
    let provision_effect =
        verify_zk_ams_provision_statement_v1(&statement, &binding, &provision_proof_bytes)
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected)?;
    let authoritative_network_id =
        release_network_id_from_genesis_hash(ZK_AMS_RELEASE_GENESIS_HASH_V1);
    if statement.context.network_id != authoritative_network_id
        || statement.context.action_index != ZK_AMS_RELEASE_PROVISION_ACTION_INDEX_V1
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    verify_zk_ams_release_production_envelope_v1(
        &statement,
        &provision_proof_bytes,
        &authoritative_network_id,
        ZK_AMS_RELEASE_GENESIS_HASH_V1,
        ZK_AMS_RELEASE_PROVISION_ACTION_INDEX_V1,
    )?;
    let PrivacyZkAmsActionV1::ProvisionAccount(provision) = &statement.action else {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    };
    if provision.admitted_seed_key_ring.len() != ring_size
        || provision_effect.ring != provision.admitted_seed_key_ring
        || provision_effect.key_image != provision.key_image
        || provision.account_registry_root != admission.next_root
        || provision.account_registry_root_epoch != admission.next_epoch
        || statement.registry_record_digest != admission.next_registry_record_digest
        || provision.admitted_seed_key_ring != admission.admitted_seed_key_ring
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let provision_original_material = zk_ams_statement_material_v1(&statement, &binding)?;
    let secondary_units = u64::try_from(admission.anchor_count)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let (public_statement_material, proof_artifacts, failure_class) = match case_kind {
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd
        | PrivacyReleaseCaseKindV1::MaximumShapeResource => {
            if provision.admitted_seed_key_ring.len() != ZK_AMS_MAX_RING_SIZE_V1 {
                if maximum {
                    return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
                }
            }
            if admission.anchor_count != ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1 {
                return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
            }
            let public_statement_material = ordered_public_statement_material_v1(
                PrivacyProtocolIdV1::IrohaZkAmsV1,
                &[
                    admission.public_statement_material.as_slice(),
                    provision_original_material.as_slice(),
                ],
            )?;
            (
                public_statement_material,
                zk_ams_release_proof_artifacts_v1(admission.proof, provision_proof_bytes),
                PrivacyReleaseFailureClassV1::NotApplicable,
            )
        }
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation => {
            let mut mutated_admission = admission.statement.clone();
            let PrivacyZkAmsActionV1::BatchAdmission(batch) = &mut mutated_admission.action else {
                return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
            };
            batch.next_account_registry_root = PrivacyRootV1::new([0x39; 32]);
            let mutated_admission_binding = zk_ams_binding_v1(&mutated_admission)?;
            if verify_zk_ams_batch_admission_v1(
                &mutated_admission,
                &mutated_admission_binding,
                &admission.proof,
            )
            .is_ok()
                || verify_zk_ams_release_production_envelope_v1(
                    &mutated_admission,
                    &admission.proof,
                    &authoritative_network_id,
                    ZK_AMS_RELEASE_GENESIS_HASH_V1,
                    ZK_AMS_RELEASE_ADMISSION_ACTION_INDEX_V1,
                )
                .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted);
            }
            let mut mutated_provision = statement.clone();
            let PrivacyZkAmsActionV1::ProvisionAccount(provision) = &mut mutated_provision.action
            else {
                return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
            };
            provision.account_registry_root = PrivacyRootV1::new([0x38; 32]);
            let mutated_provision_binding = zk_ams_binding_v1(&mutated_provision)?;
            if verify_zk_ams_provision_statement_v1(
                &mutated_provision,
                &mutated_provision_binding,
                &provision_proof_bytes,
            )
            .is_ok()
                || verify_zk_ams_release_production_envelope_v1(
                    &mutated_provision,
                    &provision_proof_bytes,
                    &authoritative_network_id,
                    ZK_AMS_RELEASE_GENESIS_HASH_V1,
                    ZK_AMS_RELEASE_PROVISION_ACTION_INDEX_V1,
                )
                .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted);
            }
            let mut wrong_network = admission.statement.clone();
            wrong_network.context.network_id = release_network_id_from_genesis_hash([0x12; 32]);
            let wrong_network_binding = zk_ams_binding_v1(&wrong_network)?;
            if verify_zk_ams_batch_admission_v1(
                &wrong_network,
                &wrong_network_binding,
                &admission.proof,
            )
            .is_ok()
                || verify_zk_ams_release_production_envelope_v1(
                    &wrong_network,
                    &admission.proof,
                    &authoritative_network_id,
                    ZK_AMS_RELEASE_GENESIS_HASH_V1,
                    ZK_AMS_RELEASE_ADMISSION_ACTION_INDEX_V1,
                )
                .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted);
            }
            let mut wrong_transaction = statement.clone();
            wrong_transaction.context.transaction_intent_digest =
                admission.statement.context.transaction_intent_digest;
            let wrong_transaction_binding = zk_ams_binding_v1(&wrong_transaction)?;
            if verify_zk_ams_provision_statement_v1(
                &wrong_transaction,
                &wrong_transaction_binding,
                &provision_proof_bytes,
            )
            .is_ok()
                || verify_zk_ams_release_production_envelope_v1(
                    &wrong_transaction,
                    &provision_proof_bytes,
                    &authoritative_network_id,
                    ZK_AMS_RELEASE_GENESIS_HASH_V1,
                    ZK_AMS_RELEASE_PROVISION_ACTION_INDEX_V1,
                )
                .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted);
            }
            let mutated_admission_material =
                zk_ams_statement_material_v1(&mutated_admission, &mutated_admission_binding)?;
            let mutated_provision_material =
                zk_ams_statement_material_v1(&mutated_provision, &mutated_provision_binding)?;
            (
                ordered_public_statement_material_v1(
                    PrivacyProtocolIdV1::IrohaZkAmsV1,
                    &[
                        mutated_admission_material.as_slice(),
                        mutated_provision_material.as_slice(),
                    ],
                )?,
                zk_ams_release_proof_artifacts_v1(admission.proof, provision_proof_bytes),
                PrivacyReleaseFailureClassV1::PublicStatementBindingRejected,
            )
        }
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation => {
            let admission_binding = zk_ams_binding_v1(&admission.statement)?;
            let mut corrupt_batch_header = admission.proof.clone();
            let first = corrupt_batch_header
                .first_mut()
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *first ^= 0x80;
            if verify_zk_ams_batch_admission_v1(
                &admission.statement,
                &admission_binding,
                &corrupt_batch_header,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
            }
            require_zk_ams_release_production_native_rejection_v1(
                verify_zk_ams_release_production_envelope_v1(
                    &admission.statement,
                    &corrupt_batch_header,
                    &authoritative_network_id,
                    ZK_AMS_RELEASE_GENESIS_HASH_V1,
                    ZK_AMS_RELEASE_ADMISSION_ACTION_INDEX_V1,
                ),
                PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted,
            )?;
            let mut corrupt_batch_interior = admission.proof.clone();
            let interior_index = corrupt_batch_interior.len() / 2;
            let interior = corrupt_batch_interior
                .get_mut(interior_index)
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *interior ^= 0x01;
            if verify_zk_ams_batch_admission_v1(
                &admission.statement,
                &admission_binding,
                &corrupt_batch_interior,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
            }
            require_zk_ams_release_production_native_rejection_v1(
                verify_zk_ams_release_production_envelope_v1(
                    &admission.statement,
                    &corrupt_batch_interior,
                    &authoritative_network_id,
                    ZK_AMS_RELEASE_GENESIS_HASH_V1,
                    ZK_AMS_RELEASE_ADMISSION_ACTION_INDEX_V1,
                ),
                PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted,
            )?;
            let truncated_batch = admission
                .proof
                .get(..admission.proof.len().saturating_sub(1))
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            if verify_zk_ams_batch_admission_v1(
                &admission.statement,
                &admission_binding,
                truncated_batch,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofTruncationAccepted);
            }
            require_zk_ams_release_production_native_rejection_v1(
                verify_zk_ams_release_production_envelope_v1(
                    &admission.statement,
                    truncated_batch,
                    &authoritative_network_id,
                    ZK_AMS_RELEASE_GENESIS_HASH_V1,
                    ZK_AMS_RELEASE_ADMISSION_ACTION_INDEX_V1,
                ),
                PrivacyReleaseEvidenceErrorClassV1::ProofTruncationAccepted,
            )?;
            for malformed_batch in zk_ams_batch_admission_adversarial_wires_v1(
                &admission.proof,
                admission.anchor_count,
            )
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
            {
                if verify_zk_ams_batch_admission_v1(
                    &admission.statement,
                    &admission_binding,
                    &malformed_batch,
                )
                .is_ok()
                {
                    return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
                }
                require_zk_ams_release_production_native_rejection_v1(
                    verify_zk_ams_release_production_envelope_v1(
                        &admission.statement,
                        &malformed_batch,
                        &authoritative_network_id,
                        ZK_AMS_RELEASE_GENESIS_HASH_V1,
                        ZK_AMS_RELEASE_ADMISSION_ACTION_INDEX_V1,
                    ),
                    PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted,
                )?;
            }
            let submax_admission = zk_ams_admission_lineage_material_v1(
                &ring,
                ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1 - 1,
                case_kind,
            )?;
            if submax_admission.anchor_count != ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1 - 1 {
                return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
            }
            let submax_binding = zk_ams_binding_v1(&submax_admission.statement)?;
            let submax_malformed = zk_ams_batch_admission_adversarial_wires_v1(
                &submax_admission.proof,
                submax_admission.anchor_count,
            )
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            if submax_malformed.len() != 5 {
                return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
            }
            for malformed_batch in submax_malformed {
                if verify_zk_ams_batch_admission_v1(
                    &submax_admission.statement,
                    &submax_binding,
                    &malformed_batch,
                )
                .is_ok()
                {
                    return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
                }
                require_zk_ams_release_production_native_rejection_v1(
                    verify_zk_ams_release_production_envelope_v1(
                        &submax_admission.statement,
                        &malformed_batch,
                        &authoritative_network_id,
                        ZK_AMS_RELEASE_GENESIS_HASH_V1,
                        ZK_AMS_RELEASE_ADMISSION_ACTION_INDEX_V1,
                    ),
                    PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted,
                )?;
            }
            let oversized_batch_len = usize::try_from(TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1)
                .expect("closed Taira proof-byte ceiling fits usize")
                .checked_add(1)
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            let mut oversized_batch = vec![0_u8; oversized_batch_len];
            oversized_batch[0] = 1;
            if verify_zk_ams_batch_admission_v1(
                &admission.statement,
                &admission_binding,
                &oversized_batch,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
            }
            require_zk_ams_release_production_admission_rejection_v1(
                verify_zk_ams_release_production_envelope_v1(
                    &admission.statement,
                    &oversized_batch,
                    &authoritative_network_id,
                    ZK_AMS_RELEASE_GENESIS_HASH_V1,
                    ZK_AMS_RELEASE_ADMISSION_ACTION_INDEX_V1,
                ),
                PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted,
            )?;
            let mut corrupt_provision_header = provision_proof_bytes.clone();
            let first = corrupt_provision_header
                .first_mut()
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *first ^= 0x80;
            if verify_zk_ams_provision_statement_v1(&statement, &binding, &corrupt_provision_header)
                .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
            }
            require_zk_ams_release_production_native_rejection_v1(
                verify_zk_ams_release_production_envelope_v1(
                    &statement,
                    &corrupt_provision_header,
                    &authoritative_network_id,
                    ZK_AMS_RELEASE_GENESIS_HASH_V1,
                    ZK_AMS_RELEASE_PROVISION_ACTION_INDEX_V1,
                ),
                PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted,
            )?;
            let mut corrupt_provision_interior = provision_proof_bytes.clone();
            let interior_index = corrupt_provision_interior.len() / 2;
            let interior = corrupt_provision_interior
                .get_mut(interior_index)
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *interior ^= 0x01;
            if verify_zk_ams_provision_statement_v1(
                &statement,
                &binding,
                &corrupt_provision_interior,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
            }
            require_zk_ams_release_production_native_rejection_v1(
                verify_zk_ams_release_production_envelope_v1(
                    &statement,
                    &corrupt_provision_interior,
                    &authoritative_network_id,
                    ZK_AMS_RELEASE_GENESIS_HASH_V1,
                    ZK_AMS_RELEASE_PROVISION_ACTION_INDEX_V1,
                ),
                PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted,
            )?;
            let truncated_provision = provision_proof_bytes
                .get(..provision_proof_bytes.len().saturating_sub(1))
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            if verify_zk_ams_provision_statement_v1(&statement, &binding, truncated_provision)
                .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofTruncationAccepted);
            }
            require_zk_ams_release_production_native_rejection_v1(
                verify_zk_ams_release_production_envelope_v1(
                    &statement,
                    truncated_provision,
                    &authoritative_network_id,
                    ZK_AMS_RELEASE_GENESIS_HASH_V1,
                    ZK_AMS_RELEASE_PROVISION_ACTION_INDEX_V1,
                ),
                PrivacyReleaseEvidenceErrorClassV1::ProofTruncationAccepted,
            )?;
            (
                ordered_public_statement_material_v1(
                    PrivacyProtocolIdV1::IrohaZkAmsV1,
                    &[
                        admission.public_statement_material.as_slice(),
                        provision_original_material.as_slice(),
                    ],
                )?,
                zk_ams_release_proof_artifacts_v1(admission.proof, provision_proof_bytes),
                PrivacyReleaseFailureClassV1::CanonicalWireCorruptionAndTruncationRejected,
            )
        }
    };
    Ok(StageMaterialV1 {
        public_statement_material,
        proof_artifacts,
        resources: PrivacyReleaseResourceFactsV1 {
            primary_units: u64::try_from(ring_size)
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
            primary_ceiling: u64::try_from(ZK_AMS_MAX_RING_SIZE_V1)
                .expect("closed ZK-AMS ring ceiling fits u64"),
            secondary_units,
            secondary_ceiling: u64::try_from(ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1)
                .expect("closed ZK-AMS admission-batch ceiling fits u64"),
            relation_depth: u64::try_from(ring_size)
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
            relation_depth_ceiling: u64::try_from(ZK_AMS_MAX_RING_SIZE_V1)
                .expect("closed ZK-AMS cyclic-response ceiling fits u64"),
        },
        failure_class,
    })
}
fn zk_ams_release_proof_artifacts_v1(
    admission_proof: Vec<u8>,
    provision_proof: Vec<u8>,
) -> Vec<ProofArtifactMaterialV1> {
    vec![
        ProofArtifactMaterialV1 {
            proof: admission_proof,
            proof_bytes_ceiling: u64::try_from(MAX_ZK_AMS_BATCH_ADMISSION_PROOF_BYTES_V1)
                .expect("closed ZK-AMS batch proof ceiling fits u64"),
        },
        ProofArtifactMaterialV1 {
            proof: provision_proof,
            proof_bytes_ceiling: u64::try_from(MAX_ZK_AMS_LSAG_PROOF_BYTES_V1)
                .expect("closed ZK-AMS LSAG proof ceiling fits u64"),
        },
    ]
}
fn zk_ams_prepared_release_material_v1(
    prepared: ZkAmsPreparedPrivacyActionV1,
    expected_effect: ZkAmsPrivacyActionEffectV1,
) -> Result<(IrohaZkAmsStatementV1, Vec<u8>), PrivacyReleaseEvidenceErrorClassV1> {
    if prepared.effect() != expected_effect {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let expected_intent = prepared.transaction_intent_digest();
    let expected_statement_digest = prepared.statement_digest();
    let expected_envelope_hash = prepared.proof_envelope_hash();
    let expected_statement_bytes = prepared.statement_bytes();
    let expected_proof_bytes = prepared.proof_bytes();
    let expected_envelope_bytes = prepared.encoded_proof_envelope_bytes();
    let (statement, proof) = {
        let (intent, submission) = prepared
            .release_evidence_payload_v1()
            .privacy_transaction_intent_binding_if_present_v1()
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
            .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
        if intent.as_bytes() != &expected_intent
            || submission.envelope.statement_digest.as_bytes() != &expected_statement_digest
        {
            return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
        }
        let PrivacyStatementV1::IrohaZkAmsV1(statement) = &submission.envelope.statement else {
            return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
        };
        let proof = match (
            &statement.action,
            &submission.envelope.proof,
            expected_effect,
        ) {
            (
                PrivacyZkAmsActionV1::BatchAdmission(_),
                PrivacyProofV1::IrohaZkAmsV1(
                    IrohaZkAmsProofV1::MaskedRelaxedSpartanBatchAdmission(proof),
                ),
                ZkAmsPrivacyActionEffectV1::BatchAdmission,
            )
            | (
                PrivacyZkAmsActionV1::ProvisionAccount(_),
                PrivacyProofV1::IrohaZkAmsV1(IrohaZkAmsProofV1::Ristretto255LsagProvisionAccount(
                    proof,
                )),
                ZkAmsPrivacyActionEffectV1::ProvisionAccount,
            ) => proof.as_bytes(),
            _ => return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant),
        };
        if u32::try_from(proof.len())
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
            != expected_proof_bytes
            || u32::try_from(
                norito::to_bytes(&submission.envelope.statement)
                    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
                    .len(),
            )
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
                != expected_statement_bytes
        {
            return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
        }
        let encoded_envelope = norito::to_bytes(&submission.envelope)
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
        if u32::try_from(encoded_envelope.len())
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
            != expected_envelope_bytes
            || *Hash::new(&encoded_envelope).as_ref() != expected_envelope_hash
        {
            return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
        }
        (statement.clone(), proof.to_vec())
    };
    let signer = KeyPair::try_from_seed(vec![39; 32], Algorithm::Ed25519)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let signed = sign_prepared_zk_ams_privacy_action_v1(prepared, signer.private_key())
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    signed
        .signed_transaction()
        .verify_signature()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected)?;
    let signed_transaction_bytes =
        u32::try_from(norito::codec::encode_adaptive(signed.signed_transaction()).len())
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    if signed.effect() != expected_effect
        || signed.transaction_intent_digest() != expected_intent
        || signed.statement_digest() != expected_statement_digest
        || signed.proof_envelope_hash() != expected_envelope_hash
        || signed.statement_bytes() != expected_statement_bytes
        || signed.proof_bytes() != expected_proof_bytes
        || signed.encoded_proof_envelope_bytes() != expected_envelope_bytes
        || signed.transaction_hash() != *signed.signed_transaction().hash().as_ref()
        || signed.adaptive_signed_transaction_bytes() != signed_transaction_bytes
        || signed.signed_transaction().attachments().is_some()
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let (signed_intent, signed_submission) = signed
        .signed_transaction()
        .payload()
        .privacy_transaction_intent_binding_if_present_v1()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let PrivacyStatementV1::IrohaZkAmsV1(signed_statement) = &signed_submission.envelope.statement
    else {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    };
    if signed_intent.as_bytes() != &expected_intent
        || signed_submission.envelope.statement_digest.as_bytes() != &expected_statement_digest
        || signed_statement != &statement
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let signed_proof = match (
        &signed_statement.action,
        &signed_submission.envelope.proof,
        expected_effect,
    ) {
        (
            PrivacyZkAmsActionV1::BatchAdmission(_),
            PrivacyProofV1::IrohaZkAmsV1(IrohaZkAmsProofV1::MaskedRelaxedSpartanBatchAdmission(
                proof,
            )),
            ZkAmsPrivacyActionEffectV1::BatchAdmission,
        )
        | (
            PrivacyZkAmsActionV1::ProvisionAccount(_),
            PrivacyProofV1::IrohaZkAmsV1(IrohaZkAmsProofV1::Ristretto255LsagProvisionAccount(
                proof,
            )),
            ZkAmsPrivacyActionEffectV1::ProvisionAccount,
        ) => proof.as_bytes(),
        _ => return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant),
    };
    let signed_envelope = norito::to_bytes(&signed_submission.envelope)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    if signed_proof != proof.as_slice()
        || u32::try_from(signed_envelope.len())
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
            != expected_envelope_bytes
        || *Hash::new(&signed_envelope).as_ref() != expected_envelope_hash
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    Ok((statement, proof))
}
struct ZkAmsAdmissionLineageMaterialV1 {
    statement: IrohaZkAmsStatementV1,
    public_statement_material: Vec<u8>,
    proof: Vec<u8>,
    anchor_count: usize,
    next_root: PrivacyRootV1,
    next_epoch: u64,
    next_registry_record_digest: PrivacyZkAmsRegistryRecordDigestV1,
    admitted_seed_key_ring: Vec<PrivacyZkAmsSeedPublicKeyV1>,
}
fn zk_ams_admission_lineage_material_v1(
    ring: &[([u8; 32], ZkAmsSeedSecretV1)],
    admission_batch_size: usize,
    case_kind: PrivacyReleaseCaseKindV1,
) -> Result<ZkAmsAdmissionLineageMaterialV1, PrivacyReleaseEvidenceErrorClassV1> {
    if ring.len() < ZK_AMS_MIN_RING_SIZE_V1
        || ring.len() > ZK_AMS_MAX_RING_SIZE_V1
        || admission_batch_size == 0
        || admission_batch_size > ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1
        || ring.len() < admission_batch_size
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let issuer_signing_key = P256SigningKey::from_bytes((&[7_u8; 32]).into())
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let issuer_id = PrivacyIssuerIdV1::new([0x31; 32]);
    let policy_id = PrivacyPolicyIdV1::new([0x35; 32]);
    let registry_id = PrivacyZkAmsRegistryIdV1::new([0x33; 32]);
    let issuer_public_key = zk_ams_issuer_key_v1()?;
    let policy_digest = PrivacyPolicyDigestV1::new([0x36; 32]);
    let issuer_policy_record_digest = zk_ams_issuer_policy_record_digest_v1(
        issuer_id,
        policy_id,
        issuer_public_key,
        policy_digest,
    );
    let credentials = ring
        .iter()
        .enumerate()
        .map(|(index, (public, _))| {
            let index = u8::try_from(index)
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            let subject_byte = 0x41_u8
                .checked_add(index)
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            let nonce_byte = 0x51_u8
                .checked_add(index)
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            Ok(PrivacyZkAmsPersonhoodCredentialV1 {
                version: ZK_AMS_PHC_VERSION_V1,
                issuer_id,
                policy_id,
                subject_commitment: PrivacyZkAmsSubjectCommitmentV1::new([subject_byte; 32]),
                seed_public_key: PrivacyZkAmsSeedPublicKeyV1::new(*public),
                credential_nonce: PrivacyZkAmsCredentialNonceV1::new([nonce_byte; 32]),
            })
        })
        .collect::<Result<Vec<_>, PrivacyReleaseEvidenceErrorClassV1>>()?;
    let all_anchors = credentials
        .iter()
        .map(|credential| PrivacyZkAmsAdmissionAnchorV1 {
            phc_hash: credential.digest(),
            seed_public_key: credential.seed_public_key,
        })
        .collect::<Vec<_>>();
    let batch_start = ring
        .len()
        .checked_sub(admission_batch_size)
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let prestate_anchors = &all_anchors[..batch_start];
    let anchors = &all_anchors[batch_start..];
    let mut current_root = PrivacyRootV1::new([0x37; 32]);
    let mut current_epoch = 1_u64;
    for prior_batch in prestate_anchors.chunks(ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1) {
        let next_epoch = current_epoch
            .checked_add(1)
            .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
        let batch_size = u32::try_from(prior_batch.len())
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
        current_root = prior_batch.iter().copied().enumerate().fold(
            current_root,
            |prior_root, (index, anchor)| {
                zk_ams_registry_transition_root_v1(
                    registry_id,
                    prior_root,
                    current_epoch,
                    next_epoch,
                    batch_size,
                    u32::try_from(index).expect("closed ZK-AMS admission index fits u32"),
                    anchor,
                )
            },
        );
        current_epoch = next_epoch;
    }
    let registry_record_digest = zk_ams_registry_record_digest_v1(
        issuer_id,
        registry_id,
        policy_id,
        issuer_policy_record_digest,
        policy_digest,
        current_root,
        current_epoch,
    );
    let next_epoch = current_epoch
        .checked_add(1)
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let signatures = credentials[batch_start..]
        .iter()
        .map(|credential| {
            let signature: P256Signature = issuer_signing_key
                .sign_prehash(credential.digest().as_bytes())
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
            let signature = signature.normalize_s().unwrap_or(signature);
            Ok(<[u8; 64]>::from(signature.to_bytes()))
        })
        .collect::<Result<Vec<_>, PrivacyReleaseEvidenceErrorClassV1>>()?;
    if anchors.len() != admission_batch_size || signatures.len() != admission_batch_size {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let batch_size = u32::try_from(anchors.len())
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let next_root =
        anchors
            .iter()
            .copied()
            .enumerate()
            .fold(current_root, |prior_root, (index, anchor)| {
                zk_ams_registry_transition_root_v1(
                    registry_id,
                    prior_root,
                    current_epoch,
                    next_epoch,
                    batch_size,
                    u32::try_from(index).expect("closed ZK-AMS admission index fits u32"),
                    anchor,
                )
            });
    let governance = ZkAmsPrivacyActionGovernanceV1 {
        issuer_id,
        issuer_public_key,
        issuer_policy_record_digest,
        registry_id,
        registry_record_digest,
        policy_id,
        policy_digest,
    };
    let action = PrivacyZkAmsBatchAdmissionV1 {
        account_registry_root: current_root,
        account_registry_root_epoch: current_epoch,
        next_account_registry_root: next_root,
        next_account_registry_root_epoch: next_epoch,
        anchors: anchors.to_vec(),
    };
    let witnesses = credentials[batch_start..]
        .iter()
        .zip(&signatures)
        .zip(&ring[batch_start..])
        .map(|((credential, signature), (_, secret))| {
            ZkAmsBatchCredentialWitnessV1::new(credential, signature, secret)
        })
        .collect::<Vec<_>>();
    if witnesses.len() != admission_batch_size {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let config = ZkAmsMaskedProverConfigV1::new(1)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let mut proof_purpose = Vec::from(b"state-lineage-batch-admission-proof-size".as_slice());
    proof_purpose.extend_from_slice(
        &u32::try_from(admission_batch_size)
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
            .to_be_bytes(),
    );
    let mut rng = EvidenceRng06::new(stage_purpose_seed_v1(
        PrivacyProtocolIdV1::IrohaZkAmsV1,
        case_kind,
        &proof_purpose,
    )?);
    let prepared = prepare_zk_ams_batch_admission_privacy_action_with_rng_v1(
        zk_ams_admission_transaction_context_v1()?,
        governance,
        action,
        &witnesses,
        config,
        ZK_AMS_RELEASE_GENESIS_HASH_V1,
        &mut rng,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let (statement, proof) =
        zk_ams_prepared_release_material_v1(prepared, ZkAmsPrivacyActionEffectV1::BatchAdmission)?;
    let binding = zk_ams_binding_v1(&statement)?;
    let effect = verify_zk_ams_batch_admission_v1(&statement, &binding, &proof)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected)?;
    let authoritative_network_id =
        release_network_id_from_genesis_hash(ZK_AMS_RELEASE_GENESIS_HASH_V1);
    if statement.context.network_id != authoritative_network_id
        || statement.context.action_index != ZK_AMS_RELEASE_ADMISSION_ACTION_INDEX_V1
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    verify_zk_ams_release_production_envelope_v1(
        &statement,
        &proof,
        &authoritative_network_id,
        ZK_AMS_RELEASE_GENESIS_HASH_V1,
        ZK_AMS_RELEASE_ADMISSION_ACTION_INDEX_V1,
    )?;
    if effect.issuer_id != issuer_id
        || effect.policy_id != policy_id
        || effect.registry_id != registry_id
        || effect.current_root != current_root
        || effect.current_epoch != current_epoch
        || effect.next_root != next_root
        || effect.next_epoch != next_epoch
        || effect.anchors != anchors
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let next_registry_record_digest = zk_ams_registry_record_digest_v1(
        issuer_id,
        registry_id,
        policy_id,
        issuer_policy_record_digest,
        policy_digest,
        next_root,
        next_epoch,
    );
    let mut public_statement_material = zk_ams_statement_material_v1(&statement, &binding)?;
    public_statement_material
        .extend_from_slice(b"iroha.privacy.release.zk-ams.authoritative-prestate-lineage.v1");
    public_statement_material.extend_from_slice(&1_u64.to_be_bytes());
    public_statement_material.extend_from_slice(PrivacyRootV1::new([0x37; 32]).as_bytes());
    public_statement_material.extend_from_slice(
        &u32::try_from(prestate_anchors.len())
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
            .to_be_bytes(),
    );
    for anchor in prestate_anchors {
        public_statement_material.extend_from_slice(anchor.phc_hash.as_bytes());
        public_statement_material.extend_from_slice(anchor.seed_public_key.as_bytes());
    }
    public_statement_material.extend_from_slice(&current_epoch.to_be_bytes());
    public_statement_material.extend_from_slice(current_root.as_bytes());
    let admitted_seed_key_ring = all_anchors
        .iter()
        .map(|anchor| anchor.seed_public_key)
        .collect::<Vec<_>>();
    if admitted_seed_key_ring
        != ring
            .iter()
            .map(|(public, _)| PrivacyZkAmsSeedPublicKeyV1::new(*public))
            .collect::<Vec<_>>()
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    Ok(ZkAmsAdmissionLineageMaterialV1 {
        statement,
        public_statement_material,
        proof,
        anchor_count: anchors.len(),
        next_root,
        next_epoch,
        next_registry_record_digest,
        admitted_seed_key_ring,
    })
}
fn zk_ams_sorted_ring_v1(
    size: usize,
) -> Result<Vec<([u8; 32], ZkAmsSeedSecretV1)>, PrivacyReleaseEvidenceErrorClassV1> {
    let mut ring = (1..=size)
        .map(|index| {
            let mut bytes = [0_u8; 32];
            bytes[0] = u8::try_from(index)
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            let secret = ZkAmsSeedSecretV1::from_bytes(bytes)
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
            Ok((zk_ams_seed_public_key_v1(&secret), secret))
        })
        .collect::<Result<Vec<_>, _>>()?;
    ring.sort_by_key(|(public, _)| *public);
    Ok(ring)
}
fn privacy_release_account_v1(seed: u8) -> Result<AccountId, PrivacyReleaseEvidenceErrorClassV1> {
    let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    Ok(AccountId::new(key_pair.public_key().clone()))
}
fn zk_ams_release_transaction_context_v1(
    creation_time_ms: u64,
    nonce: u32,
) -> Result<ZkAmsPrivacyActionTransactionContextV1, PrivacyReleaseEvidenceErrorClassV1> {
    Ok(ZkAmsPrivacyActionTransactionContextV1 {
        network_id: release_network_id_from_genesis_hash(ZK_AMS_RELEASE_GENESIS_HASH_V1),
        authority: privacy_release_account_v1(39)?,
        creation_time: Duration::from_millis(creation_time_ms),
        time_to_live: Some(Duration::from_secs(60)),
        nonce: NonZeroU32::new(nonce),
        fee_payment: FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(5_000_000)),
        metadata: Metadata::default(),
    })
}
fn zk_ams_admission_transaction_context_v1()
-> Result<ZkAmsPrivacyActionTransactionContextV1, PrivacyReleaseEvidenceErrorClassV1> {
    zk_ams_release_transaction_context_v1(
        ZK_AMS_RELEASE_ADMISSION_CREATION_TIME_MS_V1,
        ZK_AMS_RELEASE_ADMISSION_NONCE_V1,
    )
}
fn zk_ams_provision_transaction_context_v1()
-> Result<ZkAmsPrivacyActionTransactionContextV1, PrivacyReleaseEvidenceErrorClassV1> {
    zk_ams_release_transaction_context_v1(
        ZK_AMS_RELEASE_PROVISION_CREATION_TIME_MS_V1,
        ZK_AMS_RELEASE_PROVISION_NONCE_V1,
    )
}
fn zk_ams_issuer_key_v1() -> Result<PrivacyP256PointV1, PrivacyReleaseEvidenceErrorClassV1> {
    let signing_key = P256SigningKey::from_bytes((&[7_u8; 32]).into())
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let encoded = signing_key.verifying_key().to_encoded_point(true);
    let bytes: [u8; 33] = encoded
        .as_bytes()
        .try_into()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    Ok(PrivacyP256PointV1::new(bytes))
}
fn zk_ams_provision_statement_v1(
    ring: &[([u8; 32], ZkAmsSeedSecretV1)],
    key_image: [u8; 32],
    registry_root: PrivacyRootV1,
    registry_epoch: u64,
    registry_record_digest: PrivacyZkAmsRegistryRecordDigestV1,
) -> Result<IrohaZkAmsStatementV1, PrivacyReleaseEvidenceErrorClassV1> {
    let issuer_id = PrivacyIssuerIdV1::new([0x31; 32]);
    let policy_id = PrivacyPolicyIdV1::new([0x35; 32]);
    let issuer_public_key = zk_ams_issuer_key_v1()?;
    let policy_digest = PrivacyPolicyDigestV1::new([0x36; 32]);
    let governance = ZkAmsPrivacyActionGovernanceV1 {
        issuer_id,
        issuer_public_key,
        issuer_policy_record_digest: zk_ams_issuer_policy_record_digest_v1(
            issuer_id,
            policy_id,
            issuer_public_key,
            policy_digest,
        ),
        registry_id: PrivacyZkAmsRegistryIdV1::new([0x33; 32]),
        registry_record_digest,
        policy_id,
        policy_digest,
    };
    let action = PrivacyZkAmsProvisionAccountV1 {
        account_registry_root: registry_root,
        account_registry_root_epoch: registry_epoch,
        admitted_seed_key_ring: ring
            .iter()
            .map(|(public, _)| PrivacyZkAmsSeedPublicKeyV1::new(*public))
            .collect(),
        account_id: privacy_release_account_v1(40)?,
        key_image: PrivacyZkAmsKeyImageV1::new(key_image),
    };
    prepare_zk_ams_provision_account_transaction_intent_v1(
        &zk_ams_provision_transaction_context_v1()?,
        governance,
        action,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)
}
fn zk_ams_binding_v1(
    statement: &IrohaZkAmsStatementV1,
) -> Result<TranscriptBindingV1<'_>, PrivacyReleaseEvidenceErrorClassV1> {
    let statement_digest = PrivacyStatementV1::IrohaZkAmsV1(statement.clone())
        .digest()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    Ok(TranscriptBindingV1 {
        network_id: statement.context.network_id.as_bytes(),
        genesis_hash: ZK_AMS_RELEASE_GENESIS_HASH_V1,
        action_index: statement.context.action_index,
        statement_digest: *statement_digest.as_bytes(),
        parameter_id: *statement.context.parameter_id.as_bytes(),
        parameter_digest: *statement.context.parameter_digest.as_bytes(),
        verifier_digest: *statement.context.verifier_digest.as_bytes(),
        statement_schema_digest: *statement.context.statement_schema_digest.as_bytes(),
        engine_manifest_digest: *statement.context.engine_manifest_digest.as_bytes(),
        generator_digest: zk_ams_generator_digest_v1(),
    })
}
fn require_zk_ams_release_production_native_rejection_v1(
    result: Result<(), PrivacyReleaseEvidenceErrorClassV1>,
    accepted_class: PrivacyReleaseEvidenceErrorClassV1,
) -> Result<(), PrivacyReleaseEvidenceErrorClassV1> {
    match result {
        Err(PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected) => Ok(()),
        Ok(()) => Err(accepted_class),
        Err(_) => Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant),
    }
}
fn require_zk_ams_release_production_admission_rejection_v1(
    result: Result<(), PrivacyReleaseEvidenceErrorClassV1>,
    accepted_class: PrivacyReleaseEvidenceErrorClassV1,
) -> Result<(), PrivacyReleaseEvidenceErrorClassV1> {
    match result {
        Err(PrivacyReleaseEvidenceErrorClassV1::ProductionEnvelopeRejected) => Ok(()),
        Ok(()) => Err(accepted_class),
        Err(_) => Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant),
    }
}
fn verify_zk_ams_release_production_envelope_v1(
    statement: &IrohaZkAmsStatementV1,
    proof: &[u8],
    authoritative_network_id: &NetworkId,
    genesis_hash: [u8; 32],
    authoritative_action_index: u32,
) -> Result<(), PrivacyReleaseEvidenceErrorClassV1> {
    let profile = compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaZkAmsV1)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let activation = profile.activation_record(PrivacyProtocolLifecycleV1::Active(
        PrivacyActiveLifecycleV1 {
            proposed_at_height: 1,
            activated_at_height: 2,
            state_since_height: 2,
        },
    ));
    let typed_statement = PrivacyStatementV1::IrohaZkAmsV1(statement.clone());
    let statement_digest = typed_statement
        .digest()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let proof_bytes = PrivacyProofBytesV1::new(proof.to_vec());
    let action_proof = match &statement.action {
        PrivacyZkAmsActionV1::BatchAdmission(_) => {
            IrohaZkAmsProofV1::MaskedRelaxedSpartanBatchAdmission(proof_bytes)
        }
        PrivacyZkAmsActionV1::ProvisionAccount(_) => {
            IrohaZkAmsProofV1::Ristretto255LsagProvisionAccount(proof_bytes)
        }
    };
    let envelope = PrivacyProofEnvelopeV1::bind_v1(
        typed_statement,
        PrivacyProofV1::IrohaZkAmsV1(action_proof),
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::ProductionEnvelopeRejected)?;
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let effects = verify_privacy_envelope_v1(
        &envelope,
        PrivacyVerificationContextV1 {
            activation: &activation,
            consensus_limits: &limits,
            network_id: authoritative_network_id,
            genesis_hash,
            current_height: 2,
            expected_action_index: authoritative_action_index,
            block_timestamp_ms: ZK_AMS_RELEASE_BLOCK_TIMESTAMP_MS_V1,
            pgc_state: None,
            orchard_state: None,
            proof_managed_state: None,
            zk_x509_state: None,
            bootle_lantern_policy: None,
            vega_issuer_record: None,
        },
    )
    .map_err(|source| match source {
        PrivacyVerificationErrorV1::NativeZkAms(_) => {
            PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected
        }
        _ => PrivacyReleaseEvidenceErrorClassV1::ProductionEnvelopeRejected,
    })?;
    if effects.protocol_id() != PrivacyProtocolIdV1::IrohaZkAmsV1
        || effects.statement_digest() != statement_digest
        || effects.action_index() != authoritative_action_index
        || effects.encoded_action_bytes() == 0
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    Ok(())
}
fn zk_ams_statement_material_v1(
    statement: &IrohaZkAmsStatementV1,
    binding: &TranscriptBindingV1<'_>,
) -> Result<Vec<u8>, PrivacyReleaseEvidenceErrorClassV1> {
    let mut material =
        norito::encode_canonical(&PrivacyStatementV1::IrohaZkAmsV1(statement.clone()))
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    append_p256_binding_material_v1(&mut material, binding);
    Ok(material)
}
const JINDO_RELEASE_GENESIS_HASH_V1: [u8; 32] = [0xa7; 32];
const JINDO_RELEASE_ACTION_INDEX_V1: u32 = 0;
const JINDO_RELEASE_BLOCK_TIMESTAMP_MS_V1: u64 = 1_800_000_000_124;
fn run_jindo_stage_v1(
    case_kind: PrivacyReleaseCaseKindV1,
) -> Result<StageMaterialV1, PrivacyReleaseEvidenceErrorClassV1> {
    let maximum = case_kind == PrivacyReleaseCaseKindV1::MaximumShapeResource;
    let polynomials = if maximum {
        (0..JINDO_MAX_BATCH_SIZE_V1)
            .map(|polynomial_index| {
                (0..JINDO_MAX_COEFFICIENTS_V1)
                    .map(|coefficient_index| {
                        let value = 1_u64
                            + u64::try_from(polynomial_index)
                                .expect("closed Jindo polynomial index fits u64")
                                * u64::try_from(JINDO_MAX_COEFFICIENTS_V1 + 1)
                                    .expect("closed Jindo coefficient ceiling fits u64")
                            + u64::try_from(coefficient_index)
                                .expect("closed Jindo coefficient index fits u64");
                        jindo_field_v1(value)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    } else {
        vec![
            vec![
                jindo_field_v1(3),
                jindo_field_v1(5),
                jindo_field_v1(7),
                jindo_field_v1(11),
            ],
            vec![jindo_field_v1(13), jindo_field_v1(17)],
            vec![jindo_field_v1(19), jindo_field_v1(23)],
            vec![jindo_field_v1(29), jindo_field_v1(31)],
        ]
    };
    let witness = JindoPrivacyActionWitnessV1::try_new(polynomials, jindo_field_v1(13))
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let context = JindoPrivacyActionTransactionContextV1 {
        network_id: release_network_id_from_genesis_hash(JINDO_RELEASE_GENESIS_HASH_V1),
        authority: AccountId::new(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
                .parse()
                .expect("fixed Jindo evidence authority is canonical"),
        ),
        creation_time: Duration::from_millis(1_800_000_000_123),
        time_to_live: Some(Duration::from_secs(60)),
        nonce: NonZeroU32::new(7),
        fee_payment: FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(5_000_000)),
        metadata: Metadata::default(),
    };
    let mut rng = EvidenceRng06::new(stage_seed_v1(
        PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1,
        case_kind,
    ));
    let prepared = prepare_jindo_privacy_action_with_rng_v1(
        context,
        witness,
        JINDO_RELEASE_GENESIS_HASH_V1,
        &mut rng,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let observed = prepared
        .release_evidence_payload_v1()
        .privacy_transaction_intent_binding_if_present_v1()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected)?
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected)?;
    if observed.0.as_bytes() != &prepared.transaction_intent_digest() {
        return Err(PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected);
    }
    let envelope = &observed.1.envelope;
    let PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(statement) = &envelope.statement
    else {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    };
    let PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(proof) = &envelope.proof else {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    };
    let statement = statement.clone();
    let proof_bytes = proof.as_bytes().to_vec();
    if proof_bytes.len()
        != usize::try_from(prepared.proof_bytes())
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let profile = crate::privacy_profiles::compiled_privacy_profile_v1(
        PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let binding = TranscriptBindingV1 {
        network_id: statement.context.network_id.as_bytes(),
        genesis_hash: JINDO_RELEASE_GENESIS_HASH_V1,
        action_index: statement.context.action_index,
        statement_digest: prepared.statement_digest(),
        parameter_id: *profile.parameter_id.as_bytes(),
        parameter_digest: *profile.parameter_digest.as_bytes(),
        verifier_digest: *profile.verifier_digest.as_bytes(),
        statement_schema_digest: *profile.statement_schema_digest.as_bytes(),
        engine_manifest_digest: *profile.engine_manifest_digest.as_bytes(),
        generator_digest: jindo_crs_digest_v1(),
    };
    let proof_ceiling =
        u32::try_from(JINDO_NATIVE_PROOF_BYTES_V1).expect("closed Jindo proof ceiling fits u32");
    verify_batched_evaluation_v1(&statement, &proof_bytes, &binding, proof_ceiling)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected)?;
    let authoritative_network_id =
        release_network_id_from_genesis_hash(JINDO_RELEASE_GENESIS_HASH_V1);
    if statement.context.network_id != authoritative_network_id
        || statement.context.action_index != JINDO_RELEASE_ACTION_INDEX_V1
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    verify_jindo_release_production_envelope_v1(
        &statement,
        &proof_bytes,
        &authoritative_network_id,
        JINDO_RELEASE_GENESIS_HASH_V1,
        JINDO_RELEASE_ACTION_INDEX_V1,
    )?;
    let original_typed = PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(statement.clone());
    let original_material = norito::encode_canonical(&original_typed)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let (public_statement_material, failure_class) = match case_kind {
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd
        | PrivacyReleaseCaseKindV1::MaximumShapeResource => (
            original_material,
            PrivacyReleaseFailureClassV1::NotApplicable,
        ),
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation => {
            let mut mutated = statement.clone();
            let mut mutated_intent = *mutated.context.transaction_intent_digest.as_bytes();
            mutated_intent[0] ^= 0x80;
            mutated.context.transaction_intent_digest =
                PrivacyTransactionIntentDigestV1::new(mutated_intent);
            let mutated_typed =
                PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(mutated.clone());
            let mutated_digest = mutated_typed
                .digest()
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
            let mutated_binding = TranscriptBindingV1 {
                statement_digest: *mutated_digest.as_bytes(),
                ..binding
            };
            if verify_batched_evaluation_v1(&mutated, &proof_bytes, &mutated_binding, proof_ceiling)
                .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted);
            }
            require_jindo_release_production_native_rejection_v1(
                verify_jindo_release_production_envelope_v1(
                    &mutated,
                    &proof_bytes,
                    &authoritative_network_id,
                    JINDO_RELEASE_GENESIS_HASH_V1,
                    JINDO_RELEASE_ACTION_INDEX_V1,
                ),
                PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted,
            )?;
            (
                norito::encode_canonical(&mutated_typed)
                    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
                PrivacyReleaseFailureClassV1::PublicStatementBindingRejected,
            )
        }
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation => {
            let mut corrupt = proof_bytes.clone();
            let first = corrupt
                .first_mut()
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *first ^= 0x80;
            if verify_batched_evaluation_v1(&statement, &corrupt, &binding, proof_ceiling).is_ok() {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
            }
            require_jindo_release_production_native_rejection_v1(
                verify_jindo_release_production_envelope_v1(
                    &statement,
                    &corrupt,
                    &authoritative_network_id,
                    JINDO_RELEASE_GENESIS_HASH_V1,
                    JINDO_RELEASE_ACTION_INDEX_V1,
                ),
                PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted,
            )?;
            let mut corrupt_interior = proof_bytes.clone();
            let interior_index = corrupt_interior.len() / 2;
            let interior = corrupt_interior
                .get_mut(interior_index)
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *interior ^= 0x01;
            if verify_batched_evaluation_v1(&statement, &corrupt_interior, &binding, proof_ceiling)
                .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
            }
            require_jindo_release_production_native_rejection_v1(
                verify_jindo_release_production_envelope_v1(
                    &statement,
                    &corrupt_interior,
                    &authoritative_network_id,
                    JINDO_RELEASE_GENESIS_HASH_V1,
                    JINDO_RELEASE_ACTION_INDEX_V1,
                ),
                PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted,
            )?;
            let truncated = proof_bytes
                .get(..proof_bytes.len().saturating_sub(1))
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            if verify_batched_evaluation_v1(&statement, truncated, &binding, proof_ceiling).is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofTruncationAccepted);
            }
            require_jindo_release_production_native_rejection_v1(
                verify_jindo_release_production_envelope_v1(
                    &statement,
                    truncated,
                    &authoritative_network_id,
                    JINDO_RELEASE_GENESIS_HASH_V1,
                    JINDO_RELEASE_ACTION_INDEX_V1,
                ),
                PrivacyReleaseEvidenceErrorClassV1::ProofTruncationAccepted,
            )?;
            (
                original_material,
                PrivacyReleaseFailureClassV1::CanonicalWireCorruptionAndTruncationRejected,
            )
        }
    };
    let max_coefficient_count = prepared
        .coefficient_counts()
        .iter()
        .copied()
        .max()
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    Ok(StageMaterialV1 {
        public_statement_material,
        proof_artifacts: single_proof_artifact_v1(
            proof_bytes,
            u64::try_from(JINDO_NATIVE_PROOF_BYTES_V1)
                .expect("closed Jindo proof ceiling fits u64"),
        ),
        resources: PrivacyReleaseResourceFactsV1 {
            primary_units: u64::from(prepared.polynomial_count()),
            primary_ceiling: u64::try_from(JINDO_MAX_BATCH_SIZE_V1)
                .expect("closed Jindo batch ceiling fits u64"),
            secondary_units: u64::from(max_coefficient_count),
            secondary_ceiling: u64::try_from(JINDO_MAX_COEFFICIENTS_V1)
                .expect("closed Jindo coefficient ceiling fits u64"),
            relation_depth: u64::try_from(JINDO_RING_DEGREE_V1)
                .expect("closed Jindo ring degree fits u64"),
            relation_depth_ceiling: u64::try_from(JINDO_RING_DEGREE_V1)
                .expect("closed Jindo ring degree fits u64"),
        },
        failure_class,
    })
}
fn require_jindo_release_production_native_rejection_v1(
    result: Result<(), PrivacyReleaseEvidenceErrorClassV1>,
    accepted_class: PrivacyReleaseEvidenceErrorClassV1,
) -> Result<(), PrivacyReleaseEvidenceErrorClassV1> {
    match result {
        Err(PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected) => Ok(()),
        Ok(()) => Err(accepted_class),
        Err(_) => Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant),
    }
}
fn verify_jindo_release_production_envelope_v1(
    statement: &iroha_data_model::privacy::IrohaJindoPolynomialCommitmentStatementV1,
    proof: &[u8],
    authoritative_network_id: &NetworkId,
    genesis_hash: [u8; 32],
    authoritative_action_index: u32,
) -> Result<(), PrivacyReleaseEvidenceErrorClassV1> {
    let profile =
        compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1)
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let activation = profile.activation_record(PrivacyProtocolLifecycleV1::Active(
        PrivacyActiveLifecycleV1 {
            proposed_at_height: 1,
            activated_at_height: 2,
            state_since_height: 2,
        },
    ));
    let typed_statement = PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(statement.clone());
    let statement_digest = typed_statement
        .digest()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let envelope = PrivacyProofEnvelopeV1::bind_v1(
        typed_statement,
        PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(PrivacyProofBytesV1::new(proof.to_vec())),
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::ProductionEnvelopeRejected)?;
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let effects = verify_privacy_envelope_v1(
        &envelope,
        PrivacyVerificationContextV1 {
            activation: &activation,
            consensus_limits: &limits,
            network_id: authoritative_network_id,
            genesis_hash,
            current_height: 2,
            expected_action_index: authoritative_action_index,
            block_timestamp_ms: JINDO_RELEASE_BLOCK_TIMESTAMP_MS_V1,
            pgc_state: None,
            orchard_state: None,
            proof_managed_state: None,
            zk_x509_state: None,
            bootle_lantern_policy: None,
            vega_issuer_record: None,
        },
    )
    .map_err(|source| match source {
        PrivacyVerificationErrorV1::NativeJindo(_) => {
            PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected
        }
        _ => PrivacyReleaseEvidenceErrorClassV1::ProductionEnvelopeRejected,
    })?;
    if effects.protocol_id() != PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1
        || effects.statement_digest() != statement_digest
        || effects.action_index() != authoritative_action_index
        || effects.encoded_action_bytes() == 0
        || !matches!(effects.into_ledger(), VerifiedPrivacyLedgerEffectsV1::None)
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    Ok(())
}
fn jindo_field_v1(value: u64) -> PrivacyJindoFieldElementV1 {
    let mut encoding = [0_u8; 32];
    encoding[..8].copy_from_slice(&value.to_le_bytes());
    PrivacyJindoFieldElementV1::new(encoding)
}
const ORCHARD_RELEASE_GENESIS_HASH_V1: [u8; 32] = [0x4f; 32];
fn orchard_release_statement_v1(
    context: PrivacyStatementContextV1,
    draft: &OrchardBundleDraftV1,
) -> Result<OrchardHalo2ActionsStatementV1, PrivacyReleaseEvidenceErrorClassV1> {
    let domain_id = DomainId::try_new("privacy", "universal")
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let asset_name = "orchard_release"
        .parse::<Name>()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let value_balance = match draft.value_balance.cmp(&0) {
        core::cmp::Ordering::Equal => PrivacyValueBalanceV1::balanced(),
        core::cmp::Ordering::Less => PrivacyValueBalanceV1 {
            direction: PrivacyValueBalanceDirectionV1::IntoPool,
            amount: u128::from(draft.value_balance.unsigned_abs()),
        },
        core::cmp::Ordering::Greater => PrivacyValueBalanceV1 {
            direction: PrivacyValueBalanceDirectionV1::OutOfPool,
            amount: u128::from(draft.value_balance.unsigned_abs()),
        },
    };
    Ok(OrchardHalo2ActionsStatementV1 {
        context,
        asset_definition_id: AssetDefinitionId::derive_from_components(domain_id, asset_name),
        public_balance_scope: iroha_data_model::asset::AssetBalanceScope::Global,
        pool_id: PrivacyPoolIdV1::new([0x4e; 32]),
        anchor: PrivacyRootV1::new(draft.anchor),
        anchor_epoch: 1,
        actions: draft
            .actions
            .iter()
            .map(|action| PrivacyOrchardActionV1 {
                nullifier: action.nullifier,
                randomized_key: action.randomized_key,
                note_commitment: action.note_commitment,
                ephemeral_key: action.ephemeral_key,
                encrypted_note: action.encrypted_note.to_vec(),
                outgoing_ciphertext: action.outgoing_ciphertext.to_vec(),
                value_commitment: action.value_commitment,
            })
            .collect(),
        value_balance,
        expiry_height: 100,
    })
}
fn orchard_release_transaction_payload_v1(
    envelope: PrivacyProofEnvelopeV1,
) -> Result<TransactionPayload, PrivacyReleaseEvidenceErrorClassV1> {
    let authority = privacy_release_account_v1(0x4d)?;
    let mut builder = TransactionBuilder::new(
        release_network_id_from_genesis_hash(ORCHARD_RELEASE_GENESIS_HASH_V1),
        authority,
        FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(5_000_000)),
    )
    .with_instructions([SubmitPrivacyProofV1::new(envelope)])
    .with_metadata(Metadata::default());
    builder.set_creation_time(Duration::from_millis(1_800_000_000_321));
    builder.set_ttl(Duration::from_secs(60));
    builder.set_nonce(NonZeroU32::new(9).expect("fixture nonce is non-zero"));
    builder
        .into_payload()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)
}
fn run_orchard_stage_v1(
    case_kind: PrivacyReleaseCaseKindV1,
) -> Result<StageMaterialV1, PrivacyReleaseEvidenceErrorClassV1> {
    let maximum = case_kind == PrivacyReleaseCaseKindV1::MaximumShapeResource;
    let action_count = if maximum { ORCHARD_MAX_ACTIONS_V1 } else { 1 };
    let (anchor, spends, changes, spend_count, expected_value_balance) = if maximum {
        let fixture = orchard_maximum_spend_fixture_v1()?;
        let spend_count = fixture.spends.len();
        let expected_value_balance = i64::try_from(fixture.total_value)
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
        (
            fixture.anchor,
            fixture.spends,
            Vec::new(),
            spend_count,
            expected_value_balance,
        )
    } else {
        let seed = 0x31_u8;
        let value = 17_u64;
        (
            orchard_empty_root_v1(),
            Vec::new(),
            vec![OrchardChangeProverInputV1::new(
                orchard_spending_key_v1(seed),
                Scope::External,
                u32::from(seed),
                value,
                [seed; 512],
            )],
            0,
            -i64::try_from(value)
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
        )
    };
    let mut rng = EvidenceRng09::new(stage_seed_v1(
        PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
        case_kind,
    ));
    let prepared = prepare_orchard_bundle_v1_with_rng(
        anchor,
        spends,
        changes,
        u8::try_from(action_count)
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
        &mut rng,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let profile = compiled_privacy_profile_v1(PrivacyProtocolIdV1::OrchardHalo2ActionsV1)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let draft_context = PrivacyStatementContextV1 {
        network_id: release_network_id_from_genesis_hash(ORCHARD_RELEASE_GENESIS_HASH_V1),
        action_index: 0,
        transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([0; 32]),
        parameter_id: profile.parameter_id,
        parameter_digest: profile.parameter_digest,
        verifier_digest: profile.verifier_digest,
        statement_schema_digest: profile.statement_schema_digest,
        engine_manifest_digest: profile.engine_manifest_digest,
    };
    let mut statement = orchard_release_statement_v1(draft_context, prepared.public_draft())?;
    let draft_typed_statement = PrivacyStatementV1::OrchardHalo2ActionsV1(statement.clone());
    let draft_envelope = PrivacyProofEnvelopeV1::bind_v1(
        draft_typed_statement,
        PrivacyProofV1::OrchardHalo2ActionsV1(PrivacyProofBytesV1::new(Vec::new())),
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    if !profile.matches_envelope_v1(&draft_envelope) {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let canonical_intent = orchard_release_transaction_payload_v1(draft_envelope)?
        .privacy_transaction_intent_digest_v1()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    if canonical_intent.is_zero() {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    statement.context.transaction_intent_digest = canonical_intent;
    let consensus_limits = PrivacyConsensusLimitsV1::taira_default();
    let consensus_binding = PrivacyNativeConsensusBindingV1::new(
        &statement.context,
        ORCHARD_RELEASE_GENESIS_HASH_V1,
        &consensus_limits,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let proved =
        authorize_orchard_bundle_v1(prepared, consensus_binding.clone(), &consensus_limits)
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let proof_bytes = proved.authorization;
    let public = proved.public;
    verify_orchard_bundle_v1(&public, &proof_bytes, &consensus_limits)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected)?;
    if public.consensus_binding != consensus_binding
        || public.anchor != *statement.anchor.as_bytes()
        || public.actions.len() != statement.actions.len()
        || public
            .actions
            .iter()
            .zip(&statement.actions)
            .any(|(native, typed)| {
                native.nullifier != typed.nullifier
                    || native.randomized_key != typed.randomized_key
                    || native.note_commitment != typed.note_commitment
                    || native.ephemeral_key != typed.ephemeral_key
                    || native.encrypted_note.as_slice() != typed.encrypted_note.as_slice()
                    || native.outgoing_ciphertext.as_slice() != typed.outgoing_ciphertext.as_slice()
                    || native.value_commitment != typed.value_commitment
            })
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let final_typed_statement = PrivacyStatementV1::OrchardHalo2ActionsV1(statement);
    let final_envelope = PrivacyProofEnvelopeV1::bind_v1(
        final_typed_statement,
        PrivacyProofV1::OrchardHalo2ActionsV1(PrivacyProofBytesV1::new(proof_bytes.clone())),
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    if !profile.matches_envelope_v1(&final_envelope) {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let final_payload = orchard_release_transaction_payload_v1(final_envelope.clone())?;
    let validated_intent = final_payload
        .validate_privacy_transaction_intent_binding_v1()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected)?;
    if validated_intent != canonical_intent
        || public.consensus_binding.transaction_intent_digest != canonical_intent
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    if public.actions.len() != action_count || public.value_balance != expected_value_balance {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    if maximum && (spend_count != ORCHARD_MAX_ACTIONS_V1 || u64::from(ORCHARD_TREE_DEPTH_V1) != 32)
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let (public_statement_material, failure_class) = match case_kind {
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd
        | PrivacyReleaseCaseKindV1::MaximumShapeResource => (
            orchard_public_material_v1(&public)?,
            PrivacyReleaseFailureClassV1::NotApplicable,
        ),
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation => {
            let mut mutated = public.clone();
            mutated.consensus_binding.genesis_hash[0] ^= 0x80;
            if verify_orchard_bundle_v1(&mutated, &proof_bytes, &consensus_limits).is_ok() {
                return Err(PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted);
            }
            let mut changed_intent_envelope = final_envelope.clone();
            let PrivacyStatementV1::OrchardHalo2ActionsV1(changed_intent_statement) =
                &mut changed_intent_envelope.statement
            else {
                return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
            };
            let mut changed_intent = *changed_intent_statement
                .context
                .transaction_intent_digest
                .as_bytes();
            changed_intent[0] ^= 0x40;
            changed_intent_statement.context.transaction_intent_digest =
                PrivacyTransactionIntentDigestV1::new(changed_intent);
            changed_intent_envelope.statement_digest =
                changed_intent_envelope
                    .statement
                    .digest()
                    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            if orchard_release_transaction_payload_v1(changed_intent_envelope)?
                .validate_privacy_transaction_intent_binding_v1()
                .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted);
            }
            let mut changed_action_envelope = final_envelope.clone();
            let PrivacyStatementV1::OrchardHalo2ActionsV1(changed_action_statement) =
                &mut changed_action_envelope.statement
            else {
                return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
            };
            let changed_ciphertext = changed_action_statement
                .actions
                .first_mut()
                .and_then(|action| action.encrypted_note.first_mut())
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *changed_ciphertext ^= 0x20;
            changed_action_envelope.statement_digest =
                changed_action_envelope
                    .statement
                    .digest()
                    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            if orchard_release_transaction_payload_v1(changed_action_envelope)?
                .validate_privacy_transaction_intent_binding_v1()
                .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted);
            }
            (
                orchard_public_material_v1(&mutated)?,
                PrivacyReleaseFailureClassV1::PublicStatementBindingRejected,
            )
        }
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation => {
            let mut corrupt = proof_bytes.clone();
            let first = corrupt
                .first_mut()
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *first ^= 0x80;
            if verify_orchard_bundle_v1(&public, &corrupt, &consensus_limits).is_ok() {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
            }
            let mut corrupt_interior = proof_bytes.clone();
            let interior_index = corrupt_interior.len() / 2;
            let interior = corrupt_interior
                .get_mut(interior_index)
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *interior ^= 0x01;
            if verify_orchard_bundle_v1(&public, &corrupt_interior, &consensus_limits).is_ok() {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
            }
            let truncated = proof_bytes
                .get(..proof_bytes.len().saturating_sub(1))
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            if verify_orchard_bundle_v1(&public, truncated, &consensus_limits).is_ok() {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofTruncationAccepted);
            }
            (
                orchard_public_material_v1(&public)?,
                PrivacyReleaseFailureClassV1::CanonicalWireCorruptionAndTruncationRejected,
            )
        }
    };
    let proof_bytes_ceiling = orchard_authorization_wire_size_v1(ORCHARD_MAX_ACTIONS_V1)
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    Ok(StageMaterialV1 {
        public_statement_material,
        proof_artifacts: single_proof_artifact_v1(
            proof_bytes,
            u64::try_from(proof_bytes_ceiling).expect("closed Orchard proof ceiling fits u64"),
        ),
        resources: PrivacyReleaseResourceFactsV1 {
            primary_units: u64::try_from(public.actions.len())
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
            primary_ceiling: u64::try_from(ORCHARD_MAX_ACTIONS_V1)
                .expect("closed Orchard action ceiling fits u64"),
            secondary_units: u64::try_from(spend_count)
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
            secondary_ceiling: u64::try_from(ORCHARD_MAX_ACTIONS_V1)
                .expect("closed Orchard wallet-input ceiling fits u64"),
            relation_depth: u64::from(ORCHARD_TREE_DEPTH_V1),
            relation_depth_ceiling: u64::from(ORCHARD_TREE_DEPTH_V1),
        },
        failure_class,
    })
}
struct OrchardMaximumSpendFixtureV1 {
    anchor: [u8; 32],
    spends: Vec<OrchardSpendProverInputV1>,
    total_value: u64,
}
fn orchard_maximum_spend_fixture_v1()
-> Result<OrchardMaximumSpendFixtureV1, PrivacyReleaseEvidenceErrorClassV1> {
    if usize::from(ORCHARD_TREE_DEPTH_V1) != 32 {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let spending_key = orchard_spending_key_v1(0x41);
    let viewing_key = FullViewingKey::from(&spending_key);
    let recipient = viewing_key.address_at(0_u32, Scope::External);
    let values = [17_u64, 19_u64];
    let notes = values
        .iter()
        .copied()
        .enumerate()
        .map(|(index, value)| {
            let mut rho_bytes = [0_u8; 32];
            rho_bytes[0] = u8::try_from(index + 1)
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            let rho = Option::<Rho>::from(Rho::from_bytes(&rho_bytes))
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
            let note_seed = 0x61_u8
                .checked_add(
                    u8::try_from(index)
                        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
                )
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            let random_seed = (1_u8..=u8::MAX)
                .find_map(|counter| {
                    let mut bytes = [note_seed; 32];
                    bytes[0] = counter;
                    Option::<RandomSeed>::from(RandomSeed::from_bytes(bytes, &rho))
                })
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
            Option::<Note>::from(Note::from_parts(
                recipient,
                NoteValue::from_raw(value),
                rho,
                random_seed,
                NoteVersion::V2,
            ))
            .ok_or(PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if notes.len() != ORCHARD_MAX_ACTIONS_V1 {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let leaves = notes
        .iter()
        .map(|note| {
            let commitment = ExtractedNoteCommitment::from(note.commitment());
            MerkleHashOrchard::from_cmx(&commitment)
        })
        .collect::<Vec<_>>();
    let tree_depth = usize::from(ORCHARD_TREE_DEPTH_V1);
    let mut levels = Vec::with_capacity(tree_depth + 1);
    levels.push(leaves);
    for level_index in 0..tree_depth {
        let level = Level::from(
            u8::try_from(level_index)
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
        );
        let current = &levels[level_index];
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut position = 0;
        while position < current.len() {
            let left = current[position];
            let right = current
                .get(position + 1)
                .copied()
                .unwrap_or_else(|| MerkleHashOrchard::empty_root(level));
            next.push(MerkleHashOrchard::combine(level, &left, &right));
            position += 2;
        }
        levels.push(next);
    }
    let mut anchor = None;
    let mut spends = Vec::with_capacity(notes.len());
    for (index, note) in notes.into_iter().enumerate() {
        let auth_path: [MerkleHashOrchard; ORCHARD_TREE_DEPTH_V1 as usize] =
            core::array::from_fn(|level_index| {
                let level = Level::from(
                    u8::try_from(level_index).expect("closed Orchard path level fits u8"),
                );
                let sibling = (index >> level_index) ^ 1;
                levels[level_index]
                    .get(sibling)
                    .copied()
                    .unwrap_or_else(|| MerkleHashOrchard::empty_root(level))
            });
        let merkle_path = MerklePath::from_parts(
            u32::try_from(index)
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
            auth_path,
        );
        let derived_anchor = merkle_path
            .root(ExtractedNoteCommitment::from(note.commitment()))
            .to_bytes();
        if let Some(expected_anchor) = anchor {
            if expected_anchor != derived_anchor {
                return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
            }
        } else {
            anchor = Some(derived_anchor);
        }
        spends.push(OrchardSpendProverInputV1::new(
            spending_key,
            note,
            merkle_path,
        ));
    }
    let total_value = values.into_iter().try_fold(0_u64, |total, value| {
        total
            .checked_add(value)
            .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)
    })?;
    Ok(OrchardMaximumSpendFixtureV1 {
        anchor: anchor.ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
        spends,
        total_value,
    })
}
fn orchard_spending_key_v1(seed: u8) -> SpendingKey {
    (1_u8..=u8::MAX)
        .find_map(|counter| {
            let mut bytes = [seed; 32];
            bytes[0] = counter;
            bytes[15] = counter.rotate_left(3);
            bytes[31] = seed ^ counter.rotate_right(1);
            Option::<SpendingKey>::from(SpendingKey::from_bytes(bytes))
        })
        .expect("closed evidence seed admits an Orchard spending key")
}
fn orchard_public_material_v1(
    public: &OrchardBundlePublicV1,
) -> Result<Vec<u8>, PrivacyReleaseEvidenceErrorClassV1> {
    let mut material = Vec::with_capacity(2_048);
    material.extend_from_slice(b"iroha.privacy.release.orchard.public-statement.v1");
    let binding_digest = public
        .consensus_binding
        .digest()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    material.extend_from_slice(binding_digest.as_bytes());
    material.extend_from_slice(&public.anchor);
    material.extend_from_slice(&public.value_balance.to_be_bytes());
    material.push(
        u8::try_from(public.actions.len())
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
    );
    for action in &public.actions {
        material.extend_from_slice(&action.nullifier);
        material.extend_from_slice(&action.randomized_key);
        material.extend_from_slice(&action.note_commitment);
        material.extend_from_slice(&action.ephemeral_key);
        material.extend_from_slice(&action.encrypted_note);
        material.extend_from_slice(&action.outgoing_ciphertext);
        material.extend_from_slice(&action.value_commitment);
    }
    Ok(material)
}
include!("privacy_release_evidence/verange_and_rng.rs");
#[cfg(test)]
mod tests {
    include!("privacy_release_evidence/tests.rs");
}
