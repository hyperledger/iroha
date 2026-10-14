//! Canonical fixture and roundtrip checks for `Soracloud` V1 manifests.
use iroha_crypto::{
    Algorithm, Hash, KeyPair,
    fhe_bfv::{
        ram_lfe_bfv_parameters_v1, registered_bfv_key_switch_decomposition_chain_digest,
        registered_bfv_parameter_digest, registered_bfv_rns_modulus_chain_digest,
    },
};

use iroha_data_model::soracloud::SoraInrouManifestV1;
use iroha_data_model::soracloud::SoracloudManifestError;
use iroha_data_model::{
    Decode, Encode,
    account::AccountId,
    soracloud::{
        AGENT_APARTMENT_MANIFEST_VERSION_V1, AgentApartmentManifestV1, AgentSpendLimitV1,
        AgentToolCapabilityV1, AgentUpgradePolicyV1, BfvRefreshTranscriptModeV1,
        CIPHERTEXT_QUERY_PROOF_VERSION_V1, CIPHERTEXT_QUERY_RESPONSE_VERSION_V1,
        CIPHERTEXT_QUERY_SPEC_VERSION_V1, CIPHERTEXT_STATE_RECORD_VERSION_V1,
        CiphertextInclusionProofV1, CiphertextQueryMetadataLevelV1, CiphertextQueryResponseV1,
        CiphertextQueryResultItemV1, CiphertextQuerySpecV1, CiphertextStateMetadataV1,
        CiphertextStateRecordV1, DECRYPTION_AUTHORITY_POLICY_VERSION_V1,
        DECRYPTION_REQUEST_VERSION_V1, DecryptionAuthorityModeV1, DecryptionAuthorityPolicyV1,
        DecryptionRequestV1, FHE_EXECUTION_POLICY_VERSION_V1, FHE_GOVERNANCE_BUNDLE_VERSION_V1,
        FHE_JOB_SPEC_VERSION_V1, FHE_PARAM_SET_VERSION_V1, FheDeterministicRoundingModeV1,
        FheExecutionPolicyV1, FheGovernanceBundleV1, FheJobInputRefV1, FheJobOperationV1,
        FheJobSpecV1, FheParamLifecycleV1, FheParamSetV1, FheSchemeV1, SECRET_ENVELOPE_VERSION_V1,
        SORA_CONTAINER_MANIFEST_VERSION_V1, SORA_DEPLOYMENT_BUNDLE_VERSION_V1,
        SORA_SERVICE_MANIFEST_VERSION_V1, SORA_STATE_BINDING_VERSION_V1, SORACLOUD_XOR_SCALE,
        SecretEnvelopeEncryptionV1, SecretEnvelopeV1, SoraArtifactKindV1, SoraArtifactRefV1,
        SoraCapabilityPolicyV1, SoraCertifiedResponsePolicyV1, SoraConfigExportTargetV1,
        SoraConfigExportV1, SoraContainerManifestRefV1, SoraContainerManifestV1,
        SoraContainerRuntimeV1, SoraDeploymentBundleV1, SoraInrouPlacementTargetV1,
        SoraLeaseVolumeBindingV1, SoraLeaseVolumeKindV1, SoraLifecycleHooksV1,
        SoraMailboxContractV1, SoraNetworkAllowlistEntryV1, SoraNetworkPolicyV1,
        SoraResourceLimitsV1, SoraRolloutPolicyV1, SoraRouteTargetV1, SoraRouteVisibilityV1,
        SoraServiceExecutionPlaneV1, SoraServiceHandlerClassV1, SoraServiceHandlerV1,
        SoraServiceManifestV1, SoraStateBindingV1, SoraStateEncryptionV1, SoraStateMutabilityV1,
        SoraStateScopeV1, SoraTlsModeV1,
    },
    sorafs::pin_registry::StorageClass,
};
use iroha_model_base::peer::PeerId;
use iroha_primitives::numeric::{Numeric, Quantity};

use norito::json::{self, FastJsonWrite, JsonDeserialize, JsonSerialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    fs,
    num::{NonZeroU16, NonZeroU32, NonZeroU64},
    path::Path,
};
const CONTAINER_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/soracloud/sora_container_manifest_v1.json"
));
const SERVICE_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/soracloud/sora_service_manifest_v1.json"
));
const STATE_BINDING_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/soracloud/sora_state_binding_v1.json"
));
const DEPLOYMENT_BUNDLE_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/soracloud/sora_deployment_bundle_v1.json"
));
const AGENT_APARTMENT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/soracloud/agent_apartment_manifest_v1.json"
));
const FHE_PARAM_SET_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/soracloud/fhe_param_set_v1.json"
));
const FHE_EXECUTION_POLICY_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/soracloud/fhe_execution_policy_v1.json"
));
fn xor_quantity_nanos(value: u128) -> Quantity {
    Quantity::from_canonical_numeric(Numeric::new(value, SORACLOUD_XOR_SCALE))
        .expect("u128 nano-XOR manifest fixture fits Quantity")
}

fn expected_inrou_placement_targets(count: u16) -> BTreeSet<SoraInrouPlacementTargetV1> {
    (0..count)
        .map(|index| {
            let index = u8::try_from(index).expect("fixture target index fits u8");
            let account_key =
                KeyPair::try_from_seed(vec![0x80_u8.wrapping_add(index); 32], Algorithm::Ed25519)
                    .expect("fixture validator account key");
            let peer_key =
                KeyPair::try_from_seed(vec![0xA0_u8.wrapping_add(index); 32], Algorithm::BlsNormal)
                    .expect("fixture consensus peer key");
            SoraInrouPlacementTargetV1 {
                validator_account_id: AccountId::new(account_key.public_key().clone()),
                peer_id: PeerId::from(peer_key.public_key().clone()).to_string(),
            }
        })
        .collect()
}
const FHE_GOVERNANCE_BUNDLE_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/soracloud/fhe_governance_bundle_v1.json"
));
const SECRET_ENVELOPE_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/soracloud/secret_envelope_v1.json"
));
const CIPHERTEXT_STATE_RECORD_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/soracloud/ciphertext_state_record_v1.json"
));
const FHE_JOB_SPEC_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/soracloud/fhe_job_spec_v1.json"
));
const DECRYPTION_AUTHORITY_POLICY_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/soracloud/decryption_authority_policy_v1.json"
));
const DECRYPTION_REQUEST_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/soracloud/decryption_request_v1.json"
));
const CIPHERTEXT_QUERY_SPEC_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/soracloud/ciphertext_query_spec_v1.json"
));
const CIPHERTEXT_QUERY_RESPONSE_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/soracloud/ciphertext_query_response_v1.json"
));
fn sample_hash(seed: u8) -> Hash {
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = seed.wrapping_add(u8::try_from(index).expect("index fits in u8"));
    }
    Hash::prehashed(bytes)
}
fn expected_fhe_evaluation_key_digest() -> Hash {
    "6018ed3cb8315df01d8e1f7910afab8bd02c978cbf96570ff9561f5812a8874b"
        .parse()
        .expect("fixture evaluation-key digest")
}
fn expected_fhe_refresh_transcript_digest() -> Hash {
    "5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b"
        .parse()
        .expect("fixture refresh transcript digest")
}
fn expected_fhe_public_key_proof_statement_digest() -> Hash {
    sample_hash(89)
}
fn expected_fhe_bootstrap_key_proof_statement_digest() -> Hash {
    "5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7d"
        .parse()
        .expect("fixture bootstrap-key proof statement digest")
}
fn expected_state_binding() -> SoraStateBindingV1 {
    SoraStateBindingV1 {
        schema_version: SORA_STATE_BINDING_VERSION_V1,
        binding_name: "session_store".parse().expect("valid name"),
        scope: SoraStateScopeV1::ServiceState,
        mutability: SoraStateMutabilityV1::ReadWrite,
        encryption: SoraStateEncryptionV1::ClientCiphertext,
        key_prefix: "/state/session".to_string(),
        max_item_bytes: NonZeroU64::new(4_096).expect("nonzero"),
        max_total_bytes: NonZeroU64::new(262_144).expect("nonzero"),
    }
}
fn expected_container_manifest() -> SoraContainerManifestV1 {
    SoraContainerManifestV1 {
        schema_version: SORA_CONTAINER_MANIFEST_VERSION_V1,
        runtime: SoraContainerRuntimeV1::Ivm,
        bundle_hash: sample_hash(7),
        bundle_path: "/bundles/webapp.to".to_string(),
        entrypoint: "main".to_string(),
        args: vec!["--http".to_string(), "--port=8080".to_string()],
        env: BTreeMap::from([
            ("APP_ENV".to_string(), "production".to_string()),
            ("LOG_LEVEL".to_string(), "info".to_string()),
        ]),
        inrou: None,
        required_config_names: Vec::new(),
        required_secret_names: Vec::new(),
        config_exports: Vec::<SoraConfigExportV1>::new(),
        capabilities: SoraCapabilityPolicyV1 {
            network: SoraNetworkPolicyV1::Allowlist(vec![
                SoraNetworkAllowlistEntryV1::new("api.sora.internal", [443]),
                SoraNetworkAllowlistEntryV1::new("wallet.sora.internal", [443]),
            ]),
            allow_state_writes: true,
            allow_model_inference: true,
            allow_model_training: false,
        },
        resources: SoraResourceLimitsV1 {
            cpu_millis: NonZeroU32::new(750).expect("nonzero"),
            memory_bytes: NonZeroU64::new(536_870_912).expect("nonzero"),
            ephemeral_storage_bytes: NonZeroU64::new(2_147_483_648).expect("nonzero"),
            max_open_files_per_process: NonZeroU32::new(512).expect("nonzero"),
            max_tasks: NonZeroU16::new(64).expect("nonzero"),
        },
        lifecycle: SoraLifecycleHooksV1 {
            start_grace_secs: NonZeroU32::new(30).expect("nonzero"),
            stop_grace_secs: NonZeroU32::new(20).expect("nonzero"),
            healthcheck_path: Some("/healthz".to_string()),
        },
    }
}
fn expected_service_route() -> SoraRouteTargetV1 {
    SoraRouteTargetV1 {
        host: "portal.sora".to_string(),
        path_prefix: "/app".to_string(),
        service_port: NonZeroU16::new(8080).expect("nonzero"),
        visibility: SoraRouteVisibilityV1::Public,
        tls_mode: SoraTlsModeV1::Required,
    }
}
fn expected_patient_records_binding() -> SoraStateBindingV1 {
    SoraStateBindingV1 {
        schema_version: SORA_STATE_BINDING_VERSION_V1,
        binding_name: "patient_records".parse().expect("valid name"),
        scope: SoraStateScopeV1::ConfidentialState,
        mutability: SoraStateMutabilityV1::AppendOnly,
        encryption: SoraStateEncryptionV1::FheCiphertext,
        key_prefix: "/state/health".to_string(),
        max_item_bytes: NonZeroU64::new(16_384).expect("nonzero"),
        max_total_bytes: NonZeroU64::new(16_777_216).expect("nonzero"),
    }
}
fn expected_service_manifest() -> SoraServiceManifestV1 {
    SoraServiceManifestV1 {
        schema_version: SORA_SERVICE_MANIFEST_VERSION_V1,
        service_name: "web_portal".parse().expect("valid name"),
        service_version: "2026.02.0".to_string(),
        execution_plane: SoraServiceExecutionPlaneV1::DeterministicService,
        container: SoraContainerManifestRefV1 {
            manifest_hash: sample_hash(17),
            expected_schema_version: SORA_CONTAINER_MANIFEST_VERSION_V1,
        },
        replicas: NonZeroU16::new(3).expect("nonzero"),
        placement_targets: BTreeSet::new(),
        route: Some(expected_service_route()),
        rollout: SoraRolloutPolicyV1 {
            canary_percent: 0,
            max_unavailable_replicas: 1,
            health_window_secs: NonZeroU32::new(45).expect("nonzero"),
            automatic_rollback_failures: NonZeroU32::new(3).expect("nonzero"),
        },
        economics: iroha_data_model::soracloud::SoraHttpServiceEconomicsV1::default(),
        state_bindings: vec![expected_state_binding(), expected_patient_records_binding()],
        lease_volumes: Vec::new(),
        handlers: vec![
            SoraServiceHandlerV1 {
                handler_name: "assets".parse().expect("valid name"),
                class: SoraServiceHandlerClassV1::Asset,
                entrypoint: "serve_assets".to_string(),
                route_path: Some("/assets".to_string()),
                certified_response: SoraCertifiedResponsePolicyV1::StateCommitment,
                mailbox: None,
            },
            SoraServiceHandlerV1 {
                handler_name: "query".parse().expect("valid name"),
                class: SoraServiceHandlerClassV1::Query,
                entrypoint: "serve_query".to_string(),
                route_path: Some("/query".to_string()),
                certified_response: SoraCertifiedResponsePolicyV1::AuditReceipt,
                mailbox: None,
            },
            SoraServiceHandlerV1 {
                handler_name: "update".parse().expect("valid name"),
                class: SoraServiceHandlerClassV1::Update,
                entrypoint: "apply_update".to_string(),
                route_path: Some("/update".to_string()),
                certified_response: SoraCertifiedResponsePolicyV1::None,
                mailbox: Some(SoraMailboxContractV1 {
                    queue_name: "updates".parse().expect("valid name"),
                    max_pending_messages: NonZeroU32::new(1_024).expect("nonzero"),
                    max_message_bytes: NonZeroU64::new(65_536).expect("nonzero"),
                    retention_blocks: NonZeroU32::new(1_440).expect("nonzero"),
                }),
            },
            SoraServiceHandlerV1 {
                handler_name: "ciphertext_update".parse().expect("valid name"),
                class: SoraServiceHandlerClassV1::Update,
                entrypoint: "apply_ciphertext_update".to_string(),
                route_path: Some("/ciphertext/update".to_string()),
                certified_response: SoraCertifiedResponsePolicyV1::None,
                mailbox: Some(SoraMailboxContractV1 {
                    queue_name: "ciphertext_updates".parse().expect("valid name"),
                    max_pending_messages: NonZeroU32::new(256).expect("nonzero"),
                    max_message_bytes: NonZeroU64::new(131_072).expect("nonzero"),
                    retention_blocks: NonZeroU32::new(2_880).expect("nonzero"),
                }),
            },
        ],
        artifacts: vec![
            SoraArtifactRefV1 {
                kind: SoraArtifactKindV1::StaticAsset,
                artifact_hash: sample_hash(17),
                artifact_path: "/public/index.html".to_string(),
                handler_name: Some("assets".parse().expect("valid name")),
            },
            SoraArtifactRefV1 {
                kind: SoraArtifactKindV1::Journal,
                artifact_hash: sample_hash(17),
                artifact_path: "/journals/portal.journal".to_string(),
                handler_name: Some("update".parse().expect("valid name")),
            },
            SoraArtifactRefV1 {
                kind: SoraArtifactKindV1::Checkpoint,
                artifact_hash: sample_hash(17),
                artifact_path: "/checkpoints/portal.chk".to_string(),
                handler_name: Some("ciphertext_update".parse().expect("valid name")),
            },
        ],
    }
}
fn expected_deployment_bundle() -> SoraDeploymentBundleV1 {
    let container = expected_container_manifest();
    let mut service = expected_service_manifest();
    service.container.manifest_hash = Hash::new(Encode::encode(&container));
    SoraDeploymentBundleV1 {
        schema_version: SORA_DEPLOYMENT_BUNDLE_VERSION_V1,
        container,
        service,
    }
}

fn expected_inrou_http_deployment_bundle() -> SoraDeploymentBundleV1 {
    let mut container = expected_container_manifest();
    container.runtime = SoraContainerRuntimeV1::Inrou;
    container.entrypoint = "/app/bin/service".to_string();
    container.inrou = Some(
        json::from_str::<SoraInrouManifestV1>(
            r#"{
              "schema_version": 1,
              "guest_images": {
                "x86_64": {
                  "kernel_image_path": "/inrou/x86_64/vmlinux",
                  "rootfs_image_path": "/inrou/x86_64/rootfs.ext4",
                  "initrd_image_path": null,
                  "published_artifact": {
                    "manifest_digest_hex": "3131313131313131313131313131313131313131313131313131313131313131",
                    "content_cid": "bafyr6ibrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrge"
                  }
                },
                "aarch64": {
                  "kernel_image_path": "/inrou/aarch64/vmlinux",
                  "rootfs_image_path": "/inrou/aarch64/rootfs.ext4",
                  "initrd_image_path": null,
                  "published_artifact": {
                    "manifest_digest_hex": "3232323232323232323232323232323232323232323232323232323232323232",
                    "content_cid": "bafyr6ibsgizdemrsgizdemrsgizdemrsgizdemrsgizdemrsgizdemrsgi"
                  }
                }
              }
            }"#,
        )
        .expect("valid inrou manifest fixture"),
    );
    container.capabilities.network = SoraNetworkPolicyV1::Isolated;
    let mut service = expected_service_manifest();
    service.execution_plane = SoraServiceExecutionPlaneV1::HttpService;
    service.replicas = NonZeroU16::new(2).expect("nonzero");
    service.placement_targets = expected_inrou_placement_targets(service.replicas.get());
    service.state_bindings.clear();
    service.handlers.clear();
    service.artifacts.clear();
    service.lease_volumes = vec![
        SoraLeaseVolumeBindingV1 {
            volume_name: "root_disk".parse().expect("valid name"),
            kind: SoraLeaseVolumeKindV1::PersistentRootLeaseVolume,
            storage_class: StorageClass::Warm,
            mount_path: "/".to_string(),
            max_total_bytes: NonZeroU64::new(8 * 1024 * 1024 * 1024).expect("nonzero"),
        },
        SoraLeaseVolumeBindingV1 {
            volume_name: "shared_state".parse().expect("valid name"),
            kind: SoraLeaseVolumeKindV1::ServiceLeaseVolume,
            storage_class: StorageClass::Warm,
            mount_path: "/var/lib/soracloud/volumes/shared_state".to_string(),
            max_total_bytes: NonZeroU64::new(1024 * 1024).expect("nonzero"),
        },
    ];
    service.container.manifest_hash = Hash::new(Encode::encode(&container));
    SoraDeploymentBundleV1 {
        schema_version: SORA_DEPLOYMENT_BUNDLE_VERSION_V1,
        container,
        service,
    }
}
fn expected_agent_apartment_manifest() -> AgentApartmentManifestV1 {
    AgentApartmentManifestV1 {
        schema_version: AGENT_APARTMENT_MANIFEST_VERSION_V1,
        apartment_name: "ops_agent".parse().expect("valid name"),
        container: SoraContainerManifestRefV1 {
            manifest_hash: sample_hash(33),
            expected_schema_version: SORA_CONTAINER_MANIFEST_VERSION_V1,
        },
        tool_capabilities: vec![
            AgentToolCapabilityV1 {
                tool: "soracloud.deploy".to_string(),
                max_invocations_per_epoch: NonZeroU32::new(120).expect("nonzero"),
                allow_network: true,
                allow_filesystem_write: false,
            },
            AgentToolCapabilityV1 {
                tool: "wallet.transfer".to_string(),
                max_invocations_per_epoch: NonZeroU32::new(24).expect("nonzero"),
                allow_network: false,
                allow_filesystem_write: false,
            },
        ],
        policy_capabilities: vec![
            "wallet.sign".parse().expect("valid name"),
            "governance.audit".parse().expect("valid name"),
        ],
        spend_limits: vec![
            AgentSpendLimitV1 {
                asset_definition: "61CtjvNd9T3THAR65GsMVHr82Bjc".to_string(),
                max_per_tx: xor_quantity_nanos(5_000_000),
                max_per_day: xor_quantity_nanos(20_000_000),
            },
            AgentSpendLimitV1 {
                asset_definition: "7t5kWEj537rDAL7AQNp9cZPUGPr5".to_string(),
                max_per_tx: xor_quantity_nanos(2_000_000),
                max_per_day: xor_quantity_nanos(10_000_000),
            },
        ],
        state_quota_bytes: NonZeroU64::new(134_217_728).expect("nonzero"),
        network_egress: SoraNetworkPolicyV1::Allowlist(vec![
            SoraNetworkAllowlistEntryV1::new("rpc.sora.internal", [443]),
            SoraNetworkAllowlistEntryV1::new("torii.sora.internal", [443]),
        ]),
        upgrade_policy: AgentUpgradePolicyV1::Governed,
    }
}
fn expected_fhe_param_set() -> FheParamSetV1 {
    let registered_params = ram_lfe_bfv_parameters_v1();
    let parameter_digest =
        registered_bfv_parameter_digest(&registered_params).expect("registered BFV digest");
    let rns_modulus_chain_digest = registered_bfv_rns_modulus_chain_digest(&registered_params)
        .expect("registered BFV RNS digest");
    let key_switch_decomposition_chain_digest =
        registered_bfv_key_switch_decomposition_chain_digest(&registered_params)
            .expect("registered BFV key-switch decomposition-chain digest");
    FheParamSetV1 {
        schema_version: FHE_PARAM_SET_VERSION_V1,
        param_set: "bfv-default".parse().expect("valid name"),
        version: NonZeroU32::new(1).expect("nonzero"),
        backend: "fhe/bfv-rns/v1".to_string(),
        scheme: FheSchemeV1::Bfv,
        ciphertext_modulus_bits: vec![
            NonZeroU16::new(53).expect("nonzero"),
            NonZeroU16::new(52).expect("nonzero"),
        ],
        plaintext_modulus_bits: NonZeroU16::new(9).expect("nonzero"),
        polynomial_modulus_degree: NonZeroU32::new(u32::from(registered_params.polynomial_degree))
            .expect("nonzero"),
        slot_count: NonZeroU32::new(u32::from(registered_params.polynomial_degree))
            .expect("nonzero"),
        security_level_bits: NonZeroU16::new(128).expect("nonzero"),
        max_multiplicative_depth: NonZeroU16::new(1).expect("nonzero"),
        lifecycle: FheParamLifecycleV1::Active,
        activation_height: Some(1),
        withdraw_height: None,
        parameter_digest,
        rns_modulus_chain_digest,
        key_switch_decomposition_chain_digest,
    }
}
fn expected_fhe_execution_policy() -> FheExecutionPolicyV1 {
    FheExecutionPolicyV1 {
        schema_version: FHE_EXECUTION_POLICY_VERSION_V1,
        policy_name: "analytics".parse().expect("valid name"),
        param_set: "bfv-default".parse().expect("valid name"),
        param_set_version: NonZeroU32::new(1).expect("nonzero"),
        evaluation_key_digest: expected_fhe_evaluation_key_digest(),
        evaluation_key_refresh_transcript_digest: expected_fhe_refresh_transcript_digest(),
        refresh_transcript_mode: BfvRefreshTranscriptModeV1::ExactLift,
        public_key_proof_statement_digest: Some(expected_fhe_public_key_proof_statement_digest()),
        bootstrap_key_zero_refresh_proof_statement_digest: Some(
            expected_fhe_bootstrap_key_proof_statement_digest(),
        ),
        full_bootstrap_release_audit_package: None,
        full_bootstrap_release_audit_package_digest: None,
        full_bootstrap_release_audit_trusted_reviewer_id: None,
        full_bootstrap_release_audit_trusted_reviewer_public_key: None,
        max_ciphertext_bytes: NonZeroU64::new(131_072).expect("nonzero"),
        max_plaintext_bytes: NonZeroU64::new(512).expect("nonzero"),
        max_input_ciphertexts: NonZeroU16::new(4).expect("nonzero"),
        max_output_ciphertexts: NonZeroU16::new(1).expect("nonzero"),
        max_multiplication_depth: NonZeroU16::new(1).expect("nonzero"),
        max_rotation_count: NonZeroU32::new(16).expect("nonzero"),
        max_bootstrap_count: 1,
        rounding_mode: FheDeterministicRoundingModeV1::NearestTiesToEven,
    }
}
fn expected_fhe_governance_bundle() -> FheGovernanceBundleV1 {
    FheGovernanceBundleV1 {
        schema_version: FHE_GOVERNANCE_BUNDLE_VERSION_V1,
        param_set: expected_fhe_param_set(),
        execution_policy: expected_fhe_execution_policy(),
    }
}
fn expected_fhe_job_spec() -> FheJobSpecV1 {
    FheJobSpecV1 {
        schema_version: FHE_JOB_SPEC_VERSION_V1,
        job_id: "job-add-001".to_string(),
        policy_name: "analytics".parse().expect("valid name"),
        param_set: "bfv-default".parse().expect("valid name"),
        param_set_version: NonZeroU32::new(1).expect("nonzero"),
        operation: FheJobOperationV1::Add,
        inputs: vec![
            FheJobInputRefV1 {
                state_key: "/state/health/patient-1".to_string(),
                payload_bytes: NonZeroU64::new(2_048).expect("nonzero"),
                commitment: sample_hash(121),
            },
            FheJobInputRefV1 {
                state_key: "/state/health/patient-2".to_string(),
                payload_bytes: NonZeroU64::new(2_048).expect("nonzero"),
                commitment: sample_hash(122),
            },
        ],
        output_state_key: "/state/health/result-1".to_string(),
        requested_multiplication_depth: 0,
        rotation_steps: 0,
        bootstrap_count: 0,
    }
}
fn expected_decryption_authority_policy() -> DecryptionAuthorityPolicyV1 {
    DecryptionAuthorityPolicyV1 {
        schema_version: DECRYPTION_AUTHORITY_POLICY_VERSION_V1,
        policy_name: "phi_threshold_policy".parse().expect("valid name"),
        mode: DecryptionAuthorityModeV1::ThresholdService,
        approver_quorum: NonZeroU16::new(2).expect("nonzero"),
        approver_ids: vec![
            "compliance_council".parse().expect("valid name"),
            "patient_advocate".parse().expect("valid name"),
            "privacy_officer".parse().expect("valid name"),
        ],
        allow_break_glass: false,
        jurisdiction_tag: "us_hipaa".to_string(),
        require_consent_evidence: true,
        max_ttl_blocks: NonZeroU32::new(1_440).expect("nonzero"),
        audit_tag: "phi.access.review".to_string(),
    }
}
fn expected_decryption_request() -> DecryptionRequestV1 {
    DecryptionRequestV1 {
        schema_version: DECRYPTION_REQUEST_VERSION_V1,
        request_id: "decrypt-req-0001".to_string(),
        policy_name: "phi_threshold_policy".parse().expect("valid name"),
        binding_name: "patient_records".parse().expect("valid name"),
        state_key: "/state/health/patient-1".to_string(),
        ciphertext_commitment: sample_hash(131),
        justification: "treatment continuity review".to_string(),
        jurisdiction_tag: "us_hipaa".to_string(),
        consent_evidence_hash: Some(sample_hash(133)),
        requested_ttl_blocks: NonZeroU32::new(120).expect("nonzero"),
        break_glass: false,
        break_glass_reason: None,
        governance_tx_hash: sample_hash(132),
    }
}
fn expected_ciphertext_query_spec() -> CiphertextQuerySpecV1 {
    CiphertextQuerySpecV1 {
        schema_version: CIPHERTEXT_QUERY_SPEC_VERSION_V1,
        service_name: "web_portal".parse().expect("valid name"),
        binding_name: "patient_records".parse().expect("valid name"),
        state_key_prefix: "/state/health".to_string(),
        max_results: NonZeroU16::new(32).expect("nonzero"),
        metadata_level: CiphertextQueryMetadataLevelV1::Minimal,
        include_proof: true,
    }
}
fn expected_ciphertext_query_response() -> CiphertextQueryResponseV1 {
    CiphertextQueryResponseV1 {
        schema_version: CIPHERTEXT_QUERY_RESPONSE_VERSION_V1,
        query_hash: sample_hash(147),
        service_name: "web_portal".parse().expect("valid name"),
        binding_name: "patient_records".parse().expect("valid name"),
        metadata_level: CiphertextQueryMetadataLevelV1::Minimal,
        served_sequence: 19,
        result_count: 1,
        truncated: false,
        results: vec![CiphertextQueryResultItemV1 {
            binding_name: "patient_records".parse().expect("valid name"),
            state_key: None,
            state_key_digest: sample_hash(148),
            payload_bytes: NonZeroU64::new(2_112).expect("nonzero"),
            ciphertext_commitment: sample_hash(149),
            encryption: SoraStateEncryptionV1::FheCiphertext,
            last_update_sequence: 17,
            governance_tx_hash: sample_hash(150),
            proof: Some(CiphertextInclusionProofV1 {
                schema_version: CIPHERTEXT_QUERY_PROOF_VERSION_V1,
                proof_scheme: "soracloud.audit_anchor.v1".to_string(),
                leaf_hash: sample_hash(151),
                anchor_hash: sample_hash(152),
                anchor_sequence: 19,
                event_sequence: 17,
            }),
        }],
    }
}
fn expected_secret_envelope() -> SecretEnvelopeV1 {
    SecretEnvelopeV1 {
        schema_version: SECRET_ENVELOPE_VERSION_V1,
        encryption: SecretEnvelopeEncryptionV1::FheCiphertext,
        key_id: "kms/fhe/team-a".to_string(),
        key_version: NonZeroU32::new(3).expect("nonzero"),
        nonce: vec![1, 2, 3, 4, 5, 6, 7, 8],
        ciphertext: vec![11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
        commitment: sample_hash(91),
        aad_digest: Some(sample_hash(99)),
    }
}
fn expected_ciphertext_state_record() -> CiphertextStateRecordV1 {
    let secret = expected_secret_envelope();
    let payload_bytes = u64::try_from(secret.ciphertext.len()).expect("fits in u64");
    CiphertextStateRecordV1 {
        schema_version: CIPHERTEXT_STATE_RECORD_VERSION_V1,
        binding_name: "private_state".parse().expect("valid name"),
        state_key: "/state/private/patient-1".to_string(),
        metadata: CiphertextStateMetadataV1 {
            content_type: "application/vnd.sora.secret+norito".to_string(),
            payload_bytes: NonZeroU64::new(payload_bytes).expect("nonzero"),
            commitment: secret.commitment,
            policy_tag: Some("health.phi.minimum".to_string()),
            tags: vec!["phi".to_string(), "tenant:alpha".to_string()],
        },
        secret,
    }
}
fn assert_norito_roundtrip<T>(value: &T)
where
    T: Encode + Decode + PartialEq + Debug,
{
    let encoded = Encode::encode(value);
    let mut cursor = encoded.as_slice();
    let decoded = <T as Decode>::decode(&mut cursor).expect("decode succeeds");
    assert!(cursor.is_empty(), "decode must consume all bytes");
    assert_eq!(decoded, *value, "roundtrip must preserve payload");
}
fn decode_norito_roundtrip<T>(value: &T) -> T
where
    T: Encode + Decode,
{
    let encoded = Encode::encode(value);
    let mut cursor = encoded.as_slice();
    let decoded = <T as Decode>::decode(&mut cursor).expect("decode succeeds");
    assert!(cursor.is_empty(), "decode must consume all bytes");
    decoded
}

fn assert_fixture_eq<T>(path: &str, fixture: &str, expected: &T)
where
    T: Clone + PartialEq + Debug + FastJsonWrite + JsonDeserialize + JsonSerialize,
{
    let parsed: T = json::from_str(fixture).expect("fixture must decode");
    assert_eq!(
        parsed, *expected,
        "fixture `{path}` content does not match expected data model"
    );
    let canonical = json::to_json_pretty(expected).expect("serialize fixture");
    assert_eq!(
        fixture.trim(),
        canonical.trim(),
        "fixture `{path}` is not canonical JSON for the current schema"
    );
}

fn write_fixture<T: JsonSerialize>(path: &Path, value: &T) {
    let json = json::to_json_pretty(value).expect("serialize fixture");
    fs::write(path, json).unwrap_or_else(|error| {
        panic!("failed writing {}: {error}", path.display());
    });
}

#[test]
fn container_manifest_fixture_is_canonical() {
    let manifest = expected_container_manifest();
    assert_fixture_eq(
        "sora_container_manifest_v1.json",
        CONTAINER_FIXTURE,
        &manifest,
    );
    assert_norito_roundtrip(&manifest);
    manifest.validate().expect("fixture should validate");
}

#[test]
fn state_binding_fixture_is_canonical() {
    let binding = expected_state_binding();
    assert_fixture_eq(
        "sora_state_binding_v1.json",
        STATE_BINDING_FIXTURE,
        &binding,
    );
    assert_norito_roundtrip(&binding);
    binding.validate().expect("fixture should validate");
}
#[test]
fn state_binding_rejects_relative_key_prefix() {
    let mut binding = expected_state_binding();
    binding.key_prefix = "state/session".to_string();
    let error = binding
        .validate()
        .expect_err("state binding key prefixes must be absolute");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "key_prefix",
            ..
        }
    ));
}
#[test]
fn state_binding_rejects_item_limit_above_total_limit() {
    let mut binding = expected_state_binding();
    binding.max_item_bytes = NonZeroU64::new(2_048).expect("nonzero");
    binding.max_total_bytes = NonZeroU64::new(1_024).expect("nonzero");
    let error = binding
        .validate()
        .expect_err("per-item state limit must not exceed total state limit");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "max_item_bytes",
            ..
        }
    ));
}
#[test]
fn state_binding_rejects_plaintext_confidential_state() {
    let mut binding = expected_patient_records_binding();
    binding.encryption = SoraStateEncryptionV1::Plaintext;
    let error = binding
        .validate()
        .expect_err("confidential state must require ciphertext encryption");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "encryption",
            ..
        }
    ));
}

#[test]
fn service_manifest_fixture_is_canonical() {
    let manifest = expected_service_manifest();
    assert_fixture_eq("sora_service_manifest_v1.json", SERVICE_FIXTURE, &manifest);
    assert_norito_roundtrip(&manifest);
    manifest.validate().expect("fixture should validate");
}

#[test]
fn deployment_bundle_fixture_is_canonical() {
    let bundle = expected_deployment_bundle();
    assert_fixture_eq(
        "sora_deployment_bundle_v1.json",
        DEPLOYMENT_BUNDLE_FIXTURE,
        &bundle,
    );
    assert_norito_roundtrip(&bundle);
    bundle
        .validate_for_admission()
        .expect("deployment bundle fixture should validate");
}

#[test]
fn container_manifest_fixture_rejects_missing_v1_fields() {
    for field in [
        "schema_version",
        "runtime",
        "bundle_hash",
        "bundle_path",
        "entrypoint",
        "args",
        "env",
        "inrou",
        "required_config_names",
        "required_secret_names",
        "config_exports",
        "capabilities",
        "resources",
        "lifecycle",
    ] {
        let mut value: json::Value =
            json::from_str(CONTAINER_FIXTURE).expect("fixture must decode as JSON value");
        let object = value.as_object_mut().expect("fixture root must be object");
        assert!(
            object.remove(field).is_some(),
            "fixture should declare `{field}` before the omission check"
        );
        let error = json::from_value::<SoraContainerManifestV1>(value)
            .expect_err("every first-release container field must be explicit");
        assert!(
            matches!(&error, json::Error::MissingField { field: missing } if missing == field),
            "missing `{field}` reported the wrong error: {error:?}"
        );
    }
}

#[test]
fn container_manifest_fixture_rejects_missing_nested_v1_fields() {
    for (parent, field) in [
        ("capabilities", "allow_model_inference"),
        ("lifecycle", "healthcheck_path"),
    ] {
        let mut value: json::Value =
            json::from_str(CONTAINER_FIXTURE).expect("fixture must decode as JSON value");
        let object = value
            .get_mut(parent)
            .and_then(json::Value::as_object_mut)
            .expect("nested fixture field must be an object");
        assert!(
            object.remove(field).is_some(),
            "fixture should declare `{parent}.{field}` before the omission check"
        );
        let error = json::from_value::<SoraContainerManifestV1>(value)
            .expect_err("every nested first-release container field must be explicit");
        assert!(
            matches!(&error, json::Error::MissingField { field: missing } if missing == field),
            "missing `{parent}.{field}` reported the wrong error: {error:?}"
        );
    }
}

#[test]
fn container_manifest_fixture_rejects_null_v1_collections() {
    for field in [
        "args",
        "env",
        "required_config_names",
        "required_secret_names",
        "config_exports",
    ] {
        let mut value: json::Value =
            json::from_str(CONTAINER_FIXTURE).expect("fixture must decode as JSON value");
        let object = value.as_object_mut().expect("fixture root must be object");
        assert!(
            object
                .insert(field.to_string(), json::Value::Null)
                .is_some(),
            "fixture should declare `{field}` before the null check"
        );
        json::from_value::<SoraContainerManifestV1>(value)
            .expect_err("first-release collection fields must not accept null");
    }
}

#[test]
fn container_manifest_fixture_rejects_unknown_json_field() {
    let mut value: json::Value =
        json::from_str(CONTAINER_FIXTURE).expect("fixture must decode as JSON value");
    let object = value.as_object_mut().expect("fixture root must be object");
    assert!(
        object
            .insert("legacy_padding".to_string(), json::Value::Bool(true))
            .is_none(),
        "test should add a new unknown field"
    );
    let error = json::from_value::<SoraContainerManifestV1>(value)
        .expect_err("unknown container manifest fields must be rejected");
    assert!(matches!(error, json::Error::UnknownField { field } if field == "legacy_padding"));
}

#[test]
fn container_manifest_fixture_rejects_inrou_metadata_for_ivm_runtime() {
    let mut value: json::Value =
        json::from_str(CONTAINER_FIXTURE).expect("fixture must decode as JSON value");
    let object = value.as_object_mut().expect("fixture root must be object");
    let inrou: json::Value = json::from_str(
        r#"{
          "schema_version": 1,
          "guest_images": {
            "x86_64": {
              "kernel_image_path": "/inrou/x86_64/vmlinux",
              "rootfs_image_path": "/inrou/x86_64/rootfs.ext4",
              "initrd_image_path": null,
              "published_artifact": {
                "manifest_digest_hex": "3131313131313131313131313131313131313131313131313131313131313131",
                "content_cid": "bafyr6ibrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrge"
              }
            },
            "aarch64": {
              "kernel_image_path": "/inrou/aarch64/vmlinux",
              "rootfs_image_path": "/inrou/aarch64/rootfs.ext4",
              "initrd_image_path": null,
              "published_artifact": {
                "manifest_digest_hex": "3232323232323232323232323232323232323232323232323232323232323232",
                "content_cid": "bafyr6ibsgizdemrsgizdemrsgizdemrsgizdemrsgizdemrsgizdemrsgi"
              }
            }
          }
        }"#,
    )
    .expect("inrou JSON must decode");
    assert!(
        object.insert("inrou".to_string(), inrou).is_some(),
        "fixture should declare `inrou` before the runtime policy check"
    );
    let decoded: SoraContainerManifestV1 =
        json::from_value(value).expect("container fixture with inrou metadata must decode");
    let error = decoded
        .validate()
        .expect_err("Ivm containers must reject Inrou metadata");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField { field: "inrou", .. }
    ));
}

#[test]
fn container_manifest_fixture_rejects_inrou_runtime_without_metadata() {
    let mut value: json::Value =
        json::from_str(CONTAINER_FIXTURE).expect("fixture must decode as JSON value");
    let object = value.as_object_mut().expect("fixture root must be object");
    let runtime: json::Value =
        json::from_str(r#"{"runtime":"Inrou","value":null}"#).expect("runtime JSON must decode");
    assert!(
        object.insert("runtime".to_string(), runtime).is_some(),
        "fixture should declare `runtime` before the runtime policy check"
    );
    object.insert(
        "entrypoint".to_string(),
        json::Value::String("/app/bin/service".to_string()),
    );
    let decoded: SoraContainerManifestV1 =
        json::from_value(value).expect("Inrou container fixture without metadata must decode");
    let error = decoded
        .validate()
        .expect_err("Inrou containers must require explicit metadata");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField { field: "inrou", .. }
    ));
}
#[test]
fn container_manifest_accepts_declared_config_exports() {
    let mut manifest = expected_container_manifest();
    manifest.required_config_names = vec!["runtime/theme".to_string(), "runtime/tls".to_string()];
    manifest.config_exports = vec![
        SoraConfigExportV1 {
            config_name: "runtime/theme".to_string(),
            target: SoraConfigExportTargetV1::Env("APP_THEME".to_string()),
        },
        SoraConfigExportV1 {
            config_name: "runtime/tls".to_string(),
            target: SoraConfigExportTargetV1::File("config/tls.json".to_string()),
        },
    ];
    manifest
        .validate()
        .expect("declared config exports should validate");
}
#[test]
fn container_manifest_rejects_duplicate_required_config_names() {
    let mut manifest = expected_container_manifest();
    manifest.required_config_names = vec!["runtime/theme".to_string(), "runtime/theme".to_string()];
    let error = manifest
        .validate()
        .expect_err("duplicate required config names must fail validation");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "required_config_names",
            ..
        }
    ));
}
#[test]
fn container_manifest_rejects_duplicate_required_secret_names() {
    let mut manifest = expected_container_manifest();
    manifest.required_secret_names = vec!["db/password".to_string(), "db/password".to_string()];
    let error = manifest
        .validate()
        .expect_err("duplicate required secret names must fail validation");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "required_secret_names",
            ..
        }
    ));
}
#[test]
fn container_manifest_rejects_required_config_path_traversal() {
    let mut manifest = expected_container_manifest();
    manifest.required_config_names = vec!["runtime/../theme".to_string()];
    let error = manifest
        .validate()
        .expect_err("required config names must reject traversal segments");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "required_config_names",
            ..
        }
    ));
}
#[test]
fn container_manifest_rejects_export_for_undeclared_required_config() {
    let mut manifest = expected_container_manifest();
    manifest.config_exports = vec![SoraConfigExportV1 {
        config_name: "runtime/theme".to_string(),
        target: SoraConfigExportTargetV1::Env("APP_THEME".to_string()),
    }];
    let error = manifest
        .validate()
        .expect_err("config exports must reference declared required configs");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "config_exports",
            ..
        }
    ));
}
#[test]
fn container_manifest_rejects_duplicate_config_export_env_targets() {
    let mut manifest = expected_container_manifest();
    manifest.required_config_names =
        vec!["runtime/theme".to_string(), "runtime/locale".to_string()];
    manifest.config_exports = vec![
        SoraConfigExportV1 {
            config_name: "runtime/theme".to_string(),
            target: SoraConfigExportTargetV1::Env("APP_CONFIG".to_string()),
        },
        SoraConfigExportV1 {
            config_name: "runtime/locale".to_string(),
            target: SoraConfigExportTargetV1::Env("APP_CONFIG".to_string()),
        },
    ];
    let error = manifest
        .validate()
        .expect_err("duplicate config export env targets must fail validation");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "config_exports",
            ..
        }
    ));
}
#[test]
fn container_manifest_rejects_invalid_config_export_env_target() {
    let mut manifest = expected_container_manifest();
    manifest.required_config_names = vec!["runtime/theme".to_string()];
    manifest.config_exports = vec![SoraConfigExportV1 {
        config_name: "runtime/theme".to_string(),
        target: SoraConfigExportTargetV1::Env("1APP_THEME".to_string()),
    }];
    let error = manifest
        .validate()
        .expect_err("config export env targets must start with a valid character");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "config_exports",
            ..
        }
    ));
}
#[test]
fn container_manifest_rejects_invalid_config_export_file_target() {
    let mut manifest = expected_container_manifest();
    manifest.required_config_names = vec!["runtime/theme".to_string()];
    manifest.config_exports = vec![SoraConfigExportV1 {
        config_name: "runtime/theme".to_string(),
        target: SoraConfigExportTargetV1::File("../theme.json".to_string()),
    }];
    let error = manifest
        .validate()
        .expect_err("config export file targets must reject traversal segments");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "config_exports",
            ..
        }
    ));
}
#[test]
fn container_manifest_rejects_duplicate_config_export_file_targets() {
    let mut manifest = expected_container_manifest();
    manifest.required_config_names =
        vec!["runtime/theme".to_string(), "runtime/locale".to_string()];
    manifest.config_exports = vec![
        SoraConfigExportV1 {
            config_name: "runtime/theme".to_string(),
            target: SoraConfigExportTargetV1::File("config/app.json".to_string()),
        },
        SoraConfigExportV1 {
            config_name: "runtime/locale".to_string(),
            target: SoraConfigExportTargetV1::File("config/app.json".to_string()),
        },
    ];
    let error = manifest
        .validate()
        .expect_err("duplicate config export file targets must fail validation");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "config_exports",
            ..
        }
    ));
}
#[test]
fn container_manifest_rejects_relative_healthcheck_path() {
    let mut manifest = expected_container_manifest();
    manifest.lifecycle.healthcheck_path = Some("healthz".to_string());
    let error = manifest
        .validate()
        .expect_err("healthcheck paths must be absolute");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "lifecycle.healthcheck_path",
            ..
        }
    ));
}

#[test]
fn service_manifest_fixture_rejects_missing_v1_fields() {
    for field in [
        "schema_version",
        "service_name",
        "service_version",
        "execution_plane",
        "container",
        "replicas",
        "route",
        "rollout",
        "economics",
        "state_bindings",
        "lease_volumes",
        "handlers",
        "artifacts",
    ] {
        let mut value: json::Value =
            json::from_str(SERVICE_FIXTURE).expect("fixture must decode as JSON value");
        let object = value.as_object_mut().expect("fixture root must be object");
        assert!(
            object.remove(field).is_some(),
            "fixture should declare `{field}` before the omission check"
        );
        let error = json::from_value::<SoraServiceManifestV1>(value)
            .expect_err("every first-release service field must be explicit");
        assert!(
            matches!(&error, json::Error::MissingField { field: missing } if missing == field),
            "missing `{field}` reported the wrong error: {error:?}"
        );
    }
}

#[test]
fn service_manifest_fixture_rejects_missing_nested_v1_fields() {
    for (collection, field) in [
        ("handlers", "route_path"),
        ("handlers", "mailbox"),
        ("artifacts", "handler_name"),
    ] {
        let mut value: json::Value =
            json::from_str(SERVICE_FIXTURE).expect("fixture must decode as JSON value");
        let object = value
            .get_mut(collection)
            .and_then(json::Value::as_array_mut)
            .and_then(|members| members.first_mut())
            .and_then(json::Value::as_object_mut)
            .expect("nested fixture collection must contain an object");
        assert!(
            object.remove(field).is_some(),
            "fixture should declare `{collection}[0].{field}` before the omission check"
        );
        let error = json::from_value::<SoraServiceManifestV1>(value)
            .expect_err("every nested first-release service field must be explicit");
        assert!(
            matches!(&error, json::Error::MissingField { field: missing } if missing == field),
            "missing `{collection}[0].{field}` reported the wrong error: {error:?}"
        );
    }
}

#[test]
fn service_manifest_fixture_rejects_null_v1_collections() {
    for field in ["state_bindings", "lease_volumes", "handlers", "artifacts"] {
        let mut value: json::Value =
            json::from_str(SERVICE_FIXTURE).expect("fixture must decode as JSON value");
        let object = value.as_object_mut().expect("fixture root must be object");
        assert!(
            object
                .insert(field.to_string(), json::Value::Null)
                .is_some(),
            "fixture should declare `{field}` before the null check"
        );
        json::from_value::<SoraServiceManifestV1>(value)
            .expect_err("first-release service collection fields must not accept null");
    }
}
#[test]
fn service_manifest_rejects_empty_service_version() {
    let mut manifest = expected_service_manifest();
    manifest.service_version = "   ".to_string();
    let error = manifest
        .validate()
        .expect_err("blank service versions must fail validation");
    assert!(matches!(
        error,
        SoracloudManifestError::EmptyField {
            field: "service_version",
            ..
        }
    ));
}
#[test]
fn service_manifest_rejects_rollout_canary_percent_over_100() {
    let mut manifest = expected_service_manifest();
    manifest.rollout.canary_percent = 101;
    let error = manifest
        .validate()
        .expect_err("canary percent must be in range");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "rollout.canary_percent",
            ..
        }
    ));
}
#[test]
fn service_manifest_rejects_empty_route_host() {
    let mut manifest = expected_service_manifest();
    manifest.route.as_mut().expect("fixture route").host = "  ".to_string();
    let error = manifest
        .validate()
        .expect_err("blank route hosts must fail validation");
    assert!(matches!(
        error,
        SoracloudManifestError::EmptyField {
            field: "route.host",
            ..
        }
    ));
}
#[test]
fn service_manifest_rejects_relative_route_path_prefix() {
    let mut manifest = expected_service_manifest();
    manifest.route.as_mut().expect("fixture route").path_prefix = "app".to_string();
    let error = manifest
        .validate()
        .expect_err("route path prefixes must be absolute");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "route.path_prefix",
            ..
        }
    ));
}
#[test]
fn service_manifest_rejects_deterministic_service_without_handlers() {
    let mut manifest = expected_service_manifest();
    manifest.handlers.clear();
    let error = manifest
        .validate()
        .expect_err("deterministic services must declare handlers");
    assert!(matches!(
        error,
        SoracloudManifestError::EmptyField {
            field: "handlers",
            ..
        }
    ));
}
#[test]
fn service_manifest_rejects_blank_quota_class() {
    let mut manifest = expected_service_manifest();
    manifest.economics.quota_class = "   ".to_string();
    let error = manifest
        .validate()
        .expect_err("blank hosted-service quota classes must fail validation");
    assert!(matches!(
        error,
        SoracloudManifestError::EmptyField {
            field: "quota_class",
            ..
        }
    ));
}
#[test]
fn service_manifest_rejects_deterministic_service_with_lease_volume() {
    let mut manifest = expected_service_manifest();
    manifest.lease_volumes = vec![SoraLeaseVolumeBindingV1 {
        volume_name: "scratch".parse().expect("valid name"),
        kind: SoraLeaseVolumeKindV1::ServiceLeaseVolume,
        storage_class: StorageClass::Warm,
        mount_path: "/var/lib/soracloud/volumes/scratch".to_string(),
        max_total_bytes: NonZeroU64::new(1_048_576).expect("nonzero"),
    }];
    let error = manifest
        .validate()
        .expect_err("deterministic services must not declare lease volumes");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "lease_volumes",
            ..
        }
    ));
}
#[test]
fn service_manifest_rejects_duplicate_state_binding_names() {
    let mut manifest = expected_service_manifest();
    manifest.state_bindings[1].binding_name = manifest.state_bindings[0].binding_name.clone();
    let error = manifest
        .validate()
        .expect_err("duplicate state binding names must fail validation");
    assert!(matches!(
        error,
        SoracloudManifestError::DuplicateStateBinding { .. }
    ));
}
#[test]
fn service_manifest_rejects_duplicate_handler_names() {
    let mut manifest = expected_service_manifest();
    manifest.handlers[1].handler_name = manifest.handlers[0].handler_name.clone();
    let error = manifest
        .validate()
        .expect_err("duplicate handler names must fail validation");
    assert!(matches!(
        error,
        SoracloudManifestError::DuplicateHandler { .. }
    ));
}
#[test]
fn service_handler_rejects_empty_entrypoint() {
    let mut handler = expected_service_manifest().handlers[0].clone();
    handler.entrypoint = "   ".to_string();
    let error = handler
        .validate()
        .expect_err("handler entrypoints must not be blank");
    assert!(matches!(
        error,
        SoracloudManifestError::EmptyField {
            field: "entrypoint",
            ..
        }
    ));
}
#[test]
fn service_handler_rejects_relative_route_path() {
    let mut handler = expected_service_manifest().handlers[0].clone();
    handler.route_path = Some("assets".to_string());
    let error = handler
        .validate()
        .expect_err("handler route paths must be absolute");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "route_path",
            ..
        }
    ));
}
#[test]
fn service_handler_rejects_uncertified_asset_handler() {
    let mut handler = expected_service_manifest().handlers[0].clone();
    handler.certified_response = SoraCertifiedResponsePolicyV1::None;
    let error = handler
        .validate()
        .expect_err("asset handlers must use certified responses");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "certified_response",
            ..
        }
    ));
}
#[test]
fn service_handler_rejects_mailbox_on_query_handler() {
    let mut handler = expected_service_manifest().handlers[1].clone();
    handler.mailbox = Some(SoraMailboxContractV1 {
        queue_name: "query_mailbox".parse().expect("valid name"),
        max_pending_messages: NonZeroU32::new(16).expect("nonzero"),
        max_message_bytes: NonZeroU64::new(256).expect("nonzero"),
        retention_blocks: NonZeroU32::new(32).expect("nonzero"),
    });
    let error = handler
        .validate()
        .expect_err("query handlers must not declare mailboxes");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "mailbox",
            ..
        }
    ));
}
#[test]
fn service_handler_rejects_update_without_mailbox() {
    let mut handler = expected_service_manifest().handlers[2].clone();
    handler.mailbox = None;
    let error = handler
        .validate()
        .expect_err("update handlers must declare mailbox contracts");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "mailbox",
            ..
        }
    ));
}
#[test]
fn mailbox_contract_rejects_tiny_message_limit() {
    let mut mailbox = expected_service_manifest().handlers[2]
        .mailbox
        .clone()
        .expect("fixture update mailbox");
    mailbox.max_message_bytes = NonZeroU64::new(8).expect("nonzero");
    let error = mailbox
        .validate()
        .expect_err("mailbox messages must have a minimum payload budget");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "max_message_bytes",
            ..
        }
    ));
}
#[test]
fn service_manifest_rejects_artifact_referencing_unknown_handler() {
    let mut manifest = expected_service_manifest();
    manifest.artifacts[0].handler_name = Some("missing".parse().expect("valid name"));
    let error = manifest
        .validate()
        .expect_err("artifacts must reference declared handlers");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "artifacts.handler_name",
            ..
        }
    ));
}
#[test]
fn artifact_ref_rejects_empty_path() {
    let mut artifact = expected_service_manifest().artifacts[0].clone();
    artifact.artifact_path = "   ".to_string();
    let error = artifact
        .validate()
        .expect_err("artifact paths must not be blank");
    assert!(matches!(
        error,
        SoracloudManifestError::EmptyField {
            field: "artifact_path",
            ..
        }
    ));
}
#[test]
fn artifact_ref_rejects_control_character_path() {
    let mut artifact = expected_service_manifest().artifacts[0].clone();
    artifact.artifact_path = "/public/index\u{0000}.html".to_string();
    let error = artifact
        .validate()
        .expect_err("artifact paths must reject control characters");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "artifact_path",
            ..
        }
    ));
}

#[test]
fn deployment_bundle_fixture_rejects_missing_nested_container_field() {
    let mut value: json::Value = json::from_str(DEPLOYMENT_BUNDLE_FIXTURE)
        .expect("bundle fixture must decode as JSON value");
    let container = value
        .get_mut("container")
        .and_then(json::Value::as_object_mut)
        .expect("bundle fixture container must be object");
    assert!(
        container.remove("config_exports").is_some(),
        "nested container should declare `config_exports` before the omission check"
    );
    json::from_value::<SoraDeploymentBundleV1>(value)
        .expect_err("nested first-release container fields must be explicit");
}

#[test]
fn deployment_bundle_fixture_uses_embedded_container_hash() {
    let container: SoraContainerManifestV1 =
        json::from_str(CONTAINER_FIXTURE).expect("container fixture must decode");
    let bundle: SoraDeploymentBundleV1 =
        json::from_str(DEPLOYMENT_BUNDLE_FIXTURE).expect("bundle fixture must decode");
    let container_hash = Hash::new(Encode::encode(&container));
    assert_eq!(bundle.container, container);
    assert_eq!(bundle.container_manifest_hash(), container_hash);
    assert_eq!(bundle.service.container.manifest_hash, container_hash);
    assert_eq!(
        bundle.service_manifest_hash(),
        Hash::new(Encode::encode(&bundle.service))
    );
}

#[test]
fn deployment_bundle_fixture_rejects_container_drift_without_reference_update() {
    let mut bundle: SoraDeploymentBundleV1 =
        json::from_str(DEPLOYMENT_BUNDLE_FIXTURE).expect("bundle fixture must decode");
    bundle.container.args.push("--trace".to_string());
    let error = bundle
        .validate_for_admission()
        .expect_err("container drift must invalidate the embedded manifest reference");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "service.container.manifest_hash",
            ..
        }
    ));
}

#[test]
fn deployment_bundle_fixture_accepts_container_change_after_reference_refresh() {
    let mut bundle: SoraDeploymentBundleV1 =
        json::from_str(DEPLOYMENT_BUNDLE_FIXTURE).expect("bundle fixture must decode");
    bundle
        .container
        .env
        .insert("FEATURE_FLAG".to_string(), "enabled".to_string());
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    bundle
        .validate_for_admission()
        .expect("refreshed container manifest reference should validate");
}

#[test]
fn deployment_bundle_fixture_rejects_public_route_without_healthcheck() {
    let mut bundle: SoraDeploymentBundleV1 =
        json::from_str(DEPLOYMENT_BUNDLE_FIXTURE).expect("bundle fixture must decode");
    bundle.container.lifecycle.healthcheck_path = None;
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    let error = bundle
        .validate_for_admission()
        .expect_err("public routes must require a healthcheck path");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "container.lifecycle.healthcheck_path",
            ..
        }
    ));
}
#[test]
fn deployment_bundle_rejects_mutable_binding_without_state_write_capability() {
    let mut bundle = expected_deployment_bundle();
    bundle.container.capabilities.allow_state_writes = false;
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    let error = bundle
        .validate_for_admission()
        .expect_err("mutable state bindings require state-write capability");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "container.capabilities.allow_state_writes",
            ..
        }
    ));
}
#[test]
fn deployment_bundle_rejects_update_handler_without_state_write_capability() {
    let mut bundle = expected_deployment_bundle();
    bundle.container.capabilities.allow_state_writes = false;
    for binding in &mut bundle.service.state_bindings {
        binding.mutability = SoraStateMutabilityV1::ReadOnly;
    }
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    let error = bundle
        .validate_for_admission()
        .expect_err("update handlers require state-write capability");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "container.capabilities.allow_state_writes",
            ..
        }
    ));
}
#[test]
fn deployment_bundle_rejects_http_service_with_ivm_runtime() {
    let mut bundle = expected_deployment_bundle();
    bundle.service.execution_plane = SoraServiceExecutionPlaneV1::HttpService;
    bundle.service.state_bindings.clear();
    bundle.service.handlers.clear();
    bundle.service.artifacts.clear();
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    let error = bundle
        .validate_for_admission()
        .expect_err("HTTP services require Inrou runtime containers");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "container.runtime",
            ..
        }
    ));
}

#[test]
fn deployment_bundle_accepts_inrou_http_service_fixture() {
    let bundle = expected_inrou_http_deployment_bundle();
    bundle
        .validate_for_admission()
        .expect("valid Inrou HTTP deployment bundle should pass admission");
}

#[test]
fn deployment_bundle_rejects_http_service_without_root_lease_volume() {
    let mut bundle = expected_inrou_http_deployment_bundle();
    bundle
        .service
        .lease_volumes
        .retain(|volume| !volume.is_root_volume());
    let error = bundle
        .validate_for_admission()
        .expect_err("Inrou HTTP services require one persistent root volume");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "service.lease_volumes",
            ..
        }
    ));
}

#[test]
fn deployment_bundle_rejects_http_service_without_data_lease_volume() {
    let mut bundle = expected_inrou_http_deployment_bundle();
    bundle
        .service
        .lease_volumes
        .retain(SoraLeaseVolumeBindingV1::is_root_volume);
    let error = bundle
        .validate_for_admission()
        .expect_err("Inrou HTTP services require a replica-private data volume");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "service.lease_volumes",
            ..
        }
    ));
}

#[test]
fn deployment_bundle_accepts_inrou_http_service_without_login_surface() {
    let mut bundle = expected_inrou_http_deployment_bundle();
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    bundle
        .validate_for_admission()
        .expect("Inrou HTTP services must not require an SSH access path");
}

#[test]
fn deployment_source_rejects_http_service_replica_count_over_quota() {
    let mut bundle = expected_inrou_http_deployment_bundle();
    // Source compatibility runs before release preparation binds placement
    // targets. A five-replica source must fail quota checks at that boundary;
    // an admitted bundle cannot have five targets under the four-target limit.
    bundle.service.placement_targets.clear();
    bundle.container.validate().expect("valid container source");
    bundle
        .service
        .validate()
        .expect("valid unbound service source");
    SoraDeploymentBundleV1::validate_source_compatibility(
        bundle.container.runtime,
        &bundle.container.capabilities,
        bundle.container.resources,
        &bundle.container.lifecycle,
        &bundle.service,
    )
    .expect("two-replica source is within quota");
    bundle.service.replicas = NonZeroU16::new(5).expect("nonzero");
    let error = SoraDeploymentBundleV1::validate_source_compatibility(
        bundle.container.runtime,
        &bundle.container.capabilities,
        bundle.container.resources,
        &bundle.container.lifecycle,
        &bundle.service,
    )
    .expect_err("HTTP service replicas must stay within quota class limits");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "service.replicas",
            ..
        }
    ));
    assert!(matches!(
        bundle
            .validate_for_admission()
            .expect_err("bundle admission also enforces the replica quota"),
        SoracloudManifestError::InvalidField {
            field: "service.replicas",
            ..
        }
    ));
}

#[test]
fn deployment_bundle_rejects_replicas_without_distinct_placement_targets() {
    let mut bundle = expected_inrou_http_deployment_bundle();
    bundle
        .validate_for_admission()
        .expect("valid placed bundle");
    bundle.service.replicas = NonZeroU16::new(4).expect("nonzero");
    assert!(matches!(
        bundle
            .validate_for_admission()
            .expect_err("two targets cannot host four replicas"),
        SoracloudManifestError::InvalidField {
            field: "service.placement_targets",
            ..
        }
    ));
    bundle.service.placement_targets =
        expected_inrou_placement_targets(bundle.service.replicas.get());
    bundle
        .validate_for_admission()
        .expect("four distinct targets can host four replicas within quota");
}

#[test]
fn deployment_bundle_rejects_http_service_task_limit_over_quota() {
    let mut bundle = expected_inrou_http_deployment_bundle();
    bundle.container.resources.max_tasks = NonZeroU16::new(1_025).expect("nonzero");
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    let error = bundle
        .validate_for_admission()
        .expect_err("HTTP service resources must stay within quota class limits");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "container.resources.max_tasks",
            ..
        }
    ));
}

#[test]
fn deployment_bundle_charges_replica_private_lease_bytes_for_every_replica() {
    let mut bundle = expected_inrou_http_deployment_bundle();
    bundle.service.replicas = NonZeroU16::new(4).expect("nonzero");
    bundle.service.placement_targets =
        expected_inrou_placement_targets(bundle.service.replicas.get());
    bundle
        .validate_for_admission()
        .expect("four-replica baseline is within quota");
    let data_index = bundle
        .service
        .lease_volumes
        .iter()
        .position(iroha_data_model::soracloud::SoraLeaseVolumeBindingV1::is_data_volume)
        .expect("data lease volume");
    // Four copies of the 8-GiB root and 120-GiB data volumes exactly fill
    // the 512-GiB quota. Raising only the data volume must reject admission.
    bundle.service.lease_volumes[data_index].max_total_bytes =
        NonZeroU64::new(120 * 1024 * 1024 * 1024).expect("nonzero");
    bundle
        .validate_for_admission()
        .expect("exact aggregate lease quota is admitted");
    bundle.service.lease_volumes[data_index].max_total_bytes =
        NonZeroU64::new(128 * 1024 * 1024 * 1024).expect("nonzero");
    let error = bundle
        .validate_for_admission()
        .expect_err("HTTP service lease storage must stay within quota class limits");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "service.lease_volumes",
            ..
        }
    ));
}

#[test]
fn deployment_bundle_fixture_rejects_expected_schema_version_drift() {
    let mut bundle: SoraDeploymentBundleV1 =
        json::from_str(DEPLOYMENT_BUNDLE_FIXTURE).expect("bundle fixture must decode");
    bundle.service.container.expected_schema_version =
        bundle.container.schema_version.saturating_add(1);
    let error = bundle
        .validate_for_admission()
        .expect_err("container schema-version drift must fail admission");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "container.expected_schema_version",
            ..
        }
    ));
}

#[test]
fn deployment_bundle_fixture_rejects_top_level_schema_version_drift() {
    let mut bundle: SoraDeploymentBundleV1 =
        json::from_str(DEPLOYMENT_BUNDLE_FIXTURE).expect("bundle fixture must decode");
    bundle.schema_version = bundle.schema_version.saturating_add(1);
    let error = bundle
        .validate_for_admission()
        .expect_err("deployment bundle schema-version drift must fail admission");
    assert!(matches!(
        error,
        SoracloudManifestError::UnsupportedVersion {
            manifest: "sora deployment bundle",
            expected: SORA_DEPLOYMENT_BUNDLE_VERSION_V1,
            ..
        }
    ));
}

#[test]
fn agent_apartment_manifest_fixture_is_canonical() {
    let manifest = expected_agent_apartment_manifest();
    assert_fixture_eq(
        "agent_apartment_manifest_v1.json",
        AGENT_APARTMENT_FIXTURE,
        &manifest,
    );
    assert_norito_roundtrip(&manifest);
    manifest.validate().expect("fixture should validate");
}

#[test]
fn fhe_param_set_fixture_is_canonical() {
    let param_set = expected_fhe_param_set();
    assert_fixture_eq("fhe_param_set_v1.json", FHE_PARAM_SET_FIXTURE, &param_set);
    assert_norito_roundtrip(&param_set);
    param_set.validate().expect("fixture should validate");
}

#[test]
fn fhe_execution_policy_fixture_is_canonical() {
    let policy = expected_fhe_execution_policy();
    assert_fixture_eq(
        "fhe_execution_policy_v1.json",
        FHE_EXECUTION_POLICY_FIXTURE,
        &policy,
    );
    assert!(
        policy.max_bootstrap_count > 0,
        "canonical FHE policy fixture must exercise bootstrap-capable validation"
    );
    assert!(
        policy
            .bootstrap_key_zero_refresh_proof_statement_digest
            .is_some(),
        "bootstrap-capable FHE policy fixture must bind a proof statement digest"
    );
    assert!(
        policy.public_key_proof_statement_digest.is_some(),
        "canonical FHE policy fixture must bind a public-key proof statement digest"
    );
    assert_norito_roundtrip(&policy);
    policy.validate().expect("fixture should validate");
    policy
        .validate_for_param_set(&expected_fhe_param_set())
        .expect("fixture should match expected parameter set");
}

#[test]
fn fhe_execution_policy_fixture_rejects_adversarial_bootstrap_digest_drift() {
    let mut missing_digest: json::Value =
        json::from_str(FHE_EXECUTION_POLICY_FIXTURE).expect("fixture must decode as JSON value");
    let object = missing_digest
        .as_object_mut()
        .expect("fixture root must be object");
    assert!(
        object
            .remove("bootstrap_key_zero_refresh_proof_statement_digest")
            .is_some(),
        "fixture should declare bootstrap proof digest before the omission check"
    );
    json::from_value::<FheExecutionPolicyV1>(missing_digest)
        .expect_err("canonical V1 JSON must reject an omitted bootstrap proof digest key");
    let mut stale_digest = expected_fhe_execution_policy();
    stale_digest.max_bootstrap_count = 0;
    let error = stale_digest
        .validate()
        .expect_err("zero-bootstrap policies must reject stale proof digests");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "bootstrap_key_zero_refresh_proof_statement_digest",
            ..
        }
    ));
    let mut non_bootstrap_json: json::Value =
        json::from_str(FHE_EXECUTION_POLICY_FIXTURE).expect("fixture must decode as JSON value");
    let object = non_bootstrap_json
        .as_object_mut()
        .expect("fixture root must be object");
    object.insert(
        "max_bootstrap_count".to_string(),
        json::Value::Number(0_u64.into()),
    );
    object.insert(
        "bootstrap_key_zero_refresh_proof_statement_digest".to_string(),
        json::Value::Null,
    );
    let decoded_non_bootstrap: FheExecutionPolicyV1 =
        json::from_value(non_bootstrap_json).expect("explicit null digest must decode");
    decoded_non_bootstrap
        .validate()
        .expect("zero-bootstrap decoded fixture may set the proof digest to null");
}
#[test]
fn fhe_execution_policy_norito_rejects_adversarial_bootstrap_digest_drift_after_decode() {
    let param_set = expected_fhe_param_set();
    let mut missing_digest = expected_fhe_execution_policy();
    missing_digest.bootstrap_key_zero_refresh_proof_statement_digest = None;
    let decoded_missing_digest: FheExecutionPolicyV1 = decode_norito_roundtrip(&missing_digest);
    assert!(
        decoded_missing_digest.max_bootstrap_count > 0,
        "test policy must remain bootstrap-capable after binary decode"
    );
    let error = decoded_missing_digest
        .validate_for_param_set(&param_set)
        .expect_err("binary-decoded bootstrap policy must reject missing proof digest");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "bootstrap_key_zero_refresh_proof_statement_digest",
            ..
        }
    ));
    let mut stale_digest = expected_fhe_execution_policy();
    stale_digest.max_bootstrap_count = 0;
    let decoded_stale_digest: FheExecutionPolicyV1 = decode_norito_roundtrip(&stale_digest);
    let error = decoded_stale_digest
        .validate_for_param_set(&param_set)
        .expect_err("binary-decoded zero-bootstrap policy must reject stale proof digest");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "bootstrap_key_zero_refresh_proof_statement_digest",
            ..
        }
    ));
    let mut non_bootstrap_policy = expected_fhe_execution_policy();
    non_bootstrap_policy.max_bootstrap_count = 0;
    non_bootstrap_policy.bootstrap_key_zero_refresh_proof_statement_digest = None;
    let decoded_non_bootstrap: FheExecutionPolicyV1 =
        decode_norito_roundtrip(&non_bootstrap_policy);
    decoded_non_bootstrap
        .validate_for_param_set(&param_set)
        .expect("binary-decoded zero-bootstrap policy may omit the proof digest");
}

#[test]
fn fhe_governance_bundle_fixture_is_canonical() {
    let bundle = expected_fhe_governance_bundle();
    assert_fixture_eq(
        "fhe_governance_bundle_v1.json",
        FHE_GOVERNANCE_BUNDLE_FIXTURE,
        &bundle,
    );
    assert_norito_roundtrip(&bundle);
    bundle
        .validate_for_admission()
        .expect("fixture should validate");
}

#[test]
fn fhe_governance_bundle_fixture_rejects_adversarial_policy_digest_drift() {
    let mut missing_public_key_digest: json::Value =
        json::from_str(FHE_GOVERNANCE_BUNDLE_FIXTURE).expect("fixture must decode as JSON value");
    let execution_policy = missing_public_key_digest
        .as_object_mut()
        .expect("fixture root must be object")
        .get_mut("execution_policy")
        .expect("fixture must carry execution_policy")
        .as_object_mut()
        .expect("execution_policy must be object");
    assert!(
        execution_policy
            .remove("public_key_proof_statement_digest")
            .is_some(),
        "bundle fixture should declare public-key proof digest before the omission check"
    );
    json::from_value::<FheGovernanceBundleV1>(missing_public_key_digest)
        .expect_err("canonical V1 JSON must reject an omitted nested public-key digest key");
    let mut missing_digest: json::Value =
        json::from_str(FHE_GOVERNANCE_BUNDLE_FIXTURE).expect("fixture must decode as JSON value");
    let execution_policy = missing_digest
        .as_object_mut()
        .expect("fixture root must be object")
        .get_mut("execution_policy")
        .expect("fixture must carry execution_policy")
        .as_object_mut()
        .expect("execution_policy must be object");
    assert!(
        execution_policy
            .remove("bootstrap_key_zero_refresh_proof_statement_digest")
            .is_some(),
        "bundle fixture should declare bootstrap proof digest before the omission check"
    );
    json::from_value::<FheGovernanceBundleV1>(missing_digest)
        .expect_err("canonical V1 JSON must reject an omitted nested bootstrap digest key");
    let mut stale_digest = expected_fhe_governance_bundle();
    stale_digest.execution_policy.max_bootstrap_count = 0;
    let error = stale_digest
        .validate_for_admission()
        .expect_err("zero-bootstrap nested policy must reject stale proof digest");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "bootstrap_key_zero_refresh_proof_statement_digest",
            ..
        }
    ));
    let mut non_bootstrap_json: json::Value =
        json::from_str(FHE_GOVERNANCE_BUNDLE_FIXTURE).expect("fixture must decode as JSON value");
    let execution_policy = non_bootstrap_json
        .as_object_mut()
        .expect("fixture root must be object")
        .get_mut("execution_policy")
        .expect("fixture must carry execution_policy")
        .as_object_mut()
        .expect("execution_policy must be object");
    execution_policy.insert(
        "max_bootstrap_count".to_string(),
        json::Value::Number(0_u64.into()),
    );
    execution_policy.insert(
        "bootstrap_key_zero_refresh_proof_statement_digest".to_string(),
        json::Value::Null,
    );
    let decoded_non_bootstrap: FheGovernanceBundleV1 =
        json::from_value(non_bootstrap_json).expect("explicit null nested digest must decode");
    decoded_non_bootstrap
        .validate_for_admission()
        .expect("zero-bootstrap nested policy may set the proof digest to null");
}
#[test]
fn fhe_governance_bundle_norito_rejects_adversarial_policy_digest_drift_after_decode() {
    let mut missing_public_key_digest = expected_fhe_governance_bundle();
    missing_public_key_digest
        .execution_policy
        .public_key_proof_statement_digest = None;
    let decoded_missing_public_key_digest: FheGovernanceBundleV1 =
        decode_norito_roundtrip(&missing_public_key_digest);
    let error = decoded_missing_public_key_digest
        .validate_for_admission()
        .expect_err("binary-decoded governance bundle must reject missing public-key proof digest");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "public_key_proof_statement_digest",
            ..
        }
    ));
    let mut missing_digest = expected_fhe_governance_bundle();
    missing_digest
        .execution_policy
        .bootstrap_key_zero_refresh_proof_statement_digest = None;
    let decoded_missing_digest: FheGovernanceBundleV1 = decode_norito_roundtrip(&missing_digest);
    assert!(
        decoded_missing_digest.execution_policy.max_bootstrap_count > 0,
        "test bundle policy must remain bootstrap-capable after binary decode"
    );
    let error = decoded_missing_digest
        .validate_for_admission()
        .expect_err("binary-decoded bootstrap bundle must reject missing proof digest");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "bootstrap_key_zero_refresh_proof_statement_digest",
            ..
        }
    ));
    let mut stale_digest = expected_fhe_governance_bundle();
    stale_digest.execution_policy.max_bootstrap_count = 0;
    let decoded_stale_digest: FheGovernanceBundleV1 = decode_norito_roundtrip(&stale_digest);
    let error = decoded_stale_digest
        .validate_for_admission()
        .expect_err("binary-decoded zero-bootstrap bundle must reject stale proof digest");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "bootstrap_key_zero_refresh_proof_statement_digest",
            ..
        }
    ));
    let mut non_bootstrap_bundle = expected_fhe_governance_bundle();
    non_bootstrap_bundle.execution_policy.max_bootstrap_count = 0;
    non_bootstrap_bundle
        .execution_policy
        .bootstrap_key_zero_refresh_proof_statement_digest = None;
    let decoded_non_bootstrap: FheGovernanceBundleV1 =
        decode_norito_roundtrip(&non_bootstrap_bundle);
    decoded_non_bootstrap
        .validate_for_admission()
        .expect("binary-decoded zero-bootstrap bundle may omit the proof digest");
}

#[test]
fn fhe_governance_bundle_fixture_rejects_adversarial_parameter_drift() {
    let bundle: FheGovernanceBundleV1 =
        json::from_str(FHE_GOVERNANCE_BUNDLE_FIXTURE).expect("fixture must decode");
    let mut wrong_bundle_schema = bundle.clone();
    wrong_bundle_schema.schema_version = wrong_bundle_schema.schema_version.saturating_add(1);
    let error = wrong_bundle_schema
        .validate_for_admission()
        .expect_err("bundle schema drift must be rejected");
    assert!(matches!(
        error,
        SoracloudManifestError::UnsupportedVersion {
            manifest: "fhe governance bundle",
            expected: FHE_GOVERNANCE_BUNDLE_VERSION_V1,
            ..
        }
    ));
    let mut wrong_policy_version = bundle.clone();
    wrong_policy_version.execution_policy.param_set_version =
        NonZeroU32::new(bundle.param_set.version.get() + 1).expect("nonzero");
    let error = wrong_policy_version
        .validate_for_admission()
        .expect_err("policy version drift must be rejected");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "param_set_version",
            ..
        }
    ));
    let mut wrong_chain = bundle.clone();
    wrong_chain.param_set.ciphertext_modulus_bits = vec![
        NonZeroU16::new(52).expect("nonzero"),
        NonZeroU16::new(53).expect("nonzero"),
    ];
    let error = wrong_chain
        .validate_for_admission()
        .expect_err("ascending ciphertext modulus chains must be rejected");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "ciphertext_modulus_bits",
            ..
        }
    ));
    let mut output_overflow = bundle.clone();
    output_overflow.execution_policy.max_output_ciphertexts =
        NonZeroU16::new(output_overflow.execution_policy.max_input_ciphertexts.get() + 1)
            .expect("nonzero");
    let error = output_overflow
        .validate_for_admission()
        .expect_err("policy output-count overflow must be rejected");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "max_output_ciphertexts",
            ..
        }
    ));
    let mut proposed_param_set = bundle.clone();
    proposed_param_set.param_set.lifecycle = FheParamLifecycleV1::Proposed;
    proposed_param_set.param_set.withdraw_height = None;
    let error = proposed_param_set
        .validate_for_admission()
        .expect_err("proposed parameter sets must not admit execution");
    assert!(matches!(
        error,
        SoracloudManifestError::InvalidField {
            field: "param_set.lifecycle",
            ..
        }
    ));
}

#[test]
fn secret_envelope_fixture_is_canonical() {
    let envelope = expected_secret_envelope();
    assert_fixture_eq(
        "secret_envelope_v1.json",
        SECRET_ENVELOPE_FIXTURE,
        &envelope,
    );
    assert_norito_roundtrip(&envelope);
    envelope.validate().expect("fixture should validate");
}

#[test]
fn ciphertext_state_record_fixture_is_canonical() {
    let record = expected_ciphertext_state_record();
    assert_fixture_eq(
        "ciphertext_state_record_v1.json",
        CIPHERTEXT_STATE_RECORD_FIXTURE,
        &record,
    );
    assert_norito_roundtrip(&record);
    record.validate().expect("fixture should validate");
}

#[test]
fn fhe_job_spec_fixture_is_canonical() {
    let job = expected_fhe_job_spec();
    assert_fixture_eq("fhe_job_spec_v1.json", FHE_JOB_SPEC_FIXTURE, &job);
    assert_norito_roundtrip(&job);
    job.validate().expect("fixture should validate");
    job.validate_for_execution(&expected_fhe_execution_policy(), &expected_fhe_param_set())
        .expect("fixture should pass execution admission checks");
}

#[test]
fn decryption_authority_policy_fixture_is_canonical() {
    let policy = expected_decryption_authority_policy();
    assert_fixture_eq(
        "decryption_authority_policy_v1.json",
        DECRYPTION_AUTHORITY_POLICY_FIXTURE,
        &policy,
    );
    assert_norito_roundtrip(&policy);
    policy.validate().expect("fixture should validate");
}

#[test]
fn decryption_request_fixture_is_canonical() {
    let request = expected_decryption_request();
    assert_fixture_eq(
        "decryption_request_v1.json",
        DECRYPTION_REQUEST_FIXTURE,
        &request,
    );
    assert_norito_roundtrip(&request);
    request
        .validate_for_policy(&expected_decryption_authority_policy())
        .expect("fixture should pass policy-linked validation");
}

#[test]
fn ciphertext_query_spec_fixture_is_canonical() {
    let spec = expected_ciphertext_query_spec();
    assert_fixture_eq(
        "ciphertext_query_spec_v1.json",
        CIPHERTEXT_QUERY_SPEC_FIXTURE,
        &spec,
    );
    assert_norito_roundtrip(&spec);
    spec.validate().expect("fixture should validate");
}

#[test]
fn ciphertext_query_response_fixture_is_canonical() {
    let response = expected_ciphertext_query_response();
    assert_fixture_eq(
        "ciphertext_query_response_v1.json",
        CIPHERTEXT_QUERY_RESPONSE_FIXTURE,
        &response,
    );
    assert_norito_roundtrip(&response);
    response.validate().expect("fixture should validate");
}

#[test]
#[ignore = "regenerates Soracloud fixture files"]
fn regenerate_soracloud_fixtures() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("soracloud");
    write_fixture(
        &base.join("sora_container_manifest_v1.json"),
        &expected_container_manifest(),
    );
    write_fixture(
        &base.join("sora_service_manifest_v1.json"),
        &expected_service_manifest(),
    );
    write_fixture(
        &base.join("sora_state_binding_v1.json"),
        &expected_state_binding(),
    );
    write_fixture(
        &base.join("sora_deployment_bundle_v1.json"),
        &expected_deployment_bundle(),
    );
    write_fixture(
        &base.join("agent_apartment_manifest_v1.json"),
        &expected_agent_apartment_manifest(),
    );
    write_fixture(
        &base.join("fhe_param_set_v1.json"),
        &expected_fhe_param_set(),
    );
    write_fixture(
        &base.join("fhe_execution_policy_v1.json"),
        &expected_fhe_execution_policy(),
    );
    write_fixture(
        &base.join("fhe_governance_bundle_v1.json"),
        &expected_fhe_governance_bundle(),
    );
    write_fixture(&base.join("fhe_job_spec_v1.json"), &expected_fhe_job_spec());
    write_fixture(
        &base.join("decryption_authority_policy_v1.json"),
        &expected_decryption_authority_policy(),
    );
    write_fixture(
        &base.join("decryption_request_v1.json"),
        &expected_decryption_request(),
    );
    write_fixture(
        &base.join("ciphertext_query_spec_v1.json"),
        &expected_ciphertext_query_spec(),
    );
    write_fixture(
        &base.join("ciphertext_query_response_v1.json"),
        &expected_ciphertext_query_response(),
    );
    write_fixture(
        &base.join("secret_envelope_v1.json"),
        &expected_secret_envelope(),
    );
    write_fixture(
        &base.join("ciphertext_state_record_v1.json"),
        &expected_ciphertext_state_record(),
    );
}
