#[test]
fn protected_status_commands_never_allow_offline_fallback_identity() {
    use clap::Parser as _;
    #[derive(clap::Parser)]
    struct SoracloudParser {
        #[command(subcommand)]
        command: super::Command,
    }
    for command in [
        vec!["soracloud", "app", "status"],
        vec!["soracloud", "service", "status"],
        vec!["soracloud", "agent", "status"],
        vec![
            "soracloud",
            "model",
            "training-job-status",
            "--service-name",
            "trainer",
            "--job-id",
            "job1",
        ],
        vec![
            "soracloud",
            "hf",
            "status",
            "--repo-id",
            "openai/gpt-oss",
            "--revision",
            TEST_HF_COMMIT_OID,
            "--storage-class",
            "warm",
            "--lease-term-ms",
            "60000",
        ],
    ] {
        let parsed = SoracloudParser::try_parse_from(&command)
            .unwrap_or_else(|error| panic!("failed to parse {command:?}: {error}"));
        assert!(
            !parsed.command.allows_fallback_config(),
            "protected command {command:?} must require a real client configuration"
        );
    }
}
#[test]
fn hf_cli_requires_explicit_v1_model_and_storage_inputs() {
    use clap::Parser as _;

    #[derive(clap::Parser, Debug)]
    struct HfParser {
        #[command(subcommand)]
        command: HfCommand,
    }
    let asset_definition = hf_shared_lease_asset_definition().to_string();
    let join = [
        "hf",
        "join",
        "--repo-id",
        "openai/gpt-oss",
        "--revision",
        TEST_HF_COMMIT_OID,
        "--service-name",
        "hf_service",
        "--storage-class",
        "warm",
        "--lease-term-ms",
        "60000",
        "--lease-asset-definition",
        asset_definition.as_str(),
        "--base-fee",
        "1",
    ];
    HfParser::try_parse_from(join).expect("parse explicit HF join V1 inputs");

    let without_storage = join
        .into_iter()
        .filter(|value| !matches!(*value, "--storage-class" | "warm"))
        .collect::<Vec<_>>();
    HfParser::try_parse_from(without_storage)
        .expect_err("HF shared-lease join must not default storage_class");

    for command in ["status", "lease-leave"] {
        HfParser::try_parse_from([
            "hf",
            command,
            "--repo-id",
            "openai/gpt-oss",
            "--revision",
            TEST_HF_COMMIT_OID,
            "--lease-term-ms",
            "60000",
        ])
        .expect_err("HF status and leave must require explicit storage_class");
    }
    let renew = [
        "hf",
        "lease-renew",
        "--repo-id",
        "openai/gpt-oss",
        "--revision",
        TEST_HF_COMMIT_OID,
        "--service-name",
        "hf_service",
        "--storage-class",
        "warm",
        "--lease-term-ms",
        "60000",
        "--lease-asset-definition",
        asset_definition.as_str(),
        "--base-fee",
        "1",
    ];
    HfParser::try_parse_from(renew).expect("parse explicit HF renew V1 inputs");
    let without_storage = renew
        .into_iter()
        .filter(|value| !matches!(*value, "--storage-class" | "warm"))
        .collect::<Vec<_>>();
    HfParser::try_parse_from(without_storage).expect_err("HF renew must not default storage_class");
}
#[test]
fn hf_cli_identity_parsers_reject_normalization_and_trim_aliases() {
    assert_eq!(
        parse_hf_service_name_arg("café").expect("canonical NFC service name"),
        "café"
    );
    assert_eq!(
        parse_hf_apartment_name_arg(Some("ops_agent")).expect("canonical apartment name"),
        Some("ops_agent".to_owned())
    );
    for noncanonical in [" café", "cafe\u{301}"] {
        let _error = parse_hf_service_name_arg(noncanonical)
            .expect_err("service-name trim and NFC aliases must fail");
    }
    for noncanonical in [" ops_agent", "ops_agent "] {
        let _error = parse_hf_apartment_name_arg(Some(noncanonical))
            .expect_err("apartment-name trim aliases must fail");
    }
    let _error = parse_asset_definition_arg(
        "--lease-asset-definition",
        &format!(" {}", hf_shared_lease_asset_definition()),
    )
    .expect_err("lease asset surrounding whitespace must fail");
    let _error = parse_hf_account_id_arg(Some(" account"))
        .expect_err("account surrounding whitespace must fail before parsing");
}
#[test]
fn signed_soracloud_cli_helpers_reject_exact_input_drift() {
    assert_eq!(
        parse_exact_name_arg("--service-name", "café").expect("canonical NFC name"),
        "café"
    );
    assert_eq!(
        parse_service_material_name_arg("--config-name", "runtime/config")
            .expect("canonical material name"),
        "runtime/config"
    );
    assert_eq!(
        parse_training_identifier_arg("--job-id", "job-1").expect("canonical training identifier"),
        "job-1"
    );
    assert_eq!(
        require_exact_nonempty_arg("--run-label", "nightly-run").expect("canonical exact text"),
        "nightly-run"
    );

    for noncanonical in [" café", "cafe\u{301}", "café "] {
        let _error = parse_exact_name_arg("--service-name", noncanonical)
            .expect_err("Name trim and NFC aliases must fail");
    }
    for noncanonical in [" config", "config ", "/config", "a/../config"] {
        let _error = parse_service_material_name_arg("--config-name", noncanonical)
            .expect_err("material-name aliases must fail");
    }
    for noncanonical in [" job-1", "job-1 ", "job 1", "jób-1"] {
        let _error = parse_training_identifier_arg("--job-id", noncanonical)
            .expect_err("training identifier aliases must fail");
    }
    for noncanonical in [" nightly-run", "nightly-run ", "nightly\nrun"] {
        let _error = require_exact_nonempty_arg("--run-label", noncanonical)
            .expect_err("exact text aliases must fail");
    }
}
#[test]
fn app_init_template_accepts_only_canonical_v1_names() {
    use clap::ValueEnum as _;

    assert_eq!(
        AppInitTemplate::from_str("single-api", false).expect("canonical single-api name"),
        AppInitTemplate::SingleApi
    );
    assert_eq!(
        AppInitTemplate::from_str("split-app", false).expect("canonical split-app name"),
        AppInitTemplate::SplitApp
    );
    assert!(
        AppInitTemplate::from_str("nexus-split-app", false).is_err(),
        "first-release CLI must reject the retired template alias"
    );
}
#[test]
fn app_cli_exposes_only_the_mandatory_release_mutation_path() {
    use clap::Parser as _;

    #[derive(clap::Parser)]
    struct AppParser {
        #[command(subcommand)]
        command: AppCommand,
    }

    for retired in ["deploy", "upgrade"] {
        assert!(
            AppParser::try_parse_from(["app", retired]).is_err(),
            "direct app mutation command `{retired}` must not be part of V1"
        );
    }
    assert!(
        AppParser::try_parse_from([
            "app",
            "release",
            "--manifest",
            "app_manifest.json",
            "--torii-url",
            "http://127.0.0.1:8080",
            "--skip-build",
        ])
        .is_err(),
        "V1 app release must reject the retired build bypass"
    );
    assert!(
        AppParser::try_parse_from([
            "app",
            "doctor",
            "--manifest",
            "app_manifest.json",
            "--dry-run",
        ])
        .is_err(),
        "V1 app doctor has no advertised dry-run mode"
    );
}
#[test]
fn skipped_app_phases_are_never_reported_ok() {
    let phase = skipped_app_phase("verify", "not executed");
    assert!(phase.skipped);
    assert!(!phase.ok);
}
#[test]
fn positive_quantity_parser_accepts_exact_sub_nano_and_wide_values() {
    for canonical in [
        "0.0000000000000000000000000001",
        "340282366920938463463374607431768211456.0000000001",
    ] {
        let quantity = parse_positive_quantity(canonical).expect("canonical quantity");
        assert_eq!(quantity.to_string(), canonical);
    }
}
#[test]
fn positive_quantity_parser_rejects_zero_and_noncanonical_values() {
    for invalid in [
        "",
        " 1",
        "1 ",
        "+1",
        "01",
        "1.0",
        ".5",
        "1.",
        "-1",
        "0",
        "0.00000000000000000000000000001",
    ] {
        assert!(
            parse_positive_quantity(invalid).is_err(),
            "invalid quantity must be rejected: {invalid:?}"
        );
    }
}
#[test]
fn generated_kotodama_contract_fixtures_compile_with_canonical_v1_surface() {
    for (name, source) in [
        ("single-api", single_api_contract_ko("travel_ops")),
        ("hayahi-app", hayahi_app_contract_ko("hayahi_api")),
        ("split-app-vault", split_app_vault_contract_ko("travel_ops")),
    ] {
        let (program, _) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(&source)
            .unwrap_or_else(|error| panic!("{name} Kotodama fixture must compile: {error:?}"));
        let interface = ivm::ProgramMetadata::parse(&program)
            .expect("generated contract metadata")
            .contract_interface
            .expect("generated contract interface");
        assert!(!interface.entrypoints.is_empty(), "{name} has no entrypoints");
        for entrypoint in interface.entrypoints {
            assert_eq!(
                entrypoint.authorization,
                iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
                "{name} entrypoint {} must declare public scaffold access",
                entrypoint.name
            );
        }
    }
}
#[test]
fn soracloud_temp_dir_reports_suffix_rng_failure() {
    let mut rng = FailingSoracloudSignatureNonceRng;
    let error = match SoracloudTempDir::new_with_rng("iroha-soracloud-temp", &mut rng) {
        Ok(tempdir) => panic!(
            "temporary directory suffix RNG unexpectedly succeeded at `{}`",
            tempdir.path().display()
        ),
        Err(error) => error,
    };
    let message = format!("{error:?}");
    assert!(message.contains("Soracloud temporary directory suffix OS RNG failed"));
    assert!(message.contains("failing Soracloud signature nonce RNG"));
}
fn assert_manifest_pair_service_plan(output: &norito::json::Value) {
    assert_eq!(
        output
            .get("service_plan")
            .and_then(norito::json::Value::as_object)
            .and_then(|plan| plan.get("route_path_prefix"))
            .and_then(norito::json::Value::as_str),
        Some("/api/v1")
    );
    assert!(
        output
            .get("service_plan")
            .and_then(norito::json::Value::as_object)
            .and_then(|plan| plan.get("workspace_scripts"))
            .and_then(norito::json::Value::as_object)
            .and_then(|scripts| scripts.get("local_dev"))
            .and_then(norito::json::Value::as_str)
            .is_some_and(|path| path.ends_with("dev.sh"))
    );
}
fn assert_manifest_pair_output(
    output: &norito::json::Value,
    workspace_script: &str,
    script_suffix: &str,
) {
    assert_eq!(
        output
            .get("service_name")
            .and_then(norito::json::Value::as_str),
        Some("echo_console")
    );
    let service_plan = output
        .get("service_plan")
        .and_then(norito::json::Value::as_object)
        .expect("manifest-backed service plan");
    assert_eq!(
        service_plan
            .get("route_path_prefix")
            .and_then(norito::json::Value::as_str),
        Some("/api/v1")
    );
    assert!(
        service_plan
            .get("workspace_scripts")
            .and_then(norito::json::Value::as_object)
            .and_then(|scripts| scripts.get(workspace_script))
            .and_then(norito::json::Value::as_str)
            .is_some_and(|path| path.ends_with(script_suffix))
    );
}
fn assert_captured_payload_service_name(
    server: &MockHttpServer,
    path: &str,
    request_expectation: &str,
    decode_expectation: &str,
) -> norito::json::Value {
    let request = server
        .requests()
        .into_iter()
        .find(|request| request.method == "POST" && request.path == path)
        .unwrap_or_else(|| panic!("{request_expectation}"));
    let body: norito::json::Value = json::from_slice(&request.body)
        .unwrap_or_else(|error| panic!("{decode_expectation}: {error}"));
    assert_eq!(
        body.get("payload")
            .and_then(norito::json::Value::as_object)
            .and_then(|payload| payload.get("service_name"))
            .and_then(norito::json::Value::as_str),
        Some("echo_console")
    );
    body
}
fn fixture_container() -> SoraContainerManifestV1 {
    load_json(&workspace_fixture(DEFAULT_CONTAINER_MANIFEST)).expect("container fixture")
}
fn fixture_service() -> SoraServiceManifestV1 {
    load_json(&workspace_fixture(DEFAULT_SERVICE_MANIFEST)).expect("service fixture")
}
fn fixture_agent_apartment() -> AgentApartmentManifestV1 {
    load_json(&workspace_fixture(DEFAULT_AGENT_APARTMENT_MANIFEST))
        .expect("agent apartment fixture")
}
fn agent_apartment_status_fixture(
    apartment_name: &str,
    last_active_sequence: u64,
) -> AgentApartmentStatusEntryV1 {
    AgentApartmentStatusEntryV1 {
        apartment_name: apartment_name.parse().expect("canonical apartment name"),
        manifest_hash: Hash::new(format!("{apartment_name}:manifest").as_bytes()),
        status: SoraAgentRuntimeStatusV1::Running,
        lease_started_sequence: 1,
        lease_expires_sequence: 1_000,
        lease_remaining_ticks: 1_000_u64.saturating_sub(last_active_sequence),
        restart_count: 0,
        state_quota_bytes: 4_096,
        tool_capability_count: 1,
        policy_capability_count: 1,
        revoked_policy_capability_count: 0,
        pending_wallet_request_count: 0,
        pending_mailbox_message_count: 0,
        autonomy_budget_ceiling_units: 100,
        autonomy_budget_remaining_units: 90,
        artifact_allowlist_count: 0,
        autonomy_run_count: 0,
        process_generation: 1,
        process_started_sequence: 1,
        last_active_sequence,
        last_checkpoint_sequence: None,
        checkpoint_count: 0,
        persistent_state_total_bytes: 0,
        persistent_state_key_count: 0,
        spend_limit_count: 1,
        upgrade_policy: AgentUpgradePolicyV1::Governed,
        last_restart_sequence: None,
        last_restart_reason: None,
    }
}
fn agent_status_fixture(apartments: Vec<AgentApartmentStatusEntryV1>) -> json::Value {
    json::to_value(&AgentStatusResponseV1 {
        schema_version: SORACLOUD_STATUS_SCHEMA_VERSION_V1,
        apartment_count: u32::try_from(apartments.len()).expect("fixture count"),
        event_count: 3,
        apartments,
    })
    .expect("encode exact agent status fixture")
}
fn mailbox_message_fixture(
    message_id: &str,
    from_apartment: &str,
    channel: &str,
    payload: &str,
    enqueued_sequence: u64,
) -> AgentMailboxMessageEntryV1 {
    AgentMailboxMessageEntryV1 {
        message_id: message_id.to_owned(),
        from_apartment: from_apartment.parse().expect("canonical sender apartment"),
        channel: channel.to_owned(),
        payload: payload.to_owned(),
        payload_hash: Hash::new(payload.as_bytes()),
        enqueued_sequence,
    }
}
fn mailbox_status_fixture(messages: Vec<AgentMailboxMessageEntryV1>) -> json::Value {
    json::to_value(&AgentMailboxStatusResponseV1 {
        schema_version: SORACLOUD_STATUS_SCHEMA_VERSION_V1,
        apartment_name: "worker_agent".parse().expect("canonical apartment name"),
        status: SoraAgentRuntimeStatusV1::Running,
        pending_message_count: u32::try_from(messages.len()).expect("fixture count"),
        event_count: 4,
        messages,
    })
    .expect("encode exact mailbox status fixture")
}
fn autonomy_status_fixture() -> AgentAutonomyStatusResponseV1 {
    AgentAutonomyStatusResponseV1 {
        apartment_name: "ops_agent".parse().expect("canonical apartment name"),
        sequence: 10,
        status: SoraAgentRuntimeStatusV1::Running,
        lease_expires_sequence: 100,
        lease_remaining_ticks: 90,
        manifest_hash: Hash::new(b"agent autonomy manifest"),
        revoked_policy_capability_count: 0,
        budget_ceiling_units: 100,
        budget_remaining_units: 90,
        allowlist_count: 1,
        run_count: 1,
        process_generation: 1,
        process_started_sequence: 1,
        last_active_sequence: 10,
        last_checkpoint_sequence: None,
        checkpoint_count: 0,
        persistent_state_total_bytes: 0,
        persistent_state_key_count: 0,
        allowlist: vec![AgentAutonomyAllowlistEntryV1 {
            artifact_hash: "hash:agent-artifact#1".to_owned(),
            provenance_hash: None,
            added_sequence: 2,
        }],
        recent_runs: vec![AgentAutonomyRunStatusRecordV1 {
            run_id: "ops_agent:autonomy:9".to_owned(),
            artifact_hash: "hash:agent-artifact#1".to_owned(),
            provenance_hash: None,
            budget_units: 10,
            run_label: "fixture".to_owned(),
            workflow_input_json: None,
            approved_sequence: 9,
            authoritative_runtime_receipt: None,
            authoritative_execution_audit: None,
        }],
    }
}
fn hf_status_fixture() -> HfSharedLeaseStatusResponseV1 {
    HfSharedLeaseStatusResponseV1 {
        schema_version: SORACLOUD_STATUS_SCHEMA_VERSION_V1,
        source: SoraHfSourceRecordV1 {
            schema_version: 1,
            source_id: iroha::data_model::soracloud::derive_hf_source_id_v1(
                "openai/gpt-oss",
                TEST_HF_COMMIT_OID,
            )
            .expect("canonical HF source id"),
            repo_id: "openai/gpt-oss".to_owned(),
            resolved_revision: TEST_HF_COMMIT_OID.to_owned(),
            created_at_ms: 1,
            updated_at_ms: 1,
        },
        pool: None,
        member: None,
        latest_audit_event: None,
        audit_event_count: 0,
        storage_base_fee: Quantity::zero(),
    }
}
fn app_infra_status_fixture() -> AppInfraStatusResponseV1 {
    app_infra_status_fixture_for_name("test_app")
}
fn app_infra_status_fixture_for_name(app_name: &str) -> AppInfraStatusResponseV1 {
    let container = fixture_container();
    let mut service = fixture_service();
    service.container.manifest_hash = Hash::new(Encode::encode(&container));
    let bundle = SoraDeploymentBundleV1 {
        schema_version: SORA_DEPLOYMENT_BUNDLE_VERSION_V1,
        container,
        service,
    };
    let manifest = SoraAppInfraManifestV1 {
        schema_version: SORA_APP_INFRA_MANIFEST_VERSION_V1,
        app_name: app_name.parse().expect("canonical app name"),
        app_version: "1.0.0".to_owned(),
        public_url: "https://test.invalid".to_owned(),
        static_site: None,
        services: vec![
            build_app_infra_service_ref(&bundle).expect("canonical app service reference"),
        ],
    };
    let manifest_hash = manifest.manifest_hash();
    let app_name = manifest.app_name.clone();
    let key_pair = soracloud_fixture_key_pair(0x73);
    AppInfraStatusResponseV1 {
        schema_version: SORACLOUD_STATUS_SCHEMA_VERSION_V1,
        app_count: 1,
        audit_event_count: 1,
        apps: vec![SoraAppInfraStateV1 {
            schema_version: 1,
            app_name: app_name.clone(),
            current_app_version: manifest.app_version.clone(),
            current_manifest_hash: manifest_hash,
            revision_count: 1,
            deployed_sequence: 1,
            updated_sequence: 1,
            manifest,
        }],
        recent_audit_events: vec![SoraAppInfraAuditEventV1 {
            schema_version: 1,
            sequence: 1,
            action: iroha::data_model::soracloud::SoraAppInfraActionV1::Deploy,
            app_name,
            from_version: None,
            to_version: "1.0.0".to_owned(),
            app_manifest_hash: manifest_hash,
            service_count: 1,
            signer: key_pair.public_key().clone(),
        }],
    }
}
fn service_config_status_fixture(
    service_name: &str,
    config_name: &str,
) -> ServiceConfigStatusResponseV1 {
    let value_json = norito::json!({"enabled": true});
    let value_hash = SoraServiceConfigEntryV1 {
        schema_version: SORA_SERVICE_CONFIG_ENTRY_VERSION_V1,
        config_name: config_name.to_owned(),
        value_json: Json::from(value_json.clone()),
        value_hash: Hash::new(b"placeholder"),
        last_update_sequence: 1,
    }
    .canonical_value_hash()
    .expect("canonical config value hash");
    ServiceConfigStatusResponseV1 {
        schema_version: SORACLOUD_STATUS_SCHEMA_VERSION_V1,
        service_name: service_name.parse().expect("canonical service name"),
        current_version: "1.0.0".to_owned(),
        config_generation: 1,
        config_entry_count: 1,
        configs: vec![ServiceConfigStatusEntryV1 {
            config_name: config_name.to_owned(),
            value_hash,
            value_json,
            last_update_sequence: 1,
        }],
    }
}
fn service_secret_status_fixture(
    service_name: &str,
    secret_name: &str,
) -> ServiceSecretStatusResponseV1 {
    ServiceSecretStatusResponseV1 {
        schema_version: SORACLOUD_STATUS_SCHEMA_VERSION_V1,
        service_name: service_name.parse().expect("canonical service name"),
        current_version: "1.0.0".to_owned(),
        secret_generation: 1,
        secret_entry_count: 1,
        secrets: vec![ServiceSecretStatusEntryV1 {
            secret_name: secret_name.to_owned(),
            encryption: SecretEnvelopeEncryptionV1::ClientCiphertext,
            key_id: "kms/test".to_owned(),
            key_version: 1,
            commitment: Hash::new(b"secret commitment"),
            ciphertext_bytes: 32,
            last_update_sequence: 1,
        }],
    }
}
fn training_job_status_fixture(service_name: &str, job_id: &str) -> TrainingJobStatusResponseV1 {
    TrainingJobStatusResponseV1 {
        schema_version: SORACLOUD_STATUS_SCHEMA_VERSION_V1,
        job: TrainingJobStatusEntryV1 {
            service_name: service_name.parse().expect("canonical service name"),
            model_name: "fare-model".parse().expect("canonical model name"),
            job_id: job_id.to_owned(),
            status: SoraTrainingJobStatusV1::Running,
            worker_group_size: 1,
            target_steps: 100,
            completed_steps: 10,
            checkpoint_interval_steps: 10,
            last_checkpoint_step: Some(10),
            checkpoint_count: 1,
            retry_count: 0,
            max_retries: 3,
            step_compute_units: 10,
            compute_budget_units: 1_000,
            compute_consumed_units: 100,
            compute_remaining_units: 900,
            storage_budget_bytes: 1_024,
            storage_consumed_bytes: 64,
            storage_remaining_bytes: 960,
            latest_metrics_hash: Some(Hash::new(b"metrics")),
            last_failure_reason: None,
            created_sequence: 1,
            updated_sequence: 2,
        },
    }
}
fn model_artifact_status_fixture(
    service_name: &str,
    training_job_id: &str,
) -> ModelArtifactStatusResponseV1 {
    let artifact = ModelArtifactStatusEntryV1 {
        service_name: service_name.parse().expect("canonical service name"),
        model_name: "fare-model".parse().expect("canonical model name"),
        artifact_id: training_job_id.to_owned(),
        training_job_id: training_job_id.to_owned(),
        weight_version: None,
        weight_artifact_hash: Hash::new(b"weights"),
        dataset_ref: "dataset:v1".to_owned(),
        training_config_hash: Hash::new(b"training config"),
        reproducibility_hash: Hash::new(b"reproducibility"),
        provenance_attestation_hash: Hash::new(b"provenance"),
        registered_sequence: 2,
        consumed_by_version: None,
        chunk_manifest_root: None,
    };
    ModelArtifactStatusResponseV1 {
        schema_version: SORACLOUD_STATUS_SCHEMA_VERSION_V1,
        service_name: artifact.service_name.clone(),
        model_name: artifact.model_name.clone(),
        artifact_count: 1,
        artifact: artifact.clone(),
        artifacts: vec![artifact],
    }
}
fn model_weight_status_fixture(
    service_name: &str,
    model_name: &str,
) -> ModelWeightStatusResponseV1 {
    ModelWeightStatusResponseV1 {
        schema_version: SORACLOUD_STATUS_SCHEMA_VERSION_V1,
        model: ModelWeightStatusEntryV1 {
            service_name: service_name.parse().expect("canonical service name"),
            model_name: model_name.parse().expect("canonical model name"),
            current_version: Some("v1".to_owned()),
            version_count: 1,
            versions: vec![ModelWeightVersionEntryV1 {
                weight_version: "v1".to_owned(),
                parent_version: None,
                training_job_id: "job-1".to_owned(),
                weight_artifact_hash: Hash::new(b"weights"),
                dataset_ref: "dataset:v1".to_owned(),
                training_config_hash: Hash::new(b"training config"),
                reproducibility_hash: Hash::new(b"reproducibility"),
                provenance_attestation_hash: Hash::new(b"provenance"),
                registered_sequence: 2,
                promoted_sequence: Some(3),
                gate_report_hash: Some(Hash::new(b"gate report")),
            }],
        },
    }
}
fn soracloud_fixture_key_pair(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
        .expect("fixture seed must derive a valid Soracloud keypair")
}
#[test]
fn agent_status_v1_is_closed_and_rejects_duplicate_apartments() {
    let apartment = agent_apartment_status_fixture("ops_agent", 10);
    let canonical = agent_status_fixture(vec![apartment.clone()]);
    decode_agent_status(&canonical).expect("decode exact agent status V1");

    let mut unknown_root = canonical.clone();
    unknown_root
        .as_object_mut()
        .expect("agent status object")
        .insert("legacy_apartments".to_owned(), json::Value::Null);
    let _ = decode_agent_status(&unknown_root).expect_err("unknown root field must fail");

    let mut unknown_apartment = canonical.clone();
    unknown_apartment
        .get_mut("apartments")
        .and_then(json::Value::as_array_mut)
        .and_then(|apartments| apartments.first_mut())
        .and_then(json::Value::as_object_mut)
        .expect("agent apartment object")
        .insert("legacy_runtime".to_owned(), json::Value::Null);
    let _ = decode_agent_status(&unknown_apartment).expect_err("unknown apartment field must fail");

    let mut missing_apartment_field = canonical.clone();
    missing_apartment_field
        .get_mut("apartments")
        .and_then(json::Value::as_array_mut)
        .and_then(|apartments| apartments.first_mut())
        .and_then(json::Value::as_object_mut)
        .expect("agent apartment object")
        .remove("last_checkpoint_sequence");
    let _ = decode_agent_status(&missing_apartment_field)
        .expect_err("required nullable apartment field must not be omitted");

    let duplicate = agent_status_fixture(vec![apartment.clone(), apartment]);
    let error = decode_agent_status(&duplicate).expect_err("duplicate apartment must fail");
    assert!(error.to_string().contains("duplicate apartment"), "{error}");
}
#[test]
fn mailbox_status_v1_selects_exactly_one_new_matching_message() {
    let old = mailbox_message_fixture(
        "worker_agent:mail:2",
        "ops_agent",
        "ops.sync",
        "rotate-key-42",
        2,
    );
    let new = mailbox_message_fixture(
        "worker_agent:mail:3",
        "ops_agent",
        "ops.sync",
        "rotate-key-42",
        3,
    );
    let before = mailbox_status_fixture(vec![old.clone()]);
    let known = mailbox_message_ids(&before).expect("decode baseline message ids");
    let after = mailbox_status_fixture(vec![old, new.clone()]);
    let selected =
        new_mailbox_message_from_status(&after, &known, "ops_agent", "ops.sync", "rotate-key-42")
            .expect("select the one new matching message");
    assert_eq!(selected.message_id, new.message_id);

    let key_pair = soracloud_fixture_key_pair(0x74);
    let authority = AccountId::new(key_pair.public_key().clone());
    let output = build_message_send_output(
        mock_soracloud_submission_receipt(&authority, &key_pair),
        &after,
        &known,
        "ops_agent",
        "ops.sync",
        "rotate-key-42",
    )
    .expect("build exact message send output");
    assert_eq!(
        output.get("message_id").and_then(json::Value::as_str),
        Some("worker_agent:mail:3")
    );

    let ambiguous = mailbox_status_fixture(vec![
        mailbox_message_fixture(
            "worker_agent:mail:2",
            "ops_agent",
            "ops.sync",
            "rotate-key-42",
            2,
        ),
        new,
        mailbox_message_fixture(
            "worker_agent:mail:4",
            "ops_agent",
            "ops.sync",
            "rotate-key-42",
            4,
        ),
    ]);
    let error = new_mailbox_message_from_status(
        &ambiguous,
        &known,
        "ops_agent",
        "ops.sync",
        "rotate-key-42",
    )
    .expect_err("multiple new matching messages must fail");
    assert!(
        error.to_string().contains("multiple newly enqueued"),
        "{error}"
    );
}
#[test]
fn mailbox_status_v1_is_closed_and_ack_requires_exact_removal() {
    let message =
        mailbox_message_fixture("worker_agent:mail:7", "ops_agent", "ops.sync", "ack-me", 7);
    let before = mailbox_status_fixture(vec![message]);
    let after = mailbox_status_fixture(Vec::new());
    let key_pair = soracloud_fixture_key_pair(0x75);
    let authority = AccountId::new(key_pair.public_key().clone());
    let _ = build_message_ack_output(
        mock_soracloud_submission_receipt(&authority, &key_pair),
        &before,
        &after,
        "worker_agent:mail:7",
    )
    .expect("acknowledged message must be absent after mutation");
    let _ = build_message_ack_output(
        mock_soracloud_submission_receipt(&authority, &key_pair),
        &before,
        &before,
        "worker_agent:mail:7",
    )
    .expect_err("message still present after ack must fail");

    let mut unknown_message = before;
    unknown_message
        .get_mut("messages")
        .and_then(json::Value::as_array_mut)
        .and_then(|messages| messages.first_mut())
        .and_then(json::Value::as_object_mut)
        .expect("mailbox message object")
        .insert("legacy_id".to_owned(), json::Value::Null);
    let _ = decode_agent_mailbox_status(&unknown_message)
        .expect_err("unknown mailbox message field must fail");

    let mut missing_message_field = mailbox_status_fixture(vec![mailbox_message_fixture(
        "worker_agent:mail:8",
        "ops_agent",
        "ops.sync",
        "missing-field",
        8,
    )]);
    missing_message_field
        .get_mut("messages")
        .and_then(json::Value::as_array_mut)
        .and_then(|messages| messages.first_mut())
        .and_then(json::Value::as_object_mut)
        .expect("mailbox message object")
        .remove("payload_hash");
    let _ = decode_agent_mailbox_status(&missing_message_field)
        .expect_err("missing mailbox message field must fail");
}
#[test]
fn autonomy_status_v1_rejects_unknown_fields_and_duplicate_run_ids() {
    let canonical_status = autonomy_status_fixture();
    let canonical =
        json::to_value(&canonical_status).expect("encode exact autonomy status fixture");
    decode_agent_autonomy_status(&canonical).expect("decode exact autonomy status V1");

    let mut unknown_run = canonical.clone();
    unknown_run
        .get_mut("recent_runs")
        .and_then(json::Value::as_array_mut)
        .and_then(|runs| runs.first_mut())
        .and_then(json::Value::as_object_mut)
        .expect("autonomy run object")
        .insert("legacy_receipt".to_owned(), json::Value::Null);
    let _ = decode_agent_autonomy_status(&unknown_run).expect_err("unknown run field must fail");

    let mut duplicate_status = canonical_status;
    duplicate_status.run_count = 2;
    duplicate_status
        .recent_runs
        .push(duplicate_status.recent_runs[0].clone());
    let duplicate = json::to_value(&duplicate_status).expect("encode duplicate run fixture");
    let error =
        decode_agent_autonomy_status(&duplicate).expect_err("duplicate autonomy run id must fail");
    assert!(error.to_string().contains("duplicate run_id"), "{error}");
}
#[test]
fn hf_status_v1_is_closed_at_root_and_nested_source() {
    let canonical = json::to_value(&hf_status_fixture()).expect("encode exact HF status fixture");
    decode_hf_shared_lease_status(&canonical).expect("decode exact HF status V1");

    let mut unknown_root = canonical.clone();
    unknown_root
        .as_object_mut()
        .expect("HF status object")
        .insert("legacy_fee".to_owned(), json::Value::Null);
    let _ =
        decode_hf_shared_lease_status(&unknown_root).expect_err("unknown HF root field must fail");

    let mut unknown_source = canonical;
    unknown_source
        .get_mut("source")
        .and_then(json::Value::as_object_mut)
        .expect("HF source object")
        .insert("branch".to_owned(), json::Value::String("main".to_owned()));
    let _ = decode_hf_shared_lease_status(&unknown_source)
        .expect_err("unknown HF source field must fail");

    let mut missing_nullable =
        json::to_value(&hf_status_fixture()).expect("encode exact HF status fixture");
    missing_nullable
        .as_object_mut()
        .expect("HF status object")
        .remove("pool");
    let _ = decode_hf_shared_lease_status(&missing_nullable)
        .expect_err("required nullable HF field must not be omitted");
}
#[test]
fn app_infra_status_v1_is_closed_and_rejects_duplicate_apps() {
    let canonical_status = app_infra_status_fixture();
    let canonical =
        json::to_value(&canonical_status).expect("encode exact app-infra status fixture");
    decode_app_infra_status(&canonical).expect("decode exact app-infra status V1");

    let mut unknown_state = canonical.clone();
    unknown_state
        .get_mut("apps")
        .and_then(json::Value::as_array_mut)
        .and_then(|apps| apps.first_mut())
        .and_then(json::Value::as_object_mut)
        .expect("app state object")
        .insert("legacy_version".to_owned(), json::Value::Null);
    let _ = decode_app_infra_status(&unknown_state).expect_err("unknown app state field must fail");

    let mut missing_apps = canonical;
    missing_apps
        .as_object_mut()
        .expect("app-infra status object")
        .remove("apps");
    let _ = decode_app_infra_status(&missing_apps).expect_err("missing app list must fail");

    let mut duplicate_status = canonical_status;
    duplicate_status.app_count = 2;
    duplicate_status.apps.push(duplicate_status.apps[0].clone());
    let duplicate = json::to_value(&duplicate_status).expect("encode duplicate app fixture");
    let error = decode_app_infra_status(&duplicate).expect_err("duplicate app must fail");
    assert!(error.to_string().contains("duplicate app"), "{error}");
}
#[test]
fn exact_torii_json_success_rejects_alternate_status_content_type_and_body() {
    let json_content_type = HeaderValue::from_static("application/json");
    let text_content_type = HeaderValue::from_static("text/plain");
    let valid_body = br#"{"schema_version":1}"#;

    let _ = decode_exact_torii_json_success(
        reqwest::StatusCode::CREATED,
        Some(&json_content_type),
        valid_body,
        "fixture",
    )
    .expect_err("alternate 2xx status must fail");
    let _ = decode_exact_torii_json_success(reqwest::StatusCode::OK, None, valid_body, "fixture")
        .expect_err("missing JSON content type must fail");
    let _ = decode_exact_torii_json_success(
        reqwest::StatusCode::OK,
        Some(&text_content_type),
        valid_body,
        "fixture",
    )
    .expect_err("non-JSON content type must fail");
    let _ = decode_exact_torii_json_success(
        reqwest::StatusCode::OK,
        Some(&json_content_type),
        &[],
        "fixture",
    )
    .expect_err("bodyless JSON success must fail");
    let _ = decode_exact_torii_json_success(
        reqwest::StatusCode::OK,
        Some(&json_content_type),
        b"not-json",
        "fixture",
    )
    .expect_err("malformed JSON success must fail");
    assert_eq!(
        decode_exact_torii_json_success(
            reqwest::StatusCode::OK,
            Some(&json_content_type),
            valid_body,
            "fixture",
        )
        .expect("exact 200 JSON response"),
        norito::json!({"schema_version": 1})
    );
}
#[test]
fn remaining_status_v1_dtos_are_closed_and_validate_invariants() {
    macro_rules! closed_status_case {
        ($fixture:expr, $decoder:ident, $label:literal) => {{
            let canonical = json::to_value(&$fixture).expect(concat!("encode ", $label));
            $decoder(&canonical).expect(concat!("decode ", $label));
            let mut unknown = canonical;
            unknown
                .as_object_mut()
                .expect(concat!($label, " object"))
                .insert("retired_v0".to_owned(), json::Value::Null);
            let _ = $decoder(&unknown).expect_err(concat!($label, " unknown field must fail"));
        }};
    }
    closed_status_case!(
        service_config_status_fixture("echo_console", "demo_config"),
        decode_service_config_status,
        "service-config status"
    );
    closed_status_case!(
        service_secret_status_fixture("echo_console", "demo_secret"),
        decode_service_secret_status,
        "service-secret status"
    );
    closed_status_case!(
        training_job_status_fixture("echo_console", "job-1"),
        decode_training_job_status,
        "training-job status"
    );
    closed_status_case!(
        model_artifact_status_fixture("echo_console", "job-1"),
        decode_model_artifact_status,
        "model-artifact status"
    );
    closed_status_case!(
        model_weight_status_fixture("echo_console", "fare-model"),
        decode_model_weight_status,
        "model-weight status"
    );
    closed_status_case!(
        uploaded_model_status_fixture("echo_console", "fare-model", "v1"),
        decode_uploaded_model_status,
        "uploaded-model status"
    );
    let mut config = service_config_status_fixture("echo_console", "demo_config");
    config.config_entry_count = 0;
    let config = json::to_value(&config).expect("encode malformed config status");
    let _ = decode_service_config_status(&config).expect_err("config count mismatch must fail");

    let mut training = training_job_status_fixture("echo_console", "job-1");
    training.job.compute_remaining_units += 1;
    let training = json::to_value(&training).expect("encode malformed training status");
    let _ = decode_training_job_status(&training).expect_err("training budget mismatch must fail");

    let mut artifact = model_artifact_status_fixture("echo_console", "job-1");
    artifact.artifact_count = 0;
    let artifact = json::to_value(&artifact).expect("encode malformed artifact status");
    let _ = decode_model_artifact_status(&artifact).expect_err("artifact count mismatch must fail");

    let mut weight = model_weight_status_fixture("echo_console", "fare-model");
    weight.model.version_count = 0;
    let weight = json::to_value(&weight).expect("encode malformed weight status");
    let _ = decode_model_weight_status(&weight).expect_err("weight count mismatch must fail");
}
#[test]
fn public_discovery_config_status_reserves_none_for_exact_not_found() {
    let mut route =
        reqwest::Url::parse("http://fixture.invalid/v1/soracloud/service/config/status")
            .expect("fixture URL");
    route
        .query_pairs_mut()
        .append_pair("service_name", "echo_console")
        .append_pair("config_name", PUBLIC_SERVICE_DISCOVERY_CONFIG_NAME);
    let path = format!("{}?{}", route.path(), route.query().expect("fixture query"));
    let mut empty_success =
        service_config_status_fixture("echo_console", PUBLIC_SERVICE_DISCOVERY_CONFIG_NAME);
    empty_success.config_entry_count = 0;
    empty_success.configs.clear();
    let malformed_server = MockHttpServer::start(BTreeMap::from([(
        path.clone(),
        MockHttpResponse::json(
            json::to_vec(&empty_success).expect("encode empty successful config status"),
        ),
    )]));
    install_mock_protected_read_signer();
    let error = fetch_existing_public_service_discovery_registry(
        &malformed_server.base_url,
        "echo_console",
        None,
        5,
    )
    .expect_err("malformed 200 discovery config status must fail");
    assert!(error.to_string().contains("exactly the requested config"));

    let not_found_server = MockHttpServer::start(BTreeMap::new());
    install_mock_protected_read_signer();
    assert!(
        fetch_existing_public_service_discovery_registry(
            &not_found_server.base_url,
            "echo_console",
            None,
            5,
        )
        .expect("exact 404 means no existing registry")
        .is_none()
    );
}
#[test]
fn wallet_spend_v1_requires_and_emits_the_caller_request_id() {
    use clap::Parser as _;

    #[derive(clap::Parser, Debug)]
    struct AgentParser {
        #[command(subcommand)]
        command: AgentCommand,
    }
    let base = [
        "agent",
        "wallet-spend",
        "--apartment-name",
        "ops_agent",
        "--asset-definition",
        "61CtjvNd9T3THAR65GsMVHr82Bjc",
        "--amount",
        "1",
    ];
    let _ = AgentParser::try_parse_from(base).expect_err("wallet-spend must require --request-id");
    let _ = AgentParser::try_parse_from([
        "agent",
        "wallet-spend",
        "--apartment-name",
        "ops_agent",
        "--request-id",
        "wallet-spend-fixture-1",
        "--asset-definition",
        " 61CtjvNd9T3THAR65GsMVHr82Bjc",
        "--amount",
        "1",
    ])
    .expect_err("wallet-spend must reject surrounding asset-definition whitespace");
    for invalid in [" wallet-spend-fixture-1", "wallet\nspend"] {
        let _ = parse_agent_wallet_request_id(invalid)
            .expect_err("non-canonical wallet request id must fail");
    }
    let _ = parse_agent_wallet_request_id(&"x".repeat(129))
        .expect_err("oversized wallet request id must fail");
    let parsed = AgentParser::try_parse_from([
        "agent",
        "wallet-spend",
        "--apartment-name",
        "ops_agent",
        "--request-id",
        "wallet-spend-fixture-1",
        "--asset-definition",
        "61CtjvNd9T3THAR65GsMVHr82Bjc",
        "--amount",
        "1",
    ])
    .expect("parse exact wallet-spend V1 arguments");
    let AgentCommand::WalletSpend(args) = parsed.command else {
        panic!("expected wallet-spend command")
    };
    assert_eq!(args.request_id, "wallet-spend-fixture-1");

    let status = agent_status_fixture(vec![agent_apartment_status_fixture("ops_agent", 10)]);
    let key_pair = soracloud_fixture_key_pair(0x76);
    let authority = AccountId::new(key_pair.public_key().clone());
    let output = build_wallet_spend_output(
        mock_soracloud_submission_receipt(&authority, &key_pair),
        &status,
        "ops_agent",
        "wallet-spend-fixture-1",
    )
    .expect("build wallet-spend output with exact caller id");
    assert_eq!(
        output.get("request_id").and_then(json::Value::as_str),
        Some("wallet-spend-fixture-1")
    );

    let payload = AgentWalletSpendPayload {
        apartment_name: "ops_agent".to_owned(),
        request_id: "wallet-spend-fixture-1".to_owned(),
        asset_definition: "61CtjvNd9T3THAR65GsMVHr82Bjc".to_owned(),
        amount: "1".parse().expect("canonical amount"),
    };
    let canonical = json::to_value(&payload).expect("encode wallet-spend payload");
    let mut missing = canonical.clone();
    missing
        .as_object_mut()
        .expect("wallet-spend object")
        .remove("request_id");
    let _ = json::from_value::<AgentWalletSpendPayload>(missing)
        .expect_err("wallet-spend payload must require request_id");
    let mut unknown = canonical;
    unknown
        .as_object_mut()
        .expect("wallet-spend object")
        .insert("sequence".to_owned(), norito::json!(7));
    let _ = json::from_value::<AgentWalletSpendPayload>(unknown)
        .expect_err("wallet-spend payload must reject inferred sequence");
}
#[test]
fn generated_hf_autonomy_run_command_is_not_published() {
    use clap::Parser as _;

    #[derive(clap::Parser, Debug)]
    struct AgentParser {
        #[command(subcommand)]
        command: AgentCommand,
    }

    let error = AgentParser::try_parse_from(["agent", "autonomy-run"])
        .expect_err("generated-HF autonomy-run ingress must not parse");
    assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
}
#[test]
fn wallet_approve_v1_rejects_noncanonical_request_ids_before_signing() {
    let key_pair = soracloud_fixture_key_pair(0x77);
    let authority = AccountId::new(key_pair.public_key().clone());
    for invalid in ["", " request-1", "request-1 ", "request\nid"] {
        let _ = signed_agent_wallet_approve_request("ops_agent", invalid, &authority, &key_pair)
            .expect_err("non-canonical wallet approval request id must fail");
    }
    let oversized = "x".repeat(129);
    let _ = signed_agent_wallet_approve_request("ops_agent", &oversized, &authority, &key_pair)
        .expect_err("oversized wallet approval request id must fail");
}
fn assert_signed_mutation_omits_inline_signing_material<T: JsonSerialize + ?Sized>(request: &T) {
    let value = json::to_value(request).expect("serialize signed Soracloud mutation request");
    let object = value
        .as_object()
        .expect("signed Soracloud mutation request must be a JSON object");
    assert!(
        !object.contains_key("authority"),
        "signed mutation request must not serialize inline authority"
    );
    assert!(
        !object.contains_key("private_key"),
        "signed mutation request must not serialize inline private key"
    );
}
#[test]
fn signed_soracloud_mutation_requests_omit_inline_signing_material() {
    let key_pair = soracloud_fixture_key_pair(0x12);
    let authority = AccountId::new(key_pair.public_key().clone());
    let config_set = signed_service_config_set_request(
        "web_portal",
        "feature_flags",
        norito::json!({ "enabled": true }),
        &authority,
        &key_pair,
    )
    .expect("signed service config set request");
    assert_signed_mutation_omits_inline_signing_material(&config_set);
    let config_delete =
        signed_service_config_delete_request("web_portal", "feature_flags", &authority, &key_pair)
            .expect("signed service config delete request");
    assert_signed_mutation_omits_inline_signing_material(&config_delete);
    let secret = SecretEnvelopeV1 {
        schema_version: SECRET_ENVELOPE_VERSION_V1,
        encryption: SecretEnvelopeEncryptionV1::ClientCiphertext,
        key_id: "test-kms-key".to_owned(),
        key_version: NonZeroU32::new(1).expect("non-zero key version"),
        nonce: vec![0x01; 12],
        ciphertext: vec![0x02; 32],
        commitment: Hash::new(b"test ciphertext"),
        aad_digest: None,
    };
    let secret_set =
        signed_service_secret_set_request("web_portal", "api_token", secret, &authority, &key_pair)
            .expect("signed service secret set request");
    assert_signed_mutation_omits_inline_signing_material(&secret_set);
    let secret_delete =
        signed_service_secret_delete_request("web_portal", "api_token", &authority, &key_pair)
            .expect("signed service secret delete request");
    assert_signed_mutation_omits_inline_signing_material(&secret_delete);
    let app_infra = signed_app_infra_request(
        MutationMode::Deploy,
        SoraAppInfraManifestV1 {
            schema_version: SORA_APP_INFRA_MANIFEST_VERSION_V1,
            app_name: "web_portal".parse().expect("valid app name"),
            app_version: "1.0.0".to_owned(),
            public_url: "https://web-portal.example".to_owned(),
            static_site: None,
            services: Vec::new(),
        },
        Vec::new(),
        SoraAppInfraMutationPreconditionV1::AppAbsent,
        &key_pair,
    )
    .expect("signed app infra request");
    assert_signed_mutation_omits_inline_signing_material(&app_infra);
}
#[test]
fn soracloud_fixture_key_pair_uses_checked_seed_derivation() {
    assert_eq!(
        soracloud_fixture_key_pair(0x11).algorithm(),
        Algorithm::Ed25519
    );
    assert!(
        KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
        "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
    );
}
fn hf_shared_lease_asset_definition() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        iroha_model_base::domain::DomainId::try_new("wonderland", "universal").expect("domain"),
        "lease".parse().expect("name"),
    )
}
fn sample_uploaded_model_bundle() -> SoraUploadedModelBundleV1 {
    SoraUploadedModelBundleV1 {
        schema_version: SORA_UPLOADED_MODEL_BUNDLE_VERSION_V1,
        service_name: "private_models".parse().expect("service name"),
        model_id: "upload-1".to_owned(),
        weight_version: "1.0.0".to_owned(),
        family: "hf-transformers".to_owned(),
        modalities: vec!["text".to_owned()],
        plaintext_root: Hash::new(b"plaintext-root"),
        package_format: SoraUploadedModelPackageFormatV1::NormalizedHuggingFaceSafetensorsV1,
        bundle_root: Hash::new(b"bundle-root"),
        sorafs_manifest_digest: iroha::data_model::sorafs::pin_registry::ManifestDigest::new(
            [0xA5; 32],
        ),
        chunk_count: 1,
        plaintext_bytes: 48,
        ciphertext_bytes: 64,
        chunk_manifest_root: Hash::new(b"sorafs-chunk-manifest"),
        pricing_policy: Default::default(),
    }
}
fn uploaded_model_status_fixture(
    service_name: &str,
    model_name: &str,
    weight_version: &str,
) -> UploadedModelStatusResponseV1 {
    let mut bundle = sample_uploaded_model_bundle();
    bundle.service_name = service_name.parse().expect("canonical service name");
    bundle.weight_version = weight_version.to_owned();
    let artifact = ModelArtifactStatusEntryV1 {
        service_name: bundle.service_name.clone(),
        model_name: model_name.parse().expect("canonical model name"),
        artifact_id: "upload-artifact-1".to_owned(),
        training_job_id: String::new(),
        weight_version: Some(weight_version.to_owned()),
        weight_artifact_hash: Hash::new(b"uploaded weights"),
        dataset_ref: "dataset:user-upload".to_owned(),
        training_config_hash: Hash::new(b"upload training config"),
        reproducibility_hash: Hash::new(b"upload reproducibility"),
        provenance_attestation_hash: Hash::new(b"upload provenance"),
        registered_sequence: 3,
        consumed_by_version: Some(weight_version.to_owned()),
        chunk_manifest_root: Some(bundle.chunk_manifest_root),
    };
    UploadedModelStatusResponseV1 {
        schema_version: SORACLOUD_STATUS_SCHEMA_VERSION_V1,
        bundle,
        artifact: Some(artifact),
    }
}
fn sample_uploaded_model_finalize_payload() -> UploadedModelFinalizePayload {
    let bundle = sample_uploaded_model_bundle();
    UploadedModelFinalizePayload {
        service_name: bundle.service_name.to_string(),
        model_name: "vision-model".to_owned(),
        model_id: bundle.model_id,
        artifact_id: "artifact-1".to_owned(),
        weight_version: bundle.weight_version,
        bundle_root: bundle.bundle_root,
        weight_artifact_hash: Hash::new(b"artifact-hash"),
        dataset_ref: "dataset://synthetic/v1".to_owned(),
        training_config_hash: Hash::new(b"train-config"),
        reproducibility_hash: Hash::new(b"repro"),
        provenance_attestation_hash: Hash::new(b"attestation"),
    }
}
fn uploaded_model_register_validation_error(
    bundle: SoraUploadedModelBundleV1,
    finalize: UploadedModelFinalizePayload,
) -> String {
    let key_pair = soracloud_fixture_key_pair(0x12);
    let authority = AccountId::new(key_pair.public_key().clone());
    signed_uploaded_model_register_request(bundle, finalize, &authority, &key_pair)
        .expect_err("uploaded-model register request must be rejected")
        .to_string()
}
#[test]
fn decode_soracloud_tx_instructions_accepts_framed_payloads() {
    use iroha::data_model::{
        domain::Domain,
        isi::{Register, framed_instruction_payload},
    };
    let instruction = InstructionBox::from(Register::domain(Domain::new(
        iroha_model_base::domain::DomainId::try_new("wonderland", "universal").expect("domain id"),
    )));
    let (wire_id, framed) =
        framed_instruction_payload(&instruction).expect("frame registered Soracloud instruction");
    let key_pair = soracloud_fixture_key_pair(0x31);
    let response = SoracloudMutationDraftResponse {
        ok: true,
        authority: AccountId::new(key_pair.public_key().clone()),
        signed_by: key_pair.public_key().clone(),
        tx_instructions: vec![SoracloudTxInstruction {
            wire_id: wire_id.to_owned(),
            payload_hex: hex::encode(framed),
        }],
    };
    let decoded = decode_soracloud_tx_instructions(&response).expect("decode framed instructions");
    let decoded_instruction = decoded.first().expect("single instruction");
    assert_eq!(decoded.len(), 1);
    let (decoded_wire_id, _) = framed_instruction_payload(decoded_instruction)
        .expect("decoded Soracloud instruction remains registered");
    assert_eq!(decoded_wire_id, wire_id);
    assert_eq!(
        norito::to_bytes(decoded_instruction).expect("encode decoded"),
        norito::to_bytes(&instruction).expect("encode expected"),
    );
}
#[test]
fn decode_soracloud_tx_instructions_rejects_raw_wire_payloads() {
    let wire_id = "soracloud::UpgradeSoracloudService";
    let framed = norito::core::frame_bare_with_header_flags::<
        iroha::data_model::isi::soracloud::UpgradeSoracloudService,
    >(&[1_u8, 2, 3], norito::core::default_encode_flags())
    .expect("frame opaque payload");
    let key_pair = soracloud_fixture_key_pair(0x32);
    let response = SoracloudMutationDraftResponse {
        ok: true,
        authority: AccountId::new(key_pair.public_key().clone()),
        signed_by: key_pair.public_key().clone(),
        tx_instructions: vec![SoracloudTxInstruction {
            wire_id: wire_id.to_owned(),
            payload_hex: hex::encode(&framed),
        }],
    };
    let error = decode_soracloud_tx_instructions(&response).expect_err("raw draft rejected");
    assert!(
        error
            .to_string()
            .contains("failed to decode Soracloud instruction skeleton")
    );
}
#[test]
fn decode_soracloud_tx_instructions_rejects_empty_draft() {
    let key_pair = soracloud_fixture_key_pair(0x33);
    let response = SoracloudMutationDraftResponse {
        ok: true,
        authority: AccountId::new(key_pair.public_key().clone()),
        signed_by: key_pair.public_key().clone(),
        tx_instructions: Vec::new(),
    };
    let error = decode_soracloud_tx_instructions(&response)
        .expect_err("empty mutation drafts must be rejected");
    assert!(error.to_string().contains("at least one"));
}
#[test]
fn publish_app_static_site_queues_finalized_registry_ingest_and_keeps_cid_gateway_url() {
    let dir = temp_dir("publish_static_site_already_stored");
    let dist_dir = dir.join("frontend/dist");
    fs::create_dir_all(&dist_dir).expect("create dist dir");
    fs::write(
        dist_dir.join("index.html"),
        "<!doctype html><title>Travel Ops</title>",
    )
    .expect("write index");
    let manifest = SoracloudAppManifestV1 {
        schema_version: SORACLOUD_APP_MANIFEST_VERSION_V1,
        app_name: "travel_ops".to_owned(),
        app_version: Some("1.0.0".to_owned()),
        public_url: "https://travel-ops.sora".to_owned(),
        static_site: Some(SoracloudAppStaticSiteV1 {
            dist_dir: "frontend/dist".to_owned(),
            mount_path: "/".to_owned(),
            publish_mode: APP_STATIC_SITE_PUBLISH_MODE_CID_ONLY.to_owned(),
            api_base_path: Some("/api".to_owned()),
            publish_label: None,
        }),
        services: Vec::new(),
    };
    let static_site = manifest
        .static_site
        .as_ref()
        .expect("static site should exist");
    let server = MockHttpServer::start(BTreeMap::from([(
        "/v1/sorafs/pin/register".to_owned(),
        MockHttpResponse::json(
            json::to_vec(&norito::json!({ "ok": true })).expect("encode pin register response"),
        ),
    )]));
    let key_pair = soracloud_fixture_key_pair(0x13);
    let authority = AccountId::new(key_pair.public_key().clone());
    install_mock_submission_config(&authority, &key_pair);
    let (publication, artifact) = prepare_app_static_site(
        &manifest,
        &dir,
        static_site,
        &key_pair,
        SorafsReleaseIdentityV1::new(test_sorafs_retention_epoch()),
    )
    .expect("prepare static site publication");
    register_prepared_sorafs_artifact(&artifact, &server.base_url, &authority, &key_pair, 5)
        .expect("publish should register finalized provider ingest");
    assert_eq!(publication.hostname, "travel-ops.sora");
    assert_eq!(publication.public_url, "https://travel-ops.sora");
    assert!(publication.content_cid.starts_with('b'));
    assert_eq!(
        publication.cid_gateway_url,
        format!(
            "https://travel-ops.sora/sorafs/cid/{}",
            publication.content_cid
        )
    );
    let register_request = server
        .requests()
        .into_iter()
        .find(|request| request.method == "POST" && request.path == "/v1/sorafs/pin/register")
        .expect("captured pin registration");
    let registration = mock_sorafs_pin_registration(&register_request)
        .expect("decode native pin registration transaction");
    let published_manifest =
        sorafs_manifest::decode_manifest_v1_canonical(&registration.manifest_payload)
            .expect("decode registered manifest");
    let descriptor = chunker_registry::default_descriptor();
    let (plan, payload) = CarBuildPlan::from_directory_with_profile(&dist_dir, descriptor.profile)
        .expect("rebuild published static-site plan");
    let mut car_bytes = Vec::new();
    let car_stats = CarWriter::new(&plan, &payload)
        .expect("prepare published static-site CAR")
        .write_to(&mut car_bytes)
        .expect("write published static-site CAR");
    let archive_digest = *blake3::hash(&car_bytes).as_bytes();
    assert_eq!(
        published_manifest.car_digest, archive_digest,
        "published manifest must bind every byte of the canonical CARv2 archive"
    );
    assert_eq!(
        published_manifest.car_digest,
        *car_stats.car_archive_digest.as_bytes()
    );
    assert_ne!(
        published_manifest.car_digest,
        *car_stats.car_payload_digest.as_bytes(),
        "CARv1 payload-section digest must not be published as ManifestV1.car_digest"
    );
}
#[test]
fn public_service_discovery_cross_binds_canonical_document_and_artifact_envelope() {
    let bundle = canonical_taira_inrou_bundle_fixture();
    let key_pair = soracloud_fixture_key_pair(0x14);
    let (discovery, publication, artifact) = prepare_public_service_discovery(
        &bundle,
        &key_pair,
        SorafsReleaseIdentityV1::new(test_sorafs_retention_epoch()),
    )
    .expect("prepare canonical public discovery document");

    let document = public_service_discovery_document_from_projection(&discovery);
    let document_bytes = json::to_vec(&document).expect("encode canonical discovery document");
    assert_eq!(discovery.document_hash, Hash::new(&document_bytes));
    assert_eq!(publication.document_hash, discovery.document_hash);
    let document_json = json::to_value(&document).expect("encode discovery document JSON");
    let document_object = document_json
        .as_object()
        .expect("discovery document JSON object");
    for detached_field in [
        "document_hash",
        "content_cid",
        "public_discovery_url",
        "public_discovery_cid_host_url",
        "manifest_digest_hex",
    ] {
        assert!(
            !document_object.contains_key(detached_field),
            "immutable index.json must omit publication-derived field `{detached_field}`"
        );
    }
    json::from_value::<SoracloudPublicServiceDiscoveryDocumentV1>(
        json::to_value(&discovery).expect("encode on-chain discovery projection"),
    )
    .expect_err("strict index document must reject the detached artifact envelope");

    let staged = taira_test_tempdir("public-discovery-binding-");
    fs::write(
        staged.path().join(PUBLIC_SERVICE_DISCOVERY_INDEX_DOCUMENT),
        &document_bytes,
    )
    .expect("stage reconstructed canonical discovery document");
    let descriptor = chunker_registry::default_descriptor();
    let (plan, payload) =
        CarBuildPlan::from_directory_with_profile(staged.path(), descriptor.profile)
            .expect("plan reconstructed discovery artifact");
    let mut car_sink = io::sink();
    let car_stats = CarWriter::new(&plan, &payload)
        .expect("prepare reconstructed discovery CAR")
        .write_to(&mut car_sink)
        .expect("write reconstructed discovery CAR");
    assert_eq!(car_stats.root_cids.len(), 1);

    assert_eq!(artifact.payload, payload);
    assert_eq!(artifact.plan, plan);
    let published_manifest = &artifact.built.manifest;
    assert_eq!(published_manifest.root_cid, car_stats.root_cids[0]);
    assert_eq!(
        discovery.content_cid,
        encode_content_cid(&car_stats.root_cids[0])
    );
    assert_eq!(publication.content_cid, discovery.content_cid);
    assert_eq!(
        discovery.manifest_digest_hex,
        hex::encode(
            artifact
                .built
                .manifest
                .digest()
                .expect("digest prepared discovery manifest")
                .as_bytes()
        )
    );
    assert_eq!(
        discovery.public_discovery_url,
        format!(
            "https://taira.sora.org/sorafs/cid/{}/index.json",
            discovery.content_cid
        )
    );
    assert_eq!(
        discovery.public_discovery_cid_host_url,
        format!(
            "https://{}.sorafs.taira.sora.org/index.json",
            discovery.content_cid
        )
    );
}
#[test]
fn inrou_preseed_target_parsers_require_exact_canonical_identities() {
    let validator_key = soracloud_fixture_key_pair(0x5A);
    let peer_key = soracloud_fixture_key_pair(0x5B);
    let validator_account_id = AccountId::new(validator_key.public_key().clone());
    let peer_id = PeerId::from(peer_key.public_key().clone()).to_string();
    let identity = format!("{validator_account_id},{peer_id}");
    assert_eq!(
        parse_inrou_placement_target_identity(&identity)
            .expect("independently canonical validator and peer identities"),
        SoraInrouPlacementTargetV1 {
            validator_account_id: validator_account_id.clone(),
            peer_id: peer_id.clone(),
        }
    );
    let target = format!("{identity},/tmp/inrou-preseed-target");
    let parsed = target
        .parse::<InrouOperatorPreseedTargetArg>()
        .expect("canonical identity-bound preseed target");
    assert_eq!(
        parsed.validator_account_id,
        validator_account_id.to_string()
    );
    assert_eq!(parsed.peer_id, peer_id);
    assert_eq!(
        parsed
            .canonical_placement()
            .expect("parse the retained account under the active chain guard")
            .validator_account_id,
        validator_account_id
    );

    let taira_literal = {
        let _guard = iroha::data_model::account::address::ChainDiscriminantGuard::enter(369);
        validator_account_id.to_string()
    };
    let deferred = format!(
        "{taira_literal},{},/tmp/taira-inrou-preseed",
        parsed.peer_id
    )
    .parse::<InrouOperatorPreseedTargetArg>()
    .expect("Clap retains a Taira account literal before config admission");
    {
        let _wrong_guard = iroha::data_model::account::address::ChainDiscriminantGuard::enter(753);
        deferred
            .canonical_placement()
            .expect_err("a foreign active chain must reject the retained Taira literal");
    }
    {
        let _taira_guard = iroha::data_model::account::address::ChainDiscriminantGuard::enter(369);
        deferred
            .canonical_placement()
            .expect("the configured Taira guard admits the exact retained literal");
    }

    assert!(
        parse_inrou_placement_target_identity(&format!(" {identity}"))
            .expect_err("account whitespace aliases must fail")
            .contains("surrounding whitespace")
    );
    assert!(
        parse_inrou_placement_target_identity(&format!("{identity},extra"))
            .expect_err("extra identity fields must fail")
            .contains("expected exactly")
    );
}
#[test]
fn inrou_preseed_requires_capacity_and_sufficient_explicit_targets() {
    let root = temp_dir("inrou_preseed_required_targets");
    let capacity = test_inrou_preseed_capacity();
    let missing_targets = validate_inrou_operator_preseed(Some(3), &[], capacity, None, None)
        .err()
        .expect("missing preseed targets must fail");
    assert!(missing_targets.to_string().contains("at least 3"));

    let targets = test_inrou_preseed_targets(&root);
    let missing_capacity = validate_inrou_operator_preseed(Some(3), &targets, None, None, None)
        .err()
        .expect("missing exact preseed capacity must fail");
    assert!(
        missing_capacity
            .to_string()
            .contains("--inrou-preseed-max-capacity-bytes")
    );

    let insufficient =
        validate_inrou_operator_preseed(Some(3), &targets[..2], capacity, None, None)
            .err()
            .expect("insufficient preseed targets must fail");
    assert!(insufficient.to_string().contains("at least 3"));

    let mut excessive = targets.clone();
    for index in 0..2 {
        let extra = root.join(format!("extra-inrou-preseed-{index}"));
        fs::create_dir(&extra).expect("create excessive preseed target");
        let mut target = targets[0].clone();
        let key_pair = soracloud_fixture_key_pair(0x79 + index);
        target.validator_account_id = AccountId::new(key_pair.public_key().clone()).to_string();
        target.peer_id = PeerId::from(key_pair.public_key().clone()).to_string();
        target.data_dir = fs::canonicalize(extra).expect("canonical excessive target");
        excessive.push(target);
    }
    let excessive = validate_inrou_operator_preseed(Some(3), &excessive, capacity, None, None)
        .err()
        .expect("excessive preseed targets must fail");
    assert!(excessive.to_string().contains("at most 4"));
}
#[test]
fn inrou_preseed_rejects_duplicate_and_overlapping_storage_roots() {
    let root = temp_dir("inrou_preseed_distinct_roots");
    let targets = test_inrou_preseed_targets(&root);
    let mut duplicate_root = targets[2].clone();
    duplicate_root.data_dir = targets[0].data_dir.clone();
    let duplicate = vec![targets[0].clone(), targets[1].clone(), duplicate_root];
    let error = validate_inrou_operator_preseed(
        Some(3),
        &duplicate,
        test_inrou_preseed_capacity(),
        None,
        None,
    )
    .err()
    .expect("duplicate preseed roots must fail");
    assert!(error.to_string().contains("distinct storage roots"));

    let duplicate_identity = vec![
        targets[0].clone(),
        InrouOperatorPreseedTargetArg {
            validator_account_id: targets[0].validator_account_id.clone(),
            peer_id: targets[0].peer_id.clone(),
            data_dir: targets[1].data_dir.clone(),
        },
        targets[2].clone(),
    ];
    let error = validate_inrou_operator_preseed(
        Some(3),
        &duplicate_identity,
        test_inrou_preseed_capacity(),
        None,
        None,
    )
    .err()
    .expect("duplicate placement identity must fail");
    assert!(
        error
            .to_string()
            .contains("identities must each be distinct")
    );

    let nested = targets[0].data_dir.join("nested");
    fs::create_dir_all(&nested).expect("create nested preseed root");
    let mut nested_target = targets[2].clone();
    nested_target.data_dir = nested;
    let overlapping = vec![targets[0].clone(), nested_target, targets[1].clone()];
    let error = validate_inrou_operator_preseed(
        Some(3),
        &overlapping,
        test_inrou_preseed_capacity(),
        None,
        None,
    )
    .err()
    .expect("overlapping preseed roots must fail");
    assert!(error.to_string().contains("must not overlap"));
}
#[test]
fn inrou_preseed_never_reinterprets_populated_source_placement_targets() {
    let exact_targets = test_inrou_placement_targets(3);
    let mut empty = fixture_service();
    empty.placement_targets.clear();
    bind_exact_inrou_placement_targets(&mut empty, &exact_targets)
        .expect("empty source placement targets may be bound once");
    assert_eq!(empty.placement_targets, exact_targets);

    bind_exact_inrou_placement_targets(&mut empty, &exact_targets)
        .expect("an exact populated source placement set remains valid");
    let original = empty.placement_targets.clone();
    let mismatch = test_inrou_placement_targets(4);
    let error = bind_exact_inrou_placement_targets(&mut empty, &mismatch)
        .expect_err("a populated signed source placement set must never be overwritten");
    assert!(
        error
            .to_string()
            .contains("placement_targets differ from the exact durable Inrou qualification")
    );
    assert_eq!(empty.placement_targets, original);
}
#[test]
fn inrou_preseed_requires_exact_active_validator_peer_bindings() {
    let root = temp_dir("inrou_preseed_active_host_bindings");
    let (helper, helper_digest) = test_inrou_preseed_helper(&root);
    let config = test_inrou_preseed_config(
        &root,
        helper.as_deref().expect("test preseed helper"),
        helper_digest
            .as_deref()
            .expect("test preseed helper digest"),
    );
    let artifact = test_inrou_preseed_artifact(&root, "active-host-bindings");
    let receipt = expected_inrou_preseed_receipt(&config, &[&artifact])
        .expect("canonical test qualification");
    let qualification = LoadedInrouPreseedQualification {
        path: root.join("unused-qualification.json"),
        receipt,
        bytes: Vec::new(),
        targets: config.targets.clone(),
        max_capacity_bytes: config.max_capacity_bytes,
    };

    let active_hosts = mock_active_inrou_hosts();
    require_active_inrou_qualification_targets(&qualification, &active_hosts)
        .expect("every exact qualified validator/peer binding is active");

    let mut missing = active_hosts.clone();
    missing.pop();
    let error = require_active_inrou_qualification_targets(&qualification, &missing)
        .expect_err("a missing qualified validator must fail closed");
    assert!(
        error
            .to_string()
            .contains("is not an active advertised validator host")
    );

    let mut wrong_peer = active_hosts.clone();
    wrong_peer[0].peer_id = wrong_peer[1].peer_id.clone();
    let error = require_active_inrou_qualification_targets(&qualification, &wrong_peer)
        .expect_err("an active validator bound to another peer must fail closed");
    assert!(
        error
            .to_string()
            .contains("but the active capability binds")
    );

    let mut reordered = active_hosts;
    reordered.reverse();
    let error = require_active_inrou_qualification_targets(&qualification, &reordered)
        .expect_err("noncanonical active capability order must fail closed");
    assert!(
        error
            .to_string()
            .contains("must be strictly ordered by validator account")
    );
}
#[test]
fn inrou_preseed_rejects_a_changed_or_unbound_helper() {
    let root = temp_dir("inrou_preseed_helper_binding");
    let targets = test_inrou_preseed_targets(&root);
    let (helper, helper_digest) = test_inrou_preseed_helper(&root);
    fs::write(helper.as_ref().expect("test helper"), "#!/bin/sh\nexit 1\n")
        .expect("change test helper after hashing");
    let error = validate_inrou_operator_preseed(
        Some(3),
        &targets,
        test_inrou_preseed_capacity(),
        helper.as_deref(),
        helper_digest.as_deref(),
    )
    .err()
    .expect("changed preseed helper must fail");
    assert!(
        format!("{error:#}").contains("SHA-256 mismatch"),
        "{error:#}"
    );
}
#[test]
fn inrou_preseed_cli_rejects_zero_timeout() {
    use clap::Parser as _;

    #[derive(clap::Parser)]
    struct ServiceParser {
        #[command(subcommand)]
        command: ServiceCommand,
    }
    #[derive(clap::Parser)]
    struct AppParser {
        #[command(subcommand)]
        command: AppCommand,
    }

    assert!(
        ServiceParser::try_parse_from([
            "service",
            "deploy",
            "--bundle-file",
            "bundle.tgz",
            "--sorafs-retention-epoch",
            "1",
            "--timeout-secs",
            "0",
        ])
        .is_err(),
        "service deploy must reject a zero helper/request timeout"
    );
    assert!(
        ServiceParser::try_parse_from([
            "service",
            "upgrade",
            "--bundle-file",
            "bundle.tgz",
            "--sorafs-retention-epoch",
            "1",
            "--timeout-secs",
            "0",
        ])
        .is_err(),
        "service upgrade must reject a zero helper/request timeout"
    );
    assert!(
        AppParser::try_parse_from([
            "app",
            "release",
            "--sorafs-retention-epoch",
            "1",
            "--timeout-secs",
            "0",
        ])
        .is_err(),
        "app release must reject a zero helper/request timeout"
    );
    let error = start_inrou_operator_preseed_session(None, &[], 0)
        .err()
        .expect("operator-preseed startup must reject zero directly");
    assert!(format!("{error:#}").contains("timeout must be positive"));
}
#[test]
fn online_inrou_publication_rejects_retired_one_shot_preseed_flags() {
    use clap::Parser as _;

    #[derive(clap::Parser)]
    struct ServiceParser {
        #[command(subcommand)]
        command: ServiceCommand,
    }
    #[derive(clap::Parser)]
    struct AppParser {
        #[command(subcommand)]
        command: AppCommand,
    }

    assert!(
        ServiceParser::try_parse_from([
            "service",
            "deploy",
            "--bundle-file",
            "bundle.tgz",
            "--sorafs-retention-epoch",
            "1",
            "--inrou-preseed-target",
            "validator,peer,/tmp/store",
        ])
        .is_err(),
        "online service publication must not accept the retired one-shot target flag"
    );
    assert!(
        AppParser::try_parse_from([
            "app",
            "release",
            "--sorafs-retention-epoch",
            "1",
            "--inrou-preseed-helper",
            "/tmp/sorafs-node",
        ])
        .is_err(),
        "online app publication must not accept the retired one-shot helper flag"
    );
}
#[cfg(unix)]
#[test]
fn inrou_preseed_executes_an_owner_private_verified_helper_copy() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let root = temp_dir("inrou_preseed_private_helper_copy");
    let targets = test_inrou_preseed_targets(&root);
    let (helper, helper_digest) = test_inrou_preseed_helper(&root);
    let helper = helper.expect("test helper");
    let config = validate_inrou_operator_preseed(
        Some(3),
        &targets,
        test_inrou_preseed_capacity(),
        Some(&helper),
        helper_digest.as_deref(),
    )
    .expect("validate exact helper")
    .expect("Inrou preseed config");
    let stage = SoracloudTempDir::new("inrou-preseed-helper-copy-test")
        .expect("create owner-private stage");
    let staged = stage_verified_inrou_preseed_helper(&config, stage.path())
        .expect("stage exact helper copy");
    fs::write(&helper, "#!/bin/sh\nexit 1\n").expect("replace external helper after staging");

    assert_eq!(
        sha256_file(
            &staged,
            "staged test helper",
            INROU_PRESEED_HELPER_MAX_BYTES
        )
        .expect("hash staged helper"),
        config.helper_sha256
    );
    let staged_metadata = fs::symlink_metadata(&staged).expect("staged helper metadata");
    let source_metadata = fs::symlink_metadata(&helper).expect("source helper metadata");
    assert_eq!(staged_metadata.permissions().mode() & 0o777, 0o500);
    assert_eq!(
        fs::symlink_metadata(stage.path())
            .expect("stage metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_ne!(staged_metadata.ino(), source_metadata.ino());
}
#[cfg(unix)]
#[test]
fn inrou_preseed_noisy_stderr_is_bounded_and_cleaned_up() {
    let _taira_chain = iroha::data_model::account::address::ChainDiscriminantGuard::enter(369);
    let root = temp_dir("inrou_preseed_noisy_stderr");
    let (helper, helper_digest) = write_test_inrou_preseed_helper(
        &root,
        "noisy-stderr-preseed-helper.sh",
        concat!(
            "#!/bin/sh\n",
            "/bin/dd if=/dev/zero bs=1048576 count=2 1>&2 2>/dev/null\n",
            "printf '%s\\n' \"$IROHA_TEST_INROU_PRESEED_RECEIPT\"\n",
            "while IFS= read -r _line; do :; done\n",
        ),
    );
    let config = test_inrou_preseed_config(&root, &helper, &helper_digest);
    let artifact = test_inrou_preseed_artifact(&root, "noisy-stderr");

    let started = Instant::now();
    let error = start_inrou_operator_preseed_session(Some(&config), &[&artifact], 1)
        .err()
        .expect("noisy preseed stderr must be rejected");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "noisy preseed stderr exceeded its bounded cleanup window"
    );
    assert!(
        format!("{error:#}").contains("stderr exceeded its V1 byte limit"),
        "unexpected noisy-stderr error: {error:#}"
    );
}
#[cfg(unix)]
#[test]
fn inrou_preseed_stalled_readiness_is_bounded_and_cleaned_up() {
    let _taira_chain = iroha::data_model::account::address::ChainDiscriminantGuard::enter(369);
    let root = temp_dir("inrou_preseed_stalled_readiness");
    let (helper, helper_digest) = write_test_inrou_preseed_helper(
        &root,
        "stalled-readiness-preseed-helper.sh",
        "#!/bin/sh\n/bin/sleep 60\n",
    );
    let config = test_inrou_preseed_config(&root, &helper, &helper_digest);
    let artifact = test_inrou_preseed_artifact(&root, "stalled-readiness");

    let started = Instant::now();
    let error = start_inrou_operator_preseed_session(Some(&config), &[&artifact], 1)
        .err()
        .expect("stalled preseed readiness must time out");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "stalled preseed readiness exceeded its bounded cleanup window"
    );
    assert!(
        format!("{error:#}").contains("deadline before the ready receipt"),
        "unexpected stalled-readiness error: {error:#}"
    );
}
#[cfg(unix)]
#[test]
fn inrou_preseed_stalled_release_is_bounded_and_cleaned_up() {
    let _taira_chain = iroha::data_model::account::address::ChainDiscriminantGuard::enter(369);
    let root = temp_dir("inrou_preseed_stalled_release");
    let (helper, helper_digest) = write_test_inrou_preseed_helper(
        &root,
        "stalled-release-preseed-helper.sh",
        concat!(
            "#!/bin/sh\n",
            "printf '%s\\n' \"$IROHA_TEST_INROU_PRESEED_RECEIPT\"\n",
            "exec 1>&-\n",
            "while IFS= read -r _line; do :; done\n",
            "/bin/sleep 60\n",
        ),
    );
    let config = test_inrou_preseed_config(&root, &helper, &helper_digest);
    let artifact = test_inrou_preseed_artifact(&root, "stalled-release");
    let session = start_inrou_operator_preseed_session(Some(&config), &[&artifact], 1)
        .expect("start stalled-release helper")
        .expect("live stalled-release preseed session");

    let started = Instant::now();
    let error = session
        .finish()
        .expect_err("stalled preseed release must time out");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "stalled preseed release exceeded its bounded cleanup window"
    );
    assert!(
        format!("{error:#}").contains("exceeded its release deadline"),
        "unexpected stalled-release error: {error:#}"
    );
}
#[cfg(unix)]
#[test]
fn inrou_preseed_release_requires_exact_eof_acknowledgment() {
    let _taira_chain = iroha::data_model::account::address::ChainDiscriminantGuard::enter(369);
    let root = temp_dir("inrou_preseed_missing_release_ack");
    let (helper, helper_digest) = write_test_inrou_preseed_helper(
        &root,
        "missing-release-ack-preseed-helper.sh",
        concat!(
            "#!/bin/sh\n",
            "printf '%s\\n' \"$IROHA_TEST_INROU_PRESEED_RECEIPT\"\n",
            "while IFS= read -r _line; do :; done\n",
        ),
    );
    let config = test_inrou_preseed_config(&root, &helper, &helper_digest);
    let artifact = test_inrou_preseed_artifact(&root, "missing-release-ack");
    let session = start_inrou_operator_preseed_session(Some(&config), &[&artifact], 1)
        .expect("start missing-release-ack helper")
        .expect("live missing-release-ack preseed session");

    let error = session
        .finish()
        .expect_err("release without the exact acknowledgment must fail");
    assert!(
        format!("{error:#}").contains("exact EOF release acknowledgment"),
        "unexpected missing-release-ack error: {error:#}"
    );
}
#[cfg(unix)]
#[test]
fn inrou_preseed_drop_cleanup_is_bounded() {
    let _taira_chain = iroha::data_model::account::address::ChainDiscriminantGuard::enter(369);
    let root = temp_dir("inrou_preseed_bounded_drop");
    let survivor_marker = root.join("stalled-drop-descendant-survived");
    let survivor_marker = survivor_marker
        .to_str()
        .expect("test survivor marker must be UTF-8");
    assert!(!survivor_marker.contains('\''));
    let script = format!(
        concat!(
            "#!/bin/sh\n",
            "printf '%s\\n' \"$IROHA_TEST_INROU_PRESEED_RECEIPT\"\n",
            "exec 1>&-\n",
            "(exec 0<&- 1>&- 2>&-; /bin/sleep 1; /usr/bin/touch '{survivor_marker}') &\n",
            "/bin/sleep 60\n",
        ),
        survivor_marker = survivor_marker,
    );
    let (helper, helper_digest) =
        write_test_inrou_preseed_helper(&root, "stalled-drop-preseed-helper.sh", &script);
    let config = test_inrou_preseed_config(&root, &helper, &helper_digest);
    let artifact = test_inrou_preseed_artifact(&root, "stalled-drop");
    let mut session = start_inrou_operator_preseed_session(Some(&config), &[&artifact], 5)
        .expect("start stalled-drop helper")
        .expect("live stalled-drop preseed session");
    session
        .ensure_alive()
        .expect("stalled-drop helper must be live before cleanup");

    let started = Instant::now();
    drop(session);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "stalled preseed drop exceeded its bounded cleanup window"
    );
    thread::sleep(Duration::from_millis(1_500));
    assert!(
        !Path::new(survivor_marker).exists(),
        "drop cleanup left an owned preseed descendant alive"
    );
}
#[cfg(unix)]
#[test]
fn inrou_preseed_cleanup_kills_descendant_after_group_leader_exit() {
    let _taira_chain = iroha::data_model::account::address::ChainDiscriminantGuard::enter(369);
    let root = temp_dir("inrou_preseed_exited_leader_cleanup");
    let survivor_marker = root.join("exited-leader-descendant-survived");
    let survivor_marker = survivor_marker
        .to_str()
        .expect("test survivor marker must be UTF-8");
    assert!(!survivor_marker.contains('\''));
    let script = format!(
        concat!(
            "#!/bin/sh\n",
            "(exec 0<&- 1>&- 2>&-; /bin/sleep 1; /usr/bin/touch '{survivor_marker}') &\n",
            "exit 0\n",
        ),
        survivor_marker = survivor_marker,
    );
    let (helper, helper_digest) =
        write_test_inrou_preseed_helper(&root, "exited-leader-preseed-helper.sh", &script);
    let config = test_inrou_preseed_config(&root, &helper, &helper_digest);
    let artifact = test_inrou_preseed_artifact(&root, "exited-leader-cleanup");

    let _ = start_inrou_operator_preseed_session(Some(&config), &[&artifact], 1)
        .err()
        .expect("exited preseed leader must fail readiness");
    thread::sleep(Duration::from_millis(1_500));
    assert!(
        !Path::new(survivor_marker).exists(),
        "cleanup skipped the owned process group after reaping its leader"
    );
}
#[cfg(unix)]
#[test]
#[ignore = "requires a separately built, exact sorafs-node binary"]
fn inrou_preseed_cli_client_interoperates_with_real_sorafs_node() {
    let _taira_chain = iroha::data_model::account::address::ChainDiscriminantGuard::enter(369);
    let helper = std::env::var_os("IROHA_TEST_REAL_SORAFS_NODE")
        .map(PathBuf::from)
        .expect("set IROHA_TEST_REAL_SORAFS_NODE to the exact built sorafs-node binary");
    let helper = fs::canonicalize(&helper).expect("canonical real sorafs-node path");
    let helper_sha256 = sha256_file(
        &helper,
        "real sorafs-node interoperability helper",
        INROU_PRESEED_HELPER_MAX_BYTES,
    )
    .expect("hash real sorafs-node interoperability helper");
    let root = temp_dir("inrou_preseed_real_node_interoperability");
    let targets = test_inrou_preseed_targets(&root);
    let config = validate_inrou_operator_preseed(
        Some(SORACLOUD_ARTIFACT_MIN_REPLICAS_V1),
        &targets,
        test_inrou_preseed_capacity(),
        Some(&helper),
        Some(&helper_sha256),
    )
    .expect("validate real identity-bound preseed helper")
    .expect("real preseed configuration");
    let input = root.join("exact-inrou-artifact.bin");
    fs::write(&input, b"exact CLI to sorafs-node Inrou artifact bytes")
        .expect("write exact interoperability artifact");
    let key_pair = soracloud_fixture_key_pair(0x5C);
    let (artifact, _) = prepare_sorafs_file_artifact(
        &input,
        "real CLI/node interoperability artifact",
        &key_pair,
        SorafsReleaseIdentityV1::new(test_sorafs_retention_epoch()),
    )
    .expect("prepare exact interoperability artifact");
    let expected_receipt =
        expected_inrou_preseed_receipt(&config, &[&artifact]).expect("expected ready receipt");

    let mut session = start_inrou_operator_preseed_session(Some(&config), &[&artifact], 30)
        .expect("start real sorafs-node preseed session")
        .expect("live real sorafs-node preseed session");
    session
        .ensure_alive()
        .expect("real sorafs-node must retain every lock after readiness");
    assert_eq!(
        fs::read(session._stage.path().join("artifact-0.manifest.norito"))
            .expect("read staged exact manifest"),
        artifact.built.bytes,
    );
    assert_eq!(
        fs::read(session._stage.path().join("artifact-0.payload"))
            .expect("read staged exact payload"),
        artifact.payload,
    );

    let expected_manifest = root.join("expected.manifest.norito");
    fs::write(&expected_manifest, &artifact.built.bytes)
        .expect("write independent expected manifest");
    let mut contending = Command::new(&helper);
    contending.arg("preseed-session").arg(format!(
        "--max-capacity-bytes={}",
        config.max_capacity_bytes
    ));
    for target in &config.targets {
        contending.arg(format!(
            "--target={},{},{}",
            target.placement.validator_account_id,
            target.placement.peer_id,
            target.store_root.display()
        ));
    }
    let contention = contending
        .arg(format!("--manifest={}", expected_manifest.display()))
        .arg(format!("--payload={}", input.display()))
        .stdin(Stdio::null())
        .output()
        .expect("run a contending real sorafs-node session");
    assert!(!contention.status.success());
    assert!(
        String::from_utf8_lossy(&contention.stderr).contains("already in use"),
        "unexpected contention error: {}",
        String::from_utf8_lossy(&contention.stderr)
    );

    let durable_receipt = session
        .finish()
        .expect("persist the qualification and release every store lock");
    assert_eq!(durable_receipt, expected_receipt);

    fs::write(root.join("simulated-control-plane-mutation"), b"committed")
        .expect("record an online mutation only after all store locks are released");

    let mut verify = Command::new(&helper);
    verify
        .arg("preseed-session")
        .arg(format!(
            "--max-capacity-bytes={}",
            config.max_capacity_bytes
        ))
        .arg("--verify-only");
    for target in &config.targets {
        verify.arg(format!(
            "--target={},{},{}",
            target.placement.validator_account_id,
            target.placement.peer_id,
            target.store_root.display()
        ));
    }
    let verified = verify
        .arg(format!("--manifest={}", expected_manifest.display()))
        .arg(format!("--payload={}", input.display()))
        .stdin(Stdio::null())
        .output()
        .expect("run real sorafs-node exact verification replay");
    assert!(
        verified.status.success(),
        "verification replay failed: {}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let ready_end = verified
        .stdout
        .iter()
        .position(|byte| *byte == b'\n')
        .expect("real verify receipt ends in one newline");
    let (receipt_line, release) = verified.stdout.split_at(ready_end + 1);
    assert_eq!(release, OPERATOR_PRESEED_SESSION_RELEASE_ACK_V1);
    let receipt_bytes = receipt_line
        .strip_suffix(b"\n")
        .expect("real verify receipt newline");
    assert!(!receipt_bytes.is_empty());
    assert!(!receipt_bytes.contains(&b'\n'));
    assert!(!receipt_bytes.contains(&b'\r'));
    let verified_receipt: OperatorPreseedSessionReceiptV1 =
        json::from_slice(receipt_bytes).expect("decode real verification receipt");
    let mut expected_verified_receipt = durable_receipt;
    expected_verified_receipt.mode = "verify_only".to_owned();
    assert_eq!(verified_receipt, expected_verified_receipt);
}
fn write_test_inrou_guest_images(inrou_dir: &Path, label: &str) {
    for isa in ["x86_64", "aarch64"] {
        let isa_dir = inrou_dir.join(isa);
        fs::create_dir_all(&isa_dir).expect("create test inrou isa dir");
        fs::write(
            isa_dir.join("vmlinux"),
            format!("{label}-{isa}-kernel").as_bytes(),
        )
        .expect("write test inrou kernel");
        fs::write(
            isa_dir.join("rootfs.ext4"),
            format!("{label}-{isa}-rootfs").as_bytes(),
        )
        .expect("write test inrou rootfs");
    }
}
fn prepare_http_service_bundle(dir: &Path, label: &str) -> PathBuf {
    write_test_inrou_guest_images(&dir.join("http-service/inrou"), label);
    let bundle_file = dir.join("http-service/build/http-service.tgz");
    BundlePackArgs {
        source: dir.join("http-service/app/server.mjs"),
        archive_path: "app/server.mjs".to_owned(),
        output: bundle_file.clone(),
        executable: true,
    }
    .run()
    .expect("pack direct HTTP service bundle");
    SyncManifestsArgs {
        app_manifest: None,
        container: dir.join("container_manifest.json"),
        service: dir.join("service_manifest.json"),
        bundle_file: Some(bundle_file.clone()),
    }
    .run()
    .expect("sync direct HTTP service manifests");
    bundle_file
}
#[derive(Clone)]
struct MockHttpResponse {
    status: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
}
impl MockHttpResponse {
    fn json(body: Vec<u8>) -> Self {
        Self {
            status: "200 OK",
            content_type: "application/json",
            body,
        }
    }
}
#[derive(Clone, Debug)]
struct CapturedHttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}
#[derive(Clone, Debug)]
struct MockSorafsPinRegistration {
    manifest_payload: Vec<u8>,
    manifest_digest_hex: String,
    tx_hash_hex: String,
}
struct MockHttpServer {
    base_url: String,
    address: String,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<CapturedHttpRequest>>>,
    handle: Option<thread::JoinHandle<()>>,
}
impl MockHttpServer {
    fn start(routes: BTreeMap<String, MockHttpResponse>) -> Self {
        Self::start_with_mutation_transition(routes, BTreeMap::new(), None)
    }

    fn start_with_mutation_transition(
        routes: BTreeMap<String, MockHttpResponse>,
        initial_routes: BTreeMap<String, MockHttpResponse>,
        mutation_route: Option<String>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock HTTP server");
        listener
            .set_nonblocking(true)
            .expect("set mock listener nonblocking");
        let address = listener
            .local_addr()
            .expect("mock listener address")
            .to_string();
        let base_url = format!("http://{address}");
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop_flag = Arc::clone(&stop);
        let captured_requests = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            let mut registered_pin_manifests = BTreeMap::<String, Vec<u8>>::new();
            let mut mutation_requested = false;
            while !stop_flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let request = read_mock_http_request(&mut stream);
                        if request.path.is_empty() {
                            continue;
                        }
                        let path = request.path.clone();
                        mutation_requested |= request.method == "POST"
                            && mutation_route.as_deref() == Some(path.as_str());
                        let fee_quote_response = mock_fee_quote_response(&request);
                        let pin_registration = mock_sorafs_pin_registration(&request);
                        let is_pin_registration =
                            request.method == "POST" && request.path == "/v1/sorafs/pin/register";
                        captured_requests
                            .lock()
                            .expect("lock captured requests")
                            .push(request);
                        let configured_response = if mutation_requested {
                            routes.get(&path)
                        } else {
                            initial_routes.get(&path).or_else(|| routes.get(&path))
                        }
                        .cloned();
                        let pin_registration_response = configured_response
                            .as_ref()
                            .filter(|_| is_pin_registration)
                            .and_then(|_| pin_registration.as_ref())
                            .map(mock_sorafs_pin_registration_response);
                        let pin_registry_response = if configured_response.is_none()
                            && fee_quote_response.is_none()
                            && pin_registration_response.is_none()
                        {
                            mock_sorafs_pin_registry_response(&path, &registered_pin_manifests)
                        } else {
                            None
                        };
                        let (response, status) = if let Some(response) = pin_registration_response {
                            (response, "202 Accepted")
                        } else if configured_response.is_some()
                            && is_pin_registration
                            && pin_registration.is_none()
                        {
                            (
                                MockHttpResponse {
                                    status: "200 OK",
                                    content_type: "text/plain",
                                    body: b"invalid pin registration transaction".to_vec(),
                                },
                                "400 Bad Request",
                            )
                        } else if let Some(response) = configured_response {
                            let status = response.status;
                            (response, status)
                        } else if let Some(response) = fee_quote_response {
                            (response, "200 OK")
                        } else if let Some(response) = pin_registry_response {
                            (response, "200 OK")
                        } else {
                            (
                                MockHttpResponse {
                                    status: "200 OK",
                                    content_type: "text/plain",
                                    body: b"not found".to_vec(),
                                },
                                "404 Not Found",
                            )
                        };
                        if status == "202 Accepted" {
                            let registration =
                                pin_registration.expect("accepted pin registration was decoded");
                            registered_pin_manifests.insert(
                                registration.manifest_digest_hex,
                                registration.manifest_payload,
                            );
                        }
                        if let Err(error) = write!(
                            stream,
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n",
                            response.body.len(),
                            response.content_type
                        ) {
                            if mock_http_connection_closed(&error) {
                                continue;
                            }
                            panic!("write mock HTTP headers failed: {error}");
                        }
                        if let Err(error) = stream.write_all(&response.body) {
                            if mock_http_connection_closed(&error) {
                                continue;
                            }
                            panic!("write mock HTTP body failed: {error}");
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("mock HTTP server accept failed: {error}"),
                }
            }
        });
        Self {
            base_url,
            address,
            stop,
            requests,
            handle: Some(handle),
        }
    }
    fn requests(&self) -> Vec<CapturedHttpRequest> {
        self.requests
            .lock()
            .expect("lock captured requests")
            .clone()
    }
}
fn mock_fee_quote_response(request: &CapturedHttpRequest) -> Option<MockHttpResponse> {
    if request.method != "POST"
        || request.path != iroha_torii_shared::route_catalog::fees::QUOTE_PATH
    {
        return None;
    }
    let request: FeeQuoteWireRequest = json::from_slice(&request.body).ok()?;
    let (debit_source, program_revision) = match request.payload.fee_payment.sponsor_program() {
        Some((program_id, revision)) => (
            FeeDebitSource::SponsorProgram(program_id.clone()),
            Some(revision),
        ),
        None => (
            FeeDebitSource::Account(request.payload.authority.clone()),
            None,
        ),
    };
    let response = FeeQuoteResponse {
        intent: request.payload.fee_payment.clone(),
        observation: FeeQuoteObservation {
            ledger_time_ms: 1,
            next_block_height: 1,
            route_dataspace_id: DataSpaceId::UNIVERSAL,
        },
        components: Vec::new(),
        capacities: Vec::new(),
        decision: FeeQuoteDecision::Accepted {
            debit_source,
            program_revision,
        },
    };
    Some(MockHttpResponse {
        status: "200 OK",
        content_type: "application/json",
        body: json::to_vec(&response).ok()?,
    })
}
fn mock_sorafs_pin_registration(
    request: &CapturedHttpRequest,
) -> Option<MockSorafsPinRegistration> {
    if request.method != "POST" || request.path != "/v1/sorafs/pin/register" {
        return None;
    }
    let transaction = SignedTransaction::decode_all_versioned(&request.body).ok()?;
    transaction.verify_signature().ok()?;
    let Executable::Instructions(instructions) = transaction.instructions() else {
        return None;
    };
    let [instruction] = instructions.as_ref() else {
        return None;
    };
    let registration = instruction
        .as_any()
        .downcast_ref::<iroha::data_model::isi::sorafs::RegisterPinManifest>()?;
    let manifest =
        sorafs_manifest::decode_manifest_v1_canonical(&registration.manifest_payload).ok()?;
    let digest = manifest.digest().ok()?;
    Some(MockSorafsPinRegistration {
        manifest_payload: registration.manifest_payload.clone(),
        manifest_digest_hex: hex::encode(digest.as_bytes()),
        tx_hash_hex: hex::encode(transaction.hash().as_ref()),
    })
}
fn mock_sorafs_pin_registration_response(
    registration: &MockSorafsPinRegistration,
) -> MockHttpResponse {
    MockHttpResponse::json(
        json::to_vec(&norito::json!({
            "status": "submitted",
            "tx_hash_hex": (registration.tx_hash_hex.clone()),
            "manifest_digest_hex": (registration.manifest_digest_hex.clone()),
        }))
        .expect("encode mock SoraFS pin registration response"),
    )
}
fn mock_sorafs_pin_registry_response(
    path: &str,
    registered_pin_manifests: &BTreeMap<String, Vec<u8>>,
) -> Option<MockHttpResponse> {
    let digest = mock_sorafs_pin_registry_path_is_registered(path, registered_pin_manifests)?;
    let manifest =
        sorafs_manifest::decode_manifest_v1_canonical(registered_pin_manifests.get(digest)?)
            .ok()?;
    let manifest_digest = ManifestDigest::from_manifest(&manifest).ok()?;
    let root_cid = ManifestRootCid::try_from_slice(&manifest.root_cid).ok()?;
    let chunker = iroha::data_model::sorafs::pin_registry::ChunkerProfileHandle {
        profile_id: manifest.chunking.profile_id.0,
        namespace: manifest.chunking.namespace.clone(),
        name: manifest.chunking.name.clone(),
        semver: manifest.chunking.semver.clone(),
        multihash_code: manifest.chunking.multihash_code,
    };
    let storage_class = match manifest.pin_policy.storage_class {
        ManifestStorageClass::Hot => StorageClass::Hot,
        ManifestStorageClass::Warm => StorageClass::Warm,
        ManifestStorageClass::Cold => StorageClass::Cold,
    };
    let mut record = iroha::data_model::sorafs::pin_registry::PinManifestRecord::new(
        manifest_digest,
        root_cid,
        chunker,
        manifest.chunk_digest_sha3_256,
        manifest.por_root,
        manifest.content_length,
        iroha::data_model::sorafs::pin_registry::PinPolicy {
            min_replicas: manifest.pin_policy.min_replicas,
            storage_class,
            retention_epoch: manifest.pin_policy.retention_epoch,
        },
        AccountId::new(soracloud_fixture_key_pair(0x4B).public_key().clone()),
        1,
        None,
        None,
        Metadata::default(),
    );
    record.approve(2, None);
    let finalized = PinManifestFinalizedRecordV1 {
        finalized_cursor: iroha::data_model::sorafs::pin_registry::PinManifestFinalizedCursorV1 {
            height: 2,
            block_hash: [0x4B; 32],
        },
        manifest: record,
    };
    Some(MockHttpResponse {
        status: "200 OK",
        content_type: "application/json",
        body: json::to_vec(&finalized).expect("encode mock SoraFS pin registry response"),
    })
}
fn mock_sorafs_pin_registry_path_is_registered<'a>(
    path: &'a str,
    registered_pin_manifests: &'a BTreeMap<String, Vec<u8>>,
) -> Option<&'a str> {
    let digest = path.strip_prefix("/v1/sorafs/pin/")?;
    if digest.contains('/') || digest.contains('?') {
        return None;
    }
    registered_pin_manifests
        .get_key_value(&digest.to_ascii_lowercase())
        .map(|(digest, _)| digest.as_str())
}
#[test]
fn mock_http_server_quotes_the_exact_requested_fee_intent() {
    let server = MockHttpServer::start(BTreeMap::new());
    let key_pair = soracloud_fixture_key_pair(0x49);
    let authority = AccountId::new(key_pair.public_key().clone());
    let mut config = crate::fallback_config();
    config.account = authority.clone();
    config.key_pair = key_pair;
    config.torii_api_url = server.base_url.parse().expect("mock Torii URL");
    let client = Client::new(config).expect("blocking Soracloud fixture client");
    let requested_intent = FeePaymentIntent::authority(Vec::new(), None);
    let payload = client
        .account_client()
        .prepare_transaction(iroha::client::AccountTransactionDraft::new(
            Vec::<InstructionBox>::new(),
            requested_intent.clone(),
            Metadata::default(),
        ))
        .expect("build exact unsigned fee quote payload");
    let quote = client
        .quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload })
        .expect("quote mock fees");
    assert_eq!(quote.intent, requested_intent);
    assert_eq!(quote.observation.route_dataspace_id, DataSpaceId::UNIVERSAL);
    assert!(matches!(
        quote.decision,
        FeeQuoteDecision::Accepted {
            debit_source: FeeDebitSource::Account(ref quoted_authority),
            program_revision: None,
        } if quoted_authority == &authority
    ));
    assert!(server.requests().iter().any(|request| {
        request.method == "POST"
            && request.path == iroha_torii_shared::route_catalog::fees::QUOTE_PATH
    }));
}

#[test]
fn taira_mutation_binding_requires_exact_public_reset_nonce_grammar() {
    let fixture = |nonce: &str| TairaMutationBindingV1 {
        authorization_sha256: "ab".repeat(32),
        authorization_nonce: nonce.to_owned(),
        kind: "inrou_bundle_pin".to_owned(),
        phase: "pre_edge".to_owned(),
        idempotency_key: "cd".repeat(32),
        execution_expires_at_unix_ms: 1,
    };
    assert!(
        fixture("0123456789abcdef_123456789abcde-")
            .validate()
            .is_ok()
    );
    for invalid in [
        "short",
        "0123456789abcdef0123456789abcdefx",
        "0123456789abcdef0123456789abcdeF",
        "0123456789abcdef0123456789abcde.",
    ] {
        assert!(fixture(invalid).validate().is_err(), "accepted `{invalid}`");
    }
}

#[test]
fn prepared_inrou_operations_have_one_exact_child_identity() {
    for (operation, label, kind) in [
        (
            TairaInrouCanaryPreparedOperationV1::BundlePin,
            "bundle_pin",
            "inrou_bundle_pin",
        ),
        (
            TairaInrouCanaryPreparedOperationV1::GuestPin,
            "guest_pin",
            "inrou_guest_pin",
        ),
        (
            TairaInrouCanaryPreparedOperationV1::DiscoveryPin,
            "discovery_pin",
            "inrou_discovery_pin",
        ),
        (
            TairaInrouCanaryPreparedOperationV1::ServiceMutation,
            "service_mutation",
            "inrou_canary",
        ),
    ] {
        assert_eq!(operation.operation_label(), label);
        assert_eq!(operation.mutation_kind(), kind);
    }
}
