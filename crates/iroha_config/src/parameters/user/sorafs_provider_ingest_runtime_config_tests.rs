//! Focused parser tests for the `SoraFS` provider-ingest runtime policy.
use super::*;
fn provider_id() -> ProviderId {
    ProviderId::new([0x51; 32])
}
fn completion_signer_public_key_hex() -> String {
    let key =
        KeyPair::try_from_seed(vec![0x52; 32], Algorithm::Ed25519).expect("completion signer key");
    hex::encode(key.public_key().to_bytes().1)
}
fn valid_config() -> SorafsProviderIngestRuntimeConfig {
    SorafsProviderIngestRuntimeConfig {
        enabled: true,
        authenticated_source_fetch_handle: Some("https-pinned-source-pool:eu-1".to_owned()),
        authenticated_source_fetch_revision: Some(5),
        authenticated_source_fetch_policy_digest_hex: Some("b1".repeat(32)),
        completion_signer_resolver_handle: Some(
            "resolver://sorafs/provider-ingest/primary".to_owned(),
        ),
        completion_signer_resolver_revision: Some(6),
        completion_signer_resolver_policy_digest_hex: Some("b2".repeat(32)),
        completion_signer_handle: Some(
            "software://sorafs/provider-ingest/signer-primary".to_owned(),
        ),
        completion_signer_adapter_revision: Some(3),
        completion_signer_policy_id_hex: Some("a1".repeat(32)),
        completion_signer_policy_revision: Some(1),
        completion_signer_policy_predecessor_digest_hex: None,
        completion_signer_policy_digest_hex: Some("a2".repeat(32)),
        completion_signer_algorithm: Some(Algorithm::Ed25519),
        completion_signer_public_key_hex: Some(completion_signer_public_key_hex()),
        checkpoint_store_handle: Some(
            "sealed://sorafs/provider-ingest/checkpoint-primary".to_owned(),
        ),
        checkpoint_store_revision: Some(7),
        checkpoint_store_policy_digest_hex: Some("a7".repeat(32)),
        ..SorafsProviderIngestRuntimeConfig::default()
    }
}
fn enable_attestation_journal(config: &mut SorafsProviderAttestationJournalConfig) {
    config.enabled = true;
    config.clock_handle = Some("sealed://sorafs/provider-attestation/clock-primary".to_owned());
    config.clock_revision = Some(11);
    config.clock_policy_digest_hex = Some("c1".repeat(32));
    config.approval_signer_handle =
        Some("signer://sorafs/provider-attestation/approval-primary".to_owned());
    config.approval_signer_revision = Some(12);
    config.approval_signer_policy_digest_hex = Some("c2".repeat(32));
    config.inventory_handle =
        Some("coordinator://sorafs/provider-attestation/inventory-primary".to_owned());
    config.inventory_revision = Some(13);
    config.inventory_policy_digest_hex = Some("c3".repeat(32));
}
fn large_valid_outbox_config() -> SorafsProviderIngestRuntimeConfig {
    use defaults::sorafs::storage::provider_ingest_runtime::outbox;
    let mut config = valid_config();
    config.max_source_jobs_per_tick = 1;
    config.outbox.max_active_entries = 1;
    config.outbox.max_terminal_entries = 1;
    config.outbox.checkpoint_max_bytes = Bytes(outbox::CHECKPOINT_MAX_BYTES_LIMIT);
    config.outbox.max_signed_transaction_bytes = Bytes(outbox::MAX_SIGNED_TRANSACTION_BYTES_LIMIT);
    config
}
#[test]
fn disabled_default_is_inert() {
    let config = SorafsProviderIngestRuntimeConfig::default();
    let journal = &config.provider_attestation_journal;
    assert!(!journal.enabled);
    assert!(journal.clock_handle.is_none());
    assert!(journal.clock_revision.is_none());
    assert!(journal.clock_policy_digest_hex.is_none());
    assert!(journal.approval_signer_handle.is_none());
    assert!(journal.approval_signer_revision.is_none());
    assert!(journal.approval_signer_policy_digest_hex.is_none());
    assert!(journal.inventory_handle.is_none());
    assert!(journal.inventory_revision.is_none());
    assert!(journal.inventory_policy_digest_hex.is_none());
    let mut emitter = Emitter::new();
    assert!(config.parse(false, None, &mut emitter).is_none());
    assert!(emitter.into_result().is_ok());
}
#[test]
fn omitted_native_source_origins_deserializes_to_an_empty_map() {
    use iroha_config_base::{read::ConfigReader, toml::TomlSource};

    let config = ConfigReader::new()
        .with_toml_source(TomlSource::inline(toml::Table::new()))
        .read_and_complete::<SorafsProviderIngestRuntimeConfig>()
        .expect("an omitted optional native source map must not prevent startup");
    assert!(config.native_source_origins.is_empty());
    assert!(config.native_completion_credential.is_none());
    assert!(!config.enabled);
}
#[test]
fn enabled_policy_parses_without_credentials() {
    let provider_id = provider_id();
    let mut emitter = Emitter::new();
    let parsed = valid_config()
        .parse(true, Some(&provider_id), &mut emitter)
        .expect("enabled provider-ingest policy");
    emitter
        .into_result()
        .expect("valid provider-ingest policy must not emit errors");
    assert_eq!(parsed.scan_interval_ms, 1_000);
    assert_eq!(parsed.max_page_rows, 64);
    assert_eq!(parsed.max_pages_per_tick, 4);
    assert_eq!(parsed.max_source_providers, 1_024);
    assert_eq!(parsed.authenticated_source_fetch_revision, 5);
    assert_eq!(parsed.authenticated_source_fetch_policy_digest, [0xB1; 32]);
    assert_eq!(parsed.completion_signer_resolver_revision, 6);
    assert_eq!(parsed.completion_signer_resolver_policy_digest, [0xB2; 32]);
    assert_eq!(
        parsed.finalized_archive.relative_root,
        PathBuf::from("provider-ingest-finalized-archive-v1")
    );
    assert_eq!(parsed.finalized_archive.max_record_bytes, 128 * 1024 * 1024);
    assert_eq!(parsed.finalized_archive.max_archive_entries, 1_000_000);
    assert_eq!(
        parsed.finalized_archive.max_total_bytes,
        64 * 1024 * 1024 * 1024
    );
    assert_eq!(parsed.finalized_archive.max_providers_per_anchor, 1_024);
    assert_eq!(parsed.finalized_archive.max_orders_per_provider, 256);
    assert_eq!(parsed.finalized_archive.max_total_orders_per_anchor, 256);
    assert_eq!(parsed.finalized_archive.max_page_rows, 64);
    assert_eq!(parsed.finalized_archive.max_kura_tip_lag_blocks, 2);
    assert_eq!(parsed.completion_signer_adapter_revision, 3);
    assert_eq!(
        parsed.completion_signer_policy,
        ProviderIngestCompletionSignerPolicyV1 {
            policy_id: [0xA1; 32],
            revision: 1,
            predecessor_digest: None,
            policy_digest: [0xA2; 32],
        }
    );
    assert_eq!(parsed.completion_signer_algorithm, Algorithm::Ed25519);
    assert_eq!(
        hex::encode(parsed.completion_signer_public_key.to_bytes().1),
        completion_signer_public_key_hex()
    );
    assert_eq!(parsed.checkpoint_store_revision, 7);
    assert_eq!(parsed.checkpoint_store_policy_digest, [0xA7; 32]);
    assert_eq!(parsed.outbox.max_status_page_size, 256);
    assert_eq!(parsed.outbox.max_active_entries, 128);
    assert_eq!(
        parsed.outbox.checkpoint_max_bytes.0,
        defaults::sorafs::storage::provider_ingest_runtime::outbox::CHECKPOINT_MAX_BYTES.0,
    );
    assert_eq!(parsed.outbox.checkpoint_operation_timeout_ms, 30_000);
    assert!(parsed.provider_attestation_journal.is_none());
}
#[test]
fn enabled_attestation_journal_projects_exact_policy_and_bindings() {
    use defaults::sorafs::storage::provider_ingest_runtime::provider_attestation_journal as journal;
    let mut config = valid_config();
    enable_attestation_journal(&mut config.provider_attestation_journal);
    let mut emitter = Emitter::new();
    let parsed = config
        .parse(true, Some(&provider_id()), &mut emitter)
        .expect("enabled provider-ingest policy with capture journal");
    emitter
        .into_result()
        .expect("valid provider-ingest attestation journal must not emit errors");
    assert_eq!(
        parsed.provider_attestation_journal,
        Some(actual::SorafsProviderAttestationJournal {
            clock: actual::SorafsProviderAttestationRuntimeBinding {
                handle: "sealed://sorafs/provider-attestation/clock-primary".to_owned(),
                revision: 11,
                policy_digest: [0xC1; 32],
            },
            approval_signer: actual::SorafsProviderAttestationRuntimeBinding {
                handle: "signer://sorafs/provider-attestation/approval-primary".to_owned(),
                revision: 12,
                policy_digest: [0xC2; 32],
            },
            inventory: actual::SorafsProviderAttestationRuntimeBinding {
                handle: "coordinator://sorafs/provider-attestation/inventory-primary".to_owned(),
                revision: 13,
                policy_digest: [0xC3; 32],
            },
            max_entries: journal::MAX_ENTRIES,
            max_attempts: journal::MAX_ATTEMPTS,
            lease_ttl_ms: journal::LEASE_TTL_MS,
            approval_timeout_ms: journal::APPROVAL_TIMEOUT_MS,
            handoff_timeout_ms: journal::HANDOFF_TIMEOUT_MS,
            retry_delay_ms: journal::RETRY_DELAY_MS,
            checkpoint_max_bytes: usize::try_from(journal::CHECKPOINT_MAX_BYTES.0)
                .expect("default checkpoint bound fits usize"),
            max_cas_retries: journal::MAX_CAS_RETRIES,
        })
    );
}
#[test]
fn disabled_attestation_journal_rejects_every_binding_field() {
    let mutations: [fn(&mut SorafsProviderAttestationJournalConfig); 9] = [
        |config| config.clock_handle = Some("sealed://clock/primary".to_owned()),
        |config| config.clock_revision = Some(1),
        |config| config.clock_policy_digest_hex = Some("c1".repeat(32)),
        |config| config.approval_signer_handle = Some("signer://approval/primary".to_owned()),
        |config| config.approval_signer_revision = Some(1),
        |config| config.approval_signer_policy_digest_hex = Some("c2".repeat(32)),
        |config| config.inventory_handle = Some("coordinator://inventory/primary".to_owned()),
        |config| config.inventory_revision = Some(1),
        |config| config.inventory_policy_digest_hex = Some("c3".repeat(32)),
    ];
    for mutate in mutations {
        let mut config = SorafsProviderIngestRuntimeConfig::default();
        mutate(&mut config.provider_attestation_journal);
        let mut emitter = Emitter::new();
        assert!(config.parse(false, None, &mut emitter).is_none());
        assert!(emitter.into_result().is_err());
    }
}
#[test]
fn enabled_attestation_journal_requires_all_three_binding_roles() {
    for present_roles in 0_u8..0b111 {
        let mut config = valid_config();
        enable_attestation_journal(&mut config.provider_attestation_journal);
        if present_roles & 0b001 == 0 {
            config.provider_attestation_journal.clock_handle = None;
            config.provider_attestation_journal.clock_revision = None;
            config.provider_attestation_journal.clock_policy_digest_hex = None;
        }
        if present_roles & 0b010 == 0 {
            config.provider_attestation_journal.approval_signer_handle = None;
            config.provider_attestation_journal.approval_signer_revision = None;
            config
                .provider_attestation_journal
                .approval_signer_policy_digest_hex = None;
        }
        if present_roles & 0b100 == 0 {
            config.provider_attestation_journal.inventory_handle = None;
            config.provider_attestation_journal.inventory_revision = None;
            config
                .provider_attestation_journal
                .inventory_policy_digest_hex = None;
        }
        let mut emitter = Emitter::new();
        assert!(
            config
                .parse(true, Some(&provider_id()), &mut emitter)
                .is_none(),
            "role mask {present_roles:03b} must fail closed"
        );
        assert!(emitter.into_result().is_err());
    }
}
#[test]
fn enabled_attestation_journal_rejects_partial_binding_triplets() {
    for present_fields in 0b001_u8..0b111 {
        let mut config = valid_config();
        enable_attestation_journal(&mut config.provider_attestation_journal);
        config.provider_attestation_journal.clock_handle =
            (present_fields & 0b001 != 0).then(|| "sealed://clock/primary".to_owned());
        config.provider_attestation_journal.clock_revision =
            (present_fields & 0b010 != 0).then_some(11);
        config.provider_attestation_journal.clock_policy_digest_hex =
            (present_fields & 0b100 != 0).then(|| "c1".repeat(32));
        let mut emitter = Emitter::new();
        assert!(
            config
                .parse(true, Some(&provider_id()), &mut emitter)
                .is_none(),
            "field mask {present_fields:03b} must fail closed"
        );
        assert!(emitter.into_result().is_err());
    }
}
#[test]
fn enabled_attestation_journal_rejects_unqualified_bindings() {
    let mutations: [fn(&mut SorafsProviderAttestationJournalConfig); 12] = [
        |config| config.clock_handle = Some("sealed://clock/test".to_owned()),
        |config| config.approval_signer_handle = Some("signer://approval/dev".to_owned()),
        |config| config.inventory_handle = Some("coordinator://inventory/mock".to_owned()),
        |config| config.clock_revision = Some(0),
        |config| config.approval_signer_revision = Some(0),
        |config| config.inventory_revision = Some(0),
        |config| config.clock_policy_digest_hex = Some("00".repeat(32)),
        |config| config.approval_signer_policy_digest_hex = Some("00".repeat(32)),
        |config| config.inventory_policy_digest_hex = Some("00".repeat(32)),
        |config| config.clock_policy_digest_hex = Some("C1".repeat(32)),
        |config| config.approval_signer_policy_digest_hex = Some("gg".repeat(32)),
        |config| config.inventory_policy_digest_hex = Some("c3".repeat(31)),
    ];
    for mutate in mutations {
        let mut config = valid_config();
        enable_attestation_journal(&mut config.provider_attestation_journal);
        mutate(&mut config.provider_attestation_journal);
        let mut emitter = Emitter::new();
        assert!(
            config
                .parse(true, Some(&provider_id()), &mut emitter)
                .is_none()
        );
        assert!(emitter.into_result().is_err());
    }
}
#[test]
fn attestation_journal_requires_enabled_provider_ingest_parent() {
    let mut config = SorafsProviderIngestRuntimeConfig::default();
    enable_attestation_journal(&mut config.provider_attestation_journal);
    let mut emitter = Emitter::new();
    assert!(config.parse(false, None, &mut emitter).is_none());
    let error = format!("{:?}", emitter.into_result().expect_err("parent gate"));
    assert!(
        error.contains(
            "provider_attestation_journal.enabled requires provider_ingest_runtime.enabled"
        ),
        "unexpected diagnostic: {error}"
    );
}
#[test]
fn attestation_journal_rejects_zero_below_minimum_and_above_limit_bounds() {
    use defaults::sorafs::storage::provider_ingest_runtime::provider_attestation_journal as journal;
    let mutations: [fn(&mut SorafsProviderAttestationJournalConfig); 17] = [
        |config| config.max_entries = 0,
        |config| config.max_entries = journal::MAX_ENTRIES_LIMIT + 1,
        |config| config.max_attempts = 0,
        |config| config.max_attempts = journal::MAX_ATTEMPTS_LIMIT + 1,
        |config| config.lease_ttl_ms = 0,
        |config| config.lease_ttl_ms = journal::LEASE_TTL_MAX_MS + 1,
        |config| config.approval_timeout_ms = 0,
        |config| config.approval_timeout_ms = journal::EXTERNAL_TIMEOUT_MAX_MS + 1,
        |config| config.handoff_timeout_ms = 0,
        |config| config.handoff_timeout_ms = journal::EXTERNAL_TIMEOUT_MAX_MS + 1,
        |config| config.retry_delay_ms = 0,
        |config| config.retry_delay_ms = journal::RETRY_DELAY_MAX_MS + 1,
        |config| config.checkpoint_max_bytes = Bytes(0),
        |config| {
            config.checkpoint_max_bytes = Bytes(
                u64::try_from(journal::CHECKPOINT_MIN_BYTES).expect("checkpoint minimum fits u64")
                    - 1,
            );
        },
        |config| {
            config.checkpoint_max_bytes = Bytes(
                u64::try_from(journal::CHECKPOINT_MAX_BYTES_LIMIT)
                    .expect("checkpoint limit fits u64")
                    + 1,
            );
        },
        |config| config.max_cas_retries = 0,
        |config| config.max_cas_retries = journal::MAX_CAS_RETRIES_LIMIT + 1,
    ];
    for mutate in mutations {
        let mut config = valid_config();
        enable_attestation_journal(&mut config.provider_attestation_journal);
        mutate(&mut config.provider_attestation_journal);
        let mut emitter = Emitter::new();
        assert!(
            config
                .parse(true, Some(&provider_id()), &mut emitter)
                .is_none()
        );
        assert!(emitter.into_result().is_err());
    }
}
#[test]
fn attestation_journal_accepts_exact_checkpoint_minimum() {
    use defaults::sorafs::storage::provider_ingest_runtime::provider_attestation_journal as journal;
    let mut config = valid_config();
    enable_attestation_journal(&mut config.provider_attestation_journal);
    config.provider_attestation_journal.checkpoint_max_bytes =
        Bytes(u64::try_from(journal::CHECKPOINT_MIN_BYTES).expect("checkpoint minimum fits u64"));
    let mut emitter = Emitter::new();
    let parsed = config
        .parse(true, Some(&provider_id()), &mut emitter)
        .expect("exact checkpoint minimum is valid");
    emitter
        .into_result()
        .expect("minimum valid checkpoint must not emit errors");
    assert_eq!(
        parsed
            .provider_attestation_journal
            .expect("enabled journal")
            .checkpoint_max_bytes,
        journal::CHECKPOINT_MIN_BYTES
    );
}
#[test]
fn attestation_journal_stage_timeouts_must_fit_the_claim_lease() {
    let mutations: [fn(&mut SorafsProviderAttestationJournalConfig); 2] = [
        |config: &mut SorafsProviderAttestationJournalConfig| {
            config.approval_timeout_ms = config.lease_ttl_ms;
        },
        |config: &mut SorafsProviderAttestationJournalConfig| {
            config.handoff_timeout_ms = config.lease_ttl_ms;
        },
    ];
    for select_timeout in mutations {
        let mut config = valid_config();
        enable_attestation_journal(&mut config.provider_attestation_journal);
        select_timeout(&mut config.provider_attestation_journal);
        let mut emitter = Emitter::new();
        assert!(
            config
                .parse(true, Some(&provider_id()), &mut emitter)
                .is_none()
        );
        assert!(emitter.into_result().is_err());
    }
}
#[test]
fn defaults_and_actual_projection_respect_provider_broker_limits() {
    use defaults::sorafs::storage::provider_ingest_runtime::outbox;
    assert_eq!(outbox::CHECKPOINT_MAX_BYTES_LIMIT, 192 * 1024 * 1024);
    assert_eq!(outbox::MAX_SIGNED_TRANSACTION_BYTES_LIMIT, 64 * 1024 * 1024);
    assert_eq!(outbox::MAX_SIGNED_TRANSACTION_BYTES_MIN, 64 * 1024);
    const {
        assert!(
            outbox::MAX_SIGNED_TRANSACTION_BYTES_MIN
                > outbox::SIGNED_TRANSACTION_ENVELOPE_RESERVE_BYTES_V1
        );
    };
    const {
        assert!(outbox::CHECKPOINT_MAX_BYTES.0 <= outbox::CHECKPOINT_MAX_BYTES_LIMIT);
    };
    const {
        assert!(outbox::MAX_SIGNED_TRANSACTION_BYTES.0 >= outbox::MAX_SIGNED_TRANSACTION_BYTES_MIN);
    };
    const {
        assert!(
            outbox::MAX_SIGNED_TRANSACTION_BYTES.0 <= outbox::MAX_SIGNED_TRANSACTION_BYTES_LIMIT
        );
    };
    let mut emitter = Emitter::new();
    let parsed = large_valid_outbox_config()
        .parse(true, Some(&provider_id()), &mut emitter)
        .expect("large but checkpoint-compatible policy must project");
    assert!(emitter.into_result().is_ok());
    assert_eq!(
        parsed.outbox.checkpoint_max_bytes.0,
        outbox::CHECKPOINT_MAX_BYTES_LIMIT
    );
    assert_eq!(
        parsed.outbox.max_signed_transaction_bytes.0,
        outbox::MAX_SIGNED_TRANSACTION_BYTES_LIMIT
    );
}
#[test]
fn broker_incompatible_outbox_limits_fail_closed() {
    use defaults::sorafs::storage::provider_ingest_runtime::outbox;
    let mut oversized_checkpoint = large_valid_outbox_config();
    oversized_checkpoint.outbox.checkpoint_max_bytes =
        Bytes(outbox::CHECKPOINT_MAX_BYTES_LIMIT + 1);
    let mut emitter = Emitter::new();
    let _projected = oversized_checkpoint.parse(true, Some(&provider_id()), &mut emitter);
    assert!(
        emitter.into_result().is_err(),
        "checkpoint bytes above the stock broker ceiling must fail"
    );
    let mut oversized_transaction = large_valid_outbox_config();
    oversized_transaction.outbox.max_signed_transaction_bytes =
        Bytes(outbox::MAX_SIGNED_TRANSACTION_BYTES_LIMIT + 1);
    let mut emitter = Emitter::new();
    let _projected = oversized_transaction.parse(true, Some(&provider_id()), &mut emitter);
    assert!(
        emitter.into_result().is_err(),
        "signed transaction bytes above the stock broker ceiling must fail"
    );
    let mut below_envelope_reserve = large_valid_outbox_config();
    below_envelope_reserve.outbox.max_signed_transaction_bytes =
        Bytes(outbox::MAX_SIGNED_TRANSACTION_BYTES_MIN - 1);
    let mut emitter = Emitter::new();
    let _projected = below_envelope_reserve.parse(true, Some(&provider_id()), &mut emitter);
    assert!(
        emitter.into_result().is_err(),
        "a signed transaction limit without room beyond the envelope reserve must fail"
    );
    let mut exact_minimum = large_valid_outbox_config();
    exact_minimum.outbox.max_active_entries = 1;
    exact_minimum.outbox.max_terminal_entries = 1;
    exact_minimum.outbox.max_signed_transaction_bytes =
        Bytes(outbox::MAX_SIGNED_TRANSACTION_BYTES_MIN);
    let mut emitter = Emitter::new();
    let projected = exact_minimum
        .parse(true, Some(&provider_id()), &mut emitter)
        .expect("exact signed-transaction minimum must project");
    assert!(emitter.into_result().is_ok());
    assert_eq!(
        projected.outbox.max_signed_transaction_bytes.0,
        outbox::MAX_SIGNED_TRANSACTION_BYTES_MIN
    );
    let mut legacy_128_mib_ceiling = large_valid_outbox_config();
    legacy_128_mib_ceiling.outbox.max_signed_transaction_bytes = Bytes(128 * 1024 * 1024);
    let mut emitter = Emitter::new();
    let _projected = legacy_128_mib_ceiling.parse(true, Some(&provider_id()), &mut emitter);
    assert!(
        emitter.into_result().is_err(),
        "one retained expected payload plus one signed transaction at the 128 MiB ceiling cannot fit the 192 MiB checkpoint ceiling"
    );
}
#[test]
fn enabled_policy_requires_storage_provider_and_production_handles() {
    let mut config = valid_config();
    config.authenticated_source_fetch_handle = Some("mock-source.test".to_owned());
    config.authenticated_source_fetch_revision = Some(0);
    config.authenticated_source_fetch_policy_digest_hex = Some("00".repeat(32));
    config.completion_signer_resolver_handle = None;
    config.completion_signer_resolver_revision = None;
    config.completion_signer_resolver_policy_digest_hex = Some("B2".repeat(32));
    config.checkpoint_store_handle = Some("sealed.sorafs.test".to_owned());
    config.checkpoint_store_revision = Some(0);
    config.checkpoint_store_policy_digest_hex = Some("A7".repeat(32));
    let mut emitter = Emitter::new();
    assert!(config.parse(false, None, &mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn enabled_policy_rejects_credential_or_uri_parameter_handles() {
    for rejected in [
        "https://operator:secret@host",
        "https://host/source?token=secret",
        "https://host/source#fragment",
        "https://host/%73ource",
        "resolver://sorafs/provider-ingest/dummy",
    ] {
        let mut config = valid_config();
        config.authenticated_source_fetch_handle = Some(rejected.to_owned());
        let mut emitter = Emitter::new();
        assert!(
            config
                .parse(true, Some(&provider_id()), &mut emitter)
                .is_none(),
            "{rejected:?} must not reach the actual configuration"
        );
        assert!(emitter.into_result().is_err());
    }
}
#[test]
fn enabled_policy_rejects_stale_or_noncanonical_completion_signer_binding() {
    let mut config = valid_config();
    config.completion_signer_handle = Some("software://sorafs/provider-ingest/test".to_owned());
    config.completion_signer_adapter_revision = Some(0);
    config.completion_signer_policy_id_hex = Some("00".repeat(32));
    config.completion_signer_policy_revision = Some(2);
    config.completion_signer_policy_predecessor_digest_hex = None;
    config.completion_signer_policy_digest_hex = Some("A2".repeat(32));
    config.completion_signer_algorithm = Some(Algorithm::Secp256k1);
    config.completion_signer_public_key_hex =
        Some(completion_signer_public_key_hex().to_uppercase());
    let mut emitter = Emitter::new();
    assert!(
        config
            .parse(true, Some(&provider_id()), &mut emitter)
            .is_none()
    );
    assert!(emitter.into_result().is_err());
}
#[test]
fn enabled_policy_rejects_zero_provider_identity() {
    let zero_provider_id = ProviderId::new([0; 32]);
    let mut emitter = Emitter::new();
    assert!(
        valid_config()
            .parse(true, Some(&zero_provider_id), &mut emitter)
            .is_some()
    );
    assert!(emitter.into_result().is_err());
}
#[test]
fn unsafe_resource_timing_and_capacity_bounds_fail_closed() {
    use defaults::sorafs::storage::provider_ingest_runtime::outbox;
    let provider_id = provider_id();
    let mut config = valid_config();
    config.scan_interval_ms = 0;
    config.max_page_rows = 1_001;
    config.max_pages_per_tick = 4_097;
    config.max_source_jobs_per_tick = 4_097;
    config.max_source_providers = 1_025;
    config.source_operation_timeout_ms = 24 * 60 * 60 * 1_000 + 1;
    config.source_lease_renew_interval_ms = 60_000;
    config.signer_timeout_ms = 0;
    config.ingress_timeout_ms = 0;
    config.completion_transaction_ttl_ms = 0;
    config.finalized_archive.relative_root = PathBuf::from("../archive");
    config.finalized_archive.max_record_bytes = Bytes(1024 * 1024 * 1024 + 1);
    config.finalized_archive.max_archive_entries = 1_000_001;
    config.finalized_archive.max_total_bytes = Bytes(1024 * 1024 * 1024 * 1024 + 1);
    config.finalized_archive.max_providers_per_anchor = 1_025;
    config.finalized_archive.max_orders_per_provider = 65_537;
    config.finalized_archive.max_total_orders_per_anchor = 65_537;
    config.finalized_archive.max_page_rows = 1_001;
    config.finalized_archive.max_kura_tip_lag_blocks = 10_001;
    config.outbox.max_active_entries = 0;
    config.outbox.max_terminal_entries = 65_537;
    config.outbox.max_attempts = 65;
    config.outbox.checkpoint_max_bytes = Bytes(outbox::CHECKPOINT_MAX_BYTES_LIMIT + 1);
    config.outbox.checkpoint_operation_timeout_ms = 24 * 60 * 60 * 1_000 + 1;
    config.outbox.source_lease_ttl_ms = 60_000;
    config.outbox.retry_base_delay_ms = 2_000;
    config.outbox.retry_max_delay_ms = 1_000;
    config.outbox.terminal_retention_blocks = 10_000_001;
    config.outbox.max_signed_transaction_bytes =
        Bytes(outbox::MAX_SIGNED_TRANSACTION_BYTES_LIMIT + 1);
    config.outbox.max_status_page_size = 1_001;
    let mut emitter = Emitter::new();
    assert!(
        config
            .parse(true, Some(&provider_id), &mut emitter)
            .is_none()
    );
    assert!(emitter.into_result().is_err());
}
#[test]
fn checkpoint_operation_deadline_must_be_nonzero_and_bounded() {
    for invalid_timeout_ms in [0, 24 * 60 * 60 * 1_000 + 1] {
        let mut config = valid_config();
        config.outbox.checkpoint_operation_timeout_ms = invalid_timeout_ms;
        let mut emitter = Emitter::new();
        let _actual = config.parse(true, Some(&provider_id()), &mut emitter);
        assert!(
            emitter.into_result().is_err(),
            "{invalid_timeout_ms}ms must not reach a runnable configuration"
        );
    }
}
#[test]
fn checked_aggregate_capacities_fail_closed() {
    let provider_id = provider_id();
    let mut config = valid_config();
    config.max_page_rows = 1_000;
    config.max_pages_per_tick = 4_096;
    config.finalized_archive.max_page_rows = 1_000;
    config.finalized_archive.max_record_bytes = Bytes(1);
    config.max_source_jobs_per_tick = 16;
    config.outbox.max_active_entries = 1;
    config.outbox.max_terminal_entries = 1;
    config.outbox.checkpoint_max_bytes = Bytes(1);
    config.outbox.max_signed_transaction_bytes = Bytes(1);
    let mut emitter = Emitter::new();
    assert!(
        config
            .parse(true, Some(&provider_id), &mut emitter)
            .is_none()
    );
    assert!(emitter.into_result().is_err());
}
#[test]
fn archive_policy_allows_zero_lag_but_rejects_absolute_or_dot_roots() {
    let provider_id = provider_id();
    let mut zero_lag = valid_config();
    zero_lag.finalized_archive.max_kura_tip_lag_blocks = 0;
    let mut emitter = Emitter::new();
    let parsed = zero_lag
        .parse(true, Some(&provider_id), &mut emitter)
        .expect("zero-lag archive policy");
    assert_eq!(parsed.finalized_archive.max_kura_tip_lag_blocks, 0);
    emitter
        .into_result()
        .expect("zero-lag archive policy must not emit errors");
    for relative_root in [
        PathBuf::from("."),
        PathBuf::from("archive/../substituted"),
        std::env::current_dir()
            .expect("current directory")
            .join("absolute-archive"),
    ] {
        let mut config = valid_config();
        config.finalized_archive.relative_root = relative_root;
        let mut emitter = Emitter::new();
        assert!(
            config
                .parse(true, Some(&provider_id), &mut emitter)
                .is_none()
        );
        assert!(emitter.into_result().is_err());
    }
}
#[test]
fn worst_case_outbox_transactions_must_fit_checkpoint() {
    let provider_id = provider_id();
    let mut config = valid_config();
    config.outbox.max_active_entries = 4_096;
    let mut emitter = Emitter::new();
    assert!(
        config
            .parse(true, Some(&provider_id), &mut emitter)
            .is_some()
    );
    assert!(emitter.into_result().is_err());
}
#[test]
fn disabled_policy_rejects_stale_runtime_bindings() {
    let config = SorafsProviderIngestRuntimeConfig {
        authenticated_source_fetch_handle: Some(
            "network.sorafs.authenticated-source.primary".to_owned(),
        ),
        completion_signer_resolver_policy_digest_hex: Some("b2".repeat(32)),
        checkpoint_store_revision: Some(1),
        ..SorafsProviderIngestRuntimeConfig::default()
    };
    let mut emitter = Emitter::new();
    assert!(config.parse(false, None, &mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn disabled_policy_rejects_each_top_level_provider_qualification_field() {
    let mutations: [fn(&mut SorafsProviderIngestRuntimeConfig); 4] = [
        |config| config.authenticated_source_fetch_revision = Some(5),
        |config| {
            config.authenticated_source_fetch_policy_digest_hex = Some("b1".repeat(32));
        },
        |config| config.completion_signer_resolver_revision = Some(6),
        |config| {
            config.completion_signer_resolver_policy_digest_hex = Some("b2".repeat(32));
        },
    ];
    for mutate in mutations {
        let mut config = SorafsProviderIngestRuntimeConfig::default();
        mutate(&mut config);
        let mut emitter = Emitter::new();
        assert!(config.parse(false, None, &mut emitter).is_none());
        assert!(emitter.into_result().is_err());
    }
}

#[test]
fn native_completion_credential_is_explicit_absolute_and_disabled_configs_reject_it() {
    let provider = provider_id();
    for (path, accepted) in [
        ("/runtime/credentials/completion", true),
        ("completion", false),
        ("/runtime/../completion", false),
    ] {
        let mut config = valid_config();
        config.native_completion_credential = Some(PathBuf::from(path));
        let mut emitter = Emitter::new();
        let result = config.parse(true, Some(&provider), &mut emitter);
        let diagnostics = emitter.into_result();
        assert_eq!(result.is_some() && diagnostics.is_ok(), accepted);
    }
    let config = SorafsProviderIngestRuntimeConfig {
        native_completion_credential: Some(PathBuf::from("/runtime/credentials/completion")),
        ..SorafsProviderIngestRuntimeConfig::default()
    };
    let mut emitter = Emitter::new();
    assert!(config.parse(false, None, &mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}

#[test]
fn selected_clock_triplet_uses_the_single_first_release_config_spelling() {
    use iroha_config_base::{read::ConfigReader, toml::TomlSource};
    let table: toml::Table = r#"
clock_handle = "software://sorafs/provider-attestation-clock"
clock_revision = 1
clock_policy_digest_hex = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
"#
    .parse()
    .unwrap();
    let current = ConfigReader::new()
        .with_toml_source(TomlSource::inline(table.clone()))
        .read_and_complete::<SorafsProviderAttestationJournalConfig>()
        .unwrap();
    assert_eq!(current.clock_revision, Some(1));
    assert_eq!(
        current.clock_handle.as_deref(),
        Some("software://sorafs/provider-attestation-clock")
    );
    let retired = table
        .into_iter()
        .map(|(name, value)| (name.replacen("clock_", "clock_seal_", 1), value))
        .collect();
    assert!(
        ConfigReader::new()
            .with_toml_source(TomlSource::inline(retired))
            .read_and_complete::<SorafsProviderAttestationJournalConfig>()
            .is_err()
    );
}
