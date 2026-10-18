//! Focused parser tests for the `SoraFS` reputation runtime policy.
use super::*;
fn publisher_public_key_hex() -> String {
    let key = KeyPair::try_from_seed(vec![0x52; 32], Algorithm::Ed25519).expect("test keypair");
    hex::encode(key.public_key().to_bytes().1)
}
fn absolute_state_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\iroha\sorafs\reputation")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/var/lib/iroha/sorafs/reputation")
    }
}
fn absolute_trust_policy_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\iroha\reputation-trust-policy.to")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/etc/iroha/reputation-trust-policy.to")
    }
}
fn valid_config() -> SorafsReputationRuntimeConfig {
    SorafsReputationRuntimeConfig {
        enabled: true,
        state_dir: absolute_state_dir(),
        window_start_height: Some(10),
        window_end_height: Some(20),
        finalized_query_handle: Some("ledger.finalized.primary".to_owned()),
        journal_checkpoint_provider_handle: Some("sealed.reputation.journal.primary".to_owned()),
        journal_checkpoint_provider_revision: Some(1),
        journal_checkpoint_provider_policy_digest_hex: Some("60".repeat(32)),
        journal_transaction_submitter_handle: Some("queue.reputation.journal".to_owned()),
        journal_transaction_submitter_revision: Some(11),
        journal_transaction_submitter_policy_digest_hex: Some("61".repeat(32)),
        threshold_signer_handle: Some("software://sorafs/reputation/primary".to_owned()),
        threshold_signer_revision: Some(12),
        threshold_signer_policy_digest_hex: Some("62".repeat(32)),
        governance_dag_handle: Some("governance.dag.publisher".to_owned()),
        governance_dag_revision: Some(13),
        governance_dag_policy_digest_hex: Some("63".repeat(32)),
        governance_publisher_peer_id: Some("12D3KooWProductionPublisher".to_owned()),
        governance_publisher_public_key_hex: Some(publisher_public_key_hex()),
        ..SorafsReputationRuntimeConfig::default()
    }
}
#[test]
fn disabled_default_is_inert() {
    let mut emitter = Emitter::new();
    assert!(
        SorafsReputationRuntimeConfig::default()
            .parse(false, None, &mut emitter)
            .is_none()
    );
    assert!(emitter.into_result().is_ok());
}
#[test]
fn enabled_policy_parses_without_credentials() {
    let mut emitter = Emitter::new();
    let trust_policy_path = absolute_trust_policy_path();
    let parsed = valid_config()
        .parse(true, Some(trust_policy_path.as_path()), &mut emitter)
        .expect("enabled runtime policy");
    assert!(emitter.into_result().is_ok());
    assert_eq!(parsed.window_start_height, 10);
    assert_eq!(parsed.window_end_height, 20);
    assert_eq!(parsed.page_items, 64);
    assert_eq!(parsed.max_pages_per_batch, 4_096);
    assert_eq!(parsed.poll_interval, Duration::from_secs(1));
    assert_eq!(
        parsed.finalized_archive_root,
        absolute_state_dir()
            .join(defaults::sorafs::storage::reputation_runtime::FINALIZED_ARCHIVE_DIRECTORY_NAME)
    );
    assert_eq!(
        parsed.finalized_archive_max_record_bytes,
        defaults::sorafs::storage::reputation_runtime::FINALIZED_ARCHIVE_MAX_RECORD_BYTES
    );
    assert_eq!(
        parsed.finalized_archive_max_entries,
        defaults::sorafs::storage::reputation_runtime::FINALIZED_ARCHIVE_MAX_ENTRIES
    );
    assert_eq!(
        parsed.finalized_archive_max_total_bytes,
        defaults::sorafs::storage::reputation_runtime::FINALIZED_ARCHIVE_MAX_TOTAL_BYTES
    );
    assert_eq!(
        parsed.finalized_archive_max_kura_tip_lag_blocks,
        defaults::sorafs::storage::reputation_runtime::FINALIZED_ARCHIVE_MAX_KURA_TIP_LAG_BLOCKS
    );
    assert!(parsed.finalized_archive_retention_authority.is_none());
    assert_eq!(
        parsed.journal_transaction_submitter_handle,
        "queue.reputation.journal"
    );
    assert_eq!(
        parsed.journal_checkpoint_provider_handle,
        "sealed.reputation.journal.primary"
    );
    assert_eq!(parsed.journal_checkpoint_provider_revision, 1);
    assert_eq!(parsed.journal_checkpoint_provider_policy_digest, [0x60; 32]);
    assert_eq!(parsed.journal_transaction_submitter_revision, 11);
    assert_eq!(
        parsed.journal_transaction_submitter_policy_digest,
        [0x61; 32]
    );
    assert_eq!(parsed.threshold_signer_revision, 12);
    assert_eq!(parsed.threshold_signer_policy_digest, [0x62; 32]);
    assert_eq!(parsed.governance_dag_revision, 13);
    assert_eq!(parsed.governance_dag_policy_digest, [0x63; 32]);
    assert_eq!(
        parsed
            .por_success_bps
            .saturating_add(parsed.pdp_success_bps)
            .saturating_add(parsed.potr_success_bps)
            .saturating_add(parsed.latency_bps)
            .saturating_add(parsed.dispute_bps)
            .saturating_add(parsed.token_violation_bps)
            .saturating_add(parsed.repair_breach_bps),
        10_000
    );
}
#[test]
fn enabled_policy_rejects_missing_or_nonproduction_dependencies() {
    let mut config = valid_config();
    config.finalized_query_handle = Some("null-query.test".to_owned());
    config.journal_checkpoint_provider_handle = Some("mock-seal.test".to_owned());
    config.journal_transaction_submitter_handle = Some("mock-submit.test".to_owned());
    config.threshold_signer_handle = None;
    config.state_dir = PathBuf::from("relative/reputation");
    config.window_end_height = Some(9);
    config.page_items = 65;
    config.max_pages_per_batch = 516;
    config.poll_interval_ms = 0;
    config.repair_breach_bps = 999;
    let mut emitter = Emitter::new();
    assert!(config.parse(false, None, &mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn enabled_policy_rejects_omitted_zero_and_noncanonical_qualification_bindings() {
    let trust_policy_path = absolute_trust_policy_path();
    let mut omitted_revision = valid_config();
    omitted_revision.journal_transaction_submitter_revision = None;
    let mut omitted_checkpoint_revision = valid_config();
    omitted_checkpoint_revision.journal_checkpoint_provider_revision = None;
    let mut omitted_digest = valid_config();
    omitted_digest.threshold_signer_policy_digest_hex = None;
    let mut zero_revision = valid_config();
    zero_revision.governance_dag_revision = Some(0);
    let mut zero_digest = valid_config();
    zero_digest.journal_transaction_submitter_policy_digest_hex = Some("00".repeat(32));
    let mut uppercase_digest = valid_config();
    uppercase_digest.threshold_signer_policy_digest_hex = Some("A2".repeat(32));
    let mut short_digest = valid_config();
    short_digest.governance_dag_policy_digest_hex = Some("63".repeat(31));
    for config in [
        omitted_revision,
        omitted_checkpoint_revision,
        omitted_digest,
        zero_revision,
        zero_digest,
        uppercase_digest,
        short_digest,
    ] {
        let mut emitter = Emitter::new();
        assert!(
            config
                .parse(true, Some(trust_policy_path.as_path()), &mut emitter)
                .is_none()
        );
        assert!(emitter.into_result().is_err());
    }
}
#[test]
fn enabled_policy_rejects_invalid_finalized_archive_bounds_without_clamping() {
    let mut zero_record = valid_config();
    zero_record.finalized_archive_max_record_bytes = 0;
    let mut zero_entries = valid_config();
    zero_entries.finalized_archive_max_entries = 0;
    let mut undersized_total = valid_config();
    undersized_total.finalized_archive_max_record_bytes = 2;
    undersized_total.finalized_archive_max_total_bytes = 1;
    let mut allocation_overflow = valid_config();
    allocation_overflow.finalized_archive_max_record_bytes = u64::MAX;
    allocation_overflow.finalized_archive_max_total_bytes = u64::MAX;
    let mut excessive_lag = valid_config();
    excessive_lag.finalized_archive_max_kura_tip_lag_blocks =
            defaults::sorafs::storage::reputation_runtime::FINALIZED_ARCHIVE_MAX_KURA_TIP_LAG_BLOCKS_LIMIT
                + 1;
    let trust_policy_path = absolute_trust_policy_path();
    for config in [
        zero_record,
        zero_entries,
        undersized_total,
        allocation_overflow,
        excessive_lag,
    ] {
        let mut emitter = Emitter::new();
        assert!(
            config
                .parse(true, Some(trust_policy_path.as_path()), &mut emitter)
                .is_none()
        );
        assert!(emitter.into_result().is_err());
    }
}
#[test]
fn enabled_retention_requires_and_projects_exact_public_authority_binding() {
    let mut config = valid_config();
    config.finalized_archive_retention_enabled = true;
    config.finalized_archive_retention_authority_handle =
        Some("sealed.reputation.archive.primary".to_owned());
    config.finalized_archive_retention_authority_revision = Some(7);
    config.finalized_archive_retention_authority_policy_digest_hex = Some("51".repeat(32));
    let trust_policy_path = absolute_trust_policy_path();
    let mut emitter = Emitter::new();
    let parsed = config
        .parse(true, Some(trust_policy_path.as_path()), &mut emitter)
        .expect("enabled retention authority");
    assert!(emitter.into_result().is_ok());
    let authority = parsed
        .finalized_archive_retention_authority
        .expect("project exact retention authority");
    assert_eq!(authority.handle, "sealed.reputation.archive.primary");
    assert_eq!(authority.revision, 7);
    assert_eq!(authority.policy_digest, [0x51; 32]);
}
#[test]
fn retention_rejects_missing_test_marked_stale_or_noncanonical_bindings() {
    let trust_policy_path = absolute_trust_policy_path();
    let mut missing = valid_config();
    missing.finalized_archive_retention_enabled = true;
    let mut test_marked = valid_config();
    test_marked.finalized_archive_retention_enabled = true;
    test_marked.finalized_archive_retention_authority_handle =
        Some("sealed.reputation.archive.test".to_owned());
    test_marked.finalized_archive_retention_authority_revision = Some(1);
    test_marked.finalized_archive_retention_authority_policy_digest_hex = Some("51".repeat(32));
    let mut stale = valid_config();
    stale.finalized_archive_retention_enabled = true;
    stale.finalized_archive_retention_authority_handle =
        Some("sealed.reputation.archive.primary".to_owned());
    stale.finalized_archive_retention_authority_revision = Some(0);
    stale.finalized_archive_retention_authority_policy_digest_hex = Some("00".repeat(32));
    let mut dormant = valid_config();
    dormant.finalized_archive_retention_authority_handle =
        Some("sealed.reputation.archive.primary".to_owned());
    for config in [missing, test_marked, stale, dormant] {
        let mut emitter = Emitter::new();
        let parsed = config.parse(true, Some(trust_policy_path.as_path()), &mut emitter);
        let emitted_error = emitter.into_result().is_err();
        assert!(parsed.is_none() || emitted_error);
    }
}
#[test]
fn disabled_policy_rejects_stale_authority_claims() {
    let config = SorafsReputationRuntimeConfig {
        finalized_query_handle: Some("ledger.finalized.primary".to_owned()),
        ..SorafsReputationRuntimeConfig::default()
    };
    let mut emitter = Emitter::new();
    assert!(config.parse(false, None, &mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn disabled_policy_rejects_nondefault_finalized_archive_claims() {
    let mut config = SorafsReputationRuntimeConfig::default();
    config.finalized_archive_max_entries -= 1;
    let mut emitter = Emitter::new();
    assert!(config.parse(false, None, &mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
