// Current embedded-certificate capture, exact retention and restart qualification.
use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};

fn certified_reputation_chain() -> CertifiedTestChain {
    use iroha_data_model::{
        account::Account,
        asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId},
        isi::{
            Grant, Register,
            sorafs::{
                SetSorafsOrderbookPolicy, SetSorafsReputationJournalAuthorityPolicy,
                SetSorafsReservePolicy,
            },
        },
        sorafs::{
            orderbook::{ORDERBOOK_ADMISSION_POLICY_VERSION_V1, OrderbookAdmissionPolicyV1},
            reserve::{
                RESERVE_AUTHORITY_POLICY_VERSION_V1, ReserveAuthorityPolicyV1, ReservePolicyV1,
            },
        },
    };
    use iroha_executor_data_model::permission::sorafs::{
        CanManageSorafsReputationJournalPolicy, CanSetSorafsPricing, CanSetSorafsReservePolicy,
    };
    let mut config = TestChainConfig::new(crate::state::World::default(), 1_750_000_000_000);
    let authority = AccountId::new(config.genesis_key.public_key().clone());
    let policy = ReputationJournalAuthorityPolicyV1 {
        version: REPUTATION_JOURNAL_AUTHORITY_POLICY_VERSION_V1,
        revision: 1,
        predecessor_policy_digest: None,
        por_recorder_authority: authority.clone(),
        dispute_recorder_authority: authority.clone(),
        token_recorder_authority: authority.clone(),
        stream_token_delivery: iroha_data_model::sorafs::reputation::stream_token_delivery::StreamTokenReputationDeliveryTemplateV1::default(),
        max_source_age_ms: REPUTATION_JOURNAL_MAX_SOURCE_AGE_MS_V1,
    };
    config.genesis_instructions.extend([
        Grant::account_permission(CanManageSorafsReputationJournalPolicy, authority.clone()).into(),
        SetSorafsReputationJournalAuthorityPolicy::new(policy).into(),
        Grant::account_permission(CanSetSorafsPricing, authority.clone()).into(),
    ]);
    // Capture reads all governed feeds, including empty ones. Activate their real policies
    // through signed genesis so these tests exercise authoritative query validation.
    config.genesis_instructions.push(
        SetSorafsOrderbookPolicy::new(OrderbookAdmissionPolicyV1 {
            version: ORDERBOOK_ADMISSION_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            market_id: [0xA5; 32],
            matcher_authority: authority.clone(),
            settlement_authority: authority.clone(),
            paused: false,
            min_order_gib: 1,
            max_order_gib: 1024,
            price_tick_micro_xor: 10,
            max_maker_fee_bps: 100,
            max_taker_fee_bps: 200,
            max_order_lifetime_secs: 3600,
            max_receipt_age_secs: 300,
            max_clock_skew_secs: 5,
            max_receipt_bytes: 1024,
            max_receipts_per_channel: 2,
        })
        .into(),
    );
    let custody = iroha_test_samples::ALICE_ID.clone();
    let asset_id = AssetDefinitionId::derive_from_components(
        iroha_genesis::GENESIS_DOMAIN_ID.clone(),
        "reserve".parse().unwrap(),
    );
    config.genesis_instructions.extend([
        Register::account(Account::new(custody.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            asset_id.clone(),
            "Reserve".to_owned(),
            AssetBalancePolicy::Global,
            None,
        ))
        .into(),
        Grant::account_permission(CanSetSorafsReservePolicy, authority.clone()).into(),
        SetSorafsReservePolicy::new(ReserveAuthorityPolicyV1 {
            version: RESERVE_AUTHORITY_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            economics: ReservePolicyV1::default(),
            asset_definition: asset_id,
            custody_account: custody,
            treasury_account: authority.clone(),
            operations_authority: authority.clone(),
            decision_authority: authority,
            grace_period_days: 7,
            default_after_days: 30,
            max_provider_debt: sorafs_manifest::deal::XorQuantity::try_from_micro(1_000_000_000)
                .unwrap(),
            max_pending_movements_per_provider: 4,
            max_open_appeals_per_provider: 2,
        })
        .into(),
    ]);
    CertifiedTestChain::start(config).expect("current certified reputation chain")
}

#[test]
fn certified_capture_qualifies_genesis_and_successors_without_sidecars() {
    let mut chain = certified_reputation_chain();
    let directory = tempdir().unwrap();
    let archive = open_archive(&directory, bounds());
    let genesis = archive
        .reconcile_certified_state_tip(&chain.state().query_view(), chain.kura())
        .unwrap();
    assert_eq!(
        genesis.insertion,
        ReputationFinalizedArchiveInsertOutcome::Inserted
    );
    assert_eq!(genesis.qualification.archive_tip().height, 1);
    assert_eq!(
        archive
            .capture_certified_view(&chain.state().query_view(), chain.kura())
            .unwrap(),
        ReputationFinalizedArchiveInsertOutcome::ExactReplay
    );
    let generation = archive.health_generation().unwrap();
    chain.commit_at(1_750_000_000_100, Vec::new());
    assert!(matches!(
        archive.qualify_against_certified_tip(&chain.state().query_view(), chain.kura(), 0),
        Err(ReputationFinalizedArchiveError::ArchiveKuraTipLagExceeded { lag: 1, .. })
    ));
    let captured = archive
        .reconcile_certified_state_tip(&chain.state().query_view(), chain.kura())
        .unwrap();
    assert_eq!(captured.qualification.archive_tip().height, 2);
    assert_eq!(archive.health_generation().unwrap(), generation + 1);
    let foreign = Kura::blank_kura_for_testing();
    assert!(
        archive
            .capture_certified_view(&chain.state().query_view(), &foreign)
            .is_err()
    );
    assert_eq!(archive.health_generation().unwrap(), generation + 1);
    chain.commit_at(1_750_000_000_200, Vec::new());
    chain.commit_at(1_750_000_000_300, Vec::new());
    assert!(matches!(
        archive.capture_certified_view(&chain.state().query_view(), chain.kura()),
        Err(ReputationFinalizedArchiveError::ArchiveCoverageGap {
            missing_height: 3,
            ..
        })
    ));
    assert_eq!(archive.health_generation().unwrap(), generation + 1);
}

#[test]
fn certified_retention_ambiguous_cas_restart_and_successor_capture_preserve_exact_floor() {
    let mut chain = certified_reputation_chain();
    let directory = tempdir().unwrap();
    let archive = open_archive(&directory, bounds());
    let first = archive
        .reconcile_certified_state_tip(&chain.state().query_view(), chain.kura())
        .unwrap();
    chain.commit_at(1_750_000_000_100, Vec::new());
    let second = archive
        .reconcile_certified_state_tip(&chain.state().query_view(), chain.kura())
        .unwrap();
    let floor = first.qualification.archive_tip().clone();
    let fence = archive.retention_fence_for(&floor).unwrap();
    let proposal = archive
        .prepare_certified_compaction(&fence, &chain.state().query_view(), chain.kura())
        .unwrap();
    let authority = TestRetentionAuthority::new();
    authority.set_behavior(TestRetentionCasBehavior::ApplyAmbiguous);
    let binding = authority.binding();
    let installed = archive
        .approve_and_install_certified_compaction(
            &proposal,
            &chain.state().query_view(),
            chain.kura(),
            &binding,
            &authority,
        )
        .unwrap();
    assert_eq!(installed.retention_floor(), &floor);
    assert_eq!(installed.checkpoint_digest(), proposal.checkpoint_digest());
    assert_eq!(installed.pruned_anchors(), 1);
    assert_eq!(installed.generation(), archive.health_generation().unwrap());
    assert_eq!(
        archive.retention_floor(&chain.network_id()).unwrap(),
        Some(floor.clone())
    );
    assert_eq!(fs::read_dir(&archive.anchors).unwrap().count(), 1);
    let certified_id =
        *crate::sumeragi::certified_chain::CertifiedChain::new(&chain.state().query_view())
            .unwrap()
            .certified(1)
            .unwrap()
            .id()
            .0
            .as_ref();
    assert_eq!(
        archive
            .read_index()
            .unwrap()
            .checkpoints
            .get(&chain.network_id())
            .unwrap()
            .persisted
            .checkpoint
            .certified_block_id,
        certified_id
    );
    drop(archive);
    let archive = ReputationFinalizedArchive::try_open_with_retention_authority(
        archive_root(&directory),
        bounds(),
        &chain.network_id(),
        &chain.state().query_view(),
        chain.kura(),
        &binding,
        &authority,
    )
    .unwrap();
    assert_eq!(
        archive
            .qualify_against_certified_tip(&chain.state().query_view(), chain.kura(), 0)
            .unwrap()
            .archive_tip(),
        second.qualification.archive_tip()
    );
    assert_eq!(
        archive
            .capture_certified_view(&chain.state().query_view(), chain.kura())
            .unwrap(),
        ReputationFinalizedArchiveInsertOutcome::ExactReplay
    );
    chain.commit_at(1_750_000_000_200, Vec::new());
    archive
        .capture_certified_view(&chain.state().query_view(), chain.kura())
        .unwrap();
    assert_eq!(
        archive
            .qualify_against_certified_tip(&chain.state().query_view(), chain.kura(), 0)
            .unwrap()
            .archive_tip()
            .height,
        3
    );
    assert_eq!(
        archive.retention_floor(&chain.network_id()).unwrap(),
        Some(floor)
    );
    drop(archive);
    let reopened = ReputationFinalizedArchive::try_open_with_retention_authority(
        archive_root(&directory),
        bounds(),
        &chain.network_id(),
        &chain.state().query_view(),
        chain.kura(),
        &binding,
        &authority,
    )
    .unwrap();
    assert_eq!(
        reopened
            .qualify_against_certified_tip(&chain.state().query_view(), chain.kura(), 0)
            .unwrap()
            .archive_tip()
            .height,
        3
    );
}

#[test]
fn certified_qualification_rejects_corrupt_anchor_despite_warm_projection_cache() {
    let chain = certified_reputation_chain();
    let directory = tempdir().unwrap();
    let archive = open_archive(&directory, bounds());
    let captured = archive
        .reconcile_certified_state_tip(&chain.state().query_view(), chain.kura())
        .unwrap();
    let key = captured.qualification.archive_tip();
    assert!(archive.get_exact(key).unwrap().is_some());
    let path = archive.record_path(key).unwrap();
    fs::write(path, b"damaged certified reputation anchor").unwrap();
    assert!(
        archive
            .qualify_against_certified_tip(&chain.state().query_view(), chain.kura(), 0)
            .is_err()
    );
    assert!(
        archive
            .capture_certified_view(&chain.state().query_view(), chain.kura())
            .is_err()
    );
    drop(archive);
    assert!(ReputationFinalizedArchive::try_open(archive_root(&directory), bounds()).is_err());
}

#[test]
fn certified_capture_contention_returns_release_without_mutation_and_retries_exactly() {
    use std::{
        future::Future as _,
        pin::Pin,
        task::{Context, Waker},
    };
    let chain = certified_reputation_chain();
    let waiter_budget = chain.state().ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&waiter_budget);
    let directory = tempdir().unwrap();
    let archive = open_archive(&directory, bounds());
    let reader = archive.read_index().unwrap();
    let wait = match archive.capture_certified_view(&chain.state().query_view(), chain.kura()) {
        Err(ReputationFinalizedArchiveError::IndexBusy { wait }) => wait,
        other => panic!("capture must defer to the actual held reader: {other:?}"),
    };
    assert_eq!(reader.generation, 0);
    assert_eq!(fs::read_dir(&archive.anchors).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&archive.policies).unwrap().count(), 0);
    let mut released = wait.wait_for_release(&mut registration);
    let mut context = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut released).poll(&mut context).is_pending());
    drop(reader);
    assert!(Pin::new(&mut released).poll(&mut context).is_ready());
    let result = archive
        .reconcile_certified_state_tip(&chain.state().query_view(), chain.kura())
        .unwrap();
    let path = archive
        .record_path(result.qualification.archive_tip())
        .unwrap();
    let original = fs::read(&path).unwrap();
    assert_eq!(
        archive
            .capture_certified_view(&chain.state().query_view(), chain.kura())
            .unwrap(),
        ReputationFinalizedArchiveInsertOutcome::ExactReplay
    );
    assert_eq!(archive.health_generation().unwrap(), 1);
    assert_eq!(fs::read(path).unwrap(), original);
    drop(released);
    let with_registration = waiter_budget.reserved_bytes();
    drop(registration);
    assert_eq!(
        waiter_budget.reserved_bytes(),
        with_registration
            - iroha_allocation::release::ReleaseRegistration::allocation_layout().size()
    );
}

#[test]
fn retention_open_rejects_foreign_state_binding_before_creating_storage() {
    let chain = certified_reputation_chain();
    let directory = tempdir().unwrap();
    let root = archive_root(&directory).join("unopened");
    let authority = TestRetentionAuthority::new();
    let binding = authority.binding();
    let foreign = Kura::blank_kura_for_testing();
    for (network, kura) in [
        (network_id(0x71), chain.kura().as_ref()),
        (chain.network_id(), foreign.as_ref()),
    ] {
        assert!(matches!(
            ReputationFinalizedArchive::try_open_with_retention_authority(
                &root,
                bounds(),
                &network,
                &chain.state().query_view(),
                kura,
                &binding,
                &authority,
            ),
            Err(ReputationFinalizedArchiveError::FinalityAuthentication { .. })
        ));
        assert!(!root.exists());
    }
    assert_eq!(authority.load_count(), 0);
    assert_eq!(authority.cas_count(), 0);
}

#[test]
fn certified_capture_rebuilds_after_partial_io_with_identical_bytes_and_one_policy_charge() {
    let chain = certified_reputation_chain();
    let directory = tempdir().unwrap();
    let control_directory = tempdir().unwrap();
    let archive = open_archive(&directory, bounds());
    let control = open_archive(&control_directory, bounds());
    let expected = control
        .reconcile_certified_state_tip(&chain.state().query_view(), chain.kura())
        .unwrap();
    let key = expected.qualification.archive_tip();
    let expected_bytes = fs::read(control.record_path(key).unwrap()).unwrap();
    let expected_total = control.read_index().unwrap().total_bytes;
    let path = archive.record_path(key).unwrap();
    fs::create_dir(&path).unwrap();
    for _ in 0..2 {
        assert!(
            archive
                .capture_certified_view(&chain.state().query_view(), chain.kura())
                .is_err()
        );
        let index = archive.read_index().unwrap();
        assert_eq!(index.generation, 0);
        assert_eq!(index.anchor_count, 0);
        assert_eq!(index.policy_count, 1);
        let policies = fs::read_dir(&archive.policies).unwrap().collect::<Vec<_>>();
        assert_eq!(policies.len(), 1);
        let policy_size = policies[0].as_ref().unwrap().metadata().unwrap().len();
        assert_eq!(index.total_bytes, policy_size);
        assert_eq!(chain.height(), 1, "archive retry never reexecutes State");
    }
    fs::remove_dir(&path).unwrap();
    assert_eq!(
        archive
            .capture_certified_view(&chain.state().query_view(), chain.kura())
            .unwrap(),
        ReputationFinalizedArchiveInsertOutcome::Inserted
    );
    assert_eq!(fs::read(&path).unwrap(), expected_bytes);
    {
        let index = archive.read_index().unwrap();
        assert_eq!(index.generation, 1);
        assert_eq!(index.anchor_count, 1);
        assert_eq!(index.policy_count, 1);
        assert_eq!(index.total_bytes, expected_total);
    }
    assert_eq!(
        archive
            .capture_certified_view(&chain.state().query_view(), chain.kura())
            .unwrap(),
        ReputationFinalizedArchiveInsertOutcome::ExactReplay
    );
    assert_eq!(fs::read(&path).unwrap(), expected_bytes);
    drop(archive);
    let reopened = open_archive(&directory, bounds());
    assert_eq!(
        reopened
            .qualify_against_certified_tip(&chain.state().query_view(), chain.kura(), 0)
            .unwrap()
            .archive_tip(),
        key
    );
    assert_eq!(reopened.read_index().unwrap().total_bytes, expected_total);
}

#[test]
fn certified_capture_index_poison_is_storage_failure_without_publication() {
    let chain = certified_reputation_chain();
    let directory = tempdir().unwrap();
    let archive = open_archive(&directory, bounds());
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _writer = archive.index.write().unwrap();
            panic!("poison actual archive index writer");
        }))
        .is_err()
    );
    assert!(matches!(
        archive.capture_certified_view(&chain.state().query_view(), chain.kura()),
        Err(ReputationFinalizedArchiveError::InvalidStorage {
            reason: "archive index lock is poisoned",
            ..
        })
    ));
    assert!(matches!(
        archive.read_index(),
        Err(ReputationFinalizedArchiveError::InvalidStorage {
            reason: "archive index lock is poisoned",
            ..
        })
    ));
    assert_eq!(fs::read_dir(&archive.anchors).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&archive.policies).unwrap().count(), 0);
    assert_eq!(chain.height(), 1);
}
