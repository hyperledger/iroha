// Snapshot publication and restore against exact native execution history.
// Signed snapshot persistence and strict restored-state controls.

use iroha_data_model::parameter::{Parameter, system::SumeragiNposParameters};

#[tokio::test]
async fn creates_all_dirs_while_writing_snapshots() {
    let tmp_root = tempdir().unwrap();
    let snapshot_store_dir = tmp_root.path().join("path/to/snapshot/dir");
    let state = state_factory();
    let key_pair = checked_random_snapshot_keypair();
    try_write_snapshot(&state, &snapshot_store_dir, &key_pair, TEST_CHUNK_SIZE).unwrap();
    assert!(Path::exists(snapshot_store_dir.as_path()));
    assert_canonical_snapshot_generation(&snapshot_store_dir);
}
#[tokio::test]
async fn signed_snapshot_restore_keeps_configured_governance_catalog() {
    let tmp_root = tempdir().unwrap();
    let store_dir = tmp_root.path().join("snapshot");
    let mut state = state_factory();
    let mut configured_nexus = state.nexus_snapshot();
    configured_nexus.governance.modules.insert(
        "parliament".to_owned(),
        iroha_config::parameters::actual::GovernanceModule {
            module_type: Some("parliament_sortition_jit".to_owned()),
            ..Default::default()
        },
    );
    state
        .set_nexus_from_config(configured_nexus.clone())
        .expect("install the configured static governance catalog before snapshot");
    let key_pair = checked_random_snapshot_keypair();
    try_write_snapshot(&state, &store_dir, &key_pair, TEST_CHUNK_SIZE).unwrap();

    let restored = try_read_snapshot(
        &state.ivm_execution_budget(),
        &store_dir,
        &Kura::blank_kura_for_testing(),
        &state.lane_manifests.read().clone(),
        &configured_nexus,
        LiveQueryStore::start_test,
        BlockCount(state.view().height()),
        TEST_CHUNK_SIZE,
        key_pair.public_key(),
        &state.chain_id,
        &state.network_id,
        &crate::state::default_zk_config(),
        #[cfg(feature = "telemetry")]
        StateTelemetry::new(<_>::default(), true),
        &snapshot_read_budget_for_testing(),
    )
    .expect("signed restart must retain configured static governance before manifest binding");
    assert!(
        restored
            .nexus_snapshot()
            .governance
            .modules
            .contains_key("parliament"),
        "the snapshot's dynamic runtime cannot erase configured governance modules"
    );
    assert_eq!(
        canonical_state_snapshot_bytes_for_tests(&restored),
        canonical_state_snapshot_bytes_for_tests(&state),
    );
}

#[tokio::test]
async fn signed_snapshot_restore_accepts_configured_governed_lane() {
    let tmp_root = tempdir().unwrap();
    let manifest_dir = tmp_root.path().join("manifests");
    std::fs::create_dir(&manifest_dir).unwrap();
    std::fs::write(
        manifest_dir.join("governed.manifest.json"),
        r#"{"lane":"governed","governance":"parliament","version":1}"#,
    )
    .unwrap();
    let mut configured_nexus = iroha_config::parameters::actual::Nexus::default();
    let governed_lane = ModelLaneConfig {
        id: LaneId::new(1),
        alias: "governed".to_owned(),
        governance: Some("parliament".to_owned()),
        ..ModelLaneConfig::default()
    };
    configured_nexus.lane_catalog = LaneCatalog::new(
        nonzero!(2_u32),
        vec![ModelLaneConfig::default(), governed_lane],
    )
    .unwrap();
    configured_nexus.configured_lane_catalog = configured_nexus.lane_catalog.clone();
    configured_nexus.lane_config = LaneConfig::from_catalog(&configured_nexus.lane_catalog);
    configured_nexus.governance.modules.insert(
        "parliament".to_owned(),
        iroha_config::parameters::actual::GovernanceModule {
            module_type: Some("parliament_sortition_jit".to_owned()),
            ..Default::default()
        },
    );
    configured_nexus.registry.manifest_directory = Some(manifest_dir);

    let kura_config =
        kura_config_for_snapshot_test(&tmp_root.path().join("kura"), nonzero!(1_usize));
    let (kura, block_count) = Kura::new_with_configured_lane_catalog(
        &kura_config,
        &configured_nexus.lane_config,
        &configured_nexus.configured_lane_catalog,
    )
    .expect("open exact configured lane geometry");
    let mut world = crate::queue::tests::world_with_test_domains();
    crate::sns::try_seed_default_namespace_policies(
        &mut world,
        &configured_nexus.fees.fee_asset_id,
    )
    .unwrap();
    let mut state = State::try_new_with_chain_and_network_id(
        iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        world,
        Arc::clone(&kura),
        LiveQueryStore::start_test(),
        ChainId::from(TEST_CHAIN_ID),
        snapshot_test_network_id(),
        #[cfg(feature = "telemetry")]
        StateTelemetry::default(),
    )
    .expect("construct the pre-genesis State");
    let manifests = Arc::new(
        crate::governance::manifest::LaneManifestRegistry::from_config(
            &configured_nexus.configured_lane_catalog,
            &configured_nexus.governance,
            &configured_nexus.registry,
        ),
    );
    manifests
        .validate_active_coverage_for_catalog(&configured_nexus.lane_catalog)
        .expect("governed lane has a frozen matching source");
    state.install_lane_manifests_for_testing(&manifests);
    state
        .prepare_configured_primary_geometry_anchor(&configured_nexus.configured_lane_catalog)
        .unwrap();
    state
        .restore_kura_lane_segments_before_startup_replay()
        .unwrap();
    state
        .set_nexus_from_config(configured_nexus.clone())
        .unwrap();
    state.install_active_lane_markers_for_tests();
    state.configure_test_runtime_defaults();
    let store_dir = tmp_root.path().join("snapshot");
    let key_pair = checked_random_snapshot_keypair();
    try_write_snapshot(&state, &store_dir, &key_pair, TEST_CHUNK_SIZE)
        .expect("write a signed snapshot with an active governed lane");

    let restored = try_read_snapshot(
        &state.ivm_execution_budget(),
        &store_dir,
        &kura,
        &manifests,
        &configured_nexus,
        LiveQueryStore::start_test,
        block_count,
        TEST_CHUNK_SIZE,
        key_pair.public_key(),
        state.chain_id_ref(),
        state.network_id_ref(),
        &crate::state::default_zk_config(),
        #[cfg(feature = "telemetry")]
        StateTelemetry::default(),
        &snapshot_read_budget_for_testing(),
    )
    .expect("signed restore must rebind the governed lane from configured policy");
    restored
        .lane_manifests
        .read()
        .validate_active_coverage_for_catalog(&configured_nexus.lane_catalog)
        .expect("restored governed lane remains ready");
    assert_eq!(
        canonical_state_snapshot_bytes_for_tests(&restored),
        canonical_state_snapshot_bytes_for_tests(&state),
    );

    let mut missing_governance = configured_nexus.clone();
    missing_governance.governance.modules.clear();
    assert!(
        try_read_snapshot(
            &state.ivm_execution_budget(),
            &store_dir,
            &kura,
            &manifests,
            &missing_governance,
            LiveQueryStore::start_test,
            block_count,
            TEST_CHUNK_SIZE,
            key_pair.public_key(),
            state.chain_id_ref(),
            state.network_id_ref(),
            &crate::state::default_zk_config(),
            #[cfg(feature = "telemetry")]
            StateTelemetry::default(),
            &snapshot_read_budget_for_testing(),
        )
        .is_err(),
        "a local configuration missing the governed module must fail closed"
    );
}

#[tokio::test]
async fn can_read_snapshot_after_writing() {
    let tmp_root = tempdir().unwrap();
    let store_dir = tmp_root.path().join("snapshot");
    let state = state_factory();
    let key_pair = checked_random_snapshot_keypair();
    let expected_chain_id = state.chain_id.clone();
    try_write_snapshot(&state, &store_dir, &key_pair, TEST_CHUNK_SIZE).unwrap();
    let kura = Kura::blank_kura_for_testing();
    let snapshot_state = try_read_snapshot(
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        &store_dir,
        &kura,
        &state.lane_manifests.read().clone(),
        &state.nexus_snapshot(),
        LiveQueryStore::start_test,
        BlockCount(state.view().height()),
        TEST_CHUNK_SIZE,
        key_pair.public_key(),
        &state.chain_id,
        &state.network_id,
        &crate::state::default_zk_config(),
        #[cfg(feature = "telemetry")]
        StateTelemetry::new(<_>::default(), true),
        &snapshot_read_budget_for_testing(),
    )
    .unwrap();
    assert_eq!(snapshot_state.chain_id, expected_chain_id);
    assert_eq!(
        canonical_state_snapshot_bytes_for_tests(&snapshot_state),
        canonical_state_snapshot_bytes_for_tests(&state),
        "snapshot roundtrip must preserve canonical WSV bytes"
    );
}
#[tokio::test]
async fn normal_snapshot_restore_rejects_overdue_pending_consensus_evidence() {
    let tmp_root = tempdir().expect("snapshot tempdir");
    let store_dir = tmp_root.path().join("snapshot");
    use crate::sumeragi::test_chain::{CertifiedTestChain, Signers, TestChainConfig};
    use iroha_data_model::parameter::system::SumeragiConsensusMode;
    use iroha_sumeragi::{message::Evidence as NativeEvidence, types::Hash32};
    let mut config = TestChainConfig::new(crate::state::World::new(), 1_000);
    config.consensus_mode = SumeragiConsensusMode::Npos;
    config.genesis_parameters.push(Parameter::Custom(
        SumeragiNposParameters {
            slashing_delay_blocks: 2,
            ..SumeragiNposParameters::default()
        }
        .into_custom_parameter(),
    ));
    let mut chain = CertifiedTestChain::start(config).expect("actual signed native genesis");
    chain.commit(Vec::new());
    let native = NativeEvidence::ConflictingCertificates(
        chain.commit_qc(2, Hash32([0x31; 32]), Hash32([0x32; 32]), Signers::Quorum),
        chain.commit_qc(
            2,
            Hash32([0x33; 32]),
            Hash32([0x34; 32]),
            Signers::LastThree,
        ),
    );
    let evidence = Evidence::from_native(&native).unwrap();
    let evidence_key = crate::sumeragi::evidence::evidence_key(&evidence);
    crate::sumeragi::evidence::observe(chain.state(), &native).unwrap();
    chain.commit(Vec::new()); // H3 contains the actual original admission.
    chain.commit(Vec::new());
    chain.commit(Vec::new()); // H5 contains the actual finality-authorized marker.
    let state = chain.state();
    crate::sumeragi::evidence::validate_persisted_records(&state)
        .expect("original authenticated history and lifecycle");
    let original_tip = *state.view().native_execution_tip.get();
    {
        let mut records = state.world.consensus_evidence.block();
        let mut record = records.get(&evidence_key).unwrap().clone();
        assert_eq!(record.recorded_at_height, 3);
        assert_eq!(
            record.penalty_status,
            EvidencePenaltyStatus::Applied { height: 5 }
        );
        record.penalty_status = EvidencePenaltyStatus::Pending;
        records.insert(evidence_key, record);
        records.commit();
    }
    assert_eq!(
        *state.view().native_execution_tip.get(),
        original_tip,
        "negative snapshot mutation must not replace original native history"
    );
    let invalid_lifecycle = crate::sumeragi::evidence::validate_persisted_records(&state)
        .expect_err("an overdue restored pending penalty must be rejected");
    assert!(
        invalid_lifecycle
            .to_string()
            .contains("restored penalty lifecycle is impossible")
    );
    let snapshot_bytes = exact_snapshot_payload_bytes(state);
    let key_pair = checked_random_snapshot_keypair();
    write_snapshot_bundle_from_bytes(&store_dir, &snapshot_bytes, &key_pair);
    let kura = chain.kura();
    let error = match try_read_snapshot(
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        &store_dir,
        kura,
        &state.lane_manifests.read().clone(),
        &state.nexus_snapshot(),
        LiveQueryStore::start_test,
        BlockCount(state.view().height()),
        TEST_CHUNK_SIZE,
        key_pair.public_key(),
        state.chain_id_ref(),
        state.network_id_ref(),
        &crate::state::default_zk_config(),
        #[cfg(feature = "telemetry")]
        StateTelemetry::new(<_>::default(), true),
        &snapshot_read_budget_for_testing(),
    ) {
        Ok(_) => panic!("normal snapshot restore must reject overdue pending evidence"),
        Err(error) => error,
    };
    assert!(
        matches!(error, TryReadError::NativeExecutionReplayRequired),
        "a local export cannot bypass original replay even before lifecycle validation: {error:?}"
    );
}
#[tokio::test]
async fn generated_snapshot_passes_restart_validation_before_publication() {
    let state = state_factory();
    let snapshot_bytes = exact_snapshot_payload_bytes(&state);
    let snapshot: json::Value =
        json::from_slice(&snapshot_bytes).expect("writer snapshot must be canonical JSON");
    let json::Value::Object(snapshot) = snapshot else {
        panic!("writer snapshot must be an object");
    };
    for field in ["commit_topology", "prev_commit_topology"] {
        let Some(json::Value::Object(cell)) = snapshot.get(field) else {
            panic!("{field} must retain its exact MV cell envelope");
        };
        assert_eq!(cell.len(), 2, "{field} must retain exactly two MV roles");
        assert!(cell.contains_key("revert") && cell.contains_key("blocks"));
    }
    validate_generated_snapshot_for_restart(&state, &snapshot_bytes)
        .expect("writer-generated snapshot must survive restart initialization exactly");
}
#[tokio::test]
async fn canonical_account_metadata_survives_the_snapshot_restart_boundary() {
    let state = state_factory();
    let owner = state
        .world
        .accounts
        .view()
        .iter()
        .next()
        .map(|(account_id, _)| account_id.clone())
        .expect("snapshot fixture account");
    let key = "snapshot_probe".parse().expect("metadata key");
    let value = Json::from_raw_json("1".to_owned()).expect("canonical JSON spelling");
    assert_eq!(value.get(), "1");
    let mut accounts = state.world.accounts.block();
    accounts
        .get_mut(&owner)
        .expect("snapshot fixture account remains registered")
        .insert(key, value);
    accounts.commit();
    let snapshot_bytes = exact_snapshot_payload_bytes(&state);
    validate_generated_snapshot_for_restart(&state, &snapshot_bytes)
        .expect("canonical ledger Json must round-trip through restart reconstruction");
    let snapshot_text = core::str::from_utf8(&snapshot_bytes).expect("snapshot is UTF-8 JSON");
    assert!(
        snapshot_text.contains(r#""snapshot_probe":1"#),
        "snapshot must contain only the canonical metadata spelling"
    );
}
#[tokio::test]
async fn noncanonical_snapshot_publishes_and_compacts_nothing() {
    let tmp_root = tempdir().expect("snapshot tempdir");
    let store_dir = tmp_root.path().join("snapshot");
    let kura_store_dir = tmp_root.path().join("kura");
    let initial_catalog = LaneCatalog::default();
    let extended_catalog = LaneCatalog::new(
        nonzero!(2_u32),
        vec![
            ModelLaneConfig::default(),
            ModelLaneConfig {
                id: LaneId::new(1),
                alias: "snapshot-validation-secondary".to_owned(),
                ..ModelLaneConfig::default()
            },
        ],
    )
    .expect("extended lane catalog");
    let initial = LaneConfig::from_catalog(&initial_catalog);
    let extended = LaneConfig::from_catalog(&extended_catalog);
    let kura_config = kura_config_for_snapshot_test(&kura_store_dir, nonzero!(1_usize));
    let (kura, _) = Kura::open_test_kura_with_configured_lane_config(&kura_config, &initial)
        .expect("create persistent Kura");
    let state = state_factory_with_kura(Arc::clone(&kura));
    let initial_incarnations = state.lane_incarnations_snapshot();
    let extended_incarnations = BTreeMap::from([
        (LaneId::SINGLE, initial_incarnations[&LaneId::SINGLE]),
        (LaneId::new(1), Hash::new(b"snapshot-validation-secondary")),
    ]);
    let initial_activations = BTreeMap::from([(LaneId::SINGLE, 0)]);
    let extended_activations = BTreeMap::from([(LaneId::SINGLE, 0), (LaneId::new(1), 0)]);
    kura.apply_lane_geometry_transition_at_height(
        &initial,
        &extended,
        &initial_incarnations,
        &extended_incarnations,
        &initial_activations,
        &extended_activations,
        &BTreeSet::new(),
        0,
    )
    .expect("seed recoverable geometry transition");
    kura.mark_lane_geometry_catalog_published(
        &extended,
        &extended_incarnations,
        &extended_activations,
        None,
    )
    .expect("publish recoverable geometry transition");
    let journal_before = kura
        .lane_geometry_journal_state_for_test()
        .expect("read geometry journal before rejected snapshot");
    let journal_bytes_before = std::fs::read(kura.lane_geometry_journal_path())
        .expect("read exact geometry journal before rejected snapshot");
    assert_eq!(journal_before.1, vec!["catalog_published"]);
    let mut noncanonical = exact_snapshot_payload_bytes(&state);
    noncanonical.insert(1, b' ');
    let key_pair = checked_random_snapshot_keypair();
    let error = try_write_snapshot_payload_with_limit(
        &state,
        &store_dir,
        &key_pair,
        TEST_CHUNK_SIZE,
        iroha_config::parameters::defaults::snapshot::MAX_PAYLOAD_BYTES,
        noncanonical,
    )
    .expect_err("noncanonical payload must fail before publication");
    assert!(matches!(
        error,
        TryWriteError::RestartValidation(TryReadError::NonCanonicalSnapshotPayload)
    ));
    assert!(
        !store_dir.exists(),
        "restart validation must precede creation of snapshot publication artifacts"
    );
    assert_eq!(
        kura.lane_geometry_journal_state_for_test()
            .expect("read geometry journal after rejected snapshot"),
        journal_before,
        "rejected payload must not compact or otherwise rewrite geometry recovery history"
    );
    assert_eq!(
        std::fs::read(kura.lane_geometry_journal_path())
            .expect("read exact geometry journal after rejected snapshot"),
        journal_bytes_before,
        "rejected payload must preserve exact durable geometry journal bytes"
    );
}
#[tokio::test]
async fn signed_snapshot_restore_preserves_ordered_election_corpus_and_rollback() {
    let tmp_root = tempdir().expect("snapshot tempdir");
    let store_dir = tmp_root.path().join("snapshot");
    let mut state = state_factory();
    let election_id = "ordered-ballot-corpus";
    let first = crate::state::StandaloneBallotCorpusEntryV1 {
        nullifier: [0x11; 32],
        commitment: [0xa1; 32],
    };
    let second = crate::state::StandaloneBallotCorpusEntryV1 {
        nullifier: [0x22; 32],
        commitment: [0xb2; 32],
    };
    let previous = crate::state::ElectionState {
        options: 2,
        start_ts: 10,
        end_ts: 20,
        tally: vec![0, 0],
        accepted_ballots: vec![first],
        ..crate::state::ElectionState::default()
    };
    let mut current = previous.clone();
    current.accepted_ballots.push(second);
    assert!(
        state
            .world
            .elections
            .insert(election_id.to_owned(), previous)
            .is_none()
    );
    {
        let mut elections = state.world.elections.block();
        assert!(elections.insert(election_id.to_owned(), current).is_some());
        elections.commit();
    }

    let key_pair = checked_random_snapshot_keypair();
    try_write_snapshot(&state, &store_dir, &key_pair, TEST_CHUNK_SIZE)
        .expect("write generated signed snapshot with both election views");
    assert_canonical_snapshot_generation(&store_dir);
    let payload = std::fs::read(current_generation_artifact(&store_dir, SNAPSHOT_FILE_NAME))
        .expect("read generated signed snapshot payload");
    let restored = try_read_snapshot(
        &state.ivm_execution_budget(),
        &store_dir,
        &Kura::blank_kura_for_testing(),
        &state.lane_manifests.read().clone(),
        &state.nexus_snapshot(),
        LiveQueryStore::start_test,
        BlockCount(state.view().height()),
        TEST_CHUNK_SIZE,
        key_pair.public_key(),
        &state.chain_id,
        &state.network_id,
        &crate::state::default_zk_config(),
        #[cfg(feature = "telemetry")]
        StateTelemetry::new(<_>::default(), true),
        &snapshot_read_budget_for_testing(),
    )
    .expect("verify signed snapshot and restore both typed election views");
    assert_eq!(
        CapturedStateSnapshot::capture(&restored)
            .expect("capture restored typed state")
            .json
            .as_bytes(),
        payload,
        "typed restore must preserve the generated signed payload exactly"
    );
    assert_eq!(
        restored
            .world
            .elections
            .view()
            .get(election_id)
            .expect("restored current election")
            .accepted_ballots,
        vec![first, second],
        "current view must preserve accepted operation order"
    );
    let rollback = restored.world.elections.block_and_revert();
    assert_eq!(
        rollback
            .get(election_id)
            .expect("restored previous election")
            .accepted_ballots,
        vec![first],
        "rollback view must retain only the previously accepted pair"
    );
    rollback.commit();
    assert_eq!(
        restored
            .world
            .elections
            .view()
            .get(election_id)
            .expect("election after rollback")
            .accepted_ballots,
        vec![first],
        "readback after committed rollback must match the previous view"
    );
}

#[tokio::test]
async fn signed_snapshot_roundtrip_preserves_authoritative_alias_revert_maps() {
    let tmp_root = tempdir().expect("snapshot tempdir");
    let store_dir = tmp_root.path().join("snapshot");
    let state = state_factory();
    let owner = {
        let accounts = state.world.accounts.view();
        accounts
            .iter()
            .next()
            .map(|(account_id, _)| account_id.clone())
            .expect("fixture account")
    };
    let account_alias = AccountAlias::new(
        "restart_alias".parse().expect("account alias label"),
        Some(AccountAliasDomain::new(
            "wonderland".parse().expect("account alias domain"),
        )),
        DataSpaceId::UNIVERSAL,
    );
    let account_rekey_record = AccountRekeyRecord::new(account_alias.clone(), owner.clone());
    {
        let mut aliases = state.world.account_aliases.block();
        assert!(
            aliases
                .insert(account_alias.clone(), owner.clone())
                .is_none()
        );
        aliases.commit();
    }
    {
        let mut records = state.world.account_rekey_records.block();
        assert!(
            records
                .insert(account_alias.clone(), account_rekey_record)
                .is_none()
        );
        records.commit();
    }
    {
        let mut records_by_account = state.world.account_rekey_records_by_account.block();
        assert!(
            records_by_account
                .insert(
                    owner.clone(),
                    std::collections::BTreeSet::from([account_alias.clone()]),
                )
                .is_none()
        );
        records_by_account.commit();
    }
    let definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").expect("asset domain"),
        "restart_asset".parse().expect("asset name"),
    );
    let definition = AssetDefinition::numeric(
        definition_id.clone(),
        "restart asset".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&owner);
    let definition_alias: AssetDefinitionAlias =
        "restart_asset#universal".parse().expect("asset alias");
    let definition_binding = AssetDefinitionAliasBindingRecord {
        alias: definition_alias,
        lease_expiry_ms: None,
        grace_until_ms: None,
        bound_at_ms: 1,
    };
    {
        let mut definitions = state.world.asset_definitions.block();
        assert!(
            definitions
                .insert(definition_id.clone(), definition)
                .is_none()
        );
        definitions.commit();
    }
    let registration_header =
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new([b'h', 0xA5]));
    let incarnation = iroha_data_model::nexus::AxtAssetIncarnationV1::derive(
        &state.network_id,
        &definition_id,
        &registration_header,
        &Hash::new([b'e', 0xA5]),
        0,
    );
    {
        let mut incarnations = state.world.axt_asset_incarnations.block();
        assert!(
            incarnations
                .insert(definition_id.clone(), incarnation)
                .is_none()
        );
        incarnations.commit();
    }
    {
        let mut bindings = state.world.asset_definition_alias_bindings.block();
        assert!(
            bindings
                .insert(definition_id.clone(), definition_binding)
                .is_none()
        );
        bindings.commit();
    }
    let contract_address = ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .expect("canonical test network id"),
        &owner,
        17,
        DataSpaceId::UNIVERSAL,
    )
    .expect("contract address");
    let contract_alias: ContractAlias =
        "restart_router::universal".parse().expect("contract alias");
    let contract_binding = ContractAliasBindingRecord {
        alias: contract_alias,
        lease_expiry_ms: None,
        grace_until_ms: None,
        bound_at_ms: 1,
    };
    {
        let mut bindings = state.world.contract_alias_bindings.block();
        assert!(
            bindings
                .insert(contract_address.clone(), contract_binding)
                .is_none()
        );
        bindings.commit();
    }
    let key_pair = checked_random_snapshot_keypair();
    try_write_snapshot(&state, &store_dir, &key_pair, TEST_CHUNK_SIZE)
        .expect("write signed snapshot with authoritative alias revert maps");
    let payload = std::fs::read(current_generation_artifact(&store_dir, SNAPSHOT_FILE_NAME))
        .expect("read signed snapshot payload");
    let kura = Kura::blank_kura_for_testing();
    let restored = try_read_snapshot(
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        &store_dir,
        &kura,
        &state.lane_manifests.read().clone(),
        &state.nexus_snapshot(),
        LiveQueryStore::start_test,
        BlockCount(0),
        TEST_CHUNK_SIZE,
        key_pair.public_key(),
        &state.chain_id,
        &state.network_id,
        &crate::state::default_zk_config(),
        #[cfg(feature = "telemetry")]
        StateTelemetry::new(<_>::default(), true),
        &snapshot_read_budget_for_testing(),
    )
    .expect("read signed snapshot without canonical payload drift");
    let roundtrip = CapturedStateSnapshot::capture(&restored)
        .expect("stable valid fixture snapshot")
        .json;
    assert_eq!(
        roundtrip.as_bytes(),
        payload,
        "restoring derived alias indexes must not alter authoritative snapshot bytes"
    );
    let aliases = restored.world.account_aliases.block_and_revert();
    assert!(aliases.get(&account_alias).is_none());
    aliases.commit();
    let aliases_by_account = restored.world.account_aliases_by_account.block_and_revert();
    assert!(
        !aliases_by_account
            .get(&owner)
            .is_some_and(|aliases| aliases.contains(&account_alias)),
        "restored reverse alias index must revert with its authoritative binding"
    );
    aliases_by_account.commit();
    let records = restored.world.account_rekey_records.block_and_revert();
    assert!(records.get(&account_alias).is_none());
    records.commit();
    let records_by_account = restored
        .world
        .account_rekey_records_by_account
        .block_and_revert();
    assert!(records_by_account.is_empty());
    records_by_account.commit();
    let definitions = restored.world.asset_definitions.block_and_revert();
    assert!(definitions.get(&definition_id).is_none());
    definitions.commit();
    let incarnations = restored.world.axt_asset_incarnations.block_and_revert();
    assert!(incarnations.get(&definition_id).is_none());
    incarnations.commit();
    let definition_bindings = restored
        .world
        .asset_definition_alias_bindings
        .block_and_revert();
    assert!(definition_bindings.get(&definition_id).is_none());
    definition_bindings.commit();
    let contract_bindings = restored.world.contract_alias_bindings.block_and_revert();
    assert!(contract_bindings.get(&contract_address).is_none());
    contract_bindings.commit();
}
#[tokio::test]
async fn signed_snapshot_rejects_unknown_root_and_world_fields() {
    for (scope, field_name, expected_field) in [
        (
            "root",
            "future_snapshot_field",
            "state.future_snapshot_field",
        ),
        ("world", "sccp_registry", "world.sccp_registry"),
        ("world", "commit_qcs", "world.commit_qcs"),
    ] {
        let tmp_root = tempdir().expect("temporary snapshot root");
        let store_dir = tmp_root.path().join("snapshot");
        let kura = Kura::blank_kura_for_testing();
        let state = state_factory_with_kura(Arc::clone(&kura));
        let mut serialized = CapturedStateSnapshot::capture(&state)
            .expect("stable valid fixture snapshot")
            .json;
        let mut snapshot: json::Value =
            json::from_str(&serialized).expect("valid baseline snapshot JSON");
        let json::Value::Object(snapshot_object) = &mut snapshot else {
            panic!("snapshot root must be an object");
        };
        match scope {
            "root" => {
                assert!(
                    snapshot_object
                        .insert(field_name.to_owned(), json::Value::Null,)
                        .is_none()
                );
            }
            "world" => {
                let Some(json::Value::Object(world)) = snapshot_object.get_mut("world") else {
                    panic!("snapshot world must be an object");
                };
                assert!(
                    world
                        .insert(field_name.to_owned(), json::Value::Null)
                        .is_none()
                );
            }
            _ => unreachable!("closed test scope"),
        }
        serialized = snapshot_json_with_mutation(&serialized, &snapshot);
        let key_pair = checked_random_snapshot_keypair();
        write_snapshot_bundle_from_bytes(&store_dir, serialized.as_bytes(), &key_pair);
        let error = match try_read_snapshot(
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            &store_dir,
            &kura,
            &state.lane_manifests.read().clone(),
            &state.nexus_snapshot(),
            LiveQueryStore::start_test,
            BlockCount(0),
            TEST_CHUNK_SIZE,
            key_pair.public_key(),
            &state.chain_id,
            &state.network_id,
            &crate::state::default_zk_config(),
            #[cfg(feature = "telemetry")]
            StateTelemetry::new(<_>::default(), true),
            &snapshot_read_budget_for_testing(),
        ) {
            Ok(_) => panic!("signed snapshot with an unknown field must fail closed"),
            Err(error) => error,
        };
        match error {
            TryReadError::Serialization(json::Error::InvalidField { field, message }) => {
                assert_eq!(field, expected_field);
                assert!(message.contains("unknown field"), "{message}");
            }
            other => panic!("unexpected unknown-field rejection: {other:?}"),
        }
    }
}
#[tokio::test]
async fn signed_native_snapshot_caches_and_tampered_accounts_require_original_replay() {
    use crate::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    let key_pair = checked_random_snapshot_keypair();
    let mut hostile = state_factory();
    let injected_account = AccountId::new(
        checked_seeded_keypair(0xD1, Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    hostile.world.accounts.insert(
        injected_account,
        AccountValue::new(AccountDetails::new(
            Metadata::default(),
            None,
            None,
            Vec::new(),
        )),
    );
    let hostile_json: json::Value =
        json::from_slice(&exact_snapshot_payload_bytes(&hostile)).unwrap();
    let hostile_accounts = hostile_json
        .as_object()
        .unwrap()
        .get("world")
        .unwrap()
        .as_object()
        .unwrap()
        .get("accounts")
        .unwrap()
        .clone();
    for height in [1, 2] {
        if height == 2 {
            chain.commit(Vec::new());
        }
        let state = chain.state();
        let kura = chain.kura();
        let captured = CapturedStateSnapshot::capture(state).unwrap();
        let mut mutated: json::Value = json::from_str(&captured.json).unwrap();
        mutated
            .as_object_mut()
            .unwrap()
            .get_mut("world")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("accounts".into(), hostile_accounts.clone());
        let mutated = json::to_json(&mutated).unwrap();
        assert_ne!(
            canonical_snapshot_wsv_hash(captured.json.as_bytes()).unwrap(),
            canonical_snapshot_wsv_hash(mutated.as_bytes()).unwrap()
        );
        let original_hash = kura.block_hash_at_height(NonZeroUsize::new(height).unwrap());
        let original_body =
            std::fs::read(Kura::canonical_storage_path(&kura.store_root()).join("blocks.data"))
                .unwrap();
        for serialized in [&captured.json, &mutated] {
            let tmp_root = tempdir().unwrap();
            let store_dir = tmp_root.path().join("snapshot");
            write_snapshot_bundle_from_bytes(&store_dir, serialized.as_bytes(), &key_pair);
            let result = try_read_snapshot(
                &iroha_allocation::AllocationBudget::new(
                    iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
                ),
                &store_dir,
                kura,
                &state.lane_manifests.read().clone(),
                &state.nexus_snapshot(),
                LiveQueryStore::start_test,
                BlockCount(height),
                TEST_CHUNK_SIZE,
                key_pair.public_key(),
                &state.chain_id,
                &state.network_id,
                &state.zk_snapshot(),
                #[cfg(feature = "telemetry")]
                StateTelemetry::new(<_>::default(), true),
                &snapshot_read_budget_for_testing(),
            );
            assert!(matches!(
                result,
                Err(TryReadError::NativeExecutionReplayRequired)
            ));
            assert_eq!(kura.blocks_count(), height);
            assert_eq!(kura.exact_durable_blocks_count().unwrap(), height);
            assert_eq!(
                kura.block_hash_at_height(NonZeroUsize::new(height).unwrap()),
                original_hash
            );
            assert_eq!(
                std::fs::read(Kura::canonical_storage_path(&kura.store_root()).join("blocks.data"))
                    .unwrap(),
                original_body
            );
        }
    }
}
#[tokio::test]
async fn snapshot_write_signature_file_uses_checked_signing_and_verifies_digest() {
    let tmp_root = tempdir().unwrap();
    let store_dir = tmp_root.path().join("snapshot");
    let state = state_factory();
    let key_pair = checked_random_snapshot_keypair();
    try_write_snapshot(&state, &store_dir, &key_pair, TEST_CHUNK_SIZE).expect("snapshot write");
    let bundle_digest = current_snapshot_bundle_auth_digest(&store_dir);
    let signature_hex = std::fs::read_to_string(current_generation_artifact(
        &store_dir,
        SNAPSHOT_SIGNATURE_FILE_NAME,
    ))
    .expect("snapshot signature");
    let signature = Signature::try_from_hex(signature_hex.trim()).expect("snapshot signature hex");
    signature
        .verify(key_pair.public_key(), &bundle_digest)
        .expect("checked snapshot signature must verify");
}
#[tokio::test]
async fn snapshot_read_rejects_wrong_key_signature_for_matching_digest() {
    let tmp_root = tempdir().unwrap();
    let store_dir = tmp_root.path().join("snapshot");
    let state = state_factory();
    let key_pair = checked_random_snapshot_keypair();
    try_write_snapshot(&state, &store_dir, &key_pair, TEST_CHUNK_SIZE).expect("snapshot write");
    let bundle_digest = current_snapshot_bundle_auth_digest(&store_dir);
    let wrong_key_pair = checked_random_snapshot_keypair();
    let wrong_signature = Signature::try_new(wrong_key_pair.private_key(), &bundle_digest)
        .expect("checked wrong-key snapshot signature");
    std::fs::write(
        current_generation_artifact(&store_dir, SNAPSHOT_SIGNATURE_FILE_NAME),
        hex::encode(wrong_signature.payload()),
    )
    .expect("replace snapshot signature");
    let Err(error) = try_read_snapshot(
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        &store_dir,
        &Kura::blank_kura_for_testing(),
        &state.lane_manifests.read().clone(),
        &state.nexus_snapshot(),
        LiveQueryStore::start_test,
        BlockCount(state.view().height()),
        TEST_CHUNK_SIZE,
        key_pair.public_key(),
        &state.chain_id,
        &state.network_id,
        &crate::state::default_zk_config(),
        #[cfg(feature = "telemetry")]
        StateTelemetry::default(),
        &snapshot_read_budget_for_testing(),
    ) else {
        panic!("snapshot with wrong-key signature should be rejected")
    };
    assert!(matches!(error, TryReadError::SignatureInvalid(_)));
}
#[tokio::test]
async fn snapshot_read_rejects_noncanonical_uppercase_signature_hex() {
    let tmp_root = tempdir().unwrap();
    let store_dir = tmp_root.path().join("snapshot");
    let state = state_factory();
    let key_pair = checked_random_snapshot_keypair();
    try_write_snapshot(&state, &store_dir, &key_pair, TEST_CHUNK_SIZE).expect("snapshot write");
    let signature_path = current_generation_artifact(&store_dir, SNAPSHOT_SIGNATURE_FILE_NAME);
    let signature_hex = std::fs::read_to_string(&signature_path).expect("signature hex");
    std::fs::write(&signature_path, signature_hex.to_ascii_uppercase())
        .expect("replace signature with equivalent noncanonical hex");
    let Err(error) = try_read_snapshot(
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        &store_dir,
        &Kura::blank_kura_for_testing(),
        &state.lane_manifests.read().clone(),
        &state.nexus_snapshot(),
        LiveQueryStore::start_test,
        BlockCount(state.view().height()),
        TEST_CHUNK_SIZE,
        key_pair.public_key(),
        &state.chain_id,
        &state.network_id,
        &crate::state::default_zk_config(),
        #[cfg(feature = "telemetry")]
        StateTelemetry::default(),
        &snapshot_read_budget_for_testing(),
    ) else {
        panic!("uppercase signature hex must not be accepted");
    };
    assert!(matches!(error, TryReadError::SignatureMalformed(_)));
}
#[tokio::test]
async fn snapshot_read_rejects_all_zero_signature_sidecar_before_verification() {
    let tmp_root = tempdir().unwrap();
    let store_dir = tmp_root.path().join("snapshot");
    let state = state_factory();
    let key_pair = checked_random_snapshot_keypair();
    try_write_snapshot(&state, &store_dir, &key_pair, TEST_CHUNK_SIZE).expect("snapshot write");
    std::fs::write(
        current_generation_artifact(&store_dir, SNAPSHOT_SIGNATURE_FILE_NAME),
        "00".repeat(64),
    )
    .expect("replace snapshot signature");
    let Err(error) = try_read_snapshot(
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        &store_dir,
        &Kura::blank_kura_for_testing(),
        &state.lane_manifests.read().clone(),
        &state.nexus_snapshot(),
        LiveQueryStore::start_test,
        BlockCount(state.view().height()),
        TEST_CHUNK_SIZE,
        key_pair.public_key(),
        &state.chain_id,
        &state.network_id,
        &crate::state::default_zk_config(),
        #[cfg(feature = "telemetry")]
        StateTelemetry::default(),
        &snapshot_read_budget_for_testing(),
    ) else {
        panic!("snapshot with all-zero signature should be rejected")
    };
    assert!(matches!(error, TryReadError::SignatureMalformed(_)));
}
#[tokio::test]
async fn snapshot_read_rejects_malformed_ed25519_signature_r_before_verification() {
    let tmp_root = tempdir().unwrap();
    let store_dir = tmp_root.path().join("snapshot");
    let state = state_factory();
    let key_pair = checked_random_snapshot_keypair();
    try_write_snapshot(&state, &store_dir, &key_pair, TEST_CHUNK_SIZE).expect("snapshot write");
    let signature_hex = std::fs::read_to_string(current_generation_artifact(
        &store_dir,
        SNAPSHOT_SIGNATURE_FILE_NAME,
    ))
    .expect("snapshot signature");
    let valid_signature_bytes = hex::decode(signature_hex.trim()).expect("signature hex");
    for (label, replacement_r) in [
        ("small-order", SMALL_ORDER_ED25519_R),
        ("noncanonical", NONCANONICAL_ED25519_R),
    ] {
        let mut signature_bytes = valid_signature_bytes.clone();
        signature_bytes[..replacement_r.len()].copy_from_slice(&replacement_r);
        std::fs::write(
            current_generation_artifact(&store_dir, SNAPSHOT_SIGNATURE_FILE_NAME),
            hex::encode(signature_bytes),
        )
        .expect("replace snapshot signature");
        let Err(error) = try_read_snapshot(
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            &store_dir,
            &Kura::blank_kura_for_testing(),
            &state.lane_manifests.read().clone(),
            &state.nexus_snapshot(),
            LiveQueryStore::start_test,
            BlockCount(state.view().height()),
            TEST_CHUNK_SIZE,
            key_pair.public_key(),
            &state.chain_id,
            &state.network_id,
            &crate::state::default_zk_config(),
            #[cfg(feature = "telemetry")]
            StateTelemetry::default(),
            &snapshot_read_budget_for_testing(),
        ) else {
            panic!("snapshot with malformed Ed25519 signature R should be rejected")
        };
        assert!(
            matches!(error, TryReadError::SignatureMalformed(_)),
            "{label} snapshot signature R produced unexpected error: {error:?}"
        );
    }
}
#[tokio::test]
async fn snapshot_read_rejects_malformed_mldsa_signature_lengths_before_verification() {
    let tmp_root = tempdir().unwrap();
    let store_dir = tmp_root.path().join("snapshot");
    let state = state_factory();
    let key_pair = KeyPair::try_from_seed(b"snapshot-mldsa-signature".to_vec(), Algorithm::MlDsa)
        .expect("snapshot ML-DSA fixture key generation should succeed");
    try_write_snapshot(&state, &store_dir, &key_pair, TEST_CHUNK_SIZE).expect("snapshot write");
    let signature_hex = std::fs::read_to_string(current_generation_artifact(
        &store_dir,
        SNAPSHOT_SIGNATURE_FILE_NAME,
    ))
    .expect("snapshot signature");
    let valid_signature_bytes = hex::decode(signature_hex.trim()).expect("signature hex");
    for label in ["short", "overlong"] {
        let mut signature_bytes = valid_signature_bytes.clone();
        match label {
            "short" => {
                signature_bytes
                    .pop()
                    .expect("ML-DSA snapshot signature is non-empty");
            }
            "overlong" => signature_bytes.push(0xA5),
            _ => unreachable!("covered labels"),
        }
        std::fs::write(
            current_generation_artifact(&store_dir, SNAPSHOT_SIGNATURE_FILE_NAME),
            hex::encode(signature_bytes),
        )
        .expect("replace snapshot signature");
        let Err(error) = try_read_snapshot(
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            &store_dir,
            &Kura::blank_kura_for_testing(),
            &state.lane_manifests.read().clone(),
            &state.nexus_snapshot(),
            LiveQueryStore::start_test,
            BlockCount(state.view().height()),
            TEST_CHUNK_SIZE,
            key_pair.public_key(),
            &state.chain_id,
            &state.network_id,
            &crate::state::default_zk_config(),
            #[cfg(feature = "telemetry")]
            StateTelemetry::default(),
            &snapshot_read_budget_for_testing(),
        ) else {
            panic!("snapshot with malformed ML-DSA signature length should be rejected")
        };
        assert!(
            matches!(error, TryReadError::SignatureMalformed(_)),
            "{label} snapshot ML-DSA signature length produced unexpected error: {error:?}"
        );
    }
}
#[tokio::test]
async fn snapshot_roundtrip_preserves_space_directory_manifests_and_rebuilds_bindings() {
    let tmp_root = tempdir().unwrap();
    let store_dir = tmp_root.path().join("snapshot");
    let mut state = state_factory();
    let (uaid, dataspace, account_id) = install_active_space_directory_manifest(&mut state);
    let key_pair = checked_random_snapshot_keypair();
    try_write_snapshot(&state, &store_dir, &key_pair, TEST_CHUNK_SIZE).unwrap();
    let snapshot_bytes = std::fs::read(current_generation_artifact(&store_dir, SNAPSHOT_FILE_NAME))
        .expect("snapshot bytes");
    let snapshot_value: json::Value =
        json::from_slice(&snapshot_bytes).expect("snapshot JSON should parse");
    assert!(
        snapshot_has_space_directory_manifest_section(&snapshot_value),
        "new snapshots must carry a Space Directory manifest section"
    );
    let snapshot_state = try_read_snapshot(
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        &store_dir,
        &Kura::blank_kura_for_testing(),
        &state.lane_manifests.read().clone(),
        &state.nexus_snapshot(),
        LiveQueryStore::start_test,
        BlockCount(state.view().height()),
        TEST_CHUNK_SIZE,
        key_pair.public_key(),
        &state.chain_id,
        &state.network_id,
        &crate::state::default_zk_config(),
        #[cfg(feature = "telemetry")]
        StateTelemetry::new(<_>::default(), true),
        &snapshot_read_budget_for_testing(),
    )
    .expect("snapshot read");
    let manifests = snapshot_state.world.space_directory_manifests.view();
    let manifest_set = manifests
        .get(&uaid)
        .expect("manifest set should survive snapshot restore");
    assert!(
        manifest_set.get(&dataspace).is_some(),
        "dataspace manifest should survive snapshot restore"
    );
    drop(manifests);
    let bindings = snapshot_state.world.uaid_dataspaces.view();
    let uaid_bindings = bindings
        .get(&uaid)
        .expect("UAID bindings should be rebuilt after snapshot restore");
    assert!(
        uaid_bindings.is_bound_to(dataspace, &account_id),
        "restored active manifest should bind the account to the dataspace"
    );
}
#[tokio::test]
async fn snapshot_missing_space_directory_section_rejects_even_with_kura_history() {
    let tmp_root = tempdir().unwrap();
    let store_dir = tmp_root.path().join("snapshot");
    let kura = Kura::blank_kura_for_testing();
    let mut state = state_factory_with_kura(Arc::clone(&kura));
    let manifest = sample_space_directory_manifest();
    let _account_id = insert_account_with_uaid(&mut state, manifest.uaid);
    let block = signed_block_with_transaction(accepted_manifest_transaction());
    store_block_and_mark_state_height(&mut state, &kura, block);
    let key_pair = checked_random_snapshot_keypair();
    let incomplete_bytes = snapshot_payload_without_space_directory_manifest_section(&state);
    write_snapshot_bundle_from_bytes(&store_dir, &incomplete_bytes, &key_pair);
    let error = match try_read_snapshot(
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        &store_dir,
        &kura,
        &state.lane_manifests.read().clone(),
        &state.nexus_snapshot(),
        LiveQueryStore::start_test,
        BlockCount(state.view().height()),
        TEST_CHUNK_SIZE,
        key_pair.public_key(),
        &state.chain_id,
        &state.network_id,
        &crate::state::default_zk_config(),
        #[cfg(feature = "telemetry")]
        StateTelemetry::new(<_>::default(), true),
        &snapshot_read_budget_for_testing(),
    ) {
        Ok(_) => panic!("missing canonical manifest section must not be reconstructed"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        TryReadError::MissingSpaceDirectoryManifestSection { snapshot_height: 1 }
    ));
}
#[tokio::test]
async fn snapshot_missing_space_directory_section_rejects_without_manifest_history() {
    let tmp_root = tempdir().unwrap();
    let store_dir = tmp_root.path().join("snapshot");
    let kura = Kura::blank_kura_for_testing();
    let mut state = state_factory_with_kura(Arc::clone(&kura));
    let block = signed_block_with_transaction(accepted_log_transaction("missing-section"));
    store_block_and_mark_state_height(&mut state, &kura, block);
    let key_pair = checked_random_snapshot_keypair();
    let incomplete_bytes = snapshot_payload_without_space_directory_manifest_section(&state);
    write_snapshot_bundle_from_bytes(&store_dir, &incomplete_bytes, &key_pair);
    let error = match try_read_snapshot(
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        &store_dir,
        &kura,
        &state.lane_manifests.read().clone(),
        &state.nexus_snapshot(),
        LiveQueryStore::start_test,
        BlockCount(state.view().height()),
        TEST_CHUNK_SIZE,
        key_pair.public_key(),
        &state.chain_id,
        &state.network_id,
        &crate::state::default_zk_config(),
        #[cfg(feature = "telemetry")]
        StateTelemetry::new(<_>::default(), true),
        &snapshot_read_budget_for_testing(),
    ) {
        Ok(_) => panic!("non-empty snapshot must carry its canonical manifest section"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        TryReadError::MissingSpaceDirectoryManifestSection { snapshot_height: 1 }
    ));
}
#[tokio::test]
async fn signed_snapshot_roundtrip_preserves_every_sccp_map() {
    let tmp_root = tempdir().unwrap();
    let store_dir = tmp_root.path().join("snapshot");
    let state = state_factory();
    for seed in [1, 2] {
        let mut block = state.world.block();
        crate::smartcontracts::isi::sccp::test_support::populate_every_sccp_map(&mut block, seed);
        block.commit();
    }
    let key_pair = checked_random_snapshot_keypair();
    try_write_snapshot(&state, &store_dir, &key_pair, TEST_CHUNK_SIZE).unwrap();
    let snapshot_bytes = std::fs::read(current_generation_artifact(&store_dir, SNAPSHOT_FILE_NAME))
        .expect("snapshot bytes");
    let snapshot_value: json::Value =
        json::from_slice(&snapshot_bytes).expect("snapshot JSON should parse");
    assert!(
        matches!(&snapshot_value, json::Value::Object(map) if map.contains_key("sccp")),
        "new snapshots must carry the SCCP envelope"
    );
    let restored = try_read_snapshot(
        &state.ivm_execution_budget(),
        &store_dir,
        &Kura::blank_kura_for_testing(),
        &state.lane_manifests.read().clone(),
        &state.nexus_snapshot(),
        LiveQueryStore::start_test,
        BlockCount(state.view().height()),
        TEST_CHUNK_SIZE,
        key_pair.public_key(),
        &state.chain_id,
        &state.network_id,
        &crate::state::default_zk_config(),
        #[cfg(feature = "telemetry")]
        StateTelemetry::new(<_>::default(), true),
        &snapshot_read_budget_for_testing(),
    )
    .expect("snapshot with SCCP state reads back");
    assert_eq!(
        canonical_state_snapshot_bytes_for_tests(&restored),
        canonical_state_snapshot_bytes_for_tests(&state),
        "snapshot roundtrip must preserve canonical WSV bytes"
    );
    let mut original_envelope = String::new();
    crate::state::sccp_snapshot_state::serialize_envelope(&state.world, &mut original_envelope);
    let mut restored_envelope = String::new();
    crate::state::sccp_snapshot_state::serialize_envelope(&restored.world, &mut restored_envelope);
    assert_eq!(restored_envelope, original_envelope);
    use crate::state::WorldReadOnly as _;
    use mv::storage::StorageReadOnly as _;
    let world = restored.world.view();
    assert_eq!(world.sccp_bridge_keys().len(), 2);
    assert_eq!(world.sccp_rosters().len(), 2);
    assert_eq!(world.sccp_block_leaves().len(), 2);
    assert_eq!(*world.sccp_roster_current(), 2);
    assert!(world.sccp_parameters().is_some());
}
#[tokio::test]
async fn signed_snapshot_without_the_sccp_envelope_is_rejected() {
    let tmp_root = tempdir().expect("temporary snapshot root");
    let store_dir = tmp_root.path().join("snapshot");
    let kura = Kura::blank_kura_for_testing();
    let state = state_factory_with_kura(Arc::clone(&kura));
    let serialized = CapturedStateSnapshot::capture(&state)
        .expect("stable valid fixture snapshot")
        .json;
    let mut snapshot: json::Value =
        json::from_str(&serialized).expect("valid baseline snapshot JSON");
    let json::Value::Object(snapshot_object) = &mut snapshot else {
        panic!("snapshot root must be an object");
    };
    assert!(snapshot_object.remove("sccp").is_some());
    let mutated = snapshot_json_with_mutation(&serialized, &snapshot);
    let key_pair = checked_random_snapshot_keypair();
    write_snapshot_bundle_from_bytes(&store_dir, mutated.as_bytes(), &key_pair);
    assert!(
        try_read_snapshot(
            &state.ivm_execution_budget(),
            &store_dir,
            &kura,
            &state.lane_manifests.read().clone(),
            &state.nexus_snapshot(),
            LiveQueryStore::start_test,
            BlockCount(0),
            TEST_CHUNK_SIZE,
            key_pair.public_key(),
            &state.chain_id,
            &state.network_id,
            &crate::state::default_zk_config(),
            #[cfg(feature = "telemetry")]
            StateTelemetry::new(<_>::default(), true),
            &snapshot_read_budget_for_testing(),
        )
        .is_err(),
        "a snapshot must carry its SCCP envelope"
    );
}
