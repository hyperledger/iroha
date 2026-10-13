fn source_transfer_replay_key_for_tests(
    issuer_nonce: &AxtAnchoredSpendReplayKeyV1,
) -> AxtSourceTransferReplayKeyV1 {
    AxtSourceTransferReplayKeyV1 {
        network_id: issuer_nonce.issuer_context.network_id,
        dataspace_id: issuer_nonce.issuer_context.asset_dsid,
        lane_id: LaneId::SINGLE,
        block_header_hash: HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            b"AXT source transfer replay test block",
        )),
        source_tx_index: 1,
        transcript_index: 2,
        delta_index: 3,
    }
}

state_test! { sync axt_policy_refresh_clears_stale_entries_when_snapshot_missing
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let mut state = State::new_for_testing(World::new(), kura, query_handle);
    let dsid = DataSpaceId::new(31);
    let_row! { policy = AxtPolicyEntry { manifest_root: [0x77; 32], target_lane: LaneId::new(2), active_handle_era: 1, next_handle_counter: 1, current_slot: 1, } };
    state.set_axt_policy(dsid, policy);
    let snapshot = state.refresh_axt_policies_from_directory();
    assert!(
        snapshot.is_none(),
        "no snapshot should be derived without manifests"
    );
    let view = state.world.axt_policies.view();
    assert!(
        view.get(&dsid).is_none(),
        "stale policy entries must be cleared"
    );
}
state_test! { sync state_block_axt_policy_snapshot_reads_block_scope
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let mut state = State::new_for_testing(World::new(), kura, query_handle);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let dsid = DataSpaceId::new(13);
    let_row! { entry = AxtPolicyEntry { manifest_root: [0x66; 32], target_lane: LaneId::new(2), active_handle_era: 5, next_handle_counter: 4, current_slot: 99, } };
    {
        let_row! { lane_catalog = LaneCatalog::new( nonzero!(3_u32), vec![LaneConfig { id: entry.target_lane, dataspace_id: dsid, alias: "block-scope-axt".into(), ..LaneConfig::default() }], ) .expect("block-scope AXT lane catalog") };
        configure_axt_fixture_lane_catalog(&mut state, lane_catalog);
    }
    let mut block = state.block(header);
    block.world.axt_policies.insert(dsid, entry);
    let expected_slot = block.block_hashes().len() as u64;
    let snapshot = block.axt_policy_snapshot();
    let_row! { binding = snapshot .entries .iter() .find(|binding| binding.dsid == dsid) .expect("policy from block scope available") };
    assert_eq!(binding.policy.manifest_root, entry.manifest_root);
    assert_eq!(binding.policy.target_lane, entry.target_lane);
    assert_eq!(binding.policy.active_handle_era, entry.active_handle_era);
    assert_eq!(
        binding.policy.next_handle_counter,
        entry.next_handle_counter
    );
    assert_eq!(binding.policy.current_slot, expected_slot);
    let expected_version = AxtPolicySnapshot::compute_version(&snapshot.entries);
    assert_eq!(snapshot.version, expected_version);
}
state_test! { sync axt_replay_ledger_overlay_applies
    let dsid = DataSpaceId::new(41);
    let lane = LaneId::new(0);
    let_row! { lane_catalog = LaneCatalog::new( nonzero!(1_u32), vec![public_lane!(lane, dsid, "primary".to_owned())], ) .expect("lane catalog") };
    let_row! { mut nexus = iroha_config::parameters::actual::Nexus { lane_catalog: lane_catalog.clone(), lane_config: iroha_config::parameters::actual::LaneConfig::from_catalog(&lane_catalog), dataspace_catalog: dataspace_catalog_for_lane_catalog(&lane_catalog), routing_policy: LaneRoutingPolicy { default_lane: lane, default_dataspace: dsid, ..Default::default() }, ..Default::default() } };
    nexus.axt.slot_length_ms = NonZeroU64::new(1).expect("slot length");
    nexus.axt.replay_retention_slots = NonZeroU64::new(2).expect("retention");
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_with_nexus_for_testing(World::new(), nexus, query_handle);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 1, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    stx.current_lane_id = Some(lane);
    let key = AxtHandleReplayKey::from_parts(
        dsid,
        axt_replay_incarnation_for_test(0xAA),
        [0xAA; 32],
        3,
        7,
        lane,
    );
    let_row! { record = axt_replay_record_for_key(&key, 1, 4) };
    stx.world.axt_replay_ledger.insert(key, record.clone());
    stx.apply();
    assert_eq!(
        block.world.axt_replay_ledger.get(&key).cloned(),
        Some(record)
    );
}
state_test! { sync anchored_axt_spend_nonce_overlay_rolls_back_or_applies_atomically
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 1, 0));
    let key = AxtAnchoredSpendReplayKeyV1 {
        issuer_context: AxtHandleIssuerContextV1::default(),
        nonce: AxtSpendNonceV1::try_new([0xD3; 32]).expect("nonzero nonce"),
    };
    {
        let mut discarded = block.transaction();
        discarded.world.axt_spend_nonce_ledger.insert(key, 1);
    }
    assert!(block.world.axt_spend_nonce_ledger.get(&key).is_none());
    {
        let mut applied = block.transaction();
        applied.world.axt_spend_nonce_ledger.insert(key, 1);
        applied.apply();
    }
    assert_eq!(block.world.axt_spend_nonce_ledger.get(&key), Some(&1));
}
state_test! { sync anchored_axt_source_transfer_replay_is_cross_envelope_and_atomic
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 1, 0));
    let first_nonce = AxtAnchoredSpendReplayKeyV1 {
        issuer_context: AxtHandleIssuerContextV1::default(),
        nonce: AxtSpendNonceV1::try_new([0xD4; 32]).expect("first nonce"),
    };
    let source = source_transfer_replay_key_for_tests(&first_nonce);
    {
        let mut discarded = block.transaction();
        discarded
            .world
            .reserve_verified_axt_spend_replay(first_nonce, source, 1)
            .expect("reserve in discarded transaction");
    }
    assert!(block.world.axt_spend_nonce_ledger.get(&first_nonce).is_none());
    assert!(block.world.axt_source_transfer_replay_ledger.get(&source).is_none());

    {
        let mut applied = block.transaction();
        applied
            .world
            .reserve_verified_axt_spend_replay(first_nonce, source, 1)
            .expect("reserve first envelope");
        applied.apply();
    }
    assert_eq!(block.world.axt_spend_nonce_ledger.get(&first_nonce), Some(&1));
    assert_eq!(
        block.world.axt_source_transfer_replay_ledger.get(&source),
        Some(&AxtSourceTransferReplayRecordV1 { issuer_nonce: first_nonce, consumed_slot: 1 })
    );

    let second_nonce = AxtAnchoredSpendReplayKeyV1 {
        nonce: AxtSpendNonceV1::try_new([0xD5; 32]).expect("second nonce"),
        ..first_nonce
    };
    {
        let mut invalid = block.transaction();
        assert_eq!(
            invalid.world.reserve_verified_axt_spend_replay(
                second_nonce,
                AxtSourceTransferReplayKeyV1 { source_tx_index: 65_536, ..source },
                2,
            ),
            Err(AxtSpendReplayReservationErrorV1::InvalidSourceTransfer),
        );
        assert_eq!(
            invalid.world.reserve_verified_axt_spend_replay(
                second_nonce,
                AxtSourceTransferReplayKeyV1 { dataspace_id: DataSpaceId::new(99), ..source },
                2,
            ),
            Err(AxtSpendReplayReservationErrorV1::IdentityMismatch),
        );
        assert_eq!(
            invalid.world.reserve_verified_axt_spend_replay(second_nonce, source, 0),
            Err(AxtSpendReplayReservationErrorV1::ZeroSlot),
        );
        assert!(invalid.world.axt_spend_nonce_ledger.get(&second_nonce).is_none());
    }
    {
        let mut second = block.transaction();
        assert_eq!(
            second.world.reserve_verified_axt_spend_replay(second_nonce, source, 2),
            Err(AxtSpendReplayReservationErrorV1::SourceTransferConsumed),
        );
        assert!(second.world.axt_spend_nonce_ledger.get(&second_nonce).is_none());
    }
    let different_source = AxtSourceTransferReplayKeyV1 { delta_index: 4, ..source };
    {
        let mut second = block.transaction();
        assert_eq!(
            second.world.reserve_verified_axt_spend_replay(first_nonce, different_source, 2),
            Err(AxtSpendReplayReservationErrorV1::IssuerNonceConsumed),
        );
        assert!(second.world.axt_source_transfer_replay_ledger.get(&different_source).is_none());
    }
    assert!(block.world.axt_spend_nonce_ledger.get(&second_nonce).is_none());
    assert!(block.world.axt_source_transfer_replay_ledger.get(&different_source).is_none());
}
state_test! { sync ordinary_block_seals_axt_replay_pruning_before_atomic_commit
    let dsid = DataSpaceId::new(42);
    let lane = LaneId::new(0);
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.axt.slot_length_ms = NonZeroU64::new(1).expect("slot length");
    nexus.axt.replay_retention_slots = NonZeroU64::new(2).expect("retention");
    let key = AxtHandleReplayKey::from_parts(
        dsid,
        axt_replay_incarnation_for_test(0xAB),
        [0xAB; 32],
        3,
        7,
        lane,
    );
    let_row! { stale = axt_replay_record_for_key(&key, 1, 2) };
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig, Signers};
    let mut world = World::new();
    world.axt_replay_ledger.insert(key, stale.clone());
    let mut config = TestChainConfig::new(world, 0);
    config.nexus = Some(nexus);
    let mut chain = CertifiedTestChain::start(config).unwrap();
    let state = Arc::clone(chain.state());
    let proposal = chain.proposal(None, Vec::new());
    assert!(proposal.axt_envelopes().is_none());
    let mut pending = chain.begin_proposal(proposal, iroha_sumeragi::types::ControlWitness::default()).unwrap();
    assert!(pending.inspect_prepared(|_| ()).is_err(), "unprepared source is not a publication snapshot");
    pending.prepare(Signers::Quorum).unwrap();
    assert!(pending.inspect_prepared(|_| ()).is_err(), "a certificate alone has not finalized State metadata");
    pending.prepare_publication_for_inspection(Signers::Quorum)
        .expect("real history contention retains finalized original metadata before visibility");
    let inspect_state = Arc::clone(&state);
    let (staged_bytes, staged_hash) = pending.inspect_prepared(move |original| {
        let staged = original.state;
        let state = inspect_state;
        assert_eq!(
            state.world.axt_replay_ledger.view().get(&key).cloned(),
            Some(stale),
            "preparing the sealed overlay must not mutate committed replay state"
        );
        assert!(staged.world.axt_replay_ledger.get(&key).is_none(),
            "the final publication seal includes deterministic replay pruning");
        let bytes = crate::snapshot::canonical_staged_state_snapshot_bytes(staged);
        let hash = crate::snapshot::canonical_staged_state_snapshot_hash(staged);
        assert_eq!(hash, iroha_crypto::Hash::new(&bytes),
            "staged checkpoint streaming hash matches its canonical bytes");
        (bytes, hash)
    }).expect("read the exact certificate-authorized original overlay");
    pending.publish(Signers::Quorum).expect("publish actual outputs and commit deferred replay pruning");
    assert!(pending.inspect_prepared(|_| ()).is_err(), "published source is consumed");
    drop(pending);
    assert!(
        state.world.axt_replay_ledger.view().get(&key).is_none(),
        "ordinary block commit should prune expired AXT replay entries"
    );
    let committed_bytes = crate::snapshot::canonical_state_snapshot_bytes(&state);
    let committed_hash = crate::snapshot::canonical_state_snapshot_hash(&state).expect("stable valid fixture snapshot");
    assert_eq!(
        committed_hash,
        iroha_crypto::Hash::new(&committed_bytes),
        "committed checkpoint streaming hash must match its canonical bytes"
    );
    assert!(
        staged_bytes == committed_bytes && staged_hash == committed_hash,
        "pre-WSV checkpoint must project commit-time replay pruning: \
         staged_len={}, committed_len={}, staged_hash={staged_hash}, \
         committed_hash={committed_hash}",
        staged_bytes.len(),
        committed_bytes.len(),
    );
}

state_test! { sync committed_storage_projections_omit_absent_and_empty_changes
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 1, 0));
    assert!(!block.has_finalized_world_tail_for_snapshot());
    assert!(block.json_serialize_committed_axt_replay_ledger().is_none());
    assert!(block.json_serialize_committed_smart_contract_state().is_none());
    block.stage_da_pin_intent_bundle(1, Vec::new()).unwrap();
    assert!(block.json_serialize_committed_smart_contract_state().is_none());
}
state_test! { sync staged_checkpoint_projects_deferred_da_quota_without_applying_it
    let owner_keypair = crate::state::checked_keypair();
    let owner_id = AccountId::new(owner_keypair.public_key().clone());
    let mut world = World::new();
    world.accounts.insert(
        owner_id.clone(),
        iroha_data_model::account::AccountValue::new(
            iroha_data_model::account::AccountDetails::default(),
        ),
    );
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig, Signers};
    let mut config = TestChainConfig::new(world, 0);
    let lane_incarnation = derive_static_lane_incarnations(&LaneCatalog::default())[&LaneId::SINGLE];
    let admission = iroha_data_model::da::ingest::DaIngestAdmissionPolicyV1 {
        version: iroha_data_model::da::ingest::DaIngestAdmissionPolicyV1::VERSION,
        revision: 1,
        expected_previous_policy_hash: None,
        lanes: vec![iroha_data_model::da::ingest::DaIngestAdmissionLaneV1 {
            lane_id: LaneId::SINGLE,
            lane_incarnation,
            producers: vec![owner_id],
            current_epoch: 1,
            grace_epoch: None,
        }],
    };
    admission.validate().expect("bounded original DA producer policy");
    config.genesis_parameters.push(iroha_data_model::parameter::Parameter::Custom(
        admission.clone().into_custom_parameter(),
    ));
    let mut chain = CertifiedTestChain::start(config).unwrap();
    assert_eq!(chain.state().lane_incarnation_at_height(LaneId::SINGLE, 2), Some(lane_incarnation));
    assert_eq!(
        iroha_data_model::da::ingest::DaIngestAdmissionPolicyV1::from_custom_parameter(
            chain.state().world.parameters.view().custom().get(
                &iroha_data_model::da::ingest::DaIngestAdmissionPolicyV1::parameter_id(),
            ).expect("actual signed genesis producer policy"),
        ).unwrap(), Some(admission),
    );
    let state = Arc::clone(chain.state());
    let authorization = crate::da::signed_test_ingest_authorization(
        *state.network_id_ref(), &owner_keypair, LaneId::SINGLE, 1, 0, 1,
    );
    let intent = crate::da::signed_test_pin_intent(
        authorization,
        &owner_keypair,
        StorageTicketId::new([0xA4; 32]),
        ManifestDigest::new([0xB5; 32]),
        None,
    );
    let transaction = chain.sign(&owner_keypair, [Log::new(iroha_logger::Level::INFO, "ordinary DA source".into()).into()], 1);
    let mut proposal = chain.proposal(None, vec![transaction]);
    proposal.set_da_pin_intents(Some(DaPinIntentBundle::new(vec![intent])));
    let mut pending = chain.begin_proposal(proposal, iroha_sumeragi::types::ControlWitness::default()).unwrap();
    pending.prepare(Signers::Quorum).unwrap();
    assert!(pending.inspect_prepared(|_| ()).is_err(), "a certificate alone has not finalized quota metadata");
    pending.prepare_publication_for_inspection(Signers::Quorum)
        .expect("real history contention retains original quota preparation before visibility");
    let inspect_state = Arc::clone(&state);
    let (writes, projected_storage, staged_bytes, staged_hash) = pending.inspect_prepared(move |original| {
        let block = original.state;
    let writes = block.pending_da_pin_intents.as_ref()
        .expect("real block application stages its quota bundle").quota_writes.clone();
    assert!(!writes.is_empty(), "signed nonempty DA bundle must charge quota");
    for (key, value) in &writes {
        assert!(inspect_state.world.smart_contract_state.view().get(key).is_none(),
            "preparing the sealed overlay must not publish committed quota state");
        assert_eq!(block.world.smart_contract_state.get(key), Some(value),
            "certified execution includes the exact once-prepared quota tail");
    }
    let before_storage = norito::json::to_json(&block.world.smart_contract_state)
        .expect("unprojected contract storage");
    assert!(block.has_finalized_world_tail_for_snapshot(),
        "the exact original publisher completed its immutable World tail");
    assert!(block.json_serialize_committed_smart_contract_state().is_none(),
        "sealed quota values need no substitute executing projection");
    assert!(block.json_serialize_committed_da_pin_indexes().iter().all(Option::is_none),
        "sealed pin indexes need no recomputed admission plan");
    let projected_storage = before_storage.clone();
    let staged_bytes = crate::snapshot::canonical_staged_state_snapshot_bytes(block);
    let staged_hash = crate::snapshot::canonical_staged_state_snapshot_hash(block);
    assert_eq!(staged_hash, Hash::new(&staged_bytes));
    assert_eq!(norito::json::to_json(&block.world.smart_contract_state)
        .expect("unchanged contract storage"), before_storage);
        (writes, projected_storage, staged_bytes, staged_hash)
    }).expect("immutable original prepared quota observation");
    pending.publish(Signers::Quorum).expect("ordinary DA block commits actual outputs and quota");
    drop(pending);
    assert_eq!(projected_storage, norito::json::to_json(&state.world.smart_contract_state)
        .expect("committed contract storage including exact undo"));
    for (key, value) in &writes {
        assert_eq!(state.world.smart_contract_state.view().get(key), Some(value));
    }
    let committed_bytes = crate::snapshot::canonical_state_snapshot_bytes(&state);
    let committed_hash = crate::snapshot::canonical_state_snapshot_hash(&state).expect("stable valid fixture snapshot");
    assert_eq!(committed_hash, Hash::new(&committed_bytes));
    assert!(staged_bytes == committed_bytes && staged_hash == committed_hash,
        "DA quota checkpoint projection differs from committed WSV: \
         staged_hash={staged_hash}, committed_hash={committed_hash}");
}

state_test! { sync axt_slot_uses_authenticated_time_for_hash_only_snapshot_parent
    fn hash_only_state() -> State {
        let state = blank_state();
        seed_committed_height_for_state_test(&state, 5);
        state
    }

    let unavailable = hash_only_state();
    assert!(unavailable.latest_block_header_fast().is_none());
    let unavailable_view = unavailable.view();
    assert_eq!(
        crate::smartcontracts::ivm::host::current_axt_slot_for_state(&unavailable_view),
        None,
        "a non-genesis hash-only view without authenticated time must fail closed"
    );
    assert!(matches!(
        crate::smartcontracts::ivm::host::CoreHost::from_state(
            ALICE_ID.clone(),
            &unavailable
        ),
        Err(crate::smartcontracts::ivm::host::CoreHostStateError::AxtPolicySnapshot(
            iroha_data_model::nexus::AxtPolicySnapshotValidationError::AuthenticatedLedgerTimeUnavailable
        ))
    ));
    drop(unavailable_view);

    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    let mut config = TestChainConfig::new(World::new(), 1000);
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.axt.slot_length_ms = nonzero!(10_u64);
    config.nexus = Some(nexus);
    let mut chain = CertifiedTestChain::start(config).unwrap();
    chain.commit_at(10_000, Vec::new());
    let anchored = chain.state();
    let stale_prefix_header = BlockHeader::new(nonzero!(1_u64), None, None, 99, 0);
    anchored.update_latest_block_header_cache_for_tests(stale_prefix_header);
    assert_eq!(anchored.latest_block_creation_time_ms_fast(), Some(10_000));
    let anchored_view = anchored.view();
    assert_eq!(anchored_view.query_ledger_time_ms(), 10_000);
    assert_eq!(anchored_view.authenticated_query_ledger_time_ms(), Some(10_000));
    assert_eq!(
        crate::smartcontracts::ivm::host::current_axt_slot_for_state(&anchored_view),
        Some(1_000),
        "AXT expiry must use the authenticated tip anchor, never height 5 or a stale cached prefix header"
    );
}

state_test! { consensus_stack axt_post_validation_envelope_replacement_cannot_publish_world_state
    use iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_KEYPAIR;

    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    let mut config = TestChainConfig::new(World::new(), 1000);
    config.genesis_key = SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone();
    let chain = CertifiedTestChain::start(config).unwrap();
    let state = chain.state();
    let parent = chain.genesis();
    let retained_hash = state.latest_block_hash_fast();
    let transaction = TransactionBuilder::new(
        *state.network_id_ref(),
        SAMPLE_GENESIS_ACCOUNT_ID.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([iroha_data_model::isi::Log::new(
        iroha_data_model::level::Level::INFO,
        "validate the AXT envelope source".to_owned(),
    )])
    .sign(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key());
    let mut signed: SignedBlock = BlockBuilder::new(vec![AcceptedTransaction::new_unchecked(
        Cow::Owned(transaction),
    )])
    .chain(0, Some(parent))
    .sign(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key())
    .unpack(|_| {})
    .into();
    let (mut staged, recorder) = ValidBlock::start_component_execution(&signed, state)
        .expect("original AXT source starts recording before block effects");
    ValidBlock::execute_recorded_component_outputs(&mut signed, &mut staged, &recorder)
        .expect("execute and seal the genuine source");
    assert!(signed.output_error(0).is_none());
    let outputs = signed.execution_outputs().to_vec();
    let snapshot = signed.axt_policy_snapshot().cloned().unwrap_or_default();
    let envelope = AxtEnvelopeRecord {
        binding: AxtBinding::new([0xB7; 32]),
        lane: LaneId::SINGLE,
        descriptor: AxtDescriptor {
            dsids: vec![DataSpaceId::UNIVERSAL],
            touches: Vec::new(),
        },
        touches: Vec::new(),
        proofs: Vec::new(),
        spends: Vec::new(),
        commit_height: 2,
    };
    signed
        .set_execution_outputs(
            outputs,
            signed.committed_fragment_count().unwrap_or(0),
            std::collections::BTreeMap::default(),
            vec![envelope],
            snapshot,
            std::collections::BTreeSet::default(),
            &crate::execution_output_test_support::structural_output_limits(),
        )
        .expect("structurally attach a post-validation envelope");
    let error = staged.verify_execution_output_seal(&signed)
        .expect_err("replacement envelopes cannot reuse the original execution seal");
    assert_eq!(error, "execution output attachment changed after its seal");
    drop(staged);
    assert_eq!(state.latest_block_hash_fast(), retained_hash);
    assert_eq!(state.committed_height(), 1);
    assert!(state.world.axt_replay_ledger.view().is_empty());
    assert!(state.kura.get_block_hash(nonzero!(2_usize)).is_none());
}
