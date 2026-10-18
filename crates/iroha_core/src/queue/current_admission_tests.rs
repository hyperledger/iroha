// Native queue admission preserves original signed inputs until global application.
fn current_admission_queue_fixture() -> (State, TimeSource) {
    let mut state = State::new(
        world_with_test_domains(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    install_single_validator_topology_for_queue_test(&mut state, 0xB7);
    let (_, time_source) = TimeSource::new_mock(Duration::default());
    (state, time_source)
}

#[test]
fn exact_pending_retry_requires_live_healthy_original_input() {
    let mut state = State::new(
        world_with_test_domains(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let (clock, time) = TimeSource::new_mock(Duration::default());
    let mut config = config_factory();
    config.transaction_time_to_live = Duration::from_secs(1);
    let queue = Queue::test(config, &time);
    let transaction = accepted_tx_by_someone(&time);
    register_accepted_tx_authority_for_queue_test(&mut state, &transaction);
    assert!(!queue.contains_exact_pending_input(&transaction, &state));
    queue.push(transaction.clone(), state.view()).unwrap();
    assert!(queue.contains_exact_pending_input(&transaction, &state));
    let other = accepted_tx_by_someone(&time);
    assert!(!queue.contains_exact_pending_input(&other, &state));
    queue
        .accepted_work_validation_fault
        .store(true, Ordering::Release);
    assert!(!queue.contains_exact_pending_input(&transaction, &state));
    queue
        .accepted_work_validation_fault
        .store(false, Ordering::Release);
    assert!(queue.contains_exact_pending_input(&transaction, &state));
    clock.advance(Duration::from_secs(2));
    assert!(!queue.contains_exact_pending_input(&transaction, &state));
    assert_eq!(
        queue.remove_committed_hashes([transaction.hash_as_entrypoint()], None),
        1
    );
    assert!(!queue.contains_exact_pending_input(&transaction, &state));
}

#[test]
fn current_admission_preserves_original_input_across_direct_queue_boundaries() {
    let (mut state, time) = current_admission_queue_fixture();
    let transaction = accepted_tx_by_someone(&time);
    register_accepted_tx_authority_for_queue_test(&mut state, &transaction);
    let original = transaction.entrypoint_bytes().to_vec();
    let hash = transaction.hash_as_entrypoint();
    for boundary in 0..4 {
        let queue = Arc::new(Queue::test(config_factory(), &time));
        let plan = queue.route_plan_with_state(&transaction, &state).unwrap();
        match boundary {
            0 => queue.push(transaction.clone(), state.view()).map(|_| ()),
            1 => queue
                .push_with_lane_with_state(transaction.clone(), &state)
                .map(|_| ()),
            2 => queue
                .push_with_lane_with_state_and_routing_plan(
                    transaction.clone(),
                    &state,
                    plan.clone(),
                )
                .map(|_| ()),
            _ => queue
                .push_batch_with_lane_with_state_and_routing_plans(
                    vec![(transaction.clone(), plan.clone())],
                    &state,
                )
                .map(|_| ()),
        }
        .expect("native admission keeps the original signed input");
        assert_eq!((queue.active_len(), queue.queued_len()), (1, 1));
        for _ in 0..2 {
            let snapshot = queue
                .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
                .unwrap();
            assert_eq!(snapshot.len(), 1);
            assert_eq!(snapshot[0].hash_as_entrypoint(), hash);
            assert_eq!(
                snapshot[0].entrypoint_bytes().as_slice(),
                original.as_slice()
            );
            assert_eq!(queue.routing_plans.get(&hash).unwrap().value(), &plan);
        }
        assert!(matches!(
            queue
                .push(transaction.clone(), state.view())
                .unwrap_err()
                .err,
            Error::IsInQueue
        ));
        assert_eq!((queue.active_len(), queue.queued_len()), (1, 1));
    }
}

#[test]
fn current_admission_rejects_actual_multiroute_before_queue_custody() {
    let (_, time) = TimeSource::new_mock(Duration::default());
    let fixture = nexus_routing_fixture_with_nexus(test_nexus_for_routes(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (LaneId::new(1), DataSpaceId::new(7)),
    ]));
    let signed = TransactionBuilder::new(
        *fixture.state.network_id_ref(),
        fixture.authority_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([
        Register::domain(Domain::new(
            DomainId::try_new("coordinator", "universal").unwrap(),
        )),
        Register::domain(Domain::new(
            DomainId::try_new("participant", "test-dataspace-7").unwrap(),
        )),
    ])
    .sign(fixture.authority_keypair.private_key());
    let tx = AcceptedTransaction::new_unchecked(Cow::Owned(signed));
    let queue = Queue::test(config_factory(), &time);
    let actual = queue.route_plan_with_state(&tx, &fixture.state).unwrap();
    assert!(!matches!(actual, RoutingPlan::Single(_)));
    for boundary in 0..3 {
        let failure = match boundary {
            0 => queue.push(tx.clone(), fixture.state.view()).map(|_| ()),
            1 => queue
                .push_with_lane_with_state_and_routing_plan(
                    tx.clone(),
                    &fixture.state,
                    actual.clone(),
                )
                .map(|_| ()),
            _ => queue
                .push_batch_with_lane_with_state_and_routing_plans(
                    vec![(tx.clone(), actual.clone())],
                    &fixture.state,
                )
                .map(|_| ()),
        }
        .expect_err("a multiroute request has no native execution owner");
        assert!(matches!(
            failure.err,
            Error::UnsupportedTransactionAdmission { .. }
        ));
        assert_eq!(failure.tx.entrypoint(), tx.entrypoint());
        assert_eq!(queue.active_len(), 0);
        assert!(queue.txs.is_empty());
        assert!(queue.routing_plans.is_empty());
        assert!(
            queue
                .fee_admission_reservations
                .lock()
                .live_by_entrypoint
                .is_empty()
        );
    }
}

#[test]
fn current_payload_selects_full_block_gas_call_with_idle_catalog_route() {
    use crate::sumeragi::{
        lanes::{executor::LaneTransactions, global::QueueLaneTransactions},
        test_chain::{CertifiedTestChain, TestChainConfig, fixture_validators},
    };
    use iroha_data_model::sumeragi_lanes::{
        SumeragiFixedLane, SumeragiLaneMember, SumeragiLanePolicy,
    };
    let busy_route = RoutingDecision::new(LaneId::new(1), DataSpaceId::new(7));
    let mut nexus = test_nexus_for_routes(&[
        (busy_route.lane_id, busy_route.dataspace_id),
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
    ]);
    nexus.routing_policy.default_lane = busy_route.lane_id;
    nexus.routing_policy.default_dataspace = busy_route.dataspace_id;
    let (authority_id, authority_keypair) = gen_account_in("full-block-gas-lane");
    let mut committee = fixture_validators()
        .into_iter()
        .map(|(peer, pop)| SumeragiLaneMember { peer, pop })
        .collect::<Vec<_>>();
    committee.sort();
    let policy = SumeragiLanePolicy {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        anchor_freshness: 4,
        max_merge_blocks: 8,
        stall_window: 1000,
        lane_params: iroha_data_model::parameter::system::SumeragiParameters::default(),
        fixed: vec![SumeragiFixedLane {
            lane: busy_route.lane_id,
            dataspace: busy_route.dataspace_id,
            committee,
        }],
        routes: Vec::new(),
        autoscale: None,
    };
    let world = World::with(
        [],
        [Account::new(authority_id.clone()).build(&authority_id)],
        [],
    );
    let mut config = TestChainConfig::new(world, 1000);
    config.nexus = Some(nexus);
    config
        .genesis_parameters
        .push(Parameter::Custom(policy.into_custom_parameter()));
    let mut chain = CertifiedTestChain::start(config).expect("original signed native lane policy");
    chain.commit_at(2000, Vec::new());
    chain.commit_at(3000, Vec::new());
    let state = Arc::clone(chain.state());
    assert!(
        state
            .world_view()
            .sumeragi_lanes()
            .lane(busy_route.lane_id)
            .unwrap()
            .admits_anchor(3)
    );
    assert_eq!(state.nexus_snapshot().lane_catalog.lanes().len(), 2);
    let block_gas = crate::state::gas_limit_from_parameters(state.world_view().parameters());
    let (_, time) = TimeSource::new_mock(Duration::from_millis(3001));
    let queue = Arc::new(Queue::test(config_factory(), &time));
    let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
        state.network_id_ref(),
        &authority_id,
        1,
        busy_route.dataspace_id,
    )
    .unwrap();
    let signed = TransactionBuilder::new_with_time_source(
        *state.network_id_ref(),
        authority_id,
        &time,
        FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(block_gas)),
    )
    .with_executable(Executable::ContractCall(
        iroha_data_model::transaction::executable::ContractInvocation {
            contract_address,
            expected_code_hash: Hash::new(b"current-full-block-gas-call"),
            entrypoint: "configure".to_owned(),
            arguments: None,
        },
    ))
    .sign(authority_keypair.private_key());
    let accepted = AcceptedTransaction::accept_with_time_source(
        signed,
        state.network_id_ref(),
        Duration::from_millis(10),
        TransactionParameters::default(),
        &iroha_config::parameters::actual::Crypto::default(),
        &time,
    )
    .unwrap();
    assert_eq!(
        Queue::compute_proposal_gas_cost(&accepted, &crate::gas::DEFAULT_ZK_GAS)
            .expect("completed proposal gas quote"),
        block_gas
    );
    let original = accepted.entrypoint_bytes().to_vec();
    let hash = accepted.hash_as_entrypoint();
    // Lane batches retain the complete entrypoint, including its original envelope.
    let max_bytes = accepted.entrypoint_bytes().len();
    let plan = queue.route_plan_with_state(&accepted, &state).unwrap();
    assert_eq!(plan, RoutingPlan::single(busy_route));
    queue
        .push_with_lane_with_state_and_routing_plan(accepted.clone(), &state, plan.clone())
        .unwrap();
    let lane_inputs = QueueLaneTransactions::new(
        busy_route.lane_id,
        Arc::clone(&queue),
        Arc::clone(&state),
        time.clone(),
    );
    // Fresh native-lane work belongs to its lane, while idle catalog lanes do
    // not divide this original input's gas budget or transfer pending ownership.
    for _ in 0..2 {
        assert!(
            crate::sumeragi::payload::select(
                &state.view(),
                &queue,
                max_bytes,
                &crate::sumeragi::payload::MergeProposal::default(),
                iroha_primitives::time::TimeSource::new_system().now()
            )
            .expect("completed original routing read")
            .is_empty(),
            "the global chain cannot steal fresh native-lane work"
        );
        let selected = lane_inputs
            .candidates(
                4,
                max_bytes,
                &BTreeSet::new(),
                &state.ivm_execution_budget(),
            )
            .expect("completed original lane routing read")
            .0;
        assert_eq!(
            selected.len(),
            1,
            "an idle catalog route must not split the gas budget"
        );
        assert_eq!(&selected[0], accepted.entrypoint());
        let pending = queue
            .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].entrypoint_bytes().as_slice(),
            original.as_slice()
        );
        assert_eq!(
            Queue::compute_proposal_gas_cost(&pending[0], &crate::gas::DEFAULT_ZK_GAS)
                .expect("completed proposal gas quote"),
            block_gas
        );
        assert_eq!(queue.routing_plans.get(&hash).unwrap().value(), &plan);
        assert_eq!((queue.active_len(), queue.queued_len()), (1, 1));
    }
}

#[test]
fn current_native_fifo_survives_unrelated_global_application() {
    let handle = crate::sumeragi::threads::sumeragi_thread_builder("native-height-custody")
        .spawn(current_native_fifo_survives_unrelated_global_application_on_consensus_stack)
        .expect("spawn native queue and real four-validator genesis");
    if let Err(payload) = handle.join() {
        std::panic::resume_unwind(payload);
    }
}

#[inline(never)]
fn current_native_fifo_survives_unrelated_global_application_on_consensus_stack() {
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    let (authority, key) = gen_account_in("native-height-custody");
    let world = World::with([], [Account::new(authority.clone()).build(&authority)], []);
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(world, 10_000)).unwrap();
    assert_eq!(chain.height(), 1);
    let state = Arc::clone(chain.state());
    let (_, time) = TimeSource::new_mock(Duration::from_millis(20_001));
    let queue = Arc::new(Queue::test(config_factory(), &time));
    let mut hashes = Vec::new();
    let mut originals = Vec::new();
    let mut signed_inputs = Vec::new();
    for index in 0..2_u64 {
        let signed = chain.sign(
            &key,
            [InstructionBox::from(Log::new(
                Level::INFO,
                format!("pending native input {index}"),
            ))],
            20_000 + index,
        );
        signed_inputs.push(signed.clone());
        let accepted = AcceptedTransaction::accept_with_time_source(
            signed,
            state.network_id_ref(),
            Duration::from_millis(10),
            TransactionParameters::default(),
            &iroha_config::parameters::actual::Crypto::default(),
            &time,
        )
        .unwrap();
        let plan = queue.route_plan_with_state(&accepted, &state).unwrap();
        assert!(matches!(plan, RoutingPlan::Single(_)));
        hashes.push(accepted.hash_as_entrypoint());
        originals.push(accepted.entrypoint_bytes().to_vec());
        queue
            .push_with_lane_with_state_and_routing_plan(accepted, &state, plan)
            .unwrap();
    }
    let assert_retained = || {
        assert_eq!((queue.active_len(), queue.queued_len()), (2, 2));
        for _ in 0..2 {
            let selected = crate::sumeragi::payload::select(
                &state.view(),
                &queue,
                1024 * 1024,
                &crate::sumeragi::payload::MergeProposal::default(),
                iroha_primitives::time::TimeSource::new_system().now(),
            )
            .expect("completed routing read");
            assert_eq!(
                selected
                    .iter()
                    .map(AcceptedTransaction::hash_as_entrypoint)
                    .collect::<Vec<_>>(),
                hashes
            );
            assert_eq!(
                selected
                    .iter()
                    .map(|tx| tx.entrypoint_bytes().to_vec())
                    .collect::<Vec<_>>(),
                originals
            );
        }
    };
    assert_retained();
    let advance = chain.sign(
        &key,
        [InstructionBox::from(Log::new(
            Level::INFO,
            "advance committed frontier".into(),
        ))],
        20_002,
    );
    assert_eq!(chain.commit(vec![advance]), [true]);
    assert_eq!(chain.height(), 2);
    assert_eq!(
        state
            .view()
            .latest_block()
            .expect("committed history read completes")
            .expect("committed successor is retained")
            .network_entrypoint_count(),
        1
    );
    assert_retained();
    assert_eq!(chain.commit(signed_inputs), [true, true]);
    assert_eq!(chain.height(), 3);
    // The real G application precedes the queue's exact-hash cleanup notification.
    assert_eq!(queue.remove_committed_hashes(hashes.clone(), None), 2);
    assert_eq!(queue.remove_committed_hashes(hashes, None), 0);
    assert_eq!((queue.active_len(), queue.queued_len()), (0, 0));
    assert!(
        queue
            .bounded_pending_snapshot(&state.view(), nonzero!(2_usize))
            .unwrap()
            .is_empty()
    );
    assert!(queue.routing_plans.is_empty());
    assert!(
        queue
            .fee_admission_reservations
            .lock()
            .live_by_entrypoint
            .is_empty()
    );
}

#[test]
fn governed_lane_commitment_keeps_original_input_and_required_approval_refusals() {
    use iroha_data_model::transaction::signed::{
        SealedTransactionCommitmentPayload, SealedTransactionReveal,
        SignedSealedTransactionCommitment, compute_sealed_transaction_commitment,
    };
    let state = State::new(
        world_with_test_domains(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let (_, time) = TimeSource::new_mock(Duration::ZERO);
    let queue = Arc::new(Queue::test(config_factory(), &time));
    let (authority, key) = gen_account_in("sealed-manifest-owner");
    let (second, _) = gen_account_in("sealed-manifest-second");
    register_test_authority(&state, &authority);
    register_test_authority(&state, &second);
    let rules = GovernanceRules {
        validators: vec![authority.clone(), second],
        quorum: Some(2),
        protected_namespaces: BTreeSet::from([Name::from_str("apps").unwrap()]),
        ..GovernanceRules::default()
    };
    let status = LaneManifestStatus {
        lane: LaneId::SINGLE,
        alias: "default".to_owned(),
        dataspace: DataSpaceId::UNIVERSAL,
        visibility: LaneVisibility::Public,
        storage: LaneStorageProfile::FullReplica,
        governance: Some("parliament".to_owned()),
        manifest_path: Some(PathBuf::from("/tmp/sealed-manifest-owner.json")),
        governance_rules: Some(rules.clone()),
        privacy_commitments: Vec::new(),
    };
    queue.install_lane_manifests_for_testing(&Arc::new(LaneManifestRegistry::from_statuses(
        BTreeMap::from([(LaneId::SINGLE, status)]),
    )));
    let contract = iroha_data_model::smart_contract::ContractAddress::derive(
        state.network_id_ref(),
        &authority,
        0,
        DataSpaceId::UNIVERSAL,
    )
    .unwrap();
    let mut metadata = Metadata::default();
    metadata.insert(
        (*super::GOV_CONTRACT_ADDRESS_METADATA_KEY).clone(),
        Json::new(contract.to_string()),
    );
    let signed = accepted_tx_with(
        authority.clone(),
        &key,
        &time,
        vec![InstructionBox::from(ActivateContractInstance {
            contract_address: contract,
            expected_revision: 1,
            code_hash: Hash::new(b"sealed-protected-operation"),
        })],
        metadata,
    )
    .external()
    .expect("authored signed fixture")
    .clone();
    let salt = [0x65; 32];
    let commitment =
        compute_sealed_transaction_commitment(state.network_id_ref(), &signed, salt, 9);
    let source = TransactionEntrypoint::SealedCommitment(SignedSealedTransactionCommitment::sign(
        SealedTransactionCommitmentPayload::new(
            *state.network_id_ref(),
            authority,
            commitment,
            2,
            9,
            None,
        ),
        key.private_key(),
    ));
    let accept = |entrypoint| {
        AcceptedTransaction::accept_entrypoint_at_time(
            entrypoint,
            state.network_id_ref(),
            Duration::ZERO,
            TransactionParameters::default(),
            &iroha_config::parameters::actual::Crypto::default(),
            Duration::ZERO,
        )
        .expect("original Network signature and closed carrier pass admission")
    };
    let accepted = accept(source.clone());
    let bytes = accepted.entrypoint_bytes();
    let hash = accepted.hash_as_entrypoint();
    assert!(accepted.external().is_none());
    queue.push(accepted.clone(), state.view()).expect(
        "a governed-lane commitment retains its original carrier without signed projection",
    );
    let pending = queue
        .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].entrypoint(), &source);
    assert_eq!(pending[0].hash_as_entrypoint(), hash);
    assert_eq!(pending[0].entrypoint_bytes().as_slice(), bytes.as_slice());
    assert_eq!((queue.active_len(), queue.queued_len()), (1, 1));
    let checked = CheckedTransaction::new_unchecked(accepted);
    assert!(
        matches!(
            Queue::enforce_manifest_quorum("default", &rules, &checked),
            Err(Error::GovernanceNotPermitted { reason, .. })
                if reason == "lane manifest quorum requires 2 validator approvals but 1 were provided"
        ),
        "absence of an executable must not satisfy a required approval quorum"
    );
    let reveal = accept(TransactionEntrypoint::SealedReveal(
        SealedTransactionReveal::new(commitment, signed, salt),
    ));
    let original_reveal = reveal.entrypoint_bytes();
    let refused = queue
        .push(reveal.clone(), state.view())
        .expect_err("revealing protected instructions still requires actual validator approvals");
    assert!(
        matches!(refused.err, Error::GovernanceNotPermitted { reason, .. }
        if reason == "lane manifest quorum requires 2 validator approvals but 1 were provided")
    );
    assert_eq!(refused.tx.entrypoint(), reveal.entrypoint());
    assert_eq!(
        refused.tx.entrypoint_bytes().as_slice(),
        original_reveal.as_slice()
    );
    assert_eq!((queue.active_len(), queue.queued_len()), (1, 1));
}

#[test]
fn native_lane_candidates_preserve_complete_sealed_reveal_and_pending_identity() {
    use crate::sumeragi::{
        lanes::{executor::LaneTransactions, global::QueueLaneTransactions},
        test_chain::{CertifiedTestChain, TestChainConfig, fixture_validators},
    };
    use iroha_data_model::sumeragi_lanes::{
        SumeragiFixedLane, SumeragiLaneMember, SumeragiLanePolicy,
    };
    let busy_route = RoutingDecision::new(LaneId::new(1), DataSpaceId::new(7));
    let mut nexus = test_nexus_for_routes(&[
        (busy_route.lane_id, busy_route.dataspace_id),
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
    ]);
    nexus.routing_policy.default_lane = busy_route.lane_id;
    nexus.routing_policy.default_dataspace = busy_route.dataspace_id;
    let (authority_id, authority_keypair) = gen_account_in("full-block-gas-lane");
    let mut committee = fixture_validators()
        .into_iter()
        .map(|(peer, pop)| SumeragiLaneMember { peer, pop })
        .collect::<Vec<_>>();
    committee.sort();
    let policy = SumeragiLanePolicy {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        anchor_freshness: 4,
        max_merge_blocks: 8,
        stall_window: 1000,
        lane_params: iroha_data_model::parameter::system::SumeragiParameters::default(),
        fixed: vec![SumeragiFixedLane {
            lane: busy_route.lane_id,
            dataspace: busy_route.dataspace_id,
            committee,
        }],
        routes: Vec::new(),
        autoscale: None,
    };
    let world = World::with(
        [],
        [Account::new(authority_id.clone()).build(&authority_id)],
        [],
    );
    let mut config = TestChainConfig::new(world, 1000);
    config.nexus = Some(nexus);
    config
        .genesis_parameters
        .push(Parameter::Custom(policy.into_custom_parameter()));
    let mut chain = CertifiedTestChain::start(config).expect("original signed native lane policy");
    chain.commit_at(2000, Vec::new());
    chain.commit_at(3000, Vec::new());
    let state = Arc::clone(chain.state());
    assert!(
        state
            .world_view()
            .sumeragi_lanes()
            .lane(busy_route.lane_id)
            .unwrap()
            .admits_anchor(3)
    );
    assert_eq!(state.nexus_snapshot().lane_catalog.lanes().len(), 2);
    let block_gas = crate::state::gas_limit_from_parameters(state.world_view().parameters());
    let (_, time) = TimeSource::new_mock(Duration::from_millis(3001));
    let queue = Arc::new(Queue::test(config_factory(), &time));
    let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
        state.network_id_ref(),
        &authority_id,
        1,
        busy_route.dataspace_id,
    )
    .unwrap();
    let signed = TransactionBuilder::new_with_time_source(
        *state.network_id_ref(),
        authority_id,
        &time,
        FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(block_gas)),
    )
    .with_executable(Executable::ContractCall(
        iroha_data_model::transaction::executable::ContractInvocation {
            contract_address,
            expected_code_hash: Hash::new(b"current-full-block-gas-call"),
            entrypoint: "configure".to_owned(),
            arguments: None,
        },
    ))
    .sign(authority_keypair.private_key());
    let salt = [0x74; 32];
    let commitment = iroha_data_model::transaction::signed::compute_sealed_transaction_commitment(
        state.network_id_ref(),
        &signed,
        salt,
        9,
    );
    let source = TransactionEntrypoint::SealedReveal(
        iroha_data_model::transaction::signed::SealedTransactionReveal::new(
            commitment, signed, salt,
        ),
    );
    let accepted = AcceptedTransaction::accept_entrypoint_at_time(
        source.clone(),
        state.network_id_ref(),
        Duration::from_millis(10),
        TransactionParameters::default(),
        &iroha_config::parameters::actual::Crypto::default(),
        time.now(),
    )
    .unwrap();

    let original_bytes = accepted.entrypoint_bytes();
    let original_hash = accepted.hash_as_entrypoint();
    let signed_hash = accepted.external().unwrap().hash_as_entrypoint();
    assert_ne!(original_hash, signed_hash);
    let plan = queue.route_plan_with_state(&accepted, &state).unwrap();
    assert_eq!(plan, RoutingPlan::single(busy_route));
    queue
        .push_with_lane_with_state_and_routing_plan(accepted.clone(), &state, plan.clone())
        .unwrap();
    let lane = QueueLaneTransactions::new(
        busy_route.lane_id,
        Arc::clone(&queue),
        Arc::clone(&state),
        time,
    );
    assert!(original_bytes.len() > accepted.encoded_len());
    let budget = state.ivm_execution_budget();
    assert!(
        lane.candidates(4, original_bytes.len() - 1, &BTreeSet::new(), &budget)
            .unwrap()
            .0
            .is_empty(),
        "lane packing counts every original carrier byte"
    );
    for _ in 0..2 {
        let (selected, lease) = lane
            .candidates(4, original_bytes.len(), &BTreeSet::new(), &budget)
            .unwrap();
        assert!(lane.lease_is_current(&lease, &budget).unwrap());
        assert_eq!(selected.len(), 1);
        assert_eq!(
            norito::encode_canonical(&selected[0]).unwrap(),
            norito::encode_canonical(&source).unwrap(),
            "native lane selection must preserve the complete sealed reveal carrier"
        );
        let pending = queue
            .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].entrypoint(), &source);
        assert_eq!(pending[0].hash_as_entrypoint(), original_hash);
        assert_eq!(
            pending[0].entrypoint_bytes().as_slice(),
            original_bytes.as_slice()
        );
        assert_eq!(
            queue.routing_plans.get(&original_hash).unwrap().value(),
            &plan
        );
        assert_eq!((queue.active_len(), queue.queued_len()), (1, 1));
        assert!(
            lane.candidates(
                4,
                original_bytes.len(),
                &BTreeSet::from([original_hash]),
                &budget
            )
            .unwrap()
            .0
            .is_empty()
        );
    }
}

#[test]
fn ordinary_sccp_admission_needs_no_history_but_exempt_shapes_bind_original_time() {
    use crate::smartcontracts::isi::sccp::{
        admission,
        hold::{self, SccpCommittedTimeError},
    };
    use iroha_data_model::{
        isi::sccp::SubmitSccpForgeryEvidenceV1, sccp::params::SccpParametersV1,
    };

    let (mut state, time) = current_admission_queue_fixture();
    {
        let mut fees = state.nexus_snapshot().fees;
        fees.base_fee = Quantity::from(1_u32);
        {
            let mut parameters = state.world.parameters.block();
            parameters
                .set_parameter(iroha_data_model::parameter::Parameter::Custom(
                    fees.clone()
                        .into_custom_parameter()
                        .expect("explicit fixture policy"),
                ))
                .expect("valid fixture monetary projection");
            parameters.commit();
        }
    }
    // Deliberately incomplete positive-height history: it must never authenticate
    // an exemption, but ordinary instructions have no SCCP eligibility dependency.
    seed_committed_height_for_queue_test(&state, 1);
    let queue = Queue::test(config_factory(), &time);
    let (authority, key) = gen_account_in("ordinary-sccp-admission");
    let ordinary = accepted_tx_with(
        authority.clone(),
        &key,
        &time,
        vec![Log::new(Level::INFO, "ordinary fee-paying work".into()).into()],
        Metadata::default(),
    );
    let shaped = accepted_tx_with(
        authority,
        &key,
        &time,
        vec![
            SubmitSccpForgeryEvidenceV1 {
                qc: [1; 116],
                header: [2; 221],
                aggregate_signature: [3; 96],
                anchor: None,
            }
            .into(),
        ],
        Metadata::default(),
    );
    assert!(admission::exempt_shape(ordinary.external().unwrap().payload()).is_none());
    assert!(admission::exempt_shape(shaped.external().unwrap().payload()).is_some());
    for sccp_exists in [false, true] {
        {
            let mut world = state.world.block();
            *world.sccp_parameters.get_mut() = sccp_exists.then(SccpParametersV1::taira_default);
            world.commit();
        }
        let view = state.view();
        assert_eq!(
            hold::committed_time_ms(&view),
            Err(SccpCommittedTimeError::Missing)
        );
        let mut access = EagerAdmissionStateAccess::new(&view, 2, 0);
        assert!(
            matches!(
                access.sccp_exempt_admission(&queue, ordinary.external().unwrap()),
                Ok(None)
            ),
            "ordinary fee-paying work has no SCCP committed-history dependency"
        );
        assert!(
            matches!(
                access.recheck_external_nexus_fee_admission(&queue, &ordinary, Some(DataSpaceId::UNIVERSAL)),
                Err(Error::NexusFeeAdmissionRejected { code: FeeRejectionCode::InvalidFeeIntent, reason })
                if reason == "signed fee intent is missing Nexus charge limit"
            ),
            "ordinary work still requires its exact signed Nexus fee limit"
        );
        let fee_result = access.recheck_external_nexus_fee_admission(
            &queue,
            &shaped,
            Some(DataSpaceId::UNIVERSAL),
        );
        let result = access.sccp_exempt_admission(&queue, shaped.external().unwrap());
        if sccp_exists {
            assert!(
                matches!(result, Err(Error::AdmissionInvariant { reason })
                if reason == SccpCommittedTimeError::Missing.to_string()),
                "an actual SCCP exemption must reject missing original committed time"
            );
            assert!(
                matches!(fee_result, Err(Error::AdmissionInvariant { reason })
                if reason == SccpCommittedTimeError::Missing.to_string()),
                "fee exemptions require the same authenticated SCCP committed time"
            );
        } else {
            assert!(
                matches!(result, Ok(None)),
                "absent SCCP grants no exemption"
            );
            assert!(
                matches!(fee_result, Err(Error::NexusFeeAdmissionRejected { code: FeeRejectionCode::InvalidFeeIntent, reason })
                if reason == "signed fee intent is missing Nexus charge limit"),
                "absent SCCP still requires the ordinary signed fee limit"
            );
        }
        assert_eq!(queue.active_len(), 0);
        assert_eq!(queue.queued_len(), 0);
    }
}

#[test]
fn public_pause_admission_checks_authority_and_original_time_before_fee_exemption() {
    use crate::smartcontracts::isi::sccp::{admission, hold::SccpCommittedTimeError};
    use iroha_data_model::{
        bridge::SccpNetworkV1,
        isi::sccp::{AcceptSccpPausePanelSeatV1, EndorseSccpFastPauseV1},
        sccp::params::SccpParametersV1,
    };

    let (state, time) = current_admission_queue_fixture();
    seed_committed_height_for_queue_test(&state, 1);
    {
        let mut world = state.world.block();
        *world.sccp_parameters.get_mut() = Some(SccpParametersV1::taira_default());
        world.commit();
    }
    let queue = Queue::test(config_factory(), &time);
    let (authority, key) = gen_account_in("public-pause-admission");
    let accept = accepted_tx_with(
        authority.clone(),
        &key,
        &time,
        vec![AcceptSccpPausePanelSeatV1 { panel_seq: 1 }.into()],
        Metadata::default(),
    );
    let endorse = accepted_tx_with(
        authority,
        &key,
        &time,
        vec![
            EndorseSccpFastPauseV1 {
                network_id: *state.view().network_id(),
                network: SccpNetworkV1::EthereumMainnet,
                panel_id: [1; 32],
                head: 0,
                incident_digest: [2; 32],
            }
            .into(),
        ],
        Metadata::default(),
    );
    let view = state.view();
    let mut access = EagerAdmissionStateAccess::new(&view, 2, 0);
    for transaction in [&accept, &endorse] {
        assert!(admission::exempt_shape(transaction.external().unwrap().payload()).is_none());
    }
    assert!(matches!(
        access.sccp_exempt_admission(&queue, accept.external().unwrap()),
        Err(Error::NexusFeeAdmissionRejected { code: FeeRejectionCode::OperationNotAllowed, reason })
            if reason.contains("no standing panel")
    ));
    assert!(matches!(
        access.sccp_exempt_admission(&queue, endorse.external().unwrap()),
        Err(Error::AdmissionInvariant { reason })
            if reason == SccpCommittedTimeError::Missing.to_string()
    ));
    assert_eq!((queue.active_len(), queue.queued_len()), (0, 0));
}
