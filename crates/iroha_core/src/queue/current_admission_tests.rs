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
                .push_with_gossip_payload_with_state_and_routing_plan(
                    transaction.clone(),
                    &state,
                    plan.clone(),
                    None,
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
        Queue::compute_proposal_gas_cost(&accepted, &crate::gas::DEFAULT_ZK_GAS),
        Ok(block_gas)
    );
    let original = accepted.entrypoint_bytes().to_vec();
    let hash = accepted.hash_as_entrypoint();
    let max_bytes = accepted.encoded_len();
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
            .candidates(4, max_bytes, &BTreeSet::new())
            .expect("completed original lane routing read");
        assert_eq!(
            selected.len(),
            1,
            "an idle catalog route must not split the gas budget"
        );
        let original_signed: &SignedTransaction = accepted.as_ref();
        assert_eq!(&selected[0], original_signed);
        let pending = queue
            .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].entrypoint_bytes().as_slice(),
            original.as_slice()
        );
        assert_eq!(
            Queue::compute_proposal_gas_cost(&pending[0], &crate::gas::DEFAULT_ZK_GAS),
            Ok(block_gas)
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
