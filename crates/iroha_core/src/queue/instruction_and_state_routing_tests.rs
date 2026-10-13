// Instruction fixtures and committed-state routing regression tests.
use ivm::ProgramMetadata;
fn minimal_contract_bytes() -> (iroha_crypto::Hash, Vec<u8>) {
    let mut program = ivm::ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 1,
        abi_version: 1,
    }
    .encode();
    program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    ProgramMetadata::parse(&program).expect("parse minimal program");
    let code_hash = ivm::contract_code_hash(&program);
    (code_hash, program)
}
fn sample_unregister_instruction() -> InstructionBox {
    let domain_name = unique_test_domain_name("dummy");
    InstructionBox::from(Unregister::domain(
        DomainId::try_new(&domain_name, "universal").unwrap(),
    ))
}
const RUNTIME_UPGRADE_ALLOWED_ID: &str = "upgrade-q1";
fn sample_runtime_upgrade_manifest_bytes() -> Vec<u8> {
    RuntimeUpgradeManifest {
        name: "upgrade.v1.test".to_string(),
        description: "test upgrade for runtime hook enforcement (v1)".to_string(),
        abi_version: 1,
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        added_syscalls: vec![],
        added_pointer_types: vec![],
        start_height: 42,
        end_height: 84,
        sbom_digests: Vec::new(),
        slsa_attestation: Vec::new(),
        provenance: Vec::new(),
    }
    .canonical_bytes()
}
fn runtime_upgrade_instruction() -> InstructionBox {
    InstructionBox::from(ProposeRuntimeUpgrade {
        manifest_bytes: sample_runtime_upgrade_manifest_bytes(),
    })
}
fn accepted_tx_by(
    account_id: AccountId,
    key_pair: &KeyPair,
    time_source: &TimeSource,
) -> AcceptedTransaction<'static> {
    let instructions = vec![sample_unregister_instruction()];
    accepted_tx_with(
        account_id,
        key_pair,
        time_source,
        instructions,
        Metadata::default(),
    )
}
fn accepted_tx_with(
    account_id: AccountId,
    key_pair: &KeyPair,
    time_source: &TimeSource,
    instructions: Vec<InstructionBox>,
    metadata: Metadata,
) -> AcceptedTransaction<'static> {
    accepted_tx_with_attachments(
        account_id,
        key_pair,
        time_source,
        instructions,
        metadata,
        None,
    )
}
fn accepted_tx_with_attachments(
    account_id: AccountId,
    key_pair: &KeyPair,
    time_source: &TimeSource,
    instructions: Vec<InstructionBox>,
    metadata: Metadata,
    attachments: Option<Vec<ProofAttachment>>,
) -> AcceptedTransaction<'static> {
    let network_id = queue_test_network_id();
    let mut builder = TransactionBuilder::new_with_time_source(
        network_id,
        account_id,
        time_source,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instructions)
    .with_metadata(metadata);
    if let Some(att) = attachments {
        builder = builder
            .with_proof_attachments(att)
            .expect("valid proof carriers");
    }
    let tx = builder.sign(key_pair.private_key());
    let default_limits = TransactionParameters::default();
    let tx_limits = TransactionParameters::with_max_signatures(
        nonzero!(16_u64),
        nonzero!(4096_u64),
        nonzero!(1024_u64),
        default_limits.max_tx_bytes(),
        default_limits.max_decompressed_bytes(),
        default_limits.max_metadata_depth(),
    );
    let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
    AcceptedTransaction::accept_with_time_source(
        tx,
        &network_id,
        Duration::from_millis(10),
        tx_limits,
        &crypto_cfg,
        time_source,
    )
    .expect("Failed to accept Transaction.")
}
#[cfg(feature = "telemetry")]
fn accepted_ivm_tx_by(
    account_id: AccountId,
    key_pair: &KeyPair,
    time_source: &TimeSource,
    max_cycles: u64,
) -> AcceptedTransaction<'static> {
    let network_id = queue_test_network_id();
    let program = minimal_ivm_program_with_max_cycles(1, max_cycles);
    let gas_limit = crate::smartcontracts::ivm::gas_limit_for_cycles(
        std::num::NonZeroU64::new(max_cycles)
            .expect("queue IVM fixture requires a positive cycle limit"),
    );
    let tx = TransactionBuilder::new_with_time_source(
        network_id,
        account_id,
        time_source,
        iroha_data_model::transaction::FeePaymentIntent::authority(
            Vec::new(),
            std::num::NonZeroU64::new(gas_limit),
        ),
    )
    .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program)))
    .sign(key_pair.private_key());
    let default_limits = TransactionParameters::default();
    let tx_limits = TransactionParameters::with_max_signatures(
        nonzero!(16_u64),
        nonzero!(4096_u64),
        nonzero!(1024_u64),
        default_limits.max_tx_bytes(),
        default_limits.max_decompressed_bytes(),
        default_limits.max_metadata_depth(),
    );
    let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
    AcceptedTransaction::accept_with_time_source(
        tx,
        &network_id,
        Duration::from_millis(10),
        tx_limits,
        &crypto_cfg,
        time_source,
    )
    .expect("Failed to accept IVM transaction.")
}
#[cfg(feature = "telemetry")]
fn minimal_ivm_program_with_max_cycles(abi_version: u8, max_cycles: u64) -> Vec<u8> {
    let mut program = ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles,
        abi_version,
    }
    .encode();
    program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    ProgramMetadata::parse(&program).expect("parse minimal IVM program");
    program
}
/// Build a routing component World with the shared authority and explicit Global metadata.
pub fn world_with_test_domains() -> World {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("Valid");
    let account_id = AccountId::new(ALICE_KEYPAIR.public_key().clone());
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = Account::new(account_id.clone()).build(&account_id);
    let world = World::with([domain], [account], []);
    // This component fixture needs explicit routing metadata; it has no signed
    // genesis, certified history or native publication authority.
    let mut parameters = world.parameters.block();
    parameters
        .set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        ))
        .expect("valid fixture parameters");
    parameters.commit();
    world
}
fn register_test_authority(state: &State, authority: &AccountId) {
    let mut world = state.world.block();
    world.accounts.insert(
        authority.clone(),
        AccountValue::new(AccountDetails::default()),
    );
    world.commit();
}
struct NexusRoutingFixture {
    state: State,
    authority_id: AccountId,
    authority_keypair: KeyPair,
}
fn nexus_routing_fixture() -> NexusRoutingFixture {
    nexus_routing_fixture_with_nexus(Nexus::default())
}
fn nexus_routing_fixture_with_nexus(nexus: Nexus) -> NexusRoutingFixture {
    let (authority_id, authority_keypair) = gen_account_in("wonderland");
    let domain_id = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id).build(&authority_id);
    let authority = Account::new(authority_id.clone()).build(&authority_id);
    let world = World::with([domain], [authority], []);
    // This component fixture needs explicit routing metadata; it has no signed
    // genesis, certified history or native publication authority.
    let mut parameters = world.parameters.block();
    parameters
        .set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        ))
        .expect("valid fixture parameters");
    parameters.commit();
    let state = State::new_with_nexus_for_testing(world, nexus, LiveQueryStore::start_test());
    NexusRoutingFixture {
        state,
        authority_id,
        authority_keypair,
    }
}
include!("gossip_routing_metadata_tests.rs");
include!("gossip_route_validation_tests.rs");
#[test]
fn route_for_gossip_with_state_falls_back_to_view_router_path() {
    struct ViewOnlyRouter {
        lane: LaneId,
        dataspace: DataSpaceId,
    }
    impl LaneRouter for ViewOnlyRouter {
        fn try_route(
            &self,
            _tx: &dyn TransactionRoutingView,
        ) -> Result<RoutingDecision, RoutingResolveError> {
            Ok(RoutingDecision::new(self.lane, self.dataspace))
        }
        fn try_route_with_view(
            &self,
            _tx: &dyn TransactionRoutingView,
            _state_view: &StateView<'_>,
        ) -> Result<RoutingDecision, RoutingResolveError> {
            Ok(RoutingDecision::new(self.lane, self.dataspace))
        }
        fn try_route_without_state(
            &self,
            _tx: &dyn TransactionRoutingView,
        ) -> Result<Option<RoutingDecision>, RoutingResolveError> {
            Ok(None)
        }
    }
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let expected_lane = LaneId::SINGLE;
    let expected_dataspace = DataSpaceId::UNIVERSAL;
    let queue = Queue::test_with_router(
        config_factory(),
        &time_source,
        Arc::new(ViewOnlyRouter {
            lane: expected_lane,
            dataspace: expected_dataspace,
        }),
    );
    let tx = accepted_tx_by_someone(&time_source);
    let routing = queue
        .route_plan_for_gossip_with_state(&tx, state.as_ref())
        .map(|plan| plan.coordinator_route())
        .expect("route should resolve with configured catalogs");
    assert_eq!(routing.lane_id, expected_lane);
    assert_eq!(routing.dataspace_id, expected_dataspace);
}
#[test]
fn route_plan_with_state_syncs_queue_router_to_fresh_default_lane() {
    let query_handle = LiveQueryStore::start_test();
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let fresh = RoutingDecision::new(LaneId::new(3), DataSpaceId::UNIVERSAL);
    let (fresh_lanes, fresh_dataspaces) = Queue::test_catalogs_for_routes(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (fresh.lane_id, fresh.dataspace_id),
    ]);
    let mut nexus = Nexus::default();
    nexus.autoscale.enabled = false;
    nexus.lane_catalog = (*fresh_lanes).clone();
    nexus.dataspace_catalog = (*fresh_dataspaces).clone();
    nexus.fees.base_fee = Quantity::zero();
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    nexus.routing_policy.default_lane = fresh.lane_id;
    nexus.routing_policy.default_dataspace = fresh.dataspace_id;
    let state = State::new_with_nexus_for_testing(world_with_test_domains(), nexus, query_handle);
    let queue = Queue::test(config_factory(), &time_source);
    assert_eq!(
        queue.routing_policy.read().default_lane,
        LaneId::SINGLE,
        "queue fixture should intentionally start with stale routing policy"
    );
    let (account_id, key_pair) = gen_account_in("wonderland");
    register_test_authority(&state, &account_id);
    let tx = accepted_tx_with(
        account_id,
        &key_pair,
        &time_source,
        vec![InstructionBox::from(Log::new(
            Level::INFO,
            "fresh default route".into(),
        ))],
        Metadata::default(),
    );
    let routing = queue
        .route_plan_with_state(&tx, &state)
        .map(|plan| plan.coordinator_route())
        .expect("state-aware routing should sync to the fresh default lane");
    assert_eq!(routing, fresh);
    assert_eq!(queue.routing_policy.read().default_lane, fresh.lane_id);
    let gossip_routing = queue
        .route_plan_for_gossip_with_state(&tx, &state)
        .map(|plan| plan.coordinator_route())
        .expect("gossip routing should use the synchronized default lane");
    assert_eq!(gossip_routing, fresh);
}
#[test]
fn push_in_view_syncs_queue_router_to_fresh_default_lane() {
    let query_handle = LiveQueryStore::start_test();

    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let fresh = RoutingDecision::new(LaneId::new(3), DataSpaceId::UNIVERSAL);
    let (fresh_lanes, fresh_dataspaces) = Queue::test_catalogs_for_routes(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (fresh.lane_id, fresh.dataspace_id),
    ]);
    let mut nexus = Nexus::default();
    nexus.autoscale.enabled = false;
    nexus.lane_catalog = (*fresh_lanes).clone();
    nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    nexus.dataspace_catalog = (*fresh_dataspaces).clone();
    nexus.fees.base_fee = Quantity::zero();
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    nexus.routing_policy.default_lane = fresh.lane_id;
    nexus.routing_policy.default_dataspace = fresh.dataspace_id;
    let state = State::new_with_nexus_for_testing(world_with_test_domains(), nexus, query_handle);
    let queue = Queue::test(config_factory(), &time_source);
    assert_eq!(
        queue.routing_policy.read().default_lane,
        LaneId::SINGLE,
        "queue fixture should intentionally start with stale routing policy"
    );
    let (account_id, key_pair) = gen_account_in("wonderland");
    register_test_authority(&state, &account_id);
    let tx = accepted_tx_with(
        account_id,
        &key_pair,
        &time_source,
        vec![InstructionBox::from(Log::new(
            Level::INFO,
            "fresh default push route".into(),
        ))],
        Metadata::default(),
    );
    let hash = tx.hash_as_entrypoint();
    queue
        .push(tx, state.view())
        .expect("push should sync route");
    assert_eq!(
        queue
            .routing_plans
            .get(&hash)
            .map(|entry| entry.value().coordinator_route()),
        Some(fresh)
    );
    assert_eq!(queue.routing_policy.read().default_lane, fresh.lane_id);
}
#[test]
fn route_plan_with_state_rejects_stale_policy_even_when_old_lane_still_exists() {
    let query_handle = LiveQueryStore::start_test();
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let old_route = RoutingDecision::new(LaneId::new(3), DataSpaceId::UNIVERSAL);
    let current_route = RoutingDecision::new(LaneId::new(4), DataSpaceId::UNIVERSAL);
    let (lane_catalog, dataspace_catalog) = Queue::test_catalogs_for_routes(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (old_route.lane_id, old_route.dataspace_id),
        (current_route.lane_id, current_route.dataspace_id),
    ]);
    let current_rule = LaneRoutingRule {
        lane: current_route.lane_id,
        dataspace: Some(current_route.dataspace_id),
        matcher: LaneRoutingMatcher {
            account: None,
            instruction: Some("unregister::domain".to_string()),
            description: None,
        },
    };
    let mut current_nexus = Nexus::default();
    current_nexus.autoscale.enabled = false;

    current_nexus.lane_catalog = (*lane_catalog).clone();
    current_nexus.dataspace_catalog = (*dataspace_catalog).clone();
    current_nexus.routing_policy.rules = vec![current_rule.clone()];
    let state =
        State::new_with_nexus_for_testing(world_with_test_domains(), current_nexus, query_handle);
    let current_nexus = state.nexus_snapshot();
    let mut stale_nexus = current_nexus;
    stale_nexus.routing_policy.rules = vec![LaneRoutingRule {
        lane: old_route.lane_id,
        dataspace: Some(old_route.dataspace_id),
        matcher: current_rule.matcher,
    }];
    let queue = Queue::test(config_factory(), &time_source);
    queue.reconfigure_nexus_with_state(&stale_nexus, &state, None);
    assert!(
        queue
            .routing_policy
            .read()
            .rules
            .iter()
            .any(|rule| rule.lane == old_route.lane_id),
        "queue fixture should intentionally retain the stale routing rule"
    );
    let tx = accepted_tx_by_someone(&time_source);
    let routing = queue
        .route_plan_with_state(&tx, &state)
        .map(|plan| plan.coordinator_route())
        .expect("state-aware routing should sync away from the stale routing rule");
    assert_eq!(routing, current_route);
    assert!(
        queue
            .routing_policy
            .read()
            .rules
            .iter()
            .any(|rule| rule.lane == current_route.lane_id)
    );
    let gossip_routing = queue
        .route_plan_for_gossip_with_state(&tx, &state)
        .map(|plan| plan.coordinator_route())
        .expect("gossip routing should use the synchronized routing rule");
    assert_eq!(gossip_routing, current_route);
}
#[test]
fn precomputed_state_routing_plan_rejects_stale_policy_even_when_old_lane_still_exists() {
    let query_handle = LiveQueryStore::start_test();
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let old_route = RoutingDecision::new(LaneId::new(3), DataSpaceId::UNIVERSAL);
    let current_route = RoutingDecision::new(LaneId::new(4), DataSpaceId::UNIVERSAL);
    let (lane_catalog, dataspace_catalog) = Queue::test_catalogs_for_routes(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (old_route.lane_id, old_route.dataspace_id),
        (current_route.lane_id, current_route.dataspace_id),
    ]);
    let matcher = LaneRoutingMatcher {
        account: None,
        instruction: Some("unregister::domain".to_string()),
        description: None,
    };
    let mut current_nexus = Nexus::default();
    current_nexus.autoscale.enabled = false;

    current_nexus.lane_catalog = (*lane_catalog).clone();
    current_nexus.dataspace_catalog = (*dataspace_catalog).clone();
    current_nexus.routing_policy.rules = vec![LaneRoutingRule {
        lane: current_route.lane_id,
        dataspace: Some(current_route.dataspace_id),
        matcher: matcher.clone(),
    }];
    let state =
        State::new_with_nexus_for_testing(world_with_test_domains(), current_nexus, query_handle);
    let current_nexus = state.nexus_snapshot();
    let mut stale_nexus = current_nexus;
    stale_nexus.routing_policy.rules = vec![LaneRoutingRule {
        lane: old_route.lane_id,
        dataspace: Some(old_route.dataspace_id),
        matcher,
    }];
    let queue = Queue::test(config_factory(), &time_source);
    queue.reconfigure_nexus_with_state(&stale_nexus, &state, None);
    let tx = accepted_tx_by_someone(&time_source);
    let hash = tx.hash_as_entrypoint();
    let stale_plan = RoutingPlan::single(old_route);
    assert_eq!(stale_plan.coordinator_route(), old_route);
    let err = queue
        .push_with_gossip_payload_with_state_and_routing_plan(tx, &state, stale_plan, None)
        .expect_err("stale precomputed plan should be rejected");
    assert!(
        matches!(
            &err,
            Failure {
                err: Error::UnresolvedRoute { .. },
                ..
            }
        ),
        "unexpected stale-plan rejection: {err:?}"
    );
    assert!(!queue.txs.contains_key(&hash));
    assert_eq!(
        queue.routing_policy.read().rules[0].lane,
        current_route.lane_id,
        "admission should synchronize from committed Nexus before validating the plan"
    );
}
#[test]
fn reconfiguration_does_not_consult_replacement_router_for_pending_work() {
    struct ViewOnlyRouter {
        lane: LaneId,
        dataspace: DataSpaceId,
    }
    impl LaneRouter for ViewOnlyRouter {
        fn try_route(
            &self,
            _tx: &dyn TransactionRoutingView,
        ) -> Result<RoutingDecision, RoutingResolveError> {
            Ok(RoutingDecision::new(self.lane, self.dataspace))
        }
        fn try_route_with_view(
            &self,
            _tx: &dyn TransactionRoutingView,
            _state_view: &StateView<'_>,
        ) -> Result<RoutingDecision, RoutingResolveError> {
            Ok(RoutingDecision::new(self.lane, self.dataspace))
        }
        fn try_route_without_state(
            &self,
            _tx: &dyn TransactionRoutingView,
        ) -> Result<Option<RoutingDecision>, RoutingResolveError> {
            Ok(None)
        }
    }
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(config_factory(), &time_source);
    let tx = accepted_tx_by_someone(&time_source);
    let hash = tx.hash_as_entrypoint();
    queue.push(tx, state.view()).expect("push");
    let expected_lane = LaneId::SINGLE;
    let expected_dataspace = DataSpaceId::UNIVERSAL;
    let router: Arc<dyn LaneRouter> = Arc::new(ViewOnlyRouter {
        lane: expected_lane,
        dataspace: expected_dataspace,
    });
    let lane_catalog = queue.lane_catalog.read().clone();
    let dataspace_catalog = queue.dataspace_catalog.read().clone();
    queue.revalidate_pending_transactions_with_state(
        &router,
        state.as_ref(),
        &lane_catalog,
        &dataspace_catalog,
        true,
    );
    let routing = queue
        .routing_plans
        .get(&hash)
        .expect("routing plan should exist")
        .coordinator_route();
    assert_eq!(routing.lane_id, expected_lane);
    assert_eq!(routing.dataspace_id, expected_dataspace);
}
