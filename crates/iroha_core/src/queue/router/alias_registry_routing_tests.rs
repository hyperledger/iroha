//! Signed admission, routing, and native execution regressions for additive SNS bootstrap.
use crate::{
    alias_setup::{alias_intent_owner, selector_for_resolved_alias_target},
    queue::{
        ConfigLaneRouter, LaneRouter, RoutingDecision, RoutingPlan, RoutingResolveError,
        evaluate_policy_plan_with_nexus_and_world_at,
        evaluate_policy_plan_with_nexus_and_world_at_block_height,
    },
    smartcontracts::ivm::cache::IvmCache,
    sns,
    state::{State, StateReadOnly, World, WorldReadOnly},
    sumeragi::{
        startup,
        test_chain::{CertifiedTestChain, TestChainConfig, fixture_validators},
    },
    tx::AcceptedTransaction,
};
use iroha_config::parameters::actual::{LaneRoutingMatcher, LaneRoutingRule};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    IntoKeyValue,
    alias_setup::{
        AccountAliasRoleV1, AccountProvisionV1, AliasAccountIntentV1, AliasDataSpaceIntentV1,
        AliasDataspaceBootstrapGrantV1, AliasDomainIntentV1, AliasIntentV1,
        AliasLeaseAcquisitionV1, AliasQuoteGuardV1, ResolvedAccountAliasV1, ResolvedDataSpaceV1,
        ResolvedDomainV1,
    },
    consensus::{ConsensusKeyRecord, ConsensusKeyStatus},
    isi::{
        alias_setup::{EnsureAlias, RenewAliasLease},
        consensus_keys::RegisterConsensusKey,
    },
    nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig},
    prelude::*,
};
use iroha_executor_data_model::permission::{
    governance::CanManageConsensusKeys, parameter::CanSetParameters,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::topology::DataSpaceId;
use iroha_model_base::topology::LaneId;
use iroha_primitives::time::TimeSource;
use mv::storage::StorageReadOnly;
use std::{
    cell::RefCell, collections::BTreeSet, num::NonZeroU32, num::NonZeroU64, sync::Arc,
    time::Duration,
};

const PRIVATE_DATASPACE: DataSpaceId = DataSpaceId::new(10);
const PRIVATE_LANE: LaneId = LaneId::new(1);
const BPNG_LANE: LaneId = LaneId::new(2);

struct Fixture {
    state: Arc<State>,
    chain: RefCell<CertifiedTestChain>,
    signer: KeyPair,
    catalog_signer: KeyPair,
    owner: AccountId,
    collector: AccountId,
    payment_asset: AssetDefinitionId,
}

fn fixture() -> Fixture {
    fixture_with_expanded_catalog(false)
}

fn fixture_with_expanded_catalog(include_bpng: bool) -> Fixture {
    let (config, signer, owner, collector, payment_asset) = fixture_config();
    let catalog_signer = config.genesis_key.clone();
    let chain =
        CertifiedTestChain::start(config).expect("apply original paid alias signed genesis");
    let fixture = Fixture {
        state: Arc::clone(chain.state()),
        chain: RefCell::new(chain),
        signer,
        catalog_signer,
        owner,
        collector,
        payment_asset,
    };
    if include_bpng {
        commit_bpng_catalog(&fixture);
    }
    fixture
}

fn fixture_config() -> (
    TestChainConfig,
    KeyPair,
    AccountId,
    AccountId,
    AssetDefinitionId,
) {
    let signer = KeyPair::try_from_seed(vec![0xD1; 32], Algorithm::Ed25519).expect("signer");
    let owner = AccountId::new(signer.public_key().clone());
    let collector = AccountId::new(
        KeyPair::try_from_seed(vec![0xD2; 32], Algorithm::Ed25519)
            .expect("collector")
            .public_key()
            .clone(),
    );
    let payment_asset: AssetDefinitionId =
        iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
            .parse()
            .expect("current configured XOR");
    let domain = Domain::new(DomainId::try_new("genesis", "universal").expect("genesis domain"))
        .build(&collector);
    let definition = AssetDefinition::numeric(
        payment_asset.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&collector);
    let mut world = World::with_assets(
        [domain],
        [
            Account::new(owner.clone()).build(&collector),
            Account::new(collector.clone()).build(&collector),
        ],
        [definition],
        [Asset::new(
            AssetId::of(payment_asset.clone(), owner.clone()),
            Quantity::from(100_u64),
        )],
        [],
    );
    world.account_permissions_mut_for_testing().insert(
        owner.clone(),
        BTreeSet::from([
            Permission::from(CanSetParameters),
            Permission::from(CanManageConsensusKeys),
        ]),
    );
    sns::seed_default_namespace_policies(&mut world);
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.fee_asset_id = payment_asset.to_string();
    // Match the standard State test fixture's zero ordinary transaction fees. The independent
    // SNS quote/lease charge remains enabled and is asserted against actual global XOR balances.
    nexus.fees.base_fee = Quantity::zero();
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    let dataspaces = vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: PRIVATE_DATASPACE,
            alias: "paynet".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
    ];
    nexus.dataspace_catalog = DataSpaceCatalog::new(dataspaces).expect("existing dataspaces");
    nexus.lane_catalog = LaneCatalog::new(
        NonZeroU32::new(2).expect("lane bound"),
        vec![
            LaneConfig::default(),
            LaneConfig {
                id: PRIVATE_LANE,
                dataspace_id: PRIVATE_DATASPACE,
                alias: "paynet".to_owned(),
                ..LaneConfig::default()
            },
        ],
    )
    .expect("existing lanes");
    nexus.routing_policy.rules.push(LaneRoutingRule {
        lane: PRIVATE_LANE,
        dataspace: Some(PRIVATE_DATASPACE),
        matcher: LaneRoutingMatcher {
            account: Some(owner.to_string()),
            ..LaneRoutingMatcher::default()
        },
    });
    nexus.configured_lane_catalog = nexus.lane_catalog.clone();
    nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
    nexus.staking.public_validator_mode =
        iroha_config::parameters::actual::LaneValidatorMode::AdminManaged;
    let validators = fixture_validators();
    for (peer, _) in &validators {
        let id = AccountId::new(peer.public_key().clone());
        let (id, account) = Account::new(id.clone()).build(&id).into_key_value();
        world.accounts.insert(id, account);
    }
    let mut config = TestChainConfig::new(world, 0);
    // The original genesis authority also owns the universal catalog transition.
    // Grant its exact permissions before native genesis execution; the alias
    // payer keeps its private physical route and existing permission unchanged.
    let genesis_authority = AccountId::new(config.genesis_key.public_key().clone());
    config.world.account_permissions_mut_for_testing().insert(
        genesis_authority,
        BTreeSet::from([
            Permission::from(
                iroha_executor_data_model::permission::governance::CanManageConsensusKeys,
            ),
            Permission::from(CanSetParameters),
        ]),
    );
    config.nexus = Some(nexus);
    config.genesis_instructions = validators
        .into_iter()
        .map(|(peer, pop)| {
            let id = crate::state::derive_committee_key_id(peer.public_key());
            RegisterConsensusKey {
                id: id.clone(),
                record: ConsensusKeyRecord {
                    id,
                    public_key: peer.public_key().clone(),
                    pop: Some(pop),
                    activation_height: 1,
                    expiry_height: None,
                    replaces: None,
                    status: ConsensusKeyStatus::Active,
                },
            }
            .into()
        })
        .collect();
    (config, signer, owner, collector, payment_asset)
}

#[test]
fn alias_registry_fixture_consensus_registration_requires_original_signer_permission() {
    let (mut config, _, _, _, _) = fixture_config();
    let genesis_account = AccountId::new(config.genesis_key.public_key().clone());
    assert!(
        config
            .world
            .account_permissions
            .view()
            .get(&genesis_account)
            .unwrap()
            .contains(&Permission::from(CanManageConsensusKeys))
    );
    config
        .world
        .account_permissions_mut_for_testing()
        .insert(genesis_account, BTreeSet::new());
    let failure = CertifiedTestChain::prepare(config)
        .expect_err("the actual genesis signer cannot register consensus keys without permission");
    let crate::sumeragi::test_chain::TestChainError::OriginalGenesisExecution(error) =
        &failure.error
    else {
        panic!("unexpected original genesis rejection: {:?}", failure.error);
    };
    let crate::block::BlockValidationError::InvalidGenesis(
        crate::block::InvalidGenesisError::RejectedOutput(rejection),
    ) = error.as_ref()
    else {
        panic!("expected rejected genesis output: {error:?}");
    };
    assert!(matches!(
        rejection.reason.as_ref(),
        iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
            ValidationFail::InstructionFailed(
                iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(message)
            )
        ) if message.as_ref() == "not permitted: CanManageConsensusKeys"
    ));
    let view = failure.state.view();
    assert_eq!(view.height(), 0);
    assert_eq!(view.kura().blocks_count(), 0);
    assert!(view.world().consensus_keys().iter().next().is_none());
}

fn commit_bpng_catalog(fixture: &Fixture) {
    let before = fixture.state.nexus_snapshot();
    let network = *fixture.state.network_id_ref();
    let mut chain = fixture.chain.borrow_mut();
    let genesis = chain
        .genesis()
        .encode_wire()
        .expect("original signed genesis wire");
    let committed_genesis = chain
        .committed(1)
        .block()
        .encode_wire()
        .expect("original executed genesis wire");
    let bootstrap = AliasDataspaceBootstrapGrantV1::try_new("bpng", fixture.owner.clone())
        .expect("canonical BPNG authority");
    let peers = chain
        .validators()
        .iter()
        .map(|(peer, _)| peer.clone())
        .collect::<Vec<_>>();
    let payload = crate::state::runtime_catalog_tests::catalog_transition_for_testing(
        &fixture.state,
        DataSpaceMetadata {
            id: bootstrap.dataspace.dataspace_id,
            alias: "bpng".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
        bootstrap.name_hash,
        LaneConfig {
            id: BPNG_LANE,
            dataspace_id: bootstrap.dataspace.dataspace_id,
            alias: "bpng".to_owned(),
            ..LaneConfig::default()
        },
        &peers,
    );
    let request: InstructionBox = SetParameter::new(Parameter::Custom(
        payload
            .clone()
            .into_custom_parameter()
            .expect("canonical catalog transition"),
    ))
    .into();
    // The payer's ordinary application policy remains private. Parameter control
    // uses the authenticated global source even for that same account.
    let payer_signed = chain.sign(
        &fixture.signer,
        [Log::new(
            Level::DEBUG,
            "original private account-routed work".to_owned(),
        )
        .into()],
        1,
    );
    let payer_control = chain.sign(&fixture.signer, [request.clone()], 1);
    let signed = chain.sign(&fixture.catalog_signer, [request], 1);
    {
        let view = fixture.state.view();
        let route = |transaction: &SignedTransaction| {
            evaluate_policy_plan_with_nexus_and_world_at_block_height(
                view.nexus(),
                transaction.payload(),
                view.world(),
                1,
                2,
            )
            .expect("original committed policy route")
            .coordinator_route()
        };
        assert_eq!(
            route(&payer_signed),
            RoutingDecision::new(PRIVATE_LANE, PRIVATE_DATASPACE),
            "the alias payer retains the original private physical policy"
        );
        assert_eq!(
            route(&signed),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            "the actual catalog signer belongs to the authenticated global source"
        );
        assert_eq!(
            route(&payer_control),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            "the payer's parameter control also belongs to the authenticated global source"
        );
    }
    let accepted = chain.commit(vec![signed]);
    let committed = chain.committed(chain.height());
    assert_eq!(
        accepted,
        vec![true],
        "native committed catalog transition: {:#?}",
        committed
            .block()
            .network_output_at(0)
            .map(|(_, output)| output)
    );
    assert_eq!(
        chain.height(),
        2,
        "the additive authority is actually certified at H2"
    );
    assert_eq!(chain.genesis().encode_wire().unwrap(), genesis);
    assert_eq!(*fixture.state.network_id_ref(), network);
    assert_eq!(
        chain.committed(1).block().encode_wire().unwrap(),
        committed_genesis,
        "the original executed genesis remains byte-for-byte unchanged"
    );
    let view = fixture.state.view();
    let after = view.nexus();
    assert_eq!(
        &after.lane_catalog.lanes()[..before.lane_catalog.lanes().len()],
        before.lane_catalog.lanes(),
        "every original lane is retained"
    );
    assert_eq!(
        after.configured_lane_catalog,
        before.configured_lane_catalog
    );
    assert_eq!(
        after.configured_dataspace_catalog,
        before.configured_dataspace_catalog
    );
    for descriptor in before.dataspace_catalog.entries() {
        assert_eq!(
            after.dataspace_catalog.by_id(descriptor.id),
            Some(descriptor)
        );
    }
    assert_eq!(
        after
            .dataspace_catalog
            .by_id(bootstrap.dataspace.dataspace_id),
        Some(&payload.dataspace_additions[0].descriptor)
    );
    assert!(
        view.runtime_catalog_hash().unwrap().is_some(),
        "committed runtime authority exists"
    );
    let native = crate::sumeragi::lanes::lane_policy(view.world())
        .expect("completed original routing metadata read")
        .expect("committed native lane policy");
    let lane = native
        .fixed_lane(BPNG_LANE)
        .expect("new lane has authenticated authority");
    assert_eq!(lane.dataspace, bootstrap.dataspace.dataspace_id);
    assert_eq!(lane.committee.len(), 4);
    for member in &lane.committee {
        assert!(
            chain
                .validators()
                .iter()
                .any(|(peer, pop)| peer == &member.peer && pop == &member.pop)
        );
    }
    crate::sumeragi::lanes::step::validate_policy(&native).expect("exact native committee policy");
}

#[test]
fn alias_registry_routing_local_config_cannot_authorize_catalog_expansion() {
    let (config, _, _, _, _) = fixture_config();
    let account = AccountId::new(config.genesis_key.public_key().clone());
    let mode = config.consensus_mode;
    let prepared = CertifiedTestChain::prepare(config).expect("original prepared genesis");
    let genesis = prepared.genesis.block().clone();
    let mut state =
        Arc::try_unwrap(prepared.state).unwrap_or_else(|_| panic!("unique unapplied State"));
    startup::apply_genesis(&state, genesis.clone(), &account, mode.into(), None)
        .expect("genuine signed genesis establishes the physical baseline");
    let before = state.nexus_snapshot();
    let mut configured = before.clone();
    let mut entries = before.configured_dataspace_catalog.entries().to_vec();
    entries.push(DataSpaceMetadata {
        id: sns::dataspace_id_for_sns_alias("bpng").unwrap(),
        alias: "bpng".to_owned(),
        description: None,
        fault_tolerance: 1,
    });
    configured.configured_dataspace_catalog = DataSpaceCatalog::new(entries).unwrap();
    configured.dataspace_catalog = configured.configured_dataspace_catalog.clone();
    let error = state
        .set_nexus_from_config(configured)
        .expect_err("local expansion cannot mint authority");
    assert!(
        error
            .to_string()
            .contains("configured catalog differs from retained physical dataspace authority"),
        "{error}"
    );
    assert_eq!(
        state.nexus_snapshot().dataspace_catalog,
        before.dataspace_catalog
    );
    assert_eq!(state.nexus_snapshot().lane_catalog, before.lane_catalog);
    assert_eq!(state.view().latest_block_hash(), Some(genesis.hash()));
    assert_eq!(
        *state.network_id_ref(),
        NetworkId::from_genesis_hash(genesis.hash())
    );
}

fn header(fixture: &Fixture, height: u64) -> BlockHeader {
    BlockHeader::new(
        NonZeroU64::new(height).expect("height"),
        fixture.state.view().latest_block_hash(),
        None,
        0,
        0,
    )
}

fn accepted(fixture: &Fixture, instructions: Vec<InstructionBox>) -> AcceptedTransaction<'static> {
    accepted_executable(fixture, Executable::Instructions(instructions.into()))
}

fn accepted_executable(fixture: &Fixture, executable: Executable) -> AcceptedTransaction<'static> {
    let gas_limit = matches!(&executable, Executable::IvmProved(_))
        .then(|| NonZeroU64::new(1_000_000).expect("bounded proved-VM gas"));
    let mut builder = TransactionBuilder::new(
        *fixture.state.network_id_ref(),
        fixture.owner.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), gas_limit),
    )
    .with_executable(executable);
    builder.set_creation_time(Duration::from_millis(1));
    let signed = builder.sign(fixture.signer.private_key());
    let view = fixture.state.view();
    let drift = view.world().parameters().sumeragi().max_clock_drift();
    let parameters = view.world().parameters().transaction();
    let crypto = fixture.state.crypto.read().clone();
    let (_, clock) = TimeSource::new_mock(Duration::from_millis(2));
    AcceptedTransaction::accept_with_time_source(
        signed,
        fixture.state.network_id_ref(),
        drift,
        parameters,
        crypto.as_ref(),
        &clock,
    )
    .expect("signed transaction passes stateless admission")
}

fn plans(
    fixture: &Fixture,
    transaction: &AcceptedTransaction<'_>,
    height: u64,
) -> Result<RoutingPlan, RoutingResolveError> {
    let view = fixture.state.view();
    evaluate_policy_plan_with_nexus_and_world_at_block_height(
        view.nexus(),
        transaction,
        view.world(),
        0,
        height,
    )
}

fn assert_universal_queue_and_block(fixture: &Fixture, transaction: &AcceptedTransaction<'_>) {
    let view = fixture.state.view();
    let nexus = view.nexus();
    let router = ConfigLaneRouter::new(
        nexus.routing_policy.clone(),
        nexus.dataspace_catalog.clone(),
        nexus.lane_catalog.clone(),
    );
    let without_state = router
        .try_route_plan_without_state(transaction)
        .expect("routing without state");
    let queue = router
        .try_route_plan_with_view(transaction, &view)
        .expect("queue route");
    let block = evaluate_policy_plan_with_nexus_and_world_at_block_height(
        nexus,
        transaction,
        view.world(),
        0,
        u64::try_from(view.height()).expect("height") + 1,
    )
    .expect("block route");
    assert_eq!(
        queue, block,
        "queue and block must use the universal registry"
    );
    if let Some(without_state) = without_state {
        assert_eq!(
            without_state, queue,
            "narrow routing must retain the same authority"
        );
    }
    assert!(
        matches!(queue, RoutingPlan::Single(_)),
        "alias-only operations must not create a private participant: {queue:?}"
    );
    assert_eq!(
        queue.coordinator_route(),
        RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
    );
}

fn apply(fixture: &Fixture, instructions: Vec<InstructionBox>) -> Result<(), String> {
    let transaction = accepted(fixture, instructions);
    let height = u64::try_from(fixture.state.view().height()).expect("height") + 1;
    let mut block = fixture.state.block(header(fixture, height));
    let plan = plans(fixture, &transaction, height).map_err(|error| format!("{error:?}"))?;
    let RoutingPlan::Single(leg) = plan else {
        return Err("alias registry fixture must have exactly one route".into());
    };
    let mut overlay = block.transaction_for_fastpq_testing(iroha_crypto::Hash::from(
        transaction.entrypoint().execution_call_hash(),
    ));
    assert!(
        crate::executor::root_scope::execution_root_scope(&mut overlay).is_ok(),
        "paid alias and refusal cases require the authenticated ordinary execution root"
    );
    overlay.current_entrypoint_index = Some(0);
    overlay.current_network_entrypoint_hash = Some(transaction.hash_as_entrypoint());
    overlay.current_tx_hash = Some(
        transaction
            .external()
            .expect("alias fixture authors an external input")
            .hash(),
    );
    overlay.current_lane_id = Some(leg.route.lane_id);
    overlay.current_dataspace_id = Some(leg.route.dataspace_id);
    overlay.world.current_dataspace_id = Some(leg.route.dataspace_id);
    let policy_route =
        crate::state::network_policy_routes::CapturedNetworkPolicyRoute::for_component(
            &transaction,
            &overlay,
            leg.route,
        )
        .expect("completed original physical policy capture");
    crate::state::StateBlock::execute_accepted_transaction_in_overlay(
        transaction,
        &mut overlay,
        &mut IvmCache::new(),
        leg.route,
        policy_route,
        None,
    )
    .map_err(|error| format!("{error:?}"))?;
    overlay.apply();
    // Persist the validated world overlay without manufacturing consensus/QC evidence in this
    // local routing/execution regression. Carrier-height fixtures are committed separately.
    block
        .commit_world_overlay_for_testing()
        .map_err(|error| format!("{error:?}"))
}

fn bootstrap_grant(fixture: &Fixture) -> InstructionBox {
    SetParameter::new(Parameter::Custom(
        AliasDataspaceBootstrapGrantV1::try_new("bpng", fixture.owner.clone())
            .expect("canonical BPNG grant")
            .into_custom_parameter()
            .expect("canonical grant parameter"),
    ))
    .into()
}

#[test]
fn parameter_control_preserves_global_physical_route_before_private_account_rule() {
    let fixture = fixture();
    let original_genesis = fixture.chain.borrow().genesis().encode_wire().unwrap();
    let original_balance = balance(&fixture, &fixture.owner);
    let parameter = bootstrap_grant(&fixture);
    let executables = [
        Executable::Instructions(vec![parameter.clone()].into()),
        Executable::Batch(
            vec![iroha_data_model::transaction::ExecutableBatchItem::Instruction(parameter)].into(),
        ),
    ];
    for executable in executables {
        let transaction = accepted_executable(&fixture, executable);
        let view = fixture.state.view();
        let snapshot = crate::sumeragi::lanes::routing::RoutingSnapshot::of(&view).unwrap();
        let native = snapshot
            .inputs(view.world())
            .execution_route(&transaction, 2)
            .unwrap();
        assert_eq!(
            native,
            Some(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)),
            "the genuine signed parameter batch already belongs to the native global source"
        );
        drop(view);
        assert_universal_queue_and_block(&fixture, &transaction);
    }
    let application = accepted(
        &fixture,
        vec![Log::new(Level::DEBUG, "ordinary account-routed work".to_owned()).into()],
    );
    assert_eq!(
        plans(&fixture, &application, 2)
            .unwrap()
            .coordinator_route(),
        RoutingDecision::new(PRIVATE_LANE, PRIVATE_DATASPACE),
        "the same owner's application still obeys its private account rule"
    );
    assert_eq!(balance(&fixture, &fixture.owner), original_balance);
    assert_eq!(
        fixture.chain.borrow().genesis().encode_wire().unwrap(),
        original_genesis
    );
    assert_eq!(fixture.state.view().height(), 1);
}

fn ensure(fixture: &Fixture, intent: AliasIntentV1) -> EnsureAlias {
    let view = fixture.state.view();
    let selector = selector_for_resolved_alias_target(&intent.target()).expect("selector");
    let quote = sns::quote_resolved_name_registration(
        view.world(),
        selector.clone(),
        alias_intent_owner(&intent),
        1,
        None,
        0,
    )
    .expect("lease quote");
    let policy = sns::policy_by_id(view.world(), selector.suffix_id)
        .expect("policy storage")
        .expect("policy");
    EnsureAlias::new(
        intent,
        AliasLeaseAcquisitionV1::new(1, None),
        AliasQuoteGuardV1 {
            expected_policy_version: policy.policy_version,
            expected_payment_asset: quote.payment_asset_definition_id,
            max_amount: quote.charge_amount,
            valid_until_ms: u64::MAX,
        },
    )
}

fn bpng_intent(owner: &AccountId) -> AliasIntentV1 {
    let dataspace_id = sns::dataspace_id_for_sns_alias("bpng").expect("canonical hash-derived ID");
    assert_eq!(dataspace_id.as_u64(), 8_648_377_547_929_788_715);
    AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
        dataspace: ResolvedDataSpaceV1::new("bpng".parse().expect("name"), dataspace_id),
        owner: owner.clone(),
    })
}

fn balance(fixture: &Fixture, account: &AccountId) -> Quantity {
    fixture
        .state
        .view()
        .world()
        .asset(&AssetId::of(fixture.payment_asset.clone(), account.clone()))
        .map(|asset| asset.value().clone().into_inner())
        .unwrap_or_else(|_| Quantity::zero())
}

#[test]
fn alias_registry_routing_paid_post_genesis_dataspace_domain_and_renewal() {
    let fixture = fixture();
    let dataspace = ensure(&fixture, bpng_intent(&fixture.owner));
    let bpng = dataspace.intent.target().dataspace_id();
    assert_universal_queue_and_block(
        &fixture,
        &accepted(&fixture, vec![dataspace.clone().into()]),
    );
    apply(&fixture, vec![bootstrap_grant(&fixture)]).expect("grant precedes the first paid lease");
    assert_universal_queue_and_block(
        &fixture,
        &accepted(&fixture, vec![dataspace.clone().into()]),
    );
    let before = balance(&fixture, &fixture.owner);
    apply(&fixture, vec![dataspace.clone().into()]).expect("paid BPNG acquisition after genesis");
    let paid = balance(&fixture, &fixture.owner);
    assert!(paid < before, "acquisition must debit actual global XOR");
    assert!(balance(&fixture, &fixture.collector) > Quantity::zero());
    assert!(
        fixture
            .state
            .nexus_snapshot()
            .dataspace_catalog
            .by_id(bpng)
            .is_none(),
        "the name lease must not fabricate a catalog entry"
    );
    apply(&fixture, vec![dataspace.clone().into()]).expect("exact replay is idempotent");
    assert_eq!(
        balance(&fixture, &fixture.owner),
        paid,
        "no-op must not charge another lease"
    );

    // The catalog is protocol authority: commit its additive transition instead of
    // replacing the process-configured baseline with a locally expanded configuration.
    commit_bpng_catalog(&fixture);
    assert_universal_queue_and_block(
        &fixture,
        &accepted(&fixture, vec![dataspace.clone().into()]),
    );

    let domain_id = DomainId::try_new("mibank", "bpng").expect("domain");
    let domain = ensure(
        &fixture,
        AliasIntentV1::Domain(AliasDomainIntentV1 {
            domain: ResolvedDomainV1::new(domain_id.clone(), bpng),
            owner: fixture.owner.clone(),
        }),
    );
    assert_universal_queue_and_block(&fixture, &accepted(&fixture, vec![domain.clone().into()]));
    apply(&fixture, vec![domain.clone().into()])
        .expect("paid domain creation uses universal registry");
    assert_eq!(
        fixture
            .state
            .view()
            .world()
            .domain(&domain_id)
            .expect("derived domain")
            .owned_by(),
        &fixture.owner
    );
    let domain_paid = balance(&fixture, &fixture.owner);
    apply(&fixture, vec![domain.clone().into()]).expect("idempotent domain repair");
    assert_eq!(balance(&fixture, &fixture.owner), domain_paid);

    let account_alias =
        ResolvedAccountAliasV1::new("treasury@mibank.bpng".parse().expect("account alias"), bpng);
    let account = ensure(
        &fixture,
        AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
            alias: account_alias.clone(),
            target_account: fixture.owner.clone(),
            provision: AccountProvisionV1::Existing,
            role: AccountAliasRoleV1::Additional,
        }),
    );
    apply(&fixture, vec![account.into()]).expect("paid account alias after domain");
    assert_eq!(
        fixture
            .state
            .view()
            .world()
            .account_aliases()
            .get(&account_alias.account_alias()),
        Some(&fixture.owner)
    );

    let view = fixture.state.view();
    let selector = selector_for_resolved_alias_target(&domain.intent.target()).expect("selector");
    let record =
        sns::get_name_record_by_selector(view.world(), &selector, 0).expect("domain lease");
    let quote = sns::quote_resolved_name_renewal(
        view.world(),
        selector.clone(),
        record.expires_at_ms,
        record.expires_at_ms + 31_536_000_000,
        0,
    )
    .expect("renewal quote");
    let policy = sns::policy_by_id(view.world(), selector.suffix_id)
        .expect("policy")
        .expect("namespace");
    let renew = RenewAliasLease::new(
        domain.intent.target(),
        record.expires_at_ms,
        quote.expires_at_ms,
        AliasQuoteGuardV1 {
            expected_policy_version: policy.policy_version,
            expected_payment_asset: quote.payment_asset_definition_id,
            max_amount: quote.charge_amount,
            valid_until_ms: u64::MAX,
        },
    );
    drop(view);
    assert_universal_queue_and_block(&fixture, &accepted(&fixture, vec![renew.clone().into()]));
    let before_renewal = balance(&fixture, &fixture.owner);
    apply(&fixture, vec![renew.clone().into()]).expect("paid renewal");
    assert!(balance(&fixture, &fixture.owner) < before_renewal);
    assert!(
        apply(&fixture, vec![renew.into()])
            .expect_err("stale expiry CAS must reject")
            .contains("alias.lease.expiry_conflict")
    );
    assert_eq!(
        fixture.state.view().height(),
        2,
        "paid overlays retain the original genesis and its certified catalog descendant"
    );
}

#[test]
fn alias_registry_routing_is_independent_of_height_and_catalog() {
    let fixture = fixture();
    for intent in [
        bpng_intent(&fixture.owner),
        AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
            dataspace: ResolvedDataSpaceV1::new("paynet".parse().expect("name"), PRIVATE_DATASPACE),
            owner: fixture.owner.clone(),
        }),
    ] {
        let lease = ensure(&fixture, intent);
        let transaction = accepted(&fixture, vec![lease.into()]);
        assert_universal_queue_and_block(&fixture, &transaction);
        let expected =
            RoutingPlan::single(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL));
        for height in [1, 2, 3] {
            assert_eq!(
                plans(&fixture, &transaction, height).expect("exact height route"),
                expected
            );
        }
        let view = fixture.state.view();
        assert_eq!(
            evaluate_policy_plan_with_nexus_and_world_at(
                view.nexus(),
                &transaction,
                view.world(),
                0
            )
            .expect("height-independent registry route"),
            expected
        );
    }
}

#[test]
fn alias_registry_routing_nested_walkers_use_universal_registry() {
    use iroha_data_model::transaction::{ExecutableBatchItem, IvmBytecode, IvmProved};
    use iroha_executor_data_model::isi::multisig::{
        MultisigApprove, MultisigProposalState, MultisigPropose,
    };

    let fixture = fixture();
    let mut lease = ensure(&fixture, bpng_intent(&fixture.owner));
    if let AliasIntentV1::Dataspace(intent) = &mut lease.intent {
        intent.dataspace =
            ResolvedDataSpaceV1::new("paynet".parse().expect("name"), PRIVATE_DATASPACE);
    }
    let payload: Vec<InstructionBox> = vec![lease.into()];
    let instructions_hash = HashOf::new(&payload);
    let proposal_nonce =
        iroha_executor_data_model::isi::multisig::MultisigProposalNonce::new([0x51; 32]).unwrap();
    let proposal_id = iroha_executor_data_model::isi::multisig::MultisigProposalId::derive(
        fixture.state.network_id_ref(),
        &fixture.owner,
        &proposal_nonce,
    );
    let stored = MultisigProposalState {
        network_id: *fixture.state.network_id_ref(),
        proposal_nonce,
        proposal_id,
        transaction_ttl_ms: None,
        multisig_account_id: fixture.owner.clone(),
        instructions_hash,
        instructions: payload.clone(),
        proposed_at_ms: 0,
        expires_at_ms: 1_000,
        approvals: BTreeSet::new(),
    };
    {
        let mut block = fixture.state.block(header(&fixture, 2));
        let mut transaction = block.transaction();
        transaction
            .world
            .smart_contract_state_mut_for_testing()
            .insert(
                format!(
                    "multisig/proposal/{}/{}",
                    HashOf::new(&fixture.owner),
                    proposal_id
                )
                .parse()
                .expect("proposal key"),
                norito::to_bytes(&stored).expect("native proposal encoding"),
            );
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("stored proposal fixture");
    }
    let trigger_id: TriggerId = "alias_registry_nested".parse().expect("trigger id");
    let trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            payload.clone(),
            Repeats::Exactly(1),
            fixture.owner.clone(),
            ExecuteTriggerEventFilter::new().for_trigger(trigger_id),
        )
        .expect("trigger action"),
    ));
    let meta = ivm::ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 1,
        abi_version: 1,
    };
    let mut bytecode = meta.encode();
    bytecode.extend_from_slice(b"LTLB");
    for _ in 0..3 {
        bytecode.extend_from_slice(&0u32.to_le_bytes());
    }
    bytecode.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    let executables = vec![
        Executable::Batch(
            payload
                .iter()
                .cloned()
                .map(ExecutableBatchItem::Instruction)
                .collect(),
        ),
        Executable::Instructions(
            vec![
                MultisigPropose::new(fixture.owner.clone(), proposal_nonce, payload.clone(), None)
                    .into(),
            ]
            .into(),
        ),
        Executable::Instructions(
            vec![
                MultisigApprove::new(fixture.owner.clone(), proposal_id, instructions_hash).into(),
            ]
            .into(),
        ),
        Executable::Instructions(vec![trigger.into()].into()),
        Executable::IvmProved(IvmProved {
            bytecode: IvmBytecode::from_compiled(bytecode),
            overlay: payload.into(),
            events_commitment: Hash::new(b"events"),
            gas_policy_commitment: Hash::new(b"gas-policy"),
        }),
    ];
    let transactions: Vec<_> = executables
        .into_iter()
        .map(|executable| accepted_executable(&fixture, executable))
        .collect();
    for transaction in &transactions {
        assert_universal_queue_and_block(&fixture, transaction);
        for height in [1, 2, 3] {
            let plan = plans(&fixture, transaction, height).expect("nested universal route");
            assert_eq!(
                plan.coordinator_route(),
                RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
            );
            assert!(
                matches!(plan, RoutingPlan::Single(_)),
                "nested aliases have no private participant"
            );
        }
    }
}

#[test]
fn alias_registry_routing_does_not_bypass_id_owner_quote_or_catalog_guards() {
    let fixture = fixture();
    let lease = ensure(&fixture, bpng_intent(&fixture.owner));
    let before = balance(&fixture, &fixture.owner);
    let mut invalid_id = lease.clone();
    if let AliasIntentV1::Dataspace(intent) = &mut invalid_id.intent {
        intent.dataspace.dataspace_id = DataSpaceId::new(10);
    }
    assert!(
        apply(&fixture, vec![invalid_id.into()])
            .expect_err("wrong hash-derived ID")
            .contains(sns::ALIAS_CATALOG_MAPPING_CONFLICT_CODE)
    );
    let mut wrong_owner = lease.clone();
    if let AliasIntentV1::Dataspace(intent) = &mut wrong_owner.intent {
        intent.owner = fixture.collector.clone();
    }
    assert!(
        apply(&fixture, vec![wrong_owner.into()])
            .expect_err("foreign owner")
            .contains("alias.setup.authority_forbidden")
    );
    let mut unpaid = lease.clone();
    unpaid.quote_guard.max_amount = Quantity::zero();
    assert!(
        apply(&fixture, vec![unpaid.into()])
            .expect_err("zero payment cap")
            .contains("alias.quote.cap_exceeded")
    );
    let mut catalog_claim = lease;
    if let AliasIntentV1::Dataspace(intent) = &mut catalog_claim.intent {
        intent.dataspace =
            ResolvedDataSpaceV1::new("paynet".parse().expect("name"), PRIVATE_DATASPACE);
    }
    assert!(
        apply(&fixture, vec![catalog_claim.into()])
            .expect_err("ungranted catalogued name")
            .contains("alias.catalog.bootstrap_required")
    );
    assert_eq!(
        balance(&fixture, &fixture.owner),
        before,
        "every rejected creation rolls back without a lease charge"
    );
}

#[test]
fn alias_registry_routing_cold_replay_with_expanded_catalog_preserves_paid_bootstrap() {
    // Reconstruct the original pre-lease world, not a snapshot already containing the SNS name.
    // The second independent instance commits the additive catalog before paid replay starts.
    // Both retain the same signed genesis and replay the exact bootstrap grant and signed
    // lease/domain sequence; a newly signed expanded genesis is a different network.
    let original = fixture_with_expanded_catalog(false);
    let replay = fixture_with_expanded_catalog(true);
    assert_eq!(
        original.state.network_id_ref(),
        replay.state.network_id_ref()
    );
    assert_eq!(
        original.chain.borrow().genesis().encode_wire().unwrap(),
        replay.chain.borrow().genesis().encode_wire().unwrap(),
        "cold paid replay retains the same original signed genesis"
    );
    assert_eq!(
        original
            .chain
            .borrow()
            .committed(1)
            .block()
            .encode_wire()
            .unwrap(),
        replay
            .chain
            .borrow()
            .committed(1)
            .block()
            .encode_wire()
            .unwrap(),
        "cold paid replay retains the same authentic executed genesis"
    );
    let dataspace = ensure(&original, bpng_intent(&original.owner));
    let target = dataspace.intent.target();
    let selector = selector_for_resolved_alias_target(&target).expect("BPNG selector");
    assert!(
        sns::record_by_selector(replay.state.view().world(), &selector)
            .expect("record storage")
            .is_none(),
        "cold replay must start without the newly acquired lease"
    );
    let grant = bootstrap_grant(&original);
    for instruction in [grant.clone(), dataspace.clone().into()] {
        assert_eq!(
            accepted(&original, vec![instruction.clone()]).entrypoint(),
            accepted(&replay, vec![instruction]).entrypoint(),
            "cold execution replays the identical signed entrypoint"
        );
    }
    for fixture in [&original, &replay] {
        apply(fixture, vec![grant.clone()]).expect("replay the prior governed grant");
        assert_universal_queue_and_block(
            fixture,
            &accepted(fixture, vec![dataspace.clone().into()]),
        );
        apply(fixture, vec![dataspace.clone().into()])
            .expect("replay the first paid acquisition, not a no-op");
    }
    let domain_id = DomainId::try_new("mibank", "bpng").expect("domain");
    let domain = ensure(
        &original,
        AliasIntentV1::Domain(AliasDomainIntentV1 {
            domain: ResolvedDomainV1::new(domain_id.clone(), target.dataspace_id()),
            owner: original.owner.clone(),
        }),
    );
    assert_eq!(
        accepted(&original, vec![domain.clone().into()]).entrypoint(),
        accepted(&replay, vec![domain.clone().into()]).entrypoint()
    );
    for fixture in [&original, &replay] {
        apply(fixture, vec![domain.clone().into()]).expect("replay paid derived domain creation");
    }
    assert_eq!(
        sns::record_by_selector(original.state.view().world(), &selector).expect("original lease"),
        sns::record_by_selector(replay.state.view().world(), &selector).expect("replayed lease")
    );
    let domain_selector =
        selector_for_resolved_alias_target(&domain.intent.target()).expect("domain selector");
    assert_eq!(
        sns::record_by_selector(original.state.view().world(), &domain_selector)
            .expect("original domain lease"),
        sns::record_by_selector(replay.state.view().world(), &domain_selector)
            .expect("replayed domain lease")
    );
    assert_eq!(
        balance(&original, &original.owner),
        balance(&replay, &replay.owner)
    );
    assert_eq!(
        balance(&original, &original.collector),
        balance(&replay, &replay.collector)
    );
    assert_eq!(
        original
            .state
            .view()
            .world()
            .domain(&domain_id)
            .expect("original domain"),
        replay
            .state
            .view()
            .world()
            .domain(&domain_id)
            .expect("replayed domain")
    );
    assert_eq!(original.state.view().height(), 1);
    assert_eq!(replay.state.view().height(), 2);
    assert_eq!(
        replay
            .chain
            .borrow()
            .committed(2)
            .block()
            .header()
            .prev_block_hash,
        Some(original.chain.borrow().genesis().hash()),
        "expanded replay carries the actual certified descendant of the original genesis"
    );
}
