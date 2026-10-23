//! Public-boundary regression tests for state-backed native FX routing plans.
use iroha_config::parameters::actual::{LaneRoutingMatcher, LaneRoutingPolicy, LaneRoutingRule};
use iroha_core::{
    query::store::LiveQueryStore,
    queue::{
        ConfigLaneRouter, LaneRouter, RoutingPlan, RoutingResolveError,
        evaluate_policy_plan_with_nexus_and_world_at,
    },
    smartcontracts::Execute,
    state::{State, StateReadOnly, World, WorldReadOnly},
    tx::AcceptedTransaction,
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    Encode,
    account::AccountAddress,
    isi::{
        oracle::RegisterOracleFeed,
        settlement::{
            FxCorridorOracleEvidence, FxCorridorPolicy, SetFxCorridorPolicy, SettleFxCorridor,
            SettlementInstructionBox,
        },
        smart_contract_code::{ActivateContractInstance, RegisterSmartContractBytes},
    },
    nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig},
    oracle::{FeedConfigVersion, FeedEvent, FeedEventOutcome, FeedSuccess, ObservationValue},
    prelude::*,
    sns::{NameControllerV1, NameRecordV1},
};
use iroha_executor_data_model::permission::oracle::CanRegisterOracleFeed;
use iroha_executor_data_model::permission::settlement::CanManageFxCorridors;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::topology::DataSpaceId;
use iroha_model_base::topology::LaneId;
use iroha_primitives::time::TimeSource;
use iroha_test_samples::{
    ALICE_ID, ALICE_KEYPAIR, BOB_ID, CARPENTER_ID, SAMPLE_GENESIS_ACCOUNT_ID,
};
use std::{
    collections::BTreeSet,
    num::{NonZeroU32, NonZeroU64},
    time::Duration,
};
const LEDGER_TIME_MS: u64 = 0;
const SOURCE_DATASPACE: DataSpaceId = DataSpaceId::new(10);
const DESTINATION_DATASPACE: DataSpaceId = DataSpaceId::new(12);
const CONTRACT_DATASPACE: DataSpaceId = DataSpaceId::new(14);
const DEPLOY_POLICY_DATASPACE: DataSpaceId = DataSpaceId::new(16);
const SOURCE_LANE: LaneId = LaneId::new(3);
const DESTINATION_LANE: LaneId = LaneId::new(4);
const CONTRACT_LANE: LaneId = LaneId::new(5);
const DEPLOY_POLICY_LANE: LaneId = LaneId::new(6);
struct Fixture {
    state: State,
    router: ConfigLaneRouter,
    corridor: FxCorridorPolicy,
}
fn lane_catalog() -> LaneCatalog {
    LaneCatalog::new(
        NonZeroU32::new(7).expect("nonzero lane bound"),
        vec![
            LaneConfig::default(),
            LaneConfig {
                id: SOURCE_LANE,
                dataspace_id: SOURCE_DATASPACE,
                alias: "fx-source".to_owned(),
                ..LaneConfig::default()
            },
            LaneConfig {
                id: DESTINATION_LANE,
                dataspace_id: DESTINATION_DATASPACE,
                alias: "fx-destination".to_owned(),
                ..LaneConfig::default()
            },
            LaneConfig {
                id: CONTRACT_LANE,
                dataspace_id: CONTRACT_DATASPACE,
                alias: "contract-instances".to_owned(),
                ..LaneConfig::default()
            },
            LaneConfig {
                id: DEPLOY_POLICY_LANE,
                dataspace_id: DEPLOY_POLICY_DATASPACE,
                alias: "private-deploy-policy".to_owned(),
                ..LaneConfig::default()
            },
        ],
    )
    .expect("valid deterministic lane catalog")
}
fn dataspace_catalog() -> DataSpaceCatalog {
    DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: SOURCE_DATASPACE,
            alias: "cbuae".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
        DataSpaceMetadata {
            id: DESTINATION_DATASPACE,
            alias: "sbp".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
        DataSpaceMetadata {
            id: CONTRACT_DATASPACE,
            alias: "contracts".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
        DataSpaceMetadata {
            id: DEPLOY_POLICY_DATASPACE,
            alias: "private_deploy".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("valid deterministic dataspace catalog")
}
fn routing_policy() -> LaneRoutingPolicy {
    LaneRoutingPolicy {
        default_lane: LaneId::SINGLE,
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: vec![LaneRoutingRule {
            lane: DEPLOY_POLICY_LANE,
            dataspace: Some(DEPLOY_POLICY_DATASPACE),
            matcher: LaneRoutingMatcher {
                account: None,
                instruction: Some("smartcontract::deploy".to_owned()),
                description: Some("private smart-contract deployment policy".to_owned()),
            },
        }],
    }
}
fn source_asset_definition_id() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("cbuae", "universal").expect("source asset domain"),
        "aed".parse().expect("source asset name"),
    )
}
fn destination_asset_definition_id() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("sbp", "universal").expect("destination asset domain"),
        "pkr".parse().expect("destination asset name"),
    )
}
fn corridor() -> FxCorridorPolicy {
    FxCorridorPolicy {
        policy_id: "mobile_aed_pkr".parse().expect("FX policy id"),
        revision: 1,
        owner: CARPENTER_ID.clone(),
        source_dataspace: SOURCE_DATASPACE,
        source_asset_definition_id: source_asset_definition_id(),
        destination_dataspace: DESTINATION_DATASPACE,
        destination_asset_definition_id: destination_asset_definition_id(),
        allowed_destination_alias_domains: BTreeSet::from([
            DomainId::try_new("hbl", "sbp").expect("HBL alias domain"),
            DomainId::try_new("ubl", "sbp").expect("UBL alias domain"),
        ]),
        oracle_feed_id: "mobile_aed_pkr_rate".parse().expect("FX oracle feed id"),
        max_oracle_age_ms: 60_000,
        max_source_amount_per_settlement: Quantity::from(1_000_u32),
        max_destination_amount_per_settlement: Quantity::from(100_000_u32),
        velocity_window_ms: 60_000,
        max_settlements_per_window: 100,
        max_source_amount_per_window: Quantity::from(10_000_u32),
        max_destination_amount_per_window: Quantity::from(1_000_000_u32),
        enabled: true,
    }
}
fn seed_active_sns_dataspace(world: &mut World, alias: &str) {
    let selector =
        iroha_core::sns::selector_for_dataspace_alias(alias).expect("valid SNS dataspace selector");
    let owner_address =
        AccountAddress::from_account_id(&ALICE_ID).expect("canonical account address");
    let record = NameRecordV1::new(
        selector.clone(),
        ALICE_ID.clone(),
        vec![NameControllerV1::account(&owner_address)],
        0,
        LEDGER_TIME_MS,
        10_000,
        20_000,
        30_000,
        Metadata::default(),
    );
    world.smart_contract_state_mut_for_testing().insert(
        iroha_core::sns::record_storage_key(&selector),
        record.encode(),
    );
}
fn fixture(active_sns_alias: Option<&str>) -> Fixture {
    let source_domain = DomainId::try_new("cbuae", "universal").expect("source domain");
    let destination_domain = DomainId::try_new("sbp", "universal").expect("destination domain");
    let mut world = World::with_assets(
        [
            Domain::new(source_domain.clone()).build(&ALICE_ID),
            Domain::new(destination_domain.clone()).build(&ALICE_ID),
        ],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&ALICE_ID),
            Account::new(CARPENTER_ID.clone()).build(&ALICE_ID),
            Account::new(SAMPLE_GENESIS_ACCOUNT_ID.clone()).build(&ALICE_ID),
        ],
        [
            AssetDefinition::numeric(
                source_asset_definition_id(),
                "aed".to_owned(),
                AssetBalancePolicy::DataspaceRestricted,
                Some(source_domain),
            )
            .build(&ALICE_ID),
            AssetDefinition::numeric(
                destination_asset_definition_id(),
                "pkr".to_owned(),
                AssetBalancePolicy::DataspaceRestricted,
                Some(destination_domain),
            )
            .build(&ALICE_ID),
        ],
        std::iter::empty::<Asset>(),
        std::iter::empty::<Nft>(),
    );
    world.account_permissions_mut_for_testing().insert(
        ALICE_ID.clone(),
        BTreeSet::from([
            Permission::from(CanManageFxCorridors),
            Permission::from(CanRegisterOracleFeed),
        ]),
    );
    if let Some(alias) = active_sns_alias {
        seed_active_sns_dataspace(&mut world, alias);
    }
    let corridor = corridor();
    let mut feed = iroha_data_model::oracle::kits::price_xor_usd().feed_config;
    feed.feed_id = corridor.oracle_feed_id.clone();
    let lanes = lane_catalog();
    let mut dataspace_entries = dataspace_catalog().entries().to_vec();
    if let Some(alias) = active_sns_alias {
        // An active SNS lease does not itself admit a dataspace to the catalog.
        // Admit it explicitly so this fixture reaches the missing-lane guard.
        dataspace_entries.push(DataSpaceMetadata {
            id: iroha_core::sns::dataspace_id_for_sns_alias(alias).expect("SNS-only dataspace id"),
            alias: alias.to_owned(),
            description: None,
            fault_tolerance: 1,
        });
    }
    let dataspaces = DataSpaceCatalog::new(dataspace_entries)
        .expect("explicit active SNS catalog without a canonical lane");
    let policy = routing_policy();
    let defaults = iroha_config::parameters::actual::Nexus::default();
    let lane_catalog = lanes.clone();
    drop(defaults.lane_catalog);
    let lane_config = iroha_config::parameters::actual::LaneConfig::from_catalog(&lanes);
    drop(defaults.lane_config);
    let dataspace_catalog = dataspaces.clone();
    drop(defaults.dataspace_catalog);
    let routing_policy = policy.clone();
    drop(defaults.routing_policy);
    let nexus = iroha_config::parameters::actual::Nexus {
        lane_catalog,
        lane_config,
        dataspace_catalog,
        routing_policy,
        ..defaults
    };
    // Open Kura with the same original catalog that State will authenticate.
    let state =
        State::new_with_pre_genesis_nexus_for_testing(world, nexus, LiveQueryStore::start_test());
    let header = BlockHeader::new(
        NonZeroU64::new(1).expect("nonzero block height"),
        None,
        None,
        LEDGER_TIME_MS,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    RegisterOracleFeed { feed }
        .execute(&ALICE_ID, &mut transaction)
        .expect("oracle registrar must install the FX feed");
    SetFxCorridorPolicy {
        policy: corridor.clone(),
    }
    .execute(&ALICE_ID, &mut transaction)
    .expect("exact CanManageFxCorridors grant must install the valid policy");
    transaction.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("policy setup block must commit");
    Fixture {
        state,
        router: ConfigLaneRouter::new(policy, dataspaces, lanes),
        corridor,
    }
}
fn accepted_transaction(
    state: &State,
    instructions: Vec<InstructionBox>,
) -> AcceptedTransaction<'static> {
    let mut builder = TransactionBuilder::new(
        *state.network_id_ref(),
        ALICE_ID.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instructions);
    builder.set_creation_time(Duration::from_millis(1));
    let signed = builder.sign(ALICE_KEYPAIR.private_key());
    let view = state.view();
    let max_clock_drift = view.world().parameters().sumeragi().max_clock_drift();
    let transaction_parameters = view.world().parameters().transaction();
    drop(view);
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::from_millis(2));
    AcceptedTransaction::accept_with_time_source(
        signed,
        state.network_id_ref(),
        max_clock_drift,
        transaction_parameters,
        &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
            iroha_crypto::Algorithm::Ed25519,
            iroha_crypto::Algorithm::Secp256k1,
        ])
        .expect("this stateless fixture explicitly selects Ed25519 and Secp256k1"),
        &time_source,
    )
    .expect("deterministic transaction must pass stateless admission")
}
fn settlement_instruction(corridor: &FxCorridorPolicy, settlement_id: &str) -> InstructionBox {
    let request_hash = Hash::new(b"fx-routing-review-oracle-request");
    let oracle_event = FeedEvent {
        feed_id: corridor.oracle_feed_id.clone(),
        feed_config_version: FeedConfigVersion(1),
        slot: 1,
        request_hash,
        outcome: FeedEventOutcome::Success(FeedSuccess {
            value: ObservationValue::new(76, 0),
            entries: Vec::new(),
        }),
    };
    InstructionBox::from(SettlementInstructionBox::SettleFxCorridor(
        SettleFxCorridor {
            policy_id: corridor.policy_id.clone(),
            expected_policy_revision: corridor.revision,
            source_asset_definition_id: corridor.source_asset_definition_id.clone(),
            destination_asset_definition_id: corridor.destination_asset_definition_id.clone(),
            settlement_id: iroha_data_model::isi::SettlementId::new(
                ALICE_ID.clone(),
                settlement_id.parse().expect("settlement reference"),
            ),
            recipient: BOB_ID.clone(),
            source_amount: Quantity::from(10_u32),
            expected_destination_amount: Quantity::from(760_u32),
            oracle_evidence: FxCorridorOracleEvidence {
                feed_id: oracle_event.feed_id.clone(),
                feed_config_version: oracle_event.feed_config_version,
                slot: oracle_event.slot,
                request_hash: oracle_event.request_hash,
                event_hash: HashOf::new(&oracle_event),
            },
        },
    ))
}
fn queue_and_block_plans(
    fixture: &Fixture,
    transaction: &AcceptedTransaction<'_>,
) -> (RoutingPlan, RoutingPlan) {
    let view = fixture.state.view();
    let queue_plan = fixture
        .router
        .try_route_plan_with_view(transaction, &view)
        .expect("queue-time FX plan must resolve");
    let block_plan = evaluate_policy_plan_with_nexus_and_world_at(
        view.nexus(),
        transaction,
        view.world(),
        LEDGER_TIME_MS,
    )
    .expect("block-time FX plan must resolve");
    (queue_plan, block_plan)
}
fn participant_routes(plan: &RoutingPlan) -> BTreeSet<(LaneId, DataSpaceId)> {
    let RoutingPlan::NativeAmx(native) = plan else {
        panic!("FX transaction must produce a native AMX plan");
    };
    native
        .participants
        .iter()
        .map(|leg| (leg.route.lane_id, leg.route.dataspace_id))
        .collect()
}
#[test]
fn domain_retirement_rejects_governed_fx_corridor_backing_atomically() {
    let fixture = fixture(None);
    let domain_id = DomainId::try_new("cbuae", "universal").expect("FX source asset domain");
    let definition_id = fixture.corridor.source_asset_definition_id.clone();
    let header = BlockHeader::new(
        NonZeroU64::new(2).expect("second block height"),
        None,
        None,
        LEDGER_TIME_MS + 1,
        0,
    );
    let mut block = fixture.state.block(header);
    let mut transaction = block.transaction();
    let error = Unregister::domain(domain_id.clone())
        .execute(&ALICE_ID, &mut transaction)
        .expect_err("governed FX source backing must survive domain retirement");
    assert!(
        error
            .to_string()
            .contains("retained native FX corridor backing")
    );
    assert!(transaction.world().domain(&domain_id).is_ok());
    assert!(transaction.world().asset_definition(&definition_id).is_ok());
    let registry_id = iroha_data_model::isi::settlement::FxCorridorPolicyRegistry::parameter_id();
    assert!(
        transaction
            .world()
            .parameters()
            .custom()
            .contains_key(&registry_id)
    );
}

#[test]
fn fx_deployment_preserves_intrinsic_and_private_policy_participants() {
    let fixture = fixture(None);
    let code = vec![0xCA, 0xFE, 0xBA, 0xBE];
    let contract_address = ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .expect("canonical test network id"),
        &ALICE_ID,
        0,
        CONTRACT_DATASPACE,
    )
    .expect("deterministic contract address");
    let transaction = accepted_transaction(
        &fixture.state,
        vec![
            InstructionBox::from(RegisterSmartContractBytes {
                artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                    CONTRACT_DATASPACE,
                    Hash::new(&code),
                ),
                code,
            }),
            InstructionBox::from(ActivateContractInstance {
                contract_address,
                expected_revision: 1,
                code_hash: Hash::new(b"contract-code"),
            }),
            settlement_instruction(&fixture.corridor, "fx_deploy_boundary"),
        ],
    );
    let (queue_plan, block_plan) = queue_and_block_plans(&fixture, &transaction);
    assert_eq!(queue_plan, block_plan);
    assert_eq!(queue_plan.digest(), block_plan.digest());
    assert_eq!(
        participant_routes(&queue_plan),
        BTreeSet::from([
            (SOURCE_LANE, SOURCE_DATASPACE),
            (DESTINATION_LANE, DESTINATION_DATASPACE),
            (CONTRACT_LANE, CONTRACT_DATASPACE),
            (DEPLOY_POLICY_LANE, DEPLOY_POLICY_DATASPACE),
        ])
    );
}
#[test]
fn fx_state_view_rejects_active_sns_dataspace_without_canonical_lane() {
    const SNS_ALIAS: &str = "alpha";
    let fixture = fixture(Some(SNS_ALIAS));
    let dynamic_dataspace =
        iroha_core::sns::dataspace_id_for_sns_alias(SNS_ALIAS).expect("SNS-only dataspace id");
    let transaction = accepted_transaction(
        &fixture.state,
        vec![
            InstructionBox::from(Register::domain(Domain::new(
                DomainId::try_new("merchant", SNS_ALIAS).expect("SNS-scoped domain"),
            ))),
            settlement_instruction(&fixture.corridor, "fx_sns_boundary"),
        ],
    );
    let view = fixture.state.view();
    let queue_plan = fixture.router.try_route_plan_with_view(&transaction, &view);
    let block_plan = evaluate_policy_plan_with_nexus_and_world_at(
        view.nexus(),
        &transaction,
        view.world(),
        LEDGER_TIME_MS,
    );
    for plan in [queue_plan, block_plan] {
        assert!(matches!(
            plan,
            Err(RoutingResolveError::NoLaneForDataspace { dataspace_id })
                if dataspace_id == dynamic_dataspace
        ));
    }
}
