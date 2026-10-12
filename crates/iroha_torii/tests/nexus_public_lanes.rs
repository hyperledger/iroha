#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Tests for the Nexus public-lane REST endpoints.
#![cfg(feature = "app_api")]
use axum::{body::Body, http::Request};
use http::StatusCode;
use http_body_util::BodyExt;
use iroha_config::parameters::actual::Queue;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World, WorldReadOnly},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    Registrable,
    account::{Account, AccountId},
    asset::{Asset, AssetDefinition, AssetDefinitionId, AssetId},
    block::BlockHeader,
    consensus::{ConsensusKeyId, ConsensusKeyRecord, ConsensusKeyRole, ConsensusKeyStatus},
    domain::Domain,
    isi::{
        Grant, RegisterPeerWithPop,
        consensus_keys::RegisterConsensusKey,
        staking::{BondPublicLaneStake, RegisterPublicLaneValidator},
    },
    nexus::{
        PublicLaneMonetaryBondV1, PublicLaneMonetaryPlanV1, PublicLaneMonetaryPreconditionV1,
        PublicLaneMonetaryRegistrationV1, PublicLaneMonetaryScopeV1,
    },
    parameter::{Parameter, system::SumeragiNposParameters},
    permission::Permission,
};
use iroha_executor_data_model::permission::governance::CanManageConsensusKeys;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_model_base::peer::PeerId;
use iroha_model_base::topology::LaneId;
use iroha_primitives::{json::Json, numeric::Quantity};
use norito::json::{self, Value};
use std::{net::SocketAddr, num::NonZeroU64, str::FromStr, sync::Arc};
use tokio::sync::broadcast;
#[path = "fixtures.rs"]
mod fixtures;
fn with_loopback_connect_info(mut request: Request<Body>) -> Request<Body> {
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            0,
        ))));
    request
}
fn configure_nexus_staking(state: &mut State, escrow: &AccountId) {
    let mut nexus = state.nexus_snapshot();
    nexus.staking.stake_asset_id = stake_asset_definition_id().to_string();
    nexus.staking.stake_escrow_account_id = escrow.to_string();
    nexus.staking.slash_sink_account_id = escrow.to_string();
    state
        .set_nexus(nexus)
        .expect("configure Nexus staking for public-lane fixture");
}
fn relax_consensus_key_activation_for_tests(state: &mut State) {
    let mut sumeragi_params = state.view().world().parameters().sumeragi.clone();
    sumeragi_params.key_activation_lead_blocks = 0;
    state.set_sumeragi_parameters(&sumeragi_params);
}
#[tokio::test]
async fn nexus_public_lane_endpoints_exist() {
    let (world, validator_keypair, validator, delegator, escrow) = sample_world();
    let kura = Kura::blank_kura_for_testing();
    let mut state = State::new_for_testing(world, Arc::clone(&kura), LiveQueryStore::start_test());
    configure_nexus_staking(&mut state, &escrow);
    relax_consensus_key_activation_for_tests(&mut state);
    seed_public_lane_state(&state, &validator_keypair, &validator, &delegator);
    let local_peer_id = PeerId::from(validator_keypair.public_key().clone());
    let router = build_test_router(Arc::new(state), &kura, local_peer_id);
    let resp = fixtures::request(
        &router,
        with_loopback_connect_info(fixtures::get_request(
            &("/v1/nexus/public-lanes/0/validators"),
        )),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    fixtures::response_body(resp, "public lane endpoint response").await;
    let resp = fixtures::request(
        &router,
        with_loopback_connect_info(fixtures::get_request(&("/v1/nexus/public-lanes/0/stake"))),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    fixtures::response_body(resp, "public lane endpoint response").await;
    router.shutdown().await;
}
#[tokio::test]
async fn nexus_public_lane_endpoints_list_records() {
    let (world, validator_keypair, validator, delegator, escrow) = sample_world();
    let kura = Kura::blank_kura_for_testing();
    let mut state = State::new_for_testing(world, Arc::clone(&kura), LiveQueryStore::start_test());
    configure_nexus_staking(&mut state, &escrow);
    relax_consensus_key_activation_for_tests(&mut state);
    seed_public_lane_state(&state, &validator_keypair, &validator, &delegator);
    let local_peer_id = PeerId::from(validator_keypair.public_key().clone());
    let router = build_test_router(Arc::new(state), &kura, local_peer_id);
    let resp = fixtures::request(
        &router,
        with_loopback_connect_info(fixtures::get_request(
            &("/v1/nexus/public-lanes/0/validators"),
        )),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp.into_body()).await;
    assert_eq!(json["total"], Value::from(1));
    assert_eq!(
        json["items"][0]["validator"],
        Value::from(validator.to_string())
    );
    assert_eq!(
        json["items"][0]["total_stake"],
        Value::from("1250".to_string())
    );
    let resp = fixtures::request(
        &router,
        with_loopback_connect_info(fixtures::get_request(&("/v1/nexus/public-lanes/0/stake"))),
    )
    .await
    .unwrap();
    let shares = read_json(resp.into_body()).await;
    assert_eq!(shares["total"], Value::from(2));
    let resp = fixtures::request(
        &router,
        with_loopback_connect_info(fixtures::get_request(
            &(format!("/v1/nexus/public-lanes/0/stake?validator={validator}")),
        )),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    router.shutdown().await;
}
fn sample_world() -> (World, KeyPair, AccountId, AccountId, AccountId) {
    let domain_id: DomainId = DomainId::try_new("nexus", "universal").expect("domain id");
    let validator_keypair =
        KeyPair::try_from_seed(vec![0x01; 32], Algorithm::BlsNormal).expect("derive validator key");
    let validator_id = AccountId::new(validator_keypair.public_key().clone());
    let validator = Account::new(validator_id.clone()).build(&validator_id);
    let delegator_keypair =
        KeyPair::try_from_seed(vec![0x02; 32], Algorithm::Ed25519).expect("derive delegator key");
    let delegator_id = AccountId::new(delegator_keypair.public_key().clone());
    let delegator = Account::new(delegator_id.clone()).build(&delegator_id);
    let escrow_keypair =
        KeyPair::try_from_seed(vec![0x04; 32], Algorithm::Ed25519).expect("derive escrow key");
    let escrow_id = AccountId::new(escrow_keypair.public_key().clone());
    let escrow = Account::new(escrow_id.clone()).build(&escrow_id);
    let domain = Domain::new(domain_id.clone()).build(&validator_id);
    let asset_definition_id = stake_asset_definition_id();
    let asset_definition = AssetDefinition::numeric(
        asset_definition_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&validator_id);
    let validator_asset_id = AssetId::new(asset_definition_id.clone(), validator_id.clone());
    let delegator_asset_id = AssetId::new(asset_definition_id.clone(), delegator_id.clone());
    let validator_asset = Asset::new(validator_asset_id, Quantity::from(10_000_u64));
    let delegator_asset = Asset::new(delegator_asset_id, Quantity::from(10_000_u64));
    let world = World::with_assets(
        [domain],
        [validator, delegator, escrow],
        [asset_definition],
        [validator_asset, delegator_asset],
        [],
    );
    let npos = SumeragiNposParameters::default();
    npos.validate()
        .expect("valid committed NPoS fixture parameters");
    {
        let mut block = world.block();
        block
            .parameters
            .get_mut()
            .set_parameter(Parameter::Custom(npos.into_custom_parameter()))
            .expect("install valid committed NPoS fixture parameters");
        block.commit();
    }
    (
        world,
        validator_keypair,
        validator_id,
        delegator_id,
        escrow_id,
    )
}
fn stake_asset_definition_id() -> AssetDefinitionId {
    SumeragiNposParameters::default().xor_asset_definition_id
}
fn seed_public_lane_state(
    state: &State,
    validator_keypair: &KeyPair,
    validator: &AccountId,
    delegator: &AccountId,
) {
    let nexus = state.nexus_snapshot();
    let definition: AssetDefinitionId = nexus
        .staking
        .stake_asset_id
        .parse()
        .expect("configured fixture asset");
    let escrow = AccountId::parse_encoded(&nexus.staking.stake_escrow_account_id)
        .expect("configured fixture custody");
    let mut block = state.block(block_header(1));
    let mut tx = block.transaction();
    let manage_consensus_keys = Permission::from(CanManageConsensusKeys);
    Grant::account_permission(manage_consensus_keys, validator.clone())
        .execute(validator, &mut tx)
        .expect("grant manage consensus keys");
    let peer_id = PeerId::from(validator_keypair.public_key().clone());
    let pop = iroha_crypto::bls_normal_pop_prove(validator_keypair.private_key())
        .expect("PoP prove for validator keypair");
    let consensus_pop = pop.clone();
    RegisterPeerWithPop::new(peer_id.clone(), pop)
        .execute(validator, &mut tx)
        .expect("peer registration");
    let consensus_id = ConsensusKeyId::new(ConsensusKeyRole::Validator, "main");
    let consensus_record = ConsensusKeyRecord {
        id: consensus_id.clone(),
        public_key: validator_keypair.public_key().clone(),
        pop: Some(consensus_pop),
        activation_height: 1,
        expiry_height: None,
        replaces: None,
        status: ConsensusKeyStatus::Active,
    };
    RegisterConsensusKey {
        id: consensus_id,
        record: consensus_record,
    }
    .execute(validator, &mut tx)
    .expect("consensus key registration");
    let mut metadata = Metadata::default();
    metadata.insert(
        Name::from_str("alias").expect("alias key"),
        Json::from("validator-01"),
    );
    let escrow_asset = AssetId::new(definition.clone(), escrow);
    let network_scope = PublicLaneMonetaryScopeV1::Network(*state.network_id_ref());
    RegisterPublicLaneValidator {
        lane_id: LaneId::SINGLE,
        validator: validator.clone(),
        peer_id: PeerId::from(validator.expect_single_signatory().clone()),
        stake_account: validator.clone(),
        initial_stake: Quantity::from(1000_u32),
        metadata,
        monetary_plan: PublicLaneMonetaryPlanV1 {
            network_scope: network_scope.clone(),
            valid_until_height: 1,
            source_asset: AssetId::new(definition.clone(), validator.clone()),
            destination_asset: escrow_asset.clone(),
            amount: Quantity::from(1000_u32),
            precondition: PublicLaneMonetaryPreconditionV1::Registration(
                PublicLaneMonetaryRegistrationV1 {
                    activation_height: 1,
                },
            ),
        },
    }
    .execute(validator, &mut tx)
    .expect("validator registration");
    BondPublicLaneStake {
        lane_id: LaneId::SINGLE,
        validator: validator.clone(),
        staker: delegator.clone(),
        amount: Quantity::from(250_u32),
        metadata: Metadata::default(),
        monetary_plan: PublicLaneMonetaryPlanV1 {
            network_scope,
            valid_until_height: 1,
            source_asset: AssetId::new(definition, delegator.clone()),
            destination_asset: escrow_asset,
            amount: Quantity::from(250_u32),
            precondition: PublicLaneMonetaryPreconditionV1::Bond(PublicLaneMonetaryBondV1 {
                activation_height: 1,
                peer_id,
            }),
        },
    }
    .execute(delegator, &mut tx)
    .expect("bond stake");
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit block");
}
fn build_test_router(
    state: Arc<State>,
    kura: &Arc<Kura>,
    local_peer_id: PeerId,
) -> iroha_torii::TestApiRouterRuntime {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let queue_cfg = Queue::default();
    let (events_tx, _events_rx) = broadcast::channel(1);
    let queue = Arc::new(iroha_core::queue::Queue::from_config(queue_cfg, events_tx));
    let torii = fixtures::ToriiHarness::new(
        &cfg,
        kura,
        &state,
        &queue,
        &local_peer_id,
        broadcast::channel(1).0,
        iroha_config::parameters::actual::TelemetryProfile::Operator,
    );
    torii.router()
}
fn block_header(height: u64) -> BlockHeader {
    BlockHeader::new(
        NonZeroU64::new(height).expect("height must be non-zero"),
        None,
        None,
        height,
        0,
    )
}
async fn read_json(body: Body) -> Value {
    json::from_slice(&collect_body(body).await).expect("valid JSON payload")
}
async fn collect_body(body: Body) -> Vec<u8> {
    body.collect()
        .await
        .expect("body collection")
        .to_bytes()
        .to_vec()
}
