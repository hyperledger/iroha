//! Torii UAID portfolio endpoint tests.
#![cfg(feature = "app_api")]
use axum::extract::connect_info::ConnectInfo;
use http::StatusCode;
use http_body_util::BodyExt as _;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute as _,
    state::{State, World},
};
use iroha_crypto::{Algorithm, Hash, KeyPair, PublicKey};
use iroha_data_model::{
    account::NewAccount,
    asset::{AssetDefinition, AssetId},
    block::BlockHeader,
    isi::{Mint, Register},
    nexus::UniversalAccountId,
    prelude::*,
    sns::{NameControllerV1, NameRecordV1},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::peer::PeerId;
use iroha_test_samples::ALICE_ID;
use nonzero_ext::nonzero;
use norito::json::{self, Value};
use std::sync::Arc;
use tower::ServiceExt as _;
#[path = "fixtures.rs"]
mod fixtures;
const ACCOUNT_SIGNATORY: &str =
    "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245";
#[tokio::test]
async fn accounts_portfolio_endpoint_returns_snapshot() {
    let (app, uaid) = setup_portfolio_app(|state| {
        let (uaid, _accounts) = seed_portfolio_accounts(state);
        uaid
    });
    let uaid_hex = hex::encode(uaid.as_hash().as_ref());
    let mut req = fixtures::get_request(&(format!("/v1/accounts/uaid:{uaid_hex}/portfolio")));
    req.extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))));
    let resp = app.router().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::OK,
        "unexpected body: {}",
        String::from_utf8_lossy(&body)
    );
    let value: Value = json::from_slice(&body).expect("valid portfolio payload");
    assert_eq!(value["totals"]["accounts"], Value::from(1));
    assert_eq!(value["totals"]["positions"], Value::from(2));
    let mut observed_quantities: Vec<String> = value["dataspaces"][0]["accounts"]
        .as_array()
        .expect("accounts array")
        .iter()
        .filter_map(|account| account["assets"].as_array())
        .flat_map(|assets| assets.iter())
        .filter_map(|asset| asset["quantity"].as_str())
        .map(ToOwned::to_owned)
        .collect();
    observed_quantities.sort();
    assert_eq!(
        observed_quantities,
        vec!["250".to_string(), "500".to_string()]
    );
    app.shutdown().await;
}
#[tokio::test]
async fn accounts_portfolio_snapshot_matches_fixture() {
    let (app, uaid) = setup_portfolio_app(seed_fixture_portfolio_accounts);
    let uaid_hex = hex::encode(uaid.as_hash().as_ref());
    let mut req = fixtures::get_request(&(format!("/v1/accounts/uaid:{uaid_hex}/portfolio")));
    req.extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))));
    let resp = app.router().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::OK,
        "unexpected body: {}",
        String::from_utf8_lossy(&body)
    );
    let value: Value = json::from_slice(&body).expect("valid portfolio payload");
    let fixture: Value = json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/nexus/uaid_portfolio/global_default_portfolio.json"
    )))
    .expect("portfolio fixture JSON");
    assert_eq!(value, fixture);
    app.shutdown().await;
}
#[tokio::test]
async fn accounts_portfolio_filters_by_asset_id() {
    let (app, uaid) = setup_portfolio_app(|state| {
        let (uaid, _accounts) = seed_portfolio_accounts(state);
        uaid
    });
    let uaid_hex = hex::encode(uaid.as_hash().as_ref());
    let mut baseline_req =
        fixtures::get_request(&(format!("/v1/accounts/uaid:{uaid_hex}/portfolio")));
    baseline_req
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))));
    let baseline = fixtures::request(&app, baseline_req).await.unwrap();
    let baseline_status = baseline.status();
    let baseline_body = baseline.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        baseline_status,
        StatusCode::OK,
        "unexpected body: {}",
        String::from_utf8_lossy(&baseline_body)
    );
    let baseline_value: Value = json::from_slice(&baseline_body).expect("valid portfolio payload");
    let asset_id = baseline_value["dataspaces"][0]["accounts"][0]["assets"][0]["asset_id"]
        .as_str()
        .expect("baseline asset id")
        .to_owned();
    let mut req = fixtures::get_request(
        &(format!(
            "/v1/accounts/uaid:{uaid_hex}/portfolio?asset_id={}",
            urlencoding::encode(&asset_id)
        )),
    );
    req.extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))));
    let resp = app.router().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::OK,
        "unexpected body: {}",
        String::from_utf8_lossy(&body)
    );
    let value: Value = json::from_slice(&body).expect("valid portfolio payload");
    assert_eq!(value["totals"]["accounts"], Value::from(1));
    assert_eq!(value["totals"]["positions"], Value::from(1));
    let assets = value["dataspaces"][0]["accounts"][0]["assets"]
        .as_array()
        .expect("assets array");
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0]["asset_id"], Value::from(asset_id));
    app.shutdown().await;
}
fn setup_portfolio_app<SeedFn>(
    seed_fn: SeedFn,
) -> (iroha_torii::TestApiRouterRuntime, UniversalAccountId)
where
    SeedFn: FnOnce(&Arc<State>) -> UniversalAccountId,
{
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let local_peer_id = PeerId::new(cfg.common.key_pair.public_key().clone());
    let mut world = World::default();
    fixtures::seed_peer(&mut world, local_peer_id.clone());
    let state = Arc::new(State::new_for_testing(world, kura.clone(), query));
    let uaid = seed_fn(&state);
    let torii = fixtures::StandardToriiHarness::from_state(&cfg, &kura, state.clone());
    let app = torii.router();
    (app, uaid)
}
fn seed_portfolio_accounts(state: &Arc<State>) -> (UniversalAccountId, Vec<AccountId>) {
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::torii_portfolio"));
    let domain_id: DomainId = DomainId::try_new("portfolio", "universal").unwrap();
    let cash_id =
        AssetDefinitionId::derive_from_components(domain_id.clone(), "cash".parse().unwrap());
    let points_id =
        AssetDefinitionId::derive_from_components(domain_id.clone(), "points".parse().unwrap());
    let first_account = account_id_from_signatory(domain_id.clone(), ACCOUNT_SIGNATORY);
    let register: [InstructionBox; 6] = [
        Register::domain(Domain::new(domain_id.clone())).into(),
        Register::account(NewAccount::new(first_account.clone()).with_uaid(Some(uaid))).into(),
        Register::asset_definition(AssetDefinition::numeric(
            cash_id.clone(),
            "cash".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .into(),
        Register::asset_definition(AssetDefinition::numeric(
            points_id.clone(),
            "points".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .into(),
        Mint::asset_quantity(500u64, AssetId::new(cash_id, first_account.clone())).into(),
        Mint::asset_quantity(250u64, AssetId::new(points_id, first_account.clone())).into(),
    ];
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut tx = block.transaction();
    let selector =
        iroha_core::sns::selector_for_domain(&domain_id).expect("domain selector for fixtures");
    let address = iroha_data_model::account::AccountAddress::from_account_id(&ALICE_ID)
        .expect("fixture authority address");
    let record = NameRecordV1::new(
        selector.clone(),
        ALICE_ID.clone(),
        vec![NameControllerV1::account(&address)],
        0,
        0,
        4_000_000_000_000,
        4_100_000_000_000,
        4_200_000_000_000,
        Metadata::default(),
    );
    tx.world_mut_for_testing()
        .smart_contract_state_mut_for_testing()
        .insert(
            iroha_core::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&record),
        );
    for instr in register {
        instr
            .execute(&ALICE_ID, &mut tx)
            .expect("registering portfolio fixtures");
    }
    tx.apply();
    block.commit_world_overlay_for_testing().unwrap();
    (uaid, vec![first_account])
}
fn seed_fixture_portfolio_accounts(state: &Arc<State>) -> UniversalAccountId {
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::torii_fixture"));
    let domain_id: DomainId = DomainId::try_new("portfolio_fixture", "universal").unwrap();
    let cash_id =
        AssetDefinitionId::derive_from_components(domain_id.clone(), "cash".parse().unwrap());
    let points_id =
        AssetDefinitionId::derive_from_components(domain_id.clone(), "points".parse().unwrap());
    let first_account = account_id_from_seed(&domain_id, 0x11);
    let register: [InstructionBox; 6] = [
        Register::domain(Domain::new(domain_id.clone())).into(),
        Register::account(NewAccount::new(first_account.clone()).with_uaid(Some(uaid))).into(),
        Register::asset_definition(AssetDefinition::numeric(
            cash_id.clone(),
            "cash".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .into(),
        Register::asset_definition(AssetDefinition::numeric(
            points_id.clone(),
            "points".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .into(),
        Mint::asset_quantity(875u64, AssetId::new(cash_id, first_account.clone())).into(),
        Mint::asset_quantity(320u64, AssetId::new(points_id, first_account.clone())).into(),
    ];
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut tx = block.transaction();
    let selector =
        iroha_core::sns::selector_for_domain(&domain_id).expect("domain selector for fixtures");
    let address = iroha_data_model::account::AccountAddress::from_account_id(&ALICE_ID)
        .expect("fixture authority address");
    let record = NameRecordV1::new(
        selector.clone(),
        ALICE_ID.clone(),
        vec![NameControllerV1::account(&address)],
        0,
        0,
        4_000_000_000_000,
        4_100_000_000_000,
        4_200_000_000_000,
        Metadata::default(),
    );
    tx.world_mut_for_testing()
        .smart_contract_state_mut_for_testing()
        .insert(
            iroha_core::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&record),
        );
    for instr in register {
        instr
            .execute(&ALICE_ID, &mut tx)
            .expect("registering portfolio fixture");
    }
    tx.apply();
    block.commit_world_overlay_for_testing().unwrap();
    uaid
}
fn account_id_from_signatory(_domain_id: DomainId, signatory_hex: &str) -> AccountId {
    let normalized = signatory_hex
        .strip_prefix("ed0120")
        .unwrap_or(signatory_hex);
    let public_key = PublicKey::from_hex(Algorithm::Ed25519, normalized)
        .expect("signatory literal parses into a public key");
    AccountId::new(public_key)
}
fn account_id_from_seed(_domain_id: &DomainId, seed_byte: u8) -> AccountId {
    let seed = vec![seed_byte; 32];
    let (public, _) = KeyPair::try_from_seed(seed, Algorithm::Ed25519)
        .expect("derive portfolio account key")
        .into_parts();
    AccountId::new(public)
}
