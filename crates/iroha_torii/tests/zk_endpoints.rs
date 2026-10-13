#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Router-level tests for ZK convenience endpoints.
#![cfg(feature = "app_api")]
use axum::{Router, extract::State, routing::post};
use http_body_util::BodyExt as _;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{ElectionState, State as CoreState, StateReadOnly, World, WorldReadOnly},
};
use iroha_data_model::{NewAccount, prelude::*};
use iroha_model_base::domain::DomainId;
use nonzero_ext::nonzero;
use std::{collections::BTreeSet, sync::Arc};
use tower::ServiceExt as _; // for Router::oneshot
const ACCOUNT_SIGNATORY: &str =
    "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03";
fn zk_vote_tally_app(state: Arc<CoreState>) -> Router {
    Router::new().route(
        "/v1/zk/vote/tally",
        post(
            move |headers: http::HeaderMap,
                  req: iroha_torii::NoritoJson<iroha_torii::ZkVoteGetTallyRequestDto>| {
                let state = state.clone();
                let accept = headers.get(http::header::ACCEPT).cloned();
                async move { iroha_torii::handle_v1_zk_vote_tally(State(state), accept, req).await }
            },
        ),
    )
}
fn state_with_tally_read_fixture(election: ElectionState) -> (Arc<CoreState>, u64, String) {
    // Seed the test-only World before signed genesis execution. This exercises
    // retained readback without substituting for private ballot or tally proof
    // admission.
    let mut state = CoreState::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    transaction
        .world
        .elections_mut()
        .insert("election-fixture".to_owned(), election);
    transaction.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("seed pre-genesis election read fixture");
    let genesis_signer =
        iroha_crypto::KeyPair::try_from_seed(vec![0xA9; 32], iroha_crypto::Algorithm::Ed25519)
            .expect("deterministic fixture genesis signer");
    let mut config =
        iroha_core::sumeragi::test_chain::TestChainConfig::new(std::mem::take(&mut state.world), 1);
    config.genesis_key = genesis_signer;
    let chain = iroha_core::sumeragi::test_chain::CertifiedTestChain::start(config)
        .expect("original election query genesis");
    let state = chain.state().clone();
    let signed_genesis = chain.genesis();
    let view = state.view();
    let height = u64::try_from(view.height()).expect("fixture height fits u64");
    assert_eq!(height, 1);
    let hash = view
        .latest_block_hash()
        .map(|hash| hex::encode(hash.as_ref()))
        .expect("fixture block hash");
    assert_eq!(hash, hex::encode(signed_genesis.hash().as_ref()));
    assert_eq!(
        view.latest_block()
            .expect("funded canonical history read")
            .expect("fixture signed block body")
            .hash(),
        signed_genesis.hash()
    );
    drop(view);
    (state, height, hash)
}
fn state_with_registered_asset_definition() -> (Arc<CoreState>, String) {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = CoreState::new_for_testing(World::new(), kura, query);
    let domain_id = DomainId::try_new("zkd", "universal").expect("domain id");
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "rose".parse().expect("asset definition name"),
    );
    let owner = AccountId::new(ACCOUNT_SIGNATORY.parse().expect("public key"));
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    for instruction in [
        Register::domain(Domain::new(domain_id)).into(),
        Register::account(NewAccount::new(owner.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            asset_definition_id.clone(),
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .into(),
    ] {
        transaction
            .world
            .executor()
            .clone()
            .execute_instruction(&mut transaction, &owner, instruction)
            .expect("seed instruction must succeed");
    }
    transaction.apply();
    block.transactions.insert_block(
        BTreeSet::<iroha_crypto::HashOf<iroha_data_model::transaction::TransactionEntrypoint>>::new(
        ),
        nonzero!(1_usize),
    );
    let _ = block.commit();
    (Arc::new(state), asset_definition_id.to_string())
}
#[tokio::test]
async fn zk_roots_endpoint_returns_200_for_registered_asset_without_shielded_state() {
    let (state, asset_id) = state_with_registered_asset_definition();
    let app = Router::new().route(
        "/v1/zk/roots",
        post({
            let state = state.clone();
            move |req: iroha_torii::NoritoJson<iroha_torii::ZkRootsGetRequestDto>| async move {
                iroha_torii::handle_v1_zk_roots(state, None, req).await
            }
        }),
    );
    let body_value = iroha_torii::json_object(vec![
        iroha_torii::json_entry("asset_id", asset_id),
        iroha_torii::json_entry("max", 10u64),
    ]);
    let body = norito::json::to_string(&body_value).expect("serialize roots request");
    let req = http::Request::builder()
        .method("POST")
        .uri("/v1/zk/roots")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    // Basic shape keys
    assert!(v.get("latest").is_some());
    assert!(v.get("roots").is_some());
    assert!(v.get("evaluated_block_height").is_some());
    assert!(v.get("evaluated_block_hash").is_some());
    assert_eq!(v.get("latest").and_then(|value| value.as_str()), Some(""));
    assert_eq!(
        v.get("roots")
            .and_then(|value| value.as_array())
            .map(std::vec::Vec::len),
        Some(0)
    );
    assert_eq!(
        v.get("evaluated_block_height")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        v.get("evaluated_block_hash")
            .and_then(|value| value.as_str())
            .map(str::len),
        Some(64)
    );
}
#[tokio::test]
async fn zk_roots_endpoint_returns_404_for_missing_asset() {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = Arc::new(CoreState::new_for_testing(World::default(), kura, query));
    let app = Router::new().route(
        "/v1/zk/roots",
        post({
            let state = state.clone();
            move |req: iroha_torii::NoritoJson<iroha_torii::ZkRootsGetRequestDto>| async move {
                iroha_torii::handle_v1_zk_roots(state, None, req).await
            }
        }),
    );
    let missing_asset_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("missing", "universal").expect("domain id"),
        "rose".parse().expect("asset definition name"),
    )
    .to_string();
    let body_value = iroha_torii::json_object(vec![
        iroha_torii::json_entry("asset_id", missing_asset_id),
        iroha_torii::json_entry("max", 10u64),
    ]);
    let body = norito::json::to_string(&body_value).expect("serialize roots request");
    let req = http::Request::builder()
        .method("POST")
        .uri("/v1/zk/roots")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}
#[tokio::test]
async fn zk_roots_endpoint_returns_404_for_missing_asset_alias() {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = Arc::new(CoreState::new_for_testing(World::default(), kura, query));
    let app = Router::new().route(
        "/v1/zk/roots",
        post({
            let state = state.clone();
            move |req: iroha_torii::NoritoJson<iroha_torii::ZkRootsGetRequestDto>| async move {
                iroha_torii::handle_v1_zk_roots(state, None, req).await
            }
        }),
    );
    let body_value = iroha_torii::json_object(vec![
        iroha_torii::json_entry("asset_id", "rose#missing"),
        iroha_torii::json_entry("max", 10u64),
    ]);
    let body = norito::json::to_string(&body_value).expect("serialize roots request");
    let req = http::Request::builder()
        .method("POST")
        .uri("/v1/zk/roots")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}
#[tokio::test]
async fn zk_roots_endpoint_returns_403_for_invalid_asset_selector() {
    let (state, _) = state_with_registered_asset_definition();
    let app = Router::new().route(
        "/v1/zk/roots",
        post({
            let state = state.clone();
            move |req: iroha_torii::NoritoJson<iroha_torii::ZkRootsGetRequestDto>| async move {
                iroha_torii::handle_v1_zk_roots(state, None, req).await
            }
        }),
    );
    let body_value = iroha_torii::json_object(vec![
        iroha_torii::json_entry("asset_id", "prefix:not-a-real-selector"),
        iroha_torii::json_entry("max", 10u64),
    ]);
    let body = norito::json::to_string(&body_value).expect("serialize roots request");
    let req = http::Request::builder()
        .method("POST")
        .uri("/v1/zk/roots")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
}
#[tokio::test]
async fn zk_roots_endpoint_returns_403_for_blank_asset_selector() {
    let (state, _) = state_with_registered_asset_definition();
    let app = Router::new().route(
        "/v1/zk/roots",
        post({
            let state = state.clone();
            move |req: iroha_torii::NoritoJson<iroha_torii::ZkRootsGetRequestDto>| async move {
                iroha_torii::handle_v1_zk_roots(state, None, req).await
            }
        }),
    );
    let body_value = iroha_torii::json_object(vec![
        iroha_torii::json_entry("asset_id", "   "),
        iroha_torii::json_entry("max", 10u64),
    ]);
    let body = norito::json::to_string(&body_value).expect("serialize roots request");
    let req = http::Request::builder()
        .method("POST")
        .uri("/v1/zk/roots")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
}
#[tokio::test]
async fn zk_vote_tally_endpoint_returns_404_for_missing_election() {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = Arc::new(CoreState::new_for_testing(World::default(), kura, query));
    let app = zk_vote_tally_app(state);
    let body_value =
        iroha_torii::json_object(vec![iroha_torii::json_entry("election_id", "nonexistent")]);
    let body = norito::json::to_string(&body_value).expect("serialize tally request");
    let req = http::Request::builder()
        .method("POST")
        .uri("/v1/zk/vote/tally")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}
#[tokio::test]
async fn zk_vote_tally_endpoint_enforces_canonical_selector_for_json_and_norito() {
    let state = Arc::new(CoreState::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    ));
    let app = zk_vote_tally_app(state);
    for election_id in [
        String::new(),
        ".".to_owned(),
        ".hidden".to_owned(),
        "election/alias".to_owned(),
        "election%2Falias".to_owned(),
        "election alias".to_owned(),
        "élection".to_owned(),
        "a".repeat(129),
    ] {
        let dto = iroha_torii::ZkVoteGetTallyRequestDto {
            election_id: election_id.clone(),
        };
        let json =
            norito::json::to_string(&iroha_torii::json_object(vec![iroha_torii::json_entry(
                "election_id",
                election_id.clone(),
            )]))
            .expect("serialize JSON tally request");
        let norito = norito::to_bytes(&dto).expect("encode Norito tally request");
        for (content_type, body) in [
            ("application/json", json.into_bytes()),
            ("application/x-norito", norito),
        ] {
            let request = http::Request::builder()
                .method("POST")
                .uri("/v1/zk/vote/tally")
                .header(http::header::CONTENT_TYPE, content_type)
                .body(axum::body::Body::from(body))
                .expect("build tally request");
            let response = app.clone().oneshot(request).await.expect("route response");
            assert_eq!(
                response.status(),
                http::StatusCode::BAD_REQUEST,
                "{content_type} accepted noncanonical selector {election_id:?}"
            );
        }
    }
    for election_id in ["a".to_owned(), "a".repeat(128)] {
        let json =
            norito::json::to_string(&iroha_torii::json_object(vec![iroha_torii::json_entry(
                "election_id",
                election_id,
            )]))
            .expect("serialize valid tally request");
        let request = http::Request::builder()
            .method("POST")
            .uri("/v1/zk/vote/tally")
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(json))
            .expect("build valid tally request");
        let response = app.clone().oneshot(request).await.expect("route response");
        assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn zk_vote_tally_endpoint_preserves_exact_u128_and_committed_identity() {
    let exact_weight = u128::MAX;
    let (state, height, hash) = state_with_tally_read_fixture(ElectionState {
        options: 2,
        finalized: true,
        tally: vec![exact_weight, 0],
        ..ElectionState::default()
    });
    let app = zk_vote_tally_app(state.clone());
    let body = norito::json::to_string(&iroha_torii::json_object(vec![iroha_torii::json_entry(
        "election_id",
        "election-fixture",
    )]))
    .expect("serialize tally request");
    let request = http::Request::builder()
        .method("POST")
        .uri("/v1/zk/vote/tally")
        .header(http::header::ACCEPT, "application/json")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .expect("build tally request");
    let response = app.oneshot(request).await.expect("route response");
    assert_eq!(
        response.headers().get(http::header::CONTENT_TYPE),
        Some(&http::HeaderValue::from_static("application/json"))
    );
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("read response")
        .to_bytes();
    assert_eq!(
        status,
        http::StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let json = std::str::from_utf8(&bytes).expect("UTF-8 tally response");
    assert!(json.contains(&exact_weight.to_string()));
    let decoded: iroha_torii::ZkVoteGetTallyResponseDto =
        norito::json::from_slice(&bytes).expect("decode exact tally JSON");
    assert!(decoded.finalized);
    assert_eq!(decoded.tally, vec![exact_weight, 0]);
    assert_eq!(decoded.evaluated_block_height, height);
    assert_eq!(decoded.evaluated_block_hash, hash);

    let norito = iroha_torii::handle_v1_zk_vote_tally(
        State(state),
        Some(http::HeaderValue::from_static("application/x-norito")),
        iroha_torii::NoritoJson(iroha_torii::ZkVoteGetTallyRequestDto {
            election_id: "election-fixture".to_owned(),
        }),
    )
    .await
    .expect("Norito tally handler response");
    assert_eq!(
        norito.headers().get(http::header::CONTENT_TYPE),
        Some(&http::HeaderValue::from_static("application/x-norito"))
    );
    let bytes = norito
        .into_body()
        .collect()
        .await
        .expect("read Norito response")
        .to_bytes();
    let decoded_norito: iroha_torii::ZkVoteGetTallyResponseDto =
        norito::decode_from_bytes(&bytes).expect("decode Norito tally response");
    assert_eq!(decoded_norito.tally, decoded.tally);
    assert_eq!(decoded_norito.evaluated_block_height, height);
    assert_eq!(decoded_norito.evaluated_block_hash, hash);
}

#[tokio::test]
async fn zk_vote_tally_endpoint_rejects_malformed_or_partial_retained_results() {
    for election in [
        ElectionState {
            options: 1,
            tally: vec![0],
            ..ElectionState::default()
        },
        ElectionState {
            options: 2,
            tally: vec![0],
            ..ElectionState::default()
        },
        ElectionState {
            options: 2,
            finalized: true,
            tally: vec![u128::MAX, 1],
            ..ElectionState::default()
        },
        ElectionState {
            options: 2,
            start_ts: 10,
            end_ts: 9,
            tally: vec![0, 0],
            ..ElectionState::default()
        },
        ElectionState {
            options: 2,
            tally: vec![1, 0],
            ..ElectionState::default()
        },
    ] {
        let (state, _, _) = state_with_tally_read_fixture(election);
        let app = zk_vote_tally_app(state);
        let body =
            norito::json::to_string(&iroha_torii::json_object(vec![iroha_torii::json_entry(
                "election_id",
                "election-fixture",
            )]))
            .expect("serialize tally request");
        let request = http::Request::builder()
            .method("POST")
            .uri("/v1/zk/vote/tally")
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body))
            .expect("build tally request");
        let response = app.oneshot(request).await.expect("route response");
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }
}
