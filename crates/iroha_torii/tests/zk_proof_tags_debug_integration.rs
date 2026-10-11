#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Integration test for /v1/zk/proof-tags/{backend}/{hash} (feature `zk-proof-tags`).
#![cfg(all(feature = "app_api", feature = "zk-proof-tags"))]
use axum::{Router, routing::get};
use http_body_util::BodyExt as _;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use iroha_data_model::proof::ProofId;
use nonzero_ext::nonzero;
use std::sync::Arc;
use tower::ServiceExt as _;
#[tokio::test]
async fn proof_tags_returns_ascii_tags() {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::new(), kura, query);
    // Insert tag index directly (prototype path)
    let backend = "pipa-r/pasta";
    let proof_hash = [0x44; 32];
    let id = ProofId {
        backend: backend.into(),
        proof_hash,
    };
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    {
        let mut block = state.block(header);
        let mut stx = block.transaction();
        stx.world
            .proof_tags_mut_for_testing()
            .insert(id.clone(), vec![*b"PROF", *b"I10P"]);
        stx.world
            .proofs_by_tag_mut_for_testing()
            .insert(*b"PROF", vec![id.clone()]);
        stx.world
            .proofs_by_tag_mut_for_testing()
            .insert(*b"I10P", vec![id.clone()]);
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit proof tag indexes");
    }
    let state = Arc::new(state);
    let app = Router::new().route(
        "/v1/zk/proof-tags/{backend}/{hash}",
        get({
            let state = state.clone();
            move |path: axum::extract::Path<(String, String)>| async move {
                iroha_torii::handle_get_proof_tags(state, path).await
            }
        }),
    );
    let backend_enc = urlencoding::encode(backend);
    let hash_hex = hex::encode(proof_hash);
    let uri = format!("/v1/zk/proof-tags/{}/{}", backend_enc, hash_hex);
    let req = http::Request::builder()
        .method("GET")
        .uri(uri)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let arr: Vec<String> =
        norito::json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(arr, vec!["PROF".to_string(), "I10P".to_string()]);
}
