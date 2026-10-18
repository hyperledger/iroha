//! Router-level test for governance read endpoint wiring (`/v1/gov/proposals/{id}`).
#![allow(clippy::similar_names)]
#![cfg(feature = "app_api")]
use axum::{Router, routing::get};
use http_body_util::BodyExt as _;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use iroha_data_model::governance::types::{
    AbiVersion, ContractAbiHash, ContractCodeHash, DeployContractProposal, ProposalKind,
};
use std::sync::Arc;
use tower::ServiceExt as _; // for Router::oneshot
fn checked_router_proposer_fixture() -> iroha_data_model::account::AccountId {
    iroha_data_model::account::AccountId::of(
        iroha_crypto::KeyPair::try_random()
            .expect("generate checked governance router proposer fixture keypair")
            .public_key()
            .clone(),
    )
}
#[test]
fn gov_router_proposer_fixture_uses_checked_ed25519_key_generation() {
    let proposer = checked_router_proposer_fixture();
    let algorithm = proposer
        .expect_single_signatory()
        .try_algorithm()
        .expect("fixture governance router proposer public key has a valid algorithm");
    assert_eq!(algorithm, iroha_crypto::Algorithm::Ed25519);
}
#[tokio::test]
async fn gov_proposal_get_router_mapping() {
    if std::env::var("IROHA_RUN_IGNORED").ok().as_deref() != Some("1") {
        eprintln!("Skipping: gov proposal-get router test gated. Set IROHA_RUN_IGNORED=1 to run.");
        return;
    }
    // Minimal in-memory state and a single proposal record
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let mut raw_state = State::new_for_testing(World::default(), kura, query);
    let id_bytes = [0xCDu8; 32];
    let id_hex = hex::encode(id_bytes);
    let header =
        iroha_data_model::block::BlockHeader::new(nonzero_ext::nonzero!(1_u64), None, None, 0, 0);
    {
        // Open and immediately drop a state block to set up initial header if required.
        let _ = raw_state.block(header);
    }
    let proposer = checked_router_proposer_fixture();
    let rec = iroha_core::state::GovernanceProposalRecord {
        proposer: proposer.clone(),
        kind: ProposalKind::DeployContract(DeployContractProposal {
            proposal_operator: proposer.clone(),
            contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
                .parse()
                .expect("contract address"),
            code_hash: ContractCodeHash::from_hex_str(&"11".repeat(32)).expect("code hash"),
            abi_hash: ContractAbiHash::from_hex_str(&"22".repeat(32)).expect("abi hash"),
            abi_version: AbiVersion::new(1),
            manifest_provenance: None,
        }),
        created_height: 0,
        status: iroha_core::state::GovernanceProposalStatus::Proposed,
    };
    iroha_core::query::insert_gov_proposal_for_test(&mut raw_state, id_bytes, rec);
    // Wire only the GET route under the shared URI constant
    let state = Arc::new(raw_state);
    let app = Router::new().route(
        iroha_torii_shared::route_catalog::runtime_governance::GOV_PROPOSAL_GET.path(),
        get({
            let state = state.clone();
            move |axum::extract::Path(id): axum::extract::Path<String>| async move {
                iroha_torii::handle_gov_get_proposal(state, axum::extract::Path(id)).await
            }
        }),
    );
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("/v1/gov/proposals/{id_hex}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: norito::json::Value = norito::json::from_slice(&body).unwrap();
    assert_eq!(
        v.get("found").and_then(norito::json::Value::as_bool),
        Some(true)
    );
    let proposal_kind = v
        .get("proposal")
        .and_then(|o| o.get("kind"))
        .expect("proposal kind present");
    assert_eq!(
        proposal_kind
            .get("kind")
            .and_then(norito::json::Value::as_str),
        Some("DeployContract")
    );
    let deploy_payload = proposal_kind
        .get("payload")
        .expect("deploy payload present");
    assert_eq!(
        deploy_payload
            .get("contract_address")
            .and_then(norito::json::Value::as_str),
        Some("irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw")
    );
}
