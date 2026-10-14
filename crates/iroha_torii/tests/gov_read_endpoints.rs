//! Torii handler tests for governance read endpoints: proposal/referendum/locks/tally.
#![allow(unexpected_cfgs, clippy::similar_names, clippy::too_many_lines)]
use axum::{extract::Path as AxPath, response::IntoResponse};
use http_body_util::BodyExt as _;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World, WorldReadOnly},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::governance::types::{
    AbiVersion, ContractAbiHash, ContractCodeHash, DeployContractProposal, ProposalKind,
};
use mv::storage::StorageReadOnly;
use std::sync::Arc;
fn checked_governance_read_ed25519_key_fixture() -> KeyPair {
    KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
        .expect("generate checked governance read endpoint Ed25519 fixture keypair")
}
#[test]
fn governance_read_fixture_uses_checked_ed25519_key_generation() {
    let key_pair = checked_governance_read_ed25519_key_fixture();
    let algorithm = key_pair
        .public_key()
        .try_algorithm()
        .expect("fixture governance read public key has a valid algorithm");
    assert_eq!(algorithm, Algorithm::Ed25519);
}
#[tokio::test]
async fn gov_proposal_get_returns_record() {
    let mut st_raw = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    // Insert a proposal record under a known id
    let id_bytes = [0xAAu8; 32];
    let id_hex = hex::encode(id_bytes);
    // Build a minimal proposer id
    let kp = checked_governance_read_ed25519_key_fixture();
    let proposer: iroha_data_model::account::AccountId =
        iroha_data_model::account::AccountId::new(kp.public_key().clone());
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
    iroha_core::query::insert_gov_proposal_for_test(&mut st_raw, id_bytes, rec);
    {
        let view = st_raw.view();
        assert!(
            view.world().governance_proposals().get(&id_bytes).is_some(),
            "proposal record should be present in state"
        );
    }
    let state = Arc::new(st_raw);
    let resp = iroha_torii::handle_gov_get_proposal(state.clone(), AxPath(id_hex))
        .await
        .expect("handler ok")
        .into_response();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: norito::json::Value = norito::json::from_slice(&body).unwrap();
    assert_eq!(
        v.get("found").and_then(norito::json::Value::as_bool),
        Some(true)
    );
    let proposal_obj = v
        .get("proposal")
        .and_then(norito::json::Value::as_object)
        .expect("proposal present");
    let kind_obj = proposal_obj
        .get("kind")
        .and_then(norito::json::Value::as_object)
        .expect("kind present");
    assert_eq!(
        kind_obj.get("kind").and_then(norito::json::Value::as_str),
        Some("DeployContract")
    );
    let deploy_payload = kind_obj
        .get("payload")
        .and_then(norito::json::Value::as_object)
        .expect("deploy payload present");
    assert_eq!(
        deploy_payload
            .get("contract_address")
            .and_then(norito::json::Value::as_str),
        Some("irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw")
    );
}
#[tokio::test]
async fn gov_proposal_get_invalid_id_and_missing_entry() {
    let state = Arc::new(State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    ));
    // Case 1: invalid hex (odd length)
    let err = iroha_torii::handle_gov_get_proposal(state.clone(), AxPath("abc".to_string()))
        .await
        .expect_err("expected error for invalid id hex");
    match err {
        iroha_torii::Error::Query(vf) => match vf {
            iroha_data_model::ValidationFail::QueryFailed(qf) => match qf {
                iroha_data_model::query::error::QueryExecutionFail::Conversion(msg) => {
                    assert_eq!(msg, "proposal id must be exact lowercase 32-byte hex");
                }
                other => panic!("unexpected query fail variant: {other:?}"),
            },
            other => panic!("unexpected validation fail: {other:?}"),
        },
        other => panic!("unexpected error type: {other:?}"),
    }
    // Case 2: valid hex but wrong length (31 bytes)
    let bad_len = "aa".repeat(31);
    let err = iroha_torii::handle_gov_get_proposal(state.clone(), AxPath(bad_len))
        .await
        .expect_err("expected error for invalid id length");
    match err {
        iroha_torii::Error::Query(vf) => match vf {
            iroha_data_model::ValidationFail::QueryFailed(qf) => match qf {
                iroha_data_model::query::error::QueryExecutionFail::Conversion(msg) => {
                    assert_eq!(msg, "proposal id must be exact lowercase 32-byte hex");
                }
                other => panic!("unexpected query fail variant: {other:?}"),
            },
            other => panic!("unexpected validation fail: {other:?}"),
        },
        other => panic!("unexpected error type: {other:?}"),
    }
    // Case 3: well-formed (32-byte) id that does not exist → found=false
    let missing = "bb".repeat(32);
    let resp = iroha_torii::handle_gov_get_proposal(state, AxPath(missing))
        .await
        .expect("handler ok for missing entry")
        .into_response();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: norito::json::Value = norito::json::from_slice(&body).unwrap();
    assert_eq!(
        v.get("found").and_then(norito::json::Value::as_bool),
        Some(false)
    );
}
#[tokio::test]
async fn gov_referendum_and_locks_and_tally_endpoints() {
    let mut raw_state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    // Prepare a referendum record and a locks record under rid = "r1"
    let rid = "r1".to_string();
    // Referendum record
    let rr = iroha_core::state::GovernanceReferendumRecord {
        h_start: 0,
        h_end: 100,
        status: iroha_core::state::GovernanceReferendumStatus::Open,
        mode: iroha_core::state::GovernanceReferendumMode::Plain,
        plain_context: iroha_core::query::standalone_plain_test_fixture::context(&raw_state.gov, 0),
        plain_result: iroha_data_model::governance::conviction::PlainVotingResultV1::Pending,
    };
    // Locks: one Aye with amount=10000, duration=conviction_step_blocks (factor=2 before clamp).
    let kp = checked_governance_read_ed25519_key_fixture();
    let owner: iroha_data_model::account::AccountId =
        iroha_data_model::account::AccountId::new(kp.public_key().clone());
    let conviction_step = raw_state.gov.conviction_step_blocks.max(1);
    let duration_blocks = conviction_step;
    let max_conviction = raw_state.gov.max_conviction;
    let mut locks = iroha_core::state::GovernanceLocksForReferendum::default();
    let rec = iroha_core::state::GovernanceLockRecord {
        owner: owner.clone(),
        amount: 10_000_u64.into(),
        slashed: 0_u64.into(),
        expiry_height: 1_000,
        direction: 0, // approve
        duration_blocks,
        custody: iroha_core::state::GovernanceLockCustody {
            escrowed: true,
            asset_definition_id: raw_state.gov.voting_asset_id.clone(),
            bond_escrow_account: raw_state.gov.bond_escrow_account.clone(),
            slash_receiver_account: raw_state.gov.slash_receiver_account.clone(),
        },
    };
    locks.locks.insert(owner, rec);
    let prev_height = raw_state.view().height();
    assert_eq!(prev_height, 0, "fresh test state should start at height 0");
    iroha_core::query::insert_gov_referendum_for_test(&mut raw_state, rid.clone(), rr.clone());
    iroha_core::query::insert_gov_locks_for_test(&mut raw_state, rid.clone(), locks);
    let empty_rid = "empty-rid".to_string();
    iroha_core::query::insert_gov_referendum_for_test(&mut raw_state, empty_rid.clone(), rr);
    let state = Arc::new(raw_state);
    // GET referendum
    let resp_r = iroha_torii::handle_gov_get_referendum(state.clone(), AxPath(rid.clone()))
        .await
        .expect("handler ok")
        .into_response();
    assert_eq!(resp_r.status(), http::StatusCode::OK);
    let br = resp_r.into_body().collect().await.unwrap().to_bytes();
    let vr: norito::json::Value = norito::json::from_slice(&br).unwrap();
    assert_eq!(
        vr.get("found").and_then(norito::json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        vr.get("referendum")
            .and_then(|o| o.get("mode"))
            .and_then(norito::json::Value::as_str),
        Some("Plain")
    );
    // GET locks
    let resp_l = iroha_torii::handle_gov_get_locks(state.clone(), AxPath(rid.clone()))
        .await
        .expect("handler ok")
        .into_response();
    assert_eq!(resp_l.status(), http::StatusCode::OK);
    let bl = resp_l.into_body().collect().await.unwrap().to_bytes();
    let vl: norito::json::Value = norito::json::from_slice(&bl).unwrap();
    assert_eq!(
        vl.get("found").and_then(norito::json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        vl.get("referendum_id")
            .and_then(norito::json::Value::as_str),
        Some(&rid[..])
    );
    // GET tally: sqrt(10000) = 100, conviction factor = 1 + duration/step.
    let resp_t = iroha_torii::handle_gov_get_tally(state.clone(), AxPath(rid))
        .await
        .expect("handler ok")
        .into_response();
    assert_eq!(resp_t.status(), http::StatusCode::OK);
    let bt = resp_t.into_body().collect().await.unwrap().to_bytes();
    let vt: norito::json::Value = norito::json::from_slice(&bt).unwrap();
    let mut factor = 1u64 + (duration_blocks / conviction_step);
    if factor > max_conviction {
        factor = max_conviction;
    }
    let expected_approve = 100u128.saturating_mul(u128::from(factor));
    assert_eq!(
        vt.get("approve").and_then(norito::json::Value::as_u64),
        Some(expected_approve as u64)
    );
    // Missing referendum/locks return found=false; an absent tally returns NotFound.
    let missing_id = "missing-rid".to_string();
    let resp_rm = iroha_torii::handle_gov_get_referendum(state.clone(), AxPath(missing_id.clone()))
        .await
        .expect("handler ok")
        .into_response();
    let brm = resp_rm.into_body().collect().await.unwrap().to_bytes();
    let vrm: norito::json::Value = norito::json::from_slice(&brm).unwrap();
    assert_eq!(
        vrm.get("found").and_then(norito::json::Value::as_bool),
        Some(false)
    );
    let resp_lm = iroha_torii::handle_gov_get_locks(state.clone(), AxPath(missing_id.clone()))
        .await
        .expect("handler ok")
        .into_response();
    let blm = resp_lm.into_body().collect().await.unwrap().to_bytes();
    let vlm: norito::json::Value = norito::json::from_slice(&blm).unwrap();
    assert_eq!(
        vlm.get("found").and_then(norito::json::Value::as_bool),
        Some(false)
    );
    let missing_tally = iroha_torii::handle_gov_get_tally(state.clone(), AxPath(missing_id))
        .await
        .expect_err("an absent referendum cannot establish a zero tally");
    assert!(matches!(
        missing_tally,
        iroha_torii::Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::NotFound
        ))
    ));
    // An existing referendum without votes has a genuine zero tally.
    let resp_tm = iroha_torii::handle_gov_get_tally(state, AxPath(empty_rid))
        .await
        .expect("empty referendum tally")
        .into_response();
    let btm = resp_tm.into_body().collect().await.unwrap().to_bytes();
    let vtm: norito::json::Value = norito::json::from_slice(&btm).unwrap();
    assert_eq!(
        vtm.get("approve").and_then(norito::json::Value::as_u64),
        Some(0)
    );
    assert_eq!(
        vtm.get("reject").and_then(norito::json::Value::as_u64),
        Some(0)
    );
    assert_eq!(
        vtm.get("abstain").and_then(norito::json::Value::as_u64),
        Some(0)
    );
}
