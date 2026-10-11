#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Integration test for /v1/zk/roots using a minimal in-memory state.
#![allow(clippy::too_many_lines)]
use axum::{Router, routing::post};
use http_body_util::BodyExt as _;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World, WorldReadOnly},
};
use iroha_data_model::{NewAccount, prelude::*};
use iroha_model_base::domain::DomainId;
use iroha_torii::NoritoJson;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
use std::{collections::HashSet, num::NonZeroUsize, sync::Arc};
use tower::ServiceExt as _;
const ACCOUNT_SIGNATORY: &str =
    "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03";
const NORITO_MIME_TYPE: &str = "application/x-norito";
fn zk_config_with_tree_roots_history_len(
    tree_roots_history_len: NonZeroUsize,
) -> iroha_config::parameters::actual::Zk {
    iroha_config::parameters::actual::Zk {
        pipa_r: iroha_config::parameters::actual::PipaR::default(),
        trace: iroha_config::parameters::actual::DiagnosticTrace::default(),
        ipa_commitment: iroha_config::parameters::actual::IpaCommitment::default(),
        max_verify_batch: iroha_config::parameters::defaults::zk::MAX_VERIFY_BATCH,
        fastpq: iroha_config::parameters::actual::Fastpq {
            execution_mode: iroha_config::parameters::actual::FastpqExecutionMode::Cpu,
            poseidon_mode: iroha_config::parameters::actual::FastpqPoseidonMode::Cpu,
            proof_sidecar_queue_cap:
                iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_QUEUE_CAP,
            proof_sidecar_max_bytes:
                iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_MAX_BYTES,
            proof_sidecar_max_retries:
                iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_MAX_RETRIES,
            device_class: None,
            chip_family: None,
            gpu_kind: None,
            metal_queue_fanout: None,
            metal_queue_column_threshold: None,
            metal_max_in_flight: None,
            metal_threadgroup_width: None,
            metal_trace: iroha_config::parameters::defaults::zk::fastpq::METAL_TRACE,
            metal_debug_enum: iroha_config::parameters::defaults::zk::fastpq::METAL_DEBUG_ENUM,
        },
        stark: iroha_config::parameters::actual::Stark::default(),
        sccp: iroha_config::parameters::actual::Sccp::default(),
        ballot_history_cap: iroha_config::parameters::defaults::zk::vote::BALLOT_HISTORY_CAP,
        preverify_max_bytes: iroha_config::parameters::defaults::zk::preverify::MAX_BYTES,
        preverify_budget_bytes: iroha_config::parameters::defaults::zk::preverify::BUDGET_BYTES,
        proof_history_cap: iroha_config::parameters::defaults::zk::proof::RECORD_HISTORY_CAP,
        proof_retention_grace_blocks:
            iroha_config::parameters::defaults::zk::proof::RETENTION_GRACE_BLOCKS,
        proof_prune_batch: iroha_config::parameters::defaults::zk::proof::PRUNE_BATCH_SIZE,
        bridge_proof_max_range_len:
            iroha_config::parameters::defaults::zk::proof::BRIDGE_MAX_RANGE_LEN,
        bridge_proof_max_past_age_blocks:
            iroha_config::parameters::defaults::zk::proof::BRIDGE_MAX_PAST_AGE_BLOCKS,
        bridge_proof_max_future_drift_blocks:
            iroha_config::parameters::defaults::zk::proof::BRIDGE_MAX_FUTURE_DRIFT_BLOCKS,
        poseidon_params_id: iroha_config::parameters::defaults::confidential::POSEIDON_PARAMS_ID,
        pedersen_params_id: iroha_config::parameters::defaults::confidential::PEDERSEN_PARAMS_ID,
        kaigi_authorization_vk: None,
        kaigi_usage_vk: None,
        max_proof_size_bytes:
            iroha_config::parameters::defaults::confidential::MAX_PROOF_SIZE_BYTES,
        max_nullifiers_per_tx:
            iroha_config::parameters::defaults::confidential::MAX_NULLIFIERS_PER_TX,
        max_commitments_per_tx:
            iroha_config::parameters::defaults::confidential::MAX_COMMITMENTS_PER_TX,
        max_confidential_ops_per_block:
            iroha_config::parameters::defaults::confidential::MAX_CONFIDENTIAL_OPS_PER_BLOCK,
        verify_timeout: iroha_config::parameters::defaults::confidential::VERIFY_TIMEOUT,
        max_anchor_age_blocks:
            iroha_config::parameters::defaults::confidential::MAX_ANCHOR_AGE_BLOCKS,
        max_proof_bytes_block:
            iroha_config::parameters::defaults::confidential::MAX_PROOF_BYTES_BLOCK,
        max_verify_calls_per_tx:
            iroha_config::parameters::defaults::confidential::MAX_VERIFY_CALLS_PER_TX,
        max_verify_calls_per_block:
            iroha_config::parameters::defaults::confidential::MAX_VERIFY_CALLS_PER_BLOCK,
        max_public_inputs: iroha_config::parameters::defaults::confidential::MAX_PUBLIC_INPUTS,
        reorg_depth_bound: iroha_config::parameters::defaults::confidential::REORG_DEPTH_BOUND,
        policy_transition_delay_blocks:
            iroha_config::parameters::defaults::confidential::POLICY_TRANSITION_DELAY_BLOCKS,
        policy_transition_window_blocks:
            iroha_config::parameters::defaults::confidential::POLICY_TRANSITION_WINDOW_BLOCKS,
        policy_transition_max_per_height:
            iroha_config::parameters::defaults::confidential::POLICY_TRANSITION_MAX_PER_HEIGHT,
        tree_roots_history_len,
        tree_frontier_checkpoint_interval:
            iroha_config::parameters::defaults::confidential::TREE_FRONTIER_CHECKPOINT_INTERVAL,
        registry_max_vk_entries:
            iroha_config::parameters::defaults::confidential::REGISTRY_MAX_VK_ENTRIES,
        registry_max_params_entries:
            iroha_config::parameters::defaults::confidential::REGISTRY_MAX_PARAMS_ENTRIES,
        registry_max_delta_per_block:
            iroha_config::parameters::defaults::confidential::REGISTRY_MAX_DELTA_PER_BLOCK,
        gas: iroha_config::parameters::actual::ConfidentialGas {
            proof_base: iroha_config::parameters::defaults::confidential::gas::PROOF_BASE,
            per_public_input:
                iroha_config::parameters::defaults::confidential::gas::PER_PUBLIC_INPUT,
            per_proof_byte: iroha_config::parameters::defaults::confidential::gas::PER_PROOF_BYTE,
            per_nullifier: iroha_config::parameters::defaults::confidential::gas::PER_NULLIFIER,
            per_commitment: iroha_config::parameters::defaults::confidential::gas::PER_COMMITMENT,
        },
    }
}
fn seeded_zk_roots_state(
    tree_roots_history_len: NonZeroUsize,
    commitment_count: u8,
) -> (Arc<State>, AssetDefinitionId, String, Vec<[u8; 32]>) {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let mut state = State::new_for_testing(World::new(), kura, query);
    state
        .set_zk(zk_config_with_tree_roots_history_len(
            tree_roots_history_len,
        ))
        .expect("empty state accepts roots test configuration");
    let domain_id: DomainId = DomainId::try_new("zkd", "universal").unwrap();
    let asset_def_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("zkd", "universal").expect("domain id"),
        "rose".parse().expect("asset definition name"),
    );
    let asset_alias = "rose#centralbank";
    let owner = AccountId::new(ACCOUNT_SIGNATORY.parse().expect("public key"));
    {
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let definition = AssetDefinition::numeric(
            asset_def_id.clone(),
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        );
        let init_instrs: [InstructionBox; 5] = [
            Register::domain(Domain::new(domain_id.clone())).into(),
            Register::account(NewAccount::new(owner.clone())).into(),
            Register::asset_definition(definition).into(),
            Mint::asset_quantity(10_000u64, AssetId::of(asset_def_id.clone(), owner.clone()))
                .into(),
            iroha_data_model::isi::zk::RegisterZkAsset::new(asset_def_id.clone(), None).into(),
        ];
        for instr in init_instrs {
            stx.world
                .executor()
                .clone()
                .execute_instruction(&mut stx, &owner, instr)
                .unwrap();
        }
        iroha_data_model::isi::SetAssetDefinitionAlias::bind(
            asset_def_id.clone(),
            asset_alias.parse().expect("asset alias literal"),
            None,
        )
        .execute(&owner, &mut stx)
        .expect("bind asset alias");
        let mut zk_state = stx
            .world
            .zk_assets()
            .get(&asset_def_id)
            .cloned()
            .expect("registered confidential asset state");
        for i in 0..commitment_count {
            let mut note = [0u8; 32];
            note[0] = i.saturating_add(1);
            zk_state
                .push_commitment(note, nonzero!(64_usize))
                .expect("seed authenticated commitment root");
        }
        let zk_assets = stx.world_mut_for_testing().zk_assets_mut_for_testing();
        zk_assets.remove(asset_def_id.clone());
        zk_assets.insert(asset_def_id.clone(), zk_state);
        stx.apply();
        block.transactions.insert_block(
            HashSet::<
                iroha_crypto::HashOf<iroha_data_model::transaction::TransactionEntrypoint>,
            >::new(),
            nonzero!(1_usize),
        );
        let _ = block.commit();
    }
    let state = Arc::new(state);
    let roots_all = state
        .view()
        .world
        .zk_assets()
        .get(&asset_def_id)
        .map(|st| st.root_history.clone())
        .unwrap_or_default();
    (state, asset_def_id, asset_alias.to_owned(), roots_all)
}
fn zk_roots_router(state: Arc<State>) -> Router {
    Router::new().route(
        "/v1/zk/roots",
        post({
            let state = state.clone();
            move |headers: axum::http::HeaderMap,
                  NoritoJson(req): NoritoJson<iroha_torii::ZkRootsGetRequestDto>| {
                let state = state.clone();
                async move {
                    let accept = headers.get(http::header::ACCEPT).cloned();
                    iroha_torii::handle_v1_zk_roots(state, accept, NoritoJson(req)).await
                }
            }
        }),
    )
}
#[tokio::test]
async fn zk_roots_endpoint_returns_bounded_recent_roots() {
    let (state, _asset_def_id, asset_alias, roots_all) =
        seeded_zk_roots_state(nonzero!(3_usize), 5);
    let app = zk_roots_router(state.clone());
    let req_body = norito::json::to_json(&iroha_torii::json_object(vec![
        iroha_torii::json_entry("asset_id", asset_alias.clone()),
        iroha_torii::json_entry("max", 0u64),
    ]))
    .expect("json serialization");
    let req = http::Request::builder()
        .method("POST")
        .uri("/v1/zk/roots")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(req_body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    let want: Vec<_> = roots_all.iter().rev().take(3).copied().collect();
    let mut want_win = want.clone();
    want_win.reverse();
    let resp_roots: Vec<String> = v
        .get("roots")
        .and_then(|x| x.as_array())
        .unwrap()
        .iter()
        .filter_map(|x| x.as_str().map(ToString::to_string))
        .collect();
    let want_hex: Vec<String> = want_win.iter().map(hex::encode).collect();
    assert_eq!(resp_roots, want_hex);
    // latest must equal last root
    let latest = v.get("latest").and_then(|x| x.as_str()).unwrap_or("");
    assert_eq!(latest, hex::encode(roots_all.last().copied().unwrap()));
    // Query with max=2 (bounded by requested)
    let req_second_body = norito::json::to_json(&iroha_torii::json_object(vec![
        iroha_torii::json_entry("asset_id", asset_alias),
        iroha_torii::json_entry("max", 2u64),
    ]))
    .expect("json serialization");
    let req_second = http::Request::builder()
        .method("POST")
        .uri("/v1/zk/roots")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(req_second_body))
        .unwrap();
    let resp_second = app.clone().oneshot(req_second).await.unwrap();
    assert_eq!(resp_second.status(), http::StatusCode::OK);
    let bytes_second = resp_second.into_body().collect().await.unwrap().to_bytes();
    let v2: norito::json::Value = norito::json::from_slice(&bytes_second).unwrap();
    let second_root_count = v2
        .get("roots")
        .and_then(|x| x.as_array())
        .unwrap()
        .iter()
        .filter_map(|x| x.as_str().map(ToString::to_string))
        .count();
    assert_eq!(second_root_count, 2);
}
#[tokio::test]
async fn zk_roots_endpoint_returns_all_roots_when_request_exceeds_history() {
    let (state, asset_def_id, _asset_alias, roots_all) =
        seeded_zk_roots_state(nonzero!(10_usize), 2);
    let app = zk_roots_router(state.clone());
    let req_body = norito::json::to_json(&iroha_torii::json_object(vec![
        iroha_torii::json_entry("asset_id", asset_def_id.to_string()),
        iroha_torii::json_entry("max", 10u64),
    ]))
    .expect("json serialization");
    let req = http::Request::builder()
        .method("POST")
        .uri("/v1/zk/roots")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(req_body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let payload: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    assert_eq!(
        payload
            .get("roots")
            .and_then(norito::json::Value::as_array)
            .unwrap()
            .iter()
            .filter_map(|value| value.as_str().map(ToString::to_string))
            .collect::<Vec<_>>(),
        roots_all
            .iter()
            .copied()
            .map(hex::encode)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        payload.get("latest").and_then(norito::json::Value::as_str),
        Some(hex::encode(roots_all.last().copied().unwrap()).as_str())
    );
    assert_eq!(
        payload
            .get("evaluated_block_height")
            .and_then(norito::json::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        payload
            .get("evaluated_block_hash")
            .and_then(norito::json::Value::as_str)
            .map(str::len),
        Some(64)
    );
}
#[tokio::test]
async fn zk_roots_endpoint_bounds_nonzero_max_by_cap() {
    let (state, _asset_def_id, asset_alias, roots_all) =
        seeded_zk_roots_state(nonzero!(3_usize), 5);
    let app = zk_roots_router(state.clone());
    let req_body = norito::json::to_json(&iroha_torii::json_object(vec![
        iroha_torii::json_entry("asset_id", asset_alias),
        iroha_torii::json_entry("max", 10u64),
    ]))
    .expect("json serialization");
    let req = http::Request::builder()
        .method("POST")
        .uri("/v1/zk/roots")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(req_body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let payload: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    let want_hex: Vec<String> = roots_all
        .iter()
        .rev()
        .take(3)
        .copied()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(hex::encode)
        .collect();
    assert_eq!(
        payload
            .get("roots")
            .and_then(norito::json::Value::as_array)
            .unwrap()
            .iter()
            .filter_map(|value| value.as_str().map(ToString::to_string))
            .collect::<Vec<_>>(),
        want_hex
    );
}
#[tokio::test]
async fn zk_roots_endpoint_returns_profile_defined_empty_root() {
    let (state, asset_def_id, _asset_alias, roots_all) =
        seeded_zk_roots_state(nonzero!(3_usize), 0);
    assert!(roots_all.is_empty());
    let app = zk_roots_router(state);
    let req_body = norito::json::to_json(&iroha_torii::json_object(vec![
        iroha_torii::json_entry("asset_id", asset_def_id.to_string()),
        iroha_torii::json_entry("max", 0u64),
    ]))
    .expect("json serialization");
    let req = http::Request::builder()
        .method("POST")
        .uri("/v1/zk/roots")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(req_body))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let payload: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    let empty_root = iroha_core::state::ConfidentialTreeProfile::PoseidonPastaV1.empty_root();
    let expected = hex::encode(empty_root);
    assert_eq!(
        payload.get("latest").and_then(norito::json::Value::as_str),
        Some(expected.as_str())
    );
    assert_eq!(
        payload
            .get("roots")
            .and_then(norito::json::Value::as_array)
            .and_then(|roots| roots.first())
            .and_then(norito::json::Value::as_str),
        Some(expected.as_str())
    );
}
#[tokio::test]
async fn zk_roots_endpoint_accepts_trimmed_alias_literal() {
    let (state, _asset_def_id, asset_alias, roots_all) =
        seeded_zk_roots_state(nonzero!(3_usize), 4);
    let app = zk_roots_router(state.clone());
    let req_body = norito::json::to_json(&iroha_torii::json_object(vec![
        iroha_torii::json_entry("asset_id", format!("  {asset_alias}  ")),
        iroha_torii::json_entry("max", 1u64),
    ]))
    .expect("json serialization");
    let req = http::Request::builder()
        .method("POST")
        .uri("/v1/zk/roots")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(req_body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let payload: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    assert_eq!(
        payload
            .get("roots")
            .and_then(norito::json::Value::as_array)
            .unwrap()
            .iter()
            .filter_map(|value| value.as_str().map(ToString::to_string))
            .collect::<Vec<_>>(),
        vec![hex::encode(roots_all.last().copied().unwrap())]
    );
    assert_eq!(
        payload.get("latest").and_then(norito::json::Value::as_str),
        Some(hex::encode(roots_all.last().copied().unwrap()).as_str())
    );
}
#[tokio::test]
async fn zk_roots_endpoint_negotiates_norito_for_non_empty_payload() {
    let (state, _asset_def_id, asset_alias, roots_all) =
        seeded_zk_roots_state(nonzero!(3_usize), 4);
    let app = zk_roots_router(state.clone());
    let expected = iroha_torii::handle_v1_zk_roots(
        state.clone(),
        Some(http::HeaderValue::from_static(NORITO_MIME_TYPE)),
        NoritoJson(iroha_torii::ZkRootsGetRequestDto {
            asset_id: asset_alias.clone(),
            max: 2,
        }),
    )
    .await
    .expect("direct handler should succeed");
    let expected_bytes = expected.into_body().collect().await.unwrap().to_bytes();
    let req_body = norito::json::to_json(&iroha_torii::json_object(vec![
        iroha_torii::json_entry("asset_id", asset_alias),
        iroha_torii::json_entry("max", 2u64),
    ]))
    .expect("json serialization");
    let req = http::Request::builder()
        .method("POST")
        .uri("/v1/zk/roots")
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::ACCEPT, NORITO_MIME_TYPE)
        .body(axum::body::Body::from(req_body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(NORITO_MIME_TYPE)
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(!bytes.is_empty());
    assert_eq!(bytes, expected_bytes);
    assert!(roots_all.len() >= 2);
}
#[tokio::test]
async fn zk_roots_endpoint_returns_406_for_unsupported_accept_header() {
    let (state, asset_def_id, _asset_alias, _roots_all) =
        seeded_zk_roots_state(nonzero!(3_usize), 2);
    let app = zk_roots_router(state.clone());
    let req_body = norito::json::to_json(&iroha_torii::json_object(vec![
        iroha_torii::json_entry("asset_id", asset_def_id.to_string()),
        iroha_torii::json_entry("max", 2u64),
    ]))
    .expect("json serialization");
    let req = http::Request::builder()
        .method("POST")
        .uri("/v1/zk/roots")
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::ACCEPT, "text/plain")
        .body(axum::body::Body::from(req_body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::NOT_ACCEPTABLE);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = std::str::from_utf8(&bytes).expect("utf8 response body");
    assert!(body.contains("unsupported Accept header"));
}
