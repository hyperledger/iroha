use super::*;
use axum::http::StatusCode;
use http_body_util::BodyExt as _;
use iroha_core::{state::World, tx::AcceptedTransaction};
use iroha_data_model::prelude as dm;
use std::{borrow::Cow, sync::Arc};
// use tower::ServiceExt; // not needed in this module
fn checked_smoke_keypair(
    seed: u8,
    algorithm: iroha_crypto::Algorithm,
    context: &'static str,
) -> KeyPair {
    checked_routing_fixture_keypair(seed, algorithm, context)
}
fn checked_smoke_account(seed: u8, context: &'static str) -> (dm::AccountId, KeyPair) {
    let kp = checked_smoke_keypair(seed, iroha_crypto::Algorithm::Ed25519, context);
    let account = dm::AccountId::new(kp.public_key().clone());
    (account, kp)
}
fn account_with_key() -> (dm::AccountId, KeyPair) {
    checked_smoke_account(0x40, "derive transaction query smoke fixture account key")
}
fn log_instruction() -> dm::InstructionBox {
    dm::Log::new(dm::Level::INFO, "test".to_string()).into()
}
/// Start a one-validator native chain whose World holds `authority`.
fn contract_feed_chain(
    authority: &dm::AccountId,
) -> iroha_core::sumeragi::test_chain::CertifiedTestChain {
    let world = World::with(
        [],
        [dm::Account::new(authority.clone()).build(authority)],
        [],
    );
    let native_chain = iroha_core::sumeragi::test_chain::CertifiedTestChain::start(
        iroha_core::sumeragi::test_chain::TestChainConfig::new(world, 1),
    )
    .expect("contract feed fixture genesis");
    let state = Arc::clone(native_chain.state());
    state
        .block(iroha_data_model::block::BlockHeader::new(
            core::num::NonZeroU64::new(native_chain.height() + 1).unwrap(),
            state.view().latest_block_hash(),
            None,
            1_000,
            0,
        ))
        .commit_world_overlay_for_testing()
        .expect("seed contract feed fixture World");
    native_chain
}
/// Contract identity and event claims vouched for by nobody but the signer.
fn forged_contract_event_metadata(contract_address: &str) -> iroha_model_base::metadata::Metadata {
    let mut metadata = iroha_model_base::metadata::Metadata::default();
    for (key, value) in [
        ("contract_address", dm::Json::new(contract_address)),
        (
            "contract_alias",
            dm::Json::new("dlmm_router::forged.universal"),
        ),
        ("contract_entrypoint", dm::Json::new("route_swap")),
        (
            "contract_payload",
            dm::Json::new(norito::json!({ "amount_in": 100, "min_out": 95 })),
        ),
        ("contract_module", dm::Json::new("swaps")),
        ("contract_event_kind", dm::Json::new("swap_executed")),
        ("contract_event_provenance", dm::Json::new("emitted")),
        ("contract_event_schema_version", dm::Json::new(1_u64)),
        (
            "contract_event_payload",
            dm::Json::new(norito::json!({ "trader": "victim@universal", "amount": 1_000_000 })),
        ),
    ] {
        metadata.insert(key.parse().expect("static metadata key"), value);
    }
    metadata
}
async fn contract_feed_page(
    response: impl std::future::Future<Output = Result<axum::response::Response>>,
) -> norito::json::Value {
    // Native history reads and the returned body retain the same real bounded
    // request owner, just as they do through the admitted collection route.
    let working = 48 * 1024 * 1024;
    let pool = crate::ByteWeightedMemoryPool::new(working).unwrap();
    let reservation = crate::QueryFanoutMemoryReservation::from_admitted_fanout(
        pool.try_acquire_parts([working as u64]).unwrap(),
        crate::QueryFanoutMemoryEnvelope::for_body_admission(working).unwrap(),
        pool.generation(),
    )
    .unwrap();
    let response = crate::COLLECTION_READ_MEMORY_RESERVATION
        .scope(reservation, response)
        .await
        .expect("admitted contract feed collection");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    norito::json::from_slice(&body).unwrap()
}
async fn contract_activity_page(
    state: &Arc<CoreState>,
    query: iroha_torii_shared::list_query::ListQuery,
) -> norito::json::Value {
    contract_feed_page(handle_v1_contracts_activity_get(
        Arc::clone(state),
        DataspaceReadVisibility::all_for_tests(),
        query,
        crate::routing::MaybeTelemetry::for_tests(),
    ))
    .await
}
async fn contract_event_page(
    state: &Arc<CoreState>,
    query: iroha_torii_shared::list_query::ListQuery,
) -> norito::json::Value {
    contract_feed_page(handle_v1_contracts_events_get(
        Arc::clone(state),
        DataspaceReadVisibility::all_for_tests(),
        query,
        crate::routing::MaybeTelemetry::for_tests(),
    ))
    .await
}
/// Consensus binds contract metadata only to a top-level `ContractCall`, so an
/// ordinary transaction that merely claims a contract identity, an `emitted`
/// provenance and a swap payload must stay invisible to both contract feeds.
#[tokio::test]
async fn contract_feeds_ignore_contract_metadata_on_non_contract_transactions() {
    let (authority, keypair) = account_with_key();
    let mut native_chain = contract_feed_chain(&authority);
    let state = Arc::clone(native_chain.state());
    let mut tx_builder = dm::TransactionBuilder::new(
        *state.network_id_ref(),
        authority.clone(),
        dm::FeePaymentIntent::authority(Vec::new(), None),
    );
    tx_builder.set_creation_time(core::time::Duration::from_millis(1_710_000_000_000));
    let signed = tx_builder
        .with_metadata(forged_contract_event_metadata("irohac1fixturedlmmrouter"))
        .with_instructions([log_instruction()])
        .sign(keypair.private_key());
    let _committed = crate::test_utils::commit_native_accepted_inputs(
        &mut native_chain,
        vec![AcceptedTransaction::new_unchecked(Cow::Owned(signed))],
    );
    let everything = || iroha_torii_shared::list_query::ListQuery::new().limit(10);
    let events = contract_event_page(&state, everything()).await;
    assert!(
        events["items"].as_array().unwrap().is_empty(),
        "a non-contract transaction was served as a contract event: {}",
        norito::json::to_string_pretty(&events).unwrap()
    );
    let activity = contract_activity_page(&state, everything()).await;
    assert!(
        activity["items"].as_array().unwrap().is_empty(),
        "a non-contract transaction was served as contract activity: {}",
        norito::json::to_string_pretty(&activity).unwrap()
    );
}
/// A rejected by-reference call remains in call history while its forged metadata
/// cannot create an emission or contribute any native event payload.
#[tokio::test]
async fn contract_feeds_project_rejected_contract_call_from_signed_invocation() {
    let (authority, keypair) = account_with_key();
    let mut native_chain = contract_feed_chain(&authority);
    let state = Arc::clone(native_chain.state());
    let network_id = *state.network_id_ref();
    let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
        &network_id,
        &authority,
        7,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .expect("derive fixture contract address");
    let code_hash = iroha_crypto::Hash::new(b"undeployed contract feed fixture");
    let mut metadata = forged_contract_event_metadata(&contract_address.to_string());
    metadata.insert(
        "contract_code_hash".parse().unwrap(),
        dm::Json::new(code_hash.to_string()),
    );
    let gas_asset_id = test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554400aa");
    let fee_payment = dm::FeePaymentIntent::sponsor(
        dm::FeeSponsorProgramId::new(
            authority.clone(),
            "contract-activity".parse().expect("program name"),
        ),
        1,
        vec![dm::FeeChargeLimit::new(
            dm::FeeChargeKind::PipelineGas,
            gas_asset_id.clone(),
            dm::Quantity::from(1_000_u32),
        )],
        std::num::NonZeroU64::new(100_000),
    );
    let mut tx_builder = dm::TransactionBuilder::new(network_id, authority.clone(), fee_payment);
    tx_builder.set_creation_time(core::time::Duration::from_millis(1_710_000_000_000));
    let signed = tx_builder
        .with_metadata(metadata)
        .with_executable(dm::Executable::ContractCall(
            iroha_data_model::transaction::executable::ContractInvocation {
                contract_address: contract_address.clone(),
                expected_code_hash: code_hash,
                entrypoint: "route_swap".to_owned(),
                arguments: None,
            },
        ))
        .sign(keypair.private_key());
    let entry_hash = format!("{}", signed.hash_as_entrypoint());
    let _committed = crate::test_utils::commit_native_accepted_inputs(
        &mut native_chain,
        vec![AcceptedTransaction::new_unchecked(Cow::Owned(signed))],
    );
    let by_address = || {
        iroha_torii_shared::list_query::ListQuery::new()
            .limit(10)
            .filter(
                iroha_torii_shared::list_query::field("contract_address")
                    .eq(contract_address.to_string()),
            )
    };
    let activity = contract_activity_page(&state, by_address()).await;
    let items = activity["items"].as_array().unwrap();
    assert!(activity["next_cursor"].is_null());
    assert_eq!(
        items.len(),
        1,
        "the committed rejected call remains queryable"
    );
    assert_eq!(items[0]["result_ok"].as_bool(), Some(false));
    assert_eq!(
        items[0]["entrypoint_hash"].as_str(),
        Some(entry_hash.as_str())
    );
    assert_eq!(items[0]["contract_entrypoint"].as_str(), Some("route_swap"));
    assert!(items[0].get("contract_alias").is_none());
    assert!(items[0].get("contract_payload").is_none());
    assert_eq!(items[0]["fee_payment"]["payer"].as_str(), Some("sponsor"));
    assert_eq!(
        items[0]["fee_payment"]["value"]["gas_limit"].as_u64(),
        Some(100_000)
    );
    assert_eq!(
        items[0]["fee_payment"]["value"]["charge_limits"][0]["asset_definition_id"]
            .as_str()
            .expect("projected fee asset"),
        gas_asset_id.to_string()
    );
    let events = contract_event_page(&state, by_address()).await;
    let items = events["items"].as_array().unwrap();
    assert!(events["next_cursor"].is_null());
    assert!(items.is_empty(), "rejected calls never emit native events");
    let forged = iroha_torii_shared::list_query::ListQuery::new()
        .limit(10)
        .filter(iroha_torii_shared::list_query::field("provenance").eq("emitted"));
    let emitted = contract_event_page(&state, forged).await;
    assert!(emitted["items"].as_array().unwrap().is_empty());
}
// The production app path always uses the typed server-side predicate and
// then applies the authoritative endpoint filter to returned candidates.
// Typed server predicates mirror the authoritative endpoint semantics for
// authority and entrypoint-hash equality and membership operators.
