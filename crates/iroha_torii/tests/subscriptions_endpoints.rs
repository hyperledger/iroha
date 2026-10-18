//! Integration tests for Torii subscription endpoints.
#![cfg(feature = "app_api")]
use axum::{
    body::Body,
    extract::connect_info::ConnectInfo,
    http::{Request, header::CONTENT_TYPE},
    response::Response,
};
use http::StatusCode;
use http_body_util::BodyExt as _;
use iroha_core::{
    kiso::KisoHandle,
    kura::Kura,
    query::store::LiveQueryStore,
    queue::Queue,
    smartcontracts::{Execute, triggers::set::SetReadOnly},
    state::{State, World, WorldReadOnly},
};
use iroha_data_model::{
    Registrable,
    account::Account,
    asset::{AssetDefinition, AssetDefinitionId},
    block::BlockHeader,
    domain::Domain,
    events::time::{ExecutionTime, Schedule, TimeEventFilter},
    isi::{InstructionBox, Register},
    nft::{Nft, NftId},
    prelude::Repeats,
    subscription::{
        SUBSCRIPTION_INVOICE_METADATA_KEY, SUBSCRIPTION_METADATA_KEY,
        SUBSCRIPTION_PLAN_METADATA_KEY, SubscriptionBillFor, SubscriptionBilling,
        SubscriptionCadence, SubscriptionFixedPeriodCadence, SubscriptionFixedPricing,
        SubscriptionInvoice, SubscriptionInvoiceStatus, SubscriptionPlan, SubscriptionPricing,
        SubscriptionState, SubscriptionStatus,
    },
    trigger::{Trigger, TriggerId, action::Action},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_model_base::peer::PeerId;
use iroha_primitives::{
    json::Json as IrohaJson,
    numeric::{NumericSpec, Quantity},
};
use iroha_test_samples::{ALICE_ID, BOB_ID, BOB_KEYPAIR};
use iroha_torii::{MaybeTelemetry, OnlinePeersProvider, Torii, json_entry, json_object};
use mv::storage::StorageReadOnly;
use std::{net::SocketAddr, num::NonZeroU64, str::FromStr as _, sync::Arc};
use tower::ServiceExt as _;
#[path = "fixtures.rs"]
mod fixtures;
struct SubscriptionHarness {
    app: iroha_torii::TestApiRouterRuntime,
    state: Arc<State>,
    queue: Arc<Queue>,
    charge_asset_id: AssetDefinitionId,
    subscription_id: NftId,
    billing_trigger_id: TriggerId,
}
impl SubscriptionHarness {
    async fn shutdown(self) {
        self.app.shutdown().await;
    }
}
fn build_subscription_plan(charge_asset_id: AssetDefinitionId) -> SubscriptionPlan {
    SubscriptionPlan {
        provider: ALICE_ID.clone(),
        billing: SubscriptionBilling {
            cadence: SubscriptionCadence::FixedPeriod(SubscriptionFixedPeriodCadence {
                period_ms: 1_000,
            }),
            bill_for: SubscriptionBillFor::NextPeriod,
            retry_backoff_ms: 500,
            max_failures: 3,
            grace_ms: 1_000,
        },
        pricing: SubscriptionPricing::Fixed(SubscriptionFixedPricing {
            amount: Quantity::from(25_u32),
            asset_definition: charge_asset_id,
        }),
    }
}
fn build_subscription_state(
    plan_id: AssetDefinitionId,
    billing_trigger_id: TriggerId,
    status: SubscriptionStatus,
) -> SubscriptionState {
    SubscriptionState {
        plan_id,
        provider: ALICE_ID.clone(),
        subscriber: BOB_ID.clone(),
        status,
        current_period_start_ms: 1_000,
        current_period_end_ms: 2_000,
        next_charge_ms: 3_000,
        cancel_at_period_end: false,
        cancel_at_ms: None,
        failure_count: 2,
        usage_accumulated: std::collections::BTreeMap::new(),
        billing_trigger_id,
    }
}
fn build_subscription_invoice(
    subscription_id: NftId,
    charge_asset_id: AssetDefinitionId,
) -> SubscriptionInvoice {
    SubscriptionInvoice {
        subscription_nft_id: subscription_id,
        period_start_ms: 1_000,
        period_end_ms: 2_000,
        attempted_at_ms: 2_500,
        amount: Quantity::from(25_u32),
        asset_definition: charge_asset_id,
        status: SubscriptionInvoiceStatus::Failed,
        tx_hash: None,
    }
}
fn build_existing_billing_trigger(
    trigger_id: TriggerId,
    authority: iroha_data_model::account::AccountId,
) -> Trigger {
    Trigger::new(
        trigger_id,
        Action::new(
            Vec::<InstructionBox>::new(),
            Repeats::Exactly(1),
            authority,
            TimeEventFilter(ExecutionTime::Schedule(Schedule {
                start_ms: 3_000,
                period_ms: None,
            })),
        )
        .expect("trigger action fixture satisfies validation invariants"),
    )
}
fn build_subscription_harness(status: SubscriptionStatus) -> SubscriptionHarness {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let (kiso, _child) = KisoHandle::start(cfg.clone());
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let local_peer_id = PeerId::new(cfg.common.key_pair.public_key().clone());
    let domain_id = DomainId::try_new("wonderland", "universal").expect("domain id");
    let charge_asset_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        Name::from_str("fee").expect("asset name"),
    );
    let plan_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        Name::from_str("subscription_plan").expect("asset name"),
    );
    let subscription_id = NftId::of(
        domain_id.clone(),
        Name::from_str("subscription").expect("subscription name"),
    );
    let billing_trigger_id: TriggerId = "bill_subscription_router".parse().expect("trigger id");
    let mut metadata = Metadata::default();
    metadata.insert(
        Name::from_str(SUBSCRIPTION_METADATA_KEY).expect("subscription metadata key"),
        IrohaJson::new(build_subscription_state(
            plan_id.clone(),
            billing_trigger_id.clone(),
            status,
        )),
    );
    metadata.insert(
        Name::from_str(SUBSCRIPTION_INVOICE_METADATA_KEY).expect("invoice metadata key"),
        IrohaJson::new(build_subscription_invoice(
            subscription_id.clone(),
            charge_asset_id.clone(),
        )),
    );
    let domain = Domain::new(domain_id).build(&ALICE_ID);
    let provider_account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let subscriber_account = Account::new(BOB_ID.clone()).build(&BOB_ID);
    let mut plan_definition = AssetDefinition::new(
        plan_id,
        "subscription_plan".to_owned(),
        NumericSpec::integer(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&ALICE_ID);
    plan_definition.metadata.insert(
        Name::from_str(SUBSCRIPTION_PLAN_METADATA_KEY).expect("plan metadata key"),
        IrohaJson::new(build_subscription_plan(charge_asset_id.clone())),
    );
    let charge_asset_definition = AssetDefinition::new(
        charge_asset_id.clone(),
        "fee".to_owned(),
        NumericSpec::integer(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&ALICE_ID);
    let nft = Nft::new(subscription_id.clone(), metadata).build(&BOB_ID);
    let mut world = World::with_assets(
        [domain],
        [provider_account, subscriber_account],
        [plan_definition, charge_asset_definition],
        [],
        [nft],
    );
    fixtures::seed_peer(&mut world, local_peer_id.clone());
    let state = Arc::new(State::new_for_testing(world, kura.clone(), query));
    {
        let expected_height = u64::try_from(state.view().height())
            .unwrap_or(0)
            .saturating_add(1);
        let header = BlockHeader::new(
            NonZeroU64::new(expected_height).expect("height > 0"),
            None,
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        let mut stx = block.transaction();
        Register::trigger(build_existing_billing_trigger(
            billing_trigger_id.clone(),
            BOB_ID.clone(),
        ))
        .execute(&BOB_ID, &mut stx)
        .expect("register billing trigger");
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit trigger registration");
    }
    let queue_cfg = iroha_config::parameters::actual::Queue::default();
    let events_sender: iroha_core::EventsSender = tokio::sync::broadcast::channel(1).0;
    let queue = Arc::new(Queue::from_config(queue_cfg, events_sender));
    let (peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
    let _ = peers_tx;
    let torii = Torii::new_with_handle(
        state.chain_id_ref().clone(),
        *state.network_id_ref(),
        kiso,
        cfg.torii.clone(),
        queue.clone(),
        tokio::sync::broadcast::channel(1).0,
        LiveQueryStore::start_test(),
        kura,
        state.clone(),
        cfg.common.key_pair.clone(),
        OnlinePeersProvider::new(peers_rx),
        None,
        iroha_torii::ToriiRuntimeDeps::new(
            build_identity_test_fixture::build_identity(),
            MaybeTelemetry::disabled(),
        ),
    )
    .expect("valid Torii subscription fixture");
    SubscriptionHarness {
        app: torii
            .api_router_for_tests()
            .expect("test Torii router initializes"),
        state,
        queue,
        charge_asset_id,
        subscription_id,
        billing_trigger_id,
    }
}
async fn call_app(app: &axum::Router, mut request: Request<Body>) -> Response {
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    app.clone().oneshot(request).await.expect("router responds")
}
fn signed_bob_mutation(
    network_id: &iroha_data_model::NetworkId,
    uri: &str,
    body: &str,
) -> Request<Body> {
    fixtures::app_signed_request(
        network_id,
        &BOB_ID,
        &BOB_KEYPAIR,
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .expect("request"),
        body.as_bytes(),
    )
}
async fn response_json(resp: Response) -> norito::json::Value {
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    norito::json::from_slice(&body).expect("valid json response")
}
#[tokio::test]
async fn subscription_mutation_routes_are_registered() {
    let harness = build_subscription_harness(SubscriptionStatus::Paused);
    let subscription_id = harness.subscription_id.to_string();
    for uri in [
        "/v1/subscriptions/plans".to_owned(),
        "/v1/subscriptions".to_owned(),
        format!("/v1/subscriptions/{subscription_id}/pause"),
        format!("/v1/subscriptions/{subscription_id}/resume"),
        format!("/v1/subscriptions/{subscription_id}/cancel"),
        format!("/v1/subscriptions/{subscription_id}/keep"),
        format!("/v1/subscriptions/{subscription_id}/usage"),
        format!("/v1/subscriptions/{subscription_id}/charge-now"),
    ] {
        let body = "{}";
        let resp = call_app(
            &harness.app,
            signed_bob_mutation(harness.state.network_id_ref(), &uri, body),
        )
        .await;
        assert!(
            !matches!(
                resp.status(),
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
            ),
            "subscription route `{uri}` should be registered"
        );
    }
    harness.shutdown().await;
}
#[tokio::test]
async fn subscription_list_and_get_return_generic_plan_metadata() {
    let harness = build_subscription_harness(SubscriptionStatus::Paused);
    let subscription_id = harness.subscription_id.to_string();
    let list_resp = call_app(
        &harness.app,
        Request::builder()
            .uri("/v1/subscriptions?offset=0")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(list_resp.status(), StatusCode::OK);
    let list_json = response_json(list_resp).await;
    let items = list_json["items"].as_array().expect("items array");
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["subscription_id"].as_str(),
        Some(subscription_id.as_str())
    );
    let list_plan: SubscriptionPlan =
        norito::json::from_value(items[0]["plan"].clone()).expect("subscription plan");
    assert_eq!(list_plan.provider, *ALICE_ID);
    let list_state: SubscriptionState =
        norito::json::from_value(items[0]["subscription"].clone()).expect("subscription state");
    assert_eq!(list_state.status, SubscriptionStatus::Paused);
    let list_invoice: SubscriptionInvoice =
        norito::json::from_value(items[0]["invoice"].clone()).expect("subscription invoice");
    assert_eq!(list_invoice.asset_definition, harness.charge_asset_id);
    let get_resp = call_app(
        &harness.app,
        Request::builder()
            .uri(format!("/v1/subscriptions/{subscription_id}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(get_resp.status(), StatusCode::OK);
    let get_json = response_json(get_resp).await;
    let get_plan: SubscriptionPlan =
        norito::json::from_value(get_json["plan"].clone()).expect("subscription plan");
    assert_eq!(get_plan.provider, *ALICE_ID);
    let get_state: SubscriptionState =
        norito::json::from_value(get_json["subscription"].clone()).expect("subscription state");
    assert_eq!(get_state.status, SubscriptionStatus::Paused);
    let get_invoice: SubscriptionInvoice =
        norito::json::from_value(get_json["invoice"].clone()).expect("subscription invoice");
    assert_eq!(get_invoice.asset_definition, harness.charge_asset_id);
    harness.shutdown().await;
}
#[tokio::test]
async fn subscription_resume_route_returns_exact_unsigned_draft_without_mutating() {
    let harness = build_subscription_harness(SubscriptionStatus::Paused);
    let subscription_id = harness.subscription_id.to_string();
    let body = json_object(vec![
        json_entry("authority", BOB_ID.to_string()),
        json_entry("charge_at_ms", 5_000_u64),
    ]);
    let body = norito::json::to_json(&body).expect("serialize resume request");
    let resume_resp = call_app(
        &harness.app,
        signed_bob_mutation(
            harness.state.network_id_ref(),
            &format!("/v1/subscriptions/{subscription_id}/resume"),
            &body,
        ),
    )
    .await;
    assert_eq!(resume_resp.status(), StatusCode::OK);
    assert_eq!(harness.queue.queued_len(), 0);
    let resume_json = response_json(resume_resp).await;
    assert_eq!(resume_json["version"].as_u64(), Some(1));
    assert_eq!(resume_json["action"].as_str(), Some("resume"));
    assert_eq!(
        resume_json["authority"].as_str(),
        Some(BOB_ID.to_string().as_str())
    );
    assert_eq!(
        resume_json["subscription_id"].as_str(),
        Some(subscription_id.as_str())
    );
    assert_eq!(
        resume_json["details"]["billing_trigger_id"].as_str(),
        Some(harness.billing_trigger_id.to_string().as_str())
    );
    assert_eq!(
        resume_json["details"]["billing_trigger_operation"].as_str(),
        Some("replace")
    );
    assert_eq!(
        resume_json["details"]["effective_charge_ms"].as_u64(),
        Some(5_000)
    );
    assert_eq!(
        resume_json["details"]["resulting_subscription"]["status"]["status"].as_str(),
        Some("active")
    );
    assert_eq!(
        resume_json["details"]["resulting_subscription"]["next_charge_ms"].as_u64(),
        Some(5_000)
    );
    let instructions = resume_json["tx_instructions"]
        .as_array()
        .expect("draft instructions");
    assert_eq!(instructions.len(), 3);
    assert!(instructions.iter().all(|instruction| {
        instruction["wire_id"].as_str().is_some()
            && instruction["payload_hex"]
                .as_str()
                .is_some_and(|payload| !payload.is_empty())
    }));
    assert!(resume_json.get("ok").is_none());
    assert!(resume_json.get("tx_hash_hex").is_none());
    let view = harness.state.view();
    let nft = view
        .world()
        .nft(&harness.subscription_id)
        .expect("subscription nft should exist");
    let resumed_state: SubscriptionState = nft
        .content
        .get(&Name::from_str(SUBSCRIPTION_METADATA_KEY).expect("subscription metadata key"))
        .expect("subscription metadata present")
        .try_into_any_norito()
        .expect("subscription metadata decodes");
    assert_eq!(resumed_state.status, SubscriptionStatus::Paused);
    assert_eq!(resumed_state.failure_count, 2);
    assert_eq!(resumed_state.next_charge_ms, 3_000);
    assert_eq!(resumed_state.current_period_start_ms, 1_000);
    assert_eq!(resumed_state.current_period_end_ms, 2_000);
    assert!(
        view.world()
            .triggers()
            .time_triggers()
            .get(&harness.billing_trigger_id)
            .is_some(),
        "draft construction must not replace the committed billing trigger"
    );
    drop(view);
    harness.shutdown().await;
}
#[tokio::test]
async fn subscription_action_route_rejects_legacy_private_key_payload() {
    let harness = build_subscription_harness(SubscriptionStatus::Paused);
    let subscription_id = harness.subscription_id.to_string();
    let body = norito::json::to_json(&json_object(vec![
        json_entry("authority", BOB_ID.to_string()),
        json_entry("private_key", "forbidden"),
        json_entry("charge_at_ms", 5_000_u64),
    ]))
    .expect("serialize legacy request");
    let response = call_app(
        &harness.app,
        signed_bob_mutation(
            harness.state.network_id_ref(),
            &format!("/v1/subscriptions/{subscription_id}/resume"),
            &body,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(harness.queue.queued_len(), 0);
    harness.shutdown().await;
}
#[tokio::test]
async fn subscription_cancel_route_requires_exact_tagged_mode() {
    let harness = build_subscription_harness(SubscriptionStatus::Paused);
    let subscription_id = harness.subscription_id.to_string();
    let uri = format!("/v1/subscriptions/{subscription_id}/cancel");
    let legacy_body = norito::json::to_json(&json_object(vec![
        json_entry("authority", BOB_ID.to_string()),
        json_entry("cancel_mode", "immediate"),
    ]))
    .expect("serialize legacy cancel request");
    let response = call_app(
        &harness.app,
        signed_bob_mutation(harness.state.network_id_ref(), &uri, &legacy_body),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let cancel_mode = json_object(vec![
        json_entry("mode", "immediate"),
        ("value".to_owned(), norito::json::Value::Null),
    ]);
    let body = norito::json::to_json(&json_object(vec![
        json_entry("authority", BOB_ID.to_string()),
        ("cancel_mode".to_owned(), cancel_mode),
    ]))
    .expect("serialize exact cancel request");
    let response = call_app(
        &harness.app,
        signed_bob_mutation(harness.state.network_id_ref(), &uri, &body),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = response_json(response).await;
    assert_eq!(
        response["details"]["cancel_mode"]["mode"].as_str(),
        Some("immediate")
    );
    assert_eq!(
        response["details"]["cancel_mode"]["value"],
        norito::json::Value::Null
    );
    assert_eq!(harness.queue.queued_len(), 0);
    harness.shutdown().await;
}

#[path = "../src/build_identity_test_fixture.rs"]
mod build_identity_test_fixture;
