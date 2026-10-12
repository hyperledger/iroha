//! Asynchronous subscription capability, signing and draft contract tests.

use super::Client;
use super::evidence_http_tests::{base_url, client_with_base_url};
use crate::collections::{Collection, ListQuery, Page, field};
use crate::{
    Error, blocking,
    http::{HttpTransport, Method, Response, TransportFuture, TransportRequest},
    http_default::{DefaultHttpTransport, RequestSnapshot},
    subscriptions::*,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    account::AccountId,
    asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId},
    events::{
        EventFilterBox,
        time::{ExecutionTime, Schedule, TimeEventFilter},
    },
    isi::{ExecuteTrigger, InstructionBox, Register, SetKeyValue},
    nexus::FeeSponsorProgramId,
    nft::{Nft, NftId},
    proof::{ProofAttachment, ProofBox, VerifyingKeyId},
    subscription::{
        SUBSCRIPTION_METADATA_KEY, SUBSCRIPTION_PLAN_METADATA_KEY,
        SUBSCRIPTION_TRIGGER_REF_METADATA_KEY, SubscriptionBillFor, SubscriptionBilling,
        SubscriptionCadence, SubscriptionFixedPeriodCadence, SubscriptionFixedPricing,
        SubscriptionPlan, SubscriptionPricing, SubscriptionState, SubscriptionStatus,
        SubscriptionTriggerRef, SubscriptionUsageDelta,
    },
    transaction::{
        Executable, FeeChargeKind, FeeChargeLimit, FeePaymentIntent, IvmBytecode,
        TransactionBuilder, TransactionPayload,
    },
    trigger::{
        Trigger,
        action::{Action, Repeats},
    },
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_primitives::{json::Json, numeric::Quantity};
use iroha_torii_shared::subscriptions as wire;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use wire::SubscriptionCancelMode;

type Responder = dyn Fn(&RequestSnapshot) -> eyre::Result<Response<Vec<u8>>> + Send + Sync;

struct AsyncTransport {
    responder: Box<Responder>,
    requests: Arc<Mutex<Vec<RequestSnapshot>>>,
    calls: Arc<AtomicUsize>,
    delay: Duration,
}
impl std::fmt::Debug for AsyncTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SubscriptionAsyncTransport")
    }
}
impl HttpTransport for AsyncTransport {
    fn send_blocking(&self, _: TransportRequest) -> eyre::Result<Response<Vec<u8>>> {
        panic!("subscription transport must be asynchronous")
    }
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            tokio::time::sleep(self.delay).await;
            let snapshot = RequestSnapshot {
                method: request.method,
                url: request.url,
                headers: request
                    .headers
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.to_string(),
                            std::str::from_utf8(value.as_bytes()).unwrap().to_owned(),
                        )
                    })
                    .collect(),
                body: request.body,
                timeout: request.timeout,
                max_response_bytes: request.max_response_bytes,
                direct_loopback: request.direct_loopback,
            };
            let response = (self.responder)(&snapshot);
            self.requests.lock().unwrap().push(snapshot);
            response
        })
    }
}
fn attach(
    client: Client,
    responder: impl Fn(&RequestSnapshot) -> eyre::Result<Response<Vec<u8>>> + Send + Sync + 'static,
    delay: Duration,
) -> (Client, Arc<Mutex<Vec<RequestSnapshot>>>, Arc<AtomicUsize>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = AsyncTransport {
        responder: Box::new(responder),
        requests: requests.clone(),
        calls: calls.clone(),
        delay,
    };
    (
        client.with_test_http_transport(DefaultHttpTransport::from_shared(Arc::new(transport))),
        requests,
        calls,
    )
}
fn json<T: norito::json::JsonSerialize>(value: &T) -> Response<Vec<u8>> {
    Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(norito::json::to_vec(value).unwrap())
        .unwrap()
}
fn id() -> NftId {
    "sub-1$subscriptions.universal".parse().unwrap()
}
fn plan_id() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("commerce", "universal").unwrap(),
        "fixed_plan".parse().unwrap(),
    )
}
fn plan(provider: AccountId) -> SubscriptionPlan {
    SubscriptionPlan {
        provider,
        billing: SubscriptionBilling {
            cadence: SubscriptionCadence::FixedPeriod(SubscriptionFixedPeriodCadence {
                period_ms: 1000,
            }),
            bill_for: SubscriptionBillFor::PreviousPeriod,
            retry_backoff_ms: 100,
            max_failures: 3,
            grace_ms: 500,
        },
        pricing: SubscriptionPricing::Fixed(SubscriptionFixedPricing {
            amount: Quantity::from(5_u32),
            asset_definition: plan_id(),
        }),
    }
}
fn state(authority: &AccountId) -> SubscriptionState {
    SubscriptionState {
        plan_id: plan_id(),
        provider: authority.clone(),
        subscriber: authority.clone(),
        status: SubscriptionStatus::Active,
        current_period_start_ms: 0,
        current_period_end_ms: 1000,
        next_charge_ms: 1000,
        cancel_at_period_end: false,
        cancel_at_ms: None,
        failure_count: 0,
        usage_accumulated: BTreeMap::new(),
        billing_trigger_id: "sub-1-bill".parse().unwrap(),
    }
}
fn intent() -> SubscriptionCreate {
    SubscriptionCreate {
        subscription_id: id(),
        plan_id: plan_id(),
        billing_trigger_id: Some("sub-1-bill".parse().unwrap()),
        usage_trigger_id: None,
        first_charge_ms: Some(1000),
        grant_usage_to_provider: Some(false),
    }
}
fn usage_intent() -> SubscriptionUsage {
    SubscriptionUsage {
        unit_key: "compute_ms".parse().unwrap(),
        delta: Quantity::from(3_u32),
        usage_trigger_id: Some("sub-1-usage".parse().unwrap()),
    }
}
fn framed(instructions: Vec<InstructionBox>) -> Vec<wire::SubscriptionInstructionDraft> {
    instructions
        .into_iter()
        .map(|instruction| {
            let (wire_id, bytes) =
                iroha_data_model::isi::framed_instruction_payload(&instruction).unwrap();
            wire::SubscriptionInstructionDraft {
                wire_id: wire_id.to_owned(),
                payload_hex: hex::encode(bytes),
            }
        })
        .collect()
}
fn billing(authority: &AccountId, state: &SubscriptionState) -> InstructionBox {
    let mut metadata = Metadata::default();
    metadata.insert(
        SUBSCRIPTION_TRIGGER_REF_METADATA_KEY.parse().unwrap(),
        Json::new(SubscriptionTriggerRef {
            subscription_nft_id: id(),
        }),
    );
    // Opaque program fixture: this suite verifies framing, target identity and scheduling, not IVM execution.
    let action = Action::new(
        Executable::Ivm(IvmBytecode::from_compiled(vec![1, 2, 3])),
        Repeats::Exactly(1),
        authority.clone(),
        EventFilterBox::Time(TimeEventFilter(ExecutionTime::Schedule(Schedule {
            start_ms: state.next_charge_ms,
            period_ms: None,
        }))),
    )
    .unwrap()
    .with_metadata(metadata);
    Register::trigger(Trigger::new(state.billing_trigger_id.clone(), action)).into()
}
fn create_response(authority: &AccountId) -> wire::SubscriptionCreateResponse {
    let state = state(authority);
    let mut metadata = Metadata::default();
    metadata.insert(
        SUBSCRIPTION_METADATA_KEY.parse().unwrap(),
        Json::new(state.clone()),
    );
    wire::SubscriptionCreateResponse {
        version: 1,
        authority: authority.clone(),
        action: "create".to_owned(),
        subscription_id: id(),
        plan_id: plan_id(),
        billing_trigger_id: state.billing_trigger_id.clone(),
        usage_trigger_id: None,
        first_charge_ms: 1000,
        provider_usage_grant_included: false,
        tx_instructions: framed(vec![
            Register::nft(Nft::new(id(), metadata)).into(),
            billing(authority, &state),
        ]),
        resulting_subscription: state,
    }
}
fn action_response(
    authority: &AccountId,
    action: &str,
    request: &wire::SubscriptionActionRequest,
) -> wire::SubscriptionActionResponse {
    let mut state = state(authority);
    match action {
        "pause" => state.status = SubscriptionStatus::Paused,
        "cancel" if request.cancel_mode == Some(wire::SubscriptionCancelMode::Immediate) => {
            state.status = SubscriptionStatus::Canceled
        }
        "cancel" => {
            state.cancel_at_period_end = true;
            state.cancel_at_ms = Some(1000);
        }
        _ => {}
    }
    let charge =
        matches!(action, "resume" | "charge-now").then_some(request.charge_at_ms.unwrap_or(1000));
    if let Some(charge) = charge {
        state.next_charge_ms = charge;
    }
    let mut instructions = vec![
        SetKeyValue::nft(
            id(),
            SUBSCRIPTION_METADATA_KEY.parse().unwrap(),
            Json::new(state.clone()),
        )
        .into(),
    ];
    if charge.is_some() {
        instructions.push(billing(authority, &state));
    }
    wire::SubscriptionActionResponse {
        version: 1,
        authority: authority.clone(),
        action: if action == "charge-now" {
            "charge_now"
        } else {
            action
        }
        .to_owned(),
        subscription_id: id(),
        details: wire::SubscriptionActionDraftDetails {
            billing_trigger_id: state.billing_trigger_id.clone(),
            billing_trigger_operation: if charge.is_some() { "register" } else { "none" }
                .to_owned(),
            effective_charge_ms: charge,
            cancel_mode: request.cancel_mode,
            resulting_subscription: state,
        },
        tx_instructions: framed(instructions),
    }
}
fn payload_response(client: &Client, instructions: Vec<InstructionBox>) -> (String, String) {
    let builder = TransactionBuilder::new(
        client.network_id,
        client.account.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instructions);
    (
        STANDARD.encode(builder.encode_payload()),
        STANDARD.encode(builder.payload_hash_bytes()),
    )
}
fn rewrite_payload_response(
    response: Response<Vec<u8>>,
    mutate: impl FnOnce(&mut TransactionPayload),
) -> Response<Vec<u8>> {
    let bytes = response.into_body();
    let mut body: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    let fields = body.as_object_mut().unwrap();
    let bytes = STANDARD
        .decode(fields["transaction_payload_b64"].as_str().unwrap())
        .unwrap();
    let mut payload = TransactionBuilder::decode_payload(&bytes)
        .unwrap()
        .into_payload()
        .unwrap();
    mutate(&mut payload);
    let builder = TransactionBuilder::from_payload(payload).unwrap();
    fields.insert(
        "transaction_payload_b64".to_owned(),
        norito::json::Value::String(STANDARD.encode(builder.encode_payload())),
    );
    // Keep the response hash consistent with the mutation: these tests exercise
    // the operation contract independently of canonical encoding and hashing.
    fields.insert(
        "signing_message_b64".to_owned(),
        norito::json::Value::String(STANDARD.encode(builder.payload_hash_bytes())),
    );
    json(&body)
}
fn plan_response(
    client: &Client,
    request: &wire::SubscriptionPlanCreateRequest,
) -> wire::SubscriptionPlanCreateResponse {
    let (transaction_payload_b64, signing_message_b64) = payload_response(
        client,
        vec![
            Register::asset_definition(AssetDefinition::numeric(
                request.plan_id.clone(),
                request.plan_id.to_string(),
                AssetBalancePolicy::Global,
                None,
            ))
            .into(),
            SetKeyValue::asset_definition(
                request.plan_id.clone(),
                SUBSCRIPTION_PLAN_METADATA_KEY.parse().unwrap(),
                Json::new(request.plan.clone()),
            )
            .into(),
        ],
    );
    wire::SubscriptionPlanCreateResponse {
        submitted: false,
        plan_id: request.plan_id.clone(),
        transaction_payload_b64,
        signing_message_b64,
    }
}
fn respond(client: &Client, snapshot: &RequestSnapshot) -> Response<Vec<u8>> {
    let path = snapshot.url.path();
    if path.ends_with("/query") {
        return json(&Page::<norito::json::Value> {
            items: Vec::new(),
            total: Some(0),
            next_cursor: None,
        });
    }
    if snapshot.method == Method::GET {
        return json(&wire::SubscriptionGetResponse {
            subscription_id: id(),
            subscription: state(&client.account),
            invoice: None,
            plan: None,
        });
    }
    if path == "/v1/subscriptions/plans" {
        let request = norito::json::from_slice(&snapshot.body).unwrap();
        return json(&plan_response(client, &request));
    }
    if path == "/v1/subscriptions" {
        return json(&create_response(&client.account));
    }
    if path.ends_with("/usage") {
        let request: wire::SubscriptionUsageRequest =
            norito::json::from_slice(&snapshot.body).unwrap();
        let trigger = request.usage_trigger_id.clone().unwrap_or_else(|| {
            format!(
                "sub_usage_{}",
                hex::encode(Hash::new(id().to_string()).as_ref())
            )
            .parse()
            .unwrap()
        });
        let instruction = ExecuteTrigger::new(trigger).with_args(SubscriptionUsageDelta {
            subscription_nft_id: id(),
            unit_key: request.unit_key,
            delta: request.delta,
        });
        let (transaction_payload_b64, signing_message_b64) =
            payload_response(client, vec![instruction.into()]);
        return json(&wire::SubscriptionUsageResponse {
            submitted: false,
            subscription_id: id(),
            transaction_payload_b64,
            signing_message_b64,
        });
    }
    let request = norito::json::from_slice(&snapshot.body).unwrap();
    json(&action_response(
        &client.account,
        path.rsplit('/').next().unwrap(),
        &request,
    ))
}

#[tokio::test(flavor = "current_thread")]
async fn all_eleven_operations_use_async_transport_and_exact_authority() {
    let base = client_with_base_url(base_url());
    let responder_client = base.clone();
    let (client, requests, calls) = attach(
        base,
        move |snapshot| Ok(respond(&responder_client, snapshot)),
        Duration::ZERO,
    );
    let account = client.account_client().unwrap();
    let public = client.subscriptions();
    let private = account.subscriptions();
    let params = ListQuery::new()
        .filter(field("provider").eq(client.account.to_string()))
        .limit(10)
        .cursor("plans-cursor")
        .include_total();
    client
        .list_page(&Collection::SubscriptionPlans, &params)
        .await
        .unwrap();
    client
        .list_page(
            &Collection::Subscriptions,
            &ListQuery::new()
                .filter(
                    field("owned_by").eq(client.account.to_string())
                        & field("provider").eq(client.account.to_string())
                        & field("status").eq("active"),
                )
                .limit(10)
                .cursor("subscriptions-cursor")
                .include_total(),
        )
        .await
        .unwrap();
    public.get(&id()).await.unwrap();
    let plan = private
        .prepare_plan(&plan_id(), &plan(client.account.clone()))
        .await
        .unwrap();
    assert_eq!(plan.authority(), account.authority());
    assert_eq!(plan.network_id(), account.network_id());
    assert!(matches!(
        plan.operation(),
        SubscriptionDraftOperation::Plan { .. }
    ));
    assert!(matches!(
        plan.artifact(),
        SubscriptionDraftArtifact::Payload(_)
    ));
    let created = private.prepare(&intent()).await.unwrap();
    assert!(created.resulting_subscription().is_some());
    assert!(
        matches!(created.into_artifact(), SubscriptionDraftArtifact::Instructions(instructions) if instructions.len() == 2)
    );
    private.prepare_pause(&id()).await.unwrap();
    private.prepare_resume(&id(), Some(2000)).await.unwrap();
    private
        .prepare_cancel(&id(), SubscriptionCancelMode::PeriodEnd)
        .await
        .unwrap();
    private.prepare_keep(&id()).await.unwrap();
    private.prepare_charge(&id(), Some(3000)).await.unwrap();
    private.prepare_usage(&id(), &usage_intent()).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 11);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 11);
    for snapshot in requests.iter() {
        assert_eq!(snapshot.max_response_bytes, 64 * 1024 * 1024);
        if snapshot.method == Method::POST && !snapshot.url.path().ends_with("/query") {
            super::tests::assert_canonical_account_signed_json_request(&client, snapshot);
            let body: norito::json::Value = norito::json::from_slice(&snapshot.body).unwrap();
            assert_eq!(
                body.get("authority").unwrap(),
                &norito::json::to_value(account.authority()).unwrap()
            );
            assert!(body.get("private_key").is_none());
        } else {
            assert!(
                !snapshot
                    .headers
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case("X-Iroha-Signature"))
            );
            if snapshot.url.path().ends_with("/query") {
                assert_eq!(snapshot.method, Method::POST);
                assert!(snapshot.url.query().is_none());
                let query =
                    ListQuery::from_json_value(norito::json::from_slice(&snapshot.body).unwrap())
                        .unwrap();
                assert!(query.include_total);
                assert_eq!(query.limit, Some(10));
                assert_eq!(
                    query.cursor.as_deref(),
                    Some(if snapshot.url.path().contains("/plans/") {
                        "plans-cursor"
                    } else {
                        "subscriptions-cursor"
                    })
                );
                assert!(query.filter.is_some());
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn public_queries_remain_responsive_and_deadlines_cover_injected_transports() {
    let mut base = client_with_base_url(base_url());
    base.torii_request_timeout = Duration::from_millis(50);
    let (client, _, calls) = attach(
        base,
        |_| unreachable!("deadline expires before responder"),
        Duration::from_secs(1),
    );
    let ticks = Arc::new(AtomicUsize::new(0));
    let ticker = ticks.clone();
    let ticker = tokio::spawn(async move {
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(2)).await;
            ticker.fetch_add(1, Ordering::SeqCst);
        }
    });
    assert!(matches!(
        client
            .list_page(&Collection::Subscriptions, &ListQuery::new())
            .await,
        Err(Error::Timeout {
            operation: "collections.subscriptions"
        })
    ));
    ticker.await.unwrap();
    assert_eq!(ticks.load(Ordering::SeqCst), 3);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn structured_http_decode_transport_and_bound_errors_are_preserved_without_replay() {
    for status in [401, 409, 503] {
        let (client, _, calls) = attach(
            client_with_base_url(base_url()),
            move |_| {
                Ok(Response::builder()
                    .status(status)
                    .body(b"{\"code\":\"rejected\"}".to_vec())
                    .unwrap())
            },
            Duration::ZERO,
        );
        let error = client
            .account_client()
            .unwrap()
            .subscriptions()
            .prepare_pause(&id())
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::Http { status: actual, body, .. } if actual == status && body == b"{\"code\":\"rejected\"}")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    let (client, _, _) = attach(
        client_with_base_url(base_url()),
        |_| {
            Ok(Response::builder()
                .status(200)
                .header("Content-Type", "application/json")
                .body(b"{".to_vec())
                .unwrap())
        },
        Duration::ZERO,
    );
    assert!(matches!(
        client.subscriptions().get(&id()).await,
        Err(Error::Decode { .. })
    ));
    let (client, _, _) = attach(
        client_with_base_url(base_url()),
        |_| {
            Ok(Response::builder()
                .status(200)
                .header("Content-Length", (64 * 1024 * 1024 + 1).to_string())
                .body(Vec::new())
                .unwrap())
        },
        Duration::ZERO,
    );
    assert!(matches!(
        client.subscriptions().get(&id()).await,
        Err(Error::ResponseTooLarge {
            maximum: 67_108_864,
            ..
        })
    ));
    let (client, _, calls) = attach(
        client_with_base_url(base_url()),
        |_| Err(eyre::eyre!("offline fixture transport")),
        Duration::ZERO,
    );
    assert!(matches!(
        client.subscriptions().get(&id()).await,
        Err(Error::Transport { .. })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn duplicate_response_content_types_are_rejected_without_replay() {
    for extra in ["application/json", "text/plain"] {
        let (client, _, calls) = attach(
            client_with_base_url(base_url()),
            move |_| {
                let mut response = json(&Page::<norito::json::Value> {
                    items: Vec::new(),
                    total: Some(0),
                    next_cursor: None,
                });
                response
                    .headers_mut()
                    .append("Content-Type", extra.parse().unwrap());
                Ok(response)
            },
            Duration::ZERO,
        );
        assert!(matches!(
            client
                .list_page(&Collection::Subscriptions, &ListQuery::new())
                .await,
            Err(Error::Decode {
                operation: "collections.subscriptions",
                ..
            })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn foreign_plan_provider_fails_before_transport() {
    let (client, _, calls) = attach(
        client_with_base_url(base_url()),
        |_| unreachable!("foreign provider must fail before transport"),
        Duration::ZERO,
    );
    let foreign = client_with_base_url(base_url()).account;
    assert!(matches!(
        client
            .account_client()
            .unwrap()
            .subscriptions()
            .prepare_plan(&plan_id(), &plan(foreign))
            .await,
        Err(Error::InvalidRequest { .. })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn payload_drafts_bind_network_authority_signing_hash_and_submission_state() {
    for mutation in ["network", "authority", "hash", "submitted", "instructions"] {
        let base = client_with_base_url(base_url());
        let mut responder_client = base.clone();
        if mutation == "network" {
            responder_client.network_id = iroha_data_model::NetworkId::from_genesis_hash(
                HashOf::from_untyped_unchecked(Hash::prehashed([0xB5; 32])),
            );
        }
        if mutation == "authority" {
            responder_client.account = client_with_base_url(base_url()).account;
        }
        let (client, _, calls) = attach(
            base,
            move |snapshot| {
                let mut request: wire::SubscriptionPlanCreateRequest =
                    norito::json::from_slice(&snapshot.body).unwrap();
                if mutation == "instructions" {
                    request.plan.billing.max_failures += 1;
                }
                let mut response = plan_response(&responder_client, &request);
                if mutation == "hash" {
                    response.signing_message_b64 = STANDARD.encode([0_u8; 32]);
                }
                if mutation == "submitted" {
                    response.submitted = true;
                }
                Ok(json(&response))
            },
            Duration::ZERO,
        );
        let result = client
            .account_client()
            .unwrap()
            .subscriptions()
            .prepare_plan(&plan_id(), &plan(client.account.clone()))
            .await;
        assert!(
            matches!(result, Err(Error::ResponseBinding { .. })),
            "must reject {mutation}: {result:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn payload_drafts_reject_unrequested_fixed_transaction_fields() {
    for usage in [false, true] {
        for (mutation, field) in [
            ("metadata", "metadata"),
            ("attachments", "attachments"),
            ("sponsor", "fee_payer_and_gas_bound"),
            ("gas", "fee_payer_and_gas_bound"),
        ] {
            let base = client_with_base_url(base_url());
            let responder_client = base.clone();
            let (client, _, calls) = attach(
                base,
                move |snapshot| {
                    Ok(rewrite_payload_response(
                        respond(&responder_client, snapshot),
                        |payload| match mutation {
                            "metadata" => {
                                payload.metadata.insert(
                                    "unrequested".parse().unwrap(),
                                    Json::new("extra transaction metadata"),
                                );
                            }
                            "attachments" => {
                                let backend = "subscription_fixture".into();
                                let attachment = ProofAttachment::new_ref(
                                    backend,
                                    ProofBox::new("subscription_fixture".into(), vec![1]),
                                    VerifyingKeyId::new("subscription_fixture", "fixture_key"),
                                );
                                payload.set_proof_attachments_v1(&[attachment]).unwrap();
                            }
                            "sponsor" => {
                                payload.fee_payment = FeePaymentIntent::sponsor(
                                    FeeSponsorProgramId::new(
                                        payload.authority.clone(),
                                        "unrequested".parse().unwrap(),
                                    ),
                                    1,
                                    Vec::new(),
                                    None,
                                );
                            }
                            "gas" => {
                                payload.fee_payment = FeePaymentIntent::authority(
                                    Vec::new(),
                                    Some(100_u64.try_into().unwrap()),
                                );
                            }
                            _ => unreachable!(),
                        },
                    ))
                },
                Duration::ZERO,
            );
            let account = client.account_client().unwrap();
            let result = if usage {
                account
                    .subscriptions()
                    .prepare_usage(&id(), &usage_intent())
                    .await
            } else {
                account
                    .subscriptions()
                    .prepare_plan(&plan_id(), &plan(client.account.clone()))
                    .await
            };
            {
                let actual_error = result.unwrap_err();
                let Error::ResponseBinding {
                    operation: actual_operation,
                    field: actual_field,
                } = &actual_error
                else {
                    panic!("unexpected SDK error: {actual_error:?}");
                };
                assert_eq!(
                    (actual_operation, actual_field,),
                    (
                        &(if usage {
                            "subscriptions.prepare_usage"
                        } else {
                            "subscriptions.prepare_plan"
                        }),
                        &(field),
                    ),
                    "must reject {mutation} on the requested operation"
                );
            };
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn payload_drafts_preserve_all_quoted_charge_limits_for_review() {
    let fee = FeePaymentIntent::authority(
        vec![
            FeeChargeLimit::new(FeeChargeKind::Nexus, plan_id(), Quantity::from(42_u32)),
            FeeChargeLimit::new(
                FeeChargeKind::PipelineGas,
                plan_id(),
                Quantity::from(73_u32),
            ),
        ],
        None,
    );
    let response_fee = fee.clone();
    let base = client_with_base_url(base_url());
    let responder_client = base.clone();
    let (client, _, calls) = attach(
        base,
        move |snapshot| {
            Ok(rewrite_payload_response(
                respond(&responder_client, snapshot),
                |payload| payload.fee_payment = response_fee.clone(),
            ))
        },
        Duration::ZERO,
    );
    let account = client.account_client().unwrap();
    let drafts = [
        account
            .subscriptions()
            .prepare_plan(&plan_id(), &plan(client.account.clone()))
            .await
            .unwrap(),
        account
            .subscriptions()
            .prepare_usage(&id(), &usage_intent())
            .await
            .unwrap(),
    ];
    for draft in drafts {
        let SubscriptionDraftArtifact::Payload(payload) = draft.artifact() else {
            panic!("plan and usage operations must expose their exact payload");
        };
        assert_eq!(payload.fee_payment, fee);
        let json = norito::json::to_value(draft.artifact()).unwrap();
        assert_eq!(
            json.get("kind").and_then(norito::json::Value::as_str),
            Some("payload")
        );
        assert_eq!(
            json.get("value"),
            Some(&norito::json::to_value(payload.as_ref()).unwrap())
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn instruction_drafts_reject_wrong_resource_action_and_hidden_instruction_changes() {
    for mutation in [
        "authority",
        "resource",
        "action",
        "instruction",
        "extra_instruction",
        "version",
    ] {
        let base = client_with_base_url(base_url());
        let authority = base.account.clone();
        let (client, _, _) = attach(
            base,
            move |snapshot| {
                let request = norito::json::from_slice(&snapshot.body).unwrap();
                let mut response = action_response(&authority, "keep", &request);
                match mutation {
                    "authority" => response.authority = client_with_base_url(base_url()).account,
                    "resource" => {
                        response.subscription_id =
                            "another$subscriptions.universal".parse().unwrap()
                    }
                    "action" => response.action = "pause".to_owned(),
                    "version" => response.version = 2,
                    "instruction" => {
                        response.tx_instructions = framed(vec![
                            SetKeyValue::nft(
                                "another$subscriptions.universal".parse().unwrap(),
                                SUBSCRIPTION_METADATA_KEY.parse().unwrap(),
                                Json::new(response.details.resulting_subscription.clone()),
                            )
                            .into(),
                        ])
                    }
                    "extra_instruction" => response
                        .tx_instructions
                        .push(response.tx_instructions[0].clone()),
                    _ => unreachable!(),
                }
                Ok(json(&response))
            },
            Duration::ZERO,
        );
        let result = client
            .account_client()
            .unwrap()
            .subscriptions()
            .prepare_keep(&id())
            .await;
        assert!(
            matches!(result, Err(Error::ResponseBinding { .. })),
            "must reject {mutation}: {result:?}"
        );
    }
}

#[test]
fn blocking_subscription_contexts_reuse_async_dispatch_and_reject_nested_runtimes() {
    let base = client_with_base_url(base_url());
    let responder_client = base.clone();
    let (client, _, calls) = attach(
        base,
        move |snapshot| Ok(respond(&responder_client, snapshot)),
        Duration::ZERO,
    );
    let account = blocking::AccountClient::from_client(client.account_client().unwrap()).unwrap();
    account.subscriptions().prepare_pause(&id()).unwrap();
    account.clone().subscriptions().prepare_keep(&id()).unwrap();
    let public = blocking::Client::from_client(client).unwrap();
    public
        .list_page(&Collection::SubscriptionPlans, &ListQuery::new())
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        assert!(matches!(
            account.subscriptions().prepare_keep(&id()),
            Err(Error::Blocking(
                blocking::BlockingCallError::AsyncRuntime { .. }
            ))
        ));
        assert!(matches!(
            public.list_page(&Collection::Subscriptions, &ListQuery::new()),
            Err(Error::Blocking(
                blocking::BlockingCallError::AsyncRuntime { .. }
            ))
        ));
        drop(account);
        drop(public);
    });
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[test]
fn subscription_context_futures_are_send_and_drafts_stay_compact() {
    fn require_send<F: std::future::Future + Send>(_: F) {}

    assert!(std::mem::size_of::<SubscriptionDraftArtifact>() <= 4 * std::mem::size_of::<usize>());
    let client = client_with_base_url(base_url());
    let account = client.account_client().unwrap();
    let public = client.subscriptions();
    let private = account.subscriptions();
    require_send(client.list_page(&Collection::SubscriptionPlans, &ListQuery::new()));
    require_send(client.list_page(&Collection::Subscriptions, &ListQuery::new()));
    require_send(public.get(&id()));
    require_send(private.prepare_plan(&plan_id(), &plan(client.account.clone())));
    require_send(private.prepare(&intent()));
    require_send(private.prepare_pause(&id()));
    require_send(private.prepare_resume(&id(), Some(2000)));
    require_send(private.prepare_cancel(&id(), SubscriptionCancelMode::PeriodEnd));
    require_send(private.prepare_keep(&id()));
    require_send(private.prepare_charge(&id(), Some(3000)));
    require_send(private.prepare_usage(&id(), &usage_intent()));
}
