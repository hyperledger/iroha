#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Public contract preparation and strict admission failure, plus exact-payload Core execution.
//! A certified genesis and deployment anchor contract state; isolated call overlays exercise
//! contract semantics without publishing an execution receipt.
#![cfg(feature = "app_api")]
#![allow(unexpected_cfgs, clippy::too_many_lines)]
#[path = "fixtures.rs"]
mod fixtures;
use base64::Engine as _;
use http_body_util::BodyExt as _;
use iroha_core::{
    kura::Kura,
    queue::Queue,
    smartcontracts::Execute,
    state::{State, WorldReadOnly},
};
use iroha_crypto::Signature;
use iroha_data_model::{
    asset::AssetDefinitionId,
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use iroha_model_base::domain::DomainId;
use kotodama_lang::session::{CompileRequest, CompilerSession};
use mv::storage::StorageReadOnly;
use norito::json;
use std::{num::NonZeroU64, sync::Arc, time::Duration};
use tower::ServiceExt as _;
fn can_modify_account_metadata(
    account: &iroha_data_model::account::AccountId,
) -> iroha_data_model::permission::Permission {
    iroha_executor_data_model::permission::account::CanModifyAccountMetadata {
        account: account.clone(),
    }
    .into()
}
fn can_mint_asset_definition(
    asset_definition: &AssetDefinitionId,
) -> iroha_data_model::permission::Permission {
    iroha_executor_data_model::permission::asset::CanMintAssetWithDefinition {
        asset_definition: asset_definition.clone(),
    }
    .into()
}
fn can_burn_asset_definition(
    asset_definition: &AssetDefinitionId,
) -> iroha_data_model::permission::Permission {
    iroha_executor_data_model::permission::asset::CanBurnAssetWithDefinition {
        asset_definition: asset_definition.clone(),
    }
    .into()
}
fn commit_contract_operator_genesis(
    world: iroha_core::state::World,
    authority: &iroha_data_model::account::AccountId,
    signer: &iroha_crypto::KeyPair,
) -> iroha_core::sumeragi::test_chain::CertifiedTestChain {
    use iroha_data_model::prelude::Grant;
    use iroha_executor_data_model::permission::{
        account::{AccountAliasPermissionScope, CanManageAccountAlias},
        smart_contract::CanManageSmartContractCode,
    };

    fixtures::commit_genesis_fixture(
        world,
        "chain".into(),
        signer,
        vec![
            Grant::account_permission(CanManageSmartContractCode, authority.clone()).into(),
            Grant::account_permission(
                CanManageAccountAlias {
                    scope: AccountAliasPermissionScope::Dataspace(
                        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    ),
                },
                authority.clone(),
            )
            .into(),
        ],
        None,
        iroha_primitives::time::TimeSource::new_system(),
    )
}
fn contract_call_noop_program() -> Vec<u8> {
    let src = include_str!("fixtures/contracts_call/noop.ko");
    kotodama_lang::compiler::Compiler::new()
        .compile_source(src)
        .expect("compile contract call no-op test program")
}
fn contract_call_dispatch_program() -> Vec<u8> {
    let src = format!(
        r#"
seiyaku ContractCallDispatchTest {{ permission CanEnactGovernance;

  state int call_amount;
  state AssetDefinitionId call_asset;

  hajimari(AssetDefinitionId asset_definition_id) {{
    call_amount = 0;
    call_asset = asset_definition_id;
  }}

  kotoage fn credit_by_payload(int amount) authorize(CanEnactGovernance) {{
    call_amount = amount;
  }}

  kotoage fn record_asset_by_payload(AssetDefinitionId asset_definition_id) authorize(CanEnactGovernance) {{
    call_asset = asset_definition_id;
  }}

  view fn call_state() authorize(anyone) -> (int, AssetDefinitionId) {{
    return (call_amount, call_asset);
  }}
}}
"#
    );
    kotodama_lang::compiler::Compiler::new()
        .compile_source(&src)
        .expect("compile contract call dispatch test program")
}
fn contract_call_declared_state_program() -> Vec<u8> {
    let src = format!(
        r#"
seiyaku ContractCallDeclaredStateTest {{ permission CanEnactGovernance;

  state int CallAmount;
  state AssetDefinitionId CallAsset;

  hajimari(AssetDefinitionId asset_definition_id) {{
    CallAmount = 0;
    CallAsset = asset_definition_id;
  }}

  kotoage fn credit_by_payload(int amount) authorize(CanEnactGovernance) {{
    CallAmount = amount;
  }}

  kotoage fn record_asset_by_payload(AssetDefinitionId asset_definition_id) authorize(CanEnactGovernance) {{
    CallAsset = asset_definition_id;
  }}

  view fn declared_state() authorize(anyone) -> (int, AssetDefinitionId) {{
    return (CallAmount, CallAsset);
  }}
}}
"#
    );
    kotodama_lang::compiler::Compiler::new()
        .compile_source(&src)
        .expect("compile contract call declared state test program")
}
fn contract_call_declared_state_with_isi_program() -> Vec<u8> {
    let src = format!(
        r#"
seiyaku ContractCallDeclaredStateWithIsiTest {{ permission CanEnactGovernance;

  state int CallAmount;

  hajimari() {{
    CallAmount = 0;
  }}

  kotoage fn write_with_isi(int amount) authorize(CanEnactGovernance) {{
    ledger::account::set_metadata(account: context::authority(), key: Name::parse("cursor"), value: Json::parse("{{\"phase\":\"write_with_isi\"}}"));
    CallAmount = amount;
  }}

  view fn declared_state() authorize(anyone) -> int {{
    return CallAmount;
  }}
}}
"#
    );
    kotodama_lang::compiler::Compiler::new()
        .compile_source(&src)
        .expect("compile contract call declared state with isi test program")
}
fn contract_call_declared_state_with_mint_program() -> Vec<u8> {
    let src = format!(
        r#"
seiyaku ContractCallDeclaredStateWithMintTest {{ permission CanEnactGovernance;

  state int CallAmount;

  hajimari() {{
    CallAmount = 0;
  }}

  kotoage fn write_with_mint(int amount,
                           AccountId user,
                           AssetDefinitionId asset_definition_id) authorize(CanEnactGovernance) {{
    ledger::asset::mint(account: user, asset_definition: asset_definition_id, amount: 1);
    CallAmount = amount;
  }}

  view fn declared_state() authorize(anyone) -> int {{
    return CallAmount;
  }}
}}
"#
    );
    kotodama_lang::compiler::Compiler::new()
        .compile_source(&src)
        .expect("compile contract call declared state with mint test program")
}
fn contract_call_n3x_like_program() -> Vec<u8> {
    let src = format!(
        r#"
seiyaku ContractCallN3xLikeTest {{ permission CanEnactGovernance;

  error enum HubError {{
    NotInitialized = 1,
    EmptyHub = 2,
    InvalidAmount = 3,
    InsufficientSupply = 4,
    ZeroRedemption = 5
  }}

  state int HubInitialized;
  state quantity BasketUsdt;
  state quantity BasketUsdc;
  state quantity BasketKusd;
  state quantity TotalN3x;

  fn init_impl() {{
    HubInitialized = 1;
    BasketUsdt = 0;
    BasketUsdc = 0;
    BasketKusd = 0;
    TotalN3x = 0;
  }}

  hajimari() {{
    init_impl();
  }}

  kotoage fn init_hub() authorize(CanEnactGovernance) {{
    init_impl();
  }}

  fn deposit_impl(AccountId user,
                  AssetDefinitionId asset,
                  quantity usdt_in,
                  quantity usdc_in,
                  quantity kusd_in) {{
    require(HubInitialized == 1, HubError::NotInitialized);
    let minted = usdt_in + usdc_in + kusd_in;
    ledger::asset::mint(account: user, asset_definition: asset, amount: minted);
    BasketUsdt = BasketUsdt + usdt_in;
    BasketUsdc = BasketUsdc + usdc_in;
    BasketKusd = BasketKusd + kusd_in;
    TotalN3x = TotalN3x + minted;
  }}

  kotoage fn deposit_like(AccountId user,
                        AssetDefinitionId asset_definition_id,
                        quantity usdt_in,
                        quantity usdc_in,
                        quantity kusd_in) authorize(CanEnactGovernance) {{
    deposit_impl(
      user: user,
      asset: asset_definition_id,
      usdt_in: usdt_in,
      usdc_in: usdc_in,
      kusd_in: kusd_in
    );
  }}

  kotoage fn burn_like(AccountId user,
                     AssetDefinitionId asset_definition_id,
                     quantity n3x_amount) authorize(CanEnactGovernance) {{
    let total = TotalN3x;
    require(total > 0, HubError::EmptyHub);
    require(n3x_amount > 0, HubError::InvalidAmount);
    require(n3x_amount <= total, HubError::InsufficientSupply);
    let decimal redemption_ratio = n3x_amount / total;
    let quantity usdt_out = BasketUsdt * redemption_ratio;
    let quantity usdc_out = BasketUsdc * redemption_ratio;
    let quantity kusd_out = BasketKusd * redemption_ratio;
    let redeemed = usdt_out + usdc_out + kusd_out;
    require(redeemed > 0, HubError::ZeroRedemption);
    ledger::asset::burn(account: user, asset_definition: asset_definition_id, amount: n3x_amount);
    BasketUsdt = BasketUsdt - usdt_out;
    BasketUsdc = BasketUsdc - usdc_out;
    BasketKusd = BasketKusd - kusd_out;
    TotalN3x = total - n3x_amount;
  }}

  view fn state_snapshot() authorize(anyone) -> (int, quantity, quantity, quantity, quantity) {{
    return (HubInitialized, BasketUsdt, BasketUsdc, BasketKusd, TotalN3x);
  }}
}}
"#
    );
    kotodama_lang::compiler::Compiler::new()
        .compile_source(&src)
        .expect("compile contract call n3x-like test program")
}
fn contract_view_trap_program_with_source_path(source_path: &str) -> Vec<u8> {
    let src = include_str!("fixtures/contracts_call/trap.ko");
    CompilerSession::default()
        .build(CompileRequest {
            source: src,
            source_name: Some(source_path),
        })
        .expect("compile contract view trap test program")
        .artifact
}
fn contract_view_bytes_program() -> Vec<u8> {
    let src = include_str!("fixtures/contracts_call/bytes.ko");
    kotodama_lang::compiler::Compiler::new()
        .compile_source(src)
        .expect("compile contract view bytes test program")
}
fn contract_view_account_id_program() -> Vec<u8> {
    let src = include_str!("fixtures/contracts_call/account_id.ko");
    kotodama_lang::compiler::Compiler::new()
        .compile_source(src)
        .expect("compile contract view AccountId test program")
}
fn contract_call_configure_account_map_program() -> Vec<u8> {
    let src = include_str!("fixtures/contracts_call/account_map.ko");
    kotodama_lang::compiler::Compiler::new()
        .compile_source(src)
        .expect("compile contract call configure account-map test program")
}
struct ContractTestApp {
    runtime: iroha_torii::TestApiRouterRuntime,
    _harness: fixtures::ToriiHarness,
    _data_dir: iroha_torii::test_utils::TestDataDirGuard,
    authority: iroha_data_model::account::AccountId,
    key_pair: iroha_crypto::KeyPair,
    queue: Arc<Queue>,
    state: Arc<State>,
}
impl ContractTestApp {
    async fn request(&self, request: http::Request<axum::body::Body>) -> axum::response::Response {
        let (parts, body) = request.into_parts();
        let bytes = body
            .collect()
            .await
            .expect("collect request body")
            .to_bytes();
        let request = http::Request::from_parts(parts, axum::body::Body::from(bytes.clone()));
        let request = fixtures::app_signed_request(
            self.state.network_id_ref(),
            &self.authority,
            &self.key_pair,
            request,
            &bytes,
        );
        self.runtime
            .router()
            .oneshot(request)
            .await
            .expect("public contract route response")
    }
    async fn shutdown(self) {
        self.runtime.shutdown().await;
    }
}
fn contract_test_state() -> (
    iroha_torii::test_utils::AuthorityCreds,
    Arc<State>,
    Arc<Kura>,
    iroha_core::sumeragi::test_chain::CertifiedTestChain,
) {
    let creds = iroha_torii::test_utils::random_authority();
    let world = iroha_torii::test_utils::world_with_authority(&creds.account);
    let signer = iroha_crypto::KeyPair::from_private_key(creds.private_key.0.clone())
        .expect("contract genesis signer");
    let chain = commit_contract_operator_genesis(world, &creds.account, &signer);
    (creds, chain.state().clone(), chain.kura().clone(), chain)
}
fn contract_test_queue_and_app(
    state: &Arc<State>,
    kura: &Arc<Kura>,
    creds: &iroha_torii::test_utils::AuthorityCreds,
) -> (
    Arc<Queue>,
    iroha_model_base::chain::ChainId,
    ContractTestApp,
) {
    let data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.common.chain = state.chain_id_ref().clone();
    let events: iroha_core::EventsSender = tokio::sync::broadcast::channel(8).0;
    let queue = Arc::new(Queue::from_config(cfg.queue.clone(), events.clone()));
    let chain_id = cfg.common.chain.clone();
    let harness = fixtures::ToriiHarness::new_without_telemetry(&cfg, kura, state, &queue, events);
    let runtime = harness.router();
    let app = ContractTestApp {
        runtime,
        _harness: harness,
        _data_dir: data_dir,
        authority: creds.account.clone(),
        key_pair: iroha_crypto::KeyPair::from_private_key(creds.private_key.0.clone())
            .expect("fixture key pair"),
        queue: queue.clone(),
        state: state.clone(),
    };
    (queue, chain_id, app)
}
struct PreparedContractExecution {
    response: json::Value,
    transaction: iroha_data_model::transaction::SignedTransaction,
}
/// Prepare through the production HTTP router and sign its exact quoted payload locally.
/// This fixture has no certified coordinator: a detached public submit must fail closed.
async fn prepare_contract_execution(
    app: &ContractTestApp,
    request_body: String,
) -> PreparedContractExecution {
    let mut request: json::Value = json::from_str(&request_body).expect("prepare request JSON");
    assert!(request.get("private_key").is_none());
    assert_eq!(
        app.queue.active_len(),
        0,
        "preparation starts without queued work"
    );
    let response = app
        .request(
            http::Request::builder()
                .method("POST")
                .uri("/v1/contracts/call")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(request_body))
                .expect("prepare request"),
        )
        .await;
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("prepare response body")
        .to_bytes();
    assert_eq!(
        status,
        http::StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let response: json::Value = json::from_slice(&bytes).expect("prepare response JSON");
    assert_eq!(
        response.get("submitted").and_then(json::Value::as_bool),
        Some(false)
    );
    assert!(
        response
            .get("pipeline_status")
            .is_some_and(json::Value::is_null)
    );
    assert!(
        response
            .get("tx_hash_hex")
            .is_some_and(json::Value::is_null)
    );
    assert!(
        response
            .get("entrypoint_hash_hex")
            .is_some_and(json::Value::is_null)
    );
    assert!(response.get("transaction_scaffold_b64").is_none());
    assert!(response.get("signed_transaction_b64").is_none());
    let payload_b64 = response
        .get("transaction_payload_b64")
        .and_then(json::Value::as_str)
        .expect("canonical unsigned payload");
    let payload = base64::engine::general_purpose::STANDARD
        .decode(payload_b64)
        .expect("decode unsigned payload");
    assert_eq!(
        base64::engine::general_purpose::STANDARD.encode(&payload),
        payload_b64
    );
    let builder = TransactionBuilder::decode_payload(&payload).expect("canonical payload decode");
    assert_eq!(
        builder.encode_payload(),
        payload,
        "unsigned payload round-trip"
    );
    let signing_b64 = response
        .get("signing_message_b64")
        .and_then(json::Value::as_str)
        .expect("signing preimage");
    let signing = base64::engine::general_purpose::STANDARD
        .decode(signing_b64)
        .expect("decode signing preimage");
    assert_eq!(
        base64::engine::general_purpose::STANDARD.encode(&signing),
        signing_b64
    );
    assert_eq!(
        signing,
        builder.payload_hash_bytes(),
        "signature binds exact quoted payload"
    );
    let receipt = response
        .get("operation_receipt")
        .and_then(json::Value::as_object)
        .expect("prepare receipt");
    assert_eq!(
        receipt.get("status").and_then(json::Value::as_str),
        Some("pending_signature")
    );
    assert!(!receipt.contains_key("private_key"));
    assert!(!receipt.contains_key("payload"));
    let fee_payment = builder.payload().fee_payment.clone();
    assert_eq!(
        receipt.get("fee_payment"),
        Some(&json::to_value(&fee_payment).expect("fee JSON")),
        "receipt fee identity matches the signature-bound payload"
    );
    let signature = Signature::try_new(app.key_pair.private_key(), &signing)
        .expect("sign exact returned payload");
    let fields = request.as_object_mut().expect("request object");
    fields.insert(
        "transaction_payload_b64".to_owned(),
        json::Value::String(payload_b64.to_owned()),
    );
    fields.insert(
        "creation_time_ms".to_owned(),
        response
            .get("creation_time_ms")
            .cloned()
            .expect("fixed creation time"),
    );
    fields.insert(
        "fee_payment".to_owned(),
        json::to_value(&fee_payment).expect("quoted fee JSON"),
    );
    fields.insert(
        "public_key_hex".to_owned(),
        json::Value::String(hex::encode_upper(app.key_pair.public_key().to_bytes().1)),
    );
    fields.insert(
        "signature_b64".to_owned(),
        json::Value::String(base64::engine::general_purpose::STANDARD.encode(signature.payload())),
    );
    let transaction = builder.build_with_signature(signature);
    transaction
        .verify_signature()
        .expect("retained signature verifies");
    let submitted = app
        .request(
            http::Request::builder()
                .method("POST")
                .uri("/v1/contracts/call")
                .header(http::header::CONTENT_TYPE, "application/json")
                .header(http::header::ACCEPT, "application/x-norito")
                .body(axum::body::Body::from(
                    json::to_json(&request).expect("detached request JSON"),
                ))
                .expect("detached request"),
        )
        .await;
    let status = submitted.status();
    let bytes = submitted
        .into_body()
        .collect()
        .await
        .expect("submit response body")
        .to_bytes();
    assert_eq!(
        status,
        http::StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let error: iroha_torii_shared::ErrorEnvelope =
        norito::decode_from_bytes(&bytes).expect("strict ingress Norito error envelope");
    let expected_code = "route_unavailable";
    assert_eq!(error.code(), expected_code, "{error:?}");
    assert_eq!(
        app.queue.active_len(),
        0,
        "neither draft nor failed strict admission enqueues locally"
    );
    PreparedContractExecution {
        response,
        transaction,
    }
}
/// Execute the unchanged caller-signed payload in an explicit test-only world overlay.
/// This exercises Core transaction/contract semantics without claiming durable admission,
/// transaction membership, or a committed block.
fn execute_prepared_contract_in_test_overlay(
    state: &Arc<State>,
    prepared: &PreparedContractExecution,
    execution_height: u64,
) {
    let original_hash = prepared.transaction.hash();
    prepared
        .transaction
        .verify_signature()
        .expect("exact signed fixture");
    let committed_height = state.committed_height();
    let header = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(execution_height).expect("positive execution height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut cache = iroha_core::smartcontracts::ivm::cache::IvmCache::new();
    let entrypoint = prepared.transaction.hash_as_entrypoint();
    iroha_core::tx::execute_component_transaction_for_testing(
        &mut block,
        iroha_core::tx::AcceptedTransaction::new_unchecked(std::borrow::Cow::Borrowed(
            &prepared.transaction,
        )),
        &mut cache,
        None,
    )
    .expect("prepared contract executes exactly once in test overlay");
    block
        .commit_world_overlay_for_testing()
        .expect("publish only contract fixture world effects");
    assert_eq!(
        prepared.transaction.hash(),
        original_hash,
        "no signed payload mutation"
    );
    assert_eq!(
        state.committed_height(),
        committed_height,
        "fixture does not claim block finality"
    );
    assert!(
        !iroha_core::state::StateReadOnlyWithTransactions::has_entrypoint(
            &state.view(),
            entrypoint
        ),
        "component execution does not invent committed input membership"
    );
}
async fn run_contract_view_in_test_overlay(
    app: &ContractTestApp,
    authority: &iroha_data_model::account::AccountId,
    contract_address: &str,
    entrypoint: &str,
    payload: Option<&norito::json::Value>,
) -> json::Value {
    let (status, body) = run_contract_view_response_in_test_overlay(
        app,
        authority,
        contract_address,
        entrypoint,
        payload,
    )
    .await;
    assert_eq!(status, http::StatusCode::OK, "{body:?}");
    body
}
async fn run_contract_view_response_in_test_overlay(
    app: &ContractTestApp,
    authority: &iroha_data_model::account::AccountId,
    contract_address: &str,
    entrypoint: &str,
    payload: Option<&norito::json::Value>,
) -> (http::StatusCode, json::Value) {
    let body = iroha_torii::test_utils::contract_view_request_json(
        authority,
        contract_address,
        iroha_torii::test_utils::ContractViewOptions {
            entrypoint,
            payload,
            gas_limit: 1_500_000,
        },
    );
    // Local view semantics over the explicitly staged world fixture are independent of
    // public routed-read authority; this fixture intentionally has no certified committee.
    let request = json::from_str(&body).expect("view DTO");
    let (status, bytes) =
        iroha_torii::handle_post_contract_view(app.state.clone(), iroha_torii::NoritoJson(request))
            .expect("local contract view");
    (
        status,
        json::from_slice(&bytes).expect("decode contract view response"),
    )
}
async fn run_contract_hajimari_in_test_overlay(
    app: &ContractTestApp,
    state: &Arc<State>,
    creds: &iroha_torii::test_utils::AuthorityCreds,
    contract_address: &str,
    payload: Option<&json::Value>,
    block_height: u64,
) {
    let body = iroha_torii::test_utils::contract_call_request_json(
        &creds.account,
        contract_address,
        iroha_torii::test_utils::ContractCallOptions {
            entrypoint: "hajimari",
            payload,
            gas_limit: 1_500_000,
        },
    );
    let prepared = prepare_contract_execution(app, body).await;
    execute_prepared_contract_in_test_overlay(state, &prepared, block_height);
}
#[tokio::test]
async fn contracts_call_prepares_exact_payload_and_requires_durable_admission() {
    let (creds, state, kura, mut native_chain) = contract_test_state();
    let (queue, _chain_id, app) = contract_test_queue_and_app(&state, &kura, &creds);
    let program = contract_call_noop_program();
    let (contract_address, code_hash_hex, abi_hash_hex) =
        iroha_torii::test_utils::enqueue_locally_signed_contract_deployment_with_permissions(
            &state,
            &queue,
            &creds.account,
            &creds.private_key,
            &program,
            std::iter::empty(),
            ["CanEnactGovernance"
                .parse()
                .expect("declared fixture permission")],
        );
    let contract_address = contract_address.to_string();
    let applied_deploy =
        iroha_torii::test_utils::apply_queued_in_one_block(&mut native_chain, &queue);
    assert_eq!(applied_deploy, 1);
    let missing_limit_payload = iroha_torii::json_object(vec![
        iroha_torii::json_entry("entrypoint", "main"),
        iroha_torii::json_entry("authority", creds.account.clone()),
        iroha_torii::json_entry("contract_address", contract_address.as_str()),
    ]);
    let missing_limit_body = json::to_json(&missing_limit_payload).expect("serialize call request");
    let missing_limit_req = http::Request::builder()
        .method("POST")
        .uri("/v1/contracts/call")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(missing_limit_body))
        .unwrap();
    let missing_limit_resp = app.request(missing_limit_req).await;
    assert_eq!(missing_limit_resp.status(), http::StatusCode::BAD_REQUEST);
    let missing_limit_bytes = missing_limit_resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert!(String::from_utf8_lossy(&missing_limit_bytes).contains("fee_payment"));
    let zero_limit_body = iroha_torii::test_utils::contract_call_request_json(
        &creds.account,
        contract_address.as_str(),
        iroha_torii::test_utils::ContractCallOptions {
            entrypoint: "main",
            payload: None,
            gas_limit: 0,
        },
    );
    let zero_limit_req = http::Request::builder()
        .method("POST")
        .uri("/v1/contracts/call")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(zero_limit_body))
        .unwrap();
    let zero_limit_resp = app.request(zero_limit_req).await;
    assert_eq!(zero_limit_resp.status(), http::StatusCode::BAD_REQUEST);
    let zero_limit_bytes = zero_limit_resp
        .into_body()
        .collect()
        .await
        .expect("zero-limit response body")
        .to_bytes();
    assert!(
        String::from_utf8_lossy(&zero_limit_bytes).contains("fee_payment.gas_limit is required")
    );
    let mut forbidden: json::Value =
        json::from_str(&iroha_torii::test_utils::contract_call_request_json(
            &creds.account,
            &contract_address,
            iroha_torii::test_utils::ContractCallOptions {
                entrypoint: "main",
                payload: None,
                gas_limit: 5_000,
            },
        ))
        .expect("unsigned public request");
    forbidden.as_object_mut().expect("request object").insert(
        "private_key".to_owned(),
        json::Value::String("forbidden-field-test-marker".to_owned()),
    );
    let forbidden_response = app
        .request(
            http::Request::builder()
                .method("POST")
                .uri("/v1/contracts/call")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    json::to_json(&forbidden).expect("forbidden-field request"),
                ))
                .expect("forbidden-field request"),
        )
        .await;
    assert_eq!(forbidden_response.status(), http::StatusCode::BAD_REQUEST);
    let forbidden_bytes = forbidden_response
        .into_body()
        .collect()
        .await
        .expect("forbidden-field response body")
        .to_bytes();
    assert!(String::from_utf8_lossy(&forbidden_bytes).contains("private_key"));
    assert_eq!(queue.active_len(), 0);
    let transaction_ttl_ms = 900_000_u64;
    let call_payload = iroha_torii::json_object(vec![
        iroha_torii::json_entry("authority", creds.account.clone()),
        iroha_torii::json_entry("contract_address", contract_address.as_str()),
        iroha_torii::json_entry("entrypoint", "main"),
        iroha_torii::json_entry("transaction_ttl_ms", transaction_ttl_ms),
        iroha_torii::json_entry(
            "fee_payment",
            FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(5_000)),
        ),
    ]);
    let call_body = json::to_json(&call_payload).expect("serialize call request");
    let prepared = prepare_contract_execution(&app, call_body).await;
    let call_json = &prepared.response;
    assert_eq!(
        call_json.get("ok").and_then(json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        call_json.get("dataspace").and_then(json::Value::as_str),
        Some("universal")
    );
    assert_eq!(
        call_json
            .get("contract_address")
            .and_then(json::Value::as_str),
        Some(contract_address.as_str())
    );
    assert_eq!(
        call_json.get("code_hash_hex").and_then(json::Value::as_str),
        Some(code_hash_hex.as_str())
    );
    assert_eq!(
        call_json.get("abi_hash_hex").and_then(json::Value::as_str),
        Some(abi_hash_hex.as_str())
    );
    assert_eq!(
        call_json
            .get("transaction_ttl_ms")
            .and_then(json::Value::as_u64),
        Some(transaction_ttl_ms)
    );
    assert_eq!(
        prepared.transaction.time_to_live(),
        Some(Duration::from_millis(transaction_ttl_ms))
    );
    assert_eq!(hex::encode(prepared.transaction.hash().as_ref()).len(), 64);
    let receipt = call_json
        .get("operation_receipt")
        .and_then(json::Value::as_object)
        .expect("contract call receipt");
    assert_eq!(
        receipt.get("operation_kind").and_then(json::Value::as_str),
        Some("contract_call")
    );
    assert_eq!(
        receipt.get("transport").and_then(json::Value::as_str),
        Some("torii")
    );
    assert_eq!(
        receipt.get("dataspace").and_then(json::Value::as_str),
        Some("universal")
    );
    assert_eq!(
        receipt
            .get("contract_address")
            .and_then(json::Value::as_str),
        Some(contract_address.as_str())
    );
    assert_eq!(
        receipt
            .get("payload_digest_hex")
            .and_then(json::Value::as_str)
            .map(str::len),
        Some(64)
    );
    assert!(receipt.get("tx_hash_hex").is_some_and(json::Value::is_null));
    assert!(
        receipt
            .get("entrypoint_hash_hex")
            .is_some_and(json::Value::is_null)
    );
    execute_prepared_contract_in_test_overlay(&state, &prepared, 3);

    app.shutdown().await;
}
#[tokio::test]
async fn contracts_view_omits_unverified_source_path_from_vm_diagnostic() {
    let (creds, state, kura, mut native_chain) = contract_test_state();
    let (queue, _chain_id, app) = contract_test_queue_and_app(&state, &kura, &creds);
    let source_path = "contracts/view_trap_test.ko";
    let program = contract_view_trap_program_with_source_path(source_path);
    let (contract_address, _, _) =
        iroha_torii::test_utils::enqueue_locally_signed_contract_deployment(
            &state,
            &queue,
            &creds.account,
            &creds.private_key,
            &program,
        );
    let contract_address = contract_address.to_string();
    let applied_deploy =
        iroha_torii::test_utils::apply_queued_in_one_block(&mut native_chain, &queue);
    assert_eq!(applied_deploy, 1);
    let (status, value) = run_contract_view_response_in_test_overlay(
        &app,
        &creds.account,
        &contract_address,
        "explode",
        None,
    )
    .await;
    assert_eq!(status, http::StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(value.get("ok").and_then(json::Value::as_bool), Some(false));
    assert_eq!(
        value.get("entrypoint").and_then(json::Value::as_str),
        Some("explode")
    );
    assert!(
        value
            .get("vm_diagnostic")
            .and_then(json::Value::as_object)
            .and_then(|diag| diag.get("source_path"))
            .is_some_and(json::Value::is_null),
        "deployable artifacts exclude compiler source maps; a verified hash-keyed sidecar is required"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn contracts_view_decodes_literal_and_persisted_bytes_returns() {
    let (creds, state, kura, mut native_chain) = contract_test_state();
    let (queue, _chain_id, app) = contract_test_queue_and_app(&state, &kura, &creds);
    let program = contract_view_bytes_program();
    let (contract_address, _, _) =
        iroha_torii::test_utils::enqueue_locally_signed_contract_deployment_with_permissions(
            &state,
            &queue,
            &creds.account,
            &creds.private_key,
            &program,
            std::iter::empty(),
            ["CanEnactGovernance"
                .parse()
                .expect("declared fixture permission")],
        );
    let contract_address = contract_address.to_string();
    let applied_deploy =
        iroha_torii::test_utils::apply_queued_in_one_block(&mut native_chain, &queue);
    assert_eq!(applied_deploy, 1);
    let asset_definition_id = "6qLb5RYJbzychndCXgFa9aZzjWyx"
        .parse::<AssetDefinitionId>()
        .expect("asset definition id");
    let init_payload = iroha_torii::json_object(vec![
        iroha_torii::json_entry("asset_input", asset_definition_id.to_string()),
        iroha_torii::json_entry(
            "target_bytes",
            "0x7269736b5f7661756c743a3a7269736b2e756e6976657273616c",
        ),
    ]);
    let hajimari_payload = iroha_torii::json_object(vec![iroha_torii::json_entry(
        "asset_input",
        asset_definition_id.to_string(),
    )]);
    run_contract_hajimari_in_test_overlay(
        &app,
        &state,
        &creds,
        contract_address.as_str(),
        Some(&hajimari_payload),
        3,
    )
    .await;
    let init_body = iroha_torii::test_utils::contract_call_request_json(
        &creds.account,
        contract_address.as_str(),
        iroha_torii::test_utils::ContractCallOptions {
            entrypoint: "configure",
            payload: Some(&init_payload),
            gas_limit: 1_500_000,
        },
    );
    let init_prepared = prepare_contract_execution(&app, init_body).await;
    execute_prepared_contract_in_test_overlay(&state, &init_prepared, 4);
    let literal =
        run_contract_view_in_test_overlay(&app, &creds.account, &contract_address, "literal", None)
            .await;
    assert_eq!(
        literal.get("result").and_then(json::Value::as_str),
        Some("0x7269736b")
    );
    let target =
        run_contract_view_in_test_overlay(&app, &creds.account, &contract_address, "target", None)
            .await;
    assert_eq!(
        target.get("result").and_then(json::Value::as_str),
        Some("0x7269736b5f7661756c743a3a7269736b2e756e6976657273616c")
    );
    let config =
        run_contract_view_in_test_overlay(&app, &creds.account, &contract_address, "config", None)
            .await;
    assert_eq!(
        config.get("result"),
        Some(&json::Value::Array(vec![
            json::Value::String(asset_definition_id.to_string()),
            json::Value::String(
                "0x7269736b5f7661756c743a3a7269736b2e756e6976657273616c".to_owned()
            ),
        ]))
    );
    app.shutdown().await;
}
#[tokio::test]
async fn contracts_call_honors_requested_entrypoint_and_payload() {
    let (creds, state, kura, mut native_chain) = contract_test_state();
    let (queue, _chain_id, app) = contract_test_queue_and_app(&state, &kura, &creds);
    let program = contract_call_dispatch_program();
    let (contract_address, _, _) =
        iroha_torii::test_utils::enqueue_locally_signed_contract_deployment_with_permissions(
            &state,
            &queue,
            &creds.account,
            &creds.private_key,
            &program,
            std::iter::empty(),
            ["CanEnactGovernance"
                .parse()
                .expect("declared fixture permission")],
        );
    let contract_address = contract_address.to_string();
    let applied_deploy =
        iroha_torii::test_utils::apply_queued_in_one_block(&mut native_chain, &queue);
    assert_eq!(applied_deploy, 1);
    let initial_asset_literal = "6qLb5RYJbzychndCXgFa9aZzjWyx";
    let asset_literal = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
    let hajimari_payload = norito::json!({ "asset_definition_id": initial_asset_literal });
    run_contract_hajimari_in_test_overlay(
        &app,
        &state,
        &creds,
        contract_address.as_str(),
        Some(&hajimari_payload),
        3,
    )
    .await;
    let payload = norito::json!({ "amount": "7" });
    let call_body = iroha_torii::test_utils::contract_call_request_json(
        &creds.account,
        contract_address.as_str(),
        iroha_torii::test_utils::ContractCallOptions {
            entrypoint: "credit_by_payload",
            payload: Some(&payload),
            gas_limit: 1_500_000,
        },
    );
    let call_prepared = prepare_contract_execution(&app, call_body).await;
    execute_prepared_contract_in_test_overlay(&state, &call_prepared, 4);
    let state_after_credit = run_contract_view_in_test_overlay(
        &app,
        &creds.account,
        contract_address.as_str(),
        "call_state",
        None,
    )
    .await;
    assert_eq!(
        state_after_credit.get("result"),
        Some(&json::Value::Array(vec![
            json::Value::String("7".to_owned()),
            json::Value::String(initial_asset_literal.to_owned()),
        ]))
    );
    let asset_payload = norito::json!({ "asset_definition_id": asset_literal });
    let asset_call_body = iroha_torii::test_utils::contract_call_request_json(
        &creds.account,
        contract_address.as_str(),
        iroha_torii::test_utils::ContractCallOptions {
            entrypoint: "record_asset_by_payload",
            payload: Some(&asset_payload),
            gas_limit: 1_500_000,
        },
    );
    let asset_call_prepared = prepare_contract_execution(&app, asset_call_body).await;
    execute_prepared_contract_in_test_overlay(&state, &asset_call_prepared, 5);
    let state_after_asset = run_contract_view_in_test_overlay(
        &app,
        &creds.account,
        contract_address.as_str(),
        "call_state",
        None,
    )
    .await;
    assert_eq!(
        state_after_asset.get("result"),
        Some(&json::Value::Array(vec![
            json::Value::String("7".to_owned()),
            json::Value::String(asset_literal.to_owned()),
        ]))
    );
    app.shutdown().await;
}
#[tokio::test]
async fn contracts_view_roundtrips_account_id_literals_and_persisted_state() {
    let (creds, state, kura, mut native_chain) = contract_test_state();
    let (queue, _chain_id, app) = contract_test_queue_and_app(&state, &kura, &creds);
    let program = contract_view_account_id_program();
    let (contract_address, _, _) =
        iroha_torii::test_utils::enqueue_locally_signed_contract_deployment_with_permissions(
            &state,
            &queue,
            &creds.account,
            &creds.private_key,
            &program,
            std::iter::empty(),
            ["CanEnactGovernance"
                .parse()
                .expect("declared fixture permission")],
        );
    let initial_account = contract_address.subject_id().to_string();
    let contract_address = contract_address.to_string();
    let applied_deploy =
        iroha_torii::test_utils::apply_queued_in_one_block(&mut native_chain, &queue);
    assert_eq!(applied_deploy, 1);
    let hajimari_payload = iroha_torii::json_object(vec![iroha_torii::json_entry(
        "account_id",
        initial_account.clone(),
    )]);
    let bind_payload = iroha_torii::json_object(vec![iroha_torii::json_entry(
        "account_id",
        creds.account.to_string(),
    )]);
    run_contract_hajimari_in_test_overlay(
        &app,
        &state,
        &creds,
        contract_address.as_str(),
        Some(&hajimari_payload),
        3,
    )
    .await;
    let literal =
        run_contract_view_in_test_overlay(&app, &creds.account, &contract_address, "literal", None)
            .await;
    assert_eq!(
        literal.get("result").and_then(json::Value::as_str),
        Some(creds.account.to_string().as_str())
    );
    let initialized =
        run_contract_view_in_test_overlay(&app, &creds.account, &contract_address, "stored", None)
            .await;
    assert_eq!(
        initialized.get("result").and_then(json::Value::as_str),
        Some(initial_account.as_str())
    );
    let bind_body = iroha_torii::test_utils::contract_call_request_json(
        &creds.account,
        contract_address.as_str(),
        iroha_torii::test_utils::ContractCallOptions {
            entrypoint: "bind",
            payload: Some(&bind_payload),
            gas_limit: 1_500_000,
        },
    );
    let bind_prepared = prepare_contract_execution(&app, bind_body).await;
    execute_prepared_contract_in_test_overlay(&state, &bind_prepared, 4);
    let stored =
        run_contract_view_in_test_overlay(&app, &creds.account, &contract_address, "stored", None)
            .await;
    assert_eq!(
        stored.get("result").and_then(json::Value::as_str),
        Some(creds.account.to_string().as_str())
    );
    let stored_tuple = run_contract_view_in_test_overlay(
        &app,
        &creds.account,
        &contract_address,
        "stored_tuple",
        None,
    )
    .await;
    assert_eq!(
        stored_tuple.get("result"),
        Some(&json::Value::Array(vec![
            json::Value::String(creds.account.to_string()),
            json::Value::String("1".to_owned()),
        ]))
    );
    app.shutdown().await;
}
#[tokio::test]
async fn contracts_call_configure_roundtrips_account_id_map_state() {
    let (creds, state, kura, mut native_chain) = contract_test_state();
    let (queue, _chain_id, app) = contract_test_queue_and_app(&state, &kura, &creds);
    let program = contract_call_configure_account_map_program();
    let (contract_address, _, _) =
        iroha_torii::test_utils::enqueue_locally_signed_contract_deployment_with_permissions(
            &state,
            &queue,
            &creds.account,
            &creds.private_key,
            &program,
            std::iter::empty(),
            ["CanEnactGovernance"
                .parse()
                .expect("declared fixture permission")],
        );
    let contract_address = contract_address.to_string();
    let applied_deploy =
        iroha_torii::test_utils::apply_queued_in_one_block(&mut native_chain, &queue);
    assert_eq!(applied_deploy, 1, "expected locally signed deployment");
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after epoch")
        .as_millis() as u64;
    let deploy_alias: iroha_data_model::smart_contract::ContractAlias =
        "fixture0::universal".parse().expect("deployment alias");
    let post_apply_view = state.view();
    let alias_target = post_apply_view
        .world
        .contract_address_by_alias_at(&deploy_alias, now_ms);
    let alias_active = alias_target.as_ref().is_some_and(|address| {
        post_apply_view
            .world
            .contract_instances()
            .get(address)
            .is_some()
    });
    assert!(
        alias_active,
        "post-apply alias state missing or inactive: alias_target={alias_target:?}"
    );
    let configure_payload = iroha_torii::json_object(vec![
        iroha_torii::json_entry("admin_account", creds.account.to_string()),
        iroha_torii::json_entry("inori_account", creds.account.to_string()),
    ]);
    let configure_body = iroha_torii::test_utils::contract_call_request_json(
        &creds.account,
        contract_address.as_str(),
        iroha_torii::test_utils::ContractCallOptions {
            entrypoint: "configure",
            payload: Some(&configure_payload),
            gas_limit: 1_500_000,
        },
    );
    let configure_prepared = prepare_contract_execution(&app, configure_body).await;
    execute_prepared_contract_in_test_overlay(&state, &configure_prepared, 3);
    let admin =
        run_contract_view_in_test_overlay(&app, &creds.account, &contract_address, "admin", None)
            .await;
    assert_eq!(
        admin.get("result").and_then(json::Value::as_str),
        Some(creds.account.to_string().as_str())
    );
    let inori =
        run_contract_view_in_test_overlay(&app, &creds.account, &contract_address, "inori", None)
            .await;
    assert_eq!(
        inori.get("result").and_then(json::Value::as_str),
        Some(creds.account.to_string().as_str())
    );
    let paused =
        run_contract_view_in_test_overlay(&app, &creds.account, &contract_address, "paused", None)
            .await;
    assert_eq!(
        paused.get("result").and_then(json::Value::as_str),
        Some("0")
    );
    app.shutdown().await;
}
#[tokio::test]
async fn contracts_call_persists_declared_state_fields_across_calls() {
    let (creds, state, kura, mut native_chain) = contract_test_state();
    let (queue, _chain_id, app) = contract_test_queue_and_app(&state, &kura, &creds);
    let program = contract_call_declared_state_program();
    let (contract_address, _, _) =
        iroha_torii::test_utils::enqueue_locally_signed_contract_deployment_with_permissions(
            &state,
            &queue,
            &creds.account,
            &creds.private_key,
            &program,
            std::iter::empty(),
            ["CanEnactGovernance"
                .parse()
                .expect("declared fixture permission")],
        );
    let contract_address = contract_address.to_string();
    let applied_deploy =
        iroha_torii::test_utils::apply_queued_in_one_block(&mut native_chain, &queue);
    assert_eq!(applied_deploy, 1);
    let initial_asset_literal = "6qLb5RYJbzychndCXgFa9aZzjWyx";
    let asset_literal = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
    let hajimari_payload = norito::json!({ "asset_definition_id": initial_asset_literal });
    run_contract_hajimari_in_test_overlay(
        &app,
        &state,
        &creds,
        contract_address.as_str(),
        Some(&hajimari_payload),
        3,
    )
    .await;
    let credit_payload = norito::json!({ "amount": "7" });
    let credit_body = iroha_torii::test_utils::contract_call_request_json(
        &creds.account,
        contract_address.as_str(),
        iroha_torii::test_utils::ContractCallOptions {
            entrypoint: "credit_by_payload",
            payload: Some(&credit_payload),
            gas_limit: 1_500_000,
        },
    );
    let credit_prepared = prepare_contract_execution(&app, credit_body).await;
    execute_prepared_contract_in_test_overlay(&state, &credit_prepared, 4);
    let asset_payload = norito::json!({ "asset_definition_id": asset_literal });
    let asset_body = iroha_torii::test_utils::contract_call_request_json(
        &creds.account,
        contract_address.as_str(),
        iroha_torii::test_utils::ContractCallOptions {
            entrypoint: "record_asset_by_payload",
            payload: Some(&asset_payload),
            gas_limit: 1_500_000,
        },
    );
    let asset_prepared = prepare_contract_execution(&app, asset_body).await;
    execute_prepared_contract_in_test_overlay(&state, &asset_prepared, 5);
    let view_json = run_contract_view_in_test_overlay(
        &app,
        &creds.account,
        contract_address.as_str(),
        "declared_state",
        None,
    )
    .await;
    let view_result = view_json
        .get("result")
        .and_then(json::Value::as_array)
        .expect("view result array");
    assert_eq!(
        view_result.first().and_then(json::Value::as_str),
        Some("7"),
        "unexpected declared amount from view",
    );
    assert_eq!(
        view_result.get(1).and_then(json::Value::as_str),
        Some(asset_literal),
        "unexpected declared asset from view",
    );
    app.shutdown().await;
}
#[tokio::test]
async fn contracts_call_persists_declared_state_after_emitting_isi() {
    let (creds, state, kura, mut native_chain) = contract_test_state();
    let (queue, _chain_id, app) = contract_test_queue_and_app(&state, &kura, &creds);
    let program = contract_call_declared_state_with_isi_program();
    let (contract_address, _, _) =
        iroha_torii::test_utils::enqueue_locally_signed_contract_deployment_with_permissions(
            &state,
            &queue,
            &creds.account,
            &creds.private_key,
            &program,
            [can_modify_account_metadata(&creds.account)],
            ["CanEnactGovernance"
                .parse()
                .expect("declared fixture permission")],
        );
    let contract_address = contract_address.to_string();
    let applied_deploy =
        iroha_torii::test_utils::apply_queued_in_one_block(&mut native_chain, &queue);
    assert_eq!(applied_deploy, 1);
    run_contract_hajimari_in_test_overlay(&app, &state, &creds, contract_address.as_str(), None, 3)
        .await;
    let write_payload = norito::json!({ "amount": "7" });
    let write_body = iroha_torii::test_utils::contract_call_request_json(
        &creds.account,
        contract_address.as_str(),
        iroha_torii::test_utils::ContractCallOptions {
            entrypoint: "write_with_isi",
            payload: Some(&write_payload),
            gas_limit: 1_500_000,
        },
    );
    let write_prepared = prepare_contract_execution(&app, write_body).await;
    execute_prepared_contract_in_test_overlay(&state, &write_prepared, 4);
    let view_json = run_contract_view_in_test_overlay(
        &app,
        &creds.account,
        contract_address.as_str(),
        "declared_state",
        None,
    )
    .await;
    assert_eq!(
        view_json
            .get("result")
            .and_then(json::Value::as_str)
            .expect("view int result"),
        "7"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn contracts_call_persists_declared_state_after_mint_asset() {
    let (creds, state, kura, mut native_chain) = contract_test_state();
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").expect("domain id"),
        "minted".parse().expect("asset definition name"),
    );
    let mut seed_block = state.block(iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(2).expect("height > 0"),
        None,
        None,
        0,
        0,
    ));
    let mut seed_tx = seed_block.transaction();
    iroha_data_model::prelude::Register::asset_definition(
        iroha_data_model::asset::AssetDefinition::numeric(
            asset_definition_id.clone(),
            "minted".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ),
    )
    .execute(&creds.account, &mut seed_tx)
    .expect("register asset definition");
    seed_tx.apply();
    seed_block
        .commit_world_overlay_for_testing()
        .expect("commit seeded asset definition");
    let (queue, _chain_id, app) = contract_test_queue_and_app(&state, &kura, &creds);
    let program = contract_call_declared_state_with_mint_program();
    let (contract_address, _, _) =
        iroha_torii::test_utils::enqueue_locally_signed_contract_deployment_with_permissions(
            &state,
            &queue,
            &creds.account,
            &creds.private_key,
            &program,
            [can_mint_asset_definition(&asset_definition_id)],
            ["CanEnactGovernance"
                .parse()
                .expect("declared fixture permission")],
        );
    let contract_address = contract_address.to_string();
    let applied_deploy =
        iroha_torii::test_utils::apply_queued_in_one_block(&mut native_chain, &queue);
    assert_eq!(applied_deploy, 1);
    run_contract_hajimari_in_test_overlay(&app, &state, &creds, contract_address.as_str(), None, 3)
        .await;
    let write_payload = iroha_torii::json_object(vec![
        iroha_torii::json_entry("amount", "7"),
        iroha_torii::json_entry("user", creds.account.clone()),
        iroha_torii::json_entry("asset_definition_id", asset_definition_id.to_string()),
    ]);
    let write_body = iroha_torii::test_utils::contract_call_request_json(
        &creds.account,
        contract_address.as_str(),
        iroha_torii::test_utils::ContractCallOptions {
            entrypoint: "write_with_mint",
            payload: Some(&write_payload),
            gas_limit: 1_500_000,
        },
    );
    let write_prepared = prepare_contract_execution(&app, write_body).await;
    execute_prepared_contract_in_test_overlay(&state, &write_prepared, 4);
    let view_json = run_contract_view_in_test_overlay(
        &app,
        &creds.account,
        contract_address.as_str(),
        "declared_state",
        None,
    )
    .await;
    assert_eq!(
        view_json
            .get("result")
            .and_then(json::Value::as_str)
            .expect("view int result"),
        "7"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn contracts_call_persists_n3x_like_state_after_mint_asset() {
    let (creds, state, kura, mut native_chain) = contract_test_state();
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").expect("domain id"),
        "n3x_like".parse().expect("asset definition name"),
    );
    let mut seed_block = state.block(iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(2).expect("height > 0"),
        None,
        None,
        0,
        0,
    ));
    let mut seed_tx = seed_block.transaction();
    iroha_data_model::prelude::Register::asset_definition(
        iroha_data_model::asset::AssetDefinition::numeric(
            asset_definition_id.clone(),
            "n3x_like".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ),
    )
    .execute(&creds.account, &mut seed_tx)
    .expect("register asset definition");
    seed_tx.apply();
    seed_block
        .commit_world_overlay_for_testing()
        .expect("commit seeded asset definition");
    let (queue, _chain_id, app) = contract_test_queue_and_app(&state, &kura, &creds);
    let program = contract_call_n3x_like_program();
    let (contract_address, _, _) =
        iroha_torii::test_utils::enqueue_locally_signed_contract_deployment_with_permissions(
            &state,
            &queue,
            &creds.account,
            &creds.private_key,
            &program,
            [can_mint_asset_definition(&asset_definition_id)],
            ["CanEnactGovernance"
                .parse()
                .expect("declared fixture permission")],
        );
    let contract_address = contract_address.to_string();
    let applied_deploy =
        iroha_torii::test_utils::apply_queued_in_one_block(&mut native_chain, &queue);
    assert_eq!(applied_deploy, 1);
    run_contract_hajimari_in_test_overlay(&app, &state, &creds, contract_address.as_str(), None, 3)
        .await;
    let init_body = iroha_torii::test_utils::contract_call_request_json(
        &creds.account,
        contract_address.as_str(),
        iroha_torii::test_utils::ContractCallOptions {
            entrypoint: "init_hub",
            payload: None,
            gas_limit: 10_000,
        },
    );
    let init_prepared = prepare_contract_execution(&app, init_body).await;
    execute_prepared_contract_in_test_overlay(&state, &init_prepared, 4);
    let deposit_payload = iroha_torii::json_object(vec![
        iroha_torii::json_entry("user", creds.account.clone()),
        iroha_torii::json_entry("asset_definition_id", asset_definition_id.to_string()),
        iroha_torii::json_entry("usdt_in", "1"),
        iroha_torii::json_entry("usdc_in", "2"),
        iroha_torii::json_entry("kusd_in", "3"),
    ]);
    let deposit_body = iroha_torii::test_utils::contract_call_request_json(
        &creds.account,
        contract_address.as_str(),
        iroha_torii::test_utils::ContractCallOptions {
            entrypoint: "deposit_like",
            payload: Some(&deposit_payload),
            gas_limit: 1_500_000,
        },
    );
    let deposit_prepared = prepare_contract_execution(&app, deposit_body).await;
    execute_prepared_contract_in_test_overlay(&state, &deposit_prepared, 5);
    let view_json = run_contract_view_in_test_overlay(
        &app,
        &creds.account,
        contract_address.as_str(),
        "state_snapshot",
        None,
    )
    .await;
    let snapshot = view_json
        .get("result")
        .and_then(json::Value::as_array)
        .expect("state snapshot array");
    assert_eq!(snapshot.first().and_then(json::Value::as_str), Some("1"));
    assert_eq!(snapshot.get(1).and_then(json::Value::as_str), Some("1"));
    assert_eq!(snapshot.get(2).and_then(json::Value::as_str), Some("2"));
    assert_eq!(snapshot.get(3).and_then(json::Value::as_str), Some("3"));
    assert_eq!(snapshot.get(4).and_then(json::Value::as_str), Some("6"));
    app.shutdown().await;
}
#[tokio::test]
async fn contracts_call_executes_n3x_like_burn_after_mint_asset() {
    let (creds, state, kura, mut native_chain) = contract_test_state();
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").expect("domain id"),
        "n3x_burn".parse().expect("asset definition name"),
    );
    let mut seed_block = state.block(iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(2).expect("height > 0"),
        None,
        None,
        0,
        0,
    ));
    let mut seed_tx = seed_block.transaction();
    iroha_data_model::prelude::Register::asset_definition(
        iroha_data_model::asset::AssetDefinition::numeric(
            asset_definition_id.clone(),
            "n3x_burn".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ),
    )
    .execute(&creds.account, &mut seed_tx)
    .expect("register asset definition");
    seed_tx.apply();
    seed_block
        .commit_world_overlay_for_testing()
        .expect("commit seeded asset definition");
    let (queue, _chain_id, app) = contract_test_queue_and_app(&state, &kura, &creds);
    let program = contract_call_n3x_like_program();
    let (contract_address, _, _) =
        iroha_torii::test_utils::enqueue_locally_signed_contract_deployment_with_permissions(
            &state,
            &queue,
            &creds.account,
            &creds.private_key,
            &program,
            [
                can_mint_asset_definition(&asset_definition_id),
                can_burn_asset_definition(&asset_definition_id),
            ],
            ["CanEnactGovernance"
                .parse()
                .expect("declared fixture permission")],
        );
    let contract_address = contract_address.to_string();
    let applied_deploy =
        iroha_torii::test_utils::apply_queued_in_one_block(&mut native_chain, &queue);
    assert_eq!(applied_deploy, 1);
    run_contract_hajimari_in_test_overlay(&app, &state, &creds, contract_address.as_str(), None, 3)
        .await;
    let init_body = iroha_torii::test_utils::contract_call_request_json(
        &creds.account,
        contract_address.as_str(),
        iroha_torii::test_utils::ContractCallOptions {
            entrypoint: "init_hub",
            payload: None,
            gas_limit: 10_000,
        },
    );
    let init_prepared = prepare_contract_execution(&app, init_body).await;
    execute_prepared_contract_in_test_overlay(&state, &init_prepared, 4);
    let deposit_payload = iroha_torii::json_object(vec![
        iroha_torii::json_entry("user", creds.account.clone()),
        iroha_torii::json_entry("asset_definition_id", asset_definition_id.to_string()),
        iroha_torii::json_entry("usdt_in", "1"),
        iroha_torii::json_entry("usdc_in", "2"),
        iroha_torii::json_entry("kusd_in", "3"),
    ]);
    let deposit_body = iroha_torii::test_utils::contract_call_request_json(
        &creds.account,
        contract_address.as_str(),
        iroha_torii::test_utils::ContractCallOptions {
            entrypoint: "deposit_like",
            payload: Some(&deposit_payload),
            gas_limit: 1_500_000,
        },
    );
    let deposit_prepared = prepare_contract_execution(&app, deposit_body).await;
    execute_prepared_contract_in_test_overlay(&state, &deposit_prepared, 5);
    let burn_payload = iroha_torii::json_object(vec![
        iroha_torii::json_entry("user", creds.account.clone()),
        iroha_torii::json_entry("asset_definition_id", asset_definition_id.to_string()),
        iroha_torii::json_entry("n3x_amount", "6"),
    ]);
    let burn_body = iroha_torii::test_utils::contract_call_request_json(
        &creds.account,
        contract_address.as_str(),
        iroha_torii::test_utils::ContractCallOptions {
            entrypoint: "burn_like",
            payload: Some(&burn_payload),
            gas_limit: 1_500_000,
        },
    );
    let burn_prepared = prepare_contract_execution(&app, burn_body).await;
    execute_prepared_contract_in_test_overlay(&state, &burn_prepared, 6);
    let view_json = run_contract_view_in_test_overlay(
        &app,
        &creds.account,
        contract_address.as_str(),
        "state_snapshot",
        None,
    )
    .await;
    let snapshot = view_json
        .get("result")
        .and_then(json::Value::as_array)
        .expect("state snapshot array");
    assert_eq!(snapshot.first().and_then(json::Value::as_str), Some("1"));
    assert_eq!(snapshot.get(1).and_then(json::Value::as_str), Some("0"));
    assert_eq!(snapshot.get(2).and_then(json::Value::as_str), Some("0"));
    assert_eq!(snapshot.get(3).and_then(json::Value::as_str), Some("0"));
    assert_eq!(snapshot.get(4).and_then(json::Value::as_str), Some("0"));
    app.shutdown().await;
}
