//! Sponsored account-onboarding clean-break contract tests.
#![cfg(feature = "app_api")]
use axum::{
    body::{Body, to_bytes},
    extract::connect_info::ConnectInfo,
    http::{Request, header},
};
use http::StatusCode;
use iroha_core::{
    governance::manifest::LaneManifestRegistry,
    kura::Kura,
    query::store::LiveQueryStore,
    queue::Queue,
    state::{LaneAuthorityRoute, State, StateReadOnly, World, WorldReadOnly},
    tx::TransactionBuilder,
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    NetworkId, Registrable,
    account::{AccountAddress, AccountId},
    asset::{AssetDefinitionId, AssetId},
    isi::{ActivatePublicLaneValidator, RegisterPublicLaneValidator},
    level::Level,
    nexus::PublicLaneMonetaryPlanV1,
    parameter::{Parameter, system::SumeragiNposParameters},
    permission::Permission,
    prelude::{Account, Asset, AssetDefinition, Domain, Log},
    sns::{NameControllerV1, NameRecordV1},
};
use iroha_executor_data_model::permission::account::{
    AccountAliasPermissionScope, CanManageAccountAlias,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::peer::PeerId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_primitives::{json::Json, numeric::Quantity};
use iroha_torii::{json_entry, json_object};
use iroha_torii_shared::{
    AccountOnboardingCurrentStateResponseV1,
    route_catalog::{
        AuthenticationPolicy, CATALOGED_ROUTES,
        application_api::{
            ACCOUNTS_ONBOARD_PLAN_POST, ACCOUNTS_ONBOARD_POST, ACCOUNTS_ONBOARD_PREPARE_POST,
            ACCOUNTS_ONBOARDING_CURRENT_STATE_POST, ACCOUNTS_ONBOARDING_READINESS_GET,
        },
    },
};
use std::{
    collections::BTreeSet,
    num::NonZeroU8,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[path = "fixtures.rs"]
mod fixtures;
const ONBOARDING_API_TOKEN: &str = "torii-onboarding-test-token-32-bytes";
const ONBOARDING_WRONG_SCOPE_API_TOKEN: &str = "torii-onboarding-wrong-scope-token";
const ONBOARDING_SIGNER_PATH: &str = "/runtime-only/onboarding-test-signer.key";
static ONBOARDING_TORII_INIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
struct OnboardingTestContext {
    native_chain: parking_lot::Mutex<iroha_core::sumeragi::test_chain::CertifiedTestChain>,
    app: iroha_torii::TestApiRouterRuntime,
    state: Arc<State>,
    queue: Arc<Queue>,
    chain_id: iroha_model_base::chain::ChainId,
    _data_dir: tempfile::TempDir,
}
impl OnboardingTestContext {
    async fn shutdown(self) {
        self.app.shutdown().await;
    }
}
struct JsonResponse {
    status: StatusCode,
    raw_body: String,
    payload: norito::json::Value,
}
fn checked_key_pair(seed: u8, algorithm: Algorithm, context: &str) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], algorithm)
        .unwrap_or_else(|error| panic!("{context}: {error}"))
}
fn install_account_alias_policy(
    world: &mut World,
    authority: &AccountId,
    payment_asset_id: &AssetDefinitionId,
) {
    let mut policy = iroha_data_model::sns::fixtures::default_policy();
    policy.suffix_id = iroha_data_model::sns::ACCOUNT_ALIAS_SUFFIX_ID;
    "account-alias".clone_into(&mut policy.suffix);
    policy.steward = authority.clone();
    policy.fund_splitter_account = authority.clone();
    policy.payment_asset_id = payment_asset_id.to_string();
    for tier in &mut policy.pricing {
        r"^[a-z0-9_@.-]{3,255}$".clone_into(&mut tier.label_regex);
        tier.base_price
            .asset_id
            .clone_from(&policy.payment_asset_id);
    }
    world.smart_contract_state_mut_for_testing().insert(
        iroha_core::sns::policy_storage_key(iroha_data_model::sns::ACCOUNT_ALIAS_SUFFIX_ID),
        norito::codec::Encode::encode(&policy),
    );
}
fn install_universal_parent_lease(world: &mut World, authority: &AccountId) {
    let selector =
        iroha_core::sns::selector_for_dataspace_alias("universal").expect("universal selector");
    let controller = NameControllerV1::account(
        &AccountAddress::from_account_id(authority).expect("onboarding authority address"),
    );
    let mut metadata = iroha_model_base::metadata::Metadata::default();
    metadata.insert(
        iroha_core::sns::SNS_DATASPACE_ID_METADATA_KEY
            .parse()
            .expect("dataspace metadata key"),
        Json::new(DataSpaceId::UNIVERSAL.as_u64()),
    );
    let record = NameRecordV1::new(
        selector.clone(),
        authority.clone(),
        vec![controller],
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        metadata,
    );
    world.smart_contract_state_mut_for_testing().insert(
        iroha_core::sns::record_storage_key(&selector),
        norito::codec::Encode::encode(&record),
    );
}
fn build_onboarding_test_context() -> OnboardingTestContext {
    build_onboarding_test_context_with(0xA1, 0xD1)
}
fn build_onboarding_test_context_with(
    genesis_discriminator: u8,
    onboarding_signer_seed: u8,
) -> OnboardingTestContext {
    build_onboarding_test_context_at(
        genesis_discriminator,
        onboarding_signer_seed,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time"),
    )
}
fn build_onboarding_test_context_at(
    genesis_discriminator: u8,
    onboarding_signer_seed: u8,
    anchor_time: Duration,
) -> OnboardingTestContext {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let data_dir = tempfile::tempdir().expect("create isolated onboarding Torii data directory");
    cfg.torii.sorafs_storage.data_dir = data_dir.path().join("sorafs");
    let _kura = Kura::blank_kura_for_testing();
    let _query = LiveQueryStore::start_test();
    let validator_keys: Vec<_> = (0xD2..=0xD5)
        .map(|seed| checked_key_pair(seed, Algorithm::BlsNormal, "derive onboarding validator"))
        .collect();
    cfg.common.key_pair = validator_keys[0].clone();
    let local_peer_id = PeerId::new(cfg.common.key_pair.public_key().clone());
    // Genesis custody is independent of the currently configured service signer.
    // Both eligible authorities are registered and funded in the same original genesis.
    let authority_key_pair = checked_key_pair(0xD1, Algorithm::Ed25519, "genesis authority");
    let alternate_key_pair = checked_key_pair(0xE1, Algorithm::Ed25519, "alternate service signer");
    let alternate_id = AccountId::new(alternate_key_pair.public_key().clone());
    let authority_id = AccountId::new(authority_key_pair.public_key().clone());
    let fee_domain = DomainId::try_new("universal", "universal").expect("fee domain");
    let fee_asset_id: AssetDefinitionId =
        iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
            .parse()
            .expect("default fee asset id");
    let domain = Domain::new(fee_domain).build(&authority_id);
    let authority = Account::new(authority_id.clone()).build(&authority_id);
    let fee_definition = AssetDefinition::numeric(
        fee_asset_id.clone(),
        "XOR".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority_id);
    let fee_asset = Asset::new(
        AssetId::of(fee_asset_id.clone(), authority_id.clone()),
        Quantity::from(100_u32),
    );
    let mut accounts = vec![
        authority,
        Account::new(alternate_id.clone()).build(&authority_id),
    ];
    accounts.extend(validator_keys.iter().map(|key_pair| {
        let account_id = AccountId::new(key_pair.public_key().clone());
        Account::new(account_id.clone()).build(&account_id)
    }));
    let staking = iroha_config::parameters::actual::NexusStaking::default();
    let stake_asset_id: AssetDefinitionId = staking.stake_asset_id.parse().expect("stake asset");
    let stake_domain = Domain::new(DomainId::try_new("nexus", "universal").expect("stake domain"))
        .build(&authority_id);
    let stake_definition = AssetDefinition::numeric(
        stake_asset_id.clone(),
        "Staked XOR".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority_id);
    let escrow_id =
        AccountId::parse_encoded(&staking.stake_escrow_account_id).expect("canonical stake escrow");
    accounts.push(Account::new(escrow_id.clone()).build(&escrow_id));
    let mut assets = vec![
        fee_asset,
        Asset::new(
            AssetId::of(fee_asset_id.clone(), alternate_id.clone()),
            Quantity::from(100_u32),
        ),
    ];
    assets.extend(validator_keys.iter().map(|key_pair| {
        Asset::new(
            AssetId::new(
                stake_asset_id.clone(),
                AccountId::new(key_pair.public_key().clone()),
            ),
            Quantity::from(1_000_u32),
        )
    }));
    let mut world = World::with_assets(
        [domain, stake_domain],
        accounts,
        [fee_definition, stake_definition],
        assets,
        [],
    );
    {
        let mut block = world.block();
        block
            .parameters
            .get_mut()
            .set_parameter(Parameter::Custom(
                SumeragiNposParameters::default().into_custom_parameter(),
            ))
            .expect("valid default consensus parameters");
        block.commit();
    }
    install_account_alias_policy(&mut world, &authority_id, &fee_asset_id);
    install_universal_parent_lease(&mut world, &authority_id);
    for permitted in [authority_id.clone(), alternate_id] {
        world.account_permissions_mut_for_testing().insert(
            permitted,
            BTreeSet::from([Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Dataspace(DataSpaceId::UNIVERSAL),
            })]),
        );
    }
    let chain_id = iroha_model_base::chain::ChainId::from("onboarding-test-chain");
    let mut genesis_instructions: Vec<iroha_data_model::prelude::InstructionBox> = vec![
        Log::new(
            Level::INFO,
            format!("onboarding anchor {genesis_discriminator}"),
        )
        .into(),
    ];
    for key_pair in &validator_keys {
        let validator = AccountId::new(key_pair.public_key().clone());
        // Authenticate and execute validator rows, bonded shares, escrow, and
        // quantity-ledger mutations together in the signed genesis transaction.
        genesis_instructions.push(
            RegisterPublicLaneValidator {
                lane_id: LaneId::SINGLE,
                validator: validator.clone(),
                peer_id: PeerId::new(key_pair.public_key().clone()),
                stake_account: validator.clone(),
                initial_stake: Quantity::from(1_000_u32),
                metadata: iroha_model_base::metadata::Metadata::default(),
                monetary_plan: PublicLaneMonetaryPlanV1::genesis_registration(
                    AssetId::new(stake_asset_id.clone(), validator.clone()),
                    AssetId::new(stake_asset_id.clone(), escrow_id.clone()),
                    Quantity::from(1_000_u32),
                ),
            }
            .into(),
        );
        genesis_instructions.push(
            ActivatePublicLaneValidator {
                lane_id: LaneId::SINGLE,
                validator,
            }
            .into(),
        );
    }
    let chain = fixtures::commit_genesis_fixture(
        world,
        chain_id.clone(),
        &authority_key_pair,
        genesis_instructions,
        Some(validator_keys),
        iroha_primitives::time::TimeSource::new_fixed(anchor_time),
    );
    let state = chain.state().clone();
    let kura = chain.kura().clone();
    let _network_id = chain.network_id();
    let nexus = state.nexus_snapshot();
    let lane_manifests = Arc::new(LaneManifestRegistry::from_config(
        &nexus.lane_catalog,
        &nexus.governance,
        &nexus.registry,
    ));
    state.install_lane_manifests_for_testing(&lane_manifests);
    let committee = state
        .resolve_lane_committee(LaneAuthorityRoute::new(
            LaneId::SINGLE,
            DataSpaceId::UNIVERSAL,
        ))
        .expect("committed fixture must resolve real lane authority");
    assert_eq!(committee.validators().len(), 4);
    assert!(committee.validators().contains(&local_peer_id));
    let service_signer = checked_key_pair(
        onboarding_signer_seed,
        Algorithm::Ed25519,
        "active onboarding signer",
    );
    cfg.torii.account_onboarding = Some(iroha_config::parameters::actual::AccountOnboarding {
        authority: AccountId::new(service_signer.public_key().clone()),
        private_key_file: ONBOARDING_SIGNER_PATH.into(),
        signer: service_signer,
        credentials: vec![
            iroha_config::parameters::actual::AccountOnboardingCredential {
                id: "local-test".parse().expect("credential id"),
                scope:
                    iroha_config::parameters::actual::AccountOnboardingCredentialScope::Dataspace(
                        "universal".parse().expect("universal dataspace name"),
                    ),
                token_hash: *blake3::hash(ONBOARDING_API_TOKEN.as_bytes()).as_bytes(),
            },
            iroha_config::parameters::actual::AccountOnboardingCredential {
                id: "wrong-scope-test".parse().expect("credential id"),
                scope: iroha_config::parameters::actual::AccountOnboardingCredentialScope::Domain(
                    DomainId::try_new("restricted", "universal")
                        .expect("restricted fixture domain"),
                ),
                token_hash: *blake3::hash(ONBOARDING_WRONG_SCOPE_API_TOKEN.as_bytes()).as_bytes(),
            },
        ],
        additional_permissions: Vec::new(),
        fee_sponsor_program_id: None,
        lease_term_years: NonZeroU8::new(1).expect("non-zero lease term"),
        auto_renew: None,
    });
    let events_sender: iroha_core::EventsSender = tokio::sync::broadcast::channel(1).0;
    let queue = Arc::new(Queue::from_config(
        iroha_config::parameters::actual::Queue::default(),
        events_sender,
    ));
    queue.install_lane_manifests_with_state_for_testing(&lane_manifests, &state);
    // Embedded SoraFS checkpoint stores intentionally fail fast when any writer is opening in
    // this process. Keep distinct fixture roots, but serialize only their short initialization.
    let init_guard = ONBOARDING_TORII_INIT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let torii = fixtures::ToriiHarness::new(
        &cfg,
        &kura,
        &state,
        &queue,
        &local_peer_id,
        tokio::sync::broadcast::channel(1).0,
        iroha_config::parameters::actual::TelemetryProfile::Operator,
    );
    drop(init_guard);
    OnboardingTestContext {
        native_chain: parking_lot::Mutex::new(chain),
        app: torii.router(),
        state,
        queue,
        chain_id,
        _data_dir: data_dir,
    }
}

fn onboarding_plan_request(alias: &str, account_id: &AccountId) -> norito::json::Value {
    json_object(vec![
        json_entry("version", 1_u64),
        json_entry("alias", alias),
        json_entry("account_id", account_id.to_string()),
        json_entry("permissions", Vec::<String>::new()),
    ])
}
fn onboarding_current_state_request(alias: &str, account_id: &AccountId) -> norito::json::Value {
    json_object(vec![
        json_entry("version", 1_u64),
        json_entry("account_id", account_id.to_string()),
        json_entry("alias", alias),
    ])
}
fn mutation_binding(
    kind: &str,
    semantic_hash_hex: &str,
    expires_at_unix_ms: u64,
) -> norito::json::Value {
    json_object(vec![
        json_entry("schema", "iroha.prepared-operation.binding.v1"),
        json_entry("semantic_hash_hex", semantic_hash_hex),
        json_entry("kind", kind),
        json_entry("request_id", "22".repeat(32)),
        json_entry("execution_expires_at_unix_ms", expires_at_unix_ms),
    ])
}
fn onboarding_prepare_request(receipt: norito::json::Value) -> norito::json::Value {
    onboarding_prepare_request_with_expiry(receipt, u64::MAX)
}
fn onboarding_prepare_request_with_expiry(
    receipt: norito::json::Value,
    expires_at_unix_ms: u64,
) -> norito::json::Value {
    let plan_hash: iroha_crypto::Hash =
        norito::json::from_value(receipt["plan_hash"].clone()).expect("typed plan hash");
    let semantic_hash_hex = hex::encode(plan_hash.as_ref());
    json_object(vec![
        json_entry("schema", "iroha.accounts.onboard.prepare.v1"),
        json_entry(
            "binding",
            mutation_binding(
                "onboarding",
                &semantic_hash_hex,
                expires_at_unix_ms.min(
                    receipt["body"]["valid_until_ms"]
                        .as_u64()
                        .expect("receipt deadline"),
                ),
            ),
        ),
        json_entry(
            "fee_payment",
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        ),
        json_entry("receipt", receipt),
    ])
}
fn onboarding_http_request(
    path: &str,
    payload: &norito::json::Value,
    token: Option<&str>,
) -> Request<Body> {
    let body = norito::json::to_json(payload).expect("serialize onboarding request");
    assert!(!body.contains(ONBOARDING_API_TOKEN));
    assert!(!body.contains("private_key"));
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json");
    if let Some(token) = token {
        builder = builder.header("x-iroha-onboarding-token", token);
    }
    let mut request = builder.body(Body::from(body)).expect("onboarding request");
    request
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            8080,
        ))));
    request
}
async fn send_onboarding_request(
    app: &axum::Router,
    path: &str,
    payload: &norito::json::Value,
) -> JsonResponse {
    send_onboarding_request_with_token(app, path, payload, ONBOARDING_API_TOKEN).await
}
async fn send_onboarding_request_with_token(
    app: &axum::Router,
    path: &str,
    payload: &norito::json::Value,
    token: &str,
) -> JsonResponse {
    let response = fixtures::request(app, onboarding_http_request(path, payload, Some(token)))
        .await
        .expect("onboarding route response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read onboarding response");
    let raw_body = String::from_utf8(bytes.to_vec()).expect("onboarding response is UTF-8 JSON");
    let payload = norito::json::from_str(&raw_body)
        .unwrap_or_else(|error| panic!("decode onboarding response: {error}; body={raw_body}"));
    JsonResponse {
        status,
        raw_body,
        payload,
    }
}
fn response_field<'a>(payload: &'a norito::json::Value, field: &str) -> &'a str {
    payload
        .as_object()
        .and_then(|object| object.get(field))
        .and_then(norito::json::Value::as_str)
        .unwrap_or_else(|| panic!("response is missing string field `{field}`: {payload:?}"))
}
fn disposition_kind(payload: &norito::json::Value) -> &str {
    payload
        .as_object()
        .and_then(|object| object.get("disposition"))
        .and_then(norito::json::Value::as_object)
        .and_then(|disposition| disposition.get("kind"))
        .and_then(norito::json::Value::as_str)
        .unwrap_or_else(|| panic!("response is missing a typed disposition: {payload:?}"))
}
fn plan_disposition_kind(receipt: &norito::json::Value) -> &str {
    receipt
        .as_object()
        .and_then(|receipt| receipt.get("body"))
        .and_then(norito::json::Value::as_object)
        .and_then(|body| body.get("resource"))
        .and_then(norito::json::Value::as_object)
        .and_then(|resource| resource.get("disposition"))
        .and_then(norito::json::Value::as_object)
        .and_then(|disposition| disposition.get("kind"))
        .and_then(norito::json::Value::as_str)
        .unwrap_or_else(|| panic!("plan is missing a typed disposition: {receipt:?}"))
}
fn mutate_onboarding_receipt_body(
    receipt: &norito::json::Value,
    mutate: impl FnOnce(&mut norito::json::Map),
) -> norito::json::Value {
    let mut mutated = receipt.clone();
    let body = mutated
        .as_object_mut()
        .and_then(|receipt| receipt.get_mut("body"))
        .and_then(norito::json::Value::as_object_mut)
        .expect("onboarding plan body object");
    mutate(body);
    mutated
}
fn assert_secret_free(response: &JsonResponse) {
    for forbidden in [
        ONBOARDING_API_TOKEN,
        ONBOARDING_SIGNER_PATH,
        "private_key",
        "private_key_file",
    ] {
        assert!(
            !response.raw_body.contains(forbidden),
            "onboarding response leaked `{forbidden}`: {}",
            response.raw_body
        );
    }
}
#[test]
fn sponsored_onboarding_catalog_contains_plan_prepare_submit_and_readiness() {
    for route in [
        ACCOUNTS_ONBOARD_PLAN_POST,
        ACCOUNTS_ONBOARD_PREPARE_POST,
        ACCOUNTS_ONBOARD_POST,
        ACCOUNTS_ONBOARDING_READINESS_GET,
    ] {
        assert_eq!(
            route.authentication(),
            AuthenticationPolicy::OnboardingToken,
            "{} must use the dedicated onboarding credential",
            route.stable_route_id()
        );
    }
    assert_eq!(
        ACCOUNTS_ONBOARDING_CURRENT_STATE_POST.authentication(),
        AuthenticationPolicy::ToriiDefault,
        "the atomic current-state read must use ordinary conditional Torii authentication"
    );
    for removed in [
        "/v1/accounts/onboard/multisig",
        "/v1/accounts/onboard/renew",
        "/v1/accounts/onboard/auto-renew",
    ] {
        assert!(
            CATALOGED_ROUTES.iter().all(|route| route.path() != removed),
            "removed onboarding route must not be cataloged: {removed}"
        );
    }
}
#[tokio::test]
async fn sponsored_onboarding_receipt_binds_exact_network_and_active_signer() {
    let anchor_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time");
    let origin = build_onboarding_test_context_at(0xA1, 0xD1, anchor_time);
    let foreign_genesis = build_onboarding_test_context_at(0xA2, 0xD1, anchor_time);
    let rotated_signer = build_onboarding_test_context_at(0xA1, 0xE1, anchor_time);
    let local_network = *origin.state.network_id_ref();
    assert_ne!(local_network, *foreign_genesis.state.network_id_ref());
    assert_eq!(local_network, *rotated_signer.state.network_id_ref());
    assert_eq!(origin.chain_id, foreign_genesis.chain_id);
    assert_eq!(origin.chain_id, rotated_signer.chain_id);
    let target = AccountId::new(
        checked_key_pair(
            0xD3,
            Algorithm::Ed25519,
            "derive cross-network onboarding target fixture",
        )
        .public_key()
        .clone(),
    );
    let plan = send_onboarding_request(
        &origin.app,
        "/v1/accounts/onboard/plan",
        &onboarding_plan_request("networkbound@universal", &target),
    )
    .await;
    assert_eq!(plan.status, StatusCode::OK, "{}", plan.raw_body);
    let body = plan
        .payload
        .as_object()
        .and_then(|receipt| receipt.get("body"))
        .and_then(norito::json::Value::as_object)
        .expect("onboarding plan body");
    let receipt_network: NetworkId =
        norito::json::from_value(body.get("network_id").expect("receipt network id").clone())
            .expect("canonical receipt network id");
    assert_eq!(receipt_network, local_network);
    for retired in ["chain", "chainId", "chain_id"] {
        assert!(!body.contains_key(retired));
    }
    let prepare = onboarding_prepare_request(plan.payload.clone());
    for (context, replay) in [
        (&foreign_genesis, "same-label foreign-genesis"),
        (&rotated_signer, "retired onboarding signer"),
    ] {
        let response =
            send_onboarding_request(&context.app, "/v1/accounts/onboard/prepare", &prepare).await;
        assert_eq!(
            response.status,
            StatusCode::CONFLICT,
            "{replay} replay escaped: {}",
            response.raw_body
        );
        assert_eq!(response_field(&response.payload, "code"), "conflict");
        assert_eq!(context.queue.active_len(), 0);
    }
    origin.shutdown().await;
    foreign_genesis.shutdown().await;
    rotated_signer.shutdown().await;
}
#[tokio::test]
async fn sponsored_onboarding_receipt_rejects_genesis_and_retired_network_keys() {
    let context = build_onboarding_test_context();
    let target = AccountId::new(
        checked_key_pair(
            0xD7,
            Algorithm::Ed25519,
            "derive onboarding receipt schema target fixture",
        )
        .public_key()
        .clone(),
    );
    let plan = send_onboarding_request(
        &context.app,
        "/v1/accounts/onboard/plan",
        &onboarding_plan_request("schemabound@universal", &target),
    )
    .await;
    assert_eq!(plan.status, StatusCode::OK, "{}", plan.raw_body);
    let genesis = mutate_onboarding_receipt_body(&plan.payload, |body| {
        body.insert(
            "network_id".to_owned(),
            norito::json::Value::String("genesis".to_owned()),
        );
    });
    let response = send_onboarding_request(
        &context.app,
        "/v1/accounts/onboard/prepare",
        &onboarding_prepare_request(genesis),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.raw_body
    );
    for retired in ["chain", "chainId", "chain_id"] {
        for keep_network_id in [false, true] {
            let mutated = mutate_onboarding_receipt_body(&plan.payload, |body| {
                if !keep_network_id {
                    body.remove("network_id");
                }
                body.insert(
                    retired.to_owned(),
                    norito::json::Value::String(context.chain_id.to_string()),
                );
            });
            let response = send_onboarding_request(
                &context.app,
                "/v1/accounts/onboard/prepare",
                &onboarding_prepare_request(mutated),
            )
            .await;
            assert_eq!(
                response.status,
                StatusCode::BAD_REQUEST,
                "retired key {retired} (keep_network_id={keep_network_id}) escaped: {}",
                response.raw_body
            );
        }
    }
    assert_eq!(context.queue.active_len(), 0);
    context.shutdown().await;
}

#[tokio::test]
async fn sponsored_onboarding_submit_rejects_old_and_tampered_envelopes() {
    let context = build_onboarding_test_context();
    let target = AccountId::new(
        checked_key_pair(0xD8, Algorithm::Ed25519, "derive tamper target")
            .public_key()
            .clone(),
    );
    let plan = send_onboarding_request(
        &context.app,
        "/v1/accounts/onboard/plan",
        &onboarding_plan_request("tamperproof@universal", &target),
    )
    .await;
    assert_eq!(plan.status, StatusCode::OK, "{}", plan.raw_body);

    let old = json_object(vec![json_entry("receipt", plan.payload.clone())]);
    let rejected = send_onboarding_request(&context.app, "/v1/accounts/onboard", &old).await;
    assert_eq!(
        rejected.status,
        StatusCode::BAD_REQUEST,
        "{}",
        rejected.raw_body
    );

    let prepared = send_onboarding_request(
        &context.app,
        "/v1/accounts/onboard/prepare",
        &onboarding_prepare_request(plan.payload),
    )
    .await;
    assert_eq!(prepared.status, StatusCode::OK, "{}", prepared.raw_body);
    for (field, replacement) in [
        ("transaction_hash_hex", "00".repeat(32)),
        ("signed_transaction_wire_sha256", "33".repeat(32)),
        ("signed_transaction_wire_hex", "00".repeat(8)),
    ] {
        let mut tampered = prepared.payload.clone();
        tampered
            .as_object_mut()
            .expect("prepared object")
            .insert(field.to_owned(), norito::json::Value::String(replacement));
        let rejected =
            send_onboarding_request(&context.app, "/v1/accounts/onboard", &tampered).await;
        assert_eq!(
            rejected.status,
            StatusCode::BAD_REQUEST,
            "tampered {field} escaped: {}",
            rejected.raw_body
        );
    }
    let mut binding_tampered = prepared.payload;
    let substituted_signature = binding_tampered
        .as_object()
        .and_then(|body| body.get("receipt"))
        .and_then(norito::json::Value::as_object)
        .and_then(|receipt| receipt.get("signature"))
        .cloned()
        .expect("receipt signature");
    let mut signature_tampered = binding_tampered.clone();
    signature_tampered
        .as_object_mut()
        .expect("prepared object")
        .insert("server_signature".to_owned(), substituted_signature);
    let rejected =
        send_onboarding_request(&context.app, "/v1/accounts/onboard", &signature_tampered).await;
    assert_eq!(
        rejected.status,
        StatusCode::BAD_REQUEST,
        "{}",
        rejected.raw_body
    );

    binding_tampered
        .as_object_mut()
        .and_then(|body| body.get_mut("binding"))
        .and_then(norito::json::Value::as_object_mut)
        .expect("prepared binding")
        .insert(
            "phase".to_owned(),
            norito::json::Value::String("substituted_phase".to_owned()),
        );
    let rejected =
        send_onboarding_request(&context.app, "/v1/accounts/onboard", &binding_tampered).await;
    assert_eq!(
        rejected.status,
        StatusCode::BAD_REQUEST,
        "{}",
        rejected.raw_body
    );
    assert_eq!(context.queue.active_len(), 0);
    context.shutdown().await;
}

#[tokio::test]
async fn sponsored_onboarding_prepared_submit_is_idempotent_until_certified_execution() {
    let context = build_onboarding_test_context();
    let target_key_pair =
        checked_key_pair(0xD3, Algorithm::Ed25519, "derive onboarding target fixture");
    let target_id = AccountId::new(target_key_pair.public_key().clone());
    let alias = "replayuser@universal";
    let plan_request = onboarding_plan_request(alias, &target_id);
    let plan =
        send_onboarding_request(&context.app, "/v1/accounts/onboard/plan", &plan_request).await;
    assert_eq!(plan.status, StatusCode::OK, "{}", plan.raw_body);
    assert_eq!(plan_disposition_kind(&plan.payload), "create");
    assert_secret_free(&plan);
    let candidate_a = send_onboarding_request(
        &context.app,
        "/v1/accounts/onboard/prepare",
        &onboarding_prepare_request(plan.payload.clone()),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    let prepared = send_onboarding_request(
        &context.app,
        "/v1/accounts/onboard/prepare",
        &onboarding_prepare_request(plan.payload.clone()),
    )
    .await;
    assert_eq!(
        candidate_a.status,
        StatusCode::OK,
        "{}",
        candidate_a.raw_body
    );
    assert_eq!(prepared.status, StatusCode::OK, "{}", prepared.raw_body);
    assert_eq!(
        response_field(&prepared.payload, "schema"),
        "iroha.prepared-transaction.v1"
    );
    assert_eq!(response_field(&prepared.payload, "operation"), "onboarding");
    assert_eq!(disposition_kind(&prepared.payload), "create");
    let typed_prepared: iroha::client::AccountOnboardingPreparedTransactionV1 =
        norito::json::from_value(prepared.payload.clone()).expect("typed prepared envelope");
    let sdk_request: iroha::client::AccountOnboardingPlanRequestV1 =
        norito::json::from_value(plan_request).expect("typed onboarding request");
    let signed = iroha::client::verify_account_onboarding_prepared_transaction_v1(
        *context.state.network_id_ref(),
        &sdk_request,
        &typed_prepared,
        &typed_prepared.receipt,
        &typed_prepared.binding,
        &typed_prepared.fee_payment,
    )
    .expect("prepared envelope authenticates its exact signed transaction");
    signed
        .verify_signature()
        .expect("exact current transaction signature");
    assert_eq!(
        context.queue.active_len(),
        0,
        "prepare must not mutate queue"
    );
    assert!(context.state.view().world().account(&target_id).is_err());
    let selected_hash = response_field(&prepared.payload, "transaction_hash_hex").to_owned();
    let unselected_hash = response_field(&candidate_a.payload, "transaction_hash_hex");
    assert_ne!(
        selected_hash, unselected_hash,
        "distinct prepare calls must identify distinct exact candidates"
    );
    assert_secret_free(&prepared);

    let submitted =
        send_onboarding_request(&context.app, "/v1/accounts/onboard", &prepared.payload).await;
    assert_eq!(
        submitted.status,
        StatusCode::ACCEPTED,
        "{}",
        submitted.raw_body
    );
    assert_eq!(response_field(&submitted.payload, "outcome"), "Pending");
    assert_eq!(context.queue.active_len(), 1);
    let response_loss_replay =
        send_onboarding_request(&context.app, "/v1/accounts/onboard", &prepared.payload).await;
    assert_eq!(
        response_loss_replay.status,
        StatusCode::OK,
        "{}",
        response_loss_replay.raw_body
    );
    assert_eq!(
        response_field(&response_loss_replay.payload, "outcome"),
        "Pending"
    );
    assert_eq!(
        context.queue.active_len(),
        1,
        "exact retry preserves one local input"
    );
    let wrong_scope_replay = send_onboarding_request_with_token(
        &context.app,
        "/v1/accounts/onboard",
        &prepared.payload,
        ONBOARDING_WRONG_SCOPE_API_TOKEN,
    )
    .await;
    assert_eq!(
        wrong_scope_replay.status,
        StatusCode::FORBIDDEN,
        "a known hash must not bypass receipt credential scope: {}",
        wrong_scope_replay.raw_body
    );
    assert_eq!(context.queue.active_len(), 1);
    let still_preparable = send_onboarding_request(
        &context.app,
        "/v1/accounts/onboard/prepare",
        &onboarding_prepare_request(plan.payload.clone()),
    )
    .await;
    assert_eq!(
        still_preparable.status,
        StatusCode::OK,
        "{}",
        still_preparable.raw_body
    );
    assert_eq!(
        response_field(&still_preparable.payload, "schema"),
        "iroha.prepared-transaction.v1"
    );
    assert_eq!(disposition_kind(&still_preparable.payload), "create");
    assert_eq!(context.queue.active_len(), 1);
    assert_secret_free(&still_preparable);

    let current_state = send_onboarding_request(
        &context.app,
        "/v1/accounts/onboarding/current-state",
        &onboarding_current_state_request(alias, &target_id),
    )
    .await;
    assert_eq!(
        current_state.status,
        StatusCode::OK,
        "{}",
        current_state.raw_body
    );
    let current_state: AccountOnboardingCurrentStateResponseV1 =
        norito::json::from_value(current_state.payload)
            .expect("strict atomic onboarding current-state response");
    let request = iroha_torii_shared::AccountOnboardingCurrentStateRequestV1::new(
        &target_id,
        &alias.parse().expect("canonical onboarding alias"),
    );
    let (observed_height, alias_target) = current_state
        .validate_for(&request, context.state.network_id_ref())
        .expect("snapshot response binds the exact request and network");
    assert_eq!(
        observed_height.get(),
        u64::try_from(context.state.view().height()).expect("fixture height fits u64")
    );
    assert_eq!(
        current_state.observed_block_hash,
        context
            .state
            .view()
            .latest_block_hash()
            .expect("fixture has a committed block")
    );
    assert!(!current_state.account_exists);
    assert_eq!(alias_target, None);
    assert_eq!(context.state.view().height(), 1);
    assert_eq!(
        iroha_torii::test_utils::apply_queued_in_one_block(
            &mut context.native_chain.lock(),
            &context.queue
        ),
        1
    );
    assert_eq!(context.state.view().height(), 2);
    assert!(context.state.view().world().account(&target_id).is_ok());
    assert_eq!(context.queue.active_len(), 0);
    context.shutdown().await;
}

#[tokio::test]
async fn sponsored_onboarding_fresh_receipt_prepares_after_idle_anchor_and_enters_native_queue() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time");
    let context = build_onboarding_test_context_at(
        0xA1,
        0xD1,
        now.checked_sub(Duration::from_secs(33 * 60 * 60)).unwrap(),
    );
    let anchor = context
        .state
        .view()
        .latest_block()
        .expect("funded canonical history read")
        .expect("committed anchor");
    assert!(anchor.header().creation_time() + Duration::from_secs(32 * 60 * 60) < now);
    let target = AccountId::new(
        checked_key_pair(
            0xDA,
            Algorithm::Ed25519,
            "derive idle-chain onboarding target",
        )
        .public_key()
        .clone(),
    );
    let request = onboarding_plan_request("idleuser@universal", &target);
    let before_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_millis();
    let plan = send_onboarding_request(&context.app, "/v1/accounts/onboard/plan", &request).await;
    let after_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_millis();
    assert_eq!(plan.status, StatusCode::OK, "{}", plan.raw_body);
    let deadline = u128::from(
        plan.payload["body"]["valid_until_ms"]
            .as_u64()
            .expect("deadline"),
    );
    assert!((before_ms + 300_000..=after_ms + 300_000).contains(&deadline));
    assert_eq!(
        plan.payload["body"]["quote_guard"]["valid_until_ms"],
        plan.payload["body"]["valid_until_ms"]
    );
    assert_eq!(
        plan.payload["body"]["anchor"]["block_height"].as_u64(),
        Some(1)
    );
    let receipt: iroha::client::AccountOnboardingPlanReceiptV1 =
        norito::json::from_value(plan.payload.clone()).expect("SDK receipt");
    let sdk_request: iroha::client::AccountOnboardingPlanRequestV1 =
        norito::json::from_value(request).expect("SDK request");
    iroha::client::decode_and_verify_account_onboarding_plan_for_request(
        *context.state.network_id_ref(),
        &sdk_request,
        &receipt,
    )
    .expect("SDK signature and exact semantic closure remain valid");
    let prepared = send_onboarding_request(
        &context.app,
        "/v1/accounts/onboard/prepare",
        &onboarding_prepare_request(plan.payload),
    )
    .await;
    assert_eq!(prepared.status, StatusCode::OK, "{}", prepared.raw_body);
    assert_eq!(context.queue.active_len(), 0);
    let submitted =
        send_onboarding_request(&context.app, "/v1/accounts/onboard", &prepared.payload).await;
    assert_eq!(
        submitted.status,
        StatusCode::ACCEPTED,
        "{}",
        submitted.raw_body
    );
    assert_eq!(context.queue.active_len(), 1);
    assert_eq!(context.state.view().height(), 1);
    assert!(context.state.view().world().account(&target).is_err());
    assert_secret_free(&prepared);
    context.shutdown().await;
}

#[tokio::test]
async fn sponsored_onboarding_rejects_signed_expired_receipt_without_block_progress() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time");
    let context = build_onboarding_test_context_at(
        0xA1,
        0xD1,
        now.checked_sub(Duration::from_secs(33 * 60 * 60)).unwrap(),
    );
    let anchor_hash = context
        .state
        .view()
        .latest_block_hash()
        .expect("committed anchor");
    let target = AccountId::new(
        checked_key_pair(0xDB, Algorithm::Ed25519, "derive expired-receipt target")
            .public_key()
            .clone(),
    );
    let request = onboarding_plan_request("expiredreceipt@universal", &target);
    let planned =
        send_onboarding_request(&context.app, "/v1/accounts/onboard/plan", &request).await;
    assert_eq!(planned.status, StatusCode::OK, "{}", planned.raw_body);
    let mut receipt: iroha::client::AccountOnboardingPlanReceiptV1 =
        norito::json::from_value(planned.payload).expect("SDK receipt");
    let expired_at = u64::try_from(now.as_millis()).expect("millisecond time") - 60_000;
    receipt.body.valid_until_ms = expired_at;
    receipt.body.quote_guard.valid_until_ms = expired_at;
    receipt
        .body
        .resource
        .quote
        .as_mut()
        .expect("create quote")
        .guard = receipt.body.quote_guard.clone();
    let instruction: iroha_data_model::isi::InstructionBox =
        iroha_data_model::isi::alias_setup::EnsureAlias::new(
            receipt.body.resource.intent.clone(),
            receipt.body.acquisition,
            receipt.body.quote_guard.clone(),
        )
        .into();
    let (wire_id, framed_payload) = iroha_data_model::isi::framed_instruction_payload(&instruction)
        .expect("registered EnsureAlias frame");
    receipt.body.instructions[0] = iroha_data_model::alias_setup::AliasFramedInstructionV1 {
        wire_id: wire_id.to_owned(),
        framed_payload,
    };
    let signer = checked_key_pair(0xD1, Algorithm::Ed25519, "derive onboarding receipt signer");
    receipt.plan_hash = receipt.body.canonical_hash();
    receipt.signature =
        iroha_crypto::Signature::try_new(signer.private_key(), receipt.plan_hash.as_ref())
            .expect("sign expired receipt");
    assert!(
        receipt.verify(),
        "expired fixture must retain valid authority signature"
    );
    let sdk_request: iroha::client::AccountOnboardingPlanRequestV1 =
        norito::json::from_value(request).expect("SDK request");
    iroha::client::decode_and_verify_account_onboarding_plan_for_request(
        *context.state.network_id_ref(),
        &sdk_request,
        &receipt,
    )
    .expect("expired fixture retains exact semantic and instruction closure");
    let encoded = norito::json::to_value(&receipt).expect("encode signed expired receipt");
    let bound = onboarding_prepare_request(encoded);
    // The active binding cannot exceed its signed receipt. Both a faithfully expired
    // binding and an attempted extension must fail before preparing any transaction.
    let mut extended = bound.clone();
    extended
        .as_object_mut()
        .expect("prepare object")
        .get_mut("binding")
        .expect("binding")
        .as_object_mut()
        .expect("binding object")
        .insert(
            "execution_expires_at_unix_ms".to_owned(),
            norito::json::Value::from(
                u64::try_from(now.as_millis()).expect("millisecond time") + 300_000,
            ),
        );
    for candidate in [bound, extended] {
        let response =
            send_onboarding_request(&context.app, "/v1/accounts/onboard/prepare", &candidate).await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "{}",
            response.raw_body
        );
        assert_secret_free(&response);
    }
    assert_eq!(context.state.view().latest_block_hash(), Some(anchor_hash));
    assert_eq!(context.state.view().height(), 1);
    assert_eq!(context.queue.active_len(), 0);
    assert!(context.state.view().world().account(&target).is_err());
    context.shutdown().await;
}

#[tokio::test]
async fn expired_onboarding_envelopes_with_distinct_signed_hashes_fail_closed() {
    use iroha_torii_shared::prepared_transaction::{
        OnboardingPreparedSignatureFieldsV1, PreparedOperationBindingRefV1,
        onboarding_prepared_signature_transcript_v1, prepared_signature_digest_v1,
    };
    use sha2::{Digest as _, Sha256};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time");
    let context = build_onboarding_test_context_at(
        0xA1,
        0xD1,
        now.checked_sub(Duration::from_secs(33 * 60 * 60)).unwrap(),
    );
    let target = AccountId::new(
        checked_key_pair(0xD9, Algorithm::Ed25519, "derive expiry target")
            .public_key()
            .clone(),
    );
    let request = onboarding_plan_request("expiryuser@universal", &target);
    let plan = send_onboarding_request(&context.app, "/v1/accounts/onboard/plan", &request).await;
    assert_eq!(plan.status, StatusCode::OK, "{}", plan.raw_body);
    let prepared = send_onboarding_request(
        &context.app,
        "/v1/accounts/onboard/prepare",
        &onboarding_prepare_request(plan.payload),
    )
    .await;
    assert_eq!(prepared.status, StatusCode::OK, "{}", prepared.raw_body);
    let template: iroha::client::AccountOnboardingPreparedTransactionV1 =
        norito::json::from_value(prepared.payload).expect("SDK prepared envelope");
    let sdk_request: iroha::client::AccountOnboardingPlanRequestV1 =
        norito::json::from_value(request).expect("SDK request");
    let original = iroha::client::verify_account_onboarding_prepared_transaction_v1(
        *context.state.network_id_ref(),
        &sdk_request,
        &template,
        &template.receipt,
        &template.binding,
        &template.fee_payment,
    )
    .expect("real routed preparation has exact SDK closure");
    let signer = checked_key_pair(
        0xD1,
        Algorithm::Ed25519,
        "derive historical envelope signer",
    );
    let creation = now.checked_sub(Duration::from_secs(120)).unwrap();
    let deadline = u64::try_from(
        now.checked_sub(Duration::from_secs(60))
            .unwrap()
            .as_millis(),
    )
    .expect("deadline");
    let historical = |offset: u64| {
        let mut envelope = template.clone();
        envelope.binding.execution_expires_at_unix_ms = deadline;
        let mut payload = original.payload().clone();
        payload.metadata.insert(
            "prepared_operation_binding"
                .parse()
                .expect("binding metadata key"),
            Json::from_norito_value_ref(
                &norito::json::to_value(&envelope.binding).expect("binding JSON"),
            )
            .expect("canonical binding metadata"),
        );
        let mut builder = TransactionBuilder::from_payload(payload).expect("historical builder");
        let creation = creation + Duration::from_millis(offset);
        builder.set_creation_time(creation);
        builder.set_ttl(Duration::from_millis(
            deadline - u64::try_from(creation.as_millis()).expect("creation"),
        ));
        let transaction = builder
            .try_sign(signer.private_key())
            .expect("sign historical transaction");
        let wire = transaction
            .encode_wire_v1()
            .expect("canonical historical wire");
        envelope.transaction_hash_hex = hex::encode(transaction.hash().as_ref());
        envelope.signed_transaction_wire_sha256 = hex::encode(Sha256::digest(&wire));
        envelope.signed_transaction_wire_hex = hex::encode(&wire);
        assert_eq!(
            envelope.disposition,
            iroha_data_model::alias_setup::AliasPlanDispositionV1::Create
        );
        let binding = &envelope.binding;
        let transcript =
            onboarding_prepared_signature_transcript_v1(OnboardingPreparedSignatureFieldsV1 {
                envelope_schema: &envelope.schema,
                binding: PreparedOperationBindingRefV1 {
                    schema: &binding.schema,
                    semantic_hash_hex: &binding.semantic_hash_hex,
                    kind: &binding.kind,
                    request_id: &binding.request_id,
                    execution_expires_at_unix_ms: binding.execution_expires_at_unix_ms,
                },
                semantic_hash_hex: &envelope.semantic_hash_hex,
                account_id: &envelope.account_id,
                alias: &envelope.alias,
                disposition: "create",
                transaction_hash_hex: &envelope.transaction_hash_hex,
                signed_transaction_wire_sha256: &envelope.signed_transaction_wire_sha256,
                signed_transaction_wire: &wire,
            });
        envelope.server_signature = iroha_crypto::Signature::try_new(
            signer.private_key(),
            prepared_signature_digest_v1(&transcript).as_ref(),
        )
        .expect("sign historical envelope");
        iroha::client::verify_account_onboarding_prepared_transaction_v1(
            *context.state.network_id_ref(),
            &sdk_request,
            &envelope,
            &envelope.receipt,
            &envelope.binding,
            &envelope.fee_payment,
        )
        .expect("historical envelope retains complete SDK authentication and lifetime closure");
        (envelope, transaction)
    };
    let (known, known_transaction) = historical(0);
    let (unknown, unknown_transaction) = historical(1);
    assert_ne!(known.transaction_hash_hex, unknown.transaction_hash_hex);
    known_transaction
        .verify_signature()
        .expect("exact current transaction signature");
    unknown_transaction
        .verify_signature()
        .expect("exact current transaction signature");
    let known = norito::json::to_value(&known).expect("known envelope JSON");
    let unknown = norito::json::to_value(&unknown).expect("unknown envelope JSON");
    for expired in [known, unknown] {
        let response =
            send_onboarding_request(&context.app, "/v1/accounts/onboard", &expired).await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "{}",
            response.raw_body
        );
        assert!(
            response
                .payload
                .as_object()
                .and_then(|body| body.get("outcome"))
                .is_none()
        );
    }
    assert_eq!(context.queue.active_len(), 0);
    assert_eq!(context.state.view().height(), 1);
    assert!(context.state.view().world().account(&target).is_err());
    context.shutdown().await;
}

#[tokio::test]
async fn sponsored_onboarding_stale_create_receipt_returns_redacted_conflict() {
    let context = build_onboarding_test_context();
    let original_target = AccountId::new(
        checked_key_pair(
            0xD4,
            Algorithm::Ed25519,
            "derive original onboarding target fixture",
        )
        .public_key()
        .clone(),
    );
    let conflicting_target = AccountId::new(
        checked_key_pair(
            0xD5,
            Algorithm::Ed25519,
            "derive conflicting onboarding target fixture",
        )
        .public_key()
        .clone(),
    );
    let alias = "driftuser@universal";
    let conflicting_request = onboarding_plan_request(alias, &conflicting_target);
    let original_plan = send_onboarding_request(
        &context.app,
        "/v1/accounts/onboard/plan",
        &onboarding_plan_request(alias, &original_target),
    )
    .await;
    let conflicting_plan = send_onboarding_request(
        &context.app,
        "/v1/accounts/onboard/plan",
        &conflicting_request,
    )
    .await;
    for plan in [&original_plan, &conflicting_plan] {
        assert_eq!(plan.status, StatusCode::OK, "{}", plan.raw_body);
        assert_eq!(plan_disposition_kind(&plan.payload), "create");
        assert_secret_free(plan);
    }
    let conflicting_prepared = send_onboarding_request(
        &context.app,
        "/v1/accounts/onboard/prepare",
        &onboarding_prepare_request(conflicting_plan.payload.clone()),
    )
    .await;
    assert_eq!(
        conflicting_prepared.status,
        StatusCode::OK,
        "{}",
        conflicting_prepared.raw_body
    );
    let conflicting_submit = send_onboarding_request(
        &context.app,
        "/v1/accounts/onboard",
        &conflicting_prepared.payload,
    )
    .await;
    assert_eq!(
        conflicting_submit.status,
        StatusCode::ACCEPTED,
        "{}",
        conflicting_submit.raw_body
    );
    assert_eq!(context.queue.active_len(), 1);
    // Execute the exact competing prepared transaction through the native chain,
    // then revalidate the old receipt against that certified account and alias.
    let prepared: iroha::client::AccountOnboardingPreparedTransactionV1 =
        norito::json::from_value(conflicting_prepared.payload).expect("typed racing envelope");
    let request: iroha::client::AccountOnboardingPlanRequestV1 =
        norito::json::from_value(conflicting_request).expect("typed racing request");
    let transaction = iroha::client::verify_account_onboarding_prepared_transaction_v1(
        *context.state.network_id_ref(),
        &request,
        &prepared,
        &prepared.receipt,
        &prepared.binding,
        &prepared.fee_payment,
    )
    .expect("racing envelope authenticates its exact transaction");
    transaction
        .verify_signature()
        .expect("exact current transaction signature");
    assert_eq!(
        iroha_torii::test_utils::apply_queued_in_one_block(
            &mut context.native_chain.lock(),
            &context.queue,
        ),
        1
    );
    assert_eq!(context.queue.active_len(), 0);
    assert_eq!(context.state.view().height(), 2);
    assert!(
        context
            .state
            .view()
            .world()
            .account(&conflicting_target)
            .is_ok()
    );
    let stale = send_onboarding_request(
        &context.app,
        "/v1/accounts/onboard/prepare",
        &onboarding_prepare_request(original_plan.payload.clone()),
    )
    .await;
    assert_eq!(stale.status, StatusCode::CONFLICT, "{}", stale.raw_body);
    assert_eq!(response_field(&stale.payload, "code"), "conflict");
    assert_eq!(context.queue.active_len(), 0);
    assert_secret_free(&stale);
    for removed in [
        "/v1/accounts/onboard/multisig",
        "/v1/accounts/onboard/renew",
        "/v1/accounts/onboard/auto-renew",
    ] {
        let empty_body = norito::json::Value::Object(norito::json::Map::new());
        let response = fixtures::request(
            &context.app,
            onboarding_http_request(removed, &empty_body, Some(ONBOARDING_API_TOKEN)),
        )
        .await
        .expect("removed onboarding route response");
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "removed onboarding route must remain absent: {removed}"
        );
    }
    context.shutdown().await;
}
