//! Account-free bootstrap qualification through the shipping Torii router and `OpenAPI` projection.

use std::sync::Arc;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use iroha_config::parameters::actual::Root;
use iroha_core::{
    kiso::KisoHandle,
    kura::Kura,
    query::store::LiveQueryStore,
    queue::Queue,
    state::{State, World, WorldReadOnly as _},
};
use iroha_data_model::NetworkId;
use iroha_torii::{OnlinePeersProvider, TestApiRouterRuntime, Torii};
use iroha_torii_shared::{
    account_capabilities::{ACCOUNT_CAPABILITIES_MAX_BYTES_V1, AccountCapabilitiesV1},
    route_catalog,
};
use norito::json::Value;
use tower::ServiceExt as _;

fn bootstrap_router(cfg: &Root) -> (TestApiRouterRuntime, Arc<State>) {
    let kura = Kura::blank_kura_for_testing();
    let network_id = NetworkId::from_genesis_hash(cfg.genesis.expected_hash);
    let world = World::default();
    let policy = iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
        iroha_crypto::Algorithm::Secp256k1,
    ])
    .expect("explicit no-Ed25519 bootstrap fixture policy");
    let mut block = world.block();
    block
        .parameters
        .set_parameter(policy.into_parameter().unwrap())
        .unwrap();
    block.commit();
    let state = Arc::new(State::new_with_chain_and_network_id_for_testing(
        world,
        kura.clone(),
        LiveQueryStore::start_test(),
        cfg.common.chain.clone(),
        network_id,
    ));
    let queue = Arc::new(Queue::from_config(
        iroha_config::parameters::actual::Queue::default(),
        tokio::sync::broadcast::channel(1).0,
    ));
    let (_, peers_rx) = tokio::sync::watch::channel(<_>::default());
    let torii = Torii::new_with_handle(
        cfg.common.chain.clone(),
        network_id,
        KisoHandle::mock(cfg),
        cfg.torii.clone(),
        queue,
        tokio::sync::broadcast::channel(1).0,
        LiveQueryStore::start_test(),
        kura,
        state.clone(),
        cfg.common.key_pair.clone(),
        OnlinePeersProvider::new(peers_rx),
        None,
        iroha_torii::ToriiRuntimeDeps::new(
            build_identity_test_fixture::build_identity(),
            iroha_torii::MaybeTelemetry::disabled(),
        ),
    )
    .expect("valid empty-ledger bootstrap fixture");
    (
        torii
            .api_router_for_tests()
            .expect("shipping Torii router initializes"),
        state,
    )
}

#[tokio::test]
async fn account_capabilities_shipping_router_is_public_exact_bounded_and_read_only() {
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let (runtime, state) = bootstrap_router(&cfg);
    assert_eq!(state.view().world().accounts_iter().count(), 0);
    let expected = {
        let parameters = state.transaction_admission_parameters();
        AccountCapabilitiesV1::from_policy(
            *state.network_id_ref(),
            iroha_data_model::account::address::chain_discriminant(),
            parameters
                .require_crypto_policy()
                .expect("initialized fixture"),
        )
    };
    let response = runtime
        .router()
        .oneshot(
            Request::builder()
                .uri(route_catalog::application_api::ACCOUNTS_CAPABILITIES_GET.path())
                .body(Body::empty())
                .expect("credential-free bootstrap GET"),
        )
        .await
        .expect("bootstrap router response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/json; charset=utf-8"
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let bytes = to_bytes(response.into_body(), ACCOUNT_CAPABILITIES_MAX_BYTES_V1)
        .await
        .expect("bootstrap response obeys its 4 KiB wire bound");
    let actual: AccountCapabilitiesV1 =
        norito::json::from_slice(&bytes).expect("typed bootstrap JSON");
    assert_eq!(actual, expected);
    let wire: Value = norito::json::from_slice(&bytes).expect("bootstrap wire object");
    let mut keys = wire
        .as_object()
        .expect("bootstrap JSON object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "allowed_signing",
            "network_id",
            "network_prefix",
            "schema_version",
        ],
        "bootstrap must expose only the four public V1 fields"
    );
    assert_eq!(actual.allowed_signing, ["secp256k1"]);

    for (method, path, body, expected_status) in [
        (
            "GET",
            "/v1/accounts/capabilities?account_id=unregistered",
            Vec::new(),
            StatusCode::BAD_REQUEST,
        ),
        (
            "GET",
            route_catalog::application_api::ACCOUNTS_CAPABILITIES_GET.path(),
            vec![b'x'],
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            "GET",
            route_catalog::application_api::ACCOUNTS_CAPABILITIES_GET.path(),
            vec![b'x'; ACCOUNT_CAPABILITIES_MAX_BYTES_V1 + 1],
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            "POST",
            route_catalog::application_api::ACCOUNTS_CAPABILITIES_GET.path(),
            Vec::new(),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            "GET",
            "/v1/node/capabilities",
            Vec::new(),
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let response = runtime
            .router()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::from(body))
                    .expect("bootstrap policy request"),
            )
            .await
            .expect("bootstrap policy response");
        assert_eq!(response.status(), expected_status, "{method} {path}");
    }
    assert_eq!(state.view().world().accounts_iter().count(), 0);
    runtime.shutdown().await;

    // Public account bootstrap does not bypass the listener's configured API-token policy.
    cfg.torii.require_api_token = true;
    cfg.torii.api_tokens = vec!["bootstrap-listener-test-token-00000000".to_owned()].into();
    let (protected, _) = bootstrap_router(&cfg);
    let denied = protected
        .router()
        .oneshot(
            Request::builder()
                .uri(route_catalog::application_api::ACCOUNTS_CAPABILITIES_GET.path())
                .body(Body::empty())
                .expect("credential-free protected listener request"),
        )
        .await
        .expect("protected listener response");
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(denied.headers()[header::CACHE_CONTROL], "private, no-store");
    protected.shutdown().await;
}

#[test]
fn account_capabilities_generated_openapi_preserves_exact_public_bootstrap_contract() {
    let document = iroha_torii::openapi::generate_spec();
    let operation =
        &document["paths"][route_catalog::application_api::ACCOUNTS_CAPABILITIES_GET.path()]["get"];
    assert_eq!(
        operation["operationId"].as_str(),
        Some("getAccountCapabilities")
    );
    assert!(operation.get("requestBody").is_none());
    assert!(
        operation["parameters"]
            .as_array()
            .expect("parameters")
            .is_empty()
    );
    assert!(
        operation["security"]
            .as_array()
            .expect("bootstrap security")
            .iter()
            .any(|value| value
                .as_object()
                .is_some_and(std::collections::BTreeMap::is_empty))
    );
    let schema = &document["components"]["schemas"]["AccountCapabilitiesV1"];
    assert_eq!(schema["additionalProperties"].as_bool(), Some(false));
    assert_eq!(schema["x-iroha-max-bytes"].as_u64(), Some(4096));
    assert_eq!(
        schema["properties"]["schema_version"]["const"].as_u64(),
        Some(1)
    );
    assert!(
        schema["properties"]
            .as_object()
            .unwrap()
            .get("default_signing")
            .is_none()
    );
    assert_eq!(
        schema["properties"]["network_prefix"]["maximum"].as_u64(),
        Some(65535)
    );
    assert_eq!(
        schema["required"]
            .as_array()
            .expect("required fields")
            .len(),
        5
    );
    assert!(
        document["paths"]["/v1/node/capabilities"]["get"]["security"]
            .as_array()
            .expect("authenticated node capability security")
            .iter()
            .all(|value| value.as_object().is_some_and(|object| !object.is_empty()))
    );
}

#[path = "../src/build_identity_test_fixture.rs"]
mod build_identity_test_fixture;
