#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Shared fixtures used across Torii integration/unit tests.
//!
//! Some helpers are gated by telemetry and may be unused when those tests are
//! disabled; allow the definitions to stay available across feature sets.
use axum::{
    body::{Body, Bytes},
    http::Request,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use iroha_config::parameters::actual::TelemetryProfile;
use iroha_core::{
    kiso::KisoHandle,
    kura::Kura,
    query::store::LiveQueryStore,
    queue::Queue,
    state::{State, World},
};
use iroha_crypto::{KeyPair, Signature};
use iroha_data_model::{NetworkId, account::AccountId};
use iroha_model_base::chain::ChainId;
use iroha_model_base::peer::PeerId;
use iroha_telemetry::metrics::Metrics;
use iroha_test_samples::ALICE_ID;
use iroha_torii::{MaybeTelemetry, OnlinePeersProvider, TestApiRouterRuntime, Torii};
use std::sync::{
    Arc, LazyLock, Mutex,
    atomic::{AtomicU64, Ordering},
};
use tower::ServiceExt as _;
static SHARED_METRICS: LazyLock<Mutex<Arc<Metrics>>> =
    LazyLock::new(|| Mutex::new(Arc::new(Metrics::default())));
static OPERATOR_NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);
/// Canonical literals for a single well-known account used in tx query tests.
#[allow(dead_code)]
pub struct AccountLiterals {
    /// I105 canonical literal.
    pub canonical: String,
    /// Compressed literal.
    pub compressed: String,
}
/// Singleton fixture so all tx query tests share the same literals.
#[allow(dead_code)]
pub static TX_QUERY_ACCOUNT: LazyLock<AccountLiterals> = LazyLock::new(|| {
    let account = ALICE_ID.clone();
    let compressed = account
        .to_account_address()
        .and_then(|addr| addr.to_i105())
        .expect("compressed literal should encode");
    AccountLiterals {
        canonical: account.to_string(),
        compressed,
    }
});
/// Ensure duplicate metric registrations panic inside tests so suites do not silently reuse registries.
#[allow(dead_code)]
pub fn enable_duplicate_metric_panic() {
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("IROHA_METRICS_PANIC_ON_DUPLICATE", "1");
    }
}
/// Shared metrics registry for tests to avoid duplicate Prometheus descriptor warnings.
#[allow(dead_code)]
pub fn shared_metrics() -> Arc<Metrics> {
    enable_duplicate_metric_panic();
    SHARED_METRICS
        .lock()
        .expect("shared metrics mutex poisoned")
        .clone()
}
/// Reset the shared metrics registry to a fresh instance for suites that need a clean slate.
#[allow(dead_code)]
pub fn reset_shared_metrics() -> Arc<Metrics> {
    enable_duplicate_metric_panic();
    let mut guard = SHARED_METRICS
        .lock()
        .expect("shared metrics mutex poisoned");
    let metrics = Arc::new(Metrics::default());
    *guard = metrics.clone();
    metrics
}
/// Seed the world with the given peer IDs using the test-only mutator.
#[allow(dead_code)]
pub fn seed_peers<I>(world: &mut World, peer_ids: I)
where
    I: IntoIterator<Item = PeerId>,
{
    let mut world_block = world.block();
    let peers = world_block.peers_mut_for_testing().get_mut();
    for peer_id in peer_ids {
        let _ = peers.push(peer_id);
    }
    world_block.commit();
}
/// Seed the world with a single peer ID.
#[allow(dead_code)]
pub fn seed_peer(world: &mut World, peer_id: PeerId) {
    seed_peers(world, [peer_id]);
}
/// Create an original signed four-validator genesis and its native execution owner.
/// The initial World and governance instructions are committed by the same production startup.
#[allow(dead_code)]
pub fn commit_genesis_fixture(
    world: World,
    chain_id: ChainId,
    signer: &KeyPair,
    instructions: Vec<iroha_data_model::prelude::InstructionBox>,
    validator_keys: Option<Vec<KeyPair>>,
    time_source: iroha_primitives::time::TimeSource,
) -> iroha_core::sumeragi::test_chain::CertifiedTestChain {
    let time_ms =
        u64::try_from(time_source.get_unix_time().as_millis()).expect("fixture time fits");
    let mut config = iroha_core::sumeragi::test_chain::TestChainConfig::new(world, time_ms);
    config.chain_id = chain_id;
    config.genesis_key = signer.clone();
    config.genesis_instructions = instructions;
    config.validator_keys = validator_keys;
    iroha_core::sumeragi::test_chain::CertifiedTestChain::start(config)
        .expect("original signed fixture genesis")
}
/// Keep an applied signed genesis alive until the router finishes its final request.
/// This owner supplies no routing authority; the existing native genesis execution does.
#[allow(dead_code)]
pub struct CommittedToriiRouterRuntime {
    runtime: TestApiRouterRuntime,
    chain: iroha_core::sumeragi::test_chain::CertifiedTestChain,
}
#[allow(dead_code)]
impl CommittedToriiRouterRuntime {
    /// Retain the same native chain whose State and Kura were passed to Torii.
    pub fn new(
        runtime: TestApiRouterRuntime,
        chain: iroha_core::sumeragi::test_chain::CertifiedTestChain,
    ) -> Self {
        assert_eq!(
            chain.height(),
            1,
            "routing fixture retains its original applied genesis"
        );
        assert_eq!(
            chain.validators().len(),
            4,
            "routing fixture retains its signed committee"
        );
        assert_eq!(*chain.state().network_id_ref(), chain.network_id());
        Self { runtime, chain }
    }
    /// Return the exact original signed-genesis network used by the retained router State.
    pub fn network_id(&self) -> NetworkId {
        self.chain.network_id()
    }
    /// Borrow the original committed State for fixture invariants.
    pub fn state(&self) -> &Arc<State> {
        self.chain.state()
    }
    /// Authenticate an operator request against this actual genesis-derived network.
    pub fn operator_signed_request(
        &self,
        key_pair: &KeyPair,
        mut request: Request<Body>,
        body_bytes: &[u8],
    ) -> Request<Body> {
        let headers = iroha_torii::operator_signed_request_headers(
            key_pair,
            &self.chain.network_id(),
            request.method(),
            request.uri(),
            body_bytes,
        )
        .expect("operator signature bound to the original routing fixture genesis");
        request.headers_mut().extend(headers);
        request
    }
    /// Join router workers before releasing their original committed chain.
    pub async fn shutdown(self) {
        let Self { runtime, chain } = self;
        runtime.shutdown().await;
        drop(chain);
    }
}
impl std::ops::Deref for CommittedToriiRouterRuntime {
    type Target = axum::Router;
    fn deref(&self) -> &Self::Target {
        &self.runtime
    }
}
/// Own a Torii test instance together with the Kiso task that backs its configuration handle.
#[allow(dead_code)]
pub struct ToriiHarness {
    torii: Torii,
    _kiso_child: iroha_futures::supervisor::Child,
}
#[allow(dead_code)]
impl ToriiHarness {
    /// Construct Torii using the identity of the supplied, already-seeded ledger.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cfg: &iroha_config::parameters::actual::Root,
        kura: &Arc<Kura>,
        state: &Arc<State>,
        queue: &Arc<Queue>,
        local_peer_id: &PeerId,
        events: iroha_core::EventsSender,
        telemetry_profile: TelemetryProfile,
    ) -> Self {
        let (kiso, kiso_child) = KisoHandle::start(cfg.clone());
        let (peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
        let _ = peers_tx;
        #[cfg(feature = "telemetry")]
        let telemetry = if telemetry_profile.metrics_enabled() {
            use iroha_core::telemetry as core_telemetry;
            use iroha_primitives::time::TimeSource;
            let metrics = shared_metrics();
            let (_mock_handle, time_source) = TimeSource::new_mock(core::time::Duration::default());
            Some(
                core_telemetry::start(
                    metrics,
                    state.clone(),
                    kura.clone(),
                    queue.clone(),
                    peers_rx.clone(),
                    local_peer_id.clone(),
                    time_source,
                    false,
                )
                .expect("test telemetry resource registration")
                .0,
            )
        } else {
            None
        };
        #[cfg(feature = "telemetry")]
        let telemetry = MaybeTelemetry::from_profile(telemetry, telemetry_profile);
        #[cfg(not(feature = "telemetry"))]
        let telemetry = {
            let _ = telemetry_profile;
            MaybeTelemetry::disabled()
        };
        let torii = Torii::new_with_handle(
            state.chain_id_ref().clone(),
            *state.network_id_ref(),
            kiso,
            cfg.torii.clone(),
            queue.clone(),
            events,
            LiveQueryStore::start_test(),
            kura.clone(),
            state.clone(),
            cfg.common.key_pair.clone(),
            OnlinePeersProvider::new(peers_rx),
            None,
            iroha_torii::ToriiRuntimeDeps::new(
                build_identity_test_fixture::build_identity(),
                telemetry,
            ),
        )
        .expect("valid Torii integration-test fixture")
        .with_local_peer_id(local_peer_id.clone());
        Self {
            torii,
            _kiso_child: kiso_child,
        }
    }
    /// Construct Torii with telemetry disabled when the ledger has no local peer fixture.
    pub fn new_without_telemetry(
        cfg: &iroha_config::parameters::actual::Root,
        kura: &Arc<Kura>,
        state: &Arc<State>,
        queue: &Arc<Queue>,
        events: iroha_core::EventsSender,
    ) -> Self {
        let local_peer_id = PeerId::new(cfg.common.key_pair.public_key().clone());
        Self::new(
            cfg,
            kura,
            state,
            queue,
            &local_peer_id,
            events,
            TelemetryProfile::Disabled,
        )
    }
    /// Build the complete test router while retaining the backing Kiso task.
    pub fn router(&self) -> TestApiRouterRuntime {
        self.torii
            .api_router_for_tests()
            .expect("test Torii router initializes")
    }
}
/// Standard single-ledger Torii fixture used by endpoint tests.
#[allow(dead_code)]
pub struct StandardToriiHarness {
    harness: ToriiHarness,
    /// Ledger state retained for assertions after requests complete.
    pub state: Arc<State>,
    /// Transaction queue retained for request-side-effect assertions.
    pub queue: Arc<Queue>,
}
#[allow(dead_code)]
impl StandardToriiHarness {
    /// Build the common `test-chain` router around an explicitly supplied world.
    pub fn new(cfg: &iroha_config::parameters::actual::Root, mut world: World) -> Self {
        let kura = Kura::blank_kura_for_testing();
        let local_peer_id = PeerId::new(cfg.common.key_pair.public_key().clone());
        seed_peer(&mut world, local_peer_id.clone());
        let chain_id = cfg.common.chain.clone();
        let network_id = NetworkId::from_genesis_hash(cfg.genesis.expected_hash);
        let state = Arc::new(State::new_with_chain_and_network_id_for_testing(
            world,
            kura.clone(),
            LiveQueryStore::start_test(),
            chain_id,
            network_id,
        ));
        Self::from_state(cfg, &kura, state)
    }
    /// Build the common router around a preconfigured state snapshot.
    pub fn from_state(
        cfg: &iroha_config::parameters::actual::Root,
        kura: &Arc<Kura>,
        state: Arc<State>,
    ) -> Self {
        let local_peer_id = PeerId::new(cfg.common.key_pair.public_key().clone());
        let queue = Arc::new(Queue::from_config(
            iroha_config::parameters::actual::Queue::default(),
            tokio::sync::broadcast::channel(1).0,
        ));
        let harness = ToriiHarness::new(
            cfg,
            kura,
            &state,
            &queue,
            &local_peer_id,
            tokio::sync::broadcast::channel(1).0,
            TelemetryProfile::Operator,
        );
        Self {
            harness,
            state,
            queue,
        }
    }
    /// Build the endpoint router while retaining the ledger fixture.
    pub fn router(&self) -> TestApiRouterRuntime {
        self.harness.router()
    }
}
/// Send one request through a cloned test router without consuming the caller's handle.
#[allow(dead_code)]
pub async fn request(
    app: &axum::Router,
    request: Request<Body>,
) -> Result<axum::response::Response, std::convert::Infallible> {
    app.clone().oneshot(request).await
}
/// Send a bodyless GET request while preserving the router result for caller-specific errors.
#[allow(dead_code)]
pub async fn request_get(
    app: &axum::Router,
    uri: &str,
) -> Result<axum::response::Response, std::convert::Infallible> {
    request(app, get_request(uri)).await
}
/// Collect a response body with the caller's exact failure diagnostic.
#[allow(dead_code)]
pub async fn response_body(response: axum::response::Response, error: &'static str) -> Bytes {
    http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect(error)
        .to_bytes()
}
/// Build a bodyless GET request from a string URI.
#[allow(dead_code)]
pub fn get_request(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}
/// Build a JSON POST request from a string URI and concrete body.
#[allow(dead_code)]
pub fn post_json_request(uri: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(body)
        .unwrap()
}
/// Send a bodyless GET request through a test router.
#[allow(dead_code)]
pub async fn get(app: &axum::Router, uri: &str) -> axum::response::Response {
    request(app, get_request(uri)).await.unwrap()
}
/// Send a JSON POST request through a test router.
#[allow(dead_code)]
pub async fn post_json(app: &axum::Router, uri: &str, body: Body) -> axum::response::Response {
    request(app, post_json_request(uri, body)).await.unwrap()
}
/// Attach operator signature headers to a request targeting operator-only endpoints.
///
/// Operator endpoints are internet-reachable by design but must be authenticated with a
/// request signature bound to the exact genesis-derived network plus
/// (method, path, query, body, timestamp, nonce).
#[allow(dead_code)]
pub fn operator_signed_request(
    key_pair: &KeyPair,
    mut request: Request<Body>,
    body_bytes: &[u8],
) -> Request<Body> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    let nonce_counter = OPERATOR_NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut nonce_bytes = [0_u8; 12];
    nonce_bytes[..8].copy_from_slice(&nonce_counter.to_le_bytes());
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes);
    const DOMAIN: &[u8] = b"iroha.operator.http-request.network.v1\0";
    let canonical_request =
        iroha_torii::canonical_request_message(request.method(), request.uri(), body_bytes)
            .expect("canonical operator fixture is within V1 limits");
    let network_id = iroha_torii::test_utils::signed_query_network_id();
    let mut msg = Vec::with_capacity(
        DOMAIN.len() + network_id.as_bytes().len() + canonical_request.len() + nonce.len() + 32,
    );
    msg.extend_from_slice(DOMAIN);
    msg.extend_from_slice(network_id.as_bytes());
    msg.extend_from_slice(&canonical_request);
    msg.extend_from_slice(b"\n");
    msg.extend_from_slice(ts_ms.to_string().as_bytes());
    msg.extend_from_slice(b"\n");
    msg.extend_from_slice(nonce.as_bytes());
    let signature =
        Signature::try_new(key_pair.private_key(), &msg).expect("operator request signature");
    let headers = request.headers_mut();
    headers.insert(
        "x-iroha-operator-public-key",
        key_pair
            .public_key()
            .to_string()
            .parse()
            .expect("operator public key header"),
    );
    headers.insert(
        "x-iroha-operator-timestamp-ms",
        ts_ms
            .to_string()
            .parse()
            .expect("operator timestamp header"),
    );
    headers.insert(
        "x-iroha-operator-nonce",
        nonce.parse().expect("operator nonce header"),
    );
    headers.insert(
        "x-iroha-operator-signature",
        BASE64_STANDARD
            .encode(signature.payload())
            .parse()
            .expect("operator signature header"),
    );
    request
}
/// Attach app-canonical signature headers to a request targeting app-authenticated endpoints.
#[allow(dead_code)]
pub fn app_signed_request(
    network_id: &NetworkId,
    account_id: &AccountId,
    key_pair: &KeyPair,
    mut request: Request<Body>,
    body_bytes: &[u8],
) -> Request<Body> {
    use std::{
        sync::LazyLock,
        time::{SystemTime, UNIX_EPOCH},
    };
    static APP_NONCE_SEQ: LazyLock<std::sync::atomic::AtomicU64> =
        LazyLock::new(|| std::sync::atomic::AtomicU64::new(0));
    let ts_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    let nonce_seq = APP_NONCE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nonce = format!(
        "itest-{ts_ms}-{nonce_seq}-{}-{}",
        request.method().as_str(),
        request.uri().path()
    );
    let msg = iroha_torii::canonical_network_request_signature_message(
        network_id,
        request.method(),
        request.uri(),
        body_bytes,
        ts_ms,
        &nonce,
    )
    .expect("canonical app fixture is within V1 limits");
    let signature =
        Signature::try_new(key_pair.private_key(), &msg).expect("app canonical request signature");
    let headers = request.headers_mut();
    headers.insert(
        iroha_torii::HEADER_ACCOUNT,
        account_id
            .to_canonical_hex()
            .expect("canonical account header")
            .parse()
            .expect("account header"),
    );
    headers.insert(
        iroha_torii::HEADER_SIGNATURE,
        iroha_torii::signature_header_value(&signature)
            .expect("encode valid app signature header")
            .parse()
            .expect("app signature header"),
    );
    headers.insert(
        iroha_torii::HEADER_TIMESTAMP_MS,
        ts_ms.to_string().parse().expect("timestamp header"),
    );
    headers.insert(
        iroha_torii::HEADER_NONCE,
        nonce.parse().expect("nonce header"),
    );
    request
}

#[path = "../src/build_identity_test_fixture.rs"]
mod build_identity_test_fixture;
