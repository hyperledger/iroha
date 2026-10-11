use super::*;
use crate::utils::extractors::NoritoJson;
#[cfg(feature = "telemetry")]
use crate::{RecordSoranetPrivacyEventDto, RecordSoranetPrivacyShareDto};
use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::any,
};
use futures::executor;
use iroha_config::parameters::{
    actual::{NoritoRpcTransport, TelemetryProfile},
    defaults,
};
use iroha_core::{
    kiso::KisoHandle,
    kura::Kura,
    query::store::LiveQueryStore,
    queue::{LaneRouter, Queue, RoutingDecision, RoutingResolveError, TransactionRoutingView},
    smartcontracts::Execute,
    state::{State as IrohaState, World},
    tx::AcceptedTransaction,
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, Signature, SignatureOf};
use iroha_data_model::{
    NetworkId, Registrable, ValidationFail,
    account::{Account, AccountAlias, AccountId},
    asset::{Asset, AssetDefinition, AssetDefinitionId, AssetId},
    block::{BlockHeader, BlockSignature, SignedBlock},
    consensus::{ConsensusKeyId, ConsensusKeyRecord, ConsensusKeyRole, ConsensusKeyStatus},
    domain::Domain,
    events::{
        pipeline::{BlockEvent, BlockStatus, TransactionEvent, TransactionStatus},
        trigger_completed::TriggerCompletedOutcome,
    },
    isi::{Grant, Log, Register, RegisterPeerWithPop, consensus_keys::RegisterConsensusKey},
    level::Level,
    nexus::{AxtRejectReason, UniversalAccountId},
    parameter::{Parameter, system::SumeragiNposParameters},
    peer::Peer,
    permission::Permission,
    soranet::privacy_metrics::{
        SoranetPrivacyEventHandshakeSuccessV1, SoranetPrivacyEventKindV1, SoranetPrivacyEventV1,
        SoranetPrivacyModeV1, SoranetPrivacyPrioShareV1,
    },
    transaction::{
        ExecutionStep,
        error::TransactionRejectionReason,
        signed::{
            SealedTransactionReveal, SignedTransaction, TransactionBuilder, TransactionEntrypoint,
            TransactionSignature, compute_sealed_transaction_commitment,
        },
    },
    trigger::{DataTriggerSequence, DataTriggerStep, TriggerId},
};
use iroha_executor_data_model::permission::account::{
    AccountAliasPermissionScope, CanResolveAccountAlias,
};
use iroha_executor_data_model::permission::governance::CanManageConsensusKeys;
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_model_base::peer::PeerId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_primitives::{const_vec::ConstVec, json::Json, numeric::Quantity};
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
use iroha_torii_shared::configuration::Configuration;
use norito::codec::Encode;
use std::{
    collections::HashSet,
    net::SocketAddr,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::{
        Arc, LazyLock, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
fn query_conversion_message(err: &Error) -> Option<&str> {
    match err {
        Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::Conversion(message),
        )) => Some(message.as_str()),
        _ => None,
    }
}
pub fn mk_app_state_for_tests() -> SharedAppState {
    mk_app_state_for_tests_with_world_and_options(World::default(), None, None, None, None)
}
#[tokio::test]
async fn api_version_negotiates_text_success_and_typed_unavailable() {
    use iroha_version::Version as _;

    let app = mk_app_state_for_tests();
    let router = axum::Router::new()
        .route(
            route_catalog::core::API_VERSION.path(),
            axum::routing::get(handler_version),
        )
        .layer(axum::middleware::from_fn(capture_response_format))
        .layer(axum::middleware::from_fn(coalesce_accept_headers))
        .layer(axum::middleware::from_fn(enforce_typed_error_contract))
        .layer(axum::middleware::from_fn(enforce_json_utf8_charset))
        .with_state(Arc::clone(&app));
    let request = |accept| {
        let mut request = axum::http::Request::builder()
            .uri(route_catalog::core::API_VERSION.path())
            .header(axum::http::header::ACCEPT, accept)
            .body(Body::empty())
            .expect("version request");
        request
            .extensions_mut()
            .insert(MatchedRouteMetadata::from_descriptor(
                route_catalog::core::API_VERSION,
            ));
        request
    };
    assert_eq!(
        router
            .clone()
            .oneshot(request("text/plain"))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_ACCEPTABLE,
        "text-only requests cannot negotiate the public route's typed errors"
    );
    let unavailable = router
        .clone()
        .oneshot(request("text/plain, application/json"))
        .await
        .expect("version response without genesis");
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        unavailable.headers()[axum::http::header::CONTENT_TYPE],
        "application/json; charset=utf-8"
    );
    let bytes = axum::body::to_bytes(unavailable.into_body(), 4096)
        .await
        .unwrap();
    let envelope: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    assert_eq!(
        envelope.get("code").and_then(norito::json::Value::as_str),
        Some("service_unavailable")
    );

    let block = make_empty_signed_block(1, None, 0);
    let expected_version = block.version().to_string();
    let header = block.header();
    let hash = store_block(&app, block);
    record_committed_block_hash_for_test(&app, header, hash);
    let success = router
        .clone()
        .oneshot(request("text/plain, application/json"))
        .await
        .expect("version response with committed genesis");
    assert_eq!(success.status(), StatusCode::OK);
    assert_eq!(
        success.headers()[axum::http::header::CONTENT_TYPE],
        "text/plain; charset=utf-8"
    );
    let bytes = axum::body::to_bytes(success.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(bytes.as_ref(), expected_version.as_bytes());
    assert_eq!(
        router
            .oneshot(request("application/json"))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_ACCEPTABLE,
        "the successful version representation must still be plain text"
    );
}

#[tokio::test]
async fn readiness_content_negotiation_preserves_consensus_failure() {
    let mut fixture = ReadinessNode::start();
    let app = Arc::clone(&fixture.app);
    // Exercise the response boundary as well as the handler: readiness success
    // is plain text, while the ordinary failure contract is a JSON envelope.
    let router = axum::Router::new()
        .route("/readyz", axum::routing::get(handler_readyz))
        .layer(axum::middleware::from_fn(capture_response_format))
        .layer(axum::middleware::from_fn(coalesce_accept_headers))
        .layer(axum::middleware::from_fn(enforce_typed_error_contract))
        .layer(axum::middleware::from_fn(enforce_json_utf8_charset))
        .with_state(Arc::clone(&app));
    let request = |accept| {
        axum::http::Request::builder()
            .uri("/readyz")
            .header(axum::http::header::ACCEPT, accept)
            .body(Body::empty())
            .expect("readiness request")
    };
    let response = router
        .clone()
        .oneshot(request("text/plain, application/json"))
        .await
        .expect("healthy readiness response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[axum::http::header::CONTENT_TYPE],
        "text/plain; charset=utf-8"
    );
    assert_eq!(
        router
            .clone()
            .oneshot(request("application/json"))
            .await
            .expect("incompatible readiness request")
            .status(),
        StatusCode::NOT_ACCEPTABLE,
        "JSON-only probes cannot negotiate a healthy text readiness response"
    );
    fixture.stop();
    assert_eq!(app.queue.active_len(), 0);
    assert!(!app.sumeragi.as_ref().expect("native handle").ready());
    let response = router
        .oneshot(request("text/plain, application/json"))
        .await
        .expect("pending readiness response");
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "an HTTP listener and empty queue do not establish write readiness"
    );
    assert_eq!(
        response.headers()[axum::http::header::CONTENT_TYPE],
        "application/json; charset=utf-8"
    );
}

/// A real production consensus instance for the HTTP readiness boundary. The
/// transport is disconnected; the driver, genesis execution, Kura and safety
/// records use the node's normal startup path. This observer cannot manufacture
/// a quorum or a committed block merely to make readiness pass.
pub(crate) struct ReadinessNode {
    pub(crate) app: SharedAppState,
    node: Option<iroha_core::sumeragi::node::RunningNode>,
    _directory: tempfile::TempDir,
}

impl ReadinessNode {
    pub(crate) fn start() -> Self {
        Self::start_at_tip(false)
    }

    pub(crate) fn start_at_tip(with_transaction: bool) -> Self {
        use iroha_core::sumeragi::{
            driver::traits::{Frame, Net, NoObserver, SendOutcome},
            node::{NodeConfig, NodeInputs},
            test_chain::{CertifiedTestChain, TestChainConfig},
        };
        struct DisconnectedTransport;
        impl Net for DisconnectedTransport {
            fn send(&self, _: &iroha_sumeragi::types::PublicKey, _: &Frame) -> SendOutcome {
                SendOutcome::Admitted
            }
        }
        let prepared = CertifiedTestChain::prepare(TestChainConfig::new(World::default(), 10_000))
            .expect("original signed genesis and pristine State");
        let genesis = prepared.genesis.block().clone();
        let genesis_account = AccountId::new(prepared.genesis.public_key().clone());
        let state = prepared.state;
        let kura = prepared.kura;
        if with_transaction {
            let mut chain =
                CertifiedTestChain::start(TestChainConfig::new(World::default(), 10_000))
                    .expect("original certified history");
            assert_eq!(chain.genesis(), &genesis, "exact original replay source");
            chain.commit_at(20_000, Vec::new());
            for height in 1..=chain.height() {
                kura.store_block(chain.committed(height).block().clone())
                    .expect("retain original certified wire for startup replay");
            }
        }
        let mut app = mk_app_state_for_tests();
        let directory = tempfile::tempdir().expect("production readiness node files");
        let node_key = KeyPair::from_seed(vec![0xD9; 32], Algorithm::BlsNormal);
        let node = iroha_core::sumeragi::node::start(NodeInputs {
            state: Arc::clone(&state),
            queue: Arc::clone(&app.queue),
            events: tokio::sync::broadcast::channel(16).0,
            net: Arc::new(DisconnectedTransport),
            key_pair: node_key.clone(),
            genesis: Some(genesis),
            beacon_signer: None,
            genesis_account,
            consensus_mode: iroha_data_model::parameter::system::ConsensusMode::Permissioned,
            config: NodeConfig {
                records_dir: directory.path().join("records"),
                installation_log: directory.path().join("keys/installation.log"),
                bodies_dir: directory.path().join("bodies"),
                local: Default::default(),
                assert_fresh_key: true,
                retired_keys: Vec::new(),
            },
            observer: Arc::new(NoObserver),
            driver: Default::default(),
        })
        .expect("production driver startup");
        let app_mut = Arc::get_mut(&mut app).expect("exclusive app fixture");
        app_mut.state = state;
        app_mut.kura = kura;
        app_mut.sumeragi = Some(node.handle());
        app_mut.torii_proxy_bridge_signer = node_key;
        Self {
            app,
            node: Some(node),
            _directory: directory,
        }
    }

    pub(crate) fn stop(&mut self) {
        if let Some(node) = self.node.take() {
            node.driver.shutdown();
        }
    }

    async fn response(&self) -> AxResponse {
        axum::Router::new()
            .route("/readyz", axum::routing::get(handler_readyz))
            .layer(axum::middleware::from_fn(capture_response_format))
            .layer(axum::middleware::from_fn(coalesce_accept_headers))
            .layer(axum::middleware::from_fn(enforce_typed_error_contract))
            .layer(axum::middleware::from_fn(enforce_json_utf8_charset))
            .with_state(Arc::clone(&self.app))
            .oneshot(
                axum::http::Request::builder()
                    .uri("/readyz")
                    .header(axum::http::header::ACCEPT, "text/plain, application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("HTTP readiness response")
    }
}

impl Drop for ReadinessNode {
    fn drop(&mut self) {
        self.stop();
    }
}

#[tokio::test]
async fn readyz_rejects_absent_consensus_driver() {
    let app = mk_app_state_for_tests();
    assert!(app.sumeragi.is_none(), "the refusal fixture has no driver");
    let response = axum::Router::new()
        .route("/readyz", axum::routing::get(handler_readyz))
        .layer(axum::middleware::from_fn(capture_response_format))
        .layer(axum::middleware::from_fn(coalesce_accept_headers))
        .layer(axum::middleware::from_fn(enforce_typed_error_contract))
        .layer(axum::middleware::from_fn(enforce_json_utf8_charset))
        .with_state(app)
        .oneshot(
            axum::http::Request::builder()
                .uri("/readyz")
                .header(axum::http::header::ACCEPT, "text/plain, application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("ordinary readiness HTTP response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.headers()[axum::http::header::CONTENT_TYPE],
        "application/json; charset=utf-8"
    );
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let envelope: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    assert_eq!(
        envelope.get("code").and_then(norito::json::Value::as_str),
        Some("service_unavailable")
    );
}

#[tokio::test]
async fn readyz_rejects_stopped_consensus_driver() {
    let mut fixture = ReadinessNode::start();
    assert_eq!(fixture.response().await.status(), StatusCode::OK);
    fixture.stop();
    assert!(!fixture.app.sumeragi.as_ref().unwrap().ready());
    let response = fixture.response().await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.headers()[axum::http::header::CONTENT_TYPE],
        "application/json; charset=utf-8"
    );
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let envelope: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    assert_eq!(
        envelope.get("code").and_then(norito::json::Value::as_str),
        Some("service_unavailable")
    );
}

#[tokio::test]
async fn readyz_tracks_live_consensus_without_gating_beacon_setup() {
    use iroha_core::state::WorldReadOnly as _;
    let fixture = ReadinessNode::start();
    assert!(
        fixture
            .app
            .state
            .view()
            .world()
            .active_global_beacon_key_session()
            .is_none()
    );
    let handle = fixture.app.sumeragi.as_ref().unwrap();
    assert!(handle.ready());
    assert_eq!(handle.status().unwrap().committed_height, 1);
    let response = fixture.response().await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "beacon installation must be reachable through a live consensus driver"
    );
    assert_eq!(
        response.headers()[axum::http::header::CONTENT_TYPE],
        "text/plain; charset=utf-8"
    );
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap()
            .as_ref(),
        b"Ready"
    );
}

pub fn mk_app_state_for_tests_with_iso_bridge(
    iso: Option<iroha_config::parameters::actual::IsoBridge>,
) -> SharedAppState {
    mk_app_state_for_tests_with_world_and_options(World::default(), iso, None, None, None)
}
pub fn mk_app_state_for_tests_with_options(
    iso: Option<iroha_config::parameters::actual::IsoBridge>,
    deploy_limit: Option<(u32, u32)>,
    norito_rpc: Option<iroha_config::parameters::actual::NoritoRpcTransport>,
    push: Option<iroha_config::parameters::actual::Push>,
) -> SharedAppState {
    mk_app_state_for_tests_with_world_and_options(
        World::default(),
        iso,
        deploy_limit,
        norito_rpc,
        push,
    )
}
pub fn mk_app_state_for_tests_with_world(world: World) -> SharedAppState {
    mk_app_state_for_tests_with_world_and_options(world, None, None, None, None)
}
pub(crate) fn mk_app_state_for_tests_with_world_and_nexus(
    world: World,
    nexus: iroha_config::parameters::actual::Nexus,
) -> SharedAppState {
    mk_app_state_for_tests_with_world_and_options_and_network_id_and_nexus(
        world,
        None,
        None,
        None,
        None,
        "chain".parse().expect("test chain id"),
        crate::signed_query_test_network_id(),
        Some(nexus),
    )
}
#[cfg(feature = "push")]
pub fn mk_app_state_for_tests_with_world_and_push(
    world: World,
    push: iroha_config::parameters::actual::Push,
) -> SharedAppState {
    mk_app_state_for_tests_with_world_and_options(world, None, None, None, Some(push))
}
pub(crate) fn app_auth_test_guard(
    config: crate::app_auth::CanonicalRequestAuthConfig,
) -> impl Drop {
    static TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    struct Guard {
        _lock: MutexGuard<'static, ()>,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            crate::app_auth::configure(crate::app_auth::CanonicalRequestAuthConfig::default())
                .expect("default app-auth config");
        }
    }
    let guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    crate::app_auth::configure(config).expect("valid app-auth test config");
    Guard { _lock: guard }
}
pub(crate) fn world_with_account(account_id: &AccountId) -> World {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(account_id);
    let account = Account::new(account_id.clone()).build(account_id);
    World::with([domain], [account], [])
}
fn bind_uaid_to_dataspace_manifest_for_test(
    world: &mut World,
    uaid: UniversalAccountId,
    dataspace: DataSpaceId,
) {
    let manifest = iroha_data_model::nexus::AssetPermissionManifest {
        version: iroha_data_model::nexus::ManifestVersion::default(),
        uaid,
        dataspace,
        issued_ms: 0,
        activation_epoch: 1,
        expiry_epoch: None,
        entries: Vec::new(),
    };
    let mut record =
        iroha_core::nexus::space_directory::SpaceDirectoryManifestRecord::new(manifest);
    record.lifecycle.mark_activated(1);
    let mut set = iroha_core::nexus::space_directory::SpaceDirectoryManifestSet::default();
    set.upsert(record);
    world
        .space_directory_manifests_mut_for_testing()
        .insert(uaid, set);
}
pub(crate) fn world_with_account_bound_to_dataspace(
    account_id: &AccountId,
    uaid: UniversalAccountId,
    dataspace: DataSpaceId,
) -> World {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(account_id);
    let account = Account::new(account_id.clone())
        .with_uaid(Some(uaid))
        .build(account_id);
    let mut world = World::with([domain], [account], []);
    bind_uaid_to_dataspace_manifest_for_test(&mut world, uaid, dataspace);
    world
}
pub(crate) fn world_with_target_and_caller_bound_to_dataspace(
    target: &AccountId,
    caller: &AccountId,
    uaid: UniversalAccountId,
    dataspace: DataSpaceId,
) -> World {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(target);
    let target_account = Account::new(target.clone())
        .with_uaid(Some(uaid))
        .build(target);
    let caller_account = Account::new(caller.clone()).build(caller);
    let mut world = World::with([domain], [target_account, caller_account], []);
    bind_uaid_to_dataspace_manifest_for_test(&mut world, uaid, dataspace);
    world
}
fn grant_account_permission_for_test(
    app: &SharedAppState,
    authority: &AccountId,
    permission: Permission,
) {
    let next_height = app
        .state
        .latest_block_header_fast()
        .map_or(1, |header| header.height().get().saturating_add(1));
    let header = BlockHeader::new(
        NonZeroU64::new(next_height).expect("non-zero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = app.state.block(header);
    let mut tx = block.transaction();
    tx.world_mut_for_testing()
        .add_account_permission(authority, permission);
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit permission seed");
}
fn seed_asset_definition_for_test(
    app: &SharedAppState,
    asset_definition_id: &iroha_data_model::asset::AssetDefinitionId,
    owning_domain: Option<&DomainId>,
) {
    if let Some(domain_id) = owning_domain
        && app.state.view().world().domain(domain_id).is_err()
    {
        bind_domain_name_for_test(app, &domain_id.to_string());
    }
    let next_height = app
        .state
        .latest_block_header_fast()
        .map_or(1, |header| header.height().get().saturating_add(1));
    let header = BlockHeader::new(
        NonZeroU64::new(next_height).expect("non-zero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = app.state.block(header);
    let mut tx = block.transaction();
    let balance_scope_policy =
        if asset_definition_requires_restricted_balance_policy_for_test(app, owning_domain) {
            AssetBalancePolicy::DataspaceRestricted
        } else {
            AssetBalancePolicy::Global
        };
    if let Some(domain_id) = owning_domain
        && tx.world().domain(domain_id).is_err()
    {
        if tx.world().account(&ALICE_ID).is_err() {
            Register::account(Account::new(ALICE_ID.clone()))
                .execute(&ALICE_ID, &mut tx)
                .expect("seed canonical domain-owner account");
        }
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&ALICE_ID, &mut tx)
            .expect("register the separate owning domain");
    }
    let asset_definition = iroha_data_model::asset::AssetDefinition::numeric(
        asset_definition_id.clone(),
        "asset-definition".to_owned(),
        balance_scope_policy,
        owning_domain.cloned(),
    );
    Register::asset_definition(asset_definition)
        .execute(&ALICE_ID, &mut tx)
        .expect("register asset definition");
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit asset definition seed");
}
fn asset_definition_requires_restricted_balance_policy_for_test(
    app: &SharedAppState,
    owning_domain: Option<&DomainId>,
) -> bool {
    let Some(domain_id) = owning_domain else {
        return false;
    };
    let dataspace_alias = domain_id.dataspace().as_ref();
    let state_view = app.state.view();
    let nexus = state_view.nexus();
    let Some(dataspace_id) = (if dataspace_alias.eq_ignore_ascii_case("universal") {
        Some(DataSpaceId::UNIVERSAL)
    } else {
        nexus
            .dataspace_catalog
            .by_alias(dataspace_alias)
            .map(|entry| entry.id)
    }) else {
        return false;
    };
    dataspace_id != DataSpaceId::UNIVERSAL
        && !nexus.lane_catalog.lanes().iter().any(|lane| {
            lane.dataspace_id == dataspace_id
                && lane.visibility == iroha_data_model::nexus::LaneVisibility::Public
        })
}
fn configure_nexus_fee_admission_for_test(
    app: &mut SharedAppState,
    fee_asset_id: &iroha_data_model::asset::AssetDefinitionId,
    fee_sink_account_id: &AccountId,
) {
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.base_fee = Quantity::from(1_u32);
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    nexus.fees.fee_asset_id = fee_asset_id.to_string();
    nexus.fees.fee_sink_account_id = fee_sink_account_id.to_string();
    let app_state = Arc::get_mut(app).expect("unique app state");
    let state = Arc::get_mut(&mut app_state.state).expect("unique state");
    state.set_nexus(nexus.clone()).expect("apply nexus config");
    let state_view = app_state.state.view();
    app_state.queue.reconfigure_nexus(&nexus, &state_view, None);
}
pub(crate) fn multiple_dataspace_nexus_for_test() -> iroha_config::parameters::actual::Nexus {
    let secondary_dataspace = DataSpaceId::new(1);
    let secondary_lane = LaneId::new(1);
    let lane_catalog = iroha_data_model::nexus::LaneCatalog::new(
        NonZeroU32::new(2).expect("nonzero lane count"),
        vec![
            iroha_data_model::nexus::LaneConfig::default(),
            iroha_data_model::nexus::LaneConfig {
                id: secondary_lane,
                dataspace_id: secondary_dataspace,
                alias: "secondary".to_owned(),
                ..iroha_data_model::nexus::LaneConfig::default()
            },
        ],
    )
    .expect("lane catalog");
    let dataspace_catalog = iroha_data_model::nexus::DataSpaceCatalog::new(vec![
        iroha_data_model::nexus::DataSpaceMetadata::default(),
        iroha_data_model::nexus::DataSpaceMetadata {
            id: secondary_dataspace,
            alias: "secondary".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("dataspace catalog");
    iroha_config::parameters::actual::Nexus {
        lane_config: iroha_config::parameters::actual::LaneConfig::from_catalog(&lane_catalog),
        configured_lane_catalog: lane_catalog.clone(),
        configured_dataspace_catalog: dataspace_catalog.clone(),
        lane_catalog,
        dataspace_catalog,
        ..iroha_config::parameters::actual::Nexus::default()
    }
}
pub(crate) fn private_ingress_nexus_for_test() -> iroha_config::parameters::actual::Nexus {
    let governance_dataspace = DataSpaceId::new(1);
    let governance_lane = LaneId::new(1);
    let restricted_dataspace = DataSpaceId::new(10);
    let restricted_lane = LaneId::new(2);
    let lane_catalog = iroha_data_model::nexus::LaneCatalog::new(
        NonZeroU32::new(3).expect("nonzero lane count"),
        vec![
            iroha_data_model::nexus::LaneConfig::default(),
            iroha_data_model::nexus::LaneConfig {
                id: governance_lane,
                dataspace_id: governance_dataspace,
                alias: "governance".to_owned(),
                visibility: iroha_data_model::nexus::LaneVisibility::Public,
                ..iroha_data_model::nexus::LaneConfig::default()
            },
            iroha_data_model::nexus::LaneConfig {
                id: restricted_lane,
                dataspace_id: restricted_dataspace,
                alias: "restricted".to_owned(),
                visibility: iroha_data_model::nexus::LaneVisibility::Restricted,
                ..iroha_data_model::nexus::LaneConfig::default()
            },
        ],
    )
    .expect("lane catalog");
    let dataspace_catalog = iroha_data_model::nexus::DataSpaceCatalog::new(vec![
        iroha_data_model::nexus::DataSpaceMetadata::default(),
        iroha_data_model::nexus::DataSpaceMetadata {
            id: governance_dataspace,
            alias: "governance".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
        iroha_data_model::nexus::DataSpaceMetadata {
            id: restricted_dataspace,
            alias: "restricted".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("dataspace catalog");
    iroha_config::parameters::actual::Nexus {
        lane_config: iroha_config::parameters::actual::LaneConfig::from_catalog(&lane_catalog),
        configured_lane_catalog: lane_catalog.clone(),
        configured_dataspace_catalog: dataspace_catalog.clone(),
        lane_catalog,
        dataspace_catalog,
        ..iroha_config::parameters::actual::Nexus::default()
    }
}
pub(crate) fn private_ingress_with_offline_foreign_nexus_for_test()
-> iroha_config::parameters::actual::Nexus {
    let local_dataspace = DataSpaceId::new(10);
    let local_lane = LaneId::new(1);
    let foreign_dataspace = DataSpaceId::new(12);
    let foreign_lane = LaneId::new(2);
    let lane_catalog = iroha_data_model::nexus::LaneCatalog::new(
        NonZeroU32::new(3).expect("nonzero lane count"),
        vec![
            iroha_data_model::nexus::LaneConfig::default(),
            iroha_data_model::nexus::LaneConfig {
                id: local_lane,
                dataspace_id: local_dataspace,
                alias: "local-restricted".to_owned(),
                visibility: iroha_data_model::nexus::LaneVisibility::Restricted,
                ..iroha_data_model::nexus::LaneConfig::default()
            },
            iroha_data_model::nexus::LaneConfig {
                id: foreign_lane,
                dataspace_id: foreign_dataspace,
                alias: "foreign-restricted".to_owned(),
                visibility: iroha_data_model::nexus::LaneVisibility::Restricted,
                ..iroha_data_model::nexus::LaneConfig::default()
            },
        ],
    )
    .expect("lane catalog");
    let dataspace_catalog = iroha_data_model::nexus::DataSpaceCatalog::new(vec![
        iroha_data_model::nexus::DataSpaceMetadata::default(),
        iroha_data_model::nexus::DataSpaceMetadata {
            id: local_dataspace,
            alias: "local-restricted".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
        iroha_data_model::nexus::DataSpaceMetadata {
            id: foreign_dataspace,
            alias: "foreign-restricted".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("dataspace catalog");
    iroha_config::parameters::actual::Nexus {
        lane_config: iroha_config::parameters::actual::LaneConfig::from_catalog(&lane_catalog),
        configured_lane_catalog: lane_catalog.clone(),
        configured_dataspace_catalog: dataspace_catalog.clone(),
        lane_catalog,
        dataspace_catalog,
        ..iroha_config::parameters::actual::Nexus::default()
    }
}
pub(crate) fn assert_initial_nexus_catalog_for_test(
    state: &IrohaState,
    expected: &iroha_config::parameters::actual::Nexus,
) {
    let installed = state.nexus_snapshot();
    assert_eq!(installed.lane_config, expected.lane_config);
    assert_eq!(installed.lane_catalog, expected.lane_catalog);
    assert_eq!(installed.dataspace_catalog, expected.dataspace_catalog);
    assert_eq!(
        installed.configured_lane_catalog,
        expected.configured_lane_catalog
    );
    assert_eq!(
        installed.configured_dataspace_catalog,
        expected.configured_dataspace_catalog
    );
}
#[tokio::test]
async fn configured_catalog_fixture_binds_initial_geometry_and_explicit_network() {
    let nexus = private_ingress_nexus_for_test();
    let chain_id: ChainId = "configured-route-fixture".parse().expect("test chain id");
    let network_id = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::new(b"configured-route-fixture-network"),
    ));
    let (state, kura) = IrohaState::new_with_chain_and_network_id_and_pre_genesis_nexus_for_testing(
        World::default(),
        nexus.clone(),
        LiveQueryStore::start_test(),
        chain_id.clone(),
        network_id,
    );
    assert_initial_nexus_catalog_for_test(&state, &nexus);
    assert_eq!(state.chain_id_ref(), &chain_id);
    assert_eq!(state.network_id_ref(), &network_id);
    assert_eq!(
        state.nexus_snapshot().fees.per_instruction_fee,
        Quantity::zero()
    );
    assert_eq!(
        state.nexus_snapshot().fees.per_gas_unit_fee,
        Quantity::zero()
    );
    let view = state.view();
    assert!(std::ptr::eq(view.kura(), kura.as_ref()));
    assert_eq!(view.height(), 0);
    assert_eq!(
        kura.exact_durable_blocks_count()
            .expect("empty durable ledger"),
        0
    );
    IrohaState::preflight_configured_primary_geometry_replay(
        &kura,
        &network_id,
        &nexus.configured_lane_catalog,
    )
    .expect("configured catalog is the authenticated original baseline");
    assert!(matches!(
        IrohaState::preflight_configured_primary_geometry_replay(
            &kura,
            &network_id,
            &iroha_data_model::nexus::LaneCatalog::default(),
        ),
        Err(iroha_core::state::LaneLifecycleError::ConfiguredCatalogBaseline(_))
    ));
    drop(view);
    drop(state);
    drop(kura);

    let app = mk_app_state_for_tests_with_world_and_options_and_network_id_and_nexus(
        World::default(),
        None,
        None,
        None,
        None,
        chain_id.clone(),
        network_id,
        Some(nexus.clone()),
    );
    assert_initial_nexus_catalog_for_test(&app.state, &nexus);
    assert_eq!(app.chain_id.as_ref(), &chain_id);
    assert_eq!(app.state.network_id_ref(), &network_id);
    let view = app.state.view();
    assert!(std::ptr::eq(view.kura(), app.kura.as_ref()));
    assert_eq!(view.height(), 0);
    assert_eq!(
        app.kura
            .exact_durable_blocks_count()
            .expect("empty durable ledger"),
        0
    );
    IrohaState::preflight_configured_primary_geometry_replay(
        &app.kura,
        &network_id,
        &nexus.configured_lane_catalog,
    )
    .expect("Torii retains the exact configured Kura baseline");
    let pipeline = app.state.pipeline_snapshot();
    assert!(pipeline.dynamic_prepass);
    assert!(!pipeline.parallel_overlay);
    assert!(!pipeline.parallel_apply);
    assert!(!pipeline.ready_queue_heap);
    assert_eq!(pipeline.workers, 1);
    let fees = app.state.nexus_snapshot().fees;
    assert_eq!(fees.per_instruction_fee, nexus.fees.per_instruction_fee);
    assert_eq!(fees.per_gas_unit_fee, nexus.fees.per_gas_unit_fee);
}
pub(crate) fn configure_multiple_dataspace_routes_for_test(app: &mut SharedAppState) {
    let nexus = multiple_dataspace_nexus_for_test();
    let app_state = Arc::get_mut(app).expect("unique app state");
    let state = Arc::get_mut(&mut app_state.state).expect("unique state");
    assert_initial_nexus_catalog_for_test(state, &nexus);
    let state_view = app_state.state.view();
    app_state.queue.reconfigure_nexus(&nexus, &state_view, None);
}
pub(crate) fn configure_private_ingress_routes_for_test(
    app: &mut SharedAppState,
) -> (LaneId, DataSpaceId) {
    let nexus_lane = LaneId::new(0);
    let local_validator_keypair = checked_torii_test_ed25519_keypair(
        0xb6,
        "derive private-ingress local validator fixture key",
    );
    let local_peer_keypair =
        checked_torii_test_bls_keypair(0xb7, "derive private-ingress local peer fixture key");
    let local_validator = AccountId::new(local_validator_keypair.public_key().clone());
    let local_peer_id = PeerId::from(local_peer_keypair.public_key().clone());
    let governance_lane = LaneId::new(1);
    let restricted_dataspace = DataSpaceId::new(10);
    let restricted_lane = LaneId::new(2);
    let app_mut = Arc::get_mut(app).expect("unique app state");
    let (online_tx, online_rx) = tokio::sync::watch::channel(std::collections::HashSet::new());
    online_tx
        .send(std::collections::HashSet::from([Peer::new(
            "127.0.0.1:12001".parse().expect("valid local address"),
            local_peer_keypair.public_key().clone(),
        )]))
        .expect("online peers update should succeed");
    app_mut.online_peers = OnlinePeersProvider::new(online_rx);
    app_mut.local_peer_id = Some(local_peer_id.clone());
    let nexus = private_ingress_nexus_for_test();
    let state = Arc::get_mut(&mut app_mut.state).expect("unique state");
    assert_initial_nexus_catalog_for_test(state, &nexus);
    ensure_runtime_peer_binding_for_test(state, &local_validator, &local_peer_keypair, "local");
    {
        let mut topology = state.commit_topology.block();
        topology.clear();
        topology.push(local_peer_id.clone());
        topology.commit();
    }
    install_lane_manifest_registry_for_test(
        state,
        &[
            (
                nexus_lane,
                vec![(local_validator.clone(), local_peer_id.clone())],
            ),
            (
                governance_lane,
                vec![(local_validator.clone(), local_peer_id.clone())],
            ),
            (restricted_lane, vec![(local_validator, local_peer_id)]),
        ],
    );
    let state_view = app_mut.state.view();
    app_mut.queue.reconfigure_nexus(&nexus, &state_view, None);
    (restricted_lane, restricted_dataspace)
}
/// Execute the original local four-validator committee before decorating offline foreign routes.
#[cfg(feature = "app_api")]
pub(crate) fn native_ingress_with_offline_foreign_app_for_test(world: World) -> SharedAppState {
    let local_seeds = [0xb8, 0xc0, 0xc2, 0xc4];
    let foreign_seeds = [0xba, 0xc6, 0xc8, 0xca];
    let members = local_seeds
        .into_iter()
        .chain(foreign_seeds)
        .map(|seed| {
            let account =
                checked_torii_test_ed25519_keypair(seed, "original offline-foreign account");
            let peer =
                checked_torii_test_bls_keypair(seed + 1, "original offline-foreign BLS peer");
            (AccountId::new(account.public_key().clone()), peer)
        })
        .collect::<Vec<_>>();
    let labels = (0..members.len())
        .map(|index| format!("route-fixture-{index}"))
        .collect::<Vec<_>>();
    let mut app = native_ingress_with_registered_route_peers_for_test(
        world,
        private_ingress_with_offline_foreign_nexus_for_test(),
        &members,
        &labels,
    );
    let local_peer = PeerId::new(members[0].1.public_key().clone());
    let app_mut = Arc::get_mut(&mut app).expect("unique executed fixture");
    let (online_tx, online_rx) = tokio::sync::watch::channel(std::collections::HashSet::new());
    online_tx
        .send(std::collections::HashSet::from([Peer::new(
            "127.0.0.1:12001".parse().expect("original local address"),
            members[0].1.public_key().clone(),
        )]))
        .expect("original online peer");
    app_mut.online_peers = OnlinePeersProvider::new(online_rx);
    app_mut.local_peer_id = Some(local_peer.clone());
    app_mut.torii_proxy_bridge_signer = members[0].1.clone();
    let bindings = |members: &[(AccountId, KeyPair)]| {
        members
            .iter()
            .map(|(id, key)| (id.clone(), PeerId::new(key.public_key().clone())))
            .collect::<Vec<_>>()
    };
    install_lane_manifest_registry_for_test(
        &app_mut.state,
        &[
            (LaneId::SINGLE, bindings(&members[..4])),
            (LaneId::new(1), bindings(&members[..4])),
            (LaneId::new(2), bindings(&members[4..])),
        ],
    );
    let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let committee = app
        .state
        .resolve_route_authority(super::lane_authority_route(route))
        .expect("actual executed genesis owns the global route");
    assert_eq!(committee.authority_height(), 3);
    let mut original = bindings(&members[..4])
        .into_iter()
        .map(|(_, peer)| peer)
        .collect::<Vec<_>>();
    original.sort();
    assert_eq!(
        committee.into_validators(),
        original,
        "exact original four BLS voters"
    );
    assert!(super::is_local_authoritative_for_route(app.as_ref(), route));
    for (lane, members) in [
        (LaneId::new(1), &members[..4]),
        (LaneId::new(2), &members[4..]),
    ] {
        let mut expected = bindings(members)
            .into_iter()
            .map(|(_, peer)| peer)
            .collect::<Vec<_>>();
        expected.sort();
        let dataspace = if lane == LaneId::new(1) {
            DataSpaceId::new(10)
        } else {
            DataSpaceId::new(12)
        };
        let committee = app
            .state
            .resolve_lane_committee(super::lane_authority_route(RoutingDecision::new(
                lane, dataspace,
            )))
            .expect("original authenticated lane committee");
        assert_eq!(
            committee.into_validators(),
            expected,
            "original exact four-seat lane committee"
        );
    }
    app
}

pub(crate) fn configure_private_ingress_with_offline_foreign_route_for_test(
    app: &mut SharedAppState,
) -> (RoutingDecision, RoutingDecision) {
    let nexus_lane = LaneId::new(0);
    let local_validator_keypair = checked_torii_test_ed25519_keypair(
        0xb8,
        "derive offline-foreign local validator fixture key",
    );
    let local_peer_keypair =
        checked_torii_test_bls_keypair(0xb9, "derive offline-foreign local peer fixture key");
    let foreign_validator_keypair =
        checked_torii_test_ed25519_keypair(0xba, "derive offline-foreign validator fixture key");
    let foreign_peer_keypair =
        checked_torii_test_bls_keypair(0xbb, "derive offline-foreign peer fixture key");
    let local_validator = AccountId::new(local_validator_keypair.public_key().clone());
    let local_peer_id = PeerId::from(local_peer_keypair.public_key().clone());
    let foreign_validator = AccountId::new(foreign_validator_keypair.public_key().clone());
    let mut local_members = vec![(local_validator.clone(), local_peer_keypair.clone())];
    let mut foreign_members = vec![(foreign_validator, foreign_peer_keypair)];
    for (members, seeds) in [
        (&mut local_members, [0xc0, 0xc2, 0xc4]),
        (&mut foreign_members, [0xc6, 0xc8, 0xca]),
    ] {
        for seed in seeds {
            let validator_key = checked_torii_test_ed25519_keypair(
                seed,
                "derive four-validator route authority fixture key",
            );
            let peer_key = checked_torii_test_bls_keypair(
                seed + 1,
                "derive four-validator route peer fixture key",
            );
            members.push((AccountId::new(validator_key.public_key().clone()), peer_key));
        }
    }
    let local_dataspace = DataSpaceId::new(10);
    let local_lane = LaneId::new(1);
    let foreign_dataspace = DataSpaceId::new(12);
    let foreign_lane = LaneId::new(2);
    let app_mut = Arc::get_mut(app).expect("unique app state");
    let (online_tx, online_rx) = tokio::sync::watch::channel(std::collections::HashSet::new());
    online_tx
        .send(std::collections::HashSet::from([Peer::new(
            "127.0.0.1:12001".parse().expect("valid local address"),
            local_peer_keypair.public_key().clone(),
        )]))
        .expect("online peers update should succeed");
    app_mut.online_peers = OnlinePeersProvider::new(online_rx);
    app_mut.local_peer_id = Some(local_peer_id.clone());
    let nexus = private_ingress_with_offline_foreign_nexus_for_test();
    let state = Arc::get_mut(&mut app_mut.state).expect("unique state");
    assert_initial_nexus_catalog_for_test(state, &nexus);
    for (index, (validator, peer_key)) in local_members.iter().chain(&foreign_members).enumerate() {
        ensure_runtime_peer_binding_for_test(
            state,
            validator,
            peer_key,
            &format!("route-fixture-{index}"),
        );
    }
    let bindings = |members: &[(AccountId, KeyPair)]| {
        members
            .iter()
            .map(|(validator, peer_key)| {
                (
                    validator.clone(),
                    PeerId::from(peer_key.public_key().clone()),
                )
            })
            .collect::<Vec<_>>()
    };
    let local_bindings = bindings(&local_members);
    let foreign_bindings = bindings(&foreign_members);
    {
        let mut topology = state.commit_topology.block();
        topology.clear();
        for (_, peer) in local_bindings.iter().chain(&foreign_bindings) {
            topology.push(peer.clone());
        }
        topology.commit();
    }
    install_lane_manifest_registry_for_test(
        state,
        &[
            (nexus_lane, local_bindings.clone()),
            (local_lane, local_bindings),
            (foreign_lane, foreign_bindings),
        ],
    );
    let state_view = app_mut.state.view();
    app_mut.queue.reconfigure_nexus(&nexus, &state_view, None);
    drop(state_view);
    // The peer bindings activate at height one. A committed journal entry makes
    // the same authority height available to the immutable routing state view.
    let block = make_empty_signed_block(1, None, 0);
    let header = block.header();
    let block_hash = store_block(app, block);
    record_committed_block_hash_for_test(app, header, block_hash);
    for route in [
        RoutingDecision::new(local_lane, local_dataspace),
        RoutingDecision::new(foreign_lane, foreign_dataspace),
    ] {
        let committee = app
            .state
            .resolve_lane_committee(iroha_core::state::LaneAuthorityRoute::new(
                route.lane_id,
                route.dataspace_id,
            ))
            .expect("four-validator fixture authority resolves at the committed height");
        assert_eq!(committee.validators().len(), 4);
    }
    (
        RoutingDecision::new(local_lane, local_dataspace),
        RoutingDecision::new(foreign_lane, foreign_dataspace),
    )
}
fn install_lane_manifest_registry_for_test(
    state: &IrohaState,
    lanes: &[(LaneId, Vec<(AccountId, PeerId)>)],
) {
    let lanes_with_torii_urls = lanes
        .iter()
        .map(|(lane_id, validator_bindings)| {
            (
                *lane_id,
                validator_bindings
                    .iter()
                    .map(|(validator, peer_id)| (validator.clone(), peer_id.clone(), None::<&str>))
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    install_lane_manifest_registry_with_torii_urls_for_test(state, &lanes_with_torii_urls);
}
use crate::test_utils::{AutoscaleLaneCommitteeFixtureV1, pin_autoscale_lane_committee_for_test};
#[test]
fn autoscale_fixture_declares_its_nominal_identity_and_core_frame_projection() {
    use norito::NoritoSchema as _;
    let nominal = "iroha_torii::test_utils::AutoscaleLaneCommitteeFixtureV1";
    let frame = "iroha_core::state::AutoscaleLaneCommitteeV1";
    assert_eq!(AutoscaleLaneCommitteeFixtureV1::nominal_name(), nominal);
    assert_eq!(AutoscaleLaneCommitteeFixtureV1::frame_name(), frame);
    assert_ne!(nominal, frame);
    assert_eq!(
        Vec::<AutoscaleLaneCommitteeFixtureV1>::nominal_name(),
        format!("alloc::vec::Vec<{nominal}>"),
    );
    assert_eq!(
        norito::schema::identity::frame_hash::<AutoscaleLaneCommitteeFixtureV1>(),
        norito::core::schema_hash_for_name(frame),
    );
    let keys = (0xa1_u8..=0xa4)
        .map(|seed| checked_torii_test_bls_keypair(seed, "declared autoscale fixture identity"))
        .collect::<Vec<_>>();
    let mut lane = iroha_data_model::nexus::LaneConfig::default();
    let peers = pin_autoscale_lane_committee_for_test(&mut lane, &keys);
    assert_eq!(peers.len(), 4);
    let bytes = hex::decode(&lane.metadata[iroha_data_model::nexus::AUTOSCALE_META_COMMITTEE])
        .expect("actual fixture committee frame");
    let header = norito::core::Header::read(bytes.as_slice()).unwrap();
    assert_eq!(header.schema, norito::core::schema_hash_for_name(frame));
}
fn install_lane_manifest_registry_with_torii_urls_for_test(
    state: &IrohaState,
    lanes: &[(LaneId, Vec<(AccountId, PeerId, Option<&str>)>)],
) {
    static MANIFEST_ROOT_SEQ: AtomicUsize = AtomicUsize::new(0);
    let nexus = state.nexus_snapshot();
    let manifest_root_seq = MANIFEST_ROOT_SEQ.fetch_add(1, Ordering::Relaxed);
    let manifest_root = std::env::temp_dir().join(format!(
        "iroha-torii-manifests-{}-{}-{manifest_root_seq}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be valid")
            .as_nanos()
    ));
    std::fs::create_dir_all(&manifest_root).expect("create manifest directory");
    for (lane_id, validator_bindings) in lanes {
        let alias = nexus
            .lane_catalog
            .lanes()
            .iter()
            .find(|lane| lane.id == *lane_id)
            .map(|lane| lane.alias.clone())
            .unwrap_or_else(|| format!("lane-{}", lane_id.as_u32()));
        let validators_json = validator_bindings
            .iter()
            .map(|(validator, peer_id, torii_url)| {
                let torii_url_json = torii_url
                    .map(|url| format!(r#","torii_url":"{url}""#))
                    .unwrap_or_default();
                format!(r#"{{"validator":"{validator}","peer_id":"{peer_id}"{torii_url_json}}}"#)
            })
            .collect::<Vec<_>>()
            .join(", ");
        let manifest = format!(
            r#"{{"lane":"{alias}","governance":"parliament","version":1,"validators":[{validators_json}],"quorum":1}}"#
        );
        std::fs::write(
            manifest_root.join(format!("{alias}.manifest.json")),
            manifest,
        )
        .expect("write manifest");
    }
    let mut governance_modules = std::collections::BTreeMap::new();
    governance_modules.insert(
        "parliament".to_owned(),
        iroha_config::parameters::actual::GovernanceModule::default(),
    );
    let governance_catalog = iroha_config::parameters::actual::GovernanceCatalog {
        default_module: None,
        modules: governance_modules,
    };
    let registry_cfg = iroha_config::parameters::actual::LaneRegistry {
        manifest_directory: Some(manifest_root),
        ..iroha_config::parameters::actual::LaneRegistry::default()
    };
    let registry = std::sync::Arc::new(
        iroha_core::governance::manifest::LaneManifestRegistry::from_config(
            &nexus.lane_catalog,
            &governance_catalog,
            &registry_cfg,
        ),
    );
    state.install_lane_manifests_for_testing(&registry);
}
fn ensure_runtime_peer_binding_for_test(
    state: &mut IrohaState,
    validator: &AccountId,
    peer_keypair: &KeyPair,
    consensus_label: &str,
) {
    let mut sumeragi_params = state.view().world().parameters().sumeragi().clone();
    sumeragi_params.key_activation_lead_blocks = 0;
    state.set_sumeragi_parameters(&sumeragi_params);
    let next_height = state
        .latest_block_header_fast()
        .map_or(1, |header| header.height().get().saturating_add(1));
    let header = BlockHeader::new(
        NonZeroU64::new(next_height).expect("non-zero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut tx = block.transaction();
    if state.view().world().account(validator).is_err() {
        Register::account(Account::new(validator.clone()))
            .execute(&ALICE_ID, &mut tx)
            .expect("register validator authority account");
    }
    let manage_consensus_keys = Permission::from(CanManageConsensusKeys);
    Grant::account_permission(manage_consensus_keys, validator.clone())
        .execute(validator, &mut tx)
        .expect("grant manage consensus keys");
    let peer_id = PeerId::from(peer_keypair.public_key().clone());
    let pop = iroha_crypto::bls_normal_pop_prove(peer_keypair.private_key())
        .expect("PoP prove for peer keypair");
    let consensus_pop = pop.clone();
    RegisterPeerWithPop::new(peer_id.clone(), pop)
        .execute(validator, &mut tx)
        .expect("peer registration");
    for role in [ConsensusKeyRole::Validator, ConsensusKeyRole::Committee] {
        let consensus_id = ConsensusKeyId::new(role, consensus_label);
        let consensus_record = ConsensusKeyRecord {
            id: consensus_id.clone(),
            public_key: peer_keypair.public_key().clone(),
            pop: Some(consensus_pop.clone()),
            activation_height: next_height,
            expiry_height: None,
            replaces: None,
            status: ConsensusKeyStatus::Active,
        };
        RegisterConsensusKey {
            id: consensus_id,
            record: consensus_record,
        }
        .execute(validator, &mut tx)
        .expect("consensus key registration");
    }
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit runtime peer binding");
}
#[derive(Default)]
struct CapturingIterableQueryExecutor {
    query: Mutex<Option<iroha_data_model::query::QueryWithParams>>,
}
impl CapturingIterableQueryExecutor {
    fn into_query(self) -> iroha_data_model::query::QueryWithParams {
        self.query
            .into_inner()
            .expect("capture mutex should not be poisoned")
            .expect("query builder should have captured a query")
    }
}
impl iroha_data_model::query::builder::QueryExecutor for CapturingIterableQueryExecutor {
    type Cursor = ();
    type Error = iroha_data_model::query::builder::TypedBatchDowncastError;
    fn execute_singular_query(
        &self,
        _query: iroha_data_model::query::SingularQueryBox,
    ) -> Result<iroha_data_model::query::SingularQueryOutputBox, Self::Error> {
        unreachable!("capturing executor should only be used for iterable queries")
    }
    fn start_query(
        &self,
        query: iroha_data_model::query::QueryWithParams,
    ) -> Result<
        (
            iroha_data_model::query::QueryOutputBatchBoxTuple,
            Option<u64>,
            Option<Self::Cursor>,
        ),
        Self::Error,
    > {
        *self.query.lock().expect("capture mutex should lock") = Some(query);
        Err(
            iroha_data_model::query::builder::TypedBatchDowncastError::ColumnCountMismatch {
                expected: 1,
                actual: 0,
            },
        )
    }
    fn continue_query(
        _cursor: Self::Cursor,
    ) -> Result<
        (
            iroha_data_model::query::QueryOutputBatchBoxTuple,
            Option<u64>,
            Option<Self::Cursor>,
        ),
        Self::Error,
    > {
        unreachable!("capturing executor should not continue queries")
    }
}
fn build_find_triggers_query_for_test() -> iroha_data_model::query::QueryWithParams {
    let executor = CapturingIterableQueryExecutor::default();
    let _ = iroha_data_model::query::builder::QueryBuilder::new(
        &executor,
        iroha_data_model::query::trigger::prelude::FindTriggers,
    )
    .execute();
    executor.into_query()
}
fn build_find_active_trigger_ids_query_for_test() -> iroha_data_model::query::QueryWithParams {
    let executor = CapturingIterableQueryExecutor::default();
    let _ = iroha_data_model::query::builder::QueryBuilder::new(
        &executor,
        iroha_data_model::query::trigger::prelude::FindActiveTriggerIds,
    )
    .execute();
    executor.into_query()
}
pub(crate) fn build_find_account_ids_query_for_test() -> iroha_data_model::query::QueryWithParams {
    let executor = CapturingIterableQueryExecutor::default();
    let _ = iroha_data_model::query::builder::QueryBuilder::new(
        &executor,
        iroha_data_model::query::account::prelude::FindAccountIds,
    )
    .execute();
    executor.into_query()
}
fn build_find_peers_query_for_test() -> iroha_data_model::query::QueryWithParams {
    let executor = CapturingIterableQueryExecutor::default();
    let _ = iroha_data_model::query::builder::QueryBuilder::new(
        &executor,
        iroha_data_model::query::peer::prelude::FindPeers,
    )
    .execute();
    executor.into_query()
}
fn build_find_permissions_by_account_query_for_test(
    account_id: AccountId,
) -> iroha_data_model::query::QueryWithParams {
    let executor = CapturingIterableQueryExecutor::default();
    let _ = iroha_data_model::query::builder::QueryBuilder::new(
        &executor,
        iroha_data_model::prelude::FindPermissionsByAccountId::new(account_id),
    )
    .execute();
    executor.into_query()
}
fn build_find_roles_by_account_query_for_test(
    account_id: AccountId,
) -> iroha_data_model::query::QueryWithParams {
    let executor = CapturingIterableQueryExecutor::default();
    let _ = iroha_data_model::query::builder::QueryBuilder::new(
        &executor,
        iroha_data_model::prelude::FindRolesByAccountId::new(account_id),
    )
    .execute();
    executor.into_query()
}
fn build_find_domains_by_account_query_for_test(
    account_id: AccountId,
) -> iroha_data_model::query::QueryWithParams {
    let executor = CapturingIterableQueryExecutor::default();
    let _ = iroha_data_model::query::builder::QueryBuilder::new(
        &executor,
        iroha_data_model::prelude::FindDomainsByAccountId::new(account_id),
    )
    .execute();
    executor.into_query()
}
fn build_find_assets_by_account_query_for_test(
    account_id: AccountId,
) -> iroha_data_model::query::QueryWithParams {
    let executor = CapturingIterableQueryExecutor::default();
    let _ = iroha_data_model::query::builder::QueryBuilder::new(
        &executor,
        iroha_data_model::prelude::FindAssetsByAccountId::new(account_id),
    )
    .execute();
    executor.into_query()
}
fn build_find_accounts_with_asset_query_for_test(
    asset_definition_id: iroha_data_model::asset::AssetDefinitionId,
) -> iroha_data_model::query::QueryWithParams {
    let executor = CapturingIterableQueryExecutor::default();
    let _ = iroha_data_model::query::builder::QueryBuilder::new(
        &executor,
        iroha_data_model::query::account::prelude::FindAccountsWithAsset::new(asset_definition_id),
    )
    .execute();
    executor.into_query()
}
fn build_find_nfts_by_account_query_for_test(
    account_id: AccountId,
) -> iroha_data_model::query::QueryWithParams {
    let executor = CapturingIterableQueryExecutor::default();
    let _ = iroha_data_model::query::builder::QueryBuilder::new(
        &executor,
        iroha_data_model::prelude::FindNftsByAccountId::new(account_id),
    )
    .execute();
    executor.into_query()
}
fn build_find_transactions_query_for_test() -> iroha_data_model::query::QueryWithParams {
    let executor = CapturingIterableQueryExecutor::default();
    let _ = iroha_data_model::query::builder::QueryBuilder::new(
        &executor,
        iroha_data_model::query::transaction::prelude::FindTransactions::new(),
    )
    .execute();
    executor.into_query()
}
fn build_exact_transaction_details_query_for_test(
    entrypoint_hash: HashOf<TransactionEntrypoint>,
) -> iroha_data_model::query::QueryWithParams {
    use iroha_data_model::query::{CommittedTxFilters, dsl::CompoundPredicate};
    let executor = CapturingIterableQueryExecutor::default();
    let _ = iroha_data_model::query::builder::QueryBuilder::new(
        &executor,
        iroha_data_model::query::transaction::prelude::FindTransactions::new(),
    )
    .filter(CompoundPredicate::from_filters(CommittedTxFilters {
        entry_eq: Some(entrypoint_hash),
        ..CommittedTxFilters::default()
    }))
    .execute();
    executor.into_query()
}
fn assert_permissions_query_targets_account(
    query: &iroha_data_model::query::QueryWithParams,
    account_id: &AccountId,
) {
    use iroha_data_model::{prelude::FindPermissionsByAccountId, query::QueryItemKind};
    let (item_kind, _, _, payload) = query.parts();
    assert_eq!(item_kind, QueryItemKind::Permission);
    let decoded = super::decode_query_payload::<FindPermissionsByAccountId>(payload)
        .expect("permissions query payload should decode");
    assert_eq!(decoded.account_id(), account_id);
}
fn assert_roles_query_targets_account(
    query: &iroha_data_model::query::QueryWithParams,
    account_id: &AccountId,
) {
    use iroha_data_model::{prelude::FindRolesByAccountId, query::QueryItemKind};
    let (item_kind, _, _, payload) = query.parts();
    assert_eq!(item_kind, QueryItemKind::RoleId);
    let decoded = super::decode_query_payload::<FindRolesByAccountId>(payload)
        .expect("roles query payload should decode");
    assert_eq!(decoded.account_id(), account_id);
}
fn assert_domains_query_targets_account(
    query: &iroha_data_model::query::QueryWithParams,
    account_id: &AccountId,
) {
    use iroha_data_model::{prelude::FindDomainsByAccountId, query::QueryItemKind};
    let (item_kind, _, _, payload) = query.parts();
    assert_eq!(item_kind, QueryItemKind::Domain);
    let decoded = super::decode_query_payload::<FindDomainsByAccountId>(payload)
        .expect("domains query payload should decode");
    assert_eq!(decoded.account_id(), account_id);
}
fn assert_assets_query_targets_account(
    query: &iroha_data_model::query::QueryWithParams,
    account_id: &AccountId,
) {
    use iroha_data_model::{prelude::FindAssetsByAccountId, query::QueryItemKind};
    let (item_kind, _, _, payload) = query.parts();
    assert_eq!(item_kind, QueryItemKind::Asset);
    let decoded = super::decode_query_payload::<FindAssetsByAccountId>(payload)
        .expect("assets query payload should decode");
    assert_eq!(decoded.account_id(), account_id);
}
fn assert_accounts_with_asset_query_targets_domain(
    query: &iroha_data_model::query::QueryWithParams,
    asset_definition_id: &iroha_data_model::asset::AssetDefinitionId,
) {
    use iroha_data_model::{prelude::FindAccountsWithAsset, query::QueryItemKind};
    let (item_kind, _, _, payload) = query.parts();
    assert_eq!(item_kind, QueryItemKind::Account);
    let decoded = super::decode_query_payload::<FindAccountsWithAsset>(payload)
        .expect("accounts-with-asset query payload should decode");
    assert_eq!(decoded.asset_definition_id(), asset_definition_id);
}
fn assert_nfts_query_targets_account(
    query: &iroha_data_model::query::QueryWithParams,
    account_id: &AccountId,
) {
    use iroha_data_model::{prelude::FindNftsByAccountId, query::QueryItemKind};
    let (item_kind, _, _, payload) = query.parts();
    assert_eq!(item_kind, QueryItemKind::Nft);
    let decoded = super::decode_query_payload::<FindNftsByAccountId>(payload)
        .expect("nfts query payload should decode");
    assert_eq!(decoded.account_id(), account_id);
}
pub(crate) fn signed_find_triggers_query_for_test(
    authority: AccountId,
    key_pair: &KeyPair,
) -> iroha_data_model::query::SignedQuery {
    authorize_query_for_test(
        iroha_data_model::query::QueryRequest::Start(build_find_triggers_query_for_test()),
        authority,
    )
    .sign(key_pair)
}
fn signed_find_active_trigger_ids_query_for_test(
    authority: AccountId,
    key_pair: &KeyPair,
) -> iroha_data_model::query::SignedQuery {
    authorize_query_for_test(
        iroha_data_model::query::QueryRequest::Start(
            build_find_active_trigger_ids_query_for_test(),
        ),
        authority,
    )
    .sign(key_pair)
}
fn request_for_test(
    authority: &AccountId,
    request: iroha_data_model::query::QueryRequest,
) -> iroha_data_model::query::QueryRequestWithAuthority {
    authorize_query_for_test(request, authority.clone())
}
fn roundtrip_request_for_test(
    authority: &AccountId,
    request: iroha_data_model::query::QueryRequest,
) -> iroha_data_model::query::QueryRequestWithAuthority {
    let request = request_for_test(authority, request);
    norito::decode_from_bytes(
        &norito::to_bytes(&request).expect("query request should encode deterministically"),
    )
    .expect("query request should decode deterministically")
}
#[cfg(feature = "app_api")]
pub(crate) fn bind_account_alias_for_test(
    app: &SharedAppState,
    account_id: &AccountId,
    alias: &str,
) {
    let dataspace_catalog = app.state.nexus_snapshot().dataspace_catalog.clone();
    let label =
        iroha_data_model::account::rekey::AccountAlias::from_literal(alias, &dataspace_catalog)
            .expect("valid account alias");
    let next_height = app
        .state
        .latest_block_header_fast()
        .map_or(1, |header| header.height().get().saturating_add(1));
    let header = BlockHeader::new(
        NonZeroU64::new(next_height).expect("non-zero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = app.state.block(header);
    let mut tx = block.transaction();
    let world = tx.world_mut_for_testing();
    let selector = iroha_core::sns::selector_for_account_alias(&label, &dataspace_catalog)
        .expect("account alias selector");
    let account_address =
        AccountAddress::from_account_id(account_id).expect("address from account id");
    let record = iroha_data_model::sns::NameRecordV1::new(
        selector.clone(),
        account_id.clone(),
        vec![iroha_data_model::sns::NameControllerV1::account(
            &account_address,
        )],
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        iroha_model_base::metadata::Metadata::default(),
    );
    world
        .account_aliases_mut_for_testing()
        .insert(label.clone(), account_id.clone());
    let mut labels = world
        .account_aliases_by_account_mut_for_testing()
        .get(account_id)
        .cloned()
        .unwrap_or_default();
    labels.insert(label.clone());
    world
        .account_aliases_by_account_mut_for_testing()
        .insert(account_id.clone(), labels);
    world.replace_account_rekey_record_for_testing(
        iroha_data_model::account::rekey::AccountRekeyRecord::new(label, account_id.clone()),
    );
    world.smart_contract_state_mut_for_testing().insert(
        iroha_core::sns::record_storage_key(&selector),
        norito::codec::Encode::encode(&record),
    );
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit account alias for test");
}
#[cfg(feature = "app_api")]
pub(crate) fn bind_dynamic_account_alias_for_test(
    app: &SharedAppState,
    account_id: &AccountId,
    alias_literal: &str,
    dataspace_id: DataSpaceId,
) {
    let canonical_name = alias_literal
        .parse::<iroha_data_model::alias_setup::AccountAliasName>()
        .expect("canonical dynamic account alias");
    let label = AccountAlias::new(
        canonical_name.label.clone(),
        canonical_name.domain.clone().map(AccountAliasDomain::new),
        dataspace_id,
    );
    let dataspace_selector =
        iroha_core::sns::selector_for_dataspace_alias(canonical_name.dataspace.as_ref())
            .expect("dynamic dataspace selector");
    // Account selectors carry the canonical scoped alias, whose separators are
    // deliberately excluded by the generic DNS-label constructor.
    let alias_selector = iroha_data_model::sns::NameSelectorV1 {
        version: iroha_data_model::sns::NameSelectorV1::VERSION,
        suffix_id: iroha_data_model::sns::ACCOUNT_ALIAS_SUFFIX_ID,
        label: canonical_name.canonical_text(),
    };
    let account_address =
        AccountAddress::from_account_id(account_id).expect("address from account id");
    let controllers = vec![iroha_data_model::sns::NameControllerV1::account(
        &account_address,
    )];
    let mut dataspace_metadata = iroha_model_base::metadata::Metadata::default();
    dataspace_metadata.insert(
        iroha_core::sns::SNS_DATASPACE_ID_METADATA_KEY
            .parse()
            .expect("dataspace id metadata key"),
        iroha_primitives::json::Json::new(dataspace_id.as_u64()),
    );
    let dataspace_record = iroha_data_model::sns::NameRecordV1::new(
        dataspace_selector.clone(),
        account_id.clone(),
        controllers.clone(),
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        dataspace_metadata,
    );
    let alias_record = iroha_data_model::sns::NameRecordV1::new(
        alias_selector.clone(),
        account_id.clone(),
        controllers,
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        iroha_model_base::metadata::Metadata::default(),
    );
    let next_height = app
        .state
        .latest_block_header_fast()
        .map_or(1, |header| header.height().get().saturating_add(1));
    let header = BlockHeader::new(
        NonZeroU64::new(next_height).expect("non-zero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = app.state.block(header);
    let mut tx = block.transaction();
    let world = tx.world_mut_for_testing();
    world
        .account_aliases_mut_for_testing()
        .insert(label.clone(), account_id.clone());
    let mut labels = world
        .account_aliases_by_account_mut_for_testing()
        .get(account_id)
        .cloned()
        .unwrap_or_default();
    labels.insert(label.clone());
    world
        .account_aliases_by_account_mut_for_testing()
        .insert(account_id.clone(), labels);
    world.replace_account_rekey_record_for_testing(
        iroha_data_model::account::rekey::AccountRekeyRecord::new(label, account_id.clone()),
    );
    world.smart_contract_state_mut_for_testing().insert(
        iroha_core::sns::record_storage_key(&dataspace_selector),
        norito::codec::Encode::encode(&dataspace_record),
    );
    world.smart_contract_state_mut_for_testing().insert(
        iroha_core::sns::record_storage_key(&alias_selector),
        norito::codec::Encode::encode(&alias_record),
    );
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit dynamic account alias for test");
}
#[cfg(feature = "app_api")]
pub(crate) fn bind_contract_alias_for_test(
    app: &SharedAppState,
    contract_address: &iroha_data_model::smart_contract::ContractAddress,
    alias: &str,
) {
    let contract_alias = iroha_data_model::smart_contract::ContractAlias::from_str(alias)
        .expect("valid contract alias");
    let header = BlockHeader::new(
        NonZeroU64::new(1).expect("non-zero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = app.state.block(header);
    let mut tx = block.transaction();
    tx.world_mut_for_testing()
        .bind_active_contract_subject_for_testing(
            contract_address.clone(),
            iroha_crypto::Hash::new(b"Torii contract alias identity fixture"),
        );
    tx.world_mut_for_testing()
        .bind_contract_alias(contract_address, contract_alias, None, None, 0)
        .expect("bind contract alias");
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit contract alias for test");
}
pub(crate) fn bind_domain_name_for_test(app: &SharedAppState, literal: &str) {
    bind_domain_name_for_test_with_status(app, literal, iroha_data_model::sns::NameStatus::Active);
}
pub(crate) fn bind_domain_name_for_test_with_status(
    app: &SharedAppState,
    literal: &str,
    status: iroha_data_model::sns::NameStatus,
) {
    let domain_id = DomainId::parse_fully_qualified(literal).expect("valid domain literal");
    let next_height = app
        .state
        .latest_block_header_fast()
        .map_or(1, |header| header.height().get().saturating_add(1));
    let header = BlockHeader::new(
        NonZeroU64::new(next_height).expect("non-zero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = app.state.block(header);
    let mut tx = block.transaction();
    let selector = iroha_core::sns::selector_for_domain(&domain_id).expect("domain selector");
    let owner = ALICE_ID.clone();
    let owner_address = AccountAddress::from_account_id(&owner).expect("owner address");
    let mut record = iroha_data_model::sns::NameRecordV1::new(
        selector.clone(),
        owner,
        vec![iroha_data_model::sns::NameControllerV1::account(
            &owner_address,
        )],
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        iroha_model_base::metadata::Metadata::default(),
    );
    record.status = status;
    tx.world_mut_for_testing()
        .smart_contract_state_mut_for_testing()
        .insert(
            iroha_core::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&record),
        );
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit domain alias for test");
}
pub(crate) fn signed_app_headers(
    account: &AccountId,
    key_pair: &KeyPair,
    method: &axum::http::Method,
    uri: &axum::http::Uri,
    body: &[u8],
) -> HeaderMap {
    signed_app_headers_for_network(
        &crate::signed_query_test_network_id(),
        account,
        key_pair,
        method,
        uri,
        body,
    )
}
pub(crate) fn signed_network_app_headers(
    network_id: &NetworkId,
    account: &AccountId,
    key_pair: &KeyPair,
    method: &axum::http::Method,
    uri: &axum::http::Uri,
    body: &[u8],
) -> HeaderMap {
    signed_app_headers_for_network(network_id, account, key_pair, method, uri, body)
}
pub(crate) fn foreign_network_signed_app_fixture(
    method: &axum::http::Method,
    uri: &axum::http::Uri,
    body: &[u8],
    key_seed: u8,
    network_marker: u8,
) -> (SharedAppState, HeaderMap) {
    let key_pair = checked_torii_test_ed25519_keypair(
        key_seed,
        "derive foreign-network Torii auth fixture key",
    );
    let account = AccountId::new(key_pair.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&account));
    let foreign_network =
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([network_marker; Hash::LENGTH]),
        ));
    let headers =
        signed_network_app_headers(&foreign_network, &account, &key_pair, method, uri, body);
    (app, headers)
}
fn signed_app_headers_for_network(
    network_id: &NetworkId,
    account: &AccountId,
    key_pair: &KeyPair,
    method: &axum::http::Method,
    uri: &axum::http::Uri,
    body: &[u8],
) -> HeaderMap {
    static TEST_NONCE_SEQ: LazyLock<std::sync::atomic::AtomicU64> =
        LazyLock::new(|| std::sync::atomic::AtomicU64::new(0));
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_millis() as u64;
    let nonce_seq = TEST_NONCE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nonce = format!("lib-test-{timestamp_ms}-{nonce_seq}");
    let message = crate::canonical_network_request_signature_message(
        network_id,
        method,
        uri,
        body,
        timestamp_ms,
        &nonce,
    )
    .expect("canonical test request is within V1 limits");
    let signature =
        checked_torii_test_signature(key_pair, &message, "sign Torii signed-app-header fixture");
    let mut headers = HeaderMap::new();
    headers.insert(
        crate::HEADER_ACCOUNT,
        account
            .to_canonical_hex()
            .expect("canonical account header")
            .parse()
            .expect("account header"),
    );
    headers.insert(
        crate::HEADER_SIGNATURE,
        crate::signature_header_value(&signature)
            .expect("encode valid signature header")
            .parse()
            .expect("signature header"),
    );
    headers.insert(
        crate::HEADER_TIMESTAMP_MS,
        timestamp_ms.to_string().parse().expect("timestamp header"),
    );
    headers.insert(crate::HEADER_NONCE, nonce.parse().expect("nonce header"));
    headers
}
fn checked_torii_test_signature(
    key_pair: &KeyPair,
    message: &[u8],
    context: &'static str,
) -> Signature {
    Signature::try_new(key_pair.private_key(), message).expect(context)
}
fn checked_torii_test_keypair(
    seed: Vec<u8>,
    algorithm: Algorithm,
    context: &'static str,
) -> KeyPair {
    KeyPair::try_from_seed(seed, algorithm).expect(context)
}
fn checked_torii_test_keypair_from_seed_byte(
    seed: u8,
    algorithm: Algorithm,
    context: &'static str,
) -> KeyPair {
    checked_torii_test_keypair(vec![seed; 32], algorithm, context)
}
pub(crate) fn checked_torii_test_ed25519_keypair(seed: u8, context: &'static str) -> KeyPair {
    checked_torii_test_keypair_from_seed_byte(seed, Algorithm::Ed25519, context)
}
fn checked_torii_test_bls_keypair(seed: u8, context: &'static str) -> KeyPair {
    checked_torii_test_keypair_from_seed_byte(seed, Algorithm::BlsNormal, context)
}
fn checked_torii_test_peer_id(seed: u8, context: &'static str) -> PeerId {
    PeerId::from(
        checked_torii_test_ed25519_keypair(seed, context)
            .public_key()
            .clone(),
    )
}
pub(crate) fn checked_torii_test_account_id(seed: u8, context: &'static str) -> AccountId {
    AccountId::new(
        checked_torii_test_ed25519_keypair(seed, context)
            .public_key()
            .clone(),
    )
}
#[test]
fn checked_torii_test_keypair_rejects_all_zero_seed_material() {
    assert!(
        KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
        "checked Torii fixtures must reject invalid Ed25519 seed material"
    );
    assert!(
        KeyPair::try_from_seed(vec![0; 32], Algorithm::Secp256k1).is_err(),
        "checked Torii fixtures must reject invalid secp256k1 seed material"
    );
}
fn checked_torii_test_transaction(
    builder: TransactionBuilder,
    keypair: &KeyPair,
    context: &'static str,
) -> SignedTransaction {
    builder.try_sign(keypair.private_key()).expect(context)
}
fn checked_torii_test_block_signature(
    signatory_index: u64,
    keypair: &KeyPair,
    header: &BlockHeader,
    context: &'static str,
) -> BlockSignature {
    BlockSignature::new(
        signatory_index,
        SignatureOf::try_from_hash(keypair.private_key(), header.hash()).expect(context),
    )
}
#[test]
fn checked_torii_test_block_signature_verifies_and_rejects_wrong_key() {
    let keypair = checked_torii_test_bls_keypair(0xb1, "derive Torii block signature fixture key");
    let header = BlockHeader::new(
        NonZeroU64::new(9).expect("nonzero height"),
        None,
        None,
        0,
        0,
    );
    let signature =
        checked_torii_test_block_signature(0, &keypair, &header, "sign Torii block fixture");
    signature
        .signature()
        .verify_hash(keypair.public_key(), header.hash())
        .expect("checked Torii block fixture signature verifies");
    let wrong_key =
        checked_torii_test_bls_keypair(0xb2, "derive wrong Torii block signature fixture key");
    signature
        .signature()
        .verify_hash(wrong_key.public_key(), header.hash())
        .expect_err("checked Torii block fixture signature rejects wrong key");
}
fn mk_app_state_for_tests_with_world_and_options(
    world: World,
    iso: Option<iroha_config::parameters::actual::IsoBridge>,
    deploy_limit: Option<(u32, u32)>,
    norito_rpc: Option<iroha_config::parameters::actual::NoritoRpcTransport>,
    push: Option<iroha_config::parameters::actual::Push>,
) -> SharedAppState {
    let chain_id: ChainId = "chain".parse().unwrap();
    mk_app_state_for_tests_with_world_and_options_and_chain_id(
        world,
        iso,
        deploy_limit,
        norito_rpc,
        push,
        chain_id,
    )
}
fn mk_app_state_for_tests_with_world_and_options_and_chain_id(
    world: World,
    iso: Option<iroha_config::parameters::actual::IsoBridge>,
    deploy_limit: Option<(u32, u32)>,
    norito_rpc: Option<iroha_config::parameters::actual::NoritoRpcTransport>,
    push: Option<iroha_config::parameters::actual::Push>,
    chain_id: ChainId,
) -> SharedAppState {
    mk_app_state_for_tests_with_world_and_options_and_network_id(
        world,
        iso,
        deploy_limit,
        norito_rpc,
        push,
        chain_id,
        crate::signed_query_test_network_id(),
    )
}
fn mk_app_state_for_tests_with_world_and_options_and_network_id(
    world: World,
    iso: Option<iroha_config::parameters::actual::IsoBridge>,
    deploy_limit: Option<(u32, u32)>,
    norito_rpc: Option<iroha_config::parameters::actual::NoritoRpcTransport>,
    push: Option<iroha_config::parameters::actual::Push>,
    chain_id: ChainId,
    network_id: NetworkId,
) -> SharedAppState {
    mk_app_state_for_tests_with_world_and_options_and_network_id_and_nexus(
        world,
        iso,
        deploy_limit,
        norito_rpc,
        push,
        chain_id,
        network_id,
        None,
    )
}
fn mk_app_state_for_tests_with_world_and_options_and_network_id_and_nexus(
    mut world: World,
    iso: Option<iroha_config::parameters::actual::IsoBridge>,
    deploy_limit: Option<(u32, u32)>,
    norito_rpc: Option<iroha_config::parameters::actual::NoritoRpcTransport>,
    push: Option<iroha_config::parameters::actual::Push>,
    chain_id: ChainId,
    network_id: NetworkId,
    intended_nexus: Option<iroha_config::parameters::actual::Nexus>,
) -> SharedAppState {
    // These synthetic routing fixtures model a Global root unless their caller explicitly
    // supplied another root (or malformed metadata for a rejection test). An absent root
    // must never gain Global authority in production routing.
    if !world
        .view()
        .parameters()
        .custom()
        .contains_key(&iroha_data_model::parameter::system::consensus_metadata::handshake_meta_id())
    {
        crate::test_utils::bind_fixture_root(
            &mut world,
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        );
    }
    // Minimal core state
    let _ = &push;
    let query_handle = LiveQueryStore::start_test();
    let has_configured_catalog = intended_nexus.is_some();
    let (state_inner, kura) = if let Some(nexus) = intended_nexus {
        let (mut state, kura) =
            IrohaState::new_with_chain_and_network_id_and_pre_genesis_nexus_for_testing(
                world,
                nexus.clone(),
                query_handle.clone(),
                chain_id.clone(),
                network_id,
            );
        // Retain the route fixture's intended runtime settings after ordinary
        // test defaults. The physical catalog was authenticated at construction.
        state
            .set_nexus(nexus)
            .expect("apply fixture runtime Nexus settings");
        (state, kura)
    } else {
        let kura = Kura::blank_kura_for_testing();
        let state = IrohaState::new_with_chain_and_network_id_for_testing(
            world,
            kura.clone(),
            query_handle.clone(),
            chain_id.clone(),
            network_id,
        );
        (state, kura)
    };
    {
        let mut topo_block = state_inner.commit_topology.block();
        topo_block.clear();
        let peer_keypair =
            checked_torii_test_ed25519_keypair(0xb3, "derive Torii topology fixture peer key");
        let peer_id = iroha_model_base::peer::PeerId::from(peer_keypair.public_key().clone());
        topo_block.push(peer_id);
        topo_block.commit();
    }
    let state = Arc::new(state_inner);
    // Minimal queue/events
    let events: EventsSender = tokio::sync::broadcast::channel(1).0;
    let queue_cfg = iroha_config::parameters::actual::Queue::default();
    let queue = Arc::new(Queue::from_config(queue_cfg, events.clone()));
    if has_configured_catalog {
        let state_view = state.view();
        queue.reconfigure_nexus(&state.nexus_snapshot(), &state_view, None);
    }
    let pipeline_status_cache = Arc::new(PipelineStatusCache::new());
    // Minimal Kiso and peers provider (mocked to avoid spawning the full actor in tests)
    let cfg = crate::test_utils::mk_minimal_root_cfg();
    let kiso = KisoHandle::mock(&cfg);
    let (_tx, rx) =
        tokio::sync::watch::channel::<std::collections::HashSet<Peer>>(Default::default());
    let peers = OnlinePeersProvider::new(rx);
    #[cfg(feature = "connect")]
    let connect_cfg = iroha_config::parameters::actual::Connect {
        enabled: false,
        ws_max_sessions: iroha_config::parameters::defaults::connect::WS_MAX_SESSIONS,
        ws_per_ip_max_sessions: iroha_config::parameters::defaults::connect::WS_PER_IP_MAX_SESSIONS,
        ws_rate_per_ip_per_min: iroha_config::parameters::defaults::connect::WS_RATE_PER_IP_PER_MIN,
        session_ttl: iroha_config::parameters::defaults::connect::SESSION_TTL,
        frame_max_bytes: iroha_config::parameters::defaults::connect::FRAME_MAX_BYTES,
        session_buffer_max_bytes:
            iroha_config::parameters::defaults::connect::SESSION_BUFFER_MAX_BYTES,
        ping_interval: iroha_config::parameters::defaults::connect::PING_INTERVAL,
        ping_miss_tolerance: iroha_config::parameters::defaults::connect::PING_MISS_TOLERANCE,
        ping_min_interval: iroha_config::parameters::defaults::connect::PING_MIN_INTERVAL,
        dedupe_ttl: iroha_config::parameters::defaults::connect::DEDUPE_TTL,
        dedupe_cap: iroha_config::parameters::defaults::connect::DEDUPE_CAP,
        relay_enabled: false,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
        p2p_ttl_hops: iroha_config::parameters::defaults::connect::P2P_TTL_HOPS,
    };
    #[cfg(feature = "push")]
    let push_cfg = push.unwrap_or_default();
    #[cfg(feature = "push")]
    let push_bridge = if push_cfg.enabled {
        Some(push::PushBridge::new(push_cfg.clone()))
    } else {
        None
    };
    #[cfg(feature = "app_api")]
    let sorafs_cache: Option<Arc<RwLock<sorafs::ProviderAdvertCache>>> = None;
    // Test fixtures opt into an isolated storage directory explicitly. Never
    // let a unit-test helper inherit the production data path.
    let sorafs_node = {
        static SORAFS_NODE_INIT_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
        let _init_guard = SORAFS_NODE_INIT_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        sorafs_node::NodeHandle::new(
            sorafs_node::config::StorageConfig::builder()
                .enabled(false)
                .data_dir(kura.store_root().join("sorafs"))
                .build(),
        )
    };
    #[cfg(feature = "app_api")]
    let sorafs_limits = Arc::new(sorafs::SorafsQuotaEnforcer::unlimited());
    #[cfg(feature = "app_api")]
    let sorafs_alias_cache = sorafs::policy_from_config(
        &iroha_config::parameters::actual::SorafsAliasCachePolicy::default(),
    );
    #[cfg(feature = "app_api")]
    let sorafs_alias_enforcement = sorafs::enforcement_from_config(
        &iroha_config::parameters::actual::SorafsAliasCachePolicy::default(),
    );
    #[cfg(feature = "app_api")]
    let stream_token_issuer: Option<Arc<sorafs::StreamTokenIssuer>> = None;
    #[cfg(feature = "app_api")]
    let sorafs_publish_discovery =
        iroha_config::parameters::actual::SorafsPublishDiscovery::default();
    let sorafs_gateway_config = iroha_config::parameters::actual::SorafsGateway::default();
    let sorafs_site_bindings = None;
    let telemetry = routing::MaybeTelemetry::for_tests().with_profile(TelemetryProfile::Full);
    let iso_bridge = iso
        .as_ref()
        .and_then(|cfg| {
            crate::iso20022_bridge::Iso20022BridgeRuntime::from_config(cfg)
                .expect("iso bridge config for tests should be valid")
        })
        .map(Arc::new);
    let deploy_rate_limiter = match deploy_limit {
        Some((rate, burst)) => limits::RateLimiter::new(Some(rate), Some(burst)),
        None => limits::RateLimiter::new(None, None),
    };
    let norito_rpc_cfg = norito_rpc.unwrap_or_default();
    let da_replay_cache = Arc::new(iroha_core::da::ReplayCache::new(
        iroha_core::da::ReplayCacheConfig::new(),
    ));
    let da_ingest = iroha_config::parameters::actual::DaIngest::default();
    let da_ingest_compute_inflight = Arc::new(tokio::sync::Semaphore::new(
        da_ingest.max_concurrent_compute_jobs.get(),
    ));
    let da_receipt_signer = checked_torii_test_keypair_from_seed_byte(
        0xb4,
        Algorithm::Secp256k1,
        "derive Torii DA receipt fixture signer",
    );
    let da_receipt_log = Arc::new(da::DaReceiptLog::in_memory(
        Arc::new(da::ReplayCursorStore::in_memory()),
        da_receipt_signer.public_key().clone(),
    ));
    #[cfg(all(feature = "app_api", feature = "telemetry"))]
    let peer_telemetry = telemetry::peers::PeerTelemetryService::new(
        Vec::new(),
        telemetry::peers::GeoLookupConfig::disabled(),
        *state.network_id_ref(),
        None,
    );
    let content_config_snapshot = state.content_snapshot();
    let soranet_privacy_ingest = iroha_config::parameters::actual::SoranetPrivacyIngest::default();
    let soranet_privacy_allow_nets = limits::parse_cidrs(&soranet_privacy_ingest.allow_cidrs);
    let soranet_privacy_rate_limiter = limits::RateLimiter::new(
        soranet_privacy_ingest
            .rate_per_sec
            .map(std::num::NonZeroU32::get),
        soranet_privacy_ingest.burst.map(std::num::NonZeroU32::get),
    );
    let api_token_digests = Arc::new(limits::ApiTokenDigestSet::default());
    let operator_auth = Arc::new(
        operator_auth::OperatorAuth::new(
            iroha_config::parameters::actual::ToriiOperatorAuth::default(),
            defaults::torii::data_dir(),
            telemetry.clone(),
        )
        .expect("operator auth defaults should be valid"),
    );
    let operator_signatures = Arc::new(
        operator_signatures::OperatorSignatures::new(
            iroha_config::parameters::actual::ToriiOperatorSignatures::default(),
            da_receipt_signer.public_key().clone(),
            *state.network_id_ref(),
            defaults::torii::MAX_CONTENT_LEN.get(),
            telemetry.clone(),
        )
        .expect("valid operator-signature defaults"),
    );
    let soracloud_public_inflight_total = defaults::torii::SORACLOUD_PUBLIC_MAX_INFLIGHT.get();
    let soracloud_public_inflight =
        Arc::new(tokio::sync::Semaphore::new(soracloud_public_inflight_total));
    let soracloud_mutation_inflight = Arc::new(tokio::sync::Semaphore::new(
        defaults::torii::SORACLOUD_MUTATION_MAX_INFLIGHT.get(),
    ));
    let ivm_tooling_inflight = Arc::new(tokio::sync::Semaphore::new(
        defaults::torii::IVM_TOOLING_MAX_INFLIGHT,
    ));
    let proof_body_inflight = Arc::new(tokio::sync::Semaphore::new(
        defaults::torii::PROOF_BODY_MAX_INFLIGHT.get(),
    ));
    let mcp = iroha_config::parameters::actual::ToriiMcp::default();
    let mcp_rate_per_minute = mcp.rate_per_minute.map(std::num::NonZeroU32::get);
    let mcp_burst = mcp.burst.map(std::num::NonZeroU32::get);
    let mcp_rate_limiter = limits::RateLimiter::new_per_minute(mcp_rate_per_minute, mcp_burst);
    let mcp_tools = Arc::new(if mcp.enabled {
        mcp::build_tool_specs(&mcp)
    } else {
        Vec::new()
    });
    let mcp_dispatch_inflight = Arc::new(tokio::sync::Semaphore::new(
        mcp.max_inflight_dispatches.get(),
    ));
    let mcp_long_poll_inflight = Arc::new(tokio::sync::Semaphore::new(
        mcp::long_poll_dispatch_capacity(mcp.max_inflight_dispatches.get()),
    ));
    let query_memory = query_memory_geometry(
        usize::try_from(defaults::torii::QUERY_FANOUT_MAX_RETAINED_BYTES.get())
            .expect("default query memory pool fits usize"),
        usize::try_from(defaults::torii::QUERY_FANOUT_MAX_WORKING_SET_BYTES.get())
            .expect("default query working-set ceiling fits usize"),
        usize::try_from(defaults::torii::MAX_CONTENT_LEN.get())
            .expect("default content limit fits usize"),
        defaults::torii::QUERY_HEAVY_MAX_INFLIGHT.get(),
    )
    .expect("default query memory pool admits ingress and fanout reservations");
    let proxy_frame_bytes = usize::try_from(defaults::torii::MAX_CONTENT_LEN.get())
        .expect("default proxy content limit fits usize")
        .checked_add(TORII_PROXY_REQUEST_FRAME_OVERHEAD_BYTES_V1)
        .expect("default proxy frame limit fits usize");
    let torii_proxy_http_ingress_envelope =
        ToriiProxyHttpIngressEnvelope::from_max_content_bytes(proxy_frame_bytes)
            .expect("default proxy HTTP memory envelope fits");
    let query_fanout_inflight = ByteWeightedMemoryPool::new(query_memory.fanout_pool_bytes)
        .expect("default query memory pool fits weighted semaphore geometry");
    let query_fanout_working_set_bytes = query_memory.fanout_working_set_bytes.min(
        usize::try_from(query_fanout_inflight.capacity_bytes())
            .expect("default weighted query pool capacity fits usize"),
    );
    let ordinary_query_policy = OrdinaryQueryServerPolicy::new(
        routing::AppQueryLimits::default(),
        query_memory.ingress,
        QueryFanoutMemoryEnvelope::for_body_admission(query_fanout_working_set_bytes)
            .expect("default query memory pool admits ordinary response geometry"),
    )
    .expect("default query memory pool admits ordinary query limits");
    assert!(
        query_fanout_inflight.can_reserve_parts(ordinary_query_policy.start_reservation_parts()),
        "default query memory pool admits one stored ordinary query"
    );
    Arc::new(AppState {
        build_status: crate::build_identity_test_fixture::build_identity().status(),
        shutdown_signal: ShutdownSignal::new(),
        events,
        kura,
        chain_id: Arc::new(chain_id),
        signed_query_admission: signed_query_test_admission(),
        transaction_max_content_len: usize::try_from(defaults::torii::MAX_CONTENT_LEN.get())
            .unwrap_or(usize::MAX),
        torii_proxy_max_response_bytes: usize::try_from(defaults::torii::MAX_CONTENT_LEN.get())
            .unwrap_or(usize::MAX),
        query_fanout_working_set_bytes,
        query_ingress_envelope: query_memory.ingress,
        torii_proxy_http_ingress_envelope,
        torii_proxy_memory_inflight: Arc::new(tokio::sync::Semaphore::new(1)),
        torii_proxy_receiver_memory_inflight: Arc::new(tokio::sync::Semaphore::new(1)),
        query_ingress_inflight: Arc::new(tokio::sync::Semaphore::new(
            query_memory.ingress_slots.get(),
        )),
        query_fanout_inflight,
        #[cfg(feature = "app_api")]
        app_routed_read_waiters: Arc::new(tokio::sync::Semaphore::new(
            defaults::torii::QUERY_MAX_INFLIGHT.get(),
        )),
        #[cfg(feature = "app_api")]
        app_api_routed_read_body_read_timeout: Duration::from_millis(
            defaults::torii::APP_API_ROUTED_READ_BODY_READ_TIMEOUT_MS,
        ),
        ordinary_query_policy,
        transaction_ingress_compute_inflight: Arc::new(tokio::sync::Semaphore::new(
            defaults::torii::TRANSACTION_INGRESS_MAX_CONCURRENT_COMPUTE_JOBS.get(),
        )),
        #[cfg(feature = "app_api")]
        verified_source_compile_inflight: Arc::new(tokio::sync::Semaphore::new(
            defaults::torii::VERIFIED_SOURCE_MAX_CONCURRENT_COMPILES.get(),
        )),
        #[cfg(feature = "app_api")]
        verified_source_body_read_timeout: defaults::torii::VERIFIED_SOURCE_BODY_READ_TIMEOUT,
        transaction_batch_max_transactions:
            defaults::torii::TRANSACTION_INGRESS_MAX_BATCH_TRANSACTIONS.get(),
        transaction_batch_max_bytes: usize::try_from(defaults::torii::MAX_CONTENT_LEN.get())
            .unwrap_or(usize::MAX),
        state: state.clone(),
        #[cfg(feature = "app_api")]
        parliament_tle_release_coordinator: Arc::new(
            iroha_core::tle_release::TleReleaseCoordinatorV1::without_signer(),
        ),
        #[cfg(feature = "app_api")]
        musubi_search: Arc::new(RwLock::new(
            iroha_core::musubi_search::MusubiSearchIndexV1::default(),
        )),
        bootle_lantern_issuance_runtime: None,
        #[cfg(feature = "app_api")]
        kagemusha_enrollment: None,
        kiso,
        query_service: query_handle,
        query_inflight: Arc::new(tokio::sync::Semaphore::new(
            defaults::torii::QUERY_MAX_INFLIGHT.get(),
        )),
        query_heavy_inflight: Arc::new(tokio::sync::Semaphore::new(
            defaults::torii::QUERY_HEAVY_MAX_INFLIGHT.get(),
        )),
        query_queue_timeout: Duration::from_millis(defaults::torii::QUERY_QUEUE_TIMEOUT_MS),
        rate_limiter: limits::RateLimiter::new(None, None),
        query_preauth_rate_limiter: limits::RateLimiter::new(None, None),
        query_authority_rate_limiter: limits::RateLimiter::new(None, None),
        pipeline_status_rate_limiter: limits::RateLimiter::new(None, None),
        tx_preauth_rate_limiter: limits::RateLimiter::new(None, None),
        tx_rate_limiter: limits::RateLimiter::new(None, None),
        deploy_rate_limiter,
        proof_rate_limiter: limits::RateLimiter::new(None, None),
        proof_egress_limiter: limits::RateLimiter::new_u64(None, None),
        proof_body_inflight,
        soracloud_public_rate_limiter: limits::RateLimiter::new(None, None),
        soracloud_mutation_rate_limiter: limits::RateLimiter::new(None, None),
        soracloud_mutation_inflight,
        soracloud_public_max_response_bytes: usize::try_from(
            defaults::torii::SORACLOUD_PUBLIC_MAX_RESPONSE_BYTES.get(),
        )
        .unwrap_or(usize::MAX),
        soracloud_mutation_max_body_bytes: usize::try_from(
            defaults::torii::SORACLOUD_MUTATION_MAX_BODY_BYTES.get(),
        )
        .unwrap_or(usize::MAX),
        content_request_limiter: limits::RateLimiter::new(None, None),
        content_egress_limiter: limits::RateLimiter::new_u64(None, None),
        proof_limits: routing::ProofApiLimits::default(),
        content_config: content_config_snapshot,
        ws_message_timeout: Duration::from_millis(defaults::torii::WS_MESSAGE_TIMEOUT_MS),
        require_api_token: false,
        api_token_digests: api_token_digests.clone(),
        zk_attachments_enabled: defaults::torii::ZK_ATTACHMENTS_ENABLED,
        operator_auth,
        operator_signatures,
        soranet_privacy_ingest,
        soranet_privacy_allow_nets: Arc::new(soranet_privacy_allow_nets),
        soranet_privacy_rate_limiter,
        api_rate_limit_bypass_nets: Arc::new(vec![]),
        internal_api_trusted_nets: Arc::new(limits::parse_cidrs(
            &defaults::torii::internal_api_trusted_cidrs(),
        )),
        trusted_proxy_nets: Arc::new(vec![]),
        norito_rpc_mtls_trusted_proxy_nets: Arc::new(limits::parse_cidrs(
            &norito_rpc_cfg.mtls_trusted_proxy_cidrs,
        )),
        preauth_gate: Arc::new(limits::PreAuthGate::disabled()),
        queue,
        pipeline_status_cache,
        mcp,
        mcp_rate_limiter,
        mcp_tools,
        mcp_dispatch_inflight,
        mcp_long_poll_inflight,
        mcp_inflight_requests: Arc::new(mcp::McpInflightRegistry::default()),
        mcp_allowed_origins: Arc::new(Vec::new()),
        mcp_dispatch_router: McpDispatchRouterSlot::default(),
        fee_policy: FeePolicy::Disabled,
        norito_rpc_allowed_client_digests: Arc::new(limits::ApiTokenDigestSet::from_tokens(
            norito_rpc_cfg.allowed_clients.iter().map(String::as_str),
        )),
        norito_rpc: norito_rpc_cfg,
        high_load_tx_threshold: usize::MAX,
        high_load_stream_tx_threshold: usize::MAX,
        high_load_subscription_tx_threshold: usize::MAX,
        online_peers: peers,
        iso_bridge,
        #[cfg(feature = "app_api")]
        identifier_resolver: None,
        #[cfg(feature = "app_api")]
        tx_history_access_policy: Arc::new(TxHistoryAccessPolicy::default()),
        telemetry,
        soracloud_public_inflight,
        #[cfg(feature = "app_api")]
        sns_name_cache: Arc::new(sns::SnsNameRecordCache::new()),
        ivm_tooling_inflight,
        ivm_tooling_timeout: Duration::from_millis(defaults::torii::IVM_TOOLING_TIMEOUT_MS),
        #[cfg(all(feature = "app_api", feature = "telemetry"))]
        peer_telemetry,
        da_replay_cache,
        da_receipt_log,
        da_replay_lifecycle_lock: Arc::new(parking_lot::Mutex::new(())),
        da_receipt_signer,
        torii_proxy_bridge_signer: checked_torii_test_ed25519_keypair(
            0xb5,
            "derive Torii proxy bridge fixture signer",
        ),
        vpn_operator_signer: None,
        #[cfg(feature = "app_api")]
        public_dataspace_upstreams: Arc::new(BTreeMap::new()),
        #[cfg(feature = "app_api")]
        recipient_lookup: Arc::new(Default::default()),
        #[cfg(feature = "app_api")]
        recipient_lookup_rate_limiter: limits::RateLimiter::new_per_minute(
            Some(defaults::torii::recipient_lookup::REQUESTS_PER_MINUTE),
            Some(defaults::torii::recipient_lookup::REQUESTS_PER_MINUTE),
        ),
        da_ingest,
        da_ingest_compute_inflight,
        da_spooler: None,
        #[cfg(feature = "app_api")]
        sorafs_cache,
        #[cfg(feature = "app_api")]
        sorafs_routing_authority_cache: Arc::new(
            sorafs::delegated_routing::RoutingAuthorityCache::default(),
        ),
        sorafs_node,
        #[cfg(feature = "app_api")]
        sorafs_proof_outcome_signer: None,
        sorafs_provider_attestation_inventory: None,
        #[cfg(feature = "app_api")]
        sorafs_repair_transaction_signer: None,
        #[cfg(feature = "app_api")]
        sorafs_reserve_transaction_signer: None,
        #[cfg(feature = "app_api")]
        sorafs_orderbook_transaction_signer: None,
        #[cfg(feature = "app_api")]
        sorafs_reputation_committed_reader: None,
        #[cfg(feature = "app_api")]
        sorafs_hedging_billing_runtime: None,
        #[cfg(feature = "app_api")]
        sorafs_potr_runtime_signers: None,
        #[cfg(feature = "app_api")]
        sorafs_moderation_orchestrator: None,
        #[cfg(feature = "app_api")]
        sorafs_evidence_viewer: None,
        #[cfg(feature = "app_api")]
        sorafs_moderation_orchestrator_worker: None,
        #[cfg(feature = "app_api")]
        sorafs_limits,
        #[cfg(feature = "app_api")]
        por_coordinator: Arc::new(sorafs::PorCoordinator::new()),
        #[cfg(feature = "app_api")]
        por_runtime: None,
        #[cfg(feature = "app_api")]
        por_auditor_signature_threshold: usize::from(
            defaults::sorafs::por::AUDITOR_SIGNATURE_THRESHOLD,
        ),
        #[cfg(feature = "app_api")]
        sorafs_alias_cache_policy: sorafs_alias_cache,
        #[cfg(feature = "app_api")]
        sorafs_alias_enforcement,
        #[cfg(feature = "app_api")]
        sorafs_admission: None,
        #[cfg(feature = "app_api")]
        sorafs_pop_credentials: None,
        #[cfg(feature = "app_api")]
        sorafs_publish_discovery,
        sorafs_gateway_config,
        sorafs_site_bindings,
        sorafs_gateway_policy: None,
        #[cfg(feature = "app_api")]
        sorafs_gateway_tls_state: None,
        sorafs_gateway_compliance_controller: Some(
            sorafs::gateway::allow_all_gateway_compliance_controller_for_tests(),
        ),
        #[cfg(feature = "app_api")]
        sorafs_gateway_compliance_feed_transport: None,
        #[cfg(test)]
        sorafs_gateway_test_provider_id: Some([0x45; 32]),
        #[cfg(feature = "app_api")]
        sorafs_blinded_resolver: None,
        #[cfg(feature = "app_api")]
        stream_token_issuer,
        #[cfg(feature = "app_api")]
        stream_token_admission_capture: None,
        #[cfg(feature = "app_api")]
        stream_token_cleanup: None,
        #[cfg(feature = "app_api")]
        stream_token_concurrency: sorafs::StreamTokenConcurrencyTracker::default(),
        #[cfg(feature = "app_api")]
        stream_token_quota: sorafs::StreamTokenQuotaTracker::default(),
        #[cfg(feature = "app_api")]
        sorafs_chunk_range_overrides: DashMap::new(),
        #[cfg(feature = "app_api")]
        account_faucet: None,
        #[cfg(feature = "app_api")]
        sorafs_appeal_finance_policy: Arc::new(
            sorafs::api::AppealFinanceRuntimePolicy::from_config(
                &iroha_config::parameters::actual::SorafsAppealFinanceSettlement::default(),
            )
            .expect("baseline SoraFS appeal-finance policy"),
        ),
        #[cfg(feature = "app_api")]
        sorafs_appeal_settlement_submitter: None,
        #[cfg(feature = "app_api")]
        account_onboarding: None,
        vpn_relay_trust: None,
        vpn_used_payments: Arc::new(DashMap::new()),
        vpn_sessions: Arc::new(DashMap::new()),
        vpn_receipts: Arc::new(DashMap::new()),
        vpn_state_lock: Arc::new(std::sync::Mutex::new(vpn::VpnRuntimeState::default())),
        soracloud_runtime: None,
        #[cfg(feature = "connect")]
        torii_proxy_pending: Arc::new(parking_lot::Mutex::new(BTreeMap::new())),
        #[cfg(feature = "connect")]
        torii_proxy_completed: Arc::new(tokio::sync::Mutex::new(
            CompletedToriiProxyRequests::default(),
        )),
        #[cfg(feature = "connect")]
        torii_proxy_session_id: new_torii_proxy_session_id(),
        #[cfg(feature = "connect")]
        torii_proxy_sequence: std::sync::atomic::AtomicU64::new(1),
        sumeragi: None,
        #[cfg(any(feature = "app_api", feature = "connect"))]
        p2p: None,
        local_peer_id: None,
        #[cfg(feature = "connect")]
        connect_bus: crate::connect::Bus::from_config(
            &connect_cfg,
            crate::signed_query_test_network_id(),
        ),
        #[cfg(feature = "connect")]
        connect_enabled: connect_cfg.enabled,
        #[cfg(feature = "push")]
        push: push_bridge,
        #[cfg(feature = "push")]
        push_rate_limiter: super::push_registration_rate_limiter(&push_cfg),
    })
}
#[cfg(feature = "telemetry")]
pub async fn mk_norito_rpc_test_harness(cfg: NoritoRpcTransport) -> SharedAppState {
    mk_app_state_for_tests_with_options(None, None, Some(cfg), None)
}
#[tokio::test]
async fn runtime_handlers_ok_without_token_and_rate_limit() {
    let app = mk_app_state_for_tests();
    let headers = HeaderMap::new();
    // Active ABI version
    let resp = super::handler_runtime_abi_active(
        State(app.clone()),
        headers.clone(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            axum::http::HeaderValue::from_static("application/json"),
        )),
    )
    .await
    .expect("ok");
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let bytes = torii_body_bytes(resp, "body").await;
    let active: crate::runtime::RuntimeAbiActiveResponse =
        norito::json::from_slice(&bytes).expect("decode json");
    assert_eq!(active.abi_version, 1);
    // ABI hash
    let resp = super::handler_runtime_abi_hash(
        State(app),
        headers,
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            axum::http::HeaderValue::from_static("application/json"),
        )),
    )
    .await
    .expect("ok");
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let bytes = torii_body_bytes(resp, "body").await;
    let hash: crate::runtime::RuntimeAbiHashResponse =
        norito::json::from_slice(&bytes).expect("decode json");
    assert_eq!(hash.policy, "V1");
    assert_eq!(hash.abi_hash_hex.len(), 64);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn explorer_transaction_detail_not_found_returns_json_response() {
    let app = mk_app_state_for_tests();
    let headers = HeaderMap::new();
    let missing_hash = "00".repeat(32);
    let uri: axum::http::Uri = format!("/v1/explorer/transactions/{missing_hash}")
        .parse()
        .expect("valid Explorer transaction URI");
    let response = super::handler_explorer_transaction_detail(
        State(app),
        headers,
        axum::http::Method::GET,
        uri,
        crate::loopback_connect_info(),
        axum::extract::Path(missing_hash),
    )
    .await
    .expect("explorer detail handler should map errors to HTTP responses");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        torii_response_header(&response, "content-type"),
        Some("application/json")
    );
    let _payload = decode_torii_json(response, "response body", "json error payload").await;
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn explorer_instruction_detail_not_found_returns_json_response() {
    let app = mk_app_state_for_tests();
    let headers = HeaderMap::new();
    let missing_hash = "00".repeat(32);
    let uri: axum::http::Uri = format!("/v1/explorer/instructions/{missing_hash}/0")
        .parse()
        .expect("valid Explorer instruction URI");
    let response = super::handler_explorer_instruction_detail(
        State(app),
        headers,
        axum::http::Method::GET,
        uri,
        crate::loopback_connect_info(),
        axum::extract::Path((missing_hash, 0)),
    )
    .await
    .expect("explorer instruction detail handler should map errors to HTTP responses");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        torii_response_header(&response, "content-type"),
        Some("application/json")
    );
    let _payload = decode_torii_json(response, "response body", "json error payload").await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn debug_witness_returns_json_body() {
    let app = mk_app_state_for_tests();
    let headers = HeaderMap::new();
    let accept = Some(crate::utils::extractors::ExtractAccept(
        HeaderValue::from_static("application/json"),
    ));
    let resp =
        super::handler_debug_witness(State(app), headers, crate::loopback_connect_info(), accept)
            .await
            .expect("debug witness response");
    assert_eq!(resp.status(), StatusCode::OK);
    let content_type = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .expect("content type header");
    assert_eq!(content_type, "application/json");
    let _parsed = decode_torii_json(resp, "response body", "valid json").await;
}

#[cfg(feature = "telemetry")]
#[tokio::test]
async fn debug_witness_requires_a_developer_telemetry_profile() {
    for (profile, expected_status) in [
        (TelemetryProfile::Disabled, StatusCode::SERVICE_UNAVAILABLE),
        (TelemetryProfile::Operator, StatusCode::SERVICE_UNAVAILABLE),
        (TelemetryProfile::Extended, StatusCode::SERVICE_UNAVAILABLE),
        (TelemetryProfile::Developer, StatusCode::OK),
        (TelemetryProfile::Full, StatusCode::OK),
    ] {
        let app = mk_app_state_for_tests();
        let mut inner = Arc::try_unwrap(app)
            .unwrap_or_else(|_| panic!("debug-witness fixture must have one app-state owner"));
        inner.telemetry = inner.telemetry.with_profile(profile);
        let app = Arc::new(inner);
        let response = super::handler_debug_witness(
            State(app),
            HeaderMap::new(),
            crate::loopback_connect_info(),
            Some(crate::utils::extractors::ExtractAccept(
                HeaderValue::from_static("application/json"),
            )),
        )
        .await
        .expect("profile gate returns an HTTP response");
        assert_eq!(response.status(), expected_status, "profile {profile:?}");
    }
}

#[cfg(feature = "telemetry")]
#[tokio::test]
async fn debug_witness_operator_and_telemetry_profile_matrix() {
    const ROUTES: &[route_catalog::RouteDescriptor] = &[route_catalog::telemetry::DEBUG_WITNESS];
    let descriptor = &ROUTES[0];
    let uri = descriptor
        .path()
        .parse::<crate::Uri>()
        .expect("debug witness URI");
    let rogue_signer = checked_torii_test_keypair_from_seed_byte(
        0xd1,
        Algorithm::Secp256k1,
        "derive untrusted debug-witness operator fixture key",
    );

    for (profile, expected_signed_status) in [
        (TelemetryProfile::Disabled, StatusCode::SERVICE_UNAVAILABLE),
        (TelemetryProfile::Operator, StatusCode::SERVICE_UNAVAILABLE),
        (TelemetryProfile::Extended, StatusCode::SERVICE_UNAVAILABLE),
        (TelemetryProfile::Developer, StatusCode::OK),
        (TelemetryProfile::Full, StatusCode::OK),
    ] {
        let app = mk_app_state_for_tests();
        let mut inner = Arc::try_unwrap(app)
            .unwrap_or_else(|_| panic!("debug-witness fixture must have one app-state owner"));
        inner.telemetry = inner.telemetry.with_profile(profile);
        let app = Arc::new(inner);
        let mut builder = RouterBuilder::new(
            app.clone(),
            RouteCatalog::new(ROUTES),
            compiled_route_features(),
        )
        .expect("debug witness route catalog is valid");
        builder.route(
            descriptor,
            catalog_get(super::handler_debug_witness).authenticated_operator(app.clone()),
        );
        let (router, _) = builder
            .finish()
            .expect("debug witness route mounts exactly once");
        let router = router.with_state(app.clone());
        let make_request = |headers: HeaderMap| {
            let mut request = axum::http::Request::builder()
                .method(axum::http::Method::GET)
                .uri(uri.clone())
                .header(axum::http::header::ACCEPT, "application/json")
                .extension(crate::loopback_connect_info())
                .body(axum::body::Body::empty())
                .expect("debug witness request");
            request.headers_mut().extend(headers);
            request
        };

        let unsigned = router
            .clone()
            .oneshot(make_request(HeaderMap::new()))
            .await
            .expect("unsigned debug witness response");
        assert_eq!(
            unsigned.status(),
            StatusCode::UNAUTHORIZED,
            "unsigned profile {profile:?}"
        );

        let rogue_headers = operator_signatures::signed_request_headers(
            &rogue_signer,
            app.state.network_id_ref(),
            &crate::Method::GET,
            &uri,
            &[],
        )
        .expect("untrusted operator request signature");
        let untrusted = router
            .clone()
            .oneshot(make_request(rogue_headers))
            .await
            .expect("untrusted debug witness response");
        assert_eq!(
            untrusted.status(),
            StatusCode::FORBIDDEN,
            "untrusted profile {profile:?}"
        );

        let refusal = decode_torii_json(
            untrusted,
            "untrusted debug witness refusal",
            "operator refusal JSON",
        )
        .await;
        assert_eq!(refusal["code"].as_str(), Some("operator_key_not_allowed"));

        let operator_headers = operator_signatures::signed_request_headers(
            &app.da_receipt_signer,
            app.state.network_id_ref(),
            &crate::Method::GET,
            &uri,
            &[],
        )
        .expect("trusted operator request signature");
        let signed = router
            .oneshot(make_request(operator_headers))
            .await
            .expect("signed debug witness response");
        assert_eq!(
            signed.status(),
            expected_signed_status,
            "signed profile {profile:?}"
        );
    }
}

#[tokio::test]
async fn torii_tx_rate_uses_config_and_queue_default() {
    let mut cfg = crate::test_utils::mk_minimal_root_cfg();
    cfg.torii.tx_rate_per_authority_per_sec = Some(NonZeroU32::new(123).expect("nonzero tx rate"));
    cfg.torii.tx_burst_per_authority = Some(NonZeroU32::new(456).expect("nonzero tx burst"));
    cfg.torii.api_high_load_tx_threshold = None;
    let (kiso, _child) = KisoHandle::start(cfg.clone());
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = Arc::new(IrohaState::new_with_chain_and_network_id_for_testing(
        World::default(),
        kura.clone(),
        query,
        ChainId::from("tx-rate-test"),
        signed_query_test_network_id(),
    ));
    let queue_cfg = iroha_config::parameters::actual::Queue {
        capacity: NonZeroUsize::new(100).expect("queue capacity non-zero"),
        capacity_per_user: NonZeroUsize::new(100).expect("queue per-user capacity non-zero"),
        transaction_time_to_live: Duration::from_secs(60),
        ..Default::default()
    };
    let queue_events: iroha_core::EventsSender = tokio::sync::broadcast::channel(1).0;
    let queue = Arc::new(Queue::from_config(queue_cfg, queue_events));
    let (peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
    let _ = peers_tx;
    let torii = Torii::new_with_handle(
        ChainId::from("tx-rate-test"),
        signed_query_test_network_id(),
        kiso,
        cfg.torii.clone(),
        queue,
        tokio::sync::broadcast::channel(1).0,
        LiveQueryStore::start_test(),
        kura,
        state,
        cfg.common.key_pair.clone(),
        OnlinePeersProvider::new(peers_rx),
        None,
        crate::ToriiRuntimeDeps::new(
            crate::build_identity_test_fixture::build_identity(),
            routing::MaybeTelemetry::disabled(),
        ),
    )
    .expect("valid Torii test fixture");
    assert!(
        torii
            .tx_rate_limiter
            .allow_cost("configured-tx-rate", 456)
            .await,
        "configured burst must admit its full initial capacity"
    );
    assert!(
        !torii
            .tx_rate_limiter
            .allow_cost("configured-tx-rate", 456)
            .await,
        "configured limiter must reject another full burst immediately"
    );
    assert_eq!(torii.high_load_tx_threshold, 50);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn torii_ram_lfe_uses_config_runtime() {
    let mut cfg = crate::test_utils::mk_minimal_root_cfg();
    let signer =
        checked_torii_test_ed25519_keypair(0x9f, "derive Torii RAM-LFE config signer fixture key");
    cfg.torii.ram_lfe = Some(iroha_config::parameters::actual::ToriiRamLfe {
        programs: vec![iroha_config::parameters::actual::ToriiRamLfeProgram {
            program_id: "phone_retail".parse().expect("program id"),
            secret: iroha_crypto::RamLfeSecret::try_from(vec![0x01, 0x02, 0x03, 0x04])
                .expect("valid RAM-LFE test secret"),
            hidden_program: iroha_crypto::default_bfv_programmed_hidden_program(),
            signer_private_key: signer.private_key().clone(),
            receipt_ttl: Some(Duration::from_secs(30)),
        }],
    });
    let (kiso, _child) = KisoHandle::start(cfg.clone());
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = Arc::new(IrohaState::new_with_chain_and_network_id_for_testing(
        World::default(),
        kura.clone(),
        query,
        ChainId::from("identifier-resolver-config-test"),
        signed_query_test_network_id(),
    ));
    let queue_cfg = iroha_config::parameters::actual::Queue {
        capacity: NonZeroUsize::new(100).expect("queue capacity non-zero"),
        capacity_per_user: NonZeroUsize::new(100).expect("queue per-user capacity non-zero"),
        transaction_time_to_live: Duration::from_secs(60),
        ..Default::default()
    };
    let queue_events: iroha_core::EventsSender = tokio::sync::broadcast::channel(1).0;
    let queue = Arc::new(Queue::from_config(queue_cfg, queue_events));
    let (peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
    let _ = peers_tx;
    let torii = Torii::new_with_handle(
        ChainId::from("identifier-resolver-config-test"),
        signed_query_test_network_id(),
        kiso,
        cfg.torii.clone(),
        queue,
        tokio::sync::broadcast::channel(1).0,
        LiveQueryStore::start_test(),
        kura,
        state,
        cfg.common.key_pair.clone(),
        OnlinePeersProvider::new(peers_rx),
        None,
        crate::ToriiRuntimeDeps::new(
            crate::build_identity_test_fixture::build_identity(),
            routing::MaybeTelemetry::disabled(),
        ),
    )
    .expect("valid Torii test fixture");
    assert!(
        torii.identifier_resolver.is_some(),
        "Torii should build an in-process identifier resolver from config"
    );
}
fn versioned_signed_for_test(tx: &SignedTransaction) -> JsonOrNoritoVersioned<SignedTransaction> {
    JsonOrNoritoVersioned(tx.clone())
}
fn versioned_entrypoint_for_test(
    entrypoint: TransactionEntrypoint,
) -> JsonOrNoritoVersioned<TransactionEntrypoint> {
    JsonOrNoritoVersioned(entrypoint)
}
async fn post_signed_transaction_for_test(
    app: SharedAppState,
    headers: HeaderMap,
    transaction: &SignedTransaction,
) -> Result<Response, Error> {
    let response = super::handler_post_transaction(
        State(app),
        headers,
        None,
        versioned_signed_for_test(transaction),
    )
    .await?;
    Ok(response.into_response())
}
async fn post_external_transaction_entrypoint_for_test(
    app: SharedAppState,
    headers: HeaderMap,
    transaction: SignedTransaction,
) -> Result<Response, Error> {
    let response = super::handler_post_transaction_entrypoint(
        State(app),
        headers,
        None,
        versioned_entrypoint_for_test(TransactionEntrypoint::External(transaction)),
    )
    .await?;
    Ok(response.into_response())
}
fn signed_log_transaction_for_test(
    network_id: NetworkId,
    authority: AccountId,
    message: impl Into<String>,
    key_pair: &KeyPair,
) -> SignedTransaction {
    TransactionBuilder::new(
        network_id,
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, message.into())])
    .sign(key_pair.private_key())
}
fn versioned_query_for_test(query: SignedQuery) -> JsonOrNoritoVersioned<SignedQuery> {
    JsonOrNoritoVersioned(query)
}
#[cfg(feature = "connect")]
fn signed_query_proxy_request_for_test(
    request_id: Hash,
    route: RoutingDecision,
) -> ToriiProxyRequestV1 {
    ToriiProxyRequestV1 {
        schema_version: TORII_PROXY_REQUEST_VERSION_V1,
        request_id,
        deadline_unix_ms: super::torii_proxy_test_deadline_unix_ms(),
        hop_count: 1,
        max_hops: 3,
        visited_peer_ids: Vec::new(),
        request: ToriiProxyRequestKindV1::SignedQueryRouteScan {
            query_bytes: Vec::new(),
            expected_route: ToriiRouteHintV1::from(route),
            response_format: ToriiProxyResponseFormatV1::Norito,
        },
    }
}
fn torii_response_header<'a>(response: &'a Response, name: &'static str) -> Option<&'a str> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
}
fn assert_route_unavailable_response(response: &Response) {
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        torii_response_header(response, "x-iroha-reject-code"),
        Some("route_unavailable")
    );
}
async fn torii_body_bytes(response: Response, diagnostic: &'static str) -> axum::body::Bytes {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect(diagnostic)
}
async fn decode_torii_json(
    response: Response,
    body_diagnostic: &'static str,
    json_diagnostic: &'static str,
) -> norito::json::Value {
    let bytes = torii_body_bytes(response, body_diagnostic).await;
    norito::json::from_slice(&bytes).expect(json_diagnostic)
}
async fn torii_json_body(response: Response) -> norito::json::Value {
    let bytes = torii_body_bytes(response, "Torii JSON response body").await;
    norito::json::from_slice(&bytes).expect("valid Torii JSON response")
}
struct CountingRouteRouter {
    route_calls: Arc<AtomicUsize>,
    route_after_capture: Option<RoutingDecision>,
}
impl LaneRouter for CountingRouteRouter {
    fn try_route(
        &self,
        _tx: &dyn TransactionRoutingView,
    ) -> Result<RoutingDecision, RoutingResolveError> {
        Ok(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL))
    }
    fn try_route_without_state(
        &self,
        _tx: &dyn TransactionRoutingView,
    ) -> Result<Option<RoutingDecision>, RoutingResolveError> {
        Ok(None)
    }
    fn try_route_with_view(
        &self,
        tx: &dyn TransactionRoutingView,
        _state_view: &iroha_core::state::StateView<'_>,
    ) -> Result<RoutingDecision, RoutingResolveError> {
        let prior_calls = self.route_calls.fetch_add(1, Ordering::Relaxed);
        if prior_calls != 0
            && let Some(route) = self.route_after_capture
        {
            return Ok(route);
        }
        self.try_route(tx)
    }
}
fn install_counting_route_queue(
    app: &mut SharedAppState,
    route_after_capture: Option<RoutingDecision>,
) -> Arc<AtomicUsize> {
    let route_calls = Arc::new(AtomicUsize::new(0));
    let router: Arc<dyn LaneRouter> = Arc::new(CountingRouteRouter {
        route_calls: Arc::clone(&route_calls),
        route_after_capture,
    });
    let app_mut = Arc::get_mut(app).expect("unique app state");
    app_mut.queue = Arc::new(Queue::from_config_with_router(
        iroha_config::parameters::actual::Queue::default(),
        app_mut.events.clone(),
        router,
    ));
    app_mut.high_load_tx_threshold = usize::MAX;
    route_calls
}
fn install_single_slot_transaction_queue(app: &mut SharedAppState) {
    let app_mut = Arc::get_mut(app).expect("unique app state");
    let mut queue_cfg = iroha_config::parameters::actual::Queue::default();
    queue_cfg.capacity = NonZeroUsize::new(1).expect("nonzero queue capacity");
    app_mut.queue = Arc::new(Queue::from_config(queue_cfg, app_mut.events.clone()));
    app_mut.high_load_tx_threshold = usize::MAX;
}
fn transaction_with_invalid_signature_for_test(mut tx: SignedTransaction) -> SignedTransaction {
    let mut signature = tx.signature().payload().payload().to_vec();
    let last = signature
        .last_mut()
        .expect("test signature payload is non-empty");
    *last ^= 0xff;
    tx.set_signature(TransactionSignature(SignatureOf::from_signature(
        Signature::from_bytes(&signature),
    )));
    tx
}
#[cfg(feature = "connect")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_post_transaction_uses_tx_rate_limiter() {
    let keypair =
        checked_torii_test_ed25519_keypair(0xc1, "derive post-transaction rate-limit fixture key");
    let mut app = native_ingress_app_for_test(&[&keypair]);
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        app_mut.high_load_tx_threshold = usize::MAX;
        app_mut.tx_rate_limiter = limits::RateLimiter::new_without_refill_for_tests(
            std::num::NonZeroU32::new(1).expect("positive admission test burst"),
        );
        app_mut.fee_policy = FeePolicy::Disabled;
    }
    let authority = AccountId::new(keypair.public_key().clone());
    let network_id = *app.state.network_id_ref();
    let tx1 =
        signed_log_transaction_for_test(network_id, authority.clone(), "rate-limit-1", &keypair);
    let tx2 = signed_log_transaction_for_test(network_id, authority, "rate-limit-2", &keypair);
    let headers = HeaderMap::new();
    let submitted_hash = tx1.hash().to_string();
    let ok_response = post_signed_transaction_for_test(app.clone(), headers.clone(), &tx1)
        .await
        .expect("accepted");
    assert_eq!(ok_response.status(), StatusCode::ACCEPTED);
    assert_native_pending_for_test(&app, &tx1);
    let hash_header = torii_response_header(&ok_response, "x-iroha-entrypoint-hash")
        .expect("entrypoint hash header must be present");
    assert_eq!(hash_header, submitted_hash);
    let lane_header = torii_response_header(&ok_response, "x-iroha-route-lane-id")
        .expect("route lane header must be present");
    let dataspace_header = torii_response_header(&ok_response, "x-iroha-route-dataspace-id")
        .expect("route dataspace header must be present");
    let routed_by = torii_response_header(&ok_response, "x-iroha-routed-by")
        .expect("routed-by header must be present");
    assert!(!lane_header.trim().is_empty());
    assert!(!dataspace_header.trim().is_empty());
    assert_eq!(routed_by, "local");
    let err = match post_signed_transaction_for_test(app.clone(), headers, &tx2).await {
        Ok(_) => panic!("expected rate limit"),
        Err(err) => err,
    };
    assert_eq!(err.into_response().status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn invalid_transaction_signature_does_not_charge_claimed_authority_bucket() {
    let mut app = mk_app_state_for_tests();
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        app_mut.high_load_tx_threshold = usize::MAX;
        app_mut.tx_rate_limiter = limits::RateLimiter::new_without_refill_for_tests(
            std::num::NonZeroU32::new(1).expect("positive admission test burst"),
        );
        app_mut.fee_policy = FeePolicy::Disabled;
    }
    let keypair = checked_torii_test_ed25519_keypair(
        0xc0,
        "derive invalid-signature authority-limiter fixture key",
    );
    let authority = AccountId::new(keypair.public_key().clone());
    let signed = signed_log_transaction_for_test(
        *app.state.network_id_ref(),
        authority.clone(),
        "invalid-signature-must-not-charge-authority",
        &keypair,
    );
    let invalid = transaction_with_invalid_signature_for_test(signed);
    let error = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &invalid)
        .await
        .expect_err("invalid signature must be rejected");
    assert_eq!(
        torii_response_header(&error.into_response(), "x-iroha-reject-code"),
        Some(SignatureRejectionCode::InvalidSignature.as_str())
    );
    assert!(
        app.tx_rate_limiter
            .allow(&transaction_verified_authority_key(&authority))
            .await,
        "an unverified claimed authority must not select or consume the authority limiter"
    );
}
#[cfg(feature = "connect")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_post_transaction_reports_full_queue_before_rate_limit() {
    let keypair =
        checked_torii_test_ed25519_keypair(0xce, "derive queue-before-rate-limit fixture key");
    let mut app = native_ingress_app_for_test(&[&keypair]);
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        app_mut.tx_rate_limiter = limits::RateLimiter::new_without_refill_for_tests(
            std::num::NonZeroU32::new(1).expect("positive admission test burst"),
        );
        app_mut.fee_policy = FeePolicy::Disabled;
    }
    install_single_slot_transaction_queue(&mut app);
    let authority = AccountId::new(keypair.public_key().clone());
    let network_id = *app.state.network_id_ref();
    let tx1 = signed_log_transaction_for_test(
        network_id,
        authority.clone(),
        "queue-before-rate-1",
        &keypair,
    );
    let tx2 =
        signed_log_transaction_for_test(network_id, authority, "queue-before-rate-2", &keypair);
    let mut headers = HeaderMap::new();
    headers.insert("x-api-token", HeaderValue::from_static("queue-before-rate"));
    let first = post_signed_transaction_for_test(app.clone(), headers.clone(), &tx1)
        .await
        .expect("first transaction should fill the queue");
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    assert_native_pending_for_test(&app, &tx1);
    let err = match post_signed_transaction_for_test(app.clone(), headers, &tx2).await {
        Ok(_) => panic!("expected queue full before token rate limit"),
        Err(err) => err,
    };
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        torii_response_header(&response, "x-iroha-reject-code"),
        Some("PRTRY:QUEUE_FULL")
    );
}
#[cfg(feature = "connect")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_post_transaction_uses_authenticated_api_token_rate_limit_key() {
    let first_keypair = checked_torii_test_ed25519_keypair(
        0xc2,
        "derive first post-transaction API-token fixture key",
    );
    let second_keypair = checked_torii_test_ed25519_keypair(
        0xc3,
        "derive second post-transaction API-token fixture key",
    );
    let mut app = native_ingress_app_for_test(&[&first_keypair, &second_keypair]);
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        app_mut.high_load_tx_threshold = usize::MAX;
        app_mut.tx_preauth_rate_limiter = limits::RateLimiter::new_without_refill_for_tests(
            std::num::NonZeroU32::new(1).expect("positive token identity test burst"),
        );
        app_mut.fee_policy = FeePolicy::Disabled;
        app_mut.require_api_token = true;
        app_mut.api_token_digests =
            Arc::new(limits::ApiTokenDigestSet::from_tokens(["shared-token"]));
    }
    let network_id = *app.state.network_id_ref();
    let tx1 = signed_log_transaction_for_test(
        network_id,
        AccountId::new(first_keypair.public_key().clone()),
        "token-rate-limit-1",
        &first_keypair,
    );
    let tx2 = signed_log_transaction_for_test(
        network_id,
        AccountId::new(second_keypair.public_key().clone()),
        "token-rate-limit-2",
        &second_keypair,
    );
    let mut headers = HeaderMap::new();
    headers.insert("x-api-token", HeaderValue::from_static("shared-token"));
    let first = post_signed_transaction_for_test(app.clone(), headers.clone(), &tx1)
        .await
        .expect("first token-keyed transaction accepted");
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    assert_native_pending_for_test(&app, &tx1);
    let err = match post_signed_transaction_for_test(app.clone(), headers, &tx2).await {
        Ok(_) => panic!("expected shared token rate limit"),
        Err(err) => err,
    };
    assert_eq!(err.into_response().status(), StatusCode::TOO_MANY_REQUESTS);
}
#[cfg(feature = "connect")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_post_transaction_revalidates_resolved_route_before_enqueue() {
    // Capture one plan, then revalidate that same plan against the current view
    // before local admission. A raw RoutingPlan is not a frozen policy proof.
    let (mut app, keypair, _, certificate) = lifecycle_ordinary_fixture(true);
    let route_calls = install_counting_route_queue(&mut app, None);
    let transaction = lifecycle_transaction_with_nonce_for_test(&app, &keypair, &certificate, 1);
    let entrypoint_hash = transaction.hash_as_entrypoint();
    let response = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &transaction)
        .await
        .expect("accepted");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(app.queue.active_len(), 1);
    assert_eq!(
        app.queue.routing_plan_hint(&entrypoint_hash),
        Some(RoutingPlan::single(RoutingDecision::new(
            LaneId::SINGLE,
            DataSpaceId::UNIVERSAL,
        ))),
    );
    assert_eq!(
        torii_response_header(&response, "x-iroha-route-lane-id"),
        Some("0")
    );
    assert_eq!(
        torii_response_header(&response, "x-iroha-route-dataspace-id"),
        Some("0")
    );
    assert_eq!(
        route_calls.load(Ordering::Relaxed),
        2,
        "capture and current-view validation must both retain the same full plan"
    );
}
#[cfg(feature = "connect")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_post_transaction_entrypoint_accepts_external_entrypoint() {
    let keypair =
        checked_torii_test_ed25519_keypair(0xc5, "derive entrypoint external fixture key");
    let mut app = native_ingress_app_for_test(&[&keypair]);
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .high_load_tx_threshold = usize::MAX;
    let authority = AccountId::new(keypair.public_key().clone());
    let transaction = signed_log_transaction_for_test(
        *app.state.network_id_ref(),
        authority,
        "entrypoint-submit",
        &keypair,
    );
    let response = post_external_transaction_entrypoint_for_test(
        app.clone(),
        HeaderMap::new(),
        transaction.clone(),
    )
    .await
    .expect("accepted");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_native_pending_for_test(&app, &transaction);
    let entrypoint_hash = torii_response_header(&response, "x-iroha-entrypoint-hash")
        .expect("entrypoint hash header must be present");
    let signed_transaction_hash =
        torii_response_header(&response, "x-iroha-signed-transaction-hash")
            .expect("signed transaction hash header must be present");
    assert_eq!(signed_transaction_hash, entrypoint_hash);
    assert_eq!(app.queue.active_len(), 1);
}
#[cfg(feature = "connect")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_post_transaction_entrypoint_revalidates_resolved_route_before_enqueue() {
    // Capture one plan, then revalidate that same plan against the current view
    // before local admission. A raw RoutingPlan is not a frozen policy proof.
    let (mut app, keypair, _, certificate) = lifecycle_ordinary_fixture(true);
    let route_calls = install_counting_route_queue(&mut app, None);
    let transaction = lifecycle_transaction_with_nonce_for_test(&app, &keypair, &certificate, 1);
    let entrypoint_hash = transaction.hash_as_entrypoint();
    let response =
        post_external_transaction_entrypoint_for_test(app.clone(), HeaderMap::new(), transaction)
            .await
            .expect("accepted");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(app.queue.active_len(), 1);
    assert_eq!(
        app.queue.routing_plan_hint(&entrypoint_hash),
        Some(RoutingPlan::single(RoutingDecision::new(
            LaneId::SINGLE,
            DataSpaceId::UNIVERSAL,
        ))),
    );
    assert_eq!(
        torii_response_header(&response, "x-iroha-route-lane-id"),
        Some("0")
    );
    assert_eq!(
        torii_response_header(&response, "x-iroha-route-dataspace-id"),
        Some("0")
    );
    assert_eq!(
        route_calls.load(Ordering::Relaxed),
        2,
        "entrypoint capture and current-view validation must retain the same full plan"
    );
}

#[cfg(feature = "connect")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_transaction_ingress_rejects_changed_route_before_local_enqueue() {
    for entrypoint_handler in [false, true] {
        let (mut app, keypair, _, certificate) = lifecycle_ordinary_fixture(true);
        // Capture the real global route, then simulate a policy/router change to
        // a route without current catalog authority before the actual queue check.
        let route_calls = install_counting_route_queue(
            &mut app,
            Some(RoutingDecision::new(
                LaneId::new(999),
                DataSpaceId::UNIVERSAL,
            )),
        );
        let before = lifecycle_pending_wire(&app);
        let transaction =
            lifecycle_transaction_with_nonce_for_test(&app, &keypair, &certificate, 1);
        let entrypoint_hash = transaction.hash_as_entrypoint();
        let response = if entrypoint_handler {
            post_external_transaction_entrypoint_for_test(
                app.clone(),
                HeaderMap::new(),
                transaction,
            )
            .await
        } else {
            post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &transaction).await
        }
        .unwrap_or_else(IntoResponse::into_response);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            torii_response_header(&response, "x-iroha-reject-code"),
            Some("PRTRY:ROUTE_UNRESOLVED"),
        );
        assert_eq!(route_calls.load(Ordering::Relaxed), 2);
        assert_eq!(app.queue.active_len(), 0);
        assert!(app.queue.routing_plan_hint(&entrypoint_hash).is_none());
        assert!(!app.state.has_committed_entrypoint(entrypoint_hash));
        assert_eq!(
            lifecycle_pending_wire(&app),
            before,
            "a precomputed plan cannot bypass current route validation or acquire custody",
        );
    }
}

/// The production alias mounts must bind index enumeration to canonical signature authentication.
#[tokio::test]
#[cfg(feature = "app_api")]
async fn alias_route_registration_preserves_signed_index_and_bounded_dispatch() {
    let _data_dir = crate::test_utils::TestDataDirGuard::new();
    let cfg = crate::test_utils::mk_minimal_root_cfg();
    let (kiso, _child) = KisoHandle::start(cfg.clone());
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = Arc::new(IrohaState::new_with_chain_and_network_id_for_testing(
        World::default(),
        kura.clone(),
        query,
        ChainId::from("alias-route-registration-test"),
        signed_query_test_network_id(),
    ));
    let queue_cfg = iroha_config::parameters::actual::Queue {
        capacity: NonZeroUsize::new(100).expect("queue capacity non-zero"),
        capacity_per_user: NonZeroUsize::new(100).expect("queue per-user capacity non-zero"),
        transaction_time_to_live: Duration::from_secs(60),
        ..Default::default()
    };
    let queue_events: iroha_core::EventsSender = tokio::sync::broadcast::channel(1).0;
    let queue = Arc::new(Queue::from_config(queue_cfg, queue_events));
    let (peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
    let _ = peers_tx;
    let _torii = Torii::new_with_handle(
        ChainId::from("alias-route-registration-test"),
        signed_query_test_network_id(),
        kiso,
        cfg.torii.clone(),
        queue,
        tokio::sync::broadcast::channel(1).0,
        LiveQueryStore::start_test(),
        kura,
        state,
        cfg.common.key_pair.clone(),
        OnlinePeersProvider::new(peers_rx),
        None,
        crate::ToriiRuntimeDeps::new(
            crate::build_identity_test_fixture::build_identity(),
            routing::MaybeTelemetry::disabled(),
        ),
    )
    .expect("valid Torii test fixture");
    let app = mk_app_state_for_tests();
    let mut builder = RouterBuilder::new(
        app.clone(),
        RouteCatalog::new(route_catalog::aliases::ROUTES),
        compiled_route_features(),
    )
    .expect("alias catalog is valid");
    Torii::add_alias_routes(&mut builder);
    let (router, manifest) = builder
        .finish()
        .expect("every production alias route must match its authenticated catalog");
    assert_eq!(
        manifest.explicit_routes().len(),
        route_catalog::aliases::ROUTES.len()
    );
    let index = manifest
        .explicit_routes()
        .iter()
        .find(|route| route.stable_route_id() == "aliases.resolve_index")
        .expect("production index route is mounted");
    assert_eq!(
        index.authentication(),
        iroha_torii_shared::route_catalog::AuthenticationPolicy::CanonicalAccountSignature
    );
    let router = router.with_state(app);
    let make_request = |method: Method, body: axum::body::Body| {
        Request::builder()
            .method(method)
            .uri(route_catalog::aliases::RESOLVE_INDEX.path())
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .extension(crate::loopback_connect_info())
            .body(body)
            .expect("alias index dispatch request")
    };
    let unsigned = router
        .clone()
        .oneshot(make_request(Method::POST, axum::body::Body::from("{")))
        .await
        .expect("unsigned alias index response");
    assert_eq!(
        unsigned.status(),
        StatusCode::UNAUTHORIZED,
        "signature admission precedes malformed index decoding"
    );
    let wrong_method = router
        .clone()
        .oneshot(make_request(Method::GET, axum::body::Body::empty()))
        .await
        .expect("alias index method response");
    assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    let oversized = router
        .oneshot(make_request(
            Method::POST,
            axum::body::Body::from(vec![b'x'; EXACT_ALIAS_READ_MAX_BODY_BYTES + 1]),
        ))
        .await
        .expect("bounded alias index response");
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
