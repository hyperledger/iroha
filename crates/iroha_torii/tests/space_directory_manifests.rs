//! Torii Space Directory manifest endpoint tests.
#![cfg(feature = "app_api")]
use axum::{Router, http::Request, response::IntoResponse as _, routing::post};
use base64::Engine as _;
use hex::ToHex;
use http::StatusCode;
use http_body_util::BodyExt as _;
use iroha_core::{
    nexus::space_directory::{SpaceDirectoryManifestRecord, SpaceDirectoryManifestSet},
    queue::Queue,
    state::{State, World},
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    account::AccountId,
    asset::AssetDefinitionId,
    nexus::{
        Allowance, AllowanceWindow, AssetPermissionManifest, CapabilityScope, DataSpaceCatalog,
        DataSpaceMetadata, ManifestEffect, ManifestEntry, ManifestVersion, UniversalAccountId,
    },
    transaction::{Executable, signed::TransactionPayload},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::peer::PeerId;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::numeric::Quantity;
use norito::codec::Decode;
use norito::json::{self, Value};
use std::sync::Arc;
use tower::ServiceExt as _;
#[path = "fixtures.rs"]
mod fixtures;
fn checked_space_directory_ed25519_key_fixture() -> KeyPair {
    KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
        .expect("generate checked space directory Ed25519 fixture keypair")
}
fn checked_space_directory_account_fixture() -> AccountId {
    AccountId::new(
        KeyPair::try_random()
            .expect("generate checked space directory account fixture keypair")
            .public_key()
            .clone(),
    )
}
fn cbdc_manifest_entry(
    dataspace: DataSpaceId,
    method: &str,
    max_amount: u64,
    notes: Option<&str>,
) -> ManifestEntry {
    ManifestEntry {
        scope: CapabilityScope {
            dataspace: Some(dataspace),
            program: Some("cbdc.transfer".parse().unwrap()),
            method: Some(method.parse().unwrap()),
            asset: Some(AssetDefinitionId::derive_from_components(
                DomainId::try_new("bank", "universal").expect("domain id"),
                "cbdc".parse().expect("asset definition name"),
            )),
            role: None,
        },
        effect: ManifestEffect::Allow(Allowance {
            max_amount: Some(Quantity::from(max_amount)),
            window: AllowanceWindow::PerDay,
        }),
        notes: match notes {
            Some(notes) => Some(notes.into()),
            None => None,
        },
    }
}
async fn decode_unsigned_transaction_draft(
    response: axum::response::Response,
) -> TransactionPayload {
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let draft: Value = json::from_slice(&body).expect("unsigned transaction draft JSON");
    assert_eq!(draft["submitted"].as_bool(), Some(false));
    let encoded = draft["transaction_payload_b64"]
        .as_str()
        .expect("transaction payload base64");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("decode transaction payload base64");
    assert_eq!(
        base64::engine::general_purpose::STANDARD.encode(&bytes),
        encoded,
        "transaction draft must use canonical padded base64",
    );
    let _guard = norito::core::PayloadCtxGuard::enter(&bytes);
    let mut cursor = std::io::Cursor::new(bytes.as_slice());
    let payload = TransactionPayload::decode(&mut cursor).expect("decode transaction payload");
    assert_eq!(
        usize::try_from(cursor.position()).unwrap(),
        bytes.len(),
        "transaction payload must not contain trailing bytes",
    );
    payload
}
struct ManifestMutationState {
    queue: Arc<Queue>,
    state: Arc<State>,
}
struct ManifestMutationHarness {
    router: Router,
    queue: Arc<Queue>,
    state: Arc<State>,
}
async fn test_manifest_publish_handler(
    axum::extract::State(context): axum::extract::State<Arc<ManifestMutationState>>,
    request: iroha_torii::NoritoJson<iroha_torii::SpaceDirectoryManifestPublishDto>,
) -> axum::response::Response {
    iroha_torii::handle_post_space_directory_manifest_publish(
        context.queue.clone(),
        context.state.clone(),
        request,
    )
    .await
    .into_response()
}
async fn test_manifest_revoke_handler(
    axum::extract::State(context): axum::extract::State<Arc<ManifestMutationState>>,
    request: iroha_torii::NoritoJson<iroha_torii::SpaceDirectoryManifestRevokeDto>,
) -> axum::response::Response {
    iroha_torii::handle_post_space_directory_manifest_revoke(
        context.queue.clone(),
        context.state.clone(),
        request,
    )
    .await
    .into_response()
}
fn manifest_fixture_chain(
    world: World,
    catalog: Option<DataSpaceCatalog>,
) -> (
    iroha_core::sumeragi::test_chain::CertifiedTestChain,
    KeyPair,
) {
    use iroha_data_model::{
        asset::{AssetBalancePolicy, AssetDefinition},
        isi::Register,
    };
    let mut config = iroha_core::sumeragi::test_chain::TestChainConfig::new(world, 1_000);
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    if let Some(catalog) = catalog {
        nexus.dataspace_catalog = catalog;
    }
    let lanes = nexus
        .dataspace_catalog
        .entries()
        .iter()
        .enumerate()
        .map(|(index, dataspace)| iroha_data_model::nexus::LaneConfig {
            id: iroha_model_base::topology::LaneId::new(u32::try_from(index).unwrap()),
            alias: format!("manifest-ds-{}", dataspace.id.as_u64()),
            dataspace_id: dataspace.id,
            ..Default::default()
        })
        .collect::<Vec<_>>();
    nexus.lane_catalog = iroha_data_model::nexus::LaneCatalog::new(
        std::num::NonZeroU32::new(u32::try_from(lanes.len()).unwrap()).unwrap(),
        lanes,
    )
    .expect("one physical manifest route per configured dataspace");
    nexus.configured_lane_catalog = nexus.lane_catalog.clone();
    nexus.fees.base_fee = Quantity::zero();
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    // Even a zero fee quote resolves the governed canonical network currency.
    let xor = iroha_data_model::parameter::system::SumeragiNposParameters::default()
        .xor_asset_definition_id;
    config.genesis_instructions.push(
        Register::asset_definition(AssetDefinition::numeric(
            xor,
            "XOR",
            AssetBalancePolicy::Global,
            None,
        ))
        .into(),
    );
    config.nexus = Some(nexus);
    let prepared = iroha_core::sumeragi::test_chain::CertifiedTestChain::prepare(config)
        .expect("space directory original signed genesis");
    let local_key = prepared.validator_keys[0].clone();
    let chain = iroha_core::sumeragi::test_chain::CertifiedTestChain::from_prepared(prepared)
        .expect("execute space directory original signed genesis");
    assert!(
        chain
            .validators()
            .iter()
            .any(|(peer, _)| peer.public_key() == local_key.public_key())
    );
    for lane in chain.state().nexus_snapshot().lane_catalog.lanes() {
        let authority = chain
            .state()
            .resolve_route_authority(iroha_core::state::LaneAuthorityRoute::new(
                lane.id,
                lane.dataspace_id,
            ))
            .expect("original signed committee resolves every configured manifest route");
        assert!(
            authority
                .validators()
                .iter()
                .any(|peer| peer.public_key() == local_key.public_key())
        );
    }
    (chain, local_key)
}
fn manifest_mutation_catalog() -> DataSpaceCatalog {
    let mut entries = vec![DataSpaceMetadata::default()];
    entries.extend([11, 12].into_iter().map(|id| DataSpaceMetadata {
        id: DataSpaceId::new(id),
        alias: format!("draft-{id}"),
        description: None,
        fault_tolerance: 1,
    }));
    DataSpaceCatalog::new(entries).expect("exact publish and revoke fixture dataspaces")
}
fn manifest_authority() -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![0xCE; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}
fn manifest_publish_harness() -> ManifestMutationHarness {
    let (chain, _) = manifest_fixture_chain(World::default(), Some(manifest_mutation_catalog()));
    let state = chain.state().clone();
    let events: iroha_core::EventsSender = tokio::sync::broadcast::channel(8).0;
    let queue = Arc::new(Queue::from_config(
        iroha_config::parameters::actual::Queue::default(),
        events,
    ));
    let context = Arc::new(ManifestMutationState {
        queue: queue.clone(),
        state: state.clone(),
    });
    ManifestMutationHarness {
        router: Router::new()
            .route(
                "/v1/space-directory/manifests",
                post(test_manifest_publish_handler),
            )
            .with_state(context),
        queue,
        state,
    }
}
fn manifest_revoke_harness() -> ManifestMutationHarness {
    let (chain, _) = manifest_fixture_chain(World::default(), Some(manifest_mutation_catalog()));
    let state = chain.state().clone();
    let events: iroha_core::EventsSender = tokio::sync::broadcast::channel(8).0;
    let queue = Arc::new(Queue::from_config(
        iroha_config::parameters::actual::Queue::default(),
        events,
    ));
    let context = Arc::new(ManifestMutationState {
        queue: queue.clone(),
        state: state.clone(),
    });
    ManifestMutationHarness {
        router: Router::new()
            .route(
                "/v1/space-directory/manifests/revoke",
                post(test_manifest_revoke_handler),
            )
            .with_state(context),
        queue,
        state,
    }
}
#[test]
fn space_directory_ed25519_fixture_uses_checked_key_generation() {
    let key_pair = checked_space_directory_ed25519_key_fixture();
    let algorithm = key_pair
        .public_key()
        .try_algorithm()
        .expect("fixture space directory Ed25519 public key has a valid algorithm");
    assert_eq!(algorithm, Algorithm::Ed25519);
}
#[test]
fn space_directory_account_fixture_uses_checked_ed25519_key_generation() {
    let account = checked_space_directory_account_fixture();
    let algorithm = account
        .expect_single_signatory()
        .try_algorithm()
        .expect("fixture space directory account public key has a valid algorithm");
    assert_eq!(algorithm, Algorithm::Ed25519);
}
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn space_directory_manifest_endpoint_returns_records() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let dataspace = DataSpaceId::new(11);
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::space_directory"));
    let account_key = checked_space_directory_ed25519_key_fixture();
    let account_id = AccountId::new(account_key.public_key().clone());
    let mut world = World::default();
    let mut bindings = iroha_core::nexus::space_directory::UaidDataspaceBindings::default();
    bindings.bind_account(dataspace, account_id.clone());
    world
        .uaid_dataspaces_mut_for_testing()
        .insert(uaid, bindings);
    let manifest = AssetPermissionManifest {
        version: ManifestVersion::V1,
        uaid,
        dataspace,
        issued_ms: 1_762_723_200_000,
        activation_epoch: 4_096,
        expiry_epoch: Some(8_192),
        entries: vec![cbdc_manifest_entry(
            dataspace,
            "transfer",
            500,
            Some("Wholesale daily cap"),
        )],
    };
    let mut record = SpaceDirectoryManifestRecord::new(manifest);
    record.lifecycle.activated_epoch = Some(4_096);
    let expected_hash = record.manifest_hash.as_ref().encode_hex::<String>();
    let mut set = SpaceDirectoryManifestSet::default();
    set.upsert(record);
    world
        .space_directory_manifests_mut_for_testing()
        .insert(uaid, set);
    let dataspace_catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: dataspace,
            alias: "cbdc".into(),
            description: Some("CBDC lane".into()),
            fault_tolerance: 1,
        },
    ])
    .expect("dataspace catalog");
    let (chain, local_key) = manifest_fixture_chain(world, Some(dataspace_catalog));
    cfg.common.key_pair = local_key;
    let kura = chain.kura().clone();
    let state = chain.state().clone();
    let torii = fixtures::StandardToriiHarness::from_state(&cfg, &kura, state.clone());
    let app = torii.router();
    let resp = fixtures::request_get(&app, &format!("/v1/space-directory/uaids/{uaid}/manifests"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let doc: Value = json::from_slice(&body).expect("manifest payload");
    assert_eq!(doc["uaid"], Value::from(uaid.to_string()));
    assert_eq!(doc["total"], Value::from(1));
    let entries = doc["manifests"].as_array().expect("array of manifests");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["dataspace_alias"], Value::from("cbdc"));
    assert_eq!(
        entries[0]["accounts"][0],
        Value::from(account_id.to_string())
    );
    assert_eq!(
        entries[0]["manifest_hash"],
        Value::from(expected_hash.as_str())
    );
    assert_eq!(
        entries[0]["accounts"][0],
        Value::from(account_id.to_string())
    );
    let raw_uaid = uaid.to_string().trim_start_matches("uaid:").to_owned();
    // Bindings endpoint returns canonical account literals.
    let resp = fixtures::request_get(&app, &format!("/v1/space-directory/uaids/{uaid}"))
        .await
        .expect("bindings response");
    assert_eq!(resp.status(), StatusCode::OK);
    let bindings_default = resp.into_body().collect().await.unwrap().to_bytes();
    let bindings_doc: Value = json::from_slice(&bindings_default).expect("bindings payload");
    let dataspaces = bindings_doc["dataspaces"]
        .as_array()
        .expect("dataspaces array");
    assert_eq!(dataspaces.len(), 1);
    assert_eq!(
        dataspaces[0]["accounts"][0],
        Value::from(account_id.to_string())
    );
    // Raw 64-hex UAID paths are not a first-release wire form.
    let resp = fixtures::request_get(&app, &format!("/v1/space-directory/uaids/{raw_uaid}"))
        .await
        .expect("raw-hex bindings response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    fixtures::response_body(resp, "raw bindings UAID response").await;
    // Dataspace filter excludes unknown ids.
    let resp = fixtures::request_get(
        &app,
        &format!(
            "/v1/space-directory/uaids/{uaid}/manifests?dataspace={}",
            dataspace.as_u64() + 1
        ),
    )
    .await
    .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let filtered = resp.into_body().collect().await.unwrap().to_bytes();
    let filtered_doc: Value = json::from_slice(&filtered).expect("filter payload");
    assert_eq!(filtered_doc["total"], Value::from(0));
    assert_eq!(
        filtered_doc["manifests"].as_array().unwrap().len(),
        0,
        "filter removes non-matching dataspaces"
    );
    // Configured dataspace with no explicit lane route still falls back to fanout filtering.
    let resp = fixtures::request_get(
        &app,
        &format!(
            "/v1/space-directory/uaids/{uaid}/manifests?dataspace={}",
            dataspace.as_u64()
        ),
    )
    .await
    .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let filtered_existing = resp.into_body().collect().await.unwrap().to_bytes();
    let filtered_existing_doc: Value =
        json::from_slice(&filtered_existing).expect("configured dataspace payload");
    assert_eq!(filtered_existing_doc["total"], Value::from(1));
    assert_eq!(
        filtered_existing_doc["manifests"].as_array().unwrap().len(),
        1,
        "configured dataspace filter preserves the matching manifest"
    );
    assert_eq!(
        filtered_existing_doc["manifests"][0]["manifest_hash"],
        Value::from(expected_hash.as_str())
    );
    let resp = fixtures::request_get(
        &app,
        &format!("/v1/space-directory/uaids/{raw_uaid}/manifests"),
    )
    .await
    .expect("raw-hex manifests response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    fixtures::response_body(resp, "raw manifests UAID response").await;
    // Status filter (active) yields the entry, limit/offset paginate.
    let resp = fixtures::request_get(
        &app,
        &format!("/v1/space-directory/uaids/{uaid}/manifests?status=active&limit=1"),
    )
    .await
    .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let active = resp.into_body().collect().await.unwrap().to_bytes();
    let active_doc: Value = json::from_slice(&active).expect("active payload");
    assert_eq!(active_doc["total"], Value::from(1));
    assert_eq!(
        active_doc["manifests"].as_array().unwrap().len(),
        1,
        "status=active returns bindings"
    );
    // Invalid status values are rejected by the manifest query parser.
    let resp = fixtures::request_get(
        &app,
        &format!("/v1/space-directory/uaids/{uaid}/manifests?status=DefinitelyNotAStatus"),
    )
    .await
    .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    fixtures::response_body(resp, "invalid manifest status response").await;
    // Build a revoked + second manifest world to test inactive/pagination.
    let mut cfg_rev = iroha_torii::test_utils::mk_minimal_root_cfg();
    let mut world_revoked = World::default();
    let mut bindings = iroha_core::nexus::space_directory::UaidDataspaceBindings::default();
    let dataspace_two = DataSpaceId::new(13);
    bindings.bind_account(dataspace, account_id.clone());
    bindings.bind_account(dataspace_two, account_id.clone());
    world_revoked
        .uaid_dataspaces_mut_for_testing()
        .insert(uaid, bindings);
    let mut record_revoked = SpaceDirectoryManifestRecord::new(AssetPermissionManifest {
        version: ManifestVersion::V1,
        uaid,
        dataspace,
        issued_ms: 0,
        activation_epoch: 100,
        expiry_epoch: None,
        entries: Vec::new(),
    });
    record_revoked.lifecycle.activated_epoch = Some(100);
    record_revoked
        .lifecycle
        .mark_revoked(200, Some("test revoke".into()));
    let mut record_active = SpaceDirectoryManifestRecord::new(AssetPermissionManifest {
        version: ManifestVersion::V1,
        uaid,
        dataspace: dataspace_two,
        issued_ms: 0,
        activation_epoch: 150,
        expiry_epoch: None,
        entries: Vec::new(),
    });
    record_active.lifecycle.activated_epoch = Some(150);
    let mut set = SpaceDirectoryManifestSet::default();
    set.upsert(record_revoked);
    set.upsert(record_active);
    world_revoked
        .space_directory_manifests_mut_for_testing()
        .insert(uaid, set);
    let catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: dataspace,
            alias: "cbdc".into(),
            description: None,
            fault_tolerance: 1,
        },
        DataSpaceMetadata {
            id: dataspace_two,
            alias: "retail".into(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("dataspace catalog");
    let (chain_revoked, local_key) = manifest_fixture_chain(world_revoked, Some(catalog));
    cfg_rev.common.key_pair = local_key;
    let local_peer_id_rev = PeerId::new(cfg_rev.common.key_pair.public_key().clone());
    let kura_rev = chain_revoked.kura().clone();
    let state_revoked = chain_revoked.state().clone();
    let queue_cfg_rev = iroha_config::parameters::actual::Queue::default();
    let events_sender_rev: iroha_core::EventsSender = tokio::sync::broadcast::channel(1).0;
    let queue_rev = Arc::new(iroha_core::queue::Queue::from_config(
        queue_cfg_rev,
        events_sender_rev,
    ));
    let torii_rev = fixtures::ToriiHarness::new(
        &cfg_rev,
        &kura_rev,
        &state_revoked,
        &queue_rev,
        &local_peer_id_rev,
        tokio::sync::broadcast::channel(1).0,
        iroha_config::parameters::actual::TelemetryProfile::Operator,
    );
    // Inactive filter returns revoked manifest.
    app.shutdown().await;
    let app = torii_rev.router();
    let resp = fixtures::request_get(
        &app,
        &format!("/v1/space-directory/uaids/{uaid}/manifests?status=inactive"),
    )
    .await
    .expect("inactive response");
    assert_eq!(resp.status(), StatusCode::OK);
    let inactive = resp.into_body().collect().await.unwrap().to_bytes();
    let inactive_doc: Value = json::from_slice(&inactive).expect("inactive payload");
    assert_eq!(inactive_doc["total"], Value::from(1));
    assert_eq!(
        inactive_doc["manifests"].as_array().unwrap().len(),
        1,
        "inactive filter returns one entry"
    );
    assert_eq!(
        inactive_doc["manifests"][0]["status"],
        Value::from("Revoked")
    );
    // Active filter + pagination.
    let resp = fixtures::request_get(
        &app,
        &format!("/v1/space-directory/uaids/{uaid}/manifests?status=active&limit=1&offset=0"),
    )
    .await
    .expect("active response");
    assert_eq!(resp.status(), StatusCode::OK);
    let active = resp.into_body().collect().await.unwrap().to_bytes();
    let active_doc: Value = json::from_slice(&active).expect("active payload");
    assert_eq!(active_doc["total"], Value::from(1));
    assert_eq!(
        active_doc["manifests"].as_array().unwrap().len(),
        1,
        "pagination limits to 1 entry"
    );
    // A zero limit must not bypass the configured pagination ceiling.
    let resp = fixtures::request_get(
        &app,
        &format!("/v1/space-directory/uaids/{uaid}/manifests?limit=0"),
    )
    .await
    .expect("zero-limit response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    app.shutdown().await;
}
#[tokio::test]
async fn space_directory_get_routes_reject_invalid_uaid_literals() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let world = World::default();
    let (chain, local_key) = manifest_fixture_chain(world, None);
    cfg.common.key_pair = local_key;
    let kura = chain.kura().clone();
    let state = chain.state().clone();
    let torii = fixtures::StandardToriiHarness::from_state(&cfg, &kura, state.clone());
    let app = torii.router();
    let bindings_resp = fixtures::request_get(&app, "/v1/space-directory/uaids/uaid:1234")
        .await
        .expect("bindings response");
    assert_eq!(bindings_resp.status(), StatusCode::BAD_REQUEST);
    fixtures::response_body(bindings_resp, "invalid bindings UAID response").await;
    let manifests_resp =
        fixtures::request_get(&app, "/v1/space-directory/uaids/uaid:1234/manifests")
            .await
            .expect("manifests response");
    assert_eq!(manifests_resp.status(), StatusCode::BAD_REQUEST);
    app.shutdown().await;
}
#[tokio::test]
async fn space_directory_bindings_route_returns_multiple_dataspaces_with_aliases() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let uaid = UniversalAccountId::from_hash(Hash::new(b"space-directory-bindings-multi"));
    let primary_dataspace = DataSpaceId::new(31);
    let secondary_dataspace = DataSpaceId::new(33);
    let primary_account = checked_space_directory_account_fixture();
    let secondary_account = checked_space_directory_account_fixture();
    let tertiary_account = checked_space_directory_account_fixture();
    let mut world = World::default();
    let mut bindings = iroha_core::nexus::space_directory::UaidDataspaceBindings::default();
    bindings.bind_account(primary_dataspace, secondary_account.clone());
    bindings.bind_account(primary_dataspace, primary_account.clone());
    bindings.bind_account(secondary_dataspace, tertiary_account.clone());
    world
        .uaid_dataspaces_mut_for_testing()
        .insert(uaid, bindings);
    let mut primary_record = SpaceDirectoryManifestRecord::new(AssetPermissionManifest {
        version: ManifestVersion::V1,
        uaid,
        dataspace: primary_dataspace,
        issued_ms: 1_762_723_200_000,
        activation_epoch: 4_096,
        expiry_epoch: Some(8_192),
        entries: Vec::new(),
    });
    primary_record.lifecycle.mark_activated(4_096);
    let mut secondary_record = SpaceDirectoryManifestRecord::new(AssetPermissionManifest {
        version: ManifestVersion::V1,
        uaid,
        dataspace: secondary_dataspace,
        issued_ms: 1_762_723_200_100,
        activation_epoch: 4_097,
        expiry_epoch: Some(8_193),
        entries: Vec::new(),
    });
    secondary_record.lifecycle.mark_activated(4_097);
    let mut set = SpaceDirectoryManifestSet::default();
    set.upsert(primary_record);
    set.upsert(secondary_record);
    world
        .space_directory_manifests_mut_for_testing()
        .insert(uaid, set);
    let catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: primary_dataspace,
            alias: "retail".into(),
            description: Some("Retail lane".into()),
            fault_tolerance: 1,
        },
    ])
    .expect("dataspace catalog");
    let (chain, local_key) = manifest_fixture_chain(world, Some(catalog));
    cfg.common.key_pair = local_key;
    let kura = chain.kura().clone();
    let state = chain.state().clone();
    let torii = fixtures::StandardToriiHarness::from_state(&cfg, &kura, state.clone());
    let app = torii.router();
    let resp = app
        .router()
        .oneshot(fixtures::get_request(
            &(format!("/v1/space-directory/uaids/{uaid}")),
        ))
        .await
        .expect("bindings response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let doc: Value = json::from_slice(&body).expect("bindings payload");
    assert_eq!(doc["uaid"], Value::from(uaid.to_string()));
    let dataspaces = doc["dataspaces"].as_array().expect("dataspaces array");
    assert_eq!(dataspaces.len(), 2);
    let primary = dataspaces
        .iter()
        .find(|entry| entry["dataspace_id"] == Value::from(primary_dataspace.as_u64()))
        .expect("primary dataspace entry");
    assert_eq!(primary["dataspace_alias"], Value::from("retail"));
    let mut actual_primary_accounts: Vec<_> = primary["accounts"]
        .as_array()
        .expect("primary accounts array")
        .iter()
        .map(|value| value.as_str().expect("primary account literal").to_owned())
        .collect();
    let mut expected_primary_accounts =
        vec![primary_account.to_string(), secondary_account.to_string()];
    actual_primary_accounts.sort_unstable();
    expected_primary_accounts.sort_unstable();
    assert_eq!(actual_primary_accounts, expected_primary_accounts);
    let secondary = dataspaces
        .iter()
        .find(|entry| entry["dataspace_id"] == Value::from(secondary_dataspace.as_u64()))
        .expect("secondary dataspace entry");
    assert!(
        secondary["dataspace_alias"].is_null(),
        "missing catalog alias should stay null in the public route payload",
    );
    assert_eq!(
        secondary["accounts"][0],
        Value::from(tertiary_account.to_string())
    );
    app.shutdown().await;
}
#[tokio::test]
async fn space_directory_manifest_endpoint_reports_filtered_total_when_public_page_is_empty() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let uaid = UniversalAccountId::from_hash(Hash::new(b"space-directory-empty-page"));
    let active_dataspace = DataSpaceId::new(41);
    let revoked_dataspace = DataSpaceId::new(42);
    let mut world = World::default();
    let mut active_record = SpaceDirectoryManifestRecord::new(AssetPermissionManifest {
        version: ManifestVersion::V1,
        uaid,
        dataspace: active_dataspace,
        issued_ms: 1_762_723_200_000,
        activation_epoch: 4_096,
        expiry_epoch: Some(8_192),
        entries: Vec::new(),
    });
    active_record.lifecycle.mark_activated(4_096);
    let mut revoked_record = SpaceDirectoryManifestRecord::new(AssetPermissionManifest {
        version: ManifestVersion::V1,
        uaid,
        dataspace: revoked_dataspace,
        issued_ms: 1_762_723_200_100,
        activation_epoch: 4_097,
        expiry_epoch: Some(8_193),
        entries: Vec::new(),
    });
    revoked_record.lifecycle.mark_activated(4_097);
    revoked_record.lifecycle.mark_revoked(4_200, None);
    let mut set = SpaceDirectoryManifestSet::default();
    set.upsert(active_record);
    set.upsert(revoked_record);
    world
        .space_directory_manifests_mut_for_testing()
        .insert(uaid, set);
    let catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: active_dataspace,
            alias: "active".into(),
            description: None,
            fault_tolerance: 1,
        },
        DataSpaceMetadata {
            id: revoked_dataspace,
            alias: "revoked".into(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("dataspace catalog");
    let (chain, local_key) = manifest_fixture_chain(world, Some(catalog));
    cfg.common.key_pair = local_key;
    let kura = chain.kura().clone();
    let state = chain.state().clone();
    let torii = fixtures::StandardToriiHarness::from_state(&cfg, &kura, state.clone());
    let app = torii.router();
    let resp = app
        .router()
        .oneshot(fixtures::get_request(
            &(format!("/v1/space-directory/uaids/{uaid}/manifests?status=active&limit=1&offset=1")),
        ))
        .await
        .expect("manifests response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let doc: Value = json::from_slice(&body).expect("manifests payload");
    assert_eq!(doc["uaid"], Value::from(uaid.to_string()));
    assert_eq!(doc["total"], Value::from(1));
    assert_eq!(
        doc["manifests"].as_array().expect("manifests array").len(),
        0,
        "total should count status-filtered rows even when pagination clears the page",
    );
    app.shutdown().await;
}
#[tokio::test]
async fn space_directory_manifest_endpoint_keeps_null_revocation_reason_in_json() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let dataspace = DataSpaceId::new(21);
    let uaid = UniversalAccountId::from_hash(Hash::new(b"space-directory-null-reason"));
    let account = checked_space_directory_account_fixture();
    let mut world = World::default();
    let mut bindings = iroha_core::nexus::space_directory::UaidDataspaceBindings::default();
    bindings.bind_account(dataspace, account.clone());
    world
        .uaid_dataspaces_mut_for_testing()
        .insert(uaid, bindings);
    let manifest = AssetPermissionManifest {
        version: ManifestVersion::V1,
        uaid,
        dataspace,
        issued_ms: 1_762_723_200_000,
        activation_epoch: 4_096,
        expiry_epoch: Some(8_192),
        entries: Vec::new(),
    };
    let mut record = SpaceDirectoryManifestRecord::new(manifest);
    record.lifecycle.mark_activated(4_096);
    record.lifecycle.mark_revoked(4_200, None);
    let mut set = SpaceDirectoryManifestSet::default();
    set.upsert(record);
    world
        .space_directory_manifests_mut_for_testing()
        .insert(uaid, set);
    let catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: dataspace,
            alias: "archived".into(),
            description: Some("Archived dataspace".into()),
            fault_tolerance: 1,
        },
    ])
    .expect("dataspace catalog");
    let (chain, local_key) = manifest_fixture_chain(world, Some(catalog));
    cfg.common.key_pair = local_key;
    let kura = chain.kura().clone();
    let state = chain.state().clone();
    let torii = fixtures::StandardToriiHarness::from_state(&cfg, &kura, state.clone());
    let app = torii.router();
    let resp = app
        .router()
        .oneshot(fixtures::get_request(
            &(format!("/v1/space-directory/uaids/{uaid}/manifests?status=inactive")),
        ))
        .await
        .expect("inactive response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let doc: Value = json::from_slice(&body).expect("inactive payload");
    assert_eq!(doc["total"], Value::from(1));
    assert_eq!(doc["manifests"][0]["status"], Value::from("Revoked"));
    assert_eq!(
        doc["manifests"][0]["dataspace_alias"],
        Value::from("archived")
    );
    assert_eq!(
        doc["manifests"][0]["accounts"][0],
        Value::from(account.to_string())
    );
    assert!(
        doc["manifests"][0]["lifecycle"]["revocation"]["reason"].is_null(),
        "reasonless revocations should stay explicit nulls in route payloads",
    );
    app.shutdown().await;
}
#[tokio::test]
async fn manifest_publish_endpoint_returns_unsigned_transaction_draft() {
    let ManifestMutationHarness { router, queue, .. } = manifest_publish_harness();
    let authority = manifest_authority();
    let dataspace = DataSpaceId::new(11);
    let uaid = UniversalAccountId::from_hash(Hash::new(b"publish-manifest"));
    let manifest = AssetPermissionManifest {
        version: ManifestVersion::V1,
        uaid,
        dataspace,
        issued_ms: 1_762_723_200_000,
        activation_epoch: 4_096,
        expiry_epoch: Some(8_192),
        entries: vec![cbdc_manifest_entry(dataspace, "transfer", 500, None)],
    };
    let manifest_value = norito::json::to_value(&manifest).expect("manifest json");
    let value = iroha_torii::json_object(vec![
        iroha_torii::json_entry("authority", authority.clone()),
        iroha_torii::json_entry("manifest", manifest_value),
        iroha_torii::json_entry("reason", "QA publish trigger"),
    ]);
    let body = norito::json::to_json(&value).expect("serialize publish request");
    let req = Request::builder()
        .method("POST")
        .uri("/v1/space-directory/manifests")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .expect("request");
    let resp = fixtures::request(&router, req)
        .await
        .expect("publish response body");
    let payload = decode_unsigned_transaction_draft(resp).await;
    assert!(matches!(
        payload.instructions(),
        Executable::Instructions(_)
    ));
    assert_eq!(queue.queued_len(), 0, "Torii must not submit the draft");
}
#[tokio::test]
async fn manifest_publish_endpoint_applies_reason_only_to_entries_missing_notes() {
    let ManifestMutationHarness { router, queue, .. } = manifest_publish_harness();
    let authority = manifest_authority();
    let dataspace = DataSpaceId::new(11);
    let uaid = UniversalAccountId::from_hash(Hash::new(b"publish-manifest-reason"));
    let manifest = AssetPermissionManifest {
        version: ManifestVersion::V1,
        uaid,
        dataspace,
        issued_ms: 1_762_723_200_000,
        activation_epoch: 4_096,
        expiry_epoch: Some(8_192),
        entries: vec![
            cbdc_manifest_entry(dataspace, "transfer", 500, None),
            cbdc_manifest_entry(dataspace, "refund", 100, Some("keep existing")),
        ],
    };
    let manifest_value = norito::json::to_value(&manifest).expect("manifest json");
    let value = iroha_torii::json_object(vec![
        iroha_torii::json_entry("authority", authority.clone()),
        iroha_torii::json_entry("manifest", manifest_value),
        iroha_torii::json_entry("reason", "QA publish trigger"),
    ]);
    let body = norito::json::to_json(&value).expect("serialize publish request");
    let req = Request::builder()
        .method("POST")
        .uri("/v1/space-directory/manifests")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .expect("request");
    let resp = fixtures::request(&router, req)
        .await
        .expect("publish response body");
    let payload = decode_unsigned_transaction_draft(resp).await;
    assert_eq!(queue.queued_len(), 0, "Torii must not submit the draft");
    let Executable::Instructions(instructions) = payload.instructions() else {
        panic!("publish draft should contain an instruction transaction");
    };
    assert_eq!(instructions.len(), 1);
    let publish = instructions[0]
        .as_any()
        .downcast_ref::<iroha_data_model::isi::space_directory::PublishSpaceDirectoryManifest>()
        .expect("queued instruction should be publish manifest");
    assert_eq!(
        publish.manifest.entries[0].notes.as_deref(),
        Some("QA publish trigger")
    );
    assert_eq!(
        publish.manifest.entries[1].notes.as_deref(),
        Some("keep existing")
    );
}
#[tokio::test]
async fn manifest_publish_endpoint_preserves_missing_notes_when_reason_is_omitted() {
    let ManifestMutationHarness { router, queue, .. } = manifest_publish_harness();
    let authority = manifest_authority();
    let dataspace = DataSpaceId::new(12);
    let uaid = UniversalAccountId::from_hash(Hash::new(b"publish-manifest-no-reason"));
    let manifest = AssetPermissionManifest {
        version: ManifestVersion::V1,
        uaid,
        dataspace,
        issued_ms: 1_762_723_200_000,
        activation_epoch: 4_096,
        expiry_epoch: Some(8_192),
        entries: vec![cbdc_manifest_entry(dataspace, "transfer", 500, None)],
    };
    let manifest_value = norito::json::to_value(&manifest).expect("manifest json");
    let value = iroha_torii::json_object(vec![
        iroha_torii::json_entry("authority", authority.clone()),
        iroha_torii::json_entry("manifest", manifest_value),
    ]);
    let body = norito::json::to_json(&value).expect("serialize publish request");
    let req = Request::builder()
        .method("POST")
        .uri("/v1/space-directory/manifests")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .expect("request");
    let resp = fixtures::request(&router, req)
        .await
        .expect("publish response body");
    let payload = decode_unsigned_transaction_draft(resp).await;
    assert_eq!(queue.queued_len(), 0, "Torii must not submit the draft");
    let Executable::Instructions(instructions) = payload.instructions() else {
        panic!("publish draft should contain an instruction transaction");
    };
    let publish = instructions[0]
        .as_any()
        .downcast_ref::<iroha_data_model::isi::space_directory::PublishSpaceDirectoryManifest>()
        .expect("queued instruction should be publish manifest");
    assert!(
        publish.manifest.entries[0].notes.is_none(),
        "omitting reason should leave missing notes untouched",
    );
}
#[tokio::test]
async fn manifest_revoke_endpoint_returns_unsigned_transaction_draft() {
    let ManifestMutationHarness { router, queue, .. } = manifest_revoke_harness();
    let authority = manifest_authority();
    let uaid_hash = iroha_crypto::Hash::new(b"space-directory-revoke");
    let uaid_literal = format!("uaid:{}", uaid_hash.as_ref().encode_hex::<String>());
    let value = iroha_torii::json_object(vec![
        iroha_torii::json_entry("authority", authority.clone()),
        iroha_torii::json_entry("uaid", uaid_literal),
        iroha_torii::json_entry("dataspace", 11u64),
        iroha_torii::json_entry("revoked_epoch", 4096u64),
        iroha_torii::json_entry("reason", "test emergency revoke"),
    ]);
    let body = norito::json::to_json(&value).expect("serialize revoke request");
    let req = Request::builder()
        .method("POST")
        .uri("/v1/space-directory/manifests/revoke")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .expect("request");
    let resp = fixtures::request(&router, req)
        .await
        .expect("revoke response body");
    let payload = decode_unsigned_transaction_draft(resp).await;
    assert!(matches!(
        payload.instructions(),
        Executable::Instructions(_)
    ));
    assert_eq!(queue.queued_len(), 0, "Torii must not submit the draft");
}
#[tokio::test]
async fn manifest_revoke_endpoint_rejects_padded_mixed_case_uaid() {
    let ManifestMutationHarness { router, queue, .. } = manifest_revoke_harness();
    let authority = manifest_authority();
    let uaid_hash = iroha_crypto::Hash::new(b"space-directory-revoke-canonical");
    let uaid_literal = format!(
        "  UaId:  {}  ",
        uaid_hash.as_ref().encode_hex::<String>().to_uppercase()
    );
    let value = iroha_torii::json_object(vec![
        iroha_torii::json_entry("authority", authority.clone()),
        iroha_torii::json_entry("uaid", uaid_literal),
        iroha_torii::json_entry("dataspace", 11u64),
        iroha_torii::json_entry("revoked_epoch", 4096u64),
        iroha_torii::json_entry("reason", "test emergency revoke"),
    ]);
    let body = norito::json::to_json(&value).expect("serialize revoke request");
    let req = Request::builder()
        .method("POST")
        .uri("/v1/space-directory/manifests/revoke")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .expect("request");
    let resp = fixtures::request(&router, req)
        .await
        .expect("revoke response body");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(queue.queued_len(), 0, "Torii must not submit the draft");
}
#[tokio::test]
async fn manifest_revoke_endpoint_rejects_raw_hex_uaid() {
    let ManifestMutationHarness { router, queue, .. } = manifest_revoke_harness();
    let authority = manifest_authority();
    let uaid_hash = iroha_crypto::Hash::new(b"space-directory-revoke-raw-no-reason");
    let raw_hex = uaid_hash.as_ref().encode_hex::<String>();
    let value = iroha_torii::json_object(vec![
        iroha_torii::json_entry("authority", authority.clone()),
        iroha_torii::json_entry("uaid", raw_hex),
        iroha_torii::json_entry("dataspace", 12u64),
        iroha_torii::json_entry("revoked_epoch", 8192u64),
    ]);
    let body = norito::json::to_json(&value).expect("serialize revoke request");
    let req = Request::builder()
        .method("POST")
        .uri("/v1/space-directory/manifests/revoke")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .expect("request");
    let resp = fixtures::request(&router, req)
        .await
        .expect("revoke response body");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(queue.queued_len(), 0, "Torii must not submit the draft");
}
#[tokio::test]
async fn manifest_revoke_endpoint_rejects_invalid_uaid_before_queueing() {
    let ManifestMutationHarness {
        router,
        queue,
        state,
    } = manifest_revoke_harness();
    let authority = manifest_authority();
    let value = iroha_torii::json_object(vec![
        iroha_torii::json_entry("authority", authority.clone()),
        iroha_torii::json_entry("uaid", "uaid:1234"),
        iroha_torii::json_entry("dataspace", 11u64),
        iroha_torii::json_entry("revoked_epoch", 4096u64),
        iroha_torii::json_entry("reason", "test emergency revoke"),
    ]);
    let body = norito::json::to_json(&value).expect("serialize revoke request");
    let req = Request::builder()
        .method("POST")
        .uri("/v1/space-directory/manifests/revoke")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .expect("request");
    let resp = fixtures::request(&router, req)
        .await
        .expect("revoke response body");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        queue.queued_len(),
        0,
        "invalid UAID must not enqueue a transaction"
    );
    let queued = {
        let state_view = state.view();
        queue.all_transactions(&state_view).count()
    };
    assert_eq!(
        queued, 0,
        "invalid UAID must not leave pending transactions"
    );
}
#[tokio::test]
async fn api_router_registers_space_directory_manifest_mutation_routes() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let torii = fixtures::StandardToriiHarness::new(&cfg, World::default());
    let authority = manifest_authority();
    let dataspace = DataSpaceId::new(11);
    let uaid = UniversalAccountId::from_hash(Hash::new(b"router-manifest"));
    let manifest = AssetPermissionManifest {
        version: ManifestVersion::V1,
        uaid,
        dataspace,
        issued_ms: 1_762_723_200_000,
        activation_epoch: 4_096,
        expiry_epoch: Some(8_192),
        entries: vec![cbdc_manifest_entry(
            dataspace,
            "transfer",
            500,
            Some("router registration"),
        )],
    };
    let manifest_value = norito::json::to_value(&manifest).expect("manifest json");
    let publish_body = norito::json::to_json(&iroha_torii::json_object(vec![
        iroha_torii::json_entry("authority", authority.clone()),
        iroha_torii::json_entry("manifest", manifest_value),
        iroha_torii::json_entry("reason", "router publish"),
    ]))
    .expect("serialize publish request");
    let app = torii.router();
    let publish_resp = app
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/space-directory/manifests")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(publish_body))
                .expect("publish request"),
        )
        .await
        .expect("publish response");
    assert_ne!(
        publish_resp.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "publish route must be registered on the Torii API router",
    );
    assert_ne!(
        publish_resp.status(),
        StatusCode::NOT_FOUND,
        "publish route must be registered on the Torii API router",
    );
    let uaid_literal = format!(
        "uaid:{}",
        Hash::new(b"router-revoke").as_ref().encode_hex::<String>()
    );
    let revoke_body = norito::json::to_json(&iroha_torii::json_object(vec![
        iroha_torii::json_entry("authority", authority.clone()),
        iroha_torii::json_entry("uaid", uaid_literal),
        iroha_torii::json_entry("dataspace", dataspace.as_u64()),
        iroha_torii::json_entry("revoked_epoch", 4096u64),
        iroha_torii::json_entry("reason", "router revoke"),
    ]))
    .expect("serialize revoke request");
    let revoke_resp = app
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/space-directory/manifests/revoke")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(revoke_body))
                .expect("revoke request"),
        )
        .await
        .expect("revoke response");
    assert_ne!(
        revoke_resp.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "revoke route must be registered on the Torii API router",
    );
    assert_ne!(
        revoke_resp.status(),
        StatusCode::NOT_FOUND,
        "revoke route must be registered on the Torii API router",
    );
    app.shutdown().await;
}
