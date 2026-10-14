//! Torii Nexus dataspaces account summary endpoint tests.
#![cfg(feature = "app_api")]
use axum::{body::Body, http::Request};
use http::StatusCode;
use http_body_util::BodyExt as _;
use iroha_config::parameters::actual::Queue;
use iroha_core::{
    kura::Kura,
    nexus::space_directory::{
        SpaceDirectoryManifestRecord, SpaceDirectoryManifestSet, UaidDataspaceBindings,
    },
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World, WorldReadOnly},
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    account::{AccountId, NewAccount},
    asset::{AssetBalancePolicy, AssetDefinitionId, AssetId, NewAssetDefinition},
    block::BlockHeader,
    domain::Domain,
    isi::{Mint, Register},
    nexus::{
        Allowance, AllowanceWindow, AssetPermissionManifest, CapabilityScope, DataSpaceCatalog,
        DataSpaceMetadata, ManifestEffect, ManifestEntry, ManifestVersion, UniversalAccountId,
    },
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::peer::PeerId;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::numeric::Quantity;
use iroha_test_samples::ALICE_ID;
use mv::storage::StorageReadOnly;
use norito::json::{self, Value};
use std::{collections::HashSet, num::NonZeroU64, sync::Arc};
use tokio::sync::broadcast;
use tower::ServiceExt as _;
#[path = "fixtures.rs"]
mod fixtures;
fn checked_nexus_dataspaces_summary_ed25519_key_fixture() -> KeyPair {
    KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
        .expect("generate checked Nexus dataspaces summary Ed25519 fixture keypair")
}
#[test]
fn nexus_dataspaces_summary_ed25519_fixture_uses_checked_key_generation() {
    let key_pair = checked_nexus_dataspaces_summary_ed25519_key_fixture();
    let algorithm = key_pair
        .public_key()
        .try_algorithm()
        .expect("fixture Nexus dataspaces summary public key has a valid algorithm");
    assert_eq!(algorithm, Algorithm::Ed25519);
}
#[tokio::test(flavor = "current_thread")]
async fn nexus_dataspaces_summary_endpoint_returns_joined_snapshot() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let query = LiveQueryStore::start_test();
    let domain_id: DomainId = DomainId::try_new("nexus", "universal").expect("domain id");
    let account_keypair = checked_nexus_dataspaces_summary_ed25519_key_fixture();
    let account_id = AccountId::new(account_keypair.public_key().clone());
    let account_literal = account_id.to_string();
    let i105_literal = account_id
        .to_account_address()
        .and_then(|address| address.to_i105())
        .expect("i105 account literal");
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::torii::dataspaces::summary"));
    let dataspace = DataSpaceId::new(42);
    let mut world = World::default();
    let manifest = AssetPermissionManifest {
        version: ManifestVersion::V1,
        uaid,
        dataspace,
        issued_ms: 1_710_000_000_000,
        activation_epoch: 100,
        expiry_epoch: Some(200),
        entries: vec![ManifestEntry {
            scope: CapabilityScope {
                dataspace: Some(dataspace),
                program: None,
                method: None,
                asset: None,
                role: None,
            },
            effect: ManifestEffect::Allow(Allowance {
                max_amount: Some(Quantity::from(1_000_u32)),
                window: AllowanceWindow::PerDay,
            }),
            notes: Some("daily limit".to_owned()),
        }],
    };
    let mut record = SpaceDirectoryManifestRecord::new(manifest);
    record.lifecycle.mark_activated(101);
    let mut set = SpaceDirectoryManifestSet::default();
    set.upsert(record);
    world
        .space_directory_manifests_mut_for_testing()
        .insert(uaid, set);
    let mut nexus = cfg.nexus.clone();
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: dataspace,
            alias: "retail".to_owned(),
            description: Some("Retail payments lane".to_owned()),
            fault_tolerance: 1,
        },
    ])
    .expect("dataspace catalog");
    let (state, _kura) = State::new_with_chain_and_network_id_and_pre_genesis_nexus_for_testing(
        world,
        nexus,
        query,
        cfg.common.chain.clone(),
        iroha_data_model::NetworkId::from_genesis_hash(cfg.genesis.expected_hash),
    );
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("nexus", "universal").expect("domain id"),
        "xor".parse().expect("asset definition name"),
    );
    let mut block = state.block(block_header(1));
    let mut stx = block.transaction();
    Register::domain(Domain::new(domain_id.clone()))
        .execute(&ALICE_ID, &mut stx)
        .expect("register domain");
    Register::account(NewAccount::new(account_id.clone()).with_uaid(Some(uaid)))
        .execute(&ALICE_ID, &mut stx)
        .expect("register account with uaid");
    Register::asset_definition(NewAssetDefinition {
        id: asset_definition_id.clone(),
        name: "xor".to_owned(),
        description: None,
        alias: None,
        spec: Default::default(),
        mintable: Default::default(),
        logo: None,
        metadata: Default::default(),
        balance_scope_policy: AssetBalancePolicy::Global,
        owning_domain: Some(domain_id.clone()),
    })
    .execute(&ALICE_ID, &mut stx)
    .expect("register asset definition");
    Mint::asset_quantity(
        500u64,
        AssetId::new(asset_definition_id.clone(), account_id.clone()),
    )
    .execute(&ALICE_ID, &mut stx)
    .expect("mint asset");
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit seeded state");
    let router = build_test_router(Arc::new(state));
    let response = router
        .router()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/nexus/dataspaces/accounts/{}/summary",
                    urlencoding::encode(&account_literal)
                ))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let payload: Value = json::from_slice(&body).expect("json payload");
    assert_eq!(payload["account_id"], Value::from(account_literal.as_str()));
    assert_eq!(payload["account"], Value::from(i105_literal.as_str()));
    assert_eq!(payload["uaid"], Value::from(uaid.to_string()));
    assert_eq!(payload["totals"]["dataspaces"], Value::from(1));
    assert_eq!(payload["totals"]["portfolio_positions"], Value::from(1));
    assert_eq!(payload["totals"]["manifests_active"], Value::from(1));
    let dataspaces = payload["dataspaces"].as_array().expect("dataspaces array");
    assert_eq!(dataspaces.len(), 1);
    let row = &dataspaces[0];
    assert_eq!(row["dataspace_id"], Value::from(dataspace.as_u64()));
    assert_eq!(row["dataspace_alias"], Value::from("retail"));
    assert_eq!(row["accounts"].as_array().expect("accounts").len(), 1);
    assert_eq!(
        row["accounts"][0],
        Value::from(i105_literal.as_str()),
        "dataspace row should render canonical I105 account literal"
    );
    assert_eq!(row["manifest"]["status"], Value::from("Active"));
    assert_eq!(row["portfolio"]["positions"], Value::from(1));
    router.shutdown().await;
}
#[tokio::test(flavor = "current_thread")]
async fn nexus_dataspaces_summary_endpoint_returns_zeroed_snapshot_for_account_without_uaid() {
    let state = minimal_state();
    let account_keypair = checked_nexus_dataspaces_summary_ed25519_key_fixture();
    let account_id = AccountId::new(account_keypair.public_key().clone());
    let account_literal = account_id.to_string();
    let i105_literal = account_id
        .to_account_address()
        .and_then(|address| address.to_i105())
        .expect("i105 account literal");
    let mut block = state.block(block_header(1));
    let mut stx = block.transaction();
    Register::account(NewAccount::new(account_id.clone()))
        .execute(&ALICE_ID, &mut stx)
        .expect("register account");
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit account");
    let router = build_test_router(state);
    let spaced_literal = format!("  {account_literal}  ");
    let literal = urlencoding::encode(&spaced_literal);
    let uri = format!("/v1/nexus/dataspaces/accounts/{literal}/summary");
    let (status, body) = request_summary(&router, &uri).await;
    assert_eq!(status, StatusCode::OK, "unexpected body: {body}");
    let payload: Value = json::from_str(&body).expect("json payload");
    assert_current_summary_shape(&payload);
    assert_eq!(payload["account_id"], Value::from(account_literal.as_str()));
    assert_eq!(payload["account"], Value::from(i105_literal.as_str()));
    assert!(payload["uaid"].is_null(), "uaid should be null: {body}");
    assert_eq!(payload["totals"]["dataspaces"], Value::from(0));
    assert_eq!(payload["totals"]["accounts_bound"], Value::from(0));
    assert_eq!(payload["totals"]["portfolio_accounts"], Value::from(0));
    assert_eq!(payload["totals"]["portfolio_positions"], Value::from(0));
    assert_eq!(payload["totals"]["manifests_total"], Value::from(0));
    assert_eq!(payload["totals"]["manifests_active"], Value::from(0));
    assert_eq!(
        payload["dataspaces"].as_array().expect("dataspaces"),
        &Vec::<Value>::new()
    );
    router.shutdown().await;
}
#[tokio::test(flavor = "current_thread")]
async fn nexus_dataspaces_summary_endpoint_reports_portfolio_only_default_dataspace() {
    let state = minimal_state();
    let account_keypair = checked_nexus_dataspaces_summary_ed25519_key_fixture();
    let account_id = AccountId::new(account_keypair.public_key().clone());
    let account_literal = account_id.to_string();
    let i105_literal = account_id
        .to_account_address()
        .and_then(|address| address.to_i105())
        .expect("i105 account literal");
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::torii::portfolio_only"));
    let domain_id: DomainId = DomainId::try_new("portfolio-only", "universal").expect("domain id");
    let definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "rose".parse().expect("asset definition name"),
    );
    let mut block = state.block(block_header(1));
    let mut stx = block.transaction();
    Register::domain(Domain::new(domain_id.clone()))
        .execute(&ALICE_ID, &mut stx)
        .expect("register domain");
    Register::account(NewAccount::new(account_id.clone()).with_uaid(Some(uaid)))
        .execute(&ALICE_ID, &mut stx)
        .expect("register account with uaid");
    Register::asset_definition(NewAssetDefinition {
        id: definition_id.clone(),
        name: "rose".to_owned(),
        description: None,
        alias: None,
        spec: Default::default(),
        mintable: Default::default(),
        logo: None,
        metadata: Default::default(),
        balance_scope_policy: AssetBalancePolicy::Global,
        owning_domain: Some(domain_id.clone()),
    })
    .execute(&ALICE_ID, &mut stx)
    .expect("register asset definition");
    Mint::asset_quantity(25u64, AssetId::new(definition_id, account_id.clone()))
        .execute(&ALICE_ID, &mut stx)
        .expect("mint asset");
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit seeded state");
    let router = build_test_router(state);
    let literal = urlencoding::encode(&account_literal);
    let uri = format!("/v1/nexus/dataspaces/accounts/{literal}/summary");
    let (status, body) = request_summary(&router, &uri).await;
    assert_eq!(status, StatusCode::OK, "unexpected body: {body}");
    let payload: Value = json::from_str(&body).expect("json payload");
    assert_current_summary_shape(&payload);
    assert_eq!(payload["account_id"], Value::from(account_literal.as_str()));
    assert_eq!(payload["account"], Value::from(i105_literal.as_str()));
    assert_eq!(payload["uaid"], Value::from(uaid.to_string()));
    assert_eq!(payload["totals"]["dataspaces"], Value::from(1));
    assert_eq!(payload["totals"]["accounts_bound"], Value::from(1));
    assert_eq!(payload["totals"]["portfolio_accounts"], Value::from(1));
    assert_eq!(payload["totals"]["portfolio_positions"], Value::from(1));
    assert_eq!(payload["totals"]["manifests_total"], Value::from(0));
    assert_eq!(payload["totals"]["manifests_active"], Value::from(0));
    let dataspaces = payload["dataspaces"].as_array().expect("dataspaces array");
    assert_eq!(dataspaces.len(), 1);
    let row = &dataspaces[0];
    assert_eq!(
        row["dataspace_id"],
        Value::from(DataSpaceId::UNIVERSAL.as_u64())
    );
    assert_eq!(row["dataspace_alias"], Value::from("universal"));
    assert_eq!(
        row["accounts"].as_array().expect("accounts"),
        &vec![Value::from(i105_literal.as_str())]
    );
    assert_eq!(row["portfolio"]["accounts"], Value::from(1));
    assert_eq!(row["portfolio"]["positions"], Value::from(1));
    assert_eq!(row["portfolio"]["asset_definitions"], Value::from(1));
    assert_eq!(row["manifest"]["status"], Value::from("Missing"));
    router.shutdown().await;
}
#[tokio::test(flavor = "current_thread")]
async fn nexus_dataspaces_summary_endpoint_reports_pending_expired_and_revoked_manifests() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let query = LiveQueryStore::start_test();
    let pending_dataspace = DataSpaceId::new(7);
    let expired_dataspace = DataSpaceId::new(8);
    let revoked_dataspace = DataSpaceId::new(9);
    let account_keypair = checked_nexus_dataspaces_summary_ed25519_key_fixture();
    let account_id = AccountId::new(account_keypair.public_key().clone());
    let account_literal = account_id.to_string();
    let i105_literal = account_id
        .to_account_address()
        .and_then(|address| address.to_i105())
        .expect("i105 account literal");
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::torii::manifest_states"));
    let manifest_for = |dataspace: DataSpaceId, issued_ms: u64| AssetPermissionManifest {
        version: ManifestVersion::V1,
        uaid,
        dataspace,
        issued_ms,
        activation_epoch: 10,
        expiry_epoch: Some(30),
        entries: Vec::new(),
    };
    let mut world = World::default();
    let mut bindings = UaidDataspaceBindings::default();
    for dataspace in [pending_dataspace, expired_dataspace, revoked_dataspace] {
        bindings.bind_account(dataspace, account_id.clone());
    }
    world
        .uaid_dataspaces_mut_for_testing()
        .insert(uaid, bindings);
    let pending_record =
        SpaceDirectoryManifestRecord::new(manifest_for(pending_dataspace, 1_710_000_000_000));
    let mut expired_record =
        SpaceDirectoryManifestRecord::new(manifest_for(expired_dataspace, 1_710_000_000_100));
    expired_record.lifecycle.mark_activated(11);
    expired_record.lifecycle.mark_expired(22);
    let mut revoked_record =
        SpaceDirectoryManifestRecord::new(manifest_for(revoked_dataspace, 1_710_000_000_200));
    revoked_record.lifecycle.mark_activated(12);
    revoked_record
        .lifecycle
        .mark_revoked(23, Some("operator request".to_owned()));
    let mut set = SpaceDirectoryManifestSet::default();
    set.upsert(pending_record);
    set.upsert(expired_record);
    set.upsert(revoked_record);
    world
        .space_directory_manifests_mut_for_testing()
        .insert(uaid, set);
    let mut nexus = cfg.nexus.clone();
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: pending_dataspace,
            alias: "pending".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
        DataSpaceMetadata {
            id: expired_dataspace,
            alias: "expired".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
        DataSpaceMetadata {
            id: revoked_dataspace,
            alias: "revoked".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("dataspace catalog");
    let (state, _kura) = State::new_with_chain_and_network_id_and_pre_genesis_nexus_for_testing(
        world,
        nexus,
        query,
        cfg.common.chain.clone(),
        iroha_data_model::NetworkId::from_genesis_hash(cfg.genesis.expected_hash),
    );
    let mut block = state.block(block_header(1));
    let mut stx = block.transaction();
    Register::account(NewAccount::new(account_id.clone()).with_uaid(Some(uaid)))
        .execute(&ALICE_ID, &mut stx)
        .expect("register account with uaid");
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit account");
    let router = build_test_router(Arc::new(state));
    let literal = urlencoding::encode(&account_literal);
    let uri = format!("/v1/nexus/dataspaces/accounts/{literal}/summary");
    let (status, body) = request_summary(&router, &uri).await;
    assert_eq!(status, StatusCode::OK, "unexpected body: {body}");
    let payload: Value = json::from_str(&body).expect("json payload");
    assert_current_summary_shape(&payload);
    assert_eq!(payload["account_id"], Value::from(account_literal.as_str()));
    assert_eq!(payload["account"], Value::from(i105_literal.as_str()));
    assert_eq!(payload["uaid"], Value::from(uaid.to_string()));
    assert_eq!(payload["totals"]["dataspaces"], Value::from(4));
    assert_eq!(payload["totals"]["accounts_bound"], Value::from(1));
    assert_eq!(payload["totals"]["portfolio_accounts"], Value::from(1));
    assert_eq!(payload["totals"]["portfolio_positions"], Value::from(0));
    assert_eq!(payload["totals"]["manifests_total"], Value::from(3));
    assert_eq!(payload["totals"]["manifests_active"], Value::from(0));
    let dataspaces = payload["dataspaces"].as_array().expect("dataspaces array");
    assert_eq!(dataspaces.len(), 4);
    let universal = &dataspaces[0];
    assert_eq!(
        universal["dataspace_id"],
        Value::from(DataSpaceId::UNIVERSAL.as_u64())
    );
    assert_eq!(universal["dataspace_alias"], Value::from("universal"));
    assert_eq!(
        universal["accounts"].as_array().expect("accounts"),
        &vec![Value::from(i105_literal.as_str())]
    );
    assert_eq!(universal["manifest"]["status"], Value::from("Missing"));
    assert_eq!(universal["portfolio"]["accounts"], Value::from(1));
    assert_eq!(universal["portfolio"]["positions"], Value::from(0));
    let pending = &dataspaces[1];
    assert_eq!(
        pending["dataspace_id"],
        Value::from(pending_dataspace.as_u64())
    );
    assert_eq!(pending["dataspace_alias"], Value::from("pending"));
    assert_eq!(pending["accounts"].as_array().expect("accounts").len(), 0);
    assert_eq!(pending["manifest"]["status"], Value::from("Pending"));
    assert!(pending["manifest"]["activated_epoch"].is_null());
    assert!(pending["manifest"]["expired_epoch"].is_null());
    assert!(pending["manifest"]["revoked_epoch"].is_null());
    assert_eq!(pending["portfolio"]["accounts"], Value::from(0));
    assert_eq!(pending["portfolio"]["positions"], Value::from(0));
    let expired = &dataspaces[2];
    assert_eq!(
        expired["dataspace_id"],
        Value::from(expired_dataspace.as_u64())
    );
    assert_eq!(expired["dataspace_alias"], Value::from("expired"));
    assert_eq!(expired["accounts"].as_array().expect("accounts").len(), 0);
    assert_eq!(expired["manifest"]["status"], Value::from("Expired"));
    assert_eq!(expired["manifest"]["activated_epoch"], Value::from(11));
    assert_eq!(expired["manifest"]["expired_epoch"], Value::from(22));
    assert!(expired["manifest"]["revoked_epoch"].is_null());
    assert_eq!(expired["portfolio"]["accounts"], Value::from(0));
    let revoked = &dataspaces[3];
    assert_eq!(
        revoked["dataspace_id"],
        Value::from(revoked_dataspace.as_u64())
    );
    assert_eq!(revoked["dataspace_alias"], Value::from("revoked"));
    assert_eq!(revoked["accounts"].as_array().expect("accounts").len(), 0);
    assert_eq!(revoked["manifest"]["status"], Value::from("Revoked"));
    assert_eq!(revoked["manifest"]["activated_epoch"], Value::from(12));
    assert_eq!(revoked["manifest"]["revoked_epoch"], Value::from(23));
    assert_eq!(
        revoked["manifest"]["revoked_reason"],
        Value::from("operator request")
    );
    assert_eq!(revoked["portfolio"]["accounts"], Value::from(0));
    router.shutdown().await;
}
#[tokio::test(flavor = "current_thread")]
async fn nexus_dataspaces_summary_endpoint_prunes_uncataloged_state_and_preserves_global_portfolio()
{
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let dataspace = DataSpaceId::new(404);
    let account_keypair = checked_nexus_dataspaces_summary_ed25519_key_fixture();
    let account_id = AccountId::new(account_keypair.public_key().clone());
    let account_literal = account_id.to_string();
    let i105_literal = account_id
        .to_account_address()
        .and_then(|address| address.to_i105())
        .expect("i105 account literal");
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::torii::uncataloged_alias"));
    let domain_id: DomainId = DomainId::try_new("uncataloged", "universal").expect("domain id");
    let definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "lotus".parse().expect("asset definition name"),
    );
    let world = World::default();
    let mut state = State::new_for_testing(world, Arc::clone(&kura), query);
    let mut block = state.block(block_header(1));
    let mut stx = block.transaction();
    Register::domain(Domain::new(domain_id.clone()))
        .execute(&ALICE_ID, &mut stx)
        .expect("register domain");
    Register::account(NewAccount::new(account_id.clone()).with_uaid(Some(uaid)))
        .execute(&ALICE_ID, &mut stx)
        .expect("register account with uaid");
    Register::asset_definition(NewAssetDefinition {
        id: definition_id.clone(),
        name: "lotus".to_owned(),
        description: None,
        alias: None,
        spec: Default::default(),
        mintable: Default::default(),
        logo: None,
        metadata: Default::default(),
        balance_scope_policy: AssetBalancePolicy::Global,
        owning_domain: Some(domain_id.clone()),
    })
    .execute(&ALICE_ID, &mut stx)
    .expect("register asset definition");
    Mint::asset_quantity(9u64, AssetId::new(definition_id, account_id.clone()))
        .execute(&ALICE_ID, &mut stx)
        .expect("mint asset");
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit seeded state");
    let mut bindings = UaidDataspaceBindings::default();
    bindings.bind_account(dataspace, account_id.clone());
    state
        .world
        .uaid_dataspaces_mut_for_testing()
        .insert(uaid, bindings);
    let manifest = AssetPermissionManifest {
        version: ManifestVersion::V1,
        uaid,
        dataspace,
        issued_ms: 1_710_000_222_000,
        activation_epoch: 70,
        expiry_epoch: Some(170),
        entries: Vec::new(),
    };
    let mut record = SpaceDirectoryManifestRecord::new(manifest);
    record.lifecycle.mark_activated(71);
    let mut set = SpaceDirectoryManifestSet::default();
    set.upsert(record);
    state
        .world
        .space_directory_manifests_mut_for_testing()
        .insert(uaid, set);
    // Reconstruct an initial World containing a dataspace absent from the active
    // catalog. Configured genesis must prune both its manifest and derived binding;
    // the account's global asset remains owned by the same canonical account.
    {
        let world = state.world_view();
        assert!(
            world
                .uaid_dataspaces()
                .get(&uaid)
                .expect("seeded bindings")
                .is_bound_to(dataspace, &account_id)
        );
        assert!(
            world
                .space_directory_manifests()
                .get(&uaid)
                .and_then(|set| set.get(&dataspace))
                .expect("seeded uncataloged manifest")
                .is_active()
        );
    }
    let before = iroha_core::nexus::portfolio::collect_portfolio(&state.view(), uaid);
    assert_eq!(before.dataspaces.len(), 1);
    assert_eq!(before.dataspaces[0].dataspace_id, dataspace);
    assert_eq!(before.dataspaces[0].dataspace_alias, None);
    assert_eq!(before.dataspaces[0].accounts.len(), 1);
    let before_account = &before.dataspaces[0].accounts[0];
    assert_eq!(before_account.account_id, account_id);
    assert_eq!(before_account.assets.len(), 1);
    assert_eq!(before_account.assets[0].quantity, Quantity::from(9u32));
    let (router, state) = build_test_router_with_state(Arc::new(state));
    {
        let world = state.world_view();
        assert!(world.uaid_dataspaces().get(&uaid).is_none());
        assert!(world.space_directory_manifests().get(&uaid).is_none());
    }
    let after = iroha_core::nexus::portfolio::collect_portfolio(&state.view(), uaid);
    assert_eq!(after.totals, before.totals);
    assert_eq!(after.dataspaces.len(), 1);
    assert_eq!(after.dataspaces[0].dataspace_id, DataSpaceId::UNIVERSAL);
    assert_eq!(after.dataspaces[0].accounts, before.dataspaces[0].accounts);
    let literal = urlencoding::encode(&account_literal);
    let uri = format!("/v1/nexus/dataspaces/accounts/{literal}/summary");
    let (status, body) = request_summary(&router, &uri).await;
    assert_eq!(status, StatusCode::OK, "unexpected body: {body}");
    let payload: Value = json::from_str(&body).expect("json payload");
    assert_current_summary_shape(&payload);
    assert_eq!(payload["account_id"], Value::from(account_literal.as_str()));
    assert_eq!(payload["account"], Value::from(i105_literal.as_str()));
    assert_eq!(payload["uaid"], Value::from(uaid.to_string()));
    assert_eq!(payload["totals"]["dataspaces"], Value::from(1));
    assert_eq!(payload["totals"]["accounts_bound"], Value::from(1));
    assert_eq!(payload["totals"]["portfolio_accounts"], Value::from(1));
    assert_eq!(payload["totals"]["portfolio_positions"], Value::from(1));
    assert_eq!(payload["totals"]["manifests_total"], Value::from(0));
    assert_eq!(payload["totals"]["manifests_active"], Value::from(0));
    let dataspaces = payload["dataspaces"].as_array().expect("dataspaces array");
    assert_eq!(dataspaces.len(), 1);
    let row = &dataspaces[0];
    assert_eq!(
        row["dataspace_id"],
        Value::from(DataSpaceId::UNIVERSAL.as_u64())
    );
    assert_eq!(row["dataspace_alias"], Value::from("universal"));
    assert!(
        dataspaces
            .iter()
            .all(|row| row["dataspace_id"] != Value::from(dataspace.as_u64()))
    );
    assert_eq!(
        row["accounts"].as_array().expect("accounts"),
        &vec![Value::from(i105_literal.as_str())]
    );
    assert_eq!(row["portfolio"]["accounts"], Value::from(1));
    assert_eq!(row["portfolio"]["positions"], Value::from(1));
    assert_eq!(row["portfolio"]["asset_definitions"], Value::from(1));
    assert_eq!(row["manifest"]["present"], Value::Bool(false));
    assert_eq!(row["manifest"]["status"], Value::from("Missing"));
    assert_eq!(row["manifest"]["active"], Value::Bool(false));
    router.shutdown().await;
}
#[tokio::test(flavor = "current_thread")]
async fn nexus_dataspaces_summary_endpoint_rebuilds_bindings_from_the_unique_uaid_owner() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let query = LiveQueryStore::start_test();
    let dataspace = DataSpaceId::new(52);
    let primary_keypair = checked_nexus_dataspaces_summary_ed25519_key_fixture();
    let primary_account_id = AccountId::new(primary_keypair.public_key().clone());
    let primary_literal = primary_account_id.to_string();
    let primary_i105_literal = primary_account_id
        .to_account_address()
        .and_then(|address| address.to_i105())
        .expect("primary i105 account literal");
    let secondary_keypair = checked_nexus_dataspaces_summary_ed25519_key_fixture();
    let secondary_account_id = AccountId::new(secondary_keypair.public_key().clone());
    let secondary_i105_literal = secondary_account_id
        .to_account_address()
        .and_then(|address| address.to_i105())
        .expect("secondary i105 account literal");
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::torii::bound_account_portfolio"));
    let domain_id: DomainId = DomainId::try_new("multi-bindings", "universal").expect("domain id");
    let definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "cedar".parse().expect("asset definition name"),
    );
    let mut world = World::default();
    let manifest = AssetPermissionManifest {
        version: ManifestVersion::V1,
        uaid,
        dataspace,
        issued_ms: 1_710_000_111_000,
        activation_epoch: 50,
        expiry_epoch: Some(150),
        entries: Vec::new(),
    };
    let mut record = SpaceDirectoryManifestRecord::new(manifest);
    record.lifecycle.mark_activated(51);
    let mut set = SpaceDirectoryManifestSet::default();
    set.upsert(record);
    world
        .space_directory_manifests_mut_for_testing()
        .insert(uaid, set);
    let mut nexus = cfg.nexus.clone();
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: dataspace,
            alias: "retail".to_owned(),
            description: Some("Retail routed dataspace".to_owned()),
            fault_tolerance: 1,
        },
    ])
    .expect("dataspace catalog");
    let (mut state, _kura) = State::new_with_chain_and_network_id_and_pre_genesis_nexus_for_testing(
        world,
        nexus,
        query,
        cfg.common.chain.clone(),
        iroha_data_model::NetworkId::from_genesis_hash(cfg.genesis.expected_hash),
    );
    let mut block = state.block(block_header(1));
    let mut stx = block.transaction();
    Register::domain(Domain::new(domain_id.clone()))
        .execute(&ALICE_ID, &mut stx)
        .expect("register domain");
    Register::account(NewAccount::new(primary_account_id.clone()).with_uaid(Some(uaid)))
        .execute(&ALICE_ID, &mut stx)
        .expect("register primary account with uaid");
    let duplicate =
        Register::account(NewAccount::new(secondary_account_id.clone()).with_uaid(Some(uaid)))
            .execute(&ALICE_ID, &mut stx)
            .expect_err("a UAID has exactly one canonical account owner");
    assert_eq!(
        duplicate,
        iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(
            format!("UAID {uaid} already bound to account {primary_account_id}").into()
        )
    );
    Register::account(NewAccount::new(secondary_account_id.clone()))
        .execute(&ALICE_ID, &mut stx)
        .expect("register secondary account");
    Register::asset_definition(NewAssetDefinition {
        id: definition_id.clone(),
        name: "cedar".to_owned(),
        description: None,
        alias: None,
        spec: Default::default(),
        mintable: Default::default(),
        logo: None,
        metadata: Default::default(),
        balance_scope_policy: AssetBalancePolicy::Global,
        owning_domain: Some(domain_id.clone()),
    })
    .execute(&ALICE_ID, &mut stx)
    .expect("register asset definition");
    Mint::asset_quantity(
        13u64,
        AssetId::new(definition_id, primary_account_id.clone()),
    )
    .execute(&ALICE_ID, &mut stx)
    .expect("mint asset");
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit seeded state");
    let mut bindings = state
        .view()
        .world()
        .uaid_dataspaces()
        .get(&uaid)
        .cloned()
        .expect("bindings should exist after active manifest registration");
    assert!(bindings.is_bound_to(dataspace, &primary_account_id));
    assert!(!bindings.is_bound_to(dataspace, &secondary_account_id));
    // A stale derived cache must not turn a different account into a UAID owner.
    assert!(bindings.bind_account(dataspace, secondary_account_id.clone()));
    state
        .world
        .uaid_dataspaces_mut_for_testing()
        .insert(uaid, bindings);
    let (router, state) = build_test_router_with_state(Arc::new(state));
    {
        let world = state.world_view();
        assert_eq!(world.uaid_accounts().get(&uaid), Some(&primary_account_id));
        assert_eq!(
            world.account(&secondary_account_id).unwrap().value().uaid(),
            None
        );
        let bindings = world
            .uaid_dataspaces()
            .get(&uaid)
            .expect("rebuilt bindings");
        assert!(bindings.is_bound_to(dataspace, &primary_account_id));
        assert!(!bindings.is_bound_to(dataspace, &secondary_account_id));
    }
    let literal = urlencoding::encode(&primary_literal);
    let uri = format!("/v1/nexus/dataspaces/accounts/{literal}/summary");
    let (status, body) = request_summary(&router, &uri).await;
    assert_eq!(status, StatusCode::OK, "unexpected body: {body}");
    let payload: Value = json::from_str(&body).expect("json payload");
    assert_current_summary_shape(&payload);
    assert_eq!(payload["account_id"], Value::from(primary_literal.as_str()));
    assert_eq!(
        payload["account"],
        Value::from(primary_i105_literal.as_str())
    );
    assert_eq!(payload["uaid"], Value::from(uaid.to_string()));
    assert_eq!(payload["totals"]["dataspaces"], Value::from(1));
    assert_eq!(payload["totals"]["accounts_bound"], Value::from(1));
    assert_eq!(payload["totals"]["portfolio_accounts"], Value::from(1));
    assert_eq!(payload["totals"]["portfolio_positions"], Value::from(1));
    assert_eq!(payload["totals"]["manifests_total"], Value::from(1));
    assert_eq!(payload["totals"]["manifests_active"], Value::from(1));
    let dataspaces = payload["dataspaces"].as_array().expect("dataspaces array");
    assert_eq!(dataspaces.len(), 1);
    let row = &dataspaces[0];
    assert_eq!(row["dataspace_id"], Value::from(dataspace.as_u64()));
    assert_eq!(row["dataspace_alias"], Value::from("retail"));
    let accounts: HashSet<_> = row["accounts"]
        .as_array()
        .expect("accounts")
        .iter()
        .map(|value| value.as_str().expect("account string").to_owned())
        .collect();
    assert_eq!(accounts, HashSet::from([primary_i105_literal.clone()]));
    assert!(!accounts.contains(&secondary_i105_literal));
    assert_eq!(row["portfolio"]["accounts"], Value::from(1));
    assert_eq!(row["portfolio"]["positions"], Value::from(1));
    assert_eq!(row["portfolio"]["asset_definitions"], Value::from(1));
    assert_eq!(row["manifest"]["status"], Value::from("Active"));
    router.shutdown().await;
}
#[tokio::test(flavor = "current_thread")]
async fn nexus_dataspaces_summary_endpoint_rejects_invalid_account_literal() {
    let state = minimal_state();
    let router = build_test_router(state);
    let (status, body) = request_summary(
        &router,
        "/v1/nexus/dataspaces/accounts/not-a-valid-literal/summary",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body.contains("invalid account literal"),
        "expected invalid account literal message, got: {body}"
    );
    router.shutdown().await;
}
#[tokio::test(flavor = "current_thread")]
async fn nexus_dataspaces_summary_endpoint_rejects_empty_account_literal() {
    let state = minimal_state();
    let router = build_test_router(state);
    let (status, body) =
        request_summary(&router, "/v1/nexus/dataspaces/accounts/%20%20/summary").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body.contains("account literal must not be empty"),
        "expected empty account literal error, got: {body}"
    );
    router.shutdown().await;
}
#[tokio::test(flavor = "current_thread")]
async fn nexus_dataspaces_summary_endpoint_returns_not_found_for_missing_account() {
    let state = minimal_state();
    let router = build_test_router(state);
    let account_literal = valid_missing_account_literal();
    let literal = urlencoding::encode(&account_literal);
    let uri = format!("/v1/nexus/dataspaces/accounts/{literal}/summary");
    let (status, _body) = request_summary(&router, &uri).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    router.shutdown().await;
}
fn minimal_state() -> Arc<State> {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let world = World::default();
    let state = State::new_for_testing(world, Arc::clone(&kura), query);
    Arc::new(state)
}
async fn request_summary(router: &axum::Router, uri: &str) -> (StatusCode, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body = String::from_utf8_lossy(&bytes).to_string();
    (status, body)
}
fn assert_current_summary_shape(payload: &Value) {
    let totals = payload["totals"].as_object().expect("summary totals");
    assert_eq!(
        totals.keys().map(String::as_str).collect::<HashSet<_>>(),
        HashSet::from([
            "dataspaces",
            "accounts_bound",
            "portfolio_accounts",
            "portfolio_positions",
            "manifests_total",
            "manifests_active",
        ]),
    );
    for row in payload["dataspaces"].as_array().expect("dataspace rows") {
        assert_eq!(
            row.as_object()
                .expect("dataspace row")
                .keys()
                .map(String::as_str)
                .collect::<HashSet<_>>(),
            HashSet::from([
                "dataspace_id",
                "dataspace_alias",
                "accounts",
                "portfolio",
                "manifest"
            ]),
        );
    }
}
fn valid_missing_account_literal() -> String {
    let key_pair = checked_nexus_dataspaces_summary_ed25519_key_fixture();
    AccountId::new(key_pair.public_key().clone()).to_string()
}
fn build_test_router(state: Arc<State>) -> iroha_torii::TestApiRouterRuntime {
    build_test_router_with_state(state).0
}
fn build_test_router_with_state(
    state: Arc<State>,
) -> (iroha_torii::TestApiRouterRuntime, Arc<State>) {
    // The fixture assembly above only populates a pre-genesis World. Authenticate that exact
    // initial World through original signed genesis before exercising native fanout reads.
    assert_eq!(state.committed_height(), 0);
    let mut nexus = state.nexus_snapshot();
    // The catalog routes are physical storage/authority labels, separate from native lanes.
    let lanes = nexus
        .dataspace_catalog
        .entries()
        .iter()
        .enumerate()
        .map(|(index, dataspace)| iroha_data_model::nexus::LaneConfig {
            id: iroha_model_base::topology::LaneId::new(u32::try_from(index).unwrap()),
            alias: format!("summary-ds-{}", dataspace.id.as_u64()),
            dataspace_id: dataspace.id,
            ..Default::default()
        })
        .collect::<Vec<_>>();
    nexus.lane_catalog = iroha_data_model::nexus::LaneCatalog::new(
        std::num::NonZeroU32::new(u32::try_from(lanes.len()).unwrap()).unwrap(),
        lanes,
    )
    .expect("one physical summary route per configured dataspace");
    nexus.configured_lane_catalog = nexus.lane_catalog.clone();
    let seed_state = Arc::try_unwrap(state)
        .unwrap_or_else(|_| panic!("pre-genesis summary fixture must have a single owner"));
    let mut config =
        iroha_core::sumeragi::test_chain::TestChainConfig::new(seed_state.world, 1_000);
    config.genesis_key = iroha_test_samples::ALICE_KEYPAIR.clone();
    config.nexus = Some(nexus);
    let prepared = iroha_core::sumeragi::test_chain::CertifiedTestChain::prepare(config)
        .expect("summary fixture original signed genesis");
    let local_key = prepared.validator_keys[0].clone();
    let chain = iroha_core::sumeragi::test_chain::CertifiedTestChain::from_prepared(prepared)
        .expect("execute summary fixture original signed genesis");
    let state = chain.state().clone();
    let kura = chain.kura();
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.common.key_pair = local_key;
    let local_peer_id = PeerId::new(cfg.common.key_pair.public_key().clone());
    assert!(
        chain
            .validators()
            .iter()
            .any(|(peer, _)| peer == &local_peer_id)
    );
    for lane in state.nexus_snapshot().lane_catalog.lanes() {
        let authority = state
            .resolve_route_authority(iroha_core::state::LaneAuthorityRoute::new(
                lane.id,
                lane.dataspace_id,
            ))
            .expect("original signed committee resolves every configured summary route");
        assert!(authority.validators().contains(&local_peer_id));
    }
    let queue_cfg = Queue::default();
    let (events_tx, _events_rx) = broadcast::channel(1);
    let queue = Arc::new(iroha_core::queue::Queue::from_config(queue_cfg, events_tx));
    let torii = fixtures::ToriiHarness::new(
        &cfg,
        kura,
        &state,
        &queue,
        &local_peer_id,
        broadcast::channel(1).0,
        iroha_config::parameters::actual::TelemetryProfile::Operator,
    );
    (torii.router(), state)
}
fn block_header(height: u64) -> BlockHeader {
    BlockHeader::new(
        NonZeroU64::new(height).expect("height must be non-zero"),
        None,
        None,
        height,
        0,
    )
}
