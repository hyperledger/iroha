//! Account reads bind physical routing to authenticated root scope, never account labels.

use super::*;
use http_body_util::BodyExt;
use iroha_core::state::World;
use iroha_data_model::{
    Account, Registrable,
    block::consensus::SumeragiRootScope,
    nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig, LaneVisibility},
    parameter::{Parameter, custom::CustomParameter, system::consensus_metadata},
};

use crate::test_utils::bind_fixture_root;

fn private_app() -> (SharedAppState, AccountId, AccountId, DataSpaceId) {
    let owner = AccountId::new(iroha_crypto::KeyPair::random().public_key().clone());
    let stranger = AccountId::new(iroha_crypto::KeyPair::random().public_key().clone());
    let dataspace = DataSpaceId::new(u64::MAX);
    let mut world = World::with(
        [],
        [
            Account::new(owner.clone()).build(&owner),
            Account::new(stranger.clone()).build(&owner),
        ],
        [],
    );
    bind_fixture_root(
        &mut world,
        SumeragiRootScope::Dataspace {
            parent_network_id: NetworkId::from_genesis_hash(
                HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xB4; 32])),
            ),
            dataspace_id: dataspace,
        },
    );
    let lane_catalog = LaneCatalog::new(
        NonZeroU32::new(1).unwrap(),
        vec![LaneConfig {
            id: LaneId::SINGLE,
            dataspace_id: dataspace,
            alias: "private".into(),
            visibility: LaneVisibility::Restricted,
            ..LaneConfig::default()
        }],
    )
    .unwrap();
    let dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
        id: dataspace,
        alias: "private".into(),
        description: None,
        fault_tolerance: 1,
    }])
    .unwrap();
    let mut nexus = iroha_config::parameters::actual::Nexus {
        lane_config: iroha_config::parameters::actual::LaneConfig::from_catalog(&lane_catalog),
        configured_lane_catalog: lane_catalog.clone(),
        configured_dataspace_catalog: dataspace_catalog.clone(),
        lane_catalog,
        dataspace_catalog,
        ..Default::default()
    };
    nexus.routing_policy.default_dataspace = dataspace;
    let app =
        crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(world, nexus);
    (app, owner, stranger, dataspace)
}

#[tokio::test]
async fn private_unlabeled_account_routes_to_exact_signed_root_without_universal_lane() {
    let (app, owner, _, dataspace) = private_app();
    assert!(
        app.state
            .view()
            .world()
            .account_scope_entry(&owner)
            .unwrap()
            .iter()
            .any(|(id, _)| *id == DataSpaceId::UNIVERSAL),
        "fixture must retain the domainless account's logical scope that exposed the bug"
    );
    let expected = vec![RoutingDecision::new(LaneId::SINGLE, dataspace)];
    assert_eq!(
        resolve_torii_target_account_routes(&app, &owner).unwrap(),
        expected
    );
    assert_eq!(
        torii_account_read_routes(&app, &owner, Some(&owner), true).unwrap(),
        expected
    );
    assert_eq!(
        torii_account_permissions_read_routes(&app, &owner, Some(&owner), true).unwrap(),
        expected
    );
    assert_eq!(
        torii_account_assets_read_routes(&app, &owner, Some(&owner)).unwrap(),
        expected
    );
    assert!(resolve_torii_route_for_dataspace_id(&app, DataSpaceId::UNIVERSAL).is_err());
}

#[tokio::test]
async fn private_physical_account_route_does_not_grant_a_stranger_or_anonymous_read() {
    let (app, owner, stranger, _) = private_app();
    for caller in [None, Some(&stranger)] {
        assert!(!torii_should_use_target_account_routes(
            &app, &owner, caller
        ));
        assert!(
            torii_account_read_routes(&app, &owner, caller, false)
                .unwrap()
                .is_empty()
        );
        assert!(
            torii_account_permissions_read_routes(&app, &owner, caller, false)
                .unwrap()
                .is_empty()
        );
    }
    assert!(torii_account_assets_read_routes(&app, &owner, Some(&stranger)).is_err());
}

#[tokio::test]
async fn account_routes_require_valid_root_metadata_and_preserve_explicit_global_scope() {
    let owner = AccountId::new(iroha_crypto::KeyPair::random().public_key().clone());
    let app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(World::with(
        [],
        [Account::new(owner.clone()).build(&owner)],
        [],
    ));
    assert_eq!(
        resolve_torii_target_account_routes(&app, &owner).unwrap(),
        vec![RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)]
    );
    for malformed in [false, true] {
        let mut block = app.state.world.block();
        block
            .parameters
            .remove_custom_parameter(&consensus_metadata::handshake_meta_id());
        if malformed {
            block
                .parameters
                .set_parameter(Parameter::Custom(CustomParameter::new(
                    consensus_metadata::handshake_meta_id(),
                    iroha_primitives::json::Json::new(false),
                )))
                .expect("unparsed root metadata fixture");
        }
        block.commit();
        assert_eq!(
            resolve_torii_target_account_routes(&app, &owner),
            Err(queue::RoutingResolveError::UnauthenticatedRootScope)
        );
    }
}

fn set_read_permission(
    app: &SharedAppState,
    account: &AccountId,
    dataspace: DataSpaceId,
    grant: bool,
) {
    let permission: Permission = CanReadRestrictedDataspace { dataspace }.into();
    let mut block = app.state.block(BlockHeader::new(
        NonZeroU64::new(1).unwrap(),
        None,
        None,
        0,
        0,
    ));
    let mut tx = block.transaction();
    if grant {
        tx.world_mut_for_testing()
            .add_account_permission(account, permission);
    } else {
        assert!(
            tx.world_mut_for_testing()
                .remove_account_permission(account, &permission)
        );
    }
    tx.apply();
    block.commit_world_overlay_for_testing().unwrap();
}

async fn account_response(
    app: &SharedAppState,
    target: &AccountId,
    caller: Option<&AccountId>,
    dataspace: DataSpaceId,
    endpoint: ToriiReadEndpointV1,
) -> Response {
    let route = RoutingDecision::new(LaneId::SINGLE, dataspace);
    let scope = torii_account_read_route_scope(
        target,
        caller,
        torii_should_use_target_account_routes(app, target, caller),
    );
    execute_torii_read_request_locally(
        app,
        torii_read_request(
            endpoint,
            scope,
            route,
            vec![target.to_string()],
            None,
            Vec::new(),
        ),
        route,
        "local",
    )
    .await
}

#[tokio::test]
async fn private_account_and_permissions_read_require_current_physical_root_grant() {
    let (app, owner, stranger, dataspace) = private_app();
    set_read_permission(&app, &owner, dataspace, true);
    let response = account_response(
        &app,
        &owner,
        Some(&owner),
        dataspace,
        ToriiReadEndpointV1::AccountGet,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let account: AccountReadResponse = norito::json::from_slice(&body).unwrap();
    assert_eq!(account.account_id, owner);
    let response = account_response(
        &app,
        &owner,
        Some(&owner),
        dataspace,
        ToriiReadEndpointV1::AccountPermissionsGet,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let permissions: norito::json::Value = norito::json::from_slice(&body).unwrap();
    assert_eq!(permissions["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        permissions["items"][0]["name"].as_str(),
        Some("CanReadRestrictedDataspace")
    );
    assert_eq!(permissions["has_more"].as_bool(), Some(false));

    for caller in [None, Some(&stranger)] {
        let response = account_response(
            &app,
            &owner,
            caller,
            dataspace,
            ToriiReadEndpointV1::AccountGet,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = account_response(
            &app,
            &owner,
            caller,
            dataspace,
            ToriiReadEndpointV1::AccountPermissionsGet,
        )
        .await;
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let permissions: norito::json::Value = norito::json::from_slice(&body).unwrap();
        assert!(permissions["items"].as_array().unwrap().is_empty());
    }
    // A grant for a different dataspace and the caller's own account identity
    // cannot replace current access to this independently signed private root.
    set_read_permission(&app, &owner, dataspace, false);
    set_read_permission(&app, &owner, DataSpaceId::UNIVERSAL, true);
    assert!(torii_visible_account_read_routes(&app, Some(&owner)).is_empty());
    let response = account_response(
        &app,
        &owner,
        Some(&owner),
        dataspace,
        ToriiReadEndpointV1::AccountGet,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        !torii_dataspace_read_visibility(&app, Some(&owner))
            .allows_account(&app.state.world_view(), &owner)
    );
}

#[tokio::test]
async fn private_account_route_never_falls_back_to_global_physical_materialization() {
    let owner = AccountId::new(iroha_crypto::KeyPair::random().public_key().clone());
    let mut world = World::with([], [Account::new(owner.clone()).build(&owner)], []);
    let dataspace = DataSpaceId::new(u64::MAX);
    bind_fixture_root(
        &mut world,
        SumeragiRootScope::Dataspace {
            parent_network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                Hash::new(b"private-parent"),
            )),
            dataspace_id: dataspace,
        },
    );
    // A Global physical catalog is not authority to host this signed private root.
    let app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(world);
    set_read_permission(&app, &owner, dataspace, true);
    assert_eq!(
        resolve_torii_target_account_routes(&app, &owner),
        Err(queue::RoutingResolveError::NoLaneForDataspace {
            dataspace_id: dataspace
        })
    );
    assert!(torii_visible_account_read_routes(&app, Some(&owner)).is_empty());
}
