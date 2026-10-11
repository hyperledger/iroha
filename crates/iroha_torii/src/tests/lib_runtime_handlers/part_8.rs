#[cfg(all(feature = "app_api", feature = "connect"))]
#[tokio::test]
async fn incoming_read_proxy_rejects_inactive_autoscale_range_lane_hint() {
    let mut app = mk_app_state_for_tests();
    let (inactive_lane, inactive_dataspace) =
        torii_routed_read_tests::configure_corrupt_inactive_autoscale_range_route_for_test(
            &mut app,
        );
    let route = RoutingDecision::new(inactive_lane, inactive_dataspace);
    let response = incoming_read_proxy_response_for_route(app, route).await;
    assert_incoming_proxy_stale_route_rejection(&response, route);
}
#[cfg(all(feature = "app_api", feature = "connect"))]
#[tokio::test]
async fn incoming_read_proxy_rejects_future_created_autoscale_lane_hint() {
    let mut app = mk_app_state_for_tests();
    let (future_lane, future_dataspace) =
        crate::test_utils::configure_future_created_autoscale_route_for_test(&mut app);
    let route = RoutingDecision::new(future_lane, future_dataspace);
    let response = incoming_read_proxy_response_for_route(app, route).await;
    assert_incoming_proxy_stale_route_rejection(&response, route);
}
#[cfg(all(feature = "app_api", feature = "connect"))]
#[tokio::test]
async fn incoming_verified_query_proxy_rejects_retired_lane_hint() {
    let app = mk_app_state_for_tests();
    let route = RoutingDecision::new(LaneId::new(43), DataSpaceId::UNIVERSAL);
    let response = incoming_verified_query_proxy_response_for_route(app, route).await;
    assert_incoming_proxy_stale_route_rejection(&response, route);
}
#[cfg(all(feature = "app_api", feature = "connect"))]
#[tokio::test]
async fn incoming_verified_query_proxy_rejects_lane_dataspace_mismatch_hint() {
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        iroha_core::state::World::default(),
        crate::tests_runtime_handlers::multiple_dataspace_nexus_for_test(),
    );
    configure_multiple_dataspace_routes_for_test(&mut app);
    let route = RoutingDecision::new(LaneId::new(1), DataSpaceId::UNIVERSAL);
    let response = incoming_verified_query_proxy_response_for_route(app, route).await;
    assert_incoming_proxy_stale_route_rejection(&response, route);
}
#[cfg(all(feature = "app_api", feature = "connect"))]
#[tokio::test]
async fn incoming_verified_query_proxy_rejects_inactive_autoscale_range_lane_hint() {
    let mut app = mk_app_state_for_tests();
    let (inactive_lane, inactive_dataspace) =
        torii_routed_read_tests::configure_corrupt_inactive_autoscale_range_route_for_test(
            &mut app,
        );
    let route = RoutingDecision::new(inactive_lane, inactive_dataspace);
    let response = incoming_verified_query_proxy_response_for_route(app, route).await;
    assert_incoming_proxy_stale_route_rejection(&response, route);
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn incoming_verified_query_proxy_rejects_future_created_autoscale_lane_hint() {
    let mut app = mk_app_state_for_tests();
    let (future_lane, future_dataspace) =
        crate::test_utils::configure_future_created_autoscale_route_for_test(&mut app);
    let route = RoutingDecision::new(future_lane, future_dataspace);
    let response = incoming_verified_query_proxy_response_for_route(app, route).await;
    assert_incoming_proxy_stale_route_rejection(&response, route);
}

#[cfg(feature = "connect")]
#[tokio::test]
async fn incoming_signed_iterable_route_scan_refuses_before_stale_route_validation() {
    let mut app = mk_app_state_for_tests();
    let (future_lane, future_dataspace) =
        crate::test_utils::configure_future_created_autoscale_route_for_test(&mut app);
    let route = RoutingDecision::new(future_lane, future_dataspace);
    let response = incoming_signed_query_proxy_response_for_route(app, route, |_| {
        iroha_data_model::query::QueryRequest::Start(build_find_triggers_query_for_test())
    })
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        torii_response_header(&response, "x-iroha-reject-code"),
        Some("query_unsupported")
    );
}

#[cfg(feature = "connect")]
#[tokio::test]
async fn incoming_signed_query_active_restricted_hint_retains_permission_refusal() {
    let original_authority =
        checked_torii_test_account_id(0x69, "original signed route-scan authority");
    let app = mk_app_state_for_tests_with_world_and_nexus(
        world_with_account(&original_authority),
        private_ingress_nexus_for_test(),
    );
    assert!(app.state.world_view().account(&original_authority).is_ok());
    let route = RoutingDecision::new(LaneId::new(2), DataSpaceId::new(10));
    assert_eq!(
        super::validate_incoming_read_proxy_route(&app, route, "signed_query_route_scan")
            .expect("original active restricted hint"),
        route,
    );
    let response = incoming_verified_query_proxy_response_for_route(app, route).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        torii_response_header(&response, "x-iroha-reject-code"),
        Some("permission_denied")
    );
    assert!(torii_response_header(&response, "x-iroha-route-unavailable-reason").is_none());
}

#[cfg(feature = "connect")]
enum AuthoritativeLaneFixtureMode {
    OnlineWithFallback,
    Offline,
    OfflineWithHttpBridge,
}

#[cfg(feature = "connect")]
struct AuthoritativeLaneFixture {
    app: SharedAppState,
    local_peer_id: PeerId,
    authoritative_peer_id: PeerId,
    fallback_peer_id: PeerId,
    route: RoutingDecision,
}

/// Execute the exact original four BLS authorities and separate manifest accounts at genesis.
#[cfg(feature = "connect")]
fn native_proxy_authority_app_for_test(
    bindings: &[(AccountId, KeyPair)],
    labels: &[String],
) -> SharedAppState {
    assert_eq!(
        bindings.len(),
        4,
        "the original fixture has exactly four voters"
    );
    let accounts = bindings
        .iter()
        .map(|(validator, _)| Account::new(validator.clone()).build(validator));
    let mut config = iroha_core::sumeragi::test_chain::TestChainConfig::new(
        World::with([], accounts, []),
        1_000,
    );
    config.validator_keys = Some(bindings.iter().map(|(_, key)| key.clone()).collect());
    assert_eq!(labels.len(), bindings.len());
    let genesis = AccountId::new(config.genesis_key.public_key().clone());
    config
        .genesis_instructions
        .push(Grant::account_permission(Permission::from(CanManageConsensusKeys), genesis).into());
    for ((validator, key), label) in bindings.iter().zip(labels) {
        config.genesis_instructions.push(
            Grant::account_permission(Permission::from(CanManageConsensusKeys), validator.clone())
                .into(),
        );
        for role in [ConsensusKeyRole::Validator, ConsensusKeyRole::Committee] {
            let id = ConsensusKeyId::new(role, label.as_str());
            config.genesis_instructions.push(
                RegisterConsensusKey {
                    id: id.clone(),
                    record: ConsensusKeyRecord {
                        id,
                        public_key: key.public_key().clone(),
                        pop: Some(
                            iroha_crypto::bls_normal_pop_prove(key.private_key())
                                .expect("original authority PoP"),
                        ),
                        activation_height: 1,
                        expiry_height: None,
                        replaces: None,
                        status: ConsensusKeyStatus::Active,
                    },
                }
                .into(),
            );
        }
    }
    let app = native_ingress_app_with_config_for_test(config);
    let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let committee = app
        .state
        .resolve_route_authority(super::lane_authority_route(route))
        .expect("the executed genesis authenticates the original global route");
    assert_eq!(committee.authority_height(), 1);
    let mut expected = bindings
        .iter()
        .map(|(_, key)| PeerId::new(key.public_key().clone()))
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(
        committee.into_validators(),
        expected,
        "original BLS authority identities"
    );
    let view = app.state.view();
    for (validator, _) in bindings {
        assert!(
            view.world().account(validator).is_ok(),
            "original canonical manifest account"
        );
        assert!(
            super::torii_account_has_permission(
                view.world(),
                validator,
                &Permission::from(CanManageConsensusKeys)
            ),
            "original key-management grant"
        );
    }
    drop(view);
    app
}

#[cfg(feature = "connect")]
fn authoritative_lane_fixture(mode: AuthoritativeLaneFixtureMode) -> AuthoritativeLaneFixture {
    let local_keypair =
        checked_torii_test_ed25519_keypair(0x58, "derive authoritative-lane local fixture key");
    let authoritative_validator_keypair = checked_torii_test_ed25519_keypair(
        0x5e,
        "derive authoritative-lane manifest validator fixture key",
    );
    let authoritative_keypair =
        checked_torii_test_bls_keypair(0x5f, "derive authoritative-lane manifest peer fixture key");
    let additional_authorities = (0_u8..3)
        .map(|index| {
            let validator_keypair = checked_torii_test_ed25519_keypair(
                0x80 + index,
                "derive additional authoritative-lane validator fixture key",
            );
            let peer_keypair = checked_torii_test_bls_keypair(
                0x83 + index,
                "derive additional authoritative-lane peer fixture key",
            );
            (
                AccountId::new(validator_keypair.public_key().clone()),
                peer_keypair,
            )
        })
        .collect::<Vec<_>>();
    let fallback_keypair = checked_torii_test_ed25519_keypair(
        0x60,
        "derive authoritative-lane fallback peer fixture key",
    );
    let local_peer_id = PeerId::from(local_keypair.public_key().clone());
    let authoritative_validator =
        AccountId::new(authoritative_validator_keypair.public_key().clone());
    let authoritative_peer_id = PeerId::from(authoritative_keypair.public_key().clone());
    let fallback_peer_id = PeerId::from(fallback_keypair.public_key().clone());
    let mut online = vec![Peer::new(
        "127.0.0.1:10001".parse().expect("valid local address"),
        local_keypair.public_key().clone(),
    )];
    if matches!(mode, AuthoritativeLaneFixtureMode::OnlineWithFallback) {
        online.extend([
            Peer::new(
                "127.0.0.1:10002"
                    .parse()
                    .expect("valid authoritative address"),
                authoritative_keypair.public_key().clone(),
            ),
            Peer::new(
                "127.0.0.1:10003".parse().expect("valid fallback address"),
                fallback_keypair.public_key().clone(),
            ),
        ]);
        online.extend(additional_authorities.iter().enumerate().map(
            |(index, (_, peer_keypair))| {
                Peer::new(
                    format!("127.0.0.1:{}", 10004 + index)
                        .parse()
                        .expect("valid additional authoritative address"),
                    peer_keypair.public_key().clone(),
                )
            },
        ));
    }
    let mut original_bindings = vec![(
        authoritative_validator.clone(),
        authoritative_keypair.clone(),
    )];
    original_bindings.extend(additional_authorities.iter().cloned());
    let labels = (0..original_bindings.len())
        .map(|index| {
            if index == 0 {
                "authoritative".to_owned()
            } else {
                format!("authoritative-{}", index + 1)
            }
        })
        .collect::<Vec<_>>();
    let mut app = native_proxy_authority_app_for_test(&original_bindings, &labels);
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let (online_tx, online_rx) = tokio::sync::watch::channel(std::collections::HashSet::new());
        online_tx
            .send(online.into_iter().collect())
            .expect("online peers update should succeed");
        app_mut.online_peers = OnlinePeersProvider::new(online_rx);
        app_mut.local_peer_id = Some(local_peer_id.clone());
    }
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let state = Arc::get_mut(&mut app_mut.state).expect("unique state");
        let mut manifest_bindings = vec![(authoritative_validator, authoritative_peer_id.clone())];
        manifest_bindings.extend(
            additional_authorities
                .iter()
                .map(|(validator, peer_keypair)| {
                    (
                        validator.clone(),
                        PeerId::from(peer_keypair.public_key().clone()),
                    )
                }),
        );
        if matches!(mode, AuthoritativeLaneFixtureMode::OfflineWithHttpBridge) {
            let manifest_bindings = manifest_bindings
                .into_iter()
                .enumerate()
                .map(|(index, (validator, peer_id))| {
                    (
                        validator,
                        peer_id,
                        (index == 0).then_some("http://127.0.0.1:19080"),
                    )
                })
                .collect();
            install_lane_manifest_registry_with_torii_urls_for_test(
                state,
                &[(LaneId::SINGLE, manifest_bindings)],
            );
        } else {
            install_lane_manifest_registry_for_test(state, &[(LaneId::SINGLE, manifest_bindings)]);
        }
    }
    // The original signed, executed genesis retains the physical Kura body and State result.
    let committed = app
        .state
        .view()
        .canonical_block_by_height(NonZeroUsize::new(1).expect("height one"))
        .expect("authority fixture has a canonical signed height-one Kura body");
    assert_eq!(committed.header().height().get(), 1);
    let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let committee = app
        .state
        .resolve_lane_committee(super::lane_authority_route(route))
        .expect("all four fixture bindings are active at the committed height");
    assert_eq!(committee.authority_height(), 1);
    assert_eq!(committee.into_validators().len(), 4);
    assert_eq!(
        app.state
            .manifest_lane_validator_bindings_at_height(LaneId::SINGLE, 1)
            .len(),
        4
    );
    AuthoritativeLaneFixture {
        app,
        local_peer_id,
        authoritative_peer_id,
        fallback_peer_id,
        route,
    }
}

#[cfg(feature = "connect")]
#[tokio::test]
async fn torii_proxy_candidate_peers_only_use_authoritative_peers() {
    let AuthoritativeLaneFixture {
        app,
        local_peer_id,
        fallback_peer_id,
        route,
        ..
    } = authoritative_lane_fixture(AuthoritativeLaneFixtureMode::OnlineWithFallback);
    let authoritative_without_local: Vec<_> = super::authoritative_lane_peers(app.as_ref(), route)
        .authoritative
        .into_iter()
        .filter(|peer_id| peer_id != &local_peer_id)
        .map(ToriiProxyCandidate::P2p)
        .collect();
    let candidates =
        super::torii_proxy_candidate_peer_ids(app.as_ref(), &local_peer_id, route, None, &[]);
    assert_eq!(
        candidates.authoritative_count,
        authoritative_without_local.len()
    );
    assert_eq!(candidates.peers, authoritative_without_local);
    assert_eq!(candidates.authoritative_total_count, 4);
    assert_eq!(candidates.offline_authoritative_count, 0);
    assert_eq!(candidates.bridge_authoritative_count, 0);
    assert!(candidates.unavailable_reason.is_none());
    assert!(
        !candidates
            .peers
            .iter()
            .any(|candidate| candidate.peer_id() == &fallback_peer_id)
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn torii_authority_resolution_rejects_lane_dataspace_mismatch() {
    let AuthoritativeLaneFixture {
        mut app,
        authoritative_peer_id,
        route,
        ..
    } = authoritative_lane_fixture(AuthoritativeLaneFixtureMode::OnlineWithFallback);
    let authority_height = app
        .state
        .resolve_lane_committee(iroha_core::state::LaneAuthorityRoute::new(
            route.lane_id,
            route.dataspace_id,
        ))
        .expect("fixture route authority should resolve")
        .authority_height();
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .local_peer_id = Some(authoritative_peer_id.clone());
    assert!(
        super::is_local_authoritative_for_route(app.as_ref(), route),
        "fixture authority must own the exact lane/dataspace route"
    );

    let mismatched_route = RoutingDecision::new(route.lane_id, DataSpaceId::new(1));
    assert_ne!(mismatched_route.dataspace_id, route.dataspace_id);
    assert!(
        super::authoritative_lane_peer_statuses(app.as_ref(), mismatched_route).is_empty(),
        "current-height status discovery must not leak lane authority across dataspaces"
    );
    assert!(
        super::authoritative_lane_peer_statuses_at_height(
            app.as_ref(),
            mismatched_route,
            authority_height,
        )
        .is_empty(),
        "height-bound status discovery must enforce the exact lane/dataspace route"
    );
    assert!(
        super::authoritative_lane_peers(app.as_ref(), mismatched_route)
            .authoritative
            .is_empty(),
        "proxy authority discovery must fail closed for a mismatched dataspace"
    );
    assert!(
        !super::is_local_authoritative_for_route(app.as_ref(), mismatched_route),
        "a validator for the lane's real dataspace must not own a mismatched route"
    );
    assert!(
        !super::should_execute_route_locally(app.as_ref(), mismatched_route),
        "mismatched routes must never execute locally"
    );
    let candidates = super::torii_proxy_candidate_peer_ids(
        app.as_ref(),
        &authoritative_peer_id,
        mismatched_route,
        None,
        &[],
    );
    assert_eq!(candidates.authoritative_count, 0);
    assert_eq!(candidates.authoritative_total_count, 0);
    assert!(candidates.peers.is_empty());
    assert_eq!(
        candidates.unavailable_reason,
        Some(ToriiProxyUnavailableReason::MissingAuthoritativeBinding)
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn torii_proxy_candidate_peers_reject_future_created_autoscale_manifest_authority() {
    let local_keypair = checked_torii_test_ed25519_keypair(
        0x61,
        "derive future-created candidate local fixture key",
    );
    let authoritative_validator_keypair = checked_torii_test_ed25519_keypair(
        0x62,
        "derive future-created candidate manifest validator fixture key",
    );
    let authoritative_keypair = checked_torii_test_bls_keypair(
        0x63,
        "derive future-created candidate manifest peer fixture key",
    );
    let local_peer_id = PeerId::from(local_keypair.public_key().clone());
    let authoritative_validator =
        AccountId::new(authoritative_validator_keypair.public_key().clone());
    let authoritative_peer_id = PeerId::from(authoritative_keypair.public_key().clone());
    let mut app = mk_app_state_for_tests();
    let (future_lane, future_dataspace) =
        crate::test_utils::configure_future_created_autoscale_route_for_test(&mut app);
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let (online_tx, online_rx) = tokio::sync::watch::channel(std::collections::HashSet::new());
        online_tx
            .send(std::collections::HashSet::from([
                Peer::new(
                    "127.0.0.1:10001".parse().expect("valid local address"),
                    local_keypair.public_key().clone(),
                ),
                Peer::new(
                    "127.0.0.1:10002"
                        .parse()
                        .expect("valid authoritative address"),
                    authoritative_keypair.public_key().clone(),
                ),
            ]))
            .expect("online peers update should succeed");
        app_mut.online_peers = OnlinePeersProvider::new(online_rx);
        app_mut.local_peer_id = Some(local_peer_id.clone());
        let state = Arc::get_mut(&mut app_mut.state).expect("unique state");
        ensure_runtime_peer_binding_for_test(
            state,
            &authoritative_validator,
            &authoritative_keypair,
            "authoritative",
        );
        {
            let mut topology = state.commit_topology.block();
            topology.clear();
            topology.push(local_peer_id.clone());
            topology.push(authoritative_peer_id.clone());
            topology.commit();
        }
        install_lane_manifest_registry_for_test(
            state,
            &[(
                future_lane,
                vec![(authoritative_validator, authoritative_peer_id.clone())],
            )],
        );
        assert!(
            !state.is_lane_active_for_authority(future_lane),
            "fixture lane should remain inactive after manifest binding setup"
        );
    }
    let route = RoutingDecision::new(future_lane, future_dataspace);
    assert!(
        super::authoritative_lane_peers(app.as_ref(), route)
            .authoritative
            .is_empty(),
        "future-created autoscale manifest bindings must not become proxy authority early"
    );
    let candidates =
        super::torii_proxy_candidate_peer_ids(app.as_ref(), &local_peer_id, route, None, &[]);
    assert_eq!(candidates.authoritative_count, 0);
    assert_eq!(candidates.authoritative_total_count, 0);
    assert_eq!(candidates.offline_authoritative_count, 0);
    assert_eq!(candidates.bridge_authoritative_count, 0);
    assert!(candidates.peers.is_empty());
    assert_eq!(
        candidates.unavailable_reason,
        Some(ToriiProxyUnavailableReason::MissingAuthoritativeBinding)
    );
}
#[cfg(feature = "connect")]
#[test]
fn authoritative_lane_peer_statuses_decorate_only_canonical_peer_ids() {
    let canonical_with_url = PeerId::new(
        checked_torii_test_bls_keypair(0x8a, "derive canonical URL-bound peer fixture key")
            .public_key()
            .clone(),
    );
    let canonical_without_url = PeerId::new(
        checked_torii_test_bls_keypair(0x8b, "derive canonical unbound peer fixture key")
            .public_key()
            .clone(),
    );
    let non_authoritative = PeerId::new(
        checked_torii_test_bls_keypair(0x8c, "derive non-authoritative URL peer fixture key")
            .public_key()
            .clone(),
    );
    let statuses = super::authoritative_lane_peer_statuses_with_manifest_urls(
        vec![canonical_with_url.clone(), canonical_without_url.clone()],
        std::collections::BTreeMap::from([
            (
                canonical_with_url.clone(),
                "http://127.0.0.1:19100".to_owned(),
            ),
            (
                non_authoritative.clone(),
                "http://127.0.0.1:19101".to_owned(),
            ),
        ]),
    );
    assert_eq!(
        statuses
            .iter()
            .map(|status| status.peer_id.clone())
            .collect::<Vec<_>>(),
        vec![canonical_with_url, canonical_without_url],
        "manifest bindings must neither add nor reorder canonical authority"
    );
    assert_eq!(
        statuses
            .iter()
            .map(|status| status.torii_url.as_deref())
            .collect::<Vec<_>>(),
        vec![Some("http://127.0.0.1:19100"), None],
        "only the canonical peer with a matching manifest binding receives its URL"
    );
    assert!(
        statuses
            .iter()
            .all(|status| status.peer_id != non_authoritative),
        "a manifest-only peer must not enter the authoritative set"
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn autoscale_proxy_authority_uses_pinned_committee_not_disjoint_manifest_bindings() {
    let wrong_manifest_validator_keypair = checked_torii_test_ed25519_keypair(
        0x70,
        "derive disjoint autoscale manifest validator fixture key",
    );
    let wrong_manifest_peer_keypair =
        checked_torii_test_bls_keypair(0x71, "derive disjoint autoscale manifest peer fixture key");
    let pinned_keypairs = (0x72_u8..=0x75)
        .map(|seed| {
            checked_torii_test_bls_keypair(seed, "derive pinned autoscale peer fixture key")
        })
        .collect::<Vec<_>>();
    let wrong_manifest_validator =
        AccountId::new(wrong_manifest_validator_keypair.public_key().clone());
    let wrong_manifest_peer_id = PeerId::new(wrong_manifest_peer_keypair.public_key().clone());
    let lane_id = LaneId::new(1);
    let route = RoutingDecision::new(lane_id, DataSpaceId::UNIVERSAL);
    let mut autoscale_lane = iroha_data_model::nexus::LaneConfig {
        id: lane_id,
        alias: "elastic-lane-1".to_owned(),
        ..iroha_data_model::nexus::LaneConfig::default()
    };
    autoscale_lane.metadata.insert(
        iroha_data_model::nexus::AUTOSCALE_META_MANAGED.to_owned(),
        "true".to_owned(),
    );
    autoscale_lane.metadata.insert(
        iroha_data_model::nexus::AUTOSCALE_META_CREATED_HEIGHT.to_owned(),
        "1".to_owned(),
    );
    let pinned_peer_ids =
        pin_autoscale_lane_committee_for_test(&mut autoscale_lane, &pinned_keypairs);
    let lane_catalog = iroha_data_model::nexus::LaneCatalog::new(
        NonZeroU32::new(2).expect("non-zero lane count"),
        vec![
            iroha_data_model::nexus::LaneConfig::default(),
            autoscale_lane,
        ],
    )
    .expect("pinned autoscale lane catalog");
    let mut nexus = iroha_config::parameters::actual::Nexus {
        lane_catalog,
        ..iroha_config::parameters::actual::Nexus::default()
    };
    nexus.autoscale.enabled = true;
    nexus.autoscale.min_lane_id = NonZeroU32::new(1).expect("non-zero min lanes");
    nexus.autoscale.max_lane_id_exclusive = NonZeroU32::new(2).expect("non-zero max lanes");
    nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    let mut members = pinned_keypairs
        .iter()
        .enumerate()
        .map(|(index, key)| {
            (
                checked_torii_test_account_id(
                    0x76 + u8::try_from(index).expect("four original pinned validators"),
                    "pinned autoscale validator account",
                ),
                key.clone(),
            )
        })
        .collect::<Vec<_>>();
    members.push((
        wrong_manifest_validator.clone(),
        wrong_manifest_peer_keypair.clone(),
    ));
    let labels = vec![
        "pinned-autoscale-0".to_owned(),
        "pinned-autoscale-1".to_owned(),
        "pinned-autoscale-2".to_owned(),
        "pinned-autoscale-3".to_owned(),
        "wrong-autoscale-manifest".to_owned(),
    ];
    // The pinned roster is the genuine signed global committee. The disjoint
    // manifest peer is introduced by paid H2 and becomes live at paid H3.
    let mut app = native_ingress_with_registered_route_peers_for_test(
        World::default(),
        iroha_config::parameters::actual::Nexus::default(),
        &members,
        &labels,
    );
    let global_route =
        super::lane_authority_route(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL));
    let original_global_authority = app
        .state
        .resolve_route_authority(global_route)
        .expect("genuine paid global authority before routing projection");
    // This isolated routing projection uses the canonical fixture owner, which
    // requires no committed runtime catalog. It supplies no native finality,
    // execution or storage authority; the executed global schedule stays intact.
    app.state
        .install_synthetic_routing_snapshot_for_testing(nexus);
    assert_eq!(
        app.state.resolve_route_authority(global_route).unwrap(),
        original_global_authority
    );
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        app_mut.local_peer_id = Some(wrong_manifest_peer_id.clone());
        let mut online = std::collections::HashSet::from([Peer::new(
            "127.0.0.1:10100"
                .parse()
                .expect("valid wrong-manifest peer address"),
            wrong_manifest_peer_keypair.public_key().clone(),
        )]);
        online.extend(pinned_keypairs.iter().enumerate().map(|(index, keypair)| {
            Peer::new(
                format!("127.0.0.1:{}", 10101 + index)
                    .parse()
                    .expect("valid pinned peer address"),
                keypair.public_key().clone(),
            )
        }));
        let (_online_tx, online_rx) = tokio::sync::watch::channel(online);
        app_mut.online_peers = OnlinePeersProvider::new(online_rx);
        install_lane_manifest_registry_with_torii_urls_for_test(
            &app_mut.state,
            &[(
                lane_id,
                vec![(
                    wrong_manifest_validator,
                    wrong_manifest_peer_id.clone(),
                    Some("http://127.0.0.1:19100"),
                )],
            )],
        );
    }
    assert_eq!(
        app.state.view().height(),
        3,
        "original paid authority height"
    );
    assert_eq!(
        app.state
            .resolve_lane_committee(iroha_core::state::LaneAuthorityRoute::new(
                lane_id,
                route.dataspace_id,
            ))
            .expect("pinned autoscale authority should resolve")
            .into_validators(),
        pinned_peer_ids,
        "state authority must expose the immutable autoscale incarnation committee"
    );
    assert_eq!(
        app.state
            .manifest_lane_validator_bindings(lane_id)
            .into_iter()
            .map(|binding| binding.peer_id)
            .collect::<Vec<_>>(),
        vec![wrong_manifest_peer_id.clone()],
        "fixture manifest authority must be live and disjoint from the pinned committee"
    );
    assert!(
        !pinned_peer_ids.contains(&wrong_manifest_peer_id),
        "fixture authorities must be disjoint"
    );
    let statuses = super::authoritative_lane_peer_statuses(app.as_ref(), route);
    assert_eq!(
        statuses
            .iter()
            .map(|status| status.peer_id.clone())
            .collect::<Vec<_>>(),
        pinned_peer_ids,
        "mutable manifest bindings must not replace pinned autoscale authority"
    );
    assert!(
        statuses.iter().all(|status| status.torii_url.is_none()),
        "a URL belonging to a non-authoritative manifest peer must not decorate a pinned peer"
    );
    // Height-bound routing reads the original retained schedule, whose three
    // slots start at the actual paid H3 cut. A retired genesis slot is not an
    // alternate authority source for this current State.
    let retained_height = original_global_authority.authority_height();
    assert_eq!(retained_height, 3, "the original paid authority cut");
    let historical_statuses =
        super::authoritative_lane_peer_statuses_at_height(app.as_ref(), route, retained_height);
    assert_eq!(
        historical_statuses
            .iter()
            .map(|status| status.peer_id.clone())
            .collect::<Vec<_>>(),
        pinned_peer_ids,
        "height-bound routing must preserve the immutable autoscale committee"
    );
    assert!(
        historical_statuses
            .iter()
            .all(|status| status.torii_url.is_none()),
        "height-bound routing must ignore URLs from non-authoritative manifest peers"
    );
    assert!(matches!(
        app.state
            .resolve_route_authority_at_height(super::lane_authority_route(route), 1,),
        Err(
            iroha_core::state::LaneAuthorityError::InvalidAuthoritySource {
                authority_height: 1,
                ..
            }
        ),
    ));
    assert!(
        super::authoritative_lane_peer_statuses_at_height(app.as_ref(), route, 1).is_empty(),
        "a retired slot must fail closed instead of substituting current or manifest authority",
    );
    let candidates = super::torii_proxy_candidate_peer_ids(
        app.as_ref(),
        &wrong_manifest_peer_id,
        route,
        None,
        &[],
    );
    assert_eq!(candidates.authoritative_total_count, pinned_peer_ids.len());
    assert_eq!(candidates.authoritative_count, pinned_peer_ids.len());
    assert!(
        candidates
            .peers
            .iter()
            .all(|candidate| pinned_peer_ids.contains(candidate.peer_id())),
        "proxy candidates must contain only pinned committee peers"
    );
    assert!(
        candidates
            .peers
            .iter()
            .all(|candidate| candidate.peer_id() != &wrong_manifest_peer_id),
        "the disjoint manifest peer must never receive proxy execution"
    );
    let signed_query = ToriiProxyRequestKindV1::SignedQuery {
        query_bytes: Vec::new(),
        expected_route: ToriiRouteHintV1::from(route),
        response_format: ToriiProxyResponseFormatV1::Norito,
    };
    assert!(
        !super::should_execute_incoming_torii_proxy_request_locally(
            app.as_ref(),
            &signed_query,
            route,
        ),
        "a local peer present only in the mutable manifest must not execute the routed query"
    );
    let pinned_local_peer = pinned_peer_ids[0].clone();
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .local_peer_id = Some(pinned_local_peer.clone());
    assert!(
        super::should_execute_incoming_torii_proxy_request_locally(
            app.as_ref(),
            &signed_query,
            route,
        ),
        "a pinned committee peer must execute its autoscale route"
    );
    assert!(
        super::is_local_authoritative_for_route(app.as_ref(), route),
        "the pinned local peer must remain the route authority"
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn torii_proxy_candidate_peers_fail_closed_when_manifest_authoritative_peers_are_offline() {
    let AuthoritativeLaneFixture {
        app,
        local_peer_id,
        route,
        ..
    } = authoritative_lane_fixture(AuthoritativeLaneFixtureMode::Offline);
    let candidates =
        super::torii_proxy_candidate_peer_ids(app.as_ref(), &local_peer_id, route, None, &[]);
    assert_eq!(candidates.authoritative_count, 0);
    assert_eq!(candidates.authoritative_total_count, 4);
    assert_eq!(candidates.offline_authoritative_count, 4);
    assert_eq!(candidates.bridge_authoritative_count, 0);
    assert!(candidates.peers.is_empty());
    assert_eq!(
        candidates.unavailable_reason,
        Some(ToriiProxyUnavailableReason::AuthoritativePeersOffline)
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn torii_proxy_candidate_peers_bridge_to_offline_manifest_authority_when_torii_url_is_present()
 {
    let AuthoritativeLaneFixture {
        app,
        local_peer_id,
        authoritative_peer_id,
        route,
        ..
    } = authoritative_lane_fixture(AuthoritativeLaneFixtureMode::OfflineWithHttpBridge);
    let candidates =
        super::torii_proxy_candidate_peer_ids(app.as_ref(), &local_peer_id, route, None, &[]);
    assert_eq!(candidates.authoritative_count, 1);
    assert_eq!(candidates.authoritative_total_count, 4);
    assert_eq!(candidates.offline_authoritative_count, 4);
    assert_eq!(candidates.bridge_authoritative_count, 1);
    assert_eq!(
        candidates.peers,
        vec![ToriiProxyCandidate::HttpBridge {
            peer_id: authoritative_peer_id.clone(),
            torii_url: "http://127.0.0.1:19080".to_owned(),
        }]
    );
    assert!(candidates.unavailable_reason.is_none());
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn execute_torii_proxy_request_with_fallback_returns_route_unavailable_when_manifest_authoritative_peers_are_offline()
 {
    let AuthoritativeLaneFixture { app, route, .. } =
        authoritative_lane_fixture(AuthoritativeLaneFixtureMode::Offline);
    let response = super::execute_torii_proxy_request_with_fallback(
        &app,
        route,
        ToriiProxyRequestKindV1::SignedQueryRouteScan {
            query_bytes: Vec::new(),
            expected_route: ToriiRouteHintV1::from(route),
            response_format: ToriiProxyResponseFormatV1::Norito,
        },
    )
    .await;
    assert_route_unavailable_response(&response);
    let body = torii_body_bytes(response, "collect error body").await;
    let envelope =
        norito::decode_from_bytes::<super::ErrorEnvelope>(&body).expect("decode error envelope");
    assert_eq!(envelope.code(), "route_unavailable");
    assert_eq!(
        envelope.message(),
        ToriiProxyUnavailableReason::AuthoritativePeersOffline.ingress_message(route)
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn torii_proxy_candidate_peers_fail_closed_when_bindings_are_missing() {
    let local_keypair =
        checked_torii_test_ed25519_keypair(0x58, "derive authoritative-lane local fixture key");
    let fallback_keypair = checked_torii_test_ed25519_keypair(
        0x60,
        "derive authoritative-lane fallback peer fixture key",
    );
    let local_peer_id = PeerId::from(local_keypair.public_key().clone());
    let fallback_peer_id = PeerId::from(fallback_keypair.public_key().clone());
    let mut app = mk_app_state_for_tests();
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let (online_tx, online_rx) = tokio::sync::watch::channel(std::collections::HashSet::new());
        let local_peer = Peer::new(
            "127.0.0.1:10001".parse().expect("valid local address"),
            local_keypair.public_key().clone(),
        );
        let fallback_peer = Peer::new(
            "127.0.0.1:10002".parse().expect("valid fallback address"),
            fallback_keypair.public_key().clone(),
        );
        online_tx
            .send(std::collections::HashSet::from([local_peer, fallback_peer]))
            .expect("online peers update should succeed");
        app_mut.online_peers = OnlinePeersProvider::new(online_rx);
        app_mut.local_peer_id = Some(local_peer_id.clone());
    }
    let header = BlockHeader::new(
        NonZeroU64::new(1).expect("non-zero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = app.state.block(header);
    block
        .world
        .parameters
        .get_mut()
        .set_parameter(Parameter::Custom(
            SumeragiNposParameters::default().into_custom_parameter(),
        ));
    let mut peers = block.world.peers_mut_for_testing().transaction();
    peers.clear();
    peers.push(local_peer_id.clone());
    peers.push(fallback_peer_id.clone());
    peers.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit npos peer roster");
    let route = RoutingDecision::new(LaneId::new(1), DataSpaceId::new(1));
    let candidates =
        super::torii_proxy_candidate_peer_ids(app.as_ref(), &local_peer_id, route, None, &[]);
    assert!(
        super::authoritative_lane_peers(app.as_ref(), route)
            .authoritative
            .is_empty(),
        "non-core route should still have no local authoritative view"
    );
    assert_eq!(candidates.authoritative_count, 0);
    assert_eq!(candidates.authoritative_total_count, 0);
    assert_eq!(candidates.offline_authoritative_count, 0);
    assert_eq!(candidates.bridge_authoritative_count, 0);
    assert!(candidates.peers.is_empty());
    assert_eq!(
        candidates.unavailable_reason,
        Some(ToriiProxyUnavailableReason::MissingAuthoritativeBinding)
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn torii_proxy_candidates_exclude_self_sender_visited_and_fail_closed_when_exhausted() {
    let local_keypair =
        checked_torii_test_ed25519_keypair(0x58, "derive authoritative-lane local fixture key");
    let authoritative_validator_keypair = checked_torii_test_ed25519_keypair(
        0x5e,
        "derive authoritative-lane manifest validator fixture key",
    );
    let sender_validator_keypair = checked_torii_test_ed25519_keypair(
        0x63,
        "derive authoritative-lane sender validator fixture key",
    );
    let visited_validator_keypair = checked_torii_test_ed25519_keypair(
        0x65,
        "derive authoritative-lane visited validator fixture key",
    );
    let offline_validator_keypair = checked_torii_test_ed25519_keypair(
        0x67,
        "derive authoritative-lane offline validator fixture key",
    );
    let authoritative_keypair =
        checked_torii_test_bls_keypair(0x5f, "derive authoritative-lane manifest peer fixture key");
    let sender_keypair =
        checked_torii_test_bls_keypair(0x64, "derive authoritative-lane sender peer fixture key");
    let visited_keypair =
        checked_torii_test_bls_keypair(0x66, "derive authoritative-lane visited peer fixture key");
    let offline_keypair =
        checked_torii_test_bls_keypair(0x68, "derive authoritative-lane offline peer fixture key");
    let local_peer_id = PeerId::from(local_keypair.public_key().clone());
    let authoritative_validator =
        AccountId::new(authoritative_validator_keypair.public_key().clone());
    let sender_validator = AccountId::new(sender_validator_keypair.public_key().clone());
    let visited_validator = AccountId::new(visited_validator_keypair.public_key().clone());
    let offline_validator = AccountId::new(offline_validator_keypair.public_key().clone());
    let authoritative_peer_id = PeerId::from(authoritative_keypair.public_key().clone());
    let sender_peer_id = PeerId::from(sender_keypair.public_key().clone());
    let visited_peer_id = PeerId::from(visited_keypair.public_key().clone());
    let offline_peer_id = PeerId::from(offline_keypair.public_key().clone());
    let mut app = native_proxy_authority_app_for_test(
        &[
            (
                authoritative_validator.clone(),
                authoritative_keypair.clone(),
            ),
            (sender_validator.clone(), sender_keypair.clone()),
            (visited_validator.clone(), visited_keypair.clone()),
            (offline_validator.clone(), offline_keypair.clone()),
        ],
        &["authoritative", "sender", "visited", "offline"].map(str::to_owned),
    );
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let (online_tx, online_rx) = tokio::sync::watch::channel(std::collections::HashSet::new());
        online_tx
            .send(std::collections::HashSet::from([
                Peer::new(
                    "127.0.0.1:10001".parse().expect("valid local address"),
                    local_keypair.public_key().clone(),
                ),
                Peer::new(
                    "127.0.0.1:10002"
                        .parse()
                        .expect("valid authoritative address"),
                    authoritative_keypair.public_key().clone(),
                ),
                Peer::new(
                    "127.0.0.1:10003".parse().expect("valid sender address"),
                    sender_keypair.public_key().clone(),
                ),
                Peer::new(
                    "127.0.0.1:10004".parse().expect("valid visited address"),
                    visited_keypair.public_key().clone(),
                ),
            ]))
            .expect("online peers update should succeed");
        app_mut.online_peers = OnlinePeersProvider::new(online_rx);
        app_mut.local_peer_id = Some(local_peer_id.clone());
    }
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let state = Arc::get_mut(&mut app_mut.state).expect("unique state");
        install_lane_manifest_registry_for_test(
            state,
            &[(
                LaneId::SINGLE,
                vec![
                    (authoritative_validator, authoritative_peer_id.clone()),
                    (sender_validator, sender_peer_id.clone()),
                    (visited_validator, visited_peer_id.clone()),
                    (offline_validator, offline_peer_id),
                ],
            )],
        );
    }
    let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let candidates = super::torii_proxy_candidate_peer_ids(
        app.as_ref(),
        &local_peer_id,
        route,
        Some(&sender_peer_id),
        std::slice::from_ref(&visited_peer_id),
    );
    assert_eq!(candidates.authoritative_count, 1);
    assert_eq!(
        candidates.peers,
        vec![ToriiProxyCandidate::P2p(authoritative_peer_id.clone())]
    );
    assert!(
        !candidates
            .peers
            .iter()
            .any(|candidate| candidate.peer_id() == &sender_peer_id)
    );
    assert!(
        !candidates
            .peers
            .iter()
            .any(|candidate| candidate.peer_id() == &visited_peer_id)
    );
    assert_eq!(candidates.loop_prevention_drops, 2);
    let local_fanout_request = ToriiProxyRequestV1 {
        schema_version: TORII_PROXY_REQUEST_VERSION_V1,
        request_id: Hash::new(b"local-nexus-fanout-cannot-target-self"),
        deadline_unix_ms: super::torii_proxy_test_deadline_unix_ms(),
        hop_count: 1,
        max_hops: TORII_PROXY_DEFAULT_MAX_HOPS,
        visited_peer_ids: vec![local_peer_id.clone()],
        request: ToriiProxyRequestKindV1::ReadFanout(super::torii_read_fanout_request(
            ToriiReadEndpointV1::AccountGet,
            ToriiFanoutRouteScopeV1::AllDataspaces,
            ToriiReadFanoutMergeV1::Account,
            vec![ALICE_ID.to_string()],
            None,
            Vec::new(),
            ToriiProxyResponseFormatV1::Json,
        )),
    };
    let fanout_candidates = super::torii_proxy_candidate_peer_ids(
        app.as_ref(),
        &local_peer_id,
        route,
        None,
        &local_fanout_request.visited_peer_ids,
    );
    assert!(
        fanout_candidates
            .peers
            .iter()
            .all(|candidate| { candidate.peer_id() != &local_peer_id }),
        "an outbound local Nexus fanout leg must never re-enter local proxy delivery"
    );
    let exhausted = super::torii_proxy_candidate_peer_ids(
        app.as_ref(),
        &local_peer_id,
        route,
        None,
        &[
            authoritative_peer_id.clone(),
            sender_peer_id.clone(),
            visited_peer_id.clone(),
        ],
    );
    assert!(exhausted.peers.is_empty());
    assert_eq!(exhausted.authoritative_total_count, 4);
    assert_eq!(exhausted.loop_prevention_drops, 3);
    assert_eq!(
        exhausted.unavailable_reason,
        Some(ToriiProxyUnavailableReason::LoopPreventionExhausted)
    );
}
#[cfg(all(feature = "app_api", feature = "connect"))]
#[tokio::test]
async fn local_nexus_read_fanout_completes_without_recursive_self_proxying() {
    let app = native_ingress_app_with_world_for_test(world_with_account(&ALICE_ID));
    let local_peer_id = app
        .local_peer_id
        .clone()
        .expect("original four-validator authority");
    let request = ToriiProxyRequestV1 {
        schema_version: TORII_PROXY_REQUEST_VERSION_V1,
        request_id: Hash::new(b"local-nexus-fanout-terminates"),
        deadline_unix_ms: super::torii_proxy_test_deadline_unix_ms(),
        hop_count: 1,
        max_hops: TORII_PROXY_DEFAULT_MAX_HOPS,
        visited_peer_ids: vec![local_peer_id.clone()],
        request: ToriiProxyRequestKindV1::ReadFanout(super::torii_read_fanout_request(
            ToriiReadEndpointV1::AccountGet,
            ToriiFanoutRouteScopeV1::TargetAccount {
                account_id: ALICE_ID.to_string(),
                caller_account_id: Some(ALICE_ID.to_string()),
            },
            ToriiReadFanoutMergeV1::Account,
            vec![ALICE_ID.to_string()],
            None,
            Vec::new(),
            ToriiProxyResponseFormatV1::Json,
        )),
    };
    let snapshot = tokio::time::timeout(
        Duration::from_secs(2),
        super::execute_torii_proxy_request_locally(&app, local_peer_id, request),
    )
    .await
    .expect("local fanout must not recurse until timeout")
    .expect("local fanout snapshot");
    assert_eq!(snapshot.snapshot.status_code, StatusCode::OK.as_u16());
}
#[cfg(all(feature = "app_api", feature = "connect"))]
#[tokio::test]
async fn incoming_torii_proxy_rejects_every_non_v1_schema_before_dispatch() {
    let app = mk_app_state_for_tests_with_world(world_with_account(&ALICE_ID));
    let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    for schema_version in [0, 2, 3, 4, 5, 6, u16::MAX] {
        let request = ToriiProxyRequestV1 {
            schema_version,
            request_id: Hash::new(
                norito::to_bytes(&("reject-non-v1-torii-proxy-request", schema_version))
                    .expect("encode non-V1 request id"),
            ),
            deadline_unix_ms: super::torii_proxy_test_deadline_unix_ms(),
            hop_count: 1,
            max_hops: 3,
            visited_peer_ids: Vec::new(),
            request: ToriiProxyRequestKindV1::Read(super::torii_read_request(
                ToriiReadEndpointV1::AccountGet,
                ToriiFanoutRouteScopeV1::AllDataspaces,
                route,
                vec![ALICE_ID.to_string()],
                None,
                Vec::new(),
            )),
        };
        let response = super::execute_incoming_torii_proxy_request(&app, request, None).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "schema version {schema_version} must fail before dispatch"
        );
    }
}
#[cfg(all(feature = "app_api", feature = "connect"))]
#[tokio::test]
async fn incoming_torii_proxy_rejects_expired_and_excessive_authenticated_deadlines() {
    let app = mk_app_state_for_tests_with_world(world_with_account(&ALICE_ID));
    let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let now_unix_ms = super::torii_proxy_now_unix_ms().expect("test clock must be available");
    let max_horizon_ms = u64::try_from(super::TORII_PROXY_MAX_DEADLINE_HORIZON.as_millis())
        .expect("fixed proxy deadline horizon fits u64 milliseconds");
    for (label, deadline_unix_ms) in [
        ("expired", now_unix_ms.saturating_sub(1)),
        (
            "excessive",
            now_unix_ms
                .checked_add(max_horizon_ms + 10_000)
                .expect("test deadline fits u64"),
        ),
    ] {
        let request = ToriiProxyRequestV1 {
            schema_version: TORII_PROXY_REQUEST_VERSION_V1,
            request_id: Hash::new(label.as_bytes()),
            deadline_unix_ms,
            hop_count: 1,
            max_hops: 3,
            visited_peer_ids: Vec::new(),
            request: ToriiProxyRequestKindV1::Read(super::torii_read_request(
                ToriiReadEndpointV1::AccountGet,
                ToriiFanoutRouteScopeV1::AllDataspaces,
                route,
                vec![ALICE_ID.to_string()],
                None,
                Vec::new(),
            )),
        };
        let response = super::execute_incoming_torii_proxy_request(&app, request, None).await;
        assert_eq!(
            response.status(),
            StatusCode::REQUEST_TIMEOUT,
            "{label} proxy deadline must fail before dispatch"
        );
        assert_eq!(
            torii_response_header(&response, "x-iroha-reject-code"),
            Some("proxy_deadline_exceeded")
        );
    }
}
#[cfg(all(feature = "app_api", feature = "connect"))]
#[tokio::test]
async fn internal_torii_proxy_route_accepts_node_signed_requests() {
    use tower::ServiceExt as _;
    let mut app = mk_app_state_for_tests_with_world(world_with_account(&ALICE_ID));
    let bridge_signer = checked_torii_test_ed25519_keypair(
        0x67,
        "derive internal Torii HTTP bridge sender fixture key",
    );
    let receiver_signer = checked_torii_test_ed25519_keypair(
        0x68,
        "derive internal Torii HTTP bridge receiver fixture key",
    );
    let sender_peer_id = PeerId::from(bridge_signer.public_key().clone());
    let local_peer_id = PeerId::from(receiver_signer.public_key().clone());
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .torii_proxy_bridge_signer = bridge_signer.clone();
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .local_peer_id = Some(local_peer_id.clone());
    {
        let mut topology = app.state.commit_topology.block();
        topology.clear();
        topology.push(local_peer_id.clone());
        topology.push(sender_peer_id.clone());
        topology.commit();
    }
    let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let proxy_request = ToriiProxyRequestV1 {
        schema_version: TORII_PROXY_REQUEST_VERSION_V1,
        request_id: Hash::new(b"internal-torii-proxy-read"),
        deadline_unix_ms: super::torii_proxy_test_deadline_unix_ms(),
        hop_count: 1,
        max_hops: 3,
        visited_peer_ids: vec![sender_peer_id],
        request: ToriiProxyRequestKindV1::Read(super::torii_read_request(
            ToriiReadEndpointV1::AccountGet,
            ToriiFanoutRouteScopeV1::AllDataspaces,
            route,
            vec![ALICE_ID.to_string()],
            None,
            Vec::new(),
        )),
    };
    let body = norito::to_bytes(&proxy_request).expect("encode proxied read");
    let uri = TORII_INTERNAL_PROXY_HTTP_PATH
        .parse::<crate::Uri>()
        .expect("internal proxy URI");
    let signed_headers = operator_signatures::signed_torii_proxy_request_headers(
        &bridge_signer,
        app.state.network_id_ref(),
        &local_peer_id,
        &crate::Method::POST,
        &uri,
        &body,
    )
    .expect("target-bound Torii proxy signature headers");
    let peer_layer = axum::middleware::from_fn_with_state::<
        _,
        _,
        (axum::extract::State<SharedAppState>, axum::extract::Request),
    >(
        app.clone(),
        operator_signatures::enforce_torii_proxy_peer_signature,
    );
    let router = axum::Router::new()
        .route(
            TORII_INTERNAL_PROXY_HTTP_PATH,
            axum::routing::post(handler_internal_torii_proxy_request).layer(peer_layer),
        )
        .with_state(app.clone());
    let mut request = axum::http::Request::builder()
        .uri(TORII_INTERNAL_PROXY_HTTP_PATH)
        .method(axum::http::Method::POST)
        .body(axum::body::Body::from(body))
        .expect("request");
    request.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-norito"),
    );
    request.headers_mut().insert(
        axum::http::header::ACCEPT,
        HeaderValue::from_static("application/x-norito"),
    );
    request.headers_mut().extend(signed_headers);
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("router response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        torii_response_header(&response, "x-iroha-routed-by"),
        Some("proxy")
    );
    let body = torii_body_bytes(response, "response body should be readable").await;
    let payload = std::str::from_utf8(&body).expect("JSON response body");
    assert!(payload.contains(&ALICE_ID.to_string()));
    let untrusted_signer = checked_torii_test_ed25519_keypair(
        0x6b,
        "derive untrusted internal Torii HTTP bridge sender fixture key",
    );
    let untrusted_peer_id = PeerId::from(untrusted_signer.public_key().clone());
    let untrusted_body = norito::to_bytes(&ToriiProxyRequestV1 {
        schema_version: TORII_PROXY_REQUEST_VERSION_V1,
        request_id: Hash::new(b"internal-torii-proxy-untrusted-peer"),
        deadline_unix_ms: super::torii_proxy_test_deadline_unix_ms(),
        hop_count: 1,
        max_hops: 3,
        visited_peer_ids: vec![untrusted_peer_id],
        request: ToriiProxyRequestKindV1::Read(super::torii_read_request(
            ToriiReadEndpointV1::AccountGet,
            ToriiFanoutRouteScopeV1::AllDataspaces,
            route,
            vec![ALICE_ID.to_string()],
            None,
            Vec::new(),
        )),
    })
    .expect("encode untrusted proxied read");
    let untrusted_headers = operator_signatures::signed_torii_proxy_request_headers(
        &untrusted_signer,
        app.state.network_id_ref(),
        &local_peer_id,
        &crate::Method::POST,
        &uri,
        &untrusted_body,
    )
    .expect("sign target-bound request from untrusted peer");
    let mut untrusted_request = axum::http::Request::builder()
        .uri(TORII_INTERNAL_PROXY_HTTP_PATH)
        .method(axum::http::Method::POST)
        .body(axum::body::Body::from(untrusted_body))
        .expect("untrusted request");
    untrusted_request.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-norito"),
    );
    untrusted_request.headers_mut().extend(untrusted_headers);
    let untrusted_response = router
        .oneshot(untrusted_request)
        .await
        .expect("untrusted peer response");
    assert_eq!(untrusted_response.status(), StatusCode::FORBIDDEN);
}
#[cfg(all(feature = "app_api", feature = "connect"))]
#[tokio::test]
async fn internal_torii_proxy_route_rejects_unsigned_requests() {
    use tower::ServiceExt as _;
    let mut app = mk_app_state_for_tests_with_world(world_with_account(&ALICE_ID));
    let local_peer_id = checked_torii_test_peer_id(
        0x69,
        "derive unsigned internal Torii proxy receiver fixture key",
    );
    Arc::get_mut(&mut app)
        .expect("unsigned internal proxy fixture app must be uniquely owned")
        .local_peer_id = Some(local_peer_id);
    let peer_layer = axum::middleware::from_fn_with_state::<
        _,
        _,
        (axum::extract::State<SharedAppState>, axum::extract::Request),
    >(
        app.clone(),
        operator_signatures::enforce_torii_proxy_peer_signature,
    );
    let router = axum::Router::new()
        .route(
            TORII_INTERNAL_PROXY_HTTP_PATH,
            axum::routing::post(handler_internal_torii_proxy_request).layer(peer_layer),
        )
        .with_state(app.clone());
    let body = norito::to_bytes(&ToriiProxyRequestV1 {
        schema_version: TORII_PROXY_REQUEST_VERSION_V1,
        request_id: Hash::new(b"internal-torii-proxy-read-unsigned"),
        deadline_unix_ms: super::torii_proxy_test_deadline_unix_ms(),
        hop_count: 1,
        max_hops: 3,
        visited_peer_ids: vec![checked_torii_test_peer_id(
            0x6a,
            "derive unsigned internal Torii proxy visited peer fixture key",
        )],
        request: ToriiProxyRequestKindV1::Read(super::torii_read_request(
            ToriiReadEndpointV1::AccountGet,
            ToriiFanoutRouteScopeV1::AllDataspaces,
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            vec![ALICE_ID.to_string()],
            None,
            Vec::new(),
        )),
    })
    .expect("encode proxied read");
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri(TORII_INTERNAL_PROXY_HTTP_PATH)
                .method(axum::http::Method::POST)
                .header(axum::http::header::CONTENT_TYPE, "application/x-norito")
                .header(axum::http::header::ACCEPT, "application/x-norito")
                .body(axum::body::Body::from(body))
                .expect("request"),
        )
        .await
        .expect("router response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn sorafs_por_proof_route_requires_fresh_path_bound_operator_signature() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tower::ServiceExt as _;
    let app = mk_app_state_for_tests();
    let signer = app.da_receipt_signer.clone();
    let operator_layer = axum::middleware::from_fn_with_state::<
        _,
        _,
        (axum::extract::State<SharedAppState>, axum::extract::Request),
    >(app.clone(), operator_signatures::enforce_operator_access);
    let router = axum::Router::new()
        .route(
            "/v1/sorafs/capacity/por-proof",
            axum::routing::post(handler_post_sorafs_capacity_por_proof)
                .layer(operator_layer.clone()),
        )
        .route(
            "/v1/sorafs/capacity/por-verdict",
            axum::routing::post(handler_post_sorafs_capacity_por_verdict).layer(operator_layer),
        )
        .with_state(app.clone());
    let body = br#"{"proof_b64":"not-base64%%"}"#.to_vec();
    let remote =
        axum::extract::ConnectInfo(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19_999));
    let unsigned = axum::http::Request::builder()
        .uri("/v1/sorafs/capacity/por-proof")
        .method(axum::http::Method::POST)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .extension(remote)
        .body(axum::body::Body::from(body.clone()))
        .expect("unsigned PoR request");
    let unsigned_response = router
        .clone()
        .oneshot(unsigned)
        .await
        .expect("unsigned response");
    assert_eq!(unsigned_response.status(), StatusCode::UNAUTHORIZED);
    let uri = "/v1/sorafs/capacity/por-proof"
        .parse::<crate::Uri>()
        .expect("PoR proof URI");
    let signed_headers = operator_signatures::signed_request_headers(
        &signer,
        app.state.network_id_ref(),
        &crate::Method::POST,
        &uri,
        &body,
    )
    .expect("signed PoR headers");
    let signed_request = || {
        let mut request = axum::http::Request::builder()
            .uri(uri.clone())
            .method(axum::http::Method::POST)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .extension(remote)
            .body(axum::body::Body::from(body.clone()))
            .expect("signed PoR request");
        request.headers_mut().extend(signed_headers.clone());
        request
    };
    let accepted_auth = router
        .clone()
        .oneshot(signed_request())
        .await
        .expect("authenticated response");
    assert_eq!(accepted_auth.status(), StatusCode::BAD_REQUEST);
    let replay = router
        .clone()
        .oneshot(signed_request())
        .await
        .expect("replay response");
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    let mut cross_path = axum::http::Request::builder()
        .uri("/v1/sorafs/capacity/por-verdict")
        .method(axum::http::Method::POST)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .extension(remote)
        .body(axum::body::Body::from(body))
        .expect("cross-path PoR request");
    cross_path.headers_mut().extend(signed_headers);
    let cross_path_response = router
        .oneshot(cross_path)
        .await
        .expect("cross-path response");
    assert_eq!(cross_path_response.status(), StatusCode::UNAUTHORIZED);
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn forward_incoming_torii_proxy_request_returns_route_unavailable_when_hops_exhausted() {
    let local_peer_id =
        checked_torii_test_peer_id(0x68, "derive internal Torii proxy local peer fixture key");
    let sender_peer_id =
        checked_torii_test_peer_id(0x6a, "derive internal Torii proxy sender peer fixture key");
    let mut app = mk_app_state_for_tests();
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .local_peer_id = Some(local_peer_id.clone());
    let route = RoutingDecision::new(LaneId::new(1), DataSpaceId::new(1));
    let response = super::forward_incoming_torii_proxy_request(
        &app,
        &sender_peer_id,
        route,
        ToriiProxyRequestV1 {
            schema_version: TORII_PROXY_REQUEST_VERSION_V1,
            request_id: Hash::new(b"torii-proxy-hop-exhausted"),
            deadline_unix_ms: super::torii_proxy_test_deadline_unix_ms(),
            hop_count: 1,
            max_hops: 1,
            visited_peer_ids: vec![sender_peer_id.clone()],
            request: ToriiProxyRequestKindV1::SignedQueryRouteScan {
                query_bytes: Vec::new(),
                expected_route: ToriiRouteHintV1::from(route),
                response_format: ToriiProxyResponseFormatV1::Norito,
            },
        },
    )
    .await;
    assert_route_unavailable_response(&response);
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn forward_incoming_torii_proxy_request_reaches_authoritative_peer() {
    let local_keypair = checked_torii_test_bls_keypair(
        0x6b,
        "derive internal Torii forward local peer fixture key",
    );
    let authoritative_keypair = checked_torii_test_bls_keypair(
        0x6c,
        "derive internal Torii forward authoritative peer fixture key",
    );
    let sender_keypair = checked_torii_test_bls_keypair(
        0x6d,
        "derive internal Torii forward sender peer fixture key",
    );
    let relay_keypair_a = checked_torii_test_bls_keypair(
        0x70,
        "derive internal Torii forward relay A peer fixture key",
    );
    let relay_keypair_b = checked_torii_test_bls_keypair(
        0x71,
        "derive internal Torii forward relay B peer fixture key",
    );
    let local_peer_id = PeerId::from(local_keypair.public_key().clone());
    let authoritative_peer_id = PeerId::from(authoritative_keypair.public_key().clone());
    let sender_peer_id = PeerId::from(sender_keypair.public_key().clone());
    let relay_peer_id_a = PeerId::from(relay_keypair_a.public_key().clone());
    let relay_peer_id_b = PeerId::from(relay_keypair_b.public_key().clone());
    let authoritative_validator = checked_torii_test_account_id(
        0x6e,
        "derive internal Torii forward authoritative validator fixture key",
    );
    let sender_validator = checked_torii_test_account_id(
        0x6f,
        "derive internal Torii forward sender validator fixture key",
    );
    let relay_validator_a = checked_torii_test_account_id(
        0x72,
        "derive internal Torii forward relay A validator fixture key",
    );
    let relay_validator_b = checked_torii_test_account_id(
        0x73,
        "derive internal Torii forward relay B validator fixture key",
    );
    let bindings = vec![
        (
            authoritative_validator.clone(),
            authoritative_keypair.clone(),
        ),
        (sender_validator.clone(), sender_keypair.clone()),
        (relay_validator_a.clone(), relay_keypair_a.clone()),
        (relay_validator_b.clone(), relay_keypair_b.clone()),
    ];
    let labels = vec![
        "authoritative".to_owned(),
        "sender".to_owned(),
        "relay-a".to_owned(),
        "relay-b".to_owned(),
    ];
    let mut app = native_proxy_authority_app_for_test(&bindings, &labels);
    // Keep the production actor admission queues live until the exact forwarded
    // request is accepted and inspected; no peer sockets are started here.
    let (network, mut actor) = iroha_core::IrohaNetwork::actor_admission_for_tests(
        local_peer_id.clone(),
        std::collections::HashSet::from([authoritative_peer_id.clone()]),
        std::num::NonZeroUsize::new(1).expect("one forwarded request"),
    );
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let (_online_tx, online_rx) =
            tokio::sync::watch::channel(std::collections::HashSet::from([
                Peer::new(
                    "127.0.0.1:10001".parse().expect("valid local address"),
                    local_keypair.public_key().clone(),
                ),
                Peer::new(
                    "127.0.0.1:10002"
                        .parse()
                        .expect("valid authoritative address"),
                    authoritative_keypair.public_key().clone(),
                ),
            ]));
        app_mut.online_peers = OnlinePeersProvider::new(online_rx);
        // This ingress observer is deliberately outside the genuine four-seat
        // committee; only the original authoritative peer is online for forwarding.
        app_mut.local_peer_id = Some(local_peer_id.clone());
        app_mut.p2p = Some(network);
        install_lane_manifest_registry_for_test(
            &app_mut.state,
            &[(
                LaneId::SINGLE,
                vec![
                    (authoritative_validator, authoritative_peer_id.clone()),
                    (sender_validator, sender_peer_id.clone()),
                    (relay_validator_a, relay_peer_id_a),
                    (relay_validator_b, relay_peer_id_b),
                ],
            )],
        );
    }
    let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let request_id = Hash::new(b"torii-proxy-forward-success");
    let deadline_unix_ms = super::torii_proxy_test_deadline_unix_ms();
    let expected_visited = vec![sender_peer_id.clone(), local_peer_id.clone()];
    let app_for_response = app.clone();
    let authoritative_peer_for_response = authoritative_peer_id.clone();
    let request_id_for_response = request_id.clone();
    let response_task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let admitted = actor.drain_posts(|post| {
                    assert_eq!(post.peer_id, authoritative_peer_for_response);
                    let iroha_core::NetworkMessage::ToriiProxyRequest(request) = &post.data else {
                        panic!("expected the admitted forwarded Torii request");
                    };
                    assert_eq!(request.schema_version, TORII_PROXY_REQUEST_VERSION_V1);
                    assert_eq!(request.request_id, request_id_for_response);
                    assert_eq!(request.deadline_unix_ms, deadline_unix_ms);
                    assert_eq!(request.hop_count, 2);
                    assert_eq!(request.max_hops, 3);
                    assert_eq!(request.visited_peer_ids, expected_visited);
                    let ToriiProxyRequestKindV1::SignedQueryRouteScan {
                        query_bytes,
                        expected_route,
                        response_format,
                    } = &request.request
                    else {
                        panic!("the original signed-query request kind must be preserved");
                    };
                    assert!(query_bytes.is_empty());
                    assert_eq!(*expected_route, ToriiRouteHintV1::from(route));
                    assert_eq!(*response_format, ToriiProxyResponseFormatV1::Norito);
                    assert!(
                        app_for_response.torii_proxy_pending.lock().contains_key(&(
                            request_id_for_response,
                            authoritative_peer_for_response.clone(),
                        )),
                        "the response fence must remain while actual dispatch is admitted"
                    );
                });
                assert!(admitted <= 1, "one exact forwarded request is admitted");
                if admitted == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("forwarded Torii proxy request should reach the actor queue");
        super::process_incoming_torii_proxy_response(
            &app_for_response,
            authoritative_peer_for_response,
            ToriiProxyResponseV1 {
                schema_version: TORII_PROXY_RESPONSE_VERSION_V1,
                request_id: request_id_for_response,
                response: ToriiProxyHttpResponseV1 {
                    status_code: StatusCode::OK.as_u16(),
                    headers: Vec::new(),
                    body: b"forwarded-ok".to_vec(),
                },
            },
        )
        .await;
    });
    let response = super::forward_incoming_torii_proxy_request(
        &app,
        &sender_peer_id,
        route,
        ToriiProxyRequestV1 {
            schema_version: TORII_PROXY_REQUEST_VERSION_V1,
            request_id,
            deadline_unix_ms,
            hop_count: 1,
            max_hops: 3,
            visited_peer_ids: vec![sender_peer_id.clone()],
            request: ToriiProxyRequestKindV1::SignedQueryRouteScan {
                query_bytes: Vec::new(),
                expected_route: ToriiRouteHintV1::from(route),
                response_format: ToriiProxyResponseFormatV1::Norito,
            },
        },
    )
    .await;
    response_task
        .await
        .expect("proxy response task should complete");
    assert_eq!(response.status(), StatusCode::OK);
    let body = torii_body_bytes(response, "forwarded response body should be readable").await;
    assert_eq!(body.as_ref(), b"forwarded-ok");
}
#[tokio::test]
#[cfg(feature = "connect")]
async fn torii_proxy_network_message_dispatch_resolves_pending_response() {
    let app = mk_app_state_for_tests();
    let request_id = Hash::new(b"torii-proxy-dispatch");
    let responder_keypair = checked_torii_test_ed25519_keypair(
        0x78,
        "derive Torii proxy response dispatcher responder fixture key",
    );
    let responder_peer_id = PeerId::from(responder_keypair.public_key().clone());
    let responder_peer = Peer::new(
        "127.0.0.1:1337".parse().expect("valid peer address"),
        responder_keypair.public_key().clone(),
    );
    let expected_response = ToriiProxyHttpResponseV1 {
        status_code: StatusCode::ACCEPTED.as_u16(),
        headers: Vec::new(),
        body: b"torii-proxy-response".to_vec(),
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    let _waiter_token = super::register_torii_proxy_pending_waiter(
        &app,
        (request_id, responder_peer_id),
        tx,
        usize::MAX,
    );
    let payload = iroha_core::NetworkMessage::ToriiProxyResponse(Box::new(ToriiProxyResponseV1 {
        schema_version: TORII_PROXY_RESPONSE_VERSION_V1,
        request_id,
        response: expected_response.clone(),
    }));
    let payload_bytes = norito::to_bytes(&payload)
        .expect("encode synthetic Torii proxy response")
        .len();
    let message =
        iroha_p2p::peer::message::PeerMessage::new(responder_peer, payload, payload_bytes);
    let (requests, _request_rx) = tokio::sync::mpsc::channel(1);
    super::proxy_network_workers::dispatch(
        &app,
        &iroha_core::IrohaNetwork::closed_for_tests(),
        &requests,
        message,
    )
    .await;
    assert_eq!(
        rx.await
            .expect("pending Torii proxy request should resolve"),
        expected_response
    );
    assert!(
        !app.torii_proxy_pending
            .lock()
            .keys()
            .any(|(pending_request_id, _)| *pending_request_id == request_id),
        "Torii proxy response dispatcher must clear the pending request"
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn identical_torii_proxy_submissions_keep_all_pending_waiters() {
    let app = mk_app_state_for_tests();
    let request_id = Hash::new(b"identical-torii-proxy-submissions");
    let responder_peer_id = checked_torii_test_peer_id(
        0x7a,
        "derive identical-submission proxy responder fixture key",
    );
    let pending_key = (request_id, responder_peer_id.clone());
    let expected_response = ToriiProxyHttpResponseV1 {
        status_code: StatusCode::ACCEPTED.as_u16(),
        headers: Vec::new(),
        body: b"shared-durable-acceptance".to_vec(),
    };
    let (first_tx, first_rx) = tokio::sync::oneshot::channel();
    let (second_tx, second_rx) = tokio::sync::oneshot::channel();
    let _first_waiter_token =
        super::register_torii_proxy_pending_waiter(&app, pending_key.clone(), first_tx, 1024);
    let _second_waiter_token =
        super::register_torii_proxy_pending_waiter(&app, pending_key.clone(), second_tx, 1024);
    assert_eq!(
        app.torii_proxy_pending
            .lock()
            .get(&pending_key)
            .map(Vec::len),
        Some(2),
        "an identical pending submission must append its waiter instead of replacing the first"
    );

    super::mark_torii_proxy_request_completed(&app, request_id).await;
    assert_eq!(
        app.torii_proxy_pending
            .lock()
            .get(&pending_key)
            .map(Vec::len),
        Some(2),
        "completion of another caller with the same semantic request id must preserve live waiters"
    );

    super::process_incoming_torii_proxy_response(
        &app,
        responder_peer_id,
        ToriiProxyResponseV1 {
            schema_version: TORII_PROXY_RESPONSE_VERSION_V1,
            request_id,
            response: expected_response.clone(),
        },
    )
    .await;
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(100), first_rx)
            .await
            .expect("first identical waiter must resolve promptly")
            .expect("first identical waiter must remain open"),
        expected_response
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(100), second_rx)
            .await
            .expect("second identical waiter must resolve promptly")
            .expect("second identical waiter must remain open"),
        expected_response
    );
    assert!(
        !app.torii_proxy_pending.lock().contains_key(&pending_key),
        "the shared response must clear the completed waiter set"
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn identical_torii_proxy_waiters_enforce_body_bounds_independently() {
    let app = mk_app_state_for_tests();
    let request_id = Hash::new(b"identical-torii-proxy-per-waiter-bounds");
    let responder_peer_id = checked_torii_test_peer_id(
        0x7c,
        "derive identical-submission per-waiter-bounds responder fixture key",
    );
    let pending_key = (request_id, responder_peer_id.clone());
    let (tight_tx, tight_rx) = tokio::sync::oneshot::channel();
    let (wide_tx, wide_rx) = tokio::sync::oneshot::channel();
    let _tight_waiter_token =
        super::register_torii_proxy_pending_waiter(&app, pending_key.clone(), tight_tx, 4);
    let _wide_waiter_token =
        super::register_torii_proxy_pending_waiter(&app, pending_key.clone(), wide_tx, 1024);
    let expected_response = ToriiProxyHttpResponseV1 {
        status_code: StatusCode::OK.as_u16(),
        headers: Vec::new(),
        body: b"five!".to_vec(),
    };

    super::process_incoming_torii_proxy_response(
        &app,
        responder_peer_id,
        ToriiProxyResponseV1 {
            schema_version: TORII_PROXY_RESPONSE_VERSION_V1,
            request_id,
            response: expected_response.clone(),
        },
    )
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), tight_rx)
            .await
            .expect("tight waiter rejection must resolve promptly")
            .is_err(),
        "a response above one waiter's body cap must close only that waiter"
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(100), wide_rx)
            .await
            .expect("wide waiter must resolve promptly")
            .expect("wide waiter must remain open"),
        expected_response
    );
    assert!(
        !app.torii_proxy_pending.lock().contains_key(&pending_key),
        "per-waiter validation must consume the completed waiter set"
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn identical_torii_proxy_attempt_cleanup_is_waiter_scoped() {
    let app = mk_app_state_for_tests();
    let request_id = Hash::new(b"identical-torii-proxy-attempt-cleanup");
    let responder_peer_id = checked_torii_test_peer_id(
        0x7b,
        "derive identical-submission cleanup responder fixture key",
    );
    let pending_key = (request_id, responder_peer_id.clone());
    let (failed_tx, failed_rx) = tokio::sync::oneshot::channel();
    let (live_tx, live_rx) = tokio::sync::oneshot::channel();
    let failed_waiter_token =
        super::register_torii_proxy_pending_waiter(&app, pending_key.clone(), failed_tx, 1024);
    let _live_waiter_token =
        super::register_torii_proxy_pending_waiter(&app, pending_key.clone(), live_tx, 1024);

    drop(failed_waiter_token);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), failed_rx)
            .await
            .expect("failed attempt cleanup must close its waiter promptly")
            .is_err(),
        "cleaning one failed attempt must close only that attempt's waiter"
    );
    assert_eq!(
        app.torii_proxy_pending
            .lock()
            .get(&pending_key)
            .map(Vec::len),
        Some(1),
        "cleaning one identical attempt must preserve the other live waiter"
    );

    let expected_response = ToriiProxyHttpResponseV1 {
        status_code: StatusCode::ACCEPTED.as_u16(),
        headers: Vec::new(),
        body: b"remaining-waiter-response".to_vec(),
    };
    super::process_incoming_torii_proxy_response(
        &app,
        responder_peer_id,
        ToriiProxyResponseV1 {
            schema_version: TORII_PROXY_RESPONSE_VERSION_V1,
            request_id,
            response: expected_response.clone(),
        },
    )
    .await;
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(100), live_rx)
            .await
            .expect("remaining identical waiter must resolve promptly")
            .expect("remaining identical waiter must stay open"),
        expected_response
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn process_incoming_torii_proxy_response_marks_late_responses_once() {
    let app = mk_app_state_for_tests();
    let request_id = Hash::new(b"torii-proxy-late-response");
    let responder_peer_id = checked_torii_test_peer_id(
        0x79,
        "derive Torii proxy late-response responder fixture key",
    );
    super::mark_torii_proxy_request_completed(&app, request_id).await;
    let response = ToriiProxyResponseV1 {
        schema_version: TORII_PROXY_RESPONSE_VERSION_V1,
        request_id,
        response: ToriiProxyHttpResponseV1 {
            status_code: StatusCode::OK.as_u16(),
            headers: Vec::new(),
            body: b"late".to_vec(),
        },
    };
    super::process_incoming_torii_proxy_response(&app, responder_peer_id.clone(), response).await;
    {
        let completed = app.torii_proxy_completed.lock().await;
        assert!(
            completed
                .entries
                .get(&request_id)
                .is_some_and(|entry| entry.late_response_logged),
            "first late response should latch the one-time ignore marker"
        );
    }
    super::process_incoming_torii_proxy_response(
        &app,
        responder_peer_id,
        ToriiProxyResponseV1 {
            schema_version: TORII_PROXY_RESPONSE_VERSION_V1,
            request_id,
            response: ToriiProxyHttpResponseV1 {
                status_code: StatusCode::OK.as_u16(),
                headers: Vec::new(),
                body: b"late-again".to_vec(),
            },
        },
    )
    .await;
    assert!(
        app.torii_proxy_pending.lock().is_empty(),
        "late responses must not recreate pending state after completion"
    );
}
#[cfg(feature = "connect")]
#[test]
fn completed_torii_proxy_requests_are_fifo_bounded_and_ttl_pruned() {
    let request_id = |index: usize| {
        let mut bytes = [0_u8; Hash::LENGTH];
        bytes[..8].copy_from_slice(
            &u64::try_from(index)
                .expect("bounded completion-cache test index")
                .to_le_bytes(),
        );
        Hash::prehashed(bytes)
    };
    let now = Instant::now();
    let mut completed = CompletedToriiProxyRequests::default();
    for index in 0..=TORII_PROXY_COMPLETED_CAP {
        completed.record(request_id(index), now);
    }
    assert_eq!(completed.entries.len(), TORII_PROXY_COMPLETED_CAP);
    assert!(
        !completed.entries.contains_key(&request_id(0)),
        "capacity overflow must evict the oldest completed request"
    );
    assert!(
        completed
            .entries
            .contains_key(&request_id(TORII_PROXY_COMPLETED_CAP)),
        "capacity overflow must retain the newest completed request"
    );
    completed.prune(now + TORII_PROXY_COMPLETED_TTL);
    assert!(completed.entries.is_empty());
    assert!(completed.insertion_order.is_empty());
}
