/// Canonical storage and autoscale routing controls colocated with their original private owner.
mod multilane_storage_and_routing_tests {
    include!("router_multilane_storage_and_routing_tests.rs");
}

#[test]
fn asset_definition_alias_dataspace_permission_grant_routes_by_scope() {
    let (submitter_id, submitter_keypair) = gen_account_in("wonderland");
    let (holder_id, _) = gen_account_in("wonderland");
    let dataspace_id = DataSpaceId::new(10);
    let lane_id = LaneId::new(3);
    let catalog = dataspace_catalog(&[(dataspace_id, "paynet")]);
    let lane_catalog = catalog_with_lane_dataspaces(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (lane_id, dataspace_id),
    ]);
    let router = ConfigLaneRouter::new(
        LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: Vec::new(),
        },
        catalog,
        lane_catalog,
    );
    let permission = Permission::from(CanManageAssetDefinitionAlias {
        scope: AssetDefinitionAliasPermissionScope::Dataspace(dataspace_id),
    });
    let tx = sample_transaction(
        &submitter_id,
        submitter_keypair.private_key(),
        vec![InstructionBox::from(Grant::account_permission(
            permission, holder_id,
        ))],
    );
    assert_eq!(
        router
            .try_route_without_state(&tx)
            .expect("asset alias permission should route without world state"),
        Some(RoutingDecision::new(lane_id, dataspace_id))
    );
}
#[test]
fn applies_account_and_instruction_rules() {
    let (alice_id, alice_keypair) = gen_account_in("wonderland");
    let (_bob_id, _) = gen_account_in("wonderland");
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::new(0),
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: vec![
            LaneRoutingRule {
                lane: LaneId::new(1),
                dataspace: None,
                matcher: LaneRoutingMatcher {
                    account: Some(alice_id.to_string()),
                    instruction: Some("Mint".into()),
                    description: None,
                },
            },
            LaneRoutingRule {
                lane: LaneId::new(2),
                dataspace: None,
                matcher: LaneRoutingMatcher {
                    account: Some("sorauﾛ1NｲﾘｳdPBeｼRoｸQ2ﾔgｼQqeｶﾍｽﾁhRW2ｺｿZ9ﾕｦUﾅRX5NJYH53".into()),
                    instruction: None,
                    description: None,
                },
            },
        ],
    };
    let lane_catalog = catalog_with_lanes(&[LaneId::SINGLE, LaneId::new(1), LaneId::new(2)]);
    let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
    let asset_definition: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let asset_id = AssetId::of(asset_definition.clone(), alice_id.clone());
    let mint = Mint::asset_quantity(1u32, asset_id);
    let register = Register::asset_definition(AssetDefinition::numeric(
        asset_definition.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    ));
    let tx = sample_transaction(
        &alice_id,
        alice_keypair.private_key(),
        vec![InstructionBox::from(mint), InstructionBox::from(register)],
    );
    let mut state = blank_state();
    install_router_nexus(&mut state, &router);
    let decision = router
        .try_route_with_view(&tx, &state.view())
        .expect("routing should resolve");
    assert_eq!(decision.lane_id.as_u32(), 1);
    assert_eq!(decision.dataspace_id, DataSpaceId::UNIVERSAL);
    // Non-matching instruction should fall back to default lane.
    let tx = sample_transaction(
        &alice_id,
        alice_keypair.private_key(),
        vec![InstructionBox::from(Register::domain(Domain::new(
            DomainId::try_new("fallback", "universal").expect("domain"),
        )))],
    );
    let decision = router
        .try_route_with_view(&tx, &state.view())
        .expect("default routing should resolve");
    assert_eq!(decision.lane_id.as_u32(), 0);
}
#[test]
fn canonical_config_router_defers_untargeted_single_lane_routing_to_state() {
    let (alice_id, alice_keypair) = gen_account_in("wonderland");
    let tx = sample_transaction(
        &alice_id,
        alice_keypair.private_key(),
        vec![role_registration_instruction(&alice_id, "single_lane")],
    );
    let mut state = blank_state();
    let router = ConfigLaneRouter::new(
        LaneRoutingPolicy::default(),
        DataSpaceCatalog::default(),
        LaneCatalog::default(),
    );
    install_router_nexus(&mut state, &router);
    let with_view = router
        .try_route_with_view(&tx, &state.view())
        .expect("canonical single-lane routing should resolve");
    let without_view = router
        .try_route_without_state(&tx)
        .expect("canonical single-lane state-free routing should defer cleanly");
    assert_eq!(
        without_view, None,
        "even a one-lane catalog must inspect account scope before selecting the route"
    );
    assert_eq!(
        with_view,
        RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
    );
}
#[test]
fn config_lane_router_state_free_path_matches_view_path() {
    let (alice_id, alice_keypair) = gen_account_in("wonderland");
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::SINGLE,
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: vec![LaneRoutingRule {
            lane: LaneId::new(3),
            dataspace: Some(DataSpaceId::new(7)),
            matcher: LaneRoutingMatcher {
                account: Some(alice_id.to_string()),
                instruction: Some("register::role".to_string()),
                description: None,
            },
        }],
    };
    let lane_catalog = catalog_with_lane_dataspaces(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (LaneId::new(3), DataSpaceId::new(7)),
    ]);
    let dataspace_catalog = DataSpaceCatalog::new(vec![
        iroha_data_model::nexus::DataSpaceMetadata::default(),
        iroha_data_model::nexus::DataSpaceMetadata {
            id: DataSpaceId::new(7),
            alias: "alpha".to_string(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("valid dataspace catalog");
    let router = ConfigLaneRouter::new(policy, dataspace_catalog, lane_catalog);
    let tx = sample_transaction(
        &alice_id,
        alice_keypair.private_key(),
        vec![role_registration_instruction(&alice_id, "statefree")],
    );
    let mut state = blank_state();
    install_router_nexus(&mut state, &router);
    let with_view = router
        .try_route_with_view(&tx, &state.view())
        .expect("configured routing should resolve");
    let without_view = router
        .try_route_without_state(&tx)
        .expect("configured state-free routing should resolve");
    assert_eq!(without_view, Some(with_view));
}
#[test]
fn default_route_elastic_candidates_require_autoscale_metadata() {
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::SINGLE,
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: Vec::new(),
    };
    let valid = autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7);
    let mut bad_alias = autoscale_elastic_lane_config(LaneId::new(2), DataSpaceId::UNIVERSAL, 7);
    bad_alias.alias = "lane-2".to_string();
    let mut missing_height =
        autoscale_elastic_lane_config(LaneId::new(3), DataSpaceId::UNIVERSAL, 7);
    missing_height
        .metadata
        .remove(AUTOSCALE_META_CREATED_HEIGHT);
    let mut zero_height = autoscale_elastic_lane_config(LaneId::new(4), DataSpaceId::UNIVERSAL, 7);
    zero_height
        .metadata
        .insert(AUTOSCALE_META_CREATED_HEIGHT.to_string(), "0".to_string());
    let mut malformed_height =
        autoscale_elastic_lane_config(LaneId::new(5), DataSpaceId::UNIVERSAL, 7);
    malformed_height.metadata.insert(
        AUTOSCALE_META_CREATED_HEIGHT.to_string(),
        "later".to_string(),
    );
    let other_dataspace = autoscale_elastic_lane_config(LaneId::new(6), DataSpaceId::new(9), 7);
    let mut false_managed =
        autoscale_elastic_lane_config(LaneId::new(7), DataSpaceId::UNIVERSAL, 7);
    false_managed
        .metadata
        .insert(AUTOSCALE_META_MANAGED.to_string(), "TRUE".to_string());
    // A restricted corruption candidate needs its own nonuniversal disclosure scope.
    let restricted_dataspace = DataSpaceId::new(10);
    let mut restricted_lane =
        autoscale_elastic_lane_config(LaneId::new(8), restricted_dataspace, 7);
    restricted_lane.visibility = LaneVisibility::Restricted;
    let valid_lane_catalog = lane_catalog_from_configs(vec![default_lane_config(), valid]);
    assert_eq!(
        default_route_elastic_candidates(&policy, &valid_lane_catalog, None),
        vec![LaneId::SINGLE]
    );
    assert_eq!(
        default_route_elastic_candidates(
            &policy,
            &valid_lane_catalog,
            Some(AutoscaleElasticRange {
                min_lane_id: 1,
                max_lane_id_exclusive: 9,
                current_height: None,
                required_active_height: None,
            }),
        ),
        vec![LaneId::SINGLE, LaneId::new(1)]
    );
    assert_eq!(
        default_route_elastic_candidates(
            &policy,
            &valid_lane_catalog,
            Some(AutoscaleElasticRange {
                min_lane_id: 1,
                max_lane_id_exclusive: 9,
                current_height: Some(6),
                required_active_height: Some(6),
            }),
        ),
        vec![LaneId::SINGLE],
        "future-created elastic lanes must fail closed until their creation height is committed"
    );
    assert_eq!(
        default_route_elastic_candidates(
            &policy,
            &valid_lane_catalog,
            Some(AutoscaleElasticRange {
                min_lane_id: 1,
                max_lane_id_exclusive: 9,
                current_height: Some(7),
                required_active_height: Some(7),
            }),
        ),
        vec![LaneId::SINGLE, LaneId::new(1)]
    );
    let corrupted_lane_catalog = lane_catalog_from_configs(vec![
        default_lane_config(),
        autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
        bad_alias,
        missing_height,
        zero_height,
        malformed_height,
        other_dataspace,
        false_managed,
        restricted_lane,
    ]);
    assert_eq!(
        default_route_elastic_candidates(
            &policy,
            &corrupted_lane_catalog,
            Some(AutoscaleElasticRange {
                min_lane_id: 1,
                max_lane_id_exclusive: 9,
                current_height: None,
                required_active_height: None,
            }),
        ),
        vec![LaneId::SINGLE],
        "corrupted lanes inside the active elastic range must fail closed to the base default lane"
    );
    // Isolate visibility from the wrong-dataspace guard: both descriptors inhabit
    // one valid restricted dataspace, but otherwise-valid elastic metadata must
    // still never make its restricted candidate selectable by autoscale routing.
    let restricted_policy = LaneRoutingPolicy {
        default_dataspace: restricted_dataspace,
        ..policy.clone()
    };
    let mut restricted_candidate =
        autoscale_elastic_lane_config(LaneId::new(1), restricted_dataspace, 7);
    restricted_candidate.visibility = LaneVisibility::Restricted;
    let restricted_catalog = lane_catalog_from_configs(vec![
        LaneConfig {
            dataspace_id: restricted_dataspace,
            visibility: LaneVisibility::Restricted,
            ..default_lane_config()
        },
        restricted_candidate,
    ]);
    assert_eq!(
        default_route_elastic_candidates(&restricted_policy, &restricted_catalog, None),
        vec![LaneId::SINGLE]
    );
    assert_eq!(
        default_route_elastic_candidates(
            &restricted_policy,
            &restricted_catalog,
            Some(AutoscaleElasticRange {
                min_lane_id: 1,
                max_lane_id_exclusive: 2,
                current_height: Some(7),
                required_active_height: Some(7),
            }),
        ),
        vec![LaneId::SINGLE],
        "restricted elastic candidates with matching dataspace and valid metadata must fail closed"
    );
    let mismatched_default_catalog = lane_catalog_from_configs(vec![
        LaneConfig {
            dataspace_id: DataSpaceId::new(9),
            ..default_lane_config()
        },
        autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
    ]);
    assert!(
        default_route_elastic_candidates(
            &policy,
            &mismatched_default_catalog,
            Some(AutoscaleElasticRange {
                min_lane_id: 1,
                max_lane_id_exclusive: 8,
                current_height: None,
                required_active_height: None,
            }),
        )
        .is_empty()
    );
}
#[test]
fn default_route_elastic_candidates_apply_autoscale_range_when_available() {
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::SINGLE,
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: Vec::new(),
    };
    let lane_catalog = lane_catalog_from_configs(vec![
        default_lane_config(),
        autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
        autoscale_elastic_lane_config(LaneId::new(7), DataSpaceId::UNIVERSAL, 7),
        autoscale_elastic_lane_config(LaneId::new(8), DataSpaceId::UNIVERSAL, 7),
    ]);
    assert_eq!(
        default_route_elastic_candidates(&policy, &lane_catalog, None),
        vec![LaneId::SINGLE]
    );
    assert_eq!(
        default_route_elastic_candidates(
            &policy,
            &lane_catalog,
            Some(AutoscaleElasticRange {
                min_lane_id: 1,
                max_lane_id_exclusive: 8,
                current_height: None,
                required_active_height: None,
            }),
        ),
        vec![LaneId::SINGLE, LaneId::new(1), LaneId::new(7)]
    );
    assert_eq!(
        default_route_elastic_candidates(
            &policy,
            &lane_catalog,
            Some(AutoscaleElasticRange {
                min_lane_id: 2,
                max_lane_id_exclusive: 7,
                current_height: None,
                required_active_height: None,
            }),
        ),
        vec![LaneId::SINGLE]
    );
}
#[test]
fn routable_lane_ids_for_nexus_at_height_ignores_unrouted_same_dataspace_sidecar() {
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::SINGLE,
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: Vec::new(),
    };
    let lane_catalog = lane_catalog_from_configs(vec![
        default_lane_config(),
        LaneConfig {
            id: LaneId::new(1),
            dataspace_id: DataSpaceId::UNIVERSAL,
            alias: "sidecar".to_string(),
            ..LaneConfig::default()
        },
    ]);
    let nexus = nexus_with_routing(policy, lane_catalog, DataSpaceCatalog::default());
    assert_eq!(
        routable_lane_ids_for_nexus_at_height(&nexus, 1),
        BTreeSet::from([LaneId::SINGLE]),
        "active same-dataspace lanes that no policy path can select must not enable lookahead"
    );
}
#[test]
fn routable_lane_ids_for_nexus_at_height_includes_explicit_rule_sidecar() {
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::SINGLE,
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: vec![LaneRoutingRule {
            lane: LaneId::new(1),
            dataspace: Some(DataSpaceId::UNIVERSAL),
            matcher: LaneRoutingMatcher {
                account: Some("alice".to_string()),
                instruction: None,
                description: None,
            },
        }],
    };
    let lane_catalog = lane_catalog_from_configs(vec![
        default_lane_config(),
        LaneConfig {
            id: LaneId::new(1),
            dataspace_id: DataSpaceId::UNIVERSAL,
            alias: "sidecar".to_string(),
            ..LaneConfig::default()
        },
    ]);
    let nexus = nexus_with_routing(policy, lane_catalog, DataSpaceCatalog::default());
    assert_eq!(
        routable_lane_ids_for_nexus_at_height(&nexus, 1),
        BTreeSet::from([LaneId::SINGLE, LaneId::new(1)]),
        "explicit rules make an otherwise sidecar lane reachable"
    );
}
#[test]
fn routable_lane_ids_for_nexus_at_height_respects_autoscale_created_height() {
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::SINGLE,
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: Vec::new(),
    };
    let lane_catalog = lane_catalog_from_configs(vec![
        default_lane_config(),
        autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
    ]);
    let mut nexus = nexus_with_routing(policy, lane_catalog, DataSpaceCatalog::default());
    nexus.autoscale.enabled = true;
    nexus.autoscale.min_lane_id = nonzero!(1_u32);
    nexus.autoscale.max_lane_id_exclusive = nonzero!(4_u32);
    assert_eq!(
        routable_lane_ids_for_nexus_at_height(&nexus, 6),
        BTreeSet::from([LaneId::SINGLE]),
        "future-created autoscale lanes must not be policy-reachable yet"
    );
    assert_eq!(
        routable_lane_ids_for_nexus_at_height(&nexus, 7),
        BTreeSet::from([LaneId::SINGLE, LaneId::new(1)]),
        "autoscale lanes become policy-reachable once their creation height is committed"
    );
}
#[test]
fn routable_lane_ids_for_nexus_at_height_rejects_autoscale_owned_default_anchor() {
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::new(1),
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: Vec::new(),
    };
    let lane_catalog = lane_catalog_from_configs(vec![autoscale_elastic_lane_config(
        LaneId::new(1),
        DataSpaceId::UNIVERSAL,
        1,
    )]);
    let mut nexus = nexus_with_routing(policy, lane_catalog, DataSpaceCatalog::default());
    nexus.autoscale.enabled = true;
    nexus.autoscale.min_lane_id = nonzero!(1_u32);
    nexus.autoscale.max_lane_id_exclusive = nonzero!(4_u32);
    assert!(
        routable_lane_ids_for_nexus_at_height(&nexus, 1).is_empty(),
        "an autoscale-owned default anchor must not make corrupted no-target routing reachable"
    );
}
#[test]
fn routable_lane_ids_for_nexus_at_height_rejects_off_default_autoscale_owned_rule_lane() {
    let rule_dataspace = DataSpaceId::new(9);
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::SINGLE,
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: vec![LaneRoutingRule {
            lane: LaneId::new(1),
            dataspace: Some(rule_dataspace),
            matcher: LaneRoutingMatcher {
                account: Some("alice".to_string()),
                instruction: None,
                description: None,
            },
        }],
    };
    let lane_catalog = lane_catalog_from_configs(vec![
        default_lane_config(),
        autoscale_elastic_lane_config(LaneId::new(1), rule_dataspace, 1),
    ]);
    let mut nexus = nexus_with_routing(
        policy,
        lane_catalog,
        dataspace_catalog(&[(rule_dataspace, "rule-space")]),
    );
    nexus.autoscale.enabled = true;
    nexus.autoscale.min_lane_id = nonzero!(1_u32);
    nexus.autoscale.max_lane_id_exclusive = nonzero!(4_u32);
    assert_eq!(
        routable_lane_ids_for_nexus_at_height(&nexus, 1),
        BTreeSet::from([LaneId::SINGLE]),
        "off-default autoscale-owned explicit rule lanes must not inflate proposal lookahead reachability"
    );
}
