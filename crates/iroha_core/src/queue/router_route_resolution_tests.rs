// Route-resolution, catalog-validation, and dynamic-dataspace alias regressions.
#[test]
fn route_resolution_rejects_lane_dataspace_mismatch() {
    use iroha_data_model::nexus::DataSpaceMetadata;
    let (alice_id, alice_keypair) = gen_account_in("wonderland");
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::SINGLE,
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: vec![LaneRoutingRule {
            lane: LaneId::new(4),
            dataspace: Some(DataSpaceId::new(9)),
            matcher: LaneRoutingMatcher {
                account: Some(alice_id.to_string()),
                instruction: None,
                description: None,
            },
        }],
    };
    let catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: DataSpaceId::new(7),
            alias: "beta".to_string(),
            description: None,
            fault_tolerance: 1,
        },
        DataSpaceMetadata {
            id: DataSpaceId::new(9),
            alias: "gamma".to_string(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("valid dataspace catalog");
    let lane_catalog = catalog_with_lane_dataspaces(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (LaneId::new(4), DataSpaceId::new(7)),
    ]);
    let router = ConfigLaneRouter::new(policy, catalog.clone(), lane_catalog.clone());
    let state = blank_state();
    install_synthetic_router_nexus(&state, &router);
    let tx = sample_transaction(
        &alice_id,
        alice_keypair.private_key(),
        vec![InstructionBox::from(Register::domain(Domain::new(
            DomainId::try_new("override", "universal").expect("domain"),
        )))],
    );
    let direct_err = router
        .try_route_with_view(&tx, &state.view())
        .expect_err("mismatched lane/dataspace must not fall back to the universal route");
    assert!(matches!(
        direct_err,
        RoutingResolveError::LaneDataspaceMismatch { .. }
    ));
    let helper_err =
        evaluate_policy_with_catalog(router.policy.as_ref(), &lane_catalog, &catalog, &tx)
            .expect_err("mismatched lane/dataspace must be rejected");
    assert!(matches!(
        helper_err,
        RoutingResolveError::LaneDataspaceMismatch { .. }
    ));
}
#[test]
fn route_resolution_rejects_unknown_lane() {
    use iroha_data_model::nexus::DataSpaceMetadata;
    let (alice_id, alice_keypair) = gen_account_in("wonderland");
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::SINGLE,
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: vec![LaneRoutingRule {
            lane: LaneId::new(9),
            dataspace: Some(DataSpaceId::new(7)),
            matcher: LaneRoutingMatcher {
                account: Some(alice_id.to_string()),
                instruction: None,
                description: None,
            },
        }],
    };
    let catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: DataSpaceId::new(7),
            alias: "alpha".to_string(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("valid dataspace catalog");
    let lane_catalog = catalog_with_lane_dataspaces(&[(LaneId::SINGLE, DataSpaceId::UNIVERSAL)]);
    let router = ConfigLaneRouter::new(policy, catalog.clone(), lane_catalog.clone());
    let state = blank_state();
    install_synthetic_router_nexus(&state, &router);
    let tx = sample_transaction(
        &alice_id,
        alice_keypair.private_key(),
        vec![InstructionBox::from(Log::new(
            iroha_logger::Level::INFO,
            "unknown lane".into(),
        ))],
    );
    let direct_err = router
        .try_route_with_view(&tx, &state.view())
        .expect_err("unknown lane must not fall back to the universal route");
    assert!(matches!(
        direct_err,
        RoutingResolveError::UnknownLane { .. }
    ));
    let helper_err =
        evaluate_policy_with_catalog(router.policy.as_ref(), &lane_catalog, &catalog, &tx)
            .expect_err("unknown lane must be rejected");
    assert!(matches!(
        helper_err,
        RoutingResolveError::UnknownLane { .. }
    ));
}
#[test]
fn route_resolution_rejects_missing_default_lane() {
    use iroha_data_model::nexus::DataSpaceMetadata;
    let (alice_id, alice_keypair) = gen_account_in("wonderland");
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::new(9),
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: vec![LaneRoutingRule {
            lane: LaneId::new(11),
            dataspace: None,
            matcher: LaneRoutingMatcher {
                account: Some(alice_id.to_string()),
                instruction: None,
                description: None,
            },
        }],
    };
    let catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: DataSpaceId::new(7),
            alias: "alpha".to_string(),
            description: None,
            fault_tolerance: 1,
        },
        DataSpaceMetadata {
            id: DataSpaceId::new(9),
            alias: "beta".to_string(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("valid dataspace catalog");
    let lane_catalog = catalog_with_lane_dataspaces(&[
        (LaneId::new(2), DataSpaceId::new(7)),
        (LaneId::new(4), DataSpaceId::new(9)),
    ]);
    let router = ConfigLaneRouter::new(policy, catalog.clone(), lane_catalog.clone());
    let state = blank_state();
    install_synthetic_router_nexus(&state, &router);
    let tx = sample_transaction(
        &alice_id,
        alice_keypair.private_key(),
        vec![InstructionBox::from(Register::domain(Domain::new(
            DomainId::try_new("fallback", "universal").expect("domain"),
        )))],
    );
    let direct_err = router
        .try_route_with_view(&tx, &state.view())
        .expect_err("missing default lane must not fall back to the universal route");
    assert!(matches!(
        direct_err,
        RoutingResolveError::UnknownLane { .. }
    ));
    let helper_err =
        evaluate_policy_with_catalog(router.policy.as_ref(), &lane_catalog, &catalog, &tx)
            .expect_err("missing default lane must be rejected");
    assert!(matches!(
        helper_err,
        RoutingResolveError::UnknownLane { .. }
    ));
}
#[test]
fn route_resolution_rejects_missing_default_dataspace() {
    use iroha_data_model::nexus::DataSpaceMetadata;
    let (alice_id, alice_keypair) = gen_account_in("wonderland");
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::SINGLE,
        default_dataspace: DataSpaceId::new(11),
        rules: vec![LaneRoutingRule {
            lane: LaneId::SINGLE,
            dataspace: None,
            matcher: LaneRoutingMatcher {
                account: Some(alice_id.to_string()),
                instruction: None,
                description: None,
            },
        }],
    };
    let catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
        id: DataSpaceId::new(7),
        alias: "alpha".to_string(),
        description: None,
        fault_tolerance: 1,
    }])
    .expect("valid dataspace catalog");
    let lane_catalog = catalog_with_lane_dataspaces(&[(LaneId::SINGLE, DataSpaceId::new(9))]);
    let router = ConfigLaneRouter::new(policy, catalog.clone(), lane_catalog.clone());
    let tx = sample_transaction(
        &alice_id,
        alice_keypair.private_key(),
        vec![InstructionBox::from(Log::new(
            iroha_logger::Level::INFO,
            "default dataspace".into(),
        ))],
    );
    let state = blank_state();
    install_synthetic_router_nexus(&state, &router);
    let direct_err = router
        .try_route_with_view(&tx, &state.view())
        .expect_err("missing default dataspace must not fall back to the universal route");
    crate::queue::router::assert_completed_routing_error_eq(
        &(direct_err),
        &(RoutingResolveError::UnknownDataspace {
            dataspace_id: DataSpaceId::new(11),
        }),
        format_args!("same completed routing verdict"),
    );
    let helper_err =
        evaluate_policy_with_catalog(router.policy.as_ref(), &lane_catalog, &catalog, &tx)
            .expect_err("missing default dataspace must be rejected");
    crate::queue::router::assert_completed_routing_error_eq(
        &(helper_err),
        &(RoutingResolveError::UnknownDataspace {
            dataspace_id: DataSpaceId::new(11),
        }),
        format_args!("same completed routing verdict"),
    );
}
#[test]
fn route_resolution_rejects_unknown_dataspace_on_default_public_lane() {
    let dynamic_dataspace = DataSpaceId::new(4_242);
    let lane_catalog = catalog_with_lane_dataspaces(&[(LaneId::SINGLE, DataSpaceId::UNIVERSAL)]);
    let catalog = dataspace_catalog(&[]);
    let err = resolve_routing_decision(
        RoutingDecision::new(LaneId::SINGLE, dynamic_dataspace),
        &lane_catalog,
        &catalog,
    )
    .expect_err("unknown dataspaces must not use the universal lane");
    assert!(matches!(
        err,
        RoutingResolveError::UnknownDataspace { dataspace_id }
            if dataspace_id == dynamic_dataspace
    ));
}
#[test]
fn route_resolution_rejects_unknown_dataspace_on_non_default_universal_lane() {
    let dynamic_dataspace = DataSpaceId::new(4_242);
    let lane_catalog = catalog_with_lane_dataspaces(&[(LaneId::new(2), DataSpaceId::UNIVERSAL)]);
    let catalog = dataspace_catalog(&[]);
    let err = resolve_routing_decision(
        RoutingDecision::new(LaneId::new(2), dynamic_dataspace),
        &lane_catalog,
        &catalog,
    )
    .expect_err("non-default universal lanes must not accept unknown dataspaces");
    assert!(matches!(
        err,
        RoutingResolveError::UnknownDataspace { dataspace_id }
            if dataspace_id == dynamic_dataspace
    ));
}
#[test]
fn route_resolution_rejects_dynamic_dataspace_on_dataspace_scoped_lane() {
    let configured_dataspace = DataSpaceId::new(7);
    let dynamic_dataspace = DataSpaceId::new(4_242);
    let lane_catalog = catalog_with_lane_dataspaces(&[(LaneId::SINGLE, configured_dataspace)]);
    let catalog = dataspace_catalog(&[(configured_dataspace, "configured")]);
    let err = resolve_routing_decision(
        RoutingDecision::new(LaneId::SINGLE, dynamic_dataspace),
        &lane_catalog,
        &catalog,
    )
    .expect_err("dataspace-scoped lanes must not accept unknown dataspaces");
    assert!(matches!(
        err,
        RoutingResolveError::UnknownDataspace { dataspace_id }
            if dataspace_id == dynamic_dataspace
    ));
}
#[test]
fn route_resolution_rejects_universal_when_catalog_omits_universal() {
    let lane_catalog = catalog_with_lane_dataspaces(&[(LaneId::SINGLE, DataSpaceId::UNIVERSAL)]);
    let catalog = DataSpaceCatalog::new(vec![iroha_data_model::nexus::DataSpaceMetadata {
        id: DataSpaceId::new(7),
        alias: "configured".to_owned(),
        description: None,
        fault_tolerance: 1,
    }])
    .expect("catalog without universal");
    let err = resolve_routing_decision(
        RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        &lane_catalog,
        &catalog,
    )
    .expect_err("reserved universal dataspace still needs a catalog entry");
    assert!(matches!(
        err,
        RoutingResolveError::UnknownDataspace { dataspace_id }
            if dataspace_id == DataSpaceId::UNIVERSAL
    ));
}
#[test]
fn dataspace_alias_target_with_world_resolves_active_sns_dataspace() {
    let (authority_id, _) = gen_account_in("wonderland");
    let catalog = dataspace_catalog(&[]);
    let world = world_with_dynamic_dataspace("alpha", &authority_id);
    let view = world.view();
    let expected = crate::sns::dataspace_id_for_sns_alias("alpha").expect("dynamic id");
    assert_eq!(
        (dataspace_alias_target_with_world("alpha", Some(&catalog), &view, Some(0)))
            .as_ref()
            .expect("the operation must complete successfully"),
        &(Some(expected))
    );
    assert_eq!(
        (dataspace_alias_target_with_world("missing", Some(&catalog), &view, Some(0)))
            .as_ref()
            .expect("the operation must complete successfully"),
        &(None)
    );
    assert_eq!(
        (dataspace_alias_target_with_world("alpha", Some(&catalog), &view, None))
            .as_ref()
            .expect("the operation must complete successfully"),
        &(None)
    );
}
#[test]
fn dataspace_alias_target_with_world_rejects_inactive_sns_dataspace_at_ledger_time() {
    let (authority_id, _) = gen_account_in("wonderland");
    let catalog = dataspace_catalog(&[]);
    let world = world_with_dynamic_dataspace_until("alpha", &authority_id, 10);
    let view = world.view();
    let expected = crate::sns::dataspace_id_for_sns_alias("alpha").expect("dynamic id");
    assert_eq!(
        (dataspace_alias_target_with_world("alpha", Some(&catalog), &view, Some(9)))
            .as_ref()
            .expect("the operation must complete successfully"),
        &(Some(expected))
    );
    assert_eq!(
        (dataspace_alias_target_with_world("alpha", Some(&catalog), &view, Some(10)))
            .as_ref()
            .expect("the operation must complete successfully"),
        &(None)
    );
}
#[test]
fn dataspace_alias_target_with_world_fails_closed_on_active_static_conflict() {
    let (authority_id, _) = gen_account_in("wonderland");
    let static_dataspace = DataSpaceId::new(7);
    let dynamic_dataspace = crate::sns::dataspace_id_for_sns_alias("alpha").expect("dynamic id");
    assert_ne!(static_dataspace, dynamic_dataspace);
    let conflicting_catalog = dataspace_catalog(&[(static_dataspace, "alpha")]);
    let matching_catalog = dataspace_catalog(&[(dynamic_dataspace, "alpha")]);
    let world = world_with_dynamic_dataspace_until("alpha", &authority_id, 10);
    let view = world.view();

    let error =
        dataspace_alias_target_with_world("alpha", Some(&conflicting_catalog), &view, Some(9))
            .expect_err("active SNS/static disagreement must fail closed");
    assert!(matches!(
        error,
        RoutingResolveError::DataspaceAliasResolution { alias, reason }
            if alias == "alpha"
                && reason.contains(crate::sns::ALIAS_CATALOG_MAPPING_CONFLICT_CODE)
    ));
    assert_eq!(
        (dataspace_alias_target_with_world("alpha", Some(&conflicting_catalog), &view, Some(10),))
            .as_ref()
            .expect("the operation must complete successfully"),
        &(Some(static_dataspace)),
        "an inactive SNS lease legitimately falls back to the static catalog"
    );
    assert_eq!(
        (dataspace_alias_target_with_world("alpha", Some(&conflicting_catalog), &view, None,))
            .as_ref()
            .expect("the operation must complete successfully"),
        &(Some(static_dataspace)),
        "routing without ledger time remains explicitly static-only"
    );
    assert_eq!(
        (dataspace_alias_target_with_world("alpha", Some(&matching_catalog), &view, Some(9),))
            .as_ref()
            .expect("the operation must complete successfully"),
        &(Some(dynamic_dataspace)),
        "matching active SNS and static evidence resolves normally"
    );
}
#[test]
fn domain_alias_routing_propagates_malformed_dynamic_sns_record() {
    let (authority_id, authority_keypair) = gen_account_in("wonderland");
    let catalog = dataspace_catalog(&[]);
    let lane_catalog = catalog_with_lane_dataspaces(&[(LaneId::SINGLE, DataSpaceId::UNIVERSAL)]);
    let router = default_router(catalog, lane_catalog);
    let selector = crate::sns::selector_for_dataspace_alias("alpha").expect("selector");
    let mut world = crate::state::World::default();
    world
        .smart_contract_state_mut_for_testing()
        .insert(crate::sns::record_storage_key(&selector), vec![0xFF]);
    let mut state = state_from_world(world);
    install_router_nexus(&mut state, &router);
    let tx = sample_transaction(
        &authority_id,
        authority_keypair.private_key(),
        vec![InstructionBox::from(Register::domain(Domain::new(
            DomainId::try_new("merchant", "alpha").expect("domain"),
        )))],
    );

    assert_eq!(
        (router.try_route_plan_without_state(&tx))
            .as_ref()
            .expect("the operation must complete successfully"),
        &(None)
    );
    let queue_error = router
        .try_route_plan_with_state(&tx, &state)
        .expect_err("queue routing must reject malformed authoritative SNS state");
    let view = state.view();
    let block_error = evaluate_policy_plan_with_nexus_and_world_at(
        view.nexus(),
        &tx,
        view.world(),
        state_view_ledger_time_ms(&view),
    )
    .expect_err("block routing must reject the same malformed SNS state");
    crate::queue::router::assert_completed_routing_error_eq(
        &(queue_error),
        &(block_error),
        format_args!("same completed routing verdict"),
    );
    assert!(matches!(
        queue_error,
        RoutingResolveError::DataspaceAliasResolution { alias, reason }
            if alias == "alpha" && reason.contains("failed to decode an SNS record")
    ));
}
#[test]
fn domain_alias_routing_defers_without_state_and_matches_block_conflict() {
    let (authority_id, authority_keypair) = gen_account_in("wonderland");
    let static_dataspace = DataSpaceId::new(7);
    let dynamic_dataspace = crate::sns::dataspace_id_for_sns_alias("alpha").expect("dynamic id");
    assert_ne!(static_dataspace, dynamic_dataspace);
    let static_lane = LaneId::new(2);
    let catalog = dataspace_catalog(&[(static_dataspace, "alpha")]);
    let lane_catalog = catalog_with_lane_dataspaces(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (static_lane, static_dataspace),
    ]);
    let router = default_router(catalog, lane_catalog);
    let tx = sample_transaction(
        &authority_id,
        authority_keypair.private_key(),
        vec![InstructionBox::from(Register::domain(Domain::new(
            DomainId::try_new("merchant", "alpha").expect("domain"),
        )))],
    );

    assert_eq!(
        (router.try_route_plan_without_state(&tx))
            .as_ref()
            .expect("the operation must complete successfully"),
        &(None)
    );

    let mut static_state = blank_state();
    install_router_nexus(&mut static_state, &router);
    assert_eq!(
        router
            .try_route_plan_with_state(&tx, &static_state)
            .expect("static-only state should resolve"),
        RoutingPlan::single(RoutingDecision::new(static_lane, static_dataspace))
    );

    let mut conflicting_state =
        state_from_world(world_with_dynamic_dataspace("alpha", &authority_id));
    install_router_nexus(&mut conflicting_state, &router);
    let queue_error = router
        .try_route_plan_with_state(&tx, &conflicting_state)
        .expect_err("queue routing must reject active SNS/static disagreement");
    let view = conflicting_state.view();
    let block_error = evaluate_policy_plan_with_nexus_and_world_at(
        view.nexus(),
        &tx,
        view.world(),
        state_view_ledger_time_ms(&view),
    )
    .expect_err("block routing must reject the same disagreement");
    crate::queue::router::assert_completed_routing_error_eq(
        &(queue_error),
        &(block_error),
        format_args!("same completed routing verdict"),
    );
    assert!(matches!(
        queue_error,
        RoutingResolveError::DataspaceAliasResolution { alias, reason }
            if alias == "alpha"
                && reason.contains(crate::sns::ALIAS_CATALOG_MAPPING_CONFLICT_CODE)
    ));
}
#[test]
fn evaluate_policy_with_catalog_and_world_resolves_static_alias_without_ledger_time() {
    let (authority_id, authority_keypair) = gen_account_in("wonderland");
    let static_dataspace = DataSpaceId::new(7);
    let catalog = dataspace_catalog(&[(static_dataspace, "alpha")]);
    let lane_catalog = catalog_with_lane_dataspaces(&[(LaneId::SINGLE, static_dataspace)]);
    let policy = default_routing_policy();
    let tx = sample_transaction(
        &authority_id,
        authority_keypair.private_key(),
        vec![InstructionBox::from(Register::domain(Domain::new(
            DomainId::try_new("static", "alpha").expect("domain"),
        )))],
    );
    let world = crate::state::World::default();
    let view = world.view();
    assert_eq!(
        evaluate_policy_with_catalog_and_world(&policy, &lane_catalog, &catalog, &tx, &view)
            .expect("static alias should resolve without a ledger time"),
        RoutingDecision::new(LaneId::SINGLE, static_dataspace)
    );
}
#[test]
fn evaluate_policy_with_catalog_and_world_at_rejects_dynamic_sns_outside_catalog() {
    let (authority_id, authority_keypair) = gen_account_in("wonderland");
    let catalog = dataspace_catalog(&[]);
    let lane_catalog = catalog_with_lane_dataspaces(&[(LaneId::SINGLE, DataSpaceId::UNIVERSAL)]);
    let policy = default_routing_policy();
    let tx = sample_transaction(
        &authority_id,
        authority_keypair.private_key(),
        vec![InstructionBox::from(Register::domain(Domain::new(
            DomainId::try_new("dynamic", "alpha").expect("domain"),
        )))],
    );
    let world = world_with_dynamic_dataspace_until("alpha", &authority_id, 10);
    let view = world.view();
    let expected = crate::sns::dataspace_id_for_sns_alias("alpha").expect("dynamic id");
    // An active SNS alias resolves identity without admitting physical dataspace authority.
    crate::queue::router::assert_completed_routing_error_eq(
        (evaluate_policy_with_catalog_and_world_at(
            &policy,
            &lane_catalog,
            &catalog,
            &tx,
            &view,
            9,
        ))
        .as_ref()
        .expect_err("expected completed routing rejection"),
        &(RoutingResolveError::UnknownDataspace {
            dataspace_id: expected,
        }),
        format_args!("completed routing rejection"),
    );
    assert_eq!(
        evaluate_policy_with_catalog_and_world_at(
            &policy,
            &lane_catalog,
            &catalog,
            &tx,
            &view,
            10,
        )
        .expect("inactive dynamic route should fall back to default"),
        RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
    );
    assert_eq!(
        evaluate_policy_with_catalog_and_world(&policy, &lane_catalog, &catalog, &tx, &view)
            .expect("no-time world route should fall back to static catalog only"),
        RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
    );
}
#[test]
fn evaluate_policy_plan_with_catalog_and_world_at_rejects_dynamic_sns_outside_catalog() {
    let (authority_id, authority_keypair) = gen_account_in("wonderland");
    let catalog = dataspace_catalog(&[]);
    let lane_catalog = catalog_with_lane_dataspaces(&[(LaneId::SINGLE, DataSpaceId::UNIVERSAL)]);
    let policy = default_routing_policy();
    let tx = sample_transaction(
        &authority_id,
        authority_keypair.private_key(),
        vec![InstructionBox::from(Register::domain(Domain::new(
            DomainId::try_new("dynamic", "alpha").expect("domain"),
        )))],
    );
    let world = world_with_dynamic_dataspace_until("alpha", &authority_id, 10);
    let view = world.view();
    let expected = crate::sns::dataspace_id_for_sns_alias("alpha").expect("dynamic id");
    // An active SNS alias resolves identity without admitting physical dataspace authority.
    crate::queue::router::assert_completed_routing_error_eq(
        (evaluate_policy_plan_with_catalog_and_world_at(
            &policy,
            &lane_catalog,
            &catalog,
            &tx,
            &view,
            9,
        ))
        .as_ref()
        .expect_err("expected completed routing rejection"),
        &(RoutingResolveError::UnknownDataspace {
            dataspace_id: expected,
        }),
        format_args!("completed routing rejection"),
    );
    assert_eq!(
        evaluate_policy_plan_with_catalog_and_world_at(
            &policy,
            &lane_catalog,
            &catalog,
            &tx,
            &view,
            10,
        )
        .expect("inactive dynamic plan should fall back to default"),
        RoutingPlan::single(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL))
    );
    assert_eq!(
        evaluate_policy_plan_with_catalog_and_world(&policy, &lane_catalog, &catalog, &tx, &view)
            .expect("no-time world plan should fall back to static catalog only"),
        RoutingPlan::single(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL))
    );
}
