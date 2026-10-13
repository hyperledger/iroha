#[test]
fn known_opaque_global_asset_without_home_alias_routes_to_universal() {
    let (sender_id, sender_keypair) = gen_account_in("wonderland");
    let (receiver_id, _) = gen_account_in("wonderland");
    let (dataspace_id, _lane_id, dataspace_catalog, lane_catalog, router) =
        routed_dataspace_fixture("paynet");
    let transparent_asset_definition =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "paynet").expect("asset definition domain"),
            "xor".parse().expect("asset definition name"),
        );
    let opaque_asset_definition =
        AssetDefinitionId::parse_address_literal(&transparent_asset_definition.canonical_address())
            .expect("opaque canonical asset definition id");
    let transfer = Transfer::asset_quantity(
        AssetId::of(opaque_asset_definition.clone(), sender_id.clone()),
        1_u32,
        receiver_id,
    );
    let tx = sample_transaction(
        &sender_id,
        sender_keypair.private_key(),
        vec![InstructionBox::from(transfer)],
    );
    let mut scope_entry = crate::nexus::space_directory::AccountScopeDirectoryEntry::default();
    scope_entry.ensure_dataspace(dataspace_id);
    let mut state = state_with_asset_definitions(
        vec![
            AssetDefinition::numeric(
                opaque_asset_definition,
                "xor".to_owned(),
                AssetBalancePolicy::Global,
                None,
            )
            .build(&sender_id),
        ],
        dataspace_catalog,
        lane_catalog,
    );
    state
        .world
        .account_scope_directory
        .insert(sender_id.clone(), scope_entry);
    assert_eq!(
        router
            .try_route_with_view(&tx, &state.view())
            .expect("known global asset route must resolve"),
        RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
    );
}

#[test]
fn known_opaque_global_asset_mint_without_home_alias_routes_to_universal() {
    let (sender_id, sender_keypair) = gen_account_in("wonderland");
    let (dataspace_id, _lane_id, dataspace_catalog, lane_catalog, router) =
        routed_dataspace_fixture("paynet");
    let transparent_asset_definition =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "paynet").expect("asset definition domain"),
            "xor".parse().expect("asset definition name"),
        );
    let opaque_asset_definition =
        AssetDefinitionId::parse_address_literal(&transparent_asset_definition.canonical_address())
            .expect("opaque canonical asset definition id");
    let tx = sample_transaction(
        &sender_id,
        sender_keypair.private_key(),
        vec![InstructionBox::from(Mint::asset_quantity(
            1_u32,
            AssetId::of(opaque_asset_definition.clone(), sender_id.clone()),
        ))],
    );
    let mut scope_entry = crate::nexus::space_directory::AccountScopeDirectoryEntry::default();
    scope_entry.ensure_dataspace(dataspace_id);
    let mut state = state_with_asset_definitions(
        vec![
            AssetDefinition::numeric(
                opaque_asset_definition,
                "xor".to_owned(),
                AssetBalancePolicy::Global,
                None,
            )
            .build(&sender_id),
        ],
        dataspace_catalog,
        lane_catalog,
    );
    state
        .world
        .account_scope_directory
        .insert(sender_id.clone(), scope_entry);
    assert_eq!(
        router
            .try_route_with_state(&tx, &state)
            .expect("known opaque global mint must use state-aware routing"),
        RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
    );
}

#[test]
fn known_opaque_global_asset_mint_with_stored_private_home_alias_routes_to_universal() {
    let (sender_id, sender_keypair) = gen_account_in("wonderland");
    let (_dataspace_id, _lane_id, dataspace_catalog, lane_catalog, router) =
        routed_dataspace_fixture("paynet");
    let transparent_asset_definition =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "paynet").expect("asset definition domain"),
            "xor".parse().expect("asset definition name"),
        );
    let opaque_asset_definition =
        AssetDefinitionId::parse_address_literal(&transparent_asset_definition.canonical_address())
            .expect("opaque canonical asset definition id");
    let tx = sample_transaction(
        &sender_id,
        sender_keypair.private_key(),
        vec![InstructionBox::from(Mint::asset_quantity(
            1_u32,
            AssetId::of(opaque_asset_definition.clone(), sender_id.clone()),
        ))],
    );
    let alias: AssetDefinitionAlias = "xor#paynet".parse().expect("asset alias");
    let mut state = state_with_asset_definitions(
        vec![
            AssetDefinition::numeric(
                opaque_asset_definition.clone(),
                "xor".to_owned(),
                AssetBalancePolicy::Global,
                None,
            )
            .build(&sender_id),
        ],
        dataspace_catalog,
        lane_catalog,
    );
    state
        .world
        .asset_definition_aliases
        .insert(alias.clone(), opaque_asset_definition.clone());
    state.world.asset_definition_alias_bindings.insert(
        opaque_asset_definition,
        crate::state::AssetDefinitionAliasBindingRecord {
            alias,
            lease_expiry_ms: None,
            grace_until_ms: None,
            bound_at_ms: 0,
        },
    );
    assert_eq!(
        router
            .try_route_without_state(&tx)
            .expect("known opaque global mint should defer to state"),
        None
    );
    assert_eq!(
        router
            .try_route_with_state(&tx, &state)
            .expect("global mint must ignore the stored private home alias"),
        RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
    );
}
#[test]
fn known_opaque_global_asset_mint_ignores_authority_account_rule_override() {
    let (sender_id, sender_keypair) = gen_account_in("wonderland");
    let dataspace_id = DataSpaceId::new(10);
    let lane_id = LaneId::new(2);
    let dataspace_catalog = dataspace_catalog(&[(dataspace_id, "paynet")]);
    let lane_catalog = catalog_with_lane_dataspaces(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (lane_id, dataspace_id),
    ]);
    let router = ConfigLaneRouter::new(
        LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![LaneRoutingRule {
                lane: lane_id,
                dataspace: Some(dataspace_id),
                matcher: LaneRoutingMatcher {
                    account: Some(sender_id.to_string()),
                    instruction: None,
                    description: None,
                },
            }],
        },
        dataspace_catalog.clone(),
        lane_catalog.clone(),
    );
    let transparent_asset_definition =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "paynet").expect("asset definition domain"),
            "xor".parse().expect("asset definition name"),
        );
    let opaque_asset_definition =
        AssetDefinitionId::parse_address_literal(&transparent_asset_definition.canonical_address())
            .expect("opaque canonical asset definition id");
    let tx = sample_transaction(
        &sender_id,
        sender_keypair.private_key(),
        vec![InstructionBox::from(Mint::asset_quantity(
            1_u32,
            AssetId::of(opaque_asset_definition.clone(), sender_id.clone()),
        ))],
    );
    let mut scope_entry = crate::nexus::space_directory::AccountScopeDirectoryEntry::default();
    scope_entry.ensure_dataspace(dataspace_id);
    let mut state = state_with_asset_definitions(
        vec![
            AssetDefinition::numeric(
                opaque_asset_definition,
                "xor".to_owned(),
                AssetBalancePolicy::Global,
                None,
            )
            .build(&sender_id),
        ],
        dataspace_catalog,
        lane_catalog,
    );
    state
        .world
        .account_scope_directory
        .insert(sender_id.clone(), scope_entry);
    assert_eq!(
        router
            .try_route_without_state(&tx)
            .expect("known opaque global mint should defer to state"),
        None
    );
    assert_eq!(
        router
            .try_route_with_state(&tx, &state)
            .expect("global mint must not route to the authority account dataspace"),
        RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
    );
    assert_eq!(
        router
            .try_route_plan_with_view(&tx, &state.view())
            .expect("global mint plan must keep the universal coordinator")
            .coordinator_route(),
        RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
    );
}
#[test]
fn known_opaque_global_asset_transfer_ignores_authority_account_rule_override() {
    let (sender_id, sender_keypair) = gen_account_in("wonderland");
    let (receiver_id, _) = gen_account_in("wonderland");
    let dataspace_id = DataSpaceId::new(10);
    let lane_id = LaneId::new(2);
    let dataspace_catalog = dataspace_catalog(&[(dataspace_id, "paynet")]);
    let lane_catalog = catalog_with_lane_dataspaces(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (lane_id, dataspace_id),
    ]);
    let router = ConfigLaneRouter::new(
        LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![LaneRoutingRule {
                lane: lane_id,
                dataspace: Some(dataspace_id),
                matcher: LaneRoutingMatcher {
                    account: Some(sender_id.to_string()),
                    instruction: None,
                    description: None,
                },
            }],
        },
        dataspace_catalog.clone(),
        lane_catalog.clone(),
    );
    let transparent_asset_definition =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "paynet").expect("asset definition domain"),
            "xor".parse().expect("asset definition name"),
        );
    let opaque_asset_definition =
        AssetDefinitionId::parse_address_literal(&transparent_asset_definition.canonical_address())
            .expect("opaque canonical asset definition id");
    let tx = sample_transaction(
        &sender_id,
        sender_keypair.private_key(),
        vec![InstructionBox::from(Transfer::asset_quantity(
            AssetId::of(opaque_asset_definition.clone(), sender_id.clone()),
            1_u32,
            receiver_id,
        ))],
    );
    let mut scope_entry = crate::nexus::space_directory::AccountScopeDirectoryEntry::default();
    scope_entry.ensure_dataspace(dataspace_id);
    let mut state = state_with_asset_definitions(
        vec![
            AssetDefinition::numeric(
                opaque_asset_definition,
                "xor".to_owned(),
                AssetBalancePolicy::Global,
                None,
            )
            .build(&sender_id),
        ],
        dataspace_catalog,
        lane_catalog,
    );
    state
        .world
        .account_scope_directory
        .insert(sender_id.clone(), scope_entry);
    assert_eq!(
        router
            .try_route_without_state(&tx)
            .expect("known opaque global transfer should defer to state"),
        None
    );
    assert_eq!(
        router
            .try_route_with_state(&tx, &state)
            .expect("global transfer must not route to the authority account dataspace"),
        RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
    );
    assert_eq!(
        router
            .try_route_plan_with_view(&tx, &state.view())
            .expect("global transfer plan must keep the universal coordinator")
            .coordinator_route(),
        RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
    );
}
#[test]
fn known_opaque_global_asset_burn_ignores_authority_account_rule_override() {
    let (sender_id, sender_keypair) = gen_account_in("wonderland");
    let dataspace_id = DataSpaceId::new(10);
    let lane_id = LaneId::new(2);
    let dataspace_catalog = dataspace_catalog(&[(dataspace_id, "paynet")]);
    let lane_catalog = catalog_with_lane_dataspaces(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (lane_id, dataspace_id),
    ]);
    let router = ConfigLaneRouter::new(
        LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![LaneRoutingRule {
                lane: lane_id,
                dataspace: Some(dataspace_id),
                matcher: LaneRoutingMatcher {
                    account: Some(sender_id.to_string()),
                    instruction: None,
                    description: None,
                },
            }],
        },
        dataspace_catalog.clone(),
        lane_catalog.clone(),
    );
    let transparent_asset_definition =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "paynet").expect("asset definition domain"),
            "xor".parse().expect("asset definition name"),
        );
    let opaque_asset_definition =
        AssetDefinitionId::parse_address_literal(&transparent_asset_definition.canonical_address())
            .expect("opaque canonical asset definition id");
    let tx = sample_transaction(
        &sender_id,
        sender_keypair.private_key(),
        vec![InstructionBox::from(Burn::asset_quantity(
            1_u32,
            AssetId::of(opaque_asset_definition.clone(), sender_id.clone()),
        ))],
    );
    let mut scope_entry = crate::nexus::space_directory::AccountScopeDirectoryEntry::default();
    scope_entry.ensure_dataspace(dataspace_id);
    let mut state = state_with_asset_definitions(
        vec![
            AssetDefinition::numeric(
                opaque_asset_definition,
                "xor".to_owned(),
                AssetBalancePolicy::Global,
                None,
            )
            .build(&sender_id),
        ],
        dataspace_catalog,
        lane_catalog,
    );
    state
        .world
        .account_scope_directory
        .insert(sender_id.clone(), scope_entry);
    assert_eq!(
        router
            .try_route_without_state(&tx)
            .expect("known opaque global burn should defer to state"),
        None
    );
    assert_eq!(
        router
            .try_route_with_state(&tx, &state)
            .expect("global burn must not route to the authority account dataspace"),
        RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
    );
    assert_eq!(
        router
            .try_route_plan_with_view(&tx, &state.view())
            .expect("global burn plan must keep the universal coordinator")
            .coordinator_route(),
        RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
    );
}
#[test]
fn opaque_asset_transfer_rejects_dataspace_without_canonical_lane() {
    let (sender_id, sender_keypair) = gen_account_in("wonderland");
    let (receiver_id, _) = gen_account_in("wonderland");
    let dataspace_id = DataSpaceId::new(10);
    let dataspace_catalog = dataspace_catalog(&[(dataspace_id, "paynet")]);
    let lane_catalog = catalog_with_lane_dataspaces(&[(LaneId::SINGLE, DataSpaceId::UNIVERSAL)]);
    let router = default_router(dataspace_catalog.clone(), lane_catalog.clone());
    let transparent_asset_definition =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "universal").expect("asset definition domain"),
            "pkr".parse().expect("asset definition name"),
        );
    let opaque_asset_definition =
        AssetDefinitionId::parse_address_literal(&transparent_asset_definition.canonical_address())
            .expect("opaque canonical asset definition id");
    let transfer = Transfer::asset_quantity(
        AssetId::of(opaque_asset_definition.clone(), sender_id.clone()),
        1_u32,
        receiver_id,
    );
    let tx = sample_transaction(
        &sender_id,
        sender_keypair.private_key(),
        vec![InstructionBox::from(transfer)],
    );
    let alias: iroha_data_model::asset::AssetDefinitionAlias =
        "pkr#paynet".parse().expect("asset alias");
    let owning_domain = DomainId::try_new("cash", "paynet").expect("owning domain");
    let mut state = state_with_asset_definitions(
        vec![
            AssetDefinition::numeric(
                opaque_asset_definition.clone(),
                "pkr".to_owned(),
                AssetBalancePolicy::DataspaceRestricted,
                Some(owning_domain),
            )
            .build(&sender_id),
        ],
        dataspace_catalog,
        lane_catalog,
    );
    state
        .world
        .asset_definition_aliases
        .insert(alias.clone(), opaque_asset_definition.clone());
    state.world.asset_definition_alias_bindings.insert(
        opaque_asset_definition,
        crate::state::AssetDefinitionAliasBindingRecord {
            alias,
            lease_expiry_ms: None,
            grace_until_ms: None,
            bound_at_ms: 0,
        },
    );
    crate::queue::router::assert_completed_routing_error_eq(
        (router.try_route_with_view(&tx, &state.view()))
            .as_ref()
            .expect_err("expected completed routing rejection"),
        &(RoutingResolveError::NoLaneForDataspace { dataspace_id }),
        format_args!("completed routing rejection"),
    );
}
#[test]
fn opaque_asset_transfer_routes_to_sender_single_scope_when_asset_definition_unresolved() {
    let (sender_id, sender_keypair) = gen_account_in("wonderland");
    let (receiver_id, _) = gen_account_in("wonderland");
    let (dataspace_id, lane_id, dataspace_catalog, lane_catalog, router) =
        routed_dataspace_fixture("paynet");
    let transparent_asset_definition =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("cash", "paynet").expect("asset definition domain"),
            "pkr".parse().expect("asset definition name"),
        );
    let opaque_asset_definition =
        AssetDefinitionId::parse_address_literal(&transparent_asset_definition.canonical_address())
            .expect("opaque canonical asset definition id");
    let transfer = Transfer::asset_quantity(
        AssetId::of(opaque_asset_definition, sender_id.clone()),
        1_u32,
        receiver_id,
    );
    let tx = sample_transaction(
        &sender_id,
        sender_keypair.private_key(),
        vec![InstructionBox::from(transfer)],
    );
    let mut scope_entry = crate::nexus::space_directory::AccountScopeDirectoryEntry::default();
    scope_entry.ensure_dataspace(dataspace_id);
    let mut state =
        state_with_account_scope_entries(&[(sender_id.clone(), scope_entry)], dataspace_catalog);
    install_router_lane_catalog(&mut state, lane_catalog);
    assert_eq!(
        router
            .try_route_without_state(&tx)
            .expect("opaque asset transfer should defer to state"),
        None
    );
    assert_eq!(
        router
            .try_route_with_view(&tx, &state.view())
            .expect("opaque asset transfer should fall back to sender account scope"),
        RoutingDecision::new(lane_id, dataspace_id)
    );
}
