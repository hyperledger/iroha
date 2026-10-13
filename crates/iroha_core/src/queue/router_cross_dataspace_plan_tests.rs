#[test]
fn opaque_asset_transfer_with_universal_and_private_account_scope_uses_default_route() {
    let (sender_id, sender_keypair) = gen_account_in("wonderland");
    let (receiver_id, _) = gen_account_in("wonderland");
    let uaid = UniversalAccountId::from_hash(Hash::new(b"router::uaid-bound-sender"));
    let (dataspace_id, _lane_id, dataspace_catalog, lane_catalog, router) =
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
    let mut state = blank_state();
    state.set_dataspace_catalog_for_testing(dataspace_catalog);
    install_router_lane_catalog(&mut state, lane_catalog);
    let sender = Account::new(sender_id.clone())
        .with_uaid(Some(uaid))
        .build(&sender_id);
    let (account_id, account_value) = sender.into_key_value();
    state
        .world
        .accounts
        .insert(account_id.clone(), account_value);
    let mut scope_entry = crate::nexus::space_directory::AccountScopeDirectoryEntry::default();
    scope_entry.ensure_dataspace(DataSpaceId::UNIVERSAL);
    scope_entry.ensure_dataspace(dataspace_id);
    state
        .world
        .account_scope_directory
        .insert(account_id.clone(), scope_entry);
    let mut bindings = crate::nexus::space_directory::UaidDataspaceBindings::default();
    bindings.bind_account(dataspace_id, account_id);
    state.world.uaid_dataspaces.insert(uaid, bindings);
    assert_eq!(
        router
            .try_route_without_state(&tx)
            .expect("opaque asset transfer should defer to state"),
        None
    );
    assert_eq!(
        router
            .try_route_with_view(&tx, &state.view())
            .expect("ambiguous account scope should use the default route"),
        RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
    );
}

#[test]
fn strict_scoped_permission_decision_apis_match_full_plan_rejection() {
    let (authority_id, authority_keypair) = gen_account_in("wonderland");
    let permission_dataspace = DataSpaceId::new(7);
    let ordinary_dataspace = DataSpaceId::new(8);
    let dataspace_catalog = dataspace_catalog(&[
        (permission_dataspace, "permission"),
        (ordinary_dataspace, "ordinary"),
    ]);
    let lane_catalog = catalog_with_lane_dataspaces(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (LaneId::new(2), permission_dataspace),
        (LaneId::new(3), ordinary_dataspace),
    ]);
    let policy = default_routing_policy();
    let router = ConfigLaneRouter::new(
        policy.clone(),
        dataspace_catalog.clone(),
        lane_catalog.clone(),
    );
    let mut metadata = Metadata::default();
    metadata.insert(
        AMX_POLICY_METADATA_KEY.parse().expect("amx policy key"),
        iroha_primitives::json::Json::new(AMX_POLICY_REJECT_CROSS_DATASPACE),
    );
    let tx = sample_transaction_with_metadata(
        &authority_id,
        authority_keypair.private_key(),
        vec![
            InstructionBox::from(Grant::account_permission(
                CanPublishSpaceDirectoryManifest {
                    dataspace: permission_dataspace,
                },
                authority_id.clone(),
            )),
            InstructionBox::from(Register::domain(Domain::new(
                DomainId::try_new("merchant", "ordinary").expect("domain id"),
            ))),
        ],
        metadata,
    );
    let expected_error = || RoutingResolveError::ConflictingTransactionDataspaceTargets {
        first_dataspace_id: permission_dataspace,
        second_dataspace_id: ordinary_dataspace,
    };

    crate::queue::router::assert_completed_routing_error_eq(
        &(router.try_route(&tx))
            .as_ref()
            .expect_err("expected completed routing rejection"),
        &(expected_error()),
        format_args!("completed routing rejection"),
    );
    crate::queue::router::assert_completed_routing_error_eq(
        &(router.try_route_plan(&tx))
            .as_ref()
            .expect_err("expected completed routing rejection"),
        &(expected_error()),
        format_args!("completed routing rejection"),
    );
    assert_eq!(
        (router.try_route_without_state(&tx))
            .as_ref()
            .expect("the operation must complete successfully"),
        &(None)
    );
    assert_eq!(
        (router.try_route_plan_without_state(&tx))
            .as_ref()
            .expect("the operation must complete successfully"),
        &(None)
    );
    crate::queue::router::assert_completed_routing_error_eq(
        &(evaluate_policy_with_catalog(&policy, &lane_catalog, &dataspace_catalog, &tx))
            .as_ref()
            .expect_err("expected completed routing rejection"),
        &(expected_error()),
        format_args!("completed routing rejection"),
    );
    crate::queue::router::assert_completed_routing_error_eq(
        &(evaluate_policy_plan_with_catalog(&policy, &lane_catalog, &dataspace_catalog, &tx))
            .as_ref()
            .expect_err("expected completed routing rejection"),
        &(expected_error()),
        format_args!("completed routing rejection"),
    );

    let mut state = blank_state();
    install_router_nexus(&mut state, &router);
    let state_view = state.view();
    crate::queue::router::assert_completed_routing_error_eq(
        &(router.try_route_with_view(&tx, &state_view))
            .as_ref()
            .expect_err("expected completed routing rejection"),
        &(expected_error()),
        format_args!("completed routing rejection"),
    );
    crate::queue::router::assert_completed_routing_error_eq(
        &(router.try_route_plan_with_view(&tx, &state_view))
            .as_ref()
            .expect_err("expected completed routing rejection"),
        &(expected_error()),
        format_args!("completed routing rejection"),
    );
    crate::queue::router::assert_completed_routing_error_eq(
        &(evaluate_policy_with_catalog_and_world(
            &policy,
            &lane_catalog,
            &dataspace_catalog,
            &tx,
            state_view.world(),
        ))
        .as_ref()
        .expect_err("expected completed routing rejection"),
        &(expected_error()),
        format_args!("completed routing rejection"),
    );
    crate::queue::router::assert_completed_routing_error_eq(
        &(evaluate_policy_plan_with_catalog_and_world(
            &policy,
            &lane_catalog,
            &dataspace_catalog,
            &tx,
            state_view.world(),
        ))
        .as_ref()
        .expect_err("expected completed routing rejection"),
        &(expected_error()),
        format_args!("completed routing rejection"),
    );
}

#[test]
fn explicit_universal_target_is_not_rewritten_by_authority_account_rule() {
    let (authority_id, authority_keypair) = gen_account_in("wonderland");
    let private_dataspace = DataSpaceId::new(10);
    let private_lane = LaneId::new(2);
    let dataspace_catalog = dataspace_catalog(&[(private_dataspace, "paynet")]);
    let lane_catalog = catalog_with_lane_dataspaces(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (private_lane, private_dataspace),
    ]);
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::SINGLE,
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: vec![LaneRoutingRule {
            lane: private_lane,
            dataspace: Some(private_dataspace),
            matcher: LaneRoutingMatcher {
                account: Some(authority_id.to_string()),
                instruction: None,
                description: None,
            },
        }],
    };
    let router = ConfigLaneRouter::new(
        policy.clone(),
        dataspace_catalog.clone(),
        lane_catalog.clone(),
    );
    let tx = sample_transaction(
        &authority_id,
        authority_keypair.private_key(),
        vec![InstructionBox::from(Register::domain(Domain::new(
            DomainId::try_new("universal-write", "universal").expect("domain id"),
        )))],
    );
    let mut state = state_with_account_scope_entries(
        &[(authority_id, account_scope_entry(private_dataspace))],
        dataspace_catalog.clone(),
    );
    install_router_nexus(&mut state, &router);
    let expected_error = RoutingResolveError::LaneDataspaceMismatch {
        lane_id: private_lane,
        lane_dataspace_id: private_dataspace,
        dataspace_id: DataSpaceId::UNIVERSAL,
    };
    let state_view = state.view();

    crate::queue::router::assert_completed_routing_error_eq(
        (router.try_route_plan_with_view(&tx, &state_view))
            .as_ref()
            .expect_err("expected completed routing rejection"),
        &(expected_error),
        format_args!("completed routing rejection"),
    );
    crate::queue::router::assert_completed_routing_error_eq(
        (router.try_route_with_view(&tx, &state_view))
            .as_ref()
            .expect_err("expected completed routing rejection"),
        &(expected_error),
        format_args!("completed routing rejection"),
    );
    crate::queue::router::assert_completed_routing_error_eq(
        (evaluate_policy_plan_with_catalog_and_world(
            &policy,
            &lane_catalog,
            &dataspace_catalog,
            &tx,
            state_view.world(),
        ))
        .as_ref()
        .expect_err("expected completed routing rejection"),
        &(expected_error),
        format_args!("completed routing rejection"),
    );
    crate::queue::router::assert_completed_routing_error_eq(
        &(evaluate_policy_with_catalog_and_world(
            &policy,
            &lane_catalog,
            &dataspace_catalog,
            &tx,
            state_view.world(),
        ))
        .as_ref()
        .expect_err("expected completed routing rejection"),
        &(expected_error),
        format_args!("completed routing rejection"),
    );
}

#[test]
fn opaque_asset_transfer_with_multiple_private_account_bindings_uses_default_route() {
    let (sender_id, sender_keypair) = gen_account_in("wonderland");
    let (receiver_id, _) = gen_account_in("wonderland");
    let uaid = UniversalAccountId::from_hash(Hash::new(b"router::multi-private-uaid"));
    let first_dataspace = DataSpaceId::new(10);
    let second_dataspace = DataSpaceId::new(11);
    let dataspace_catalog =
        dataspace_catalog(&[(first_dataspace, "paynet"), (second_dataspace, "bankb")]);
    let lane_catalog = catalog_with_lane_dataspaces(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (LaneId::new(2), first_dataspace),
        (LaneId::new(3), second_dataspace),
    ]);
    let router = default_router(dataspace_catalog.clone(), lane_catalog.clone());
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
    let mut state = blank_state();
    state.set_dataspace_catalog_for_testing(dataspace_catalog);
    install_router_lane_catalog(&mut state, lane_catalog);
    let sender = Account::new(sender_id.clone())
        .with_uaid(Some(uaid))
        .build(&sender_id);
    let (account_id, account_value) = sender.into_key_value();
    state
        .world
        .accounts
        .insert(account_id.clone(), account_value);
    let mut scope_entry = crate::nexus::space_directory::AccountScopeDirectoryEntry::default();
    scope_entry.ensure_dataspace(first_dataspace);
    scope_entry.ensure_dataspace(second_dataspace);
    state
        .world
        .account_scope_directory
        .insert(account_id.clone(), scope_entry);
    let mut bindings = crate::nexus::space_directory::UaidDataspaceBindings::default();
    bindings.bind_account(first_dataspace, account_id.clone());
    bindings.bind_account(second_dataspace, account_id.clone());
    state.world.uaid_dataspaces.insert(uaid, bindings);
    assert_eq!(
        state.view().world().dataspace_for_account(&account_id),
        Some(first_dataspace)
    );
    assert_eq!(
        router
            .try_route_with_view(&tx, &state.view())
            .expect("multi-dataspace account should use the default route"),
        RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
    );
}
#[test]
fn explicit_lane_rule_infers_target_dataspace_for_domain_write() {
    let (authority_id, authority_keypair) = gen_account_in("wonderland");
    let dataspace_id = DataSpaceId::new(7);
    let router = ConfigLaneRouter::new(
        LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![LaneRoutingRule {
                lane: LaneId::new(3),
                dataspace: None,
                matcher: LaneRoutingMatcher {
                    account: Some(authority_id.to_string()),
                    instruction: Some("register::domain".to_string()),
                    description: None,
                },
            }],
        },
        dataspace_catalog(&[(dataspace_id, "acme")]),
        catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (LaneId::new(3), dataspace_id),
        ]),
    );
    let tx = sample_transaction(
        &authority_id,
        authority_keypair.private_key(),
        vec![InstructionBox::from(Register::domain(Domain::new(
            DomainId::try_new("merchant", "acme").expect("domain id"),
        )))],
    );
    assert_eq!(
        router.try_route(&tx).expect("domain route must resolve"),
        RoutingDecision::new(LaneId::new(3), dataspace_id)
    );
}

#[test]
fn primary_alias_compare_and_set_same_dataspace_stays_single_route() {
    let (authority_id, authority_keypair) = gen_account_in("wonderland");
    let dataspace = DataSpaceId::new(7);
    let router = ConfigLaneRouter::new(
        default_routing_policy(),
        dataspace_catalog(&[(dataspace, "acme")]),
        catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (LaneId::new(2), dataspace),
        ]),
    );
    let instruction = CompareAndSetPrimaryAccountAlias::new(
        authority_id.clone(),
        Some(resolved_account_alias("old@acme", dataspace)),
        Some(resolved_account_alias("new@acme", dataspace)),
    );
    let tx = sample_transaction(
        &authority_id,
        authority_keypair.private_key(),
        vec![InstructionBox::from(instruction)],
    );
    assert_eq!(
        router
            .try_route_plan(&tx)
            .expect("same-dataspace alias change must remain local"),
        RoutingPlan::single(RoutingDecision::new(LaneId::new(2), dataspace))
    );
    let empty = CompareAndSetPrimaryAccountAlias::new(authority_id.clone(), None, None);
    let empty_tx = sample_transaction(
        &authority_id,
        authority_keypair.private_key(),
        vec![InstructionBox::from(empty)],
    );
    assert_eq!(
        router
            .try_route_plan(&empty_tx)
            .expect("empty compare-and-set must keep account fallback routing"),
        RoutingPlan::single(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL,))
    );
}
#[test]
fn strict_amx_policy_rejects_cross_dataspace_primary_alias_compare_and_set() {
    let (authority_id, authority_keypair) = gen_account_in("wonderland");
    let first_dataspace = DataSpaceId::new(7);
    let second_dataspace = DataSpaceId::new(8);
    let router = ConfigLaneRouter::new(
        default_routing_policy(),
        dataspace_catalog(&[(first_dataspace, "acme"), (second_dataspace, "bank")]),
        catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (LaneId::new(2), first_dataspace),
            (LaneId::new(3), second_dataspace),
        ]),
    );
    let mut metadata = Metadata::default();
    metadata.insert(
        AMX_POLICY_METADATA_KEY.parse().expect("amx policy key"),
        iroha_primitives::json::Json::new(AMX_POLICY_REJECT_CROSS_DATASPACE),
    );
    let instruction = CompareAndSetPrimaryAccountAlias::new(
        authority_id.clone(),
        Some(resolved_account_alias("merchant@acme", first_dataspace)),
        Some(resolved_account_alias("merchant@bank", second_dataspace)),
    );
    let tx = sample_transaction_with_metadata(
        &authority_id,
        authority_keypair.private_key(),
        vec![InstructionBox::from(instruction)],
        metadata,
    );
    crate::queue::router::assert_completed_routing_error_eq(
        &(router.try_route_plan(&tx))
            .as_ref()
            .expect_err("expected completed routing rejection"),
        &(RoutingResolveError::ConflictingTransactionDataspaceTargets {
            first_dataspace_id: first_dataspace,
            second_dataspace_id: second_dataspace,
        }),
        format_args!("completed routing rejection"),
    );
}
#[test]
fn strict_amx_policy_rejects_mixed_domain_write_targets() {
    let (authority_id, authority_keypair) = gen_account_in("wonderland");
    let first_dataspace = DataSpaceId::new(7);
    let second_dataspace = DataSpaceId::new(8);
    let router = ConfigLaneRouter::new(
        default_routing_policy(),
        dataspace_catalog(&[(first_dataspace, "acme"), (second_dataspace, "bank")]),
        catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (LaneId::new(2), first_dataspace),
            (LaneId::new(3), second_dataspace),
        ]),
    );
    let mut metadata = Metadata::default();
    metadata.insert(
        AMX_POLICY_METADATA_KEY.parse().expect("amx policy key"),
        iroha_primitives::json::Json::new(AMX_POLICY_REJECT_CROSS_DATASPACE),
    );
    let tx = sample_transaction_with_metadata(
        &authority_id,
        authority_keypair.private_key(),
        vec![
            InstructionBox::from(Register::domain(Domain::new(
                DomainId::try_new("merchant", "acme").expect("domain id"),
            ))),
            InstructionBox::from(Register::domain(Domain::new(
                DomainId::try_new("treasury", "bank").expect("domain id"),
            ))),
        ],
        metadata,
    );
    crate::queue::router::assert_completed_routing_error_eq(
        &(router.try_route(&tx))
            .as_ref()
            .expect_err("expected completed routing rejection"),
        &(RoutingResolveError::ConflictingTransactionDataspaceTargets {
            first_dataspace_id: first_dataspace,
            second_dataspace_id: second_dataspace,
        }),
        format_args!("completed routing rejection"),
    );
}
#[test]
fn strict_amx_policy_rejects_mixed_proved_overlay_write_targets() {
    let (authority_id, authority_keypair) = gen_account_in("wonderland");
    let first_dataspace = DataSpaceId::new(7);
    let second_dataspace = DataSpaceId::new(8);
    let router = ConfigLaneRouter::new(
        default_routing_policy(),
        dataspace_catalog(&[(first_dataspace, "acme"), (second_dataspace, "bank")]),
        catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (LaneId::new(2), first_dataspace),
            (LaneId::new(3), second_dataspace),
        ]),
    );
    let mut metadata = Metadata::default();
    metadata.insert(
        AMX_POLICY_METADATA_KEY.parse().expect("amx policy key"),
        iroha_primitives::json::Json::new(AMX_POLICY_REJECT_CROSS_DATASPACE),
    );
    let tx = sample_executable_transaction_with_metadata(
        &authority_id,
        authority_keypair.private_key(),
        sample_proved_executable(vec![
            InstructionBox::from(Register::domain(Domain::new(
                DomainId::try_new("merchant", "acme").expect("domain id"),
            ))),
            InstructionBox::from(Register::domain(Domain::new(
                DomainId::try_new("treasury", "bank").expect("domain id"),
            ))),
        ]),
        metadata,
    );
    crate::queue::router::assert_completed_routing_error_eq(
        &(router.try_route(&tx))
            .as_ref()
            .expect_err("expected completed routing rejection"),
        &(RoutingResolveError::ConflictingTransactionDataspaceTargets {
            first_dataspace_id: first_dataspace,
            second_dataspace_id: second_dataspace,
        }),
        format_args!("completed routing rejection"),
    );
}
#[test]
fn strict_amx_policy_value_is_trimmed_and_case_insensitive() {
    let (authority_id, authority_keypair) = gen_account_in("wonderland");
    let first_dataspace = DataSpaceId::new(7);
    let second_dataspace = DataSpaceId::new(8);
    let router = ConfigLaneRouter::new(
        default_routing_policy(),
        dataspace_catalog(&[(first_dataspace, "acme"), (second_dataspace, "bank")]),
        catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (LaneId::new(2), first_dataspace),
            (LaneId::new(3), second_dataspace),
        ]),
    );
    let mut metadata = Metadata::default();
    metadata.insert(
        AMX_POLICY_METADATA_KEY.parse().expect("amx policy key"),
        iroha_primitives::json::Json::new("  ReJeCt_CrOsS_DaTaSpAcE  "),
    );
    let tx = sample_transaction_with_metadata(
        &authority_id,
        authority_keypair.private_key(),
        vec![
            InstructionBox::from(Register::domain(Domain::new(
                DomainId::try_new("merchant", "acme").expect("domain id"),
            ))),
            InstructionBox::from(Register::domain(Domain::new(
                DomainId::try_new("treasury", "bank").expect("domain id"),
            ))),
        ],
        metadata,
    );
    crate::queue::router::assert_completed_routing_error_eq(
        &(router.try_route(&tx))
            .as_ref()
            .expect_err("expected completed routing rejection"),
        &(RoutingResolveError::ConflictingTransactionDataspaceTargets {
            first_dataspace_id: first_dataspace,
            second_dataspace_id: second_dataspace,
        }),
        format_args!("completed routing rejection"),
    );
}
#[test]
fn strict_amx_policy_rejects_mixed_dataspace_scoped_permissions() {
    let (authority_id, authority_keypair) = gen_account_in("wonderland");
    let first_dataspace = DataSpaceId::new(7);
    let second_dataspace = DataSpaceId::new(8);
    let router = ConfigLaneRouter::new(
        default_routing_policy(),
        dataspace_catalog(&[(first_dataspace, "acme"), (second_dataspace, "bank")]),
        catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (LaneId::new(2), first_dataspace),
            (LaneId::new(3), second_dataspace),
        ]),
    );
    let mut metadata = Metadata::default();
    metadata.insert(
        AMX_POLICY_METADATA_KEY.parse().expect("amx policy key"),
        iroha_primitives::json::Json::new(AMX_POLICY_REJECT_CROSS_DATASPACE),
    );
    let first_permission: Permission = CanPublishSpaceDirectoryManifest {
        dataspace: first_dataspace,
    }
    .into();
    let second_permission: Permission = CanPublishSpaceDirectoryManifest {
        dataspace: second_dataspace,
    }
    .into();
    let tx = sample_transaction_with_metadata(
        &authority_id,
        authority_keypair.private_key(),
        vec![
            InstructionBox::from(Grant::account_permission(
                first_permission,
                authority_id.clone(),
            )),
            InstructionBox::from(Revoke::account_permission(
                second_permission,
                authority_id.clone(),
            )),
        ],
        metadata,
    );
    crate::queue::router::assert_completed_routing_error_eq(
        &(router.try_route(&tx))
            .as_ref()
            .expect_err("expected completed routing rejection"),
        &(RoutingResolveError::ConflictingDataspaceScopedPermissions {
            first_dataspace_id: first_dataspace,
            second_dataspace_id: second_dataspace,
        }),
        format_args!("completed routing rejection"),
    );
}
#[test]
fn mixed_dataspace_scoped_permissions_without_universal_lane_fail_closed() {
    let (authority_id, authority_keypair) = gen_account_in("wonderland");
    let first_dataspace = DataSpaceId::new(7);
    let second_dataspace = DataSpaceId::new(8);
    let router = ConfigLaneRouter::new(
        LaneRoutingPolicy {
            default_lane: LaneId::new(2),
            default_dataspace: first_dataspace,
            rules: vec![],
        },
        dataspace_catalog(&[(first_dataspace, "acme"), (second_dataspace, "bank")]),
        catalog_with_lane_dataspaces(&[
            (LaneId::new(2), first_dataspace),
            (LaneId::new(3), second_dataspace),
        ]),
    );
    let first_permission: Permission = CanPublishSpaceDirectoryManifest {
        dataspace: first_dataspace,
    }
    .into();
    let second_permission: Permission = CanPublishSpaceDirectoryManifest {
        dataspace: second_dataspace,
    }
    .into();
    let tx = sample_transaction(
        &authority_id,
        authority_keypair.private_key(),
        vec![
            InstructionBox::from(Grant::account_permission(
                first_permission,
                authority_id.clone(),
            )),
            InstructionBox::from(Revoke::account_permission(
                second_permission,
                authority_id.clone(),
            )),
        ],
    );
    crate::queue::router::assert_completed_routing_error_eq(
        &(router.try_route(&tx))
            .as_ref()
            .expect_err("expected completed routing rejection"),
        &(RoutingResolveError::NoLaneForDataspace {
            dataspace_id: DataSpaceId::UNIVERSAL,
        }),
        format_args!("completed routing rejection"),
    );
}
#[test]
fn account_rule_takes_precedence_over_transfer_destination_rule() {
    let (uae_sender_id, uae_sender_keypair) = gen_account_in("uae");
    let (bank_sender_id, bank_sender_keypair) = gen_account_in("banka");
    let (acme_receiver_id, _) = gen_account_in("acme");
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::SINGLE,
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: vec![
            LaneRoutingRule {
                lane: LaneId::new(2),
                dataspace: None,
                matcher: LaneRoutingMatcher {
                    account: Some("*@uae.universal".to_string()),
                    instruction: Some("transfer".to_string()),
                    description: None,
                },
            },
            LaneRoutingRule {
                lane: LaneId::new(1),
                dataspace: None,
                matcher: LaneRoutingMatcher {
                    account: None,
                    instruction: Some("transfer::asset@acme.universal".to_string()),
                    description: None,
                },
            },
        ],
    };
    let lane_catalog = catalog_with_lanes(&[LaneId::SINGLE, LaneId::new(1), LaneId::new(2)]);
    let router = ConfigLaneRouter::new(policy, DataSpaceCatalog::default(), lane_catalog);
    let asset_definition: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("uae", "universal").unwrap(),
            "aed".parse().unwrap(),
        );
    let uae_transfer = Transfer::asset_quantity(
        AssetId::of(asset_definition.clone(), uae_sender_id.clone()),
        1_u32,
        acme_receiver_id.clone(),
    );
    let bank_transfer = Transfer::asset_quantity(
        AssetId::of(asset_definition, bank_sender_id.clone()),
        1_u32,
        acme_receiver_id.clone(),
    );
    let uae_tx = sample_transaction(
        &uae_sender_id,
        uae_sender_keypair.private_key(),
        vec![InstructionBox::from(uae_transfer)],
    );
    let bank_tx = sample_transaction(
        &bank_sender_id,
        bank_sender_keypair.private_key(),
        vec![InstructionBox::from(bank_transfer)],
    );
    let catalog = DataSpaceCatalog::default();
    let mut state = state_with_account_aliases(
        &[
            (
                uae_sender_id.clone(),
                account_alias("central@uae.universal", &catalog),
            ),
            (
                bank_sender_id.clone(),
                account_alias("settler@banka.universal", &catalog),
            ),
            (
                acme_receiver_id.clone(),
                account_alias("merchant@acme.universal", &catalog),
            ),
        ],
        catalog,
    );
    install_router_nexus(&mut state, &router);
    let uae_decision = router
        .try_route_with_view(&uae_tx, &state.view())
        .expect("UAE routing should resolve");
    let bank_decision = router
        .try_route_with_view(&bank_tx, &state.view())
        .expect("bank routing should resolve");
    assert_eq!(uae_decision.lane_id, LaneId::new(2));
    assert_eq!(bank_decision.lane_id, LaneId::new(1));
}
#[test]
fn matches_dataspace_root_account_alias_scope_rule() {
    let (dataspace_id, dataspace_keypair) = gen_account_in("wonderland");
    let (domain_id, domain_keypair) = gen_account_in("wonderland");
    let catalog = dataspace_catalog(&[(DataSpaceId::new(10), "paynet")]);
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::SINGLE,
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: vec![LaneRoutingRule {
            lane: LaneId::new(1),
            dataspace: Some(DataSpaceId::new(10)),
            matcher: LaneRoutingMatcher {
                account: Some("*@paynet".to_string()),
                instruction: None,
                description: None,
            },
        }],
    };
    let lane_catalog = catalog_with_lane_dataspaces(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (LaneId::new(1), DataSpaceId::new(10)),
    ]);
    let router = ConfigLaneRouter::new(policy, catalog.clone(), lane_catalog);
    let dataspace_tx = sample_transaction(
        &dataspace_id,
        dataspace_keypair.private_key(),
        vec![role_registration_instruction(
            &dataspace_id,
            "paynet_alias_match",
        )],
    );
    let domain_tx = sample_transaction(
        &domain_id,
        domain_keypair.private_key(),
        vec![role_registration_instruction(
            &domain_id,
            "paynet_domain_alias_match",
        )],
    );
    let mut state = state_with_account_aliases(
        &[
            (
                dataspace_id.clone(),
                account_alias("issuer@paynet", &catalog),
            ),
            (
                domain_id.clone(),
                account_alias("operator@banka.paynet", &catalog),
            ),
        ],
        catalog,
    );
    install_router_nexus(&mut state, &router);
    assert_eq!(
        router
            .try_route_with_view(&dataspace_tx, &state.view())
            .expect("dataspace alias routing should resolve"),
        RoutingDecision::new(LaneId::new(1), DataSpaceId::new(10))
    );
    assert_eq!(
        router
            .try_route_with_view(&domain_tx, &state.view())
            .expect("domain alias routing should resolve"),
        RoutingDecision::new(LaneId::new(1), DataSpaceId::new(10))
    );
}
#[test]
fn try_route_with_view_resolves_against_same_state_catalog_snapshot() {
    let (authority_id, authority_keypair) = gen_account_in("wonderland");
    let dataspace_id = DataSpaceId::new(10);
    let lane_id = LaneId::new(2);
    let catalog = dataspace_catalog(&[(dataspace_id, "paynet")]);
    let state_lane_catalog = catalog_with_lane_dataspaces(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (lane_id, dataspace_id),
    ]);
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::SINGLE,
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: vec![LaneRoutingRule {
            lane: lane_id,
            dataspace: Some(dataspace_id),
            matcher: LaneRoutingMatcher {
                account: Some("*@paynet".to_string()),
                instruction: None,
                description: None,
            },
        }],
    };
    let stale_router_lane_catalog =
        catalog_with_lane_dataspaces(&[(LaneId::SINGLE, DataSpaceId::UNIVERSAL)]);
    let router = ConfigLaneRouter::new(
        policy,
        DataSpaceCatalog::default(),
        stale_router_lane_catalog,
    );
    let tx = sample_transaction(
        &authority_id,
        authority_keypair.private_key(),
        vec![role_registration_instruction(
            &authority_id,
            "state_catalog_route",
        )],
    );
    let mut state = state_with_account_aliases(
        &[(
            authority_id.clone(),
            account_alias("operator@paynet", &catalog),
        )],
        catalog,
    );
    let mut nexus = state.nexus_snapshot();
    nexus.routing_policy = router.policy.as_ref().clone();
    nexus.lane_catalog = state_lane_catalog;
    replace_router_fixture_nexus(&mut state, nexus);
    let decision = router
        .try_route_with_view(&tx, &state.view())
        .expect("state-aware routing must resolve against the same state catalogs it matched");
    assert_eq!(decision, RoutingDecision::new(lane_id, dataspace_id));
}
#[test]
fn legacy_bare_domain_account_scope_does_not_match() {
    let (authority_id, authority_keypair) = gen_account_in("wonderland");
    let catalog = dataspace_catalog(&[(DataSpaceId::new(10), "paynet")]);
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::SINGLE,
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: vec![LaneRoutingRule {
            lane: LaneId::new(1),
            dataspace: Some(DataSpaceId::new(10)),
            matcher: LaneRoutingMatcher {
                account: Some("*@banka".to_string()),
                instruction: None,
                description: None,
            },
        }],
    };
    let lane_catalog = catalog_with_lane_dataspaces(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (LaneId::new(1), DataSpaceId::new(10)),
    ]);
    let router = ConfigLaneRouter::new(policy, catalog.clone(), lane_catalog);
    let tx = sample_transaction(
        &authority_id,
        authority_keypair.private_key(),
        vec![InstructionBox::from(Register::domain(Domain::new(
            DomainId::try_new("legacy-no-match", "universal").expect("domain id"),
        )))],
    );
    let state = state_with_account_aliases(
        &[(
            authority_id.clone(),
            account_alias("operator@banka.paynet", &catalog),
        )],
        catalog,
    );
    assert_eq!(
        router
            .try_route_with_view(&tx, &state.view())
            .expect("default routing should resolve"),
        RoutingDecision::default()
    );
}
#[test]
fn resolve_query_routing_decision_matches_authority_rule() {
    let (alice_id, _) = gen_account_in("wonderland");
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::new(0),
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: vec![LaneRoutingRule {
            lane: LaneId::new(2),
            dataspace: Some(DataSpaceId::new(2)),
            matcher: LaneRoutingMatcher {
                account: Some(alice_id.to_string()),
                instruction: None,
                description: None,
            },
        }],
    };
    let lane_catalog = catalog_with_lane_dataspaces(&[
        (LaneId::new(0), DataSpaceId::UNIVERSAL),
        (LaneId::new(2), DataSpaceId::new(2)),
    ]);
    let dataspace_catalog = DataSpaceCatalog::new(vec![
        iroha_data_model::nexus::DataSpaceMetadata {
            id: DataSpaceId::UNIVERSAL,
            alias: "universal".to_owned(),
            ..Default::default()
        },
        iroha_data_model::nexus::DataSpaceMetadata {
            id: DataSpaceId::new(2),
            alias: "ds2".to_owned(),
            ..Default::default()
        },
    ])
    .expect("dataspace catalog");
    let decision =
        resolve_query_routing_decision(&policy, &lane_catalog, &dataspace_catalog, &alice_id, None)
            .expect("query route must resolve");
    assert_eq!(
        decision,
        RoutingDecision::new(LaneId::new(2), DataSpaceId::new(2))
    );
}
#[test]
fn resolve_query_routing_decision_ignores_instruction_matchers() {
    let (alice_id, _) = gen_account_in("wonderland");
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::new(0),
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: vec![LaneRoutingRule {
            lane: LaneId::new(1),
            dataspace: Some(DataSpaceId::new(1)),
            matcher: LaneRoutingMatcher {
                account: Some(alice_id.to_string()),
                instruction: Some("mint".to_owned()),
                description: None,
            },
        }],
    };
    let lane_catalog = catalog_with_lane_dataspaces(&[
        (LaneId::new(0), DataSpaceId::UNIVERSAL),
        (LaneId::new(1), DataSpaceId::new(1)),
    ]);
    let dataspace_catalog = DataSpaceCatalog::new(vec![
        iroha_data_model::nexus::DataSpaceMetadata {
            id: DataSpaceId::UNIVERSAL,
            alias: "universal".to_owned(),
            ..Default::default()
        },
        iroha_data_model::nexus::DataSpaceMetadata {
            id: DataSpaceId::new(1),
            alias: "ds1".to_owned(),
            ..Default::default()
        },
    ])
    .expect("dataspace catalog");
    let decision =
        resolve_query_routing_decision(&policy, &lane_catalog, &dataspace_catalog, &alice_id, None)
            .expect("query route must resolve");
    assert_eq!(
        decision,
        RoutingDecision::new(LaneId::new(0), DataSpaceId::UNIVERSAL)
    );
}
#[test]
fn resolve_query_routing_decision_rejects_autoscale_owned_default_lane_without_state() {
    let (alice_id, _) = gen_account_in("wonderland");
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::new(1),
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: Vec::new(),
    };
    let lane_catalog = lane_catalog_from_configs(vec![
        default_lane_config(),
        autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
    ]);
    crate::queue::router::assert_completed_routing_error_eq(
        &(resolve_query_routing_decision(
            &policy,
            &lane_catalog,
            &DataSpaceCatalog::default(),
            &alice_id,
            None,
        ))
        .as_ref()
        .expect_err("expected completed routing rejection"),
        &(RoutingResolveError::AutoscaleOwnedDefaultLane {
            lane_id: LaneId::new(1),
        }),
        format_args!("state-free query routing must not accept autoscale-owned default lanes"),
    );
}
#[test]
fn resolve_query_routing_decision_rejects_autoscale_owned_rule_lane_without_state() {
    let (alice_id, _) = gen_account_in("wonderland");
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::SINGLE,
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: vec![LaneRoutingRule {
            lane: LaneId::new(1),
            dataspace: Some(DataSpaceId::UNIVERSAL),
            matcher: LaneRoutingMatcher {
                account: Some(alice_id.to_string()),
                instruction: None,
                description: None,
            },
        }],
    };
    let lane_catalog = lane_catalog_from_configs(vec![
        default_lane_config(),
        autoscale_elastic_lane_config(LaneId::new(1), DataSpaceId::UNIVERSAL, 7),
    ]);
    crate::queue::router::assert_completed_routing_error_eq(
        &(resolve_query_routing_decision(
            &policy,
            &lane_catalog,
            &DataSpaceCatalog::default(),
            &alice_id,
            None,
        ))
        .as_ref()
        .expect_err("expected completed routing rejection"),
        &(RoutingResolveError::AutoscaleOwnedRuleLane {
            lane_id: LaneId::new(1),
        }),
        format_args!(
            "state-free query routing must not accept autoscale-owned explicit rule lanes"
        ),
    );
}
#[test]
fn dataspace_scoped_permission_grant_routes_by_permission_dataspace() {
    let (alice_id, alice_keypair) = gen_account_in("wonderland");
    let dataspace = DataSpaceId::new(7);
    let lane = LaneId::new(3);
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::SINGLE,
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: vec![LaneRoutingRule {
            lane: LaneId::new(1),
            dataspace: Some(DataSpaceId::new(1)),
            matcher: LaneRoutingMatcher {
                account: Some(alice_id.to_string()),
                instruction: None,
                description: None,
            },
        }],
    };
    let lane_catalog = catalog_with_lane_dataspaces(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (lane, dataspace),
    ]);
    let dataspace_catalog = DataSpaceCatalog::new(vec![
        iroha_data_model::nexus::DataSpaceMetadata::default(),
        iroha_data_model::nexus::DataSpaceMetadata {
            id: dataspace,
            alias: "manifest".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("dataspace catalog");
    let router = ConfigLaneRouter::new(policy, dataspace_catalog, lane_catalog);
    let tx = sample_transaction(
        &alice_id,
        alice_keypair.private_key(),
        vec![InstructionBox::from(Grant::account_permission(
            CanPublishSpaceDirectoryManifest { dataspace },
            alice_id.clone(),
        ))],
    );
    let decision = router
        .try_route(&tx)
        .expect("dataspace-scoped permission should resolve");
    assert_eq!(decision, RoutingDecision::new(lane, dataspace));
    let uaid_scoped_tx = sample_transaction(
        &alice_id,
        alice_keypair.private_key(),
        vec![InstructionBox::from(Grant::account_permission(
            CanPublishSpaceDirectoryManifestForUaid {
                dataspace,
                uaid: UniversalAccountId::from_hash(Hash::new(
                    b"uaid::dataspace-scoped-permission-route",
                )),
            },
            alice_id.clone(),
        ))],
    );
    assert_eq!(
        router
            .try_route(&uaid_scoped_tx)
            .expect("UAID-scoped permission should resolve"),
        RoutingDecision::new(lane, dataspace),
    );
    let domain_scoped_tx = sample_transaction(
        &alice_id,
        alice_keypair.private_key(),
        vec![InstructionBox::from(Grant::account_permission(
            CanPublishSpaceDirectoryManifestForAccountDomain {
                dataspace,
                domain: DomainId::try_new("hbl", "manifest").expect("HBL manifest domain"),
            },
            alice_id.clone(),
        ))],
    );
    assert_eq!(
        router
            .try_route(&domain_scoped_tx)
            .expect("account-domain-scoped permission should resolve"),
        RoutingDecision::new(lane, dataspace),
    );
    let role_id: RoleId = "hbl_manifest_publishers".parse().expect("role id");
    let role_scoped_tx = sample_transaction(
        &alice_id,
        alice_keypair.private_key(),
        vec![InstructionBox::from(Grant::role_permission(
            CanPublishSpaceDirectoryManifestForAccountDomain {
                dataspace,
                domain: DomainId::try_new("hbl", "manifest").expect("HBL manifest domain"),
            },
            role_id,
        ))],
    );
    assert_eq!(
        router
            .try_route_without_state(&role_scoped_tx)
            .expect("role permission routing should resolve from its dataspace payload"),
        Some(RoutingDecision::new(lane, dataspace)),
    );
}
#[test]
fn space_directory_manifest_writes_route_by_manifest_dataspace() {
    let (alice_id, alice_keypair) = gen_account_in("wonderland");
    let dataspace = DataSpaceId::new(10);
    let lane = LaneId::new(3);
    let policy = default_routing_policy();
    let lane_catalog = catalog_with_lane_dataspaces(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (lane, dataspace),
    ]);
    let dataspace_catalog = dataspace_catalog(&[(dataspace, "sbp")]);
    let router = ConfigLaneRouter::new(policy.clone(), dataspace_catalog, lane_catalog.clone());
    let manifest = AssetPermissionManifest {
        version: ManifestVersion::default(),
        uaid: UniversalAccountId::from_hash(Hash::new(b"router::space-directory-publish")),
        dataspace,
        issued_ms: 0,
        activation_epoch: 0,
        expiry_epoch: None,
        entries: Vec::new(),
    };
    let tx = sample_transaction(
        &alice_id,
        alice_keypair.private_key(),
        vec![InstructionBox::from(PublishSpaceDirectoryManifest {
            manifest: manifest.clone(),
        })],
    );
    let expected = RoutingDecision::new(lane, dataspace);
    assert_eq!(
        router
            .try_route_without_state(&tx)
            .expect("space-directory publish should route without WSV state"),
        Some(expected)
    );
    assert_eq!(
        router
            .try_route_plan_without_state(&tx)
            .expect("space-directory publish plan should route without WSV state")
            .map(|plan| plan.coordinator_route()),
        Some(expected)
    );
    assert_eq!(
        evaluate_policy_with_catalog(
            &policy,
            &lane_catalog,
            router.dataspace_catalog.as_ref(),
            &tx,
        )
        .expect("validation routing should match queue routing"),
        expected
    );
}
#[test]
fn account_permission_grant_routes_by_destination_account_policy() {
    let (alice_id, alice_keypair, bob_id, router) = two_account_policy_router_fixture!();
    let tx = sample_transaction(
        &alice_id,
        alice_keypair.private_key(),
        vec![InstructionBox::from(Grant::account_permission(
            iroha_executor_data_model::permission::account::CanModifyAccountMetadata {
                account: alice_id.clone(),
            },
            bob_id.clone(),
        ))],
    );
    let decision = router
        .try_route(&tx)
        .expect("account permission should route to destination account lane");
    assert_eq!(
        decision,
        RoutingDecision::new(LaneId::new(2), DataSpaceId::new(2))
    );
}
#[test]
fn asset_definition_permission_grant_routes_by_asset_definition_dataspace_policy() {
    let (alice_id, alice_keypair, bob_id, router) = two_account_policy_router_fixture!();
    let asset_definition = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        DomainId::try_new("nexus", "universal").unwrap(),
        "ds1".parse().unwrap(),
    );
    let opaque_asset_definition =
        AssetDefinitionId::parse_address_literal(&asset_definition.canonical_address())
            .expect("opaque canonical asset definition id");
    let tx = sample_transaction(
        &alice_id,
        alice_keypair.private_key(),
        vec![InstructionBox::from(Grant::account_permission(
            iroha_executor_data_model::permission::asset::CanTransferAssetWithDefinition {
                asset_definition: opaque_asset_definition,
            },
            bob_id,
        ))],
    );
    let state = state_with_asset_definitions(
        vec![
            AssetDefinition::numeric(
                asset_definition,
                "ds1".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&alice_id),
        ],
        router.dataspace_catalog.as_ref().clone(),
        router.lane_catalog.as_ref().clone(),
    );
    assert_eq!(
        router
            .try_route_without_state(&tx)
            .expect("opaque asset-definition permission should defer to state"),
        None
    );
    let decision = router
        .try_route_with_view(&tx, &state.view())
        .expect("asset-definition permission should route to the asset-definition dataspace");
    assert_eq!(
        decision,
        RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
    );
}
#[test]
fn asset_definition_permission_revoke_routes_by_asset_definition_dataspace_policy() {
    let (alice_id, alice_keypair, bob_id, router) = two_account_policy_router_fixture!();
    let asset_definition = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        DomainId::try_new("nexus", "universal").unwrap(),
        "ds1".parse().unwrap(),
    );
    let opaque_asset_definition =
        AssetDefinitionId::parse_address_literal(&asset_definition.canonical_address())
            .expect("opaque canonical asset definition id");
    let tx = sample_transaction(
        &alice_id,
        alice_keypair.private_key(),
        vec![InstructionBox::from(Revoke::account_permission(
            iroha_executor_data_model::permission::asset::CanTransferAssetWithDefinition {
                asset_definition: opaque_asset_definition,
            },
            bob_id,
        ))],
    );
    let state = state_with_asset_definitions(
        vec![
            AssetDefinition::numeric(
                asset_definition,
                "ds1".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&alice_id),
        ],
        router.dataspace_catalog.as_ref().clone(),
        router.lane_catalog.as_ref().clone(),
    );
    assert_eq!(
        router
            .try_route_without_state(&tx)
            .expect("opaque asset-definition revoke should defer to state"),
        None
    );
    let decision = router.try_route_with_view(&tx, &state.view()).expect(
        "asset-definition permission revoke should route to the asset-definition dataspace",
    );
    assert_eq!(
        decision,
        RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
    );
}
#[test]
fn asset_definition_permission_grant_routes_by_named_dataspace_alias() {
    let (alice_id, alice_keypair, bob_id, router) = two_account_policy_router_fixture!();
    let asset_definition = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        DomainId::try_new("vault", "bob").unwrap(),
        "voucher".parse().unwrap(),
    );
    let opaque_asset_definition =
        AssetDefinitionId::parse_address_literal(&asset_definition.canonical_address())
            .expect("opaque canonical asset definition id");
    let tx = sample_transaction(
        &alice_id,
        alice_keypair.private_key(),
        vec![InstructionBox::from(Grant::account_permission(
            iroha_executor_data_model::permission::asset::CanTransferAssetWithDefinition {
                asset_definition: opaque_asset_definition,
            },
            alice_id.clone(),
        ))],
    );
    let state = state_with_bound_numeric_asset_definition(
        &asset_definition,
        "voucher#bob",
        "voucher",
        &bob_id,
        router.dataspace_catalog.as_ref().clone(),
        router.lane_catalog.as_ref().clone(),
    );
    assert_eq!(
        router
            .try_route_without_state(&tx)
            .expect("opaque named-dataspace permission should defer to state"),
        None
    );
    let decision = router
        .try_route_with_view(&tx, &state.view())
        .expect("named-dataspace asset permission should route to that dataspace");
    assert_eq!(
        decision,
        RoutingDecision::new(LaneId::new(2), DataSpaceId::new(2))
    );
}
