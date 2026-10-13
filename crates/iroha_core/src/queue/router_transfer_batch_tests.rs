// Batch routing uses committed balance policy without inventing an AssetId scope.

#[test]
fn transfer_batch_scoped_atomic_and_independent_routes_match_sealed_and_world_views() {
    use iroha_data_model::{
        isi::transfer::{BatchMode, TransferAssetBatchEntry},
        transaction::{
            TransactionEntrypoint,
            signed::{SealedTransactionReveal, compute_sealed_transaction_commitment},
        },
    };

    let (alice, key) = gen_account_in("wonderland");
    let (bob, _) = gen_account_in("wonderland");
    let (dataspace, lane, catalog, lanes, router) = routed_dataspace_fixture("batchnet");
    let domain = DomainId::try_new("cash", "batchnet").expect("asset domain");
    let definition = AssetDefinitionId::derive_from_components(
        domain.clone(),
        "coin".parse().expect("asset name"),
    );
    let mut state = state_with_asset_definitions(
        vec![
            AssetDefinition::numeric(
                definition.clone(),
                "coin",
                AssetBalancePolicy::DataspaceRestricted,
                Some(domain),
            )
            .build(&alice),
        ],
        catalog.clone(),
        lanes.clone(),
    );
    install_router_nexus(&mut state, &router);
    for mode in [BatchMode::Atomic, BatchMode::Independent] {
        let batch = TransferAssetBatch::new(vec![
            TransferAssetBatchEntry::new(alice.clone(), bob.clone(), definition.clone(), 1_u32),
            TransferAssetBatchEntry::new(bob.clone(), alice.clone(), definition.clone(), 2_u32),
        ])
        .with_mode(mode);
        let ordinary = sample_transaction(&alice, key.private_key(), vec![batch.into()]);
        let signed = ordinary
            .external()
            .expect("signed external transaction")
            .clone();
        let salt = [0xBC; 32];
        let commitment = compute_sealed_transaction_commitment(
            &super::super::queue_test_network_id(),
            &signed,
            salt,
            9,
        );
        let sealed = AcceptedTransaction::new_unchecked_entrypoint(std::borrow::Cow::Owned(
            TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
                commitment, signed, salt,
            )),
        ));
        let expected = RoutingPlan::single(RoutingDecision::new(lane, dataspace));
        for transaction in [&ordinary, &sealed] {
            assert_eq!(
                (router.try_route_plan_without_state(transaction))
                    .as_ref()
                    .expect("the operation must complete successfully"),
                &(None)
            );
            let view = state.view();
            let from_view = router
                .try_route_plan_with_view(transaction, &view)
                .expect("committed scoped batch route");
            assert_eq!(from_view, expected, "{mode:?}");
            assert_eq!(
                (evaluate_policy_plan_with_catalog_and_world_at(
                    &default_routing_policy(),
                    &lanes,
                    &catalog,
                    transaction,
                    view.world(),
                    state_view_ledger_time_ms(&view),
                ))
                .as_ref()
                .expect("the operation must complete successfully"),
                &(expected.clone()),
                "{mode:?} execution must use the same committed definition policy"
            );
            crate::queue::validate_current_admission_route(&from_view)
                .expect("same-dataspace batch has one supported route");
        }
    }
}

#[test]
fn transfer_batch_cross_dataspace_preserves_all_targets_and_refuses_current_admission() {
    use iroha_data_model::isi::transfer::{BatchMode, TransferAssetBatchEntry};

    let (alice, key) = gen_account_in("wonderland");
    let (bob, _) = gen_account_in("wonderland");
    let first = DataSpaceId::new(10);
    let second = DataSpaceId::new(11);
    let catalog = dataspace_catalog(&[(first, "batchone"), (second, "batchtwo")]);
    let lanes = catalog_with_lane_dataspaces(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (LaneId::new(2), first),
        (LaneId::new(3), second),
    ]);
    let router = default_router(catalog.clone(), lanes.clone());
    let definitions = ["batchone", "batchtwo"].map(|alias| {
        let domain = DomainId::try_new("cash", alias).expect("asset domain");
        let id = AssetDefinitionId::derive_from_components(
            domain.clone(),
            "coin".parse().expect("asset name"),
        );
        AssetDefinition::numeric(
            id,
            "coin",
            AssetBalancePolicy::DataspaceRestricted,
            Some(domain),
        )
        .build(&alice)
    });
    let mut state =
        state_with_asset_definitions(definitions.to_vec(), catalog.clone(), lanes.clone());
    install_router_nexus(&mut state, &router);
    for mode in [BatchMode::Atomic, BatchMode::Independent] {
        let batch = TransferAssetBatch::new(
            definitions
                .iter()
                .map(|definition| {
                    TransferAssetBatchEntry::new(
                        alice.clone(),
                        bob.clone(),
                        definition.id.clone(),
                        1_u32,
                    )
                })
                .collect(),
        )
        .with_mode(mode);
        let instruction = InstructionBox::from(batch);
        let transaction = sample_transaction(&alice, key.private_key(), vec![instruction.clone()]);
        let view = state.view();
        assert_eq!(
            (deferred_instruction_concrete_dataspace_targets(
                &*instruction,
                Some(&catalog),
                Some(&view)
            ))
            .as_ref()
            .expect("the operation must complete successfully"),
            &(Some(BTreeSet::from([first, second])))
        );
        assert_eq!(
            (native_amx_participant_dataspaces_with_world_at(
                &transaction,
                &catalog,
                view.world(),
                None,
            ))
            .as_ref()
            .expect("the operation must complete successfully"),
            &(vec![first, second]),
            "batch participants cannot disappear during plan reconciliation"
        );
        let plan = router
            .try_route_plan_with_view(&transaction, &view)
            .expect("complete batch plan");
        assert!(
            matches!(plan, RoutingPlan::NativeAmx(_)),
            "{mode:?}: {plan:?}"
        );
        assert_eq!(
            (evaluate_policy_plan_with_catalog_and_world_at(
                &default_routing_policy(),
                &lanes,
                &catalog,
                &transaction,
                view.world(),
                state_view_ledger_time_ms(&view),
            ))
            .as_ref()
            .expect("the operation must complete successfully"),
            &(plan.clone())
        );
        assert!(matches!(
            crate::queue::validate_current_admission_route(&plan),
            Err(crate::queue::Error::UnsupportedTransactionAdmission { .. }),
        ));
    }
}

#[test]
fn transfer_batch_global_definition_keeps_the_global_balance_owner() {
    use iroha_data_model::isi::transfer::TransferAssetBatchEntry;

    let (alice, key) = gen_account_in("wonderland");
    let (bob, _) = gen_account_in("wonderland");
    let (_, _, catalog, lanes, router) = routed_dataspace_fixture("batchnet");
    let domain = DomainId::try_new("cash", "batchnet").expect("asset domain");
    let definition = AssetDefinitionId::derive_from_components(
        domain.clone(),
        "coin".parse().expect("asset name"),
    );
    let mut state = state_with_asset_definitions(
        vec![
            AssetDefinition::numeric(
                definition.clone(),
                "coin",
                AssetBalancePolicy::Global,
                Some(domain),
            )
            .build(&alice),
        ],
        catalog.clone(),
        lanes.clone(),
    );
    install_router_nexus(&mut state, &router);
    let transaction = sample_transaction(
        &alice,
        key.private_key(),
        vec![
            TransferAssetBatch::new(vec![TransferAssetBatchEntry::new(
                alice.clone(),
                bob,
                definition,
                1_u32,
            )])
            .into(),
        ],
    );
    let view = state.view();
    let expected =
        RoutingPlan::single(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL));
    assert_eq!(
        (router.try_route_plan_with_view(&transaction, &view))
            .as_ref()
            .expect("the operation must complete successfully"),
        &(expected.clone())
    );
    assert_eq!(
        (evaluate_policy_plan_with_catalog_and_world_at(
            &default_routing_policy(),
            &lanes,
            &catalog,
            &transaction,
            view.world(),
            state_view_ledger_time_ms(&view),
        ))
        .as_ref()
        .expect("the operation must complete successfully"),
        &(expected)
    );
}

#[test]
fn transfer_batch_policy_matchers_select_the_same_profile_as_original_single_transfers() {
    use iroha_data_model::{
        isi::transfer::{BatchMode, TransferAssetBatchEntry},
        transaction::{
            TransactionEntrypoint,
            signed::{SealedTransactionReveal, compute_sealed_transaction_commitment},
        },
    };

    let (alice, key) = gen_account_in("banka");
    let (bob, _) = gen_account_in("acme");
    let dataspace = DataSpaceId::new(10);
    let catalog = dataspace_catalog(&[(dataspace, "batchnet")]);
    let lanes = catalog_with_lane_dataspaces(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (LaneId::new(1), dataspace),
        (LaneId::new(2), dataspace),
    ]);
    let domain = DomainId::try_new("cash", "batchnet").expect("asset domain");
    let definition = AssetDefinitionId::derive_from_components(
        domain.clone(),
        "coin".parse().expect("asset name"),
    );
    let mut state = state_with_account_aliases(
        &[
            (
                alice.clone(),
                account_alias("sender@banka.batchnet", &catalog),
            ),
            (
                bob.clone(),
                account_alias("receiver@acme.batchnet", &catalog),
            ),
        ],
        catalog.clone(),
    );
    state.world.asset_definitions.insert(
        definition.clone(),
        AssetDefinition::numeric(
            definition.clone(),
            "coin",
            AssetBalancePolicy::DataspaceRestricted,
            Some(domain),
        )
        .build(&alice),
    );
    for (matcher, selected_lane) in [
        ("transfer", LaneId::new(2)),
        ("transfer::asset", LaneId::new(2)),
        ("transfer::asset@acme.batchnet", LaneId::new(2)),
        ("transfer::asset@absent.batchnet", LaneId::new(1)),
        ("transfer::domain", LaneId::new(1)),
    ] {
        let policy = LaneRoutingPolicy {
            default_lane: LaneId::new(1),
            default_dataspace: dataspace,
            rules: vec![LaneRoutingRule {
                lane: LaneId::new(2),
                dataspace: Some(dataspace),
                matcher: LaneRoutingMatcher {
                    account: None,
                    instruction: Some(matcher.into()),
                    description: None,
                },
            }],
            ..default_routing_policy()
        };
        let router = ConfigLaneRouter::new(policy.clone(), catalog.clone(), lanes.clone());
        install_router_nexus(&mut state, &router);
        let singles = sample_transaction(
            &alice,
            key.private_key(),
            vec![
                Transfer::asset_quantity(
                    AssetId::of(definition.clone(), alice.clone()),
                    1_u32,
                    alice.clone(),
                )
                .into(),
                Transfer::asset_quantity(
                    AssetId::of(definition.clone(), alice.clone()),
                    2_u32,
                    bob.clone(),
                )
                .into(),
            ],
        );
        let expected = RoutingPlan::single(RoutingDecision::new(selected_lane, dataspace));
        let view = state.view();
        assert_eq!(
            (router.try_route_plan_with_view(&singles, &view))
                .as_ref()
                .expect("the operation must complete successfully"),
            &(expected.clone()),
            "{matcher}"
        );
        for mode in [BatchMode::Atomic, BatchMode::Independent] {
            let batch = TransferAssetBatch::new(vec![
                TransferAssetBatchEntry::new(
                    alice.clone(),
                    alice.clone(),
                    definition.clone(),
                    1_u32,
                ),
                TransferAssetBatchEntry::new(alice.clone(), bob.clone(), definition.clone(), 2_u32),
            ])
            .with_mode(mode);
            let ordinary = sample_transaction(&alice, key.private_key(), vec![batch.into()]);
            let signed = ordinary.external().expect("signed batch").clone();
            let salt = [0xAD; 32];
            let commitment = compute_sealed_transaction_commitment(
                &super::super::queue_test_network_id(),
                &signed,
                salt,
                9,
            );
            let sealed = AcceptedTransaction::new_unchecked_entrypoint(std::borrow::Cow::Owned(
                TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
                    commitment, signed, salt,
                )),
            ));
            for transaction in [&ordinary, &sealed] {
                assert_eq!(
                    (router.try_route_plan_with_view(transaction, &view))
                        .as_ref()
                        .expect("the operation must complete successfully"),
                    &(expected.clone()),
                    "{matcher}: {mode:?}"
                );
                assert_eq!(
                    (evaluate_policy_plan_with_catalog_and_world_at(
                        &policy,
                        &lanes,
                        &catalog,
                        transaction,
                        view.world(),
                        state_view_ledger_time_ms(&view),
                    ))
                    .as_ref()
                    .expect("the operation must complete successfully"),
                    &(expected.clone()),
                    "{matcher}: {mode:?}"
                );
            }
        }
    }
}
