//! Registration controls through the original completed quantity source owner.
use super::*;

fn empty_definition(label: &str) -> (AssetDefinitionId, AssetDefinition) {
    let id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("quantity-capture", "universal").unwrap(),
        label.parse().unwrap(),
    );
    let definition = AssetDefinition::numeric(
        id.clone(),
        "Registration control",
        AssetBalancePolicy::Global,
        None,
    )
    .build(&ALICE_ID);
    (id, definition)
}

#[test]
fn original_source_rejects_raw_zero_definition_insertion() {
    with_signed_quantity_block(|block, alice, _, _call| {
        let original_supply = block
            .world
            .asset_definitions
            .get(alice.definition())
            .unwrap()
            .total_quantity()
            .clone();
        let (id, definition) = empty_definition("raw-zero");
        let mut transaction = block.transaction();
        transaction
            .world
            .insert_asset_definition_entry(id.clone(), definition);
        transaction.apply();
        block.observe_quantity_block_journals();
        assert_eq!(
            block.fastpq_quantity_candidate.issue,
            Some(QuantityCaptureIssue::UnownedMutation)
        );
        assert_eq!(
            block.fastpq_quantity_candidate.commitments.coverage_gap(),
            Some(CoverageGap::RawQuantityWrite)
        );
        assert!(
            block
                .world
                .asset_definitions
                .get(&id)
                .unwrap()
                .total_quantity()
                .is_zero()
        );
        assert_eq!(
            block
                .world
                .asset_definitions
                .get(alice.definition())
                .unwrap()
                .total_quantity(),
            &original_supply
        );
    });
}

#[test]
fn original_source_registration_refuses_foreign_key_and_nonzero_supply() {
    for mutation in 0..2 {
        with_signed_quantity_block(|block, _, _, call| {
            let (id, mut definition) = empty_definition("original-zero");
            let key = if mutation == 0 {
                empty_definition("foreign-zero").0
            } else {
                definition.total_quantity = Quantity::from(1_u32);
                id.clone()
            };
            let mut transaction = block.transaction();
            transaction.tx_call_hash = Some(call);
            let error = transaction
                .register_quantity_definition(key.clone(), definition)
                .unwrap_err();
            assert!(matches!(
                error,
                InstructionExecutionError::InvariantViolation(_)
            ));
            assert!(transaction.world.asset_definitions.get(&id).is_none());
            assert!(transaction.world.asset_definitions.get(&key).is_none());
            assert!(transaction.world.axt_asset_incarnations.get(&id).is_none());
            assert!(transaction.world.axt_asset_incarnations.get(&key).is_none());
            // Even a caller which catches the original refusal cannot relabel
            // the attempted foreign/nonzero write as complete source coverage.
            transaction.apply();
            block.observe_quantity_block_journals();
            assert_eq!(
                block.fastpq_quantity_candidate.issue,
                Some(QuantityCaptureIssue::UnownedMutation)
            );
            assert_eq!(
                block.fastpq_quantity_candidate.commitments.coverage_gap(),
                Some(CoverageGap::RawQuantityWrite)
            );
        });
    }
}

#[test]
fn original_registration_refuses_an_existing_incarnation_and_preserves_rollback() {
    with_signed_quantity_block(|block, alice, _, call| {
        let original_incarnation = *block
            .world
            .axt_asset_incarnations
            .get(alice.definition())
            .unwrap();
        let (id, definition) = empty_definition("stale-lifecycle");
        {
            let mut transaction = block.transaction();
            transaction.tx_call_hash = Some(call);
            transaction
                .world
                .axt_asset_incarnations
                .insert(id.clone(), original_incarnation);
            assert!(matches!(
                transaction.register_quantity_definition(id.clone(), definition),
                Err(InstructionExecutionError::InvariantViolation(_)),
            ));
            assert!(transaction.world.asset_definitions.get(&id).is_none());
            assert_eq!(
                transaction.world.axt_asset_incarnations.get(&id),
                Some(&original_incarnation)
            );
        }
        assert!(block.world.asset_definitions.get(&id).is_none());
        assert!(block.world.axt_asset_incarnations.get(&id).is_none());
        block.observe_quantity_block_journals();
        assert_eq!(block.fastpq_quantity_candidate.issue, None);
        assert_eq!(
            block.fastpq_quantity_candidate.commitments.coverage_gap(),
            None
        );
    });
}

#[test]
fn original_registration_refuses_foreign_balance_indexes_and_direct_home() {
    for mutation in 0..5 {
        with_signed_quantity_block(|block, alice, _, call| {
            let original_incarnation = *block
                .world
                .axt_asset_incarnations
                .get(alice.definition())
                .unwrap();
            let (id, definition) = empty_definition("foreign-index");
            {
                let mut transaction = block.transaction();
                transaction.tx_call_hash = Some(call);
                match mutation {
                    0 => {
                        transaction
                            .world
                            .asset_definition_assets
                            .insert((id.clone(), AssetId::of(id.clone(), BOB_ID.clone())), ());
                    }
                    1 => {
                        transaction
                            .world
                            .asset_definition_holders
                            .insert((id.clone(), BOB_ID.clone()), ());
                    }
                    2 => {
                        transaction
                            .world
                            .asset_definition_nonzero_holders
                            .insert((id.clone(), BOB_ID.clone()), ());
                    }
                    3 => {
                        transaction
                            .world
                            .asset_definition_asset_counts
                            .insert(id.clone(), 1);
                    }
                    _ => {
                        transaction.world.asset_definition_direct_homes.insert(
                            id.clone(),
                            iroha_data_model::asset::AssetDefinitionDirectHomeV1 {
                                incarnation: original_incarnation,
                                dataspace_id: iroha_model_base::topology::DataSpaceId::new(7),
                            },
                        );
                    }
                }
                assert!(matches!(
                    transaction.register_quantity_definition(id.clone(), definition),
                    Err(InstructionExecutionError::InvariantViolation(_)),
                ));
                assert!(transaction.world.asset_definitions.get(&id).is_none());
                assert!(transaction.world.axt_asset_incarnations.get(&id).is_none());
                match mutation {
                    0 => assert!(
                        index_members(&transaction.world.asset_definition_assets, &id)
                            .next()
                            .is_some()
                    ),
                    1 => assert!(
                        index_members(&transaction.world.asset_definition_holders, &id)
                            .next()
                            .is_some()
                    ),
                    2 => assert!(
                        index_members(&transaction.world.asset_definition_nonzero_holders, &id)
                            .next()
                            .is_some()
                    ),
                    3 => assert_eq!(
                        transaction.world.asset_definition_asset_counts.get(&id),
                        Some(&1)
                    ),
                    _ => assert_eq!(
                        transaction
                            .world
                            .asset_definition_direct_homes
                            .get(&id)
                            .unwrap()
                            .incarnation,
                        original_incarnation
                    ),
                }
            }
            assert!(block.world.asset_definitions.get(&id).is_none());
            assert!(block.world.axt_asset_incarnations.get(&id).is_none());
            assert!(
                index_members(&block.world.asset_definition_assets, &id)
                    .next()
                    .is_none()
            );
            assert!(
                index_members(&block.world.asset_definition_holders, &id)
                    .next()
                    .is_none()
            );
            assert!(
                index_members(&block.world.asset_definition_nonzero_holders, &id)
                    .next()
                    .is_none()
            );
            assert!(block.world.asset_definition_direct_homes.get(&id).is_none());
            assert!(block.world.asset_definition_asset_counts.get(&id).is_none());
            block.observe_quantity_block_journals();
            assert_eq!(block.fastpq_quantity_candidate.issue, None);
            assert_eq!(
                block.fastpq_quantity_candidate.commitments.coverage_gap(),
                None
            );
        });
    }
}

#[test]
fn original_source_zero_registration_never_clears_prior_raw_write() {
    with_signed_quantity_block(|block, _, _, call| {
        let (id, definition) = empty_definition("sticky-zero");
        let mut transaction = block.transaction();
        transaction.tx_call_hash = Some(call);
        assert!(
            transaction
                .world
                .asset_definitions
                .remove(id.clone())
                .is_none()
        );
        let incarnation = transaction
            .register_quantity_definition(id.clone(), definition)
            .unwrap();
        assert_eq!(
            transaction.world.axt_asset_incarnations.get(&id),
            Some(&incarnation)
        );
        assert!(
            transaction
                .world
                .asset_definitions
                .get(&id)
                .unwrap()
                .total_quantity()
                .is_zero()
        );
        transaction.apply();
        block.observe_quantity_block_journals();
        assert_eq!(
            block.fastpq_quantity_candidate.issue,
            Some(QuantityCaptureIssue::UnownedMutation)
        );
        assert_eq!(
            block.fastpq_quantity_candidate.commitments.coverage_gap(),
            Some(CoverageGap::RawQuantityWrite)
        );
    });
}
