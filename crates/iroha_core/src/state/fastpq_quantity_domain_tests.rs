//! Actual ledger transfers and source inventory across the complete quantity domain.

use super::*;
use crate::{query::store::LiveQueryStore, smartcontracts::Execute as _};
use iroha_data_model::{
    fastpq::{FastpqQuantityUnits, transfer_asset_scales},
    isi::{Mint, Transfer},
};
use iroha_primitives::{bigint::BigInt, numeric::Numeric};
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID, gen_account_in};
use nonzero_ext::nonzero;

/// Bind the original recorder to this empty carrier before component effects.
#[expect(
    clippy::large_types_passed_by_value,
    reason = "the signed block builder owns the supplied header"
)]
fn quantity_component_source(header: BlockHeader) -> SignedBlock {
    iroha_data_model::block::builder::BlockBuilder::new(header)
        .build_with_signature(0, ALICE_KEYPAIR.private_key())
}

#[test]
fn direct_quantity_component_refuses_an_unretained_hash_and_keeps_original_balances() {
    let domain = DomainId::try_new("quantity-owner", "universal").unwrap();
    let definition =
        AssetDefinitionId::derive_from_components(domain.clone(), "units".parse().unwrap());
    let alice = AssetId::new(definition.clone(), ALICE_ID.clone());
    let bob = AssetId::new(definition.clone(), BOB_ID.clone());
    let world = World::with_assets(
        [Domain::new(domain).build(&ALICE_ID)],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&BOB_ID),
        ],
        [AssetDefinition::numeric(
            definition,
            "Units",
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID)],
        [Asset::new(alice.clone(), Quantity::from(10_u32))],
        [],
    );
    let state = State::new(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let original = quantity_component_source(BlockHeader::new(nonzero!(2_u64), None, None, 7, 0));
    let (mut block, _recording) =
        crate::block::ValidBlock::start_component_execution(&original, &state)
            .expect("original component recorder");
    let invocation = Hash::new(b"original-direct-quantity-source");
    {
        let mut tx = block.transaction();
        tx.tx_call_hash = Some(invocation);
        let error = Transfer::asset_quantity(alice.clone(), 1_u32, BOB_ID.clone())
            .execute(&ALICE_ID, &mut tx)
            .expect_err("a copied hash cannot supply its original producer");
        assert!(
            error
                .to_string()
                .contains("FASTPQ source has no retained producer invocation")
        );
        assert_eq!(
            tx.world.assets.get(&alice).unwrap().as_ref(),
            &Quantity::from(10_u32)
        );
        assert!(tx.world.assets.get(&bob).is_none());
    }
    assert!(matches!(
        block.execution_output_plan,
        Some(crate::state::output_capacity::ExecutionOutputPlanState::Poisoned),
    ));
    // An unowned movement poisons its carrier. A positive component must obtain
    // a fresh original recorder over the unchanged State rather than replace it.
    drop((block, _recording));
    {
        let view = state.view();
        assert_eq!(
            view.world.assets.get(&alice).unwrap().as_ref(),
            &Quantity::from(10_u32)
        );
        assert!(view.world.assets.get(&bob).is_none());
    }
    let (mut block, _recording) =
        crate::block::ValidBlock::start_component_execution(&original, &state)
            .expect("fresh original component recorder after refused owner drops");
    let mut tx = block.transaction_for_fastpq_testing(invocation);
    Transfer::asset_quantity(alice.clone(), 1_u32, BOB_ID.clone())
        .execute(&ALICE_ID, &mut tx)
        .expect("the same exact invocation now has finite original custody");
    assert_eq!(
        tx.world.assets.get(&alice).unwrap().as_ref(),
        &Quantity::from(9_u32)
    );
    assert_eq!(
        tx.world.assets.get(&bob).unwrap().as_ref(),
        &Quantity::one()
    );
}

#[test]
fn ledger_transfers_and_owned_inventory_preserve_quantities_beyond_u64_units() {
    std::thread::Builder::new()
        .name("fastpq_full_quantity_ledger".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(check_full_quantity_ledger)
        .unwrap()
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

fn check_full_quantity_ledger() {
    let mut maximum_bytes = [0xff_u8; 64];
    maximum_bytes[63] = 0x7f;
    let maximum = Quantity::from_canonical_numeric(
        Numeric::try_new(BigInt::from_twos_bytes(&maximum_bytes).unwrap(), 0).unwrap(),
    )
    .unwrap();
    let tiny = Quantity::from_canonical_numeric(Numeric::try_new(1_u32, 28).unwrap()).unwrap();
    let cases = [
        (Quantity::from(u128::MAX), Quantity::zero(), Quantity::one()),
        (maximum.clone(), Quantity::zero(), maximum.clone()),
        (
            maximum.try_sub(&Quantity::one()).unwrap(),
            tiny.clone(),
            Quantity::one(),
        ),
        (Quantity::from(2_u32), Quantity::zero(), tiny),
    ];
    for (index, (from_before, to_before, amount)) in cases.into_iter().enumerate() {
        let domain_id = DomainId::try_new("wonderland", "universal").unwrap();
        let definition_id =
            AssetDefinitionId::derive_from_components(domain_id.clone(), "rose".parse().unwrap());
        let source_id = AssetId::new(definition_id.clone(), ALICE_ID.clone());
        let destination_id = AssetId::new(definition_id.clone(), BOB_ID.clone());
        let (reserve, _) = gen_account_in("reserve");
        let reserve_id = AssetId::new(definition_id.clone(), reserve.clone());
        let world = World::with(
            [Domain::new(domain_id).build(&ALICE_ID)],
            [
                Account::new(ALICE_ID.clone()).build(&ALICE_ID),
                Account::new(BOB_ID.clone()).build(&BOB_ID),
                Account::new(reserve.clone()).build(&reserve),
            ],
            [AssetDefinition::numeric(
                definition_id.clone(),
                "rose",
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&ALICE_ID)],
        );
        let state = State::new(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let initial_supply = if index == 2 {
            maximum.clone()
        } else {
            from_before.clone()
        };
        // Seed through real mint/transfer instructions. The mixed-scale case
        // retains a third balance so total supply remains the canonical maximum.
        let mut setup = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 6, 0));
        {
            let mut tx = setup.transaction_for_fastpq_testing(Hash::new(format!(
                "quantity-fixture-mint-{index}"
            )));
            Mint::asset_quantity(initial_supply.clone(), source_id.clone())
                .execute(&ALICE_ID, &mut tx)
                .unwrap();
            tx.apply();
        }
        if index == 2 {
            {
                let mut tx = setup
                    .transaction_for_fastpq_testing(Hash::new(b"quantity-fixture-whole-transfer"));
                Transfer::asset_quantity(source_id.clone(), Quantity::one(), BOB_ID.clone())
                    .execute(&ALICE_ID, &mut tx)
                    .unwrap();
                tx.apply();
            }
            {
                let mut tx = setup.transaction_for_fastpq_testing(Hash::new(
                    b"quantity-fixture-fractional-transfer",
                ));
                Transfer::asset_quantity(
                    destination_id.clone(),
                    Quantity::one().try_sub(&to_before).unwrap(),
                    reserve.clone(),
                )
                .execute(&BOB_ID, &mut tx)
                .unwrap();
                tx.apply();
            }
        }
        setup.commit_world_overlay_for_testing().unwrap();
        let header = BlockHeader::new(nonzero!(2_u64), None, None, 7, 0);
        let source = quantity_component_source(header);
        let (mut block, _recording) =
            crate::block::ValidBlock::start_component_execution(&source, &state)
                .expect("original full-domain component recorder");
        assert_eq!(
            block
                .world
                .asset_definitions
                .get(&definition_id)
                .unwrap()
                .total_quantity(),
            &initial_supply
        );
        assert_eq!(
            block
                .world
                .assets
                .get(&source_id)
                .map(|value| value.as_ref().clone())
                .unwrap_or_else(Quantity::zero),
            from_before
        );
        assert_eq!(
            block
                .world
                .assets
                .get(&destination_id)
                .map(|value| value.as_ref().clone())
                .unwrap_or_else(Quantity::zero),
            to_before
        );
        if index == 2 {
            assert_eq!(
                block.world.assets.get(&reserve_id).unwrap().as_ref(),
                &Quantity::one().try_sub(&to_before).unwrap()
            );
        }
        let call = Hash::new(format!("full-quantity-ledger-case-{index}"));
        let from_after = from_before.try_sub(&amount).unwrap();
        let to_after = to_before.try_add(&amount).unwrap();
        {
            let mut tx = block.transaction_for_fastpq_testing(call);
            Transfer::asset_quantity(source_id.clone(), amount.clone(), BOB_ID.clone())
                .execute(&ALICE_ID, &mut tx)
                .unwrap();
            tx.apply();
        }
        let observed_source = block
            .world
            .assets
            .get(&source_id)
            .map(|value| value.as_ref().clone())
            .unwrap_or_else(Quantity::zero);
        let observed_destination = block
            .world
            .assets
            .get(&destination_id)
            .map(|value| value.as_ref().clone())
            .unwrap_or_else(Quantity::zero);
        assert_eq!(observed_source, from_after);
        assert_eq!(observed_destination, to_after);
        assert_eq!(
            block
                .world
                .asset_definitions
                .get(&definition_id)
                .unwrap()
                .total_quantity(),
            &initial_supply
        );
        // Direct fixture execution has no external or time entrypoint wires.
        let tx_set_hash: [u8; 32] =
            iroha_data_model::nexus::axt_ordered_transaction_set_digest_v1(std::iter::empty::<
                &iroha_data_model::transaction::TransactionEntrypoint,
            >())
            .unwrap()
            .into();
        block.set_fastpq_tx_set_hash(tx_set_hash);
        block
            .finalize_fastpq_source_inventory(&[], &[], &[])
            .unwrap();
        let inventory = block.fastpq_source_inventory().unwrap().unwrap().clone();
        assert_eq!(inventory.tx_set_hash(), tx_set_hash);
        assert_eq!(inventory.entries().len(), 1);
        assert!(inventory.transcript_entry_hashes().contains(&call));
        let transcripts = block.drain_transfer_transcripts();
        let bundle = &transcripts[&call];
        assert_eq!(bundle.len(), 1);
        assert_eq!(bundle[0].deltas.len(), 1);
        let delta = &bundle[0].deltas[0];
        assert_eq!(delta.amount, amount);
        assert_eq!(delta.from_balance_before, from_before);
        assert_eq!(delta.from_balance_after, from_after);
        assert_eq!(delta.to_balance_before, to_before);
        assert_eq!(delta.to_balance_after, to_after);
        let scale = transfer_asset_scales(bundle)[&definition_id];
        let units = |quantity| FastpqQuantityUnits::from_quantity(quantity, scale).unwrap();
        assert_eq!(
            units(&from_before).checked_sub(&units(&amount)),
            Some(units(&from_after))
        );
        assert_eq!(
            units(&to_before).checked_add(&units(&amount)),
            Some(units(&to_after))
        );
        assert!(units(&from_before).try_to_u64().is_none());
        if index == 2 {
            assert_ne!(
                units(&from_before).limbs()[18],
                0,
                "valid ledger execution needs all nineteen unit limbs"
            );
        }
        // The fixed-width prover rejects wide values. The full-domain source
        // producer below must succeed; compact proof integration is the next gate.
        let result = crate::fastpq::batch_and_public_statement_from_finalized_transcripts(
            crate::fastpq::FASTPQ_CANONICAL_PARAMETER_SET,
            crate::fastpq::FastpqPublicInputsTemplate {
                dsid: crate::fastpq::dataspace_id_bytes(DataSpaceId::UNIVERSAL),
                slot: 7,
                old_root: [0; 32],
                new_root: [0; 32],
                perm_root: [0; 32],
            }
            .with_tx_set_hash(inventory.tx_set_hash()),
            bundle,
        );
        assert!(
            matches!(
                &result,
                Err(crate::fastpq::FinalizedPublicStatementError::Batch(
                    crate::fastpq::TranscriptBatchError::TransferWitness {
                        source: fastpq_prover::Error::TransferNumericBounds { .. }
                    }
                ))
            ),
            "case {index}: {result:?}"
        );
        let limits = crate::fastpq::FastpqSourceStatementBuildLimits {
            max_executed_entries: 1,
            max_transcripts: 1,
            max_deltas: 1,
            max_input_transcript_bytes: 1_000_000,
            max_statement_bytes: 1_000_000,
            max_total_statement_bytes: 1_000_000,
        };
        let produced = crate::fastpq::quantity_statement_from_finalized_transcripts_for_testing(
            crate::fastpq::FastpqPublicInputsTemplate {
                dsid: crate::fastpq::dataspace_id_bytes(DataSpaceId::UNIVERSAL),
                slot: 7,
                old_root: [0; 32],
                new_root: [0; 32],
                perm_root: [0; 32],
            }.with_tx_set_hash(inventory.tx_set_hash()),
            bundle,
            fastpq_prover::gadgets::public_transfer_statement::PublicTransferLimits::default(),
            fastpq_prover::gadgets::public_transfer_statement::TransferSmtBuildLimits::for_update_limit(2).unwrap(),
        ).unwrap();
        let statement = produced.statement();
        assert_eq!(
            statement.transcripts,
            vec![iroha_data_model::fastpq::FastpqPublicTransferTranscriptV1::from(&bundle[0])]
        );
        assert_eq!(
            produced.witnesses().roots(),
            (
                statement.public_inputs.old_root,
                statement.public_inputs.new_root
            )
        );
        assert_eq!(produced.witnesses().pairs().len(), 1);
        let (manifest, leaves) = inventory
            .prepare_transfer_diagnostic(7, [0; 32], &transcripts, limits)
            .unwrap();
        assert_eq!(manifest.statement_count, 1);
        assert_eq!(leaves.len(), 1);
        assert_eq!(
            leaves[0].statement_digest,
            <[u8; 32]>::from(Hash::new(norito::encode_canonical(statement).unwrap()))
        );
        assert_eq!(block.fastpq_source_inventory().unwrap(), Some(&inventory));
    }
}

#[test]
fn ledger_supply_changes_between_transfers_preserve_every_source_occurrence() {
    std::thread::Builder::new()
        .name("fastpq_intervening_supply".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(check_supply_changes_between_transfers)
        .unwrap()
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

fn check_supply_changes_between_transfers() {
    use iroha_data_model::isi::Burn;

    for mint in [true, false] {
        let domain = DomainId::try_new("wonderland", "universal").unwrap();
        let definition =
            AssetDefinitionId::derive_from_components(domain.clone(), "rose".parse().unwrap());
        let source = AssetId::new(definition.clone(), ALICE_ID.clone());
        let destination = AssetId::new(definition.clone(), BOB_ID.clone());
        let state = State::new(
            World::with(
                [Domain::new(domain).build(&ALICE_ID)],
                [
                    Account::new(ALICE_ID.clone()).build(&ALICE_ID),
                    Account::new(BOB_ID.clone()).build(&BOB_ID),
                ],
                [AssetDefinition::numeric(
                    definition.clone(),
                    "rose",
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
                .build(&ALICE_ID)],
            ),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut setup = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 6, 0));
        {
            let mut tx =
                setup.transaction_for_fastpq_testing(Hash::new(b"mixed-source-initial-mint"));
            Mint::asset_quantity(100_u32, source.clone())
                .execute(&ALICE_ID, &mut tx)
                .unwrap();
            tx.apply();
        }
        setup.commit_world_overlay_for_testing().unwrap();
        let original =
            quantity_component_source(BlockHeader::new(nonzero!(2_u64), None, None, 7, 0));
        let (mut block, _recording) =
            crate::block::ValidBlock::start_component_execution(&original, &state)
                .expect("original mixed-supply component recorder");
        let call = Hash::new(if mint {
            b"transfer-mint-transfer".as_slice()
        } else {
            b"transfer-burn-transfer".as_slice()
        });
        {
            let mut tx = block.transaction_for_fastpq_testing(call);
            Transfer::asset_quantity(source.clone(), 10_u32, BOB_ID.clone())
                .execute(&ALICE_ID, &mut tx)
                .unwrap();
            if mint {
                Mint::asset_quantity(5_u32, source.clone())
                    .execute(&ALICE_ID, &mut tx)
                    .unwrap();
            } else {
                Burn::asset_quantity(5_u32, source.clone())
                    .execute(&ALICE_ID, &mut tx)
                    .unwrap();
            }
            Transfer::asset_quantity(source.clone(), 10_u32, BOB_ID.clone())
                .execute(&ALICE_ID, &mut tx)
                .unwrap();
            tx.apply();
        }
        let final_source = Quantity::from(if mint { 85_u32 } else { 75_u32 });
        let supply = Quantity::from(if mint { 105_u32 } else { 95_u32 });
        assert_eq!(
            block.world.assets.get(&source).unwrap().as_ref(),
            &final_source
        );
        assert_eq!(
            block.world.assets.get(&destination).unwrap().as_ref(),
            &Quantity::from(20_u32)
        );
        assert_eq!(
            block
                .world
                .asset_definitions
                .get(&definition)
                .unwrap()
                .total_quantity(),
            &supply
        );
        // Direct fixture execution has no external or time entrypoint wires.
        let tx_set_hash: [u8; 32] =
            iroha_data_model::nexus::axt_ordered_transaction_set_digest_v1(std::iter::empty::<
                &iroha_data_model::transaction::TransactionEntrypoint,
            >())
            .unwrap()
            .into();
        block.set_fastpq_tx_set_hash(tx_set_hash);
        block
            .finalize_fastpq_source_inventory(&[], &[], &[])
            .unwrap();
        let inventory = block.fastpq_source_inventory().unwrap().unwrap().clone();
        assert_eq!(inventory.tx_set_hash(), tx_set_hash);
        let transcripts = block.drain_transfer_transcripts();
        let bundle = &transcripts[&call];
        assert_eq!(inventory.entries().len(), 1);
        assert_eq!(transcripts.len(), 1);
        assert_eq!(bundle.len(), 2);
        assert!(
            bundle
                .iter()
                .all(|t| t.batch_hash == call && t.deltas.len() == 1)
        );
        assert_eq!(
            bundle[0].deltas[0].from_balance_before,
            Quantity::from(100_u32)
        );
        assert_eq!(
            bundle[0].deltas[0].from_balance_after,
            Quantity::from(90_u32)
        );
        assert_eq!(
            bundle[1].deltas[0].from_balance_before,
            Quantity::from(if mint { 95_u32 } else { 85_u32 })
        );
        assert_eq!(bundle[1].deltas[0].from_balance_after, final_source);
        assert_eq!(
            bundle[0].deltas[0].to_balance_after,
            bundle[1].deltas[0].to_balance_before
        );
        let original = norito::encode_canonical(bundle).unwrap();
        let limits = crate::fastpq::FastpqSourceStatementBuildLimits {
            max_executed_entries: 1,
            max_transcripts: 2,
            max_deltas: 2,
            max_input_transcript_bytes: 1_000_000,
            max_statement_bytes: 1_000_000,
            max_total_statement_bytes: 1_000_000,
        };
        // TODO: the final complete execution relation must cover intervening supply
        // changes. The transfer-only whole-entry manifest cannot hide this gap by
        // splitting the original operations into separately valid source leaves.
        let calls = crate::fastpq::quantity_materializer_invocations_for_testing();
        let manifest_error = inventory
            .prepare_transfer_diagnostic(7, [0; 32], &transcripts, limits)
            .unwrap_err();
        assert!(
            manifest_error.contains("public repeated-key balances do not chain"),
            "{manifest_error}"
        );
        assert_eq!(
            crate::fastpq::quantity_materializer_invocations_for_testing(),
            calls
        );
        assert_eq!(inventory.entries().len(), 1);
        assert_eq!(bundle.len(), 2);
        let inputs = crate::fastpq::FastpqPublicInputsTemplate {
            dsid: crate::fastpq::dataspace_id_bytes(DataSpaceId::UNIVERSAL),
            slot: 7,
            old_root: [0; 32],
            new_root: [0; 32],
            perm_root: [0; 32],
        }
        .with_tx_set_hash(inventory.tx_set_hash());
        let public_limits =
            fastpq_prover::gadgets::public_transfer_statement::PublicTransferLimits::default();
        let tree_limits = fastpq_prover::gadgets::public_transfer_statement::TransferSmtBuildLimits::for_update_limit(4).unwrap();
        let error = crate::fastpq::quantity_statement_from_finalized_transcripts_for_testing(
            inputs.clone(),
            bundle,
            public_limits,
            tree_limits,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("public repeated-key balances do not chain"),
            "{error}"
        );
        // Each individual operation remains mathematically valid, but these are
        // independent arithmetic controls, never a manifest fallback producer.
        for (index, transcript) in bundle.iter().enumerate() {
            assert_eq!(transcript.batch_hash, call);
            let produced =
                crate::fastpq::quantity_statement_from_finalized_transcripts_for_testing(
                    inputs.clone(),
                    std::slice::from_ref(&bundle[index]),
                    public_limits,
                    tree_limits,
                )
                .unwrap();
            assert_eq!(
                produced.statement().transcripts,
                vec![
                    iroha_data_model::fastpq::FastpqPublicTransferTranscriptV1::from(
                        &bundle[index]
                    )
                ]
            );
            let bytes = norito::encode_canonical(produced.statement()).unwrap();
            let decoded = norito::decode_canonical::<
                iroha_data_model::fastpq::FastpqPublicTransferStatementV1,
            >(&bytes)
            .unwrap();
            assert_eq!(&decoded, produced.statement());
        }
        assert_eq!(norito::encode_canonical(bundle).unwrap(), original);
        assert_eq!(block.fastpq_source_inventory().unwrap(), Some(&inventory));
    }
}
