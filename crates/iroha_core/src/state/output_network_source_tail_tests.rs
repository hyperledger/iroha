//! Actual source accounting across body rollback, mandatory settlement and supply changes.

use std::collections::BTreeMap;

use super::*;
use iroha_config::parameters::actual::{GasLiquidity, GasRate, GasVolatility};
use iroha_data_model::{
    asset::{AssetDefinitionId, AssetId},
    execution_witness::ExecutionWitnessKeyTagV1,
    fastpq::{
        TransferDeltaTranscript, TransferSmtWitness, TransferTranscript, TransferTranscriptBundle,
    },
    isi::{Mint, Transfer},
    parameter::FastpqSourcePolicyV1,
    transaction::{FeeChargeKind, FeeChargeLimit},
};
use iroha_primitives::numeric::{Numeric, Quantity};
use iroha_test_samples::{BOB_ID, CARPENTER_ID};

#[test]
fn intrinsic_body_rejection_keeps_only_pipeline_gas_transfer_under_the_original_entry() {
    let _fee_guard = crate::status::nexus_fee_test_lock().lock().unwrap();
    for batch in [false, true] {
        crate::status::reset_nexus_economics_for_tests();
        let asset = AssetDefinitionId::parse_address_literal(
            &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
        )
        .expect("canonical network XOR fee asset");
        let mut state = fixture_with_fee_asset(65_536, None, Some(asset.clone()));
        state.nexus.get_mut().fees.base_fee = Quantity::zero();
        let gas = iroha_config::parameters::actual::Gas {
            tech_account_id: CARPENTER_ID.to_string(),
            accepted_assets: vec![asset.canonical_address()],
            units_per_gas: vec![GasRate {
                asset: asset.canonical_address(),
                units_per_gas: 1,
                twap_local_per_xor: Numeric::one(),
                liquidity: GasLiquidity::Tier1,
                volatility: GasVolatility::Stable,
            }],
        };
        {
            let mut parameters = state.world.parameters.block();
            for parameter in crate::pipeline_gas_policy::parameters_for_testing(gas) {
                parameters
                    .get_mut()
                    .set_parameter(parameter)
                    .expect("valid fixture parameters");
            }
            parameters.commit();
        }
        let alice = AssetId::of(asset.clone(), ALICE_ID.clone());
        let bob = AssetId::of(asset.clone(), BOB_ID.clone());
        let tech = AssetId::of(asset.clone(), CARPENTER_ID.clone());
        let initial = Quantity::from(1_000_000_010_u64);
        {
            let (mut setup, _setup_recording) = output_fixture_setup(&state);
            let mut tx = setup.transaction_for_callback_testing();
            Register::account(Account::new(CARPENTER_ID.clone()))
                .execute(&ALICE_ID, &mut tx)
                .unwrap();
            Mint::asset_quantity(Quantity::from(1_000_000_000_u64), alice.clone())
                .execute(&ALICE_ID, &mut tx)
                .unwrap();
            tx.apply();
            setup.commit_world_overlay_for_testing().unwrap();
        }
        let mut parameters = state.world.parameters.block();
        let previous = parameters.get().block().fastpq_source();
        let mut intrinsic = previous.intrinsic;
        intrinsic.max_transcripts = 1;
        intrinsic.max_deltas = 1;
        let profile = FastpqSourcePolicyV1::from_sizing(
            parameters.get().block().execution_output(),
            intrinsic,
            previous.mandatory,
            1,
        )
        .unwrap();
        parameters
            .get_mut()
            .set_parameter(Parameter::Block(BlockParameter::FastpqSource(profile)))
            .expect("valid fixture parameters");
        parameters.commit();

        let marker: Name = "intrinsic_pipeline_body_rollback".parse().unwrap();
        let body = vec![
            SetKeyValue::account(ALICE_ID.clone(), marker.clone(), Json::new(9)).into(),
            Transfer::asset_quantity(alice.clone(), 1_u32, BOB_ID.clone()).into(),
            Transfer::asset_quantity(alice.clone(), 1_u32, BOB_ID.clone()).into(),
        ];
        let expected_gas = crate::gas::meter_instructions(&body, &crate::gas::DEFAULT_ZK_GAS)
            .expect("gas quote must complete for this fixture");
        assert!(expected_gas > 0 && expected_gas < 1_000_000_000);
        let fee = Quantity::from(expected_gas);
        let remaining = initial.checked_sub(&fee).unwrap();
        let entry = input(
            &state,
            body,
            FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::PipelineGas,
                    asset.clone(),
                    fee.clone(),
                )],
                NonZeroU64::new(expected_gas),
            ),
            batch,
        );
        let hash = Hash::from(entry.execution_call_hash());
        let source = carrier(&state, vec![entry]);
        let (mut block, _recording) = recorded_network_block(&state, &source);
        let fragments = block.committed_fragment_count();
        execute(&mut block, &source).unwrap();
        assert!(
            matches!(network_row(&block, 0).result.as_ref(),
            Err(iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
                iroha_data_model::ValidationFail::NotPermitted(reason)
            )) if reason == crate::fastpq::source_reservation::admission::SOURCE_INTRINSIC_REJECTION),
            "batch={batch}: {:?}",
            network_row(&block, 0).result
        );
        assert_eq!(block.world.assets().get(&alice).unwrap().0, remaining);
        assert!(
            block
                .world
                .assets()
                .get(&bob)
                .is_none_or(|value| value.0.is_zero())
        );
        assert_eq!(block.world.assets().get(&tech).unwrap().0, fee);
        assert_eq!(
            block
                .world
                .asset_definition(&asset)
                .unwrap()
                .total_quantity(),
            &initial
        );
        assert!(
            block
                .world
                .account(&ALICE_ID)
                .unwrap()
                .metadata()
                .get(&marker)
                .is_none()
        );
        assert_eq!(block.gas_used_in_block, expected_gas);
        assert_eq!(block.committed_fragment_count(), fragments + 1);
        assert!(network_row(&block, 0).completions.is_empty());

        let delta = TransferDeltaTranscript {
            from_account: ALICE_ID.clone(),
            to_account: CARPENTER_ID.clone(),
            asset_definition: asset,
            amount: fee.clone(),
            from_balance_before: initial,
            from_balance_after: remaining,
            to_balance_before: Quantity::zero(),
            to_balance_after: fee,
            from_smt_witness: TransferSmtWitness::default(),
            to_smt_witness: TransferSmtWitness::default(),
        };
        let expected = TransferTranscript {
            batch_hash: hash,
            authority_digest: crate::fastpq::authority_digest(&ALICE_ID),
            poseidon_preimage_digest: Some(crate::fastpq::poseidon_preimage_digest(&delta, &hash)),
            deltas: vec![delta],
        };
        assert_eq!(
            block.fastpq_transcripts,
            BTreeMap::from([(hash, vec![expected.clone()])])
        );
        let captured = block.captured_fastpq_transcript_sources().unwrap();
        assert_eq!(captured.len(), 1);
        assert!(!captured[&hash].is_protocol_purpose());
        let (ordinary, mandatory) = block.fastpq_source_usage_for_testing();
        assert_eq!(
            (
                ordinary.executed_entries,
                ordinary.transcripts,
                ordinary.deltas
            ),
            (1, 1, 1)
        );
        assert_eq!(
            ordinary.input_transcript_bytes,
            u64::try_from(norito::canonical_frame_len(&expected).unwrap()).unwrap()
        );
        assert_eq!(ordinary.max_statement_bytes, ordinary.total_statement_bytes);
        assert!(ordinary.max_statement_bytes > 0);
        assert_eq!(
            mandatory,
            crate::fastpq::source_reservation::SourceUsage::ZERO
        );
        let actual_witness = crate::exec_witness::drain_exec_witness();
        assert_eq!(
            actual_witness.fastpq_transcripts,
            vec![TransferTranscriptBundle {
                entry_hash: hash,
                transcripts: vec![expected],
            }]
        );
        let mut metadata_key = vec![ExecutionWitnessKeyTagV1::AccountMetadata as u8];
        metadata_key.extend_from_slice(ALICE_ID.to_string().as_bytes());
        metadata_key.push(0x1f);
        metadata_key.extend_from_slice(marker.as_ref().as_bytes());
        let mut business_asset_key = vec![ExecutionWitnessKeyTagV1::AssetBalance as u8];
        business_asset_key.extend_from_slice(bob.to_string().as_bytes());
        assert!(
            actual_witness
                .reads
                .iter()
                .chain(&actual_witness.writes)
                .all(|kv| { kv.key != metadata_key && kv.key != business_asset_key }),
            "rolled-back business reads and writes must not escape to the witness"
        );
    }
}

/// Serialize the actual public fields as one whole-entry frame without asserting a relation.
/// Fixed-width context fields affect values, not byte lengths; this is only a codec oracle.
fn unchecked_whole_entry_statement_bytes(bundle: &[TransferTranscript]) -> usize {
    use fastpq_prover::gadgets::public_transfer_statement::encode_quantity_units_v1;
    use iroha_data_model::fastpq::{
        FastpqOperationKind, FastpqPublicInputs, FastpqPublicTransferStatementV1,
        FastpqPublicTransferTranscriptV1, FastpqQuantityUnits, FastpqStateTransition,
        transfer_balance_key,
    };
    use iroha_primitives::numeric::MAX_DECIMAL_SCALE;

    let mut transitions = Vec::new();
    for transcript in bundle {
        for delta in &transcript.deltas {
            for (account, before, after) in [
                (
                    &delta.from_account,
                    &delta.from_balance_before,
                    &delta.from_balance_after,
                ),
                (
                    &delta.to_account,
                    &delta.to_balance_before,
                    &delta.to_balance_after,
                ),
            ] {
                let encode = |value| {
                    encode_quantity_units_v1(
                        &FastpqQuantityUnits::from_quantity(value, MAX_DECIMAL_SCALE).unwrap(),
                    )
                    .unwrap()
                };
                transitions.push(FastpqStateTransition {
                    key: transfer_balance_key(&delta.asset_definition, account).unwrap(),
                    pre_value: encode(before),
                    post_value: encode(after),
                    operation: FastpqOperationKind::Transfer,
                });
            }
        }
    }
    let frame = FastpqPublicTransferStatementV1 {
        public_inputs: FastpqPublicInputs {
            dsid: [0; 16],
            slot: 0,
            old_root: [0; 32],
            new_root: [0; 32],
            perm_root: [0; 32],
            tx_set_hash: [0; 32],
        },
        ordering_hash: [0; 32],
        transitions,
        transcripts: bundle
            .iter()
            .map(FastpqPublicTransferTranscriptV1::from)
            .collect(),
    };
    norito::encode_canonical(&frame).unwrap().len()
}

#[test]
fn transfer_mint_transfer_keeps_one_accounted_entry_before_d7_relation_activation() {
    let _fee_guard = crate::status::nexus_fee_test_lock().lock().unwrap();
    for batch in [false, true] {
        crate::status::reset_nexus_economics_for_tests();
        let asset = AssetDefinitionId::parse_address_literal(
            &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
        )
        .expect("canonical network XOR fee asset");
        let mut state = fixture_with_fee_asset(65_536, None, Some(asset.clone()));
        state.nexus.get_mut().fees.base_fee = Quantity::zero();
        let alice = AssetId::of(asset.clone(), ALICE_ID.clone());
        let bob = AssetId::of(asset.clone(), BOB_ID.clone());
        let entry = input(
            &state,
            vec![
                Transfer::asset_quantity(alice.clone(), 1_u32, BOB_ID.clone()).into(),
                Mint::asset_quantity(5_u32, alice.clone()).into(),
                Transfer::asset_quantity(alice.clone(), 2_u32, BOB_ID.clone()).into(),
            ],
            FeePaymentIntent::authority(vec![], None),
            batch,
        );
        let hash = Hash::from(entry.execution_call_hash());
        let mut source = carrier(&state, vec![entry]);
        let (mut block, _recording) = recorded_network_block(&state, &source);
        block.reserve_ordinary_execution_outputs(&source).unwrap();
        block.execute_ordinary_output_plan(&source, None).unwrap();
        assert!(
            network_row(&block, 0).result.is_ok(),
            "batch={batch}: {:?}",
            network_row(&block, 0).result
        );
        assert_eq!(
            block.world.assets().get(&alice).unwrap().0,
            Quantity::from(12_u32)
        );
        assert_eq!(
            block.world.assets().get(&bob).unwrap().0,
            Quantity::from(3_u32)
        );
        assert_eq!(
            block
                .world
                .asset_definition(&asset)
                .unwrap()
                .total_quantity(),
            &Quantity::from(15_u32)
        );
        assert_eq!(block.fastpq_transcripts.len(), 1);
        let bundle = block.fastpq_transcripts[&hash].clone();
        assert_eq!(bundle.len(), 2);
        for (transcript, (amount, from_before, from_after, to_before, to_after)) in bundle
            .iter()
            .zip([(1_u32, 10_u32, 9_u32, 0_u32, 1_u32), (2, 14, 12, 1, 3)])
        {
            assert_eq!(transcript.batch_hash, hash);
            assert_eq!(
                transcript.authority_digest,
                crate::fastpq::authority_digest(&ALICE_ID)
            );
            assert_eq!(transcript.deltas.len(), 1);
            let delta = &transcript.deltas[0];
            assert_eq!(
                (
                    &delta.from_account,
                    &delta.to_account,
                    &delta.asset_definition
                ),
                (&*ALICE_ID, &*BOB_ID, &asset)
            );
            assert_eq!(delta.amount, Quantity::from(amount));
            assert_eq!(delta.from_balance_before, Quantity::from(from_before));
            assert_eq!(delta.from_balance_after, Quantity::from(from_after));
            assert_eq!(delta.to_balance_before, Quantity::from(to_before));
            assert_eq!(delta.to_balance_after, Quantity::from(to_after));
            assert_eq!(
                transcript.poseidon_preimage_digest,
                Some(crate::fastpq::poseidon_preimage_digest(delta, &hash))
            );
        }
        let input_bytes: usize = bundle
            .iter()
            .map(|transcript| norito::encode_canonical(transcript).unwrap().len())
            .sum();
        let statement_bytes = unchecked_whole_entry_statement_bytes(&bundle);
        assert!(
            statement_bytes
                < bundle
                    .iter()
                    .map(
                        |transcript| unchecked_whole_entry_statement_bytes(std::slice::from_ref(
                            transcript
                        ))
                    )
                    .sum::<usize>()
        );
        let usage_before = block.fastpq_source_usage_for_testing();
        let (ordinary, mandatory) = usage_before;
        assert_eq!(
            (
                ordinary.executed_entries,
                ordinary.transcripts,
                ordinary.deltas
            ),
            (1, 2, 2)
        );
        assert_eq!(
            ordinary.input_transcript_bytes,
            u64::try_from(input_bytes).unwrap()
        );
        assert_eq!(
            ordinary.max_statement_bytes,
            u64::try_from(statement_bytes).unwrap()
        );
        assert_eq!(ordinary.total_statement_bytes, ordinary.max_statement_bytes);
        assert_eq!(
            mandatory,
            crate::fastpq::source_reservation::SourceUsage::ZERO
        );

        // Use the actual consuming output seal: it finalizes the owned source
        // inventory, reconciles quotas, and attaches the complete original archive.
        block
            .seal_execution_outputs::<String>(&mut source, |block, source, routes| {
                assert_eq!(routes.len(), 1);
                Ok(crate::state::ExecutionOutputSealMetadata {
                    sccp_finality_header:
                        iroha_data_model::sumeragi_finality::SccpFinalityHeaderV1::inactive(
                            *block.network_id().as_bytes(),
                            source.header().height().get(),
                            source.header().creation_time_ms,
                        )
                        .expect("nonzero fixture height"),
                    committed_fragment_count: u64::try_from(block.committed_fragment_count())
                        .unwrap(),
                })
            })
            .unwrap();
        block.verify_execution_output_seal(&source).unwrap();
        let inventory = block.fastpq_source_inventory().unwrap().unwrap();
        assert_eq!(inventory.entries().len(), 1);
        assert_eq!(inventory.entries()[0].entry_hash, hash);
        assert_eq!(
            inventory
                .transcript_entry_hashes()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![hash]
        );
        assert_eq!(block.fastpq_source_usage_for_testing(), usage_before);
        assert!(block.fastpq_transcripts.is_empty());
        assert_eq!(
            source.fastpq_transcripts(),
            &BTreeMap::from([(hash, bundle.clone())])
        );

        // The live transfer-only diagnostic must still reject a supply gap.
        // The mandatory source below instead commits the complete ordered tape.
        let limits = crate::fastpq::FastpqSourceStatementBuildLimits {
            max_executed_entries: 1,
            max_transcripts: 2,
            max_deltas: 2,
            max_input_transcript_bytes: input_bytes,
            max_statement_bytes: statement_bytes,
            max_total_statement_bytes: statement_bytes,
        };
        let error = block
            .prepare_owned_transfer_diagnostic(source.fastpq_transcripts(), limits)
            .unwrap_err();
        assert!(
            error.contains("public repeated-key balances do not chain"),
            "{error}"
        );
        assert!(block.fastpq_source_inventory().unwrap().is_some());
        assert_eq!(block.fastpq_source_usage_for_testing(), usage_before);
        assert!(block.exec_witness.is_none());
        assert!(block.fastpq_witness_context.is_none());
        let inventory = block
            .verified_fastpq_source_inventory_for_capture()
            .unwrap();
        let captured = crate::exec_witness::drain_exec_witness_checked(|raw| {
            inventory.verify_finalized_transcript_map(raw)
        })
        .unwrap();
        assert_eq!(
            captured.fastpq_transcripts,
            vec![TransferTranscriptBundle {
                entry_hash: hash,
                transcripts: bundle
            }]
        );
        inventory
            .verify_ordinary_witness_bundles(&captured.fastpq_transcripts)
            .unwrap();
        assert!(captured.writes.iter().all(|write| write.key.first()
            != Some(&(ExecutionWitnessKeyTagV1::FastpqOrdinarySourceStatements as u8))));
        let retained = block.retain_quantity_source_witness(captured).unwrap();
        assert_eq!(retained.manifest().executed_entry_count, 1);
        assert_eq!(retained.manifest().statement_count, 1);
        let entry = retained.quantity_entry(0).unwrap();
        assert_eq!(entry.leaf().effect_count, 3);
        let effects = &entry.effects().effects;
        assert_eq!(effects.len(), 3);
        assert!(matches!(
            effects[0].kind,
            iroha_data_model::fastpq::FastpqExecutionEffectKindV1::Transfer(_)
        ));
        assert!(matches!(
            effects[1].kind,
            iroha_data_model::fastpq::FastpqExecutionEffectKindV1::Mint(_)
        ));
        assert!(matches!(
            effects[2].kind,
            iroha_data_model::fastpq::FastpqExecutionEffectKindV1::Transfer(_)
        ));
        assert_eq!(
            <[u8; 32]>::from(
                iroha_data_model::fastpq::execution_effects_digest_v1(entry.effects()).unwrap()
            ),
            entry.leaf().effects_digest
        );
        assert_eq!(
            retained
                .writes
                .iter()
                .filter(|write| write.key.first()
                    == Some(&(ExecutionWitnessKeyTagV1::FastpqOrdinarySourceStatements as u8)))
                .count(),
            1
        );
        assert!(retained.verify_current(&block).is_ok());
    }
}
