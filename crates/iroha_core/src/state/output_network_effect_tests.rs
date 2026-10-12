//! Real signed execution limits, callback scope and effect-owner failure controls.
//! These exercise State overlays; they do not qualify the canonical carrier driver.

use super::*;
use crate::{executor::Executor, smartcontracts::ivm::cache::IvmCache};
use iroha_data_model::{
    ValidationFail,
    asset::{AssetDefinitionId, AssetId},
    transaction::{
        FeeChargeKind, FeeChargeLimit, SignedTransaction, error::TransactionRejectionReason,
    },
};
use iroha_model_base::topology::{DataSpaceId, LaneId};
use iroha_primitives::numeric::Quantity;
use norito::codec::Encode;

fn write() -> InstructionBox {
    SetKeyValue::account(
        ALICE_ID.clone(),
        "effect_write".parse().unwrap(),
        Json::new(1),
    )
    .into()
}

fn bind_root(transaction: &mut StateTransaction<'_, '_>, signed: &SignedTransaction) {
    transaction.current_entrypoint_index = Some(0);
    transaction.tx_call_hash = Some(Hash::from(signed.hash_as_entrypoint()));
    transaction.current_tx_hash = Some(signed.hash());
    transaction.current_lane_id = Some(LaneId::SINGLE);
    transaction.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    transaction.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
}

#[test]
fn preparation_refusal_is_fee_free_but_admitted_business_failure_charges_actual_work() {
    let _fee_guard = crate::status::nexus_fee_test_lock().lock().unwrap();
    for batch in [false, true] {
        for maximum in [1, 2] {
            let asset = AssetDefinitionId::parse_address_literal(
                &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
            )
            .expect("canonical network XOR fee asset");
            let state = fixture_with_policy(65_536, None, Some(asset.clone()), |policy| {
                policy.overlay_max_instructions = maximum;
                policy.overlay_max_bytes = 0;
            });
            let source = carrier(
                &state,
                vec![input(
                    &state,
                    vec![
                        write(),
                        Unregister::trigger("missing_effect_trigger".parse().unwrap()).into(),
                    ],
                    FeePaymentIntent::authority(
                        vec![FeeChargeLimit::new(
                            FeeChargeKind::Nexus,
                            asset.clone(),
                            Quantity::from(1_u32),
                        )],
                        None,
                    ),
                    batch,
                )],
            );
            let (mut block, _recording) = recorded_network_block(&state, &source);
            let fragments = block.committed_fragment_count();
            execute(&mut block, &source).unwrap();
            let result = network_row(&block, 0).result.as_ref();
            assert!(result.is_err());
            if maximum == 1 {
                assert!(matches!(result,
                    Err(TransactionRejectionReason::Validation(ValidationFail::NotPermitted(reason)))
                    if reason == "overlay exceeds max instructions: 2 > 1"));
            } else {
                assert!(!matches!(result,
                    Err(TransactionRejectionReason::Validation(ValidationFail::NotPermitted(reason)))
                    if reason.starts_with("overlay exceeds max")));
            }
            let expected = Quantity::from(if maximum == 1 { 10_u32 } else { 9 });
            assert_eq!(
                block
                    .world
                    .assets()
                    .get(&AssetId::of(asset.clone(), ALICE_ID.clone()))
                    .unwrap()
                    .0,
                expected
            );
            assert!(
                block
                    .world
                    .assets()
                    .get(&AssetId::of(
                        asset.clone(),
                        iroha_test_samples::BOB_ID.clone()
                    ))
                    .is_none_or(|balance| balance.0 == Quantity::zero())
            );
            assert_eq!(
                block
                    .world
                    .asset_definition(&asset)
                    .unwrap()
                    .total_quantity(),
                &expected
            );
            assert!(
                block
                    .world
                    .account(&ALICE_ID)
                    .unwrap()
                    .metadata()
                    .get("effect_write")
                    .is_none()
            );
            assert_eq!(
                block.committed_fragment_count(),
                fragments + usize::from(maximum == 2)
            );
            assert_eq!(block.gas_used_in_block > 0, maximum == 2);
            assert!(network_row(&block, 0).completions.is_empty());
        }
    }
}

#[test]
fn actual_by_call_callback_keeps_its_separate_instruction_scope() {
    let root: InstructionBox = ExecuteTrigger::new("network_callback".parse().unwrap()).into();
    let direct_gas =
        crate::gas::meter_instructions(std::slice::from_ref(&root), &crate::gas::DEFAULT_ZK_GAS);
    let state = fixture_with_policy(65_536, Some(512), None, |policy| {
        policy.overlay_max_instructions = 1;
        policy.overlay_max_bytes = u64::try_from(root.encode().len()).unwrap();
    });
    let source = carrier(
        &state,
        vec![input(
            &state,
            vec![root],
            FeePaymentIntent::authority(vec![], None),
            false,
        )],
    );
    let (mut block, _recording) = recorded_network_block(&state, &source);
    execute(&mut block, &source).unwrap();
    assert!(
        network_row(&block, 0).result.is_ok(),
        "{:?}",
        network_row(&block, 0).result
    );
    assert!(!network_row(&block, 0).completions.is_empty());
    assert_eq!(
        block
            .world
            .account(&ALICE_ID)
            .unwrap()
            .metadata()
            .get("callback_write"),
        Some(&Json::new(7))
    );
    assert!(block.gas_used_in_block > direct_gas);
}

fn actual_generic_ivm_callback_output(quarantine: bool) -> (NetworkExecutionOutputV1, u64) {
    use iroha_data_model::{isi::Grant, transaction::IvmBytecode};
    use ivm::{encoding::wide, instruction::wide as opcode, pointer_abi::PointerType};
    let id: TriggerId = "generic_effect_callback".parse().unwrap();
    let instruction: InstructionBox = ExecuteTrigger::new(id.clone()).into();
    // Both executions sign the same policy into genesis. The selected signed root
    // may spend one VM cycle; the five-opcode callback keeps its own trigger scope.
    let state = fixture_with_policy(65_536, None, None, |policy| {
        policy.quarantine_max_txs_per_block = 1;
        policy.quarantine_tx_max_cycles = 1;
        policy.overlay_max_instructions = 1;
        policy.overlay_max_bytes = u64::try_from(instruction.encode().len()).unwrap();
    });
    let key: Name = "generic_callback_write".parse().unwrap();
    let literals: Vec<Vec<u8>> = [
        (
            PointerType::AccountId,
            norito::to_bytes(&*ALICE_ID).unwrap(),
        ),
        (PointerType::Name, norito::to_bytes(&key).unwrap()),
        (PointerType::Json, norito::to_bytes(&Json::new(9)).unwrap()),
    ]
    .into_iter()
    .map(|(kind, payload)| {
        let mut tlv = (kind as u16).to_be_bytes().to_vec();
        tlv.push(1);
        tlv.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        tlv.extend_from_slice(&payload);
        tlv.extend_from_slice(Hash::new(&payload).as_ref());
        tlv
    })
    .collect();
    let mut program = ivm::ProgramMetadata {
        max_cycles: 1_000,
        ..Default::default()
    }
    .encode();
    let data_offset = 16 + literals.len() * 8;
    let data_len: usize = literals.iter().map(Vec::len).sum();
    let padding = (4 - (data_offset + data_len) % 4) % 4;
    program.extend_from_slice(b"LTLB");
    for value in [literals.len(), padding, data_len] {
        program.extend_from_slice(&u32::try_from(value).unwrap().to_le_bytes());
    }
    let mut offset = data_offset;
    for literal in &literals {
        program.extend_from_slice(
            &ivm::encode_literal_descriptor(
                ivm::LiteralKindV1::PointerTlv,
                u64::try_from(offset).unwrap(),
            )
            .unwrap()
            .to_le_bytes(),
        );
        offset += literal.len();
    }
    for literal in literals {
        program.extend_from_slice(&literal);
    }
    program.extend(std::iter::repeat_n(0, padding));
    for instruction in [
        wide::encode_literal(opcode::memory::LDLIT, 10, 0),
        wide::encode_literal(opcode::memory::LDLIT, 11, 1),
        wide::encode_literal(opcode::memory::LDLIT, 12, 2),
        wide::encode_sys(
            opcode::system::SCALL,
            u8::try_from(ivm::syscalls::SYSCALL_SET_ACCOUNT_DETAIL).unwrap(),
        ),
        wide::encode_halt(),
    ] {
        program.extend_from_slice(&instruction.to_le_bytes());
    }
    assert!(matches!(
        IvmCache::new().summarize_executable(&program).unwrap(),
        crate::smartcontracts::ivm::cache::ExecutableProgramSummary::Generic(_)
    ));
    {
        let (mut setup, _setup_recording) = output_fixture_setup(&state);
        let mut transaction = setup.transaction_for_callback_testing();
        Grant::account_permission(
            iroha_executor_data_model::permission::trigger::CanRegisterTrigger {
                authority: ALICE_ID.clone(),
            },
            ALICE_ID.clone(),
        )
        .execute(&ALICE_ID, &mut transaction)
        .unwrap();
        Register::trigger(Trigger::new(
            id.clone(),
            Action::new(
                Executable::Ivm(IvmBytecode::from_compiled(program)),
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(id.clone())
                    .under_authority(ALICE_ID.clone()),
            )
            .unwrap(),
        ))
        .execute(&ALICE_ID, &mut transaction)
        .unwrap();
        transaction.apply();
        setup.commit_world_overlay_for_testing().unwrap();
    }
    let direct_gas = crate::gas::meter_instructions(
        std::slice::from_ref(&instruction),
        &crate::gas::DEFAULT_ZK_GAS,
    );
    let entrypoint = if quarantine {
        let mut metadata = iroha_model_base::metadata::Metadata::default();
        metadata.insert("quarantine".parse().unwrap(), Json::new(true));
        let mut builder = TransactionBuilder::new(
            state.network_id,
            ALICE_ID.clone(),
            FeePaymentIntent::authority(vec![], None),
        );
        builder.set_creation_time(output_fixture_input_time(&state));
        let signed = builder
            .with_metadata(metadata)
            .with_instructions(vec![instruction])
            .sign(ALICE_KEYPAIR.private_key());
        assert!(crate::tx::is_quarantine_transaction(&signed));
        TransactionEntrypoint::External(signed)
    } else {
        input(
            &state,
            vec![instruction],
            FeePaymentIntent::authority(vec![], None),
            false,
        )
    };
    let source = carrier(&state, vec![entrypoint]);
    let (mut block, _recording) = recorded_network_block(&state, &source);
    execute(&mut block, &source).unwrap();
    assert!(
        network_row(&block, 0).result.is_ok(),
        "{:?}",
        network_row(&block, 0).result
    );
    assert!(!network_row(&block, 0).completions.is_empty());
    assert_eq!(
        block.world.account(&ALICE_ID).unwrap().metadata().get(&key),
        Some(&Json::new(9))
    );
    assert!(block.gas_used_in_block > direct_gas);
    (network_row(&block, 0).clone(), block.gas_used_in_block)
}

#[test]
fn actual_generic_ivm_callback_artifact_is_outside_the_signed_root_budget() {
    let _ = actual_generic_ivm_callback_output(false);
}

#[test]
fn actual_quarantined_network_root_does_not_charge_callback_vm_cycles() {
    let (ordinary, ordinary_gas) = actual_generic_ivm_callback_output(false);
    let (quarantined, quarantined_gas) = actual_generic_ivm_callback_output(true);
    // The real callback must pass three LDLITs before its SET_ACCOUNT_DETAIL
    // syscall. A shared one-cycle root allowance would refuse before that effect.
    // Compare the entire actual row, including callback trace and completions.
    assert_eq!(quarantined, ordinary);
    assert_eq!(quarantined_gas, ordinary_gas);
    assert_eq!(quarantined.input_index, 0);
    assert!(quarantined.result.is_ok());
    assert!(quarantined.result.batch_transfer_outcomes().is_empty());
    assert_eq!(quarantined.completions.len(), 1);
    assert_eq!(quarantined.completions[0].callback_index, 0);
    assert_eq!(
        quarantined.completions[0].trigger_id,
        "generic_effect_callback".parse::<TriggerId>().unwrap()
    );
    assert!(matches!(
        quarantined.completions[0].outcome,
        iroha_data_model::events::trigger_completed::TriggerCompletedOutcome::Success
    ));
}

#[test]
fn actual_root_effects_cannot_apply_after_owner_reuse_or_context_substitution() {
    for (consensus_only, mutation) in [
        (false, 0),
        (false, 1),
        (false, 2),
        (false, 3),
        (false, 4),
        (true, 1),
        (true, 2),
        (true, 3),
        (true, 4),
    ] {
        let state = fixture(65_536, None);
        let entry = input(
            &state,
            vec![write()],
            FeePaymentIntent::authority(vec![], None),
            false,
        );
        let TransactionEntrypoint::External(signed) = &entry else {
            unreachable!()
        };
        let source = carrier(&state, vec![entry.clone()]);
        let mut block = state.block(source.header());
        let fragments = block.committed_fragment_count();
        let mut transaction =
            block.transaction_for_fastpq_testing(Hash::from(signed.hash_as_entrypoint()));
        bind_root(&mut transaction, signed);
        Executor::Initial
            .execute_transaction(
                &mut transaction,
                &ALICE_ID,
                signed.clone(),
                &mut IvmCache::new(),
            )
            .unwrap();
        assert!(
            transaction
                .world
                .account(&ALICE_ID)
                .unwrap()
                .metadata()
                .get("effect_write")
                .is_some()
        );
        assert!(
            transaction
                .require_completed_execution_effect_owner()
                .is_ok()
        );
        match mutation {
            0 => {}
            1 => assert!(
                transaction
                    .admit_authored_execution_effects(&[write()])
                    .is_err()
            ),
            2 => transaction.current_entrypoint_index = Some(1),
            3 => assert!(transaction.begin_execution_effect_budget(signed).is_err()),
            4 => assert!(transaction.finish_execution_effect_budget().is_err()),
            _ => unreachable!(),
        }
        assert_eq!(
            transaction
                .require_completed_execution_effect_owner()
                .is_ok(),
            mutation == 0
        );
        assert!(!transaction.execution_effect_limit_exceeded());
        if consensus_only {
            transaction.apply_consensus_effects();
        } else {
            transaction.apply();
        }
        assert_eq!(
            block.committed_fragment_count(),
            fragments + usize::from(mutation == 0)
        );
        assert_eq!(
            block
                .world
                .account(&ALICE_ID)
                .unwrap()
                .metadata()
                .get("effect_write")
                .is_some(),
            mutation == 0
        );
        if mutation != 0 {
            assert!(matches!(
                block.execution_output_plan,
                Some(ExecutionOutputPlanState::Poisoned)
            ));
            assert!(matches!(
                block.commit().unwrap_err(),
                TransactionsBlockError::ExecutionOutputCapacity
            ));
        }
    }
}

#[test]
fn unwinding_before_root_close_cannot_publish_already_staged_effects() {
    let state = fixture(65_536, None);
    let entry = input(
        &state,
        vec![write()],
        FeePaymentIntent::authority(vec![], None),
        false,
    );
    let TransactionEntrypoint::External(signed) = &entry else {
        unreachable!()
    };
    let source = carrier(&state, vec![entry.clone()]);
    let mut block = state.block(source.header());
    let fragments = block.committed_fragment_count();
    let mut transaction = block.transaction();
    bind_root(&mut transaction, signed);
    // Exercise the local owner lifecycle with a real staged instruction. This
    // deliberately injected unwind is not complete source admission or consensus.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        transaction.begin_execution_effect_budget(signed).unwrap();
        transaction
            .admit_authored_execution_effects(&[write()])
            .unwrap();
        write().execute(&ALICE_ID, &mut transaction).unwrap();
        panic!("crash cut after staging an instruction before root close");
    }));
    assert!(result.is_err());
    assert!(
        transaction
            .world
            .account(&ALICE_ID)
            .unwrap()
            .metadata()
            .get("effect_write")
            .is_some()
    );
    assert!(
        transaction
            .require_completed_execution_effect_owner()
            .is_err()
    );
    transaction.apply();
    assert_eq!(block.committed_fragment_count(), fragments);
    assert!(
        block
            .world
            .account(&ALICE_ID)
            .unwrap()
            .metadata()
            .get("effect_write")
            .is_none()
    );
    assert!(matches!(
        block.execution_output_plan,
        Some(ExecutionOutputPlanState::Poisoned)
    ));
    assert!(matches!(
        block.commit().unwrap_err(),
        TransactionsBlockError::ExecutionOutputCapacity
    ));
}
