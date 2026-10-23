//! Outbound SCCP records execute only as signed instructions (`specs/sccp.md` §4.4).
//!
//! A top-level signed `RecordSccpMessage` records, both as an `Instructions` executable and as
//! a `Batch` instruction item. A user-registered trigger, a raw IVM program registering a
//! trigger, a supplied IVM-proved replay and a trigger's native instruction group cannot derive
//! one.

use super::Executor;
use crate::{
    pipeline::overlay::IvmProvedReplay,
    smartcontracts::{
        isi::{
            sccp::test_support::{
                ONE_XOR, install_outbound_route, outbound_record, outbound_sender, set_xor_balance,
            },
            triggers::set::SetReadOnly as _,
        },
        ivm::{cache::IvmCache, host::QueuedEffect},
    },
    state::{StateBlock, StateTransaction},
    tx::TransactionRejectionReason,
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    ValidationFail,
    account::AccountId,
    asset::AssetId,
    events::execute_trigger::ExecuteTriggerEventFilter,
    isi::{InstructionBox, Register, SetKeyValue},
    sccp::escrow::sccp_taira_xor_asset_definition_id,
    transaction::{
        Executable, ExecutableBatchItem, FeePaymentIntent, IvmBytecode, IvmProved,
        SignedTransaction, TransactionBuilder,
    },
    trigger::{
        Trigger, TriggerId,
        action::{Action, Repeats},
    },
};
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::{json::Json, numeric::Quantity};
use mv::storage::StorageReadOnly as _;
use std::collections::BTreeMap;

const GAS: u64 = 100_000_000;

fn signer(seed: u8) -> KeyPair {
    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
}

/// Run `test` on a post-genesis block where live SCCP accepts an Ethereum record and the
/// signed authority holds 10 XOR and may register its own triggers.
fn with_record_fixture(test: impl FnOnce(&mut StateBlock<'_>, &AccountId)) {
    crate::validation_fee::tests::with_validation_fee_payout_block_at_time(
        2,
        2_000,
        |block, authority, _, _| {
            assert_eq!(*authority, AccountId::new(signer(55).public_key().clone()));
            let mut tx = block.transaction_for_callback_testing();
            tx.world.add_account_permission(
                authority,
                iroha_executor_data_model::permission::trigger::CanRegisterTrigger {
                    authority: authority.clone(),
                }
                .into(),
            );
            install_outbound_route(&mut tx, 100 * ONE_XOR);
            set_xor_balance(&mut tx, authority, 10 * ONE_XOR);
            tx.apply();
            test(block, authority);
        },
    );
}

fn signed(
    block: &StateBlock<'_>,
    authority: &AccountId,
    executable: Executable,
) -> SignedTransaction {
    TransactionBuilder::new(
        block.network_id,
        authority.clone(),
        FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(GAS)),
    )
    .with_executable(executable)
    .sign(signer(55).private_key())
}

fn bind_scope(tx: &mut StateTransaction<'_, '_>) {
    tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
}

fn xor_balance(tx: &StateTransaction<'_, '_>, holder: &AccountId) -> Option<Quantity> {
    tx.world
        .assets
        .get(&AssetId::of(
            sccp_taira_xor_asset_definition_id(),
            holder.clone(),
        ))
        .map(|value| value.as_ref().clone())
}

/// Nothing was recorded and the authority kept its 10 XOR.
fn assert_unrecorded(tx: &StateTransaction<'_, '_>, authority: &AccountId) {
    assert!(outbound_sender(&*tx.world, 0).is_none());
    assert_eq!(
        xor_balance(tx, authority),
        Some(crate::smartcontracts::isi::sccp::escrow::xor_quantity(10 * ONE_XOR).unwrap())
    );
}

fn record_trigger(authority: &AccountId, name: &str) -> (TriggerId, Trigger) {
    let trigger_id: TriggerId = name.parse().unwrap();
    let trigger = Trigger::new(
        trigger_id.clone(),
        Action::new(
            vec![InstructionBox::from(outbound_record(2, [0x22; 20]))],
            Repeats::Exactly(1),
            authority.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(authority.clone()),
        )
        .unwrap(),
    );
    (trigger_id, trigger)
}

fn assert_signed_only_rejection(error: &ValidationFail) {
    assert!(
        matches!(error, ValidationFail::NotPermitted(message)
            if message.contains("derived `RecordSccpMessage`")
                && message.contains("must be a signed transaction instruction")),
        "{error:?}"
    );
}

#[test]
fn top_level_signed_record_executes() {
    with_record_fixture(|block, authority| {
        let record = || InstructionBox::from(outbound_record(2, [0x22; 20]));
        // Both signed native forms record: an `Instructions` executable and an instruction item
        // of a `Batch`. Each runs in its own unapplied transaction.
        for executable in [
            Executable::Instructions(vec![record()].into()),
            Executable::Batch(
                vec![
                    ExecutableBatchItem::Instruction(InstructionBox::from(SetKeyValue::account(
                        authority.clone(),
                        "before_record".parse().unwrap(),
                        Json::new(true),
                    ))),
                    ExecutableBatchItem::Instruction(record()),
                ]
                .into(),
            ),
        ] {
            let signed = signed(block, authority, executable);
            let call = Hash::from(signed.hash_as_entrypoint());
            let mut tx = block.transaction_for_fastpq_testing(call);
            bind_scope(&mut tx);
            Executor::Initial
                .execute_transaction(&mut tx, authority, &signed, &mut IvmCache::new())
                .map_err(crate::execution_attempt::expect_completed_rejection)
                .expect("a signed RecordSccpMessage records");
            assert_eq!(outbound_sender(&*tx.world, 0), Some(authority.clone()));
            assert_eq!(
                xor_balance(&tx, authority),
                Some(crate::smartcontracts::isi::sccp::escrow::xor_quantity(8 * ONE_XOR).unwrap())
            );
        }
    });
}

#[test]
fn signed_trigger_registration_cannot_carry_a_record() {
    with_record_fixture(|block, authority| {
        let (trigger_id, trigger) = record_trigger(authority, "user_record_trigger");
        let signed = signed(
            block,
            authority,
            Executable::Instructions(vec![Register::trigger(trigger).into()].into()),
        );
        let call = Hash::from(signed.hash_as_entrypoint());
        let mut tx = block.transaction_for_fastpq_testing(call);
        bind_scope(&mut tx);
        let error = Executor::Initial
            .execute_transaction(&mut tx, authority, &signed, &mut IvmCache::new())
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("a user trigger may not derive RecordSccpMessage");
        assert!(
            format!("{error:?}").contains("a trigger action cannot derive `RecordSccpMessage`"),
            "{error:?}"
        );
        assert!(
            tx.world
                .triggers
                .by_call_triggers()
                .get(&trigger_id)
                .is_none()
        );
        assert_unrecorded(&tx, authority);
    });
}

#[test]
fn raw_ivm_trigger_registration_cannot_carry_a_record() {
    with_record_fixture(|block, authority| {
        for carries_record in [true, false] {
            let (trigger_id, trigger) = if carries_record {
                record_trigger(authority, "ivm_record_trigger")
            } else {
                let trigger_id: TriggerId = "ivm_ordinary_trigger".parse().unwrap();
                let trigger = Trigger::new(
                    trigger_id.clone(),
                    Action::new(
                        vec![InstructionBox::from(SetKeyValue::account(
                            authority.clone(),
                            "ordinary_callback".parse().unwrap(),
                            Json::new(true),
                        ))],
                        Repeats::Exactly(1),
                        authority.clone(),
                        ExecuteTriggerEventFilter::new()
                            .for_trigger(trigger_id.clone())
                            .under_authority(authority.clone()),
                    )
                    .unwrap(),
                );
                (trigger_id, trigger)
            };
            let signed = signed(
                block,
                authority,
                Executable::Ivm(IvmBytecode::from_compiled(
                    super::opaque_monetary_tests::create_trigger_program(&trigger),
                )),
            );
            let call = Hash::from(signed.hash_as_entrypoint());
            let mut tx = block.transaction_for_fastpq_testing(call);
            bind_scope(&mut tx);
            let result = Executor::Initial.execute_transaction(
                &mut tx,
                authority,
                &signed,
                &mut IvmCache::new(),
            );
            assert!(
                tx.last_tx_gas_used > 0,
                "actual signed raw VM consumed work"
            );
            if carries_record {
                // The syscall refuses the action before anything is queued, so the VM run
                // fails with the host's `PermissionDenied` at `CREATE_TRIGGER`.
                let error = result
                    .map_err(crate::execution_attempt::expect_completed_rejection)
                    .expect_err("CREATE_TRIGGER may not register a record-deriving trigger");
                assert!(
                    matches!(&error, ValidationFail::IvmFault(fault)
                        if fault.kind
                            == iroha_data_model::executor::fault::IvmFaultKindV1::PermissionDenied),
                    "{error:?}"
                );
            } else {
                result
                    .map_err(crate::execution_attempt::expect_completed_rejection)
                    .expect("ordinary raw VM trigger registration remains allowed");
            }
            assert_eq!(
                tx.world
                    .triggers
                    .by_call_triggers()
                    .get(&trigger_id)
                    .is_some(),
                !carries_record
            );
            assert_unrecorded(&tx, authority);
        }
    });
}

#[test]
fn supplied_proved_replay_cannot_derive_a_record() {
    with_record_fixture(|block, authority| {
        let instructions: Vec<InstructionBox> = vec![outbound_record(2, [0x22; 20]).into()];
        // As in the monetary-staking regression, this exercises strict replay consumption
        // only; the supplied overlay is no substitute proof.
        let mut program = ivm::ProgramMetadata::default().encode();
        program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        let signed = signed(
            block,
            authority,
            Executable::IvmProved(IvmProved {
                bytecode: IvmBytecode::from_compiled(program),
                overlay: instructions.clone().into(),
                events_commitment: Hash::new(b"supplied events"),
                gas_policy_commitment: Hash::new(b"supplied gas policy"),
            }),
        );
        let call = Hash::from(signed.hash_as_entrypoint());
        let replay = IvmProvedReplay {
            queued: instructions
                .iter()
                .cloned()
                .map(|instruction| QueuedEffect {
                    payload: crate::smartcontracts::ivm::host::QueuedEffectPayload::Instruction(
                        instruction,
                    ),
                    authority: authority.clone(),
                    contract_runtime_context: None,
                    entrypoint_authorization: None,
                })
                .collect(),
            completed_axt: Vec::new(),
            durable_state_overlay: BTreeMap::new(),
            durable_state_authorizations: BTreeMap::new(),
            access_log: None,
            gas_used: 40_000,
        };
        let mut tx = block.transaction_for_fastpq_testing(call);
        bind_scope(&mut tx);
        tx.current_tx_hash = Some(signed.hash());
        tx.tx_call_hash = Some(call);
        tx.begin_execution_effect_budget(&signed).unwrap();
        tx.last_tx_gas_used = replay.gas_used;
        tx.record_execution_fee_instructions(replay.queued.len(), replay.gas_used)
            .unwrap();
        let error = Executor::Initial
            .execute_metered_instructions(
                &mut tx,
                authority,
                &signed,
                &instructions,
                Some(replay),
                None,
                None,
                0,
                Some(GAS),
                true,
                None,
                None,
                true,
                None,
            )
            .expect_err("a supplied replay must not manufacture a signed record");
        assert_signed_only_rejection(&error);
        tx.finish_execution_effect_budget().unwrap();
        assert_unrecorded(&tx, authority);
    });
}

#[test]
fn trigger_instruction_group_cannot_derive_a_record() {
    with_record_fixture(|block, authority| {
        let record = InstructionBox::from(outbound_record(2, [0x22; 20]));
        let groups = BTreeMap::from([(authority.clone(), vec![record.clone()])]);
        let mut tx = block.transaction_for_callback_testing();
        bind_scope(&mut tx);
        // Native trigger bodies and contract outputs are consumed through this boundary.
        let Err(TransactionRejectionReason::Validation(error)) =
            crate::validation_fee::enforce_opaque_deferred_instruction_groups(
                &groups,
                &[(authority.clone(), record)],
                &mut tx,
                None,
            )
        else {
            panic!("an opaque instruction group may not derive RecordSccpMessage");
        };
        assert_signed_only_rejection(&error);
        assert_unrecorded(&tx, authority);
    });
}
