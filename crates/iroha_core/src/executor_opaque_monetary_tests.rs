//! Signed raw execution and supplied replay cannot derive staking monetary authority.

use super::Executor;
use crate::{
    pipeline::overlay::IvmProvedReplay,
    smartcontracts::{
        isi::triggers::set::SetReadOnly as _,
        ivm::{cache::IvmCache, host::QueuedEffect},
    },
    state::{StateBlock, StateTransaction, WorldReadOnly as _},
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    ValidationFail,
    account::AccountId,
    asset::AssetId,
    events::execute_trigger::ExecuteTriggerEventFilter,
    isi::{InstructionBox, SetKeyValue, staking::ClaimPublicLaneRewards},
    nexus::{PublicLaneMonetaryScopeV1, PublicLaneRewardClaimPlanV1},
    transaction::{
        Executable, FeePaymentIntent, IvmBytecode, IvmProved, SignedTransaction, TransactionBuilder,
    },
    trigger::{
        Trigger, TriggerId,
        action::{Action, Repeats},
    },
};
use iroha_model_base::topology::{DataSpaceId, LaneId};
use iroha_primitives::{json::Json, numeric::Quantity};
use mv::storage::StorageReadOnly as _;
use std::collections::BTreeMap;

const GAS: u64 = 100_000_000;

fn signer(seed: u8) -> KeyPair {
    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
}

fn with_claim_fixture(
    test: impl FnOnce(&mut StateBlock<'_>, &AccountId, &AssetId, &AssetId, InstructionBox),
) {
    crate::retail_fee_tests::fixture_block(1_793_451_600_000, |block, _policy| {
        let authority = &AccountId::new(signer(55).public_key().clone());
        let (source, destination, claim) = {
            let mut tx = block.transaction_for_callback_testing();
            tx.world.add_account_permission(
                authority,
                iroha_executor_data_model::permission::trigger::CanRegisterTrigger {
                    authority: authority.clone(),
                }
                .into(),
            );
            let fee = crate::validation_fee_rewards::seed_automatic_claim_for_testing(
                &mut tx,
                authority,
                10_000_000_000,
                20_000_000_000,
            );
            let source = fee.source_asset.clone();
            let destination = fee.destination_asset.clone();
            let claim = ClaimPublicLaneRewards {
                lane_id: LaneId::SINGLE,
                account: authority.clone(),
                claim_plan: PublicLaneRewardClaimPlanV1 {
                    network_scope: PublicLaneMonetaryScopeV1::Network(tx.network_id),
                    valid_until_height: tx.block_height(),
                    fee_claim: fee,
                },
            }
            .into();
            tx.apply();
            (source, destination, claim)
        };
        test(block, authority, &source, &destination, claim);
    });
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

fn assert_claim_unchanged(
    tx: &StateTransaction<'_, '_>,
    authority: &AccountId,
    source: &AssetId,
    destination: &AssetId,
) {
    assert_eq!(
        tx.world.assets.get(source).unwrap().as_ref(),
        &Quantity::from(20_u32)
    );
    assert!(tx.world.assets.get(destination).is_none());
    let claim = crate::validation_fee_rewards::fee_reward_claim_plan(
        &tx.world,
        tx.block_height(),
        authority,
        LaneId::SINGLE,
    )
    .unwrap()
    .unwrap();
    assert_eq!(claim.amount, Quantity::from(10_u32));
    assert_eq!(claim.source_asset, *source);
    assert_eq!(claim.destination_asset, *destination);
    assert_eq!(claim.expected_claim_sequence, 0);
}

fn assert_opaque_rejection(error: ValidationFail) {
    assert!(
        matches!(error, ValidationFail::NotPermitted(ref message)
        if message.contains("opaque deferred executable derived monetary staking operation `iroha.instruction.v1::staking::ClaimPublicLaneRewards`")
            && message.contains("the exact monetary plan must be a signed instruction")),
        "{error:?}"
    );
}

// Real generic VM bytecode uses a canonical literal directory and hashed Json TLV.
// No pre-populated host queue or VM-register injection supplies the trigger.
pub(super) fn create_trigger_program(trigger: &Trigger) -> Vec<u8> {
    use ivm::{encoding::wide, instruction::wide as opcode, pointer_abi::PointerType};
    let payload = norito::to_bytes(&Json::new(trigger.clone())).unwrap();
    let mut tlv = (PointerType::Json as u16).to_be_bytes().to_vec();
    tlv.push(1);
    tlv.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    tlv.extend_from_slice(&payload);
    tlv.extend_from_slice(Hash::new(&payload).as_ref());
    let data_offset = 24;
    let padding = (4 - (data_offset + tlv.len()) % 4) % 4;
    let mut program = ivm::ProgramMetadata {
        max_cycles: 1_000,
        ..Default::default()
    }
    .encode();
    program.extend_from_slice(b"LTLB");
    for value in [1, padding, tlv.len()] {
        program.extend_from_slice(&u32::try_from(value).unwrap().to_le_bytes());
    }
    program.extend_from_slice(
        &ivm::encode_literal_descriptor(ivm::LiteralKindV1::PointerTlv, data_offset as u64)
            .unwrap()
            .to_le_bytes(),
    );
    program.extend_from_slice(&tlv);
    program.extend(std::iter::repeat_n(0, padding));
    for instruction in [
        wide::encode_literal(opcode::memory::LDLIT, 10, 0),
        wide::encode_sys(
            opcode::system::SCALL,
            u8::try_from(ivm::syscalls::SYSCALL_CREATE_TRIGGER).unwrap(),
        ),
        wide::encode_halt(),
    ] {
        program.extend_from_slice(&instruction.to_le_bytes());
    }
    program
}

#[test]
fn raw_ivm_staking_trigger_requires_signed_monetary_plan() {
    with_claim_fixture(|block, authority, source, destination, claim| {
        for monetary in [true, false] {
            let trigger_id: TriggerId = if monetary {
                "opaque_claim"
            } else {
                "opaque_metadata"
            }
            .parse()
            .unwrap();
            let instruction = if monetary {
                claim.clone()
            } else {
                SetKeyValue::account(
                    authority.clone(),
                    "ordinary_callback".parse().unwrap(),
                    Json::new(true),
                )
                .into()
            };
            let trigger = Trigger::new(
                trigger_id.clone(),
                Action::new(
                    vec![instruction],
                    Repeats::Exactly(1),
                    authority.clone(),
                    ExecuteTriggerEventFilter::new()
                        .for_trigger(trigger_id.clone())
                        .under_authority(authority.clone()),
                )
                .unwrap(),
            );
            let signed = signed(
                block,
                authority,
                Executable::Ivm(IvmBytecode::from_compiled(create_trigger_program(&trigger))),
            );
            let call = Hash::from(signed.hash_as_entrypoint());
            let fragments = block.committed_fragment_count();
            {
                let mut tx = block.transaction_for_fastpq_testing(call);
                bind_scope(&mut tx);
                let result = Executor::Initial.execute_transaction(
                    &mut tx,
                    authority,
                    signed,
                    &mut IvmCache::new(),
                );
                assert!(
                    tx.last_tx_gas_used > 0,
                    "actual signed raw VM consumed work"
                );
                assert_claim_unchanged(&tx, authority, source, destination);
                if monetary {
                    assert_opaque_rejection(
                        result
                            .map_err(crate::execution_attempt::expect_completed_rejection)
                            .expect_err("opaque trigger must fail before registration"),
                    );
                    assert!(
                        tx.world
                            .triggers
                            .by_call_triggers()
                            .get(&trigger_id)
                            .is_none()
                    );
                    // Drop the actual rejected transaction; do not manually restore any row.
                } else {
                    result.expect("ordinary raw VM trigger registration remains allowed");
                    assert!(tx.complete_direct_callbacks(call).unwrap().is_empty());
                    tx.apply();
                }
            }
            assert_eq!(
                block.committed_fragment_count(),
                fragments + usize::from(!monetary)
            );
            let tx = block.transaction_for_callback_testing();
            assert_eq!(
                tx.world
                    .triggers
                    .by_call_triggers()
                    .get(&trigger_id)
                    .is_some(),
                !monetary
            );
            assert_claim_unchanged(&tx, authority, source, destination);
        }
        // The identical exact plan is valid when the recipient signs it as an ISI.
        let signed = signed(
            block,
            authority,
            Executable::Instructions(vec![claim].into()),
        );
        let call = Hash::from(signed.hash_as_entrypoint());
        let fragments = block.committed_fragment_count();
        let mut tx = block.transaction_for_fastpq_testing(call);
        bind_scope(&mut tx);
        Executor::Initial
            .execute_transaction(&mut tx, authority, signed, &mut IvmCache::new())
            .unwrap();
        assert!(tx.complete_direct_callbacks(call).unwrap().is_empty());
        tx.apply();
        assert_eq!(block.committed_fragment_count(), fragments + 1);
        let tx = block.transaction_for_callback_testing();
        assert_eq!(
            tx.world.assets.get(source).unwrap().as_ref(),
            &Quantity::from(10_u32)
        );
        assert_eq!(
            tx.world.assets.get(destination).unwrap().as_ref(),
            &Quantity::from(10_u32)
        );
        assert!(
            crate::validation_fee_rewards::fee_reward_claim_plan(
                &tx.world,
                tx.block_height(),
                authority,
                LaneId::SINGLE
            )
            .unwrap()
            .is_none()
        );
    });
}

#[test]
fn supplied_proved_staking_effects_require_signed_monetary_plan() {
    with_claim_fixture(|block, authority, source, destination, claim| {
        let marker: iroha_model_base::name::Name = "proved_prefix".parse().unwrap();
        let instructions: Vec<InstructionBox> = vec![
            SetKeyValue::account(authority.clone(), marker.clone(), Json::new(true)).into(),
            claim,
        ];
        // This private-call regression exercises strict replay consumption only.
        // The production verifier still rejects proof acceptance until the complete
        // native STARK execution relation exists; these are no substitute proofs.
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
        let replay_gas = 40_000;
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
            gas_used: replay_gas,
        };
        let fragments = block.committed_fragment_count();
        {
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
                    instructions,
                    Some(replay),
                    None,
                    None,
                    0,
                    Some(GAS),
                    true,
                    None,
                    None,
                    true,
                )
                .expect_err("supplied replay must not manufacture a signed monetary plan");
            assert_opaque_rejection(error);
            assert_eq!(tx.last_tx_gas_used, replay_gas);
            tx.finish_execution_effect_budget().unwrap();
            assert!(
                tx.world
                    .account(authority)
                    .unwrap()
                    .metadata()
                    .get(&marker)
                    .is_none(),
                "whole replay is checked before its first effect"
            );
            assert_claim_unchanged(&tx, authority, source, destination);
        }
        assert_eq!(block.committed_fragment_count(), fragments);
        let tx = block.transaction_for_callback_testing();
        assert!(
            tx.world
                .account(authority)
                .unwrap()
                .metadata()
                .get(&marker)
                .is_none()
        );
        assert_claim_unchanged(&tx, authority, source, destination);
    });
}
