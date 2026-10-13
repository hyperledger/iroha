//! Exact signed Reserve/Complete origins preserve local refusal before output and fee settlement.

use super::*;
use crate::{
    executor::Executor,
    state::{ExecutionOutputAttemptError, StateBlock, StateTransaction, WorldReadOnly},
};
use iroha_data_model::{
    asset::{AssetDefinitionId, AssetId},
    block::{SignedBlock, execution_output::ExecutionOutputV1},
    sorafs::final_promotion_authority::{FinalPromotionCompleteV1, FinalPromotionReserveV1},
};
use iroha_primitives::numeric::Quantity;
use ivm::error::ExecutionDeferral;
use mv::storage::StorageReadOnly;
use sorafs_manifest::signer::protocol::{
    SignerOperationAuditHeadV1, SignerOperationCommitmentV1, SignerOperationIntentV1,
};

fn original(f: &mut Fixture, complete: bool) -> (InstructionBox, SignedTransaction, SignedBlock) {
    let (action, now) = if complete {
        let reserved = reserve_reviewed_request(f);
        (
            FinalPromotionAuthorityActionV1::Complete(FinalPromotionCompleteV1 {
                intent: reserved.intent,
                custody: reserved.custody,
                reservation: reserved.reservation,
                commitment: SignerOperationCommitmentV1 {
                    audit: SignerOperationAuditHeadV1 {
                        sequence: 1,
                        digest: [21; 32],
                    },
                    response_digest: [22; 32],
                },
                signatures_digest: [23; 32],
            }),
            NOW + 1,
        )
    } else {
        let expected = f.expected();
        (
            FinalPromotionAuthorityActionV1::Reserve(FinalPromotionReserveV1 {
                intent: SignerOperationIntentV1 {
                    action: SignerOperationActionV1::Sign,
                    operation_id: expected.request.operation_id,
                    request_digest: expected.request.digest().unwrap(),
                    previous_audit: f.snapshot().operations.audit,
                },
                custody: expected.request.original_custody,
            }),
            NOW,
        )
    };
    let instruction: InstructionBox = f.instruction(action).into();
    let signed = f.sign(instruction.clone(), 2, now);
    let proposal = f.chain.proposal(Some(now), vec![signed.clone()]);
    assert_eq!(proposal.network_entrypoint_count(), 1);
    (instruction, signed, proposal)
}

fn bind_original(tx: &mut StateTransaction<'_, '_>, signed: &SignedTransaction) {
    let outer = signed.try_hash_as_entrypoint().unwrap();
    tx.current_network_entrypoint_hash = Some(outer);
    tx.current_tx_hash = Some(signed.hash());
    tx.tx_call_hash = Some(Hash::from(outer));
    tx.current_entrypoint_index = Some(0);
}

fn no_allocation() -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128)
}

#[test]
fn direct_final_promotion_origin_quota_clears_token_and_preserves_first_local_refusal() {
    for complete in [false, true] {
        let mut f = Fixture::new();
        let (instruction, signed, source) = original(&mut f, complete);
        let exact = norito::encode_canonical(&signed).unwrap();
        let mut block = f.state.block(source.header());
        for prior in [None, Some(ExecutionDeferral::CanonicalHistoryUnavailable)] {
            let mut tx = block.transaction();
            bind_original(&mut tx, &signed);
            tx.current_direct_final_promotion_operation_origin =
                Executor::direct_final_promotion_operation_origin(
                    &mut tx,
                    &signed,
                    &instruction,
                    true,
                )
                .unwrap();
            assert!(tx.current_direct_final_promotion_operation_origin.is_some());
            if let Some(reason) = prior.clone() {
                let _ = tx.defer_execution(reason);
            }
            let refused = norito::with_decode_limits_scope(no_allocation(), || {
                Executor::direct_final_promotion_operation_origin(
                    &mut tx,
                    &signed,
                    &instruction,
                    true,
                )
            });
            assert!(refused.is_err(), "{complete}");
            assert!(tx.current_direct_final_promotion_operation_origin.is_none());
            assert_eq!(
                tx.borrow_execution_deferral().unwrap().reason(),
                prior.unwrap_or(ExecutionDeferral::ActiveMemoryCapacity)
            );
            assert_eq!(tx.last_tx_gas_used, 0);
        }
        let mut retry = block.transaction();
        bind_original(&mut retry, &signed);
        let origin = Executor::direct_final_promotion_operation_origin(
            &mut retry,
            &signed,
            &instruction,
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            origin.entry_hash,
            *signed.try_hash_as_entrypoint().unwrap().as_ref()
        );
        assert_eq!(origin.entry_index, 0);
        assert!(!retry.is_execution_deferred());
        assert_eq!(norito::encode_canonical(&signed).unwrap(), exact);
    }
}

fn recorded<'state>(
    f: &'state Fixture,
    source: &SignedBlock,
) -> (
    Box<StateBlock<'state>>,
    crate::exec_witness::ExecWitnessGuard,
) {
    f.state
        .block_with_recorded_pristine_carrier_stage(
            source,
            |block| {
                crate::smartcontracts::ivm::active_runtime_abi_hash(
                    &block.world,
                    source.header().height().get(),
                )
                .map(|_| ())
                .map_err(|error| error.to_string())
            },
            |error| error,
        )
        .unwrap()
}

fn balance(block: &StateBlock<'_>, asset: &AssetDefinitionId, authority: &AccountId) -> Quantity {
    block
        .world
        .assets()
        .get(&AssetId::of(asset.clone(), authority.clone()))
        .map_or_else(Quantity::zero, |balance| balance.0.clone())
}

#[test]
fn original_final_promotion_quota_refusal_has_no_output_fee_gas_or_overlay_and_retries() {
    let _fee_guard = crate::status::nexus_fee_test_lock().lock().unwrap();
    for complete in [false, true] {
        let mut f = Fixture::with_fees();
        let (_, signed, source) = original(&mut f, complete);
        let exact = norito::encode_canonical(&signed).unwrap();
        let asset = AssetDefinitionId::parse_address_literal(
            &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
        )
        .unwrap();
        let operator = signed.authority();
        let sink = AccountId::new(key(3).public_key().clone());
        let before_balance;
        {
            let (mut block, _recording) = recorded(&f, &source);
            let fragments = block.committed_fragment_count();
            before_balance = balance(&block, &asset, operator);
            let before_sink = balance(&block, &asset, &sink);
            let before_rows: Vec<_> = block
                .world
                .smart_contract_state()
                .iter()
                .map(|(path, value)| (path.clone(), value.clone()))
                .collect();
            block.reserve_ordinary_execution_outputs(&source).unwrap();
            // The whole original Network attempt shares this allowance. The direct-source
            // test above separately pins refusal at capture, including its sticky precedence.
            // This full attempt first refuses the five-element canonical decode allocation;
            // retain that actual owner instead of expecting a reason-only deferral.
            let result = norito::with_decode_limits_scope(no_allocation(), || {
                block.execute_ordinary_output_plan(&source, None)
            });
            assert!(
                matches!(&(result), Err(ExecutionOutputAttemptError::Deferred(owner)) if owner.reason() == ExecutionDeferral::ActiveMemoryCapacity && owner.phase().is_none() && owner.allocation_refusal().is_none() && owner.decode_refusal().is_some_and(|original| matches!(original.resource_error(), norito::core::DecodeResourceError::TotalAllocationExceeded { attempted: 5, limit: 0 })) && owner.verification_refusal().is_none()),
                "complete={complete}, actual original output attempt={result:?}"
            );
            assert_eq!(block.gas_used_in_block, 0);
            assert_eq!(block.committed_fragment_count(), fragments);
            assert_eq!(balance(&block, &asset, operator), before_balance);
            assert_eq!(balance(&block, &asset, &sink), before_sink);
            assert_eq!(
                block
                    .world
                    .smart_contract_state()
                    .iter()
                    .map(|(path, value)| (path.clone(), value.clone()))
                    .collect::<Vec<_>>(),
                before_rows
            );
            assert!(block.retained_execution_outputs_for_test().is_err());
        }
        let (mut retry, _recording) = recorded(&f, &source);
        retry.reserve_ordinary_execution_outputs(&source).unwrap();
        retry.execute_ordinary_output_plan(&source, None).unwrap();
        let [ExecutionOutputV1::Network(output)] =
            retry.retained_execution_outputs_for_test().unwrap()
        else {
            panic!("exactly the original Network source must produce one output")
        };
        assert!(output.result.is_ok(), "{complete}: {:?}", output.result);
        assert!(retry.gas_used_in_block > 0);
        assert_eq!(
            balance(&retry, &asset, operator),
            before_balance.checked_sub(&Quantity::from(2_u32)).unwrap()
        );
        assert_eq!(norito::encode_canonical(&signed).unwrap(), exact);
    }
}
