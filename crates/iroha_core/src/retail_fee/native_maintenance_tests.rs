//! Original retail permits and all-or-nothing State/source/witness publication.
use super::*;

#[test]
fn original_retail_permit_rejects_identical_discarded_sibling() {
    crate::retail_fee_tests::with_original_due_idle_wallet(|block, policy, owner| {
        let original_usage = block.native_maintenance_usage_for_testing();
        let original_fragment = block.committed_fragment_count();
        let (permit, original_rows) = {
            let mut abandoned = block.consensus_effects_transaction().unwrap();
            let record = account_state(&abandoned.world, &owner).unwrap().unwrap();
            settle_idle_account(&mut abandoned, &policy, record).unwrap();
            let rows = receipts(&abandoned.world, &owner, None, 10).unwrap();
            let permit = RetailNativeMaintenancePermit::issue(&mut abandoned).unwrap();
            (permit, rows)
        };
        assert_eq!(block.committed_fragment_count(), original_fragment);
        assert_eq!(block.native_maintenance_usage_for_testing(), original_usage);
        let mut sibling = block.consensus_effects_transaction().unwrap();
        let record = account_state(&sibling.world, &owner).unwrap().unwrap();
        settle_idle_account(&mut sibling, &policy, record).unwrap();
        assert_eq!(
            receipts(&sibling.world, &owner, None, 10).unwrap(),
            original_rows
        );
        let error = permit.into_entries(&sibling).unwrap_err();
        assert!(matches!(error, ExecutionAttemptError::Rejected(message)
            if message == "retail maintenance belongs to a foreign original State source"));
        let own_permit = RetailNativeMaintenancePermit::issue(&mut sibling).unwrap();
        sibling
            .flush_retail_native_transfer_transcripts(own_permit)
            .unwrap();
        assert_eq!(sibling.retail_fee_transcripts_for_test().len(), 1);
        finalize(&mut sibling).unwrap();
        drop(sibling);
        assert_eq!(block.native_maintenance_usage_for_testing(), original_usage);
        assert!(receipts(&block.world, &owner, None, 10).unwrap().is_empty());
        process_idle_accounts(block).unwrap();
        assert_eq!(
            receipts(&block.world, &owner, None, 10).unwrap(),
            original_rows
        );
        assert_eq!(
            block
                .native_maintenance_usage_for_testing()
                .executed_entries,
            1
        );
    });
}

#[test]
fn original_retail_permit_rejects_changed_receipt_and_foreign_invocation_scope() {
    for change_receipt in [false, true] {
        crate::retail_fee_tests::with_original_due_idle_wallet(|block, policy, owner| {
            let mut transaction = block.consensus_effects_transaction().unwrap();
            let record = account_state(&transaction.world, &owner).unwrap().unwrap();
            settle_idle_account(&mut transaction, &policy, record).unwrap();
            let row = receipts(&transaction.world, &owner, None, 10)
                .unwrap()
                .remove(0);
            let permit = RetailNativeMaintenancePermit::issue(&mut transaction).unwrap();
            if change_receipt {
                let path = retail_fee_receipt_state_key_v1(&row).unwrap();
                let mut changed = transaction
                    .world
                    .smart_contract_state
                    .get(&path)
                    .unwrap()
                    .clone();
                changed.push(0);
                transaction.world.smart_contract_state.insert(path, changed);
            } else {
                transaction.tx_call_hash = Some(Hash::new(b"foreign signed invocation TESTDATA"));
            }
            let error = permit.into_entries(&transaction).unwrap_err();
            let ExecutionAttemptError::Rejected(message) = error else {
                panic!("completed source substitution is not a local refusal")
            };
            assert_eq!(
                message,
                if change_receipt {
                    "retail source receipt journal changed after original preparation"
                } else {
                    "retail maintenance requires its original block-start State owner"
                }
            );
            drop(transaction);
            assert_eq!(
                block
                    .native_maintenance_usage_for_testing()
                    .executed_entries,
                0
            );
            assert!(receipts(&block.world, &owner, None, 10).unwrap().is_empty());
            process_idle_accounts(block).unwrap();
            assert_eq!(receipts(&block.world, &owner, None, 10).unwrap(), vec![row]);
        });
    }
}

#[test]
fn original_idle_reward_refusal_rolls_back_witness_and_source_before_exact_retry() {
    crate::retail_fee_tests::with_original_due_idle_wallet(|block, _policy, owner| {
        let (reward_key, original_bytes) = {
            let mut setup = block.transaction();
            let binding = crate::validation_fee::active_payout_binding_at_height(
                &setup,
                setup.block_height(),
            )
            .unwrap()
            .unwrap();
            let path = iroha_data_model::validation_fee_rewards::validation_fee_reward_state_key(
                &binding, "State",
            )
            .unwrap();
            let original = setup.world.smart_contract_state.get(&path).cloned();
            setup
                .world
                .smart_contract_state
                .insert(path.clone(), vec![0xff; 8]);
            setup.apply();
            (path, original)
        };
        let account_before = account_state(&block.world, &owner).unwrap();
        let quota_before = block.native_maintenance_usage_for_testing();
        let fragments = block.committed_fragment_count();
        let _recording = crate::exec_witness::begin_exec_witness_capture().unwrap();
        let witness_before = crate::exec_witness::snapshot_exec_witness();
        process_idle_accounts(block).unwrap();
        assert_eq!(account_state(&block.world, &owner).unwrap(), account_before);
        assert!(receipts(&block.world, &owner, None, 10).unwrap().is_empty());
        assert_eq!(block.native_maintenance_usage_for_testing(), quota_before);
        assert_eq!(block.committed_fragment_count(), fragments);
        assert_eq!(
            crate::exec_witness::snapshot_exec_witness(),
            witness_before,
            "refused native batch must not leak its prepared FASTPQ witness"
        );
        {
            let mut repair = block.transaction();
            if let Some(bytes) = original_bytes {
                repair.world.smart_contract_state.insert(reward_key, bytes);
            } else {
                repair.world.smart_contract_state.remove(reward_key);
            }
            repair.apply();
        }
        process_idle_accounts(block).unwrap();
        let rows = receipts(&block.world, &owner, None, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].collected_minor, rows[0].waived_minor), (100, 0));
        assert_eq!(
            block
                .native_maintenance_usage_for_testing()
                .executed_entries,
            quota_before.executed_entries + 1
        );
        assert!(
            crate::exec_witness::snapshot_exec_witness()
                .fastpq_transcripts
                .iter()
                .any(|entry| entry.entry_hash == Hash::prehashed(rows[0].receipt_id))
        );
    });
}

#[test]
fn original_retail_receipt_decode_refusal_retains_exact_pending_owner_for_retry() {
    crate::retail_fee_tests::with_original_due_idle_wallet(|block, policy, owner| {
        let before = block.native_maintenance_usage_for_testing();
        let mut transaction = block.consensus_effects_transaction().unwrap();
        let record = account_state(&transaction.world, &owner).unwrap().unwrap();
        settle_idle_account(&mut transaction, &policy, record).unwrap();
        let pending = transaction.world.retail_fee_pending_transcripts.clone();
        let refused = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, usize::MAX),
            || RetailNativeMaintenancePermit::issue(&mut transaction),
        );
        let Err(ExecutionAttemptError::Deferred(original)) = refused else {
            panic!("original retail evidence decoder refusal must keep its typed owner");
        };
        assert!(original.decode_refusal().is_some());
        assert_eq!(
            original.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert_eq!(transaction.world.retail_fee_pending_transcripts, pending);
        let permit = RetailNativeMaintenancePermit::issue(&mut transaction).unwrap();
        transaction
            .flush_retail_native_transfer_transcripts(permit)
            .unwrap();
        finalize(&mut transaction).unwrap();
        drop(transaction);
        assert_eq!(block.native_maintenance_usage_for_testing(), before);
        assert!(receipts(&block.world, &owner, None, 10).unwrap().is_empty());
        process_idle_accounts(block).unwrap();
        assert_eq!(receipts(&block.world, &owner, None, 10).unwrap().len(), 1);
    });
}
