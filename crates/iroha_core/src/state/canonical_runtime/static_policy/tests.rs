//! Actual construction and transaction custody for immutable original policies.

use super::*;
use iroha_model_base::state_path::StatePath;

fn addresses(policy: &StaticExecutionPolicy) -> [usize; 7] {
    [
        std::ptr::from_ref(policy) as usize,
        std::ptr::from_ref(&policy.oracle) as usize,
        std::ptr::from_ref(&policy.gov) as usize,
        std::ptr::from_ref(&policy.content) as usize,
        std::ptr::from_ref(&policy.settlement) as usize,
        std::ptr::from_ref(&policy.crypto) as usize,
        Arc::as_ptr(&policy.crypto) as usize,
    ]
}

#[test]
fn transactions_borrow_exact_original_policy_across_rollback_and_apply() {
    let (state, proposal) = crate::state::acquisition_fixture_tests::fixture();
    let original_crypto = state.crypto();
    let mut block = state.block(proposal.header());
    let original = addresses(block.runtime_policy.static_inputs());
    assert_eq!(addresses(std::ops::Deref::deref(&*block)), original);
    assert!(Arc::ptr_eq(&block.crypto, &original_crypto));
    let key: StatePath = "policy/rollback".parse().unwrap();
    {
        let mut transaction = block.transaction();
        assert_eq!(addresses(std::ops::Deref::deref(&transaction)), original);
        assert_eq!(addresses(transaction.static_execution_policy()), original);
        let retained = transaction.static_execution_policy();
        transaction
            .world
            .smart_contract_state
            .insert(key.clone(), vec![7]);
        assert_eq!(
            addresses(retained),
            original,
            "original policy borrow survives disjoint mutation"
        );
        // Drop rolls back real World writes while retaining the block's owner.
    }
    assert!(block.world.smart_contract_state.get(&key).is_none());
    {
        let mut transaction = block.transaction();
        assert_eq!(addresses(std::ops::Deref::deref(&transaction)), original);
        transaction
            .world
            .smart_contract_state
            .insert(key.clone(), vec![9]);
        transaction.apply();
    }
    assert_eq!(block.world.smart_contract_state.get(&key), Some(&vec![9]));
    assert_eq!(addresses(block.runtime_policy.static_inputs()), original);
    assert_eq!(
        addresses(std::ops::Deref::deref(&block.transaction())),
        original
    );
}

#[test]
fn equal_and_different_live_crypto_replacements_cannot_rebind_original_input() {
    let (state, proposal) = crate::state::acquisition_fixture_tests::fixture();
    let mut block = state.block(proposal.header());
    let original = addresses(block.runtime_policy.static_inputs());
    let captured = Arc::clone(&block.crypto);
    // A same-byte foreign Arc is a different live owner, not the retained input.
    state.install_crypto_snapshot_for_isolated_replay((*captured).clone());
    assert!(!Arc::ptr_eq(&state.crypto(), &captured));
    assert!(Arc::ptr_eq(&block.crypto, &captured));
    assert_eq!(
        addresses(std::ops::Deref::deref(&block.transaction())),
        original
    );
    let mut foreign = (*captured).clone();
    foreign.sm2_distid_default.push_str("-foreign");
    state.install_crypto_snapshot_for_isolated_replay(foreign);
    assert_ne!(
        state.crypto().sm2_distid_default,
        captured.sm2_distid_default
    );
    assert_eq!(block.crypto.sm2_distid_default, captured.sm2_distid_default);
    assert_eq!(
        addresses(std::ops::Deref::deref(&block.transaction())),
        original
    );
    assert_eq!(addresses(block.runtime_policy.static_inputs()), original);
}
