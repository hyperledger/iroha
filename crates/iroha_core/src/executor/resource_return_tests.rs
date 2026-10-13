//! Executor output reads retain original local attempt custody until the transaction bridge.

use super::*;
use crate::{
    execution_attempt::ExecutionAttemptError,
    smartcontracts::ivm::return_value::resource_tests::{funded_return_vm, leave_read_slots},
};

#[test]
fn executor_output_reads_preserve_refusal_through_sticky_transaction_bridge() {
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    let (mut vm, budget) = funded_return_vm();
    let payload = [1_u8, 2, 3, 4];
    let framed_len = EXECUTOR_LENGTH_PREFIX_BYTES + payload.len();
    let pointer = vm.alloc_heap(u64::try_from(framed_len).unwrap()).unwrap();
    let mut framed = u64::try_from(framed_len).unwrap().to_le_bytes().to_vec();
    framed.extend_from_slice(&payload);
    vm.store_bytes(pointer, &framed).unwrap();
    assert_eq!(
        executor_output_payload(&vm, pointer, "validation verdict").unwrap(),
        payload
    );
    let gas = vm.remaining_gas();
    // Both real callers use this same fallible prefix/full-frame boundary and
    // already propagate ExecutionAttemptError before verdict or model decode.
    for output_kind in ["validation verdict", "migration result"] {
        for spare_reads in 0..2 {
            let expected = crate::execution_attempt::ExecutionDeferred::try_from_vm_error(
                leave_read_slots(&vm, &budget, spare_reads),
            )
            .unwrap();
            let error = executor_output_payload(&vm, pointer, output_kind).unwrap_err();
            let ExecutionAttemptError::Deferred(owner) = &error else {
                panic!("local output read became a completed rejection: {error}");
            };
            assert_eq!(owner.allocation_refusal(), expected.allocation_refusal());
            assert_eq!(owner.reason(), expected.reason());
            let state = State::new_for_testing(
                World::default(),
                Kura::blank_kura_for_testing(),
                LiveQueryStore::start_test(),
            );
            let mut block = state.block(iroha_data_model::block::BlockHeader::new(
                std::num::NonZeroU64::MIN,
                None,
                None,
                0,
                0,
            ));
            let mut transaction = block.transaction();
            let fuel = transaction.executor_fuel_remaining;
            transaction.attempt_error_to_validation_fail(error);
            let moved = transaction.take_execution_deferral().unwrap();
            assert_eq!(moved.allocation_refusal(), expected.allocation_refusal());
            assert_eq!(moved.reason(), expected.reason());
            assert!(transaction.is_execution_deferred());
            assert_eq!(transaction.last_tx_gas_used, 0);
            assert_eq!(transaction.executor_fuel_remaining, fuel);
            assert_eq!(vm.remaining_gas(), gas);
            budget.set_limit_bytes(128 * 1024 * 1024);
            assert_eq!(
                executor_output_payload(&vm, pointer, output_kind).unwrap(),
                payload
            );
        }
    }
}

#[test]
fn executor_output_reader_retains_deterministic_length_and_memory_rejections() {
    let (mut vm, _budget) = funded_return_vm();
    let pointer = vm.alloc_heap(8).unwrap();
    for (declared, message) in [
        (
            EXECUTOR_LENGTH_PREFIX_BYTES_U64 - 1,
            "shorter than its fixed u64 length prefix",
        ),
        (MAX_EXECUTOR_OUTPUT_BYTES + 1, "length exceeds"),
    ] {
        vm.store_u64(pointer, declared).unwrap();
        let error = executor_output_payload(&vm, pointer, "validation verdict").unwrap_err();
        assert!(matches!(
            &error,
            ExecutionAttemptError::Rejected(ValidationFail::InternalError(_))
        ));
        assert!(error.to_string().contains(message));
    }
    let error = executor_output_payload(&vm, u64::MAX, "migration result").unwrap_err();
    assert!(matches!(
        &error,
        ExecutionAttemptError::Rejected(ValidationFail::InternalError(_))
    ));
    assert!(error.to_string().contains("length prefix is not readable"));
}
