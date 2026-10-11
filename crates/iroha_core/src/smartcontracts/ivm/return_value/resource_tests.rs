//! Return collection preserves local resource refusal through the real memory owner.

use super::*;
use crate::execution_attempt::{ExecutionAttemptError, ExecutionDeferred, vm_attempt_error};
use iroha_allocation::{AllocationBudget, AllocationRefusal};
use iroha_data_model::smart_contract::entrypoint::{
    EntrypointValueKindV1, EntrypointValueTypeNodeV1, EntrypointValueTypeV1,
    MAX_ENTRYPOINT_RETURN_RECORD_BYTES,
};
use iroha_primitives::bigint::BigInt;
use ivm::{IVM, VMError, error::ExecutionDeferral};

const FUNDED_BYTES: usize = 128 * 1024 * 1024;

/// Complete an authenticated root call before trusted fixture mutation.
pub(crate) fn funded_return_vm() -> (IVM, AllocationBudget) {
    let budget = AllocationBudget::new(FUNDED_BYTES);
    let mut vm = IVM::try_new_with_memory_budget(100_000, &budget).expect("fund root VM");
    let program = kotodama_lang::compiler::Compiler::new()
        .compile_source("seiyaku ResourceReturn { view fn main() authorize(anyone) { () } }")
        .expect("compile authenticated root call");
    vm.load_program(&program)
        .expect("load authenticated root call");
    vm.select_entrypoint("main").expect("select root call");
    vm.run().expect("complete root call");
    assert_eq!(vm.call_result_word_count().unwrap(), 1);
    (vm, budget)
}

/// Fill the original funded read backing, leaving an exact number of read slots.
///
/// No mock injection or substitute pool creates the refusal. The successful
/// count is observed through actual loads, bounded for this tiny fixture.
pub(crate) fn leave_read_slots(vm: &IVM, budget: &AllocationBudget, spare_reads: usize) -> VMError {
    vm.memory.clear_tracking();
    budget.set_limit_bytes(budget.reserved_bytes());
    let mut capacity = 0;
    let refusal = loop {
        assert!(
            capacity < 65_536,
            "tiny fixture must reach its funded read boundary"
        );
        match vm.memory.load_u64(vm.register(10)) {
            Ok(_) => capacity += 1,
            Err(error @ VMError::AllocationDeferred(AllocationRefusal::Capacity { .. })) => {
                break error;
            }
            Err(error) => panic!("unexpected tracked load failure: {error}"),
        }
    };
    assert!(capacity >= spare_reads);
    let reserved = budget.reserved_bytes();
    vm.memory.clear_tracking();
    for _ in 0..capacity - spare_reads {
        vm.memory
            .load_u64(vm.register(10))
            .expect("reuse admitted read slot");
    }
    assert_eq!(budget.reserved_bytes(), reserved);
    refusal
}

fn leaf(kind: EntrypointValueKindV1) -> EntrypointValueTypeV1 {
    EntrypointValueTypeV1 {
        nodes: vec![EntrypointValueTypeNodeV1::Leaf(kind)],
    }
}

fn expect_deferred(error: EntrypointReturnDecodeError, expected: &VMError) {
    let EntrypointReturnDecodeError::ExecutionDeferred { word_index, reason } = error else {
        panic!("local capacity must remain a typed execution deferral: {error:?}");
    };
    assert_eq!(word_index, 0);
    assert_eq!(&reason, expected);
    let owner = ExecutionDeferred::from_vm_error(&reason).expect("retain local retry owner");
    assert_eq!(owner.into_vm_error(), expected.clone().into_unmetered());
}

#[test]
fn public_return_collectors_preserve_actual_read_capacity_and_retry() {
    type Collector = fn(&IVM, &EntrypointValueTypeV1) -> Result<(), EntrypointReturnDecodeError>;
    let collectors: [Collector; 3] = [
        |vm, schema| encode_entrypoint_return_record(vm, schema).map(|_| ()),
        |vm, schema| encode_entrypoint_return_record_bytes(vm, schema).map(|_| ()),
        |vm, schema| decode_entrypoint_return(vm, schema).map(|_| ()),
    ];
    let schema = EntrypointValueTypeV1 {
        nodes: vec![EntrypointValueTypeNodeV1::Unit],
    };
    for collect in collectors {
        let (vm, budget) = funded_return_vm();
        collect(&vm, &schema).expect("valid completed return");
        let gas = vm.remaining_gas();
        let expected = leave_read_slots(&vm, &budget, 0);
        expect_deferred(collect(&vm, &schema).unwrap_err(), &expected);
        assert_eq!(vm.remaining_gas(), gas);
        assert_eq!(vm.call_result_word_count().unwrap(), 1);
        budget.set_limit_bytes(FUNDED_BYTES);
        collect(&vm, &schema).expect("same valid return retries after original-pool admission");
        assert_eq!(vm.remaining_gas(), gas);
        drop(vm);
        assert_eq!(
            budget.reserved_bytes(),
            0,
            "final VM owner refunds every backing"
        );
    }
}

#[test]
fn pointer_return_preserves_refusal_at_each_tracked_read_boundary() {
    let (mut vm, budget) = funded_return_vm();
    let envelope = ivm_abi::numeric_tlv::encode_int(&BigInt::from_i128(42)).unwrap();
    let pointer = vm
        .alloc_heap(u64::try_from(envelope.len()).unwrap())
        .unwrap();
    vm.store_bytes(pointer, &envelope).unwrap();
    vm.store_u64(vm.register(10), pointer).unwrap();
    let schema = leaf(EntrypointValueKindV1::Int);
    let baseline = encode_entrypoint_return_record_bytes(&vm, &schema).unwrap();
    let gas = vm.remaining_gas();
    // Result word, typed header, validated envelope, and copied envelope each
    // execute their actual tracked load. The fourth boundary belongs to Core.
    for spare_reads in 0..4 {
        let expected = leave_read_slots(&vm, &budget, spare_reads);
        expect_deferred(
            encode_entrypoint_return_record_bytes(&vm, &schema).unwrap_err(),
            &expected,
        );
        assert_eq!(vm.remaining_gas(), gas);
        budget.set_limit_bytes(FUNDED_BYTES);
        assert_eq!(
            encode_entrypoint_return_record_bytes(&vm, &schema).unwrap(),
            baseline
        );
    }
    drop(vm);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn return_error_mapping_retains_all_local_variants_and_metered_owners() {
    let budget = AllocationBudget::new(8);
    let reservation = budget.try_reserve_bytes(8).unwrap();
    let capacity = budget.try_reserve_bytes(1).unwrap_err();
    let errors = [
        VMError::AllocationDeferred(capacity.clone()),
        VMError::AllocationDeferred(AllocationRefusal::DemandOverflow),
        VMError::AllocationDeferred(AllocationRefusal::ExceedsLimit {
            requested_bytes: 9,
            limit_bytes: 8,
        }),
        VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable),
        VMError::ExecutionDeferred(ExecutionDeferral::ActiveMemoryCapacity),
        VMError::ExecutionDeferred(ExecutionDeferral::VerifierArtifactsUnavailable),
        VMError::ExecutionDeferred(ExecutionDeferral::TraceOwnerUnavailable),
        VMError::Metered {
            gas: 17,
            source: Box::new(VMError::AllocationDeferred(capacity)),
        },
    ];
    for expected in errors {
        let error = EntrypointReturnDecodeError::from_vm_error(0, "result table", expected.clone());
        expect_deferred(error, &expected);
        let nested =
            EntrypointReturnDecodeError::from_vm_error(0, "result table", expected.clone())
                .into_nested_vm_error();
        assert_eq!(nested, expected);
        // This is the same meter and attempt classifier used by the nested
        // host/executor boundary. Local refusal must never reach rejection.
        let metered = VMError::metered(91, nested);
        assert_eq!(metered.metered_gas(), None);
        let attempt = vm_attempt_error(metered, |_| panic!("deferral became rejection"));
        let ExecutionAttemptError::Deferred(owner) = attempt else {
            panic!("local refusal must not complete an execution attempt");
        };
        assert_eq!(owner.into_vm_error(), expected.into_unmetered());
    }
    drop(reservation);
}

#[test]
fn return_error_mapping_preserves_privacy_malformed_and_gas_boundaries() {
    assert!(matches!(
        EntrypointReturnDecodeError::from_vm_error(2, "Int", VMError::NoritoInvalid),
        EntrypointReturnDecodeError::InvalidValue {
            word_index: 2,
            kind: "Int",
            ..
        }
    ));
    assert_eq!(
        EntrypointReturnDecodeError::from_vm_error(2, "Int", VMError::NoritoInvalid)
            .into_nested_vm_error(),
        VMError::DecodeError
    );
    assert_eq!(
        EntrypointReturnDecodeError::from_vm_error(2, "Int", VMError::PrivacyViolation)
            .into_nested_vm_error(),
        VMError::PrivacyViolation
    );
    for (max_bytes, expected) in [
        (1024, VMError::OutOfGas),
        (MAX_ENTRYPOINT_RETURN_RECORD_BYTES, VMError::DecodeError),
    ] {
        assert_eq!(
            EntrypointReturnDecodeError::RecordTooLarge {
                bytes: max_bytes + 1,
                max_bytes,
            }
            .into_nested_vm_error(),
            expected
        );
    }
}
