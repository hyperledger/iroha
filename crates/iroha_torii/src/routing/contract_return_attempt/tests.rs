//! Actual funded return-read refusal, transport classification, and retry.

use axum::{http::StatusCode, response::IntoResponse as _};
use iroha_allocation::{AllocationBudget, AllocationRefusal};
use ivm::{IVM, VMError, error::ExecutionDeferral};

use super::*;
use crate::routing::{
    ContractCallSimulationError, ContractViewExecutionError, contract_transport_attempt,
};

const LIMIT: usize = 128 * 1024 * 1024;

fn completed_return() -> (IVM, AllocationBudget, EntrypointValueTypeV1) {
    let original = AllocationBudget::new(LIMIT);
    let mut vm = IVM::try_new_with_memory_budget(100_000, &original).unwrap();
    let program = kotodama_lang::compiler::Compiler::new()
        .compile_source(
            "seiyaku ReturnAttempt { view fn main() authorize(anyone) -> bool { true } }",
        )
        .unwrap();
    vm.load_program(&program).unwrap();
    vm.select_entrypoint("main").unwrap();
    let schema = vm
        .contract_interface()
        .unwrap()
        .entrypoints
        .iter()
        .find(|entry| entry.name == "main")
        .unwrap()
        .return_schema
        .clone()
        .unwrap();
    vm.run().unwrap();
    assert_eq!(vm.call_result_word_count().unwrap(), 1);
    (vm, original, schema)
}

fn exhaust_read_capacity(vm: &IVM, original: &AllocationBudget) -> VMError {
    vm.memory.clear_tracking();
    original.set_limit_bytes(original.reserved_bytes());
    for _ in 0..65_536 {
        match vm.memory.load_u64(vm.register(10)) {
            Ok(_) => {}
            Err(error @ VMError::AllocationDeferred(AllocationRefusal::Capacity { .. })) => {
                return error;
            }
            Err(error) => panic!("unexpected return read failure: {error:?}"),
        }
    }
    panic!("tiny fixture must exhaust its original read backing");
}

fn assert_transport_refusal<E>(
    attempt: Result<Value, ExecutionAttemptError<E>>,
    expected: &VMError,
) {
    let Err(ExecutionAttemptError::Deferred(owner)) = &attempt else {
        panic!("return resource refusal cannot complete an execution attempt");
    };
    assert_eq!(owner.clone().into_vm_error(), *expected);
    match contract_transport_attempt(attempt) {
        Err(error) => assert_eq!(
            error.into_response().status(),
            StatusCode::TOO_MANY_REQUESTS
        ),
        Ok(_) => panic!("local refusal must not publish a completed response DTO"),
    }
}

#[test]
fn original_return_read_refusal_bypasses_both_response_renderers_and_retries() {
    let (vm, original, schema) = completed_return();
    assert_eq!(decode(&vm, &schema).unwrap(), Value::Bool(true));
    let gas = vm.remaining_gas();
    let expected = exhaust_read_capacity(&vm, &original);
    let retained = original.reserved_bytes();
    let view = decode(&vm, &schema).map_err(|error| {
        error.map_rejection(|_| -> ContractViewExecutionError {
            panic!("unfinished view return cannot enter its rejection renderer")
        })
    });
    assert_transport_refusal(view, &expected);
    let simulation = decode(&vm, &schema).map_err(|error| {
        error.map_rejection(|_| -> ContractCallSimulationError {
            panic!("unfinished simulation return cannot publish gas or queued effects")
        })
    });
    assert_transport_refusal(simulation, &expected);
    assert_eq!(vm.remaining_gas(), gas);
    assert_eq!(vm.call_result_word_count().unwrap(), 1);
    assert_eq!(original.reserved_bytes(), retained);
    original.set_limit_bytes(LIMIT);
    assert_eq!(decode(&vm, &schema).unwrap(), Value::Bool(true));
    assert_eq!(vm.remaining_gas(), gas);
    drop(vm);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn malformed_actual_return_keeps_its_completed_semantic_response() {
    let (mut vm, original, schema) = completed_return();
    vm.store_u64(vm.register(10), 2).unwrap();
    let gas = vm.remaining_gas();
    let raw = decode_entrypoint_return(&vm, &schema).unwrap_err();
    assert!(
        vm.last_diagnostic().is_none(),
        "post-success decode is not a VM trap"
    );
    assert!(matches!(
        raw,
        EntrypointReturnDecodeError::NonCanonicalBit {
            word_index: 0,
            role: "bool",
            value: 2,
        }
    ));
    let message = raw.to_string();
    let view = decode(&vm, &schema).map_err(|error| error.map_rejection(|error| error.to_string()));
    let Ok(Err(rejected)) = contract_transport_attempt(view) else {
        panic!("malformed guest return remains a completed rejection");
    };
    assert_eq!(rejected, message);
    assert_eq!(vm.remaining_gas(), gas);
    drop(vm);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn nested_metered_trace_and_allocation_refusals_keep_their_original_owners() {
    let original = AllocationBudget::new(8);
    let held = original.try_reserve_bytes(8).unwrap();
    let capacity = original.try_reserve_bytes(1).unwrap_err();
    let failures = [
        VMError::AllocationDeferred(capacity),
        VMError::AllocationDeferred(AllocationRefusal::DemandOverflow),
        VMError::AllocationDeferred(AllocationRefusal::ExceedsLimit {
            requested_bytes: 9,
            limit_bytes: 8,
        }),
        VMError::ExecutionDeferred(ExecutionDeferral::TraceOwnerUnavailable),
        VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable),
    ];
    for expected in failures {
        let refusal = classify(EntrypointReturnDecodeError::ExecutionDeferred {
            word_index: 0,
            reason: VMError::Metered {
                gas: 31,
                source: Box::new(VMError::Metered {
                    gas: 17,
                    source: Box::new(expected.clone()),
                }),
            },
        });
        let ExecutionAttemptError::Deferred(owner) = refusal else {
            panic!("wrapped local refusal must not become a contract result");
        };
        assert_eq!(owner.into_vm_error(), expected);
    }
    drop(held);
    assert_eq!(original.reserved_bytes(), 0);
}
