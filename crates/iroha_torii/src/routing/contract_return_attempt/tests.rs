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
    assert_eq!(Some(owner.reason()), expected.execution_deferral());
    let VMError::AllocationDeferred(expected) = expected else {
        panic!("actual return read must retain its original allocation refusal");
    };
    assert_eq!(owner.allocation_refusal(), Some(expected));
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
        let expected_reason = expected.execution_deferral().unwrap();
        let expected_allocation = match &expected {
            VMError::AllocationDeferred(original) => Some(original.clone()),
            _ => None,
        };
        let refusal = classify(EntrypointReturnDecodeError::ExecutionDeferred {
            word_index: 0,
            reason: VMError::Metered {
                gas: 31,
                source: Box::new(VMError::Metered {
                    gas: 17,
                    source: Box::new(expected),
                }),
            },
        });
        let ExecutionAttemptError::Deferred(owner) = refusal else {
            panic!("wrapped local refusal must not become a contract result");
        };
        assert_eq!(owner.reason(), expected_reason);
        assert_eq!(owner.allocation_refusal(), expected_allocation.as_ref());
        let moved = owner.into_vm_error();
        assert_eq!(moved.execution_deferral(), Some(expected_reason));
        assert_eq!(moved.metered_gas(), None);
    }
    drop(held);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn nonlocal_error_in_return_wrapper_keeps_completed_payload_and_word_index() {
    let error = classify(EntrypointReturnDecodeError::ExecutionDeferred {
        word_index: 19,
        reason: VMError::Metered {
            gas: 41,
            source: Box::new(VMError::PermissionDenied),
        },
    });
    let ExecutionAttemptError::Rejected(EntrypointReturnDecodeError::ExecutionDeferred {
        word_index,
        reason,
    }) = error
    else {
        panic!("a completed nonlocal error must retain its complete unmatched wrapper");
    };
    assert_eq!(word_index, 19);
    assert_eq!(reason.metered_gas(), Some(41));
    assert!(matches!(reason.into_unmetered(), VMError::PermissionDenied));
}

#[test]
fn captured_decoder_and_shared_verifier_owners_survive_both_route_classifiers() {
    for shared in [false, true] {
        let captured = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32),
            || {
                norito::core::classify_decode_attempt(|| {
                    norito::core::reserve_decode_allocation(11)
                })
            },
        )
        .unwrap_err();
        let expected = captured.local_refusal().unwrap();
        let original = captured.into_local_refusal().unwrap();
        let reason = if shared {
            VMError::VerificationDeferred(ivm::error::VerificationRefusal::from_decode_refusal(
                original,
            ))
        } else {
            VMError::DecodeDeferred(original)
        };
        let returned = classify(EntrypointReturnDecodeError::ExecutionDeferred {
            word_index: 0,
            reason: VMError::Metered {
                gas: 17,
                source: Box::new(reason),
            },
        });
        let ExecutionAttemptError::Deferred(original) = returned else {
            panic!("original local owner cannot become a public result");
        };
        assert_eq!(original.decode_refusal(), Some(&expected));
        assert!(original.allocation_refusal().is_none());
        assert_eq!(original.verification_refusal().is_some(), shared);
        let converted: ExecutionAttemptError<()> =
            crate::routing::contract_vm_attempt_error(original.into_vm_error(), |_| {
                panic!("unfinished VM error cannot enter a completed renderer")
            });
        let ExecutionAttemptError::Deferred(original) = converted else {
            panic!("route classifier must consume the same local owner");
        };
        assert_eq!(original.decode_refusal(), Some(&expected));
        let result: Result<Value, ExecutionAttemptError<()>> =
            Err(ExecutionAttemptError::Deferred(original));
        assert_eq!(
            contract_transport_attempt(result)
                .unwrap_err()
                .into_response()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        norito::core::reserve_decode_allocation(11).unwrap();
    }
}
