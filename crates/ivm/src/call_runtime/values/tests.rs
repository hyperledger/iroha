//! Mutation and staged-gas tests for recursive callable value validation.

use super::*;
use crate::{PointerType, call_frame::CallTables, ivm::call_runtime::CallLayouts};
use ivm_abi::{call::EmbeddedCallableV1, entrypoint::EntrypointValueKindV1 as Kind};

fn root(nodes: Vec<CallTypeNodeV1>) -> (IVM, u64) {
    let bytes = kotodama_lang::compiler::Compiler::new()
        .compile_source("seiyaku Schema { view fn main() authorize(anyone) -> bool { true } }")
        .unwrap();
    let mut interface = crate::ProgramMetadata::parse(&bytes)
        .unwrap()
        .contract_interface
        .unwrap();
    let callable = EmbeddedCallableV1 {
        entry_pc: 0,
        frame_bytes: 128,
        arguments: CallSchemaV1::empty(),
        results: CallSchemaV1 { nodes },
    };
    interface.callables = vec![callable];
    let layouts = CallLayouts::prepare(&interface, None).unwrap();
    let shape = layouts.callable(0).unwrap().frame;
    let mut vm = IVM::new(1_000_000);
    vm.call_layouts = Some(layouts);
    vm.contract_interface = Some(crate::prepared::shared_metadata(interface, true));
    let base = vm.alloc_heap((shape.result_words * 8) as u64).unwrap();
    vm.memory
        .call_frames
        .enter_root(
            vm.memory.stack_top(),
            &shape,
            CallTables {
                argument_base: 0,
                argument_words: 0,
                result_base: base,
                result_words: shape.result_words as u64,
            },
            vm.memory.stack_top(),
        )
        .unwrap();
    vm.registers.set(10, base);
    vm.registers.set(11, shape.result_words as u64);
    vm.registers.set(31, vm.memory.stack_top());
    (vm, base)
}

fn boolean() -> CallTypeNodeV1 {
    CallTypeNodeV1::Leaf(Kind::Bool)
}

fn blob(vm: &mut IVM, value: &[u8]) -> u64 {
    vm.alloc_host_tlv(&ivm_abi::numeric_tlv::encode_envelope(PointerType::Blob, value).unwrap())
        .unwrap()
}

#[test]
fn nested_option_checks_active_bool_and_string_before_return_publication() {
    let nodes = vec![
        CallTypeNodeV1::Option,
        CallTypeNodeV1::Tuple(2),
        boolean(),
        CallTypeNodeV1::Leaf(Kind::String),
    ];
    let (mut vm, table) = root(nodes.clone());
    let sum = vm.alloc_heap(24).unwrap();
    vm.store_u64(table, sum).unwrap();
    vm.store_u64(sum, 0).unwrap();
    vm.store_u64(sum + 8, u64::MAX).unwrap();
    vm.store_u64(sum + 16, u64::MAX).unwrap();
    let before = vm.remaining_gas();
    vm.finish_call().unwrap();
    assert_eq!(
        before - vm.remaining_gas(),
        crate::call_gas::NODE + 2 * crate::call_gas::WORD
    );

    let (mut vm, table) = root(nodes);
    let sum = vm.alloc_heap(24).unwrap();
    let invalid = blob(&mut vm, &[0xff]);
    vm.store_u64(table, sum).unwrap();
    vm.store_u64(sum, 1).unwrap();
    vm.store_u64(sum + 8, 2).unwrap();
    vm.store_u64(sum + 16, invalid).unwrap();
    assert_eq!(vm.finish_call(), Err(VMError::DecodeError));
    assert!(vm.call_result_word_count().is_err());
    vm.store_u64(sum + 8, 1).unwrap();
    assert_eq!(vm.finish_call(), Err(VMError::NoritoInvalid));
    assert!(vm.call_result_word_count().is_err());
    let valid = blob(&mut vm, "日本語".as_bytes());
    vm.store_u64(sum + 16, valid).unwrap();
    vm.finish_call().unwrap();
    assert_eq!(vm.public_call_result_word(0), Ok(sum));
}

#[test]
fn list_requires_exact_capacity_and_validates_only_logical_nested_elements() {
    let (mut vm, table) = root(vec![
        CallTypeNodeV1::List { capacity: 2 },
        CallTypeNodeV1::Option,
        boolean(),
    ]);
    let list = vm.alloc_heap(32).unwrap();
    let some = vm.alloc_heap(16).unwrap();
    vm.store_u64(table, list).unwrap();
    vm.store_u64(list, 1).unwrap();
    vm.store_u64(list + 8, 1).unwrap();
    vm.store_u64(list + 16, some).unwrap();
    vm.store_u64(list + 24, u64::MAX).unwrap();
    vm.store_u64(some, 1).unwrap();
    vm.store_u64(some + 8, 2).unwrap();
    assert_eq!(vm.finish_call(), Err(VMError::DecodeError));
    vm.store_u64(list + 8, 2).unwrap();
    assert_eq!(vm.finish_call(), Err(VMError::DecodeError));
    vm.store_u64(some + 8, 1).unwrap();
    vm.store_u64(list, 2).unwrap();
    assert_eq!(vm.finish_call(), Err(VMError::DecodeError));
    assert!(vm.call_result_word_count().is_err());
    vm.store_u64(list, 1).unwrap();
    let before = vm.remaining_gas();
    vm.finish_call().unwrap();
    assert_eq!(
        before - vm.remaining_gas(),
        3 * crate::call_gas::NODE + 6 * crate::call_gas::WORD
    );
}

#[test]
fn recursive_return_exhausts_each_gas_stage_without_publishing_or_losing_ownership() {
    use crate::call_gas::{NODE, WORD};

    let (mut vm, table) = root(vec![
        CallTypeNodeV1::List { capacity: 2 },
        CallTypeNodeV1::Option,
        boolean(),
    ]);
    let list = vm.alloc_heap(32).unwrap();
    let some = vm.alloc_heap(16).unwrap();
    vm.store_u64(table, list).unwrap();
    for (address, word) in [
        (list, 1),
        (list + 8, 2),
        (list + 16, some),
        (list + 24, u64::MAX),
        (some, 1),
        (some + 8, 1),
    ] {
        vm.store_u64(address, word).unwrap();
    }
    let stages = [NODE, WORD, 2 * WORD, NODE, WORD, WORD, NODE, WORD];
    let exact = stages.iter().sum::<u64>();
    for budget in 0..exact {
        vm.set_gas_limit(budget);
        assert_eq!(vm.finish_call(), Err(VMError::OutOfGas));
        assert!(vm.call_result_word_count().is_err());
        assert_eq!(vm.memory.call_frames.entry_pc(), Ok(0));
        assert_eq!(vm.memory.active_call_result(0), Ok((table, list)));
        let mut remaining = budget;
        for debit in stages {
            if remaining < debit {
                break;
            }
            remaining -= debit;
        }
        assert_eq!(vm.remaining_gas(), remaining, "initial gas {budget}");
    }
    vm.set_gas_limit(exact);
    vm.finish_call().unwrap();
    assert_eq!(vm.remaining_gas(), 0);
    assert_eq!(vm.public_call_result_word(0), Ok(list));
}

#[test]
fn recursive_return_faults_are_observed_only_after_their_validation_charge() {
    use crate::call_gas::{NODE, WORD};

    let (mut vm, table) = root(vec![CallTypeNodeV1::Option, boolean()]);
    vm.store_u64(table, Memory::INPUT_START).unwrap();
    let header_work = NODE + 2 * WORD;
    vm.set_gas_limit(header_work - 1);
    assert_eq!(vm.finish_call(), Err(VMError::OutOfGas));
    vm.set_gas_limit(header_work);
    assert_eq!(vm.finish_call(), Err(VMError::DecodeError));
    assert_eq!(vm.remaining_gas(), 0);
    assert!(vm.call_result_word_count().is_err());

    let some = vm.alloc_heap(16).unwrap();
    vm.store_u64(table, some).unwrap();
    vm.store_u64(some, 1).unwrap();
    vm.store_u64(some + 8, 2).unwrap();
    let active_work = header_work + NODE + WORD;
    vm.set_gas_limit(active_work - 1);
    assert_eq!(vm.finish_call(), Err(VMError::OutOfGas));
    vm.set_gas_limit(active_work);
    assert_eq!(vm.finish_call(), Err(VMError::DecodeError));
    assert_eq!(vm.remaining_gas(), 0);
    assert!(vm.call_result_word_count().is_err());
    vm.store_u64(some + 8, 1).unwrap();
    vm.set_gas_limit(active_work);
    vm.finish_call().unwrap();
    assert_eq!(vm.public_call_result_word(0), Ok(some));
}

#[test]
fn inactive_sum_and_empty_list_still_require_full_aligned_owned_footprints() {
    for nodes in [
        vec![
            CallTypeNodeV1::Option,
            CallTypeNodeV1::Tuple(2),
            boolean(),
            boolean(),
        ],
        vec![CallTypeNodeV1::List { capacity: 2 }, boolean()],
    ] {
        let (mut vm, table) = root(nodes);
        let truncated = vm.alloc_heap(16).unwrap();
        vm.store_u64(table, truncated).unwrap();
        vm.store_u64(truncated, 0).unwrap();
        vm.store_u64(truncated + 8, 2).unwrap();
        assert_eq!(vm.finish_call(), Err(VMError::DecodeError));
        vm.store_u64(table, truncated + 1).unwrap();
        assert_eq!(vm.finish_call(), Err(VMError::DecodeError));
        vm.store_u64(table, Memory::INPUT_START).unwrap();
        assert_eq!(vm.finish_call(), Err(VMError::DecodeError));
        assert!(vm.call_result_word_count().is_err());
    }
}

#[test]
fn result_binds_nominal_error_codes_and_success_branch_without_reading_slack() {
    use iroha_data_model::smart_contract::manifest::{
        ContractErrorTypeDescriptor, ContractErrorVariantDescriptor,
    };
    let error = ContractErrorTypeDescriptor {
        identity: "errors::Failure".into(),
        variants: vec![ContractErrorVariantDescriptor {
            name: "Failed".into(),
            code: 7,
        }],
    };
    let schema = vec![
        CallTypeNodeV1::Result,
        CallTypeNodeV1::Tuple(2),
        boolean(),
        boolean(),
        CallTypeNodeV1::Error(error),
    ];
    let (mut vm, table) = root(schema.clone());
    let sum = vm.alloc_heap(24).unwrap();
    vm.store_u64(table, sum).unwrap();
    vm.store_u64(sum, 0).unwrap();
    vm.store_u64(sum + 8, 8).unwrap();
    vm.store_u64(sum + 16, u64::MAX).unwrap();
    assert_eq!(vm.finish_call(), Err(VMError::DecodeError));
    vm.store_u64(sum + 8, 7).unwrap();
    vm.finish_call().unwrap();
    let (mut vm, table) = root(schema);
    let sum = vm.alloc_heap(24).unwrap();
    vm.store_u64(table, sum).unwrap();
    vm.store_u64(sum, 1).unwrap();
    vm.store_u64(sum + 8, 1).unwrap();
    vm.store_u64(sum + 16, 0).unwrap();
    vm.finish_call().unwrap();
}

#[test]
fn empty_product_requires_initialized_zero_word_and_node_work_is_prepaid() {
    let (mut vm, table) = root(vec![CallTypeNodeV1::Struct {
        name: "Fixture::Empty".into(),
        fields: vec![],
    }]);
    assert_eq!(vm.finish_call(), Err(VMError::AssertionFailed));
    vm.store_u64(table, 1).unwrap();
    assert_eq!(vm.finish_call(), Err(VMError::DecodeError));
    vm.store_u64(table, 0).unwrap();
    vm.set_gas_limit(crate::call_gas::NODE + crate::call_gas::WORD - 1);
    assert_eq!(vm.finish_call(), Err(VMError::OutOfGas));
    assert!(vm.call_result_word_count().is_err());
    vm.set_gas_limit(crate::call_gas::NODE + crate::call_gas::WORD);
    vm.finish_call().unwrap();
    assert_eq!(vm.remaining_gas(), 0);
}

#[test]
fn aggregate_headers_and_active_leaves_preserve_private_tags() {
    let (mut vm, table) = root(vec![CallTypeNodeV1::Option, boolean()]);
    // Enabling ZK before installing private fixture tags avoids changing call ownership.
    vm.zk_mode = true;
    let sum = vm.alloc_heap(16).unwrap();
    vm.store_u64(table, sum).unwrap();
    vm.store_u64(sum, 1).unwrap();
    vm.store_u64(sum + 8, 1).unwrap();
    vm.preflight_memory_store_privacy(sum + 8, 8, true).unwrap();
    vm.record_memory_store_privacy(sum + 8, 8, true);
    assert_eq!(vm.finish_call(), Err(VMError::PrivacyViolation));
    assert!(vm.call_result_word_count().is_err());
    vm.store_u64(sum, 0).unwrap();
    vm.finish_call().unwrap();
}

#[test]
fn nested_argument_fault_keeps_caller_frame_and_never_publishes_results() {
    let (mut vm, _) = root(vec![boolean()]);
    let mut interface = vm.contract_interface.as_ref().unwrap().as_ref().clone();
    interface.callables.push(EmbeddedCallableV1 {
        entry_pc: 4,
        frame_bytes: 32,
        arguments: CallSchemaV1 {
            nodes: vec![CallTypeNodeV1::Option, boolean()],
        },
        results: CallSchemaV1 {
            nodes: vec![boolean()],
        },
    });
    vm.call_layouts = Some(CallLayouts::prepare(&interface, None).unwrap());
    vm.contract_interface = Some(crate::prepared::shared_metadata(interface, true));
    vm.strict_return_integrity = true;
    let caller = vm.memory.stack_top() - 128;
    let sum = vm.alloc_heap(16).unwrap();
    vm.store_u64(sum, 1).unwrap();
    vm.store_u64(sum + 8, 2).unwrap();
    vm.store_u64(caller, sum).unwrap();
    for (register, value) in [
        (10, caller),
        (11, 1),
        (12, caller + 8),
        (13, 1),
        (31, caller),
    ] {
        vm.registers.set(register, value);
    }
    assert_eq!(vm.begin_child_call(4), Err(VMError::DecodeError));
    assert_eq!(vm.memory.call_frames.entry_pc(), Ok(0));
    assert!(vm.call_result_word_count().is_err());
    vm.store_u64(sum + 8, 1).unwrap();
    vm.begin_child_call(4).unwrap();
    assert_eq!(vm.memory.call_frames.entry_pc(), Ok(4));
    vm.store_u64(caller + 8, 1).unwrap();
    vm.registers.set(10, caller + 8);
    vm.finish_call().unwrap();
    assert_eq!(vm.memory.call_frames.entry_pc(), Ok(0));
    assert!(vm.call_result_word_count().is_err());
}

#[test]
fn maximum_schema_depth_and_repeated_list_subtrees_use_bounded_continuations() {
    let mut schema = vec![CallTypeNodeV1::Option; MAX_CALL_SCHEMA_DEPTH_V1 - 1];
    schema.push(boolean());
    let (mut vm, table) = root(schema);
    let mut payload = 1;
    for _ in 1..MAX_CALL_SCHEMA_DEPTH_V1 {
        let sum = vm.alloc_heap(16).unwrap();
        vm.store_u64(sum, 1).unwrap();
        vm.store_u64(sum + 8, payload).unwrap();
        payload = sum;
    }
    vm.store_u64(table, payload).unwrap();
    vm.finish_call().unwrap();

    let (mut vm, table) = root(vec![
        CallTypeNodeV1::List { capacity: 2 },
        CallTypeNodeV1::Tuple(2),
        boolean(),
        boolean(),
    ]);
    let list = vm.alloc_heap(48).unwrap();
    vm.store_u64(table, list).unwrap();
    for (index, word) in [2, 2, 1, 0, 0, 2].into_iter().enumerate() {
        vm.store_u64(list + index as u64 * 8, word).unwrap();
    }
    assert_eq!(vm.finish_call(), Err(VMError::DecodeError));
    vm.store_u64(list + 40, 1).unwrap();
    vm.finish_call().unwrap();
}
