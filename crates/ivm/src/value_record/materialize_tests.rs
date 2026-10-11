//! Exact funded nested-return copying and authenticated direct argument installation.
use super::*;
use crate::VMError;
use ivm_abi::entrypoint::EntrypointValueTypeNodeV1 as Node;

pub(crate) fn complete_test_result(source: &mut IVM, words: &[u64]) -> u64 {
    let result_table = source.alloc_heap((words.len() * 8) as u64).unwrap();
    let stack_top = source.memory.stack_top();
    let callable = crate::call_frame::CallFrameShape {
        entry_pc: 0,
        frame_bytes: 0,
        argument_words: 0,
        result_words: words.len(),
    };
    source
        .memory
        .call_frames
        .enter_root(
            stack_top,
            &callable,
            crate::call_frame::CallTables {
                argument_base: 0,
                argument_words: 0,
                result_base: result_table,
                result_words: words.len() as u64,
            },
            stack_top,
        )
        .unwrap();
    for (index, word) in words.iter().enumerate() {
        source
            .store_u64(result_table + (index * 8) as u64, *word)
            .unwrap();
    }
    // These unit tests exercise schema validation independently of root runtime role validation.
    source
        .memory
        .call_frames
        .finish(stack_top, result_table, words.len() as u64)
        .unwrap();
    result_table
}

fn transfer_return(
    source: &IVM,
    destination: &mut IVM,
    schema: &EntrypointValueTypeV1,
    arity: usize,
    result_table: u64,
) -> Result<(), VMError> {
    let budget = iroha_allocation::AllocationBudget::new(8 * 1024 * 1024);
    validate_return_destination(destination, result_table, arity)?;
    let record = capture_completed_return_funded(source, schema, &budget)?;
    transfer_return_record_funded(
        &record,
        schema,
        destination,
        result_table,
        arity,
        destination.remaining_gas(),
        &budget,
    )
    .and_then(|gas| {
        destination.debit_gas(gas)?;
        destination.set_register(10, result_table);
        destination.set_register(11, arity as u64);
        Ok(())
    })
}
mod tests {
    use super::*;
    use crate::PointerType;
    use iroha_primitives::numeric_abi::IntValueV1;
    use ivm_abi::entrypoint::EntrypointListTypeNodeV1;
    use ivm_abi::entrypoint::{EntrypointValueKindV1 as Kind, EntrypointValueTypeNodeV1 as Node};

    fn make_tlv(pointer_type: PointerType, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(7 + payload.len() + iroha_crypto::Hash::LENGTH);
        out.extend_from_slice(&(pointer_type as u16).to_be_bytes());
        out.push(1);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        let hash: [u8; 32] = iroha_crypto::Hash::new(payload).into();
        out.extend_from_slice(&hash);
        out
    }

    #[test]
    fn nested_sum_list_returns_own_all_handles_and_tlvs() {
        let schema = EntrypointValueTypeV1 {
            nodes: vec![
                Node::Option,
                Node::List(EntrypointListTypeNodeV1 { capacity: 2 }),
                Node::Result,
                Node::Leaf(Kind::Int),
                Node::Leaf(Kind::Bool),
            ],
        };
        let sum = SumLayoutV1::try_new(1, 1).unwrap();
        let list = ListLayoutV1::try_new(2, 1).unwrap();
        let option = SumLayoutV1::option(1).unwrap();
        let mut source = IVM::new(0);
        let integer = source
            .alloc_host_tlv(&ivm_abi::numeric_tlv::encode_int(&30.into()).unwrap())
            .unwrap();
        let ok = crate::sum::allocate_words(&mut source, sum, 1, &[integer]).unwrap();
        let err = crate::sum::allocate_words(&mut source, sum, 0, &[1]).unwrap();
        let items = crate::list::allocate_words(&mut source, list, &[vec![ok], vec![err]]).unwrap();
        let some = crate::sum::allocate_words(&mut source, option, 1, &[items]).unwrap();
        complete_test_result(&mut source, &[some]);
        let mut destination = IVM::new(1_000_000);
        destination.alloc_heap(128).unwrap();
        let result_table = destination.alloc_heap(8).unwrap();
        transfer_return(&source, &mut destination, &schema, 1, result_table).unwrap();
        drop(source);
        let (tag, active) = crate::sum::read_words(
            &destination,
            destination.load_u64(result_table).unwrap(),
            option,
        )
        .unwrap();
        assert!(tag);
        let elements = crate::list::read_words(&destination, active[0], list).unwrap();
        assert_eq!(elements.len(), 2);
        let (tag, active) = crate::sum::read_words(&destination, elements[0][0], sum).unwrap();
        assert!(tag);
        let value = destination.validate_tlv(active[0]).unwrap();
        assert_eq!(value.type_id, PointerType::Int);
        assert_eq!(
            IntValueV1::decode_frame(value.payload)
                .unwrap()
                .into_int()
                .try_to_i64(),
            Some(30)
        );
        assert_eq!(
            crate::sum::read_words(&destination, elements[1][0], sum).unwrap(),
            (false, vec![1])
        );
    }

    #[test]
    fn malformed_return_shape_or_handle_cannot_mutate_destination() {
        let schema = EntrypointValueTypeV1 {
            nodes: vec![Node::Option, Node::Leaf(Kind::Int)],
        };
        let layout = SumLayoutV1::option(1).unwrap();
        let mut source = IVM::new(0);
        let none = crate::sum::allocate_words(&mut source, layout, 0, &[]).unwrap();
        complete_test_result(&mut source, &[none]);
        let mut destination = IVM::new(1_000_000);
        destination.set_register(10, 42);
        let result_table = destination.alloc_heap(8).unwrap();
        destination.store_u64(result_table, 99).unwrap();
        let allocated = destination.memory.heap_allocated_len();
        assert!(transfer_return(&source, &mut destination, &schema, 2, result_table).is_err());
        assert!(transfer_return(&source, &mut destination, &schema, 1, result_table + 1).is_err());
        assert!(transfer_return(&source, &mut destination, &schema, 1, 0).is_err());
        for unowned in [
            result_table + 8,
            crate::Memory::OUTPUT_START,
            destination.memory.stack_top() - 8,
        ] {
            assert!(transfer_return(&source, &mut destination, &schema, 1, unowned).is_err());
        }
        source.store_u64(none + 8, 99).unwrap();
        assert!(transfer_return(&source, &mut destination, &schema, 1, result_table).is_err());
        assert_eq!(destination.register(10), 42);
        assert_eq!(destination.memory.heap_allocated_len(), allocated);
        assert_eq!(destination.load_u64(result_table).unwrap(), 99);
        source.store_u64(none + 8, 0).unwrap();
        transfer_return(&source, &mut destination, &schema, 1, result_table).unwrap();
        assert_eq!(
            crate::sum::read_words(
                &destination,
                destination.load_u64(result_table).unwrap(),
                layout
            )
            .unwrap(),
            (false, vec![])
        );
    }

    #[test]
    fn ordinary_enum_transfer_validates_before_mutating_destination() {
        let schema = EntrypointValueTypeV1 { nodes: vec![Node::Enum(iroha_data_model::smart_contract::manifest::ContractEnumTypeDescriptorV1 {
                identity: "local::Status".into(),
                variants: vec![
                    iroha_data_model::smart_contract::manifest::ContractEnumVariantDescriptorV1 { name: "Open".into(), code: 1 },
                    iroha_data_model::smart_contract::manifest::ContractEnumVariantDescriptorV1 { name: "Closed".into(), code: 7 },
                ],
            })] };
        let mut source = IVM::new(0);
        let source_table = complete_test_result(&mut source, &[7]);
        let mut destination = IVM::new(1_000_000);
        let result_table = destination.alloc_heap(8).unwrap();
        transfer_return(&source, &mut destination, &schema, 1, result_table).unwrap();
        assert_eq!(destination.load_u64(result_table).unwrap(), 7);
        for word in [0, 2, u64::MAX] {
            source.store_u64(source_table, word).unwrap();
            assert_eq!(
                transfer_return(&source, &mut destination, &schema, 1, result_table),
                Err(VMError::DecodeError)
            );
            assert_eq!(destination.load_u64(result_table).unwrap(), 7);
        }
    }
    #[test]
    fn tuple_transfer_validates_scalars_and_all_nested_pointer_types() {
        let schema = EntrypointValueTypeV1 {
            nodes: vec![
                Node::Tuple(2),
                Node::Leaf(Kind::Bool),
                Node::Leaf(Kind::Int),
            ],
        };
        let mut source = IVM::new(0);
        let wrong = source
            .alloc_host_tlv(&make_tlv(PointerType::Blob, b"wrong"))
            .unwrap();
        let source_table = complete_test_result(&mut source, &[2, wrong]);
        let mut destination = IVM::new(1_000_000);
        let result_table = destination.alloc_heap(16).unwrap();
        assert!(transfer_return(&source, &mut destination, &schema, 2, result_table).is_err());
        source.store_u64(source_table, 1).unwrap();
        assert!(transfer_return(&source, &mut destination, &schema, 2, result_table).is_err());
        let integer = source
            .alloc_host_tlv(&ivm_abi::numeric_tlv::encode_int(&7.into()).unwrap())
            .unwrap();
        source.store_u64(source_table + 8, integer).unwrap();
        transfer_return(&source, &mut destination, &schema, 2, result_table).unwrap();
        assert_eq!(destination.load_u64(result_table).unwrap(), 1);
        assert_eq!(
            destination
                .validate_tlv(destination.load_u64(result_table + 8).unwrap())
                .unwrap()
                .type_id,
            PointerType::Int
        );
    }
}

#[cfg(test)]
mod depth_tests {
    use super::*;
    #[test]
    fn maximal_option_depth_and_unit_word_transfer_without_recursion() {
        let mut schema = EntrypointValueTypeV1 {
            nodes: vec![Node::Unit],
        };
        let mut source = IVM::new(0);
        let mut destination = IVM::new(1_000_000);
        let source_table = complete_test_result(&mut source, &[0]);
        let result_table = destination.alloc_heap(8).unwrap();
        transfer_return(&source, &mut destination, &schema, 1, result_table).unwrap();
        assert_eq!(destination.load_u64(result_table).unwrap(), 0);
        let layout = SumLayoutV1::option(1).unwrap();
        let mut handle = 0;
        for _ in 1..ivm_abi::entrypoint::MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH {
            schema.nodes.insert(0, Node::Option);
            handle = crate::sum::allocate_words(&mut source, layout, 1, &[handle]).unwrap();
        }
        source.store_u64(source_table, handle).unwrap();
        transfer_return(&source, &mut destination, &schema, 1, result_table).unwrap();
        drop(source);
        let mut handle = destination.load_u64(result_table).unwrap();
        for _ in 1..ivm_abi::entrypoint::MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH {
            let (tag, payload) = crate::sum::read_words(&destination, handle, layout).unwrap();
            assert!(tag);
            handle = payload[0];
        }
        assert_eq!(handle, 0);
    }
}

#[test]
fn funded_arguments_install_once_without_public_input_transport_or_record_decode() {
    let (code, manifest) = kotodama_lang::compiler::Compiler::new().compile_source_with_manifest(
        "seiyaku DirectArguments { view fn echo(bool value) authorize(anyone) -> bool { value } }"
    ).unwrap();
    let entry = manifest
        .entrypoints
        .as_ref()
        .unwrap()
        .iter()
        .find(|entry| entry.name == "echo")
        .unwrap();
    let schema = entry.argument_schema.as_ref().unwrap();
    let mut source = IVM::new(1_000_000);
    let base = source.alloc_heap(8).unwrap();
    source.store_u64(base, 1).unwrap();
    let budget = iroha_allocation::AllocationBudget::new(8 * 1024 * 1024);
    let quote = quote_argument_record(&source, schema, base, 1, source.remaining_gas()).unwrap();
    let insufficient = quote_argument_record(&source, schema, base, 1, quote.gas - 1).unwrap_err();
    assert!(matches!(insufficient.as_unmetered(), VMError::OutOfGas));
    assert_eq!(insufficient.split_metered().0, Some(quote.gas - 1));
    let captured = capture_argument_record_funded(&source, schema, base, 1, &budget).unwrap();
    let mut child = IVM::new(1_000_000);
    child.load_program(&code).unwrap();
    child.select_entrypoint("echo").unwrap();
    let gas_before = child.remaining_gas();
    crate::argument_record::reset_argument_record_decode_count();
    install_captured_arguments(&captured, schema, &mut child, 1, &budget).unwrap();
    assert!(child.remaining_gas() < gas_before);
    assert!(install_captured_arguments(&captured, schema, &mut child, 1, &budget).is_err());
    drop(captured);
    assert_eq!(budget.reserved_bytes(), 0);
    child
        .run_with_host(&mut crate::host::DefaultHost::default())
        .unwrap();
    assert_eq!(child.public_call_result_word(0), Ok(1));
    assert_eq!(crate::argument_record::argument_record_decode_count(), 0);
    assert!(child.captured_root_tables.is_none());
}

#[test]
fn captured_argument_local_refusal_and_gas_exhaustion_leave_child_unprepared() {
    let (code, manifest) = kotodama_lang::compiler::Compiler::new().compile_source_with_manifest(
        "seiyaku DirectArguments { view fn echo(bool value) authorize(anyone) -> bool { value } }"
    ).unwrap();
    let schema = manifest.entrypoints.as_ref().unwrap()[0]
        .argument_schema
        .as_ref()
        .unwrap();
    let mut source = IVM::new(1_000_000);
    let base = source.alloc_heap(8).unwrap();
    source.store_u64(base, 1).unwrap();
    let budget = iroha_allocation::AllocationBudget::new(8 * 1024 * 1024);
    let captured = capture_argument_record_funded(&source, schema, base, 1, &budget).unwrap();
    let retained = budget.reserved_bytes();
    let mut child = IVM::new(0);
    child.load_program(&code).unwrap();
    child.select_entrypoint("echo").unwrap();
    let heap = child.memory.heap_allocated_len();
    assert!(matches!(
        install_captured_arguments(&captured, schema, &mut child, 1, &budget),
        Err(VMError::OutOfGas)
    ));
    assert_eq!(child.memory.heap_allocated_len(), heap);
    assert!(child.captured_root_tables.is_none());
    child.set_gas_limit(1_000_000);
    budget.set_limit_bytes(retained);
    assert!(matches!(
        install_captured_arguments(&captured, schema, &mut child, 1, &budget),
        Err(VMError::AllocationDeferred(_))
    ));
    assert_eq!(child.memory.heap_allocated_len(), heap);
    assert!(child.captured_root_tables.is_none());
    assert_eq!(budget.reserved_bytes(), retained);
}

#[test]
fn funded_return_transfer_uses_explicit_escrow_and_preserves_call_descriptors() {
    let schema = EntrypointValueTypeV1 {
        nodes: vec![Node::Leaf(EntrypointValueKindV1::Bool)],
    };
    let mut source = IVM::new(0);
    complete_test_result(&mut source, &[1]);
    let budget = iroha_allocation::AllocationBudget::new(1024 * 1024);
    let quote = quote_completed_return_record(&source, &schema, u64::MAX).unwrap();
    assert!(quote.gas > 0);
    let captured = capture_completed_return_funded(&source, &schema, &budget).unwrap();
    let retained = budget.reserved_bytes();
    let mut parent = IVM::new(0);
    let table = parent.alloc_heap(8).unwrap();
    parent.store_u64(table, 77).unwrap();
    parent.set_register(10, 91);
    parent.set_register(11, 92);
    assert_eq!(
        transfer_return_record_funded(&captured, &schema, &mut parent, table, 1, 0, &budget),
        Err(VMError::OutOfGas)
    );
    assert_eq!(parent.load_u64(table), Ok(77));
    assert_eq!(budget.reserved_bytes(), retained);
    let gas = transfer_return_record_funded(
        &captured,
        &schema,
        &mut parent,
        table,
        1,
        1_000_000,
        &budget,
    )
    .unwrap();
    assert!(gas > 0);
    assert_eq!(parent.remaining_gas(), 0);
    assert_eq!(parent.load_u64(table), Ok(1));
    assert_eq!(parent.register(10), 91);
    assert_eq!(parent.register(11), 92);
    let other = iroha_allocation::AllocationBudget::new(1024 * 1024);
    assert!(matches!(
        transfer_return_record_funded(&captured, &schema, &mut parent, table, 1, 1_000_000, &other),
        Err(VMError::ExecutionDeferred(
            crate::ExecutionDeferral::LocalInvariantViolation
        ))
    ));
    drop(captured);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn empty_captured_root_is_metered_and_selection_invalidates_preparation() {
    let code = kotodama_lang::compiler::Compiler::new()
        .compile_source("seiyaku DirectEmpty { view fn echo() authorize(anyone) -> bool { true } }")
        .unwrap();
    let mut child = IVM::new(100_000);
    child.load_program(&code).unwrap();
    child.select_entrypoint("echo").unwrap();
    let gas = child.remaining_gas();
    install_empty_captured_arguments(&mut child, 1).unwrap();
    assert_eq!(child.remaining_gas(), gas - 40);
    assert!(child.captured_root_tables.is_some());
    child.select_entrypoint("echo").unwrap();
    assert!(child.captured_root_tables.is_none());
    install_empty_captured_arguments(&mut child, 1).unwrap();
    child.run().unwrap();
    assert_eq!(child.public_call_result_word(0), Ok(1));
}

#[test]
fn funded_return_copy_retries_original_record_after_pool_shrink_and_guest_capacity_failure() {
    let schema = EntrypointValueTypeV1 {
        nodes: vec![Node::Option, Node::Leaf(EntrypointValueKindV1::String)],
    };
    let mut source = IVM::new(0);
    let envelope = crate::pointer_abi::encode_tlv(PointerType::Blob, b"original owner").unwrap();
    let pointer = source.alloc_host_tlv(&envelope).unwrap();
    let some =
        crate::sum::allocate_words(&mut source, SumLayoutV1::option(1).unwrap(), 1, &[pointer])
            .unwrap();
    complete_test_result(&mut source, &[some]);
    let budget = iroha_allocation::AllocationBudget::new(1024 * 1024);
    let captured = capture_completed_return_funded(&source, &schema, &budget).unwrap();
    let retained = budget.reserved_bytes();
    let original_atoms = captured.get().atoms.as_ptr();
    let mut parent = IVM::new(0);
    let table = parent.alloc_heap(8).unwrap();
    parent.store_u64(table, 77).unwrap();
    let heap = parent.memory.heap_allocated_len();
    budget.set_limit_bytes(retained);
    let error = transfer_return_record_funded(
        &captured,
        &schema,
        &mut parent,
        table,
        1,
        1_000_000,
        &budget,
    )
    .unwrap_err();
    assert!(matches!(error, VMError::AllocationDeferred(_)));
    assert_eq!(parent.load_u64(table), Ok(77));
    assert_eq!(parent.memory.heap_allocated_len(), heap);
    assert_eq!(budget.reserved_bytes(), retained);
    assert_eq!(captured.get().atoms.as_ptr(), original_atoms);

    budget.set_limit_bytes(1024 * 1024);
    parent.memory.set_heap_max_limit(heap).unwrap();
    assert_eq!(
        transfer_return_record_funded(
            &captured,
            &schema,
            &mut parent,
            table,
            1,
            1_000_000,
            &budget
        ),
        Err(VMError::OutOfMemory)
    );
    assert_eq!(parent.load_u64(table), Ok(77));
    assert_eq!(parent.memory.heap_allocated_len(), heap);
    assert_eq!(budget.reserved_bytes(), retained);
    assert_eq!(captured.get().atoms.as_ptr(), original_atoms);

    parent
        .memory
        .set_heap_max_limit(crate::Memory::HEAP_SIZE)
        .unwrap();
    parent
        .memory
        .set_heap_limit(crate::Memory::HEAP_SIZE)
        .unwrap();
    let gas = transfer_return_record_funded(
        &captured,
        &schema,
        &mut parent,
        table,
        1,
        1_000_000,
        &budget,
    )
    .unwrap();
    assert!(gas > envelope.len() as u64);
    let (_, words) = crate::sum::read_words(
        &parent,
        parent.load_u64(table).unwrap(),
        SumLayoutV1::option(1).unwrap(),
    )
    .unwrap();
    assert_eq!(
        parent.validate_tlv(words[0]).unwrap().payload,
        b"original owner"
    );
    assert_eq!(
        budget.reserved_bytes(),
        retained,
        "all copying scratch is refunded"
    );
    drop(source);
    drop(captured);
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "the original record graph releases all retained credit"
    );
    assert_eq!(
        parent.validate_tlv(words[0]).unwrap().payload,
        b"original owner",
        "copied return has independent destination ownership"
    );
}
