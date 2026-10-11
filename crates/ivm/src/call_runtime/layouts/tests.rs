//! Exact layout funding, shared lifetime, and allocation-free warm reuse.

use super::*;
use ivm_abi::call::{CallSchemaV1, CallTypeNodeV1};

fn interface() -> EmbeddedContractInterfaceV1 {
    let bytes = kotodama_lang::compiler::Compiler::new()
        .compile_source("seiyaku Schema { view fn main() authorize(anyone) -> bool { true } }")
        .unwrap();
    crate::ProgramMetadata::parse(&bytes)
        .unwrap()
        .contract_interface
        .unwrap()
}

#[test]
fn funded_layouts_refuse_before_allocation_and_release_only_after_final_borrower() {
    let interface = interface();
    let budget = AllocationBudget::new(0);
    assert!(matches!(
        CallLayouts::prepare(&interface, Some(&budget)),
        Err(VMError::AllocationDeferred(_))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    let node_count: usize = interface
        .callables
        .iter()
        .map(|call| call.arguments.nodes.len() + call.results.nodes.len())
        .sum();
    let bytes = interface.callables.len() * size_of::<CallableLayout>()
        + node_count * size_of::<CallNodeLayoutV1>()
        + norito::core::owned_arc_allocation_bytes::<CallLayoutsData>().unwrap();
    budget.set_limit_bytes(bytes);
    let owner = CallLayouts::prepare(&interface, Some(&budget)).unwrap();
    assert_eq!(budget.reserved_bytes(), bytes);
    let borrower = owner.clone();
    assert!(StrongOwner::ptr_eq(&owner.0, &borrower.0));
    budget.set_limit_bytes(0);
    let _ = owner.try_retain();
    drop(owner);
    assert_eq!(budget.reserved_bytes(), bytes);
    assert_eq!(borrower.callable(0).unwrap().frame.result_words, 1);
    assert!(borrower.callable(usize::MAX).is_err());
    assert!(borrower.node(usize::MAX, 1).is_err());
    drop(borrower);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn local_layouts_derive_aggregate_widths_and_reject_malformed_types() {
    let mut interface = interface();
    interface.callables[0].results = CallSchemaV1 {
        nodes: vec![
            CallTypeNodeV1::Tuple(2),
            CallTypeNodeV1::Unit,
            CallTypeNodeV1::Option,
            CallTypeNodeV1::Tuple(2),
            CallTypeNodeV1::Unit,
            CallTypeNodeV1::Unit,
        ],
    };
    let layouts = CallLayouts::prepare(&interface, None).unwrap();
    let call = layouts.callable(0).unwrap();
    assert_eq!(call.frame.result_words, 2);
    assert_eq!(
        layouts.node(call.results, 2).unwrap(),
        CallNodeLayoutV1 {
            subtree_end: 6,
            words: 1
        }
    );
    assert_eq!(layouts.node(call.results, 3).unwrap().words, 2);
    interface.callables[0].results.nodes.pop();
    assert!(matches!(
        CallLayouts::prepare(&interface, None),
        Err(VMError::InvalidMetadata)
    ));
}

#[test]
fn warm_reset_preserves_immutable_schema_layout_owner() {
    let bytes = kotodama_lang::compiler::Compiler::new()
        .compile_source("seiyaku Schema { view fn main() authorize(anyone) -> bool { true } }")
        .unwrap();
    let mut vm = crate::IVM::new(100_000);
    vm.load_program(&bytes).unwrap();
    let owner = vm.call_layouts.as_ref().unwrap().clone();
    let template = vm.try_runtime_template().unwrap();
    vm.select_entrypoint("main").unwrap();
    vm.run().unwrap();
    vm.reset_from_runtime_template(&template).unwrap();
    assert!(StrongOwner::ptr_eq(
        &owner.0,
        &vm.call_layouts.as_ref().unwrap().0
    ));
}
