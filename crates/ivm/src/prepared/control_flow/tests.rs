//! Exact graph behavior and original allocation custody through final release.

use super::*;
use crate::encoding::wide as enc;
use iroha_allocation::AllocationRefusal;

fn decoded(words: &[u32]) -> Vec<DecodedOp> {
    words
        .iter()
        .enumerate()
        .map(|(index, word)| DecodedOp {
            pc: (index as u64) * 4,
            inst: *word,
        })
        .collect()
}

fn measured_arrays(decoded: &[DecodedOp]) -> (usize, usize) {
    let budget = AllocationBudget::new(1024 * 1024);
    let flow = PreparedControlFlow::from_decoded(decoded, Some(&budget)).unwrap();
    let bytes = (
        flow.boundaries.allocation_bytes(),
        flow.nodes.allocation_bytes(),
    );
    assert_eq!(budget.reserved_bytes(), bytes.0 + bytes.1);
    drop(flow);
    assert_eq!(budget.reserved_bytes(), 0);
    bytes
}

#[test]
fn every_control_opcode_preserves_successor_order_and_indirect_flags() {
    let halt = enc::encode_halt();
    let budget = AllocationBudget::new(1024 * 1024);
    let cases = [
        (
            enc::encode_branch(wide::control::BEQ, 2, 3, 2),
            vec![8, 4],
            false,
        ),
        (
            enc::encode_branch(wide::control::BNE, 2, 3, 2),
            vec![8, 4],
            false,
        ),
        (
            enc::encode_branch(wide::control::BLT, 2, 3, 2),
            vec![8, 4],
            false,
        ),
        (
            enc::encode_branch(wide::control::BGE, 2, 3, 2),
            vec![8, 4],
            false,
        ),
        (
            enc::encode_branch(wide::control::BLTU, 2, 3, 2),
            vec![8, 4],
            false,
        ),
        (
            enc::encode_branch(wide::control::BGEU, 2, 3, 2),
            vec![8, 4],
            false,
        ),
        (enc::encode_jump(wide::control::JAL, 0, 2), vec![8], false),
        (
            enc::encode_jump(wide::control::JAL, 1, 2),
            vec![8, 4],
            false,
        ),
        (enc::encode_offset24(wide::control::JMP, 2), vec![8], false),
        (
            enc::encode_offset24(wide::control::JALS, 2),
            vec![8, 4],
            false,
        ),
        (enc::encode_rr(wide::control::JALR, 0, 1, 0), vec![], true),
        (enc::encode_rr(wide::control::JR, 0, 1, 0), vec![], true),
        (
            enc::encode_rr(wide::arithmetic::ADD, 1, 2, 3),
            vec![4],
            false,
        ),
        (halt, vec![], false),
    ];
    for (word, expected, indirect) in cases {
        let decoded = decoded(&[word, halt, halt]);
        let funded = PreparedControlFlow::from_decoded(&decoded, Some(&budget)).unwrap();
        let diagnostic = PreparedControlFlow::from_decoded(&decoded, None).unwrap();
        assert_eq!(funded.boundaries.as_ref(), &[0, 4, 8]);
        let node = funded.node(0).unwrap();
        assert_eq!(node.successors(), expected);
        assert_eq!(node.has_indirect_successor, indirect);
        assert_eq!(node.successors(), diagnostic.node(0).unwrap().successors());
        assert!(funded.node(2).is_none());
        assert!(funded.node(12).is_none());
        drop(funded);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    for word in [
        enc::encode_branch(wide::control::BEQ, 2, 3, -1),
        enc::encode_jump(wide::control::JAL, 1, -1),
        enc::encode_offset24(wide::control::JALS, -1),
    ] {
        let flow = PreparedControlFlow::from_decoded(&decoded(&[halt, word, halt]), Some(&budget))
            .unwrap();
        assert_eq!(flow.node(4).unwrap().successors(), &[0, 8]);
    }
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_pool_refuses_before_construction_and_retries_exact_arrays() {
    let decoded = decoded(&[enc::encode_halt()]);
    let (boundaries, nodes) = measured_arrays(&decoded);
    let budget = AllocationBudget::new(0);
    assert!(matches!(
        PreparedControlFlow::from_decoded(&decoded, Some(&budget)),
        Err(VMError::AllocationDeferred(
            AllocationRefusal::ExceedsLimit { .. }
        ))
    ));
    assert_eq!(budget.peak_reserved_bytes(), 0);
    budget.set_limit_bytes(boundaries + nodes);
    let occupied = budget.try_reserve_bytes(boundaries + nodes).unwrap();
    assert!(matches!(
        PreparedControlFlow::from_decoded(&decoded, Some(&budget)),
        Err(VMError::AllocationDeferred(
            AllocationRefusal::Capacity { .. }
        ))
    ));
    assert_eq!(budget.reserved_bytes(), boundaries + nodes);
    drop(occupied);
    let flow = PreparedControlFlow::from_decoded(&decoded, Some(&budget)).unwrap();
    assert!(flow.boundaries.belongs_to(&budget));
    assert!(flow.nodes.belongs_to(&budget));
    assert_eq!(budget.reserved_bytes(), boundaries + nodes);
    assert_eq!(budget.peak_reserved_bytes(), boundaries + nodes);
    drop(flow);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn second_array_refusal_and_invalid_edges_refund_every_unpublished_owner() {
    let halt = enc::encode_halt();
    let decoded = decoded(&[halt]);
    let (boundaries, nodes) = measured_arrays(&decoded);
    let budget = AllocationBudget::new(boundaries + nodes - 1);
    assert!(matches!(
        PreparedControlFlow::from_decoded(&decoded, Some(&budget)),
        Err(VMError::AllocationDeferred(AllocationRefusal::Capacity { requested_bytes, .. }))
            if requested_bytes == nodes
    ));
    assert_eq!(budget.peak_reserved_bytes(), boundaries);
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(boundaries + nodes);
    for word in [
        enc::encode_branch(wide::control::BEQ, 2, 3, -1),
        enc::encode_branch(wide::control::BEQ, 2, 3, 0),
        enc::encode_jump(wide::control::JAL, 0, 1),
        enc::encode_jump(wide::control::JAL, 1, 0),
        enc::encode_offset24(wide::control::JMP, -1),
        enc::encode_offset24(wide::control::JALS, 0),
    ] {
        let decoded = [DecodedOp { pc: 0, inst: word }];
        assert!(matches!(
            PreparedControlFlow::from_decoded(&decoded, Some(&budget)),
            Err(VMError::DecodeError)
        ));
        assert!(matches!(
            PreparedControlFlow::from_decoded(&decoded, None),
            Err(VMError::DecodeError)
        ));
        assert_eq!(budget.reserved_bytes(), 0);
    }
    let flow = PreparedControlFlow::from_decoded(&decoded, Some(&budget)).unwrap();
    assert!(flow.node(0).unwrap().successors().is_empty());
}

#[test]
fn zero_retention_and_pool_shrink_keep_each_array_until_its_final_borrower() {
    let _limits = crate::ivm_cache::CacheLimitsGuard::new(crate::ivm_cache::CacheLimits {
        capacity: 0,
        max_bytes: 0,
        max_decoded_ops: 0,
    });
    let decoded = decoded(&[enc::encode_halt()]);
    let (boundary_bytes, node_bytes) = measured_arrays(&decoded);
    let budget = AllocationBudget::new(boundary_bytes + node_bytes);
    let flow = PreparedControlFlow::from_decoded(&decoded, Some(&budget)).unwrap();
    assert!(!flow.boundaries.try_retain());
    assert!(!flow.nodes.try_retain());
    let borrowed = flow.clone();
    assert!(SharedAllocation::ptr_eq(
        &flow.boundaries,
        &borrowed.boundaries
    ));
    assert!(SharedAllocation::ptr_eq(&flow.nodes, &borrowed.nodes));
    drop(flow);
    budget.set_limit_bytes(0);
    assert_eq!(budget.reserved_bytes(), boundary_bytes + node_bytes);
    let nodes = borrowed.nodes.clone();
    drop(borrowed);
    assert_eq!(budget.reserved_bytes(), node_bytes);
    assert!(nodes[0].successors().is_empty());
    drop(nodes);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn native_contract_preparation_funds_and_retains_its_original_graph() {
    let artifact = kotodama_lang::compiler::Compiler::new()
        .compile_source("seiyaku GraphOwner { view fn main() authorize(anyone) -> bool { true } }")
        .unwrap();
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let contract = crate::prepare_contract_with_memory_budget(&artifact, &budget).unwrap();
    let flow = contract.inner.control_flow.clone();
    assert!(flow.boundaries.belongs_to(&budget));
    assert!(flow.nodes.belongs_to(&budget));
    let bytes = flow.boundaries.allocation_bytes() + flow.nodes.allocation_bytes();
    assert!(budget.reserved_bytes() > bytes);
    drop(contract);
    assert_eq!(budget.reserved_bytes(), bytes);
    assert!(!flow.boundaries.is_empty());
    drop(flow);
    assert_eq!(budget.reserved_bytes(), 0);
}
