//! Combined admission, fixed-point parity, bounded queuing and borrowed roots.

use super::*;
use iroha_allocation::AllocationRefusal;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    panic::{AssertUnwindSafe, catch_unwind},
};

fn bytes(instructions: usize) -> usize {
    instructions * (std::mem::size_of::<Row>() + std::mem::size_of::<usize>())
}

#[test]
fn combined_original_pool_admission_precedes_both_backings_and_retries() {
    let demand = bytes(3);
    let budget = AllocationBudget::new(0);
    assert!(matches!(Workspace::new(3, &budget),
        Err(VMError::AllocationDeferred(AllocationRefusal::ExceedsLimit {
            requested_bytes, limit_bytes: 0,
        })) if requested_bytes == demand));
    assert_eq!(budget.peak_reserved_bytes(), 0);
    budget.set_limit_bytes(demand - 1);
    assert!(matches!(
        Workspace::new(3, &budget),
        Err(VMError::AllocationDeferred(_))
    ));
    assert_eq!(
        budget.peak_reserved_bytes(),
        0,
        "no partial fact array admission"
    );
    budget.set_limit_bytes(demand);
    let occupied = budget.try_reserve_bytes(1).unwrap();
    assert!(matches!(Workspace::new(3, &budget),
        Err(VMError::AllocationDeferred(AllocationRefusal::Capacity { requested_bytes, .. }))
        if requested_bytes == demand));
    assert_eq!(budget.reserved_bytes(), 1);
    drop(occupied);
    let workspace = Workspace::new(3, &budget).unwrap();
    assert_eq!(budget.reserved_bytes(), demand);
    assert_eq!(budget.peak_reserved_bytes(), demand);
    assert_eq!(workspace.rows.as_slice().len(), 3);
    assert_eq!(workspace.queue.as_slice().len(), 3);
    budget.set_limit_bytes(0);
    assert_eq!(
        budget.reserved_bytes(),
        demand,
        "shrink cannot forgive live storage"
    );
    drop(workspace);
    assert_eq!(budget.reserved_bytes(), 0);
    let empty = Workspace::new(0, &budget).unwrap();
    assert!(empty.rows.as_slice().is_empty());
    assert!(empty.queue.as_slice().is_empty());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn queued_changes_merge_once_and_back_edges_requeue_after_pop_without_growth() {
    let budget = AllocationBudget::new(bytes(3));
    let mut workspace = Workspace::new(3, &budget).unwrap();
    let mut one = StaticStateFacts::entrypoint();
    one.names[7] = Some(1);
    for index in 0..3 {
        assert!(workspace.merge(index, &one).unwrap());
    }
    let charged = budget.reserved_bytes();
    budget.set_limit_bytes(0);
    let mut two = one.clone();
    two.names[7] = Some(2);
    assert!(workspace.merge(1, &two).unwrap());
    assert_eq!(
        workspace.pending, 3,
        "pending row updated without duplicate slot"
    );
    assert!(!workspace.merge(1, &two).unwrap());
    let (index, _) = workspace.pop().unwrap();
    assert_eq!(index, 0);
    assert!(
        workspace.merge(0, &two).unwrap(),
        "changed back edge requeues popped row"
    );
    assert_eq!(workspace.pending, 3);
    for expected in [1, 2, 0] {
        let (index, facts) = workspace.pop().unwrap();
        assert_eq!(
            index, expected,
            "original pending FIFO order remains deterministic"
        );
        assert_eq!(facts.names[7], if index == 2 { Some(1) } else { None });
    }
    assert!(workspace.pop().is_none());
    assert_eq!(workspace.pending, 0);
    assert_eq!(budget.reserved_bytes(), charged);
    assert_eq!(budget.peak_reserved_bytes(), charged);
    assert!(matches!(
        workspace.merge(3, &one),
        Err(VMError::DecodeError)
    ));
    assert!(
        workspace.pop().is_none(),
        "malformed successor cannot publish a queue entry"
    );
    drop(workspace);
    assert_eq!(budget.reserved_bytes(), 0);
}

fn transfer(index: usize, facts: &mut StaticStateFacts) {
    if index == 1 {
        facts.names[7] = Some(1);
    } else if index == 2 {
        facts.names[7] = Some(2);
        facts.direct = false;
    }
}

#[test]
fn diamond_loop_matches_original_merge_fixed_point_and_observed_fact_values() {
    const EDGES: &[&[usize]] = &[&[1, 2], &[3, 3], &[3], &[1, 4], &[]];
    let mut seed = StaticStateFacts::entrypoint();
    seed.names[7] = Some(1);
    // A test-only reference keeps the former duplicate-capable worklist. The
    // production draft owns only bounded instruction-indexed arrays.
    let mut incoming = BTreeMap::from([(0, seed.clone())]);
    let mut pending = VecDeque::from([0]);
    let mut expected_seen = BTreeSet::new();
    let mut old_visits = 0;
    while let Some(index) = pending.pop_front() {
        old_visits += 1;
        assert!(old_visits < 100);
        let mut outgoing = incoming[&index].clone();
        expected_seen.insert((index, outgoing.names[7], outgoing.direct));
        transfer(index, &mut outgoing);
        for next in EDGES[index] {
            match incoming.entry(*next) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(outgoing.clone());
                    pending.push_back(*next);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    if entry.get_mut().merge_from(&outgoing) {
                        pending.push_back(*next);
                    }
                }
            }
        }
    }
    let budget = AllocationBudget::new(bytes(EDGES.len()));
    let mut workspace = Workspace::new(EDGES.len(), &budget).unwrap();
    workspace.merge(0, &seed).unwrap();
    let mut actual_seen = BTreeSet::new();
    let mut visits = 0;
    while let Some((index, mut outgoing)) = workspace.pop() {
        visits += 1;
        assert!(visits < 100);
        actual_seen.insert((index, outgoing.names[7], outgoing.direct));
        transfer(index, &mut outgoing);
        for next in EDGES[index] {
            workspace.merge(*next, &outgoing).unwrap();
            assert!(workspace.pending <= EDGES.len());
        }
    }
    assert!(visits < old_visits, "duplicate queue events were redundant");
    assert_eq!(actual_seen, expected_seen);
    for (index, expected) in incoming {
        assert!(workspace.rows.as_slice()[index].facts.as_ref() == Some(&expected));
    }
    assert_eq!(budget.peak_reserved_bytes(), bytes(EDGES.len()));
    drop(workspace);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn scratch_is_funded_with_zero_retention_and_reclaimed_on_error_or_unwind() {
    let _limits = crate::ivm_cache::CacheLimitsGuard::new(crate::ivm_cache::CacheLimits {
        capacity: 0,
        max_bytes: 0,
        max_decoded_ops: 0,
    });
    let budget = AllocationBudget::new(bytes(2));
    for unwind in [false, true] {
        let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), VMError> {
            let mut workspace = Workspace::new(2, &budget)?;
            workspace.merge(0, &StaticStateFacts::entrypoint())?;
            assert_eq!(budget.reserved_bytes(), bytes(2));
            assert!(!unwind, "static-state traversal interrupted");
            workspace.merge(2, &StaticStateFacts::entrypoint())?;
            Ok(())
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(matches!(result, Ok(Err(VMError::DecodeError))));
        }
        assert_eq!(budget.reserved_bytes(), 0);
    }
    let empty_budget = AllocationBudget::new(0);
    let original = empty_budget.try_reserve_bytes(1).unwrap_err();
    assert_eq!(
        buffer_error(PrepaidBufferError::Allocation(
            ChargedBufferError::Admission(original.clone())
        )),
        VMError::AllocationDeferred(original),
    );
    assert_eq!(
        buffer_error(PrepaidBufferError::Allocation(
            ChargedBufferError::Allocator { requested_bytes: 7 }
        )),
        VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable),
    );
}

#[test]
fn roots_borrow_exact_original_descriptors_for_selection_and_whole_contract() {
    let bytes = kotodama_lang::compiler::Compiler::new().compile_source(
        "seiyaku WorkspaceRoots { view fn first() authorize(anyone) -> bool { true } view fn second() authorize(anyone) -> bool { false } }",
    ).unwrap();
    let prepared = crate::prepare_contract(std::sync::Arc::from(bytes.as_slice())).unwrap();
    let all = Roots::new(&prepared, None).unwrap();
    assert_eq!(all.descriptors.len(), 2);
    assert_eq!(
        all.descriptors.as_ptr(),
        prepared.contract_interface().entrypoints.as_ptr()
    );
    assert!(
        all.iter().eq(prepared
            .contract_interface()
            .entrypoints
            .iter()
            .map(|entry| entry.entry_pc))
    );
    for name in ["first", "second"] {
        let selected = Roots::new(&prepared, Some(name)).unwrap();
        let original = prepared.entrypoint_descriptor(name).unwrap();
        assert_eq!(selected.descriptors.as_ptr(), std::ptr::from_ref(original));
        assert_eq!(selected.iter().collect::<Vec<_>>(), vec![original.entry_pc]);
        assert!(selected.contains(original.entry_pc));
        assert!(all.contains(original.entry_pc));
        assert!(!selected.contains(u64::MAX));
    }
    assert!(Roots::new(&prepared, Some("absent")).is_none());
}
