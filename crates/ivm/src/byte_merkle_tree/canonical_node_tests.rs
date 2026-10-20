//! Fixed canonical backing, original credit and in-place maintenance controls.
use super::*;
use crate::memory::dirty_chunks::DirtyChunks;
use iroha_allocation::AllocationBudget;
use std::sync::{Arc, Barrier};

#[test]
fn canonical_node_constructor_refusal_and_clone_failure_preserve_original_tree() {
    for count in [0, 1, 3, 65] {
        let plan = ByteMerkleTree::memory_plan(count).unwrap();
        let budget = AllocationBudget::new(plan.requested_bytes() - 1);
        let allocations = canonical_nodes::ALLOCATIONS.get();
        assert!(ExecutionMemoryLease::reserve(&budget, plan).is_err());
        assert_eq!(canonical_nodes::ALLOCATIONS.get(), allocations);
        assert_eq!(budget.reserved_bytes(), 0);
        budget.set_limit_bytes(plan.requested_bytes());
        let mut lease = ExecutionMemoryLease::reserve(&budget, plan).unwrap();
        canonical_nodes::REFUSE_NEXT_ALLOCATION.set(true);
        assert!(ByteMerkleTree::new_funded(count, 32, &mut lease).is_err());
        drop(lease);
        assert_eq!(budget.reserved_bytes(), 0);
        let mut lease = ExecutionMemoryLease::reserve(&budget, plan).unwrap();
        let source = ByteMerkleTree::new_funded(count, 32, &mut lease).unwrap();
        assert_eq!(lease.remaining_bytes(), 0);
        source.update_leaf(0, &[0xa5]).unwrap();
        let root = source.root();
        let leaves = source.leaves.lock().to_vec();
        canonical_nodes::REFUSE_NEXT_ALLOCATION.set(true);
        assert!(source.try_clone_for_runtime_template(None).is_err());
        assert_eq!(source.root(), root);
        assert_eq!(&**source.leaves.lock(), leaves);
        assert_eq!(budget.reserved_bytes(), plan.requested_bytes());
        drop(source);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn canonical_nodes_keep_exact_geometry_across_dense_sparse_reset_and_final_borrowers() {
    for count in [1, 3, 65, 513] {
        let plan = ByteMerkleTree::memory_plan(count).unwrap();
        let budget = AllocationBudget::new(plan.requested_bytes());
        let mut lease = ExecutionMemoryLease::reserve(&budget, plan).unwrap();
        let mut tree = ByteMerkleTree::new_funded(count, 32, &mut lease).unwrap();
        let template = tree.try_clone_for_runtime_template(None).unwrap();
        let leaf_pointer = tree.leaves.lock().as_ptr();
        let nodes_bytes = tree.nodes.lock().allocated_bytes();
        assert_eq!(
            nodes_bytes,
            MerkleTree::<[u8; 32]>::repeated_sha256_node_allocation_bytes(count).unwrap()
        );
        let allocations = canonical_nodes::ALLOCATIONS.get();
        let mut bytes = vec![0; count * 32];
        let mut dirty = DirtyChunks::new(count, None).unwrap();
        budget.set_limit_bytes(0);
        for dense in [false, true] {
            for index in 0..count {
                if dense || index == 0 || index == count - 1 {
                    bytes[index * 32] = (index % 251 + 1) as u8;
                    dirty.insert(index);
                }
            }
            tree.update_dirty_leaves_from_bytes(&bytes, &dirty);
            let canonical = MerkleTree::<[u8; 32]>::from_byte_chunks(&bytes, 32).unwrap();
            assert_eq!(tree.root_hash(), canonical.root().unwrap());
            tree.recompute_all_leaves_parallel(&bytes);
            assert!(!tree.nodes.lock().is_current());
            assert_eq!(tree.root_hash(), canonical.root().unwrap());
            for index in 0..count {
                assert_eq!(
                    tree.proof(index).unwrap(),
                    canonical.get_proof(index as u32).unwrap()
                );
            }
            assert_eq!(tree.leaves.lock().as_ptr(), leaf_pointer);
            assert_eq!(tree.nodes.lock().allocated_bytes(), nodes_bytes);
            assert_eq!(canonical_nodes::ALLOCATIONS.get(), allocations);
        }
        dirty.extend((0..count).rev());
        tree.reset_leaves_from(&template, &dirty);
        assert!(tree.nodes.lock().is_current());
        assert_eq!(tree.root_hash(), template.root_hash());
        assert_eq!(canonical_nodes::ALLOCATIONS.get(), allocations);
        assert_eq!(budget.reserved_bytes(), plan.requested_bytes());
        let owner = Arc::new(tree);
        let barrier = Barrier::new(3);
        std::thread::scope(|scope| {
            for _ in 0..2 {
                let borrower = Arc::clone(&owner);
                let barrier = &barrier;
                let expected = template.root();
                scope.spawn(move || {
                    barrier.wait();
                    assert_eq!(borrower.root(), expected);
                    barrier.wait();
                });
            }
            drop(owner);
            assert_eq!(budget.reserved_bytes(), plan.requested_bytes());
            barrier.wait();
            barrier.wait();
        });
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn template_node_copy_spends_exact_original_plan_and_outlives_source() {
    let source = ByteMerkleTree::from_bytes(&[0xa5; 65 * 32 - 7], 32).unwrap();
    let plan = source.runtime_template_memory_plan().unwrap();
    let budget = AllocationBudget::new(plan.requested_bytes());
    let mut lease = ExecutionMemoryLease::reserve(&budget, plan).unwrap();
    let copy = source
        .try_clone_for_runtime_template(Some(&mut lease))
        .unwrap();
    assert_eq!(lease.remaining_bytes(), 0);
    assert_eq!(budget.reserved_bytes(), plan.requested_bytes());
    assert_eq!(source.root(), copy.root());
    assert_ne!(source.leaves.lock().as_ptr(), copy.leaves.lock().as_ptr());
    let root = source.root();
    drop(source);
    drop(lease);
    budget.set_limit_bytes(0);
    assert_eq!(copy.root(), root);
    copy.update_leaf(64, &[0x5a]).unwrap();
    assert_ne!(copy.root(), root);
    assert_eq!(budget.reserved_bytes(), plan.requested_bytes());
    drop(copy);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn complete_leaf_replacement_rejects_wrong_geometry_before_mutating_nodes_or_leaves() {
    let tree = ByteMerkleTree::from_bytes(&[0xa5; 65], 32).unwrap();
    let root = tree.root();
    let original = tree.leaves.lock().to_vec();
    let node_bytes = tree.nodes.lock().allocated_bytes();
    let allocations = canonical_nodes::ALLOCATIONS.get();
    assert!(tree.lock_leaf_update(&[[0x11; 32]; 2]).is_none());
    assert!(tree.nodes.lock().is_current());
    assert_eq!(&**tree.leaves.lock(), original);
    assert_eq!(tree.root(), root);
    let replacement = [[0x37; 32]; 3];
    tree.lock_leaf_update(&replacement).unwrap().install();
    assert!(tree.nodes.lock().is_current());
    assert_eq!(&**tree.leaves.lock(), &replacement);
    let expected = MerkleTree::from_hashed_leaves_sha256(replacement);
    assert_eq!(tree.root_hash(), expected.root().unwrap());
    assert_eq!(tree.nodes.lock().allocated_bytes(), node_bytes);
    assert_eq!(canonical_nodes::ALLOCATIONS.get(), allocations);
    for index in 0..3 {
        assert_eq!(
            tree.proof(index).unwrap(),
            expected.get_proof(index as u32).unwrap()
        );
    }
}
