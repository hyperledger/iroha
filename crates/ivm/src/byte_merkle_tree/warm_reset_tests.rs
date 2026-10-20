//! Warm restoration maintains canonical paths using the original dirty bitmap.

use super::*;
use crate::memory::dirty_chunks::DirtyChunks;

#[test]
fn warm_reset_keeps_current_nodes_and_matches_full_rebuild() {
    for leaf_count in [1, 2, 3, 63, 64, 65, 513, 4_097] {
        for chunk in [1, 7, 32] {
            let original: Vec<u8> = (0..leaf_count * chunk - chunk / 2)
                .map(|index| (index % 239) as u8)
                .collect();
            let template = ByteMerkleTree::from_bytes(&original, chunk).unwrap();
            for stride in [1, 5, 64] {
                let mut bytes = original.clone();
                let mut restored = DirtyChunks::new(leaf_count, None).unwrap();
                for index in (0..leaf_count).step_by(stride) {
                    bytes[index * chunk] ^= 0xa5;
                    restored.insert(index);
                }
                restored.insert(leaf_count - 1);
                bytes[(leaf_count - 1) * chunk] ^= 0x5a;
                let mut worker = ByteMerkleTree::from_bytes(&bytes, chunk).unwrap();
                let leaf_pointer = worker.leaves.lock().as_ptr();
                let node_bytes = worker.nodes.lock().allocated_bytes();
                let allocations = canonical_nodes::ALLOCATIONS.get();
                worker.reset_leaves_from(&template, &restored);
                assert!(worker.nodes.lock().is_current());
                assert_eq!(**worker.nodes.lock(), **template.nodes.lock());
                assert_eq!(worker.root(), template.root());
                for index in restored.iter() {
                    assert_eq!(worker.proof(index).unwrap(), template.proof(index).unwrap());
                }
                assert_eq!(worker.leaves.lock().as_ptr(), leaf_pointer);
                assert_eq!(worker.nodes.lock().allocated_bytes(), node_bytes);
                assert_eq!(canonical_nodes::ALLOCATIONS.get(), allocations);

                // The next invocation must update the restored canonical nodes
                // directly, including at the ragged final leaf.
                worker.update_leaf(leaf_count - 1, &[0xb6]).unwrap();
                let mut expected = original.clone();
                expected[(leaf_count - 1) * chunk..].fill(0);
                expected[(leaf_count - 1) * chunk] = 0xb6;
                let expected = ByteMerkleTree::from_bytes(&expected, chunk).unwrap();
                assert_eq!(**worker.nodes.lock(), **expected.nodes.lock());
                assert_eq!(worker.root(), expected.root());
            }
        }
    }
}

#[test]
fn warm_reset_preserves_unrestored_leaves_and_refreshes_already_stale_nodes() {
    let template = ByteMerkleTree::from_bytes(&[0xa5; 65 * 32 - 7], 32).unwrap();
    let mut restored = DirtyChunks::new(65, None).unwrap();
    restored.extend([0, 63, 64, 0]);
    for stale in [false, true] {
        let mut bytes = vec![0xb6; 65 * 32 - 7];
        let mut worker = ByteMerkleTree::from_bytes(&bytes, 32).unwrap();
        if stale {
            bytes[32..64].fill(0xc7);
            worker.recompute_all_leaves_parallel(&bytes);
            assert!(!worker.nodes.lock().is_current());
        }
        for index in restored.iter() {
            let end = ((index + 1) * 32).min(bytes.len());
            bytes[index * 32..end].fill(0xa5);
        }
        worker.reset_leaves_from(&template, &restored);
        assert_eq!(worker.nodes.lock().is_current(), !stale);
        let expected = ByteMerkleTree::from_bytes(&bytes, 32).unwrap();
        assert_eq!(worker.root(), expected.root());
        assert_eq!(**worker.nodes.lock(), **expected.nodes.lock());
        for index in 0..65 {
            assert_eq!(worker.proof(index).unwrap(), expected.proof(index).unwrap());
        }
        restored.clear();
        worker.reset_leaves_from(&template, &restored);
        assert!(worker.nodes.lock().is_current());
        assert_eq!(worker.root(), expected.root());
        restored.extend([0, 63, 64]);
    }
}

#[test]
fn warm_reset_rejects_wrong_bitmap_before_changing_leaves_or_nodes() {
    let template = ByteMerkleTree::new(65, 32).unwrap();
    let mut worker = ByteMerkleTree::from_bytes(&[0xa5; 65 * 32], 32).unwrap();
    let expected = worker.root();
    let leaves = worker.leaves.lock().to_vec();
    for count in [64, 66] {
        let restored = DirtyChunks::new(count, None).unwrap();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                worker.reset_leaves_from(&template, &restored);
            }))
            .is_err()
        );
        assert_eq!(worker.root(), expected);
        assert_eq!(&**worker.leaves.lock(), leaves);
        assert!(worker.nodes.lock().is_current());
    }
}

/// The previous reset algorithm, retained only as a diagnostic timing reference.
fn reset_with_full_refresh_reference(
    worker: &mut ByteMerkleTree,
    template: &ByteMerkleTree,
    restored: &DirtyChunks,
) {
    let mut nodes = worker.nodes.lock();
    let source = template.leaves.lock();
    let mut leaves = worker.leaves.lock();
    for index in restored.iter() {
        leaves[index] = source[index];
    }
    nodes.mark_stale();
}

#[test]
#[ignore = "diagnostic timing comparison; run explicitly with --ignored --nocapture"]
fn warm_reset_then_root_benchmark() {
    use std::{hint::black_box, time::Duration, time::Instant};

    // Default memory image: 3 MiB before the stack plus its 4 MiB maximum.
    let leaf_count = 7 * 1024 * 1024 / 32;
    let template = ByteMerkleTree::new(leaf_count, 32).unwrap();
    let iterations = 12_u32;
    for restored_count in [1, 32, 256, 1_024] {
        for scattered in [false, true] {
            let mut restored = DirtyChunks::new(leaf_count, None).unwrap();
            for index in 0..restored_count {
                let leaf = if scattered {
                    index * (leaf_count - 1) / restored_count
                } else {
                    index
                };
                restored.insert(leaf);
            }
            let mut current = template.try_clone_for_runtime_template(None).unwrap();
            let mut reference = template.try_clone_for_runtime_template(None).unwrap();
            let mut elapsed = [Duration::ZERO; 2];
            for iteration in 0..iterations {
                // Alternate order to reduce cache/temperature bias. Setup is
                // outside the timing interval; both trees have committed writes.
                for mode in [iteration % 2, 1 - iteration % 2] {
                    let worker = if mode == 0 {
                        &mut reference
                    } else {
                        &mut current
                    };
                    for index in restored.iter() {
                        worker.update_leaf(index, &[0xa5; 32]).unwrap();
                    }
                    let start = Instant::now();
                    if mode == 0 {
                        reset_with_full_refresh_reference(worker, &template, &restored);
                    } else {
                        worker.reset_leaves_from(&template, &restored);
                    }
                    let root = black_box(worker.root());
                    elapsed[mode as usize] += start.elapsed();
                    assert_eq!(root, template.root());
                }
            }
            assert_eq!(**reference.nodes.lock(), **current.nodes.lock());
            eprintln!(
                "warm_reset_then_root leaves={leaf_count} restored={restored_count} scattered={scattered} iterations={iterations} full_refresh_us={:.2} marked_parents_us={:.2} speedup={:.2}x",
                elapsed[0].as_secs_f64() * 1_000_000.0 / f64::from(iterations),
                elapsed[1].as_secs_f64() * 1_000_000.0 / f64::from(iterations),
                elapsed[0].as_secs_f64() / elapsed[1].as_secs_f64(),
            );
        }
    }
}
