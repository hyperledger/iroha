//! Streaming dirty-bit updates preserve canonical roots and fixed leaf ownership.

use super::*;
use crate::memory::dirty_chunks::DirtyChunks;

#[test]
fn sparse_and_parallel_dirty_updates_match_full_rebuild_without_replacing_backing() {
    for leaf_count in [1, 2, 63, 64, 65, 513] {
        for dense in [false, true] {
            let mut bytes = vec![0; leaf_count * 32 - 3];
            let mut tree = ByteMerkleTree::from_bytes(&bytes, 32).unwrap();
            let mut dirty = DirtyChunks::new(leaf_count, None).unwrap();
            let leaf_backing = tree.leaves.lock().as_ptr();
            let node_bytes = tree.nodes.lock().allocated_bytes();
            // Reverse insertion and duplicate bits must produce the same canonical
            // order, with an odd final leaf and the final word only partly used.
            for index in (0..leaf_count).rev() {
                if dense || index == 0 || index == leaf_count - 1 {
                    bytes[index * 32] = (index % 251 + 1) as u8;
                    dirty.insert(index);
                    dirty.insert(index);
                }
            }
            tree.update_dirty_leaves_from_bytes(&bytes, &dirty);
            let expected = ByteMerkleTree::from_bytes(&bytes, 32).unwrap();
            assert_eq!(tree.root(), expected.root());
            assert_eq!(tree.leaves.lock().as_ptr(), leaf_backing);
            assert_eq!(tree.nodes.lock().allocated_bytes(), node_bytes);
            for index in dirty.iter() {
                assert_eq!(tree.path(index).unwrap(), expected.path(index).unwrap());
            }
            let root = tree.root();
            dirty.clear();
            tree.update_dirty_leaves_from_bytes(&[], &dirty);
            assert_eq!(tree.root(), root, "an empty bitmap must not read the input");
            assert_eq!(tree.leaves.lock().as_ptr(), leaf_backing);
        }
    }
}

#[test]
fn initial_dirty_updates_preserve_padding_and_ignore_bytes_outside_tree_geometry() {
    let mut tree = ByteMerkleTree::new(65, 32).unwrap();
    let mut dirty = DirtyChunks::new(65, None).unwrap();
    dirty.extend([0, 64]);
    let mut bytes = vec![0; 64 * 32 + 1];
    bytes[0] = 0xa5;
    bytes[64 * 32] = 0x5a;
    tree.update_dirty_leaves_from_bytes(&bytes, &dirty);
    assert!(tree.nodes.lock().is_current());
    assert_eq!(
        tree.root(),
        ByteMerkleTree::from_bytes(&bytes, 32).unwrap().root()
    );
    let expected = tree.root();
    bytes.resize(67 * 32, 0);
    bytes[65 * 32..].fill(0xb6);
    tree.update_dirty_leaves_from_bytes(&bytes, &dirty);
    assert_eq!(tree.leaf_count(), 65);
    assert_eq!(tree.root(), expected);
}

#[test]
fn mismatched_bitmap_is_rejected_before_any_leaf_or_cached_root_changes() {
    let mut tree = ByteMerkleTree::from_bytes(&[0xa5; 65 * 32], 32).unwrap();
    let root = tree.root();
    let leaves = tree.leaves.lock().to_vec();
    let mut dirty = DirtyChunks::new(64, None).unwrap();
    dirty.insert(0);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tree.update_dirty_leaves_from_bytes(&[0xb6; 65 * 32], &dirty);
    }));
    assert!(result.is_err());
    assert_eq!(&**tree.leaves.lock(), leaves);
    assert_eq!(tree.root(), root);
}

#[test]
fn bitmap_update_keeps_cached_tree_and_matches_full_rebuild() {
    let mut data = vec![0u8; 32 * 8];
    for (idx, byte) in data.iter_mut().enumerate() {
        *byte = idx as u8;
    }
    let mut tree = ByteMerkleTree::from_bytes(&data, 32).unwrap();
    assert!(tree.nodes.lock().is_current());
    let (_, updates_before) = merkle_update_counters();
    data[32..64].fill(0xAA);
    data[96..128].fill(0x55);
    let mut dirty = DirtyChunks::new(8, None).unwrap();
    dirty.extend([3, 1, 1]);
    assert_eq!(dirty.len(), 2);
    tree.update_dirty_leaves_from_bytes(&data, &dirty);
    assert!(tree.nodes.lock().is_current());
    let expected = MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 32)
        .expect("canonical tree")
        .root()
        .expect("root");
    assert_eq!(tree.root_hash(), expected);
    let (_, updates_after) = merkle_update_counters();
    assert!(
        updates_after >= updates_before.saturating_add(2),
        "deduped leaf updates should be counted once per touched leaf"
    );
}
#[test]
fn cloned_tree_preserves_cache_for_incremental_updates() {
    let mut data = vec![7u8; 32 * 4];
    let tree = ByteMerkleTree::from_bytes(&data, 32).unwrap();
    let mut cloned = tree.try_clone_for_runtime_template(None).unwrap();
    assert!(cloned.nodes.lock().is_current());
    data[64..96].fill(0x11);
    let mut dirty = DirtyChunks::new(4, None).unwrap();
    dirty.insert(2);
    cloned.update_dirty_leaves_from_bytes(&data, &dirty);
    assert!(cloned.nodes.lock().is_current());
    let expected = MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 32)
        .expect("canonical tree")
        .root()
        .expect("root");
    assert_eq!(cloned.root_hash(), expected);
    assert_ne!(cloned.root_hash(), tree.root_hash());
}

#[test]
fn marked_parent_rehash_matches_per_leaf_path_updates() {
    for leaf_count in [1, 2, 3, 63, 64, 65, 100, 513, 4_097] {
        let original: Vec<u8> = (0..leaf_count * 32 - 5)
            .map(|byte| (byte % 239) as u8)
            .collect();
        let patterns: [Vec<usize>; 5] = [
            // One leaf, a contiguous program image, scattered leaves, the last
            // leaf of every bitmap word plus the ragged edge, and the full image.
            vec![leaf_count / 3],
            (0..leaf_count.div_ceil(4)).collect(),
            (0..leaf_count).step_by(5).collect(),
            (0..leaf_count)
                .filter(|leaf| leaf % 64 == 63 || *leaf == leaf_count - 1)
                .collect(),
            (0..leaf_count).collect(),
        ];
        for marks in patterns {
            let mut bytes = original.clone();
            let mut dirty = DirtyChunks::new(leaf_count, None).unwrap();
            for &leaf in &marks {
                bytes[leaf * 32] ^= 0xa5;
                dirty.insert(leaf);
            }
            let mut tree = ByteMerkleTree::from_bytes(&original, 32).unwrap();
            let updated = ByteMerkleTree::from_bytes(&bytes, 32).unwrap();
            // Reference: the previous one leaf-to-root path rewrite per dirty leaf.
            let mut per_leaf = (**tree.nodes.lock()).clone();
            for &leaf in &marks {
                per_leaf.update_hashed_leaf_sha256(leaf, updated.leaves.lock()[leaf]);
            }
            tree.update_dirty_leaves_from_bytes(&bytes, &dirty);
            assert!(tree.nodes.lock().is_current());
            assert_eq!(**tree.nodes.lock(), per_leaf, "{leaf_count} leaves");
            assert_eq!(tree.root_hash(), updated.root_hash());
            for &leaf in &marks {
                assert_eq!(tree.path(leaf).unwrap(), updated.path(leaf).unwrap());
            }
        }
    }
}
