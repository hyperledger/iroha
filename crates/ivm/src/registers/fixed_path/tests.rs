//! All-register root/path parity and fixed-depth public API rejection.

use super::*;
use crate::parallel::REGISTER_COUNT;
use iroha_crypto::{Hash, MerkleProof};

#[test]
fn every_fixed_register_path_matches_canonical_tree_and_authenticates_its_original_leaf() {
    let mut registers = Registers::new();
    for index in 1..REGISTER_COUNT {
        registers.set(index, (index as u64).wrapping_mul(0x0102_0304_0506_0708));
        registers.set_tag(index, index % 3 == 0);
    }
    let digests = super::super::register_leaf_digests(&registers.gpr, &registers.tags);
    let canonical = MerkleTree::from_hashed_leaves_sha256(digests);
    for (index, digest) in digests.into_iter().enumerate() {
        let (root, path) = registers.merkle_root_and_path(index).unwrap();
        assert_eq!(root, canonical.root().unwrap());
        assert_eq!(path.len(), REGISTER_MERKLE_PATH_DEPTH);
        assert_eq!(path, registers.merkle_path(index).unwrap());
        let expected = canonical.get_proof(index as u32).unwrap();
        let siblings = path.map(|bytes| {
            Some(HashOf::<[u8; 32]>::from_untyped_unchecked(Hash::prehashed(
                bytes,
            )))
        });
        assert_eq!(siblings.as_slice(), expected.audit_path());
        let leaf = HashOf::<[u8; 32]>::from_untyped_unchecked(Hash::prehashed(digest));
        assert!(MerkleProof::verify_audit_path_sha256(
            index as u32,
            &siblings,
            &leaf,
            &canonical.commitment().unwrap()
        ));
    }
}

#[test]
fn fixed_register_paths_reject_outside_indices_without_changing_original_state() {
    let mut registers = Registers::new();
    registers.set(255, 17);
    registers.set_tag(255, true);
    let values = registers.snapshot();
    let tags = registers.snapshot_tags();
    let root = registers.merkle_root();
    for index in [REGISTER_COUNT, usize::MAX] {
        assert!(matches!(
            registers.merkle_path(index),
            Err(VMError::RegisterOutOfBounds)
        ));
        assert!(matches!(
            registers.merkle_root_and_path(index),
            Err(VMError::RegisterOutOfBounds)
        ));
    }
    assert_eq!(registers.snapshot(), values);
    assert_eq!(registers.snapshot_tags(), tags);
    assert_eq!(registers.merkle_root(), root);
}
