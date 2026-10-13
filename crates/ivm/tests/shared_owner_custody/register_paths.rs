//! Physical zero-allocation census for original-owner register authentication paths.

use super::{ObserveLog, SERIAL, observe_log_requests, stop_log_requests};
use iroha_allocation::AllocationBudget;
use iroha_crypto::{Hash, HashOf, MerkleProof, MerkleTree, MerkleTreeCommitment};
use ivm::{IVM, VMError};
use sha2::{Digest, Sha256};
use std::num::NonZeroU64;

#[test]
fn all_register_paths_include_cold_dirty_rebuilds_without_any_heap_request() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let original = AllocationBudget::new(128 * 1024 * 1024);
    let mut vm = IVM::try_new_with_memory_budget(10_000, &original).unwrap();
    let occupied = original.reserved_bytes();
    original.set_limit_bytes(0);
    let _scope = ObserveLog;
    observe_log_requests();
    for index in 0..256 {
        let value = if index == 0 {
            0
        } else {
            (index as u64).wrapping_mul(0x0102_0304_0506_0708)
        };
        let tag = index != 0 && index % 3 == 0;
        // Every nonzero iteration starts dirty; neither cold root collection nor
        // a second clean path can allocate a temporary canonical proof or Vec.
        vm.registers.set(index, value);
        vm.registers.set_tag(index, tag);
        let (root, path): (HashOf<MerkleTree<[u8; 32]>>, [[u8; 32]; 8]) =
            vm.registers.merkle_root_and_path(index).unwrap();
        assert_eq!(vm.registers.merkle_path(index).unwrap(), path);
        assert_eq!(vm.registers.merkle_root(), root);
        let mut bytes = [0; 9];
        bytes[0] = u8::from(tag);
        bytes[1..].copy_from_slice(&value.to_le_bytes());
        let leaf = HashOf::<[u8; 32]>::from_untyped_unchecked(Hash::prehashed(
            Sha256::digest(bytes).into(),
        ));
        let siblings =
            path.map(|sibling| Some(HashOf::from_untyped_unchecked(Hash::prehashed(sibling))));
        let commitment = MerkleTreeCommitment::new(root, NonZeroU64::new(256).unwrap());
        assert!(MerkleProof::verify_audit_path_sha256(
            index as u32,
            &siblings,
            &leaf,
            &commitment
        ));
    }
    assert!(matches!(
        vm.registers.merkle_path(256),
        Err(VMError::RegisterOutOfBounds)
    ));
    assert!(matches!(
        vm.registers.merkle_root_and_path(usize::MAX),
        Err(VMError::RegisterOutOfBounds)
    ));
    let requests = stop_log_requests();
    assert_eq!(
        requests, 0,
        "fixed register paths must never allocate temporary siblings"
    );
    assert_eq!(original.reserved_bytes(), occupied);
    drop(vm);
    assert_eq!(original.reserved_bytes(), 0);
}
