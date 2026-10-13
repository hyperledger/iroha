use ivm::{IVM, VMError};
#[test]
fn memory_compact_bundle_roundtrip() {
    let mut vm = IVM::new(u64::MAX);
    let addr = ivm::Memory::HEAP_START + 128;
    vm.memory.store_u64(addr, 0xAA55_AA55_AA55_AA55).unwrap();
    vm.memory.commit();
    let bundle = ivm::merkle_utils::memory_compact_bundle(&mut vm.memory, addr, Some(16)).unwrap();
    let (cp, root) = vm.memory.merkle_compact(addr, Some(16)).unwrap();
    let cp2 = bundle.to_compact_proof();
    assert_eq!(bundle.depth, cp.depth());
    assert_eq!(bundle.dirs, cp.dirs());
    assert_eq!(bundle.root, *root.as_ref());
    assert_eq!(cp2.depth(), cp.depth());
    assert_eq!(cp2.dirs(), cp.dirs());
    // Also expand the self-contained bundle and reconstruct its partial root.
    use iroha_crypto::{Hash, HashOf, MerkleError};
    use sha2::Digest as _;
    let base = (addr / 32) * 32;
    let mut chunk = [0u8; 32];
    vm.memory.load_bytes(base, &mut chunk).unwrap();
    let mut leaf = [0u8; 32];
    leaf.copy_from_slice(&sha2::Sha256::digest(chunk));
    let leaf_t = HashOf::<[u8; 32]>::from_untyped_unchecked(Hash::prehashed(leaf));
    let root_t = root;
    let depth = bundle.depth;
    let dirs = bundle.dirs;
    let mut noncanonical = bundle.clone();
    noncanonical.dirs |= 1u32
        .checked_shl(u32::from(depth))
        .expect("memory bundle is capped below depth 32");
    assert!(matches!(
        noncanonical.try_into_full_proof(),
        Err(MerkleError::NonCanonicalCompactProof)
    ));
    let mut wrong_sibling_count = bundle.clone();
    wrong_sibling_count.siblings.pop();
    assert!(matches!(
        wrong_sibling_count.try_into_full_proof(),
        Err(MerkleError::NonCanonicalCompactProof)
    ));
    let full = bundle
        .try_into_full_proof()
        .expect("helper emitted a canonical compact proof");
    assert_eq!(full.leaf_index(), dirs);
    assert_eq!(dirs, (addr / 32) as u32 & ((1u32 << depth) - 1));
    let computed = full
        .compute_partial_root_sha256(&leaf_t, usize::from(depth))
        .expect("memory proof should produce a root");
    assert_eq!(computed, root_t, "memory compact bundle root mismatch");
}
#[test]
fn registers_compact_bundle_roundtrip() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(3, 0xDEADBEEF);
    let bundle = ivm::merkle_utils::registers_compact_bundle(&vm.registers, 3, Some(16)).unwrap();
    let (cp, root) = vm.registers.merkle_compact(3, Some(16)).unwrap();
    let cp2 = bundle.to_compact_proof();
    assert_eq!(bundle.depth, cp.depth());
    assert_eq!(bundle.dirs, cp.dirs());
    assert_eq!(bundle.root, *root.as_ref());
    assert_eq!(cp2.depth(), cp.depth());
    assert_eq!(cp2.dirs(), cp.dirs());
    // The uncapped 8-level register proof has a fixed, authenticated count.
    use iroha_crypto::{Hash, HashOf, MerkleTreeCommitment};
    use sha2::Digest as _;
    use std::num::NonZeroU64;
    let val = vm.register(3);
    let mut bytes = [0u8; 9];
    bytes[0] = 0;
    bytes[1..].copy_from_slice(&val.to_le_bytes());
    let mut leaf = [0u8; 32];
    leaf.copy_from_slice(&sha2::Sha256::digest(bytes));
    let leaf_t = HashOf::<[u8; 32]>::from_untyped_unchecked(Hash::prehashed(leaf));
    let root_t = root;
    let full = bundle
        .try_into_full_proof()
        .expect("helper emitted a canonical compact proof");
    assert_eq!(full.leaf_index(), 3);
    let commitment = MerkleTreeCommitment::new(
        root_t,
        NonZeroU64::new(256).expect("register count is non-zero"),
    );
    assert!(full.verify_sha256(&leaf_t, &commitment));
}

#[test]
fn memory_compact_bundle_rejects_non_addresses() {
    let mut vm = IVM::new(u64::MAX);
    for invalid in [vm.memory.stack_top(), u64::MAX] {
        assert!(matches!(
            ivm::merkle_utils::memory_compact_bundle(&mut vm.memory, invalid, None),
            Err(VMError::MemoryOutOfBounds)
        ));
    }
}
