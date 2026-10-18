use crate::common;
use common::assemble_syscalls;
use iroha_crypto::{HashOf, MerkleProof, MerkleTree, MerkleTreeCommitment};
use ivm::{IVM, syscalls};
use std::num::NonZeroU64;
#[test]
fn registers_compact_helper_matches_syscall() {
    let target = 9usize;
    let mut vm = IVM::new(u64::MAX);
    let prog = assemble_syscalls(&[syscalls::SYSCALL_GET_REGISTER_MERKLE_COMPACT as u8]);
    vm.load_program(&prog).unwrap();
    vm.set_register(target, 0xCAFEBABE);
    vm.set_register(5, 0x12345678);
    // Via syscall
    let out_ptr = ivm::Memory::OUTPUT_START;
    let root_out = ivm::Memory::OUTPUT_START + 4096;
    vm.set_register(10, target as u64);
    vm.set_register(11, out_ptr);
    vm.set_register(12, 16);
    vm.set_register(13, root_out);
    let (proof_h, root_h) = vm.registers.merkle_compact(target, Some(16)).unwrap();
    vm.run().unwrap();
    // Decode syscall output
    let mut hdr = [0u8; 1 + 4 + 4];
    vm.memory.load_bytes(out_ptr, &mut hdr).unwrap();
    let depth = hdr[0] as usize;
    let total = 1 + 4 + 4 + depth * 32;
    let mut buf = vec![0u8; total];
    vm.memory.load_bytes(out_ptr, &mut buf).unwrap();
    let (proof_s, _) = ivm::merkle_utils::decode_compact_proof_bytes(&buf).unwrap();
    let mut root_s = [0u8; 32];
    vm.memory.load_bytes(root_out, &mut root_s).unwrap();
    assert_eq!(proof_h.depth(), proof_s.depth());
    assert_eq!(proof_h.dirs(), proof_s.dirs());
    assert_eq!(root_h.as_ref(), &root_s);
    // Verify leaf digest for target register (default tag=false)
    let val = vm.register(target);
    let leaf = register_leaf_digest(val, false);
    let root_hash = root_h;
    let commitment = register_commitment(root_hash);
    assert!(proof_h.verify_sha256(&leaf, &commitment));
    assert!(proof_s.verify_sha256(&leaf, &commitment));
    let full_h: MerkleProof<[u8; 32]> = proof_h
        .try_into_full()
        .expect("helper emitted a canonical compact proof");
    let full_s: MerkleProof<[u8; 32]> = proof_s
        .try_into_full()
        .expect("syscall emitted a canonical compact proof");
    assert_eq!(full_h.leaf_index(), target as u32);
    assert_eq!(full_s.leaf_index(), target as u32);
    assert!(full_h.verify_sha256(&leaf, &commitment));
    assert!(full_s.verify_sha256(&leaf, &commitment));
}
#[test]
fn registers_compact_depth_cap_returns_partial_root() {
    let target = 200usize;
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(3, 0xDEADBEEFCAFEBABE);
    vm.set_register(target, 0xBADC0FFEE0DDFACE);
    let (full_proof, full_root) = vm.registers.merkle_compact(target, None).unwrap();
    let leaf = register_leaf_digest(vm.register(target), false);
    let full_commitment = register_commitment(full_root);
    assert!(full_proof.verify_sha256(&leaf, &full_commitment));
    let (capped_proof, capped_root) = vm.registers.merkle_compact(target, Some(4)).unwrap();
    assert_eq!(capped_proof.depth(), 4);
    let capped_full = capped_proof
        .clone()
        .try_into_full()
        .expect("helper emitted a canonical capped proof");
    assert_eq!(capped_full.leaf_index(), target as u32 & 0x0f);
    let computed_partial = capped_full
        .compute_partial_root_sha256(&leaf, usize::from(capped_proof.depth()))
        .expect("proof height equals compact depth");
    assert_eq!(computed_partial, capped_root);
    assert_ne!(capped_root, full_root);
    // A capped path cannot be promoted to membership in the full register tree.
    assert!(!capped_proof.verify_sha256(&leaf, &full_commitment));
}
fn register_commitment(root: HashOf<MerkleTree<[u8; 32]>>) -> MerkleTreeCommitment<[u8; 32]> {
    MerkleTreeCommitment::new(
        root,
        NonZeroU64::new(256).expect("register count is non-zero"),
    )
}
fn register_leaf_digest(value: u64, private: bool) -> HashOf<[u8; 32]> {
    use iroha_crypto::{Hash, HashOf};
    use sha2::Digest as _;
    let mut bytes = [0u8; 9];
    bytes[0] = if private { 1 } else { 0 };
    bytes[1..].copy_from_slice(&value.to_le_bytes());
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&sha2::Sha256::digest(bytes));
    HashOf::from_untyped_unchecked(Hash::prehashed(digest))
}
