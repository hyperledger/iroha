use crate::common;
use common::assemble_syscalls;
use ivm::{IVM, syscalls};
#[test]
fn compact_proof_decodes_and_verifies() {
    use iroha_crypto::{Hash, HashOf, MerkleProof, MerkleTree};
    use sha2::{Digest, Sha256};
    let mut vm = IVM::new(u64::MAX);
    let prog = assemble_syscalls(&[syscalls::SYSCALL_GET_MERKLE_COMPACT as u8]);
    vm.load_program(&prog).expect("load");
    // Write 8 bytes into the second 32-byte chunk.
    let addr = ivm::Memory::HEAP_START + 32;
    vm.memory
        .store_u64(addr, 0xDEAD_BEEF_DEAD_BEEFu64)
        .expect("store");
    vm.memory.commit();
    // Request a compact proof with depth cap 16 and also request root.
    let out_ptr = ivm::Memory::OUTPUT_START;
    let root_ptr = ivm::Memory::OUTPUT_START + 4096;
    vm.set_register(10, addr);
    vm.set_register(11, out_ptr);
    vm.set_register(12, 16);
    vm.set_register(13, root_ptr);
    vm.run().expect("run");
    // Read header to determine total length
    let mut hdr = [0u8; 1 + 4 + 4];
    vm.memory.load_bytes(out_ptr, &mut hdr).expect("load hdr");
    let depth = hdr[0] as usize;
    let total_len = 1 + 4 + 4 + depth * 32;
    let mut buf = vec![0u8; total_len];
    vm.memory.load_bytes(out_ptr, &mut buf).expect("load body");
    let (compact, used) = ivm::merkle_utils::decode_compact_proof_bytes(&buf).expect("decode");
    assert_eq!(used, total_len);
    // Reconstruct leaf typed hash (SHA-256(chunk), prehashed) and root typed hash
    let chunk_base = (addr / 32) * 32;
    let mut chunk = [0u8; 32];
    vm.memory
        .load_bytes(chunk_base, &mut chunk)
        .expect("load chunk");
    let digest = Sha256::digest(chunk);
    let mut leaf_bytes = [0u8; 32];
    leaf_bytes.copy_from_slice(&digest);
    let leaf = HashOf::<[u8; 32]>::from_untyped_unchecked(Hash::prehashed(leaf_bytes));
    let mut root_bytes = [0u8; 32];
    vm.memory
        .load_bytes(root_ptr, &mut root_bytes)
        .expect("load root");
    let root = HashOf::<MerkleTree<[u8; 32]>>::from_untyped_unchecked(Hash::prehashed(root_bytes));
    // A depth-capped syscall root is a path-fragment root, not a full-tree
    // membership commitment. Expand the self-contained direction bitset and
    // reconstruct exactly that partial root.
    let idx = (addr / 32) as u32;
    let full: MerkleProof<[u8; 32]> = compact
        .clone()
        .try_into_full()
        .expect("syscall emitted a canonical compact proof");
    assert_eq!(full.leaf_index(), idx);
    let computed = full
        .compute_partial_root_sha256(&leaf, usize::from(compact.depth()))
        .expect("proof height equals compact depth");
    assert_eq!(computed, root);
}
#[test]
fn compact_proof_dir_flip_fails() {
    use iroha_crypto::{CompactMerkleProof, Hash, HashOf, MerkleTree};
    use sha2::{Digest, Sha256};
    let mut vm = IVM::new(u64::MAX);
    let prog = assemble_syscalls(&[syscalls::SYSCALL_GET_MERKLE_COMPACT as u8]);
    vm.load_program(&prog).unwrap();
    let addr = ivm::Memory::HEAP_START + 32;
    vm.memory.store_u32(addr, 0xDEAD_BEEF).unwrap();
    vm.memory.commit();
    // Request compact proof
    let out_ptr = ivm::Memory::OUTPUT_START;
    let root_ptr = ivm::Memory::OUTPUT_START + 4096;
    vm.set_register(10, addr);
    vm.set_register(11, out_ptr);
    vm.set_register(12, 16);
    vm.set_register(13, root_ptr);
    vm.run().unwrap();
    // Decode proof
    let mut hdr = [0u8; 9];
    vm.memory.load_bytes(out_ptr, &mut hdr).unwrap();
    let depth = hdr[0] as usize;
    let total = 1 + 4 + 4 + depth * 32;
    let mut buf = vec![0u8; total];
    vm.memory.load_bytes(out_ptr, &mut buf).unwrap();
    let (cp, _) = ivm::merkle_utils::decode_compact_proof_bytes(&buf).unwrap();
    // Build leaf and root
    let base = (addr / 32) * 32;
    let mut chunk = [0u8; 32];
    vm.memory.load_bytes(base, &mut chunk).unwrap();
    let digest = Sha256::digest(chunk);
    let mut leaf_bytes = [0u8; 32];
    leaf_bytes.copy_from_slice(&digest);
    let leaf = HashOf::<[u8; 32]>::from_untyped_unchecked(Hash::prehashed(leaf_bytes));
    let mut root_bytes = [0u8; 32];
    vm.memory.load_bytes(root_ptr, &mut root_bytes).unwrap();
    let partial_root =
        HashOf::<MerkleTree<[u8; 32]>>::from_untyped_unchecked(Hash::prehashed(root_bytes));
    let full = cp
        .clone()
        .try_into_full()
        .expect("syscall emitted a canonical compact proof");
    assert_eq!(
        full.compute_partial_root_sha256(&leaf, usize::from(cp.depth())),
        Some(partial_root)
    );
    // Flip the lowest direction/index bit and ensure it cannot reconstruct the
    // syscall's partial root.
    let flipped = CompactMerkleProof::from_parts(cp.depth(), cp.dirs() ^ 1, cp.siblings().to_vec());
    let flipped_full = flipped
        .try_into_full()
        .expect("flipped used direction bit remains canonical");
    assert_ne!(
        flipped_full.compute_partial_root_sha256(&leaf, usize::from(cp.depth())),
        Some(partial_root)
    );
}
#[test]
fn compact_depth_cap_uses_the_full_protocol_register() {
    let mut vm = IVM::new(u64::MAX);
    let prog = assemble_syscalls(&[syscalls::SYSCALL_GET_MERKLE_COMPACT as u8]);
    vm.load_program(&prog).expect("load program");
    let addr = ivm::Memory::HEAP_START + 32;
    vm.memory.store_u32(addr, 0xDEAD_BEEF).expect("store");
    vm.memory.commit();
    vm.set_register(10, addr);
    vm.set_register(11, ivm::Memory::OUTPUT_START);
    // On a 32-bit host, an unchecked usize cast aliases this value to one.
    // The protocol meaning is instead min(raw, 32), so the proof is not
    // truncated to depth one.
    vm.set_register(12, u64::from(u32::MAX) + 2);
    vm.set_register(13, 0);
    vm.run().expect("run");
    assert!(vm.register(10) > 1);
}
