//! Deterministic IVM memory Merkle proof regression tests.
use iroha_crypto::{Hash, HashOf, MerkleTreeCommitment};
use ivm::Memory;
use sha2::Digest as _;
use std::num::NonZeroU64;
const CHUNK_BYTES: usize = 32;
fn leaf_hash(bytes: &[u8; CHUNK_BYTES]) -> HashOf<[u8; CHUNK_BYTES]> {
    let digest = sha2::Sha256::digest(bytes);
    let mut arr = [0u8; CHUNK_BYTES];
    arr.copy_from_slice(&digest);
    HashOf::from_untyped_unchecked(Hash::prehashed(arr))
}
fn deterministic_chunk(chunk_idx: usize, seed: u8) -> [u8; CHUNK_BYTES] {
    let mut data = [0u8; CHUNK_BYTES];
    for (idx, byte) in data.iter_mut().enumerate() {
        *byte = seed
            .wrapping_add(idx as u8)
            .wrapping_add((chunk_idx as u8).wrapping_mul(17));
    }
    data
}
#[test]
fn memory_merkle_compact_proofs_verify_for_deterministic_chunks() {
    let chunk_indices = [0, 1, 3, 5];
    let depth_caps = [None];
    for chunk_idx in chunk_indices {
        for depth_cap in depth_caps {
            let data = deterministic_chunk(chunk_idx, depth_cap.unwrap_or(13) as u8);
            let mut memory = Memory::new();
            let addr = Memory::HEAP_START + (chunk_idx * CHUNK_BYTES) as u64;
            memory.store_bytes(addr, &data).expect("store heap chunk");
            memory.commit();
            let (proof, root) = memory.merkle_compact(addr, depth_cap).unwrap();
            let mut chunk = [0u8; CHUNK_BYTES];
            memory
                .load_bytes((addr / CHUNK_BYTES as u64) * CHUNK_BYTES as u64, &mut chunk)
                .expect("load proof chunk");
            let leaf = leaf_hash(&chunk);
            let commitment = memory.merkle_commitment();
            assert_eq!(commitment.root(), &root);
            assert!(
                proof.verify_sha256(&leaf, &commitment),
                "chunk_idx={chunk_idx} depth_cap={depth_cap:?}"
            );
            let wrong_leaf_count = NonZeroU64::new(commitment.leaf_count().get() / 2)
                .expect("memory has more than one leaf");
            let wrong_commitment = MerkleTreeCommitment::new(root, wrong_leaf_count);
            assert!(
                !proof.verify_sha256(&leaf, &wrong_commitment),
                "wrong memory leaf count must fail"
            );
            let mut tampered = chunk;
            tampered[0] ^= 0x01;
            let tampered_leaf = leaf_hash(&tampered);
            assert!(!proof.verify_sha256(&tampered_leaf, &commitment));
        }
    }
}
