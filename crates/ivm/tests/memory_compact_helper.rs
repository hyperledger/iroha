use crate::common;
use ivm::IVM;
#[test]
fn memory_compact_helper_matches_syscall() {
    use iroha_crypto::{CompactMerkleProof, Hash, HashOf, MerkleTree};
    let mut vm = IVM::new(u64::MAX);
    let addr = ivm::Memory::HEAP_START + 96;
    vm.memory.store_u32(addr, 0xDEADBEEF).unwrap();
    vm.memory.commit();
    // Fetch proof/root via syscall helper (writes into OUTPUT)
    let bundle = common::syscall_memory_compact_bundle(&mut vm, addr, Some(16));
    let proof_s = {
        let siblings = bundle
            .siblings
            .iter()
            .map(|b| {
                if *b == [0u8; 32] {
                    None
                } else {
                    Some(HashOf::<[u8; 32]>::from_untyped_unchecked(Hash::prehashed(
                        *b,
                    )))
                }
            })
            .collect();
        CompactMerkleProof::from_parts(bundle.depth, bundle.dirs, siblings)
    };
    let root_s =
        HashOf::<MerkleTree<[u8; 32]>>::from_untyped_unchecked(Hash::prehashed(bundle.root));
    // Reference proof after syscall (OUTPUT writes affect the Merkle root)
    let (proof_h, root_h) = vm.memory.merkle_compact(addr, Some(16)).unwrap();
    assert_eq!(proof_h.depth(), proof_s.depth());
    assert_eq!(proof_h.dirs(), proof_s.dirs());
    assert_eq!(root_h.as_ref(), root_s.as_ref());
    let expected_siblings: Vec<[u8; 32]> = proof_h
        .siblings()
        .iter()
        .map(|opt| opt.map(|h| *h.as_ref()).unwrap_or([0u8; 32]))
        .collect();
    assert_eq!(bundle.siblings, expected_siblings);
}
