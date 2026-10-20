//! Warm memory resets preserve pending template writes and canonical commitments.

use super::*;

#[test]
fn warm_reset_roots_and_proofs_match_templates_with_pending_dirty_leaves() {
    for pending in [false, true] {
        let mut template = Memory::new_with_stack_limit(Memory::MIN_STACK_SIZE).unwrap();
        let addresses = [
            Memory::HEAP_START,
            Memory::HEAP_START + 63 * 32,
            Memory::HEAP_START + 64 * 32,
            Memory::STACK_START + Memory::MIN_STACK_SIZE - 32,
        ];
        for (index, &address) in addresses.iter().enumerate() {
            template.store_u8(address, 0xa0 + index as u8).unwrap();
        }
        if !pending {
            template.commit();
        }
        // Runtime templates can retain pending Merkle writes after their
        // modification tracking has become the invocation baseline.
        template.mark_template_clean();
        assert_eq!(template.dirty_chunks.is_empty(), !pending);
        let mut expected = template.try_clone_for_runtime_template(None).unwrap();
        let expected_root = expected.root();
        let expected_proofs: Vec<_> = addresses
            .iter()
            .map(|&address| expected.merkle_root_and_path(address).unwrap())
            .collect();
        let mut worker = template.try_clone_for_runtime_template(None).unwrap();
        let memory_pointer = worker.data.as_ptr();
        let dirty_pointer = worker.dirty_chunks.words().as_ptr();
        let modified_pointer = worker.modified_chunks.words().as_ptr();
        for iteration in 0..6 {
            if iteration != 2 {
                // Some writes overlap pending template leaves; one deliberately
                // does not. The untouched dirty leaves must survive every cycle.
                worker
                    .store_u8(addresses[iteration % addresses.len()], 0xe1)
                    .unwrap();
                worker.store_u8(Memory::HEAP_START + 32, 0xf2).unwrap();
            }
            if iteration % 2 == 0 {
                worker.commit();
            }
            worker.reset_from_template(&template).unwrap();
            assert_eq!(&*worker.data, &*template.data);
            assert_eq!(worker.dirty_chunks, template.dirty_chunks);
            assert!(worker.modified_chunks.is_empty());
            assert_eq!(worker.data.as_ptr(), memory_pointer);
            assert_eq!(worker.dirty_chunks.words().as_ptr(), dirty_pointer);
            assert_eq!(worker.modified_chunks.words().as_ptr(), modified_pointer);
            assert_eq!(worker.root(), expected_root);
            for (&address, expected_proof) in addresses.iter().zip(&expected_proofs) {
                assert_eq!(
                    worker.merkle_root_and_path(address).unwrap(),
                    *expected_proof
                );
            }
        }
        assert_eq!(template.dirty_chunks.is_empty(), !pending);
    }
}
