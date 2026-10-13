//! Original shared history survives private edits, handoff, abort and stale publication.
use super::*;
use std::io::Write as _;
fn hash(n: u8) -> HashOf<BlockHeader> {
    HashOf::from_untyped_unchecked(Hash::prehashed([n; Hash::LENGTH]))
}
fn values(read: &dyn BlockHashRead) -> Vec<HashOf<BlockHeader>> {
    read.iter().copied().collect()
}
#[test]
fn ordinary_detachment_retains_original_nodes_without_pinning_writers() {
    let owner = BlockHashes::new(vec![hash(1), hash(2)]);
    let reader = owner.view();
    let mut block = owner.block();
    assert!((&reader).into_iter().copied().eq([hash(1), hash(2)]));
    assert!((&block).into_iter().copied().eq([hash(1), hash(2)]));
    assert_eq!(
        std::ptr::from_ref(reader.get(0).unwrap()),
        std::ptr::from_ref(block.get(0).unwrap())
    );
    block.push(hash(3));
    block.push(hash(4));
    let pointer = std::ptr::from_ref(block.get(0).unwrap());
    assert!(owner.writer_available());
    let detached = block.detach();
    assert_eq!(std::ptr::from_ref(detached.get(0).unwrap()), pointer);
    assert_eq!(detached.mode(), mv::BlockMode::Ordinary);
    assert_eq!(detached.prefix(), &[hash(1), hash(2)]);
    assert_eq!(detached.pending(), &[hash(3), hash(4)]);
    assert_eq!(values(&detached), [hash(1), hash(2), hash(3), hash(4)]);
    assert!(detached.matches_current(&owner));
    drop(detached);
    assert_eq!(values(&reader), [hash(1), hash(2)]);
    assert_eq!(values(&owner.view()), [hash(1), hash(2)]);
    assert_eq!(owner.committed_height(), 2);
}
#[test]
fn replacement_detachment_retains_tip_removal_and_original_predecessor() {
    let owner = BlockHashes::new(vec![hash(1), hash(2)]);
    let mut block = owner.block_and_revert();
    block.push(hash(3));
    let detached = block.detach();
    assert_eq!(detached.prefix(), &[hash(1)]);
    assert_eq!(detached.pending(), &[hash(3)]);
    assert_eq!(values(&detached), [hash(1), hash(3)]);
    assert!(detached.matches_current(&owner));
    assert!(!detached.matches_block_predecessor(&owner.block()));
    assert!(detached.matches_block_predecessor(&owner.block_and_revert()));
    drop(detached);
    assert_eq!(values(&owner.view()), [hash(1), hash(2)]);
}
#[test]
fn replacement_without_appends_publishes_tip_removal_even_with_old_reader() {
    let owner = BlockHashes::new(vec![hash(1), hash(2)]);
    let reader = owner.view();
    let detached = owner.block_and_revert().detach();
    assert!(detached.pending().is_empty());
    assert_eq!(detached.prefix(), &[hash(1)]);
    owner.block_and_revert().commit();
    assert_eq!(values(&reader), [hash(1), hash(2)]);
    assert_eq!(values(&owner.view()), [hash(1)]);
    assert!(!detached.matches_current(&owner));
    let empty = BlockHashes::default();
    let ordinary = empty.block().detach();
    let replace = empty.block_and_revert().detach();
    assert!(ordinary.is_empty());
    assert!(replace.is_empty());
    assert!(!ordinary.matches_block_predecessor(&empty.block_and_revert()));
    assert!(!replace.matches_block_predecessor(&empty.block()));
}
#[test]
fn aborted_block_and_read_only_child_preserve_original_identity() {
    let owner = BlockHashes::new(vec![hash(1)]);
    let original = owner.block().detach();
    {
        let mut aborted = owner.block();
        aborted.push(hash(2));
    }
    assert!(original.matches_current(&owner));
    let mut block = owner.block();
    {
        let child = block.transaction();
        assert_eq!(values(&child), [hash(1)]);
        assert!((&child).into_iter().copied().eq([hash(1)]));
    }
    {
        let child = block.transaction();
        assert_eq!(values(&child), [hash(1)]);
        assert!((&child).into_iter().copied().eq([hash(1)]));
        child.apply();
    }
    let unchanged = block.detach();
    assert!(unchanged.pending().is_empty());
    assert!(unchanged.matches_current(&owner));
    owner.block().commit();
    assert!(!original.matches_current(&owner));
    assert!(!unchanged.matches_current(&owner));
}
#[test]
fn equal_content_aba_cannot_restore_original_predecessor() {
    let owner = BlockHashes::new(vec![hash(1), hash(2)]);
    let original = owner.block().detach();
    for tip in [3, 2] {
        let mut block = owner.block_and_revert();
        block.push(hash(tip));
        block.commit();
        assert!(!original.matches_current(&owner));
    }
    assert_eq!(values(&owner.view()), values(&original));
    assert_eq!(owner.committed_height(), 2);
    assert!(!original.matches_block_predecessor(&owner.block()));
}
#[test]
fn private_edit_after_new_publication_stays_original_and_cannot_publish() {
    let owner = BlockHashes::new(vec![hash(1)]);
    let mut original = owner.block();
    let mut replacement = owner.block_and_revert();
    replacement.push(hash(3));
    replacement.commit();
    original.push(hash(2));
    let detached = original.detach();
    assert_eq!(values(&detached), [hash(1), hash(2)]);
    assert!(!detached.matches_current(&owner));
    assert!(matches!(
        detached
            .try_prepare_publication(&owner, |_, _| Ok::<_, ()>(()))
            .err()
            .unwrap()
            .1,
        mv::PublicationPreparationError::Changed
    ));
    assert_eq!(values(&owner.view()), [hash(3)]);
}
#[test]
fn original_generation_crosses_static_handoff_and_outlives_state_facade() {
    fn owned<T: Send + Sync + 'static>() {}
    owned::<DetachedBlockHashes>();
    let owner = Arc::new(BlockHashes::new(vec![hash(1)]));
    let worker = owner.clone();
    let first = std::thread::spawn(move || {
        let mut block = worker.block();
        block.push(hash(2));
        block.detach()
    })
    .join()
    .unwrap();
    assert_eq!(Arc::strong_count(&owner), 1);
    assert!(owner.writer_available());
    let weak = Arc::downgrade(&owner);
    drop(owner);
    assert!(weak.upgrade().is_none());
    assert_eq!(first.prefix(), &[hash(1)]);
    assert_eq!(first.pending(), &[hash(2)]);
    assert!(!first.matches_current(&BlockHashes::new(vec![hash(1)])));
}
#[test]
fn cold_restoration_preserves_values_without_forging_original_identity() {
    let owner = BlockHashes::new(vec![hash(1), hash(2)]);
    let detached = owner.block_and_revert().detach();
    let mut encoded = String::new();
    serialize_block_hashes(&owner.view(), &mut encoded);
    assert_eq!(
        encoded,
        norito::json::to_json(&vec![hash(1), hash(2)]).unwrap()
    );
    let restored = BlockHashes::new(norito::json::from_json(&encoded).unwrap());
    assert_eq!(values(&restored.view()), values(&owner.view()));
    assert_eq!(restored.committed_height(), 2);
    assert!(detached.matches_current(&owner));
    assert!(!detached.matches_current(&restored));
    assert!(!detached.matches_block_predecessor(&restored.block_and_revert()));
}
#[test]
fn emergency_mapping_cannot_capture_mutable_generation_or_family() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(hash(1).as_ref()).unwrap();
    let mapping = ReadOnlyMmap::copy_read_only(file.as_file(), Hash::LENGTH).unwrap();
    let mapped = BlockHashes::new_emergency_fast_mapped(mapping, 1);
    assert!(mapped.map().is_none());
    for replace in [false, true] {
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| if replace {
                mapped.block_and_revert()
            } else {
                mapped.block()
            }))
            .is_err()
        );
        assert_eq!(values(&mapped.view()), [hash(1)]);
        assert_eq!(mapped.committed_height(), 1);
    }
}
#[test]
fn shared_generation_ranges_are_exact_and_double_ended() {
    let owner = BlockHashes::new((0..200).map(hash).collect());
    let old = owner.view();
    let mut block = owner.block();
    block.push(hash(200));
    block.commit();
    let mut range = old.hash_range(31, 130);
    assert_eq!(range.len(), 99);
    assert_eq!(range.next(), Some(&hash(31)));
    assert_eq!(range.next_back(), Some(&hash(129)));
    assert_eq!(range.len(), 97);
    assert!(range.copied().eq((32..129).map(hash)));
    assert!(old.hash_range(200, 200).next().is_none());
    assert_eq!(old.len(), 200);
    assert_eq!(owner.view().len(), 201);
}
