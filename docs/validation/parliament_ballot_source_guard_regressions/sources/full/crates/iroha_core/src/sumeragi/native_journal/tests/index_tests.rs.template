//! Original-pool index backing, physical allocator refusal and unchanged cursor controls.

use super::*;
use crate::test_allocations::{allocations_during, refuse_one_layout_during};
use iroha_allocation::AllocationRefusal;
use std::{
    alloc::Layout,
    task::{Context, Waker},
};

#[test]
fn native_journal_indexes_retain_exact_backing_and_share_original_blocks_without_allocation() {
    let (chain, journal) = fixture();
    // The original offline read owns a finite pool independent of the fixture's
    // retired State generations. Its actual shared controls survive the read.
    let pool = AllocationBudget::new(limits().allocated_bytes);
    let source_floor = pool.reserved_bytes();
    let count = 3;
    let blocks = with_verified_native_journal(
        (&journal).into(),
        &ChainId::from("sumeragi-certified-test-chain"),
        &chain.network_id(),
        limits(),
        &pool,
        |reader| {
            Ok([
                reader.certified(1)?.block().clone(),
                reader.certified(2)?.block().clone(),
                reader.certified(3)?.block().clone(),
            ])
        },
    )
    .unwrap();
    let hashes = blocks.each_ref().map(|block| block.hash());
    let floor = pool.reserved_bytes();
    assert_eq!(
        floor,
        source_floor + count * SharedSignedBlock::allocation_layout().size()
    );
    assert!(blocks.iter().all(|block| block.belongs_to(&pool)));
    let bytes = Layout::array::<SharedSignedBlock>(count).unwrap().size()
        + Layout::array::<HashOf<BlockHeader>>(count).unwrap().size();
    let mut index = NativeJournalIndex::new(count, &pool).unwrap();
    assert_eq!(pool.reserved_bytes(), floor + bytes);
    assert_eq!(index.frames.capacity(), count);
    assert_eq!(index.hashes.capacity(), count);
    let allocations = allocations_during(|| {
        for (block, hash) in blocks.iter().zip(hashes) {
            index.hashes.push_reserved(hash);
            index.frames.push_reserved(block.clone());
        }
    });
    assert_eq!(allocations, 0);
    for (offset, block) in index.frames.as_slice().iter().enumerate() {
        assert!(SharedSignedBlock::ptr_eq(block, &blocks[offset]));
        assert_eq!(index.hashes.as_slice()[offset], block.hash());
    }
    assert_eq!(pool.reserved_bytes(), floor + bytes);
    drop(index);
    assert_eq!(pool.reserved_bytes(), floor);
    drop(blocks);
    assert_eq!(pool.reserved_bytes(), source_floor);
}

#[test]
fn native_journal_index_allocator_refusal_refunds_both_exact_backings() {
    let pool = AllocationBudget::new(64 * 1024);
    let count = 17;
    let layouts = [
        Layout::array::<SharedSignedBlock>(count).unwrap(),
        Layout::array::<HashOf<BlockHeader>>(count).unwrap(),
    ];
    for layout in layouts {
        let (result, refused) =
            refuse_one_layout_during(layout, || NativeJournalIndex::new(count, &pool));
        assert!(refused, "the exact index allocator must be reached");
        let error = match result {
            Ok(_) => panic!("physical refusal cannot manufacture index backing"),
            Err(error) => error,
        };
        assert!(
            matches!(error, NativeJournalError::Index(ChargedBufferError::Allocator { requested_bytes }) if requested_bytes == layout.size())
        );
        assert_eq!(pool.reserved_bytes(), 0);
        let same_pool_retry = NativeJournalIndex::new(count, &pool).unwrap();
        assert_eq!(
            pool.reserved_bytes(),
            layouts.iter().map(Layout::size).sum::<usize>()
        );
        drop(same_pool_retry);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn native_journal_index_capacity_refusal_keeps_original_release_and_unchanged_cursor() {
    let (chain, journal) = fixture();
    // One original offline-reader pool retains every retry owner and refusal.
    let pool = AllocationBudget::new(limits().allocated_bytes);
    let floor = pool.reserved_bytes();
    let mut observer = crate::unit_test_support::release_registration(&pool);
    let mut cursor = NativeJournalCursor::new(
        ChainId::from("sumeragi-certified-test-chain"),
        chain.network_id(),
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        limits(),
        &pool,
    )
    .unwrap();
    cursor
        .advance(
            (&NativeFinalityJournal {
                blocks: journal.blocks[..2].to_vec(),
            })
                .into(),
        )
        .unwrap();
    let retained = cursor.tip().unwrap().block_hash();
    let credits = pool.reserved_bytes();
    let count = journal.blocks.len();
    let frame_bytes = Layout::array::<SharedSignedBlock>(count).unwrap().size();
    let hash_bytes = Layout::array::<HashOf<BlockHeader>>(count).unwrap().size();
    for (earlier_index_bytes, requested) in [(0, frame_bytes), (frame_bytes, hash_bytes)] {
        let allowed = SharedSignedBlock::allocation_layout().size() + earlier_index_bytes;
        let blocker = pool
            .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes() - allowed)
            .unwrap();
        let before = pool.reserved_bytes();
        let AllocationRefusal::Capacity {
            release: original_release,
            ..
        } = pool.try_reserve_bytes(pool.limit_bytes()).unwrap_err()
        else {
            panic!("same original occupied pool");
        };
        let error = cursor.advance((&journal).into()).unwrap_err();
        let NativeJournalError::Index(ChargedBufferError::Admission(AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            release,
        })) = error
        else {
            panic!("exact original index refusal: {error:?}");
        };
        assert_eq!(requested_bytes, requested);
        assert_eq!(reserved_bytes, pool.limit_bytes());
        assert_eq!(limit_bytes, pool.limit_bytes());
        assert_eq!(release, original_release);
        assert_eq!(pool.reserved_bytes(), before);
        assert_eq!(cursor.tip().unwrap().block_hash(), retained);
        // Partial attempt owners were physically freed while returning the original refusal.
        // Their actual release wakes the same source; the blocker remains occupied.
        let mut context = Context::from_waker(Waker::noop());
        assert!(observer.poll_wait(&release, &mut context).is_ready());
        observer.cancel();
        drop(blocker);
        assert_eq!(pool.reserved_bytes(), credits);
    }
    assert_eq!(
        cursor.advance((&journal).into()).unwrap().block_hash(),
        chain.committed(3).block_hash()
    );
    drop(cursor);
    drop(observer);
    assert_eq!(pool.reserved_bytes(), floor);
}
