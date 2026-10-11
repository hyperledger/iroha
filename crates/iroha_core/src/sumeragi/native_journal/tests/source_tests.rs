//! Exact funded source frame, prepared canonical view and real native verification.

use super::*;
use crate::test_allocations::{allocations_during, refuse_one_layout_during};
use iroha_data_model::sumeragi::finality::{
    PreparedNativeFinalityError, PreparedNativeFinalityJournal,
};

#[test]
fn prepared_native_journal_decodes_without_late_allocations_and_advances_real_native_cursor() {
    let (chain, journal) = fixture();
    let wire = norito::encode_canonical(&journal).unwrap();
    // All source and cursor owners use one original offline-reader pool.
    let pool = AllocationBudget::new(limits().allocated_bytes);
    let floor = pool.reserved_bytes();
    let mut source = ChargedBuffer::new(wire.len(), &pool).unwrap();
    source.append(&wire).unwrap();
    drop(wire);
    let mut prepared = PreparedNativeFinalityJournal::new(limits(), &pool).unwrap();
    let credits = pool.reserved_bytes();
    let prepared_bytes =
        2 * std::alloc::Layout::array::<norito::core::SequenceSpan>(limits().block_count)
            .unwrap()
            .size()
            + norito::core::PreparedDecodeWorkspace::allocation_layouts()
                .iter()
                .map(std::alloc::Layout::size)
                .sum::<usize>();
    assert_eq!(credits, floor + source.capacity() + prepared_bytes);
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
        .unwrap();
    let saturated = pool.reserved_bytes();
    let mut result = None;
    let allocations = allocations_during(|| {
        result = Some(prepared.decode(&source));
    });
    result.take().unwrap().unwrap();
    assert_eq!(allocations, 0);
    assert_eq!(pool.reserved_bytes(), saturated);
    let first = prepared
        .view(&source)
        .unwrap()
        .frames()
        .next()
        .unwrap()
        .wire()
        .as_ptr();
    let allocations = allocations_during(|| {
        result = Some(prepared.decode(&source));
    });
    result.take().unwrap().unwrap();
    assert_eq!(allocations, 0);
    assert_eq!(
        prepared
            .view(&source)
            .unwrap()
            .frames()
            .next()
            .unwrap()
            .wire()
            .as_ptr(),
        first
    );
    drop(blocker);
    assert_eq!(pool.reserved_bytes(), credits);
    let mut cursor = NativeJournalCursor::new(
        ChainId::from("sumeragi-certified-test-chain"),
        chain.network_id(),
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        limits(),
        &pool,
    )
    .unwrap();
    let view = prepared.view(&source).unwrap();
    for frame in view.frames() {
        let charged = frame
            .charged_source()
            .expect("actual original prepared source");
        assert!(std::ptr::eq(charged.original_source(), &source));
        assert!(charged.belongs_to(&pool));
        assert_eq!(charged.wire().as_ptr(), frame.wire().as_ptr());
        assert_eq!(charged.span().get(source.as_slice()).unwrap(), frame.wire());
    }
    assert_eq!(
        cursor.advance(view).unwrap().block_hash(),
        chain.committed(3).block_hash()
    );
    drop(cursor);
    drop(prepared);
    drop(source);
    assert_eq!(pool.reserved_bytes(), floor);
}

#[test]
fn prepared_native_journal_range_allocator_refusal_refunds_original_pool() {
    let pool = AllocationBudget::new(2 * 1024 * 1024);
    let layout =
        std::alloc::Layout::array::<norito::core::SequenceSpan>(limits().block_count).unwrap();
    let (result, refused) = refuse_one_layout_during(layout, || {
        PreparedNativeFinalityJournal::new(limits(), &pool)
    });
    assert!(refused);
    let error = match result {
        Ok(_) => panic!("actual prepared span refusal"),
        Err(error) => error,
    };
    assert!(
        matches!(error, PreparedNativeFinalityError::Storage(ChargedBufferError::Allocator { requested_bytes }) if requested_bytes == layout.size())
    );
    assert_eq!(pool.reserved_bytes(), 0);
    let same_pool = PreparedNativeFinalityJournal::new(limits(), &pool).unwrap();
    assert!(same_pool.belongs_to(&pool));
    drop(same_pool);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn native_reader_rejects_foreign_prepared_source_pool_before_decode_or_control_admission() {
    let (chain, journal) = fixture();
    let wire = norito::encode_canonical(&journal).unwrap();
    // Keep both original offchain operation pools independent of the chain
    // fixture's MV epoch reclamation. No refusal creates or replaces a pool.
    let pool = AllocationBudget::new(limits().allocated_bytes);
    let foreign = AllocationBudget::new(pool.limit_bytes());
    let mut source = ChargedBuffer::new(wire.len(), &foreign).unwrap();
    source.append(&wire).unwrap();
    drop(wire);
    let mut prepared = PreparedNativeFinalityJournal::new(limits(), &foreign).unwrap();
    prepared.decode(&source).unwrap();
    let original_pointer = source.as_slice().as_ptr();
    let original_hash = iroha_crypto::Hash::new(source.as_slice());
    let original_foreign_bytes = foreign.reserved_bytes();
    let original_pool_bytes = pool.reserved_bytes();
    let mut error = None;
    let chain_id = ChainId::from("sumeragi-certified-test-chain");
    let network = chain.network_id();
    assert_eq!(
        allocations_during(|| {
            error = Some(with_verified_native_journal(
                prepared.view(&source).unwrap(),
                &chain_id,
                &network,
                limits(),
                &pool,
                |_| -> Result<(), NativeJournalError> {
                    panic!("foreign pool may not decode or authenticate")
                },
            ));
        }),
        0
    );
    assert!(matches!(
        error.unwrap(),
        Err(NativeJournalError::SourcePool)
    ));
    assert_eq!(pool.reserved_bytes(), original_pool_bytes);
    assert_eq!(foreign.reserved_bytes(), original_foreign_bytes);
    assert_eq!(source.as_slice().as_ptr(), original_pointer);
    assert_eq!(iroha_crypto::Hash::new(source.as_slice()), original_hash);
    let mut cursor = NativeJournalCursor::new(
        ChainId::from("sumeragi-certified-test-chain"),
        chain.network_id(),
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        limits(),
        &foreign,
    )
    .unwrap();
    assert_eq!(
        cursor
            .advance(prepared.view(&source).unwrap())
            .unwrap()
            .block_hash(),
        chain.committed(3).block_hash()
    );
    drop(cursor);
    drop(prepared);
    drop(source);
    assert_eq!(foreign.reserved_bytes(), 0);
    assert_eq!(pool.reserved_bytes(), original_pool_bytes);
}
