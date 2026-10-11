//! Paired immutable cursor reads keep actual prepaid payloads, metadata and scope.

use super::*;
use iroha_allocation::ChargedBuffer;
use mv::{BlockMode, PublicationPreparationError};

#[test]
fn frozen_pair_partial_thaw_keeps_actual_credit_metadata_and_original_scope() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    reset();
    let counters = Arc::new(Counters::default());
    let _context = PolicyContext::new(&counters);
    let budget = AllocationBudget::new(8 << 20);
    let foreign_pool = AllocationBudget::new(budget.limit_bytes());
    let storage = NativeStorage::try_new_admitted(budget.clone()).unwrap();
    seed(&storage, &budget, 0x11);
    let mut metadata = ChargedBuffer::<u8>::new(8, &budget).unwrap();
    metadata.try_push(73).unwrap();
    let metadata_pointer = metadata.as_slice().as_ptr();
    let original = storage
        .try_capture_admitted_block(BlockMode::Ordinary, |block| {
            drop(put(block, &budget, 7, 0x22));
            assert!(put(block, &budget, 10, 0x2a).is_none());
            Ok::<_, ()>(metadata)
        })
        .unwrap();
    let identity = original.publication_identity();
    let current_pointer = original.get(&7).unwrap().pointer();
    let before_pointer = original
        .get_before_block(original.iter().next().unwrap().0)
        .unwrap()
        .pointer();
    let credit = budget.reserved_bytes();
    let full = budget
        .try_reserve_bytes(budget.limit_bytes() - credit)
        .unwrap();
    let copies = (counters.keys.load(SeqCst), counters.values.load(SeqCst));
    let admissions = counters.admissions.load(SeqCst);
    let records = NEXT_RECORD.load(SeqCst);
    let original = without_allocations(|| {
        let frozen = original.freeze_pair();
        assert!(frozen.admission().belongs_to(&budget));
        assert!(!frozen.admission().belongs_to(&foreign_pool));
        assert_eq!(frozen.admission().as_slice().as_ptr(), metadata_pointer);
        let readers = frozen.readers();
        let current_reader = readers.current().clone();
        drop(readers);
        // Undo is unique, so this takes the actual partial-thaw branch. Current
        // remains held by its real original cursor, not a quota-counter proxy.
        let frozen = match frozen.try_into_detached() {
            Err(frozen) => frozen,
            Ok(_) => panic!("held original current reader must refuse paired thaw"),
        };
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        assert_eq!(frozen.publication_identity(), identity);
        assert_eq!(frozen.admission().as_slice().as_ptr(), metadata_pointer);
        let readers = frozen.readers();
        assert!(readers.current().same_original(&current_reader));
        let mut undo = readers.undo().positions();
        let position = undo.try_next(|_| Ok::<_, ()>(())).unwrap().unwrap();
        let (key, value) = readers
            .undo()
            .resolve(&position, |_| Ok::<_, ()>(()))
            .unwrap();
        assert_eq!(key.order, 7);
        assert_eq!(value.as_ref().unwrap().pointer(), before_pointer);
        let mut current = readers.current().positions();
        let position_current = current.try_next(|_| Ok::<_, ()>(())).unwrap().unwrap();
        assert_eq!(
            readers
                .current()
                .resolve(&position_current, |_| Ok::<_, ()>(()))
                .unwrap()
                .1
                .pointer(),
            current_pointer
        );
        drop((
            position,
            position_current,
            undo,
            current,
            readers,
            current_reader,
        ));
        frozen
            .try_into_detached()
            .unwrap_or_else(|_| panic!("both original readers retired"))
    });
    let original = without_allocations(|| {
        foreign_pool.with_deferred_refund_notifications(|scope| {
            match original.try_publication_slot(scope, &storage) {
                Err((
                    original,
                    PublicationPreparationError::Admission(AdmittedStorageError::ScopeIdentity),
                )) => original,
                _ => panic!("same retained pair must reject the foreign refund scope"),
            }
        })
    });
    assert_eq!(foreign_pool.reserved_bytes(), 0);
    assert_eq!(original.publication_identity(), identity);
    assert_eq!(original.admission().as_slice().as_ptr(), metadata_pointer);
    let metadata = without_allocations(|| {
        budget.with_deferred_refund_notifications(|scope| {
            let mut slot = original
                .try_publication_slot(scope, &storage)
                .unwrap_or_else(|_| panic!("original scope and pool"));
            slot.try_prepare().unwrap();
            slot.into_prepared().publish().into_admission()
        })
    });
    assert_eq!(metadata.as_slice(), &[73]);
    assert_eq!(metadata.as_slice().as_ptr(), metadata_pointer);
    assert!(metadata.belongs_to(&budget));
    assert_eq!(storage.view().get(&7).unwrap().pointer(), current_pointer);
    assert_eq!(
        (counters.keys.load(SeqCst), counters.values.load(SeqCst)),
        copies
    );
    assert_eq!(counters.admissions.load(SeqCst), admissions);
    assert_eq!(NEXT_RECORD.load(SeqCst), records);
    drop(full);
    without_allocations(|| {
        budget.with_deferred_refund_notifications(|_| drop((metadata, identity, storage)))
    });
    reclaimed_since(0);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn frozen_pair_equal_foreign_target_and_changed_predecessor_cannot_publish() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    reset();
    let counters = Arc::new(Counters::default());
    let _context = PolicyContext::new(&counters);
    let budget = AllocationBudget::new(8 << 20);
    let storage = NativeStorage::try_new_admitted(budget.clone()).unwrap();
    let foreign = NativeStorage::try_new_admitted(budget.clone()).unwrap();
    seed(&storage, &budget, 0x31);
    seed(&foreign, &budget, 0x31);
    let original = storage
        .try_capture_admitted_block(BlockMode::Ordinary, |block| {
            drop(put(block, &budget, 7, 0x32));
            Ok::<_, ()>(())
        })
        .unwrap();
    let identity = original.publication_identity();
    let pointer = original.get(&7).unwrap().pointer();
    let original = without_allocations(|| {
        let frozen = original.freeze_pair();
        assert!(frozen.belongs_to(&storage));
        assert!(!frozen.belongs_to(&foreign));
        assert!(frozen.matches_current(&storage));
        frozen
            .try_into_detached()
            .unwrap_or_else(|_| panic!("no reader escaped"))
    });
    let original = without_allocations(|| {
        budget.with_deferred_refund_notifications(|scope| {
            let mut slot = original
                .try_publication_slot(scope, &foreign)
                .unwrap_or_else(|_| panic!("same pool does not grant source authority"));
            assert_eq!(
                slot.try_prepare(),
                Err(PublicationPreparationError::Changed)
            );
            let original = slot.recover_original();
            drop(slot);
            original
        })
    });
    let frozen = original.freeze_pair();
    storage
        .try_with_admitted_block(|_| Ok::<_, ()>(()))
        .unwrap();
    assert!(!frozen.matches_current(&storage));
    let original = frozen
        .try_into_detached()
        .unwrap_or_else(|_| panic!("source changes do not replace immutable work"));
    let original = without_allocations(|| {
        budget.with_deferred_refund_notifications(|scope| {
            let mut slot = original
                .try_publication_slot(scope, &storage)
                .unwrap_or_else(|_| panic!("same original pool"));
            assert_eq!(
                slot.try_prepare(),
                Err(PublicationPreparationError::Changed)
            );
            let original = slot.recover_original();
            assert_eq!(original.publication_identity(), identity);
            assert_eq!(original.get(&7).unwrap().pointer(), pointer);
            marker(original.get(&7), 0x32);
            drop(slot);
            original
        })
    });
    without_allocations(|| {
        budget.with_deferred_refund_notifications(|_| drop((original, identity, storage, foreign)))
    });
    reclaimed_since(0);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn frozen_pair_row_positions_retain_actual_original_pool_until_last_reader_retirement() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    reset();
    let counters = Arc::new(Counters::default());
    let _context = PolicyContext::new(&counters);
    let budget = AllocationBudget::new(8 << 20);
    let storage = NativeStorage::try_new_admitted(budget.clone()).unwrap();
    seed(&storage, &budget, 0x41);
    let original = storage
        .try_capture_admitted_block(BlockMode::Ordinary, |block| {
            drop(put(block, &budget, 7, 0x42));
            Ok::<_, ()>(())
        })
        .unwrap();
    let pointer = original.get(&7).unwrap().pointer();
    let frozen = original.freeze_pair();
    let readers = frozen.readers();
    let current_reader = readers.current().clone();
    let mut positions = current_reader.positions();
    let position = positions.try_next(|_| Ok::<_, ()>(())).unwrap().unwrap();
    drop((positions, readers));
    without_allocations(|| budget.with_deferred_refund_notifications(|_| drop((frozen, storage))));
    assert!(
        budget.reserved_bytes() > 0,
        "actual charged original nodes and payload remain owned"
    );
    without_allocations(|| {
        let (_, value) = current_reader
            .resolve(&position, |_| Ok::<_, ()>(()))
            .unwrap();
        assert_eq!(value.pointer(), pointer);
        marker(Some(value), 0x42);
    });
    without_allocations(|| {
        budget.with_deferred_refund_notifications(|_| drop((position, current_reader)))
    });
    reclaimed_since(0);
    assert_eq!(budget.reserved_bytes(), 0);
}
