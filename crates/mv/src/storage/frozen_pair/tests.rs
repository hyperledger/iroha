//! Exact original pair capture, finite row reads and intact thaw refusal.

use super::*;
use crate::allocation_test_support::without_allocations;
use concread::bptree::RowPositionError;

fn target() -> Storage<u64, String> {
    [(1, "base"), (2, "deleted"), (4, "equal"), (8, "untouched")]
        .into_iter()
        .map(|(key, value)| (key, value.into()))
        .collect()
}

#[test]
fn frozen_pair_preserves_complete_original_rows_metadata_and_replacement_cut() {
    for mode in [BlockMode::Ordinary, BlockMode::Replace] {
        let target = target();
        let mut tip = target.block();
        tip.insert(1, "tip".into());
        tip.commit();
        let mut block = match mode {
            BlockMode::Ordinary => target.block(),
            BlockMode::Replace => target.block_and_revert(),
        };
        block.insert(1, "successor".into());
        block.remove(2);
        block.remove(3);
        block.insert(4, "equal".into());
        block.insert(5, "new".into());
        let identity = block.publication_identity();
        let current_pointer = block.get(&1).unwrap().as_ptr();
        let before_pointer = block.get_before_block(&1).unwrap().as_ptr();
        let admission = Box::new(73_u64);
        let admission_pointer = std::ptr::from_ref(admission.as_ref());
        let original = block.try_detach(|_| Ok::<_, ()>(admission)).unwrap();
        without_allocations(|| {
            let frozen = original.freeze_pair();
            assert_eq!(frozen.mode(), mode);
            assert!(frozen.is_dirty());
            assert!(frozen.belongs_to(&target));
            assert!(frozen.matches_current(&target));
            assert_eq!(frozen.publication_identity(), identity);
            assert_eq!(
                std::ptr::from_ref(frozen.admission().as_ref()),
                admission_pointer
            );
            let readers = frozen.readers();
            assert!(readers.same_original(&frozen.readers()));
            assert_eq!(readers.publication_identity(), &identity);
            let mut current = readers.current().positions();
            let mut undo = readers.undo().positions();
            for (key, value) in [(1, "successor"), (4, "equal"), (5, "new"), (8, "untouched")] {
                let position = current.try_next(|_| Ok::<_, ()>(())).unwrap().unwrap();
                let (actual_key, actual_value) = readers
                    .current()
                    .resolve(&position, |_| Ok::<_, ()>(()))
                    .unwrap();
                assert_eq!((*actual_key, actual_value.as_str()), (key, value));
                if key == 1 {
                    assert_eq!(actual_value.as_ptr(), current_pointer);
                }
            }
            for (key, value) in [
                (
                    1,
                    Some(if mode == BlockMode::Ordinary {
                        "tip"
                    } else {
                        "base"
                    }),
                ),
                (2, Some("deleted")),
                (3, None),
                (4, Some("equal")),
                (5, None),
            ] {
                let position = undo.try_next(|_| Ok::<_, ()>(())).unwrap().unwrap();
                let (actual_key, actual_value) = readers
                    .undo()
                    .resolve(&position, |_| Ok::<_, ()>(()))
                    .unwrap();
                assert_eq!((*actual_key, actual_value.as_deref()), (key, value));
                if key == 1 {
                    assert_eq!(actual_value.as_ref().unwrap().as_ptr(), before_pointer);
                }
            }
            assert!(current.try_next(|_| Err::<(), _>(17)).unwrap().is_none());
            assert!(undo.try_next(|_| Err::<(), _>(17)).unwrap().is_none());
            drop((current, undo, readers));
            let original = frozen
                .try_into_detached()
                .unwrap_or_else(|_| panic!("all original readers retired"));
            assert_eq!(original.publication_identity(), identity);
            assert_eq!(original.mode(), mode);
            assert!(original.is_dirty());
            assert_eq!(original.get(&1).unwrap().as_ptr(), current_pointer);
            assert_eq!(
                original.get_before_block(&1).unwrap().as_ptr(),
                before_pointer
            );
            assert_eq!(
                std::ptr::from_ref(original.admission().as_ref()),
                admission_pointer
            );
            let prepared = original
                .try_prepare_publication(&target, |_, _| Ok::<_, ()>(()))
                .unwrap_or_else(|(_, error, _)| {
                    panic!("original target and predecessor: {error:?}")
                });
            let (admission, ()) = prepared.publish().into_reservations();
            assert_eq!(std::ptr::from_ref(admission.as_ref()), admission_pointer);
            assert_eq!(*admission, 73);
            assert_eq!(target.view().get(&1).unwrap().as_ptr(), current_pointer);
        });
    }
}

#[test]
fn frozen_pair_current_only_thaw_refusal_refreezes_the_same_undo_and_metadata() {
    let target = target();
    let mut block = target.block();
    block.insert(1, "successor".into());
    let original = block.try_detach(|_| Ok::<_, ()>(Box::new(19_u64))).unwrap();
    let before_pointer = original.get_before_block(&1).unwrap().as_ptr();
    let current_pointer = original.get(&1).unwrap().as_ptr();
    let admission_pointer = std::ptr::from_ref(original.admission().as_ref());
    let identity = original.publication_identity();
    without_allocations(|| {
        let frozen = original.freeze_pair();
        let readers = frozen.readers();
        let current_reader = readers.current().clone();
        // No undo reader survives: the first map really thaws before the held
        // current map refuses. An untouched fixed identity cannot fake this test.
        drop(readers);
        let frozen = match frozen.try_into_detached() {
            Err(original) => original,
            Ok(_) => panic!("held current work must refuse paired thaw"),
        };
        assert_eq!(frozen.publication_identity(), identity);
        assert_eq!(
            std::ptr::from_ref(frozen.admission().as_ref()),
            admission_pointer
        );
        let readers = frozen.readers();
        assert!(readers.current().same_original(&current_reader));
        let mut undo = readers.undo().positions();
        let position = undo.try_next(|_| Ok::<_, ()>(())).unwrap().unwrap();
        let (key, value) = readers
            .undo()
            .resolve(&position, |_| Ok::<_, ()>(()))
            .unwrap();
        assert_eq!(*key, 1);
        assert_eq!(value.as_ref().unwrap().as_ptr(), before_pointer);
        drop((position, undo, readers, current_reader));
        let original = frozen
            .try_into_detached()
            .unwrap_or_else(|_| panic!("same intact pair after current retirement"));
        assert_eq!(original.get(&1).unwrap().as_ptr(), current_pointer);
        assert_eq!(
            original.get_before_block(&1).unwrap().as_ptr(),
            before_pointer
        );
        assert_eq!(original.publication_identity(), identity);
        assert_eq!(
            std::ptr::from_ref(original.admission().as_ref()),
            admission_pointer
        );
    });
}

#[test]
fn frozen_pair_readers_reject_equal_foreign_work_and_stale_predecessor_publication() {
    let target: Storage<_, _> = [(1, 10_u64), (2, 20)].into_iter().collect();
    let foreign: Storage<_, _> = [(1, 10_u64), (2, 20)].into_iter().collect();
    let first = target
        .block()
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap()
        .freeze_pair();
    let second = target
        .block()
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap()
        .freeze_pair();
    let foreign_pair = foreign
        .block()
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap()
        .freeze_pair();
    let identity = first.publication_identity();
    assert_eq!(identity, second.publication_identity());
    assert_ne!(identity, foreign_pair.publication_identity());
    assert!(!first.belongs_to(&foreign));
    let readers = first.readers();
    let second_readers = second.readers();
    let foreign_readers = foreign_pair.readers();
    assert!(!readers.same_original(&second_readers));
    assert!(!readers.same_original(&foreign_readers));
    let mut current = readers.current().positions();
    let position = current.try_next(|_| Ok::<_, ()>(())).unwrap().unwrap();
    without_allocations(|| {
        assert!(matches!(
            second_readers
                .current()
                .resolve(&position, |_| Err::<(), _>("must not admit a foreign path")),
            Err(RowPositionError::ForeignOwner)
        ));
        assert!(matches!(
            foreign_readers
                .current()
                .resolve(&position, |_| Err::<(), _>("must not admit a foreign path")),
            Err(RowPositionError::ForeignOwner)
        ));
    });
    let pointer = std::ptr::from_ref(
        readers
            .current()
            .resolve(&position, |_| Ok::<_, ()>(()))
            .unwrap()
            .1,
    );
    drop((
        position,
        current,
        readers,
        second_readers,
        foreign_readers,
        second,
        foreign_pair,
    ));
    target.block().commit();
    assert!(!first.matches_current(&target));
    let original = first
        .try_into_detached()
        .unwrap_or_else(|_| panic!("readers retired"));
    let (original, refusal, cleanup) = match original.try_prepare_publication(&target, |_, _| {
        Err::<(), _>("must reject stale predecessor before admission")
    }) {
        Err(error) => error,
        Ok(_) => panic!("equal values cannot replace original predecessor authority"),
    };
    assert_eq!(refusal, PublicationPreparationError::Changed);
    assert_eq!(original.publication_identity(), identity);
    assert_eq!(std::ptr::from_ref(original.get(&1).unwrap()), pointer);
    drop(cleanup);
}

#[test]
fn frozen_pair_work_refusal_retains_successful_prefix_and_both_original_maps() {
    let target: Storage<_, _> = [(1, 10_u64), (2, 20)].into_iter().collect();
    let original = target.block().try_detach(|_| Ok::<_, ()>(())).unwrap();
    without_allocations(|| {
        let frozen = original.freeze_pair();
        let readers = frozen.readers();
        let mut current = readers.current().positions();
        let mut work = 0_usize;
        let first = current
            .try_next(|bound| {
                work += bound;
                Ok::<_, u8>(())
            })
            .unwrap()
            .unwrap();
        let successful_prefix = work;
        assert!(successful_prefix > 0);
        assert!(matches!(
            current.try_next(|bound| {
                work += bound;
                Err::<(), _>(17_u8)
            }),
            Err(RowPositionError::Work(17))
        ));
        assert!(work > successful_prefix);
        let refused_work = work;
        let frozen = match frozen.try_into_detached() {
            Err(original) => original,
            Ok(_) => panic!("completed positions retain original current work"),
        };
        assert!(readers.same_original(&frozen.readers()));
        let second = current
            .try_next(|bound| {
                work += bound;
                Ok::<_, u8>(())
            })
            .unwrap()
            .unwrap();
        assert!(work > refused_work);
        assert_eq!(
            *readers
                .current()
                .resolve(&first, |_| Ok::<_, ()>(()))
                .unwrap()
                .0,
            1
        );
        assert_eq!(
            *readers
                .current()
                .resolve(&second, |_| Ok::<_, ()>(()))
                .unwrap()
                .0,
            2
        );
        drop((first, second, current, readers));
        assert!(frozen.try_into_detached().is_ok());
    });
}
