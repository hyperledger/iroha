//! Original paired readers must retire before the same field can publish.

use super::super::*;
use crate::test_allocations::allocations_during;
use mv::storage::{Storage, StorageReadOnly};

#[test]
fn retained_field_readers_and_positions_refuse_thaw_without_a_writer_wait() {
    for mode in [mv::BlockMode::Ordinary, mv::BlockMode::Replace] {
        let target =
            Storage::<u64, String>::from_iter([(1, "before".into()), (2, "untouched".into())]);
        if mode == mv::BlockMode::Replace {
            let mut tip = target.block();
            tip.insert(1, "tip".into());
            tip.commit();
        }
        let mut field = BlockField::new(if mode == mv::BlockMode::Ordinary {
            target.block()
        } else {
            target.block_and_revert()
        });
        field.insert(1, "after".into());
        field.remove(2);
        field.insert(3, "new".into());
        let identity = field.publication_identity();
        let pointer = field.get(&1).unwrap().as_ptr();
        assert!(field.retain_original_readers().is_none());
        field.begin_freeze();
        field.finish_freeze();
        field.retire_frozen_cleanup();
        let allocations = allocations_during(|| {
            let source = field.retain_original_readers().unwrap();
            assert_eq!(*source.publication_identity(), identity);
            assert!(field.retained_read_matches_source(&source));
            let mut positions = source.current().positions();
            let position = positions.try_next(|_| Ok::<_, ()>(())).unwrap().unwrap();
            assert_eq!(
                source
                    .current()
                    .resolve(&position, |_| Ok::<_, ()>(()))
                    .unwrap()
                    .1
                    .as_ptr(),
                pointer
            );
            let second = positions.try_next(|_| Ok::<_, ()>(())).unwrap().unwrap();
            assert_eq!(
                *source
                    .current()
                    .resolve(&second, |_| Ok::<_, ()>(()))
                    .unwrap()
                    .0,
                3
            );
            assert!(positions.try_next(|_| Ok::<_, ()>(())).unwrap().is_none());
            let mut undo = source.undo().positions();
            for expected in [1, 2, 3] {
                let row = undo.try_next(|_| Ok::<_, ()>(())).unwrap().unwrap();
                let (key, value) = source.undo().resolve(&row, |_| Ok::<_, ()>(())).unwrap();
                assert_eq!(*key, expected);
                assert_eq!(value.is_none(), expected == 3);
            }
            assert!(undo.try_next(|_| Ok::<_, ()>(())).unwrap().is_none());
            drop((second, undo));
            assert!(field.frozen_images().is_none());
            assert_eq!(field.retained_read_matches_current(&target), Some(true));
            assert_eq!(
                field.try_retire_original_readers(),
                Err(RetainedReadPhaseError::ReadersRetained)
            );
            let repeated = field.retain_original_readers().unwrap();
            assert!(source.same_original(&repeated));
            // Successful undo thaw followed by current refusal refreezes that same
            // pair. The remaining original position, not a lock, owns the refusal.
            drop((source, repeated, positions));
            assert_eq!(
                field.try_retire_original_readers(),
                Err(RetainedReadPhaseError::ReadersRetained)
            );
            drop(position);
            field.try_retire_original_readers().unwrap();
            assert_eq!(
                field.frozen_images().unwrap().publication_identity(),
                identity
            );
            assert_eq!(field.get(&1).unwrap().as_ptr(), pointer);
        });
        assert_eq!(allocations, 0);
        // Exact original predecessor validation still runs in the sole writer path.
        field
            .begin_frozen_publication(|original| {
                Ok::<_, (mv::storage::Detached<u64, String, ()>, ())>(
                    mv::storage::BlockPublicationSlot::from_frozen(original, &target),
                )
            })
            .unwrap();
        field.try_prepare_frozen_publication().unwrap();
        field.publish_prepared();
        assert_eq!(target.view().get(&1).map(String::as_str), Some("after"));
    }
}

#[test]
fn retained_field_readers_reject_changed_equal_predecessor_and_terminal_release() {
    let target = Storage::<u64, String>::from_iter([(1, "same".into())]);
    let mut field = BlockField::new(target.block());
    field.insert(1, "pending".into());
    field.begin_freeze();
    field.finish_freeze();
    field.retire_frozen_cleanup();
    let source = field.retain_original_readers().unwrap();
    let foreign_target = Storage::<u64, String>::from_iter([(1, "pending".into())]);
    let mut foreign_field = BlockField::new(foreign_target.block());
    foreign_field.begin_freeze();
    foreign_field.finish_freeze();
    foreign_field.retire_frozen_cleanup();
    let foreign_source = foreign_field.retain_original_readers().unwrap();
    assert!(!field.retained_read_matches_source(&foreign_source));
    assert!(field.retained_read_matches_source(&source));
    drop(foreign_source);
    foreign_field.try_retire_original_readers().unwrap();
    let mut equal = target.block();
    equal.insert(1, "same".into());
    equal.commit();
    assert_eq!(field.retained_read_matches_current(&target), Some(false));
    let repeated = field.retain_original_readers().unwrap();
    assert!(source.same_original(&repeated));
    field.release_writers();
    assert!(field.retain_original_readers().is_none());
    assert_eq!(field.retained_read_matches_current(&target), None);
    assert_eq!(
        field.try_retire_original_readers(),
        Err(RetainedReadPhaseError::NotFrozen)
    );
    drop((source, repeated));
}

#[test]
fn retained_cell_original_pair_reads_and_partial_thaw_preserve_exact_values_and_cut() {
    use mv::cell::Cell;
    for mode in [mv::BlockMode::Ordinary, mv::BlockMode::Replace] {
        for hold_current in [false, true] {
            let target = Cell::<String>::new("before".into());
            if mode == mv::BlockMode::Replace {
                let mut tip = target.block();
                *tip.get_mut() = "tip".into();
                tip.commit();
            }
            let mut field = BlockField::new(if mode == mv::BlockMode::Ordinary {
                target.block()
            } else {
                target.block_and_revert()
            });
            *field.get_mut() = "after".into();
            let current = std::ptr::from_ref(field.get());
            let undo = std::ptr::from_ref(field.original_undo());
            let before = std::ptr::from_ref(field.get_before_block());
            let identity = field.publication_identity();
            assert!(field.retain_original_readers().is_none());
            assert!(field.frozen_values().is_none());
            field.begin_freeze();
            assert!(field.retain_original_readers().is_none());
            assert!(field.frozen_values().is_none());
            field.finish_freeze();
            field.retire_frozen_cleanup();
            let allocations = allocations_during(|| {
                let source = field.retain_original_readers().unwrap();
                let held_current = hold_current.then(|| source.current().clone());
                let held_undo = (!hold_current).then(|| source.undo().clone());
                assert_eq!(source.publication_identity(), &identity);
                assert!(field.retained_read_matches_source(&source));
                assert_eq!(field.retained_read_matches_current(&target), Some(true));
                assert!(field.belongs_to(&target));
                assert_eq!(field.mode(), mode);
                assert!(field.is_dirty());
                let touched = field.touched_value().unwrap();
                assert_eq!(std::ptr::from_ref(touched.before), before);
                assert_eq!(std::ptr::from_ref(touched.after), current);
                assert_eq!(std::ptr::from_ref(field.get()), current);
                assert_eq!(std::ptr::from_ref(field.original_undo()), undo);
                let (actual, original) = field.frozen_values().unwrap();
                assert_eq!(std::ptr::from_ref(actual), current);
                assert_eq!(std::ptr::from_ref(original), before);
                drop(source);
                for _ in 0..3 {
                    assert_eq!(
                        field.try_retire_original_readers(),
                        Err(RetainedReadPhaseError::ReadersRetained)
                    );
                    let retry = field.retain_original_readers().unwrap();
                    assert!(field.retained_read_matches_source(&retry));
                    assert_eq!(std::ptr::from_ref(field.get()), current);
                    assert_eq!(std::ptr::from_ref(field.original_undo()), undo);
                    assert_eq!(field.publication_identity(), identity);
                }
                drop((held_current, held_undo));
                field.try_retire_original_readers().unwrap();
                assert_eq!(std::ptr::from_ref(field.get()), current);
                assert_eq!(std::ptr::from_ref(field.original_undo()), undo);
            });
            assert_eq!(
                allocations, 0,
                "original immutable pair and partial thaw add no backing"
            );
            field.install_frozen_publication(&target).unwrap();
            assert!(field.frozen_values().is_none());
            field.try_prepare_frozen_publication().unwrap();
            field.publish_prepared();
            assert_eq!(target.view().get(), "after");
        }
    }
}

#[test]
fn retained_cell_equal_same_predecessor_foreign_and_terminal_readers_refuse_substitution() {
    use mv::cell::Cell;
    let target = Cell::<u64>::new(1);
    let mut field = BlockField::new(target.block());
    *field.get_mut() = 2;
    field.begin_freeze();
    field.finish_freeze();
    field.retire_frozen_cleanup();
    let source = field.retain_original_readers().unwrap();
    let mut equal = BlockField::new(target.block());
    *equal.get_mut() = 2;
    equal.begin_freeze();
    equal.finish_freeze();
    equal.retire_frozen_cleanup();
    let equal_source = equal.retain_original_readers().unwrap();
    assert_eq!(field.publication_identity(), equal.publication_identity());
    assert_eq!(field.frozen_values(), equal.frozen_values());
    assert!(!field.retained_read_matches_source(&equal_source));
    assert!(!equal.retained_read_matches_source(&source));
    let foreign = Cell::<u64>::new(1);
    let mut foreign_field = BlockField::new(foreign.block());
    *foreign_field.get_mut() = 2;
    foreign_field.begin_freeze();
    foreign_field.finish_freeze();
    foreign_field.retire_frozen_cleanup();
    let foreign_source = foreign_field.retain_original_readers().unwrap();
    assert!(!field.retained_read_matches_source(&foreign_source));
    assert!(field.retained_read_matches_source(&source));
    drop((foreign_source, equal_source));
    foreign_field.try_retire_original_readers().unwrap();
    equal.try_retire_original_readers().unwrap();
    target.block().commit();
    assert_eq!(field.retained_read_matches_current(&target), Some(false));
    assert!(field.retained_read_matches_source(&source));
    field.release_writers();
    assert!(field.frozen_values().is_none());
    assert!(field.retain_original_readers().is_none());
    assert!(!field.retained_read_matches_source(&source));
    assert_eq!(field.retained_read_matches_current(&target), None);
    assert_eq!(
        field.try_retire_original_readers(),
        Err(RetainedReadPhaseError::NotFrozen)
    );
}
