//! Published undo, stale allocation, same-value ABA and actual release custody.

use super::*;

#[test]
fn committed_pair_preserves_previous_undo_when_ordinary_overlay_clears_it() {
    let cell = Cell::new(10_u64);
    let mut first = cell.block();
    *first.get_mut() = 20;
    first.commit();
    let captured = cell.try_committed_view().unwrap();
    assert_eq!((*captured.current(), *captured.undo()), (20, Some(10)));
    let mut ordinary = cell.block();
    assert_eq!(ordinary.original_undo(), &None);
    assert!(captured.matches_block_source(&ordinary));
    *ordinary.get_mut() = 30;
    assert_eq!(ordinary.original_undo(), &Some(20));
    assert_eq!((*captured.current(), *captured.undo()), (20, Some(10)));
    assert!(captured.matches_block_source(&ordinary));
    drop(ordinary);
    assert!(captured.same_publication(&cell.try_committed_view().unwrap()));
}

#[test]
fn replacement_source_preserves_committed_pair_and_distinct_nested_absence() {
    let cell = Cell::new(None::<u64>);
    let empty = cell.try_committed_view().unwrap();
    assert_eq!(empty.undo(), &None);
    let mut first = cell.block();
    *first.get_mut() = Some(7);
    first.commit();
    let committed = cell.try_committed_view().unwrap();
    assert_eq!(committed.current(), &Some(7));
    assert_eq!(committed.undo(), &Some(None));
    let replacement = cell.block_and_revert();
    assert_eq!(replacement.get(), &None);
    assert!(committed.matches_block_source(&replacement));
    assert!(!empty.matches_block_source(&replacement));
    assert_eq!(committed.current(), &Some(7));
}

#[test]
fn foreign_and_same_value_republication_never_restore_original_identity() {
    let cell = Cell::new(9_u64);
    let other = Cell::new(9_u64);
    let captured = cell.try_committed_view().unwrap();
    assert!(!captured.same_publication(&other.try_committed_view().unwrap()));
    assert!(!captured.matches_block_source(&other.block()));
    cell.replace_current_preserving_predecessor(9);
    assert!(!captured.same_publication(&cell.try_committed_view().unwrap()));
    assert!(!captured.matches_block_source(&cell.block()));
    assert_eq!(captured.current(), &9);
}

#[test]
fn changed_current_or_undo_read_cannot_form_a_committed_pair() {
    let cell = Cell::new(10_u64);
    let current = cell.blocks.read();
    let undo = cell.revert.read();
    let mut next = cell.block();
    *next.get_mut() = 20;
    next.commit();
    assert!(matches!(
        cell.capture_committed_reads(current, cell.revert.read()),
        Err(CommittedCellReadError::Publication(
            PublicationPreparationError::Changed
        ))
    ));
    assert!(matches!(
        cell.capture_committed_reads(cell.blocks.read(), undo),
        Err(CommittedCellReadError::Publication(
            PublicationPreparationError::Changed
        ))
    ));
}

#[test]
fn concurrent_publication_never_returns_a_mixed_current_undo_pair() {
    let cell = Cell::new(0_u64);
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| {
            for value in 1..=128 {
                let mut block = cell.block();
                *block.get_mut() = value;
                block.commit();
            }
        });
        for _ in 0..256 {
            match cell.try_committed_view() {
                Ok(pair) => {
                    let current = *pair.current();
                    assert_eq!(*pair.undo(), current.checked_sub(1));
                }
                Err(CommittedCellReadError::Publication(
                    PublicationPreparationError::Changed | PublicationPreparationError::Busy(_),
                )) => {}
                Err(error) => panic!("unexpected original read failure: {error:?}"),
            }
        }
        writer.join().unwrap();
    });
    let final_pair = cell.try_committed_view().unwrap();
    assert_eq!(
        (*final_pair.current(), *final_pair.undo()),
        (128, Some(127))
    );
}

#[test]
fn empty_payload_retains_exact_current_and_undo_allocations() {
    let cell = Cell::new(());
    let foreign = Cell::new(());
    let first = cell.try_committed_view().unwrap();
    let foreign_read = foreign.try_committed_view().unwrap();
    assert!(!std::ptr::eq(first.current(), foreign_read.current()));
    assert_eq!(*first.undo(), None);
    assert!(!first.same_publication(&foreign_read));
    let block = cell.block();
    assert!(first.matches_block_source(&block));
    block.commit();
    let untouched = cell.try_committed_view().unwrap();
    assert!(!first.same_publication(&untouched));
    assert!(std::ptr::eq(first.current(), untouched.current()));
    assert!(!std::ptr::eq(first.undo(), untouched.undo()));
    let mut block = cell.block();
    assert!(untouched.matches_block_source(&block));
    *block.get_mut() = ();
    block.commit();
    let second = cell.try_committed_view().unwrap();
    assert!(!first.same_publication(&second));
    assert!(!std::ptr::eq(first.current(), second.current()));
    assert!(!first.matches_block_source(&cell.block()));
    assert_eq!(*first.undo(), None);
}
