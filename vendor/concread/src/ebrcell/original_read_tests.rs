//! Original protected allocation identity without another collector pin.

use super::EbrCell;

#[test]
fn original_read_identity_rejects_foreign_and_equal_value_republication() {
    let source = EbrCell::new(7_u64);
    let foreign = EbrCell::new(7_u64);
    let first = source.read();
    assert!(source.matches_read(&first));
    assert!(!foreign.matches_read(&first));
    let writer = source.write();
    assert!(
        source.matches_read(&first),
        "unpublished writers are not current"
    );
    writer.commit();
    assert_eq!(*first, 7, "the exact old allocation remains borrowed");
    assert!(
        !source.matches_read(&first),
        "equal payload cannot restore identity"
    );
    assert!(source.matches_read(&source.read()));
}

#[test]
fn empty_payload_uses_unique_original_allocated_header() {
    let source = EbrCell::new(());
    let foreign = EbrCell::new(());
    assert!(EbrCell::<()>::allocation_layout().size() > 0);
    let original = source.read();
    assert!(source.matches_read(&original));
    assert!(!foreign.matches_read(&original));
    source.write().commit();
    assert!(!source.matches_read(&original));
    assert!(source.matches_read(&source.read()));
}
