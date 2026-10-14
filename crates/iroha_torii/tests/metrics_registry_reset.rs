//! Smoke test for the shared metrics registry wiring used by Torii test suites.
use std::sync::Arc;
#[path = "fixtures.rs"]
mod fixtures;
#[test]
fn shared_metrics_can_be_reset_for_clean_suites() {
    let first = fixtures::reset_shared_metrics();
    first.block_height.inc();
    assert_eq!(first.block_height.get(), 1);
    let second = fixtures::reset_shared_metrics();
    assert!(!Arc::ptr_eq(&first, &second), "registry should be swapped");
    assert_eq!(second.block_height.get(), 0);
    second.block_height.inc();
    assert_eq!(second.block_height.get(), 1);
}
