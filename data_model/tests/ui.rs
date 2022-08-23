#![cfg(not(coverage))]
use trybuild::TestCases;

#[test]
fn ui() {
    TestCases::new().compile_fail("tests/ui_fail/*.rs");
}
