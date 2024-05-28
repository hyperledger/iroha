#![cfg(not(coverage))]
use trybuild::TestCases;

#[test]
fn ui() {
    let test_cases = TestCases::new();
    test_cases.compile_fail("tests/ui_fail/*.rs");
}
