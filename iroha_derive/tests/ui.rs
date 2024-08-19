#![cfg(not(coverage))]
use trybuild::TestCases;

#[test]
fn ui() {
    let test_cases = TestCases::new();
    test_cases.pass("tests/ui_pass/*.rs");
    test_cases.compile_fail("tests/ui_fail/*.rs");
}
