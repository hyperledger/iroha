#![cfg(not(coverage))]
use trybuild::TestCases;

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn ui() {
    let test_cases = TestCases::new();
    test_cases.compile_fail("tests/ui_fail/*.rs");
}
