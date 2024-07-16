#![cfg(not(coverage))]
#![cfg(not(target_arch = "wasm32"))]

use trybuild::TestCases;

#[test]
fn ui() {
    let test_cases = TestCases::new();
    test_cases.compile_fail("tests/ui_fail/*.rs");
}
