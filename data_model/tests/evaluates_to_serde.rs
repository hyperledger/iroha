#![cfg(not(coverage))]
use trybuild::TestCases;

#[test]
fn evaluates_to_ser_deser_check() {
    TestCases::new().pass("tests/evaluates_to_serde_pass/*.rs");
    TestCases::new().compile_fail("tests/evaluates_to_serde_fail/*.rs");
}