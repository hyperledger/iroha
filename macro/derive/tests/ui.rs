use trybuild::TestCases;

#[test]
fn from_variant_ui() {
    let test_cases = TestCases::new();
    test_cases.pass("tests/ui_pass/from_variant/*.rs");
    test_cases.compile_fail("tests/ui_fail/from_variant/*.rs");
}

#[cfg(feature = "dump_decoded")]
#[test]
fn dump_decoded_ui() {
    let test_cases = TestCases::new();
    test_cases.pass("tests/ui_pass/dump_decoded/*.rs");
    test_cases.compile_fail("tests/ui_fail/dump_decoded/*.rs");
}
