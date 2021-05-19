use trybuild::TestCases;

#[test]
fn trybuild() {
    let test_cases = TestCases::new();
    test_cases.pass("tests/ok/*.rs");
    test_cases.compile_fail("tests/fail/*.rs");
}
