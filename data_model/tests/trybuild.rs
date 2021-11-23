use trybuild::TestCases;

#[test]
fn trybuild() {
    TestCases::new().compile_fail("tests/fail_to_compile/*.rs");
}
