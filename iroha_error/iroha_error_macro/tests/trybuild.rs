use trybuild::TestCases;

#[test]
fn test_error() {
    let pass = ["01-basic-test", "03-unnamed-field-variant"];
    let fail = ["02-fail-debug"];
    let to_test = |test| format!("tests/error/{}.rs", test);

    let t = TestCases::new();

    pass.iter().map(to_test).for_each(|test| t.pass(test));
    fail.iter()
        .map(to_test)
        .for_each(|test| t.compile_fail(test));
}
