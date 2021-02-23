#[cfg(test)]
mod tests {
    use trybuild::TestCases;

    #[test]
    fn ui() {
        let test_cases = TestCases::new();
        test_cases.pass("tests/ui/ok_*.rs");
        test_cases.compile_fail("tests/ui/fail_*.rs");
    }
}
