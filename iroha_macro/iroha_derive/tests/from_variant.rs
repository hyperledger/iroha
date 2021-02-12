#[cfg(test)]
mod tests {
    use trybuild::TestCases;

    #[test]
    fn test_from_variant() {
        let pass = ["01-big-enum", "03-container-enums"];
        let fail = ["02-double-from", "04-container-from", "05-struct"];
        let to_test = |test| format!("tests/from_variant/{}.rs", test);

        let t = TestCases::new();

        pass.iter().map(to_test).for_each(|test| t.pass(test));
        fail.iter()
            .map(to_test)
            .for_each(|test| t.compile_fail(test));
    }
}
