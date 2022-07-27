use super::*;

mod display {
    use super::*;

    #[test]
    fn simple_expr_should_not_use_parentheses() {
        let left = Value::U32(5);
        let right = Value::U32(10);
        let mult = Multiply::new(left, right);

        assert_eq!(mult.to_string(), "5*10");
    }

    #[test]
    fn complex_expr_should_use_parentheses() {
        let left = Add::new(Value::U32(12), Value::U32(8));
        let right = Value::U32(10);
        let div = Divide::new(left, right);

        assert_eq!(div.to_string(), "(12+8)/10");
    }

    #[test]
    fn raise_to_expr_should_use_stars() {
        let left = Value::U32(2);
        let right = Value::U32(3);
        let pow = RaiseTo::new(left, right);

        assert_eq!(pow.to_string(), "2**3");
    }

    #[test]
    fn mod_expr_should_use_spaces() {
        let left = Value::U32(5);
        let right = Value::U32(2);
        let mod_expr = Mod::new(left, right);

        assert_eq!(mod_expr.to_string(), "5 % 2");
    }

    #[test]
    fn method_argument_should_have_exactly_one_pair_of_parentheses() {
        let collection = Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)]);

        let simple_element = Value::U32(2);
        let simple_call = Contains::new(collection.clone(), simple_element);
        // This looks odd.
        // Like we are trying to search for a number in a collection of strings
        assert_eq!(simple_call.to_string(), "[\"1\", \"2\", \"3\"].contains(2)");

        let complex_element = Subtract::new(Value::U32(10), Value::U32(7));
        let complex_call = Contains::new(collection, complex_element);
        assert_eq!(
            complex_call.to_string(),
            "[\"1\", \"2\", \"3\"].contains(10-7)"
        );
    }
}
