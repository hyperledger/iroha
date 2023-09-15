//! A test for `PartiallyTaggedSerialize` and `PartiallyTaggedDeserialize` which uses `Self` as a type

use iroha_data_model_derive::{PartiallyTaggedDeserialize, PartiallyTaggedSerialize};

#[derive(Debug, PartialEq, Eq, PartiallyTaggedSerialize, PartiallyTaggedDeserialize)]
enum Expr<T> {
    Negate(Box<Self>),
    #[serde_partially_tagged(untagged)]
    Atom(T),
}

#[test]
fn partially_tagged_serde() {
    use Expr::*;

    let values = [
        Atom(42),
        Negate(Box::new(Atom(42))),
        Negate(Box::new(Negate(Box::new(Atom(42))))),
    ];
    let serialized_values = [r#"42"#, r#"{"Negate":42}"#, r#"{"Negate":{"Negate":42}}"#];

    for (value, serialized_value) in values.iter().zip(serialized_values.iter()) {
        let serialized = serde_json::to_string(value)
            .unwrap_or_else(|e| panic!("Failed to serialize `{:?}`: {:?}", value, e));
        assert_eq!(
            serialized, *serialized_value,
            "Serialized form of `{:?}` does not match the expected value",
            value
        );
        let deserialized: Expr<i32> = serde_json::from_str(serialized_value)
            .unwrap_or_else(|e| panic!("Failed to deserialize `{:?}`: {:?}", serialized_value, e));
        assert_eq!(
            *value, deserialized,
            "Deserialized form of `{:?}` does not match the expected value",
            value
        );
    }
}
