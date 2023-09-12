use std::fmt::Formatter;

use iroha_data_model_derive::{PartiallyTaggedDeserialize, PartiallyTaggedSerialize};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

#[allow(variant_size_differences)] // it's a test, duh
#[derive(Debug, PartialEq, Eq, PartiallyTaggedDeserialize, PartiallyTaggedSerialize)]
enum Value {
    Bool(bool),
    String(String),
    #[serde_partially_tagged(untagged)]
    Numeric(NumericValue),
}

// a simpler version of NumericValue than used in data_model
// this one is always i32, but is still serialized as a string literal
// NOTE: debug is actually required for `PartiallyTaggedDeserialize`!
#[derive(Debug, PartialEq, Eq)]
struct NumericValue(i32);

impl Serialize for NumericValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

struct NumericValueVisitor;

impl de::Visitor<'_> for NumericValueVisitor {
    type Value = NumericValue;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("a string literal containing a number")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let parsed = v.parse::<i32>().map_err(|e| E::custom(e))?;

        Ok(NumericValue(parsed))
    }
}

impl<'de> Deserialize<'de> for NumericValue {
    fn deserialize<D>(deserializer: D) -> Result<NumericValue, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(NumericValueVisitor)
    }
}

#[test]
fn partially_tagged_serde() {
    let values = [
        Value::Bool(true),
        Value::String("I am string".to_owned()),
        Value::Numeric(NumericValue(42)),
    ];
    let serialized_values = [r#"{"Bool":true}"#, r#"{"String":"I am string"}"#, r#""42""#];

    for (value, serialized_value) in values.iter().zip(serialized_values.iter()) {
        let serialized = serde_json::to_string(value)
            .unwrap_or_else(|e| panic!("Failed to serialize `{:?}`: {:?}", value, e));
        assert_eq!(
            serialized, *serialized_value,
            "Serialized form of `{:?}` does not match the expected value",
            value
        );
        let deserialized: Value = serde_json::from_str(serialized_value)
            .unwrap_or_else(|e| panic!("Failed to deserialize `{:?}`: {:?}", serialized_value, e));
        assert_eq!(
            *value, deserialized,
            "Deserialized form of `{:?}` does not match the expected value",
            value
        );
    }
}
