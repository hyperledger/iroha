//! String containing serialized valid JSON.
//! This string is guaranteed to parse as JSON

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
// use core::str::FromStr;
#[cfg(feature = "std")]
use std::{
    string::{String, ToString},
    vec::Vec,
};

use derive_more::Display;
use iroha_schema::{IntoSchema, Metadata, TypeId};
use parity_scale_codec::{Decode, Encode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

/// A newtype of [`serde_json::Value`] with the following features:
///
/// - Delegates [`Serialize`]/[`Deserialize`] to the [`Value`] itself
/// - Delegates [`Encode`]/[`Decode`] to the JSON-serialized string of [`Value`]
/// - Delegates [`PartialOrd`]/[`Ord`]/[`PartialEq`]/[`Eq`] to the JSON-serialized string of [`Value`]
///
/// It is a core type in the schema, i.e. SDKs should handle it as a special case.
///
/// It **should not be** wrapped into [`Option`], as its [`None`] value overlaps with [`Value::Null`] in JSON (both are `null`).
/// Use [`JsonValueWrap`]  with [`Option`] instead.
#[derive(Debug, Display, Clone, Serialize, TypeId)]
#[display(fmt = "{value}")]
#[serde(transparent)]
pub struct JsonValue {
    value: Value,
    #[serde(skip)]
    stringified: String,
}

impl JsonValue {
    /// Construct from [`serde_json::Value`]
    pub fn from_value(value: Value) -> Self {
        let string = value.to_string();
        Self {
            value,
            stringified: string,
        }
    }

    /// Construct from a JSON string, ensuring it is a valid JSON.
    ///
    /// While this method parses the string into [`Value`], it **guarantees** that
    /// the original string is used for encoding, ord/eq impls, and is returned from [`Self::as_str`].
    pub fn from_string(raw: impl Into<String>) -> serde_json::Result<Self> {
        let stringified = raw.into();
        let value = serde_json::from_str(&stringified)?;
        Ok(Self { value, stringified })
    }

    /// Borrow the value itself
    pub fn get(&self) -> &Value {
        &self.value
    }

    /// Consume the container and own the actual [`Value`].
    pub fn into_value(self) -> Value {
        self.value
    }

    /// Essentially a chaining shortcut for [`serde_json::from_value`].
    pub fn try_into_any<T: DeserializeOwned>(self) -> serde_json::Result<T> {
        serde_json::from_value(self.value)
    }

    /// Borrow the string representation of the value
    pub fn as_str(&self) -> &str {
        &self.stringified
    }
}

// Note: need a custom impl so that `stringified` is filled on deserialization
impl<'de> Deserialize<'de> for JsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        Ok(Self::from_value(value))
    }
}

impl IntoSchema for JsonValue {
    fn type_name() -> iroha_schema::Ident {
        Self::id()
    }

    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(Metadata::JsonValue);
        }
    }
}

/// [`Value::Null`]
impl Default for JsonValue {
    fn default() -> Self {
        Self::from_value(Value::Null)
    }
}

impl<T> From<T> for JsonValue
where
    T: Into<Value>,
{
    fn from(value: T) -> Self {
        Self::from_value(value.into())
    }
}

impl Encode for JsonValue {
    fn encode_to<T: parity_scale_codec::Output + ?Sized>(&self, dest: &mut T) {
        self.stringified.encode_to(dest)
    }

    fn size_hint(&self) -> usize {
        self.stringified.size_hint()
    }
}

impl Decode for JsonValue {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let string = String::decode(input)?;
        let value = serde_json::from_str(&string).map_err(|_err| {
            parity_scale_codec::Error::from(
                "Could not decode `JsonValue`: string is not a valid JSON",
            )
        })?;
        Ok(Self {
            value,
            stringified: string,
        })
    }
}

impl PartialEq for JsonValue {
    fn eq(&self, other: &Self) -> bool {
        self.stringified.eq(&other.stringified)
    }
}

impl Eq for JsonValue {}

impl PartialOrd for JsonValue {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.stringified.partial_cmp(&other.stringified)
    }
}

impl Ord for JsonValue {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.stringified.cmp(&other.stringified)
    }
}

/// A wrapper around [`JsonValue`] to workaround issues with ambiguous serialisation of `Option<JsonValue>`.
///
/// The ambiguity comes from the fact that both `None` and `Some(null)` are serialised as `null`. To solve it, use
/// `Option<JsonValueWrap>`, so that the difference is clear: `null` vs `{ "value": null }`
#[derive(
    Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, IntoSchema,
)]
pub struct JsonValueWrap {
    /// The wrapped value
    pub value: JsonValue,
}

#[cfg(test)]
mod tests {
    use core::cmp::Ordering;

    use parity_scale_codec::DecodeAll;
    use serde_json::json;

    use super::*;

    #[test]
    fn as_string_in_scale() {
        for (value, as_str) in [
            (json!([1, 5, 2]), "[1,5,2]"),
            (json!(null), "null"),
            (json!(55.23), "55.23"),
            (json!("i am data"), "\"i am data\""),
        ] {
            let expected_encoded_str = as_str.encode();

            let value_encoded = JsonValue::from_value(value.clone()).encode();
            assert_eq!(
                value_encoded, expected_encoded_str,
                "value {value:?} is not encoded as `{as_str}`"
            );

            let value_decoded = JsonValue::decode(&mut expected_encoded_str.as_slice())
                .expect("should decode fine");
            assert_eq!(value_decoded, JsonValue::from_value(value));
        }
    }

    #[test]
    fn as_value_in_json() {
        for input in [
            json!([1, 5, 2]),
            json!(null),
            json!(55.23),
            json!("i am data"),
        ] {
            let value = JsonValue::from_value(input.clone());
            let value_str = serde_json::to_string(&value).unwrap();
            assert_eq!(value_str, input.to_string());
        }
    }

    #[test]
    fn sorts_values_by_their_str_impls() {
        let input = vec![
            json!("Jack"),
            json!("Brown"),
            json!(412),
            json!(null),
            json!(["foo"]),
        ];

        let mut values: Vec<_> = input.into_iter().map(JsonValue::from_value).collect();
        values.sort();

        let values: Vec<_> = values.into_iter().map(|x| x.get().clone()).collect();
        assert_eq!(
            values,
            vec![
                json!("Brown"),
                json!("Jack"),
                json!(412),
                json!(["foo"]),
                json!(null),
            ]
        );
    }

    #[test]
    fn when_decoded_from_invalid_json_string() {
        let invalid_input = "i am not JSON".encode();

        let _err = JsonValue::decode(&mut invalid_input.as_slice())
            .expect_err("string is not a valid JSON");
    }

    #[test]
    fn when_constructed_from_str_original_string_is_preserved_for_encoding() {
        let source = "[1,    2, 3]";

        let value = JsonValue::from_string(source).expect("input is a valid json");
        let whitespace_differ = JsonValue::from_string("[1, 2,     3]").expect("also a valid json");

        assert_eq!(value.as_str(), source);
        assert_eq!(value.get(), &json!([1, 2, 3]));
        assert_ne!(value, whitespace_differ);
        assert_ne!(value.cmp(&whitespace_differ), Ordering::Equal);
    }

    #[test]
    fn serialize_deserialize_encode_decode() {
        let value = JsonValue::from_value(json!({ "foo": ["bar", false, 1234, null]}));

        let serialized = serde_json::to_string(&value).unwrap();
        assert_eq!(serialized, "{\"foo\":[\"bar\",false,1234,null]}");

        let deserialized: JsonValue = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, value);

        let encoded = deserialized.encode();
        let decoded = JsonValue::decode_all(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded, value);
    }
}
