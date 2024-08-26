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
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

/// A valid `JsonString` that consists of valid String of Json type
#[derive(Debug, Display, Clone, PartialOrd, PartialEq, Ord, Eq, IntoSchema, Encode, Decode)]
#[display(fmt = "{_0}")]
pub struct JsonString(String);

impl JsonString {
    /// Constructs [`JsonString`]
    /// # Errors
    ///
    /// - Serialization can fail if T's implementation of Serialize decides to fail,
    /// - or if T contains a map with non-string keys.
    // Todo: Doesn't remove extra spaces in if `&str` is an object
    pub fn new<T: Serialize>(payload: T) -> Self {
        candidate::JsonCandidate::new(payload).try_into().unwrap()
    }

    /// Tries cast [`JsonString`] to any value.
    ///
    /// # Errors
    /// - if invalid representation of `T`
    pub fn try_into_any<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_str(&self.0)
    }

    /// Create without checking whether the input is a valid JSON string.
    ///
    /// The caller must guarantee that the value is valid.
    pub fn from_string_unchecked(value: String) -> Self {
        Self(value)
    }

    /// Getter for [`JsonString`]
    pub fn get(&self) -> &String {
        &self.0
    }
}

const JSON_EXPECTED_HINT: &str = "expected either a string with valid JSON (e.g. `\"null\"` or `\"42\"`) \
                                  or an object with inlined JSON value (i.e. `{{ \"__inline__\": ... }}`)";

impl<'de> serde::de::Deserialize<'de> for JsonString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Candidate {
            String(String),
            Inline {
                #[serde(rename = "__inline__")]
                inline: Value,
            },
        }

        let candidate = Candidate::deserialize(deserializer)
            .map_err(|_err| serde::de::Error::custom(JSON_EXPECTED_HINT))?;

        match candidate {
            Candidate::String(x) => {
                let value: Value = serde_json::from_str(&x).map_err(|_err| {
                    serde::de::Error::custom(format!(
                        "string is not a valid JSON - {}",
                        JSON_EXPECTED_HINT
                    ))
                })?;
                Ok(Self(value.to_string()))
            }
            Candidate::Inline { inline } => Ok(Self(inline.to_string())),
        }
    }
}

impl serde::ser::Serialize for JsonString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl From<&Value> for JsonString {
    fn from(value: &Value) -> Self {
        JsonString(value.to_string())
    }
}

impl From<Value> for JsonString {
    fn from(value: Value) -> Self {
        JsonString(value.to_string())
    }
}

impl From<u32> for JsonString {
    fn from(value: u32) -> Self {
        JsonString::new(value)
    }
}

impl From<u64> for JsonString {
    fn from(value: u64) -> Self {
        JsonString::new(value)
    }
}

impl From<f64> for JsonString {
    fn from(value: f64) -> Self {
        JsonString::new(value)
    }
}

impl From<bool> for JsonString {
    fn from(value: bool) -> Self {
        JsonString::new(value)
    }
}

impl<T: Into<JsonString> + Serialize> From<Vec<T>> for JsonString {
    fn from(value: Vec<T>) -> Self {
        JsonString::new(value)
    }
}

impl Default for JsonString {
    fn default() -> Self {
        // NOTE: empty string isn't valid JSON
        Self("null".to_string())
    }
}

impl AsRef<str> for JsonString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

mod candidate {
    use super::*;

    /// A candidate for a valid `JsonString`.
    /// Is used for generalizing ser/de any types to `JsonString` and vise versa
    #[derive(Serialize, Deserialize, Clone)]
    pub(super) struct JsonCandidate<T>(T);

    impl<T: Serialize> JsonCandidate<T> {
        pub(super) fn new(value: T) -> Self {
            JsonCandidate(value)
        }
    }

    impl<T: Serialize> TryFrom<JsonCandidate<T>> for JsonString {
        type Error = serde_json::Error;
        fn try_from(value: JsonCandidate<T>) -> Result<Self, Self::Error> {
            Ok(JsonString(serde_json::to_string(&value.0)?))
        }
    }
}

#[cfg(test)]
mod tests {
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
            let actual = JsonString::new(value.clone()).encode();
            let actual_str =
                String::decode(&mut actual.as_slice()).expect("should be encoded as a string");
            assert_eq!(
                actual_str, as_str,
                "expected value {value:?} to be encoded as string `{as_str}`"
            );
        }
    }

    #[test]
    fn as_string_in_json() {
        for (value, as_str) in [
            (json!([1, 5, 2]), "[1,5,2]"),
            (json!(null), "null"),
            (json!(55.23), "55.23"),
            (json!("i am data"), "\\\"i am data\\\""),
        ] {
            let actual = serde_json::to_string(&JsonString::from(value.clone())).unwrap();
            assert_eq!(
                actual,
                format!("\"{as_str}\""),
                "expected value {value:?} to be encoded as string \"{as_str}\""
            );
        }
    }

    #[test]
    fn inline_and_option_in_json() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct Test {
            as_str: JsonString,
            as_inline: JsonString,
            as_opt_none: Option<JsonString>,
            as_opt_some_str: Option<JsonString>,
            as_opt_some_inline: Option<JsonString>,
        }

        let value: Test = serde_json::from_value(json!({
            "as_str": "null",
            "as_inline": { "__inline__": null },
            "as_opt_none": null,
            "as_opt_some_str": "null",
            "as_opt_some_inline": { "__inline__": ["foo", "bar"] }
        }))
        .expect("input is valid, should parse");

        assert_eq!(
            value,
            Test {
                as_str: JsonString::new(json!(null)),
                as_inline: JsonString::new(json!(null)),
                as_opt_none: None,
                as_opt_some_str: Some(JsonString::new(json!(null))),
                as_opt_some_inline: Some(JsonString::new(json!(["foo", "bar"]))),
            }
        )
    }

    #[test]
    fn when_json_input_is_not_valid() {
        for invalid in [
            json!("i am not a valid json"),
            json!(42),
            json!([1, 2, 3]),
            json!({ "a": 1, "b": 2}),
        ] {
            #[derive(Deserialize, Debug)]
            struct Test {
                _json: JsonString,
            }

            let err = serde_json::from_value::<Test>(json!({ "json": invalid }))
                .expect_err("the input is invalid");
            assert!(format!("{err}").contains("expected either a string with valid JSON (e.g. `\"null\"` or `\"42\"`) \
                                        or an object with inlined JSON value (i.e. `{{ \"__inline__\": ... }}`)"));
        }
    }

    #[test]
    fn str_into_json_string_does_not_parse_it() {
        let value = JsonString::from("i am data");
        assert_eq!(
            serde_json::to_string(&value).unwrap(),
            "\"\\\"i am data\\\"\""
        )
    }
}
