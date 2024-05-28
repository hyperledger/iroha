//! String containing serialized valid JSON.
//! This string is guaranteed to parse as JSON

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::{
    fmt::{Display, Formatter},
    str::FromStr,
};
#[cfg(feature = "std")]
use std::{
    string::{String, ToString},
    vec::Vec,
};

use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

/// A valid `JsonString` that consists of valid String of Json type
#[derive(Debug, Clone, PartialOrd, PartialEq, Ord, Eq, IntoSchema, Encode, Decode)]
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

impl<'de> serde::de::Deserialize<'de> for JsonString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let json = Value::deserialize(deserializer)?;
        Ok(Self(json.to_string()))
    }
}

impl serde::ser::Serialize for JsonString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let json: Value = serde_json::from_str(&self.0).map_err(serde::ser::Error::custom)?;
        json.serialize(serializer)
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

impl From<&str> for JsonString {
    fn from(value: &str) -> Self {
        value.parse::<JsonString>().expect("Impossible error")
    }
}

impl<T: Into<JsonString> + Serialize> From<Vec<T>> for JsonString {
    fn from(value: Vec<T>) -> Self {
        JsonString::new(value)
    }
}

/// Removes extra spaces from object if `&str` is an object
impl FromStr for JsonString {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(value) = serde_json::from_str::<Value>(s) {
            Ok(JsonString(value.to_string()))
        } else {
            let json_formatted_string = serde_json::to_string(s)?;
            let value: Value = serde_json::from_str(&json_formatted_string)?;
            Ok(JsonString(value.to_string()))
        }
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

impl Display for JsonString {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", &self.0)
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
