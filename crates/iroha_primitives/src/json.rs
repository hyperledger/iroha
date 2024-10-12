//! String containing serialized valid JSON.
//! This string is guaranteed to parse as JSON

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::str::FromStr;
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

/// A valid `Json` that consists of valid String of Json type
#[derive(Debug, Display, Clone, PartialOrd, PartialEq, Ord, Eq, IntoSchema, Encode, Decode)]
#[display(fmt = "{_0}")]
pub struct Json(String);

impl Json {
    /// Constructs [`Self`]
    /// # Errors
    ///
    /// - Serialization can fail if T's implementation of Serialize decides to fail,
    /// - or if T contains a map with non-string keys.
    // Todo: Doesn't remove extra spaces in if `&str` is an object
    pub fn new<T: Serialize>(payload: T) -> Self {
        candidate::JsonCandidate::new(payload).try_into().unwrap()
    }

    /// Tries cast [`Self`] to any value.
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

    /// Getter for [`Self`]
    pub fn get(&self) -> &String {
        &self.0
    }
}

impl<'de> serde::de::Deserialize<'de> for Json {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let json = Value::deserialize(deserializer)?;
        Ok(Self(json.to_string()))
    }
}

impl serde::ser::Serialize for Json {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let json: Value = serde_json::from_str(&self.0).map_err(serde::ser::Error::custom)?;
        json.serialize(serializer)
    }
}

impl From<&Value> for Json {
    fn from(value: &Value) -> Self {
        Json(value.to_string())
    }
}

impl From<Value> for Json {
    fn from(value: Value) -> Self {
        Json(value.to_string())
    }
}

impl From<u32> for Json {
    fn from(value: u32) -> Self {
        Json::new(value)
    }
}

impl From<u64> for Json {
    fn from(value: u64) -> Self {
        Json::new(value)
    }
}

impl From<f64> for Json {
    fn from(value: f64) -> Self {
        Json::new(value)
    }
}

impl From<bool> for Json {
    fn from(value: bool) -> Self {
        Json::new(value)
    }
}

impl From<&str> for Json {
    fn from(value: &str) -> Self {
        value.parse::<Json>().expect("Impossible error")
    }
}

impl<T: Into<Json> + Serialize> From<Vec<T>> for Json {
    fn from(value: Vec<T>) -> Self {
        Json::new(value)
    }
}

/// Removes extra spaces from object if `&str` is an object
impl FromStr for Json {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(value) = serde_json::from_str::<Value>(s) {
            Ok(Json(value.to_string()))
        } else {
            let json_formatted_string = serde_json::to_string(s)?;
            let value: Value = serde_json::from_str(&json_formatted_string)?;
            Ok(Json(value.to_string()))
        }
    }
}

impl Default for Json {
    fn default() -> Self {
        // NOTE: empty string isn't valid JSON
        Self("null".to_string())
    }
}

impl AsRef<str> for Json {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

mod candidate {
    use super::*;

    #[derive(Serialize, Deserialize, Clone)]
    pub(super) struct JsonCandidate<T>(T);

    impl<T: Serialize> JsonCandidate<T> {
        pub(super) fn new(value: T) -> Self {
            JsonCandidate(value)
        }
    }

    impl<T: Serialize> TryFrom<JsonCandidate<T>> for Json {
        type Error = serde_json::Error;
        fn try_from(value: JsonCandidate<T>) -> Result<Self, Self::Error> {
            Ok(Json(serde_json::to_string(&value.0)?))
        }
    }
}
