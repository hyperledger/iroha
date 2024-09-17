//! String containing serialized valid JSON.
//! This string is guaranteed to parse as JSON

#[cfg(not(feature = "std"))]
use alloc::{
    borrow::ToOwned,
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::{cmp::Ordering, str::FromStr};
#[cfg(feature = "std")]
use std::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

use derive_more::Display;
use parity_scale_codec::{Compact, Decode, Encode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

/// A valid `JsonString` that consists of valid String of Json type
#[derive(Debug, Display, Clone, Deserialize, Serialize)]
#[display(fmt = "{_0}")]
#[serde(transparent)]
pub struct JsonString(Value);

/// Helper struct to work with [`JsonString`]
struct JsonStringRef<'value>(&'value Value);

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
    pub fn try_into_any<T: DeserializeOwned>(self) -> Result<T, serde_json::Error> {
        serde_json::from_value(self.0)
    }
}

impl From<&Value> for JsonString {
    fn from(value: &Value) -> Self {
        JsonString(value.clone())
    }
}

impl From<Value> for JsonString {
    fn from(value: Value) -> Self {
        JsonString(value)
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
            Ok(JsonString(value))
        } else {
            let json_formatted_string = serde_json::to_string(s)?;
            let value: Value = serde_json::from_str(&json_formatted_string)?;
            Ok(JsonString(value))
        }
    }
}

impl Default for JsonString {
    fn default() -> Self {
        Self(Value::Null)
    }
}

impl Ord for JsonString {
    fn cmp(&self, other: &Self) -> Ordering {
        JsonStringRef(&self.0).cmp(&JsonStringRef(&other.0))
    }
}

impl PartialOrd for JsonString {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for JsonString {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for JsonString {}

impl Ord for JsonStringRef<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        discriminant(self.0)
            .cmp(&discriminant(other.0))
            .then_with(|| match (self.0, other.0) {
                (Value::Null, Value::Null) => Ordering::Equal,
                (Value::String(l), Value::String(r)) => l.cmp(r),
                (Value::Bool(l), Value::Bool(r)) => l.cmp(r),
                (Value::Array(l), Value::Array(r)) => {
                    let l = l.iter().map(JsonStringRef);
                    let r = r.iter().map(JsonStringRef);
                    l.cmp(r)
                }
                (Value::Number(l), Value::Number(r)) => {
                    let l = l.to_string();
                    let r = r.to_string();
                    l.cmp(&r)
                }
                (Value::Object(l), Value::Object(r)) => {
                    let l = l.iter().map(|(k, v)| (k, JsonStringRef(v)));
                    let r = r.iter().map(|(k, v)| (k, JsonStringRef(v)));
                    l.cmp(r)
                }
                _ => unreachable!("other variants are handled through discriminant comparison"),
            })
    }
}

impl PartialOrd for JsonStringRef<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for JsonStringRef<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for JsonStringRef<'_> {}

mod schema {
    use iroha_schema::{EnumMeta, EnumVariant, IntoSchema, Metadata, TypeId};

    use super::*;

    impl TypeId for JsonString {
        fn id() -> iroha_schema::Ident {
            stringify!(JsonString).into()
        }
    }

    impl IntoSchema for JsonString {
        fn type_name() -> iroha_schema::Ident {
            Self::id()
        }

        fn update_schema_map(metamap: &mut iroha_schema::MetaMap) {
            if !metamap.contains_key::<Self>() {
                if !metamap.contains_key::<String>() {
                    <String as iroha_schema::IntoSchema>::update_schema_map(metamap);
                }
                if !metamap.contains_key::<bool>() {
                    <bool as iroha_schema::IntoSchema>::update_schema_map(metamap);
                }
                if !metamap.contains_key::<String>() {
                    <String as iroha_schema::IntoSchema>::update_schema_map(metamap);
                }
                if !metamap.contains_key::<Vec<Self>>() {
                    <Vec<Self> as iroha_schema::IntoSchema>::update_schema_map(metamap);
                }
                if !metamap.contains_key::<BTreeMap<String, Self>>() {
                    <BTreeMap<String, Self> as iroha_schema::IntoSchema>::update_schema_map(
                        metamap,
                    );
                }

                metamap.insert::<Self>(Metadata::Enum(EnumMeta {
                    variants: Vec::from([
                        EnumVariant {
                            tag: "Null".to_owned(),
                            discriminant: discriminants::NULL,
                            ty: None,
                        },
                        EnumVariant {
                            tag: "String".to_owned(),
                            discriminant: discriminants::STRING,
                            ty: Some(core::any::TypeId::of::<String>()),
                        },
                        EnumVariant {
                            tag: "Bool".to_owned(),
                            discriminant: discriminants::BOOL,
                            ty: Some(core::any::TypeId::of::<bool>()),
                        },
                        EnumVariant {
                            tag: "Array".to_owned(),
                            discriminant: discriminants::ARRAY,
                            ty: Some(core::any::TypeId::of::<Vec<Self>>()),
                        },
                        EnumVariant {
                            tag: "Number".to_owned(),
                            discriminant: discriminants::NUMBER,
                            ty: Some(core::any::TypeId::of::<String>()),
                        },
                        EnumVariant {
                            tag: "Object".to_owned(),
                            discriminant: discriminants::OBJECT,
                            ty: Some(core::any::TypeId::of::<BTreeMap<String, Self>>()),
                        },
                    ]),
                }));
            }
        }
    }
}

mod scale {
    use parity_scale_codec::{Error, Input, Output};
    use serde_json::{Map, Number};

    use super::*;

    impl Encode for JsonStringRef<'_> {
        fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
            match self.0 {
                Value::Null => {
                    dest.push_byte(discriminants::NULL);
                }
                Value::String(string) => {
                    dest.push_byte(discriminants::STRING);
                    string.encode_to(dest);
                }
                Value::Bool(bool) => {
                    dest.push_byte(discriminants::BOOL);
                    bool.encode_to(dest);
                }
                Value::Array(arr) => {
                    dest.push_byte(discriminants::ARRAY);
                    Compact(arr.len() as u64).encode_to(dest);
                    for e in arr {
                        JsonStringRef(e).encode_to(dest);
                    }
                }
                Value::Number(num) => {
                    dest.push_byte(discriminants::NUMBER);
                    num.to_string().encode_to(dest);
                }
                Value::Object(obj) => {
                    dest.push_byte(discriminants::OBJECT);
                    Compact(obj.len() as u64).encode_to(dest);
                    for (key, value) in obj {
                        key.encode_to(dest);
                        JsonStringRef(value).encode_to(dest);
                    }
                }
            }
        }
    }

    impl Encode for JsonString {
        fn encode(&self) -> Vec<u8> {
            JsonStringRef(&self.0).encode()
        }
    }

    impl Decode for JsonString {
        fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
            let discriminant = input.read_byte()?;
            let value = match discriminant {
                discriminants::NULL => Value::Null,
                discriminants::STRING => {
                    let string = String::decode(input)?;
                    Value::String(string)
                }
                discriminants::BOOL => {
                    let bool = bool::decode(input)?;
                    Value::Bool(bool)
                }
                discriminants::ARRAY => {
                    let len = Compact::<u64>::decode(input)?.0;
                    let len = usize::try_from(len).map_err(|_| "length of array is too big")?;
                    let mut arr = Vec::with_capacity(len);
                    for _ in 0..len {
                        let value = JsonString::decode(input)?.0;
                        arr.push(value);
                    }
                    Value::Array(arr)
                }
                discriminants::NUMBER => {
                    let num = String::decode(input)?;
                    Value::Number(Number::from_str(&num).map_err(|_| "not valid number")?)
                }
                discriminants::OBJECT => {
                    let len = Compact::<u64>::decode(input)?.0;
                    let len = usize::try_from(len).map_err(|_| "length of array is too big")?;
                    let mut map = Map::with_capacity(len);
                    for _ in 0..len {
                        let key = String::decode(input)?;
                        let value = JsonString::decode(input)?.0;
                        map.insert(key, value);
                    }
                    Value::Object(map)
                }
                _ => return Err("get invalid JSON value discriminant".into()),
            };
            Ok(JsonString(value))
        }
    }
}

mod discriminants {
    pub const NULL: u8 = 0;
    pub const STRING: u8 = 1;
    pub const BOOL: u8 = 2;
    pub const ARRAY: u8 = 3;
    pub const NUMBER: u8 = 4;
    pub const OBJECT: u8 = 5;
}

fn discriminant(value: &Value) -> u8 {
    match value {
        Value::Null => discriminants::NULL,
        Value::String(_) => discriminants::STRING,
        Value::Bool(_) => discriminants::BOOL,
        Value::Array(_) => discriminants::ARRAY,
        Value::Number(_) => discriminants::NUMBER,
        Value::Object(_) => discriminants::OBJECT,
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
            serde_json::to_value(&value.0).map(JsonString)
        }
    }
}
