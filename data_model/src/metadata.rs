//! Metadata: key-value pairs that can be attached to accounts, transactions and assets.

#[cfg(not(feature = "std"))]
use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::borrow::Borrow;
#[cfg(feature = "std")]
use std::{collections::BTreeMap, string::ToString, vec::Vec};

use derive_more::Display;
use iroha_data_model_derive::model;
use iroha_primitives::json::JsonString;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;
use crate::prelude::Name;

/// A path slice, composed of [`Name`]s.

pub type Path = [Name];

/// Collection of parameters by their names.
pub type UnlimitedMetadata = BTreeMap<Name, JsonString>;

#[model]
mod model {
    use super::*;

    /// Collection of parameters by their names with checked insertion.
    #[derive(
        Debug,
        Display,
        Clone,
        Default,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Deserialize,
        Serialize,
        Decode,
        Encode,
        IntoSchema,
    )]
    #[ffi_type(opaque)]
    #[repr(transparent)]
    #[serde(transparent)]
    #[display(fmt = "Metadata")]
    #[allow(clippy::multiple_inherent_impl)]
    pub struct Metadata(pub(super) BTreeMap<Name, JsonString>);

    /// Limits for [`Metadata`].
    #[derive(
        Debug,
        Display,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[ffi_type]
    #[display(fmt = "{capacity},{max_entry_len}_ML")]
    pub struct Limits {
        /// Maximum number of entries
        pub capacity: u32,
        /// Maximum length of entry
        pub max_entry_len: u32,
    }

    /// Metadata related errors.
    #[derive(
        Debug,
        displaydoc::Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[ffi_type(local)]
    #[cfg_attr(feature = "std", derive(thiserror::Error))]
    pub enum MetadataError {
        /// Path specification empty
        EmptyPath,
        /// Metadata entry is too big
        EntryTooBig(#[cfg_attr(feature = "std", source)] SizeError),
        /// Metadata exceeds overall length limit
        MaxCapacity(#[cfg_attr(feature = "std", source)] SizeError),
        /// `{0}`: path segment not found, i.e. nothing was found at that key
        MissingSegment(Name),
        /// `{0}`: path segment not an instance of metadata
        InvalidSegment(Name),
        /// Metadata has an Invalid Json
        InvalidJson(String),
    }

    /// Size limits exhaustion error
    #[derive(
        Debug,
        Display,
        Copy,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[ffi_type]
    #[cfg_attr(feature = "std", derive(thiserror::Error))]
    #[display(fmt = "Limits are {limits}, while the actual value is {actual}")]
    pub struct SizeError {
        /// The limits that were set for this entry
        pub limits: Limits,
        /// The actual *entry* size in bytes
        pub actual: u64,
    }
}

impl Limits {
    /// Constructor.
    pub const fn new(capacity: u32, max_entry_len: u32) -> Limits {
        Limits {
            capacity,
            max_entry_len,
        }
    }
}

impl From<serde_json::Error> for MetadataError {
    fn from(err: serde_json::Error) -> Self {
        MetadataError::InvalidJson(err.to_string())
    }
}

impl Metadata {
    /// Constructor.
    #[inline]
    pub fn new() -> Self {
        Self(UnlimitedMetadata::new())
    }

    /// Check if the internal map contains the given key.
    pub fn contains(&self, key: &Name) -> bool {
        self.0.contains_key(key)
    }

    /// Iterate over key/value pairs stored in the internal map.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&Name, &JsonString)> {
        self.0.iter()
    }

    /// Get the `Some(&Value)` associated to `key`. Return `None` if not found.
    #[inline]
    pub fn get<K: Ord + ?Sized>(&self, key: &K) -> Option<&JsonString>
    where
        Name: Borrow<K>,
    {
        self.0.get(key)
    }

    fn len_u64(&self) -> u64 {
        self.0
            .len()
            .try_into()
            .expect("`usize` should always fit into `u64`")
    }

    /// Insert [`Value`] under the given key.  Returns `Some(value)`
    /// if the value was already present, `None` otherwise.
    ///
    /// # Errors
    /// Fails if `max_entry_len` or `capacity` from `limits` are exceeded.
    pub fn insert_with_limits(
        &mut self,
        key: Name,
        value: impl TryInto<JsonString>,
        limits: Limits,
    ) -> Result<Option<JsonString>, MetadataError> {
        let value = match value.try_into() {
            Ok(value) => value,
            _ => return Err(MetadataError::InvalidJson("Invalid Json value".to_string())),
        };

        if self.0.len() >= limits.capacity as usize && !self.0.contains_key(&key) {
            return Err(MetadataError::MaxCapacity(SizeError {
                limits,
                actual: self.len_u64(),
            }));
        }
        check_size_limits(&key, &value, limits)?;
        Ok(self.0.insert(key, value))
    }
}

#[cfg(feature = "transparent_api")]
impl Metadata {
    /// Removes a key from the map, returning the owned
    /// `Some(value)` at the key if the key was previously in the
    /// map, else `None`.
    #[inline]
    pub fn remove<K: Ord + ?Sized>(&mut self, key: &K) -> Option<JsonString>
    where
        Name: Borrow<K>,
    {
        self.0.remove(key)
    }
}

fn check_size_limits(key: &Name, value: &JsonString, limits: Limits) -> Result<(), MetadataError> {
    let entry_bytes: Vec<u8> = (key, value).encode();
    let byte_size = entry_bytes.len();
    if byte_size > limits.max_entry_len as usize {
        return Err(MetadataError::EntryTooBig(SizeError {
            limits,
            actual: byte_size
                .try_into()
                .expect("`usize` should always fit into `u64`"),
        }));
    }
    Ok(())
}

pub mod prelude {
    //! Prelude: re-export most commonly used traits, structs and macros from this module.
    pub use super::{Limits as MetadataLimits, Metadata, UnlimitedMetadata};
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::{borrow::ToOwned as _, vec};
    use core::str::FromStr as _;

    use iroha_macro::FromVariant;

    use super::*;
    use crate::ParseError;

    /// Error used in testing to make text more readable using the `?` operator.
    #[derive(Debug, Display, Clone, FromVariant)]
    pub enum TestError {
        Parse(ParseError),
        Metadata(MetadataError),
    }

    #[test]
    fn insert_exceeds_entry_size() -> Result<(), TestError> {
        let mut metadata = Metadata::new();
        let limits = Limits::new(10, 5);
        assert!(metadata
            .insert_with_limits(Name::from_str("1")?, JsonString::new("2"), limits)
            .is_ok());
        assert!(metadata
            .insert_with_limits(Name::from_str("1")?, JsonString::new("23456"), limits)
            .is_err());
        Ok(())
    }

    #[test]
    // This test is a good candidate for both property-based and parameterised testing
    fn insert_exceeds_len() -> Result<(), TestError> {
        let mut metadata = Metadata::new();
        let limits = Limits::new(2, 5);
        assert!(metadata
            .insert_with_limits(Name::from_str("1")?, 0_u32, limits)
            .is_ok());
        assert!(metadata
            .insert_with_limits(Name::from_str("2")?, 0_u32, limits)
            .is_ok());
        assert!(metadata
            .insert_with_limits(Name::from_str("2")?, 1_u32, limits)
            .is_ok());
        assert!(metadata
            .insert_with_limits(Name::from_str("3")?, 0_u32, limits)
            .is_err());
        Ok(())
    }
}
