//! Metadata: key-value pairs that can be attached to accounts, transactions and assets.

#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap, format, string::String, vec::Vec};
use core::borrow::Borrow;
#[cfg(feature = "std")]
use std::{collections::BTreeMap, vec::Vec};

use iroha_data_model_derive::model;
use iroha_primitives::json::JsonString;

pub use self::model::*;
use crate::prelude::Name;

/// A path slice, composed of [`Name`]s.

pub type Path = [Name];

#[model]
mod model {
    use derive_more::Display;
    use iroha_schema::IntoSchema;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

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
}

impl Metadata {
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

    /// Insert [`Value`] under the given key.  Returns `Some(value)`
    /// if the value was already present, `None` otherwise.
    pub fn insert(&mut self, key: Name, value: impl Into<JsonString>) -> Option<JsonString> {
        self.0.insert(key, value.into())
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

pub mod prelude {
    //! Prelude: re-export most commonly used traits, structs and macros from this module.
    pub use super::Metadata;
}
