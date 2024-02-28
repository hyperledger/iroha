//! Permission Token and related impls
#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned as _, collections::BTreeSet, format, string::String, vec::Vec};
#[cfg(feature = "std")]
use std::collections::BTreeSet;

use iroha_data_model_derive::model;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;
use crate::name::Name;

/// Collection of [`Token`]s
pub type Permissions = BTreeSet<PermissionToken>;

use super::*;

/// Unique id of [`PermissionToken`]
pub type PermissionTokenId = Name;

#[model]
mod model {
    use super::*;

    /// Stored proof of the account having a permission for a certain action.
    ///
    /// Since permission token is represented opaque to core
    /// either executor or client should make sure that tokens are represented uniformly.
    ///
    /// So that:
    /// - payload A is equal to payload B then token A must be equal to token B
    /// - and if payload A is't equal to B then token A mustn't be equal to token B
    #[derive(
        Debug,
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
    pub struct PermissionToken {
        /// Token identifier
        pub definition_id: PermissionTokenId,
        /// JSON encoded token payload
        pub payload: JsonString,
    }

    /// Description of tokens defined in the executor
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Default,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[display(fmt = "{token_ids:#?}")]
    #[ffi_type]
    pub struct PermissionTokenSchema {
        /// Ids of all permission tokens, sorted.
        pub token_ids: Vec<PermissionTokenId>,
        /// Type schema of permission tokens
        ///
        /// At the time of writing this doc a complete schema is returned but it's
        /// possible that in the future this field will contain references to types
        /// defined in the Iroha schema without defining them itself
        pub schema: String,
    }

    /// String containing serialized valid JSON.
    /// This string is guaranteed to parse as JSON
    #[derive(Debug, Clone, Eq, Encode, Decode)]
    pub struct JsonString(pub(super) String);
}

// TODO: Use getset to derive this
impl PermissionTokenSchema {
    /// Construct new [`PermissionTokenSchema`]
    pub fn new(token_ids: Vec<PermissionTokenId>, schema: String) -> Self {
        Self { token_ids, schema }
    }

    /// Return id of this token
    pub fn token_ids(&self) -> &[PermissionTokenId] {
        &self.token_ids
    }
}

impl PermissionToken {
    /// Construct [`Self`] from a raw string slice. The caller of the function
    /// must make sure that the given string slice can be parsed as valid JSON.
    ///
    /// Only used in tests
    #[cfg(debug_assertions)]
    // TODO: Remove after integration tests have been moved to python tests
    #[deprecated(note = "Will be removed after integration tests are removed from iroha_client")]
    pub fn from_str_unchecked(definition_id: PermissionTokenId, payload: &str) -> Self {
        Self {
            definition_id,
            payload: JsonString(payload.to_owned()),
        }
    }

    /// Construct [`Self`]
    pub fn new(definition_id: PermissionTokenId, payload: &serde_json::Value) -> Self {
        Self {
            definition_id,
            payload: JsonString::new(payload),
        }
    }

    /// Return id of this token
    // TODO: Use getset to derive this after fixes in FFI
    pub fn definition_id(&self) -> &Name {
        &self.definition_id
    }

    /// Payload of this token
    // TODO: Use getset to derive this after fixes in FFI
    pub fn payload(&self) -> &String {
        &self.payload.0
    }
}

impl core::fmt::Display for PermissionToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.definition_id)
    }
}

impl JsonString {
    /// Construct [`JsonString`]
    pub fn new(payload: &serde_json::Value) -> Self {
        Self(payload.to_string())
    }
}
impl PartialEq for JsonString {
    fn eq(&self, other: &Self) -> bool {
        serde_json::from_str::<serde_json::Value>(&self.0).unwrap()
            == serde_json::from_str::<serde_json::Value>(&other.0).unwrap()
    }
}

impl<'de> serde::de::Deserialize<'de> for JsonString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let json = serde_json::Value::deserialize(deserializer)?;
        Ok(Self::new(&json))
    }
}

impl serde::ser::Serialize for JsonString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let json = serde_json::Value::from_str(&self.0).map_err(serde::ser::Error::custom)?;
        json.serialize(serializer)
    }
}

impl iroha_schema::TypeId for JsonString {
    fn id() -> iroha_schema::Ident {
        "JsonString".to_owned()
    }
}

impl IntoSchema for JsonString {
    fn type_name() -> iroha_schema::Ident {
        <Self as iroha_schema::TypeId>::id()
    }

    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(iroha_schema::Metadata::String);
        }
    }
}

impl PartialOrd for JsonString {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for JsonString {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

pub mod prelude {
    //! The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub use super::{PermissionToken, PermissionTokenId, PermissionTokenSchema};
}
