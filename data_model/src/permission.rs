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
pub mod model {
    use super::*;

    /// Stored proof of the account having a permission for a certain action.
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
        pub payload: StringWithJson,
    }

    /// Description of tokens defined in the validator
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

    /// String containing serialized json
    #[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
    pub struct StringWithJson(pub(super) String);
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
    /// Construct [`Self`]
    pub fn new(definition_id: PermissionTokenId, payload: &serde_json::Value) -> Self {
        Self {
            definition_id,
            payload: StringWithJson::new(payload),
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

impl StringWithJson {
    /// Construct [`StringWithJson`]
    pub fn new(payload: &serde_json::Value) -> Self {
        Self(payload.to_string())
    }
}

impl<'de> serde::de::Deserialize<'de> for StringWithJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let json = serde_json::Value::deserialize(deserializer)?;
        Ok(Self::new(&json))
    }
}

impl serde::ser::Serialize for StringWithJson {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let json = serde_json::Value::from_str(&self.0).map_err(serde::ser::Error::custom)?;
        json.serialize(serializer)
    }
}

impl iroha_schema::TypeId for StringWithJson {
    fn id() -> iroha_schema::Ident {
        "StringWithJson".to_owned()
    }
}

impl IntoSchema for StringWithJson {
    fn type_name() -> iroha_schema::Ident {
        <Self as iroha_schema::TypeId>::id()
    }

    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(iroha_schema::Metadata::String);
        }
    }
}

impl PartialOrd for StringWithJson {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StringWithJson {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

pub mod prelude {
    //! The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub use super::{PermissionToken, PermissionTokenId, PermissionTokenSchema};
}
