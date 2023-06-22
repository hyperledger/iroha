//! Permission Token and related impls
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeSet, format, string::String, vec::Vec};
#[cfg(feature = "std")]
use std::collections::BTreeSet;

use iroha_data_model_derive::model;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;

/// Collection of [`Token`]s
pub type Permissions = BTreeSet<PermissionToken>;

use super::*;

/// Unique id of [`PermissionToken`]
pub type PermissionTokenId = String;

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
        /// SCALE encoded token payload
        pub payload: Vec<u8>,
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
        /// Ids of all permission tokens
        pub token_ids: Vec<PermissionTokenId>,
        /// Type schema of permission tokens
        ///
        /// At the time of writing this doc a complete schema is returned but it's
        /// possible that in the future this field will contain references to types
        /// defined in the Iroha schema without defining them itself
        pub schema: String,
    }
}

// TODO: Use getset to derive this
impl PermissionTokenSchema {
    /// Return id of this token
    pub fn token_ids(&self) -> &[PermissionTokenId] {
        &self.token_ids
    }
}

impl PermissionToken {
    /// Construct [`Self`]
    pub fn new<T: Encode>(definition_id: PermissionTokenId, payload: &T) -> Self {
        Self {
            definition_id,
            payload: payload.encode(),
        }
    }

    /// Return id of this token
    // TODO: Use getset to derive this after fixes in FFI
    pub fn definition_id(&self) -> &str {
        &self.definition_id
    }

    /// Payload of this token
    // TODO: Use getset to derive this after fixes in FFI
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl core::fmt::Display for PermissionToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.definition_id)
    }
}

pub mod prelude {
    //! The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub use super::{PermissionToken, PermissionTokenId, PermissionTokenSchema};
}
