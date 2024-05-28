//! Permission Token and related impls
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeSet, format, string::String, vec::Vec};
use core::borrow::Borrow;
#[cfg(feature = "std")]
use std::collections::BTreeSet;

use iroha_data_model_derive::model;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;
use crate::name::Name;

/// Collection of [`Token`]s
pub type Permissions = BTreeSet<Permission>;

use super::*;

#[model]
mod model {
    use super::*;

    /// Identifies a [`Permission`].
    /// The executor defines available permission names.
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        Constructor,
        FromStr,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[getset(get = "pub")]
    #[serde(transparent)]
    #[repr(transparent)]
    #[ffi_type(opaque)]
    pub struct PermissionId {
        /// Should be unique.
        pub name: Name,
    }

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
        Display,
        Getters,
    )]
    #[ffi_type]
    #[display(fmt = "PERMISSION `{id}` = `{payload}`")]
    #[getset(get = "pub")]
    pub struct Permission {
        /// Refers to a type defined in [`crate::executor::ExecutorDataModel`].
        pub id: PermissionId,
        /// Payload containing actual value.
        ///
        /// It is JSON-encoded, and its structure must correspond to the structure of
        /// the type defined in [`crate::executor::ExecutorDataModel`].
        #[getset(skip)]
        pub payload: JsonString,
    }
}

impl Permission {
    /// Constructor
    pub fn new(id: PermissionId, payload: impl IntoJsonString) -> Self {
        Self {
            id,
            payload: payload.into_json_string(),
        }
    }
}

impl Borrow<str> for PermissionId {
    fn borrow(&self) -> &str {
        self.name.borrow()
    }
}

impl Borrow<str> for Permission {
    fn borrow(&self) -> &str {
        self.id.borrow()
    }
}

impl Permission {
    /// Getter
    // TODO: derive with getset once FFI impl is fixed
    pub fn payload(&self) -> &JsonString {
        &self.payload
    }
}

pub mod prelude {
    //! The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub use super::{Permission, PermissionId};
}
