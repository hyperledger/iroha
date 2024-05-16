//! Permission Token and related impls
#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned as _, collections::BTreeSet, format, string::String, vec::Vec};
use core::borrow::Borrow;
#[cfg(feature = "std")]
use std::collections::BTreeSet;

use iroha_data_model_derive::{model, IdEqOrdHash};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;
use crate::{executor::ExecutorDataModelObject, name::Name};

/// Collection of [`Token`]s
pub type Permissions = BTreeSet<PermissionToken>;

use super::*;

#[model]
mod model {
    use super::*;

    /// Identification of [`PermissionToken`].
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
    pub struct PermissionTokenId {
        /// Should be unique.
        pub name: Name,
    }

    /// Stored proof of the account having a permission for a certain action.
    #[derive(
        Debug, Clone, IdEqOrdHash, Decode, Encode, Deserialize, Serialize, IntoSchema, Display,
    )]
    #[ffi_type]
    #[display(fmt = "PERMISSION TOKEN `{definition_id}`")]
    pub struct PermissionToken {
        /// Refers to a type defined in [`crate::executor::ExecutorDataModel`].
        #[id]
        pub definition_id: PermissionTokenId,
        /// Payload containing actual value.
        ///
        /// It is JSON-encoded, and its structure must correspond to the structure of
        /// the type defined in [`crate::executor::ExecutorDataModel`].
        pub payload: JsonString,
    }
}

impl PermissionToken {
    /// Constructor
    pub fn new(definition_id: PermissionTokenId, payload: impl IntoJsonString) -> Self {
        Self {
            definition_id,
            payload: payload.into_json_string(),
        }
    }
}

impl Borrow<str> for PermissionTokenId {
    fn borrow(&self) -> &str {
        self.name.borrow()
    }
}

impl Borrow<str> for PermissionToken {
    fn borrow(&self) -> &str {
        self.definition_id.borrow()
    }
}

impl From<Name> for PermissionTokenId {
    fn from(name: Name) -> Self {
        Self { name }
    }
}

impl From<PermissionTokenId> for Name {
    fn from(value: PermissionTokenId) -> Self {
        value.name
    }
}

impl ExecutorDataModelObject for PermissionToken {
    type DefinitionId = PermissionTokenId;

    fn new(id: Self::DefinitionId, payload: JsonString) -> Self {
        PermissionToken::new(id, payload)
    }

    fn object_definition_id(&self) -> &Self::DefinitionId {
        &self.definition_id
    }

    fn object_payload(&self) -> &JsonString {
        &self.payload
    }
}

pub mod prelude {
    //! The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub use super::{PermissionToken, PermissionTokenId};
}
