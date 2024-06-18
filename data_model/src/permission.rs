//! Permission Token and related impls
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeSet, format, string::String, vec::Vec};
#[cfg(feature = "std")]
use std::collections::BTreeSet;

use iroha_data_model_derive::model;
use iroha_primitives::json::JsonString;
use iroha_schema::{Ident, IntoSchema};

pub use self::model::*;

/// Collection of [`Token`]s
pub type Permissions = BTreeSet<Permission>;

use super::*;

#[model]
mod model {
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

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
        Display,
    )]
    #[ffi_type]
    #[display(fmt = "PERMISSION `{name}` = `{payload}`")]
    pub struct Permission {
        /// Refers to a type defined in [`crate::executor::ExecutorDataModel`].
        pub name: Ident,
        /// Payload containing actual value.
        ///
        /// It is JSON-encoded, and its structure must correspond to the structure of
        /// the type defined in [`crate::executor::ExecutorDataModel`].
        pub payload: JsonString,
    }
}

impl Permission {
    /// Constructor
    pub fn new(name: Ident, payload: impl Into<JsonString>) -> Self {
        Self {
            name,
            payload: payload.into(),
        }
    }

    /// Refers to a type defined in [`crate::executor::ExecutorDataModel`].
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Getter
    // TODO: derive with getset once FFI impl is fixed
    pub fn payload(&self) -> &JsonString {
        &self.payload
    }
}

pub mod prelude {
    //! The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub use super::Permission;
}
