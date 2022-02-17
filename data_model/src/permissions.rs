//! Structures, traits and impls related to `Permission`s.

#[cfg(not(feature = "std"))]
use alloc::{collections::btree_map, format, string::String, vec::Vec};
#[cfg(feature = "std")]
use std::collections::btree_map;

use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{Name, Value};

/// Stored proof of the account having a permission for a certain action.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
pub struct PermissionToken {
    /// Name of the permission rule given to account.
    pub name: Name,
    /// Params identifying how this rule applies.
    pub params: btree_map::BTreeMap<Name, Value>,
}

impl PermissionToken {
    /// Constructor.
    #[inline]
    pub fn new(name: impl Into<Name>, params: impl IntoIterator<Item = (Name, Value)>) -> Self {
        let params = params.into_iter().collect();
        let name = name.into();
        Self { name, params }
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this module.
pub mod prelude {
    pub use super::PermissionToken;
}
