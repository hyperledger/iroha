//! Structures, traits and impls related to `Permission`s.

#[cfg(not(feature = "std"))]
use alloc::{
    boxed::Box,
    collections::{btree_map, btree_set},
    format,
    string::String,
    vec::Vec,
};
#[cfg(feature = "std")]
use std::collections::{btree_map, btree_set};

use derive_more::Display;
use getset::Getters;
#[cfg(feature = "ffi")]
use iroha_ffi::{ffi_export, IntoFfi, TryFromFfi};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{Name, Value};

/// Collection of [`PermissionToken`]s
pub type Permissions = btree_set::BTreeSet<PermissionToken>;

/// Stored proof of the account having a permission for a certain action.
#[derive(
    Debug,
    Display,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Getters,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoSchema,
)]
#[cfg_attr(feature = "ffi", derive(IntoFfi, TryFromFfi))]
#[cfg_attr(feature = "ffi", ffi_export)]
#[getset(get = "pub")]
#[display(fmt = "{name}")]
pub struct PermissionToken {
    /// Name of the permission rule given to account.
    name: Name,
    /// Params identifying how this rule applies.
    #[getset(skip)]
    params: btree_map::BTreeMap<Name, Value>,
}

impl PermissionToken {
    /// Constructor.
    #[inline]
    pub fn new(name: Name) -> Self {
        Self {
            name,
            params: btree_map::BTreeMap::default(),
        }
    }

    /// Add parameters to the `PermissionToken` replacing any previously defined
    #[inline]
    #[must_use]
    pub fn with_params(mut self, params: impl IntoIterator<Item = (Name, Value)>) -> Self {
        self.params = params.into_iter().collect();
        self
    }

    /// Return a reference to the parameter corresponding to the given name
    #[inline]
    pub fn get_param(&self, name: &Name) -> Option<&Value> {
        self.params.get(name)
    }

    /// Get an iterator over parameters of the `PermissionToken`
    #[inline]
    pub fn params(&self) -> impl ExactSizeIterator<Item = (&Name, &Value)> {
        self.params.iter()
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this module.
pub mod prelude {
    pub use super::{PermissionToken, Permissions};
}
