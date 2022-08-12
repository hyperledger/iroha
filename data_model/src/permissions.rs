//! Structures, traits and impls related to `Permission`s.

#[cfg(not(feature = "std"))]
use alloc::{
    alloc::alloc,
    boxed::Box,
    collections::{btree_map, btree_set},
    format,
    string::String,
    vec::Vec,
};
#[cfg(feature = "std")]
use std::{
    alloc::alloc,
    collections::{btree_map, btree_set},
};

use derive_more::{Constructor, Display, FromStr};
use getset::Getters;
use iroha_data_model_derive::IdOrdEqHash;
use iroha_ffi::{IntoFfi, TryFromReprC};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{ffi::ffi_item, utils::format_comma_separated, Identifiable, Name, Registered, Value};

/// Collection of [`PermissionToken`]s
pub type Permissions = btree_set::BTreeSet<PermissionToken>;

/// Unique id of [`PermissionTokenDefinition`]
#[derive(
    Debug,
    Display,
    Constructor,
    FromStr,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoSchema,
    TryFromReprC,
    IntoFfi,
)]
#[cfg_attr(feature = "ffi", derive(IntoFfi, TryFromFfi))]
pub struct Id {
    /// [`PermissionToken`] name
    name: Name,
}

ffi_item! {
    /// Defines a type of [`PermissionToken`] with given id
    #[derive(
        Debug, Display, Clone, IdOrdEqHash, Getters, Decode, Encode, Deserialize, Serialize, IntoSchema, IntoFfi, TryFromReprC
    )]
    #[cfg_attr(all(feature = "ffi_export", not(feature = "ffi_import")), iroha_ffi::ffi_export)]
    #[cfg_attr(feature = "ffi_import", iroha_ffi::ffi_import)]
    #[display(fmt = "{id}")]
    #[getset(get = "pub")]
    #[id(type = "Id")]
    pub struct PermissionTokenDefinition {
        /// PermissionTokenDefinition Id
        id: Id,
    }
}

impl Registered for PermissionTokenDefinition {
    type With = Self;
}

impl PermissionTokenDefinition {
    /// Construct new `PermissionTokenDefinition`
    pub fn new(id: Id) -> Self {
        Self { id }
    }
}

ffi_item! {
    /// Stored proof of the account having a permission for a certain action.
    #[derive(
        Debug,
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
        IntoFfi,
        TryFromReprC
    )]
    #[cfg_attr(all(feature = "ffi_export", not(feature = "ffi_import")), iroha_ffi::ffi_export)]
    #[cfg_attr(feature = "ffi_import", iroha_ffi::ffi_import)]
    #[getset(get = "pub")]
    pub struct PermissionToken {
        /// Name of the permission rule given to account.
        definition_id: <PermissionTokenDefinition as Identifiable>::Id,
        /// Params identifying how this rule applies.
        #[getset(skip)]
        params: btree_map::BTreeMap<Name, Value>,
    }
}

impl core::fmt::Display for PermissionToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: ", self.definition_id)?;
        format_comma_separated(
            self.params
                .iter()
                .map(|(name, value)| format!("`{name}` : `{value}`")),
            ('{', '}'),
            f,
        )
    }
}

impl PermissionToken {
    /// Constructor.
    #[inline]
    pub fn new(definition_id: <PermissionTokenDefinition as Identifiable>::Id) -> Self {
        Self {
            definition_id,
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
    pub use super::{
        Id as PermissionTokenDefinitionId, PermissionToken, PermissionTokenDefinition, Permissions,
    };
}
