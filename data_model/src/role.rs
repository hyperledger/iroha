//! Structures, traits and impls related to `Role`s.

#[cfg(not(feature = "std"))]
use alloc::{collections::btree_set, format, string::String, vec::Vec};
#[cfg(feature = "std")]
use std::collections::btree_set;

use derive_more::{Constructor, Display, FromStr};
use getset::Getters;
use iroha_data_model_derive::IdEqOrdHash;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    model,
    permission::{Permissions, Token as PermissionToken},
    Identifiable, Name, Registered,
};

/// Collection of [`RoleId`](Id)s
pub type RoleIds = btree_set::BTreeSet<<Role as Identifiable>::Id>;

model! {
    /// Identification of a role.
    #[derive(Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Constructor, FromStr, Getters, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[getset(get = "pub")]
    #[serde(transparent)]
    #[repr(transparent)]
    #[ffi_type(opaque)]
    pub struct Id {
        /// Role name, should be unique .
        pub name: Name,
    }

    /// Role is a tag for a set of permission tokens.
    #[derive(Debug, Display, Clone, IdEqOrdHash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[display(fmt = "{id}")]
    #[ffi_type]
    pub struct Role {
        /// Unique name of the role.
        pub id: Id,
        /// Permission tokens.
        pub permissions: Permissions,
    }

    /// Builder for [`Role`]
    #[derive(Debug, Display, Clone, IdEqOrdHash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[serde(transparent)]
    #[repr(transparent)]
    #[ffi_type(opaque)]
    pub struct NewRole {
        #[id(transparent)]
        inner: Role,
    }
}

impl Role {
    /// Constructor.
    #[inline]
    pub fn new(id: <Self as Identifiable>::Id) -> <Self as Registered>::With {
        NewRole::new(id)
    }

    /// Get an iterator over [`permissions`](PermissionToken) of the `Role`
    #[inline]
    pub fn permissions(&self) -> impl ExactSizeIterator<Item = &PermissionToken> {
        self.permissions.iter()
    }

    /// Remove permission tokens with specified id from `Role`
    #[cfg(feature = "transparent_api")]
    pub fn remove_permission(&mut self, definition_id: &crate::permission::token::Id) {
        self.permissions
            .retain(|token| token.definition_id != *definition_id);
    }
}

impl NewRole {
    /// Constructor
    #[must_use]
    #[inline]
    fn new(id: <Role as Identifiable>::Id) -> Self {
        Self {
            inner: Role {
                id,
                permissions: Permissions::new(),
            },
        }
    }

    /// Add permission to the [`Role`]
    #[must_use]
    #[inline]
    pub fn add_permission(mut self, perm: impl Into<PermissionToken>) -> Self {
        self.inner.permissions.insert(perm.into());
        self
    }
}

impl Registered for Role {
    type With = NewRole;
}

#[cfg(feature = "transparent_api")]
impl crate::Registrable for NewRole {
    type Target = Role;

    #[must_use]
    #[inline]
    fn build(self) -> Self::Target {
        self.inner
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this module.
pub mod prelude {
    pub use super::{Id as RoleId, NewRole, Role};
}
