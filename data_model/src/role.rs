//! Structures, traits and impls related to `Role`s.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, collections::btree_set, string::String};
use core::fmt;
#[cfg(feature = "std")]
use std::collections::btree_set;

use getset::Getters;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    permissions::{PermissionToken, Permissions},
    Identifiable, Name,
};

/// Collection of [`RoleId`]s
pub type RoleIds = btree_set::BTreeSet<<Role as Identifiable>::Id>;

/// Identification of a role.
#[derive(
    Debug,
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
)]
pub struct Id {
    /// Role name, should be unique .
    pub name: Name,
}

impl Id {
    /// Construct role id
    #[inline]
    pub fn new(name: impl Into<Name>) -> Self {
        Self { name: name.into() }
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// Role is a tag for a set of permission tokens.
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
)]
#[getset(get = "pub")]
pub struct Role {
    /// Unique name of the role.
    id: <Self as Identifiable>::Id,
    /// Permission tokens.
    #[getset(skip)]
    permissions: Permissions,
}

impl Role {
    /// Constructor.
    #[inline]
    pub fn new(
        id: impl Into<Id>,
        permissions: impl Into<Permissions>,
    ) -> <Self as Identifiable>::RegisteredWith {
        Self {
            id: id.into(),
            permissions: permissions.into(),
        }
    }

    /// Get an iterator over [`permissions`](PermissionToken) of the `Role`
    #[inline]
    pub fn permissions(&self) -> impl Iterator<Item = &PermissionToken> {
        self.permissions.iter()
    }
}

impl Identifiable for Role {
    type Id = Id;
    type RegisteredWith = Self;
}

/// The prelude re-exports most commonly used traits, structs and macros from this module.
pub mod prelude {
    pub use super::{Id as RoleId, Role};
}
