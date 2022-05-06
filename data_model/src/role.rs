//! Structures, traits and impls related to `Role`s.

#[cfg(not(feature = "std"))]
use alloc::{collections::btree_set, format, string::String, vec::Vec};
use core::{fmt, str::FromStr};
#[cfg(feature = "std")]
use std::collections::btree_set;

use getset::Getters;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    permissions::{PermissionToken, Permissions},
    Identifiable, Name, ParseError,
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
    pub fn new(name: Name) -> Self {
        Self { name }
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl FromStr for Id {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            name: Name::from_str(s)?,
        })
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
        id: <Self as Identifiable>::Id,
        permissions: impl IntoIterator<Item = impl Into<PermissionToken>>,
    ) -> <Self as Identifiable>::RegisteredWith {
        Self {
            id,
            permissions: permissions.into_iter().map(Into::into).collect(),
        }
    }

    /// Get an iterator over [`permissions`](PermissionToken) of the `Role`
    #[inline]
    pub fn permissions(&self) -> impl ExactSizeIterator<Item = &PermissionToken> {
        self.permissions.iter()
    }
}

impl Identifiable for Role {
    type Id = Id;
    type RegisteredWith = Self;
}

/// Builder for [`Role`]
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
pub struct NewRole {
    inner: Role,
}

/// Builder for [`Role`]
impl NewRole {
    /// Constructor
    pub fn new(id: <Role as Identifiable>::Id) -> Self {
        Self {
            inner: Role {
                id,
                permissions: Permissions::new(),
            },
        }
    }

    /// Add permission to the [`Role`]
    #[must_use]
    pub fn add_permission(mut self, perm: impl Into<PermissionToken>) -> Self {
        self.inner.permissions.insert(perm.into());
        self
    }

    /// Construct [`Role`]
    #[must_use]
    pub fn build(self) -> Role {
        self.inner
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this module.
pub mod prelude {
    pub use super::{Id as RoleId, NewRole, Role};
}
