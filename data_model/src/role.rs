//! Structures, traits and impls related to `Role`s.

#[cfg(not(feature = "std"))]
use alloc::{collections::btree_set, format, string::String, vec::Vec};
#[cfg(feature = "std")]
use std::collections::btree_set;

use derive_more::{Constructor, Display, FromStr};
use getset::Getters;
#[cfg(feature = "ffi_api")]
use iroha_ffi::ffi_bindgen;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    permissions::{PermissionToken, Permissions},
    Identifiable, Name, Registered,
};

/// Collection of [`RoleId`](Id)s
pub type RoleIds = btree_set::BTreeSet<<Role as Identifiable>::Id>;

/// Identification of a role.
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
)]
pub struct Id {
    /// Role name, should be unique .
    pub name: Name,
}

/// Role is a tag for a set of permission tokens.
#[derive(
    Debug,
    Display,
    Clone,
    PartialEq,
    Eq,
    Getters,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoSchema,
)]
#[cfg_attr(feature = "ffi_api", ffi_bindgen)]
#[display(fmt = "{id}")]
#[getset(get = "pub")]
pub struct Role<const HASH_LENGTH: usize> {
    /// Unique name of the role.
    #[getset(skip)]
    id: <Self as Identifiable>::Id,
    /// Permission tokens.
    #[getset(skip)]
    permissions: Permissions<HASH_LENGTH>,
}

impl<const HASH_LENGTH: usize> PartialOrd for Role<HASH_LENGTH> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<const HASH_LENGTH: usize> Ord for Role<HASH_LENGTH> {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id().cmp(other.id())
    }
}

#[cfg_attr(feature = "ffi_api", ffi_bindgen)]
impl<const HASH_LENGTH: usize> Role<HASH_LENGTH> {
    /// Constructor.
    #[inline]
    pub fn new(
        id: <Self as Identifiable>::Id,
        permissions: impl IntoIterator<Item = impl Into<PermissionToken<HASH_LENGTH>>>,
    ) -> <Self as Registered>::With {
        Self {
            id,
            permissions: permissions.into_iter().map(Into::into).collect(),
        }
    }

    /// Get an iterator over [`permissions`](PermissionToken) of the `Role`
    #[inline]
    pub fn permissions(&self) -> impl ExactSizeIterator<Item = &PermissionToken<HASH_LENGTH>> {
        self.permissions.iter()
    }
}

impl<const HASH_LENGTH: usize> Identifiable for Role<HASH_LENGTH> {
    type Id = Id;

    fn id(&self) -> &Self::Id {
        &self.id
    }
}

impl<const HASH_LENGTH: usize> Registered for Role<HASH_LENGTH> {
    type With = Self;
}

/// Builder for [`Role`]
#[derive(
    Debug, Clone, PartialEq, Eq, Getters, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
pub struct NewRole<const HASH_LENGTH: usize> {
    inner: Role<HASH_LENGTH>,
}

impl<const HASH_LENGTH: usize> PartialOrd for NewRole<HASH_LENGTH> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<const HASH_LENGTH: usize> Ord for NewRole<HASH_LENGTH> {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.inner.cmp(&other.inner)
    }
}

/// Builder for [`Role`]
impl<const HASH_LENGTH: usize> NewRole<HASH_LENGTH> {
    /// Constructor
    pub fn new(id: <Role<HASH_LENGTH> as Identifiable>::Id) -> Self {
        Self {
            inner: Role {
                id,
                permissions: Permissions::new(),
            },
        }
    }

    /// Add permission to the [`Role`]
    #[must_use]
    pub fn add_permission(mut self, perm: impl Into<PermissionToken<HASH_LENGTH>>) -> Self {
        self.inner.permissions.insert(perm.into());
        self
    }

    /// Construct [`Role`]
    #[must_use]
    pub fn build(self) -> Role<HASH_LENGTH> {
        self.inner
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this module.
pub mod prelude {
    pub use super::{Id as RoleId, NewRole, Role};
}
