//! Structures, traits and impls related to `Role`s.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, collections::btree_set, format, string::String, vec::Vec};
#[cfg(feature = "std")]
use std::collections::btree_set;

use derive_more::{Constructor, Display, FromStr};
use getset::Getters;
#[cfg(feature = "ffi")]
use iroha_ffi::{ffi_export, IntoFfi, TryFromFfi};
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
#[cfg_attr(feature = "ffi", derive(IntoFfi, TryFromFfi))]
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
#[cfg_attr(feature = "ffi", derive(IntoFfi, TryFromFfi))]
#[cfg_attr(feature = "ffi", ffi_export)]
#[display(fmt = "{id}")]
#[getset(get = "pub")]
pub struct Role {
    /// Unique name of the role.
    #[getset(skip)]
    id: <Self as Identifiable>::Id,
    /// Permission tokens.
    #[getset(skip)]
    permissions: Permissions,
}

impl PartialOrd for Role {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Role {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id().cmp(other.id())
    }
}

#[cfg_attr(feature = "ffi", ffi_export)]
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
}

impl Identifiable for Role {
    type Id = Id;

    fn id(&self) -> &Self::Id {
        &self.id
    }
}

impl Registered for Role {
    type With = NewRole;
}

/// Builder for [`Role`]
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
#[cfg_attr(feature = "ffi", derive(IntoFfi, TryFromFfi))]
#[allow(clippy::multiple_inherent_impl)]
pub struct NewRole {
    inner: Role,
}

#[cfg(feature = "mutable_api")]
impl crate::Registrable for NewRole {
    type Target = Role;

    #[must_use]
    #[inline]
    fn build(self) -> Self::Target {
        self.inner
    }
}

impl PartialOrd for NewRole {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NewRole {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.inner.cmp(&other.inner)
    }
}

#[cfg_attr(feature = "ffi", ffi_export)]
impl NewRole {
    /// Add permission to the [`Role`]
    #[must_use]
    #[inline]
    pub fn add_permission(mut self, perm: impl Into<PermissionToken>) -> Self {
        self.inner.permissions.insert(perm.into());
        self
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

    /// Identification
    #[inline]
    pub(crate) fn id(&self) -> &<Role as Identifiable>::Id {
        &self.inner.id
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this module.
pub mod prelude {
    pub use super::{Id as RoleId, NewRole, Role};
}
