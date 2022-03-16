//! Structures, traits and impls related to `Role`s.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String};
use core::fmt;

use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{permissions::prelude::*, IdBox, Identifiable, IdentifiableBox, Name, Value};

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
    /// Constructor.
    #[inline]
    pub fn new(name: impl Into<Name>) -> Self {
        Self { name: name.into() }
    }
}

impl From<Name> for Id {
    #[inline]
    fn from(name: Name) -> Self {
        Self::new(name)
    }
}

impl From<Id> for Value {
    #[inline]
    fn from(id: Id) -> Self {
        Self::Id(IdBox::RoleId(id))
    }
}

impl TryFrom<Value> for Id {
    type Error = iroha_macro::error::ErrorTryFromEnum<Value, Self>;

    #[inline]
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Id(IdBox::RoleId(id)) = value {
            Ok(id)
        } else {
            Err(Self::Error::default())
        }
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl From<Role> for Value {
    #[inline]
    fn from(role: Role) -> Self {
        IdentifiableBox::from(Box::new(role)).into()
    }
}

impl TryFrom<Value> for Role {
    type Error = iroha_macro::error::ErrorTryFromEnum<Value, Self>;

    #[inline]
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Identifiable(IdentifiableBox::Role(role)) = value {
            Ok(*role)
        } else {
            Err(Self::Error::default())
        }
    }
}

/// Role is a tag for a set of permission tokens.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
pub struct Role {
    /// Unique name of the role.
    pub id: <Self as Identifiable>::Id,
    /// Permission tokens.
    pub permissions: Permissions,
}

impl Role {
    /// Constructor.
    #[inline]
    pub fn new(
        id: impl Into<<Self as Identifiable>::Id>,
        permissions: impl IntoIterator<Item = PermissionToken>,
    ) -> Self {
        Self {
            id: id.into(),
            permissions: permissions.into_iter().collect(),
        }
    }
}

impl Identifiable for Role {
    type Id = Id;
}

/// The prelude re-exports most commonly used traits, structs and macros from this module.
pub mod prelude {
    pub use super::{Id as RoleId, Role};
}
