//! Iroha Data Model contains structures for Domains, Peers, Accounts and Assets with simple,
//! non-specific functions like serialization.

#![allow(clippy::module_name_repetitions)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::{fmt, fmt::Debug, ops::RangeInclusive, str::FromStr};

use derive_more::Display;
use iroha_crypto::{Hash, PublicKey};
use iroha_data_primitives::small::SmallVec;
pub use iroha_data_primitives::{fixed, small};
use iroha_macro::{error::ErrorTryFromEnum, FromVariant};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    account::SignatureCheckCondition, permissions::PermissionToken, transaction::TransactionValue,
};

pub mod account;
pub mod asset;
pub mod domain;
pub mod events;
pub mod expression;
pub mod isi;
pub mod merkle;
pub mod metadata;
pub mod pagination;
pub mod query;
pub mod transaction;

/// Error which occurs when parsing string into a data model entity
#[derive(Debug, Clone, Copy, Display)]
pub struct ParseError {
    reason: &'static str,
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

/// Error which occurs when validating data model entity
#[derive(Debug, Clone, Display)]
pub struct ValidationError {
    reason: String,
}

#[cfg(feature = "std")]
impl std::error::Error for ValidationError {}

impl ValidationError {
    /// Construct [`ValidationError`].
    pub fn new(reason: &str) -> Self {
        Self {
            reason: String::from(reason),
        }
    }
}

/// `Name` struct represents type for Iroha Entities names, like
/// [`Domain`](`domain::Domain`)'s name or
/// [`Account`](`account::Account`)'s name.
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Display,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoSchema,
)]
pub struct Name(String);

impl Name {
    /// Construct [`Name`] if `name` is valid.
    ///
    /// # Errors
    /// Fails if parsing fails
    #[inline]
    pub fn new(name: &str) -> Result<Self, ParseError> {
        name.parse::<Self>()
    }

    /// Instantly construct [`Name`] assuming `name` is valid.
    #[inline]
    #[allow(clippy::expect_used)]
    pub fn test(name: &str) -> Self {
        name.parse::<Self>()
            .expect("Valid names never fail to parse")
    }

    /// Check if `range` contains the number of chars in the inner `String` of this [`Name`].
    ///
    /// # Errors
    /// Fails if `range` does not
    pub fn validate_len(
        &self,
        range: impl Into<RangeInclusive<usize>>,
    ) -> Result<(), ValidationError> {
        let range = range.into();
        if range.contains(&self.as_ref().chars().count()) {
            Ok(())
        } else {
            Err(ValidationError::new(&format!(
                "Name must be between {} and {} characters in length.",
                &range.start(),
                &range.end()
            )))
        }
    }
}

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl FromStr for Name {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: This should also prevent '@' and '#' from being added to names.
        if s.chars().any(char::is_whitespace) {
            return Err(ParseError {
                reason: "Name must have no white-space",
            });
        }

        Ok(Self(String::from(s)))
    }
}

impl Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

/// Represents a sequence of bytes. Used for storing encoded data.
pub type Bytes = Vec<u8>;

#[allow(clippy::missing_errors_doc)]
/// [`AsMut`] but reference conversion can fail.
pub trait TryAsMut<T> {
    /// The type returned in the event of a conversion error.
    type Error;

    /// Perform the conversion.
    fn try_as_mut(&mut self) -> Result<&mut T, Self::Error>;
}

#[allow(clippy::missing_errors_doc)]
/// Similar to [`AsRef`] but indicating that this reference conversion can fail.
pub trait TryAsRef<T> {
    /// The type returned in the event of a conversion error.
    type Error;

    /// Perform the conversion.
    fn try_as_ref(&self) -> Result<&T, Self::Error>;
}

/// Error which occurs when converting an enum reference to a variant reference
#[derive(Debug, Clone, Copy, Display)]
#[display(bound = "GOT: Debug")]
#[display(
    fmt = "Expected: {}\nGot: {:?}",
    "core::any::type_name::<EXPECTED>()",
    got
)]
pub struct EnumTryAsError<EXPECTED, GOT> {
    expected: core::marker::PhantomData<EXPECTED>,
    /// Actual enum variant which was being converted
    pub got: GOT,
}

impl<EXPECTED, GOT> EnumTryAsError<EXPECTED, GOT> {
    fn got(got: GOT) -> Self {
        Self {
            expected: core::marker::PhantomData,
            got,
        }
    }
}

#[cfg(feature = "std")]
impl<EXPECTED: Debug, GOT: Debug> std::error::Error for EnumTryAsError<EXPECTED, GOT> {}

/// Represents Iroha Configuration parameters.
#[derive(
    Debug,
    Clone,
    Copy,
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
pub enum Parameter {
    /// Maximum amount of Faulty Peers in the system.
    MaximumFaultyPeersAmount(u32),
    /// Maximum time for a leader to create a block.
    BlockTime(u128),
    /// Maximum time for a proxy tail to send commit message.
    CommitTime(u128),
    /// Time to wait for a transaction Receipt.
    TransactionReceiptTime(u128),
}

/// Sized container for all possible identifications.
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
    FromVariant,
    IntoSchema,
)]
#[allow(clippy::enum_variant_names)]
pub enum IdBox {
    /// [`AccountId`](`account::Id`) variant.
    AccountId(account::Id),
    /// [`AssetId`](`asset::Id`) variant.
    AssetId(asset::Id),
    /// [`AssetDefinitionId`](`asset::DefinitionId`) variant.
    AssetDefinitionId(asset::DefinitionId),
    /// [`DomainId`](`domain::Id`) variant.
    DomainId(domain::Id),
    /// [`PeerId`](`peer::Id`) variant.
    PeerId(peer::Id),
    /// [`RoleId`](`role::Id`) variant.
    #[cfg(feature = "roles")]
    RoleId(role::Id),
    /// `World`.
    WorldId,
}

/// Sized container for all possible entities.
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
    FromVariant,
    IntoSchema,
)]
pub enum IdentifiableBox {
    /// [`Account`](`account::Account`) variant.
    Account(Box<account::Account>),
    /// [`NewAccount`](`account::NewAccount`) variant.
    NewAccount(Box<account::NewAccount>),
    /// [`Asset`](`asset::Asset`) variant.
    Asset(Box<asset::Asset>),
    /// [`AssetDefinition`](`asset::AssetDefinition`) variant.
    AssetDefinition(Box<asset::AssetDefinition>),
    /// [`Domain`](`domain::Domain`) variant.
    Domain(Box<domain::Domain>),
    /// [`Peer`](`peer::Peer`) variant.
    Peer(Box<peer::Peer>),
    /// [`Role`](`role::Role`) variant.
    #[cfg(feature = "roles")]
    Role(Box<role::Role>),
    /// `World`.
    World,
}

/// Boxed [`Value`].
pub type ValueBox = Box<Value>;

/// Sized container for all possible values.
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
    FromVariant,
    IntoSchema,
)]
#[allow(clippy::enum_variant_names)]
pub enum Value {
    /// [`u32`] integer.
    U32(u32),
    /// [`u128`] integer.
    U128(u128),
    /// [`bool`] value.
    Bool(bool),
    /// [`String`] value.
    String(String),
    /// [`Name`] value.
    Name(Name),
    /// [`fixed::Fixed`] value
    Fixed(fixed::Fixed),
    /// [`Vec`] of `Value`.
    Vec(
        #[skip_from]
        #[skip_try_from]
        Vec<Value>,
    ),
    /// Recursive inclusion of LimitedMetadata,
    LimitedMetadata(metadata::Metadata),
    /// `Id` of `Asset`, `Account`, etc.
    Id(IdBox),
    /// `Identifiable` as `Asset`, `Account` etc.
    Identifiable(IdentifiableBox),
    /// [`PublicKey`].
    PublicKey(PublicKey),
    /// Iroha `Parameter` variant.
    Parameter(Parameter),
    /// Signature check condition.
    SignatureCheckCondition(SignatureCheckCondition),
    /// Committed or rejected transactions
    TransactionValue(TransactionValue),
    /// [`PermissionToken`].
    PermissionToken(PermissionToken),
    /// [`struct@Hash`]
    Hash(Hash),
}

#[allow(clippy::len_without_is_empty)]
impl Value {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        use Value::*;

        match self {
            U32(_) | U128(_) | Id(_) | PublicKey(_) | Bool(_) | Parameter(_) | Identifiable(_)
            | String(_) | Name(_) | Fixed(_) | TransactionValue(_) | PermissionToken(_)
            | Hash(_) => 1_usize,
            Vec(v) => v.iter().map(Self::len).sum::<usize>() + 1_usize,
            LimitedMetadata(data) => data.nested_len() + 1_usize,
            SignatureCheckCondition(s) => s.0.len(),
        }
    }
}

impl<A: small::Array> From<SmallVec<A>> for Value
where
    A::Item: Into<Value>,
{
    fn from(sv: SmallVec<A>) -> Self {
        // This looks inefficient, but `Value` can only hold a
        // heap-allocated `Vec` (it's recursive) and the vector
        // conversions only do a heap allocation (if that).
        let vec: Vec<_> = sv.0.into_vec();
        vec.into()
    }
}

macro_rules! from_and_try_from_value_idbox {
    ( $($variant:ident( $ty:ty ),)* ) => {
        $(
            impl TryFrom<Value> for $ty {
                type Error = ErrorTryFromEnum<Self, Value>;

                fn try_from(value: Value) -> Result<Self, Self::Error> {
                    if let Value::Id(IdBox::$variant(id)) = value {
                        Ok(id)
                    } else {
                        Err(Self::Error::default())
                    }
                }
            }

            impl From<$ty> for Value {
                fn from(id: $ty) -> Self {
                    Value::Id(IdBox::$variant(id))
                }
            }
        )*
    };
}

from_and_try_from_value_idbox!(
    AccountId(account::Id),
    AssetId(asset::Id),
    AssetDefinitionId(asset::DefinitionId),
    DomainId(domain::Id),
    PeerId(peer::Id),
);
// TODO: Should we wrap String with new type in order to convert like here?
//from_and_try_from_value_idbox!((DomainName(Name), ErrorValueTryFromDomainName),);

macro_rules! from_and_try_from_value_identifiablebox {
    ( $( $variant:ident( Box< $ty:ty > ),)* ) => {
        $(
            impl TryFrom<Value> for $ty {
                type Error = ErrorTryFromEnum<Self, Value>;

                fn try_from(value: Value) -> Result<Self, Self::Error> {
                    if let Value::Identifiable(IdentifiableBox::$variant(id)) = value {
                        Ok(*id)
                    } else {
                        Err(Self::Error::default())
                    }
                }
            }

            impl From<$ty> for Value {
                fn from(id: $ty) -> Self {
                    Value::Identifiable(IdentifiableBox::$variant(Box::new(id)))
                }
            }
        )*
    };
}
macro_rules! from_and_try_from_value_identifiable {
    ( $( $variant:ident( $ty:ty ), )* ) => {
        $(
            impl TryFrom<Value> for $ty {
                type Error = ErrorTryFromEnum<Self, Value>;

                fn try_from(value: Value) -> Result<Self, Self::Error> {
                    if let Value::Identifiable(IdentifiableBox::$variant(id)) = value {
                        Ok(id)
                    } else {
                        Err(Self::Error::default())
                    }
                }
            }

            impl From<$ty> for Value {
                fn from(id: $ty) -> Self {
                    Value::Identifiable(IdentifiableBox::$variant(id))
                }
            }
        )*
    };
}

from_and_try_from_value_identifiablebox!(
    Account(Box<account::Account>),
    NewAccount(Box<account::NewAccount>),
    Asset(Box<asset::Asset>),
    AssetDefinition(Box<asset::AssetDefinition>),
    Domain(Box<domain::Domain>),
    Peer(Box<peer::Peer>),
);
from_and_try_from_value_identifiable!(
    Account(Box<account::Account>),
    NewAccount(Box<account::NewAccount>),
    Asset(Box<asset::Asset>),
    AssetDefinition(Box<asset::AssetDefinition>),
    Domain(Box<domain::Domain>),
    Peer(Box<peer::Peer>),
);

impl<V: Into<Value>> From<Vec<V>> for Value {
    fn from(values: Vec<V>) -> Value {
        Value::Vec(values.into_iter().map(Into::into).collect())
    }
}

impl<V> TryFrom<Value> for Vec<V>
where
    Value: TryInto<V>,
{
    type Error = ErrorTryFromEnum<Value, Self>;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Vec(vec) = value {
            return vec
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_e| Self::Error::default());
        }

        Err(Self::Error::default())
    }
}

impl<A: small::Array> TryFrom<Value> for small::SmallVec<A>
where
    Value: TryInto<A::Item>,
{
    type Error = ErrorTryFromEnum<Value, Self>;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Vec(vec) = value {
            return vec
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<small::SmallVec<_>, _>>()
                .map_err(|_e| Self::Error::default());
        }
        Err(Self::Error::default())
    }
}

/// Marker trait for values.
pub trait ValueMarker: Debug + Clone + Into<Value> {}

impl<V: Into<Value> + Debug + Clone> ValueMarker for V {}

/// This trait marks entity that implement it as identifiable with an `Id` type to find them by.
pub trait Identifiable: Debug + Clone {
    /// Defines the type of entity's identification.
    type Id: Into<IdBox> + Debug + Clone + Eq + Ord;
}

/// Limits of length of the identifiers (e.g. in [`domain::Domain`], [`account::NewAccount`], [`asset::AssetDefinition`]) in number of chars
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, Deserialize, Serialize)]
pub struct LengthLimits {
    /// Minimal length in number of chars (inclusive).
    min: u32,
    /// Maximal length in number of chars (inclusive).
    max: u32,
}

impl LengthLimits {
    /// Constructor.
    pub const fn new(min: u32, max: u32) -> Self {
        Self { min, max }
    }
}

impl From<LengthLimits> for RangeInclusive<usize> {
    #[inline]
    fn from(limits: LengthLimits) -> Self {
        RangeInclusive::new(limits.min as usize, limits.max as usize)
    }
}

/// Get the current system time as `Duration` since the unix epoch.
#[cfg(feature = "std")]
pub fn current_time() -> core::time::Duration {
    use std::time::SystemTime;

    #[allow(clippy::expect_used)]
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Failed to get the current system time")
}

#[cfg(feature = "roles")]
pub mod role {
    //! Structures, traits and impls related to `Role`s.

    #[cfg(not(feature = "std"))]
    use alloc::{boxed::Box, collections::btree_set, string::String};
    use core::fmt;
    #[cfg(feature = "std")]
    use std::collections::btree_set;

    use iroha_schema::IntoSchema;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::{permissions::PermissionToken, IdBox, Identifiable, IdentifiableBox, Name, Value};

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
    )]
    pub struct Role {
        /// Unique name of the role.
        pub id: Id,
        /// Permission tokens.
        pub permissions: btree_set::BTreeSet<PermissionToken>,
    }

    impl Role {
        /// Constructor.
        #[inline]
        pub fn new(
            id: impl Into<Id>,
            permissions: impl Into<btree_set::BTreeSet<PermissionToken>>,
        ) -> Self {
            Self {
                id: id.into(),
                permissions: permissions.into(),
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
}

pub mod permissions {
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
}

pub mod peer {
    //! This module contains [`Peer`] structure and related implementations and traits implementations.

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};
    use core::{
        cmp::Ordering,
        fmt,
        hash::{Hash, Hasher},
    };

    use iroha_schema::IntoSchema;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::{Identifiable, PublicKey, Value};

    /// Peer represents Iroha instance.
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
    )]
    pub struct Peer {
        /// Peer Identification.
        pub id: Id,
    }

    /// Peer's identification.
    ///
    /// Equality is tested by `public_key` field only.
    /// Each peer should have a unique public key.
    #[derive(Debug, Clone, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct Id {
        /// Address of the [`Peer`]'s entrypoint.
        pub address: String,
        /// Public Key of the [`Peer`].
        pub public_key: PublicKey,
    }

    impl PartialEq for Id {
        fn eq(&self, other: &Self) -> bool {
            // Comparison is done by public key only.
            // It is a system invariant that each peer has a unique public key.
            // Also it helps to handle peer id comparison without domain name resolution.
            self.public_key == other.public_key
        }
    }

    impl PartialOrd for Id {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for Id {
        fn cmp(&self, other: &Self) -> Ordering {
            self.public_key.cmp(&other.public_key)
        }
    }

    impl Hash for Id {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.public_key.hash(state);
        }
    }

    impl fmt::Display for Id {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Debug::fmt(self, f)
        }
    }

    impl Peer {
        /// Construct `Peer` given `id`.
        #[inline]
        pub const fn new(id: Id) -> Self {
            Self { id }
        }
    }

    impl Identifiable for Peer {
        type Id = Id;
    }

    impl Id {
        /// Construct `Id` given `public_key` and `address`.
        #[inline]
        pub fn new(address: &str, public_key: &PublicKey) -> Self {
            Self {
                address: String::from(address),
                public_key: public_key.clone(),
            }
        }
    }

    impl FromIterator<Id> for Value {
        fn from_iter<T: IntoIterator<Item = Id>>(iter: T) -> Self {
            iter.into_iter()
                .map(Into::into)
                .collect::<Vec<Value>>()
                .into()
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{Id as PeerId, Peer};
    }
}

/// URI that `Torii` uses to route incoming requests.
pub mod uri {
    /// Default socket for listening on external requests
    pub const DEFAULT_API_URL: &str = "127.0.0.1:8080";
    /// Query URI is used to handle incoming Query requests.
    pub const QUERY: &str = "query";
    /// Transaction URI is used to handle incoming ISI requests.
    pub const TRANSACTION: &str = "transaction";
    /// Block URI is used to handle incoming Block requests.
    pub const CONSENSUS: &str = "consensus";
    /// Health URI is used to handle incoming Healthcheck requests.
    pub const HEALTH: &str = "health";
    /// The URI used for block synchronization.
    pub const BLOCK_SYNC: &str = "block/sync";
    /// The web socket uri used to subscribe to block and transactions statuses.
    pub const SUBSCRIPTION: &str = "events";
    /// The web socket uri used to subscribe to blocks stream.
    pub const BLOCKS_STREAM: &str = "block/stream";
    /// Get pending transactions.
    pub const PENDING_TRANSACTIONS: &str = "pending_transactions";
    /// The URI for local config changing inspecting
    pub const CONFIGURATION: &str = "configuration";
    /// URI to report status for administration
    pub const STATUS: &str = "status";
    ///  Metrics URI is used to export metrics according to [Prometheus
    ///  Guidance](https://prometheus.io/docs/instrumenting/writing_exporters/).
    pub const METRICS: &str = "metrics";
}

pub mod prelude {
    //! Prelude: re-export of most commonly used traits, structs and macros in this crate.
    #[cfg(feature = "std")]
    pub use super::current_time;
    #[cfg(feature = "roles")]
    pub use super::role::prelude::*;
    pub use super::{
        account::prelude::*, asset::prelude::*, domain::prelude::*, fixed::prelude::*,
        pagination::prelude::*, peer::prelude::*, uri, Bytes, EnumTryAsError, IdBox, Identifiable,
        IdentifiableBox, Name, Parameter, TryAsMut, TryAsRef, ValidationError, Value,
    };
    pub use crate::{
        events::prelude::*, expression::prelude::*, isi::prelude::*, metadata::prelude::*,
        permissions::prelude::*, query::prelude::*, small, transaction::prelude::*,
    };
}
