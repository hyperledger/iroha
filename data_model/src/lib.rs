//! Iroha Data Model contains structures for Domains, Peers, Accounts and Assets with simple,
//! non-specific functions like serialization.

#![allow(clippy::module_name_repetitions, clippy::unwrap_in_result)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{
    borrow::ToOwned as _,
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt, fmt::Debug, ops::RangeInclusive};

use block_value::BlockValue;
use derive_more::Display;
use events::FilterBox;
use iroha_crypto::{Hash, PublicKey};
use iroha_data_primitives::small::SmallVec;
pub use iroha_data_primitives::{self as primitives, fixed, small};
use iroha_macro::{error::ErrorTryFromEnum, FromVariant};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    account::SignatureCheckCondition, name::Name, permissions::PermissionToken,
    transaction::TransactionValue,
};

pub mod account;
pub mod asset;
pub mod block_value;
pub mod domain;
pub mod events;
pub mod expression;
pub mod isi;
pub mod metadata;
pub mod name;
pub mod pagination;
pub mod peer;
pub mod permissions;
pub mod predicate;
pub mod query;
pub mod role;
pub mod transaction;
pub mod trigger;
pub mod uri;

/// Error which occurs when parsing string into a data model entity
#[derive(Debug, Display, Clone, Copy)]
pub struct ParseError {
    reason: &'static str,
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

/// Validation of the data model entity failed.
#[derive(Debug, Display, Clone)]
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
    const fn got(got: GOT) -> Self {
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
    Display,
    Clone,
    Copy,
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
pub enum Parameter {
    /// Maximum amount of Faulty Peers in the system.
    #[display(fmt = "Maximum number of faults is {}", _0)]
    MaximumFaultyPeersAmount(u32),
    /// Maximum time for a leader to create a block.
    #[display(fmt = "Block time: {}ms", _0)]
    BlockTime(u128),
    /// Maximum time for a proxy tail to send commit message.
    #[display(fmt = "Commit time: {}ms", _0)]
    CommitTime(u128),
    /// Time to wait for a transaction Receipt.
    #[display(fmt = "Transaction receipt time: {}ms", _0)]
    TransactionReceiptTime(u128),
}

/// Sized container for all possible identifications.
#[derive(
    Debug,
    Display,
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
    /// [`DomainId`](`domain::Id`) variant.
    DomainId(<domain::Domain as Identifiable>::Id),
    /// [`AccountId`](`account::Id`) variant.
    AccountId(<account::Account as Identifiable>::Id),
    /// [`AssetDefinitionId`](`asset::DefinitionId`) variant.
    AssetDefinitionId(<asset::AssetDefinition as Identifiable>::Id),
    /// [`AssetId`](`asset::Id`) variant.
    AssetId(<asset::Asset as Identifiable>::Id),
    /// [`PeerId`](`peer::Id`) variant.
    PeerId(<peer::Peer as Identifiable>::Id),
    /// [`TriggerId`](trigger::Id) variant.
    TriggerId(<trigger::Trigger<FilterBox> as Identifiable>::Id),
    /// [`RoleId`](`role::Id`) variant.
    RoleId(<role::Role as Identifiable>::Id),
}

impl Identifiable for IdBox {
    type Id = Self;

    fn id(&self) -> &Self::Id {
        self
    }
}

/// Sized container for constructors of all [`Identifiable`]s that can be registered via transaction
#[derive(
    Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum RegistrableBox {
    /// [`Peer`](`peer::Peer`) variant.
    Peer(Box<<peer::Peer as Registered>::With>),
    /// [`Domain`](`domain::Domain`) variant.
    Domain(Box<<domain::Domain as Registered>::With>),
    /// [`Account`](`account::Account`) variant.
    Account(Box<<account::Account as Registered>::With>),
    /// [`AssetDefinition`](`asset::AssetDefinition`) variant.
    AssetDefinition(Box<<asset::AssetDefinition as Registered>::With>),
    /// [`Asset`](`asset::Asset`) variant.
    Asset(Box<<asset::Asset as Registered>::With>),
    /// [`Trigger`](`trigger::Trigger`) variant.
    Trigger(Box<<trigger::Trigger<FilterBox> as Registered>::With>),
    /// [`Role`](`role::Role`) variant.
    Role(Box<<role::Role as Registered>::With>),
}

/// Sized container for all possible entities.
#[derive(
    Debug,
    Display,
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
    /// [`NewDomain`](`domain::NewDomain`) variant.
    NewDomain(Box<<domain::Domain as Registered>::With>),
    /// [`NewAccount`](`account::NewAccount`) variant.
    NewAccount(Box<<account::Account as Registered>::With>),
    /// [`NewAssetDefinition`](`asset::NewAssetDefinition`) variant.
    NewAssetDefinition(Box<<asset::AssetDefinition as Registered>::With>),
    /// [`NewRole`](`role::NewRole`) variant.
    NewRole(Box<<role::Role as Registered>::With>),
    /// [`Peer`](`peer::Peer`) variant.
    Peer(Box<peer::Peer>),
    /// [`Domain`](`domain::Domain`) variant.
    Domain(Box<domain::Domain>),
    /// [`Account`](`account::Account`) variant.
    Account(Box<account::Account>),
    /// [`AssetDefinition`](`asset::AssetDefinition`) variant.
    AssetDefinition(Box<asset::AssetDefinition>),
    /// [`Asset`](`asset::Asset`) variant.
    Asset(Box<asset::Asset>),
    /// [`Trigger`](`trigger::Trigger`) variant.
    Trigger(Box<trigger::Trigger<FilterBox>>),
    /// [`Role`](`role::Role`) variant.
    Role(Box<role::Role>),
}

// TODO: think of a way to `impl Identifiable for IdentifiableBox`.
// The main problem is lifetimes and conversion cost.

impl IdentifiableBox {
    fn id_box(&self) -> IdBox {
        match self {
            IdentifiableBox::NewDomain(a) => a.id().clone().into(),
            IdentifiableBox::NewAccount(a) => a.id().clone().into(),
            IdentifiableBox::NewAssetDefinition(a) => a.id().clone().into(),
            IdentifiableBox::NewRole(a) => a.id().clone().into(),
            IdentifiableBox::Peer(a) => a.id().clone().into(),
            IdentifiableBox::Domain(a) => a.id().clone().into(),
            IdentifiableBox::Account(a) => a.id().clone().into(),
            IdentifiableBox::AssetDefinition(a) => a.id().clone().into(),
            IdentifiableBox::Asset(a) => a.id().clone().into(),
            IdentifiableBox::Trigger(a) => a.id().clone().into(),
            IdentifiableBox::Role(a) => a.id().clone().into(),
        }
    }
}

/// Boxed [`Value`].
pub type ValueBox = Box<Value>;

/// Sized container for all possible values.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    FromVariant,
    IntoSchema,
    PartialOrd,
    Ord,
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
    /// `impl Identifiable` as in `Asset`, `Account` etc.
    Identifiable(IdentifiableBox),
    /// [`PublicKey`].
    PublicKey(PublicKey),
    /// Iroha [`Parameter`] variant.
    Parameter(Parameter),
    /// Signature check condition.
    SignatureCheckCondition(SignatureCheckCondition),
    /// Committed or rejected transactions
    TransactionValue(TransactionValue),
    /// [`PermissionToken`].
    PermissionToken(PermissionToken),
    /// [`struct@Hash`]
    Hash(Hash),
    /// Block
    Block(BlockValue),
}

impl fmt::Display for Value {
    // TODO: Maybe derive
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::U32(v) => fmt::Display::fmt(&v, f),
            Value::U128(v) => fmt::Display::fmt(&v, f),
            Value::Bool(v) => fmt::Display::fmt(&v, f),
            Value::String(v) => fmt::Display::fmt(&v, f),
            Value::Name(v) => fmt::Display::fmt(&v, f),
            Value::Fixed(v) => fmt::Display::fmt(&v, f),
            #[allow(clippy::use_debug)]
            Value::Vec(v) => {
                // TODO: Remove so we can derive.
                let list_of_display: Vec<_> = v.iter().map(ToString::to_string).collect();
                // this prints with quotation marks, which is fine 90%
                // of the time, and helps delineate where a display of
                // one value stops and another one begins.
                write!(f, "{:?}", list_of_display)
            }
            Value::LimitedMetadata(v) => fmt::Display::fmt(&v, f),
            Value::Id(v) => fmt::Display::fmt(&v, f),
            Value::Identifiable(v) => fmt::Display::fmt(&v, f),
            Value::PublicKey(v) => fmt::Display::fmt(&v, f),
            Value::Parameter(v) => fmt::Display::fmt(&v, f),
            Value::SignatureCheckCondition(v) => fmt::Display::fmt(&v, f),
            Value::TransactionValue(_) => write!(f, "TransactionValue"),
            Value::PermissionToken(v) => fmt::Display::fmt(&v, f),
            Value::Hash(v) => fmt::Display::fmt(&v, f),
            Value::Block(v) => fmt::Display::fmt(&v, f),
        }
    }
}

#[allow(clippy::len_without_is_empty)]
impl Value {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        use Value::*;

        match self {
            U32(_) | U128(_) | Id(_) | PublicKey(_) | Bool(_) | Parameter(_) | Identifiable(_)
            | String(_) | Name(_) | Fixed(_) | TransactionValue(_) | PermissionToken(_)
            | Hash(_) | Block(_) => 1_usize,
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
        let vec: Vec<_> = sv.into_vec();
        vec.into()
    }
}

// TODO: This macro looks very similar to `from_and_try_from_value_identifiable`
// and `from_and_try_from_value_identifiablebox` macros. It should be possible to
// generalize them under one macro
macro_rules! from_and_try_from_value_idbox {
    ( $($variant:ident( $ty:ty ),)* $(,)? ) => {
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
    PeerId(peer::Id),
    DomainId(domain::Id),
    AccountId(account::Id),
    AssetId(asset::Id),
    AssetDefinitionId(asset::DefinitionId),
    TriggerId(trigger::Id),
    RoleId(role::Id),
);

// TODO: Should we wrap String with new type in order to convert like here?
//from_and_try_from_value_idbox!((DomainName(Name), ErrorValueTryFromDomainName),);

macro_rules! from_and_try_from_value_identifiablebox {
    ( $( $variant:ident( Box< $ty:ty > ),)* $(,)? ) => {
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
    ( $( $variant:ident( $ty:ty ), )* $(,)? ) => {
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
    NewDomain(Box<domain::NewDomain>),
    NewAccount(Box<account::NewAccount>),
    NewAssetDefinition(Box<asset::NewAssetDefinition>),
    NewRole(Box<role::NewRole>),
    Peer(Box<peer::Peer>),
    Domain(Box<domain::Domain>),
    Account(Box<account::Account>),
    AssetDefinition(Box<asset::AssetDefinition>),
    Asset(Box<asset::Asset>),
    Trigger(Box<trigger::Trigger<FilterBox>>),
    Role(Box<role::Role>),
);

from_and_try_from_value_identifiable!(
    NewDomain(Box<domain::NewDomain>),
    NewAccount(Box<account::NewAccount>),
    NewAssetDefinition(Box<asset::NewAssetDefinition>),
    Peer(Box<peer::Peer>),
    Domain(Box<domain::Domain>),
    Account(Box<account::Account>),
    AssetDefinition(Box<asset::AssetDefinition>),
    Asset(Box<asset::Asset>),
    Trigger(Box<trigger::Trigger<FilterBox>>),
);

from_and_try_from_value_identifiable!(Role(Box<role::Role>),);

impl TryFrom<Value> for RegistrableBox {
    type Error = ErrorTryFromEnum<Self, Value>;

    fn try_from(source: Value) -> Result<Self, Self::Error> {
        if let Value::Identifiable(identifiable) = source {
            identifiable
                .try_into()
                .map_err(|_err| Self::Error::default())
        } else {
            Err(Self::Error::default())
        }
    }
}

impl From<RegistrableBox> for Value {
    fn from(source: RegistrableBox) -> Self {
        let identifiable = source.into();
        Value::Identifiable(identifiable)
    }
}

impl TryFrom<IdentifiableBox> for RegistrableBox {
    type Error = ErrorTryFromEnum<Self, IdentifiableBox>;

    fn try_from(source: IdentifiableBox) -> Result<Self, Self::Error> {
        use IdentifiableBox::*;

        match source {
            Peer(peer) => Ok(RegistrableBox::Peer(peer)),
            NewDomain(domain) => Ok(RegistrableBox::Domain(domain)),
            NewAccount(account) => Ok(RegistrableBox::Account(account)),
            NewAssetDefinition(asset) => Ok(RegistrableBox::AssetDefinition(asset)),
            NewRole(role) => Ok(RegistrableBox::Role(role)),
            Asset(asset) => Ok(RegistrableBox::Asset(asset)),
            Trigger(trigger) => Ok(RegistrableBox::Trigger(trigger)),
            _ => Err(Self::Error::default()),
        }
    }
}

impl From<RegistrableBox> for IdentifiableBox {
    fn from(registrable: RegistrableBox) -> Self {
        use RegistrableBox::*;

        match registrable {
            Peer(peer) => IdentifiableBox::Peer(peer),
            Domain(domain) => IdentifiableBox::NewDomain(domain),
            Account(account) => IdentifiableBox::NewAccount(account),
            AssetDefinition(asset) => IdentifiableBox::NewAssetDefinition(asset),
            Role(role) => IdentifiableBox::NewRole(role),
            Asset(asset) => IdentifiableBox::Asset(asset),
            Trigger(trigger) => IdentifiableBox::Trigger(trigger),
        }
    }
}

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

/// This trait marks entity that implement it as identifiable with an
/// `Id` type. `Id`s are unique, which is relevant for `PartialOrd`
/// and `PartialCmp` implementations.
pub trait Identifiable: Debug {
    /// The type of the `Id` of the entity.
    type Id: Into<IdBox> + fmt::Display + fmt::Debug + Clone + Eq + Ord;

    /// Get reference to the type's `Id`. There should be no other
    /// inherent `impl` with the same name (e.g. `getset`).
    fn id(&self) -> &Self::Id;
}

/// Trait that marks the entity as having metadata.
pub trait HasMetadata {
    // type Metadata = metadata::Metadata;
    // Uncomment when stable.

    /// The metadata associated to this object.
    fn metadata(&self) -> &metadata::Metadata;
}

/// Trait for objects that are registered by proxy.
pub trait Registered: Identifiable {
    /// The proxy type that is used to register this entity. Usually
    /// `Self`, but if you have a complex structure where most fields
    /// would be empty, to save space you create a builder for it, and
    /// set `With` to the builder's type.
    type With: Into<RegistrableBox>;
}

/// Limits of length of the identifiers (e.g. in [`domain::Domain`], [`account::Account`], [`asset::AssetDefinition`]) in number of chars
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

/// Trait for generic predicates.
pub trait PredicateTrait<T: ?Sized> {
    /// The result of applying the predicate to a value.
    fn applies(&self, input: &T) -> bool;
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

#[cfg(feature = "ffi_api")]
mod ffi {
    use iroha_ffi::{gen_ffi_impl, handles};

    use super::*;

    handles! {0,
        account::Account,
        asset::Asset,
        domain::Domain,
        metadata::Metadata,
        permissions::PermissionToken,
        role::Role,
        Name,

        iroha_crypto::PublicKey,
        iroha_crypto::PrivateKey,
        iroha_crypto::KeyPair
    }

    gen_ffi_impl! { Clone:
        account::Account,
        asset::Asset,
        domain::Domain,
        metadata::Metadata,
        permissions::PermissionToken,
        role::Role,
        Name,

        iroha_crypto::PublicKey,
        iroha_crypto::PrivateKey,
        iroha_crypto::KeyPair
    }
    gen_ffi_impl! { Eq:
        account::Account,
        asset::Asset,
        domain::Domain,
        metadata::Metadata,
        permissions::PermissionToken,
        role::Role,
        Name,

        iroha_crypto::PublicKey,
        iroha_crypto::PrivateKey,
        iroha_crypto::KeyPair
    }
    gen_ffi_impl! { Ord:
        account::Account,
        asset::Asset,
        domain::Domain,
        permissions::PermissionToken,
        role::Role,
        Name,

        iroha_crypto::PublicKey
    }
    gen_ffi_impl! { Drop:
        account::Account,
        asset::Asset,
        domain::Domain,
        metadata::Metadata,
        permissions::PermissionToken,
        role::Role,
        Name,

        iroha_crypto::PublicKey,
        iroha_crypto::PrivateKey,
        iroha_crypto::KeyPair
    }
}

pub mod prelude {
    //! Prelude: re-export of most commonly used traits, structs and macros in this crate.
    #[cfg(feature = "std")]
    pub use super::current_time;
    pub use super::{
        account::prelude::*,
        asset::prelude::*,
        block_value::prelude::*,
        domain::prelude::*,
        fixed::prelude::*,
        name::prelude::*,
        pagination::{prelude::*, Pagination},
        peer::prelude::*,
        role::prelude::*,
        trigger::prelude::*,
        uri, EnumTryAsError, HasMetadata, IdBox, Identifiable, IdentifiableBox, Parameter,
        PredicateTrait, RegistrableBox, TryAsMut, TryAsRef, ValidationError, Value,
    };
    pub use crate::{
        events::prelude::*, expression::prelude::*, isi::prelude::*, metadata::prelude::*,
        permissions::prelude::*, query::prelude::*, small, transaction::prelude::*,
        trigger::prelude::*,
    };
}
