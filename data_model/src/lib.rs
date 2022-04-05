//! Iroha Data Model contains structures for Domains, Peers, Accounts and Assets with simple,
//! non-specific functions like serialization.

#![allow(clippy::module_name_repetitions, clippy::unwrap_in_result)]
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
use parity_scale_codec::{Decode, Encode, Input};
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
pub mod peer;
pub mod permissions;
pub mod query;
#[cfg(feature = "roles")]
pub mod role;
pub mod transaction;
pub mod trigger;
pub mod uri;

/// Mintability logic error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintabilityError {
    /// Tried to mint an Un-mintable asset.
    MintUnmintable,
    /// Tried to forbid minting on assets that should be mintable.
    ForbidMintOnMintable,
}

impl fmt::Display for MintabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            MintabilityError::MintUnmintable => {
                "This asset cannot be minted more than once and it was already minted."
            }
            MintabilityError::ForbidMintOnMintable => {
                "This asset was set as infinitely mintable. You cannot forbid its minting."
            }
        };
        write!(f, "{}", message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MintabilityError {}

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

/// `Name` struct represents type for Iroha Entities names, like
/// [`Domain`](`domain::Domain`)'s name or
/// [`Account`](`account::Account`)'s name.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Display, Encode, Serialize, IntoSchema)]
#[repr(transparent)]
pub struct Name(String);

impl Name {
    pub(crate) const fn empty() -> Self {
        Self(String::new())
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

    fn from_str(candidate: &str) -> Result<Self, Self::Err> {
        if candidate.is_empty() {
            return Ok(Self::empty());
        }

        if candidate.chars().any(char::is_whitespace) {
            return Err(ParseError {
                reason: "White space not allowed in `Name` constructs",
            });
        }
        if candidate.chars().any(|ch| ch == '@' || ch == '#') {
            #[allow(clippy::non_ascii_literal)]
            return Err(ParseError {
                reason: "The `@` character is reserved for `account@domain` constructs, `#` — for `asset#domain`",
            });
        }
        Ok(Self(String::from(candidate)))
    }
}

impl Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<'de> Deserialize<'de> for Name {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[cfg(not(feature = "std"))]
        use alloc::borrow::Cow;
        #[cfg(feature = "std")]
        use std::borrow::Cow;

        use serde::de::Error as _;

        let name = <Cow<str>>::deserialize(deserializer)?;
        Self::from_str(&name).map_err(D::Error::custom)
    }
}
impl Decode for Name {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        let name = String::decode(input)?;
        Self::from_str(&name).map_err(|error| error.reason.into())
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
    TriggerId(<trigger::Trigger as Identifiable>::Id),
    /// [`RoleId`](`role::Id`) variant.
    #[cfg(feature = "roles")]
    RoleId(<role::Role as Identifiable>::Id),
}

/// Sized container for constructors of all [`Identifiable`]s that can be registered via transaction
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
pub enum RegistrableBox {
    /// [`Peer`](`peer::Peer`) variant.
    Peer(Box<<peer::Peer as Identifiable>::RegisteredWith>),
    /// [`Domain`](`domain::Domain`) variant.
    Domain(Box<<domain::Domain as Identifiable>::RegisteredWith>),
    /// [`Account`](`account::Account`) variant.
    Account(Box<<account::Account as Identifiable>::RegisteredWith>),
    /// [`AssetDefinition`](`asset::AssetDefinition`) variant.
    AssetDefinition(Box<<asset::AssetDefinition as Identifiable>::RegisteredWith>),
    /// [`Asset`](`asset::Asset`) variant.
    Asset(Box<<asset::Asset as Identifiable>::RegisteredWith>),
    /// [`Trigger`](`trigger::Trigger`) variant.
    Trigger(Box<<trigger::Trigger as Identifiable>::RegisteredWith>),
    /// [`Role`](`role::Role`) variant.
    #[cfg(feature = "roles")]
    Role(Box<<role::Role as Identifiable>::RegisteredWith>),
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
    /// [`Peer`](`peer::Peer`) variant.
    Peer(Box<peer::Peer>),
    /// [`NewDomain`](`domain::NewDomain`) variant.
    NewDomain(Box<<domain::Domain as Identifiable>::RegisteredWith>),
    /// [`NewAccount`](`account::NewAccount`) variant.
    NewAccount(Box<<account::Account as Identifiable>::RegisteredWith>),
    /// [`Domain`](`domain::Domain`) variant.
    Domain(Box<domain::Domain>),
    /// [`Account`](`account::Account`) variant.
    Account(Box<account::Account>),
    /// [`AssetDefinition`](`asset::AssetDefinition`) variant.
    AssetDefinition(Box<asset::AssetDefinition>),
    /// [`Asset`](`asset::Asset`) variant.
    Asset(Box<asset::Asset>),
    /// [`Trigger`](`trigger::Trigger`) variant.
    Trigger(Box<trigger::Trigger>),
    /// [`Role`](`role::Role`) variant.
    #[cfg(feature = "roles")]
    Role(Box<role::Role>),
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
);
#[cfg(feature = "roles")]
from_and_try_from_value_idbox!(RoleId(role::Id),);

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
    Peer(Box<peer::Peer>),
    Domain(Box<domain::Domain>),
    Account(Box<account::Account>),
    AssetDefinition(Box<asset::AssetDefinition>),
    Asset(Box<asset::Asset>),
    Trigger(Box<trigger::Trigger>),
);
#[cfg(feature = "roles")]
from_and_try_from_value_identifiablebox!(Role(Box<role::Role>),);

from_and_try_from_value_identifiable!(
    NewDomain(Box<domain::NewDomain>),
    NewAccount(Box<account::NewAccount>),
    Peer(Box<peer::Peer>),
    Domain(Box<domain::Domain>),
    Account(Box<account::Account>),
    AssetDefinition(Box<asset::AssetDefinition>),
    Asset(Box<asset::Asset>),
    Trigger(Box<trigger::Trigger>),
);
#[cfg(feature = "roles")]
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
            AssetDefinition(asset) => Ok(RegistrableBox::AssetDefinition(asset)),
            Asset(asset) => Ok(RegistrableBox::Asset(asset)),
            Trigger(trigger) => Ok(RegistrableBox::Trigger(trigger)),
            #[cfg(feature = "roles")]
            Role(role) => Ok(RegistrableBox::Role(role)),
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
            AssetDefinition(asset) => IdentifiableBox::AssetDefinition(asset),
            Asset(asset) => IdentifiableBox::Asset(asset),
            Trigger(trigger) => IdentifiableBox::Trigger(trigger),
            #[cfg(feature = "roles")]
            Role(role) => IdentifiableBox::Role(role),
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

/// Marker trait for values.
pub trait ValueMarker: Debug + Clone + Into<Value> {}

impl<V: Into<Value> + Debug + Clone> ValueMarker for V {}

/// This trait marks entity that implement it as identifiable with an `Id` type to find them by.
pub trait Identifiable: Debug + Clone {
    /// Type of entity's identification.
    type Id: Into<IdBox> + Debug + Clone + Eq + Ord;
    /// Type used to register `Identifiable` entity
    type RegisteredWith: Into<RegistrableBox>;
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

/// Get the current system time as `Duration` since the unix epoch.
#[cfg(feature = "std")]
pub fn current_time() -> core::time::Duration {
    use std::time::SystemTime;

    #[allow(clippy::expect_used)]
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Failed to get the current system time")
}

pub mod prelude {
    //! Prelude: re-export of most commonly used traits, structs and macros in this crate.
    #[cfg(feature = "std")]
    pub use super::current_time;
    #[cfg(feature = "roles")]
    pub use super::role::prelude::*;
    pub use super::{
        account::prelude::*, asset::prelude::*, domain::prelude::*, fixed::prelude::*,
        pagination::prelude::*, peer::prelude::*, trigger::prelude::*, uri, EnumTryAsError, IdBox,
        Identifiable, IdentifiableBox, Name, Parameter, RegistrableBox, TryAsMut, TryAsRef,
        ValidationError, Value,
    };
    pub use crate::{
        events::prelude::*, expression::prelude::*, isi::prelude::*, metadata::prelude::*,
        permissions::prelude::*, query::prelude::*, small, transaction::prelude::*,
        trigger::prelude::*,
    };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use super::*;

    const INVALID_NAMES: [&str; 3] = [" ", "@", "#"];

    #[test]
    fn deserialize_name() {
        for invalid_name in INVALID_NAMES {
            let invalid_name = Name(invalid_name.to_owned());
            let serialized = serde_json::to_string(&invalid_name).expect("Valid");
            let name = serde_json::from_str::<Name>(serialized.as_str());

            assert!(name.is_err());
        }
    }

    #[test]
    fn decode_name() {
        for invalid_name in INVALID_NAMES {
            let invalid_name = Name(invalid_name.to_owned());
            let bytes = invalid_name.encode();
            let name = Name::decode(&mut &bytes[..]);

            assert!(name.is_err());
        }
    }
}
