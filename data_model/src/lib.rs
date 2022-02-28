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
pub mod peer;
pub mod permissions;
pub mod query;
#[cfg(feature = "roles")]
pub mod role;
pub mod transaction;
pub mod uri;

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
    /// [`TriggerId`](trigger::Id) variant.
    TriggerId(trigger::Id),
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
    /// [`Trigger`](`trigger::Trigger`) variant.
    Trigger(Box<trigger::Trigger>),
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

pub mod trigger {
    //! Structures traits and impls related to `Trigger`s.

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};
    use core::cmp::Ordering;

    use iroha_schema::IntoSchema;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::{
        metadata::Metadata, prelude::EventFilter, transaction::Executable, Identifiable, Name,
        ParseError,
    };

    /// Type which is used for registering a `Trigger`.
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
    pub struct Trigger {
        /// [`Id`] of the [`Trigger`].
        pub id: Id,
        /// Action to be performed when the trigger matches.
        pub action: Action,
        /// Metadata of this account as a key-value store.
        pub metadata: Metadata,
    }

    impl Trigger {
        /// Construct trigger, given name action and signatories.
        ///
        /// # Errors
        /// - Name is malformed
        pub fn new(name: &str, action: Action) -> Result<Self, ParseError> {
            let id = Id {
                name: Name::new(name)?,
            };
            Ok(Trigger {
                id,
                action,
                metadata: Metadata::new(),
            })
        }
    }

    /// Designed to differentiate between oneshot and unlimited
    /// triggers. If the trigger must be run a limited number of times,
    /// it's the end-user's responsibility to either unregister the
    /// `Unlimited` variant.
    ///
    /// # Considerations
    ///
    /// The granularity might not be sufficient to run an action exactly
    /// `n` times. In order to ensure that it is even possible to run the
    /// triggers without gaps, the `Executable` wrapped in the action must
    /// be run before any of the ISIs are pushed into the queue of the
    /// next block.
    #[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, IntoSchema)]
    pub struct Action {
        /// The executable linked to this action
        pub executable: Executable,
        /// The repeating scheme of the action. It's kept as part of the
        /// action and not inside the [`Trigger`] type, so that further
        /// sanity checking can be done.
        pub repeats: Repeats,
        /// Technical account linked to this trigger. The technical
        /// account must already exist in order for `Register<Trigger>` to
        /// work.
        pub technical_account: super::account::Id,
        /// Each trigger should be given a name. As with every other
        /// instance of [`Name`] it has to exlclude whitespace.
        pub filter: EventFilter,
    }

    impl Action {
        /// Construct an action given `executable`, `repeats`, `technical_account` and `filter`.
        pub fn new(
            executable: impl Into<Executable>,
            repeats: impl Into<Repeats>,
            technical_account: super::account::Id,
            filter: EventFilter,
        ) -> Action {
            Action {
                executable: executable.into(),
                repeats: repeats.into(),
                // TODO: At this point the technical account is meaningless.
                technical_account,
                filter,
            }
        }
    }

    impl PartialOrd for Action {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for Action {
        fn cmp(&self, other: &Self) -> Ordering {
            // Exclude the executable. When debugging and replacing
            // the trigger, its position in Hash and Tree maps should
            // not change depending on the content.
            match self.repeats.cmp(&other.repeats) {
                Ordering::Equal => {}
                ord => return ord,
            }
            self.technical_account.cmp(&other.technical_account)
        }
    }

    /// Enumeration of possible repetitions schemes.
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialOrd,
        Ord,
        PartialEq,
        Eq,
        Encode,
        Decode,
        Serialize,
        Deserialize,
        IntoSchema,
    )]
    pub enum Repeats {
        /// Repeat indefinitely, until the trigger is unregistered.
        Indefinitely,
        /// Repeat a set number of times
        Exactly(u32), // If you need more, use `Indefinitely`.
    }

    impl From<u32> for Repeats {
        fn from(num: u32) -> Self {
            Repeats::Exactly(num)
        }
    }

    /// Identification of a `Trigger`.
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
        /// Name given to trigger by its creator.
        pub name: Name,
    }

    impl Identifiable for Trigger {
        type Id = Id;
    }

    impl Id {
        /// Construct [`Id`], while performing lenght checks and acceptable character validation.
        ///
        /// # Errors
        /// If name contains invalid characters.
        pub fn new(name: &str) -> Result<Self, ParseError> {
            Ok(Self {
                name: Name::new(name)?,
            })
        }

        /// Unchecked variant of [`Self::new`]. Does not panic on error.
        pub fn test(name: &str) -> Self {
            Self {
                name: Name::test(name),
            }
        }
    }

    pub mod prelude {
        //! Re-exports of commonly used types.
        pub use super::{Action, Id as TriggerId, Repeats, Trigger};
    }
}
pub mod prelude {
    //! Prelude: re-export of most commonly used traits, structs and macros in this crate.
    #[cfg(feature = "std")]
    pub use super::current_time;
    #[cfg(feature = "roles")]
    pub use super::role::prelude::*;
    pub use super::{
        account::prelude::*, asset::prelude::*, domain::prelude::*, fixed::prelude::*,
        pagination::prelude::*, peer::prelude::*, trigger::prelude::*, uri, Bytes, EnumTryAsError,
        IdBox, Identifiable, IdentifiableBox, Name, Parameter, TryAsMut, TryAsRef, ValidationError,
        Value,
    };
    pub use crate::{
        events::prelude::*, expression::prelude::*, isi::prelude::*, metadata::prelude::*,
        permissions::prelude::*, query::prelude::*, small, transaction::prelude::*,
        trigger::prelude::*,
    };
}
