//! Iroha Data Model contains structures for Domains, Peers, Accounts and Assets with simple,
//! non-specific functions like serialization.

#![allow(clippy::module_name_repetitions)]

use std::{
    error,
    fmt::{self, Debug},
    ops::RangeInclusive,
    str,
    time::{Duration, SystemTime},
};

use eyre::{eyre, Error, Result, WrapErr};
use iroha_crypto::{Hash, PublicKey};
use iroha_macro::{error::ErrorTryFromEnum, FromVariant};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    account::SignatureCheckCondition, permissions::PermissionToken, transaction::TransactionValue,
};

pub mod events;
pub mod expression;
pub mod fixed;
pub mod isi;
pub mod merkle;
pub mod metadata;
pub mod query;
pub mod transaction;

/// `Name` struct represents type for Iroha Entities names, like
/// [`Domain`](`domain::Domain`)'s name or
/// [`Account`](`account::Account`)'s name.
#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
pub struct Name(String);

impl Name {
    /// Construct [`Name`] if `name` is valid.
    ///
    /// # Errors
    /// Fails if parsing fails
    #[inline]
    pub fn new(name: &str) -> Result<Self> {
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
    pub fn validate_len(&self, range: impl Into<RangeInclusive<usize>>) -> Result<()> {
        let range = range.into();
        if range.contains(&self.as_ref().chars().count()) {
            Ok(())
        } else {
            Err(eyre!(
                "The number of chars in the name must be {} to {}",
                &range.start(),
                &range.end()
            ))
        }
    }
}

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl str::FromStr for Name {
    type Err = Error;
    fn from_str(str: &str) -> Result<Self, Self::Err> {
        if str.chars().any(char::is_whitespace) {
            return Err(eyre!("Name must have no whitespaces"));
        }
        Ok(Self(str.to_owned()))
    }
}

impl Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
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
    /// [`DomainId`](`Id`) variant.
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
    /// [`World`](`world::World`).
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
    /// [`Fixed`] value
    Fixed(fixed::Fixed),
    /// [`Vec`] of `Value`.
    Vec(
        #[skip_from]
        #[skip_try_from]
        Vec<Value>,
    ),
    /// Recursive inclusion of LimitedMetadata,
    LimitedMetadata(metadata::Metadata),
    /// [`Id`] of [`Asset`], [`Account`], etc.
    Id(IdBox),
    /// [`Identifiable`] as [`Asset`], [`Account`] etc.
    Identifiable(IdentifiableBox),
    /// [`PublicKey`].
    PublicKey(PublicKey),
    /// Iroha `Parameter` variant.
    Parameter(Parameter),
    /// Signature check condition.
    SignatureCheckCondition(SignatureCheckCondition),
    /// Committed or rejected transactions
    TransactionValue(TransactionValue),
    /// Permission token.
    PermissionToken(PermissionToken),
    /// Hash
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
    V: TryFrom<Value>,
    <V as TryFrom<Value>>::Error: Send + Sync + error::Error + 'static,
{
    type Error = eyre::Error;
    fn try_from(value: Value) -> Result<Vec<V>> {
        if let Value::Vec(vec) = value {
            vec.into_iter()
                .map(V::try_from)
                .collect::<Result<Vec<_>, _>>()
                .wrap_err("Failed to convert to vector")
        } else {
            Err(eyre::eyre!("Expected vector, but found something else"))
        }
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
pub fn current_time() -> Duration {
    #[allow(clippy::expect_used)]
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Failed to get the current system time")
}

#[cfg(feature = "roles")]
pub mod role {
    //! Structures, traits and impls related to `Role`s.

    use std::{
        collections::BTreeSet,
        convert::TryFrom,
        fmt::{Display, Formatter, Result as FmtResult},
    };

    use dashmap::DashMap;
    use iroha_schema::IntoSchema;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::{permissions::PermissionToken, IdBox, Identifiable, IdentifiableBox, Name, Value};

    /// `RolesMap` provides an API to work with collection of key (`Id`) - value (`Role`) pairs.
    pub type RolesMap = DashMap<Id, Role>;

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

    impl Display for Id {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
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
        pub permissions: BTreeSet<PermissionToken>,
    }

    impl Role {
        /// Constructor.
        #[inline]
        pub fn new(id: impl Into<Id>, permissions: impl Into<BTreeSet<PermissionToken>>) -> Self {
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

    use std::collections::BTreeMap;

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
        pub params: BTreeMap<Name, Value>,
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

pub mod account {
    //! Structures, traits and impls related to `Account`s.

    use std::{
        collections::{BTreeMap, BTreeSet},
        fmt,
    };

    use eyre::{eyre, Error, Result};
    //TODO: get rid of it?
    use iroha_crypto::SignatureOf;
    use iroha_schema::IntoSchema;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    #[cfg(feature = "roles")]
    use crate::role::Id as RoleId;
    use crate::{
        asset::AssetsMap,
        domain::prelude::*,
        expression::{ContainsAny, ContextValue, EvaluatesTo, ExpressionBox, WhereBuilder},
        metadata::Metadata,
        permissions::PermissionToken,
        transaction::Payload,
        Identifiable, Name, PublicKey, Value,
    };

    /// `AccountsMap` provides an API to work with collection of key (`Id`) - value
    /// (`Account`) pairs.
    pub type AccountsMap = BTreeMap<Id, Account>;

    /// Collection of [`PermissionToken`]s
    pub type Permissions = BTreeSet<PermissionToken>;

    type Signatories = Vec<PublicKey>;

    /// Genesis account name.
    pub const GENESIS_ACCOUNT_NAME: &str = "genesis";

    /// The context value name for transaction signatories.
    pub const TRANSACTION_SIGNATORIES_VALUE: &str = "transaction_signatories";

    /// The context value name for account signatories.
    pub const ACCOUNT_SIGNATORIES_VALUE: &str = "account_signatories";

    /// Genesis account. Used to mainly be converted to ordinary `Account` struct.
    #[derive(Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct GenesisAccount {
        public_key: PublicKey,
    }

    impl GenesisAccount {
        /// Returns `GenesisAccount` instance.
        pub const fn new(public_key: PublicKey) -> Self {
            GenesisAccount { public_key }
        }
    }

    impl From<GenesisAccount> for Account {
        #[inline]
        fn from(account: GenesisAccount) -> Self {
            Account::with_signatory(Id::genesis(), account.public_key)
        }
    }

    /// Condition which checks if the account has the right signatures.
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
    pub struct SignatureCheckCondition(pub EvaluatesTo<bool>);

    impl SignatureCheckCondition {
        /// Gets reference to the raw `ExpressionBox`.
        #[inline]
        pub const fn as_expression(&self) -> &ExpressionBox {
            let Self(condition) = self;
            &condition.expression
        }
    }

    impl From<EvaluatesTo<bool>> for SignatureCheckCondition {
        #[inline]
        fn from(condition: EvaluatesTo<bool>) -> Self {
            SignatureCheckCondition(condition)
        }
    }

    /// Default signature condition check for accounts. Returns true if any of the signatories have signed a transaction.
    impl Default for SignatureCheckCondition {
        #[inline]
        fn default() -> Self {
            Self(
                ContainsAny::new(
                    ContextValue::new(TRANSACTION_SIGNATORIES_VALUE),
                    ContextValue::new(ACCOUNT_SIGNATORIES_VALUE),
                )
                .into(),
            )
        }
    }

    /// Type which is used for registering `Account`
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
    pub struct NewAccount {
        /// An Identification of the `NewAccount`.
        pub id: Id,
        /// `Account`'s signatories.
        pub signatories: Signatories,
        /// Metadata of this account as a key-value store.
        pub metadata: Metadata,
    }

    impl From<NewAccount> for Account {
        #[inline]
        fn from(account: NewAccount) -> Self {
            let NewAccount {
                id,
                signatories,
                metadata,
            } = account;
            Self {
                id,
                signatories,
                metadata,
                assets: AssetsMap::new(),
                permission_tokens: Permissions::default(),
                signature_check_condition: SignatureCheckCondition::default(),
                #[cfg(feature = "roles")]
                roles: BTreeSet::default(),
            }
        }
    }

    impl NewAccount {
        /// Construct [`NewAccount`].
        #[inline]
        pub fn new(id: Id) -> Self {
            Self {
                id,
                signatories: Signatories::new(),
                metadata: Metadata::default(),
            }
        }

        /// Account with single `signatory` constructor.
        #[inline]
        pub fn with_signatory(id: Id, signatory: PublicKey) -> Self {
            let signatories = vec![signatory];
            Self {
                id,
                signatories,
                metadata: Metadata::default(),
            }
        }
    }

    /// Account entity is an authority which is used to execute `Iroha Special Instructions`.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct Account {
        /// An Identification of the [`Account`].
        pub id: Id,
        /// Asset's in this [`Account`].
        pub assets: AssetsMap,
        /// [`Account`]'s signatories.
        pub signatories: Signatories,
        /// Permissions tokens of this account
        pub permission_tokens: Permissions,
        /// Condition which checks if the account has the right signatures.
        #[serde(default)]
        pub signature_check_condition: SignatureCheckCondition,
        /// Metadata of this account as a key-value store.
        pub metadata: Metadata,
        /// Roles of this account, they are tags for sets of permissions stored in [`World`].
        #[cfg(feature = "roles")]
        pub roles: BTreeSet<RoleId>,
    }

    impl PartialOrd for Account {
        #[inline]
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            self.id.partial_cmp(&other.id)
        }
    }

    impl Ord for Account {
        #[inline]
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.id.cmp(&other.id)
        }
    }

    /// Identification of an Account. Consists of Account's name and Domain's name.
    ///
    /// # Example
    ///
    /// ```
    /// use iroha_data_model::account::Id;
    ///
    /// let id = Id::new("user", "company");
    /// ```
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
        /// [`Account`]'s name.
        pub name: Name,
        /// [`Account`]'s [`Domain`](`crate::domain::Domain`)'s id.
        pub domain_id: DomainId,
    }

    impl Account {
        /// Construct [`Account`].
        #[inline]
        pub fn new(id: Id) -> Self {
            Self {
                id,
                assets: AssetsMap::new(),
                signatories: Vec::new(),
                permission_tokens: Permissions::new(),
                signature_check_condition: SignatureCheckCondition::default(),
                metadata: Metadata::new(),
                #[cfg(feature = "roles")]
                roles: BTreeSet::new(),
            }
        }

        /// Account with single `signatory` constructor.
        #[inline]
        pub fn with_signatory(id: Id, signatory: PublicKey) -> Self {
            let signatories = vec![signatory];
            Self {
                id,
                assets: AssetsMap::new(),
                signatories,
                permission_tokens: Permissions::new(),
                signature_check_condition: SignatureCheckCondition::default(),
                metadata: Metadata::new(),
                #[cfg(feature = "roles")]
                roles: BTreeSet::new(),
            }
        }

        /// Returns a prebuilt expression that when executed
        /// returns if the needed signatures are gathered.
        pub fn check_signature_condition<'a>(
            &'a self,
            signatures: impl IntoIterator<Item = &'a SignatureOf<Payload>>,
        ) -> EvaluatesTo<bool> {
            let transaction_signatories: Signatories = signatures
                .into_iter()
                .map(|signature| &signature.public_key)
                .cloned()
                .collect();
            WhereBuilder::evaluate(self.signature_check_condition.as_expression().clone())
                .with_value(
                    TRANSACTION_SIGNATORIES_VALUE.to_owned(),
                    transaction_signatories,
                )
                .with_value(
                    ACCOUNT_SIGNATORIES_VALUE.to_owned(),
                    self.signatories.clone(),
                )
                .build()
                .into()
        }

        /// Inserts permission token into account.
        #[inline]
        pub fn insert_permission_token(&mut self, token: PermissionToken) -> bool {
            self.permission_tokens.insert(token)
        }
    }

    impl Id {
        /// Construct [`Id`] from an account `name` and a `domain_name` if these names are valid.
        ///
        /// # Errors
        /// Fails if any sub-construction fails
        #[inline]
        pub fn new(name: &str, domain_name: &str) -> Result<Self> {
            Ok(Self {
                name: Name::new(name)?,
                domain_id: DomainId::new(domain_name)?,
            })
        }

        /// Instantly construct [`Id`] from an account `name` and a `domain_name` assuming these names are valid.
        #[inline]
        pub fn test(name: &str, domain_name: &str) -> Self {
            Self {
                name: Name::test(name),
                domain_id: DomainId::test(domain_name),
            }
        }

        /// Construct [`Id`] of the genesis account.
        #[inline]
        pub fn genesis() -> Self {
            Self {
                name: Name::test(GENESIS_ACCOUNT_NAME),
                domain_id: DomainId::test(GENESIS_DOMAIN_NAME),
            }
        }
    }

    impl Identifiable for NewAccount {
        type Id = Id;
    }

    impl Identifiable for Account {
        type Id = Id;
    }

    impl FromIterator<Account> for Value {
        fn from_iter<T: IntoIterator<Item = Account>>(iter: T) -> Self {
            iter.into_iter()
                .map(Into::into)
                .collect::<Vec<Self>>()
                .into()
        }
    }

    /// Account Identification is represented by `name@domain_name` string.
    impl std::str::FromStr for Id {
        type Err = Error;

        fn from_str(string: &str) -> Result<Self, Self::Err> {
            let vector: Vec<&str> = string.split('@').collect();
            if vector.len() != 2 {
                return Err(eyre!("Id should have format `name@domain_name`"));
            }
            Ok(Self {
                name: Name::new(vector[0])?,
                domain_id: DomainId::new(vector[1])?,
            })
        }
    }

    impl fmt::Display for Id {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}@{}", self.name, self.domain_id)
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{Account, Id as AccountId, NewAccount, SignatureCheckCondition};
    }
}

pub mod asset {
    //! This module contains [`Asset`] structure, it's implementation and related traits and
    //! instructions implementations.

    use std::{
        cmp::Ordering,
        collections::BTreeMap,
        fmt::{self, Display, Formatter},
        str::FromStr,
    };

    use eyre::{eyre, Error, Result, WrapErr};
    use iroha_macro::FromVariant;
    use iroha_schema::IntoSchema;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::{
        account::prelude::*,
        domain::prelude::*,
        fixed,
        fixed::Fixed,
        metadata::{Limits as MetadataLimits, Metadata},
        Identifiable, Name, TryAsMut, TryAsRef, Value,
    };

    /// [`AssetsMap`] provides an API to work with collection of key ([`Id`]) - value
    /// ([`Asset`]) pairs.
    pub type AssetsMap = BTreeMap<Id, Asset>;
    /// [`AssetDefinitionsMap`] provides an API to work with collection of key ([`DefinitionId`]) - value
    /// (`AssetDefinition`) pairs.
    pub type AssetDefinitionsMap = BTreeMap<DefinitionId, AssetDefinitionEntry>;

    /// An entry in [`AssetDefinitionsMap`].
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct AssetDefinitionEntry {
        /// Asset definition.
        pub definition: AssetDefinition,
        /// The account that registered this asset.
        pub registered_by: AccountId,
    }

    impl PartialOrd for AssetDefinitionEntry {
        #[inline]
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.definition.cmp(&other.definition))
        }
    }

    impl Ord for AssetDefinitionEntry {
        #[inline]
        fn cmp(&self, other: &Self) -> Ordering {
            self.definition.cmp(&other.definition)
        }
    }

    impl AssetDefinitionEntry {
        /// Constructor.
        pub const fn new(definition: AssetDefinition, registered_by: AccountId) -> Self {
            Self {
                definition,
                registered_by,
            }
        }
    }

    /// Asset definition defines type of that asset.
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
    pub struct AssetDefinition {
        /// Type of [`AssetValue`]
        pub value_type: AssetValueType,
        /// An Identification of the [`AssetDefinition`].
        pub id: DefinitionId,
        /// Metadata of this asset definition as a key-value store.
        pub metadata: Metadata,
        /// Is the asset mintable
        pub mintable: bool,
    }

    /// Asset represents some sort of commodity or value.
    /// All possible variants of [`Asset`] entity's components.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct Asset {
        /// Component Identification.
        pub id: Id,
        /// Asset's Quantity.
        pub value: AssetValue,
    }

    /// Asset's inner value type.
    #[derive(
        Debug,
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
    pub enum AssetValueType {
        /// Asset's Quantity.
        Quantity,
        /// Asset's Big Quantity.
        BigQuantity,
        /// Decimal quantity with fixed precision
        Fixed,
        /// Asset's key-value structured data.
        Store,
    }

    impl FromStr for AssetValueType {
        type Err = Error;
        fn from_str(value_type: &str) -> Result<Self> {
            serde_json::from_value(serde_json::json!(value_type))
                .wrap_err("Failed to deserialize value type")
        }
    }

    /// Asset's inner value.
    #[derive(
        Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
    )]
    pub enum AssetValue {
        /// Asset's Quantity.
        Quantity(u32),
        /// Asset's Big Quantity.
        BigQuantity(u128),
        /// Asset's Decimal Quantity.
        Fixed(fixed::Fixed),
        /// Asset's key-value structured data.
        Store(Metadata),
    }

    impl AssetValue {
        /// Returns the asset type as a string.
        pub const fn value_type(&self) -> AssetValueType {
            match *self {
                Self::Quantity(_) => AssetValueType::Quantity,
                Self::BigQuantity(_) => AssetValueType::BigQuantity,
                Self::Fixed(_) => AssetValueType::Fixed,
                Self::Store(_) => AssetValueType::Store,
            }
        }
        /// Returns true if this value is zero, false if it contains [`Metadata`] or positive value
        pub const fn is_zero_value(&self) -> bool {
            match *self {
                Self::Quantity(q) => q == 0_u32,
                Self::BigQuantity(q) => q == 0_u128,
                Self::Fixed(ref q) => q.is_zero(),
                Self::Store(_) => false,
            }
        }
    }

    macro_rules! impl_try_as_for_asset_value {
        ( $($variant:ident( $ty:ty ),)* ) => {$(
            impl TryAsMut<$ty> for AssetValue {
                type Error = Error;

                fn try_as_mut(&mut self) -> Result<&mut $ty> {
                    if let AssetValue:: $variant (value) = self {
                        Ok(value)
                    } else {
                        Err(eyre!(
                            concat!(
                                "Expected source asset with value type:",
                                stringify!($variant),
                                ". Got: {:?}",
                            ),
                            self.value_type()
                        ))
                    }
                }
            }

            impl TryAsRef<$ty> for AssetValue {
                type Error = Error;

                fn try_as_ref(&self) -> Result<& $ty > {
                    if let AssetValue:: $variant (value) = self {
                        Ok(value)
                    } else {
                        Err(eyre!(
                            concat!(
                                "Expected source asset with value type:",
                                stringify!($variant),
                                ". Got: {:?}",
                            ),
                            self.value_type()
                        ))
                    }
                }
            }
        )*}
    }

    impl_try_as_for_asset_value! {
        Quantity(u32),
        BigQuantity(u128),
        Fixed(Fixed),
        Store(Metadata),
    }

    impl PartialOrd for Asset {
        #[inline]
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.id.cmp(&other.id))
        }
    }

    impl Ord for Asset {
        #[inline]
        fn cmp(&self, other: &Self) -> Ordering {
            self.id.cmp(&other.id)
        }
    }

    /// Identification of an Asset Definition. Consists of Asset's name and Domain's name.
    ///
    /// # Example
    ///
    /// ```
    /// use iroha_data_model::asset::DefinitionId;
    ///
    /// let definition_id = DefinitionId::new("xor", "soramitsu");
    /// ```
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
    pub struct DefinitionId {
        /// Asset's name.
        pub name: Name,
        /// Domain's id.
        pub domain_id: DomainId,
    }

    /// Identification of an Asset's components include Entity Id ([`Asset::Id`]) and [`Account::Id`].
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
        /// Entity Identification.
        pub definition_id: DefinitionId,
        /// Account Identification.
        pub account_id: AccountId,
    }

    impl AssetDefinition {
        /// Construct [`AssetDefinition`].
        #[inline]
        pub fn new(id: DefinitionId, value_type: AssetValueType, mintable: bool) -> Self {
            Self {
                value_type,
                id,
                metadata: Metadata::new(),
                mintable,
            }
        }

        /// Asset definition with quantity asset value type.
        #[inline]
        pub fn new_quantity(id: DefinitionId) -> Self {
            AssetDefinition::new(id, AssetValueType::Quantity, true)
        }

        /// Token definition with quantity asset value type.
        #[inline]
        pub fn new_quantity_token(id: DefinitionId) -> Self {
            AssetDefinition::new(id, AssetValueType::BigQuantity, true)
        }

        /// Asset definition with big quantity asset value type.
        #[inline]
        pub fn new_big_quantity(id: DefinitionId) -> Self {
            AssetDefinition::new(id, AssetValueType::BigQuantity, true)
        }

        /// Token definition with big quantity asset value type.
        #[inline]
        pub fn new_bin_quantity_token(id: DefinitionId) -> Self {
            AssetDefinition::new(id, AssetValueType::BigQuantity, false)
        }

        /// Asset definition with decimal quantity asset value type.
        #[inline]
        pub fn with_precision(id: DefinitionId) -> Self {
            AssetDefinition::new(id, AssetValueType::Fixed, true)
        }

        /// Token definition with decimal quantity asset value type.
        #[inline]
        pub fn with_precision_token(id: DefinitionId) -> Self {
            AssetDefinition::new(id, AssetValueType::Fixed, true)
        }

        /// Asset definition with store asset value type.
        #[inline]
        pub fn new_store(id: DefinitionId) -> Self {
            AssetDefinition::new(id, AssetValueType::Store, true)
        }

        /// Token definition with store asset value type.
        #[inline]
        pub fn new_store_token(id: DefinitionId) -> Self {
            AssetDefinition::new(id, AssetValueType::Store, false)
        }
    }

    impl Asset {
        /// Constructor
        pub fn new<V: Into<AssetValue>>(id: Id, value: V) -> Self {
            Self {
                id,
                value: value.into(),
            }
        }

        /// `Asset` with `quantity` value constructor.
        #[inline]
        pub fn with_quantity(id: Id, quantity: u32) -> Self {
            Self {
                id,
                value: quantity.into(),
            }
        }

        /// `Asset` with `big_quantity` value constructor.
        #[inline]
        pub fn with_big_quantity(id: Id, big_quantity: u128) -> Self {
            Self {
                id,
                value: big_quantity.into(),
            }
        }

        /// `Asset` with a `parameter` inside `store` value constructor.
        ///
        /// # Errors
        /// Fails if limit check fails
        pub fn with_parameter(
            id: Id,
            key: Name,
            value: Value,
            limits: MetadataLimits,
        ) -> Result<Self> {
            let mut store = Metadata::new();
            store.insert_with_limits(key, value, limits)?;
            Ok(Self {
                id,
                value: store.into(),
            })
        }

        /// Returns the asset type as a string.
        pub const fn value_type(&self) -> AssetValueType {
            self.value.value_type()
        }
    }

    impl<T> TryAsMut<T> for Asset
    where
        AssetValue: TryAsMut<T, Error = Error>,
    {
        type Error = Error;

        #[inline]
        fn try_as_mut(&mut self) -> Result<&mut T> {
            self.value.try_as_mut()
        }
    }

    impl<T> TryAsRef<T> for Asset
    where
        AssetValue: TryAsRef<T, Error = Error>,
    {
        type Error = Error;

        #[inline]
        fn try_as_ref(&self) -> Result<&T> {
            self.value.try_as_ref()
        }
    }

    impl DefinitionId {
        /// Construct [`Id`] from an asset definition `name` and a `domain_name` if these names are valid.
        ///
        /// # Errors
        /// Fails if any sub-construction fails
        #[inline]
        pub fn new(name: &str, domain_name: &str) -> Result<Self> {
            Ok(Self {
                name: Name::new(name)?,
                domain_id: DomainId::new(domain_name)?,
            })
        }

        /// Instantly construct [`Id`] from an asset definition `name` and a `domain_name` assuming these names are valid.
        #[inline]
        pub fn test(name: &str, domain_name: &str) -> Self {
            Self {
                name: Name::test(name),
                domain_id: DomainId::test(domain_name),
            }
        }
    }

    impl Id {
        /// Construct [`Id`] from [`DefinitionId`] and [`AccountId`].
        #[inline]
        pub const fn new(definition_id: DefinitionId, account_id: AccountId) -> Self {
            Self {
                definition_id,
                account_id,
            }
        }

        /// Instantly construct [`Id`] from names which constitute [`DefinitionId`] and [`AccountId`] assuming these names are valid.
        #[inline]
        pub fn test(
            asset_definition_name: &str,
            asset_definition_domain_name: &str,
            account_name: &str,
            account_domain_name: &str,
        ) -> Self {
            Self {
                definition_id: DefinitionId::test(
                    asset_definition_name,
                    asset_definition_domain_name,
                ),
                account_id: AccountId::test(account_name, account_domain_name),
            }
        }
    }

    impl Identifiable for Asset {
        type Id = Id;
    }

    impl Identifiable for AssetDefinition {
        type Id = DefinitionId;
    }

    impl FromIterator<Asset> for Value {
        fn from_iter<T: IntoIterator<Item = Asset>>(iter: T) -> Self {
            iter.into_iter()
                .map(Into::into)
                .collect::<Vec<Self>>()
                .into()
        }
    }

    impl FromIterator<AssetDefinition> for Value {
        fn from_iter<T: IntoIterator<Item = AssetDefinition>>(iter: T) -> Self {
            iter.into_iter()
                .map(Into::into)
                .collect::<Vec<Self>>()
                .into()
        }
    }

    /// Asset Identification is represented by `name#domain_name` string.
    impl FromStr for DefinitionId {
        type Err = Error;

        fn from_str(string: &str) -> Result<Self, Self::Err> {
            let vector: Vec<&str> = string.split('#').collect();
            if vector.len() != 2 {
                return Err(eyre!(
                    "Asset definition ID should have format `name#domain_name`.",
                ));
            }
            Ok(Self {
                name: Name::new(vector[0])?,
                domain_id: DomainId::new(vector[1])?,
            })
        }
    }

    impl Display for DefinitionId {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{}#{}", self.name, self.domain_id)
        }
    }

    impl Display for Id {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{}@{}", self.definition_id, self.account_id)
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{
            Asset, AssetDefinition, AssetDefinitionEntry, AssetValue, AssetValueType,
            DefinitionId as AssetDefinitionId, Id as AssetId,
        };
    }
}

pub mod domain {
    //! This module contains [`Domain`](`crate::domain::Domain`) structure and related implementations and trait implementations.

    use std::{cmp::Ordering, collections::BTreeMap, fmt, iter, str::FromStr};

    use dashmap::DashMap;
    use eyre::{Error, Result};
    use iroha_crypto::PublicKey;
    use iroha_schema::IntoSchema;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::{
        account::{Account, AccountsMap, GenesisAccount},
        asset::AssetDefinitionsMap,
        metadata::Metadata,
        Identifiable, Name, Value,
    };

    /// Genesis domain name. Genesis domain should contain only genesis account.
    pub const GENESIS_DOMAIN_NAME: &str = "genesis";

    /// [`DomainsMap`] provides an API to work with collection of
    /// key ([`Id`]) - value ([`Domain`]) pairs.
    pub type DomainsMap = DashMap<Id, Domain>;

    /// Genesis domain. It will contain only one `genesis` account.
    #[derive(Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct GenesisDomain {
        genesis_key: PublicKey,
    }

    impl GenesisDomain {
        /// Returns `GenesisDomain`.
        #[inline]
        pub const fn new(genesis_key: PublicKey) -> Self {
            Self { genesis_key }
        }
    }

    impl From<GenesisDomain> for Domain {
        fn from(domain: GenesisDomain) -> Self {
            Self {
                id: Id::test(GENESIS_DOMAIN_NAME),
                accounts: iter::once((
                    <Account as Identifiable>::Id::genesis(),
                    GenesisAccount::new(domain.genesis_key).into(),
                ))
                .collect(),
                asset_definitions: BTreeMap::default(),
                metadata: Metadata::new(),
            }
        }
    }

    /// Named group of [`Account`] and [`Asset`](`crate::asset::Asset`) entities.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct Domain {
        /// Identification of this [`Domain`].
        pub id: Id,
        /// Accounts of the domain.
        pub accounts: AccountsMap,
        /// Assets of the domain.
        pub asset_definitions: AssetDefinitionsMap,
        /// Metadata of this domain as a key-value store.
        pub metadata: Metadata,
    }

    impl PartialOrd for Domain {
        #[inline]
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.id.cmp(&other.id))
        }
    }

    impl Ord for Domain {
        #[inline]
        fn cmp(&self, other: &Self) -> Ordering {
            self.id.cmp(&other.id)
        }
    }

    impl Domain {
        /// Construct [`Domain`] from [`Id`].
        pub fn new(id: Id) -> Self {
            Self {
                id,
                accounts: AccountsMap::new(),
                asset_definitions: AssetDefinitionsMap::new(),
                metadata: Metadata::new(),
            }
        }

        /// Instantly construct [`Domain`] assuming `name` is valid.
        pub fn test(name: &str) -> Self {
            Self {
                id: Id::test(name),
                accounts: AccountsMap::new(),
                asset_definitions: AssetDefinitionsMap::new(),
                metadata: Metadata::new(),
            }
        }

        /// Domain constructor with pre-setup accounts. Useful for testing purposes.
        pub fn with_accounts(name: &str, accounts: impl IntoIterator<Item = Account>) -> Self {
            let accounts_map = accounts
                .into_iter()
                .map(|account| (account.id.clone(), account))
                .collect();
            Self {
                id: Id::test(name),
                accounts: accounts_map,
                asset_definitions: AssetDefinitionsMap::new(),
                metadata: Metadata::new(),
            }
        }
    }

    impl Identifiable for Domain {
        type Id = Id;
    }

    impl FromIterator<Domain> for Value {
        fn from_iter<T: IntoIterator<Item = Domain>>(iter: T) -> Self {
            iter.into_iter()
                .map(Into::into)
                .collect::<Vec<Self>>()
                .into()
        }
    }

    /// Identification of a [`Domain`].
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
        /// [`Name`] unique to a [`Domain`] e.g. company name
        pub name: Name,
    }

    impl Id {
        /// Construct [`Id`] if the given domain `name` is valid.
        ///
        /// # Errors
        /// Fails if any sub-construction fails
        #[inline]
        pub fn new(name: &str) -> Result<Self> {
            Ok(Self {
                name: Name::new(name)?,
            })
        }

        /// Instantly construct [`Id`] assuming the given domain `name` is valid.
        #[inline]
        pub fn test(name: &str) -> Self {
            Self {
                name: Name::test(name),
            }
        }
    }

    impl FromStr for Id {
        type Err = Error;

        fn from_str(name: &str) -> Result<Self, Self::Err> {
            Self::new(name)
        }
    }

    impl fmt::Display for Id {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.name)
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{Domain, GenesisDomain, Id as DomainId, GENESIS_DOMAIN_NAME};
    }
}

pub mod peer {
    //! This module contains [`Peer`] structure and related implementations and traits implementations.

    use std::{fmt, hash::Hash};

    use dashmap::DashSet;
    use iroha_schema::IntoSchema;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::{Identifiable, PublicKey, Value};

    /// Ids of peers.
    pub type PeersIds = DashSet<Id>;

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
    #[derive(
        Debug,
        Clone,
        Eq,
        PartialEq,
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
        /// Address of the [`Peer`]'s entrypoint.
        pub address: String,
        /// Public Key of the [`Peer`].
        pub public_key: PublicKey,
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
                address: address.to_owned(),
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

/// Structures and traits related to pagination.
pub mod pagination {
    use std::{collections::BTreeMap, fmt};

    use serde::{Deserialize, Serialize};
    #[cfg(feature = "warp")]
    use warp::{
        http::StatusCode,
        reply::{self, Response},
        Filter, Rejection, Reply,
    };

    /// Describes a collection to which pagination can be applied.
    /// Implemented for the [`Iterator`] implementors.
    pub trait Paginate: Iterator + Sized {
        /// Returns a paginated [`Iterator`].
        fn paginate(self, pagination: Pagination) -> Paginated<Self>;
    }

    impl<I: Iterator + Sized> Paginate for I {
        fn paginate(self, pagination: Pagination) -> Paginated<Self> {
            Paginated {
                pagination,
                iter: self,
            }
        }
    }

    /// Paginated [`Iterator`].
    /// Not recommended to use directly, only use in iterator chains.
    #[derive(Debug)]
    pub struct Paginated<I: Iterator> {
        pagination: Pagination,
        iter: I,
    }

    impl<I: Iterator> Iterator for Paginated<I> {
        type Item = I::Item;

        fn next(&mut self) -> Option<Self::Item> {
            if let Some(limit) = self.pagination.limit.as_mut() {
                if *limit == 0 {
                    return None;
                }
                *limit -= 1
            }

            #[allow(clippy::option_if_let_else)]
            // Required because of E0524. 2 closures with unique refs to self
            if let Some(start) = self.pagination.start.take() {
                self.iter.nth(start)
            } else {
                self.iter.next()
            }
        }
    }

    /// Structure for pagination requests
    #[derive(Clone, Eq, PartialEq, Debug, Default, Copy, Deserialize, Serialize)]
    pub struct Pagination {
        /// start of indexing
        pub start: Option<usize>,
        /// limit of indexing
        pub limit: Option<usize>,
    }

    impl Pagination {
        /// Constructs [`Pagination`].
        pub const fn new(start: Option<usize>, limit: Option<usize>) -> Self {
            Self { start, limit }
        }
    }

    const PAGINATION_START: &str = "start";
    const PAGINATION_LIMIT: &str = "limit";

    /// Error for pagination
    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct PaginateError(pub std::num::ParseIntError);

    impl fmt::Display for PaginateError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Failed to decode pagination. Error occurred in one of numbers: {}",
                self.0
            )
        }
    }
    impl std::error::Error for PaginateError {}

    #[cfg(feature = "warp")]
    impl Reply for PaginateError {
        fn into_response(self) -> Response {
            reply::with_status(self.to_string(), StatusCode::BAD_REQUEST).into_response()
        }
    }

    #[cfg(feature = "warp")]
    /// Filter for warp which extracts pagination
    pub fn paginate() -> impl Filter<Extract = (Pagination,), Error = Rejection> + Copy {
        warp::query()
    }

    impl From<Pagination> for BTreeMap<String, String> {
        fn from(pagination: Pagination) -> Self {
            let mut query_params = Self::new();
            if let Some(start) = pagination.start {
                query_params.insert(PAGINATION_START.to_owned(), start.to_string());
            }
            if let Some(limit) = pagination.limit {
                query_params.insert(PAGINATION_LIMIT.to_owned(), limit.to_string());
            }
            query_params
        }
    }

    impl From<Pagination> for Vec<(&'static str, usize)> {
        fn from(pagination: Pagination) -> Self {
            match (pagination.start, pagination.limit) {
                (Some(start), Some(limit)) => {
                    vec![(PAGINATION_START, start), (PAGINATION_LIMIT, limit)]
                }
                (Some(start), None) => vec![(PAGINATION_START, start)],
                (None, Some(limit)) => vec![(PAGINATION_LIMIT, limit)],
                (None, None) => Vec::new(),
            }
        }
    }

    pub mod prelude {
        //! Prelude: re-export most commonly used traits, structs and macros from this module.
        pub use super::*;
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn empty() {
            assert_eq!(
                vec![1_i32, 2_i32, 3_i32]
                    .into_iter()
                    .paginate(Pagination::new(None, None))
                    .collect::<Vec<_>>(),
                vec![1_i32, 2_i32, 3_i32]
            )
        }

        #[test]
        fn start() {
            assert_eq!(
                vec![1_i32, 2_i32, 3_i32]
                    .into_iter()
                    .paginate(Pagination::new(Some(0), None))
                    .collect::<Vec<_>>(),
                vec![1_i32, 2_i32, 3_i32]
            );
            assert_eq!(
                vec![1_i32, 2_i32, 3_i32]
                    .into_iter()
                    .paginate(Pagination::new(Some(1), None))
                    .collect::<Vec<_>>(),
                vec![2_i32, 3_i32]
            );
            assert_eq!(
                vec![1_i32, 2_i32, 3_i32]
                    .into_iter()
                    .paginate(Pagination::new(Some(3), None))
                    .collect::<Vec<_>>(),
                Vec::<i32>::new()
            );
        }

        #[test]
        fn limit() {
            assert_eq!(
                vec![1_i32, 2_i32, 3_i32]
                    .into_iter()
                    .paginate(Pagination::new(None, Some(0)))
                    .collect::<Vec<_>>(),
                Vec::<i32>::new()
            );
            assert_eq!(
                vec![1_i32, 2_i32, 3_i32]
                    .into_iter()
                    .paginate(Pagination::new(None, Some(2)))
                    .collect::<Vec<_>>(),
                vec![1_i32, 2_i32]
            );
            assert_eq!(
                vec![1_i32, 2_i32, 3_i32]
                    .into_iter()
                    .paginate(Pagination::new(None, Some(4)))
                    .collect::<Vec<_>>(),
                vec![1_i32, 2_i32, 3_i32]
            );
        }

        #[test]
        fn start_and_limit() {
            assert_eq!(
                vec![1_i32, 2_i32, 3_i32]
                    .into_iter()
                    .paginate(Pagination::new(Some(1), Some(1)))
                    .collect::<Vec<_>>(),
                vec![2_i32]
            )
        }
    }
}

pub mod uri {
    //! URI that `Torii` uses to route incoming requests.

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
    #[cfg(feature = "roles")]
    pub use super::role::prelude::*;
    pub use super::{
        account::prelude::*, asset::prelude::*, current_time, domain::prelude::*,
        fixed::prelude::*, pagination::prelude::*, peer::prelude::*, transaction::prelude::*, uri,
        Bytes, IdBox, Identifiable, IdentifiableBox, Name, Parameter, TryAsMut, TryAsRef, Value,
    };
    pub use crate::{
        events::prelude::*,
        expression::prelude::*,
        isi::prelude::*,
        metadata::{self, prelude::*},
        permissions::prelude::*,
        query::prelude::*,
    };
}
