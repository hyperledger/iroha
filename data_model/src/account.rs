//! Structures, traits and impls related to `Account`s.

#[cfg(not(feature = "std"))]
use alloc::{
    collections::{btree_map, btree_set},
    format,
    string::String,
    vec::Vec,
};
use core::{fmt, str::FromStr};
#[cfg(feature = "std")]
use std::collections::{btree_map, btree_set};

use iroha_data_primitives::small::{smallvec, SmallVec};
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
    Identifiable, Name, ParseError, PublicKey, Value,
};

/// `AccountsMap` provides an API to work with collection of key (`Id`) - value
/// (`Account`) pairs.
pub type AccountsMap = btree_map::BTreeMap<Id, Account>;

/// Collection of [`PermissionToken`]s
pub type Permissions = btree_set::BTreeSet<PermissionToken>;

// The size of the array must be fixed. If we use more than `1` we
// waste all of that space for all non-multisig accounts. If we
// have 1 signatory per account, we keep the signature on the
// stack. If we have more than 1, we keep everything on the
// heap. Thanks to the union feature, we're not wasting `8Bytes`
// of space, over `Vec`.
type Signatories = SmallVec<[PublicKey; 1]>;

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
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, Deserialize, Serialize, IntoSchema,
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
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, Deserialize, Serialize, IntoSchema,
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
            roles: btree_set::BTreeSet::default(),
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
        let signatories = SmallVec(smallvec![signatory]);
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
    pub roles: btree_set::BTreeSet<RoleId>,
}

impl PartialOrd for Account {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.id.partial_cmp(&other.id)
    }
}

impl Ord for Account {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
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
            signatories: SmallVec::new(),
            permission_tokens: Permissions::new(),
            signature_check_condition: SignatureCheckCondition::default(),
            metadata: Metadata::new(),
            #[cfg(feature = "roles")]
            roles: btree_set::BTreeSet::new(),
        }
    }

    /// Account with single `signatory` constructor.
    #[inline]
    pub fn with_signatory(id: Id, signatory: PublicKey) -> Self {
        let signatories = SmallVec(smallvec![signatory]);
        Self {
            id,
            assets: AssetsMap::new(),
            signatories,
            permission_tokens: Permissions::new(),
            signature_check_condition: SignatureCheckCondition::default(),
            metadata: Metadata::new(),
            #[cfg(feature = "roles")]
            roles: btree_set::BTreeSet::new(),
        }
    }

    /// Returns a prebuilt expression that when executed
    /// returns if the needed signatures are gathered.
    pub fn check_signature_condition(&self, signatories: Signatories) -> EvaluatesTo<bool> {
        let expr = WhereBuilder::evaluate(self.signature_check_condition.as_expression().clone())
            .with_value(
                String::from(ACCOUNT_SIGNATORIES_VALUE),
                self.signatories.clone(),
            )
            .with_value(String::from(TRANSACTION_SIGNATORIES_VALUE), signatories)
            .build()
            .into();
        expr
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
    pub fn new(name: &str, domain_name: &str) -> Result<Self, ParseError> {
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
impl FromStr for Id {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let vector: Vec<&str> = string.split('@').collect();
        if vector.len() != 2 {
            return Err(ParseError {
                reason: "Id should have format `name@domain_name`",
            });
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
