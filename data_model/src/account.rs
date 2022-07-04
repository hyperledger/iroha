//! Structures, traits and impls related to `Account`s.

#[cfg(not(feature = "std"))]
use alloc::{
    collections::{btree_map, btree_set},
    format,
    string::String,
    vec::Vec,
};
use core::str::FromStr;
#[cfg(feature = "std")]
use std::collections::{btree_map, btree_set};

use derive_more::Display;
use getset::{Getters, MutGetters, Setters};
#[cfg(feature = "ffi_api")]
use iroha_ffi::ffi_bindgen;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    asset::{prelude::AssetId, AssetsMap},
    domain::prelude::*,
    expression::{ContainsAny, ContextValue, EvaluatesTo},
    metadata::Metadata,
    permissions::{PermissionToken, Permissions},
    prelude::Asset,
    role::{prelude::RoleId, RoleIds},
    HasMetadata, Identifiable, Name, ParseError, PublicKey, Registered,
};

/// `AccountsMap` provides an API to work with collection of key (`Id`) - value
/// (`Account`) pairs.
pub type AccountsMap = btree_map::BTreeMap<<Account as Identifiable>::Id, Account>;

// The size of the array must be fixed. If we use more than `1` we
// waste all of that space for all non-multisig accounts. If we
// have 1 signatory per account, we keep the signature on the
// stack. If we have more than 1, we keep everything on the
// heap. Thanks to the union feature, we're not wasting `8Bytes`
// of space, over `Vec`.
type Signatories = btree_set::BTreeSet<PublicKey>;

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
    #[must_use]
    pub const fn new(public_key: PublicKey) -> Self {
        GenesisAccount { public_key }
    }
}

#[cfg(feature = "mutable_api")]
impl From<GenesisAccount> for Account {
    #[inline]
    fn from(account: GenesisAccount) -> Self {
        Account::new(Id::genesis(), [account.public_key]).build()
    }
}

/// Condition which checks if the account has the right signatures.
#[derive(
    Debug,
    Display,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoSchema,
    PartialOrd,
    Ord,
)]
pub struct SignatureCheckCondition(pub EvaluatesTo<bool>);

impl SignatureCheckCondition {
    /// Gets reference to the raw `ExpressionBox`.
    #[inline]
    pub const fn as_expression(&self) -> &crate::expression::ExpressionBox {
        let Self(condition) = self;
        &condition.expression
    }
}

// TODO: derive
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

/// Builder which should be submitted in a transaction to create a new [`Account`]
#[allow(clippy::multiple_inherent_impl)]
#[derive(
    Debug, Display, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
#[display(fmt = "[{id}]")]
pub struct NewAccount {
    /// Identification
    id: <NewAccount as Identifiable>::Id,
    /// Signatories, i.e. signatures attached to this message.
    signatories: Signatories,
    /// Metadata that should be submitted with the builder
    metadata: Metadata,
}

impl Identifiable for NewAccount {
    type Id = <Account as Identifiable>::Id;

    fn id(&self) -> &Self::Id {
        &self.id
    }
}

impl PartialOrd for NewAccount {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NewAccount {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl HasMetadata for NewAccount {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}

impl NewAccount {
    fn new(
        id: <Account as Identifiable>::Id,
        signatories: impl IntoIterator<Item = PublicKey>,
    ) -> Self {
        Self {
            id,
            signatories: signatories.into_iter().collect(),
            metadata: Metadata::default(),
        }
    }

    /// Construct [`Account`]
    #[must_use]
    #[cfg(feature = "mutable_api")]
    pub fn build(self) -> Account {
        Account {
            id: self.id,
            signatories: self.signatories,
            assets: AssetsMap::default(),
            permission_tokens: Permissions::default(),
            signature_check_condition: SignatureCheckCondition::default(),
            metadata: self.metadata,
            roles: RoleIds::default(),
        }
    }
}

#[cfg_attr(feature = "ffi_api", ffi_bindgen)]
impl NewAccount {
    /// Add [`Metadata`] to the account replacing previously defined
    #[must_use]
    pub fn with_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Account entity is an authority which is used to execute `Iroha Special Instructions`.
#[derive(
    Debug,
    Display,
    Clone,
    PartialEq,
    Eq,
    Getters,
    MutGetters,
    Setters,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoSchema,
)]
#[allow(clippy::multiple_inherent_impl)]
#[cfg_attr(feature = "ffi_api", ffi_bindgen)]
#[display(fmt = "({id})")] // TODO: Add more?
pub struct Account {
    /// An Identification of the [`Account`].
    id: <Self as Identifiable>::Id,
    /// Asset's in this [`Account`].
    assets: AssetsMap,
    /// [`Account`]'s signatories.
    signatories: Signatories,
    /// Permissions tokens of this account
    permission_tokens: Permissions,
    /// Condition which checks if the account has the right signatures.
    #[cfg_attr(feature = "mutable_api", getset(get = "pub", set = "pub"))]
    signature_check_condition: SignatureCheckCondition,
    /// Metadata of this account as a key-value store.
    #[cfg_attr(feature = "mutable_api", getset(get_mut = "pub"))]
    metadata: Metadata,
    /// Roles of this account, they are tags for sets of permissions stored in `World`.
    roles: RoleIds,
}

impl Identifiable for Account {
    type Id = Id;

    fn id(&self) -> &Self::Id {
        &self.id
    }
}

impl HasMetadata for Account {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}

impl Registered for Account {
    type With = NewAccount;
}

impl PartialOrd for Account {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Account {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id().cmp(other.id())
    }
}

#[cfg_attr(feature = "ffi_api", ffi_bindgen)]
impl Account {
    /// Construct builder for [`Account`] identifiable by [`Id`] containing the given signatories.
    #[must_use]
    pub fn new(
        id: <Self as Identifiable>::Id,
        signatories: impl IntoIterator<Item = PublicKey>,
    ) -> <Self as Registered>::With {
        <Self as Registered>::With::new(id, signatories)
    }

    /// Return `true` if the `Account` contains signatory
    #[inline]
    pub fn contains_signatory(&self, signatory: &PublicKey) -> bool {
        self.signatories.contains(signatory)
    }

    /// Return a reference to the [`Asset`] corresponding to the asset id.
    #[inline]
    pub fn asset(&self, asset_id: &AssetId) -> Option<&Asset> {
        self.assets.get(asset_id)
    }

    /// Get an iterator over [`Asset`]s of the `Account`
    #[inline]
    pub fn assets(&self) -> impl ExactSizeIterator<Item = &Asset> {
        self.assets.values()
    }

    /// Get an iterator over [`signatories`](PublicKey) of the `Account`
    #[inline]
    pub fn signatories(&self) -> impl ExactSizeIterator<Item = &PublicKey> {
        self.signatories.iter()
    }

    /// Return `true` if `Account` contains permission token
    #[inline]
    pub fn contains_permission(&self, token: &PermissionToken) -> bool {
        self.permission_tokens.contains(token)
    }

    /// Get an iterator over [`permissions`](PermissionToken) of the `Account`
    #[inline]
    pub fn permissions(&self) -> impl ExactSizeIterator<Item = &PermissionToken> {
        self.permission_tokens.iter()
    }

    /// Return `true` if `Account` contains role
    #[inline]
    pub fn contains_role(&self, role_id: &RoleId) -> bool {
        self.roles.contains(role_id)
    }

    /// Get an iterator over [`role ids`](RoleId) of the `Account`
    #[inline]
    pub fn roles(&self) -> impl ExactSizeIterator<Item = &RoleId> {
        self.roles.iter()
    }
}

#[cfg(feature = "mutable_api")]
impl Account {
    /// Add [`signatory`](PublicKey) into the [`Account`].
    ///
    /// If `Account` did not have this signatory present, `true` is returned.
    /// If `Account` did have this signatory present, `false` is returned.
    #[inline]
    pub fn add_signatory(&mut self, signatory: PublicKey) -> bool {
        self.signatories.insert(signatory)
    }

    /// Remove a signatory from the `Account` and return whether the signatory was present in the `Account`
    #[inline]
    pub fn remove_signatory(&mut self, signatory: &PublicKey) -> bool {
        self.signatories.remove(signatory)
    }

    /// Return a mutable reference to the [`Asset`] corresponding to the asset id
    #[inline]
    pub fn asset_mut(&mut self, asset_id: &AssetId) -> Option<&mut Asset> {
        self.assets.get_mut(asset_id)
    }

    /// Add [`Asset`] into the [`Account`] returning previous asset stored under the same id
    #[inline]
    pub fn add_asset(&mut self, asset: Asset) -> Option<Asset> {
        self.assets.insert(asset.id().clone(), asset)
    }

    /// Remove asset from the [`Account`] and return it
    #[inline]
    pub fn remove_asset(&mut self, asset_id: &AssetId) -> Option<Asset> {
        self.assets.remove(asset_id)
    }

    /// Add [`permission`](PermissionToken) into the [`Account`].
    ///
    /// If `Account` did not have this permission present, `true` is returned.
    /// If `Account` did have this permission present, `false` is returned.
    #[inline]
    pub fn add_permission(&mut self, token: PermissionToken) -> bool {
        self.permission_tokens.insert(token)
    }

    /// Remove a permission from the `Account` and return whether the permission was present in the `Account`
    #[inline]
    pub fn remove_permission(&mut self, token: &PermissionToken) -> bool {
        self.permission_tokens.remove(token)
    }

    /// Add [`Role`](crate::role::Role) into the [`Account`].
    ///
    /// If `Account` did not have this role present, `true` is returned.
    /// If `Account` did have this role present, `false` is returned.
    #[inline]
    pub fn add_role(&mut self, role_id: RoleId) -> bool {
        self.roles.insert(role_id)
    }

    /// Remove a role from the `Account` and return whether the role was present in the `Account`
    #[inline]
    pub fn remove_role(&mut self, role_id: &RoleId) -> bool {
        self.roles.remove(role_id)
    }
}

impl FromIterator<Account> for crate::Value {
    fn from_iter<T: IntoIterator<Item = Account>>(iter: T) -> Self {
        iter.into_iter()
            .map(Into::into)
            .collect::<Vec<Self>>()
            .into()
    }
}

/// Identification of an Account. Consists of Account's name and Domain's name.
///
/// # Example
///
/// ```
/// use iroha_data_model::account::Id;
///
/// let id = "user@company".parse::<Id>().expect("Valid");
/// ```
#[derive(
    Debug,
    Display,
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
#[display(fmt = "{name}@{domain_id}")]
pub struct Id {
    /// [`Account`]'s name.
    pub name: Name,
    /// [`Account`]'s [`Domain`](`crate::domain::Domain`)'s id.
    pub domain_id: <Domain as Identifiable>::Id,
}

impl Id {
    /// Construct [`Id`] from an account `name` and a `domain_name` if
    /// these names are valid.
    #[inline]
    pub const fn new(name: Name, domain_id: <Domain as Identifiable>::Id) -> Self {
        Self { name, domain_id }
    }

    /// Construct [`Id`] of the genesis account.
    #[inline]
    #[must_use]
    pub fn genesis() -> Self {
        #[allow(clippy::expect_used)]
        Self {
            name: Name::from_str(GENESIS_ACCOUNT_NAME).expect("Valid"),
            domain_id: DomainId::from_str(GENESIS_DOMAIN_NAME).expect("Valid"),
        }
    }
}

/// Account Identification is represented by `name@domain_name` string.
impl FromStr for Id {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        if string.is_empty() {
            return Err(ParseError {
                reason: "`AccountId` cannot be empty",
            });
        }

        let vector: Vec<&str> = string.split('@').collect();

        if vector.len() != 2 {
            return Err(ParseError {
                reason: "Id should have format `name@domain_name`",
            });
        }
        Ok(Self {
            name: Name::from_str(vector[0])?,
            domain_id: DomainId::from_str(vector[1])?,
        })
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{Account, Id as AccountId, SignatureCheckCondition};
}
