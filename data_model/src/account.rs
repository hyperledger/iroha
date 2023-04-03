//! Structures, traits and impls related to `Account`s.
#![allow(clippy::std_instead_of_alloc)]

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

use derive_more::{Constructor, Display};
use getset::Getters;
use iroha_data_model_derive::IdEqOrdHash;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

#[cfg(feature = "transparent_api")]
use crate::Registrable;
use crate::{
    asset::{
        prelude::{Asset, AssetId},
        AssetsMap,
    },
    domain::prelude::*,
    expression::{ContainsAny, ContextValue, EvaluatesTo},
    metadata::Metadata,
    model,
    role::{prelude::RoleId, RoleIds},
    HasMetadata, Identifiable, Name, ParseError, PublicKey, Registered,
};

/// API to work with collections of [`Id`] : [`Account`] mappings.
pub type AccountsMap = btree_map::BTreeMap<<Account as Identifiable>::Id, Account>;

// The size of the array must be fixed. If we use more than `1` we
// waste all of that space for all non-multisig accounts. If we
// have 1 signatory per account, we keep the signature on the
// stack. If we have more than 1, we keep everything on the
// heap. Thanks to the union feature, we're not wasting `8Bytes`
// of space, over `Vec`.
type Signatories = btree_set::BTreeSet<PublicKey>;

/// The context value name for transaction signatories.
pub const TRANSACTION_SIGNATORIES_VALUE: &str = "transaction_signatories";

/// The context value name for account signatories.
pub const ACCOUNT_SIGNATORIES_VALUE: &str = "account_signatories";

model! {
    /// Identification of an [`Account`]. Consists of Account name and Domain name.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use iroha_data_model::account::Id;
    ///
    /// let id = "user@company".parse::<Id>().expect("Valid");
    /// ```
    #[derive(Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Constructor, Getters, Decode, Encode, DeserializeFromStr, SerializeDisplay, IntoSchema)]
    #[display(fmt = "{name}@{domain_id}")]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct AccountId {
        /// [`Account`]'s name.
        pub name: Name,
        /// [`Account`]'s [`Domain`](`crate::domain::Domain`) id.
        pub domain_id: <Domain as Identifiable>::Id,
    }

    /// Account entity is an authority which is used to execute `Iroha Special Instructions`.
    #[derive(Debug, Display, Clone, IdEqOrdHash, Getters, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[allow(clippy::multiple_inherent_impl)]
    #[display(fmt = "({id})")] // TODO: Add more?
    #[ffi_type]
    pub struct Account {
        /// An Identification of the [`Account`].
        pub id: AccountId,
        /// Assets in this [`Account`].
        pub assets: AssetsMap,
        /// [`Account`]'s signatories.
        pub signatories: Signatories,
        /// Condition which checks if the account has the right signatures.
        #[getset(get = "pub")]
        pub signature_check_condition: SignatureCheckCondition,
        /// Metadata of this account as a key-value store.
        pub metadata: Metadata,
        /// Roles of this account, they are tags for sets of permissions stored in `World`.
        pub roles: RoleIds,
    }

    /// Builder which should be submitted in a transaction to create a new [`Account`]
    #[derive(Debug, Display, Clone, IdEqOrdHash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[display(fmt = "[{id}]")]
    #[ffi_type]
    pub struct NewAccount {
        /// Identification
        id: <Account as Identifiable>::Id,
        /// Signatories, i.e. signatures attached to this message.
        signatories: Signatories,
        /// Metadata that should be submitted with the builder
        metadata: Metadata,
    }

    /// Condition which checks if the account has the right signatures.
    #[derive(Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Constructor, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[serde(transparent)]
    #[repr(transparent)]
    // SAFETY: `SignatureCheckCondition` has no trap representation in `EvalueatesTo<bool>`
    #[ffi_type(unsafe {robust})]
    pub struct SignatureCheckCondition(pub EvaluatesTo<bool>);
}

impl AccountId {
    #[cfg(feature = "transparent_api")]
    const GENESIS_ACCOUNT_NAME: &str = "genesis";

    /// Construct [`Id`] of the genesis account.
    #[inline]
    #[must_use]
    #[cfg(feature = "transparent_api")]
    pub fn genesis() -> Self {
        Self {
            name: Self::GENESIS_ACCOUNT_NAME.parse().expect("Valid"),
            domain_id: DomainId::genesis(),
        }
    }
}

impl Account {
    /// Construct builder for [`Account`] identifiable by [`Id`] containing the given signatories.
    #[inline]
    #[must_use]
    pub fn new(
        id: <Self as Identifiable>::Id,
        signatories: impl IntoIterator<Item = PublicKey>,
    ) -> <Self as Registered>::With {
        <Self as Registered>::With::new(id, signatories)
    }

    /// Get an iterator over [`signatories`](PublicKey) of the `Account`
    #[inline]
    pub fn signatories(&self) -> impl ExactSizeIterator<Item = &PublicKey> {
        self.signatories.iter()
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

    /// Get an iterator over [`role ids`](RoleId) of the `Account`
    #[inline]
    pub fn roles(&self) -> impl ExactSizeIterator<Item = &RoleId> {
        self.roles.iter()
    }

    /// Return `true` if the `Account` contains the given signatory
    #[inline]
    pub fn contains_signatory(&self, signatory: &PublicKey) -> bool {
        self.signatories.contains(signatory)
    }

    /// Return `true` if `Account` contains the given role
    #[inline]
    pub fn contains_role(&self, role_id: &RoleId) -> bool {
        self.roles.contains(role_id)
    }
}

#[cfg(feature = "transparent_api")]
impl Account {
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

    /// Add [`Metadata`] to the account replacing any previously defined metadata
    #[must_use]
    pub fn with_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = metadata;
        self
    }
}

impl SignatureCheckCondition {
    /// Get a reference to the raw `ExpressionBox`.
    #[inline]
    pub const fn as_expression(&self) -> &crate::expression::Expression {
        let Self(condition) = self;
        &condition.expression
    }
}

/// Default signature condition check for accounts.
/// Returns true if any of the signatories have signed the transaction.
impl Default for SignatureCheckCondition {
    #[inline]
    #[allow(clippy::expect_used)]
    fn default() -> Self {
        Self(
            ContainsAny::new(
                EvaluatesTo::new_unchecked(
                    ContextValue::new(
                        Name::from_str(TRANSACTION_SIGNATORIES_VALUE)
                            .expect("TRANSACTION_SIGNATORIES_VALUE should be valid."),
                    )
                    .into(),
                ),
                EvaluatesTo::new_unchecked(
                    ContextValue::new(
                        Name::from_str(ACCOUNT_SIGNATORIES_VALUE)
                            .expect("ACCOUNT_SIGNATORIES_VALUE should be valid."),
                    )
                    .into(),
                ),
            )
            .into(),
        )
    }
}

#[cfg(feature = "transparent_api")]
impl Registrable for NewAccount {
    type Target = Account;

    #[must_use]
    #[inline]
    fn build(self) -> Self::Target {
        Self::Target {
            id: self.id,
            signatories: self.signatories,
            assets: AssetsMap::default(),
            signature_check_condition: SignatureCheckCondition::default(),
            metadata: self.metadata,
            roles: RoleIds::default(),
        }
    }
}

impl HasMetadata for NewAccount {
    fn metadata(&self) -> &Metadata {
        &self.metadata
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

impl FromIterator<Account> for crate::Value {
    fn from_iter<T: IntoIterator<Item = Account>>(iter: T) -> Self {
        iter.into_iter()
            .map(Into::into)
            .collect::<Vec<Self>>()
            .into()
    }
}

/// Account Identification is represented by `name@domain_name` string.
impl FromStr for AccountId {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let split = string.rsplit_once('@');
        match split {
            Some(("", _)) => Err(ParseError {
                reason: "`AccountId` cannot be empty",
            }),
            Some((name, domain_id)) if !name.is_empty() && !domain_id.is_empty() => Ok(AccountId {
                name: name.parse()?,
                domain_id: domain_id.parse()?,
            }),
            _ => Err(ParseError {
                reason: "`AccountId` should have format `name@domain_name`",
            }),
        }
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{Account, AccountId, SignatureCheckCondition};
}
