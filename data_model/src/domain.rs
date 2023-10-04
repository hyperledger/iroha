//! This module contains [`Domain`](`crate::domain::Domain`) structure
//! and related implementations and trait implementations.
#![allow(clippy::std_instead_of_alloc)]

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use derive_more::{Constructor, Display, FromStr};
use getset::Getters;
use iroha_data_model_derive::{model, IdEqOrdHash};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

pub use self::model::*;
use crate::{
    account::{Account, AccountsMap},
    asset::{AssetDefinition, AssetDefinitionsMap, AssetTotalQuantityMap},
    ipfs::IpfsPath,
    metadata::Metadata,
    prelude::*,
    HasMetadata, Name, NumericValue, Registered,
};

#[model]
pub mod model {
    use super::*;

    /// Identification of a [`Domain`].
    #[derive(
        Debug,
        Display,
        FromStr,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        Constructor,
        Getters,
        Decode,
        Encode,
        DeserializeFromStr,
        SerializeDisplay,
        IntoSchema,
    )]
    #[display(fmt = "{name}")]
    #[getset(get = "pub")]
    #[repr(transparent)]
    #[ffi_type(opaque)]
    pub struct DomainId {
        /// [`Name`] unique to a [`Domain`] e.g. company name
        pub name: Name,
    }

    /// Named group of [`Account`] and [`Asset`](`crate::asset::Asset`) entities.
    #[derive(
        Debug,
        Display,
        Clone,
        IdEqOrdHash,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[allow(clippy::multiple_inherent_impl)]
    #[display(fmt = "[{id}]")]
    #[ffi_type]
    pub struct Domain {
        /// Identification of this [`Domain`].
        pub id: DomainId,
        /// [`Account`]s of the domain.
        pub accounts: AccountsMap,
        /// [`Asset`](AssetDefinition)s defined of the `Domain`.
        pub asset_definitions: AssetDefinitionsMap,
        /// Total amount of [`Asset`].
        pub asset_total_quantities: AssetTotalQuantityMap,
        /// IPFS link to the [`Domain`] logo
        #[getset(get = "pub")]
        pub logo: Option<IpfsPath>,
        /// [`Metadata`] of this `Domain` as a key-value store.
        pub metadata: Metadata,
        /// The account that owns this domain. Usually the [`Account`] that registered it.
        #[getset(get = "pub")]
        pub owned_by: AccountId,
    }

    /// Builder which can be submitted in a transaction to create a new [`Domain`]
    #[derive(
        Debug, Display, Clone, IdEqOrdHash, Decode, Encode, Deserialize, Serialize, IntoSchema,
    )]
    #[display(fmt = "[{id}]")]
    #[ffi_type]
    pub struct NewDomain {
        /// The identification associated with the domain builder.
        pub id: DomainId,
        /// The (IPFS) link to the logo of this domain.
        pub logo: Option<IpfsPath>,
        /// Metadata associated with the domain builder.
        pub metadata: Metadata,
    }
}

impl HasMetadata for NewDomain {
    #[inline]
    fn metadata(&self) -> &crate::metadata::Metadata {
        &self.metadata
    }
}

impl NewDomain {
    /// Create a [`NewDomain`], reserved for internal use.
    #[must_use]
    fn new(id: DomainId) -> Self {
        Self {
            id,
            logo: None,
            metadata: Metadata::default(),
        }
    }

    /// Add [`logo`](IpfsPath) to the domain replacing previously defined value
    #[must_use]
    pub fn with_logo(mut self, logo: IpfsPath) -> Self {
        self.logo = Some(logo);
        self
    }

    /// Add [`Metadata`] to the domain replacing previously defined value
    #[must_use]
    pub fn with_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = metadata;
        self
    }
}

impl HasMetadata for Domain {
    #[inline]
    fn metadata(&self) -> &crate::metadata::Metadata {
        &self.metadata
    }
}

impl Registered for Domain {
    type With = NewDomain;
}

impl Domain {
    /// Construct builder for [`Domain`] identifiable by [`Id`].
    #[inline]
    pub fn new(id: DomainId) -> <Self as Registered>::With {
        <Self as Registered>::With::new(id)
    }
}

impl Domain {
    /// Return a reference to the [`Account`] corresponding to the account id.
    #[inline]
    pub fn account(&self, account_id: &AccountId) -> Option<&Account> {
        self.accounts.get(account_id)
    }

    /// Return a reference to the asset definition corresponding to the asset definition id
    #[inline]
    pub fn asset_definition(
        &self,
        asset_definition_id: &AssetDefinitionId,
    ) -> Option<&AssetDefinition> {
        self.asset_definitions.get(asset_definition_id)
    }

    /// Return a reference to the asset definition corresponding to the asset definition id
    #[inline]
    pub fn asset_total_quantity(
        &self,
        asset_definition_id: &AssetDefinitionId,
    ) -> Option<&NumericValue> {
        self.asset_total_quantities.get(asset_definition_id)
    }

    /// Get an iterator over [`Account`]s of the `Domain`
    #[inline]
    pub fn accounts(&self) -> impl ExactSizeIterator<Item = &Account> {
        self.accounts.values()
    }

    /// Return `true` if the `Domain` contains [`Account`]
    #[inline]
    pub fn contains_account(&self, account_id: &AccountId) -> bool {
        self.accounts.contains_key(account_id)
    }

    /// Get an iterator over asset definitions of the `Domain`
    #[inline]
    pub fn asset_definitions(&self) -> impl ExactSizeIterator<Item = &AssetDefinition> {
        self.asset_definitions.values()
    }
}

#[cfg(feature = "transparent_api")]
impl Domain {
    /// Add [`Account`] into the [`Domain`] returning previous account stored under the same id
    #[inline]
    pub fn add_account(&mut self, account: Account) -> Option<Account> {
        self.accounts.insert(account.id().clone(), account)
    }

    /// Remove account from the [`Domain`] and return it
    #[inline]
    pub fn remove_account(&mut self, account_id: &AccountId) -> Option<Account> {
        self.accounts.remove(account_id)
    }

    /// Add asset definition into the [`Domain`] returning previous
    /// asset definition stored under the same id
    #[inline]
    pub fn add_asset_definition(
        &mut self,
        asset_definition: AssetDefinition,
    ) -> Option<AssetDefinition> {
        self.asset_definitions
            .insert(asset_definition.id().clone(), asset_definition)
    }

    /// Remove asset definition from the [`Domain`] and return it
    #[inline]
    pub fn remove_asset_definition(
        &mut self,
        asset_definition_id: &AssetDefinitionId,
    ) -> Option<AssetDefinition> {
        self.asset_definitions.remove(asset_definition_id)
    }

    /// Add asset total amount into the [`Domain`] returning previous
    /// asset amount stored under the same id
    #[inline]
    pub fn add_asset_total_quantity(
        &mut self,
        asset_definition_id: AssetDefinitionId,
        initial_amount: impl Into<NumericValue>,
    ) -> Option<NumericValue> {
        self.asset_total_quantities
            .insert(asset_definition_id, initial_amount.into())
    }

    /// Remove asset total amount from the [`Domain`] and return it
    #[inline]
    pub fn remove_asset_total_quantity(
        &mut self,
        asset_definition_id: &AssetDefinitionId,
    ) -> Option<NumericValue> {
        self.asset_total_quantities.remove(asset_definition_id)
    }
}

impl FromIterator<Domain> for crate::Value {
    fn from_iter<T: IntoIterator<Item = Domain>>(iter: T) -> Self {
        iter.into_iter()
            .map(Into::into)
            .collect::<Vec<Self>>()
            .into()
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{Domain, DomainId};
}
