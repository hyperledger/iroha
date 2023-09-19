//! Iroha Queries provides declarative API for Iroha Queries.

#![allow(clippy::missing_inline_in_public_items, unused_imports)]

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::cmp::Ordering;

#[cfg(feature = "http")]
pub use cursor::ForwardCursor;
use derive_more::Display;
use iroha_crypto::{PublicKey, SignatureOf};
use iroha_data_model_derive::model;
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use iroha_version::prelude::*;
#[cfg(feature = "http")]
pub use pagination::Pagination;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
#[cfg(feature = "http")]
pub use sorting::Sorting;

pub use self::model::*;
use self::{
    account::*, asset::*, block::*, domain::*, peer::*, permission::*, role::*, transaction::*,
    trigger::*,
};
use crate::{
    account::Account,
    block::VersionedSignedBlock,
    seal,
    transaction::{TransactionPayload, TransactionValue, VersionedSignedTransaction},
    Identifiable, Value,
};

#[cfg(feature = "http")]
pub mod cursor;
#[cfg(feature = "http")]
pub mod pagination;
#[cfg(feature = "http")]
pub mod sorting;

macro_rules! queries {
    ($($($meta:meta)* $item:item)+) => {
        pub use self::model::*;

        #[iroha_data_model_derive::model]
        pub mod model{
            use super::*; $(

            #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
            #[derive(parity_scale_codec::Decode, parity_scale_codec::Encode)]
            #[derive(serde::Deserialize, serde::Serialize)]
            #[derive(iroha_schema::IntoSchema)]
            $($meta)*
            $item )+
        }
    };
}

/// Trait for typesafe query output
pub trait Query: Into<QueryBox> + seal::Sealed {
    /// Output type of query
    type Output: Into<Value> + TryFrom<Value>;
}

#[model]
pub mod model {
    use getset::Getters;
    use iroha_crypto::HashOf;

    use super::*;
    use crate::{block::VersionedSignedBlock, permission::PermissionTokenId};

    /// Sized container for all possible Queries.
    #[allow(clippy::enum_variant_names)]
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        FromVariant,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[ffi_type]
    #[allow(missing_docs)]
    pub enum QueryBox {
        FindAllAccounts(FindAllAccounts),
        FindAccountById(FindAccountById),
        FindAccountKeyValueByIdAndKey(FindAccountKeyValueByIdAndKey),
        FindAccountsByName(FindAccountsByName),
        FindAccountsByDomainId(FindAccountsByDomainId),
        FindAccountsWithAsset(FindAccountsWithAsset),
        FindAllAssets(FindAllAssets),
        FindAllAssetsDefinitions(FindAllAssetsDefinitions),
        FindAssetById(FindAssetById),
        FindAssetDefinitionById(FindAssetDefinitionById),
        FindAssetsByName(FindAssetsByName),
        FindAssetsByAccountId(FindAssetsByAccountId),
        FindAssetsByAssetDefinitionId(FindAssetsByAssetDefinitionId),
        FindAssetsByDomainId(FindAssetsByDomainId),
        FindAssetsByDomainIdAndAssetDefinitionId(FindAssetsByDomainIdAndAssetDefinitionId),
        FindAssetQuantityById(FindAssetQuantityById),
        FindTotalAssetQuantityByAssetDefinitionId(FindTotalAssetQuantityByAssetDefinitionId),
        IsAssetDefinitionOwner(IsAssetDefinitionOwner),
        FindAssetKeyValueByIdAndKey(FindAssetKeyValueByIdAndKey),
        FindAssetDefinitionKeyValueByIdAndKey(FindAssetDefinitionKeyValueByIdAndKey),
        FindAllDomains(FindAllDomains),
        FindDomainById(FindDomainById),
        FindDomainKeyValueByIdAndKey(FindDomainKeyValueByIdAndKey),
        FindAllPeers(FindAllPeers),
        FindAllBlocks(FindAllBlocks),
        FindAllBlockHeaders(FindAllBlockHeaders),
        FindBlockHeaderByHash(FindBlockHeaderByHash),
        FindAllTransactions(FindAllTransactions),
        FindTransactionsByAccountId(FindTransactionsByAccountId),
        FindTransactionByHash(FindTransactionByHash),
        FindPermissionTokensByAccountId(FindPermissionTokensByAccountId),
        FindPermissionTokenSchema(FindPermissionTokenSchema),
        FindAllActiveTriggerIds(FindAllActiveTriggerIds),
        FindTriggerById(FindTriggerById),
        FindTriggerKeyValueByIdAndKey(FindTriggerKeyValueByIdAndKey),
        FindTriggersByDomainId(FindTriggersByDomainId),
        FindAllRoles(FindAllRoles),
        FindAllRoleIds(FindAllRoleIds),
        FindRoleByRoleId(FindRoleByRoleId),
        FindRolesByAccountId(FindRolesByAccountId),
        FindAllParameters(FindAllParameters),
    }

    /// Output of [`FindAllTransactions`] query
    #[derive(
        Debug, Clone, PartialEq, Eq, Getters, Decode, Encode, Deserialize, Serialize, IntoSchema,
    )]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct TransactionQueryOutput {
        /// Transaction
        pub transaction: TransactionValue,
        /// The hash of the block to which `tx` belongs to
        pub block_hash: HashOf<VersionedSignedBlock>,
    }

    /// Type returned from [`Metadata`] queries
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
    #[ffi_type]
    pub struct MetadataValue(pub Value);
}

impl From<MetadataValue> for Value {
    #[inline]
    fn from(source: MetadataValue) -> Self {
        source.0
    }
}

impl From<Value> for MetadataValue {
    #[inline]
    fn from(source: Value) -> Self {
        Self(source)
    }
}

impl Query for QueryBox {
    type Output = Value;
}

impl TransactionQueryOutput {
    #[inline]
    /// Return payload of the transaction
    pub fn payload(&self) -> &TransactionPayload {
        self.transaction.payload()
    }
}

impl PartialOrd for TransactionQueryOutput {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TransactionQueryOutput {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        let tx1 = self.transaction.payload();
        let tx2 = other.transaction.payload();

        tx1.creation_time().cmp(&tx2.creation_time())
    }
}

pub mod role {
    //! Queries related to [`Role`].

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;

    use super::Query;
    use crate::prelude::*;

    queries! {
        /// [`FindAllRoles`] Iroha Query finds all [`Role`]s presented.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all roles")]
        #[ffi_type]
        pub struct FindAllRoles;

        /// [`FindAllRoleIds`] Iroha Query finds [`Id`](crate::RoleId)s of
        /// all [`Role`]s presented.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all role ids")]
        #[ffi_type]
        pub struct FindAllRoleIds;


        /// [`FindRoleByRoleId`] Iroha Query finds the [`Role`] which has the given [`Id`](crate::RoleId)
        #[derive(Display)]
        #[display(fmt = "Find `{id}` role")]
        #[repr(transparent)]
        // SAFETY: `FindRoleByRoleId` has no trap representation in `EvaluatesTo<RoleId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindRoleByRoleId {
            /// `Id` of the [`Role`] to find
            pub id: EvaluatesTo<RoleId>,
        }

        /// [`FindRolesByAccountId`] Iroha Query finds all [`Role`]s for a specified account.
        #[derive(Display)]
        #[display(fmt = "Find all roles for `{id}` account")]
        #[repr(transparent)]
        // SAFETY: `FindRolesByAccountId` has no trap representation in `EvaluatesTo<AccountId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindRolesByAccountId {
            /// `Id` of an account to find.
            pub id: EvaluatesTo<AccountId>,
        }
    }

    impl Query for FindAllRoles {
        type Output = Vec<Role>;
    }

    impl Query for FindAllRoleIds {
        type Output = Vec<RoleId>;
    }

    impl Query for FindRolesByAccountId {
        type Output = Vec<RoleId>;
    }

    impl Query for FindRoleByRoleId {
        type Output = Role;
    }

    impl FindRoleByRoleId {
        /// Construct [`FindRoleByRoleId`].
        pub fn new(id: impl Into<EvaluatesTo<RoleId>>) -> Self {
            Self { id: id.into() }
        }
    }

    impl FindRolesByAccountId {
        /// Construct [`FindRolesByAccountId`].
        pub fn new(account_id: impl Into<EvaluatesTo<AccountId>>) -> Self {
            Self {
                id: account_id.into(),
            }
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this module.
    pub mod prelude {
        pub use super::{FindAllRoleIds, FindAllRoles, FindRoleByRoleId, FindRolesByAccountId};
    }
}

pub mod permission {
    //! Queries related to [`PermissionToken`].

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;

    use super::Query;
    use crate::{
        permission::{self, PermissionTokenSchema},
        prelude::*,
    };

    queries! {
        /// Finds all registered permission tokens
        #[derive(Copy, Display)]
        #[ffi_type]
        pub struct FindPermissionTokenSchema;

        /// [`FindPermissionTokensByAccountId`] Iroha Query finds all [`PermissionToken`]s
        /// for a specified account.
        #[derive(Display)]
        #[display(fmt = "Find permission tokens specified for `{id}` account")]
        #[repr(transparent)]
        // SAFETY: `FindPermissionTokensByAccountId` has no trap representation in `EvaluatesTo<AccountId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindPermissionTokensByAccountId {
            /// `Id` of an account to find.
            pub id: EvaluatesTo<AccountId>,
        }
    }

    impl Query for FindPermissionTokenSchema {
        type Output = PermissionTokenSchema;
    }

    impl Query for FindPermissionTokensByAccountId {
        type Output = Vec<permission::PermissionToken>;
    }

    impl FindPermissionTokensByAccountId {
        /// Construct [`FindPermissionTokensByAccountId`].
        pub fn new(account_id: impl Into<EvaluatesTo<AccountId>>) -> Self {
            Self {
                id: account_id.into(),
            }
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this module.
    pub mod prelude {
        pub use super::{FindPermissionTokenSchema, FindPermissionTokensByAccountId};
    }
}

pub mod account {
    //! Queries related to [`Account`].

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;

    use super::{MetadataValue, Query};
    use crate::prelude::*;

    queries! {
        // TODO: Better to have find all account ids query instead.
        /// [`FindAllAccounts`] Iroha Query finds all [`Account`]s presented.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all accounts")]
        #[ffi_type]
        pub struct FindAllAccounts;

        /// [`FindAccountById`] Iroha Query finds an [`Account`] by it's identification.
        #[derive(Display)]
        #[display(fmt = "Find `{id}` account")]
        #[repr(transparent)]
        // SAFETY: `FindAccountById` has no trap representation in `EvaluatesTo<AccountId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAccountById {
            /// `Id` of an account to find.
            pub id: EvaluatesTo<AccountId>,
        }

        /// [`FindAccountKeyValueByIdAndKey`] Iroha Query finds a [`Value`]
        /// of the key-value metadata pair in the specified account.
        #[derive(Display)]
        #[display(fmt = "Find metadata value with `{key}` key in `{id}` account")]
        #[ffi_type]
        pub struct FindAccountKeyValueByIdAndKey {
            /// `Id` of an account to find.
            pub id: EvaluatesTo<AccountId>,
            /// Key of the specific key-value in the Account's metadata.
            pub key: EvaluatesTo<Name>,
        }

        /// [`FindAccountsByName`] Iroha Query gets [`Account`]s name as input and
        /// finds all [`Account`]s with this name.
        #[derive(Display)]
        #[display(fmt = "Find accounts with `{name}` name")]
        #[repr(transparent)]
        // SAFETY: `FindAccountsByName` has no trap representation in `EvaluatesTo<Name>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAccountsByName {
            /// `name` of accounts to find.
            pub name: EvaluatesTo<Name>,
        }


        /// [`FindAccountsByDomainId`] Iroha Query gets [`Domain`]s id as input and
        /// finds all [`Account`]s under this [`Domain`].
        #[derive(Display)]
        #[display(fmt = "Find accounts under `{domain_id}` domain")]
        #[repr(transparent)]
        // SAFETY: `FindAccountsByDomainId` has no trap representation in `EvaluatesTo<DomainId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAccountsByDomainId {
            /// `Id` of the domain under which accounts should be found.
            pub domain_id: EvaluatesTo<DomainId>,
        }

        /// [`FindAccountsWithAsset`] Iroha Query gets [`AssetDefinition`]s id as input and
        /// finds all [`Account`]s storing [`Asset`] with such definition.
        #[derive(Display)]
        #[display(fmt = "Find accounts with `{asset_definition_id}` asset")]
        #[repr(transparent)]
        // SAFETY: `FindAccountsWithAsset` has no trap representation in `EvaluatesTo<AssetDefinitionId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAccountsWithAsset {
            /// `Id` of the definition of the asset which should be stored in founded accounts.
            pub asset_definition_id: EvaluatesTo<AssetDefinitionId>,
        }
    }

    impl Query for FindAllAccounts {
        type Output = Vec<Account>;
    }

    impl Query for FindAccountById {
        type Output = Account;
    }

    impl Query for FindAccountKeyValueByIdAndKey {
        type Output = MetadataValue;
    }

    impl Query for FindAccountsByName {
        type Output = Vec<Account>;
    }

    impl Query for FindAccountsByDomainId {
        type Output = Vec<Account>;
    }

    impl Query for FindAccountsWithAsset {
        type Output = Vec<Account>;
    }

    impl FindAccountById {
        /// Construct [`FindAccountById`].
        pub fn new(id: impl Into<EvaluatesTo<AccountId>>) -> Self {
            Self { id: id.into() }
        }
    }

    impl FindAccountKeyValueByIdAndKey {
        /// Construct [`FindAccountById`].
        pub fn new(
            id: impl Into<EvaluatesTo<AccountId>>,
            key: impl Into<EvaluatesTo<Name>>,
        ) -> Self {
            Self {
                id: id.into(),
                key: key.into(),
            }
        }
    }

    impl FindAccountsByName {
        /// Construct [`FindAccountsByName`].
        pub fn new(name: impl Into<EvaluatesTo<Name>>) -> Self {
            Self { name: name.into() }
        }
    }

    impl FindAccountsByDomainId {
        /// Construct [`FindAccountsByDomainId`].
        pub fn new(domain_id: impl Into<EvaluatesTo<DomainId>>) -> Self {
            Self {
                domain_id: domain_id.into(),
            }
        }
    }

    impl FindAccountsWithAsset {
        /// Construct [`FindAccountsWithAsset`].
        pub fn new(asset_definition_id: impl Into<EvaluatesTo<AssetDefinitionId>>) -> Self {
            Self {
                asset_definition_id: asset_definition_id.into(),
            }
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{
            FindAccountById, FindAccountKeyValueByIdAndKey, FindAccountsByDomainId,
            FindAccountsByName, FindAccountsWithAsset, FindAllAccounts,
        };
    }
}

pub mod asset {
    //! Queries related to [`Asset`].

    #![allow(clippy::missing_inline_in_public_items)]

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;
    use iroha_data_model_derive::model;

    pub use self::model::*;
    use super::{MetadataValue, Query};
    use crate::prelude::*;

    queries! {
        /// [`FindAllAssets`] Iroha Query finds all [`Asset`]s presented in Iroha Peer.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all assets")]
        #[ffi_type]
        pub struct FindAllAssets;

        /// [`FindAllAssetsDefinitions`] Iroha Query finds all [`AssetDefinition`]s presented
        /// in Iroha Peer.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all asset definitions")]
        #[ffi_type]
        pub struct FindAllAssetsDefinitions; // TODO: Should it be renamed to [`FindAllAssetDefinitions`?

        /// [`FindAssetById`] Iroha Query finds an [`Asset`] by it's identification in Iroha [`Peer`].
        #[derive(Display)]
        #[display(fmt = "Find `{id}` asset")]
        #[repr(transparent)]
        // SAFETY: `FindAssetById` has no trap representation in `EvaluatesTo<AssetId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAssetById {
            /// `Id` of an [`Asset`] to find.
            pub id: EvaluatesTo<AssetId>,
        }

        /// [`FindAssetDefinitionById`] Iroha Query finds an [`AssetDefinition`] by it's identification in Iroha [`Peer`].
        #[derive(Display)]
        #[display(fmt = "Find `{id}` asset definition")]
        #[repr(transparent)]
        // SAFETY: `FindAssetDefinitionById` has no trap representation in `EvaluatesTo<AssetDefinitionId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAssetDefinitionById {
            /// `Id` of an [`AssetDefinition`] to find.
            pub id: EvaluatesTo<AssetDefinitionId>,
        }

        /// [`FindAssetsByName`] Iroha Query gets [`Asset`]s name as input and
        /// finds all [`Asset`]s with it in Iroha [`Peer`].
        #[derive(Display)]
        #[display(fmt = "Find asset with `{name}` name")]
        #[repr(transparent)]
        // SAFETY: `FindAssetsByName` has no trap representation in `EvaluatesTo<Name>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAssetsByName {
            /// [`Name`] of [`Asset`]s to find.
            pub name: EvaluatesTo<Name>,
        }

        /// [`FindAssetsByAccountId`] Iroha Query gets [`AccountId`] as input and find all [`Asset`]s
        /// owned by the [`Account`] in Iroha Peer.
        #[derive(Display)]
        #[display(fmt = "Find assets owned by the `{account_id}` account")]
        #[repr(transparent)]
        // SAFETY: `FindAssetsByAccountId` has no trap representation in `EvaluatesTo<AccountId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAssetsByAccountId {
            /// [`AccountId`] under which assets should be found.
            pub account_id: EvaluatesTo<AccountId>,
        }

        /// [`FindAssetsByAssetDefinitionId`] Iroha Query gets [`AssetDefinitionId`] as input and
        /// finds all [`Asset`]s with this [`AssetDefinition`] in Iroha Peer.
        #[derive(Display)]
        #[display(fmt = "Find assets with `{asset_definition_id}` asset definition")]
        #[repr(transparent)]
        // SAFETY: `FindAssetsByAssetDefinitionId` has no trap representation in `EvaluatesTo<AssetDefinitionId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAssetsByAssetDefinitionId {
            /// [`AssetDefinitionId`] with type of [`Asset`]s should be found.
            pub asset_definition_id: EvaluatesTo<AssetDefinitionId>,
        }

        /// [`FindAssetsByDomainId`] Iroha Query gets [`Domain`]s id as input and
        /// finds all [`Asset`]s under this [`Domain`] in Iroha [`Peer`].
        #[derive(Display)]
        #[display(fmt = "Find assets under the `{domain_id}` domain")]
        #[repr(transparent)]
        // SAFETY: `FindAssetsByDomainId` has no trap representation in `EvaluatesTo<DomainId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAssetsByDomainId {
            /// `Id` of the domain under which assets should be found.
            pub domain_id: EvaluatesTo<DomainId>,
        }

        /// [`FindAssetsByDomainIdAndAssetDefinitionId`] Iroha Query gets [`DomainId`] and
        /// [`AssetDefinitionId`] as inputs and finds [`Asset`]s under the [`Domain`]
        /// with this [`AssetDefinition`] in Iroha [`Peer`].
        #[derive(Display)]
        #[display(fmt = "Find assets under the `{domain_id}` domain with `{asset_definition_id}` asset definition")]
        #[ffi_type]
        pub struct FindAssetsByDomainIdAndAssetDefinitionId {
            /// `Id` of the domain under which assets should be found.
            pub domain_id: EvaluatesTo<DomainId>,
            /// [`AssetDefinitionId`] assets of which type should be found.
            pub asset_definition_id: EvaluatesTo<AssetDefinitionId>,
        }

        /// [`FindAssetQuantityById`] Iroha Query gets [`AssetId`] as input and finds [`Asset::quantity`]
        /// parameter's value if [`Asset`] is presented in Iroha Peer.
        #[derive(Display)]
        #[display(fmt = "Find quantity of the `{id}` asset")]
        #[repr(transparent)]
        // SAFETY: `FindAssetQuantityById` has no trap representation in `EvaluatesTo<AssetId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAssetQuantityById {
            /// `Id` of an [`Asset`] to find quantity of.
            pub id: EvaluatesTo<AssetId>,
        }

        /// [`FindTotalAssetQuantityByAssetDefinitionId`] Iroha Query gets [`AssetDefinitionId`] as input and finds total [`Asset::quantity`]
        /// if [`AssetDefinitionId`] is presented in Iroha Peer.
        /// In case of `Store` asset value type total quantity is sum of assets through all accounts with provided [`AssetDefinitionId`].
        #[derive(Display)]
        #[display(fmt = "Find total quantity of the `{id}` asset")]
        #[repr(transparent)]
        // SAFETY: `FindTotalAssetQuantityByAssetDefinitionId` has no trap representation in `EvaluatesTo<AssetDefinitionId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindTotalAssetQuantityByAssetDefinitionId {
            /// `Id` of an [`Asset`] to find quantity of.
            pub id: EvaluatesTo<AssetDefinitionId>,
        }

        /// [`FindAssetKeyValueByIdAndKey`] Iroha Query gets [`AssetId`] and key as input and finds [`Value`]
        /// of the key-value pair stored in this asset.
        #[derive(Display)]
        #[display(fmt = "Find metadata value with `{key}` key in `{id}` asset")]
        #[ffi_type]
        pub struct FindAssetKeyValueByIdAndKey {
            /// `Id` of an [`Asset`] acting as [`Store`](crate::asset::AssetValue::Store).
            pub id: EvaluatesTo<AssetId>,
            /// The key of the key-value pair stored in the asset.
            pub key: EvaluatesTo<Name>,
        }

        /// [`FindAssetDefinitionKeyValueByIdAndKey`] Iroha Query gets [`AssetDefinitionId`] and key as input and finds [`Value`]
        /// of the key-value pair stored in this asset definition.
        #[derive(Display)]
        #[display(fmt = "Find metadata value with `{key}` key in `{id}` asset definition")]
        #[ffi_type]
        pub struct FindAssetDefinitionKeyValueByIdAndKey {
            /// `Id` of an [`Asset`] acting as [`Store`](crate::asset::AssetValue::Store)..
            pub id: EvaluatesTo<AssetDefinitionId>,
            /// The key of the key-value pair stored in the asset.
            pub key: EvaluatesTo<Name>,
        }

        /// [`IsAssetDefinitionOwner`] Iroha Query checks if provided account is the asset definition owner.
        #[derive(Display)]
        #[display(fmt = "Check if `{account_id}` is creator of `{asset_definition_id}` asset")]
        #[ffi_type]
        pub struct IsAssetDefinitionOwner {
            /// `Id` of an [`AssetDefinition`] to check.
            pub asset_definition_id: EvaluatesTo<AssetDefinitionId>,
            /// `Id` of a possible owner [`Account`].
            pub account_id: EvaluatesTo<AccountId>,
        }
    }
    impl Query for FindAllAssets {
        type Output = Vec<Asset>;
    }

    impl Query for FindAllAssetsDefinitions {
        type Output = Vec<AssetDefinition>;
    }

    impl Query for FindAssetById {
        type Output = Asset;
    }

    impl Query for FindAssetDefinitionById {
        type Output = AssetDefinition;
    }

    impl Query for FindAssetsByName {
        type Output = Vec<Asset>;
    }

    impl Query for FindAssetsByAccountId {
        type Output = Vec<Asset>;
    }

    impl Query for FindAssetsByAssetDefinitionId {
        type Output = Vec<Asset>;
    }

    impl Query for FindAssetsByDomainId {
        type Output = Vec<Asset>;
    }

    impl Query for FindAssetsByDomainIdAndAssetDefinitionId {
        type Output = Vec<Asset>;
    }

    impl Query for FindAssetQuantityById {
        type Output = NumericValue;
    }

    impl Query for FindTotalAssetQuantityByAssetDefinitionId {
        type Output = NumericValue;
    }

    impl Query for FindAssetKeyValueByIdAndKey {
        type Output = MetadataValue;
    }

    impl Query for FindAssetDefinitionKeyValueByIdAndKey {
        type Output = MetadataValue;
    }

    impl Query for IsAssetDefinitionOwner {
        type Output = bool;
    }

    impl FindAssetById {
        /// Construct [`FindAssetById`].
        pub fn new(id: impl Into<EvaluatesTo<AssetId>>) -> Self {
            Self { id: id.into() }
        }
    }

    impl FindAssetDefinitionById {
        /// Construct [`FindAssetDefinitionById`].
        pub fn new(id: impl Into<EvaluatesTo<AssetDefinitionId>>) -> Self {
            Self { id: id.into() }
        }
    }

    impl FindAssetsByName {
        /// Construct [`FindAssetsByName`].
        pub fn new(name: impl Into<EvaluatesTo<Name>>) -> Self {
            Self { name: name.into() }
        }
    }

    impl FindAssetsByAccountId {
        /// Construct [`FindAssetsByAccountId`].
        pub fn new(account_id: impl Into<EvaluatesTo<AccountId>>) -> Self {
            Self {
                account_id: account_id.into(),
            }
        }
    }

    impl FindAssetsByAssetDefinitionId {
        /// Construct [`FindAssetsByAssetDefinitionId`].
        pub fn new(asset_definition_id: impl Into<EvaluatesTo<AssetDefinitionId>>) -> Self {
            Self {
                asset_definition_id: asset_definition_id.into(),
            }
        }
    }

    impl FindAssetsByDomainId {
        /// Construct [`FindAssetsByDomainId`].
        pub fn new(domain_id: impl Into<EvaluatesTo<DomainId>>) -> Self {
            Self {
                domain_id: domain_id.into(),
            }
        }
    }

    impl FindAssetsByDomainIdAndAssetDefinitionId {
        /// Construct [`FindAssetsByDomainIdAndAssetDefinitionId`].
        pub fn new(
            domain_id: impl Into<EvaluatesTo<DomainId>>,
            asset_definition_id: impl Into<EvaluatesTo<AssetDefinitionId>>,
        ) -> Self {
            Self {
                domain_id: domain_id.into(),
                asset_definition_id: asset_definition_id.into(),
            }
        }
    }

    impl FindAssetQuantityById {
        /// Construct [`FindAssetQuantityById`].
        pub fn new(id: impl Into<EvaluatesTo<AssetId>>) -> Self {
            Self { id: id.into() }
        }
    }

    impl FindTotalAssetQuantityByAssetDefinitionId {
        /// Construct [`FindTotalAssetQuantityByAssetDefinitionId`]
        pub fn new(id: impl Into<EvaluatesTo<AssetDefinitionId>>) -> Self {
            Self { id: id.into() }
        }
    }

    impl FindAssetKeyValueByIdAndKey {
        /// Construct [`FindAssetKeyValueByIdAndKey`].
        pub fn new(id: impl Into<EvaluatesTo<AssetId>>, key: impl Into<EvaluatesTo<Name>>) -> Self {
            Self {
                id: id.into(),
                key: key.into(),
            }
        }
    }

    impl FindAssetDefinitionKeyValueByIdAndKey {
        /// Construct [`FindAssetDefinitionKeyValueByIdAndKey`].
        pub fn new(
            id: impl Into<EvaluatesTo<AssetDefinitionId>>,
            key: impl Into<EvaluatesTo<Name>>,
        ) -> Self {
            Self {
                id: id.into(),
                key: key.into(),
            }
        }
    }

    impl IsAssetDefinitionOwner {
        /// Construct [`IsAssetDefinitionOwner`].
        pub fn new(
            asset_definition_id: impl Into<EvaluatesTo<AssetDefinitionId>>,
            account_id: impl Into<EvaluatesTo<AccountId>>,
        ) -> Self {
            Self {
                asset_definition_id: asset_definition_id.into(),
                account_id: account_id.into(),
            }
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{
            FindAllAssets, FindAllAssetsDefinitions, FindAssetById, FindAssetDefinitionById,
            FindAssetDefinitionKeyValueByIdAndKey, FindAssetKeyValueByIdAndKey,
            FindAssetQuantityById, FindAssetsByAccountId, FindAssetsByAssetDefinitionId,
            FindAssetsByDomainId, FindAssetsByDomainIdAndAssetDefinitionId, FindAssetsByName,
            FindTotalAssetQuantityByAssetDefinitionId, IsAssetDefinitionOwner,
        };
    }
}

pub mod domain {
    //! Queries related to [`Domain`].

    #![allow(clippy::missing_inline_in_public_items)]

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;

    use super::{MetadataValue, Query};
    use crate::prelude::*;

    queries! {
        /// [`FindAllDomains`] Iroha Query finds all [`Domain`]s presented in Iroha [`Peer`].
        #[derive(Copy, Display)]
        #[display(fmt = "Find all domains")]
        #[ffi_type]
        pub struct FindAllDomains;

        /// [`FindDomainById`] Iroha Query finds a [`Domain`] by it's identification in Iroha [`Peer`].
        #[derive(Display)]
        #[display(fmt = "Find `{id}` domain")]
        #[repr(transparent)]
        // SAFETY: `FindTotalAssetQuantityByAssetDefinitionId` has no trap representation in `EvaluatesTo<DomainId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindDomainById {
            /// `Id` of the domain to find.
            pub id: EvaluatesTo<DomainId>,
        }


        /// [`FindDomainKeyValueByIdAndKey`] Iroha Query finds a [`Value`] of the key-value metadata pair
        /// in the specified domain.
        #[derive(Display)]
        #[display(fmt = "Find metadata value with key `{key}` in `{id}` domain")]
        #[ffi_type]
        pub struct FindDomainKeyValueByIdAndKey {
            /// `Id` of an domain to find.
            pub id: EvaluatesTo<DomainId>,
            /// Key of the specific key-value in the domain's metadata.
            pub key: EvaluatesTo<Name>,
        }
    }

    impl Query for FindAllDomains {
        type Output = Vec<Domain>;
    }

    impl Query for FindDomainById {
        type Output = Domain;
    }

    impl Query for FindDomainKeyValueByIdAndKey {
        type Output = MetadataValue;
    }

    impl FindDomainById {
        /// Construct [`FindDomainById`].
        pub fn new(id: impl Into<EvaluatesTo<DomainId>>) -> Self {
            Self { id: id.into() }
        }
    }

    impl FindDomainKeyValueByIdAndKey {
        /// Construct [`FindDomainKeyValueByIdAndKey`].
        pub fn new(
            id: impl Into<EvaluatesTo<DomainId>>,
            key: impl Into<EvaluatesTo<Name>>,
        ) -> Self {
            Self {
                id: id.into(),
                key: key.into(),
            }
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{FindAllDomains, FindDomainById, FindDomainKeyValueByIdAndKey};
    }
}

pub mod peer {
    //! Queries related to [`Domain`](crate::domain::Domain).

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;

    use super::Query;
    use crate::{parameter::Parameter, peer::Peer};

    queries! {
        /// [`FindAllPeers`] Iroha Query finds all trusted [`Peer`]s presented in current Iroha [`Peer`].
        #[derive(Copy, Display)]
        #[display(fmt = "Find all peers")]
        #[ffi_type]
        pub struct FindAllPeers;


        /// [`FindAllParameters`] Iroha Query finds all [`Peer`]s parameters.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all peers parameters")]
        // TODO: Unused query. Remove?
        #[ffi_type]
        pub struct FindAllParameters;
    }

    impl Query for FindAllPeers {
        type Output = Vec<Peer>;
    }

    impl Query for FindAllParameters {
        type Output = Vec<Parameter>;
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{FindAllParameters, FindAllPeers};
    }
}

pub mod trigger {
    //! Trigger-related queries.
    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;

    use super::{MetadataValue, Query};
    use crate::{
        domain::prelude::*,
        events::TriggeringFilterBox,
        expression::EvaluatesTo,
        prelude::InstructionBox,
        trigger::{OptimizedExecutable, Trigger, TriggerId},
        Executable, Identifiable, Name, Value,
    };

    queries! {
        /// Find all currently active (as in not disabled and/or expired)
        /// trigger IDs.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all trigger ids")]
        #[ffi_type]
        pub struct FindAllActiveTriggerIds;


        /// Find Trigger given its ID.
        #[derive(Display)]
        #[display(fmt = "Find `{id}` trigger")]
        #[repr(transparent)]
        // SAFETY: `FindTriggerById` has no trap representation in `EvaluatesTo<TriggerId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindTriggerById {
            /// The Identification of the trigger to be found.
            pub id: EvaluatesTo<TriggerId>,
        }


        /// Find Trigger's metadata key-value pairs.
        #[derive(Display)]
        #[display(fmt = "Find metadata value with `{key}` key in `{id}` trigger")]
        #[ffi_type]
        pub struct FindTriggerKeyValueByIdAndKey {
            /// The Identification of the trigger to be found.
            pub id: EvaluatesTo<TriggerId>,
            /// The key inside the metadata dictionary to be returned.
            pub key: EvaluatesTo<Name>,
        }


        /// Find [`Trigger`]s under the given [`DomainId`].
        #[derive(Display)]
        #[display(fmt = "Find trigger under `{domain_id}` domain")]
        #[repr(transparent)]
        // SAFETY: `FindTriggersByDomainId` has no trap representation in `EvaluatesTo<DomainId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindTriggersByDomainId {
            /// [`DomainId`] specifies the domain in which to search for triggers.
            pub domain_id: EvaluatesTo<DomainId>,
        }
    }

    impl Query for FindAllActiveTriggerIds {
        type Output = Vec<TriggerId>;
    }

    impl Query for FindTriggerById {
        type Output = Trigger<TriggeringFilterBox, OptimizedExecutable>;
    }

    impl Query for FindTriggerKeyValueByIdAndKey {
        type Output = MetadataValue;
    }

    impl Query for FindTriggersByDomainId {
        type Output = Vec<Trigger<TriggeringFilterBox, OptimizedExecutable>>;
    }

    impl FindTriggerById {
        /// Construct [`FindTriggerById`].
        pub fn new(id: impl Into<EvaluatesTo<TriggerId>>) -> Self {
            Self { id: id.into() }
        }
    }

    impl FindTriggerKeyValueByIdAndKey {
        /// Construct [`FindTriggerKeyValueByIdAndKey`].
        pub fn new(
            id: impl Into<EvaluatesTo<TriggerId>>,
            key: impl Into<EvaluatesTo<Name>>,
        ) -> Self {
            Self {
                id: id.into(),
                key: key.into(),
            }
        }
    }

    impl FindTriggersByDomainId {
        /// Construct [`FindTriggersByDomainId`].
        pub fn new(domain_id: impl Into<EvaluatesTo<DomainId>>) -> Self {
            Self {
                domain_id: domain_id.into(),
            }
        }
    }

    pub mod prelude {
        //! Prelude Re-exports most commonly used traits, structs and macros from this crate.
        pub use super::{
            FindAllActiveTriggerIds, FindTriggerById, FindTriggerKeyValueByIdAndKey,
            FindTriggersByDomainId,
        };
    }
}

pub mod transaction {
    //! Queries related to transactions.

    #![allow(clippy::missing_inline_in_public_items)]

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;
    use iroha_crypto::HashOf;

    use super::{Query, TransactionQueryOutput};
    use crate::{
        account::AccountId, expression::EvaluatesTo, prelude::Account,
        transaction::VersionedSignedTransaction,
    };

    queries! {
        /// [`FindAllTransactions`] Iroha Query lists all transactions included in a blockchain
        #[derive(Copy, Display)]
        #[display(fmt = "Find all transactions")]
        #[ffi_type]
        pub struct FindAllTransactions;

        /// [`FindTransactionsByAccountId`] Iroha Query finds all transactions included in a blockchain
        /// for the account
        #[derive(Display)]
        #[display(fmt = "Find all transactions for `{account_id}` account")]
        #[repr(transparent)]
        // SAFETY: `FindTransactionsByAccountId` has no trap representation in `EvaluatesTo<AccountId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindTransactionsByAccountId {
            /// Signer's [`AccountId`] under which transactions should be found.
            pub account_id: EvaluatesTo<AccountId>,
        }

        /// [`FindTransactionByHash`] Iroha Query finds a transaction (if any)
        /// with corresponding hash value
        #[derive(Display)]
        #[display(fmt = "Find transaction with `{hash}` hash")]
        #[repr(transparent)]
        // SAFETY: `FindTransactionByHash` has no trap representation in `EvaluatesTo<HashOf<VersionedSignedTransaction>>`
        #[ffi_type(unsafe {robust})]
        pub struct FindTransactionByHash {
            /// Transaction hash.
            pub hash: EvaluatesTo<HashOf<VersionedSignedTransaction>>,
        }
    }

    impl Query for FindAllTransactions {
        type Output = Vec<TransactionQueryOutput>;
    }

    impl Query for FindTransactionsByAccountId {
        type Output = Vec<TransactionQueryOutput>;
    }

    impl Query for FindTransactionByHash {
        type Output = TransactionQueryOutput;
    }

    impl FindTransactionsByAccountId {
        /// Construct [`FindTransactionsByAccountId`].
        pub fn new(account_id: impl Into<EvaluatesTo<AccountId>>) -> Self {
            Self {
                account_id: account_id.into(),
            }
        }
    }

    impl FindTransactionByHash {
        /// Construct [`FindTransactionByHash`].
        pub fn new(hash: impl Into<EvaluatesTo<HashOf<VersionedSignedTransaction>>>) -> Self {
            Self { hash: hash.into() }
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{FindAllTransactions, FindTransactionByHash, FindTransactionsByAccountId};
    }
}

pub mod block {
    //! Queries related to blocks.

    #![allow(clippy::missing_inline_in_public_items)]

    #[cfg(not(feature = "std"))]
    use alloc::{boxed::Box, format, string::String, vec::Vec};

    use derive_more::Display;
    use iroha_crypto::HashOf;

    use super::Query;
    use crate::{
        block::{BlockHeader, VersionedSignedBlock},
        prelude::EvaluatesTo,
    };

    queries! {
        /// [`FindAllBlocks`] Iroha Query lists all blocks sorted by
        /// height in descending order
        #[derive(Copy, Display)]
        #[display(fmt = "Find all blocks")]
        #[ffi_type]
        pub struct FindAllBlocks;

        /// [`FindAllBlockHeaders`] Iroha Query lists all block headers
        /// sorted by height in descending order
        #[derive(Copy, Display)]
        #[display(fmt = "Find all block headers")]
        #[ffi_type]
        pub struct FindAllBlockHeaders;

        /// [`FindBlockHeaderByHash`] Iroha Query finds block header by block hash
        #[derive(Display)]
        #[display(fmt = "Find block header with `{hash}` hash")]
        #[repr(transparent)]
        // SAFETY: `FindBlockHeaderByHash` has no trap representation in `EvaluatesTo<HashOf<VersionedSignedBlock>>`
        #[ffi_type(unsafe {robust})]
        pub struct FindBlockHeaderByHash {
            /// Block hash.
            pub hash: EvaluatesTo<HashOf<VersionedSignedBlock>>,
        }
    }

    impl Query for FindAllBlocks {
        type Output = Vec<VersionedSignedBlock>;
    }

    impl Query for FindAllBlockHeaders {
        type Output = Vec<BlockHeader>;
    }

    impl Query for FindBlockHeaderByHash {
        type Output = BlockHeader;
    }

    impl FindBlockHeaderByHash {
        /// Construct [`FindBlockHeaderByHash`].
        pub fn new(hash: impl Into<EvaluatesTo<HashOf<VersionedSignedBlock>>>) -> Self {
            Self { hash: hash.into() }
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{FindAllBlockHeaders, FindAllBlocks, FindBlockHeaderByHash};
    }
}

#[cfg(feature = "http")]
pub mod http {
    //! Structures related to sending queries over HTTP

    use getset::Getters;
    use iroha_data_model_derive::model;

    pub use self::model::*;
    use super::*;
    use crate::{account::AccountId, predicate::PredicateBox};

    // TODO: Could we make a variant of `Value` that holds only query results?
    /// Type representing Result of executing a query
    pub type QueryOutput = Value;

    declare_versioned_with_scale!(VersionedSignedQuery 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema);

    #[model]
    pub mod model {
        use core::num::NonZeroU64;

        use super::*;

        /// I/O ready structure to send queries.
        #[derive(Debug, Clone)]
        #[repr(transparent)]
        #[must_use]
        pub struct QueryBuilder {
            /// Payload
            pub(super) payload: QueryPayload,
        }

        /// Payload of a query.
        #[derive(
            Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
        )]
        pub(crate) struct QueryPayload {
            /// Account id of the user who will sign this query.
            pub authority: AccountId,
            /// Query definition.
            pub query: QueryBox,
            /// The filter applied to the result on the server-side.
            pub filter: PredicateBox,
        }

        /// I/O ready structure to send queries.
        #[derive(Debug, Clone, Encode, Serialize, IntoSchema)]
        #[version_with_scale(version = 1, versioned_alias = "VersionedSignedQuery")]
        pub struct SignedQuery {
            /// Signature of the client who sends this query.
            pub signature: SignatureOf<QueryPayload>,
            /// Payload
            pub payload: QueryPayload,
        }
    }

    mod candidate {
        use parity_scale_codec::Input;

        use super::*;

        #[derive(Decode, Deserialize)]
        struct SignedQueryCandidate {
            signature: SignatureOf<QueryPayload>,
            payload: QueryPayload,
        }

        impl SignedQueryCandidate {
            fn validate(self) -> Result<SignedQuery, &'static str> {
                #[cfg(feature = "std")]
                if self.signature.verify(&self.payload).is_err() {
                    return Err("Query signature not valid");
                }

                Ok(SignedQuery {
                    payload: self.payload,
                    signature: self.signature,
                })
            }
        }

        impl Decode for SignedQuery {
            fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
                SignedQueryCandidate::decode(input)?
                    .validate()
                    .map_err(Into::into)
            }
        }

        impl<'de> Deserialize<'de> for SignedQuery {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                use serde::de::Error as _;

                SignedQueryCandidate::deserialize(deserializer)?
                    .validate()
                    .map_err(D::Error::custom)
            }
        }
    }

    #[cfg(feature = "transparent_api")]
    impl VersionedSignedQuery {
        /// Return query signature
        pub fn signature(&self) -> &SignatureOf<QueryPayload> {
            let VersionedSignedQuery::V1(query) = self;
            &query.signature
        }
        /// Return query payload
        pub fn query(&self) -> &QueryBox {
            let VersionedSignedQuery::V1(query) = self;
            &query.payload.query
        }
        /// Return query authority
        pub fn authority(&self) -> &AccountId {
            let VersionedSignedQuery::V1(query) = self;
            &query.payload.authority
        }
        /// Return query filter
        pub fn filter(&self) -> &PredicateBox {
            let VersionedSignedQuery::V1(query) = self;
            &query.payload.filter
        }
    }

    impl QueryBuilder {
        /// Construct a new request with the `query`.
        pub fn new(query: impl Into<QueryBox>, authority: AccountId) -> Self {
            Self {
                payload: QueryPayload {
                    query: query.into(),
                    authority,
                    filter: PredicateBox::default(),
                },
            }
        }

        /// Construct a new request with the `query`.
        #[inline]
        pub fn with_filter(mut self, filter: PredicateBox) -> Self {
            self.payload.filter = filter;
            self
        }

        /// Consumes self and returns a signed [`QueryBuilder`].
        ///
        /// # Errors
        /// Fails if signature creation fails.
        #[inline]
        pub fn sign(
            self,
            key_pair: iroha_crypto::KeyPair,
        ) -> Result<VersionedSignedQuery, iroha_crypto::error::Error> {
            SignatureOf::new(key_pair, &self.payload)
                .map(|signature| SignedQuery {
                    payload: self.payload,
                    signature,
                })
                .map(Into::into)
        }
    }

    pub mod prelude {
        //! The prelude re-exports most commonly used traits, structs and macros from this crate.

        pub use super::{QueryBuilder, SignedQuery, VersionedSignedQuery};
    }
}

pub mod error {
    //! Module containing errors that can occur during query execution

    use derive_more::Display;
    use iroha_crypto::HashOf;
    use iroha_data_model_derive::model;
    use iroha_macro::FromVariant;
    use iroha_schema::IntoSchema;
    use parity_scale_codec::{Decode, Encode};

    pub use self::model::*;
    use super::*;
    use crate::{block::VersionedSignedBlock, permission, prelude::*, validator};

    #[model]
    pub mod model {
        use super::*;

        /// Query errors.
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            FromVariant,
            Deserialize,
            Serialize,
            Decode,
            Encode,
            IntoSchema,
        )]
        #[cfg_attr(feature = "std", derive(thiserror::Error))]
        pub enum QueryExecutionFail {
            /// Query has the wrong signature: {0}
            Signature(
                #[skip_from]
                #[skip_try_from]
                String,
            ),
            /// Query has a malformed expression: {0}
            Evaluate(
                #[skip_from]
                #[skip_try_from]
                String,
            ),
            /// {0}
            #[cfg_attr(feature = "std", error(transparent))]
            Find(FindError),
            /// Query found wrong type of asset: {0}
            Conversion(
                #[skip_from]
                #[skip_try_from]
                String,
            ),
            /// Unauthorized query: account not provided
            Unauthorized,
        }

        /// Type assertion error
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Deserialize,
            Serialize,
            Decode,
            Encode,
            IntoSchema,
        )]
        #[cfg_attr(feature = "std", derive(thiserror::Error))]
        // TODO: Only temporary
        #[ffi_type(opaque)]
        pub enum FindError {
            /// Failed to find asset: `{0}`
            Asset(AssetId),
            /// Failed to find asset definition: `{0}`
            AssetDefinition(AssetDefinitionId),
            /// Failed to find account: `{0}`
            Account(AccountId),
            /// Failed to find domain: `{0}`
            Domain(DomainId),
            /// Failed to find metadata key: `{0}`
            MetadataKey(Name),
            /// Block with hash `{0}` not found
            Block(HashOf<VersionedSignedBlock>),
            /// Transaction with hash `{0}` not found
            Transaction(HashOf<VersionedSignedTransaction>),
            /// Peer with id `{0}` not found
            Peer(PeerId),
            /// Trigger with id `{0}` not found
            Trigger(TriggerId),
            /// Role with id `{0}` not found
            Role(RoleId),
            /// Failed to find [`PermissionToken`] by id.
            PermissionToken(PermissionTokenId),
            /// Parameter with id `{0}` not found
            Parameter(ParameterId),
            /// Failed to find public key: `{0}`
            PublicKey(PublicKey),
        }
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
#[allow(ambiguous_glob_reexports)]
pub mod prelude {
    #[cfg(feature = "http")]
    pub use super::http::*;
    pub use super::{
        account::prelude::*, asset::prelude::*, block::prelude::*, domain::prelude::*,
        peer::prelude::*, permission::prelude::*, role::prelude::*, transaction::*,
        trigger::prelude::*, QueryBox, TransactionQueryOutput,
    };
}
