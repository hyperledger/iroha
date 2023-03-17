//! Iroha Queries provides declarative API for Iroha Queries.

#![allow(clippy::missing_inline_in_public_items, unused_imports)]

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};

use derive_more::Display;
use iroha_crypto::SignatureOf;
use iroha_macro::FromVariant;
use iroha_schema::prelude::*;
use iroha_version::prelude::*;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use self::{
    account::*, asset::*, block::*, domain::*, peer::*, permissions::*, role::*, transaction::*,
    trigger::*,
};
use crate::{account::Account, model, Identifiable, Value};

macro_rules! query {
    ($($meta:meta)* $item:item) => {
        crate::model! {
            #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
            #[derive(parity_scale_codec::Decode, parity_scale_codec::Encode)]
            #[derive(serde::Deserialize, serde::Serialize)]
            #[derive(iroha_schema::IntoSchema)]
            $($meta)*
            $item
        }
    };
}

/// Trait for typesafe query output
pub trait Query {
    /// Output type of query
    type Output: Into<Value> + TryFrom<Value>;
}

model! {
    /// Sized container for all possible Queries.
    #[allow(clippy::enum_variant_names)]
    #[derive(Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, FromVariant, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[ffi_type]
    pub enum QueryBox {
        /// [`FindAllAccounts`] variant.
        FindAllAccounts(FindAllAccounts),
        /// [`FindAccountById`] variant.
        FindAccountById(FindAccountById),
        /// [`FindAccountKeyValueByIdAndKey`] variant.
        FindAccountKeyValueByIdAndKey(FindAccountKeyValueByIdAndKey),
        /// [`FindAccountsByName`] variant.
        FindAccountsByName(FindAccountsByName),
        /// [`FindAccountsByDomainId`] variant.
        FindAccountsByDomainId(FindAccountsByDomainId),
        /// [`FindAccountsWithAsset`] variant.
        FindAccountsWithAsset(FindAccountsWithAsset),
        /// [`FindAllAssets`] variant.
        FindAllAssets(FindAllAssets),
        /// [`FindAllAssetsDefinitions`] variant.
        FindAllAssetsDefinitions(FindAllAssetsDefinitions),
        /// [`FindAssetById`] variant.
        FindAssetById(FindAssetById),
        /// [`FindAssetDefinitionById`] variant.
        FindAssetDefinitionById(FindAssetDefinitionById),
        /// [`FindAssetsByName`] variant.
        FindAssetsByName(FindAssetsByName),
        /// [`FindAssetsByAccountId`] variant.
        FindAssetsByAccountId(FindAssetsByAccountId),
        /// [`FindAssetsByAssetDefinitionId`] variant.
        FindAssetsByAssetDefinitionId(FindAssetsByAssetDefinitionId),
        /// [`FindAssetsByDomainId`] variant.
        FindAssetsByDomainId(FindAssetsByDomainId),
        /// [`FindAssetsByDomainIdAndAssetDefinitionId`] variant.
        FindAssetsByDomainIdAndAssetDefinitionId(FindAssetsByDomainIdAndAssetDefinitionId),
        /// [`FindAssetQuantityById`] variant.
        FindAssetQuantityById(FindAssetQuantityById),
        /// [`FindTotalAssetQuantityByAssetDefinitionId`] variant.
        FindTotalAssetQuantityByAssetDefinitionId(FindTotalAssetQuantityByAssetDefinitionId),
        /// [`IsAssetDefinitionOwner`] variant.
        IsAssetDefinitionOwner(IsAssetDefinitionOwner),
        /// [`FindAssetKeyValueByIdAndKey`] variant.
        FindAssetKeyValueByIdAndKey(FindAssetKeyValueByIdAndKey),
        /// [`FindAssetKeyValueByIdAndKey`] variant.
        FindAssetDefinitionKeyValueByIdAndKey(FindAssetDefinitionKeyValueByIdAndKey),
        /// [`FindAllDomains`] variant.
        FindAllDomains(FindAllDomains),
        /// [`FindDomainById`] variant.
        FindDomainById(FindDomainById),
        /// [`FindDomainKeyValueByIdAndKey`] variant.
        FindDomainKeyValueByIdAndKey(FindDomainKeyValueByIdAndKey),
        /// [`FindAllPeers`] variant.
        FindAllPeers(FindAllPeers),
        /// [`FindAllBlocks`] variant.
        FindAllBlocks(FindAllBlocks),
        /// [`FindAllBlockHeaders`] variant.
        FindAllBlockHeaders(FindAllBlockHeaders),
        /// [`FindBlockHeaderByHash`] variant.
        FindBlockHeaderByHash(FindBlockHeaderByHash),
        /// [`FindAllTransactions`] variant.
        FindAllTransactions(FindAllTransactions),
        /// [`FindTransactionsByAccountId`] variant.
        FindTransactionsByAccountId(FindTransactionsByAccountId),
        /// [`FindTransactionByHash`] variant.
        FindTransactionByHash(FindTransactionByHash),
        /// [`FindPermissionTokensByAccountId`] variant.
        FindPermissionTokensByAccountId(FindPermissionTokensByAccountId),
        /// [`FindAllPermissionTokenDefinitions`] variant.
        FindAllPermissionTokenDefinitions(FindAllPermissionTokenDefinitions),
        /// [`DoesAccountHavePermissionToken`] variant.
        DoesAccountHavePermissionToken(DoesAccountHavePermissionToken),
        /// [`FindAllActiveTriggerIds`] variant.
        FindAllActiveTriggerIds(FindAllActiveTriggerIds),
        /// [`FindTriggerById`] variant.
        FindTriggerById(FindTriggerById),
        /// [`FindTriggerKeyValueByIdAndKey`] variant.
        FindTriggerKeyValueByIdAndKey(FindTriggerKeyValueByIdAndKey),
        /// [`FindTriggersByDomainId`] variant.
        FindTriggersByDomainId(FindTriggersByDomainId),
        /// [`FindAllRoles`] variant.
        FindAllRoles(FindAllRoles),
        /// [`FindAllRoleIds`] variant.
        FindAllRoleIds(FindAllRoleIds),
        /// [`FindRoleByRoleId`] variant.
        FindRoleByRoleId(FindRoleByRoleId),
        /// [`FindRolesByAccountId`] variant.
        FindRolesByAccountId(FindRolesByAccountId),
        /// [`FindAllParameters`] variant.
        FindAllParameters(FindAllParameters),
    }
}

impl Query for QueryBox {
    type Output = Value;
}

pub mod role {
    //! Queries related to [`Role`].

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;

    use crate::prelude::*;

    query! {
        /// [`FindAllRoles`] Iroha Query finds all [`Role`]s presented.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all roles")]
        #[ffi_type]
        pub struct FindAllRoles;
    }

    impl Query for FindAllRoles {
        type Output = Vec<Role>;
    }

    query! {
        /// [`FindAllRoleIds`] Iroha Query finds [`Id`](crate::role::Id)s of
        /// all [`Role`]s presented.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all role ids")]
        #[ffi_type]
        pub struct FindAllRoleIds;
    }

    impl Query for FindAllRoleIds {
        type Output = Vec<<Role as Identifiable>::Id>;
    }

    query! {
        /// [`FindRoleByRoleId`] Iroha Query finds the [`Role`] which has the given [`Id`](crate::role::Id)
        #[derive(Display)]
        #[display(fmt = "Find `{id}` role")]
        #[repr(transparent)]
        // SAFETY: `FindRoleByRoleId` has no trap representation in `EvaluatesTo<<Role as Identifiable>::Id>`
        #[ffi_type(unsafe {robust})]
        pub struct FindRoleByRoleId {
            /// `Id` of the [`Role`] to find
            pub id: EvaluatesTo<<Role as Identifiable>::Id>,
        }
    }

    impl Query for FindRoleByRoleId {
        type Output = Role;
    }

    query! {
        /// [`FindRolesByAccountId`] Iroha Query finds all [`Role`]s for a specified account.
        #[derive(Display)]
        #[display(fmt = "Find all roles for `{id}` account")]
        #[repr(transparent)]
        // SAFETY: `FindRolesByAccountId` has no trap representation in `EvaluatesTo<<Account as Identifiable>::Id>`
        #[ffi_type(unsafe {robust})]
        pub struct FindRolesByAccountId {
            /// `Id` of an account to find.
            pub id: EvaluatesTo<<Account as Identifiable>::Id>,
        }
    }

    impl Query for FindRolesByAccountId {
        type Output = Vec<<Role as Identifiable>::Id>;
    }

    impl FindRoleByRoleId {
        /// Construct [`FindRoleByRoleId`].
        pub fn new(id: impl Into<EvaluatesTo<<Role as Identifiable>::Id>>) -> Self {
            Self { id: id.into() }
        }
    }

    impl FindRolesByAccountId {
        /// Construct [`FindRolesByAccountId`].
        pub fn new(account_id: impl Into<EvaluatesTo<<Account as Identifiable>::Id>>) -> Self {
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

pub mod permissions {
    //! Queries related to [`PermissionToken`].

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;

    use crate::{permission, prelude::*};

    query! {
        /// [`FindAllPermissionTokenDefinitions`] Iroha Query finds all registered
        /// [`PermissionTokenDefinition`][crate::permission::token::Definition]s
        #[derive(Copy, Display)]
        #[ffi_type]
        pub struct FindAllPermissionTokenDefinitions;
    }

    impl Query for FindAllPermissionTokenDefinitions {
        type Output = Vec<PermissionTokenDefinition>;
    }

    query! {
        /// [`FindPermissionTokensByAccountId`] Iroha Query finds all [`PermissionToken`]s
        /// for a specified account.
        #[derive(Display)]
        #[display(fmt = "Find permission tokens specified for `{id}` account")]
        #[repr(transparent)]
        // SAFETY: `FindPermissionTokensByAccountId` has no trap representation in `EvaluatesTo<<Account as Identifiable>::Id>`
        #[ffi_type(unsafe {robust})]
        pub struct FindPermissionTokensByAccountId {
            /// `Id` of an account to find.
            pub id: EvaluatesTo<<Account as Identifiable>::Id>,
        }
    }

    impl Query for FindPermissionTokensByAccountId {
        type Output = Vec<permission::Token>;
    }

    query! {
        /// [`DoesAccountHavePermission`] Iroha Query checks if the account has the specified permission.
        #[derive(Display)]
        #[display(fmt = "Check if `{account_id}` account has `{permission_token}` permission token")]
        #[ffi_type]
        pub struct DoesAccountHavePermissionToken {
            /// `Id` of an account to check.
            pub account_id: EvaluatesTo<<Account as Identifiable>::Id>,
            /// `PermissionToken` to check for.
            pub permission_token: permission::Token,
        }
    }

    impl Query for DoesAccountHavePermissionToken {
        type Output = bool;
    }

    impl DoesAccountHavePermissionToken {
        /// Construct [`DoesAccountHavePermissionToken`].
        pub fn new(
            account_id: impl Into<EvaluatesTo<<Account as Identifiable>::Id>>,
            permission_token: permission::Token,
        ) -> Self {
            Self {
                account_id: account_id.into(),
                permission_token,
            }
        }
    }

    impl FindPermissionTokensByAccountId {
        /// Construct [`DoesAccountHavePermissionToken`].
        pub fn new(account_id: impl Into<EvaluatesTo<<Account as Identifiable>::Id>>) -> Self {
            Self {
                id: account_id.into(),
            }
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this module.
    pub mod prelude {
        pub use super::{
            DoesAccountHavePermissionToken, FindAllPermissionTokenDefinitions,
            FindPermissionTokensByAccountId,
        };
    }
}

pub mod account {
    //! Queries related to [`Account`].

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;

    use crate::prelude::*;

    query! {
        // TODO: Better to have find all account ids query instead.
        /// [`FindAllAccounts`] Iroha Query finds all [`Account`]s presented.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all accounts")]
        #[ffi_type]
        pub struct FindAllAccounts;
    }

    impl Query for FindAllAccounts {
        type Output = Vec<Account>;
    }

    query! {
        /// [`FindAccountById`] Iroha Query finds an [`Account`] by it's identification.
        #[derive(Display)]
        #[display(fmt = "Find `{id}` account")]
        #[repr(transparent)]
        // SAFETY: `FindAccountById` has no trap representation in `EvaluatesTo<<Account as Identifiable>::Id>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAccountById {
            /// `Id` of an account to find.
            pub id: EvaluatesTo<<Account as Identifiable>::Id>,
        }
    }

    impl Query for FindAccountById {
        type Output = Account;
    }

    query! {
        /// [`FindAccountKeyValueByIdAndKey`] Iroha Query finds a [`Value`]
        /// of the key-value metadata pair in the specified account.
        #[derive(Display)]
        #[display(fmt = "Find metadata value with `{key}` key in `{id}` account")]
        #[ffi_type]
        pub struct FindAccountKeyValueByIdAndKey {
            /// `Id` of an account to find.
            pub id: EvaluatesTo<<Account as Identifiable>::Id>,
            /// Key of the specific key-value in the Account's metadata.
            pub key: EvaluatesTo<Name>,
        }
    }

    impl Query for FindAccountKeyValueByIdAndKey {
        type Output = Value;
    }

    query! {
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
    }

    impl Query for FindAccountsByName {
        type Output = Vec<Account>;
    }

    query! {
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
    }

    impl Query for FindAccountsByDomainId {
        type Output = Vec<Account>;
    }

    query! {
        /// [`FindAccountsWithAsset`] Iroha Query gets [`AssetDefinition`]s id as input and
        /// finds all [`Account`]s storing [`Asset`] with such definition.
        #[derive(Display)]
        #[display(fmt = "Find accounts with `{asset_definition_id}` asset")]
        #[repr(transparent)]
        // SAFETY: `FindAccountsWithAsset` has no trap representation in `EvaluatesTo<<AssetDefinition as Identifiable>::Id>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAccountsWithAsset {
            /// `Id` of the definition of the asset which should be stored in founded accounts.
            pub asset_definition_id: EvaluatesTo<<AssetDefinition as Identifiable>::Id>,
        }
    }

    impl Query for FindAccountsWithAsset {
        type Output = Vec<Account>;
    }

    impl FindAccountById {
        /// Construct [`FindAccountById`].
        pub fn new(id: impl Into<EvaluatesTo<<Account as Identifiable>::Id>>) -> Self {
            Self { id: id.into() }
        }
    }

    impl FindAccountKeyValueByIdAndKey {
        /// Construct [`FindAccountById`].
        pub fn new(
            id: impl Into<EvaluatesTo<<Account as Identifiable>::Id>>,
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

    use crate::prelude::*;

    query! {
        /// [`FindAllAssets`] Iroha Query finds all [`Asset`]s presented in Iroha Peer.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all assets")]
        #[ffi_type]
        pub struct FindAllAssets;
    }

    impl Query for FindAllAssets {
        type Output = Vec<Asset>;
    }

    query! {
        /// [`FindAllAssetsDefinitions`] Iroha Query finds all [`AssetDefinition`]s presented
        /// in Iroha Peer.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all asset definitions")]
        #[ffi_type]
        pub struct FindAllAssetsDefinitions; // TODO: Should it be renamed to [`FindAllAssetDefinitions`?
    }

    impl Query for FindAllAssetsDefinitions {
        type Output = Vec<AssetDefinition>;
    }

    query! {
        /// [`FindAssetById`] Iroha Query finds an [`Asset`] by it's identification in Iroha [`Peer`].
        #[derive(Display)]
        #[display(fmt = "Find `{id}` asset")]
        #[repr(transparent)]
        // SAFETY: `FindAssetById` has no trap representation in `EvaluatesTo<<Asset as Identifiable>::Id>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAssetById {
            /// `Id` of an [`Asset`] to find.
            pub id: EvaluatesTo<<Asset as Identifiable>::Id>,
        }
    }

    impl Query for FindAssetById {
        type Output = Asset;
    }

    query! {
        /// [`FindAssetDefinitionById`] Iroha Query finds an [`AssetDefinition`] by it's identification in Iroha [`Peer`].
        #[derive(Display)]
        #[display(fmt = "Find `{id}` asset definition")]
        #[repr(transparent)]
        // SAFETY: `FindAssetDefinitionById` has no trap representation in `EvaluatesTo<<AssetDefinition as Identifiable>::Id>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAssetDefinitionById {
            /// `Id` of an [`AssetDefinition`] to find.
            pub id: EvaluatesTo<<AssetDefinition as Identifiable>::Id>,
        }
    }

    impl Query for FindAssetDefinitionById {
        type Output = AssetDefinition;
    }

    query! {
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
    }

    impl Query for FindAssetsByName {
        type Output = Vec<Asset>;
    }

    query! {
        /// [`FindAssetsByAccountId`] Iroha Query gets [`AccountId`] as input and find all [`Asset`]s
        /// owned by the [`Account`] in Iroha Peer.
        #[derive(Display)]
        #[display(fmt = "Find assets owned by the `{account_id}` account")]
        #[repr(transparent)]
        // SAFETY: `FindAssetsByAccountId` has no trap representation in `EvaluatesTo<<Account as Identifiable>::Id>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAssetsByAccountId {
            /// [`AccountId`] under which assets should be found.
            pub account_id: EvaluatesTo<<Account as Identifiable>::Id>,
        }
    }

    impl Query for FindAssetsByAccountId {
        type Output = Vec<Asset>;
    }

    query! {
        /// [`FindAssetsByAssetDefinitionId`] Iroha Query gets [`AssetDefinitionId`] as input and
        /// finds all [`Asset`]s with this [`AssetDefinition`] in Iroha Peer.
        #[derive(Display)]
        #[display(fmt = "Find assets with `{asset_definition_id}` asset definition")]
        #[repr(transparent)]
        // SAFETY: `FindAssetsByAssetDefinitionId` has no trap representation in `EvaluatesTo<<AssetDefinition as Identifiable>::Id>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAssetsByAssetDefinitionId {
            /// [`AssetDefinitionId`] with type of [`Asset`]s should be found.
            pub asset_definition_id: EvaluatesTo<<AssetDefinition as Identifiable>::Id>,
        }
    }

    impl Query for FindAssetsByAssetDefinitionId {
        type Output = Vec<Asset>;
    }

    query! {
        /// [`FindAssetsByDomainId`] Iroha Query gets [`Domain`]s id as input and
        /// finds all [`Asset`]s under this [`Domain`] in Iroha [`Peer`].
        #[derive(Display)]
        #[display(fmt = "Find assets under the `{domain_id}` domain")]
        #[repr(transparent)]
        // SAFETY: `FindAssetsByDomainId` has no trap representation in `EvaluatesTo<<Domain as Identifiable>::Id>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAssetsByDomainId {
            /// `Id` of the domain under which assets should be found.
            pub domain_id: EvaluatesTo<<Domain as Identifiable>::Id>,
        }
    }

    impl Query for FindAssetsByDomainId {
        type Output = Vec<Asset>;
    }

    query! {
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
    }

    impl Query for FindAssetsByDomainIdAndAssetDefinitionId {
        type Output = Vec<Asset>;
    }

    query! {
        /// [`FindAssetQuantityById`] Iroha Query gets [`AssetId`] as input and finds [`Asset::quantity`]
        /// parameter's value if [`Asset`] is presented in Iroha Peer.
        #[derive(Display)]
        #[display(fmt = "Find quantity of the `{id}` asset")]
        #[repr(transparent)]
        // SAFETY: `FindAssetQuantityById` has no trap representation in `EvaluatesTo<<Asset as Identifiable>::Id>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAssetQuantityById {
            /// `Id` of an [`Asset`] to find quantity of.
            pub id: EvaluatesTo<<Asset as Identifiable>::Id>,
        }
    }

    impl Query for FindAssetQuantityById {
        type Output = NumericValue;
    }

    query! {
        /// [`FindTotalAssetQuantityByAssetDefinitionId`] Iroha Query gets [`AssetDefinitionId`] as input and finds total [`Asset::quantity`]
        /// if [`AssetDefinitionId`] is presented in Iroha Peer.
        /// In case of `Store` asset value type total quantity is sum of assets through all accounts with provided [`AssetDefinitionId`].
        #[derive(Display)]
        #[display(fmt = "Find total quantity of the `{id}` asset")]
        #[repr(transparent)]
        // SAFETY: `FindTotalAssetQuantityByAssetDefinitionId` has no trap representation in `EvaluatesTo<<AssetDefinition as Identifiable>::Id>`
        #[ffi_type(unsafe {robust})]
        pub struct FindTotalAssetQuantityByAssetDefinitionId {
            /// `Id` of an [`Asset`] to find quantity of.
            pub id: EvaluatesTo<<AssetDefinition as Identifiable>::Id>,
        }
    }

    impl Query for FindTotalAssetQuantityByAssetDefinitionId {
        type Output = NumericValue;
    }

    query! {
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
    }

    impl Query for FindAssetKeyValueByIdAndKey {
        type Output = Value;
    }

    query! {
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
    }

    impl Query for FindAssetDefinitionKeyValueByIdAndKey {
        type Output = Value;
    }

    query! {
        /// [`IsAssetDefinitionOwner`] Iroha Query checks if provided account is the asset definition owner.
        #[derive(Display)]
        #[display(fmt = "Check if `{account_id}` is creator of `{asset_definition_id}` asset")]
        #[ffi_type]
        pub struct IsAssetDefinitionOwner {
            /// `Id` of an [`AssetDefinition`] to check.
            pub asset_definition_id: EvaluatesTo<AssetDefinitionId>,
            /// `Id` of a possible owner [`Account`].
            pub account_id: EvaluatesTo<<Account as Identifiable>::Id>,
        }
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
        pub fn new(account_id: impl Into<EvaluatesTo<<Account as Identifiable>::Id>>) -> Self {
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
            account_id: impl Into<EvaluatesTo<<Account as Identifiable>::Id>>,
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

    use crate::prelude::*;

    query! {
        /// [`FindAllDomains`] Iroha Query finds all [`Domain`]s presented in Iroha [`Peer`].
        #[derive(Copy, Display)]
        #[display(fmt = "Find all domains")]
        #[ffi_type]
        pub struct FindAllDomains;
    }

    impl Query for FindAllDomains {
        type Output = Vec<Domain>;
    }

    query! {
        /// [`FindDomainById`] Iroha Query finds a [`Domain`] by it's identification in Iroha [`Peer`].
        #[derive(Display)]
        #[display(fmt = "Find `{id}` domain")]
        #[repr(transparent)]
        // SAFETY: `FindTotalAssetQuantityByAssetDefinitionId` has no trap representation in `EvaluatesTo<<Domain as Identifiable>::Id>`
        #[ffi_type(unsafe {robust})]
        pub struct FindDomainById {
            /// `Id` of the domain to find.
            pub id: EvaluatesTo<<Domain as Identifiable>::Id>,
        }
    }

    impl Query for FindDomainById {
        type Output = Domain;
    }

    query! {
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

    impl Query for FindDomainKeyValueByIdAndKey {
        type Output = Value;
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

    query! {
        /// [`FindAllPeers`] Iroha Query finds all trusted [`Peer`]s presented in current Iroha [`Peer`].
        #[derive(Copy, Display)]
        #[display(fmt = "Find all peers")]
        #[ffi_type]
        pub struct FindAllPeers;
    }

    impl Query for FindAllPeers {
        type Output = Vec<Peer>;
    }

    query! {
        /// [`FindAllParameters`] Iroha Query finds all [`Peer`]s parameters.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all peers parameters")]
        // TODO: Unused query. Remove?
        #[ffi_type]
        pub struct FindAllParameters;
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

    use super::Query;
    use crate::{
        domain::prelude::*, events::FilterBox, expression::EvaluatesTo, trigger::Trigger,
        Identifiable, Name, Value,
    };

    query! {
        /// Find all currently active (as in not disabled and/or expired)
        /// trigger IDs.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all trigger ids")]
        #[ffi_type]
        pub struct FindAllActiveTriggerIds;
    }

    impl Query for FindAllActiveTriggerIds {
        type Output = Vec<<Trigger<FilterBox> as Identifiable>::Id>;
    }

    query! {
        /// Find Trigger given its ID.
        #[derive(Display)]
        #[display(fmt = "Find `{id}` trigger")]
        #[repr(transparent)]
        // SAFETY: `FindTriggerById` has no trap representation in `EvaluatesTo<<Trigger<FilterBox> as Identifiable>::Id>`
        #[ffi_type(unsafe {robust})]
        pub struct FindTriggerById {
            /// The Identification of the trigger to be found.
            pub id: EvaluatesTo<<Trigger<FilterBox> as Identifiable>::Id>,
        }
    }

    impl Query for FindTriggerById {
        type Output = Trigger<FilterBox>;
    }

    query! {
        /// Find Trigger's metadata key-value pairs.
        #[derive(Display)]
        #[display(fmt = "Find metadata value with `{key}` key in `{id}` trigger")]
        #[ffi_type]
        pub struct FindTriggerKeyValueByIdAndKey {
            /// The Identification of the trigger to be found.
            pub id: EvaluatesTo<<Trigger<FilterBox> as Identifiable>::Id>,
            /// The key inside the metadata dictionary to be returned.
            pub key: EvaluatesTo<Name>,
        }
    }

    impl Query for FindTriggerKeyValueByIdAndKey {
        type Output = Value;
    }

    query! {
        /// Find [`Trigger`]s under the given [`DomainId`].
        #[derive(Display)]
        #[display(fmt = "Find trigger under `{domain_id}` domain")]
        #[repr(transparent)]
        // SAFETY: `FindTriggersByDomainId` has no trap representation in `EvaluatesTo<<Domain as Identifiable>::Id>`
        #[ffi_type(unsafe {robust})]
        pub struct FindTriggersByDomainId {
            /// [`DomainId`] specifies the domain in which to search for triggers.
            pub domain_id: EvaluatesTo<<Domain as Identifiable>::Id>,
        }
    }

    impl Query for FindTriggersByDomainId {
        type Output = Vec<Trigger<FilterBox>>;
    }

    impl FindTriggerById {
        /// Construct [`FindTriggerById`].
        pub fn new(id: impl Into<EvaluatesTo<<Trigger<FilterBox> as Identifiable>::Id>>) -> Self {
            Self { id: id.into() }
        }
    }

    impl FindTriggerKeyValueByIdAndKey {
        /// Construct [`FindTriggerKeyValueByIdAndKey`].
        pub fn new(
            id: impl Into<EvaluatesTo<<Trigger<FilterBox> as Identifiable>::Id>>,
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
    use iroha_crypto::Hash;

    use super::Query;
    use crate::{
        expression::EvaluatesTo,
        prelude::Account,
        transaction::{TransactionQueryResult, TransactionValue},
        Identifiable,
    };

    query! {
        /// [`FindAllTransactions`] Iroha Query lists all transactions included in a blockchain
        #[derive(Copy, Display)]
        #[display(fmt = "Find all transactions")]
        #[ffi_type]
        pub struct FindAllTransactions;
    }

    impl Query for FindAllTransactions {
        type Output = Vec<TransactionQueryResult>;
    }

    query! {
        /// [`FindTransactionsByAccountId`] Iroha Query finds all transactions included in a blockchain
        /// for the account
        #[derive(Display)]
        #[display(fmt = "Find all transactions for `{account_id}` account")]
        #[repr(transparent)]
        // SAFETY: `FindTransactionsByAccountId` has no trap representation in `EvaluatesTo<<Account as Identifiable>::Id>`
        #[ffi_type(unsafe {robust})]
        pub struct FindTransactionsByAccountId {
            /// Signer's [`AccountId`] under which transactions should be found.
            pub account_id: EvaluatesTo<<Account as Identifiable>::Id>,
        }
    }

    impl Query for FindTransactionsByAccountId {
        type Output = Vec<TransactionValue>;
    }

    query! {
        /// [`FindTransactionByHash`] Iroha Query finds a transaction (if any)
        /// with corresponding hash value
        #[derive(Display)]
        #[display(fmt = "Find transaction with `{hash}` hash")]
        #[repr(transparent)]
        // SAFETY: `FindTransactionByHash` has no trap representation in `EvaluatesTo<Hash>`
        #[ffi_type(unsafe {robust})]
        pub struct FindTransactionByHash {
            /// Transaction hash.
            pub hash: EvaluatesTo<Hash>,
        }
    }

    impl Query for FindTransactionByHash {
        type Output = TransactionValue;
    }

    impl FindTransactionsByAccountId {
        ///Construct [`FindTransactionsByAccountId`].
        pub fn new(account_id: impl Into<EvaluatesTo<<Account as Identifiable>::Id>>) -> Self {
            Self {
                account_id: account_id.into(),
            }
        }
    }

    impl FindTransactionByHash {
        ///Construct [`FindTransactionByHash`].
        pub fn new(hash: impl Into<EvaluatesTo<Hash>>) -> Self {
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
    use iroha_crypto::Hash;

    use super::Query;
    use crate::{
        block::{BlockHeader, VersionedCommittedBlock},
        prelude::EvaluatesTo,
    };

    query! {
        /// [`FindAllBlocks`] Iroha Query lists all blocks sorted by
        /// height in descending order
        #[derive(Copy, Display)]
        #[display(fmt = "Find all blocks")]
        #[ffi_type]
        pub struct FindAllBlocks;
    }

    impl Query for FindAllBlocks {
        type Output = Vec<VersionedCommittedBlock>;
    }

    query! {
        /// [`FindAllBlockHeaders`] Iroha Query lists all block headers
        /// sorted by height in descending order
        #[derive(Copy, Display)]
        #[display(fmt = "Find all block headers")]
        #[ffi_type]
        pub struct FindAllBlockHeaders;
    }

    impl Query for FindAllBlockHeaders {
        type Output = Vec<BlockHeader>;
    }

    query! {
        /// [`FindBlockHeaderByHash`] Iroha Query finds block header by block hash
        #[derive(Display)]
        #[display(fmt = "Find block header with `{hash}` hash")]
        #[repr(transparent)]
        // SAFETY: `FindBlockHeaderByHash` has no trap representation in `EvaluatesTo<Hash>`
        #[ffi_type(unsafe {robust})]
        pub struct FindBlockHeaderByHash {
            /// Block hash.
            pub hash: EvaluatesTo<Hash>,
        }
    }

    impl Query for FindBlockHeaderByHash {
        type Output = BlockHeader;
    }

    impl FindBlockHeaderByHash {
        /// Construct [`FindBlockHeaderByHash`].
        pub fn new(hash: impl Into<EvaluatesTo<Hash>>) -> Self {
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

    use super::*;
    use crate::{pagination::prelude::*, predicate::PredicateBox, sorting::prelude::*};

    model! {
        /// Payload of a query.
        #[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize, IntoSchema)]
        pub(crate) struct Payload {
            /// Timestamp of the query creation.
            #[codec(compact)]
            pub timestamp_ms: u128,
            /// Query definition.
            pub query: QueryBox,
            /// Account id of the user who will sign this query.
            pub account_id: <Account as Identifiable>::Id,
            /// The filter applied to the result on the server-side.
            pub filter: PredicateBox,
        }
    }

    model! {
        /// I/O ready structure to send queries.
        #[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize)]
        #[serde(transparent)]
        #[repr(transparent)]
        pub struct QueryRequest {
            /// Payload
            pub payload: Payload,
        }
    }

    declare_versioned_with_scale!(VersionedSignedQueryRequest 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema);

    model! {
        /// I/O ready structure to send queries.
        #[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize, IntoSchema)]
        #[version_with_scale(n = 1, versioned = "VersionedSignedQueryRequest")]
        pub struct SignedQueryRequest {
            /// Payload
            pub payload: Payload,
            /// Signature of the client who sends this query.
            pub signature: SignatureOf<Payload>,
        }
    }

    declare_versioned_with_scale!(VersionedQueryResult 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema);

    model! {
        /// Sized container for all possible Query results.
        #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
        #[version_with_scale(n = 1, versioned = "VersionedQueryResult")]
        #[serde(transparent)]
        #[repr(transparent)]
        pub struct QueryResult(pub Value);
    }

    impl From<QueryResult> for Value {
        fn from(source: QueryResult) -> Self {
            source.0
        }
    }

    declare_versioned_with_scale!(VersionedPaginatedQueryResult 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema);

    /// Paginated Query Result
    // TODO: This is the only structure whose inner fields are exposed. Wrap it in model macro?
    #[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[version_with_scale(n = 1, versioned = "VersionedPaginatedQueryResult")]
    pub struct PaginatedQueryResult {
        /// The result of the query execution.
        pub result: QueryResult,
        /// The filter that was applied to the Query result. Returned as a sanity check, but also to ease debugging on the front-end.
        pub filter: PredicateBox,
        /// pagination
        pub pagination: Pagination,
        /// sorting
        pub sorting: Sorting,
        /// Total query amount (if applicable) else 0.
        pub total: u64,
    }

    impl QueryRequest {
        /// Constructs a new request with the `query`.
        pub fn new(
            query: QueryBox,
            account_id: <Account as Identifiable>::Id,
            filter: PredicateBox,
        ) -> Self {
            let timestamp_ms = crate::current_time().as_millis();

            Self {
                payload: Payload {
                    timestamp_ms,
                    query,
                    account_id,
                    filter,
                },
            }
        }

        /// Consumes self and returns a signed [`QueryRequest`].
        ///
        /// # Errors
        /// Fails if signature creation fails.
        pub fn sign(
            self,
            key_pair: iroha_crypto::KeyPair,
        ) -> Result<SignedQueryRequest, iroha_crypto::Error> {
            SignatureOf::new(key_pair, &self.payload).map(|signature| SignedQueryRequest {
                payload: self.payload,
                signature,
            })
        }
    }

    pub mod prelude {
        //! The prelude re-exports most commonly used traits, structs and macros from this crate.

        pub use super::{
            PaginatedQueryResult, QueryRequest, QueryResult, SignedQueryRequest,
            VersionedPaginatedQueryResult, VersionedQueryResult, VersionedSignedQueryRequest,
        };
    }
}

pub mod error {
    //! Module containing errors that can occur during query execution

    use derive_more::Display;
    use iroha_crypto::HashOf;
    use iroha_macro::FromVariant;
    use iroha_schema::IntoSchema;
    use parity_scale_codec::{Decode, Encode};

    use super::*;
    use crate::{block::VersionedCommittedBlock, permission, prelude::*};

    model! {
        /// Query errors.
        #[derive(Debug, Display, FromVariant, Decode, Encode, IntoSchema)]
        #[cfg_attr(feature = "std", derive(thiserror::Error))]
        // TODO: Only temporarily opaque because of iroha_version::error::Error
        #[ffi_type(opaque)]
        pub enum QueryExecutionFailure {
            /// Query cannot be decoded.
            #[display(fmt = "Query cannot be decoded")]
            Decode(#[cfg_attr(feature = "std", source)] Box<iroha_version::error::Error>),
            /// Query has wrong signature.
            #[display(fmt = "Query has the wrong signature: {_0}")]
            Signature(#[skip_from] #[skip_try_from] String),
            /// Query is not allowed.
            #[display(fmt = "Query is not allowed: {_0}")]
            Permission(permission::validator::DenialReason),
            /// Query has wrong expression.
            #[display(fmt = "Query has a malformed expression: {_0}")]
            Evaluate(#[skip_from] #[skip_try_from] String),
            /// Query found nothing.
            #[display(fmt = "Query found nothing: {_0}")]
            Find(#[cfg_attr(feature = "std", source)] Box<FindError>),
            /// Query found wrong type of asset.
            #[display(fmt = "Query found wrong type of asset: {_0}")]
            Conversion(#[skip_from] #[skip_try_from] String),
            /// Query without account.
            #[display(fmt = "Unauthorized query: account not provided")]
            Unauthorized,
        }

        /// Type assertion error
        #[derive(Debug, Display, Decode, Encode, IntoSchema)]
        // TODO: Only temporary
        #[ffi_type(opaque)]
        pub enum FindError {
            /// Failed to find asset
            #[display(fmt = "Failed to find asset: `{_0}`")]
            Asset(AssetId),
            /// Failed to find asset definition
            #[display(fmt = "Failed to find asset definition: `{_0}`")]
            AssetDefinition(AssetDefinitionId),
            /// Failed to find account
            #[display(fmt = "Failed to find account: `{_0}`")]
            Account(<Account as Identifiable>::Id),
            /// Failed to find domain
            #[display(fmt = "Failed to find domain: `{_0}`")]
            Domain(DomainId),
            /// Failed to find metadata key
            #[display(fmt = "Failed to find metadata key")]
            MetadataKey(Name),
            /// Block with supplied parent hash not found. More description in a string.
            #[display(fmt = "Block with hash {_0} not found")]
            Block(HashOf<VersionedCommittedBlock>),
            /// Transaction with given hash not found.
            #[display(fmt = "Transaction not found")]
            Transaction(HashOf<VersionedSignedTransaction>),
            /// Value not found in context.
            #[display(fmt = "Value named {_0} not found in context")]
            Context(String),
            /// Peer not found.
            #[display(fmt = "Peer {_0} not found")]
            Peer(PeerId),
            /// Trigger not found.
            #[display(fmt = "Trigger not found.")]
            Trigger(TriggerId),
            /// Failed to find Role by id.
            #[display(fmt = "Failed to find role by id: `{_0}`")]
            Role(RoleId),
            /// Failed to find [`PermissionToken`] by id.
            #[display(fmt = "Failed to find permission definition token by id: `{_0}`")]
            PermissionTokenDefinition(PermissionTokenId),
            /// Failed to find [`Validator`](permission::Validator) by id.
            #[display(fmt = "Failed to find permission validator by id: `{_0}`")]
            Validator(permission::validator::Id),
            /// Failed to find specified [`Parameter`] variant.
            #[display(fmt = "Failed to find specified parameter variant: `{_0}`")]
            Parameter(Parameter),
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for FindError {}
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    #[cfg(feature = "http")]
    pub use super::http::*;
    pub use super::{
        account::prelude::*, asset::prelude::*, block::prelude::*, domain::prelude::*,
        peer::prelude::*, permissions::prelude::*, role::prelude::*, transaction::*,
        trigger::prelude::*, Query, QueryBox,
    };
}
