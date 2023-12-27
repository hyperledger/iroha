//! Iroha Queries provides declarative API for Iroha Queries.

#![allow(clippy::missing_inline_in_public_items, unused_imports)]

#[cfg(not(feature = "std"))]
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString as _},
    vec,
    vec::Vec,
};
use core::{cmp::Ordering, num::NonZeroU32};

pub use cursor::ForwardCursor;
use derive_more::{Constructor, Display};
use iroha_crypto::{PublicKey, SignatureOf};
use iroha_data_model_derive::model;
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use iroha_version::prelude::*;
pub use pagination::Pagination;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
pub use sorting::Sorting;

pub use self::model::*;
use self::{
    account::*, asset::*, block::*, domain::*, peer::*, permission::*, role::*, transaction::*,
    trigger::*,
};
use crate::{
    account::Account,
    block::SignedBlock,
    seal,
    transaction::{SignedTransaction, TransactionPayload, TransactionValue},
    Identifiable, Value,
};

pub mod cursor;
pub mod pagination;
pub mod sorting;

const FETCH_SIZE: &str = "fetch_size";

/// Default value for `fetch_size` parameter in queries.
// SAFETY: `10` is greater than `0`
#[allow(unsafe_code)]
pub const DEFAULT_FETCH_SIZE: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(10) };

/// Max value for `fetch_size` parameter in queries.
// SAFETY: `10_000` is greater than `0`
#[allow(unsafe_code)]
pub const MAX_FETCH_SIZE: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(10_000) };

/// Structure for query fetch size parameter encoding/decoding
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Constructor, Decode, Encode, Deserialize, Serialize,
)]
pub struct FetchSize {
    /// Inner value of a fetch size.
    ///
    /// If not specified then [`DEFAULT_FETCH_SIZE`] is used.
    pub fetch_size: Option<NonZeroU32>,
}

impl FetchSize {
    /// Converts self to iterator of tuples to be used in queries.
    ///
    /// The length of the output iterator is not constant and has either 0 or 1 value.
    pub fn into_query_parameters(
        self,
    ) -> impl IntoIterator<Item = (&'static str, NonZeroU32)> + Clone {
        self.fetch_size
            .map(|fetch_size| (FETCH_SIZE, fetch_size))
            .into_iter()
    }
}

macro_rules! queries {
    ($($($meta:meta)* $item:item)+) => {
        pub use self::model::*;

        #[iroha_data_model_derive::model]
        pub mod model{
            use super::*; $(

            #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
            #[derive(parity_scale_codec::Decode, parity_scale_codec::Encode)]
            #[derive(serde::Deserialize, serde::Serialize)]
            #[derive(derive_more::Constructor)]
            #[derive(iroha_schema::IntoSchema)]
            $($meta)*
            $item )+
        }
    };
}

/// Unique id of a query.
pub type QueryId = String;

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
    use crate::{block::SignedBlock, permission::PermissionTokenId};

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
        /// The hash of the block to which `tx` belongs to
        pub block_hash: HashOf<SignedBlock>,
        /// Transaction
        pub transaction: Box<TransactionValue>,
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

    /// Request type clients (like http clients or wasm) can send to a query endpoint.
    #[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
    pub enum QueryRequest<Q> {
        /// Query it-self.
        /// Basically used for one-time queries or to get a cursor for big queries.
        Query(QueryWithParameters<Q>),
        /// Cursor over previously sent [`Query`](QueryRequest::Query).
        Cursor(ForwardCursor),
    }

    /// Query with parameters client can specify.
    #[derive(
        Clone, Debug, PartialEq, Eq, Constructor, Getters, Encode, Decode, Serialize, Deserialize,
    )]
    #[getset(get = "pub")]
    pub struct QueryWithParameters<Q> {
        /// The actual query.
        pub query: Q,
        /// Sorting of the query results.
        pub sorting: Sorting,
        /// Pagination of the query results.
        pub pagination: Pagination,
        /// Amount of results to fetch.
        pub fetch_size: FetchSize,
    }
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

impl<Q: core::fmt::Display> core::fmt::Display for QueryRequest<Q> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Query(query) => write!(f, "{query}"),
            Self::Cursor(cursor) => write!(f, "{cursor:?}"),
        }
    }
}

impl<Q: core::fmt::Display> core::fmt::Display for QueryWithParameters<Q> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QueryWithParameters")
            .field("query", &self.query.to_string())
            .field("sorting", &self.sorting)
            .field("pagination", &self.pagination)
            .finish()
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
            pub id: RoleId,
        }

        /// [`FindRolesByAccountId`] Iroha Query finds all [`Role`]s for a specified account.
        #[derive(Display)]
        #[display(fmt = "Find all roles for `{id}` account")]
        #[repr(transparent)]
        // SAFETY: `FindRolesByAccountId` has no trap representation in `EvaluatesTo<AccountId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindRolesByAccountId {
            /// `Id` of an account to find.
            pub id: AccountId,
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
            pub id: AccountId,
        }
    }

    impl Query for FindPermissionTokenSchema {
        type Output = PermissionTokenSchema;
    }

    impl Query for FindPermissionTokensByAccountId {
        type Output = Vec<permission::PermissionToken>;
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
            pub id: AccountId,
        }

        /// [`FindAccountKeyValueByIdAndKey`] Iroha Query finds a [`Value`]
        /// of the key-value metadata pair in the specified account.
        #[derive(Display)]
        #[display(fmt = "Find metadata value with `{key}` key in `{id}` account")]
        #[ffi_type]
        pub struct FindAccountKeyValueByIdAndKey {
            /// `Id` of an account to find.
            pub id: AccountId,
            /// Key of the specific key-value in the Account's metadata.
            pub key: Name,
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
            pub name: Name,
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
            pub domain_id: DomainId,
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
            pub asset_definition_id: AssetDefinitionId,
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
            pub id: AssetId,
        }

        /// [`FindAssetDefinitionById`] Iroha Query finds an [`AssetDefinition`] by it's identification in Iroha [`Peer`].
        #[derive(Display)]
        #[display(fmt = "Find `{id}` asset definition")]
        #[repr(transparent)]
        // SAFETY: `FindAssetDefinitionById` has no trap representation in `EvaluatesTo<AssetDefinitionId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindAssetDefinitionById {
            /// `Id` of an [`AssetDefinition`] to find.
            pub id: AssetDefinitionId,
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
            pub name: Name,
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
            pub account_id: AccountId,
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
            pub asset_definition_id: AssetDefinitionId,
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
            pub domain_id: DomainId,
        }

        /// [`FindAssetsByDomainIdAndAssetDefinitionId`] Iroha Query gets [`DomainId`] and
        /// [`AssetDefinitionId`] as inputs and finds [`Asset`]s under the [`Domain`]
        /// with this [`AssetDefinition`] in Iroha [`Peer`].
        #[derive(Display)]
        #[display(fmt = "Find assets under the `{domain_id}` domain with `{asset_definition_id}` asset definition")]
        #[ffi_type]
        pub struct FindAssetsByDomainIdAndAssetDefinitionId {
            /// `Id` of the domain under which assets should be found.
            pub domain_id: DomainId,
            /// [`AssetDefinitionId`] assets of which type should be found.
            pub asset_definition_id: AssetDefinitionId,
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
            pub id: AssetId,
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
            pub id: AssetDefinitionId,
        }

        /// [`FindAssetKeyValueByIdAndKey`] Iroha Query gets [`AssetId`] and key as input and finds [`Value`]
        /// of the key-value pair stored in this asset.
        #[derive(Display)]
        #[display(fmt = "Find metadata value with `{key}` key in `{id}` asset")]
        #[ffi_type]
        pub struct FindAssetKeyValueByIdAndKey {
            /// `Id` of an [`Asset`] acting as [`Store`](crate::asset::AssetValue::Store).
            pub id: AssetId,
            /// The key of the key-value pair stored in the asset.
            pub key: Name,
        }

        /// [`FindAssetDefinitionKeyValueByIdAndKey`] Iroha Query gets [`AssetDefinitionId`] and key as input and finds [`Value`]
        /// of the key-value pair stored in this asset definition.
        #[derive(Display)]
        #[display(fmt = "Find metadata value with `{key}` key in `{id}` asset definition")]
        #[ffi_type]
        pub struct FindAssetDefinitionKeyValueByIdAndKey {
            /// `Id` of an [`Asset`] acting as [`Store`](crate::asset::AssetValue::Store)..
            pub id: AssetDefinitionId,
            /// The key of the key-value pair stored in the asset.
            pub key: Name,
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

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{
            FindAllAssets, FindAllAssetsDefinitions, FindAssetById, FindAssetDefinitionById,
            FindAssetDefinitionKeyValueByIdAndKey, FindAssetKeyValueByIdAndKey,
            FindAssetQuantityById, FindAssetsByAccountId, FindAssetsByAssetDefinitionId,
            FindAssetsByDomainId, FindAssetsByDomainIdAndAssetDefinitionId, FindAssetsByName,
            FindTotalAssetQuantityByAssetDefinitionId,
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
            pub id: DomainId,
        }

        /// [`FindDomainKeyValueByIdAndKey`] Iroha Query finds a [`Value`] of the key-value metadata pair
        /// in the specified domain.
        #[derive(Display)]
        #[display(fmt = "Find metadata value with key `{key}` in `{id}` domain")]
        #[ffi_type]
        pub struct FindDomainKeyValueByIdAndKey {
            /// `Id` of an domain to find.
            pub id: DomainId,
            /// Key of the specific key-value in the domain's metadata.
            pub key: Name,
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
        prelude::InstructionBox,
        trigger::{Trigger, TriggerId},
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
            pub id: TriggerId,
        }


        /// Find Trigger's metadata key-value pairs.
        #[derive(Display)]
        #[display(fmt = "Find metadata value with `{key}` key in `{id}` trigger")]
        #[ffi_type]
        pub struct FindTriggerKeyValueByIdAndKey {
            /// The Identification of the trigger to be found.
            pub id: TriggerId,
            /// The key inside the metadata dictionary to be returned.
            pub key: Name,
        }


        /// Find [`Trigger`]s under the given [`DomainId`].
        #[derive(Display)]
        #[display(fmt = "Find trigger under `{domain_id}` domain")]
        #[repr(transparent)]
        // SAFETY: `FindTriggersByDomainId` has no trap representation in `EvaluatesTo<DomainId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindTriggersByDomainId {
            /// [`DomainId`] specifies the domain in which to search for triggers.
            pub domain_id: DomainId,
        }
    }

    impl Query for FindAllActiveTriggerIds {
        type Output = Vec<TriggerId>;
    }

    impl Query for FindTriggerById {
        type Output = Trigger<TriggeringFilterBox>;
    }

    impl Query for FindTriggerKeyValueByIdAndKey {
        type Output = MetadataValue;
    }

    impl Query for FindTriggersByDomainId {
        type Output = Vec<Trigger<TriggeringFilterBox>>;
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
    use crate::{account::AccountId, prelude::Account, transaction::SignedTransaction};

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
            pub account_id: AccountId,
        }

        /// [`FindTransactionByHash`] Iroha Query finds a transaction (if any)
        /// with corresponding hash value
        #[derive(Copy, Display)]
        #[display(fmt = "Find transaction with `{hash}` hash")]
        #[repr(transparent)]
        // SAFETY: `FindTransactionByHash` has no trap representation in `EvaluatesTo<HashOf<SignedTransaction>>`
        #[ffi_type(unsafe {robust})]
        pub struct FindTransactionByHash {
            /// Transaction hash.
            pub hash: HashOf<SignedTransaction>,
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
    use crate::block::{BlockHeader, SignedBlock};

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
        #[derive(Copy, Display)]
        #[display(fmt = "Find block header with `{hash}` hash")]
        #[repr(transparent)]
        // SAFETY: `FindBlockHeaderByHash` has no trap representation in `EvaluatesTo<HashOf<SignedBlock>>`
        #[ffi_type(unsafe {robust})]
        pub struct FindBlockHeaderByHash {
            /// Block hash.
            pub hash: HashOf<SignedBlock>,
        }
    }

    impl Query for FindAllBlocks {
        type Output = Vec<SignedBlock>;
    }

    impl Query for FindAllBlockHeaders {
        type Output = Vec<BlockHeader>;
    }

    impl Query for FindBlockHeaderByHash {
        type Output = BlockHeader;
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

    declare_versioned_with_scale!(SignedQuery 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema);

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
        #[version_with_scale(version = 1, versioned_alias = "SignedQuery")]
        pub struct SignedQueryV1 {
            /// Signature of the client who sends this query.
            pub signature: SignatureOf<QueryPayload>,
            /// Payload
            pub payload: QueryPayload,
        }

        /// End type of a query http clients can send to an endpoint.
        #[derive(Debug, Clone, Decode, Encode)]
        pub struct ClientQueryRequest(pub QueryRequest<SignedQuery>);
    }

    impl ClientQueryRequest {
        /// Construct a new request containing query.
        pub fn query(
            query: SignedQuery,
            sorting: Sorting,
            pagination: Pagination,
            fetch_size: FetchSize,
        ) -> Self {
            Self(QueryRequest::Query(QueryWithParameters::new(
                query, sorting, pagination, fetch_size,
            )))
        }

        /// Construct a new request containing cursor.
        pub fn cursor(cursor: ForwardCursor) -> Self {
            Self(QueryRequest::Cursor(cursor))
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
            fn validate(self) -> Result<SignedQueryV1, &'static str> {
                #[cfg(feature = "std")]
                if self.signature.verify(&self.payload).is_err() {
                    return Err("Query signature not valid");
                }

                Ok(SignedQueryV1 {
                    payload: self.payload,
                    signature: self.signature,
                })
            }
        }

        impl Decode for SignedQueryV1 {
            fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
                SignedQueryCandidate::decode(input)?
                    .validate()
                    .map_err(Into::into)
            }
        }

        impl<'de> Deserialize<'de> for SignedQueryV1 {
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
    impl SignedQuery {
        /// Return query signature
        pub fn signature(&self) -> &SignatureOf<QueryPayload> {
            let SignedQuery::V1(query) = self;
            &query.signature
        }
        /// Return query payload
        pub fn query(&self) -> &QueryBox {
            let SignedQuery::V1(query) = self;
            &query.payload.query
        }
        /// Return query authority
        pub fn authority(&self) -> &AccountId {
            let SignedQuery::V1(query) = self;
            &query.payload.authority
        }
        /// Return query filter
        pub fn filter(&self) -> &PredicateBox {
            let SignedQuery::V1(query) = self;
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
        pub fn sign(self, key_pair: iroha_crypto::KeyPair) -> SignedQuery {
            SignedQueryV1 {
                signature: SignatureOf::new(key_pair, &self.payload),
                payload: self.payload,
            }
            .into()
        }
    }

    pub mod prelude {
        //! The prelude re-exports most commonly used traits, structs and macros from this crate.

        pub use super::{QueryBuilder, SignedQuery, SignedQueryV1};
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
    use crate::{block::SignedBlock, executor, permission, prelude::*};

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
            /// {0}
            #[cfg_attr(feature = "std", error(transparent))]
            Find(FindError),
            /// Query found wrong type of asset: {0}
            Conversion(
                #[skip_from]
                #[skip_try_from]
                String,
            ),
            /// Unknown query cursor
            UnknownCursor,
            /// fetch_size could not be greater than {MAX_FETCH_SIZE:?}
            FetchSizeTooBig,
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
            Block(HashOf<SignedBlock>),
            /// Transaction with hash `{0}` not found
            Transaction(HashOf<SignedTransaction>),
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
            PublicKey(Box<PublicKey>),
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
        trigger::prelude::*, FetchSize, QueryBox, QueryId, TransactionQueryOutput,
    };
}
