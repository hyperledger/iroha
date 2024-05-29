//! Iroha Queries provides declarative API for Iroha Queries.

#![allow(clippy::missing_inline_in_public_items, unused_imports)]

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::{cmp::Ordering, num::NonZeroU32, time::Duration};

pub use cursor::ForwardCursor;
use derive_more::{Constructor, Display};
use iroha_crypto::{PublicKey, SignatureOf};
use iroha_data_model_derive::{model, EnumRef};
use iroha_primitives::{numeric::Numeric, small::SmallVec};
use iroha_schema::IntoSchema;
use iroha_version::prelude::*;
use nonzero_ext::nonzero;
pub use pagination::Pagination;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
pub use sorting::Sorting;

pub use self::model::*;
use self::{
    account::*, asset::*, block::*, domain::*, executor::*, peer::*, permission::*, predicate::*,
    role::*, transaction::*, trigger::*,
};
use crate::{
    account::{Account, AccountId},
    block::{BlockHeader, SignedBlock},
    events::TriggeringEventFilterBox,
    metadata::MetadataValueBox,
    seal,
    transaction::{CommittedTransaction, SignedTransaction, TransactionPayload},
    IdBox, Identifiable, IdentifiableBox,
};

pub mod cursor;
pub mod pagination;
pub mod predicate;
pub mod sorting;

const FETCH_SIZE: &str = "fetch_size";

/// Default value for `fetch_size` parameter in queries.
pub const DEFAULT_FETCH_SIZE: NonZeroU32 = nonzero!(10_u32);

/// Max value for `fetch_size` parameter in queries.
pub const MAX_FETCH_SIZE: NonZeroU32 = nonzero!(10_000_u32);

/// Structure for query fetch size parameter encoding/decoding
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Constructor,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoSchema,
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
        mod model{
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
    type Output: Into<QueryOutputBox> + TryFrom<QueryOutputBox>;

    /// [`Encode`] [`Self`] as [`QueryBox`].
    ///
    /// Used to avoid an unnecessary clone
    fn encode_as_query_box(&self) -> Vec<u8>;
}

/// A [`Query`] that either returns a single value or errors out
pub trait SingularQuery: Query {}

/// A [`Query`] that returns an iterable collection of values
pub trait IterableQuery: Query {
    /// A type of single element of the output collection
    type Item;
}

#[model]
mod model {
    use getset::Getters;
    use iroha_crypto::HashOf;
    use iroha_macro::FromVariant;
    use strum::EnumDiscriminants;

    use super::*;
    use crate::{block::SignedBlock, permission::PermissionId};

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
        EnumRef,
        EnumDiscriminants,
        FromVariant,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[enum_ref(derive(Encode, FromVariant))]
    #[strum_discriminants(
        vis(pub(super)),
        name(QueryType),
        derive(Encode),
        allow(clippy::enum_variant_names)
    )]
    #[ffi_type]
    #[allow(missing_docs)]
    pub enum QueryBox {
        FindAllAccounts(FindAllAccounts),
        FindAccountById(FindAccountById),
        FindAccountKeyValueByIdAndKey(FindAccountKeyValueByIdAndKey),
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
        FindPermissionsByAccountId(FindPermissionsByAccountId),
        FindExecutorDataModel(FindExecutorDataModel),
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

    /// Sized container for all possible [`Query::Output`]s
    #[derive(
        Debug,
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
    #[allow(missing_docs)]
    pub enum QueryOutputBox {
        Id(IdBox),
        Identifiable(IdentifiableBox),
        Transaction(TransactionQueryOutput),
        Permission(crate::permission::Permission),
        LimitedMetadata(MetadataValueBox),
        Numeric(Numeric),
        BlockHeader(BlockHeader),
        Block(crate::block::SignedBlock),
        ExecutorDataModel(crate::executor::ExecutorDataModel),

        Vec(
            #[skip_from]
            #[skip_try_from]
            Vec<QueryOutputBox>,
        ),
    }

    /// Output of [`FindAllTransactions`] query
    #[derive(
        Debug,
        Clone,
        PartialOrd,
        Ord,
        PartialEq,
        Eq,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct TransactionQueryOutput {
        /// The hash of the block to which `tx` belongs to
        pub block_hash: HashOf<SignedBlock>,
        /// Transaction
        #[getset(skip)]
        pub transaction: CommittedTransaction,
    }

    /// Request type clients (like http clients or wasm) can send to a query endpoint.
    ///
    /// `Q` should be either [`http::SignedQuery`] for client or [`SmartContractQuery`] for wasm smart contract.
    // NOTE: if updating, also update the `iroha_smart_contract::QueryRequest` and its encoding
    #[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
    pub enum QueryRequest<Q> {
        /// Query it-self.
        /// Basically used for one-time queries or to get a cursor for big queries.
        Query(Q),
        /// Cursor over previously sent [`Query`](QueryRequest::Query).
        Cursor(ForwardCursor),
    }

    /// A query with parameters, as coming from a smart contract.
    // NOTE: if updating, also update the `iroha_smart_contract::SmartContractQuery` and its encoding
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        Constructor,
        Getters,
    )]
    #[getset(get = "pub")]
    pub struct SmartContractQuery {
        /// Query definition.
        pub query: QueryBox,
        /// The filter applied to the result on the server-side.
        pub filter: PredicateBox,
        /// Sorting of the query results.
        pub sorting: Sorting,
        /// Pagination of the query results.
        pub pagination: Pagination,
        /// Amount of results to fetch.
        pub fetch_size: FetchSize,
    }
}

impl From<u32> for QueryOutputBox {
    fn from(value: u32) -> Self {
        Self::Numeric(value.into())
    }
}

impl From<u64> for QueryOutputBox {
    fn from(value: u64) -> Self {
        Self::Numeric(value.into())
    }
}

impl TryFrom<QueryOutputBox> for u32 {
    type Error = iroha_macro::error::ErrorTryFromEnum<QueryOutputBox, Self>;

    fn try_from(value: QueryOutputBox) -> Result<Self, Self::Error> {
        use iroha_macro::error::ErrorTryFromEnum;

        let QueryOutputBox::Numeric(numeric) = value else {
            return Err(ErrorTryFromEnum::default());
        };

        numeric.try_into().map_err(|_| ErrorTryFromEnum::default())
    }
}

impl TryFrom<QueryOutputBox> for u64 {
    type Error = iroha_macro::error::ErrorTryFromEnum<QueryOutputBox, Self>;

    fn try_from(value: QueryOutputBox) -> Result<Self, Self::Error> {
        use iroha_macro::error::ErrorTryFromEnum;

        let QueryOutputBox::Numeric(numeric) = value else {
            return Err(ErrorTryFromEnum::default());
        };

        numeric.try_into().map_err(|_| ErrorTryFromEnum::default())
    }
}

/// Uses custom syntax to implement query-related traits on query types
///
/// Implements [`Query`] and, additionally, either [`SingularQuery`] or [`IterableQuery`],
///     depending on whether the output type is wrapped into a Vec (purely syntactically)
macro_rules! impl_queries {
    // we can't delegate matching over `Vec<$item:ty>` to an inner macro,
    //   as the moment a fragment is matched as `$output:ty` it becomes opaque and unmatchable to any literal
    //   https://doc.rust-lang.org/nightly/reference/macros-by-example.html#forwarding-a-matched-fragment
    // hence we match at the top level with a tt-muncher and a use `@impl_query` inner macro to avoid duplication of the `impl Query`
    ($ty:ty => Vec<$item:ty> $(, $($rest:tt)*)?) => {
        impl_queries!(@impl_query $ty => Vec<$item>);

        impl IterableQuery for $ty {
            type Item = $item;
        }

        $(
            impl_queries!($($rest)*);
        )?
    };
    ($ty:ty => $output:ty $(, $($rest:tt)*)?) => {
        impl_queries!(@impl_query $ty => $output);

        impl SingularQuery for $ty {
        }

        $(
            impl_queries!($($rest)*);
        )?
    };
    (@impl_query $ty:ty => $output:ty) =>{
        impl Query for $ty {
            type Output = $output;

            fn encode_as_query_box(&self) -> Vec<u8> {
                QueryBoxRef::from(self).encode()
            }
        }
    };
}

impl_queries! {
    FindAllRoles => Vec<crate::role::Role>,
    FindAllRoleIds => Vec<crate::role::RoleId>,
    FindRolesByAccountId => Vec<crate::role::RoleId>,
    FindRoleByRoleId => crate::role::Role,
    FindPermissionsByAccountId => Vec<crate::permission::Permission>,
    FindAllAccounts => Vec<crate::account::Account>,
    FindAccountById => crate::account::Account,
    FindAccountKeyValueByIdAndKey => MetadataValueBox,
    FindAccountsByDomainId => Vec<crate::account::Account>,
    FindAccountsWithAsset => Vec<crate::account::Account>,
    FindAllAssets => Vec<crate::asset::Asset>,
    FindAllAssetsDefinitions => Vec<crate::asset::AssetDefinition>,
    FindAssetById => crate::asset::Asset,
    FindAssetDefinitionById => crate::asset::AssetDefinition,
    FindAssetsByName => Vec<crate::asset::Asset>,
    FindAssetsByAccountId => Vec<crate::asset::Asset>,
    FindAssetsByAssetDefinitionId => Vec<crate::asset::Asset>,
    FindAssetsByDomainId => Vec<crate::asset::Asset>,
    FindAssetsByDomainIdAndAssetDefinitionId => Vec<crate::asset::Asset>,
    FindAssetQuantityById => Numeric,
    FindTotalAssetQuantityByAssetDefinitionId => Numeric,
    FindAssetKeyValueByIdAndKey => MetadataValueBox,
    FindAssetDefinitionKeyValueByIdAndKey => MetadataValueBox,
    FindAllDomains => Vec<crate::domain::Domain>,
    FindDomainById => crate::domain::Domain,
    FindDomainKeyValueByIdAndKey => MetadataValueBox,
    FindAllPeers => Vec<crate::peer::Peer>,
    FindAllParameters => Vec<crate::parameter::Parameter>,
    FindAllActiveTriggerIds => Vec<crate::trigger::TriggerId>,
    FindTriggerById => crate::trigger::Trigger,
    FindTriggerKeyValueByIdAndKey => MetadataValueBox,
    FindTriggersByDomainId => Vec<crate::trigger::Trigger>,
    FindAllTransactions => Vec<TransactionQueryOutput>,
    FindTransactionsByAccountId => Vec<TransactionQueryOutput>,
    FindTransactionByHash => TransactionQueryOutput,
    FindAllBlocks => Vec<SignedBlock>,
    FindAllBlockHeaders => Vec<crate::block::BlockHeader>,
    FindBlockHeaderByHash => crate::block::BlockHeader,
    FindExecutorDataModel => crate::executor::ExecutorDataModel
}

impl Query for QueryBox {
    type Output = QueryOutputBox;

    fn encode_as_query_box(&self) -> Vec<u8> {
        self.encode()
    }
}

impl core::fmt::Display for QueryOutputBox {
    // TODO: Maybe derive
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            QueryOutputBox::Id(v) => core::fmt::Display::fmt(&v, f),
            QueryOutputBox::Identifiable(v) => core::fmt::Display::fmt(&v, f),
            QueryOutputBox::Transaction(_) => write!(f, "TransactionQueryOutput"),
            QueryOutputBox::Permission(v) => core::fmt::Display::fmt(&v, f),
            QueryOutputBox::Block(v) => core::fmt::Display::fmt(&v, f),
            QueryOutputBox::BlockHeader(v) => core::fmt::Display::fmt(&v, f),
            QueryOutputBox::Numeric(v) => core::fmt::Display::fmt(&v, f),
            QueryOutputBox::LimitedMetadata(v) => core::fmt::Display::fmt(&v, f),
            QueryOutputBox::ExecutorDataModel(v) => core::fmt::Display::fmt(&v, f),

            QueryOutputBox::Vec(v) => {
                // TODO: Remove so we can derive.
                let list_of_display: Vec<_> = v.iter().map(ToString::to_string).collect();
                // this prints with quotation marks, which is fine 90%
                // of the time, and helps delineate where a display of
                // one value stops and another one begins.
                write!(f, "{list_of_display:?}")
            }
        }
    }
}

// TODO: The following macros looks very similar. Try to generalize them under one macro
macro_rules! from_and_try_from_value_idbox {
    ( $($variant:ident( $ty:ty ),)+ $(,)? ) => { $(
        impl TryFrom<QueryOutputBox> for $ty {
            type Error = iroha_macro::error::ErrorTryFromEnum<QueryOutputBox, Self>;

            fn try_from(value: QueryOutputBox) -> Result<Self, Self::Error> {
                if let QueryOutputBox::Id(IdBox::$variant(id)) = value {
                    Ok(id)
                } else {
                    Err(Self::Error::default())
                }
            }
        }

        impl From<$ty> for QueryOutputBox {
            fn from(id: $ty) -> Self {
                QueryOutputBox::Id(IdBox::$variant(id))
            }
        })+
    };
}

macro_rules! from_and_try_from_value_identifiable {
    ( $( $variant:ident( $ty:ty ), )+ $(,)? ) => { $(
        impl TryFrom<QueryOutputBox> for $ty {
            type Error = iroha_macro::error::ErrorTryFromEnum<QueryOutputBox, Self>;

            fn try_from(value: QueryOutputBox) -> Result<Self, Self::Error> {
                if let QueryOutputBox::Identifiable(IdentifiableBox::$variant(id)) = value {
                    Ok(id)
                } else {
                    Err(Self::Error::default())
                }
            }
        }

        impl From<$ty> for QueryOutputBox {
            fn from(id: $ty) -> Self {
                QueryOutputBox::Identifiable(IdentifiableBox::$variant(id))
            }
        } )+
    };
}

from_and_try_from_value_idbox!(
    PeerId(crate::peer::PeerId),
    DomainId(crate::domain::DomainId),
    AccountId(crate::account::AccountId),
    AssetId(crate::asset::AssetId),
    AssetDefinitionId(crate::asset::AssetDefinitionId),
    TriggerId(crate::trigger::TriggerId),
    RoleId(crate::role::RoleId),
    ParameterId(crate::parameter::ParameterId),
    // TODO: Should we wrap String with new type in order to convert like here?
    //from_and_try_from_value_idbox!((DomainName(Name), ErrorValueTryFromDomainName),);
);

from_and_try_from_value_identifiable!(
    NewDomain(crate::domain::NewDomain),
    NewAccount(crate::account::NewAccount),
    NewAssetDefinition(crate::asset::NewAssetDefinition),
    NewRole(crate::role::NewRole),
    Peer(crate::peer::Peer),
    Domain(crate::domain::Domain),
    Account(crate::account::Account),
    AssetDefinition(crate::asset::AssetDefinition),
    Asset(crate::asset::Asset),
    Trigger(crate::trigger::Trigger),
    Role(crate::role::Role),
    Parameter(crate::parameter::Parameter),
);

impl<V: Into<QueryOutputBox>> From<Vec<V>> for QueryOutputBox {
    fn from(values: Vec<V>) -> QueryOutputBox {
        QueryOutputBox::Vec(values.into_iter().map(Into::into).collect())
    }
}

impl<V> TryFrom<QueryOutputBox> for Vec<V>
where
    QueryOutputBox: TryInto<V>,
{
    type Error = iroha_macro::error::ErrorTryFromEnum<QueryOutputBox, Self>;

    fn try_from(value: QueryOutputBox) -> Result<Self, Self::Error> {
        if let QueryOutputBox::Vec(vec) = value {
            return vec
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_e| Self::Error::default());
        }

        Err(Self::Error::default())
    }
}

impl AsRef<CommittedTransaction> for TransactionQueryOutput {
    fn as_ref(&self) -> &CommittedTransaction {
        &self.transaction
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

impl core::fmt::Display for SmartContractQuery {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QueryWithParameters")
            .field("query", &self.query.to_string())
            .field("filter", &self.filter)
            .field("sorting", &self.sorting)
            .field("pagination", &self.pagination)
            .field("fetch_size", &self.fetch_size)
            .finish()
    }
}

pub mod role {
    //! Queries related to [`Role`].

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;
    use parity_scale_codec::Encode;

    use super::{Query, QueryType};
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

    /// The prelude re-exports most commonly used traits, structs and macros from this module.
    pub mod prelude {
        pub use super::{FindAllRoleIds, FindAllRoles, FindRoleByRoleId, FindRolesByAccountId};
    }
}

pub mod permission {
    //! Queries related to [`Permission`].

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;
    use parity_scale_codec::Encode;

    use super::{Query, QueryType};
    use crate::prelude::*;

    queries! {
        /// [`FindPermissionsByAccountId`] Iroha Query finds all [`Permission`]s
        /// for a specified account.
        #[derive(Display)]
        #[display(fmt = "Find permission tokens specified for `{id}` account")]
        #[repr(transparent)]
        // SAFETY: `FindPermissionsByAccountId` has no trap representation in `EvaluatesTo<AccountId>`
        #[ffi_type(unsafe {robust})]
        pub struct FindPermissionsByAccountId {
            /// `Id` of an account to find.
            pub id: AccountId,
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this module.
    pub mod prelude {
        pub use super::FindPermissionsByAccountId;
    }
}

pub mod account {
    //! Queries related to [`Account`].

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;
    use parity_scale_codec::Encode;

    use super::{MetadataValueBox, Query, QueryType};
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

        /// [`FindAccountKeyValueByIdAndKey`] Iroha Query finds an [`MetadataValue`]
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

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{
            FindAccountById, FindAccountKeyValueByIdAndKey, FindAccountsByDomainId,
            FindAccountsWithAsset, FindAllAccounts,
        };
    }
}

pub mod asset {
    //! Queries related to [`Asset`].

    #![allow(clippy::missing_inline_in_public_items)]

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;
    use iroha_primitives::numeric::Numeric;
    use parity_scale_codec::Encode;

    use super::{MetadataValueBox, Query, QueryType};
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

        /// [`FindAssetKeyValueByIdAndKey`] Iroha Query gets [`AssetId`] and key as input and finds [`MetadataValue`]
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

        /// [`FindAssetDefinitionKeyValueByIdAndKey`] Iroha Query gets [`AssetDefinitionId`] and key as input and finds [`MetadataValue`]
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
    use parity_scale_codec::Encode;

    use super::{MetadataValueBox, Query, QueryType};
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

        /// [`FindDomainKeyValueByIdAndKey`] Iroha Query finds a [`MetadataValue`] of the key-value metadata pair
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

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{FindAllDomains, FindDomainById, FindDomainKeyValueByIdAndKey};
    }
}

pub mod peer {
    //! Queries related to [`crate::peer`].

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;
    use parity_scale_codec::Encode;

    use super::{Query, QueryType};

    queries! {
        /// [`FindAllPeers`] Iroha Query finds all trusted [`Peer`]s presented in current Iroha [`Peer`].
        #[derive(Copy, Display)]
        #[display(fmt = "Find all peers")]
        #[ffi_type]
        pub struct FindAllPeers;
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::FindAllPeers;
    }
}

pub mod executor {
    //! Queries related to [`crate::executor`].

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;

    queries! {
        /// [`FindExecutorDataModel`] Iroha Query finds the data model of the current executor.
        #[derive(Copy, Display)]
        #[display(fmt = "Find executor data model")]
        #[ffi_type]
        pub struct FindExecutorDataModel;

        /// [`FindAllParameters`] Iroha Query finds all defined executor configuration parameters.
        #[derive(Copy, Display)]
        #[display(fmt = "Find all peers parameters")]
        #[ffi_type]
        pub struct FindAllParameters;
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{FindAllParameters, FindExecutorDataModel};
    }
}

pub mod trigger {
    //! Trigger-related queries.
    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;
    use parity_scale_codec::Encode;

    use super::{MetadataValueBox, Query, QueryType};
    use crate::{
        domain::prelude::*,
        events::TriggeringEventFilterBox,
        prelude::InstructionBox,
        trigger::{Trigger, TriggerId},
        Executable, Identifiable, Name,
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
    use parity_scale_codec::Encode;

    use super::{Query, QueryType, TransactionQueryOutput};
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

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{FindAllTransactions, FindTransactionByHash, FindTransactionsByAccountId};
    }
}

pub mod block {
    //! Queries related to blocks.

    #![allow(clippy::missing_inline_in_public_items)]

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;
    use iroha_crypto::HashOf;
    use parity_scale_codec::{Decode, Encode};

    use super::{Query, SignedBlock};

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
    use predicate::PredicateBox;

    pub use self::model::*;
    use super::*;
    use crate::account::AccountId;

    declare_versioned!(SignedQuery 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema);

    #[model]
    mod model {
        use core::num::NonZeroU64;

        use super::*;

        /// I/O ready structure to send queries.
        #[derive(Debug, Clone)]
        #[repr(transparent)]
        #[must_use]
        pub struct ClientQueryBuilder {
            /// Payload
            pub(super) payload: ClientQueryPayload,
        }

        /// Payload of a query.
        #[derive(
            Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
        )]
        pub(crate) struct ClientQueryPayload {
            /// Account id of the user who will sign this query.
            pub authority: AccountId,
            /// Query definition.
            pub query: QueryBox,
            /// The filter applied to the result on the server-side.
            pub filter: PredicateBox,
            /// Sorting applied to the result on the server-side.
            pub sorting: Sorting,
            /// Selects the page of the result set to return.
            pub pagination: Pagination,
            /// Specifies the size of a single batch of results.
            pub fetch_size: FetchSize,
        }

        /// I/O ready structure to send queries.
        #[derive(Debug, Clone, Encode, Serialize, IntoSchema)]
        #[version_with_scale(version = 1, versioned_alias = "SignedQuery")]
        pub struct SignedQueryV1 {
            /// Signature of the client who sends this query.
            pub signature: SignatureOf<ClientQueryPayload>,
            /// Payload
            pub payload: ClientQueryPayload,
        }

        /// End type of a query http clients can send to an endpoint.
        #[derive(Debug, Clone, Decode, Encode)]
        pub struct ClientQueryRequest(pub QueryRequest<SignedQuery>);
    }

    impl ClientQueryRequest {
        /// Construct a new request containing query.
        pub fn query(query: SignedQuery) -> Self {
            Self(QueryRequest::Query(query))
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
            signature: SignatureOf<ClientQueryPayload>,
            payload: ClientQueryPayload,
        }

        impl SignedQueryCandidate {
            fn validate(self) -> Result<SignedQueryV1, &'static str> {
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
        pub fn signature(&self) -> &SignatureOf<ClientQueryPayload> {
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
        /// Return query sorting
        pub fn sorting(&self) -> &Sorting {
            let SignedQuery::V1(query) = self;
            &query.payload.sorting
        }
        /// Return query pagination
        pub fn pagination(&self) -> Pagination {
            let SignedQuery::V1(query) = self;
            query.payload.pagination
        }
        /// Return query fetch size
        pub fn fetch_size(&self) -> FetchSize {
            let SignedQuery::V1(query) = self;
            query.payload.fetch_size
        }
    }

    impl ClientQueryBuilder {
        /// Construct a new request with the `query`.
        pub fn new(query: impl Query, authority: AccountId) -> Self {
            Self {
                payload: ClientQueryPayload {
                    query: query.into(),
                    authority,
                    filter: PredicateBox::default(),
                    sorting: Sorting::default(),
                    pagination: Pagination::default(),
                    fetch_size: FetchSize::default(),
                },
            }
        }

        /// Set the filter for the query
        #[inline]
        pub fn with_filter(mut self, filter: PredicateBox) -> Self {
            self.payload.filter = filter;
            self
        }

        /// Set the sorting for the query
        #[inline]
        pub fn with_sorting(mut self, sorting: Sorting) -> Self {
            self.payload.sorting = sorting;
            self
        }

        /// Set the pagination for the query
        #[inline]
        pub fn with_pagination(mut self, pagination: Pagination) -> Self {
            self.payload.pagination = pagination;
            self
        }

        /// Set the fetch size for the query
        #[inline]
        pub fn with_fetch_size(mut self, fetch_size: FetchSize) -> Self {
            self.payload.fetch_size = fetch_size;
            self
        }

        /// Consumes self and returns a signed [`ClientQueryBuilder`].
        ///
        /// # Errors
        /// Fails if signature creation fails.
        #[inline]
        #[must_use]
        pub fn sign(self, key_pair: &iroha_crypto::KeyPair) -> SignedQuery {
            SignedQueryV1 {
                signature: SignatureOf::new(key_pair, &self.payload),
                payload: self.payload,
            }
            .into()
        }
    }

    pub mod prelude {
        //! The prelude re-exports most commonly used traits, structs and macros from this crate.

        pub use super::{ClientQueryBuilder, SignedQuery, SignedQueryV1};
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
    use crate::{executor, permission, prelude::*};

    #[model]
    mod model {
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
            /// Some of the specified parameters (filter/pagination/fetch_size/sorting) are not applicable to singular queries
            InvalidSingularParameters,
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
            /// Failed to find [`Permission`] by id.
            Permission(PermissionId),
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
        executor::prelude::*, peer::prelude::*, permission::prelude::*, predicate::PredicateTrait,
        role::prelude::*, transaction::prelude::*, trigger::prelude::*, FetchSize, QueryBox,
        QueryId, TransactionQueryOutput,
    };
}
