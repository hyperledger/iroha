//! Iroha Queries provides declarative API for Iroha Queries.

#![allow(clippy::missing_inline_in_public_items)]

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

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
use crate::{
    account::Account, pagination::Pagination, predicate::PredicateBox, Identifiable, Value,
};

/// Sized container for all possible Queries.
#[allow(clippy::enum_variant_names)]
#[derive(
    Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum QueryBox<const HASH_LENGTH: usize> {
    /// [`FindAllAccounts`] variant.
    FindAllAccounts(FindAllAccounts),
    /// [`FindAccountById`] variant.
    FindAccountById(FindAccountById<{ HASH_LENGTH }>),
    /// [`FindAccountKeyValueByIdAndKey`] variant.
    FindAccountKeyValueByIdAndKey(FindAccountKeyValueByIdAndKey<{ HASH_LENGTH }>),
    /// [`FindAccountsByName`] variant.
    FindAccountsByName(FindAccountsByName<{ HASH_LENGTH }>),
    /// [`FindAccountsByDomainId`] variant.
    FindAccountsByDomainId(FindAccountsByDomainId<{ HASH_LENGTH }>),
    /// [`FindAccountsWithAsset`] variant.
    FindAccountsWithAsset(FindAccountsWithAsset<{ HASH_LENGTH }>),
    /// [`FindAllAssets`] variant.
    FindAllAssets(FindAllAssets),
    /// [`FindAllAssetsDefinitions`] variant.
    FindAllAssetsDefinitions(FindAllAssetsDefinitions),
    /// [`FindAssetById`] variant.
    FindAssetById(FindAssetById<{ HASH_LENGTH }>),
    /// [`FindAssetDefinitionById`] variant.
    FindAssetDefinitionById(FindAssetDefinitionById<{ HASH_LENGTH }>),
    /// [`FindAssetsByName`] variant.
    FindAssetsByName(FindAssetsByName<{ HASH_LENGTH }>),
    /// [`FindAssetsByAccountId`] variant.
    FindAssetsByAccountId(FindAssetsByAccountId<{ HASH_LENGTH }>),
    /// [`FindAssetsByAssetDefinitionId`] variant.
    FindAssetsByAssetDefinitionId(FindAssetsByAssetDefinitionId<{ HASH_LENGTH }>),
    /// [`FindAssetsByDomainId`] variant.
    FindAssetsByDomainId(FindAssetsByDomainId<{ HASH_LENGTH }>),
    /// [`FindAssetsByDomainIdAndAssetDefinitionId`] variant.
    FindAssetsByDomainIdAndAssetDefinitionId(FindAssetsByDomainIdAndAssetDefinitionId<{ HASH_LENGTH }>),
    /// [`FindAssetQuantityById`] variant.
    FindAssetQuantityById(FindAssetQuantityById<{ HASH_LENGTH }>),
    /// [`FindAssetKeyValueByIdAndKey`] variant.
    FindAssetKeyValueByIdAndKey(FindAssetKeyValueByIdAndKey<{ HASH_LENGTH }>),
    /// [`FindAssetKeyValueByIdAndKey`] variant.
    FindAssetDefinitionKeyValueByIdAndKey(FindAssetDefinitionKeyValueByIdAndKey<{ HASH_LENGTH }>),
    /// [`FindAllDomains`] variant.
    FindAllDomains(FindAllDomains),
    /// [`FindDomainById`] variant.
    FindDomainById(FindDomainById<{ HASH_LENGTH }>),
    /// [`FindDomainKeyValueByIdAndKey`] variant.
    FindDomainKeyValueByIdAndKey(FindDomainKeyValueByIdAndKey<{ HASH_LENGTH }>),
    /// [`FindAllPeers`] variant.
    FindAllPeers(FindAllPeers),
    /// [`FindAllBlocks`] variant.
    FindAllBlocks(FindAllBlocks),
    /// [`FindAllTransactions`] variant.
    FindAllTransactions(FindAllTransactions),
    /// [`FindTransactionsByAccountId`] variant.
    FindTransactionsByAccountId(FindTransactionsByAccountId<{ HASH_LENGTH }>),
    /// [`FindTransactionByHash`] variant.
    FindTransactionByHash(FindTransactionByHash<{ HASH_LENGTH }>),
    /// [`FindPermissionTokensByAccountId`] variant.
    FindPermissionTokensByAccountId(FindPermissionTokensByAccountId<{ HASH_LENGTH }>),
    /// [`FindAllActiveTriggerIds`] variant.
    FindAllActiveTriggerIds(FindAllActiveTriggerIds),
    /// [`FindTriggerById`] variant.
    FindTriggerById(FindTriggerById<{ HASH_LENGTH }>),
    /// [`FindTriggerKeyValueByIdAndKey`] variant.
    FindTriggerKeyValueByIdAndKey(FindTriggerKeyValueByIdAndKey<{ HASH_LENGTH }>),
    /// [`FindTriggersByDomainId`] variant.
    FindTriggersByDomainId(FindTriggersByDomainId<{ HASH_LENGTH }>),
    /// [`FindAllRoles`] variant.
    FindAllRoles(FindAllRoles),
    /// [`FindAllRoleIds`] variant.
    FindAllRoleIds(FindAllRoleIds),
    /// [`FindRoleByRoleId`] variant.
    FindRoleByRoleId(FindRoleByRoleId<{ HASH_LENGTH }>),
    /// [`FindRolesByAccountId`] variant.
    FindRolesByAccountId(FindRolesByAccountId<{ HASH_LENGTH }>),
}

/// Trait for typesafe query output
pub trait Query<const HASH_LENGTH: usize> {
    /// Output type of query
    type Output: Into<Value<HASH_LENGTH>> + TryFrom<Value<HASH_LENGTH>>;
}

impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for QueryBox<HASH_LENGTH> {
    type Output = Value<HASH_LENGTH>;
}

/// Payload of a query.
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct Payload<const HASH_LENGTH: usize> {
    /// Timestamp of the query creation.
    #[codec(compact)]
    pub timestamp_ms: u128,
    /// Query definition.
    pub query: QueryBox<HASH_LENGTH>,
    /// Account id of the user who will sign this query.
    pub account_id: <Account<HASH_LENGTH> as Identifiable>::Id,
    /// The filter applied to the result on the server-side.
    pub filter: PredicateBox,
}

impl<const HASH_LENGTH: usize> Payload<HASH_LENGTH> {
    /// Hash of this payload.
    #[cfg(feature = "std")]
    pub fn hash(&self) -> iroha_crypto::HashOf<Self, HASH_LENGTH> {
        iroha_crypto::HashOf::new(self)
    }
}

/// I/O ready structure to send queries.
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize)]
#[cfg(feature = "warp")]
pub struct QueryRequest<const HASH_LENGTH: usize> {
    /// Payload
    pub payload: Payload<HASH_LENGTH>,
}

#[cfg(feature = "warp")]
declare_versioned_with_scale!(VersionedSignedQueryRequest 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema);

/// I/O ready structure to send queries.
#[version_with_scale(n = 1, versioned = "VersionedSignedQueryRequest")]
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct SignedQueryRequest<const HASH_LENGTH: usize> {
    /// Payload
    pub payload: Payload<HASH_LENGTH>,
    /// Signature of the client who sends this query.
    pub signature: SignatureOf<Payload<HASH_LENGTH>, HASH_LENGTH>,
}

declare_versioned_with_scale!(VersionedQueryResult 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema);

/// Sized container for all possible Query results.
#[version_with_scale(n = 1, versioned = "VersionedQueryResult")]
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct QueryResult<const HASH_LENGTH: usize>(pub Value<HASH_LENGTH>);

declare_versioned_with_scale!(VersionedPaginatedQueryResult 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema);

/// Paginated Query Result
#[version_with_scale(n = 1, versioned = "VersionedPaginatedQueryResult")]
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct PaginatedQueryResult<const HASH_LENGTH: usize> {
    /// The result of the query execution.
    pub result: QueryResult<HASH_LENGTH>,
    /// The filter that was applied to the Query result. Returned as a sanity check, but also to ease debugging on the front-end.
    pub filter: PredicateBox,
    /// pagination
    pub pagination: Pagination,
    /// Total query amount (if applicable) else 0.
    pub total: u64,
}

#[cfg(all(feature = "std", feature = "warp"))]
impl<const HASH_LENGTH: usize> QueryRequest<HASH_LENGTH> {
    /// Constructs a new request with the `query`.
    pub fn new(
        query: QueryBox<HASH_LENGTH>,
        account_id: <Account<HASH_LENGTH> as Identifiable>::Id,
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

    /// Consumes self and returns a signed `QueryRequest`.
    ///
    /// # Errors
    /// Fails if signature creation fails.
    pub fn sign(
        self,
        key_pair: iroha_crypto::KeyPair<HASH_LENGTH>,
    ) -> Result<SignedQueryRequest<HASH_LENGTH>, iroha_crypto::Error> {
        let signature = SignatureOf::new(key_pair, &self.payload)?;
        Ok(SignedQueryRequest {
            payload: self.payload,
            signature,
        })
    }
}

pub mod role {
    //! Queries related to `Role`.

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::prelude::*;

    /// `FindAllRoles` Iroha Query will find all `Roles`s presented.
    #[derive(
        Debug,
        Clone,
        Copy,
        Default,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct FindAllRoles;

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAllRoles {
        type Output = Vec<Role<HASH_LENGTH>>;
    }

    /// `FindAllRoles` Iroha Query will find all `Roles`s presented.
    #[derive(
        Debug,
        Clone,
        Copy,
        Default,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct FindAllRoleIds;

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAllRoleIds {
        type Output = Vec<<Role<HASH_LENGTH> as Identifiable>::Id>;
    }

    /// `FindRoleByRoleId` Iroha Query to find the [`Role`] which has the given [`Id`](crate::role::Id)
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindRoleByRoleId<const HASH_LENGTH: usize> {
        /// `Id` of the `Role` to find
        pub id: EvaluatesTo<<Role<HASH_LENGTH> as Identifiable>::Id, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindRoleByRoleId<HASH_LENGTH> {
        type Output = Role<HASH_LENGTH>;
    }

    /// `FindRolesByAccountId` Iroha Query will find an [`Role`]s for a specified account.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindRolesByAccountId<const HASH_LENGTH: usize> {
        /// `Id` of an account to find.
        pub id: EvaluatesTo<<Account<HASH_LENGTH> as Identifiable>::Id, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindRolesByAccountId<HASH_LENGTH> {
        type Output = Vec<<Role<HASH_LENGTH> as Identifiable>::Id>;
    }

    impl FindAllRoles {
        /// Construct [`FindAllRoles`].
        pub const fn new() -> Self {
            FindAllRoles
        }
    }

    impl FindAllRoleIds {
        /// Construct [`FindAllRoleIds`].
        pub const fn new() -> Self {
            FindAllRoleIds
        }
    }

    impl<const HASH_LENGTH: usize> FindRoleByRoleId<HASH_LENGTH> {
        /// Construct [`FindRoleByRoleId`].
        pub fn new(
            id: impl Into<EvaluatesTo<<Role<HASH_LENGTH> as Identifiable>::Id, HASH_LENGTH>>,
        ) -> Self {
            let id = id.into();
            FindRoleByRoleId { id }
        }
    }

    impl<const HASH_LENGTH: usize> FindRolesByAccountId<HASH_LENGTH> {
        /// Construct [`FindRolesByAccountId`].
        pub fn new(
            account_id: impl Into<EvaluatesTo<<Account<HASH_LENGTH> as Identifiable>::Id, HASH_LENGTH>>,
        ) -> Self {
            let account_id = account_id.into();
            FindRolesByAccountId { id: account_id }
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this module.
    pub mod prelude {
        pub use super::{FindAllRoleIds, FindAllRoles, FindRoleByRoleId, FindRolesByAccountId};
    }
}

pub mod permissions {
    //! Queries related to `PermissionToken`.

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::prelude::*;

    /// `FindPermissionTokensByAccountId` Iroha Query will find an `Role`s for a specified account.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindPermissionTokensByAccountId<const HASH_LENGTH: usize> {
        /// `Id` of an account to find.
        pub id: EvaluatesTo<AccountId<HASH_LENGTH>, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindPermissionTokensByAccountId<HASH_LENGTH> {
        type Output = Vec<PermissionToken<HASH_LENGTH>>;
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this module.
    pub mod prelude {
        pub use super::FindPermissionTokensByAccountId;
    }
}

pub mod account {
    //! Queries related to `Account`.

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::prelude::*;

    // TODO: Better to have find all account ids query instead.
    /// `FindAllAccounts` Iroha Query will find all `Account`s presented.
    #[derive(
        Debug,
        Clone,
        Copy,
        Default,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct FindAllAccounts;

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAllAccounts {
        type Output = Vec<Account<HASH_LENGTH>>;
    }

    /// `FindAccountById` Iroha Query will find an `Account` by it's identification.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindAccountById<const HASH_LENGTH: usize> {
        /// `Id` of an account to find.
        pub id: EvaluatesTo<AccountId<HASH_LENGTH>, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAccountById<HASH_LENGTH> {
        type Output = Account<HASH_LENGTH>;
    }

    /// `FindAccountById` Iroha Query will find a [`Value`] of the key-value metadata pair
    /// in the specified account.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindAccountKeyValueByIdAndKey<const HASH_LENGTH: usize> {
        /// `Id` of an account to find.
        pub id: EvaluatesTo<AccountId<HASH_LENGTH>, HASH_LENGTH>,
        /// Key of the specific key-value in the Account's metadata.
        pub key: EvaluatesTo<Name, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAccountKeyValueByIdAndKey<HASH_LENGTH> {
        type Output = Value<HASH_LENGTH>;
    }

    /// `FindAccountsByName` Iroha Query will get `Account`s name as input and
    /// find all `Account`s with this name.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindAccountsByName<const HASH_LENGTH: usize> {
        /// `name` of accounts to find.
        pub name: EvaluatesTo<Name, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAccountsByName<HASH_LENGTH> {
        type Output = Vec<Account<HASH_LENGTH>>;
    }

    /// `FindAccountsByDomainId` Iroha Query will get `Domain`s id as input and
    /// find all `Account`s under this `Domain`.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindAccountsByDomainId<const HASH_LENGTH: usize> {
        /// `Id` of the domain under which accounts should be found.
        pub domain_id: EvaluatesTo<DomainId, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAccountsByDomainId<HASH_LENGTH> {
        type Output = Vec<Account<HASH_LENGTH>>;
    }

    /// `FindAccountsWithAsset` Iroha Query will get `AssetDefinition`s id as input and
    /// find all `Account`s storing `Asset` with such definition.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindAccountsWithAsset<const HASH_LENGTH: usize> {
        /// `Id` of the definition of the asset which should be stored in founded accounts.
        pub asset_definition_id: EvaluatesTo<AssetDefinitionId<HASH_LENGTH>, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAccountsWithAsset<HASH_LENGTH> {
        type Output = Vec<Account<HASH_LENGTH>>;
    }

    impl FindAllAccounts {
        /// Construct [`FindAllAccounts`].
        pub const fn new() -> Self {
            FindAllAccounts
        }
    }

    impl<const HASH_LENGTH: usize> FindAccountById<HASH_LENGTH> {
        /// Construct [`FindAccountById`].
        pub fn new(id: impl Into<EvaluatesTo<AccountId<HASH_LENGTH>, HASH_LENGTH>>) -> Self {
            let id = id.into();
            FindAccountById { id }
        }
    }

    impl<const HASH_LENGTH: usize> FindAccountKeyValueByIdAndKey<HASH_LENGTH> {
        /// Construct [`FindAccountById`].
        pub fn new(
            id: impl Into<EvaluatesTo<AccountId<HASH_LENGTH>, HASH_LENGTH>>,
            key: impl Into<EvaluatesTo<Name, HASH_LENGTH>>,
        ) -> Self {
            let id = id.into();
            let key = key.into();
            FindAccountKeyValueByIdAndKey { id, key }
        }
    }

    impl<const HASH_LENGTH: usize> FindAccountsByName<HASH_LENGTH> {
        /// Construct [`FindAccountsByName`].
        pub fn new(name: impl Into<EvaluatesTo<Name, HASH_LENGTH>>) -> Self {
            let name = name.into();
            FindAccountsByName { name }
        }
    }

    impl<const HASH_LENGTH: usize> FindAccountsByDomainId<HASH_LENGTH> {
        /// Construct [`FindAccountsByDomainId`].
        pub fn new(domain_id: impl Into<EvaluatesTo<DomainId, HASH_LENGTH>>) -> Self {
            let domain_id = domain_id.into();
            FindAccountsByDomainId { domain_id }
        }
    }

    impl<const HASH_LENGTH: usize> FindAccountsWithAsset<HASH_LENGTH> {
        /// Construct [`FindAccountsWithAsset`].
        pub fn new(
            asset_definition_id: impl Into<EvaluatesTo<AssetDefinitionId<HASH_LENGTH>, HASH_LENGTH>>,
        ) -> Self {
            let asset_definition_id = asset_definition_id.into();
            FindAccountsWithAsset {
                asset_definition_id,
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
    //! Queries related to `Asset`.

    #![allow(clippy::missing_inline_in_public_items)]

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::prelude::*;

    /// `FindAllAssets` Iroha Query will find all `Asset`s presented in Iroha Peer.
    #[derive(
        Debug,
        Clone,
        Copy,
        Default,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct FindAllAssets;

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAllAssets {
        type Output = Vec<Asset<HASH_LENGTH>>;
    }

    /// `FindAllAssetsDefinitions` Iroha Query will find all `AssetDefinition`s presented
    /// in Iroha Peer.
    #[derive(
        Debug,
        Clone,
        Copy,
        Default,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct FindAllAssetsDefinitions;

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAllAssetsDefinitions {
        type Output = Vec<AssetDefinition<HASH_LENGTH>>;
    }

    /// `FindAssetById` Iroha Query will find an `Asset` by it's identification in Iroha `Peer`.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindAssetById<const HASH_LENGTH: usize> {
        /// `Id` of an `Asset` to find.
        pub id: EvaluatesTo<AssetId<HASH_LENGTH>, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAssetById<HASH_LENGTH> {
        type Output = Asset<HASH_LENGTH>;
    }

    /// `FindAssetDefinitionById` Iroha Query will find an `AssetDefinition` by it's identification in Iroha `Peer`.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindAssetDefinitionById<const HASH_LENGTH: usize> {
        /// `Id` of an `AssetDefinition` to find.
        pub id: EvaluatesTo<AssetDefinitionId<HASH_LENGTH>, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAssetDefinitionById<HASH_LENGTH> {
        type Output = AssetDefinition<HASH_LENGTH>;
    }

    /// `FindAssetsByName` Iroha Query will get `Asset`s name as input and
    /// find all `Asset`s with it in Iroha `Peer`.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindAssetsByName<const HASH_LENGTH: usize> {
        /// `Name` of `Asset`s to find.
        pub name: EvaluatesTo<Name, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAssetsByName<HASH_LENGTH> {
        type Output = Vec<Asset<HASH_LENGTH>>;
    }

    /// `FindAssetsByAccountId` Iroha Query will get `AccountId` as input and find all `Asset`s
    /// owned by the `Account` in Iroha Peer.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindAssetsByAccountId<const HASH_LENGTH: usize> {
        /// `AccountId` under which assets should be found.
        pub account_id: EvaluatesTo<AccountId<HASH_LENGTH>, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAssetsByAccountId<HASH_LENGTH> {
        type Output = Vec<Asset<HASH_LENGTH>>;
    }

    /// `FindAssetsByAssetDefinitionId` Iroha Query will get `AssetDefinitionId` as input and
    /// find all `Asset`s with this `AssetDefinition` in Iroha Peer.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindAssetsByAssetDefinitionId<const HASH_LENGTH: usize> {
        /// `AssetDefinitionId` with type of `Asset`s should be found.
        pub asset_definition_id: EvaluatesTo<AssetDefinitionId<HASH_LENGTH>, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAssetsByAssetDefinitionId<HASH_LENGTH> {
        type Output = Vec<Asset<HASH_LENGTH>>;
    }

    /// `FindAssetsByDomainId` Iroha Query will get `Domain`s id as input and
    /// find all `Asset`s under this `Domain` in Iroha `Peer`.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindAssetsByDomainId<const HASH_LENGTH: usize> {
        /// `Id` of the domain under which assets should be found.
        pub domain_id: EvaluatesTo<DomainId, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAssetsByDomainId<HASH_LENGTH> {
        type Output = Vec<Asset<HASH_LENGTH>>;
    }

    /// `FindAssetsByDomainIdAndAssetDefinitionId` Iroha Query will get `Domain`'s id and
    /// `AssetDefinitionId` as inputs and find all `Asset`s under the `Domain`
    /// with this `AssetDefinition` in Iroha `Peer`.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindAssetsByDomainIdAndAssetDefinitionId<const HASH_LENGTH: usize> {
        /// `Id` of the domain under which assets should be found.
        pub domain_id: EvaluatesTo<DomainId, HASH_LENGTH>,
        /// `AssetDefinitionId` assets of which type should be found.
        pub asset_definition_id: EvaluatesTo<AssetDefinitionId<HASH_LENGTH>, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH>
        for FindAssetsByDomainIdAndAssetDefinitionId<HASH_LENGTH>
    {
        type Output = Vec<Asset<HASH_LENGTH>>;
    }

    /// `FindAssetQuantityById` Iroha Query will get `AssetId` as input and find `Asset::quantity`
    /// parameter's value if `Asset` is presented in Iroha Peer.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindAssetQuantityById<const HASH_LENGTH: usize> {
        /// `Id` of an `Asset` to find quantity of.
        pub id: EvaluatesTo<AssetId<HASH_LENGTH>, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAssetQuantityById<HASH_LENGTH> {
        type Output = u32;
    }

    /// `FindAssetKeyValueByIdAndKey` Iroha Query will get `AssetId` and key as input and find
    /// [`Value`] of the key-value pair stored in this asset.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindAssetKeyValueByIdAndKey<const HASH_LENGTH: usize> {
        /// `Id` of an `Asset` acting as `Store`.
        pub id: EvaluatesTo<AssetId<HASH_LENGTH>, HASH_LENGTH>,
        /// The key of the key-value pair stored in the asset.
        pub key: EvaluatesTo<Name, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAssetKeyValueByIdAndKey<HASH_LENGTH> {
        type Output = Value<HASH_LENGTH>;
    }

    /// `FindAssetDefinitionKeyValueByIdAndKey` Iroha Query will get `AssetDefinitionId` and key as
    /// input and find [`Value`] of the key-value pair stored in this asset definition.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindAssetDefinitionKeyValueByIdAndKey<const HASH_LENGTH: usize> {
        /// `Id` of an `Asset` acting as `Store`.
        pub id: EvaluatesTo<AssetDefinitionId<HASH_LENGTH>, HASH_LENGTH>,
        /// The key of the key-value pair stored in the asset.
        pub key: EvaluatesTo<Name, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH>
        for FindAssetDefinitionKeyValueByIdAndKey<HASH_LENGTH>
    {
        type Output = Value<HASH_LENGTH>;
    }

    impl FindAllAssets {
        /// Construct [`FindAllAssets`].
        pub const fn new() -> Self {
            FindAllAssets
        }
    }

    impl FindAllAssetsDefinitions {
        /// Construct [`FindAllAssetsDefinitions`].
        pub const fn new() -> Self {
            FindAllAssetsDefinitions
        }
    }

    impl<const HASH_LENGTH: usize> FindAssetById<HASH_LENGTH> {
        /// Construct [`FindAssetById`].
        pub fn new(id: impl Into<EvaluatesTo<AssetId<HASH_LENGTH>, HASH_LENGTH>>) -> Self {
            let id = id.into();
            Self { id }
        }
    }

    impl<const HASH_LENGTH: usize> FindAssetDefinitionById<HASH_LENGTH> {
        /// Construct [`FindAssetDefinitionById`].
        pub fn new(
            id: impl Into<EvaluatesTo<AssetDefinitionId<HASH_LENGTH>, HASH_LENGTH>>,
        ) -> Self {
            let id = id.into();
            Self { id }
        }
    }

    impl<const HASH_LENGTH: usize> FindAssetsByName<HASH_LENGTH> {
        /// Construct [`FindAssetsByName`].
        pub fn new(name: impl Into<EvaluatesTo<Name, HASH_LENGTH>>) -> Self {
            let name = name.into();
            Self { name }
        }
    }

    impl<const HASH_LENGTH: usize> FindAssetsByAccountId<HASH_LENGTH> {
        /// Construct [`FindAssetsByAccountId`].
        pub fn new(
            account_id: impl Into<EvaluatesTo<AccountId<HASH_LENGTH>, HASH_LENGTH>>,
        ) -> Self {
            let account_id = account_id.into();
            FindAssetsByAccountId { account_id }
        }
    }

    impl<const HASH_LENGTH: usize> FindAssetsByAssetDefinitionId<HASH_LENGTH> {
        /// Construct [`FindAssetsByAssetDefinitionId`].
        pub fn new(
            asset_definition_id: impl Into<EvaluatesTo<AssetDefinitionId<HASH_LENGTH>, HASH_LENGTH>>,
        ) -> Self {
            let asset_definition_id = asset_definition_id.into();
            FindAssetsByAssetDefinitionId {
                asset_definition_id,
            }
        }
    }

    impl<const HASH_LENGTH: usize> FindAssetsByDomainId<HASH_LENGTH> {
        /// Construct [`FindAssetsByDomainId`].
        pub fn new(domain_id: impl Into<EvaluatesTo<DomainId, HASH_LENGTH>>) -> Self {
            let domain_id = domain_id.into();
            Self { domain_id }
        }
    }

    impl<const HASH_LENGTH: usize> FindAssetsByDomainIdAndAssetDefinitionId<HASH_LENGTH> {
        /// Construct [`FindAssetsByDomainIdAndAssetDefinitionId`].
        pub fn new(
            domain_id: impl Into<EvaluatesTo<DomainId, HASH_LENGTH>>,
            asset_definition_id: impl Into<EvaluatesTo<AssetDefinitionId<HASH_LENGTH>, HASH_LENGTH>>,
        ) -> Self {
            let domain_id = domain_id.into();
            let asset_definition_id = asset_definition_id.into();
            Self {
                domain_id,
                asset_definition_id,
            }
        }
    }

    impl<const HASH_LENGTH: usize> FindAssetQuantityById<HASH_LENGTH> {
        /// Construct [`FindAssetQuantityById`].
        pub fn new(id: impl Into<EvaluatesTo<AssetId<HASH_LENGTH>, HASH_LENGTH>>) -> Self {
            let id = id.into();
            FindAssetQuantityById { id }
        }
    }

    impl<const HASH_LENGTH: usize> FindAssetKeyValueByIdAndKey<HASH_LENGTH> {
        /// Construct [`FindAssetKeyValueByIdAndKey`].
        pub fn new(
            id: impl Into<EvaluatesTo<AssetId<HASH_LENGTH>, HASH_LENGTH>>,
            key: impl Into<EvaluatesTo<Name, HASH_LENGTH>>,
        ) -> Self {
            let id = id.into();
            let key = key.into();
            Self { id, key }
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{
            FindAllAssets, FindAllAssetsDefinitions, FindAssetById, FindAssetDefinitionById,
            FindAssetDefinitionKeyValueByIdAndKey, FindAssetKeyValueByIdAndKey,
            FindAssetQuantityById, FindAssetsByAccountId, FindAssetsByAssetDefinitionId,
            FindAssetsByDomainId, FindAssetsByDomainIdAndAssetDefinitionId, FindAssetsByName,
        };
    }
}

pub mod domain {
    //! Queries related to `Domain`.

    #![allow(clippy::missing_inline_in_public_items)]

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::prelude::*;

    /// `FindAllDomains` Iroha Query will find all `Domain`s presented in Iroha `Peer`.
    #[derive(
        Debug,
        Clone,
        Copy,
        Default,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct FindAllDomains;

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAllDomains {
        type Output = Vec<Domain<HASH_LENGTH>>;
    }

    /// `FindDomainById` Iroha Query will find a `Domain` by it's identification in Iroha `Peer`.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindDomainById<const HASH_LENGTH: usize> {
        /// `Id` of the domain to find.
        pub id: EvaluatesTo<DomainId, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindDomainById<HASH_LENGTH> {
        type Output = Domain<HASH_LENGTH>;
    }

    impl FindAllDomains {
        /// Construct [`FindAllDomains`].
        pub const fn new() -> Self {
            FindAllDomains
        }
    }

    impl<const HASH_LENGTH: usize> FindDomainById<HASH_LENGTH> {
        /// Construct [`FindDomainById`].
        pub fn new(id: impl Into<EvaluatesTo<DomainId, HASH_LENGTH>>) -> Self {
            let id = id.into();
            FindDomainById { id }
        }
    }

    /// `FindDomainKeyValueByIdAndKey` Iroha Query will find a [`Value`] of the key-value metadata pair
    /// in the specified domain.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindDomainKeyValueByIdAndKey<const HASH_LENGTH: usize> {
        /// `Id` of an domain to find.
        pub id: EvaluatesTo<DomainId, HASH_LENGTH>,
        /// Key of the specific key-value in the domain's metadata.
        pub key: EvaluatesTo<Name, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> FindDomainKeyValueByIdAndKey<HASH_LENGTH> {
        /// Construct [`FindDomainKeyValueByIdAndKey`].
        pub fn new(
            id: impl Into<EvaluatesTo<DomainId, HASH_LENGTH>>,
            key: impl Into<EvaluatesTo<Name, HASH_LENGTH>>,
        ) -> Self {
            let id = id.into();
            let key = key.into();
            FindDomainKeyValueByIdAndKey { id, key }
        }
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindDomainKeyValueByIdAndKey<HASH_LENGTH> {
        type Output = Value<HASH_LENGTH>;
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{FindAllDomains, FindDomainById, FindDomainKeyValueByIdAndKey};
    }
}

pub mod peer {
    //! Queries related to `Domain`.

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use super::Query;
    use crate::{peer::Peer, Parameter};

    /// `FindAllPeers` Iroha Query will find all trusted `Peer`s presented in current Iroha `Peer`.
    #[derive(
        Debug,
        Clone,
        Copy,
        Default,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct FindAllPeers;

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAllPeers {
        type Output = Vec<Peer>;
    }

    /// `FindAllParameters` Iroha Query will find all `Peer`s parameters.
    #[derive(
        Debug,
        Clone,
        Copy,
        Default,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct FindAllParameters;

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAllParameters {
        type Output = Vec<Parameter>;
    }

    impl FindAllPeers {
        ///Construct [`FindAllPeers`].
        pub const fn new() -> Self {
            FindAllPeers
        }
    }

    impl FindAllParameters {
        /// Construct [`FindAllParameters`].
        pub const fn new() -> Self {
            FindAllParameters
        }
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

    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use super::Query;
    use crate::{
        domain::prelude::*, events::FilterBox, expression::EvaluatesTo, trigger::Trigger,
        Identifiable, Name, Value,
    };

    /// Find all currently active (as in not disabled and/or expired)
    /// trigger IDs.
    #[derive(
        Debug,
        Clone,
        Copy,
        Default,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct FindAllActiveTriggerIds;

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAllActiveTriggerIds {
        type Output = Vec<<Trigger<FilterBox<HASH_LENGTH>, HASH_LENGTH> as Identifiable>::Id>;
    }

    /// Find Trigger given its ID.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindTriggerById<const HASH_LENGTH: usize> {
        /// The Identification of the trigger to be found.
        pub id: EvaluatesTo<<Trigger<FilterBox<HASH_LENGTH>, HASH_LENGTH> as Identifiable>::Id, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindTriggerById<HASH_LENGTH> {
        type Output = Trigger<FilterBox<HASH_LENGTH>, HASH_LENGTH>;
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    /// Find Trigger's metadata key-value pairs.
    pub struct FindTriggerKeyValueByIdAndKey<const HASH_LENGTH: usize> {
        /// The Identification of the trigger to be found.
        pub id: EvaluatesTo<<Trigger<FilterBox<HASH_LENGTH>, HASH_LENGTH> as Identifiable>::Id, HASH_LENGTH>,
        /// The key inside the metadata dictionary to be returned.
        pub key: EvaluatesTo<Name, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindTriggerKeyValueByIdAndKey<HASH_LENGTH> {
        type Output = Value<HASH_LENGTH>;
    }

    /// Find Triggers given domain ID.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindTriggersByDomainId<const HASH_LENGTH: usize> {
        /// `DomainId` under which triggers should be found.
        pub domain_id: EvaluatesTo<DomainId, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> FindTriggersByDomainId<HASH_LENGTH> {
        /// Construct [`FindTriggersByDomainId`].
        pub fn new(domain_id: impl Into<EvaluatesTo<DomainId, HASH_LENGTH>>) -> Self {
            Self {
                domain_id: domain_id.into(),
            }
        }
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindTriggersByDomainId<HASH_LENGTH> {
        type Output = Vec<Trigger<FilterBox<HASH_LENGTH>, HASH_LENGTH>>;
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
    //! Queries related to `Transaction`.

    #![allow(clippy::missing_inline_in_public_items)]

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use iroha_crypto::Hash;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use super::Query;
    use crate::{
        account::prelude::AccountId, expression::EvaluatesTo, transaction::TransactionValue,
    };

    #[derive(
        Default,
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    /// `FindAllTransactions` Iroha Query will list all transactions included in blockchain
    pub struct FindAllTransactions;

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAllTransactions {
        type Output = Vec<TransactionValue>;
    }

    impl FindAllTransactions {
        /// Construct [`FindAllTransactions`].
        pub fn new() -> Self {
            Self {}
        }
    }

    /// `FindTransactionsByAccountId` Iroha Query will find all transaction included in blockchain
    /// for the account
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindTransactionsByAccountId<const HASH_LENGTH: usize> {
        /// Signer's `AccountId` under which transactions should be found.
        pub account_id: EvaluatesTo<AccountId<HASH_LENGTH>, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindTransactionsByAccountId<HASH_LENGTH> {
        type Output = Vec<TransactionValue>;
    }

    impl<const HASH_LENGTH: usize> FindTransactionsByAccountId<HASH_LENGTH> {
        ///Construct [`FindTransactionsByAccountId`].
        pub fn new(account_id: impl Into<EvaluatesTo<AccountId<HASH_LENGTH>, HASH_LENGTH>>) -> Self {
            let account_id = account_id.into();
            FindTransactionsByAccountId { account_id }
        }
    }

    /// `FindTransactionByHash` Iroha Query will find a transaction (if any)
    /// with corresponding hash value
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct FindTransactionByHash<const HASH_LENGTH: usize> {
        /// Transaction hash.
        pub hash: EvaluatesTo<Hash<HASH_LENGTH>, HASH_LENGTH>,
    }

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindTransactionByHash<HASH_LENGTH> {
        type Output = TransactionValue;
    }

    impl<const HASH_LENGTH: usize> FindTransactionByHash<HASH_LENGTH> {
        ///Construct [`FindTransactionByHash`].
        pub fn new(hash: impl Into<EvaluatesTo<Hash<HASH_LENGTH>, HASH_LENGTH>>) -> Self {
            let hash = hash.into();
            FindTransactionByHash { hash }
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{FindAllTransactions, FindTransactionByHash, FindTransactionsByAccountId};
    }
}

pub mod block {
    //! Queries related to `Transaction`.

    #![allow(clippy::missing_inline_in_public_items)]

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use super::Query;
    use crate::block_value::BlockValue;

    #[derive(
        Default,
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    /// `FindAllBlocks` Iroha Query will list all blocks
    pub struct FindAllBlocks;

    impl<const HASH_LENGTH: usize> Query<HASH_LENGTH> for FindAllBlocks {
        type Output = Vec<BlockValue<HASH_LENGTH>>;
    }

    impl FindAllBlocks {
        /// Construct [`FindAllBlocks`].
        pub fn new() -> Self {
            Self {}
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::FindAllBlocks;
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{
        account::prelude::*, asset::prelude::*, block::prelude::*, domain::prelude::*,
        peer::prelude::*, permissions::prelude::*, role::prelude::*, transaction::*,
        trigger::prelude::*, PaginatedQueryResult, Query, QueryBox, QueryResult,
        VersionedPaginatedQueryResult, VersionedQueryResult,
    };
    #[cfg(feature = "warp")]
    pub use super::{QueryRequest, VersionedSignedQueryRequest};
}
