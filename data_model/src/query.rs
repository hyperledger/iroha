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
use crate::{
    account::Account, pagination::Pagination, predicate::PredicateBox, prelude::Sorting,
    Identifiable, Value,
};

/// Sized container for all possible Queries.
#[allow(clippy::enum_variant_names)]
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
    FromVariant,
    IntoSchema,
    PartialOrd,
    Ord,
    Hash,
)]
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
}

/// Trait for typesafe query output
pub trait Query {
    /// Output type of query
    type Output: Into<Value> + TryFrom<Value>;
}

impl Query for QueryBox {
    type Output = Value;
}

/// Payload of a query.
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct Payload {
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

impl Payload {
    /// Hash of this payload.
    #[cfg(feature = "std")]
    pub fn hash(&self) -> iroha_crypto::HashOf<Self> {
        iroha_crypto::HashOf::new(self)
    }
}

/// I/O ready structure to send queries.
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize)]
#[cfg(feature = "warp")]
pub struct QueryRequest {
    /// Payload
    pub payload: Payload,
}

#[cfg(feature = "warp")]
declare_versioned_with_scale!(VersionedSignedQueryRequest 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema);

/// I/O ready structure to send queries.
#[version_with_scale(n = 1, versioned = "VersionedSignedQueryRequest")]
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct SignedQueryRequest {
    /// Payload
    pub payload: Payload,
    /// Signature of the client who sends this query.
    pub signature: SignatureOf<Payload>,
}

declare_versioned_with_scale!(VersionedQueryResult 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema);

/// Sized container for all possible Query results.
#[version_with_scale(n = 1, versioned = "VersionedQueryResult")]
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct QueryResult(pub Value);

declare_versioned_with_scale!(VersionedPaginatedQueryResult 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema);

/// Paginated Query Result
#[version_with_scale(n = 1, versioned = "VersionedPaginatedQueryResult")]
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize, IntoSchema)]
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

#[cfg(all(feature = "std", feature = "warp"))]
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
        let signature = SignatureOf::new(key_pair, &self.payload)?;
        Ok(SignedQueryRequest {
            payload: self.payload,
            signature,
        })
    }
}

pub mod role {
    //! Queries related to [`Role`].

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::prelude::*;

    /// [`FindAllRoles`] Iroha Query finds all [`Role`]s presented.
    #[derive(
        Debug,
        Display,
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
        PartialOrd,
        Ord,
        Hash,
    )]
    #[display(fmt = "Find all roles")]
    pub struct FindAllRoles;

    impl Query for FindAllRoles {
        type Output = Vec<Role>;
    }

    /// [`FindAllRoleIds`] Iroha Query finds [`Id`](crate::role::Id)s of
    /// all [`Role`]s presented.
    #[derive(
        Debug,
        Display,
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
        PartialOrd,
        Ord,
        Hash,
    )]
    #[display(fmt = "Find all role ids")]
    pub struct FindAllRoleIds;

    impl Query for FindAllRoleIds {
        type Output = Vec<<Role as Identifiable>::Id>;
    }

    /// [`FindRoleByRoleId`] Iroha Query finds the [`Role`] which has the given [`Id`](crate::role::Id)
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
        Hash,
    )]
    #[display(fmt = "Find `{}` role", id)]
    pub struct FindRoleByRoleId {
        /// `Id` of the [`Role`] to find
        pub id: EvaluatesTo<<Role as Identifiable>::Id>,
    }

    impl Query for FindRoleByRoleId {
        type Output = Role;
    }

    /// [`FindRolesByAccountId`] Iroha Query finds all [`Role`]s for a specified account.
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
        Hash,
    )]
    #[display(fmt = "Find all roles for `{}` account", id)]
    pub struct FindRolesByAccountId {
        /// `Id` of an account to find.
        pub id: EvaluatesTo<<Account as Identifiable>::Id>,
    }

    impl Query for FindRolesByAccountId {
        type Output = Vec<<Role as Identifiable>::Id>;
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

    impl FindRoleByRoleId {
        /// Construct [`FindRoleByRoleId`].
        pub fn new(id: impl Into<EvaluatesTo<<Role as Identifiable>::Id>>) -> Self {
            let id = id.into();
            FindRoleByRoleId { id }
        }
    }

    impl FindRolesByAccountId {
        /// Construct [`FindRolesByAccountId`].
        pub fn new(account_id: impl Into<EvaluatesTo<<Account as Identifiable>::Id>>) -> Self {
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
    //! Queries related to [`PermissionToken`].

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::{permission, prelude::*};

    /// [`FindAllPermissionTokenDefinitions`] Iroha Query finds all registered
    /// [`PermissionTokenDefinition`][crate::permission::token::Definition]s
    #[derive(
        Debug,
        Display,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        PartialOrd,
        Ord,
        Hash,
    )]
    pub struct FindAllPermissionTokenDefinitions;

    impl Query for FindAllPermissionTokenDefinitions {
        type Output = Vec<PermissionTokenDefinition>;
    }

    /// [`FindPermissionTokensByAccountId`] Iroha Query finds all [`PermissionToken`]s
    /// for a specified account.
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
        Hash,
    )]
    #[display(fmt = "Find permission tokens specified for `{}` account", id)]
    pub struct FindPermissionTokensByAccountId {
        /// `Id` of an account to find.
        pub id: EvaluatesTo<AccountId>,
    }

    impl Query for FindPermissionTokensByAccountId {
        type Output = Vec<permission::Token>;
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this module.
    pub mod prelude {
        pub use super::{FindAllPermissionTokenDefinitions, FindPermissionTokensByAccountId};
    }
}

pub mod account {
    //! Queries related to [`Account`].

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::prelude::*;

    // TODO: Better to have find all account ids query instead.
    /// [`FindAllAccounts`] Iroha Query finds all [`Account`]s presented.
    #[derive(
        Debug,
        Display,
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
        PartialOrd,
        Ord,
        Hash,
    )]
    #[display(fmt = "Find all accounts")]
    pub struct FindAllAccounts;

    impl Query for FindAllAccounts {
        type Output = Vec<Account>;
    }

    /// [`FindAccountById`] Iroha Query finds an [`Account`] by it's identification.
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
        Hash,
    )]
    #[display(fmt = "Find `{}` account", id)]
    pub struct FindAccountById {
        /// `Id` of an account to find.
        pub id: EvaluatesTo<AccountId>,
    }

    impl Query for FindAccountById {
        type Output = Account;
    }

    /// [`FindAccountKeyValueByIdAndKey`] Iroha Query finds a [`Value`]
    /// of the key-value metadata pair in the specified account.
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
        Hash,
    )]
    #[display(fmt = "Find metadata value with `{}` key in `{}` account", key, id)]
    pub struct FindAccountKeyValueByIdAndKey {
        /// `Id` of an account to find.
        pub id: EvaluatesTo<AccountId>,
        /// Key of the specific key-value in the Account's metadata.
        pub key: EvaluatesTo<Name>,
    }

    impl Query for FindAccountKeyValueByIdAndKey {
        type Output = Value;
    }

    /// [`FindAccountsByName`] Iroha Query gets [`Account`]s name as input and
    /// finds all [`Account`]s with this name.
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
        Hash,
    )]
    #[display(fmt = "Find accounts with `{}` name", name)]
    pub struct FindAccountsByName {
        /// `name` of accounts to find.
        pub name: EvaluatesTo<Name>,
    }

    impl Query for FindAccountsByName {
        type Output = Vec<Account>;
    }

    /// [`FindAccountsByDomainId`] Iroha Query gets [`Domain`]s id as input and
    /// finds all [`Account`]s under this [`Domain`].
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
        Hash,
    )]
    #[display(fmt = "Find accounts under `{}` domain", domain_id)]
    pub struct FindAccountsByDomainId {
        /// `Id` of the domain under which accounts should be found.
        pub domain_id: EvaluatesTo<DomainId>,
    }

    impl Query for FindAccountsByDomainId {
        type Output = Vec<Account>;
    }

    /// [`FindAccountsWithAsset`] Iroha Query gets [`AssetDefinition`]s id as input and
    /// finds all [`Account`]s storing [`Asset`] with such definition.
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
        Hash,
    )]
    #[display(fmt = "Find accounts with `{}` asset", asset_definition_id)]
    pub struct FindAccountsWithAsset {
        /// `Id` of the definition of the asset which should be stored in founded accounts.
        pub asset_definition_id: EvaluatesTo<AssetDefinitionId>,
    }

    impl Query for FindAccountsWithAsset {
        type Output = Vec<Account>;
    }

    impl FindAllAccounts {
        /// Construct [`FindAllAccounts`].
        pub const fn new() -> Self {
            FindAllAccounts
        }
    }

    impl FindAccountById {
        /// Construct [`FindAccountById`].
        pub fn new(id: impl Into<EvaluatesTo<AccountId>>) -> Self {
            let id = id.into();
            FindAccountById { id }
        }
    }

    impl FindAccountKeyValueByIdAndKey {
        /// Construct [`FindAccountById`].
        pub fn new(
            id: impl Into<EvaluatesTo<AccountId>>,
            key: impl Into<EvaluatesTo<Name>>,
        ) -> Self {
            let id = id.into();
            let key = key.into();
            FindAccountKeyValueByIdAndKey { id, key }
        }
    }

    impl FindAccountsByName {
        /// Construct [`FindAccountsByName`].
        pub fn new(name: impl Into<EvaluatesTo<Name>>) -> Self {
            let name = name.into();
            FindAccountsByName { name }
        }
    }

    impl FindAccountsByDomainId {
        /// Construct [`FindAccountsByDomainId`].
        pub fn new(domain_id: impl Into<EvaluatesTo<DomainId>>) -> Self {
            let domain_id = domain_id.into();
            FindAccountsByDomainId { domain_id }
        }
    }

    impl FindAccountsWithAsset {
        /// Construct [`FindAccountsWithAsset`].
        pub fn new(asset_definition_id: impl Into<EvaluatesTo<AssetDefinitionId>>) -> Self {
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
    //! Queries related to [`Asset`].

    #![allow(clippy::missing_inline_in_public_items)]

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::prelude::*;

    /// [`FindAllAssets`] Iroha Query finds all [`Asset`]s presented in Iroha Peer.
    #[derive(
        Debug,
        Display,
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
        PartialOrd,
        Ord,
        Hash,
    )]
    #[display(fmt = "Find all assets")]
    pub struct FindAllAssets;

    impl Query for FindAllAssets {
        type Output = Vec<Asset>;
    }

    /// [`FindAllAssetsDefinitions`] Iroha Query finds all [`AssetDefinition`]s presented
    /// in Iroha Peer.
    #[derive(
        Debug,
        Display,
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
        PartialOrd,
        Ord,
        Hash,
    )]
    #[display(fmt = "Find all asset definitions")]
    pub struct FindAllAssetsDefinitions; // TODO: Should it be renamed to [`FindAllAssetDefinitions`?

    impl Query for FindAllAssetsDefinitions {
        type Output = Vec<AssetDefinition>;
    }

    /// [`FindAssetById`] Iroha Query finds an [`Asset`] by it's identification in Iroha [`Peer`].
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
        Hash,
    )]
    #[display(fmt = "Find `{}` asset", id)]
    pub struct FindAssetById {
        /// `Id` of an [`Asset`] to find.
        pub id: EvaluatesTo<AssetId>,
    }

    impl Query for FindAssetById {
        type Output = Asset;
    }

    /// [`FindAssetDefinitionById`] Iroha Query finds an [`AssetDefinition`] by it's identification in Iroha [`Peer`].
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
        Hash,
    )]
    #[display(fmt = "Find `{}` asset definition", id)]
    pub struct FindAssetDefinitionById {
        /// `Id` of an [`AssetDefinition`] to find.
        pub id: EvaluatesTo<AssetDefinitionId>,
    }

    impl Query for FindAssetDefinitionById {
        type Output = AssetDefinition;
    }

    /// [`FindAssetsByName`] Iroha Query gets [`Asset`]s name as input and
    /// finds all [`Asset`]s with it in Iroha [`Peer`].
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
        Hash,
    )]
    #[display(fmt = "Find asset with `{}` name", name)]
    pub struct FindAssetsByName {
        /// [`Name`] of [`Asset`]s to find.
        pub name: EvaluatesTo<Name>,
    }

    impl Query for FindAssetsByName {
        type Output = Vec<Asset>;
    }

    /// [`FindAssetsByAccountId`] Iroha Query gets [`AccountId`] as input and find all [`Asset`]s
    /// owned by the [`Account`] in Iroha Peer.
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
        Hash,
    )]
    #[display(fmt = "Find assets owned by the `{}` account", account_id)]
    pub struct FindAssetsByAccountId {
        /// [`AccountId`] under which assets should be found.
        pub account_id: EvaluatesTo<AccountId>,
    }

    impl Query for FindAssetsByAccountId {
        type Output = Vec<Asset>;
    }

    /// [`FindAssetsByAssetDefinitionId`] Iroha Query gets [`AssetDefinitionId`] as input and
    /// finds all [`Asset`]s with this [`AssetDefinition`] in Iroha Peer.
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
        Hash,
    )]
    #[display(fmt = "Find assets with `{}` asset definition", asset_definition_id)]
    pub struct FindAssetsByAssetDefinitionId {
        /// [`AssetDefinitionId`] with type of [`Asset`]s should be found.
        pub asset_definition_id: EvaluatesTo<AssetDefinitionId>,
    }

    impl Query for FindAssetsByAssetDefinitionId {
        type Output = Vec<Asset>;
    }

    /// [`FindAssetsByDomainId`] Iroha Query gets [`Domain`]s id as input and
    /// finds all [`Asset`]s under this [`Domain`] in Iroha [`Peer`].
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
        Hash,
    )]
    #[display(fmt = "Find assets under the `{}` domain", domain_id)]
    pub struct FindAssetsByDomainId {
        /// `Id` of the domain under which assets should be found.
        pub domain_id: EvaluatesTo<DomainId>,
    }

    impl Query for FindAssetsByDomainId {
        type Output = Vec<Asset>;
    }

    /// [`FindAssetsByDomainIdAndAssetDefinitionId`] Iroha Query gets [`DomainId`] and
    /// [`AssetDefinitionId`] as inputs and finds [`Asset`]s under the [`Domain`]
    /// with this [`AssetDefinition`] in Iroha [`Peer`].
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
        Hash,
    )]
    #[display(
        fmt = "Find assets under the `{}` domain with `{}` asset definition",
        domain_id,
        asset_definition_id
    )]
    pub struct FindAssetsByDomainIdAndAssetDefinitionId {
        /// `Id` of the domain under which assets should be found.
        pub domain_id: EvaluatesTo<DomainId>,
        /// [`AssetDefinitionId`] assets of which type should be found.
        pub asset_definition_id: EvaluatesTo<AssetDefinitionId>,
    }

    impl Query for FindAssetsByDomainIdAndAssetDefinitionId {
        type Output = Vec<Asset>;
    }

    /// [`FindAssetQuantityById`] Iroha Query gets [`AssetId`] as input and finds [`Asset::quantity`
    /// parameter's value if [`Asset`] is presented in Iroha Peer.
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
        Hash,
    )]
    #[display(fmt = "Find quantity of the `{}` asset", id)]
    pub struct FindAssetQuantityById {
        /// `Id` of an [`Asset`] to find quantity of.
        pub id: EvaluatesTo<AssetId>,
    }

    impl Query for FindAssetQuantityById {
        type Output = u32;
    }

    /// [`FindAssetKeyValueByIdAndKey`] Iroha Query gets [`AssetId`] and key as input and finds [`Value`]
    /// of the key-value pair stored in this asset.
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
        Hash,
    )]
    #[display(fmt = "Find metadata value with `{}` key in `{}` asset", key, id)]
    pub struct FindAssetKeyValueByIdAndKey {
        /// `Id` of an [`Asset`] acting as [`Store`](crate::asset::AssetValue::Store).
        pub id: EvaluatesTo<AssetId>,
        /// The key of the key-value pair stored in the asset.
        pub key: EvaluatesTo<Name>,
    }

    impl Query for FindAssetKeyValueByIdAndKey {
        type Output = Value;
    }

    /// [`FindAssetDefinitionKeyValueByIdAndKey`] Iroha Query gets [`AssetDefinitionId`] and key as input and finds [`Value`]
    /// of the key-value pair stored in this asset definition.
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
        Hash,
    )]
    #[display(
        fmt = "Find metadata value with `{}` key in `{}` asset definition",
        key,
        id
    )]
    pub struct FindAssetDefinitionKeyValueByIdAndKey {
        /// `Id` of an [`Asset`] acting as [`Store`](crate::asset::AssetValue::Store)..
        pub id: EvaluatesTo<AssetDefinitionId>,
        /// The key of the key-value pair stored in the asset.
        pub key: EvaluatesTo<Name>,
    }

    impl Query for FindAssetDefinitionKeyValueByIdAndKey {
        type Output = Value;
    }

    impl FindAllAssets {
        /// Construct [`FindAllAssets`].
        pub const fn new() -> Self {
            Self
        }
    }

    impl FindAllAssetsDefinitions {
        /// Construct [`FindAllAssetsDefinitions`].
        pub const fn new() -> Self {
            FindAllAssetsDefinitions
        }
    }

    impl FindAssetById {
        /// Construct [`FindAssetById`].
        pub fn new(id: impl Into<EvaluatesTo<AssetId>>) -> Self {
            let id = id.into();
            Self { id }
        }
    }

    impl FindAssetDefinitionById {
        /// Construct [`FindAssetDefinitionById`].
        pub fn new(id: impl Into<EvaluatesTo<AssetDefinitionId>>) -> Self {
            let id = id.into();
            Self { id }
        }
    }

    impl FindAssetsByName {
        /// Construct [`FindAssetsByName`].
        pub fn new(name: impl Into<EvaluatesTo<Name>>) -> Self {
            let name = name.into();
            Self { name }
        }
    }

    impl FindAssetsByAccountId {
        /// Construct [`FindAssetsByAccountId`].
        pub fn new(account_id: impl Into<EvaluatesTo<AccountId>>) -> Self {
            let account_id = account_id.into();
            FindAssetsByAccountId { account_id }
        }
    }

    impl FindAssetsByAssetDefinitionId {
        /// Construct [`FindAssetsByAssetDefinitionId`].
        pub fn new(asset_definition_id: impl Into<EvaluatesTo<AssetDefinitionId>>) -> Self {
            let asset_definition_id = asset_definition_id.into();
            FindAssetsByAssetDefinitionId {
                asset_definition_id,
            }
        }
    }

    impl FindAssetsByDomainId {
        /// Construct [`FindAssetsByDomainId`].
        pub fn new(domain_id: impl Into<EvaluatesTo<DomainId>>) -> Self {
            let domain_id = domain_id.into();
            Self { domain_id }
        }
    }

    impl FindAssetsByDomainIdAndAssetDefinitionId {
        /// Construct [`FindAssetsByDomainIdAndAssetDefinitionId`].
        pub fn new(
            domain_id: impl Into<EvaluatesTo<DomainId>>,
            asset_definition_id: impl Into<EvaluatesTo<AssetDefinitionId>>,
        ) -> Self {
            let domain_id = domain_id.into();
            let asset_definition_id = asset_definition_id.into();
            Self {
                domain_id,
                asset_definition_id,
            }
        }
    }

    impl FindAssetQuantityById {
        /// Construct [`FindAssetQuantityById`].
        pub fn new(id: impl Into<EvaluatesTo<AssetId>>) -> Self {
            let id = id.into();
            FindAssetQuantityById { id }
        }
    }

    impl FindAssetKeyValueByIdAndKey {
        /// Construct [`FindAssetKeyValueByIdAndKey`].
        pub fn new(id: impl Into<EvaluatesTo<AssetId>>, key: impl Into<EvaluatesTo<Name>>) -> Self {
            let id = id.into();
            let key = key.into();
            Self { id, key }
        }
    }

    impl FindAssetDefinitionKeyValueByIdAndKey {
        /// Construct [`FindAssetDefinitionKeyValueByIdAndKey`].
        pub fn new(
            id: impl Into<EvaluatesTo<AssetDefinitionId>>,
            key: impl Into<EvaluatesTo<Name>>,
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
    //! Queries related to [`Domain`].

    #![allow(clippy::missing_inline_in_public_items)]

    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};

    use derive_more::Display;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::prelude::*;

    /// [`FindAllDomains`] Iroha Query finds all [`Domain`]s presented in Iroha [`Peer`].
    #[derive(
        Debug,
        Display,
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
        PartialOrd,
        Ord,
        Hash,
    )]
    #[display(fmt = "Find all domains")]
    pub struct FindAllDomains;

    impl Query for FindAllDomains {
        type Output = Vec<Domain>;
    }

    /// [`FindDomainById`] Iroha Query finds a [`Domain`] by it's identification in Iroha [`Peer`].
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
        Hash,
    )]
    #[display(fmt = "Find `{}` domain", id)]
    pub struct FindDomainById {
        /// `Id` of the domain to find.
        pub id: EvaluatesTo<DomainId>,
    }

    impl Query for FindDomainById {
        type Output = Domain;
    }

    impl FindAllDomains {
        /// Construct [`FindAllDomains`].
        pub const fn new() -> Self {
            FindAllDomains
        }
    }

    impl FindDomainById {
        /// Construct [`FindDomainById`].
        pub fn new(id: impl Into<EvaluatesTo<DomainId>>) -> Self {
            let id = id.into();
            FindDomainById { id }
        }
    }

    /// [`FindDomainKeyValueByIdAndKey`] Iroha Query finds a [`Value`] of the key-value metadata pair
    /// in the specified domain.
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
        Hash,
    )]
    #[display(fmt = "Find metadata value with key `{}` in `{}` domain", key, id)]
    pub struct FindDomainKeyValueByIdAndKey {
        /// `Id` of an domain to find.
        pub id: EvaluatesTo<DomainId>,
        /// Key of the specific key-value in the domain's metadata.
        pub key: EvaluatesTo<Name>,
    }

    impl FindDomainKeyValueByIdAndKey {
        /// Construct [`FindDomainKeyValueByIdAndKey`].
        pub fn new(
            id: impl Into<EvaluatesTo<DomainId>>,
            key: impl Into<EvaluatesTo<Name>>,
        ) -> Self {
            let id = id.into();
            let key = key.into();
            FindDomainKeyValueByIdAndKey { id, key }
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
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use super::Query;
    use crate::{peer::Peer, Parameter};

    /// [`FindAllPeers`] Iroha Query finds all trusted [`Peer`]s presented in current Iroha [`Peer`].
    #[derive(
        Debug,
        Display,
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
        PartialOrd,
        Ord,
        Hash,
    )]
    #[display(fmt = "Find all peers")]
    pub struct FindAllPeers;

    impl Query for FindAllPeers {
        type Output = Vec<Peer>;
    }

    /// [`FindAllParameters`] Iroha Query finds all [`Peer`]s parameters.
    // TODO: Unused query. Remove?
    #[derive(
        Debug,
        Display,
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
        PartialOrd,
        Ord,
    )]
    #[display(fmt = "Find all peers parameters")]
    pub struct FindAllParameters;

    impl Query for FindAllParameters {
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

    use derive_more::Display;
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
        Display,
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
        PartialOrd,
        Ord,
        Hash,
    )]
    #[display(fmt = "Find all trigger ids")]
    pub struct FindAllActiveTriggerIds;

    impl Query for FindAllActiveTriggerIds {
        type Output = Vec<<Trigger<FilterBox> as Identifiable>::Id>;
    }

    /// Find Trigger given its ID.
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
        Hash,
    )]
    #[display(fmt = "Find `{}` trigger", id)]
    pub struct FindTriggerById {
        /// The Identification of the trigger to be found.
        pub id: EvaluatesTo<<Trigger<FilterBox> as Identifiable>::Id>,
    }

    impl Query for FindTriggerById {
        type Output = Trigger<FilterBox>;
    }

    /// Find Trigger's metadata key-value pairs.
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
        Hash,
    )]
    #[display(fmt = "Find metadata value with `{}` key in `{}` trigger", key, id)]
    pub struct FindTriggerKeyValueByIdAndKey {
        /// The Identification of the trigger to be found.
        pub id: EvaluatesTo<<Trigger<FilterBox> as Identifiable>::Id>,
        /// The key inside the metadata dictionary to be returned.
        pub key: EvaluatesTo<Name>,
    }

    impl Query for FindTriggerKeyValueByIdAndKey {
        type Output = Value;
    }

    /// Find [`Trigger`]s under the given [`DomainId`].
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
        Hash,
    )]
    #[display(fmt = "Find trigger under `{}` domain", domain_id)]
    pub struct FindTriggersByDomainId {
        /// [`DomainId`] specifies the domain in which to search for triggers.
        pub domain_id: EvaluatesTo<DomainId>,
    }

    impl FindTriggersByDomainId {
        /// Construct [`FindTriggersByDomainId`].
        pub fn new(domain_id: impl Into<EvaluatesTo<DomainId>>) -> Self {
            Self {
                domain_id: domain_id.into(),
            }
        }
    }

    impl Query for FindTriggersByDomainId {
        type Output = Vec<Trigger<FilterBox>>;
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
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use super::Query;
    use crate::{
        account::prelude::AccountId,
        expression::EvaluatesTo,
        transaction::{TransactionQueryResult, TransactionValue},
    };

    /// [`FindAllTransactions`] Iroha Query lists all transactions included in a blockchain
    #[derive(
        Default,
        Debug,
        Display,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        PartialOrd,
        Ord,
        Hash,
    )]
    #[display(fmt = "Find all transactions")]
    pub struct FindAllTransactions;

    impl Query for FindAllTransactions {
        type Output = Vec<TransactionQueryResult>;
    }

    impl FindAllTransactions {
        /// Construct [`FindAllTransactions`].
        pub fn new() -> Self {
            Self {}
        }
    }

    /// [`FindTransactionsByAccountId`] Iroha Query finds all transactions included in a blockchain
    /// for the account
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
        Hash,
    )]
    #[display(fmt = "Find all transactions for `{}` account", account_id)]
    pub struct FindTransactionsByAccountId {
        /// Signer's [`AccountId`] under which transactions should be found.
        pub account_id: EvaluatesTo<AccountId>,
    }

    impl Query for FindTransactionsByAccountId {
        type Output = Vec<TransactionValue>;
    }

    impl FindTransactionsByAccountId {
        ///Construct [`FindTransactionsByAccountId`].
        pub fn new(account_id: impl Into<EvaluatesTo<AccountId>>) -> Self {
            let account_id = account_id.into();
            FindTransactionsByAccountId { account_id }
        }
    }

    /// [`FindTransactionByHash`] Iroha Query finds a transaction (if any)
    /// with corresponding hash value
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
        Hash,
    )]
    #[display(fmt = "Find transaction with `{}` hash", hash)]
    pub struct FindTransactionByHash {
        /// Transaction hash.
        pub hash: EvaluatesTo<Hash>,
    }

    impl Query for FindTransactionByHash {
        type Output = TransactionValue;
    }

    impl FindTransactionByHash {
        ///Construct [`FindTransactionByHash`].
        pub fn new(hash: impl Into<EvaluatesTo<Hash>>) -> Self {
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
    //! Queries related to blocks.

    #![allow(clippy::missing_inline_in_public_items)]

    #[cfg(not(feature = "std"))]
    use alloc::{boxed::Box, format, string::String, vec::Vec};

    use derive_more::Display;
    use iroha_crypto::Hash;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use super::Query;
    use crate::{
        block_value::{BlockHeaderValue, BlockValue},
        prelude::EvaluatesTo,
    };

    /// [`FindAllBlocks`] Iroha Query lists all blocks sorted by
    /// height in descending order
    #[derive(
        Default,
        Debug,
        Display,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        PartialOrd,
        Ord,
        Hash,
    )]
    #[display(fmt = "Find all blocks")]
    pub struct FindAllBlocks;

    impl Query for FindAllBlocks {
        type Output = Vec<BlockValue>;
    }

    impl FindAllBlocks {
        /// Construct [`FindAllBlocks`].
        pub const fn new() -> Self {
            Self
        }
    }

    /// [`FindAllBlockHeaders`] Iroha Query lists all block headers
    /// sorted by height in descending order
    #[derive(
        Default,
        Debug,
        Display,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        PartialOrd,
        Ord,
        Hash,
    )]
    #[display(fmt = "Find all block headers")]
    pub struct FindAllBlockHeaders;

    impl Query for FindAllBlockHeaders {
        type Output = Vec<BlockHeaderValue>;
    }

    impl FindAllBlockHeaders {
        /// Construct [`FindAllBlockHeaders`].
        pub const fn new() -> Self {
            Self
        }
    }

    /// [`FindBlockHeaderByHash`] Iroha Query finds block header by block hash
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
        Hash,
    )]
    #[display(fmt = "Find block header with `{}` hash", hash)]
    pub struct FindBlockHeaderByHash {
        /// Block hash.
        pub hash: EvaluatesTo<Hash>,
    }

    impl Query for FindBlockHeaderByHash {
        type Output = BlockHeaderValue;
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
