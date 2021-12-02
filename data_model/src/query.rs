//! Iroha Queries provides declarative API for Iroha Queries.

#![allow(clippy::missing_inline_in_public_items)]

use eyre::Result;
use iroha_crypto::{prelude::*, SignatureOf};
use iroha_macro::{FromVariant, Io};
use iroha_schema::prelude::*;
use iroha_version::prelude::*;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
#[cfg(feature = "warp")]
use warp::{reply::Response, Reply};

#[cfg(feature = "roles")]
use self::role::*;
use self::{account::*, asset::*, domain::*, peer::*, permissions::*, transaction::*};
use crate::{account::Account, current_time, Identifiable, Value};

/// Sized container for all possible Queries.
#[allow(clippy::enum_variant_names)]
#[derive(
    Debug,
    Clone,
    Io,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    PartialEq,
    Eq,
    FromVariant,
    PartialOrd,
    Ord,
    IntoSchema,
)]
pub enum QueryBox {
    /// `FindAllAccounts` variant.
    FindAllAccounts(FindAllAccounts),
    /// `FindAccountById` variant.
    FindAccountById(FindAccountById),
    /// `FindAccountKeyValueByIdAndKey` variant.
    FindAccountKeyValueByIdAndKey(FindAccountKeyValueByIdAndKey),
    /// `FindAccountsByName` variant.
    FindAccountsByName(FindAccountsByName),
    /// `FindAccountsByDomainName` variant.
    FindAccountsByDomainName(FindAccountsByDomainName),
    /// `FindAllAssets` variant.
    FindAllAssets(FindAllAssets),
    /// `FindAllAssetsDefinitions` variant.
    FindAllAssetsDefinitions(FindAllAssetsDefinitions),
    /// `FindAssetById` variant.
    FindAssetById(FindAssetById),
    /// `FindAssetByName` variant.
    FindAssetsByName(FindAssetsByName),
    /// `FindAssetsByAccountId` variant.
    FindAssetsByAccountId(FindAssetsByAccountId),
    /// `FindAssetsByAssetDefinitionId` variant.
    FindAssetsByAssetDefinitionId(FindAssetsByAssetDefinitionId),
    /// `FindAssetsByDomainName` variant.
    FindAssetsByDomainName(FindAssetsByDomainName),
    /// `FindAssetsByDomainNameAndAssetDefinitionId` variant.
    FindAssetsByDomainNameAndAssetDefinitionId(FindAssetsByDomainNameAndAssetDefinitionId),
    /// `FindAssetQuantityById` variant.
    FindAssetQuantityById(FindAssetQuantityById),
    /// `FindAssetKeyValueByIdAndKey` variant.
    FindAssetKeyValueByIdAndKey(FindAssetKeyValueByIdAndKey),
    /// `FindAssetKeyValueByIdAndKey` variant.
    FindAssetDefinitionKeyValueByIdAndKey(FindAssetDefinitionKeyValueByIdAndKey),
    /// `FindAllDomains` variant.
    FindAllDomains(FindAllDomains),
    /// `FindDomainByName` variant.
    FindDomainByName(FindDomainByName),
    /// `FindDomainKeyValueByIdAndKey` variant.
    FindDomainKeyValueByIdAndKey(FindDomainKeyValueByIdAndKey),
    /// `FindAllPeers` variant.
    FindAllPeers(FindAllPeers),
    /// `FindTransactionsByAccountId` variant.
    FindTransactionsByAccountId(FindTransactionsByAccountId),
    /// `FindTransactionByHash` variant.
    FindTransactionByHash(FindTransactionByHash),
    /// `FindAllRoles` variant.
    #[cfg(feature = "roles")]
    FindAllRoles(FindAllRoles),
    /// `FindRolesByAccountId` variant.
    #[cfg(feature = "roles")]
    FindRolesByAccountId(FindRolesByAccountId),
    /// `FindPermissionTokensByAccountId` variant.
    FindPermissionTokensByAccountId(FindPermissionTokensByAccountId),
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
#[derive(Debug, Io, Decode, Encode, Deserialize, Serialize, Clone, IntoSchema)]
pub struct Payload {
    /// Timestamp of the query creation.
    #[codec(compact)]
    pub timestamp_ms: u128,
    /// Query definition.
    pub query: QueryBox,
    /// Account id of the user who will sign this query.
    pub account_id: <Account as Identifiable>::Id,
}

impl Payload {
    /// Hash of this payload.
    pub fn hash(&self) -> Hash {
        let payload: Vec<u8> = self.clone().into();
        Hash::new(&payload)
    }
}

/// I/O ready structure to send queries.
#[derive(Debug, Io, Decode, Encode, Deserialize, Serialize, Clone)]
pub struct QueryRequest {
    /// Payload
    pub payload: Payload,
}

declare_versioned_with_scale!(VersionedSignedQueryRequest 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema);

/// I/O ready structure to send queries.
#[version_with_scale(n = 1, versioned = "VersionedSignedQueryRequest")]
#[derive(Debug, Clone, Io, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct SignedQueryRequest {
    /// Payload
    pub payload: Payload,
    /// Signature of the client who sends this query.
    pub signature: SignatureOf<Payload>,
}

declare_versioned_with_scale!(VersionedQueryResult 1..2, Debug, Clone, iroha_macro::FromVariant, Io, IntoSchema);

/// Sized container for all possible Query results.
#[version_with_scale(n = 1, versioned = "VersionedQueryResult")]
#[derive(Debug, Clone, Io, Serialize, Deserialize, Encode, Decode, IntoSchema)]
pub struct QueryResult(pub Value);

#[cfg(feature = "warp")]
impl Reply for &QueryResult {
    fn into_response(self) -> Response {
        Response::new(Vec::from(self).into())
    }
}

#[cfg(feature = "warp")]
impl Reply for QueryResult {
    fn into_response(self) -> Response {
        (&self).into_response()
    }
}

impl QueryRequest {
    /// Constructs a new request with the `query`.
    #[allow(clippy::expect_used)]
    pub fn new(query: QueryBox, account_id: <Account as Identifiable>::Id) -> Self {
        let timestamp_ms = current_time().as_millis();
        QueryRequest {
            payload: Payload {
                timestamp_ms,
                query,
                account_id,
            },
        }
    }

    /// Consumes self and returns a signed `QueryReuest`.
    ///
    /// # Errors
    /// Fails if signature creation fails.
    pub fn sign(self, key_pair: KeyPair) -> Result<SignedQueryRequest> {
        let signature = SignatureOf::new(key_pair, &self.payload)?;
        Ok(SignedQueryRequest {
            payload: self.payload,
            signature,
        })
    }
}

#[cfg(feature = "roles")]
pub mod role {
    //! Queries related to `Role`.

    use iroha_macro::Io;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::prelude::*;

    /// `FindAllRoles` Iroha Query will find all `Roles`s presented.
    #[derive(
        Default,
        Copy,
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindAllRoles {}

    impl Query for FindAllRoles {
        type Output = Vec<Role>;
    }

    /// `FindRolesByAccountId` Iroha Query will find an `Role`s for a specified account.
    #[derive(
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindRolesByAccountId {
        /// `Id` of an account to find.
        pub id: EvaluatesTo<AccountId>,
    }

    impl Query for FindRolesByAccountId {
        type Output = Vec<RoleId>;
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this module.
    pub mod prelude {
        pub use super::{FindAllRoles, FindRolesByAccountId};
    }
}

pub mod permissions {
    //! Queries related to `PermissionToken`.

    use iroha_macro::Io;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::prelude::*;

    /// `FindPermissionTokensByAccountId` Iroha Query will find an `Role`s for a specified account.
    #[derive(
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindPermissionTokensByAccountId {
        /// `Id` of an account to find.
        pub id: EvaluatesTo<AccountId>,
    }

    impl Query for FindPermissionTokensByAccountId {
        type Output = Vec<PermissionToken>;
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this module.
    pub mod prelude {
        pub use super::FindPermissionTokensByAccountId;
    }
}

pub mod account {
    //! Queries related to `Account`.

    use iroha_macro::Io;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::prelude::*;

    // TODO: Better to have find all account ids query instead.
    /// `FindAllAccounts` Iroha Query will find all `Account`s presented.
    #[derive(
        Default,
        Copy,
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindAllAccounts {}

    impl Query for FindAllAccounts {
        type Output = Vec<Account>;
    }

    /// `FindAccountById` Iroha Query will find an `Account` by it's identification.
    #[derive(
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindAccountById {
        /// `Id` of an account to find.
        pub id: EvaluatesTo<AccountId>,
    }

    impl Query for FindAccountById {
        type Output = Account;
    }

    /// `FindAccountById` Iroha Query will find a [`Value`] of the key-value metadata pair
    /// in the specified account.
    #[derive(
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindAccountKeyValueByIdAndKey {
        /// `Id` of an account to find.
        pub id: EvaluatesTo<AccountId>,
        /// Key of the specific key-value in the Account's metadata.
        pub key: EvaluatesTo<Name>,
    }

    impl Query for FindAccountKeyValueByIdAndKey {
        type Output = Value;
    }

    /// `FindAccountsByName` Iroha Query will get `Account`s name as input and
    /// find all `Account`s with this name.
    #[derive(
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindAccountsByName {
        /// `name` of accounts to find.
        pub name: EvaluatesTo<Name>,
    }

    impl Query for FindAccountsByName {
        type Output = Vec<Account>;
    }

    /// `FindAccountsByDomainName` Iroha Query will get `Domain`s name as input and
    /// find all `Account`s under this `Domain`.
    #[derive(
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindAccountsByDomainName {
        /// `domain_name` under which accounts should be found.
        pub domain_name: EvaluatesTo<Name>,
    }

    impl Query for FindAccountsByDomainName {
        type Output = Vec<Account>;
    }

    impl FindAllAccounts {
        /// Default `FindAllAccounts` constructor.
        pub const fn new() -> Self {
            FindAllAccounts {}
        }
    }

    impl FindAccountById {
        /// Default `FindAccountById` constructor.
        pub fn new(id: impl Into<EvaluatesTo<AccountId>>) -> Self {
            let id = id.into();
            FindAccountById { id }
        }
    }

    impl FindAccountKeyValueByIdAndKey {
        /// Default `FindAccountById` constructor.
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
        /// Default `FindAccountsByName` constructor.
        pub fn new(name: impl Into<EvaluatesTo<Name>>) -> Self {
            let name = name.into();
            FindAccountsByName { name }
        }
    }

    impl FindAccountsByDomainName {
        /// Default `FindAccountsByDomainName` constructor.
        pub fn new(domain_name: impl Into<EvaluatesTo<Name>>) -> Self {
            let domain_name = domain_name.into();
            FindAccountsByDomainName { domain_name }
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{
            FindAccountById, FindAccountKeyValueByIdAndKey, FindAccountsByDomainName,
            FindAccountsByName, FindAllAccounts,
        };
    }
}

pub mod asset {
    //! Queries related to `Asset`.

    #![allow(clippy::missing_inline_in_public_items)]

    use iroha_macro::Io;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::prelude::*;

    /// `FindAllAssets` Iroha Query will find all `Asset`s presented in Iroha Peer.
    #[derive(
        Copy,
        Clone,
        Debug,
        Default,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindAllAssets {}

    impl Query for FindAllAssets {
        type Output = Vec<Asset>;
    }

    /// `FindAllAssetsDefinitions` Iroha Query will find all `AssetDefinition`s presented
    /// in Iroha Peer.
    #[derive(
        Copy,
        Clone,
        Debug,
        Default,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindAllAssetsDefinitions {}

    impl Query for FindAllAssetsDefinitions {
        type Output = Vec<AssetDefinition>;
    }

    /// `FindAssetById` Iroha Query will find an `Asset` by it's identification in Iroha `Peer`.
    #[derive(
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindAssetById {
        /// `Id` of an `Asset` to find.
        pub id: EvaluatesTo<AssetId>,
    }

    impl Query for FindAssetById {
        type Output = Asset;
    }

    /// `FindAssetsByName` Iroha Query will get `Asset`s name as input and
    /// find all `Asset`s with it in Iroha `Peer`.
    #[derive(
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindAssetsByName {
        /// `Name` of `Asset`s to find.
        pub name: EvaluatesTo<Name>,
    }

    impl Query for FindAssetsByName {
        type Output = Vec<Asset>;
    }

    /// `FindAssetsByAccountId` Iroha Query will get `AccountId` as input and find all `Asset`s
    /// owned by the `Account` in Iroha Peer.
    #[derive(
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindAssetsByAccountId {
        /// `AccountId` under which assets should be found.
        pub account_id: EvaluatesTo<AccountId>,
    }

    impl Query for FindAssetsByAccountId {
        type Output = Vec<Asset>;
    }

    /// `FindAssetsByAssetDefinitionId` Iroha Query will get `AssetDefinitionId` as input and
    /// find all `Asset`s with this `AssetDefinition` in Iroha Peer.
    #[derive(
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindAssetsByAssetDefinitionId {
        /// `AssetDefinitionId` with type of `Asset`s should be found.
        pub asset_definition_id: EvaluatesTo<AssetDefinitionId>,
    }

    impl Query for FindAssetsByAssetDefinitionId {
        type Output = Vec<Asset>;
    }

    /// `FindAssetsByDomainName` Iroha Query will get `Domain`s name as input and
    /// find all `Asset`s under this `Domain` in Iroha `Peer`.
    #[derive(
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindAssetsByDomainName {
        /// `Name` of the domain under which assets should be found.
        pub domain_name: EvaluatesTo<Name>,
    }

    impl Query for FindAssetsByDomainName {
        type Output = Vec<Asset>;
    }

    /// `FindAssetsByDomainNameAndAssetDefinitionId` Iroha Query will get `Domain`'s name and
    /// `AssetDefinitionId` as inputs and find all `Asset`s under the `Domain`
    /// with this `AssetDefinition` in Iroha `Peer`.
    #[derive(
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindAssetsByDomainNameAndAssetDefinitionId {
        /// `Name` of the domain under which assets should be found.
        pub domain_name: EvaluatesTo<Name>,
        /// `AssetDefinitionId` assets of which type should be found.
        pub asset_definition_id: EvaluatesTo<AssetDefinitionId>,
    }

    impl Query for FindAssetsByDomainNameAndAssetDefinitionId {
        type Output = Vec<Asset>;
    }

    /// `FindAssetQuantityById` Iroha Query will get `AssetId` as input and find `Asset::quantity`
    /// parameter's value if `Asset` is presented in Iroha Peer.
    #[derive(
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindAssetQuantityById {
        /// `Id` of an `Asset` to find quantity of.
        pub id: EvaluatesTo<AssetId>,
    }

    impl Query for FindAssetQuantityById {
        type Output = u32;
    }

    /// `FindAssetKeyValueByIdAndKey` Iroha Query will get `AssetId` and key as input and find [`Value`]
    /// of the key-value pair stored in this asset.
    #[derive(
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindAssetKeyValueByIdAndKey {
        /// `Id` of an `Asset` acting as `Store`.
        pub id: EvaluatesTo<AssetId>,
        /// The key of the key-value pair stored in the asset.
        pub key: EvaluatesTo<Name>,
    }

    impl Query for FindAssetKeyValueByIdAndKey {
        type Output = Value;
    }

    /// `FindAssetDefinitionKeyValueByIdAndKey` Iroha Query will get `AssetDefinitionId` and key as input and find [`Value`]
    /// of the key-value pair stored in this asset definition.
    #[derive(
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindAssetDefinitionKeyValueByIdAndKey {
        /// `Id` of an `Asset` acting as `Store`.
        pub id: EvaluatesTo<AssetDefinitionId>,
        /// The key of the key-value pair stored in the asset.
        pub key: EvaluatesTo<Name>,
    }

    impl Query for FindAssetDefinitionKeyValueByIdAndKey {
        type Output = Value;
    }

    impl FindAllAssets {
        /// Default `FindAllAssets` constructor.
        pub const fn new() -> Self {
            FindAllAssets {}
        }
    }

    impl FindAllAssetsDefinitions {
        /// Default `FindAllAssetsDefinitions` constructor.
        pub const fn new() -> Self {
            FindAllAssetsDefinitions {}
        }
    }

    impl FindAssetById {
        /// Default `FindAssetById` constructor
        pub fn new(id: impl Into<EvaluatesTo<AssetId>>) -> Self {
            let id = id.into();
            Self { id }
        }
    }

    impl FindAssetsByName {
        /// Default `FindAssetsByName` constructor
        pub fn new(name: impl Into<EvaluatesTo<Name>>) -> Self {
            let name = name.into();
            Self { name }
        }
    }

    impl FindAssetsByAccountId {
        /// Default `FindAssetsByAccountId` constructor.
        pub fn new(account_id: impl Into<EvaluatesTo<AccountId>>) -> Self {
            let account_id = account_id.into();
            FindAssetsByAccountId { account_id }
        }
    }

    impl FindAssetsByAssetDefinitionId {
        /// Default `FindAssetsByAssetDefinitionId` constructor.
        pub fn new(asset_definition_id: impl Into<EvaluatesTo<AssetDefinitionId>>) -> Self {
            let asset_definition_id = asset_definition_id.into();
            FindAssetsByAssetDefinitionId {
                asset_definition_id,
            }
        }
    }

    impl FindAssetsByDomainName {
        /// Default `FindAssetsByDomainName` constructor
        pub fn new(domain_name: impl Into<EvaluatesTo<Name>>) -> Self {
            let domain_name = domain_name.into();
            Self { domain_name }
        }
    }

    impl FindAssetsByDomainNameAndAssetDefinitionId {
        /// Default `FindAssetsByDomainNameAndAssetDefinitionId` constructor
        pub fn new(
            domain_name: impl Into<EvaluatesTo<Name>>,
            asset_definition_id: impl Into<EvaluatesTo<AssetDefinitionId>>,
        ) -> Self {
            let domain_name = domain_name.into();
            let asset_definition_id = asset_definition_id.into();
            Self {
                domain_name,
                asset_definition_id,
            }
        }
    }

    impl FindAssetQuantityById {
        /// Default `FindAssetQuantityById` constructor.
        pub fn new(id: impl Into<EvaluatesTo<AssetId>>) -> Self {
            let id = id.into();
            FindAssetQuantityById { id }
        }
    }

    impl FindAssetKeyValueByIdAndKey {
        /// Default [`FindAssetKeyValueByIdAndKey`] constructor.
        pub fn new(id: impl Into<EvaluatesTo<AssetId>>, key: impl Into<EvaluatesTo<Name>>) -> Self {
            let id = id.into();
            let key = key.into();
            Self { id, key }
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{
            FindAllAssets, FindAllAssetsDefinitions, FindAssetById,
            FindAssetDefinitionKeyValueByIdAndKey, FindAssetKeyValueByIdAndKey,
            FindAssetQuantityById, FindAssetsByAccountId, FindAssetsByAssetDefinitionId,
            FindAssetsByDomainName, FindAssetsByDomainNameAndAssetDefinitionId, FindAssetsByName,
        };
    }
}

pub mod domain {
    //! Queries related to `Domain`.

    #![allow(clippy::missing_inline_in_public_items)]

    use iroha_macro::Io;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::prelude::*;

    /// `FindAllDomains` Iroha Query will find all `Domain`s presented in Iroha `Peer`.
    #[derive(
        Copy,
        Clone,
        Debug,
        Default,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindAllDomains {}

    impl Query for FindAllDomains {
        type Output = Vec<Domain>;
    }

    /// `FindDomainByName` Iroha Query will find a `Domain` by it's identification in Iroha `Peer`.
    #[derive(
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindDomainByName {
        /// Name of the domain to find.
        pub name: EvaluatesTo<Name>,
    }

    impl Query for FindDomainByName {
        type Output = Domain;
    }

    impl FindAllDomains {
        /// Default `FindAllDomains` constructor.
        pub const fn new() -> Self {
            FindAllDomains {}
        }
    }

    impl FindDomainByName {
        /// Default `FindDomainByName` constructor.
        pub fn new(name: impl Into<EvaluatesTo<Name>>) -> Self {
            let name = name.into();
            FindDomainByName { name }
        }
    }

    /// `FindDomainKeyValueByIdAndKey` Iroha Query will find a [`Value`] of the key-value metadata pair
    /// in the specified domain.
    #[derive(
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindDomainKeyValueByIdAndKey {
        /// `Name` of an domain to find.
        pub name: EvaluatesTo<Name>,
        /// Key of the specific key-value in the domain's metadata.
        pub key: EvaluatesTo<Name>,
    }

    impl FindDomainKeyValueByIdAndKey {
        /// Default `FindDomainKeyValueByIdAndKey` constructor.
        pub fn new(name: impl Into<EvaluatesTo<Name>>, key: impl Into<EvaluatesTo<Name>>) -> Self {
            let name = name.into();
            let key = key.into();
            FindDomainKeyValueByIdAndKey { name, key }
        }
    }

    impl Query for FindDomainKeyValueByIdAndKey {
        type Output = Value;
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{FindAllDomains, FindDomainByName, FindDomainKeyValueByIdAndKey};
    }
}

pub mod peer {
    //! Queries related to `Domain`.

    use iroha_macro::Io;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use super::Query;
    use crate::{peer::Peer, Parameter};

    /// `FindAllPeers` Iroha Query will find all trusted `Peer`s presented in current Iroha `Peer`.
    #[derive(
        Copy,
        Clone,
        Debug,
        Default,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindAllPeers {}

    impl Query for FindAllPeers {
        type Output = Vec<Peer>;
    }

    /// `FindAllParameters` Iroha Query will find all `Peer`s parameters.
    #[derive(
        Copy,
        Clone,
        Debug,
        Default,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindAllParameters {}

    impl Query for FindAllParameters {
        type Output = Vec<Parameter>;
    }

    impl FindAllPeers {
        ///Default `FindAllPeers` constructor.
        pub const fn new() -> Self {
            FindAllPeers {}
        }
    }

    impl FindAllParameters {
        /// Default `FindAllParameters` constructor.
        pub const fn new() -> Self {
            FindAllParameters {}
        }
    }
    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{FindAllParameters, FindAllPeers};
    }
}

pub mod transaction {
    //! Queries related to `Transaction`.

    #![allow(clippy::missing_inline_in_public_items)]

    use iroha_crypto::Hash;
    use iroha_macro::Io;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use super::Query;
    use crate::{
        account::prelude::AccountId, expression::EvaluatesTo, transaction::TransactionValue,
    };

    /// `FindTransactionsByAccountId` Iroha Query will find all transaction included in blockchain
    /// for the account
    #[derive(
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindTransactionsByAccountId {
        /// Signer's `AccountId` under which transactions should be found.
        pub account_id: EvaluatesTo<AccountId>,
    }

    impl Query for FindTransactionsByAccountId {
        type Output = Vec<TransactionValue>;
    }

    impl FindTransactionsByAccountId {
        ///Default [`FindTransactionsByAccountId`] constructor.
        pub fn new(account_id: impl Into<EvaluatesTo<AccountId>>) -> Self {
            let account_id = account_id.into();
            FindTransactionsByAccountId { account_id }
        }
    }

    /// `FindTransactionByHash` Iroha Query will find a transaction (if any)
    /// with corresponding hash value
    #[derive(
        Clone,
        Debug,
        Io,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct FindTransactionByHash {
        /// Transaction hash.
        pub hash: EvaluatesTo<Hash>,
    }

    impl Query for FindTransactionByHash {
        type Output = TransactionValue;
    }

    impl FindTransactionByHash {
        ///Default [`FindTransactionByHash`] constructor.
        pub fn new(hash: impl Into<EvaluatesTo<Hash>>) -> Self {
            let hash = hash.into();
            FindTransactionByHash { hash }
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{FindTransactionByHash, FindTransactionsByAccountId};
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    #[cfg(feature = "roles")]
    pub use super::role::prelude::*;
    pub use super::{
        account::prelude::*, asset::prelude::*, domain::prelude::*, peer::prelude::*,
        permissions::prelude::*, transaction::*, Query, QueryBox, QueryRequest, QueryResult,
        SignedQueryRequest, VersionedQueryResult, VersionedSignedQueryRequest,
    };
}
