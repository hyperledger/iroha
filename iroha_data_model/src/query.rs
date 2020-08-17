//! Iroha Queries provides declarative API for Iroha Queries.

#![warn(
    anonymous_parameters,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    private_doc_tests,
    trivial_casts,
    trivial_numeric_casts,
    unused,
    future_incompatible,
    nonstandard_style,
    unsafe_code,
    unused_import_braces,
    unused_results,
    variant_size_differences
)]

use self::{account::*, asset::*, domain::*, peer::*};
use crate::ValueBox;
use iroha_crypto::prelude::*;
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Sized container for all possible Queries.
#[derive(Debug, Clone, Io, Serialize, Deserialize, Encode, Decode)]
pub enum QueryBox {
    /// `FindAllAccounts` variant.
    FindAllAccounts(Box<FindAllAccounts>),
    /// `FindAccountById` variant.
    FindAccountById(Box<FindAccountById>),
    /// `FindAccountsByName` variant.
    FindAccountsByName(Box<FindAccountsByName>),
    /// `FindAccountsByDomainName` variant.
    FindAccountsByDomainName(Box<FindAccountsByDomainName>),
    /// `FindAllAssets` variant.
    FindAllAssets(Box<FindAllAssets>),
    /// `FindAllAssetsDefinitions` variant.
    FindAllAssetsDefinitions(Box<FindAllAssetsDefinitions>),
    /// `FindAssetById` variant.
    FindAssetById(Box<FindAssetById>),
    /// `FindAssetByName` variant.
    FindAssetsByName(Box<FindAssetsByName>),
    /// `FindAssetsByAccountId` variant.
    FindAssetsByAccountId(Box<FindAssetsByAccountId>),
    /// `FindAssetsByAssetDefinitionId` variant.
    FindAssetsByAssetDefinitionId(Box<FindAssetsByAssetDefinitionId>),
    /// `FindAssetsByDomainName` variant.
    FindAssetsByDomainName(Box<FindAssetsByDomainName>),
    /// `FindAssetsByAccountIdAndAssetDefinitionId` variant.
    FindAssetsByAccountIdAndAssetDefinitionId(Box<FindAssetsByAccountIdAndAssetDefinitionId>),
    /// `FindAssetsByDomainNameAndAssetDefinitionId` variant.
    FindAssetsByDomainNameAndAssetDefinitionId(Box<FindAssetsByDomainNameAndAssetDefinitionId>),
    /// `FindAssetQuantityById` variant.
    FindAssetQuantityById(Box<FindAssetQuantityById>),
    /// `FindAllDomains` variant.
    FindAllDomains(Box<FindAllDomains>),
    /// `FindDomainByName` variant.
    FindDomainByName(Box<FindDomainByName>),
    /// `FindAllPeers` variant.
    FindAllPeers(Box<FindAllPeers>),
    /// `FindPeerById` variant.
    FindPeerById(Box<FindPeerById>),
}

/// I/O ready structure to send queries.
#[derive(Debug, Io, Encode, Decode, Clone)]
pub struct QueryRequest {
    //TODO: why use `String` for timestamp? maybe replace it with milliseconds in `u64`
    /// Timestamp of the query creation.
    pub timestamp: String,
    /// Query definition.
    pub query: QueryBox,
}

/// I/O ready structure to send queries.
#[derive(Debug, Io, Encode, Decode)]
pub struct SignedQueryRequest {
    /// Timestamp of the query creation.
    pub timestamp: String,
    /// Signature of the client who sends this query.
    pub signature: Signature,
    /// Query definition.
    pub query: QueryBox,
}

/// Sized container for all possible Query results.
#[derive(Debug, Clone, Io, Serialize, Deserialize, Encode, Decode)]
pub enum QueryResult {
    /// `FindAllAccounts` variant.
    FindAllAccounts(Box<FindAllAccountsResult>),
    /// `FindAccountById` variant.
    FindAccountById(Box<FindAccountByIdResult>),
    /// `FindAccountsByName` variant.
    FindAccountsByName(Box<FindAccountsByNameResult>),
    /// `FindAccountsByDomainName` variant.
    FindAccountsByDomainName(Box<FindAccountsByDomainNameResult>),
    /// `FindAllAssets` variant.
    FindAllAssets(Box<FindAllAssetsResult>),
    /// `FindAllAssetsDefinitions` variant.
    FindAllAssetsDefinitions(Box<FindAllAssetsDefinitionsResult>),
    /// `FindAssetById` variant.
    FindAssetById(Box<FindAssetByIdResult>),
    /// `FindAssetByName` variant.
    FindAssetsByName(Box<FindAssetsByNameResult>),
    /// `FindAssetsByAccountId` variant.
    FindAssetsByAccountId(Box<FindAssetsByAccountIdResult>),
    /// `FindAssetsByAssetDefinitionId` variant.
    FindAssetsByAssetDefinitionId(Box<FindAssetsByAssetDefinitionIdResult>),
    /// `FindAssetsByDomainName` variant.
    FindAssetsByDomainName(Box<FindAssetsByDomainNameResult>),
    /// `FindAssetsByAccountIdAndAssetDefinitionId` variant.
    FindAssetsByAccountIdAndAssetDefinitionId(Box<FindAssetsByAccountIdAndAssetDefinitionIdResult>),
    /// `FindAssetsByDomainNameAndAssetDefinitionId` variant.
    FindAssetsByDomainNameAndAssetDefinitionId(
        Box<FindAssetsByDomainNameAndAssetDefinitionIdResult>,
    ),
    /// `FindAssetQuantityById` variant.
    FindAssetQuantityById(Box<FindAssetQuantityByIdResult>),
    /// `FindAllDomains` variant.
    FindAllDomains(Box<FindAllDomainsResult>),
    /// `FindDomainByName` variant.
    FindDomainByName(Box<FindDomainByNameResult>),
    /// `FindAllPeers` variant.
    FindAllPeers(Box<FindAllPeersResult>),
    /// `FindPeerById` variant.
    FindPeerById(Box<FindPeerByIdResult>),
}

impl QueryRequest {
    /// Constructs a new request with the `query`.
    pub fn new(query: QueryBox) -> Self {
        QueryRequest {
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to get System Time.")
                .as_millis()
                .to_string(),
            query,
        }
    }

    /// `Hash` of this request.
    pub fn hash(&self) -> Hash {
        let mut payload: Vec<u8> = self.query.clone().into();
        payload.extend_from_slice(self.timestamp.as_bytes());
        iroha_crypto::hash(payload)
    }

    /// Consumes self and returns a signed `QueryReuest`.
    pub fn sign(self, key_pair: &KeyPair) -> Result<SignedQueryRequest, String> {
        Ok(SignedQueryRequest {
            timestamp: self.timestamp.clone(),
            signature: Signature::new(key_pair.clone(), &self.hash())?,
            query: self.query,
        })
    }
}

impl SignedQueryRequest {
    /// `Hash` of this request.
    pub fn hash(&self) -> Hash {
        let mut payload: Vec<u8> = self.query.clone().into();
        payload.extend_from_slice(self.timestamp.as_bytes());
        iroha_crypto::hash(payload)
    }
}

impl<I: Into<QueryBox>> From<I> for ValueBox {
    fn from(query_box: I) -> ValueBox {
        ValueBox::Query(Box::new(query_box.into()))
    }
}

pub mod account {
    //! Queries related to `Account`.
    use crate::prelude::*;
    use iroha_derive::Io;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    /// `FindAllAccounts` Iroha Query will find all `Account`s presented in Iroha `Peer`.
    #[derive(Default, Copy, Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAllAccounts {}

    /// Result of the `FindAllAccounts` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAllAccountsResult {
        /// Accounts information.
        pub accounts: Vec<Account>,
    }

    /// `FindAccountById` Iroha Query will find an `Account` by it's identification in Iroha `Peer`.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAccountById {
        /// `Id` of an account to find.
        pub id: AccountId,
    }

    /// Result of the `FindAccountById` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAccountByIdResult {
        /// Account information.
        pub account: Account,
    }

    /// `FindAccountsByName` Iroha Query will get `Account`s name as input and
    /// find all `Account`s with this name in Iroha `Peer`.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAccountsByName {
        /// `name` of accounts to find.
        pub name: Name,
    }

    /// Result of the `FindAccountsByName` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAccountsByNameResult {
        /// Accounts information.
        pub accounts: Vec<Account>,
    }

    /// `FindAccountsByDomainName` Iroha Query will get `Domain`s name as input and
    /// find all `Account`s under this `Domain` in Iroha `Peer`.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAccountsByDomainName {
        /// `domain_name` under which accounts should be found.
        pub domain_name: Name,
    }

    /// Result of the `FindAccountsByDomainName` execution.
    #[derive(Clone, Debug, Default, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAccountsByDomainNameResult {
        /// Accounts information.
        pub accounts: Vec<Account>,
    }

    impl FindAllAccounts {
        /// Default `FindAllAccounts` constructor.
        pub fn new() -> Self {
            FindAllAccounts {}
        }
    }

    impl FindAccountById {
        /// Default `FindAccountById` constructor.
        pub fn new(id: AccountId) -> Self {
            FindAccountById { id }
        }
    }

    impl FindAccountsByName {
        /// Default `FindAccountsByName` constructor.
        pub fn new(name: Name) -> Self {
            FindAccountsByName { name }
        }
    }

    impl FindAccountsByDomainName {
        /// Default `FindAccountsByDomainName` constructor.
        pub fn new(domain_name: Name) -> Self {
            FindAccountsByDomainName { domain_name }
        }
    }

    impl From<FindAllAccounts> for QueryBox {
        fn from(query: FindAllAccounts) -> QueryBox {
            QueryBox::FindAllAccounts(Box::new(query))
        }
    }

    impl From<FindAccountById> for QueryBox {
        fn from(query: FindAccountById) -> QueryBox {
            QueryBox::FindAccountById(Box::new(query))
        }
    }

    impl From<FindAccountsByName> for QueryBox {
        fn from(query: FindAccountsByName) -> QueryBox {
            QueryBox::FindAccountsByName(Box::new(query))
        }
    }

    impl From<FindAccountsByDomainName> for QueryBox {
        fn from(query: FindAccountsByDomainName) -> QueryBox {
            QueryBox::FindAccountsByDomainName(Box::new(query))
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{
            FindAccountById, FindAccountByIdResult, FindAccountsByDomainName,
            FindAccountsByDomainNameResult, FindAccountsByName, FindAccountsByNameResult,
            FindAllAccounts, FindAllAccountsResult,
        };
    }
}

pub mod asset {
    //! Queries related to `Asset`.

    use crate::prelude::*;
    use iroha_derive::Io;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    /// `FindAllAssets` Iroha Query will find all `Asset`s presented in Iroha Peer.
    #[derive(Copy, Clone, Debug, Default, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAllAssets {}

    /// Result of the `FindAllAssets` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAllAssetsResult {
        /// Assets which are needed to be included in query result.
        pub assets: Vec<Asset>,
    }

    /// `FindAllAssetsDefinitions` Iroha Query will find all `AssetDefinition`s presented
    /// in Iroha Peer.
    #[derive(Copy, Clone, Debug, Default, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAllAssetsDefinitions {}

    /// Result of the `FindAllAssetsDefinitions` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAllAssetsDefinitionsResult {
        /// Assets types which are needed to be included in query result.
        pub assets_definitions: Vec<AssetDefinition>,
    }

    /// `FindAssetById` Iroha Query will find an `Asset` by it's identification in Iroha `Peer`.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAssetById {
        /// `Id` of an `Asset` to find.
        pub id: AssetId,
    }

    /// Result of the `FindAssetById` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAssetByIdResult {
        /// Asset which is needed to be included in query result.
        pub asset: Asset,
    }

    /// `FindAssetsByName` Iroha Query will get `Asset`s name as input and
    /// find all `Asset`s with it in Iroha `Peer`.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAssetsByName {
        /// `Name` of `Asset`s to find.
        pub name: Name,
    }

    /// Result of the `FindAssetsByName` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAssetsByNameResult {
        /// Assets which are needed to be included in query result.
        pub assets: Vec<Asset>,
    }

    /// `FindAssetsByAccountId` Iroha Query will get `AccountId` as input and find all `Asset`s
    /// owned by the `Account` in Iroha Peer.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAssetsByAccountId {
        /// `AccountId` under which assets should be found.
        pub account_id: AccountId,
    }

    /// Result of the `FindAssetsByAccountId` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAssetsByAccountIdResult {
        /// Assets types which are needed to be included in query result.
        pub assets: Vec<Asset>,
    }

    /// `FindAssetsByAssetDefinitionId` Iroha Query will get `AssetDefinitionId` as input and
    /// find all `Asset`s with this `AssetDefinition` in Iroha Peer.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAssetsByAssetDefinitionId {
        /// `AssetDefinitionId` with type of `Asset`s should be found.
        pub asset_definition_id: AssetDefinitionId,
    }

    /// Result of the `FindAssetsByAssetDefinitionId` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAssetsByAssetDefinitionIdResult {
        /// Assets which are needed to be included in query result.
        pub assets: Vec<Asset>,
    }

    /// `FindAssetsByDomainName` Iroha Query will get `Domain`s name as input and
    /// find all `Asset`s under this `Domain` in Iroha `Peer`.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAssetsByDomainName {
        /// `Name` of the domain under which assets should be found.
        pub domain_name: Name,
    }

    /// Result of the `FindAssetsByDomainName` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAssetsByDomainNameResult {
        /// Assets which are needed to be included in query result.
        pub assets: Vec<Asset>,
    }

    /// `FindAssetsByAccountIdAndAssetDefinitionId` Iroha Query will get `AccountId` and
    /// `AssetDefinitionId` as inputs and find all `Asset`s owned by the `Account`
    /// with this `AssetDefinition` in Iroha Peer.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAssetsByAccountIdAndAssetDefinitionId {
        /// `AccountId` under which assets should be found.
        pub account_id: AccountId,
        /// `AssetDefinitionId` which assets should be found.
        pub asset_definition_id: AssetDefinitionId,
    }

    /// Result of the `FindAssetsByAccountId` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAssetsByAccountIdAndAssetDefinitionIdResult {
        /// Assets types which are needed to be included in query result.
        pub assets: Vec<Asset>,
    }

    /// `FindAssetsByDomainNameAndAssetDefinitionId` Iroha Query will get `Domain`'s name and
    /// `AssetDefinitionId` as inputs and find all `Asset`s under the `Domain`
    /// with this `AssetDefinition` in Iroha `Peer`.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAssetsByDomainNameAndAssetDefinitionId {
        /// `Name` of the domain under which assets should be found.
        pub domain_name: Name,
        /// `AssetDefinitionId` assets of which type should be found.
        pub asset_definition_id: AssetDefinitionId,
    }

    /// Result of the `FindAssetsByDomainNameAndAssetDefinitionId` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAssetsByDomainNameAndAssetDefinitionIdResult {
        /// Assets which are needed to be included in query result.
        pub assets: Vec<Asset>,
    }

    /// `FindAssetQuantityById` Iroha Query will get `AssetId` as input and find `Asset::quantity`
    /// parameter's value if `Asset` is presented in Iroha Peer.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAssetQuantityById {
        /// `Id` of an `Asset` to find quantity of.
        pub id: AssetId,
    }

    /// Result of the `FindAssetQuantityById` execution.
    #[derive(Copy, Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAssetQuantityByIdResult {
        /// Assets which are needed to be included in query result.
        pub quantity: u32,
    }

    impl FindAllAssets {
        /// Default `FindAllAssets` constructor.
        pub fn new() -> Self {
            FindAllAssets {}
        }
    }

    impl FindAllAssetsDefinitions {
        /// Default `FindAllAssetsDefinitions` constructor.
        pub fn new() -> Self {
            FindAllAssetsDefinitions {}
        }
    }

    impl FindAssetsByAccountId {
        /// Default `FindAssetsByAccountId` constructor.
        pub fn new(account_id: AccountId) -> Self {
            FindAssetsByAccountId { account_id }
        }
    }

    impl FindAssetsByAssetDefinitionId {
        /// Default `FindAssetsByAssetDefinitionId` constructor.
        pub fn new(asset_definition_id: AssetDefinitionId) -> Self {
            FindAssetsByAssetDefinitionId {
                asset_definition_id,
            }
        }
    }

    impl FindAssetsByAccountIdAndAssetDefinitionId {
        /// Default `FindAssetsByAccountIdAndAssetDefinitionId` constructor.
        pub fn new(account_id: AccountId, asset_definition_id: AssetDefinitionId) -> Self {
            FindAssetsByAccountIdAndAssetDefinitionId {
                account_id,
                asset_definition_id,
            }
        }
    }

    impl FindAssetQuantityById {
        /// Default `FindAssetQuantityById` constructor.
        pub fn new(id: AssetId) -> Self {
            FindAssetQuantityById { id }
        }
    }

    impl Value for FindAssetsByAccountIdAndAssetDefinitionId {
        type Type = Vec<Asset>;
    }

    impl Value for FindAssetQuantityById {
        type Type = u32;
    }

    impl From<FindAllAssets> for QueryBox {
        fn from(query: FindAllAssets) -> QueryBox {
            QueryBox::FindAllAssets(Box::new(query))
        }
    }

    impl From<FindAllAssetsDefinitions> for QueryBox {
        fn from(query: FindAllAssetsDefinitions) -> QueryBox {
            QueryBox::FindAllAssetsDefinitions(Box::new(query))
        }
    }

    impl From<FindAssetsByAccountId> for QueryBox {
        fn from(query: FindAssetsByAccountId) -> QueryBox {
            QueryBox::FindAssetsByAccountId(Box::new(query))
        }
    }

    impl From<FindAssetsByAssetDefinitionId> for QueryBox {
        fn from(query: FindAssetsByAssetDefinitionId) -> QueryBox {
            QueryBox::FindAssetsByAssetDefinitionId(Box::new(query))
        }
    }

    impl From<FindAssetsByAccountIdAndAssetDefinitionId> for QueryBox {
        fn from(query: FindAssetsByAccountIdAndAssetDefinitionId) -> QueryBox {
            QueryBox::FindAssetsByAccountIdAndAssetDefinitionId(Box::new(query))
        }
    }

    impl From<FindAssetQuantityById> for QueryBox {
        fn from(query: FindAssetQuantityById) -> QueryBox {
            QueryBox::FindAssetQuantityById(Box::new(query))
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{
            FindAllAssets, FindAllAssetsDefinitions, FindAllAssetsDefinitionsResult,
            FindAllAssetsResult, FindAssetById, FindAssetByIdResult, FindAssetQuantityById,
            FindAssetQuantityByIdResult, FindAssetsByAccountId,
            FindAssetsByAccountIdAndAssetDefinitionId,
            FindAssetsByAccountIdAndAssetDefinitionIdResult, FindAssetsByAccountIdResult,
            FindAssetsByAssetDefinitionId, FindAssetsByAssetDefinitionIdResult,
            FindAssetsByDomainName, FindAssetsByDomainNameAndAssetDefinitionId,
            FindAssetsByDomainNameAndAssetDefinitionIdResult, FindAssetsByDomainNameResult,
            FindAssetsByName, FindAssetsByNameResult,
        };
    }
}

pub mod domain {
    //! Queries related to `Domain`.

    use crate::prelude::*;
    use iroha_derive::Io;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    /// `FindAllDomains` Iroha Query will find all `Domain`s presented in Iroha `Peer`.
    #[derive(Copy, Clone, Debug, Default, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAllDomains {}

    /// Result of the `FindAllDomains` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAllDomainsResult {
        /// Domain information.
        pub domains: Vec<Domain>,
    }

    /// `FindDomainByName` Iroha Query will find a `Domain` by it's identification in Iroha `Peer`.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindDomainByName {
        /// Name of the domain to find.
        pub name: Name,
    }

    /// Result of the `FindDomainByName` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindDomainByNameResult {
        /// Domain information.
        pub domain: Domain,
    }

    impl FindAllDomains {
        /// Default `FindAllDomains` constructor.
        pub fn new() -> Self {
            FindAllDomains {}
        }
    }

    impl FindDomainByName {
        /// Default `FindDomainByName` constructor.
        pub fn new(name: Name) -> Self {
            FindDomainByName { name }
        }
    }

    impl Value for FindAllDomains {
        type Type = Vec<Domain>;
    }

    impl Value for FindDomainByName {
        type Type = Domain;
    }

    impl From<FindAllDomains> for QueryBox {
        fn from(query: FindAllDomains) -> QueryBox {
            QueryBox::FindAllDomains(Box::new(query))
        }
    }

    impl From<FindDomainByName> for QueryBox {
        fn from(query: FindDomainByName) -> QueryBox {
            QueryBox::FindDomainByName(Box::new(query))
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{
            FindAllDomains, FindAllDomainsResult, FindDomainByName, FindDomainByNameResult,
        };
    }
}

pub mod peer {
    //! Queries related to `Domain`.

    use crate::prelude::*;
    use iroha_derive::Io;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    /// `FindAllPeers` Iroha Query will find all trusted `Peer`s presented in current Iroha `Peer`.
    #[derive(Copy, Clone, Debug, Default, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAllPeers {}

    /// Result of the `FindAllPeers` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAllPeersResult {
        /// Peers which are needed to be included in query result.
        pub peers: Vec<PeerId>,
    }

    /// `FindPeerById` Iroha Query will find a trusted `Peer` by it's identification in
    /// current Iroha `Peer`.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindPeerById {
        /// `Id` of the Peer to find.
        pub id: PeerId,
    }

    /// Result of the `FindPeerById` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindPeerByIdResult {
        /// Peer which is needed to be included in query result.
        pub peer: PeerId,
    }

    impl FindAllPeers {
        ///Default `FindAllPeers` constructor.
        pub fn new() -> Self {
            FindAllPeers {}
        }
    }

    impl FindPeerById {
        ///Default `FindPeerById` constructor.
        pub fn new(id: PeerId) -> Self {
            FindPeerById { id }
        }
    }

    impl Value for FindAllPeers {
        type Type = Vec<Peer>;
    }

    impl Value for FindPeerById {
        type Type = Peer;
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{FindAllPeers, FindAllPeersResult, FindPeerById, FindPeerByIdResult};
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{
        account::prelude::*, asset::prelude::*, domain::prelude::*, peer::prelude::*, QueryBox,
        QueryRequest, QueryResult, SignedQueryRequest,
    };
}
