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

pub mod account {
    //! Queries related to `Account`.
    use crate::prelude::*;

    /// `FindAllAccounts` Iroha Query will find all `Account`s presented in Iroha `Peer`.
    #[derive(Copy, Clone, Debug)]
    pub struct FindAllAccounts {}

    /// `FindAccountById` Iroha Query will find an `Account` by it's identification in Iroha `Peer`.
    #[derive(Debug)]
    pub struct FindAccountById {
        id: AccountId,
    }

    /// `FindAccountsByName` Iroha Query will get `Account`s name as input and
    /// find all `Account`s with this name in Iroha `Peer`.
    #[derive(Debug)]
    pub struct FindAccountsByName {
        name: Name,
    }

    /// `FindAccountsByDomainName` Iroha Query will get `Domain`s name as input and
    /// find all `Account`s under this `Domain` in Iroha `Peer`.
    #[derive(Debug)]
    pub struct FindAccountsByDomainName {
        domain_name: Name,
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{FindAccountById, FindAccountsByDomainName, FindAllAccounts};
    }
}

pub mod asset {
    //! Queries related to `Asset`.

    use crate::prelude::*;

    /// `FindAllAssets` Iroha Query will find all `Asset`s presented in Iroha Peer.
    #[derive(Copy, Clone, Debug, Default)]
    pub struct FindAllAssets {}

    /// `FindAllAssetsDefinitions` Iroha Query will find all `AssetDefinition`s presented
    /// in Iroha Peer.
    #[derive(Copy, Clone, Debug, Default)]
    pub struct FindAllAssetsDefinitions {}

    /// `FindAssetById` Iroha Query will find an `Asset` by it's identification in Iroha `Peer`.
    #[derive(Debug)]
    pub struct FindAssetById {
        id: AssetId,
    }

    /// `FindAssetsByName` Iroha Query will get `Asset`s name as input and
    /// find all `Asset`s with it in Iroha `Peer`.
    #[derive(Debug)]
    pub struct FindAssetByName {
        name: Name,
    }

    /// `FindAssetsByAccountId` Iroha Query will get `AccountId` as input and find all `Asset`s
    /// owned by the `Account` in Iroha Peer.
    #[derive(Debug)]
    pub struct FindAssetsByAccountId {
        account_id: AccountId,
    }

    /// `FindAssetsByAssetDefinitionId` Iroha Query will get `AssetDefinitionId` as input and
    /// find all `Asset`s with this `AssetDefinition` in Iroha Peer.
    #[derive(Debug)]
    pub struct FindAssetsByAssetDefinitionId {
        asset_definition_id: AssetDefinitionId,
    }

    /// `FindAssetsByDomainName` Iroha Query will get `Domain`s name as input and
    /// find all `Asset`s under this `Domain` in Iroha `Peer`.
    #[derive(Debug)]
    pub struct FindAssetsByDomainName {
        domain_name: Name,
    }

    /// `FindAssetsByAccountIdAndAssetDefinitionId` Iroha Query will get `AccountId` and
    /// `AssetDefinitionId` as inputs and find all `Asset`s owned by the `Account`
    /// with this `AssetDefinition` in Iroha Peer.
    #[derive(Debug)]
    pub struct FindAssetsByAccountIdAndAssetDefinitionId {
        account_id: AccountId,
        asset_definition_id: AssetDefinitionId,
    }

    /// `FindAssetsByDomainNameAndAssetDefinitionId` Iroha Query will get `Domain`'s name and
    /// `AssetDefinitionId` as inputs and find all `Asset`s under the `Domain`
    /// with this `AssetDefinition` in Iroha `Peer`.
    #[derive(Debug)]
    pub struct FindAssetsByDomainNameAndAssetDefinitionId {
        domain_name: Name,
        asset_definition_id: AssetDefinitionId,
    }

    /// `FindAssetQuantityById` Iroha Query will get `AssetId` as input and find `Asset::quantity`
    /// parameter's value if `Asset` is presented in Iroha Peer.
    #[derive(Debug)]
    pub struct FindAssetQuantityById {
        id: AssetId,
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

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{
            FindAllAssets, FindAllAssetsDefinitions, FindAssetById, FindAssetByName,
            FindAssetQuantityById, FindAssetsByAccountId,
            FindAssetsByAccountIdAndAssetDefinitionId, FindAssetsByAssetDefinitionId,
            FindAssetsByDomainNameAndAssetDefinitionId,
        };
    }
}

pub mod domain {
    //! Queries related to `Domain`.

    use crate::prelude::*;

    /// `FindAllDomains` Iroha Query will find all `Domain`s presented in Iroha `Peer`.
    #[derive(Copy, Clone, Debug, Default)]
    pub struct FindAllDomains {}

    /// `FindDomainByName` Iroha Query will find a `Domain` by it's identification in Iroha `Peer`.
    #[derive(Debug)]
    pub struct FindDomainByName {
        name: Name,
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

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{FindAllDomains, FindDomainByName};
    }
}

pub mod peer {
    //! Queries related to `Domain`.

    use crate::prelude::*;

    /// `FindAllPeers` Iroha Query will find all trusted `Peer`s presented in current Iroha `Peer`.
    #[derive(Copy, Clone, Debug, Default)]
    pub struct FindAllPeers {}

    /// `FindPeerById` Iroha Query will find a trusted `Peer` by it's identification in
    /// current Iroha `Peer`.
    #[derive(Debug)]
    pub struct FindPeerById {
        id: PeerId,
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
        pub use super::{FindAllPeers, FindPeerById};
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{account::prelude::*, asset::prelude::*, domain::prelude::*, peer::prelude::*};
    pub use crate::prelude::*;
}
