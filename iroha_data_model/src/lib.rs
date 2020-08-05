//! Iroha Data Model contains structures for Domains, Peers, Accounts and Assets with simple,
//! non-specific functions like serialization.

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

pub mod isi;
pub mod query;

use iroha_crypto::PublicKey;
use std::fmt::Debug;

/// `Name` struct represents type for Iroha Entities names, like `Domain`'s name or `Account`'s
/// name.
pub type Name = String;

/// This trait marks entity that implement it as identifiable with an `Id` type to find them by.
pub trait Identifiable: Debug {
    /// Defines the type of entity's identification.
    type Id: Debug;
}

/// This trait marks entity that can be used as a value for different Iroha Special Instructions.
pub trait Value: Debug {
    /// Defines the type of the value.
    type Type;
}

impl Value for u32 {
    type Type = u32;
}

pub mod account {
    //! Structures, traits and impls related to `Account`s.

    use crate::{asset::AssetsMap, Identifiable, Name, PublicKey};
    use std::collections::BTreeMap;

    /// `AccountsMap` provides an API to work with collection of key (`Id`) - value
    /// (`Account`) pairs.
    pub type AccountsMap = BTreeMap<Id, Account>;

    /// Account entity is an authority which is used to execute `Iroha Special Insturctions`.
    #[derive(Debug)]
    pub struct Account {
        /// An Identification of the `Account`.
        pub id: Id,
        /// Asset's in this `Account`.
        pub assets: AssetsMap,
        signatories: Vec<PublicKey>,
    }

    /// Identification of an Account. Consists of Account's name and Domain's name.
    ///
    /// # Example
    ///
    /// ```
    /// use iroha_data_model::account::Id;
    ///
    /// let id = Id::new("user", "company");
    /// ```
    #[derive(Debug)]
    pub struct Id {
        name: Name,
        domain_name: Name,
    }

    impl Id {
        /// `Id` constructor used to easily create an `Id` from two string slices - one for the
        /// account's name, another one for the container's name.
        pub fn new(name: &str, domain_name: &str) -> Self {
            Id {
                name: name.to_string(),
                domain_name: domain_name.to_string(),
            }
        }
    }

    impl Identifiable for Account {
        type Id = Id;
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{Account, Id as AccountId};
    }
}

pub mod asset {
    //! This module contains `Asset` structure, it's implementation and related traits and
    //! instructions implementations.

    use crate::{account::prelude::*, Identifiable, Name};
    use std::{
        collections::BTreeMap,
        fmt::{self, Display, Formatter},
    };

    /// `AssetsMap` provides an API to work with collection of key (`Id`) - value
    /// (`Asset`) pairs.
    pub type AssetsMap = BTreeMap<Id, Asset>;
    /// `AssetDefinitionsMap` provides an API to work with collection of key (`DefinitionId`) - value
    /// (`AssetDefinition`) pairs.
    pub type AssetDefinitionsMap = BTreeMap<DefinitionId, AssetDefinition>;
    /// Represents a sequence of bytes. Used for storing encoded data.
    type Bytes = Vec<u8>;
    /// Collection of `Bytes` represented parameters and their names.
    type Store = BTreeMap<Name, Bytes>;

    /// Asset definition defines type of that asset.
    #[derive(Debug)]
    pub struct AssetDefinition {
        /// An Identification of the `AssetDefinition`.
        pub id: DefinitionId,
    }

    /// Asset represents some sort of commodity or value.
    /// All possible variants of `Asset` entity's components.
    #[derive(Debug)]
    pub struct Asset {
        /// Component Identification.
        pub id: Id,
        /// Asset's Quantity.
        pub quantity: u32,
        /// Asset's Big Quantity.
        pub big_quantity: u128,
        /// Asset's key-value structured data.
        pub store: Store,
        // Asset's key-value  (action, object_id) structured permissions.
        //pub permissions: Permissions,
    }

    /// Identification of an Asset Definition. Consists of Asset's name and Domain's name.
    ///
    /// # Example
    ///
    /// ```
    /// use iroha_data_model::asset::DefinitionId;
    ///
    /// let definition_id = DefinitionId::new("xor", "soramitsu");
    /// ```
    #[derive(Debug)]
    pub struct DefinitionId {
        /// Asset's name.
        pub name: Name,
        /// Domain's name.
        pub domain_name: Name,
    }

    /// Identification of an Asset's components include Entity Id (`Asset::Id`) and `Account::Id`.
    #[derive(Debug)]
    pub struct Id {
        /// Entity Identification.
        pub definition_id: DefinitionId,
        /// Account Identification.
        pub account_id: AccountId,
    }

    impl DefinitionId {
        /// `Id` constructor used to easily create an `Id` from three string slices - one for the
        /// asset definition's name, another one for the domain's name.
        pub fn new(name: &str, domain_name: &str) -> Self {
            DefinitionId {
                name: name.to_string(),
                domain_name: domain_name.to_string(),
            }
        }
    }

    impl Id {
        /// `Id` constructor used to easily create an `Id` from an names of asset definition and
        /// account.
        pub fn from_names(
            asset_definition_name: &str,
            asset_definition_domain_name: &str,
            account_name: &str,
            account_domain_name: &str,
        ) -> Self {
            Id {
                definition_id: DefinitionId::new(
                    asset_definition_name,
                    asset_definition_domain_name,
                ),
                account_id: AccountId::new(account_name, account_domain_name),
            }
        }

        /// `Id` constructor used to easily create an `Id` from an `AssetDefinitionId` and
        /// an `AccountId`.
        pub fn new(definition_id: DefinitionId, account_id: AccountId) -> Self {
            Id {
                definition_id,
                account_id,
            }
        }
    }

    impl Identifiable for Asset {
        type Id = Id;
    }

    impl Identifiable for AssetDefinition {
        type Id = DefinitionId;
    }

    /// Asset Identification is represented by `name#domain_name` string.
    impl std::str::FromStr for DefinitionId {
        type Err = String;

        fn from_str(string: &str) -> Result<Self, Self::Err> {
            let vector: Vec<&str> = string.split('#').collect();
            Ok(DefinitionId {
                name: String::from(vector[0]),
                domain_name: String::from(vector[1]),
            })
        }
    }

    impl Display for DefinitionId {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{}#{}", self.name, self.domain_name)
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{Asset, AssetDefinition, DefinitionId as AssetDefinitionId, Id as AssetId};
    }
}

pub mod domain {
    //! This module contains `Domain` structure and related implementations and trait implementations.

    use crate::{account::AccountsMap, asset::AssetDefinitionsMap, Identifiable, Name};
    use std::collections::BTreeMap;

    /// `DomainsMap` provides an API to work with collection of key (`Name`) - value
    /// (`Domain`) pairs.
    pub type DomainsMap = BTreeMap<Name, Domain>;

    /// Named group of `Account` and `Asset` entities.
    #[derive(Debug)]
    pub struct Domain {
        /// Domain name, for example company name.
        pub name: Name,
        /// Accounts of the domain.
        pub accounts: AccountsMap,
        /// Assets of the domain.
        pub asset_definitions: AssetDefinitionsMap,
    }

    impl Identifiable for Domain {
        type Id = Name;
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::Domain;
    }
}

pub mod peer {
    //! This module contains `Peer` structure and related implementations and traits implementations.

    use crate::{domain::DomainsMap, isi::Instruction, Identifiable, PublicKey};
    use std::collections::BTreeSet;

    type PeersIds = BTreeSet<Id>;

    /// Peer's identification.
    #[derive(Debug)]
    pub struct Id {
        /// Address of the Peer's entrypoint.
        pub address: String,
        /// Public Key of the Peer.
        pub public_key: PublicKey,
    }

    /// Peer represents Iroha instance.
    #[derive(Debug)]
    pub struct Peer {
        /// Peer Identification.
        pub id: Id,
        /// Address of the peer.
        pub address: String,
        /// Registered domains.
        pub domains: DomainsMap,
        /// Identifications of discovered trusted peers.
        pub trusted_peers_ids: PeersIds,
        /// Iroha `Triggers` registered on the peer.
        pub triggers: Vec<Box<dyn Instruction>>,
    }

    impl Identifiable for Peer {
        type Id = Id;
    }

    impl Id {
        /// Default `PeerId` constructor.
        pub fn new(address: &str, public_key: &PublicKey) -> Self {
            Id {
                address: address.to_string(),
                public_key: public_key.clone(),
            }
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{Id as PeerId, Peer};
    }
}

pub mod permission {
    //! This module contains `Permission` structures and related implementations
    //! and traits implementations.

    use crate::{account::prelude::*, asset::prelude::*, domain::prelude::*, Identifiable};

    /// `Permission` grants it's owner an ability to execute Iroha Special Instructions on Iroha
    /// Peers. Some permissions like `Anything` grants an ability to execute any instruction inside
    /// any domain, some permissions grants an ability to execute only one type of instructions and
    /// may be limited in scope (only inside one domain or account or only work with assets of
    /// certain defintion.
    #[derive(Debug)]
    pub enum PermissionBox {
        /// Variant for `Anything` permission.
        Anything(Box<Anything>),
        /// Variant for `AddDomain` permission.
        AddDomain(Box<AddDomain>),
        /// Variant for `RemoveDomain` permission.
        RemoveDomain(Box<RemoveDomain>),
        /// Variant for `AddTrigger` permission.
        AddTrigger(Box<AddTrigger>),
        /// Variant for `RemoveTrigger` permission.
        RemoveTrigger(Box<RemoveTrigger>),
        /// Variant for `RegisterAssetDefinition` permission.
        RegisterAssetDefinition(Box<RegisterAssetDefinition>),
        /// Variant for `UnregisterAssetDefinition` permission.
        UnregisterAssetDefinition(Box<UnregisterAssetDefinition>),
        /// Variant for `RegisterAccount` permission.
        RegisterAccount(Box<RegisterAccount>),
        /// Variant for `UnregisterAccount` permission.
        UnregisterAccount(Box<UnregisterAccount>),
        /// Variant for `MintAsset` permission.
        MintAsset(Box<MintAsset>),
        /// Variant for `DemintAsset` permission.
        DemintAsset(Box<DemintAsset>),
        /// Variant for `TransferAsset` permission.
        TransferAsset(Box<TransferAsset>),
        /// Variant for `AddSignatory` permission.
        AddSignatory(Box<AddSignatory>),
        /// Variant for `RemoveSignatory` permission.
        RemoveSignatory(Box<RemoveSignatory>),
    }

    /// Permission owner can execute any Iroha Special Instruction.
    /// If `Domain`'s name is defined, permission is limited to execute instructions for
    /// entites inside this domain.
    #[derive(Debug)]
    pub struct Anything {
        domain_name: Option<<Domain as Identifiable>::Id>,
    }

    /// Permission owner can add `Domain` to Iroha `Peer`.
    #[derive(Copy, Clone, Debug)]
    pub struct AddDomain {}

    /// Permission owner can remove `Domain` from Iroha `Peer`.
    #[derive(Copy, Clone, Debug)]
    pub struct RemoveDomain {}

    /// Permission owner can add `Trigger` to Iroha `Peer`.
    #[derive(Copy, Clone, Debug)]
    pub struct AddTrigger {}

    /// Permission owner can remove `Trigger` from Iroha `Peer`.
    #[derive(Copy, Clone, Debug)]
    pub struct RemoveTrigger {}

    /// Permission owner can register `AssetDefinition` in `Domain`.
    /// If `Domain`'s name is defined, permission is limited to register asset definitions
    /// only inside this domain.
    #[derive(Debug)]
    pub struct RegisterAssetDefinition {
        domain_name: Option<<Domain as Identifiable>::Id>,
    }

    /// Permission owner can unregister `AssetDefinition` from `Domain`.
    /// If `Domain`'s name is defined, permission is limited to unregister asset definitions
    /// only inside this domain.
    #[derive(Debug)]
    pub struct UnregisterAssetDefinition {
        domain_name: Option<<Domain as Identifiable>::Id>,
    }

    /// Permission owner can register `Account` in `Domain`.
    /// If `Domain`'s name is defined, permission is limited to register account
    /// only inside this domain.
    #[derive(Debug)]
    pub struct RegisterAccount {
        domain_name: Option<<Domain as Identifiable>::Id>,
    }

    /// Permission owner can unregister `Account` from `Domain`.
    /// If `Domain`'s name is defined, permission is limited to unregister account
    /// only inside this domain.
    #[derive(Debug)]
    pub struct UnregisterAccount {
        domain_name: Option<<Domain as Identifiable>::Id>,
    }

    /// Permission owner can mint `Asset` in Iroha `Peer`.
    /// If `Domain`'s name is defined, permission is limited to mint asset
    /// only inside this domain.
    /// If `Account`'s id is defined, permission is limited to mint asset
    /// only inside this account.
    /// If `AssetDefinition`'s id is defined, permission is limited to mint asset
    /// only with this defintion.
    #[derive(Debug)]
    pub struct MintAsset {
        domain_name: Option<<Domain as Identifiable>::Id>,
        account_id: Option<<Account as Identifiable>::Id>,
        asset_definition_id: Option<<AssetDefinition as Identifiable>::Id>,
    }

    /// Permission owner can demint `Asset` in Iroha `Peer`.
    /// If `Domain`'s name is defined, permission is limited to demint asset
    /// only inside this domain.
    /// If `Account`'s id is defined, permission is limited to demint asset
    /// only inside this account.
    /// If `AssetDefinition`'s id is defined, permission is limited to demint asset
    /// only with this defintion.
    #[derive(Debug)]
    pub struct DemintAsset {
        domain_name: Option<<Domain as Identifiable>::Id>,
        account_id: Option<<Account as Identifiable>::Id>,
        asset_definition_id: Option<<AssetDefinition as Identifiable>::Id>,
    }

    /// Permission owner can transfer `Asset` in Iroha `Peer`.
    /// If `Domain`'s name is defined, permission is limited to transfer asset
    /// only inside this domain.
    /// If `Account`s ids are defined, permission is limited to transfer asset
    /// only from or to these accounts.
    /// If `AssetDefinition`'s id is defined, permission is limited to demint asset
    /// only with this defintion.
    #[derive(Debug)]
    pub struct TransferAsset {
        domain_name: Option<<Domain as Identifiable>::Id>,
        account_id: Option<(<Account as Identifiable>::Id, <Account as Identifiable>::Id)>,
        asset_definition_id: Option<<AssetDefinition as Identifiable>::Id>,
    }

    /// Permission owner can add `Signatory` to Iroha `Peer`.
    /// If `Domain`'s name is defined, permission is limited to add signatories
    /// only inside this domain.
    /// If `Account`'s id is defined, permission is limited to add signatories
    /// only for this account.
    #[derive(Debug)]
    pub struct AddSignatory {
        domain_name: Option<<Domain as Identifiable>::Id>,
        account_id: Option<<Account as Identifiable>::Id>,
    }

    /// Permission owner can remove `Signatory` from Iroha `Peer`.
    /// If `Domain`'s name is defined, permission is limited to remove signatories
    /// only inside this domain.
    /// If `Account`'s id is defined, permission is limited to remove signatories
    /// only for this account.
    #[derive(Debug)]
    pub struct RemoveSignatory {
        domain_name: Option<<Domain as Identifiable>::Id>,
        account_id: Option<<Account as Identifiable>::Id>,
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{
        account::prelude::*, asset::prelude::*, domain::prelude::*, peer::prelude::*, Identifiable,
        Name, Value,
    };
    pub use crate::{isi::prelude::*, query::prelude::*};
}
