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

/// Represents a sequence of bytes. Used for storing encoded data.
pub type Bytes = Vec<u8>;

/// This trait marks entity that implement it as identifiable with an `Id` type to find them by.
pub trait Identifiable: Debug + Clone {
    /// Defines the type of entity's identification.
    type Id: Debug + Clone + Eq + Ord;
}

/// This trait marks entity that can be used as a value for different Iroha Special Instructions.
pub trait Value: Debug + Clone {
    /// Defines the type of the value.
    type Type: Debug + Clone;
}

impl Value for u32 {
    type Type = u32;
}

impl Value for u128 {
    type Type = u128;
}

impl Value for Name {
    type Type = Name;
}

impl Value for (Name, Bytes) {
    type Type = (Name, Bytes);
}

impl Value for PublicKey {
    type Type = PublicKey;
}

pub mod account {
    //! Structures, traits and impls related to `Account`s.

    use crate::{asset::AssetsMap, Identifiable, Name, PublicKey};
    use iroha_derive::Io;
    use serde::{Deserialize, Serialize};
    //TODO: get rid of it?
    use parity_scale_codec::{Decode, Encode};
    use std::collections::BTreeMap;

    /// `AccountsMap` provides an API to work with collection of key (`Id`) - value
    /// (`Account`) pairs.
    pub type AccountsMap = BTreeMap<Id, Account>;
    type Signatories = Vec<PublicKey>;

    /// Account entity is an authority which is used to execute `Iroha Special Insturctions`.
    #[derive(Clone, Debug, Serialize, Deserialize, Io, Encode, Decode)]
    pub struct Account {
        /// An Identification of the `Account`.
        pub id: Id,
        /// Asset's in this `Account`.
        pub assets: AssetsMap,
        /// `Account`'s signatories.
        //TODO: signatories are not public keys - rename this field.
        pub signatories: Signatories,
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
    #[derive(
        Clone,
        Debug,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        Serialize,
        Deserialize,
        Io,
        Encode,
        Decode,
    )]
    pub struct Id {
        /// `Account`'s name.
        pub name: Name,
        /// `Account`'s `Domain`'s name.
        pub domain_name: Name,
    }

    impl Account {
        /// Default `Account` constructor.
        pub fn new(id: Id) -> Self {
            Account {
                id,
                assets: AssetsMap::new(),
                signatories: Signatories::new(),
            }
        }

        /// Account with single `signatory` constructor.
        pub fn with_signatory(id: Id, signatory: PublicKey) -> Self {
            let mut signatories = Signatories::new();
            signatories.push(signatory);
            Account {
                id,
                assets: AssetsMap::new(),
                signatories,
            }
        }
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

    use crate::{account::prelude::*, permission::prelude::*, Bytes, Identifiable, Name, Value};
    use iroha_derive::Io;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};
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
    /// Collection of `Bytes` represented parameters and their names.
    type Store = BTreeMap<Name, Bytes>;
    /// `Permissions` is a collection of `PermissionBox` objects.
    pub type Permissions = Vec<PermissionBox>;

    /// Asset definition defines type of that asset.
    #[derive(Clone, Debug, Serialize, Deserialize, Io, Encode, Decode)]
    pub struct AssetDefinition {
        /// An Identification of the `AssetDefinition`.
        pub id: DefinitionId,
    }

    /// Asset represents some sort of commodity or value.
    /// All possible variants of `Asset` entity's components.
    #[derive(Clone, Debug, Serialize, Deserialize, Io, Encode, Decode)]
    pub struct Asset {
        /// Component Identification.
        pub id: Id,
        /// Asset's Quantity.
        pub quantity: u32,
        /// Asset's Big Quantity.
        pub big_quantity: u128,
        /// Asset's key-value structured data.
        pub store: Store,
        /// Asset's `Permissions`.
        pub permissions: Permissions,
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
    #[derive(
        Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Io, Encode, Decode,
    )]
    pub struct DefinitionId {
        /// Asset's name.
        pub name: Name,
        /// Domain's name.
        pub domain_name: Name,
    }

    /// Identification of an Asset's components include Entity Id (`Asset::Id`) and `Account::Id`.
    #[derive(
        Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Io, Encode, Decode,
    )]
    pub struct Id {
        /// Entity Identification.
        pub definition_id: DefinitionId,
        /// Account Identification.
        pub account_id: AccountId,
    }

    impl AssetDefinition {
        /// Default `AssetDefinition` constructor.
        pub fn new(id: DefinitionId) -> Self {
            AssetDefinition { id }
        }
    }

    impl Asset {
        /// `Asset` with `quantity` value constructor.
        pub fn with_quantity(id: Id, quantity: u32) -> Self {
            Asset {
                id,
                quantity,
                big_quantity: 0,
                store: Store::new(),
                permissions: Permissions::new(),
            }
        }

        /// `Asset` with `big_quantity` value constructor.
        pub fn with_big_quantity(id: Id, big_quantity: u128) -> Self {
            Asset {
                id,
                quantity: 0,
                big_quantity,
                store: Store::new(),
                permissions: Permissions::new(),
            }
        }

        /// `Asset` with a `parameter` inside `store` value constructor.
        pub fn with_parameter(id: Id, parameter: (String, Bytes)) -> Self {
            let mut store = Store::new();
            let _ = store.insert(parameter.0, parameter.1);
            Asset {
                id,
                quantity: 0,
                big_quantity: 0,
                store,
                permissions: Permissions::new(),
            }
        }

        /// `Asset` with a `permission` inside `permissions` value constructor.
        pub fn with_permission(id: Id, permission: PermissionBox) -> Self {
            let mut permissions = Permissions::new();
            let _ = permissions.push(permission);
            Asset {
                id,
                quantity: 0,
                big_quantity: 0,
                store: Store::new(),
                permissions,
            }
        }
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

    impl Value for Asset {
        type Type = Asset;
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
    use iroha_derive::Io;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    /// `DomainsMap` provides an API to work with collection of key (`Name`) - value
    /// (`Domain`) pairs.
    pub type DomainsMap = BTreeMap<Name, Domain>;

    /// Named group of `Account` and `Asset` entities.
    #[derive(Clone, Debug, Serialize, Deserialize, Io, Encode, Decode)]
    pub struct Domain {
        /// Domain name, for example company name.
        pub name: Name,
        /// Accounts of the domain.
        pub accounts: AccountsMap,
        /// Assets of the domain.
        pub asset_definitions: AssetDefinitionsMap,
    }

    impl Domain {
        /// Default `Domain` constructor.
        pub fn new(name: &str) -> Self {
            Domain {
                name: name.to_string(),
                accounts: AccountsMap::new(),
                asset_definitions: AssetDefinitionsMap::new(),
            }
        }
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

    use crate::{domain::DomainsMap, isi::InstructionBox, Identifiable, PublicKey};
    use iroha_derive::Io;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeSet;

    type PeersIds = BTreeSet<Id>;

    /// Peer represents Iroha instance.
    #[derive(Clone, Debug, Serialize, Deserialize, Io, Encode, Decode)]
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
        pub triggers: Vec<InstructionBox>,
    }

    /// Peer's identification.
    #[derive(
        Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Io, Encode, Decode,
    )]
    pub struct Id {
        /// Address of the Peer's entrypoint.
        pub address: String,
        /// Public Key of the Peer.
        pub public_key: PublicKey,
    }

    impl Peer {
        /// Default `Peer` constructor.
        pub fn new(id: Id) -> Self {
            let address = id.address.clone();
            Peer {
                id,
                address,
                domains: DomainsMap::new(),
                trusted_peers_ids: PeersIds::new(),
                triggers: Vec::new(),
            }
        }

        /// Constructor with additional parameters.
        pub fn with(id: Id, domains: DomainsMap, trusted_peers_ids: PeersIds) -> Self {
            let address = id.address.clone();
            Peer {
                id,
                address,
                domains,
                trusted_peers_ids,
                triggers: Vec::new(),
            }
        }
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
    use iroha_derive::Io;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    /// Sized container for all possible permissions.
    #[derive(Clone, Debug, Serialize, Deserialize, Io, Encode, Decode)]
    pub enum PermissionBox {
        /// `Anything` variant.
        Anything(Box<Anything>),
        /// `AddDomain` variant.
        AddDomain(Box<AddDomain>),
        /// `RemoveDomain` variant.
        RemoveDomain(Box<RemoveDomain>),
        /// `AddTrigger` variant.
        AddTrigger(Box<AddTrigger>),
        /// `RemoveTrigger` variant.
        RemoveTrigger(Box<RemoveTrigger>),
        /// `RegisterAssetDefinition` variant.
        RegisterAssetDefinition(Box<RegisterAssetDefinition>),
        /// `UnregisterAssetDefinition` variant.
        UnregisterAssetDefinition(Box<UnregisterAssetDefinition>),
        /// `RegisterAccount` variant.
        RegisterAccount(Box<RegisterAccount>),
        /// `UnregisterAccount` variant.
        UnregisterAccount(Box<UnregisterAccount>),
        /// `MintAsset` variant.
        MintAsset(Box<MintAsset>),
        /// `DemintAsset` variant.
        DemintAsset(Box<DemintAsset>),
        /// `TransferAsset` variant.
        TransferAsset(Box<TransferAsset>),
        /// `AddSignatory` variant.
        AddSignatory(Box<AddSignatory>),
        /// `RemoveSignatory` variant.
        RemoveSignatory(Box<RemoveSignatory>),
    }

    /// Permission owner can execute any Iroha Special Instruction.
    /// If `Domain`'s name is defined, permission is limited to execute instructions for
    /// entites inside this domain.
    #[derive(Clone, Debug, Serialize, Deserialize, Io, Encode, Decode)]
    pub struct Anything {
        domain_name: Option<<Domain as Identifiable>::Id>,
    }

    /// Permission owner can add `Domain` to Iroha `Peer`.
    #[derive(Copy, Clone, Debug, Serialize, Deserialize, Io, Encode, Decode)]
    pub struct AddDomain {}

    /// Permission owner can remove `Domain` from Iroha `Peer`.
    #[derive(Copy, Clone, Debug, Serialize, Deserialize, Io, Encode, Decode)]
    pub struct RemoveDomain {}

    /// Permission owner can add `Trigger` to Iroha `Peer`.
    #[derive(Copy, Clone, Debug, Serialize, Deserialize, Io, Encode, Decode)]
    pub struct AddTrigger {}

    /// Permission owner can remove `Trigger` from Iroha `Peer`.
    #[derive(Copy, Clone, Debug, Serialize, Deserialize, Io, Encode, Decode)]
    pub struct RemoveTrigger {}

    /// Permission owner can register `AssetDefinition` in `Domain`.
    /// If `Domain`'s name is defined, permission is limited to register asset definitions
    /// only inside this domain.
    #[derive(Clone, Debug, Serialize, Deserialize, Io, Encode, Decode)]
    pub struct RegisterAssetDefinition {
        domain_name: Option<<Domain as Identifiable>::Id>,
    }

    /// Permission owner can unregister `AssetDefinition` from `Domain`.
    /// If `Domain`'s name is defined, permission is limited to unregister asset definitions
    /// only inside this domain.
    #[derive(Clone, Debug, Serialize, Deserialize, Io, Encode, Decode)]
    pub struct UnregisterAssetDefinition {
        domain_name: Option<<Domain as Identifiable>::Id>,
    }

    /// Permission owner can register `Account` in `Domain`.
    /// If `Domain`'s name is defined, permission is limited to register account
    /// only inside this domain.
    #[derive(Clone, Debug, Serialize, Deserialize, Io, Encode, Decode)]
    pub struct RegisterAccount {
        domain_name: Option<<Domain as Identifiable>::Id>,
    }

    /// Permission owner can unregister `Account` from `Domain`.
    /// If `Domain`'s name is defined, permission is limited to unregister account
    /// only inside this domain.
    #[derive(Clone, Debug, Serialize, Deserialize, Io, Encode, Decode)]
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
    #[derive(Clone, Debug, Serialize, Deserialize, Io, Encode, Decode)]
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
    #[derive(Clone, Debug, Serialize, Deserialize, Io, Encode, Decode)]
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
    #[derive(Clone, Debug, Serialize, Deserialize, Io, Encode, Decode)]
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
    #[derive(Clone, Debug, Serialize, Deserialize, Io, Encode, Decode)]
    pub struct AddSignatory {
        domain_name: Option<<Domain as Identifiable>::Id>,
        account_id: Option<<Account as Identifiable>::Id>,
    }

    /// Permission owner can remove `Signatory` from Iroha `Peer`.
    /// If `Domain`'s name is defined, permission is limited to remove signatories
    /// only inside this domain.
    /// If `Account`'s id is defined, permission is limited to remove signatories
    /// only for this account.
    #[derive(Clone, Debug, Serialize, Deserialize, Io, Encode, Decode)]
    pub struct RemoveSignatory {
        domain_name: Option<<Domain as Identifiable>::Id>,
        account_id: Option<<Account as Identifiable>::Id>,
    }

    impl Anything {
        /// Default `Anything` constructor.
        pub fn new() -> Self {
            Anything { domain_name: None }
        }

        /// `Anything` constructor with specified `domain_name` as permission's scope.
        pub fn within_domain(domain_name: <Domain as Identifiable>::Id) -> Self {
            Anything {
                domain_name: Some(domain_name),
            }
        }

        /// `Anything` --> `PermissionBox` transformator.
        pub fn into_boxed(self) -> PermissionBox {
            PermissionBox::Anything(Box::new(self))
        }
    }

    impl AddDomain {
        /// Default `AddDomain` constructor.
        pub fn new() -> Self {
            AddDomain {}
        }
    }

    impl RemoveDomain {
        /// Default `RemoveDomain` constructor.
        pub fn new() -> Self {
            RemoveDomain {}
        }
    }

    impl AddTrigger {
        /// Default `AddTrigger` constructor.
        pub fn new() -> Self {
            AddTrigger {}
        }
    }

    impl RemoveTrigger {
        /// Default `RemoveTrigger` constructor.
        pub fn new() -> Self {
            RemoveTrigger {}
        }
    }

    impl RegisterAssetDefinition {
        /// Default `RegisterAssetDefinition` constructor.
        pub fn new() -> Self {
            RegisterAssetDefinition { domain_name: None }
        }

        /// `RegisterAssetDefinition` constructor with `domain_name` as permission's scope.
        pub fn within_domain(domain_name: <Domain as Identifiable>::Id) -> Self {
            RegisterAssetDefinition {
                domain_name: Some(domain_name),
            }
        }
    }

    impl UnregisterAssetDefinition {
        /// Default `UnregisterAssetDefinition` constructor.
        pub fn new() -> Self {
            UnregisterAssetDefinition { domain_name: None }
        }

        /// `UnregisterAssetDefinition` constructor with `domain_name` as permission's scope.
        pub fn within_domain(domain_name: <Domain as Identifiable>::Id) -> Self {
            UnregisterAssetDefinition {
                domain_name: Some(domain_name),
            }
        }
    }

    impl RegisterAccount {
        /// Default `RegisterAccount` constructor.
        pub fn new() -> Self {
            RegisterAccount { domain_name: None }
        }

        /// `RegisterAccount` constructor with `domain_name` as permission's scope.
        pub fn within_domain(domain_name: <Domain as Identifiable>::Id) -> Self {
            RegisterAccount {
                domain_name: Some(domain_name),
            }
        }
    }

    impl UnregisterAccount {
        /// Default `UnregisterAccount` constructor.
        pub fn new() -> Self {
            UnregisterAccount { domain_name: None }
        }

        /// `UnregisterAccount` constructor with `domain_name` as permission's scope.
        pub fn within_domain(domain_name: <Domain as Identifiable>::Id) -> Self {
            UnregisterAccount {
                domain_name: Some(domain_name),
            }
        }
    }

    impl MintAsset {
        /// Default `MintAsset` constructor.
        pub fn new() -> Self {
            MintAsset {
                domain_name: None,
                account_id: None,
                asset_definition_id: None,
            }
        }

        /// `MintAsset` constructor with `domain_name` as permission's scope.
        pub fn within_domain(domain_name: <Domain as Identifiable>::Id) -> Self {
            MintAsset {
                domain_name: Some(domain_name),
                account_id: None,
                asset_definition_id: None,
            }
        }

        /// `MintAsset` constructor with `account_id` as permission's scope.
        pub fn within_account(account_id: <Account as Identifiable>::Id) -> Self {
            MintAsset {
                domain_name: None,
                account_id: Some(account_id),
                asset_definition_id: None,
            }
        }

        /// `MintAsset` constructor with `asset_definition_id` as permission's scope.
        pub fn with_asset_definition(
            asset_definition_id: <AssetDefinition as Identifiable>::Id,
        ) -> Self {
            MintAsset {
                domain_name: None,
                account_id: None,
                asset_definition_id: Some(asset_definition_id),
            }
        }
    }

    impl DemintAsset {
        /// Default `DemintAsset` constructor.
        pub fn new() -> Self {
            DemintAsset {
                domain_name: None,
                account_id: None,
                asset_definition_id: None,
            }
        }

        /// `DemintAsset` constructor with `domain_name` as permission's scope.
        pub fn within_domain(domain_name: <Domain as Identifiable>::Id) -> Self {
            DemintAsset {
                domain_name: Some(domain_name),
                account_id: None,
                asset_definition_id: None,
            }
        }

        /// `DemintAsset` constructor with `account_id` as permission's scope.
        pub fn within_account(account_id: <Account as Identifiable>::Id) -> Self {
            DemintAsset {
                domain_name: None,
                account_id: Some(account_id),
                asset_definition_id: None,
            }
        }

        /// `DemintAsset` constructor with `asset_definition_id` as permission's scope.
        pub fn with_asset_definition(
            asset_definition_id: <AssetDefinition as Identifiable>::Id,
        ) -> Self {
            DemintAsset {
                domain_name: None,
                account_id: None,
                asset_definition_id: Some(asset_definition_id),
            }
        }
    }

    impl TransferAsset {
        /// Default `TransferAsset` constructor.
        pub fn new() -> Self {
            TransferAsset {
                domain_name: None,
                account_id: None,
                asset_definition_id: None,
            }
        }

        /// `TransferAsset` constructor with `domain_name` as permission's scope.
        pub fn within_domain(domain_name: <Domain as Identifiable>::Id) -> Self {
            TransferAsset {
                domain_name: Some(domain_name),
                account_id: None,
                asset_definition_id: None,
            }
        }

        /// `TransferAsset` constructor with `account_id` as permission's scope.
        pub fn within_accounts(
            left_account_id: <Account as Identifiable>::Id,
            right_account_id: <Account as Identifiable>::Id,
        ) -> Self {
            TransferAsset {
                domain_name: None,
                account_id: Some((left_account_id, right_account_id)),
                asset_definition_id: None,
            }
        }

        /// `TransferAsset` constructor with `asset_definition_id` as permission's scope.
        pub fn with_asset_definition(
            asset_definition_id: <AssetDefinition as Identifiable>::Id,
        ) -> Self {
            TransferAsset {
                domain_name: None,
                account_id: None,
                asset_definition_id: Some(asset_definition_id),
            }
        }
    }

    impl AddSignatory {
        /// Default `AddSignatory` constructor.
        pub fn new() -> Self {
            AddSignatory {
                domain_name: None,
                account_id: None,
            }
        }

        /// `AddSignatory` constructor with `domain_name` as permission's scope.
        pub fn within_domain(domain_name: <Domain as Identifiable>::Id) -> Self {
            AddSignatory {
                domain_name: Some(domain_name),
                account_id: None,
            }
        }

        /// `AddSignatory` constructor with `account_id` as permission's scope.
        pub fn within_account(account_id: <Account as Identifiable>::Id) -> Self {
            AddSignatory {
                domain_name: None,
                account_id: Some(account_id),
            }
        }
    }

    impl RemoveSignatory {
        /// Default `RemoveSignatory` constructor.
        pub fn new() -> Self {
            RemoveSignatory {
                domain_name: None,
                account_id: None,
            }
        }

        /// `RemoveSignatory` constructor with `domain_name` as permission's scope.
        pub fn within_domain(domain_name: <Domain as Identifiable>::Id) -> Self {
            RemoveSignatory {
                domain_name: Some(domain_name),
                account_id: None,
            }
        }

        /// `RemoveSignatory` constructor with `account_id` as permission's scope.
        pub fn within_account(account_id: <Account as Identifiable>::Id) -> Self {
            RemoveSignatory {
                domain_name: None,
                account_id: Some(account_id),
            }
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{
            AddDomain, AddSignatory, AddTrigger, Anything, DemintAsset, MintAsset, PermissionBox,
            RegisterAccount, RegisterAssetDefinition, RemoveDomain, RemoveSignatory, RemoveTrigger,
            TransferAsset, UnregisterAccount, UnregisterAssetDefinition,
        };
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{
        account::prelude::*, asset::prelude::*, domain::prelude::*, peer::prelude::*,
        permission::prelude::*, Bytes, Identifiable, Name, Value,
    };
    pub use crate::{isi::prelude::*, query::prelude::*};
}
