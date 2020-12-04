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
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// `Name` struct represents type for Iroha Entities names, like `Domain`'s name or `Account`'s
/// name.
pub type Name = String;

/// Represents a sequence of bytes. Used for storing encoded data.
pub type Bytes = Vec<u8>;

/// Represents Iroha Configuration parameters.
#[derive(Copy, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum Parameter {
    /// Maximum amount of Faulty Peers in the system.
    MaximumFaultyPeersAmount(u32),
    /// TODO: write a doc
    CommitTime(u128),
    /// Time to wait for a transaction Receipt.
    TransactionReceiptTime(u128),
    /// TODO: write a doc
    BlockTime(u128),
}

/// Sized container for all possible identifications.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub enum IdBox {
    /// `AccountId` variant.
    AccountId(account::Id),
    /// `AssetId` variant.
    AssetId(asset::Id),
    /// `AssetDefinitionId` variant.
    AssetDefinitionId(asset::DefinitionId),
    /// `DomainName` variant.
    DomainName(Name),
    /// `PeerId` variant.
    PeerId(peer::Id),
}

/// Sized container for all possible entities.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub enum IdentifiableBox {
    /// `Account` variant.
    Account(Box<account::Account>),
    /// `Asset` variant.
    Asset(Box<asset::Asset>),
    /// `AssetDefinition` variant.
    AssetDefinition(Box<asset::AssetDefinition>),
    /// `Domain` variant.
    Domain(Box<domain::Domain>),
    /// `Peer` variant.
    Peer(Box<peer::Peer>),
}

/// Sized container for all possible values.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub enum ValueBox {
    /// `u32` variant.
    U32(u32),
    /// Iroha `Query` variant.
    Query(Box<query::QueryBox>),
    /// Iroha `Parameter` variant.
    Parameter(Parameter),
}

/// This trait marks entity that implement it as identifiable with an `Id` type to find them by.
pub trait Identifiable: Debug + Clone {
    /// Defines the type of entity's identification.
    type Id: Into<IdBox> + Debug + Clone + Eq + Ord;
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

impl Value for Parameter {
    type Type = Parameter;
}

impl From<u32> for ValueBox {
    fn from(value: u32) -> ValueBox {
        ValueBox::U32(value)
    }
}

impl From<Parameter> for ValueBox {
    fn from(value: Parameter) -> ValueBox {
        ValueBox::Parameter(value)
    }
}

pub mod permissions {
    //! Structures, traits and impls related to `Permission`s.

    /// Raw byte representation of Permission.
    pub type PermissionRaw = Vec<u8>;
}

pub mod account {
    //! Structures, traits and impls related to `Account`s.

    use crate::{
        asset::AssetsMap, domain::GENESIS_DOMAIN_NAME, permissions::PermissionRaw, IdBox,
        Identifiable, IdentifiableBox, Name, PublicKey,
    };
    use iroha_derive::Io;
    use serde::{Deserialize, Serialize};
    //TODO: get rid of it?
    use iroha_crypto::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use std::{collections::BTreeMap, fmt};

    /// `AccountsMap` provides an API to work with collection of key (`Id`) - value
    /// (`Account`) pairs.
    pub type AccountsMap = BTreeMap<Id, Account>;
    type Signatories = Vec<PublicKey>;
    type Permissions = Vec<PermissionRaw>;

    /// Genesis account name.
    pub const GENESIS_ACCOUNT_NAME: &str = "genesis";

    /// Genesis account. Used to mainly be converted to ordinary `Account` struct.
    #[derive(Debug)]
    pub struct GenesisAccount {
        public_key: PublicKey,
    }

    impl GenesisAccount {
        /// Returns `GenesisAccount` instance.
        pub fn new(public_key: PublicKey) -> Self {
            GenesisAccount { public_key }
        }
    }

    impl From<GenesisAccount> for Account {
        fn from(account: GenesisAccount) -> Self {
            Account::with_signatory(Id::genesis_account(), account.public_key)
        }
    }

    /// Account entity is an authority which is used to execute `Iroha Special Insturctions`.
    #[derive(
        Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Io, Encode, Decode,
    )]
    pub struct Account {
        /// An Identification of the `Account`.
        pub id: Id,
        /// Asset's in this `Account`.
        pub assets: AssetsMap,
        /// `Account`'s signatories.
        //TODO: signatories are not public keys - rename this field.
        pub signatories: Signatories,
        /// Permissions of this account
        pub permissions: Permissions,
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
                permissions: Permissions::new(),
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
                permissions: Permissions::new(),
            }
        }
        /// Verify if the signature is produced by the owner of this account.
        pub fn verify_signature(
            &self,
            signature: &Signature,
            payload: &[u8],
        ) -> Result<(), String> {
            if self.signatories.contains(&signature.public_key) {
                signature.verify(payload)
            } else {
                Err(format!(
                    "Account does not have a signatory with this public key: {}",
                    signature.public_key
                ))
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

        /// `Id` of the genesis account.
        pub fn genesis_account() -> Self {
            Id {
                name: GENESIS_ACCOUNT_NAME.to_string(),
                domain_name: GENESIS_DOMAIN_NAME.to_string(),
            }
        }
    }

    impl Identifiable for Account {
        type Id = Id;
    }

    impl From<Account> for IdentifiableBox {
        fn from(account: Account) -> IdentifiableBox {
            IdentifiableBox::Account(Box::new(account))
        }
    }

    impl From<Id> for IdBox {
        fn from(id: Id) -> IdBox {
            IdBox::AccountId(id)
        }
    }

    /// Account Identification is represented by `name@domain_name` string.
    impl std::str::FromStr for Id {
        type Err = String;

        fn from_str(string: &str) -> Result<Self, Self::Err> {
            let vector: Vec<&str> = string.split('@').collect();
            Ok(Id {
                name: String::from(vector[0]),
                domain_name: String::from(vector[1]),
            })
        }
    }

    impl fmt::Display for Id {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}@{}", self.name, self.domain_name)
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{Account, Id as AccountId};
    }
}

pub mod asset {
    //! This module contains `Asset` structure, it's implementation and related traits and
    //! instructions implementations.

    use crate::{account::prelude::*, Bytes, IdBox, Identifiable, IdentifiableBox, Name, Value};
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
    pub type Store = BTreeMap<Name, Bytes>;

    /// Asset definition defines type of that asset.
    #[derive(
        Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Io, Encode, Decode,
    )]
    pub struct AssetDefinition {
        /// An Identification of the `AssetDefinition`.
        pub id: DefinitionId,
    }

    /// Asset represents some sort of commodity or value.
    /// All possible variants of `Asset` entity's components.
    #[derive(
        Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Io, Encode, Decode,
    )]
    pub struct Asset {
        /// Component Identification.
        pub id: Id,
        /// Asset's Quantity.
        pub quantity: u32,
        /// Asset's Big Quantity.
        pub big_quantity: u128,
        /// Asset's key-value structured data.
        pub store: Store,
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
            }
        }

        /// `Asset` with `big_quantity` value constructor.
        pub fn with_big_quantity(id: Id, big_quantity: u128) -> Self {
            Asset {
                id,
                quantity: 0,
                big_quantity,
                store: Store::new(),
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

    impl From<Asset> for IdentifiableBox {
        fn from(asset: Asset) -> IdentifiableBox {
            IdentifiableBox::Asset(Box::new(asset))
        }
    }

    impl From<AssetDefinition> for IdentifiableBox {
        fn from(asset_definition: AssetDefinition) -> IdentifiableBox {
            IdentifiableBox::AssetDefinition(Box::new(asset_definition))
        }
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

    impl From<DefinitionId> for IdBox {
        fn from(id: DefinitionId) -> IdBox {
            IdBox::AssetDefinitionId(id)
        }
    }

    impl Display for Id {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{}@{}", self.definition_id, self.account_id)
        }
    }

    impl From<Id> for IdBox {
        fn from(id: Id) -> IdBox {
            IdBox::AssetId(id)
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{Asset, AssetDefinition, DefinitionId as AssetDefinitionId, Id as AssetId};
    }
}

pub mod domain {
    //! This module contains `Domain` structure and related implementations and trait implementations.

    use crate::{
        account::{Account, AccountsMap, GenesisAccount},
        asset::AssetDefinitionsMap,
        IdBox, Identifiable, IdentifiableBox, Name,
    };
    use iroha_crypto::PublicKey;
    use iroha_derive::Io;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};
    use std::{collections::BTreeMap, iter};

    /// Genesis domain name. Genesis domain should contain only genesis account.
    pub const GENESIS_DOMAIN_NAME: &str = "genesis";

    /// `DomainsMap` provides an API to work with collection of key (`Name`) - value
    /// (`Domain`) pairs.
    pub type DomainsMap = BTreeMap<Name, Domain>;

    /// Genesis domain. It will contain only one `genesis` account.
    #[derive(Debug)]
    pub struct GenesisDomain {
        genesis_account_public_key: PublicKey,
    }

    impl GenesisDomain {
        /// Returns `GenesisDomain`.
        pub fn new(genesis_account_public_key: PublicKey) -> Self {
            GenesisDomain {
                genesis_account_public_key,
            }
        }
    }

    impl From<GenesisDomain> for Domain {
        fn from(domain: GenesisDomain) -> Self {
            Domain {
                name: GENESIS_DOMAIN_NAME.to_string(),
                accounts: iter::once((
                    <Account as Identifiable>::Id::genesis_account(),
                    GenesisAccount::new(domain.genesis_account_public_key).into(),
                ))
                .collect(),
                asset_definitions: AssetDefinitionsMap::new(),
            }
        }
    }

    /// Named group of `Account` and `Asset` entities.
    #[derive(
        Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Io, Encode, Decode,
    )]
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

    impl From<Domain> for IdentifiableBox {
        fn from(domain: Domain) -> IdentifiableBox {
            IdentifiableBox::Domain(Box::new(domain))
        }
    }

    impl From<Name> for IdBox {
        fn from(name: Name) -> IdBox {
            IdBox::DomainName(name)
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{Domain, GenesisDomain, GENESIS_DOMAIN_NAME};
    }
}

pub mod peer {
    //! This module contains `Peer` structure and related implementations and traits implementations.

    use crate::{
        domain::DomainsMap, isi::InstructionBox, IdBox, Identifiable, IdentifiableBox, Parameter,
        PublicKey,
    };
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
        /// Iroha parameters.
        pub parameters: Vec<Parameter>,
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
                parameters: Vec::new(),
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
                parameters: Vec::new(),
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

    impl From<Peer> for IdentifiableBox {
        fn from(peer: Peer) -> IdentifiableBox {
            IdentifiableBox::Peer(Box::new(peer))
        }
    }

    impl From<Id> for IdBox {
        fn from(id: Id) -> IdBox {
            IdBox::PeerId(id)
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{Id as PeerId, Peer};
    }
}

pub mod transaction {
    //! This module contains `Transaction` structures and related implementations
    //! and traits implementations.

    use crate::{account::Account, isi::InstructionBox, Identifiable};
    use iroha_crypto::prelude::*;
    use iroha_derive::Io;
    use parity_scale_codec::{Decode, Encode};
    use std::time::SystemTime;

    /// This structure represents transaction in non-trusted form.
    ///
    /// `Iroha` and its' clients use `Transaction` to send transactions via network.
    /// Direct usage in business logic is strongly prohibited. Before any interactions
    /// `accept`.
    #[derive(Clone, Debug, Io, Encode, Decode)]
    pub struct Transaction {
        /// `Transaction` payload.
        pub payload: Payload,
        /// `Transaction`'s `Signature`s.
        pub signatures: Vec<Signature>,
    }

    /// Iroha `Transaction` payload.
    #[derive(Clone, Debug, Io, Encode, Decode)]
    pub struct Payload {
        /// Account ID of transaction creator.
        pub account_id: <Account as Identifiable>::Id,
        /// An ordered set of instructions.
        pub instructions: Vec<InstructionBox>,
        /// Time of creation (unix time, in milliseconds).
        pub creation_time: u64,
        /// The transaction will be dropped after this time if it is still in a `Queue`.
        pub time_to_live_ms: u64,
    }

    impl Transaction {
        /// Default `Transaction` constructor.
        pub fn new(
            instructions: Vec<InstructionBox>,
            account_id: <Account as Identifiable>::Id,
            proposed_ttl_ms: u64,
        ) -> Transaction {
            Transaction {
                payload: Payload {
                    instructions,
                    account_id,
                    creation_time: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .expect("Failed to get System Time.")
                        .as_millis() as u64,
                    time_to_live_ms: proposed_ttl_ms,
                },
                signatures: Vec::new(),
            }
        }

        /// Calculate transaction `Hash`.
        pub fn hash(&self) -> Hash {
            let bytes: Vec<u8> = self.payload.clone().into();
            Hash::new(&bytes)
        }

        /// Sign transaction with the provided key pair.
        ///
        /// Returns `Ok(Transaction)` if succeeded and `Err(String)` if failed.
        pub fn sign(self, key_pair: &KeyPair) -> Result<Transaction, String> {
            let mut signatures = self.signatures.clone();
            signatures.push(Signature::new(key_pair.clone(), self.hash().as_ref())?);
            Ok(Transaction {
                payload: self.payload,
                signatures,
            })
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{Payload, Transaction};
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{
        account::prelude::*, asset::prelude::*, domain::prelude::*, peer::prelude::*,
        transaction::prelude::*, Bytes, IdBox, Identifiable, IdentifiableBox, Name, Parameter,
        Value, ValueBox,
    };
    pub use crate::{isi::prelude::*, query::prelude::*};
}
