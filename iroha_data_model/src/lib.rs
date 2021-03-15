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

pub mod events;
pub mod expression;
pub mod isi;
pub mod query;

use iroha_crypto::PublicKey;
use iroha_derive::FromVariant;
use iroha_error::{error, Error, Result};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt::Debug};

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
    /// Maximum time for a leader to create a block.
    BlockTime(u128),
    /// Maximum time for a proxy tail to send commit message.
    CommitTime(u128),
    /// Time to wait for a transaction Receipt.
    TransactionReceiptTime(u128),
}

/// Sized container for all possible identifications.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, FromVariant)]
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
    /// `World`.
    WorldId,
}

/// Sized container for all possible entities.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, FromVariant)]
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
    /// `World`.
    World,
}

/// Boxed `Value`.
pub type ValueBox = Box<Value>;

/// Sized container for all possible values.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub enum Value {
    /// `u32` integer.
    U32(u32),
    /// `bool` value.
    Bool(bool),
    /// `Vec` of `Value`.
    Vec(Vec<Value>),
    /// `Id` of `Asset`, `Account`, etc.
    Id(IdBox),
    /// `Identifiable` as `Asset`, `Account` etc.
    Identifiable(IdentifiableBox),
    /// `PublicKey`.
    PublicKey(PublicKey),
    /// Iroha `Parameter` variant.
    Parameter(Parameter),
    /// Signature check condition.
    SignatureCheckCondition(account::SignatureCheckCondition),
}

#[allow(clippy::len_without_is_empty)]
impl Value {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        use Value::*;

        match self {
            U32(_) | Id(_) | PublicKey(_) | Bool(_) | Parameter(_) | Identifiable(_) => 1,
            Vec(v) => v.iter().map(Self::len).sum::<usize>() + 1,
            SignatureCheckCondition(s) => s.0.len(),
        }
    }
}

impl TryFrom<Value> for u32 {
    type Error = Error;

    fn try_from(value: Value) -> Result<u32> {
        if let Value::U32(value) = value {
            Ok(value)
        } else {
            Err(error!("Value {:?} is not U32.", value))
        }
    }
}

impl TryFrom<Value> for bool {
    type Error = Error;

    fn try_from(value: Value) -> Result<bool> {
        if let Value::Bool(value) = value {
            Ok(value)
        } else {
            Err(error!("Value {:?} is not bool.", value))
        }
    }
}

impl TryFrom<Value> for Vec<Value> {
    type Error = Error;

    fn try_from(value: Value) -> Result<Vec<Value>> {
        if let Value::Vec(value) = value {
            Ok(value)
        } else {
            Err(error!("Value {:?} is not vec.", value))
        }
    }
}

impl TryFrom<Value> for IdBox {
    type Error = Error;

    fn try_from(value: Value) -> Result<IdBox> {
        if let Value::Id(value) = value {
            Ok(value)
        } else {
            Err(error!("Value {:?} is not an id.", value))
        }
    }
}

impl TryFrom<Value> for IdentifiableBox {
    type Error = Error;

    fn try_from(value: Value) -> Result<IdentifiableBox> {
        if let Value::Identifiable(value) = value {
            Ok(value)
        } else {
            Err(error!("Value {:?} is not an identifiable entity.", value))
        }
    }
}

impl TryFrom<Value> for PublicKey {
    type Error = Error;

    fn try_from(value: Value) -> Result<PublicKey> {
        if let Value::PublicKey(value) = value {
            Ok(value)
        } else {
            Err(error!("Value {:?} is not a public key.", value))
        }
    }
}

impl TryFrom<Value> for Parameter {
    type Error = Error;

    fn try_from(value: Value) -> Result<Parameter> {
        if let Value::Parameter(value) = value {
            Ok(value)
        } else {
            Err(error!("Value {:?} is not a parameter.", value))
        }
    }
}

impl From<u32> for Value {
    fn from(value: u32) -> Value {
        Value::U32(value)
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Value {
        Value::Bool(value)
    }
}

impl From<Parameter> for Value {
    fn from(value: Parameter) -> Value {
        Value::Parameter(value)
    }
}

impl From<IdentifiableBox> for Value {
    fn from(value: IdentifiableBox) -> Value {
        Value::Identifiable(value)
    }
}

impl From<IdBox> for Value {
    fn from(value: IdBox) -> Value {
        Value::Id(value)
    }
}

impl<V: Into<Value>> From<Vec<V>> for Value {
    fn from(values: Vec<V>) -> Value {
        Value::Vec(values.into_iter().map(|value| value.into()).collect())
    }
}

impl From<PublicKey> for Value {
    fn from(value: PublicKey) -> Value {
        Value::PublicKey(value)
    }
}

impl From<u128> for Value {
    fn from(_: u128) -> Value {
        unimplemented!()
    }
}

impl From<String> for Value {
    fn from(_: String) -> Value {
        unimplemented!()
    }
}

impl From<(String, Vec<u8>)> for Value {
    fn from(_: (String, Vec<u8>)) -> Value {
        unimplemented!()
    }
}

/// Marker trait for values.
pub trait ValueMarker: Debug + Clone + Into<Value> {}

impl<V: Into<Value> + Debug + Clone> ValueMarker for V {}

/// This trait marks entity that implement it as identifiable with an `Id` type to find them by.
pub trait Identifiable: Debug + Clone {
    /// Defines the type of entity's identification.
    type Id: Into<IdBox> + Debug + Clone + Eq + Ord;
}

pub mod world {
    //! Structures, traits and impls related to `World`.

    use crate::{
        domain::DomainsMap, isi::Instruction, peer::PeersIds, IdBox, Identifiable, IdentifiableBox,
        Parameter,
    };

    /// The global entity consisting of `domains`, `triggers` and etc.
    /// For exmaple registration of domain, will have this as an ISI target.
    #[derive(Debug, Clone, Default)]
    pub struct World {
        /// Registered domains.
        pub domains: DomainsMap,
        /// Identifications of discovered trusted peers.
        pub trusted_peers_ids: PeersIds,
        /// Iroha `Triggers` registered on the peer.
        pub triggers: Vec<Instruction>,
        /// Iroha parameters.
        pub parameters: Vec<Parameter>,
    }

    impl World {
        /// Creates an empty `World`.
        pub fn new() -> Self {
            Self::default()
        }

        /// Creates `World` with these `domains` and `trusted_peers_ids`
        pub fn with(domains: DomainsMap, trusted_peers_ids: PeersIds) -> Self {
            World {
                domains,
                trusted_peers_ids,
                ..World::new()
            }
        }
    }

    /// The ID of the `World`. The `World` has only a single instance, therefore the ID has no fields.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Copy)]
    pub struct WorldId;

    impl From<WorldId> for IdBox {
        fn from(_: WorldId) -> IdBox {
            IdBox::WorldId
        }
    }

    impl Identifiable for World {
        type Id = WorldId;
    }

    impl From<World> for IdentifiableBox {
        fn from(_: World) -> Self {
            IdentifiableBox::World
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {

        pub use super::{World, WorldId};
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
        asset::AssetsMap,
        domain::GENESIS_DOMAIN_NAME,
        expression::{ContainsAny, ContextValue, EvaluatesTo, ExpressionBox, WhereBuilder},
        permissions::PermissionRaw,
        Identifiable, Name, PublicKey, Value,
    };
    use iroha_derive::Io;
    use serde::{Deserialize, Serialize};
    //TODO: get rid of it?
    use iroha_crypto::prelude::*;
    use iroha_error::{error, Error, Result};
    use parity_scale_codec::{Decode, Encode};
    use std::{collections::BTreeMap, fmt, iter::FromIterator};

    /// `AccountsMap` provides an API to work with collection of key (`Id`) - value
    /// (`Account`) pairs.
    pub type AccountsMap = BTreeMap<Id, Account>;
    type Signatories = Vec<PublicKey>;
    type Permissions = Vec<PermissionRaw>;

    /// Genesis account name.
    pub const GENESIS_ACCOUNT_NAME: &str = "genesis";

    /// The context value name for transaction signatories.
    pub const TRANSACTION_SIGNATORIES_VALUE: &str = "transaction_signatories";

    /// The context value name for account signatories.
    pub const ACCOUNT_SIGNATORIES_VALUE: &str = "account_signatories";

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

    /// Condition which checks if the account has the right signatures.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Io, Encode, Decode)]
    pub struct SignatureCheckCondition(pub EvaluatesTo<bool>);

    impl SignatureCheckCondition {
        /// Gets reference to the raw `ExpressionBox`.
        pub fn as_expression(&self) -> &ExpressionBox {
            let Self(condition) = self;
            &condition.expression
        }
    }

    impl From<EvaluatesTo<bool>> for SignatureCheckCondition {
        fn from(condition: EvaluatesTo<bool>) -> Self {
            SignatureCheckCondition(condition)
        }
    }

    /// Default signature condition check for accounts. Returns true if any of the signatories have signed a transaction.
    impl Default for SignatureCheckCondition {
        fn default() -> Self {
            Self(
                ContainsAny::new(
                    ContextValue::new(TRANSACTION_SIGNATORIES_VALUE),
                    ContextValue::new(ACCOUNT_SIGNATORIES_VALUE),
                )
                .into(),
            )
        }
    }

    /// Account entity is an authority which is used to execute `Iroha Special Insturctions`.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Io, Encode, Decode)]
    pub struct Account {
        /// An Identification of the `Account`.
        pub id: Id,
        /// Asset's in this `Account`.
        pub assets: AssetsMap,
        /// `Account`'s signatories.
        pub signatories: Signatories,
        /// Permissions of this account
        pub permissions: Permissions,
        /// Condition which checks if the account has the right signatures.
        #[serde(default)]
        #[codec(skip)]
        pub signature_check_condition: SignatureCheckCondition,
    }

    impl PartialOrd for Account {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            self.id.partial_cmp(&other.id)
        }
    }

    impl Ord for Account {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.id.cmp(&other.id)
        }
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
                signature_check_condition: Default::default(),
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
                signature_check_condition: Default::default(),
            }
        }

        /// Returns a prebuilt expression that when executed
        /// returns if the needed signatures are gathered.
        pub fn check_signature_condition(&self, signatures: &[Signature]) -> EvaluatesTo<bool> {
            let transaction_signatories: Signatories = signatures
                .iter()
                .cloned()
                .map(|signature| signature.public_key)
                .collect();
            WhereBuilder::evaluate(self.signature_check_condition.as_expression().clone())
                .with_value(
                    TRANSACTION_SIGNATORIES_VALUE.to_string(),
                    transaction_signatories,
                )
                .with_value(
                    ACCOUNT_SIGNATORIES_VALUE.to_string(),
                    self.signatories.clone(),
                )
                .build()
                .into()
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

    impl From<Account> for Value {
        fn from(account: Account) -> Self {
            Value::Identifiable(account.into())
        }
    }

    impl FromIterator<Account> for Value {
        fn from_iter<T: IntoIterator<Item = Account>>(iter: T) -> Self {
            iter.into_iter()
                .map(|account| account.into())
                .collect::<Vec<Value>>()
                .into()
        }
    }

    impl From<SignatureCheckCondition> for Value {
        fn from(condition: SignatureCheckCondition) -> Value {
            Value::SignatureCheckCondition(condition)
        }
    }

    /// Account Identification is represented by `name@domain_name` string.
    impl std::str::FromStr for Id {
        type Err = Error;

        fn from_str(string: &str) -> Result<Self, Self::Err> {
            let vector: Vec<&str> = string.split('@').collect();
            if vector.len() != 2 {
                return Err(error!("Id should have format `name@domain_name`"));
            }
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
        pub use super::{Account, Id as AccountId, SignatureCheckCondition};
    }
}

pub mod asset {
    //! This module contains `Asset` structure, it's implementation and related traits and
    //! instructions implementations.

    use crate::{account::prelude::*, Bytes, Identifiable, Name, Value};
    use iroha_derive::Io;
    use iroha_error::{error, Error, Result};
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};
    use std::{
        cmp::Ordering,
        collections::BTreeMap,
        fmt::{self, Display, Formatter},
        iter::FromIterator,
        str::FromStr,
    };

    /// `AssetsMap` provides an API to work with collection of key (`Id`) - value
    /// (`Asset`) pairs.
    pub type AssetsMap = BTreeMap<Id, Asset>;
    /// `AssetDefinitionsMap` provides an API to work with collection of key (`DefinitionId`) - value
    /// (`AssetDefinition`) pairs.
    pub type AssetDefinitionsMap = BTreeMap<DefinitionId, AssetDefinitionEntry>;
    /// Collection of `Bytes` represented parameters and their names.
    pub type Store = BTreeMap<Name, Bytes>;

    /// An entry in `AssetDefinitionsMap`.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Io, Encode, Decode)]
    pub struct AssetDefinitionEntry {
        /// Asset definition.
        pub definition: AssetDefinition,
        /// The account that registered this asset.
        pub registered_by: AccountId,
    }

    impl PartialOrd for AssetDefinitionEntry {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.definition.cmp(&other.definition))
        }
    }

    impl Ord for AssetDefinitionEntry {
        fn cmp(&self, other: &Self) -> Ordering {
            self.definition.cmp(&other.definition)
        }
    }

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
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Io, Encode, Decode)]
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

    impl PartialOrd for Asset {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.id.cmp(&other.id))
        }
    }

    impl Ord for Asset {
        fn cmp(&self, other: &Self) -> Ordering {
            self.id.cmp(&other.id)
        }
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

    impl Identifiable for AssetDefinition {
        type Id = DefinitionId;
    }

    impl From<Asset> for Value {
        fn from(asset: Asset) -> Value {
            Value::Identifiable(asset.into())
        }
    }

    impl FromIterator<Asset> for Value {
        fn from_iter<T: IntoIterator<Item = Asset>>(iter: T) -> Self {
            iter.into_iter()
                .map(|asset| asset.into())
                .collect::<Vec<Value>>()
                .into()
        }
    }

    impl From<AssetDefinition> for Value {
        fn from(asset_definition: AssetDefinition) -> Value {
            Value::Identifiable(asset_definition.into())
        }
    }

    impl FromIterator<AssetDefinition> for Value {
        fn from_iter<T: IntoIterator<Item = AssetDefinition>>(iter: T) -> Self {
            iter.into_iter()
                .map(|asset_definition| asset_definition.into())
                .collect::<Vec<Value>>()
                .into()
        }
    }

    /// Asset Identification is represented by `name#domain_name` string.
    impl FromStr for DefinitionId {
        type Err = Error;

        fn from_str(string: &str) -> Result<Self, Self::Err> {
            let vector: Vec<&str> = string.split('#').collect();
            if vector.len() != 2 {
                return Err(error!(
                    "Asset definition ID should have format `name#domain_name`.",
                ));
            }
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

    impl Display for Id {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{}@{}", self.definition_id, self.account_id)
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{
            Asset, AssetDefinition, AssetDefinitionEntry, DefinitionId as AssetDefinitionId,
            Id as AssetId,
        };
    }
}

pub mod domain {
    //! This module contains `Domain` structure and related implementations and trait implementations.

    use crate::{
        account::{Account, AccountsMap, GenesisAccount},
        asset::AssetDefinitionsMap,
        Identifiable, Name, Value,
    };
    use iroha_crypto::PublicKey;
    use iroha_derive::Io;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};
    use std::{cmp::Ordering, collections::BTreeMap, iter, iter::FromIterator};

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
            Self {
                name: GENESIS_DOMAIN_NAME.to_string(),
                accounts: iter::once((
                    <Account as Identifiable>::Id::genesis_account(),
                    GenesisAccount::new(domain.genesis_account_public_key).into(),
                ))
                .collect(),
                asset_definitions: Default::default(),
            }
        }
    }

    /// Named group of `Account` and `Asset` entities.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Io, Encode, Decode)]
    pub struct Domain {
        /// Domain name, for example company name.
        pub name: Name,
        /// Accounts of the domain.
        pub accounts: AccountsMap,
        /// Assets of the domain.
        pub asset_definitions: AssetDefinitionsMap,
    }

    impl PartialOrd for Domain {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.name.cmp(&other.name))
        }
    }

    impl Ord for Domain {
        fn cmp(&self, other: &Self) -> Ordering {
            self.name.cmp(&other.name)
        }
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

    impl From<Domain> for Value {
        fn from(domain: Domain) -> Value {
            Value::Identifiable(domain.into())
        }
    }

    impl FromIterator<Domain> for Value {
        fn from_iter<T: IntoIterator<Item = Domain>>(iter: T) -> Self {
            iter.into_iter()
                .map(|domain| domain.into())
                .collect::<Vec<Value>>()
                .into()
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{Domain, GenesisDomain, GENESIS_DOMAIN_NAME};
    }
}

pub mod peer {
    //! This module contains `Peer` structure and related implementations and traits implementations.

    use crate::{Identifiable, PublicKey, Value};
    use iroha_derive::Io;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};
    use std::{collections::BTreeSet, iter::FromIterator};

    /// Ids of peers.
    pub type PeersIds = BTreeSet<Id>;

    /// Peer represents Iroha instance.
    #[derive(
        Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Io, Encode, Decode,
    )]
    pub struct Peer {
        /// Peer Identification.
        pub id: Id,
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
            Peer { id }
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

    impl From<Id> for Value {
        fn from(id: Id) -> Value {
            Value::Id(id.into())
        }
    }

    impl FromIterator<Id> for Value {
        fn from_iter<T: IntoIterator<Item = Id>>(iter: T) -> Self {
            iter.into_iter()
                .map(|id| id.into())
                .collect::<Vec<Value>>()
                .into()
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

    use crate::{account::Account, isi::Instruction, Identifiable};
    use iroha_crypto::prelude::*;
    use iroha_derive::Io;
    use iroha_error::{error, Result};
    use iroha_version::{declare_versioned_with_scale, version_with_scale};
    use parity_scale_codec::{Decode, Encode};
    use std::{iter::FromIterator, time::SystemTime, vec::IntoIter as VecIter};

    #[cfg(feature = "http_error")]
    use {
        iroha_http_server::http::HttpResponse,
        iroha_version::{error::Error as VersionError, scale::EncodeVersioned},
    };

    /// Maximum number of instructions and expressions per transaction
    pub const MAX_INSTRUCTION_NUMBER: usize = 4096;

    declare_versioned_with_scale!(VersionedTransaction 1..2);

    /// This structure represents transaction in non-trusted form.
    ///
    /// `Iroha` and its' clients use `Transaction` to send transactions via network.
    /// Direct usage in business logic is strongly prohibited. Before any interactions
    /// `accept`.
    #[version_with_scale(n = 1, versioned = "VersionedTransaction")]
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
        pub instructions: Vec<Instruction>,
        /// Time of creation (unix time, in milliseconds).
        pub creation_time: u64,
        /// The transaction will be dropped after this time if it is still in a `Queue`.
        pub time_to_live_ms: u64,
    }

    impl Transaction {
        /// Default `Transaction` constructor.
        pub fn new(
            instructions: Vec<Instruction>,
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

        /// Checks if number of instructions in payload exceeds maximum
        pub fn check_instruction_len(&self, max_instruction_number: usize) -> Result<()> {
            if self
                .payload
                .instructions
                .iter()
                .map(Instruction::len)
                .sum::<usize>()
                > max_instruction_number
            {
                return Err(error!("Too many instructions in payload"));
            }
            Ok(())
        }

        /// Sign transaction with the provided key pair.
        ///
        /// Returns `Ok(Transaction)` if succeeded and `Err(String)` if failed.
        pub fn sign(self, key_pair: &KeyPair) -> Result<Transaction> {
            let mut signatures = self.signatures.clone();
            signatures.push(Signature::new(key_pair.clone(), self.hash().as_ref())?);
            Ok(Transaction {
                payload: self.payload,
                signatures,
            })
        }
    }

    impl Payload {
        /// Used to compare the contents of the transaction independent of when it was created.
        pub fn equals_excluding_creation_time(&self, other: &Payload) -> bool {
            self.account_id == other.account_id
                && self.instructions == other.instructions
                && self.time_to_live_ms == other.time_to_live_ms
        }
    }

    declare_versioned_with_scale!(VersionedPendingTransactions 1..2);

    #[cfg(feature = "http_error")]
    impl std::convert::TryInto<HttpResponse> for VersionedPendingTransactions {
        type Error = VersionError;
        fn try_into(self) -> Result<HttpResponse, Self::Error> {
            self.encode_versioned()
                .map(|pending| HttpResponse::ok(Default::default(), pending))
        }
    }

    /// Represents a collection of transactions that the peer sends to describe its pending transactions in a queue.
    #[version_with_scale(n = 1, versioned = "VersionedPendingTransactions")]
    #[derive(Debug, Clone, Encode, Decode, Io)]
    pub struct PendingTransactions(pub Vec<Transaction>);

    impl FromIterator<Transaction> for PendingTransactions {
        fn from_iter<T: IntoIterator<Item = Transaction>>(iter: T) -> Self {
            PendingTransactions(iter.into_iter().collect())
        }
    }

    impl IntoIterator for PendingTransactions {
        type Item = Transaction;

        type IntoIter = VecIter<Self::Item>;

        fn into_iter(self) -> Self::IntoIter {
            let PendingTransactions(transactions) = self;
            transactions.into_iter()
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this module.
    pub mod prelude {
        pub use super::{
            Payload, PendingTransactions, Transaction, VersionedPendingTransactions,
            VersionedTransaction,
        };
    }
}

/// Structures and traits related to pagination.
pub mod pagination {
    use iroha_error::Result;
    #[cfg(feature = "http_error")]
    use iroha_http_server::http::{HttpResponseError, StatusCode, HTTP_CODE_BAD_REQUEST};
    use std::{collections::BTreeMap, convert::TryFrom, fmt};

    /// Describes a collection to which pagination can be applied.
    /// Implemented for the [`Iterator`] implementors.
    pub trait Paginate: Iterator + Sized {
        /// Returns a paginated [`Iterator`].
        fn paginate(self, pagination: Pagination) -> Paginated<Self>;
    }

    impl<I: Iterator + Sized> Paginate for I {
        fn paginate(self, pagination: Pagination) -> Paginated<Self> {
            Paginated {
                pagination,
                iter: self,
            }
        }
    }

    /// Paginated [`Iterator`].
    /// Not recommended to use directly, only use in iterator chains.
    #[derive(Debug)]
    pub struct Paginated<I: Iterator> {
        pagination: Pagination,
        iter: I,
    }

    impl<I: Iterator> Iterator for Paginated<I> {
        type Item = I::Item;

        fn next(&mut self) -> Option<Self::Item> {
            if let Some(limit) = self.pagination.limit.as_mut() {
                if *limit == 0 {
                    return None;
                } else {
                    *limit -= 1
                }
            }
            if let Some(start) = self.pagination.start.take() {
                self.iter.nth(start)
            } else {
                self.iter.next()
            }
        }
    }

    /// Structure for pagination requests
    #[derive(Clone, Eq, PartialEq, Debug, Default, Copy)]
    pub struct Pagination {
        /// start of indexing
        pub start: Option<usize>,
        /// limit of indexing
        pub limit: Option<usize>,
    }

    impl Pagination {
        /// Constructs [`Pagination`].
        pub fn new(start: Option<usize>, limit: Option<usize>) -> Pagination {
            Pagination { start, limit }
        }
    }

    const PAGINATION_START: &str = "start";
    const PAGINATION_LIMIT: &str = "limit";

    /// Error for pagination
    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct PaginateError(pub std::num::ParseIntError);

    impl fmt::Display for PaginateError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Failed to decode pagination. Error occurred in one of numbers: {}",
                self.0
            )
        }
    }
    impl std::error::Error for PaginateError {}

    #[cfg(feature = "http_error")]
    impl HttpResponseError for PaginateError {
        fn status_code(&self) -> StatusCode {
            HTTP_CODE_BAD_REQUEST
        }
        fn error_body(&self) -> Vec<u8> {
            self.to_string().into()
        }
    }

    impl<'a> TryFrom<&'a BTreeMap<String, String>> for Pagination {
        type Error = PaginateError;

        fn try_from(query_params: &'a BTreeMap<String, String>) -> Result<Self, PaginateError> {
            let get_num = |key| {
                query_params
                    .get(key)
                    .map(|value| value.parse::<usize>())
                    .transpose()
            };
            let start = get_num(PAGINATION_START).map_err(PaginateError)?;
            let limit = get_num(PAGINATION_LIMIT).map_err(PaginateError)?;
            Ok(Self { start, limit })
        }
    }
    impl TryFrom<BTreeMap<String, String>> for Pagination {
        type Error = PaginateError;
        fn try_from(query_params: BTreeMap<String, String>) -> Result<Self, PaginateError> {
            Self::try_from(&query_params)
        }
    }

    impl Into<BTreeMap<String, String>> for Pagination {
        fn into(self) -> BTreeMap<String, String> {
            let mut query_params = BTreeMap::new();
            if let Some(start) = self.start {
                let _ = query_params.insert(PAGINATION_START.to_owned(), start.to_string());
            }
            if let Some(limit) = self.limit {
                let _ = query_params.insert(PAGINATION_LIMIT.to_owned(), limit.to_string());
            }
            query_params
        }
    }

    impl Into<Vec<(&'static str, usize)>> for Pagination {
        fn into(self) -> Vec<(&'static str, usize)> {
            match (self.start, self.limit) {
                (Some(start), Some(limit)) => {
                    vec![(PAGINATION_START, start), (PAGINATION_LIMIT, limit)]
                }
                (Some(start), None) => vec![(PAGINATION_START, start)],
                (None, Some(limit)) => vec![(PAGINATION_LIMIT, limit)],
                (None, None) => Vec::new(),
            }
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this module.
    pub mod prelude {
        pub use super::*;
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn empty() {
            assert_eq!(
                vec![1, 2, 3]
                    .into_iter()
                    .paginate(Pagination::new(None, None))
                    .collect::<Vec<_>>(),
                vec![1, 2, 3]
            )
        }

        #[test]
        fn start() {
            assert_eq!(
                vec![1, 2, 3]
                    .into_iter()
                    .paginate(Pagination::new(Some(0), None))
                    .collect::<Vec<_>>(),
                vec![1, 2, 3]
            );
            assert_eq!(
                vec![1, 2, 3]
                    .into_iter()
                    .paginate(Pagination::new(Some(1), None))
                    .collect::<Vec<_>>(),
                vec![2, 3]
            );
            assert_eq!(
                vec![1, 2, 3]
                    .into_iter()
                    .paginate(Pagination::new(Some(3), None))
                    .collect::<Vec<_>>(),
                Vec::<usize>::new()
            );
        }

        #[test]
        fn limit() {
            assert_eq!(
                vec![1, 2, 3]
                    .into_iter()
                    .paginate(Pagination::new(None, Some(0)))
                    .collect::<Vec<_>>(),
                Vec::<usize>::new()
            );
            assert_eq!(
                vec![1, 2, 3]
                    .into_iter()
                    .paginate(Pagination::new(None, Some(2)))
                    .collect::<Vec<_>>(),
                vec![1, 2]
            );
            assert_eq!(
                vec![1, 2, 3]
                    .into_iter()
                    .paginate(Pagination::new(None, Some(4)))
                    .collect::<Vec<_>>(),
                vec![1, 2, 3]
            );
        }

        #[test]
        fn start_and_limit() {
            assert_eq!(
                vec![1, 2, 3]
                    .into_iter()
                    .paginate(Pagination::new(Some(1), Some(1)))
                    .collect::<Vec<_>>(),
                vec![2]
            )
        }
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{
        account::prelude::*, asset::prelude::*, domain::prelude::*, pagination::prelude::*,
        peer::prelude::*, transaction::prelude::*, world::prelude::*, Bytes, IdBox, Identifiable,
        IdentifiableBox, Name, Parameter, Value,
    };
    pub use crate::{
        events::prelude::*, expression::prelude::*, isi::prelude::*, query::prelude::*,
    };
}
