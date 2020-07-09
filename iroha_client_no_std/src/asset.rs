//! This module contains `Asset` structure and it's implementation.

use crate::permission::{Permission, Permissions};
use crate::prelude::*;
use parity_scale_codec::{Decode, Encode};
use std::{
    collections::BTreeMap,
    fmt::{self, Display, Formatter},
    hash::Hash,
};

/// Asset entity represents some sort of commodity or value.
#[derive(Clone, Debug, Encode, Decode)]
pub struct AssetDefinition {
    /// An Identification of the `Asset`.
    pub id: <AssetDefinition as Identifiable>::Id,
}

impl AssetDefinition {
    /// Constructor of the detached and empty `AssetDefinition` entity.
    ///
    /// This method can be used to create an `AssetDefinition` which should be registered in the domain.
    /// This method should not be used to create an `AssetDefinition` to work with as a part of the Iroha
    /// State.
    pub fn new(id: <AssetDefinition as Identifiable>::Id) -> Self {
        AssetDefinition { id }
    }
}

/// Represents a sequence of bytes. Used for storing encoded data.
pub type Bytes = Vec<u8>;

/// All possible variants of `Asset` entity's components.
#[derive(Clone, Debug, Encode, Decode)]
pub struct Asset {
    /// Component Identification.
    pub id: <Asset as Identifiable>::Id,
    /// Asset's Quantity associated with an `Account`.
    pub quantity: u32,
    /// Asset's Big Quantity associated with an `Account`.
    pub big_quantity: u128,
    /// Asset's key-value structured data associated with an `Account`.
    pub store: BTreeMap<String, Bytes>,
    /// Asset's key-value  (action, object_id) structured permissions associated with an `Account`.
    pub permissions: Permissions,
}

impl Asset {
    /// Constructor with filled `store` field.
    pub fn with_parameter(id: <Asset as Identifiable>::Id, parameter: (String, Bytes)) -> Self {
        let mut store = BTreeMap::new();
        store.insert(parameter.0, parameter.1);
        Self {
            id,
            quantity: 0,
            big_quantity: 0,
            store,
            permissions: Permissions::new(),
        }
    }

    /// Constructor with filled `quantity` field.
    pub fn with_quantity(id: <Asset as Identifiable>::Id, quantity: u32) -> Self {
        Self {
            id,
            quantity,
            big_quantity: 0,
            store: BTreeMap::new(),
            permissions: Permissions::new(),
        }
    }

    /// Constructor with filled `big_quantity` field.
    pub fn with_big_quantity(id: <Asset as Identifiable>::Id, big_quantity: u128) -> Self {
        Self {
            id,
            quantity: 0,
            big_quantity,
            store: BTreeMap::new(),
            permissions: Permissions::new(),
        }
    }

    /// Constructor with filled `permissions` field.
    pub fn with_permission(id: <Asset as Identifiable>::Id, permission: Permission) -> Self {
        let permissions = Permissions::single(permission);
        Self {
            id,
            quantity: 0,
            big_quantity: 0,
            store: BTreeMap::new(),
            permissions,
        }
    }
}

/// Identification of an Asset Definition. Consists of Asset's name and Domain's name.
///
/// # Example
///
/// ```
/// use iroha::asset::AssetDefinitionId as Id;
///
/// let id = Id::new("xor", "soramitsu");
/// ```
#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Eq, std::hash::Hash, Encode, Decode)]
pub struct AssetDefinitionId {
    /// Asset's name.
    pub name: String,
    /// Domain's name.
    pub domain_name: String,
}

impl AssetDefinitionId {
    /// `Id` constructor used to easily create an `Id` from three string slices - one for the
    /// asset's name, another one for the domain's name.
    pub fn new(name: &str, domain_name: &str) -> Self {
        AssetDefinitionId {
            name: name.to_string(),
            domain_name: domain_name.to_string(),
        }
    }
}

/// Asset Identification is represented by `name#domain_name` string.
impl From<&str> for AssetDefinitionId {
    fn from(string: &str) -> AssetDefinitionId {
        let vector: Vec<&str> = string.split('#').collect();
        AssetDefinitionId {
            name: String::from(vector[0]),
            domain_name: String::from(vector[1]),
        }
    }
}

impl Display for AssetDefinitionId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.name, self.domain_name)
    }
}

impl Identifiable for AssetDefinition {
    type Id = AssetDefinitionId;
}

/// Identification of an Asset's components include Entity Id (`Asset::Id`) and `Account::Id`.
#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Eq, Hash, Encode, Decode)]
pub struct AssetId {
    /// Entity Identification.
    pub definition_id: <AssetDefinition as Identifiable>::Id,
    /// Account Identification.
    pub account_id: <Account as Identifiable>::Id,
}

impl AssetId {
    /// `AssetId` constructor used to easily create an `AssetId` from an `AssetDefinitionId` and
    /// an `AccountId`.
    pub fn new(
        definition_id: <AssetDefinition as Identifiable>::Id,
        account_id: <Account as Identifiable>::Id,
    ) -> Self {
        AssetId {
            definition_id,
            account_id,
        }
    }
}

impl Identifiable for Asset {
    type Id = AssetId;
}

/// Iroha Special Instructions module provides `AssetInstruction` enum with all legal types of
/// Asset related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `AssetInstruction` variants into generic ISI.
pub mod isi {
    use super::*;
    use iroha_derive::*;

    /// Enumeration of all legal Asset related Instructions.
    #[derive(Clone, Debug, Io, Encode, Decode)]
    pub enum AssetInstruction {
        /// Variant of the generic `Mint` instruction for `u32` --> `Asset`.
        MintAsset(u32, <Asset as Identifiable>::Id),
        /// Variant of the generic `Mint` instruction for `u128` --> `Asset`.
        MintBigAsset(u128, <Asset as Identifiable>::Id),
        /// Variant of the generic `Mint` instruction for `(String, Bytes)` --> `Asset`.
        MintParameterAsset((String, Bytes), <Asset as Identifiable>::Id),
        /// Variant of the generic `Demint` instruction for `u32` --> `Asset`.
        DemintAsset(u32, <Asset as Identifiable>::Id),
        /// Variant of the generic `Demint` instruction for `u128` --> `Asset`.
        DemintBigAsset(u128, <Asset as Identifiable>::Id),
        /// Variant of the generic `Demint` instruction for `String` --> `Asset`.
        DemintParameterAsset(String, <Asset as Identifiable>::Id),
    }
}

/// Query module provides `IrohaQuery` Asset related implementations.
pub mod query {
    use super::*;
    use crate::query::IrohaQuery;
    use iroha_derive::{IntoQuery, Io};
    use parity_scale_codec::{Decode, Encode};
    use std::time::SystemTime;

    /// To get the state of all assets in an account (a balance),
    /// GetAccountAssets query can be used.
    #[derive(Clone, Debug, Io, IntoQuery, Encode, Decode)]
    pub struct GetAccountAssets {
        account_id: <Account as Identifiable>::Id,
    }

    /// Result of the `GetAccountAssets` execution.
    #[derive(Clone, Debug, Encode, Decode)]
    pub struct GetAccountAssetsResult {
        /// Assets types which are needed to be included in query result.
        pub assets: Vec<Asset>,
    }

    impl GetAccountAssets {
        /// Build a `GetAccountAssets` query in the form of a `QueryRequest`.
        pub fn build_request(account_id: <Account as Identifiable>::Id) -> QueryRequest {
            let query = GetAccountAssets { account_id };
            QueryRequest {
                timestamp: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("Failed to get System Time.")
                    .as_millis()
                    .to_string(),
                signature: Option::None,
                query: query.into(),
            }
        }
    }
}
