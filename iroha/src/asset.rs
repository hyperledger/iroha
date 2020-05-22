//! This module contains `Asset` structure, it's implementation and related traits and
//! instructions implementations.

use crate::{isi::prelude::*, prelude::*};
use iroha_derive::log;
use parity_scale_codec::{Decode, Encode};
use std::{collections::BTreeMap, hash::Hash};

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
    store: BTreeMap<String, String>,
}

impl Asset {
    /// Constructor with filled `quantity` field.
    pub fn with_quantity(id: <Asset as Identifiable>::Id, quantity: u32) -> Self {
        Self {
            id,
            quantity,
            big_quantity: 0,
            store: BTreeMap::new(),
        }
    }

    /// Constructor of the `Mint<Asset, u32>` Iroha Special Instruction.
    pub fn mint(&self, object: u32) -> Mint<Asset, u32> {
        Mint {
            object,
            destination_id: self.id.clone(),
        }
    }

    /// Constructor of the `Mint<Asset, u128>` Iroha Special Instruction.
    pub fn mint_big(&self, object: u128) -> Mint<Asset, u128> {
        Mint {
            object,
            destination_id: self.id.clone(),
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

impl Identifiable for AssetDefinition {
    type Id = AssetDefinitionId;
}

/// Identification of an Asset's components include Entitiy Id (`Asset::Id`) and `Account::Id`.
#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Eq, Hash, Encode, Decode)]
pub struct AssetId {
    /// Entity Identification.
    pub definition_id: <AssetDefinition as Identifiable>::Id,
    /// Account Identificatin.
    pub account_id: <Account as Identifiable>::Id,
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
    }

    impl AssetInstruction {
        /// Executes `AssetInstruction` on the given `WorldStateView`.
        /// Returns `Ok(())` if execution succeeded and `Err(String)` with error message if not.
        pub fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            match self {
                AssetInstruction::MintAsset(quantity, asset_id) => {
                    Mint::new(*quantity, asset_id.clone()).execute(world_state_view)
                }
                AssetInstruction::MintBigAsset(big_quantity, asset_id) => {
                    Mint::new(*big_quantity, asset_id.clone()).execute(world_state_view)
                }
            }
        }
    }

    impl Mint<Asset, u32> {
        fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            world_state_view
                .asset_definition(&self.destination_id.definition_id)
                .ok_or("Failed to find asset.")?;
            match world_state_view.asset(&self.destination_id) {
                Some(asset) => {
                    asset.quantity += self.object;
                }
                None => world_state_view.add_asset(Asset {
                    id: self.destination_id.clone(),
                    quantity: self.object,
                    big_quantity: 0,
                    store: BTreeMap::new(),
                }),
            }
            Ok(())
        }
    }

    impl Mint<Asset, u128> {
        fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            world_state_view
                .asset_definition(&self.destination_id.definition_id)
                .ok_or("Failed to find asset.")?;
            match world_state_view.asset(&self.destination_id) {
                Some(asset) => {
                    asset.big_quantity += self.object;
                }
                None => world_state_view.add_asset(Asset {
                    id: self.destination_id.clone(),
                    big_quantity: self.object,
                    quantity: 0,
                    store: BTreeMap::new(),
                }),
            }
            Ok(())
        }
    }

    impl From<Mint<Asset, u32>> for Instruction {
        fn from(instruction: Mint<Asset, u32>) -> Self {
            Instruction::Asset(AssetInstruction::MintAsset(
                instruction.object,
                instruction.destination_id,
            ))
        }
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
    #[derive(Debug, Io, IntoQuery, Encode, Decode)]
    pub struct GetAccountAssets {
        account_id: <Account as Identifiable>::Id,
    }

    /// Result of the `GetAccountAssets` execution.
    #[derive(Debug, Encode, Decode)]
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

    impl Query for GetAccountAssets {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            let assets: Vec<Asset> = world_state_view
                .read_account(&self.account_id)
                .ok_or(format!(
                    "No account with id: {:?} found in the current world state: {:?}.",
                    &self.account_id, world_state_view
                ))?
                .assets
                .values()
                .cloned()
                .collect();
            Ok(QueryResult::GetAccountAssets(GetAccountAssetsResult {
                assets,
            }))
        }
    }
}
