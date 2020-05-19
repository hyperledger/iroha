//! This module contains `Asset` structure, it's implementation and related traits and
//! instructions implementations.

use crate::{isi::prelude::*, prelude::*};
use iroha_derive::log;
use parity_scale_codec::{Decode, Encode};

/// Asset entity represents some sort of commodity or value.
#[derive(Clone, Debug, Encode, Decode)]
pub struct Asset {
    /// An Identification of the `Asset`.
    pub id: Id,
    /// Assets' quantity.
    pub quantity: u128,
}

impl Asset {
    /// Constructor of the detached and empty `Asset` entity.
    ///
    /// This method can be used to create an `Asset` which should be registered in the domain.
    /// This method should not be used to create an `Asset` to work with as a part of the Iroha
    /// State.
    pub fn new(id: Id) -> Self {
        Asset { id, quantity: 0 }
    }

    /// Feels the `Asset` with the quantity.
    pub fn with_quantity(mut self, quantity: u128) -> Self {
        self.quantity = quantity;
        self
    }

    /// Constructor of the `Mint<Asset, u128>` Iroha Special Instruction.
    pub fn mint(&self, object: u128) -> Mint<Asset, u128> {
        Mint {
            object,
            destination_id: self.id.clone(),
        }
    }
}

/// Identification of an Asset. Consists of Asset's name, Domain's name and Account's name.
///
/// # Example
///
/// ```
/// use iroha::asset::Id;
///
/// let id = Id::new("xor", "user", "company");
/// ```
#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Eq, std::hash::Hash, Encode, Decode)]
pub struct Id {
    /// Asset's name.
    pub name: String,
    /// Container's name.
    pub container: String,
    /// Account's name.
    pub account: String,
}

impl Id {
    /// `Id` constructor used to easily create an `Id` from three string slices - one for the
    /// asset's name, another one for the container's name and the last one for the account's
    /// name.
    pub fn new(name: &str, container: &str, account: &str) -> Self {
        Id {
            name: name.to_string(),
            container: container.to_string(),
            account: account.to_string(),
        }
    }

    /// Generate `Id` of the `Account` based on account's name and container's name.
    pub fn account_id(&self) -> <Account as Identifiable>::Id {
        <Account as Identifiable>::Id::new(&self.account, &self.container)
    }
}

impl From<&str> for Id {
    fn from(string: &str) -> Id {
        let vector: Vec<&str> = string.split('@').collect();
        Id {
            name: String::from(vector[0]),
            container: String::from(vector[1]),
            account: String::from(vector[2]),
        }
    }
}

impl Identifiable for Asset {
    type Id = Id;
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
        /// Variant of the generic `Mint` instruction for `u128` --> `Asset`.
        MintAsset(u128, <Asset as Identifiable>::Id),
    }

    impl AssetInstruction {
        /// Executes `AssetInstruction` on the given `WorldStateView`.
        /// Returns `Ok(())` if execution succeeded and `Err(String)` with error message if not.
        pub fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            match self {
                AssetInstruction::MintAsset(quantity, asset_id) => {
                    Mint::new(*quantity, asset_id.clone()).execute(world_state_view)
                }
            }
        }
    }

    impl Mint<Asset, u128> {
        fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            world_state_view
                .asset(&self.destination_id)
                .ok_or("Failed to find asset.")?
                .quantity += self.object;
            Ok(())
        }
    }

    impl From<Mint<Asset, u128>> for Instruction {
        fn from(instruction: Mint<Asset, u128>) -> Self {
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
    use crate::{asset::Asset, query::IrohaQuery};
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
