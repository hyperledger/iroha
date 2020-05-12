use crate::prelude::*;
use iroha_derive::log;
use parity_scale_codec::{Decode, Encode};

#[derive(Clone, Debug, Encode, Decode)]
pub struct Asset {
    /// identifier of asset, formatted as asset_name#domain_id
    pub id: Id,
    pub quantity: u128,
}

impl Asset {
    pub fn new(id: Id) -> Self {
        Asset { id, quantity: 0 }
    }

    pub fn with_quantity(mut self, quantity: u128) -> Self {
        self.quantity = quantity;
        self
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
    pub name: String,
    pub container: String,
    pub account: String,
}

impl Id {
    pub fn new(name: &str, container: &str, account: &str) -> Self {
        Id {
            name: name.to_string(),
            container: container.to_string(),
            account: account.to_string(),
        }
    }

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

pub mod isi {
    use super::*;
    use crate::isi::Mint;
    use iroha_derive::*;

    #[derive(Clone, Debug, Io, Encode, Decode)]
    pub enum AssetInstruction {
        MintAsset(u128, <Asset as Identifiable>::Id),
    }

    impl AssetInstruction {
        pub fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            match self {
                AssetInstruction::MintAsset(quantity, asset_id) => {
                    Mint::new(*quantity, asset_id.clone()).execute(world_state_view)
                }
            }
        }
    }

    impl Mint<Asset, u128> {
        pub fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
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

    #[derive(Debug, Encode, Decode)]
    pub struct GetAccountAssetsResult {
        pub assets: Vec<Asset>,
    }

    impl GetAccountAssets {
        pub fn new(account_id: <Account as Identifiable>::Id) -> GetAccountAssets {
            GetAccountAssets { account_id }
        }

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
