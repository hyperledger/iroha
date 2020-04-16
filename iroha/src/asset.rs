use crate::prelude::*;
use iroha_derive::log;
use parity_scale_codec::{Decode, Encode};

#[derive(Clone, Debug, Encode, Decode)]
pub struct Asset {
    /// identifier of asset, formatted as asset_name#domain_id
    pub id: Id,
    pub amount: u128,
}

impl Asset {
    pub fn new(id: Id) -> Self {
        Asset { id, amount: 0 }
    }

    pub fn with_amount(mut self, amount: u128) -> Self {
        self.amount = amount;
        self
    }
}

pub mod isi {
    use super::*;
    use crate::isi::Contract;
    use iroha_derive::{IntoContract, Io};
    use parity_scale_codec::{Decode, Encode};

    /// The purpose of add asset quantity command is to increase the quantity of an asset on account of
    /// transaction creator. Use case scenario is to increase the number of a mutable asset in the
    /// system, which can act as a claim on a commodity (e.g. money, gold, etc.).
    #[derive(Clone, Debug, PartialEq, Io, IntoContract, Encode, Decode)]
    pub struct AddAssetQuantity {
        pub asset_id: Id,
        pub account_id: Id,
        pub amount: u128,
    }

    impl Instruction for AddAssetQuantity {
        fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            let assets = &mut world_state_view
                .account(&self.account_id)
                .ok_or("Account not found.")?
                .assets;
            if let Some(asset) = assets.get_mut(&self.asset_id) {
                asset.amount += self.amount;
            } else {
                assets.insert(self.asset_id.clone(), Asset::new(self.asset_id.clone()));
                assets
                    .get_mut(&self.asset_id)
                    .ok_or("Failed to get asset.")?
                    .amount += self.amount;
            }
            Ok(())
        }
    }

    /// The purpose of сreate asset command is to create a new type of asset, unique in a domain.
    /// An asset is a countable representation of a commodity.
    #[derive(Clone, Debug, PartialEq, Io, IntoContract, Encode, Decode)]
    pub struct CreateAsset {
        pub asset_name: String,
        pub domain_id: String,
        pub decimals: u8,
    }

    /// The purpose of transfer asset command is to share assets within the account in peer
    /// network: in the way that source account transfers assets to the target account.
    #[derive(Clone, Debug, PartialEq, Io, IntoContract, Encode, Decode)]
    pub struct TransferAsset {
        pub source_account_id: Id,
        pub destination_account_id: Id,
        pub asset_id: Id,
        pub description: String,
        pub amount: u128,
    }

    impl Instruction for TransferAsset {
        fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            let asset = world_state_view
                .account(&self.source_account_id)
                .ok_or("Source account not found")?
                .assets
                .get_mut(&self.asset_id)
                .ok_or("Asset not found")?;
            asset.amount -= self.amount;
            let destination_account = world_state_view
                .account(&self.destination_account_id)
                .ok_or("Destionation account not found")?;
            match destination_account.assets.get_mut(&self.asset_id.clone()) {
                Some(asset) => {
                    asset.amount += self.amount;
                }
                None => {
                    destination_account.assets.insert(
                        self.destination_account_id.clone(),
                        Asset::new(self.asset_id.clone()).with_amount(self.amount),
                    );
                }
            }
            Ok(())
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
        account_id: Id,
    }

    #[derive(Debug, Encode, Decode)]
    pub struct GetAccountAssetsResult {
        pub assets: Vec<Asset>,
    }

    impl GetAccountAssets {
        pub fn new(account_id: Id) -> GetAccountAssets {
            GetAccountAssets { account_id }
        }

        pub fn build_request(account_id: Id) -> QueryRequest {
            let query = GetAccountAssets { account_id };
            QueryRequest {
                timestamp: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("Failed to get System Time.")
                    .as_millis(),
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
