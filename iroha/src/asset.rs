//! This module contains `Asset` structure, it's implementation and related traits and
//! instructions implementations.

use crate::{isi::prelude::*, prelude::*};
use iroha_data_model::prelude::*;

/// Iroha Special Instructions module provides `AssetInstruction` enum with all possible types of
/// Asset related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `AssetInstruction` variants into generic ISI.
pub mod isi {
    use super::*;

    impl Execute for Mint<Asset, u32> {
        fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            permission::check(
                authority,
                Box::new(MintAsset::with_asset_definition(
                    self.destination_id.definition_id,
                )),
                world_state_view,
            )?;
            let mut world_state_view = world_state_view.clone();
            world_state_view
                .asset_definition(&self.destination_id.definition_id)
                .ok_or("Failed to find asset.")?;
            match world_state_view.asset(&self.destination_id) {
                Some(asset) => {
                    asset.quantity += self.object;
                }
                None => world_state_view
                    .add_asset(Asset::with_quantity(self.destination_id, self.object)),
            }
            Ok(world_state_view)
        }
    }

    impl Execute for Mint<Asset, u128> {
        fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            permission::check(
                authority,
                Box::new(MintAsset::with_asset_definition(
                    self.destination_id.definition_id,
                )),
                world_state_view,
            )?;
            let mut world_state_view = world_state_view.clone();
            world_state_view
                .asset_definition(&self.destination_id.definition_id)
                .ok_or("Failed to find asset.")?;
            match world_state_view.asset(&self.destination_id) {
                Some(asset) => {
                    asset.big_quantity += self.object;
                }
                None => world_state_view
                    .add_asset(Asset::with_big_quantity(self.destination_id, self.object)),
            }
            Ok(world_state_view)
        }
    }

    impl Execute for Mint<Asset, (String, Bytes)> {
        fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            permission::check(
                authority,
                Box::new(MintAsset::with_asset_definition(
                    self.destination_id.definition_id,
                )),
                world_state_view,
            )?;
            let mut world_state_view = world_state_view.clone();
            world_state_view
                .asset_definition(&self.destination_id.definition_id)
                .ok_or(format!(
                    "Failed to find asset definition. {:?}",
                    &self.destination_id.definition_id
                ))?;
            match world_state_view.asset(&self.destination_id) {
                Some(asset) => {
                    asset
                        .store
                        .insert(self.object.0.clone(), self.object.1.clone());
                }
                None => world_state_view.add_asset(Asset::with_parameter(
                    self.destination_id,
                    self.object.clone(),
                )),
            }
            Ok(world_state_view)
        }
    }

    impl Execute for Demint<Asset, u32> {
        fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            permission::check(
                authority,
                Box::new(DemintAsset::with_asset_definition(
                    self.destination_id.definition_id,
                )),
                world_state_view,
            )?;
            let mut world_state_view = world_state_view.clone();
            world_state_view
                .asset_definition(&self.destination_id.definition_id)
                .ok_or("Failed to find asset.")?;
            let asset = world_state_view
                .asset(&self.destination_id)
                .ok_or("Asset not found.")?;
            asset.quantity = asset
                .quantity
                .checked_sub(self.object)
                .ok_or("Not enough quantity to demint.")?;
            Ok(world_state_view)
        }
    }

    impl Execute for Demint<Asset, u128> {
        fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            permission::check(
                authority,
                Box::new(DemintAsset::with_asset_definition(
                    self.destination_id.definition_id,
                )),
                world_state_view,
            )?;
            let mut world_state_view = world_state_view.clone();
            world_state_view
                .asset_definition(&self.destination_id.definition_id)
                .ok_or("Failed to find asset.")?;
            let asset = world_state_view
                .asset(&self.destination_id)
                .ok_or("Asset not found.")?;
            asset.big_quantity = asset
                .big_quantity
                .checked_sub(self.object)
                .ok_or("Not enough big quantity to demint.")?;
            Ok(world_state_view)
        }
    }

    impl Execute for Demint<Asset, Name> {
        fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            permission::check(
                authority,
                Box::new(DemintAsset::with_asset_definition(
                    self.destination_id.definition_id,
                )),
                world_state_view,
            )?;
            let mut world_state_view = world_state_view.clone();
            world_state_view
                .asset_definition(&self.destination_id.definition_id)
                .ok_or("Failed to find asset definition.")?;
            let asset = world_state_view
                .asset(&self.destination_id)
                .ok_or("Asset not found.")?;
            asset.store.remove(&self.object).ok_or("Key not found.")?;
            Ok(world_state_view)
        }
    }
}

/// Query module provides `IrohaQuery` Asset related implementations.
pub mod query {
    use super::*;
    use crate::query::QueryResult;
    use iroha_derive::log;
    use iroha_derive::Io;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    /// Result of the `FindAllAssets` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAllAssetsResult {
        /// Assets types which are needed to be included in query result.
        pub assets: Vec<Asset>,
    }

    impl Query for FindAllAssets {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            let assets: Vec<Asset> = world_state_view
                .read_all_assets()
                .into_iter()
                .cloned()
                .collect();
            Ok(QueryResult::FindAllAssets(Box::new(FindAllAssetsResult {
                assets,
            })))
        }
    }

    /// Result of the `FindAllAssetsDefinitions` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAllAssetsDefinitionsResult {
        /// Assets types which are needed to be included in query result.
        pub assets_definitions: Vec<AssetDefinition>,
    }

    impl Query for FindAllAssetsDefinitions {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            let assets_definitions: Vec<AssetDefinition> = world_state_view
                .read_all_assets_definitions()
                .into_iter()
                .cloned()
                .collect();
            Ok(QueryResult::FindAllAssetsDefinitions(Box::new(
                FindAllAssetsDefinitionsResult { assets_definitions },
            )))
        }
    }

    /// Result of the `FindAssetsByAccountId` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAssetsByAccountIdResult {
        /// Assets types which are needed to be included in query result.
        pub assets: Vec<Asset>,
    }

    impl Query for FindAssetsByAccountId {
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
            Ok(QueryResult::FindAssetsByAccountId(Box::new(
                FindAssetsByAccountIdResult { assets },
            )))
        }
    }

    /// Result of the `FindAssetsByAccountId` execution.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct FindAssetsByAccountIdAndAssetDefinitionIdResult {
        /// Assets types which are needed to be included in query result.
        pub assets: Vec<Asset>,
    }

    impl Query for FindAssetsByAccountIdAndAssetDefinitionId {
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
                .filter(|asset| asset.id.definition_id == self.asset_definition_id)
                .collect();
            Ok(QueryResult::FindAssetsByAccountIdAndAssetDefinitionId(
                Box::new(FindAssetsByAccountIdAndAssetDefinitionIdResult { assets }),
            ))
        }
    }
}
