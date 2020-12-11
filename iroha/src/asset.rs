//! This module contains `Asset` structure, it's implementation and related traits and
//! instructions implementations.

use crate::{isi::prelude::*, prelude::*};
use iroha_data_model::prelude::*;
use iroha_derive::log;

/// Iroha Special Instructions module provides `AssetInstruction` enum with all possible types of
/// Asset related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `AssetInstruction` variants into generic ISI.
pub mod isi {
    use super::*;

    impl Execute for Mint<Asset, u32> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            let mut world_state_view = world_state_view.clone();
            let _ = world_state_view
                .asset_definition_entry(&self.destination_id.definition_id)
                .ok_or("Failed to find asset.")?;
            match world_state_view.asset(&self.destination_id) {
                Some(asset) => {
                    asset.quantity += self.object;
                }
                None => world_state_view.add_asset(Asset::with_quantity(
                    self.destination_id.clone(),
                    self.object,
                )),
            }
            Ok(world_state_view)
        }
    }

    impl Execute for Mint<Asset, u128> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            let mut world_state_view = world_state_view.clone();
            let _ = world_state_view
                .asset_definition_entry(&self.destination_id.definition_id)
                .ok_or("Failed to find asset.")?;
            match world_state_view.asset(&self.destination_id) {
                Some(asset) => {
                    asset.big_quantity += self.object;
                }
                None => world_state_view.add_asset(Asset::with_big_quantity(
                    self.destination_id.clone(),
                    self.object,
                )),
            }
            Ok(world_state_view)
        }
    }

    impl Execute for Mint<Asset, (String, Bytes)> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            let mut world_state_view = world_state_view.clone();
            let _ = world_state_view
                .asset_definition_entry(&self.destination_id.definition_id)
                .ok_or(format!(
                    "Failed to find asset definition. {:?}",
                    &self.destination_id.definition_id
                ))?;
            match world_state_view.asset(&self.destination_id) {
                Some(asset) => {
                    let _ = asset
                        .store
                        .insert(self.object.0.clone(), self.object.1.clone());
                }
                None => world_state_view.add_asset(Asset::with_parameter(
                    self.destination_id.clone(),
                    self.object.clone(),
                )),
            }
            Ok(world_state_view)
        }
    }

    impl Execute for Burn<Asset, u32> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            let mut world_state_view = world_state_view.clone();
            let _ = world_state_view
                .asset_definition_entry(&self.destination_id.definition_id)
                .ok_or("Failed to find asset.")?;
            let asset = world_state_view
                .asset(&self.destination_id)
                .ok_or("Asset not found.")?;
            asset.quantity = asset
                .quantity
                .checked_sub(self.object)
                .ok_or("Not enough quantity to burn.")?;
            Ok(world_state_view)
        }
    }

    impl Execute for Burn<Asset, u128> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            let mut world_state_view = world_state_view.clone();
            let _ = world_state_view
                .asset_definition_entry(&self.destination_id.definition_id)
                .ok_or("Failed to find asset.")?;
            let asset = world_state_view
                .asset(&self.destination_id)
                .ok_or("Asset not found.")?;
            asset.big_quantity = asset
                .big_quantity
                .checked_sub(self.object)
                .ok_or("Not enough big quantity to burn.")?;
            Ok(world_state_view)
        }
    }

    impl Execute for Burn<Asset, Name> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            let mut world_state_view = world_state_view.clone();
            let _ = world_state_view
                .asset_definition_entry(&self.destination_id.definition_id)
                .ok_or("Failed to find asset definition.")?;
            let asset = world_state_view
                .asset(&self.destination_id)
                .ok_or("Asset not found.")?;
            let _ = asset.store.remove(&self.object).ok_or("Key not found.")?;
            Ok(world_state_view)
        }
    }

    impl Execute for Transfer<Asset, u32, Asset> {
        #[log]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            let mut world_state_view = world_state_view.clone();
            let _ = world_state_view
                .asset_definition_entry(&self.source_id.definition_id)
                .ok_or("Failed to find asset.")?;
            let _ = world_state_view
                .asset_definition_entry(&self.destination_id.definition_id)
                .ok_or("Failed to find asset.")?;
            match world_state_view.asset(&self.source_id) {
                Some(asset) => {
                    if asset.quantity >= self.object {
                        asset.quantity -= self.object;
                    } else {
                        return Err("Source asset is too small.".to_string());
                    }
                }
                None => return Err("Source asset not found.".to_string()),
            }
            match world_state_view.asset(&self.destination_id) {
                Some(asset) => {
                    asset.quantity += self.object;
                }
                None => world_state_view.add_asset(Asset::with_quantity(
                    self.destination_id.clone(),
                    self.object,
                )),
            }
            Ok(world_state_view)
        }
    }
}

/// Query module provides `IrohaQuery` Asset related implementations.
pub mod query {
    use super::*;

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

    impl Query for FindAllAssetsDefinitions {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            let assets_definitions_entries: Vec<AssetDefinitionEntry> = world_state_view
                .read_all_assets_definitions_entries()
                .into_iter()
                .cloned()
                .collect();
            Ok(QueryResult::FindAllAssetsDefinitions(Box::new(
                FindAllAssetsDefinitionsResult {
                    assets_definitions_entries,
                },
            )))
        }
    }

    impl Query for FindAssetById {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            Ok(QueryResult::FindAssetById(Box::new(FindAssetByIdResult {
                asset: world_state_view
                    .read_asset(&self.id)
                    .map(Clone::clone)
                    .ok_or(format!(
                        "Failed to get an asset with identification: {}.",
                        &self.id
                    ))?,
            })))
        }
    }

    impl Query for FindAssetsByName {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            Ok(QueryResult::FindAssetsByName(Box::new(
                FindAssetsByNameResult {
                    assets: world_state_view
                        .read_all_assets()
                        .into_iter()
                        .filter(|asset| asset.id.definition_id.name == self.name)
                        .cloned()
                        .collect(),
                },
            )))
        }
    }

    impl Query for FindAssetsByAccountId {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            let assets: Vec<Asset> = world_state_view
                .read_account(&self.account_id)
                .ok_or(format!("No account with id: {} found.", &self.account_id))?
                .assets
                .values()
                .cloned()
                .collect();
            Ok(QueryResult::FindAssetsByAccountId(Box::new(
                FindAssetsByAccountIdResult { assets },
            )))
        }
    }

    impl Query for FindAssetsByAssetDefinitionId {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            Ok(QueryResult::FindAssetsByAssetDefinitionId(Box::new(
                FindAssetsByAssetDefinitionIdResult {
                    assets: world_state_view
                        .read_all_assets()
                        .into_iter()
                        .filter(|asset| asset.id.definition_id == self.asset_definition_id)
                        .cloned()
                        .collect(),
                },
            )))
        }
    }

    impl Query for FindAssetsByDomainName {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            Ok(QueryResult::FindAssetsByDomainName(Box::new(
                FindAssetsByDomainNameResult {
                    assets: world_state_view
                        .read_all_assets()
                        .into_iter()
                        .filter(|asset| asset.id.account_id.domain_name == self.domain_name)
                        .cloned()
                        .collect(),
                },
            )))
        }
    }

    impl Query for FindAssetsByAccountIdAndAssetDefinitionId {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            let assets: Vec<Asset> = world_state_view
                .read_account(&self.account_id)
                .ok_or(format!("No account with id: {} found.", &self.account_id))?
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

    impl Query for FindAssetsByDomainNameAndAssetDefinitionId {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            Ok(QueryResult::FindAssetsByDomainNameAndAssetDefinitionId(
                Box::new(FindAssetsByDomainNameAndAssetDefinitionIdResult {
                    assets: world_state_view
                        .read_all_assets()
                        .into_iter()
                        .filter(|asset| {
                            asset.id.account_id.domain_name == self.domain_name
                                && asset.id.definition_id == self.asset_definition_id
                        })
                        .cloned()
                        .collect(),
                }),
            ))
        }
    }

    impl Query for FindAssetQuantityById {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            Ok(QueryResult::FindAssetQuantityById(Box::new(
                FindAssetQuantityByIdResult {
                    quantity: world_state_view
                        .read_asset(&self.id)
                        .map(|asset| asset.quantity)
                        .ok_or(format!(
                            "Failed to get an asset with identification: {}.",
                            &self.id
                        ))?,
                },
            )))
        }
    }
}
