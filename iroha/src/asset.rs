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
    use iroha_error::{error, Result};

    impl Execute for Mint<Asset, u32> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let _ = world_state_view
                .asset_definition_entry(&self.destination_id.definition_id)
                .ok_or_else(|| error!("Failed to find asset."))?;
            match world_state_view.asset(&self.destination_id) {
                Some(asset) => {
                    let quantity: &mut u32 = asset.try_as_mut()?;
                    *quantity = quantity
                        .checked_add(self.object)
                        .ok_or_else(|| error!("Overflow occured."))?;
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
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let _ = world_state_view
                .asset_definition_entry(&self.destination_id.definition_id)
                .ok_or_else(|| error!("Failed to find asset."))?;
            match world_state_view.asset(&self.destination_id) {
                Some(asset) => {
                    let quantity: &mut u128 = asset.try_as_mut()?;
                    *quantity = quantity
                        .checked_add(self.object)
                        .ok_or_else(|| error!("Overflow occured."))?;
                }
                None => world_state_view.add_asset(Asset::with_big_quantity(
                    self.destination_id.clone(),
                    self.object,
                )),
            }
            Ok(world_state_view)
        }
    }

    impl Execute for SetKeyValue<Asset, String, Value> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let _ = world_state_view
                .asset_definition_entry(&self.object_id.definition_id)
                .ok_or_else(|| {
                    error!(
                        "Failed to find asset definition. {:?}",
                        &self.object_id.definition_id
                    )
                })?;
            match world_state_view.asset(&self.object_id) {
                Some(asset) => {
                    let store: &mut Metadata = asset.try_as_mut()?;
                    let _ = store.insert(self.key, self.value);
                }
                None => world_state_view.add_asset(Asset::with_parameter(
                    self.object_id,
                    self.key,
                    self.value,
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
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let _ = world_state_view
                .asset_definition_entry(&self.destination_id.definition_id)
                .ok_or_else(|| error!("Failed to find asset."))?;
            let asset = world_state_view
                .asset(&self.destination_id)
                .ok_or_else(|| error!("Asset not found."))?;
            let quantity: &mut u32 = asset.try_as_mut()?;
            *quantity = quantity
                .checked_sub(self.object)
                .ok_or_else(|| error!("Not enough quantity to burn."))?;
            Ok(world_state_view)
        }
    }

    impl Execute for Burn<Asset, u128> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let _ = world_state_view
                .asset_definition_entry(&self.destination_id.definition_id)
                .ok_or_else(|| error!("Failed to find asset."))?;
            let asset = world_state_view
                .asset(&self.destination_id)
                .ok_or_else(|| error!("Asset not found."))?;
            let quantity: &mut u128 = asset.try_as_mut()?;
            *quantity = quantity
                .checked_sub(self.object)
                .ok_or_else(|| error!("Not enough quantity to burn."))?;
            Ok(world_state_view)
        }
    }

    impl Execute for RemoveKeyValue<Asset, String> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let _ = world_state_view
                .asset_definition_entry(&self.object_id.definition_id)
                .ok_or_else(|| error!("Failed to find asset definition."))?;
            let asset = world_state_view
                .asset(&self.object_id)
                .ok_or_else(|| error!("Asset not found."))?;
            let store: &mut Metadata = asset.try_as_mut()?;
            let _ = store
                .remove(&self.key)
                .ok_or_else(|| error!("Key not found."))?;
            Ok(world_state_view)
        }
    }

    impl Execute for Transfer<Asset, u32, Asset> {
        #[log]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            if self.destination_id.definition_id != self.source_id.definition_id {
                return Err(error!(
                    "Can not transfer asset between different asset types."
                ));
            }
            let _ = world_state_view
                .asset_definition_entry(&self.source_id.definition_id)
                .ok_or_else(|| error!("Failed to find asset."))?;
            let source_asset = world_state_view
                .asset(&self.source_id)
                .ok_or_else(|| error!("Source asset not found."))?;
            let quantity: &mut u32 = source_asset.try_as_mut()?;
            *quantity = quantity
                .checked_sub(self.object)
                .ok_or_else(|| error!("Source account doesn not enough asset quantity."))?;
            let destitantion_asset = world_state_view
                .asset_or_insert(&self.destination_id, 0u32)
                .ok_or_else(|| {
                    error!("Destination asset not found and failed to initialize new one.")
                })?;
            let quantity: &mut u32 = destitantion_asset.try_as_mut()?;
            *quantity = quantity
                .checked_add(self.object)
                .ok_or_else(|| error!("Destination asset overflowed."))?;
            Ok(world_state_view)
        }
    }
}

/// Query module provides `IrohaQuery` Asset related implementations.
pub mod query {
    use super::*;
    use iroha_error::{error, Result};

    impl Query for FindAllAssets {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            Ok(world_state_view
                .read_all_assets()
                .into_iter()
                .cloned()
                .collect())
        }
    }

    impl Query for FindAllAssetsDefinitions {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            Ok(world_state_view
                .read_all_assets_definitions_entries()
                .into_iter()
                .cloned()
                .map(|entry| entry.definition)
                .collect())
        }
    }

    impl Query for FindAssetById {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            Ok(world_state_view
                .read_asset(&self.id)
                .cloned()
                .ok_or_else(|| error!("Failed to get an asset with identification: {}.", &self.id))?
                .into())
        }
    }

    impl Query for FindAssetsByName {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            Ok(world_state_view
                .read_all_assets()
                .into_iter()
                .filter(|asset| asset.id.definition_id.name == self.name)
                .cloned()
                .collect())
        }
    }

    impl Query for FindAssetsByAccountId {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let vec = world_state_view
                .read_account_assets(&self.account_id)
                .ok_or_else(|| error!("No account with id: {} found.", &self.account_id))?
                .into_iter()
                .cloned()
                .map(Box::new)
                .map(IdentifiableBox::Asset)
                .map(Value::Identifiable)
                .collect();
            Ok(Value::Vec(vec))
        }
    }

    impl Query for FindAssetsByAssetDefinitionId {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            Ok(world_state_view
                .read_all_assets()
                .into_iter()
                .filter(|asset| asset.id.definition_id == self.asset_definition_id)
                .cloned()
                .collect())
        }
    }

    impl Query for FindAssetsByDomainName {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            Ok(world_state_view
                .read_all_assets()
                .into_iter()
                .filter(|asset| asset.id.account_id.domain_name == self.domain_name)
                .cloned()
                .collect())
        }
    }

    impl Query for FindAssetsByAccountIdAndAssetDefinitionId {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let vec = world_state_view
                .read_account_assets(&self.account_id)
                .ok_or_else(|| error!("No account with id: {} found.", &self.account_id))?
                .into_iter()
                .filter(|asset| asset.id.definition_id == self.asset_definition_id)
                .cloned()
                .map(Box::new)
                .map(IdentifiableBox::Asset)
                .map(Value::Identifiable)
                .collect();
            Ok(Value::Vec(vec))
        }
    }

    impl Query for FindAssetsByDomainNameAndAssetDefinitionId {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            Ok(world_state_view
                .read_all_assets()
                .into_iter()
                .filter(|asset| {
                    asset.id.account_id.domain_name == self.domain_name
                        && asset.id.definition_id == self.asset_definition_id
                })
                .cloned()
                .collect())
        }
    }

    impl Query for FindAssetQuantityById {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            Ok(world_state_view
                .read_asset(&self.id)
                .map(|asset| {
                    let quantity: Result<u32> = asset.try_as_ref().map(Clone::clone);
                    quantity
                })
                .transpose()?
                .ok_or_else(|| error!("Failed to get an asset with identification: {}.", &self.id))?
                .into())
        }
    }

    impl Query for FindAssetKeyValueByIdAndKey {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            Ok(world_state_view
                .read_asset(&self.id)
                .map(|asset| {
                    let store: Result<&Metadata> = asset.try_as_ref();
                    store.and_then(|store| {
                        store
                            .get(&self.key)
                            .map(|value| value.to_owned())
                            .ok_or_else(|| {
                                error!("Key {} not found in asset {}", self.key, self.id)
                            })
                    })
                })
                .transpose()?
                .ok_or_else(|| {
                    error!("Failed to get an asset with identification: {}.", &self.id)
                })?)
        }
    }
}
