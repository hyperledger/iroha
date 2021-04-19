//! This module contains `Asset` structure, it's implementation and related traits and
//! instructions implementations.

use iroha_data_model::prelude::*;

use crate::{isi::prelude::*, prelude::*};

/// Iroha Special Instructions module provides `AssetInstruction` enum with all possible types of
/// Asset related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `AssetInstruction` variants into generic ISI.
pub mod isi {
    use iroha_error::error;
    use iroha_logger::log;

    use super::*;

    fn assert_asset_type(
        definition_id: &AssetDefinitionId,
        world_state_view: &WorldStateView,
        expected_value_type: AssetValueType,
    ) -> Result<(), Error> {
        world_state_view.asset_definition_entry(definition_id, |asset| {
            if asset.definition.value_type == expected_value_type {
                Ok(())
            } else {
                Err(TypeError::from(AssetTypeError {
                    expected: expected_value_type,
                    got: asset.definition.value_type,
                })
                .into())
            }
        })?
    }

    impl Execute for Mint<Asset, u32> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            assert_asset_type(
                &self.destination_id.definition_id,
                world_state_view,
                AssetValueType::Quantity,
            )?;
            world_state_view.asset_or(
                &self.destination_id,
                |asset| -> Result<(), Error> {
                    asset.try_as_mut(|quantity: &mut u32| {
                        *quantity = quantity
                            .checked_add(self.object)
                            .ok_or(MathError::OverflowError)?;
                        Ok(())
                    })?
                },
                || {
                    world_state_view.add_asset(Asset::with_quantity(
                        self.destination_id.clone(),
                        self.object,
                    ))?;
                    Ok(())
                },
            )?;
            Ok(())
        }
    }

    impl Execute for Mint<Asset, u128> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            assert_asset_type(
                &self.destination_id.definition_id,
                world_state_view,
                AssetValueType::BigQuantity,
            )?;
            world_state_view.asset_or(
                &self.destination_id,
                |asset| {
                    asset.try_as_mut(|quantity: &mut u128| {
                        *quantity = quantity
                            .checked_add(self.object)
                            .ok_or(MathError::OverflowError)?;
                        Ok(())
                    })?
                },
                || {
                    world_state_view.add_asset(Asset::with_big_quantity(
                        self.destination_id.clone(),
                        self.object,
                    ))
                },
            )?;
            Ok(())
        }
    }

    impl Execute for SetKeyValue<Asset, String, Value> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            assert_asset_type(
                &self.object_id.definition_id,
                world_state_view,
                AssetValueType::Store,
            )?;
            let asset_metadata_limits = world_state_view.config.asset_metadata_limits;
            world_state_view.asset_or(
                &self.object_id,
                |asset| {
                    asset.try_as_mut(|store: &mut Metadata| {
                        let _ = store.insert_with_limits(
                            self.key.clone(),
                            self.value.clone(),
                            asset_metadata_limits,
                        );
                        Ok(())
                    })?
                },
                || {
                    world_state_view.add_asset(Asset::with_parameter(
                        self.object_id.clone(),
                        self.key.clone(),
                        self.value.clone(),
                        asset_metadata_limits,
                    )?)
                },
            )?;
            Ok(())
        }
    }

    impl Execute for Burn<Asset, u32> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            assert_asset_type(
                &self.destination_id.definition_id,
                world_state_view,
                AssetValueType::Quantity,
            )?;
            world_state_view.asset(&self.destination_id, |asset| {
                asset.try_as_mut(|quantity: &mut u32| {
                    *quantity = quantity
                        .checked_sub(self.object)
                        .ok_or_else(|| error!("Not enough quantity to burn."))?;
                    Ok(())
                })?
            })?
        }
    }

    impl Execute for Burn<Asset, u128> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            assert_asset_type(
                &self.destination_id.definition_id,
                world_state_view,
                AssetValueType::BigQuantity,
            )?;
            world_state_view.asset(&self.destination_id, |asset| {
                asset.try_as_mut(|quantity: &mut u128| {
                    *quantity = quantity
                        .checked_sub(self.object)
                        .ok_or_else(|| error!("Not enough quantity to burn."))?;
                    Ok(())
                })?
            })?
        }
    }

    impl Execute for RemoveKeyValue<Asset, String> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            assert_asset_type(
                &self.object_id.definition_id,
                world_state_view,
                AssetValueType::Store,
            )?;
            world_state_view.asset(&self.object_id, |asset| {
                asset.try_as_mut(|store: &mut Metadata| {
                    let _ = store
                        .remove(&self.key)
                        .ok_or_else(|| FindError::MetadataKey(self.key.clone()))?;
                    Ok(())
                })?
            })?
        }
    }

    impl Execute for Transfer<Asset, u32, Asset> {
        #[log(skip(_authority))]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            if self.destination_id.definition_id != self.source_id.definition_id {
                return Err(error!("Can not transfer asset between different asset types.").into());
            }
            assert_asset_type(
                &self.source_id.definition_id,
                world_state_view,
                AssetValueType::Quantity,
            )?;
            assert_asset_type(
                &self.destination_id.definition_id,
                world_state_view,
                AssetValueType::Quantity,
            )?;
            world_state_view.asset(&self.source_id, |asset| -> Result<(), Error> {
                asset.try_as_mut(|quantity: &mut u32| {
                    *quantity = quantity.checked_sub(self.object).ok_or_else(|| {
                        error!("Source account doesn not have enough asset quantity.")
                    })?;
                    Ok(())
                })?
            })??;
            world_state_view.asset_or_insert(&self.destination_id, 0_u32, |asset| {
                asset.try_as_mut(|quantity: &mut u32| {
                    *quantity = quantity
                        .checked_add(self.object)
                        .ok_or(MathError::OverflowError)?;
                    Ok(())
                })?
            })?
        }
    }
}

/// Query module provides `IrohaQuery` Asset related implementations.
pub mod query {
    use iroha_error::{error, Result, WrapErr};
    use iroha_logger::log;

    use super::*;
    use crate::expression::Evaluate;

    impl Query for FindAllAssets {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let mut vec = Vec::new();
            for domain in world_state_view.domains().iter() {
                for account in domain.accounts.iter() {
                    for asset in account.assets.iter() {
                        vec.push(Value::from(asset.clone()))
                    }
                }
            }
            Ok(vec.into())
        }
    }

    impl Query for FindAllAssetsDefinitions {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let mut vec = Vec::new();
            for domain in world_state_view.domains().iter() {
                for asset in domain.asset_definitions.iter() {
                    vec.push(Value::from(asset.definition.clone()))
                }
            }
            Ok(vec.into())
        }
    }

    impl Query for FindAssetById {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let id = self
                .id
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get asset id")?;
            Ok(world_state_view.asset(&id, Clone::clone)?.into())
        }
    }

    impl Query for FindAssetsByName {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let name = self
                .name
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get asset name")?;
            let mut vec = Vec::new();
            for domain in world_state_view.domains().iter() {
                for account in domain.accounts.iter() {
                    for asset in account.assets.iter() {
                        if asset.id.definition_id.name == name {
                            vec.push(Value::from(asset.clone()))
                        }
                    }
                }
            }
            Ok(vec.into())
        }
    }

    impl Query for FindAssetsByAccountId {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let id = self
                .account_id
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get account id")?;
            let mut vec = Vec::new();
            world_state_view.account_assets(&id, |asset| {
                vec.push(Value::from(asset.clone()));
            })?;
            Ok(vec.into())
        }
    }

    impl Query for FindAssetsByAssetDefinitionId {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let id = self
                .asset_definition_id
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get asset definition id")?;
            let mut vec = Vec::new();

            for domain in world_state_view.domains().iter() {
                for account in domain.accounts.iter() {
                    for asset in account.assets.iter() {
                        if asset.id.definition_id == id {
                            vec.push(Value::from(asset.clone()))
                        }
                    }
                }
            }
            Ok(vec.into())
        }
    }

    impl Query for FindAssetsByDomainName {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let name = self
                .domain_name
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get domain name")?;
            let mut vec = Vec::new();
            world_state_view.domain(&name, |domain| {
                for account in domain.accounts.iter() {
                    for asset in account.assets.iter() {
                        vec.push(Value::from(asset.clone()))
                    }
                }
            })?;
            Ok(vec.into())
        }
    }

    impl Query for FindAssetsByAccountIdAndAssetDefinitionId {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let id = self
                .account_id
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get account id")?;
            let asset_id = self
                .asset_definition_id
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get asset id")?;
            let mut vec = Vec::new();
            world_state_view.account_assets(&id, |asset| {
                if asset.id.definition_id == asset_id {
                    vec.push(Value::from(asset.clone()))
                }
            })?;
            Ok(Value::Vec(vec))
        }
    }

    impl Query for FindAssetsByDomainNameAndAssetDefinitionId {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let name = self
                .domain_name
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get domain name")?;
            let asset_id = self
                .asset_definition_id
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get asset id")?;
            let assets = world_state_view
                .domain(&name, |domain| {
                    let _definition = domain.asset_definitions.get(&asset_id)?;
                    let mut assets = Vec::new();
                    for account in domain.accounts.iter() {
                        for asset in account.assets.iter() {
                            if asset.id.account_id.domain_name == name
                                && asset.id.definition_id == asset_id
                            {
                                assets.push(asset.clone())
                            }
                        }
                    }
                    if assets.is_empty() {
                        None
                    } else {
                        Some(assets)
                    }
                })?
                .ok_or_else(|| FindError::AssetDefinition(asset_id.clone()))?;
            Ok(assets.into_iter().collect())
        }
    }

    impl Query for FindAssetQuantityById {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let asset_id = self
                .id
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get asset id")?;
            Ok(world_state_view
                .asset(&asset_id, |asset| {
                    let quantity: Result<u32> = asset.value.read().try_as_ref().map(Clone::clone);
                    quantity
                })??
                .into())
        }
    }

    impl Query for FindAssetKeyValueByIdAndKey {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let id = self
                .id
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get asset id")?;
            let key = self
                .key
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get key")?;
            world_state_view.asset(&id, |asset| {
                let value = asset.value.read();
                let store: Result<&Metadata> = value.try_as_ref();
                store.and_then(|store| {
                    store
                        .get(&key)
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| error!("Key {} not found in asset {}", key, id))
                })
            })?
        }
    }
}
