//! This module contains `Asset` structure, it's implementation and related traits and
//! instructions implementations.

use iroha_data_model::prelude::*;

use super::prelude::*;
use crate::prelude::*;

/// Iroha Special Instructions module provides `AssetInstruction` enum with all possible types of
/// Asset related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `AssetInstruction` variants into generic ISI.
pub mod isi {
    use iroha_error::error;
    use iroha_logger::log;

    use super::*;

    /// Asserts that asset definition with `deifintion_id` has asset type `expected_value_type`.
    fn assert_asset_type(
        definition_id: &AssetDefinitionId,
        wsv: &WorldStateView,
        expected_value_type: AssetValueType,
    ) -> Result<(), Error> {
        let value_type = wsv
            .asset_definition_entry(definition_id)?
            .definition
            .value_type;
        if value_type == expected_value_type {
            Ok(())
        } else {
            Err(TypeError::from(AssetTypeError {
                expected: expected_value_type,
                got: value_type,
            })
            .into())
        }
    }

    impl Execute for Mint<Asset, u32> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Error> {
            assert_asset_type(
                &self.destination_id.definition_id,
                wsv,
                AssetValueType::Quantity,
            )?;
            drop(wsv.asset_or_insert(&self.destination_id, 0_u32)?);
            wsv.modify_asset(&self.destination_id, |asset| {
                let quantity: &mut u32 = asset.try_as_mut()?;
                *quantity = quantity
                    .checked_add(self.object)
                    .ok_or(MathError::OverflowError)?;
                Ok(())
            })?;
            Ok(())
        }
    }

    impl Execute for Mint<Asset, u128> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Error> {
            assert_asset_type(
                &self.destination_id.definition_id,
                wsv,
                AssetValueType::BigQuantity,
            )?;
            drop(wsv.asset_or_insert(&self.destination_id, 0_u128)?);
            wsv.modify_asset(&self.destination_id, |asset| {
                let quantity: &mut u128 = asset.try_as_mut()?;
                *quantity = quantity
                    .checked_add(self.object)
                    .ok_or(MathError::OverflowError)?;
                Ok(())
            })?;
            Ok(())
        }
    }

    impl Execute for SetKeyValue<Asset, String, Value> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Error> {
            assert_asset_type(&self.object_id.definition_id, wsv, AssetValueType::Store)?;
            let asset_metadata_limits = wsv.config.asset_metadata_limits;
            drop(wsv.asset_or_insert(&self.object_id, Metadata::new())?);
            wsv.modify_asset(&self.object_id, |asset| {
                let store: &mut Metadata = asset.try_as_mut()?;
                drop(store.insert_with_limits(
                    self.key.clone(),
                    self.value.clone(),
                    asset_metadata_limits,
                ));
                Ok(())
            })?;
            Ok(())
        }
    }

    impl Execute for Burn<Asset, u32> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Error> {
            assert_asset_type(
                &self.destination_id.definition_id,
                wsv,
                AssetValueType::Quantity,
            )?;
            wsv.modify_asset(&self.destination_id, |asset| {
                let quantity: &mut u32 = asset.try_as_mut()?;
                *quantity = quantity
                    .checked_sub(self.object)
                    .ok_or_else(|| error!("Not enough quantity to burn."))?;
                Ok(())
            })?;
            Ok(())
        }
    }

    impl Execute for Burn<Asset, u128> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Error> {
            assert_asset_type(
                &self.destination_id.definition_id,
                wsv,
                AssetValueType::BigQuantity,
            )?;
            wsv.modify_asset(&self.destination_id, |asset| {
                let quantity: &mut u128 = asset.try_as_mut()?;
                *quantity = quantity
                    .checked_sub(self.object)
                    .ok_or_else(|| error!("Not enough quantity to burn."))?;
                Ok(())
            })?;
            Ok(())
        }
    }

    impl Execute for RemoveKeyValue<Asset, String> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Error> {
            assert_asset_type(&self.object_id.definition_id, wsv, AssetValueType::Store)?;
            wsv.modify_asset(&self.object_id, |asset| {
                let store: &mut Metadata = asset.try_as_mut()?;
                drop(
                    store
                        .remove(&self.key)
                        .ok_or_else(|| FindError::MetadataKey(self.key.clone()))?,
                );
                Ok(())
            })?;
            Ok(())
        }
    }

    impl Execute for Transfer<Asset, u32, Asset> {
        #[log(skip(_authority))]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Error> {
            if self.destination_id.definition_id != self.source_id.definition_id {
                return Err(error!("Can not transfer asset between different asset types.").into());
            }
            assert_asset_type(&self.source_id.definition_id, wsv, AssetValueType::Quantity)?;
            assert_asset_type(
                &self.destination_id.definition_id,
                wsv,
                AssetValueType::Quantity,
            )?;
            wsv.modify_asset(&self.source_id, |asset| {
                let quantity: &mut u32 = asset.try_as_mut()?;
                *quantity = quantity
                    .checked_sub(self.object)
                    .ok_or_else(|| error!("Source account does not have enough asset quantity."))?;
                Ok(())
            })?;
            drop(wsv.asset_or_insert(&self.destination_id, 0_u32));
            wsv.modify_asset(&self.destination_id, |asset| {
                let quantity: &mut u32 = asset.try_as_mut()?;
                *quantity = quantity
                    .checked_add(self.object)
                    .ok_or(MathError::OverflowError)?;
                Ok(())
            })?;
            Ok(())
        }
    }
}

/// Query module provides `IrohaQuery` Asset related implementations.
pub mod query {
    use iroha_error::{error, Result, WrapErr};
    use iroha_logger::log;

    use super::super::expression::Evaluate;
    use super::*;

    impl Query for FindAllAssets {
        #[log]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output> {
            let mut vec = Vec::new();
            for domain in wsv.domains().iter() {
                for account in domain.accounts.values() {
                    for asset in account.assets.values() {
                        vec.push(asset.clone())
                    }
                }
            }
            Ok(vec)
        }
    }

    impl Query for FindAllAssetsDefinitions {
        #[log]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output> {
            let mut vec = Vec::new();
            for domain in wsv.domains().iter() {
                for asset_definition_entry in domain.asset_definitions.values() {
                    vec.push(asset_definition_entry.definition.clone())
                }
            }
            Ok(vec)
        }
    }

    impl Query for FindAssetById {
        #[log]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset id")?;
            wsv.asset(&id)
        }
    }

    impl Query for FindAssetsByName {
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output> {
            let name = self
                .name
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset name")?;
            let mut vec = Vec::new();
            for domain in wsv.domains().iter() {
                for account in domain.accounts.values() {
                    for asset in account.assets.values() {
                        if asset.id.definition_id.name == name {
                            vec.push(asset.clone())
                        }
                    }
                }
            }
            Ok(vec)
        }
    }

    impl Query for FindAssetsByAccountId {
        #[log]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output> {
            let id = self
                .account_id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get account id")?;
            wsv.account_assets(&id)
        }
    }

    impl Query for FindAssetsByAssetDefinitionId {
        #[log]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output> {
            let id = self
                .asset_definition_id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset definition id")?;
            let mut vec = Vec::new();
            for domain in wsv.domains().iter() {
                for account in domain.accounts.values() {
                    for asset in account.assets.values() {
                        if asset.id.definition_id == id {
                            vec.push(asset.clone())
                        }
                    }
                }
            }
            Ok(vec)
        }
    }

    impl Query for FindAssetsByDomainName {
        #[log]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output> {
            let name = self
                .domain_name
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get domain name")?;
            let mut vec = Vec::new();
            for account in wsv.domain(&name)?.accounts.values() {
                for asset in account.assets.values() {
                    vec.push(asset.clone())
                }
            }
            Ok(vec)
        }
    }

    impl Query for FindAssetsByAccountIdAndAssetDefinitionId {
        #[log]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output> {
            let id = self
                .account_id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get account id")?;
            let asset_id = self
                .asset_definition_id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset id")?;
            Ok(wsv
                .account_assets(&id)?
                .into_iter()
                .filter(|asset| asset.id.definition_id == asset_id)
                .collect())
        }
    }

    impl Query for FindAssetsByDomainNameAndAssetDefinitionId {
        #[log]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output> {
            let name = self
                .domain_name
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get domain name")?;
            let asset_definition_id = self
                .asset_definition_id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset id")?;
            let domain = wsv.domain(&name)?;
            let _definition = domain
                .asset_definitions
                .get(&asset_definition_id)
                .ok_or_else(|| FindError::AssetDefinition(asset_definition_id.clone()))?;
            let mut assets = Vec::new();
            for account in domain.accounts.values() {
                for asset in account.assets.values() {
                    if asset.id.account_id.domain_name == name
                        && asset.id.definition_id == asset_definition_id
                    {
                        assets.push(asset.clone())
                    }
                }
            }
            Ok(assets)
        }
    }

    impl Query for FindAssetQuantityById {
        #[log]
        fn execute(&self, wsv: &WorldStateView) -> Result<u32> {
            let asset_id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset id")?;
            wsv.asset(&asset_id)?.value.try_as_ref().map(Clone::clone)
        }
    }

    impl Query for FindAssetKeyValueByIdAndKey {
        #[log]
        fn execute(&self, wsv: &WorldStateView) -> Result<Value> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset id")?;
            let key = self
                .key
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get key")?;
            let asset = wsv.asset(&id)?;
            let store: &Metadata = asset.value.try_as_ref()?;
            Ok(store
                .get(&key)
                .ok_or_else(|| error!("Key {} not found in asset {}", key, id))?
                .clone())
        }
    }
}
