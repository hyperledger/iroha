//! This module contains [`Asset`] structure, it's implementation and related traits and
//! instructions implementations.

use iroha_data_model::prelude::*;

use super::prelude::*;
use crate::prelude::*;

/// ISI module contains all instructions related to assets:
/// - minting/burning assets
/// - update metadata
/// - transfer, etc.
pub mod isi {
    use eyre::eyre;
    use iroha_logger::prelude::*;

    use super::*;

    /// Asserts that asset definition with [`definition_id`] has asset type [`expected_value_type`].
    fn assert_asset_type<W: WorldTrait>(
        definition_id: &AssetDefinitionId,
        wsv: &WorldStateView<W>,
        expected_value_type: AssetValueType,
    ) -> Result<AssetDefinition, Error> {
        let definition = wsv.asset_definition_entry(definition_id)?.definition;
        if definition.value_type == expected_value_type {
            Ok(definition)
        } else {
            Err(TypeError::from(AssetTypeError {
                expected: expected_value_type,
                got: definition.value_type,
            })
            .into())
        }
    }

    fn assert_can_mint<W: WorldTrait>(
        definition_id: &AssetDefinitionId,
        wsv: &WorldStateView<W>,
        expected_value_type: AssetValueType,
    ) -> Result<(), Error> {
        let definition = assert_asset_type(definition_id, wsv, expected_value_type)?;
        if !definition.mintable {
            return Err(MintabilityError::MintUnmintableError.into());
        }
        Ok(())
    }

    impl<W: WorldTrait> Execute<W> for Mint<Asset, u32> {
        type Error = Error;

        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Error> {
            assert_can_mint(
                &self.destination_id.definition_id,
                wsv,
                AssetValueType::Quantity,
            )?;
            wsv.asset_or_insert(&self.destination_id, 0_u32)?;
            wsv.modify_asset(&self.destination_id, |asset| {
                let quantity: &mut u32 = asset.try_as_mut()?;
                *quantity = quantity
                    .checked_add(self.object)
                    .ok_or(MathError::OverflowError)?;
                Ok(())
            })
            .map_err(Into::into)
        }
    }

    impl<W: WorldTrait> Execute<W> for Mint<Asset, u128> {
        type Error = Error;

        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Error> {
            assert_can_mint(
                &self.destination_id.definition_id,
                wsv,
                AssetValueType::BigQuantity,
            )?;
            wsv.asset_or_insert(&self.destination_id, 0_u128)?;
            wsv.modify_asset(&self.destination_id, |asset| {
                let quantity: &mut u128 = asset.try_as_mut()?;
                *quantity = quantity
                    .checked_add(self.object)
                    .ok_or(MathError::OverflowError)?;
                Ok(())
            })
            .map_err(Into::into)
        }
    }

    impl<W: WorldTrait> Execute<W> for Mint<Asset, Fixed> {
        type Error = Error;

        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Error> {
            assert_can_mint(
                &self.destination_id.definition_id,
                wsv,
                AssetValueType::Fixed,
            )?;
            wsv.asset_or_insert(&self.destination_id, Fixed::ZERO)?;
            wsv.modify_asset(&self.destination_id, |asset| {
                let quantity: &mut Fixed = asset.try_as_mut()?;
                *quantity = quantity.checked_add(self.object)?;
                Ok(())
            })
            .map_err(Into::into)
        }
    }

    impl<W: WorldTrait> Execute<W> for SetKeyValue<Asset, String, Value> {
        type Error = Error;

        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Error> {
            assert_asset_type(&self.object_id.definition_id, wsv, AssetValueType::Store)?;
            let asset_metadata_limits = wsv.config.asset_metadata_limits;
            wsv.asset_or_insert(&self.object_id, Metadata::new())?;
            wsv.modify_asset(&self.object_id, |asset| {
                let store: &mut Metadata = asset.try_as_mut()?;
                store.insert_with_limits(
                    self.key.clone(),
                    self.value.clone(),
                    asset_metadata_limits,
                )?;
                Ok(())
            })
            .map_err(Into::into)
        }
    }

    impl<W: WorldTrait> Execute<W> for Burn<Asset, u32> {
        type Error = Error;

        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
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
                    .ok_or(MathError::NotEnoughQuantity)?;
                Ok(())
            })
            .map_err(Into::into)
        }
    }

    impl<W: WorldTrait> Execute<W> for Burn<Asset, u128> {
        type Error = Error;

        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
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
                    .ok_or(MathError::NotEnoughQuantity)?;
                Ok(())
            })
            .map_err(Into::into)
        }
    }

    impl<W: WorldTrait> Execute<W> for Burn<Asset, Fixed> {
        type Error = Error;

        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Error> {
            assert_asset_type(
                &self.destination_id.definition_id,
                wsv,
                AssetValueType::Fixed,
            )?;
            wsv.modify_asset(&self.destination_id, |asset| {
                let quantity: &mut Fixed = asset.try_as_mut()?;
                *quantity = quantity.checked_sub(self.object)?;
                Ok(())
            })
            .map_err(Into::into)
        }
    }

    impl<W: WorldTrait> Execute<W> for RemoveKeyValue<Asset, String> {
        type Error = Error;

        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Error> {
            assert_asset_type(&self.object_id.definition_id, wsv, AssetValueType::Store)?;
            wsv.modify_asset(&self.object_id, |asset| {
                let store: &mut Metadata = asset.try_as_mut()?;
                store
                    .remove(&self.key)
                    .ok_or_else(|| FindError::MetadataKey(self.key.clone()))?;
                Ok(())
            })
            .map_err(Into::into)
        }
    }

    impl<W: WorldTrait> Execute<W> for Transfer<Asset, u32, Asset> {
        type Error = Error;

        #[log(skip(_authority))]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Error> {
            if self.destination_id.definition_id != self.source_id.definition_id {
                return Err(eyre!("Can not transfer asset between different asset types.").into());
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
                    .ok_or_else(|| eyre!("Insufficient assets at source account."))?;
                Ok(())
            })?;
            wsv.asset_or_insert(&self.destination_id, 0_u32)?;
            wsv.modify_asset(&self.destination_id, |asset| {
                let quantity: &mut u32 = asset.try_as_mut()?;
                *quantity = quantity
                    .checked_add(self.object)
                    .ok_or(MathError::OverflowError)?;
                Ok(())
            })
            .map_err(Into::into)
        }
    }
}

/// Query module provides [`Query`] Asset related implementations.
pub mod query {
    use eyre::{eyre, Result, WrapErr};
    use iroha_logger::prelude::*;

    use super::*;

    impl<W: WorldTrait> ValidQuery<W> for FindAllAssets {
        #[log]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output> {
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

    impl<W: WorldTrait> ValidQuery<W> for FindAllAssetsDefinitions {
        #[log]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output> {
            let mut vec = Vec::new();
            for domain in wsv.domains().iter() {
                for asset_definition_entry in domain.asset_definitions.values() {
                    vec.push(asset_definition_entry.definition.clone())
                }
            }
            Ok(vec)
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindAssetById {
        #[log]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset id")?;
            wsv.asset(&id).map_err(|asset_err| {
                match wsv.asset_definition_entry(&id.definition_id) {
                    Ok(_) => asset_err,
                    Err(definition_err) => definition_err,
                }
            })
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindAssetsByName {
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output> {
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

    impl<W: WorldTrait> ValidQuery<W> for FindAssetsByAccountId {
        #[log]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output> {
            let id = self
                .account_id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get account id")?;
            wsv.account_assets(&id)
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindAssetsByAssetDefinitionId {
        #[log]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output> {
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

    impl<W: WorldTrait> ValidQuery<W> for FindAssetsByDomainName {
        #[log]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output> {
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

    impl<W: WorldTrait> ValidQuery<W> for FindAssetsByDomainNameAndAssetDefinitionId {
        #[log]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output> {
            let name = self
                .domain_name
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get domain name")?;
            let asset_definition_id = self
                .asset_definition_id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset definition id")?;
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

    impl<W: WorldTrait> ValidQuery<W> for FindAssetQuantityById {
        #[log]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<u32> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset id")?;
            wsv.asset(&id)
                .map_err(
                    |asset_err| match wsv.asset_definition_entry(&id.definition_id) {
                        Ok(_) => asset_err,
                        Err(definition_err) => definition_err,
                    },
                )?
                .value
                .try_as_ref()
                .map(Clone::clone)
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindAssetKeyValueByIdAndKey {
        #[log]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Value> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset id")?;
            let key = self
                .key
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get key")?;
            let asset = wsv.asset(&id).map_err(|asset_err| {
                match wsv.asset_definition_entry(&id.definition_id) {
                    Ok(_) => asset_err,
                    Err(definition_err) => definition_err,
                }
            })?;
            let store: &Metadata = asset.value.try_as_ref()?;
            Ok(store
                .get(&key)
                .ok_or_else(|| eyre!("Key {} not found in asset {}", key, id))?
                .clone())
        }
    }
}
