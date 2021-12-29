//! This module contains [`Asset`] structure, it's implementation and related traits and
//! instructions implementations.

use iroha_data_model::prelude::*;
use iroha_telemetry::metrics;

use super::prelude::*;
use crate::prelude::*;

/// ISI module contains all instructions related to assets:
/// - minting/burning assets
/// - update metadata
/// - transfer, etc.
pub mod isi {
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
            Err(Error::Type(TypeError::Asset(AssetTypeError {
                expected: expected_value_type,
                got: definition.value_type,
            })))
        }
    }

    /// Assert that this asset is `mintable`.
    fn assert_can_mint<W: WorldTrait>(
        definition_id: &AssetDefinitionId,
        wsv: &WorldStateView<W>,
        expected_value_type: AssetValueType,
    ) -> Result<(), Error> {
        let definition = assert_asset_type(definition_id, wsv, expected_value_type)?;
        if !definition.mintable {
            return Err(Error::Mintability(MintabilityError::MintUnmintableError));
        }
        Ok(())
    }

    impl<W: WorldTrait> Execute<W> for Mint<Asset, u32> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"mint_qty")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            assert_can_mint(
                &self.destination_id.definition_id,
                wsv,
                AssetValueType::Quantity,
            )?;
            wsv.asset_or_insert(&self.destination_id, 0_u32)?;
            wsv.modify_asset(&self.destination_id, |asset| {
                let quantity: &mut u32 = asset.try_as_mut().map_err(Error::Conversion)?;
                *quantity = quantity
                    .checked_add(self.object)
                    .ok_or(Error::Math(MathError::Overflow))?;
                wsv.metrics.tx_amounts.observe(f64::from(*quantity));
                Ok(())
            })
            .map(|_| self.into())
            .map_err(Into::into)
        }
    }

    impl<W: WorldTrait> Execute<W> for Mint<Asset, u128> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"mint_big_qty")]
        #[log]
        fn execute(
            self,
            authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            assert_can_mint(
                &self.destination_id.definition_id,
                wsv,
                AssetValueType::BigQuantity,
            )?;
            wsv.asset_or_insert(&self.destination_id, 0_u128)?;
            wsv.modify_asset(&self.destination_id, |asset| {
                let quantity: &mut u128 = asset.try_as_mut().map_err(Error::Conversion)?;
                *quantity = quantity
                    .checked_add(self.object)
                    .ok_or(Error::Math(MathError::Overflow))?;
                #[allow(clippy::cast_precision_loss)]
                wsv.metrics.tx_amounts.observe(*quantity as f64);
                Ok(())
            })
            .map(|_| self.into())
            .map_err(Into::into)
        }
    }

    impl<W: WorldTrait> Execute<W> for Mint<Asset, Fixed> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"mint_fixed")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            assert_can_mint(
                &self.destination_id.definition_id,
                wsv,
                AssetValueType::Fixed,
            )?;
            wsv.asset_or_insert(&self.destination_id, Fixed::ZERO)?;
            wsv.modify_asset(&self.destination_id, |asset| {
                let quantity: &mut Fixed = asset.try_as_mut().map_err(Error::Conversion)?;
                *quantity = quantity.checked_add(self.object)?;
                wsv.metrics.tx_amounts.observe((*quantity).into());
                Ok(())
            })
            .map(|_| self.into())
            .map_err(Into::into)
        }
    }

    impl<W: WorldTrait> Execute<W> for SetKeyValue<Asset, Name, Value> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"asset_set_key_value")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            assert_asset_type(&self.object_id.definition_id, wsv, AssetValueType::Store)?;
            let asset_metadata_limits = wsv.config.asset_metadata_limits;
            wsv.asset_or_insert(&self.object_id, Metadata::new())?;
            wsv.modify_asset(&self.object_id, |asset| {
                let store: &mut Metadata = asset.try_as_mut().map_err(Error::Conversion)?;
                store.insert_with_limits(
                    self.key.clone(),
                    self.value.clone(),
                    asset_metadata_limits,
                )?;
                Ok(())
            })
            .map(|_| self.into())
            .map_err(Into::into)
        }
    }

    impl<W: WorldTrait> Execute<W> for Burn<Asset, u32> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"burn_qty")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            assert_asset_type(
                &self.destination_id.definition_id,
                wsv,
                AssetValueType::Quantity,
            )?;
            wsv.modify_asset(&self.destination_id, |asset| {
                let quantity: &mut u32 = asset.try_as_mut().map_err(Error::Conversion)?;
                *quantity = quantity
                    .checked_sub(self.object)
                    .ok_or(MathError::NotEnoughQuantity)?;
                wsv.metrics.tx_amounts.observe(f64::from(*quantity));
                Ok(())
            })
            .map(|_| self.into())
            .map_err(Into::into)
        }
    }

    impl<W: WorldTrait> Execute<W> for Burn<Asset, u128> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"burn_big_qty")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            assert_asset_type(
                &self.destination_id.definition_id,
                wsv,
                AssetValueType::BigQuantity,
            )?;
            wsv.modify_asset(&self.destination_id, |asset| {
                let quantity: &mut u128 = asset.try_as_mut().map_err(Error::Conversion)?;
                *quantity = quantity
                    .checked_sub(self.object)
                    .ok_or(MathError::NotEnoughQuantity)?;
                #[allow(clippy::cast_precision_loss)]
                wsv.metrics.tx_amounts.observe(*quantity as f64);
                Ok(())
            })
            .map(|_| self.into())
            .map_err(Into::into)
        }
    }

    impl<W: WorldTrait> Execute<W> for Burn<Asset, Fixed> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"burn_fixed")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            assert_asset_type(
                &self.destination_id.definition_id,
                wsv,
                AssetValueType::Fixed,
            )?;
            wsv.modify_asset(&self.destination_id, |asset| {
                let quantity: &mut Fixed = asset.try_as_mut().map_err(Error::Conversion)?;
                *quantity = quantity.checked_sub(self.object)?;
                // Careful if `Fixed` stops being `Copy`.
                wsv.metrics.tx_amounts.observe((*quantity).into());
                Ok(())
            })
            .map(|_| self.into())
            .map_err(Into::into)
        }
    }

    impl<W: WorldTrait> Execute<W> for RemoveKeyValue<Asset, Name> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"asset_remove_key_value")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            assert_asset_type(&self.object_id.definition_id, wsv, AssetValueType::Store)?;
            wsv.modify_asset(&self.object_id, |asset| {
                let store: &mut Metadata = asset.try_as_mut().map_err(Error::Conversion)?;
                store
                    .remove(&self.key)
                    .ok_or_else(|| FindError::MetadataKey(self.key.clone()))?;
                Ok(())
            })
            .map(|_| self.into())
            .map_err(Into::into)
        }
    }

    impl<W: WorldTrait> Execute<W> for Transfer<Asset, u32, Asset> {
        type Error = Error;
        type Diff = Vec<DataEvent>;

        #[log(skip(_authority))]
        #[metrics(+"transfer_qty_asset")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            if self.destination_id.definition_id != self.source_id.definition_id {
                let expected = wsv
                    .asset_definition_entry(&self.destination_id.definition_id)?
                    .definition
                    .value_type;
                let got = wsv
                    .asset_definition_entry(&self.source_id.definition_id)?
                    .definition
                    .value_type;
                return Err(Error::Type(TypeError::Asset(AssetTypeError {
                    expected,
                    got,
                })));
            }
            assert_asset_type(&self.source_id.definition_id, wsv, AssetValueType::Quantity)?;
            assert_asset_type(
                &self.destination_id.definition_id,
                wsv,
                AssetValueType::Quantity,
            )?;
            wsv.modify_asset(&self.source_id, |asset| {
                let quantity: &mut u32 = asset.try_as_mut().map_err(Error::Conversion)?;
                *quantity = quantity
                    .checked_sub(self.object)
                    .ok_or(Error::Math(MathError::NotEnoughQuantity))?;
                Ok(())
            })?;
            wsv.asset_or_insert(&self.destination_id, 0_u32)?;
            wsv.modify_asset(&self.destination_id, |asset| {
                let quantity: &mut u32 = asset.try_as_mut().map_err(Error::Conversion)?;
                *quantity = quantity
                    .checked_add(self.object)
                    .ok_or(MathError::Overflow)?;
                wsv.metrics.tx_amounts.observe(f64::from(*quantity));
                Ok(())
            })?;
            Ok(self.into())
        }
    }
}

/// Asset-related query implementations.
pub mod query {
    use eyre::{Result, WrapErr};
    use iroha_logger::prelude::*;

    use super::*;
    use crate::smartcontracts::query::Error;

    impl<W: WorldTrait> ValidQuery<W> for FindAllAssets {
        #[log]
        #[metrics(+"find_all_assets")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
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
        #[metrics(+"find_all_asset_definitions")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
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
        #[metrics(+"find_asset_by_id")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset id")
                .map_err(Error::Evaluate)?;
            wsv.asset(&id)
                .map_err(
                    |asset_err| match wsv.asset_definition_entry(&id.definition_id) {
                        Ok(_) => asset_err,
                        Err(definition_err) => definition_err,
                    },
                )
                .map_err(Into::into)
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindAssetsByName {
        #[log]
        #[metrics(+"find_assets_by_name")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let name = self
                .name
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset name")
                .map_err(Error::Evaluate)?;
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
        #[metrics(+"find_assets_by_account_id")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let id = self
                .account_id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get account id")
                .map_err(Error::Evaluate)?;
            wsv.account_assets(&id).map_err(Into::into)
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindAssetsByAssetDefinitionId {
        #[log]
        #[metrics(+"find_assets_by_asset_definition_id")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let id = self
                .asset_definition_id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset definition id")
                .map_err(Error::Evaluate)?;
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

    impl<W: WorldTrait> ValidQuery<W> for FindAssetsByDomainId {
        #[log]
        #[metrics(+"find_assets_by_domain_id")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let id = self
                .domain_id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get domain id")
                .map_err(Error::Evaluate)?;
            let mut vec = Vec::new();
            for account in wsv.domain(&id)?.accounts.values() {
                for asset in account.assets.values() {
                    vec.push(asset.clone())
                }
            }
            Ok(vec)
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindAssetsByDomainIdAndAssetDefinitionId {
        #[log]
        #[metrics(+"find_assets_by_domain_id_and_asset_definition_id")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let domain_id = self
                .domain_id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get domain id")
                .map_err(Error::Evaluate)?;
            let asset_definition_id = self
                .asset_definition_id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset definition id")
                .map_err(Error::Evaluate)?;
            let domain = wsv.domain(&domain_id)?;
            let _definition = domain
                .asset_definitions
                .get(&asset_definition_id)
                .ok_or_else(|| FindError::AssetDefinition(asset_definition_id.clone()))?;
            let mut assets = Vec::new();
            for account in domain.accounts.values() {
                for asset in account.assets.values() {
                    if asset.id.account_id.domain_id == domain_id
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
        #[metrics(+"find_asset_quantity_by_id")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<u32, Error> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset id")
                .map_err(Error::Evaluate)?;
            wsv.asset(&id)
                .map_err(
                    |asset_err| match wsv.asset_definition_entry(&id.definition_id) {
                        Ok(_) => Error::Find(Box::new(asset_err)),
                        Err(definition_err) => Error::Find(Box::new(definition_err)),
                    },
                )?
                .value
                .try_as_ref()
                .map_err(Error::Conversion)
                .map(Clone::clone)
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindAssetKeyValueByIdAndKey {
        #[log]
        #[metrics(+"find_asset_key_value_by_id_and_key")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Value, Error> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset id")
                .map_err(Error::Evaluate)?;
            let key = self
                .key
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get key")
                .map_err(Error::Evaluate)?;
            let asset = wsv.asset(&id).map_err(|asset_err| {
                match wsv.asset_definition_entry(&id.definition_id) {
                    Ok(_) => asset_err,
                    Err(definition_err) => definition_err,
                }
            })?;
            let store: &Metadata = asset.value.try_as_ref().map_err(Error::Conversion)?;
            Ok(store
                .get(&key)
                .ok_or_else(|| Error::Find(Box::new(FindError::MetadataKey(key))))?
                .clone())
        }
    }
}
