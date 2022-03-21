//! This module contains [`Asset`] structure, it's implementation and related traits and
//! instructions implementations.

use iroha_data_model::prelude::*;
use iroha_telemetry::metrics;

use super::prelude::*;

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
        let asset_definition_entry = wsv.asset_definition_entry(definition_id)?;
        let definition = asset_definition_entry.definition();

        if *definition.value_type() == expected_value_type {
            Ok(definition.clone())
        } else {
            Err(Error::Type(TypeError::Asset(AssetTypeError {
                expected: expected_value_type,
                got: *definition.value_type(),
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
        if !definition.mintable() {
            return Err(Error::Mintability(MintabilityError::MintUnmintableError));
        }
        Ok(())
    }

    impl<W: WorldTrait> Execute<W> for Mint<Asset, u32> {
        type Error = Error;

        #[metrics(+"mint_qty")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let asset_id = self.destination_id;

            assert_can_mint(&asset_id.definition_id, wsv, AssetValueType::Quantity)?;
            wsv.asset_or_insert(&asset_id, 0_u32)?;
            wsv.modify_asset(&asset_id, |asset| {
                let quantity: &mut u32 = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity
                    .checked_add(self.object)
                    .ok_or(Error::Math(MathError::Overflow))?;
                wsv.metrics.tx_amounts.observe(f64::from(*quantity));

                Ok(AssetEvent::Added(asset_id.clone()))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for Mint<Asset, u128> {
        type Error = Error;

        #[metrics(+"mint_big_qty")]
        #[log]
        fn execute(
            self,
            authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let asset_id = self.destination_id;

            assert_can_mint(&asset_id.definition_id, wsv, AssetValueType::BigQuantity)?;
            wsv.asset_or_insert(&asset_id, 0_u128)?;
            wsv.modify_asset(&asset_id, |asset| {
                let quantity: &mut u128 = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity
                    .checked_add(self.object)
                    .ok_or(Error::Math(MathError::Overflow))?;
                #[allow(clippy::cast_precision_loss)]
                wsv.metrics.tx_amounts.observe(*quantity as f64);

                Ok(AssetEvent::Added(asset_id.clone()))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for Mint<Asset, Fixed> {
        type Error = Error;

        #[metrics(+"mint_fixed")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let asset_id = self.destination_id;

            assert_can_mint(&asset_id.definition_id, wsv, AssetValueType::Fixed)?;
            wsv.asset_or_insert(&asset_id, Fixed::ZERO)?;
            wsv.modify_asset(&asset_id, |asset| {
                let quantity: &mut Fixed = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity.checked_add(self.object)?;
                wsv.metrics.tx_amounts.observe((*quantity).into());

                Ok(AssetEvent::Added(asset_id.clone()))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for SetKeyValue<Asset, Name, Value> {
        type Error = Error;

        #[metrics(+"asset_set_key_value")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let asset_id = self.object_id;

            assert_asset_type(&asset_id.definition_id, wsv, AssetValueType::Store)?;
            wsv.asset_or_insert(&asset_id, Metadata::new())?;
            wsv.modify_asset(&asset_id, |asset| {
                let asset_metadata_limits = wsv.config.asset_metadata_limits;

                let store: &mut Metadata = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                store.insert_with_limits(self.key, self.value, asset_metadata_limits)?;

                Ok(AssetEvent::MetadataInserted(asset_id.clone()))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for Burn<Asset, u32> {
        type Error = Error;

        #[metrics(+"burn_qty")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let asset_id = self.destination_id;

            assert_asset_type(&asset_id.definition_id, wsv, AssetValueType::Quantity)?;
            wsv.modify_asset(&asset_id, |asset| {
                let quantity: &mut u32 = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity
                    .checked_sub(self.object)
                    .ok_or(MathError::NotEnoughQuantity)?;
                wsv.metrics.tx_amounts.observe(f64::from(*quantity));

                Ok(AssetEvent::Removed(asset_id.clone()))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for Burn<Asset, u128> {
        type Error = Error;

        #[metrics(+"burn_big_qty")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let asset_id = self.destination_id;

            assert_asset_type(&asset_id.definition_id, wsv, AssetValueType::BigQuantity)?;
            wsv.modify_asset(&asset_id, |asset| {
                let quantity: &mut u128 = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity
                    .checked_sub(self.object)
                    .ok_or(MathError::NotEnoughQuantity)?;
                #[allow(clippy::cast_precision_loss)]
                wsv.metrics.tx_amounts.observe(*quantity as f64);

                Ok(AssetEvent::Removed(asset_id.clone()))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for Burn<Asset, Fixed> {
        type Error = Error;

        #[metrics(+"burn_fixed")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let asset_id = self.destination_id;

            assert_asset_type(&asset_id.definition_id, wsv, AssetValueType::Fixed)?;
            wsv.modify_asset(&asset_id, |asset| {
                let quantity: &mut Fixed = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity.checked_sub(self.object)?;
                // Careful if `Fixed` stops being `Copy`.
                wsv.metrics.tx_amounts.observe((*quantity).into());

                Ok(AssetEvent::Removed(asset_id.clone()))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for RemoveKeyValue<Asset, Name> {
        type Error = Error;

        #[metrics(+"asset_remove_key_value")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let asset_id = self.object_id;

            assert_asset_type(&asset_id.definition_id, wsv, AssetValueType::Store)?;
            wsv.modify_asset(&asset_id, |asset| {
                let store: &mut Metadata = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                store
                    .remove(&self.key)
                    .ok_or(FindError::MetadataKey(self.key))?;

                Ok(AssetEvent::MetadataRemoved(asset_id.clone()))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for Transfer<Asset, u32, Asset> {
        type Error = Error;

        #[log(skip(_authority))]
        #[metrics(+"transfer_qty_asset")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let source_asset_id = self.source_id;
            let destination_asset_id = self.destination_id;

            if destination_asset_id.definition_id != source_asset_id.definition_id {
                let expected = *wsv
                    .asset_definition_entry(&destination_asset_id.definition_id)?
                    .definition()
                    .value_type();
                let got = *wsv
                    .asset_definition_entry(&source_asset_id.definition_id)?
                    .definition()
                    .value_type();
                return Err(Error::Type(TypeError::Asset(AssetTypeError {
                    expected,
                    got,
                })));
            }
            assert_asset_type(
                &source_asset_id.definition_id,
                wsv,
                AssetValueType::Quantity,
            )?;
            assert_asset_type(
                &destination_asset_id.definition_id,
                wsv,
                AssetValueType::Quantity,
            )?;

            wsv.asset_or_insert(&destination_asset_id, 0_u32)?;
            wsv.modify_asset(&source_asset_id, |asset| {
                let quantity: &mut u32 = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity
                    .checked_sub(self.object)
                    .ok_or(Error::Math(MathError::NotEnoughQuantity))?;

                Ok(AssetEvent::Removed(source_asset_id.clone()))
            })?;
            wsv.modify_asset(&destination_asset_id, |asset| {
                let quantity: &mut u32 = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity
                    .checked_add(self.object)
                    .ok_or(MathError::Overflow)?;
                wsv.metrics.tx_amounts.observe(f64::from(*quantity));

                Ok(AssetEvent::Added(destination_asset_id.clone()))
            })
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
                for account in domain.accounts() {
                    for asset in account.assets() {
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
                for asset_definition_entry in domain.asset_definitions() {
                    vec.push(asset_definition_entry.definition().clone())
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
                .map_err(|e| Error::Evaluate(e.to_string()))?;
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
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let mut vec = Vec::new();
            for domain in wsv.domains().iter() {
                for account in domain.accounts() {
                    for asset in account.assets() {
                        if asset.id().definition_id.name == name {
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
                .map_err(|e| Error::Evaluate(e.to_string()))?;
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
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let mut vec = Vec::new();
            for domain in wsv.domains().iter() {
                for account in domain.accounts() {
                    for asset in account.assets() {
                        if asset.id().definition_id == id {
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
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let mut vec = Vec::new();
            for account in wsv.domain(&id)?.accounts() {
                for asset in account.assets() {
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
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let asset_definition_id = self
                .asset_definition_id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset definition id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let domain = wsv.domain(&domain_id)?;
            let _definition = domain
                .asset_definition(&asset_definition_id)
                .ok_or_else(|| FindError::AssetDefinition(asset_definition_id.clone()))?;
            let mut assets = Vec::new();
            for account in domain.accounts() {
                for asset in account.assets() {
                    if asset.id().account_id.domain_id == domain_id
                        && asset.id().definition_id == asset_definition_id
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
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            wsv.asset(&id)
                .map_err(
                    |asset_err| match wsv.asset_definition_entry(&id.definition_id) {
                        Ok(_) => Error::Find(Box::new(asset_err)),
                        Err(definition_err) => Error::Find(Box::new(definition_err)),
                    },
                )?
                .value()
                .try_as_ref()
                .map_err(eyre::Error::from)
                .map_err(|e| Error::Conversion(e.to_string()))
                .map(Clone::clone)
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindAssetKeyValueByIdAndKey {
        #[log]
        #[metrics(+"find_asset_key_value_by_id_and_key")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let key = self
                .key
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get key")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let asset = wsv.asset(&id).map_err(|asset_err| {
                match wsv.asset_definition_entry(&id.definition_id) {
                    Ok(_) => asset_err,
                    Err(definition_err) => definition_err,
                }
            })?;
            let store: &Metadata = asset
                .value()
                .try_as_ref()
                .map_err(eyre::Error::from)
                .map_err(|e| Error::Conversion(e.to_string()))?;
            Ok(store
                .get(&key)
                .ok_or_else(|| Error::Find(Box::new(FindError::MetadataKey(key))))?
                .clone())
        }
    }
}
