//! This module contains [`Asset`] structure, it's implementation and related traits and
//! instructions implementations.

use iroha_data_model::{
    isi::error::{MathError, Mismatch, TypeError},
    prelude::*,
    query::error::{FindError, QueryExecutionFail},
};
use iroha_telemetry::metrics;

use super::prelude::*;

impl Registrable for NewAssetDefinition {
    type Target = AssetDefinition;

    #[must_use]
    #[inline]
    fn build(self, authority: &AccountId) -> Self::Target {
        Self::Target {
            id: self.id,
            value_type: self.value_type,
            mintable: self.mintable,
            logo: self.logo,
            metadata: self.metadata,
            owned_by: authority.clone(),
        }
    }
}

/// ISI module contains all instructions related to assets:
/// - minting/burning assets
/// - update metadata
/// - transfer, etc.
pub mod isi {
    use iroha_data_model::{asset::AssetValueType, isi::error::MintabilityError};

    use super::*;
    use crate::smartcontracts::account::isi::forbid_minting;

    impl Execute for SetKeyValue<Asset> {
        #[metrics(+"set_asset_key_value")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let asset_id = self.object_id;

            assert_asset_type(
                &asset_id.definition_id,
                wsv,
                expected_asset_value_type_store,
            )?;

            // Increase `Store` asset total quantity by 1 if asset was not present earlier
            if matches!(wsv.asset(&asset_id), Err(QueryExecutionFail::Find(_))) {
                wsv.increase_asset_total_amount(&asset_id.definition_id, Numeric::ONE)?;
            }

            let asset_metadata_limits = wsv.config.asset_metadata_limits;
            let asset = wsv.asset_or_insert(asset_id.clone(), Metadata::new())?;

            {
                let store: &mut Metadata = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                store.insert_with_limits(
                    self.key.clone(),
                    self.value.clone(),
                    asset_metadata_limits,
                )?;
            }

            wsv.emit_events(Some(AssetEvent::MetadataInserted(MetadataChanged {
                target_id: asset_id,
                key: self.key,
                value: Box::new(self.value),
            })));

            Ok(())
        }
    }

    impl Execute for RemoveKeyValue<Asset> {
        #[metrics(+"remove_asset_key_value")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let asset_id = self.object_id;

            assert_asset_type(
                &asset_id.definition_id,
                wsv,
                expected_asset_value_type_store,
            )?;

            let value = {
                let asset = wsv.asset_mut(&asset_id)?;
                let store: &mut Metadata = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                store
                    .remove(&self.key)
                    .ok_or_else(|| FindError::MetadataKey(self.key.clone()))?
            };

            wsv.emit_events(Some(AssetEvent::MetadataRemoved(MetadataChanged {
                target_id: asset_id,
                key: self.key,
                value: Box::new(value),
            })));

            Ok(())
        }
    }

    impl Execute for Transfer<Asset, Metadata, Account> {
        #[metrics(+"transfer_store")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let asset_id = self.source_id;
            assert_asset_type(
                &asset_id.definition_id,
                wsv,
                expected_asset_value_type_store,
            )?;
            let account_id = asset_id.account_id.clone();

            let asset = wsv.account_mut(&account_id).and_then(|account| {
                account
                    .remove_asset(&asset_id)
                    .ok_or_else(|| FindError::Asset(asset_id.clone()))
            })?;

            let destination_store = {
                let destination_id =
                    AssetId::new(asset_id.definition_id.clone(), self.destination_id.clone());
                let destination_store_asset =
                    wsv.asset_or_insert(destination_id.clone(), asset.value)?;

                destination_store_asset.clone()
            };

            wsv.emit_events([
                AssetEvent::Deleted(asset_id),
                AssetEvent::Created(destination_store),
            ]);

            Ok(())
        }
    }

    impl Execute for Mint<Numeric, Asset> {
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let asset_id = self.destination_id;

            let asset_definition = assert_asset_type(
                &asset_id.definition_id,
                wsv,
                expected_asset_value_type_numeric,
            )?;
            assert_numeric_spec(&self.object, &asset_definition)?;

            assert_can_mint(&asset_definition, wsv)?;
            let asset = wsv.asset_or_insert(asset_id.clone(), Numeric::ZERO)?;
            let quantity: &mut Numeric = asset
                .try_as_mut()
                .map_err(eyre::Error::from)
                .map_err(|e| Error::Conversion(e.to_string()))?;
            *quantity = quantity
                .checked_add(self.object)
                .ok_or(MathError::Overflow)?;

            #[allow(clippy::float_arithmetic)]
            {
                wsv.new_tx_amounts.lock().push(self.object.into());
                wsv.increase_asset_total_amount(&asset_id.definition_id, self.object)?;
            }

            wsv.emit_events(Some(AssetEvent::Added(AssetChanged {
                asset_id,
                amount: self.object.into(),
            })));

            Ok(())
        }
    }

    impl Execute for Burn<Numeric, Asset> {
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let asset_id = self.destination_id;

            let asset_definition = assert_asset_type(
                &asset_id.definition_id,
                wsv,
                expected_asset_value_type_numeric,
            )?;
            assert_numeric_spec(&self.object, &asset_definition)?;

            let account = wsv.account_mut(&asset_id.account_id)?;
            let asset = account
                .assets
                .get_mut(&asset_id)
                .ok_or_else(|| FindError::Asset(asset_id.clone()))?;
            let quantity: &mut Numeric = asset
                .try_as_mut()
                .map_err(eyre::Error::from)
                .map_err(|e| Error::Conversion(e.to_string()))?;
            *quantity = quantity
                .checked_sub(self.object)
                .ok_or(MathError::NotEnoughQuantity)?;

            if asset.value.is_zero_value() {
                assert!(account.remove_asset(&asset_id).is_some());
            }

            #[allow(clippy::float_arithmetic)]
            {
                wsv.new_tx_amounts.lock().push(self.object.into());
                wsv.decrease_asset_total_amount(&asset_id.definition_id, self.object)?;
            }

            wsv.emit_events(Some(AssetEvent::Removed(AssetChanged {
                asset_id: asset_id.clone(),
                amount: self.object.into(),
            })));

            Ok(())
        }
    }

    impl Execute for Transfer<Asset, Numeric, Account> {
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let source_id = self.source_id;
            let destination_id =
                AssetId::new(source_id.definition_id.clone(), self.destination_id.clone());

            let asset_definition = assert_asset_type(
                &source_id.definition_id,
                wsv,
                expected_asset_value_type_numeric,
            )?;
            assert_numeric_spec(&self.object, &asset_definition)?;

            {
                let account = wsv.account_mut(&source_id.account_id)?;
                let asset = account
                    .assets
                    .get_mut(&source_id)
                    .ok_or_else(|| FindError::Asset(source_id.clone()))?;
                let quantity: &mut Numeric = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity
                    .checked_sub(self.object)
                    .ok_or(MathError::NotEnoughQuantity)?;
                if asset.value.is_zero_value() {
                    assert!(account.remove_asset(&source_id).is_some());
                }
            }

            let destination_asset = wsv.asset_or_insert(destination_id.clone(), Numeric::ZERO)?;
            {
                let quantity: &mut Numeric = destination_asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity
                    .checked_add(self.object)
                    .ok_or(MathError::Overflow)?;
            }

            #[allow(clippy::float_arithmetic)]
            {
                wsv.new_tx_amounts.lock().push(self.object.into());
            }

            wsv.emit_events([
                AssetEvent::Removed(AssetChanged {
                    asset_id: source_id,
                    amount: self.object.into(),
                }),
                AssetEvent::Added(AssetChanged {
                    asset_id: destination_id,
                    amount: self.object.into(),
                }),
            ]);

            Ok(())
        }
    }

    /// Assert that asset type is Numeric and that it satisfy asset definition spec
    pub(crate) fn assert_numeric_spec(
        object: &Numeric,
        asset_definition: &AssetDefinition,
    ) -> Result<NumericSpec, Error> {
        let object_spec = NumericSpec::fractional(object.scale());
        let object_asset_value_type = AssetValueType::Numeric(object_spec);
        let asset_definition_spec = match asset_definition.value_type {
            AssetValueType::Numeric(spec) => spec,
            other => {
                return Err(TypeError::from(Mismatch {
                    expected: other,
                    actual: object_asset_value_type,
                })
                .into())
            }
        };
        asset_definition_spec.check(object).map_err(|_| {
            TypeError::from(Mismatch {
                expected: AssetValueType::Numeric(asset_definition_spec),
                actual: object_asset_value_type,
            })
        })?;
        Ok(asset_definition_spec)
    }

    /// Asserts that asset definition with [`definition_id`] has asset type [`expected_value_type`].
    pub(crate) fn assert_asset_type(
        definition_id: &AssetDefinitionId,
        wsv: &WorldStateView,
        expected_value_type: impl Fn(&AssetValueType) -> Result<(), TypeError>,
    ) -> Result<AssetDefinition, Error> {
        let asset_definition = wsv.asset_definition(definition_id)?;
        expected_value_type(&asset_definition.value_type)
            .map(|()| asset_definition)
            .map_err(Into::into)
    }

    /// Assert that this asset is `mintable`.
    fn assert_can_mint(
        asset_definition: &AssetDefinition,
        wsv: &mut WorldStateView,
    ) -> Result<(), Error> {
        match asset_definition.mintable {
            Mintable::Infinitely => Ok(()),
            Mintable::Not => Err(Error::Mintability(MintabilityError::MintUnmintable)),
            Mintable::Once => {
                let asset_definition_id = asset_definition.id.clone();
                let asset_definition = wsv.asset_definition_mut(&asset_definition_id)?;
                forbid_minting(asset_definition)?;
                wsv.emit_events(Some(AssetDefinitionEvent::MintabilityChanged(
                    asset_definition_id,
                )));
                Ok(())
            }
        }
    }

    pub(crate) fn expected_asset_value_type_numeric(
        asset_value_type: &AssetValueType,
    ) -> Result<(), TypeError> {
        match asset_value_type {
            AssetValueType::Numeric(_) => Ok(()),
            other => Err(TypeError::NumericAssetValueTypeExpected(*other)),
        }
    }

    pub(crate) fn expected_asset_value_type_store(
        asset_value_type: &AssetValueType,
    ) -> Result<(), TypeError> {
        match asset_value_type {
            AssetValueType::Store => Ok(()),
            other => Err(TypeError::NumericAssetValueTypeExpected(*other)),
        }
    }
}

/// Asset-related query implementations.
pub mod query {
    use eyre::Result;
    use iroha_data_model::{
        asset::{Asset, AssetDefinition, AssetValue},
        query::{
            asset::FindAssetDefinitionById, error::QueryExecutionFail as Error, MetadataValue,
        },
    };

    use super::*;

    impl ValidQuery for FindAllAssets {
        #[metrics(+"find_all_assets")]
        fn execute<'wsv>(
            &self,
            wsv: &'wsv WorldStateView,
        ) -> Result<Box<dyn Iterator<Item = Asset> + 'wsv>, Error> {
            Ok(Box::new(
                wsv.domains()
                    .values()
                    .flat_map(|domain| {
                        domain
                            .accounts
                            .values()
                            .flat_map(|account| account.assets.values())
                    })
                    .cloned(),
            ))
        }
    }

    impl ValidQuery for FindAllAssetsDefinitions {
        #[metrics(+"find_all_asset_definitions")]
        fn execute<'wsv>(
            &self,
            wsv: &'wsv WorldStateView,
        ) -> Result<Box<dyn Iterator<Item = AssetDefinition> + 'wsv>, Error> {
            Ok(Box::new(
                wsv.domains()
                    .values()
                    .flat_map(|domain| domain.asset_definitions.values())
                    .cloned(),
            ))
        }
    }

    impl ValidQuery for FindAssetById {
        #[metrics(+"find_asset_by_id")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Asset, Error> {
            let id = &self.id;
            iroha_logger::trace!(%id);
            wsv.asset(id).map_err(|asset_err| {
                if let Err(definition_err) = wsv.asset_definition(&id.definition_id) {
                    definition_err.into()
                } else {
                    asset_err
                }
            })
        }
    }

    impl ValidQuery for FindAssetDefinitionById {
        #[metrics(+"find_asset_defintion_by_id")]
        fn execute(&self, wsv: &WorldStateView) -> Result<AssetDefinition, Error> {
            let id = &self.id;

            let entry = wsv.asset_definition(id).map_err(Error::from)?;

            Ok(entry)
        }
    }

    impl ValidQuery for FindAssetsByName {
        #[metrics(+"find_assets_by_name")]
        fn execute<'wsv>(
            &self,
            wsv: &'wsv WorldStateView,
        ) -> Result<Box<dyn Iterator<Item = Asset> + 'wsv>, Error> {
            let name = self.name.clone();
            iroha_logger::trace!(%name);
            Ok(Box::new(
                wsv.domains()
                    .values()
                    .flat_map(move |domain| {
                        let name = name.clone();

                        domain.accounts.values().flat_map(move |account| {
                            let name = name.clone();

                            account
                                .assets
                                .values()
                                .filter(move |asset| asset.id().definition_id.name == name)
                        })
                    })
                    .cloned(),
            ))
        }
    }

    impl ValidQuery for FindAssetsByAccountId {
        #[metrics(+"find_assets_by_account_id")]
        fn execute<'wsv>(
            &self,
            wsv: &'wsv WorldStateView,
        ) -> Result<Box<dyn Iterator<Item = Asset> + 'wsv>, Error> {
            let id = &self.account_id;
            iroha_logger::trace!(%id);
            Ok(Box::new(wsv.account_assets(id)?.cloned()))
        }
    }

    impl ValidQuery for FindAssetsByAssetDefinitionId {
        #[metrics(+"find_assets_by_asset_definition_id")]
        fn execute<'wsv>(
            &self,
            wsv: &'wsv WorldStateView,
        ) -> Result<Box<dyn Iterator<Item = Asset> + 'wsv>, Error> {
            let id = self.asset_definition_id.clone();
            iroha_logger::trace!(%id);
            Ok(Box::new(
                wsv.domains()
                    .values()
                    .flat_map(move |domain| {
                        let id = id.clone();

                        domain.accounts.values().flat_map(move |account| {
                            let id = id.clone();

                            account
                                .assets
                                .values()
                                .filter(move |asset| asset.id().definition_id == id)
                        })
                    })
                    .cloned(),
            ))
        }
    }

    impl ValidQuery for FindAssetsByDomainId {
        #[metrics(+"find_assets_by_domain_id")]
        fn execute<'wsv>(
            &self,
            wsv: &'wsv WorldStateView,
        ) -> Result<Box<dyn Iterator<Item = Asset> + 'wsv>, Error> {
            let id = &self.domain_id;
            iroha_logger::trace!(%id);
            Ok(Box::new(
                wsv.domain(id)?
                    .accounts
                    .values()
                    .flat_map(|account| account.assets.values())
                    .cloned(),
            ))
        }
    }

    impl ValidQuery for FindAssetsByDomainIdAndAssetDefinitionId {
        #[metrics(+"find_assets_by_domain_id_and_asset_definition_id")]
        fn execute<'wsv>(
            &self,
            wsv: &'wsv WorldStateView,
        ) -> Result<Box<dyn Iterator<Item = Asset> + 'wsv>, Error> {
            let domain_id = self.domain_id.clone();
            let asset_definition_id = self.asset_definition_id.clone();
            let domain = wsv.domain(&domain_id)?;
            let _definition = domain
                .asset_definitions
                .get(&asset_definition_id)
                .ok_or_else(|| FindError::AssetDefinition(asset_definition_id.clone()))?;
            iroha_logger::trace!(%domain_id, %asset_definition_id);
            Ok(Box::new(
                domain
                    .accounts
                    .values()
                    .flat_map(move |account| {
                        let domain_id = domain_id.clone();
                        let asset_definition_id = asset_definition_id.clone();

                        account.assets.values().filter(move |asset| {
                            asset.id().account_id.domain_id == domain_id
                                && asset.id().definition_id == asset_definition_id
                        })
                    })
                    .cloned(),
            ))
        }
    }

    impl ValidQuery for FindAssetQuantityById {
        #[metrics(+"find_asset_quantity_by_id")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Numeric, Error> {
            let id = &self.id;
            iroha_logger::trace!(%id);
            let value = wsv
                .asset(id)
                .map_err(|asset_err| {
                    if let Err(definition_err) = wsv.asset_definition(&id.definition_id) {
                        Error::Find(definition_err)
                    } else {
                        asset_err
                    }
                })?
                .value;

            match value {
                AssetValue::Store(_) => Err(Error::Conversion(
                    "Can't get quantity for strore asset".to_string(),
                )),
                AssetValue::Numeric(numeric) => Ok(numeric),
            }
        }
    }

    impl ValidQuery for FindTotalAssetQuantityByAssetDefinitionId {
        #[metrics(+"find_total_asset_quantity_by_asset_definition_id")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Numeric, Error> {
            let id = &self.id;
            iroha_logger::trace!(%id);
            let asset_value = wsv.asset_total_amount(id)?;
            Ok(asset_value)
        }
    }

    impl ValidQuery for FindAssetKeyValueByIdAndKey {
        #[metrics(+"find_asset_key_value_by_id_and_key")]
        fn execute(&self, wsv: &WorldStateView) -> Result<MetadataValue, Error> {
            let id = &self.id;
            let key = &self.key;
            let asset = wsv.asset(id).map_err(|asset_err| {
                if let Err(definition_err) = wsv.asset_definition(&id.definition_id) {
                    Error::Find(definition_err)
                } else {
                    asset_err
                }
            })?;
            iroha_logger::trace!(%id, %key);
            let store: &Metadata = asset
                .value
                .try_as_ref()
                .map_err(eyre::Error::from)
                .map_err(|e| Error::Conversion(e.to_string()))?;
            store
                .get(key)
                .ok_or_else(|| Error::Find(FindError::MetadataKey(key.clone())))
                .cloned()
                .map(Into::into)
        }
    }
}
