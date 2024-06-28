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
            type_: self.type_,
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
    use iroha_data_model::{asset::AssetType, isi::error::MintabilityError};

    use super::*;
    use crate::smartcontracts::account::isi::forbid_minting;

    impl Execute for SetKeyValue<Asset> {
        #[metrics(+"set_asset_key_value")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let asset_id = self.object;

            assert_asset_type(
                &asset_id.definition,
                state_transaction,
                expected_asset_type_store,
            )?;

            // Increase `Store` asset total quantity by 1 if asset was not present earlier
            if matches!(
                state_transaction.world.asset(&asset_id),
                Err(QueryExecutionFail::Find(_))
            ) {
                state_transaction
                    .world
                    .increase_asset_total_amount(&asset_id.definition, Numeric::ONE)?;
            }

            let asset = state_transaction
                .world
                .asset_or_insert(asset_id.clone(), Metadata::default())?;

            {
                let AssetValue::Store(store) = &mut asset.value else {
                    return Err(Error::Conversion("Expected store asset type".to_owned()));
                };

                store.insert(self.key.clone(), self.value.clone());
            }

            state_transaction
                .world
                .emit_events(Some(AssetEvent::MetadataInserted(MetadataChanged {
                    target: asset_id,
                    key: self.key,
                    value: self.value,
                })));

            Ok(())
        }
    }

    impl Execute for RemoveKeyValue<Asset> {
        #[metrics(+"remove_asset_key_value")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let asset_id = self.object;

            assert_asset_type(
                &asset_id.definition,
                state_transaction,
                expected_asset_type_store,
            )?;

            let value = {
                let asset = state_transaction.world.asset_mut(&asset_id)?;

                let AssetValue::Store(store) = &mut asset.value else {
                    return Err(Error::Conversion("Expected store asset type".to_owned()));
                };

                store
                    .remove(&self.key)
                    .ok_or_else(|| FindError::MetadataKey(self.key.clone()))?
            };

            state_transaction
                .world
                .emit_events(Some(AssetEvent::MetadataRemoved(MetadataChanged {
                    target: asset_id,
                    key: self.key,
                    value,
                })));

            Ok(())
        }
    }

    impl Execute for Transfer<Asset, Metadata, Account> {
        #[metrics(+"transfer_store")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let asset_id = self.source;
            assert_asset_type(
                &asset_id.definition,
                state_transaction,
                expected_asset_type_store,
            )?;

            let asset = state_transaction
                .world
                .account_mut(&asset_id.account)
                .and_then(|account| {
                    account
                        .remove_asset(&asset_id.definition)
                        .ok_or_else(|| FindError::Asset(asset_id.clone()))
                })?;

            let destination_store = {
                let destination_id =
                    AssetId::new(asset_id.definition.clone(), self.destination.clone());
                let destination_store_asset = state_transaction
                    .world
                    .asset_or_insert(destination_id.clone(), asset.value)?;

                destination_store_asset.clone()
            };

            state_transaction.world.emit_events([
                AssetEvent::Deleted(asset_id),
                AssetEvent::Created(destination_store),
            ]);

            Ok(())
        }
    }

    impl Execute for Mint<Numeric, Asset> {
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let asset_id = self.destination;

            let asset_definition = assert_asset_type(
                &asset_id.definition,
                state_transaction,
                expected_asset_type_numeric,
            )?;
            assert_numeric_spec(&self.object, &asset_definition)?;

            assert_can_mint(&asset_definition, state_transaction)?;
            let asset = state_transaction
                .world
                .asset_or_insert(asset_id.clone(), Numeric::ZERO)?;
            let AssetValue::Numeric(quantity) = &mut asset.value else {
                return Err(Error::Conversion("Expected numeric asset type".to_owned()));
            };
            *quantity = quantity
                .checked_add(self.object)
                .ok_or(MathError::Overflow)?;

            #[allow(clippy::float_arithmetic)]
            {
                state_transaction
                    .new_tx_amounts
                    .lock()
                    .push(self.object.to_f64());
                state_transaction
                    .world
                    .increase_asset_total_amount(&asset_id.definition, self.object)?;
            }

            state_transaction
                .world
                .emit_events(Some(AssetEvent::Added(AssetChanged {
                    asset: asset_id,
                    amount: self.object.into(),
                })));

            Ok(())
        }
    }

    impl Execute for Burn<Numeric, Asset> {
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let asset_id = self.destination;

            let asset_definition = assert_asset_type(
                &asset_id.definition,
                state_transaction,
                expected_asset_type_numeric,
            )?;
            assert_numeric_spec(&self.object, &asset_definition)?;

            let account = state_transaction.world.account_mut(&asset_id.account)?;
            let asset = account
                .assets
                .get_mut(&asset_id.definition)
                .ok_or_else(|| FindError::Asset(asset_id.clone()))?;
            let AssetValue::Numeric(quantity) = &mut asset.value else {
                return Err(Error::Conversion("Expected numeric asset type".to_owned()));
            };
            *quantity = quantity
                .checked_sub(self.object)
                .ok_or(MathError::NotEnoughQuantity)?;

            if asset.value.is_zero_value() {
                assert!(account.remove_asset(&asset_id.definition).is_some());
            }

            #[allow(clippy::float_arithmetic)]
            {
                state_transaction
                    .new_tx_amounts
                    .lock()
                    .push(self.object.to_f64());
                state_transaction
                    .world
                    .decrease_asset_total_amount(&asset_id.definition, self.object)?;
            }

            state_transaction
                .world
                .emit_events(Some(AssetEvent::Removed(AssetChanged {
                    asset: asset_id.clone(),
                    amount: self.object.into(),
                })));

            Ok(())
        }
    }

    impl Execute for Transfer<Asset, Numeric, Account> {
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let source_id = self.source;
            let destination_id =
                AssetId::new(source_id.definition.clone(), self.destination.clone());

            let asset_definition = assert_asset_type(
                &source_id.definition,
                state_transaction,
                expected_asset_type_numeric,
            )?;
            assert_numeric_spec(&self.object, &asset_definition)?;

            {
                let account = state_transaction.world.account_mut(&source_id.account)?;
                let asset = account
                    .assets
                    .get_mut(&source_id.definition)
                    .ok_or_else(|| FindError::Asset(source_id.clone()))?;
                let AssetValue::Numeric(quantity) = &mut asset.value else {
                    return Err(Error::Conversion("Expected numeric asset type".to_owned()));
                };
                *quantity = quantity
                    .checked_sub(self.object)
                    .ok_or(MathError::NotEnoughQuantity)?;
                if asset.value.is_zero_value() {
                    assert!(account.remove_asset(&source_id.definition).is_some());
                }
            }

            let destination_asset = state_transaction
                .world
                .asset_or_insert(destination_id.clone(), Numeric::ZERO)?;
            {
                let AssetValue::Numeric(quantity) = &mut destination_asset.value else {
                    return Err(Error::Conversion("Expected numeric asset type".to_owned()));
                };
                *quantity = quantity
                    .checked_add(self.object)
                    .ok_or(MathError::Overflow)?;
            }

            #[allow(clippy::float_arithmetic)]
            {
                state_transaction
                    .new_tx_amounts
                    .lock()
                    .push(self.object.to_f64());
            }

            state_transaction.world.emit_events([
                AssetEvent::Removed(AssetChanged {
                    asset: source_id,
                    amount: self.object.into(),
                }),
                AssetEvent::Added(AssetChanged {
                    asset: destination_id,
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
        let object_asset_type = AssetType::Numeric(object_spec);
        let asset_definition_spec = match asset_definition.type_ {
            AssetType::Numeric(spec) => spec,
            other => {
                return Err(TypeError::from(Mismatch {
                    expected: other,
                    actual: object_asset_type,
                })
                .into())
            }
        };
        asset_definition_spec.check(object).map_err(|_| {
            TypeError::from(Mismatch {
                expected: AssetType::Numeric(asset_definition_spec),
                actual: object_asset_type,
            })
        })?;
        Ok(asset_definition_spec)
    }

    /// Asserts that asset definition with [`definition_id`] has asset type [`expected_type`].
    pub(crate) fn assert_asset_type(
        definition_id: &AssetDefinitionId,
        state_transaction: &StateTransaction<'_, '_>,
        expected_type: impl Fn(&AssetType) -> Result<(), TypeError>,
    ) -> Result<AssetDefinition, Error> {
        let asset_definition = state_transaction.world.asset_definition(definition_id)?;
        expected_type(&asset_definition.type_)
            .map(|()| asset_definition)
            .map_err(Into::into)
    }

    /// Assert that this asset is `mintable`.
    fn assert_can_mint(
        asset_definition: &AssetDefinition,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match asset_definition.mintable {
            Mintable::Infinitely => Ok(()),
            Mintable::Not => Err(Error::Mintability(MintabilityError::MintUnmintable)),
            Mintable::Once => {
                let asset_definition_id = asset_definition.id.clone();
                let asset_definition = state_transaction
                    .world
                    .asset_definition_mut(&asset_definition_id)?;
                forbid_minting(asset_definition)?;
                state_transaction.world.emit_events(Some(
                    AssetDefinitionEvent::MintabilityChanged(asset_definition_id),
                ));
                Ok(())
            }
        }
    }

    pub(crate) fn expected_asset_type_numeric(asset_type: &AssetType) -> Result<(), TypeError> {
        match asset_type {
            AssetType::Numeric(_) => Ok(()),
            other => Err(TypeError::NumericAssetTypeExpected(*other)),
        }
    }

    pub(crate) fn expected_asset_type_store(asset_type: &AssetType) -> Result<(), TypeError> {
        match asset_type {
            AssetType::Store => Ok(()),
            other => Err(TypeError::NumericAssetTypeExpected(*other)),
        }
    }
}

/// Asset-related query implementations.
pub mod query {
    use eyre::Result;
    use iroha_data_model::{
        asset::{Asset, AssetDefinition, AssetValue},
        query::{asset::FindAssetDefinitionById, error::QueryExecutionFail as Error},
    };
    use iroha_primitives::json::JsonString;

    use super::*;
    use crate::state::StateReadOnly;

    impl ValidQuery for FindAllAssets {
        #[metrics(+"find_all_assets")]
        fn execute<'state>(
            &self,
            state_ro: &'state impl StateReadOnly,
        ) -> Result<Box<dyn Iterator<Item = Asset> + 'state>, Error> {
            Ok(Box::new(
                state_ro
                    .world()
                    .accounts_iter()
                    .flat_map(|account| account.assets.values())
                    .cloned(),
            ))
        }
    }

    impl ValidQuery for FindAllAssetsDefinitions {
        #[metrics(+"find_all_asset_definitions")]
        fn execute<'state>(
            &self,
            state_ro: &'state impl StateReadOnly,
        ) -> Result<Box<dyn Iterator<Item = AssetDefinition> + 'state>, Error> {
            Ok(Box::new(
                state_ro
                    .world()
                    .domains_iter()
                    .flat_map(|domain| domain.asset_definitions.values())
                    .cloned(),
            ))
        }
    }

    impl ValidQuery for FindAssetById {
        #[metrics(+"find_asset_by_id")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<Asset, Error> {
            let id = &self.id;
            iroha_logger::trace!(%id);
            state_ro.world().asset(id).map_err(|asset_err| {
                if let Err(definition_err) = state_ro.world().asset_definition(&id.definition) {
                    definition_err.into()
                } else {
                    asset_err
                }
            })
        }
    }

    impl ValidQuery for FindAssetDefinitionById {
        #[metrics(+"find_asset_defintion_by_id")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<AssetDefinition, Error> {
            let id = &self.id;

            let entry = state_ro.world().asset_definition(id).map_err(Error::from)?;

            Ok(entry)
        }
    }

    impl ValidQuery for FindAssetsByName {
        #[metrics(+"find_assets_by_name")]
        fn execute<'state>(
            &self,
            state_ro: &'state impl StateReadOnly,
        ) -> Result<Box<dyn Iterator<Item = Asset> + 'state>, Error> {
            let name = self.name.clone();
            iroha_logger::trace!(%name);
            Ok(Box::new(
                state_ro
                    .world()
                    .accounts_iter()
                    .flat_map(move |account| {
                        let name = name.clone();

                        account
                            .assets
                            .values()
                            .filter(move |asset| asset.id().definition.name == name)
                    })
                    .cloned(),
            ))
        }
    }

    impl ValidQuery for FindAssetsByAccountId {
        #[metrics(+"find_assets_by_account_id")]
        fn execute<'state>(
            &self,
            state_ro: &'state impl StateReadOnly,
        ) -> Result<Box<dyn Iterator<Item = Asset> + 'state>, Error> {
            let id = &self.account;
            iroha_logger::trace!(%id);
            Ok(Box::new(state_ro.world().account_assets(id)?.cloned()))
        }
    }

    impl ValidQuery for FindAssetsByAssetDefinitionId {
        #[metrics(+"find_assets_by_asset_definition_id")]
        fn execute<'state>(
            &self,
            state_ro: &'state impl StateReadOnly,
        ) -> Result<Box<dyn Iterator<Item = Asset> + 'state>, Error> {
            let id = self.asset_definition.clone();
            iroha_logger::trace!(%id);
            Ok(Box::new(
                state_ro
                    .world()
                    .accounts_iter()
                    .flat_map(move |account| {
                        let id = id.clone();

                        account
                            .assets
                            .values()
                            .filter(move |asset| asset.id().definition == id)
                    })
                    .cloned(),
            ))
        }
    }

    impl ValidQuery for FindAssetsByDomainId {
        #[metrics(+"find_assets_by_domain_id")]
        fn execute<'state>(
            &self,
            state_ro: &'state impl StateReadOnly,
        ) -> Result<Box<dyn Iterator<Item = Asset> + 'state>, Error> {
            let id = &self.domain;
            iroha_logger::trace!(%id);
            Ok(Box::new(
                state_ro
                    .world()
                    .accounts_in_domain_iter(id)
                    .flat_map(|account| account.assets.values())
                    .cloned(),
            ))
        }
    }

    impl ValidQuery for FindAssetsByDomainIdAndAssetDefinitionId {
        #[metrics(+"find_assets_by_domain_id_and_asset_definition_id")]
        fn execute<'state>(
            &self,
            state_ro: &'state impl StateReadOnly,
        ) -> Result<Box<dyn Iterator<Item = Asset> + 'state>, Error> {
            let domain_id = self.domain.clone();
            let asset_definition_id = self.asset_definition.clone();
            let domain = state_ro.world().domain(&domain_id)?;
            let _definition = domain
                .asset_definitions
                .get(&asset_definition_id)
                .ok_or_else(|| FindError::AssetDefinition(asset_definition_id.clone()))?;
            iroha_logger::trace!(%domain_id, %asset_definition_id);
            Ok(Box::new(
                state_ro
                    .world()
                    .accounts_in_domain_iter(&domain_id)
                    .flat_map(move |account| {
                        let domain_id = domain_id.clone();
                        let asset_definition_id = asset_definition_id.clone();

                        account.assets.values().filter(move |asset| {
                            asset.id().account.domain == domain_id
                                && asset.id().definition == asset_definition_id
                        })
                    })
                    .cloned(),
            ))
        }
    }

    impl ValidQuery for FindAssetQuantityById {
        #[metrics(+"find_asset_quantity_by_id")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<Numeric, Error> {
            let id = &self.id;
            iroha_logger::trace!(%id);
            let value = state_ro
                .world()
                .asset(id)
                .map_err(|asset_err| {
                    if let Err(definition_err) = state_ro.world().asset_definition(&id.definition) {
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
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<Numeric, Error> {
            let id = &self.id;
            iroha_logger::trace!(%id);
            let asset_value = state_ro.world().asset_total_amount(id)?;
            Ok(asset_value)
        }
    }

    impl ValidQuery for FindAssetKeyValueByIdAndKey {
        #[metrics(+"find_asset_key_value_by_id_and_key")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<JsonString, Error> {
            let id = &self.id;
            let key = &self.key;
            let asset = state_ro.world().asset(id).map_err(|asset_err| {
                if let Err(definition_err) = state_ro.world().asset_definition(&id.definition) {
                    Error::Find(definition_err)
                } else {
                    asset_err
                }
            })?;
            iroha_logger::trace!(%id, %key);
            let AssetValue::Store(store) = &asset.value else {
                return Err(Error::Conversion("expected store, found other".to_owned()));
            };

            store
                .get(key)
                .ok_or_else(|| Error::Find(FindError::MetadataKey(key.clone())))
                .cloned()
                .map(Into::into)
        }
    }
}
