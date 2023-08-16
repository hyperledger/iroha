//! This module contains [`Asset`] structure, it's implementation and related traits and
//! instructions implementations.

use iroha_data_model::{
    isi::error::{MathError, Mismatch, TypeError},
    prelude::*,
    query::error::{FindError, QueryExecutionFail},
};
use iroha_primitives::{fixed::Fixed, CheckedOp, IntoMetric};
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
    use iroha_data_model::isi::error::MintabilityError;

    use super::*;
    use crate::smartcontracts::account::isi::forbid_minting;

    impl Execute for SetKeyValue<Asset> {
        #[metrics(+"set_asset_key_value")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let asset_id = self.object_id;

            assert_asset_type(&asset_id.definition_id, wsv, AssetValueType::Store)?;

            // Increase `Store` asset total quantity by 1 if asset was not present earlier
            if matches!(wsv.asset(&asset_id), Err(QueryExecutionFail::Find(_))) {
                wsv.increase_asset_total_amount(&asset_id.definition_id, 1_u32)?;
            }

            wsv.asset_or_insert(&asset_id, Metadata::new())?;
            let asset_metadata_limits = wsv.config.asset_metadata_limits;

            {
                let asset = wsv.asset_mut(&asset_id)?;
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
                target_id: asset_id.clone(),
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

            assert_asset_type(&asset_id.definition_id, wsv, AssetValueType::Store)?;

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
                target_id: asset_id.clone(),
                key: self.key,
                value: Box::new(value),
            })));

            Ok(())
        }
    }

    impl Execute for Transfer<Account, AssetDefinitionId, Account> {
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            wsv.asset_definition_mut(&self.object)?.owned_by = self.destination_id.clone();

            wsv.emit_events(Some(AssetDefinitionEvent::OwnerChanged(
                AssetDefinitionOwnerChanged {
                    asset_definition_id: self.object,
                    new_owner: self.destination_id,
                },
            )));

            Ok(())
        }
    }

    macro_rules! impl_mint {
        ($ty:ty, $metrics:literal) => {
            impl InnerMint for $ty {}

            impl Execute for Mint<Asset, $ty> {
                #[metrics(+$metrics)]
                fn execute(
                    self,
                    authority: &AccountId,
                    wsv: &mut WorldStateView,
                ) -> Result<(), Error> {
                    <$ty as InnerMint>::execute(self, authority, wsv)
                }
            }
        };
    }

    macro_rules! impl_burn {
        ($ty:ty, $metrics:literal) => {
            impl InnerBurn for $ty {}

            impl Execute for Burn<Asset, $ty> {
                #[metrics(+$metrics)]
                fn execute(
                    self,
                    authority: &AccountId,
                    wsv: &mut WorldStateView,
                ) -> Result<(), Error> {
                    <$ty as InnerBurn>::execute(self, authority, wsv)
                }
            }
        };
    }

    macro_rules! impl_transfer {
        ($ty:ty, $metrics:literal) => {
            impl InnerTransfer for $ty {}

            impl Execute for Transfer<Asset, $ty, Account> {
                #[metrics(+$metrics)]
                fn execute(
                    self,
                    authority: &AccountId,
                    wsv: &mut WorldStateView,
                ) -> Result<(), Error> {
                    <$ty as InnerTransfer>::execute(self, authority, wsv)
                }
            }
        };
    }

    impl_mint!(u32, "mint_qty");
    impl_mint!(u128, "mint_big_qty");
    impl_mint!(Fixed, "mint_fixed");

    impl_burn!(u32, "burn_qty");
    impl_burn!(u128, "burn_big_qty");
    impl_burn!(Fixed, "burn_fixed");

    impl_transfer!(u32, "transfer_qty");
    impl_transfer!(u128, "transfer_big_qty");
    impl_transfer!(Fixed, "transfer_fixed");

    /// Trait for blanket mint implementation.
    trait InnerMint {
        fn execute(
            mint: Mint<Asset, Self>,
            _authority: &AccountId,
            wsv: &mut WorldStateView,
        ) -> Result<(), Error>
        where
            Self: AssetInstructionInfo + CheckedOp + IntoMetric + Copy,
            AssetValue: From<Self> + TryAsMut<Self>,
            NumericValue: From<Self> + TryAsMut<Self>,
            eyre::Error: From<<AssetValue as TryAsMut<Self>>::Error>
                + From<<NumericValue as TryAsMut<Self>>::Error>,
            Value: From<Self>,
        {
            let asset_id = mint.destination_id;

            assert_asset_type(
                &asset_id.definition_id,
                wsv,
                <Self as AssetInstructionInfo>::EXPECTED_VALUE_TYPE,
            )?;
            assert_can_mint(
                &asset_id.definition_id,
                wsv,
                <Self as AssetInstructionInfo>::EXPECTED_VALUE_TYPE,
            )?;
            wsv.asset_or_insert(
                &asset_id,
                <Self as AssetInstructionInfo>::DEFAULT_ASSET_VALUE,
            )?;
            let new_quantity = {
                let asset = wsv.asset_mut(&asset_id)?;
                let quantity: &mut Self = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity
                    .checked_add(mint.object)
                    .ok_or(MathError::Overflow)?;
                mint.object
            };

            #[allow(clippy::float_arithmetic)]
            {
                wsv.new_tx_amounts.lock().push(new_quantity.into_metric());
                wsv.increase_asset_total_amount(&asset_id.definition_id, mint.object)?;
            }

            wsv.emit_events(Some(AssetEvent::Added(AssetChanged {
                asset_id: asset_id.clone(),
                amount: mint.object.into(),
            })));

            Ok(())
        }
    }

    /// Trait for blanket burn implementation.
    trait InnerBurn {
        fn execute(
            burn: Burn<Asset, Self>,
            _authority: &AccountId,
            wsv: &mut WorldStateView,
        ) -> Result<(), Error>
        where
            Self: AssetInstructionInfo + CheckedOp + IntoMetric + Copy,
            AssetValue: From<Self> + TryAsMut<Self>,
            NumericValue: From<Self> + TryAsMut<Self>,
            eyre::Error: From<<AssetValue as TryAsMut<Self>>::Error>
                + From<<NumericValue as TryAsMut<Self>>::Error>,
            Value: From<Self>,
        {
            let asset_id = burn.destination_id;

            assert_asset_type(
                &asset_id.definition_id,
                wsv,
                <Self as AssetInstructionInfo>::EXPECTED_VALUE_TYPE,
            )?;
            let burn_quantity = {
                let account = wsv.account_mut(&asset_id.account_id)?;
                let asset = account
                    .assets
                    .get_mut(&asset_id)
                    .ok_or_else(|| FindError::Asset(asset_id.clone()))?;
                let quantity: &mut Self = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity
                    .checked_sub(burn.object)
                    .ok_or(MathError::NotEnoughQuantity)?;
                if asset.value.is_zero_value() {
                    assert!(account.remove_asset(&asset_id).is_some());
                }
                burn.object
            };

            #[allow(clippy::float_arithmetic)]
            {
                wsv.new_tx_amounts.lock().push(burn_quantity.into_metric());
                wsv.decrease_asset_total_amount(&asset_id.definition_id, burn.object)?;
            }

            wsv.emit_events(Some(AssetEvent::Removed(AssetChanged {
                asset_id: asset_id.clone(),
                amount: burn.object.into(),
            })));

            Ok(())
        }
    }

    /// Trait for blanket transfer implementation.
    trait InnerTransfer {
        fn execute(
            transfer: Transfer<Asset, Self, Account>,
            _authority: &AccountId,
            wsv: &mut WorldStateView,
        ) -> Result<(), Error>
        where
            Self: AssetInstructionInfo + CheckedOp + IntoMetric + Copy,
            AssetValue: From<Self> + TryAsMut<Self>,
            eyre::Error: From<<AssetValue as TryAsMut<Self>>::Error>,
            Value: From<Self>,
        {
            let source_id = &transfer.source_id;
            let destination_id = AssetId::new(
                source_id.definition_id.clone(),
                transfer.destination_id.clone(),
            );

            wsv.asset_or_insert(
                &destination_id,
                <Self as AssetInstructionInfo>::DEFAULT_ASSET_VALUE,
            )?;
            {
                let account = wsv.account_mut(&source_id.account_id)?;
                let asset = account
                    .assets
                    .get_mut(source_id)
                    .ok_or_else(|| FindError::Asset(source_id.clone()))?;
                let quantity: &mut Self = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity
                    .checked_sub(transfer.object)
                    .ok_or(MathError::NotEnoughQuantity)?;
                if asset.value.is_zero_value() {
                    assert!(account.remove_asset(source_id).is_some());
                }
            }

            let transfer_quantity = {
                let asset = wsv.asset_mut(&destination_id)?;
                let quantity: &mut Self = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity
                    .checked_add(transfer.object)
                    .ok_or(MathError::Overflow)?;
                transfer.object
            };

            #[allow(clippy::float_arithmetic)]
            {
                wsv.new_tx_amounts
                    .lock()
                    .push(transfer_quantity.into_metric());
            }

            wsv.emit_events([
                AssetEvent::Removed(AssetChanged {
                    asset_id: source_id.clone(),
                    amount: transfer.object.into(),
                }),
                AssetEvent::Added(AssetChanged {
                    asset_id: destination_id.clone(),
                    amount: transfer.object.into(),
                }),
            ]);

            Ok(())
        }
    }

    /// Trait for collecting fields associated with Iroha Special Instructions for assets:
    /// - asset value type
    /// - default asset value
    trait AssetInstructionInfo {
        const EXPECTED_VALUE_TYPE: AssetValueType;
        const DEFAULT_ASSET_VALUE: Self;
    }

    macro_rules! impl_asset_instruction_info {
        ($ty:ty, $expected_value_type:expr, $default_value:expr) => {
            impl AssetInstructionInfo for $ty {
                const EXPECTED_VALUE_TYPE: AssetValueType = $expected_value_type;
                const DEFAULT_ASSET_VALUE: Self = $default_value;
            }
        };
    }

    impl_asset_instruction_info!(u32, AssetValueType::Quantity, 0_u32);
    impl_asset_instruction_info!(u128, AssetValueType::BigQuantity, 0_u128);
    impl_asset_instruction_info!(Fixed, AssetValueType::Fixed, Fixed::ZERO);

    /// Asserts that asset definition with [`definition_id`] has asset type [`expected_value_type`].
    pub(crate) fn assert_asset_type(
        definition_id: &AssetDefinitionId,
        wsv: &WorldStateView,
        expected_value_type: AssetValueType,
    ) -> Result<AssetDefinition, Error> {
        let asset_definition = wsv.asset_definition(definition_id)?;
        if asset_definition.value_type == expected_value_type {
            Ok(asset_definition)
        } else {
            Err(TypeError::from(Mismatch {
                expected: expected_value_type,
                actual: asset_definition.value_type,
            })
            .into())
        }
    }

    /// Assert that this asset is `mintable`.
    fn assert_can_mint(
        definition_id: &AssetDefinitionId,
        wsv: &mut WorldStateView,
        expected_value_type: AssetValueType,
    ) -> Result<(), Error> {
        let asset_definition = assert_asset_type(definition_id, wsv, expected_value_type)?;
        match asset_definition.mintable {
            Mintable::Infinitely => Ok(()),
            Mintable::Not => Err(Error::Mintability(MintabilityError::MintUnmintable)),
            Mintable::Once => {
                let asset_definition = wsv.asset_definition_mut(definition_id)?;
                forbid_minting(asset_definition)?;
                wsv.emit_events(Some(AssetDefinitionEvent::MintabilityChanged(
                    definition_id.clone(),
                )));
                Ok(())
            }
        }
    }
}

/// Asset-related query implementations.
pub mod query {
    use eyre::{Result, WrapErr as _};
    use iroha_data_model::{
        asset::{Asset, AssetDefinition},
        query::{asset::IsAssetDefinitionOwner, error::QueryExecutionFail as Error, MetadataValue},
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
            let id = wsv
                .evaluate(&self.id)
                .wrap_err("Failed to get asset id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%id);
            wsv.asset(&id).map_err(|asset_err| {
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
            let id = wsv
                .evaluate(&self.id)
                .wrap_err("Failed to get asset definition id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;

            let entry = wsv.asset_definition(&id).map_err(Error::from)?;

            Ok(entry)
        }
    }

    impl ValidQuery for FindAssetsByName {
        #[metrics(+"find_assets_by_name")]
        fn execute<'wsv>(
            &self,
            wsv: &'wsv WorldStateView,
        ) -> Result<Box<dyn Iterator<Item = Asset> + 'wsv>, Error> {
            let name = wsv
                .evaluate(&self.name)
                .wrap_err("Failed to get asset name")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
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
            let id = wsv
                .evaluate(&self.account_id)
                .wrap_err("Failed to get account id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%id);
            Ok(Box::new(wsv.account_assets(&id)?.cloned()))
        }
    }

    impl ValidQuery for FindAssetsByAssetDefinitionId {
        #[metrics(+"find_assets_by_asset_definition_id")]
        fn execute<'wsv>(
            &self,
            wsv: &'wsv WorldStateView,
        ) -> Result<Box<dyn Iterator<Item = Asset> + 'wsv>, Error> {
            let id = wsv
                .evaluate(&self.asset_definition_id)
                .wrap_err("Failed to get asset definition id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
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
            let id = wsv
                .evaluate(&self.domain_id)
                .wrap_err("Failed to get domain id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%id);
            Ok(Box::new(
                wsv.domain(&id)?
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
            let domain_id = wsv
                .evaluate(&self.domain_id)
                .wrap_err("Failed to get domain id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let asset_definition_id = wsv
                .evaluate(&self.asset_definition_id)
                .wrap_err("Failed to get asset definition id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
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
        fn execute(&self, wsv: &WorldStateView) -> Result<NumericValue, Error> {
            let id = wsv
                .evaluate(&self.id)
                .wrap_err("Failed to get asset id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%id);
            let value = wsv
                .asset(&id)
                .map_err(|asset_err| {
                    if let Err(definition_err) = wsv.asset_definition(&id.definition_id) {
                        Error::Find(definition_err)
                    } else {
                        asset_err
                    }
                })?
                .value;
            let value =
                NumericValue::try_from(value).map_err(|err| Error::Conversion(err.to_string()))?;
            Ok(value)
        }
    }

    impl ValidQuery for FindTotalAssetQuantityByAssetDefinitionId {
        #[metrics(+"find_total_asset_quantity_by_asset_definition_id")]
        fn execute(&self, wsv: &WorldStateView) -> Result<NumericValue, Error> {
            let id = wsv
                .evaluate(&self.id)
                .wrap_err("Failed to get asset definition id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%id);
            let asset_value = wsv.asset_total_amount(&id)?;
            Ok(asset_value)
        }
    }

    impl ValidQuery for FindAssetKeyValueByIdAndKey {
        #[metrics(+"find_asset_key_value_by_id_and_key")]
        fn execute(&self, wsv: &WorldStateView) -> Result<MetadataValue, Error> {
            let id = wsv
                .evaluate(&self.id)
                .wrap_err("Failed to get asset id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let key = wsv
                .evaluate(&self.key)
                .wrap_err("Failed to get key")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let asset = wsv.asset(&id).map_err(|asset_err| {
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
                .get(&key)
                .ok_or_else(|| Error::Find(FindError::MetadataKey(key)))
                .cloned()
                .map(Into::into)
        }
    }

    impl ValidQuery for IsAssetDefinitionOwner {
        #[metrics("is_asset_definition_owner")]
        fn execute(&self, wsv: &WorldStateView) -> Result<bool, Error> {
            let asset_definition_id = wsv
                .evaluate(&self.asset_definition_id)
                .wrap_err("Failed to get asset definition id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let account_id = wsv
                .evaluate(&self.account_id)
                .wrap_err("Failed to get account id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;

            let entry = wsv.asset_definition(&asset_definition_id)?;
            Ok(entry.owned_by == account_id)
        }
    }
}
