//! This module contains [`Asset`] structure, it's implementation and related traits and
//! instructions implementations.

use iroha_data_model::{
    prelude::*,
    primitives::{CheckedOp, IntoMetric},
};
use iroha_telemetry::metrics;

use super::prelude::*;

/// ISI module contains all instructions related to assets:
/// - minting/burning assets
/// - update metadata
/// - transfer, etc.
pub mod isi {
    use super::*;

    impl Execute for SetKeyValue<Asset, Name, Value> {
        type Error = Error;

        #[metrics(+"asset_set_key_value")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
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

    impl Execute for RemoveKeyValue<Asset, Name> {
        type Error = Error;

        #[metrics(+"asset_remove_key_value")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
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

    macro_rules! impl_mint {
        ($ty:ty, $metrics:literal) => {
            impl InnerMint for $ty {}

            impl Execute for Mint<Asset, $ty> {
                type Error = Error;

                #[metrics(+$metrics)]
                fn execute(
                    self,
                    authority: AccountId,
                    wsv: &WorldStateView,
                ) -> Result<(), Self::Error> {
                    <$ty as InnerMint>::execute(self, authority, wsv)
                }
            }
        };
    }

    macro_rules! impl_burn {
        ($ty:ty, $metrics:literal) => {
            impl InnerBurn for $ty {}

            impl Execute for Burn<Asset, $ty> {
                type Error = Error;

                #[metrics(+$metrics)]
                fn execute(
                    self,
                    authority: AccountId,
                    wsv: &WorldStateView,
                ) -> Result<(), Self::Error> {
                    <$ty as InnerBurn>::execute(self, authority, wsv)
                }
            }
        };
    }

    macro_rules! impl_transfer {
        ($ty:ty, $metrics:literal) => {
            impl InnerTransfer for $ty {}

            impl Execute for Transfer<Asset, $ty, Asset> {
                type Error = Error;

                #[metrics(+$metrics)]
                fn execute(
                    self,
                    authority: AccountId,
                    wsv: &WorldStateView,
                ) -> Result<(), Self::Error> {
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
        fn execute<Err>(
            mint: Mint<Asset, Self>,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Err>
        where
            Self: AssetInstructionInfo + CheckedOp + IntoMetric + Copy,
            AssetValue: From<Self> + TryAsMut<Self>,
            Value: From<Self>,
            <AssetValue as TryAsMut<Self>>::Error: std::error::Error + Send + Sync + 'static,
            Err: From<Error>,
        {
            let asset_id = mint.destination_id;

            assert_can_mint(
                &asset_id.definition_id,
                wsv,
                <Self as AssetInstructionInfo>::EXPECTED_VALUE_TYPE,
            )?;
            wsv.asset_or_insert(
                &asset_id,
                <Self as AssetInstructionInfo>::DEFAULT_ASSET_VALUE,
            )?;
            wsv.modify_asset(&asset_id, |asset| {
                let quantity: &mut Self = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity
                    .checked_add(mint.object)
                    .ok_or(MathError::Overflow)?;
                wsv.metrics.tx_amounts.observe((*quantity).into_metric());

                Ok(AssetEvent::Added(asset_id.clone()))
            })?;
            Ok(())
        }
    }

    /// Trait for blanket burn implementation.
    trait InnerBurn {
        fn execute<Err>(
            burn: Burn<Asset, Self>,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Err>
        where
            Self: AssetInstructionInfo + CheckedOp + IntoMetric + Copy,
            AssetValue: From<Self> + TryAsMut<Self>,
            Value: From<Self>,
            <AssetValue as TryAsMut<Self>>::Error: std::error::Error + Send + Sync + 'static,
            Err: From<Error>,
        {
            let asset_id = burn.destination_id;

            assert_asset_type(
                &asset_id.definition_id,
                wsv,
                <Self as AssetInstructionInfo>::EXPECTED_VALUE_TYPE,
            )?;
            wsv.modify_asset(&asset_id, |asset| {
                let quantity: &mut Self = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity
                    .checked_sub(burn.object)
                    .ok_or(MathError::NotEnoughQuantity)?;
                wsv.metrics.tx_amounts.observe((*quantity).into_metric());

                Ok(AssetEvent::Removed(asset_id.clone()))
            })?;
            Ok(())
        }
    }

    /// Trait for blanket transfer implementation.
    trait InnerTransfer {
        fn execute<Err>(
            transfer: Transfer<Asset, Self, Asset>,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Err>
        where
            Self: AssetInstructionInfo + CheckedOp + IntoMetric + Copy,
            AssetValue: From<Self> + TryAsMut<Self>,
            Value: From<Self>,
            <AssetValue as TryAsMut<Self>>::Error: std::error::Error + Send + Sync + 'static,
            Err: From<Error>,
        {
            assert_matching_definitions(
                &transfer.source_id,
                &transfer.destination_id,
                wsv,
                <Self as AssetInstructionInfo>::EXPECTED_VALUE_TYPE,
            )?;

            wsv.asset_or_insert(
                &transfer.destination_id,
                <Self as AssetInstructionInfo>::DEFAULT_ASSET_VALUE,
            )?;
            wsv.modify_asset(&transfer.source_id, |asset| {
                let quantity: &mut Self = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity
                    .checked_sub(transfer.object)
                    .ok_or(MathError::NotEnoughQuantity)?;

                Ok(AssetEvent::Removed(transfer.source_id.clone()))
            })?;
            wsv.modify_asset(&transfer.destination_id, |asset| {
                let quantity: &mut Self = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity
                    .checked_add(transfer.object)
                    .ok_or(MathError::Overflow)?;
                wsv.metrics.tx_amounts.observe((*quantity).into_metric());

                Ok(AssetEvent::Added(transfer.destination_id.clone()))
            })?;
            Ok(())
        }
    }

    /// Trait for collecting fields associated with asset isi instructions:
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
        let asset_definition = wsv.asset_definition_entry(definition_id)?;
        let definition = asset_definition.definition();
        if *definition.value_type() == expected_value_type {
            Ok(definition.clone())
        } else {
            Err(TypeError::from(Mismatch {
                expected: expected_value_type,
                actual: *definition.value_type(),
            })
            .into())
        }
    }

    /// Assert that this asset is `mintable`.
    fn assert_can_mint(
        definition_id: &AssetDefinitionId,
        wsv: &WorldStateView,
        expected_value_type: AssetValueType,
    ) -> Result<(), Error> {
        let definition = assert_asset_type(definition_id, wsv, expected_value_type)?;
        match definition.mintable() {
            Mintable::Infinitely => Ok(()),
            Mintable::Not => Err(Error::Mintability(MintabilityError::MintUnmintable)),
            Mintable::Once => wsv.modify_asset_definition_entry(definition_id, |entry| {
                entry.forbid_minting()?;
                Ok(AssetDefinitionEvent::MintabilityChanged(
                    definition_id.clone(),
                ))
            }),
        }
    }

    /// Assert that the two assets have the same asset `definition_id`.
    fn assert_matching_definitions(
        source: &<Asset as Identifiable>::Id,
        destination: &<Asset as Identifiable>::Id,
        wsv: &WorldStateView,
        value_type: AssetValueType,
    ) -> Result<(), Error> {
        if destination.definition_id != source.definition_id {
            let expected = wsv
                .asset_definition_entry(&destination.definition_id)?
                .definition()
                .id()
                .clone();
            let actual = wsv
                .asset_definition_entry(&source.definition_id)?
                .definition()
                .id()
                .clone();
            return Err(TypeError::from(Box::new(Mismatch { expected, actual })).into());
        }
        assert_asset_type(&source.definition_id, wsv, value_type)?;
        assert_asset_type(&destination.definition_id, wsv, value_type)?;
        Ok(())
    }
}

/// Asset-related query implementations.
pub mod query {
    use eyre::{Result, WrapErr as _};

    use super::*;
    use crate::smartcontracts::query::Error;

    impl ValidQuery for FindAllAssets {
        #[metrics(+"find_all_assets")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
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

    impl ValidQuery for FindAllAssetsDefinitions {
        #[metrics(+"find_all_asset_definitions")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            let mut vec = Vec::new();
            for domain in wsv.domains().iter() {
                for asset_definition_entry in domain.asset_definitions() {
                    vec.push(asset_definition_entry.definition().clone())
                }
            }
            Ok(vec)
        }
    }

    impl ValidQuery for FindAssetById {
        #[metrics(+"find_asset_by_id")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%id);
            wsv.asset(&id).map_err(|asset_err| {
                if let Err(definition_err) = wsv.asset_definition_entry(&id.definition_id) {
                    definition_err.into()
                } else {
                    asset_err
                }
            })
        }
    }

    impl ValidQuery for FindAssetDefinitionById {
        #[metrics(+"find_asset_defintion_by_id")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset definition id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;

            let entry = wsv.asset_definition_entry(&id).map_err(Error::from)?;

            Ok(entry.definition().clone())
        }
    }

    impl ValidQuery for FindAssetsByName {
        #[metrics(+"find_assets_by_name")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            let name = self
                .name
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset name")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%name);
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

    impl ValidQuery for FindAssetsByAccountId {
        #[metrics(+"find_assets_by_account_id")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            let id = self
                .account_id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get account id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%id);
            wsv.account_assets(&id).map_err(Into::into)
        }
    }

    impl ValidQuery for FindAssetsByAssetDefinitionId {
        #[metrics(+"find_assets_by_asset_definition_id")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            let id = self
                .asset_definition_id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset definition id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%id);
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

    impl ValidQuery for FindAssetsByDomainId {
        #[metrics(+"find_assets_by_domain_id")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            let id = self
                .domain_id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get domain id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%id);
            let mut vec = Vec::new();
            for account in wsv.domain(&id)?.accounts() {
                for asset in account.assets() {
                    vec.push(asset.clone())
                }
            }
            Ok(vec)
        }
    }

    impl ValidQuery for FindAssetsByDomainIdAndAssetDefinitionId {
        #[metrics(+"find_assets_by_domain_id_and_asset_definition_id")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
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
            iroha_logger::trace!(%domain_id, %asset_definition_id);
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

    impl ValidQuery for FindAssetQuantityById {
        #[metrics(+"find_asset_quantity_by_id")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%id);
            wsv.asset(&id)
                .map_err(|asset_err| {
                    if let Err(definition_err) = wsv.asset_definition_entry(&id.definition_id) {
                        Error::Find(Box::new(definition_err))
                    } else {
                        asset_err
                    }
                })?
                .value()
                .try_as_ref()
                .map_err(eyre::Error::from)
                .map_err(|e| Error::Conversion(e.to_string()))
                .map(Clone::clone)
        }
    }

    impl ValidQuery for FindAssetKeyValueByIdAndKey {
        #[metrics(+"find_asset_key_value_by_id_and_key")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
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
                if let Err(definition_err) = wsv.asset_definition_entry(&id.definition_id) {
                    Error::Find(Box::new(definition_err))
                } else {
                    asset_err
                }
            })?;
            iroha_logger::trace!(%id, %key);
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
