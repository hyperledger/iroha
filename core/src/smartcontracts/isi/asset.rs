//! This module contains [`Asset`] structure, it's implementation and related traits and
//! instructions implementations.

use iroha_data_model::{
    isi::error::{MathError, Mismatch, TypeError},
    prelude::*,
    query::error::{FindError, QueryExecutionFailure},
};
use iroha_primitives::{fixed::Fixed, CheckedOp, IntoMetric};
use iroha_telemetry::metrics;

use super::prelude::*;

impl Registrable for NewAssetDefinition {
    type Target = AssetDefinition;

    #[must_use]
    #[inline]
    fn build(self, authority: AccountId) -> Self::Target {
        Self::Target {
            id: self.id,
            value_type: self.value_type,
            mintable: self.mintable,
            logo: self.logo,
            metadata: self.metadata,
            owned_by: authority,
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
        type Error = Error;

        #[metrics(+"asset_set_key_value")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let asset_id = self.object_id;

            assert_asset_type(&asset_id.definition_id, wsv, AssetValueType::Store)?;

            // Increase `Store` asset total quantity by 1 if asset was not present earlier
            if matches!(wsv.asset(&asset_id), Err(QueryExecutionFailure::Find(_))) {
                wsv.increase_asset_total_amount(&asset_id.definition_id, 1_u32)?;
            }

            wsv.asset_or_insert(&asset_id, Metadata::new())?;
            let asset_metadata_limits = wsv.config.borrow().asset_metadata_limits;

            wsv.modify_asset(&asset_id, |asset| {
                let store: &mut Metadata = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                store.insert_with_limits(
                    self.key.clone(),
                    self.value.clone(),
                    asset_metadata_limits,
                )?;

                Ok(AssetEvent::MetadataInserted(MetadataChanged {
                    target_id: asset_id.clone(),
                    key: self.key,
                    value: Box::new(self.value),
                }))
            })
        }
    }

    impl Execute for RemoveKeyValue<Asset> {
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
                let value = store
                    .remove(&self.key)
                    .ok_or_else(|| FindError::MetadataKey(self.key.clone()))?;

                Ok(AssetEvent::MetadataRemoved(MetadataChanged {
                    target_id: asset_id.clone(),
                    key: self.key,
                    value: Box::new(value),
                }))
            })
        }
    }

    impl Execute for Transfer<Account, AssetDefinition, Account> {
        type Error = Error;

        fn execute(self, _authority: AccountId, wsv: &WorldStateView) -> Result<(), Self::Error> {
            wsv.modify_asset_definition(self.object.id(), |entry| {
                entry.owned_by = self.destination_id.clone();

                Ok(AssetDefinitionEvent::OwnerChanged(
                    AssetDefinitionOwnerChanged {
                        asset_definition_id: self.object.id().clone(),
                        new_owner: self.destination_id,
                    },
                ))
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

            impl Execute for Transfer<Asset, $ty, Account> {
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
            NumericValue: From<Self> + TryAsMut<Self>,
            eyre::Error: From<<AssetValue as TryAsMut<Self>>::Error>
                + From<<NumericValue as TryAsMut<Self>>::Error>,
            Value: From<Self>,
            Err: From<Error>,
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
            wsv.modify_asset(&asset_id, |asset| {
                let quantity: &mut Self = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity
                    .checked_add(mint.object)
                    .ok_or(MathError::Overflow)?;
                #[allow(clippy::float_arithmetic)]
                wsv.metric_tx_amounts
                    .set(wsv.metric_tx_amounts.get() + (*quantity).into_metric());
                wsv.metric_tx_amounts_counter
                    .set(wsv.metric_tx_amounts_counter.get() + 1);

                Ok(AssetEvent::Added(AssetChanged {
                    asset_id: asset_id.clone(),
                    amount: mint.object.into(),
                }))
            })?;

            wsv.increase_asset_total_amount(&asset_id.definition_id, mint.object)?;
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
            NumericValue: From<Self> + TryAsMut<Self>,
            eyre::Error: From<<AssetValue as TryAsMut<Self>>::Error>
                + From<<NumericValue as TryAsMut<Self>>::Error>,
            Value: From<Self>,
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
                #[allow(clippy::float_arithmetic)]
                wsv.metric_tx_amounts
                    .set(wsv.metric_tx_amounts.get() + (*quantity).into_metric());
                wsv.metric_tx_amounts_counter
                    .set(wsv.metric_tx_amounts_counter.get() + 1);

                Ok(AssetEvent::Removed(AssetChanged {
                    asset_id: asset_id.clone(),
                    amount: burn.object.into(),
                }))
            })?;

            wsv.decrease_asset_total_amount(&asset_id.definition_id, burn.object)?;

            Ok(())
        }
    }

    /// Trait for blanket transfer implementation.
    trait InnerTransfer {
        fn execute<Err>(
            transfer: Transfer<Asset, Self, Account>,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Err>
        where
            Self: AssetInstructionInfo + CheckedOp + IntoMetric + Copy,
            AssetValue: From<Self> + TryAsMut<Self>,
            eyre::Error: From<<AssetValue as TryAsMut<Self>>::Error>,
            Value: From<Self>,
            Err: From<Error>,
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
            wsv.modify_asset(source_id, |asset| {
                let quantity: &mut Self = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity
                    .checked_sub(transfer.object)
                    .ok_or(MathError::NotEnoughQuantity)?;

                Ok(AssetEvent::Removed(AssetChanged {
                    asset_id: source_id.clone(),
                    amount: transfer.object.into(),
                }))
            })?;
            let destination_id_clone = destination_id.clone();
            wsv.modify_asset(&destination_id, |asset| {
                let quantity: &mut Self = asset
                    .try_as_mut()
                    .map_err(eyre::Error::from)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
                *quantity = quantity
                    .checked_add(transfer.object)
                    .ok_or(MathError::Overflow)?;
                #[allow(clippy::float_arithmetic)]
                wsv.metric_tx_amounts
                    .set(wsv.metric_tx_amounts.get() + (*quantity).into_metric());
                wsv.metric_tx_amounts_counter
                    .set(wsv.metric_tx_amounts_counter.get() + 1);

                Ok(AssetEvent::Added(AssetChanged {
                    asset_id: destination_id_clone,
                    amount: transfer.object.into(),
                }))
            })?;
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
        wsv: &WorldStateView,
        expected_value_type: AssetValueType,
    ) -> Result<(), Error> {
        let asset_definition = assert_asset_type(definition_id, wsv, expected_value_type)?;
        match asset_definition.mintable {
            Mintable::Infinitely => Ok(()),
            Mintable::Not => Err(Error::Mintability(MintabilityError::MintUnmintable)),
            Mintable::Once => wsv.modify_asset_definition(definition_id, |entry| {
                forbid_minting(entry)?;
                Ok(AssetDefinitionEvent::MintabilityChanged(
                    definition_id.clone(),
                ))
            }),
        }
    }
}

/// Asset-related query implementations.
pub mod query {
    use eyre::{Result, WrapErr as _};
    use iroha_data_model::query::{
        asset::IsAssetDefinitionOwner, error::QueryExecutionFailure as Error,
    };

    use super::*;

    impl ValidQuery for FindAllAssets {
        #[metrics(+"find_all_assets")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
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

    impl ValidQuery for FindAllAssetsDefinitions {
        #[metrics(+"find_all_asset_definitions")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            let mut vec = Vec::new();
            for domain in wsv.domains().iter() {
                for asset_definition in domain.asset_definitions.values() {
                    vec.push(asset_definition.clone())
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
                .evaluate(&Context::new(wsv))
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
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            let id = self
                .id
                .evaluate(&Context::new(wsv))
                .wrap_err("Failed to get asset definition id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;

            let entry = wsv.asset_definition(&id).map_err(Error::from)?;

            Ok(entry)
        }
    }

    impl ValidQuery for FindAssetsByName {
        #[metrics(+"find_assets_by_name")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            let name = self
                .name
                .evaluate(&Context::new(wsv))
                .wrap_err("Failed to get asset name")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%name);
            let mut vec = Vec::new();
            for domain in wsv.domains().iter() {
                for account in domain.accounts.values() {
                    for asset in account.assets.values() {
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
                .evaluate(&Context::new(wsv))
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
                .evaluate(&Context::new(wsv))
                .wrap_err("Failed to get asset definition id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%id);
            let mut vec = Vec::new();
            for domain in wsv.domains().iter() {
                for account in domain.accounts.values() {
                    for asset in account.assets.values() {
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
                .evaluate(&Context::new(wsv))
                .wrap_err("Failed to get domain id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%id);
            let mut vec = Vec::new();
            for account in wsv.domain(&id)?.accounts.values() {
                for asset in account.assets.values() {
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
                .evaluate(&Context::new(wsv))
                .wrap_err("Failed to get domain id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let asset_definition_id = self
                .asset_definition_id
                .evaluate(&Context::new(wsv))
                .wrap_err("Failed to get asset definition id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let domain = wsv.domain(&domain_id)?;
            let _definition = domain
                .asset_definitions
                .get(&asset_definition_id)
                .ok_or_else(|| FindError::AssetDefinition(asset_definition_id.clone()))?;
            iroha_logger::trace!(%domain_id, %asset_definition_id);
            let mut assets = Vec::new();
            for account in domain.accounts.values() {
                for asset in account.assets.values() {
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
                .evaluate(&Context::new(wsv))
                .wrap_err("Failed to get asset id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%id);
            let value = wsv
                .asset(&id)
                .map_err(|asset_err| {
                    if let Err(definition_err) = wsv.asset_definition(&id.definition_id) {
                        Error::Find(Box::new(definition_err))
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
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            let id = self
                .id
                .evaluate(&Context::new(wsv))
                .wrap_err("Failed to get asset definition id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%id);
            let asset_value = wsv.asset_total_amount(&id)?;
            Ok(asset_value)
        }
    }

    impl ValidQuery for FindAssetKeyValueByIdAndKey {
        #[metrics(+"find_asset_key_value_by_id_and_key")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            let id = self
                .id
                .evaluate(&Context::new(wsv))
                .wrap_err("Failed to get asset id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let key = self
                .key
                .evaluate(&Context::new(wsv))
                .wrap_err("Failed to get key")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let asset = wsv.asset(&id).map_err(|asset_err| {
                if let Err(definition_err) = wsv.asset_definition(&id.definition_id) {
                    Error::Find(Box::new(definition_err))
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
            Ok(store
                .get(&key)
                .ok_or_else(|| Error::Find(Box::new(FindError::MetadataKey(key))))?
                .clone())
        }
    }

    impl ValidQuery for IsAssetDefinitionOwner {
        #[metrics("is_asset_definition_owner")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            let asset_definition_id = self
                .asset_definition_id
                .evaluate(&Context::new(wsv))
                .wrap_err("Failed to get asset definition id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let account_id = self
                .account_id
                .evaluate(&Context::new(wsv))
                .wrap_err("Failed to get account id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;

            let entry = wsv.asset_definition(&asset_definition_id)?;
            Ok(entry.owned_by == account_id)
        }
    }
}
