//! ## Asset ISI and queries

use iroha_data_model::{
    isi::error::{MathError, Mismatch, TypeError},
    prelude::*,
    query::error::FindError,
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
            spec: self.spec,
            mintable: self.mintable,
            logo: self.logo,
            metadata: self.metadata,
            owned_by: authority.clone(),
            total_quantity: Numeric::ZERO,
        }
    }
}

/// ISI module contains all instructions related to assets:
/// - minting/burning assets
/// - update metadata
/// - transfer, etc.
pub mod isi {
    use iroha_data_model::isi::error::{MintabilityError, RepetitionError};

    use super::*;

    impl Execute for Register<AssetDefinition> {
        #[metrics(+"register_asset_definition")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction,
        ) -> Result<(), Error> {
            let asset_definition = self.object.build(authority);

            let world = &mut state_transaction.world;
            if world.asset_definition(&asset_definition.id).is_ok() {
                return Err(RepetitionError {
                    instruction: InstructionType::Register,
                    id: IdBox::AssetDefinitionId(asset_definition.id),
                }
                .into());
            }
            world.domain(&asset_definition.id.domain)?;

            world
                .asset_definitions
                .insert(asset_definition.id.clone(), asset_definition.clone());

            world.emit_events(Some(AssetDefinitionEvent::Created(asset_definition)));
            Ok(())
        }
    }

    impl Execute for Unregister<AssetDefinition> {
        #[metrics(+"unregister_asset_definition")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction,
        ) -> Result<(), Error> {
            let asset_definition = self.object;
            let world = &mut state_transaction.world;

            world.asset_definition(&asset_definition)?;

            let assets_to_remove = world
                .assets
                .iter()
                .filter(|(asset, _)| asset.definition == asset_definition)
                .map(|(asset, _)| asset)
                .cloned()
                .collect::<Vec<_>>();

            let mut events = Vec::with_capacity(assets_to_remove.len() + 1);
            for asset in assets_to_remove {
                let removed = world
                    .assets
                    .remove(asset)
                    .expect("INTERNAL BUG: asset should be removed");
                events.push(AssetEvent::Deleted(removed.id).into());
            }

            world
                .asset_definitions
                .remove(asset_definition.clone())
                .expect("INTERNAL BUG: asset definition should be removed");
            world
                .domain(&asset_definition.domain)
                .expect("INTERNAL BUG: domain should exist");

            events.push(AssetDefinitionEvent::Deleted(asset_definition).into());

            world.emit_events::<_, DataEvent>(events);
            Ok(())
        }
    }

    impl Execute for SetKeyValue<AssetDefinition> {
        #[metrics(+"set_key_value_asset_definition")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction,
        ) -> Result<(), Error> {
            let asset_definition_id = self.object;
            let world = &mut state_transaction.world;
            world
                .asset_definition_mut(&asset_definition_id)?
                .metadata
                .insert(self.key.clone(), self.value.clone());
            world.emit_events(Some(AssetDefinitionEvent::MetadataInserted(
                MetadataChanged {
                    target: asset_definition_id,
                    key: self.key,
                    value: self.value,
                },
            )));
            Ok(())
        }
    }

    impl Execute for RemoveKeyValue<AssetDefinition> {
        #[metrics(+"remove_key_value_asset_definition")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction,
        ) -> Result<(), Error> {
            let asset_definition_id = self.object;

            let world = &mut state_transaction.world;
            let Some(value) = world
                .asset_definition_mut(&asset_definition_id)?
                .metadata
                .remove(&self.key)
            else {
                return Err(FindError::MetadataKey(self.key).into());
            };

            state_transaction
                .world
                .emit_events(Some(AssetDefinitionEvent::MetadataRemoved(
                    MetadataChanged {
                        target: asset_definition_id,
                        key: self.key,
                        value,
                    },
                )));

            Ok(())
        }
    }

    impl Execute for Transfer<Account, AssetDefinitionId, Account> {
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction,
        ) -> Result<(), Error> {
            let Transfer {
                source,
                object,
                destination,
            } = self;

            let world = &mut state_transaction.world;

            let _ = world.account(&source)?;
            let _ = world.account(&destination)?;
            let asset_definition = world.asset_definition_mut(&object)?;

            if asset_definition.owned_by != source {
                // FIXME: seems like a bad error for this
                return Err(FindError::Account(source).into());
            }
            asset_definition.owned_by = destination.clone();

            world.emit_events(Some(AssetDefinitionEvent::OwnerChanged(
                AssetDefinitionOwnerChanged {
                    asset_definition: object,
                    new_owner: destination,
                },
            )));

            Ok(())
        }
    }

    impl Execute for Mint<Numeric, Asset> {
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction,
        ) -> Result<(), Error> {
            let asset_id = self.destination;
            let amount = self.object;

            let world = &mut state_transaction.world;

            let asset_definition = world.asset_definition_mut(&asset_id.definition)?;
            assert_numeric_spec(&amount, &asset_definition)?;
            let mintability_changed = assert_can_mint(asset_definition)?;
            if mintability_changed {
                let asset_definition = asset_definition.id.clone();
                world.emit_events(Some(AssetDefinitionEvent::MintabilityChanged(
                    asset_definition,
                )))
            }

            let asset = world.asset_or_insert(asset_id.clone())?;
            asset.value = asset.value.checked_add(amount).ok_or(MathError::Overflow)?;

            // FIXME: replace with events
            state_transaction
                .new_tx_amounts
                .lock()
                .push(amount.to_f64());
            world.increase_asset_total_amount(&asset_id.definition, amount)?;

            world.emit_events(Some(AssetEvent::Added(AssetChanged {
                asset: asset_id,
                amount: amount.into(),
            })));

            Ok(())
        }
    }

    impl Execute for Burn<Numeric, Asset> {
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction,
        ) -> Result<(), Error> {
            let asset_id = self.destination;
            let amount = self.object;

            let world = &mut state_transaction.world;

            let asset_definition = world.asset_definition(&asset_id.definition)?;
            assert_numeric_spec(&amount, &asset_definition)?;

            let Ok(asset) = world.asset_mut(&asset_id) else {
                // same as having zero of the asset
                return Err(MathError::NotEnoughQuantity.into());
            };
            asset.value = asset
                .value
                .checked_sub(amount)
                .ok_or(MathError::NotEnoughQuantity)?;

            if asset.value.is_zero() {
                assert!(world.assets.remove(asset_id.clone()).is_some());
            }

            // FIXME: replace with events
            state_transaction
                .new_tx_amounts
                .lock()
                .push(amount.to_f64());
            world.decrease_asset_total_amount(&asset_id.definition, amount)?;

            world.emit_events(Some(AssetEvent::Removed(AssetChanged {
                asset: asset_id,
                amount: amount.into(),
            })));

            Ok(())
        }
    }

    impl Execute for Transfer<Asset, Numeric, Account> {
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction,
        ) -> Result<(), Error> {
            let source_id = self.source;
            let amount = self.object;

            let world = &mut state_transaction.world;

            let asset_definition = world.asset_definition(&source_id.definition)?;
            assert_numeric_spec(&amount, &asset_definition)?;

            let Ok(source) = world.asset_mut(&source_id) else {
                // same as having zero of the asset
                return Err(MathError::NotEnoughQuantity.into());
            };
            source.value = source
                .value
                .checked_sub(amount)
                .ok_or(MathError::NotEnoughQuantity)?;
            if source.value.is_zero() {
                assert!(world.assets.remove(source_id.clone()).is_some());
            }

            let target_id = AssetId::new(source_id.definition.clone(), self.destination);
            let target = world.asset_or_insert(target_id.clone())?;
            let value = &mut target.value;
            *value = value.checked_add(amount).ok_or(MathError::Overflow)?;

            // FIXME: replace with events
            state_transaction
                .new_tx_amounts
                .lock()
                .push(amount.to_f64());

            world.emit_events([
                AssetEvent::Removed(AssetChanged {
                    asset: source_id,
                    amount: amount.into(),
                }),
                AssetEvent::Added(AssetChanged {
                    asset: target_id,
                    amount: amount.into(),
                }),
            ]);
            Ok(())
        }
    }

    /// Assert that asset type is Numeric and that it satisfy asset definition spec
    fn assert_numeric_spec(
        object: &Numeric,
        asset_definition: &AssetDefinition,
    ) -> Result<NumericSpec, Error> {
        let object_spec = NumericSpec::fractional(object.scale());
        let asset_definition_spec = asset_definition.spec;
        asset_definition_spec.check(object).map_err(|_| {
            TypeError::from(Mismatch {
                expected: asset_definition_spec,
                actual: object_spec,
            })
        })?;
        Ok(asset_definition_spec)
    }

    /// Stop minting on the [`AssetDefinition`] globally.
    ///
    /// # Errors
    /// If the [`AssetDefinition`] is not `Mintable::Once`.
    #[inline]
    fn forbid_minting(definition: &mut AssetDefinition) -> Result<(), MintabilityError> {
        if definition.mintable == Mintable::Once {
            definition.mintable = Mintable::Not;
            Ok(())
        } else {
            Err(MintabilityError::ForbidMintOnMintable)
        }
    }

    /// Assert that this asset is `mintable`.
    ///
    /// Returns whether mintability changed.
    fn assert_can_mint(asset_definition: &mut AssetDefinition) -> Result<bool, Error> {
        match asset_definition.mintable {
            Mintable::Infinitely => Ok(false),
            Mintable::Not => Err(Error::Mintability(MintabilityError::MintUnmintable)),
            Mintable::Once => {
                forbid_minting(asset_definition)?;
                Ok(true)
            }
        }
    }

    #[cfg(test)]
    mod test {
        use iroha_data_model::{prelude::AssetDefinition, ParseError};
        use iroha_test_samples::gen_account_in;

        use crate::smartcontracts::isi::Registrable;

        #[test]
        fn cannot_forbid_minting_on_asset_mintable_infinitely() -> Result<(), ParseError> {
            let (authority, _authority_keypair) = gen_account_in("wonderland");
            let mut definition = AssetDefinition::new("test#hello".parse()?).build(&authority);
            assert!(super::forbid_minting(&mut definition).is_err());
            Ok(())
        }
    }
}

/// Asset-related query implementations.
pub mod query {
    use eyre::Result;
    use iroha_data_model::{
        asset::{Asset, AssetDefinition},
        query::{
            error::QueryExecutionFail as Error,
            predicate::{
                predicate_atoms::asset::{AssetDefinitionPredicateBox, AssetPredicateBox},
                CompoundPredicate,
            },
        },
    };

    use super::*;
    use crate::{smartcontracts::ValidQuery, state::StateReadOnly};

    impl ValidQuery for FindAssetsDefinitions {
        #[metrics(+"find_asset_definitions")]
        fn execute(
            self,
            filter: CompoundPredicate<AssetDefinitionPredicateBox>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = AssetDefinition>, Error> {
            Ok(state_ro
                .world()
                .asset_definitions_iter()
                .filter(move |&asset_definition| filter.applies(asset_definition))
                .cloned())
        }
    }

    impl ValidSingularQuery for FindAssetDefinitionMetadata {
        #[metrics(+"find_asset_definition_key_value_by_id_and_key")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<Json, Error> {
            let id = &self.id;
            let key = &self.key;
            iroha_logger::trace!(%id, %key);
            Ok(state_ro
                .world()
                .asset_definition(id)?
                .metadata
                .get(key)
                .ok_or(FindError::MetadataKey(key.clone()))
                .cloned()
                .map(Into::into)?)
        }
    }

    impl ValidQuery for FindAssets {
        #[metrics(+"find_assets")]
        fn execute(
            self,
            filter: CompoundPredicate<AssetPredicateBox>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = Asset>, Error> {
            Ok(state_ro
                .world()
                .assets_iter()
                .filter(move |&asset| filter.applies(asset))
                .cloned())
        }
    }

    impl ValidSingularQuery for FindAssetQuantityById {
        #[metrics(+"find_asset_quantity_by_id")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<Numeric, Error> {
            let id = &self.id;
            trace!(%id);
            state_ro
                .world()
                .asset(id)
                .map(|asset| asset.value)
                .map_err(|asset_err| {
                    if let Err(definition_err) = state_ro.world().asset_definition(&id.definition) {
                        Error::Find(definition_err)
                    } else {
                        asset_err
                    }
                })
        }
    }
}
