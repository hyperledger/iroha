//! This module contains [`Domain`] structure and related implementations and trait implementations.

use eyre::Result;
use iroha_data_model::{
    account::AccountsMap,
    asset::{AssetDefinitionsMap, AssetTotalQuantityMap},
    prelude::*,
    query::error::FindError,
};
use iroha_telemetry::metrics;

use super::super::isi::prelude::*;

impl Registrable for iroha_data_model::domain::NewDomain {
    type Target = Domain;

    #[must_use]
    #[inline]
    fn build(self, authority: &AccountId) -> Self::Target {
        Self::Target {
            id: self.id,
            accounts: AccountsMap::default(),
            asset_definitions: AssetDefinitionsMap::default(),
            asset_total_quantities: AssetTotalQuantityMap::default(),
            metadata: self.metadata,
            logo: self.logo,
            owned_by: authority.clone(),
        }
    }
}

/// ISI module contains all instructions related to domains:
/// - creating/changing assets
/// - registering/unregistering accounts
/// - update metadata
/// - transfer, etc.
pub mod isi {
    use iroha_data_model::isi::error::{InstructionExecutionError, RepetitionError};
    use iroha_logger::prelude::*;

    use super::*;

    impl Execute for Register<Account> {
        #[metrics(+"register_account")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let account_id = self.object.id().clone();

            if *account_id.domain_id() == *iroha_genesis::GENESIS_DOMAIN_ID {
                return Err(InstructionExecutionError::InvariantViolation(
                    "Not allowed to register account in genesis domain".to_owned(),
                ));
            }

            recognize_account(&account_id, authority, state_transaction)?;

            let account = state_transaction
                .world
                .account_mut(&account_id)
                .expect("account should exist");

            if account.is_active {
                return Err(RepetitionError {
                    instruction_type: InstructionType::Register,
                    id: IdBox::AccountId(account_id),
                }
                .into());
            }

            // FIXME: disregarding self.object.metadata
            account.activate();

            state_transaction
                .world
                .emit_events(Some(DomainEvent::Account(AccountEvent::Activated(
                    account_id,
                ))));

            Ok(())
        }
    }

    impl Execute for Unregister<Account> {
        #[metrics(+"unregister_account")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let account_id = self.object_id;

            state_transaction
                .world()
                .triggers()
                .inspect_by_action(
                    |action| action.authority() == &account_id,
                    |trigger_id, _| trigger_id.clone(),
                )
                .collect::<Vec<_>>()
                .into_iter()
                .for_each(|trigger_id| {
                    state_transaction
                        .world
                        .triggers
                        .remove(trigger_id)
                        .then_some(())
                        .expect("should succeed")
                });

            if state_transaction
                .world
                .domain_mut(&account_id.domain_id)?
                .remove_account(&account_id)
                .is_none()
            {
                return Err(FindError::Account(account_id).into());
            }

            state_transaction
                .world
                .emit_events(Some(AccountEvent::Deleted(account_id)));

            Ok(())
        }
    }

    impl Execute for Register<AssetDefinition> {
        #[metrics(+"register_asset_definition")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let asset_definition = self.object.build(authority);
            asset_definition
                .id()
                .name
                .validate_len(state_transaction.config.ident_length_limits)
                .map_err(Error::from)?;

            let asset_definition_id = asset_definition.id().clone();
            let domain = state_transaction
                .world
                .domain_mut(&asset_definition_id.domain_id)?;
            if domain.asset_definitions.contains_key(&asset_definition_id) {
                return Err(RepetitionError {
                    instruction_type: InstructionType::Register,
                    id: IdBox::AssetDefinitionId(asset_definition_id),
                }
                .into());
            }

            domain.add_asset_total_quantity(asset_definition_id, Numeric::ZERO);

            domain.add_asset_definition(asset_definition.clone());

            state_transaction
                .world
                .emit_events(Some(DomainEvent::AssetDefinition(
                    AssetDefinitionEvent::Created(asset_definition),
                )));

            Ok(())
        }
    }

    impl Execute for Unregister<AssetDefinition> {
        #[metrics(+"unregister_asset_definition")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let asset_definition_id = self.object_id;

            let mut assets_to_remove = Vec::new();
            for domain in state_transaction.world.domains_iter() {
                for account in domain.accounts.values() {
                    assets_to_remove.extend(
                        account
                            .assets
                            .values()
                            .filter_map(|asset| {
                                if asset.id().definition_id == asset_definition_id {
                                    return Some(asset.id());
                                }

                                None
                            })
                            .cloned(),
                    )
                }
            }

            let mut events = Vec::with_capacity(assets_to_remove.len() + 1);
            for asset_id in assets_to_remove {
                if state_transaction
                    .world
                    .account_mut(&asset_id.account_id)?
                    .remove_asset(&asset_id.definition_id)
                    .is_none()
                {
                    error!(%asset_id, "asset not found. This is a bug");
                }

                events.push(AccountEvent::Asset(AssetEvent::Deleted(asset_id)).into());
            }

            let domain = state_transaction
                .world
                .domain_mut(&asset_definition_id.domain_id)?;
            if domain
                .remove_asset_definition(&asset_definition_id)
                .is_none()
            {
                return Err(FindError::AssetDefinition(asset_definition_id).into());
            }

            domain.remove_asset_total_quantity(&asset_definition_id);

            events.push(DataEvent::from(DomainEvent::AssetDefinition(
                AssetDefinitionEvent::Deleted(asset_definition_id),
            )));

            state_transaction.world.emit_events(events);

            Ok(())
        }
    }

    impl Execute for SetKeyValue<AssetDefinition> {
        #[metrics(+"set_key_value_asset_definition")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let asset_definition_id = self.object_id;

            let metadata_limits = state_transaction.config.asset_definition_metadata_limits;
            state_transaction
                .world
                .asset_definition_mut(&asset_definition_id)
                .map_err(Error::from)
                .and_then(|asset_definition| {
                    asset_definition
                        .metadata
                        .insert_with_limits(self.key.clone(), self.value.clone(), metadata_limits)
                        .map_err(Error::from)
                })?;

            state_transaction
                .world
                .emit_events(Some(AssetDefinitionEvent::MetadataInserted(
                    MetadataChanged {
                        target_id: asset_definition_id,
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
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let asset_definition_id = self.object_id;

            let value = state_transaction
                .world
                .asset_definition_mut(&asset_definition_id)
                .and_then(|asset_definition| {
                    asset_definition
                        .metadata
                        .remove(&self.key)
                        .ok_or_else(|| FindError::MetadataKey(self.key.clone()))
                })?;

            state_transaction
                .world
                .emit_events(Some(AssetDefinitionEvent::MetadataRemoved(
                    MetadataChanged {
                        target_id: asset_definition_id,
                        key: self.key,
                        value,
                    },
                )));

            Ok(())
        }
    }

    impl Execute for SetKeyValue<Domain> {
        #[metrics(+"set_domain_key_value")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let domain_id = self.object_id;

            let limits = state_transaction.config.domain_metadata_limits;

            let domain = state_transaction.world.domain_mut(&domain_id)?;
            domain
                .metadata
                .insert_with_limits(self.key.clone(), self.value.clone(), limits)?;

            state_transaction
                .world
                .emit_events(Some(DomainEvent::MetadataInserted(MetadataChanged {
                    target_id: domain_id,
                    key: self.key,
                    value: self.value,
                })));

            Ok(())
        }
    }

    impl Execute for RemoveKeyValue<Domain> {
        #[metrics(+"remove_domain_key_value")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let domain_id = self.object_id;

            let domain = state_transaction.world.domain_mut(&domain_id)?;
            let value = domain
                .metadata
                .remove(&self.key)
                .ok_or_else(|| FindError::MetadataKey(self.key.clone()))?;

            state_transaction
                .world
                .emit_events(Some(DomainEvent::MetadataRemoved(MetadataChanged {
                    target_id: domain_id,
                    key: self.key,
                    value,
                })));

            Ok(())
        }
    }

    impl Execute for Transfer<Account, DomainId, Account> {
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let Transfer {
                source_id,
                object,
                destination_id,
            } = self;

            let _ = state_transaction.world.account(&source_id)?;
            // Exceptionally, the destination account should not be recognized here.
            // Otherwise, the risk is that the previous owner can no longer activate the current owner who cannot yet take any action by oneself.
            // Thus, the destination account should be explicitly registered before this transfer
            let _ = state_transaction.world.account(&destination_id)?;

            let domain = state_transaction.world.domain_mut(&object)?;

            if domain.owned_by != source_id {
                return Err(Error::Find(FindError::Account(source_id)));
            }

            domain.owned_by = destination_id.clone();

            state_transaction
                .world
                .emit_events(Some(DomainEvent::OwnerChanged(DomainOwnerChanged {
                    domain_id: object,
                    new_owner: destination_id,
                })));

            Ok(())
        }
    }
}

/// Query module provides [`Query`] Domain related implementations.
pub mod query {
    use eyre::Result;
    use iroha_data_model::{
        domain::Domain, metadata::MetadataValueBox, query::error::QueryExecutionFail as Error,
    };

    use super::*;
    use crate::state::StateReadOnly;

    impl ValidQuery for FindAllDomains {
        #[metrics(+"find_all_domains")]
        fn execute<'state>(
            &self,
            state_ro: &'state impl StateReadOnly,
        ) -> Result<Box<dyn Iterator<Item = Domain> + 'state>, Error> {
            Ok(Box::new(state_ro.world().domains_iter().cloned()))
        }
    }

    impl ValidQuery for FindDomainById {
        #[metrics(+"find_domain_by_id")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<Domain, Error> {
            let id = &self.id;
            iroha_logger::trace!(%id);
            Ok(state_ro.world().domain(id)?.clone())
        }
    }

    impl ValidQuery for FindDomainKeyValueByIdAndKey {
        #[metrics(+"find_domain_key_value_by_id_and_key")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<MetadataValueBox, Error> {
            let id = &self.id;
            let key = &self.key;
            iroha_logger::trace!(%id, %key);
            state_ro
                .world()
                .map_domain(id, |domain| domain.metadata.get(key).cloned())?
                .ok_or_else(|| FindError::MetadataKey(key.clone()).into())
                .map(Into::into)
        }
    }

    impl ValidQuery for FindAssetDefinitionKeyValueByIdAndKey {
        #[metrics(+"find_asset_definition_key_value_by_id_and_key")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<MetadataValueBox, Error> {
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
}
