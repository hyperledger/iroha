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
    use iroha_data_model::isi::error::RepetitionError;
    use iroha_logger::prelude::*;

    use super::*;

    impl Execute for Register<Account> {
        #[metrics(+"register_account")]
        fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let account: Account = self.object.build(authority);
            let account_id = account.id().clone();

            account_id
                .name
                .validate_len(wsv.config.ident_length_limits)
                .map_err(Error::from)?;

            let domain = wsv.domain_mut(&account_id.domain_id)?;
            if domain.accounts.get(&account_id).is_some() {
                return Err(RepetitionError {
                    instruction_type: InstructionType::Register,
                    id: IdBox::AccountId(account_id),
                }
                .into());
            }
            domain.add_account(account.clone());

            wsv.emit_events(Some(DomainEvent::Account(AccountEvent::Created(account))));

            Ok(())
        }
    }

    impl Execute for Unregister<Account> {
        #[metrics(+"unregister_account")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let account_id = self.object_id;

            let domain = wsv.domain_mut(&account_id.domain_id)?;
            if domain.remove_account(&account_id).is_none() {
                return Err(FindError::Account(account_id).into());
            }

            wsv.emit_events(Some(DomainEvent::Account(AccountEvent::Deleted(
                account_id,
            ))));

            Ok(())
        }
    }

    impl Execute for Register<AssetDefinition> {
        #[metrics(+"register_asset_definition")]
        fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let asset_definition = self.object.build(authority);
            asset_definition
                .id()
                .name
                .validate_len(wsv.config.ident_length_limits)
                .map_err(Error::from)?;

            let asset_definition_id = asset_definition.id().clone();
            let domain = wsv.domain_mut(&asset_definition_id.domain_id)?;
            if domain.asset_definitions.get(&asset_definition_id).is_some() {
                return Err(RepetitionError {
                    instruction_type: InstructionType::Register,
                    id: IdBox::AssetDefinitionId(asset_definition_id),
                }
                .into());
            }

            #[allow(clippy::match_same_arms)]
            match asset_definition.value_type {
                AssetValueType::Fixed => {
                    domain.add_asset_total_quantity(asset_definition_id, Fixed::ZERO);
                }
                AssetValueType::Quantity => {
                    domain.add_asset_total_quantity(asset_definition_id, u32::MIN);
                }
                AssetValueType::BigQuantity => {
                    domain.add_asset_total_quantity(asset_definition_id, u128::MIN);
                }
                AssetValueType::Store => {
                    domain.add_asset_total_quantity(asset_definition_id, u32::MIN);
                }
            }

            domain.add_asset_definition(asset_definition.clone());

            wsv.emit_events(Some(DomainEvent::AssetDefinition(
                AssetDefinitionEvent::Created(asset_definition),
            )));

            Ok(())
        }
    }

    impl Execute for Unregister<AssetDefinition> {
        #[metrics(+"unregister_asset_definition")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let asset_definition_id = self.object_id;

            let mut assets_to_remove = Vec::new();
            for domain in wsv.domains().values() {
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
                let account_id = asset_id.account_id.clone();
                if wsv
                    .account_mut(&account_id)?
                    .remove_asset(&asset_id)
                    .is_none()
                {
                    error!(%asset_id, "asset not found. This is a bug");
                }

                events.push(AccountEvent::Asset(AssetEvent::Deleted(asset_id)).into());
            }

            let domain = wsv.domain_mut(&asset_definition_id.domain_id)?;
            if domain
                .remove_asset_definition(&asset_definition_id)
                .is_none()
            {
                return Err(FindError::AssetDefinition(asset_definition_id).into());
            }

            domain.remove_asset_total_quantity(&asset_definition_id);

            events.push(WorldEvent::from(DomainEvent::AssetDefinition(
                AssetDefinitionEvent::Deleted(asset_definition_id),
            )));

            wsv.emit_events(events);

            Ok(())
        }
    }

    impl Execute for SetKeyValue<AssetDefinition> {
        #[metrics(+"set_key_value_asset_definition")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let asset_definition_id = self.object_id;

            let metadata_limits = wsv.config.asset_definition_metadata_limits;
            wsv.asset_definition_mut(&asset_definition_id)
                .map_err(Error::from)
                .and_then(|asset_definition| {
                    asset_definition
                        .metadata
                        .insert_with_limits(self.key.clone(), self.value.clone(), metadata_limits)
                        .map_err(Error::from)
                })?;

            wsv.emit_events(Some(AssetDefinitionEvent::MetadataInserted(
                MetadataChanged {
                    target_id: asset_definition_id,
                    key: self.key,
                    value: Box::new(self.value),
                },
            )));

            Ok(())
        }
    }

    impl Execute for RemoveKeyValue<AssetDefinition> {
        #[metrics(+"remove_key_value_asset_definition")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let asset_definition_id = self.object_id;

            let value =
                wsv.asset_definition_mut(&asset_definition_id)
                    .and_then(|asset_definition| {
                        asset_definition
                            .metadata
                            .remove(&self.key)
                            .ok_or_else(|| FindError::MetadataKey(self.key.clone()))
                    })?;

            wsv.emit_events(Some(AssetDefinitionEvent::MetadataRemoved(
                MetadataChanged {
                    target_id: asset_definition_id,
                    key: self.key,
                    value: Box::new(value),
                },
            )));

            Ok(())
        }
    }

    impl Execute for SetKeyValue<Domain> {
        #[metrics(+"set_domain_key_value")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let domain_id = self.object_id;

            let limits = wsv.config.domain_metadata_limits;

            let domain = wsv.domain_mut(&domain_id)?;
            domain
                .metadata
                .insert_with_limits(self.key.clone(), self.value.clone(), limits)?;

            wsv.emit_events(Some(DomainEvent::MetadataInserted(MetadataChanged {
                target_id: domain_id,
                key: self.key,
                value: Box::new(self.value),
            })));

            Ok(())
        }
    }

    impl Execute for RemoveKeyValue<Domain> {
        #[metrics(+"remove_domain_key_value")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let domain_id = self.object_id;

            let domain = wsv.domain_mut(&domain_id)?;
            let value = domain
                .metadata
                .remove(&self.key)
                .ok_or_else(|| FindError::MetadataKey(self.key.clone()))?;

            wsv.emit_events(Some(DomainEvent::MetadataRemoved(MetadataChanged {
                target_id: domain_id,
                key: self.key,
                value: Box::new(value),
            })));

            Ok(())
        }
    }

    impl Execute for Transfer<Account, DomainId, Account> {
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            wsv.domain_mut(&self.object)?.owned_by = self.destination_id.clone();

            wsv.emit_events(Some(DomainEvent::OwnerChanged(DomainOwnerChanged {
                domain_id: self.object,
                new_owner: self.destination_id,
            })));

            Ok(())
        }
    }
}

/// Query module provides [`Query`] Domain related implementations.
pub mod query {
    use eyre::{Result, WrapErr};
    use iroha_data_model::{
        domain::Domain,
        query::{error::QueryExecutionFail as Error, MetadataValue},
    };

    use super::*;

    impl ValidQuery for FindAllDomains {
        #[metrics(+"find_all_domains")]
        fn execute<'wsv>(
            &self,
            wsv: &'wsv WorldStateView,
        ) -> Result<Box<dyn Iterator<Item = Domain> + 'wsv>, Error> {
            Ok(Box::new(wsv.domains().values().cloned()))
        }
    }

    impl ValidQuery for FindDomainById {
        #[metrics(+"find_domain_by_id")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Domain, Error> {
            let id = wsv
                .evaluate(&self.id)
                .wrap_err("Failed to get domain id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%id);
            Ok(wsv.domain(&id)?.clone())
        }
    }

    impl ValidQuery for FindDomainKeyValueByIdAndKey {
        #[metrics(+"find_domain_key_value_by_id_and_key")]
        fn execute(&self, wsv: &WorldStateView) -> Result<MetadataValue, Error> {
            let id = wsv
                .evaluate(&self.id)
                .wrap_err("Failed to get domain id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let key = wsv
                .evaluate(&self.key)
                .wrap_err("Failed to get key")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%id, %key);
            wsv.map_domain(&id, |domain| domain.metadata.get(&key).map(Clone::clone))?
                .ok_or_else(|| FindError::MetadataKey(key).into())
                .map(Into::into)
        }
    }

    impl ValidQuery for FindAssetDefinitionKeyValueByIdAndKey {
        #[metrics(+"find_asset_definition_key_value_by_id_and_key")]
        fn execute(&self, wsv: &WorldStateView) -> Result<MetadataValue, Error> {
            let id = wsv
                .evaluate(&self.id)
                .wrap_err("Failed to get asset definition id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let key = wsv
                .evaluate(&self.key)
                .wrap_err("Failed to get key")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%id, %key);
            Ok(wsv
                .asset_definition(&id)?
                .metadata
                .get(&key)
                .ok_or(FindError::MetadataKey(key))
                .cloned()
                .map(Into::into)?)
        }
    }
}
