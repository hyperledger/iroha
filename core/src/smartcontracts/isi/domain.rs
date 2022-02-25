//! This module contains [`Domain`] structure and related implementations and trait implementations.
use std::collections::btree_map::Entry;

use eyre::Result;
use iroha_data_model::prelude::*;
use iroha_telemetry::metrics;

use super::super::isi::prelude::*;
use crate::prelude::*;

/// ISI module contains all instructions related to domains:
/// - creating/changing assets
/// - registering/unregistering accounts
/// - update metadata
/// - transfer, etc.
pub mod isi {

    use super::*;

    impl<W: WorldTrait> Execute<W> for Register<NewAccount> {
        type Error = Error;

        #[metrics(+"register_account")]
        fn execute(
            self,
            _authority: <NewAccount as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Vec<DataEvent>, Self::Error> {
            let account = self.object;
            let account_id = account.id.clone();

            account
                .id
                .name
                .validate_len(wsv.config.ident_length_limits)
                .map_err(Error::Validate)?;

            match wsv
                .domain_mut(&account_id.domain_id)?
                .accounts
                .entry(account_id.clone())
            {
                Entry::Occupied(_) => {
                    return Err(Error::Repetition(
                        InstructionType::Register,
                        IdBox::AccountId(account_id),
                    ))
                }
                Entry::Vacant(entry) => {
                    let _ = entry.insert(account.into());
                }
            }

            Ok(vec![DataEvent::new(account_id, DataStatus::Created)])
        }
    }

    impl<W: WorldTrait> Execute<W> for Unregister<Account> {
        type Error = Error;

        #[metrics(+"unregister_account")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Vec<DataEvent>, Self::Error> {
            let account_id = self.object_id;

            wsv.domain_mut(&account_id.domain_id)?
                .accounts
                .remove(&account_id);

            Ok(vec![DataEvent::new(account_id, DataStatus::Deleted)])
        }
    }

    impl<W: WorldTrait> Execute<W> for Register<AssetDefinition> {
        type Error = Error;

        #[metrics(+"register_asset_def")]
        fn execute(
            self,
            authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Vec<DataEvent>, Self::Error> {
            let asset_definition = self.object.clone();
            asset_definition
                .id
                .name
                .validate_len(wsv.config.ident_length_limits)
                .map_err(Error::Validate)?;
            let domain_id = asset_definition.id.domain_id.clone();
            let mut domain = wsv.domain_mut(&domain_id)?;
            match domain.asset_definitions.entry(asset_definition.id.clone()) {
                Entry::Vacant(entry) => {
                    let _ = entry.insert(AssetDefinitionEntry {
                        definition: asset_definition,
                        registered_by: authority,
                    });
                }
                Entry::Occupied(entry) => {
                    return Err(Error::Repetition(
                        InstructionType::Register,
                        IdBox::AccountId(entry.get().registered_by.clone()),
                    ))
                }
            }

            Ok(vec![DataEvent::new(self.object.id, DataStatus::Created)])
        }
    }

    impl<W: WorldTrait> Execute<W> for Unregister<AssetDefinition> {
        type Error = Error;

        #[metrics(+"unregister_asset_def")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Vec<DataEvent>, Self::Error> {
            let asset_definition_id = self.object_id;

            wsv.domain_mut(&asset_definition_id.domain_id)?
                .asset_definitions
                .remove(&asset_definition_id);
            for mut domain in wsv.domains().iter_mut() {
                for account in domain.accounts.values_mut() {
                    let keys = account
                        .assets
                        .iter()
                        .filter(|(asset_id, _asset)| asset_id.definition_id == asset_definition_id)
                        .map(|(asset_id, _asset)| asset_id.clone())
                        .collect::<Vec<_>>();
                    for id in &keys {
                        account.assets.remove(id);
                    }
                }
            }

            Ok(vec![DataEvent::new(
                asset_definition_id,
                DataStatus::Deleted,
            )])
        }
    }

    impl<W: WorldTrait> Execute<W> for SetKeyValue<AssetDefinition, Name, Value> {
        type Error = Error;

        #[metrics(+"set_key_value_asset_def")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Vec<DataEvent>, Self::Error> {
            let asset_definition_id = self.object_id;

            let metadata_limits = wsv.config.asset_definition_metadata_limits;
            wsv.modify_asset_definition_entry(&asset_definition_id, |asset_definition_entry| {
                asset_definition_entry
                    .definition
                    .metadata
                    .insert_with_limits(self.key, self.value, metadata_limits)?;
                Ok(())
            })?;

            Ok(vec![DataEvent::new(
                asset_definition_id,
                MetadataUpdated::Inserted,
            )])
        }
    }

    impl<W: WorldTrait> Execute<W> for RemoveKeyValue<AssetDefinition, Name> {
        type Error = Error;

        #[metrics(+"remove_key_value_asset_def")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Vec<DataEvent>, Self::Error> {
            let asset_definition_id = self.object_id;

            wsv.modify_asset_definition_entry(&asset_definition_id, |asset_definition_entry| {
                asset_definition_entry
                    .definition
                    .metadata
                    .remove(&self.key)
                    .ok_or(FindError::MetadataKey(self.key))?;
                Ok(())
            })?;

            Ok(vec![DataEvent::new(
                asset_definition_id,
                MetadataUpdated::Removed,
            )])
        }
    }

    impl<W: WorldTrait> Execute<W> for SetKeyValue<Domain, Name, Value> {
        type Error = Error;

        #[metrics(+"set_key_value_domain")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Vec<DataEvent>, Self::Error> {
            let domain_id = self.object_id;

            let limits = wsv.config.domain_metadata_limits;
            wsv.modify_domain(&domain_id, |domain| {
                domain
                    .metadata
                    .insert_with_limits(self.key, self.value, limits)?;
                Ok(())
            })?;

            Ok(vec![DataEvent::new(domain_id, MetadataUpdated::Inserted)])
        }
    }

    impl<W: WorldTrait> Execute<W> for RemoveKeyValue<Domain, Name> {
        type Error = Error;

        #[metrics(+"remove_key_value_domain")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Vec<DataEvent>, Self::Error> {
            let domain_id = self.object_id;

            wsv.modify_domain(&domain_id, |domain| {
                domain
                    .metadata
                    .remove(&self.key)
                    .ok_or(FindError::MetadataKey(self.key))?;
                Ok(())
            })?;

            Ok(vec![DataEvent::new(domain_id, MetadataUpdated::Removed)])
        }
    }
}

/// Query module provides [`Query`] Domain related implementations.
pub mod query {
    use eyre::{Result, WrapErr};
    use iroha_logger::prelude::*;

    use super::*;
    use crate::smartcontracts::query::Error;

    impl<W: WorldTrait> ValidQuery<W> for FindAllDomains {
        #[log]
        #[metrics(+"find_all_domains")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            Ok(wsv
                .domains()
                .iter()
                .map(|guard| guard.value().clone())
                .collect())
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindDomainById {
        #[metrics(+"find_domain_by_id")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get domain id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            Ok(wsv.domain(&id)?.clone())
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindDomainKeyValueByIdAndKey {
        #[log]
        #[metrics(+"find_domain_key_value_by_id_and_key")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get domain id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let key = self
                .key
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get key")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            wsv.map_domain(&id, |domain| domain.metadata.get(&key).map(Clone::clone))?
                .ok_or_else(|| FindError::MetadataKey(key).into())
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindAssetDefinitionKeyValueByIdAndKey {
        #[metrics(+"find_asset_definition_key_value_by_id_and_key")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get asset definition id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            let key = self
                .key
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get key")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            Ok(wsv
                .asset_definition_entry(&id)?
                .definition
                .metadata
                .get(&key)
                .ok_or(FindError::MetadataKey(key))?
                .clone())
        }
    }
}
