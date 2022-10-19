//! This module contains [`Domain`] structure and related implementations and trait implementations.

use eyre::Result;
use iroha_data_model::prelude::*;
use iroha_telemetry::metrics;

use super::super::isi::prelude::*;

/// ISI module contains all instructions related to domains:
/// - creating/changing assets
/// - registering/unregistering accounts
/// - update metadata
/// - transfer, etc.
pub mod isi {
    use iroha_logger::prelude::*;

    use super::*;

    impl Execute for Register<Account> {
        type Error = Error;

        #[metrics(+"register_account")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let account: Account = self.object.build();
            let account_id = account.id().clone();

            account_id
                .name
                .validate_len(wsv.config.ident_length_limits)
                .map_err(Error::Validate)?;

            wsv.modify_domain(&account_id.domain_id.clone(), |domain| {
                if domain.account(&account_id).is_some() {
                    return Err(Error::Repetition(
                        InstructionType::Register,
                        IdBox::AccountId(account_id),
                    ));
                }

                domain.add_account(account);
                Ok(DomainEvent::Account(AccountEvent::Created(account_id)))
            })
        }
    }

    impl Execute for Unregister<Account> {
        type Error = Error;

        #[metrics(+"unregister_account")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let account_id = self.object_id;

            wsv.modify_domain(&account_id.domain_id.clone(), |domain| {
                if domain.remove_account(&account_id).is_none() {
                    return Err(FindError::Account(account_id).into());
                }

                Ok(DomainEvent::Account(AccountEvent::Deleted(account_id)))
            })
        }
    }

    impl Execute for Register<AssetDefinition> {
        type Error = Error;

        #[metrics(+"register_asset_def")]
        fn execute(
            self,
            authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let asset_definition = self.object.build();
            asset_definition
                .id()
                .name
                .validate_len(wsv.config.ident_length_limits)
                .map_err(Error::Validate)?;

            let asset_definition_id = asset_definition.id().clone();
            wsv.modify_domain(&asset_definition_id.domain_id.clone(), |domain| {
                if domain.asset_definition(&asset_definition_id).is_some() {
                    return Err(Error::Repetition(
                        InstructionType::Register,
                        IdBox::AssetDefinitionId(asset_definition_id),
                    ));
                }

                domain.add_asset_definition(asset_definition, authority);
                Ok(DomainEvent::AssetDefinition(AssetDefinitionEvent::Created(
                    asset_definition_id,
                )))
            })
        }
    }

    impl Execute for Unregister<AssetDefinition> {
        type Error = Error;

        #[metrics(+"unregister_asset_def")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let asset_definition_id = self.object_id;

            for domain in wsv.domains().iter() {
                for account in domain.accounts() {
                    let keys: Vec<_> = account
                        .assets()
                        .filter_map(|asset| {
                            if asset.id().definition_id == asset_definition_id {
                                return Some(asset.id());
                            }

                            None
                        })
                        .cloned()
                        .collect();

                    for key_id in keys {
                        wsv.modify_account(account.id(), |account_mut| {
                            if account_mut.remove_asset(&key_id).is_none() {
                                error!(%key_id, "asset not found. This is a bug");
                            }

                            Ok(AccountEvent::Asset(AssetEvent::Deleted(key_id)))
                        })?;
                    }
                }
            }

            wsv.modify_domain(&asset_definition_id.domain_id.clone(), |domain| {
                if domain
                    .remove_asset_definition(&asset_definition_id)
                    .is_none()
                {
                    return Err(FindError::AssetDefinition(asset_definition_id).into());
                }

                Ok(DomainEvent::AssetDefinition(AssetDefinitionEvent::Deleted(
                    asset_definition_id,
                )))
            })?;

            Ok(())
        }
    }

    impl Execute for SetKeyValue<AssetDefinition, Name, Value> {
        type Error = Error;

        #[metrics(+"set_key_value_asset_def")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let asset_definition_id = self.object_id;

            let metadata_limits = wsv.config.asset_definition_metadata_limits;
            wsv.modify_asset_definition_entry(
                &asset_definition_id.clone(),
                |asset_definition_entry| {
                    let asset_definition = asset_definition_entry.definition_mut();

                    asset_definition.metadata_mut().insert_with_limits(
                        self.key.clone(),
                        self.value.clone(),
                        metadata_limits,
                    )?;

                    Ok(AssetDefinitionEvent::MetadataInserted(MetadataChanged {
                        target_id: asset_definition_id,
                        key: self.key,
                        value: Box::new(self.value),
                    }))
                },
            )
        }
    }

    impl Execute for RemoveKeyValue<AssetDefinition, Name> {
        type Error = Error;

        #[metrics(+"remove_key_value_asset_def")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let asset_definition_id = self.object_id;

            wsv.modify_asset_definition_entry(
                &asset_definition_id.clone(),
                |asset_definition_entry| {
                    let asset_definition = asset_definition_entry.definition_mut();

                    let value = asset_definition
                        .metadata_mut()
                        .remove(&self.key)
                        .ok_or_else(|| FindError::MetadataKey(self.key.clone()))?;

                    Ok(AssetDefinitionEvent::MetadataRemoved(MetadataChanged {
                        target_id: asset_definition_id,
                        key: self.key,
                        value: Box::new(value),
                    }))
                },
            )
        }
    }

    impl Execute for SetKeyValue<Domain, Name, Value> {
        type Error = Error;

        #[metrics(+"set_key_value_domain")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let domain_id = self.object_id;

            let limits = wsv.config.domain_metadata_limits;

            wsv.modify_domain(&domain_id.clone(), |domain| {
                domain.metadata_mut().insert_with_limits(
                    self.key.clone(),
                    self.value.clone(),
                    limits,
                )?;

                Ok(DomainEvent::MetadataInserted(MetadataChanged {
                    target_id: domain_id,
                    key: self.key,
                    value: Box::new(self.value),
                }))
            })
        }
    }

    impl Execute for RemoveKeyValue<Domain, Name> {
        type Error = Error;

        #[metrics(+"remove_key_value_domain")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let domain_id = self.object_id;

            wsv.modify_domain(&domain_id.clone(), |domain| {
                let value = domain
                    .metadata_mut()
                    .remove(&self.key)
                    .ok_or_else(|| FindError::MetadataKey(self.key.clone()))?;

                Ok(DomainEvent::MetadataRemoved(MetadataChanged {
                    target_id: domain_id,
                    key: self.key,
                    value: Box::new(value),
                }))
            })
        }
    }
}

/// Query module provides [`Query`] Domain related implementations.
pub mod query {
    use eyre::{Result, WrapErr};

    use super::*;
    use crate::smartcontracts::query::Error;

    impl ValidQuery for FindAllDomains {
        #[metrics(+"find_all_domains")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            Ok(wsv
                .domains()
                .iter()
                .map(|guard| guard.value().clone())
                .collect())
        }
    }

    impl ValidQuery for FindDomainById {
        #[metrics(+"find_domain_by_id")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            let id = self
                .id
                .evaluate(wsv, &Context::default())
                .wrap_err("Failed to get domain id")
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%id);
            Ok(wsv.domain(&id)?.clone())
        }
    }

    impl ValidQuery for FindDomainKeyValueByIdAndKey {
        #[metrics(+"find_domain_key_value_by_id_and_key")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
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
            iroha_logger::trace!(%id, %key);
            wsv.map_domain(&id, |domain| {
                Ok(domain.metadata().get(&key).map(Clone::clone))
            })?
            .ok_or_else(|| FindError::MetadataKey(key).into())
        }
    }

    impl ValidQuery for FindAssetDefinitionKeyValueByIdAndKey {
        #[metrics(+"find_asset_definition_key_value_by_id_and_key")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
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
            iroha_logger::trace!(%id, %key);
            Ok(wsv
                .asset_definition_entry(&id)?
                .definition()
                .metadata()
                .get(&key)
                .ok_or(FindError::MetadataKey(key))?
                .clone())
        }
    }
}
