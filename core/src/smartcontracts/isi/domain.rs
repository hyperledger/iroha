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

    use super::*;

    impl<W: WorldTrait> Execute<W> for Register<Account> {
        type Error = Error;

        #[metrics(+"register_account")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let account: Account = self.object.into();
            let account_id = account.id().clone();

            account_id
                .name
                .validate_len(wsv.config.ident_length_limits)
                .map_err(Error::Validate)?;

            wsv.modify_domain(&account_id.domain_id, |domain| {
                let _m = domain.metadata_mut();
                let _n = domain.metadata();
                if domain.account(&account_id).is_some() {
                    return Err(Error::Repetition(
                        InstructionType::Register,
                        IdBox::AccountId(account_id.clone()),
                    ));
                }

                assert!(domain.add_account(account).is_none());
                Ok(DomainEvent::Account(AccountEvent::Created(
                    account_id.clone(),
                )))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for Unregister<Account> {
        type Error = Error;

        #[metrics(+"unregister_account")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let account_id = self.object_id;

            wsv.modify_domain(&account_id.domain_id, |domain| {
                assert!(domain.remove_account(&account_id).is_some());
                Ok(DomainEvent::Account(AccountEvent::Deleted(
                    account_id.clone(),
                )))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for Register<AssetDefinition> {
        type Error = Error;

        #[metrics(+"register_asset_def")]
        fn execute(
            self,
            authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let asset_definition = self.object;
            let asset_definition_id = asset_definition.id().clone();
            asset_definition_id
                .name
                .validate_len(wsv.config.ident_length_limits)
                .map_err(Error::Validate)?;
            let domain_id = asset_definition_id.domain_id.clone();

            wsv.modify_domain(&domain_id, |domain| {
                if let Some(entry) = domain.asset_definition(&asset_definition_id) {
                    return Err(Error::Repetition(
                        InstructionType::Register,
                        IdBox::AccountId(entry.registered_by().clone()),
                    ));
                }

                assert!(domain
                    .add_asset_definition(asset_definition, authority)
                    .is_none());
                Ok(DomainEvent::AssetDefinition(AssetDefinitionEvent::Created(
                    asset_definition_id,
                )))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for Unregister<AssetDefinition> {
        type Error = Error;

        #[metrics(+"unregister_asset_def")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let asset_definition_id = self.object_id;
            wsv.modify_domain(&asset_definition_id.domain_id, |domain| {
                assert!(domain
                    .remove_asset_definition(&asset_definition_id)
                    .is_none());
                Ok(DomainEvent::AssetDefinition(AssetDefinitionEvent::Deleted(
                    asset_definition_id.clone(),
                )))
            })?;

            for domain in wsv.domains().iter() {
                for account in domain.accounts() {
                    let keys = account
                        .assets()
                        .filter_map(|asset| {
                            if asset.id().definition_id == asset_definition_id {
                                return Some(asset.id());
                            }

                            None
                        })
                        .collect::<Vec<_>>();
                    for id in keys {
                        wsv.modify_account(account.id(), |account_mut| {
                            assert!(account_mut.remove_asset(id).is_some());
                            Ok(AccountEvent::Asset(AssetEvent::Deleted(id.clone())))
                        })?;
                    }
                }
            }

            Ok(())
        }
    }

    impl<W: WorldTrait> Execute<W> for SetKeyValue<AssetDefinition, Name, Value> {
        type Error = Error;

        #[metrics(+"set_key_value_asset_def")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let asset_definition_id = self.object_id;

            let metadata_limits = wsv.config.asset_definition_metadata_limits;
            wsv.modify_asset_definition_entry(&asset_definition_id, |asset_definition_entry| {
                let asset_definition = asset_definition_entry.definition_mut();

                asset_definition.metadata_mut().insert_with_limits(
                    self.key,
                    self.value,
                    metadata_limits,
                )?;

                Ok(AssetDefinitionEvent::MetadataInserted(
                    asset_definition_id.clone(),
                ))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for RemoveKeyValue<AssetDefinition, Name> {
        type Error = Error;

        #[metrics(+"remove_key_value_asset_def")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let asset_definition_id = self.object_id;

            wsv.modify_asset_definition_entry(&asset_definition_id, |asset_definition_entry| {
                let asset_definition = asset_definition_entry.definition_mut();

                asset_definition
                    .metadata_mut()
                    .remove(&self.key)
                    .ok_or(FindError::MetadataKey(self.key))?;

                Ok(AssetDefinitionEvent::MetadataRemoved(
                    asset_definition_id.clone(),
                ))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for SetKeyValue<Domain, Name, Value> {
        type Error = Error;

        #[metrics(+"set_key_value_domain")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let domain_id = self.object_id;

            wsv.modify_domain(&domain_id, |domain| {
                let limits = wsv.config.domain_metadata_limits;

                domain
                    .metadata_mut()
                    .insert_with_limits(self.key, self.value, limits)?;

                Ok(DomainEvent::MetadataInserted(domain_id.clone()))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for RemoveKeyValue<Domain, Name> {
        type Error = Error;

        #[metrics(+"remove_key_value_domain")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let domain_id = self.object_id;

            wsv.modify_domain(&domain_id, |domain| {
                domain
                    .metadata_mut()
                    .remove(&self.key)
                    .ok_or(FindError::MetadataKey(self.key))?;

                Ok(DomainEvent::MetadataRemoved(domain_id.clone()))
            })
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
            wsv.map_domain(&id, |domain| {
                Ok(domain.metadata().get(&key).map(Clone::clone))
            })?
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
                .definition()
                .metadata()
                .get(&key)
                .ok_or(FindError::MetadataKey(key))?
                .clone())
        }
    }
}
