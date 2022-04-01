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

    impl<W: WorldTrait> Execute<W> for Register<Account> {
        type Error = Error;

        #[metrics(+"register_account")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
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

    impl<W: WorldTrait> Execute<W> for Unregister<Account> {
        type Error = Error;

        #[metrics(+"unregister_account")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let account_id = self.object_id;

            wsv.modify_domain(&account_id.domain_id.clone(), |domain| {
                if domain.remove_account(&account_id).is_none() {
                    return Err(Error::Find(Box::new(FindError::Account(account_id))));
                }

                Ok(DomainEvent::Account(AccountEvent::Deleted(account_id)))
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

    impl<W: WorldTrait> Execute<W> for Unregister<AssetDefinition> {
        type Error = Error;

        #[metrics(+"unregister_asset_def")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
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

                    for id in keys {
                        wsv.modify_account(account.id(), |account_mut| {
                            if account_mut.remove_asset(&id).is_none() {
                                error!(%id, "asset not found - this is a bug");
                            }

                            Ok(AccountEvent::Asset(AssetEvent::Deleted(id)))
                        })?;
                    }
                }
            }

            wsv.modify_domain(&asset_definition_id.domain_id.clone(), |domain| {
                if domain
                    .remove_asset_definition(&asset_definition_id)
                    .is_none()
                {
                    return Err(Error::Find(Box::new(FindError::AssetDefinition(
                        asset_definition_id,
                    ))));
                }

                Ok(DomainEvent::AssetDefinition(AssetDefinitionEvent::Deleted(
                    asset_definition_id,
                )))
            })?;

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
            wsv.modify_asset_definition_entry(
                &asset_definition_id.clone(),
                |asset_definition_entry| {
                    let asset_definition = asset_definition_entry.definition_mut();

                    asset_definition.metadata_mut().insert_with_limits(
                        self.key,
                        self.value,
                        metadata_limits,
                    )?;

                    Ok(AssetDefinitionEvent::MetadataInserted(asset_definition_id))
                },
            )
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

            wsv.modify_asset_definition_entry(
                &asset_definition_id.clone(),
                |asset_definition_entry| {
                    let asset_definition = asset_definition_entry.definition_mut();

                    asset_definition
                        .metadata_mut()
                        .remove(&self.key)
                        .ok_or(FindError::MetadataKey(self.key))?;

                    Ok(AssetDefinitionEvent::MetadataRemoved(asset_definition_id))
                },
            )
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

            wsv.modify_domain(&domain_id.clone(), |domain| {
                let limits = wsv.config.domain_metadata_limits;

                domain
                    .metadata_mut()
                    .insert_with_limits(self.key, self.value, limits)?;

                Ok(DomainEvent::MetadataInserted(domain_id))
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

            wsv.modify_domain(&domain_id.clone(), |domain| {
                domain
                    .metadata_mut()
                    .remove(&self.key)
                    .ok_or(FindError::MetadataKey(self.key))?;

                Ok(DomainEvent::MetadataRemoved(domain_id))
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
