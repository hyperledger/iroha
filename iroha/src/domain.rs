//! This module contains `Domain` structure and related implementations and trait implementations.
use iroha_data_model::prelude::*;
use iroha_error::{error, Result};
use iroha_structs::hashmap::Entry;

use crate::{isi::prelude::*, prelude::*};

/// Iroha Special Instructions module provides `DomainInstruction` enum with all possible types of
/// Domain related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `DomainInstruction` variants into generic ISI.
pub mod isi {
    use super::*;

    impl Execute for Register<NewAccount> {
        fn execute(
            self,
            _authority: <NewAccount as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            let account = self.object;
            account.validate_len(world_state_view.config.length_limits)?;
            let name = account.id.domain_name.clone();
            world_state_view.domain(&name, |domain| {
                match domain.accounts.entry(account.id.clone()) {
                    Entry::Occupied(_) => Err(error!(
                        "Domain already contains an account with an Id: {:?}",
                        &account.id
                    )
                    .into()),
                    Entry::Vacant(entry) => {
                        drop(entry.insert(account.into()));
                        Ok(())
                    }
                }
            })?
        }
    }

    impl Execute for Unregister<Account> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            let account_id = self.object_id;
            world_state_view.domain(&account_id.domain_name, |domain| {
                // TODO: Should we fail if no domain found?
                drop(domain.accounts.remove(&account_id));
            })?;
            Ok(())
        }
    }

    impl Execute for Register<AssetDefinition> {
        fn execute(
            self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            let asset_definition = self.object;
            asset_definition.validate_len(world_state_view.config.length_limits)?;
            let name = asset_definition.id.domain_name.clone();
            world_state_view.domain(&name, |domain| {
                match domain.asset_definitions.entry(asset_definition.id.clone()) {
                    Entry::Vacant(entry) => {
                        drop(entry.insert(AssetDefinitionEntry {
                            definition: asset_definition,
                            registered_by: authority,
                        }));
                        Ok(())
                    }
                    Entry::Occupied(entry) => Err(error!(
                        "Asset definition already exists and was registered by {}",
                        entry.get().registered_by
                    )
                    .into()),
                }
            })?
        }
    }

    impl Execute for Unregister<AssetDefinition> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            let asset_definition_id = self.object_id;
            // :TODO: Should we fail if no domain found?
            drop(
                world_state_view.domain(&asset_definition_id.domain_name, |domain| {
                    domain.asset_definitions.remove(&asset_definition_id)
                })?,
            );
            for domain in world_state_view.domains().iter() {
                for account in domain.accounts.iter() {
                    let keys = account
                        .assets
                        .iter()
                        .filter(|read_guard| read_guard.key().definition_id == asset_definition_id)
                        .map(|read_guard| read_guard.key().clone())
                        .collect::<Vec<_>>();
                    keys.iter().for_each(|asset_id| {
                        drop(account.assets.remove(asset_id));
                    });
                }
            }
            Ok(())
        }
    }
}

/// Query module provides `IrohaQuery` Domain related implementations.
pub mod query {
    use iroha_error::{Result, WrapErr};
    use iroha_logger::log;

    use super::*;
    use crate::expression::Evaluate;

    impl Query for FindAllDomains {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            Ok(world_state_view
                .domains()
                .iter()
                .map(|guard| guard.value().clone())
                .collect())
        }
    }

    impl Query for FindDomainByName {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            let name = self
                .name
                .evaluate(world_state_view, &Context::default())
                .wrap_err("Failed to get domain name")?;
            Ok(world_state_view.domain(&name, Clone::clone)?.into())
        }
    }
}
