//! This module contains `Domain` structure and related implementations and trait implementations.
use iroha_data_model::prelude::*;
use iroha_error::{error, Result};

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
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let account = self.object;
            account.validate_len(world_state_view.config.length_limits)?;
            let domain = world_state_view
                .domain(&account.id.domain_name)
                .ok_or_else(|| error!("Failed to find domain."))?;
            if domain.accounts.contains_key(&account.id) {
                Err(error!(
                    "Domain already contains an account with an Id: {:?}",
                    &account.id
                ))
            } else {
                let _ = domain.accounts.insert(account.id.clone(), account.into());
                Ok(world_state_view)
            }
        }
    }

    impl Execute for Unregister<Account> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let account_id = self.object_id;
            let domain = world_state_view
                .domain(&account_id.domain_name)
                .ok_or_else(|| error!("Failed to find domain."))?;
            let _ = domain.accounts.remove(&account_id);
            Ok(world_state_view)
        }
    }

    impl Execute for Register<AssetDefinition> {
        fn execute(
            self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let asset_definition = self.object;
            asset_definition.validate_len(world_state_view.config.length_limits)?;
            let _ = world_state_view
                .domain(&asset_definition.id.domain_name)
                .ok_or_else(|| error!("Failed to find domain."))?
                .asset_definitions
                .insert(
                    asset_definition.id.clone(),
                    AssetDefinitionEntry {
                        definition: asset_definition,
                        registered_by: authority,
                    },
                );
            Ok(world_state_view)
        }
    }

    impl Execute for Unregister<AssetDefinition> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let asset_definition_id = self.object_id;
            let _ = world_state_view
                .domain(&asset_definition_id.domain_name)
                .ok_or_else(|| error!("Failed to find domain."))?
                .asset_definitions
                .remove(&asset_definition_id);
            Ok(world_state_view)
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
                .read_all_domains()
                .into_iter()
                .cloned()
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
            Ok(world_state_view
                .read_domain(&name)
                .map(Clone::clone)
                .ok_or_else(|| error!("Failed to get a domain."))?
                .into())
        }
    }
}
