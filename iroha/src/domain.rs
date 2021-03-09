//! This module contains `Domain` structure and related implementations and trait implementations.
use crate::{isi::prelude::*, prelude::*};
use iroha_data_model::prelude::*;
use iroha_error::{Error, Result};

/// Iroha Special Instructions module provides `DomainInstruction` enum with all possible types of
/// Domain related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `DomainInstruction` variants into generic ISI.
pub mod isi {
    use super::*;

    impl Execute for Register<Account> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let account = self.object;
            let domain = world_state_view
                .domain(&account.id.domain_name)
                .ok_or_else(|| Error::msg("Failed to find domain."))?;
            if domain.accounts.contains_key(&account.id) {
                Err(Error::msg(format!(
                    "Domain already contains an account with an Id: {:?}",
                    &account.id
                )))
            } else {
                let _ = domain.accounts.insert(account.id.clone(), account);
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
                .ok_or_else(|| Error::msg("Failed to find domain."))?;
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
            let _ = world_state_view
                .domain(&asset_definition.id.domain_name)
                .ok_or_else(|| Error::msg("Failed to find domain."))?
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
                .ok_or_else(|| Error::msg("Failed to find domain."))?
                .asset_definitions
                .remove(&asset_definition_id);
            Ok(world_state_view)
        }
    }
}

/// Query module provides `IrohaQuery` Domain related implementations.
pub mod query {
    use super::*;
    use iroha_derive::*;

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
            Ok(world_state_view
                .read_domain(&self.name)
                .map(Clone::clone)
                .ok_or_else(|| Error::msg("Failed to get a domain."))?
                .into())
        }
    }
}
