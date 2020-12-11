//! This module contains `Domain` structure and related implementations and trait implementations.
use crate::{isi::prelude::*, prelude::*};
use iroha_data_model::prelude::*;

/// Iroha Special Instructions module provides `DomainInstruction` enum with all possible types of
/// Domain related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `DomainInstruction` variants into generic ISI.
pub mod isi {
    use super::*;

    impl Execute for Register<Domain, Account> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            let mut world_state_view = world_state_view.clone();
            let account = self.object.clone();
            let domain = world_state_view
                .domain(&self.destination_id)
                .ok_or("Failed to find domain.")?;
            if domain.accounts.contains_key(&account.id) {
                Err(format!(
                    "Domain already contains an account with an Id: {:?}",
                    &account.id
                ))
            } else {
                let _ = domain.accounts.insert(account.id.clone(), account);
                Ok(world_state_view)
            }
        }
    }

    impl Execute for Unregister<Domain, Account> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            let mut world_state_view = world_state_view.clone();
            let account = self.object.clone();
            let domain = world_state_view
                .domain(&self.destination_id)
                .ok_or("Failed to find domain.")?;
            let _ = domain.accounts.remove(&account.id);
            Ok(world_state_view)
        }
    }

    impl Execute for Register<Domain, AssetDefinition> {
        fn execute(
            self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            let mut world_state_view = world_state_view.clone();
            let asset = self.object.clone();
            let _ = world_state_view
                .domain(&self.destination_id)
                .ok_or("Failed to find domain.")?
                .asset_definitions
                .insert(
                    asset.id.clone(),
                    AssetDefinitionEntry {
                        definition: asset,
                        registered_by: authority,
                    },
                );
            Ok(world_state_view)
        }
    }

    impl Execute for Unregister<Domain, AssetDefinition> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            let mut world_state_view = world_state_view.clone();
            let asset_definition = self.object.clone();
            let _ = world_state_view
                .domain(&self.destination_id)
                .ok_or("Failed to find domain.")?
                .asset_definitions
                .remove(&asset_definition.id);
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
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            Ok(QueryResult::FindAllDomains(Box::new(
                FindAllDomainsResult {
                    domains: world_state_view
                        .read_all_domains()
                        .into_iter()
                        .cloned()
                        .collect(),
                },
            )))
        }
    }

    impl Query for FindDomainByName {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            Ok(QueryResult::FindDomainByName(Box::new(
                FindDomainByNameResult {
                    domain: world_state_view
                        .read_domain(&self.name)
                        .map(Clone::clone)
                        .ok_or("Failed to get a domain.")?,
                },
            )))
        }
    }
}
