//! This module contains `World` related ISI implementations.

use crate::{isi::prelude::*, prelude::*};
use iroha_data_model::*;

/// Iroha Special Instructions that have `World` as their target.
pub mod isi {
    use super::*;
    use iroha_data_model::prelude::*;
    use iroha_error::{error, Result};

    impl Execute for Register<Peer> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            if world_state_view
                .world()
                .trusted_peers_ids
                .insert(self.object.id)
            {
                Ok(world_state_view)
            } else {
                Err(error!(
                    "Peer already presented in the list of trusted peers.",
                ))
            }
        }
    }

    impl Execute for Register<Domain> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let _ = world_state_view
                .world()
                .domains
                .insert(self.object.name.clone(), self.object);
            Ok(world_state_view)
        }
    }

    impl Execute for Unregister<Domain> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            let _ = world_state_view.world().domains.remove(&self.object_id);
            Ok(world_state_view)
        }
    }

    impl Execute for Mint<World, Parameter> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView> {
            let mut world_state_view = world_state_view.clone();
            world_state_view.world().parameters.push(self.object);
            Ok(world_state_view)
        }
    }
}

/// Query module provides `IrohaQuery` Peer related implementations.
pub mod query {
    use super::*;
    use iroha_data_model::prelude::*;
    use iroha_derive::*;
    use iroha_error::Result;

    impl Query for FindAllPeers {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            Ok(Value::Vec(
                world_state_view
                    .read_all_peers()
                    .into_iter()
                    .map(Box::new)
                    .map(IdentifiableBox::Peer)
                    .map(Value::Identifiable)
                    .collect::<Vec<_>>(),
            ))
        }
    }

    impl Query for FindAllParameters {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            Ok(world_state_view
                .read_world()
                .parameters
                .iter()
                .cloned()
                .map(Value::Parameter)
                .collect::<Vec<Value>>()
                .into())
        }
    }
}
