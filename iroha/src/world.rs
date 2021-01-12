//! This module contains `World` related ISI implementations.

use crate::{isi::prelude::*, prelude::*};
use iroha_data_model::*;

/// Iroha Special Instructions that have `World` as their target.
pub mod isi {
    use super::*;
    use iroha_data_model::prelude::*;

    impl Execute for Register<World, Peer> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            let mut world_state_view = world_state_view.clone();
            if world_state_view
                .world()
                .trusted_peers_ids
                .insert(self.object.id)
            {
                Ok(world_state_view)
            } else {
                Err("Peer already presented in the list of trusted peers.".to_string())
            }
        }
    }

    impl Execute for Register<World, Domain> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            let mut world_state_view = world_state_view.clone();
            let _ = world_state_view
                .world()
                .domains
                .insert(self.object.name.clone(), self.object);
            Ok(world_state_view)
        }
    }

    impl Execute for Unregister<World, Domain> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            let mut world_state_view = world_state_view.clone();
            let _ = world_state_view.world().domains.remove(&self.object.name);
            Ok(world_state_view)
        }
    }

    impl Execute for Mint<World, Parameter> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
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

    impl Query for FindAllPeers {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value, String> {
            Ok(world_state_view
                .read_world()
                .clone()
                .trusted_peers_ids
                .into_iter()
                .collect())
        }
    }

    impl Query for FindPeerById {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value, String> {
            Ok(world_state_view
                .read_world()
                .clone()
                .trusted_peers_ids
                .iter()
                .find(|peer_id| *peer_id == &self.id)
                .ok_or("Failed to find Peer.")?
                .clone()
                .into())
        }
    }

    impl Query for FindAllParameters {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value, String> {
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
