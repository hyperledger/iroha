//! This module contains `World` related ISI implementations.

use crate::{isi::prelude::*, prelude::*};

/// Iroha Special Instructions that have `World` as their target.
pub mod isi {
    use iroha_data_model::prelude::*;
    use iroha_error::{error, Result};

    use super::*;

    impl Execute for Register<Peer> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), Error> {
            if world_state_view
                .world()
                .trusted_peers_ids
                .insert(self.object.id)
            {
                Ok(())
            } else {
                Err(error!("Peer already presented in the list of trusted peers.",).into())
            }
        }
    }

    impl Execute for Register<Domain> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), Error> {
            let domain = self.object;
            domain.validate_len(world_state_view.config.length_limits)?;
            let _ = world_state_view
                .world()
                .domains
                .insert(domain.name.clone(), domain);
            Ok(())
        }
    }

    impl Execute for Unregister<Domain> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), Error> {
            // TODO: Should we fail if no domain found?
            let _ = world_state_view.world().domains.remove(&self.object_id);
            Ok(())
        }
    }

    impl Execute for Mint<World, Parameter> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), Error> {
            world_state_view.world().parameters.push(self.object);
            Ok(())
        }
    }

    #[cfg(feature = "roles")]
    impl Execute for Register<Role> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), Error> {
            let role = self.object;
            let _ = world_state_view.world.roles.insert(role.id.clone(), role);
            Ok(())
        }
    }

    #[cfg(feature = "roles")]
    impl Execute for Unregister<Role> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), Error> {
            let _ = world_state_view.world.roles.remove(&self.object_id);
            world_state_view
                .world
                .domains
                .values_mut()
                .flat_map(|domain| domain.accounts.values_mut())
                .for_each(|account| {
                    let _ = account.roles.remove(&self.object_id);
                });
            Ok(())
        }
    }
}

/// Query module provides `IrohaQuery` Peer related implementations.
pub mod query {
    use iroha_data_model::prelude::*;
    use iroha_error::Result;
    use iroha_logger::log;

    use super::*;

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
