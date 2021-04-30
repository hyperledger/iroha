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
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            if world_state_view.trusted_peers_ids().insert(self.object.id) {
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
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            let domain = self.object;
            domain.validate_len(world_state_view.config.length_limits)?;
            drop(
                world_state_view
                    .domains()
                    .insert(domain.name.clone(), domain),
            );
            Ok(())
        }
    }

    impl Execute for Unregister<Domain> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            // TODO: Should we fail if no domain found?
            drop(world_state_view.domains().remove(&self.object_id));
            Ok(())
        }
    }

    #[cfg(feature = "roles")]
    impl Execute for Register<Role> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
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
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            let _ = world_state_view.world.roles.remove(&self.object_id);
            for mut domain in world_state_view.domains().iter_mut() {
                for account in domain.accounts.values_mut() {
                    let _ = account.roles.remove(&self.object_id);
                }
            }
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

    #[cfg(feature = "roles")]
    impl Query for FindAllRoles {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            Ok(Value::Vec(
                world_state_view
                    .world
                    .roles
                    .iter()
                    .map(|pair| Box::new(pair.value().clone()))
                    .map(IdentifiableBox::Role)
                    .map(Value::Identifiable)
                    .collect::<Vec<_>>(),
            ))
        }
    }

    impl Query for FindAllPeers {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
            Ok(Value::Vec(
                world_state_view
                    .peers()
                    .into_iter()
                    .map(Box::new)
                    .map(IdentifiableBox::Peer)
                    .map(Value::Identifiable)
                    .collect::<Vec<_>>(),
            ))
        }
    }
}
