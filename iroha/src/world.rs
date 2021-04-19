//! This module contains `World` related ISI implementations.

use crate::{isi::prelude::*, prelude::*};

/// Iroha Special Instructions that have `World` as their target.
pub mod isi {
    use async_std::task::block_on;
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

    impl Execute for Mint<World, Parameter> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<(), Error> {
            block_on(world_state_view.parameters().write()).push(self.object);
            Ok(())
        }
    }
}

/// Query module provides `IrohaQuery` Peer related implementations.
pub mod query {
    use async_std::task::block_on;
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
            Ok(block_on(world_state_view.parameters().read())
                .iter()
                .cloned()
                .map(Value::Parameter)
                .collect::<Vec<Value>>()
                .into())
        }
    }
}
