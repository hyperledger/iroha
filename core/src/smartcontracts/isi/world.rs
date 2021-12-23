//! `World`-related ISI implementations.

use super::prelude::*;
use crate::prelude::*;

/// Iroha Special Instructions that have `World` as their target.
pub mod isi {
    use eyre::Result;
    use iroha_data_model::prelude::*;
    use iroha_telemetry::metrics;

    use super::*;

    impl<W: WorldTrait> Execute<W> for Register<Peer> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"register_peer")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            if wsv.trusted_peers_ids().insert(self.object.id.clone()) {
                Ok(self.into())
            } else {
                Err(Error::Repetition(
                    InstructionType::Register,
                    IdBox::PeerId(self.object.id),
                ))
            }
        }
    }

    impl<W: WorldTrait> Execute<W> for Unregister<Peer> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"unregister_peer")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            if wsv.trusted_peers_ids().remove(&self.object_id).is_some() {
                Ok(self.into())
            } else {
                Err(FindError::Peer(self.object_id).into())
            }
        }
    }

    impl<W: WorldTrait> Execute<W> for Register<Domain> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics("register_domain")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            let domain = self.object.clone();
            domain
                .id
                .name
                .validate_len(wsv.config.ident_length_limits)
                .map_err(Error::Validate)?;
            wsv.domains().insert(domain.id.clone(), domain);
            wsv.metrics.domains.inc();
            Ok(self.into())
        }
    }

    impl<W: WorldTrait> Execute<W> for Unregister<Domain> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics("unregister_domain")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            // TODO: Should we fail if no domain found?
            wsv.domains().remove(&self.object_id);
            wsv.metrics.domains.dec();
            Ok(self.into())
        }
    }

    #[cfg(feature = "roles")]
    impl<W: WorldTrait> Execute<W> for Register<Role> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"register_role")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            let role = self.object.clone();
            wsv.world.roles.insert(role.id.clone(), role);
            Ok(self.into())
        }
    }

    #[cfg(feature = "roles")]
    impl<W: WorldTrait> Execute<W> for Unregister<Role> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics("unregister_peer")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            wsv.world.roles.remove(&self.object_id);
            for mut domain in wsv.domains().iter_mut() {
                for account in domain.accounts.values_mut() {
                    let _ = account.roles.remove(&self.object_id);
                }
            }
            Ok(self.into())
        }
    }
}

/// Query module provides `IrohaQuery` Peer related implementations.
pub mod query {
    use eyre::Result;
    use iroha_data_model::prelude::*;
    use iroha_logger::log;

    use super::*;
    use crate::smartcontracts::query::Error;

    #[cfg(feature = "roles")]
    impl<W: WorldTrait> ValidQuery<W> for FindAllRoles {
        #[log]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            Ok(wsv
                .world
                .roles
                .iter()
                .map(|role| role.value().clone())
                .collect())
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindAllPeers {
        #[log]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            Ok(wsv.peers())
        }
    }
}
