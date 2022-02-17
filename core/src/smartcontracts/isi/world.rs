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

        #[metrics(+"register_peer")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Vec<DataEvent>, Self::Error> {
            if wsv.trusted_peers_ids().insert(self.object.id.clone()) {
                Ok(vec![DataEvent::new(self.object.id, DataStatus::Created)])
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

        #[metrics(+"unregister_peer")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Vec<DataEvent>, Self::Error> {
            if wsv.trusted_peers_ids().remove(&self.object_id).is_some() {
                Ok(vec![DataEvent::new(self.object_id, DataStatus::Deleted)])
            } else {
                Err(FindError::Peer(self.object_id).into())
            }
        }
    }

    impl<W: WorldTrait> Execute<W> for Register<Domain> {
        type Error = Error;

        #[metrics("register_domain")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Vec<DataEvent>, Self::Error> {
            let domain_id = self.object.id.clone();
            let domain = self.object;

            domain
                .id
                .name
                .validate_len(wsv.config.ident_length_limits)
                .map_err(Error::Validate)?;
            wsv.domains().insert(domain_id.clone(), domain);
            wsv.metrics.domains.inc();

            Ok(vec![DataEvent::new(domain_id, DataStatus::Created)])
        }
    }

    impl<W: WorldTrait> Execute<W> for Unregister<Domain> {
        type Error = Error;

        #[metrics("unregister_domain")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Vec<DataEvent>, Self::Error> {
            let domain_id = self.object_id;

            // TODO: Should we fail if no domain found?
            wsv.domains().remove(&domain_id);
            wsv.metrics.domains.dec();

            Ok(vec![DataEvent::new(domain_id, DataStatus::Deleted)])
        }
    }

    #[cfg(feature = "roles")]
    impl<W: WorldTrait> Execute<W> for Register<Role> {
        type Error = Error;

        #[metrics(+"register_role")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Vec<DataEvent>, Self::Error> {
            let role = self.object;
            let role_id = role.id.clone();

            wsv.world.roles.insert(role_id.clone(), role);
            Ok(vec![DataEvent::new(role_id, DataStatus::Created)])
        }
    }

    #[cfg(feature = "roles")]
    impl<W: WorldTrait> Execute<W> for Unregister<Role> {
        type Error = Error;

        #[metrics("unregister_peer")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Vec<DataEvent>, Self::Error> {
            let role_id = self.object_id;

            wsv.world.roles.remove(&role_id);
            for mut domain in wsv.domains().iter_mut() {
                for account in domain.accounts.values_mut() {
                    let _ = account.roles.remove(&role_id);
                }
            }

            Ok(vec![DataEvent::new(role_id, DataStatus::Deleted)])
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
