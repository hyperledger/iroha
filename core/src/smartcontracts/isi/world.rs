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
            authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let peer = self.object;
            wsv.register(peer, authority)
        }
    }

    impl<W: WorldTrait> Execute<W> for Unregister<Peer> {
        type Error = Error;

        #[metrics(+"unregister_peer")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let peer_id = self.object_id;
            wsv.unregister::<Peer>(peer_id)
        }
    }

    impl<W: WorldTrait> Execute<W> for Register<Domain> {
        type Error = Error;

        #[metrics("register_domain")]
        fn execute(
            self,
            authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let domain = self.object;
            wsv.register(domain, authority)
        }
    }

    impl<W: WorldTrait> Execute<W> for Unregister<Domain> {
        type Error = Error;

        #[metrics("unregister_domain")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let domain_id = self.object_id;
            wsv.unregister::<Domain>(domain_id)
        }
    }

    #[cfg(feature = "roles")]
    impl<W: WorldTrait> Execute<W> for Register<Role> {
        type Error = Error;

        #[metrics(+"register_role")]
        fn execute(
            self,
            authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let role = self.object;
            wsv.register(role.authority)
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
        ) -> Result<(), Self::Error> {
            let role_id = self.object_id;
            wsv.unregister::<Role>(role_id)
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
