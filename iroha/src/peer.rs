//! This module contains `Peer` structure and related implementations and traits implementations.

use crate::{isi::prelude::*, prelude::*};
use iroha_data_model::*;

/// Iroha Special Instructions module provides `PeerInstruction` enum with all possible types of
/// Peer related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `PeerInstruction` variants into generic ISI.
pub mod isi {
    use super::*;
    use iroha_data_model::prelude::*;

    impl Execute for Register<Peer, Peer> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            let mut world_state_view = world_state_view.clone();
            if world_state_view
                .peer()
                .trusted_peers_ids
                .insert(self.object.id)
            {
                Ok(world_state_view)
            } else {
                Err("Peer already presented in the list of trusted peers.".to_string())
            }
        }
    }

    impl Execute for Register<Peer, Domain> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            let mut world_state_view = world_state_view.clone();
            let _ = world_state_view
                .peer()
                .domains
                .insert(self.object.name.clone(), self.object);
            Ok(world_state_view)
        }
    }

    impl Execute for Unregister<Peer, Domain> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            let mut world_state_view = world_state_view.clone();
            let _ = world_state_view.peer().domains.remove(&self.object.name);
            Ok(world_state_view)
        }
    }

    impl Execute for Mint<Peer, Parameter> {
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            let mut world_state_view = world_state_view.clone();
            world_state_view.peer().parameters.push(self.object);
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
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            Ok(QueryResult::FindAllPeers(Box::new(FindAllPeersResult {
                peers: world_state_view
                    .read_peer()
                    .clone()
                    .trusted_peers_ids
                    .into_iter()
                    .collect(),
            })))
        }
    }

    impl Query for FindPeerById {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            Ok(QueryResult::FindPeerById(Box::new(FindPeerByIdResult {
                peer: world_state_view
                    .read_peer()
                    .clone()
                    .trusted_peers_ids
                    .iter()
                    .find(|peer_id| *peer_id == &self.id)
                    .ok_or("Failed to find Peer.")?
                    .clone(),
            })))
        }
    }

    impl Query for FindAllParameters {
        #[log]
        fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
            Ok(QueryResult::FindAllParameters(Box::new(
                FindAllParametersResult {
                    parameters: world_state_view.read_peer().parameters.clone(),
                },
            )))
        }
    }
}
