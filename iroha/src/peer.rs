//! This module contains `Peer` structure and related implementations and traits implementations.

use crate::{isi::prelude::*, prelude::*};
use iroha_data_model::*;

/// Iroha Special Instructions module provides `PeerInstruction` enum with all possible types of
/// Peer related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `PeerInstruction` variants into generic ISI.
pub mod isi {
    use super::*;
    use crate::permission;
    use iroha_data_model::prelude::*;

    impl Execute for Register<Peer, Domain> {
        fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            permission::check(authority, Box::new(AddDomain::new()), world_state_view)?;
            let mut world_state_view = world_state_view.clone();
            world_state_view
                .peer()
                .domains
                .insert(self.object.name.clone(), self.object);
            Ok(world_state_view)
        }
    }

    impl Execute for Register<Peer, InstructionBox> {
        fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<WorldStateView, String> {
            permission::check(authority, Box::new(AddTrigger::new()), world_state_view)?;
            let mut world_state_view = world_state_view.clone();
            world_state_view.peer().triggers.push(self.object);
            Ok(world_state_view)
        }
    }
}
