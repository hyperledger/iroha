//! This module contains `Peer` structure and related implementations and traits implementations.

use crate::{isi::prelude::*, prelude::*};
use iroha_derive::*;
use parity_scale_codec::{Decode, Encode};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

/// Peer's identification.
#[derive(
    Encode, Decode, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Hash, Io, Default, Deserialize,
)]
pub struct PeerId {
    /// Address of the Peer's entrypoint.
    pub address: String,
    /// Public Key of the Peer.
    pub public_key: PublicKey,
}

impl PeerId {
    /// Default `PeerId` constructor.
    pub fn new(address: &str, public_key: &PublicKey) -> Self {
        PeerId {
            address: address.to_string(),
            public_key: public_key.clone(),
        }
    }
}

/// Peer represents currently running Iroha instance.
#[derive(Debug, Clone, Default, Encode, Decode, Io)]
pub struct Peer {
    /// Peer Identification.
    pub id: PeerId,
    /// All discovered Peers' Ids.
    pub peers: BTreeSet<PeerId>,
    /// Address to listen to.
    pub listen_address: String,
    /// Registered domains.
    pub domains: BTreeMap<String, Domain>,
    /// Events Triggers.
    pub triggers: Vec<Instruction>,
}

impl Peer {
    /// Default `Peer` constructor.
    pub fn new(id: PeerId, trusted_peers: &[PeerId]) -> Peer {
        Self::with_domains(id, trusted_peers, BTreeMap::new())
    }

    /// `Peer` constructor with a predefined domains.
    pub fn with_domains(
        id: PeerId,
        trusted_peers: &[PeerId],
        domains: BTreeMap<<Domain as Identifiable>::Id, Domain>,
    ) -> Peer {
        Peer {
            id: id.clone(),
            peers: trusted_peers.iter().cloned().collect(),
            listen_address: id.address,
            domains,
            triggers: Vec::new(),
        }
    }

    /// `Peer` constructor with a predefined triggers.
    pub fn with_triggers(id: PeerId, trusted_peers: &[PeerId], triggers: Vec<Instruction>) -> Peer {
        Peer {
            id: id.clone(),
            peers: trusted_peers
                .iter()
                .filter(|peer_id| id.address != peer_id.address)
                .cloned()
                .collect(),
            listen_address: id.address,
            domains: BTreeMap::new(),
            triggers,
        }
    }

    /// `Peer` constructor with a predefined domains and triggers.
    pub fn with_domains_and_triggers(
        id: PeerId,
        trusted_peers: &[PeerId],
        domains: BTreeMap<<Domain as Identifiable>::Id, Domain>,
        triggers: Vec<Instruction>,
    ) -> Peer {
        Peer {
            id: id.clone(),
            peers: trusted_peers
                .iter()
                .filter(|peer_id| id.address != peer_id.address)
                .cloned()
                .collect(),
            listen_address: id.address,
            domains,
            triggers,
        }
    }

    /// Constructor of `Add<Peer, Domain>` Iroha Special Instruction.
    pub fn add_domain(&self, object: Domain) -> Add<Peer, Domain> {
        Add {
            object,
            destination_id: self.id.clone(),
        }
    }

    /// Add new Trigger to the World.
    pub fn add_trigger(&mut self, trigger: Instruction) {
        self.triggers.push(trigger);
    }

    /// This method should be used to generate Peer's authority.
    /// For example if you need to execute some Iroha Special Instructions.
    pub fn authority(&self) -> <Account as Identifiable>::Id {
        AccountId::new("root", "global")
    }
}

impl Identifiable for Peer {
    type Id = PeerId;
}

/// Iroha Special Instructions module provides `PeerInstruction` enum with all possible types of
/// Peer related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `PeerInstruction` variants into generic ISI.
pub mod isi {
    use super::*;
    use crate::permission::isi::PermissionInstruction;
    use std::ops::{AddAssign, Sub};

    /// Enumeration of all possible Peer related Instructions.
    #[derive(Clone, Debug, Io, Encode, Decode)]
    pub enum PeerInstruction {
        /// Variant of the generic `Add` instruction for `Domain` --> `Peer`.
        AddDomain(String, PeerId),
        /// Variant of the generic `Add` instruction for `Instruction` --> `Peer`.
        AddTrigger(Box<Instruction>, PeerId),
        /// Instruction to add a peer to the network.
        AddPeer(PeerId),
    }

    /// Enumeration of all possible Outputs for `PeerInstruction` execution.
    #[derive(Debug)]
    pub enum Output {
        /// Variant of output for `PeerInstruction::AddDomain`.
        AddDomain(WorldStateView),
        /// Variant of output for `PeerInstruction::AddTrigger`.
        AddTrigger(WorldStateView),
        /// Variant of output for `PeerInstruction::AddPeer`.
        AddPeer(WorldStateView),
    }

    impl PeerInstruction {
        /// Executes `PeerInstruction` on the given `WorldStateView`.
        /// Returns `Ok(())` if execution succeeded and `Err(String)` with error message if not.
        pub fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<Output, String> {
            match self {
                PeerInstruction::AddDomain(domain_name, peer_id) => {
                    Add::new(Domain::new(domain_name.to_string()), peer_id.clone())
                        .execute(authority, world_state_view)
                }
                PeerInstruction::AddTrigger(trigger, peer_id) => {
                    Add::new(*trigger.clone(), peer_id.clone()).execute(authority, world_state_view)
                }
                PeerInstruction::AddPeer(candidate_peer) => {
                    let mut world_state_view = world_state_view.clone();
                    let peer = world_state_view.peer();
                    if peer.peers.contains(candidate_peer) {
                        Err("Peer is already in the peer network.".to_string())
                    } else {
                        peer.peers.insert(candidate_peer.clone());
                        Ok(Output::AddPeer(world_state_view))
                    }
                }
            }
        }
    }

    impl Output {
        /// Get instance of `WorldStateView` with changes applied during `Instruction` execution.
        pub fn world_state_view(&self) -> WorldStateView {
            match self {
                Output::AddDomain(world_state_view)
                | Output::AddTrigger(world_state_view)
                | Output::AddPeer(world_state_view) => world_state_view.clone(),
            }
        }
    }

    impl AddAssign<Domain> for Peer {
        fn add_assign(&mut self, domain: Domain) {
            self.domains.insert(domain.name.clone(), domain);
        }
    }

    impl Add<Peer, Domain> {
        pub(crate) fn execute(
            self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<Output, String> {
            PermissionInstruction::CanAddDomain(authority).execute(world_state_view)?;
            let mut world_state_view = world_state_view.clone();
            *world_state_view.peer() += self.object;
            Ok(Output::AddDomain(world_state_view))
        }
    }

    impl From<Add<Peer, Domain>> for Instruction {
        fn from(add_instruction: Add<Peer, Domain>) -> Self {
            Instruction::Peer(PeerInstruction::AddDomain(
                add_instruction.object.name,
                add_instruction.destination_id,
            ))
        }
    }

    impl Sub<Domain> for Peer {
        type Output = Self;

        fn sub(mut self, domain: Domain) -> Self {
            self.domains.remove(&domain.name);
            self
        }
    }

    impl Add<Peer, Instruction> {
        fn execute(
            self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &WorldStateView,
        ) -> Result<Output, String> {
            PermissionInstruction::CanAddTrigger(authority).execute(world_state_view)?;
            let mut world_state_view = world_state_view.clone();
            world_state_view.peer().triggers.push(self.object);
            Ok(Output::AddTrigger(world_state_view))
        }
    }
}
