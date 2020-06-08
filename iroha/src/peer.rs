//! This module contains `Peer` structure and related implementations and traits implementations.

use crate::{isi::prelude::*, prelude::*};
use iroha_derive::*;
use parity_scale_codec::{Decode, Encode};
use std::collections::{HashMap, HashSet};

type PublicKey = [u8; 32];

/// Peer's identification.
#[derive(Encode, Decode, PartialEq, Eq, Debug, Clone, Hash, Io, Default)]
pub struct PeerId {
    /// Address of the Peer's entrypoint.
    pub address: String,
    /// Public Key of the Peer.
    pub public_key: PublicKey,
}

/// Peer represents currently running Iroha instance.
#[derive(Debug, Clone, Default)]
pub struct Peer {
    /// Peer Identification.
    pub id: PeerId,
    /// All discovered Peers' Ids.
    pub peers: HashSet<PeerId>,
    /// Address to listen to.
    pub listen_address: String,
    /// Registered domains.
    pub domains: HashMap<String, Domain>,
    /// Events Listeners.
    pub listeners: Vec<Instruction>,
    #[cfg(feature = "bridge")]
    /// Registered bridges.
    pub bridges: HashMap<String, Bridge>,
}

impl Peer {
    /// Default `Peer` constructor.
    pub fn new(id: PeerId, trusted_peers: &[PeerId]) -> Peer {
        Self::with_domains(id, trusted_peers, HashMap::new())
    }

    /// `Peer` constructor with a predefined domains.
    pub fn with_domains(
        id: PeerId,
        trusted_peers: &[PeerId],
        domains: HashMap<<Domain as Identifiable>::Id, Domain>,
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
            listeners: Vec::new(),
            ..Default::default()
        }
    }

    /// `Peer` constructor with a predefined listeners.
    pub fn with_listeners(
        id: PeerId,
        trusted_peers: &[PeerId],
        listeners: Vec<Instruction>,
    ) -> Peer {
        Peer {
            id: id.clone(),
            peers: trusted_peers
                .iter()
                .filter(|peer_id| id.address != peer_id.address)
                .cloned()
                .collect(),
            listen_address: id.address,
            domains: HashMap::new(),
            listeners,
            ..Default::default()
        }
    }

    /// `Peer` constructor with a predefined domains and listeners.
    pub fn with_domains_and_listeners(
        id: PeerId,
        trusted_peers: &[PeerId],
        domains: HashMap<<Domain as Identifiable>::Id, Domain>,
        listeners: Vec<Instruction>,
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
            listeners,
            ..Default::default()
        }
    }

    /// Constructor of `Add<Peer, Domain>` Iroha Special Instruction.
    pub fn add_domain(&self, object: Domain) -> Add<Peer, Domain> {
        Add {
            object,
            destination_id: self.id.clone(),
        }
    }

    /// Add new Listener to the World.
    pub fn add_listener(&mut self, listener: Instruction) {
        self.listeners.push(listener);
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

/// Iroha Special Instructions module provides `PeerInstruction` enum with all legal types of
/// Peer related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `PeerInstruction` variants into generic ISI.
pub mod isi {
    use super::*;
    use crate::permission::isi::PermissionInstruction;
    use std::ops::{AddAssign, Sub};

    /// Enumeration of all legal Peer related Instructions.
    #[derive(Clone, Debug, Io, Encode, Decode)]
    pub enum PeerInstruction {
        /// Variant of the generic `Add` instruction for `Domain` --> `Peer`.
        AddDomain(String, PeerId),
        /// Variant of the generic `Add` instruction for `Instruction` --> `Peer`.
        AddListener(Box<Instruction>, PeerId),
        #[cfg(feature = "bridge")]
        /// Variant of the generic `Register` instruction for `BridgeDefinition` --> `Peer`.
        RegisterBridge(BridgeDefinition, PeerId),
    }

    impl PeerInstruction {
        /// Executes `PeerInstruction` on the given `WorldStateView`.
        /// Returns `Ok(())` if execution succeeded and `Err(String)` with error message if not.
        pub fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), String> {
            match self {
                PeerInstruction::AddDomain(domain_name, peer_id) => {
                    Add::new(Domain::new(domain_name.to_string()), peer_id.clone())
                        .execute(authority, world_state_view)
                }
                PeerInstruction::AddListener(listener, peer_id) => {
                    Add::new(*listener.clone(), peer_id.clone())
                        .execute(authority, world_state_view)
                }
                #[cfg(feature = "bridge")]
                PeerInstruction::RegisterBridge(bridge_def, peer_id) => {
                    Register::new(bridge_def.clone(), peer_id.clone()).execute(world_state_view)
                }
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
            world_state_view: &mut WorldStateView,
        ) -> Result<(), String> {
            PermissionInstruction::CanAddDomain(authority).execute(world_state_view)?;
            *world_state_view.peer() += self.object;
            Ok(())
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
            world_state_view: &mut WorldStateView,
        ) -> Result<(), String> {
            PermissionInstruction::CanAddListener(authority).execute(world_state_view)?;
            world_state_view.peer().listeners.push(self.object);
            Ok(())
        }
    }
}
