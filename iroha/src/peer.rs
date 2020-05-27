//! This module contains `Peer` structure and related implementations and traits implementations.

use crate::{isi::prelude::*, prelude::*};
use iroha_derive::*;
use parity_scale_codec::{Decode, Encode};
use std::collections::{HashMap, HashSet};

type PublicKey = [u8; 32];

/// Peer's identification.
#[derive(Encode, Decode, PartialEq, Eq, Debug, Clone, Hash, Io)]
pub struct PeerId {
    /// Address of the Peer's entrypoint.
    pub address: String,
    /// Public Key of the Peer.
    pub public_key: PublicKey,
}

/// Peer represents currently running Iroha instance.
#[derive(Debug, Clone)]
pub struct Peer {
    /// Peer Identification.
    pub id: PeerId,
    /// All discovered Peers' Ids.
    pub peers: HashSet<PeerId>,
    /// Address to listen to.
    pub listen_address: String,
    /// Registered domains.
    pub domains: HashMap<String, Domain>,
}

impl Peer {
    /// Default `Peer` constructor.
    pub fn new(id: PeerId, trusted_peers: &[PeerId]) -> Peer {
        Peer {
            id: id.clone(),
            peers: trusted_peers
                .iter()
                .filter(|peer_id| id.address != peer_id.address)
                .cloned()
                .collect(),
            listen_address: id.address,
            domains: HashMap::new(),
        }
    }

    /// Constructor of `Add<Peer, Domain>` Iroha Special Instruction.
    pub fn add_domain(&self, object: Domain) -> Add<Peer, Domain> {
        Add {
            object,
            destination_id: self.id.clone(),
        }
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
    use std::ops::{AddAssign, Sub};

    /// Enumeration of all legal Peer related Instructions.
    #[derive(Clone, Debug, Io, Encode, Decode)]
    pub enum PeerInstruction {
        /// Variant of the generic `Add` instruction for `Domain` --> `Peer`.
        AddDomain(String, PeerId),
    }

    impl PeerInstruction {
        /// Executes `PeerInstruction` on the given `WorldStateView`.
        /// Returns `Ok(())` if execution succeeded and `Err(String)` with error message if not.
        pub fn execute(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
            match self {
                PeerInstruction::AddDomain(domain_name, peer_id) => {
                    Add::new(Domain::new(domain_name.to_string()), peer_id.clone())
                        .execute(world_state_view)
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
        fn execute(self, world_state_view: &mut WorldStateView) -> Result<(), String> {
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
}
