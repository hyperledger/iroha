//! This module contains `Peer` structure and related implementations.

use crate::{
    account::{Account, Id as AccountId},
    domain::*,
    isi::*,
    Identifiable,
};
use iroha_crypto::PublicKey;
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
    /// Events Listeners.
    pub listeners: Vec<Instruction>,
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
            listeners: Vec::new(),
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
            domains: BTreeMap::new(),
            listeners,
        }
    }

    /// `Peer` constructor with a predefined domains and listeners.
    pub fn with_domains_and_listeners(
        id: PeerId,
        trusted_peers: &[PeerId],
        domains: BTreeMap<<Domain as Identifiable>::Id, Domain>,
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

    /// Enumeration of all legal Peer related Instructions.
    #[derive(Clone, Debug, Io, Encode, Decode)]
    pub enum PeerInstruction {
        /// Variant of the generic `Add` instruction for `Domain` --> `Peer`.
        AddDomain(String, PeerId),
        /// Variant of the generic `Add` instruction for `Instruction` --> `Peer`.
        AddListener(Box<Instruction>, PeerId),
        /// Instruction to add a peer to the network.
        AddPeer(PeerId),
    }
}
