//! Structures formalising the peer topology (e.g. which peers have which predefined roles).
#![allow(
    clippy::new_without_default,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic_side_effects
)]

use derive_more::Display;
use iroha_crypto::{PublicKey, SignatureOf};
use iroha_data_model::prelude::PeerId;
use iroha_logger::trace;

/// The ordering of the peers which defines their roles in the current round of consensus.
///
/// A  |       |              |>|                  |->|
/// B  |       |              | |                  |  V
/// C  | A Set |              ^ V  Rotate A Set    ^  |
/// D  | 2f +1 |              | |                  |  V  Rotate all
/// E  |       |              |<|                  ^  |
/// F             | B Set |                        |  V
/// G             |   f   |                        |<-|
///
/// Above is an illustration of how the various operations work for a f = 2 topology.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Topology {
    /// Current order of peers. The roles of peers are defined based on this order.
    pub(crate) sorted_peers: Vec<PeerId>,
}

impl Topology {
    /// Create a new topology.
    pub fn new(peers: impl IntoIterator<Item = PeerId>) -> Self {
        Topology {
            sorted_peers: peers.into_iter().collect(),
        }
    }
    /// Is consensus required, aka are there more than 1 peer.
    pub fn is_consensus_required(&self) -> bool {
        self.min_votes_for_commit() > 1
    }
    /// How many faulty peers can this topology tolerate.
    pub fn max_faults(&self) -> usize {
        (self.sorted_peers.len().saturating_sub(1)) / 3
    }
    /// The required amount of votes to commit a block with this topology.
    pub fn min_votes_for_commit(&self) -> usize {
        self.max_faults() * 2 + 1
    }
    /// Filter signatures by roles in the topology.
    #[allow(clippy::comparison_chain)]
    pub fn filter_signatures_by_roles<'a, T: 'a, I: IntoIterator<Item = &'a SignatureOf<T>>>(
        &self,
        roles: &[Role],
        signatures: I,
    ) -> Vec<SignatureOf<T>> {
        let mut public_keys = Vec::new();
        for role in roles {
            let role_public_keys = match (role, self.max_faults()) {
                (Role::Leader, _) => vec![self.sorted_peers[0].public_key.clone()],
                (Role::ValidatingPeer, 0) => {
                    if self.sorted_peers.len() > 2 {
                        vec![self.sorted_peers[1].public_key.clone()]
                    } else {
                        vec![]
                    }
                }
                (Role::ProxyTail, 0) => {
                    if self.sorted_peers.len() == 2 {
                        vec![self.sorted_peers[1].public_key.clone()]
                    } else if self.sorted_peers.len() > 2 {
                        vec![self.sorted_peers[2].public_key.clone()]
                    } else {
                        vec![]
                    }
                }
                (Role::ObservingPeer, 0) => {
                    if self.sorted_peers.len() == 4 {
                        vec![self.sorted_peers[3].public_key.clone()]
                    } else {
                        vec![]
                    }
                }
                (Role::ValidatingPeer, _) => self.sorted_peers
                    [1..(self.min_votes_for_commit() - 1)]
                    .iter()
                    .map(|peer_id| peer_id.public_key.clone())
                    .collect(),
                (Role::ProxyTail, _) => vec![self.sorted_peers[self.min_votes_for_commit() - 1]
                    .public_key
                    .clone()],
                (Role::ObservingPeer, _) => self.sorted_peers[self.min_votes_for_commit()..]
                    .iter()
                    .map(|peer_id| peer_id.public_key.clone())
                    .collect(),
            };
            public_keys.extend(role_public_keys);
        }
        signatures
            .into_iter()
            .filter(|signature| public_keys.contains(signature.public_key()))
            .cloned()
            .collect()
    }
    /// What role does this peer have in the topology. If it is not in the toplogy
    /// the function will return `Role::ObservingPeer`.
    // This lint is a bad suggestion.
    #[allow(clippy::option_if_let_else)]
    pub fn role(&self, peer_id: &PeerId) -> Role {
        match self.sorted_peers.iter().position(|p| p == peer_id) {
            Some(index) if index == 0 => Role::Leader,
            Some(index) if index < self.min_votes_for_commit() => Role::ValidatingPeer,
            Some(index) if index == self.min_votes_for_commit() => Role::ProxyTail,
            Some(_) => Role::ObservingPeer,
            None => {
                trace!(%peer_id, "Peer is not in topology.");
                Role::ObservingPeer
            }
        }
    }
    /// Get leader's peer id.
    pub fn leader(&self) -> &PeerId {
        &self.sorted_peers[0]
    }
    /// Get proxy tail's peer id.
    pub fn proxy_tail(&self) -> &PeerId {
        &self.sorted_peers[self.min_votes_for_commit()]
    }
    /// Add or remove peers from the topology.
    pub fn update_peer_list(&mut self, new_peer_list: &[PeerId]) {
        let mut i = 0;
        while i < self.sorted_peers.len() {
            if new_peer_list.iter().any(|p| p == &self.sorted_peers[i]) {
                i += 1;
            } else {
                self.sorted_peers.remove(i);
            }
        }
        self.sorted_peers.extend(
            new_peer_list
                .iter()
                .filter(|p| !self.sorted_peers.contains(p))
                .cloned()
                .collect::<Vec<PeerId>>(),
        );
    }
    /// Rotate peers after each failed attempt to create a block.
    pub fn rotate_all(&mut self) {
        self.sorted_peers.rotate_left(1);
    }
    /// Re-arrange the set of peers after each successful block commit.
    pub fn rotate_set_a(&mut self) {
        let top = self.sorted_peers.remove(0);
        self.sorted_peers.insert(
            self.min_votes_for_commit().min(self.sorted_peers.len()),
            top,
        );
    }
    /// Pull peers up in the topology to the top of the a set while preserving local order.
    pub fn lift_up_peers(&mut self, to_lift_up: &[PublicKey]) {
        let mut observing = Vec::new();
        let mut i = 0;
        while i < self.sorted_peers.len() {
            if to_lift_up.contains(&self.sorted_peers[i].public_key) {
                i += 1;
            } else {
                observing.insert(0, self.sorted_peers.remove(i)); // This has to be insert(0) and not push in order to preserve order.
            }
        }
        self.sorted_peers.extend(observing);
    }
}

/// Possible Peer's roles in consensus.
#[derive(Debug, Display, Clone, Copy, PartialOrd, Ord, Eq, PartialEq, Hash)]
pub enum Role {
    /// Leader.
    Leader,
    /// Validating Peer.
    ValidatingPeer,
    /// Observing Peer.
    ObservingPeer,
    /// Proxy Tail.
    ProxyTail,
}
