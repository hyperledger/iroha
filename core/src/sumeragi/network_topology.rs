//! Structures formalising the peer topology (e.g. which peers have which predefined roles).
#![allow(
    clippy::new_without_default,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic_side_effects
)]

use std::collections::HashSet;

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
    pub fn update_peer_list(&mut self, mut new_peers: HashSet<PeerId>) {
        self.sorted_peers.retain(|peer| new_peers.remove(peer));
        self.sorted_peers.extend(new_peers);
    }
    /// Rotate peers after each failed attempt to create a block.
    pub fn rotate_all(&mut self) {
        self.sorted_peers.rotate_left(1);
    }
    /// Re-arrange the set of peers after each successful block commit.
    pub fn rotate_set_a(&mut self) {
        let rotate_at = self.min_votes_for_commit().min(self.sorted_peers.len());
        self.sorted_peers[..rotate_at].rotate_left(1);
    }
    /// Pull peers up in the topology to the top of the a set while preserving local order.
    pub fn lift_up_peers(&mut self, to_lift_up: &[PublicKey]) {
        self.sorted_peers
            .sort_by_cached_key(|peer| !to_lift_up.contains(&peer.public_key));
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

#[cfg(test)]
mod tests {
    use iroha_crypto::KeyPair;

    use super::*;

    macro_rules! peers {
        ($($id:literal),+$(,)?) => {
            vec![
                $(PeerId::new($id, KeyPair::generate().expect("Failed to generate key pair").public_key())),+
            ]
        };
    }

    fn topology() -> Topology {
        let peers = peers!["A", "B", "C", "D", "E", "F", "G"];
        Topology::new(peers)
    }

    fn extract_addresses(topology: &Topology) -> Vec<&str> {
        topology
            .sorted_peers
            .iter()
            .map(|peer| peer.address.as_str())
            .collect()
    }

    #[test]
    fn rotate_all() {
        let mut topology = topology();
        topology.rotate_all();
        assert_eq!(
            extract_addresses(&topology),
            vec!["B", "C", "D", "E", "F", "G", "A"]
        )
    }

    #[test]
    fn rotate_set_a() {
        let mut topology = topology();
        topology.rotate_set_a();
        assert_eq!(
            extract_addresses(&topology),
            vec!["B", "C", "D", "E", "A", "F", "G"]
        )
    }

    #[test]
    fn lift_up_peers() {
        let mut topology = topology();
        // Will lift up "B", "C", "E", "G"
        let to_lift_up = &[
            topology.sorted_peers[1].public_key().clone(),
            topology.sorted_peers[2].public_key().clone(),
            topology.sorted_peers[4].public_key().clone(),
            topology.sorted_peers[6].public_key().clone(),
        ];
        topology.lift_up_peers(to_lift_up);
        assert_eq!(
            extract_addresses(&topology),
            vec!["B", "C", "E", "G", "A", "D", "F"]
        )
    }

    #[test]
    fn update_peer_list() {
        let mut topology = topology();
        // New peers will be "A", "C", "F", "H"
        let new_peers = {
            let mut peers = HashSet::from([
                topology.sorted_peers[0].clone(),
                topology.sorted_peers[5].clone(),
                topology.sorted_peers[2].clone(),
            ]);
            peers.extend(peers!["H"]);
            peers
        };
        topology.update_peer_list(new_peers);
        assert_eq!(extract_addresses(&topology), vec!["A", "C", "F", "H"])
    }
}
