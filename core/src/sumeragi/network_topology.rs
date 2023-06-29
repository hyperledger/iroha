//! Structures formalising the peer topology (e.g. which peers have which predefined roles).
#![allow(
    clippy::new_without_default,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic_side_effects
)]

use std::collections::HashSet;

use derive_more::Display;
use iroha_crypto::{PublicKey, SignatureOf, SignaturesOf};
use iroha_data_model::{block::BlockPayload, prelude::PeerId};
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
    pub(crate) ordered_peers: Vec<PeerId>,
}

/// Topology with at least one peer
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Deref)]
pub struct NonEmptyTopology<'topology> {
    topology: &'topology Topology,
}

/// Topology which requires consensus (more than one peer)
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Deref)]
pub struct ConsensusTopology<'topology> {
    topology: &'topology Topology,
}

impl Topology {
    /// Create a new topology.
    pub fn new(peers: impl IntoIterator<Item = PeerId>) -> Self {
        Topology {
            ordered_peers: peers.into_iter().collect(),
        }
    }

    /// True, if the topology contains at least one peer and thus requires consensus
    pub fn is_non_empty(&self) -> Option<NonEmptyTopology> {
        (!self.ordered_peers.is_empty()).then_some(NonEmptyTopology { topology: self })
    }

    /// Is consensus required, aka are there more than 1 peer.
    pub fn is_consensus_required(&self) -> Option<ConsensusTopology> {
        (self.ordered_peers.len() > 1).then_some(ConsensusTopology { topology: self })
    }

    /// How many faulty peers can this topology tolerate.
    pub fn max_faults(&self) -> usize {
        (self.ordered_peers.len().saturating_sub(1)) / 3
    }

    /// The required amount of votes to commit a block with this topology.
    pub fn min_votes_for_commit(&self) -> usize {
        let len = self.ordered_peers.len();
        if len > 3 {
            self.max_faults() * 2 + 1
        } else {
            len
        }
    }

    /// Index of leader among `ordered_peers`
    #[allow(clippy::unused_self)] // In order to be consistent with `proxy_tail_index` method
    fn leader_index(&self) -> usize {
        0
    }

    /// Index of leader among `ordered_peers`
    fn proxy_tail_index(&self) -> usize {
        // NOTE: proxy tail is the last element from the set A so that's why it's `min_votes_for_commit - 1`
        self.min_votes_for_commit() - 1
    }

    /// Filter signatures by roles in the topology.
    #[allow(clippy::comparison_chain)]
    pub fn filter_signatures_by_roles<'a, T: 'a, I: IntoIterator<Item = &'a SignatureOf<T>>>(
        &self,
        roles: &[Role],
        signatures: I,
    ) -> Vec<SignatureOf<T>> {
        let mut public_keys: HashSet<&PublicKey> = HashSet::with_capacity(self.ordered_peers.len());
        for role in roles {
            match (role, self.is_non_empty(), self.is_consensus_required()) {
                (Role::Leader, Some(topology), _) => {
                    public_keys.insert(&topology.leader().public_key);
                }
                (Role::ProxyTail, _, Some(topology)) => {
                    public_keys.insert(&topology.proxy_tail().public_key);
                }
                (Role::ValidatingPeer, _, Some(topology)) => {
                    for peer in topology.validating_peers() {
                        public_keys.insert(&peer.public_key);
                    }
                }
                (Role::ObservingPeer, _, Some(topology)) => {
                    for peer in topology.observing_peers() {
                        public_keys.insert(&peer.public_key);
                    }
                }
                _ => {}
            };
        }
        signatures
            .into_iter()
            .filter(|signature| public_keys.contains(signature.public_key()))
            .cloned()
            .collect()
    }

    /// What role does this peer have in the topology.
    pub fn role(&self, peer_id: &PeerId) -> Role {
        match self.ordered_peers.iter().position(|p| p == peer_id) {
            Some(index) if index == self.leader_index() => Role::Leader,
            Some(index) if index < self.proxy_tail_index() => Role::ValidatingPeer,
            Some(index) if index == self.proxy_tail_index() => Role::ProxyTail,
            Some(_) => Role::ObservingPeer,
            None => {
                trace!(%peer_id, "Peer is not in topology.");
                Role::Undefined
            }
        }
    }

    /// Add or remove peers from the topology.
    pub fn update_peer_list(&mut self, mut new_peers: HashSet<PeerId>) {
        self.ordered_peers.retain(|peer| new_peers.remove(peer));
        self.ordered_peers.extend(new_peers);
    }

    /// Rotate peers after each failed attempt to create a block.
    pub fn rotate_all(&mut self) {
        self.rotate_all_n(1);
    }

    /// Rotate peers n times where n is a number of failed attempt to create a block.
    pub fn rotate_all_n(&mut self, n: usize) {
        let len = self.ordered_peers.len();
        if let Some(rem) = n.checked_rem(len) {
            self.ordered_peers.rotate_left(rem);
        }
    }

    /// Re-arrange the set of peers after each successful block commit.
    pub fn rotate_set_a(&mut self) {
        let rotate_at = self.min_votes_for_commit();
        if rotate_at > 0 {
            self.ordered_peers[..rotate_at].rotate_left(1);
        }
    }

    /// Pull peers up in the topology to the top of the a set while preserving local order.
    pub fn lift_up_peers(&mut self, to_lift_up: &[PublicKey]) {
        self.ordered_peers
            .sort_by_cached_key(|peer| !to_lift_up.contains(&peer.public_key));
    }

    /// Perform sequence of actions after block committed.
    pub fn update_topology(&mut self, block_signees: &[PublicKey], new_peers: HashSet<PeerId>) {
        self.lift_up_peers(block_signees);
        self.rotate_set_a();
        self.update_peer_list(new_peers);
    }

    /// Check if block's signatures meet requirements for given topology.
    ///
    /// In order for block to be considered valid there should be at least $2f + 1$ signatures (including proxy tail and leader signature) where f is maximum number of faulty nodes.
    /// For further information please refer to the [whitepaper](docs/source/iroha_2_whitepaper.md) section 2.8 consensus.
    ///
    /// # Errors
    /// - Not enough signatures
    /// - Missing proxy tail signature
    /// - Missing leader signature
    pub fn verify_signatures(
        &self,
        signatures: &SignaturesOf<BlockPayload>,
    ) -> Result<(), SignatureVerificationError> {
        if self.is_consensus_required().is_none() {
            return Ok(());
        }

        let votes_count = self
            .filter_signatures_by_roles(
                &[
                    Role::ValidatingPeer,
                    Role::Leader,
                    Role::ProxyTail,
                    Role::ObservingPeer,
                ],
                signatures.iter(),
            )
            .len();
        let min_votes_for_commit = self.min_votes_for_commit();
        if votes_count < min_votes_for_commit {
            return Err(SignatureVerificationError::NotEnoughSignatures {
                votes_count,
                min_votes_for_commit,
            });
        }

        if self
            .filter_signatures_by_roles(&[Role::Leader], signatures.iter())
            .is_empty()
        {
            return Err(SignatureVerificationError::LeaderMissing);
        }

        if self
            .filter_signatures_by_roles(&[Role::ProxyTail], signatures.iter())
            .is_empty()
        {
            return Err(SignatureVerificationError::ProxyTailMissing);
        }

        Ok(())
    }
}

impl<'topology> NonEmptyTopology<'topology> {
    /// Get leader's [`PeerId`].
    pub fn leader(&self) -> &'topology PeerId {
        &self.topology.ordered_peers[self.topology.leader_index()]
    }
}

impl<'topology> ConsensusTopology<'topology> {
    /// Get proxy tail's peer id.
    pub fn proxy_tail(&self) -> &'topology PeerId {
        &self.topology.ordered_peers[self.topology.proxy_tail_index()]
    }

    /// Get leader's [`PeerId`]
    pub fn leader(&self) -> &'topology PeerId {
        &self.topology.ordered_peers[self.topology.leader_index()]
    }

    /// Get validating [`PeerId`]s.
    pub fn validating_peers(&self) -> &'topology [PeerId] {
        &self.ordered_peers[self.leader_index() + 1..self.proxy_tail_index()]
    }

    /// Get observing [`PeerId`]s.
    pub fn observing_peers(&self) -> &'topology [PeerId] {
        &self.ordered_peers[self.proxy_tail_index() + 1..]
    }

    /// Get voting [`PeerId`]s.
    pub fn voting_peers(&self) -> &'topology [PeerId] {
        &self.ordered_peers[self.leader_index()..=self.proxy_tail_index()]
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
    /// Undefined. Not part of the topology
    Undefined,
}

/// Error during signature verification
#[derive(thiserror::Error, displaydoc::Display, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureVerificationError {
    /// The block doesn't have enough valid signatures to be committed ({votes_count} out of {min_votes_for_commit})
    NotEnoughSignatures {
        /// Current number of signatures
        votes_count: usize,
        /// Minimal required number of signatures
        min_votes_for_commit: usize,
    },
    /// The block doesn't contain an expected signature. Expected signature can be leader or the current peer
    SignatureMissing,
    /// Found signature that does not correspond to block payload
    UnknownSignature,
    /// The block doesn't have proxy tail signature
    ProxyTailMissing,
    /// The block doesn't have leader signature
    LeaderMissing,
}

#[cfg(test)]
mod tests {
    use iroha_crypto::KeyPair;

    use super::*;
    use crate::block::ValidBlock;

    macro_rules! peers {
        ($($id:literal),+$(,)?) => {{
            let mut iter = core::iter::repeat_with(|| KeyPair::generate().expect("Failed to generate key pair"));
            peers![$($id),*: iter]
        }};
        ($($id:literal),+$(,)?: $key_pair_iter:expr) => {
            vec![
                $(PeerId::new(&(([0, 0, 0, 0], $id).into()), $key_pair_iter.next().expect("Not enough key pairs").public_key())),+
            ]
        };
    }

    fn topology() -> Topology {
        let peers = peers![0, 1, 2, 3, 4, 5, 6];
        Topology::new(peers)
    }

    fn extract_ports(topology: &Topology) -> Vec<u16> {
        topology
            .ordered_peers
            .iter()
            .map(|peer| peer.address.port())
            .collect()
    }

    #[test]
    fn rotate_all() {
        let mut topology = topology();
        topology.rotate_all();
        assert_eq!(extract_ports(&topology), vec![1, 2, 3, 4, 5, 6, 0])
    }

    #[test]
    fn rotate_set_a() {
        let mut topology = topology();
        topology.rotate_set_a();
        assert_eq!(extract_ports(&topology), vec![1, 2, 3, 4, 0, 5, 6])
    }

    #[test]
    fn lift_up_peers() {
        let mut topology = topology();
        // Will lift up 1, 2, 4, 6
        let to_lift_up = &[
            topology.ordered_peers[1].public_key().clone(),
            topology.ordered_peers[2].public_key().clone(),
            topology.ordered_peers[4].public_key().clone(),
            topology.ordered_peers[6].public_key().clone(),
        ];
        topology.lift_up_peers(to_lift_up);
        assert_eq!(extract_ports(&topology), vec![1, 2, 4, 6, 0, 3, 5])
    }

    #[test]
    fn update_peer_list() {
        let mut topology = topology();
        // New peers will be 0, 2, 5, 7
        let new_peers = {
            let mut peers = HashSet::from([
                topology.ordered_peers[0].clone(),
                topology.ordered_peers[5].clone(),
                topology.ordered_peers[2].clone(),
            ]);
            peers.extend(peers![7]);
            peers
        };
        topology.update_peer_list(new_peers);
        assert_eq!(extract_ports(&topology), vec![0, 2, 5, 7])
    }

    #[test]
    fn filter_by_role() {
        let key_pairs =
            core::iter::repeat_with(|| KeyPair::generate().expect("Failed to generate key pair"))
                .take(7)
                .collect::<Vec<_>>();
        let mut key_pairs_iter = key_pairs.iter();
        let peers = peers![0, 1, 2, 3, 4, 5, 6: key_pairs_iter];
        let topology = Topology::new(peers.clone());

        let dummy = "value to sign";
        let signatures = key_pairs
            .iter()
            .map(|key_pair| SignatureOf::new(key_pair.clone(), &dummy).expect("Failed to sign"))
            .collect::<Vec<SignatureOf<_>>>();

        let leader_signatures =
            topology.filter_signatures_by_roles(&[Role::Leader], signatures.iter());
        assert_eq!(leader_signatures.len(), 1);
        assert_eq!(leader_signatures[0].public_key(), peers[0].public_key());

        let proxy_tail_signatures =
            topology.filter_signatures_by_roles(&[Role::ProxyTail], signatures.iter());
        assert_eq!(proxy_tail_signatures.len(), 1);
        assert_eq!(proxy_tail_signatures[0].public_key(), peers[4].public_key());

        let validating_peers_signatures =
            topology.filter_signatures_by_roles(&[Role::ValidatingPeer], signatures.iter());
        assert_eq!(validating_peers_signatures.len(), 3);
        assert!(validating_peers_signatures
            .iter()
            .map(|s| s.public_key())
            .eq(peers[1..4].iter().map(PeerId::public_key)));

        let observing_peers_signatures =
            topology.filter_signatures_by_roles(&[Role::ObservingPeer], signatures.iter());
        assert_eq!(observing_peers_signatures.len(), 2);
        assert!(observing_peers_signatures
            .iter()
            .map(|s| s.public_key())
            .eq(peers[5..].iter().map(PeerId::public_key)));
    }

    #[test]
    fn filter_by_role_empty() {
        let key_pairs =
            core::iter::repeat_with(|| KeyPair::generate().expect("Failed to generate key pair"))
                .take(7)
                .collect::<Vec<_>>();
        let peers = Vec::new();
        let topology = Topology::new(peers);

        let dummy = "value to sign";
        let signatures = key_pairs
            .iter()
            .map(|key_pair| SignatureOf::new(key_pair.clone(), &dummy).expect("Failed to sign"))
            .collect::<Vec<SignatureOf<_>>>();

        let leader_signatures =
            topology.filter_signatures_by_roles(&[Role::Leader], signatures.iter());
        assert!(leader_signatures.is_empty());

        let proxy_tail_signatures =
            topology.filter_signatures_by_roles(&[Role::ProxyTail], signatures.iter());
        assert!(proxy_tail_signatures.is_empty());

        let validating_peers_signatures =
            topology.filter_signatures_by_roles(&[Role::ValidatingPeer], signatures.iter());
        assert!(validating_peers_signatures.is_empty());

        let observing_peers_signatures =
            topology.filter_signatures_by_roles(&[Role::ObservingPeer], signatures.iter());
        assert!(observing_peers_signatures.is_empty());
    }

    #[test]
    fn filter_by_role_1() {
        let key_pairs =
            core::iter::repeat_with(|| KeyPair::generate().expect("Failed to generate key pair"))
                .take(7)
                .collect::<Vec<_>>();
        let mut key_pairs_iter = key_pairs.iter();
        let peers = peers![0: key_pairs_iter];
        let topology = Topology::new(peers.clone());

        let dummy = "value to sign";
        let signatures = key_pairs
            .iter()
            .map(|key_pair| SignatureOf::new(key_pair.clone(), &dummy).expect("Failed to sign"))
            .collect::<Vec<SignatureOf<_>>>();

        let leader_signatures =
            topology.filter_signatures_by_roles(&[Role::Leader], signatures.iter());
        assert_eq!(leader_signatures.len(), 1);
        assert_eq!(leader_signatures[0].public_key(), peers[0].public_key());

        let proxy_tail_signatures =
            topology.filter_signatures_by_roles(&[Role::ProxyTail], signatures.iter());
        assert!(proxy_tail_signatures.is_empty());

        let validating_peers_signatures =
            topology.filter_signatures_by_roles(&[Role::ValidatingPeer], signatures.iter());
        assert!(validating_peers_signatures.is_empty());

        let observing_peers_signatures =
            topology.filter_signatures_by_roles(&[Role::ObservingPeer], signatures.iter());
        assert!(observing_peers_signatures.is_empty());
    }

    #[test]
    fn filter_by_role_2() {
        let key_pairs =
            core::iter::repeat_with(|| KeyPair::generate().expect("Failed to generate key pair"))
                .take(7)
                .collect::<Vec<_>>();
        let mut key_pairs_iter = key_pairs.iter();
        let peers = peers![0, 1: key_pairs_iter];
        let topology = Topology::new(peers.clone());

        let dummy = "value to sign";
        let signatures = key_pairs
            .iter()
            .map(|key_pair| SignatureOf::new(key_pair.clone(), &dummy).expect("Failed to sign"))
            .collect::<Vec<SignatureOf<_>>>();

        let leader_signatures =
            topology.filter_signatures_by_roles(&[Role::Leader], signatures.iter());
        assert_eq!(leader_signatures.len(), 1);
        assert_eq!(leader_signatures[0].public_key(), peers[0].public_key());

        let proxy_tail_signatures =
            topology.filter_signatures_by_roles(&[Role::ProxyTail], signatures.iter());
        assert_eq!(proxy_tail_signatures.len(), 1);
        assert_eq!(proxy_tail_signatures[0].public_key(), peers[1].public_key());

        let validating_peers_signatures =
            topology.filter_signatures_by_roles(&[Role::ValidatingPeer], signatures.iter());
        assert!(validating_peers_signatures.is_empty());

        let observing_peers_signatures =
            topology.filter_signatures_by_roles(&[Role::ObservingPeer], signatures.iter());
        assert!(observing_peers_signatures.is_empty());
    }

    #[test]
    fn filter_by_role_3() {
        let key_pairs =
            core::iter::repeat_with(|| KeyPair::generate().expect("Failed to generate key pair"))
                .take(7)
                .collect::<Vec<_>>();
        let mut key_pairs_iter = key_pairs.iter();
        let peers = peers![0, 1, 2: key_pairs_iter];
        let topology = Topology::new(peers.clone());

        let dummy = "value to sign";
        let signatures = key_pairs
            .iter()
            .map(|key_pair| SignatureOf::new(key_pair.clone(), &dummy).expect("Failed to sign"))
            .collect::<Vec<SignatureOf<_>>>();

        let leader_signatures =
            topology.filter_signatures_by_roles(&[Role::Leader], signatures.iter());
        assert_eq!(leader_signatures.len(), 1);
        assert_eq!(leader_signatures[0].public_key(), peers[0].public_key());

        let proxy_tail_signatures =
            topology.filter_signatures_by_roles(&[Role::ProxyTail], signatures.iter());
        assert_eq!(proxy_tail_signatures.len(), 1);
        assert_eq!(proxy_tail_signatures[0].public_key(), peers[2].public_key());

        let validating_peers_signatures =
            topology.filter_signatures_by_roles(&[Role::ValidatingPeer], signatures.iter());
        assert_eq!(validating_peers_signatures.len(), 1);
        assert_eq!(
            validating_peers_signatures[0].public_key(),
            peers[1].public_key()
        );

        let observing_peers_signatures =
            topology.filter_signatures_by_roles(&[Role::ObservingPeer], signatures.iter());
        assert!(observing_peers_signatures.is_empty());
    }

    #[test]
    fn roles() {
        let peers = peers![0, 1, 2, 3, 4, 5, 6];
        let not_in_topology_peers = peers![7, 8, 9];
        let topology = Topology::new(peers.clone());
        let expected_roles = [
            Role::Leader,
            Role::ValidatingPeer,
            Role::ValidatingPeer,
            Role::ValidatingPeer,
            Role::ProxyTail,
            Role::ObservingPeer,
            Role::ObservingPeer,
            Role::Undefined,
            Role::Undefined,
            Role::Undefined,
        ];

        for ((i, peer), expected_role) in (0..)
            .zip(peers.into_iter().chain(not_in_topology_peers))
            .zip(expected_roles)
        {
            let actual_role = topology.role(&peer);
            assert_eq!(
                actual_role, expected_role,
                "Role detection failed for peer with index: {i}"
            );
        }
    }

    #[test]
    fn proxy_tail() {
        let peers = peers![0, 1, 2, 3, 4, 5, 6];
        let topology = Topology::new(peers.clone());

        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::proxy_tail),
            Some(&peers[4])
        );
    }

    #[test]
    fn proxy_tail_empty() {
        let peers = Vec::new();
        let topology = Topology::new(peers);

        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::proxy_tail),
            None,
        );
    }

    #[test]
    fn proxy_tail_1() {
        let peers = peers![0];
        let topology = Topology::new(peers);

        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::proxy_tail),
            None
        );
    }

    #[test]
    fn proxy_tail_2() {
        let peers = peers![0, 1];
        let topology = Topology::new(peers.clone());

        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::proxy_tail),
            Some(&peers[1])
        );
    }

    #[test]
    fn proxy_tail_3() {
        let peers = peers![0, 1, 2];
        let topology = Topology::new(peers.clone());

        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::proxy_tail),
            Some(&peers[2])
        );
    }

    #[test]
    fn leader() {
        let peers = peers![0, 1, 2, 3, 4, 5, 6];
        let topology = Topology::new(peers.clone());

        assert_eq!(
            topology
                .is_non_empty()
                .as_ref()
                .map(NonEmptyTopology::leader),
            Some(&peers[0])
        );
    }

    #[test]
    fn leader_empty() {
        let peers = Vec::new();
        let topology = Topology::new(peers);

        assert_eq!(
            topology
                .is_non_empty()
                .as_ref()
                .map(NonEmptyTopology::leader),
            None,
        );
    }

    #[test]
    fn leader_1() {
        let peers = peers![0];
        let topology = Topology::new(peers.clone());

        assert_eq!(
            topology
                .is_non_empty()
                .as_ref()
                .map(NonEmptyTopology::leader),
            Some(&peers[0])
        );
    }

    #[test]
    fn leader_2() {
        let peers = peers![0, 1];
        let topology = Topology::new(peers.clone());

        assert_eq!(
            topology
                .is_non_empty()
                .as_ref()
                .map(NonEmptyTopology::leader),
            Some(&peers[0])
        );
    }

    #[test]
    fn leader_3() {
        let peers = peers![0, 1, 3];
        let topology = Topology::new(peers.clone());

        assert_eq!(
            topology
                .is_non_empty()
                .as_ref()
                .map(NonEmptyTopology::leader),
            Some(&peers[0])
        );
    }

    #[test]
    fn validating_peers() {
        let peers = peers![0, 1, 2, 3, 4, 5, 6];
        let topology = Topology::new(peers.clone());

        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::validating_peers),
            Some(&peers[1..4])
        );
    }

    #[test]
    fn validating_peers_empty() {
        let peers = Vec::new();
        let topology = Topology::new(peers);

        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::validating_peers),
            None,
        );
    }

    #[test]
    fn validating_peers_1() {
        let peers = peers![0];
        let topology = Topology::new(peers);

        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::validating_peers),
            None
        );
    }

    #[test]
    fn validating_peers_2() {
        let peers = peers![0, 1];
        let topology = Topology::new(peers);

        let empty_peer_slice: &[PeerId] = &[];
        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::validating_peers),
            Some(empty_peer_slice)
        );
    }

    #[test]
    fn validating_peers_3() {
        let peers = peers![0, 1, 2];
        let topology = Topology::new(peers.clone());

        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::validating_peers),
            Some(&peers[1..2])
        );
    }

    #[test]
    fn observing_peers() {
        let peers = peers![0, 1, 2, 3, 4, 5, 6];
        let topology = Topology::new(peers.clone());

        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::observing_peers),
            Some(&peers[5..])
        );
    }

    #[test]
    fn observing_peers_empty() {
        let peers = Vec::new();
        let topology = Topology::new(peers);

        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::observing_peers),
            None,
        );
    }

    #[test]
    fn observing_peers_1() {
        let peers = peers![0];
        let topology = Topology::new(peers);

        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::validating_peers),
            None
        );
    }

    #[test]
    fn observing_peers_2() {
        let peers = peers![0, 1];
        let topology = Topology::new(peers);

        let empty_peer_slice: &[PeerId] = &[];
        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::observing_peers),
            Some(empty_peer_slice)
        );
    }

    #[test]
    fn observing_peers_3() {
        let peers = peers![0, 1, 2];
        let topology = Topology::new(peers);

        let empty_peer_slice: &[PeerId] = &[];
        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::observing_peers),
            Some(empty_peer_slice)
        );
    }

    #[test]
    fn signature_verification_ok() {
        let key_pairs =
            core::iter::repeat_with(|| KeyPair::generate().expect("Failed to generate key pair"))
                .take(7)
                .collect::<Vec<_>>();
        let mut key_pairs_iter = key_pairs.iter();
        let peers = peers![0, 1, 2, 3, 4, 5, 6: key_pairs_iter];
        let topology = Topology::new(peers);

        let dummy = ValidBlock::new_dummy();
        let signatures = key_pairs
            .iter()
            .map(|key_pair| {
                SignatureOf::new(key_pair.clone(), dummy.payload()).expect("Failed to sign")
            })
            .collect();

        assert_eq!(topology.verify_signatures(&signatures), Ok(()));
    }

    #[test]
    fn signature_verification_consensus_not_required_ok() {
        let key_pairs =
            core::iter::repeat_with(|| KeyPair::generate().expect("Failed to generate key pair"))
                .take(1)
                .collect::<Vec<_>>();
        let mut key_pairs_iter = key_pairs.iter();
        let peers = peers![0,: key_pairs_iter];
        let topology = Topology::new(peers);

        let dummy = ValidBlock::new_dummy();
        let signatures = key_pairs
            .iter()
            .enumerate()
            .map(|(_, key_pair)| {
                SignatureOf::new(key_pair.clone(), dummy.payload()).expect("Failed to sign")
            })
            .collect();

        let result = topology.verify_signatures(&signatures);
        assert_eq!(result, Ok(()))
    }

    /// Check requirement of having at least $2f + 1$ signatures in $3f + 1$ network
    #[test]
    fn signature_verification_not_enough_signatures() {
        let key_pairs =
            core::iter::repeat_with(|| KeyPair::generate().expect("Failed to generate key pair"))
                .take(7)
                .collect::<Vec<_>>();
        let mut key_pairs_iter = key_pairs.iter();
        let peers = peers![0, 1, 2, 3, 4, 5, 6: key_pairs_iter];
        let topology = Topology::new(peers);

        let dummy = ValidBlock::new_dummy();
        let signatures = SignatureOf::new(key_pairs[0].clone(), dummy.payload())
            .expect("Failed to sign")
            .into();

        let result = topology.verify_signatures(&signatures);
        assert_eq!(
            result,
            Err(SignatureVerificationError::NotEnoughSignatures {
                votes_count: 1,
                min_votes_for_commit: topology.min_votes_for_commit(),
            })
        )
    }

    /// Check requirement of having leader signature
    #[test]
    fn signature_verification_miss_leader_signature() {
        let key_pairs =
            core::iter::repeat_with(|| KeyPair::generate().expect("Failed to generate key pair"))
                .take(7)
                .collect::<Vec<_>>();
        let mut key_pairs_iter = key_pairs.iter();
        let peers = peers![0, 1, 2, 3, 4, 5, 6: key_pairs_iter];
        let topology = Topology::new(peers);

        let dummy = ValidBlock::new_dummy();
        let signatures = key_pairs
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 0) // Skip leader
            .map(|(_, key_pair)| SignatureOf::new(key_pair.clone(), dummy.payload()).expect("Failed to sign"))
            .collect();

        let result = topology.verify_signatures(&signatures);
        assert_eq!(result, Err(SignatureVerificationError::LeaderMissing))
    }

    /// Check requirement of having leader signature
    #[test]
    fn signature_verification_miss_proxy_tail_signature() {
        let key_pairs =
            core::iter::repeat_with(|| KeyPair::generate().expect("Failed to generate key pair"))
                .take(7)
                .collect::<Vec<_>>();
        let mut key_pairs_iter = key_pairs.iter();
        let peers = peers![0, 1, 2, 3, 4, 5, 6: key_pairs_iter];
        let topology = Topology::new(peers);

        let dummy = ValidBlock::new_dummy();
        let signatures = key_pairs
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 4) // Skip proxy tail
            .map(|(_, key_pair)| SignatureOf::new(key_pair.clone(), dummy.payload()).expect("Failed to sign"))
            .collect();

        let result = topology.verify_signatures(&signatures);
        assert_eq!(result, Err(SignatureVerificationError::ProxyTailMissing))
    }
}
