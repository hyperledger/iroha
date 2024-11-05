//! Structures formalising the peer topology (e.g. which peers have which predefined roles).

use derive_more::Display;
use indexmap::IndexSet;
#[cfg(test)]
use iroha_crypto::KeyPair;
use iroha_crypto::PublicKey;
use iroha_data_model::{block::BlockSignature, prelude::PeerId};

/// The ordering of the peers which defines their roles in the current round of consensus.
///
/// ```txt
/// A  |       |              |>|                  |->|
/// B  |       |              | |                  |  V
/// C  | A Set |              ^ V  Rotate A Set    ^  |
/// D  | 2f +1 |              | |                  |  V  Rotate all
/// E  |       |              |<|                  ^  |
/// F             | B Set |                        |  V
/// G             |   f   |                        |<-|
/// ```
///
/// Above is an illustration of how the various operations work for a f = 2 topology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Topology(
    /// Ordered set of peers
    Vec<PeerId>,
    /// Current view change index. Reset to 0 after every block commit
    usize,
);

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

impl AsRef<[PeerId]> for Topology {
    fn as_ref(&self) -> &[PeerId] {
        &self.0
    }
}

impl IntoIterator for Topology {
    type Item = PeerId;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl Topology {
    /// Create a new topology.
    pub fn new(peers: impl IntoIterator<Item = PeerId>) -> Self {
        let topology = peers.into_iter().collect::<IndexSet<_>>();

        assert!(
            !topology.is_empty(),
            "Topology must contain at least one peer"
        );

        Topology(topology.into_iter().collect(), 0)
    }

    pub(crate) fn position(&self, peer: &PublicKey) -> Option<usize> {
        self.0.iter().position(|p| p.public_key() == peer)
    }

    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = &PeerId> {
        self.0.iter()
    }

    /// Some, if the topology contains at least one peer and thus requires consensus
    pub fn as_non_empty(&self) -> Option<NonEmptyTopology> {
        (!self.0.is_empty()).then_some(NonEmptyTopology { topology: self })
    }

    /// Is consensus required, aka are there more than 1 peer.
    pub fn is_consensus_required(&self) -> Option<ConsensusTopology> {
        (self.0.len() > 1).then_some(ConsensusTopology { topology: self })
    }

    /// How many faulty peers can this topology tolerate.
    pub fn max_faults(&self) -> usize {
        (self.0.len().saturating_sub(1)) / 3
    }

    /// The required amount of votes to commit a block with this topology.
    pub fn min_votes_for_commit(&self) -> usize {
        let len = self.0.len();

        if len > 3 {
            self.max_faults() * 2 + 1
        } else {
            len
        }
    }

    /// Index of leader
    #[allow(clippy::unused_self)] // In order to be consistent with `proxy_tail_index` method
    pub const fn leader_index(&self) -> usize {
        0
    }

    /// Index of proxy tail
    pub fn proxy_tail_index(&self) -> usize {
        // NOTE: last element of set A
        self.min_votes_for_commit() - 1
    }

    /// Index of leader
    pub fn leader(&self) -> &PeerId {
        &self.0[self.leader_index()]
    }

    /// Index of leader
    pub fn proxy_tail(&self) -> &PeerId {
        &self.0[self.proxy_tail_index()]
    }

    /// Filter signatures by roles in the topology.
    pub fn filter_signatures_by_roles<'a, I: IntoIterator<Item = &'a BlockSignature>>(
        &self,
        roles: &[Role],
        signatures: I,
    ) -> impl Iterator<Item = &'a BlockSignature>
    where
        <I as IntoIterator>::IntoIter: 'a,
    {
        let mut filtered = IndexSet::new();

        for role in roles {
            match (role, self.as_non_empty(), self.is_consensus_required()) {
                (Role::Leader, Some(topology), _) => {
                    filtered.insert(topology.leader_index());
                }
                (Role::ProxyTail, _, Some(topology)) => {
                    filtered.insert(topology.proxy_tail_index());
                }
                (Role::ValidatingPeer, _, Some(topology)) => {
                    filtered.extend(topology.leader_index() + 1..topology.proxy_tail_index());
                }
                (Role::ObservingPeer, _, Some(topology)) => {
                    filtered.extend(topology.proxy_tail_index() + 1..topology.0.len());
                }
                _ => {}
            };
        }

        signatures.into_iter().filter(move |signature| {
            filtered.contains(
                &(usize::try_from(signature.0).expect("Peer index should fit into usize")),
            )
        })
    }

    /// What role does this peer have in the topology.
    pub fn role(&self, peer: &PeerId) -> Role {
        match self.position(peer.public_key()) {
            Some(x) if x == self.leader_index() => Role::Leader,
            Some(x) if x < self.proxy_tail_index() => Role::ValidatingPeer,
            Some(x) if x == self.proxy_tail_index() => Role::ProxyTail,
            Some(_) => Role::ObservingPeer,
            None => Role::Undefined,
        }
    }

    /// Add or remove peers from the topology.
    fn update_peer_list(&mut self, new_peers: impl IntoIterator<Item = PeerId>) {
        let (old_peers, new_peers): (IndexSet<_>, IndexSet<_>) = new_peers
            .into_iter()
            .partition(|peer| self.0.contains(peer));
        self.0.retain(|peer| old_peers.contains(peer));
        self.0.extend(new_peers);
    }

    /// Rotate peers n times
    pub fn nth_rotation(&mut self, n: usize) -> usize {
        assert!(n >= self.1, "View change index must monotonically increase");

        let rotations = n - self.1;
        if let Some(rem) = rotations.checked_rem(self.0.len()) {
            self.0.rotate_left(rem);
        }

        self.1 = n;
        rotations
    }

    /// Return current view change index of topology
    pub fn view_change_index(&self) -> usize {
        self.1
    }

    /// Re-arrange the set of peers after each successful block commit.
    fn rotate_set_a(&mut self) {
        let rotate_at = self.min_votes_for_commit();
        self.0[..rotate_at].rotate_left(1);
    }

    /// Rotate topology after a block has been committed
    pub fn block_committed(&mut self, new_peers: impl IntoIterator<Item = PeerId>) {
        self.rotate_set_a();
        self.update_peer_list(new_peers);
        self.1 = 0;
    }
}

impl<'topology> NonEmptyTopology<'topology> {
    /// Get leader's [`PeerId`].
    pub fn leader(&self) -> &'topology PeerId {
        &self.topology.0[self.topology.leader_index()]
    }
}

impl<'topology> ConsensusTopology<'topology> {
    /// Get proxy tail's peer id.
    pub fn proxy_tail(&self) -> &'topology PeerId {
        &self.topology.0[self.topology.proxy_tail_index()]
    }

    /// Get leader's [`PeerId`]
    pub fn leader(&self) -> &'topology PeerId {
        &self.topology.0[self.topology.leader_index()]
    }

    /// Get validating [`PeerId`]s.
    pub fn validating_peers(&self) -> &'topology [PeerId] {
        &self.0[self.leader_index() + 1..self.proxy_tail_index()]
    }

    /// Get observing [`PeerId`]s.
    pub fn observing_peers(&self) -> &'topology [PeerId] {
        &self.0[self.proxy_tail_index() + 1..]
    }

    /// Get voting [`PeerId`]s.
    pub fn voting_peers(&self) -> &'topology [PeerId] {
        &self.0[self.leader_index()..=self.proxy_tail_index()]
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

#[cfg(test)]
fn test_peers(n_peers: usize) -> Vec<PeerId> {
    (0..n_peers)
        .map(|_| PeerId::new(KeyPair::random().into_parts().0))
        .collect()
}

#[cfg(test)]
pub fn test_topology(n_peers: usize) -> Topology {
    let keys = (0..n_peers).map(|_| KeyPair::random()).collect::<Vec<_>>();
    test_topology_with_keys(&keys)
}

#[cfg(test)]
#[allow(single_use_lifetimes)] // false-positive
pub fn test_topology_with_keys<'a>(keys: impl IntoIterator<Item = &'a KeyPair>) -> Topology {
    let peers = keys
        .into_iter()
        .map(|key| PeerId::new(key.public_key().clone()));
    Topology::new(peers)
}

#[cfg(test)]
mod tests {
    use iroha_crypto::KeyPair;
    use iroha_primitives::unique_vec;

    use super::*;
    use crate::block::ValidBlock;

    fn extract_order(topology: &Topology, initial_topology: &Topology) -> Vec<usize> {
        topology
            .0
            .iter()
            .map(|peer| {
                initial_topology
                    .0
                    .iter()
                    .position(|p| p.public_key == peer.public_key)
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn rotate_set_a() {
        let mut topology = test_topology(7);
        let initial_topology = topology.clone();
        topology.rotate_set_a();
        assert_eq!(
            extract_order(&topology, &initial_topology),
            vec![1, 2, 3, 4, 0, 5, 6]
        )
    }

    #[test]
    fn update_peer_list() {
        let mut topology = test_topology(7);
        let peer0 = topology.0[0].clone();
        let peer2 = topology.0[2].clone();
        let peer5 = topology.0[5].clone();
        let peer7 = test_peers(1).remove(0);
        // New peers will be 0, 2, 5, 7
        let new_peers = unique_vec![peer5.clone(), peer0.clone(), peer2.clone(), peer7.clone()];
        topology.update_peer_list(new_peers);
        assert_eq!(topology.0, vec![peer0, peer2, peer5, peer7])
    }

    #[test]
    fn filter_by_role() {
        let key_pairs = core::iter::repeat_with(KeyPair::random)
            .take(7)
            .collect::<Vec<_>>();
        let topology = test_topology_with_keys(&key_pairs);

        let dummy_block = ValidBlock::new_dummy(key_pairs[0].private_key());
        let dummy_signature = &dummy_block.as_ref().signatures().next().unwrap().1;
        let dummy_signatures = (0..key_pairs.len())
            .map(|i| BlockSignature(i as u64, dummy_signature.clone()))
            .collect::<Vec<_>>();

        let leader_signatures = topology
            .filter_signatures_by_roles(&[Role::Leader], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(leader_signatures.len(), 1);
        assert_eq!(leader_signatures[0].0, 0);

        let proxy_tail_signatures = topology
            .filter_signatures_by_roles(&[Role::ProxyTail], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(proxy_tail_signatures.len(), 1);
        assert_eq!(proxy_tail_signatures[0].0, 4);

        let validating_peers_signatures = topology
            .filter_signatures_by_roles(&[Role::ValidatingPeer], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(validating_peers_signatures.len(), 3);
        assert!(validating_peers_signatures.iter().map(|s| s.0).eq(1..4));

        let observing_peers_signatures = topology
            .filter_signatures_by_roles(&[Role::ObservingPeer], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(observing_peers_signatures.len(), 2);
        assert!(observing_peers_signatures.iter().map(|s| s.0).eq(5..7));
    }

    #[test]
    fn filter_by_role_1() {
        let key_pairs = core::iter::repeat_with(KeyPair::random)
            .take(7)
            .collect::<Vec<_>>();
        let key_pairs_iter = key_pairs.iter().take(1);
        let topology = test_topology_with_keys(key_pairs_iter);

        let dummy_block = ValidBlock::new_dummy(key_pairs[0].private_key());
        let dummy_signature = &dummy_block.as_ref().signatures().next().unwrap().1;
        let dummy_signatures = (0..key_pairs.len())
            .map(|i| BlockSignature(i as u64, dummy_signature.clone()))
            .collect::<Vec<_>>();

        let leader_signatures = topology
            .filter_signatures_by_roles(&[Role::Leader], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(leader_signatures.len(), 1);
        assert_eq!(leader_signatures[0].0, 0);

        let mut proxy_tail_signatures =
            topology.filter_signatures_by_roles(&[Role::ProxyTail], dummy_signatures.iter());
        assert!(proxy_tail_signatures.next().is_none());

        let mut validating_peers_signatures =
            topology.filter_signatures_by_roles(&[Role::ValidatingPeer], dummy_signatures.iter());
        assert!(validating_peers_signatures.next().is_none());

        let mut observing_peers_signatures =
            topology.filter_signatures_by_roles(&[Role::ObservingPeer], dummy_signatures.iter());
        assert!(observing_peers_signatures.next().is_none());
    }

    #[test]
    fn filter_by_role_2() {
        let key_pairs = core::iter::repeat_with(KeyPair::random)
            .take(7)
            .collect::<Vec<_>>();
        let key_pairs_iter = key_pairs.iter().take(2);
        let topology = test_topology_with_keys(key_pairs_iter);

        let dummy_block = ValidBlock::new_dummy(key_pairs[0].private_key());
        let dummy_signature = &dummy_block.as_ref().signatures().next().unwrap().1;
        let dummy_signatures = (0..key_pairs.len())
            .map(|i| BlockSignature(i as u64, dummy_signature.clone()))
            .collect::<Vec<_>>();

        let leader_signatures = topology
            .filter_signatures_by_roles(&[Role::Leader], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(leader_signatures.len(), 1);
        assert_eq!(leader_signatures[0].0, 0);

        let proxy_tail_signatures = topology
            .filter_signatures_by_roles(&[Role::ProxyTail], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(proxy_tail_signatures.len(), 1);
        assert_eq!(proxy_tail_signatures[0].0, 1);

        let mut validating_peers_signatures =
            topology.filter_signatures_by_roles(&[Role::ValidatingPeer], dummy_signatures.iter());
        assert!(validating_peers_signatures.next().is_none());

        let mut observing_peers_signatures =
            topology.filter_signatures_by_roles(&[Role::ObservingPeer], dummy_signatures.iter());
        assert!(observing_peers_signatures.next().is_none());
    }

    #[test]
    fn filter_by_role_3() {
        let key_pairs = core::iter::repeat_with(KeyPair::random)
            .take(7)
            .collect::<Vec<_>>();
        let key_pairs_iter = key_pairs.iter().take(3);
        let topology = test_topology_with_keys(key_pairs_iter);

        let dummy_block = ValidBlock::new_dummy(key_pairs[0].private_key());
        let dummy_signature = &dummy_block.as_ref().signatures().next().unwrap().1;
        let dummy_signatures = (0..key_pairs.len())
            .map(|i| BlockSignature(i as u64, dummy_signature.clone()))
            .collect::<Vec<_>>();

        let leader_signatures = topology
            .filter_signatures_by_roles(&[Role::Leader], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(leader_signatures.len(), 1);
        assert_eq!(leader_signatures[0].0, 0);

        let proxy_tail_signatures = topology
            .filter_signatures_by_roles(&[Role::ProxyTail], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(proxy_tail_signatures.len(), 1);
        assert_eq!(proxy_tail_signatures[0].0, 2);

        let validating_peers_signatures = topology
            .filter_signatures_by_roles(&[Role::ValidatingPeer], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(validating_peers_signatures.len(), 1);
        assert_eq!(validating_peers_signatures[0].0, 1);

        let mut observing_peers_signatures =
            topology.filter_signatures_by_roles(&[Role::ObservingPeer], dummy_signatures.iter());
        assert!(observing_peers_signatures.next().is_none());
    }

    #[test]
    fn proxy_tail() {
        let peers = test_peers(7);
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
    #[should_panic(expected = "Topology must contain at least one peer")]
    fn topology_empty() {
        let _topology = Topology::new(Vec::new());
    }

    #[test]
    fn proxy_tail_1() {
        let topology = test_topology(1);

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
        let peers = test_peers(2);
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
        let peers = test_peers(3);
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
        let peers = test_peers(7);
        let topology = Topology::new(peers.clone());

        assert_eq!(
            topology
                .as_non_empty()
                .as_ref()
                .map(NonEmptyTopology::leader),
            Some(&peers[0])
        );
    }

    #[test]
    fn leader_1() {
        let peers = test_peers(1);
        let topology = Topology::new(peers.clone());

        assert_eq!(
            topology
                .as_non_empty()
                .as_ref()
                .map(NonEmptyTopology::leader),
            Some(&peers[0])
        );
    }

    #[test]
    fn leader_2() {
        let peers = test_peers(2);
        let topology = Topology::new(peers.clone());

        assert_eq!(
            topology
                .as_non_empty()
                .as_ref()
                .map(NonEmptyTopology::leader),
            Some(&peers[0])
        );
    }

    #[test]
    fn leader_3() {
        let peers = test_peers(3);
        let topology = Topology::new(peers.clone());

        assert_eq!(
            topology
                .as_non_empty()
                .as_ref()
                .map(NonEmptyTopology::leader),
            Some(&peers[0])
        );
    }

    #[test]
    fn validating_peers() {
        let peers = test_peers(7);
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
    fn validating_peers_1() {
        let peers = test_peers(1);
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
        let peers = test_peers(2);
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
        let peers = test_peers(3);
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
        let peers = test_peers(7);
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
    fn observing_peers_1() {
        let peers = test_peers(1);
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
        let peers = test_peers(2);
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
        let peers = test_peers(3);
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
    fn validating_peers_empty() {
        let peers = test_peers(2);
        let topology = Topology::new(peers);

        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::validating_peers),
            Some::<&[_]>(&[]),
        );
    }

    #[test]
    fn observing_peers_empty() {
        let peers = test_peers(3);
        let topology = Topology::new(peers);

        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::observing_peers),
            Some::<&[_]>(&[]),
        );
    }
}
