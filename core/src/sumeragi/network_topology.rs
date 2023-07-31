//! Structures formalising the peer topology (e.g. which peers have which predefined roles).
#![allow(
    clippy::new_without_default,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic_side_effects
)]

use std::collections::HashSet;

use derive_more::Display;
use iroha_crypto::{HashOf, PublicKey, SignatureOf, SignaturesOf};
use iroha_data_model::{block::VersionedCommittedBlock, prelude::PeerId};
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
// FIXME: https://github.com/hyperledger/iroha/issues/3529 (topology for 3 or less peers)

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

    /// Index of leader among `sorted_peers`
    #[allow(clippy::unused_self)] // In order to be consistent with `proxy_tail_index` method
    fn leader_index(&self) -> usize {
        0
    }

    /// Index of leader among `sorted_peers`
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
        let mut public_keys = Vec::new();
        for role in roles {
            let role_public_keys = match (role, self.max_faults()) {
                (Role::Leader, _) => {
                    vec![self.sorted_peers[self.leader_index()].public_key.clone()]
                }
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
                    vec![]
                }
                (Role::ValidatingPeer, _) => self.sorted_peers
                    [self.leader_index() + 1..self.proxy_tail_index()]
                    .iter()
                    .map(|peer_id| peer_id.public_key.clone())
                    .collect(),
                (Role::ProxyTail, _) => vec![self.sorted_peers[self.proxy_tail_index()]
                    .public_key
                    .clone()],
                (Role::ObservingPeer, _) => self.sorted_peers[self.proxy_tail_index() + 1..]
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
    pub fn role(&self, peer_id: &PeerId) -> Role {
        match self.sorted_peers.iter().position(|p| p == peer_id) {
            Some(index) if index == self.leader_index() => Role::Leader,
            Some(index) if index < self.proxy_tail_index() => Role::ValidatingPeer,
            Some(index) if index == self.proxy_tail_index() => Role::ProxyTail,
            Some(_) => Role::ObservingPeer,
            None => {
                trace!(%peer_id, "Peer is not in topology.");
                Role::ObservingPeer
            }
        }
    }
    /// Get leader's peer id.
    ///
    /// # Panics
    /// This method will panic when called on empty topology
    pub fn leader(&self) -> &PeerId {
        &self.sorted_peers[self.leader_index()]
    }

    /// Get proxy tail's peer id.
    ///
    /// # Panics
    /// This method will panic when called on empty topology
    pub fn proxy_tail(&self) -> &PeerId {
        &self.sorted_peers[self.proxy_tail_index()]
    }

    /// Add or remove peers from the topology.
    pub fn update_peer_list(&mut self, mut new_peers: HashSet<PeerId>) {
        self.sorted_peers.retain(|peer| new_peers.remove(peer));
        self.sorted_peers.extend(new_peers);
    }

    /// Rotate peers after each failed attempt to create a block.
    pub fn rotate_all(&mut self) {
        self.rotate_all_n(1);
    }

    /// Rotate peers n times where n is a number of failed attempt to create a block.
    pub fn rotate_all_n(&mut self, n: usize) {
        let len = self.sorted_peers.len();
        if let Some(rem) = n.checked_rem(len) {
            self.sorted_peers.rotate_left(rem);
        }
    }

    /// Re-arrange the set of peers after each successful block commit.
    pub fn rotate_set_a(&mut self) {
        let rotate_at = self.min_votes_for_commit().min(self.sorted_peers.len());
        if rotate_at > 0 {
            self.sorted_peers[..rotate_at].rotate_left(1);
        }
    }

    /// Pull peers up in the topology to the top of the a set while preserving local order.
    pub fn lift_up_peers(&mut self, to_lift_up: &[PublicKey]) {
        self.sorted_peers
            .sort_by_cached_key(|peer| !to_lift_up.contains(&peer.public_key));
    }

    /// Perform sequence of actions after block committed.
    pub fn update_topology(&mut self, block_signees: &[PublicKey], new_peers: HashSet<PeerId>) {
        self.lift_up_peers(block_signees);
        self.rotate_set_a();
        self.update_peer_list(new_peers);
    }

    /// Recreate topology for given block and view change index
    pub fn recreate_topology(
        block: &VersionedCommittedBlock,
        view_change_index: usize,
        new_peers: HashSet<PeerId>,
    ) -> Self {
        let mut topology = Topology::new(block.as_v1().header().committed_with_topology.clone());
        let block_signees = block
            .signatures()
            .map(|s| s.public_key())
            .cloned()
            .collect::<Vec<PublicKey>>();

        topology.update_topology(&block_signees, new_peers);

        // Rotate all once for every view_change
        topology.rotate_all_n(view_change_index);

        topology
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
    pub fn verify_signatures<T>(
        &self,
        signatures: &mut SignaturesOf<T>,
        hash: HashOf<T>,
    ) -> Result<(), SignatureVerificationError> {
        if !self.is_consensus_required() {
            return Ok(());
        }

        let _ = signatures.retain_verified_by_hash(hash);

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
    /// The block doesn't have proxy tail signature
    ProxyTailMissing,
    /// The block doesn't have leader signature
    LeaderMissing,
}

#[cfg(test)]
mod tests {
    use iroha_crypto::{KeyPair, SignaturesOf};

    use super::*;

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
            .sorted_peers
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
            topology.sorted_peers[1].public_key().clone(),
            topology.sorted_peers[2].public_key().clone(),
            topology.sorted_peers[4].public_key().clone(),
            topology.sorted_peers[6].public_key().clone(),
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
                topology.sorted_peers[0].clone(),
                topology.sorted_peers[5].clone(),
                topology.sorted_peers[2].clone(),
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
    fn roles() {
        let peers = peers![0, 1, 2, 3, 4, 5, 6];
        let topology = Topology::new(peers.clone());
        let expected_roles = [
            Role::Leader,
            Role::ValidatingPeer,
            Role::ValidatingPeer,
            Role::ValidatingPeer,
            Role::ProxyTail,
            Role::ObservingPeer,
            Role::ObservingPeer,
        ];

        for ((i, peer), expected_role) in (0..).zip(peers).zip(expected_roles) {
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

        assert_eq!(topology.proxy_tail(), &peers[4]);
    }

    #[test]
    fn leader() {
        let peers = peers![0, 1, 2, 3, 4, 5, 6];
        let topology = Topology::new(peers.clone());

        assert_eq!(topology.leader(), &peers[0]);
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

        let dummy = "value to sign";
        let mut signatures = key_pairs
            .iter()
            .map(|key_pair| SignatureOf::new(key_pair.clone(), &dummy).expect("Failed to sign"))
            .collect::<Result<SignaturesOf<_>, _>>()
            .expect("Failed to create `SignaturesOf`");

        assert_eq!(
            topology.verify_signatures(&mut signatures, HashOf::new(&dummy)),
            Ok(())
        );
    }

    #[test]
    fn signature_verification_consensus_not_required_ok() {
        let key_pairs =
            core::iter::repeat_with(|| KeyPair::generate().expect("Failed to generate key pair"))
                .take(3)
                .collect::<Vec<_>>();
        let mut key_pairs_iter = key_pairs.iter();
        let peers = peers![0, 1, 2: key_pairs_iter];
        let topology = Topology::new(peers);

        let dummy = "value to sign";
        let mut signatures = key_pairs
            .iter()
            .enumerate()
            .filter(|(i, _)| *i == 2) // Retain only last signature
            .map(|(_, key_pair)| SignatureOf::new(key_pair.clone(), &dummy).expect("Failed to sign"))
            .collect::<Result<SignaturesOf<_>, _>>()
            .expect("Failed to create `SignaturesOf`");

        let result = topology.verify_signatures(&mut signatures, HashOf::new(&dummy));
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

        let dummy = "value to sign";
        let mut signatures = SignatureOf::new(key_pairs[0].clone(), &dummy)
            .expect("Failed to sign")
            .into();

        let result = topology.verify_signatures(&mut signatures, HashOf::new(&dummy));
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

        let dummy = "value to sign";
        let mut signatures = key_pairs
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 0) // Skip leader
            .map(|(_, key_pair)| SignatureOf::new(key_pair.clone(), &dummy).expect("Failed to sign"))
            .collect::<Result<SignaturesOf<_>, _>>()
            .expect("Failed to create `SignaturesOf`");

        let result = topology.verify_signatures(&mut signatures, HashOf::new(&dummy));
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

        let dummy = "value to sign";
        let mut signatures = key_pairs
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 4) // Skip proxy tail
            .map(|(_, key_pair)| SignatureOf::new(key_pair.clone(), &dummy).expect("Failed to sign"))
            .collect::<Result<SignaturesOf<_>, _>>()
            .expect("Failed to create `SignaturesOf`");

        let result = topology.verify_signatures(&mut signatures, HashOf::new(&dummy));
        assert_eq!(result, Err(SignatureVerificationError::ProxyTailMissing))
    }
}
