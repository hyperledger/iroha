//! Structures formalising the peer topology (e.g. which peers have which predefined roles).
#![allow(
    clippy::new_without_default,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic
)]
use std::{collections::HashSet, iter};

use eyre::{eyre, Context, Result};
use iroha_crypto::{Hash, HashOf, SignatureOf};
use iroha_data_model::{prelude::PeerId, transaction::VersionedSignedTransaction};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use serde::Serialize;

use crate::{
    block::{EmptyChainHash, VersionedCommittedBlock, VersionedValidBlock},
    WorldStateView,
};

/// Sorts peers based on the `hash`.
pub fn sort_peers_by_hash(
    peers: Vec<PeerId>,
    hash: &HashOf<VersionedCommittedBlock>,
) -> Vec<PeerId> {
    sort_peers_by_hash_and_counter(peers, hash, 0)
}

/// Sorts peers based on the `hash` and `counter` combined as a seed.
fn sort_peers_by_hash_and_counter(
    mut peers: Vec<PeerId>,
    hash: &HashOf<VersionedCommittedBlock>,
    counter: u64,
) -> Vec<PeerId> {
    peers.sort_by(|p1, p2| p1.address.cmp(&p2.address));
    let mut bytes: Vec<u8> = counter.to_le_bytes().to_vec();
    bytes.extend(hash.as_ref());
    let bytes = Hash::new(&bytes).into();
    let mut rng = StdRng::from_seed(bytes);
    peers.shuffle(&mut rng);
    peers
}

/// Shifts `sorted_peers` by one to the right.
#[allow(clippy::expect_used)]
pub fn shift_peers_by_one(mut peers: Vec<PeerId>) -> Vec<PeerId> {
    let last_element = peers.pop().expect("No elements found in sorted peers.");
    peers.insert(0, last_element);
    peers
}

/// Shifts `sorted_peers` by `n` to the right.
pub fn shift_peers_by_n(mut peers: Vec<PeerId>, n: u64) -> Vec<PeerId> {
    for _ in 0..n {
        peers = shift_peers_by_one(peers);
    }
    peers
}

macro_rules! field_is_some_or_err {
    ($s:ident.$f:ident) => {
        $s.$f.ok_or(eyre!(
            "Field with name {} should not be `None`.",
            stringify!($f)
        ))
    };
}

/// Alternative builder for genesis case.
/// Can set custom topology roles.
#[derive(Clone, Default, Debug)]
#[must_use = ".build() not used"]
pub struct GenesisBuilder {
    leader: Option<PeerId>,

    set_a: Option<HashSet<PeerId>>,

    set_b: Option<HashSet<PeerId>>,
}

impl GenesisBuilder {
    /// Constructor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Specify which peer (it does not matter if currently in set a or b) should be leader in genesis round.
    pub fn with_leader(mut self, id: PeerId) -> Self {
        self.leader = Some(id);
        self
    }

    /// Set a — validators and leader and proxy tail.
    pub fn with_set_a(mut self, peers: HashSet<PeerId>) -> Self {
        self.set_a = Some(peers);
        self
    }

    /// Set b — observing peers
    pub fn with_set_b(mut self, peers: HashSet<PeerId>) -> Self {
        self.set_b = Some(peers);
        self
    }

    /// Build and get topology.
    ///
    /// # Errors
    /// 1. Required field is omitted.
    /// 2. Could not deduce max faults.
    /// 3. Not enough peers to be Byzantine fault tolerant
    pub fn build(self) -> Result<Topology> {
        let leader = field_is_some_or_err!(self.leader)?;
        let mut set_a = field_is_some_or_err!(self.set_a)?;
        let mut set_b = field_is_some_or_err!(self.set_b)?;
        let max_faults_rem = (set_a.len() - 1) % 2;
        if max_faults_rem > 0 {
            return Err(eyre!("Could not deduce max faults. As given: 2f+1=set_a.len() We get a non integer f. f should be an integer."));
        }
        #[allow(clippy::integer_division)]
        let max_faults = (set_a.len() - 1_usize) / 2_usize;
        if set_b.len() < max_faults {
            return Err(eyre!(
                    "Not enough peers to be Byzantine fault tolerant. Expected least {} peers in `set_b`, got {}",
                    max_faults,
                    set_b.len(),
                ));
        }
        let _ = set_a.remove(&leader);
        let _ = set_b.remove(&leader);
        let sorted_peers: Vec<_> = iter::once(leader)
            .chain(set_a.into_iter())
            .chain(set_b.into_iter())
            .collect();
        Ok(Topology {
            sorted_peers,
            at_block: EmptyChainHash::default().into(),
        })
    }
}

/// Builder of [`Topology`] struct.
#[derive(Clone, Debug, Default)]
#[must_use = ".build() not used"]
pub struct Builder {
    /// Current order of peers. The roles of peers are defined based on this order.
    peers: Option<HashSet<PeerId>>,
    /// Hash of the last committed block.
    at_block: Option<HashOf<VersionedCommittedBlock>>,
}

impl Builder {
    /// Constructor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set peers that participate in consensus.
    pub fn with_peers(mut self, peers: HashSet<PeerId>) -> Self {
        self.peers = Some(peers);
        self
    }

    /// Set the latest committed block.
    pub fn at_block(mut self, block: HashOf<VersionedCommittedBlock>) -> Self {
        self.at_block = Some(block);
        self
    }

    /// Build and get topology.
    ///
    /// # Errors
    /// 1. Required field is omitted.
    /// 2. No peer exists.
    pub fn build(self, number_of_view_changes_this_round: u64) -> Result<Topology> {
        let peers = field_is_some_or_err!(self.peers)?;
        if peers.is_empty() {
            return Err(eyre!("There must be at least one peer in the network."));
        }
        let at_block = field_is_some_or_err!(self.at_block)?;
        let peers: Vec<_> = peers.into_iter().collect();
        let n_view_changes = number_of_view_changes_this_round;
        let since_last_shuffle = n_view_changes % (peers.len() as u64);
        let is_full_circle = since_last_shuffle == 0;
        let sorted_peers = if is_full_circle {
            sort_peers_by_hash_and_counter(peers, &at_block, n_view_changes)
        } else {
            let last_shuffled_at = n_view_changes - since_last_shuffle;
            let peers = sort_peers_by_hash_and_counter(peers, &at_block, last_shuffled_at);
            shift_peers_by_n(peers, since_last_shuffle)
        };
        Ok(Topology {
            sorted_peers,
            at_block,
        })
    }
}

/// The ordering of the peers which defines their roles in the current round of consensus.
#[derive(Clone, Debug, Encode, Decode, IntoSchema, Serialize)]
pub struct Topology {
    /// Current order of peers. The roles of peers are defined based on this order.
    sorted_peers: Vec<PeerId>,
    /// Hash of the last committed block.
    at_block: HashOf<VersionedCommittedBlock>,
}

impl Topology {
    /// Get Builder struct.
    pub fn builder() -> Builder {
        Builder::new()
    }

    /// Into Builder.
    pub fn into_builder(self) -> Builder {
        Builder {
            peers: Some(self.sorted_peers.into_iter().collect()),
            at_block: Some(self.at_block),
        }
    }

    /// Apply new committed block hash.
    #[allow(clippy::expect_used)]
    pub fn refresh_at_new_block(&mut self, block: HashOf<VersionedCommittedBlock>) {
        *self = self
            .clone()
            .into_builder()
            .at_block(block)
            .build(0)
            .expect("Topology was invalid.");
    }

    /// Apply a `view change`, i.e. change the topology in case there were faults in the consensus round.
    #[allow(clippy::expect_used)]
    pub fn rebuild_with_new_view_change_count(&mut self, view_change_count: u64) {
        *self = self.clone().into_builder().build(view_change_count).expect(
            "Invalid topology. At this stage the error is unrecoverable. Please restart the peer.",
        )
    }

    /// Answers if the consensus stage is required with the current number of peers.
    pub fn is_consensus_required(&self) -> bool {
        self.min_votes_for_commit() > 1
    }

    /// The minimum number of signatures needed to commit a block
    pub fn min_votes_for_commit(&self) -> usize {
        2 * self.max_faults() + 1
    }

    /// The minimum number of signatures needed to perform a view change (change leader, proxy, etc.)
    pub fn min_votes_for_view_change(&self) -> usize {
        self.max_faults() + 1
    }

    /// Peers of set A. They participate in the consensus.
    pub fn peers_set_a(&self) -> &[PeerId] {
        let n_a_peers = 2 * self.max_faults() + 1;
        &self.sorted_peers[..n_a_peers]
    }

    /// Peers of set B. The watch the consensus process.
    pub fn peers_set_b(&self) -> &[PeerId] {
        let n_a_peers = 2 * self.max_faults() + 1;
        &self.sorted_peers[n_a_peers..]
    }

    /// The leader of the current round.
    #[allow(clippy::expect_used)]
    pub fn leader(&self) -> &PeerId {
        self.peers_set_a()
            .first()
            .expect("Failed to get first peer.")
    }

    /// The proxy tail of the current round.
    #[allow(clippy::expect_used)]
    pub fn proxy_tail(&self) -> &PeerId {
        self.peers_set_a().last().expect("Failed to get last peer.")
    }

    /// The peers that validate the block in discussion this round and vote for it to be accepted by the blockchain.
    pub fn validating_peers(&self) -> &[PeerId] {
        let a_set = self.peers_set_a();
        if a_set.len() > 1 {
            &a_set[1..(a_set.len() - 1)]
        } else {
            &[]
        }
    }

    /// Get role of the peer by its id.
    pub fn role(&self, peer_id: &PeerId) -> Role {
        if self.leader() == peer_id {
            Role::Leader
        } else if self.proxy_tail() == peer_id {
            Role::ProxyTail
        } else if self.validating_peers().contains(peer_id) {
            Role::ValidatingPeer
        } else {
            Role::ObservingPeer
        }
    }

    /// Verifies that this `message` was signed by the `signature` of a peer with specified `role`.
    ///
    /// # Errors
    /// Fails if there are no such peer with this key and if signature verification fails
    pub fn verify_signature_with_role(
        &self,
        signature: &SignatureOf<VersionedSignedTransaction>,
        role: Role,
        tx: &HashOf<VersionedSignedTransaction>,
    ) -> Result<()> {
        if role
            .peers(self)
            .iter()
            .any(|peer| peer.public_key == *signature.public_key())
        {
            Ok(())
        } else {
            Err(eyre!("No {:?} with this public key exists.", role))
        }
        .and_then(|()| {
            signature
                .verify_hash(tx)
                .wrap_err("Transaction signature check failed")
        })
    }

    /// Returns signatures of the peers with the specified `roles` from all `signatures`.
    pub fn filter_signatures_by_roles<'slf>(
        &'slf self,
        roles: &'slf [Role],
        signatures: impl IntoIterator<Item = &'slf SignatureOf<VersionedValidBlock>> + 'slf,
    ) -> Vec<SignatureOf<VersionedValidBlock>> {
        let roles: HashSet<Role> = roles.iter().copied().collect();
        let public_keys: HashSet<_> = roles
            .iter()
            .flat_map(|role| role.peers(self))
            .map(|peer| peer.public_key)
            .collect();
        signatures
            .into_iter()
            .filter(|signature| public_keys.contains(signature.public_key()))
            .cloned()
            .collect()
    }

    /// Sorted peers that this topology has.
    pub fn sorted_peers(&self) -> &[PeerId] {
        &self.sorted_peers
    }

    /// Block hash on which this topology is based.
    pub const fn at_block(&self) -> &HashOf<VersionedCommittedBlock> {
        &self.at_block
    }

    /// Maximum number of faulty peers that the network will tolerate.
    #[allow(clippy::integer_division)]
    pub fn max_faults(&self) -> usize {
        (self.sorted_peers.len() - 1) / 3
    }

    /// Updates network topology by taking the actual list of peers from `WorldStateView`.
    /// Updates it only if there is a change in WSV peers, otherwise leaves the order unchanged.
    #[allow(clippy::expect_used)]
    pub fn update_network_topology(&mut self, wsv: &WorldStateView) {
        let wsv_peers: HashSet<_> = wsv
            .trusted_peers_ids()
            .iter()
            .map(|id_ref| id_ref.clone())
            .collect();
        let topology_peers: HashSet<_> = self.sorted_peers().iter().cloned().collect();
        if topology_peers != wsv_peers {
            *self = self
                    .clone()
                    .into_builder()
                    .with_peers(wsv_peers)
                    .build(0)
                .expect("The safety of changing the number of peers should have been checked at the Instruction execution stage.");
        }
    }
}

/// Possible Peer's roles in consensus.
#[derive(Copy, Clone, Debug, Hash, PartialOrd, Ord, Eq, PartialEq)]
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

impl Role {
    /// Returns peers that have this `Role` in this voting round.
    pub fn peers(self, network_topology: &Topology) -> Vec<PeerId> {
        match self {
            Role::Leader => vec![network_topology.leader().clone()],
            Role::ValidatingPeer => network_topology.validating_peers().to_vec(),
            Role::ObservingPeer => network_topology.peers_set_b().to_vec(),
            Role::ProxyTail => vec![network_topology.proxy_tail().clone()],
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use iroha_crypto::KeyPair;

    use super::*;

    #[test]
    #[should_panic]
    fn wrong_number_of_peers_genesis() {
        let peer_1: PeerId = PeerId {
            address: "127.0.0.1".to_owned(),
            public_key: KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key()
                .clone(),
        };
        let peer_2: PeerId = PeerId {
            address: "127.0.0.2".to_owned(),
            public_key: KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key()
                .clone(),
        };
        let peer_3: PeerId = PeerId {
            address: "127.0.0.3".to_owned(),
            public_key: KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key()
                .clone(),
        };
        // set_a.len() = 2, is wrong as it is not possible to get integer f in: 2f + 1 = 2
        let set_a: HashSet<_> = vec![peer_1.clone(), peer_2].into_iter().collect();
        let set_b = vec![peer_3].into_iter().collect();
        let _network_topology = GenesisBuilder::new()
            .with_leader(peer_1)
            .with_set_a(set_a)
            .with_set_b(set_b)
            .build()
            .expect("Failed to create topology.");
    }

    #[test]
    fn correct_number_of_peers_genesis() {
        let peers = topology_test_peers();
        // set_a.len() = 2, is wrong as it is not possible to get integer f in: 2f + 1 = 2
        let set_a: HashSet<_> = topology_test_peers().iter().take(3).cloned().collect();
        let set_b: HashSet<_> = topology_test_peers().iter().skip(3).cloned().collect();
        let _network_topology = GenesisBuilder::new()
            .with_leader(peers.iter().next().unwrap().clone())
            .with_set_a(set_a)
            .with_set_b(set_b)
            .build()
            .expect("Failed to create topology.");
    }

    #[allow(clippy::expect_used)]
    fn topology_test_peers() -> HashSet<PeerId> {
        vec![
            PeerId {
                address: "127.0.0.1:7878".to_owned(),
                public_key: KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key()
                    .clone(),
            },
            PeerId {
                address: "127.0.0.1:7879".to_owned(),
                public_key: KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key()
                    .clone(),
            },
            PeerId {
                address: "127.0.0.1:7880".to_owned(),
                public_key: KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key()
                    .clone(),
            },
            PeerId {
                address: "127.0.0.1:7881".to_owned(),
                public_key: KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key()
                    .clone(),
            },
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn different_order() {
        let hash1 = Hash::prehashed([1_u8; Hash::LENGTH]).typed();
        let hash2 = Hash::prehashed([2_u8; Hash::LENGTH]).typed();

        let peers: Vec<_> = topology_test_peers().into_iter().collect();
        let peers_1 = sort_peers_by_hash(peers.clone(), &hash1);
        let peers_2 = sort_peers_by_hash(peers, &hash2);
        assert_ne!(peers_1, peers_2);
    }

    #[test]
    fn same_order() {
        let hash = Hash::prehashed([2_u8; Hash::LENGTH]).typed();

        let peers: Vec<_> = topology_test_peers().into_iter().collect();
        let peers_1 = sort_peers_by_hash(peers.clone(), &hash);
        let peers_2 = sort_peers_by_hash(peers, &hash);
        assert_eq!(peers_1, peers_2);
    }

    #[test]
    fn same_order_by_hash_and_counter() {
        let hash = Hash::prehashed([2_u8; Hash::LENGTH]).typed();

        let peers: Vec<_> = topology_test_peers().into_iter().collect();
        let peers_1 = sort_peers_by_hash_and_counter(peers.clone(), &hash, 1);
        let peers_2 = sort_peers_by_hash_and_counter(peers, &hash, 1);
        assert_eq!(peers_1, peers_2);
    }

    #[test]
    fn different_order_by_hash_and_counter() {
        let hash = Hash::prehashed([2_u8; Hash::LENGTH]).typed();

        let peers: Vec<_> = topology_test_peers().into_iter().collect();
        let peers_1 = sort_peers_by_hash_and_counter(peers.clone(), &hash, 1);
        let peers_2 = sort_peers_by_hash_and_counter(peers, &hash, 2);
        assert_ne!(peers_1, peers_2);
    }

    #[test]
    fn topology_shifts_or_shuffles() -> Result<()> {
        let peers = topology_test_peers();
        let n_peers = peers.len() as u64;
        let mut number_of_view_changes: u64 = 0;
        let mut last_topology = Builder::new()
            .with_peers(peers)
            .at_block(Hash::zeroed().typed())
            .build(number_of_view_changes)?;
        for _a_view_change in 0..2 * n_peers {
            let mut topology = last_topology.clone();
            // When
            last_topology.sorted_peers.rotate_right(1);
            number_of_view_changes += 1;
            topology.rebuild_with_new_view_change_count(number_of_view_changes);
            // Then
            let is_shifted_by_one = last_topology.sorted_peers == topology.sorted_peers;
            let nth_view_change = number_of_view_changes;
            let is_full_circle = nth_view_change % n_peers == 0;
            if is_full_circle {
                // `topology` should have shuffled
                if is_shifted_by_one {
                    return Err(eyre!(
                        "At {nth_view_change}: shifted by one despite full circle"
                    ));
                }
            } else {
                // `topology` should have shifted by one
                if !is_shifted_by_one {
                    return Err(eyre!(
                        "At {nth_view_change}: not shifted by one despite incomplete circle"
                    ));
                }
            }
            last_topology = topology;
        }
        Ok(())
    }
}
