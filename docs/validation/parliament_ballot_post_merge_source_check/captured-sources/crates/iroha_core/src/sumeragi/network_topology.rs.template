#![allow(unexpected_cfgs, clippy::similar_names)]
//! Structures formalising the peer topology (e.g. which peers have which predefined roles).
use derive_more::Display;
use indexmap::IndexSet;
use iroha_crypto::HashOf;
#[cfg(test)]
use iroha_crypto::KeyPair;
use iroha_crypto::PublicKey;
use iroha_data_model::block::{BlockHeader, BlockSignature};
use iroha_model_base::peer::PeerId;
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
pub struct Topology(
    /// Ordered set of peers
    Vec<PeerId>,
    /// Current view change index. Reset to 0 after every block commit.
    u64,
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
    #[allow(dead_code)]
    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = &PeerId> {
        self.0.iter()
    }
    /// True, if the topology contains at least one peer and thus requires consensus
    pub fn is_non_empty(&self) -> Option<NonEmptyTopology<'_>> {
        (!self.0.is_empty()).then_some(NonEmptyTopology { topology: self })
    }
    /// Is consensus required, aka are there more than 1 peer.
    pub fn is_consensus_required(&self) -> Option<ConsensusTopology<'_>> {
        (self.0.len() > 1).then_some(ConsensusTopology { topology: self })
    }
    /// How many faulty peers can this topology tolerate.
    pub fn max_faults(&self) -> usize {
        (self.0.len().saturating_sub(1)) / 3
    }
    /// The required amount of votes to commit a block with this topology.
    pub fn min_votes_for_commit(&self) -> usize {
        iroha_sumeragi::types::quorum(self.0.len())
    }
    /// The required amount of votes to trigger a view change (f + 1).
    pub fn min_votes_for_view_change(&self) -> usize {
        let required = self.max_faults().saturating_add(1);
        required.min(self.0.len().max(1))
    }
    /// Index of leader
    #[allow(clippy::unused_self)] // In order to be consistent with `proxy_tail_index` method
    pub const fn leader_index(&self) -> usize {
        0
    }
    /// Index of proxy tail
    pub fn proxy_tail_index(&self) -> usize {
        self.min_votes_for_commit().saturating_sub(1)
    }
    /// Rotate peers so that the peer at `idx` becomes leader (index 0),
    /// preserving the current `view_change_index` counter.
    pub fn rotate_preserve_view_to_front(&mut self, idx: usize) {
        if self.0.is_empty() {
            return;
        }
        let n = self.0.len();
        let r = idx % n;
        self.0.rotate_left(r);
    }
    /// Deterministically shuffle the topology for a given `height` using the PRF seed.
    ///
    /// Callers should canonicalize the roster before shuffling to keep the
    /// permutation deterministic across nodes.
    pub fn shuffle_prf(&mut self, seed: [u8; 32], height: u64) {
        let n = self.0.len();
        if n <= 1 {
            return;
        }
        let shuffled = Self::prf_shuffled_indices(seed, height, n)
            .into_iter()
            .map(|idx| self.0[idx].clone())
            .collect();
        self.0 = shuffled;
    }
    /// PRF-based leader index for `(height, view)`.
    ///
    /// The seed selects a deterministic validator permutation per height, and
    /// views walk that permutation cyclically. This preserves deterministic
    /// leader unpredictability for the height while bounding consecutive views
    /// led by the same faulty validator.
    pub fn leader_index_prf(&self, seed: [u8; 32], height: u64, view: u64) -> usize {
        let n = self.0.len();
        if n == 0 {
            return 0;
        }
        let slot = usize::try_from(view % u64::try_from(n).expect("topology length fits u64"))
            .expect("view slot fits usize");
        Self::prf_shuffled_indices(seed, height, n)[slot]
    }
    fn shuffle_prf_slot(seed: [u8; 32], height: u64, ctr: u64, modulus: usize) -> usize {
        use iroha_crypto::blake2::{Blake2b512, Digest as _};
        debug_assert!(modulus > 0);
        let mut hasher = Blake2b512::new();
        iroha_crypto::blake2::digest::Update::update(&mut hasher, &seed);
        iroha_crypto::blake2::digest::Update::update(&mut hasher, &height.to_be_bytes());
        iroha_crypto::blake2::digest::Update::update(&mut hasher, &ctr.to_be_bytes());
        let digest = iroha_crypto::blake2::Digest::finalize(hasher);
        let mut idx_bytes = [0u8; 8];
        idx_bytes.copy_from_slice(&digest[..8]);
        let r = u64::from_be_bytes(idx_bytes);
        let modulus = u128::try_from(modulus).expect("candidate length fits u128");
        (u128::from(r) % modulus) as usize
    }
    fn prf_shuffled_indices(seed: [u8; 32], height: u64, len: usize) -> Vec<usize> {
        let mut slots: Vec<usize> = (0..len).collect();
        let mut shuffled = Vec::with_capacity(len);
        let mut ctr: u64 = 0;
        while !slots.is_empty() {
            let pos = Self::shuffle_prf_slot(seed, height, ctr, slots.len());
            shuffled.push(slots.swap_remove(pos));
            ctr = ctr.saturating_add(1);
        }
        shuffled
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
            match (role, self.is_non_empty(), self.is_consensus_required()) {
                (Role::Leader, Some(topology), _) => {
                    filtered.insert(topology.leader_index());
                }
                (Role::ProxyTail, Some(topology), None) => {
                    filtered.insert(topology.proxy_tail_index());
                }
                (Role::ProxyTail, _, Some(topology)) => {
                    filtered.insert(topology.proxy_tail_index());
                }
                (Role::ValidatingPeer, _, Some(topology)) => {
                    filtered.extend(topology.leader_index() + 1..topology.proxy_tail_index());
                }
                (Role::SetBValidator, _, Some(topology)) => {
                    filtered.extend(topology.proxy_tail_index() + 1..topology.0.len());
                }
                _ => {}
            }
        }
        signatures.into_iter().filter(move |signature| {
            usize::try_from(signature.index())
                .ok()
                .is_some_and(|idx| filtered.contains(&idx))
        })
    }
    /// What role does this peer have in the topology.
    pub fn role(&self, peer: &PeerId) -> Role {
        match self.position(peer.public_key()) {
            Some(x) if x == self.leader_index() => Role::Leader,
            Some(x) if x < self.proxy_tail_index() => Role::ValidatingPeer,
            Some(x) if x == self.proxy_tail_index() => Role::ProxyTail,
            Some(_) => Role::SetBValidator,
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
    /// Rotate peers n times.
    pub fn nth_rotation(&mut self, n: u64) -> u64 {
        assert!(n >= self.1, "View change index must monotonically increase");
        let rotations = n - self.1;
        let len = self.0.len() as u64;
        if len > 0 {
            let rem = usize::try_from(rotations % len).unwrap_or(0);
            if rem > 0 {
                self.0.rotate_left(rem);
            }
        }
        self.1 = n;
        rotations
    }
    /// Return current view change index of topology
    pub fn view_change_index(&self) -> u64 {
        self.1
    }
    /// Update topology after a block has been committed.
    ///
    /// Membership is refreshed while preserving canonical ordering for subsequent
    /// per-view role derivation.
    pub fn block_committed(
        &mut self,
        new_peers: impl IntoIterator<Item = PeerId>,
        _prev_block_hash: HashOf<BlockHeader>,
    ) {
        self.update_peer_list(new_peers);
        self.1 = 0;
    }
    /// Canonicalize the internal peer ordering without changing the view index.
    #[cfg(test)]
    pub(crate) fn canonicalize_order(&mut self) {
        if self.0.is_empty() {
            return;
        }
        self.0.sort();
        self.0.dedup();
    }
}
#[cfg(test)]
mod prf_collectors_tests {
    use super::*;
    use std::collections::BTreeSet;
    #[test]
    fn topology_new_deduplicates_peers_preserving_order() {
        let peer_a = PeerId::new(checked_keypair().public_key().clone());
        let peer_b = PeerId::new(checked_keypair().public_key().clone());
        let topology = Topology::new(vec![peer_a.clone(), peer_b.clone(), peer_a.clone()]);
        let peers = topology.as_ref();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0], peer_a);
        assert_eq!(peers[1], peer_b);
    }
    #[test]
    fn topology_mutation_formal_gate_matrix() {
        fn topology_from_ids(base: &[PeerId], ids: &[usize], view: u64) -> Topology {
            let mut topology = if ids.is_empty() {
                Topology(Vec::new(), 0)
            } else {
                Topology::new(ids.iter().map(|idx| base[*idx].clone()))
            };
            topology.1 = view;
            topology
        }
        fn ids(topology: &Topology, base: &[PeerId]) -> Vec<usize> {
            topology
                .as_ref()
                .iter()
                .map(|peer| {
                    base.iter()
                        .position(|candidate| candidate == peer)
                        .expect("peer must come from abstract base")
                })
                .collect()
        }
        fn assert_topology(
            name: &str,
            topology: &Topology,
            base: &[PeerId],
            expected_ids: &[usize],
            expected_view: u64,
        ) {
            let actual = ids(topology, base);
            assert_eq!(actual.as_slice(), expected_ids, "{name} order");
            assert_eq!(topology.view_change_index(), expected_view, "{name} view");
            let distinct: BTreeSet<_> = actual.iter().copied().collect();
            assert_eq!(distinct.len(), actual.len(), "{name} distinct");
        }
        fn prev_hash(seed: u64) -> HashOf<BlockHeader> {
            let mut seed_bytes = [0u8; iroha_crypto::Hash::LENGTH];
            seed_bytes[..8].copy_from_slice(&seed.to_be_bytes());
            HashOf::<BlockHeader>::from_untyped_unchecked(iroha_crypto::Hash::prehashed(seed_bytes))
        }
        let base = test_peers(6);
        let rotate_cases = [
            ("rotate_empty", &[][..], 0_usize, &[][..]),
            ("rotate_single_idx99", &[0][..], 99, &[0][..]),
            ("rotate_len4_idx0", &[0, 1, 2, 3][..], 0, &[0, 1, 2, 3][..]),
            ("rotate_len4_idx2", &[0, 1, 2, 3][..], 2, &[2, 3, 0, 1][..]),
            ("rotate_len4_idx6", &[0, 1, 2, 3][..], 6, &[2, 3, 0, 1][..]),
        ];
        for (name, initial, idx, expected) in rotate_cases {
            let mut topology = topology_from_ids(&base, initial, 7);
            topology.rotate_preserve_view_to_front(idx);
            assert_topology(name, &topology, &base, expected, 7);
        }
        let nth_cases = [
            ("nth_same", 4_usize, 2_u64, 2_u64, 0_u64, &[0, 1, 2, 3][..]),
            ("nth_forward_one", 4, 0, 1, 1, &[1, 2, 3, 0][..]),
            ("nth_forward_three", 4, 1, 4, 3, &[3, 0, 1, 2][..]),
            ("nth_full_cycle", 4, 0, 4, 4, &[0, 1, 2, 3][..]),
            ("nth_large_mod", 4, 0, 10, 10, &[2, 3, 0, 1][..]),
            ("nth_single_large", 1, 0, 10, 10, &[0][..]),
            ("nth_empty_forward", 0, 0, 5, 5, &[][..]),
        ];
        for (name, len, current_view, target_view, expected_delta, expected) in nth_cases {
            let initial: Vec<_> = (0..len).collect();
            let mut topology = topology_from_ids(&base, &initial, current_view);
            let rotations = topology.nth_rotation(target_view);
            assert_eq!(rotations, expected_delta, "{name} rotations");
            assert_topology(name, &topology, &base, expected, target_view);
        }
        let mut rewind_topology = topology_from_ids(&base, &[0, 1, 2, 3], 4);
        let rewind_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rewind_topology.nth_rotation(2);
        }));
        assert!(rewind_result.is_err(), "nth_rewind must reject view rewind");
        assert_topology("nth_rewind", &rewind_topology, &base, &[0, 1, 2, 3], 4);
        let new_cases = [
            ("new_dedup_preserve", &[2, 1, 2, 0][..], &[2, 1, 0][..]),
            ("new_all_duplicates", &[1, 1, 1][..], &[1][..]),
            ("new_single", &[4][..], &[4][..]),
        ];
        for (name, input, expected) in new_cases {
            let topology = Topology::new(input.iter().map(|idx| base[*idx].clone()));
            assert_topology(name, &topology, &base, expected, 0);
        }
        let update_cases = [
            (
                "update_mixed",
                &[0, 1, 3, 2][..],
                &[5, 1, 3, 4][..],
                &[1, 3, 5, 4][..],
            ),
            (
                "update_keep_all_reordered_input",
                &[0, 1, 2][..],
                &[2, 0, 1][..],
                &[0, 1, 2][..],
            ),
            (
                "update_remove_all_add_two",
                &[0, 1, 2][..],
                &[4, 5][..],
                &[4, 5][..],
            ),
            ("update_duplicates", &[1][..], &[1, 2, 2][..], &[1, 2][..]),
        ];
        for (name, initial, update, expected) in update_cases {
            let mut topology = topology_from_ids(&base, initial, 9);
            topology.update_peer_list(update.iter().map(|idx| base[*idx].clone()));
            assert_topology(name, &topology, &base, expected, 9);
        }
        let block_cases = [
            (
                "block_mixed",
                &[0, 1, 3, 2][..],
                &[5, 1, 3, 4][..],
                &[1, 3, 5, 4][..],
            ),
            (
                "block_keep_all_reordered_input",
                &[0, 1, 2][..],
                &[2, 0, 1][..],
                &[0, 1, 2][..],
            ),
            (
                "block_remove_all_add_two",
                &[0, 1, 2][..],
                &[4, 5][..],
                &[4, 5][..],
            ),
        ];
        for (name, initial, update, expected) in block_cases {
            let mut topology = topology_from_ids(&base, initial, 9);
            topology.block_committed(update.iter().map(|idx| base[*idx].clone()), prev_hash(11));
            assert_topology(name, &topology, &base, expected, 0);
        }
        let canon_cases = [
            ("canon_reverse", vec![3, 2, 1, 0], vec![0, 1, 2, 3]),
            ("canon_duplicates", vec![0, 1, 1, 2, 2], vec![0, 1, 2]),
            ("canon_empty", Vec::new(), Vec::new()),
        ];
        for (name, initial, expected) in canon_cases {
            let mut topology = if initial.is_empty() {
                Topology(Vec::new(), 8)
            } else {
                Topology(
                    initial
                        .iter()
                        .map(|idx| base[*idx].clone())
                        .collect::<Vec<_>>(),
                    8,
                )
            };
            topology.canonicalize_order();
            assert_topology(name, &topology, &base, &expected, 8);
        }
    }
    #[test]
    fn prf_leader_shuffle_formal_gate_matrix() {
        fn ids(topology: &Topology, base: &[PeerId]) -> Vec<usize> {
            topology
                .as_ref()
                .iter()
                .map(|peer| {
                    base.iter()
                        .position(|candidate| candidate == peer)
                        .expect("peer must come from abstract base")
                })
                .collect()
        }
        fn assert_permutation(name: &str, values: &[usize], len: usize) {
            assert_eq!(values.len(), len, "{name} length");
            let distinct: BTreeSet<_> = values.iter().copied().collect();
            assert_eq!(distinct.len(), values.len(), "{name} distinct");
            assert!(values.iter().all(|idx| *idx < len), "{name} in range");
        }
        fn height_with<F>(seed: [u8; 32], len: usize, predicate: F) -> u64
        where
            F: Fn(&[usize]) -> bool,
        {
            (0..256)
                .find(|height| predicate(&Topology::prf_shuffled_indices(seed, *height, len)))
                .expect("bounded PRF search should find a matching height")
        }
        let seed = [0x6D; 32];
        let leader_height = height_with(seed, 4, |perm| perm[0] != 0);
        let shuffle_height = height_with(seed, 4, |perm| perm != [0, 1, 2, 3]);
        let wrapper_height = height_with(seed, 3, |perm| perm != [0, 1, 2]);
        let alt_height = (0..256)
            .find(|height| {
                Topology::prf_shuffled_indices(seed, *height, 4)
                    != Topology::prf_shuffled_indices(seed, shuffle_height, 4)
            })
            .expect("bounded PRF search should find a distinct alternate height");
        let base = test_peers(5);
        let empty_topology = Topology(Vec::new(), 0);
        assert_eq!(
            empty_topology.leader_index_prf(seed, leader_height, 0),
            0,
            "leader_empty"
        );
        let single_topology = Topology::new([base[0].clone()]);
        assert_eq!(
            single_topology.leader_index_prf(seed, leader_height, 9),
            0,
            "leader_single"
        );
        let topology = Topology::new(base[..4].iter().cloned());
        let leader_perm = Topology::prf_shuffled_indices(seed, leader_height, 4);
        assert_permutation("leader_len4_cycle", &leader_perm, 4);
        for view in [0_u64, 3, 5] {
            assert_eq!(
                topology.leader_index_prf(seed, leader_height, view),
                leader_perm[usize::try_from(view % 4).expect("view slot fits")],
                "leader_len4_view{view}"
            );
        }
        assert_eq!(
            topology.leader_index_prf(seed, leader_height, 1),
            topology.leader_index_prf(seed, leader_height, 5),
            "leader_len4_periodic"
        );
        let leader_cycle: BTreeSet<_> = (0..4)
            .map(|view| topology.leader_index_prf(seed, leader_height, view))
            .collect();
        assert_eq!(leader_cycle.len(), 4, "leader_len4_cycle_distinct");
        let mut empty_shuffle = Topology(Vec::new(), 7);
        empty_shuffle.shuffle_prf(seed, shuffle_height);
        let empty_peers: &[PeerId] = &[];
        assert_eq!(empty_shuffle.as_ref(), empty_peers, "shuffle_empty");
        assert_eq!(empty_shuffle.view_change_index(), 7, "shuffle_empty view");
        let mut single_shuffle = Topology::new([base[0].clone()]);
        single_shuffle.1 = 7;
        single_shuffle.shuffle_prf(seed, shuffle_height);
        assert_eq!(ids(&single_shuffle, &base), vec![0], "shuffle_single");
        assert_eq!(single_shuffle.view_change_index(), 7, "shuffle_single view");
        let shuffle_perm = Topology::prf_shuffled_indices(seed, shuffle_height, 4);
        assert_permutation("shuffle_len4", &shuffle_perm, 4);
        let mut shuffled = Topology::new(base[..4].iter().cloned());
        shuffled.1 = 7;
        shuffled.shuffle_prf(seed, shuffle_height);
        assert_eq!(ids(&shuffled, &base), shuffle_perm, "shuffle_len4");
        assert_eq!(shuffled.view_change_index(), 7, "shuffle_len4 view");
        let wrapper_perm = Topology::prf_shuffled_indices(seed, wrapper_height, 3);
        assert_permutation("wrapper_canonical_dedup", &wrapper_perm, 3);
        let canonical_ids = [1_usize, 2, 3];
        let expected_wrapper: Vec<_> = wrapper_perm.iter().map(|idx| canonical_ids[*idx]).collect();
        let wrapper = shuffled_for_prf_seed(
            [3, 1, 3, 2].iter().map(|idx| base[*idx].clone()),
            seed,
            wrapper_height,
        );
        assert_eq!(
            ids(&wrapper, &base),
            expected_wrapper,
            "wrapper_canonical_dedup"
        );
        assert_eq!(
            wrapper.view_change_index(),
            0,
            "wrapper_canonical_dedup view"
        );
        let wrapper_single = shuffled_for_prf_seed(
            [4, 4, 4].iter().map(|idx| base[*idx].clone()),
            seed,
            wrapper_height,
        );
        assert_eq!(ids(&wrapper_single, &base), vec![4], "wrapper_single_dedup");
        assert_eq!(wrapper_single.view_change_index(), 0, "wrapper_single view");
        let alt_perm = Topology::prf_shuffled_indices(seed, alt_height, 4);
        assert_permutation("wrapper_alt_height", &alt_perm, 4);
        let alt_wrapper = shuffled_for_prf_seed(base[..4].iter().cloned(), seed, alt_height);
        assert_eq!(ids(&alt_wrapper, &base), alt_perm, "wrapper_alt_height");
        assert_eq!(
            alt_wrapper.view_change_index(),
            0,
            "wrapper_alt_height view"
        );
    }
    #[test]
    fn prf_leader_is_deterministic_and_varies_with_seed() {
        let peers: Vec<PeerId> = test_peers(8);
        let topo = Topology::new(peers);
        let seed_a = [1u8; 32];
        let seed_b = [2u8; 32];
        let la1 = topo.leader_index_prf(seed_a, 10, 5);
        let la2 = topo.leader_index_prf(seed_a, 10, 5);
        let lb = topo.leader_index_prf(seed_b, 10, 5);
        assert_eq!(la1, la2);
        // With different seed, high probability to differ; allow equality only if very unlucky
        // Accept difference as a sanity check:
        assert!(la1 != lb || topo.as_ref().len() == 1);
    }
    #[test]
    fn prf_leader_cycles_through_height_permutation_without_repeats() {
        let peers: Vec<PeerId> = test_peers(5);
        let topo = Topology::new(peers);
        let seed = [3u8; 32];
        let height = 42;
        let first_cycle: Vec<_> = (0..topo.as_ref().len())
            .map(|view| topo.leader_index_prf(seed, height, view as u64))
            .collect();
        let unique: std::collections::BTreeSet<_> = first_cycle.iter().copied().collect();
        assert_eq!(
            unique.len(),
            topo.as_ref().len(),
            "one NPoS leader cycle should visit every validator exactly once"
        );
        assert_eq!(
            topo.leader_index_prf(seed, height, topo.as_ref().len() as u64),
            first_cycle[0],
            "NPoS leader selection should repeat only after a full cycle"
        );
    }
}
/// Historical rotation keyed to the previous block hash.
///
/// This helper produces a `Topology` whose Set A (first `min_votes_for_commit()` peers)
/// is rotated left by `hash(prev_block_hash) mod min_votes_for_commit` positions. The
/// Set B segment order is preserved, and the view change index is set to 0.
///
/// Notes
/// - Rotation depends only on the provided inputs. It is not influenced by any
///   signature set or runtime state and is thus suitable for auditing.
/// - `prev_block_hash` is the hash of the block immediately preceding the round.
///
/// Invariants
/// - Deterministic across nodes and hardware.
/// - Independent of any observed QC signer set for the same height.
/// - Historical behavior; permissioned mode now uses PRF-based ordering.
///
/// Example
/// ```ignore
/// use iroha_core::sumeragi::network_topology::{rotated_for_prev_block_hash, ConsensusTopology};
/// use iroha_data_model::block::BlockHeader;
/// use iroha_model_base::peer::PeerId;
/// use iroha_crypto::HashOf;
///
/// // Application provides the current ordered peer list (e.g., from committed state)
/// let peers: Vec<PeerId> = get_current_peers();
/// let prev_hash: HashOf<BlockHeader> = get_prev_block_hash();
///
/// let topo = rotated_for_prev_block_hash(peers, prev_hash);
/// let leader = topo.leader().clone();
/// let proxy_tail = topo
///     .is_consensus_required()
///     .expect("N > 1 required for proxy tail")
///     .proxy_tail()
///     .clone();
/// // Now (leader, proxy_tail) are the expected roles for the next round
/// ```
pub fn rotated_for_prev_block_hash(
    peers: impl IntoIterator<Item = PeerId>,
    prev_block_hash: HashOf<BlockHeader>,
) -> Topology {
    // Canonicalize ordering to keep topology deterministic across nodes and restarts.
    let mut peers: Vec<PeerId> = peers.into_iter().collect();
    peers.sort();
    peers.dedup();
    let mut topology = Topology::new(peers);
    let rotate_at = topology.min_votes_for_commit();
    let k = rotation_offset_for_prev_hash(&prev_block_hash, rotate_at);
    if k > 0 {
        topology.0[..rotate_at].rotate_left(k);
    }
    topology
}
fn rotation_offset_for_prev_hash(prev_block_hash: &HashOf<BlockHeader>, rotate_at: usize) -> usize {
    if rotate_at == 0 {
        return 0;
    }
    let mut head = [0u8; 8];
    head.copy_from_slice(&prev_block_hash.as_ref()[..8]);
    let modulus = u128::try_from(rotate_at).expect("rotate_at fits u128");
    (u128::from(u64::from_be_bytes(head)) % modulus) as usize
}
/// Compute the expected role of each peer for auditing given the previous block hash.
/// Returns a vector of (`PeerId`, `Role`) in the rotated topology order.
pub fn audit_roles_for_prev_block_hash(
    peers: impl IntoIterator<Item = PeerId>,
    prev_block_hash: HashOf<BlockHeader>,
) -> Vec<(PeerId, Role)> {
    let topo = rotated_for_prev_block_hash(peers, prev_block_hash);
    topo.0
        .iter()
        .cloned()
        .map(|pid| {
            let role = topo.role(&pid);
            (pid, role)
        })
        .collect()
}
/// Deterministic PRF-based shuffle for permissioned ordering at a given height.
pub fn shuffled_for_prf_seed(
    peers: impl IntoIterator<Item = PeerId>,
    seed: [u8; 32],
    height: u64,
) -> Topology {
    // Canonicalize ordering to keep topology deterministic across nodes and restarts.
    let mut peers: Vec<PeerId> = peers.into_iter().collect();
    peers.sort();
    peers.dedup();
    let mut topology = Topology::new(peers);
    topology.shuffle_prf(seed, height);
    topology
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
    /// Get Set A validator [`PeerId`]s (excluding leader/proxy tail).
    pub fn validating_peers(&self) -> &'topology [PeerId] {
        &self.0[self.leader_index() + 1..self.proxy_tail_index()]
    }
    /// Get Set B validator [`PeerId`]s (tail segment after proxy tail).
    pub fn set_b_validators(&self) -> &'topology [PeerId] {
        &self.0[self.proxy_tail_index() + 1..]
    }
    /// Get all voting [`PeerId`]s (Set A + Set B).
    pub fn voting_peers(&self) -> &'topology [PeerId] {
        &self.0[..]
    }
}
/// Possible Peer's roles in consensus.
#[derive(Debug, Display, Clone, Copy, PartialOrd, Ord, Eq, PartialEq, Hash)]
pub enum Role {
    /// Leader.
    Leader,
    /// Validating Peer.
    ValidatingPeer,
    /// Set B validator (tail segment; still voting).
    SetBValidator,
    /// Proxy Tail.
    ProxyTail,
    /// Undefined. Not part of the topology
    Undefined,
}
#[cfg(test)]
fn checked_keypair() -> KeyPair {
    KeyPair::try_random().expect("network topology fixture key generation should succeed")
}
#[cfg(test)]
#[allow(dead_code)]
fn test_peers(n_peers: usize) -> Vec<PeerId> {
    let mut peers: Vec<_> = (0..n_peers)
        .map(|_| PeerId::new(checked_keypair().into_parts().0))
        .collect();
    peers.sort();
    peers
}
#[cfg(test)]
/// Construct a test `Topology` with `n_peers` randomly generated keys.
pub fn test_topology(n_peers: usize) -> Topology {
    let keys = (0..n_peers).map(|_| checked_keypair()).collect::<Vec<_>>();
    test_topology_with_keys(&keys)
}
#[cfg(test)]
#[allow(single_use_lifetimes)] // false-positive
/// Construct a test `Topology` from provided key pairs.
pub fn test_topology_with_keys<'a>(keys: impl IntoIterator<Item = &'a KeyPair>) -> Topology {
    let peers = keys
        .into_iter()
        .map(|key| PeerId::new(key.public_key().clone()));
    Topology::new(peers)
}
#[cfg(test)]
mod tests {
    #![allow(unused_variables, unused_mut)]
    use super::*;
    use crate::block::ValidBlock;
    use iroha_primitives::unique_vec;
    fn extract_order(topology: &Topology, initial_topology: &Topology) -> Vec<usize> {
        topology
            .0
            .iter()
            .map(|peer| {
                initial_topology
                    .0
                    .iter()
                    .position(|p| p.public_key() == peer.public_key())
                    .unwrap()
            })
            .collect()
    }
    fn prev_hash_with_seed(seed: u64) -> HashOf<BlockHeader> {
        let mut seed_bytes = [0u8; iroha_crypto::Hash::LENGTH];
        seed_bytes[..8].copy_from_slice(&seed.to_be_bytes());
        HashOf::<BlockHeader>::from_untyped_unchecked(iroha_crypto::Hash::prehashed(seed_bytes))
    }
    #[test]
    fn rotate_set_a() {
        let mut topology = test_topology(7);
        let initial_topology = topology.clone();
        let rotate_at = topology.min_votes_for_commit().min(topology.0.len());
        if rotate_at > 1 {
            topology.0[..rotate_at].rotate_left(1);
        }
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
        let key_pairs = core::iter::repeat_with(checked_keypair)
            .take(7)
            .collect::<Vec<_>>();
        let topology = test_topology_with_keys(&key_pairs);
        let dummy_block = ValidBlock::new_dummy(key_pairs[0].private_key());
        let dummy_signature = dummy_block
            .as_ref()
            .signatures()
            .next()
            .unwrap()
            .signature()
            .clone();
        let dummy_signatures = (0..key_pairs.len())
            .map(|i| BlockSignature::new(i as u64, dummy_signature.clone()))
            .collect::<Vec<_>>();
        let leader_signatures = topology
            .filter_signatures_by_roles(&[Role::Leader], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(leader_signatures.len(), 1);
        assert_eq!(leader_signatures[0].index(), 0);
        let proxy_tail_signatures = topology
            .filter_signatures_by_roles(&[Role::ProxyTail], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(proxy_tail_signatures.len(), 1);
        assert_eq!(proxy_tail_signatures[0].index(), 4);
        let validating_peers_signatures = topology
            .filter_signatures_by_roles(&[Role::ValidatingPeer], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(validating_peers_signatures.len(), 3);
        assert!(
            validating_peers_signatures
                .iter()
                .map(|s| s.index())
                .eq(1..4)
        );
        let set_b_signatures = topology
            .filter_signatures_by_roles(&[Role::SetBValidator], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(set_b_signatures.len(), 2);
        assert!(set_b_signatures.iter().map(|s| s.index()).eq(5..7));
    }
    #[test]
    fn filter_by_role_ignores_invalid_signature_indices() {
        let key_pairs = core::iter::repeat_with(checked_keypair)
            .take(3)
            .collect::<Vec<_>>();
        let topology = test_topology_with_keys(key_pairs.iter().take(3));
        let dummy_block = ValidBlock::new_dummy(key_pairs[0].private_key());
        let dummy_signature = dummy_block
            .as_ref()
            .signatures()
            .next()
            .unwrap()
            .signature()
            .clone();
        let dummy_signatures = [
            BlockSignature::new(0, dummy_signature.clone()),
            BlockSignature::new(u64::MAX, dummy_signature.clone()),
        ];
        let leader_signatures = topology
            .filter_signatures_by_roles(&[Role::Leader], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(leader_signatures.len(), 1);
        assert_eq!(leader_signatures[0].index(), 0);
    }
    #[test]
    fn filter_by_role_1() {
        let key_pairs = core::iter::repeat_with(checked_keypair)
            .take(7)
            .collect::<Vec<_>>();
        let key_pairs_iter = key_pairs.iter().take(1);
        let topology = test_topology_with_keys(key_pairs_iter);
        let dummy_block = ValidBlock::new_dummy(key_pairs[0].private_key());
        let dummy_signature = dummy_block
            .as_ref()
            .signatures()
            .next()
            .unwrap()
            .signature()
            .clone();
        let dummy_signatures = (0..key_pairs.len())
            .map(|i| BlockSignature::new(i as u64, dummy_signature.clone()))
            .collect::<Vec<_>>();
        let leader_signatures = topology
            .filter_signatures_by_roles(&[Role::Leader], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(leader_signatures.len(), 1);
        assert_eq!(leader_signatures[0].index(), 0);
        let proxy_tail_signatures =
            topology.filter_signatures_by_roles(&[Role::ProxyTail], dummy_signatures.iter());
        let proxy_tail_signatures = proxy_tail_signatures.collect::<Vec<_>>();
        assert_eq!(proxy_tail_signatures.len(), 1);
        assert_eq!(proxy_tail_signatures[0].index(), 0);
        let mut validating_peers_signatures =
            topology.filter_signatures_by_roles(&[Role::ValidatingPeer], dummy_signatures.iter());
        assert!(validating_peers_signatures.next().is_none());
        let mut set_b_signatures =
            topology.filter_signatures_by_roles(&[Role::SetBValidator], dummy_signatures.iter());
        assert!(set_b_signatures.next().is_none());
    }
    #[test]
    fn filter_by_role_2() {
        let key_pairs = core::iter::repeat_with(checked_keypair)
            .take(7)
            .collect::<Vec<_>>();
        let key_pairs_iter = key_pairs.iter().take(2);
        let topology = test_topology_with_keys(key_pairs_iter);
        let dummy_block = ValidBlock::new_dummy(key_pairs[0].private_key());
        let dummy_signature = dummy_block
            .as_ref()
            .signatures()
            .next()
            .unwrap()
            .signature()
            .clone();
        let dummy_signatures = (0..key_pairs.len())
            .map(|i| BlockSignature::new(i as u64, dummy_signature.clone()))
            .collect::<Vec<_>>();
        let leader_signatures = topology
            .filter_signatures_by_roles(&[Role::Leader], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(leader_signatures.len(), 1);
        assert_eq!(leader_signatures[0].index(), 0);
        let proxy_tail_signatures = topology
            .filter_signatures_by_roles(&[Role::ProxyTail], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(proxy_tail_signatures.len(), 1);
        assert_eq!(proxy_tail_signatures[0].index(), 1);
        let mut validating_peers_signatures =
            topology.filter_signatures_by_roles(&[Role::ValidatingPeer], dummy_signatures.iter());
        assert!(validating_peers_signatures.next().is_none());
        let mut set_b_signatures =
            topology.filter_signatures_by_roles(&[Role::SetBValidator], dummy_signatures.iter());
        assert!(set_b_signatures.next().is_none());
    }
    #[test]
    fn filter_by_role_3() {
        let key_pairs = core::iter::repeat_with(checked_keypair)
            .take(7)
            .collect::<Vec<_>>();
        let key_pairs_iter = key_pairs.iter().take(3);
        let topology = test_topology_with_keys(key_pairs_iter);
        let dummy_block = ValidBlock::new_dummy(key_pairs[0].private_key());
        let dummy_signature = dummy_block
            .as_ref()
            .signatures()
            .next()
            .unwrap()
            .signature()
            .clone();
        let dummy_signatures = (0..key_pairs.len())
            .map(|i| BlockSignature::new(i as u64, dummy_signature.clone()))
            .collect::<Vec<_>>();
        let leader_signatures = topology
            .filter_signatures_by_roles(&[Role::Leader], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(leader_signatures.len(), 1);
        assert_eq!(leader_signatures[0].index(), 0);
        let proxy_tail_signatures = topology
            .filter_signatures_by_roles(&[Role::ProxyTail], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(proxy_tail_signatures.len(), 1);
        assert_eq!(proxy_tail_signatures[0].index(), 2);
        let validating_peers_signatures = topology
            .filter_signatures_by_roles(&[Role::ValidatingPeer], dummy_signatures.iter())
            .collect::<Vec<_>>();
        assert_eq!(validating_peers_signatures.len(), 1);
        assert_eq!(validating_peers_signatures[0].index(), 1);
        let mut set_b_signatures =
            topology.filter_signatures_by_roles(&[Role::SetBValidator], dummy_signatures.iter());
        assert!(set_b_signatures.next().is_none());
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
                .is_non_empty()
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
                .is_non_empty()
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
                .is_non_empty()
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
                .is_non_empty()
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
    fn commit_quorum_matches_the_core_quorum() {
        let cases = [1_usize, 2, 3, 4, 5, 6, 7, 9, 10, 16];
        for len in cases {
            let topology = test_topology(len);
            assert_eq!(
                topology.min_votes_for_commit(),
                iroha_sumeragi::types::quorum(len),
                "quorum mismatch for len={len}"
            );
        }
    }
    /// The core quorum reproduces every value of the retired `commit_quorum_from_len`
    /// (`0` for an empty topology, `len - (len - 1) / 3` otherwise), so swapping the helper
    /// changed no quorum anywhere.
    #[test]
    fn core_quorum_equals_the_retired_topology_helper_everywhere() {
        fn retired_commit_quorum_from_len(len: usize) -> usize {
            if len == 0 {
                return 0;
            }
            len - (len - 1) / 3
        }
        let expected = [0_usize, 1, 2, 3, 3, 4, 5, 5, 6, 7, 7, 8, 9];
        for (len, expected) in expected.into_iter().enumerate() {
            assert_eq!(
                iroha_sumeragi::types::quorum(len),
                expected,
                "quorum mismatch for len={len}"
            );
        }
        for len in (0_usize..=4_096).chain([usize::MAX - 1, usize::MAX]) {
            let quorum = iroha_sumeragi::types::quorum(len);
            assert_eq!(quorum, retired_commit_quorum_from_len(len), "len={len}");
            assert_eq!(quorum, len - len.saturating_sub(1) / 3, "len={len}");
            assert!(quorum <= len);
            if (1..=4_096).contains(&len) {
                assert!(
                    3 * quorum > 2 * len,
                    "quorum must strictly exceed two thirds for len={len}"
                );
            }
        }
    }
    #[test]
    fn view_change_quorum_is_f_plus_one() {
        let cases = [1_usize, 2, 3, 4, 5, 6, 7, 10, 16];
        for len in cases {
            let topology = test_topology(len);
            let max_faults = (len.saturating_sub(1)) / 3;
            let expected = max_faults.saturating_add(1);
            assert_eq!(
                topology.min_votes_for_view_change(),
                expected,
                "view-change quorum mismatch for len={len}"
            );
        }
    }
    #[test]
    fn set_b_validators() {
        let peers = test_peers(7);
        let topology = Topology::new(peers.clone());
        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::set_b_validators),
            Some(&peers[5..])
        );
    }
    #[test]
    fn set_b_validators_1() {
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
    fn set_b_validators_2() {
        let peers = test_peers(2);
        let topology = Topology::new(peers);
        let empty_peer_slice: &[PeerId] = &[];
        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::set_b_validators),
            Some(empty_peer_slice)
        );
    }
    #[test]
    fn set_b_validators_3() {
        let peers = test_peers(3);
        let topology = Topology::new(peers);
        let empty_peer_slice: &[PeerId] = &[];
        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::set_b_validators),
            Some(empty_peer_slice)
        );
    }
    #[test]
    fn voting_peers_span_full_topology() {
        let peers = test_peers(7);
        let topology = Topology::new(peers.clone());
        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::voting_peers),
            Some(&peers[..])
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
    fn set_b_validators_empty() {
        let peers = test_peers(3);
        let topology = Topology::new(peers);
        assert_eq!(
            topology
                .is_consensus_required()
                .as_ref()
                .map(ConsensusTopology::set_b_validators),
            Some::<&[_]>(&[]),
        );
    }
    #[test]
    fn block_committed_preserves_membership_order() {
        let mut peers = test_peers(4);
        peers.reverse();
        let mut topo = Topology::new(peers.clone());
        let prev_hash = prev_hash_with_seed(0);
        topo.block_committed(peers.clone(), prev_hash);
        assert_eq!(topo.as_ref(), peers.as_slice());
    }
    #[test]
    fn canonicalize_order_sorts_without_resetting_view() {
        let mut peers = test_peers(4);
        peers.reverse();
        let mut topo = Topology::new(peers.clone());
        topo.nth_rotation(2);
        let view_index = topo.view_change_index();
        topo.canonicalize_order();
        let mut expected = peers;
        expected.sort();
        expected.dedup();
        assert_eq!(topo.as_ref(), expected.as_slice());
        assert_eq!(topo.view_change_index(), view_index);
    }
    #[test]
    fn nth_rotation_handles_large_view_indices() {
        let peers = test_peers(4);
        let mut topo = Topology::new(peers.clone());
        let large_view = u64::MAX - 2;
        topo.nth_rotation(large_view);
        let mut expected = Topology::new(peers);
        let rotations = large_view % expected.as_ref().len() as u64;
        expected.nth_rotation(rotations);
        assert_eq!(topo.as_ref(), expected.as_ref());
        assert_eq!(topo.view_change_index(), large_view);
    }
    #[test]
    fn rotated_for_prev_block_hash_rotates_set_a() {
        let peers = test_peers(7);
        let mut seed_bytes = [0u8; iroha_crypto::Hash::LENGTH];
        seed_bytes[7] = 1;
        let prev_hash = HashOf::<BlockHeader>::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed(seed_bytes),
        );
        let rotated = rotated_for_prev_block_hash(peers.clone(), prev_hash);
        let mut expected = Topology::new(peers);
        let rotate_at = expected.min_votes_for_commit();
        expected.0[..rotate_at].rotate_left(1);
        assert_eq!(rotated.0, expected.0);
    }
    #[test]
    fn rotated_for_prev_block_hash_is_deterministic_across_nodes() {
        let keys = (0..5).map(|_| checked_keypair()).collect::<Vec<_>>();
        let peers = keys.iter().map(|k| PeerId::new(k.public_key().clone()));
        let prev_hash = HashOf::<BlockHeader>::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([0x11; iroha_crypto::Hash::LENGTH]),
        );
        let a = rotated_for_prev_block_hash(peers.clone(), prev_hash);
        let b = rotated_for_prev_block_hash(peers, prev_hash);
        assert_eq!(a.0, b.0);
        assert_eq!(a.leader(), b.leader());
        assert_eq!(a.proxy_tail(), b.proxy_tail());
    }
    #[test]
    fn rotated_for_prev_block_hash_is_deterministic_regardless_of_input_order() {
        let keys = (0..5).map(|_| checked_keypair()).collect::<Vec<_>>();
        let peers: Vec<PeerId> = keys
            .iter()
            .map(|k| PeerId::new(k.public_key().clone()))
            .collect();
        let prev_hash = HashOf::<BlockHeader>::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([0x11; iroha_crypto::Hash::LENGTH]),
        );
        let mut sorted = peers.clone();
        sorted.sort();
        let mut reversed = sorted.clone();
        reversed.reverse();
        let a = rotated_for_prev_block_hash(sorted, prev_hash);
        let b = rotated_for_prev_block_hash(reversed, prev_hash);
        assert_eq!(a.0, b.0);
    }
    #[test]
    fn prf_shuffle_is_deterministic_across_nodes() {
        let keys = (0..5).map(|_| checked_keypair()).collect::<Vec<_>>();
        let peers = keys.iter().map(|k| PeerId::new(k.public_key().clone()));
        let seed = [0x22; 32];
        let a = shuffled_for_prf_seed(peers.clone(), seed, 42);
        let b = shuffled_for_prf_seed(peers, seed, 42);
        assert_eq!(a.0, b.0);
    }
    #[test]
    fn prf_shuffle_is_deterministic_regardless_of_input_order() {
        let keys = (0..5).map(|_| checked_keypair()).collect::<Vec<_>>();
        let peers: Vec<PeerId> = keys
            .iter()
            .map(|k| PeerId::new(k.public_key().clone()))
            .collect();
        let seed = [0x33; 32];
        let mut sorted = peers.clone();
        sorted.sort();
        let mut reversed = sorted.clone();
        reversed.reverse();
        let a = shuffled_for_prf_seed(sorted, seed, 9);
        let b = shuffled_for_prf_seed(reversed, seed, 9);
        assert_eq!(a.0, b.0);
    }
}
