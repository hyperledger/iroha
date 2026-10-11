//! The B-Chain style topology overlay (spec §2): a per-epoch permutation, the skipped-leader
//! demotion set `D_h`, the order of every round `(h, v)` with slot substitution, the roles
//! (leader, set A, proxy tail, set B) and the stage-1 hint (§5.2).
//!
//! Topology only affects liveness and routing; no safety rule depends on positions.

use std::collections::BTreeMap;

use crate::{
    crypto::Crypto,
    message::{BlockHeader, Qc},
    preimage,
    types::{
        Committee, EpochConfig, Hash32, PublicKey, ValidatorIndex, fault_threshold, index_of,
        quorum, usize_of,
    },
};

/// `prf_shuffle(seed, n)` (§2.1): `out[i]` is the canonical index at permutation position `i`.
///
/// ```text
/// slots = [0, 1, …, n−1]; ctr = 0
/// while slots not empty:
///     r = be64_to_u64(H(seed ‖ be64(ctr))[0..8]); pos = r mod len(slots)
///     out.push(slots.swap_remove(pos)); ctr += 1
/// ```
pub fn prf_shuffle(crypto: &dyn Crypto, seed: &Hash32, n: usize) -> Vec<ValidatorIndex> {
    let mut slots: Vec<ValidatorIndex> = (0..n).map(index_of).collect();
    let mut out = Vec::with_capacity(n);
    let mut ctr: u64 = 0;
    let mut input = [0u8; 40];
    input[..32].copy_from_slice(seed.as_bytes());
    while !slots.is_empty() {
        input[32..].copy_from_slice(&ctr.to_be_bytes());
        let digest = crypto.hash(&input);
        let mut head = [0u8; 8];
        head.copy_from_slice(&digest.as_bytes()[..8]);
        let r = u64::from_be_bytes(head);
        let len = u64::try_from(slots.len()).unwrap_or(u64::MAX);
        let pos = usize::try_from(r % len).unwrap_or(0);
        out.push(slots.swap_remove(pos));
        ctr += 1;
    }
    out
}

/// `perm_C = prf_shuffle(H(TAG_TOPOLOGY ‖ I ‖ E ‖ leader_seed ‖ committee_digest(C)), n)` (§2.1). Depends only on
/// the authenticated epoch context, fresh leader seed, committee and instance.
pub fn committee_permutation(
    crypto: &dyn Crypto,
    instance: &Hash32,
    epoch: &EpochConfig,
    committee: &Committee,
) -> Vec<ValidatorIndex> {
    let seed = preimage::topology_seed(crypto, instance, epoch, committee);
    prf_shuffle(crypto, &seed, committee.n())
}

/// The demotion window `J_h = [max(g+1, h−1−W), h−2]` as an inclusive range (`None` if empty).
pub fn demotion_window(height: u64, genesis_height: u64, window: u64) -> Option<(u64, u64)> {
    let lo = height
        .saturating_sub(1)
        .saturating_sub(window)
        .max(genesis_height.saturating_add(1));
    let hi = height.checked_sub(2)?;
    (lo <= hi).then_some((lo, hi))
}

/// `D_h` (§2.1): members of `committee` that were skipped leaders at some height of the window
/// `J_h`, sorted by (latest such height descending, canonical index ascending), truncated to
/// `f_h`. `headers` are committed headers (any superset of the window; others are ignored); the
/// caller must supply every header of `J_h` it holds (the core holds all of them, §6.8).
pub fn demoted_set(
    committee: &Committee,
    height: u64,
    genesis_height: u64,
    window: u64,
    headers: impl IntoIterator<Item = impl std::borrow::Borrow<BlockHeader>>,
) -> Vec<ValidatorIndex> {
    let Some((lo, hi)) = demotion_window(height, genesis_height, window) else {
        return Vec::new();
    };
    let mut last: BTreeMap<ValidatorIndex, u64> = BTreeMap::new();
    for header in headers {
        let header = std::borrow::Borrow::borrow(&header);
        if header.height < lo || header.height > hi {
            continue;
        }
        for key in &header.skipped_leaders {
            if let Some(index) = committee.index_of(key) {
                let entry = last.entry(index).or_insert(header.height);
                *entry = (*entry).max(header.height);
            }
        }
    }
    let mut candidates: Vec<(ValidatorIndex, u64)> = last.into_iter().collect();
    candidates.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    candidates.truncate(committee.f());
    #[cfg(sumeragi_mutation = "ML7")]
    candidates.clear();
    candidates.into_iter().map(|(index, _)| index).collect()
}

/// Topology of one height `h`: permutation, demotion set and the derived non-demoted list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Topology {
    height: u64,
    perm: Vec<ValidatorIndex>,
    pos: Vec<usize>,
    demoted: Vec<ValidatorIndex>,
    is_demoted: Vec<bool>,
    nd: Vec<ValidatorIndex>,
    k0: usize,
}

impl Topology {
    /// Build from a permutation of `0..n` and `D_h` (in priority order). Demoted entries that are
    /// out of range or repeated are ignored and the list is truncated to `f`; `None` if `perm` is
    /// not a permutation of `0..n` for some `n ≥ 1`.
    pub fn from_parts(
        perm: Vec<ValidatorIndex>,
        demoted: &[ValidatorIndex],
        height: u64,
    ) -> Option<Self> {
        let n = perm.len();
        if n == 0 {
            return None;
        }
        let mut pos = vec![usize::MAX; n];
        for (position, member) in perm.iter().enumerate() {
            let slot = pos.get_mut(usize_of(*member))?;
            if *slot != usize::MAX {
                return None;
            }
            *slot = position;
        }
        let mut is_demoted = vec![false; n];
        let mut kept = Vec::new();
        for member in demoted {
            if kept.len() == fault_threshold(n) {
                break;
            }
            if let Some(flag) = is_demoted.get_mut(usize_of(*member))
                && !*flag
            {
                *flag = true;
                kept.push(*member);
            }
        }
        let nd: Vec<ValidatorIndex> = perm
            .iter()
            .copied()
            .filter(|member| !is_demoted[usize_of(*member)])
            .collect();
        // k0(h): the first non-demoted member at permutation positions h mod n, (h+1) mod n, …
        let anchor = modulo(height, n);
        let first = (0..n)
            .map(|t| perm[(anchor + t) % n])
            .find(|member| !is_demoted[usize_of(*member)])?;
        let k0 = nd.iter().position(|member| *member == first)?;
        Some(Self {
            height,
            perm,
            pos,
            demoted: kept,
            is_demoted,
            nd,
            k0,
        })
    }

    /// Compute the topology of `height` for `committee = C_h` (§2.1): permutation from the
    /// authenticated epoch, committee and instance, `D_h` from the committed headers of the window.
    #[allow(clippy::too_many_arguments, reason = "the §2.1 perm and `D_h` inputs")]
    pub fn compute(
        crypto: &dyn Crypto,
        instance: &Hash32,
        epoch: &EpochConfig,
        committee: &Committee,
        height: u64,
        genesis_height: u64,
        window: u64,
        headers: &[BlockHeader],
    ) -> Self {
        let perm = committee_permutation(crypto, instance, epoch, committee);
        let demoted = demoted_set(committee, height, genesis_height, window, headers);
        // Committee construction proves n >= 1; shuffle preserves a permutation and
        // demotion retains at most f < n members. No substitute committee is permissible.
        Self::from_parts(perm, &demoted, height).expect("validated committee gives a topology")
    }

    /// Height `h`.
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Committee size `n`.
    pub fn n(&self) -> usize {
        self.perm.len()
    }

    /// Quorum `q` (size of set A).
    pub fn q(&self) -> usize {
        quorum(self.n())
    }

    /// `perm_C`.
    pub fn permutation(&self) -> &[ValidatorIndex] {
        &self.perm
    }

    /// `D_h` in priority order.
    pub fn demoted(&self) -> &[ValidatorIndex] {
        &self.demoted
    }

    /// Whether `member` is in `D_h`.
    pub fn is_demoted(&self, member: ValidatorIndex) -> bool {
        self.is_demoted
            .get(usize_of(member))
            .copied()
            .unwrap_or(false)
    }

    /// Leader `L(h, v) = nd_h[(k0(h) + v) mod a_h]`.
    pub fn leader(&self, view: u64) -> ValidatorIndex {
        // ML18: views rotate over permutation slots (`perm[(h + v + i) mod n]`, first non-demoted).
        #[cfg(sumeragi_mutation = "ML18")]
        {
            let n = self.perm.len();
            let start = (modulo(self.height, n) + modulo(view, n)) % n;
            return (0..n)
                .map(|t| self.perm[(start + t) % n])
                .find(|member| !self.is_demoted(*member))
                .unwrap_or(self.perm[0]);
        }
        let a = self.nd.len();
        self.nd[(self.k0 + modulo(view, a)) % a]
    }

    /// `skipped_leaders` of a fresh block first proposed in `origin_view`:
    /// `[L(h, x) for x in 0..min(origin_view, a_h)]`.
    pub fn skipped_leaders(&self, origin_view: u64) -> Vec<ValidatorIndex> {
        let count = usize::try_from(origin_view)
            .unwrap_or(usize::MAX)
            .min(self.nd.len());
        (0..count)
            .map(|x| self.leader(u64::try_from(x).unwrap_or(u64::MAX)))
            .collect()
    }

    /// Keys of [`Topology::skipped_leaders`] for `committee = C_h`.
    pub fn skipped_leader_keys(&self, committee: &Committee, origin_view: u64) -> Vec<PublicKey> {
        self.skipped_leaders(origin_view)
            .into_iter()
            .filter_map(|member| committee.get(member).cloned())
            .collect()
    }

    /// The order and roles of round `(h, view)` (§2.1 rules 4–5).
    pub fn round(&self, view: u64) -> Round {
        let n = self.n();
        let start = self.pos[usize_of(self.leader(view))];
        let base = (0..n).map(|i| self.perm[(start + i) % n]);
        let mut order: Vec<ValidatorIndex> = base
            .clone()
            .filter(|member| !self.is_demoted(*member))
            .collect();
        order.extend(base.filter(|member| self.is_demoted(*member)));
        Round { order, q: self.q() }
    }
}

fn modulo(value: u64, n: usize) -> usize {
    let n64 = u64::try_from(n).unwrap_or(u64::MAX).max(1);
    usize::try_from(value % n64).unwrap_or(0)
}

/// The order of one round `(h, v)` and its roles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Round {
    order: Vec<ValidatorIndex>,
    q: usize,
}

impl Round {
    /// `order_{h,v}`: canonical indices by position.
    pub fn order(&self) -> &[ValidatorIndex] {
        &self.order
    }

    /// Leader `order[0]`.
    pub fn leader(&self) -> ValidatorIndex {
        self.order[0]
    }

    /// Proxy tail `order[q − 1]` (equals the leader iff `q = 1`).
    pub fn proxy_tail(&self) -> ValidatorIndex {
        self.order[self.q - 1]
    }

    /// Set A: `order[0 .. q]`.
    pub fn set_a(&self) -> &[ValidatorIndex] {
        &self.order[..self.q]
    }

    /// Set B: `order[q .. n]` (empty if `f = 0`).
    pub fn set_b(&self) -> &[ValidatorIndex] {
        &self.order[self.q..]
    }

    /// Whether `member` is in set A.
    pub fn in_set_a(&self, member: ValidatorIndex) -> bool {
        self.set_a().contains(&member)
    }

    /// Whether `member` is in set B.
    pub fn in_set_b(&self, member: ValidatorIndex) -> bool {
        self.set_b().contains(&member)
    }
}

/// The stage-1 hint (§5.2): the initial stage of every round of height `h` is 1 if the parent
/// `CommitQC` `commit_qc` (of height `h − 1`) has a signer outside `setA(h − 1, commit_qc.view)`,
/// else 0. `parent` is the topology of `h − 1`. Without a parent `CommitQC` the stage is 0.
pub fn initial_stage(parent: &Topology, commit_qc: Option<&Qc>) -> u8 {
    let Some(qc) = commit_qc.filter(|_| !cfg!(sumeragi_mutation = "ML16")) else {
        return 0;
    };
    let round = parent.round(qc.view);
    u8::from(qc.signers.ones().any(|member| !round.in_set_a(member)))
}

#[cfg(test)]
mod tests {
    //! Golden vectors come from an independent Python implementation of §2.1 (SHA-256 as `H`).
    use super::*;
    use crate::{
        message::VoteKind,
        testing::FakeCrypto,
        types::{AggregateSignature, Bitmap, SIGNATURE_LEN},
    };

    const I: Hash32 = Hash32([0x11; 32]);

    fn key(byte: u8) -> PublicKey {
        PublicKey::new(vec![byte; 32]).unwrap()
    }

    fn committee(n: u8) -> Committee {
        Committee::new((1..=n).map(key).collect()).unwrap()
    }

    fn header(height: u64, skipped: &[PublicKey]) -> BlockHeader {
        BlockHeader {
            control_witness: crate::types::ControlWitness::empty(),
            epoch: crate::testing::TEST_EPOCH.id,
            instance: I,
            height,
            origin_view: u64::try_from(skipped.len()).unwrap(),
            parent_hash: Hash32::ZERO,
            parent_result: Hash32::ZERO,
            payload_hash: Hash32::ZERO,
            availability_digest: crate::types::Hash32::ZERO,
            payload_len: 0,
            proposer: 0,
            skipped_leaders: skipped.to_vec(),
        }
    }

    fn commit_qc(n: usize, view: u64, signers: &[ValidatorIndex]) -> Qc {
        Qc {
            epoch: crate::testing::TEST_EPOCH.id,
            kind: VoteKind::Commit,
            instance: I,
            height: 1,
            view,
            block_hash: Hash32::ZERO,
            result: Hash32::ZERO,
            signers: Bitmap::from_indices(n, signers.iter().copied()).unwrap(),
            agg_sig: AggregateSignature([0; SIGNATURE_LEN]),
        }
    }

    /// Simple xorshift for property tests.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
        }
    }

    #[test]
    fn golden_permutation() {
        let crypto = FakeCrypto::new();
        assert_eq!(
            prf_shuffle(&crypto, &Hash32([0x5a; 32]), 0),
            Vec::<u32>::new()
        );
        assert_eq!(prf_shuffle(&crypto, &Hash32([0x5a; 32]), 1), vec![0]);
        assert_eq!(
            prf_shuffle(&crypto, &Hash32([0x5a; 32]), 7),
            vec![4, 6, 2, 1, 5, 3, 0]
        );
        assert_eq!(
            committee_permutation(&crypto, &I, &crate::testing::TEST_EPOCH, &committee(4)),
            vec![3, 0, 1, 2]
        );
        assert_eq!(
            committee_permutation(&crypto, &I, &crate::testing::TEST_EPOCH, &committee(7)),
            vec![0, 4, 6, 1, 3, 2, 5]
        );
        // Permutations for every size are permutations.
        for n in 1..=31u8 {
            let mut perm =
                committee_permutation(&crypto, &I, &crate::testing::TEST_EPOCH, &committee(n));
            perm.sort_unstable();
            assert_eq!(perm, (0..u32::from(n)).collect::<Vec<_>>());
        }
        // The instance separates topologies.
        assert_ne!(
            committee_permutation(&crypto, &I, &crate::testing::TEST_EPOCH, &committee(7)),
            committee_permutation(
                &crypto,
                &Hash32([0x12; 32]),
                &crate::testing::TEST_EPOCH,
                &committee(7)
            )
        );
    }

    #[test]
    fn window_bounds() {
        assert_eq!(demotion_window(1, 0, 128), None);
        assert_eq!(demotion_window(2, 0, 128), None);
        assert_eq!(demotion_window(3, 0, 128), Some((1, 1)));
        assert_eq!(demotion_window(200, 0, 128), Some((71, 198)));
        assert_eq!(demotion_window(200, 100, 128), Some((101, 198)));
        assert_eq!(demotion_window(10, 0, 1), Some((8, 8)));
        assert_eq!(demotion_window(0, 0, 1), None);
        assert_eq!(demotion_window(5, u64::MAX, 1), None);
    }

    #[test]
    fn golden_demotion_set() {
        let c = committee(7); // f = 2
        let headers = [
            header(10, &[key(3)]),
            header(11, &[key(5), key(6)]),
            header(12, &[key(3)]),
            header(13, &[key(9)]), // not a member
            header(14, &[key(1)]), // outside the window of h = 15 (h − 2 = 13)
        ];
        // J_15 = [max(1, 14 − W), 13].
        assert_eq!(demoted_set(&c, 15, 0, 128, &headers), vec![2, 4]);
        // Window W = 3: J = [11, 13]; key(3) last at 12, key(5)/key(6) at 11 → tie by index.
        assert_eq!(demoted_set(&c, 15, 0, 3, &headers), vec![2, 4]);
        // Window W = 2: J = [12, 13]: only key(3).
        assert_eq!(demoted_set(&c, 15, 0, 2, &headers), vec![2]);
        // h = 16: key(1) at 14 is now in the window and is the most recent.
        assert_eq!(demoted_set(&c, 16, 0, 128, &headers), vec![0, 2]);
        // Genesis bound: nothing at or below g.
        assert_eq!(demoted_set(&c, 15, 12, 128, &headers), Vec::<u32>::new());
        // f = 0: nobody is demoted.
        assert_eq!(
            demoted_set(&committee(3), 15, 0, 128, &headers),
            Vec::<u32>::new()
        );
    }

    fn keys_of(indices: &[u32]) -> Vec<u8> {
        indices.iter().map(|i| u8::try_from(*i).unwrap()).collect()
    }

    #[test]
    fn empty_demotion_matches_plain_rotation() {
        let crypto = FakeCrypto::new();
        for n in 1..=13u8 {
            let c = committee(n);
            let perm = committee_permutation(&crypto, &I, &crate::testing::TEST_EPOCH, &c);
            let nn = usize::from(n);
            for height in 0..30u64 {
                let topo = Topology::from_parts(perm.clone(), &[], height).unwrap();
                for view in 0..(3 * u64::from(n)) {
                    let round = topo.round(view);
                    let expected: Vec<u32> = (0..nn)
                        .map(|i| perm[(modulo(height + view, nn) + i) % nn])
                        .collect();
                    assert_eq!(round.order(), &expected[..], "n={n} h={height} v={view}");
                }
            }
        }
    }

    /// perm = identity [A=0, B=1, C=2, D=3, …] makes golden orders readable.
    fn identity(n: u32) -> Vec<u32> {
        (0..n).collect()
    }

    #[test]
    fn det_l18_f_plus_1_distinct_leaders() {
        // n = 4, D = {B}, perm = [A, B, C, D], height anchored at B's slot (h mod 4 = 1):
        // views 0 and 1 are led by C and then D (the literal formula would give C twice).
        let topo = Topology::from_parts(identity(4), &[1], 5).unwrap();
        assert_eq!(topo.leader(0), 2);
        assert_eq!(topo.leader(1), 3);
        assert_ne!(topo.leader(0), topo.leader(1));
        assert_eq!(topo.round(0).order(), &[2, 3, 0, 1]);
        assert_eq!(topo.round(1).order(), &[3, 0, 2, 1]);
        assert_eq!(topo.round(2).order(), &[0, 2, 3, 1]);
    }

    #[test]
    fn golden_slot_substitution_orders() {
        // n = 7 (f = 2, q = 5), perm = identity so members read as positions.
        // |D| = 0.
        let t = Topology::from_parts(identity(7), &[], 3).unwrap();
        assert_eq!(t.round(0).order(), &[3, 4, 5, 6, 0, 1, 2]);
        assert_eq!(t.round(1).order(), &[4, 5, 6, 0, 1, 2, 3]);
        assert_eq!(t.round(2).order(), &[5, 6, 0, 1, 2, 3, 4]);
        // |D| = 1 = f − 1, demoted slot at the anchor: slot 3 passes to 4.
        let t = Topology::from_parts(identity(7), &[3], 3).unwrap();
        assert_eq!(&t.nd, &[0, 1, 2, 4, 5, 6]);
        assert_eq!(t.round(0).order(), &[4, 5, 6, 0, 1, 2, 3]);
        assert_eq!(t.round(1).order(), &[5, 6, 0, 1, 2, 4, 3]);
        assert_eq!(t.round(2).order(), &[6, 0, 1, 2, 4, 5, 3]);
        // |D| = 1, demoted member between views (slot after the anchor): views skip it.
        let t = Topology::from_parts(identity(7), &[4], 3).unwrap();
        assert_eq!(t.round(0).order(), &[3, 5, 6, 0, 1, 2, 4]);
        assert_eq!(t.round(1).order(), &[5, 6, 0, 1, 2, 3, 4]);
        assert_eq!(t.round(2).order(), &[6, 0, 1, 2, 3, 5, 4]);
        // |D| = f = 2, adjacent demoted slots at the anchor: slots 3 and 4 pass to 5.
        let t = Topology::from_parts(identity(7), &[4, 3], 3).unwrap();
        assert_eq!(t.demoted(), &[4, 3]);
        assert_eq!(t.round(0).order(), &[5, 6, 0, 1, 2, 3, 4]);
        assert_eq!(t.round(1).order(), &[6, 0, 1, 2, 5, 3, 4]);
        assert_eq!(t.round(2).order(), &[0, 1, 2, 5, 6, 3, 4]);
        let r = t.round(0);
        assert_eq!(keys_of(r.set_a()), vec![5, 6, 0, 1, 2]);
        assert_eq!(r.proxy_tail(), 2);
        assert_eq!(keys_of(r.set_b()), vec![3, 4]);
        // |D| = f = 2, non-adjacent demoted members, anchor not demoted.
        let t = Topology::from_parts(identity(7), &[1, 5], 4).unwrap();
        assert_eq!(t.round(0).order(), &[4, 6, 0, 2, 3, 5, 1]);
        assert_eq!(t.round(1).order(), &[6, 0, 2, 3, 4, 1, 5]);
        assert_eq!(t.round(2).order(), &[0, 2, 3, 4, 6, 1, 5]);
        // Demotion list is truncated to f and ignores repeats / out-of-range members.
        let t = Topology::from_parts(identity(7), &[9, 1, 1, 5, 6], 4).unwrap();
        assert_eq!(t.demoted(), &[1, 5]);
        assert!(t.is_demoted(1) && !t.is_demoted(6) && !t.is_demoted(99));
    }

    #[test]
    fn golden_orders_with_real_permutation() {
        // n = 4 and n = 7 with the fake-hash permutation, |D| ∈ {0, f − 1, f}, views 0, 1, 2.
        let crypto = FakeCrypto::new();
        let c7 = committee(7);
        let perm7 = committee_permutation(&crypto, &I, &crate::testing::TEST_EPOCH, &c7);
        let got: Vec<Vec<Vec<u32>>> = [vec![], vec![perm7[3]], vec![perm7[3], perm7[4]]]
            .iter()
            .map(|demoted| {
                let t = Topology::from_parts(perm7.clone(), demoted, 10).unwrap();
                (0..3).map(|v| t.round(v).order().to_vec()).collect()
            })
            .collect();
        assert_eq!(
            got, /* golden updated */
            vec![
                vec![
                    vec![1, 3, 2, 5, 0, 4, 6],
                    vec![3, 2, 5, 0, 4, 6, 1],
                    vec![2, 5, 0, 4, 6, 1, 3]
                ],
                vec![
                    vec![3, 2, 5, 0, 4, 6, 1],
                    vec![2, 5, 0, 4, 6, 3, 1],
                    vec![5, 0, 4, 6, 3, 2, 1]
                ],
                vec![
                    vec![2, 5, 0, 4, 6, 1, 3],
                    vec![5, 0, 4, 6, 2, 1, 3],
                    vec![0, 4, 6, 2, 5, 1, 3]
                ]
            ]
        );
        let c4 = committee(4);
        let perm4 = committee_permutation(&crypto, &I, &crate::testing::TEST_EPOCH, &c4);
        let got: Vec<Vec<Vec<u32>>> = [vec![], vec![perm4[1]]]
            .iter()
            .map(|demoted| {
                let t = Topology::from_parts(perm4.clone(), demoted, 5).unwrap();
                (0..3).map(|v| t.round(v).order().to_vec()).collect()
            })
            .collect();
        assert_eq!(
            got, /* golden updated */
            vec![
                vec![vec![0, 1, 2, 3], vec![1, 2, 3, 0], vec![2, 3, 0, 1]],
                vec![vec![1, 2, 3, 0], vec![2, 3, 1, 0], vec![3, 1, 2, 0]]
            ]
        );
    }

    #[test]
    fn roles() {
        let t = Topology::from_parts(identity(4), &[], 0).unwrap();
        let r = t.round(0);
        assert_eq!(r.leader(), 0);
        assert_eq!(r.set_a(), &[0, 1, 2]);
        assert_eq!(r.proxy_tail(), 2);
        assert_eq!(r.set_b(), &[3]);
        assert_eq!(r.order.iter().position(|member| *member == 3), Some(3));
        assert_eq!(r.order.iter().position(|member| *member == 9), None);
        assert!(r.in_set_a(1) && !r.in_set_a(3));
        assert!(r.in_set_b(3) && !r.in_set_b(0));
        // q = 1: the leader is the proxy tail; set B empty.
        let t = Topology::from_parts(vec![0], &[], 9).unwrap();
        let r = t.round(5);
        assert_eq!((r.leader(), r.proxy_tail()), (0, 0));
        assert!(r.set_b().is_empty());
        // n = 3: f = 0, q = 3.
        let t = Topology::from_parts(identity(3), &[1], 0).unwrap();
        assert!(t.demoted().is_empty());
        assert_eq!(t.round(0).set_a(), &[0, 1, 2]);
        assert_eq!((t.height(), t.n(), t.q(), t.k0), (0, 3, 3, 0));
        assert_eq!(t.permutation(), &[0, 1, 2]);
    }

    #[test]
    fn from_parts_rejects_non_permutations() {
        assert!(Topology::from_parts(vec![], &[], 0).is_none());
        assert!(Topology::from_parts(vec![0, 0], &[], 0).is_none());
        assert!(Topology::from_parts(vec![0, 2], &[], 0).is_none());
    }

    #[test]
    fn skipped_leaders_list() {
        let c = committee(7);
        let t = Topology::from_parts(identity(7), &[3], 3).unwrap();
        assert!(t.skipped_leaders(0).is_empty());
        assert_eq!(t.skipped_leaders(2), vec![4, 5]);
        // Capped at a_h = 6.
        assert_eq!(t.skipped_leaders(u64::MAX), vec![4, 5, 6, 0, 1, 2]);
        assert_eq!(t.skipped_leader_keys(&c, 2), vec![key(5), key(6)]);
    }

    #[test]
    fn huge_views_and_heights() {
        let t = Topology::from_parts(identity(7), &[2, 4], u64::MAX).unwrap();
        for view in [u64::MAX, u64::MAX - 1, 1 << 63] {
            let r = t.round(view);
            assert_eq!(r.order().len(), 7);
            assert!(!t.is_demoted(r.leader()));
        }
    }

    #[test]
    #[allow(clippy::many_single_char_names)]
    fn properties_random() {
        let mut rng = Rng(0x1234_5678_9abc_def1);
        for _ in 0..400 {
            let n = 1 + rng.below(31);
            let f = fault_threshold(n);
            let q = quorum(n);
            let mut perm: Vec<u32> = (0..index_of(n)).collect();
            for i in (1..n).rev() {
                perm.swap(i, rng.below(i + 1));
            }
            let d_size = rng.below(f + 1);
            let mut members: Vec<u32> = (0..index_of(n)).collect();
            for i in (1..n).rev() {
                members.swap(i, rng.below(i + 1));
            }
            let demoted: Vec<u32> = members[..d_size].to_vec();
            let a = n - d_size;
            let base_height = rng.next() % 1_000_000;
            for dh in 0..u64::try_from(n).unwrap() {
                let height = base_height + dh;
                let t = Topology::from_parts(perm.clone(), &demoted, height).unwrap();
                assert!(a >= q);
                for view in 0..u64::try_from(2 * n + 2).unwrap() {
                    let r = t.round(view);
                    // A permutation of the committee.
                    let mut sorted = r.order().to_vec();
                    sorted.sort_unstable();
                    assert_eq!(sorted, (0..index_of(n)).collect::<Vec<_>>());
                    // Demoted members never lead, never in set A / proxy tail.
                    for member in &demoted {
                        assert!(!r.in_set_a(*member));
                    }
                    assert_eq!(r.leader(), t.leader(view));
                    // The failed leader of view v is at position a − 1 in view v + 1.
                    let next = t.round(view + 1);
                    if a > 1 {
                        assert_eq!(
                            next.order.iter().position(|member| *member == r.leader()),
                            Some(a - 1)
                        );
                    }
                    // f + 1 consecutive views have f + 1 distinct leaders.
                    let mut leaders: Vec<u32> = (0..=u64::try_from(f).unwrap())
                        .map(|x| t.leader(view + x))
                        .collect();
                    leaders.sort_unstable();
                    leaders.dedup();
                    assert_eq!(leaders.len(), f + 1);
                }
            }
            // Fairness: over n consecutive heights every slot anchors view 0 once; a
            // non-demoted member leads view 0 1 + (#demoted immediately preceding it) times.
            let mut counts = vec![0usize; n];
            for dh in 0..u64::try_from(n).unwrap() {
                let t = Topology::from_parts(perm.clone(), &demoted, base_height + dh).unwrap();
                counts[usize_of(t.leader(0))] += 1;
            }
            for (position, member) in perm.iter().enumerate() {
                let m = usize_of(*member);
                if demoted.contains(member) {
                    assert_eq!(counts[m], 0);
                } else {
                    let mut preceding = 0;
                    let mut p = (position + n - 1) % n;
                    while demoted.contains(&perm[p]) && preceding < n {
                        preceding += 1;
                        p = (p + n - 1) % n;
                    }
                    assert_eq!(counts[m], 1 + preceding);
                }
            }
        }
    }

    #[test]
    fn det_l7_demotion_golden() {
        // Leader of (h, 0) silent, commit at view 1: from h + 2 it is in D, its slot's view-0
        // leader is its successor, and other heights' view-0 leaders are unchanged.
        let crypto = FakeCrypto::new();
        for n in [4u8, 7] {
            let c = committee(n);
            let nn = usize::from(n);
            let perm = committee_permutation(&crypto, &I, &crate::testing::TEST_EPOCH, &c);
            let g = 0u64;
            let h = 20u64;
            let base =
                Topology::compute(&crypto, &I, &crate::testing::TEST_EPOCH, &c, h, g, 128, &[]);
            let silent = base.leader(0);
            let committed = header(h, &[c.get(silent).unwrap().clone()]);
            let headers = [committed];
            // h + 1 does not see the header of h yet (window ends at h − 1).
            let t1 = Topology::compute(
                &crypto,
                &I,
                &crate::testing::TEST_EPOCH,
                &c,
                h + 1,
                g,
                128,
                &headers,
            );
            assert!(t1.demoted().is_empty());
            for later in (h + 2)..(h + 2 + 2 * u64::from(n)) {
                let t = Topology::compute(
                    &crypto,
                    &I,
                    &crate::testing::TEST_EPOCH,
                    &c,
                    later,
                    g,
                    128,
                    &headers,
                );
                let plain = Topology::from_parts(perm.clone(), &[], later).unwrap();
                assert_eq!(t.demoted(), &[silent], "n={n} h={later}");
                assert_ne!(t.leader(0), silent);
                if plain.leader(0) == silent {
                    let slot = perm.iter().position(|m| *m == silent).unwrap();
                    assert_eq!(
                        t.leader(0),
                        perm[(slot + 1) % nn],
                        "successor takes the slot"
                    );
                } else {
                    assert_eq!(t.leader(0), plain.leader(0), "unchanged elsewhere");
                }
            }
            // After W heights the member is reinstated.
            let t = Topology::compute(
                &crypto,
                &I,
                &crate::testing::TEST_EPOCH,
                &c,
                h + 2 + 128,
                g,
                128,
                &headers,
            );
            assert!(t.demoted().is_empty());
        }
    }

    #[test]
    fn stage_hint() {
        // n = 7: set A of the parent round = first q = 5 positions.
        let parent = Topology::from_parts(identity(7), &[], 0).unwrap();
        // View 0 order = [0..7]: set A = {0..4}, set B = {5, 6}.
        assert_eq!(initial_stage(&parent, None), 0);
        assert_eq!(
            initial_stage(&parent, Some(&commit_qc(7, 0, &[0, 1, 2, 3, 4]))),
            0
        );
        assert_eq!(
            initial_stage(&parent, Some(&commit_qc(7, 0, &[0, 1, 2, 3, 5]))),
            1
        );
        // View 1 order = [1..7, 0]: member 5 is in set A, member 0 in set B.
        assert_eq!(
            initial_stage(&parent, Some(&commit_qc(7, 1, &[1, 2, 3, 4, 5]))),
            0
        );
        assert_eq!(
            initial_stage(&parent, Some(&commit_qc(7, 1, &[0, 1, 2, 3, 4]))),
            1
        );
        // With a demoted member the parent's set A excludes it.
        let parent = Topology::from_parts(identity(7), &[2], 0).unwrap();
        assert_eq!(parent.round(0).set_a(), &[0, 1, 3, 4, 5]);
        assert_eq!(
            initial_stage(&parent, Some(&commit_qc(7, 0, &[0, 1, 3, 4, 5]))),
            0
        );
        assert_eq!(
            initial_stage(&parent, Some(&commit_qc(7, 0, &[0, 1, 2, 3, 4]))),
            1
        );
        // Golden: fake-hash permutation, n = 4.
        let crypto = FakeCrypto::new();
        let c4 = committee(4);
        let parent = Topology::compute(
            &crypto,
            &I,
            &crate::testing::TEST_EPOCH,
            &c4,
            5,
            0,
            128,
            &[],
        );
        let set_a = parent.round(0).set_a().to_vec();
        assert_eq!(initial_stage(&parent, Some(&commit_qc(4, 0, &set_a))), 0);
        let set_b = parent.round(0).set_b().to_vec();
        let mixed = [set_a[0], set_a[1], set_b[0]];
        assert_eq!(initial_stage(&parent, Some(&commit_qc(4, 0, &mixed))), 1);
    }
}
