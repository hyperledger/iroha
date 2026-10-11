//! Native references of the trees the step relations open (wire record
//! `specs/kagemusha_wallet_wire_v1.md` sections 3.2 and 3.3; proposal
//! sections 3 and 7): the blacklist gap tree, the quota-window tree and the
//! depth-32 indexed Merkle tree of the wallet maps, with their domains,
//! leaves, nodes, openings and small builders for witnesses and tests.
//!
//! These are the in-circuit values of `crate::control_circuit`, computed
//! with [`hash_with_domain`] over the σ field. The G1 data model owns the
//! wallet's own trees; the shared vectors of
//! `fixtures/kagemusha/wallet_v1_vectors.json` pin both
//! (`tests/digest_parity.rs`).
//!
//! # Which σ opens which tree
//!
//! - `sigma_send` with the blacklist control: one gap opening of the
//!   Request's receiver account digest in the payer's blacklist gap tree
//!   ([`BlacklistTree`], depth 16), against the head-committed
//!   `blacklist_root`.
//! - `sigma_recv` with the blacklist control: one gap opening of the
//!   Request's payer account digest in the receiver's gap tree.
//! - `sigma_send` with the quota control: openings of the quota-window tree
//!   ([`QuotaWindowTree`], depth 6) and aligned value updates in the
//!   quota-usage array ([`QuotaUsageTree`], depth 6), against the head-committed
//!   `quota_windows_root` and `quota_usage_root`.
//!
//! The lineage relation opens every other map (consumed-credit,
//! pending-outgoing, load/redeem recovery, fee-claim) and the credit-digest
//! tree; no σ opens them (proposal section 3).

use std::collections::BTreeMap;

use iroha_pasta::poseidon::{PoseidonField, hash_with_domain};
use iroha_plonk_gadgets::statement::digest_fields;

/// Blacklist gap-leaf domain `kgwblkl1` (G1
/// `KAGEMUSHA_WALLET_BLACKLIST_LEAF_DOMAIN_V1`).
pub const BLACKLIST_LEAF_DOMAIN: u64 = u64::from_le_bytes(*b"kgwblkl1");
/// Blacklist node domain `kgwblkn1` (G1
/// `KAGEMUSHA_WALLET_BLACKLIST_NODE_DOMAIN_V1`).
pub const BLACKLIST_NODE_DOMAIN: u64 = u64::from_le_bytes(*b"kgwblkn1");
/// Depth of the blacklist gap tree (65,536 gap leaves).
pub const BLACKLIST_DEPTH: usize = 16;
/// The lowest blacklist sentinel `00..00`.
pub const BLACKLIST_SENTINEL_LOW: [u8; 32] = [0; 32];
/// The highest blacklist sentinel `FF..FF`.
pub const BLACKLIST_SENTINEL_HIGH: [u8; 32] = [0xff; 32];
/// The most blacklist entries (G1 `KAGEMUSHA_WALLET_BLACKLIST_ENTRIES_MAX_V1`).
pub const BLACKLIST_ENTRIES_MAX: usize = 65_535;

/// Quota-window leaf domain `kgwqwin1` (G1
/// `KAGEMUSHA_WALLET_QUOTA_WINDOW_DOMAIN_V1`).
pub const QUOTA_WINDOW_DOMAIN: u64 = u64::from_le_bytes(*b"kgwqwin1");
/// Quota-window node domain `kgwqwnd1` (G1
/// `KAGEMUSHA_WALLET_QUOTA_NODE_DOMAIN_V1`).
pub const QUOTA_NODE_DOMAIN: u64 = u64::from_le_bytes(*b"kgwqwnd1");
/// Depth of the quota-window tree.
pub const QUOTA_DEPTH: usize = 6;
/// Window slots of a quota share (G1 `KAGEMUSHA_WALLET_QUOTA_WINDOWS_MAX_V1`).
pub const QUOTA_SLOTS: usize = 1 << QUOTA_DEPTH;
/// The Daily window kind tag.
pub const WINDOW_DAILY: u8 = 1;
/// The Monthly window kind tag.
pub const WINDOW_MONTHLY: u8 = 2;
/// The window kind tags, in tree order.
pub const WINDOW_KINDS: [u8; 2] = [WINDOW_DAILY, WINDOW_MONTHLY];

/// Indexed-tree leaf domain `kgwimlf1` (G1
/// `KAGEMUSHA_WALLET_INDEXED_LEAF_DOMAIN_V1`).
pub const INDEXED_LEAF_DOMAIN: u64 = u64::from_le_bytes(*b"kgwimlf1");
/// Indexed-tree node domain `kgwimnd1` (G1
/// `KAGEMUSHA_WALLET_INDEXED_NODE_DOMAIN_V1`).
pub const INDEXED_NODE_DOMAIN: u64 = u64::from_le_bytes(*b"kgwimnd1");
/// Depth of every indexed map tree.
pub const INDEXED_DEPTH: usize = 32;
/// Quota-usage leaf domain `kgwquse1` (G1
/// `KAGEMUSHA_WALLET_QUOTA_USAGE_LEAF_DOMAIN_V1`).
pub const QUOTA_USAGE_DOMAIN: u64 = u64::from_le_bytes(*b"kgwquse1");

/// Quota-usage array node domain `kgwqusn1` (B5).
pub const QUOTA_USAGE_NODE_DOMAIN: u64 = u64::from_le_bytes(*b"kgwqusn1");

/// Whether `left < right` in the blacklist's limb order (owner answer A4):
/// `int(a) = hi * 2^128 + lo`, the 32 bytes read as one little-endian
/// integer.
#[must_use]
pub fn limb_less(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter().rev().cmp(right.iter().rev()) == core::cmp::Ordering::Less
}

/// Whether `left < right` as integers in `[0, p)`.
#[must_use]
pub fn field_less<F: PoseidonField>(left: &F, right: &F) -> bool {
    let left = left.to_canonical_limbs();
    let right = right.to_canonical_limbs();
    left.iter().rev().cmp(right.iter().rev()) == core::cmp::Ordering::Less
}

/// The root over `node` at the leaf position `index` of a binary tree whose
/// nodes are `P(node_domain, [left, right])`: bit `h` of `index` puts the
/// running node on the right at height `h`.
#[must_use]
pub fn path_root<F: PoseidonField>(node_domain: u64, node: F, index: u64, siblings: &[F]) -> F {
    let mut current = node;
    for (height, sibling) in siblings.iter().enumerate() {
        current = if (index >> height) & 1 == 1 {
            hash_with_domain(node_domain, &[*sibling, current])
        } else {
            hash_with_domain(node_domain, &[current, *sibling])
        };
    }
    current
}

// ---------------------------------------------------------------------------
// Blacklist gap tree (wire record section 3.3)
// ---------------------------------------------------------------------------

/// The gap leaf `P(kgwblkl1, limbs(lower) || limbs(upper))`.
#[must_use]
pub fn blacklist_leaf<F: PoseidonField>(lower: &[u8; 32], upper: &[u8; 32]) -> F {
    let [lower_lo, lower_hi] = digest_fields::<F>(lower);
    let [upper_lo, upper_hi] = digest_fields::<F>(upper);
    hash_with_domain(
        BLACKLIST_LEAF_DOMAIN,
        &[lower_lo, lower_hi, upper_lo, upper_hi],
    )
}

/// A blacklist non-membership opening: the gap leaf `(lower, upper)` at
/// `leaf_index` and its 16 siblings (a local witness, never transmitted).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlacklistGap<F> {
    /// The gap leaf index.
    pub leaf_index: u32,
    /// The lower sentinel or entry of the gap.
    pub lower: [u8; 32],
    /// The upper entry or sentinel of the gap.
    pub upper: [u8; 32],
    /// The siblings, height 0 first.
    pub siblings: [F; BLACKLIST_DEPTH],
}

impl<F: PoseidonField> BlacklistGap<F> {
    /// The all-zero opening of a relation whose list is not enforced.
    #[must_use]
    pub fn unused() -> Self {
        Self {
            leaf_index: 0,
            lower: [0; 32],
            upper: [0; 32],
            siblings: [F::ZERO; BLACKLIST_DEPTH],
        }
    }

    /// The gap leaf.
    #[must_use]
    pub fn leaf(&self) -> F {
        blacklist_leaf(&self.lower, &self.upper)
    }

    /// The root the opening recomputes.
    #[must_use]
    pub fn root(&self) -> F {
        path_root(
            BLACKLIST_NODE_DOMAIN,
            self.leaf(),
            u64::from(self.leaf_index),
            &self.siblings,
        )
    }

    /// Whether `account` lies strictly inside the gap in limb order.
    #[must_use]
    pub fn brackets(&self, account: &[u8; 32]) -> bool {
        limb_less(&self.lower, account) && limb_less(account, &self.upper)
    }

    /// Whether the opening proves `account` absent from the tree `root`.
    #[must_use]
    pub fn proves_absent(&self, root: &F, account: &[u8; 32]) -> bool {
        self.brackets(account) && self.root() == *root
    }
}

/// A blacklist gap tree over sorted entries (the G1
/// `kagemusha_wallet_blacklist_root_v1` construction).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlacklistTree {
    entries: Vec<[u8; 32]>,
}

impl BlacklistTree {
    /// The tree of `entries`, sorted here into limb order (`None` for a
    /// duplicate, a sentinel value or too many entries).
    #[must_use]
    pub fn new(mut entries: Vec<[u8; 32]>) -> Option<Self> {
        entries.sort_by(|left, right| left.iter().rev().cmp(right.iter().rev()));
        let duplicate = entries.windows(2).any(|pair| pair[0] == pair[1]);
        let sentinel = entries
            .iter()
            .any(|entry| *entry == BLACKLIST_SENTINEL_LOW || *entry == BLACKLIST_SENTINEL_HIGH);
        (!duplicate && !sentinel && entries.len() <= BLACKLIST_ENTRIES_MAX)
            .then_some(Self { entries })
    }

    /// The entries in limb order.
    #[must_use]
    pub fn entries(&self) -> &[[u8; 32]] {
        &self.entries
    }

    /// Every level (gap leaves first, the root last) and the padding root of
    /// every height.
    fn levels<F: PoseidonField>(&self) -> (Vec<Vec<F>>, [F; BLACKLIST_DEPTH + 1]) {
        let mut padding = [F::ZERO; BLACKLIST_DEPTH + 1];
        padding[0] = blacklist_leaf(&BLACKLIST_SENTINEL_HIGH, &BLACKLIST_SENTINEL_HIGH);
        for height in 0..BLACKLIST_DEPTH {
            padding[height + 1] =
                hash_with_domain(BLACKLIST_NODE_DOMAIN, &[padding[height], padding[height]]);
        }
        let mut level = Vec::with_capacity(self.entries.len() + 1);
        let mut lower = &BLACKLIST_SENTINEL_LOW;
        for entry in &self.entries {
            level.push(blacklist_leaf(lower, entry));
            lower = entry;
        }
        level.push(blacklist_leaf(lower, &BLACKLIST_SENTINEL_HIGH));
        let mut levels = Vec::with_capacity(BLACKLIST_DEPTH + 1);
        for pad in padding.iter().take(BLACKLIST_DEPTH) {
            let next = level
                .chunks(2)
                .map(|pair| {
                    hash_with_domain(
                        BLACKLIST_NODE_DOMAIN,
                        &[pair[0], *pair.get(1).unwrap_or(pad)],
                    )
                })
                .collect();
            levels.push(level);
            level = next;
        }
        levels.push(level);
        (levels, padding)
    }

    /// The gap-tree root.
    #[must_use]
    pub fn root<F: PoseidonField>(&self) -> F {
        let (levels, _) = self.levels::<F>();
        levels
            .last()
            .and_then(|root| root.first())
            .copied()
            .unwrap_or(F::ZERO)
    }

    /// The gap opening of an absent `account` (`None` when it is listed or a
    /// sentinel).
    #[must_use]
    pub fn gap<F: PoseidonField>(&self, account: &[u8; 32]) -> Option<BlacklistGap<F>> {
        if *account == BLACKLIST_SENTINEL_LOW || *account == BLACKLIST_SENTINEL_HIGH {
            return None;
        }
        let index = self
            .entries
            .partition_point(|entry| limb_less(entry, account));
        let upper = self
            .entries
            .get(index)
            .copied()
            .unwrap_or(BLACKLIST_SENTINEL_HIGH);
        if upper == *account {
            return None;
        }
        let lower = index
            .checked_sub(1)
            .and_then(|previous| self.entries.get(previous))
            .copied()
            .unwrap_or(BLACKLIST_SENTINEL_LOW);
        let (levels, padding) = self.levels::<F>();
        let mut siblings = [F::ZERO; BLACKLIST_DEPTH];
        let mut position = index;
        for ((sibling, level), pad) in siblings.iter_mut().zip(&levels).zip(&padding) {
            *sibling = level.get(position ^ 1).copied().unwrap_or(*pad);
            position >>= 1;
        }
        Some(BlacklistGap {
            leaf_index: u32::try_from(index).ok()?,
            lower,
            upper,
            siblings,
        })
    }
}

// ---------------------------------------------------------------------------
// Quota-window tree (wire record section 3.3)
// ---------------------------------------------------------------------------

/// One quota-window slot: `kind` Daily 1 or Monthly 2, the half-open
/// `[start_ms, end_ms)` and the gross limit; the empty slot is all zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QuotaWindow {
    /// The window kind tag (0 for an empty slot).
    pub kind: u8,
    /// The inclusive start in Unix milliseconds.
    pub start_ms: u64,
    /// The exclusive end in Unix milliseconds.
    pub end_ms: u64,
    /// The gross sending limit.
    pub limit: u128,
}

impl QuotaWindow {
    /// The empty slot `(0, 0, 0, 0)`.
    pub const EMPTY: Self = Self {
        kind: 0,
        start_ms: 0,
        end_ms: 0,
        limit: 0,
    };

    /// The window leaf `P(kgwqwin1, [kind, start, end, limit])`.
    #[must_use]
    pub fn leaf<F: PoseidonField>(&self) -> F {
        hash_with_domain(
            QUOTA_WINDOW_DOMAIN,
            &[
                F::from(u64::from(self.kind)),
                F::from(self.start_ms),
                F::from(self.end_ms),
                F::from_u128(self.limit),
            ],
        )
    }

    /// Whether a Send over `[lower, upper]` touches the window: `start <=
    /// upper` and `lower < end` (wire record section 3.3, Time).
    #[must_use]
    pub const fn touches(&self, lower: u64, upper: u64) -> bool {
        self.start_ms <= upper && lower < self.end_ms
    }

    /// The quota-usage value `P(kgwquse1, [kind, start, end, used])` of this
    /// window with `used` (a field value: the circuit's sum).
    #[must_use]
    pub fn usage_value<F: PoseidonField>(&self, used: F) -> F {
        hash_with_domain(
            QUOTA_USAGE_DOMAIN,
            &[
                F::from(u64::from(self.kind)),
                F::from(self.start_ms),
                F::from(self.end_ms),
                used,
            ],
        )
    }
}

/// A quota-window tree: the windows first, sorted by `(kind, start)`, then
/// empty slots (the G1 `kagemusha_wallet_quota_windows_root_v1`
/// construction).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotaWindowTree {
    slots: Vec<QuotaWindow>,
}

impl QuotaWindowTree {
    /// The tree of `windows` (`None` for more than 64 windows, an empty or
    /// unknown kind, or windows out of `(kind, start)` order).
    #[must_use]
    pub fn new(windows: &[QuotaWindow]) -> Option<Self> {
        if windows.len() > QUOTA_SLOTS
            || windows
                .iter()
                .any(|window| !WINDOW_KINDS.contains(&window.kind))
            || windows
                .windows(2)
                .any(|pair| (pair[0].kind, pair[0].start_ms) >= (pair[1].kind, pair[1].start_ms))
        {
            return None;
        }
        let mut slots = windows.to_vec();
        slots.resize(QUOTA_SLOTS, QuotaWindow::EMPTY);
        Some(Self { slots })
    }

    /// The window (or empty slot) at `slot`.
    #[must_use]
    pub fn slot(&self, slot: usize) -> QuotaWindow {
        self.slots.get(slot).copied().unwrap_or(QuotaWindow::EMPTY)
    }

    /// Every level, leaves first.
    fn levels<F: PoseidonField>(&self) -> Vec<Vec<F>> {
        let mut level: Vec<F> = self.slots.iter().map(QuotaWindow::leaf).collect();
        let mut levels = Vec::with_capacity(QUOTA_DEPTH + 1);
        while level.len() > 1 {
            let next = level
                .chunks_exact(2)
                .map(|pair| hash_with_domain(QUOTA_NODE_DOMAIN, &[pair[0], pair[1]]))
                .collect();
            levels.push(level);
            level = next;
        }
        levels.push(level);
        levels
    }

    /// The windows root.
    #[must_use]
    pub fn root<F: PoseidonField>(&self) -> F {
        self.levels::<F>()
            .last()
            .and_then(|root| root.first())
            .copied()
            .unwrap_or(F::ZERO)
    }

    /// The siblings of `slot`, height 0 first.
    #[must_use]
    pub fn siblings<F: PoseidonField>(&self, slot: usize) -> [F; QUOTA_DEPTH] {
        let levels = self.levels::<F>();
        let mut siblings = [F::ZERO; QUOTA_DEPTH];
        let mut position = slot;
        for (sibling, level) in siblings.iter_mut().zip(&levels) {
            *sibling = level.get(position ^ 1).copied().unwrap_or(F::ZERO);
            position >>= 1;
        }
        siblings
    }
}

/// Fixed quota-usage array aligned with the 64 quota-window slots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotaUsageTree<F> {
    windows: QuotaWindowTree,
    used: [u128; QUOTA_SLOTS],
    field: core::marker::PhantomData<F>,
}

impl<F: PoseidonField> QuotaUsageTree<F> {
    /// Build zero usage at every window slot.
    #[must_use]
    pub fn new(windows: &QuotaWindowTree) -> Self {
        Self {
            windows: windows.clone(),
            used: [0; QUOTA_SLOTS],
            field: core::marker::PhantomData,
        }
    }

    /// Usage at an array slot, or `None` outside the array.
    #[must_use]
    pub fn used(&self, slot: usize) -> Option<u128> {
        self.used.get(slot).copied()
    }

    /// Set usage at a populated slot; padding remains zero.
    pub fn set(&mut self, slot: usize, used: u128) -> bool {
        if slot >= QUOTA_SLOTS || self.windows.slot(slot).kind == 0 {
            return false;
        }
        self.used[slot] = used;
        true
    }

    fn levels(&self) -> Vec<Vec<F>> {
        let mut level: Vec<F> = (0..QUOTA_SLOTS)
            .map(|slot| {
                self.windows
                    .slot(slot)
                    .usage_value(F::from_u128(self.used[slot]))
            })
            .collect();
        let mut levels = Vec::with_capacity(QUOTA_DEPTH + 1);
        while level.len() > 1 {
            let next = level
                .chunks_exact(2)
                .map(|pair| hash_with_domain(QUOTA_USAGE_NODE_DOMAIN, &[pair[0], pair[1]]))
                .collect();
            levels.push(level);
            level = next;
        }
        levels.push(level);
        levels
    }

    /// The committed array root.
    #[must_use]
    pub fn root(&self) -> F {
        self.levels()[QUOTA_DEPTH][0]
    }

    /// Six siblings at `slot`, height zero first; `None` outside the array.
    #[must_use]
    pub fn siblings(&self, slot: usize) -> Option<[F; QUOTA_DEPTH]> {
        if slot >= QUOTA_SLOTS {
            return None;
        }
        let levels = self.levels();
        Some(core::array::from_fn(|height| {
            levels[height][(slot >> height) ^ 1]
        }))
    }
}

// ---------------------------------------------------------------------------
// Indexed Merkle tree (wire record section 3.2)
// ---------------------------------------------------------------------------

/// One indexed-tree leaf `(key, value, next_key)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IndexedLeaf<F> {
    /// The key (zero only for the sentinel).
    pub key: F,
    /// The map value (zero only for the sentinel).
    pub value: F,
    /// The next larger key present, or zero for the largest.
    pub next_key: F,
}

impl<F: PoseidonField> IndexedLeaf<F> {
    /// The zero sentinel leaf of slot 0.
    #[must_use]
    pub fn sentinel() -> Self {
        Self {
            key: F::ZERO,
            value: F::ZERO,
            next_key: F::ZERO,
        }
    }

    /// The leaf hash `P(kgwimlf1, [key, value, next_key])`.
    #[must_use]
    pub fn hash(&self) -> F {
        hash_with_domain(INDEXED_LEAF_DOMAIN, &[self.key, self.value, self.next_key])
    }

    /// Whether the leaf is the low leaf of an absent `key`: `self.key < key`
    /// and (`next_key = 0` or `key < next_key`).
    #[must_use]
    pub fn brackets(&self, key: &F) -> bool {
        field_less(&self.key, key)
            && (bool::from(self.next_key.is_zero()) || field_less(key, &self.next_key))
    }
}

/// The empty subtree root of every height (height 0: the empty slot `0`).
#[must_use]
pub fn indexed_empty<F: PoseidonField>() -> [F; INDEXED_DEPTH + 1] {
    let mut empty = [F::ZERO; INDEXED_DEPTH + 1];
    for height in 0..INDEXED_DEPTH {
        empty[height + 1] = hash_with_domain(INDEXED_NODE_DOMAIN, &[empty[height], empty[height]]);
    }
    empty
}

/// A sparse depth-32 indexed Merkle tree (the G1
/// `KagemushaWalletIndexedTreeV1` construction): the zero sentinel in slot
/// 0 and insertions at monotonically allocated slots. Removal relinks the
/// predecessor and clears the removed slot without making it reusable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedTree<F> {
    slots: BTreeMap<u32, IndexedLeaf<F>>,
    nodes: Vec<BTreeMap<u64, F>>,
    empty: [F; INDEXED_DEPTH + 1],
    next_free: u64,
}

impl<F: PoseidonField> Default for IndexedTree<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PoseidonField> IndexedTree<F> {
    /// The empty tree: the zero sentinel leaf in slot 0.
    #[must_use]
    pub fn new() -> Self {
        let mut tree = Self {
            slots: BTreeMap::new(),
            nodes: vec![BTreeMap::new(); INDEXED_DEPTH + 1],
            empty: indexed_empty(),
            next_free: 1,
        };
        tree.write(0, Some(IndexedLeaf::sentinel()));
        tree
    }

    /// The root.
    #[must_use]
    pub fn root(&self) -> F {
        self.node(INDEXED_DEPTH, 0)
    }

    /// The next free slot.
    #[must_use]
    pub const fn next_free(&self) -> u64 {
        self.next_free
    }

    fn node(&self, height: usize, index: u64) -> F {
        self.nodes[height]
            .get(&index)
            .copied()
            .unwrap_or(self.empty[height])
    }

    fn write(&mut self, slot: u32, leaf: Option<IndexedLeaf<F>>) {
        let mut index = u64::from(slot);
        if let Some(leaf) = leaf {
            self.slots.insert(slot, leaf);
            self.nodes[0].insert(index, leaf.hash());
        } else {
            self.slots.remove(&slot);
            self.nodes[0].remove(&index);
        }
        for height in 0..INDEXED_DEPTH {
            let left = self.node(height, index & !1);
            let right = self.node(height, index | 1);
            index >>= 1;
            let parent = hash_with_domain(INDEXED_NODE_DOMAIN, &[left, right]);
            if parent == self.empty[height + 1] {
                self.nodes[height + 1].remove(&index);
            } else {
                self.nodes[height + 1].insert(index, parent);
            }
        }
    }

    /// The siblings of `slot`, height 0 first.
    #[must_use]
    pub fn siblings(&self, slot: u32) -> [F; INDEXED_DEPTH] {
        let mut siblings = [F::ZERO; INDEXED_DEPTH];
        let mut index = u64::from(slot);
        for (height, sibling) in siblings.iter_mut().enumerate() {
            *sibling = self.node(height, index ^ 1);
            index >>= 1;
        }
        siblings
    }

    /// The slot and leaf of a present `key`.
    #[must_use]
    pub fn find(&self, key: &F) -> Option<(u32, IndexedLeaf<F>)> {
        self.slots
            .iter()
            .find(|(_, leaf)| leaf.key == *key && !bool::from(key.is_zero()))
            .map(|(slot, leaf)| (*slot, *leaf))
    }

    /// The slot and leaf of the low leaf of an absent nonzero `key`.
    #[must_use]
    pub fn low(&self, key: &F) -> Option<(u32, IndexedLeaf<F>)> {
        self.slots
            .iter()
            .find(|(_, leaf)| leaf.brackets(key))
            .map(|(slot, leaf)| (*slot, *leaf))
    }

    /// The value of `key`, if present.
    #[must_use]
    pub fn get(&self, key: &F) -> Option<F> {
        self.find(key).map(|(_, leaf)| leaf.value)
    }

    /// Inserts a fresh nonzero `key` and `value`, returning the two ordered
    /// authentication paths. A duplicate, zero key/value or full tree is
    /// rejected without mutation. Indexed maps never update a value in place;
    /// quota usage uses the separate fixed array.
    #[must_use]
    pub fn insert(&mut self, key: F, value: F) -> Option<IndexedInsert<F>> {
        if bool::from(key.is_zero()) || bool::from(value.is_zero()) || self.find(&key).is_some() {
            return None;
        }
        let (low_slot, low) = self.low(&key)?;
        let slot = u32::try_from(self.next_free).ok()?;
        let leaf_siblings = self.siblings(low_slot);
        self.write(
            low_slot,
            Some(IndexedLeaf {
                next_key: key,
                ..low
            }),
        );
        let slot_siblings = self.siblings(slot);
        self.write(
            slot,
            Some(IndexedLeaf {
                key,
                value,
                next_key: low.next_key,
            }),
        );
        self.next_free = u64::from(slot) + 1;
        Some(IndexedInsert {
            leaf: low,
            leaf_slot: low_slot,
            leaf_siblings,
            slot,
            slot_siblings,
        })
    }

    /// Remove a present nonzero key, returning the ordered relink/clear paths.
    /// The predecessor opens against the old root; the removed leaf opens
    /// against the root after relinking. The cleared slot is exactly zero,
    /// and its allocation is never reused. Absent keys and the sentinel are
    /// rejected without changing the tree or its allocation counter.
    #[must_use]
    pub fn remove(&mut self, key: &F) -> Option<IndexedRemove<F>> {
        let (slot, leaf) = self.find(key)?;
        let (predecessor_slot, predecessor) = self
            .slots
            .iter()
            .find(|(_, predecessor)| predecessor.next_key == *key)
            .map(|(slot, predecessor)| (*slot, *predecessor))?;
        let predecessor_siblings = self.siblings(predecessor_slot);
        self.write(
            predecessor_slot,
            Some(IndexedLeaf {
                next_key: leaf.next_key,
                ..predecessor
            }),
        );
        let leaf_siblings = self.siblings(slot);
        self.write(slot, None);
        Some(IndexedRemove {
            predecessor,
            predecessor_slot,
            predecessor_siblings,
            leaf,
            slot,
            leaf_siblings,
        })
    }
}

/// Witness of one indexed-tree insertion: the bracketing low leaf against
/// the old root, then an empty slot against the root after relinking it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexedInsert<F> {
    /// The low leaf before the insertion.
    pub leaf: IndexedLeaf<F>,
    /// The slot of `leaf`.
    pub leaf_slot: u32,
    /// The siblings of `leaf_slot` against the old root.
    pub leaf_siblings: [F; INDEXED_DEPTH],
    /// The written slot, authenticated as empty before the insertion.
    pub slot: u32,
    /// The siblings of `slot` against the root after the first write.
    pub slot_siblings: [F; INDEXED_DEPTH],
}

/// Witness of one indexed-tree removal, in the circuit's relink/clear order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexedRemove<F> {
    /// Predecessor whose `next_key` is the removed key, before relinking.
    pub predecessor: IndexedLeaf<F>,
    /// Permanent slot of the predecessor, including sentinel slot zero.
    pub predecessor_slot: u32,
    /// Predecessor path against the original root.
    pub predecessor_siblings: [F; INDEXED_DEPTH],
    /// Original removed leaf, retaining its value and successor key.
    pub leaf: IndexedLeaf<F>,
    /// Removed slot, cleared permanently rather than recycled.
    pub slot: u32,
    /// Removed-leaf path against the root after relinking the predecessor.
    pub leaf_siblings: [F; INDEXED_DEPTH],
}

#[cfg(test)]
mod tests {
    use ff::{Field, PrimeField};
    use iroha_pasta::{Fp, Fq};

    use super::*;

    #[test]
    fn domains_are_the_g1_ones() {
        assert_eq!(BLACKLIST_LEAF_DOMAIN.to_le_bytes(), *b"kgwblkl1");
        assert_eq!(BLACKLIST_NODE_DOMAIN.to_le_bytes(), *b"kgwblkn1");
        assert_eq!(QUOTA_WINDOW_DOMAIN.to_le_bytes(), *b"kgwqwin1");
        assert_eq!(QUOTA_NODE_DOMAIN.to_le_bytes(), *b"kgwqwnd1");
        assert_eq!(INDEXED_LEAF_DOMAIN.to_le_bytes(), *b"kgwimlf1");
        assert_eq!(INDEXED_NODE_DOMAIN.to_le_bytes(), *b"kgwimnd1");
        assert_eq!(QUOTA_USAGE_DOMAIN.to_le_bytes(), *b"kgwquse1");
    }

    #[test]
    fn limb_order_reads_the_digest_as_one_little_endian_integer() {
        let mut low_hi = [0_u8; 32];
        low_hi[31] = 1;
        let mut high_lo = [0_u8; 32];
        high_lo[0] = 0xff;
        // Byte order says high_lo > low_hi; limb order the reverse.
        assert!(limb_less(&high_lo, &low_hi));
        assert!(!limb_less(&low_hi, &high_lo));
        assert!(!limb_less(&low_hi, &low_hi));
        assert!(limb_less(&BLACKLIST_SENTINEL_LOW, &high_lo));
        assert!(limb_less(&low_hi, &BLACKLIST_SENTINEL_HIGH));
        assert!(field_less(&Fp::from(3_u64), &Fp::from(4_u64)));
        assert!(!field_less(&-Fp::ONE, &Fp::from(4_u64)));
    }

    #[test]
    fn gap_openings_reach_the_root_and_bracket_only_absent_accounts() {
        let entries = vec![[0x30; 32], [0x10; 32], [0x20; 32]];
        let tree = BlacklistTree::new(entries).expect("tree");
        assert_eq!(tree.entries()[0], [0x10; 32]);
        let root: Fp = tree.root();
        for account in [[0x01; 32], [0x15; 32], [0x25; 32], [0x40; 32]] {
            let gap: BlacklistGap<Fp> = tree.gap(&account).expect("absent");
            assert!(gap.proves_absent(&root, &account), "{account:?}");
            assert!(!gap.proves_absent(&(root + Fp::ONE), &account));
        }
        assert!(tree.gap::<Fp>(&[0x20; 32]).is_none());
        assert!(tree.gap::<Fp>(&BLACKLIST_SENTINEL_HIGH).is_none());
        // A gap does not bracket its own bounds.
        let gap: BlacklistGap<Fq> = tree.gap(&[0x15; 32]).expect("absent");
        assert!(!gap.brackets(&gap.lower) && !gap.brackets(&gap.upper));
        assert!(BlacklistTree::new(vec![[1; 32], [1; 32]]).is_none());
        assert!(BlacklistTree::new(vec![BLACKLIST_SENTINEL_HIGH]).is_none());
        // The empty list is one gap from sentinel to sentinel.
        let empty = BlacklistTree::new(Vec::new()).expect("empty");
        let gap: BlacklistGap<Fp> = empty.gap(&[0x77; 32]).expect("absent");
        assert_eq!(gap.leaf_index, 0);
        assert!(gap.proves_absent(&empty.root(), &[0x77; 32]));
    }

    #[test]
    fn window_trees_open_every_slot() {
        let windows = [
            QuotaWindow {
                kind: WINDOW_DAILY,
                start_ms: 10,
                end_ms: 20,
                limit: 5,
            },
            QuotaWindow {
                kind: WINDOW_MONTHLY,
                start_ms: 0,
                end_ms: 100,
                limit: 50,
            },
        ];
        let tree = QuotaWindowTree::new(&windows).expect("tree");
        let root: Fp = tree.root();
        for slot in [0, 1, 2, 63] {
            let leaf = tree.slot(slot).leaf::<Fp>();
            let siblings = tree.siblings::<Fp>(slot);
            assert_eq!(
                path_root(QUOTA_NODE_DOMAIN, leaf, slot as u64, &siblings),
                root
            );
        }
        assert_eq!(tree.slot(5), QuotaWindow::EMPTY);
        assert!(QuotaWindowTree::new(&[windows[1], windows[0]]).is_none());
        assert!(windows[0].touches(19, 30) && !windows[0].touches(20, 30));
        assert!(windows[0].touches(0, 10) && !windows[0].touches(0, 9));
        let mut usage = QuotaUsageTree::<Fp>::new(&tree);
        let before = usage.root();
        assert!(usage.set(1, 9));
        assert_eq!(usage.used(1), Some(9));
        assert_ne!(usage.root(), before);
        for slot in [0, 1, 2, 63] {
            assert_eq!(
                path_root(
                    QUOTA_USAGE_NODE_DOMAIN,
                    tree.slot(slot)
                        .usage_value(Fp::from_u128(usage.used(slot).expect("slot"))),
                    slot as u64,
                    &usage.siblings(slot).expect("siblings")
                ),
                usage.root()
            );
        }
        assert!(!usage.set(2, 1));
        assert!(!usage.set(64, 0));
        assert_eq!(usage.used(64), None);
        assert_eq!(usage.siblings(64), None);
    }

    #[test]
    fn indexed_allocator_uses_the_last_slot_then_refuses_without_mutation() {
        let mut tree = IndexedTree::<Fp>::new();
        tree.next_free = u64::from(u32::MAX);
        let last = tree.insert(Fp::from(7), Fp::from(9)).expect("last slot");
        assert_eq!(last.slot, u32::MAX);
        assert_eq!(tree.next_free, 1_u64 << 32);
        let full = tree.clone();
        assert_eq!(tree.insert(Fp::from(8), Fp::from(10)), None);
        assert_eq!(tree, full);
        assert_eq!(tree.insert(Fp::from(7), Fp::from(11)), None);
        assert_eq!(tree, full);
        assert_eq!(tree.get(&Fp::from(7)), Some(Fp::from(9)));
        let removal = tree.remove(&Fp::from(7)).expect("remove final allocation");
        assert_eq!(removal.slot, u32::MAX);
        assert_eq!(tree.root(), IndexedTree::<Fp>::new().root());
        assert_eq!(tree.next_free(), 1_u64 << 32);
        let exhausted = tree.clone();
        assert_eq!(tree.insert(Fp::from(8), Fp::from(10)), None);
        assert_eq!(tree, exhausted);
    }

    fn removal_paths<F: PoseidonField>() {
        let mut tree = IndexedTree::<F>::new();
        for key in [5, 3, 9] {
            tree.insert(F::from(key), F::from(10 * key)).unwrap();
        }
        for key in [5, 9, 3] {
            let before = tree.clone();
            let removed = tree.remove(&F::from(key)).unwrap();
            assert_eq!(removed.predecessor.next_key, F::from(key));
            assert_eq!(removed.leaf.key, F::from(key));
            assert_eq!(removed.leaf.value, F::from(10 * key));
            assert_eq!(
                path_root(
                    INDEXED_NODE_DOMAIN,
                    removed.predecessor.hash(),
                    u64::from(removed.predecessor_slot),
                    &removed.predecessor_siblings
                ),
                before.root(),
            );
            let relinked = IndexedLeaf {
                next_key: removed.leaf.next_key,
                ..removed.predecessor
            };
            let middle = path_root(
                INDEXED_NODE_DOMAIN,
                relinked.hash(),
                u64::from(removed.predecessor_slot),
                &removed.predecessor_siblings,
            );
            assert_eq!(
                path_root(
                    INDEXED_NODE_DOMAIN,
                    removed.leaf.hash(),
                    u64::from(removed.slot),
                    &removed.leaf_siblings
                ),
                middle,
            );
            assert_eq!(
                path_root(
                    INDEXED_NODE_DOMAIN,
                    F::ZERO,
                    u64::from(removed.slot),
                    &removed.leaf_siblings
                ),
                tree.root(),
            );
            assert_eq!(tree.node(0, u64::from(removed.slot)), F::ZERO);
            assert_eq!(tree.get(&F::from(key)), None);
            assert_eq!(tree.next_free(), before.next_free());
            let retained = tree.clone();
            for absent in [F::ZERO, F::from(key), F::from(11)] {
                assert_eq!(tree.remove(&absent), None);
                assert_eq!(tree, retained);
            }
        }
        assert_eq!(tree.root(), IndexedTree::<F>::new().root());
        assert_eq!(tree.insert(F::from(5), F::from(51)).unwrap().slot, 4);
        assert_eq!(tree.get(&F::from(5)), Some(F::from(51)));
        assert_eq!(tree.next_free(), 5);
    }

    #[test]
    fn indexed_removal_relinks_clears_and_never_reuses_in_both_fields() {
        removal_paths::<Fp>();
        removal_paths::<Fq>();
    }

    #[test]
    fn indexed_insertions_verify_against_the_roots() {
        let mut tree = IndexedTree::<Fp>::new();
        assert_eq!(tree.root(), {
            let empty = indexed_empty::<Fp>();
            path_root(
                INDEXED_NODE_DOMAIN,
                IndexedLeaf::<Fp>::sentinel().hash(),
                0,
                &empty[..INDEXED_DEPTH],
            )
        });
        for (key, value) in [(5_u64, 50_u64), (3, 30), (9, 90)] {
            let old = tree.root();
            let key = Fp::from(key);
            let value = Fp::from(value);
            let insertion = tree.insert(key, value).expect("insertion");
            let leaf_root = path_root(
                INDEXED_NODE_DOMAIN,
                insertion.leaf.hash(),
                u64::from(insertion.leaf_slot),
                &insertion.leaf_siblings,
            );
            assert_eq!(leaf_root, old);
            assert!(insertion.leaf.brackets(&key));
            let written = IndexedLeaf {
                next_key: key,
                ..insertion.leaf
            };
            let middle = path_root(
                INDEXED_NODE_DOMAIN,
                written.hash(),
                u64::from(insertion.leaf_slot),
                &insertion.leaf_siblings,
            );
            let slot = u64::from(insertion.slot);
            assert_eq!(
                path_root(
                    INDEXED_NODE_DOMAIN,
                    Fp::ZERO,
                    slot,
                    &insertion.slot_siblings
                ),
                middle
            );
            let content = IndexedLeaf {
                key,
                value,
                next_key: insertion.leaf.next_key,
            }
            .hash();
            assert_eq!(
                path_root(INDEXED_NODE_DOMAIN, content, slot, &insertion.slot_siblings),
                tree.root()
            );
            assert_eq!(tree.get(&key), Some(value));
        }
        assert_eq!(tree.next_free(), 4);
        let original = tree.clone();
        for (key, value) in [
            (Fp::ZERO, Fp::ONE),
            (Fp::from(6), Fp::ZERO),
            (Fp::from(5), Fp::from(55)),
        ] {
            assert!(tree.insert(key, value).is_none());
            assert_eq!(tree, original);
        }
    }
}
