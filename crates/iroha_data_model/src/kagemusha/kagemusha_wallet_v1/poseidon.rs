//! σ-field Poseidon values of the wallet: the `P` and `P_bytes` hashes, their domains and the
//! depth-32 indexed Merkle tree of every wallet map and of the credit-digest tree (§§3, 3.2,
//! 4.1, 5.1; owner answers Q1, Q2, Q9 and Q10, and A2 and A3 of the second set, 2026-10-05).
//!
//! `P(d, items)` is the RP57 Poseidon `iroha_pasta::poseidon::hash_with_domain` with domain word
//! `d` over Pasta `Fp`, the Vesta scalar field in which the step proofs σ are proved. Its value is
//! one canonical field element, carried as its 32-byte little-endian encoding (`< p`). Element
//! lists follow one rule: an integer, tag or mask is one element; a 32-byte SHA-256 digest or
//! identifier is two `u128` limbs, low half first; a `P` value (commitment, chain, root, nonce,
//! `credit_id`, `proof_digest`, Payment, lineage, credit-opening, credit-status or credited
//! digest, signing message) is one element.
//!
//! `P_bytes(d, b) = P(d, [len(b)] || c_0 || ... || c_(m-1))` hashes a byte string: `len(b)` is
//! the byte length as one element, `m = ceil(len(b) / 31)` and `c_i` is bytes `31i .. 31i + 30`
//! of `b` read as a little-endian integer, the last chunk zero-filled. Every chunk is below
//! `2^248 < p`, so the packing is injective for a fixed length and the length element separates
//! lengths.
//!
//! # Indexed Merkle tree (owner answer A2)
//!
//! Every wallet map (consumed-credit, pending-outgoing, load/redeem recovery, fee-claim and
//! quota-usage) and the lineage-level credit-digest tree is a depth-32 Poseidon indexed Merkle
//! tree ([`KagemushaWalletIndexedTreeV1`]):
//!
//! - Slots `0 .. 2^32` are the leaves at height 0. The node at height `h + 1` and index `j` has
//!   the children `2j` (left) and `2j + 1` (right) at height `h`, so bit `h` of the slot index
//!   selects the child at height `h`; the root is the node at height 32. A node is
//!   `P(kgwimnd1, [left, right])`. An empty slot is the element `0`, and an empty subtree of
//!   height `h + 1` is the node over two empty subtrees of height `h`.
//! - An occupied slot holds a leaf `(key, value, next_key)` hashed
//!   `P(kgwimlf1, [key, value, next_key])`. Keys are nonzero canonical values compared as
//!   integers; `next_key` is the next larger key present, or `0` for the largest. The leaves form
//!   one list sorted by key from the zero sentinel leaf `(0, 0, 0)` in slot 0, which alone forms
//!   the empty tree.
//! - Membership of `k` opens the leaf whose key is `k`; non-membership of `x` opens the low leaf
//!   whose key and `next_key` bracket `x`. Insertion updates the low leaf's `next_key` and writes
//!   the new leaf at the next free slot `f`, one more than the highest slot ever written;
//!   removal relinks the predecessor and clears the slot, which is never reused. Every opening
//!   carries exactly 32 siblings, from height 0 upward.

use std::{cmp::Ordering, collections::BTreeMap, sync::OnceLock};

use iroha_pasta::{Fp, PastaField, poseidon::hash_with_domain};

use super::{
    WalletResult,
    digest::{WalletTranscriptV1, kagemusha_wallet_is_canonical_field_v1},
    invalid_v1,
};

#[cfg(test)]
#[path = "poseidon_tests.rs"]
pub(super) mod poseidon_tests;

const fn domain_v1(ascii: [u8; 8]) -> u64 {
    u64::from_le_bytes(ascii)
}

/// Poseidon domain of the state commitment `P(core elements || rest digest)` (§3).
pub const KAGEMUSHA_WALLET_CORE_DOMAIN_V1: u64 = domain_v1(*b"kgwcore1");
/// Poseidon domain of the rest digest (§3).
pub const KAGEMUSHA_WALLET_REST_DOMAIN_V1: u64 = domain_v1(*b"kgwrest1");
/// Poseidon domain of the σ public statement digest (§3.2).
pub const KAGEMUSHA_WALLET_STATEMENT_DOMAIN_V1: u64 = domain_v1(*b"kgwstmt1");
/// Poseidon domain of `credit_id` over the 28 Request body elements (§5.1, owner answers Q1
/// and A5).
pub const KAGEMUSHA_WALLET_CREDIT_DOMAIN_V1: u64 = domain_v1(*b"kgwcrdt1");
/// Poseidon domain of one `send_chain` append (§3).
pub const KAGEMUSHA_WALLET_SEND_CHAIN_DOMAIN_V1: u64 = domain_v1(*b"kgwschn1");
/// Poseidon domain of one `recv_chain` append (§3).
pub const KAGEMUSHA_WALLET_RECV_CHAIN_DOMAIN_V1: u64 = domain_v1(*b"kgwrchn1");
/// Poseidon domain of consumed-credit map values (permanent map).
pub const KAGEMUSHA_WALLET_CONSUMED_CREDIT_VALUE_DOMAIN_V1: u64 = domain_v1(*b"kgwccrd1");
/// Poseidon domain of pending-outgoing map values.
pub const KAGEMUSHA_WALLET_PENDING_OUTGOING_VALUE_DOMAIN_V1: u64 = domain_v1(*b"kgwpout1");
/// Poseidon domain of load values of the load/redeem recovery map.
pub const KAGEMUSHA_WALLET_LOAD_VALUE_DOMAIN_V1: u64 = domain_v1(*b"kgwload1");
/// Poseidon domain of redeem values of the load/redeem recovery map.
pub const KAGEMUSHA_WALLET_REDEEM_VALUE_DOMAIN_V1: u64 = domain_v1(*b"kgwrdm_1");
/// Poseidon domain of fee-claim map values.
pub const KAGEMUSHA_WALLET_FEE_CLAIM_VALUE_DOMAIN_V1: u64 = domain_v1(*b"kgwfee_1");
/// Poseidon domain of quota-usage map values.
pub const KAGEMUSHA_WALLET_QUOTA_USAGE_VALUE_DOMAIN_V1: u64 = domain_v1(*b"kgwquse1");
/// Poseidon domain of lineage-level credit-digest values (§3).
pub const KAGEMUSHA_WALLET_CREDIT_DIGEST_VALUE_DOMAIN_V1: u64 = domain_v1(*b"kgwcdig1");
/// Poseidon domain of an indexed-tree leaf `P(kgwimlf1, [key, value, next_key])`.
pub const KAGEMUSHA_WALLET_INDEXED_LEAF_DOMAIN_V1: u64 = domain_v1(*b"kgwimlf1");
/// Poseidon domain of an indexed-tree node `P(kgwimnd1, [left, right])`.
pub const KAGEMUSHA_WALLET_INDEXED_NODE_DOMAIN_V1: u64 = domain_v1(*b"kgwimnd1");
/// Poseidon domain of a blacklist gap leaf (§7).
pub const KAGEMUSHA_WALLET_BLACKLIST_LEAF_DOMAIN_V1: u64 = domain_v1(*b"kgwblkl1");
/// Poseidon domain of a blacklist tree node (§7).
pub const KAGEMUSHA_WALLET_BLACKLIST_NODE_DOMAIN_V1: u64 = domain_v1(*b"kgwblkn1");
/// Poseidon domain of a quota window leaf (§7).
pub const KAGEMUSHA_WALLET_QUOTA_WINDOW_DOMAIN_V1: u64 = domain_v1(*b"kgwqwin1");
/// Poseidon domain of a quota windows tree node (§7).
pub const KAGEMUSHA_WALLET_QUOTA_NODE_DOMAIN_V1: u64 = domain_v1(*b"kgwqwnd1");
/// `P_bytes` domain of `proof_digest` over `LE32 len(Ω) || Ω || LE32 len(σ) || σ` (Send, Unload,
/// Retiring; §4.1).
pub const KAGEMUSHA_WALLET_PROOF_DOMAIN_V1: u64 = domain_v1(*b"kgwprf_1");
/// `P_bytes` domain of the distinct σ-only `proof_digest` over `LE32 len(σ) || σ` (§4.1).
pub const KAGEMUSHA_WALLET_STEP_PROOF_DOMAIN_V1: u64 = domain_v1(*b"kgwstep1");
/// `P_bytes` domain of the Payment digest over the `payment` transcript (§5.1).
pub const KAGEMUSHA_WALLET_PAYMENT_DOMAIN_V1: u64 = domain_v1(*b"kgwpay_1");
/// `P_bytes` domain of the lineage digest over the Ω bytes (§5.1, owner answer A3).
pub const KAGEMUSHA_WALLET_LINEAGE_DOMAIN_V1: u64 = domain_v1(*b"kgwlin_1");
/// `P_bytes` domain of the credit-opening digest (§5.1, owner answer A3).
pub const KAGEMUSHA_WALLET_CREDIT_OPENING_DOMAIN_V1: u64 = domain_v1(*b"kgwcopn1");
/// `P_bytes` domain of the credit-status digest (§5.1, owner answer A3).
pub const KAGEMUSHA_WALLET_CREDIT_STATUS_DOMAIN_V1: u64 = domain_v1(*b"kgwcsts1");
/// `P_bytes` domain of the Credited digest (§5.1, owner answer A3).
pub const KAGEMUSHA_WALLET_CREDITED_DOMAIN_V1: u64 = domain_v1(*b"kgwcrdd1");

/// Every Poseidon domain of the wallet other than the signing domains
/// ([`super::KagemushaWalletSigningDomainV1`]), by use, in table order.
pub const KAGEMUSHA_WALLET_POSEIDON_DOMAINS_V1: [(&str, u64); 26] = [
    ("core", KAGEMUSHA_WALLET_CORE_DOMAIN_V1),
    ("rest", KAGEMUSHA_WALLET_REST_DOMAIN_V1),
    ("statement", KAGEMUSHA_WALLET_STATEMENT_DOMAIN_V1),
    ("credit_id", KAGEMUSHA_WALLET_CREDIT_DOMAIN_V1),
    ("send_chain", KAGEMUSHA_WALLET_SEND_CHAIN_DOMAIN_V1),
    ("recv_chain", KAGEMUSHA_WALLET_RECV_CHAIN_DOMAIN_V1),
    (
        "consumed_credit_value",
        KAGEMUSHA_WALLET_CONSUMED_CREDIT_VALUE_DOMAIN_V1,
    ),
    (
        "pending_outgoing_value",
        KAGEMUSHA_WALLET_PENDING_OUTGOING_VALUE_DOMAIN_V1,
    ),
    ("load_value", KAGEMUSHA_WALLET_LOAD_VALUE_DOMAIN_V1),
    ("redeem_value", KAGEMUSHA_WALLET_REDEEM_VALUE_DOMAIN_V1),
    (
        "fee_claim_value",
        KAGEMUSHA_WALLET_FEE_CLAIM_VALUE_DOMAIN_V1,
    ),
    (
        "quota_usage_value",
        KAGEMUSHA_WALLET_QUOTA_USAGE_VALUE_DOMAIN_V1,
    ),
    (
        "credit_digest_value",
        KAGEMUSHA_WALLET_CREDIT_DIGEST_VALUE_DOMAIN_V1,
    ),
    ("indexed_leaf", KAGEMUSHA_WALLET_INDEXED_LEAF_DOMAIN_V1),
    ("indexed_node", KAGEMUSHA_WALLET_INDEXED_NODE_DOMAIN_V1),
    ("blacklist_leaf", KAGEMUSHA_WALLET_BLACKLIST_LEAF_DOMAIN_V1),
    ("blacklist_node", KAGEMUSHA_WALLET_BLACKLIST_NODE_DOMAIN_V1),
    ("quota_window_leaf", KAGEMUSHA_WALLET_QUOTA_WINDOW_DOMAIN_V1),
    ("quota_node", KAGEMUSHA_WALLET_QUOTA_NODE_DOMAIN_V1),
    ("proof_digest", KAGEMUSHA_WALLET_PROOF_DOMAIN_V1),
    ("step_proof_digest", KAGEMUSHA_WALLET_STEP_PROOF_DOMAIN_V1),
    ("payment_digest", KAGEMUSHA_WALLET_PAYMENT_DOMAIN_V1),
    ("lineage_digest", KAGEMUSHA_WALLET_LINEAGE_DOMAIN_V1),
    (
        "credit_opening_digest",
        KAGEMUSHA_WALLET_CREDIT_OPENING_DOMAIN_V1,
    ),
    (
        "credit_status_digest",
        KAGEMUSHA_WALLET_CREDIT_STATUS_DOMAIN_V1,
    ),
    ("credited_digest", KAGEMUSHA_WALLET_CREDITED_DOMAIN_V1),
];

/// Bytes of one `P_bytes` chunk: 31, so every chunk is a canonical field element.
pub const KAGEMUSHA_WALLET_PACKED_CHUNK_BYTES_V1: usize = 31;
/// Depth of every indexed Merkle tree: an opening carries exactly this many siblings.
pub const KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1: usize = 32;
/// Number of slots of an indexed Merkle tree, `2^32`.
pub const KAGEMUSHA_WALLET_INDEXED_TREE_SLOTS_V1: u64 = 1 << KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1;
/// Bytes of the concatenated siblings of one opening: 32 values of 32 bytes.
pub const KAGEMUSHA_WALLET_INDEXED_SIBLINGS_BYTES_V1: usize =
    KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1 * 32;
/// Exact leaf-opening transcript bytes: `key || value || next_key || LE32 slot || siblings`.
pub const KAGEMUSHA_WALLET_INDEXED_LEAF_OPENING_TRANSCRIPT_BYTES_V1: usize =
    3 * 32 + 4 + KAGEMUSHA_WALLET_INDEXED_SIBLINGS_BYTES_V1;
/// Exact empty-slot opening transcript bytes: `LE32 slot || siblings`.
pub const KAGEMUSHA_WALLET_INDEXED_EMPTY_OPENING_TRANSCRIPT_BYTES_V1: usize =
    4 + KAGEMUSHA_WALLET_INDEXED_SIBLINGS_BYTES_V1;

// ---------------------------------------------------------------------------------------
// Field conversions and `P`
// ---------------------------------------------------------------------------------------

fn limbs_of_v1(value: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0_u64; 4];
    for (limb, chunk) in limbs.iter_mut().zip(value.chunks_exact(8)) {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        *limb = u64::from_le_bytes(bytes);
    }
    limbs
}

fn bytes_of_limbs_v1(limbs: [u64; 4]) -> [u8; 32] {
    let mut value = [0_u8; 32];
    for (chunk, limb) in value.chunks_exact_mut(8).zip(limbs) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    value
}

/// The field element of a canonical encoding, or `None` for a value `>= p`.
fn field_of_v1(value: &[u8; 32]) -> Option<Fp> {
    Option::from(Fp::from_canonical_limbs(limbs_of_v1(value)))
}

/// Canonical encoding of a field element.
fn bytes_of_field_v1(value: &Fp) -> [u8; 32] {
    bytes_of_limbs_v1(value.to_canonical_limbs())
}

/// `P(domain, items)` over elements that are canonical by construction: integers, limbs and
/// field values already validated by their owner.
///
/// Every caller builds its items from integers below `2^128`, chunks below `2^248` or field
/// values it validated; the reduction never applies to such an item.
pub(super) fn poseidon_items_v1(domain: u64, items: &[[u8; 32]]) -> [u8; 32] {
    let inputs: Vec<Fp> = items
        .iter()
        .map(|item| {
            debug_assert!(kagemusha_wallet_is_canonical_field_v1(item));
            Fp::from_raw_reduced(limbs_of_v1(item))
        })
        .collect();
    bytes_of_field_v1(&hash_with_domain(domain, &inputs))
}

/// `P(domain, items)`: the RP57 Poseidon hash of canonical σ-field elements (§3).
///
/// # Errors
///
/// Rejects an item that is not a canonical encoding (`>= p`).
pub fn kagemusha_wallet_poseidon_v1(domain: u64, items: &[[u8; 32]]) -> WalletResult<[u8; 32]> {
    let inputs = items
        .iter()
        .map(|item| field_of_v1(item).ok_or_else(|| invalid_v1("poseidon.item")))
        .collect::<WalletResult<Vec<Fp>>>()?;
    Ok(bytes_of_field_v1(&hash_with_domain(domain, &inputs)))
}

/// The `P_bytes` element list of `bytes`: the byte length as one element, then the 31-byte
/// little-endian chunks, the last one zero-filled.
#[must_use]
pub fn kagemusha_wallet_packed_bytes_v1(bytes: &[u8]) -> Vec<[u8; 32]> {
    let chunks = bytes.len().div_ceil(KAGEMUSHA_WALLET_PACKED_CHUNK_BYTES_V1);
    let mut items = Vec::with_capacity(chunks.saturating_add(1));
    // `usize` is at most 64 bits on every admitted target, so the length is exact.
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let mut length = [0_u8; 32];
    length[..8].copy_from_slice(&len.to_le_bytes());
    items.push(length);
    for chunk in bytes.chunks(KAGEMUSHA_WALLET_PACKED_CHUNK_BYTES_V1) {
        let mut item = [0_u8; 32];
        item[..chunk.len()].copy_from_slice(chunk);
        items.push(item);
    }
    items
}

/// `P_bytes(domain, bytes)`: Poseidon over the packed bytes (§3).
#[must_use]
pub fn kagemusha_wallet_poseidon_bytes_v1(domain: u64, bytes: &[u8]) -> [u8; 32] {
    poseidon_items_v1(domain, &kagemusha_wallet_packed_bytes_v1(bytes))
}

// ---------------------------------------------------------------------------------------
// Integer order and map keys
// ---------------------------------------------------------------------------------------

/// Integer order of two 32-byte little-endian values: the 32 bytes read as one little-endian
/// integer, `hi · 2^128 + lo` of their two σ limbs (§§3.2, 3.3; owner answer A4).
///
/// It orders indexed-tree keys (canonical σ-field values compared as integers in `[0, p)`) and
/// blacklist entries (limb order, compare `hi` then `lo`).
#[must_use]
pub fn kagemusha_wallet_integer_cmp_v1(left: &[u8; 32], right: &[u8; 32]) -> Ordering {
    left.iter().rev().cmp(right.iter().rev())
}

/// Map key of an integer pair `(high, low)`: `high · 2^128 + low`, a canonical element for every
/// `high < 2^125`. The load/redeem recovery map uses `(kind, ordinal)` (owner answer Q3) and the
/// quota-usage map `(window kind, window start)`.
#[must_use]
pub fn kagemusha_wallet_pair_key_v1(high: u8, low: u128) -> [u8; 32] {
    let mut key = [0_u8; 32];
    key[..16].copy_from_slice(&low.to_le_bytes());
    key[16] = high;
    key
}

/// Big-endian form of a little-endian value, whose byte order is the integer order.
fn order_key_v1(value: &[u8; 32]) -> [u8; 32] {
    let mut key = *value;
    key.reverse();
    key
}

fn is_zero_field_v1(value: &[u8; 32]) -> bool {
    value.iter().all(|byte| *byte == 0)
}

// ---------------------------------------------------------------------------------------
// Indexed Merkle tree (depth 32; owner answer A2)
// ---------------------------------------------------------------------------------------

/// Indexed-tree node `P(kgwimnd1, [left, right])` over canonical children.
///
/// # Errors
///
/// Rejects a noncanonical child.
pub fn kagemusha_wallet_indexed_node_v1(
    left: &[u8; 32],
    right: &[u8; 32],
) -> WalletResult<[u8; 32]> {
    kagemusha_wallet_poseidon_v1(KAGEMUSHA_WALLET_INDEXED_NODE_DOMAIN_V1, &[*left, *right])
}

fn indexed_node_v1(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    poseidon_items_v1(KAGEMUSHA_WALLET_INDEXED_NODE_DOMAIN_V1, &[*left, *right])
}

fn indexed_empty_v1() -> &'static [[u8; 32]; KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1 + 1] {
    static EMPTY: OnceLock<[[u8; 32]; KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1 + 1]> =
        OnceLock::new();
    EMPTY.get_or_init(|| {
        let mut empty = [[0_u8; 32]; KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1 + 1];
        for height in 0..KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1 {
            let child = empty[height];
            empty[height + 1] = indexed_node_v1(&child, &child);
        }
        empty
    })
}

/// Root of the empty subtree of `height`: `0` for an empty slot (height 0), and the node over
/// two empty subtrees of `height − 1` above it.
///
/// # Errors
///
/// Rejects a height above [`KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1`].
pub fn kagemusha_wallet_indexed_empty_subtree_v1(height: usize) -> WalletResult<[u8; 32]> {
    indexed_empty_v1()
        .get(height)
        .copied()
        .ok_or_else(|| invalid_v1("indexed_tree.height"))
}

/// Root of the empty indexed tree, holding only the zero sentinel leaf `(0, 0, 0)` in slot 0:
/// the empty root of every wallet map and the Λ base-case credit-digest root (§§3, 3.2).
#[must_use]
pub fn kagemusha_wallet_empty_map_root_v1() -> [u8; 32] {
    static ROOT: OnceLock<[u8; 32]> = OnceLock::new();
    *ROOT.get_or_init(|| KagemushaWalletIndexedTreeV1::new().root())
}

/// One leaf `(key, value, next_key)` of an indexed tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletIndexedLeafV1 {
    /// Map key: a canonical σ-field value; zero only for the sentinel.
    pub key: [u8; 32],
    /// Map value `P(value domain, elements)`; zero only for the sentinel.
    pub value: [u8; 32],
    /// Next larger key present, or zero for the largest key.
    pub next_key: [u8; 32],
}

impl KagemushaWalletIndexedLeafV1 {
    /// The zero sentinel leaf `(0, 0, 0)` of slot 0.
    pub const SENTINEL: Self = Self {
        key: [0; 32],
        value: [0; 32],
        next_key: [0; 32],
    };

    /// Validate the leaf: canonical fields and `next_key` zero or above `key`.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical field and a `next_key` that is nonzero and not above `key`.
    pub fn validate(&self) -> WalletResult<()> {
        for value in [&self.key, &self.value, &self.next_key] {
            if !kagemusha_wallet_is_canonical_field_v1(value) {
                return Err(invalid_v1("indexed_leaf.field"));
            }
        }
        if !is_zero_field_v1(&self.next_key)
            && kagemusha_wallet_integer_cmp_v1(&self.next_key, &self.key) != Ordering::Greater
        {
            return Err(invalid_v1("indexed_leaf.next_key"));
        }
        Ok(())
    }

    /// Leaf hash `P(kgwimlf1, [key, value, next_key])`.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate`] rejects.
    pub fn hash(&self) -> WalletResult<[u8; 32]> {
        self.validate()?;
        Ok(self.hash_unchecked())
    }

    fn hash_unchecked(&self) -> [u8; 32] {
        poseidon_items_v1(
            KAGEMUSHA_WALLET_INDEXED_LEAF_DOMAIN_V1,
            &[self.key, self.value, self.next_key],
        )
    }

    /// Whether this leaf is the low leaf of an absent `key`: `self.key < key` and
    /// (`next_key = 0` or `key < next_key`).
    #[must_use]
    pub fn brackets(&self, key: &[u8; 32]) -> bool {
        kagemusha_wallet_integer_cmp_v1(&self.key, key) == Ordering::Less
            && (is_zero_field_v1(&self.next_key)
                || kagemusha_wallet_integer_cmp_v1(key, &self.next_key) == Ordering::Less)
    }
}

/// Opening of one slot of an indexed tree: its slot index and exactly 32 siblings, from height
/// 0 upward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletIndexedOpeningV1 {
    /// Opened slot.
    pub slot: u32,
    /// Sibling σ-field values, height 0 first.
    pub siblings: [[u8; 32]; KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1],
}

impl KagemushaWalletIndexedOpeningV1 {
    /// Parse the opening of `slot` from exactly 1,024 concatenated sibling bytes.
    ///
    /// # Errors
    ///
    /// Rejects another length and a noncanonical sibling.
    pub fn from_sibling_bytes(slot: u32, bytes: &[u8]) -> WalletResult<Self> {
        if bytes.len() != KAGEMUSHA_WALLET_INDEXED_SIBLINGS_BYTES_V1 {
            return Err(invalid_v1("indexed_opening.siblings"));
        }
        let mut siblings = [[0_u8; 32]; KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1];
        for (sibling, chunk) in siblings.iter_mut().zip(bytes.chunks_exact(32)) {
            sibling.copy_from_slice(chunk);
            if !kagemusha_wallet_is_canonical_field_v1(sibling) {
                return Err(invalid_v1("indexed_opening.sibling"));
            }
        }
        Ok(Self { slot, siblings })
    }

    /// The 1,024 concatenated sibling bytes, height 0 first.
    #[must_use]
    pub fn sibling_bytes(&self) -> Vec<u8> {
        self.siblings.concat()
    }

    /// Root recomputed from `node` at the opened slot.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical node or sibling.
    pub fn root_over(&self, node: &[u8; 32]) -> WalletResult<[u8; 32]> {
        if !kagemusha_wallet_is_canonical_field_v1(node) {
            return Err(invalid_v1("indexed_opening.node"));
        }
        let mut current = *node;
        for (height, sibling) in self.siblings.iter().enumerate() {
            if !kagemusha_wallet_is_canonical_field_v1(sibling) {
                return Err(invalid_v1("indexed_opening.sibling"));
            }
            current = if (self.slot >> height) & 1 == 1 {
                indexed_node_v1(sibling, &current)
            } else {
                indexed_node_v1(&current, sibling)
            };
        }
        Ok(current)
    }

    /// Root recomputed from `leaf` at the opened slot.
    ///
    /// # Errors
    ///
    /// Rejects an invalid leaf and what [`Self::root_over`] rejects.
    pub fn leaf_root(&self, leaf: &KagemushaWalletIndexedLeafV1) -> WalletResult<[u8; 32]> {
        self.root_over(&leaf.hash()?)
    }

    /// Root recomputed with the opened slot empty.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::root_over`] rejects.
    pub fn empty_root(&self) -> WalletResult<[u8; 32]> {
        self.root_over(&[0; 32])
    }

    /// Exact leaf-opening transcript `key || value || next_key || LE32 slot || siblings`
    /// (1,124 bytes).
    #[must_use]
    pub fn leaf_transcript(&self, leaf: &KagemushaWalletIndexedLeafV1) -> Vec<u8> {
        WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_INDEXED_LEAF_OPENING_TRANSCRIPT_BYTES_V1)
            .digest(&leaf.key)
            .digest(&leaf.value)
            .digest(&leaf.next_key)
            .u32(self.slot)
            .bytes(&self.sibling_bytes())
            .finish()
    }

    /// Exact empty-slot opening transcript `LE32 slot || siblings` (1,028 bytes).
    #[must_use]
    pub fn empty_transcript(&self) -> Vec<u8> {
        WalletTranscriptV1::with_capacity(
            KAGEMUSHA_WALLET_INDEXED_EMPTY_OPENING_TRANSCRIPT_BYTES_V1,
        )
        .u32(self.slot)
        .bytes(&self.sibling_bytes())
        .finish()
    }
}

/// Require that `leaf` sits at `opening` under `root`.
fn require_leaf_root_v1(
    root: &[u8; 32],
    leaf: &KagemushaWalletIndexedLeafV1,
    opening: &KagemushaWalletIndexedOpeningV1,
) -> WalletResult<()> {
    if opening.leaf_root(leaf)? == *root {
        Ok(())
    } else {
        Err(invalid_v1("indexed_opening.root"))
    }
}

/// Require a nonzero canonical map key.
fn require_key_v1(key: &[u8; 32]) -> WalletResult<()> {
    if is_zero_field_v1(key) || !kagemusha_wallet_is_canonical_field_v1(key) {
        return Err(invalid_v1("indexed_tree.key"));
    }
    Ok(())
}

/// Verify that `opening` proves `leaf` (a nonzero key) present under `root`.
///
/// # Errors
///
/// Rejects a zero or noncanonical key, an invalid leaf or opening, and another root.
pub fn kagemusha_wallet_indexed_verify_membership_v1(
    root: &[u8; 32],
    leaf: &KagemushaWalletIndexedLeafV1,
    opening: &KagemushaWalletIndexedOpeningV1,
) -> WalletResult<()> {
    require_key_v1(&leaf.key)?;
    require_leaf_root_v1(root, leaf, opening)
}

/// Verify that the low leaf `low` at `opening` proves `key` absent under `root`.
///
/// # Errors
///
/// Rejects a zero or noncanonical key, a leaf that does not bracket `key`, an invalid leaf or
/// opening, and another root.
pub fn kagemusha_wallet_indexed_verify_non_membership_v1(
    root: &[u8; 32],
    key: &[u8; 32],
    low: &KagemushaWalletIndexedLeafV1,
    opening: &KagemushaWalletIndexedOpeningV1,
) -> WalletResult<()> {
    require_key_v1(key)?;
    if !low.brackets(key) {
        return Err(invalid_v1("indexed_tree.low_leaf"));
    }
    require_leaf_root_v1(root, low, opening)
}

/// Witness of one insertion of `(key, value)`: the low leaf and its opening against the old
/// root, and the empty-slot opening of the written slot against the root after the low leaf's
/// update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletIndexedInsertV1 {
    /// Low leaf `(k, w, n)` before the insertion.
    pub low: KagemushaWalletIndexedLeafV1,
    /// Opening of the low leaf against the old root.
    pub low_opening: KagemushaWalletIndexedOpeningV1,
    /// Empty-slot opening of the written slot against the intermediate root.
    pub slot_opening: KagemushaWalletIndexedOpeningV1,
}

impl KagemushaWalletIndexedInsertV1 {
    /// Verify the insertion of `(key, value)` under `old_root` and return the new root.
    ///
    /// Non-membership of `key` through the low leaf `(k, w, n)`; the low leaf becomes
    /// `(k, w, key)`; the written slot opens empty in that intermediate root and receives
    /// `(key, value, n)`.
    ///
    /// # Errors
    ///
    /// Rejects what [`kagemusha_wallet_indexed_verify_non_membership_v1`] rejects, a zero or
    /// noncanonical value, and a written slot that is not empty in the intermediate root.
    pub fn verify(
        &self,
        old_root: &[u8; 32],
        key: &[u8; 32],
        value: &[u8; 32],
    ) -> WalletResult<[u8; 32]> {
        kagemusha_wallet_indexed_verify_non_membership_v1(
            old_root,
            key,
            &self.low,
            &self.low_opening,
        )?;
        if is_zero_field_v1(value) || !kagemusha_wallet_is_canonical_field_v1(value) {
            return Err(invalid_v1("indexed_tree.value"));
        }
        let linked = KagemushaWalletIndexedLeafV1 {
            next_key: *key,
            ..self.low
        };
        let intermediate = self.low_opening.leaf_root(&linked)?;
        if self.slot_opening.empty_root()? != intermediate {
            return Err(invalid_v1("indexed_tree.slot"));
        }
        self.slot_opening.leaf_root(&KagemushaWalletIndexedLeafV1 {
            key: *key,
            value: *value,
            next_key: self.low.next_key,
        })
    }
}

/// Witness of one in-place value update: the leaf and its opening against the old root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletIndexedUpdateV1 {
    /// Leaf before the update.
    pub leaf: KagemushaWalletIndexedLeafV1,
    /// Opening of the leaf against the old root.
    pub opening: KagemushaWalletIndexedOpeningV1,
}

impl KagemushaWalletIndexedUpdateV1 {
    /// Verify the update of the leaf's value to `value` under `old_root` and return the new
    /// root.
    ///
    /// # Errors
    ///
    /// Rejects what [`kagemusha_wallet_indexed_verify_membership_v1`] rejects and a zero or
    /// noncanonical value.
    pub fn verify(&self, old_root: &[u8; 32], value: &[u8; 32]) -> WalletResult<[u8; 32]> {
        kagemusha_wallet_indexed_verify_membership_v1(old_root, &self.leaf, &self.opening)?;
        if is_zero_field_v1(value) || !kagemusha_wallet_is_canonical_field_v1(value) {
            return Err(invalid_v1("indexed_tree.value"));
        }
        self.opening.leaf_root(&KagemushaWalletIndexedLeafV1 {
            value: *value,
            ..self.leaf
        })
    }
}

/// Witness of one removal (`ArchiveSent` on the pending-outgoing map): the predecessor leaf
/// `(k', w', k)` and its opening against the old root, then the removed leaf `(k, v, n)` and its
/// opening against the root after the predecessor is relinked to `n`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletIndexedRemoveV1 {
    /// Predecessor leaf `(k', w', k)` before the removal.
    pub predecessor: KagemushaWalletIndexedLeafV1,
    /// Opening of the predecessor against the old root.
    pub predecessor_opening: KagemushaWalletIndexedOpeningV1,
    /// Removed leaf `(k, v, n)`.
    pub leaf: KagemushaWalletIndexedLeafV1,
    /// Opening of the removed leaf against the intermediate root.
    pub leaf_opening: KagemushaWalletIndexedOpeningV1,
}

impl KagemushaWalletIndexedRemoveV1 {
    /// Verify the removal of `key` under `old_root` and return the new root.
    ///
    /// # Errors
    ///
    /// Rejects a zero or noncanonical key, a predecessor whose `next_key` is not `key`, a
    /// removed leaf of another key or at the predecessor's slot, invalid leaves or openings, and
    /// another root.
    pub fn verify(&self, old_root: &[u8; 32], key: &[u8; 32]) -> WalletResult<[u8; 32]> {
        require_key_v1(key)?;
        if self.predecessor.next_key != *key || self.leaf.key != *key {
            return Err(invalid_v1("indexed_tree.remove"));
        }
        if self.leaf_opening.slot == self.predecessor_opening.slot {
            return Err(invalid_v1("indexed_tree.remove"));
        }
        require_leaf_root_v1(old_root, &self.predecessor, &self.predecessor_opening)?;
        let relinked = KagemushaWalletIndexedLeafV1 {
            next_key: self.leaf.next_key,
            ..self.predecessor
        };
        let intermediate = self.predecessor_opening.leaf_root(&relinked)?;
        require_leaf_root_v1(&intermediate, &self.leaf, &self.leaf_opening)?;
        self.leaf_opening.empty_root()
    }
}

/// Native depth-32 indexed Merkle tree of one wallet map (§3.2, owner answer A2).
///
/// This is the native helper of a map's owner; its roots and openings are the in-circuit
/// values. Values are the `P` map values of the map's entry type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KagemushaWalletIndexedTreeV1 {
    /// Occupied slots and their leaves; slot 0 always holds the sentinel.
    slots: BTreeMap<u32, KagemushaWalletIndexedLeafV1>,
    /// Slot of every key, the sentinel's zero key included, in integer order.
    keys: BTreeMap<[u8; 32], u32>,
    /// Nodes that differ from the empty subtree, per height (0 is the leaf level).
    nodes: Vec<BTreeMap<u64, [u8; 32]>>,
    /// One more than the highest slot ever written.
    next_free: u64,
}

impl Default for KagemushaWalletIndexedTreeV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl KagemushaWalletIndexedTreeV1 {
    /// The empty tree: the zero sentinel leaf in slot 0.
    #[must_use]
    pub fn new() -> Self {
        let mut tree = Self {
            slots: BTreeMap::new(),
            keys: BTreeMap::new(),
            nodes: vec![BTreeMap::new(); KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1 + 1],
            next_free: 1,
        };
        tree.keys.insert([0; 32], 0);
        tree.write_slot(0, Some(KagemushaWalletIndexedLeafV1::SENTINEL));
        tree
    }

    /// Root of the tree.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.node(KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1, 0)
    }

    /// Number of keys present, the sentinel excluded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len().saturating_sub(1)
    }

    /// Whether the tree holds no key besides the sentinel.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// One more than the highest slot ever written: the slot of the next insertion.
    #[must_use]
    pub const fn next_free_slot(&self) -> u64 {
        self.next_free
    }

    /// Value of `key`, if present.
    #[must_use]
    pub fn get(&self, key: &[u8; 32]) -> Option<[u8; 32]> {
        if is_zero_field_v1(key) {
            return None;
        }
        let slot = self.keys.get(&order_key_v1(key))?;
        self.slots.get(slot).map(|leaf| leaf.value)
    }

    /// Leaf held by `slot`, if occupied.
    #[must_use]
    pub fn leaf_at(&self, slot: u32) -> Option<KagemushaWalletIndexedLeafV1> {
        self.slots.get(&slot).copied()
    }

    fn node(&self, height: usize, index: u64) -> [u8; 32] {
        self.nodes[height]
            .get(&index)
            .copied()
            .unwrap_or(indexed_empty_v1()[height])
    }

    /// Opening of `slot` against the current root.
    #[must_use]
    pub fn opening(&self, slot: u32) -> KagemushaWalletIndexedOpeningV1 {
        let mut siblings = [[0_u8; 32]; KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1];
        let mut index = u64::from(slot);
        for (height, sibling) in siblings.iter_mut().enumerate() {
            *sibling = self.node(height, index ^ 1);
            index >>= 1;
        }
        KagemushaWalletIndexedOpeningV1 { slot, siblings }
    }

    /// Write `leaf` (or empty) at `slot` and recompute the path to the root.
    fn write_slot(&mut self, slot: u32, leaf: Option<KagemushaWalletIndexedLeafV1>) {
        let empty = indexed_empty_v1();
        let mut index = u64::from(slot);
        match leaf {
            Some(leaf) => {
                self.slots.insert(slot, leaf);
                self.nodes[0].insert(index, leaf.hash_unchecked());
            }
            None => {
                self.slots.remove(&slot);
                self.nodes[0].remove(&index);
            }
        }
        for height in 0..KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1 {
            let left = self.node(height, index & !1);
            let right = self.node(height, index | 1);
            index >>= 1;
            let parent = indexed_node_v1(&left, &right);
            if parent == empty[height + 1] {
                self.nodes[height + 1].remove(&index);
            } else {
                self.nodes[height + 1].insert(index, parent);
            }
        }
    }

    /// Slot and leaf of a present nonzero `key`.
    fn present(&self, key: &[u8; 32]) -> WalletResult<(u32, KagemushaWalletIndexedLeafV1)> {
        require_key_v1(key)?;
        let slot = *self
            .keys
            .get(&order_key_v1(key))
            .ok_or_else(|| invalid_v1("indexed_tree.absent"))?;
        let leaf = self
            .leaf_at(slot)
            .ok_or_else(|| invalid_v1("indexed_tree.slot"))?;
        Ok((slot, leaf))
    }

    /// Slot and leaf of the low leaf of an absent nonzero `key`.
    fn low(&self, key: &[u8; 32]) -> WalletResult<(u32, KagemushaWalletIndexedLeafV1)> {
        require_key_v1(key)?;
        let order = order_key_v1(key);
        if self.keys.contains_key(&order) {
            return Err(invalid_v1("indexed_tree.present"));
        }
        let (_, slot) = self
            .keys
            .range(..order)
            .next_back()
            .ok_or_else(|| invalid_v1("indexed_tree.low_leaf"))?;
        let leaf = self
            .leaf_at(*slot)
            .ok_or_else(|| invalid_v1("indexed_tree.slot"))?;
        Ok((*slot, leaf))
    }

    /// Membership opening of a present `key`: its leaf and the opening of its slot.
    ///
    /// # Errors
    ///
    /// Rejects a zero, noncanonical or absent key.
    pub fn membership(
        &self,
        key: &[u8; 32],
    ) -> WalletResult<(
        KagemushaWalletIndexedLeafV1,
        KagemushaWalletIndexedOpeningV1,
    )> {
        let (slot, leaf) = self.present(key)?;
        Ok((leaf, self.opening(slot)))
    }

    /// Non-membership opening of an absent `key`: its low leaf and the opening of that slot.
    ///
    /// # Errors
    ///
    /// Rejects a zero, noncanonical or present key.
    pub fn non_membership(
        &self,
        key: &[u8; 32],
    ) -> WalletResult<(
        KagemushaWalletIndexedLeafV1,
        KagemushaWalletIndexedOpeningV1,
    )> {
        let (slot, leaf) = self.low(key)?;
        Ok((leaf, self.opening(slot)))
    }

    /// Insert an absent `key` with `value` at the next free slot and return the witness.
    ///
    /// # Errors
    ///
    /// Rejects a zero, noncanonical or present key, a zero or noncanonical value, and a full
    /// tree (next free slot `2^32`). The tree is unchanged on error.
    pub fn insert(
        &mut self,
        key: [u8; 32],
        value: [u8; 32],
    ) -> WalletResult<KagemushaWalletIndexedInsertV1> {
        let (low_slot, low) = self.low(&key)?;
        if is_zero_field_v1(&value) || !kagemusha_wallet_is_canonical_field_v1(&value) {
            return Err(invalid_v1("indexed_tree.value"));
        }
        let slot = u32::try_from(self.next_free).map_err(|_| invalid_v1("indexed_tree.full"))?;
        let low_opening = self.opening(low_slot);
        self.write_slot(
            low_slot,
            Some(KagemushaWalletIndexedLeafV1 {
                next_key: key,
                ..low
            }),
        );
        let slot_opening = self.opening(slot);
        self.write_slot(
            slot,
            Some(KagemushaWalletIndexedLeafV1 {
                key,
                value,
                next_key: low.next_key,
            }),
        );
        self.keys.insert(order_key_v1(&key), slot);
        self.next_free = self.next_free.saturating_add(1);
        Ok(KagemushaWalletIndexedInsertV1 {
            low,
            low_opening,
            slot_opening,
        })
    }

    /// Replace the value of a present `key` and return the witness.
    ///
    /// # Errors
    ///
    /// Rejects a zero, noncanonical or absent key and a zero or noncanonical value.
    pub fn update(
        &mut self,
        key: &[u8; 32],
        value: [u8; 32],
    ) -> WalletResult<KagemushaWalletIndexedUpdateV1> {
        let (slot, leaf) = self.present(key)?;
        if is_zero_field_v1(&value) || !kagemusha_wallet_is_canonical_field_v1(&value) {
            return Err(invalid_v1("indexed_tree.value"));
        }
        let opening = self.opening(slot);
        self.write_slot(slot, Some(KagemushaWalletIndexedLeafV1 { value, ..leaf }));
        Ok(KagemushaWalletIndexedUpdateV1 { leaf, opening })
    }

    /// Remove a present `key`: relink its predecessor and clear its slot, which is never
    /// reused. Returns the witness.
    ///
    /// # Errors
    ///
    /// Rejects a zero, noncanonical or absent key.
    pub fn remove(&mut self, key: &[u8; 32]) -> WalletResult<KagemushaWalletIndexedRemoveV1> {
        let (slot, leaf) = self.present(key)?;
        let order = order_key_v1(key);
        let (_, predecessor_slot) = self
            .keys
            .range(..order)
            .next_back()
            .ok_or_else(|| invalid_v1("indexed_tree.low_leaf"))?;
        let predecessor_slot = *predecessor_slot;
        let predecessor = self
            .leaf_at(predecessor_slot)
            .ok_or_else(|| invalid_v1("indexed_tree.slot"))?;
        let predecessor_opening = self.opening(predecessor_slot);
        self.write_slot(
            predecessor_slot,
            Some(KagemushaWalletIndexedLeafV1 {
                next_key: leaf.next_key,
                ..predecessor
            }),
        );
        let leaf_opening = self.opening(slot);
        self.write_slot(slot, None);
        self.keys.remove(&order);
        Ok(KagemushaWalletIndexedRemoveV1 {
            predecessor,
            predecessor_opening,
            leaf,
            leaf_opening,
        })
    }
}
