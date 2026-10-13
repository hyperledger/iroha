//! Development-only prototypes of the keyed State commitment candidates.
//!
//! ZK delivery plan task G.2 measures authenticated-map constructions and hash
//! profiles against the construction-independent contract of
//! `specs/sumeragi.md` §16 before task G.3 selects one. This module holds every
//! prototype in one place so the native candidates, their witness formats and
//! the in-circuit witness relations cannot drift apart:
//!
//! - [`hash`]: one native-fast profile over raw BLAKE2b-256, two
//!   arithmetization-friendly sponge profiles over Goldilocks (Poseidon2 and
//!   Rescue-Prime, each with published parameters and a pinned known-answer
//!   vector) and the repository's own six-lane Poseidon digest as a native
//!   comparator;
//! - [`radix`], [`btree`], [`linked`] and [`chain`]: four different
//!   constructions behind one [`Engine`] interface;
//! - [`keyed`]: the multi-table wrapper that binds the schema descriptor and
//!   normalises the 32-byte root;
//! - [`circuit`]: the hash-chain relation written against [`crate::air`] and
//!   the programs that verify inclusion, absence and complete-range witnesses
//!   of the tree candidates;
//! - [`key_gadgets`]: the byte-order and key-bit relations a private key needs
//!   beside the hash chain, built and checked on their own;
//! - [`workload`]: the deterministic workloads the measurement run uses.
//!
//! Nothing here is consensus code. The module is compiled only for tests and
//! under the `dev-tools` feature, no root it produces is published, certified
//! or admitted, and no witness format here is a wire format. Conformance with
//! rules K1..K12 is checked in `iroha_core` by thin adapters
//! (`keyed_commitment/candidates_tests.rs`), which own no construction logic.
//!
//! TODO(G.3): delete this module together with its adapters once the selected
//! construction is implemented by its State owner. No prototype may survive
//! as a second implementation of the selected construction.

pub mod btree;
pub mod chain;
pub mod circuit;
mod codec;
mod critbit;
mod fringe;
pub mod hash;
pub mod key_gadgets;
pub mod keyed;
pub mod linked;
pub mod poseidon2;
pub mod radix;
pub mod rescue;
pub mod workload;

pub use hash::{Digest, HashProfile, ZERO_DIGEST};
pub use keyed::{KeyedMap, PrototypeSchema};

/// Namespace of every prototype hash domain: ASCII `G2` in the high half.
const DOMAIN_NAMESPACE: u64 = 0x4732 << 32;

/// Domain of the schema descriptor digest.
pub const DOMAIN_SCHEMA: u64 = DOMAIN_NAMESPACE | 1;
/// Domain of a composite key digest.
pub const DOMAIN_KEY: u64 = DOMAIN_NAMESPACE | 2;
/// Domain of a value digest.
pub const DOMAIN_VALUE: u64 = DOMAIN_NAMESPACE | 3;
/// Domain of an entry leaf: key digest and value digest.
pub const DOMAIN_LEAF: u64 = DOMAIN_NAMESPACE | 4;
/// Domain of a radix branch; the auxiliary word is the branching bit index.
pub const DOMAIN_BRANCH: u64 = DOMAIN_NAMESPACE | 5;
/// Domain of the normalised root: structure root and schema digest.
pub const DOMAIN_ROOT: u64 = DOMAIN_NAMESPACE | 6;
/// Domain of a linked leaf: entry leaf and successor key digest.
pub const DOMAIN_LINK: u64 = DOMAIN_NAMESPACE | 7;
/// Domain of the digest of the lower sentinel of the linked-leaf map.
pub const DOMAIN_BOUND_HEAD: u64 = DOMAIN_NAMESPACE | 8;
/// Domain of the digest of the upper sentinel of the linked-leaf map.
pub const DOMAIN_BOUND_END: u64 = DOMAIN_NAMESPACE | 9;
/// Domain of a hash-chain step and of the chain's start value.
pub const DOMAIN_CHAIN: u64 = DOMAIN_NAMESPACE | 10;
/// Domain of an interior node of the sorted Merkle B-tree.
pub const DOMAIN_PAGE_NODE: u64 = DOMAIN_NAMESPACE | 11;

/// Why a carried witness does not establish its statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// The bytes are not a canonical witness of the construction.
    Malformed,
    /// The witness is well formed but does not establish the statement at the root.
    NotProven,
}

/// Accounting model of one construction's authenticated structure as a
/// persisted node store would hold it, excluding the committed key and value
/// payload bytes themselves.
///
/// The node counts are read from the structure the engine holds. The bytes per
/// node are declared constants of each construction (`MODEL_*_BYTES` in its
/// module): what a node store would keep, not what the prototype's in-memory
/// containers occupy. The figures are therefore a model, not a measurement;
/// the heap the prototype really holds is measured by the measurement run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Storage {
    /// Committed entries.
    pub entries: u64,
    /// Digests the model keeps (leaves, value digests, interior nodes, cached
    /// accumulators), counted from the nodes the engine holds.
    pub digests: u64,
    /// Modelled bytes of the authenticated structure: digests, child
    /// references and node metadata.
    pub structure_bytes: u64,
    /// Modelled bytes of an unauthenticated auxiliary index the prover needs
    /// beside the structure (for example the sorted key index of the
    /// linked-leaf map), excluding the key bytes it indexes.
    pub auxiliary_bytes: u64,
    /// Longest root-to-leaf path in authenticated nodes.
    pub max_depth: u32,
}

/// One net change over composite keys: the value after the change, or `None`
/// for an absent key.
pub type Change<'a> = (&'a [u8], Option<&'a [u8]>);

/// One authenticated ordered map over composite byte-string keys.
///
/// Keys are compared as byte strings. The multi-table semantics, the schema
/// binding and the root normalisation belong to [`KeyedMap`]; an engine only
/// commits a finite map from keys to value digests and reconstructs, from a
/// witness of one of the three statement kinds, the structure root at which
/// that statement holds. An engine is cloned to replay the same change sets
/// from one state.
pub trait Engine: Sized + Clone {
    /// Hash profile of every digest of the structure.
    type Hash: HashProfile;

    /// Stable identity of the construction and its parameters.
    const CONSTRUCTION: &'static str;

    /// The empty map.
    fn new() -> Self;

    /// Apply one net change set. Every key occurs at most once; removing an
    /// absent key and rewriting an equal value change nothing.
    fn apply(&mut self, changes: &[Change<'_>]);

    /// Root of the structure: a function of the committed entries alone.
    fn structure_root(&self) -> Digest;

    /// Number of committed entries.
    fn len(&self) -> u64;

    /// Whether the map holds no entry.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Witness that `key` is present, or `None` when it is absent.
    fn prove_inclusion(&self, key: &[u8]) -> Option<Vec<u8>>;

    /// Witness that `key` is absent, or `None` when it is present.
    fn prove_absence(&self, key: &[u8]) -> Option<Vec<u8>>;

    /// Witness of every entry with `lower <= key < upper`; `None` is unbounded.
    fn prove_range(&self, lower: &[u8], upper: Option<&[u8]>) -> Vec<u8>;

    /// The structure root implied by an inclusion witness of `key` with exactly
    /// `value`. The statement holds at a root iff this equals its structure root.
    ///
    /// # Errors
    /// See [`Reject`].
    fn inclusion_root(key: &[u8], value: &[u8], witness: &[u8]) -> Result<Digest, Reject>;

    /// The structure root implied by an absence witness of `key`.
    ///
    /// # Errors
    /// See [`Reject`].
    fn absence_root(key: &[u8], witness: &[u8]) -> Result<Digest, Reject>;

    /// The structure root implied by a witness that `entries` is exactly the
    /// ascending list of every committed entry with `lower <= key < upper`.
    /// The caller has already checked that the claimed keys are strictly
    /// ascending inside the interval.
    ///
    /// # Errors
    /// See [`Reject`].
    fn range_root(
        lower: &[u8],
        upper: Option<&[u8]>,
        entries: &[(&[u8], &[u8])],
        witness: &[u8],
    ) -> Result<Digest, Reject>;

    /// Accounting model of the authenticated structure; see [`Storage`].
    fn storage(&self) -> Storage;
}

/// Digest of a composite key.
pub(crate) fn key_digest<H: HashProfile>(key: &[u8]) -> Digest {
    H::hash_bytes(DOMAIN_KEY, key)
}

/// Digest of a value: the byte length is part of the hashed frame.
pub(crate) fn value_digest<H: HashProfile>(value: &[u8]) -> Digest {
    H::hash_bytes(DOMAIN_VALUE, value)
}

/// Leaf digest of one entry from its key and value digests.
pub(crate) fn leaf_digest<H: HashProfile>(key: &Digest, value: &Digest) -> Digest {
    H::compress(DOMAIN_LEAF, 0, key, value)
}

/// Leaf digest of one entry from its key and value bytes.
pub(crate) fn entry_leaf<H: HashProfile>(key: &[u8], value: &[u8]) -> Digest {
    leaf_digest::<H>(&key_digest::<H>(key), &value_digest::<H>(value))
}

/// The smallest byte string greater than `key`: `key` followed by one zero byte.
pub(crate) fn immediate_successor(key: &[u8]) -> Vec<u8> {
    let mut next = Vec::with_capacity(key.len() + 1);
    next.extend_from_slice(key);
    next.push(0);
    next
}

/// The keys strictly below `key`, as bounds of an ordered-map range.
pub(crate) fn keys_below(key: &[u8]) -> (core::ops::Bound<&[u8]>, core::ops::Bound<&[u8]>) {
    (core::ops::Bound::Unbounded, core::ops::Bound::Excluded(key))
}

/// The keys at or above `key`, as bounds of an ordered-map range.
pub(crate) fn keys_from(key: &[u8]) -> (core::ops::Bound<&[u8]>, core::ops::Bound<&[u8]>) {
    (core::ops::Bound::Included(key), core::ops::Bound::Unbounded)
}

#[cfg(test)]
mod tests;
