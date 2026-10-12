//! Batch all-but-one vector commitment over one GGM tree: commit, open and
//! reconstruct (FAEST v3.0 section 5, Figures 5.2 to 5.5), and the decoding of the
//! third challenge into the hidden indices (section 5.5, Figure 5.7).
//!
//! # Tree
//!
//! One GGM tree commits to `tau` vectors at once. Vector `i` has `N_i = 2^{d_i}`
//! entries and the tree has `L = sum_i N_i` leaves. The `2L - 1` node keys of
//! `lambda` bits are numbered in heap order: node `a` has the children `2a + 1` and
//! `2a + 2`, the internal nodes are `[0, L - 1)` and the leaves `[L - 1, 2L - 1)`.
//! `(k_{2a+1}, k_{2a+2}) = PRG(k_a, iv, a; 2 lambda)` with the root `k_0 = r`.
//! Entry `j` of vector `i` sits at the leaf given by `BAVC.PosInTree`, which
//! interleaves the vectors ([`position_in_tree`]).
//!
//! # Leaf commitment
//!
//! Every leaf key is turned into a leaf seed `sd` and a commitment `com` with the
//! tweak `i + L - 1` ([`leaf_commit`]). The rule follows `n_leafcom`
//! ([`LeafScheme`]): with three blocks the key is expanded to `4 lambda` bits
//! `sd || x_1` and `com = LeafHash(uhash, (sd, x_1))` under the key
//! `uhash = H_0(iv)`; with two blocks (the Even-Mansour rows) `sd` is the key itself
//! and `com = PRG(key, iv, tweak; 2 lambda)`. Vector `i` is committed as
//! `h_i = H_1(com_{i,0} || ... || com_{i,N_i - 1})` and the whole batch as
//! `H_1(h_0 || ... || h_{tau - 1})`.
//!
//! # Decommitment
//!
//! An opening hides entry `Delta_i` of each vector. Its byte layout is fixed:
//! the `tau` hidden leaf commitments in vector order, then the keys of the nodes
//! that have a hidden sibling subtree, in order of descending parent index, then
//! zero bytes up to `T_open` keys: `(n_leafcom * tau + T_open) * lambda / 8` bytes
//! ([`decommitment_bytes`]). A pattern that needs more than `T_open` keys cannot be
//! opened: [`Commitment::open`] reports [`BavcError::OpeningTooLarge`], which
//! depends on the public pattern only, and the signer retries with the next
//! counter.
//!
//! # Secrets
//!
//! The root, every node key and every leaf seed held by a [`Commitment`] are
//! secret. They are processed by a sequence of operations that depends only on the
//! parameters, never index a table or select a branch, and are erased on drop.
//! The hidden indices, a decommitment and everything [`reconstruct`] derives from
//! one are public and are handled with ordinary control flow.
//!
//! # Namespaces
//!
//! [`commit_in`] and [`reconstruct_in`] evaluate `H_0` and both levels of `H_1`
//! inside a caller-supplied [`Namespace`] (a byte prefix absorbed before each
//! message); [`commit`] and [`reconstruct`] are the same functions in reference
//! mode, the empty prefix. The tree expansion and the leaf generator are AES-based
//! and do not depend on the namespace.
//!
//! # Memory
//!
//! With `lb = lambda / 8`, [`commit`] allocates the node keys (`(2L - 1) * lb`
//! bytes) and the leaf seeds (`L * lb` bytes) and nothing else that grows with
//! `L`; leaf commitments are hashed as they are produced and recomputed for the
//! `tau` hidden leaves on opening. [`Commitment::open`] adds one flag per node
//! (`2L - 1` bytes) and the decommitment. [`reconstruct`] peaks at the same three
//! buffers (node keys, leaf seeds, node flags), frees the node keys and flags
//! before returning, and keeps the `L * lb` bytes of leaf seeds grouped by vector
//! so that a caller can consume one small-VOLE instance at a time
//! ([`Reconstruction::seeds`]) without touching the tree again.

use core::fmt;

use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    field::{Gf128, Gf192, Gf256},
    hash::{HashError, Hasher, Namespace, Oracle, hash_in},
    params::{IV_BYTES, SecurityLevel, VoleParams},
    prg::{Prg, PrgError},
    universal_hash::{UniversalHashError, leaf_hash_bytes},
};

/// Largest `lambda / 8`.
const MAX_LAMBDA_BYTES: usize = 32;
/// Tweaks at or above this value belong to `ConvertToVOLE` (`i + 2^31`), so the
/// tree tweaks, at most `L + tau - 2`, must stay below it.
const TWEAK_LIMIT: usize = 1 << 31;

/// Which buffer had the wrong length in a [`BavcError::InvalidLength`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Input {
    /// The root seed `r`, `lambda / 8` bytes.
    RootSeed,
    /// A decommitment, [`decommitment_bytes`] bytes.
    Decommitment,
    /// The third challenge, `lambda / 8` bytes.
    Challenge,
    /// A tree node key given to [`leaf_commit`], `lambda / 8` bytes.
    LeafKey,
    /// The leaf-hash key `uhash`: `3 * lambda / 8` bytes for
    /// [`LeafScheme::Hashed`] and empty for [`LeafScheme::Direct`].
    LeafHashKey,
    /// The leaf seed output of [`leaf_commit`], `lambda / 8` bytes.
    LeafSeed,
    /// The leaf commitment output of [`leaf_commit`], `n_leafcom * lambda / 8`
    /// bytes.
    LeafCommitment,
}

/// Errors and rejections of the vector commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BavcError {
    /// A buffer does not have the length the parameters fix for it.
    #[error("{input:?} must be {expected} bytes long, got {actual}")]
    InvalidLength {
        /// The buffer concerned.
        input: Input,
        /// Required length in bytes.
        expected: usize,
        /// Length supplied.
        actual: usize,
    },
    /// The number of hidden indices is not `tau`.
    #[error("expected {expected} hidden indices, got {actual}")]
    InvalidIndexCount {
        /// `tau`.
        expected: usize,
        /// Number of indices supplied.
        actual: usize,
    },
    /// A hidden index is not below the length `N_i` of its vector.
    #[error("hidden index {index} of vector {vector} is not below {leaves}")]
    IndexOutOfRange {
        /// The vector `i`.
        vector: usize,
        /// The index supplied.
        index: usize,
        /// `N_i`.
        leaves: usize,
    },
    /// The hidden pattern needs more than `T_open` node keys. For a signer this is
    /// the ordinary signal to retry with the next counter; for a verifier it is a
    /// rejection.
    #[error("the opening needs {nodes} node keys, more than T_open = {t_open}")]
    OpeningTooLarge {
        /// Node keys the pattern needs.
        nodes: usize,
        /// The threshold `T_open`.
        t_open: usize,
    },
    /// The bytes of a decommitment after its last node key are not all zero.
    #[error("the padding of the decommitment is not zero")]
    NonZeroPadding,
    /// The top `w_grind` bits of the challenge are not all zero. For a signer this
    /// is the ordinary signal to retry with the next counter.
    #[error("the grinding bits of the challenge are not zero")]
    GrindingBitsSet,
    /// The tree is too large for its tweaks to stay below `2^31` or for its
    /// buffers to be addressed. No row [`VoleParams::new`] accepts triggers this.
    #[error("a tree of {leaves} leaves is not supported")]
    TreeTooLarge {
        /// `L`.
        leaves: usize,
    },
    /// The pseudorandom generator rejected a call.
    #[error(transparent)]
    Prg(#[from] PrgError),
    /// A hash function rejected a call.
    #[error(transparent)]
    Hash(#[from] HashError),
    /// The leaf hash rejected a call.
    #[error(transparent)]
    LeafHash(#[from] UniversalHashError),
}

impl BavcError {
    /// Whether the error is one of the two outcomes a signer answers by trying the
    /// next counter: [`Self::GrindingBitsSet`] and [`Self::OpeningTooLarge`].
    pub const fn is_retry(&self) -> bool {
        matches!(self, Self::GrindingBitsSet | Self::OpeningTooLarge { .. })
    }
}

fn check_length(input: Input, expected: usize, actual: usize) -> Result<(), BavcError> {
    if expected == actual {
        Ok(())
    } else {
        Err(BavcError::InvalidLength {
            input,
            expected,
            actual,
        })
    }
}

/// The leaf commitment rule of a row (specification Figure 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeafScheme {
    /// `FAEST.LeafCommit`, `n_leafcom = 3`: the key is expanded to `sd || x_1` and
    /// the commitment is `LeafHash(uhash, (sd, x_1))`.
    Hashed,
    /// `FAEST-EM.LeafCommit`, `n_leafcom = 2`: the seed is the key and the
    /// commitment is `2 * lambda` generator bits.
    Direct,
}

impl LeafScheme {
    /// The rule a row uses, selected by its `n_leafcom`.
    pub const fn of(params: &VoleParams) -> Self {
        if params.n_leafcom() == 3 {
            Self::Hashed
        } else {
            Self::Direct
        }
    }

    /// Bytes of the leaf-hash key `uhash` at `level`: `3 * lambda / 8` for
    /// [`Self::Hashed`], none for [`Self::Direct`].
    pub const fn hash_key_bytes(self, level: SecurityLevel) -> usize {
        match self {
            Self::Hashed => 3 * level.bytes(),
            Self::Direct => 0,
        }
    }
}

/// Bytes of a decommitment: `(n_leafcom * tau + T_open) * lambda / 8`.
pub const fn decommitment_bytes(params: &VoleParams) -> usize {
    (params.n_leafcom() * params.tau() + params.t_open()) * params.lambda().bytes()
}

/// `BAVC.PosInTree(i, j)`: the heap index in `[L - 1, 2L - 1)` of the leaf holding
/// entry `j` of vector `i`, or `None` unless `i < tau` and `j < N_i`.
pub fn position_in_tree(params: &VoleParams, vector: usize, index: usize) -> Option<usize> {
    let shape = Shape::new(params).ok()?;
    (vector < shape.tau && index < shape.vector_leaves(vector))
        .then(|| shape.position(vector, index))
}

/// Sizes of the tree of one row, validated once.
#[derive(Debug, Clone, Copy)]
struct Shape {
    level: SecurityLevel,
    scheme: LeafScheme,
    /// `lambda / 8`.
    lb: usize,
    tau: usize,
    tau1: usize,
    /// `2^{k - 1}`, the length of the short vectors.
    half: usize,
    /// `L`.
    leaves: usize,
    /// Bytes of one leaf commitment.
    com_bytes: usize,
    t_open: usize,
}

impl Shape {
    fn new(params: &VoleParams) -> Result<Self, BavcError> {
        let leaves = params.leaves();
        let lb = params.lambda().bytes();
        let error = BavcError::TreeTooLarge { leaves };
        // Tweaks: nodes `[0, L - 1)` and leaves `L - 1 + i`.
        if leaves
            .checked_add(params.tau())
            .is_none_or(|bound| bound > TWEAK_LIMIT)
        {
            return Err(error);
        }
        // The largest buffer is the node keys.
        if leaves
            .checked_mul(2)
            .and_then(|nodes| nodes.checked_mul(lb))
            .is_none()
        {
            return Err(error);
        }
        Ok(Self {
            level: params.lambda(),
            scheme: LeafScheme::of(params),
            lb,
            tau: params.tau(),
            tau1: params.tau1(),
            half: 1 << (params.k() - 1),
            leaves,
            com_bytes: params.leaf_commitment_bytes(),
            t_open: params.t_open(),
        })
    }

    /// Number of tree nodes, `2L - 1`.
    fn nodes(&self) -> usize {
        2 * self.leaves - 1
    }

    /// `N_i` for `vector < tau`.
    fn vector_leaves(&self, vector: usize) -> usize {
        if vector < self.tau1 {
            2 * self.half
        } else {
            self.half
        }
    }

    /// Number of entries in the vectors before `vector`, for `vector <= tau`.
    fn vector_offset(&self, vector: usize) -> usize {
        let long = vector.min(self.tau1);
        (vector + long) * self.half
    }

    /// `BAVC.PosInTree(vector, index)` for `vector < tau` and `index < N_i`.
    fn position(&self, vector: usize, index: usize) -> usize {
        if index < self.half {
            self.leaves - 1 + self.tau * index + vector
        } else {
            self.leaves - 1 + self.tau * self.half + self.tau1 * (index - self.half) + vector
        }
    }

    /// The tweak `i + L - 1` of the leaves of `vector`.
    fn leaf_tweak(&self, vector: usize) -> Result<u32, BavcError> {
        self.tweak(self.leaves - 1 + vector)
    }

    fn tweak(&self, value: usize) -> Result<u32, BavcError> {
        u32::try_from(value).map_err(|_| BavcError::TreeTooLarge {
            leaves: self.leaves,
        })
    }

    fn decommitment_bytes(&self) -> usize {
        (self.tau * self.com_bytes) + self.t_open * self.lb
    }
}

/// The bytes of node `node` in a buffer of consecutive `lb`-byte keys.
fn key(keys: &[u8], lb: usize, node: usize) -> &[u8] {
    &keys[node * lb..(node + 1) * lb]
}

/// Write `PRG(k_node, iv, node; 2 lambda)` to the two children of `node`.
fn expand_node(
    shape: &Shape,
    iv: &[u8; IV_BYTES],
    keys: &mut [u8],
    node: usize,
) -> Result<(), BavcError> {
    let lb = shape.lb;
    let (head, children) = keys.split_at_mut((2 * node + 1) * lb);
    Prg::new(key(head, lb, node))?.fill(iv, shape.tweak(node)?, &mut children[..2 * lb])?;
    Ok(())
}

fn leaf_hash(
    level: SecurityLevel,
    uhash: &[u8],
    x: &[u8],
    out: &mut [u8],
) -> Result<(), UniversalHashError> {
    match level {
        SecurityLevel::L128 => leaf_hash_bytes::<Gf128>(uhash, x, out),
        SecurityLevel::L192 => leaf_hash_bytes::<Gf192>(uhash, x, out),
        SecurityLevel::L256 => leaf_hash_bytes::<Gf256>(uhash, x, out),
    }
}

/// The leaf commitment function of one row under one `iv`.
#[derive(Clone)]
struct LeafCommitter {
    level: SecurityLevel,
    scheme: LeafScheme,
    iv: [u8; IV_BYTES],
    /// The public key `uhash`; `scheme.hash_key_bytes(level)` bytes are used.
    uhash: [u8; 3 * MAX_LAMBDA_BYTES],
}

impl LeafCommitter {
    /// The function with `uhash = H_0(iv)`, evaluated inside `namespace`, where
    /// the scheme has a key.
    fn new(
        namespace: Namespace<'_>,
        level: SecurityLevel,
        scheme: LeafScheme,
        iv: &[u8; IV_BYTES],
    ) -> Result<Self, BavcError> {
        let mut uhash = [0u8; 3 * MAX_LAMBDA_BYTES];
        if scheme == LeafScheme::Hashed {
            hash_in(
                namespace,
                level,
                Oracle::H0,
                iv,
                &mut uhash[..scheme.hash_key_bytes(level)],
            )?;
        }
        Ok(Self {
            level,
            scheme,
            iv: *iv,
            uhash,
        })
    }

    /// The function with a caller-supplied `uhash`.
    fn with_hash_key(
        level: SecurityLevel,
        scheme: LeafScheme,
        iv: &[u8; IV_BYTES],
        hash_key: &[u8],
    ) -> Result<Self, BavcError> {
        check_length(
            Input::LeafHashKey,
            scheme.hash_key_bytes(level),
            hash_key.len(),
        )?;
        let mut uhash = [0u8; 3 * MAX_LAMBDA_BYTES];
        uhash[..hash_key.len()].copy_from_slice(hash_key);
        Ok(Self {
            level,
            scheme,
            iv: *iv,
            uhash,
        })
    }

    fn commitment_bytes(&self) -> usize {
        match self.scheme {
            LeafScheme::Hashed => 3 * self.level.bytes(),
            LeafScheme::Direct => 2 * self.level.bytes(),
        }
    }

    /// `LeafCommit(key, iv, tweak)`: the seed to `sd`, the commitment to `com`.
    fn commit(
        &self,
        node_key: &[u8],
        tweak: u32,
        sd: &mut [u8],
        com: &mut [u8],
    ) -> Result<(), BavcError> {
        let lb = self.level.bytes();
        check_length(Input::LeafKey, lb, node_key.len())?;
        check_length(Input::LeafSeed, lb, sd.len())?;
        check_length(Input::LeafCommitment, self.commitment_bytes(), com.len())?;
        let generator = Prg::new(node_key)?;
        match self.scheme {
            LeafScheme::Hashed => {
                let mut expanded = Zeroizing::new([0u8; 4 * MAX_LAMBDA_BYTES]);
                let expanded = &mut expanded[..4 * lb];
                generator.fill(&self.iv, tweak, expanded)?;
                sd.copy_from_slice(&expanded[..lb]);
                leaf_hash(self.level, &self.uhash[..3 * lb], expanded, com)?;
            }
            LeafScheme::Direct => {
                generator.fill(&self.iv, tweak, com)?;
                sd.copy_from_slice(node_key);
            }
        }
        Ok(())
    }
}

/// `LeafCommit(key, iv, tweak[, uhash])` of specification Figure 5.3 for the row
/// `params`: writes the leaf seed (`lambda / 8` bytes) to `sd` and the leaf
/// commitment (`n_leafcom * lambda / 8` bytes) to `com`.
///
/// `hash_key` is the `3 * lambda / 8`-byte `uhash` for [`LeafScheme::Hashed`] and
/// must be empty for [`LeafScheme::Direct`]. [`commit`] and [`reconstruct`] use
/// `uhash = H_0(iv)`.
///
/// # Errors
/// Returns [`BavcError::InvalidLength`] naming the first buffer whose length is
/// wrong.
pub fn leaf_commit(
    params: &VoleParams,
    node_key: &[u8],
    iv: &[u8; IV_BYTES],
    tweak: u32,
    hash_key: &[u8],
    sd: &mut [u8],
    com: &mut [u8],
) -> Result<(), BavcError> {
    LeafCommitter::with_hash_key(params.lambda(), LeafScheme::of(params), iv, hash_key)?
        .commit(node_key, tweak, sd, com)
}

/// Check the hidden indices and mark every node whose key must stay hidden: the
/// hidden leaves and all their ancestors. Returns the flags and the number of node
/// keys an opening reveals, which equals `n_h - 2 tau + 1` of Figure 5.4.
fn mark_hidden(shape: &Shape, hidden: &[u16]) -> Result<(Vec<bool>, usize), BavcError> {
    if hidden.len() != shape.tau {
        return Err(BavcError::InvalidIndexCount {
            expected: shape.tau,
            actual: hidden.len(),
        });
    }
    for (vector, &index) in hidden.iter().enumerate() {
        let leaves = shape.vector_leaves(vector);
        if usize::from(index) >= leaves {
            return Err(BavcError::IndexOutOfRange {
                vector,
                index: usize::from(index),
                leaves,
            });
        }
    }
    let mut marks = vec![false; shape.nodes()];
    for (vector, &index) in hidden.iter().enumerate() {
        marks[shape.position(vector, usize::from(index))] = true;
    }
    let mut revealed = 0;
    for parent in (0..shape.leaves - 1).rev() {
        let (left, right) = (marks[2 * parent + 1], marks[2 * parent + 2]);
        marks[parent] = left | right;
        revealed += usize::from(left ^ right);
    }
    Ok((marks, revealed))
}

/// The revealed nodes of an opening in decommitment order: for each parent with
/// exactly one hidden child, from the last parent down to the root, the other
/// child.
fn revealed_nodes<'a>(shape: &Shape, marks: &'a [bool]) -> impl Iterator<Item = usize> + 'a {
    (0..shape.leaves - 1).rev().filter_map(|parent| {
        let (left, right) = (marks[2 * parent + 1], marks[2 * parent + 2]);
        (left ^ right).then(|| 2 * parent + 1 + usize::from(left))
    })
}

/// Number of node keys an opening of the pattern `hidden` contains. The pattern
/// can be opened if and only if this is at most `T_open`.
///
/// # Errors
/// Returns [`BavcError::InvalidIndexCount`] or [`BavcError::IndexOutOfRange`] for a
/// malformed pattern.
pub fn opening_nodes(params: &VoleParams, hidden: &[u16]) -> Result<usize, BavcError> {
    let shape = Shape::new(params)?;
    mark_hidden(&shape, hidden).map(|(_, revealed)| revealed)
}

/// Compute every leaf commitment and seed and hash them into the commitment.
///
/// `keys` holds the node keys. `seeds` receives the `L` leaf seeds grouped by
/// vector. When `opened` is `Some((marks, coms))` the marked leaves take their
/// commitment from the `tau` entries of `coms` and their seed slot is left
/// untouched. The commitment, `2 * lambda / 8` bytes, is written to `out`. Both
/// levels of `H_1` are evaluated inside `namespace`.
fn hash_leaves(
    namespace: Namespace<'_>,
    shape: &Shape,
    committer: &LeafCommitter,
    keys: &[u8],
    opened: Option<(&[bool], &[u8])>,
    seeds: &mut [u8],
    out: &mut [u8],
) -> Result<(), BavcError> {
    let lb = shape.lb;
    let mut com = Zeroizing::new([0u8; 3 * MAX_LAMBDA_BYTES]);
    let com = &mut com[..shape.com_bytes];
    let mut vector_hash = [0u8; 2 * MAX_LAMBDA_BYTES];
    let vector_hash = &mut vector_hash[..2 * lb];
    let mut outer = Hasher::new_in(namespace, shape.level, Oracle::H1);
    let mut slots = seeds.chunks_exact_mut(lb);
    for vector in 0..shape.tau {
        let tweak = shape.leaf_tweak(vector)?;
        let mut inner = Hasher::new_in(namespace, shape.level, Oracle::H1);
        for index in 0..shape.vector_leaves(vector) {
            let node = shape.position(vector, index);
            let slot = slots.next().ok_or(BavcError::TreeTooLarge {
                leaves: shape.leaves,
            })?;
            match opened {
                Some((marks, coms)) if marks[node] => {
                    inner.update(&coms[vector * shape.com_bytes..(vector + 1) * shape.com_bytes]);
                }
                _ => {
                    committer.commit(key(keys, lb, node), tweak, slot, com)?;
                    inner.update(com);
                }
            }
        }
        inner.finalize(vector_hash)?;
        outer.update(vector_hash);
    }
    outer.finalize(out)?;
    Ok(())
}

/// The prover's side of a commitment: the result of [`commit`].
///
/// Holds the secret node keys and leaf seeds, which are erased on drop.
pub struct Commitment {
    params: VoleParams,
    shape: Shape,
    committer: LeafCommitter,
    com: Vec<u8>,
    keys: Zeroizing<Vec<u8>>,
    seeds: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Commitment")
            .field("params", &self.params)
            .field("com", &self.com)
            .finish_non_exhaustive()
    }
}

/// `BAVC.Commit(r, iv)` in reference mode; see [`commit_in`].
///
/// # Errors
/// As [`commit_in`].
pub fn commit(
    params: &VoleParams,
    root: &[u8],
    iv: &[u8; IV_BYTES],
) -> Result<Commitment, BavcError> {
    commit_in(Namespace::REFERENCE, params, root, iv)
}

/// `BAVC.Commit(r, iv)`: commit to the `tau` vectors of leaf seeds derived from
/// the root seed `root` (`lambda / 8` bytes), with `H_0` and both levels of `H_1`
/// evaluated inside `namespace`.
///
/// # Errors
/// Returns [`BavcError::InvalidLength`] unless `root` is `lambda / 8` bytes long.
pub fn commit_in(
    namespace: Namespace<'_>,
    params: &VoleParams,
    root: &[u8],
    iv: &[u8; IV_BYTES],
) -> Result<Commitment, BavcError> {
    let shape = Shape::new(params)?;
    let lb = shape.lb;
    check_length(Input::RootSeed, lb, root.len())?;
    let committer = LeafCommitter::new(namespace, shape.level, shape.scheme, iv)?;

    let mut keys = Zeroizing::new(vec![0u8; shape.nodes() * lb]);
    keys[..lb].copy_from_slice(root);
    for node in 0..shape.leaves - 1 {
        expand_node(&shape, iv, &mut keys, node)?;
    }

    let mut seeds = Zeroizing::new(vec![0u8; shape.leaves * lb]);
    let mut com = vec![0u8; 2 * lb];
    hash_leaves(
        namespace, &shape, &committer, &keys, None, &mut seeds, &mut com,
    )?;
    Ok(Commitment {
        params: *params,
        shape,
        committer,
        com,
        keys,
        seeds,
    })
}

impl Commitment {
    /// The row the commitment was made for.
    pub fn params(&self) -> &VoleParams {
        &self.params
    }

    /// The commitment `com`, `2 * lambda / 8` bytes. Public.
    pub fn commitment(&self) -> &[u8] {
        &self.com
    }

    /// The leaf seeds `sd_{i,0} || ... || sd_{i,N_i - 1}` of vector `vector`,
    /// `lambda / 8` bytes each, or `None` if `vector >= tau`. **Secret.**
    pub fn seeds(&self, vector: usize) -> Option<&[u8]> {
        (vector < self.shape.tau).then(|| {
            let lb = self.shape.lb;
            &self.seeds
                [self.shape.vector_offset(vector) * lb..self.shape.vector_offset(vector + 1) * lb]
        })
    }

    /// All `2L - 1` node keys in heap order, `lambda / 8` bytes each. **Secret**;
    /// exposed so that the tree can be compared against reference vectors.
    pub fn node_keys(&self) -> &[u8] {
        &self.keys
    }

    /// `BAVC.Open(decom, I)`: the decommitment that hides entry `hidden[i]` of each
    /// vector `i` and reveals all others, [`decommitment_bytes`] bytes.
    ///
    /// # Errors
    /// Returns [`BavcError::OpeningTooLarge`] if the pattern needs more than
    /// `T_open` node keys (the signer then tries its next counter), and
    /// [`BavcError::InvalidIndexCount`] or [`BavcError::IndexOutOfRange`] for a
    /// malformed pattern.
    pub fn open(&self, hidden: &[u16]) -> Result<Vec<u8>, BavcError> {
        let shape = &self.shape;
        let lb = shape.lb;
        let (marks, nodes) = mark_hidden(shape, hidden)?;
        if nodes > shape.t_open {
            return Err(BavcError::OpeningTooLarge {
                nodes,
                t_open: shape.t_open,
            });
        }
        let mut decommitment = vec![0u8; shape.decommitment_bytes()];
        let (coms, revealed) = decommitment.split_at_mut(shape.tau * shape.com_bytes);
        // The hidden leaf seed is recomputed along with its commitment and
        // discarded.
        let mut sd = Zeroizing::new([0u8; MAX_LAMBDA_BYTES]);
        for ((vector, &index), com) in hidden
            .iter()
            .enumerate()
            .zip(coms.chunks_exact_mut(shape.com_bytes))
        {
            let node = shape.position(vector, usize::from(index));
            self.committer.commit(
                key(&self.keys, lb, node),
                shape.leaf_tweak(vector)?,
                &mut sd[..lb],
                com,
            )?;
        }
        for (node, slot) in revealed_nodes(shape, &marks).zip(revealed.chunks_exact_mut(lb)) {
            slot.copy_from_slice(key(&self.keys, lb, node));
        }
        Ok(decommitment)
    }
}

/// The verifier's side of a commitment: the result of [`reconstruct`]. Everything
/// in it is public.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reconstruction {
    tau: usize,
    lb: usize,
    offsets: Vec<usize>,
    com: Vec<u8>,
    seeds: Vec<u8>,
    hidden: Vec<u16>,
}

impl Reconstruction {
    /// The recomputed commitment `com`, `2 * lambda / 8` bytes. The caller must
    /// bind it into the challenge it checks; nothing here compares it.
    pub fn commitment(&self) -> &[u8] {
        &self.com
    }

    /// The hidden index `Delta_i` of vector `vector`, or `None` if
    /// `vector >= tau`.
    pub fn hidden_index(&self, vector: usize) -> Option<u16> {
        self.hidden.get(vector).copied()
    }

    /// The `N_i` leaf seed slots of vector `vector` in index order, `lambda / 8`
    /// bytes each, or `None` if `vector >= tau`. Slot `Delta_i` is unknown to a
    /// verifier and holds zero bytes; every other slot holds `sd_{i,j}`.
    pub fn seeds(&self, vector: usize) -> Option<&[u8]> {
        (vector < self.tau).then(|| {
            &self.seeds[self.offsets[vector] * self.lb..self.offsets[vector + 1] * self.lb]
        })
    }
}

/// `BAVC.Reconstruct(decom_I, I, iv)` in reference mode; see [`reconstruct_in`].
///
/// # Errors
/// As [`reconstruct_in`].
pub fn reconstruct(
    params: &VoleParams,
    decommitment: &[u8],
    hidden: &[u16],
    iv: &[u8; IV_BYTES],
) -> Result<Reconstruction, BavcError> {
    reconstruct_in(Namespace::REFERENCE, params, decommitment, hidden, iv)
}

/// `BAVC.Reconstruct(decom_I, I, iv)`: recompute the commitment and the `L - tau`
/// revealed leaf seeds from a decommitment and the hidden indices, with `H_0` and
/// both levels of `H_1` evaluated inside `namespace`.
///
/// This is a verifier entry point: every input is untrusted and public.
///
/// # Errors
/// * [`BavcError::InvalidLength`] unless `decommitment` is exactly
///   [`decommitment_bytes`] bytes long;
/// * [`BavcError::InvalidIndexCount`] unless there are `tau` indices and
///   [`BavcError::IndexOutOfRange`] unless each is below its `N_i`;
/// * [`BavcError::OpeningTooLarge`] if the pattern needs more than `T_open` node
///   keys;
/// * [`BavcError::NonZeroPadding`] if a byte after the last node key is not zero.
pub fn reconstruct_in(
    namespace: Namespace<'_>,
    params: &VoleParams,
    decommitment: &[u8],
    hidden: &[u16],
    iv: &[u8; IV_BYTES],
) -> Result<Reconstruction, BavcError> {
    let shape = Shape::new(params)?;
    let lb = shape.lb;
    check_length(
        Input::Decommitment,
        shape.decommitment_bytes(),
        decommitment.len(),
    )?;
    let (marks, nodes) = mark_hidden(&shape, hidden)?;
    if nodes > shape.t_open {
        return Err(BavcError::OpeningTooLarge {
            nodes,
            t_open: shape.t_open,
        });
    }
    let (coms, revealed) = decommitment.split_at(shape.tau * shape.com_bytes);
    let (revealed, padding) = revealed.split_at(nodes * lb);
    if padding.iter().any(|&byte| byte != 0) {
        return Err(BavcError::NonZeroPadding);
    }
    let committer = LeafCommitter::new(namespace, shape.level, shape.scheme, iv)?;

    // Keys of marked nodes are unknown; their slots stay zero and are never read.
    let mut keys = vec![0u8; shape.nodes() * lb];
    for (node, revealed_key) in revealed_nodes(&shape, &marks).zip(revealed.chunks_exact(lb)) {
        keys[node * lb..(node + 1) * lb].copy_from_slice(revealed_key);
    }
    // An unmarked node has its key from the decommitment (marked parent) or from
    // its unmarked parent, which precedes it in this ascending order.
    for (node, &hidden_node) in marks.iter().enumerate().take(shape.leaves - 1) {
        if !hidden_node {
            expand_node(&shape, iv, &mut keys, node)?;
        }
    }

    let mut seeds = vec![0u8; shape.leaves * lb];
    let mut com = vec![0u8; 2 * lb];
    hash_leaves(
        namespace,
        &shape,
        &committer,
        &keys,
        Some((&marks, coms)),
        &mut seeds,
        &mut com,
    )?;
    Ok(Reconstruction {
        tau: shape.tau,
        lb,
        offsets: (0..=shape.tau)
            .map(|vector| shape.vector_offset(vector))
            .collect(),
        com,
        seeds,
        hidden: hidden.to_vec(),
    })
}

/// `DecodeAllChall3(chall)`: check that the top `w_grind` bits of the
/// `lambda / 8`-byte challenge are zero and split its first `n_Delta` bits into the
/// `tau` hidden indices, vector `i` taking the next `d_i` bits, low bit first.
///
/// The challenge is public.
///
/// # Errors
/// Returns [`BavcError::InvalidLength`] unless `challenge` is `lambda / 8` bytes
/// long and [`BavcError::GrindingBitsSet`] if a grinding bit is set (the signer
/// then tries its next counter).
pub fn decode_challenge(params: &VoleParams, challenge: &[u8]) -> Result<Vec<u16>, BavcError> {
    let lambda = params.lambda().bits();
    check_length(Input::Challenge, params.lambda().bytes(), challenge.len())?;
    let bit = |position: usize| (challenge[position / 8] >> (position % 8)) & 1;
    if (params.n_delta()..lambda).any(|position| bit(position) != 0) {
        return Err(BavcError::GrindingBitsSet);
    }
    let mut low = 0;
    let mut hidden = Vec::with_capacity(params.tau());
    for vector in 0..params.tau() {
        let depth = if vector < params.tau1() {
            params.k()
        } else {
            params.k() - 1
        };
        let index = (0..depth).fold(0u16, |index, offset| {
            index | (u16::from(bit(low + offset)) << offset)
        });
        hidden.push(index);
        low += depth;
    }
    Ok(hidden)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hash::hash,
        params::{FAEST_PARAMETER_SETS, MAX_VOLE_BITS},
    };

    const REFERENCE: Namespace<'static> = Namespace::REFERENCE;

    const IV: [u8; IV_BYTES] = [
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e,
        0x5f,
    ];

    /// A small row with both vector lengths: `tau = 50`, `k = 3`, `tau_1 = 20`,
    /// `L = 280`.
    fn small(n_leafcom: usize, t_open: usize) -> VoleParams {
        VoleParams::new(SecurityLevel::L128, 50, 8, t_open, n_leafcom, 7, 312)
            .expect("valid small row")
    }

    /// A small 192-bit row: `tau = 64`, `k = 3`, `tau_1 = 56`, `L = 480`.
    fn small_192(n_leafcom: usize) -> VoleParams {
        VoleParams::new(SecurityLevel::L192, 64, 8, 700, n_leafcom, 7, 504)
            .expect("valid small row")
    }

    fn rows() -> [VoleParams; 4] {
        [small(3, 600), small(2, 600), small_192(3), small_192(2)]
    }

    fn root(params: &VoleParams) -> Vec<u8> {
        (0..params.lambda().bytes())
            .map(|byte| u8::try_from(3 * byte + 1).expect("small"))
            .collect()
    }

    /// A deterministic valid pattern.
    fn pattern(params: &VoleParams, salt: usize) -> Vec<u16> {
        (0..params.tau())
            .map(|vector| {
                let leaves = params.leaves_of(vector).expect("vector below tau");
                u16::try_from((vector * 7 + salt * 13 + 5) % leaves).expect("index fits")
            })
            .collect()
    }

    #[test]
    fn retry_outcomes_are_classified() {
        assert!(BavcError::GrindingBitsSet.is_retry());
        assert!(
            BavcError::OpeningTooLarge {
                nodes: 2,
                t_open: 1
            }
            .is_retry()
        );
        assert!(!BavcError::NonZeroPadding.is_retry());
        assert!(
            !BavcError::InvalidIndexCount {
                expected: 2,
                actual: 1
            }
            .is_retry()
        );
    }

    #[test]
    fn check_length_names_the_buffer() {
        assert_eq!(check_length(Input::Challenge, 4, 4), Ok(()));
        assert_eq!(
            check_length(Input::Challenge, 4, 5),
            Err(BavcError::InvalidLength {
                input: Input::Challenge,
                expected: 4,
                actual: 5
            })
        );
    }

    #[test]
    fn leaf_scheme_follows_n_leafcom() {
        assert_eq!(LeafScheme::of(&small(3, 1)), LeafScheme::Hashed);
        assert_eq!(LeafScheme::of(&small(2, 1)), LeafScheme::Direct);
        assert_eq!(LeafScheme::Hashed.hash_key_bytes(SecurityLevel::L192), 72);
        assert_eq!(LeafScheme::Direct.hash_key_bytes(SecurityLevel::L192), 0);
        for set in &FAEST_PARAMETER_SETS {
            let expected = if set.name().contains("EM") {
                LeafScheme::Direct
            } else {
                LeafScheme::Hashed
            };
            assert_eq!(LeafScheme::of(set.vole()), expected, "{}", set.name());
        }
    }

    #[test]
    fn decommitment_length_matches_the_specification() {
        assert_eq!(decommitment_bytes(&small(3, 600)), (3 * 50 + 600) * 16);
        assert_eq!(decommitment_bytes(&small_192(2)), (2 * 64 + 700) * 24);
        for set in &FAEST_PARAMETER_SETS {
            let shape = Shape::new(set.vole()).expect("standard row");
            assert_eq!(decommitment_bytes(set.vole()), shape.decommitment_bytes());
        }
    }

    #[test]
    fn positions_are_a_bijection_onto_the_leaves() {
        let mut all: Vec<VoleParams> = FAEST_PARAMETER_SETS.iter().map(|set| *set.vole()).collect();
        all.extend(rows());
        for params in all {
            let shape = Shape::new(&params).expect("supported row");
            assert_eq!(shape.leaves, params.leaves());
            assert_eq!(shape.nodes(), 2 * params.leaves() - 1);
            assert_eq!(shape.vector_offset(shape.tau), shape.leaves);
            let mut seen = vec![false; shape.nodes()];
            for vector in 0..shape.tau {
                let leaves = params.leaves_of(vector).expect("vector below tau");
                assert_eq!(shape.vector_leaves(vector), leaves);
                assert_eq!(
                    shape.vector_offset(vector + 1) - shape.vector_offset(vector),
                    leaves
                );
                assert_eq!(
                    shape.leaf_tweak(vector),
                    Ok(u32::try_from(shape.leaves - 1 + vector).expect("small"))
                );
                for index in 0..leaves {
                    let node = shape.position(vector, index);
                    assert_eq!(position_in_tree(&params, vector, index), Some(node));
                    assert!(node >= shape.leaves - 1, "leaf index");
                    assert!(!seen[node], "leaf used twice");
                    seen[node] = true;
                }
                assert_eq!(position_in_tree(&params, vector, leaves), None);
            }
            assert_eq!(position_in_tree(&params, shape.tau, 0), None);
            assert!(seen[..shape.leaves - 1].iter().all(|&used| !used));
            assert!(seen[shape.leaves - 1..].iter().all(|&used| used));
        }
    }

    /// Figure 5.2 by hand on the small row: `tau = 50`, `tau_1 = 20`, half `= 4`,
    /// `L = 280`.
    #[test]
    fn positions_match_figure_5_2() {
        let params = small(3, 600);
        assert_eq!(position_in_tree(&params, 0, 0), Some(279));
        assert_eq!(position_in_tree(&params, 49, 0), Some(279 + 49));
        assert_eq!(position_in_tree(&params, 7, 3), Some(279 + 150 + 7));
        assert_eq!(position_in_tree(&params, 7, 4), Some(279 + 200 + 7));
        assert_eq!(position_in_tree(&params, 19, 7), Some(279 + 200 + 60 + 19));
        assert_eq!(position_in_tree(&params, 20, 4), None);
    }

    #[test]
    fn shape_accepts_the_largest_supported_row() {
        // k = 16 with the fewest vectors: the largest tree `VoleParams::new` allows.
        let params = VoleParams::new(SecurityLevel::L256, 17, 0, 1, 3, 7, 1).expect("valid row");
        assert_eq!(params.k(), MAX_VOLE_BITS);
        let shape = Shape::new(&params).expect("supported");
        assert_eq!(shape.half, 1 << 15);
        assert!(shape.leaves + shape.tau <= TWEAK_LIMIT);
        assert_eq!(shape.tweak(7), Ok(7));
    }

    #[test]
    fn key_slices_one_node() {
        let keys: Vec<u8> = (0..12).collect();
        assert_eq!(key(&keys, 4, 0), [0, 1, 2, 3]);
        assert_eq!(key(&keys, 4, 2), [8, 9, 10, 11]);
    }

    #[test]
    fn expand_node_writes_both_children() {
        let params = small(3, 600);
        let shape = Shape::new(&params).expect("supported row");
        let mut keys = vec![0u8; shape.nodes() * 16];
        keys[16 * 5..16 * 6].copy_from_slice(&root(&params));
        expand_node(&shape, &IV, &mut keys, 5).expect("valid node");
        let mut expected = [0u8; 32];
        Prg::new(&root(&params))
            .expect("valid key")
            .fill(&IV, 5, &mut expected)
            .expect("short output");
        assert_eq!(keys[16 * 11..16 * 13], expected);
        assert!(keys[..16 * 5].iter().all(|&byte| byte == 0));
        assert!(keys[16 * 13..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn leaf_hash_dispatches_on_the_level() {
        for level in SecurityLevel::ALL {
            let lb = level.bytes();
            let uhash = vec![0x35u8; 3 * lb];
            let x: Vec<u8> = (0..4 * lb)
                .map(|byte| u8::try_from(byte).expect("small"))
                .collect();
            let mut out = vec![0u8; 3 * lb];
            leaf_hash(level, &uhash, &x, &mut out).expect("exact lengths");
            let mut expected = vec![0u8; 3 * lb];
            match level {
                SecurityLevel::L128 => leaf_hash_bytes::<Gf128>(&uhash, &x, &mut expected),
                SecurityLevel::L192 => leaf_hash_bytes::<Gf192>(&uhash, &x, &mut expected),
                SecurityLevel::L256 => leaf_hash_bytes::<Gf256>(&uhash, &x, &mut expected),
            }
            .expect("exact lengths");
            assert_eq!(out, expected);
            assert!(leaf_hash(level, &uhash[1..], &x, &mut out).is_err());
        }
    }

    #[test]
    fn hashed_leaf_commitment_is_the_leaf_hash_of_the_expansion() {
        let params = small_192(3);
        let node_key = root(&params);
        let uhash = [0x9cu8; 72];
        let (mut sd, mut com) = ([0u8; 24], [0u8; 72]);
        leaf_commit(&params, &node_key, &IV, 77, &uhash, &mut sd, &mut com).expect("valid call");
        let mut expanded = [0u8; 96];
        Prg::new(&node_key)
            .expect("valid key")
            .fill(&IV, 77, &mut expanded)
            .expect("short output");
        assert_eq!(sd, expanded[..24]);
        let mut expected = [0u8; 72];
        leaf_hash_bytes::<Gf192>(&uhash, &expanded, &mut expected).expect("exact lengths");
        assert_eq!(com, expected);
    }

    #[test]
    fn direct_leaf_commitment_keeps_the_key_as_seed() {
        let params = small_192(2);
        let node_key = root(&params);
        let (mut sd, mut com) = ([0u8; 24], [0u8; 48]);
        leaf_commit(&params, &node_key, &IV, 78, &[], &mut sd, &mut com).expect("valid call");
        assert_eq!(sd[..], node_key[..]);
        let mut expected = [0u8; 48];
        Prg::new(&node_key)
            .expect("valid key")
            .fill(&IV, 78, &mut expected)
            .expect("short output");
        assert_eq!(com, expected);
    }

    #[test]
    fn leaf_commit_rejects_each_wrong_length() {
        let invalid = |input, expected, actual| {
            Err(BavcError::InvalidLength {
                input,
                expected,
                actual,
            })
        };
        let hashed = small(3, 600);
        let direct = small(2, 600);
        let node_key = [1u8; 16];
        let (mut sd, mut com) = ([0u8; 16], [0u8; 48]);
        assert_eq!(
            leaf_commit(&hashed, &node_key, &IV, 0, &[0; 47], &mut sd, &mut com),
            invalid(Input::LeafHashKey, 48, 47)
        );
        assert_eq!(
            leaf_commit(
                &direct,
                &node_key,
                &IV,
                0,
                &[0; 48],
                &mut sd,
                &mut com[..32]
            ),
            invalid(Input::LeafHashKey, 0, 48)
        );
        // A 24-byte key is a valid generator seed but not a key of this row.
        assert_eq!(
            leaf_commit(&hashed, &[1; 24], &IV, 0, &[0; 48], &mut sd, &mut com),
            invalid(Input::LeafKey, 16, 24)
        );
        assert_eq!(
            leaf_commit(
                &hashed,
                &node_key,
                &IV,
                0,
                &[0; 48],
                &mut sd[..15],
                &mut com
            ),
            invalid(Input::LeafSeed, 16, 15)
        );
        assert_eq!(
            leaf_commit(
                &hashed,
                &node_key,
                &IV,
                0,
                &[0; 48],
                &mut sd,
                &mut com[..32]
            ),
            invalid(Input::LeafCommitment, 48, 32)
        );
        assert_eq!(
            leaf_commit(&direct, &node_key, &IV, 0, &[], &mut sd, &mut com),
            invalid(Input::LeafCommitment, 32, 48)
        );
    }

    #[test]
    fn committer_derives_the_hash_key_from_the_iv() {
        let hashed = LeafCommitter::new(REFERENCE, SecurityLevel::L128, LeafScheme::Hashed, &IV)
            .expect("valid call");
        let mut expected = [0u8; 48];
        hash(SecurityLevel::L128, Oracle::H0, &IV, &mut expected).expect("exact length");
        assert_eq!(hashed.uhash[..48], expected);
        assert!(hashed.uhash[48..].iter().all(|&byte| byte == 0));
        assert_eq!(hashed.commitment_bytes(), 48);
        let direct = LeafCommitter::new(REFERENCE, SecurityLevel::L128, LeafScheme::Direct, &IV)
            .expect("valid call");
        assert!(direct.uhash.iter().all(|&byte| byte == 0));
        assert_eq!(direct.commitment_bytes(), 32);
        let supplied =
            LeafCommitter::with_hash_key(SecurityLevel::L128, LeafScheme::Hashed, &IV, &expected)
                .expect("valid key");
        assert_eq!(supplied.uhash, hashed.uhash);
    }

    /// The marking of Figure 5.4 lines 5 to 15, literally.
    fn specification_marks(shape: &Shape, hidden: &[u16]) -> (Vec<bool>, usize) {
        let mut marks = vec![false; shape.nodes()];
        let mut marked = 0;
        for (vector, &index) in hidden.iter().enumerate() {
            let mut node = shape.position(vector, usize::from(index));
            marks[node] = true;
            marked += 1;
            while node > 0 && !marks[(node - 1) / 2] {
                node = (node - 1) / 2;
                marks[node] = true;
                marked += 1;
            }
        }
        (marks, marked)
    }

    #[test]
    fn marking_agrees_with_the_specification_count() {
        for params in rows() {
            let shape = Shape::new(&params).expect("supported row");
            for salt in 0..8 {
                let hidden = pattern(&params, salt);
                let (marks, revealed) = mark_hidden(&shape, &hidden).expect("valid pattern");
                let (expected_marks, marked) = specification_marks(&shape, &hidden);
                assert_eq!(marks, expected_marks);
                assert_eq!(revealed, marked - 2 * shape.tau + 1);
                assert_eq!(opening_nodes(&params, &hidden), Ok(revealed));
                let nodes: Vec<usize> = revealed_nodes(&shape, &marks).collect();
                assert_eq!(nodes.len(), revealed);
                assert!(
                    nodes
                        .windows(2)
                        .all(|pair| (pair[0] - 1) / 2 > (pair[1] - 1) / 2)
                );
                for &node in &nodes {
                    assert!(!marks[node], "a revealed node is not hidden");
                    assert!(marks[(node - 1) / 2], "its parent is hidden");
                }
            }
        }
    }

    #[test]
    fn malformed_patterns_are_rejected() {
        let params = small(3, 600);
        let shape = Shape::new(&params).expect("supported row");
        let mut hidden = pattern(&params, 0);
        assert_eq!(
            mark_hidden(&shape, &hidden[..49]).map(|_| ()),
            Err(BavcError::InvalidIndexCount {
                expected: 50,
                actual: 49
            })
        );
        // Vector 20 is the first short one: 4 entries.
        hidden[20] = 4;
        let out_of_range = Err(BavcError::IndexOutOfRange {
            vector: 20,
            index: 4,
            leaves: 4,
        });
        assert_eq!(opening_nodes(&params, &hidden), out_of_range);
        hidden[20] = 3;
        hidden[19] = 7;
        assert!(opening_nodes(&params, &hidden).is_ok());
        hidden[19] = 8;
        assert_eq!(
            opening_nodes(&params, &hidden),
            Err(BavcError::IndexOutOfRange {
                vector: 19,
                index: 8,
                leaves: 8
            })
        );
    }

    #[test]
    fn commit_builds_the_tree_of_figure_5_4() {
        for params in rows() {
            let lb = params.lambda().bytes();
            let seed = root(&params);
            let commitment = commit(&params, &seed, &IV).expect("valid call");
            assert_eq!(commitment.params(), &params);
            assert_eq!(commitment.commitment().len(), 2 * lb);
            let keys = commitment.node_keys();
            assert_eq!(keys.len(), (2 * params.leaves() - 1) * lb);
            assert_eq!(key(keys, lb, 0), seed);
            for node in [0usize, 1, 17, params.leaves() - 2] {
                let mut children = vec![0u8; 2 * lb];
                Prg::new(key(keys, lb, node))
                    .expect("valid key")
                    .fill(&IV, u32::try_from(node).expect("small"), &mut children)
                    .expect("short output");
                assert_eq!(keys[(2 * node + 1) * lb..(2 * node + 3) * lb], children[..]);
            }

            // Recompute the commitment from the public leaf function.
            let shape = Shape::new(&params).expect("supported row");
            let mut uhash = vec![0u8; shape.scheme.hash_key_bytes(shape.level)];
            if shape.scheme == LeafScheme::Hashed {
                hash(shape.level, Oracle::H0, &IV, &mut uhash).expect("exact length");
            }
            let mut outer = Hasher::new(shape.level, Oracle::H1);
            for vector in 0..params.tau() {
                let seeds = commitment.seeds(vector).expect("vector below tau");
                let leaves = params.leaves_of(vector).expect("vector below tau");
                assert_eq!(seeds.len(), leaves * lb);
                let mut inner = Hasher::new(shape.level, Oracle::H1);
                for index in 0..leaves {
                    let node = position_in_tree(&params, vector, index).expect("valid leaf");
                    let (mut sd, mut com) = (vec![0u8; lb], vec![0u8; shape.com_bytes]);
                    let tweak = u32::try_from(params.leaves() - 1 + vector).expect("small");
                    leaf_commit(
                        &params,
                        key(keys, lb, node),
                        &IV,
                        tweak,
                        &uhash,
                        &mut sd,
                        &mut com,
                    )
                    .expect("valid call");
                    assert_eq!(key(seeds, lb, index), sd);
                    inner.update(&com);
                }
                let mut vector_hash = vec![0u8; 2 * lb];
                inner.finalize(&mut vector_hash).expect("exact length");
                outer.update(&vector_hash);
            }
            let mut expected = vec![0u8; 2 * lb];
            outer.finalize(&mut expected).expect("exact length");
            assert_eq!(commitment.commitment(), expected);
            assert!(commitment.seeds(params.tau()).is_none());
            assert!(!format!("{commitment:?}").contains("keys"));
        }
    }

    /// SHAKE of the row's level computed by the independent `sha3` crate.
    fn shake(level: SecurityLevel, parts: &[&[u8]], len: usize) -> Vec<u8> {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let mut out = vec![0u8; len];
        if level == SecurityLevel::L128 {
            let mut sponge = sha3::Shake128::default();
            for part in parts {
                sponge.update(part);
            }
            sponge.finalize_xof().read(&mut out);
        } else {
            let mut sponge = sha3::Shake256::default();
            for part in parts {
                sponge.update(part);
            }
            sponge.finalize_xof().read(&mut out);
        }
        out
    }

    /// The commitment recomputed from the node keys with an independent SHAKE,
    /// with a separate prefix for `H_0`, the inner `H_1` and the outer `H_1`.
    fn independent_commitment(params: &VoleParams, keys: &[u8], prefixes: [&[u8]; 3]) -> Vec<u8> {
        let [for_h0, for_inner, for_outer] = prefixes;
        let shape = Shape::new(params).expect("supported row");
        let lb = shape.lb;
        let uhash = if shape.scheme == LeafScheme::Hashed {
            shake(shape.level, &[for_h0, &IV, &[0x00]], 3 * lb)
        } else {
            Vec::new()
        };
        let mut digests = Vec::new();
        for vector in 0..params.tau() {
            let mut leaves = Vec::new();
            for index in 0..params.leaves_of(vector).expect("vector below tau") {
                let node = position_in_tree(params, vector, index).expect("valid leaf");
                let (mut sd, mut com) = (vec![0u8; lb], vec![0u8; shape.com_bytes]);
                let tweak = u32::try_from(params.leaves() - 1 + vector).expect("small");
                leaf_commit(
                    params,
                    key(keys, lb, node),
                    &IV,
                    tweak,
                    &uhash,
                    &mut sd,
                    &mut com,
                )
                .expect("valid call");
                leaves.extend_from_slice(&com);
            }
            digests.extend(shake(shape.level, &[for_inner, &leaves, &[0x01]], 2 * lb));
        }
        shake(shape.level, &[for_outer, &digests, &[0x01]], 2 * lb)
    }

    #[test]
    fn each_hash_of_the_commitment_absorbs_the_namespace_prefix() {
        let first = [0xa5u8; 77];
        let prefixes: [&[u8]; 3] = [b"", &first, b"a second namespace"];
        for params in rows() {
            let seed = root(&params);
            let mut observed_commitments = Vec::new();
            for prefix in prefixes {
                let namespace = Namespace::new(prefix).expect("bounded");
                let commitment = commit_in(namespace, &params, &seed, &IV).expect("valid call");
                let keys = commitment.node_keys();
                // The exact layout of every call: prefix || body || suffix.
                assert_eq!(
                    commitment.commitment(),
                    independent_commitment(&params, keys, [prefix; 3])
                );
                if !prefix.is_empty() {
                    // A call that forgot the prefix would give one of these.
                    let hashed = LeafScheme::of(&params) == LeafScheme::Hashed;
                    for (forgotten, observable) in [(0, hashed), (1, true), (2, true)] {
                        let mut mixed = [prefix; 3];
                        mixed[forgotten] = b"";
                        let other = independent_commitment(&params, keys, mixed);
                        assert_eq!(other != commitment.commitment(), observable);
                    }
                }
                // The tree and the seeds do not depend on the namespace.
                let plain = commit(&params, &seed, &IV).expect("valid call");
                assert_eq!(plain.node_keys(), keys);
                assert_eq!(plain.seeds(0), commitment.seeds(0));
                assert_eq!(
                    plain.commitment() == commitment.commitment(),
                    prefix.is_empty()
                );

                // The verifier recomputes the commitment only in the same namespace.
                let hidden = pattern(&params, 3);
                {
                    let decommitment = commitment.open(&hidden).expect("pattern fits");
                    let same = reconstruct_in(namespace, &params, &decommitment, &hidden, &IV)
                        .expect("honest opening");
                    assert_eq!(same.commitment(), commitment.commitment());
                    let other = Namespace::new(b"a third namespace").expect("bounded");
                    let foreign = reconstruct_in(other, &params, &decommitment, &hidden, &IV)
                        .expect("well formed");
                    assert_ne!(foreign.commitment(), commitment.commitment());
                    let plain =
                        reconstruct(&params, &decommitment, &hidden, &IV).expect("well formed");
                    assert_eq!(
                        plain.commitment() == commitment.commitment(),
                        prefix.is_empty()
                    );
                }
                observed_commitments.push(commitment.commitment().to_vec());
            }
            observed_commitments.sort();
            observed_commitments.dedup();
            assert_eq!(observed_commitments.len(), prefixes.len());
        }
    }

    #[test]
    fn the_leaf_hash_key_is_h0_of_the_iv_inside_the_namespace() {
        let prefix = [0x3cu8; 77];
        let namespace = Namespace::new(&prefix).expect("bounded");
        for level in SecurityLevel::ALL {
            let committer =
                LeafCommitter::new(namespace, level, LeafScheme::Hashed, &IV).expect("valid call");
            let expected = shake(level, &[&prefix, &IV, &[0x00]], 3 * level.bytes());
            assert_eq!(committer.uhash[..3 * level.bytes()], expected[..]);
            let plain =
                LeafCommitter::new(REFERENCE, level, LeafScheme::Hashed, &IV).expect("valid call");
            assert_ne!(plain.uhash, committer.uhash);
        }
    }

    #[test]
    fn commit_rejects_a_root_of_the_wrong_length() {
        let params = small(3, 600);
        for length in [0, 15, 17, 24, 32] {
            assert_eq!(
                commit(&params, &vec![7u8; length], &IV).map(|_| ()),
                Err(BavcError::InvalidLength {
                    input: Input::RootSeed,
                    expected: 16,
                    actual: length
                })
            );
        }
    }

    #[test]
    fn commit_depends_on_root_and_iv() {
        let params = small(2, 600);
        let seed = root(&params);
        let base = commit(&params, &seed, &IV).expect("valid call");
        let again = commit(&params, &seed, &IV).expect("valid call");
        assert_eq!(base.commitment(), again.commitment());
        assert_eq!(base.node_keys(), again.node_keys());
        let mut other_seed = seed.clone();
        other_seed[0] ^= 1;
        let mut other_iv = IV;
        other_iv[15] ^= 0x80;
        assert_ne!(
            commit(&params, &other_seed, &IV)
                .expect("valid call")
                .commitment(),
            base.commitment()
        );
        assert_ne!(
            commit(&params, &seed, &other_iv)
                .expect("valid call")
                .commitment(),
            base.commitment()
        );
    }

    #[test]
    fn open_then_reconstruct_returns_the_commitment_and_seeds() {
        for params in rows() {
            let lb = params.lambda().bytes();
            let commitment = commit(&params, &root(&params), &IV).expect("valid call");
            for salt in 0..3 {
                let hidden = pattern(&params, salt);
                let decommitment = commitment.open(&hidden).expect("within T_open");
                assert_eq!(decommitment.len(), decommitment_bytes(&params));
                let rebuilt = reconstruct(&params, &decommitment, &hidden, &IV).expect("valid");
                assert_eq!(rebuilt.commitment(), commitment.commitment());
                for (vector, &index) in hidden.iter().enumerate() {
                    let delta = usize::from(index);
                    assert_eq!(rebuilt.hidden_index(vector), Some(index));
                    let mut expected = commitment.seeds(vector).expect("below tau").to_vec();
                    expected[delta * lb..(delta + 1) * lb].fill(0);
                    assert_eq!(rebuilt.seeds(vector), Some(&expected[..]));
                }
                assert_eq!(rebuilt.hidden_index(params.tau()), None);
                assert_eq!(rebuilt.seeds(params.tau()), None);
            }
        }
    }

    #[test]
    fn decommitment_layout_is_commitments_then_keys_then_zeros() {
        let params = small(3, 600);
        let shape = Shape::new(&params).expect("supported row");
        let commitment = commit(&params, &root(&params), &IV).expect("valid call");
        let hidden = pattern(&params, 1);
        let decommitment = commitment.open(&hidden).expect("within T_open");
        let (marks, revealed) = mark_hidden(&shape, &hidden).expect("valid pattern");
        let keys_at = 50 * 48;
        for (slot, node) in revealed_nodes(&shape, &marks).enumerate() {
            assert_eq!(
                decommitment[keys_at + 16 * slot..keys_at + 16 * (slot + 1)],
                *key(commitment.node_keys(), 16, node)
            );
        }
        assert!(revealed < 600);
        assert!(
            decommitment[keys_at + 16 * revealed..]
                .iter()
                .all(|&byte| byte == 0)
        );
        assert!(decommitment[..keys_at].iter().any(|&byte| byte != 0));
    }

    #[test]
    fn a_pattern_above_the_threshold_cannot_be_opened() {
        let wide = small(3, 600);
        let hidden = pattern(&wide, 2);
        let nodes = opening_nodes(&wide, &hidden).expect("valid pattern");
        assert!(nodes > 1);
        // The same pattern under a threshold one below what it needs, and exactly at it.
        for (t_open, fits) in [(nodes - 1, false), (nodes, true)] {
            let params = small(3, t_open);
            let commitment = commit(&params, &root(&params), &IV).expect("valid call");
            let opened = commitment.open(&hidden);
            if fits {
                let decommitment = opened.expect("exactly T_open keys");
                let rebuilt = reconstruct(&params, &decommitment, &hidden, &IV).expect("valid");
                assert_eq!(rebuilt.commitment(), commitment.commitment());
            } else {
                let too_large = BavcError::OpeningTooLarge { nodes, t_open };
                assert_eq!(opened, Err(too_large));
                assert!(too_large.is_retry());
                // The verifier rejects the same pattern whatever the bytes are.
                assert_eq!(
                    reconstruct(
                        &params,
                        &vec![0u8; decommitment_bytes(&params)],
                        &hidden,
                        &IV
                    ),
                    Err(too_large)
                );
            }
        }
    }

    #[test]
    fn reconstruct_rejects_malformed_decommitments() {
        let params = small(2, 600);
        let commitment = commit(&params, &root(&params), &IV).expect("valid call");
        let hidden = pattern(&params, 0);
        let decommitment = commitment.open(&hidden).expect("within T_open");
        let nodes = opening_nodes(&params, &hidden).expect("valid pattern");
        let length = decommitment.len();

        for wrong in [0, length - 1, length + 1, length - 16, length + 16] {
            let mut resized = decommitment.clone();
            resized.resize(wrong, 0);
            assert_eq!(
                reconstruct(&params, &resized, &hidden, &IV),
                Err(BavcError::InvalidLength {
                    input: Input::Decommitment,
                    expected: length,
                    actual: wrong
                })
            );
        }

        // Every byte of the padding is checked, from the first to the last.
        let padding = 50 * 32 + 16 * nodes;
        for position in [
            padding,
            padding + 1,
            usize::midpoint(padding, length),
            length - 1,
        ] {
            for bit in [0, 7] {
                let mut padded = decommitment.clone();
                padded[position] ^= 1 << bit;
                assert_eq!(
                    reconstruct(&params, &padded, &hidden, &IV),
                    Err(BavcError::NonZeroPadding)
                );
            }
        }

        assert_eq!(
            reconstruct(&params, &decommitment, &hidden[1..], &IV),
            Err(BavcError::InvalidIndexCount {
                expected: 50,
                actual: 49
            })
        );
        let mut out_of_range = hidden.clone();
        out_of_range[49] = 4;
        assert_eq!(
            reconstruct(&params, &decommitment, &out_of_range, &IV),
            Err(BavcError::IndexOutOfRange {
                vector: 49,
                index: 4,
                leaves: 4
            })
        );
        out_of_range[49] = u16::MAX;
        assert!(matches!(
            reconstruct(&params, &decommitment, &out_of_range, &IV),
            Err(BavcError::IndexOutOfRange { vector: 49, .. })
        ));
    }

    #[test]
    fn tampering_changes_the_reconstructed_commitment() {
        for params in [small(3, 600), small(2, 600)] {
            let commitment = commit(&params, &root(&params), &IV).expect("valid call");
            let hidden = pattern(&params, 4);
            let decommitment = commitment.open(&hidden).expect("within T_open");
            let used = 50 * params.leaf_commitment_bytes()
                + 16 * opening_nodes(&params, &hidden).expect("valid pattern");
            for position in (0..used).step_by(41) {
                let mut tampered = decommitment.clone();
                tampered[position] ^= 1 << (position % 8);
                let rebuilt = reconstruct(&params, &tampered, &hidden, &IV).expect("well formed");
                assert_ne!(
                    rebuilt.commitment(),
                    commitment.commitment(),
                    "byte {position}"
                );
            }
            // A different pattern with the same decommitment does not verify either.
            let mut moved = hidden.clone();
            moved[0] ^= 1;
            match reconstruct(&params, &decommitment, &moved, &IV) {
                Ok(rebuilt) => assert_ne!(rebuilt.commitment(), commitment.commitment()),
                Err(error) => assert!(matches!(
                    error,
                    BavcError::NonZeroPadding | BavcError::OpeningTooLarge { .. }
                )),
            }
        }
    }

    /// Pack indices into a challenge: the inverse of [`decode_challenge`].
    fn encode_challenge(params: &VoleParams, hidden: &[u16]) -> Vec<u8> {
        let mut challenge = vec![0u8; params.lambda().bytes()];
        let mut low = 0;
        for (vector, &index) in hidden.iter().enumerate() {
            let depth = params.depth(vector).expect("vector below tau");
            for offset in 0..depth {
                let bit = u8::try_from((index >> offset) & 1).expect("one bit");
                challenge[(low + offset) / 8] |= bit << ((low + offset) % 8);
            }
            low += depth;
        }
        assert_eq!(low, params.n_delta());
        challenge
    }

    #[test]
    fn challenge_decoding_inverts_the_packing() {
        let mut all: Vec<VoleParams> = FAEST_PARAMETER_SETS.iter().map(|set| *set.vole()).collect();
        all.extend(rows());
        for params in all {
            for salt in 0..4 {
                let hidden = pattern(&params, salt);
                let challenge = encode_challenge(&params, &hidden);
                assert_eq!(decode_challenge(&params, &challenge), Ok(hidden));
            }
            // All ones below the grinding bits: every index is the largest.
            let largest: Vec<u16> = (0..params.tau())
                .map(|vector| {
                    u16::try_from(params.leaves_of(vector).expect("below tau") - 1).expect("fits")
                })
                .collect();
            let challenge = encode_challenge(&params, &largest);
            assert_eq!(decode_challenge(&params, &challenge), Ok(largest));
        }
    }

    /// Figure 5.7 by hand: FAEST-128f has `k = 8`, `tau_1 = 1`, so vector 0 takes
    /// bits `[0, 8)` and vector `i >= 1` the seven bits from `8 + 7 (i - 1)`.
    #[test]
    fn challenge_decoding_matches_figure_5_7() {
        let params = *FAEST_PARAMETER_SETS[1].vole();
        assert_eq!((params.tau(), params.k(), params.tau1()), (17, 8, 1));
        let mut challenge = [0u8; 16];
        challenge[0] = 0xa5;
        challenge[1] = 0b1000_0011;
        challenge[2] = 0b0000_0001;
        let hidden = decode_challenge(&params, &challenge).expect("grinding bits clear");
        assert_eq!(hidden[0], 0xa5);
        assert_eq!(hidden[1], 0b000_0011);
        assert_eq!(hidden[2], 0b000_0011);
        assert!(hidden[3..].iter().all(|&index| index == 0));
        assert_eq!(hidden.len(), 17);
    }

    #[test]
    fn challenge_decoding_checks_length_and_grinding() {
        for set in &FAEST_PARAMETER_SETS {
            let params = set.vole();
            let lb = params.lambda().bytes();
            let zero = vec![0u8; lb];
            assert_eq!(
                decode_challenge(params, &zero),
                Ok(vec![0u16; params.tau()])
            );
            for wrong in [lb - 1, lb + 1] {
                assert_eq!(
                    decode_challenge(params, &vec![0u8; wrong]),
                    Err(BavcError::InvalidLength {
                        input: Input::Challenge,
                        expected: lb,
                        actual: wrong
                    })
                );
            }
            for position in 0..8 * lb {
                let mut challenge = zero.clone();
                challenge[position / 8] |= 1 << (position % 8);
                let decoded = decode_challenge(params, &challenge);
                if position < params.n_delta() {
                    let hidden = decoded.expect("no grinding bit set");
                    assert_eq!(hidden.iter().filter(|&&index| index != 0).count(), 1);
                } else {
                    assert_eq!(decoded, Err(BavcError::GrindingBitsSet), "{}", set.name());
                }
            }
        }
        // A row without grinding accepts every challenge.
        let params = VoleParams::new(SecurityLevel::L128, 64, 0, 600, 3, 7, 312).expect("valid");
        assert!(decode_challenge(&params, &[0xff; 16]).is_ok());
    }
}
