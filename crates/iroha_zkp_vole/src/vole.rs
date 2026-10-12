//! Small-VOLE conversion, `VOLECommit` and `VOLEReconstruct` (FAEST v3.0 section 6)
//! with the CRT layer of section 5.2 and Appendix B.
//!
//! # The column matrix
//!
//! The vector commitment of [`crate::bavc`] yields `tau` vectors of leaf seeds.
//! `ConvertToVOLE` ([`convert_to_vole`]) turns vector `i`, of `N_i = 2^{d_i}` seeds,
//! into a string `u_i` and `d_i` columns `v_{i,0..d_i}` of
//! `ell_hat = ell + n_mask * d_0` bits each. The columns of all instances, in
//! instance order, form a matrix of `n_Delta = sum_i d_i` columns: column
//! `start_i + c` is `v_{i,c}`, which is also the order of the bits of the decoded
//! challenge `Delta'`. Rows `[0, ell)` carry the witness mask and rows
//! `[ell + m * d_0, ell + (m + 1) * d_0)` are the block of mask `m`.
//!
//! # `VOLECommit` ([`commit`])
//!
//! 1. `u = u_0[0, ell)` and the corrections `c_i = u + u_i[0, ell)` for `i >= 1`
//!    make all instances share one `u`.
//! 2. Mask `m` has the value
//!    `ubar_m = W_CRT * u_low^(m) + M_tree(x) * u_hi^(m)(x)`, where bit
//!    `start_i + b` of `u_low^(m)` is row `ell + m * d_0 + b` of `u_i` and the
//!    `n_mask` strings `u_hi^(m)` of `w_grind` bits are consecutive pieces of
//!    `PRG(r, iv, 2^31 - 1; n_mask * w_grind)` ([`MASK_TWEAK`]).
//! 3. The tree share of instance `i` in mask `m` is the residue modulo the tree
//!    modulus `M_i` of `sum_{c,t} v_{i,c}[ell + m * d_0 + t] x^{c + t}`, written to
//!    bits `[start_i, start_i + d_i)`.
//! 4. Gate `e` of the `n_mult` multiplication gates has the label `L_0`, the sum of
//!    the columns selected by row `e` of `G`, restricted to rows `[0, lambda)`, and
//!    `L_1 = L_0 + u[0, lambda)`. With `h_b = H_5(iv, e, L_b)` of `n_mask` bits, the
//!    gate share of mask `m` is bit `m` of `h_0` and the published correction is
//!    `c_mult[m][e] = h_0[m] + h_1[m] + <F[e], ubar_m>`.
//! 5. The tag of mask `m` is `vbar_m = W_tree * shares_m + W_gate * gates_m`, and
//!    row `j < ell` of the column matrix is lifted to the field element
//!    `V[j] = W_CRT * row_j`.
//!
//! # `VOLEReconstruct` ([`reconstruct`])
//!
//! The verifier decodes `chall_3` into the hidden indices and `Delta'`
//! ([`crate::bavc::decode_challenge`], which rejects non-zero grinding bits),
//! rebuilds the revealed seeds, runs [`convert_to_vole_hidden`] and adds `c_i` to
//! column `start_i + c` on rows `[0, ell)` when bit `start_i + c` of `Delta'` is
//! set. With `Delta = W_CRT * Delta'` this gives `Q[j] = V[j] + u[j] * Delta`. The
//! mask keys follow the prover's steps 3 to 5 on the `q` columns, with the gate
//! share `H_5(iv, e, L')[m] + <G[e], Delta'> * c_mult[m][e]`, and satisfy
//! `qbar_m = vbar_m + ubar_m * Delta`. `Delta`, `V[j]` and `Q[j]` have their top
//! `w_grind` coefficients zero; the mask values are full field elements.
//!
//! # Tables
//!
//! `F`, `G`, `W_tree`, `W_gate`, `W_CRT`, the tree moduli and `M_tree` come from a
//! [`CrtTables`] set. [`commit`] and [`reconstruct`] use the set embedded for the
//! row ([`VoleParams::crt_tables`]); the `_with_tables` variants take any set that
//! matches the row, for example one built by [`crate::crt::generator`]. The witness
//! length `ell` is free: nothing in the tables depends on it.
//!
//! # Namespaces
//!
//! [`commit_in`] and [`reconstruct_in`] evaluate every random-oracle call of this
//! layer and of the vector commitment below it (`H_0`, both levels of `H_1`, and
//! `H_5`) inside a caller-supplied [`Namespace`]. The other entry points are the
//! same functions in reference mode, the empty prefix. The generator calls keep
//! their `iv` and tweaks in every namespace.
//!
//! # Secrets
//!
//! On the prover's side the seeds, every `u_i`, the columns, `u`, `V` and the mask
//! values and tags are secret. They are combined only with XOR, AND with public
//! table words, shifts by public amounts and population counts; no secret selects
//! a branch, an index or an early exit, and every buffer that held one is erased
//! on drop. The corrections `c_i` and `c_mult` are public outputs. Everything on
//! the verifier's side (`Delta`, `Q`, the mask keys, the proof) is public.
//!
//! # Memory
//!
//! One small-VOLE instance is converted at a time and no buffer is quadratic in
//! any parameter. With `lb = lambda / 8` and `W = ceil(ell_hat / 8)`:
//!
//! * the vector commitment (`(2L - 1) * lb` bytes of node keys and `L * lb` of
//!   seeds for the prover, `L * lb` of seeds for the verifier);
//! * the column matrix, `n_Delta * W` bytes, and the working buffers of one
//!   conversion, `(d_0 + 2) * W` bytes;
//! * the lift: `lambda * W` bytes of lifted columns, the column matrix being freed
//!   before the `ell * lb` bytes of `V` or `Q` are allocated;
//! * `(tau - 1) * ell / 8` bytes of corrections, and `(n_Delta + n_mult) * lb`
//!   bytes of gate labels.
//!
//! For a relation of `ell = 36,000` witness bits on the FAEST-256f row
//! (`lambda = 256`, `tau = 33`, `n_Delta = 248`, `d_0 = 8`, `L = 6400`):
//! `ell_hat = 36,080`, `W = 4510`, so the column matrix is 1,118,480 bytes, a
//! conversion works in 45,100 bytes, the lifted columns are 1,154,560 bytes, `V` is
//! 1,152,000 bytes, the corrections 144,000 bytes and the vector commitment
//! 614,368 bytes. The peak is the lifted columns together with `V`, about 3.1 MB
//! in all for the prover; the verifier, which has dropped its seeds by then,
//! peaks at about 2.3 MB. On the FAEST-256s row
//! (`tau = 22`, `n_Delta = 250`, `d_0 = 12`, `L = 61,440`) `W = 4515` and the same
//! buffers are within one percent of these, but the vector commitment holds
//! 5,898,208 bytes.
//!
//! # Conformance
//!
//! `tests/conformance_vole.rs` reproduces every entry of
//! `tests/fixtures/faest_v3_0_2/vole_tvs.txt` for all twelve parameter sets.

mod bits;
pub mod convert;

use core::fmt;

use thiserror::Error;
use zeroize::Zeroizing;

use self::bits::{bit, load_words, or_bits, read_bits, store_words, xor_into, xor_shifted_masked};
pub use self::convert::{SMALL_VOLE_TWEAK, convert_to_vole, convert_to_vole_hidden};
use crate::{
    bavc::{self, BavcError},
    crt::{CrtError, CrtTables},
    field::{FieldError, LambdaField},
    hash::{HashError, Namespace, h5_in},
    params::{IV_BYTES, ProofParams, SecurityLevel, VoleParams},
    prg::{Prg, PrgError},
};

/// Tweak of the generator of the high parts `u_hi^(m)` of the mask values:
/// `2^31 - 1`, one below the small-VOLE tweaks.
pub const MASK_TWEAK: u32 = SMALL_VOLE_TWEAK - 1;

/// Largest `lambda / 8`.
const MAX_LAMBDA_BYTES: usize = 32;

/// Which buffer had the wrong length in a [`VoleError::InvalidLength`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Input {
    /// The leaf seeds of one instance, `N_i * lambda / 8` bytes.
    Seeds,
    /// The columns of one instance, `d_i * ceil(bits / 8)` bytes.
    Columns,
    /// The string `u_i` of one instance, `ceil(bits / 8)` bytes.
    SmallVoleU,
    /// The corrections `c_1 || ... || c_{tau - 1}`, [`corrections_bytes`] bytes.
    Corrections,
    /// The gate corrections `c_mult`, [`mult_corrections_bytes`] bytes.
    MultCorrections,
}

/// Errors and rejections of the VOLE layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum VoleError {
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
    /// There is no small-VOLE instance with this number.
    #[error("small-VOLE instance {instance} is not below tau = {tau}")]
    InstanceOutOfRange {
        /// The instance asked for.
        instance: usize,
        /// `tau`.
        tau: usize,
    },
    /// The table set was built for another parameter row.
    #[error("the CRT tables have {what} = {actual}, the row needs {expected}")]
    TableMismatch {
        /// The quantity that differs.
        what: &'static str,
        /// Value the row needs.
        expected: usize,
        /// Value of the tables.
        actual: usize,
    },
    /// A padding bit of `c_mult` (a bit at or above `n_mult` in a row) is set.
    #[error("a padding bit of the gate corrections is not zero")]
    NonZeroPadding,
    /// Field elements of another security level were asked for.
    #[error("the row has lambda = {expected}, the field has {actual} bits")]
    FieldMismatch {
        /// `lambda` of the row.
        expected: usize,
        /// Extension degree of the field type.
        actual: usize,
    },
    /// A buffer size does not fit the address space. No row the parameter
    /// constructors accept triggers this on a 32-bit or larger target.
    #[error("the size of the {what} overflows")]
    TooLarge {
        /// The buffer concerned.
        what: &'static str,
    },
    /// The vector commitment rejected a call. This carries the two retry outcomes
    /// of a signer, see [`Self::is_retry`].
    #[error(transparent)]
    Bavc(#[from] BavcError),
    /// A table product rejected a call.
    #[error(transparent)]
    Crt(#[from] CrtError),
    /// The pseudorandom generator rejected a call.
    #[error(transparent)]
    Prg(#[from] PrgError),
    /// A hash function rejected a call.
    #[error(transparent)]
    Hash(#[from] HashError),
    /// Decoding field elements failed.
    #[error(transparent)]
    Field(#[from] FieldError),
}

impl VoleError {
    /// Whether the error is one of the two outcomes a signer answers by trying the
    /// next counter ([`BavcError::is_retry`]).
    pub const fn is_retry(&self) -> bool {
        match self {
            Self::Bavc(error) => error.is_retry(),
            _ => false,
        }
    }
}

fn check_length(input: Input, expected: usize, actual: usize) -> Result<(), VoleError> {
    if expected == actual {
        Ok(())
    } else {
        Err(VoleError::InvalidLength {
            input,
            expected,
            actual,
        })
    }
}

/// `left * right`, or [`VoleError::TooLarge`] naming the buffer.
fn product(what: &'static str, left: usize, right: usize) -> Result<usize, VoleError> {
    left.checked_mul(right).ok_or(VoleError::TooLarge { what })
}

/// A table scalar as a `usize`.
fn index(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// Bytes of the corrections `c_1 || ... || c_{tau - 1}`: `(tau - 1) * ell / 8`.
pub const fn corrections_bytes(params: &ProofParams) -> usize {
    (params.vole().tau() - 1) * params.witness_bytes()
}

/// Bytes of the gate corrections `c_mult`: `n_mask` rows of `ceil(n_mult / 8)`
/// bytes, gate `e` of mask `m` at bit `e` of row `m`.
pub const fn mult_corrections_bytes(params: &VoleParams) -> usize {
    params.n_mask() * params.n_mult().div_ceil(8)
}

/// Decode `bytes` as consecutive elements of the field `F` of the row's security
/// level, for example [`Commitment::v`] as `ell` elements of `GF(2^lambda)`.
///
/// The result is erased on drop, because the prover's values are secret.
///
/// # Errors
/// [`VoleError::FieldMismatch`] unless `F` is the field of `params.lambda()` and
/// [`FieldError`] (wrapped) unless `bytes` is a whole number of elements.
pub fn elements<F: LambdaField>(
    params: &VoleParams,
    bytes: &[u8],
) -> Result<Zeroizing<Vec<F>>, VoleError> {
    if F::LEVEL != params.lambda() {
        return Err(VoleError::FieldMismatch {
            expected: params.lambda().bits(),
            actual: F::BITS,
        });
    }
    if !bytes.len().is_multiple_of(F::BYTES) {
        return Err(VoleError::Field(FieldError::InvalidLength {
            expected: bytes.len().next_multiple_of(F::BYTES),
            actual: bytes.len(),
        }));
    }
    // Sized once and already inside the erasing wrapper: the vector never
    // reallocates, so no copy of the values is left behind in freed memory.
    let mut decoded = Zeroizing::new(Vec::with_capacity(bytes.len() / F::BYTES));
    for chunk in bytes.chunks_exact(F::BYTES) {
        decoded.push(F::from_bytes(chunk)?);
    }
    Ok(decoded)
}

/// [`VoleError::NonZeroPadding`] if a bit at or above `n_mult` is set in one of
/// the rows of `ceil(n_mult / 8)` bytes of `mult_corrections`.
fn check_padding(n_mult: usize, mult_corrections: &[u8]) -> Result<(), VoleError> {
    let used = n_mult % 8;
    if used != 0
        && mult_corrections
            .chunks_exact(n_mult.div_ceil(8))
            .any(|row| row.last().is_some_and(|last| last >> used != 0))
    {
        return Err(VoleError::NonZeroPadding);
    }
    Ok(())
}

/// `value mod modulus` in `GF(2)[x]` for a modulus of degree `depth` (leading bit
/// included) and a value of degree at most `2 * depth - 2`. The modulus is public;
/// the value may be secret and only selects masks.
fn reduce(mut value: u32, modulus: u32, depth: usize) -> u32 {
    for position in (depth..(2 * depth).saturating_sub(1)).rev() {
        let mask = 0u32.wrapping_sub((value >> position) & 1);
        value ^= (modulus << (position - depth)) & mask;
    }
    value
}

/// Set bit `gate` of row `mask` of `rows` to bit `mask` of `value`, for every mask.
/// `rows` holds `n_mask` rows of `words` words, all bits concerned still zero.
fn spread(rows: &mut [u64], words: usize, gate: usize, value: u16) {
    for (mask, row) in rows.chunks_exact_mut(words).enumerate() {
        if let Some(word) = row.get_mut(gate / 64) {
            *word |= u64::from((value >> mask) & 1) << (gate % 64);
        }
    }
}

/// One small-VOLE instance in the column matrix.
#[derive(Debug, Clone, Copy)]
struct Tree {
    /// `d_i`.
    depth: usize,
    /// `start_i`, the first column and the first residue coordinate.
    start: usize,
    /// The tree modulus `M_i`, leading bit included.
    modulus: u32,
}

/// The sizes of one row with its tables, validated once.
struct Layout<'t> {
    vole: VoleParams,
    tables: &'t CrtTables<'t>,
    level: SecurityLevel,
    /// `lambda / 8`.
    lb: usize,
    /// `ell`.
    ell: usize,
    /// `ell / 8`.
    ell_bytes: usize,
    /// `ell_hat`.
    ell_hat: usize,
    /// `ceil(ell_hat / 8)`, the bytes of one column.
    width: usize,
    n_delta: usize,
    w_grind: usize,
    n_mask: usize,
    n_mult: usize,
    d0: usize,
    trees: Vec<Tree>,
}

impl<'t> Layout<'t> {
    fn new(params: &ProofParams, tables: &'t CrtTables<'t>) -> Result<Self, VoleError> {
        fn same(what: &'static str, expected: usize, actual: u32) -> Result<(), VoleError> {
            let actual = index(actual);
            if expected == actual {
                Ok(())
            } else {
                Err(VoleError::TableMismatch {
                    what,
                    expected,
                    actual,
                })
            }
        }

        let vole = *params.vole();
        let level = vole.lambda();
        same("lambda", level.bits(), tables.lambda())?;
        same("tau", vole.tau(), tables.tau())?;
        same("w_grind", vole.w_grind(), tables.w_grind())?;
        same("n_mult", vole.n_mult(), tables.n_mult())?;
        let tau = vole.tau();
        let mut trees = Vec::with_capacity(tau);
        let mut start = 0;
        for instance in 0..tau {
            let depth = vole
                .depth(instance)
                .ok_or(VoleError::InstanceOutOfRange { instance, tau })?;
            same(
                "tree modulus degree",
                depth,
                tables.tree_degree(instance).unwrap_or(u32::MAX),
            )?;
            same(
                "residue offset",
                start,
                tables.residue_offset(instance).unwrap_or(u32::MAX),
            )?;
            let modulus = tables
                .tree_modulus(instance)
                .ok_or(VoleError::TableMismatch {
                    what: "tree moduli",
                    expected: tau,
                    actual: instance,
                })?;
            trees.push(Tree {
                depth,
                start,
                modulus: u32::from(modulus),
            });
            start += depth;
        }
        let ell_hat = params.ell_hat();
        Ok(Self {
            vole,
            tables,
            level,
            lb: level.bytes(),
            ell: params.witness_bits(),
            ell_bytes: params.witness_bytes(),
            ell_hat,
            width: ell_hat.div_ceil(8),
            n_delta: vole.n_delta(),
            w_grind: vole.w_grind(),
            n_mask: vole.n_mask(),
            n_mult: vole.n_mult(),
            d0: vole.d0(),
            trees,
        })
    }

    /// Words of an `n_Delta`-bit string.
    fn delta_words(&self) -> usize {
        self.n_delta.div_ceil(64)
    }

    /// Words of an `n_mult`-bit string.
    fn gate_words(&self) -> usize {
        self.n_mult.div_ceil(64)
    }

    /// Words of a `lambda`-bit string.
    fn lambda_words(&self) -> usize {
        self.lb / 8
    }

    /// Bytes of one row of `c_mult`.
    fn gate_bytes(&self) -> usize {
        self.n_mult.div_ceil(8)
    }

    /// The first row `ell + m * d_0` of the block of mask `mask`.
    fn mask_row(&self, mask: usize) -> usize {
        self.ell + mask * self.d0
    }

    /// A zeroed column matrix, `n_Delta * W` bytes.
    fn new_columns(&self) -> Result<Zeroizing<Vec<u8>>, VoleError> {
        let len = product("column matrix", self.n_delta, self.width)?;
        Ok(Zeroizing::new(vec![0u8; len]))
    }

    /// The columns of `tree` inside a column matrix.
    fn block<'c>(&self, tree: &Tree, columns: &'c mut [u8]) -> &'c mut [u8] {
        &mut columns[tree.start * self.width..(tree.start + tree.depth) * self.width]
    }

    /// Write the mask rows of `u_i` to bits `[start_i, start_i + d_i)` of each
    /// `u_low^(m)`. `low` holds `n_mask` strings of [`Self::delta_words`] words.
    fn fold_mask_values(&self, tree: &Tree, u: &[u8], low: &mut [u64]) {
        for (mask, target) in low.chunks_exact_mut(self.delta_words()).enumerate() {
            let value = read_bits(u, self.mask_row(mask), tree.depth);
            or_bits(target, tree.start, tree.depth, u64::from(value));
        }
    }

    /// Write the tree share of `tree` in each mask, the residue of its mask block
    /// modulo `M_i`, to bits `[start_i, start_i + d_i)` of `shares`. `block` is the
    /// `d_i` columns of the instance.
    fn fold_mask_rows(&self, tree: &Tree, block: &[u8], shares: &mut [u64]) {
        for (mask, target) in shares.chunks_exact_mut(self.delta_words()).enumerate() {
            let row = self.mask_row(mask);
            let mut value = 0u32;
            for (position, column) in block.chunks_exact(self.width).enumerate() {
                value ^= read_bits(column, row, tree.depth) << position;
            }
            let residue = reduce(value, tree.modulus, tree.depth);
            or_bits(target, tree.start, tree.depth, u64::from(residue));
        }
    }

    /// The mask values `ubar_m` as `n_mask` strings of [`Self::lambda_words`]
    /// words, from the low parts `low` and the high parts drawn from `root`.
    fn mask_values(
        &self,
        root: &[u8],
        iv: &[u8; IV_BYTES],
        low: &[u64],
    ) -> Result<Zeroizing<Vec<u64>>, VoleError> {
        let high_bits = product("mask generator output", self.n_mask, self.w_grind)?;
        let mut high = Zeroizing::new(vec![0u8; high_bits.div_ceil(8)]);
        Prg::new(root)?.fill_bits(iv, MASK_TWEAK, high_bits, &mut high)?;
        let words = self.lambda_words();
        let mut values = Zeroizing::new(vec![0u64; self.n_mask * words]);
        for (mask, (value, low)) in values
            .chunks_exact_mut(words)
            .zip(low.chunks_exact(self.delta_words()))
            .enumerate()
        {
            self.tables.w_crt().mul_vec(value, low)?;
            // `M_tree(x) * u_hi(x)`: degree below `n_Delta + w_grind = lambda`.
            for position in 0..self.w_grind {
                let selected = 0u64.wrapping_sub(bit(&high, mask * self.w_grind + position));
                xor_shifted_masked(value, self.tables.m_tree(), position, selected);
            }
        }
        Ok(values)
    }

    /// The label of every gate: the sum of the columns selected by its row of `G`,
    /// restricted to rows `[0, lambda)`. `n_mult` labels of `lambda / 8` bytes.
    fn gate_labels(&self, columns: &[u8]) -> Result<Zeroizing<Vec<u8>>, VoleError> {
        let lb = self.lb;
        let mut heads = Zeroizing::new(vec![0u8; product("label inputs", self.n_delta, lb)?]);
        for (head, column) in heads
            .chunks_exact_mut(lb)
            .zip(columns.chunks_exact(self.width))
        {
            // `ell >= lambda`, so a column has at least `lambda / 8` bytes.
            for (slot, byte) in head.iter_mut().zip(column) {
                *slot = *byte;
            }
        }
        let mut labels = Zeroizing::new(vec![0u8; product("gate labels", self.n_mult, lb)?]);
        self.tables
            .g()
            .apply_to_byte_columns(&mut labels, &heads, lb)?;
        Ok(labels)
    }

    /// `W_tree * shares_m + W_gate * gates_m` for every mask: `n_mask` elements of
    /// `lambda / 8` bytes.
    fn mask_tags(&self, shares: &[u64], gates: &[u64]) -> Result<Zeroizing<Vec<u8>>, VoleError> {
        let words = self.lambda_words();
        let mut tags = Zeroizing::new(vec![0u8; self.n_mask * self.lb]);
        let mut tree_part = Zeroizing::new(vec![0u64; words]);
        let mut gate_part = Zeroizing::new(vec![0u64; words]);
        for ((tag, shares), gates) in tags
            .chunks_exact_mut(self.lb)
            .zip(shares.chunks_exact(self.delta_words()))
            .zip(gates.chunks_exact(self.gate_words()))
        {
            self.tables.w_tree().mul_vec(&mut tree_part, shares)?;
            self.tables.w_gate().mul_vec(&mut gate_part, gates)?;
            for (left, right) in tree_part.iter_mut().zip(gate_part.iter()) {
                *left ^= *right;
            }
            store_words(tag, &tree_part);
        }
        Ok(tags)
    }

    /// Lift rows `[0, ell)` of the column matrix: element `j` of the result is
    /// `W_CRT * row_j`, `lambda / 8` bytes. The column matrix is freed before the
    /// result is allocated.
    fn lift(&self, columns: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, VoleError> {
        let (lb, width) = (self.lb, self.width);
        let lifted_len = product("lifted columns", self.level.bits(), width)?;
        let rows_len = product("lifted rows", self.ell, lb)?;
        // Lifted column `r` is the sum of the columns selected by row `r` of
        // `W_CRT`; its bit `j` is bit `r` of `W_CRT * row_j`.
        let mut lifted = Zeroizing::new(vec![0u8; lifted_len]);
        self.tables
            .w_crt()
            .apply_to_byte_columns(&mut lifted, &columns, width)?;
        drop(columns);
        let mut rows = Zeroizing::new(vec![0u8; rows_len]);
        for (position, column) in lifted.chunks_exact(width).enumerate() {
            let (byte, shift) = (position / 8, position % 8);
            // Eight rows per column byte; `rows` ends after `ell / 8` groups.
            for (group, bits) in rows.chunks_exact_mut(8 * lb).zip(column.iter()) {
                for (offset, row) in group.chunks_exact_mut(lb).enumerate() {
                    if let Some(slot) = row.get_mut(byte) {
                        *slot |= ((bits >> offset) & 1) << shift;
                    }
                }
            }
        }
        Ok(rows)
    }
}

/// The prover's side of `VOLECommit`: the result of [`commit`].
///
/// `u`, `V`, the mask values and tags and the vector commitment inside are secret
/// and erased on drop.
pub struct Commitment {
    params: ProofParams,
    tree: bavc::Commitment,
    corrections: Vec<u8>,
    mult_corrections: Vec<u8>,
    u: Zeroizing<Vec<u8>>,
    v: Zeroizing<Vec<u8>>,
    u_masks: Zeroizing<Vec<u8>>,
    v_masks: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Commitment")
            .field("params", &self.params)
            .field("com", &self.tree.commitment())
            .finish_non_exhaustive()
    }
}

impl Commitment {
    /// The row the commitment was made for.
    pub fn params(&self) -> &ProofParams {
        &self.params
    }

    /// The vector commitment `com`, `2 * lambda / 8` bytes. Public.
    pub fn commitment(&self) -> &[u8] {
        self.tree.commitment()
    }

    /// The corrections `c_1 || ... || c_{tau - 1}`, `ell / 8` bytes each. Public.
    pub fn corrections(&self) -> &[u8] {
        &self.corrections
    }

    /// The gate corrections `c_mult`: `n_mask` rows of `ceil(n_mult / 8)` bytes,
    /// gate `e` of mask `m` at bit `e` of row `m`, padding bits zero. Public.
    pub fn mult_corrections(&self) -> &[u8] {
        &self.mult_corrections
    }

    /// The witness mask `u`, `ell` bits. **Secret.**
    pub fn u(&self) -> &[u8] {
        &self.u
    }

    /// The tags `V[0] || ... || V[ell - 1]`, each an element of `GF(2^lambda)` in
    /// `lambda / 8` bytes ([`elements`]). **Secret.**
    pub fn v(&self) -> &[u8] {
        &self.v
    }

    /// The mask values `ubar_0 || ... || ubar_{n_mask - 1}`, elements of
    /// `GF(2^lambda)`. **Secret.**
    pub fn u_masks(&self) -> &[u8] {
        &self.u_masks
    }

    /// The mask tags `vbar_0 || ... || vbar_{n_mask - 1}`, elements of
    /// `GF(2^lambda)`. **Secret.**
    pub fn v_masks(&self) -> &[u8] {
        &self.v_masks
    }

    /// The underlying vector commitment.
    pub fn bavc(&self) -> &bavc::Commitment {
        &self.tree
    }

    /// `BAVC.Open` for the hidden indices decoded from `chall_3`
    /// ([`bavc::Commitment::open`]).
    ///
    /// # Errors
    /// As [`bavc::Commitment::open`]; [`VoleError::is_retry`] is true when the
    /// signer should try its next counter.
    pub fn open(&self, hidden: &[u16]) -> Result<Vec<u8>, VoleError> {
        Ok(self.tree.open(hidden)?)
    }
}

/// `VOLECommit(r, iv)` with the table set embedded for the row.
///
/// `root` is the seed `r`, `lambda / 8` bytes.
///
/// # Errors
/// [`CrtError::NoEmbeddedTables`] (wrapped) if the row has no embedded set, and
/// as [`commit_with_tables`].
pub fn commit(
    params: &ProofParams,
    root: &[u8],
    iv: &[u8; IV_BYTES],
) -> Result<Commitment, VoleError> {
    commit_with_tables(params, params.vole().crt_tables()?, root, iv)
}

/// `VOLECommit(r, iv)` with an explicit table set, in reference mode.
///
/// # Errors
/// As [`commit_in`].
pub fn commit_with_tables(
    params: &ProofParams,
    tables: &CrtTables<'_>,
    root: &[u8],
    iv: &[u8; IV_BYTES],
) -> Result<Commitment, VoleError> {
    commit_in(Namespace::REFERENCE, params, tables, root, iv)
}

/// `VOLECommit(r, iv)` with an explicit table set and every random-oracle call
/// (`H_0`, `H_1`, `H_5`) evaluated inside `namespace`.
///
/// # Errors
/// * [`VoleError::TableMismatch`] unless `tables` has the row's `lambda`, `tau`,
///   `w_grind`, `n_mult` and tree degrees;
/// * [`BavcError::InvalidLength`] (wrapped) unless `root` is `lambda / 8` bytes.
pub fn commit_in(
    namespace: Namespace<'_>,
    params: &ProofParams,
    tables: &CrtTables<'_>,
    root: &[u8],
    iv: &[u8; IV_BYTES],
) -> Result<Commitment, VoleError> {
    let layout = Layout::new(params, tables)?;
    let (lb, ell_bytes) = (layout.lb, layout.ell_bytes);
    let tree = bavc::commit_in(namespace, &layout.vole, root, iv)?;

    let mut columns = layout.new_columns()?;
    let mut u = Zeroizing::new(vec![0u8; ell_bytes]);
    let mut corrections = vec![0u8; corrections_bytes(params)];
    let mut instance_u = Zeroizing::new(vec![0u8; layout.width]);
    let mut low = Zeroizing::new(vec![0u64; layout.n_mask * layout.delta_words()]);
    let mut shares = Zeroizing::new(vec![0u64; layout.n_mask * layout.delta_words()]);
    for (instance, shape) in layout.trees.iter().enumerate() {
        let seeds = tree.seeds(instance).ok_or(VoleError::InstanceOutOfRange {
            instance,
            tau: layout.trees.len(),
        })?;
        let block = layout.block(shape, &mut columns);
        convert_to_vole(
            &layout.vole,
            instance,
            iv,
            seeds,
            layout.ell_hat,
            &mut instance_u,
            block,
        )?;
        // `ell` is a multiple of 8: the first `ell / 8` bytes are rows `[0, ell)`.
        let head = &instance_u[..ell_bytes];
        if instance == 0 {
            u.copy_from_slice(head);
        } else {
            let correction = &mut corrections[(instance - 1) * ell_bytes..instance * ell_bytes];
            correction.copy_from_slice(&u);
            xor_into(correction, head);
        }
        layout.fold_mask_values(shape, &instance_u, &mut low);
        layout.fold_mask_rows(shape, block, &mut shares);
    }
    let mask_values = layout.mask_values(root, iv, &low)?;

    // Gates: both labels are hashed; the difference of the two hashes and the
    // mask value's coordinate under `F` give the public correction.
    let labels = layout.gate_labels(&columns)?;
    let gate_words = layout.gate_words();
    let mut gates = Zeroizing::new(vec![0u64; layout.n_mask * gate_words]);
    let mut differences = Zeroizing::new(vec![0u64; layout.n_mask * gate_words]);
    let mut shifted = Zeroizing::new([0u8; MAX_LAMBDA_BYTES]);
    for (gate, label) in labels.chunks_exact(lb).enumerate() {
        let number = u32::try_from(gate).map_err(|_| VoleError::TooLarge { what: "gate index" })?;
        let shifted = &mut shifted[..lb];
        shifted.copy_from_slice(label);
        xor_into(shifted, &u);
        let h0 = h5_in(namespace, layout.level, iv, number, label, layout.n_mask)?;
        let h1 = h5_in(namespace, layout.level, iv, number, shifted, layout.n_mask)?;
        spread(&mut gates, gate_words, gate, h0);
        spread(&mut differences, gate_words, gate, h0 ^ h1);
    }
    let mut mult_corrections = vec![0u8; mult_corrections_bytes(&layout.vole)];
    let mut row = Zeroizing::new(vec![0u64; gate_words]);
    for ((correction, value), difference) in mult_corrections
        .chunks_exact_mut(layout.gate_bytes())
        .zip(mask_values.chunks_exact(layout.lambda_words()))
        .zip(differences.chunks_exact(gate_words))
    {
        tables.f().mul_vec(&mut row, value)?;
        for (left, right) in row.iter_mut().zip(difference) {
            *left ^= *right;
        }
        store_words(correction, &row);
    }

    let v_masks = layout.mask_tags(&shares, &gates)?;
    let mut u_masks = Zeroizing::new(vec![0u8; layout.n_mask * lb]);
    for (bytes, words) in u_masks
        .chunks_exact_mut(lb)
        .zip(mask_values.chunks_exact(layout.lambda_words()))
    {
        store_words(bytes, words);
    }
    let v = layout.lift(columns)?;
    Ok(Commitment {
        params: *params,
        tree,
        corrections,
        mult_corrections,
        u,
        v,
        u_masks,
        v_masks,
    })
}

/// The verifier's side: the result of [`reconstruct`]. Everything in it is public.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reconstruction {
    commitment: Vec<u8>,
    hidden: Vec<u16>,
    delta: Vec<u8>,
    q: Vec<u8>,
    q_masks: Vec<u8>,
}

impl Reconstruction {
    /// The recomputed vector commitment `com`, `2 * lambda / 8` bytes. The caller
    /// must bind it into the challenge it checks; nothing here compares it.
    pub fn commitment(&self) -> &[u8] {
        &self.commitment
    }

    /// The hidden indices `Delta_0, ..., Delta_{tau - 1}` decoded from `chall_3`.
    pub fn hidden_indices(&self) -> &[u16] {
        &self.hidden
    }

    /// `Delta = W_CRT * Delta'`, an element of `GF(2^lambda)` in `lambda / 8`
    /// bytes whose top `w_grind` coefficients are zero.
    pub fn delta(&self) -> &[u8] {
        &self.delta
    }

    /// The keys `Q[0] || ... || Q[ell - 1]`, each an element of `GF(2^lambda)` in
    /// `lambda / 8` bytes, with `Q[j] = V[j] + u[j] * Delta` for an honest prover.
    pub fn q(&self) -> &[u8] {
        &self.q
    }

    /// The mask keys `qbar_0 || ... || qbar_{n_mask - 1}`, elements of
    /// `GF(2^lambda)`, with `qbar_m = vbar_m + ubar_m * Delta` for an honest prover.
    pub fn q_masks(&self) -> &[u8] {
        &self.q_masks
    }
}

/// `VOLEReconstruct(chall_3, decom_I, c, c_mult, iv)` with the table set embedded
/// for the row.
///
/// # Errors
/// [`CrtError::NoEmbeddedTables`] (wrapped) if the row has no embedded set, and
/// as [`reconstruct_with_tables`].
pub fn reconstruct(
    params: &ProofParams,
    challenge: &[u8],
    decommitment: &[u8],
    corrections: &[u8],
    mult_corrections: &[u8],
    iv: &[u8; IV_BYTES],
) -> Result<Reconstruction, VoleError> {
    reconstruct_with_tables(
        params,
        params.vole().crt_tables()?,
        challenge,
        decommitment,
        corrections,
        mult_corrections,
        iv,
    )
}

/// `VOLEReconstruct` with an explicit table set, in reference mode.
///
/// # Errors
/// As [`reconstruct_in`].
pub fn reconstruct_with_tables(
    params: &ProofParams,
    tables: &CrtTables<'_>,
    challenge: &[u8],
    decommitment: &[u8],
    corrections: &[u8],
    mult_corrections: &[u8],
    iv: &[u8; IV_BYTES],
) -> Result<Reconstruction, VoleError> {
    reconstruct_in(
        Namespace::REFERENCE,
        params,
        tables,
        &Opening {
            challenge,
            decommitment,
            corrections,
            mult_corrections,
        },
        iv,
    )
}

/// The proof fields `VOLEReconstruct` reads. Everything in it is public and
/// untrusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opening<'a> {
    /// `chall_3`, `lambda / 8` bytes.
    pub challenge: &'a [u8],
    /// `decom_I`, [`bavc::decommitment_bytes`] bytes.
    pub decommitment: &'a [u8],
    /// `c_1 || ... || c_{tau - 1}`, [`corrections_bytes`] bytes.
    pub corrections: &'a [u8],
    /// `c_mult`, [`mult_corrections_bytes`] bytes.
    pub mult_corrections: &'a [u8],
}

/// `VOLEReconstruct` with an explicit table set and every random-oracle call
/// (`H_0`, `H_1`, `H_5`) evaluated inside `namespace`.
///
/// This is a verifier entry point: every input is untrusted and public.
///
/// # Errors
/// * [`VoleError::TableMismatch`] unless `tables` matches the row;
/// * [`VoleError::InvalidLength`] unless `corrections` is [`corrections_bytes`]
///   and `mult_corrections` is [`mult_corrections_bytes`] bytes long;
/// * [`VoleError::NonZeroPadding`] if a bit of `mult_corrections` at or above
///   `n_mult` in a row is set (no standard row has such bits);
/// * the rejections of [`bavc::decode_challenge`] (wrong challenge length,
///   grinding bits set) and of [`bavc::reconstruct_in`] (wrong decommitment
///   length, too many node keys, non-zero padding), wrapped in
///   [`VoleError::Bavc`].
pub fn reconstruct_in(
    namespace: Namespace<'_>,
    params: &ProofParams,
    tables: &CrtTables<'_>,
    opening: &Opening<'_>,
    iv: &[u8; IV_BYTES],
) -> Result<Reconstruction, VoleError> {
    let Opening {
        challenge,
        decommitment,
        corrections,
        mult_corrections,
    } = *opening;
    let layout = Layout::new(params, tables)?;
    let (lb, ell_bytes, width) = (layout.lb, layout.ell_bytes, layout.width);
    let (gate_words, gate_bytes) = (layout.gate_words(), layout.gate_bytes());
    check_length(
        Input::Corrections,
        corrections_bytes(params),
        corrections.len(),
    )?;
    check_length(
        Input::MultCorrections,
        mult_corrections_bytes(&layout.vole),
        mult_corrections.len(),
    )?;
    check_padding(layout.n_mult, mult_corrections)?;
    let hidden = bavc::decode_challenge(&layout.vole, challenge)?;
    let opened = bavc::reconstruct_in(namespace, &layout.vole, decommitment, &hidden, iv)?;
    // `Delta'`: the grinding bits are zero, so the challenge is the selector.
    let mut selector = vec![0u64; layout.delta_words()];
    load_words(&mut selector, challenge);

    let mut columns = layout.new_columns()?;
    let mut shares = vec![0u64; layout.n_mask * layout.delta_words()];
    for ((instance, shape), &index) in layout.trees.iter().enumerate().zip(&hidden) {
        let seeds = opened
            .seeds(instance)
            .ok_or(VoleError::InstanceOutOfRange {
                instance,
                tau: layout.trees.len(),
            })?;
        let block = layout.block(shape, &mut columns);
        convert_to_vole_hidden(
            &layout.vole,
            instance,
            iv,
            seeds,
            index,
            layout.ell_hat,
            block,
        )?;
        if instance > 0 {
            let correction = &corrections[(instance - 1) * ell_bytes..instance * ell_bytes];
            for (position, column) in block.chunks_exact_mut(width).enumerate() {
                // Bit `start_i + position` of `Delta'` is bit `position` of the index.
                if (index >> position) & 1 == 1 {
                    xor_into(&mut column[..ell_bytes], correction);
                }
            }
        }
        layout.fold_mask_rows(shape, block, &mut shares);
    }

    // The seeds are not needed any more.
    let commitment = opened.commitment().to_vec();
    drop(opened);

    let mut delta_words = vec![0u64; layout.lambda_words()];
    tables.w_crt().mul_vec(&mut delta_words, &selector)?;
    let mut delta = vec![0u8; lb];
    store_words(&mut delta, &delta_words);

    let labels = layout.gate_labels(&columns)?;
    let mut gates = vec![0u64; layout.n_mask * gate_words];
    for (gate, label) in labels.chunks_exact(lb).enumerate() {
        let number = u32::try_from(gate).map_err(|_| VoleError::TooLarge { what: "gate index" })?;
        let hashed = h5_in(namespace, layout.level, iv, number, label, layout.n_mask)?;
        spread(&mut gates, gate_words, gate, hashed);
    }
    // `gamma_e = <G[e], Delta'>` selects the correction of gate `e`.
    let mut gamma = vec![0u64; gate_words];
    tables.g().mul_vec(&mut gamma, &selector)?;
    let mut row = vec![0u64; gate_words];
    for (gates, correction) in gates
        .chunks_exact_mut(gate_words)
        .zip(mult_corrections.chunks_exact(gate_bytes))
    {
        load_words(&mut row, correction);
        for ((gate, selected), bits) in gates.iter_mut().zip(&gamma).zip(&row) {
            *gate ^= selected & bits;
        }
    }

    // The results are public: they are moved out of the erasing wrappers, not
    // copied.
    let q_masks = core::mem::take(&mut *layout.mask_tags(&shares, &gates)?);
    let q = core::mem::take(&mut *layout.lift(columns)?);
    Ok(Reconstruction {
        commitment,
        hidden,
        delta,
        q,
        q_masks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        field::{BinaryField, Gf128, Gf192, Gf256},
        params::{FAEST_128F, FAEST_128S, FAEST_192F, FAEST_256F, FAEST_EM_192S},
    };

    const IV: [u8; 16] = [0x5a; 16];

    fn row(set: &crate::params::FaestParams, ell: usize) -> ProofParams {
        ProofParams::new(*set.vole(), ell, ell + 1).expect("valid row")
    }

    fn root(params: &ProofParams) -> Vec<u8> {
        (0u8..32)
            .map(|byte| byte.wrapping_mul(29) ^ 0xc3)
            .take(params.vole().lambda().bytes())
            .collect()
    }

    /// A challenge with zero grinding bits whose pattern can be opened.
    fn challenge(commitment: &Commitment, seed: u8) -> (Vec<u8>, Vec<u8>) {
        let vole = *commitment.params().vole();
        for attempt in 0u8..=255 {
            let mut challenge: Vec<u8> = (0..vole.lambda().bytes())
                .map(|at| {
                    u8::try_from(at)
                        .expect("small")
                        .wrapping_mul(seed)
                        .wrapping_add(attempt.wrapping_mul(101))
                        ^ seed
                })
                .collect();
            for position in vole.n_delta()..vole.lambda().bits() {
                challenge[position / 8] &= !(1 << (position % 8));
            }
            let hidden = bavc::decode_challenge(&vole, &challenge).expect("grinding bits cleared");
            match commitment.open(&hidden) {
                Ok(decommitment) => return (challenge, decommitment),
                Err(error) => assert!(error.is_retry(), "{error}"),
            }
        }
        panic!("no challenge could be opened");
    }

    /// `Q[j] = V[j] + u[j] * Delta` and `qbar_m = vbar_m + ubar_m * Delta`.
    fn assert_relations<F: LambdaField>(commitment: &Commitment, opened: &Reconstruction) {
        let vole = commitment.params().vole();
        let delta = elements::<F>(vole, opened.delta()).expect("one element")[0];
        let v = elements::<F>(vole, commitment.v()).expect("elements");
        let q = elements::<F>(vole, opened.q()).expect("elements");
        assert_eq!(v.len(), commitment.params().witness_bits());
        assert_eq!(q.len(), v.len());
        for (position, (q, v)) in q.iter().zip(v.iter()).enumerate() {
            let bit = (commitment.u()[position / 8] >> (position % 8)) & 1;
            assert_eq!(*q, *v + delta.mul_bit(bit), "row {position}");
        }
        let u_masks = elements::<F>(vole, commitment.u_masks()).expect("elements");
        let v_masks = elements::<F>(vole, commitment.v_masks()).expect("elements");
        let q_masks = elements::<F>(vole, opened.q_masks()).expect("elements");
        assert_eq!(u_masks.len(), vole.n_mask());
        for mask in 0..vole.n_mask() {
            assert_eq!(
                q_masks[mask],
                v_masks[mask] + u_masks[mask] * delta,
                "mask {mask}"
            );
        }
    }

    fn round_trip<F: LambdaField>(params: &ProofParams) {
        let commitment = commit(params, &root(params), &IV).expect("commit");
        let (challenge, decommitment) = challenge(&commitment, 0x9d);
        let opened = reconstruct(
            params,
            &challenge,
            &decommitment,
            commitment.corrections(),
            commitment.mult_corrections(),
            &IV,
        )
        .expect("reconstruct");
        assert_eq!(opened.commitment(), commitment.commitment());
        assert_eq!(
            opened.hidden_indices(),
            bavc::decode_challenge(params.vole(), &challenge)
                .expect("valid")
                .as_slice()
        );
        assert_relations::<F>(&commitment, &opened);
    }

    /// The gate hash `H_5` has three call sites: the prover's two labels and the
    /// verifier's one. The mask tags depend on the prover's first call only, and
    /// `qbar_m = vbar_m + ubar_m * Delta` holds only if all three calls agree, so a
    /// call site that forgot the prefix fails one of the assertions below.
    #[test]
    fn every_gate_hash_absorbs_the_namespace_prefix() {
        let params = row(&FAEST_128F, 128);
        let tables = params.vole().crt_tables().expect("embedded");
        let seed = root(&params);
        let plain = commit(&params, &seed, &IV).expect("commit");
        let first = [0x77u8; 77];
        let mut observed_commitments = vec![(
            plain.commitment().to_vec(),
            plain.mult_corrections().to_vec(),
            plain.v_masks().to_vec(),
        )];
        for prefix in [&first[..], b"second"] {
            let namespace = Namespace::new(prefix).expect("bounded");
            let commitment = commit_in(namespace, &params, tables, &seed, &IV).expect("commit");
            // Nothing derived from the generator alone moves.
            assert_eq!(commitment.u(), plain.u());
            assert_eq!(commitment.v(), plain.v());
            assert_eq!(commitment.corrections(), plain.corrections());
            assert_eq!(commitment.u_masks(), plain.u_masks());
            let (challenge, decommitment) = challenge(&commitment, 0x9d);
            let opening = Opening {
                challenge: &challenge,
                decommitment: &decommitment,
                corrections: commitment.corrections(),
                mult_corrections: commitment.mult_corrections(),
            };
            let opened =
                reconstruct_in(namespace, &params, tables, &opening, &IV).expect("reconstruct");
            assert_eq!(opened.commitment(), commitment.commitment());
            assert_relations::<Gf128>(&commitment, &opened);

            // A verifier in another namespace gets other mask keys and another
            // commitment, and the same `Q`.
            let foreign = reconstruct_in(Namespace::REFERENCE, &params, tables, &opening, &IV)
                .expect("well formed");
            assert_eq!(foreign.q(), opened.q());
            assert_ne!(foreign.q_masks(), opened.q_masks());
            assert_ne!(foreign.commitment(), opened.commitment());
            observed_commitments.push((
                commitment.commitment().to_vec(),
                commitment.mult_corrections().to_vec(),
                commitment.v_masks().to_vec(),
            ));
        }
        for (left, right) in [(0, 1), (0, 2), (1, 2)] {
            assert_ne!(observed_commitments[left].0, observed_commitments[right].0);
            assert_ne!(observed_commitments[left].1, observed_commitments[right].1);
            assert_ne!(observed_commitments[left].2, observed_commitments[right].2);
        }
        // The wrappers are reference mode.
        let again = commit_with_tables(&params, tables, &seed, &IV).expect("commit");
        assert_eq!(again.mult_corrections(), plain.mult_corrections());
        assert_eq!(again.v_masks(), plain.v_masks());
        assert_eq!(again.commitment(), plain.commitment());
    }

    #[test]
    fn commit_and_reconstruct_agree_on_fast_rows_of_every_level() {
        round_trip::<Gf128>(&row(&FAEST_128F, 128));
        round_trip::<Gf128>(&row(&FAEST_128F, 1000));
        round_trip::<Gf192>(&row(&FAEST_192F, 192));
        round_trip::<Gf256>(&row(&FAEST_256F, 264));
    }

    #[test]
    fn outputs_have_the_documented_lengths_and_zero_top_coefficients() {
        let params = row(&FAEST_128F, 256);
        let vole = params.vole();
        let commitment = commit(&params, &root(&params), &IV).expect("commit");
        assert_eq!(commitment.params(), &params);
        assert_eq!(commitment.commitment().len(), 32);
        assert_eq!(commitment.commitment(), commitment.bavc().commitment());
        assert_eq!(commitment.corrections().len(), corrections_bytes(&params));
        assert_eq!(corrections_bytes(&params), 16 * 32);
        assert_eq!(
            commitment.mult_corrections().len(),
            mult_corrections_bytes(vole)
        );
        assert_eq!(mult_corrections_bytes(vole), 10 * 39);
        assert_eq!(commitment.u().len(), 32);
        assert_eq!(commitment.v().len(), 256 * 16);
        assert_eq!(commitment.u_masks().len(), 10 * 16);
        assert_eq!(commitment.v_masks().len(), 10 * 16);
        // `W_CRT` has zero rows at and above `n_Delta`: the top byte of every
        // `V[j]` is zero for `w_grind = 8`, while the masks are full elements.
        assert!(commitment.v().chunks(16).all(|element| element[15] == 0));
        assert!(commitment.u_masks().chunks(16).any(|mask| mask[15] != 0));
        assert!(commitment.v_masks().chunks(16).any(|mask| mask[15] != 0));
        let rendered = format!("{commitment:?}");
        assert!(rendered.contains("com"));
        assert!(!rendered.contains("u_masks"));
    }

    #[test]
    fn the_layout_follows_the_row_and_rejects_foreign_tables() {
        let params = row(&FAEST_EM_192S, 192);
        let tables = params.vole().crt_tables().expect("embedded");
        let layout = Layout::new(&params, tables).expect("matching tables");
        assert_eq!(layout.trees.len(), 16);
        assert_eq!((layout.trees[0].depth, layout.trees[0].start), (12, 0));
        assert_eq!((layout.trees[8].depth, layout.trees[8].start), (11, 96));
        assert_eq!(layout.trees[0].modulus, 0x1009);
        assert_eq!(layout.ell_hat, 192 + 120);
        assert_eq!(layout.width, 39);
        assert_eq!(layout.mask_row(3), 192 + 36);
        assert_eq!(
            (
                layout.delta_words(),
                layout.gate_words(),
                layout.lambda_words()
            ),
            (3, 8, 3)
        );
        assert_eq!(layout.gate_bytes(), 63);
        assert_eq!(layout.new_columns().expect("small").len(), 184 * 39);
        let mut columns = vec![0u8; 184 * 39];
        assert_eq!(layout.block(&layout.trees[8], &mut columns).len(), 11 * 39);

        let mismatch = |set: &crate::params::FaestParams| {
            Layout::new(&params, set.vole().crt_tables().expect("embedded"))
                .err()
                .expect("foreign tables")
        };
        assert_eq!(
            mismatch(&FAEST_128F),
            VoleError::TableMismatch {
                what: "lambda",
                expected: 192,
                actual: 128
            }
        );
        assert_eq!(
            mismatch(&FAEST_192F),
            VoleError::TableMismatch {
                what: "tau",
                expected: 16,
                actual: 24
            }
        );
        // FAEST-192s has `w_grind = 12`, the Even-Mansour row 8.
        assert_eq!(
            mismatch(&crate::params::FAEST_192S),
            VoleError::TableMismatch {
                what: "w_grind",
                expected: 8,
                actual: 12
            }
        );
        let other = commit_with_tables(
            &params,
            FAEST_128S.vole().crt_tables().expect("embedded"),
            &root(&params),
            &IV,
        );
        assert!(matches!(other, Err(VoleError::TableMismatch { .. })));
        let other = reconstruct_with_tables(
            &params,
            FAEST_128S.vole().crt_tables().expect("embedded"),
            &[],
            &[],
            &[],
            &[],
            &IV,
        );
        assert!(matches!(other, Err(VoleError::TableMismatch { .. })));
    }

    #[test]
    fn a_row_without_embedded_tables_is_a_typed_error() {
        let vole = VoleParams::new(SecurityLevel::L128, 16, 8, 100, 3, 7, 312).expect("valid row");
        let params = ProofParams::new(vole, 128, 129).expect("valid row");
        assert!(matches!(
            commit(&params, &root(&params), &IV),
            Err(VoleError::Crt(CrtError::NoEmbeddedTables { .. }))
        ));
        assert!(matches!(
            reconstruct(&params, &[], &[], &[], &[], &IV),
            Err(VoleError::Crt(CrtError::NoEmbeddedTables { .. }))
        ));
    }

    #[test]
    fn reduction_is_the_polynomial_remainder() {
        fn remainder(mut value: u32, modulus: u32) -> u32 {
            let degree = 31 - modulus.leading_zeros();
            for position in (degree..32).rev() {
                if (value >> position) & 1 == 1 {
                    value ^= modulus << (position - degree);
                }
            }
            value
        }
        for (modulus, depth) in [(0x11bu32, 8usize), (0x83, 7), (0x1009, 12), (0b111, 2)] {
            let top = 2 * depth - 1;
            let mut state = 0x1234_5678_u32;
            for _ in 0..500 {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let value = (state >> 3) & ((1 << top) - 1);
                assert_eq!(reduce(value, modulus, depth), remainder(value, modulus));
            }
            assert_eq!(reduce(modulus, modulus, depth), 0);
        }
        assert_eq!(reduce(1, 1, 0), 1, "degenerate depth is the identity");
    }

    #[test]
    fn padding_bits_of_the_gate_corrections_must_be_zero() {
        // Thirteen gates: rows of two bytes with three padding bits each.
        let clean = [0xff, 0x1f, 0x00, 0x00, 0xa5, 0x1f];
        assert_eq!(check_padding(13, &clean), Ok(()));
        for (row, bit) in [(0, 5), (1, 7), (2, 6)] {
            let mut padded = clean;
            padded[2 * row + 1] |= 1 << bit;
            assert_eq!(check_padding(13, &padded), Err(VoleError::NonZeroPadding));
        }
        // A whole number of bytes has no padding.
        assert_eq!(check_padding(16, &[0xff; 6]), Ok(()));
        assert_eq!(check_padding(13, &[]), Ok(()));
    }

    #[test]
    fn spread_writes_one_bit_per_mask() {
        let mut rows = [0u64; 6];
        spread(&mut rows, 2, 70, 0b101);
        spread(&mut rows, 2, 3, 0b110);
        assert_eq!(rows, [0, 1 << 6, 1 << 3, 0, 1 << 3, 1 << 6]);
        // A gate beyond the rows is ignored.
        spread(&mut rows, 2, 128, 0b111);
        assert_eq!(rows, [0, 1 << 6, 1 << 3, 0, 1 << 3, 1 << 6]);
    }

    #[test]
    fn mask_rows_are_folded_into_the_residue_coordinates() {
        let params = row(&FAEST_128F, 128);
        let tables = params.vole().crt_tables().expect("embedded");
        let layout = Layout::new(&params, tables).expect("matching tables");
        // Instance 1: seven columns, modulus 0x83, coordinates [8, 15).
        let tree = layout.trees[1];
        assert_eq!((tree.depth, tree.start, tree.modulus), (7, 8, 0x83));
        let width = layout.width;
        let block: Vec<u8> = (0..tree.depth * width)
            .map(|at| u8::try_from((at * 89 + 3) % 256).expect("byte"))
            .collect();
        let mut shares = vec![0u64; layout.n_mask * layout.delta_words()];
        layout.fold_mask_rows(&tree, &block, &mut shares);
        let mut low = vec![0u64; layout.n_mask * layout.delta_words()];
        layout.fold_mask_values(&tree, &block[..width], &mut low);
        for mask in 0..layout.n_mask {
            let first = layout.mask_row(mask);
            let mut value = 0u32;
            let mut plain = 0u64;
            for offset in 0..tree.depth {
                plain |= bit(&block[..width], first + offset) << offset;
                for column in 0..tree.depth {
                    let bit = bit(&block[column * width..(column + 1) * width], first + offset);
                    value ^= u32::try_from(bit).expect("bit") << (column + offset);
                }
            }
            let residue = u64::from(reduce(value, 0x83, 7));
            assert_eq!(shares[mask * 2], residue << 8, "mask {mask}");
            assert_eq!(shares[mask * 2 + 1], 0);
            assert_eq!(low[mask * 2], plain << 8, "mask {mask}");
        }
    }

    #[test]
    fn mask_values_add_the_generator_bits_times_the_tree_product() {
        let params = row(&FAEST_128S, 128);
        let tables = params.vole().crt_tables().expect("embedded");
        let layout = Layout::new(&params, tables).expect("matching tables");
        let root = root(&params);
        // With zero low parts the value is `M_tree(x) * u_hi(x)`.
        let low = vec![0u64; layout.n_mask * layout.delta_words()];
        let values = layout.mask_values(&root, &IV, &low).expect("valid call");
        // 10 masks of 7 bits: 70 generator bits, not a whole number of bytes.
        let mut high = [0u8; 9];
        Prg::new(&root)
            .expect("seed")
            .fill_bits(&IV, MASK_TWEAK, 70, &mut high)
            .expect("valid call");
        assert_eq!(MASK_TWEAK, 0x7fff_ffff);
        for mask in 0..10 {
            let mut want = [0u64; 2];
            for position in 0..7 {
                if bit(&high, mask * 7 + position) == 1 {
                    xor_shifted_masked(&mut want, tables.m_tree(), position, u64::MAX);
                }
            }
            assert_eq!(&values[mask * 2..mask * 2 + 2], &want, "mask {mask}");
        }
        // A low part adds its image under `W_CRT`.
        let mut low = low;
        low[0] = 0b1001;
        let shifted = layout.mask_values(&root, &IV, &low).expect("valid call");
        let mut image = [0u64; 2];
        tables
            .w_crt()
            .mul_vec(&mut image, &low[..2])
            .expect("shape");
        assert_eq!([shifted[0] ^ values[0], shifted[1] ^ values[1]], image);
        assert_eq!(&shifted[2..], &values[2..]);
    }

    #[test]
    fn labels_tags_and_the_lift_are_the_table_products() {
        let params = row(&FAEST_128F, 136);
        let tables = params.vole().crt_tables().expect("embedded");
        let layout = Layout::new(&params, tables).expect("matching tables");
        let (width, lb) = (layout.width, layout.lb);
        let columns: Vec<u8> = (0..layout.n_delta * width)
            .map(|at| u8::try_from((at * 151 + 13) % 255).expect("byte"))
            .collect();
        let column_bit = |column: usize, row: usize| {
            bit(&columns[column * width..(column + 1) * width], row) == 1
        };

        let labels = layout.gate_labels(&columns).expect("valid call");
        assert_eq!(labels.len(), layout.n_mult * lb);
        for gate in [0, 1, 150, layout.n_mult - 1] {
            for row in [0, 5, 127] {
                let want = (0..layout.n_delta)
                    .filter(|&column| tables.g().bit(gate, column) == Some(true))
                    .fold(false, |acc, column| acc ^ column_bit(column, row));
                let got = bit(&labels[gate * lb..(gate + 1) * lb], row) == 1;
                assert_eq!(got, want, "gate {gate} row {row}");
            }
        }

        let lifted = layout
            .lift(Zeroizing::new(columns.clone()))
            .expect("valid call");
        assert_eq!(lifted.len(), 136 * lb);
        let mut selector = [0u64; 2];
        let mut image = [0u64; 2];
        for row in [0, 1, 7, 8, 64, 135] {
            selector.fill(0);
            for column in 0..layout.n_delta {
                selector[column / 64] |= u64::from(column_bit(column, row)) << (column % 64);
            }
            tables
                .w_crt()
                .mul_vec(&mut image, &selector)
                .expect("shape");
            let mut want = [0u8; 16];
            store_words(&mut want, &image);
            assert_eq!(&lifted[row * lb..(row + 1) * lb], &want, "row {row}");
        }

        let shares: Vec<u64> = (0..layout.n_mask * 2)
            .map(|at| 0x0123_4567_89ab_cdef_u64.rotate_left(u32::try_from(at).expect("small")))
            .map(|word| word & 0x00ff_ffff_ffff_ffff)
            .collect();
        let gates: Vec<u64> = (0..layout.n_mask * layout.gate_words())
            .map(|at| 0xfedc_ba98_7654_3210_u64.rotate_left(u32::try_from(at).expect("small")))
            .map(|word| word & 0x00ff_ffff_ffff_ffff)
            .collect();
        let tags = layout.mask_tags(&shares, &gates).expect("valid call");
        for mask in 0..layout.n_mask {
            let (mut tree, mut gate) = ([0u64; 2], [0u64; 2]);
            tables
                .w_tree()
                .mul_vec(&mut tree, &shares[mask * 2..mask * 2 + 2])
                .expect("shape");
            tables
                .w_gate()
                .mul_vec(&mut gate, &gates[mask * 5..mask * 5 + 5])
                .expect("shape");
            let mut want = [0u8; 16];
            store_words(&mut want, &[tree[0] ^ gate[0], tree[1] ^ gate[1]]);
            assert_eq!(&tags[mask * lb..(mask + 1) * lb], &want, "mask {mask}");
        }
    }

    #[test]
    fn elements_decode_only_the_field_of_the_row() {
        let vole = FAEST_192F.vole();
        let bytes: Vec<u8> = (0u8..48).collect();
        let decoded = elements::<Gf192>(vole, &bytes).expect("two elements");
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[1].to_bytes().as_ref(), &bytes[24..]);
        assert_eq!(
            elements::<Gf128>(vole, &bytes).err(),
            Some(VoleError::FieldMismatch {
                expected: 192,
                actual: 128
            })
        );
        assert!(matches!(
            elements::<Gf192>(vole, &bytes[1..]),
            Err(VoleError::Field(_))
        ));
        assert_eq!(
            elements::<Gf192>(vole, &bytes[1..]).err(),
            Some(VoleError::Field(FieldError::InvalidLength {
                expected: 48,
                actual: 47
            }))
        );
    }

    #[test]
    fn elements_are_decoded_into_a_vector_that_never_reallocates() {
        let vole = FAEST_256F.vole();
        let bytes: Vec<u8> = (0..32_000u32)
            .map(|at| u8::try_from(at % 251).expect("byte"))
            .collect();
        let decoded = elements::<Gf256>(vole, &bytes).expect("a thousand elements");
        assert_eq!(decoded.len(), 1000);
        assert_eq!(decoded.capacity(), decoded.len());
        assert_eq!(
            decoded.as_slice(),
            Gf256::vec_from_bytes(&bytes).expect("whole elements")
        );
        let empty = elements::<Gf256>(vole, &[]).expect("no elements");
        assert_eq!((empty.len(), empty.capacity()), (0, 0));
    }

    #[test]
    fn helpers_and_error_classification() {
        assert_eq!(check_length(Input::Seeds, 3, 3), Ok(()));
        assert_eq!(
            check_length(Input::Corrections, 3, 4),
            Err(VoleError::InvalidLength {
                input: Input::Corrections,
                expected: 3,
                actual: 4
            })
        );
        assert_eq!(product("buffer", 6, 7), Ok(42));
        assert_eq!(
            product("buffer", usize::MAX, 2),
            Err(VoleError::TooLarge { what: "buffer" })
        );
        assert_eq!(index(7), 7);
        assert!(VoleError::Bavc(BavcError::GrindingBitsSet).is_retry());
        assert!(
            VoleError::Bavc(BavcError::OpeningTooLarge {
                nodes: 2,
                t_open: 1
            })
            .is_retry()
        );
        assert!(!VoleError::Bavc(BavcError::NonZeroPadding).is_retry());
        assert!(!VoleError::NonZeroPadding.is_retry());
        for error in [
            VoleError::InvalidLength {
                input: Input::MultCorrections,
                expected: 1,
                actual: 2,
            },
            VoleError::InstanceOutOfRange {
                instance: 3,
                tau: 2,
            },
            VoleError::TableMismatch {
                what: "tau",
                expected: 1,
                actual: 2,
            },
            VoleError::NonZeroPadding,
            VoleError::FieldMismatch {
                expected: 128,
                actual: 256,
            },
            VoleError::TooLarge { what: "buffer" },
            VoleError::Bavc(BavcError::GrindingBitsSet),
        ] {
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn malformed_verifier_inputs_are_rejected_before_any_work() {
        let params = row(&FAEST_128F, 128);
        let commitment = commit(&params, &root(&params), &IV).expect("commit");
        let (challenge, decommitment) = challenge(&commitment, 0x31);
        let (c, cm) = (commitment.corrections(), commitment.mult_corrections());
        let run = |challenge: &[u8], decommitment: &[u8], c: &[u8], cm: &[u8]| {
            reconstruct(&params, challenge, decommitment, c, cm, &IV).err()
        };
        assert_eq!(run(&challenge, &decommitment, c, cm), None);
        assert_eq!(
            run(&challenge, &decommitment, &c[1..], cm),
            Some(VoleError::InvalidLength {
                input: Input::Corrections,
                expected: c.len(),
                actual: c.len() - 1
            })
        );
        assert_eq!(
            run(&challenge, &decommitment, c, &cm[..cm.len() - 1]),
            Some(VoleError::InvalidLength {
                input: Input::MultCorrections,
                expected: cm.len(),
                actual: cm.len() - 1
            })
        );
        let mut ground = challenge.clone();
        ground[15] |= 0x80;
        assert_eq!(
            run(&ground, &decommitment, c, cm),
            Some(VoleError::Bavc(BavcError::GrindingBitsSet))
        );
        assert!(matches!(
            run(&challenge[1..], &decommitment, c, cm),
            Some(VoleError::Bavc(BavcError::InvalidLength { .. }))
        ));
        assert!(matches!(
            run(&challenge, &decommitment[1..], c, cm),
            Some(VoleError::Bavc(BavcError::InvalidLength { .. }))
        ));
        assert!(matches!(
            commit(&params, &root(&params)[1..], &IV),
            Err(VoleError::Bavc(BavcError::InvalidLength { .. }))
        ));
    }
}
