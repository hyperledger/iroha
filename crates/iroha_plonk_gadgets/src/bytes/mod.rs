//! Byte linking: byte strings as constrained cells, the `P_bytes` packing of
//! the KAGEMUSHA wallet (spec section 3, wire section 3.2), 32-byte proof
//! messages linked to the field elements a verifier consumes, and the
//! length-prefixed proof export a step leaf hands to the aggregator (M3 gadget
//! `::bytes` of `specs/kagemusha_lambda_omega_v1.md`).
//!
//! # `P_bytes`
//!
//! `P_bytes(d, b) = P(d, [len(b)] || c_0 || ... || c_(m-1))` with
//! `m = ceil(len(b) / 31)`, where `c_i` is bytes `31 i .. 31 i + 30` of `b`
//! read as a little-endian integer and the last chunk is zero-filled
//! (`kagemusha_wallet_packed_bytes_v1` of `iroha_data_model`). Every chunk is
//! below `2^248 < p`, so the packing is injective for a fixed length, and the
//! length element separates lengths. [`p_bytes_items_native`] and
//! [`p_bytes_native`] are the native references; [`PBytes`] builds the same
//! element list in circuit and hashes it with a [`crate::SpongeChip`].
//!
//! # The tape ([`tape`])
//!
//! A run of witness bytes takes one row per byte on two equality-enabled
//! advice columns. The primary column holds little-endian running sums over
//! segments of at most 31 bytes (`z_j = b_j + 256 z_(j+1)`, the last byte of a
//! segment is `z` itself), and every byte expression is looked up in a
//! 256-row byte table, so each segment word is the little-endian integer of
//! its bytes. The secondary column recomposes the same bytes along a second,
//! independent segmentation, little- or big-endian, and a gate equates its
//! byte expression with the primary one on every row it covers. The cost is
//! one cell per byte for a run that is only packed, and two cells per byte
//! for a run whose bytes are also linked to other values.
//!
//! Primary segments follow the 31-byte chunk boundaries of the `P_bytes`
//! string the run belongs to ([`chunk_segments`]), so a chunk is a segment
//! word, or a glue combination of segment words and constant bytes when a
//! chunk mixes them; no chunk needs a range check of its own.
//!
//! # Packing ([`packing`])
//!
//! [`PBytes`] places constant bytes, tape runs and bounded words
//! ([`BoundedBytes`]: a word known to be below `256^len`, such as an opaque
//! chunk range-checked by the running-sum chip, or an exported chunk received
//! as a bounded instance) at their offsets of a `P_bytes` string, splits a
//! bounded word that crosses a chunk boundary ([`split_bounded`]) and
//! produces the chunk words and the digest. Constant bytes inside a signed
//! transcript (enum tags, zero fill, the SEC1 tag `0x04` before a P-256
//! key) are constant pieces between tape runs, so they cost no cells.
//!
//! The length-prefixed export ([`export_length_prefixed`]) is the proof
//! string `LE32 len(sigma) || sigma` of the step-proof digest cut into chunk
//! pieces: a step leaf (over `Fq`) exports these words as bounded instances,
//! and the aggregator (over `Fp`) appends them to its own `P_bytes` strings,
//! the sigma-only `proof_digest` (aligned, no rows) or `LE32 len(Omega) ||
//! Omega || LE32 len(sigma) || sigma` (realigned with one split per piece).
//! For the measured sigma of 3,296 bytes the export has
//! [`SIGMA_EXPORT_CHUNKS`] = 107 pieces.
//!
//! # Messages ([`element`])
//!
//! A 32-byte little-endian proof message (PIPA-v1 section 1) is decoded from
//! secondary segments `[16, 15, 1]` into `lo < 2^128`, `hi < 2^127` and the top
//! bit. A compressed Pasta point is `x` with the parity of `y` in bit 255: the
//! link checks that `x = lo + 2^128 hi` is canonical and that the canonical
//! parity of `y` is the top bit, so the opposite point and the alias `y + p`
//! are rejected. A point over the other Pasta field (the Vesta accumulator
//! point in the `Fp` aggregator) links with `y` given as canonical limbs. A
//! scalar must have a clear top bit and `lo + 2^128 hi` below its modulus.
//! Every link has a hard form (unsatisfiable on a mismatch) and a soft form
//! (a bit, never unsatisfiable, determined by the bytes) for soft verifiers.
//! Big-endian
//! 32-byte values (P-256 coordinates and signature halves in the signed
//! transcripts) decode from secondary segments `[16, 16]` into two `U128`
//! halves.
//!
//! # Scope
//!
//! [`PBytes`] uses circuit-fixed lengths for valid proofs and fixed transcript
//! layouts. Untrusted incoming proofs may have a different actual length:
//! [`ActiveBytes`] retains their original bounded byte tapes, and
//! [`VariablePBytes`] frames, concatenates and hashes their constrained active
//! prefixes without introducing capacity padding. Decoder views can share the
//! tape while retaining the exact original bytes for consuming digests.
//! Variable lengths never change the circuit's layout. Its digest currently
//! requires an ordinary sponge lane; compact phase lanes reject it.
//!
//! The point link does not check that `(x, y)` is on
//! the curve; the curve chip does, and that check also excludes the identity
//! `(0, 0)` because `5` is not a square in either Pasta field.
//!
//! TODO(M4 bytes): when the A-leaf layout is fixed, check bytes against a
//! shared 15-bit value column instead of the chip's own 256-row table (a
//! byte `v` as the two memberships `v` and `2^7 v`, as the foreign-field top
//! sublimbs do, `crate::ff`), riding on a host argument of that leaf
//! (`crate::table`), so the chip stops owning its own lookup argument.
//! Sharing the table alone removes no argument; the Q leaf does not use
//! this chip.

pub mod element;
pub mod packing;
pub mod tape;
pub mod variable;

#[cfg(test)]
mod tests;

use iroha_pasta::{PastaField, poseidon::PoseidonField};
use iroha_plonk::frontend::Value;

pub use element::{
    BeElement, LeElement, PIPA_DUMMY, SoftPipaPoint, SoftPoint, assert_foreign_point_bytes,
    assert_le_max, assert_point_bytes, assert_scalar_bytes, be_value_segments, decode_be_element,
    decode_le_element, decode_pipa_point_soft, decode_point, decode_point_soft, element_value,
    foreign_point_bytes_match, le_max, le_message_segments, low_bit, modulus_max, parity,
    point_bytes_match, point_bytes_native, scalar_bytes_canonical,
};
pub use packing::{
    PBytes, PackedItem, bound_bytes, export_length_prefixed, length_prefix, opaque_bytes,
    split_bounded,
};
pub use tape::{ByteOrder, ByteRun, BytesChip, BytesConfig, Segment, SegmentSpec, segment_value};
pub use variable::{ActiveBytes, VariablePBytes};

use crate::cells::Word;

/// Bytes of one `P_bytes` chunk: 31, so every chunk is below `2^248`.
pub const CHUNK_BYTES: usize = 31;
/// The longest segment of a tape column and the longest bounded word.
pub const MAX_SEGMENT_BYTES: usize = CHUNK_BYTES;
/// Rows of the byte table.
pub const BYTE_TABLE_ROWS: usize = 256;
/// Bytes of the `LE32` length prefix of each proof in a `proof_digest`
/// string.
pub const LENGTH_PREFIX_BYTES: usize = 4;
/// Bytes of one PIPA-v1 proof message (a scalar or a compressed point).
pub const MESSAGE_BYTES: usize = 32;
/// Bytes of the sigma step proof measured at k12 with one Poseidon lane
/// (M12fix).
pub const SIGMA_PROOF_BYTES: usize = 3_296;
/// Chunks of `LE32 len(sigma) || sigma` for [`SIGMA_PROOF_BYTES`]:
/// `ceil(3,300 / 31) = 107`.
pub const SIGMA_EXPORT_CHUNKS: usize = length_prefixed_chunks(SIGMA_PROOF_BYTES);

const _: () = assert!(SIGMA_EXPORT_CHUNKS == 107);

/// Chunks of the length-prefixed string `LE32 len || bytes` of `len` bytes,
/// starting at a chunk boundary.
#[must_use]
pub const fn length_prefixed_chunks(len: usize) -> usize {
    (len + LENGTH_PREFIX_BYTES).div_ceil(CHUNK_BYTES)
}

/// A word known to hold the little-endian integer of `len` bytes, that is a
/// value below `256^len` (`1 <= len <= 31`).
///
/// The tape, the running-sum chip and [`split_bounded`] produce such words
/// with the bound enforced; [`BoundedBytes::trusted`] wraps a word whose
/// bound another circuit enforced.
#[derive(Clone, Debug)]
pub struct BoundedBytes<F: PastaField> {
    word: Word<F>,
    len: usize,
}

impl<F: PastaField> BoundedBytes<F> {
    /// Wraps a word whose bound the caller laid out.
    pub(crate) const fn new(word: Word<F>, len: usize) -> Self {
        Self { word, len }
    }

    /// Wraps `word` as `len` bytes without constraining it.
    ///
    /// The caller guarantees `word < 256^len` by other means, for example a
    /// chunk received as a bounded instance of a proof this circuit verifies
    /// (the exporting circuit enforced the bound, the verifier enforces the
    /// instance type). `None` for a length outside `1..=31`.
    #[must_use]
    pub fn trusted(word: Word<F>, len: usize) -> Option<Self> {
        (1..=MAX_SEGMENT_BYTES)
            .contains(&len)
            .then_some(Self { word, len })
    }

    /// The word.
    #[must_use]
    pub const fn word(&self) -> &Word<F> {
        &self.word
    }

    /// The byte length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Always false: a bounded word holds at least one byte.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// `256^power` in `F`.
#[must_use]
pub fn byte_power<F: PastaField>(power: usize) -> F {
    let mut value = F::ONE;
    let radix = F::from(256_u64);
    for _ in 0..power {
        value *= radix;
    }
    value
}

/// The little-endian integer of at most 31 bytes, or `None` for a longer
/// slice.
#[must_use]
pub fn le_value<F: PastaField>(bytes: &[u8]) -> Option<F> {
    if bytes.len() > MAX_SEGMENT_BYTES {
        return None;
    }
    let mut repr = [0_u8; 32];
    repr[..bytes.len()].copy_from_slice(bytes);
    Option::from(F::from_repr(repr))
}

/// The 32 little-endian bytes of the canonical integer value of `value`.
#[must_use]
pub fn field_le_bytes<F: PastaField>(value: &F) -> [u8; 32] {
    value.to_repr()
}

/// The lengths of the primary segments of `len` bytes that start at offset
/// `offset` of a `P_bytes` string: the bytes are cut at every multiple of 31,
/// so no segment crosses a chunk boundary.
#[must_use]
pub fn chunk_segments(offset: usize, len: usize) -> Vec<usize> {
    let mut lengths = Vec::with_capacity(len.div_ceil(CHUNK_BYTES).saturating_add(1));
    let mut position = offset;
    let end = offset.saturating_add(len);
    while position < end {
        let room = CHUNK_BYTES - position % CHUNK_BYTES;
        let take = room.min(end - position);
        lengths.push(take);
        position += take;
    }
    lengths
}

/// Native reference: the `P_bytes` element list of `bytes`, the byte length
/// as one element then the zero-filled 31-byte little-endian chunks
/// (`kagemusha_wallet_packed_bytes_v1`).
#[must_use]
pub fn p_bytes_items_native<F: PastaField>(bytes: &[u8]) -> Vec<F> {
    let mut items = Vec::with_capacity(bytes.len().div_ceil(CHUNK_BYTES).saturating_add(1));
    items.push(F::from(length_word(bytes.len())));
    for chunk in bytes.chunks(CHUNK_BYTES) {
        items.push(le_value(chunk).unwrap_or(F::ZERO));
    }
    items
}

/// Native reference: `P_bytes(domain, bytes)`
/// (`kagemusha_wallet_poseidon_bytes_v1` over the field `F`).
#[must_use]
pub fn p_bytes_native<F: PoseidonField>(domain: u64, bytes: &[u8]) -> F {
    iroha_pasta::poseidon::hash_with_domain(domain, &p_bytes_items_native::<F>(bytes))
}

/// A byte length as a `u64` (in-memory lengths always fit).
pub(crate) fn length_word(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// The bytes of known byte values (unknown when any one is).
pub(crate) fn collect_bytes(bytes: &[Value<u8>]) -> Value<Vec<u8>> {
    let mut out = Value::known(Vec::with_capacity(bytes.len()));
    for byte in bytes {
        out = out.zip(*byte).map(|(mut values, byte)| {
            values.push(byte);
            values
        });
    }
    out
}
