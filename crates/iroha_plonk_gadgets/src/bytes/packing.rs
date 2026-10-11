//! `P_bytes` strings in circuit: constant bytes, tape runs and bounded words
//! placed at their offsets, cut into 31-byte chunks and hashed.
//!
//! # Chunks
//!
//! A [`PBytes`] string starts at in-chunk offset `origin` (0 for a string that
//! is hashed; a nonzero origin only describes pieces exported for a string
//! that continues elsewhere). Chunk `c` covers the absolute offsets
//! `[31 c, 31 c + 31)` intersected with the string, and its word is
//! `sum_i b_i 256^(i - base)` with `base` the first string byte in the chunk.
//! Bounded pieces never cross a chunk boundary ([`PBytes::push_bounded`]
//! rejects it, [`PBytes::push_bounded_split`] splits), so each chunk word is
//!
//! - a bounded word alone (no row: the word is the chunk),
//! - a constant (no row), or
//! - one glue linear row per three pieces (`sum_i 256^(o_i) w_i + k`).
//!
//! Since every piece is below `256^len` and the pieces of a chunk do not
//! overlap, each chunk word is the little-endian integer of the chunk's bytes,
//! below `2^248`, exactly as the native packing.
//!
//! # Costs (rows of each chip)
//!
//! - a tape run: one primary row per byte (see [`super::tape`]);
//! - [`opaque_bytes`]: one running-sum check of `8 len` bits (18 rows for 31
//!   bytes at 15-bit limbs);
//! - [`split_bounded`]: two running-sum checks (`8 at` and `8 (len - at)`
//!   bits) and one glue row;
//! - the digest: `floor((m + 3) / 2) + 1` permutations for `m` chunks.

use iroha_pasta::{PastaField, poseidon::PoseidonField};
use iroha_plonk::frontend::{Error, Region, Value};

use super::{
    BoundedBytes, CHUNK_BYTES, LENGTH_PREFIX_BYTES, MAX_SEGMENT_BYTES, byte_power, chunk_segments,
    field_le_bytes, le_value, length_word,
    tape::{ByteRun, BytesChip, SegmentSpec},
};
use crate::{
    WordHasher,
    arith::GlueChip,
    cells::Word,
    poseidon::AbsorbInput,
    range::{running_sum::RunningSumChip, u128::UintChip},
};

/// One element of a packed string: a chunk cell or a constant chunk.
#[derive(Clone, Debug)]
pub enum PackedItem<F: PastaField> {
    /// A cell.
    Word(Word<F>),
    /// A constant (a chunk of constant bytes only, or the length).
    Constant(F),
}

impl<F: PastaField> PackedItem<F> {
    /// The value.
    #[must_use]
    pub fn value(&self) -> Value<F> {
        match self {
            Self::Word(word) => word.value(),
            Self::Constant(constant) => Value::known(*constant),
        }
    }

    /// The item as a sponge input.
    #[must_use]
    pub const fn absorb(&self) -> AbsorbInput<'_, F> {
        match self {
            Self::Word(word) => AbsorbInput::Word(word),
            Self::Constant(constant) => AbsorbInput::Constant(*constant),
        }
    }
}

/// A piece of a string.
#[derive(Clone, Debug)]
enum Piece<F: PastaField> {
    /// Constant bytes (any length).
    Constant(Vec<u8>),
    /// A bounded word inside one chunk.
    Bounded(BoundedBytes<F>),
}

/// A piece at its absolute offset (origin included).
#[derive(Clone, Debug)]
struct Placed<F: PastaField> {
    offset: usize,
    piece: Piece<F>,
}

/// A `P_bytes` string under construction.
#[derive(Clone, Debug)]
pub struct PBytes<F: PastaField> {
    origin: usize,
    len: usize,
    pieces: Vec<Placed<F>>,
}

impl<F: PastaField> Default for PBytes<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PastaField> PBytes<F> {
    /// An empty string starting at a chunk boundary.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            origin: 0,
            len: 0,
            pieces: Vec::new(),
        }
    }

    /// An empty string starting at in-chunk offset `origin` (for exported
    /// pieces of a string that continues in another circuit).
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] for an origin of 31 or more.
    pub fn starting_at(origin: usize) -> Result<Self, Error> {
        if origin >= CHUNK_BYTES {
            return Err(Error::Synthesis);
        }
        Ok(Self {
            origin,
            len: 0,
            pieces: Vec::new(),
        })
    }

    /// The byte length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the string is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The absolute offset of the next byte (origin included).
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.origin + self.len
    }

    /// The lengths of the chunk pieces: the bytes cut at the chunk
    /// boundaries ([`chunk_segments`] from the origin).
    #[must_use]
    pub fn piece_lengths(&self) -> Vec<usize> {
        chunk_segments(self.origin, self.len)
    }

    /// Appends constant bytes.
    pub fn push_constant(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.pieces.push(Placed {
            offset: self.offset(),
            piece: Piece::Constant(bytes.to_vec()),
        });
        self.len += bytes.len();
    }

    /// Appends a bounded word that ends at or before the next chunk
    /// boundary.
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] when the word would cross a chunk boundary.
    pub fn push_bounded(&mut self, piece: BoundedBytes<F>) -> Result<(), Error> {
        let offset = self.offset();
        if offset % CHUNK_BYTES + piece.len() > CHUNK_BYTES {
            return Err(Error::Synthesis);
        }
        self.len += piece.len();
        self.pieces.push(Placed {
            offset,
            piece: Piece::Bounded(piece),
        });
        Ok(())
    }

    /// Appends a bounded word, split at the chunk boundary when it crosses
    /// one ([`split_bounded`]).
    ///
    /// # Errors
    ///
    /// [`Error`] from the split.
    pub fn push_bounded_split(
        &mut self,
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
        piece: &BoundedBytes<F>,
    ) -> Result<(), Error> {
        let room = CHUNK_BYTES - self.offset() % CHUNK_BYTES;
        if piece.len() <= room {
            return self.push_bounded(piece.clone());
        }
        let (low, high) = split_bounded(uint, region, piece, room)?;
        self.push_bounded(low)?;
        self.push_bounded(high)
    }

    /// Lays out `bytes` on the tape with primary segments cut at this
    /// string's chunk boundaries, appends them, and returns the run (whose
    /// secondary segments `secondary` are relative to the run).
    ///
    /// # Errors
    ///
    /// [`Error`] from [`BytesChip::run`].
    pub fn push_run(
        &mut self,
        chip: &mut BytesChip<F>,
        region: &mut Region<'_, F>,
        bytes: &[Value<u8>],
        secondary: &[SegmentSpec],
    ) -> Result<ByteRun<F>, Error> {
        let primary = chunk_segments(self.offset(), bytes.len());
        let run = chip.run(region, bytes, &primary, secondary)?;
        for segment in run.primary() {
            self.push_bounded(segment.bounded().ok_or(Error::Synthesis)?)?;
        }
        Ok(run)
    }

    /// The chunk elements `c_0 .. c_(m-1)` of the string.
    ///
    /// # Errors
    ///
    /// [`Error`] from the glue rows.
    pub fn chunk_items(
        &self,
        glue: &mut GlueChip<F>,
        region: &mut Region<'_, F>,
    ) -> Result<Vec<PackedItem<F>>, Error> {
        let end = self.offset();
        let first = self.origin / CHUNK_BYTES;
        let chunks = if self.len == 0 {
            0
        } else {
            end.div_ceil(CHUNK_BYTES) - first
        };
        let base = |chunk: usize| (chunk * CHUNK_BYTES).max(self.origin);
        let mut constants = vec![F::ZERO; chunks];
        let mut terms: Vec<Vec<(F, &Word<F>)>> = vec![Vec::new(); chunks];
        for placed in &self.pieces {
            match &placed.piece {
                Piece::Constant(bytes) => {
                    for (index, byte) in bytes.iter().enumerate() {
                        let at = placed.offset + index;
                        let chunk = at / CHUNK_BYTES;
                        let slot = constants.get_mut(chunk - first).ok_or(Error::Synthesis)?;
                        *slot += F::from(u64::from(*byte)) * byte_power::<F>(at - base(chunk));
                    }
                }
                Piece::Bounded(piece) => {
                    let chunk = placed.offset / CHUNK_BYTES;
                    let power = byte_power::<F>(placed.offset - base(chunk));
                    terms
                        .get_mut(chunk - first)
                        .ok_or(Error::Synthesis)?
                        .push((power, piece.word()));
                }
            }
        }
        constants
            .into_iter()
            .zip(terms)
            .map(|(constant, terms)| combine(glue, region, constant, &terms))
            .collect()
    }

    /// The chunk words as cells (a constant chunk is pinned by a glue row),
    /// bounded by their piece lengths: the pieces a circuit exports for a
    /// string that another circuit continues.
    ///
    /// # Errors
    ///
    /// [`Error`] from the glue rows.
    pub fn chunk_words(
        &self,
        glue: &mut GlueChip<F>,
        region: &mut Region<'_, F>,
    ) -> Result<Vec<BoundedBytes<F>>, Error> {
        let items = self.chunk_items(glue, region)?;
        items
            .into_iter()
            .zip(self.piece_lengths())
            .map(|(item, len)| {
                let word = match item {
                    PackedItem::Word(word) => word,
                    PackedItem::Constant(constant) => glue.constant(region, constant)?,
                };
                Ok(BoundedBytes::new(word, len))
            })
            .collect()
    }

    /// The `P_bytes` element list: the byte length, then the chunks.
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] for a string with a nonzero origin, and
    /// [`Error`] from the glue rows.
    pub fn items(
        &self,
        glue: &mut GlueChip<F>,
        region: &mut Region<'_, F>,
    ) -> Result<Vec<PackedItem<F>>, Error> {
        if self.origin != 0 {
            return Err(Error::Synthesis);
        }
        let mut items = vec![PackedItem::Constant(F::from(length_word(self.len)))];
        items.extend(self.chunk_items(glue, region)?);
        Ok(items)
    }

    /// `P_bytes(domain, string)`.
    ///
    /// # Errors
    ///
    /// As [`Self::items`], and [`Error`] from the sponge.
    pub fn digest(
        &self,
        glue: &mut GlueChip<F>,
        sponge: &mut impl WordHasher<F>,
        region: &mut Region<'_, F>,
        domain: u64,
    ) -> Result<Word<F>, Error>
    where
        F: PoseidonField,
    {
        let items = self.items(glue, region)?;
        let inputs: Vec<AbsorbInput<'_, F>> = items.iter().map(PackedItem::absorb).collect();
        sponge.hash_inputs(region, domain, &inputs)
    }
}

/// One chunk word from its constant part and its bounded terms.
fn combine<F: PastaField>(
    glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    constant: F,
    terms: &[(F, &Word<F>)],
) -> Result<PackedItem<F>, Error> {
    match terms {
        [] => Ok(PackedItem::Constant(constant)),
        [(power, word)] if *power == F::ONE && bool::from(constant.is_zero()) => {
            Ok(PackedItem::Word((*word).clone()))
        }
        _ => {
            let (head, mut rest) = terms.split_at(terms.len().min(3));
            let mut acc = glue.linear(region, head, constant)?;
            while !rest.is_empty() {
                let (next, tail) = rest.split_at(rest.len().min(2));
                let mut row: Vec<(F, &Word<F>)> = vec![(F::ONE, &acc)];
                row.extend_from_slice(next);
                acc = glue.linear(region, &row, F::ZERO)?;
                rest = tail;
            }
            Ok(PackedItem::Word(acc))
        }
    }
}

/// The halves of the little-endian integer `value` of `len` bytes split at
/// byte `at`: bytes `0 .. at` and `at .. len`.
fn split_native<F: PastaField>(value: &F, at: usize, len: usize) -> (F, F) {
    let bytes = field_le_bytes(value);
    let low = bytes.get(..at).and_then(le_value).unwrap_or(F::ZERO);
    let high = bytes.get(at..len).and_then(le_value).unwrap_or(F::ZERO);
    (low, high)
}

/// Splits `piece` at byte `at` (`0 < at < len`) into its first `at` bytes and
/// the rest: both halves are range-checked to `8 at` and `8 (len - at)` bits,
/// and `low + 256^at high` is constrained to equal the piece.
///
/// # Errors
///
/// [`Error::Synthesis`] for `at` outside `1 .. len`, and [`Error`] from the
/// layout.
pub fn split_bounded<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    piece: &BoundedBytes<F>,
    at: usize,
) -> Result<(BoundedBytes<F>, BoundedBytes<F>), Error> {
    let len = piece.len();
    if at == 0 || at >= len {
        return Err(Error::Synthesis);
    }
    let halves = piece
        .word()
        .value()
        .map(|value| split_native(&value, at, len));
    let (low, high) = halves.unzip();
    let low = uint.range().witness_range_checked(region, low, 8 * at)?;
    let high = uint
        .range()
        .witness_range_checked(region, high, 8 * (len - at))?;
    let glue = uint.glue();
    let recomposed = glue.linear(
        region,
        &[(F::ONE, &low), (byte_power::<F>(at), &high)],
        F::ZERO,
    )?;
    GlueChip::assert_equal(region, &recomposed, piece.word())?;
    Ok((
        BoundedBytes::new(low, at),
        BoundedBytes::new(high, len - at),
    ))
}

/// A new word of `len` opaque bytes (`1..=31`), range-checked to `8 len`
/// bits: a chunk whose bytes are hashed but not linked to anything else.
///
/// # Errors
///
/// [`Error::Synthesis`] for a length outside `1..=31`, and [`Error`] from the
/// layout.
pub fn opaque_bytes<F: PastaField>(
    range: &mut RunningSumChip<F>,
    region: &mut Region<'_, F>,
    value: Value<F>,
    len: usize,
) -> Result<BoundedBytes<F>, Error> {
    if !(1..=MAX_SEGMENT_BYTES).contains(&len) {
        return Err(Error::Synthesis);
    }
    let word = range.witness_range_checked(region, value, 8 * len)?;
    Ok(BoundedBytes::new(word, len))
}

/// Range-checks an existing word to `8 len` bits (`1..=31` bytes) and
/// returns it as bounded bytes.
///
/// # Errors
///
/// As [`opaque_bytes`].
pub fn bound_bytes<F: PastaField>(
    range: &mut RunningSumChip<F>,
    region: &mut Region<'_, F>,
    word: &Word<F>,
    len: usize,
) -> Result<BoundedBytes<F>, Error> {
    if !(1..=MAX_SEGMENT_BYTES).contains(&len) {
        return Err(Error::Synthesis);
    }
    range.range_check(region, word, 8 * len)?;
    Ok(BoundedBytes::new(word.clone(), len))
}

/// The `LE32` length prefix of `len` bytes.
///
/// # Errors
///
/// [`Error::Synthesis`] for a length of `2^32` or more.
pub fn length_prefix(len: usize) -> Result<[u8; LENGTH_PREFIX_BYTES], Error> {
    u32::try_from(len)
        .map(u32::to_le_bytes)
        .map_err(|_| Error::Synthesis)
}

/// The length-prefixed proof string `LE32 len(bytes) || bytes`, starting at
/// in-chunk offset `origin`, laid out on the tape and cut into its chunk
/// pieces.
///
/// With `origin = 0` the pieces are the chunks of the step-proof digest
/// string (`kgwstep1`): [`super::SIGMA_EXPORT_CHUNKS`] = 107 for the sigma of
/// 3,296 bytes, the first holding the length prefix and 27 proof bytes. A
/// circuit that appends them to a string at another offset splits each piece
/// once ([`PBytes::push_bounded_split`]); exporting at the consumer's origin
/// instead (`(4 + |Omega|) mod 31` for `LE32 len(Omega) || Omega || LE32
/// len(sigma) || sigma`) avoids the splits. `secondary` places the secondary
/// segments relative to the first proof byte.
///
/// # Errors
///
/// [`Error::Synthesis`] for an origin of 31 or more or a length of `2^32` or
/// more, and [`Error`] from the layout.
pub fn export_length_prefixed<F: PastaField>(
    chip: &mut BytesChip<F>,
    glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    bytes: &[Value<u8>],
    secondary: &[SegmentSpec],
    origin: usize,
) -> Result<(ByteRun<F>, Vec<BoundedBytes<F>>), Error> {
    let mut string = PBytes::starting_at(origin)?;
    string.push_constant(&length_prefix(bytes.len())?);
    let run = string.push_run(chip, region, bytes, secondary)?;
    let pieces = string.chunk_words(glue, region)?;
    Ok((run, pieces))
}

#[cfg(test)]
mod unit_tests {
    use iroha_pasta::Fp;

    use super::*;

    #[test]
    fn split_native_halves() {
        let value = le_value::<Fp>(&[1, 2, 3, 4, 5]).expect("value");
        let (low, high) = split_native(&value, 2, 5);
        assert_eq!(low, Fp::from(0x0201));
        assert_eq!(high, Fp::from(0x05_0403));
        assert_eq!(low + Fp::from(65_536) * high, value);
    }

    #[test]
    fn length_prefixes() {
        assert_eq!(length_prefix(3_296), Ok([0xe0, 0x0c, 0, 0]));
        assert_eq!(length_prefix(0), Ok([0; 4]));
        assert_eq!(
            length_prefix(usize::try_from(u64::from(u32::MAX) + 1).unwrap_or(usize::MAX)),
            Err(Error::Synthesis)
        );
    }

    #[test]
    fn piece_lengths_follow_the_origin() {
        let mut string = PBytes::<Fp>::starting_at(28).expect("origin");
        string.push_constant(&[0; 40]);
        assert_eq!(string.piece_lengths(), vec![3, 31, 6]);
        assert_eq!(string.offset(), 68);
        assert!(PBytes::<Fp>::starting_at(31).is_err());
        let empty = PBytes::<Fp>::default();
        assert!(empty.is_empty());
        assert!(empty.piece_lengths().is_empty());
        // An empty string has no chunk, whatever its origin.
        let shifted = PBytes::<Fp>::starting_at(5).expect("origin");
        assert!(shifted.piece_lengths().is_empty());
        assert_eq!(shifted.offset(), 5);
    }
}
