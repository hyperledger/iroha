//! The unit geometry of the SHA-256 chip: how a 32-bit word is cut into
//! pieces, where each piece lives, and the spread sums of its rotations.
//!
//! A *unit* is two rows of the chip's columns. Each row carries one lookup
//! `(tag, dense, spread)` against the spread table, so a unit holds two
//! looked-up pieces; the other pieces are boolean cells in the bit columns.
//! A decomposition spec lists the pieces of one word (they tile `[0, 32)`)
//! and the rotation sums the unit outputs. Every rotation or shift amount
//! of a sum is a piece boundary, so a rotated word is a reordering of whole
//! pieces and its spread form is a linear combination of piece spreads.

use super::native::spread;

/// Bit columns of the chip.
pub const BIT_COLUMNS: usize = 7;

/// Word columns of the chip (equality-enabled).
pub const WORD_COLUMNS: usize = 4;

/// Rows of one unit.
pub const UNIT_ROWS: usize = 2;

/// Bit cells of one unit.
pub const BIT_SLOTS: usize = BIT_COLUMNS * UNIT_ROWS;

/// Word cells of one unit.
pub const WORD_SLOTS: usize = WORD_COLUMNS * UNIT_ROWS;

/// The piece widths the spread table holds: `(w, x, spread(x))` for every
/// `x < 2^w`, plus the all-zero row of inactive rows.
pub const TABLE_TAGS: [u32; 3] = [7, 8, 11];

/// Rows of the spread table.
pub const TABLE_ROWS: usize = 1 + (1 << 7) + (1 << 8) + (1 << 11);

/// Where the cells of one piece live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PieceCells {
    /// The lookup cells of unit row `row` with width tag `tag`.
    Lookup {
        /// The unit row (0 or 1).
        row: usize,
        /// The table tag, equal to the piece width.
        tag: u32,
    },
    /// Consecutive bit slots from `first` (slot `j` is bit column `j % 7`
    /// of unit row `j / 7`), least significant bit first.
    Bits {
        /// The first bit slot.
        first: usize,
    },
}

/// One piece `[lo, lo + width)` of a 32-bit word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Piece {
    /// The lowest bit.
    pub lo: u32,
    /// The width in bits.
    pub width: u32,
    /// Its cells.
    pub cells: PieceCells,
}

/// A rotation or shift of a 32-bit word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shift {
    /// Rotate right.
    Rotr(u32),
    /// Shift right.
    Shr(u32),
}

/// The pieces of one decomposition unit and its outputs.
///
/// Outputs are word slots of the unit: the dense value in slot 0, the
/// spread value in slot 1 when [`Self::spread_output`] is set, and the
/// rotation sums in slots 2, 3, ... in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecompositionSpec {
    /// A label for gates and diagnostics.
    pub name: &'static str,
    /// The pieces, tiling `[0, 32)` in increasing order.
    pub pieces: &'static [Piece],
    /// Whether slot 1 holds the spread form of the word.
    pub spread_output: bool,
    /// Each rotation sum: the spread forms of the listed shifts, added.
    pub rotations: &'static [&'static [Shift]],
}

/// Shorthand constructors for the static specs.
const fn lookup(lo: u32, width: u32, row: usize) -> Piece {
    Piece {
        lo,
        width,
        cells: PieceCells::Lookup { row, tag: width },
    }
}

const fn bits(lo: u32, width: u32, first: usize) -> Piece {
    Piece {
        lo,
        width,
        cells: PieceCells::Bits { first },
    }
}

/// A 32-bit word with its spread form: 11 bits looked up, 14 boolean
/// cells, 7 bits looked up. Even and odd halves of every spread sum, and
/// every 32-bit range check, are this unit.
pub const HALF: DecompositionSpec = DecompositionSpec {
    name: "half",
    pieces: &[lookup(0, 11, 0), bits(11, 14, 0), lookup(25, 7, 1)],
    spread_output: true,
    rotations: &[],
};

/// The compression word `A_t`: pieces `2 | 11 | 9 | 7 | 3` at the `Σ0`
/// rotation points 2, 13, 22 (the 11- and 7-bit pieces looked up).
pub const DECOMPOSE_A: DecompositionSpec = DecompositionSpec {
    name: "decompose a",
    pieces: &[
        bits(0, 2, 0),
        lookup(2, 11, 0),
        bits(13, 9, 2),
        lookup(22, 7, 1),
        bits(29, 3, 11),
    ],
    spread_output: true,
    rotations: &[&[Shift::Rotr(2), Shift::Rotr(13), Shift::Rotr(22)]],
};

/// The compression word `E_t`: pieces `6 | 5 | 3 | 11 | 7` at the `Σ1`
/// rotation points 6, 11, 25 (all 14 bit slots used).
pub const DECOMPOSE_E: DecompositionSpec = DecompositionSpec {
    name: "decompose e",
    pieces: &[
        bits(0, 6, 0),
        bits(6, 5, 6),
        bits(11, 3, 11),
        lookup(14, 11, 0),
        lookup(25, 7, 1),
    ],
    spread_output: true,
    rotations: &[&[Shift::Rotr(6), Shift::Rotr(11), Shift::Rotr(25)]],
};

/// A schedule word `W_t`: pieces `3 | 4 | 3 | 7 | 1 | 1 | 2 | 11` at the
/// `σ0` points 3, 7, 18 and the `σ1` points 10, 17, 19 (all 14 bit slots
/// used). It outputs the `σ0` and `σ1` spread sums, not its spread form.
pub const DECOMPOSE_W: DecompositionSpec = DecompositionSpec {
    name: "decompose w",
    pieces: &[
        bits(0, 3, 0),
        bits(3, 4, 3),
        bits(7, 3, 7),
        lookup(10, 7, 0),
        bits(17, 1, 10),
        bits(18, 1, 11),
        bits(19, 2, 12),
        lookup(21, 11, 1),
    ],
    spread_output: false,
    rotations: &[
        &[Shift::Rotr(7), Shift::Rotr(18), Shift::Shr(3)],
        &[Shift::Rotr(17), Shift::Rotr(19), Shift::Shr(10)],
    ],
};

/// Every decomposition spec of the chip.
pub const SPECS: [DecompositionSpec; 4] = [HALF, DECOMPOSE_A, DECOMPOSE_E, DECOMPOSE_W];

/// `2^width - 1`.
#[must_use]
pub const fn mask(width: u32) -> u32 {
    if width >= 32 {
        u32::MAX
    } else {
        (1 << width) - 1
    }
}

impl Piece {
    /// The piece of `word`.
    #[must_use]
    pub const fn of(&self, word: u32) -> u32 {
        (word >> self.lo) & mask(self.width)
    }

    /// The bit position of this piece in `shift(word)`, or `None` when the
    /// shift drops it. The shift amount must not fall strictly inside the
    /// piece ([`DecompositionSpec::validate`] checks this).
    #[must_use]
    pub const fn shifted_position(&self, shift: Shift) -> Option<u32> {
        match shift {
            Shift::Rotr(amount) => Some((self.lo + 32 - amount) % 32),
            Shift::Shr(amount) => {
                if self.lo >= amount {
                    Some(self.lo - amount)
                } else {
                    None
                }
            }
        }
    }

    /// The spread coefficients of this piece in a rotation sum: one power
    /// `4^position` per shift that keeps it.
    #[must_use]
    pub fn rotation_positions(&self, shifts: &[Shift]) -> Vec<u32> {
        shifts
            .iter()
            .filter_map(|shift| self.shifted_position(*shift))
            .collect()
    }
}

impl DecompositionSpec {
    /// Checks the geometry: pieces tile `[0, 32)`; exactly two looked-up
    /// pieces, one on each unit row, each a table width; bit pieces fill
    /// all [`BIT_SLOTS`] slots once (the row-wide booleanity gate reads
    /// every bit cell of a unit); every shift amount a piece boundary; at
    /// most two rotation sums.
    ///
    /// # Errors
    ///
    /// A description of the first violated rule.
    #[cfg(test)]
    pub fn validate(&self) -> Result<(), &'static str> {
        let mut next = 0;
        let mut lookup_rows = [false; UNIT_ROWS];
        let mut used = [false; BIT_SLOTS];
        for piece in self.pieces {
            if piece.lo != next || piece.width == 0 {
                return Err("pieces do not tile the word");
            }
            next += piece.width;
            match piece.cells {
                PieceCells::Lookup { row, tag } => {
                    if row >= UNIT_ROWS || lookup_rows[row] {
                        return Err("lookup rows must be distinct unit rows");
                    }
                    if tag != piece.width || !TABLE_TAGS.contains(&tag) {
                        return Err("lookup width must be a table tag");
                    }
                    lookup_rows[row] = true;
                }
                PieceCells::Bits { first } => {
                    let slots = used
                        .get_mut(first..first + piece.width as usize)
                        .ok_or("bit slots overlap or overflow")?;
                    if slots.iter().any(|slot| *slot) {
                        return Err("bit slots overlap or overflow");
                    }
                    slots.fill(true);
                }
            }
        }
        if next != 32 {
            return Err("pieces do not cover 32 bits");
        }
        if lookup_rows != [true; UNIT_ROWS] {
            return Err("a unit has one lookup per row");
        }
        if used != [true; BIT_SLOTS] {
            return Err("a unit fills every bit slot");
        }
        if self.rotations.len() > WORD_SLOTS / 2 - 2 {
            return Err("too many rotation sums");
        }
        let boundaries: Vec<u32> = self.pieces.iter().map(|piece| piece.lo).collect();
        for shifts in self.rotations {
            for shift in *shifts {
                let (Shift::Rotr(amount) | Shift::Shr(amount)) = *shift;
                if amount == 0 || amount >= 32 || !boundaries.contains(&amount) {
                    return Err("a shift amount is not a piece boundary");
                }
            }
        }
        Ok(())
    }

    /// The bit slots the pieces use.
    #[cfg(test)]
    #[must_use]
    pub fn bit_slots(&self) -> usize {
        self.pieces
            .iter()
            .map(|piece| match piece.cells {
                PieceCells::Bits { .. } => piece.width as usize,
                PieceCells::Lookup { .. } => 0,
            })
            .sum()
    }

    /// The word slot of rotation sum `index`.
    #[must_use]
    pub const fn rotation_slot(index: usize) -> usize {
        2 + index
    }

    /// Native reference of rotation sum `index` of `word`, computed from
    /// the pieces exactly as the gate does.
    #[must_use]
    pub fn rotation_sum(&self, index: usize, word: u32) -> u64 {
        let Some(shifts) = self.rotations.get(index) else {
            return 0;
        };
        self.pieces
            .iter()
            .map(|piece| {
                let piece_spread = spread(piece.of(word));
                piece
                    .rotation_positions(shifts)
                    .iter()
                    .map(|position| piece_spread << (2 * position))
                    .sum::<u64>()
            })
            .sum()
    }
}

/// The table rows `(tag, x, spread(x))`, the zero row first.
pub fn table_rows() -> impl Iterator<Item = (u32, u32, u64)> {
    core::iter::once((0, 0, 0)).chain(
        TABLE_TAGS
            .into_iter()
            .flat_map(|tag| (0..1_u32 << tag).map(move |x| (tag, x, spread(x)))),
    )
}

#[cfg(test)]
mod tests {
    use super::{super::native::*, *};

    #[test]
    fn specs_are_valid_and_fit_the_unit() {
        for spec in SPECS {
            assert_eq!(spec.validate(), Ok(()), "{}", spec.name);
        }
        for spec in SPECS {
            assert_eq!(spec.bit_slots(), BIT_SLOTS, "{}", spec.name);
        }
        assert_eq!(table_rows().count(), TABLE_ROWS);
        assert_eq!(TABLE_ROWS, 2433);
    }

    #[test]
    fn validation_rejects_bad_geometry() {
        const GAP: &[Piece] = &[lookup(0, 11, 0), bits(12, 14, 0), lookup(26, 7, 1)];
        const ONE_ROW: &[Piece] = &[lookup(0, 11, 0), bits(11, 14, 0), lookup(25, 7, 0)];
        const ODD_WIDTH: &[Piece] = &[lookup(0, 9, 0), bits(9, 14, 0), lookup(23, 9, 1)];
        const OVERLAP: &[Piece] = &[
            bits(0, 8, 0),
            lookup(8, 11, 0),
            lookup(19, 7, 1),
            bits(26, 6, 7),
        ];
        const SHORT: &[Piece] = &[lookup(0, 11, 0), bits(11, 10, 0), lookup(21, 11, 1)];
        for (pieces, error) in [
            (GAP, "pieces do not tile the word"),
            (ONE_ROW, "lookup rows must be distinct unit rows"),
            (ODD_WIDTH, "lookup width must be a table tag"),
            (OVERLAP, "bit slots overlap or overflow"),
            (SHORT, "a unit fills every bit slot"),
        ] {
            let mut spec = HALF;
            spec.pieces = pieces;
            assert_eq!(spec.validate(), Err(error));
        }
        let mut straddle = DECOMPOSE_A;
        straddle.rotations = &[&[Shift::Rotr(3)]];
        assert_eq!(
            straddle.validate(),
            Err("a shift amount is not a piece boundary")
        );
    }

    #[test]
    fn rotation_sums_match_the_direct_formulas() {
        let mut word = 0x0123_4567_u32;
        for _ in 0..256 {
            word = word
                .wrapping_mul(0x9e37_79b9)
                .wrapping_add(0x7f4a_7c15)
                .rotate_left(5);
            assert_eq!(
                DECOMPOSE_A.rotation_sum(0, word),
                big_sigma0_spread_sum(word)
            );
            assert_eq!(
                DECOMPOSE_E.rotation_sum(0, word),
                big_sigma1_spread_sum(word)
            );
            assert_eq!(
                DECOMPOSE_W.rotation_sum(0, word),
                small_sigma0_spread_sum(word)
            );
            assert_eq!(
                DECOMPOSE_W.rotation_sum(1, word),
                small_sigma1_spread_sum(word)
            );
            assert_eq!(HALF.rotation_sum(0, word), 0);
            for spec in SPECS {
                let recomposed: u32 = spec
                    .pieces
                    .iter()
                    .map(|piece| piece.of(word) << piece.lo)
                    .sum();
                assert_eq!(recomposed, word);
            }
        }
        for word in [0, u32::MAX] {
            assert_eq!(
                DECOMPOSE_W.rotation_sum(1, word),
                small_sigma1_spread_sum(word)
            );
        }
    }

    #[test]
    fn piece_positions() {
        let piece = lookup(10, 7, 0);
        assert_eq!(piece.shifted_position(Shift::Rotr(7)), Some(3));
        assert_eq!(piece.shifted_position(Shift::Rotr(17)), Some(25));
        assert_eq!(piece.shifted_position(Shift::Shr(10)), Some(0));
        assert_eq!(piece.shifted_position(Shift::Shr(17)), None);
        assert_eq!(
            piece.rotation_positions(&[Shift::Rotr(7), Shift::Shr(17)]),
            vec![3]
        );
        assert_eq!(piece.of(0xffff_ffff), 0x7f);
        assert_eq!(mask(32), u32::MAX);
        assert_eq!(mask(3), 7);
    }
}
