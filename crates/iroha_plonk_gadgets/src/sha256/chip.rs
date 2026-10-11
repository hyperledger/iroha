//! The SHA-256 chip: configuration, units, the compression function and the
//! digest codec (see the module documentation of [`super`]).

use core::{cmp::Ordering, marker::PhantomData};

use iroha_pasta::PastaField;
use iroha_plonk::{
    cs::{Advice, Column, ConstraintSystem, Expression, Fixed, Rotation, Selector, VirtualCells},
    frontend::{Error, Layouter, Region, Value},
};

use super::{
    native::{
        BLOCK_WORDS, DIGEST_PADDING, ROUNDS, SHA256_IV, SHA256_K, SPREAD_ONES, STATE_WORDS,
        big_sigma0_spread_sum, big_sigma1_spread_sum, canonical_u32_limbs, digest_message,
        small_sigma0_spread_sum, small_sigma1_spread_sum, split, spread,
    },
    spec::{
        BIT_COLUMNS, BIT_SLOTS, DecompositionSpec, Piece, PieceCells, SPECS, UNIT_ROWS,
        WORD_COLUMNS, WORD_SLOTS, table_rows,
    },
};
use crate::{
    cells::{RowCursor, Uint, Word, assign_constant, assign_word, copy_word},
    table::{GuestLookup, SHA_TAG_BASE, SharedTable, TableGuest},
};

/// Advice columns of the chip: the lookup pair `(dense, spread)`, seven bit
/// columns and four equality-enabled word columns, in that order.
pub const SHA256_ADVICE_COLUMNS: usize = 2 + BIT_COLUMNS + WORD_COLUMNS;

/// Rows of one compression round (twelve units).
pub const ROUND_ROWS: usize = 12 * UNIT_ROWS;

/// Rows of one message-schedule step `t >= 16` (five units).
pub const SCHEDULE_ROWS: usize = 5 * UNIT_ROWS;

/// Rows of the feed-forward (eight units).
pub const FEED_FORWARD_ROWS: usize = 8 * UNIT_ROWS;

/// Rows of the digest codec (sixteen byte units and eight borrow units).
pub const DIGEST_CODEC_ROWS: usize = 24 * UNIT_ROWS;

/// Rows of [`Sha256Chip::hash_digest`]: the codec, the seven assigned
/// message words `W_1 .. W_7` (`W_0` and the padding cost no unit), the
/// schedule, the rounds and the feed-forward (2,094 rows).
pub const HASH_DIGEST_ROWS: usize = DIGEST_CODEC_ROWS
    + 7 * UNIT_ROWS
    + (ROUNDS - BLOCK_WORDS) * SCHEDULE_ROWS
    + ROUNDS * ROUND_ROWS
    + FEED_FORWARD_ROWS;

/// Spec indices into [`SPECS`].
const SPEC_HALF: usize = 0;
const SPEC_A: usize = 1;
const SPEC_E: usize = 2;
const SPEC_W: usize = 3;

/// Word slots shared by the gates (slot `j` is word column `j % 4` of unit
/// row `j / 4`).
const SLOT_DENSE: usize = 0;
const SLOT_SPREAD: usize = 1;
const SLOT_EVEN: usize = 2;
const SLOT_INPUT: usize = 3;

/// `2^32` as an integer.
const TWO_32: u64 = 1 << 32;

/// The table tag of a looked-up piece of width `width` (the SHA namespace of
/// the shared table, [`SHA_TAG_BASE`]` + w`).
#[must_use]
pub const fn table_tag(width: u32) -> u64 {
    SHA_TAG_BASE + width as u64
}

/// The spread table's columns `(T, spread, dense)`: its own three fixed
/// columns, or `T`, `x_0` and `V` of the shared table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SpreadTable {
    tag: Column<Fixed>,
    spread: Column<Fixed>,
    dense: Column<Fixed>,
}

/// Columns, table and selectors of the SHA-256 chip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sha256Config {
    dense: Column<Advice>,
    spread: Column<Advice>,
    bits: [Column<Advice>; BIT_COLUMNS],
    words: [Column<Advice>; WORD_COLUMNS],
    tag: Column<Fixed>,
    constant: Column<Fixed>,
    table: SpreadTable,
    /// The first row of the spread table.
    table_start: usize,
    q_lookup: Selector,
    q_bool: Selector,
    q_decompose: [Selector; 4],
    q_bytes: Selector,
    q_bytes_join: Selector,
    q_split: Selector,
    q_split_maj: Selector,
    q_split_ch: Selector,
    q_split_ch_not: Selector,
    q_add_e: Selector,
    q_t1: Selector,
    q_add_a: Selector,
    q_add_w: Selector,
    q_feed: Selector,
    q_borrow: Selector,
}

/// `2^exponent` in `F` (`exponent <= 127`).
fn pow2<F: PastaField>(exponent: u32) -> F {
    F::from_u128(1_u128 << exponent)
}

/// A constant expression.
fn constant<F: PastaField>(value: F) -> Expression<F> {
    Expression::Constant(value)
}

/// The sum of `terms` (zero when empty).
fn sum<F: PastaField>(terms: impl IntoIterator<Item = Expression<F>>) -> Expression<F> {
    terms
        .into_iter()
        .reduce(|acc, term| acc + term)
        .unwrap_or_else(|| constant(F::ZERO))
}

/// `x (x - 1)`: zero exactly on `{0, 1}`.
fn boolean<F: PastaField>(x: Expression<F>) -> Expression<F> {
    x.clone() * (x - constant(F::ONE))
}

/// `x (x - 1) (x - 2) (x - 3)`: zero exactly on `{0, 1, 2, 3}` (degree 4).
fn below_four<F: PastaField>(x: &Expression<F>) -> Expression<F> {
    (1..4).fold(x.clone(), |acc, root| {
        acc * (x.clone() - constant(F::from(root)))
    })
}

/// The rotation of unit row `row`.
const fn unit_rotation(row: usize) -> Rotation {
    if row == 0 {
        Rotation::cur()
    } else {
        Rotation::next()
    }
}

/// Query helpers over the chip's columns inside a gate.
struct Queries<'c, 'v, 'm, F: PastaField> {
    cells: &'c mut VirtualCells<'m, F>,
    config: &'v Sha256Config,
}

impl<F: PastaField> Queries<'_, '_, '_, F> {
    fn word(&mut self, slot: usize) -> Expression<F> {
        self.cells.query_advice(
            self.config.words[slot % WORD_COLUMNS],
            unit_rotation(slot / WORD_COLUMNS),
        )
    }

    fn bit(&mut self, slot: usize) -> Expression<F> {
        self.cells.query_advice(
            self.config.bits[slot % BIT_COLUMNS],
            unit_rotation(slot / BIT_COLUMNS),
        )
    }

    fn dense(&mut self, row: usize) -> Expression<F> {
        self.cells
            .query_advice(self.config.dense, unit_rotation(row))
    }

    fn spread(&mut self, row: usize) -> Expression<F> {
        self.cells
            .query_advice(self.config.spread, unit_rotation(row))
    }

    fn constant_column(&mut self) -> Expression<F> {
        self.cells
            .query_fixed(self.config.constant, Rotation::cur())
    }

    fn selector(&mut self, selector: Selector) -> Expression<F> {
        self.cells.query_selector(selector)
    }

    /// `sum_k bit(first + k) radix^k` over `count` bit slots.
    fn bits_value(&mut self, first: usize, count: u32, radix_log2: u32) -> Expression<F> {
        sum((0..count).map(|k| self.bit(first + k as usize) * pow2::<F>(radix_log2 * k)))
    }

    /// The dense and spread expressions of `piece`.
    fn piece(&mut self, piece: &Piece) -> (Expression<F>, Expression<F>) {
        match piece.cells {
            PieceCells::Lookup { row, .. } => (self.dense(row), self.spread(row)),
            PieceCells::Bits { first } => (
                self.bits_value(first, piece.width, 1),
                self.bits_value(first, piece.width, 2),
            ),
        }
    }
}

impl Sha256Config {
    /// Configures the chip on `advice` (in the order of
    /// [`SHA256_ADVICE_COLUMNS`]: dense, spread, seven bit columns, four
    /// word columns; the word columns are made equality-enabled) and enables
    /// `constants` as a constants column. It adds two fixed columns (the
    /// lookup tag and the per-row constant), its own three table columns
    /// `(T, spread, dense)` and its lookup argument, one complex selector and
    /// seventeen simple selectors.
    pub fn configure<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; SHA256_ADVICE_COLUMNS],
        constants: Column<Fixed>,
    ) -> Self {
        let table = SpreadTable {
            tag: meta.fixed_column(),
            spread: meta.fixed_column(),
            dense: meta.fixed_column(),
        };
        let config = Self::configure_on(meta, advice, constants, table, 0);
        meta.lookup_any("sha256 spread", |cells| {
            let GuestLookup { mut pairs, value } = config.guest_lookup(cells);
            pairs.push((value, cells.query_fixed(table.dense, Rotation::cur())));
            pairs
        });
        config
    }

    /// [`Self::configure`] on the shared table ([`crate::table`]): the spread
    /// rows go to `T`, `x_0` and `V` from `table_start`, and the chip
    /// registers no lookup of its own. The caller passes the configuration
    /// as the `C`/`Q` guest of [`crate::ff::FfConfig::configure_shared`]
    /// and must keep the SHA rows disjoint from the foreign-field rows (the
    /// Q-leaf layout, [`crate::q_leaf`]).
    pub fn configure_shared<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; SHA256_ADVICE_COLUMNS],
        constants: Column<Fixed>,
        shared: &SharedTable,
        table_start: usize,
    ) -> Self {
        let [spread, ..] = shared.x();
        let table = SpreadTable {
            tag: shared.tag(),
            spread,
            dense: shared.value(),
        };
        Self::configure_on(meta, advice, constants, table, table_start)
    }

    fn configure_on<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; SHA256_ADVICE_COLUMNS],
        constants: Column<Fixed>,
        table: SpreadTable,
        table_start: usize,
    ) -> Self {
        let [dense, spread, bits @ .., w0, w1, w2, w3] = advice;
        let bits: [Column<Advice>; BIT_COLUMNS] = bits;
        let words = [w0, w1, w2, w3];
        for column in words {
            meta.enable_equality(column);
        }
        meta.enable_constant(constants);
        let config = Self {
            dense,
            spread,
            bits,
            words,
            tag: meta.fixed_column(),
            constant: meta.fixed_column(),
            table,
            table_start,
            q_lookup: meta.complex_selector(),
            q_bool: meta.selector(),
            q_decompose: core::array::from_fn(|_| meta.selector()),
            q_bytes: meta.selector(),
            q_bytes_join: meta.selector(),
            q_split: meta.selector(),
            q_split_maj: meta.selector(),
            q_split_ch: meta.selector(),
            q_split_ch_not: meta.selector(),
            q_add_e: meta.selector(),
            q_t1: meta.selector(),
            q_add_a: meta.selector(),
            q_add_w: meta.selector(),
            q_feed: meta.selector(),
            q_borrow: meta.selector(),
        };
        config.configure_units(meta);
        config.configure_word_gates(meta);
        config
    }

    /// The first row of the spread table.
    #[must_use]
    pub const fn table_start(&self) -> usize {
        self.table_start
    }

    /// The input tag column (`2^33 + w` on lookup rows, 0 elsewhere).
    #[must_use]
    pub const fn tag_column(&self) -> Column<Fixed> {
        self.tag
    }

    /// The lookup selector.
    #[must_use]
    pub const fn lookup_selector(&self) -> Selector {
        self.q_lookup
    }

    /// Booleanity, the four decomposition units and the byte unit.
    fn configure_units<F: PastaField>(&self, meta: &mut ConstraintSystem<F>) {
        let config = *self;
        meta.create_gate("sha256 bits", |cells| {
            let q = cells.query_selector(config.q_bool);
            config
                .bits
                .iter()
                .enumerate()
                .map(|(index, column)| {
                    let bit = cells.query_advice(*column, Rotation::cur());
                    (
                        format!("bit {index}"),
                        q.clone() * (bit.clone() * bit.clone() - bit),
                    )
                })
                .collect::<Vec<_>>()
        });
        for (index, spec) in SPECS.iter().enumerate() {
            let selector = config.q_decompose[index];
            meta.create_gate(format!("sha256 {}", spec.name), |cells| {
                decomposition_polynomials(
                    &mut Queries {
                        cells,
                        config: &config,
                    },
                    selector,
                    spec,
                )
            });
        }
        meta.create_gate("sha256 bytes", |cells| {
            let mut q = Queries {
                cells,
                config: &config,
            };
            let s = q.selector(config.q_bytes);
            let (high, low) = (q.dense(0), q.dense(1));
            let (be, le) = (q.word(0), q.word(1));
            vec![
                (
                    "big-endian pair",
                    s.clone() * (high.clone() * pow2::<F>(8) + low.clone() - be),
                ),
                ("little-endian pair", s * (high + low * pow2::<F>(8) - le)),
            ]
        });
    }

    /// The word-level gates hosted on unit windows.
    fn configure_word_gates<F: PastaField>(&self, meta: &mut ConstraintSystem<F>) {
        let config = *self;
        let two_32 = constant(F::from(TWO_32));
        let split_lhs =
            |q: &mut Queries<'_, '_, '_, F>| q.word(SLOT_EVEN) + q.word(SLOT_SPREAD) * F::from(2);
        meta.create_gate("sha256 split", |cells| {
            let mut q = Queries {
                cells,
                config: &config,
            };
            let s = q.selector(config.q_split);
            let lhs = split_lhs(&mut q);
            vec![("even + 2 odd = sum", s * (lhs - q.word(SLOT_INPUT)))]
        });
        meta.create_gate("sha256 split maj", |cells| {
            let mut q = Queries {
                cells,
                config: &config,
            };
            let s = q.selector(config.q_split_maj);
            let lhs = split_lhs(&mut q);
            let rhs = q.word(3) + q.word(4) + q.word(5);
            vec![("even + 2 odd = a + b + c", s * (lhs - rhs))]
        });
        meta.create_gate("sha256 split ch", |cells| {
            let mut q = Queries {
                cells,
                config: &config,
            };
            let s = q.selector(config.q_split_ch);
            let lhs = split_lhs(&mut q);
            let rhs = q.word(3) + q.word(4);
            vec![("even + 2 odd = e + f", s * (lhs - rhs))]
        });
        let ones = constant(F::from(SPREAD_ONES));
        meta.create_gate("sha256 split ch not", |cells| {
            let mut q = Queries {
                cells,
                config: &config,
            };
            let s = q.selector(config.q_split_ch_not);
            let lhs = split_lhs(&mut q);
            let rhs = ones - q.word(3) + q.word(4);
            vec![("even + 2 odd = !e + g", s * (lhs - rhs))]
        });
        let two_32_e = two_32.clone();
        meta.create_gate("sha256 add e", |cells| {
            let mut q = Queries {
                cells,
                config: &config,
            };
            let s = q.selector(config.q_add_e);
            let (low, high) = (q.word(6), q.word(7));
            let carry = low.clone() + high.clone() * F::from(4);
            let e_sum = q.word(2) + carry * two_32_e - q.word(3) - q.word(4) - q.word(5);
            vec![
                ("e + 2^32 carry = d + t1 + ch_q", s.clone() * e_sum),
                ("carry low in [0, 4)", s.clone() * below_four(&low)),
                ("carry high boolean", s * boolean(high)),
            ]
        });
        meta.create_gate("sha256 t1", |cells| {
            let mut q = Queries {
                cells,
                config: &config,
            };
            let s = q.selector(config.q_t1);
            let k = q.constant_column();
            let t1 = q.word(6) - q.word(2) - q.word(3) - q.word(4) - q.word(5) - k;
            vec![("t1 = h + S1 + ch_p + w + k", s * t1)]
        });
        let two_32_a = two_32.clone();
        meta.create_gate("sha256 add a", |cells| {
            let mut q = Queries {
                cells,
                config: &config,
            };
            let s = q.selector(config.q_add_a);
            let carry = q.word(7);
            let lhs = q.word(SLOT_DENSE) + carry.clone() * two_32_a.clone();
            let rhs = q.word(3) - q.word(4) + q.word(5) + q.word(6) + two_32_a;
            vec![
                (
                    "a + 2^32 carry = e - d + S0 + maj + 2^32",
                    s.clone() * (lhs - rhs),
                ),
                ("carry in [0, 4)", s * below_four(&carry)),
            ]
        });
        let two_32_w = two_32.clone();
        meta.create_gate("sha256 add w", |cells| {
            let mut q = Queries {
                cells,
                config: &config,
            };
            let s = q.selector(config.q_add_w);
            let carry = q.word(6);
            let lhs = q.word(2) + carry.clone() * two_32_w;
            let rhs = q.word(SLOT_DENSE) + q.word(3) + q.word(4) + q.word(5);
            vec![
                (
                    "w + 2^32 carry = s1 + w7 + s0 + w16",
                    s.clone() * (lhs - rhs),
                ),
                ("carry in [0, 4)", s * below_four(&carry)),
            ]
        });
        let two_32_f = two_32.clone();
        meta.create_gate("sha256 feed forward", |cells| {
            let mut q = Queries {
                cells,
                config: &config,
            };
            let s = q.selector(config.q_feed);
            let carry = q.word(4);
            let lhs = q.word(SLOT_DENSE) + carry.clone() * two_32_f;
            vec![
                (
                    "h + 2^32 carry = v + x",
                    s.clone() * (lhs - q.word(2) - q.word(3)),
                ),
                ("carry boolean", s * boolean(carry)),
            ]
        });
        meta.create_gate("sha256 bytes join", |cells| {
            let mut q = Queries {
                cells,
                config: &config,
            };
            let s = q.selector(config.q_bytes_join);
            let be = q.word(4) - q.word(2) * pow2::<F>(16) - q.word(0);
            let le = q.word(5) - q.word(3) - q.word(1) * pow2::<F>(16);
            vec![
                ("big-endian word", s.clone() * be),
                ("little-endian limb", s * le),
            ]
        });
        meta.create_gate("sha256 borrow", |cells| {
            let mut q = Queries {
                cells,
                config: &config,
            };
            let s = q.selector(config.q_borrow);
            let p = q.constant_column();
            let borrow_out = q.word(4);
            let chain = q.word(SLOT_DENSE) + q.word(2) + q.word(3)
                - p
                - borrow_out.clone() * two_32.clone();
            let acc = q.word(6) - q.word(5) * two_32 - q.word(2);
            vec![
                ("c + l + borrow = p + 2^32 borrow'", s.clone() * chain),
                ("borrow' boolean", s.clone() * boolean(borrow_out)),
                ("acc = 2^32 acc' + l", s * acc),
            ]
        });
    }

    /// The advice columns, in the order [`Self::configure`] takes them.
    #[must_use]
    pub fn advice_columns(&self) -> [Column<Advice>; SHA256_ADVICE_COLUMNS] {
        let mut out = [self.dense; SHA256_ADVICE_COLUMNS];
        out[1] = self.spread;
        out[2..2 + BIT_COLUMNS].copy_from_slice(&self.bits);
        out[2 + BIT_COLUMNS..].copy_from_slice(&self.words);
        out
    }
}

/// The spread lookup `(tag, q spread, q dense)` against `(T, spread,
/// dense)`: inactive rows give `(0, 0, 0)` (the tag is 0 off lookup rows).
/// As a guest of a foreign-field argument its dense value joins `V`.
impl<F: PastaField> TableGuest<F> for Sha256Config {
    fn guest_name(&self) -> &'static str {
        "sha256 spread"
    }

    fn guest_lookup(&self, cells: &mut VirtualCells<'_, F>) -> GuestLookup<F> {
        let q = cells.query_selector(self.q_lookup);
        let tag = cells.query_fixed(self.tag, Rotation::cur());
        let dense = cells.query_advice(self.dense, Rotation::cur());
        let spread = cells.query_advice(self.spread, Rotation::cur());
        let table_tag = cells.query_fixed(self.table.tag, Rotation::cur());
        let table_spread = cells.query_fixed(self.table.spread, Rotation::cur());
        GuestLookup {
            pairs: vec![(tag, table_tag), (q.clone() * spread, table_spread)],
            value: q * dense,
        }
    }
}

/// The polynomials of one decomposition unit: dense value, spread value and
/// rotation sums as linear combinations of the pieces.
fn decomposition_polynomials<F: PastaField>(
    q: &mut Queries<'_, '_, '_, F>,
    selector: Selector,
    spec: &DecompositionSpec,
) -> Vec<(String, Expression<F>)> {
    let s = q.selector(selector);
    let mut dense = Vec::new();
    let mut spread = Vec::new();
    let mut rotations: Vec<Vec<Expression<F>>> = vec![Vec::new(); spec.rotations.len()];
    for piece in spec.pieces {
        let (piece_dense, piece_spread) = q.piece(piece);
        dense.push(piece_dense * pow2::<F>(piece.lo));
        if spec.spread_output {
            spread.push(piece_spread.clone() * pow2::<F>(2 * piece.lo));
        }
        for (terms, shifts) in rotations.iter_mut().zip(spec.rotations) {
            let coefficient: u128 = piece
                .rotation_positions(shifts)
                .iter()
                .map(|position| 1_u128 << (2 * position))
                .sum();
            if coefficient != 0 {
                terms.push(piece_spread.clone() * F::from_u128(coefficient));
            }
        }
    }
    let mut polys = vec![(
        "dense".to_owned(),
        s.clone() * (sum(dense) - q.word(SLOT_DENSE)),
    )];
    if spec.spread_output {
        polys.push((
            "spread".to_owned(),
            s.clone() * (sum(spread) - q.word(SLOT_SPREAD)),
        ));
    }
    for (index, terms) in rotations.into_iter().enumerate() {
        let slot = DecompositionSpec::rotation_slot(index);
        polys.push((
            format!("rotation sum {index}"),
            s.clone() * (sum(terms) - q.word(slot)),
        ));
    }
    polys
}

/// An operand of a word gate: an assigned word (copied in) or a constant
/// (assigned from the constants column).
#[derive(Clone, Debug)]
enum Operand<F: PastaField> {
    Cell(Word<F>),
    Constant(u64),
}

/// A SHA-256 word: a constant (initial values, padding) or an assigned cell
/// constrained to `[0, 2^32)`.
#[derive(Clone, Debug)]
pub enum Sha256Word<F: PastaField> {
    /// A circuit constant.
    Constant(u32),
    /// A range-checked cell.
    Assigned(Uint<F, 32>),
}

/// The low 32 bits of `value`.
fn low_u32(value: u128) -> u32 {
    let bytes = value.to_le_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// The low 32 bits and the rest of a sum.
fn split_u64(value: u64) -> (u32, u32) {
    (low_u32(u128::from(value)), low_u32(u128::from(value >> 32)))
}

impl<F: PastaField> Sha256Word<F> {
    /// The word's value (unknown during key generation).
    #[must_use]
    pub fn value(&self) -> Value<u32> {
        match self {
            Self::Constant(word) => Value::known(*word),
            Self::Assigned(cell) => cell.value().map(low_u32),
        }
    }

    fn operand(&self) -> Operand<F> {
        match self {
            Self::Constant(word) => Operand::Constant(u64::from(*word)),
            Self::Assigned(cell) => Operand::Cell(cell.word().clone()),
        }
    }
}

/// Collects the values of `words`.
fn word_values<F: PastaField, const N: usize>(words: &[Sha256Word<F>; N]) -> Value<[u32; N]> {
    let collected: Value<Vec<u32>> = words.iter().map(Sha256Word::value).collect();
    collected.map(|values| {
        let mut out = [0_u32; N];
        out.copy_from_slice(&values);
        out
    })
}

/// A chaining state: eight words.
#[derive(Clone, Debug)]
pub struct Sha256State<F: PastaField> {
    words: [Sha256Word<F>; STATE_WORDS],
}

impl<F: PastaField> Sha256State<F> {
    /// The initial hash value as constants.
    #[must_use]
    pub fn iv() -> Self {
        Self {
            words: SHA256_IV.map(Sha256Word::Constant),
        }
    }

    /// A state from its words `a .. h`.
    #[must_use]
    pub const fn new(words: [Sha256Word<F>; STATE_WORDS]) -> Self {
        Self { words }
    }

    /// The words `a .. h`.
    #[must_use]
    pub const fn words(&self) -> &[Sha256Word<F>; STATE_WORDS] {
        &self.words
    }

    /// The values of the words.
    #[must_use]
    pub fn value(&self) -> Value<[u32; STATE_WORDS]> {
        word_values(&self.words)
    }
}

/// The chaining state after a compression: eight range-checked cells. After
/// the last block it is the digest, whose bytes are the big-endian words in
/// order.
#[derive(Clone, Debug)]
pub struct Sha256Digest<F: PastaField> {
    words: [Uint<F, 32>; STATE_WORDS],
}

impl<F: PastaField> Sha256Digest<F> {
    /// The words `H_0 .. H_7`.
    #[must_use]
    pub const fn words(&self) -> &[Uint<F, 32>; STATE_WORDS] {
        &self.words
    }

    /// The digest bytes (the big-endian words in order).
    #[must_use]
    pub fn value(&self) -> Value<[u8; 32]> {
        self.state()
            .value()
            .map(|words| super::native::state_bytes(&words))
    }

    /// The state for chaining a further block.
    #[must_use]
    pub fn state(&self) -> Sha256State<F> {
        Sha256State {
            words: self.words.clone().map(Sha256Word::Assigned),
        }
    }
}

/// The native values of one compression, in the order the chip lays them
/// out.
#[derive(Clone, Debug)]
struct Trace {
    w: [u32; ROUNDS],
    w_carry: [u32; ROUNDS],
    small0: [(u32, u32); ROUNDS],
    small1: [(u32, u32); ROUNDS],
    big0: [(u32, u32); ROUNDS],
    maj: [(u32, u32); ROUNDS],
    big1: [(u32, u32); ROUNDS],
    ch: [(u32, u32); ROUNDS],
    ch_not: [(u32, u32); ROUNDS],
    t1: [u64; ROUNDS],
    a: [u32; ROUNDS],
    a_carry: [u32; ROUNDS],
    e: [u32; ROUNDS],
    e_carry: [u32; ROUNDS],
    out: [u32; STATE_WORDS],
    out_carry: [u32; STATE_WORDS],
}

impl Trace {
    /// Runs the compression the way the chip constrains it.
    fn new(state: &[u32; STATE_WORDS], block: &[u32; BLOCK_WORDS]) -> Box<Self> {
        let mut trace = Box::new(Self {
            w: [0; ROUNDS],
            w_carry: [0; ROUNDS],
            small0: [(0, 0); ROUNDS],
            small1: [(0, 0); ROUNDS],
            big0: [(0, 0); ROUNDS],
            maj: [(0, 0); ROUNDS],
            big1: [(0, 0); ROUNDS],
            ch: [(0, 0); ROUNDS],
            ch_not: [(0, 0); ROUNDS],
            t1: [0; ROUNDS],
            a: [0; ROUNDS],
            a_carry: [0; ROUNDS],
            e: [0; ROUNDS],
            e_carry: [0; ROUNDS],
            out: [0; STATE_WORDS],
            out_carry: [0; STATE_WORDS],
        });
        trace.w[..BLOCK_WORDS].copy_from_slice(block);
        for t in BLOCK_WORDS..ROUNDS {
            trace.small0[t] = split(small_sigma0_spread_sum(trace.w[t - 15]));
            trace.small1[t] = split(small_sigma1_spread_sum(trace.w[t - 2]));
            let total = u64::from(trace.small1[t].0)
                + u64::from(trace.w[t - 7])
                + u64::from(trace.small0[t].0)
                + u64::from(trace.w[t - 16]);
            (trace.w[t], trace.w_carry[t]) = split_u64(total);
        }
        // a_words[t + 4] = A_t; A_{-1..-4} = a, b, c, d.
        let mut a_words = [0_u32; ROUNDS + 4];
        let mut e_words = [0_u32; ROUNDS + 4];
        a_words[..4].copy_from_slice(&[state[3], state[2], state[1], state[0]]);
        e_words[..4].copy_from_slice(&[state[7], state[6], state[5], state[4]]);
        for t in 0..ROUNDS {
            let [a4, a3, a2, a1] = [a_words[t], a_words[t + 1], a_words[t + 2], a_words[t + 3]];
            let [e4, e3, e2, e1] = [e_words[t], e_words[t + 1], e_words[t + 2], e_words[t + 3]];
            trace.big0[t] = split(big_sigma0_spread_sum(a1));
            trace.maj[t] = split(spread(a1) + spread(a2) + spread(a3));
            trace.big1[t] = split(big_sigma1_spread_sum(e1));
            trace.ch[t] = split(spread(e1) + spread(e2));
            trace.ch_not[t] = split(SPREAD_ONES - spread(e1) + spread(e3));
            trace.t1[t] = u64::from(e4)
                + u64::from(trace.big1[t].0)
                + u64::from(trace.ch[t].1)
                + u64::from(trace.w[t])
                + u64::from(SHA256_K[t]);
            (trace.e[t], trace.e_carry[t]) =
                split_u64(u64::from(a4) + trace.t1[t] + u64::from(trace.ch_not[t].1));
            (trace.a[t], trace.a_carry[t]) = split_u64(
                u64::from(trace.e[t]) + TWO_32 - u64::from(a4)
                    + u64::from(trace.big0[t].0)
                    + u64::from(trace.maj[t].1),
            );
            a_words[t + 4] = trace.a[t];
            e_words[t + 4] = trace.e[t];
        }
        let finals = [
            a_words[ROUNDS + 3],
            a_words[ROUNDS + 2],
            a_words[ROUNDS + 1],
            a_words[ROUNDS],
            e_words[ROUNDS + 3],
            e_words[ROUNDS + 2],
            e_words[ROUNDS + 1],
            e_words[ROUNDS],
        ];
        for index in 0..STATE_WORDS {
            (trace.out[index], trace.out_carry[index]) =
                split_u64(u64::from(state[index]) + u64::from(finals[index]));
        }
        trace
    }
}

/// A laid-out unit: its first row and the word cells assigned so far.
#[derive(Clone, Debug)]
struct Unit<F: PastaField> {
    row: usize,
    words: [Option<Word<F>>; WORD_SLOTS],
}

impl<F: PastaField> Unit<F> {
    /// The word in `slot`.
    fn word(&self, slot: usize) -> Result<&Word<F>, Error> {
        self.words
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(Error::Synthesis)
    }

    /// The word in `slot` as an operand.
    fn operand(&self, slot: usize) -> Result<Operand<F>, Error> {
        self.word(slot).cloned().map(Operand::Cell)
    }
}

/// A compression word with the spread forms a round needs.
#[derive(Clone, Debug)]
struct Lane<F: PastaField> {
    dense: Operand<F>,
    spread: Option<Operand<F>>,
    rotation: Option<Operand<F>>,
}

impl<F: PastaField> Lane<F> {
    fn spread(&self) -> Result<&Operand<F>, Error> {
        self.spread.as_ref().ok_or(Error::Synthesis)
    }

    fn rotation(&self) -> Result<&Operand<F>, Error> {
        self.rotation.as_ref().ok_or(Error::Synthesis)
    }
}

/// A schedule word with its `σ0` and `σ1` spread sums.
#[derive(Clone, Debug)]
struct ScheduleWord<F: PastaField> {
    dense: Operand<F>,
    small0: Option<Operand<F>>,
    small1: Option<Operand<F>>,
}

/// The SHA-256 chip: units allocated from its own row cursor.
#[derive(Clone, Debug)]
pub struct Sha256Chip<F: PastaField> {
    config: Sha256Config,
    rows: RowCursor,
    _marker: PhantomData<F>,
}

impl<F: PastaField> Sha256Chip<F> {
    /// A chip whose first row is 0.
    #[must_use]
    pub const fn new(config: &Sha256Config) -> Self {
        Self::starting_at(config, 0)
    }

    /// A chip whose first row is `row`.
    #[must_use]
    pub const fn starting_at(config: &Sha256Config, row: usize) -> Self {
        Self::with_cursor(config, RowCursor::starting_at(row))
    }

    /// A chip whose units come from `rows` (a bounded cursor keeps them in
    /// a row range other chips do not use).
    #[must_use]
    pub const fn with_cursor(config: &Sha256Config, rows: RowCursor) -> Self {
        Self {
            config: *config,
            rows,
            _marker: PhantomData,
        }
    }

    /// The configuration.
    #[must_use]
    pub const fn config(&self) -> &Sha256Config {
        &self.config
    }

    /// The first row not used yet.
    #[must_use]
    pub const fn next_row(&self) -> usize {
        self.rows.next_row()
    }

    /// Loads the spread table (2,433 rows from the configured start: the
    /// zero row and `(2^33 + w, spread(x), x)` for `w` in 7, 8, 11 and
    /// `x < 2^w`) into fixed columns, in its own region.
    ///
    /// # Errors
    ///
    /// [`Error`] when the table does not fit the usable rows.
    pub fn load_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let table = self.config.table;
        let start = self.config.table_start;
        layouter.assign_region(
            || "sha256 spread table",
            |mut region| {
                for (offset, (width, value, spread_value)) in table_rows().enumerate() {
                    let row = start.checked_add(offset).ok_or(Error::BoundsFailure)?;
                    if width == 0 {
                        // The zero row: every column stays zero.
                        continue;
                    }
                    region.assign_fixed(table.tag, row, F::from(table_tag(width)))?;
                    region.assign_fixed(table.spread, row, F::from(spread_value))?;
                    region.assign_fixed(table.dense, row, F::from(u64::from(value)))?;
                }
                Ok(())
            },
        )
    }

    /// Witnesses a word and range-checks it to 32 bits (one unit).
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn assign_u32(
        &mut self,
        region: &mut Region<'_, F>,
        value: Value<u32>,
    ) -> Result<Uint<F, 32>, Error> {
        let unit = self.decompose(region, SPEC_HALF, value)?;
        Ok(Uint::new(unit.word(SLOT_DENSE)?.clone()))
    }

    /// Range-checks a copy of `word` to 32 bits (one unit) and returns it.
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn range_check_u32(
        &mut self,
        region: &mut Region<'_, F>,
        word: &Word<F>,
    ) -> Result<Uint<F, 32>, Error> {
        let unit = self.decompose_word(region, SPEC_HALF, word)?;
        Ok(Uint::new(unit.word(SLOT_DENSE)?.clone()))
    }

    /// The rows [`Self::compress`] uses for `state` and `block`.
    #[must_use]
    pub fn compress_rows(state: &Sha256State<F>, block: &[Sha256Word<F>; BLOCK_WORDS]) -> usize {
        let assigned = |word: &Sha256Word<F>| matches!(word, Sha256Word::Assigned(_));
        let state_units = [0, 1, 2, 4, 5, 6]
            .iter()
            .filter(|index| assigned(&state.words[**index]))
            .count();
        let message_units = block[1..].iter().filter(|word| assigned(word)).count();
        UNIT_ROWS * (state_units + message_units)
            + (ROUNDS - BLOCK_WORDS) * SCHEDULE_ROWS
            + ROUNDS * ROUND_ROWS
            + FEED_FORWARD_ROWS
    }

    /// One SHA-256 compression of `block` from `state`.
    ///
    /// Constant words cost nothing; every assigned message word `W_1 ..
    /// W_15` and every assigned state word `a, b, c, e, f, g` costs one
    /// decomposition unit; the rest is fixed (see [`Self::compress_rows`]).
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn compress(
        &mut self,
        region: &mut Region<'_, F>,
        state: &Sha256State<F>,
        block: &[Sha256Word<F>; BLOCK_WORDS],
    ) -> Result<Sha256Digest<F>, Error> {
        let trace = state
            .value()
            .zip(word_values(block))
            .map(|(state, block)| Trace::new(&state, &block));
        let mut a_lanes = Vec::with_capacity(ROUNDS + 4);
        let mut e_lanes = Vec::with_capacity(ROUNDS + 4);
        for (lanes, spec, indices) in [
            (&mut a_lanes, SPEC_A, [3, 2, 1, 0]),
            (&mut e_lanes, SPEC_E, [7, 6, 5, 4]),
        ] {
            for (position, index) in indices.into_iter().enumerate() {
                let lane = self.initial_lane(region, spec, &state.words[index], position > 0)?;
                lanes.push(lane);
            }
        }
        let schedule = self.schedule(region, block, &trace)?;
        for t in 0..ROUNDS {
            let (a, e) = self.round(
                region,
                t,
                &a_lanes[t..t + 4],
                &e_lanes[t..t + 4],
                &schedule[t],
                &trace,
            )?;
            a_lanes.push(a);
            e_lanes.push(e);
        }
        let finals = [
            &a_lanes[ROUNDS + 3],
            &a_lanes[ROUNDS + 2],
            &a_lanes[ROUNDS + 1],
            &a_lanes[ROUNDS],
            &e_lanes[ROUNDS + 3],
            &e_lanes[ROUNDS + 2],
            &e_lanes[ROUNDS + 1],
            &e_lanes[ROUNDS],
        ];
        let mut out = Vec::with_capacity(STATE_WORDS);
        for (index, last) in finals.into_iter().enumerate() {
            let unit = self.decompose(region, SPEC_HALF, trace.as_ref().map(|t| t.out[index]))?;
            self.config.q_feed.enable(region, unit.row)?;
            self.put(region, unit.row, 2, &state.words[index].operand())?;
            self.put(region, unit.row, 3, &last.dense)?;
            self.carry(
                region,
                unit.row,
                4,
                trace.as_ref().map(|t| t.out_carry[index]),
            )?;
            out.push(Uint::new(unit.word(SLOT_DENSE)?.clone()));
        }
        let words: [Uint<F, 32>; STATE_WORDS] = out.try_into().map_err(|_| Error::Synthesis)?;
        Ok(Sha256Digest { words })
    }

    /// The single padded block of the 32-byte canonical (little-endian)
    /// encoding of a digest `m` of the field `D`, held by `digest` as the
    /// integer `m`: eight big-endian message words, then the constant
    /// padding.
    ///
    /// The bytes are constrained to recompose `digest` and to encode an
    /// integer below the modulus of `D` (a borrow chain over 32-bit limbs
    /// proves `(|D| - 1) - m >= 0`), so the block is unique: `m + |F|`
    /// cannot be passed for `m`.
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] when `|D| > |F|` (a value of `D` would not fit a
    /// cell of `F`), and [`Error`] from the layout.
    pub fn digest_block<D: PastaField>(
        &mut self,
        region: &mut Region<'_, F>,
        digest: &Word<F>,
    ) -> Result<[Sha256Word<F>; BLOCK_WORDS], Error> {
        let modulus = canonical_u32_limbs(&-D::ONE);
        if compare_limbs(&modulus, &canonical_u32_limbs(&-F::ONE)) == Ordering::Greater {
            return Err(Error::Synthesis);
        }
        let bytes = digest.value().map(|value| digest_message(&value));
        self.digest_block_with_bytes(region, digest, &modulus, bytes)
    }

    /// [`Self::digest_block`] with the message bytes supplied by the caller
    /// (tests force non-canonical encodings through it).
    pub(super) fn digest_block_with_bytes(
        &mut self,
        region: &mut Region<'_, F>,
        digest: &Word<F>,
        modulus: &[u32; 8],
        bytes: Value<[u8; 32]>,
    ) -> Result<[Sha256Word<F>; BLOCK_WORDS], Error> {
        let mut words = Vec::with_capacity(8);
        let mut limbs = Vec::with_capacity(8);
        for word in 0..8 {
            let first = self.bytes_unit(region, bytes.map(|b| (b[4 * word], b[4 * word + 1])))?;
            let second =
                self.bytes_unit(region, bytes.map(|b| (b[4 * word + 2], b[4 * word + 3])))?;
            self.config.q_bytes_join.enable(region, second.row)?;
            self.put(region, second.row, 2, &first.operand(0)?)?;
            self.put(region, second.row, 3, &first.operand(1)?)?;
            let chunk = bytes.map(|b| {
                [
                    b[4 * word],
                    b[4 * word + 1],
                    b[4 * word + 2],
                    b[4 * word + 3],
                ]
            });
            let be = self.fresh(
                region,
                second.row,
                4,
                chunk.map(|c| F::from(u64::from(u32::from_be_bytes(c)))),
            )?;
            let le = self.fresh(
                region,
                second.row,
                5,
                chunk.map(|c| F::from(u64::from(u32::from_le_bytes(c)))),
            )?;
            words.push(Sha256Word::Assigned(Uint::new(be)));
            limbs.push(le);
        }
        let limb_values = bytes.map(|b| {
            let mut out = [0_u32; 8];
            for (limb, chunk) in out.iter_mut().zip(b.chunks_exact(4)) {
                *limb = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
            out
        });
        // c_j = p_j - l_j - borrow_j mod 2^32, borrow_{j+1} = [p_j < l_j + borrow_j].
        let chain = limb_values.map(|l| {
            let mut c = [0_u32; 8];
            let mut borrows = [0_u32; 9];
            for j in 0..8 {
                let need = u64::from(l[j]) + u64::from(borrows[j]);
                let have = u64::from(modulus[j]);
                borrows[j + 1] = u32::from(have < need);
                c[j] = low_u32(u128::from(have + (u64::from(borrows[j + 1]) << 32) - need));
            }
            (c, borrows)
        });
        let mut units = Vec::with_capacity(8);
        let mut borrows_out = Vec::with_capacity(8);
        let mut accumulators = Vec::with_capacity(8);
        let accumulator_values = limb_values.map(|l| {
            let mut acc = [F::ZERO; 9];
            for j in (0..8).rev() {
                acc[j] = acc[j + 1] * F::from(TWO_32) + F::from(u64::from(l[j]));
            }
            acc
        });
        for j in 0..8 {
            let unit = self.decompose(region, SPEC_HALF, chain.map(|(c, _)| c[j]))?;
            self.config.q_borrow.enable(region, unit.row)?;
            region.assign_fixed(
                self.config.constant,
                unit.row,
                F::from(u64::from(modulus[j])),
            )?;
            self.put(region, unit.row, 2, &Operand::Cell(limbs[j].clone()))?;
            borrows_out.push(self.fresh(
                region,
                unit.row,
                4,
                chain.map(|(_, borrows)| F::from(u64::from(borrows[j + 1]))),
            )?);
            accumulators.push(self.fresh(
                region,
                unit.row,
                6,
                accumulator_values.map(|acc| acc[j]),
            )?);
            units.push(unit);
        }
        for (j, unit) in units.iter().enumerate() {
            let borrow_in = if j == 0 {
                Operand::Constant(0)
            } else {
                Operand::Cell(borrows_out[j - 1].clone())
            };
            let accumulator_in = accumulators
                .get(j + 1)
                .map_or(Operand::Constant(0), |word| Operand::Cell(word.clone()));
            self.put(region, unit.row, 3, &borrow_in)?;
            self.put(region, unit.row, 5, &accumulator_in)?;
        }
        let last_borrow = borrows_out.last().ok_or(Error::Synthesis)?;
        region.constrain_constant(last_borrow.cell(), F::ZERO)?;
        let total = accumulators.first().ok_or(Error::Synthesis)?;
        region.constrain_equal(total.cell(), digest.cell())?;
        words.extend(DIGEST_PADDING.map(Sha256Word::Constant));
        words.try_into().map_err(|_| Error::Synthesis)
    }

    /// SHA-256 of the 32-byte canonical encoding of the digest held by
    /// `digest` (a value of `D`): [`Self::digest_block`], then one
    /// [`Self::compress`] from the initial hash value.
    ///
    /// # Errors
    ///
    /// As [`Self::digest_block`] and [`Self::compress`].
    pub fn hash_digest<D: PastaField>(
        &mut self,
        region: &mut Region<'_, F>,
        digest: &Word<F>,
    ) -> Result<Sha256Digest<F>, Error> {
        let block = self.digest_block::<D>(region, digest)?;
        self.compress(region, &Sha256State::iv(), &block)
    }

    // ----- units -----

    /// Lays out one lookup row.
    fn lookup(
        &self,
        region: &mut Region<'_, F>,
        row: usize,
        tag: u32,
        value: Value<u32>,
    ) -> Result<(), Error> {
        self.config.q_lookup.enable(region, row)?;
        region.assign_fixed(self.config.tag, row, F::from(table_tag(tag)))?;
        region.assign_advice(self.config.dense, row, value.map(|x| F::from(u64::from(x))))?;
        region.assign_advice(self.config.spread, row, value.map(|x| F::from(spread(x))))?;
        Ok(())
    }

    /// Assigns bit slot `slot` of the unit at `row`.
    fn bit(
        &self,
        region: &mut Region<'_, F>,
        row: usize,
        slot: usize,
        value: Value<u32>,
    ) -> Result<(), Error> {
        if slot >= BIT_SLOTS {
            return Err(Error::Synthesis);
        }
        region.assign_advice(
            self.config.bits[slot % BIT_COLUMNS],
            row + slot / BIT_COLUMNS,
            value.map(|bit| F::from(u64::from(bit))),
        )?;
        Ok(())
    }

    /// Assigns a carry (a small integer) in word slot `slot`.
    fn carry(
        &self,
        region: &mut Region<'_, F>,
        row: usize,
        slot: usize,
        value: Value<u32>,
    ) -> Result<Word<F>, Error> {
        self.fresh(
            region,
            row,
            slot,
            value.map(|carry| F::from(u64::from(carry))),
        )
    }

    /// The column and row of word slot `slot` of the unit at `row`.
    fn slot(&self, row: usize, slot: usize) -> Result<(Column<Advice>, usize), Error> {
        if slot >= WORD_SLOTS {
            return Err(Error::Synthesis);
        }
        Ok((
            self.config.words[slot % WORD_COLUMNS],
            row + slot / WORD_COLUMNS,
        ))
    }

    /// Assigns a new word in slot `slot`.
    fn fresh(
        &self,
        region: &mut Region<'_, F>,
        row: usize,
        slot: usize,
        value: Value<F>,
    ) -> Result<Word<F>, Error> {
        let (column, row) = self.slot(row, slot)?;
        assign_word(region, column, row, value)
    }

    /// Places `operand` in slot `slot`: a copy of a word or a constant.
    fn put(
        &self,
        region: &mut Region<'_, F>,
        row: usize,
        slot: usize,
        operand: &Operand<F>,
    ) -> Result<Word<F>, Error> {
        let (column, row) = self.slot(row, slot)?;
        match operand {
            Operand::Cell(word) => copy_word(region, word, column, row),
            Operand::Constant(value) => assign_constant(region, column, row, F::from(*value)),
        }
    }

    /// Lays out a decomposition unit of `value` with spec `SPECS[index]`.
    fn decompose(
        &mut self,
        region: &mut Region<'_, F>,
        index: usize,
        value: Value<u32>,
    ) -> Result<Unit<F>, Error> {
        let spec = SPECS.get(index).ok_or(Error::Synthesis)?;
        let row = self.rows.take(UNIT_ROWS)?;
        self.config.q_decompose[index].enable(region, row)?;
        for offset in 0..UNIT_ROWS {
            self.config.q_bool.enable(region, row + offset)?;
        }
        for piece in spec.pieces {
            let piece_value = value.map(|word| piece.of(word));
            match piece.cells {
                PieceCells::Lookup { row: offset, tag } => {
                    self.lookup(region, row + offset, tag, piece_value)?;
                }
                PieceCells::Bits { first } => {
                    for k in 0..piece.width {
                        self.bit(
                            region,
                            row,
                            first + k as usize,
                            piece_value.map(|p| (p >> k) & 1),
                        )?;
                    }
                }
            }
        }
        let mut words: [Option<Word<F>>; WORD_SLOTS] = Default::default();
        words[SLOT_DENSE] = Some(self.fresh(
            region,
            row,
            SLOT_DENSE,
            value.map(|w| F::from(u64::from(w))),
        )?);
        if spec.spread_output {
            words[SLOT_SPREAD] =
                Some(self.fresh(region, row, SLOT_SPREAD, value.map(|w| F::from(spread(w))))?);
        }
        for rotation in 0..spec.rotations.len() {
            let slot = DecompositionSpec::rotation_slot(rotation);
            words[slot] = Some(self.fresh(
                region,
                row,
                slot,
                value.map(|w| F::from(spec.rotation_sum(rotation, w))),
            )?);
        }
        Ok(Unit { row, words })
    }

    /// Decomposes the value of `word` and binds the unit's dense cell to it.
    fn decompose_word(
        &mut self,
        region: &mut Region<'_, F>,
        index: usize,
        word: &Word<F>,
    ) -> Result<Unit<F>, Error> {
        let value = word
            .value()
            .map(|value| low_u32(crate::cells::low_u128(&value)));
        let unit = self.decompose(region, index, value)?;
        region.constrain_equal(unit.word(SLOT_DENSE)?.cell(), word.cell())?;
        Ok(unit)
    }

    /// Lays out a byte unit: bytes `(high, low)` looked up with tag 8, the
    /// big-endian pair in slot 0 and the little-endian pair in slot 1.
    fn bytes_unit(
        &mut self,
        region: &mut Region<'_, F>,
        pair: Value<(u8, u8)>,
    ) -> Result<Unit<F>, Error> {
        let row = self.rows.take(UNIT_ROWS)?;
        self.config.q_bytes.enable(region, row)?;
        self.lookup(region, row, 8, pair.map(|(high, _)| u32::from(high)))?;
        self.lookup(region, row + 1, 8, pair.map(|(_, low)| u32::from(low)))?;
        let mut words: [Option<Word<F>>; WORD_SLOTS] = Default::default();
        words[0] = Some(self.fresh(
            region,
            row,
            0,
            pair.map(|(high, low)| F::from(u64::from(u16::from_be_bytes([high, low])))),
        )?);
        words[1] = Some(self.fresh(
            region,
            row,
            1,
            pair.map(|(high, low)| F::from(u64::from(u16::from_le_bytes([high, low])))),
        )?);
        Ok(Unit { row, words })
    }

    /// Lays out an even/odd split: two half units, the odd one hosting
    /// `selector` with the even spread copied to slot 2 and `inputs` in
    /// slots 3, 4, 5.
    fn split(
        &mut self,
        region: &mut Region<'_, F>,
        halves: Value<(u32, u32)>,
        selector: Selector,
        inputs: &[&Operand<F>],
    ) -> Result<(Unit<F>, Unit<F>), Error> {
        let even = self.decompose(region, SPEC_HALF, halves.map(|(even, _)| even))?;
        let odd = self.decompose(region, SPEC_HALF, halves.map(|(_, odd)| odd))?;
        selector.enable(region, odd.row)?;
        self.put(region, odd.row, SLOT_EVEN, &even.operand(SLOT_SPREAD)?)?;
        for (offset, input) in inputs.iter().enumerate() {
            self.put(region, odd.row, SLOT_INPUT + offset, input)?;
        }
        Ok((even, odd))
    }

    /// The lane of an initial state word: dense only for `d` and `h`
    /// (`with_spread` false), constants for a constant word, otherwise a
    /// decomposition unit bound to the word.
    fn initial_lane(
        &mut self,
        region: &mut Region<'_, F>,
        spec: usize,
        word: &Sha256Word<F>,
        with_spread: bool,
    ) -> Result<Lane<F>, Error> {
        let rotation_sum = |value: u32| {
            if spec == SPEC_A {
                big_sigma0_spread_sum(value)
            } else {
                big_sigma1_spread_sum(value)
            }
        };
        Ok(match (word, with_spread) {
            (_, false) => Lane {
                dense: word.operand(),
                spread: None,
                rotation: None,
            },
            (Sha256Word::Constant(value), true) => Lane {
                dense: Operand::Constant(u64::from(*value)),
                spread: Some(Operand::Constant(spread(*value))),
                rotation: Some(Operand::Constant(rotation_sum(*value))),
            },
            (Sha256Word::Assigned(cell), true) => {
                let unit = self.decompose_word(region, spec, cell.word())?;
                Lane {
                    dense: Operand::Cell(cell.word().clone()),
                    spread: Some(unit.operand(SLOT_SPREAD)?),
                    rotation: Some(unit.operand(2)?),
                }
            }
        })
    }

    /// The message schedule `W_0 .. W_63` with the spread sums the
    /// schedule reads.
    fn schedule(
        &mut self,
        region: &mut Region<'_, F>,
        block: &[Sha256Word<F>; BLOCK_WORDS],
        trace: &Value<Box<Trace>>,
    ) -> Result<Vec<ScheduleWord<F>>, Error> {
        let mut words: Vec<ScheduleWord<F>> = Vec::with_capacity(ROUNDS);
        for (t, word) in block.iter().enumerate() {
            words.push(match word {
                Sha256Word::Constant(value) => ScheduleWord {
                    dense: Operand::Constant(u64::from(*value)),
                    small0: Some(Operand::Constant(small_sigma0_spread_sum(*value))),
                    small1: Some(Operand::Constant(small_sigma1_spread_sum(*value))),
                },
                // W_0 only enters additions; its spread sums are never read.
                Sha256Word::Assigned(cell) if t == 0 => ScheduleWord {
                    dense: Operand::Cell(cell.word().clone()),
                    small0: None,
                    small1: None,
                },
                Sha256Word::Assigned(cell) => {
                    let unit = self.decompose_word(region, SPEC_W, cell.word())?;
                    ScheduleWord {
                        dense: Operand::Cell(cell.word().clone()),
                        small0: Some(unit.operand(2)?),
                        small1: Some(unit.operand(3)?),
                    }
                }
            });
        }
        for t in BLOCK_WORDS..ROUNDS {
            let small0_input = words[t - 15].small0.clone().ok_or(Error::Synthesis)?;
            let small1_input = words[t - 2].small1.clone().ok_or(Error::Synthesis)?;
            let (small0, _) = self.split(
                region,
                trace.as_ref().map(|trace| trace.small0[t]),
                self.config.q_split,
                &[&small0_input],
            )?;
            let (small1, _) = self.split(
                region,
                trace.as_ref().map(|trace| trace.small1[t]),
                self.config.q_split,
                &[&small1_input],
            )?;
            let unit = self.decompose(region, SPEC_W, trace.as_ref().map(|trace| trace.w[t]))?;
            self.config.q_add_w.enable(region, small1.row)?;
            self.put(region, small1.row, 2, &unit.operand(SLOT_DENSE)?)?;
            self.put(region, small1.row, 3, &small0.operand(SLOT_DENSE)?)?;
            self.put(region, small1.row, 4, &words[t - 7].dense)?;
            self.put(region, small1.row, 5, &words[t - 16].dense)?;
            self.carry(
                region,
                small1.row,
                6,
                trace.as_ref().map(|trace| trace.w_carry[t]),
            )?;
            words.push(ScheduleWord {
                dense: unit.operand(SLOT_DENSE)?,
                small0: Some(unit.operand(2)?),
                small1: Some(unit.operand(3)?),
            });
        }
        Ok(words)
    }

    /// Round `t`: `a` and `e` hold `A_{t-4} .. A_{t-1}` and `E_{t-4} ..
    /// E_{t-1}`; returns the lanes of `A_t` and `E_t`.
    fn round(
        &mut self,
        region: &mut Region<'_, F>,
        t: usize,
        a: &[Lane<F>],
        e: &[Lane<F>],
        w: &ScheduleWord<F>,
        trace: &Value<Box<Trace>>,
    ) -> Result<(Lane<F>, Lane<F>), Error> {
        let [a4, a3, a2, a1] = [&a[0], &a[1], &a[2], &a[3]];
        let [e4, e3, e2, e1] = [&e[0], &e[1], &e[2], &e[3]];
        let config = self.config;
        let (big0, _) = self.split(
            region,
            trace.as_ref().map(|tr| tr.big0[t]),
            config.q_split,
            &[a1.rotation()?],
        )?;
        let (_, maj) = self.split(
            region,
            trace.as_ref().map(|tr| tr.maj[t]),
            config.q_split_maj,
            &[a1.spread()?, a2.spread()?, a3.spread()?],
        )?;
        let (big1, _) = self.split(
            region,
            trace.as_ref().map(|tr| tr.big1[t]),
            config.q_split,
            &[e1.rotation()?],
        )?;
        let (ch_even, ch) = self.split(
            region,
            trace.as_ref().map(|tr| tr.ch[t]),
            config.q_split_ch,
            &[e1.spread()?, e2.spread()?],
        )?;
        let (ch_not, ch_not_odd) = self.split(
            region,
            trace.as_ref().map(|tr| tr.ch_not[t]),
            config.q_split_ch_not,
            &[e1.spread()?, e3.spread()?],
        )?;
        // T1 = h + Σ1 + Ch_p + W_t + K_t on the Ch even unit.
        config.q_t1.enable(region, ch_even.row)?;
        region.assign_fixed(
            config.constant,
            ch_even.row,
            F::from(u64::from(SHA256_K[t])),
        )?;
        self.put(region, ch_even.row, 2, &e4.dense)?;
        self.put(region, ch_even.row, 3, &big1.operand(SLOT_DENSE)?)?;
        self.put(region, ch_even.row, 4, &ch.operand(SLOT_DENSE)?)?;
        self.put(region, ch_even.row, 5, &w.dense)?;
        let t1 = self.fresh(
            region,
            ch_even.row,
            6,
            trace.as_ref().map(|tr| F::from(tr.t1[t])),
        )?;
        // E_t + 2^32 carry = d + T1 + Ch_q on the Ch-not even unit.
        let e_unit = self.decompose(region, SPEC_E, trace.as_ref().map(|tr| tr.e[t]))?;
        config.q_add_e.enable(region, ch_not.row)?;
        self.put(region, ch_not.row, 2, &e_unit.operand(SLOT_DENSE)?)?;
        self.put(region, ch_not.row, 3, &a4.dense)?;
        self.put(region, ch_not.row, 4, &Operand::Cell(t1))?;
        self.put(region, ch_not.row, 5, &ch_not_odd.operand(SLOT_DENSE)?)?;
        let e_carry = trace.as_ref().map(|tr| tr.e_carry[t]);
        self.carry(region, ch_not.row, 6, e_carry.map(|carry| carry & 3))?;
        self.carry(region, ch_not.row, 7, e_carry.map(|carry| carry >> 2))?;
        // A_t + 2^32 carry = E_t - d + Σ0 + Maj + 2^32 on the A unit.
        let a_unit = self.decompose(region, SPEC_A, trace.as_ref().map(|tr| tr.a[t]))?;
        config.q_add_a.enable(region, a_unit.row)?;
        self.put(region, a_unit.row, 3, &e_unit.operand(SLOT_DENSE)?)?;
        self.put(region, a_unit.row, 4, &a4.dense)?;
        self.put(region, a_unit.row, 5, &big0.operand(SLOT_DENSE)?)?;
        self.put(region, a_unit.row, 6, &maj.operand(SLOT_DENSE)?)?;
        self.carry(
            region,
            a_unit.row,
            7,
            trace.as_ref().map(|tr| tr.a_carry[t]),
        )?;
        let lane = |unit: &Unit<F>| -> Result<Lane<F>, Error> {
            Ok(Lane {
                dense: unit.operand(SLOT_DENSE)?,
                spread: Some(unit.operand(SLOT_SPREAD)?),
                rotation: Some(unit.operand(2)?),
            })
        };
        Ok((lane(&a_unit)?, lane(&e_unit)?))
    }
}

/// Compares two little-endian limb vectors as integers.
fn compare_limbs(left: &[u32; 8], right: &[u32; 8]) -> Ordering {
    left.iter().rev().cmp(right.iter().rev())
}

impl<F: PastaField> Sha256Chip<F> {
    /// Test hook: a decomposition unit of an arbitrary value; returns its
    /// word cells by slot.
    #[cfg(test)]
    pub(super) fn test_decompose(
        &mut self,
        region: &mut Region<'_, F>,
        spec: &DecompositionSpec,
        value: Value<u32>,
    ) -> Result<Vec<Option<Word<F>>>, Error> {
        let index = SPECS
            .iter()
            .position(|candidate| candidate == spec)
            .ok_or(Error::Synthesis)?;
        Ok(self.decompose(region, index, value)?.words.to_vec())
    }

    /// Test hook: a single-input split with explicit halves; returns the
    /// even and odd dense cells.
    #[cfg(test)]
    pub(super) fn test_split(
        &mut self,
        region: &mut Region<'_, F>,
        halves: Value<(u32, u32)>,
        input: &Word<F>,
    ) -> Result<(Word<F>, Word<F>), Error> {
        let selector = self.config.q_split;
        let (even, odd) = self.split(region, halves, selector, &[&Operand::Cell(input.clone())])?;
        Ok((
            even.word(SLOT_DENSE)?.clone(),
            odd.word(SLOT_DENSE)?.clone(),
        ))
    }
}
