//! Running-sum range checks against a `2^b`-row lookup table (port of the
//! M8 `U128Circuit` decomposition).
//!
//! # Relation
//!
//! A check that `v < 2^bits` with `b`-bit limbs uses `L = ceil(bits / b)`
//! limbs and the running sum `z_i = floor(v / 2^(b i))` in one
//! equality-enabled advice column, one row per `z_i`:
//!
//! - rows `0 .. L-1` (`q_step`): `z_i - 2^b z_{i+1}` (limb `i`) is in the
//!   table, i.e. in `[0, 2^b)`;
//! - row `L-1` (`q_limb`): `z_{L-1}` (the top limb) is in the table;
//! - when the top limb has `t = bits - (L-1) b < b` bits, one more row
//!   (`q_limb` and `q_shift`) holds `z_{L-1} 2^(b-t)`, which must also be in
//!   the table, so `z_{L-1} < 2^t`.
//!
//! Then `v = z_0 = sum_i limb_i 2^(b i) < 2^(b(L-1)) 2^t = 2^bits` as an
//! integer: every partial sum stays below `2^bits <= 2^252 < p`, so nothing
//! wraps. An out-of-range witness has no satisfying assignment; the chip
//! still lays out `floor(v / 2^(b i))`, which a table lookup rejects.
//!
//! The lookup input is `q_step (z - 2^b z_next) + q_limb z` (degree 2, so the
//! lookup needs degree 5) and the shift gate is
//! `q_shift (z - z_prev shift)` (degree 3) with the factor `2^(b-t)` in a
//! fixed column, so one chip checks any width. The column is queried at
//! rotations `-1, 0, 1`, inside the default blinding budget.
//!
//! A check takes `L + [t < b]` rows: 10 for 128 bits at `b = 15`, 16 at
//! `b = 9` (M8 inventory).

use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use iroha_pasta::PastaField;
use iroha_plonk::{
    cs::{Advice, Column, ConstraintSystem, Expression, Fixed, Rotation, Selector, TableColumn},
    frontend::{Cell, Error, Layouter, Region, Value},
};

use crate::cells::{RowCursor, SharedRows, Word, assign_word, copy_word};

#[cfg(test)]
#[path = "tagged_tests.rs"]
mod tagged_tests;

/// The widest value a range check accepts (`2^252 < p` for both fields).
pub const MAX_RANGE_BITS: usize = 252;

/// The limb width `b` of a running-sum chip, `1 <= b <= 24`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LimbBits(usize);

impl LimbBits {
    /// The widest supported limb (a `2^24`-row table).
    pub const MAX: usize = 24;

    /// `bits`, when it is in `1..=24`.
    #[must_use]
    pub const fn new(bits: usize) -> Option<Self> {
        if bits >= 1 && bits <= Self::MAX {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// The widest limb whose table fits a circuit of `2^k` rows: `k - 1`
    /// (the M8 choice), when that is a valid width.
    #[must_use]
    pub const fn for_k(k: u32) -> Option<Self> {
        if k < 2 {
            return None;
        }
        Self::new((k - 1) as usize)
    }

    /// The width.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }

    /// The table size `2^b`.
    #[must_use]
    pub const fn table_rows(self) -> usize {
        1 << self.0
    }
}

/// The shape of one range check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeShape {
    /// The checked width.
    pub bits: usize,
    /// The limb width `b`.
    pub limb_bits: usize,
    /// The number of limbs `L = ceil(bits / b)`.
    pub limbs: usize,
    /// The width `t` of the top limb (`1..=b`).
    pub top_bits: usize,
    /// Rows: ordinary layouts use `L + [t < b]`; the exact tagged layout uses `L`.
    pub rows: usize,
}

impl RangeShape {
    /// The shape of a `bits`-bit check with `limb_bits` limbs, for
    /// `1 <= bits <= 252`.
    #[must_use]
    pub const fn new(bits: usize, limb_bits: LimbBits) -> Option<Self> {
        if bits == 0 || bits > MAX_RANGE_BITS {
            return None;
        }
        let b = limb_bits.get();
        let limbs = bits.div_ceil(b);
        let top_bits = bits - (limbs - 1) * b;
        let rows = if top_bits < b { limbs + 1 } else { limbs };
        Some(Self {
            bits,
            limb_bits: b,
            limbs,
            top_bits,
            rows,
        })
    }

    /// Whether the check has a shifted top-limb row.
    #[must_use]
    pub const fn shifted(&self) -> bool {
        self.rows > self.limbs
    }
}

/// Columns, table and selectors of the running-sum chip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunningSumConfig {
    z: Column<Advice>,
    table: TableColumn,
    shift: Column<Fixed>,
    pattern: Pattern,
    limb_bits: LimbBits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pattern {
    Selectors {
        step: Selector,
        limb: Selector,
        shift: Selector,
    },
    Fixed {
        step: Column<Fixed>,
    },
    Tagged {
        step: Column<Fixed>,
        tag_table: TableColumn,
    },
}

impl RunningSumConfig {
    /// One tuple lookup authenticates `(width, limb)` against exact-width
    /// subsets for widths `3..=15`. The table requires at least 65,528 usable
    /// rows. Top widths one and two use algebraic checks.
    /// Every check uses exactly `ceil(bits/15)` running-sum rows.
    ///
    /// The two fixed pattern columns have five codes: idle zero, step one,
    /// tagged top two, one-bit top three, and two-bit top four. On a tagged top
    /// the second column contains its exact width. An overlay may use that
    /// column only when the pattern is zero, and must disable all four active
    /// codes. A scalar union of offset intervals is deliberately not used:
    /// the tuple's tag prevents cross-width aliases.
    pub fn configure_tagged<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        z: Column<Advice>,
    ) -> Self {
        let table = meta.lookup_table_column();
        let tag_table = meta.lookup_table_column();
        Self::configure_tagged_on(meta, z, table, tag_table)
    }

    /// Independent exact-width tuple lookups sharing one `(width,value)`
    /// table. Each bus authenticates one value, with its own fixed pattern.
    /// The empty list configures no table. A nonempty bank needs at least
    /// 65,528 usable rows, just as [`Self::configure_tagged`].
    pub fn configure_tagged_bank<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        columns: &[Column<Advice>],
    ) -> Vec<Self> {
        if columns.is_empty() {
            return Vec::new();
        }
        let table = meta.lookup_table_column();
        let tag_table = meta.lookup_table_column();
        columns
            .iter()
            .map(|z| Self::configure_tagged_on(meta, *z, table, tag_table))
            .collect()
    }

    fn configure_tagged_on<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        z: Column<Advice>,
        table: TableColumn,
        tag_table: TableColumn,
    ) -> Self {
        meta.enable_equality(z);
        let shift = meta.fixed_column();
        let step = meta.fixed_column();
        let indicator = |pattern: Expression<F>, code: u64| {
            let mut expression = Expression::Constant(F::ONE);
            let mut denominator = F::ONE;
            for other in 0..=4 {
                if other != code {
                    expression =
                        expression * (pattern.clone() - Expression::Constant(F::from(other)));
                    denominator *= F::from(code) - F::from(other);
                }
            }
            expression * denominator.invert().expect("distinct fixed pattern codes")
        };
        meta.lookup("exact tagged running-sum limb", |cells| {
            let pattern = cells.query_fixed(step, Rotation::cur());
            let active = indicator(pattern.clone(), 1);
            let top = indicator(pattern, 2);
            let width = cells.query_fixed(shift, Rotation::cur());
            let cur = cells.query_advice(z, Rotation::cur());
            let next = cells.query_advice(z, Rotation::next());
            let tag = Expression::Constant(F::from(15))
                + top.clone() * (width - Expression::Constant(F::from(15)));
            let value = active * (cur.clone() - next * F::from(1 << 15)) + top * cur;
            vec![(tag, tag_table), (value, table)]
        });
        meta.create_gate("algebraic narrow tagged top", |cells| {
            let pattern = cells.query_fixed(step, Rotation::cur());
            let value = cells.query_advice(z, Rotation::cur());
            let binary = value.clone() * (value.clone() - Expression::Constant(F::ONE));
            vec![
                indicator(pattern.clone(), 3) * binary.clone(),
                indicator(pattern, 4)
                    * binary
                    * (value.clone() - Expression::Constant(F::from(2)))
                    * (value - Expression::Constant(F::from(3))),
            ]
        });
        Self {
            z,
            table,
            shift,
            pattern: Pattern::Tagged { step, tag_table },
            limb_bits: LimbBits::new(15).expect("fixed limb width"),
        }
    }
    /// Configures the chip on `z` (made equality-enabled) with a new table
    /// column of `2^b` rows.
    pub fn configure<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        z: Column<Advice>,
        limb_bits: LimbBits,
    ) -> Self {
        meta.enable_equality(z);
        let table = meta.lookup_table_column();
        let shift = meta.fixed_column();
        let q_step = meta.complex_selector();
        let q_limb = meta.complex_selector();
        let q_shift = meta.selector();
        let radix = F::from(1_u64 << limb_bits.get());
        meta.lookup("running-sum limb", |cells| {
            let step = cells.query_selector(q_step);
            let limb = cells.query_selector(q_limb);
            let cur = cells.query_advice(z, Rotation::cur());
            let next = cells.query_advice(z, Rotation::next());
            vec![(step * (cur.clone() - next * radix) + limb * cur, table)]
        });
        meta.create_gate("running-sum shifted top limb", |cells| {
            let q = cells.query_selector(q_shift);
            let cur = cells.query_advice(z, Rotation::cur());
            let prev = cells.query_advice(z, Rotation::prev());
            let factor = cells.query_fixed(shift, Rotation::cur());
            vec![("z - z_prev shift", q * (cur - prev * factor))]
        });
        Self {
            z,
            table,
            shift,
            pattern: Pattern::Selectors {
                step: q_step,
                limb: q_limb,
                shift: q_shift,
            },
            limb_bits,
        }
    }

    /// Configures a dedicated range bus with two fixed pattern columns.
    /// A ternary fixed pattern is one on running-sum steps, two on top and
    /// shifted-top rows, and zero elsewhere. Its two indicator polynomials
    /// enable the same step/top expressions as the ordinary layout, including
    /// a fully disabled input on idle rows. A nonzero shift factor enables
    /// `pattern*factor*(z - factor*z_prev)=0`, retaining both top-limb
    /// memberships. On idle rows the factor column may carry another
    /// circuit-fixed pattern, provided that consumer is disabled on range rows.
    /// This replaces three selectors and a shift column without dropping any
    /// range premise. Lookup inputs have degree three (argument degree six).
    pub fn configure_compact<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        z: Column<Advice>,
        limb_bits: LimbBits,
    ) -> Self {
        let table = meta.lookup_table_column();
        Self::configure_compact_on(meta, z, limb_bits, table)
    }

    /// Independent range buses with one shared table. Each bus keeps its own
    /// fixed activation pattern; tuple membership is never used as independent
    /// range membership. The empty list configures no table or buses.
    pub fn configure_bank<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        columns: &[Column<Advice>],
        limb_bits: LimbBits,
    ) -> Vec<Self> {
        if columns.is_empty() {
            return Vec::new();
        }
        let table = meta.lookup_table_column();
        columns
            .iter()
            .map(|z| Self::configure_compact_on(meta, *z, limb_bits, table))
            .collect()
    }

    fn configure_compact_on<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        z: Column<Advice>,
        limb_bits: LimbBits,
        table: TableColumn,
    ) -> Self {
        meta.enable_equality(z);
        let shift = meta.fixed_column();
        let step = meta.fixed_column();
        let radix = F::from(1_u64 << limb_bits.get());
        meta.lookup("compact running-sum limb", |cells| {
            let pattern = cells.query_fixed(step, Rotation::cur());
            let enabled = pattern.clone()
                * (iroha_plonk::cs::Expression::Constant(F::from(2)) - pattern.clone());
            let top = pattern.clone()
                * (pattern - iroha_plonk::cs::Expression::Constant(F::ONE))
                * F::TWO_INV;
            let cur = cells.query_advice(z, Rotation::cur());
            let next = cells.query_advice(z, Rotation::next());
            vec![(enabled * (cur.clone() - next * radix) + top * cur, table)]
        });
        meta.create_gate("compact shifted top limb", |cells| {
            let pattern = cells.query_fixed(step, Rotation::cur());
            let factor = cells.query_fixed(shift, Rotation::cur());
            let cur = cells.query_advice(z, Rotation::cur());
            let prev = cells.query_advice(z, Rotation::prev());
            vec![(
                "pattern factor (z - z_prev factor)",
                pattern * factor.clone() * (cur - prev * factor),
            )]
        });
        Self {
            z,
            table,
            shift,
            pattern: Pattern::Fixed { step },
            limb_bits,
        }
    }

    /// Compact `(pattern, factor)` columns, or `None` for the selector
    /// layout. Pattern zero fully disables the range bus; another fixed gate
    /// may reuse the factor on those rows only. Its gate must be disabled at
    /// every active code returned by [`Self::compact_pattern_codes`], and assignments must be on
    /// disjoint rows. This does not relax any active range check.
    #[must_use]
    pub const fn compact_patterns(&self) -> Option<(Column<Fixed>, Column<Fixed>)> {
        match self.pattern {
            Pattern::Fixed { step } | Pattern::Tagged { step, .. } => Some((step, self.shift)),
            Pattern::Selectors { .. } => None,
        }
    }

    /// Active fixed pattern codes, all integers `1..=result`. Zero disables
    /// the complete range relation. Selector-based configurations return zero.
    #[must_use]
    pub const fn compact_pattern_codes(&self) -> u64 {
        match self.pattern {
            Pattern::Selectors { .. } => 0,
            Pattern::Fixed { .. } => 2,
            Pattern::Tagged { .. } => 4,
        }
    }

    /// The running-sum column.
    #[must_use]
    pub const fn column(&self) -> Column<Advice> {
        self.z
    }

    /// The limb width.
    #[must_use]
    pub const fn limb_bits(&self) -> LimbBits {
        self.limb_bits
    }
}

/// `limbs >> shift` for a little-endian 256-bit integer.
fn shift_right(limbs: [u64; 4], shift: usize) -> [u64; 4] {
    let words = shift / 64;
    let bits = shift % 64;
    let mut out = [0_u64; 4];
    for (index, out) in out.iter_mut().enumerate() {
        let source = index + words;
        let Some(low) = limbs.get(source) else {
            continue;
        };
        let mut value = low >> bits;
        if bits > 0
            && let Some(high) = limbs.get(source + 1)
        {
            value |= high << (64 - bits);
        }
        *out = value;
    }
    out
}

/// The running-sum column entries for `value`, honest or not:
/// `z_i = floor(v / 2^(b i))` for `i < L`, then the shifted top limb.
#[must_use]
pub fn running_sum_witness<F: PastaField>(value: &F, shape: RangeShape) -> Vec<F> {
    let limbs = value.to_canonical_limbs();
    let mut entries: Vec<F> = (0..shape.limbs)
        .map(|limb| F::from_raw_reduced(shift_right(limbs, shape.limb_bits * limb)))
        .collect();
    if shape.shifted()
        && let Some(top) = entries.last().copied()
    {
        entries.push(top * F::from(1_u64 << (shape.limb_bits - shape.top_bits)));
    }
    entries
}

/// Native reference: the limbs of `value` when `value < 2^bits`, or `None`.
#[must_use]
pub fn limbs_native<F: PastaField>(value: &F, shape: RangeShape) -> Option<Vec<u64>> {
    let width = usize::try_from(value.bit_length_vartime()).ok()?;
    if width > shape.bits {
        return None;
    }
    let limbs = value.to_canonical_limbs();
    let mask = (1_u64 << shape.limb_bits) - 1;
    Some(
        (0..shape.limbs)
            .map(|limb| shift_right(limbs, shape.limb_bits * limb)[0] & mask)
            .collect(),
    )
}

/// Exact cell-bound range certificates for a single synthesis. A narrower
/// proved bound implies a wider requested bound; values never index this map.
#[derive(Debug, Default)]
struct RangeCertificates<F: PastaField>(BTreeMap<Cell, (usize, Word<F>)>);

/// The running-sum range-check chip.
#[derive(Clone, Debug)]
pub struct RunningSumChip<F: PastaField> {
    config: RunningSumConfig,
    rows: RowCursor,
    shared_rows: Option<SharedRows>,
    certificates: Option<Rc<RefCell<RangeCertificates<F>>>>,
    banks: Option<Rc<RefCell<Vec<Self>>>>,
    replay: Option<super::secondary::schedule::Replay<F>>,
    _marker: core::marker::PhantomData<F>,
}

impl<F: PastaField> RunningSumChip<F> {
    /// A chip whose first row is 0.
    #[must_use]
    pub const fn new(config: RunningSumConfig) -> Self {
        Self::with_cursor(config, RowCursor::starting_at(0))
    }

    /// Uses a caller-reserved row interval, for example after a disjoint
    /// public-prefix pattern sharing the compact factor column.
    #[must_use]
    pub const fn with_cursor(config: RunningSumConfig, rows: RowCursor) -> Self {
        Self {
            config,
            rows,
            shared_rows: None,
            certificates: None,
            banks: None,
            replay: None,
            _marker: core::marker::PhantomData,
        }
    }

    /// Shares a caller-owned reservation cursor with another user of these
    /// same columns. Exact range certificates are shared by chip clones, so
    /// repeated checks of the same physical cell reuse an existing narrower
    /// bound. Construct fresh chips and cursors for each synthesis.
    #[must_use]
    pub fn with_shared_cursor(config: RunningSumConfig, rows: &SharedRows) -> Self {
        Self {
            config,
            rows: RowCursor::starting_at(0),
            shared_rows: Some(rows.clone()),
            certificates: Some(Rc::new(RefCell::new(RangeCertificates(BTreeMap::new())))),
            banks: None,
            replay: None,
            _marker: core::marker::PhantomData,
        }
    }

    /// A fixed set of independent range buses, selecting the least occupied
    /// bus by structural row counts (ties use column order). Clones share
    /// reservations and exact-cell certificates. A fresh bank is required per
    /// synthesis; the owner calls `load_table` once.
    ///
    /// # Errors
    /// No buses, duplicate advice columns, or different table/limb metadata.
    pub fn banked(configs: Vec<RunningSumConfig>) -> Result<Self, Error> {
        let first = *configs.first().ok_or(Error::Synthesis)?;
        if configs.iter().enumerate().any(|(i, c)| {
            c.table != first.table
                || c.limb_bits != first.limb_bits
                || match (c.pattern, first.pattern) {
                    (
                        Pattern::Tagged {
                            tag_table: left, ..
                        },
                        Pattern::Tagged {
                            tag_table: right, ..
                        },
                    ) => left != right,
                    (Pattern::Tagged { .. }, _) | (_, Pattern::Tagged { .. }) => true,
                    _ => false,
                }
                || configs[..i].iter().any(|previous| previous.z == c.z)
        }) {
            return Err(Error::Synthesis);
        }
        let mut out = Self::new(first);
        out.certificates = Some(Rc::new(RefCell::new(RangeCertificates(BTreeMap::new()))));
        out.banks = Some(Rc::new(RefCell::new(
            configs.into_iter().map(Self::new).collect(),
        )));
        Ok(out)
    }

    /// Replays a fixed secondary schedule. Each request immediately emits its
    /// exact bound; the owner must finish the shared stream in the same region.
    ///
    /// # Errors
    /// Existing banks/replay, or mismatched primary/control columns.
    pub fn with_secondary_plan(
        mut self,
        secondary: super::secondary::SecondaryRangeConfig,
        plan: super::secondary::SecondaryPlan,
    ) -> Result<Self, Error> {
        if self.banks.is_some() || self.replay.is_some() {
            return Err(Error::Synthesis);
        }
        self.replay = Some(super::secondary::schedule::Replay::new(
            plan,
            secondary,
            self.config,
        )?);
        Ok(self)
    }

    /// Completes all structurally enabled dummy rows and verifies that every
    /// scheduled request was consumed. A second finish is rejected.
    ///
    /// # Errors
    /// Missing events, fixed/cell conflicts, or out-of-domain assignments.
    pub fn finish_secondary(&self, region: &mut Region<'_, F>) -> Result<(), Error> {
        self.replay
            .as_ref()
            .map_or(Ok(()), |replay| replay.finish(region))
    }

    fn least_occupied(banks: &[Self]) -> usize {
        banks
            .iter()
            .enumerate()
            .min_by_key(|(_, lane)| lane.next_row())
            .map_or(0, |(i, _)| i)
    }

    fn cached(&self, word: &Word<F>, bits: usize) -> Option<Word<F>> {
        self.certificates.as_ref().and_then(|certificates| {
            certificates
                .borrow()
                .0
                .get(&word.cell())
                .filter(|(proved, _)| *proved <= bits)
                .map(|(_, checked)| checked.clone())
        })
    }

    fn remember(&self, source: &Word<F>, checked: &Word<F>, bits: usize) {
        if let Some(certificates) = &self.certificates {
            let mut certificates = certificates.borrow_mut();
            for cell in [source.cell(), checked.cell()] {
                let entry = certificates
                    .0
                    .entry(cell)
                    .or_insert_with(|| (bits, checked.clone()));
                if bits < entry.0 {
                    *entry = (bits, checked.clone());
                }
            }
        }
    }

    fn take_rows(&mut self, count: usize) -> Result<usize, Error> {
        match &self.shared_rows {
            Some(rows) => rows.take(count),
            None => self.rows.take(count),
        }
    }

    /// The configuration.
    #[must_use]
    pub const fn config(&self) -> &RunningSumConfig {
        &self.config
    }

    /// The first row not used yet.
    #[must_use]
    pub fn next_row(&self) -> usize {
        if let Some(replay) = &self.replay {
            return replay.next_row();
        }
        if let Some(banks) = &self.banks {
            return banks.borrow().iter().map(Self::next_row).max().unwrap_or(0);
        }
        self.shared_rows
            .as_ref()
            .map_or_else(|| self.rows.next_row(), SharedRows::next_row)
    }

    /// The shape of a `bits`-bit check.
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] for a width outside `1..=252`.
    pub fn shape(&self, bits: usize) -> Result<RangeShape, Error> {
        let mut shape = RangeShape::new(bits, self.config.limb_bits).ok_or(Error::Synthesis)?;
        if matches!(self.config.pattern, Pattern::Tagged { .. }) {
            shape.rows = shape.limbs;
        }
        Ok(shape)
    }

    /// Loads `0 .. 2^b`, or the exact tagged subsets for a tagged configuration.
    ///
    /// # Errors
    ///
    /// [`Error`] when the table does not fit the usable rows.
    pub fn load_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let table = self.config.table;
        if let Pattern::Tagged { tag_table, .. } = self.config.pattern {
            return layouter.assign_table(
                || "exact tagged range table",
                |mut cells| {
                    let mut row = 0;
                    // First/default tuple is (15,0), also used by every inactive
                    // and algebraic-narrow row. Both columns are padded together.
                    for bits in (3_u64..=15).rev() {
                        for value in 0..1_u64 << bits {
                            cells.assign_cell(
                                || "width",
                                tag_table,
                                row,
                                || Value::known(F::from(bits)),
                            )?;
                            cells.assign_cell(
                                || "limb",
                                table,
                                row,
                                || Value::known(F::from(value)),
                            )?;
                            row += 1;
                        }
                    }
                    Ok(())
                },
            );
        }
        let rows = self.config.limb_bits.table_rows();
        layouter.assign_table(
            || "running-sum limb table",
            |mut cells| {
                for row in 0..rows {
                    let value = u64::try_from(row).map_err(|_| Error::BoundsFailure)?;
                    cells.assign_cell(|| "limb", table, row, || Value::known(F::from(value)))?;
                }
                Ok(())
            },
        )
    }

    /// Range-checks a copy of `word` to `bits` bits and returns the copy
    /// (`z_0`).
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] for a width outside `1..=252`, and [`Error`]
    /// from the layout.
    pub fn range_check(
        &mut self,
        region: &mut Region<'_, F>,
        word: &Word<F>,
        bits: usize,
    ) -> Result<Word<F>, Error> {
        let shape = self.shape(bits)?;
        if let Some(checked) = self.cached(word, bits) {
            return Ok(checked);
        }
        if let Some(banks) = &self.banks {
            let mut banks = banks.borrow_mut();
            let index = Self::least_occupied(&banks);
            let checked = banks[index].range_check(region, word, bits)?;
            self.remember(word, &checked, bits);
            return Ok(checked);
        }
        if let Some(replay) = &self.replay {
            let checked = replay.assign(region, word.value(), bits)?;
            region.constrain_equal(word.cell(), checked.cell())?;
            self.remember(word, &checked, bits);
            return Ok(checked);
        }
        let start = self.take_rows(shape.rows)?;
        let z0 = copy_word(region, word, self.config.z, start)?;
        self.decompose(region, start, word.value(), shape)?;
        self.remember(word, &z0, bits);
        Ok(z0)
    }

    /// Assigns `value` as `z_0` of a new `bits`-bit check and returns it.
    ///
    /// # Errors
    ///
    /// As [`Self::range_check`].
    pub fn witness_range_checked(
        &mut self,
        region: &mut Region<'_, F>,
        value: Value<F>,
        bits: usize,
    ) -> Result<Word<F>, Error> {
        let shape = self.shape(bits)?;
        if let Some(banks) = &self.banks {
            let mut banks = banks.borrow_mut();
            let index = Self::least_occupied(&banks);
            let checked = banks[index].witness_range_checked(region, value, bits)?;
            self.remember(&checked, &checked, bits);
            return Ok(checked);
        }
        if let Some(replay) = &self.replay {
            let checked = replay.assign(region, value, bits)?;
            self.remember(&checked, &checked, bits);
            return Ok(checked);
        }
        let start = self.take_rows(shape.rows)?;
        let z0 = assign_word(region, self.config.z, start, value)?;
        self.decompose(region, start, value, shape)?;
        self.remember(&z0, &z0, bits);
        Ok(z0)
    }

    /// Lays out rows `1..` of a check whose `z_0` is at `start`.
    fn decompose(
        &self,
        region: &mut Region<'_, F>,
        start: usize,
        value: Value<F>,
        shape: RangeShape,
    ) -> Result<(), Error> {
        let entries = value.map(|value| running_sum_witness(&value, shape));
        let entries = entries.transpose_vec(shape.rows)?;
        for (offset, entry) in entries.into_iter().enumerate().skip(1) {
            let row = start.checked_add(offset).ok_or(Error::BoundsFailure)?;
            assign_word(region, self.config.z, row, entry)?;
        }
        for limb in 0..shape.limbs - 1 {
            match self.config.pattern {
                Pattern::Selectors { step, .. } => step.enable(region, start + limb)?,
                Pattern::Fixed { step } | Pattern::Tagged { step, .. } => {
                    region.assign_fixed(step, start + limb, F::ONE)?;
                }
            }
        }
        let top = start + shape.limbs - 1;
        if let Pattern::Tagged { step, .. } = self.config.pattern {
            let code = match shape.top_bits {
                1 => 3,
                2 => 4,
                _ => 2,
            };
            region.assign_fixed(step, top, F::from(code))?;
            if shape.top_bits >= 3 {
                region.assign_fixed(self.config.shift, top, F::from(shape.top_bits as u64))?;
            }
            return Ok(());
        }
        if let Pattern::Selectors { limb, .. } = self.config.pattern {
            region.enable_selector(String::new, &limb, top)?;
        } else if let Pattern::Fixed { step } = self.config.pattern {
            region.assign_fixed(step, top, F::from(2))?;
        }
        if shape.shifted() {
            let shifted = top + 1;
            if let Pattern::Selectors { limb, shift, .. } = self.config.pattern {
                region.enable_selector(String::new, &limb, shifted)?;
                shift.enable(region, shifted)?;
            } else if let Pattern::Fixed { step } = self.config.pattern {
                region.assign_fixed(step, shifted, F::from(2))?;
            }
            let factor = F::from(1_u64 << (shape.limb_bits - shape.top_bits));
            region.assign_fixed(self.config.shift, shifted, factor)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ff::{Field, PrimeField};
    use iroha_pasta::{Fp, Fq};

    use super::*;

    fn bits(b: usize) -> LimbBits {
        LimbBits::new(b).expect("valid limb width")
    }

    #[test]
    fn limb_bits_bounds() {
        assert_eq!(LimbBits::new(0), None);
        assert_eq!(LimbBits::new(25), None);
        assert_eq!(LimbBits::new(9).map(LimbBits::get), Some(9));
        assert_eq!(LimbBits::for_k(10), LimbBits::new(9));
        assert_eq!(LimbBits::for_k(1), None);
        assert_eq!(bits(9).table_rows(), 512);
    }

    #[test]
    fn shapes_match_the_m8_inventory() {
        // M8: rows per 128-bit check at lookup bits 15 / 12 / 10 / 8.
        for (b, rows) in [(15, 10), (12, 12), (10, 14), (8, 16), (9, 16)] {
            assert_eq!(
                RangeShape::new(128, bits(b)).map(|s| s.rows),
                Some(rows),
                "b = {b}"
            );
        }
        let shape = RangeShape::new(64, bits(8)).expect("shape");
        assert_eq!((shape.limbs, shape.top_bits, shape.rows), (8, 8, 8));
        assert!(!shape.shifted());
        assert_eq!(RangeShape::new(0, bits(8)), None);
        assert_eq!(RangeShape::new(253, bits(8)), None);
        assert_eq!(RangeShape::new(3, bits(8)).map(|s| s.rows), Some(2));
    }

    #[test]
    fn shift_right_matches_integer_shifts() {
        let limbs = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210, 7, 1 << 60];
        assert_eq!(shift_right(limbs, 0), limbs);
        assert_eq!(shift_right(limbs, 64), [limbs[1], 7, 1 << 60, 0]);
        assert_eq!(shift_right(limbs, 256), [0; 4]);
        let low = u128::from(limbs[0]) | (u128::from(limbs[1]) << 64);
        let shifted = shift_right(limbs, 4);
        assert_eq!(
            u128::from(shifted[0]) | (u128::from(shifted[1]) << 64),
            (low >> 4) | (7 << 124)
        );
    }

    #[test]
    fn witness_and_native_limbs() {
        let shape = RangeShape::new(10, bits(4)).expect("shape");
        assert_eq!((shape.limbs, shape.top_bits, shape.rows), (3, 2, 4));
        let value = Fp::from(0b10_1101_0110);
        let entries = running_sum_witness(&value, shape);
        assert_eq!(
            entries,
            vec![
                value,
                Fp::from(0b10_1101),
                Fp::from(0b10),
                Fp::from(0b10 << 2)
            ]
        );
        assert_eq!(
            limbs_native(&value, shape),
            Some(vec![0b0110, 0b1101, 0b10])
        );
        assert_eq!(limbs_native(&Fp::from(1 << 10), shape), None);
        assert_eq!(limbs_native(&-Fq::ONE, shape), None);
        let wide = RangeShape::new(128, bits(9)).expect("shape");
        let max = Fq::from_u128(u128::MAX);
        let limbs = limbs_native(&max, wide).expect("in range");
        assert_eq!(limbs.len(), 15);
        assert_eq!(limbs[14], 0b11);
    }
}

#[cfg(test)]
#[path = "running_sum/cache_tests.rs"]
mod cache_tests;
