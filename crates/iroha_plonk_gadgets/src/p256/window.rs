//! The window lookup of the P-256 chip: per-limb digit decompositions of
//! proper scalars whose digits select points from window tables through one
//! `lookup_any` argument.
//!
//! # Tables
//!
//! One table holds every window point the circuit can select, as tuples
//! `(tag, x_0, x_1, x_2, y_0, y_1, y_2, digit)` of the 87-bit limbs (the
//! column order of [`SharedTable`]; the digit is `V`):
//!
//! - **fixed-base** rows (fixed columns only): window `w` of fixed base `b`
//!   has tag `1 + 64 b + w` and one row per digit (the entries of a
//!   [`FixedTable`]); base 0 is the generator, bases `1..` the circuit's
//!   fixed keys;
//! - **dynamic** rows (per proof): the multiples `[e] Q`, `e = 1..=16`, of a
//!   variable key, tag `2^32 + r` for the dynamic table whose first row is
//!   `r` ([`dynamic_tag`]: unique in the circuit, also across chips that
//!   share the columns); two rows per entry (`x` limbs, then `y` limbs in
//!   the three point columns), enabled by the fixed column `q_dyn` and
//!   copied from the foreign-field values that computed them;
//! - every other row contributes its own tuple, which no window input
//!   matches (all zero, or a SHA or range row of the shared table, whose
//!   tags are not window tags).
//!
//! Table expressions are `fixed + q_dyn * advice`, so a fixed row's entry is
//! a constant and a dynamic row's entry is the copied advice.
//!
//! The table is the chip's own eight fixed columns
//! ([`WindowConfig::configure`], one argument named `p256 window`), or the
//! Q leaf's shared table ([`WindowConfig::configure_shared`]), where the
//! window lookup is the guest of a foreign-field `U` range argument
//! ([`crate::table`]).
//!
//! # Lookups
//!
//! A scalar limb `L` is decomposed by a running sum `z_0 = L`,
//! `z_{j+1} = (z_j - d_j) / 2^bits_j` in the `z` column at every second row,
//! the last window of a limb reading `d = z` (shift 0). Each window's row
//! pair looks up `(in_tag, x limbs, y limbs, z_j - shift z_{j+1} + offset)`
//! with the point limbs in the three point columns of the two rows.
//! Every fixed-base digit is range-checked by the table (a window of `b`
//! bits has `2^b` rows), so the running sum recomposes the limb exactly. A
//! dynamic digit is checked against `1..=16` only; the limb bound of the
//! proper scalar bounds its top digit.
//!
//! Inputs and table expressions have degree 2, so the lookup has degree 6.
//!
//! # Rows
//!
//! Lookup rows (the input side) and dynamic-table rows (the table side) use
//! the same four advice columns. A chip either takes both from one cursor
//! ([`WindowChip::starting_at`]) or from two ([`WindowChip::with_cursors`]),
//! the dynamic one starting after the fixed-base rows so that its fixed
//! tag and digit cells never overwrite a fixed-base entry.

use core::marker::PhantomData;

use iroha_pasta::PastaField;
use iroha_plonk::{
    cs::{Advice, Column, ConstraintSystem, Expression, Fixed, Rotation, VirtualCells},
    frontend::{Error, Region, Value},
};

use super::native::{Affine, FixedTable, Window, limbs_of};
use crate::{
    cells::{RowCursor, Word, assign_word, copy_word},
    ff::{FfValue, ForeignModulus, Form, LIMBS, Nat},
    table::{DYNAMIC_TAG_BASE, GuestLookup, SharedTable, TableGuest},
};

/// Advice columns of the window lookup: the running sum `z` and three
/// point-limb columns.
pub const WINDOW_ADVICE_COLUMNS: usize = 4;
/// Fixed columns of the window lookup with its own table (five input and
/// dynamic-table columns and the eight table columns).
pub const WINDOW_FIXED_COLUMNS: usize = 13;
/// Fixed columns of the window lookup on the shared table.
pub const WINDOW_SHARED_FIXED_COLUMNS: usize = 5;
/// Window width of variable-base (dynamic table) multiplication.
pub const VARIABLE_WINDOW_BITS: u32 = 4;
/// Window width of fixed-base multiplication.
pub const FIXED_WINDOW_BITS: u32 = 8;
/// Entries of a dynamic table (`[e] Q` for `e = 1..=16`).
pub const DYNAMIC_ENTRIES: usize = 16;
/// Advice rows of one window lookup (`x` limbs, then `y` limbs).
pub const LOOKUP_ROWS: usize = 2;
/// Tags per fixed base (at least the number of fixed windows).
const FIXED_TAG_STRIDE: u64 = 64;

/// The tag of window `window` of fixed base `base`.
#[must_use]
pub const fn fixed_tag(base: usize, window: usize) -> u64 {
    1 + FIXED_TAG_STRIDE * base as u64 + window as u64
}

/// [`fixed_tag`] when it is unique: the window is below the per-base stride
/// and the tag below every dynamic tag.
///
/// # Errors
///
/// [`Error::Synthesis`] otherwise.
pub fn checked_fixed_tag(base: usize, window: usize) -> Result<u64, Error> {
    let stride = usize::try_from(FIXED_TAG_STRIDE).map_err(|_| Error::Synthesis)?;
    let tag = u64::try_from(base)
        .ok()
        .and_then(|base| base.checked_mul(FIXED_TAG_STRIDE))
        .and_then(|offset| offset.checked_add(1 + u64::try_from(window).ok()?))
        .ok_or(Error::Synthesis)?;
    (window < stride && tag < DYNAMIC_TAG_BASE)
        .then_some(tag)
        .ok_or(Error::Synthesis)
}

/// The tag of the dynamic table whose first row is `row`: `2^32 + row`.
///
/// Rows hold one table each, so the tag is unique in the circuit whichever
/// [`WindowChip`] (two chips on one configuration, or a cloned chip) laid
/// the table out; a per-chip counter would give two such tables one tag, and
/// a window lookup could then select another key's multiples.
///
/// # Errors
///
/// [`Error::Synthesis`] for a row that does not fit the tag.
pub fn dynamic_tag(row: usize) -> Result<u64, Error> {
    u64::try_from(row)
        .ok()
        .and_then(|row| DYNAMIC_TAG_BASE.checked_add(row))
        .ok_or(Error::Synthesis)
}

/// Columns of the window lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowConfig {
    /// `z`, then the point-limb columns `a, b, c`.
    advice: [Column<Advice>; WINDOW_ADVICE_COLUMNS],
    /// Input tag (nonzero exactly on lookup rows).
    in_tag: Column<Fixed>,
    /// 1 on lookup rows.
    q_in: Column<Fixed>,
    /// The running-sum shift `2^bits` (0 on the last window of a limb).
    shift: Column<Fixed>,
    /// The digit offset of a dynamic lookup (1, or 3 for the top window).
    offset: Column<Fixed>,
    /// The table: tag, point limbs and digit (`V`).
    table: SharedTable,
    /// 1 on the first row of a dynamic entry.
    q_dyn: Column<Fixed>,
}

impl WindowConfig {
    /// Configures the lookup on `advice` (made equality-enabled) with its
    /// own eight table columns and its own argument `p256 window`.
    pub fn configure<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; WINDOW_ADVICE_COLUMNS],
    ) -> Self {
        let table = SharedTable::configure(meta);
        let config = Self::configure_on(meta, advice, table);
        meta.lookup_any("p256 window", |cells| {
            let GuestLookup { mut pairs, value } = config.guest_lookup(cells);
            pairs.push((value, cells.query_fixed(table.value(), Rotation::cur())));
            pairs
        });
        config
    }

    /// [`Self::configure`] on the shared table: no argument of its own; the
    /// caller passes the configuration as the `U` guest of
    /// [`crate::ff::FfConfig::configure_shared`] and keeps the lookup rows
    /// disjoint from the foreign-field rows (the Q-leaf layout,
    /// [`crate::q_leaf`]).
    pub fn configure_shared<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; WINDOW_ADVICE_COLUMNS],
        table: &SharedTable,
    ) -> Self {
        Self::configure_on(meta, advice, *table)
    }

    fn configure_on<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; WINDOW_ADVICE_COLUMNS],
        table: SharedTable,
    ) -> Self {
        for column in advice {
            meta.enable_equality(column);
        }
        Self {
            advice,
            in_tag: meta.fixed_column(),
            q_in: meta.fixed_column(),
            shift: meta.fixed_column(),
            offset: meta.fixed_column(),
            table,
            q_dyn: meta.fixed_column(),
        }
    }

    /// The advice columns `z, a, b, c`.
    #[must_use]
    pub const fn advice_columns(&self) -> [Column<Advice>; WINDOW_ADVICE_COLUMNS] {
        self.advice
    }

    /// The table columns.
    #[must_use]
    pub const fn table(&self) -> &SharedTable {
        &self.table
    }

    /// The input-side fixed columns `in_tag, q_in, shift, offset` (all zero
    /// off lookup rows).
    #[must_use]
    pub const fn input_columns(&self) -> [Column<Fixed>; 4] {
        [self.in_tag, self.q_in, self.shift, self.offset]
    }

    /// The dynamic-entry enable column.
    #[must_use]
    pub const fn dynamic_column(&self) -> Column<Fixed> {
        self.q_dyn
    }
}

/// The window lookup `(in_tag, q_in limbs, digit)` against `(T, fixed +
/// q_dyn advice limbs, V)`; every input component is zero off lookup rows.
impl<F: PastaField> TableGuest<F> for WindowConfig {
    fn guest_name(&self) -> &'static str {
        "p256 window"
    }

    fn guest_lookup(&self, cells: &mut VirtualCells<'_, F>) -> GuestLookup<F> {
        let [z, a, b, c] = self.advice;
        let z_cur = cells.query_advice(z, Rotation::cur());
        let z_next = cells.query_advice(z, Rotation(2));
        let limbs: [Expression<F>; 2 * LIMBS] = [
            cells.query_advice(a, Rotation::cur()),
            cells.query_advice(b, Rotation::cur()),
            cells.query_advice(c, Rotation::cur()),
            cells.query_advice(a, Rotation::next()),
            cells.query_advice(b, Rotation::next()),
            cells.query_advice(c, Rotation::next()),
        ];
        let in_tag = cells.query_fixed(self.in_tag, Rotation::cur());
        let q_in = cells.query_fixed(self.q_in, Rotation::cur());
        let shift = cells.query_fixed(self.shift, Rotation::cur());
        let offset = cells.query_fixed(self.offset, Rotation::cur());
        let tab_tag = cells.query_fixed(self.table.tag(), Rotation::cur());
        let q_dyn = cells.query_fixed(self.q_dyn, Rotation::cur());
        let digit = q_in.clone() * z_cur - shift * z_next + offset;
        let mut pairs = vec![(in_tag, tab_tag)];
        let point_columns = self.table.x().into_iter().chain(self.table.y());
        for (limb, column) in limbs.into_iter().zip(point_columns) {
            let fixed = cells.query_fixed(column, Rotation::cur());
            pairs.push((q_in.clone() * limb.clone(), fixed + q_dyn.clone() * limb));
        }
        GuestLookup {
            pairs,
            value: digit,
        }
    }
}

/// A looked-up window point `(x, y)`, coordinates modulo `p`.
pub type WindowPoint<F> = (FfValue<F>, FfValue<F>);

/// Where the points of a decomposition come from.
#[derive(Clone, Copy, Debug)]
pub enum TableSource<'t, F: PastaField> {
    /// Window tables of fixed base `base`.
    Fixed {
        /// The fixed-base index (0 is the generator).
        base: usize,
        /// The table.
        table: &'t FixedTable,
    },
    /// A dynamic table of multiples.
    Dynamic {
        /// Its tag.
        tag: u64,
        /// `[e] Q` for `e = 1..=16`.
        entries: &'t [WindowPoint<F>],
    },
}

/// The window lookup's rows over its four advice columns: lookup rows from
/// one cursor, dynamic-table rows from the same cursor or a second one.
#[derive(Clone, Debug)]
pub struct WindowChip<F: PastaField> {
    config: WindowConfig,
    queries: RowCursor,
    /// The dynamic-table cursor (`None`: the lookup cursor).
    dynamic: Option<RowCursor>,
    _marker: PhantomData<F>,
}

/// The constant-time selection `entries[index]` of limb tuples (all
/// entries are read).
fn select_limbs(entries: &[[u128; 2 * LIMBS]], index: u64) -> [u128; 2 * LIMBS] {
    let mut out = [0_u128; 2 * LIMBS];
    for (position, entry) in (0_u64..).zip(entries) {
        let difference = position ^ index;
        // All ones exactly when `difference == 0`.
        let mask = u128::from(((difference | difference.wrapping_neg()) >> 63) ^ 1).wrapping_neg();
        for (slot, limb) in out.iter_mut().zip(entry) {
            *slot |= limb & mask;
        }
    }
    out
}

/// The limbs `x_0..x_2, y_0..y_2` of an affine point.
fn point_limbs(point: &Affine) -> [u128; 2 * LIMBS] {
    let x = limbs_of(&point.x);
    let y = limbs_of(&point.y);
    [x[0], x[1], x[2], y[0], y[1], y[2]]
}

/// Limb-wise maxima of limb tuples.
fn max_limbs(entries: impl Iterator<Item = [u128; 2 * LIMBS]>) -> [u128; 2 * LIMBS] {
    let mut out = [0_u128; 2 * LIMBS];
    for entry in entries {
        for (slot, limb) in out.iter_mut().zip(entry) {
            *slot = (*slot).max(limb);
        }
    }
    out
}

impl<F: PastaField> WindowChip<F> {
    /// A chip whose lookup and dynamic-table rows share one cursor from
    /// `row`.
    #[must_use]
    pub const fn starting_at(config: WindowConfig, row: usize) -> Self {
        Self {
            config,
            queries: RowCursor::starting_at(row),
            dynamic: None,
            _marker: PhantomData,
        }
    }

    /// A chip with lookup rows from `queries` and dynamic-table rows from
    /// `dynamic` (which must not overlap each other, other users of the
    /// advice columns, or the fixed-base table rows).
    #[must_use]
    pub const fn with_cursors(
        config: WindowConfig,
        queries: RowCursor,
        dynamic: RowCursor,
    ) -> Self {
        Self {
            config,
            queries,
            dynamic: Some(dynamic),
            _marker: PhantomData,
        }
    }

    /// The first free lookup row.
    #[must_use]
    pub const fn next_row(&self) -> usize {
        self.queries.next_row()
    }

    /// The first free dynamic-table row.
    #[must_use]
    pub const fn next_dynamic_row(&self) -> usize {
        match self.dynamic {
            Some(dynamic) => dynamic.next_row(),
            None => self.queries.next_row(),
        }
    }

    /// Writes the fixed-base tables (`tables[b]` is base `b`) into the fixed
    /// columns from row `start`; returns the first row after them. Dynamic
    /// rows must not overlap these rows.
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn load_fixed(
        &self,
        region: &mut Region<'_, F>,
        tables: &[&FixedTable],
        start: usize,
    ) -> Result<usize, Error> {
        let table = &self.config.table;
        let point_columns: Vec<Column<Fixed>> = table.x().into_iter().chain(table.y()).collect();
        let mut row = start;
        for (base, fixed) in tables.iter().enumerate() {
            for (window, entries) in fixed.entries.iter().enumerate() {
                let tag = F::from(checked_fixed_tag(base, window)?);
                for (digit, entry) in (0_u64..).zip(entries) {
                    region.assign_fixed(table.tag(), row, tag)?;
                    if digit != 0 {
                        region.assign_fixed(table.value(), row, F::from(digit))?;
                    }
                    for (column, limb) in point_columns.iter().zip(point_limbs(entry)) {
                        region.assign_fixed(*column, row, F::from_u128(limb))?;
                    }
                    row = row.checked_add(1).ok_or(Error::BoundsFailure)?;
                }
            }
        }
        Ok(row)
    }

    /// Registers a dynamic table of `entries` (`[e] Q`, `e = 1..=16`):
    /// copies their limbs into two rows each. Returns its tag
    /// ([`dynamic_tag`] of its first row, so unique in the circuit whichever
    /// chip lays it out).
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] unless there are 16 entries of one modulus, and
    /// [`Error`] from the layout.
    pub fn dynamic_table(
        &mut self,
        region: &mut Region<'_, F>,
        entries: &[WindowPoint<F>],
    ) -> Result<u64, Error> {
        if entries.len() != DYNAMIC_ENTRIES {
            return Err(Error::Synthesis);
        }
        let cursor = self.dynamic.as_mut().unwrap_or(&mut self.queries);
        let first = cursor.take(LOOKUP_ROWS * DYNAMIC_ENTRIES)?;
        let tag = dynamic_tag(first)?;
        let [_, a, b, c] = self.config.advice;
        let table = self.config.table;
        for ((index, (x, y)), row) in (1_u64..).zip(entries).zip((first..).step_by(LOOKUP_ROWS)) {
            region.assign_fixed(self.config.q_dyn, row, F::ONE)?;
            region.assign_fixed(table.tag(), row, F::from(tag))?;
            region.assign_fixed(table.value(), row, F::from(index))?;
            for (column, limb) in [a, b, c].into_iter().zip(x.limbs()) {
                copy_word(region, limb, column, row)?;
            }
            for (column, limb) in [a, b, c].into_iter().zip(y.limbs()) {
                copy_word(region, limb, column, row + 1)?;
            }
        }
        Ok(tag)
    }

    /// Decomposes the proper scalar `scalar` into the windows of `layout`
    /// and looks up each window's point in `source`; returns the points in
    /// window order. For a dynamic source the looked-up entry is
    /// `digit + 1`, or `digit + top_offset` for the last window.
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] for a non-proper scalar or a layout that does
    /// not match the source, and [`Error`] from the layout.
    pub fn decompose(
        &mut self,
        region: &mut Region<'_, F>,
        scalar: &FfValue<F>,
        layout: &[Window],
        source: TableSource<'_, F>,
        top_offset: u64,
    ) -> Result<Vec<WindowPoint<F>>, Error> {
        if scalar.form() < Form::Proper {
            return Err(Error::Synthesis);
        }
        let (x_modulus, entry_limbs, bounds, form) = Self::source_data(&source)?;
        let limb_values = scalar.limb_values();
        let [z, a, b, c] = self.config.advice;
        let top = layout.len().checked_sub(1).ok_or(Error::Synthesis)?;
        let mut out = Vec::with_capacity(layout.len());
        for (index, window) in layout.iter().enumerate() {
            let last_in_limb = layout
                .get(index + 1)
                .is_none_or(|next| next.limb != window.limb);
            let row = self.queries.take(LOOKUP_ROWS)?;
            // The running sum entry `z_j = limb >> offset`.
            let entry = limb_values.map(|limbs| limbs[window.limb].shr(window.offset as usize));
            let z_value = entry.map(Nat::to_field::<F>);
            // The first entry of a limb's running sum is a copy of the limb.
            if window.offset == 0 {
                let limb = scalar.limbs().get(window.limb).ok_or(Error::Synthesis)?;
                copy_word(region, limb, z, row)?;
            } else {
                assign_word(region, z, row, z_value)?;
            }
            let (tag, offset) = match source {
                TableSource::Fixed { base, .. } => (checked_fixed_tag(base, index)?, 0),
                TableSource::Dynamic { tag, .. } => {
                    (tag, if index == top { top_offset } else { 1 })
                }
            };
            region.assign_fixed(self.config.in_tag, row, F::from(tag))?;
            region.assign_fixed(self.config.q_in, row, F::ONE)?;
            if !last_in_limb {
                region.assign_fixed(self.config.shift, row, F::from(1_u64 << window.bits))?;
            }
            if offset != 0 {
                region.assign_fixed(self.config.offset, row, F::from(offset))?;
            }
            let mask = (1_u128 << window.bits) - 1;
            let digit = entry.map(|entry| {
                // A window holds at most 8 bits.
                #[allow(clippy::cast_possible_truncation)]
                let digit = (entry.low_bits_u128(window.bits as usize) & mask) as u64;
                digit
            });
            let selected = digit.map(|digit| {
                let table: &[[u128; 2 * LIMBS]] = match &source {
                    TableSource::Fixed { .. } => &entry_limbs[index],
                    TableSource::Dynamic { .. } => &entry_limbs[0],
                };
                let position = match source {
                    TableSource::Fixed { .. } => digit,
                    TableSource::Dynamic { .. } => (digit + offset).wrapping_sub(1),
                };
                select_limbs(table, position)
            });
            let mut x_words = Vec::with_capacity(LIMBS);
            let mut y_words = Vec::with_capacity(LIMBS);
            for (slot, column) in [a, b, c].into_iter().enumerate() {
                let x_limb = selected.map(|limbs| F::from_u128(limbs[slot]));
                let y_limb = selected.map(|limbs| F::from_u128(limbs[LIMBS + slot]));
                x_words.push(assign_word(region, column, row, x_limb)?);
                y_words.push(assign_word(region, column, row + 1, y_limb)?);
            }
            let x_words: [Word<F>; LIMBS] = x_words.try_into().map_err(|_| Error::Synthesis)?;
            let y_words: [Word<F>; LIMBS] = y_words.try_into().map_err(|_| Error::Synthesis)?;
            let x_bounds = [bounds[0], bounds[1], bounds[2]];
            let y_bounds = [bounds[3], bounds[4], bounds[5]];
            out.push((
                FfValue::from_parts(x_words, x_bounds, x_modulus, form),
                FfValue::from_parts(y_words, y_bounds, x_modulus, form),
            ));
        }
        Ok(out)
    }

    /// The modulus, per-window entry limbs, limb bounds and form of a
    /// source.
    #[allow(clippy::type_complexity)]
    fn source_data(
        source: &TableSource<'_, F>,
    ) -> Result<
        (
            ForeignModulus,
            Vec<Vec<[u128; 2 * LIMBS]>>,
            [u128; 2 * LIMBS],
            Form,
        ),
        Error,
    > {
        match source {
            TableSource::Fixed { table, .. } => {
                let limbs: Vec<Vec<[u128; 2 * LIMBS]>> = table
                    .entries
                    .iter()
                    .map(|entries| entries.iter().map(point_limbs).collect())
                    .collect();
                let bounds = max_limbs(limbs.iter().flatten().copied());
                Ok((ForeignModulus::P256_BASE, limbs, bounds, Form::Canonical))
            }
            TableSource::Dynamic { entries, .. } => {
                let (first, _) = entries.first().ok_or(Error::Synthesis)?;
                let modulus = first.modulus();
                let mut bounds = [0_u128; 2 * LIMBS];
                let mut form = Form::Canonical;
                let mut values: Vec<Value<[u128; 2 * LIMBS]>> = Vec::new();
                for (x, y) in *entries {
                    if x.modulus() != modulus || y.modulus() != modulus {
                        return Err(Error::Synthesis);
                    }
                    for (slot, bound) in x.bounds().iter().chain(y.bounds().iter()).enumerate() {
                        bounds[slot] = bounds[slot].max(*bound);
                    }
                    form = form.min(x.form()).min(y.form());
                    values.push(x.limb_values().zip(y.limb_values()).map(|(x, y)| {
                        let limb = |value: &Nat| value.low_bits_u128(128);
                        [
                            limb(&x[0]),
                            limb(&x[1]),
                            limb(&x[2]),
                            limb(&y[0]),
                            limb(&y[1]),
                            limb(&y[2]),
                        ]
                    }));
                }
                // Unknown witness values (key generation) give an empty
                // table; nothing is selected from it then.
                let mut known = Vec::with_capacity(values.len());
                for value in values {
                    let mut out = None;
                    let _ = value.map(|limbs| out = Some(limbs));
                    match out {
                        Some(limbs) => known.push(limbs),
                        None => return Ok((modulus, vec![Vec::new()], bounds, form)),
                    }
                }
                Ok((modulus, vec![known], bounds, form))
            }
        }
    }
}
