//! Typed assigned cells and row cursors.
//!
//! Every value a chip of this crate hands back is a typed wrapper around an
//! [`AssignedCell`] in an equality-enabled advice column, so it can be copied
//! into any other chip:
//!
//! - [`Word`]: a field element;
//! - [`Bit`]: a field element a gate constrained to `{0, 1}`;
//! - [`Uint`]: a field element a running-sum range check constrained to
//!   `[0, 2^BITS)` ([`U128`], [`U64`]).
//!
//! The wrappers have no public constructors: a [`Bit`] or a [`Uint`] exists
//! only once the constraint its type promises has been laid out.
//!
//! The `iroha_plonk` floor planner starts every region at row 0, so chips
//! address absolute rows. Each chip keeps a [`RowCursor`] over its own
//! columns and allocates rows from it; chips on disjoint columns therefore
//! share rows freely, and one chip never overwrites its own cells.

use iroha_pasta::PastaField;
use iroha_plonk::{
    cs::{Advice, Column},
    frontend::{AssignedCell, Cell, Error, Region, Value},
};

/// A field element in an equality-enabled advice cell.
#[derive(Clone, Debug)]
pub struct Word<F: PastaField> {
    cell: AssignedCell<F, F>,
}

impl<F: PastaField> Word<F> {
    /// Wraps an assigned cell of an equality-enabled column.
    pub(crate) const fn new(cell: AssignedCell<F, F>) -> Self {
        Self { cell }
    }

    /// The cell (column and absolute row).
    #[must_use]
    pub const fn cell(&self) -> Cell {
        self.cell.cell()
    }

    /// The witness value (unknown during key generation).
    #[must_use]
    pub fn value(&self) -> Value<F> {
        self.cell.value().copied()
    }

    /// The underlying assigned cell.
    #[must_use]
    pub const fn assigned(&self) -> &AssignedCell<F, F> {
        &self.cell
    }
}

/// A cell constrained to `{0, 1}`.
#[derive(Clone, Debug)]
pub struct Bit<F: PastaField>(Word<F>);

impl<F: PastaField> Bit<F> {
    /// Wraps a word whose booleanity a gate enforces.
    pub(crate) const fn new(word: Word<F>) -> Self {
        Self(word)
    }

    /// The bit as a field element.
    #[must_use]
    pub const fn word(&self) -> &Word<F> {
        &self.0
    }

    /// The cell.
    #[must_use]
    pub const fn cell(&self) -> Cell {
        self.0.cell()
    }

    /// The witness value as a boolean (any nonzero value reads as `true`).
    #[must_use]
    pub fn value(&self) -> Value<bool> {
        self.0.value().map(|value| !bool::from(value.is_zero()))
    }
}

/// A cell constrained to `[0, 2^BITS)` by a running-sum range check.
///
/// `BITS` is at most 128, so the value is an unsigned integer that fits a
/// `u128`; the chips reject wider types at compile time.
#[derive(Clone, Debug)]
pub struct Uint<F: PastaField, const BITS: usize>(Word<F>);

/// A cell constrained to `[0, 2^128)`.
pub type U128<F> = Uint<F, 128>;

/// A cell constrained to `[0, 2^64)`.
pub type U64<F> = Uint<F, 64>;

impl<F: PastaField, const BITS: usize> Uint<F, BITS> {
    /// Wraps a word whose range a running-sum check enforces.
    pub(crate) const fn new(word: Word<F>) -> Self {
        Self(word)
    }

    /// The value as a field element.
    #[must_use]
    pub const fn word(&self) -> &Word<F> {
        &self.0
    }

    /// The cell.
    #[must_use]
    pub const fn cell(&self) -> Cell {
        self.0.cell()
    }

    /// The witness value as an integer: the low 128 bits of the canonical
    /// value, which is the whole value for every witness the range check
    /// accepts.
    #[must_use]
    pub fn value(&self) -> Value<u128> {
        self.0.value().map(|value| low_u128(&value))
    }
}

/// The low 128 bits of the canonical integer value of `value`.
pub fn low_u128<F: PastaField>(value: &F) -> u128 {
    let limbs = value.to_canonical_limbs();
    u128::from(limbs[0]) | (u128::from(limbs[1]) << 64)
}

/// The canonical integer value of `value` when it is below `2^128`.
pub fn to_u128<F: PastaField>(value: &F) -> Option<u128> {
    let limbs = value.to_canonical_limbs();
    (limbs[2] == 0 && limbs[3] == 0).then(|| low_u128(value))
}

/// The next free row of a group of columns.
///
/// Rows are absolute (regions start at row 0). [`RowCursor::take`] hands out
/// consecutive, non-overlapping row ranges with checked arithmetic below an
/// optional end row (chips that share columns get disjoint row ranges); the
/// assembly rejects rows at or beyond the usable rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowCursor {
    next: usize,
    end: usize,
}

impl Default for RowCursor {
    fn default() -> Self {
        Self::starting_at(0)
    }
}

impl RowCursor {
    /// A cursor whose first free row is `row`.
    #[must_use]
    pub const fn starting_at(row: usize) -> Self {
        Self {
            next: row,
            end: usize::MAX,
        }
    }

    /// A cursor over the rows `[start, end)`.
    #[must_use]
    pub const fn bounded(start: usize, end: usize) -> Self {
        Self { next: start, end }
    }

    /// The first free row.
    #[must_use]
    pub const fn next_row(self) -> usize {
        self.next
    }

    /// The end of the cursor's rows (`usize::MAX` when unbounded).
    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }

    /// Reserves `rows` consecutive rows and returns the first.
    ///
    /// # Errors
    ///
    /// [`Error::BoundsFailure`] when the row index overflows or the rows
    /// pass the end.
    pub fn take(&mut self, rows: usize) -> Result<usize, Error> {
        let start = self.next;
        let next = start
            .checked_add(rows)
            .filter(|next| *next <= self.end)
            .ok_or(Error::BoundsFailure)?;
        self.next = next;
        Ok(start)
    }
}

/// A deterministic reservation cursor shared by chips using the same columns.
/// Clones retain the same cursor within one synthesis; they must never be
/// retained across independent synthesis runs. Reservations are single-threaded
/// and structural, with the same checked bound as [`RowCursor`].
#[derive(Clone, Debug)]
pub struct SharedRows {
    next: std::rc::Rc<std::cell::Cell<usize>>,
    end: usize,
}
impl SharedRows {
    /// Shares a fresh cursor over the supplied interval.
    #[must_use]
    pub fn new(rows: RowCursor) -> Self {
        Self {
            next: std::rc::Rc::new(std::cell::Cell::new(rows.next_row())),
            end: rows.end(),
        }
    }
    /// The next unreserved row, including reservations by other owners.
    #[must_use]
    pub fn next_row(&self) -> usize {
        self.next.get()
    }
    pub(crate) const fn is_bounded(&self) -> bool {
        self.end != usize::MAX
    }

    /// Reserves one consecutive interval. A refusal leaves every clone intact.
    ///
    /// # Errors
    /// Arithmetic overflow or the interval's fixed end would be exceeded.
    pub fn take(&self, rows: usize) -> Result<usize, Error> {
        let start = self.next.get();
        let next = start
            .checked_add(rows)
            .filter(|next| *next <= self.end)
            .ok_or(Error::BoundsFailure)?;
        self.next.set(next);
        Ok(start)
    }
}

/// Assigns `value` to `column` at `row` and wraps it as a [`Word`].
pub(crate) fn assign_word<F: PastaField>(
    region: &mut Region<'_, F>,
    column: Column<Advice>,
    row: usize,
    value: Value<F>,
) -> Result<Word<F>, Error> {
    let assigned = region.assign_advice(column, row, value)?;
    Ok(Word::new(AssignedCell::new(value, assigned.cell())))
}

/// Assigns a constant to `column` at `row`, constrained through the
/// constants column.
pub(crate) fn assign_constant<F: PastaField>(
    region: &mut Region<'_, F>,
    column: Column<Advice>,
    row: usize,
    constant: F,
) -> Result<Word<F>, Error> {
    let assigned = region.assign_advice_from_constant(String::new, column, row, constant)?;
    Ok(Word::new(assigned))
}

/// Copies `word` into `column` at `row`: assigns its value, then constrains
/// the new cell to equal it (the halo2 `copy_advice` order).
pub(crate) fn copy_word<F: PastaField>(
    region: &mut Region<'_, F>,
    word: &Word<F>,
    column: Column<Advice>,
    row: usize,
) -> Result<Word<F>, Error> {
    let copy = assign_word(region, column, row, word.value())?;
    region.constrain_equal(copy.cell(), word.cell())?;
    Ok(copy)
}

/// The value of a known [`Value`], for native cross-checks in tests and
/// diagnostics (`None` during key generation).
pub fn known<V: Clone>(value: &Value<V>) -> Option<V> {
    let mut out = None;
    let _ = value.as_ref().map(|inner| out = Some(inner.clone()));
    out
}

#[cfg(test)]
mod tests {
    use ff::{Field, PrimeField};
    use iroha_pasta::{Fp, Fq};

    use super::*;

    #[test]
    fn row_cursor_reserves_disjoint_ranges_and_rejects_overflow() {
        let mut cursor = RowCursor::default();
        assert_eq!(cursor.take(3), Ok(0));
        assert_eq!(cursor.take(0), Ok(3));
        assert_eq!(cursor.take(2), Ok(3));
        assert_eq!(cursor.next_row(), 5);
        let mut full = RowCursor::starting_at(usize::MAX);
        assert_eq!(full.take(1), Err(Error::BoundsFailure));
        assert_eq!(full.next_row(), usize::MAX);
        // A bounded cursor stops at its end and is unchanged by a refusal.
        let mut bounded = RowCursor::bounded(10, 14);
        assert_eq!(bounded.end(), 14);
        assert_eq!(bounded.take(3), Ok(10));
        assert_eq!(bounded.take(2), Err(Error::BoundsFailure));
        assert_eq!(bounded.next_row(), 13);
        assert_eq!(bounded.take(1), Ok(13));
        assert_eq!(bounded.take(0), Ok(14));
        assert_eq!(RowCursor::default().end(), usize::MAX);
    }

    #[test]
    fn shared_rows_preserve_disjoint_reservations_and_refusal() {
        let owner = SharedRows::new(RowCursor::bounded(8, 16));
        let second = owner.clone();
        assert_eq!(owner.take(3), Ok(8));
        assert_eq!(second.take(2), Ok(11));
        assert_eq!(owner.next_row(), 13);
        assert_eq!(second.take(4), Err(Error::BoundsFailure));
        assert_eq!(owner.next_row(), 13);
        assert_eq!(owner.take(3), Ok(13));
        assert_eq!(second.next_row(), 16);
        let independent = SharedRows::new(RowCursor::starting_at(0));
        assert_eq!(independent.next_row(), 0);
    }

    #[test]
    fn integer_views_of_field_elements() {
        assert_eq!(to_u128(&Fp::from_u128(u128::MAX)), Some(u128::MAX));
        assert_eq!(to_u128(&-Fq::ONE), None);
        assert_eq!(low_u128(&Fp::from(7u64)), 7);
        let two_128 = Fp::from_u128(u128::MAX) + Fp::ONE;
        assert_eq!(to_u128(&two_128), None);
        assert_eq!(low_u128(&two_128), 0);
    }

    #[test]
    fn known_reads_known_values_only() {
        assert_eq!(known(&Value::known(5u8)), Some(5));
        assert_eq!(known(&Value::<u8>::unknown()), None);
    }
}
