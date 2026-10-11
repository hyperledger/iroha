//! The byte tape: one row per byte on a primary and a secondary column.
//!
//! # Relation
//!
//! A run of `n` bytes occupies rows `r .. r + n` of the two equality-enabled
//! advice columns `z` (primary) and `w` (secondary).
//!
//! The primary column is cut into segments of `1..=31` bytes. Inside a
//! segment `[s, s + L)` it holds the little-endian running sums
//! `z_j = sum_(i >= j) b_i 256^(i - j)`:
//!
//! - rows `s .. s + L - 1` (`q_z_next`): the byte is `z_j - 256 z_(j+1)`;
//! - row `s + L - 1` (`q_z_last`): the byte is `z_j`.
//!
//! The lookup `q_z_next (z - 256 z_next) + q_z_last z` into the byte table
//! `0 .. 256` puts every byte in `[0, 256)`, so by induction from the last
//! row every `z_j` is the integer `sum_(i >= j) b_i 256^(i - j) < 256^(L - j)`
//! (no wrap: `256^31 < p`), and the segment word `z_s` is the little-endian
//! integer of the segment's bytes. Rows outside a run have no selector, and
//! the lookup input there is `0`, which is in the table.
//!
//! The secondary column recomposes the same bytes along its own segments,
//! little-endian (`q_w_next` then `q_w_single`, word at the first row) or
//! big-endian (`q_w_single` then `q_w_prev`, `w_j = 256 w_(j-1) + b_j`, word at
//! the last row). Its byte expression
//! `q_w_next (w - 256 w_next) + q_w_prev (w - 256 w_prev) + q_w_single w` must
//! equal the primary byte expression on every row it covers:
//!
//! ```text
//! (q_w_next + q_w_prev + q_w_single) (q_z_next (z - 256 z_next) + q_z_last z)
//!     - (q_w_next (w - 256 w_next) + q_w_prev (w - 256 w_prev) + q_w_single w) = 0
//! ```
//!
//! so each secondary word is the integer of the same bytes in its order, and
//! below `256^L`. Secondary segments may leave rows uncovered.
//!
//! | constraint | degree |
//! | --- | --- |
//! | primary byte lookup (input degree 2) | 5 |
//! | secondary link gate | 3 |
//!
//! `z` is queried at rotations `0, 1` and `w` at `-1, 0, 1`, inside the
//! default blinding budget. All five selectors are complex (they appear
//! inside sums and in the lookup).

use iroha_pasta::PastaField;
use iroha_plonk::{
    cs::{Advice, Column, ConstraintSystem, Rotation, Selector, TableColumn},
    frontend::{Error, Layouter, Region, Value},
};

use super::{BYTE_TABLE_ROWS, BoundedBytes, MAX_SEGMENT_BYTES, collect_bytes};
use crate::cells::{RowCursor, Word, assign_word};

/// The byte order of a segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ByteOrder {
    /// The first byte is the least significant.
    Little,
    /// The first byte is the most significant.
    Big,
}

/// A segment of a run: `len` bytes from run offset `start`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SegmentSpec {
    /// The run offset of the first byte.
    pub start: usize,
    /// The byte length (`1..=31`).
    pub len: usize,
    /// The byte order of the segment word.
    pub order: ByteOrder,
}

impl SegmentSpec {
    /// A little-endian segment.
    #[must_use]
    pub const fn little(start: usize, len: usize) -> Self {
        Self {
            start,
            len,
            order: ByteOrder::Little,
        }
    }

    /// A big-endian segment.
    #[must_use]
    pub const fn big(start: usize, len: usize) -> Self {
        Self {
            start,
            len,
            order: ByteOrder::Big,
        }
    }

    /// One past the last byte.
    #[must_use]
    pub const fn end(&self) -> usize {
        self.start + self.len
    }
}

/// Native reference of a segment word: the integer of `bytes` (at most 31)
/// in `order`, or `None` for a longer slice.
#[must_use]
pub fn segment_value<F: PastaField>(bytes: &[u8], order: ByteOrder) -> Option<F> {
    match order {
        ByteOrder::Little => super::le_value(bytes),
        ByteOrder::Big => {
            let reversed: Vec<u8> = bytes.iter().rev().copied().collect();
            super::le_value(&reversed)
        }
    }
}

/// The column entries of one segment, in row order: the little-endian
/// running sums from the end, or the big-endian prefix sums.
fn segment_entries<F: PastaField>(bytes: &[u8], spec: SegmentSpec) -> Vec<F> {
    let radix = F::from(256_u64);
    let segment = bytes.get(spec.start..spec.end()).unwrap_or(&[]);
    let mut entries = vec![F::ZERO; segment.len()];
    let mut acc = F::ZERO;
    match spec.order {
        ByteOrder::Little => {
            for (entry, byte) in entries.iter_mut().zip(segment).rev() {
                acc = acc * radix + F::from(u64::from(*byte));
                *entry = acc;
            }
        }
        ByteOrder::Big => {
            for (entry, byte) in entries.iter_mut().zip(segment) {
                acc = acc * radix + F::from(u64::from(*byte));
                *entry = acc;
            }
        }
    }
    entries
}

/// Columns, table and selectors of the byte tape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BytesConfig {
    z: Column<Advice>,
    w: Column<Advice>,
    table: TableColumn,
    q_z_next: Selector,
    q_z_last: Selector,
    q_w_next: Selector,
    q_w_prev: Selector,
    q_w_single: Selector,
}

impl BytesConfig {
    /// Configures the tape on `z` (primary) and `w` (secondary), both made
    /// equality-enabled, with a new 256-row byte table.
    pub fn configure<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        z: Column<Advice>,
        w: Column<Advice>,
    ) -> Self {
        meta.enable_equality(z);
        meta.enable_equality(w);
        let table = meta.lookup_table_column();
        let primary_step = meta.complex_selector();
        let primary_last = meta.complex_selector();
        let little_step = meta.complex_selector();
        let big_step = meta.complex_selector();
        let single = meta.complex_selector();
        let radix = F::from(256_u64);
        meta.lookup("bytes primary byte", |cells| {
            let step = cells.query_selector(primary_step);
            let last = cells.query_selector(primary_last);
            let cur = cells.query_advice(z, Rotation::cur());
            let following = cells.query_advice(z, Rotation::next());
            vec![(step * (cur.clone() - following * radix) + last * cur, table)]
        });
        meta.create_gate("bytes secondary link", |cells| {
            let step = cells.query_selector(primary_step);
            let last = cells.query_selector(primary_last);
            let little = cells.query_selector(little_step);
            let big = cells.query_selector(big_step);
            let lone = cells.query_selector(single);
            let primary_here = cells.query_advice(z, Rotation::cur());
            let primary_after = cells.query_advice(z, Rotation::next());
            let secondary_here = cells.query_advice(w, Rotation::cur());
            let secondary_after = cells.query_advice(w, Rotation::next());
            let secondary_before = cells.query_advice(w, Rotation::prev());
            let primary =
                step * (primary_here.clone() - primary_after * radix) + last * primary_here;
            let secondary = little.clone() * (secondary_here.clone() - secondary_after * radix)
                + big.clone() * (secondary_here.clone() - secondary_before * radix)
                + lone.clone() * secondary_here;
            vec![(
                "secondary byte = primary byte",
                (little + big + lone) * primary - secondary,
            )]
        });
        Self {
            z,
            w,
            table,
            q_z_next: primary_step,
            q_z_last: primary_last,
            q_w_next: little_step,
            q_w_prev: big_step,
            q_w_single: single,
        }
    }

    /// The primary column.
    #[must_use]
    pub const fn primary(&self) -> Column<Advice> {
        self.z
    }

    /// The secondary column.
    #[must_use]
    pub const fn secondary(&self) -> Column<Advice> {
        self.w
    }
}

/// A segment laid out on a tape column, with its word.
#[derive(Clone, Debug)]
pub struct Segment<F: PastaField> {
    word: Word<F>,
    spec: SegmentSpec,
}

impl<F: PastaField> Segment<F> {
    /// The segment word: the integer of its bytes in its order, below
    /// `256^len`.
    #[must_use]
    pub const fn word(&self) -> &Word<F> {
        &self.word
    }

    /// The segment's place in its run.
    #[must_use]
    pub const fn spec(&self) -> SegmentSpec {
        self.spec
    }

    /// The word as bounded little-endian bytes (`None` for a big-endian
    /// segment of more than one byte, whose word is not the little-endian
    /// integer of its bytes).
    #[must_use]
    pub fn bounded(&self) -> Option<BoundedBytes<F>> {
        (self.spec.order == ByteOrder::Little || self.spec.len == 1)
            .then(|| BoundedBytes::new(self.word.clone(), self.spec.len))
    }
}

/// A run of bytes laid out on the tape.
#[derive(Clone, Debug)]
pub struct ByteRun<F: PastaField> {
    first_row: usize,
    len: usize,
    primary: Vec<Segment<F>>,
    secondary: Vec<Segment<F>>,
}

impl<F: PastaField> ByteRun<F> {
    /// The row of the first byte.
    #[must_use]
    pub const fn first_row(&self) -> usize {
        self.first_row
    }

    /// The number of bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the run is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The primary segments in run order.
    #[must_use]
    pub fn primary(&self) -> &[Segment<F>] {
        &self.primary
    }

    /// The secondary segments in run order.
    #[must_use]
    pub fn secondary(&self) -> &[Segment<F>] {
        &self.secondary
    }

    /// The secondary segment laid out exactly as `spec`.
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] when the run has no such segment.
    pub fn secondary_segment(&self, spec: SegmentSpec) -> Result<&Segment<F>, Error> {
        let index = self
            .secondary
            .binary_search_by_key(&spec.start, |segment| segment.spec.start)
            .map_err(|_| Error::Synthesis)?;
        self.secondary
            .get(index)
            .filter(|segment| segment.spec == spec)
            .ok_or(Error::Synthesis)
    }
}

/// Validates a run layout: primary lengths in `1..=31` summing to `len`,
/// secondary segments in `1..=31`, in increasing order, disjoint and inside
/// the run. Returns the primary segments.
fn validate_layout(
    len: usize,
    primary: &[usize],
    secondary: &[SegmentSpec],
) -> Result<Vec<SegmentSpec>, Error> {
    let mut specs = Vec::with_capacity(primary.len());
    let mut start = 0_usize;
    for length in primary {
        if !(1..=MAX_SEGMENT_BYTES).contains(length) {
            return Err(Error::Synthesis);
        }
        specs.push(SegmentSpec::little(start, *length));
        start = start.checked_add(*length).ok_or(Error::Synthesis)?;
    }
    if start != len {
        return Err(Error::Synthesis);
    }
    let mut free = 0_usize;
    for spec in secondary {
        let end = spec.start.checked_add(spec.len).ok_or(Error::Synthesis)?;
        if !(1..=MAX_SEGMENT_BYTES).contains(&spec.len) || spec.start < free || end > len {
            return Err(Error::Synthesis);
        }
        free = end;
    }
    Ok(specs)
}

/// The byte tape chip: runs allocated from its own row cursor.
#[derive(Clone, Debug)]
pub struct BytesChip<F: PastaField> {
    config: BytesConfig,
    rows: RowCursor,
    _marker: core::marker::PhantomData<F>,
}

impl<F: PastaField> BytesChip<F> {
    /// A chip whose first row is 0.
    #[must_use]
    pub const fn new(config: BytesConfig) -> Self {
        Self::starting_at(config, 0)
    }

    /// A chip whose first row is `row`.
    #[must_use]
    pub const fn starting_at(config: BytesConfig, row: usize) -> Self {
        Self {
            config,
            rows: RowCursor::starting_at(row),
            _marker: core::marker::PhantomData,
        }
    }

    /// The configuration.
    #[must_use]
    pub const fn config(&self) -> &BytesConfig {
        &self.config
    }

    /// The first row not used yet.
    #[must_use]
    pub const fn next_row(&self) -> usize {
        self.rows.next_row()
    }

    /// Loads the byte table `0 .. 256`.
    ///
    /// # Errors
    ///
    /// [`Error`] when the table does not fit the usable rows.
    pub fn load_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let table = self.config.table;
        layouter.assign_table(
            || "byte table",
            |mut cells| {
                for row in 0..BYTE_TABLE_ROWS {
                    let value = u64::try_from(row).map_err(|_| Error::BoundsFailure)?;
                    cells.assign_cell(|| "byte", table, row, || Value::known(F::from(value)))?;
                }
                Ok(())
            },
        )
    }

    /// Lays out `bytes` as one run: the primary column cut into segments of
    /// the lengths `primary` (each `1..=31`, summing to the run length) and
    /// the secondary column cut into `secondary` (increasing, disjoint, each
    /// `1..=31` bytes, inside the run).
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] for an invalid layout, and [`Error`] from the
    /// layout (rows out of range, unknown values while proving).
    pub fn run(
        &mut self,
        region: &mut Region<'_, F>,
        bytes: &[Value<u8>],
        primary: &[usize],
        secondary: &[SegmentSpec],
    ) -> Result<ByteRun<F>, Error> {
        let primary_specs = validate_layout(bytes.len(), primary, secondary)?;
        let first_row = self.rows.take(bytes.len())?;
        let known = collect_bytes(bytes);
        let primary = self.lay_segments(region, first_row, &known, &primary_specs, true)?;
        let secondary = self.lay_segments(region, first_row, &known, secondary, false)?;
        Ok(ByteRun {
            first_row,
            len: bytes.len(),
            primary,
            secondary,
        })
    }

    /// Lays out the segments of one column and enables their selectors.
    fn lay_segments(
        &self,
        region: &mut Region<'_, F>,
        first_row: usize,
        bytes: &Value<Vec<u8>>,
        specs: &[SegmentSpec],
        primary: bool,
    ) -> Result<Vec<Segment<F>>, Error> {
        let column = if primary {
            self.config.z
        } else {
            self.config.w
        };
        let mut segments = Vec::with_capacity(specs.len());
        for spec in specs {
            let entries = bytes
                .as_ref()
                .map(|bytes| segment_entries::<F>(bytes, *spec))
                .transpose_vec(spec.len)?;
            let start = first_row
                .checked_add(spec.start)
                .ok_or(Error::BoundsFailure)?;
            let mut words = Vec::with_capacity(spec.len);
            for (offset, entry) in entries.into_iter().enumerate() {
                words.push(assign_word(region, column, start + offset, entry)?);
            }
            let last = start + spec.len - 1;
            let word_index = match (primary, spec.order) {
                (true, _) | (false, ByteOrder::Little) => {
                    let (next, end) = if primary {
                        (self.config.q_z_next, self.config.q_z_last)
                    } else {
                        (self.config.q_w_next, self.config.q_w_single)
                    };
                    for row in start..last {
                        next.enable(region, row)?;
                    }
                    end.enable(region, last)?;
                    0
                }
                (false, ByteOrder::Big) => {
                    self.config.q_w_single.enable(region, start)?;
                    for row in start + 1..=last {
                        self.config.q_w_prev.enable(region, row)?;
                    }
                    spec.len - 1
                }
            };
            let word = words.swap_remove(word_index);
            segments.push(Segment { word, spec: *spec });
        }
        Ok(segments)
    }
}

#[cfg(test)]
mod unit_tests {
    use iroha_pasta::{Fp, Fq};

    use super::*;

    #[test]
    fn segment_specs_and_values() {
        let spec = SegmentSpec::little(3, 4);
        assert_eq!(spec.end(), 7);
        assert_eq!(SegmentSpec::big(1, 2).order, ByteOrder::Big);
        let bytes = [0x01, 0x02, 0x03];
        assert_eq!(
            segment_value::<Fp>(&bytes, ByteOrder::Little),
            Some(Fp::from(0x03_0201))
        );
        assert_eq!(
            segment_value::<Fq>(&bytes, ByteOrder::Big),
            Some(Fq::from(0x01_0203))
        );
        assert_eq!(segment_value::<Fp>(&[0; 32], ByteOrder::Little), None);
    }

    #[test]
    fn segment_entries_are_running_sums() {
        let bytes = [9, 0x10, 0x20, 0x30, 7];
        let little = segment_entries::<Fp>(&bytes, SegmentSpec::little(1, 3));
        assert_eq!(
            little,
            vec![Fp::from(0x30_2010), Fp::from(0x3020), Fp::from(0x30)]
        );
        let big = segment_entries::<Fp>(&bytes, SegmentSpec::big(1, 3));
        assert_eq!(
            big,
            vec![Fp::from(0x10), Fp::from(0x1020), Fp::from(0x10_2030)]
        );
        // The word of a little-endian segment is its first entry, of a
        // big-endian one its last.
        assert_eq!(
            Some(little[0]),
            segment_value(&bytes[1..4], ByteOrder::Little)
        );
        assert_eq!(Some(big[2]), segment_value(&bytes[1..4], ByteOrder::Big));
    }

    #[test]
    fn layouts_are_validated() {
        let ok = validate_layout(5, &[2, 3], &[SegmentSpec::little(0, 2)]);
        assert_eq!(
            ok,
            Ok(vec![SegmentSpec::little(0, 2), SegmentSpec::little(2, 3)])
        );
        assert_eq!(validate_layout(0, &[], &[]), Ok(Vec::new()));
        // Lengths must cover the run exactly and stay in 1..=31.
        assert_eq!(validate_layout(5, &[2, 2], &[]), Err(Error::Synthesis));
        assert_eq!(validate_layout(5, &[0, 5], &[]), Err(Error::Synthesis));
        assert_eq!(validate_layout(32, &[32], &[]), Err(Error::Synthesis));
        // Secondary segments must be increasing, disjoint and inside the run.
        let overlap = [SegmentSpec::little(0, 3), SegmentSpec::big(2, 2)];
        assert_eq!(validate_layout(5, &[5], &overlap), Err(Error::Synthesis));
        let outside = [SegmentSpec::little(4, 2)];
        assert_eq!(validate_layout(5, &[5], &outside), Err(Error::Synthesis));
        let long = [SegmentSpec::little(0, 32)];
        assert_eq!(validate_layout(40, &[31, 9], &long), Err(Error::Synthesis));
        let unordered = [SegmentSpec::little(3, 1), SegmentSpec::little(0, 1)];
        assert_eq!(validate_layout(5, &[5], &unordered), Err(Error::Synthesis));
    }
}
