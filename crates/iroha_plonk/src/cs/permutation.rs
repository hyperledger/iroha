//! The halo2 permutation (equality) argument and its copy assembly.
//!
//! [`PermutationArgument`] lists the equality-enabled columns in
//! `enable_equality` order. With degree `d` the columns split into sets of
//! `d - 2` consecutive columns, one grand product per set (spec section 2).
//!
//! [`PermutationAssembly`] records copy constraints with the vendored
//! union-find, so the resulting permutation, and therefore the `sigma`
//! commitments of the verifying key, equal halo2's: cells are numbered
//! `column * n + row`; a copy within one cycle is a no-op; otherwise the
//! smaller cycle is merged into the larger one (the left one survives a tie),
//! relabelled, and the two cells' mapping entries are swapped.

use core::{fmt, ops::Range};

use super::{
    descriptor::Blake2bPersonal,
    expression::{Any, Column},
};

/// `BLAKE2b` personalization of [`PermutationAssembly::mapping_digest`].
pub const COPY_MAPPING_PERSONA: &[u8; 16] = b"PIPA-v1-CopyMapD";

/// The columns of the permutation argument.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PermutationArgument {
    columns: Vec<Column<Any>>,
}

impl PermutationArgument {
    /// An argument over no columns.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            columns: Vec::new(),
        }
    }

    /// Adds `column` unless it is already present.
    pub fn add_column(&mut self, column: Column<Any>) {
        if !self.columns.contains(&column) {
            self.columns.push(column);
        }
    }

    /// The equality columns in `enable_equality` order.
    #[must_use]
    pub fn columns(&self) -> &[Column<Any>] {
        &self.columns
    }

    /// Position of `column` in the argument.
    #[must_use]
    pub fn position(&self, column: Column<Any>) -> Option<usize> {
        self.columns.iter().position(|c| *c == column)
    }

    /// The degree the permutation constraints need on their own.
    pub const REQUIRED_DEGREE: usize = 3;

    /// The column ranges of the grand-product sets for circuit degree `degree`:
    /// set `s` covers `[s (d-2), min((s+1)(d-2), m))`. `None` when `degree < 3`.
    #[must_use]
    pub fn sets(&self, degree: usize) -> Option<Vec<Range<usize>>> {
        let chunk = degree.checked_sub(2).filter(|chunk| *chunk > 0)?;
        let total = self.columns.len();
        let mut sets = Vec::with_capacity(total.div_ceil(chunk));
        let mut start = 0;
        while start < total {
            let end = start.saturating_add(chunk).min(total);
            sets.push(start..end);
            start = end;
        }
        Some(sets)
    }
}

/// A copy constraint could not be recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermutationError {
    /// The column is not equality-enabled.
    ColumnNotInPermutation(Column<Any>),
    /// The row is outside the domain.
    RowOutOfBounds {
        /// The offending row.
        row: usize,
        /// The domain size.
        n: usize,
    },
    /// `columns * n` overflows `usize`.
    TooManyCells,
}

impl fmt::Display for PermutationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ColumnNotInPermutation(column) => write!(
                f,
                "{:?} column {} is not equality-enabled",
                column.column_type(),
                column.index()
            ),
            Self::RowOutOfBounds { row, n } => write!(f, "row {row} is outside a domain of {n}"),
            Self::TooManyCells => f.write_str("the permutation has more cells than usize holds"),
        }
    }
}

impl std::error::Error for PermutationError {}

/// Explicit union-find arrays over `columns * n` cells.
#[derive(Clone, Debug, PartialEq, Eq)]
struct UnionFind {
    /// The permutation: cell -> next cell of its cycle.
    mapping: Vec<usize>,
    /// Distinguished representative of each cell's cycle.
    aux: Vec<usize>,
    /// Cycle sizes, meaningful at representatives.
    sizes: Vec<usize>,
}

impl UnionFind {
    /// The identity over `cells` cells.
    fn identity(cells: usize) -> Self {
        Self {
            mapping: (0..cells).collect(),
            aux: (0..cells).collect(),
            sizes: vec![1; cells],
        }
    }
}

/// Copy constraints recorded as the vendored permutation cycles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermutationAssembly {
    columns: Vec<Column<Any>>,
    n: usize,
    cells: usize,
    /// `None` while every cell maps to itself (until the first nontrivial
    /// copy), as in the vendored assembly.
    union_find: Option<UnionFind>,
}

impl PermutationAssembly {
    /// An identity permutation over `argument`'s columns and `n` rows.
    ///
    /// # Errors
    ///
    /// [`PermutationError::TooManyCells`] when `columns * n` overflows.
    pub fn new(n: usize, argument: &PermutationArgument) -> Result<Self, PermutationError> {
        let cells = argument
            .columns
            .len()
            .checked_mul(n)
            .ok_or(PermutationError::TooManyCells)?;
        Ok(Self {
            columns: argument.columns.clone(),
            n,
            cells,
            union_find: None,
        })
    }

    /// The equality columns.
    #[must_use]
    pub fn columns(&self) -> &[Column<Any>] {
        &self.columns
    }

    /// Number of rows per column.
    #[must_use]
    pub const fn rows(&self) -> usize {
        self.n
    }

    /// Whether no nontrivial copy has been recorded.
    #[must_use]
    pub const fn is_identity(&self) -> bool {
        self.union_find.is_none()
    }

    /// Records the copy constraint `left == right`.
    ///
    /// # Errors
    ///
    /// [`PermutationError`] when a column is not equality-enabled or a row is
    /// outside the domain.
    pub fn copy(
        &mut self,
        left_column: Column<Any>,
        left_row: usize,
        right_column: Column<Any>,
        right_row: usize,
    ) -> Result<(), PermutationError> {
        let left_position = self
            .columns
            .iter()
            .position(|c| *c == left_column)
            .ok_or(PermutationError::ColumnNotInPermutation(left_column))?;
        let right_position = self
            .columns
            .iter()
            .position(|c| *c == right_column)
            .ok_or(PermutationError::ColumnNotInPermutation(right_column))?;
        for row in [left_row, right_row] {
            if row >= self.n {
                return Err(PermutationError::RowOutOfBounds { row, n: self.n });
            }
        }
        // position < columns and row < n, so the products cannot overflow
        // (`columns * n` was checked in `new`).
        let left_cell = left_position * self.n + left_row;
        let right_cell = right_position * self.n + right_row;
        if left_cell == right_cell {
            return Ok(());
        }
        let cells = self.cells;
        let UnionFind {
            mapping,
            aux,
            sizes,
        } = self
            .union_find
            .get_or_insert_with(|| UnionFind::identity(cells));
        let mut left_cycle = aux[left_cell];
        let mut right_cycle = aux[right_cell];
        if left_cycle == right_cycle {
            return Ok(());
        }
        if sizes[left_cycle] < sizes[right_cycle] {
            core::mem::swap(&mut left_cycle, &mut right_cycle);
        }
        // Cycle sizes sum to at most `cells`, so the addition cannot overflow.
        sizes[left_cycle] += sizes[right_cycle];
        let mut i = right_cycle;
        loop {
            aux[i] = left_cycle;
            i = mapping[i];
            if i == right_cycle {
                break;
            }
        }
        mapping.swap(left_cell, right_cell);
        Ok(())
    }

    /// The cell `(column position, row)` that `(column, row)` maps to, or
    /// `None` outside the assembly.
    #[must_use]
    pub fn mapping(&self, column: usize, row: usize) -> Option<(usize, usize)> {
        if column >= self.columns.len() || row >= self.n {
            return None;
        }
        let cell = column * self.n + row;
        let target = self
            .union_find
            .as_ref()
            .map_or(cell, |union_find| union_find.mapping[cell]);
        Some((target / self.n, target % self.n))
    }

    /// A digest of the permutation: `BLAKE2b(32, "PIPA-v1-CopyMapD",
    /// u64_le(columns) || u64_le(n) || (u32_le(column') || u32_le(row')) for
    /// every cell in column-major order)`, where `(column', row')` is the
    /// cell's image. Equal digests mean equal permutations, and so equal
    /// `sigma` polynomials, so a proving key stores this digest instead of
    /// recomputing field-valued `sigma` columns to check a circuit. It
    /// streams in constant memory.
    #[must_use]
    pub fn mapping_digest(&self) -> [u8; 32] {
        match self.mapping_digest_with(&|| Ok::<(), core::convert::Infallible>(())) {
            Ok(value) => value,
            Err(error) => match error {},
        }
    }

    /// Hash the exact copy mapping with bounded cancellation checkpoints.
    ///
    /// # Errors
    /// [`iroha_pasta::Cancelled`] when the supplied token is cancelled.
    pub fn mapping_digest_cancellable(
        &self,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<[u8; 32], iroha_pasta::Cancelled> {
        self.mapping_digest_with(&|| iroha_pasta::CancellationToken::checkpoint(cancellation))
    }

    fn mapping_digest_with<E>(
        &self,
        checkpoint: &impl Fn() -> Result<(), E>,
    ) -> Result<[u8; 32], E> {
        /// Cells hashed per update.
        const CELLS_PER_UPDATE: usize = 512;
        checkpoint()?;
        let mut hasher = Blake2bPersonal::<32>::new(COPY_MAPPING_PERSONA);
        let count = |value: usize| u64::try_from(value).unwrap_or(u64::MAX).to_le_bytes();
        hasher.update(&count(self.columns.len()));
        hasher.update(&count(self.n));
        let mut chunk = Vec::with_capacity(8 * CELLS_PER_UPDATE);
        for cell in 0..self.cells {
            if cell % CELLS_PER_UPDATE == 0 {
                checkpoint()?;
            }
            let target = self
                .union_find
                .as_ref()
                .map_or(cell, |union_find| union_find.mapping[cell]);
            // Columns are at most 65,535 and rows below 2^28 (spec section 1).
            for coordinate in [target / self.n, target % self.n] {
                chunk.extend_from_slice(
                    &u32::try_from(coordinate).unwrap_or(u32::MAX).to_le_bytes(),
                );
            }
            if chunk.len() == chunk.capacity() {
                hasher.update(&chunk);
                chunk.clear();
            }
        }
        hasher.update(&chunk);
        checkpoint()?;
        Ok(hasher.finalize())
    }

    /// Whether the cell is in a cycle of length at least two (it is copied).
    #[must_use]
    pub fn is_copied(&self, column: usize, row: usize) -> bool {
        self.mapping(column, row)
            .is_some_and(|target| target != (column, row))
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn copy_digest_cancellation_streams_then_retries_identically() {
        use iroha_pasta::CancellationToken;
        use std::cell::Cell;
        let a = Column::new(0, Advice).into();
        let b = Column::new(0, Fixed).into();
        let mut assembly = PermutationAssembly::new(4096, &argument(&[a, b])).unwrap();
        assembly.copy(a, 2, b, 3072).unwrap();
        let token = CancellationToken::new();
        let calls = Cell::new(0);
        let result = assembly.mapping_digest_with(&|| {
            let current = calls.get() + 1;
            calls.set(current);
            if current == 4 {
                token.cancel();
            }
            token.check()
        });
        assert_eq!(calls.get(), 4);
        assert_eq!(result, Err(iroha_pasta::Cancelled));
        assert_eq!(
            assembly.mapping_digest_cancellable(Some(&token)),
            Err(iroha_pasta::Cancelled)
        );
        let fresh = CancellationToken::new();
        assert_eq!(
            assembly.mapping_digest_cancellable(Some(&fresh)).unwrap(),
            assembly.mapping_digest()
        );
    }

    use super::*;
    use crate::cs::expression::{Advice, Fixed, Instance};

    fn argument(columns: &[Column<Any>]) -> PermutationArgument {
        let mut argument = PermutationArgument::new();
        for column in columns {
            argument.add_column(*column);
        }
        argument
    }

    #[test]
    fn add_column_deduplicates_and_keeps_order() {
        let a: Column<Any> = Column::new(0, Advice).into();
        let f: Column<Any> = Column::new(0, Fixed).into();
        let mut argument = argument(&[a, f, a]);
        argument.add_column(f);
        assert_eq!(argument.columns(), &[a, f]);
        assert_eq!(argument.position(f), Some(1));
        assert_eq!(argument.position(Column::new(3, Any::Instance)), None);
        assert_eq!(PermutationArgument::REQUIRED_DEGREE, 3);
    }

    #[test]
    fn sets_chunk_by_degree_minus_two() {
        let columns: Vec<Column<Any>> = (0..5).map(|i| Column::new(i, Any::Advice)).collect();
        let argument = argument(&columns);
        let bounds = |degree: usize| {
            argument.sets(degree).map(|sets| {
                sets.into_iter()
                    .map(|set| (set.start, set.end))
                    .collect::<Vec<_>>()
            })
        };
        assert_eq!(bounds(4), Some(vec![(0, 2), (2, 4), (4, 5)]));
        assert_eq!(bounds(7), Some(vec![(0, 5)]));
        assert_eq!(
            bounds(3),
            Some(vec![(0, 1), (1, 2), (2, 3), (3, 4), (4, 5)])
        );
        assert_eq!(bounds(2), None);
        assert_eq!(PermutationArgument::new().sets(5).map(|s| s.len()), Some(0));
    }

    /// Reference cycles: cells in the same cycle follow `mapping` around.
    fn cycle_of(assembly: &PermutationAssembly, start: (usize, usize)) -> Vec<(usize, usize)> {
        let mut cycle = vec![start];
        let mut next = assembly.mapping(start.0, start.1).expect("in range");
        while next != start {
            cycle.push(next);
            next = assembly.mapping(next.0, next.1).expect("in range");
        }
        cycle.sort_unstable();
        cycle
    }

    #[test]
    fn copies_merge_cycles_like_the_vendored_union_find() {
        let a: Column<Any> = Column::new(0, Advice).into();
        let i: Column<Any> = Column::new(0, Instance).into();
        let mut assembly = PermutationAssembly::new(4, &argument(&[a, i])).expect("small");
        assert!(assembly.is_identity());
        assembly.copy(a, 1, a, 1).expect("self copy");
        assert!(assembly.is_identity(), "a self copy stays implicit");
        assembly.copy(a, 0, i, 0).expect("copy");
        assert!(!assembly.is_identity());
        assert_eq!(assembly.mapping(0, 0), Some((1, 0)));
        assert_eq!(assembly.mapping(1, 0), Some((0, 0)));
        assembly.copy(a, 2, a, 0).expect("copy");
        assert_eq!(cycle_of(&assembly, (0, 0)), vec![(0, 0), (0, 2), (1, 0)]);
        // A repeated copy inside one cycle changes nothing.
        let before = assembly.clone();
        assembly.copy(i, 0, a, 2).expect("copy");
        assert_eq!(assembly, before);
        assert!(assembly.is_copied(0, 2));
        assert!(!assembly.is_copied(0, 3));
        assert_eq!(assembly.mapping(2, 0), None);
        assert_eq!(assembly.columns(), &[a, i]);
        assert_eq!(assembly.rows(), 4);
    }

    #[test]
    fn exact_vendored_mapping_for_a_fixed_copy_sequence() {
        // Derived step by step from the vendored `Assembly::copy` algorithm
        // (the oracle crate compares against the vendored code itself):
        // (0,0)-(1,0), (1,1)-(0,1), (0,1)-(0,0) over 2 columns x 2 rows.
        let a: Column<Any> = Column::new(0, Advice).into();
        let b: Column<Any> = Column::new(1, Advice).into();
        let mut assembly = PermutationAssembly::new(2, &argument(&[a, b])).expect("small");
        assembly.copy(a, 0, b, 0).expect("copy");
        assembly.copy(b, 1, a, 1).expect("copy");
        assembly.copy(a, 1, a, 0).expect("copy");
        // Cells: a0=0, a1=1, b0=2, b1=3.
        // copy(0,2): cycles {0},{2} sizes tie -> left 0 survives; swap -> m=[2,1,0,3].
        // copy(3,1): tie -> left 3 survives; swap -> m=[2,3,0,1].
        // copy(1,0): aux[1]=3 (size 2), aux[0]=0 (size 2); tie -> left (3) survives;
        //   swap m[1], m[0] -> m=[3,2,0,1].
        let flat: Vec<(usize, usize)> = (0..2)
            .flat_map(|c| (0..2).map(move |r| (c, r)))
            .map(|(c, r)| assembly.mapping(c, r).expect("in range"))
            .collect();
        assert_eq!(flat, vec![(1, 1), (1, 0), (0, 0), (0, 1)]);
    }

    #[test]
    fn copy_errors_are_typed() {
        let a: Column<Any> = Column::new(0, Advice).into();
        let other: Column<Any> = Column::new(1, Advice).into();
        let mut assembly = PermutationAssembly::new(4, &argument(&[a])).expect("small");
        assert_eq!(
            assembly.copy(a, 0, other, 0),
            Err(PermutationError::ColumnNotInPermutation(other))
        );
        assert_eq!(
            assembly.copy(a, 4, a, 0),
            Err(PermutationError::RowOutOfBounds { row: 4, n: 4 })
        );
        assert_eq!(
            PermutationAssembly::new(usize::MAX, &argument(&[a, other])),
            Err(PermutationError::TooManyCells)
        );
        for error in [
            PermutationError::TooManyCells,
            PermutationError::RowOutOfBounds { row: 1, n: 1 },
            PermutationError::ColumnNotInPermutation(a),
        ] {
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn mapping_digests_identify_the_permutation() {
        let columns: Vec<Column<Any>> = (0..2).map(|i| Column::new(i, Any::Advice)).collect();
        let identity = PermutationAssembly::new(4, &argument(&columns)).expect("assembly");
        // Python: hashlib.blake2b(struct.pack('<QQ', 2, 4) + b''.join(
        // struct.pack('<II', c, r) for c in range(2) for r in range(4)),
        // digest_size=32, person=b'PIPA-v1-CopyMapD').
        let hex = |bytes: &[u8]| {
            use core::fmt::Write as _;
            bytes.iter().fold(String::new(), |mut out, byte| {
                let _ = write!(out, "{byte:02x}");
                out
            })
        };
        assert_eq!(
            hex(&identity.mapping_digest()),
            "8664f9d53fe1af622ef43dc9e0670577611afc599e88adb2619833185119cfe8"
        );
        let mut copied = identity.clone();
        copied.copy(columns[0], 1, columns[1], 2).expect("copy");
        assert_ne!(copied.mapping_digest(), identity.mapping_digest());
        let mut again = identity.clone();
        again.copy(columns[0], 1, columns[1], 2).expect("copy");
        assert_eq!(again.mapping_digest(), copied.mapping_digest());
        // A different row count is a different permutation.
        let wider = PermutationAssembly::new(8, &argument(&columns)).expect("assembly");
        assert_ne!(wider.mapping_digest(), identity.mapping_digest());
        // Streaming across update chunks equals the one-shot digest.
        let mut large = PermutationAssembly::new(1024, &argument(&columns)).expect("assembly");
        large.copy(columns[1], 1000, columns[0], 3).expect("copy");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2_u64.to_le_bytes());
        bytes.extend_from_slice(&1024_u64.to_le_bytes());
        for column in 0..2 {
            for row in 0..1024 {
                let (target_column, target_row) = large.mapping(column, row).expect("cell");
                bytes
                    .extend_from_slice(&u32::try_from(target_column).expect("small").to_le_bytes());
                bytes.extend_from_slice(&u32::try_from(target_row).expect("small").to_le_bytes());
            }
        }
        assert_eq!(
            large.mapping_digest(),
            crate::cs::descriptor::blake2b_personal::<32>(COPY_MAPPING_PERSONA, &[&bytes])
        );
    }
}
