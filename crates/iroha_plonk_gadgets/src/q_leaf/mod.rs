//! The Q-leaf layout of the P-256 and SHA-256 chips (M3 decisions D1-D5;
//! `specs/kagemusha_lambda_omega_v1.md` sections 2.1 and 10, gate G3.6).
//!
//! # Columns
//!
//! Seventeen advice columns ([`Q_LEAF_ADVICE_COLUMNS`]):
//!
//! | columns | chips | equality |
//! | --- | --- | --- |
//! | `0..10` | foreign field (`c_0..c_2, q_0..q_2, u_0..u_3`); SHA-256 | `c`, `q` |
//! | `10..14` | glue; the P-256 window lookup (`z, a, b, c`) | all four |
//! | `14..17` | SHA-256 bit columns | none |
//!
//! SHA-256 runs on the ten foreign-field columns and the three SHA-only
//! columns: its four word columns (copied, so equality-enabled) are `c_0,
//! c_1, c_2, q_0`, its dense and spread columns `q_1, q_2`, its seven bit
//! columns `u_0..u_3` and the SHA-only columns. With the constants column
//! and the circuit's instance column, twelve columns are equality-enabled
//! (three permutation sets of four).
//!
//! # Lookups
//!
//! Ten arguments, all on the shared table ([`crate::table`]): eight width-1
//! foreign-field range arguments, the `c_0` range argument carrying the
//! SHA-256 spread lookup (width 3: `T, x_0, V`; degree `2 + 3 + 1 = 6`),
//! and the `u_0` range argument carrying the window lookup (width 8; degree
//! `2 + 2 + 2 = 6`).
//!
//! # Rows
//!
//! A leaf is laid out from a split row `s`, the SHA-256 rows
//! ([`sha_rows`]):
//!
//! | rows | foreign-field and SHA-only columns | glue columns |
//! | --- | --- | --- |
//! | `[0, s)` | SHA-256 units | window lookups |
//! | `[s, ..)` | foreign-field blocks | glue rows, below the dynamic tables |
//! | from [`P256Config::tables_end`] | | dynamic window tables |
//!
//! and the fixed table rows are the range values `[0, 2^15)`, the SHA-256
//! spread rows from [`SHA_TABLE_START`] (2,433 rows) and the fixed-base
//! window rows from [`WINDOW_TABLE_START`] (7,940 per base: the generator
//! and every fixed key, 8-bit windows), then the dynamic tables (32 rows per
//! variable key). Every chip takes its rows from a bounded cursor
//! ([`QLeafConfig::chips`]), so the ranges cannot overlap.
//!
//! The shared-table conditions hold by construction: SHA-256 lookup rows
//! are below `s` and the foreign-field patterns start at `s` (the `c_0`
//! host's scaled-top check on row `r` reads the pattern of row `r + 6`,
//! which is never a top row below `s`); window lookups are below `s` and
//! the `u_0` host's patterns start at `s`; the tag namespaces are disjoint
//! and every `V` entry is below `2^15`. The module tests check each
//! condition on the synthesized fixed columns, and the foreign-field
//! adversarial suite runs on this table too.
//!
//! # Capacity
//!
//! With the measured per-verification rows (10,003 foreign-field rows and a
//! 2,094-row SHA block per witness-key verification, 1,659 and 2,094 per
//! fixed-key one) a leaf of `V` witness-key and `F` fixed-key verifications
//! spans `12,097 V + 3,753 F` rows, so `5 V + 1 F` (64,238 rows) is the
//! largest leaf with five witness keys in the 65,530 usable rows at `k =
//! 16`. Its table rows end at 51,081 with one fixed key, at 59,021 with
//! two, and its glue and window rows stay below them.

#[cfg(test)]
mod tests;

use iroha_pasta::PastaField;
use iroha_plonk::{
    cs::{Advice, Column, ConstraintSystem, Fixed},
    frontend::{AssignedTables, Error, Layouter},
};

use crate::{
    arith::{GLUE_WIDTH, GlueChip, GlueConfig},
    cells::{RowCursor, to_u128},
    ff::{FF_ADVICE_COLUMNS, FfChip, FfConfig, FfGuests, RANGE_TABLE_ROWS},
    p256::{
        P256_MODULI, P256Chip, P256Config,
        native::Affine,
        window::{DYNAMIC_ENTRIES, FIXED_WINDOW_BITS},
    },
    sha256::{
        HASH_DIGEST_ROWS, SHA256_ADVICE_COLUMNS, Sha256Chip, Sha256Config, TABLE_ROWS, TABLE_TAGS,
        native::spread, table_tag,
    },
    table::{DYNAMIC_TAG_BASE, SharedTable, VALUE_BITS},
};

/// SHA-256 bit columns beyond the foreign-field columns.
pub const SHA_ONLY_COLUMNS: usize = 3;

/// Advice columns of the leaf.
pub const Q_LEAF_ADVICE_COLUMNS: usize = FF_ADVICE_COLUMNS + GLUE_WIDTH + SHA_ONLY_COLUMNS;

/// The first SHA-256 spread row of the shared table.
pub const SHA_TABLE_START: usize = RANGE_TABLE_ROWS;

/// The first fixed-base window row of the shared table.
pub const WINDOW_TABLE_START: usize = SHA_TABLE_START + TABLE_ROWS;

/// The split row of a leaf hashing `blocks` digests ([`HASH_DIGEST_ROWS`]
/// each).
#[must_use]
pub const fn sha_rows(blocks: usize) -> usize {
    blocks * HASH_DIGEST_ROWS
}

/// The SHA-256 columns in [`Sha256Config::configure`] order (dense, spread,
/// seven bits, four words) from the leaf's advice columns.
fn sha_columns(advice: &[Column<Advice>; Q_LEAF_ADVICE_COLUMNS]) -> [Column<Advice>; 13] {
    let [
        c0,
        c1,
        c2,
        q0,
        q1,
        q2,
        u0,
        u1,
        u2,
        u3,
        _,
        _,
        _,
        _,
        x0,
        x1,
        x2,
    ] = *advice;
    [q1, q2, u0, u1, u2, u3, x0, x1, x2, c0, c1, c2, q0]
}

/// A violated shared-table condition found by [`QLeafConfig::audit`] (the
/// conditions of [`crate::table`]), with the first offending row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafViolation {
    /// A `V` entry at or above `2^15`.
    ValueRange {
        /// The row.
        row: usize,
    },
    /// A table row outside the namespace of its row range: a range row
    /// whose tag or limbs are not zero or whose value is not its row, a
    /// SHA-256 row that is not a spread entry, a fixed-base row without a
    /// fixed-window tag or 8-bit digit, a dynamic row without a dynamic
    /// tag and an entry index, or any other row that is not all zero.
    Namespace {
        /// The row.
        row: usize,
    },
    /// The SHA-256 lookup and the `c_0` host's range lookup are both active.
    ShaOverlap {
        /// The row.
        row: usize,
    },
    /// The window lookup and the `u_0` host's range lookup are both active.
    WindowOverlap {
        /// The row.
        row: usize,
    },
    /// The dynamic-entry enable `q_dyn` is nonzero below the dynamic rows
    /// (it would add advice to a fixed table entry) or not boolean above.
    DynamicEnable {
        /// The row.
        row: usize,
    },
}

/// The chips' configurations on the leaf's columns.
#[derive(Clone, Debug)]
pub struct QLeafConfig {
    ff: FfConfig,
    glue: GlueConfig,
    p256: P256Config,
    sha: Sha256Config,
    table: SharedTable,
}

/// The leaf's chips, each on its own row range ([`QLeafConfig::chips`]).
#[derive(Clone, Debug)]
pub struct QLeafChips<F: PastaField> {
    /// SHA-256, rows `[0, s)`.
    pub sha: Sha256Chip<F>,
    /// Foreign field, rows from `s`.
    pub ff: FfChip<F>,
    /// Glue, rows `[s, tables_end)`.
    pub glue: GlueChip<F>,
    /// P-256: window lookups in rows `[0, s)`, dynamic tables from
    /// `tables_end`.
    pub p256: P256Chip<F>,
}

impl QLeafConfig {
    /// Configures the leaf on `advice` (the column map of the module
    /// documentation) with the constants column `constants` and the fixed
    /// keys `fixed_keys` (each with its own fixed-base table).
    pub fn configure<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; Q_LEAF_ADVICE_COLUMNS],
        constants: Column<Fixed>,
        fixed_keys: &[Affine],
    ) -> Self {
        const { assert!(SHA256_ADVICE_COLUMNS == 13) };
        let table = SharedTable::configure(meta);
        let ff_columns: [Column<Advice>; FF_ADVICE_COLUMNS] =
            core::array::from_fn(|index| advice[index]);
        let glue_columns: [Column<Advice>; GLUE_WIDTH] =
            core::array::from_fn(|index| advice[FF_ADVICE_COLUMNS + index]);
        let glue = GlueConfig::configure(meta, glue_columns, constants);
        let p256 = P256Config::configure_shared(
            meta,
            glue_columns,
            fixed_keys,
            &table,
            WINDOW_TABLE_START,
        );
        let sha = Sha256Config::configure_shared(
            meta,
            sha_columns(&advice),
            constants,
            &table,
            SHA_TABLE_START,
        );
        let window = *p256.window();
        let guests = FfGuests {
            cq: Some(&sha),
            u: Some(&window),
        };
        let ff = FfConfig::configure_shared(meta, ff_columns, &P256_MODULI, &table, &guests);
        Self {
            ff,
            glue,
            p256,
            sha,
            table,
        }
    }

    /// The foreign-field configuration.
    #[must_use]
    pub const fn ff(&self) -> &FfConfig {
        &self.ff
    }

    /// The glue configuration.
    #[must_use]
    pub const fn glue(&self) -> &GlueConfig {
        &self.glue
    }

    /// The P-256 configuration.
    #[must_use]
    pub const fn p256(&self) -> &P256Config {
        &self.p256
    }

    /// The SHA-256 configuration.
    #[must_use]
    pub const fn sha(&self) -> &Sha256Config {
        &self.sha
    }

    /// The shared table.
    #[must_use]
    pub const fn table(&self) -> &SharedTable {
        &self.table
    }

    /// Loads every fixed row of the shared table: the range values, the
    /// SHA-256 spread rows and the fixed-base window rows (each in its own
    /// region; the row ranges are disjoint by construction).
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn load_tables<F: PastaField>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        FfChip::<F>::new(self.ff.clone()).load_table(layouter)?;
        Sha256Chip::<F>::new(&self.sha).load_table(layouter)?;
        let p256 = P256Chip::<F>::new(self.p256.clone());
        layouter.assign_region(
            || "p256 window tables",
            |mut region| p256.load_tables(&mut region),
        )
    }

    /// Checks the shared-table conditions ([`crate::table`]) on a synthesized
    /// leaf: every `V` entry below `2^15`, every table row in the namespace
    /// of its row range, and at most one of host and guest active on every
    /// usable row of the two shared arguments. The activation patterns are
    /// fixed, so a key generation's tables (no witness) audit the circuit
    /// for every witness.
    ///
    /// # Errors
    ///
    /// The first [`LeafViolation`].
    pub fn audit<F: PastaField>(&self, tables: &AssignedTables<F>) -> Result<(), LeafViolation> {
        let fixed = tables.fixed();
        let column = |column: Column<Fixed>| &fixed[column.index()];
        let small = |value: &F| to_u128(value);
        let [tag, x0, x1, x2, y0, y1, y2, value] = self.table.columns().map(column);
        let [h_c, _, s_u, t_u] = self.ff.pattern_columns().map(column);
        let sha_tag = column(self.sha.tag_column());
        let sha_lookup = &tables.selectors()[self.sha.lookup_selector().index()];
        let window = self.p256.window();
        let inputs = window.input_columns().map(column);
        let q_dyn = column(window.dynamic_column());
        let n = tables.n();
        let tables_end = self.p256.tables_end();
        let value_bound = 1_u128 << VALUE_BITS;
        let two = F::from(2_u64);
        for row in 0..tables.usable_rows() {
            let v = small(&value[row]).filter(|v| *v < value_bound);
            let Some(v) = v else {
                return Err(LeafViolation::ValueRange { row });
            };
            let t = small(&tag[row]);
            // The window table's limbs are `fixed + q_dyn advice`: only a
            // dynamic row may add advice.
            let dynamic_enable = !bool::from(q_dyn[row].is_zero());
            if dynamic_enable && (row < tables_end || q_dyn[row] != F::ONE) {
                return Err(LeafViolation::DynamicEnable { row });
            }
            let limbs = [x0, x1, x2, y0, y1, y2].map(|limb| limb[row]);
            let no_limbs = limbs.iter().all(|limb| bool::from(limb.is_zero()));
            let no_points = limbs[1..].iter().all(|limb| bool::from(limb.is_zero()));
            let in_namespace = if row < RANGE_TABLE_ROWS {
                t == Some(0) && no_limbs && usize::try_from(v).ok() == Some(row)
            } else if row < WINDOW_TABLE_START {
                let zero_row = t == Some(0) && no_limbs && v == 0;
                let spread_row = TABLE_TAGS.iter().any(|width| {
                    t == Some(u128::from(table_tag(*width)))
                        && v < 1 << width
                        && u32::try_from(v).is_ok_and(|x| limbs[0] == F::from(spread(x)))
                }) && no_points;
                zero_row || spread_row
            } else if row < tables_end {
                t.is_some_and(|t| (1..u128::from(DYNAMIC_TAG_BASE)).contains(&t))
                    && v < 1 << FIXED_WINDOW_BITS
            } else if bool::from(q_dyn[row].is_zero()) {
                t == Some(0) && no_limbs && v == 0
            } else {
                let dynamic = u128::from(DYNAMIC_TAG_BASE);
                let entries = u128::try_from(DYNAMIC_ENTRIES).unwrap_or(u128::MAX);
                let rows = u128::try_from(n).unwrap_or(u128::MAX);
                t.is_some_and(|t| t >= dynamic && t - dynamic < rows)
                    && (1..=entries).contains(&v)
                    && no_limbs
            };
            if !in_namespace {
                return Err(LeafViolation::Namespace { row });
            }
            // The `c_0` host is active where its pattern is nonzero or its
            // scaled-top term reads a top row six rows down.
            let host_cq = !bool::from(h_c[row].is_zero()) || h_c[(row + 6) % n] == two;
            let sha = sha_lookup[row] || !bool::from(sha_tag[row].is_zero());
            if host_cq && sha {
                return Err(LeafViolation::ShaOverlap { row });
            }
            let host_u = !bool::from(s_u[row].is_zero()) || !bool::from(t_u[row].is_zero());
            let lookup = inputs.iter().any(|input| !bool::from(input[row].is_zero()));
            if host_u && lookup {
                return Err(LeafViolation::WindowOverlap { row });
            }
        }
        Ok(())
    }

    /// The chips of a leaf whose SHA-256 rows and window lookups end below
    /// `split` (normally [`sha_rows`] of its block count).
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] when `split` reaches the dynamic-table rows.
    pub fn chips<F: PastaField>(&self, split: usize) -> Result<QLeafChips<F>, Error> {
        let tables_end = self.p256.tables_end();
        if split >= tables_end {
            return Err(Error::Synthesis);
        }
        Ok(QLeafChips {
            sha: Sha256Chip::with_cursor(&self.sha, RowCursor::bounded(0, split)),
            ff: FfChip::starting_at(self.ff.clone(), split),
            glue: GlueChip::with_cursor(self.glue, RowCursor::bounded(split, tables_end)),
            p256: P256Chip::with_cursors(
                self.p256.clone(),
                RowCursor::bounded(0, split),
                RowCursor::starting_at(tables_end),
            )?,
        })
    }
}
