//! P-256 ECDSA verification in an `Fq` circuit (M3 gadget
//! `iroha_plonk_gadgets::p256`, `specs/kagemusha_lambda_omega_v1.md`
//! sections 7 C11, 9 and 10, gates G3.1 and G3.2).
//!
//! Every KAGEMUSHA P-256 signature is `SHA256withECDSA` over the 32-byte
//! canonical encoding of a Poseidon digest, so the message scalar is
//! `e = SHA-256(..)` read as a big-endian integer, reduced mod `n`
//! ([`P256Chip::message_scalar`] takes the [`crate::sha256`] chip's digest
//! words). The chip verifies `(r, s)` under a key in one of two modes:
//!
//! - [`P256Key::Variable`]: a witness key `(x, y)`;
//! - [`P256Key::Fixed`]: a key fixed at configuration time (issuer or scheme
//!   root), with its own window tables.
//!
//! and one of two verdict modes ([`VerifyMode`]):
//!
//! - **hard**: the circuit is satisfiable iff the native verifier
//!   ([`native::verify_prehashed`]) accepts;
//! - **soft**: the verdict is a bit equal to the native verdict, and the
//!   circuit is satisfiable for every input (every check yields a bit; a
//!   failing input is replaced by a fixed valid default before use).
//!
//! # Verdict
//!
//! Accept iff `1 <= r <= n - 1`, `1 <= s <= (n - 1) / 2` (low-S), the key's
//! coordinates are canonical and on `y^2 = x^3 - 3 x + b`, and
//! `R = [e / s] G + [r / s] Q` is not the identity with `x(R) mod n = r`.
//! Inputs `r`, `s`, `x`, `y` are proper witnesses (256-bit integers); `e` is
//! any value modulo `n`. On a soft failure the arithmetic runs on
//! `r = s = 1`, `Q = G`.
//!
//! # Scalar multiplication and completeness
//!
//! `u1 = e / s` and `u2 = r / s` are division blocks; their proper
//! representatives are cut per 87-bit limb into windows ([`native::windows`]).
//!
//! - **`[u1] G` (and `[u2] Q` for a fixed key)**: 8-bit fixed-base windows
//!   looked up from fixed tables holding `(d + 2) 2^pos_w G` and, in the top
//!   window, `d 2^pos_top G - 2 sum_w 2^pos_w G` (Orchard's offsets). The
//!   windows below the top are summed upward with incomplete additions: the
//!   partial sum `A_w = sum_{v < w} (d_v + 2) 2^pos_v` satisfies
//!   `0 < A_w < 2 2^pos_w <= (d_w + 2) 2^pos_w` and
//!   `A_w + (d_w + 2) 2^pos_w < n` for every digit sequence
//!   (`fixed_base_partial_sums_are_exception_free`), so no addend equals
//!   `+-` the accumulator. The top window joins by complete addition.
//! - **`[u2] Q` for a variable key**: a per-proof table `[e] Q`,
//!   `e = 1..=16` (one doubling and fourteen incomplete additions of small
//!   distinct multiples), looked up with 4-bit digits of
//!   `k* = u2 - C mod n` as `e_w = d_w + 1` (`d_top + 3` in the top
//!   window), so `sum e_w 2^pos_w = k* + C = k'' = u2 (mod n)` with
//!   `C < k'' < 2^256 + C < 2n - 16`. The chain starts at `[e_top] Q` and per
//!   window doubles `shift - 1` times and then computes `2 P + [e_w] Q`
//!   (Eisentraeger-Lauter-Montgomery). With `a` the multiple held by the
//!   accumulator before a window, every intermediate multiple is below `n`
//!   (it is at most `k'' / 2`), `a >= 3`, so `(shift / 2) a > 16 >= e_w`, and
//!   the window's result is `0 mod n` only for the last window with
//!   `k'' = n`, i.e. `u2 = 0`, which `r != 0` excludes. So every
//!   incomplete operation of the chain is exception-free for every key of
//!   order `n` (every curve point) and every nonzero `u2`
//!   (`variable_base_chain_is_exception_free`).
//! - The two results join by complete addition, which handles `u1 = 0`
//!   (identity), `[u1] G = [u2] Q` (doubling) and `[u1] G = -[u2] Q`
//!   (identity result: reject).
//!
//! Complete addition is affine with two soft zero tests (equal `x`, equal
//! `y`), a slope through a selected numerator and denominator, and
//! selections for the identity cases (`point::Arith::complete_add`): this
//! replaces the projective Renes-Costello-Batina formulas of the design
//! (`12 M + 2 m_b`, more than twice the six multiplication blocks and two
//! witnesses used here; a division costs one multiplication block in this
//! chip). It is used only for the joins, so the incomplete chains stay
//! affine.
//!
//! # Soundness of the soft verdict
//!
//! Every bit is a function of the inputs: [`point::Arith::soft_le`] proves
//! `x + d = M + 2^256 (1 - c)` over the integers with a proper `d`, so `c`
//! is unique; [`point::Arith::is_zero_mod`] forces its bit through one
//! product whose limbs must be exactly `(1 - z, 0, 0)`; the identity bits
//! of the joins come from those tests; the verdict is their conjunction.
//! Every incomplete operation is exception-free for every proper scalar the
//! constraints admit (the two inequalities above), so no slope is a free
//! `0 / 0` witness, and the defaults keep every soft input satisfiable.
//!
//! # Layout and costs
//!
//! The chip runs on the caller's [`FfChip`] (ten columns, moduli
//! [`P256_MODULI`]) and [`GlueChip`] (four columns), plus the four advice
//! columns of the window lookup ([`window::WindowConfig`]): with its own
//! table ([`P256Config::configure`]) one `lookup_any` argument (degree 6)
//! and thirteen fixed columns, 18 advice columns. Measured per verification
//! (inputs included; pinned by `p256_inventory_per_verification`, module
//! tests):
//!
//! | verification | assigned advice cells | rows |
//! | --- | ---: | ---: |
//! | variable key (G3.1: 0.30M, 14k rows, 22 columns) | 115,787 | 10,003 |
//! | fixed key (G3.2: 0.12M) | 20,057 | 1,659 |
//! | variable key with its message (one SHA-256 block of a Poseidon digest and the message scalar) | 139,208 | 12,097 in the Q leaf |
//!
//! The rows are the foreign-field rows; the glue and window columns use
//! fewer. In the Q-leaf layout ([`crate::q_leaf`], 17 advice columns) the
//! [`crate::sha256`] chip (2,094 rows per message, selector-gated) runs on
//! the foreign-field columns and three of its own in the rows before the
//! foreign-field rows, the window lookups run on the glue columns beside the
//! SHA rows, and the window lookup is the guest of a foreign-field `U` range
//! argument of the shared table ([`P256Config::configure_shared`],
//! [`crate::table`]); dynamic tables sit on the glue columns above the
//! shared table's fixed rows ([`P256Chip::with_cursors`]). The fixed tables
//! use 7,940 fixed rows per base (33 windows of 8 bits; the generator and
//! each fixed key). Narrower windows would trade free fixed rows for
//! foreign-field rows (6 bits: 11 more windows per base, about 1,600 rows
//! of a 5 V + 1 F leaf, which then no longer fits), so the width stays 8.
//!
//! # Determinism and secrets
//!
//! Layouts depend only on the mode and key kind. Witness arithmetic uses the
//! constant-time [`Nat`] and Montgomery routines; table selections read
//! every entry. The native group arithmetic in [`native`] is variable time
//! and serves only public constants and test oracles.

pub mod native;
pub mod point;
#[cfg(test)]
mod tests;
pub mod window;

use std::sync::{Arc, OnceLock};

use iroha_pasta::PastaField;
use iroha_plonk::{
    cs::{Advice, Column, ConstraintSystem},
    frontend::{Error, Region},
};

use self::{
    native::{Affine, FixedTable, GX, GY, HALF_N, Window},
    point::{Arith, Constants, MaybePoint, P256Point},
    window::{
        FIXED_WINDOW_BITS, TableSource, VARIABLE_WINDOW_BITS, WINDOW_ADVICE_COLUMNS, WindowChip,
        WindowConfig, WindowPoint,
    },
};
use crate::{
    arith::GlueChip,
    cells::{Bit, RowCursor, Uint, Word},
    ff::{FfChip, FfValue, ForeignModulus, Form, Nat},
    sha256::{Sha256Chip, Sha256Digest},
    table::SharedTable,
};

/// The moduli the [`FfChip`] of a P-256 circuit must be configured with.
pub const P256_MODULI: [ForeignModulus; 2] =
    [ForeignModulus::P256_BASE, ForeignModulus::P256_ORDER];

/// How a verification reports its verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VerifyMode {
    /// Unsatisfiable unless the signature is valid (the bit is constrained
    /// to 1).
    Hard,
    /// Satisfiable for every input; the bit is the native verdict.
    Soft,
}

/// The verification key.
#[derive(Clone, Copy, Debug)]
pub enum P256Key<'k, F: PastaField> {
    /// A witness key: proper coordinates modulo `p`.
    Variable {
        /// `x`.
        x: &'k FfValue<F>,
        /// `y`.
        y: &'k FfValue<F>,
    },
    /// The configured fixed key with this index.
    Fixed(usize),
}

/// The fixed-base table of the generator (built once per process).
fn generator_table() -> Option<&'static FixedTable> {
    static TABLE: OnceLock<Option<FixedTable>> = OnceLock::new();
    TABLE
        .get_or_init(|| FixedTable::new(&Affine::GENERATOR, FIXED_WINDOW_BITS))
        .as_ref()
}

/// The offset `C = sum_{w < top} 2^pos_w + 3 2^pos_top` of the variable-base
/// digits, as an integer.
#[must_use]
pub fn variable_offset() -> Nat {
    let layout = native::windows(VARIABLE_WINDOW_BITS);
    let top = layout.len() - 1;
    layout
        .iter()
        .enumerate()
        .fold(Nat::ZERO, |acc, (index, window)| {
            let weight = Nat::pow2(window.position as usize);
            let weight = if index == top {
                weight.wrapping_mul(&Nat::from_u64(3))
            } else {
                weight
            };
            acc.wrapping_add(&weight)
        })
}

/// Columns, fixed tables and fixed keys of the chip.
#[derive(Clone, Debug)]
pub struct P256Config {
    window: WindowConfig,
    /// Base 0 is the generator, base `j + 1` the fixed key `j` (`None` for
    /// an invalid key).
    tables: Arc<Vec<Option<FixedTable>>>,
    /// The first fixed-base table row.
    table_start: usize,
}

impl P256Config {
    /// Configures the window lookup on `window_advice` (made
    /// equality-enabled) and builds the fixed-base tables of the generator
    /// and of every fixed key. The circuit's [`FfChip`] must include
    /// [`P256_MODULI`]; an invalid fixed key gets no table (using it is a
    /// synthesis error).
    pub fn configure<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        window_advice: [Column<Advice>; WINDOW_ADVICE_COLUMNS],
        fixed_keys: &[Affine],
    ) -> Self {
        let window = WindowConfig::configure(meta, window_advice);
        Self::with_window(window, fixed_keys, 0)
    }

    /// [`Self::configure`] on the shared table ([`crate::table`]): the
    /// fixed-base rows start at `table_start`, and the window lookup has no
    /// argument of its own (the caller passes [`Self::window`] as the `U`
    /// guest of [`FfConfig::configure_shared`](crate::ff::FfConfig::configure_shared)).
    pub fn configure_shared<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        window_advice: [Column<Advice>; WINDOW_ADVICE_COLUMNS],
        fixed_keys: &[Affine],
        table: &SharedTable,
        table_start: usize,
    ) -> Self {
        let window = WindowConfig::configure_shared(meta, window_advice, table);
        Self::with_window(window, fixed_keys, table_start)
    }

    fn with_window(window: WindowConfig, fixed_keys: &[Affine], table_start: usize) -> Self {
        let mut tables = vec![generator_table().cloned()];
        for key in fixed_keys {
            let table = key
                .is_valid()
                .then(|| FixedTable::new(key, FIXED_WINDOW_BITS))
                .flatten();
            tables.push(table);
        }
        Self {
            window,
            tables: Arc::new(tables),
            table_start,
        }
    }

    /// The window lookup's columns.
    #[must_use]
    pub const fn window(&self) -> &WindowConfig {
        &self.window
    }

    /// The fixed rows the tables occupy (from [`Self::table_start`]).
    #[must_use]
    pub fn table_rows(&self) -> usize {
        self.tables.iter().flatten().map(FixedTable::rows).sum()
    }

    /// The first fixed-base table row (0 with the chip's own table).
    #[must_use]
    pub const fn table_start(&self) -> usize {
        self.table_start
    }

    /// The first row after the fixed-base tables: dynamic tables start here
    /// or later.
    #[must_use]
    pub fn tables_end(&self) -> usize {
        self.table_start.saturating_add(self.table_rows())
    }

    /// The number of fixed keys.
    #[must_use]
    pub fn fixed_keys(&self) -> usize {
        self.tables.len() - 1
    }

    fn table(&self, base: usize) -> Result<&FixedTable, Error> {
        self.tables
            .get(base)
            .and_then(Option::as_ref)
            .ok_or(Error::Synthesis)
    }
}

/// The P-256 chip: window rows from its own cursor, constants cached per
/// chip.
#[derive(Clone, Debug)]
pub struct P256Chip<F: PastaField> {
    config: P256Config,
    window: WindowChip<F>,
    constants: Constants<F>,
}

impl<F: PastaField> P256Chip<F> {
    /// A chip whose window rows start after the fixed tables.
    #[must_use]
    pub fn new(config: P256Config) -> Self {
        let start = config.tables_end();
        Self::starting_at(config, start)
    }

    /// A chip whose window lookup and dynamic-table rows share one cursor
    /// from `row` (at least the end of the fixed tables: dynamic-table rows
    /// must not overlap them).
    #[must_use]
    pub fn starting_at(config: P256Config, row: usize) -> Self {
        let start = row.max(config.tables_end());
        let window = WindowChip::starting_at(*config.window(), start);
        Self {
            config,
            window,
            constants: Constants::default(),
        }
    }

    /// A chip with window lookup rows from `queries` and dynamic-table rows
    /// from `dynamic` (the Q-leaf layout: lookups below the glue rows,
    /// dynamic tables above the shared table's fixed rows).
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] when `dynamic` starts inside the fixed tables.
    pub fn with_cursors(
        config: P256Config,
        queries: RowCursor,
        dynamic: RowCursor,
    ) -> Result<Self, Error> {
        if dynamic.next_row() < config.tables_end() {
            return Err(Error::Synthesis);
        }
        let window = WindowChip::with_cursors(*config.window(), queries, dynamic);
        Ok(Self {
            config,
            window,
            constants: Constants::default(),
        })
    }

    /// The configuration.
    #[must_use]
    pub const fn config(&self) -> &P256Config {
        &self.config
    }

    /// The first free window lookup row.
    #[must_use]
    pub const fn next_window_row(&self) -> usize {
        self.window.next_row()
    }

    /// The first free dynamic-table row.
    #[must_use]
    pub const fn next_dynamic_row(&self) -> usize {
        self.window.next_dynamic_row()
    }

    /// Writes the fixed tables into the table columns from
    /// [`P256Config::table_start`]. Call once per circuit.
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn load_tables(&self, region: &mut Region<'_, F>) -> Result<(), Error> {
        let tables: Vec<&FixedTable> = self.config.tables.iter().flatten().collect();
        // Invalid keys have no table, so the bases of later keys would
        // shift: refuse such configurations.
        if tables.len() != self.config.tables.len() {
            return Err(Error::Synthesis);
        }
        self.window
            .load_fixed(region, &tables, self.config.table_start)
            .map(|_| ())
    }

    /// The message scalar `e mod n` of a SHA-256 digest (the big-endian
    /// integer of its words): `e = X + 2^-23 Y (mod n)` with the limbs of
    /// `X` and `Y` linear in the words (`Y` holds the two words that
    /// straddle a limb boundary), one constant multiplication.
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn message_scalar(
        &mut self,
        ff: &mut FfChip<F>,
        glue: &mut GlueChip<F>,
        region: &mut Region<'_, F>,
        digest: &Sha256Digest<F>,
    ) -> Result<FfValue<F>, Error> {
        let words: Vec<&Word<F>> = digest.words().iter().map(Uint::word).collect();
        let [h0, h1, h2, h3, h4, h5, h6, h7] = words.as_slice() else {
            return Err(Error::Synthesis);
        };
        let shift = |bits: u32| F::from_u128(1_u128 << bits);
        let word_max = u128::from(u32::MAX);
        let one = F::from(1_u64);
        let x0 = glue.linear(region, &[(one, h7), (shift(32), h6)], F::ZERO)?;
        let x1 = glue.linear(region, &[(shift(9), h4), (shift(41), h3)], F::ZERO)?;
        let x2 = glue.linear(region, &[(shift(18), h1), (shift(50), h0)], F::ZERO)?;
        let x = FfValue::from_parts(
            [x0, x1, x2],
            [
                word_max * ((1 << 32) + 1),
                word_max * ((1 << 9) + (1 << 41)),
                word_max * ((1 << 18) + (1 << 50)),
            ],
            ForeignModulus::P256_ORDER,
            Form::Bounded,
        );
        let zero = glue.constant(region, F::ZERO)?;
        let y2 = glue.linear(region, &[(shift(9), h2)], F::ZERO)?;
        let y = FfValue::from_parts(
            [zero, (*h5).clone(), y2],
            [0, word_max, word_max << 9],
            ForeignModulus::P256_ORDER,
            Form::Bounded,
        );
        let inverse = native::ORDER.inverse(&native::pow2_words(23));
        let scaled = ff.mul_constant(region, &y, &Nat::from_words(inverse))?;
        let mut arith = Arith {
            ff,
            glue,
            constants: &mut self.constants,
        };
        arith.lin(region, &[(1, &x), (1, &scaled)], &[0; 4])
    }

    /// SHA-256 of the 32-byte canonical encoding of the digest `digest` (a
    /// value of `D`) and its message scalar.
    ///
    /// # Errors
    ///
    /// As [`Sha256Chip::hash_digest`] and [`Self::message_scalar`].
    pub fn message_from_digest<D: PastaField>(
        &mut self,
        sha: &mut Sha256Chip<F>,
        ff: &mut FfChip<F>,
        glue: &mut GlueChip<F>,
        region: &mut Region<'_, F>,
        digest: &Word<F>,
    ) -> Result<FfValue<F>, Error> {
        let hashed = sha.hash_digest::<D>(region, digest)?;
        self.message_scalar(ff, glue, region, &hashed)
    }

    /// Verifies `(r, s)` over the message scalar `e` under `key` and returns
    /// the verdict bit (constrained to 1 in [`VerifyMode::Hard`]).
    ///
    /// `r` and `s` are proper values modulo `n`, `e` any value modulo `n`,
    /// a variable key's coordinates proper values modulo `p`.
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] for inputs of the wrong modulus or form, an
    /// unknown fixed key or a missing modulus, and [`Error`] from the
    /// layout.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &mut self,
        ff: &mut FfChip<F>,
        glue: &mut GlueChip<F>,
        region: &mut Region<'_, F>,
        mode: VerifyMode,
        key: P256Key<'_, F>,
        e: &FfValue<F>,
        r: &FfValue<F>,
        s: &FfValue<F>,
    ) -> Result<Bit<F>, Error> {
        let order = ForeignModulus::P256_ORDER;
        if [e, r, s].iter().any(|value| value.modulus() != order) {
            return Err(Error::Synthesis);
        }
        if let P256Key::Variable { x, y } = key
            && (x.modulus() != ForeignModulus::P256_BASE
                || y.modulus() != ForeignModulus::P256_BASE)
        {
            return Err(Error::Synthesis);
        }
        let Self {
            config,
            window,
            constants,
        } = self;
        let mut arith = Arith {
            ff,
            glue,
            constants,
        };
        // Input checks.
        let n_minus_one = native::ORDER.neg(&[1, 0, 0, 0]);
        let r_le = arith.soft_le(region, r, &n_minus_one)?;
        let r_nonzero = arith.is_nonzero(region, r)?;
        let s_le = arith.soft_le(region, s, &HALF_N)?;
        let s_nonzero = arith.is_nonzero(region, s)?;
        let r_ok = arith.glue.and(region, &r_le, &r_nonzero)?;
        let s_ok = arith.glue.and(region, &s_le, &s_nonzero)?;
        let mut valid = arith.glue.and(region, &r_ok, &s_ok)?;
        if let P256Key::Variable { x, y } = key {
            let p_minus_one = native::BASE.neg(&[1, 0, 0, 0]);
            let x_le = arith.soft_le(region, x, &p_minus_one)?;
            let y_le = arith.soft_le(region, y, &p_minus_one)?;
            let on_curve = arith.on_curve(region, x, y)?;
            let canonical = arith.glue.and(region, &x_le, &y_le)?;
            let key_ok = arith.glue.and(region, &canonical, &on_curve)?;
            valid = arith.glue.and(region, &valid, &key_ok)?;
        }
        // Defaults on failure.
        let one = arith.constant(region, order, &[1, 0, 0, 0])?;
        let r_used = arith.select(region, &valid, r, &one)?;
        let s_used = arith.select(region, &valid, s, &one)?;
        let u1 = arith.ff.div(region, e, &s_used)?;
        let u2 = arith.ff.div(region, &r_used, &s_used)?;
        // [u1] G.
        let generator = fixed_base(&mut arith, window, config, region, 0, &u1)?;
        let other = match key {
            P256Key::Variable { x, y } => {
                let gx = arith.constant(region, ForeignModulus::P256_BASE, &GX)?;
                let gy = arith.constant(region, ForeignModulus::P256_BASE, &GY)?;
                let x_used = arith.select(region, &valid, x, &gx)?;
                let y_used = arith.select(region, &valid, y, &gy)?;
                let point = variable_base(
                    &mut arith,
                    window,
                    region,
                    &P256Point::new(x_used, y_used),
                    &u2,
                )?;
                MaybePoint::known(point)
            }
            P256Key::Fixed(index) => {
                let base = index.checked_add(1).ok_or(Error::Synthesis)?;
                fixed_base(&mut arith, window, config, region, base, &u2)?
            }
        };
        let sum = arith.complete_add(region, &generator, &other)?;
        // x(R) mod n = r.
        let x_canonical = arith.canonical(region, sum.point().x())?;
        let x_as_scalar = FfValue::from_parts(
            x_canonical.limbs().clone(),
            x_canonical.bounds(),
            order,
            Form::Proper,
        );
        let difference = arith.lin(region, &[(1, &x_as_scalar), (-1, &r_used)], &[0; 4])?;
        let matches = arith.is_zero_mod(region, &difference)?;
        let mut verdict = arith.glue.and(region, &valid, &matches)?;
        if let Some(identity) = sum.identity() {
            let finite = arith.glue.not(region, identity)?;
            verdict = arith.glue.and(region, &verdict, &finite)?;
        }
        if mode == VerifyMode::Hard {
            region.constrain_constant(verdict.cell(), F::from(1_u64))?;
        }
        Ok(verdict)
    }
}

/// `[k] base` for fixed base `base` (0: the generator) and a proper `k`:
/// incomplete sums of the windows below the top, a complete top window.
fn fixed_base<F: PastaField>(
    arith: &mut Arith<'_, F>,
    window: &mut WindowChip<F>,
    config: &P256Config,
    region: &mut Region<'_, F>,
    base: usize,
    k: &FfValue<F>,
) -> Result<MaybePoint<F>, Error> {
    let table = config.table(base)?;
    let points = window.decompose(
        region,
        k,
        &table.windows,
        TableSource::Fixed { base, table },
        0,
    )?;
    let mut points = points.into_iter().map(|(x, y)| P256Point::new(x, y));
    let mut acc = points.next().ok_or(Error::Synthesis)?;
    let top = points.next_back().ok_or(Error::Synthesis)?;
    for point in points {
        acc = arith.add(region, &acc, &point)?;
    }
    arith.complete_add(region, &MaybePoint::known(acc), &MaybePoint::known(top))
}

/// `[k] Q` for a variable point `Q` of order `n` and `k != 0 (mod n)`: the
/// per-proof table, the offset digits and the incomplete chain (module
/// documentation).
fn variable_base<F: PastaField>(
    arith: &mut Arith<'_, F>,
    window: &mut WindowChip<F>,
    region: &mut Region<'_, F>,
    q: &P256Point<F>,
    k: &FfValue<F>,
) -> Result<P256Point<F>, Error> {
    let mut entries: Vec<P256Point<F>> = Vec::with_capacity(window::DYNAMIC_ENTRIES);
    entries.push(q.clone());
    let mut current = arith.double(region, q)?;
    entries.push(current.clone());
    while entries.len() < window::DYNAMIC_ENTRIES {
        current = arith.add(region, &current, q)?;
        entries.push(current.clone());
    }
    let pairs: Vec<WindowPoint<F>> = entries
        .iter()
        .map(|point| (point.x().clone(), point.y().clone()))
        .collect();
    let tag = window.dynamic_table(region, &pairs)?;
    // k* = k - C (mod n), proper.
    let offset = ForeignModulus::P256_ORDER.reduce(&variable_offset());
    let minus_offset = native::ORDER.neg(&offset.low_words());
    let shifted = arith.lin(region, &[(1, k)], &minus_offset)?;
    let k_star = arith.ff.reduce(region, &shifted)?;
    let layout: Vec<Window> = native::windows(VARIABLE_WINDOW_BITS);
    let points = window.decompose(
        region,
        &k_star,
        &layout,
        TableSource::Dynamic {
            tag,
            entries: &pairs,
        },
        3,
    )?;
    let top = points.len() - 1;
    let (x, y) = points[top].clone();
    let mut acc = P256Point::new(x, y);
    for index in (0..top).rev() {
        let shift = layout[index + 1].position - layout[index].position;
        for _ in 1..shift {
            acc = arith.double(region, &acc)?;
        }
        let (x, y) = points[index].clone();
        acc = arith.double_add(region, &acc, &P256Point::new(x, y))?;
    }
    Ok(acc)
}
