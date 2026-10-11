//! FF-CRT foreign-field arithmetic: integers modulo a foreign modulus `m`
//! (Pasta `q` in an `Fp` circuit, Pasta `p` in an `Fq` circuit, the P-256
//! base field `p` and group order `n` in either) as three 87-bit limbs, with
//! a fused multiply-reduce gate that proves `a b = c + q m` over the
//! integers.
//!
//! # Representation
//!
//! An [`FfValue`] is an integer `x = x_0 + x_1 B + x_2 B^2` with `B = 2^87`
//! and every limb a nonnegative integer below a tracked bound. The chip
//! never creates a value whose limbs are not proven bounded: values come
//! from range-checked running sums, from constants, or from limb-wise linear
//! combinations of other values with nonnegative results. Three forms:
//!
//! - [`Form::Proper`]: limbs below `2^87, 2^87, 2^82`, so `x < 2^256`. Every
//!   multiplication output is proper; an honest prover outputs the canonical
//!   residue, but only canonicity checks prove it.
//! - [`Form::Canonical`]: proper and `x < m` (proven by a canonical
//!   comparison), so the limbs are the unique representation of the residue.
//!   Equality of canonical values is limb equality.
//! - [`Form::Bounded`]: an unreduced linear combination whose limbs are below
//!   their tracked bounds, at most `2^94 - 1` ([`OPERAND_LIMB_BITS`]).
//!
//! # The fused gate
//!
//! A multiplication block proves `a b = c + q m` with `c` proper and
//! `0 <= q < 2^261` ([`QUOTIENT_BITS`]). Writing every quantity in limbs,
//! the column sums `t_k = sum_{i+j=k} (a_i b_j - q_i m_j) - c_k` (`k <= 3`)
//! are tied by four carries `u_k` with `u_k in [-2^104, 2^104)`:
//!
//! - `t_0 = u_0 B`, `t_1 + u_0 = u_1 B`, `t_2 + u_1 = u_2 B`,
//!   `t_3 + u_2 = u_3 B` (each a native equation that cannot wrap, so an
//!   integer equation), hence `X = a b - c - q m = 0 (mod 2^348)`;
//! - the native residue `(sum a_i B^i)(sum b_j B^j) - sum c_k B^k -
//!   (sum q_i B^i) m = 0 (mod N)` for the native field order `N`.
//!
//! Since `gcd(N, 2^348) = 1` and `|X| < 2^537 < N 2^348`, `X = 0`. The
//! carry-bound memo (M3 gate G3.4) gives the bounds for every supported
//! modulus in both native fields; the unit test
//! `ff_carry_memo_bounds_hold_for_every_modulus` recomputes every inequality
//! with exact big-integer interval arithmetic. Carries of operands within
//! the envelope (limbs below `2^94`) stay below `2^102.6`; the honest
//! quotient fits iff `max(a) max(b) < m 2^261`
//! ([`FfChip::mul_admissible`]), and operands outside that set are reduced
//! first.
//!
//! A division block proves `b c = a + q m - K` for a fixed multiple `K` of
//! `m` (so `q >= 0` for every bounded `a`), which makes `c = a / b`. An
//! inverse is a division of the constant one: one witness and one fused
//! multiplication.
//!
//! # Layout
//!
//! Ten advice columns, each with its own range lookup into one 15-bit table
//! column `V` ([`RANGE_TABLE_ROWS`] = `2^15` rows, `V = 0..2^15`). A block
//! is seven rows:
//!
//! | group | columns | row `0` | rows `1..=5` | row `6` |
//! | --- | --- | --- | --- | --- |
//! | `C` | 3 | operand `a` | running sums of `c` | top sublimb (12, 12, 7 bits) |
//! | `Q` | 3 | operand `b` | running sums of `q` | top sublimb (12, 12, 12 bits) |
//! | `U` | 4 | running sums of `u_k + 2^104` (seven 15-bit sublimbs, rows `0..=6`) | | |
//!
//! A running sum `z_j = floor(z / 2^(15 j))` is range-checked by looking up
//! `z_j - 2^15 z_{j+1}` on step rows and the top entry `z_top` on the top
//! row. A top of `w < 15` bits is looked up twice, as `z_top` and as
//! `2^(15-w) z_top` (read from the operand row through rotation 6): both in
//! `[0, 2^15)` force `z_top < 2^w`. The `C` and `Q` groups each have one
//! ternary pattern column `h` (1 on steps, 2 on the top row, 0 elsewhere;
//! `s = h (2 - h)`, `t = h (h - 1) / 2`, and the scaled top enabled by `t`
//! of `h` six rows down), the `U` group binary step and top columns
//! ([`FF_PATTERN_COLUMNS`] = 4). The `C`/`Q` lookup inputs have degree 3
//! (lookup degree 6), the `U` inputs degree 2; the gates have degree 3 and
//! anchor on row 0, reading operands there, the `C`/`Q` running-sum roots
//! on row 1 and the `U` roots on row 0, so every operand column is queried
//! at rotations 0, 1 and 6 (five blinding rows). A multiplication or
//! division is one block: [`MUL_CELLS`] = 70 advice cells in 7 rows of 10
//! columns, no idle cell. Comparisons and witnesses use the `C` and `Q`
//! groups of a block ([`COMPARE_CELLS`], [`WITNESS_CELLS`],
//! [`CANONICAL_WITNESS_CELLS`]).
//!
//! Additions, subtractions and selections are limb-wise rows of the glue
//! chip ([`GlueChip`]): three rows per operation, three new cells plus six
//! copies. A subtraction adds a multiple `K` of `m` whose limbs dominate the
//! subtrahend's bounds ([`ForeignModulus::padding`]), so every limb stays a
//! nonnegative integer.
//!
//! Every column carries its own lookup argument (ten per chip), the price of
//! 54 range-checked sublimbs per multiplication in 7 rows. In the Q-leaf
//! layout ([`crate::q_leaf`]) the table column is `V` of the shared table
//! ([`crate::table`]) and two of the ten arguments also carry a guest: the
//! SHA-256 spread lookup on a `C`/`Q` argument and the P-256 window lookup
//! on a `U` argument ([`FfConfig::configure_shared`]), so the leaf has ten
//! lookup arguments in all.
//!
//! Soft (bit-valued) comparisons for soft-mode verifiers are not provided
//! yet.
//!
//! # Determinism and secrets
//!
//! Layouts depend only on the circuit structure (bounds are structural, not
//! witness values). Witness arithmetic uses the constant-time [`Nat`]
//! routines; moduli and bounds are public.

#[cfg(test)]
mod bounded_tests;
pub mod dot;
pub mod mont;
pub mod nat;
mod reduction;
pub mod rotated;
mod s6;
pub mod serialized;
#[cfg(test)]
mod tests;

use core::{cmp::Ordering, marker::PhantomData};

use iroha_pasta::PastaField;
use iroha_plonk::{
    cs::{Advice, Column, ConstraintSystem, Expression, Fixed, Rotation, Selector, VirtualCells},
    frontend::{Error, Layouter, Region, Value},
};

pub use self::nat::Nat;
pub use self::s6::CanonicalS6;
use crate::{
    arith::GlueChip,
    cells::{Bit, RowCursor, Word, assign_constant, assign_word, copy_word},
    range::RunningSumChip,
    table::{GuestLookup, SharedTable, TableGuest},
};

/// Limbs per value.
pub const LIMBS: usize = 3;
/// Bits of the low limbs (`B = 2^87`).
pub const LIMB_BITS: usize = 87;
/// Bits of the top limb of a proper value (`3 x 87` limbs, top 82: values
/// below `2^256`).
pub const TOP_LIMB_BITS: usize = 82;
/// Bits of one range-table sublimb.
pub const SUBLIMB_BITS: usize = 15;
/// Running-sum rows of a value or quotient limb.
pub const LIMB_SUBLIMBS: usize = 6;
/// Carries of the fused gate (columns `0..=3` of the limb product).
pub const CARRIES: usize = 4;
/// Running-sum rows of a carry.
pub const CARRY_SUBLIMBS: usize = 7;
/// A carry is `u` with `u + 2^104` in `[0, 2^105)`.
pub const CARRY_OFFSET_BITS: usize = 104;
/// The quotient `q` is below `2^261` (three 87-bit limbs).
pub const QUOTIENT_BITS: usize = 261;
/// Operand limbs are below `2^94` (the envelope the carry memo covers).
pub const OPERAND_LIMB_BITS: usize = 94;
/// Rows per block.
pub const BLOCK_ROWS: usize = 7;
/// Advice columns of the chip.
pub const FF_ADVICE_COLUMNS: usize = 10;
/// Fixed pattern columns of the chip: the ternary patterns of the `C` and
/// `Q` groups and the step and top patterns of the `U` group.
pub const FF_PATTERN_COLUMNS: usize = 4;
/// Range-table rows: `V = v` for every `v < 2^15`.
pub const RANGE_TABLE_ROWS: usize = 1 << SUBLIMB_BITS;
/// Advice cells of one multiplication or division block.
pub const MUL_CELLS: usize = 70;
/// Advice cells of one canonical comparison of an existing value.
pub const COMPARE_CELLS: usize = 21;
/// Advice cells of one proper witness.
pub const WITNESS_CELLS: usize = 18;
/// Advice cells of one canonical witness.
pub const CANONICAL_WITNESS_CELLS: usize = 36;

/// Top sublimb widths of the `C` group (`87, 87, 82`-bit limbs).
pub const VALUE_TOPS: [usize; LIMBS] = [12, 12, 7];
/// Top sublimb widths of the `Q` group (`87`-bit limbs).
pub const QUOTIENT_TOPS: [usize; LIMBS] = [12, 12, 12];
/// The operand row of a block (`C` and `Q` groups; the gates' anchor).
const OPERAND_ROW: usize = 0;
/// The first running-sum row of the `C` and `Q` groups.
const ROOT_ROW: usize = 1;
/// The rotation from the operand row to the top row of a block.
const TOP_ROTATION: Rotation = Rotation(6);
/// The ternary pattern value of a `C`/`Q` step row.
const PATTERN_STEP: u64 = 1;
/// The ternary pattern value of a `C`/`Q` top row.
const PATTERN_TOP: u64 = 2;

/// `2^bits - 1` for `bits <= 127`.
const fn mask(bits: usize) -> u128 {
    (1_u128 << bits) - 1
}

/// Limb bounds of a proper value.
pub const PROPER_BOUNDS: [u128; LIMBS] = [mask(LIMB_BITS), mask(LIMB_BITS), mask(TOP_LIMB_BITS)];
/// Stronger unsigned result envelope used only by the staged Pasta kernel.
const NARROW_PROPER_BOUNDS: [u128; LIMBS] = [mask(LIMB_BITS), mask(LIMB_BITS), mask(81)];

/// The largest operand limb.
pub const OPERAND_LIMB_MAX: u128 = mask(OPERAND_LIMB_BITS);

/// The integer `sum limbs_i 2^(87 i)` (limbs below `2^128`).
#[must_use]
pub fn from_limbs(limbs: &[u128; LIMBS]) -> Nat {
    limbs
        .iter()
        .enumerate()
        .fold(Nat::ZERO, |acc, (index, limb)| {
            acc.wrapping_add(&Nat::from_u128(*limb).shl(LIMB_BITS * index))
        })
}

/// The limbs `x mod 2^87, (x >> 87) mod 2^87, x >> 174` when the top limb
/// fits a `u128` (`x < 2^302`).
#[must_use]
pub fn to_limbs(value: &Nat) -> Option<[u128; LIMBS]> {
    let low = value.low_bits_u128(LIMB_BITS);
    let middle = value.shr(LIMB_BITS).low_bits_u128(LIMB_BITS);
    let top = value.shr(2 * LIMB_BITS).to_u128()?;
    Some([low, middle, top])
}

/// Limbs of a nonnegative or two's complement integer as field elements:
/// the low limbs masked, the top limb the arithmetic shift (so a negative or
/// oversized value has an out-of-range top limb).
fn limb_fields<F: PastaField>(value: &Nat) -> [F; LIMBS] {
    [
        Nat::from_u128(value.low_bits_u128(LIMB_BITS)).to_field(),
        Nat::from_u128(value.shr(LIMB_BITS).low_bits_u128(LIMB_BITS)).to_field(),
        value.sar(2 * LIMB_BITS).to_field_signed(),
    ]
}

/// `sum bounds_i B^i`, the largest integer a value with these limb bounds
/// can hold.
#[must_use]
pub fn value_bound(bounds: &[u128; LIMBS]) -> Nat {
    from_limbs(bounds)
}

/// Whether every limb bound is within the operand envelope.
#[must_use]
pub fn within_envelope(bounds: &[u128; LIMBS]) -> bool {
    bounds.iter().all(|bound| *bound <= OPERAND_LIMB_MAX)
}

/// A foreign modulus `m`: odd, `2^252 <= m < 2^256`.
///
/// The lower bound makes every product of two proper values admissible
/// (`2^512 < m 2^261`). Division and inversion are complete only for a
/// prime `m` (Fermat inversion); their soundness does not depend on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ForeignModulus([u64; 4]);

impl ForeignModulus {
    /// The Pallas base field order `p` (the Vesta scalar field).
    pub const PASTA_FP: Self = Self([
        0x992d_30ed_0000_0001,
        0x2246_98fc_094c_f91b,
        0,
        0x4000_0000_0000_0000,
    ]);
    /// The Pallas scalar field order `q` (the Vesta base field).
    pub const PASTA_FQ: Self = Self([
        0x8c46_eb21_0000_0001,
        0x2246_98fc_0994_a8dd,
        0,
        0x4000_0000_0000_0000,
    ]);
    /// The P-256 base field order `p`.
    pub const P256_BASE: Self = Self([
        0xffff_ffff_ffff_ffff,
        0x0000_0000_ffff_ffff,
        0,
        0xffff_ffff_0000_0001,
    ]);
    /// The P-256 group order `n`.
    pub const P256_ORDER: Self = Self([
        0xf3b9_cac2_fc63_2551,
        0xbce6_faad_a717_9e84,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_0000_0000,
    ]);

    /// The modulus with little-endian words `words`, when it is odd and in
    /// `[2^252, 2^256)`.
    #[must_use]
    pub const fn new(words: [u64; 4]) -> Option<Self> {
        if words[0] & 1 == 1 && words[3] >> 60 != 0 {
            Some(Self(words))
        } else {
            None
        }
    }

    /// The little-endian words.
    #[must_use]
    pub const fn words(self) -> [u64; 4] {
        self.0
    }

    /// The modulus as an integer.
    #[must_use]
    pub const fn nat(self) -> Nat {
        Nat::from_words(self.0)
    }

    /// The limbs of `m`.
    #[must_use]
    pub fn limbs(self) -> [u128; LIMBS] {
        to_limbs(&self.nat()).unwrap_or([0; LIMBS])
    }

    /// The limbs of `m - 1` (the canonical comparison constant).
    #[must_use]
    pub fn limbs_minus_one(self) -> [u128; LIMBS] {
        to_limbs(&self.nat().wrapping_sub(&Nat::ONE)).unwrap_or([0; LIMBS])
    }

    /// `x mod m`.
    #[must_use]
    pub fn reduce(self, x: &Nat) -> Nat {
        x.rem(&self.nat()).unwrap_or(Nat::ZERO)
    }

    /// `x + y mod m`.
    #[must_use]
    pub fn add(self, x: &Nat, y: &Nat) -> Nat {
        self.reduce(&self.reduce(x).wrapping_add(&self.reduce(y)))
    }

    /// `x - y mod m`.
    #[must_use]
    pub fn sub(self, x: &Nat, y: &Nat) -> Nat {
        let modulus = self.nat();
        self.reduce(
            &self
                .reduce(x)
                .wrapping_add(&modulus)
                .wrapping_sub(&self.reduce(y)),
        )
    }

    /// `x y mod m`.
    #[must_use]
    pub fn mul(self, x: &Nat, y: &Nat) -> Nat {
        self.reduce(&self.reduce(x).wrapping_mul(&self.reduce(y)))
    }

    /// `x^(m-2) mod m` by a constant-time Fermat exponentiation: the inverse
    /// of `x` for a prime `m`, and 0 for `x = 0 mod m`. Runs in Montgomery
    /// form ([`mont::MontModulus`]); equal to [`Nat::pow_mod`] with exponent
    /// `m - 2`.
    #[must_use]
    pub fn fermat_inverse(self, x: &Nat) -> Nat {
        let mont = mont::MontModulus::new(self.0);
        Nat::from_words(mont.inverse(&self.reduce(x).low_words()))
    }

    /// `x^-1 mod m`, or `None` when `x` has no inverse (the check is
    /// variable time in whether `x` is invertible).
    #[must_use]
    pub fn inverse(self, x: &Nat) -> Option<Nat> {
        let inverse = self.fermat_inverse(x);
        (self.mul(x, &inverse) == Nat::ONE).then_some(inverse)
    }

    /// `x / y mod m`, or `None` when `y = 0 mod m`.
    #[must_use]
    pub fn div(self, x: &Nat, y: &Nat) -> Option<Nat> {
        self.inverse(y).map(|inverse| self.mul(x, &inverse))
    }

    /// Whether `x < m`.
    #[must_use]
    pub fn is_canonical(self, x: &Nat) -> bool {
        x.cmp_vartime(&self.nat()) == Ordering::Less
    }

    /// The smallest-limb padding `K = k m` (as `k` and its limbs) whose
    /// limbs dominate `floors` limb-wise: `K_i >= floors_i`, `K = sum K_i
    /// B^i`. Subtracting a value whose limbs are at most `floors` from `K`
    /// leaves nonnegative limbs.
    #[must_use]
    pub fn padding(self, floors: &[u128; LIMBS]) -> Option<(Nat, [u128; LIMBS])> {
        let modulus = self.nat();
        let radix = Nat::pow2(LIMB_BITS);
        let target = Nat::from_u128(floors[2])
            .shl(2 * LIMB_BITS)
            .wrapping_add(
                &Nat::from_u128(floors[1])
                    .wrapping_add(&radix)
                    .shl(LIMB_BITS),
            )
            .wrapping_add(&Nat::from_u128(floors[0]))
            .wrapping_add(&radix);
        let (k, _) = target
            .wrapping_add(&modulus)
            .wrapping_sub(&Nat::ONE)
            .div_rem(&modulus)?;
        let total = k.wrapping_mul(&modulus);
        let limb_at_least = |value: &Nat, floor: u128| -> Option<u128> {
            // floor + ((value - floor) mod B)
            let excess = value.wrapping_sub(&Nat::from_u128(floor));
            if excess.is_negative() {
                return None;
            }
            floor.checked_add(excess.low_bits_u128(LIMB_BITS))
        };
        let k0 = limb_at_least(&total, floors[0])?;
        let rest = total.wrapping_sub(&Nat::from_u128(k0)).shr(LIMB_BITS);
        let k1 = limb_at_least(&rest, floors[1])?;
        let k2 = rest
            .wrapping_sub(&Nat::from_u128(k1))
            .shr(LIMB_BITS)
            .to_u128()?;
        let limbs = [k0, k1, k2];
        (k2 >= floors[2] && from_limbs(&limbs) == total).then_some((k, limbs))
    }

    /// The division-gate padding: dominates every operand limb.
    #[must_use]
    pub fn division_padding(self) -> Option<(Nat, [u128; LIMBS])> {
        self.padding(&[OPERAND_LIMB_MAX; LIMBS])
    }
}

/// How much is proven about a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Form {
    /// Limbs below their tracked bounds (at most `2^94 - 1`).
    Bounded,
    /// Limbs below `2^87, 2^87, 2^82` (the integer is below `2^256`).
    Proper,
    /// Proper and below `m`.
    Canonical,
}

/// A foreign-field value: three limb cells with proven bounds.
#[derive(Clone, Debug)]
pub struct FfValue<F: PastaField> {
    limbs: [Word<F>; LIMBS],
    bounds: [u128; LIMBS],
    modulus: ForeignModulus,
    form: Form,
}

impl<F: PastaField> FfValue<F> {
    /// The limb cells (equality-enabled).
    #[must_use]
    pub const fn limbs(&self) -> &[Word<F>; LIMBS] {
        &self.limbs
    }

    /// The inclusive limb bounds.
    #[must_use]
    pub const fn bounds(&self) -> [u128; LIMBS] {
        self.bounds
    }

    /// The modulus.
    #[must_use]
    pub const fn modulus(&self) -> ForeignModulus {
        self.modulus
    }

    /// What is proven about the value.
    #[must_use]
    pub const fn form(&self) -> Form {
        self.form
    }

    /// The limb values (unknown during key generation).
    #[must_use]
    pub fn limb_values(&self) -> Value<[Nat; LIMBS]> {
        let [a, b, c] = &self.limbs;
        a.value()
            .zip(b.value())
            .zip(c.value())
            .map(|((a, b), c)| [a, b, c].map(|limb| Nat::from_field(&limb)))
    }

    /// The integer `sum x_i B^i`.
    #[must_use]
    pub fn integer(&self) -> Value<Nat> {
        self.limb_values().map(|limbs| {
            limbs
                .iter()
                .enumerate()
                .fold(Nat::ZERO, |acc, (index, limb)| {
                    acc.wrapping_add(&limb.shl(LIMB_BITS * index))
                })
        })
    }

    /// The canonical residue `x mod m`.
    #[must_use]
    pub fn residue(&self) -> Value<Nat> {
        let modulus = self.modulus;
        self.integer().map(|value| modulus.reduce(&value))
    }

    /// Wraps limb cells whose bounds and form other constraints already
    /// prove (crate-internal: cells looked up from a table of such values,
    /// limb-wise linear combinations of bounded values, range-checked
    /// words). The caller is responsible for the claim; nothing is laid out.
    pub(crate) const fn from_parts(
        limbs: [Word<F>; LIMBS],
        bounds: [u128; LIMBS],
        modulus: ForeignModulus,
        form: Form,
    ) -> Self {
        Self {
            limbs,
            bounds,
            modulus,
            form,
        }
    }
}

/// A value placed into an operand slot: a copy of a value's limbs, or
/// constant limbs pinned through the constants column.
#[derive(Clone, Copy, Debug)]
struct Operand<'v, F: PastaField> {
    value: Option<&'v FfValue<F>>,
    constant: [u128; LIMBS],
}

impl<'v, F: PastaField> Operand<'v, F> {
    /// A copy of `value`'s limbs.
    const fn value(value: &'v FfValue<F>) -> Self {
        Self {
            value: Some(value),
            constant: [0; LIMBS],
        }
    }

    /// Constant limbs.
    const fn constant(limbs: [u128; LIMBS]) -> Self {
        Self {
            value: None,
            constant: limbs,
        }
    }

    fn bounds(&self) -> [u128; LIMBS] {
        self.value.map_or(self.constant, |value| value.bounds)
    }

    /// Structural admission for the unsigned three-carry product. Constants
    /// are pinned; values must retain a proved Proper or Canonical form.
    fn is_proper(&self) -> bool {
        self.value
            .is_none_or(|value| matches!(value.form, Form::Proper | Form::Canonical))
            && self
                .bounds()
                .iter()
                .zip(PROPER_BOUNDS)
                .all(|(bound, maximum)| *bound <= maximum)
    }

    fn limb_values(&self) -> Value<[Nat; LIMBS]> {
        self.value.map_or_else(
            || Value::known(self.constant.map(Nat::from_u128)),
            FfValue::limb_values,
        )
    }

    fn slots(&self) -> [Slot<'v, F>; LIMBS] {
        self.value.map_or_else(
            || self.constant.map(|limb| Slot::Constant(F::from_u128(limb))),
            |value| {
                let [a, b, c] = &value.limbs;
                [Slot::Copy(a), Slot::Copy(b), Slot::Copy(c)]
            },
        )
    }
}

/// What one operand cell holds.
#[derive(Clone, Copy, Debug)]
enum Slot<'w, F: PastaField> {
    /// A copy of an existing word.
    Copy(&'w Word<F>),
    /// A constant pinned through the constants column.
    Constant(F),
    /// A free witness (adversarial tests only).
    #[cfg_attr(not(test), allow(dead_code))]
    Free(Value<F>),
}

/// A block group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Group {
    /// Columns `c_0..c_2`.
    C,
    /// Columns `q_0..q_2`.
    Q,
    /// Columns `u_0..u_3`.
    U,
}

impl Group {
    const fn bit(self) -> u8 {
        match self {
            Self::C => 1,
            Self::Q => 2,
            Self::U => 4,
        }
    }
}

/// The fused-gate mode of a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// `a b = c + q m`.
    Mul,
    /// `b c = a + q m - K`.
    Div,
}

/// A structural CRT envelope; all choices retain the same native residue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CarryLayout {
    Full,
    ProperProduct,
    BoundedPasta,
}

/// Selectors of one configured modulus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ModulusGates {
    modulus: ForeignModulus,
    mul: Selector,
    div: Selector,
    compare: Selector,
    canonical_witness: Selector,
}

/// An explicitly selected layout for the same admitted modulus.
#[derive(Clone, Copy, Debug)]
struct SelectedModulus {
    modulus: ForeignModulus,
    fused: Option<ModulusGates>,
}

#[derive(Clone, Debug)]
struct SerializedState<F: PastaField> {
    kernel: Option<rotated::RotatedFfConfig>,
    glue: GlueChip<F>,
    range: RunningSumChip<F>,
    moduli: Vec<ForeignModulus>,
}

/// Columns, table, pattern columns and per-modulus selectors of the chip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FfConfig {
    c: [Column<Advice>; LIMBS],
    q: [Column<Advice>; LIMBS],
    u: [Column<Advice>; CARRIES],
    /// The range table column `V` (its own, or `V` of the shared table).
    value: Column<Fixed>,
    /// `h_C, h_Q, s_U, t_U`.
    pattern: [Column<Fixed>; FF_PATTERN_COLUMNS],
    moduli: Vec<ModulusGates>,
}

/// The guests of a shared configuration ([`FfConfig::configure_shared`]):
/// at most one on the `c_0` range argument (fixed table expressions only,
/// the input there having degree 3) and one on the `u_0` range argument.
pub struct FfGuests<'g, F: PastaField> {
    /// The guest of the `c_0` argument.
    pub cq: Option<&'g dyn TableGuest<F>>,
    /// The guest of the `u_0` argument.
    pub u: Option<&'g dyn TableGuest<F>>,
}

impl<F: PastaField> FfGuests<'_, F> {
    /// No guests.
    #[must_use]
    pub const fn none() -> Self {
        Self { cq: None, u: None }
    }
}

/// The residual of a `C` or `Q` column on the block row of the query: with
/// the ternary pattern `h` (1 on steps, 2 on the top row, 0 elsewhere),
/// `s = h (2 - h)` and `t = h (h - 1) / 2` are 0/1 and never both 1, and
/// `e = t(h six rows down)` is 1 exactly on a block's operand row (whose
/// pattern is 0). The residual `s (z - 2^15 z_next) + t z + e 2^(15 - w)
/// z_top` is a step on step rows, the top entry on the top row, the scaled
/// top on the operand row and 0 elsewhere (degree 3).
fn cq_residual<F: PastaField>(
    cells: &mut VirtualCells<'_, F>,
    z: Column<Advice>,
    pattern: Column<Fixed>,
    top_bits: usize,
) -> Expression<F> {
    let h = cells.query_fixed(pattern, Rotation::cur());
    let h_top = cells.query_fixed(pattern, TOP_ROTATION);
    let cur = cells.query_advice(z, Rotation::cur());
    let next = cells.query_advice(z, Rotation::next());
    let top = cells.query_advice(z, TOP_ROTATION);
    let two = Expression::Constant(F::from(2_u64));
    let one = Expression::Constant(F::ONE);
    let step = h.clone() * (two - h.clone());
    let top_row = h.clone() * (h - one.clone()) * F::TWO_INV;
    let operand_row = h_top.clone() * (h_top - one) * F::TWO_INV;
    let scale = F::from_u128(1 << (SUBLIMB_BITS - top_bits));
    step * (cur.clone() - next * F::from_u128(1 << SUBLIMB_BITS))
        + top_row * cur
        + operand_row * top * scale
}

/// The residual of a `U` column: `(s + t) z - 2^15 s z_next` with binary
/// step and top patterns (never both 1; degree 2).
fn u_residual<F: PastaField>(
    cells: &mut VirtualCells<'_, F>,
    z: Column<Advice>,
    step: Column<Fixed>,
    top: Column<Fixed>,
) -> Expression<F> {
    let s = cells.query_fixed(step, Rotation::cur());
    let t = cells.query_fixed(top, Rotation::cur());
    let cur = cells.query_advice(z, Rotation::cur());
    let next = cells.query_advice(z, Rotation::next());
    (s.clone() + t) * cur - s * next * F::from_u128(1 << SUBLIMB_BITS)
}

/// One range lookup: the residual (plus the guest's value) in `V`, after
/// the guest's components.
fn range_lookup<F: PastaField>(
    meta: &mut ConstraintSystem<F>,
    name: &str,
    value: Column<Fixed>,
    guest: Option<&dyn TableGuest<F>>,
    residual: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
) {
    let name = guest.map_or_else(
        || name.to_owned(),
        |guest| format!("{name} + {}", guest.guest_name()),
    );
    meta.lookup_any(name, |cells| {
        let residual = residual(cells);
        let (mut pairs, input) = match guest {
            Some(guest) => {
                let GuestLookup { pairs, value } = guest.guest_lookup(cells);
                (pairs, residual + value)
            }
            None => (Vec::new(), residual),
        };
        pairs.push((input, cells.query_fixed(value, Rotation::cur())));
        pairs
    });
}

/// `F::from_u128(value)` as an expression.
fn constant<F: PastaField>(value: u128) -> Expression<F> {
    Expression::Constant(F::from_u128(value))
}

/// `sum limbs_i B^i` as an expression.
fn recompose<F: PastaField>(limbs: &[Expression<F>]) -> Expression<F> {
    let radix = F::from_u128(1 << LIMB_BITS);
    limbs
        .iter()
        .rev()
        .cloned()
        .reduce(|acc, limb| acc * radix + limb)
        .unwrap_or(Expression::Constant(F::ZERO))
}

/// The cells one fused constraint set reads.
struct FusedTerms<F> {
    /// Factor limbs `P`.
    p: [Expression<F>; LIMBS],
    /// Factor limbs `R`.
    r: [Expression<F>; LIMBS],
    /// Subtracted limbs `S`.
    s: [Expression<F>; LIMBS],
    /// Quotient limbs.
    q: [Expression<F>; LIMBS],
    /// Carries (offset removed).
    u: [Expression<F>; CARRIES],
}

/// The fused constraints of `P R - S + K - q m = 0`: four carry columns and
/// the native residue.
fn fused_constraints<F: PastaField>(
    selector: &Expression<F>,
    terms: &FusedTerms<F>,
    modulus: ForeignModulus,
    padding: [u128; LIMBS],
) -> Vec<(&'static str, Expression<F>)> {
    const NAMES: [&str; CARRIES] = [
        "column 0: t_0 = u_0 B",
        "column 1: t_1 + u_0 = u_1 B",
        "column 2: t_2 + u_1 = u_2 B",
        "column 3: t_3 + u_2 = u_3 B",
    ];
    let m = modulus.limbs();
    let radix = F::from_u128(1 << LIMB_BITS);
    let mut out = Vec::with_capacity(CARRIES + 1);
    let mut carry_in: Option<Expression<F>> = None;
    for (column, name) in NAMES.iter().enumerate() {
        let mut terms_k: Vec<Expression<F>> = Vec::new();
        for i in 0..LIMBS {
            let Some(j) = column.checked_sub(i) else {
                continue;
            };
            if j >= LIMBS {
                continue;
            }
            terms_k.push(terms.p[i].clone() * terms.r[j].clone());
            if m[j] != 0 {
                terms_k.push(-(terms.q[i].clone() * F::from_u128(m[j])));
            }
        }
        if column < LIMBS {
            terms_k.push(-terms.s[column].clone());
            if padding[column] != 0 {
                terms_k.push(constant(padding[column]));
            }
        }
        if let Some(carry) = carry_in.take() {
            terms_k.push(carry);
        }
        terms_k.push(-(terms.u[column].clone() * radix));
        let sum = terms_k
            .into_iter()
            .reduce(|acc, term| acc + term)
            .unwrap_or(Expression::Constant(F::ZERO));
        out.push((*name, selector.clone() * sum));
        carry_in = Some(terms.u[column].clone());
    }
    let padding_native = from_limbs(&padding).to_field::<F>();
    let modulus_native = modulus.nat().to_field::<F>();
    let mut native = recompose(&terms.p) * recompose(&terms.r)
        - recompose(&terms.s)
        - recompose(&terms.q) * modulus_native;
    if !bool::from(padding_native.is_zero()) {
        native = native + Expression::Constant(padding_native);
    }
    out.push(("native residue", selector.clone() * native));
    out
}

/// The canonical comparison `x + d = m - 1` with `d >= 0`: the low two limbs
/// with a boolean borrow `beta = (m-1)_2 - d_2 - x_2`.
fn compare_constraints<F: PastaField>(
    selector: &Expression<F>,
    x: &[Expression<F>; LIMBS],
    d: &[Expression<F>; LIMBS],
    modulus: ForeignModulus,
) -> Vec<(&'static str, Expression<F>)> {
    let bound = modulus.limbs_minus_one();
    let radix = F::from_u128(1 << LIMB_BITS);
    let beta = constant::<F>(bound[2]) - d[2].clone() - x[2].clone();
    let low = d[0].clone() + x[0].clone() - constant(bound[0])
        + (d[1].clone() + x[1].clone() - constant(bound[1])) * radix
        - beta.clone() * (radix * radix);
    let boolean = beta.clone() * (Expression::Constant(F::ONE) - beta);
    vec![
        (
            "low limbs: x + d = (m-1) + beta B^2",
            selector.clone() * low,
        ),
        ("borrow beta is boolean", selector.clone() * boolean),
    ]
}

impl FfConfig {
    /// Configures the chip on ten advice columns (`c_0..c_2`, `q_0..q_2`,
    /// `u_0..u_3`; the six `c` and `q` columns are made equality-enabled)
    /// with its own range-table column `V`, four fixed pattern columns and,
    /// per distinct modulus of `moduli`, a multiplication, division,
    /// comparison and canonical-witness gate.
    ///
    /// Operations that place constants (reductions, inversions, constant
    /// multiplications) need a constants column in the circuit.
    pub fn configure<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        columns: [Column<Advice>; FF_ADVICE_COLUMNS],
        moduli: &[ForeignModulus],
    ) -> Self {
        let value = meta.fixed_column();
        Self::configure_on(meta, columns, moduli, value, &FfGuests::none())
    }

    /// [`Self::configure`] with `V` of the shared table as the range column
    /// and the guests' lookups merged into two of the ten arguments: the
    /// `c_0` argument (whose input has degree 3, so the guest's table
    /// expressions must have degree 1) and the `u_0` argument. The caller
    /// must keep every guest inactive on the foreign-field rows (the
    /// conditions of [`crate::table`]); the Q-leaf layout ([`crate::q_leaf`])
    /// does, and its tests check it.
    pub fn configure_shared<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        columns: [Column<Advice>; FF_ADVICE_COLUMNS],
        moduli: &[ForeignModulus],
        table: &SharedTable,
        guests: &FfGuests<'_, F>,
    ) -> Self {
        Self::configure_on(meta, columns, moduli, table.value(), guests)
    }

    fn configure_on<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        columns: [Column<Advice>; FF_ADVICE_COLUMNS],
        moduli: &[ForeignModulus],
        value: Column<Fixed>,
        guests: &FfGuests<'_, F>,
    ) -> Self {
        let [c0, c1, c2, q0, q1, q2, u0, u1, u2, u3] = columns;
        let values = [c0, c1, c2];
        let quotients = [q0, q1, q2];
        let carries = [u0, u1, u2, u3];
        for column in values.iter().chain(quotients.iter()) {
            meta.enable_equality(*column);
        }
        let pattern: [Column<Fixed>; FF_PATTERN_COLUMNS] =
            core::array::from_fn(|_| meta.fixed_column());
        let [h_c, h_q, s_u, t_u] = pattern;
        // The guests ride on the first `C` and the first `U` argument.
        let cq_guest = |index: usize| guests.cq.filter(|_| index == 0);
        let u_guest = |index: usize| guests.u.filter(|_| index == 0);
        for (index, column) in values.iter().enumerate() {
            range_lookup(
                meta,
                &format!("ff c_{index} range"),
                value,
                cq_guest(index),
                |cells| cq_residual(cells, *column, h_c, VALUE_TOPS[index]),
            );
        }
        for (index, column) in quotients.iter().enumerate() {
            range_lookup(
                meta,
                &format!("ff q_{index} range"),
                value,
                cq_guest(LIMBS + index),
                |cells| cq_residual(cells, *column, h_q, QUOTIENT_TOPS[index]),
            );
        }
        for (index, column) in carries.iter().enumerate() {
            range_lookup(
                meta,
                &format!("ff u_{index} range"),
                value,
                u_guest(index),
                |cells| u_residual(cells, *column, s_u, t_u),
            );
        }
        let mut configured: Vec<ModulusGates> = Vec::new();
        for modulus in moduli {
            if configured.iter().any(|gates| gates.modulus == *modulus) {
                continue;
            }
            let gates = ModulusGates {
                modulus: *modulus,
                mul: meta.selector(),
                div: meta.selector(),
                compare: meta.selector(),
                canonical_witness: meta.selector(),
            };
            let padding = modulus.division_padding().map_or([0; LIMBS], |(_, k)| k);
            let offset = F::from_u128(1 << CARRY_OFFSET_BITS);
            // Every gate anchors on the operand row: operands at the current
            // row, `C`/`Q` running-sum roots one row down, `U` roots here.
            let (operand, root) = (Rotation::cur(), Rotation::next());
            meta.create_gate(format!("ff mul {modulus:?}"), |cells| {
                let selector = cells.query_selector(gates.mul);
                let terms = FusedTerms {
                    p: values.map(|column| cells.query_advice(column, operand)),
                    r: quotients.map(|column| cells.query_advice(column, operand)),
                    s: values.map(|column| cells.query_advice(column, root)),
                    q: quotients.map(|column| cells.query_advice(column, root)),
                    u: carries.map(|column| {
                        cells.query_advice(column, Rotation::cur()) - Expression::Constant(offset)
                    }),
                };
                fused_constraints(&selector, &terms, *modulus, [0; LIMBS])
            });
            meta.create_gate(format!("ff div {modulus:?}"), |cells| {
                let selector = cells.query_selector(gates.div);
                let terms = FusedTerms {
                    p: quotients.map(|column| cells.query_advice(column, operand)),
                    r: values.map(|column| cells.query_advice(column, root)),
                    s: values.map(|column| cells.query_advice(column, operand)),
                    q: quotients.map(|column| cells.query_advice(column, root)),
                    u: carries.map(|column| {
                        cells.query_advice(column, Rotation::cur()) - Expression::Constant(offset)
                    }),
                };
                fused_constraints(&selector, &terms, *modulus, padding)
            });
            meta.create_gate(format!("ff canonical compare {modulus:?}"), |cells| {
                let selector = cells.query_selector(gates.compare);
                let x = quotients.map(|column| cells.query_advice(column, operand));
                let d = quotients.map(|column| cells.query_advice(column, root));
                compare_constraints(&selector, &x, &d, *modulus)
            });
            meta.create_gate(format!("ff canonical witness {modulus:?}"), |cells| {
                let selector = cells.query_selector(gates.canonical_witness);
                let x = values.map(|column| cells.query_advice(column, root));
                let d = quotients.map(|column| cells.query_advice(column, root));
                compare_constraints(&selector, &x, &d, *modulus)
            });
            configured.push(gates);
        }
        Self {
            c: values,
            q: quotients,
            u: carries,
            value,
            pattern,
            moduli: configured,
        }
    }

    /// The ten advice columns in configuration order.
    #[must_use]
    pub fn advice_columns(&self) -> [Column<Advice>; FF_ADVICE_COLUMNS] {
        let [c0, c1, c2] = self.c;
        let [q0, q1, q2] = self.q;
        let [u0, u1, u2, u3] = self.u;
        [c0, c1, c2, q0, q1, q2, u0, u1, u2, u3]
    }

    /// The range-table column `V` (the shared table's `V` in a shared
    /// configuration).
    #[must_use]
    pub const fn value_column(&self) -> Column<Fixed> {
        self.value
    }

    /// The pattern columns `h_C, h_Q, s_U, t_U`.
    #[must_use]
    pub const fn pattern_columns(&self) -> [Column<Fixed>; FF_PATTERN_COLUMNS] {
        self.pattern
    }

    /// The configured moduli, in configuration order.
    #[must_use]
    pub fn moduli(&self) -> Vec<ForeignModulus> {
        self.moduli.iter().map(|gates| gates.modulus).collect()
    }

    fn gates(&self, modulus: ForeignModulus) -> Result<&ModulusGates, Error> {
        self.moduli
            .iter()
            .find(|gates| gates.modulus == modulus)
            .ok_or(Error::Synthesis)
    }
}

/// The running-sum entries `floor(z / 2^(15 j))`, `j < rows`, of the
/// canonical integer of `value` (honest or not: an out-of-range value gets a
/// top entry the table rejects).
fn running_sum_entries<F: PastaField>(value: &F, rows: usize) -> Vec<F> {
    let integer = Nat::from_field(value);
    (0..rows)
        .map(|row| integer.shr(SUBLIMB_BITS * row).to_field())
        .collect()
}

/// The witness of a fused block: the result limbs, quotient limbs and
/// offset carries, as field elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FusedWitness<F> {
    c: [F; LIMBS],
    q: [F; LIMBS],
    u: [F; CARRIES],
}

/// The signed carries of `P R - S + K - q m` column by column.
fn carries(
    left: &[Nat; LIMBS],
    right: &[Nat; LIMBS],
    subtracted: &[Nat; LIMBS],
    padding: &[u128; LIMBS],
    quotient: &[Nat; LIMBS],
    modulus: &[u128; LIMBS],
) -> [Nat; CARRIES] {
    let mut out = [Nat::ZERO; CARRIES];
    let mut carry = Nat::ZERO;
    for (column, out) in out.iter_mut().enumerate() {
        let mut t = carry;
        for i in 0..LIMBS {
            let Some(j) = column.checked_sub(i) else {
                continue;
            };
            if j >= LIMBS {
                continue;
            }
            t = t
                .wrapping_add(&left[i].wrapping_mul(&right[j]))
                .wrapping_sub(&quotient[i].wrapping_mul(&Nat::from_u128(modulus[j])));
        }
        if column < LIMBS {
            t = t
                .wrapping_add(&Nat::from_u128(padding[column]))
                .wrapping_sub(&subtracted[column]);
        }
        carry = t.sar(LIMB_BITS);
        *out = carry;
    }
    out
}

/// The limbs of an integer below `2^576` with the top limb unbounded (as a
/// [`Nat`]).
fn nat_limbs(value: &Nat) -> [Nat; LIMBS] {
    [
        Nat::from_u128(value.low_bits_u128(LIMB_BITS)),
        Nat::from_u128(value.shr(LIMB_BITS).low_bits_u128(LIMB_BITS)),
        value.shr(2 * LIMB_BITS),
    ]
}

/// The integer of limb values.
fn recompose_nat(limbs: &[Nat; LIMBS]) -> Nat {
    limbs
        .iter()
        .enumerate()
        .fold(Nat::ZERO, |acc, (index, limb)| {
            acc.wrapping_add(&limb.shl(LIMB_BITS * index))
        })
}

/// The field witness of a fused block from integer limbs.
fn fused_witness_fields<F: PastaField>(
    c: &[Nat; LIMBS],
    quotient: &[Nat; LIMBS],
    carries: &[Nat; CARRIES],
) -> FusedWitness<F> {
    let offset = Nat::pow2(CARRY_OFFSET_BITS);
    FusedWitness {
        c: c.map(Nat::to_field),
        q: quotient.map(Nat::to_field),
        u: carries.map(|carry| carry.wrapping_add(&offset).to_field_signed()),
    }
}

/// The honest multiplication witness of `a b` (limbs) modulo `modulus`.
fn mul_witness<F: PastaField>(
    modulus: ForeignModulus,
    a: &[Nat; LIMBS],
    b: &[Nat; LIMBS],
) -> FusedWitness<F> {
    let m = modulus.nat();
    let product = recompose_nat(a).wrapping_mul(&recompose_nat(b));
    let (quotient, remainder) = product.div_rem(&m).unwrap_or((Nat::ZERO, Nat::ZERO));
    let c = nat_limbs(&remainder);
    let quotient = nat_limbs(&quotient);
    let carries = carries(a, b, &c, &[0; LIMBS], &quotient, &modulus.limbs());
    fused_witness_fields(&c, &quotient, &carries)
}

/// The honest division witness `c = a / b` (limbs) modulo `modulus`: the
/// gate proves `b c = a + q m - K`.
fn div_witness<F: PastaField>(
    modulus: ForeignModulus,
    a: &[Nat; LIMBS],
    b: &[Nat; LIMBS],
) -> FusedWitness<F> {
    let m = modulus.nat();
    let (_, padding) = modulus
        .division_padding()
        .unwrap_or((Nat::ZERO, [0; LIMBS]));
    let a_value = recompose_nat(a);
    let b_value = recompose_nat(b);
    // Branch-free: an uninvertible `b` gets `c = 0`; the gate then fails
    // unless `a = 0 mod m`, exactly when no quotient exists.
    let c_value = modulus.mul(&a_value, &modulus.fermat_inverse(&b_value));
    let numerator = b_value
        .wrapping_mul(&c_value)
        .wrapping_add(&from_limbs(&padding))
        .wrapping_sub(&a_value);
    let (quotient, _) = numerator.div_rem(&m).unwrap_or((Nat::ZERO, Nat::ZERO));
    let c = nat_limbs(&c_value);
    let quotient = nat_limbs(&quotient);
    let carries = carries(b, &c, a, &padding, &quotient, &modulus.limbs());
    fused_witness_fields(&c, &quotient, &carries)
}

/// The comparison witness `d = (m - 1) - x` (two's complement when `x >=
/// m`, so its top limb is out of range).
fn compare_witness<F: PastaField>(modulus: ForeignModulus, x: &[Nat; LIMBS]) -> [F; LIMBS] {
    let bound = modulus.nat().wrapping_sub(&Nat::ONE);
    limb_fields(&bound.wrapping_sub(&recompose_nat(x)))
}

/// An open block and the groups already used in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OpenBlock {
    start: usize,
    used: u8,
}

/// The foreign-field chip: blocks of seven rows on its ten columns,
/// allocated from its own cursor.
#[derive(Clone, Debug)]
pub struct FfChip<F: PastaField> {
    config: Option<FfConfig>,
    serialized: Option<SerializedState<F>>,
    rows: RowCursor,
    open: Option<OpenBlock>,
    blocks: usize,
    _marker: PhantomData<F>,
}

impl<F: PastaField> FfChip<F> {
    /// A chip whose first row is 0.
    #[must_use]
    pub const fn new(config: FfConfig) -> Self {
        Self::starting_at(config, 0)
    }

    /// A chip whose first row is `row`.
    #[must_use]
    pub const fn starting_at(config: FfConfig, row: usize) -> Self {
        Self::with_cursor(config, RowCursor::starting_at(row))
    }

    /// A chip whose blocks come from `rows`.
    #[must_use]
    pub const fn with_cursor(config: FfConfig, rows: RowCursor) -> Self {
        Self {
            config: Some(config),
            serialized: None,
            rows,
            open: None,
            blocks: 0,
            _marker: PhantomData,
        }
    }

    /// Uses the explicitly serialized CRT layout without configuring another
    /// gate or table. Both chips must share their reservation cursors with the
    /// owning interpreter; its range owner loads the table exactly once.
    #[must_use]
    pub fn serialized(
        glue: GlueChip<F>,
        range: RunningSumChip<F>,
        moduli: &[ForeignModulus],
    ) -> Self {
        Self {
            config: None,
            serialized: Some(SerializedState {
                kernel: None,
                glue,
                range,
                moduli: moduli.to_vec(),
            }),
            rows: RowCursor::starting_at(0),
            open: None,
            blocks: 0,
            _marker: PhantomData,
        }
    }

    /// Uses the four-row CRT gate for this explicitly serialized profile.
    /// The same Glue/range cursors and all original admission checks remain.
    ///
    /// # Errors
    /// The profile is fused, its modulus differs, or its ports differ.
    pub fn with_rotated_kernel(mut self, kernel: &rotated::RotatedFfConfig) -> Result<Self, Error> {
        let state = self.serialized.as_mut().ok_or(Error::Synthesis)?;
        if state.moduli.as_slice() != [kernel.modulus]
            || state.glue.config().advice() != kernel.columns
        {
            return Err(Error::Synthesis);
        }
        state.kernel = Some(*kernel);
        Ok(self)
    }

    /// Fused-layout configuration, absent for an explicit serialized layout.
    #[must_use]
    pub const fn config(&self) -> Option<&FfConfig> {
        self.config.as_ref()
    }

    fn fused_config(&self) -> Result<&FfConfig, Error> {
        self.config.as_ref().ok_or(Error::Synthesis)
    }

    /// The next arithmetic row; serialized operations share the owning
    /// interpreter's Glue cursor.
    #[must_use]
    pub fn next_row(&self) -> usize {
        self.serialized
            .as_ref()
            .map_or_else(|| self.rows.next_row(), |state| state.glue.next_row())
    }

    /// The number of blocks laid out.
    #[must_use]
    pub const fn blocks(&self) -> usize {
        self.blocks
    }

    /// Loads the range table: `V = v` on row `v` for every `v < 2^15`
    /// ([`RANGE_TABLE_ROWS`] rows from row 0; a circuit needs `k >= 16`). In
    /// a shared configuration these are the rows `[0, 2^15)` of the shared
    /// table, whose other columns stay zero there.
    ///
    /// # Errors
    ///
    /// [`Error`] when the table does not fit the usable rows.
    pub fn load_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let Some(config) = &self.config else {
            return Ok(());
        };
        let value = config.value;
        layouter.assign_region(
            || "ff range table",
            |mut region| {
                for (row, entry) in (0..RANGE_TABLE_ROWS).zip(0_u64..) {
                    region.assign_fixed(value, row, F::from(entry))?;
                }
                Ok(())
            },
        )
    }

    /// The start row of a block whose `groups` are free: the open block when
    /// none of them is used there, otherwise a new block.
    fn block(&mut self, groups: &[Group]) -> Result<usize, Error> {
        let wanted = groups.iter().fold(0, |acc, group| acc | group.bit());
        if let Some(open) = self.open.as_mut()
            && open.used & wanted == 0
        {
            open.used |= wanted;
            return Ok(open.start);
        }
        let start = self.rows.take(BLOCK_ROWS)?;
        self.open = Some(OpenBlock {
            start,
            used: wanted,
        });
        self.blocks = self.blocks.checked_add(1).ok_or(Error::BoundsFailure)?;
        Ok(start)
    }

    /// Turns on the range lookups of `group` in the block at `start`: `C`/`Q`
    /// steps on rows `1..=5` and the top on row 6 (whose scaled check reads
    /// it from row 0), `U` steps on rows `0..=5` and the top on row 6.
    fn activate(
        &self,
        region: &mut Region<'_, F>,
        start: usize,
        group: Group,
    ) -> Result<(), Error> {
        let [h_c, h_q, s_u, t_u] = self.fused_config()?.pattern;
        let top_row = start + BLOCK_ROWS - 1;
        match group {
            Group::C | Group::Q => {
                let h = if group == Group::C { h_c } else { h_q };
                for row in start + ROOT_ROW..top_row {
                    region.assign_fixed(h, row, F::from(PATTERN_STEP))?;
                }
                region.assign_fixed(h, top_row, F::from(PATTERN_TOP))?;
            }
            Group::U => {
                for row in start..top_row {
                    region.assign_fixed(s_u, row, F::ONE)?;
                }
                region.assign_fixed(t_u, top_row, F::ONE)?;
            }
        }
        Ok(())
    }

    /// Assigns the running sum of `value` (`rows` entries) to `column` from
    /// `start` and returns `z_0`.
    fn running_sum(
        region: &mut Region<'_, F>,
        column: Column<Advice>,
        start: usize,
        rows: usize,
        value: Value<F>,
    ) -> Result<Word<F>, Error> {
        let entries = value
            .map(|value| running_sum_entries(&value, rows))
            .transpose_vec(rows)?;
        let mut first = None;
        for (offset, entry) in entries.into_iter().enumerate() {
            let word = assign_word(region, column, start + offset, entry)?;
            if offset == 0 {
                first = Some(word);
            }
        }
        first.ok_or(Error::Synthesis)
    }

    /// Places one operand cell.
    fn place(
        region: &mut Region<'_, F>,
        column: Column<Advice>,
        row: usize,
        slot: Slot<'_, F>,
    ) -> Result<Word<F>, Error> {
        match slot {
            Slot::Copy(word) => copy_word(region, word, column, row),
            Slot::Constant(value) => assign_constant(region, column, row, value),
            Slot::Free(value) => assign_word(region, column, row, value),
        }
    }

    /// Lays out a fused block: operands `a` (group `C`, row 0) and `b`
    /// (group `Q`, row 0), the result `c` and quotient (rows `1..=6`) and the
    /// carries (rows `0..=6`); enables the gate of `mode` on row 0. Returns
    /// the result limbs.
    fn fused_block(
        &mut self,
        region: &mut Region<'_, F>,
        gates: SelectedModulus,
        mode: Mode,
        operands: ([Slot<'_, F>; LIMBS], [Slot<'_, F>; LIMBS]),
        witness: Value<FusedWitness<F>>,
        carry_layout: CarryLayout,
    ) -> Result<[Word<F>; LIMBS], Error> {
        if let Some(state) = &mut self.serialized {
            if gates.fused.is_some() {
                return Err(Error::Synthesis);
            }
            let mut place = |slots: [Slot<'_, F>; LIMBS]| -> Result<[Word<F>; LIMBS], Error> {
                slots
                    .into_iter()
                    .map(|slot| match slot {
                        Slot::Copy(word) => Ok(word.clone()),
                        Slot::Constant(value) => state.glue.constant(region, value),
                        Slot::Free(value) => state.glue.witness(region, value),
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .map_err(|_| Error::Synthesis)
            };
            let left = place(operands.0)?;
            let right = place(operands.1)?;
            self.blocks = self.blocks.checked_add(1).ok_or(Error::BoundsFailure)?;
            if let Some(kernel) = state.kernel {
                if carry_layout != CarryLayout::Full && kernel.is_staged() {
                    return kernel.constrain_short_product(
                        &mut state.glue,
                        &mut state.range,
                        region,
                        mode,
                        (&left, &right),
                        witness,
                        carry_layout,
                    );
                }
                return kernel.constrain(
                    &mut state.glue,
                    &mut state.range,
                    region,
                    mode,
                    (&left, &right),
                    witness,
                );
            }
            return serialized::constrain_fused(
                &mut state.glue,
                &mut state.range,
                region,
                mode,
                gates.modulus,
                (&left, &right),
                witness,
                carry_layout,
            );
        }
        let gates = gates.fused.ok_or(Error::Synthesis)?;
        let start = self.block(&[Group::C, Group::Q, Group::U])?;
        for group in [Group::C, Group::Q, Group::U] {
            self.activate(region, start, group)?;
        }
        let operand_row = start + OPERAND_ROW;
        let root_row = start + ROOT_ROW;
        let (a, b) = operands;
        for (index, slot) in a.into_iter().enumerate() {
            Self::place(region, self.fused_config()?.c[index], operand_row, slot)?;
        }
        for (index, slot) in b.into_iter().enumerate() {
            Self::place(region, self.fused_config()?.q[index], operand_row, slot)?;
        }
        let mut c = Vec::with_capacity(LIMBS);
        for (index, column) in self.fused_config()?.c.iter().enumerate() {
            let value = witness.map(|witness| witness.c[index]);
            c.push(Self::running_sum(
                region,
                *column,
                root_row,
                LIMB_SUBLIMBS,
                value,
            )?);
        }
        for (index, column) in self.fused_config()?.q.iter().enumerate() {
            let value = witness.map(|witness| witness.q[index]);
            Self::running_sum(region, *column, root_row, LIMB_SUBLIMBS, value)?;
        }
        for (index, column) in self.fused_config()?.u.iter().enumerate() {
            let value = witness.map(|witness| witness.u[index]);
            Self::running_sum(region, *column, start, CARRY_SUBLIMBS, value)?;
        }
        let selector = match mode {
            Mode::Mul => gates.mul,
            Mode::Div => gates.div,
        };
        selector.enable(region, operand_row)?;
        c.try_into().map_err(|_| Error::Synthesis)
    }

    /// The gates of a value's modulus, checking that `others` share it.
    fn gates_of(
        &self,
        modulus: ForeignModulus,
        others: &[&FfValue<F>],
    ) -> Result<SelectedModulus, Error> {
        if others.iter().any(|value| value.modulus != modulus) {
            return Err(Error::Synthesis);
        }
        if let Some(state) = &self.serialized {
            if !state.moduli.contains(&modulus) {
                return Err(Error::Synthesis);
            }
            Ok(SelectedModulus {
                modulus,
                fused: None,
            })
        } else {
            let gates = self.fused_config()?.gates(modulus).copied()?;
            Ok(SelectedModulus {
                modulus,
                fused: Some(gates),
            })
        }
    }

    /// Whether `a b` is a complete multiplication: operand limbs within the
    /// envelope and `max(a) max(b) < m 2^261`, so the honest quotient fits.
    #[must_use]
    pub fn mul_admissible(modulus: ForeignModulus, a: &[u128; LIMBS], b: &[u128; LIMBS]) -> bool {
        within_envelope(a)
            && within_envelope(b)
            && value_bound(a)
                .wrapping_mul(&value_bound(b))
                .cmp_vartime(&modulus.nat().shl(QUOTIENT_BITS))
                == Ordering::Less
    }

    /// Whether `a / b` is a complete division: operand limbs within the
    /// envelope and `max(b) + k < 2^261` for the padding `K = k m`.
    #[must_use]
    pub fn div_admissible(modulus: ForeignModulus, a: &[u128; LIMBS], b: &[u128; LIMBS]) -> bool {
        let Some((multiple, _)) = modulus.division_padding() else {
            return false;
        };
        within_envelope(a)
            && within_envelope(b)
            && value_bound(b)
                .wrapping_add(&multiple)
                .cmp_vartime(&Nat::pow2(QUOTIENT_BITS))
                == Ordering::Less
    }

    /// Unsigned bounded Pasta products with a proved integer product below
    /// 2^512 and each operand limb below2^88. These bounds, not Form or honest
    /// values, admit q87/87/85 and three offset92/range93 carries.
    fn bounded_product_admissible(
        modulus: ForeignModulus,
        a: &[u128; LIMBS],
        b: &[u128; LIMBS],
    ) -> bool {
        modulus.nat().cmp_vartime(&Nat::pow2(254)).is_gt()
            && modulus.nat().cmp_vartime(&Nat::pow2(255)).is_lt()
            && a.iter().chain(b).all(|bound| *bound < 1 << 88)
            && value_bound(a)
                .wrapping_mul(&value_bound(b))
                .cmp_vartime(&Nat::pow2(512))
                .is_lt()
    }

    /// Padded division in the same three-carry envelope. The numerator keeps
    /// the original94-bit admission; the nonnegative divisor has a tracked
    /// value below2^257 and limbs below2^89, with fixed padding below2^95.
    fn bounded_division_admissible(
        modulus: ForeignModulus,
        a: &[u128; LIMBS],
        b: &[u128; LIMBS],
    ) -> bool {
        modulus.nat().cmp_vartime(&Nat::pow2(254)).is_gt()
            && modulus.nat().cmp_vartime(&Nat::pow2(255)).is_lt()
            && within_envelope(a)
            && b.iter().all(|bound| *bound < 1 << 89)
            && value_bound(b).cmp_vartime(&Nat::pow2(257)).is_lt()
            && modulus
                .division_padding()
                .is_some_and(|(_, padding)| padding.iter().all(|limb| *limb < 1 << 95))
    }

    /// Selects only an envelope proved by the retained operand metadata.
    fn carry_layout(
        mode: Mode,
        modulus: ForeignModulus,
        a: Operand<'_, F>,
        b: Operand<'_, F>,
    ) -> CarryLayout {
        match mode {
            Mode::Mul
                if a.is_proper()
                    && b.is_proper()
                    && modulus.nat().cmp_vartime(&Nat::pow2(254)).is_gt() =>
            {
                CarryLayout::ProperProduct
            }
            Mode::Mul if Self::bounded_product_admissible(modulus, &a.bounds(), &b.bounds()) => {
                CarryLayout::BoundedPasta
            }
            Mode::Div if Self::bounded_division_admissible(modulus, &a.bounds(), &b.bounds()) => {
                CarryLayout::BoundedPasta
            }
            Mode::Mul | Mode::Div => CarryLayout::Full,
        }
    }

    fn fused_mul(
        &mut self,
        region: &mut Region<'_, F>,
        gates: SelectedModulus,
        a: Operand<'_, F>,
        b: Operand<'_, F>,
    ) -> Result<FfValue<F>, Error> {
        if !Self::mul_admissible(gates.modulus, &a.bounds(), &b.bounds()) {
            return Err(Error::Synthesis);
        }
        let modulus = gates.modulus;
        let witness = a
            .limb_values()
            .zip(b.limb_values())
            .map(|(a, b)| mul_witness::<F>(modulus, &a, &b));
        let carry_layout = Self::carry_layout(Mode::Mul, modulus, a, b);
        let limbs = self.fused_block(
            region,
            gates,
            Mode::Mul,
            (a.slots(), b.slots()),
            witness,
            carry_layout,
        )?;
        Ok(FfValue {
            limbs,
            bounds: self.fused_result_bounds(),
            modulus,
            form: Form::Proper,
        })
    }

    fn fused_div(
        &mut self,
        region: &mut Region<'_, F>,
        gates: SelectedModulus,
        a: Operand<'_, F>,
        b: Operand<'_, F>,
    ) -> Result<FfValue<F>, Error> {
        if !Self::div_admissible(gates.modulus, &a.bounds(), &b.bounds()) {
            return Err(Error::Synthesis);
        }
        let modulus = gates.modulus;
        let witness = a
            .limb_values()
            .zip(b.limb_values())
            .map(|(a, b)| div_witness::<F>(modulus, &a, &b));
        let carry_layout = Self::carry_layout(Mode::Div, modulus, a, b);
        let limbs = self.fused_block(
            region,
            gates,
            Mode::Div,
            (a.slots(), b.slots()),
            witness,
            carry_layout,
        )?;
        Ok(FfValue {
            limbs,
            bounds: self.fused_result_bounds(),
            modulus,
            form: Form::Proper,
        })
    }

    fn fused_result_bounds(&self) -> [u128; LIMBS] {
        self.serialized
            .as_ref()
            .and_then(|state| state.kernel)
            .map_or(PROPER_BOUNDS, |kernel| kernel.result_bounds())
    }

    /// Evaluates a fixed unsigned Proper dot batch on the explicitly shared
    /// Glue/range profile. The result remains Proper rather than Canonical.
    ///
    /// # Errors
    /// A fused-only profile, unconfigured or mixed modulus, non-Proper input,
    /// batch outside1..=8, modulus at most2^254, or layout error.
    pub fn dot_proper(
        &mut self,
        region: &mut Region<'_, F>,
        pairs: &[(&FfValue<F>, &FfValue<F>)],
    ) -> Result<FfValue<F>, Error> {
        let modulus = pairs.first().ok_or(Error::Synthesis)?.0.modulus;
        self.gates_of(modulus, &[])?;
        let state = self.serialized.as_mut().ok_or(Error::Synthesis)?;
        if let Some(kernel) = state.kernel
            && let Some(value) = kernel.dot(&mut state.glue, &mut state.range, region, pairs)?
        {
            return Ok(value);
        }
        dot::UnsignedDot::evaluate(&mut state.glue, &mut state.range, region, pairs)
    }

    /// Reduces `x` to a proper value congruent to it. The serialized layout
    /// uses the bounded unsigned reduction predicate; the fused layout uses
    /// multiplication by one. A proper or canonical `x` is returned unchanged.
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] for an unconfigured modulus, and [`Error`] from
    /// the layout.
    pub fn reduce(
        &mut self,
        region: &mut Region<'_, F>,
        x: &FfValue<F>,
    ) -> Result<FfValue<F>, Error> {
        if x.form >= Form::Proper {
            return Ok(x.clone());
        }
        let gates = self.gates_of(x.modulus, &[])?;
        if let Some(state) = &mut self.serialized {
            return reduction::reduce(&mut state.glue, &mut state.range, region, x);
        }
        self.fused_mul(
            region,
            gates,
            Operand::value(x),
            Operand::constant([1, 0, 0]),
        )
    }

    /// Reduces the operands of `a b` until the product is admissible: the
    /// non-proper operand with the larger value bound first.
    fn make_admissible(
        &mut self,
        region: &mut Region<'_, F>,
        a: &FfValue<F>,
        b: &FfValue<F>,
    ) -> Result<(FfValue<F>, FfValue<F>), Error> {
        let (mut a, mut b) = (a.clone(), b.clone());
        for _ in 0..2 {
            if Self::mul_admissible(a.modulus, &a.bounds, &b.bounds) {
                break;
            }
            self.reduce_larger(region, &mut a, &mut b)?;
        }
        if Self::mul_admissible(a.modulus, &a.bounds, &b.bounds) {
            Ok((a, b))
        } else {
            Err(Error::Synthesis)
        }
    }

    /// `a b mod m` as a proper value (one block of [`MUL_CELLS`] cells).
    /// Operands outside the admissible set are reduced first.
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] for mixed or unconfigured moduli, and [`Error`]
    /// from the layout.
    pub fn mul(
        &mut self,
        region: &mut Region<'_, F>,
        a: &FfValue<F>,
        b: &FfValue<F>,
    ) -> Result<FfValue<F>, Error> {
        let gates = self.gates_of(a.modulus, &[b])?;
        let (a, b) = self.make_admissible(region, a, b)?;
        self.fused_mul(region, gates, Operand::value(&a), Operand::value(&b))
    }

    /// `a^2 mod m`.
    ///
    /// # Errors
    ///
    /// As [`Self::mul`].
    pub fn square(
        &mut self,
        region: &mut Region<'_, F>,
        a: &FfValue<F>,
    ) -> Result<FfValue<F>, Error> {
        self.mul(region, a, a)
    }

    /// `a k mod m` for a constant `k` (reduced modulo `m`; its limbs are
    /// placed through the constants column).
    ///
    /// # Errors
    ///
    /// As [`Self::mul`].
    pub fn mul_constant(
        &mut self,
        region: &mut Region<'_, F>,
        a: &FfValue<F>,
        k: &Nat,
    ) -> Result<FfValue<F>, Error> {
        let gates = self.gates_of(a.modulus, &[])?;
        let limbs = to_limbs(&a.modulus.reduce(k)).ok_or(Error::Synthesis)?;
        let a = if Self::mul_admissible(a.modulus, &a.bounds, &limbs) {
            a.clone()
        } else {
            self.reduce(region, a)?
        };
        self.fused_mul(region, gates, Operand::value(&a), Operand::constant(limbs))
    }

    /// `a / b mod m` as a proper value: a witness `c` and one fused
    /// multiplication `b c = a + q m - K`. Unsatisfiable when `b = 0 mod m`
    /// and `a != 0 mod m`.
    ///
    /// # Errors
    ///
    /// As [`Self::mul`].
    pub fn div(
        &mut self,
        region: &mut Region<'_, F>,
        a: &FfValue<F>,
        b: &FfValue<F>,
    ) -> Result<FfValue<F>, Error> {
        let gates = self.gates_of(a.modulus, &[b])?;
        // Only the divisor's value bound limits a division.
        let b = if Self::div_admissible(b.modulus, &a.bounds, &b.bounds) {
            b.clone()
        } else {
            self.reduce(region, b)?
        };
        self.fused_div(region, gates, Operand::value(a), Operand::value(&b))
    }

    /// `b^-1 mod m` as a proper value (a division of the constant one).
    /// Unsatisfiable when `b = 0 mod m`.
    ///
    /// # Errors
    ///
    /// As [`Self::mul`].
    pub fn inverse(
        &mut self,
        region: &mut Region<'_, F>,
        b: &FfValue<F>,
    ) -> Result<FfValue<F>, Error> {
        let gates = self.gates_of(b.modulus, &[])?;
        let b = if Self::div_admissible(b.modulus, &[1, 0, 0], &b.bounds) {
            b.clone()
        } else {
            self.reduce(region, b)?
        };
        self.fused_div(
            region,
            gates,
            Operand::constant([1, 0, 0]),
            Operand::value(&b),
        )
    }

    /// A proper witness: the limbs of a 256-bit integer, range-checked in
    /// group `C` ([`WITNESS_CELLS`] cells). Not proven below `m`.
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] for an unconfigured modulus, and [`Error`] from
    /// the layout.
    pub fn witness(
        &mut self,
        region: &mut Region<'_, F>,
        modulus: ForeignModulus,
        value: Value<[u64; 4]>,
    ) -> Result<FfValue<F>, Error> {
        self.gates_of(modulus, &[])?;
        if let Some(state) = &mut self.serialized {
            return serialized::SerializedFf::witness(&mut state.range, region, modulus, value);
        }
        let start = self.block(&[Group::C])?;
        self.activate(region, start, Group::C)?;
        let limbs = value.map(|value| limb_fields::<F>(&Nat::from_words(value)));
        let limbs = self.value_running_sums(region, start, limbs)?;
        Ok(FfValue {
            limbs,
            bounds: PROPER_BOUNDS,
            modulus,
            form: Form::Proper,
        })
    }

    /// Running sums of a proper value in group `C` of the block at `start`
    /// (rows `1..=6`).
    fn value_running_sums(
        &self,
        region: &mut Region<'_, F>,
        start: usize,
        limbs: Value<[F; LIMBS]>,
    ) -> Result<[Word<F>; LIMBS], Error> {
        let mut out = Vec::with_capacity(LIMBS);
        for (index, column) in self.fused_config()?.c.iter().enumerate() {
            let value = limbs.map(|limbs| limbs[index]);
            out.push(Self::running_sum(
                region,
                *column,
                start + ROOT_ROW,
                LIMB_SUBLIMBS,
                value,
            )?);
        }
        out.try_into().map_err(|_| Error::Synthesis)
    }

    /// Running sums of the comparison difference in group `Q` of the block
    /// at `start` (rows `1..=6`).
    fn difference_running_sums(
        &self,
        region: &mut Region<'_, F>,
        start: usize,
        difference: Value<[F; LIMBS]>,
    ) -> Result<(), Error> {
        for (index, column) in self.fused_config()?.q.iter().enumerate() {
            let value = difference.map(|difference| difference[index]);
            Self::running_sum(region, *column, start + ROOT_ROW, LIMB_SUBLIMBS, value)?;
        }
        Ok(())
    }

    /// A canonical witness: a proper witness in group `C` and its
    /// comparison `x + d = m - 1` in group `Q` of one block
    /// ([`CANONICAL_WITNESS_CELLS`] cells). Unsatisfiable for `value >= m`.
    ///
    /// # Errors
    ///
    /// As [`Self::witness`].
    pub fn witness_canonical(
        &mut self,
        region: &mut Region<'_, F>,
        modulus: ForeignModulus,
        value: Value<[u64; 4]>,
    ) -> Result<FfValue<F>, Error> {
        let gates = self.gates_of(modulus, &[])?;
        if let Some(state) = &mut self.serialized {
            let value =
                serialized::SerializedFf::witness(&mut state.range, region, modulus, value)?;
            return serialized::SerializedFf::assert_canonical(
                &mut state.glue,
                &mut state.range,
                region,
                &value,
            );
        }
        let gates = gates.fused.ok_or(Error::Synthesis)?;
        let start = self.block(&[Group::C, Group::Q])?;
        self.activate(region, start, Group::C)?;
        self.activate(region, start, Group::Q)?;
        let integer = value.map(Nat::from_words);
        let limbs = integer.map(|value| limb_fields::<F>(&value));
        let limbs = self.value_running_sums(region, start, limbs)?;
        let difference = integer.map(|value| compare_witness::<F>(modulus, &nat_limbs(&value)));
        self.difference_running_sums(region, start, difference)?;
        gates
            .canonical_witness
            .enable(region, start + OPERAND_ROW)?;
        Ok(FfValue {
            limbs,
            bounds: PROPER_BOUNDS,
            modulus,
            form: Form::Canonical,
        })
    }

    // TODO(M4): soft-mode verifiers (spec S12) need a bit-valued `x < m`
    // that is satisfiable for every witness; only the hard check exists.
    /// Proves `x < m` for a proper `x` (a non-proper `x` is reduced first)
    /// and returns `x` as canonical: the difference `d = m - 1 - x` in group
    /// `Q` with copies of `x` ([`COMPARE_CELLS`] cells). Unsatisfiable for
    /// `x >= m`.
    ///
    /// # Errors
    ///
    /// As [`Self::witness`].
    pub fn assert_canonical(
        &mut self,
        region: &mut Region<'_, F>,
        x: &FfValue<F>,
    ) -> Result<FfValue<F>, Error> {
        if x.form == Form::Canonical {
            return Ok(x.clone());
        }
        let x = self.reduce(region, x)?;
        let gates = self.gates_of(x.modulus, &[])?;
        if let Some(state) = &mut self.serialized {
            return serialized::SerializedFf::assert_canonical(
                &mut state.glue,
                &mut state.range,
                region,
                &x,
            );
        }
        let gates = gates.fused.ok_or(Error::Synthesis)?;
        let start = self.block(&[Group::Q])?;
        self.activate(region, start, Group::Q)?;
        let modulus = x.modulus;
        let difference = x
            .limb_values()
            .map(|limbs| compare_witness::<F>(modulus, &limbs));
        self.difference_running_sums(region, start, difference)?;
        for (index, limb) in x.limbs.iter().enumerate() {
            copy_word(
                region,
                limb,
                self.fused_config()?.q[index],
                start + OPERAND_ROW,
            )?;
        }
        gates.compare.enable(region, start + OPERAND_ROW)?;
        Ok(FfValue {
            form: Form::Canonical,
            ..x
        })
    }

    /// Constrains two canonical values to be equal (limb copies).
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] unless both are canonical with one modulus, and
    /// [`Error`] from the copies.
    pub fn assert_equal(
        region: &mut Region<'_, F>,
        x: &FfValue<F>,
        y: &FfValue<F>,
    ) -> Result<(), Error> {
        if x.modulus != y.modulus || x.form != Form::Canonical || y.form != Form::Canonical {
            return Err(Error::Synthesis);
        }
        for (x, y) in x.limbs.iter().zip(&y.limbs) {
            region.constrain_equal(x.cell(), y.cell())?;
        }
        Ok(())
    }

    /// A canonical constant (`value < m`): three glue constant cells.
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] for `value >= m` or an unconfigured modulus, and
    /// [`Error`] from the layout.
    pub fn constant(
        &self,
        glue: &mut GlueChip<F>,
        region: &mut Region<'_, F>,
        modulus: ForeignModulus,
        value: &Nat,
    ) -> Result<FfValue<F>, Error> {
        self.gates_of(modulus, &[])?;
        if !modulus.is_canonical(value) {
            return Err(Error::Synthesis);
        }
        let limbs = to_limbs(value).ok_or(Error::Synthesis)?;
        let mut words = Vec::with_capacity(LIMBS);
        for limb in limbs {
            words.push(glue.constant(region, F::from_u128(limb))?);
        }
        Ok(FfValue {
            limbs: words.try_into().map_err(|_| Error::Synthesis)?,
            bounds: limbs,
            modulus,
            form: Form::Canonical,
        })
    }

    /// One limb-wise linear combination `sum coefficient x + constant` on the
    /// glue chip, with the given result bounds (already checked).
    fn limbwise(
        glue: &mut GlueChip<F>,
        region: &mut Region<'_, F>,
        terms: &[(F, &FfValue<F>)],
        constants: [u128; LIMBS],
        bounds: [u128; LIMBS],
        modulus: ForeignModulus,
    ) -> Result<FfValue<F>, Error> {
        let mut words = Vec::with_capacity(LIMBS);
        for (index, constant) in constants.iter().enumerate() {
            let limb_terms: Vec<(F, &Word<F>)> = terms
                .iter()
                .map(|(coefficient, value)| (*coefficient, &value.limbs[index]))
                .collect();
            words.push(glue.linear(region, &limb_terms, F::from_u128(*constant))?);
        }
        Ok(FfValue {
            limbs: words.try_into().map_err(|_| Error::Synthesis)?,
            bounds,
            modulus,
            form: Form::Bounded,
        })
    }

    /// Reduces the non-proper operand with the larger bound (for linear
    /// operations whose result would leave the envelope).
    fn reduce_larger(
        &mut self,
        region: &mut Region<'_, F>,
        x: &mut FfValue<F>,
        y: &mut FfValue<F>,
    ) -> Result<(), Error> {
        let x_first = match (x.form >= Form::Proper, y.form >= Form::Proper) {
            (false, false) => {
                value_bound(&x.bounds).cmp_vartime(&value_bound(&y.bounds)) != Ordering::Less
            }
            (false, true) => true,
            (true, false) => false,
            (true, true) => return Err(Error::Synthesis),
        };
        if x_first {
            *x = self.reduce(region, x)?;
        } else {
            *y = self.reduce(region, y)?;
        }
        Ok(())
    }

    /// `x + y` (unreduced; limb bounds add).
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] for mixed or unconfigured moduli, and [`Error`]
    /// from the layout.
    pub fn add(
        &mut self,
        glue: &mut GlueChip<F>,
        region: &mut Region<'_, F>,
        x: &FfValue<F>,
        y: &FfValue<F>,
    ) -> Result<FfValue<F>, Error> {
        self.gates_of(x.modulus, &[y])?;
        let (mut x, mut y) = (x.clone(), y.clone());
        for _ in 0..3 {
            let bounds = add_bounds(&x.bounds, &y.bounds);
            if let Some(bounds) = bounds.filter(within_envelope) {
                return Self::limbwise(
                    glue,
                    region,
                    &[(F::ONE, &x), (F::ONE, &y)],
                    [0; LIMBS],
                    bounds,
                    x.modulus,
                );
            }
            self.reduce_larger(region, &mut x, &mut y)?;
        }
        Err(Error::Synthesis)
    }

    /// `x - y + K` for the padding `K = k m` that dominates `y`'s limbs
    /// (unreduced, congruent to `x - y`).
    ///
    /// # Errors
    ///
    /// As [`Self::add`].
    pub fn sub(
        &mut self,
        glue: &mut GlueChip<F>,
        region: &mut Region<'_, F>,
        x: &FfValue<F>,
        y: &FfValue<F>,
    ) -> Result<FfValue<F>, Error> {
        self.gates_of(x.modulus, &[y])?;
        let (mut x, mut y) = (x.clone(), y.clone());
        for _ in 0..3 {
            let (_, padding) = x.modulus.padding(&y.bounds).ok_or(Error::Synthesis)?;
            let bounds = add_bounds(&x.bounds, &padding);
            if let Some(bounds) = bounds.filter(within_envelope) {
                return Self::limbwise(
                    glue,
                    region,
                    &[(F::ONE, &x), (-F::ONE, &y)],
                    padding,
                    bounds,
                    x.modulus,
                );
            }
            self.reduce_larger(region, &mut x, &mut y)?;
        }
        Err(Error::Synthesis)
    }

    /// `K - y` for the padding `K = k m` that dominates `y`'s limbs
    /// (congruent to `-y`).
    ///
    /// # Errors
    ///
    /// As [`Self::add`].
    pub fn neg(
        &mut self,
        glue: &mut GlueChip<F>,
        region: &mut Region<'_, F>,
        y: &FfValue<F>,
    ) -> Result<FfValue<F>, Error> {
        self.gates_of(y.modulus, &[])?;
        let mut y = y.clone();
        for _ in 0..2 {
            let (_, padding) = y.modulus.padding(&y.bounds).ok_or(Error::Synthesis)?;
            if within_envelope(&padding) {
                return Self::limbwise(glue, region, &[(-F::ONE, &y)], padding, padding, y.modulus);
            }
            y = self.reduce(region, &y)?;
        }
        Err(Error::Synthesis)
    }

    /// `k x` for a small `k` (unreduced; limb bounds scale). A non-proper
    /// `x` is reduced first when needed; the result must stay within the
    /// envelope, so `k <= 128` for a proper `x`.
    ///
    /// # Errors
    ///
    /// As [`Self::add`], and [`Error::Synthesis`] for a `k` whose product
    /// leaves the envelope even for a proper `x`.
    pub fn scale(
        &mut self,
        glue: &mut GlueChip<F>,
        region: &mut Region<'_, F>,
        x: &FfValue<F>,
        k: u64,
    ) -> Result<FfValue<F>, Error> {
        self.gates_of(x.modulus, &[])?;
        let mut x = x.clone();
        for _ in 0..2 {
            let bounds = scale_bounds(&x.bounds, k);
            if let Some(bounds) = bounds.filter(within_envelope) {
                return Self::limbwise(
                    glue,
                    region,
                    &[(F::from(k), &x)],
                    [0; LIMBS],
                    bounds,
                    x.modulus,
                );
            }
            if x.form >= Form::Proper {
                break;
            }
            x = self.reduce(region, &x)?;
        }
        Err(Error::Synthesis)
    }

    /// `bit ? x : y`, limb-wise (the form is the weaker of the two).
    ///
    /// # Errors
    ///
    /// As [`Self::add`].
    pub fn select(
        &self,
        glue: &mut GlueChip<F>,
        region: &mut Region<'_, F>,
        bit: &Bit<F>,
        x: &FfValue<F>,
        y: &FfValue<F>,
    ) -> Result<FfValue<F>, Error> {
        self.gates_of(x.modulus, &[y])?;
        let mut words = Vec::with_capacity(LIMBS);
        for (x, y) in x.limbs.iter().zip(&y.limbs) {
            words.push(glue.select(region, bit, x, y)?);
        }
        let bounds = core::array::from_fn(|index| x.bounds[index].max(y.bounds[index]));
        Ok(FfValue {
            limbs: words.try_into().map_err(|_| Error::Synthesis)?,
            bounds,
            modulus: x.modulus,
            form: x.form.min(y.form),
        })
    }

    /// The native residue `sum x_i B^i mod N` of the integer `x` (one glue
    /// row).
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout.
    pub fn native(
        glue: &mut GlueChip<F>,
        region: &mut Region<'_, F>,
        x: &FfValue<F>,
    ) -> Result<Word<F>, Error> {
        let radix = F::from_u128(1 << LIMB_BITS);
        let [x0, x1, x2] = &x.limbs;
        glue.linear(
            region,
            &[(F::ONE, x0), (radix, x1), (radix * radix, x2)],
            F::ZERO,
        )
    }
}

/// Limb-wise `x + y`, or `None` on overflow.
fn add_bounds(x: &[u128; LIMBS], y: &[u128; LIMBS]) -> Option<[u128; LIMBS]> {
    Some([
        x[0].checked_add(y[0])?,
        x[1].checked_add(y[1])?,
        x[2].checked_add(y[2])?,
    ])
}

/// Limb-wise `k x`, or `None` on overflow.
fn scale_bounds(x: &[u128; LIMBS], k: u64) -> Option<[u128; LIMBS]> {
    let k = u128::from(k);
    Some([
        x[0].checked_mul(k)?,
        x[1].checked_mul(k)?,
        x[2].checked_mul(k)?,
    ])
}
