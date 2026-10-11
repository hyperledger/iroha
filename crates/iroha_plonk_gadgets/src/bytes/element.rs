//! 32-byte proof messages linked to field elements.
//!
//! # Little-endian messages (PIPA-v1 section 1)
//!
//! A message laid out with the secondary segments `[16, 15, 1]`
//! ([`le_message_segments`]) decodes ([`decode_le_element`]) into
//!
//! - `lo`, the first 16 bytes (`< 2^128`, a tape word),
//! - `hi = mid + 2^120 t7 < 2^127`, from the next 15 bytes and the low seven
//!   bits of the last byte `t = t7 + 128 top`,
//! - `top`, bit 255,
//!
//! with one boolean row, two glue rows and a 7-bit range check. The integer
//! value of the 32 bytes is `lo + 2^128 hi + 2^255 top`.
//!
//! - **Compressed point** (`x` with the parity of `y` in bit 255; the point's
//!   coordinates are cells of the circuit field): `x = lo + 2^128 hi`, that
//!   integer is below the modulus ([`assert_le_max`]), and the canonical
//!   parity of `y` ([`parity`]) is `top`. A wrong sign bit, the opposite
//!   point `(x, -y)`, a non-canonical `x + p` and the parity of the alias
//!   `y + p` are all unsatisfiable.
//! - **Point over a foreign field** (a Vesta accumulator point in an `Fp`
//!   circuit): [`assert_foreign_point_bytes`] checks `x` and `y` (given as
//!   limbs) canonical in that field and the low bit of `y` against `top`.
//! - **Scalar** of a field `G`: `top = 0` and `lo + 2^128 hi < |G|`.
//!
//! Soft forms ([`point_bytes_match`], [`decode_point_soft`],
//! [`decode_pipa_point_soft`], [`scalar_bytes_canonical`],
//! [`foreign_point_bytes_match`]) return a bit instead and are satisfiable
//! for every byte string and every witness. The generic soft decode is the
//! native `GroupEncoding::from_bytes`: it proves `x^3 + 5` a square or not
//! (a root of `x^3 + 5` or of `5 (x^3 + 5)`, since `5` is not a square),
//! accepts the identity encoding (all zeros) and rejects the signed zero, so
//! its point and verdict are functions of the bytes alone, as soft
//! verifiers require: a prover can neither reject valid bytes with a wrong
//! root nor accept invalid ones. Proof and accumulator points of a PIPA-v1
//! proof go through the native PIPA decoder, which also rejects the
//! identity: soft verifiers of PIPA proofs use [`decode_pipa_point_soft`],
//! whose verdict is `canonical q` and whose rejected output is a fixed curve
//! point.
//!
//! # Canonical comparison
//!
//! For `max = m - 1 = M_lo + 2^128 M_hi`, `lo + 2^128 hi <= max` (with
//! `lo, hi < 2^128`) holds iff `hi <= M_hi` and, when `hi = M_hi`,
//! `lo <= M_lo`: the hard form range-checks `M_hi - hi` and
//! `[hi = M_hi] (M_lo - lo)` to 128 bits (the `statement` S6 rule), the soft
//! form computes `[hi < M_hi] + [hi = M_hi] [lo <= M_lo]`.
//!
//! # Parity
//!
//! [`parity`] decomposes `y = b + 2 r + 2^128 hi` with `b` boolean,
//! `r < 2^127`, `hi < 2^127` and `b + 2 r + 2^128 hi <= p - 1`, so the
//! decomposition is the canonical one and `b` is the parity of the canonical
//! `y`. The alias `y + p` (whose parity is the opposite, `p` being odd) fails
//! the comparison.
//!
//! # Big-endian values
//!
//! A 32-byte big-endian value (a P-256 coordinate, `r` or `s` of a signed
//! transcript) laid out with the big-endian secondary segments `[16, 16]`
//! ([`be_value_segments`]) gives its high and low 128-bit halves directly
//! ([`decode_be_element`], no rows); [`assert_le_max`] and [`le_max`] compare
//! them with any 256-bit modulus.

use iroha_pasta::PastaField;
use iroha_plonk::frontend::{Error, Region, Value};

use super::tape::{ByteRun, SegmentSpec};
use crate::{
    arith::GlueChip,
    cells::{Bit, U128, Uint, Word},
    range::u128::UintChip,
    statement::foreign_limbs,
};

/// Bytes of the low limb of a message.
const LOW_BYTES: usize = 16;
/// Bytes of the middle segment of a little-endian message.
const MIDDLE_BYTES: usize = 15;

/// The secondary segments of `count` consecutive 32-byte little-endian
/// messages from run offset `start`: `[16, 15, 1]` each.
#[must_use]
pub fn le_message_segments(start: usize, count: usize) -> Vec<SegmentSpec> {
    (0..count)
        .flat_map(|index| {
            let base = start + 32 * index;
            [
                SegmentSpec::little(base, LOW_BYTES),
                SegmentSpec::little(base + LOW_BYTES, MIDDLE_BYTES),
                SegmentSpec::little(base + LOW_BYTES + MIDDLE_BYTES, 1),
            ]
        })
        .collect()
}

/// The secondary segments of `count` consecutive 32-byte big-endian values
/// from run offset `start`: `[16, 16]` big-endian each (high half first).
#[must_use]
pub fn be_value_segments(start: usize, count: usize) -> Vec<SegmentSpec> {
    (0..count)
        .flat_map(|index| {
            let base = start + 32 * index;
            [
                SegmentSpec::big(base, LOW_BYTES),
                SegmentSpec::big(base + LOW_BYTES, LOW_BYTES),
            ]
        })
        .collect()
}

/// `m - 1` of the field `G` as limbs `(M_lo, M_hi)`.
#[must_use]
pub fn modulus_max<G: PastaField>() -> [u128; 2] {
    foreign_limbs(&-G::ONE)
}

/// Native reference of the compressed point encoding (PIPA-v1 section 1,
/// `pasta_curves` 0.5.2): the canonical little-endian `x` with the parity of
/// the canonical `y` in bit 255. The identity `(0, 0)` encodes as zeros.
#[must_use]
pub fn point_bytes_native<F: PastaField>(x: &F, y: &F) -> [u8; 32] {
    let mut bytes = x.to_repr();
    let sign = y.to_repr()[0] & 1;
    bytes[31] |= sign << 7;
    bytes
}

/// `2^power` in `F` for `power < 256`.
fn two_power<F: PastaField>(power: u64) -> F {
    F::from(2_u64).pow_vartime([power, 0, 0, 0])
}

/// A decoded little-endian 32-byte message: `lo + 2^128 hi + 2^255 top`.
#[derive(Clone, Debug)]
pub struct LeElement<F: PastaField> {
    lo: U128<F>,
    hi: Uint<F, 127>,
    top: Bit<F>,
}

impl<F: PastaField> LeElement<F> {
    /// Assigns one exact 32-byte private message as bounded low/high limbs and
    /// its top bit, without a separate byte tape. This representation is
    /// bijective for all 256-bit strings, including malformed proof encodings.
    /// Use the tape decoder when the same bytes also enter a digest or export:
    /// this constructor does not bind a separately assigned byte sequence.
    ///
    /// # Errors
    /// A range or glue row cannot be assigned.
    pub fn assign(
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
        bytes: Value<[u8; 32]>,
    ) -> Result<Self, Error> {
        let lo = bytes.map(|bytes| {
            let mut low = [0; 16];
            low.copy_from_slice(&bytes[..16]);
            u128::from_le_bytes(low)
        });
        let hi = bytes.map(|bytes| {
            let mut high = [0; 16];
            high.copy_from_slice(&bytes[16..]);
            u128::from_le_bytes(high) & ((1_u128 << 127) - 1)
        });
        let lo = uint.assign::<128>(region, lo)?;
        let hi = uint.assign::<127>(region, hi)?;
        let top = uint
            .glue()
            .boolean(region, bytes.map(|bytes| bytes[31] >> 7 == 1))?;
        Ok(Self { lo, hi, top })
    }

    /// Bytes `0 .. 16` as an integer.
    #[must_use]
    pub const fn lo(&self) -> &U128<F> {
        &self.lo
    }

    /// Bits `128 .. 255`.
    #[must_use]
    pub const fn hi(&self) -> &Uint<F, 127> {
        &self.hi
    }

    /// Bit 255 (the sign of a compressed point).
    #[must_use]
    pub const fn top(&self) -> &Bit<F> {
        &self.top
    }
}

/// A decoded big-endian 32-byte value: `2^128 hi + lo`.
#[derive(Clone, Debug)]
pub struct BeElement<F: PastaField> {
    hi: U128<F>,
    lo: U128<F>,
}

impl<F: PastaField> BeElement<F> {
    /// The high 128 bits (bytes `0 .. 16`).
    #[must_use]
    pub const fn hi(&self) -> &U128<F> {
        &self.hi
    }

    /// The low 128 bits (bytes `16 .. 32`).
    #[must_use]
    pub const fn lo(&self) -> &U128<F> {
        &self.lo
    }
}

/// Decodes the little-endian message at run offset `start`, laid out with
/// [`le_message_segments`].
///
/// # Errors
///
/// [`Error::Synthesis`] when the run lacks those segments, and [`Error`]
/// from the layout.
pub fn decode_le_element<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    run: &ByteRun<F>,
    start: usize,
) -> Result<LeElement<F>, Error> {
    let lo = run.secondary_segment(SegmentSpec::little(start, LOW_BYTES))?;
    let middle = run.secondary_segment(SegmentSpec::little(start + LOW_BYTES, MIDDLE_BYTES))?;
    let last = run.secondary_segment(SegmentSpec::little(start + LOW_BYTES + MIDDLE_BYTES, 1))?;
    let last_word = last.word().clone();
    let glue = uint.glue();
    let top = glue.boolean(
        region,
        last_word
            .value()
            .map(|byte| super::field_le_bytes(&byte)[0] >= 0x80),
    )?;
    let low_bits = glue.linear(
        region,
        &[(F::ONE, &last_word), (-F::from(128_u64), top.word())],
        F::ZERO,
    )?;
    let hi = glue.linear(
        region,
        &[(F::ONE, middle.word()), (two_power::<F>(120), &low_bits)],
        F::ZERO,
    )?;
    uint.range().range_check(region, &low_bits, 7)?;
    Ok(LeElement {
        lo: Uint::new(lo.word().clone()),
        hi: Uint::new(hi),
        top,
    })
}

/// Decodes the big-endian value at run offset `start`, laid out with
/// [`be_value_segments`] (no rows: the tape words are the halves).
///
/// # Errors
///
/// [`Error::Synthesis`] when the run lacks those segments.
pub fn decode_be_element<F: PastaField>(
    run: &ByteRun<F>,
    start: usize,
) -> Result<BeElement<F>, Error> {
    let hi = run.secondary_segment(SegmentSpec::big(start, LOW_BYTES))?;
    let lo = run.secondary_segment(SegmentSpec::big(start + LOW_BYTES, LOW_BYTES))?;
    Ok(BeElement {
        hi: Uint::new(hi.word().clone()),
        lo: Uint::new(lo.word().clone()),
    })
}

/// `lo + 2^128 hi` (the message without its top bit, reduced into `F`).
///
/// # Errors
///
/// [`Error`] from the layout.
pub fn element_value<F: PastaField>(
    glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    element: &LeElement<F>,
) -> Result<Word<F>, Error> {
    glue.linear(
        region,
        &[
            (F::ONE, element.lo.word()),
            (two_power::<F>(128), element.hi.word()),
        ],
        F::ZERO,
    )
}

/// Constrains `lo + 2^128 hi <= max` for `lo < 2^128` (an integer the caller
/// bounded) and `hi < 2^128`, with `max = (M_lo, M_hi)`.
///
/// # Errors
///
/// [`Error`] from the layout.
pub fn assert_le_max<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    lo: &Word<F>,
    hi: &U128<F>,
    max: [u128; 2],
) -> Result<(), Error> {
    let [max_lo, max_hi] = max;
    let glue = uint.glue();
    let hi_slack = glue.linear(region, &[(-F::ONE, hi.word())], F::from_u128(max_hi))?;
    let at_max = glue.is_zero(region, &hi_slack)?;
    let lo_slack = glue.linear(region, &[(-F::ONE, lo)], F::from_u128(max_lo))?;
    let bounded = glue.mul(region, at_max.word(), &lo_slack)?;
    uint.range().range_check(region, &hi_slack, 128)?;
    uint.range().range_check(region, &bounded, 128)?;
    Ok(())
}

/// `[lo + 2^128 hi <= max]` for `lo, hi < 2^128` (never unsatisfiable).
///
/// # Errors
///
/// [`Error`] from the layout.
pub fn le_max<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    lo: &U128<F>,
    hi: &U128<F>,
    max: [u128; 2],
) -> Result<Bit<F>, Error> {
    let [max_lo, max_hi] = max;
    let max_hi_cell = uint.constant::<128>(region, max_hi)?;
    let max_lo_cell = uint.constant::<128>(region, max_lo)?;
    let hi_below = uint.lt(region, hi, &max_hi_cell)?;
    let lo_above = uint.lt(region, &max_lo_cell, lo)?;
    let glue = uint.glue();
    let at_max = glue.is_equal(region, hi.word(), max_hi_cell.word())?;
    let lo_within = glue.not(region, &lo_above)?;
    // The two cases are exclusive, so their sum is a bit.
    let within = glue.mul_add(region, at_max.word(), lo_within.word(), hi_below.word())?;
    Ok(Bit::new(within))
}

/// The canonical parity of `y`: bit 0 of the canonical integer value.
///
/// # Errors
///
/// [`Error`] from the layout.
pub fn parity<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    y: &Word<F>,
) -> Result<Bit<F>, Error> {
    let witness = y.value().map(|y| {
        let [lo, hi] = foreign_limbs(&y);
        (lo & 1 == 1, lo >> 1, hi)
    });
    parity_with_witness(uint, region, y, witness)
}

/// [`parity`] with the decomposition `(b, r, hi)` supplied by the caller
/// (tests force the alias `y + p` through it).
pub(crate) fn parity_with_witness<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    y: &Word<F>,
    witness: Value<(bool, u128, u128)>,
) -> Result<Bit<F>, Error> {
    let bit = uint
        .glue()
        .boolean(region, witness.map(|(bit, _, _)| bit))?;
    let half = uint.assign::<127>(region, witness.map(|(_, half, _)| half))?;
    let hi = uint.assign::<127>(region, witness.map(|(_, _, hi)| hi))?;
    let glue = uint.glue();
    let lo = glue.linear(
        region,
        &[(F::ONE, bit.word()), (F::from(2_u64), half.word())],
        F::ZERO,
    )?;
    let recomposed = glue.linear(
        region,
        &[(F::ONE, &lo), (two_power::<F>(128), hi.word())],
        F::ZERO,
    )?;
    GlueChip::assert_equal(region, &recomposed, y)?;
    assert_le_max(
        uint,
        region,
        &lo,
        &UintChip::widen::<127, 128>(&hi),
        modulus_max::<F>(),
    )?;
    Ok(bit)
}

/// Hard point link: the message is the compressed encoding of `(x, y)`, two
/// cells of the circuit field. The curve equation is the caller's.
///
/// # Errors
///
/// [`Error`] from the layout.
pub fn assert_point_bytes<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    element: &LeElement<F>,
    x: &Word<F>,
    y: &Word<F>,
) -> Result<(), Error> {
    let decoded = decode_point(uint, region, element, y)?;
    GlueChip::assert_equal(region, &decoded, x)
}

/// Hard point decode: `x` from the message, constrained canonical, and the
/// parity of `y` constrained to the sign bit. Returns `x`.
///
/// # Errors
///
/// [`Error`] from the layout.
pub fn decode_point<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    element: &LeElement<F>,
    y: &Word<F>,
) -> Result<Word<F>, Error> {
    let x = element_value(uint.glue(), region, element)?;
    assert_le_max(
        uint,
        region,
        element.lo.word(),
        &UintChip::widen::<127, 128>(&element.hi),
        modulus_max::<F>(),
    )?;
    let sign = parity(uint, region, y)?;
    GlueChip::assert_equal(region, sign.word(), element.top.word())?;
    Ok(x)
}

/// The coefficient `b = 5` of both Pasta curves `y^2 = x^3 + b`; `5` is not
/// a square in either base field.
const PASTA_B: u64 = 5;

/// A point decoded softly from its message ([`decode_point_soft`]).
#[derive(Clone, Debug)]
pub struct SoftPoint<F: PastaField> {
    /// `x` of the decoded point: `lo + 2^128 hi` reduced into the field (`0`
    /// for the identity). A curve coordinate only when [`Self::valid`] is
    /// set.
    pub x: Word<F>,
    /// `y` of the decoded point: the square root of `x^3 + 5` whose
    /// canonical parity is the sign bit, or `0` for the identity. A curve
    /// coordinate only when [`Self::valid`] is set.
    pub y: Word<F>,
    /// `[the native decoder accepts the message]`
    /// (`GroupEncoding::from_bytes` of the Pasta affine types): `x`
    /// canonical, and either `x^3 + 5` a square or the message the identity
    /// encoding (all zeros). A function of the message alone.
    pub valid: Bit<F>,
    /// `[the message is the identity encoding]` (all zeros; the signed zero
    /// with bit 255 set is invalid).
    pub identity: Bit<F>,
}

/// The soft decode witness of `x`: `[x^3 + 5 is a square]` and a square
/// root of `x^3 + 5` when it is one, of `5 (x^3 + 5)` otherwise (both roots
/// are computed, so the selection does not branch).
pub(crate) fn soft_root_witness<F: PastaField>(x: &F) -> (bool, F) {
    let b = F::from(PASTA_B);
    let t = x.square() * x + b;
    let root = t.sqrt();
    let other = (t * b).sqrt().unwrap_or(F::ZERO);
    (bool::from(root.is_some()), root.unwrap_or(other))
}

/// Soft point decode: the point the native decoder
/// (`GroupEncoding::from_bytes`) returns for the message and the bit
/// `[it accepts]`, both functions of the message alone and satisfiable for
/// every message.
///
/// Decoding succeeds iff `x = lo + 2^128 hi` is canonical and either
/// `t = x^3 + 5` is a square (the point `(x, y)` with `y` the root of the
/// sign bit's parity) or the message is the identity encoding (`x = 0`, sign
/// bit clear). A bit `q` and a witness `w` with `w^2 = t (5 - 4 q)` decide
/// the square: `t` is never 0 (a root would be a point `(x, 0)` of order 2,
/// and both curves have odd prime order) and `5` is not a square, so exactly
/// one of `t`, `5 t` is a square and `q` is unique. A prover can therefore
/// neither accept an `x` off the curve nor reject one on it; `y = +-w` by
/// the parity of the sign bit is the same whichever root it supplied. The
/// identity encoding forces `q = 0` (`t = 5`), so `valid = canonical q +
/// identity` is a bit.
///
/// # Errors
///
/// [`Error`] from the layout.
pub fn decode_point_soft<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    element: &LeElement<F>,
) -> Result<SoftPoint<F>, Error> {
    let x = element_value(uint.glue(), region, element)?;
    let witness = x.value().map(|x| soft_root_witness(&x));
    decode_point_soft_witnessed(uint, region, element, &x, witness)
}

/// [`decode_point_soft`] from `x` (the message's reduced `lo + 2^128 hi`)
/// with the prover's square bit and root (the honest values come from
/// [`soft_root_witness`]; adversarial tests pass others, which must be
/// unsatisfiable unless they give the same outputs).
pub(crate) fn decode_point_soft_witnessed<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    element: &LeElement<F>,
    x: &Word<F>,
    witness: Value<(bool, F)>,
) -> Result<SoftPoint<F>, Error> {
    let root = soft_root(uint, region, element, x, witness)?;
    let glue = uint.glue();
    // The identity encoding: canonical x = 0 with the sign bit clear.
    let x_zero = glue.is_zero(region, x)?;
    let clear = glue.not(region, &element.top)?;
    let zero_clear = glue.and(region, &x_zero, &clear)?;
    let identity = glue.and(region, &root.canonical, &zero_clear)?;
    let valid = glue.mul_add(
        region,
        root.canonical.word(),
        root.is_square.word(),
        identity.word(),
    )?;
    let finite = glue.not(region, &identity)?;
    let y = glue.mul(region, &root.y, finite.word())?;
    Ok(SoftPoint {
        x: x.clone(),
        y,
        valid: Bit::new(valid),
        identity,
    })
}

/// The shared core of the soft decoders: `[x canonical]`, the square bit
/// `q` with its root constraint `w^2 = t (5 - 4 q)` (`t = x^3 + 5`), and
/// `y = +-w` with the sign bit's parity.
struct SoftRoot<F: PastaField> {
    canonical: Bit<F>,
    is_square: Bit<F>,
    y: Word<F>,
}

fn soft_root<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    element: &LeElement<F>,
    x: &Word<F>,
    witness: Value<(bool, F)>,
) -> Result<SoftRoot<F>, Error> {
    let canonical = le_max(
        uint,
        region,
        &element.lo,
        &UintChip::widen::<127, 128>(&element.hi),
        modulus_max::<F>(),
    )?;
    let b = F::from(PASTA_B);
    let glue = uint.glue();
    // w^2 = t (5 - 4 q) with t = x^3 + 5.
    let square = glue.mul(region, x, x)?;
    let cube = glue.mul(region, &square, x)?;
    let t = glue.add_constant(region, &cube, b)?;
    let is_square = glue.boolean(region, witness.map(|(q, _)| q))?;
    let root = glue.witness(region, witness.map(|(_, w)| w))?;
    let factor = glue.linear(region, &[(-F::from(4_u64), is_square.word())], b)?;
    let target = glue.mul(region, &t, &factor)?;
    let root_squared = glue.mul(region, &root, &root)?;
    GlueChip::assert_equal(region, &root_squared, &target)?;
    // The root (never 0) of the sign bit's parity.
    let sign = parity(uint, region, &root)?;
    let glue = uint.glue();
    let same_sign = glue.is_equal(region, sign.word(), element.top.word())?;
    let negated = glue.linear(region, &[(-F::ONE, &root)], F::ZERO)?;
    let y = glue.select(region, &same_sign, &root, &negated)?;
    Ok(SoftRoot {
        canonical,
        is_square,
        y,
    })
}

/// The dummy point `(-1, 2)` that [`decode_pipa_point_soft`] returns for a
/// rejected message: a finite point of both Pasta curves (`(-1)^3 + 5 =
/// 2^2`; their generator), so unconditional curve arithmetic on it stays
/// total.
pub const PIPA_DUMMY: (i64, i64) = (-1, 2);

/// A PIPA-v1 proof point decoded softly ([`decode_pipa_point_soft`]).
#[derive(Clone, Debug)]
pub struct SoftPipaPoint<F: PastaField> {
    /// `x` of the decoded point when [`Self::valid`] is set, otherwise `-1`
    /// ([`PIPA_DUMMY`]).
    pub x: Word<F>,
    /// `y` of the decoded point when [`Self::valid`] is set, otherwise `2`.
    pub y: Word<F>,
    /// `[the PIPA-v1 point decoder accepts the message]`
    /// (`iroha_plonk::transcript::decode_point`, which proof and
    /// accumulator points go through): `x` canonical and `x^3 + 5` a square,
    /// so never the identity. A function of the message alone.
    pub valid: Bit<F>,
}

/// Soft decode of a PIPA-v1 proof point: the native PIPA decoder
/// (`iroha_plonk::transcript::decode_point`) rejects the identity encoding
/// that the generic decoder ([`decode_point_soft`], `GroupEncoding`
/// semantics) accepts, so its verdict is `valid (1 - identity)`. With the
/// identity encoding the root equation forces `q = 0` (`x = 0`, `t = 5`,
/// and `5` is not a square), so that verdict is `canonical q`: one product
/// instead of the identity test. A rejected message yields the curve point
/// [`PIPA_DUMMY`] instead of the root of a non-point, so a soft verifier
/// can feed the output to complete arithmetic unconditionally and gate only
/// the verdict. Satisfiable for every message; the point and the bit are
/// functions of the message alone (a prover can neither reject valid bytes
/// with a wrong root nor accept invalid ones, as in [`decode_point_soft`]).
///
/// # Errors
///
/// [`Error`] from the layout.
pub fn decode_pipa_point_soft<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    element: &LeElement<F>,
) -> Result<SoftPipaPoint<F>, Error> {
    let x = element_value(uint.glue(), region, element)?;
    let witness = x.value().map(|x| soft_root_witness(&x));
    decode_pipa_point_soft_witnessed(uint, region, element, &x, witness)
}

/// [`decode_pipa_point_soft`] with the prover's square bit and root (the
/// adversarial tests pass others).
pub(crate) fn decode_pipa_point_soft_witnessed<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    element: &LeElement<F>,
    x: &Word<F>,
    witness: Value<(bool, F)>,
) -> Result<SoftPipaPoint<F>, Error> {
    let root = soft_root(uint, region, element, x, witness)?;
    let glue = uint.glue();
    let valid = glue.and(region, &root.canonical, &root.is_square)?;
    let (dummy_x, dummy_y) = PIPA_DUMMY;
    let dummy = |value: i64| {
        let magnitude = F::from(value.unsigned_abs());
        if value < 0 { -magnitude } else { magnitude }
    };
    let x = glue.select_constant(region, &valid, x, dummy(dummy_x))?;
    let y = glue.select_constant(region, &valid, &root.y, dummy(dummy_y))?;
    Ok(SoftPipaPoint { x, y, valid })
}

/// Soft point link: `[the message encodes (x, y)]` for two cells of the
/// circuit field (never unsatisfiable): `x` canonical and equal to the
/// message's `x`, and the canonical parity of `y` equal to the sign bit. The
/// bit is a function of the message and the two cells; a caller without
/// trusted coordinates decodes them with [`decode_point_soft`] instead.
///
/// # Errors
///
/// [`Error`] from the layout.
pub fn point_bytes_match<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    element: &LeElement<F>,
    x: &Word<F>,
    y: &Word<F>,
) -> Result<Bit<F>, Error> {
    let decoded = element_value(uint.glue(), region, element)?;
    let canonical = le_max(
        uint,
        region,
        &element.lo,
        &UintChip::widen::<127, 128>(&element.hi),
        modulus_max::<F>(),
    )?;
    let sign = parity(uint, region, y)?;
    let glue = uint.glue();
    let same_sign = glue.is_equal(region, sign.word(), element.top.word())?;
    let same_x = glue.is_equal(region, &decoded, x)?;
    let encoded = glue.and(region, &canonical, &same_sign)?;
    glue.and(region, &encoded, &same_x)
}

/// The low bit of `value < 2^128` (an integer the caller bounded):
/// `value = b + 2 r` with `b` boolean and `r < 2^127`.
///
/// # Errors
///
/// [`Error`] from the layout.
pub fn low_bit<F: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    value: &Word<F>,
) -> Result<Bit<F>, Error> {
    let witness = value.value().map(|value| {
        let low = crate::cells::low_u128(&value);
        (low & 1 == 1, low >> 1)
    });
    let bit = uint.glue().boolean(region, witness.map(|(bit, _)| bit))?;
    let half = uint.assign::<127>(region, witness.map(|(_, half)| half))?;
    let recomposed = uint.glue().linear(
        region,
        &[(F::ONE, bit.word()), (F::from(2_u64), half.word())],
        F::ZERO,
    )?;
    GlueChip::assert_equal(region, &recomposed, value)?;
    Ok(bit)
}

/// Hard link of a point over a foreign base field `G` (a Vesta point in an
/// `Fp` circuit, a Pallas point in an `Fq` circuit): `x` is the message's
/// `lo + 2^128 hi`, canonical in `G` (its limbs are the element's `lo` and
/// `hi`), and `y`, given by its limbs `y_lo + 2^128 y_hi` (each below
/// `2^128`), is canonical in `G` with its low bit equal to the sign bit.
///
/// # Errors
///
/// [`Error`] from the layout.
pub fn assert_foreign_point_bytes<F: PastaField, G: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    element: &LeElement<F>,
    y_lo: &U128<F>,
    y_hi: &U128<F>,
) -> Result<(), Error> {
    assert_le_max(
        uint,
        region,
        element.lo.word(),
        &UintChip::widen::<127, 128>(&element.hi),
        modulus_max::<G>(),
    )?;
    assert_le_max(uint, region, y_lo.word(), y_hi, modulus_max::<G>())?;
    let sign = low_bit(uint, region, y_lo.word())?;
    GlueChip::assert_equal(region, sign.word(), element.top.word())
}

/// Soft form of [`assert_foreign_point_bytes`]: the bit `[x canonical in G]
/// AND [y canonical in G] AND [low bit of y = sign bit]` (never
/// unsatisfiable; a function of the message and the `y` limbs).
///
/// # Errors
///
/// [`Error`] from the layout.
pub fn foreign_point_bytes_match<F: PastaField, G: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    element: &LeElement<F>,
    y_lo: &U128<F>,
    y_hi: &U128<F>,
) -> Result<Bit<F>, Error> {
    let x_canonical = le_max(
        uint,
        region,
        &element.lo,
        &UintChip::widen::<127, 128>(&element.hi),
        modulus_max::<G>(),
    )?;
    let y_canonical = le_max(uint, region, y_lo, y_hi, modulus_max::<G>())?;
    let sign = low_bit(uint, region, y_lo.word())?;
    let glue = uint.glue();
    let same_sign = glue.is_equal(region, sign.word(), element.top.word())?;
    let canonical = glue.and(region, &x_canonical, &y_canonical)?;
    glue.and(region, &canonical, &same_sign)
}

/// Hard scalar link: the message is a canonical scalar of `G` (top bit
/// clear, `lo + 2^128 hi < |G|`); its limbs are the element's `lo` and `hi`.
///
/// # Errors
///
/// [`Error`] from the layout.
pub fn assert_scalar_bytes<F: PastaField, G: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    element: &LeElement<F>,
) -> Result<(), Error> {
    uint.glue()
        .enforce_constant(region, element.top.word(), F::ZERO)?;
    assert_le_max(
        uint,
        region,
        element.lo.word(),
        &UintChip::widen::<127, 128>(&element.hi),
        modulus_max::<G>(),
    )
}

/// Soft scalar link: `[the message is a canonical scalar of G]`.
///
/// # Errors
///
/// [`Error`] from the layout.
pub fn scalar_bytes_canonical<F: PastaField, G: PastaField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    element: &LeElement<F>,
) -> Result<Bit<F>, Error> {
    let below = le_max(
        uint,
        region,
        &element.lo,
        &UintChip::widen::<127, 128>(&element.hi),
        modulus_max::<G>(),
    )?;
    let glue = uint.glue();
    let clear = glue.not(region, &element.top)?;
    glue.and(region, &below, &clear)
}

#[cfg(test)]
mod unit_tests {
    use iroha_pasta::{Fp, Fq};

    use super::*;

    #[test]
    fn message_segment_plans() {
        let little = le_message_segments(4, 2);
        assert_eq!(little.len(), 6);
        assert_eq!(little[0], SegmentSpec::little(4, 16));
        assert_eq!(little[1], SegmentSpec::little(20, 15));
        assert_eq!(little[2], SegmentSpec::little(35, 1));
        assert_eq!(little[3], SegmentSpec::little(36, 16));
        let big = be_value_segments(1, 1);
        assert_eq!(big, vec![SegmentSpec::big(1, 16), SegmentSpec::big(17, 16)]);
        assert!(le_message_segments(0, 0).is_empty());
    }

    #[test]
    fn modulus_limbs() {
        // Both Pasta moduli are 2^254 + small: M_hi = 2^126.
        assert_eq!(modulus_max::<Fp>()[1], 1 << 126);
        assert_eq!(modulus_max::<Fq>()[1], 1 << 126);
        assert!(modulus_max::<Fp>()[0] < modulus_max::<Fq>()[0]);
        assert_eq!(two_power::<Fp>(8), Fp::from(256_u64));
    }
}
