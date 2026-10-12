//! The `QuickSilver` polynomial constraint check of FAEST v3.0 (sections 7 and 8) for
//! an arbitrary relation of degree at most `d_zk = 7`.
//!
//! # Writing a relation
//!
//! A relation is written **once**, as an implementation of [`Relation`] whose
//! [`Relation::emit`] is generic over a [`ConstraintSystem`]. It reads witness
//! coordinates with [`ConstraintSystem::witness`], combines values with
//! [`ConstraintSystem::add`], [`ConstraintSystem::mul`] and
//! [`ConstraintSystem::scale`], brings public inputs in as
//! [`ConstraintSystem::constant`]s or scalars, and hands each constraint, a value
//! that must be zero, to [`ConstraintSystem::constrain`] in a fixed order. The
//! same code is then driven by three evaluators:
//!
//! * the **plain** evaluator ([`is_satisfied`], [`violated_constraints`]) computes
//!   every constraint on the witness bits and reports which are not zero;
//! * the **prover** ([`prove`]) computes every constraint as a polynomial over
//!   `GF(2^lambda)` on the formal commitments `rho_i(X) = V_i + w_i * X`;
//! * the **verifier** ([`verify`]) computes the value of the same polynomial at
//!   `Delta` from the keys `Q_i + d_i * Delta`.
//!
//! # Degrees and homogenisation
//!
//! Every value carries a public degree: a witness coordinate has degree 1, a
//! constant degree 0, a sum the larger of its operands' degrees, a product their
//! sum, and a scaled value its own. A value of degree `e` for the polynomial `f`
//! stands for `X^e * f(rho(X) / X)`: when two values of different degrees are
//! added, the one of lower degree is first multiplied by the missing power of
//! `X` (the prover shifts coefficients, the verifier multiplies by a power of
//! `Delta`). A constraint of degree `e <= d_zk` is lifted to nominal degree
//! `d_zk` as `X^(d_zk - e)` times its value, which is
//! `X^(d_zk - e) * Hom_e(f)(rho(X), X) = X^d_zk * f(rho(X) / X)`. This does not
//! depend on how the relation groups its operations, only on `f`: the coefficient
//! of `X^d_zk` is `f(w)` and must be zero.
//!
//! A product whose degree would exceed `d_zk`, and a witness index at or above the
//! witness length, do not panic: the value is marked, and the evaluation fails
//! with [`QuickSilverError::DegreeOverflow`] or
//! [`QuickSilverError::WitnessIndex`] when the mark reaches a constraint. A
//! relation that emits a different number of constraints than
//! [`Relation::constraints`] fails with [`QuickSilverError::ConstraintCount`].
//!
//! # The check
//!
//! The engine itself prepends one Booleanity constraint `w_i * (w_i + 1)` per
//! witness coordinate, in witness order; the relation's constraints follow. With
//! `C = ell + Relation::constraints()` constraints in all:
//!
//! * the prover hashes coefficient `j` of every lifted constraint, in constraint
//!   order, with `ZKHash` keyed by `chall_2` and masked by
//!   `p_0 = vbar_0`, `p_j = ubar_{j-1} + vbar_j` (`0 < j < d_zk - 1`),
//!   `p_{d_zk-1} = ubar_{d_zk-2}`, giving `a~_0 .. a~_{d_zk-1}`; `a~_0` enters
//!   `chall_3` and `a~_1 .. a~_{d_zk-1}` are sent;
//! * the verifier hashes its values with the mask
//!   `q* = sum_{j < d_zk-1} qbar_j * Delta^j` and returns
//!   `a~_0 = ZKHash(..) + sum_{j >= 1} a~_j * Delta^j`. Nothing is compared here:
//!   the result enters `chall_3`, which the caller compares.
//!
//! # Resources
//!
//! Constraints are streamed into `ZKHash` as they are emitted and never stored:
//! the prover keeps `d_zk` hash states (five field elements and one word each), the
//! verifier one state and the powers of `Delta`. There is no heap allocation per
//! constraint and none that grows with the witness or the constraint count;
//! polynomials are fixed arrays of `d_zk + 1` coefficients. The engine reads the
//! witness, `V` and `Q` in place from the buffers of [`crate::vole`]. For a
//! relation of 36,000 witness bits at `lambda = 256` the engine's own state is
//! below 2 kB next to the 4,500-byte witness and the 1,152,000 bytes of `V` or
//! `Q` it borrows; values a relation keeps while it runs (a prover value is
//! `8 * 32 + 1` bytes at `lambda = 256`) are the relation's.
//!
//! # Secrets
//!
//! The prover's and the plain evaluator's values depend on the witness. They are
//! combined with field additions and multiplications only, over loops whose
//! bounds are the public degrees; no value selects a branch, an index or an early
//! exit, and structurally zero coefficients are multiplied like any other. The
//! hash states are erased on drop. Values are `Copy` and live on the stack of the
//! relation code: the engine cannot erase copies a relation leaves behind.
//! [`violated_constraints`] branches on which constraints fail and is for tests
//! and diagnostics; [`is_satisfied`] folds the outcomes into one flag.

mod plain;
mod prover;
mod verifier;

use thiserror::Error;

pub use self::{plain::PlainValue, prover::Polynomial, verifier::Key};
use crate::{
    field::{FieldError, LambdaField},
    params::D_ZK,
    universal_hash::UniversalHashError,
};

/// The degree `d_zk` of the check: every constraint is lifted to it.
pub const DEGREE: usize = D_ZK;

/// Number of mask values and tags `VOLECommit` produces: `n_mask = d_zk + 3`. The
/// check uses the first `d_zk - 1`.
pub const MASKS: usize = DEGREE + 3;

/// The operations a relation is written against.
///
/// See the module documentation for the meaning of degrees. All methods are free
/// of panics; misuse is reported when the evaluation finishes.
pub trait ConstraintSystem {
    /// The field `GF(2^lambda)` public scalars and constants live in.
    type Field: LambdaField;
    /// A value: a witness coordinate, a constant, or a combination of them.
    type Value: Copy;

    /// Witness coordinate `index`, of degree 1.
    fn witness(&self, index: usize) -> Self::Value;

    /// The public constant `value`, of degree 0.
    fn constant(&self, value: Self::Field) -> Self::Value;

    /// `a + b`, of the larger of the two degrees.
    fn add(&self, a: Self::Value, b: Self::Value) -> Self::Value;

    /// `a * b`, of the sum of the two degrees.
    fn mul(&self, a: Self::Value, b: Self::Value) -> Self::Value;

    /// `a * scalar` for a public `scalar`, of the degree of `a`.
    fn scale(&self, a: Self::Value, scalar: Self::Field) -> Self::Value;

    /// Emit the next constraint: `value` must be zero.
    fn constrain(&mut self, value: Self::Value);

    /// The constant 0.
    fn zero(&self) -> Self::Value {
        self.constant(<Self::Field as crate::field::BinaryField>::ZERO)
    }

    /// The constant 1.
    fn one(&self) -> Self::Value {
        self.constant(<Self::Field as crate::field::BinaryField>::ONE)
    }

    /// The public bit `bit` as a constant.
    fn bit(&self, bit: bool) -> Self::Value {
        self.constant(<Self::Field as crate::field::BinaryField>::from_bit(
            u8::from(bit),
        ))
    }

    /// `a + bit` for a public bit.
    fn add_bit(&self, a: Self::Value, bit: bool) -> Self::Value {
        self.add(a, self.bit(bit))
    }
}

/// A relation over witness bits, written once for all evaluators.
///
/// `F` is the field of the row the relation is used on. A relation that is
/// meaningful at one security level implements the trait for that field only.
pub trait Relation<F: LambdaField> {
    /// The public input the constraints read.
    type PublicInput: ?Sized;

    /// Witness length `ell` in bits.
    fn witness_bits(&self) -> usize;

    /// Number of constraints [`Self::emit`] emits. The engine's `ell` Booleanity
    /// constraints are not counted.
    fn constraints(&self) -> usize;

    /// Emit the constraints, in their fixed order, into `system`.
    ///
    /// The sequence of operations must be the same for every evaluator and may
    /// depend on the public input only: values are opaque.
    fn emit<C: ConstraintSystem<Field = F>>(&self, public: &Self::PublicInput, system: &mut C);
}

/// Which buffer had the wrong length in a [`QuickSilverError::InvalidLength`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Input {
    /// The witness, `ell / 8` bytes.
    Witness,
    /// The tags `V`, `ell` field elements.
    Tags,
    /// The mask values `ubar`, [`MASKS`] field elements.
    MaskValues,
    /// The mask tags `vbar`, [`MASKS`] field elements.
    MaskTags,
    /// The masked witness `d`, `ell / 8` bytes.
    MaskedWitness,
    /// The keys `Q`, `ell` field elements.
    Keys,
    /// The mask keys `qbar`, [`MASKS`] field elements.
    MaskKeys,
    /// `Delta`, one field element.
    Delta,
    /// The coefficients `a~_1 .. a~_{d_zk-1}`.
    Coefficients,
}

/// Errors of the constraint check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum QuickSilverError {
    /// A buffer does not have the length the relation and the field fix for it.
    #[error("{input:?} must be {expected} bytes long, got {actual}")]
    InvalidLength {
        /// The buffer concerned.
        input: Input,
        /// Required length in bytes.
        expected: usize,
        /// Length supplied.
        actual: usize,
    },
    /// The relation's witness length is not a positive multiple of 8.
    #[error("a witness of {witness_bits} bits is not a whole, positive number of bytes")]
    WitnessBits {
        /// [`Relation::witness_bits`].
        witness_bits: usize,
    },
    /// A constraint used a witness coordinate at or above the witness length.
    #[error("constraint {constraint} reads a witness coordinate that does not exist")]
    WitnessIndex {
        /// Index of the constraint in the stream, Booleanity constraints included.
        constraint: usize,
    },
    /// A constraint has degree above [`DEGREE`].
    #[error("constraint {constraint} has degree above {DEGREE}")]
    DegreeOverflow {
        /// Index of the constraint in the stream, Booleanity constraints included.
        constraint: usize,
    },
    /// The relation did not emit the number of constraints it declares.
    #[error("the relation declares {expected} constraints and emitted {actual}")]
    ConstraintCount {
        /// [`Relation::constraints`].
        expected: usize,
        /// Constraints emitted; when there are too many, the first excess count.
        actual: usize,
    },
    /// The universal hash rejected `chall_2`.
    #[error(transparent)]
    Hash(#[from] UniversalHashError),
    /// A field element could not be decoded.
    #[error(transparent)]
    Field(#[from] FieldError),
}

fn check_length(input: Input, expected: usize, actual: usize) -> Result<(), QuickSilverError> {
    if expected == actual {
        Ok(())
    } else {
        Err(QuickSilverError::InvalidLength {
            input,
            expected,
            actual,
        })
    }
}

/// The public degree of a value, or the reason it cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Degree {
    /// A degree in `[0, DEGREE]`.
    Of(u8),
    /// Derived from a witness coordinate that does not exist.
    BadIndex,
    /// A product went above [`DEGREE`].
    Overflow,
}

impl Degree {
    const ZERO: Self = Self::Of(0);
    const ONE: Self = Self::Of(1);
    const TWO: Self = Self::Of(2);

    /// Degree of a sum, with the two degrees when both are valid.
    fn sum(self, other: Self) -> (Self, Option<(usize, usize)>) {
        match (self, other) {
            (Self::Of(a), Self::Of(b)) => {
                (Self::Of(a.max(b)), Some((usize::from(a), usize::from(b))))
            }
            (Self::BadIndex, _) | (_, Self::BadIndex) => (Self::BadIndex, None),
            _ => (Self::Overflow, None),
        }
    }

    /// Degree of a product, with the two degrees when the product is valid.
    fn product(self, other: Self) -> (Self, Option<(usize, usize)>) {
        match (self, other) {
            (Self::Of(a), Self::Of(b)) if usize::from(a) + usize::from(b) <= DEGREE => {
                (Self::Of(a + b), Some((usize::from(a), usize::from(b))))
            }
            (Self::BadIndex, _) | (_, Self::BadIndex) => (Self::BadIndex, None),
            _ => (Self::Overflow, None),
        }
    }

    /// The degree, when valid.
    fn get(self) -> Option<usize> {
        match self {
            Self::Of(degree) => Some(usize::from(degree)),
            Self::BadIndex | Self::Overflow => None,
        }
    }
}

/// Bookkeeping of the constraint stream shared by the three evaluators.
#[derive(Debug)]
struct Stream {
    /// Constraints accepted so far.
    emitted: usize,
    /// Constraints the stream must have in all.
    expected: usize,
    /// The first error.
    error: Option<QuickSilverError>,
}

impl Stream {
    fn new(expected: usize) -> Self {
        Self {
            emitted: 0,
            expected,
            error: None,
        }
    }

    /// Accept the next constraint of degree `degree` and return the power of `X`
    /// that lifts it to [`DEGREE`]. `None` means the constraint must be dropped: an
    /// error is, or was already, recorded.
    fn admit(&mut self, degree: Degree) -> Option<usize> {
        if self.error.is_some() {
            return None;
        }
        let constraint = self.emitted;
        if constraint >= self.expected {
            self.error = Some(QuickSilverError::ConstraintCount {
                expected: self.expected,
                actual: constraint + 1,
            });
            return None;
        }
        match degree {
            Degree::Of(degree) => {
                self.emitted += 1;
                Some(DEGREE - usize::from(degree))
            }
            Degree::BadIndex => {
                self.error = Some(QuickSilverError::WitnessIndex { constraint });
                None
            }
            Degree::Overflow => {
                self.error = Some(QuickSilverError::DegreeOverflow { constraint });
                None
            }
        }
    }

    /// The first error, or a count error if the stream is short.
    fn finish(&self) -> Result<(), QuickSilverError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if self.emitted != self.expected {
            return Err(QuickSilverError::ConstraintCount {
                expected: self.expected,
                actual: self.emitted,
            });
        }
        Ok(())
    }
}

/// Sizes of one relation: `(ell, ell / 8, C)` with `C` counting the Booleanity
/// constraints.
fn sizes<F: LambdaField, R: Relation<F> + ?Sized>(
    relation: &R,
) -> Result<(usize, usize, usize), QuickSilverError> {
    let witness_bits = relation.witness_bits();
    if witness_bits == 0 || !witness_bits.is_multiple_of(8) {
        return Err(QuickSilverError::WitnessBits { witness_bits });
    }
    let total = witness_bits.saturating_add(relation.constraints());
    Ok((witness_bits, witness_bits / 8, total))
}

/// Total number `C` of constraints hashed for `relation`: its own plus one
/// Booleanity constraint per witness bit.
///
/// # Errors
/// Returns [`QuickSilverError::WitnessBits`] unless the witness length is a
/// positive multiple of 8.
pub fn total_constraints<F: LambdaField, R: Relation<F> + ?Sized>(
    relation: &R,
) -> Result<usize, QuickSilverError> {
    sizes(relation).map(|(_, _, total)| total)
}

/// Whether `witness` (`ell / 8` bytes, bit `i` at bit `i mod 8` of byte `i / 8`)
/// satisfies every constraint of `relation` for `public`.
///
/// The outcomes of the constraints are folded into one flag; only the final
/// answer depends on the witness.
///
/// # Errors
/// Returns [`QuickSilverError::InvalidLength`] for a witness of the wrong length
/// and the stream errors of the module documentation for a malformed relation.
pub fn is_satisfied<F: LambdaField, R: Relation<F> + ?Sized>(
    relation: &R,
    public: &R::PublicInput,
    witness: &[u8],
) -> Result<bool, QuickSilverError> {
    let (_, witness_bytes, total) = sizes(relation)?;
    check_length(Input::Witness, witness_bytes, witness.len())?;
    let mut system = plain::Plain::<F>::new(witness, total, false);
    system.booleanity();
    relation.emit(public, &mut system);
    system.finish().map(|(satisfied, _)| satisfied)
}

/// The indices of the constraints `witness` violates, in increasing order. Index
/// `i < ell` is the Booleanity constraint of witness bit `i` (never violated by a
/// witness given as bits); the relation's constraint `c` has index `ell + c`.
///
/// For tests and diagnostics: the control flow depends on the witness.
///
/// # Errors
/// As [`is_satisfied`].
pub fn violated_constraints<F: LambdaField, R: Relation<F> + ?Sized>(
    relation: &R,
    public: &R::PublicInput,
    witness: &[u8],
) -> Result<Vec<usize>, QuickSilverError> {
    let (_, witness_bytes, total) = sizes(relation)?;
    check_length(Input::Witness, witness_bytes, witness.len())?;
    let mut system = plain::Plain::<F>::new(witness, total, true);
    system.booleanity();
    relation.emit(public, &mut system);
    system.finish().map(|(_, violated)| violated)
}

/// The prover's inputs: the witness and the outputs of `VOLECommit`, in the byte
/// layouts of [`crate::vole::Commitment`]. Everything in it is secret.
#[derive(Clone, Copy)]
pub struct ProverInputs<'a> {
    /// The witness `w`, `ell / 8` bytes.
    pub witness: &'a [u8],
    /// The tags `V[0] || ... || V[ell - 1]`.
    pub tags: &'a [u8],
    /// The mask values `ubar_0 || ... || ubar_{n_mask - 1}`.
    pub mask_values: &'a [u8],
    /// The mask tags `vbar_0 || ... || vbar_{n_mask - 1}`.
    pub mask_tags: &'a [u8],
}

impl core::fmt::Debug for ProverInputs<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProverInputs").finish_non_exhaustive()
    }
}

/// The prover's side of the check: `a~_0 .. a~_{d_zk-1}` for the constraint stream
/// of `relation` under the `ZKHash` key `challenge_2`.
///
/// The witness is **not** checked against the relation here: a violated
/// constraint has a non-zero coefficient of `X^d_zk`, which is not hashed, and the
/// resulting proof is rejected by the verifier. Callers check with
/// [`is_satisfied`] first.
///
/// # Errors
/// Returns [`QuickSilverError::InvalidLength`] naming the first buffer of the
/// wrong length, [`QuickSilverError::Hash`] for a `challenge_2` of the wrong
/// length, and the stream errors of the module documentation for a malformed
/// relation.
pub fn prove<F: LambdaField, R: Relation<F> + ?Sized>(
    relation: &R,
    public: &R::PublicInput,
    inputs: &ProverInputs<'_>,
    challenge_2: &[u8],
) -> Result<[F; DEGREE], QuickSilverError> {
    let (witness_bits, witness_bytes, total) = sizes(relation)?;
    check_length(Input::Witness, witness_bytes, inputs.witness.len())?;
    check_length(
        Input::Tags,
        witness_bits.saturating_mul(F::BYTES),
        inputs.tags.len(),
    )?;
    check_length(
        Input::MaskValues,
        MASKS * F::BYTES,
        inputs.mask_values.len(),
    )?;
    check_length(Input::MaskTags, MASKS * F::BYTES, inputs.mask_tags.len())?;
    let mut system = prover::Prover::<F>::new(inputs.witness, inputs.tags, total, challenge_2)?;
    system.booleanity();
    relation.emit(public, &mut system);
    system.finish(inputs.mask_values, inputs.mask_tags)
}

/// The verifier's inputs: the masked witness of the proof and the outputs of
/// `VOLEReconstruct`, in the byte layouts of [`crate::vole::Reconstruction`].
/// Everything in it is public.
#[derive(Debug, Clone, Copy)]
pub struct VerifierInputs<'a> {
    /// The masked witness `d = w + u`, `ell / 8` bytes.
    pub masked_witness: &'a [u8],
    /// The keys `Q[0] || ... || Q[ell - 1]`.
    pub keys: &'a [u8],
    /// The mask keys `qbar_0 || ... || qbar_{n_mask - 1}`.
    pub mask_keys: &'a [u8],
    /// `Delta`, one field element.
    pub delta: &'a [u8],
}

/// The verifier's side of the check: the `a~_0` that an honest prover with these
/// commitments would have hashed, from the transmitted `coefficients`
/// `a~_1 || ... || a~_{d_zk-1}`.
///
/// This is a verifier entry point: every input is untrusted and public. Nothing
/// is compared; the caller puts the result into `chall_3`.
///
/// # Errors
/// As [`prove`].
pub fn verify<F: LambdaField, R: Relation<F> + ?Sized>(
    relation: &R,
    public: &R::PublicInput,
    inputs: &VerifierInputs<'_>,
    challenge_2: &[u8],
    coefficients: &[u8],
) -> Result<F, QuickSilverError> {
    let (witness_bits, witness_bytes, total) = sizes(relation)?;
    check_length(
        Input::MaskedWitness,
        witness_bytes,
        inputs.masked_witness.len(),
    )?;
    check_length(
        Input::Keys,
        witness_bits.saturating_mul(F::BYTES),
        inputs.keys.len(),
    )?;
    check_length(Input::MaskKeys, MASKS * F::BYTES, inputs.mask_keys.len())?;
    check_length(Input::Delta, F::BYTES, inputs.delta.len())?;
    check_length(
        Input::Coefficients,
        (DEGREE - 1) * F::BYTES,
        coefficients.len(),
    )?;
    let delta = F::from_bytes(inputs.delta)?;
    let mut system = verifier::Verifier::<F>::new(
        inputs.masked_witness,
        inputs.keys,
        delta,
        total,
        challenge_2,
    )?;
    system.booleanity();
    relation.emit(public, &mut system);
    system.finish(inputs.mask_keys, coefficients)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::field::{BinaryField, Gf128, Gf192, Gf256};

    /// A deterministic field element.
    pub(crate) fn element<F: LambdaField>(seed: u64) -> F {
        let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let mut acc = F::ZERO;
        for _ in 0..F::BYTES / 8 + 1 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            acc = acc * F::from_u64(0x1_0000_0001).mul_x() + F::from_u64(state);
        }
        acc * acc + F::from_u64(seed)
    }

    fn element_bytes<F: LambdaField>(seeds: impl Iterator<Item = u64>) -> Vec<u8> {
        seeds
            .flat_map(|seed| element::<F>(seed).to_bytes().as_ref().to_vec())
            .collect()
    }

    /// A relation with one constraint of each kind the engine must handle.
    ///
    /// Public input: a list of bits. Witness: 64 bits.
    /// * degree 1 with a public term: `w0 + w1 + w2 + p0`;
    /// * degree 1 with public scalars: `sum_i s_i * w_i + c` over `w8..w16`, where
    ///   `s_i` are fixed field elements and `c` is derived from the public bits;
    /// * degree 2: `w3 * w4 + w5 + p1`;
    /// * degree 4: `w16 * w17 * w18 * w19 + w20 * w21 + w22 + p2`;
    /// * degree 7: `w24 * .. * w30 + w31`;
    /// * identically zero, twice: `w6 * 0` and the constant 0;
    /// * degree 3 through a product with a degree-0 constant:
    ///   `(w32 * w33) * (w34 + 1) * 1 + w35`.
    pub(crate) struct Mixed;

    pub(crate) const MIXED_SCALARS: [u64; 8] = [3, 5, 7, 11, 13, 17, 19, 23];

    impl Mixed {
        /// The public constant of the scalar constraint: the scalars of the
        /// coordinates whose public bit `3 + i` is set.
        pub(crate) fn target<F: LambdaField>(public: &[bool]) -> F {
            let mut acc = F::ZERO;
            for (i, seed) in MIXED_SCALARS.into_iter().enumerate() {
                acc += element::<F>(seed).mul_bit(u8::from(public[3 + i]));
            }
            acc
        }

        /// A witness satisfying the relation for `public`, varied by `salt`.
        pub(crate) fn witness(public: &[bool], salt: u64) -> Vec<u8> {
            let mut bits = [false; 64];
            for (i, bit) in bits.iter_mut().enumerate() {
                *bit = (salt.wrapping_mul(0x2545_f491_4f6c_dd1d) >> (i % 61)) & 1 == 1;
            }
            bits[2] = bits[0] ^ bits[1] ^ public[0];
            for i in 0..8 {
                bits[8 + i] = public[3 + i];
            }
            bits[5] = (bits[3] & bits[4]) ^ public[1];
            bits[22] =
                (bits[16] & bits[17] & bits[18] & bits[19]) ^ (bits[20] & bits[21]) ^ public[2];
            bits[31] = bits[24..31].iter().all(|&bit| bit);
            bits[35] = bits[32] & bits[33] & !bits[34];
            let mut bytes = vec![0u8; 8];
            for (i, bit) in bits.into_iter().enumerate() {
                bytes[i / 8] |= u8::from(bit) << (i % 8);
            }
            bytes
        }
    }

    impl<F: LambdaField> Relation<F> for Mixed {
        type PublicInput = [bool];

        fn witness_bits(&self) -> usize {
            64
        }

        fn constraints(&self) -> usize {
            8
        }

        fn emit<C: ConstraintSystem<Field = F>>(&self, public: &[bool], cs: &mut C) {
            let w = |i: usize| cs.witness(i);
            let linear = cs.add_bit(cs.add(cs.add(w(0), w(1)), w(2)), public[0]);
            let mut scaled = cs.constant(Self::target::<F>(public));
            for (i, seed) in MIXED_SCALARS.into_iter().enumerate() {
                scaled = cs.add(scaled, cs.scale(w(8 + i), element::<F>(seed)));
            }
            let quadratic = cs.add_bit(cs.add(cs.mul(w(3), w(4)), w(5)), public[1]);
            let quartic = cs.add_bit(
                cs.add(
                    cs.add(
                        cs.mul(cs.mul(w(16), w(17)), cs.mul(w(18), w(19))),
                        cs.mul(w(20), w(21)),
                    ),
                    w(22),
                ),
                public[2],
            );
            let mut septic = w(24);
            for i in 25..31 {
                septic = cs.mul(septic, w(i));
            }
            let septic = cs.add(septic, w(31));
            let vanishing = cs.mul(w(6), cs.zero());
            let nothing = cs.zero();
            let cubic = cs.add(
                cs.mul(
                    cs.mul(cs.mul(w(32), w(33)), cs.add(w(34), cs.one())),
                    cs.one(),
                ),
                w(35),
            );
            cs.constrain(linear);
            cs.constrain(scaled);
            cs.constrain(quadratic);
            cs.constrain(quartic);
            cs.constrain(septic);
            cs.constrain(vanishing);
            cs.constrain(nothing);
            cs.constrain(cubic);
        }
    }

    const PUBLIC: [bool; 11] = [
        true, false, true, true, false, false, true, true, false, true, false,
    ];

    #[test]
    fn the_plain_evaluator_reports_exactly_the_violated_constraints() {
        fn check<F: LambdaField>() {
            let witness = Mixed::witness(&PUBLIC, 5);
            assert_eq!(
                is_satisfied::<F, _>(&Mixed, &PUBLIC[..], &witness),
                Ok(true)
            );
            assert_eq!(
                violated_constraints::<F, _>(&Mixed, &PUBLIC[..], &witness),
                Ok(Vec::new())
            );
            assert_eq!(total_constraints::<F, _>(&Mixed), Ok(72));
            // Flip the output bit of each constraint that has one.
            for (bit, constraint) in [
                (2usize, 64usize),
                (9, 65),
                (5, 66),
                (22, 67),
                (31, 68),
                (35, 71),
            ] {
                let mut broken = witness.clone();
                broken[bit / 8] ^= 1 << (bit % 8);
                assert_eq!(
                    is_satisfied::<F, _>(&Mixed, &PUBLIC[..], &broken),
                    Ok(false)
                );
                assert_eq!(
                    violated_constraints::<F, _>(&Mixed, &PUBLIC[..], &broken),
                    Ok(vec![constraint])
                );
            }
            // Another public input: the public-input-dependent constraints fail.
            let mut other = PUBLIC;
            other[0] ^= true;
            other[4] ^= true;
            assert_eq!(
                violated_constraints::<F, _>(&Mixed, &other[..], &witness),
                Ok(vec![64, 65])
            );
            // Bits the relation does not read are free, as is the bit multiplied
            // by zero.
            for bit in [6usize, 7, 23, 40, 63] {
                let mut free = witness.clone();
                free[bit / 8] ^= 1 << (bit % 8);
                assert_eq!(is_satisfied::<F, _>(&Mixed, &PUBLIC[..], &free), Ok(true));
            }
            assert_eq!(
                is_satisfied::<F, _>(&Mixed, &PUBLIC[..], &witness[1..]),
                Err(QuickSilverError::InvalidLength {
                    input: Input::Witness,
                    expected: 8,
                    actual: 7
                })
            );
        }
        check::<Gf128>();
        check::<Gf192>();
        check::<Gf256>();
    }

    /// Everything a prover and a verifier need for `relation`, built from seeds:
    /// field-valued witness values (not necessarily bits), tags, `Delta`, keys and
    /// consistent masks.
    struct Instance<F> {
        values: Vec<F>,
        tags: Vec<u8>,
        keys: Vec<F>,
        delta: F,
        mask_values: Vec<u8>,
        mask_tags: Vec<u8>,
        mask_keys: Vec<u8>,
        challenge: Vec<u8>,
    }

    fn instance<F: LambdaField>(values: Vec<F>, seed: u64) -> Instance<F> {
        let ell = values.len();
        let delta = element::<F>(seed + 1);
        let tags: Vec<F> = (0u64..)
            .take(ell)
            .map(|i| element::<F>(seed + 100 + i))
            .collect();
        let keys = tags
            .iter()
            .zip(&values)
            .map(|(tag, value)| *tag + *value * delta)
            .collect();
        let mask_values: Vec<F> = (0u64..)
            .take(MASKS)
            .map(|m| element(seed + 10 + m))
            .collect();
        let mask_tags: Vec<F> = (0u64..)
            .take(MASKS)
            .map(|m| element(seed + 30 + m))
            .collect();
        let mask_keys: Vec<u8> = mask_tags
            .iter()
            .zip(&mask_values)
            .flat_map(|(tag, value)| (*tag + *value * delta).to_bytes().as_ref().to_vec())
            .collect();
        let flat = |elements: &[F]| -> Vec<u8> {
            elements
                .iter()
                .flat_map(|element| element.to_bytes().as_ref().to_vec())
                .collect()
        };
        Instance {
            tags: flat(&tags),
            keys,
            delta,
            mask_values: flat(&mask_values),
            mask_tags: flat(&mask_tags),
            mask_keys,
            challenge: element_bytes::<F>((seed + 60)..(seed + 64))[..3 * F::BYTES + 8].to_vec(),
            values,
        }
    }

    fn evaluate<F: LambdaField>(polynomial: &[F; DEGREE + 1], point: F) -> F {
        polynomial
            .iter()
            .rev()
            .fold(F::ZERO, |acc, coefficient| acc * point + *coefficient)
    }

    #[test]
    fn the_prover_polynomial_at_delta_is_the_verifier_value_for_any_field_values() {
        fn check<F: LambdaField>(seed: u64) {
            // Random field elements, not bits: the identity is polynomial.
            let values: Vec<F> = (0..64u64).map(|i| element::<F>(seed + 1000 + i)).collect();
            let fixture = instance(values, seed);
            let mut prover = prover::Prover::<F>::with_elements(
                &fixture.values,
                &fixture.tags,
                72,
                &fixture.challenge,
            )
            .expect("valid challenge");
            prover.record();
            prover.booleanity();
            Relation::<F>::emit(&Mixed, &PUBLIC[..], &mut prover);
            let polynomials = prover.recorded().to_vec();
            let coefficients = prover
                .finish(&fixture.mask_values, &fixture.mask_tags)
                .expect("well formed");

            let mut verifier = verifier::Verifier::<F>::with_keys(
                &fixture.keys,
                fixture.delta,
                72,
                &fixture.challenge,
            )
            .expect("valid challenge");
            verifier.record();
            verifier.booleanity();
            Relation::<F>::emit(&Mixed, &PUBLIC[..], &mut verifier);
            let values = verifier.recorded().to_vec();
            let tail: Vec<u8> = coefficients[1..]
                .iter()
                .flat_map(|coefficient| coefficient.to_bytes().as_ref().to_vec())
                .collect();
            let recomputed = verifier
                .finish(&fixture.mask_keys, &tail)
                .expect("well formed");

            assert_eq!(polynomials.len(), 72);
            assert_eq!(values.len(), 72);
            let mut plain = plain::Plain::<F>::with_elements(&fixture.values, 72);
            plain.booleanity();
            Relation::<F>::emit(&Mixed, &PUBLIC[..], &mut plain);
            let tops = plain.recorded().to_vec();
            let mut non_zero_tops = 0;
            for ((polynomial, value), top) in polynomials.iter().zip(&values).zip(&tops) {
                assert_eq!(evaluate(polynomial, fixture.delta), *value);
                // The coefficient of X^7 is the plain value of the constraint.
                assert_eq!(polynomial[DEGREE], *top);
                non_zero_tops += usize::from(!top.is_zero());
            }
            // Random values violate everything except the two zero constraints.
            assert_eq!(non_zero_tops, 70);
            // With non-zero top coefficients the hashed check does not close: the
            // verifier's value includes them.
            assert_ne!(recomputed, coefficients[0]);
        }
        check::<Gf128>(1);
        check::<Gf192>(2);
        check::<Gf256>(3);
    }

    fn run<F: LambdaField>(
        public: &[bool],
        witness: &[u8],
        seed: u64,
    ) -> ([F; DEGREE], Result<F, QuickSilverError>) {
        let values: Vec<F> = (0..64)
            .map(|i| F::from_bit(witness[i / 8] >> (i % 8)))
            .collect();
        let fixture = instance(values, seed);
        let coefficients = prove::<F, _>(
            &Mixed,
            public,
            &ProverInputs {
                witness,
                tags: &fixture.tags,
                mask_values: &fixture.mask_values,
                mask_tags: &fixture.mask_tags,
            },
            &fixture.challenge,
        )
        .expect("well formed");
        // d = w + u with u = 0, so Q = V.
        let keys = &fixture.tags;
        let tail: Vec<u8> = coefficients[1..]
            .iter()
            .flat_map(|coefficient| coefficient.to_bytes().as_ref().to_vec())
            .collect();
        let recomputed = verify::<F, _>(
            &Mixed,
            public,
            &VerifierInputs {
                masked_witness: witness,
                keys,
                mask_keys: &fixture.mask_keys,
                delta: fixture.delta.to_bytes().as_ref(),
            },
            &fixture.challenge,
            &tail,
        );
        (coefficients, recomputed)
    }

    #[test]
    fn the_verifier_recomputes_the_hashed_coefficient_exactly_for_valid_witnesses() {
        fn check<F: LambdaField>(seed: u64) {
            let witness = Mixed::witness(&PUBLIC, seed);
            let (coefficients, recomputed) = run::<F>(&PUBLIC, &witness, seed);
            assert_eq!(recomputed, Ok(coefficients[0]));
            // The prover's output depends on the witness and the masks.
            let (other, _) = run::<F>(&PUBLIC, &Mixed::witness(&PUBLIC, seed + 1), seed);
            assert_ne!(other, coefficients);

            // A violated constraint, another public input: no agreement.
            let mut broken = witness.clone();
            broken[0] ^= 4;
            let (coefficients, recomputed) = run::<F>(&PUBLIC, &broken, seed);
            assert_ne!(recomputed, Ok(coefficients[0]));
            let mut other = PUBLIC;
            other[1] ^= true;
            // An additive public constant moves only the coefficient of X^7, which
            // the prover does not hash: its output is unchanged and the verifier,
            // whose value includes the constant, disagrees.
            let (unchanged, _) = run::<F>(&PUBLIC, &witness, seed);
            let (coefficients, recomputed) = run::<F>(&other, &witness, seed);
            assert_eq!(coefficients, unchanged);
            assert_ne!(recomputed, Ok(coefficients[0]));
        }
        check::<Gf128>(11);
        check::<Gf192>(12);
        check::<Gf256>(13);
    }

    #[test]
    fn booleanity_has_the_two_coefficients_of_the_specification() {
        // For a bit, the lifted constraint is V^2 * X^5 + V * X^6.
        let values = vec![Gf128::ONE; 8];
        let fixture = instance(values, 77);
        let mut prover =
            prover::Prover::<Gf128>::new(&[0xa5], &fixture.tags, 8, &fixture.challenge)
                .expect("valid challenge");
        prover.record();
        prover.booleanity();
        for (index, polynomial) in prover.recorded().iter().enumerate() {
            let tag = Gf128::from_bytes(&fixture.tags[16 * index..16 * (index + 1)]).expect("tag");
            let mut expected = [Gf128::ZERO; DEGREE + 1];
            expected[5] = tag.square();
            expected[6] = tag;
            assert_eq!(polynomial, &expected, "bit {index}");
        }
    }

    /// A relation that misbehaves in a selectable way.
    struct Faulty(u8);

    impl<F: LambdaField> Relation<F> for Faulty {
        type PublicInput = ();

        fn witness_bits(&self) -> usize {
            if self.0 == 5 { 12 } else { 8 }
        }

        fn constraints(&self) -> usize {
            2
        }

        fn emit<C: ConstraintSystem<Field = F>>(&self, (): &(), cs: &mut C) {
            cs.constrain(cs.zero());
            match self.0 {
                // One constraint too few.
                0 => {}
                // One too many.
                1 => {
                    cs.constrain(cs.zero());
                    cs.constrain(cs.zero());
                    cs.constrain(cs.zero());
                }
                // A witness coordinate that does not exist, hidden in a product.
                2 => cs.constrain(cs.mul(cs.add(cs.witness(8), cs.one()), cs.zero())),
                // Degree 8.
                3 => {
                    let mut product = cs.one();
                    for _ in 0..8 {
                        product = cs.mul(product, cs.witness(0));
                    }
                    cs.constrain(cs.scale(cs.add(product, cs.witness(1)), F::ONE));
                }
                _ => cs.constrain(cs.zero()),
            }
        }
    }

    #[test]
    fn malformed_relations_are_typed_errors_in_every_evaluator() {
        fn check<F: LambdaField>() {
            let fixture = instance(vec![F::ZERO; 8], 5);
            let cases = [
                (
                    0,
                    QuickSilverError::ConstraintCount {
                        expected: 10,
                        actual: 9,
                    },
                ),
                (
                    1,
                    QuickSilverError::ConstraintCount {
                        expected: 10,
                        actual: 11,
                    },
                ),
                (2, QuickSilverError::WitnessIndex { constraint: 9 }),
                (3, QuickSilverError::DegreeOverflow { constraint: 9 }),
                (5, QuickSilverError::WitnessBits { witness_bits: 12 }),
            ];
            for (fault, error) in cases {
                let relation = Faulty(fault);
                assert_eq!(is_satisfied::<F, _>(&relation, &(), &[0]), Err(error));
                assert_eq!(
                    violated_constraints::<F, _>(&relation, &(), &[0]),
                    Err(error)
                );
                assert_eq!(
                    total_constraints::<F, _>(&relation).err(),
                    (fault == 5).then_some(error)
                );
                let inputs = ProverInputs {
                    witness: &[0],
                    tags: &fixture.tags,
                    mask_values: &fixture.mask_values,
                    mask_tags: &fixture.mask_tags,
                };
                assert_eq!(
                    prove::<F, _>(&relation, &(), &inputs, &fixture.challenge),
                    Err(error)
                );
                assert!(format!("{inputs:?}").starts_with("ProverInputs"));
                let delta = fixture.delta.to_bytes();
                let verifier = VerifierInputs {
                    masked_witness: &[0],
                    keys: &fixture.tags,
                    mask_keys: &fixture.mask_keys,
                    delta: delta.as_ref(),
                };
                assert_eq!(
                    verify::<F, _>(
                        &relation,
                        &(),
                        &verifier,
                        &fixture.challenge,
                        &vec![0u8; 6 * F::BYTES]
                    ),
                    Err(error)
                );
            }
            assert_eq!(is_satisfied::<F, _>(&Faulty(4), &(), &[0]), Ok(true));
        }
        check::<Gf128>();
        check::<Gf256>();
    }

    #[test]
    fn every_buffer_length_is_checked() {
        type F = Gf128;
        let fixture = instance(vec![F::ZERO; 8], 9);
        let relation = Faulty(4);
        let good = ProverInputs {
            witness: &[0],
            tags: &fixture.tags,
            mask_values: &fixture.mask_values,
            mask_tags: &fixture.mask_tags,
        };
        assert!(prove::<F, _>(&relation, &(), &good, &fixture.challenge).is_ok());
        let invalid = |input, expected, actual| QuickSilverError::InvalidLength {
            input,
            expected,
            actual,
        };
        let cases = [
            (
                ProverInputs {
                    witness: &[0, 0],
                    ..good
                },
                invalid(Input::Witness, 1, 2),
            ),
            (
                ProverInputs {
                    tags: &fixture.tags[1..],
                    ..good
                },
                invalid(Input::Tags, 128, 127),
            ),
            (
                ProverInputs {
                    mask_values: &fixture.mask_values[16..],
                    ..good
                },
                invalid(Input::MaskValues, 160, 144),
            ),
            (
                ProverInputs {
                    mask_tags: &fixture.mask_tags[..6 * 16],
                    ..good
                },
                invalid(Input::MaskTags, 160, 96),
            ),
        ];
        for (inputs, error) in cases {
            assert_eq!(
                prove::<F, _>(&relation, &(), &inputs, &fixture.challenge),
                Err(error)
            );
        }
        assert!(matches!(
            prove::<F, _>(&relation, &(), &good, &fixture.challenge[1..]),
            Err(QuickSilverError::Hash(_))
        ));

        let delta = fixture.delta.to_bytes();
        let good = VerifierInputs {
            masked_witness: &[0],
            keys: &fixture.tags,
            mask_keys: &fixture.mask_keys,
            delta: delta.as_ref(),
        };
        let tail = vec![0u8; 6 * 16];
        assert!(verify::<F, _>(&relation, &(), &good, &fixture.challenge, &tail).is_ok());
        let cases = [
            (
                VerifierInputs {
                    masked_witness: &[],
                    ..good
                },
                invalid(Input::MaskedWitness, 1, 0),
            ),
            (
                VerifierInputs {
                    keys: &fixture.tags[16..],
                    ..good
                },
                invalid(Input::Keys, 128, 112),
            ),
            (
                VerifierInputs {
                    mask_keys: &fixture.mask_keys[1..],
                    ..good
                },
                invalid(Input::MaskKeys, 160, 159),
            ),
            (
                VerifierInputs {
                    delta: &delta.as_ref()[1..],
                    ..good
                },
                invalid(Input::Delta, 16, 15),
            ),
        ];
        for (inputs, error) in cases {
            assert_eq!(
                verify::<F, _>(&relation, &(), &inputs, &fixture.challenge, &tail),
                Err(error)
            );
        }
        assert_eq!(
            verify::<F, _>(&relation, &(), &good, &fixture.challenge, &tail[1..]),
            Err(invalid(Input::Coefficients, 96, 95))
        );
        assert!(matches!(
            verify::<F, _>(&relation, &(), &good, &fixture.challenge[1..], &tail),
            Err(QuickSilverError::Hash(_))
        ));
        assert_eq!(check_length(Input::Delta, 3, 3), Ok(()));
    }

    #[test]
    fn degrees_combine_and_poison_as_documented() {
        let (one, two, six) = (Degree::ONE, Degree::TWO, Degree::Of(6));
        assert_eq!(Degree::ZERO.sum(two), (two, Some((0, 2))));
        assert_eq!(six.sum(one), (six, Some((6, 1))));
        assert_eq!(one.product(six), (Degree::Of(7), Some((1, 6))));
        assert_eq!(two.product(six), (Degree::Overflow, None));
        assert_eq!(Degree::Overflow.sum(one), (Degree::Overflow, None));
        assert_eq!(
            Degree::Overflow.product(Degree::ZERO),
            (Degree::Overflow, None)
        );
        assert_eq!(
            Degree::BadIndex.sum(Degree::Overflow),
            (Degree::BadIndex, None)
        );
        assert_eq!(
            Degree::Overflow.product(Degree::BadIndex),
            (Degree::BadIndex, None)
        );
        assert_eq!(six.get(), Some(6));
        assert_eq!(Degree::BadIndex.get(), None);
        assert_eq!(Degree::Overflow.get(), None);
    }

    #[test]
    fn the_stream_latches_the_first_error() {
        let mut stream = Stream::new(2);
        assert_eq!(stream.admit(Degree::Of(7)), Some(0));
        assert_eq!(
            stream.finish(),
            Err(QuickSilverError::ConstraintCount {
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(stream.admit(Degree::Overflow), None);
        assert_eq!(stream.admit(Degree::ONE), None);
        assert_eq!(stream.admit(Degree::BadIndex), None);
        assert_eq!(
            stream.finish(),
            Err(QuickSilverError::DegreeOverflow { constraint: 1 })
        );

        let mut stream = Stream::new(1);
        assert_eq!(stream.admit(Degree::ZERO), Some(7));
        assert_eq!(stream.finish(), Ok(()));
        assert_eq!(stream.admit(Degree::ZERO), None);
        assert_eq!(
            stream.finish(),
            Err(QuickSilverError::ConstraintCount {
                expected: 1,
                actual: 2
            })
        );
    }

    #[test]
    fn constants_follow_the_field() {
        let system = plain::Plain::<Gf192>::new(&[1], 8, false);
        assert_eq!(system.value_of(system.zero()), Gf192::ZERO);
        assert_eq!(system.value_of(system.one()), Gf192::ONE);
        assert_eq!(system.value_of(system.bit(true)), Gf192::ONE);
        assert_eq!(system.value_of(system.bit(false)), Gf192::ZERO);
        assert_eq!(
            system.value_of(system.add_bit(system.witness(0), true)),
            Gf192::ZERO
        );
        assert_eq!(
            system.value_of(system.add_bit(system.witness(1), true)),
            Gf192::ONE
        );
        assert_eq!((DEGREE, MASKS), (7, 10));
    }
}
