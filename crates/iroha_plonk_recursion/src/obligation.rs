//! Fixed incoming-claim modes and the constrained burn/no-op verdict.
//!
//! The branch rule is Lambda §2.7. It never gates a predecessor, own step,
//! Q proof or A proof. A consuming relation must separately bind every mode
//! to its fixed obligation slot, select the corresponding accumulator and
//! require a Corrected commitment to differ from the original. This module
//! establishes the mode rule; it does not decide an accumulator.

pub mod ledger;

use iroha_pasta::PastaField;
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{
    GlueChip,
    cells::{Bit, Word},
};

/// The three one-hot bits of one incoming obligation's mode.
#[derive(Clone, Debug)]
pub struct ModeCells<F: PastaField> {
    accept: Bit<F>,
    trivial: Bit<F>,
    corrected: Bit<F>,
}

impl<F: PastaField> ModeCells<F> {
    /// Constrains three existing cells to one-hot Accept, Trivial, Corrected.
    /// The caller can copy these cells from another proof's public instances.
    ///
    /// # Errors
    /// Layout or synthesis failure. Invalid mode values make the circuit
    /// unsatisfied; no witness-dependent control flow changes its shape.
    pub fn constrain(
        glue: &mut GlueChip<F>,
        region: &mut Region<'_, F>,
        modes: &[Word<F>; 3],
    ) -> Result<Self, Error> {
        let accept = glue.assert_bool(region, &modes[0])?;
        let trivial = glue.assert_bool(region, &modes[1])?;
        let corrected = glue.assert_bool(region, &modes[2])?;
        let first_two = glue.add(region, accept.word(), trivial.word())?;
        let sum = glue.add(region, &first_two, corrected.word())?;
        glue.enforce_constant(region, &sum, F::ONE)?;
        Ok(Self {
            accept,
            trivial,
            corrected,
        })
    }

    /// Use the original pending claim when this bit is one.
    pub const fn accept(&self) -> &Bit<F> {
        &self.accept
    }

    /// Use the pinned full-length trivial accumulator when this bit is one.
    pub const fn trivial(&self) -> &Bit<F> {
        &self.trivial
    }

    /// Use a same-challenges, distinct-commitment corrected claim when one.
    pub const fn corrected(&self) -> &Bit<F> {
        &self.corrected
    }
}

/// Constrains the complete incoming-slot branch rule and returns `valid`.
///
/// `valid = AND(soft_bits) AND (no Corrected slot)`. A valid branch accepts
/// every incoming claim. An invalid branch has only Trivial slots, with at
/// most one Corrected slot; when all soft checks pass, exactly one Corrected
/// slot is necessary to justify the invalid branch. Every input is copied
/// into the constraints. Slice lengths are fixed circuit metadata.
///
/// Corrected inputs must still be folded and finally decided, so a prover
/// cannot justify a burn simply by setting a mode bit. The consumer must also
/// check `G* != G`, copy the original challenges and authenticate the source.
///
/// # Errors
/// Empty check/slot lists, unrepresentable slot count or layout failure.
/// Incorrect witness modes yield an unsatisfied circuit.
pub fn constrain_incoming_modes<F: PastaField>(
    glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    soft_bits: &[Bit<F>],
    modes: &[ModeCells<F>],
) -> Result<Bit<F>, Error> {
    // The bounded count also makes the sum an ordinary integer, not a
    // modular count that could wrap to zero or one in either Pasta field.
    if modes.is_empty() || u32::try_from(modes.len()).is_err() {
        return Err(Error::Synthesis);
    }
    let (first, rest) = soft_bits.split_first().ok_or(Error::Synthesis)?;
    let mut soft_ok = first.clone();
    for bit in rest {
        soft_ok = glue.and(region, &soft_ok, bit)?;
    }
    let mut count = modes[0].corrected.word().clone();
    for mode in &modes[1..] {
        count = glue.add(region, &count, mode.corrected.word())?;
    }
    let has_correction = glue.assert_bool(region, &count)?;
    let no_correction = glue.not(region, &has_correction)?;
    let valid = glue.and(region, &soft_ok, &no_correction)?;
    for mode in modes {
        GlueChip::assert_equal(region, mode.accept.word(), valid.word())?;
    }
    Ok(valid)
}
