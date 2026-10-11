//! Fixed two-pair Miller program for normal BLS signature verification.
//!
//! A source relation binds pair zero to the aggregate authorized G1 key and
//! exact W3f message point, pair one to negative G1 generator and aggregate G2
//! signature, with canonical encodings and subgroup checks. The full state and
//! monotonically advancing step cursor must be linked through every step.
//! Terminal output still requires the complete final exponent and equality to
//! one; a single step or a raw Miller result is not signature authority.

use super::super::{
    curve::{G1Value, G2Value},
    extension::Fp12Value,
    field::Bls381Chip,
    native,
};
use super::{MILLER_X, MillerG2Value, MillerLine};
use iroha_pasta::PastaField;
use iroha_plonk::frontend::{Error, Region};

/// One operation in the fixed two-pair Miller schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MillerStep {
    /// Square the Fp12 accumulator before a scalar bit.
    Square,
    /// Double one current G2 point and replace its line coefficients.
    Double {
        /// Fixed pair index, zero or one.
        pair: usize,
    },
    /// Add that pair's original G2 base and replace its line coefficients.
    Add {
        /// Fixed pair index, zero or one.
        pair: usize,
    },
    /// Evaluate the current line at that pair's G1 point and multiply the accumulator.
    Evaluate {
        /// Fixed pair index, zero or one.
        pair: usize,
    },
    /// Conjugate the terminal accumulator for the negative BLS parameter.
    Conjugate,
}
/// Exact fixed schedule for the two BLS verification pairings.
pub const MILLER_STEPS: [MillerStep; 336] = miller_program();
const fn miller_program() -> [MillerStep; 336] {
    let mut steps = [MillerStep::Square; 336];
    let mut count = 0;
    let mut bit = 63;
    while bit > 0 {
        bit -= 1;
        steps[count] = MillerStep::Square;
        count += 1;
        let mut pair = 0;
        while pair < 2 {
            steps[count] = MillerStep::Double { pair };
            count += 1;
            steps[count] = MillerStep::Evaluate { pair };
            count += 1;
            pair += 1;
        }
        if (MILLER_X >> bit) & 1 == 1 {
            let mut pair = 0;
            while pair < 2 {
                steps[count] = MillerStep::Add { pair };
                count += 1;
                steps[count] = MillerStep::Evaluate { pair };
                count += 1;
                pair += 1;
            }
        }
    }
    steps[count] = MillerStep::Conjugate;
    count += 1;
    assert!(count == 336, "fixed two-pair Miller schedule length");
    steps
}
/// Arithmetic continuation whose components require a common authenticated
/// context and exact predecessor binding in the source relation.
#[derive(Clone, Debug)]
pub struct MillerPairState<F: PastaField> {
    points: [MillerG2Value<F>; 2],
    lines: [MillerLine<F>; 2],
    accumulator: Fp12Value<F>,
}
impl<F: PastaField> MillerPairState<F> {
    /// Assemble already constrained components; this does not establish their
    /// common origin, predecessor or step cursor.
    pub const fn from_parts(
        points: [MillerG2Value<F>; 2],
        lines: [MillerLine<F>; 2],
        accumulator: Fp12Value<F>,
    ) -> Self {
        Self {
            points,
            lines,
            accumulator,
        }
    }
    /// Both homogeneous G2 continuations.
    pub const fn points(&self) -> &[MillerG2Value<F>; 2] {
        &self.points
    }
    /// Both current line triples.
    pub const fn lines(&self) -> &[MillerLine<F>; 2] {
        &self.lines
    }
    /// Current Fp12 accumulator.
    pub const fn accumulator(&self) -> &Fp12Value<F> {
        &self.accumulator
    }
}
impl<F: PastaField> Bls381Chip<'_, F> {
    /// Apply one fixed two-pair Miller step. Step zero additionally pins the
    /// initial accumulator to one and each point to its exact affine base.
    /// All subsequent register states, cursor progression and original bases
    /// must be linked by the source proof, then the terminal result must pass
    /// final exponentiation. No signature capability is returned here.
    /// # Errors
    /// Returns layout errors or rejects an out-of-program index.
    pub fn miller_pair_step(
        &mut self,
        region: &mut Region<'_, F>,
        state: &MillerPairState<F>,
        g1: &[G1Value<F>; 2],
        g2: &[G2Value<F>; 2],
        index: usize,
    ) -> Result<MillerPairState<F>, Error> {
        let step = *MILLER_STEPS.get(index).ok_or(Error::Synthesis)?;
        if index == 0 {
            let one = self.constant_fp2(region, [native::ONE, native::ZERO])?;
            let zero = self.constant_fp2(region, [native::ZERO; 2])?;
            let mut identity = [[[native::ZERO; 2]; 3]; 2];
            identity[0][0][0] = native::ONE;
            let identity = self.constant_fp12(region, &identity)?;
            Self::assert_equal_fp12(region, state.accumulator(), &identity)?;
            for pair in 0..2 {
                self.assert_nonidentity_g1(region, &g1[pair])?;
                self.assert_nonidentity_g2(region, &g2[pair])?;
                Self::assert_equal_fp2(region, state.points[pair].x(), g2[pair].x())?;
                Self::assert_equal_fp2(region, state.points[pair].y(), g2[pair].y())?;
                Self::assert_equal_fp2(region, state.points[pair].z(), &one)?;
                for coefficient in state.lines[pair].coefficients() {
                    Self::assert_equal_fp2(region, coefficient, &zero)?;
                }
            }
        }
        let mut out = state.clone();
        match step {
            MillerStep::Square => out.accumulator = self.square_fp12(region, &state.accumulator)?,
            MillerStep::Double { pair } => {
                let (point, line) = self.miller_double(region, &state.points[pair])?;
                out.points[pair] = point;
                out.lines[pair] = line;
            }
            MillerStep::Add { pair } => {
                let (point, line) = self.miller_add(region, &state.points[pair], &g2[pair])?;
                out.points[pair] = point;
                out.lines[pair] = line;
            }
            MillerStep::Evaluate { pair } => {
                out.accumulator =
                    self.miller_evaluate(region, &state.accumulator, &state.lines[pair], &g1[pair])?
            }
            MillerStep::Conjugate => {
                out.accumulator = self.conjugate_fp12(region, &state.accumulator)?
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
#[path = "miller_program_tests.rs"]
mod tests;
