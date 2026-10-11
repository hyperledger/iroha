//! Fixed native final-exponent program over five Fp12 registers.
//!
//! The source relation must authenticate register zero as the completed Miller
//! product, bind the complete register state and monotonically advancing cursor
//! through every step, and require register zero to equal one at the terminal.
//! Executing one arbitrary step is not a pairing verification capability.

use super::super::{extension::Fp12Value, field::Bls381Chip};
use iroha_pasta::PastaField;
use iroha_plonk::frontend::{Error, Region};

/// One fixed arithmetic operation in the exact final-exponent schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalExponentStep {
    /// Copy a register without changing its value.
    Copy {
        /// Destination register index.
        destination: usize,
        /// Source register index.
        source: usize,
    },
    /// Constrained general Fp12 multiplication.
    Multiply {
        /// Destination register index.
        destination: usize,
        /// First source register index.
        left: usize,
        /// Second source register index.
        right: usize,
    },
    /// General squaring, also valid in the cyclotomic subgroup.
    Square {
        /// Destination register index.
        destination: usize,
        /// Source register index.
        source: usize,
    },
    /// Nonzero Fp12 inversion; used only at the easy part's beginning.
    Inverse {
        /// Destination register index.
        destination: usize,
        /// Source register index.
        source: usize,
    },
    /// Fp12 conjugation; equals inversion on the later unitary subgroup.
    Conjugate {
        /// Destination register index.
        destination: usize,
        /// Source register index.
        source: usize,
    },
    /// Fixed Frobenius power.
    Frobenius {
        /// Destination register index.
        destination: usize,
        /// Source register index.
        source: usize,
        /// Fixed exponent of the Frobenius map.
        power: usize,
    },
}

/// Complete easy/hard exponentiation schedule used by native BLS12-381.
/// Five fixed `x` powers use scratch register four. Each starts at its base,
/// processes the remaining 63 bits of `|x|`, then conjugates for negative x.
/// After the easy part the value is cyclotomic, so general squaring and
/// conjugation reproduce the native cyclotomic optimizations exactly.
pub const FINAL_EXPONENT_STEPS: [FinalExponentStep; 374] = final_exponent_program();

struct ProgramBuilder {
    steps: [FinalExponentStep; 374],
    count: usize,
}
impl ProgramBuilder {
    const fn push(&mut self, step: FinalExponentStep) {
        self.steps[self.count] = step;
        self.count += 1;
    }
    const fn copy(&mut self, destination: usize, source: usize) {
        self.push(FinalExponentStep::Copy {
            destination,
            source,
        });
    }
    const fn multiply(&mut self, destination: usize, left: usize, right: usize) {
        self.push(FinalExponentStep::Multiply {
            destination,
            left,
            right,
        });
    }
    const fn square(&mut self, destination: usize, source: usize) {
        self.push(FinalExponentStep::Square {
            destination,
            source,
        });
    }
    const fn conjugate(&mut self, destination: usize, source: usize) {
        self.push(FinalExponentStep::Conjugate {
            destination,
            source,
        });
    }
    const fn frobenius(&mut self, destination: usize, source: usize, power: usize) {
        self.push(FinalExponentStep::Frobenius {
            destination,
            source,
            power,
        });
    }
    const fn power_x(&mut self, destination: usize, source: usize) {
        self.copy(4, source);
        self.copy(destination, source);
        let mut bit = 63;
        while bit > 0 {
            bit -= 1;
            self.square(destination, destination);
            if (super::MILLER_X >> bit) & 1 == 1 {
                self.multiply(destination, destination, 4);
            }
        }
        self.conjugate(destination, destination);
    }
}
const fn final_exponent_program() -> [FinalExponentStep; 374] {
    let mut p = ProgramBuilder {
        steps: [FinalExponentStep::Copy {
            destination: 0,
            source: 0,
        }; 374],
        count: 0,
    };
    // Registers 0..3 correspond to r,y0,y1,y2; register4 is an x-power base.
    p.conjugate(1, 0);
    p.push(FinalExponentStep::Inverse {
        destination: 2,
        source: 0,
    });
    p.multiply(0, 1, 2);
    p.copy(2, 0);
    p.frobenius(0, 0, 2);
    p.multiply(0, 0, 2);
    p.square(1, 0);
    p.power_x(2, 0);
    p.conjugate(3, 0);
    p.multiply(2, 2, 3);
    p.power_x(3, 2);
    p.conjugate(2, 2);
    p.multiply(2, 2, 3);
    p.power_x(3, 2);
    p.frobenius(2, 2, 1);
    p.multiply(2, 2, 3);
    p.multiply(0, 0, 1);
    p.power_x(1, 2);
    p.power_x(3, 1);
    p.frobenius(1, 2, 2);
    p.conjugate(2, 2);
    p.multiply(2, 2, 3);
    p.multiply(2, 2, 1);
    p.multiply(0, 0, 2);
    assert!(p.count == 374, "fixed final-exponent schedule length");
    p.steps
}

impl<F: PastaField> Bls381Chip<'_, F> {
    /// Apply one circuit-fixed program step. The caller must bind the exact
    /// prior state, step cursor, start, terminal and register-zero source.
    /// # Errors
    /// Returns layout errors or rejects an out-of-program step index.
    pub fn final_exponent_step(
        &mut self,
        region: &mut Region<'_, F>,
        registers: &[Fp12Value<F>; 5],
        index: usize,
    ) -> Result<[Fp12Value<F>; 5], Error> {
        let step = *FINAL_EXPONENT_STEPS.get(index).ok_or(Error::Synthesis)?;
        let (destination, value) = match step {
            FinalExponentStep::Copy {
                destination,
                source,
            } => (destination, registers[source].clone()),
            FinalExponentStep::Multiply {
                destination,
                left,
                right,
            } => (
                destination,
                self.mul_fp12(region, &registers[left], &registers[right])?,
            ),
            FinalExponentStep::Square {
                destination,
                source,
            } => (destination, self.square_fp12(region, &registers[source])?),
            FinalExponentStep::Inverse {
                destination,
                source,
            } => (destination, self.invert_fp12(region, &registers[source])?),
            FinalExponentStep::Conjugate {
                destination,
                source,
            } => (
                destination,
                self.conjugate_fp12(region, &registers[source])?,
            ),
            FinalExponentStep::Frobenius {
                destination,
                source,
                power,
            } => (
                destination,
                self.frobenius_fp12(region, &registers[source], power)?,
            ),
        };
        let mut result = registers.clone();
        result[destination] = value;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fq, Fq2, Fq6, Fq12, G1Affine, G2Affine};
    use ark_ec::{
        AffineRepr,
        pairing::{MillerLoopOutput, Pairing},
    };
    use ark_ff::Field;

    /// Native oracle execution of the fixed schedule, never circuit admission.
    pub(super) fn execute(step: FinalExponentStep, r: &mut [Fq12; 5]) {
        match step {
            FinalExponentStep::Copy {
                destination,
                source,
            } => r[destination] = r[source],
            FinalExponentStep::Multiply {
                destination,
                left,
                right,
            } => r[destination] = r[left] * r[right],
            FinalExponentStep::Square {
                destination,
                source,
            } => r[destination] = r[source].square(),
            FinalExponentStep::Inverse {
                destination,
                source,
            } => r[destination] = r[source].inverse().unwrap(),
            FinalExponentStep::Conjugate {
                destination,
                source,
            } => r[destination] = Fq12::new(r[source].c0, -r[source].c1),
            FinalExponentStep::Frobenius {
                destination,
                source,
                power,
            } => r[destination] = r[source].frobenius_map(power),
        }
    }
    #[test]
    fn whole_schedule_reproduces_native_final_exponentiation() {
        let miller =
            Bls12_381::multi_miller_loop([G1Affine::generator()], [G2Affine::generator()]).0;
        let sample = Fq12::new(
            Fq6::new(
                Fq2::new(Fq::from(3_u64), Fq::from(5_u64)),
                Fq2::ONE,
                Fq2::ZERO,
            ),
            Fq6::ONE,
        );
        for value in [Fq12::ONE, sample, miller, miller * sample] {
            let mut registers = [Fq12::ZERO; 5];
            registers[0] = value;
            for step in FINAL_EXPONENT_STEPS {
                execute(step, &mut registers);
            }
            assert_eq!(
                registers[0],
                Bls12_381::final_exponentiation(MillerLoopOutput(value))
                    .unwrap()
                    .0
            );
        }
    }
}
