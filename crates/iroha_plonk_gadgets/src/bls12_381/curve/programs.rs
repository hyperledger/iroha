//! Fixed G2 cofactor and subgroup programs for recursively bound continuations.
//!
//! A proof owner must authenticate the initial point, bind every register and
//! cursor across all steps, and enforce the terminal index. Passing arbitrary
//! witnesses to a single step does not authenticate a cofactor result or prove
//! subgroup membership. G2 cofactor output is register four; the subgroup
//! program's terminal step requires `[x]P=ψ(P)`.

use super::super::{field::Bls381Chip, pairing::MILLER_X};
use super::G2Value;
use iroha_pasta::PastaField;
use iroha_plonk::frontend::{Error, Region};

/// One operation on six canonical on-curve G2 registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum G2Step {
    /// Copy one point.
    Copy {
        /// Destination register.
        destination: usize,
        /// Source register.
        source: usize,
    },
    /// Complete doubling.
    Double {
        /// Destination register.
        destination: usize,
        /// Source register.
        source: usize,
    },
    /// Complete addition.
    Add {
        /// Destination register.
        destination: usize,
        /// First source register.
        left: usize,
        /// Second source register.
        right: usize,
    },
    /// Complete negation.
    Negate {
        /// Destination register.
        destination: usize,
        /// Source register.
        source: usize,
    },
    /// Untwist–Frobenius–twist endomorphism.
    Psi {
        /// Destination register.
        destination: usize,
        /// Source register.
        source: usize,
    },
    /// Twice-composed endomorphism.
    Psi2 {
        /// Destination register.
        destination: usize,
        /// Source register.
        source: usize,
    },
}
struct Builder<const N: usize> {
    steps: [G2Step; N],
    count: usize,
}
impl<const N: usize> Builder<N> {
    const fn new() -> Self {
        Self {
            steps: [G2Step::Copy {
                destination: 0,
                source: 0,
            }; N],
            count: 0,
        }
    }
    const fn push(&mut self, s: G2Step) {
        self.steps[self.count] = s;
        self.count += 1;
    }
    const fn copy(&mut self, destination: usize, source: usize) {
        self.push(G2Step::Copy {
            destination,
            source,
        });
    }
    const fn add(&mut self, destination: usize, left: usize, right: usize) {
        self.push(G2Step::Add {
            destination,
            left,
            right,
        });
    }
    const fn negate(&mut self, destination: usize, source: usize) {
        self.push(G2Step::Negate {
            destination,
            source,
        });
    }
    const fn power_x_tail(&mut self, acc: usize, base: usize) {
        let mut bit = 63;
        while bit > 0 {
            bit -= 1;
            self.push(G2Step::Double {
                destination: acc,
                source: acc,
            });
            if (MILLER_X >> bit) & 1 == 1 {
                self.add(acc, acc, base);
            }
        }
        self.negate(acc, acc);
    }
}
/// Native effective-cofactor schedule: `[x²-x-1]P + [x-1]ψ(P) + ψ²(2P)`.
/// Register zero is the initial point and remains unchanged; output is four.
pub const G2_COFACTOR_STEPS: [G2Step; 151] = cofactor_program();
const fn cofactor_program() -> [G2Step; 151] {
    let mut b = Builder::new();
    b.copy(1, 0);
    b.power_x_tail(1, 0);
    b.push(G2Step::Psi {
        destination: 2,
        source: 0,
    });
    b.push(G2Step::Double {
        destination: 4,
        source: 0,
    });
    b.push(G2Step::Psi2 {
        destination: 4,
        source: 4,
    });
    b.add(3, 1, 2);
    b.copy(5, 3);
    b.power_x_tail(3, 5);
    b.add(4, 4, 3);
    b.negate(3, 1);
    b.add(4, 4, 3);
    b.negate(3, 2);
    b.add(4, 4, 3);
    b.negate(3, 0);
    b.add(4, 4, 3);
    assert!(b.count == 151, "fixed cofactor schedule length");
    b.steps
}
/// Fixed G2 subgroup schedule. Terminal register one is `[x]P`, register two
/// is `ψ(P)`; the step helper enforces their equality on the last step.
pub const G2_SUBGROUP_STEPS: [G2Step; 71] = subgroup_program();
const fn subgroup_program() -> [G2Step; 71] {
    let mut b = Builder::new();
    b.copy(1, 0);
    b.power_x_tail(1, 0);
    b.push(G2Step::Psi {
        destination: 2,
        source: 0,
    });
    assert!(b.count == 71, "fixed subgroup schedule length");
    b.steps
}
impl<F: PastaField> Bls381Chip<'_, F> {
    fn g2_program_step(
        &mut self,
        region: &mut Region<'_, F>,
        r: &[G2Value<F>; 6],
        step: G2Step,
    ) -> Result<[G2Value<F>; 6], Error> {
        let (destination, value) = match step {
            G2Step::Copy {
                destination,
                source,
            } => (destination, r[source].clone()),
            G2Step::Double {
                destination,
                source,
            } => (destination, self.add_g2(region, &r[source], &r[source])?),
            G2Step::Add {
                destination,
                left,
                right,
            } => (destination, self.add_g2(region, &r[left], &r[right])?),
            G2Step::Negate {
                destination,
                source,
            } => (destination, self.neg_g2(region, &r[source])?),
            G2Step::Psi {
                destination,
                source,
            } => (destination, self.psi_g2(region, &r[source])?),
            G2Step::Psi2 {
                destination,
                source,
            } => (destination, self.psi2_g2(region, &r[source])?),
        };
        let mut out = r.clone();
        out[destination] = value;
        Ok(out)
    }
    /// One fixed native cofactor step. Bind the full contiguous program before
    /// interpreting terminal register four as the cleared point.
    /// # Errors
    /// Returns layout errors or rejects an out-of-program index.
    pub fn g2_cofactor_step(
        &mut self,
        region: &mut Region<'_, F>,
        registers: &[G2Value<F>; 6],
        index: usize,
    ) -> Result<[G2Value<F>; 6], Error> {
        let step = *G2_COFACTOR_STEPS.get(index).ok_or(Error::Synthesis)?;
        self.g2_program_step(region, registers, step)
    }
    /// One fixed subgroup step. The terminal step enforces the subgroup
    /// equality; it is sound only with all prior states and cursors linked.
    /// # Errors
    /// Returns layout errors, rejects an invalid index, or fails the terminal
    /// subgroup constraint for a nonmember.
    pub fn g2_subgroup_step(
        &mut self,
        region: &mut Region<'_, F>,
        registers: &[G2Value<F>; 6],
        index: usize,
    ) -> Result<[G2Value<F>; 6], Error> {
        let step = *G2_SUBGROUP_STEPS.get(index).ok_or(Error::Synthesis)?;
        let out = self.g2_program_step(region, registers, step)?;
        if index + 1 == G2_SUBGROUP_STEPS.len() {
            Self::assert_equal_g2(region, &out[1], &out[2])?;
        }
        Ok(out)
    }
}

#[cfg(test)]
#[path = "programs_tests.rs"]
mod tests;
