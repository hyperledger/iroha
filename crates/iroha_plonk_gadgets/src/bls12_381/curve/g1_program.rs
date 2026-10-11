//! Exact native G1 subgroup program, including the nonidentity fixed-point guard.
//!
//! The source relation must bind the initial point in register zero, all three
//! registers and a contiguous cursor across every step. The terminal comparison
//! proves membership only with that full source linkage. This module does not
//! return a trusted key capability from an unlinked terminal witness.

use super::super::{field::Bls381Chip, pairing::MILLER_X};
use super::G1Value;
use iroha_pasta::PastaField;
use iroha_plonk::frontend::{Error, Region};

/// One fixed operation on the subgroup program's three G1 registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum G1Step {
    /// Copy a point.
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
    /// G1 cube-root endomorphism.
    Phi {
        /// Destination register.
        destination: usize,
        /// Source register.
        source: usize,
    },
    /// Reject `[|x|]P=P` for a nonidentity P before the second multiplication.
    RejectNonidentityFixedPoint,
}
struct Builder {
    steps: [G1Step; 141],
    count: usize,
}
impl Builder {
    const fn push(&mut self, step: G1Step) {
        self.steps[self.count] = step;
        self.count += 1;
    }
    const fn x_tail(&mut self, base: usize) {
        let mut bit = 63;
        while bit > 0 {
            bit -= 1;
            self.push(G1Step::Double {
                destination: 1,
                source: 1,
            });
            if (MILLER_X >> bit) & 1 == 1 {
                self.push(G1Step::Add {
                    destination: 1,
                    left: 1,
                    right: base,
                });
            }
        }
    }
}
/// Native optimized subgroup program: reject nonidentity fixed points, then
/// compare `φ(P)` with `-[|x|²]P` at the terminal step.
pub const G1_SUBGROUP_STEPS: [G1Step; 141] = program();
const fn program() -> [G1Step; 141] {
    let mut b = Builder {
        steps: [G1Step::Copy {
            destination: 0,
            source: 0,
        }; 141],
        count: 0,
    };
    b.push(G1Step::Copy {
        destination: 1,
        source: 0,
    });
    b.x_tail(0);
    b.push(G1Step::RejectNonidentityFixedPoint);
    b.push(G1Step::Copy {
        destination: 2,
        source: 1,
    });
    b.x_tail(2);
    b.push(G1Step::Negate {
        destination: 1,
        source: 1,
    });
    b.push(G1Step::Phi {
        destination: 2,
        source: 0,
    });
    assert!(b.count == 141, "fixed G1 subgroup schedule length");
    b.steps
}
impl<F: PastaField> Bls381Chip<'_, F> {
    /// One native G1 subgroup continuation. The final step compares the exact
    /// subgroup relation, but all prior states/cursors must also be linked.
    /// # Errors
    /// Returns layout errors or rejects an invalid index; constraints reject
    /// the nonidentity fixed point and terminal subgroup mismatch.
    pub fn g1_subgroup_step(
        &mut self,
        region: &mut Region<'_, F>,
        registers: &[G1Value<F>; 3],
        index: usize,
    ) -> Result<[G1Value<F>; 3], Error> {
        let step = *G1_SUBGROUP_STEPS.get(index).ok_or(Error::Synthesis)?;
        let mut out = registers.clone();
        let change = match step {
            G1Step::Copy {
                destination,
                source,
            } => Some((destination, registers[source].clone())),
            G1Step::Double {
                destination,
                source,
            } => Some((
                destination,
                self.add_g1(region, &registers[source], &registers[source])?,
            )),
            G1Step::Add {
                destination,
                left,
                right,
            } => Some((
                destination,
                self.add_g1(region, &registers[left], &registers[right])?,
            )),
            G1Step::Negate {
                destination,
                source,
            } => Some((destination, self.neg_g1(region, &registers[source])?)),
            G1Step::Phi {
                destination,
                source,
            } => Some((destination, self.phi_g1(region, &registers[source])?)),
            G1Step::RejectNonidentityFixedPoint => {
                let x_equal = self.is_equal(region, registers[0].x(), registers[1].x())?;
                let y_equal = self.is_equal(region, registers[0].y(), registers[1].y())?;
                let infinity_equal = self.glue().is_equal(
                    region,
                    registers[0].infinity().word(),
                    registers[1].infinity().word(),
                )?;
                let coordinates_equal = self.glue().and(region, &x_equal, &y_equal)?;
                let equal = self
                    .glue()
                    .and(region, &coordinates_equal, &infinity_equal)?;
                let finite = self.glue().not(region, registers[0].infinity())?;
                let invalid = self.glue().and(region, &finite, &equal)?;
                self.glue()
                    .enforce_constant(region, invalid.word(), F::ZERO)?;
                None
            }
        };
        if let Some((destination, value)) = change {
            out[destination] = value;
        }
        if index + 1 == G1_SUBGROUP_STEPS.len() {
            Self::assert_equal_g1(region, &out[1], &out[2])?;
        }
        Ok(out)
    }
}

#[cfg(test)]
#[path = "g1_program_tests.rs"]
mod tests;
