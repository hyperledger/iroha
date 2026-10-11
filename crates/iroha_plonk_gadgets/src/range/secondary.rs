//! Algebraic range stream on structurally spare compact-lane cells.
//!
//! This component keeps the existing primary tuple lookup. It proves exact
//! 81/87/128-bit (and Glue-only 93-bit) bounds using small polynomial roots and a second running sum.
//! The opt-in checked replay schedules exact requests and guards shared cells.
//! TODO: qualify the complete verifier and admitted catalog; component predicates
//! and structural projections alone do not establish a production row fit.

pub(crate) mod schedule;
pub use schedule::SecondaryPlan;

use super::{LimbBits, RangeShape, RunningSumConfig, running_sum_witness};
use crate::{
    Word,
    cells::{RowCursor, assign_word},
    phase::PhaseColumns,
};
use iroha_pasta::PastaField;
use iroha_plonk::{
    cs::{Advice, Column, ConstraintSystem, Expression, Fixed, Rotation},
    frontend::{Error, Region, Value},
};

/// The fixed phase owning the other cells on a secondary-stream row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecondaryPhase {
    /// Ordinary Glue: twelve packed bits in five spare cells.
    Glue,
    /// Ordinary Poseidon: fifteen packed bits in five spare cells.
    Poseidon,
    /// Paired Poseidon, with the same spare cells and radix.
    PairedPoseidon,
}
impl SecondaryPhase {
    const fn code(self) -> u8 {
        match self {
            Self::Glue => 0,
            Self::Poseidon => 2,
            Self::PairedPoseidon => 3,
        }
    }
    const fn radix_bits(self) -> usize {
        match self {
            Self::Glue => 12,
            Self::Poseidon | Self::PairedPoseidon => 15,
        }
    }
}

/// Existing compact ports, phase metadata and primary range-control columns.
/// Every returned word is constrained immediately; no deferred finalizer can
/// omit its range predicate. The caller must reserve disjoint live columns.
#[derive(Clone, Copy, Debug)]
pub struct SecondaryRangeConfig {
    ports: [Column<Advice>; 10],
    phases: PhaseColumns,
    primary: Column<Fixed>,
    control: Column<Fixed>,
}

fn constant<F: PastaField>(value: u64) -> Expression<F> {
    Expression::Constant(F::from(value))
}
fn indicator<F: PastaField>(value: &Expression<F>, code: u64, max: u64) -> Expression<F> {
    let mut out = constant(1);
    let mut scale = F::ONE;
    for other in 0..=max {
        if other != code {
            out = out * (value.clone() - constant(other));
            scale *= F::from(code) - F::from(other);
        }
    }
    out * scale.invert().expect("distinct fixed small codes")
}
fn roots<F: PastaField>(value: &Expression<F>, count: u64) -> Expression<F> {
    (0..count).fold(constant(1), |out, root| {
        out * (value.clone() - constant(root))
    })
}
fn packed<F: PastaField>(ports: &[Expression<F>; 10], digits: &[(usize, usize)]) -> Expression<F> {
    let mut scale = F::ONE;
    let mut out = constant(0);
    for (index, bits) in digits {
        out = out + ports[*index].clone() * scale;
        scale *= F::from(1 << bits);
    }
    out
}

impl SecondaryRangeConfig {
    /// Adds exact algebraic bounds while retaining one primary tuple lookup.
    /// Port four gains equality; every queried rotation already belongs to the
    /// compact ECC/Glue layout. All added gates have degree at most nine.
    ///
    /// # Errors
    /// Repeated ports, overlap with the primary bus, a non-tagged primary, or
    /// phase metadata without the explicit idle-ECC encoding.
    pub fn configure<F: PastaField>(
        meta: &mut ConstraintSystem<F>,
        ports: [Column<Advice>; 10],
        phases: PhaseColumns,
        primary: RunningSumConfig,
    ) -> Result<Self, Error> {
        if !phases.has_idle_ecc()
            || primary.compact_pattern_codes() != 4
            || ports
                .iter()
                .enumerate()
                .any(|(i, port)| *port == primary.column() || ports[..i].contains(port))
        {
            return Err(Error::Synthesis);
        }
        let (pattern, control) = primary.compact_patterns().ok_or(Error::Synthesis)?;
        meta.enable_equality(ports[4]);
        let phase_bits = phases.bits();
        meta.create_gate("secondary exact small digits", |cells| {
            let low = cells.query_fixed(phase_bits[0], Rotation::cur());
            let high = cells.query_fixed(phase_bits[1], Rotation::cur());
            let values: [_; 10] =
                core::array::from_fn(|i| cells.query_advice(ports[i], Rotation::cur()));
            let mut gates = Vec::new();
            // low+high is nonzero exactly on Glue/Poseidon phases. It is
            // linear, keeping an eight-root digit gate within degree nine.
            for index in [5, 9] {
                gates.push((low.clone() + high.clone()) * roots(&values[index], 8));
            }
            for index in [6, 7, 8] {
                gates.push(low.clone() * (constant(1) - high.clone()) * roots(&values[index], 4));
            }
            for index in [0, 1, 2] {
                gates.push(high.clone() * roots(&values[index], 8));
            }
            let primary = cells.query_fixed(pattern, Rotation::cur());
            let mode = cells.query_fixed(control, Rotation::cur());
            // On primary tagged tops `control` is a width, not our code.
            // Their factor is zero. The public prefix uses idle-ECC phase.
            gates.push(
                (primary.clone() - constant(2))
                    * indicator(&mode, 3, 3)
                    * high.clone()
                    * roots(&values[2], 4),
            );
            gates.push(
                (primary - constant(2))
                    * indicator(&mode, 0, 3)
                    * low
                    * (constant(1) - high)
                    * roots(&values[7], 2),
            );
            gates
        });
        meta.create_gate("secondary exact running sum", |cells| {
            let low = cells.query_fixed(phase_bits[0], Rotation::cur());
            let high = cells.query_fixed(phase_bits[1], Rotation::cur());
            let primary = cells.query_fixed(pattern, Rotation::cur());
            let mode = cells.query_fixed(control, Rotation::cur());
            let values: [_; 10] =
                core::array::from_fn(|i| cells.query_advice(ports[i], Rotation::cur()));
            let next = cells.query_advice(ports[4], Rotation::next());
            let glue = packed(&values, &[(5, 3), (9, 3), (6, 2), (7, 2), (8, 2)]);
            let sponge = packed(&values, &[(0, 3), (1, 3), (2, 3), (5, 3), (9, 3)]);
            let step = values[4].clone()
                - (constant(1) - high.clone()) * (next.clone() * F::from(1 << 12) + glue)
                - high.clone() * (next * F::from(1 << 15) + sponge);
            let top81 = values[4].clone()
                - values[5].clone()
                - values[9].clone() * F::from(8)
                - (constant(1) - high.clone())
                    * (values[6].clone() * F::from(64) + values[7].clone() * F::from(256));
            let unused81 = (constant(1) - high.clone()) * values[8].clone()
                + high.clone() * (values[0].clone() + values[1].clone() + values[2].clone());
            let top87 = values[4].clone()
                - (constant(1) - high.clone()) * values[5].clone()
                - high.clone() * packed(&values, &[(0, 3), (1, 3), (5, 3), (9, 3)]);
            let top128 = values[4].clone()
                - values[5].clone()
                - values[9].clone() * F::from(8)
                - ((constant(1) - high.clone()) * values[6].clone()
                    + high.clone() * values[2].clone())
                    * F::from(64);
            let unused87 = (constant(1) - high.clone())
                * (values[9].clone() + values[6].clone() + values[7].clone() + values[8].clone())
                + high.clone() * values[2].clone();
            let unused128 = (constant(1) - high.clone()) * (values[7].clone() + values[8].clone())
                + high.clone() * (values[0].clone() + values[1].clone());
            let forbidden = (constant(1) - low) * (constant(1) - high);
            let optional = (primary.clone() - constant(2)) * (constant(1) - forbidden.clone());
            // Code zero also occurs on ordinary inactive/narrow primary
            // rows. Gate its exact top by the eligible phase and exclude
            // only primary tagged-top code2, whose control is a width.
            let top_zero = (primary.clone() - constant(2))
                * indicator(&mode, 0, 3)
                * (constant(1) - forbidden.clone());
            vec![
                top_zero.clone() * top81,
                top_zero * unused81,
                optional.clone() * indicator(&mode, 1, 3) * step.clone(),
                optional.clone() * indicator(&mode, 2, 3) * top87,
                optional.clone() * indicator(&mode, 2, 3) * unused87,
                optional.clone() * indicator(&mode, 3, 3) * top128,
                optional.clone() * indicator(&mode, 3, 3) * unused128,
                // Primary exact-tag tops need no spare fixed control: every
                // eligible row is a secondary step. Unused states are zero.
                indicator(&primary, 2, 4) * (constant(1) - forbidden) * step,
            ]
        });
        Ok(Self {
            ports,
            phases,
            primary: pattern,
            control,
        })
    }

    /// Assigns one exact 81/87/128-bit (and Glue-only 93-bit) check on a reserved consecutive interval.
    /// `forced_tops` selects primary tagged-top rows among the nonfinal rows;
    /// other rows use the primary-step control overlay. The primary bus's
    /// actual assignments must agree with this structural metadata. The caller
    /// reserves a final successor row for the primary bus's next-row query.
    /// Every owned advice cell is exclusively reserved and every shared fixed
    /// value is guarded against existing or later conflicting assignments.
    /// Composition still validates query neighborhoods and the complete event
    /// schedule; an unassigned but live neighboring query is not a free port.
    ///
    /// # Errors
    /// Unsupported width, wrong fixed mask length, or out-of-bound assignments.
    /// Out-of-range values produce unsatisfied constraints.
    pub fn assign<F: PastaField>(
        &self,
        region: &mut Region<'_, F>,
        rows: &mut RowCursor,
        phase: SecondaryPhase,
        bits: usize,
        value: Value<F>,
        forced_tops: &[bool],
    ) -> Result<Word<F>, Error> {
        if !(matches!(bits, 81 | 87 | 128) || bits == 93 && phase == SecondaryPhase::Glue) {
            return Err(Error::Synthesis);
        }
        let mut shape = RangeShape::new(
            bits,
            LimbBits::new(phase.radix_bits()).ok_or(Error::Synthesis)?,
        )
        .ok_or(Error::Synthesis)?;
        shape.rows = shape.limbs;
        if forced_tops.len() + 1 != shape.rows {
            return Err(Error::Synthesis);
        }
        let start = rows.take(shape.rows)?;
        let entries = value
            .map(|value| running_sum_witness(&value, shape))
            .transpose_vec(shape.rows)?;
        let mut root = None;
        for (index, entry) in entries.into_iter().enumerate() {
            let row = start + index;
            self.phases.expect(region, row, phase.code())?;
            self.phases.enable(phase.code(), None).enable(region, row)?;
            let top = index + 1 == shape.rows;
            let forced = !top && forced_tops[index];
            let primary = F::from(if forced { 2 } else { 1 });
            let control = F::from(if forced {
                15
            } else if !top {
                1
            } else {
                match bits {
                    81 | 93 => 0,
                    87 => 2,
                    128 => 3,
                    _ => unreachable!(),
                }
            });
            for (column, value) in [(self.primary, primary), (self.control, control)] {
                region.expect_fixed(column, row, value)?;
                region.assign_fixed(column, row, value)?;
            }
            let word = self.assign_digits(region, row, phase, bits, top, entry)?;
            if root.is_none() {
                root = Some(word);
            }
        }
        root.ok_or(Error::Synthesis)
    }
    fn assign_digits<F: PastaField>(
        &self,
        region: &mut Region<'_, F>,
        row: usize,
        phase: SecondaryPhase,
        bits: usize,
        top: bool,
        entry: Value<F>,
    ) -> Result<Word<F>, Error> {
        self.phases.expect(region, row, phase.code())?;
        self.phases.enable(phase.code(), None).enable(region, row)?;
        region.reserve_advice(self.ports[4], row)?;
        let word = assign_word(region, self.ports[4], row, entry)?;
        let parts: &[(usize, usize)] = match (phase, bits, top) {
            (SecondaryPhase::Glue, _, false) => &[(5, 3), (9, 3), (6, 2), (7, 2), (8, 2)],
            (_, _, false) => &[(0, 3), (1, 3), (2, 3), (5, 3), (9, 3)],
            (SecondaryPhase::Glue, 81 | 93, true) => &[(5, 3), (9, 3), (6, 2), (7, 1)],
            (_, 81, true) => &[(5, 3), (9, 3)],
            (SecondaryPhase::Glue, 87, true) => &[(5, 3)],
            (_, 87, true) => &[(0, 3), (1, 3), (5, 3), (9, 3)],
            (SecondaryPhase::Glue, 128, true) => &[(5, 3), (9, 3), (6, 2)],
            (_, 128, true) => &[(5, 3), (9, 3), (2, 2)],
            _ => return Err(Error::Synthesis),
        };
        let mut shift = 0;
        if top {
            let unused: &[usize] = match (phase, bits) {
                (SecondaryPhase::Glue, 81 | 93) => &[8],
                (_, 81) => &[0, 1, 2],
                (SecondaryPhase::Glue, 87) => &[9, 6, 7, 8],
                (_, 87) => &[2],
                (SecondaryPhase::Glue, 128) => &[7, 8],
                (_, 128) => &[0, 1],
                _ => return Err(Error::Synthesis),
            };
            for port in unused {
                region.reserve_advice(self.ports[*port], row)?;
                assign_word(region, self.ports[*port], row, Value::known(F::ZERO))?;
            }
        }
        for (port, width) in parts {
            let digit = entry.map(|value| {
                let repr = value.to_repr();
                let low = u64::from_le_bytes(repr.as_ref()[..8].try_into().expect("Pasta repr"));
                F::from((low >> shift) & ((1 << width) - 1))
            });
            region.reserve_advice(self.ports[*port], row)?;
            assign_word(region, self.ports[*port], row, digit)?;
            shift += width;
        }
        Ok(word)
    }

    fn assign_zero_digits<F: PastaField>(
        &self,
        region: &mut Region<'_, F>,
        row: usize,
        phase: SecondaryPhase,
        value: Value<F>,
    ) -> Result<(), Error> {
        self.phases.expect(region, row, phase.code())?;
        self.phases.enable(phase.code(), None).enable(region, row)?;
        region.reserve_advice(self.ports[4], row)?;
        assign_word(region, self.ports[4], row, value)?;
        let ports: &[usize] = if phase == SecondaryPhase::Glue {
            &[5, 6, 7, 8, 9]
        } else {
            &[0, 1, 2, 5, 9]
        };
        for port in ports {
            region.reserve_advice(self.ports[*port], row)?;
            assign_word(region, self.ports[*port], row, Value::known(F::ZERO))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod schedule_tests;
