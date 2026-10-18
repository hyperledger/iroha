//! Successful native padding and the unused suffix of the original history.
//!
//! The selected public artifact fixes the cycle horizon. All gas and retired
//! cycles come from original packets constrained by the preceding banks, not
//! from `NativeInvocation`'s summary or a caller-provided expected outcome.
//! Statement/output commitment and general fault admission remain separate gates.

use super::super::{bit, packet};
use super::{F, Fields, root};
use crate::execution_proofs::ivm_step_air::residues::{Scratch, Sink, Stream};
use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};
use ivm::execution_packets::{MAX_STEPS, NativeInvocation, PACKET_SLOTS, instruction_clocks};

const DELTA_BITS: usize = 7;
const INVERSE: usize = DELTA_BITS;
const BORROWS: usize = INVERSE + 1;
const WIDTH: usize = BORROWS + 4;
const CONSTRAINTS: usize = 128;

struct Witness([F; WIDTH]);
impl Witness {
    fn clear(&mut self) {
        for field in &mut self.0 {
            field.zeroize_v1();
        }
    }
}
impl Drop for Witness {
    fn drop(&mut self) {
        self.clear();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum Row {
    Padding,
    Unused(usize),
}

pub(super) struct Terminal {
    cycle_limit: u64,
    row: ChargedBuffer<Witness>,
}
impl Terminal {
    pub(super) const BYTES: usize = core::mem::size_of::<Witness>();

    pub(super) fn new(
        native: &NativeInvocation,
        root: &root::Plan,
        budget: &AllocationBudget,
    ) -> Result<Self, ChargedBufferError> {
        let mut row = ChargedBuffer::new(1, budget)?;
        let fixed = Fixed::new(native);
        let mut witness = Witness([F::ZERO; WIDTH]);
        fill(&mut witness.0, root.cycle_limit(), &fixed);
        row.push_reserved(witness);
        Ok(Self {
            cycle_limit: root.cycle_limit(),
            row,
        })
    }

    /// The sole Source supplies its original owner and the same history pass.
    pub(super) fn evaluate<E>(
        &self,
        native: &NativeInvocation,
        scratch: &mut Scratch,
        mut consume: impl FnMut(Row, &[F]) -> Result<(), E>,
    ) -> Result<(), E> {
        let fixed = Fixed::new(native);
        {
            let mut emit = |values: &[F]| consume(Row::Padding, values);
            let mut out = Stream::new(scratch, &mut emit);
            append(
                &mut out,
                self.cycle_limit,
                &self.row.as_slice()[0].0,
                &fixed,
            );
            out.finish()?;
        }
        for clock in padding_first() + 2..PACKET_SLOTS {
            let fields = Fields::native(&native.packets()[clock]);
            let mut emit = |values: &[F]| consume(Row::Unused(clock), values);
            let mut out = Stream::new(scratch, &mut emit);
            append_unused(&mut out, &fields.0);
            out.finish()?;
        }
        Ok(())
    }
}

/// Derived from the common public schedule, never a supplied/rebased clock.
fn padding_first() -> usize {
    instruction_clocks(MAX_STEPS).expect("fixed root return")[20] as usize + 1
}
struct Fixed {
    retired_cycles: Fields,
    validated_gas: Fields,
    padding_gas: Fields,
    padding_cycles: Fields,
}
impl Fixed {
    fn new(native: &NativeInvocation) -> Self {
        let returning = instruction_clocks(MAX_STEPS).expect("fixed root return");
        Self {
            retired_cycles: Fields::native(&native.packets()[returning[19] as usize]),
            validated_gas: Fields::native(&native.packets()[returning[0] as usize + 23]),
            padding_gas: Fields::native(&native.packets()[padding_first()]),
            padding_cycles: Fields::native(&native.packets()[padding_first() + 1]),
        }
    }
}
fn word(fields: &Fields, at: usize) -> u64 {
    (0..4).fold(0, |value, limb| {
        value | (fields.0[at + limb].0 << (16 * limb))
    })
}
fn fill(row: &mut [F; WIDTH], cycle_limit: u64, fixed: &Fixed) {
    let delta = cycle_limit.wrapping_sub(word(&fixed.retired_cycles, packet::AFTER));
    for (index, cell) in row[..DELTA_BITS].iter_mut().enumerate() {
        *cell = F((delta >> index) & 1);
    }
    row[INVERSE] = F(delta).inv().unwrap_or(F::ZERO);
    let before = word(&fixed.padding_gas, packet::BEFORE);
    let mut borrow = 0;
    for limb in 0..4 {
        let a = (before >> (16 * limb)) & 0xffff;
        let b = ((delta >> (16 * limb)) & 0xffff) + borrow;
        borrow = u64::from(a < b);
        row[BORROWS + limb] = F(borrow);
    }
}

fn append(out: &mut impl Sink, cycle_limit: u64, row: &[F; WIDTH], fixed: &Fixed) {
    use packet::*;
    let start = out.len();
    out.extend(
        row[..DELTA_BITS]
            .iter()
            .chain(&row[BORROWS..])
            .map(|x| bit(*x)),
    );
    let delta = row[..DELTA_BITS]
        .iter()
        .enumerate()
        .fold(F::ZERO, |sum, (index, x)| sum.add(x.mul(F(1 << index))));
    let enabled = fixed.padding_gas.0[ENABLED];
    out.push(bit(enabled));
    out.push(delta.add(fixed.retired_cycles.0[AFTER]).sub(F(cycle_limit)));
    for limb in 1..8 {
        out.push(fixed.retired_cycles.0[AFTER + limb]);
    }
    out.push(delta.mul(F::ONE.sub(enabled)));
    out.push(delta.mul(row[INVERSE]).sub(enabled));
    out.push(F::ONE.sub(enabled).mul(row[INVERSE]));
    for (port, index, clock) in [
        (&fixed.padding_gas, 33, padding_first()),
        (&fixed.padding_cycles, 34, padding_first() + 1),
    ] {
        header(out, &port.0, index, clock, enabled);
        out.extend(port.0.iter().map(|x| F::ONE.sub(enabled).mul(*x)));
        for at in [BEFORE, AFTER] {
            for limb in 4..8 {
                out.push(port.0[at + limb]);
            }
        }
        out.push(port.0[BEFORE_TAG]);
        out.push(port.0[AFTER_TAG]);
    }
    for limb in 0..4 {
        out.push(
            fixed.padding_cycles.0[BEFORE + limb]
                .sub(enabled.mul(fixed.retired_cycles.0[AFTER + limb])),
        );
        out.push(
            fixed.padding_cycles.0[AFTER + limb]
                .sub(enabled.mul(F((cycle_limit >> (16 * limb)) & 0xffff))),
        );
        out.push(
            fixed.padding_gas.0[BEFORE + limb]
                .sub(enabled.mul(fixed.validated_gas.0[AFTER + limb])),
        );
        let incoming = if limb == 0 {
            F::ZERO
        } else {
            row[BORROWS + limb - 1]
        };
        let debit = if limb == 0 { delta } else { F::ZERO };
        out.push(
            fixed.padding_gas.0[BEFORE + limb]
                .sub(debit)
                .sub(incoming)
                .sub(fixed.padding_gas.0[AFTER + limb])
                .add(row[BORROWS + limb].mul(F(65536))),
        );
    }
    out.push(row[BORROWS + 3]);
    debug_assert_eq!(out.len() - start, CONSTRAINTS);
}
fn header(out: &mut impl Sink, fields: &[F; packet::WIDTH], index: u64, clock: usize, enabled: F) {
    use packet::*;
    for (column, expected) in [
        (SPACE, F(Space::Owner as u64)),
        (VM, F::ZERO),
        (GENERATION, F::ZERO),
        (INDEX, F(index)),
        (KEY, F(index + ((Space::Owner as u64) << 56))),
        (CLOCK, F(clock as u64)),
        (ENABLED, F::ONE),
        (WRITE, F::ONE),
    ] {
        out.push(fields[column].sub(enabled.mul(expected)));
    }
}
fn append_unused(out: &mut impl Sink, fields: &[F; packet::WIDTH]) {
    out.extend(fields.iter().copied());
}

#[cfg(test)]
mod tests;
