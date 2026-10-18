//! Signed MEAN over the full 65-bit sum, with truncation toward zero.
//!
//! The already constrained ADD bank supplies the low 64 bits and final carry.
//! Source signs minus that carry give the exact signed sum sign. The ABS bank
//! supplies four result limbs, radix-four digits and increment carries. Its last
//! four cells hold each sum limb's low bit on MEAN rows; only the gas zero-check
//! needs new cells. No full-width integer is reduced to one field element.

use super::{F, Sources, absolute, bit, word};

/// Four result limbs, radix-four digits, increment carries and sum low bits.
pub(in super::super) const WIDTH: usize = absolute::WIDTH;
pub(super) const GAS_WIDTH: usize = 2;
pub(super) const CONSTRAINTS: usize = 19;
const LOW_BITS: usize = 40;
const NO_GAS: usize = 0;
const NO_GAS_INVERSE: usize = 1;

/// Untrusted candidate cells; constraints establish the arithmetic and trap.
pub(super) fn witness(left: u64, right: u64, gas: u64) -> ([F; absolute::WIDTH], [F; GAS_WIDTH]) {
    let bank = result_witness(left, right);
    let low_digit = gas & 3;
    let delta = F(low_digit * low_digit.saturating_sub(1)
        + (1..32).map(|index| (gas >> (2 * index)) & 3).sum::<u64>());
    (
        bank,
        [
            F(u64::from(delta == F::ZERO)),
            delta.inv().unwrap_or(F::ZERO),
        ],
    )
}

/// Candidate signed-MEAN result; both callers constrain the original source bits.
pub(in super::super) fn result_witness(left: u64, right: u64) -> [F; WIDTH] {
    let sum = i128::from(u64::cast_signed(left)) + i128::from(u64::cast_signed(right));
    let result = (sum / 2) as u64;
    let floor = (sum >> 1) as u64;
    let low_sum = left.wrapping_add(right);
    let mut incoming = u64::from(sum < 0 && low_sum & 1 != 0);
    let mut bank = [F::ZERO; absolute::WIDTH];
    for limb in 0..4 {
        bank[limb] = F((result >> (16 * limb)) & 0xffff);
        incoming = (((floor >> (16 * limb)) & 0xffff) + incoming) >> 16;
        bank[36 + limb] = F(incoming);
        bank[LOW_BITS + limb] = F((low_sum >> (16 * limb)) & 1);
    }
    word::fill_digits(&mut bank[4..36], result);
    bank
}

pub(super) fn append_residues(
    out: &mut impl crate::execution_proofs::ivm_step_air::residues::Sink,
    bank: &[F],
    gas: &[F],
    sum: &[F],
    sources: Sources<'_>,
    gas_digits: &[F],
    active: F,
    out_of_gas: F,
    assertion_failed: F,
) {
    let initial = out.len();
    append_arithmetic_residues(out, bank, sum, sources, active);
    // On bounded radix-four digits this nonnegative value is zero exactly for
    // gas zero or one. Its maximum is 99, so field wrap cannot fake exhaustion.
    let delta = gas_digits[0]
        .mul(gas_digits[0].sub(F::ONE))
        .add(gas_digits[1..].iter().copied().fold(F::ZERO, F::add));
    out.push(bit(gas[NO_GAS]));
    out.push(active.mul(delta.mul(gas[NO_GAS_INVERSE]).sub(F::ONE.sub(gas[NO_GAS]))));
    out.push(active.mul(delta.mul(gas[NO_GAS])));
    out.push(active.mul(gas[NO_GAS].mul(gas[NO_GAS_INVERSE])));
    out.push(active.mul(gas[NO_GAS]).sub(out_of_gas));
    out.push(assertion_failed);
    debug_assert_eq!(out.len() - initial, CONSTRAINTS);
}

/// Shared exact 65-bit signed sum, arithmetic shift and negative-odd correction.
/// Callers own unconditional result ranges, carry bits and canonical inactive cells.
pub(in super::super) fn append_arithmetic_residues(
    out: &mut impl crate::execution_proofs::ivm_step_air::residues::Sink,
    bank: &[F],
    sum: &[F],
    sources: Sources<'_>,
    active: F,
) {
    // This is the sign of the full signed 65-bit sum, including unsigned carry.
    let negative = sources.sign(0).add(sources.sign(1)).sub(sum[39]);
    out.push(active.mul(bit(negative)));
    for limb in 0..4 {
        let low = bank[LOW_BITS + limb];
        // Gate these checks: ABS uses two of these cells for field inverses.
        out.push(active.mul(bit(low)));
        let even = sum[4 + 8 * limb].sub(low);
        out.push(active.mul(even.mul(even.sub(F(2)))));
        let next_bit = if limb == 3 {
            negative
        } else {
            bank[LOW_BITS + limb + 1]
        };
        let incoming = if limb == 0 {
            negative.mul(bank[LOW_BITS])
        } else {
            bank[36 + limb - 1]
        };
        // Twice the arithmetic right shift, plus the negative-odd correction.
        // Every term is bounded far below the field modulus; carries are bits.
        out.push(
            active.mul(
                sum[limb]
                    .sub(low)
                    .add(F(1 << 16).mul(next_bit))
                    .add(F(2).mul(incoming))
                    .sub(F(2).mul(bank[limb]))
                    .sub(F(1 << 17).mul(bank[36 + limb])),
            ),
        );
    }
}
