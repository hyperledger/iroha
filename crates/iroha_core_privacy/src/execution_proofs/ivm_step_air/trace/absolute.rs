//! Exact signed ABS magnitude, overflow and gas-first opcode-boundary traps.
//!
//! Separate cells retain every existing arithmetic bank and its degree bound.
//! A full 64-bit source-bit equality check identifies `i64::MIN`; neither the
//! source word nor gas is collapsed modulo the field. Range checks are quartic
//! and unconditional. All remaining equations have degree at most three.

use super::{F, Sources, bit, multiply, word};

pub(super) const WIDTH: usize = 44;
pub(super) const CONSTRAINTS: usize = 54;
const MINIMUM: usize = 40;
const MINIMUM_INVERSE: usize = 41;
const NO_GAS: usize = 42;
const NO_GAS_INVERSE: usize = 43;

/// Untrusted candidate cells; verifier equations establish every result.
pub(super) fn witness(value: u64, gas: u64) -> [F; WIDTH] {
    let negative = u64::cast_signed(value) < 0;
    let mut bank = [F::ZERO; WIDTH];
    bank[..40].copy_from_slice(&multiply::correction_witness(
        if negative { 0 } else { value },
        if negative { value } else { 0 },
    ));
    let minimum_delta = F(u64::from((value ^ (1 << 63)).count_ones()));
    let gas_delta = F((0..32).map(|index| (gas >> (2 * index)) & 3).sum());
    for (flag, inverse, delta) in [
        (MINIMUM, MINIMUM_INVERSE, minimum_delta),
        (NO_GAS, NO_GAS_INVERSE, gas_delta),
    ] {
        bank[flag] = F(u64::from(delta == F::ZERO));
        bank[inverse] = delta.inv().unwrap_or(F::ZERO);
    }
    bank
}

pub(super) fn append_residues(
    out: &mut Vec<F>,
    bank: &[F],
    sources: Sources<'_>,
    gas_digits: &[F],
    active: F,
    out_of_gas: F,
    assertion_failed: F,
) {
    let initial = out.len();
    out.extend(bank[4..36].iter().copied().map(word::radix4));
    out.extend(bank[36..40].iter().copied().map(bit));
    out.extend([bit(bank[MINIMUM]), bit(bank[NO_GAS])]);
    for limb in 0..4 {
        out.push(bank[limb].sub(word::pack(&bank[4 + 8 * limb..12 + 8 * limb], 2)));
        let incoming = if limb == 0 {
            F::ZERO
        } else {
            bank[36 + limb - 1]
        };
        let source = sources.limb(0, limb);
        out.push(
            active.mul(
                source
                    .sub(F(2).mul(sources.sign(0)).mul(source))
                    .sub(incoming)
                    .sub(bank[limb])
                    .add(F(1 << 16).mul(bank[36 + limb])),
            ),
        );
    }
    let minimum_delta = F::ONE
        .sub(sources.sign(0))
        .add(sources.bits(0)[..63].iter().copied().fold(F::ZERO, F::add));
    let gas_delta = gas_digits.iter().copied().fold(F::ZERO, F::add);
    for (flag, inverse, delta) in [
        (MINIMUM, MINIMUM_INVERSE, minimum_delta),
        (NO_GAS, NO_GAS_INVERSE, gas_delta),
    ] {
        out.push(active.mul(delta.mul(bank[inverse]).sub(F::ONE.sub(bank[flag]))));
        out.push(active.mul(delta.mul(bank[flag])));
        out.push(active.mul(bank[flag].mul(bank[inverse])));
    }
    out.push(active.mul(bank[NO_GAS]).sub(out_of_gas));
    out.push(
        active
            .mul(F::ONE.sub(bank[NO_GAS]))
            .mul(bank[MINIMUM])
            .sub(assertion_failed),
    );
    debug_assert_eq!(out.len() - initial, CONSTRAINTS);
}
