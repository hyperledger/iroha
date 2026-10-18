//! Exact signed/unsigned quotient, remainder, arithmetic traps and gas admission.
//!
//! On division rows the 208-cell shift workspace is reused. New quartic range
//! checks occupy only cells already Boolean under the old barrel constraints;
//! masking the old cubic equations therefore preserves degree four and every
//! prior operation. Product and magnitude slots are owned by the shared multiply
//! equations. Quotient/remainder are unique from the full 128-bit product/sum
//! and strict remainder bound, never from native recomputation.

use super::{F, Sources, bit, multiply, shift, word};

pub(in super::super) const QUOTIENT: usize = 0;
pub(in super::super) const REMAINDER: usize = 36;
pub(in super::super) const QUOTIENT_RESULT: usize = 72;
pub(in super::super) const QUOTIENT_BORROWS: usize = 108;
pub(in super::super) const REMAINDER_RESULT: usize = 112;
pub(in super::super) const REMAINDER_BORROWS: usize = 148;
pub(in super::super) const QUOTIENT_NEGATIVE: usize = 152;
pub(in super::super) const REMAINDER_NEGATIVE: usize = 153;
pub(in super::super) const GAS_DIFFERENCE: usize = 154;
pub(in super::super) const GAS_BORROWS: usize = 190;
pub(in super::super) const SUM_CARRIES: usize = 194;
pub(in super::super) const ZERO_DENOMINATOR: usize = 202;
pub(in super::super) const ZERO_INVERSE: usize = 203;
pub(in super::super) const OVERFLOW: usize = 204;
pub(in super::super) const OVERFLOW_INVERSE: usize = 205;
pub(in super::super) const ARITHMETIC_ERROR: usize = 206;
pub(in super::super) const LOCAL_TRAP: usize = 207;
pub(in super::super) const CONSTRAINTS: usize = 264;
const WORDS: [usize; 5] = [
    QUOTIENT,
    REMAINDER,
    QUOTIENT_RESULT,
    REMAINDER_RESULT,
    GAS_DIFFERENCE,
];
const BOOLEAN_RANGES: [(usize, usize); 5] =
    [(108, 112), (148, 154), (190, 203), (204, 205), (206, 208)];

pub(in super::super) fn signed_kind(kind: usize) -> bool {
    kind == 0 || kind == 2 || kind == 4
}

fn fill_word(bank: &mut [F], offset: usize, value: u64) {
    for limb in 0..4 {
        bank[offset + limb] = F((value >> (16 * limb)) & 0xffff);
    }
    word::fill_digits(&mut bank[offset + 4..offset + 36], value);
}

/// Untrusted candidate material. The verifier constrains every cell independently.
pub(in super::super) struct Witness {
    pub(in super::super) bank: [F; shift::BANK_WIDTH],
    pub(in super::super) product: [F; multiply::WIDTH],
    pub(in super::super) digits: [F; 64],
    pub(in super::super) remainder: u64,
    pub(in super::super) denominator: u64,
}

pub(in super::super) fn witness(left: u64, right: u64, gas: u64, kind: usize) -> Witness {
    let signed = signed_kind(kind);
    let a_negative = signed && u64::cast_signed(left) < 0;
    let b_negative = signed && u64::cast_signed(right) < 0;
    let magnitude_a = if a_negative {
        left.wrapping_neg()
    } else {
        left
    };
    let magnitude_b = if b_negative {
        right.wrapping_neg()
    } else {
        right
    };
    let overflow = left == i64::cast_unsigned(i64::MIN) && right == u64::MAX;
    let arithmetic_error = right == 0 || signed && overflow;
    let debit = if kind == 4 { 12 } else { 10 };
    let trap = gas < debit || arithmetic_error;
    let (quotient, remainder) = if trap {
        (0, 0)
    } else {
        (magnitude_a / magnitude_b, magnitude_a % magnitude_b)
    };
    let quotient_negative = a_negative != b_negative;
    let mut bank = [F::ZERO; shift::BANK_WIDTH];
    fill_word(&mut bank, QUOTIENT, quotient);
    fill_word(&mut bank, REMAINDER, remainder);
    for (offset, borrows, value, negative) in [
        (
            QUOTIENT_RESULT,
            QUOTIENT_BORROWS,
            quotient,
            quotient_negative,
        ),
        (REMAINDER_RESULT, REMAINDER_BORROWS, remainder, a_negative),
    ] {
        let correction = multiply::correction_witness(
            if negative { 0 } else { value },
            if negative { value } else { 0 },
        );
        bank[offset..offset + 36].copy_from_slice(&correction[..36]);
        bank[borrows..borrows + 4].copy_from_slice(&correction[36..]);
    }
    bank[QUOTIENT_NEGATIVE] = F(u64::from(quotient_negative));
    bank[REMAINDER_NEGATIVE] = F(u64::from(a_negative));
    let gas_difference = multiply::correction_witness(gas, debit);
    bank[GAS_DIFFERENCE..GAS_DIFFERENCE + 36].copy_from_slice(&gas_difference[..36]);
    bank[GAS_BORROWS..GAS_BORROWS + 4].copy_from_slice(&gas_difference[36..]);
    let digits = multiply::product_digits(magnitude_b, quotient);
    let mut product = multiply::witness(magnitude_b, quotient, &digits, !trap);
    // The same correction witness primitive produces modular absolute values.
    for (offset, value, negative) in [
        (multiply::SIGNED_UNSIGNED, left, a_negative),
        (multiply::SIGNED_SIGNED, right, b_negative),
    ] {
        let correction = multiply::correction_witness(
            if negative { 0 } else { value },
            if negative { value } else { 0 },
        );
        product[offset..offset + 40].copy_from_slice(&correction);
    }
    if !trap {
        let mut carry = 0;
        for limb in 0..8 {
            let r = if limb < 4 {
                (remainder >> (16 * limb)) & 0xffff
            } else {
                0
            };
            let sum = product[multiply::PRODUCT + limb].0 + r + carry;
            carry = sum >> 16;
            bank[SUM_CARRIES + limb] = F(carry);
        }
        debug_assert_eq!(carry, 0);
    }
    let denominator_delta = F(u64::from(right.count_ones()));
    let overflow_delta = F(u64::from(
        (left ^ (1 << 63)).count_ones() + (!right).count_ones(),
    ));
    for (flag, inverse, delta) in [
        (ZERO_DENOMINATOR, ZERO_INVERSE, denominator_delta),
        (OVERFLOW, OVERFLOW_INVERSE, overflow_delta),
    ] {
        bank[flag] = F(u64::from(delta == F::ZERO));
        bank[inverse] = delta.inv().unwrap_or(F::ZERO);
    }
    bank[ARITHMETIC_ERROR] = F(u64::from(arithmetic_error));
    bank[LOCAL_TRAP] = F(u64::from(trap));
    Witness {
        bank,
        product,
        digits,
        remainder,
        denominator: magnitude_b,
    }
}

pub(in super::super) struct Selection {
    pub(in super::super) active: F,
    pub(in super::super) signed: F,
    pub(in super::super) ceiling: F,
    pub(in super::super) out_of_gas: F,
    pub(in super::super) assertion_failed: F,
}

pub(in super::super) fn append_residues(
    out: &mut impl crate::execution_proofs::ivm_step_air::residues::Sink,
    bank: &[F],
    product: &[F],
    sources: Sources<'_>,
    gas_digits: &[F],
    remainder_less: F,
    selection: Selection,
) {
    let initial = out.len();
    let Selection {
        active,
        signed,
        ceiling,
        out_of_gas,
        assertion_failed,
    } = selection;
    let trap = out_of_gas.add(assertion_failed);
    let success = active.sub(trap);
    // Old shift rows make every one of these positions Boolean, so the
    // unconditional range constraints preserve every prior row and padding.
    for offset in WORDS {
        out.extend(
            bank[offset + 4..offset + 36]
                .iter()
                .copied()
                .map(word::radix4),
        );
        for limb in 0..4 {
            out.push(active.mul(bank[offset + limb].sub(word::pack(
                &bank[offset + 4 + 8 * limb..offset + 4 + 8 * (limb + 1)],
                2,
            ))));
        }
    }
    for (start, end) in BOOLEAN_RANGES {
        out.extend(bank[start..end].iter().copied().map(bit));
    }
    let a_sign = sources.sign(0);
    let b_sign = sources.sign(1);
    out.push(
        active.mul(
            bank[QUOTIENT_NEGATIVE]
                .sub(signed.mul(a_sign.add(b_sign).sub(F(2).mul(a_sign).mul(b_sign)))),
        ),
    );
    out.push(active.mul(bank[REMAINDER_NEGATIVE].sub(signed.mul(a_sign))));
    for (input, result, borrows, negative) in [
        (
            QUOTIENT,
            QUOTIENT_RESULT,
            QUOTIENT_BORROWS,
            QUOTIENT_NEGATIVE,
        ),
        (
            REMAINDER,
            REMAINDER_RESULT,
            REMAINDER_BORROWS,
            REMAINDER_NEGATIVE,
        ),
    ] {
        for limb in 0..4 {
            let previous = if limb == 0 {
                F::ZERO
            } else {
                bank[borrows + limb - 1]
            };
            out.push(
                active.mul(
                    bank[input + limb]
                        .sub(F(2).mul(bank[negative]).mul(bank[input + limb]))
                        .sub(previous)
                        .sub(bank[result + limb])
                        .add(F(1 << 16).mul(bank[borrows + limb])),
                ),
            );
        }
    }
    for limb in 0..4 {
        let incoming = if limb == 0 {
            F::ZERO
        } else {
            bank[GAS_BORROWS + limb - 1]
        };
        let debit = if limb == 0 {
            F(10).add(F(2).mul(ceiling))
        } else {
            F::ZERO
        };
        out.push(
            active.mul(
                word::pack(&gas_digits[8 * limb..8 * (limb + 1)], 2)
                    .sub(debit)
                    .sub(incoming)
                    .sub(bank[GAS_DIFFERENCE + limb])
                    .add(F(1 << 16).mul(bank[GAS_BORROWS + limb])),
            ),
        );
    }
    let denominator_delta = sources.bits(1).iter().copied().fold(F::ZERO, F::add);
    let overflow_delta = F::ONE
        .sub(a_sign)
        .add(sources.bits(0)[..63].iter().copied().fold(F::ZERO, F::add))
        .add(
            sources
                .bits(1)
                .iter()
                .fold(F::ZERO, |sum, bit| sum.add(F::ONE.sub(*bit))),
        );
    for (flag, inverse, delta) in [
        (ZERO_DENOMINATOR, ZERO_INVERSE, denominator_delta),
        (OVERFLOW, OVERFLOW_INVERSE, overflow_delta),
    ] {
        out.push(active.mul(delta.mul(bank[inverse]).sub(F::ONE.sub(bank[flag]))));
        out.push(active.mul(delta.mul(bank[flag])));
        out.push(active.mul(bank[flag].mul(bank[inverse])));
    }
    let insufficient = bank[GAS_BORROWS + 3];
    let error = bank[ARITHMETIC_ERROR];
    out.push(
        active.mul(
            error
                .sub(bank[ZERO_DENOMINATOR])
                .sub(signed.mul(bank[OVERFLOW])),
        ),
    );
    out.push(
        active.mul(
            bank[LOCAL_TRAP]
                .sub(insufficient)
                .sub(F::ONE.sub(insufficient).mul(error)),
        ),
    );
    for limb in 0..8 {
        let incoming = if limb == 0 {
            F::ZERO
        } else {
            bank[SUM_CARRIES + limb - 1]
        };
        let r = if limb < 4 {
            bank[REMAINDER + limb]
        } else {
            F::ZERO
        };
        let a = if limb < 4 {
            product[multiply::SIGNED_UNSIGNED + limb]
        } else {
            F::ZERO
        };
        out.push(
            success.mul(
                product[multiply::PRODUCT + limb]
                    .add(r)
                    .add(incoming)
                    .sub(a)
                    .sub(F(1 << 16).mul(bank[SUM_CARRIES + limb])),
            ),
        );
    }
    out.push(success.mul(bank[SUM_CARRIES + 7]));
    out.push(success.mul(remainder_less.sub(F::ONE)));
    // Trap workspaces remain canonical even though no division is performed.
    for value in bank[QUOTIENT..QUOTIENT + 4]
        .iter()
        .chain(&bank[REMAINDER..REMAINDER + 4])
        .chain(&bank[SUM_CARRIES..SUM_CARRIES + 8])
        .chain(&product[multiply::PRODUCT..multiply::PRODUCT + 8])
    {
        out.push(trap.mul(*value));
    }
    out.push(active.mul(insufficient).sub(out_of_gas));
    out.push(
        active
            .mul(F::ONE.sub(insufficient))
            .mul(error)
            .sub(assertion_failed),
    );
    debug_assert_eq!(out.len() - initial, CONSTRAINTS);
}

pub(in super::super) fn result_half(bank: &[F], kind: usize, half: usize) -> F {
    let offset = if kind < 2 || kind == 4 {
        QUOTIENT_RESULT
    } else {
        REMAINDER_RESULT
    };
    super::half_from_limbs(bank, offset, half)
}
