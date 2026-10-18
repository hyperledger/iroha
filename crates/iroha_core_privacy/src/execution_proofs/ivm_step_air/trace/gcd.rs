//! Exact Euclidean microsteps for signed-input GCD with one architectural debit.
//!
//! Entry proves both unsigned magnitudes, including `i64::MIN`. Ninety-one
//! division slots suffice for every pair of magnitudes at most 2^63: a 92-step
//! Euclidean execution requires F93 = 12200160415121876738 > 2^63. The verifier
//! also requires denominator zero at the fixed commit slot, so the bound is
//! never an unconstrained host termination claim. Zero denominators freeze.
//! Intermediate pairs use the existing Boolean source bank; exact 128-bit
//! multiplication, bounded carries and R < B establish every Euclidean step.

use super::{F, Sources, absolute, bit, division, half_from_limbs, mean, multiply, shift, word};

pub(super) const STRIDE: usize = 93;
pub(super) const WIDTH: usize = 5;
pub(super) const ACTIVE: usize = 0;
pub(super) const ENTRY: usize = 1;
pub(super) const WORK: usize = 2;
pub(super) const DIVIDE: usize = 3;
pub(super) const COMMIT: usize = 4;
// The existing ABS Boolean flag is disjoint from every GCD magnitude cell.
const GAS_DIGIT_THREE: usize = 40;
pub(super) const CONSTRAINTS: usize = 10 + 10 + 208 + 8 + 3 + 10 + 24 + 6 + 43;

pub(super) fn magnitude(value: u64) -> u64 {
    u64::cast_signed(value).unsigned_abs()
}

/// Candidate arithmetic only; the AIR below establishes all equalities.
pub(super) fn witness(left: u64, right: u64, entry: bool) -> division::Witness {
    let (a, b) = if entry {
        (magnitude(left), magnitude(right))
    } else {
        (left, right)
    };
    let (q, r) = if entry || b == 0 {
        (0, 0)
    } else {
        (a / b, a % b)
    };
    let mut bank = [F::ZERO; shift::BANK_WIDTH];
    if !entry {
        for (offset, value) in [(division::QUOTIENT, q), (division::REMAINDER, r)] {
            for limb in 0..4 {
                bank[offset + limb] = F((value >> (16 * limb)) & 0xffff);
            }
            word::fill_digits(&mut bank[offset + 4..offset + 36], value);
        }
        let delta = F(u64::from(b.count_ones()));
        bank[division::ZERO_DENOMINATOR] = F(u64::from(b == 0));
        bank[division::ZERO_INVERSE] = delta.inv().unwrap_or(F::ZERO);
    }
    let digits = multiply::product_digits(b, q);
    let mut product = multiply::witness(b, q, &digits, !entry && b != 0);
    for (offset, source) in [
        (multiply::SIGNED_UNSIGNED, left),
        (multiply::SIGNED_SIGNED, right),
    ] {
        let negative = entry && u64::cast_signed(source) < 0;
        product[offset..offset + 40].copy_from_slice(&multiply::correction_witness(
            if negative { 0 } else { source },
            if negative { source } else { 0 },
        ));
    }
    if !entry && b != 0 {
        let mut carry = 0;
        for limb in 0..8 {
            let remainder = if limb < 4 {
                (r >> (16 * limb)) & 0xffff
            } else {
                0
            };
            let sum = product[multiply::PRODUCT + limb].0 + remainder + carry;
            carry = sum >> 16;
            bank[division::SUM_CARRIES + limb] = F(carry);
        }
        debug_assert_eq!(carry, 0);
    }
    division::Witness {
        bank,
        product,
        digits,
        remainder: r,
        denominator: b,
    }
}

pub(super) fn gas_witness(gas: u64) -> ([F; absolute::WIDTH], [F; mean::GAS_WIDTH]) {
    let mut bank = [F::ZERO; absolute::WIDTH];
    let digit_three = u64::from((gas >> 2) & 3 == 3);
    bank[GAS_DIGIT_THREE] = F(digit_three);
    let delta = F(digit_three + (2..32).map(|index| (gas >> (2 * index)) & 3).sum::<u64>());
    (
        bank,
        [
            F(u64::from(delta == F::ZERO)),
            delta.inv().unwrap_or(F::ZERO),
        ],
    )
}

/// Every mode is owned by authenticated fetch and a verifier-derived phase.
pub(super) struct Selection {
    pub(super) fetched: F,
    pub(super) out_of_gas: F,
    pub(super) assertion_failed: F,
    pub(super) entry: F,
    pub(super) work: F,
    pub(super) commit: F,
}

pub(super) fn append_residues(
    out: &mut Vec<F>,
    modes: &[F],
    bank: &[F],
    product: &[F],
    absolute_bank: &[F],
    gas_bank: &[F],
    sources: Sources<'_>,
    next_sources: Sources<'_>,
    gas_digits: &[F],
    remainder_less: F,
    selection: Selection,
) {
    let initial = out.len();
    let Selection {
        fetched,
        out_of_gas,
        assertion_failed,
        entry,
        work,
        commit,
    } = selection;
    let active = modes[ACTIVE];
    let entering = modes[ENTRY];
    let working = modes[WORK];
    let dividing = modes[DIVIDE];
    let committing = modes[COMMIT];
    let zero = bank[division::ZERO_DENOMINATOR];
    out.extend(modes.iter().copied().map(bit));
    out.extend([
        active.sub(fetched.mul(F::ONE.sub(out_of_gas))),
        entering.sub(active.mul(entry)),
        working.sub(active.mul(work)),
        dividing.sub(working.mul(F::ONE.sub(zero))),
        committing.sub(active.mul(commit)),
    ]);
    for operand in 0..2 {
        let offset = if operand == 0 {
            multiply::SIGNED_UNSIGNED
        } else {
            multiply::SIGNED_SIGNED
        };
        for half in 0..2 {
            out.push(
                entering.mul(
                    next_sources
                        .half(operand, half)
                        .sub(half_from_limbs(product, offset, half)),
                ),
            );
            let current = sources.half(0, half);
            let denominator = sources.half(1, half);
            let remainder = half_from_limbs(bank, division::REMAINDER, half);
            let expected = if operand == 0 {
                F::ONE.sub(zero).mul(denominator).add(zero.mul(current))
            } else {
                F::ONE.sub(zero).mul(remainder)
            };
            out.push(working.mul(next_sources.half(operand, half).sub(expected)));
        }
    }
    for half in 0..2 {
        out.push(committing.mul(sources.half(1, half)));
    }
    // Every shift-bank cell has one phase owner. Entry has no quotient yet;
    // the work phase owns only Q, R, sum carries and the exact zero predicate.
    for (index, value) in bank.iter().copied().enumerate() {
        let work_owned = (division::QUOTIENT..division::QUOTIENT + 36).contains(&index)
            || (division::REMAINDER..division::REMAINDER + 36).contains(&index)
            || (division::SUM_CARRIES..division::ZERO_INVERSE + 1).contains(&index);
        out.push(
            if work_owned {
                entering
            } else {
                entering.add(working)
            }
            .mul(value),
        );
    }
    for offset in [division::QUOTIENT, division::REMAINDER] {
        for limb in 0..4 {
            out.push(working.mul(bank[offset + limb].sub(word::pack(
                &bank[offset + 4 + 8 * limb..offset + 12 + 8 * limb],
                2,
            ))));
        }
    }
    let denominator_delta = sources.bits(1).iter().copied().fold(F::ZERO, F::add);
    out.push(
        working.mul(
            denominator_delta
                .mul(bank[division::ZERO_INVERSE])
                .sub(F::ONE.sub(zero)),
        ),
    );
    out.push(working.mul(denominator_delta.mul(zero)));
    out.push(working.mul(zero.mul(bank[division::ZERO_INVERSE])));
    for limb in 0..8 {
        let incoming = if limb == 0 {
            F::ZERO
        } else {
            bank[division::SUM_CARRIES + limb - 1]
        };
        let remainder = if limb < 4 {
            bank[division::REMAINDER + limb]
        } else {
            F::ZERO
        };
        let numerator = if limb < 4 {
            product[multiply::SIGNED_UNSIGNED + limb]
        } else {
            F::ZERO
        };
        out.push(
            dividing.mul(
                product[multiply::PRODUCT + limb]
                    .add(remainder)
                    .add(incoming)
                    .sub(numerator)
                    .sub(F(1 << 16).mul(bank[division::SUM_CARRIES + limb])),
            ),
        );
    }
    out.push(dividing.mul(bank[division::SUM_CARRIES + 7]));
    out.push(dividing.mul(remainder_less.sub(F::ONE)));
    for value in bank[division::QUOTIENT..division::QUOTIENT + 4]
        .iter()
        .chain(&bank[division::REMAINDER..division::REMAINDER + 4])
        .chain(&bank[division::SUM_CARRIES..division::SUM_CARRIES + 8])
        .chain(&product[multiply::PRODUCT..multiply::PRODUCT + 8])
    {
        out.push(entering.add(working).sub(dividing).mul(*value));
    }
    // Gas < 12 iff all base-four digits above d1 are zero and d1 != 3.
    // 6*is_three = d1*(d1-1)*(d1-2) has degree four including fetch.
    let digit = gas_digits[1];
    let is_three = absolute_bank[GAS_DIGIT_THREE];
    out.push(
        fetched.mul(
            F(6).mul(is_three)
                .sub(digit.mul(digit.sub(F::ONE)).mul(digit.sub(F(2)))),
        ),
    );
    let delta = is_three.add(gas_digits[2..].iter().copied().fold(F::ZERO, F::add));
    out.push(fetched.mul(delta.mul(gas_bank[1]).sub(F::ONE.sub(gas_bank[0]))));
    out.push(fetched.mul(delta.mul(gas_bank[0])));
    out.push(fetched.mul(gas_bank[0].mul(gas_bank[1])));
    out.push(fetched.mul(gas_bank[0].sub(out_of_gas)));
    out.push(fetched.mul(assertion_failed));
    for (index, value) in absolute_bank.iter().copied().enumerate() {
        if index != GAS_DIGIT_THREE {
            out.push(fetched.mul(value));
        }
    }
    debug_assert_eq!(out.len() - initial, CONSTRAINTS);
}
