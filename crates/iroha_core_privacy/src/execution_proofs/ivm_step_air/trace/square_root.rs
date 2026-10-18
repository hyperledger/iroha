//! Exact floor square root using the shared radix-2^16 product workspace.
//!
//! A 32-bit root q and bounded nonnegative remainder r satisfy n=q*q+r and
//! r<=2*q, which is equivalent to q*q<=n<(q+1)*(q+1), including `u64::MAX`.
//! The shift/division workspace holds q, r, 2*q-r and the gas comparison. All
//! shared word digits and borrow/carry bits remain unconditionally constrained.
//! No interpreter callback or field-reduced 64-bit equality establishes a root.

use super::{F, Sources, division as d, multiply as m, shift, word};

pub(super) const CONSTRAINTS: usize = 95;

fn fill_word(bank: &mut [F], offset: usize, value: u64) {
    for limb in 0..4 {
        bank[offset + limb] = F((value >> (16 * limb)) & 0xffff);
    }
    word::fill_digits(&mut bank[offset + 4..offset + 36], value);
}

/// Candidate generation uses integer binary search; the AIR establishes the result.
pub(in super::super) fn witness(value: u64, gas: u64) -> d::Witness {
    let trapped = gas < 6;
    let root = if trapped {
        0
    } else {
        let (mut lo, mut hi) = (0_u64, 1_u64 << 32);
        while lo + 1 < hi {
            let middle = (lo + hi) / 2;
            if u128::from(middle) * u128::from(middle) <= u128::from(value) {
                lo = middle;
            } else {
                hi = middle;
            }
        }
        lo
    };
    let remainder = if trapped { 0 } else { value - root * root };
    let mut bank = [F::ZERO; shift::BANK_WIDTH];
    fill_word(&mut bank, d::QUOTIENT, root);
    fill_word(&mut bank, d::REMAINDER, remainder);
    fill_word(&mut bank, d::REMAINDER_RESULT, 2 * root);
    let mut double_carry = 0;
    for limb in 0..4 {
        double_carry = (2 * ((root >> (16 * limb)) & 0xffff) + double_carry) >> 16;
        bank[d::REMAINDER_BORROWS + limb] = F(double_carry);
    }
    let bound = m::correction_witness(2 * root, remainder);
    bank[d::QUOTIENT_RESULT..d::QUOTIENT_RESULT + 36].copy_from_slice(&bound[..36]);
    bank[d::QUOTIENT_BORROWS..d::QUOTIENT_BORROWS + 4].copy_from_slice(&bound[36..]);
    let gas_difference = m::correction_witness(gas, 6);
    bank[d::GAS_DIFFERENCE..d::GAS_DIFFERENCE + 36].copy_from_slice(&gas_difference[..36]);
    bank[d::GAS_BORROWS..d::GAS_BORROWS + 4].copy_from_slice(&gas_difference[36..]);
    bank[d::LOCAL_TRAP] = F(u64::from(trapped));
    let digits = m::product_digits(root, root);
    let mut product = m::witness(root, root, &digits, !trapped);
    product[m::SIGNED_UNSIGNED..m::SIGNED_UNSIGNED + 40]
        .copy_from_slice(&m::correction_witness(value, 0));
    product[m::SIGNED_SIGNED..m::SIGNED_SIGNED + 40]
        .copy_from_slice(&m::correction_witness(root, 0));
    let mut carry = 0;
    for limb in 0..8 {
        let r = if limb < 4 {
            (remainder >> (16 * limb)) & 0xffff
        } else {
            0
        };
        let sum = product[m::PRODUCT + limb].0 + r + carry;
        carry = sum >> 16;
        bank[d::SUM_CARRIES + limb] = F(carry);
    }
    d::Witness {
        bank,
        product,
        digits,
        remainder,
        denominator: root,
    }
}

pub(in super::super) fn append_residues(
    out: &mut impl crate::execution_proofs::ivm_step_air::residues::Sink,
    bank: &[F],
    product: &[F],
    sources: Sources<'_>,
    gas_digits: &[F],
    active: F,
    out_of_gas: F,
    assertion_failed: F,
) {
    let initial = out.len();
    let success = active.sub(out_of_gas);
    // The division owner supplies unconditional digit ranges; this mode owns
    // their packing because the ordinary quotient equations are inactive.
    for offset in [
        d::QUOTIENT,
        d::REMAINDER,
        d::QUOTIENT_RESULT,
        d::REMAINDER_RESULT,
        d::GAS_DIFFERENCE,
    ] {
        for limb in 0..4 {
            out.push(active.mul(bank[offset + limb].sub(word::pack(
                &bank[offset + 4 + 8 * limb..offset + 12 + 8 * limb],
                2,
            ))));
        }
    }
    // The multiply owner packs and ranges both magnitudes and their borrows.
    for limb in 0..4 {
        out.push(active.mul(product[m::SIGNED_UNSIGNED + limb].sub(sources.limb(0, limb))));
        out.push(active.mul(product[m::SIGNED_SIGNED + limb].sub(bank[d::QUOTIENT + limb])));
        for offset in [m::SIGNED_UNSIGNED, m::SIGNED_SIGNED] {
            out.push(active.mul(product[offset + m::BORROWS + limb]));
        }
    }
    out.push(active.mul(bank[d::QUOTIENT + 2]));
    out.push(active.mul(bank[d::QUOTIENT + 3]));
    for limb in 0..4 {
        let incoming = if limb == 0 {
            F::ZERO
        } else {
            bank[d::REMAINDER_BORROWS + limb - 1]
        };
        out.push(
            active.mul(
                F(2).mul(bank[d::QUOTIENT + limb])
                    .add(incoming)
                    .sub(bank[d::REMAINDER_RESULT + limb])
                    .sub(F(1 << 16).mul(bank[d::REMAINDER_BORROWS + limb])),
            ),
        );
    }
    out.push(active.mul(bank[d::REMAINDER_BORROWS + 3]));
    for limb in 0..4 {
        let incoming = if limb == 0 {
            F::ZERO
        } else {
            bank[d::QUOTIENT_BORROWS + limb - 1]
        };
        out.push(
            active.mul(
                bank[d::REMAINDER_RESULT + limb]
                    .sub(bank[d::REMAINDER + limb])
                    .sub(incoming)
                    .sub(bank[d::QUOTIENT_RESULT + limb])
                    .add(F(1 << 16).mul(bank[d::QUOTIENT_BORROWS + limb])),
            ),
        );
    }
    // An unborrowed full-width subtraction proves the exact nonnegative bound.
    out.push(active.mul(bank[d::QUOTIENT_BORROWS + 3]));
    for limb in 0..4 {
        let incoming = if limb == 0 {
            F::ZERO
        } else {
            bank[d::GAS_BORROWS + limb - 1]
        };
        out.push(
            active.mul(
                word::pack(&gas_digits[8 * limb..8 * (limb + 1)], 2)
                    .sub(if limb == 0 { F(6) } else { F::ZERO })
                    .sub(incoming)
                    .sub(bank[d::GAS_DIFFERENCE + limb])
                    .add(F(1 << 16).mul(bank[d::GAS_BORROWS + limb])),
            ),
        );
    }
    for limb in 0..8 {
        let incoming = if limb == 0 {
            F::ZERO
        } else {
            bank[d::SUM_CARRIES + limb - 1]
        };
        let remainder = if limb < 4 {
            bank[d::REMAINDER + limb]
        } else {
            F::ZERO
        };
        let value = if limb < 4 {
            sources.limb(0, limb)
        } else {
            F::ZERO
        };
        out.push(
            success.mul(
                product[m::PRODUCT + limb]
                    .add(remainder)
                    .add(incoming)
                    .sub(value)
                    .sub(F(1 << 16).mul(bank[d::SUM_CARRIES + limb])),
            ),
        );
    }
    out.push(success.mul(bank[d::SUM_CARRIES + 7]));
    // Shared slots unused by ISQRT have unique canonical contents.
    for offset in
        (d::QUOTIENT_NEGATIVE..d::GAS_DIFFERENCE).chain(d::ZERO_DENOMINATOR..d::LOCAL_TRAP)
    {
        out.push(active.mul(bank[offset]));
    }
    for value in bank[d::QUOTIENT..d::QUOTIENT + 4]
        .iter()
        .chain(&bank[d::REMAINDER..d::REMAINDER + 4])
        .chain(&bank[d::SUM_CARRIES..d::SUM_CARRIES + 8])
        .chain(&product[m::PRODUCT..m::PRODUCT + 8])
    {
        out.push(out_of_gas.mul(*value));
    }
    out.push(active.mul(bank[d::LOCAL_TRAP]).sub(out_of_gas));
    out.push(active.mul(bank[d::GAS_BORROWS + 3]).sub(out_of_gas));
    out.push(assertion_failed);
    debug_assert_eq!(out.len() - initial, CONSTRAINTS);
}
