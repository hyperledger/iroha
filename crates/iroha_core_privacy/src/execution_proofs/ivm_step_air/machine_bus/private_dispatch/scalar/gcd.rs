//! Exact signed-magnitude GCD through normalized products and bounded Bezout.
//!
//! This successful private step borrows existing radix-four workspace, adds no
//! columns or ports, and keeps every inactive physical cell canonically owned.
//! For b > 0, g*A=a, g*B=b and v*B-u*A=1 prove maximality. Strict u<B fixes the
//! coefficient pair. All eight radix-2^16 convolution positions are checked;
//! every bounded integer residual has magnitude below 2^35, below Goldilocks.
//! The b=0 case sets g=a and zeros all work-only advice, including biased carries.
//! TODO: Complete invocation/finalized-State and side-channel qualification;
//! this local relation never activates a production proving capability.

use super::*;

const WORD: usize = 32;
const A: usize = 0;
const B: usize = A + WORD;
pub(super) const RESULT: usize = B + WORD;
const NORMAL_A: usize = RESULT + WORD;
const NORMAL_B: usize = NORMAL_A + WORD;
const U: usize = NORMAL_B + WORD;
const V: usize = U + WORD;
const MAGNITUDE_BORROWS: usize = V + WORD;
const PRODUCT_CARRIES: usize = MAGNITUDE_BORROWS + 8;
const BEZOUT_CARRIES: usize = PRODUCT_CARRIES + 2 * 7 * 9;
const DIFFERENCE: usize = BEZOUT_CARRIES + 7 * 10;
const STRICT_BORROWS: usize = DIFFERENCE + WORD;
const PAYLOAD: usize = STRICT_BORROWS + 4;
const POOL_WIDTH: usize = 479;
pub(super) const CONSTRAINTS: usize = 569;
const RADIX: F = F(1 << 16);
const BIAS: F = F(1 << 18);
const SHIFT_WORDS: [usize; 5] = [
    division::QUOTIENT,
    division::REMAINDER,
    division::QUOTIENT_RESULT,
    division::REMAINDER_RESULT,
    division::GAS_DIFFERENCE,
];
const DIGIT_RANGES: [(usize, usize); 12] = [
    (ALU + alu::DIGITS, 32),
    (PRODUCT_DIGITS, 64),
    (MULTIPLY + multiply::CARRY_DIGITS, 63),
    (
        MULTIPLY + multiply::SIGNED_UNSIGNED + multiply::CORRECTION_DIGITS,
        32,
    ),
    (
        MULTIPLY + multiply::SIGNED_SIGNED + multiply::CORRECTION_DIGITS,
        32,
    ),
    (COUNT, 64),
    (MEAN + 4, 32),
    (SHIFT + division::QUOTIENT + 4, 32),
    (SHIFT + division::REMAINDER + 4, 32),
    (SHIFT + division::QUOTIENT_RESULT + 4, 32),
    (SHIFT + division::REMAINDER_RESULT + 4, 32),
    (SHIFT + division::GAS_DIFFERENCE + 4, 32),
];

const fn pool() -> [usize; POOL_WIDTH] {
    let mut result = [0; POOL_WIDTH];
    let mut output = 0;
    let mut range = 0;
    while range < DIGIT_RANGES.len() {
        let (start, len) = DIGIT_RANGES[range];
        let mut offset = 0;
        while offset < len {
            result[output] = start + offset;
            output += 1;
            offset += 1;
        }
        range += 1;
    }
    assert!(output == POOL_WIDTH);
    const { assert!(PAYLOAD == 464) };
    result
}
const POOL: [usize; POOL_WIDTH] = pool();

fn value(bank: &[F], logical: usize) -> F {
    bank[POOL[logical]]
}

fn packed(bank: &[F], logical: usize, count: usize) -> F {
    (0..count).fold(F::ZERO, |sum, index| {
        sum.add(value(bank, logical + index).mul(F(1 << (2 * index))))
    })
}

pub(super) fn limb(bank: &[F], word: usize, index: usize) -> F {
    packed(bank, word + 8 * index, 8)
}

fn carry(bank: &[F], offset: usize, index: usize, signed: bool) -> F {
    if index == 0 || index == 8 {
        F::ZERO
    } else {
        let width = if signed { 10 } else { 9 };
        let result = packed(bank, offset + (index - 1) * width, width);
        if signed { result.sub(BIAS) } else { result }
    }
}

fn convolution(bank: &[F], left: usize, right: usize, index: usize) -> F {
    (0..4)
        .filter(|i| index >= *i && index - *i < 4)
        .fold(F::ZERO, |sum, i| {
            sum.add(limb(bank, left, i).mul(limb(bank, right, index - i)))
        })
}

pub(super) fn append_residues(
    out: &mut impl crate::execution_proofs::ivm_step_air::residues::Sink,
    bank: &[F],
    sources: word::Sources<'_>,
    selected: F,
    zero_b: F,
) {
    let initial = out.len();
    let nonzero = selected.mul(F::ONE.sub(zero_b));
    let zero = selected.mul(zero_b);
    // These were unique Boolean count prefixes in every prior mode. Their new
    // radix-four checks are unconditional, never a selected degree-five range.
    out.extend(bank[COUNT..MOVE].iter().copied().map(word::radix4));
    for logical in (MAGNITUDE_BORROWS..PRODUCT_CARRIES)
        .chain(STRICT_BORROWS..PAYLOAD)
        .chain((0..7).map(|i| BEZOUT_CARRIES + i * 10 + 9))
    {
        out.push(selected.mul(bit(value(bank, logical))));
    }
    for (start, len) in [
        (ALU + alu::TRANSFER, 4),
        (MULTIPLY + multiply::SIGNED_UNSIGNED + multiply::BORROWS, 4),
        (MULTIPLY + multiply::SIGNED_SIGNED + multiply::BORROWS, 4),
        (MEAN + 36, 8),
    ] {
        out.extend(bank[start..start + len].iter().map(|v| selected.mul(*v)));
    }
    for offset in 0..shift::BANK_WIDTH {
        if !SHIFT_WORDS
            .iter()
            .any(|start| (*start..*start + 36).contains(&offset))
        {
            out.push(selected.mul(bank[SHIFT + offset]));
        }
    }
    for physical in &POOL[PAYLOAD..] {
        out.push(selected.mul(bank[*physical]));
    }
    // Existing shared division ranges own these digits in every mode; its
    // selected semantic packing is inactive here, so GCD owns the twenty limbs.
    for start in SHIFT_WORDS {
        for index in 0..4 {
            let digits = SHIFT + start + 4 + 8 * index;
            out.push(
                selected
                    .mul(bank[SHIFT + start + index].sub(word::pack(&bank[digits..digits + 8], 2))),
            );
        }
    }
    for logical in (NORMAL_A..MAGNITUDE_BORROWS).chain(PRODUCT_CARRIES..PAYLOAD) {
        out.push(zero.mul(value(bank, logical)));
    }
    for index in 0..4 {
        out.push(zero.mul(limb(bank, RESULT, index).sub(limb(bank, A, index))));
    }
    for (operand, offset) in [(0, A), (1, B)] {
        let sign = sources.sign(operand);
        for index in 0..4 {
            let source = sources.limb(operand, index);
            let incoming = if index == 0 {
                F::ZERO
            } else {
                value(bank, MAGNITUDE_BORROWS + operand * 4 + index - 1)
            };
            let outgoing = value(bank, MAGNITUDE_BORROWS + operand * 4 + index);
            out.push(
                selected.mul(
                    source
                        .sub(F(2).mul(sign).mul(source))
                        .sub(incoming)
                        .sub(limb(bank, offset, index))
                        .add(RADIX.mul(outgoing)),
                ),
            );
        }
        out.push(selected.mul(value(bank, MAGNITUDE_BORROWS + operand * 4 + 3).sub(sign)));
    }
    for (product, normalized, original) in [(0, NORMAL_A, A), (1, NORMAL_B, B)] {
        let offset = PRODUCT_CARRIES + product * 7 * 9;
        for index in 0..8 {
            let result = if index < 4 {
                limb(bank, original, index)
            } else {
                F::ZERO
            };
            out.push(
                nonzero.mul(
                    convolution(bank, RESULT, normalized, index)
                        .add(carry(bank, offset, index, false))
                        .sub(result)
                        .sub(RADIX.mul(carry(bank, offset, index + 1, false))),
                ),
            );
        }
    }
    for index in 0..8 {
        out.push(
            nonzero.mul(
                convolution(bank, V, NORMAL_B, index)
                    .sub(convolution(bank, U, NORMAL_A, index))
                    .add(carry(bank, BEZOUT_CARRIES, index, true))
                    .sub(if index == 0 { F::ONE } else { F::ZERO })
                    .sub(RADIX.mul(carry(bank, BEZOUT_CARRIES, index + 1, true))),
            ),
        );
    }
    for index in 0..4 {
        let incoming = if index == 0 {
            F::ZERO
        } else {
            value(bank, STRICT_BORROWS + index - 1)
        };
        let outgoing = value(bank, STRICT_BORROWS + index);
        out.push(
            nonzero.mul(
                limb(bank, U, index)
                    .sub(limb(bank, NORMAL_B, index))
                    .sub(incoming)
                    .sub(limb(bank, DIFFERENCE, index))
                    .add(RADIX.mul(outgoing)),
            ),
        );
    }
    out.push(nonzero.mul(value(bank, STRICT_BORROWS + 3).sub(F::ONE)));
    debug_assert_eq!(out.len() - initial, CONSTRAINTS);
}

#[cfg(test)]
mod witness {
    use super::*;

    fn digits(payload: &mut [F; PAYLOAD], offset: usize, count: usize, value: u64) {
        for index in 0..count {
            payload[offset + index] = F((value >> (2 * index)) & 3);
        }
    }

    fn coefficients(a: u64, b: u64) -> (u64, u64) {
        if b == 1 {
            return (0, 1);
        }
        let (mut x, mut y) = (i128::from(a), i128::from(b));
        let (mut old, mut current) = (1_i128, 0_i128);
        // At most 93 Euclidean steps for the full 64-bit domain. Candidate
        // construction is test-only and is not a constant-time custody claim.
        for _ in 0..93 {
            if y != 0 {
                let q = x / y;
                (x, y) = (y, x - q * y);
                (old, current) = (current, old - q * current);
            }
        }
        assert_eq!((x, y), (1, 0));
        let u = u64::try_from((-old).rem_euclid(i128::from(b))).unwrap();
        let numerator = u128::from(u) * u128::from(a) + 1;
        assert_eq!(numerator % u128::from(b), 0);
        (u, u64::try_from(numerator / u128::from(b)).unwrap())
    }

    pub(super) fn repack(bank: &mut [F]) {
        for (start, len) in [
            (ALU + alu::TRANSFER, 4),
            (MULTIPLY + multiply::SIGNED_UNSIGNED + multiply::BORROWS, 4),
            (MULTIPLY + multiply::SIGNED_SIGNED + multiply::BORROWS, 4),
            (MEAN + 36, 8),
        ] {
            bank[start..start + len].fill(F::ZERO);
        }
        for offset in 0..shift::BANK_WIDTH {
            if !SHIFT_WORDS
                .iter()
                .any(|start| (*start..*start + 36).contains(&offset))
            {
                bank[SHIFT + offset] = F::ZERO;
            }
        }
        for (start, digits_offset, limbs, width) in [
            (ALU, ALU + alu::DIGITS, 4, 8),
            (MULTIPLY + multiply::PRODUCT, PRODUCT_DIGITS, 8, 8),
            (
                MULTIPLY + multiply::CARRY,
                MULTIPLY + multiply::CARRY_DIGITS,
                7,
                9,
            ),
            (
                MULTIPLY + multiply::SIGNED_UNSIGNED,
                MULTIPLY + multiply::SIGNED_UNSIGNED + multiply::CORRECTION_DIGITS,
                4,
                8,
            ),
            (
                MULTIPLY + multiply::SIGNED_SIGNED,
                MULTIPLY + multiply::SIGNED_SIGNED + multiply::CORRECTION_DIGITS,
                4,
                8,
            ),
            (MEAN, MEAN + 4, 4, 8),
        ]
        .into_iter()
        .chain(SHIFT_WORDS.map(|start| (SHIFT + start, SHIFT + start + 4, 4, 8)))
        {
            for index in 0..limbs {
                bank[start + index] = word::pack(
                    &bank[digits_offset + index * width..digits_offset + (index + 1) * width],
                    2,
                );
            }
        }
    }

    pub(in super::super) fn fill(bank: &mut [F], left: u64, right: u64) {
        let (a, b) = (
            u64::cast_signed(left).unsigned_abs(),
            u64::cast_signed(right).unsigned_abs(),
        );
        let (mut g, mut rest) = (a, b);
        for _ in 0..93 {
            if rest != 0 {
                (g, rest) = (rest, g % rest);
            }
        }
        assert_eq!(rest, 0);
        let mut payload = [F::ZERO; PAYLOAD];
        for (offset, value) in [(A, a), (B, b), (RESULT, g)] {
            digits(&mut payload, offset, WORD, value);
        }
        for (operand, raw, magnitude) in [(0, left, a), (1, right, b)] {
            let sign = raw >> 63;
            let mut borrow = 0_i128;
            for index in 0..4 {
                let source = i128::from((raw >> (16 * index)) & 0xffff);
                let target = i128::from((magnitude >> (16 * index)) & 0xffff);
                let residual = source - 2 * i128::from(sign) * source - borrow - target;
                assert_eq!(residual % (1 << 16), 0);
                borrow = -residual / (1 << 16);
                assert!((0..=1).contains(&borrow));
                payload[MAGNITUDE_BORROWS + operand * 4 + index] = F(borrow as u64);
            }
            assert_eq!(borrow, i128::from(sign));
        }
        if b != 0 {
            let (normal_a, normal_b) = (a / g, b / g);
            let (u, v) = coefficients(normal_a, normal_b);
            for (offset, value) in [(NORMAL_A, normal_a), (NORMAL_B, normal_b), (U, u), (V, v)] {
                digits(&mut payload, offset, WORD, value);
            }
            for (product, normalized, original) in [(0, normal_a, a), (1, normal_b, b)] {
                let mut carry = 0_u64;
                for index in 0..8 {
                    let sum =
                        (0..4)
                            .filter(|i| index >= *i && index - *i < 4)
                            .fold(carry, |sum, i| {
                                sum + ((g >> (16 * i)) & 0xffff)
                                    * ((normalized >> (16 * (index - i))) & 0xffff)
                            });
                    assert_eq!(
                        sum & 0xffff,
                        if index < 4 {
                            (original >> (16 * index)) & 0xffff
                        } else {
                            0
                        }
                    );
                    carry = sum >> 16;
                    if index < 7 {
                        assert!(carry < 1 << 18);
                        digits(
                            &mut payload,
                            PRODUCT_CARRIES + product * 7 * 9 + index * 9,
                            9,
                            carry,
                        );
                    } else {
                        assert_eq!(carry, 0);
                    }
                }
            }
            let mut carry = 0_i128;
            for index in 0..8 {
                let mut sum = carry - i128::from(index == 0);
                for i in (0..4).filter(|i| index >= *i && index - *i < 4) {
                    let j = index - i;
                    sum += i128::from((v >> (16 * i)) & 0xffff)
                        * i128::from((normal_b >> (16 * j)) & 0xffff);
                    sum -= i128::from((u >> (16 * i)) & 0xffff)
                        * i128::from((normal_a >> (16 * j)) & 0xffff);
                }
                assert_eq!(sum % (1 << 16), 0);
                carry = sum / (1 << 16);
                if index < 7 {
                    assert!((-(1 << 18)..(1 << 18)).contains(&carry));
                    digits(
                        &mut payload,
                        BEZOUT_CARRIES + index * 10,
                        10,
                        (carry + (1 << 18)) as u64,
                    );
                } else {
                    assert_eq!(carry, 0);
                }
            }
            digits(&mut payload, DIFFERENCE, WORD, u.wrapping_sub(normal_b));
            let mut borrow = 0;
            for index in 0..4 {
                borrow = u64::from(
                    ((u >> (16 * index)) & 0xffff) < ((normal_b >> (16 * index)) & 0xffff) + borrow,
                );
                payload[STRICT_BORROWS + index] = F(borrow);
            }
            assert_eq!(borrow, 1);
        }
        for physical in POOL {
            bank[physical] = F::ZERO;
        }
        for (logical, value) in payload.into_iter().enumerate() {
            bank[POOL[logical]] = value;
        }
        repack(bank);
        let population = F(u64::from(right.count_ones()));
        bank[MOVE_ZERO] = F(u64::from(right == 0));
        bank[MOVE_INVERSE] = population.inv().unwrap_or(F::ZERO);
    }
}
#[cfg(test)]
pub(super) use witness::fill;

#[cfg(test)]
mod tests {
    use super::*;

    fn write_digits(bank: &mut [F], offset: usize, count: usize, value: u64) {
        for index in 0..count {
            bank[POOL[offset + index]] = F((value >> (2 * index)) & 3);
        }
    }

    fn word_value(bank: &[F], offset: usize) -> u64 {
        (0..32).fold(0, |result, i| result | value(bank, offset + i).0 << (2 * i))
    }

    // Coherent adversary: recompute every derived carry and old packed limb
    // after replacing normalized words. A wrong Bezout integer has a retained
    // nonzero low-limb residue; no candidate host check may hide that attack.
    fn replace_normalized(bank: &mut [F], words: [u64; 5]) {
        let [g, a, b, u, v] = words;
        for (offset, value) in [(RESULT, g), (NORMAL_A, a), (NORMAL_B, b), (U, u), (V, v)] {
            write_digits(bank, offset, WORD, value);
        }
        for (product, normalized) in [(0, a), (1, b)] {
            let mut carry = 0_u64;
            for index in 0..7 {
                let sum = (0..4)
                    .filter(|i| index >= *i && index - *i < 4)
                    .fold(carry, |sum, i| {
                        sum + ((g >> (16 * i)) & 0xffff)
                            * ((normalized >> (16 * (index - i))) & 0xffff)
                    });
                carry = sum >> 16;
                write_digits(bank, PRODUCT_CARRIES + product * 63 + index * 9, 9, carry);
            }
        }
        let mut carry = 0_i128;
        for index in 0..7 {
            let mut sum = carry - i128::from(index == 0);
            for i in (0..4).filter(|i| index >= *i && index - *i < 4) {
                let j = index - i;
                sum += i128::from((v >> (16 * i)) & 0xffff) * i128::from((b >> (16 * j)) & 0xffff);
                sum -= i128::from((u >> (16 * i)) & 0xffff) * i128::from((a >> (16 * j)) & 0xffff);
            }
            carry = sum.div_euclid(1 << 16);
            assert!((-(1 << 18)..(1 << 18)).contains(&carry));
            write_digits(
                bank,
                BEZOUT_CARRIES + index * 10,
                10,
                (carry + (1 << 18)) as u64,
            );
        }
        write_digits(bank, DIFFERENCE, WORD, u.wrapping_sub(b));
        let mut borrow = 0;
        for index in 0..4 {
            borrow =
                u64::from(((u >> (16 * index)) & 0xffff) < ((b >> (16 * index)) & 0xffff) + borrow);
            bank[POOL[STRICT_BORROWS + index]] = F(borrow);
        }
        witness::repack(bank);
    }

    fn residuals(bank: &[F], left: u64, right: u64) -> Vec<F> {
        let bits = word::witness(left, right);
        let mut out = Vec::new();
        append_residues(
            &mut out,
            bank,
            word::Sources::new(&bits),
            F::ONE,
            F(u64::from(right == 0)),
        );
        assert_eq!(out.len(), 569);
        out
    }

    #[test]
    fn normalized_bezout_rejects_smaller_common_divisors_and_noncanonical_coefficients() {
        let mut bank = [F::ZERO; WIDTH];
        fill(&mut bank, 12, 18);
        assert!(residuals(&bank, 12, 18).iter().all(|r| *r == F::ZERO));
        assert_eq!(
            (
                word_value(&bank, RESULT),
                word_value(&bank, U),
                word_value(&bank, V)
            ),
            (6, 1, 1)
        );
        for (g, a, b) in [(1, 12, 18), (2, 6, 9), (3, 4, 6), (4, 3, 4), (9, 1, 2)] {
            let mut forged = bank;
            replace_normalized(&mut forged, [g, a, b, 1, 1]);
            assert!(
                residuals(&forged, 12, 18).iter().any(|r| *r != F::ZERO),
                "wrong g={g}"
            );
        }
        // 3*3-4*2=1 is a valid Bezout pair, but u=4 is not below B=3.
        let mut forged = bank;
        replace_normalized(&mut forged, [6, 2, 3, 4, 3]);
        let failed: Vec<_> = residuals(&forged, 12, 18)
            .into_iter()
            .filter(|r| *r != F::ZERO)
            .collect();
        assert_eq!(failed, vec![F::ZERO.sub(F::ONE)]);
    }

    #[test]
    fn exact_full_product_rejects_goldilocks_wrap_and_biased_carry_substitution() {
        // Whole-field 2^32 * 2^32 equals 2^32-1 modulo Goldilocks. The full
        // eight-limb divisibility equality must nevertheless reject this g.
        assert_eq!(F(1 << 32).mul(F(1 << 32)), F((1 << 32) - 1));
        let mut bank = [F::ZERO; WIDTH];
        fill(&mut bank, (1 << 32) - 1, 1 << 32);
        replace_normalized(&mut bank, [1 << 32, 1 << 32, 1, 0, 1]);
        assert!(
            residuals(&bank, (1 << 32) - 1, 1 << 32)
                .iter()
                .any(|r| *r != F::ZERO)
        );
        fill(&mut bank, 12, 18);
        for offset in (0..7)
            .map(|i| BEZOUT_CARRIES + i * 10 + 9)
            .chain(MAGNITUDE_BORROWS..PRODUCT_CARRIES)
            .chain(STRICT_BORROWS..PAYLOAD)
        {
            let mut forged = bank;
            forged[POOL[offset]] = F(2);
            assert!(residuals(&forged, 12, 18).iter().any(|r| *r != F::ZERO));
        }
    }

    #[test]
    fn original_workspace_mapping_is_disjoint_and_zero_branch_work_is_canonical() {
        let mut physical = POOL.to_vec();
        physical.sort_unstable();
        physical.dedup();
        assert_eq!(physical.len(), 479);
        assert_eq!((PAYLOAD, WIDTH, CONSTRAINTS), (464, 758, 569));
        assert_eq!(
            (POOL[0], POOL[463], POOL[464], POOL[478]),
            (132, 724, 725, 739)
        );
        for left in [0, 1, u64::MAX, 1 << 63] {
            let mut bank = [F::ZERO; WIDTH];
            fill(&mut bank, left, 0);
            assert_eq!(
                word_value(&bank, RESULT),
                u64::cast_signed(left).unsigned_abs()
            );
            assert!(residuals(&bank, left, 0).iter().all(|r| *r == F::ZERO));
            for logical in (NORMAL_A..MAGNITUDE_BORROWS).chain(PRODUCT_CARRIES..PAYLOAD) {
                assert_eq!(value(&bank, logical), F::ZERO);
                let mut forged = bank;
                forged[POOL[logical]] = F::ONE;
                assert!(residuals(&forged, left, 0).iter().any(|r| *r != F::ZERO));
            }
        }
    }
}
