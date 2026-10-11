//! Total predicates shared by authenticated object relations.

use ff::{Field, PrimeField};
use iroha_pasta::Fp;
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{Bit, GlueChip, UintChip, Word};

pub fn all(
    glue: &mut GlueChip<Fp>,
    region: &mut Region<'_, Fp>,
    bits: &[Bit<Fp>],
) -> Result<Bit<Fp>, Error> {
    let one = glue.constant(region, Fp::ONE)?;
    let mut result = glue.assert_bool(region, &one)?;
    for bit in bits {
        result = glue.and(region, &result, bit)?;
    }
    Ok(result)
}

pub fn nonzero(
    glue: &mut GlueChip<Fp>,
    region: &mut Region<'_, Fp>,
    words: &[Word<Fp>],
) -> Result<Bit<Fp>, Error> {
    let zeroes = words
        .iter()
        .map(|word| glue.is_zero(region, word))
        .collect::<Result<Vec<_>, _>>()?;
    let zero = all(glue, region, &zeroes)?;
    glue.not(region, &zero)
}

pub fn equal(
    glue: &mut GlueChip<Fp>,
    region: &mut Region<'_, Fp>,
    a: &[Word<Fp>],
    b: &[Word<Fp>],
) -> Result<Bit<Fp>, Error> {
    if a.len() != b.len() {
        return Err(Error::Synthesis);
    }
    let bits = a
        .iter()
        .zip(b)
        .map(|(a, b)| glue.is_equal(region, a, b))
        .collect::<Result<Vec<_>, _>>()?;
    all(glue, region, &bits)
}

pub fn is_constant(
    glue: &mut GlueChip<Fp>,
    region: &mut Region<'_, Fp>,
    word: &Word<Fp>,
    expected: u64,
) -> Result<Bit<Fp>, Error> {
    let constant = glue.constant(region, Fp::from(expected))?;
    glue.is_equal(region, word, &constant)
}

pub fn implies(
    glue: &mut GlueChip<Fp>,
    region: &mut Region<'_, Fp>,
    premise: &Bit<Fp>,
    conclusion: &Bit<Fp>,
) -> Result<Bit<Fp>, Error> {
    let failure = glue.not(region, conclusion)?;
    let failed = glue.and(region, premise, &failure)?;
    glue.not(region, &failed)
}

pub fn bits32(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    word: &Word<Fp>,
) -> Result<Vec<Bit<Fp>>, Error> {
    let integer = uint.range_check::<32>(region, word)?;
    let bits = (0..32)
        .map(|i| {
            uint.glue()
                .boolean(region, integer.value().map(|v| (v >> i) & 1 == 1))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let terms: Vec<_> = bits
        .iter()
        .enumerate()
        .map(|(i, bit)| (Fp::from(1_u64 << i), bit.word()))
        .collect();
    let mut composed = uint.glue().constant(region, Fp::ZERO)?;
    for chunk in terms.chunks(2) {
        let mut row = vec![(Fp::ONE, &composed)];
        row.extend_from_slice(chunk);
        composed = uint.glue().linear(region, &row, Fp::ZERO)?;
    }
    GlueChip::assert_equal(region, word, &composed)?;
    Ok(bits)
}

pub fn le64(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    a: &Word<Fp>,
    b: &Word<Fp>,
) -> Result<Bit<Fp>, Error> {
    let a = uint.range_check::<64>(region, a)?;
    let b = uint.range_check::<64>(region, b)?;
    let greater = uint.lt(region, &b, &a)?;
    uint.glue().not(region, &greater)
}

/// Total u128 addition predicate with exact carry; no field alias can hide overflow.
pub fn sum_fits128(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    a: &Word<Fp>,
    b: &Word<Fp>,
) -> Result<Bit<Fp>, Error> {
    let a = uint.range_check::<128>(region, a)?;
    let b = uint.range_check::<128>(region, b)?;
    let result = a.value().zip(b.value()).map(|(a, b)| a.overflowing_add(b));
    let lo = uint.assign::<128>(region, result.map(|(lo, _)| lo))?;
    let carry = uint
        .glue()
        .boolean(region, result.map(|(_, carry)| carry))?;
    let sum = uint.glue().add(region, a.word(), b.word())?;
    let joined = uint.glue().linear(
        region,
        &[
            (Fp::ONE, lo.word()),
            (Fp::from_u128(1 << 127).double(), carry.word()),
        ],
        Fp::ZERO,
    )?;
    GlueChip::assert_equal(region, &sum, &joined)?;
    uint.glue().not(region, &carry)
}
