//! Exact unsigned reduction of an already bounded three-limb integer.
//!
//! With B=2^87, each input limb below2^94 gives x<2^269. The admitted
//! modulus is in[2^252,2^256), hence q=floor(x/m)<2^17. We range c at
//! 87/87/81 or82 bits, q at17 bits and u+2^17 at18 bits, and constrain
//! x0-c0-q*m0=B*u plus x-c-q*m=0 in the native field. The local residual
//! is below2^106<N; the complete residual is below2^274<B*N. The two
//! coprime congruences therefore imply exact integer equality. Honest u is
//! in(-2^17,128). Output remains Proper: comparison with m is separate.

use super::{
    FfValue, Form, LIMB_BITS, LIMBS, NARROW_PROPER_BOUNDS, Nat, PROPER_BOUNDS, limb_fields,
    serialized::{constrain_linear, ranged, recompose},
    within_envelope,
};
use crate::{GlueChip, range::RunningSumChip};
use iroha_pasta::PastaField;
use iroha_plonk::frontend::{Error, Region, Value};

#[cfg(test)]
mod tests;

#[derive(Clone, Copy)]
struct Witness<F> {
    result: [F; LIMBS],
    quotient: F,
    carry: F,
}

fn witness<F: PastaField>(value: &FfValue<F>) -> Value<Witness<F>> {
    value
        .limb_values()
        .zip(value.integer())
        .map(|(limbs, integer)| {
            let (quotient, result) = integer
                .div_rem(&value.modulus.nat())
                .expect("nonzero modulus");
            let carry = limbs[0]
                .wrapping_sub(&Nat::from_u128(result.low_bits_u128(LIMB_BITS)))
                .wrapping_sub(&quotient.wrapping_mul(&Nat::from_u128(value.modulus.limbs()[0])))
                .sar(LIMB_BITS);
            Witness {
                result: limb_fields(&result),
                quotient: quotient.to_field(),
                carry: carry.wrapping_add(&Nat::pow2(17)).to_field_signed(),
            }
        })
}

pub(super) fn reduce<F: PastaField>(
    glue: &mut GlueChip<F>,
    range: &mut RunningSumChip<F>,
    region: &mut Region<'_, F>,
    value: &FfValue<F>,
) -> Result<FfValue<F>, Error> {
    constrain(glue, range, region, value, witness(value))
}

fn constrain<F: PastaField>(
    glue: &mut GlueChip<F>,
    range: &mut RunningSumChip<F>,
    region: &mut Region<'_, F>,
    value: &FfValue<F>,
    witness: Value<Witness<F>>,
) -> Result<FfValue<F>, Error> {
    if !within_envelope(&value.bounds)
        || value.modulus.nat().cmp_vartime(&Nat::pow2(252)).is_lt()
        || !value.modulus.nat().cmp_vartime(&Nat::pow2(256)).is_lt()
    {
        return Err(Error::Synthesis);
    }
    let bounds = if value.modulus.nat().cmp_vartime(&Nat::pow2(255)).is_lt() {
        NARROW_PROPER_BOUNDS
    } else {
        PROPER_BOUNDS
    };
    let result = ranged(
        range,
        region,
        witness.map(|w| w.result),
        [LIMB_BITS, LIMB_BITS, bounds[2].ilog2() as usize + 1],
    )?;
    let [quotient] = ranged(range, region, witness.map(|w| [w.quotient]), [17])?;
    let [carry] = ranged(range, region, witness.map(|w| [w.carry]), [18])?;
    let radix = F::from_u128(1 << LIMB_BITS);
    constrain_linear(
        glue,
        region,
        [
            (F::ONE, &value.limbs[0]),
            (-F::ONE, &result[0]),
            (-F::from_u128(value.modulus.limbs()[0]), &quotient),
            (-radix, &carry),
        ],
        radix * F::from(1 << 17),
    )?;
    let input = recompose(glue, region, &value.limbs)?;
    let output = recompose(glue, region, &result)?;
    constrain_linear(
        glue,
        region,
        [
            (F::ONE, &input),
            (-F::ONE, &output),
            (-value.modulus.nat().to_field::<F>(), &quotient),
        ],
        F::ZERO,
    )?;
    Ok(FfValue::from_parts(
        result,
        bounds,
        value.modulus,
        Form::Proper,
    ))
}
