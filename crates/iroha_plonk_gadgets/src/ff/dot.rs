//! Fixed batches of one to eight unsigned Proper foreign products.
//!
//! For B=2^87 and operands below2^256, S=sum(a*b)<2^515 and the explicitly
//! admitted modulus m>2^254 gives q=floor(S/m)<2^261. Four low carry equations and the
//! native residue constrain S=c+qm with the existing87/87/82 result,3x87
//! quotient and four105-bit offset-carry certificates. Honest low-column
//! magnitudes are below28B^2 and carries below29B<2^92. Even adversarial
//! admitted carries make each local residual smaller than2^194, below the
//! native prime; the global residual is below2^518 while B^4*p>2^602.
//! Thus CRT uniqueness proves integer equality. The result is Proper, not
//! Canonical. The staged compact kernel separately admits three carries when
//! 2^254<m<2^255 and every input is Canonical or has exact87/87/81 Proper
//! bounds. Then S<2^513, q<2^259 and result<2^255; offset92/range93 carries
//! give local residuals<2^180 and global residual<2^515<B^3*p. Its fixed
//! selector is chosen from proved metadata only. Signed or lazy batches are
//! deliberately outside either API.

use super::{
    CARRIES, CARRY_OFFSET_BITS, FfValue, ForeignModulus, Form, FusedWitness, LIMB_BITS, LIMBS, Nat,
    PROPER_BOUNDS, TOP_LIMB_BITS, fused_witness_fields, nat_limbs, recompose_nat,
    serialized::{ranged, recompose},
};
use crate::{
    GlueChip,
    arith::{Coefficients, Slot},
    range::RunningSumChip,
};
use iroha_pasta::PastaField;
use iroha_plonk::frontend::{Error, Region, Value};

/// Largest unsigned Proper batch covered by this exact quotient envelope.
pub const MAX_PRODUCTS: usize = 8;

/// Shared-range lowering of the fixed unsigned dot-product CRT predicate.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnsignedDot;
impl UnsignedDot {
    /// Proves the sum of one to eight products modulo the common modulus.
    /// All inputs must already have proven Proper or Canonical limb bounds,
    /// and the modulus must be strictly greater than2^254.
    ///
    /// # Errors
    /// Empty/oversized batch, modulus at most2^254, mixed moduli,
    /// non-Proper input, or layout error.
    pub fn evaluate<F: PastaField>(
        glue: &mut GlueChip<F>,
        range: &mut RunningSumChip<F>,
        region: &mut Region<'_, F>,
        pairs: &[(&FfValue<F>, &FfValue<F>)],
    ) -> Result<FfValue<F>, Error> {
        let modulus = admitted(pairs)?;
        let values = pairs
            .iter()
            .fold(Value::known(Vec::new()), |values, (a, b)| {
                values
                    .zip(a.limb_values())
                    .zip(b.limb_values())
                    .map(|((mut values, a), b)| {
                        values.push((a, b));
                        values
                    })
            });
        constrain(
            glue,
            range,
            region,
            pairs,
            values.map(|values| witness(modulus, &values)),
        )
    }
}
pub(super) fn admitted<F: PastaField>(
    pairs: &[(&FfValue<F>, &FfValue<F>)],
) -> Result<ForeignModulus, Error> {
    let modulus = pairs.first().ok_or(Error::Synthesis)?.0.modulus;
    if pairs.len() > MAX_PRODUCTS
        || !modulus.nat().cmp_vartime(&Nat::pow2(254)).is_gt()
        || pairs.iter().flat_map(|(a, b)| [a, b]).any(|v| {
            v.modulus != modulus
                || !matches!(v.form, Form::Proper | Form::Canonical)
                || v.bounds
                    .iter()
                    .zip(PROPER_BOUNDS)
                    .any(|(bound, max)| *bound > max)
        })
    {
        return Err(Error::Synthesis);
    }
    Ok(modulus)
}

/// A stronger three-carry envelope, checked only after `admitted`. Canonical
/// form proves the integer comparison, while Proper form must carry its exact
/// narrower limb bounds. No witness value selects this route.
pub(super) fn narrow<F: PastaField>(pairs: &[(&FfValue<F>, &FfValue<F>)]) -> bool {
    let Some((first, _)) = pairs.first() else {
        return false;
    };
    first.modulus.nat().cmp_vartime(&Nat::pow2(255)).is_lt()
        && pairs
            .iter()
            .flat_map(|(left, right)| [left, right])
            .all(|value| {
                value.form == Form::Canonical
                    || (value.form == Form::Proper
                        && value
                            .bounds
                            .iter()
                            .zip(super::NARROW_PROPER_BOUNDS)
                            .all(|(bound, maximum)| *bound <= maximum))
            })
}
pub(super) fn witness<F: PastaField>(
    modulus: ForeignModulus,
    pairs: &[([Nat; LIMBS], [Nat; LIMBS])],
) -> FusedWitness<F> {
    let sum = pairs.iter().fold(Nat::ZERO, |sum, (a, b)| {
        sum.wrapping_add(&recompose_nat(a).wrapping_mul(&recompose_nat(b)))
    });
    let (q, c) = sum
        .div_rem(&modulus.nat())
        .expect("nonzero supported modulus");
    let (q, c) = (nat_limbs(&q), nat_limbs(&c));
    let m = modulus.limbs();
    let mut carry = Nat::ZERO;
    let carries = core::array::from_fn(|column| {
        let mut value = carry;
        for i in 0..LIMBS {
            if let Some(j) = column.checked_sub(i).filter(|j| *j < LIMBS) {
                for (a, b) in pairs {
                    value = value.wrapping_add(&a[i].wrapping_mul(&b[j]));
                }
                value = value.wrapping_sub(&q[i].wrapping_mul(&Nat::from_u128(m[j])));
            }
        }
        if column < LIMBS {
            value = value.wrapping_sub(&c[column]);
        }
        carry = value.sar(LIMB_BITS);
        carry
    });
    fused_witness_fields(&c, &q, &carries)
}
#[allow(clippy::many_single_char_names)]
fn constrain<F: PastaField>(
    glue: &mut GlueChip<F>,
    range: &mut RunningSumChip<F>,
    region: &mut Region<'_, F>,
    pairs: &[(&FfValue<F>, &FfValue<F>)],
    witness: Value<FusedWitness<F>>,
) -> Result<FfValue<F>, Error> {
    let modulus = admitted(pairs)?;
    let result = ranged(
        range,
        region,
        witness.map(|w| w.c),
        [LIMB_BITS, LIMB_BITS, TOP_LIMB_BITS],
    )?;
    let quotient = ranged(range, region, witness.map(|w| w.q), [LIMB_BITS; LIMBS])?;
    let carries = ranged(
        range,
        region,
        witness.map(|w| w.u),
        [CARRY_OFFSET_BITS + 1; CARRIES],
    )?;
    let m = modulus.limbs();
    let radix = F::from_u128(1 << LIMB_BITS);
    let offset = F::from_u128(1 << CARRY_OFFSET_BITS);
    for column in 0..CARRIES {
        let mut terms = Vec::new();
        for (i, q) in quotient.iter().enumerate() {
            if let Some(j) = column.checked_sub(i).filter(|j| *j < LIMBS) {
                terms.push((-F::from_u128(m[j]), q));
            }
        }
        if column < LIMBS {
            terms.push((-F::ONE, &result[column]));
        }
        if column > 0 {
            terms.push((F::ONE, &carries[column - 1]));
        }
        let (first, rest) = terms.split_at(terms.len().min(3));
        let mut sum = glue.linear(region, first, if column > 0 { -offset } else { F::ZERO })?;
        for chunk in rest.chunks(2) {
            let mut terms = vec![(F::ONE, &sum)];
            terms.extend_from_slice(chunk);
            sum = glue.linear(region, &terms, F::ZERO)?;
        }
        let products: Vec<_> = pairs
            .iter()
            .flat_map(|(a, b)| {
                (0..LIMBS).filter_map(move |i| {
                    column
                        .checked_sub(i)
                        .filter(|j| *j < LIMBS)
                        .map(|j| (&a.limbs[i], &b.limbs[j]))
                })
            })
            .collect();
        for (index, (a, b)) in products.iter().enumerate() {
            if index + 1 == products.len() {
                glue.row(
                    region,
                    Coefficients {
                        m: F::ONE,
                        c: F::ONE,
                        d: -radix,
                        k: offset * radix,
                        ..Coefficients::zero()
                    },
                    [
                        Slot::Copy(a),
                        Slot::Copy(b),
                        Slot::Copy(&sum),
                        Slot::Copy(&carries[column]),
                    ],
                    None,
                )?;
            } else {
                sum = glue.mul_add(region, a, b, &sum)?;
            }
        }
    }
    let c = recompose(glue, region, &result)?;
    let q = recompose(glue, region, &quotient)?;
    let mut sum = glue.linear(
        region,
        &[(-F::ONE, &c), (-modulus.nat().to_field::<F>(), &q)],
        F::ZERO,
    )?;
    for (index, (a, b)) in pairs.iter().enumerate() {
        let a = recompose(glue, region, &a.limbs)?;
        let b = recompose(glue, region, &b.limbs)?;
        if index + 1 == pairs.len() {
            glue.row(
                region,
                Coefficients {
                    m: F::ONE,
                    c: F::ONE,
                    ..Coefficients::zero()
                },
                [
                    Slot::Copy(&a),
                    Slot::Copy(&b),
                    Slot::Copy(&sum),
                    Slot::Empty,
                ],
                None,
            )?;
        } else {
            sum = glue.mul_add(region, &a, &b, &sum)?;
        }
    }
    Ok(FfValue::from_parts(
        result,
        PROPER_BOUNDS,
        modulus,
        Form::Proper,
    ))
}

#[cfg(test)]
mod tests;
