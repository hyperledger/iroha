//! Canonical BLS12-381 base-field arithmetic over either Pasta field.
//!
//! Write B = 2^64 and p = [`native::MODULUS`]. Every value has six unsigned
//! limbs (the top has 61 bits) and a constrained subtraction from p-1 proving
//! it is below p. No public constructor can bypass these checks.
//!
//! Multiplication assigns canonical r,q and checks all twelve columns of
//! `a*b = r + q*p`: `c_i + sum(a_j*b_k) - sum(q_j*p_k) - r_i = B*c_(i+1)`.
//! Endpoint carries are zero. Each internal carry is represented by
//! `u_i = c_i + 2^68`, with `u_i` range-checked to 69 bits; thus
//! `-16B <= c_i < 16B`. Each product-column sum is below 6B². Consequently
//! the absolute integer discrepancy in any column is below
//! `22B² + 17B < 2^134`, strictly below both Pasta primes (>2^254).
//! The field equations are therefore integer equations, and telescoping
//! yields exact integer division. Canonical r uniquely determines the result.
//! Honest carries satisfy `|c_i| < 7B` inductively: the difference of the two
//! nonnegative product sums has magnitude below 6B², and the previous carry
//! and result limb contribute less than 8B. The chosen interval is complete.
//!
//! Addition checks six analogous columns with a boolean quotient and
//! carries in [-4,4). Their discrepancy is below 8B, also without wrap.
//! Inversion is a canonical witness whose multiplication by the input must
//! equal one. Native routines supply witnesses, never validity predicates.

use iroha_pasta::PastaField;
use iroha_plonk::frontend::{Error, Region, Value};

use super::native::{self, Fp};
use crate::{
    arith::GlueChip,
    cells::{Bit, Word},
    range::RunningSumChip,
};

const RADIX: u128 = 1_u128 << 64;
const CARRY_OFFSET: i128 = 1_i128 << 68;

/// A canonical BLS12-381 base-field element, constrained to `[0,p)`.
#[derive(Clone, Debug)]
pub struct Bls381Value<F: PastaField> {
    limbs: [Word<F>; 6],
}

impl<F: PastaField> Bls381Value<F> {
    /// The six equality-enabled little-endian limb cells.
    #[must_use]
    pub const fn limbs(&self) -> &[Word<F>; 6] {
        &self.limbs
    }

    /// Native witness value, unknown during key generation.
    #[must_use]
    pub fn value(&self) -> Value<Fp> {
        let mut value = Value::known(native::ZERO);
        for (i, limb) in self.limbs.iter().enumerate() {
            value = value.zip(limb.value()).map(|(mut words, limb)| {
                words[i] = limb.to_canonical_limbs()[0];
                words
            });
        }
        value
    }
}

/// A view over an existing glue lane and running-sum range lane.
#[derive(Debug)]
pub struct Bls381Chip<'a, F: PastaField> {
    glue: &'a mut GlueChip<F>,
    range: &'a mut RunningSumChip<F>,
}

impl<'a, F: PastaField> Bls381Chip<'a, F> {
    /// Uses the caller's configured gates and row cursors.
    pub const fn new(glue: &'a mut GlueChip<F>, range: &'a mut RunningSumChip<F>) -> Self {
        Self { glue, range }
    }

    /// The underlying glue lane.
    pub fn glue(&mut self) -> &mut GlueChip<F> {
        self.glue
    }

    /// The underlying range lane.
    pub fn range(&mut self) -> &mut RunningSumChip<F> {
        self.range
    }

    /// Assigns all six limbs and proves the integer is canonical.
    ///
    /// # Errors
    /// Returns a layout error; a noncanonical witness is laid out and rejected
    /// by constraints, not by a host-language validation branch.
    pub fn assign(
        &mut self,
        region: &mut Region<'_, F>,
        value: Value<Fp>,
    ) -> Result<Bls381Value<F>, Error> {
        let mut limbs = Vec::with_capacity(6);
        for i in 0..6 {
            limbs.push(self.range.witness_range_checked(
                region,
                value.map(|words| F::from(words[i])),
                if i == 5 { 61 } else { 64 },
            )?);
        }
        let out = Bls381Value {
            limbs: limbs.try_into().map_err(|_| Error::Synthesis)?,
        };
        let mut maximum = native::MODULUS;
        maximum[0] -= 1;
        let borrows = value.map(|a| native::subtract_words(&maximum, &a).1);
        let mut previous = self.glue.constant(region, F::ZERO)?;
        for i in 0..6 {
            let next = self.glue.boolean(region, borrows.map(|b| b[i] == 1))?;
            let difference = self.glue.linear(
                region,
                &[
                    (-F::ONE, &out.limbs[i]),
                    (-F::ONE, &previous),
                    (F::from_u128(RADIX), next.word()),
                ],
                F::from(maximum[i]),
            )?;
            self.range.range_check(region, &difference, 64)?;
            previous = next.word().clone();
        }
        self.glue.enforce_constant(region, &previous, F::ZERO)?;
        Ok(out)
    }

    /// Pins a canonical circuit-fixed constant; no witness range checks needed.
    ///
    /// # Errors
    /// A noncanonical constant or a layout error.
    pub fn constant(
        &mut self,
        region: &mut Region<'_, F>,
        value: Fp,
    ) -> Result<Bls381Value<F>, Error> {
        if !native::is_canonical(&value) {
            return Err(Error::Synthesis);
        }
        let limbs = value
            .into_iter()
            .map(|limb| self.glue.constant(region, F::from(limb)))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        Ok(Bls381Value { limbs })
    }

    /// Canonical modular sum.
    ///
    /// # Errors
    /// A layout error.
    pub fn add(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Bls381Value<F>,
        b: &Bls381Value<F>,
    ) -> Result<Bls381Value<F>, Error> {
        let witness = a
            .value()
            .zip(b.value())
            .map(|(a, b)| native::add_with_quotient(&a, &b));
        let r = self.assign(region, witness.map(|(r, _)| r))?;
        self.constrain_sum(region, a, b, &r, witness.map(|(_, q)| q))?;
        Ok(r)
    }

    /// Canonical modular difference.
    ///
    /// # Errors
    /// A layout error.
    pub fn sub(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Bls381Value<F>,
        b: &Bls381Value<F>,
    ) -> Result<Bls381Value<F>, Error> {
        let witness = a.value().zip(b.value());
        let r = self.assign(region, witness.map(|(a, b)| native::sub(&a, &b)))?;
        let quotient = witness.map(|(a, b)| native::subtract_words(&a, &b).1[5]);
        // r + b = a + q*p, where q is precisely the original subtraction borrow.
        self.constrain_sum(region, &r, b, a, quotient)?;
        Ok(r)
    }

    fn constrain_sum(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Bls381Value<F>,
        b: &Bls381Value<F>,
        r: &Bls381Value<F>,
        q: Value<u64>,
    ) -> Result<(), Error> {
        let q_bit = self.glue.boolean(region, q.map(|q| q == 1))?;
        let carries = a
            .value()
            .zip(b.value())
            .zip(r.value())
            .zip(q)
            .map(|(((a, b), r), q)| {
                let mut carries = [0_i128; 7];
                for i in 0..6 {
                    carries[i + 1] = (carries[i] + i128::from(a[i]) + i128::from(b[i])
                        - i128::from(r[i])
                        - i128::from(q) * i128::from(native::MODULUS[i]))
                        >> 64;
                }
                carries
            });
        let mut previous = self.glue.constant(region, F::ZERO)?;
        for i in 0..6 {
            let next = self.signed_carry(region, carries.map(|c| c[i + 1]), 4, 3, i == 5)?;
            let left = self.glue.linear(
                region,
                &[
                    (F::ONE, &a.limbs[i]),
                    (F::ONE, &b.limbs[i]),
                    (F::ONE, &previous),
                ],
                F::ZERO,
            )?;
            let right = self.glue.linear(
                region,
                &[
                    (F::ONE, &r.limbs[i]),
                    (F::from(native::MODULUS[i]), q_bit.word()),
                    (F::from_u128(RADIX), &next),
                ],
                F::ZERO,
            )?;
            GlueChip::assert_equal(region, &left, &right)?;
            previous = next;
        }
        Ok(())
    }

    fn signed_carry(
        &mut self,
        region: &mut Region<'_, F>,
        value: Value<i128>,
        offset: i128,
        bits: usize,
        endpoint: bool,
    ) -> Result<Word<F>, Error> {
        if endpoint {
            return self.glue.constant(region, F::ZERO);
        }
        let biased = self.range.witness_range_checked(
            region,
            value.map(|carry| {
                // Honest biased carries are nonnegative. A negative bad witness
                // wraps to at least 2^127 and fails this narrow range constraint.
                F::from_u128((carry + offset).cast_unsigned())
            }),
            bits,
        )?;
        self.glue
            .add_constant(region, &biased, -F::from_u128(offset.cast_unsigned()))
    }

    /// Canonical product, with constrained canonical quotient and signed carries.
    ///
    /// # Errors
    /// A layout error.
    pub fn mul(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Bls381Value<F>,
        b: &Bls381Value<F>,
    ) -> Result<Bls381Value<F>, Error> {
        let inputs = a.value().zip(b.value());
        let witness = inputs.map(|(a, b)| native::mul_with_quotient(&a, &b));
        let r = self.assign(region, witness.map(|(r, _)| r))?;
        let q = self.assign(region, witness.map(|(_, q)| q))?;
        self.constrain_product(region, a, b, &r, &q)?;
        Ok(r)
    }

    fn constrain_product(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Bls381Value<F>,
        b: &Bls381Value<F>,
        remainder: &Bls381Value<F>,
        q: &Bls381Value<F>,
    ) -> Result<(), Error> {
        let carries = a
            .value()
            .zip(b.value())
            .zip(remainder.value())
            .zip(q.value())
            .map(|(((a, b), remainder), q)| native::multiplication_carries(&a, &b, &remainder, &q));
        let mut previous = self.glue.constant(region, F::ZERO)?;
        for column in 0..12 {
            let mut left = previous;
            let mut right = if column < 6 {
                remainder.limbs[column].clone()
            } else {
                self.glue.constant(region, F::ZERO)?
            };
            for i in 0..6 {
                if column >= i && column - i < 6 {
                    let j = column - i;
                    left = self.glue.mul_add(region, &a.limbs[i], &b.limbs[j], &left)?;
                    right = self.glue.linear(
                        region,
                        &[(F::from(native::MODULUS[j]), &q.limbs[i]), (F::ONE, &right)],
                        F::ZERO,
                    )?;
                }
            }
            let next = self.signed_carry(
                region,
                carries.map(|c| c[column + 1]),
                CARRY_OFFSET,
                69,
                column == 11,
            )?;
            right = self.glue.linear(
                region,
                &[(F::ONE, &right), (F::from_u128(RADIX), &next)],
                F::ZERO,
            )?;
            GlueChip::assert_equal(region, &left, &right)?;
            previous = next;
        }
        Ok(())
    }

    /// Canonical square.
    ///
    /// # Errors
    /// A layout error.
    pub fn square(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Bls381Value<F>,
    ) -> Result<Bls381Value<F>, Error> {
        self.mul(region, a, a)
    }

    /// Reduce an assigned 512-bit integer, supplied as eight little-endian words.
    /// Every source word is range-checked to 64 bits; canonical r,q and twelve
    /// signed carry equations enforce `n = r + q*p`. The multiplication carry
    /// bounds above also cover these smaller columns. An honest quotient is
    /// below 2^132, hence below p, so canonical quotient checks are complete.
    /// This is suitable for the 64-byte `hash_to_field` input of BLS12-381.
    ///
    /// # Errors
    /// A layout error. Oversized source words yield unsatisfied constraints.
    pub fn reduce_words(
        &mut self,
        region: &mut Region<'_, F>,
        words: &[Word<F>; 8],
    ) -> Result<Bls381Value<F>, Error> {
        let mut integer = Value::known([0_u64; 8]);
        for (i, word) in words.iter().enumerate() {
            self.range.range_check(region, word, 64)?;
            integer = integer.zip(word.value()).map(|(mut n, word)| {
                n[i] = word.to_canonical_limbs()[0];
                n
            });
        }
        let division = integer.map(|n| {
            let mut wide = [0; 12];
            wide[..8].copy_from_slice(&n);
            let (q, r) = native::reduce(&wide);
            (r, core::array::from_fn(|i| q[i]))
        });
        let r = self.assign(region, division.map(|(r, _)| r))?;
        let q = self.assign(region, division.map(|(_, q)| q))?;
        let carries = integer
            .zip(division)
            .map(|(n, (r, q))| native::reduction_carries(&n, &r, &q));
        let mut previous = self.glue.constant(region, F::ZERO)?;
        for column in 0..12 {
            let left = if column < 8 {
                self.glue.add(region, &previous, &words[column])?
            } else {
                previous
            };
            let mut right = if column < 6 {
                r.limbs[column].clone()
            } else {
                self.glue.constant(region, F::ZERO)?
            };
            for i in 0..6 {
                if column >= i && column - i < 6 {
                    right = self.glue.linear(
                        region,
                        &[
                            (F::from(native::MODULUS[column - i]), &q.limbs[i]),
                            (F::ONE, &right),
                        ],
                        F::ZERO,
                    )?;
                }
            }
            let next = self.signed_carry(
                region,
                carries.map(|c| c[column + 1]),
                CARRY_OFFSET,
                69,
                column == 11,
            )?;
            right = self.glue.linear(
                region,
                &[(F::ONE, &right), (F::from_u128(RADIX), &next)],
                F::ZERO,
            )?;
            GlueChip::assert_equal(region, &left, &right)?;
            previous = next;
        }
        Ok(r)
    }

    /// Canonical additive inverse.
    ///
    /// # Errors
    /// A layout error.
    pub fn neg(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Bls381Value<F>,
    ) -> Result<Bls381Value<F>, Error> {
        let zero = self.constant(region, native::ZERO)?;
        self.sub(region, &zero, a)
    }

    /// Multiplicative inverse; a zero input makes the constraints unsatisfiable.
    ///
    /// # Errors
    /// A layout error.
    pub fn invert(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Bls381Value<F>,
    ) -> Result<Bls381Value<F>, Error> {
        let inverse = self.assign(region, a.value().map(|a| native::invert(&a)))?;
        let product = self.mul(region, a, &inverse)?;
        let one = self.constant(region, native::ONE)?;
        Self::assert_equal(region, &product, &one)?;
        Ok(inverse)
    }

    /// Selects `a` for a true bit, otherwise `b`; canonicality follows from
    /// the boolean selection of already canonical operands.
    ///
    /// # Errors
    /// A layout error.
    pub fn select(
        &mut self,
        region: &mut Region<'_, F>,
        bit: &Bit<F>,
        a: &Bls381Value<F>,
        b: &Bls381Value<F>,
    ) -> Result<Bls381Value<F>, Error> {
        let limbs = a
            .limbs
            .iter()
            .zip(&b.limbs)
            .map(|(a, b)| self.glue.select(region, bit, a, b))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        Ok(Bls381Value { limbs })
    }

    /// Exact zero test, with the boolean result constrained in both directions.
    ///
    /// # Errors
    /// A layout error.
    pub fn is_zero(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Bls381Value<F>,
    ) -> Result<Bit<F>, Error> {
        // Sum < 6*2^64 < Pasta modulus; it is zero exactly when all limbs are.
        let mut sum = a.limbs[0].clone();
        for limb in &a.limbs[1..] {
            sum = self.glue.add(region, &sum, limb)?;
        }
        self.glue.is_zero(region, &sum)
    }

    /// Exact equality test of two canonical elements.
    ///
    /// # Errors
    /// A layout error.
    pub fn is_equal(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Bls381Value<F>,
        b: &Bls381Value<F>,
    ) -> Result<Bit<F>, Error> {
        let difference = self.sub(region, a, b)?;
        self.is_zero(region, &difference)
    }

    /// Enforces equality of every limb.
    ///
    /// # Errors
    /// A copy-constraint error.
    pub fn assert_equal(
        region: &mut Region<'_, F>,
        a: &Bls381Value<F>,
        b: &Bls381Value<F>,
    ) -> Result<(), Error> {
        for (a, b) in a.limbs.iter().zip(&b.limbs) {
            GlueChip::assert_equal(region, a, b)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
