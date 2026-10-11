//! Exact native compressed BLS point encoding, bound to canonical curve cells.
//!
//! Native W3f/ark-bls12-381 encodes big-endian x, with compression/infinity/sign
//! in the first byte. G2 writes x.c1 before x.c0 and chooses the lexicographically
//! larger y, comparing c1 first. This sign is different from hash-to-curve parity.
//! These methods reject infinity but do not prove subgroup membership. Consumers
//! must additionally prove the fixed subgroup relation before accepting a key or
//! signature; serialization alone confers no signature verification authority.

use iroha_pasta::PastaField;
use iroha_plonk::frontend::{Error, Region};

use super::{
    curve::{G1Value, G2Value},
    field::{Bls381Chip, Bls381Value},
    native,
};
use crate::{Bit, GlueChip, Word};

impl<F: PastaField> Bls381Chip<'_, F> {
    /// Exact integer comparison of two canonical BLS base-field elements.
    ///
    /// # Errors
    /// Returns layout errors. Six ranged borrow equations uniquely determine
    /// the final borrow; no comparison result is accepted from the host.
    pub fn less_bls_fp(
        &mut self,
        region: &mut Region<'_, F>,
        a: &Bls381Value<F>,
        b: &Bls381Value<F>,
    ) -> Result<Bit<F>, Error> {
        let witness = a
            .value()
            .zip(b.value())
            .map(|(a, b)| native::subtract_words(&a, &b).1);
        let zero = self.glue().constant(region, F::ZERO)?;
        let mut previous = Bit::new(zero);
        for i in 0..6 {
            let next = self
                .glue()
                .boolean(region, witness.map(|borrows| borrows[i] == 1))?;
            let difference = self.glue().linear(
                region,
                &[
                    (F::ONE, &a.limbs()[i]),
                    (-F::ONE, &b.limbs()[i]),
                    (-F::ONE, previous.word()),
                ],
                F::ZERO,
            )?;
            let remainder = self.glue().linear(
                region,
                &[
                    (F::ONE, &difference),
                    (F::from_u128(1_u128 << 64), next.word()),
                ],
                F::ZERO,
            )?;
            self.range().range_check(region, &remainder, 64)?;
            previous = next;
        }
        Ok(previous)
    }

    /// Canonical 48-byte nonidentity compressed G1 encoding used by native W3f.
    ///
    /// # Errors
    /// Returns layout errors; identity points have no satisfying witness.
    pub fn compressed_g1(
        &mut self,
        region: &mut Region<'_, F>,
        point: &G1Value<F>,
    ) -> Result<[Word<F>; 48], Error> {
        self.assert_nonidentity_g1(region, point)?;
        let negative = self.neg(region, point.y())?;
        let sign = self.less_bls_fp(region, &negative, point.y())?;
        self.compressed_coordinate(region, point.x(), Some(&sign))
    }

    /// Canonical 96-byte nonidentity compressed G2 encoding, c1 before c0.
    ///
    /// # Errors
    /// Returns layout errors; identity points have no satisfying witness.
    pub fn compressed_g2(
        &mut self,
        region: &mut Region<'_, F>,
        point: &G2Value<F>,
    ) -> Result<[Word<F>; 96], Error> {
        self.assert_nonidentity_g2(region, point)?;
        let [y0, y1] = point.y().coefficients();
        let negative0 = self.neg(region, y0)?;
        let negative1 = self.neg(region, y1)?;
        let sign0 = self.less_bls_fp(region, &negative0, y0)?;
        let sign1 = self.less_bls_fp(region, &negative1, y1)?;
        // y1 == -y1 precisely when y1 == 0, since the modulus is odd.
        let first_zero = self.is_zero(region, y1)?;
        let sign = Bit::new(
            self.glue()
                .select(region, &first_zero, sign0.word(), sign1.word())?,
        );
        let c1 = self.compressed_coordinate(region, &point.x().coefficients()[1], Some(&sign))?;
        let c0 = self.compressed_coordinate(region, &point.x().coefficients()[0], None)?;
        Ok(core::array::from_fn(|i| {
            if i < 48 {
                c1[i].clone()
            } else {
                c0[i - 48].clone()
            }
        }))
    }

    fn compressed_coordinate(
        &mut self,
        region: &mut Region<'_, F>,
        x: &Bls381Value<F>,
        sign: Option<&Bit<F>>,
    ) -> Result<[Word<F>; 48], Error> {
        let mut bytes = Vec::with_capacity(48);
        for limb in (0..6).rev() {
            let mut packed = self.glue().constant(region, F::ZERO)?;
            for offset in (0..8).rev() {
                let byte = self.range().witness_range_checked(
                    region,
                    x.value()
                        .map(|words| F::from((words[limb] >> (8 * offset)) & 255)),
                    if limb == 5 && offset == 7 { 5 } else { 8 },
                )?;
                packed = self.glue().linear(
                    region,
                    &[(F::from(256), &packed), (F::ONE, &byte)],
                    F::ZERO,
                )?;
                bytes.push(byte);
            }
            GlueChip::assert_equal(region, &packed, &x.limbs()[limb])?;
        }
        if let Some(sign) = sign {
            bytes[0] = self.glue().linear(
                region,
                &[(F::ONE, &bytes[0]), (F::from(32), sign.word())],
                F::from(128),
            )?;
        }
        bytes.try_into().map_err(|_| Error::Synthesis)
    }
}

#[cfg(test)]
mod tests;
