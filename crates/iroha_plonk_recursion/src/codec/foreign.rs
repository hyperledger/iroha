//! Total Vesta accumulator decoding in A's Fp circuit.
//!
//! Fq arithmetic proves either a square root of x³+5 or a square root of
//! 5(x³+5), with 5 a pinned nonsquare. Canonical limbs, both square equations
//! and the chosen sign bind the verdict to the original compressed bytes;
//! a malicious root witness cannot manufacture a burn for a valid point.

use crate::{K, VESTA_TRIVIAL_GENERATOR, codec::ScalarCells, verifier::VerifierChip};
use ff::Field;
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaAffine};
use iroha_plonk::{
    frontend::{Error, Region, Value},
    transcript::decode_point,
};
use iroha_plonk_gadgets::{
    Bit, GlueChip, Uint, UintChip, Word,
    bytes::element::{LeElement, element_value, le_max, modulus_max, scalar_bytes_canonical},
    statement::foreign_limbs,
};

/// A canonical finite Vesta point represented by Fq limbs in Fp.
#[derive(Clone, Debug)]
pub struct ForeignVestaPoint {
    /// Canonical x and y; malformed bytes select the fixed point (-1,2).
    pub coordinates: [ScalarCells<Ep>; 2],
    /// Exactly the native finite PIPA point decoder's verdict.
    pub valid: Bit<Fp>,
}

/// Total transported Vesta accumulator result, with pinned deciding dummy.
#[must_use = "include valid in the incoming soft predicate before choosing its mode"]
#[derive(Clone, Debug)]
pub struct ForeignVestaAccumulator {
    /// Canonical finite x/y; invalid accumulators select the pinned trivial point.
    pub coordinates: [ScalarCells<Ep>; 2],
    /// Nonzero Fp challenges; invalid accumulators select sixteen ones.
    pub challenges: [Word<Fp>; K],
    /// Exact length, finite point and canonical nonzero scalar verdict.
    pub valid: Bit<Fp>,
}

fn witness_scalar(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    value: Value<Fq>,
) -> Result<ScalarCells<Ep>, Error> {
    let lo = chip
        .uint()
        .assign::<128>(region, value.map(|v| foreign_limbs(&v)[0]))?;
    let hi = chip
        .uint()
        .assign::<127>(region, value.map(|v| foreign_limbs(&v)[1]))?;
    ScalarCells::from_limbs(&mut chip.uint(), region, &lo, &hi)
}
fn parity(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    value: &ScalarCells<Ep>,
) -> Result<Bit<Fp>, Error> {
    let low = value.lo();
    let bit = chip
        .uint()
        .glue()
        .boolean(region, low.value().map(|v| v & 1 != 0))?;
    let half = chip
        .uint()
        .assign::<127>(region, low.value().map(|v| v >> 1))?;
    let composed = chip.uint().glue().linear(
        region,
        &[(Fp::ONE, bit.word()), (Fp::from(2), half.word())],
        Fp::ZERO,
    )?;
    GlueChip::assert_equal(region, &composed, low.word())?;
    Ok(bit)
}

impl VerifierChip<Ep> {
    /// Totally decodes a compressed Vesta point using constrained Fq arithmetic.
    /// Its boolean square/nonsquare witness is forced by the two disjoint
    /// equations; rejected x encodings never enter foreign arithmetic unchecked.
    ///
    /// # Errors
    /// Layout failure. Every fixed-size byte value has a satisfying output.
    pub fn decode_vesta_point_soft(
        &mut self,
        region: &mut Region<'_, Fp>,
        message: &LeElement<Fp>,
    ) -> Result<ForeignVestaPoint, Error> {
        let canonical = le_max(
            &mut self.uint(),
            region,
            message.lo(),
            &UintChip::widen::<127, 128>(message.hi()),
            modulus_max::<Fq>(),
        )?;
        let lo = self
            .glue
            .select_constant(region, &canonical, message.lo().word(), Fp::ZERO)?;
        let hi = self
            .glue
            .select_constant(region, &canonical, message.hi().word(), Fp::ZERO)?;
        let lo = self.uint().range_check::<128>(region, &lo)?;
        let hi = self.uint().range_check::<127>(region, &hi)?;
        let x = ScalarCells::from_limbs(&mut self.uint(), region, &lo, &hi)?;
        let x = self.import(region, &x)?;
        let x2 = self.mul(region, &x, &x)?;
        let x3 = self.mul(region, &x2, &x)?;
        let five = self.constant(region, Fq::from(5))?;
        let rhs = self.add(region, &x3, &five)?;
        let native = rhs
            .integer()
            .map(iroha_plonk_gadgets::ff::Nat::to_field::<Fq>);
        let square = self
            .glue
            .boolean(region, native.map(|v| bool::from(v.sqrt().is_some())))?;
        let root = witness_scalar(
            self,
            region,
            native.map(|v| {
                Option::<Fq>::from(v.sqrt())
                    .or_else(|| Option::from((v * Fq::from(5)).sqrt()))
                    .unwrap_or(Fq::ZERO)
            }),
        )?;
        let root_ff = self.import(region, &root)?;
        let root2 = self.mul(region, &root_ff, &root_ff)?;
        let nonsquare_rhs = self.mul(region, &rhs, &five)?;
        let expected = self.arithmetic.select(
            &mut UintChip::new(&mut self.glue, &mut self.range),
            region,
            &square,
            &rhs,
            &nonsquare_rhs,
        )?;
        let equal = self.arithmetic.equal(
            &mut UintChip::new(&mut self.glue, &mut self.range),
            region,
            &root2,
            &expected,
        )?;
        GlueChip::assert_constant(region, equal.word(), Fp::ONE)?;
        let nonzero = self.nonzero(region, &rhs)?;
        let zero = self.glue.not(region, &nonzero)?;
        let not_square = self.glue.not(region, &square)?;
        let impossible = self.glue.and(region, &zero, &not_square)?;
        GlueChip::assert_constant(region, impossible.word(), Fp::ZERO)?;
        let root_parity = parity(self, region, &root)?;
        let same = self
            .glue
            .is_equal(region, root_parity.word(), message.top().word())?;
        let negative = self.neg(region, &root_ff)?;
        let y = self.arithmetic.select(
            &mut UintChip::new(&mut self.glue, &mut self.range),
            region,
            &same,
            &root_ff,
            &negative,
        )?;
        let y_cells = self.export(region, &y)?;
        let actual_sign = parity(self, region, &y_cells)?;
        let sign_matches = self
            .glue
            .is_equal(region, actual_sign.word(), message.top().word())?;
        let mut valid = self.glue.and(region, &canonical, &square)?;
        valid = self.glue.and(region, &valid, &sign_matches)?;
        // The identity's all-zero encoding has x=0; x^3+5 is the nonsquare5,
        // so square=false already rejects both identity and signed zero.
        let dummy_x = self.constant(region, -Fq::ONE)?;
        let dummy_y = self.constant(region, Fq::from(2))?;
        let safe_x = self.arithmetic.select(
            &mut UintChip::new(&mut self.glue, &mut self.range),
            region,
            &valid,
            &x,
            &dummy_x,
        )?;
        let safe_y = self.arithmetic.select(
            &mut UintChip::new(&mut self.glue, &mut self.range),
            region,
            &valid,
            &y,
            &dummy_y,
        )?;
        Ok(ForeignVestaPoint {
            coordinates: [self.export(region, &safe_x)?, self.export(region, &safe_y)?],
            valid,
        })
    }

    /// Totally decodes the exact 544-byte transported Vesta accumulator.
    /// `messages` and actual LE32 length must come from the same bound tape.
    /// No zero-prefix normalized claim is accepted as a transported value.
    ///
    /// # Errors
    /// Wrong fixed message count or layout errors.
    pub fn decode_vesta_accumulator(
        &mut self,
        region: &mut Region<'_, Fp>,
        messages: &[LeElement<Fp>],
        length: &Uint<Fp, 32>,
    ) -> Result<ForeignVestaAccumulator, Error> {
        if messages.len() != 17 {
            return Err(Error::Synthesis);
        }
        let point = self.decode_vesta_point_soft(region, &messages[0])?;
        let expected = self.glue.constant(region, Fp::from(544))?;
        let right_length = self.glue.is_equal(region, length.word(), &expected)?;
        let mut valid = self.glue.and(region, &point.valid, &right_length)?;
        let mut challenges = Vec::with_capacity(K);
        for message in &messages[1..] {
            let canonical = scalar_bytes_canonical::<Fp, Fp>(&mut self.uint(), region, message)?;
            valid = self.glue.and(region, &valid, &canonical)?;
            let word = element_value(&mut self.glue, region, message)?;
            let zero = self.glue.is_zero(region, &word)?;
            let nonzero = self.glue.not(region, &zero)?;
            valid = self.glue.and(region, &valid, &nonzero)?;
            challenges.push(word);
        }
        let trivial = decode_point::<Eq>(&VESTA_TRIVIAL_GENERATOR).map_err(|_| Error::Synthesis)?;
        let (x, y) = Option::from(trivial.coordinates()).ok_or(Error::Synthesis)?;
        let mut coordinates = Vec::with_capacity(2);
        for (actual, dummy) in point.coordinates.iter().zip([x, y]) {
            let actual = self.import(region, actual)?;
            let dummy = self.constant(region, dummy)?;
            let selected = self.arithmetic.select(
                &mut UintChip::new(&mut self.glue, &mut self.range),
                region,
                &valid,
                &actual,
                &dummy,
            )?;
            coordinates.push(self.export(region, &selected)?);
        }
        let challenges = challenges
            .iter()
            .map(|word| self.glue.select_constant(region, &valid, word, Fp::ONE))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ForeignVestaAccumulator {
            coordinates: coordinates.try_into().map_err(|_| Error::Synthesis)?,
            challenges: challenges.try_into().map_err(|_| Error::Synthesis)?,
            valid,
        })
    }
}
