//! Shared canonical S6 certificates and injective 128/127 ↔ 87-bit bridges.
//!
//! Every constructor proves an integer in `[0,m)`, with `m<2^255`, and retains
//! the same constrained cells. The declared modulus and smallest hard-proved
//! upper bound are private parts of the certificate. Widening the declared
//! modulus never discards a tighter bound or consults the witness value.
//! Import splits `lo=a+2^87*b0`, `hi=b1+2^46*c` with widths87/41/46/81,
//! then sets `b=b0+2^41*b1`. Export reverses those equalities, range-checking
//! only b0 and b1: canonical FF limbs already prove the other bounds.
//! Each side of every bridge equality is below `2^128`, so no native-field
//! wrap can identify different integers. The resulting representations satisfy
//! `lo+2^128*hi=a+2^87*b+2^174*c` over the integers.

use super::{FfChip, FfValue, ForeignModulus, Form, Nat};
use crate::{
    Bit, GlueChip, U128, Uint,
    bytes::element::{LeElement, assert_le_max, assert_scalar_bytes, scalar_bytes_canonical},
    range::u128::UintChip,
    statement::assign_canonical_limbs,
};
use iroha_pasta::PastaField;
use iroha_plonk::frontend::{Error, Region};

/// Canonical S6 limbs with their exact foreign modulus. No unchecked
/// constructor is exposed; a certificate always retains its proving cells.
#[derive(Clone, Debug)]
pub struct CanonicalS6<F: PastaField> {
    lo: U128<F>,
    hi: Uint<F, 127>,
    modulus: ForeignModulus,
    // Strict integer bound established by a hard constraint on these exact
    // limbs. It may be tighter than the declared arithmetic modulus after
    // widening. A selected value needs a bound valid for both possible arms.
    proved_upper_bound: ForeignModulus,
}
impl<F: PastaField> CanonicalS6<F> {
    /// The modulus of a Pasta field, represented as an FF modulus.
    #[must_use]
    pub fn field_modulus<G: PastaField>() -> ForeignModulus {
        // PastaField is sealed to exactly these two fields.
        if G::MODULUS == <iroha_pasta::Fp as ::ff::PrimeField>::MODULUS {
            ForeignModulus::PASTA_FP
        } else {
            ForeignModulus::PASTA_FQ
        }
    }
    fn supported(modulus: ForeignModulus) -> Result<(), Error> {
        if modulus.nat().bits_vartime() > 255 {
            return Err(Error::Synthesis);
        }
        Ok(())
    }
    /// Proves the supplied bounded limbs represent an integer below `modulus`.
    ///
    /// # Errors
    /// Moduli at least `2^255` are unsupported. Out-of-range limb integers make
    /// the circuit unsatisfied; layout errors are returned.
    pub fn from_limbs(
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
        modulus: ForeignModulus,
        lo: &U128<F>,
        hi: &Uint<F, 127>,
    ) -> Result<Self, Error> {
        Self::supported(modulus)?;
        let maximum = modulus.nat().wrapping_sub(&Nat::ONE);
        assert_le_max(
            uint,
            region,
            lo.word(),
            &UintChip::widen::<127, 128>(hi),
            [maximum.low_u128(), maximum.shr(128).low_u128()],
        )?;
        Ok(Self {
            lo: lo.clone(),
            hi: hi.clone(),
            modulus,
            proved_upper_bound: modulus,
        })
    }
    /// Canonically decomposes one native word and retains that modulus proof.
    ///
    /// # Errors
    /// Layout errors.
    pub fn from_native_word(
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
        word: &crate::Word<F>,
    ) -> Result<Self, Error> {
        let limbs = assign_canonical_limbs(uint, region, word)?;
        Ok(Self {
            lo: limbs.lo().clone(),
            hi: limbs.hi().clone(),
            modulus: Self::field_modulus::<F>(),
            proved_upper_bound: Self::field_modulus::<F>(),
        })
    }
    /// Changes the declared modulus while retaining the tightest hard-proved
    /// bound. A smaller modulus adds a comparison only when the retained proof
    /// does not already imply it. The exact constrained limb cells are retained.
    ///
    /// # Errors
    /// As [`Self::from_limbs`]. No modular reduction is performed.
    pub fn with_modulus(
        self,
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
        modulus: ForeignModulus,
    ) -> Result<Self, Error> {
        Self::supported(modulus)?;
        if self.proves_less_than(modulus) {
            Ok(Self { modulus, ..self })
        } else {
            Self::from_limbs(uint, region, modulus, &self.lo, &self.hi)
        }
    }
    /// Hard-decodes one exact scalar message for field `G`.
    ///
    /// # Errors
    /// Layout errors. A noncanonical integer or set top bit is unsatisfiable.
    pub fn decode<G: PastaField>(
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
        element: &LeElement<F>,
    ) -> Result<Self, Error> {
        assert_scalar_bytes::<F, G>(uint, region, element)?;
        Ok(Self {
            lo: element.lo().clone(),
            hi: element.hi().clone(),
            modulus: Self::field_modulus::<G>(),
            proved_upper_bound: Self::field_modulus::<G>(),
        })
    }
    /// Total-decodes a scalar; invalid bytes select the fixed zero integer.
    /// Selection preserves the original limb bounds, and its validity bit
    /// proves canonicality, so no second range or modulus proof is added.
    ///
    /// # Errors
    /// Layout errors only.
    pub fn decode_soft<G: PastaField>(
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
        element: &LeElement<F>,
    ) -> Result<(Self, Bit<F>), Error> {
        let valid = scalar_bytes_canonical::<F, G>(uint, region, element)?;
        let lo = uint
            .glue()
            .select_constant(region, &valid, element.lo().word(), F::ZERO)?;
        let hi = uint
            .glue()
            .select_constant(region, &valid, element.hi().word(), F::ZERO)?;
        Ok((
            Self {
                lo: Uint::new(lo),
                hi: Uint::new(hi),
                modulus: Self::field_modulus::<G>(),
                // Both branches satisfy this bound: the valid original is
                // canonical in G and the invalid branch is the fixed zero.
                // Never strengthen it merely because the witness is invalid.
                proved_upper_bound: Self::field_modulus::<G>(),
            },
            valid,
        ))
    }
    /// Low128bits.
    #[must_use]
    pub const fn lo(&self) -> &U128<F> {
        &self.lo
    }
    /// High127bits.
    #[must_use]
    pub const fn hi(&self) -> &Uint<F, 127> {
        &self.hi
    }
    /// The exact integer modulus whose proof this certificate retains.
    #[must_use]
    pub const fn modulus(&self) -> ForeignModulus {
        self.modulus
    }

    /// Whether retained hard constraints already prove this exact limb integer
    /// is strictly below `bound`. This uses only opaque structural metadata,
    /// never limb witness values or a soft decoder's validity bit.
    #[must_use]
    pub fn proves_less_than(&self, bound: ForeignModulus) -> bool {
        self.proved_upper_bound
            .nat()
            .cmp_vartime(&bound.nat())
            .is_le()
    }
}

impl<F: PastaField> FfChip<F> {
    /// Imports a canonical S6 certificate with four bounded fragments and
    /// exact integer recomposition. No second canonicality proof is needed.
    ///
    /// # Errors
    /// The certificate's modulus is not configured, or layout fails.
    pub fn import_s6(
        &self,
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
        value: &CanonicalS6<F>,
    ) -> Result<FfValue<F>, Error> {
        self.gates_of(value.modulus, &[])?;
        let a = uint.assign::<87>(region, value.lo.value().map(|x| x & ((1_u128 << 87) - 1)))?;
        let b0 = uint.assign::<41>(region, value.lo.value().map(|x| x >> 87))?;
        let b1 = uint.assign::<46>(region, value.hi.value().map(|x| x & ((1_u128 << 46) - 1)))?;
        let c = uint.assign::<81>(region, value.hi.value().map(|x| x >> 46))?;
        let lo = uint.glue().linear(
            region,
            &[(F::ONE, a.word()), (F::from_u128(1 << 87), b0.word())],
            F::ZERO,
        )?;
        GlueChip::assert_equal(region, &lo, value.lo.word())?;
        let hi = uint.glue().linear(
            region,
            &[(F::ONE, b1.word()), (F::from_u128(1 << 46), c.word())],
            F::ZERO,
        )?;
        GlueChip::assert_equal(region, &hi, value.hi.word())?;
        let b = uint.glue().linear(
            region,
            &[(F::ONE, b0.word()), (F::from_u128(1 << 41), b1.word())],
            F::ZERO,
        )?;
        Ok(FfValue {
            limbs: [a.word().clone(), b, c.word().clone()],
            bounds: [(1 << 87) - 1, (1 << 87) - 1, (1 << 81) - 1],
            modulus: value.modulus,
            form: Form::Canonical,
        })
    }
    /// Exports canonical FF limbs with the exact reverse bridge. Only the
    /// middle limb's41/46 split is new: the retained canonical FF proof implies
    /// `a<2^87`, `c<2^81`, hence low128/high127 and the same integer below m.
    ///
    /// # Errors
    /// A modulus at least `2^255`, mixed/unconfigured values, or layout errors.
    pub fn export_s6(
        &mut self,
        uint: &mut UintChip<'_, F>,
        region: &mut Region<'_, F>,
        value: &FfValue<F>,
    ) -> Result<CanonicalS6<F>, Error> {
        CanonicalS6::<F>::supported(value.modulus)?;
        let value = self.assert_canonical(region, value)?;
        let [a, b, c] = value.limbs();
        let middle = b.value().map(|value| Nat::from_field(&value).low_u128());
        let b0 = uint.assign::<41>(region, middle.map(|value| value & ((1_u128 << 41) - 1)))?;
        let b1 = uint.assign::<46>(region, middle.map(|value| value >> 41))?;
        let recomposed = uint.glue().linear(
            region,
            &[(F::ONE, b0.word()), (F::from_u128(1 << 41), b1.word())],
            F::ZERO,
        )?;
        GlueChip::assert_equal(region, &recomposed, b)?;
        let lo = uint.glue().linear(
            region,
            &[(F::ONE, a), (F::from_u128(1 << 87), b0.word())],
            F::ZERO,
        )?;
        let hi = uint.glue().linear(
            region,
            &[(F::ONE, b1.word()), (F::from_u128(1 << 46), c)],
            F::ZERO,
        )?;
        Ok(CanonicalS6 {
            lo: Uint::new(lo),
            hi: Uint::new(hi),
            modulus: value.modulus,
            proved_upper_bound: value.modulus,
        })
    }
}

#[cfg(test)]
mod tests;
