//! Canonical PIPA-R message cells and the full-width challenge map.
//!
//! Scalars use injective S6 limbs (`lo < 2^128`, `hi < 2^127`, integer below
//! the scalar modulus). Pallas absorbs both limbs; Vesta absorbs their native
//! Fq recomposition, whose integer is below p. Soft decoders prove a verdict
//! determined by the bytes and select fixed valid dummies before arithmetic.
//!
//! The Fq→Fp challenge map first proves the canonical decomposition of w,
//! computes the exact comparison w < p, and binds c = w − [w ≥ p]p. Proving
//! 0 ≤ c < p < q makes that Fq equality an injective integer relation; the
//! comparison forbids choosing the wrong subtraction. Fp→Fq preserves w's
//! canonical integer without reduction. Witness extraction never substitutes
//! for these constraints, and unknown values follow the identical layout.

pub mod foreign;

use core::marker::PhantomData;

use ff::{Field, PrimeField};
use iroha_pasta::{Fp, PastaCurve, PastaField};
use iroha_plonk::{
    cs::InstanceType,
    frontend::{Error, Region},
};
use iroha_plonk_gadgets::{
    Bit, GlueChip, U128, Uint, Word,
    bytes::element::{LeElement, decode_pipa_point_soft, le_max, modulus_max},
    ecc::{EccChip, NonIdentityPoint},
    ff::CanonicalS6,
    range::u128::UintChip,
    statement::foreign_limbs,
};

/// Canonical scalar cells for one proof curve, including the injective S6 limbs.
/// Construction is private: every value carries its scalar-modulus proof.
#[derive(Clone, Debug)]
pub struct ScalarCells<C: PastaCurve> {
    canonical: CanonicalS6<C::Base>,
    native: Option<Word<C::Base>>,
    marker: PhantomData<C>,
}

impl<C: PastaCurve> ScalarCells<C> {
    /// Embeds a canonical base-field word as the same scalar integer.
    /// This is not modular reduction: words outside the scalar field reject.
    ///
    /// # Errors
    /// Layout failure; an integer outside the scalar modulus is unsatisfiable.
    pub fn from_native_word(
        uint: &mut UintChip<'_, C::Base>,
        region: &mut Region<'_, C::Base>,
        word: &Word<C::Base>,
    ) -> Result<Self, Error> {
        let limbs = CanonicalS6::from_native_word(uint, region, word)?.with_modulus(
            uint,
            region,
            CanonicalS6::<C::Base>::field_modulus::<C::ScalarExt>(),
        )?;
        Self::from_canonical(uint, region, limbs)
    }

    /// Checks already constrained S6 limbs against the scalar modulus.
    /// This connects canonical foreign-arithmetic outputs to transcript cells.
    ///
    /// # Errors
    /// Layout errors; limbs outside the scalar modulus make the circuit unsatisfied.
    pub fn from_limbs(
        uint: &mut UintChip<'_, C::Base>,
        region: &mut Region<'_, C::Base>,
        lo: &U128<C::Base>,
        hi: &Uint<C::Base, 127>,
    ) -> Result<Self, Error> {
        let limbs = CanonicalS6::from_limbs(
            uint,
            region,
            CanonicalS6::<C::Base>::field_modulus::<C::ScalarExt>(),
            lo,
            hi,
        )?;
        Self::from_canonical(uint, region, limbs)
    }

    /// Retains an existing checked integer certificate. A certificate for a
    /// different modulus is rejected even if its witness happens to fit.
    pub(crate) fn from_canonical(
        uint: &mut UintChip<'_, C::Base>,
        region: &mut Region<'_, C::Base>,
        canonical: CanonicalS6<C::Base>,
    ) -> Result<Self, Error> {
        if canonical.modulus() != CanonicalS6::<C::Base>::field_modulus::<C::ScalarExt>() {
            return Err(Error::Synthesis);
        }
        let native = if native_scalar::<C>() {
            Some(recompose(
                uint.glue(),
                region,
                canonical.lo(),
                canonical.hi(),
            )?)
        } else {
            None
        };
        Ok(Self {
            canonical,
            native,
            marker: PhantomData,
        })
    }
    pub(crate) const fn canonical(&self) -> &CanonicalS6<C::Base> {
        &self.canonical
    }

    /// Proves whether this canonical scalar belongs to a descriptor instance type.
    /// The type is circuit metadata; `Bits(0)` accepts only zero.
    ///
    /// # Errors
    /// Layout errors or [`Error::Synthesis`] for unsupported `Bits` widths above 253.
    pub fn instance_type(
        &self,
        uint: &mut UintChip<'_, C::Base>,
        region: &mut Region<'_, C::Base>,
        ty: InstanceType,
    ) -> Result<Bit<C::Base>, Error> {
        let max = match ty {
            InstanceType::Field => {
                let one = uint.glue().constant(region, C::Base::ONE)?;
                return uint.glue().assert_bool(region, &one);
            }
            InstanceType::Bounded
                if self
                    .canonical
                    .proves_less_than(CanonicalS6::<C::Base>::field_modulus::<Fp>()) =>
            {
                // The exact retained limbs already have a hard x<Fp proof.
                // This includes Vesta scalars and Fp words embedded in Fq;
                // a soft false verdict or a small witness alone proves nothing.
                let one = uint.glue().constant(region, C::Base::ONE)?;
                return uint.glue().assert_bool(region, &one);
            }
            InstanceType::Bounded => modulus_max::<Fp>(),
            InstanceType::Bits(bits) if bits <= 253 => {
                let low = if bits >= 128 {
                    u128::MAX
                } else {
                    (1_u128 << bits) - 1
                };
                let high = if bits <= 128 {
                    0
                } else {
                    (1_u128 << (bits - 128)) - 1
                };
                [low, high]
            }
            InstanceType::Bits(_) => return Err(Error::Synthesis),
        };
        le_max(
            uint,
            region,
            self.lo(),
            &UintChip::widen::<127, 128>(self.hi()),
            max,
        )
    }

    /// The low 128 bits of the canonical scalar integer.
    #[must_use]
    pub const fn lo(&self) -> &U128<C::Base> {
        self.canonical.lo()
    }

    /// The high 127 bits of the canonical scalar integer.
    #[must_use]
    pub const fn hi(&self) -> &Uint<C::Base, 127> {
        self.canonical.hi()
    }

    /// Vesta's single native Fq absorption word; Pallas uses the S6 pair.
    #[must_use]
    pub const fn native_word(&self) -> Option<&Word<C::Base>> {
        self.native.as_ref()
    }
}

/// A total scalar decode: rejected bytes select scalar zero.
/// The validity bit is a constrained function of all 32 input bytes.
#[derive(Clone, Debug)]
pub struct SoftScalar<C: PastaCurve> {
    /// The canonical decoded scalar or fixed zero dummy.
    pub value: ScalarCells<C>,
    /// Whether the bytes canonically encode a proof scalar.
    pub valid: Bit<C::Base>,
}

/// A total finite-point decode: rejected bytes select `(-1, 2)`.
#[derive(Clone, Debug)]
pub struct SoftPoint<C: PastaCurve> {
    /// A finite curve point safe for complete arithmetic on every input.
    pub value: NonIdentityPoint<C::Base>,
    /// Whether the native PIPA decoder accepts the original bytes.
    pub valid: Bit<C::Base>,
}

fn native_scalar<C: PastaCurve>() -> bool {
    C::ScalarExt::MODULUS == Fp::MODULUS
}

fn recompose<F: PastaField>(
    glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    lo: &U128<F>,
    hi: &Uint<F, 127>,
) -> Result<Word<F>, Error> {
    glue.linear(
        region,
        &[
            (F::ONE, lo.word()),
            (F::from_u128(1 << 127).double(), hi.word()),
        ],
        F::ZERO,
    )
}

/// Hard-decodes a canonical proof scalar from a byte-linked element.
///
/// # Errors
/// Layout errors are returned; noncanonical bytes make the circuit unsatisfied.
pub fn decode_scalar<C: PastaCurve>(
    uint: &mut UintChip<'_, C::Base>,
    region: &mut Region<'_, C::Base>,
    element: &LeElement<C::Base>,
) -> Result<ScalarCells<C>, Error> {
    let scalar = CanonicalS6::decode::<C::ScalarExt>(uint, region, element)?;
    ScalarCells::from_canonical(uint, region, scalar)
}

/// Soft-decodes every 32-byte value and selects zero for invalid encodings.
///
/// # Errors
/// Only layout errors; arbitrary byte values do not make this relation fail.
pub fn decode_scalar_soft<C: PastaCurve>(
    uint: &mut UintChip<'_, C::Base>,
    region: &mut Region<'_, C::Base>,
    element: &LeElement<C::Base>,
) -> Result<SoftScalar<C>, Error> {
    let (scalar, valid) = CanonicalS6::decode_soft::<C::ScalarExt>(uint, region, element)?;
    let value = ScalarCells::from_canonical(uint, region, scalar)?;
    Ok(SoftScalar { value, valid })
}

/// Soft-decodes compressed bytes, selects the fixed dummy, then checks its curve.
///
/// # Errors
/// Only layout errors; malformed, noncanonical and identity encodings soft-fail.
pub fn decode_point_soft<C: PastaCurve>(
    uint: &mut UintChip<'_, C::Base>,
    ecc: &mut EccChip<C>,
    region: &mut Region<'_, C::Base>,
    element: &LeElement<C::Base>,
) -> Result<SoftPoint<C>, Error> {
    let decoded = decode_pipa_point_soft(uint, region, element)?;
    let value = ecc.constrain_non_identity(region, &decoded.x, &decoded.y)?;
    Ok(SoftPoint {
        value,
        valid: decoded.valid,
    })
}

/// Hard-decodes a finite point, using the same predicate as soft decoding.
///
/// # Errors
/// Layout errors are returned; rejected encodings make the circuit unsatisfied.
pub fn decode_point<C: PastaCurve>(
    uint: &mut UintChip<'_, C::Base>,
    ecc: &mut EccChip<C>,
    region: &mut Region<'_, C::Base>,
    element: &LeElement<C::Base>,
) -> Result<NonIdentityPoint<C::Base>, Error> {
    let decoded = decode_point_soft(uint, ecc, region, element)?;
    uint.glue()
        .enforce_constant(region, decoded.valid.word(), C::Base::ONE)?;
    Ok(decoded.value)
}

/// Maps a constrained base-field squeeze to canonical proof-scalar cells.
///
/// # Errors
/// Only layout errors. The map is total, including zero and either modulus boundary.
pub fn map_challenge<C: PastaCurve>(
    uint: &mut UintChip<'_, C::Base>,
    region: &mut Region<'_, C::Base>,
    word: &Word<C::Base>,
) -> Result<ScalarCells<C>, Error> {
    let canonical = CanonicalS6::from_native_word(uint, region, word)?;
    if !native_scalar::<C>() {
        // w < p < q, so the canonical Fp limbs are already canonical in Fq.
        let canonical = canonical.with_modulus(
            uint,
            region,
            CanonicalS6::<C::Base>::field_modulus::<C::ScalarExt>(),
        )?;
        return ScalarCells::from_canonical(uint, region, canonical);
    }
    let below = le_max(
        uint,
        region,
        canonical.lo(),
        &UintChip::widen::<127, 128>(canonical.hi()),
        modulus_max::<Fp>(),
    )?;
    let subtract = uint.glue().not(region, &below)?;
    let p = C::Base::from_raw_reduced((-Fp::ONE).to_canonical_limbs()) + C::Base::ONE;
    let result = uint.glue().linear(
        region,
        &[(C::Base::ONE, word), (-p, subtract.word())],
        C::Base::ZERO,
    )?;
    let limbs = result.value().map(|value| foreign_limbs(&value));
    let lo = uint.assign::<128>(region, limbs.map(|parts| parts[0]))?;
    let hi = uint.assign::<127>(region, limbs.map(|parts| parts[1]))?;
    let value = ScalarCells::from_limbs(uint, region, &lo, &hi)?;
    let native = value.native_word().ok_or(Error::Synthesis)?;
    GlueChip::assert_equal(region, native, &result)?;
    Ok(value)
}
