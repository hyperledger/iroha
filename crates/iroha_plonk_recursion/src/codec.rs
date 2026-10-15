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
    ecc::{AssignedPoint, EccChip, NonIdentityPoint},
    ff::CanonicalS6,
    range::u128::UintChip,
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
    /// Assigns a private scalar with its complete canonical field certificate.
    pub fn assign_value(
        uint: &mut UintChip<'_, C::Base>,
        region: &mut Region<'_, C::Base>,
        value: iroha_plonk::frontend::Value<C::ScalarExt>,
    ) -> Result<Self, Error> {
        let canonical = CanonicalS6::assign_value(uint, region, value)?;
        Self::from_canonical(uint, region, canonical)
    }

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

    /// Maps zero to one on the exact retained canonical cells without a new range proof.
    /// # Errors
    /// Layout errors or an invalid retained modulus certificate.
    pub(crate) fn nonzero_or_one(
        &self,
        uint: &mut UintChip<'_, C::Base>,
        region: &mut Region<'_, C::Base>,
    ) -> Result<Self, Error> {
        let canonical = self.canonical.clone().nonzero_or_one(uint, region)?;
        Self::from_canonical(uint, region, canonical)
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

/// A generator claim point, including the canonical identity (0, 0).
/// Ordinary transcript commitments retain their separate finite-point type.
#[derive(Clone, Debug)]
pub struct GeneratorPoint<F: PastaField>(AssignedPoint<F>);
impl<F: PastaField> GeneratorPoint<F> {
    pub(crate) fn from_assigned(value: AssignedPoint<F>) -> Self {
        Self(value)
    }
    /// Exact constrained x coordinate; zero for identity.
    pub const fn x(&self) -> &Word<F> {
        self.0.x()
    }
    /// Exact constrained y coordinate; zero for identity.
    pub const fn y(&self) -> &Word<F> {
        self.0.y()
    }
    /// Complete curve-or-identity point on the same cells.
    pub const fn point(&self) -> &AssignedPoint<F> {
        &self.0
    }
    /// Assigned coordinates.
    pub fn value(&self) -> iroha_plonk::frontend::Value<(F, F)> {
        self.0.value()
    }
}
/// Exact generator decode verdict and a safe complete-arithmetic point.
#[derive(Clone, Debug)]
pub struct SoftGenerator<C: PastaCurve> {
    /// Original canonical generator or the fixed finite dummy (-1, 2).
    pub value: GeneratorPoint<C::Base>,
    /// Exact canonical GroupEncoding acceptance predicate, including zero32.
    pub valid: Bit<C::Base>,
}
/// Decodes a generator claim or final suffix; ordinary messages use decode_point_soft.
/// # Errors
/// Layout failure only; malformed encodings select the fixed finite dummy.
pub fn decode_generator_soft<C: PastaCurve>(
    uint: &mut UintChip<'_, C::Base>,
    ecc: &mut EccChip<C>,
    region: &mut Region<'_, C::Base>,
    element: &LeElement<C::Base>,
) -> Result<SoftGenerator<C>, Error> {
    let decoded = iroha_plonk_gadgets::bytes::element::decode_point_soft(uint, region, element)?;
    let x = uint
        .glue()
        .select_constant(region, &decoded.valid, &decoded.x, -C::Base::ONE)?;
    let y = uint
        .glue()
        .select_constant(region, &decoded.valid, &decoded.y, C::Base::from(2))?;
    let value = GeneratorPoint::from_assigned(ecc.constrain_point(region, &x, &y)?);
    Ok(SoftGenerator {
        value,
        valid: decoded.valid,
    })
}
/// Hard canonical generator decode, admitting identity only as all-zero bytes.
/// # Errors
/// Layout failure; malformed encodings are unsatisfiable.
pub fn decode_generator<C: PastaCurve>(
    uint: &mut UintChip<'_, C::Base>,
    ecc: &mut EccChip<C>,
    region: &mut Region<'_, C::Base>,
    element: &LeElement<C::Base>,
) -> Result<GeneratorPoint<C::Base>, Error> {
    let decoded = decode_generator_soft(uint, ecc, region, element)?;
    uint.glue()
        .enforce_constant(region, decoded.valid.word(), C::Base::ONE)?;
    Ok(decoded.value)
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
    let canonical = canonical.reduce_fq_to_fp(uint, region)?;
    ScalarCells::from_canonical(uint, region, canonical)
}
