//! The KAGEMUSHA RP57 Poseidon transcript (spec 6.2).
//!
//! The hash is [`iroha_pasta::poseidon::Sponge`] over the scalar field `F`:
//! width 3, rate 2, `x^5`, `R_F = 8`, `R_P = 57`, MDS 0, starting from
//! `[2^64, 0, 0]`. It reproduces snark-verifier's
//! `PoseidonTranscript<C, NativeLoader, _, 3, 2, 8, 57>`:
//!
//! - `common_scalar` buffers the scalar;
//! - `common_point` rejects the identity and buffers two elements;
//! - `squeeze` absorbs the buffer in rate-2 chunks (a short chunk is padded
//!   with a single 1; an even buffer length, zero included, adds a `[1]`
//!   block) and returns word 1; the state carries over.
//!
//! # Point absorption
//!
//! A finite point `(x, y)` with canonical integer coordinates in the base
//! field `B` is buffered as:
//!
//! - [`PointAbsorption::Injective`] (production):
//!   `[x mod |F|, [x >= |F|] + 2 (y mod 2)]`. The Pasta moduli satisfy
//!   `|B| < 2|F|`, so `x` is recovered from the two elements and `y` from its
//!   parity: the encoding is injective and costs the same two elements.
//! - `PointAbsorption::FeToFe` (historical reference, `cfg(test)` only): `[x mod |F|, y mod |F|]`, snark-verifier
//!   `fe_to_fe`. It is not injective on Vesta, where `q > p`.
//!
//! On Pallas (`B = Fp`, `F = Fq`, `p < q`) both encodings keep `x` unchanged;
//! they differ in the second element.

use core::marker::PhantomData;

use ff::PrimeField;
use iroha_pasta::{
    PastaAffine, PastaCurve, PastaField,
    poseidon::{PoseidonField, Sponge},
};

use super::{TranscriptError, TranscriptHash};

/// How a point enters the Poseidon sponge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PointAbsorption {
    /// `[x mod |F|, [x >= |F|] + 2 (y mod 2)]` (production, injective).
    Injective,
    /// `[x mod |F|, y mod |F|]`, snark-verifier `fe_to_fe` (oracle mode only).
    #[cfg(test)]
    FeToFe,
}

/// `value mod |F|` for a canonical base-field element.
fn reduce_into<B: PastaField, F: PastaField>(value: &B) -> F {
    F::from_raw_reduced(value.to_canonical_limbs())
}

/// Whether the canonical integer `value` is at least `|F|`.
fn exceeds_modulus<B: PastaField, F: PastaField>(value: &B) -> bool {
    Option::<F>::from(F::from_canonical_limbs(value.to_canonical_limbs())).is_none()
}

/// The two scalar-field elements a point is buffered as.
///
/// # Errors
///
/// [`TranscriptError::IdentityPoint`] for the identity.
pub fn point_elements<C: PastaCurve>(
    point: &C::AffineExt,
    absorption: PointAbsorption,
) -> Result<[C::ScalarExt; 2], TranscriptError> {
    let (x, y): (C::Base, C::Base) =
        Option::from(point.coordinates()).ok_or(TranscriptError::IdentityPoint)?;
    let x_reduced = reduce_into::<C::Base, C::ScalarExt>(&x);
    match absorption {
        PointAbsorption::Injective => {
            let high = u64::from(exceeds_modulus::<C::Base, C::ScalarExt>(&x));
            let parity = u64::from(bool::from(y.is_odd()));
            Ok([x_reduced, C::ScalarExt::from(high + 2 * parity)])
        }
        #[cfg(test)]
        PointAbsorption::FeToFe => Ok([x_reduced, reduce_into::<C::Base, C::ScalarExt>(&y)]),
    }
}

/// The KAGEMUSHA Poseidon hash state.
#[derive(Clone, Debug)]
pub struct PoseidonHash<C: PastaCurve>
where
    C::ScalarExt: PoseidonField,
{
    sponge: Sponge<C::ScalarExt>,
    absorption: PointAbsorption,
    _curve: PhantomData<C>,
}

impl<C: PastaCurve> Default for PoseidonHash<C>
where
    C::ScalarExt: PoseidonField,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<C: PastaCurve> PoseidonHash<C>
where
    C::ScalarExt: PoseidonField,
{
    /// A fresh production state (injective point absorption).
    #[must_use]
    pub fn new() -> Self {
        Self::with_absorption(PointAbsorption::Injective)
    }

    /// A fresh oracle-mode state (`fe_to_fe` point absorption, spec 6.4).
    /// Unit tests only.
    #[cfg(test)]
    #[doc(hidden)]
    #[must_use]
    pub fn new_oracle() -> Self {
        Self::with_absorption(PointAbsorption::FeToFe)
    }

    fn with_absorption(absorption: PointAbsorption) -> Self {
        Self {
            sponge: Sponge::new(),
            absorption,
            _curve: PhantomData,
        }
    }

    /// The point absorption of this state.
    #[must_use]
    pub fn absorption(&self) -> PointAbsorption {
        self.absorption
    }
}

impl<C: PastaCurve> TranscriptHash<C> for PoseidonHash<C>
where
    C::ScalarExt: PoseidonField,
{
    fn absorb_point(&mut self, point: &C::AffineExt) -> Result<(), TranscriptError> {
        let elements = point_elements::<C>(point, self.absorption)?;
        self.sponge.update(&elements);
        Ok(())
    }

    fn absorb_scalar(&mut self, scalar: &C::ScalarExt) {
        self.sponge.update(&[*scalar]);
    }

    fn squeeze(&mut self) -> C::ScalarExt {
        self.sponge.squeeze()
    }
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use group::{Curve, Group, prime::PrimeCurveAffine};
    use iroha_pasta::{Ep, EpAffine, Eq, EqAffine, Fp, Fq};

    use super::*;

    /// A Vesta point whose `x` is at least `p` (found by scanning multiples).
    fn vesta_point_with_large_x() -> EqAffine {
        let generator = Eq::generator();
        let mut point = generator;
        for _ in 0..10_000 {
            let affine = point.to_affine();
            let (x, _): (Fq, Fq) = Option::from(affine.coordinates()).expect("finite");
            if exceeds_modulus::<Fq, Fp>(&x) {
                return affine;
            }
            point += generator;
        }
        panic!("no Vesta point with x >= p among the first multiples");
    }

    /// DEV-03 (spec section 14): production Poseidon absorption is injective, unlike the vendored
    /// `fe_to_fe`.
    #[test]
    fn injective_encoding_recovers_the_point() {
        for point in [
            vesta_point_with_large_x(),
            (Eq::generator() * Fp::from(3)).to_affine(),
            -(Eq::generator() * Fp::from(3)).to_affine(),
        ] {
            let [low, flag] =
                point_elements::<Eq>(&point, PointAbsorption::Injective).expect("finite");
            let (x, y): (Fq, Fq) = Option::from(point.coordinates()).expect("finite");
            let flag = flag.to_canonical_limbs()[0];
            assert!(flag < 4);
            // x = low + (flag & 1) * p, recomputed in Fq.
            let mut recovered = Fq::from_raw_reduced(low.to_canonical_limbs());
            if flag & 1 == 1 {
                // p as an element of Fq: (p - 1) + 1.
                recovered += Fq::from_raw_reduced((-Fp::ONE).to_canonical_limbs()) + Fq::ONE;
            }
            assert_eq!(recovered, x);
            assert_eq!(flag >> 1, u64::from(bool::from(y.is_odd())));
        }
        // fe_to_fe collapses x and x - p on Vesta; the injective form does not.
        let large = vesta_point_with_large_x();
        let fe = point_elements::<Eq>(&large, PointAbsorption::FeToFe).expect("finite");
        let injective = point_elements::<Eq>(&large, PointAbsorption::Injective).expect("finite");
        assert_eq!(fe[0], injective[0]);
        assert_eq!(injective[1].to_canonical_limbs()[0] & 1, 1);
    }

    #[test]
    fn pallas_x_is_always_below_the_scalar_modulus() {
        let point = (Ep::generator() * Fq::from(9)).to_affine();
        let (x, y): (Fp, Fp) = Option::from(point.coordinates()).expect("finite");
        let [low, flag] = point_elements::<Ep>(&point, PointAbsorption::Injective).expect("finite");
        assert_eq!(low.to_repr(), x.to_repr());
        assert_eq!(flag, Fq::from(2 * u64::from(bool::from(y.is_odd()))));
        let [fe_x, fe_y] = point_elements::<Ep>(&point, PointAbsorption::FeToFe).expect("finite");
        assert_eq!(fe_x.to_repr(), x.to_repr());
        assert_eq!(fe_y.to_repr(), y.to_repr());
    }

    #[test]
    fn identity_is_rejected_and_modes_differ() {
        assert_eq!(
            point_elements::<Ep>(&EpAffine::identity(), PointAbsorption::Injective),
            Err(TranscriptError::IdentityPoint)
        );
        let point = Eq::generator().to_affine();
        let mut production = PoseidonHash::<Eq>::new();
        let mut oracle = PoseidonHash::<Eq>::new_oracle();
        assert_eq!(production.absorption(), PointAbsorption::Injective);
        assert_eq!(oracle.absorption(), PointAbsorption::FeToFe);
        production.absorb_point(&point).expect("finite");
        oracle.absorb_point(&point).expect("finite");
        assert_ne!(production.squeeze(), oracle.squeeze());
        // Scalars absorb identically in both modes.
        let mut a = PoseidonHash::<Eq>::new();
        let mut b = PoseidonHash::<Eq>::new_oracle();
        a.absorb_scalar(&Fp::from(4));
        b.absorb_scalar(&Fp::from(4));
        assert_eq!(a.squeeze(), b.squeeze());
        assert_eq!(
            PoseidonHash::<Eq>::default().squeeze(),
            PoseidonHash::<Eq>::new().squeeze()
        );
    }
}
