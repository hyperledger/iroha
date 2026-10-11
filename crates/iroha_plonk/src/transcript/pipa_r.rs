//! PIPA-R's injective base-field transcript and explicit VK binding.

use super::{INSTANCE_FRAME_TAG, Transcript, TranscriptError, TranscriptHash};
use crate::cs::{InstanceType, TranscriptV2, descriptor::blake2b_personal};
use core::marker::PhantomData;
use ff::{FromUniformBytes, PrimeField};
use iroha_pasta::{
    PastaAffine, PastaCurve, PastaField,
    poseidon::{PoseidonField, Sponge},
};

/// The field of the descriptor-bound VK representation is part of its type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptRepr<C: PastaCurve> {
    /// Retained scalar-field transcript profiles.
    Scalar(C::ScalarExt),
    /// The PIPA-R base-field profile.
    Base(C::Base),
}
impl<C: PastaCurve> TranscriptRepr<C> {
    /// Canonical bytes, without converting between the two fields.
    #[must_use]
    pub fn to_repr(self) -> [u8; 32] {
        match self {
            Self::Scalar(v) => v.to_repr(),
            Self::Base(v) => v.to_repr(),
        }
    }
    /// Builds the explicit binding for a descriptor version and profile.
    #[must_use]
    pub fn derive(v2: bool, profile: TranscriptV2, digest: &[u8; 32], vk: &[u8]) -> Self {
        let persona = if v2 {
            b"Iroha-PlonkVK-v2"
        } else {
            b"Iroha-PlonkVK-v1"
        };
        let wide = blake2b_personal::<64>(persona, &[digest, vk]);
        if profile == TranscriptV2::KagemushaPoseidonRp57Base {
            Self::Base(C::Base::from_uniform_bytes(&wide))
        } else {
            Self::Scalar(C::ScalarExt::from_uniform_bytes(&wide))
        }
    }
    /// Derive the identical VK binding while checking cancellation between hash chunks.
    ///
    /// # Errors
    /// Returns caller cancellation without a partial binding.
    pub fn derive_cancellable(
        v2: bool,
        profile: TranscriptV2,
        digest: &[u8; 32],
        vk: &[u8],
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Self, iroha_pasta::Cancelled> {
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        let persona = if v2 {
            b"Iroha-PlonkVK-v2"
        } else {
            b"Iroha-PlonkVK-v1"
        };
        let mut hasher = crate::cs::descriptor::Blake2bPersonal::<64>::new(persona);
        hasher.update(digest);
        for chunk in vk.chunks(4096) {
            iroha_pasta::CancellationToken::checkpoint(cancellation)?;
            hasher.update(chunk);
        }
        let wide = hasher.finalize();
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        Ok(if profile == TranscriptV2::KagemushaPoseidonRp57Base {
            Self::Base(C::Base::from_uniform_bytes(&wide))
        } else {
            Self::Scalar(C::ScalarExt::from_uniform_bytes(&wide))
        })
    }

    /// Returns a scalar representation only when its profile uses that field.
    #[must_use]
    pub fn scalar(&self) -> Option<&C::ScalarExt> {
        match self {
            Self::Scalar(value) => Some(value),
            Self::Base(_) => None,
        }
    }
}

/// The native RP57 transcript in the proof curve's base field.
#[derive(Clone, Debug)]
pub struct BasePoseidonHash<C: PastaCurve>
where
    C::Base: PoseidonField,
{
    sponge: Sponge<C::Base>,
    marker: PhantomData<C>,
}
impl<C: PastaCurve> Default for BasePoseidonHash<C>
where
    C::Base: PoseidonField,
{
    fn default() -> Self {
        Self::new()
    }
}
impl<C: PastaCurve> BasePoseidonHash<C>
where
    C::Base: PoseidonField,
{
    /// A fresh state, with the PIPA-R tag as its first buffered element.
    #[must_use]
    pub fn new() -> Self {
        Self::with_domain(*b"pipa-rb1")
    }
    /// A base-field transcript with an explicit eight-byte protocol domain.
    #[must_use]
    pub fn with_domain(domain: [u8; 8]) -> Self {
        let mut sponge = Sponge::new();
        sponge.update(&[C::Base::from(u64::from_le_bytes(domain))]);
        Self {
            sponge,
            marker: PhantomData,
        }
    }
}

/// The canonical full-width challenge map: identity Fp→Fq, one subtraction Fq→Fp.
#[must_use]
pub fn challenge_from_base<C: PastaCurve>(value: &C::Base) -> C::ScalarExt {
    C::ScalarExt::from_raw_reduced(value.to_canonical_limbs())
}

/// The injective scalar encoding in the base field: one element for Vesta,
/// or the S6 low-128/high-127 pair for Pallas, including leading zero limbs.
#[must_use]
pub fn scalar_elements<C: PastaCurve>(value: &C::ScalarExt) -> Vec<C::Base> {
    let limbs = value.to_canonical_limbs();
    if <C::ScalarExt as PrimeField>::MODULUS == <iroha_pasta::Fp as PrimeField>::MODULUS {
        vec![C::Base::from_raw_reduced(limbs)]
    } else {
        vec![
            C::Base::from_raw_reduced([limbs[0], limbs[1], 0, 0]),
            C::Base::from_raw_reduced([limbs[2], limbs[3], 0, 0]),
        ]
    }
}
impl<C: PastaCurve> TranscriptHash<C> for BasePoseidonHash<C>
where
    C::Base: PoseidonField,
{
    fn absorb_point(&mut self, point: &C::AffineExt) -> Result<(), TranscriptError> {
        let (x, y) = Option::from(point.coordinates()).ok_or(TranscriptError::IdentityPoint)?;
        self.sponge.update(&[x, y]);
        Ok(())
    }
    fn absorb_scalar(&mut self, scalar: &C::ScalarExt) {
        self.sponge.update(&scalar_elements::<C>(scalar));
    }
    fn absorb_binding(&mut self, binding: &TranscriptRepr<C>) -> Result<(), TranscriptError> {
        match binding {
            TranscriptRepr::Base(value) => self.absorb_base(value),
            TranscriptRepr::Scalar(_) => Err(TranscriptError::ProfileMismatch),
        }
    }
    fn absorb_base(&mut self, value: &C::Base) -> Result<(), TranscriptError> {
        self.sponge.update(&[*value]);
        Ok(())
    }
    fn squeeze(&mut self) -> C::ScalarExt {
        challenge_from_base::<C>(&self.sponge.squeeze())
    }
}

/// Absorbs the explicit V2 binding and the complete typed instance frame.
/// Integer framing data are native base elements in PIPA-R; retained scalar
/// profiles absorb the same framing integers through their scalar lane.
///
/// # Errors
/// A field/profile mismatch returns [`TranscriptError::ProfileMismatch`].
pub fn absorb_prelude_v2<C: PastaCurve, T: Transcript<C> + ?Sized>(
    transcript: &mut T,
    repr: &TranscriptRepr<C>,
    lengths: &[u32],
    types: &[InstanceType],
) -> Result<(), TranscriptError> {
    transcript.common_binding(repr)?;
    let base = matches!(repr, TranscriptRepr::Base(_));
    let mut frame = |value: u64| {
        if base {
            transcript.common_base(&C::Base::from(value))
        } else {
            transcript.common_scalar(&C::ScalarExt::from(value));
            Ok(())
        }
    };
    frame(u64::from_le_bytes(INSTANCE_FRAME_TAG))?;
    frame(u64::try_from(lengths.len()).map_err(|_| TranscriptError::ProfileMismatch)?)?;
    for length in lengths {
        frame(u64::from(*length))?;
    }
    for ty in types {
        frame(ty.code())?;
    }
    Ok(())
}
