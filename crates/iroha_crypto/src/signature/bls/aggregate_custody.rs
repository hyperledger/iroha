//! Explicit caller-owned pairing scratch for the canonical normal aggregate relation.

use blst::{Pairing, blst_fp12, blst_p2_affine};
use blstrs::{G1Projective, G2Projective};
use group::{Curve as _, Group as _};

pub use super::pairing::AggregateScratchError;
use super::pairing::{FalliblePairing, PairingContext, StackPairing};
use super::uncached::{self, HASH_TO_FIELD_DST, NORMAL_PREFIX, Orientation};
use crate::{BlsNormalPopVerifiedKey, SignatureVerificationError};

/// Reusable normal-BLS aggregate verifier with one explicitly admitted heap owner.
///
/// The caller supplies the custody token for the exact pairing-context backing.
/// This token remains owned through every verdict and is released only after that
/// backing is dropped. Verification borrows the PoP-verified keys and allocates
/// no heap collections, prepared-point buffers, signature copies or cache entries.
/// Physical allocation is fallible and remains distinct from pool admission.
#[derive(Debug)]
#[must_use = "dropping the verifier releases its original pairing backing and custody token"]
pub struct BlsNormalAggregateScratch<O = ()> {
    // Declaration order is intentional: release the backing before its funding.
    pairing: FalliblePairing,
    _owner: O,
}

impl<O> BlsNormalAggregateScratch<O> {
    /// Exact checked heap layout of the upstream `blst` pairing context.
    ///
    /// Callers can partition an original reservation into a move-only charge
    /// for this layout and return that charge from the admission callback.
    #[must_use]
    pub fn backing_layout() -> core::alloc::Layout {
        FalliblePairing::layout()
    }

    /// Exact heap backing bytes allocated for the upstream `blst` context.
    #[must_use]
    pub fn backing_bytes() -> usize {
        Self::backing_layout().size()
    }

    /// Admit the exact backing before allocating and retain the returned owner.
    ///
    /// # Errors
    /// Returns the caller's unchanged typed admission refusal, or a separate
    /// physical allocator failure. Neither becomes a cryptographic rejection.
    /// An empty linked context is refused as unsupported geometry before any backing
    /// reservation or C call; the admitted owner is then retired.
    pub fn new<E>(
        admit: impl FnOnce(usize) -> Result<O, E>,
    ) -> Result<Self, AggregateScratchError<E>> {
        let bytes = Self::backing_bytes();
        let owner = admit(bytes).map_err(AggregateScratchError::Admission)?;
        let pairing = FalliblePairing::new(HASH_TO_FIELD_DST)?;
        Ok(Self {
            pairing,
            _owner: owner,
        })
    }

    /// Verify a grouped aggregate without allocating or retaining borrowed input.
    ///
    /// Each group contains a repeatable, cloneable iterator of PoP-verified keys and one
    /// message. Groups must have distinct messages and no repeated key within a
    /// group. Cloning an iterator must preserve its order and contents. The same
    /// key may sign distinct messages. Iterators are rescanned to
    /// enforce these conditions without heap sets. Each call resets the original
    /// context, including calls following rejected or differently shaped proofs.
    ///
    /// # Errors
    /// Returns the same canonical signature parse or relation rejection as the
    /// ordinary aggregate API, in fixed unformatted form. There is no resource
    /// refusal after construction; the original scratch owner remains reusable.
    pub fn verify<'a, G, K>(
        &mut self,
        groups: G,
        aggregate: &[u8],
    ) -> Result<(), SignatureVerificationError>
    where
        G: Iterator<Item = (K, &'a [u8])> + Clone,
        K: Iterator<Item = &'a BlsNormalPopVerifiedKey> + Clone,
    {
        NormalRelation {
            pairing: self.pairing.context(),
        }
        .verify(groups, aggregate)
    }
}

/// The ordinary public adapter uses stack storage and the same canonical relation.
pub(crate) fn verify_on_stack(
    groups: &[(&[&BlsNormalPopVerifiedKey], &[u8])],
    aggregate: &[u8],
) -> Result<(), SignatureVerificationError> {
    // Fails closed only on a linked build that `consensus::check_pairing_geometry`
    // refuses at node startup; this verdict-only API has no resource-refusal variant.
    let Some(mut pairing) = StackPairing::new(HASH_TO_FIELD_DST) else {
        return Err(SignatureVerificationError::bad_signature());
    };
    NormalRelation {
        pairing: pairing.context(),
    }
    .verify(
        groups
            .iter()
            .map(|(keys, message)| (keys.iter().copied(), *message)),
        aggregate,
    )
}

struct NormalRelation<'a> {
    pairing: PairingContext<'a>,
}

impl NormalRelation<'_> {
    fn verify<'a, G, K>(
        &mut self,
        groups: G,
        aggregate: &[u8],
    ) -> Result<(), SignatureVerificationError>
    where
        G: Iterator<Item = (K, &'a [u8])> + Clone,
        K: Iterator<Item = &'a BlsNormalPopVerifiedKey> + Clone,
    {
        self.pairing.init(true, HASH_TO_FIELD_DST);
        if groups.clone().next().is_none() {
            return Err(SignatureVerificationError::bad_signature());
        }
        // Preserve the original public adapter's geometry/duplicate rejection
        // before canonical aggregate-signature parsing.
        for (group_index, (keys, message)) in groups.clone().enumerate() {
            if keys.clone().next().is_none()
                || groups
                    .clone()
                    .take(group_index)
                    .any(|(_, prior)| prior == message)
            {
                return Err(SignatureVerificationError::bad_signature());
            }
            for (key_index, key) in keys.clone().enumerate() {
                if keys.clone().take(key_index).any(|prior| prior == key) {
                    return Err(SignatureVerificationError::bad_signature());
                }
            }
        }
        let signature = match uncached::signature(Orientation::Normal, aggregate)
            .map_err(SignatureVerificationError::from_bls)?
        {
            uncached::Signature::Normal(signature) => signature,
            uncached::Signature::Small(_) => {
                return Err(SignatureVerificationError::bad_signature());
            }
        };
        for (keys, message) in groups {
            let sum = keys.fold(G1Projective::identity(), |sum, key| sum + key.point);
            if bool::from(sum.is_identity()) {
                return Err(SignatureVerificationError::bad_signature());
            }
            // This is the existing contextual w3f Message point, independently
            // covered by the shared uncached suite's original-point parity test.
            let message = G2Projective::hash_to_curve(message, HASH_TO_FIELD_DST, NORMAL_PREFIX);
            self.pairing
                .raw_aggregate(message.to_affine().as_ref(), sum.to_affine().as_ref());
        }
        self.pairing.commit();
        let mut signature_pairing = blst_fp12::default();
        let signature: &blst_p2_affine = signature.as_ref();
        Pairing::aggregated(&mut signature_pairing, signature);
        if self.pairing.finalverify(Some(&signature_pairing)) {
            Ok(())
        } else {
            Err(SignatureVerificationError::bad_signature())
        }
    }
}

#[cfg(test)]
mod tests;
