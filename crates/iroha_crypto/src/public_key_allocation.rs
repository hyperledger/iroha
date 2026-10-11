//! Original-pool custody for one exact compact public-key allocation.

use std::alloc::Layout;

use iroha_allocation::{
    AllocationBudget, AllocationCharge, ChargedBuffer, ChargedBufferFromChargeError,
};
use iroha_primitives::const_vec::ConstVec;

use super::{PublicKey, PublicKeyCompact};

/// Exact compact public-key bytes retained with their original allocation charge.
///
/// This owner offers immutable access only and cannot be cloned. The borrowed
/// `PublicKey` still permits ordinary clones; those are separate, unfunded objects
/// and must not be treated as part of this original allocation's admission.
/// The compact byte Box is destroyed before its original credit is refunded.
pub struct ChargedPublicKey {
    key: PublicKey,
    charge: AllocationCharge,
}

/// Local source-custody or exact allocator refusal while copying a retained key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicKeyAllocationError {
    /// The offered charge belongs to another original finite pool.
    ForeignPool,
    /// The layout differs or the allocator refused its exact admitted request.
    Allocation(ChargedBufferFromChargeError),
}

impl std::fmt::Display for PublicKeyAllocationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForeignPool => formatter.write_str("public-key charge belongs to another pool"),
            Self::Allocation(error) => error.fmt(formatter),
        }
    }
}
impl std::error::Error for PublicKeyAllocationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ForeignPool => None,
            Self::Allocation(error) => Some(error),
        }
    }
}

impl PublicKey {
    /// Exact retained compact allocation layout, including the algorithm byte.
    ///
    /// This reads existing allocation geometry without allocating, parsing or
    /// authenticating the key. Even a discarded/malformed private test value is
    /// measured exactly; measurement does not confer protocol validity.
    pub fn retained_allocation_layout(&self) -> Layout {
        Layout::array::<u8>(self.0.algorithm_and_payload.len())
            .expect("an existing compact Box has a representable allocation layout")
    }

    /// Copy original compact bytes into an exact prepaid allocation from this pool.
    ///
    /// Neither backend parsing nor ordinary Clone is invoked. The source key and
    /// all its allocations stay unchanged. This copies a previously owned value;
    /// callers must separately establish its semantic/protocol authority.
    /// No pool admission or refund occurs on refusal: the exact offered charge
    /// returns to the caller for retry or abandonment. A successful key retains
    /// the same charge until its actual compact allocation is destroyed.
    ///
    /// # Errors
    /// Returns the original charge for a foreign pool, different size/alignment,
    /// or physical allocator refusal after exact admission.
    pub fn try_clone_from_charge(
        &self,
        budget: &AllocationBudget,
        charge: AllocationCharge,
    ) -> Result<ChargedPublicKey, (AllocationCharge, PublicKeyAllocationError)> {
        if !charge.belongs_to(budget) {
            return Err((charge, PublicKeyAllocationError::ForeignPool));
        }
        let length = self.0.algorithm_and_payload.len();
        let mut bytes = ChargedBuffer::<u8>::try_from_charge(length, charge)
            .map_err(|(charge, error)| (charge, PublicKeyAllocationError::Allocation(error)))?;
        // The source length is the exact admitted capacity; append cannot grow.
        bytes
            .append(&self.0.algorithm_and_payload)
            .expect("exact original compact-byte capacity");
        Ok(Self::bind_compact_allocation(bytes))
    }

    #[allow(unsafe_code)]
    pub(crate) fn bind_compact_allocation(bytes: ChargedBuffer<u8>) -> ChargedPublicKey {
        // SAFETY: the immediately constructed owner retains the same charge.
        // Length equals exact capacity, so into_boxed_slice performs no resize;
        // the compact key has no mutation/escape API on ChargedPublicKey.
        // PublicKey contains only the compact u8 Box, whose destructor cannot
        // unwind. Field order drops it before the charge on every owner drop.
        let (bytes, charge) = unsafe { bytes.into_allocation_parts() };
        let key = Self(PublicKeyCompact {
            algorithm_and_payload: ConstVec::new(bytes.into_boxed_slice()),
        });
        ChargedPublicKey { key, charge }
    }
}

impl ChargedPublicKey {
    /// Whether this exact compact allocation retains the original finite pool.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.charge.belongs_to(budget)
    }

    /// Borrow the exact original key without moving its allocation or charge.
    pub fn get(&self) -> &PublicKey {
        &self.key
    }

    /// Transfer this exact compact allocation and charge into an audited owner.
    ///
    /// # Safety
    /// Immediately retain the key and charge together in a move-only canonical
    /// owner. The original key must be destroyed before refunding its charge,
    /// including every refusal and unwind. Do not replace, mutate or move its
    /// compact allocation elsewhere while refund custody stays behind. Any new
    /// clone owns separate storage and needs separate original-pool admission.
    #[allow(unsafe_code)]
    pub unsafe fn into_allocation_parts(self) -> (PublicKey, AllocationCharge) {
        let Self { key, charge } = self;
        (key, charge)
    }
}
