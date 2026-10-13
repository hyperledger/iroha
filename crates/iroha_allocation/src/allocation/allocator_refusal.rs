//! Move-only transport of the allocation layer's original physical failures.

use crate::{
    ChargedBufferError, ChargedBufferFromChargeError, PrepaidSharedError, SharedFromChargeError,
};
use std::{error::Error, fmt};

/// An original physical allocation failure, retained inline without a release source.
///
/// Consuming conversions accept the allocation APIs' allocator variants and an
/// original empty-vector reservation failure with its already checked layout.
/// Admission, exhausted prepaid reservations and layout failures are returned intact.
/// Transport and inspection allocate nothing. Original charge and payload ownership
/// remain with the allocation API's separate return values; this owner never refunds
/// them, acquires new credits or fabricates a pool wake notification.
///
/// The underlying error enums are public. This type preserves a supplied cause; it
/// does not authenticate that an arbitrary caller actually invoked the allocator.
/// It cannot restore layout detail absent from that original error.
///
/// ```compile_fail
/// use iroha_allocation::{AllocatorRefusal, ChargedBufferError};
/// let owner = AllocatorRefusal::try_from(ChargedBufferError::Allocator { requested_bytes: 1 }).unwrap();
/// let moved = owner;
/// let duplicate = owner; // original custody is move-only
/// ```
#[derive(Debug)]
pub struct AllocatorRefusal {
    original: Original,
}
#[derive(Debug)]
enum Original {
    Buffer(ChargedBufferError),
    Shared(PrepaidSharedError),
    BufferFromCharge(ChargedBufferFromChargeError),
    SharedFromCharge(SharedFromChargeError),
    VecReserve {
        original: std::collections::TryReserveError,
        layout: std::alloc::Layout,
    },
}

impl AllocatorRefusal {
    /// Retain the exact failure of an empty vector reservation after its layout was checked.
    ///
    /// The caller must have established a representable array layout before invoking
    /// `try_reserve_exact` on the empty vector. This preserves that actual error and
    /// requested layout, but does not authenticate arbitrary supplied public errors.
    /// It creates no charged pool or release observation.
    pub fn from_vec_reserve(
        original: std::collections::TryReserveError,
        layout: std::alloc::Layout,
    ) -> Self {
        Self {
            original: Original::VecReserve { original, layout },
        }
    }

    /// Borrow the unchanged vector reservation error and its checked requested layout.
    pub fn vec_reserve_error(
        &self,
    ) -> Option<(&std::collections::TryReserveError, std::alloc::Layout)> {
        match &self.original {
            Original::VecReserve { original, layout } => Some((original, *layout)),
            _ => None,
        }
    }

    /// Move out the unchanged vector cause, returning the complete owner on mismatch.
    ///
    /// # Errors
    /// Returns this owner unchanged when the original failure is not a vector reservation error.
    pub fn into_vec_reserve_error(
        self,
    ) -> Result<(std::collections::TryReserveError, std::alloc::Layout), Self> {
        match self.original {
            Original::VecReserve { original, layout } => Ok((original, layout)),
            original => Err(Self { original }),
        }
    }

    /// Borrow the unchanged [`ChargedBufferError`], if it is this owner's original cause.
    pub fn buffer_error(&self) -> Option<&ChargedBufferError> {
        match &self.original {
            Original::Buffer(error) => Some(error),
            _ => None,
        }
    }
    /// Return the original [`ChargedBufferError`], retaining this entire owner on mismatch.
    ///
    /// # Errors
    /// Returns this owner unchanged when the original failure is not a [`ChargedBufferError`].
    pub fn into_buffer_error(self) -> Result<ChargedBufferError, Self> {
        match self.original {
            Original::Buffer(error) => Ok(error),
            original => Err(Self { original }),
        }
    }
    /// Borrow the unchanged [`PrepaidSharedError`], if it is this owner's original cause.
    pub fn shared_error(&self) -> Option<&PrepaidSharedError> {
        match &self.original {
            Original::Shared(error) => Some(error),
            _ => None,
        }
    }
    /// Return the original [`PrepaidSharedError`], retaining this entire owner on mismatch.
    ///
    /// # Errors
    /// Returns this owner unchanged when the original failure is not a [`PrepaidSharedError`].
    pub fn into_shared_error(self) -> Result<PrepaidSharedError, Self> {
        match self.original {
            Original::Shared(error) => Ok(error),
            original => Err(Self { original }),
        }
    }
    /// Borrow the unchanged [`ChargedBufferFromChargeError`], if it is this owner's original cause.
    pub fn buffer_from_charge_error(&self) -> Option<&ChargedBufferFromChargeError> {
        match &self.original {
            Original::BufferFromCharge(error) => Some(error),
            _ => None,
        }
    }
    /// Return the original [`ChargedBufferFromChargeError`], retaining this entire owner on mismatch.
    ///
    /// # Errors
    /// Returns this owner unchanged when the original failure is not a [`ChargedBufferFromChargeError`].
    pub fn into_buffer_from_charge_error(self) -> Result<ChargedBufferFromChargeError, Self> {
        match self.original {
            Original::BufferFromCharge(error) => Ok(error),
            original => Err(Self { original }),
        }
    }
    /// Borrow the unchanged [`SharedFromChargeError`], if it is this owner's original cause.
    pub fn shared_from_charge_error(&self) -> Option<&SharedFromChargeError> {
        match &self.original {
            Original::SharedFromCharge(error) => Some(error),
            _ => None,
        }
    }
    /// Return the original [`SharedFromChargeError`], retaining this entire owner on mismatch.
    ///
    /// # Errors
    /// Returns this owner unchanged when the original failure is not a [`SharedFromChargeError`].
    pub fn into_shared_from_charge_error(self) -> Result<SharedFromChargeError, Self> {
        match self.original {
            Original::SharedFromCharge(error) => Ok(error),
            original => Err(Self { original }),
        }
    }
}
impl TryFrom<ChargedBufferError> for AllocatorRefusal {
    type Error = ChargedBufferError;
    fn try_from(error: ChargedBufferError) -> Result<Self, Self::Error> {
        match error {
            original @ ChargedBufferError::Allocator { .. } => Ok(Self {
                original: Original::Buffer(original),
            }),
            error => Err(error),
        }
    }
}
impl TryFrom<PrepaidSharedError> for AllocatorRefusal {
    type Error = PrepaidSharedError;
    fn try_from(error: PrepaidSharedError) -> Result<Self, Self::Error> {
        match error {
            original @ PrepaidSharedError::Allocator { .. } => Ok(Self {
                original: Original::Shared(original),
            }),
            error => Err(error),
        }
    }
}
impl TryFrom<ChargedBufferFromChargeError> for AllocatorRefusal {
    type Error = ChargedBufferFromChargeError;
    fn try_from(error: ChargedBufferFromChargeError) -> Result<Self, Self::Error> {
        match error {
            original @ ChargedBufferFromChargeError::Allocator { .. } => Ok(Self {
                original: Original::BufferFromCharge(original),
            }),
            error => Err(error),
        }
    }
}
impl TryFrom<SharedFromChargeError> for AllocatorRefusal {
    type Error = SharedFromChargeError;
    fn try_from(error: SharedFromChargeError) -> Result<Self, Self::Error> {
        match error {
            original @ SharedFromChargeError::Allocator { .. } => Ok(Self {
                original: Original::SharedFromCharge(original),
            }),
            error => Err(error),
        }
    }
}
impl fmt::Display for AllocatorRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.original {
            Original::Buffer(error) => error.fmt(f),
            Original::Shared(error) => error.fmt(f),
            Original::BufferFromCharge(error) => error.fmt(f),
            Original::SharedFromCharge(error) => error.fmt(f),
            Original::VecReserve { original, layout } => {
                write!(f, "failed to reserve {} bytes: {original}", layout.size())
            }
        }
    }
}
impl Error for AllocatorRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(match &self.original {
            Original::Buffer(error) => error,
            Original::Shared(error) => error,
            Original::BufferFromCharge(error) => error,
            Original::SharedFromCharge(error) => error,
            Original::VecReserve { original, .. } => original,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AllocationBudget, AllocationRefusal, ChargedBuffer, ChargedShared};
    use std::alloc::Layout;
    #[test]
    fn pool_exhaustion_retains_the_actual_original_release_owner() {
        let budget = AllocationBudget::new(8);
        let occupied = budget.try_reserve_bytes(8).unwrap();
        let original = match ChargedBuffer::<u8>::new(1, &budget) {
            Err(error) => error,
            Ok(_) => panic!("pool is occupied"),
        };
        let expected = match &original {
            ChargedBufferError::Admission(error) => error.clone(),
            _ => panic!("no physical allocation was attempted"),
        };
        let returned = AllocatorRefusal::try_from(original).unwrap_err();
        assert!(matches!(returned, ChargedBufferError::Admission(actual) if actual == expected));
        drop(occupied);
        assert_eq!(budget.reserved_bytes(), 0);
        assert!(ChargedBuffer::<u8>::new(1, &budget).is_ok());
        assert!(matches!(
            AllocatorRefusal::try_from(ChargedBufferError::Admission(
                AllocationRefusal::DemandOverflow
            )),
            Err(ChargedBufferError::Admission(
                AllocationRefusal::DemandOverflow
            ))
        ));
    }
    #[test]
    fn exhausted_reservation_and_incompatible_charge_never_become_allocator_failures() {
        let budget = AllocationBudget::new(1024);
        let mut reservation = budget.try_reserve_bytes(0).unwrap();
        let (_, original) = match ChargedShared::from_reservation(7_u8, &mut reservation) {
            Err(error) => error,
            Ok(_) => panic!("no prepaid shell"),
        };
        assert_eq!(AllocatorRefusal::try_from(original).unwrap_err(), original);
        let small = Layout::new::<u8>();
        let charge = budget.try_reserve(small).unwrap().try_split(small).unwrap();
        let (charge, original) = match ChargedBuffer::<u64>::try_from_charge(1, charge) {
            Err(error) => error,
            Ok(_) => panic!("wrong charge"),
        };
        assert_eq!(AllocatorRefusal::try_from(original).unwrap_err(), original);
        let (charge, original) = match ChargedShared::<u64>::reserve_from_charge(charge) {
            Err(error) => error,
            Ok(_) => panic!("wrong charge"),
        };
        assert_eq!(AllocatorRefusal::try_from(original).unwrap_err(), original);
        assert!(charge.belongs_to(&budget));
        assert_eq!(charge.layout(), small);
        drop(charge);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(
            AllocatorRefusal::try_from(ChargedBufferFromChargeError::DemandOverflow).unwrap_err(),
            ChargedBufferFromChargeError::DemandOverflow
        );
    }
    #[test]
    fn borrowed_and_consuming_inspection_preserves_every_typed_field() {
        // These are transport controls, not evidence of a physical allocation failure.
        let layout = Layout::from_size_align(257, 64).unwrap();
        let owner = AllocatorRefusal::try_from(ChargedBufferError::Allocator {
            requested_bytes: 257,
        })
        .unwrap();
        assert!(matches!(
            owner.buffer_error(),
            Some(ChargedBufferError::Allocator {
                requested_bytes: 257
            })
        ));
        assert!(owner.source().unwrap().is::<ChargedBufferError>());
        assert!(owner.to_string().contains("257"));
        assert!(owner.shared_error().is_none());
        let owner = owner.into_shared_error().unwrap_err();
        assert!(owner.buffer_from_charge_error().is_none());
        let owner = owner.into_buffer_from_charge_error().unwrap_err();
        assert!(owner.shared_from_charge_error().is_none());
        let owner = owner.into_shared_from_charge_error().unwrap_err();
        assert!(matches!(
            owner.into_buffer_error().unwrap(),
            ChargedBufferError::Allocator {
                requested_bytes: 257
            }
        ));
        let owner = AllocatorRefusal::try_from(PrepaidSharedError::Allocator {
            requested_bytes: 257,
        })
        .unwrap();
        assert_eq!(
            owner.shared_error(),
            Some(&PrepaidSharedError::Allocator {
                requested_bytes: 257
            })
        );
        assert!(owner.source().unwrap().is::<PrepaidSharedError>());
        assert!(owner.buffer_error().is_none());
        let owner = owner.into_buffer_error().unwrap_err();
        assert!(owner.buffer_from_charge_error().is_none());
        let owner = owner.into_buffer_from_charge_error().unwrap_err();
        assert!(owner.shared_from_charge_error().is_none());
        let owner = owner.into_shared_from_charge_error().unwrap_err();
        assert_eq!(
            owner.into_shared_error().unwrap(),
            PrepaidSharedError::Allocator {
                requested_bytes: 257
            }
        );
        let owner =
            AllocatorRefusal::try_from(ChargedBufferFromChargeError::Allocator { layout }).unwrap();
        assert_eq!(
            owner.buffer_from_charge_error(),
            Some(&ChargedBufferFromChargeError::Allocator { layout })
        );
        assert!(owner.source().unwrap().is::<ChargedBufferFromChargeError>());
        assert!(owner.buffer_error().is_none());
        let owner = owner.into_buffer_error().unwrap_err();
        assert!(owner.shared_error().is_none());
        let owner = owner.into_shared_error().unwrap_err();
        assert!(owner.shared_from_charge_error().is_none());
        let owner = owner.into_shared_from_charge_error().unwrap_err();
        assert_eq!(
            owner.into_buffer_from_charge_error().unwrap(),
            ChargedBufferFromChargeError::Allocator { layout }
        );
        let owner =
            AllocatorRefusal::try_from(SharedFromChargeError::Allocator { layout }).unwrap();
        assert_eq!(
            owner.shared_from_charge_error(),
            Some(&SharedFromChargeError::Allocator { layout })
        );
        assert!(owner.source().unwrap().is::<SharedFromChargeError>());
        assert!(owner.buffer_error().is_none());
        let owner = owner.into_buffer_error().unwrap_err();
        assert!(owner.shared_error().is_none());
        let owner = owner.into_shared_error().unwrap_err();
        assert!(owner.buffer_from_charge_error().is_none());
        let owner = owner.into_buffer_from_charge_error().unwrap_err();
        assert_eq!(
            owner.into_shared_from_charge_error().unwrap(),
            SharedFromChargeError::Allocator { layout }
        );
    }
}
