//! Exact prepaid control allocations using Concread's existing shared owner.
//!
//! This facade has no default, untracked constructor, weak reference, or raw
//! escape. Nested payload allocations remain separately owned obligations.

use super::{AllocationBudget, AllocationCharge, AllocationReservation, InsufficientReservation};
use crate::shared::{Reserved, Shared};
use std::{alloc::Layout, fmt, ops::Deref};

/// Immutable shared allocation retaining its original exact prepaid charge.
///
/// Clones share the same control allocation without allocating or invoking the
/// payload's Clone implementation. The final owner physically frees its control
/// block before destroying the payload and then refunding its original credit.
/// If payload destruction panics, the existing underlying protocol conservatively
/// retains that credit; it never reports incomplete reclamation as available.
pub struct ChargedShared<T>(Shared<T, AllocationCharge>);

/// Exact prepaid shared shell reserved before consuming an original payload.
/// Dropping an unused shell frees its allocation before returning the original credit.
pub struct ReservedChargedShared<T>(Reserved<T, AllocationCharge>);

impl<T> ReservedChargedShared<T> {
    /// Whether this exact original shell retains the supplied finite pool.
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.0.charge().belongs_to(budget)
    }

    /// Move the original payload into its already allocated shell without allocating.
    pub fn initialize(self, value: T) -> ChargedShared<T> {
        ChargedShared(self.0.initialize(value))
    }
}

/// Refusal to allocate one shared shell from its exact original layout charge.
/// Every failure returns the same charge, without refunding or reacquiring it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SharedFromChargeError {
    /// Size or alignment differs from the actual concrete shared allocation.
    LayoutMismatch {
        /// Layout required by the concrete payload, reference count and charge.
        expected: Layout,
        /// Layout retained by the original charge.
        actual: Layout,
    },
    /// Physical allocation refused the already prepaid concrete shared layout.
    Allocator {
        /// Exact layout refused by the allocator.
        layout: Layout,
    },
}
impl fmt::Display for SharedFromChargeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LayoutMismatch { expected, actual } => write!(
                f,
                "shared shell requires {expected:?} but original charge covers {actual:?}"
            ),
            Self::Allocator { layout } => write!(
                f,
                "failed to allocate {} prepaid shared bytes with alignment {}",
                layout.size(),
                layout.align()
            ),
        }
    }
}
impl std::error::Error for SharedFromChargeError {}

/// Local failure before a complete shared allocation can be returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrepaidSharedError {
    /// The original parent's unchanged remainder cannot fund this exact layout.
    Reservation(InsufficientReservation),
    /// The physical allocator refused an already admitted nonzero layout.
    Allocator {
        /// Exact requested control allocation bytes, including inline payload.
        requested_bytes: usize,
    },
}

impl fmt::Display for PrepaidSharedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reservation(error) => error.fmt(f),
            Self::Allocator { requested_bytes } => write!(
                f,
                "failed to allocate {requested_bytes} admitted shared bytes"
            ),
        }
    }
}
impl std::error::Error for PrepaidSharedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Reservation(error) => Some(error),
            Self::Allocator { .. } => None,
        }
    }
}

impl<T> ChargedShared<T> {
    /// Exact concrete layout of the shared control block, inline T and charge.
    /// This is nonzero even for a zero-sized payload; it includes reference custody.
    pub fn allocation_layout() -> Layout {
        Shared::<T, AllocationCharge>::layout()
    }

    /// Allocate one shell using its already admitted exact original charge.
    ///
    /// No capacity is acquired, refunded or substituted. A refused allocation
    /// returns the identical charge, allowing the original partial owner to retry
    /// without releasing sibling allocations or granting replacement credit.
    ///
    /// # Errors
    /// Rejects a size/alignment mismatch before allocator work, or returns the
    /// original charge and exact layout on physical allocation refusal.
    pub fn reserve_from_charge(
        charge: AllocationCharge,
    ) -> Result<ReservedChargedShared<T>, (AllocationCharge, SharedFromChargeError)> {
        let expected = Self::allocation_layout();
        if charge.layout() != expected {
            let actual = charge.layout();
            return Err((
                charge,
                SharedFromChargeError::LayoutMismatch { expected, actual },
            ));
        }
        Reserved::try_new(charge)
            .map(ReservedChargedShared)
            .map_err(|(charge, error)| {
                (
                    charge,
                    SharedFromChargeError::Allocator {
                        layout: error.layout(),
                    },
                )
            })
    }

    /// Reserve the exact physical shell before entering a consuming transition.
    ///
    /// # Errors
    /// A short parent remains unchanged; physical refusal releases only the split credit.
    pub fn reserve_from(
        reservation: &mut AllocationReservation,
    ) -> Result<ReservedChargedShared<T>, PrepaidSharedError> {
        let charge = reservation
            .try_split(Self::allocation_layout())
            .map_err(PrepaidSharedError::Reservation)?;
        Reserved::try_new(charge)
            .map(ReservedChargedShared)
            .map_err(|(charge, error)| {
                drop(charge);
                PrepaidSharedError::Allocator {
                    requested_bytes: error.layout().size(),
                }
            })
    }

    /// Whether this exact shared control allocation belongs to the supplied pool.
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.0.charge().belongs_to(budget)
    }

    /// Split this exact layout from the original parent before allocating it.
    ///
    /// No new pool admission or wait occurs, even after the original pool shrinks.
    /// The returned owner retains the split credit through its final clone.
    ///
    /// # Errors
    /// A short parent returns the original value and typed shortage without
    /// changing the reservation or invoking the allocator. A physical failure
    /// returns the original value, refunds the split charge and leaves the
    /// parent's unspent remainder intact. The payload is never cloned or dropped
    /// by a failed construction; its existing nested owners remain with the caller.
    pub fn from_reservation(
        value: T,
        reservation: &mut AllocationReservation,
    ) -> Result<Self, (T, PrepaidSharedError)> {
        let layout = Self::allocation_layout();
        let charge = match reservation.try_split(layout) {
            Ok(charge) => charge,
            Err(error) => return Err((value, PrepaidSharedError::Reservation(error))),
        };
        match Shared::try_new(value, charge) {
            Ok(owner) => Ok(Self(owner)),
            Err((value, charge, error)) => {
                // No control allocation exists. Only its split credit returns;
                // the caller still owns the unchanged input value and remainder.
                drop(charge);
                Err((
                    value,
                    PrepaidSharedError::Allocator {
                        requested_bytes: error.layout().size(),
                    },
                ))
            }
        }
    }

    /// Whether two handles retain exactly the same original control allocation.
    pub fn ptr_eq(left: &Self, right: &Self) -> bool {
        Shared::ptr_eq(&left.0, &right.0)
    }
}

impl<T: crate::shared::SharedWake> ChargedShared<T> {
    /// Move this exact charged reference into an allocation-free runtime waker.
    /// Clones and callbacks retain the same allocation through its final owner.
    pub fn into_waker(self) -> std::task::Waker {
        self.0.into_waker()
    }
}

impl<T> Clone for ChargedShared<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<T> Deref for ChargedShared<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T: fmt::Debug> fmt::Debug for ChargedShared<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}
