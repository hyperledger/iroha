//! Cancellation interest for one original local proposal, independent of historical authority.

use crate::execution_attempt::ExecutionAttemptError as Attempt;
use iroha_allocation::{AllocationBudget, ChargedShared};
use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
};

pub(super) struct Control {
    cancelled: AtomicBool,
}

/// One non-cloneable local proposal request. Keep it across every retry of that request.
/// It allocates only when proposal selection first needs a lane, from the exact State pool.
/// Dropping it withdraws only its proposal interest; it cannot revoke historical reads.
#[derive(Default)]
pub struct ProposalReadScope {
    control: Option<ChargedShared<Control>>,
}

impl ProposalReadScope {
    /// Create an unadmitted request without allocating or authorizing a storage operation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub(super) fn admit(&mut self, budget: &AllocationBudget) -> Result<(), Attempt<io::Error>> {
        if self.control.is_some() {
            return self.require_pool(budget);
        }
        let mut reservation = budget
            .try_reserve_bytes(Self::admission_bytes())
            .map_err(|original| Attempt::Deferred(original.into()))?;
        let control = ChargedShared::from_reservation(
            Control {
                cancelled: AtomicBool::new(false),
            },
            &mut reservation,
        )
        .map_err(|(_, error)| match error {
            original @ iroha_allocation::PrepaidSharedError::Reservation(_) => {
                Attempt::Rejected(io::Error::new(io::ErrorKind::InvalidData, original))
            }
            original @ iroha_allocation::PrepaidSharedError::Allocator { .. } => Attempt::Deferred(
                iroha_allocation::AllocatorRefusal::try_from(original)
                    .expect("original physical shared-control refusal")
                    .into(),
            ),
        })?;
        self.control = Some(control);
        Ok(())
    }

    pub(in crate::sumeragi) fn admission_bytes() -> usize {
        ChargedShared::<Control>::allocation_layout().size()
    }

    pub(super) fn require_pool(&self, budget: &AllocationBudget) -> Result<(), Attempt<io::Error>> {
        if self.control.as_ref().is_some_and(|control| {
            control.belongs_to(budget) && !control.cancelled.load(Ordering::Acquire)
        }) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proposal read requires its live original State pool",
            )
            .into())
        }
    }

    #[cfg(test)]
    pub(in crate::sumeragi) fn observation_for_test(&self) -> ProposalReadObservation {
        ProposalReadObservation(
            self.control
                .as_ref()
                .expect("admitted original request")
                .clone(),
        )
    }
    fn cancel(&self) {
        if let Some(control) = &self.control {
            control.cancelled.store(true, Ordering::Release);
        }
    }
}
impl Drop for ProposalReadScope {
    fn drop(&mut self) {
        if !cfg!(all(test, sumeragi_core_mutation = "HC429")) {
            self.cancel();
        }
    }
}

/// Interest in the exact retained job; never a replacement source, schedule or certificate.
#[derive(Clone)]
pub(super) enum ReadInterest {
    Historical,
    Proposal(ChargedShared<Control>),
}
impl ReadInterest {
    pub(super) fn proposal(
        scope: &ProposalReadScope,
        budget: &AllocationBudget,
    ) -> Result<Self, Attempt<io::Error>> {
        scope.require_pool(budget)?;
        Ok(Self::Proposal(
            scope.control.as_ref().expect("admitted request").clone(),
        ))
    }
    #[cfg(test)]
    pub(super) fn cancel_for_cleanup(&self) {
        if let Self::Proposal(control) = self {
            control.cancelled.store(true, Ordering::Release);
        }
    }
    pub(super) fn cancelled(&self) -> bool {
        matches!(self, Self::Proposal(control) if control.cancelled.load(Ordering::Acquire))
    }
    pub(super) fn join(
        &mut self,
        requested: &Self,
        same_height: bool,
    ) -> Result<(), Attempt<io::Error>> {
        match (&*self, requested) {
            (Self::Historical, _) => Ok(()),
            (Self::Proposal(original), Self::Historical) => {
                if same_height {
                    if !cfg!(all(test, sumeragi_core_mutation = "HC430")) {
                        *self = Self::Historical;
                    }
                    Ok(())
                } else if original.cancelled.load(Ordering::Acquire) {
                    Err(busy())
                } else {
                    Ok(())
                }
            }
            (Self::Proposal(original), Self::Proposal(next)) => {
                if ChargedShared::ptr_eq(original, next) {
                    return Ok(());
                }
                // Another live request cannot consume this request's refusal. A cancelled
                // request can transfer only its exact height; the original job is unchanged.
                if (!same_height || !original.cancelled.load(Ordering::Acquire))
                    && !cfg!(all(test, sumeragi_core_mutation = "HC431"))
                {
                    return Err(busy());
                }
                *self = requested.clone();
                Ok(())
            }
        }
    }
}
fn busy() -> Attempt<io::Error> {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "original lane read belongs to another proposal request",
    )
    .into()
}

#[cfg(test)]
pub(in crate::sumeragi) struct ProposalReadObservation(ChargedShared<Control>);
#[cfg(test)]
impl ProposalReadObservation {
    pub(in crate::sumeragi) fn matches(&self, request: &ProposalReadScope) -> bool {
        request
            .control
            .as_ref()
            .is_some_and(|control| ChargedShared::ptr_eq(&self.0, control))
    }
    pub(in crate::sumeragi) fn cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::Acquire)
    }
}
