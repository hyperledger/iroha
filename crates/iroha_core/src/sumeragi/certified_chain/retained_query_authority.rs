//! Persistent custody of the original, once-constructed native query authority.
//!
//! Optional State prepayment precedes every retained material clone. The unchanged
//! query constructor and all original request admissions execute exactly once.
//! Sharing failure moves that same completed graph into its already admitted
//! transient owner; it neither rebuilds authority nor consumes another query debit.

use super::*;
use iroha_allocation::{
    AllocationBudget, AllocationReservation, ChargedShared, PrepaidSharedError,
};

/// The original authority; only the retained variant can escape its request lease.
#[derive(Clone)]
pub(super) enum PrefixAuthority {
    Transient(Arc<VerifiedAuthority>),
    Retained(ChargedShared<RetainedQueryAuthority>),
}
impl PrefixAuthority {
    pub(super) fn projection(&self) -> AuthorityRef<'_> {
        match self {
            Self::Transient(original) => original.projection(),
            Self::Retained(original) => original.authority.projection(),
        }
    }
    pub(super) fn material(&self) -> &ValidatorEpochContextV1 {
        self.projection().material
    }
    pub(super) fn retained(&self) -> Option<ChargedShared<RetainedQueryAuthority>> {
        match self {
            Self::Transient(_) => None,
            Self::Retained(original) => Some(original.clone()),
        }
    }
}

/// The actual original material, committee, parsed credentials and pairing scratch.
/// Declaration order destroys every payload allocation before returning its credits;
/// ChargedShared separately retains shell credit through physical deallocation.
pub(super) struct RetainedQueryAuthority {
    authority: VerifiedAuthority,
    payload: AllocationReservation,
}
impl RetainedQueryAuthority {
    pub(super) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.payload.belongs_to(budget)
    }
}

/// Private prepaid custody created before the sole native constructor materializes.
pub(super) struct QueryAuthorityReservation {
    shell: AllocationReservation,
    payload: AllocationReservation,
}

/// Optional cache refusal remains separate from the original native proof verdict.
pub(crate) struct QueryCacheOwner {
    pub(super) budget: AllocationBudget,
    refusal: Option<ExecutionDeferred>,
}
impl QueryCacheOwner {
    pub(crate) fn new(budget: AllocationBudget) -> Self {
        Self {
            budget,
            refusal: None,
        }
    }
    pub(super) fn enabled(&self) -> bool {
        self.refusal.is_none()
    }
    pub(crate) fn refuse(&mut self, original: ExecutionDeferred) {
        if self.refusal.is_none() {
            self.refusal = Some(original);
        }
    }
    pub(super) fn take_refusal(&mut self) -> Option<ExecutionDeferred> {
        self.refusal.take()
    }

    /// Prepay the complete closed native graph before material.clone or construction.
    /// This pure extent walk performs no query admission, source validation or clone.
    pub(super) fn reserve_authority(
        &mut self,
        material: &ValidatorEpochContextV1,
    ) -> Option<QueryAuthorityReservation> {
        if !self.enabled() {
            return None;
        }
        let admitted = (|| {
            let payload_bytes = query_reader::authority_retention_bytes(material)?;
            let shell_bytes = ChargedShared::<RetainedQueryAuthority>::allocation_layout().size();
            let total = payload_bytes.checked_add(shell_bytes).ok_or_else(|| {
                ExecutionDeferred::from(iroha_allocation::AllocationRefusal::DemandOverflow)
            })?;
            let mut payload = self
                .budget
                .try_reserve_bytes(total)
                .map_err(ExecutionDeferred::from)?;
            let shell = payload
                .try_partition_bytes(shell_bytes)
                .map_err(|_| invariant())?;
            Ok(QueryAuthorityReservation { shell, payload })
        })();
        match admitted {
            Ok(original) => Some(original),
            Err(original) => {
                self.refuse(original);
                None
            }
        }
    }

    /// Move the exact completed native value into shared custody, without re-verifying it.
    pub(super) fn retain_authority(
        &mut self,
        authority: VerifiedAuthority,
        reservation: Option<QueryAuthorityReservation>,
    ) -> PrefixAuthority {
        let Some(QueryAuthorityReservation { mut shell, payload }) = reservation else {
            return PrefixAuthority::Transient(Arc::new(authority));
        };
        debug_assert!(shell.belongs_to(&self.budget) && payload.belongs_to(&self.budget));
        let value = RetainedQueryAuthority { authority, payload };
        match share_original(value, &mut shell) {
            Ok(original) => PrefixAuthority::Retained(original),
            Err((RetainedQueryAuthority { authority, payload }, error)) => {
                self.refuse(shared_refusal(error));
                // The unchanged request graph lease and original Arc admission are
                // still live. Move this same graph back to that owner; no second
                // constructor, material clone, codec debit or verifier is invoked.
                let original = PrefixAuthority::Transient(Arc::new(authority));
                drop(payload);
                original
            }
        }
    }
}

fn share_original(
    value: RetainedQueryAuthority,
    shell: &mut AllocationReservation,
) -> Result<ChargedShared<RetainedQueryAuthority>, (RetainedQueryAuthority, PrepaidSharedError)> {
    #[cfg(test)]
    if REFUSE_SHELL.with(|active| active.replace(false)) {
        let material = value.authority.material.committee.as_ptr();
        let committee = value.authority.committee.members().as_ptr();
        let (result, refused) = crate::test_allocations::refuse_one_layout_during(
            ChargedShared::<RetainedQueryAuthority>::allocation_layout(),
            || ChargedShared::from_reservation(value, shell),
        );
        assert!(
            refused,
            "the original authority wrapper reached its actual allocator"
        );
        let Err((original, _)) = &result else {
            panic!("physical wrapper allocation must refuse");
        };
        assert_eq!(
            original.authority.material.committee.as_ptr(),
            material,
            "late refusal returns the exact original epoch allocation"
        );
        assert_eq!(
            original.authority.committee.members().as_ptr(),
            committee,
            "late refusal returns the exact original native committee allocation"
        );
        return result;
    }
    ChargedShared::from_reservation(value, shell)
}

#[cfg(test)]
pub(crate) fn query_authority_shell_layout() -> std::alloc::Layout {
    ChargedShared::<RetainedQueryAuthority>::allocation_layout()
}
#[cfg(test)]
thread_local! { static REFUSE_SHELL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
pub(crate) fn with_refused_query_authority_shell<T>(check: impl FnOnce() -> T) -> T {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            REFUSE_SHELL.with(|active| active.set(false));
        }
    }
    assert!(
        !REFUSE_SHELL.with(|active| active.replace(true)),
        "no nested original wrapper refusal"
    );
    let restore = Restore;
    let result = check();
    assert!(
        !REFUSE_SHELL.with(std::cell::Cell::get),
        "actual authority wrapper must be reached"
    );
    drop(restore);
    result
}

pub(super) fn invariant() -> ExecutionDeferred {
    ivm::error::ExecutionDeferral::LocalInvariantViolation.into()
}
pub(super) fn schedule_refusal(error: schedule::ScheduleError) -> ExecutionDeferred {
    match error {
        schedule::ScheduleError::Admission(original) => original.into(),
        schedule::ScheduleError::Allocator { requested_bytes } => {
            allocator_refusal(requested_bytes)
        }
        _ => invariant(),
    }
}
pub(super) fn shared_refusal(error: PrepaidSharedError) -> ExecutionDeferred {
    match error {
        original @ PrepaidSharedError::Allocator { .. } => {
            iroha_allocation::AllocatorRefusal::try_from(original)
                .expect("matched original shared allocator refusal")
                .into()
        }
        PrepaidSharedError::Reservation(_) => invariant(),
    }
}
pub(super) fn buffer_refusal(error: iroha_allocation::ChargedBufferError) -> ExecutionDeferred {
    match error {
        iroha_allocation::ChargedBufferError::Admission(original) => original.into(),
        original @ iroha_allocation::ChargedBufferError::Allocator { .. } => {
            iroha_allocation::AllocatorRefusal::try_from(original)
                .expect("matched original buffer allocator refusal")
                .into()
        }
    }
}
fn allocator_refusal(requested_bytes: usize) -> ExecutionDeferred {
    iroha_allocation::AllocatorRefusal::try_from(iroha_allocation::ChargedBufferError::Allocator {
        requested_bytes,
    })
    .expect("original retained schedule allocator refusal")
    .into()
}
