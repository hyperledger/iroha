//! Paid native proposal clock admission retaining exact builder or recovered body custody.

use super::driver::traits::{PublicationDeferral, PublicationError};
use iroha_allocation::{AllocationBudget, ChargedShared};
use iroha_primitives::time::TimeSource;
use iroha_sumeragi::{
    availability::PayloadBytes,
    crypto::SigningError,
    proposal_admission::{ProposalAdmission, ProposalAdmissionOwner, ProposalSigningRequest},
    types::{EpochId, Hash32},
};

/// Original source captured before asynchronous control, authoring or signing work.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProposalSource {
    pub(crate) instance: Hash32,
    pub(crate) epoch: EpochId,
    pub(crate) height: u64,
    pub(crate) view: u64,
    pub(crate) parent_hash: Hash32,
    pub(crate) parent_result: Hash32,
    /// Present when reacquiring the exact completed body after restart.
    pub(crate) block_hash: Option<Hash32>,
}

struct NativeProposalAdmission {
    source: ProposalSource,
    payload: PayloadBytes,
    creation_time: std::time::Duration,
    clock: TimeSource,
}
impl core::fmt::Debug for NativeProposalAdmission {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativeProposalAdmission")
            .field("source", &self.source)
            .field("creation_time", &self.creation_time)
            .finish_non_exhaustive()
    }
}
impl ProposalAdmissionOwner for NativeProposalAdmission {
    fn check(&self, request: &ProposalSigningRequest) -> Result<(), SigningError> {
        let source = self.source;
        if request.instance() != source.instance
            || request.epoch() != source.epoch
            || request.height() != source.height
            || request.view() != source.view
            || request.parent_hash() != source.parent_hash
            || request.parent_result() != source.parent_result
            || source
                .block_hash
                .is_some_and(|hash| request.block_hash() != hash)
            || request.payload() != &self.payload
        {
            return Err(SigningError::InvalidInput);
        }
        if !request.certified() && !cfg!(all(test, sumeragi_core_mutation = "HC356")) {
            let now = self.clock.now();
            if self.creation_time > now {
                return Err(SigningError::ClockAhead {
                    block_time_ms: u64::try_from(self.creation_time.as_millis())
                        .map_err(|_| SigningError::InvalidInput)?,
                    observed_ms: u64::try_from(now.as_millis())
                        .map_err(|_| SigningError::InvalidInput)?,
                    max_clock_drift_ms: 0,
                });
            }
        }
        Ok(())
    }
}

/// Retain the original paid bytes and clock; this grants no block execution authority.
pub(crate) fn capture(
    source: ProposalSource,
    payload: &PayloadBytes,
    creation_time: std::time::Duration,
    clock: &TimeSource,
    budget: &AllocationBudget,
) -> Result<ProposalAdmission, PublicationError> {
    if !payload.admitted_to(budget) {
        return Err(PublicationError::RecoveryRequired(
            "proposal admission changed its original payload pool".into(),
        ));
    }
    let mut reservation = budget
        .try_reserve(ChargedShared::<NativeProposalAdmission>::allocation_layout())
        .map_err(|original| {
            PublicationError::Deferred(
                crate::execution_attempt::ExecutionDeferred::from(original).into(),
            )
        })?;
    let owner = ChargedShared::from_reservation(
        NativeProposalAdmission {
            source,
            payload: payload.clone(),
            creation_time,
            clock: clock.clone(),
        },
        &mut reservation,
    )
    .map_err(|(_, original)| {
        PublicationError::Deferred(PublicationDeferral::SharedControl(original))
    })?;
    Ok(ProposalAdmission::from_owner(
        owner.project::<dyn ProposalAdmissionOwner>(|value| value),
    ))
}
