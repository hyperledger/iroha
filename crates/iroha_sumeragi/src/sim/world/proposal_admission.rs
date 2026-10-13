//! Original simulator builder custody at the actual first proposal-signing boundary.

use super::*;
use crate::{
    api::ControlWitnessContext,
    availability::PayloadBytes,
    crypto::SigningError,
    proposal_admission::{ProposalAdmission, ProposalAdmissionOwner, ProposalSigningRequest},
};
use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

#[derive(Debug)]
struct SimProposalAdmission {
    instance: Hash32,
    context: ControlWitnessContext,
    payload: PayloadBytes,
    wall: Option<Arc<AtomicI64>>,
}

impl ProposalAdmissionOwner for SimProposalAdmission {
    fn check(&self, request: &ProposalSigningRequest) -> Result<(), SigningError> {
        if request.instance() != self.instance
            || request.epoch() != self.context.epoch
            || request.height() != self.context.height
            || request.view() != self.context.view
            || request.parent_hash() != self.context.parent_hash
            || request.parent_result() != self.context.parent_result
            || request.payload().as_slice() != self.payload.as_slice()
        {
            return Err(SigningError::InvalidInput);
        }
        if request.certified() || cfg!(sumeragi_mutation = "MS70") {
            return Ok(());
        }
        if let Some(wall) = &self.wall
            && let Some(block_time_ms) = crate::sim::driver::block_time(self.payload.as_slice())
        {
            let observed = wall.load(Ordering::Relaxed);
            if i128::from(block_time_ms) > i128::from(observed) {
                return Err(SigningError::ClockAhead {
                    block_time_ms,
                    observed_ms: u64::try_from(observed.max(0)).unwrap(),
                    max_clock_drift_ms: 0,
                });
            }
        }
        Ok(())
    }
}

impl World {
    pub(super) fn original_proposal_admission(
        &self,
        r: usize,
        context: ControlWitnessContext,
        payload: PayloadBytes,
    ) -> ProposalAdmission {
        let machine = self.replicas[r].machine;
        let wall = self
            .clock_guard
            .as_ref()
            .filter(|_| !self.machines[machine].byz)
            .map(|guard| Arc::clone(&guard.signing_walls[machine]));
        let owner = iroha_allocation::shared::Shared::new(
            SimProposalAdmission {
                instance: self.instances[self.replicas[r].inst].id,
                context,
                payload,
                wall,
            },
            (),
        );
        ProposalAdmission::from_owner(owner.project::<dyn ProposalAdmissionOwner>(|value| value))
    }
}
