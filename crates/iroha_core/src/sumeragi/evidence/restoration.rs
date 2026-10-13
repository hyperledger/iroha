//! Retained original-cut lane reauthentication before a restored evidence table is usable.
use super::*;
use crate::sumeragi::{
    evidence_history::{LaneEvidenceRead, VerifiedNativeEvidence},
    runtime_availability::history::HistoryCapture,
};
use iroha_data_model::block::consensus::{EvidenceScope, LaneEvidenceScope};

struct RestoredLane {
    key: Hash,
    frame: ChargedBuffer<u8>,
    scope: LaneEvidenceScope,
    native: NativeEvidence,
    read: LaneEvidenceRead,
    verified: Option<VerifiedNativeEvidence>,
}
/// Original State and proof frames remain in this job across every local read refusal.
pub(super) struct RestorationRead {
    generation: u64,
    tip: Option<NativeExecutionTip>,
    lanes: ChargedBuffer<RestoredLane>,
    sccp: Option<SccpJob>,
}
struct SccpJob {
    read: crate::sumeragi::runtime_availability::history::sccp::SccpHistoryRead,
    reducer: crate::smartcontracts::isi::sccp::forgery::SccpRestore,
}
/// An absent/early/non-Global original cut cannot authenticate SCCP claims in either
/// current or predecessor state. Inspect the union of current and nonempty undo values:
/// every value in that union occurs in one of the two exact cuts; undo `None` adds none.
fn require_no_sccp_claims(state: &State) -> Result<(), EvidenceAdmissionError> {
    let records = state.world.consensus_evidence.snapshot();
    let has_record = records
        .current()
        .iter()
        .map(|(_, record)| record)
        .chain(
            records
                .revert_map()
                .iter()
                .filter_map(|(_, old)| old.as_ref()),
        )
        .any(|record| {
            record.native_evidence().is_none()
                || matches!(
                    record.attribution.scope,
                    EvidenceScope::SccpGeneration { .. }
                )
        });
    let offences = state.world.sccp_forgery_offences.snapshot();
    let has_offence = !offences.current().is_empty()
        || offences.revert_map().iter().any(|(_, old)| old.is_some());
    let maximum = state.world.sccp_forgery_max_generation.view();
    let previous = state.world.sccp_forgery_max_generation.predecessor_view();
    let has_maximum =
        maximum.get().is_some() || previous.get().as_ref().is_some_and(Option::is_some);
    if has_record || has_offence || has_maximum {
        return Err(invalid("SCCP restore has no original Global history"));
    }
    Ok(())
}

impl RestorationRead {
    fn capture(
        state: &State,
        view: &StateView<'_>,
        generation: u64,
    ) -> Result<Self, EvidenceAdmissionError> {
        let capacity = committed_evidence_capacity(view.world());
        if capacity.record_capacity_exceeded || capacity.byte_capacity_exceeded {
            return Err(invalid("restored evidence exceeds canonical capacity"));
        }
        let sccp = if view.native_execution_tip().is_some_and(|tip| {
            tip.height() >= 2
                && tip.root_scope() == iroha_data_model::block::consensus::SumeragiRootScope::Global
        }) {
            let read = crate::sumeragi::runtime_availability::history::sccp::SccpHistoryRead::new(
                HistoryCapture::for_sccp(state, view, generation)
                    .map_err(EvidenceAdmissionError::Source)?
                    .ok_or_else(|| invalid("SCCP restore lacks original native history"))?,
            );
            let reducer = crate::smartcontracts::isi::sccp::forgery::SccpRestore::new(
                state,
                read.tip_height(),
                read.budget(),
            )?;
            Some(SccpJob { read, reducer })
        } else {
            require_no_sccp_claims(state)?;
            None
        };
        let count = view
            .world()
            .consensus_evidence()
            .iter()
            .filter(|(_, record)| matches!(record.attribution.scope, EvidenceScope::Lane(_)))
            .count();
        let budget = state.evidence_preparation_budget();
        let mut lanes =
            ChargedBuffer::new(count, budget).map_err(EvidencePreparationError::from)?;
        for (key, record) in view.world().consensus_evidence().iter() {
            let EvidenceScope::Lane(scope) = record.attribution.scope else {
                continue;
            };
            let proof = record
                .native_evidence()
                .ok_or_else(|| invalid("SCCP material cannot enter native restoration"))?;
            if *key != evidence_key(proof)
                || scope.admission_parent_height.checked_add(1) != Some(record.recorded_at_height)
            {
                return Err(invalid("restored lane admission source differs"));
            }
            let capture = HistoryCapture::from_view(state, view, generation)
                .map_err(EvidenceAdmissionError::Source)?
                .ok_or_else(|| {
                    invalid("restored lane evidence lacks its original native execution tip")
                })?;
            let mut frame = ChargedBuffer::new(evidence_encoded_len(proof), budget)
                .map_err(EvidencePreparationError::from)?;
            frame
                .append(proof.native_frame())
                .map_err(|_| EvidencePreparationError::Invariant)?;
            let native = proof
                .decode_native()
                .map_err(EvidenceAdmissionError::from)?;
            let height = super::super::evidence_history::subject(&native).1;
            lanes
                .try_push(RestoredLane {
                    key: *key,
                    frame,
                    scope,
                    native,
                    read: LaneEvidenceRead::new(capture, scope, height),
                    verified: None,
                })
                .map_err(|_| EvidencePreparationError::Invariant)?;
        }
        Ok(Self {
            generation,
            tip: view.native_execution_tip(),
            lanes,
            sccp,
        })
    }
    fn matches(&self, view: &StateView<'_>, generation: u64) -> bool {
        if self.generation != generation || self.tip != view.native_execution_tip() {
            return false;
        }
        let mut current = view
            .world()
            .consensus_evidence()
            .iter()
            .filter(|(_, record)| matches!(record.attribution.scope, EvidenceScope::Lane(_)));
        self.lanes.as_slice().iter().all(|source| {
            current.next().is_some_and(|(key, record)| {
                *key == source.key
                    && record.attribution.scope == EvidenceScope::Lane(source.scope)
                    && record
                        .native_evidence()
                        .is_some_and(|proof| proof.native_frame() == source.frame.as_slice())
            })
        }) && current.next().is_none()
    }
    fn complete(&mut self, state: &State) -> Result<(), EvidenceAdmissionError> {
        if let Some(job) = &mut self.sccp {
            let budget = job.read.budget().clone();
            let network = job.read.network();
            job.read
                .poll::<EvidenceAdmissionError>(|source, instance| {
                    job.reducer
                        .consume(source, instance, network, &budget, state)
                })?;
        }
        for lane in self.lanes.as_mut_slice() {
            if lane.verified.is_none() {
                let verified = lane.read.poll(&lane.native)?;
                if Some(verified.tip()) != self.tip
                    || verified.scope() != EvidenceScope::Lane(lane.scope)
                {
                    return Err(EvidencePreparationError::Invariant.into());
                }
                lane.verified = Some(verified);
            }
        }
        Ok(())
    }
    pub(super) fn validate_sccp(&self) -> Result<(), EvidenceAdmissionError> {
        if let Some(job) = &self.sccp {
            if !job.read.is_complete() || !job.reducer.is_complete() {
                return Err(invalid(
                    "SCCP original interval and both cuts are not sealed",
                ));
            }
        }
        Ok(())
    }
    pub(super) fn verified(&self, key: &Hash) -> Option<&VerifiedNativeEvidence> {
        self.lanes
            .as_slice()
            .iter()
            .find(|lane| &lane.key == key)?
            .verified
            .as_ref()
    }
}

pub(super) fn validate(state: &State) -> Result<(), EvidenceAdmissionError> {
    let generation = state.state_view_generation();
    if generation % 2 != 0 {
        return Err(EvidencePreparationError::OriginalHistoryPending.into());
    }
    let Some(mut cache) = state.native_evidence_admission.try_lock() else {
        return Err(EvidencePreparationError::OriginalHistoryPending.into());
    };
    let view = state.view();
    if cache
        .restore
        .as_ref()
        .is_some_and(|read| !read.matches(&view, generation))
    {
        cache.restore = None;
    }
    if cache.restore.is_none() {
        cache.restore = Some(RestorationRead::capture(state, &view, generation)?);
    }
    drop(view);
    let result = cache
        .restore
        .as_mut()
        .expect("original restore cut")
        .complete(state);
    if let Err(error) = result {
        if !crate::state::is_stable_state_view_generation(generation, state.state_view_generation())
        {
            cache.restore = None;
            return Err(EvidencePreparationError::OriginalHistoryPending.into());
        }
        if !super::admission::retryable(&error) {
            cache.restore = None;
        }
        return Err(error);
    }
    let view = state.view();
    if !crate::state::is_stable_state_view_generation(generation, state.state_view_generation())
        || !cache
            .restore
            .as_ref()
            .expect("complete original restore cut")
            .matches(&view, generation)
    {
        cache.restore = None;
        return Err(EvidencePreparationError::OriginalHistoryPending.into());
    }
    let mut result = super::validate_persisted_records_inner(
        &view,
        cache
            .restore
            .as_ref()
            .expect("same verified original lane proofs"),
    );
    if !crate::state::is_stable_state_view_generation(generation, state.state_view_generation()) {
        result = Err(EvidencePreparationError::OriginalHistoryPending.into());
    }
    if result.is_ok()
        || result
            .as_ref()
            .is_err_and(|error| !super::admission::retryable(error))
    {
        cache.restore = None;
    }
    result
}
