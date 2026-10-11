//! One retained original-parent admission attempt, with bounded exact signer replay fences.
//!
//! The caller captures all World reads before dropping its view. Native lane reads subsequently
//! retain their source and pool here. The canonical capacity is unchanged; no live replay fence
//! is evicted. Completed offender vectors/compact keys retain their original execution pool
//! through one immutable World record body. TODO(S8): native proof decoding and BLS/context
//! scratch retain their existing owners; the funded body grants none of that scratch custody.
use super::*;
use crate::sumeragi::{
    evidence_history::LaneEvidenceRead, runtime_availability::history::HistoryCapture,
};
use iroha_data_model::block::consensus::LaneEvidenceScope;
use iroha_data_model::sumeragi_lanes::SumeragiLaneStakeBinding;

#[derive(Clone, Copy, PartialEq, Eq)]
struct OriginalSigner {
    signer: u32,
    key: [u8; 48],
    lane_stake: Option<SumeragiLaneStakeBinding>,
}
impl OriginalSigner {
    fn from_offender(offender: &EvidenceOffender) -> Result<Self, EvidenceAdmissionError> {
        let (algorithm, bytes) = offender
            .peer_id
            .public_key()
            .borrowed_parts()
            .map_err(|_| invalid("retained signer key is malformed"))?;
        if algorithm != iroha_crypto::Algorithm::BlsNormal {
            return Err(invalid(
                "retained signer is outside the native BLS committee",
            ));
        }
        let key = bytes
            .try_into()
            .map_err(|_| invalid("retained signer key has invalid geometry"))?;
        Ok(Self {
            signer: offender.signer,
            key,
            lane_stake: offender.lane_stake,
        })
    }
}
struct ReplayFence {
    key: Hash,
    retained: bool,
    instance: [u8; 32],
    epoch: u64,
    context: [u8; 32],
    generation: [u8; 32],
    first_signer: usize,
    count: usize,
}
impl ReplayFence {
    fn new(
        key: Hash,
        retained: bool,
        attribution: &EvidenceAttribution,
        signers: &mut ChargedBuffer<OriginalSigner>,
    ) -> Result<Self, EvidenceAdmissionError> {
        if attribution.offenders.len() > iroha_sumeragi::types::MAX_COMMITTEE_SIZE
            || !attribution
                .offenders
                .windows(2)
                .all(|pair| pair[0].signer < pair[1].signer)
        {
            return Err(invalid("retained offender geometry is noncanonical"));
        }
        let first_signer = signers.as_slice().len();
        for source in &attribution.offenders {
            signers
                .try_push(OriginalSigner::from_offender(source)?)
                .map_err(|_| EvidencePreparationError::Invariant)?;
        }
        Ok(Self {
            key,
            retained,
            instance: attribution.instance,
            epoch: attribution.epoch,
            context: attribution.context_id,
            generation: attribution.authority_generation,
            first_signer,
            count: attribution.offenders.len(),
        })
    }
    fn shares(
        &self,
        attribution: &EvidenceAttribution,
        signers: &[OriginalSigner],
    ) -> Result<bool, EvidenceAdmissionError> {
        if !self.retained
            || self.instance != attribution.instance
            || self.epoch != attribution.epoch
            || self.context != attribution.context_id
            || self.generation != attribution.authority_generation
        {
            return Ok(false);
        }
        for offender in &attribution.offenders {
            let original = OriginalSigner::from_offender(offender)?;
            let original_signers = signers
                .get(self.first_signer..self.first_signer + self.count)
                .ok_or(EvidencePreparationError::Invariant)?;
            if original_signers
                .iter()
                .any(|retained| retained.key == original.key)
            {
                return Ok(true);
            }
        }
        // Empty-offender safety violations remain exact-hash replay fences only.
        Ok(false)
    }
}
struct Candidate {
    key: Hash,
    frame: Option<ChargedBuffer<u8>>,
    native: NativeEvidence,
    lane: Option<LaneEvidenceRead>,
    verified: Option<AdmittedEvidence>,
}

pub(in crate::sumeragi) struct AdmissionRead {
    generation: u64,
    tip: Option<NativeExecutionTip>,
    carrier: u64,
    fences: ChargedBuffer<ReplayFence>,
    signers: ChargedBuffer<OriginalSigner>,
    candidates: ChargedBuffer<Candidate>,
    admitted: ChargedBuffer<AdmittedEvidence>,
    proof_budget: AllocationBudget,
    execution_budget: AllocationBudget,
}
impl AdmissionRead {
    pub(in crate::sumeragi) fn capture(
        state: &State,
        view: &StateView<'_>,
        generation: u64,
        carrier: u64,
        proofs: &[Evidence],
    ) -> Result<Self, EvidenceAdmissionError> {
        if !crate::state::is_stable_state_view_generation(generation, state.state_view_generation())
        {
            return Err(EvidencePreparationError::OriginalHistoryPending.into());
        }
        if !std::ptr::eq(view.ivm, &state.ivm)
            || !view
                .pipeline_ivm_prepared_cache
                .execution_budget()
                .same_pool(&state.ivm_execution_budget())
            || !std::ptr::eq(view.kura(), state.kura_handle().as_ref())
            || view.network_id() != state.network_id_ref()
            || view.chain_id() != state.chain_id_ref()
        {
            return Err(EvidenceAdmissionError::Source(
                std::io::Error::from(std::io::ErrorKind::InvalidInput).into(),
            ));
        }
        if proofs.len() > MAX_EVIDENCE_ADMISSIONS_PER_BLOCK {
            return Err(invalid("too many evidence admissions"));
        }
        let incoming = checked_evidence_byte_sum(
            0,
            proofs.iter().map(evidence_encoded_len),
            MAX_EVIDENCE_ADMISSION_BYTES,
        )
        .ok_or_else(|| invalid("evidence admission bytes exceed the block limit"))?;
        let capacity = committed_evidence_capacity(view.world());
        if capacity.record_capacity_exceeded || capacity.byte_capacity_exceeded {
            return Err(invalid("retained evidence exceeds its canonical capacity"));
        }
        let tip = view.native_execution_tip();
        if !proofs.is_empty() && tip.and_then(|tip| tip.height().checked_add(1)) != Some(carrier) {
            return Err(invalid(
                "evidence carrier is not the original parent's successor",
            ));
        }
        let budget = state.evidence_preparation_budget();
        let execution_budget = state.ivm_execution_budget();
        if proofs.is_empty() {
            return Ok(Self {
                generation,
                tip,
                carrier,
                fences: ChargedBuffer::new(0, budget).map_err(EvidencePreparationError::from)?,
                signers: ChargedBuffer::new(0, budget).map_err(EvidencePreparationError::from)?,
                candidates: ChargedBuffer::new(0, budget)
                    .map_err(EvidencePreparationError::from)?,
                admitted: ChargedBuffer::new(0, budget).map_err(EvidencePreparationError::from)?,
                proof_budget: budget.clone(),
                execution_budget: execution_budget.clone(),
            });
        }
        let count = view.world().consensus_evidence().iter().count();
        let mut fences =
            ChargedBuffer::new(count, budget).map_err(EvidencePreparationError::from)?;
        let signer_count =
            view.world()
                .consensus_evidence()
                .iter()
                .try_fold(0_usize, |sum, (_, record)| {
                    let count = record.attribution.offenders.len();
                    if count > iroha_sumeragi::types::MAX_COMMITTEE_SIZE {
                        return Err(invalid("retained offender geometry is noncanonical"));
                    }
                    sum.checked_add(count)
                        .ok_or_else(|| invalid("retained signer count overflows"))
                })?;
        let mut signers =
            ChargedBuffer::new(signer_count, budget).map_err(EvidencePreparationError::from)?;
        let mut retained_count = 0;
        let mut retained_bytes = 0;
        for (key, record) in view.world().consensus_evidence().iter() {
            let retained = !committed_evidence_record_is_prunable(view.world(), record, carrier)?;
            if retained {
                retained_count += 1;
                retained_bytes += evidence_encoded_len(&record.evidence);
            }
            fences
                .try_push(ReplayFence::new(
                    *key,
                    retained,
                    &record.attribution,
                    &mut signers,
                )?)
                .map_err(|_| EvidencePreparationError::Invariant)?;
        }
        if retained_count + proofs.len() > MAX_COMMITTED_EVIDENCE_RECORDS
            || checked_evidence_byte_sum(retained_bytes, [incoming], MAX_COMMITTED_EVIDENCE_BYTES)
                .is_none()
        {
            return Err(invalid("retained evidence has no reclaimable capacity"));
        }
        let mut candidates =
            ChargedBuffer::new(proofs.len(), budget).map_err(EvidencePreparationError::from)?;
        let admitted =
            ChargedBuffer::new(proofs.len(), budget).map_err(EvidencePreparationError::from)?;
        let mut previous = None;
        for proof in proofs {
            let parameters = view
                .world()
                .sumeragi_npos_parameters()?
                .filter(|parameters| parameters.evidence_horizon_blocks() > 0)
                .ok_or_else(|| invalid("evidence requires a signed positive NPoS horizon"))?;
            let key = evidence_key(proof);
            if previous.is_some_and(|previous| previous >= key) {
                return Err(invalid("evidence keys must be strictly increasing"));
            }
            if fences.as_slice().iter().any(|fence| fence.key == key) {
                return Err(invalid("evidence is already committed"));
            }
            let mut frame = ChargedBuffer::new(evidence_encoded_len(proof), budget)
                .map_err(EvidencePreparationError::from)?;
            frame
                .append(proof.native_frame())
                .map_err(|_| EvidencePreparationError::Invariant)?;
            let native = proof
                .decode_native()
                .map_err(EvidenceAdmissionError::from)?;
            let (instance, height, _) = super::super::evidence_history::subject(&native);
            let mut matching = view
                .world()
                .sumeragi_lanes()
                .custody
                .iter()
                .filter(|row| row.instance == instance.0);
            let row = matching.next();
            if matching.next().is_some() {
                return Err(invalid("native instance has ambiguous original custody"));
            }
            let (lane, verified) = if let Some(row) = row {
                row.validate().map_err(invalid)?;
                if row.evidence_horizon != parameters.evidence_horizon_blocks()
                    || row.slashing_delay != parameters.slashing_delay_blocks()
                    || row
                        .created_at
                        .checked_add(2)
                        .is_none_or(|active| active >= carrier)
                    || (!cfg!(all(test, sumeragi_core_mutation = "HC4"))
                        && !row.admits_at(carrier).map_err(invalid)?)
                    || !row.covers_native_subject(height).map_err(invalid)?
                {
                    return Err(invalid(
                        "native lane offence is outside original custody admission or coverage",
                    ));
                }
                let tip = tip.expect("a nonempty batch has an original parent");
                let scope = LaneEvidenceScope {
                    lane: row.lane,
                    incarnation: row.incarnation,
                    created_at: row.created_at,
                    admission_parent_height: tip.height(),
                    admission_parent_hash: tip.iroha_hash(),
                    admission_parent_core_hash: tip.core_hash().0,
                    admission_parent_result: tip.result().0,
                };
                let capture = HistoryCapture::from_view(state, view, generation)
                    .map_err(EvidenceAdmissionError::Source)?
                    .ok_or_else(|| invalid("native lane admission has no original history cut"))?;
                (Some(LaneEvidenceRead::new(capture, scope, height)), None)
            } else {
                if height >= carrier || carrier - height > parameters.evidence_horizon_blocks() {
                    return Err(invalid(
                        "offence is not prior to its carrier within the signed horizon",
                    ));
                }
                let verified = super::super::evidence_history::verify_from_state(
                    view,
                    &native,
                    |_, _| Ok(()),
                )?;
                (
                    None,
                    Some(AdmittedEvidence::from_verified(
                        key,
                        verified.into_attribution(),
                    )),
                )
            };
            candidates
                .try_push(Candidate {
                    key,
                    frame: Some(frame),
                    native,
                    lane,
                    verified,
                })
                .map_err(|_| EvidencePreparationError::Invariant)?;
            previous = Some(key);
        }
        Ok(Self {
            generation,
            tip,
            carrier,
            fences,
            signers,
            candidates,
            admitted,
            proof_budget: budget.clone(),
            execution_budget: execution_budget.clone(),
        })
    }
    pub(in crate::sumeragi) fn matches(
        &self,
        generation: u64,
        carrier: u64,
        proofs: &[Evidence],
    ) -> bool {
        self.generation == generation
            && self.carrier == carrier
            && self.candidates.as_slice().len() == proofs.len()
            && self
                .candidates
                .as_slice()
                .iter()
                .zip(proofs)
                .all(|(candidate, proof)| {
                    candidate
                        .frame
                        .as_ref()
                        .map(ChargedBuffer::as_slice)
                        .or_else(|| {
                            candidate
                                .verified
                                .as_ref()
                                .and_then(AdmittedEvidence::native_frame)
                        })
                        == Some(proof.native_frame())
                })
    }
    pub(in crate::sumeragi) fn complete(&mut self) -> Result<(), EvidenceAdmissionError> {
        for index in 0..self.candidates.as_slice().len() {
            if self.candidates.as_slice()[index].verified.is_none() {
                let candidate = &mut self.candidates.as_mut_slice()[index];
                let verified = candidate
                    .lane
                    .as_mut()
                    .expect("an unfinished candidate retains its original lane reader")
                    .poll(&candidate.native)?;
                if Some(verified.tip()) != self.tip {
                    return Err(EvidencePreparationError::Invariant.into());
                }
                candidate.verified = Some(AdmittedEvidence::from_verified(
                    candidate.key,
                    verified.into_attribution(),
                ));
            }
            let current = &self.candidates.as_slice()[index]
                .verified
                .as_ref()
                .expect("independently verified")
                .attribution();
            for fence in self.fences.as_slice() {
                if fence.shares(current, self.signers.as_slice())? {
                    return Err(invalid(
                        "a retained report already accounts for an original signer in this epoch",
                    ));
                }
            }
            if self.candidates.as_slice()[..index].iter().any(|candidate| {
                shares_offender(
                    &candidate
                        .verified
                        .as_ref()
                        .expect("earlier complete candidate")
                        .attribution(),
                    current,
                )
            }) {
                return Err(invalid(
                    "a retained report already accounts for an original signer in this epoch",
                ));
            }
        }
        // Every original proof/authentication/replay guard completes before the new
        // shared shell admission. A later local refusal retains both completed graphs
        // in this same candidate; cache retirement remains generation/tip guarded.
        for candidate in self.candidates.as_mut_slice() {
            candidate
                .verified
                .as_mut()
                .ok_or(EvidencePreparationError::Invariant)?
                .bind_body(
                    &mut candidate.frame,
                    &self.proof_budget,
                    &self.execution_budget,
                )?;
        }
        Ok(())
    }
    pub(in crate::sumeragi) fn finish(
        mut self,
    ) -> Result<ChargedBuffer<AdmittedEvidence>, EvidenceAdmissionError> {
        for candidate in self.candidates.as_mut_slice() {
            self.admitted
                .try_push(
                    candidate
                        .verified
                        .take()
                        .ok_or(EvidencePreparationError::Invariant)?,
                )
                .map_err(|_| EvidencePreparationError::Invariant)?;
        }
        Ok(self.admitted)
    }
}

/// The State owns one bounded original request. A newer publication cancels the obsolete cut;
/// a competing request cannot replace in-progress native acquisition from the same cut.
#[derive(Default)]
pub(crate) struct AdmissionCache {
    pending: Option<AdmissionRead>,
    pub(super) restore: Option<super::restoration::RestorationRead>,
}

pub(super) fn retryable(error: &EvidenceAdmissionError) -> bool {
    use iroha_allocation::AllocationRefusal;
    use iroha_data_model::query::error::{CanonicalHistoryError, QueryExecutionFail};
    if cfg!(all(test, sumeragi_core_mutation = "HC5")) {
        return matches!(
            error,
            EvidenceAdmissionError::Source(_)
                | EvidenceAdmissionError::History(_)
                | EvidenceAdmissionError::Preparation(_)
        );
    }
    match error {
        EvidenceAdmissionError::Policy(crate::execution_attempt::ExecutionAttemptError::Deferred(_)) => true,
        EvidenceAdmissionError::Source(error) => matches!(
            error.io_kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
        ),
        EvidenceAdmissionError::History(crate::execution_attempt::ExecutionAttemptError::Deferred(_)) => true,
        EvidenceAdmissionError::History(crate::execution_attempt::ExecutionAttemptError::Rejected(
            QueryExecutionFail::GasBudgetExceeded | QueryExecutionFail::CapacityLimit
            // Kura still returns Option for this body read. Absence at a committed hash
            // is pending, never evidence of corruption or a reason to blame the proof.
            | QueryExecutionFail::CanonicalHistory(CanonicalHistoryError::BodyUnavailable { .. })
        )) => true,
        EvidenceAdmissionError::Preparation(
            EvidencePreparationError::Admission(AllocationRefusal::Capacity { .. } | AllocationRefusal::ExceedsLimit { .. })
            | EvidencePreparationError::Allocator { .. }
            | EvidencePreparationError::DecodeScope { .. }
            | EvidencePreparationError::DecodeResource(_)
            | EvidencePreparationError::OriginalHistoryPending
        ) => true,
        _ => false,
    }
}

/// Capture World once, drop its view before native I/O, and retain local refusal in the State.
/// Empty carriers do not wait behind an unrelated pending report: the next publication
/// explicitly cancels that old cut. No empty block or observation publication is introduced.
pub(in crate::sumeragi) fn prepare_admissions(
    state: &State,
    generation: u64,
    carrier: u64,
    proofs: &[Evidence],
) -> Result<ChargedBuffer<AdmittedEvidence>, EvidenceAdmissionError> {
    if !crate::state::is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Err(EvidencePreparationError::OriginalHistoryPending.into());
    }
    if proofs.is_empty() {
        let mut read = AdmissionRead::capture(state, &state.view(), generation, carrier, proofs)?;
        read.complete()?;
        return read.finish();
    }
    let Some(mut cache) = state.native_evidence_admission.try_lock() else {
        return Err(EvidencePreparationError::OriginalHistoryPending.into());
    };
    if cache
        .pending
        .as_ref()
        .is_some_and(|pending| pending.generation != generation)
    {
        // Publication makes this exact old acquisition irrelevant. Cancellation drops every
        // original owner; it never silently rebinds an old reader to a later source.
        cache.pending = None;
    }
    if let Some(pending) = cache.pending.as_mut()
        && !pending.matches(generation, carrier, proofs)
    {
        match pending.complete() {
            Err(error) if retryable(&error) => return Err(error),
            Ok(()) | Err(_) => cache.pending = None,
        }
    }
    if cache.pending.is_none() {
        let view = state.view();
        cache.pending = Some(AdmissionRead::capture(
            state, &view, generation, carrier, proofs,
        )?);
        drop(view);
    }
    let result = cache
        .pending
        .as_mut()
        .expect("original pending admission")
        .complete();
    if let Err(error) = result {
        if !retryable(&error) {
            cache.pending = None;
        }
        return Err(error);
    }
    let captured_tip = cache
        .pending
        .as_ref()
        .expect("complete original admission")
        .tip;
    if !crate::state::is_stable_state_view_generation(generation, state.state_view_generation())
        || state.view().native_execution_tip() != captured_tip
        || state.state_view_generation() != generation
    {
        cache.pending = None;
        return Err(EvidencePreparationError::OriginalHistoryPending.into());
    }
    cache
        .pending
        .take()
        .expect("same complete original admission")
        .finish()
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod frame_tests;
