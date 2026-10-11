//! Native signed evidence admission and bounded local observation custody.
//!
//! The canonical frame carries signed artifacts only. Every admitting execution obtains
//! authority and exact original signer attribution from its immutable native execution tip.
//! Local observations never enter World until a canonical block admits the same proof.

/// Immutable original-pool World evidence values and explicit typed restoration.
pub(crate) mod record;

use crate::state::{
    EvidencePreparationError, NativeExecutionTip, State, StateReadOnly, StateView, WorldReadOnly,
};
use iroha_allocation::{AllocationBudget, ChargedBuffer};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    block::{
        BlockHeader,
        consensus::{
            Evidence, EvidenceAttribution, EvidenceOffender, EvidencePenaltyStatus, EvidenceRecord,
        },
    },
    consensus::NposPenaltyAction,
};
use iroha_sumeragi::message::Evidence as NativeEvidence;
use mv::storage::StorageReadOnly;

/// Maximum number of original reports admitted by one carrier.
pub(crate) const MAX_EVIDENCE_ADMISSIONS_PER_BLOCK: usize = 8;
/// Aggregate canonical proof bytes admitted by one carrier.
pub(crate) const MAX_EVIDENCE_ADMISSION_BYTES: usize =
    iroha_sumeragi::message::MAX_EVIDENCE_FRAME_BYTES;
/// Four maximum global rosters of retained forensic records.
pub(crate) const MAX_COMMITTED_EVIDENCE_RECORDS: usize = 4 * 31;
/// Aggregate canonical proof bytes retained in World.
pub(crate) const MAX_COMMITTED_EVIDENCE_BYTES: usize = 4 * MAX_EVIDENCE_ADMISSION_BYTES;
/// Aggregate canonical proof bytes retained only in this process.
const MAX_LOCAL_EVIDENCE_BYTES: usize = 2 * MAX_EVIDENCE_ADMISSION_BYTES;
const KEY_DOMAIN: &[u8] = b"iroha:native-consensus-evidence:v1\0";

/// An invalid proof is distinct from local original-history or preparation refusal.
#[derive(Debug, thiserror::Error)]
pub(crate) enum EvidenceAdmissionError {
    /// Original signed policy read, retaining unfinished local decode work.
    #[error(transparent)]
    Policy(#[from] crate::execution_attempt::ExecutionAttemptError<String>),
    /// Deterministically invalid signed input, replay or bounded canonical state.
    #[error("native evidence: {0}")]
    Invalid(String),
    /// A source was missing, corrupt or locally refused before authenticated observation.
    #[error("native evidence source: {0}")]
    History(
        crate::execution_attempt::ExecutionAttemptError<
            iroha_data_model::query::error::QueryExecutionFail,
        >,
    ),
    /// An original retained lane read is pending, missing or invalid locally.
    #[error("native lane evidence source: {0}")]
    Source(crate::execution_attempt::ExecutionAttemptError<std::io::Error>),
    /// Original process capacity refused preparation.
    #[error(transparent)]
    Preparation(#[from] EvidencePreparationError),
}
impl From<super::evidence_history::NativeEvidenceError> for EvidenceAdmissionError {
    fn from(error: super::evidence_history::NativeEvidenceError) -> Self {
        use super::evidence_history::NativeEvidenceError;
        match error {
            NativeEvidenceError::History(error) => Self::History(error),
            NativeEvidenceError::Source(error) => Self::Source(error),
            NativeEvidenceError::Preparation(error) => Self::Preparation(error),
            other => Self::Invalid(other.to_string()),
        }
    }
}
impl From<iroha_sumeragi::message::CodecError> for EvidenceAdmissionError {
    fn from(error: iroha_sumeragi::message::CodecError) -> Self {
        if cfg!(all(test, sumeragi_core_mutation = "HC7")) {
            return Self::Invalid(error.to_string());
        }
        match error {
            iroha_sumeragi::message::CodecError::Resource(refusal) => {
                Self::Preparation(EvidencePreparationError::DecodeResource(refusal))
            }
            other => Self::Invalid(other.to_string()),
        }
    }
}
fn invalid(reason: &str) -> EvidenceAdmissionError {
    EvidenceAdmissionError::Invalid(reason.into())
}

/// Exact canonical proof-frame length, shared by block and retained-state bounds.
pub(crate) fn evidence_encoded_len(evidence: &Evidence) -> usize {
    evidence.native_frame().len()
}
/// Overflow-safe aggregate evidence byte accounting.
pub(crate) fn checked_evidence_byte_sum(
    initial: usize,
    lengths: impl IntoIterator<Item = usize>,
    limit: usize,
) -> Option<usize> {
    if initial > limit {
        return None;
    }
    lengths.into_iter().try_fold(initial, |total, length| {
        total.checked_add(length).filter(|next| *next <= limit)
    })
}
/// Domain-separated key of the sole canonical native proof. Pair ordering belongs to its codec.
pub(crate) fn evidence_key(evidence: &Evidence) -> Hash {
    Hash::new_from_writer(|writer| {
        writer.write_all(KEY_DOMAIN)?;
        writer.write_all(evidence.native_frame())
    })
    .expect("incremental evidence hashing is infallible")
}

fn horizon(world: &(impl WorldReadOnly + ?Sized)) -> Result<Option<u64>, EvidenceAdmissionError> {
    Ok(world
        .sumeragi_npos_parameters()?
        .map(|parameters| parameters.evidence_horizon_blocks())
        .filter(|value| *value > 0))
}
/// Borrowed lifecycle fields shared by canonical fixture claims and actual World owners.
/// This observation grants neither funding nor evidence authority.
pub(crate) trait EvidenceLifecycleRecord {
    fn attribution(&self) -> &EvidenceAttribution;
    fn penalty_status(&self) -> EvidencePenaltyStatus;
    fn recorded_at_height(&self) -> u64;
}
impl EvidenceLifecycleRecord for EvidenceRecord {
    fn attribution(&self) -> &EvidenceAttribution {
        &self.attribution
    }
    fn penalty_status(&self) -> EvidencePenaltyStatus {
        self.penalty_status
    }
    fn recorded_at_height(&self) -> u64 {
        self.recorded_at_height
    }
}
impl EvidenceLifecycleRecord for crate::state::RetainedEvidenceRecord {
    fn attribution(&self) -> &EvidenceAttribution {
        &self.attribution
    }
    fn penalty_status(&self) -> EvidencePenaltyStatus {
        self.penalty_status
    }
    fn recorded_at_height(&self) -> u64 {
        self.recorded_at_height
    }
}
/// Terminal root reports remain replay fences through their signed offence horizon. Lane
/// reports retain their exact original incarnation until strictly after retirement admission
/// closes; a native subject height never supplies this root-clock pruning boundary.
pub(crate) fn committed_evidence_record_is_prunable(
    world: &(impl WorldReadOnly + ?Sized),
    record: &(impl EvidenceLifecycleRecord + ?Sized),
    height: u64,
) -> Result<bool, EvidenceAdmissionError> {
    use iroha_data_model::block::consensus::EvidenceScope;
    if !record.penalty_status().is_terminal() {
        return Ok(false);
    }
    let Some(parameters) = world.sumeragi_npos_parameters()? else {
        return Ok(false);
    };
    if parameters.evidence_horizon_blocks() == 0 {
        return Ok(false);
    }
    Ok(match record.attribution().scope {
        EvidenceScope::Root => {
            height.saturating_sub(record.attribution().height)
                > parameters.evidence_horizon_blocks()
        }
        EvidenceScope::Lane(_) if cfg!(all(test, sumeragi_core_mutation = "HC1")) => {
            height.saturating_sub(record.attribution().height)
                > parameters.evidence_horizon_blocks()
        }
        EvidenceScope::Lane(scope) => world.sumeragi_lanes().custody.iter().any(|row| {
            row.validate().is_ok()
                && row.lane == scope.lane
                && row.incarnation == scope.incarnation
                && row.instance == record.attribution().instance
                && row.created_at == scope.created_at
                && scope.admission_parent_height.checked_add(1) == Some(record.recorded_at_height())
                && row
                    .created_at
                    .checked_add(2)
                    .is_some_and(|active| active <= scope.admission_parent_height)
                && row.evidence_horizon == parameters.evidence_horizon_blocks()
                && row.slashing_delay == parameters.slashing_delay_blocks()
                && row.admits_at(record.recorded_at_height()) == Ok(true)
                && row
                    .admission_deadline()
                    .is_ok_and(|deadline| deadline.is_some_and(|deadline| height > deadline))
        }),
    })
}
/// Borrowed count and byte-capacity observation, without copying nested proofs.
pub(crate) struct CommittedEvidenceCapacity {
    pub(crate) record_capacity_exceeded: bool,
    pub(crate) byte_capacity_exceeded: bool,
}
/// Validate retained-table capacity before allocating a penalty plan.
pub(crate) fn committed_evidence_capacity(
    world: &(impl WorldReadOnly + ?Sized),
) -> CommittedEvidenceCapacity {
    let mut count = 0usize;
    let mut bytes = Some(0);
    for (_, record) in world.consensus_evidence().iter() {
        count = count.saturating_add(1);
        if evidence_encoded_len(&record.evidence) > MAX_EVIDENCE_ADMISSION_BYTES {
            bytes = None;
            break;
        }
        bytes = bytes.and_then(|total| {
            checked_evidence_byte_sum(
                total,
                [evidence_encoded_len(&record.evidence)],
                MAX_COMMITTED_EVIDENCE_BYTES,
            )
        });
        if count > MAX_COMMITTED_EVIDENCE_RECORDS || bytes.is_none() {
            break;
        }
    }
    CommittedEvidenceCapacity {
        record_capacity_exceeded: count > MAX_COMMITTED_EVIDENCE_RECORDS,
        byte_capacity_exceeded: bytes.is_none(),
    }
}

/// Exact parent-derived terminal prune plan retains its original backing through application.
pub(crate) fn committed_evidence_prune_keys_from_state(
    state: &State,
    height: u64,
) -> Result<ChargedBuffer<Hash>, EvidenceAdmissionError> {
    let mut keys = ChargedBuffer::new(
        MAX_COMMITTED_EVIDENCE_RECORDS,
        state.evidence_preparation_budget(),
    )
    .map_err(EvidencePreparationError::from)?;
    let view = state.view();
    for (key, record) in view.world().consensus_evidence().iter() {
        if committed_evidence_record_is_prunable(view.world(), record, height)? {
            keys.try_push(*key)
                .map_err(|_| EvidencePreparationError::Invariant)?;
        }
    }
    keys.as_mut_slice().sort_unstable();
    Ok(keys)
}

fn shares_offender(left: &EvidenceAttribution, right: &EvidenceAttribution) -> bool {
    left.instance == right.instance
        && left.epoch == right.epoch
        && left.context_id == right.context_id
        && left.authority_generation == right.authority_generation
        && left.offenders.iter().any(|left| {
            right
                .offenders
                .iter()
                .any(|right| left.peer_id == right.peer_id)
        })
}

/// Original independently verified attribution for exactly one proposed evidence frame.
/// Private fields prevent raw proof or snapshot decoding from manufacturing admission.
/// The exact original graph follows one immutable body into World; metadata alone copies.
pub(crate) struct AdmittedEvidence {
    key: Hash,
    attribution: Option<super::evidence_history::FundedEvidenceAttribution>,
    body: Option<iroha_allocation::ChargedShared<record::EvidenceRecordBody>>,
}
impl AdmittedEvidence {
    fn from_verified(
        key: Hash,
        attribution: super::evidence_history::FundedEvidenceAttribution,
    ) -> Self {
        Self {
            key,
            attribution: Some(attribution),
            body: None,
        }
    }
    pub(crate) fn key(&self) -> Hash {
        self.key
    }
    pub(crate) fn attribution(&self) -> &EvidenceAttribution {
        self.attribution.as_ref().map_or_else(
            || {
                &self
                    .body
                    .as_ref()
                    .expect("completed admitted record")
                    .canonical()
                    .attribution
            },
            |attribution| attribution.get(),
        )
    }
    fn bind_body(
        &mut self,
        frame: &mut Option<ChargedBuffer<u8>>,
        proof_budget: &AllocationBudget,
        budget: &AllocationBudget,
    ) -> Result<(), EvidencePreparationError> {
        if let Some(body) = &self.body {
            return if body.belongs_to(budget)
                && body.attribution_belongs_to(budget)
                && body.proof_belongs_to(proof_budget)
            {
                Ok(())
            } else {
                Err(EvidencePreparationError::Invariant)
            };
        }
        let attribution = self
            .attribution
            .as_ref()
            .ok_or(EvidencePreparationError::Invariant)?;
        let source = frame.as_ref().ok_or(EvidencePreparationError::Invariant)?;
        if !attribution.belongs_to(budget) || !source.belongs_to(proof_budget) {
            return Err(EvidencePreparationError::Invariant);
        }
        let shell = record::EvidenceRecordBody::reserve(budget)?;
        // The shell exists before either exact graph leaves the retained candidate.
        // Refusal preserves the successful attribution and original proof bytes.
        self.body = Some(record::EvidenceRecordBody::initialize(
            shell,
            frame.take().expect("checked original proof"),
            self.attribution
                .take()
                .expect("checked original attribution"),
            budget,
        ));
        Ok(())
    }
    #[cfg(test)]
    fn attribution_belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.attribution.as_ref().map_or_else(
            || {
                self.body.as_ref().is_some_and(|body| {
                    body.belongs_to(budget) && body.attribution_belongs_to(budget)
                })
            },
            |attribution| attribution.belongs_to(budget),
        )
    }
    #[cfg(test)]
    fn allocation_bytes(&self) -> Option<usize> {
        self.attribution.as_ref().map_or_else(
            || self.body.as_ref()?.execution_allocation_bytes(),
            |attribution| attribution.allocation_bytes(),
        )
    }
    fn native_frame(&self) -> Option<&[u8]> {
        self.body
            .as_ref()
            .map(|body| body.canonical().evidence.native_frame())
    }
    pub(crate) fn record(
        &self,
        proof: &Evidence,
        height: u64,
        view: u64,
        timestamp: u64,
    ) -> Result<crate::state::RetainedEvidenceRecord, EvidencePreparationError> {
        let body = self
            .body
            .as_ref()
            .ok_or(EvidencePreparationError::Invariant)?;
        if body.canonical().evidence.native_frame() != proof.native_frame() {
            return Err(EvidencePreparationError::Invariant);
        }
        Ok(crate::state::RetainedEvidenceRecord::from_body(
            body.clone(),
            height,
            view,
            timestamp,
        ))
    }
}

/// Same-block admission can never authorize mandatory slashing.
pub(crate) fn validate_admission_penalty_separation(
    admissions: &[AdmittedEvidence],
    actions: &[NposPenaltyAction],
) -> Result<(), EvidenceAdmissionError> {
    if actions.iter().any(|action| {
        let key = match action {
            NposPenaltyAction::ConsensusSlash(action) => action.evidence_key,
            NposPenaltyAction::MarkConsensusEvidenceApplied(action) => action.evidence_key,
        };
        admissions.iter().any(|admission| admission.key == key)
    }) {
        return Err(invalid("same-block evidence cannot authorize a penalty"));
    }
    Ok(())
}

/// Reauthenticate restored records against actual native execution, including their attribution.
/// A snapshot's key, claimed signer list or decoded context is never authority.
pub(crate) fn validate_persisted_records(state: &State) -> Result<(), EvidenceAdmissionError> {
    restoration::validate(state)
}

fn validate_persisted_records_inner(
    view: &StateView<'_>,
    restored: &restoration::RestorationRead,
) -> Result<(), EvidenceAdmissionError> {
    let capacity = committed_evidence_capacity(view.world());
    if capacity.record_capacity_exceeded || capacity.byte_capacity_exceeded {
        return Err(invalid("restored evidence exceeds canonical capacity"));
    }
    if view.world().consensus_evidence().iter().next().is_none() {
        return Ok(());
    }
    let parameters = view
        .world()
        .sumeragi_npos_parameters()?
        .ok_or_else(|| invalid("restored evidence requires signed NPoS parameters"))?;
    let committed_height =
        u64::try_from(view.height()).map_err(|_| invalid("restored height overflows"))?;
    for (key, record) in view.world().consensus_evidence().iter() {
        if *key != evidence_key(&record.evidence) {
            return Err(invalid("restored proof key differs"));
        }
        let root;
        let verified = match record.attribution.scope {
            iroha_data_model::block::consensus::EvidenceScope::Root => {
                let native = record
                    .evidence
                    .decode_native()
                    .map_err(EvidenceAdmissionError::from)?;
                root = super::evidence_history::verify_from_state(view, &native, |_, _| Ok(()))?;
                &root
            }
            iroha_data_model::block::consensus::EvidenceScope::Lane(_) => restored
                .verified(key)
                .ok_or_else(|| invalid("restored lane proof lacks its retained original reader"))?,
        };
        if !verified.matches_attribution(&record.attribution) {
            return Err(invalid(
                "restored attribution differs from original native history",
            ));
        }
        let within_original_lifetime = match record.attribution.scope {
            iroha_data_model::block::consensus::EvidenceScope::Root => {
                record.attribution.height < record.recorded_at_height
                    && record.recorded_at_height - record.attribution.height
                        <= parameters.evidence_horizon_blocks()
            }
            iroha_data_model::block::consensus::EvidenceScope::Lane(scope) => {
                let mut rows = view
                    .world()
                    .sumeragi_lanes()
                    .custody
                    .iter()
                    .filter(|row| row.incarnation == scope.incarnation);
                rows.next().is_some_and(|row| {
                    row.validate().is_ok()
                        && row.lane == scope.lane
                        && row.instance == record.attribution.instance
                        && row.created_at == scope.created_at
                        && scope.admission_parent_height.checked_add(1)
                            == Some(record.recorded_at_height)
                        && row.evidence_horizon == parameters.evidence_horizon_blocks()
                        && row.slashing_delay == parameters.slashing_delay_blocks()
                        && row.admits_at(record.recorded_at_height) == Ok(true)
                }) && rows.next().is_none()
            }
        };
        if !within_original_lifetime || record.recorded_at_height > committed_height {
            return Err(invalid(
                "restored evidence was not admitted within its original horizon",
            ));
        }
        let carrier_height = usize::try_from(record.recorded_at_height)
            .ok()
            .and_then(std::num::NonZeroUsize::new)
            .ok_or_else(|| invalid("restored carrier height overflows"))?;
        let carrier = view
            .canonical_history()
            .executed_receipt(carrier_height, |_, _| Ok(()))
            .map_err(EvidenceAdmissionError::History)?;
        let header = carrier.block().header();
        if header.view_change_index() != record.recorded_at_view
            || header.creation_time_ms != record.recorded_at_ms
            || !carrier
                .block()
                .npos_consensus_effects()
                .is_some_and(|effects| {
                    effects
                        .evidence_admissions
                        .iter()
                        .any(|proof| proof == &record.evidence)
                })
        {
            return Err(invalid(
                "restored evidence was not included by its original recorded carrier",
            ));
        }
        let due = record
            .recorded_at_height
            .checked_add(parameters.slashing_delay_blocks())
            .ok_or_else(|| invalid("restored penalty height overflows"))?;
        let lifecycle_valid = match record.penalty_status {
            EvidencePenaltyStatus::Pending => committed_height < due,
            EvidencePenaltyStatus::Applied { height } => {
                if height != due || height > committed_height {
                    false
                } else {
                    let position = usize::try_from(height)
                        .ok()
                        .and_then(std::num::NonZeroUsize::new)
                        .ok_or_else(|| invalid("restored penalty carrier height overflows"))?;
                    let carrier = view
                        .canonical_history()
                        .executed_receipt(position, |_, _| Ok(()))
                        .map_err(EvidenceAdmissionError::History)?;
                    carrier.block().npos_consensus_effects().is_some_and(|effects|
                        effects.penalty_actions.iter().any(|action| matches!(action,
                            NposPenaltyAction::MarkConsensusEvidenceApplied(mark) if mark.evidence_key == *key && mark.height == height)))
                }
            }
        };
        if !lifecycle_valid {
            return Err(invalid("restored penalty lifecycle is impossible"));
        }
        for (other_key, other) in view.world().consensus_evidence().iter() {
            if other_key < key && shares_offender(&record.attribution, &other.attribution) {
                return Err(invalid(
                    "restored evidence duplicates original signer accountability",
                ));
            }
        }
    }
    Ok(())
}

/// A local lane observation names an original incarnation, never a global offence height.
#[derive(Clone, Copy)]
struct LocalLane {
    lane: iroha_model_base::topology::LaneId,
    incarnation: [u8; 32],
    instance: [u8; 32],
    created_at: u64,
}
impl LocalLane {
    fn admits_at(
        &self,
        world: &impl WorldReadOnly,
        policy: Option<&iroha_data_model::parameter::system::SumeragiNposParameters>,
        carrier: u64,
    ) -> bool {
        let Some(policy) = policy else {
            return false;
        };
        world.sumeragi_lanes().custody.iter().any(|row| {
            row.validate().is_ok()
                && row.lane == self.lane
                && row.incarnation == self.incarnation
                && row.instance == self.instance
                && row.created_at == self.created_at
                && row.evidence_horizon == policy.evidence_horizon_blocks()
                && row.slashing_delay == policy.slashing_delay_blocks()
                && row.admits_at(carrier) == Ok(true)
        })
    }
}
/// One original charged canonical observation. Lane reports remain untrusted until selection.
struct LocalEvidence {
    key: Hash,
    subject_height: u64,
    lane: Option<LocalLane>,
    frame: ChargedBuffer<u8>,
}
/// Finite flat local pool. Both descriptor backing and canonical frames retain original charges.
#[derive(Default)]
pub(crate) struct NativeEvidencePool {
    entries: Option<ChargedBuffer<LocalEvidence>>,
    bytes: usize,
}
impl NativeEvidencePool {
    fn retain(
        &mut self,
        evidence: &Evidence,
        subject_height: u64,
        lane: Option<LocalLane>,
        budget: &AllocationBudget,
    ) -> Result<bool, EvidenceAdmissionError> {
        let key = evidence_key(evidence);
        if self
            .entries
            .as_ref()
            .is_some_and(|entries| entries.as_slice().iter().any(|entry| entry.key == key))
        {
            return Ok(false);
        }
        let Some(bytes) = checked_evidence_byte_sum(
            self.bytes,
            [evidence_encoded_len(evidence)],
            MAX_LOCAL_EVIDENCE_BYTES,
        ) else {
            return Ok(false);
        };
        if self
            .entries
            .as_ref()
            .is_some_and(|entries| entries.as_slice().len() == MAX_COMMITTED_EVIDENCE_RECORDS)
        {
            return Ok(false);
        }
        if self.entries.is_none() {
            self.entries = Some(
                ChargedBuffer::new(MAX_COMMITTED_EVIDENCE_RECORDS, budget)
                    .map_err(EvidencePreparationError::from)?,
            );
        }
        let mut frame = ChargedBuffer::new(evidence_encoded_len(evidence), budget)
            .map_err(EvidencePreparationError::from)?;
        frame
            .append(evidence.native_frame())
            .map_err(|_| EvidencePreparationError::Invariant)?;
        self.entries
            .as_mut()
            .expect("original descriptor backing exists")
            .try_push(LocalEvidence {
                key,
                subject_height,
                lane,
                frame,
            })
            .map_err(|_| EvidencePreparationError::Invariant)?;
        self.entries
            .as_mut()
            .unwrap()
            .as_mut_slice()
            .sort_unstable_by_key(|entry| entry.key);
        self.bytes = bytes;
        Ok(true)
    }
    fn prune(
        &mut self,
        committed: &impl WorldReadOnly,
        height: u64,
    ) -> Result<(), EvidenceAdmissionError> {
        let Some(entries) = &mut self.entries else {
            return Ok(());
        };
        let policy = committed.sumeragi_npos_parameters()?;
        let horizon = policy
            .as_ref()
            .map(|parameters| parameters.evidence_horizon_blocks())
            .filter(|value| *value > 0);
        let mut index = 0;
        while index < entries.as_slice().len() {
            let entry = &entries.as_slice()[index];
            if committed.consensus_evidence().get(&entry.key).is_some()
                || entry.lane.map_or_else(
                    || {
                        horizon.is_some_and(|horizon| {
                            height.saturating_sub(entry.subject_height) > horizon
                        })
                    },
                    |lane| !lane.admits_at(committed, policy.as_ref(), height),
                )
            {
                let last = entries.as_slice().len() - 1;
                entries.as_mut_slice().swap(index, last);
                let removed = entries.pop().expect("the selected entry remains owned");
                self.bytes -= removed.frame.as_slice().len();
                drop(removed);
            } else {
                index += 1;
            }
        }
        entries
            .as_mut_slice()
            .sort_unstable_by_key(|entry| entry.key);
        Ok(())
    }
}

/// Independently validate a reducer observation and retain only its bounded canonical bytes.
/// Finalized World and stake remain unchanged. The actual candidate reauthenticates the proof.
pub(crate) fn observe(
    state: &State,
    native: &NativeEvidence,
) -> Result<bool, EvidenceAdmissionError> {
    let evidence = Evidence::from_native(native).map_err(EvidenceAdmissionError::from)?;
    let generation = state.state_view_generation();
    let view = state.view();
    let Some(horizon) = horizon(view.world())? else {
        return Ok(false);
    };
    let height =
        u64::try_from(view.height()).map_err(|_| invalid("local history height overflows"))?;
    let (_, subject_height, _) = super::evidence_history::subject(native);
    if height.saturating_sub(subject_height) > horizon {
        return Ok(false);
    }
    super::evidence_history::verify_from_state(&view, native, |_, _| Ok(()))?;
    if generation != state.state_view_generation() || generation % 2 != 0 {
        return Ok(false);
    }
    let mut pending = state.native_pending_evidence.lock();
    pending.prune(view.world(), height)?;
    pending.retain(
        &evidence,
        subject_height,
        None,
        state.evidence_preparation_budget(),
    )
}

/// Keep only bounded canonical bytes from this lane reducer. This is deliberately not
/// authentication or monetary admission: the proposer and every follower independently read
/// original global custody and complete native ancestry before publishing any attribution.
pub(crate) fn observe_lane(
    state: &State,
    lane: iroha_model_base::topology::LaneId,
    incarnation: [u8; 32],
    native: &NativeEvidence,
) -> Result<bool, EvidenceAdmissionError> {
    let (instance, subject_height, _) = super::evidence_history::subject(native);
    let generation = state.state_view_generation();
    let view = state.view();
    let Some(carrier) = (view.height() as u64).checked_add(1) else {
        return Ok(false);
    };
    let mut matching = view
        .world()
        .sumeragi_lanes()
        .custody
        .iter()
        .filter(|row| row.lane == lane && row.incarnation == incarnation);
    let Some(row) = matching.next() else {
        return Ok(false);
    };
    if matching.next().is_some() || row.instance != instance.0 || subject_height == 0 {
        return Ok(false);
    }
    let scope = LocalLane {
        lane,
        incarnation,
        instance: instance.0,
        created_at: row.created_at,
    };
    if !scope.admits_at(
        view.world(),
        view.world().sumeragi_npos_parameters()?.as_ref(),
        carrier,
    ) {
        return Ok(false);
    }
    let evidence = Evidence::from_native(native).map_err(EvidenceAdmissionError::from)?;
    if !crate::state::is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Ok(false);
    }
    let mut pending = state.native_pending_evidence.lock();
    pending.prune(view.world(), carrier)?;
    pending.retain(
        &evidence,
        subject_height,
        Some(scope),
        state.evidence_preparation_budget(),
    )
}

/// Capture bounded original frames under one immutable parent, then release all World/pool
/// guards before the shared retained admission reader performs native disk I/O. The final
/// caller rechecks the same generation before publishing any proposal.
pub(crate) fn pending_evidence_admissions(
    state: &State,
    height: u64,
    generation: u64,
) -> Vec<Evidence> {
    let captured = (|| -> Result<ChargedBuffer<ChargedBuffer<u8>>, EvidenceAdmissionError> {
        let view = state.view();
        if !crate::state::is_stable_state_view_generation(generation, state.state_view_generation())
        {
            return Err(EvidencePreparationError::OriginalHistoryPending.into());
        }
        let mut pending = state.native_pending_evidence.lock();
        pending.prune(view.world(), height)?;
        let entries = pending
            .entries
            .as_ref()
            .map_or(&[][..], ChargedBuffer::as_slice);
        let budget = state.evidence_preparation_budget();
        let mut frames =
            ChargedBuffer::new(entries.len(), budget).map_err(EvidencePreparationError::from)?;
        for entry in entries {
            let mut frame = ChargedBuffer::new(entry.frame.as_slice().len(), budget)
                .map_err(EvidencePreparationError::from)?;
            frame
                .append(entry.frame.as_slice())
                .map_err(|_| EvidencePreparationError::Invariant)?;
            frames
                .try_push(frame)
                .map_err(|_| EvidencePreparationError::Invariant)?;
        }
        Ok(frames)
    })();
    let Ok(frames) = captured else {
        return Vec::new();
    };
    let mut selected = Vec::new();
    if frames.as_slice().is_empty() {
        return selected;
    }
    if selected
        .try_reserve_exact(MAX_EVIDENCE_ADMISSIONS_PER_BLOCK)
        .is_err()
    {
        return selected;
    }
    for frame in frames.as_slice() {
        if selected.len() == MAX_EVIDENCE_ADMISSIONS_PER_BLOCK {
            break;
        }
        // TODO(S8): the outgoing proposal model and decoded proof graph still require their
        // complete funded owner. Temporary original source snapshots above are fully charged.
        let mut native = Vec::new();
        if native.try_reserve_exact(frame.as_slice().len()).is_err() {
            break;
        }
        native.extend_from_slice(frame.as_slice());
        selected.push(Evidence { native });
        match admission::prepare_admissions(state, generation, height, &selected) {
            Ok(_) => {}
            Err(error) => {
                selected.pop();
                if admission::retryable(&error) {
                    // Temporary refusal retains the exact original read. Ordinary work may
                    // continue; publication explicitly cancels an obsolete acquisition.
                    break;
                }
                // A terminally failed local source grants no proof authority, but cannot
                // pin unrelated reports behind it. Keep the local observation for repair;
                // never delete or blame its signed input merely because storage failed.
            }
        }
    }
    selected
}

/// Finality controls independently prepared from one pristine State generation.
/// This token has no decoder or public constructor; application consumes it once.
pub(crate) struct PreparedStakingEffects<'state> {
    state: &'state State,
    generation: u64,
    header: BlockHeader,
    tip: Option<NativeExecutionTip>,
    effects_hash: Option<HashOf<iroha_data_model::consensus::NposConsensusEffects>>,
    admissions: ChargedBuffer<AdmittedEvidence>,
    prune: ChargedBuffer<Hash>,
    stake_index: Option<crate::smartcontracts::isi::staking::PublicLaneStakeIndex>,
}
impl PreparedStakingEffects<'_> {
    /// Rejoin the exact State, header and original publication before any execution effect.
    pub(crate) fn apply(
        self,
        state: &mut crate::state::StateBlock<'_>,
        block: &iroha_data_model::block::SignedBlock,
        original: &State,
        generation: u64,
    ) -> eyre::Result<()> {
        if !std::ptr::eq(self.state, original)
            || self.generation != generation
            || original.state_view_generation() != generation
            || generation % 2 != 0
            || self.header != block.header()
            || self.tip != state.native_execution_tip()
            || self.effects_hash != block.npos_consensus_effects().map(HashOf::new)
        {
            return Err(eyre::eyre!(
                "staking effects lost their original pristine native source"
            ));
        }
        if let Some(effects) = block.npos_consensus_effects() {
            state.apply_pristine_npos_consensus_effects(
                effects,
                self.stake_index.as_ref(),
                self.prune.as_slice(),
                self.admissions.as_slice(),
                block.header().height().get(),
                block.header().view_change_index(),
                block.header().creation_time_ms,
            )?;
        } else if !self.admissions.as_slice().is_empty() || !self.prune.as_slice().is_empty() {
            return Err(eyre::eyre!(
                "absent staking effects cannot consume prepared records"
            ));
        }
        Ok(())
    }
}

/// Check candidate evidence and exact deterministic parent penalties before writers are acquired.
pub(crate) fn prepare<'state>(
    state: &'state State,
    block: &iroha_data_model::block::SignedBlock,
    generation: u64,
) -> Result<PreparedStakingEffects<'state>, crate::block::BlockValidationError> {
    use crate::block::BlockValidationError;
    let header = block.header();
    let view = state.view();
    let no_effects = iroha_data_model::consensus::NposConsensusEffects::default();
    let effects = block.npos_consensus_effects().unwrap_or(&no_effects);
    let npos = view
        .world()
        .sumeragi_npos_parameters()
        .map_err(|error| classify(error.into()))?
        .is_some();
    let tip = view.native_execution_tip();
    drop(view);
    let admissions = admission::prepare_admissions(
        state,
        generation,
        header.height().get(),
        &effects.evidence_admissions,
    )
    .map_err(classify)?;
    validate_admission_penalty_separation(admissions.as_slice(), &effects.penalty_actions)
        .map_err(classify)?;
    let (actions, index) = if npos {
        let (actions, index) = super::penalties::PenaltyApplier::new(state, None)
            .derive_npos_penalty_actions(&header)
            .map_err(|error| {
                BlockValidationError::from_npos_application_error(
                    error,
                    "native penalty preparation",
                )
            })?;
        let needs_index = actions
            .iter()
            .any(|action| matches!(action, NposPenaltyAction::ConsensusSlash(_)));
        (actions, needs_index.then_some(index))
    } else {
        (Vec::new(), None)
    };
    if actions != effects.penalty_actions {
        return Err(BlockValidationError::NposEffectsInvalid(
            "penalties differ from exact committed parent derivation".into(),
        ));
    }
    let prune = if block.npos_consensus_effects().is_some() {
        committed_evidence_prune_keys_from_state(state, header.height().get()).map_err(classify)?
    } else {
        ChargedBuffer::new(0, state.evidence_preparation_budget())
            .map_err(EvidencePreparationError::from)
            .map_err(BlockValidationError::EvidencePreparation)?
    };
    if state.state_view_generation() != generation || generation % 2 != 0 {
        return Err(BlockValidationError::LocalStorageRecoveryRequired {
            reason: "native evidence parent changed during pristine preparation".into(),
        });
    }
    Ok(PreparedStakingEffects {
        state,
        generation,
        header,
        tip,
        effects_hash: block.npos_consensus_effects().map(HashOf::new),
        admissions,
        prune,
        stake_index: index,
    })
}
fn classify(error: EvidenceAdmissionError) -> crate::block::BlockValidationError {
    use crate::block::BlockValidationError;
    if matches!(
        &error,
        EvidenceAdmissionError::Source(crate::execution_attempt::ExecutionAttemptError::Rejected(
            _
        )) | EvidenceAdmissionError::History(
            crate::execution_attempt::ExecutionAttemptError::Rejected(_)
        )
    ) && admission::retryable(&error)
    {
        return BlockValidationError::EvidencePreparation(
            EvidencePreparationError::OriginalHistoryPending,
        );
    }
    match error {
        EvidenceAdmissionError::Policy(
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason),
        ) => BlockValidationError::ExecutionDeferred(reason),
        EvidenceAdmissionError::Policy(
            crate::execution_attempt::ExecutionAttemptError::Rejected(error),
        ) => BlockValidationError::NposEffectsInvalid(error),
        EvidenceAdmissionError::Preparation(error) => {
            BlockValidationError::EvidencePreparation(error)
        }
        EvidenceAdmissionError::Source(
            crate::execution_attempt::ExecutionAttemptError::Deferred(local),
        ) => BlockValidationError::ExecutionDeferred(local),
        EvidenceAdmissionError::Source(
            crate::execution_attempt::ExecutionAttemptError::Rejected(error),
        ) => BlockValidationError::LocalStorageRecoveryRequired {
            reason: error.to_string(),
        },
        EvidenceAdmissionError::History(
            crate::execution_attempt::ExecutionAttemptError::Deferred(local),
        ) => BlockValidationError::ExecutionDeferred(local),
        EvidenceAdmissionError::History(
            crate::execution_attempt::ExecutionAttemptError::Rejected(error),
        ) => BlockValidationError::LocalStorageRecoveryRequired {
            reason: error.to_string(),
        },
        EvidenceAdmissionError::Invalid(error) => BlockValidationError::NposEffectsInvalid(error),
    }
}

pub(crate) mod admission;

#[cfg(test)]
mod tests;

mod restoration;

#[cfg(test)]
mod codec_tests;

#[cfg(test)]
mod lifecycle_tests;
