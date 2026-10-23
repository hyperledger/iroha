//! Original global payload custody under an exact physical parent, lane plan and Queue lease.

use super::*;
use crate::state::NativeExecutionTip;

/// Fixed original source and complete build parameters. Capturing this value creates no authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct OriginalPayloadScope {
    pub(super) height: u64,
    pub(super) view: u64,
    max_bytes: u32,
    exec_budget_ms: u32,
    generation: u64,
    pub(super) parent: Option<NativeExecutionTip>,
}

impl OriginalPayloadScope {
    /// Borrow the actually executed State identity after the caller reads its physical parent.
    pub(super) fn capture(
        state_view: &crate::state::StateView<'_>,
        generation: u64,
        height: u64,
        view: u64,
        max_bytes: u32,
        exec_budget_ms: u32,
    ) -> Self {
        Self {
            height,
            view,
            max_bytes,
            exec_budget_ms,
            generation,
            parent: state_view.native_execution_tip(),
        }
    }

    pub(super) fn matches_request(
        self,
        height: u64,
        view: u64,
        max_bytes: u32,
        exec_budget_ms: u32,
    ) -> bool {
        (self.height, self.view, self.max_bytes, self.exec_budget_ms)
            == (height, view, max_bytes, exec_budget_ms)
    }

    fn matches_tip(self, view: &crate::state::StateView<'_>, applied: (u64, Hash32)) -> bool {
        self.parent.is_some_and(|parent| {
            view.native_execution_tip() == Some(parent)
                && (parent.height(), parent.core_hash()) == applied
                && parent.height().checked_add(1) == Some(self.height)
        })
    }

    pub(super) fn is_current(
        self,
        state: &State,
        view: &crate::state::StateView<'_>,
        applied: (u64, Hash32),
    ) -> bool {
        self.matches_tip(view, applied)
            && crate::state::is_stable_state_view_generation(
                self.generation,
                state.state_view_generation(),
            )
    }

    fn authenticates_physical_parent(self, parent: &SignedBlock) -> bool {
        self.parent.is_some_and(|original| {
            original.height() == parent.header().height().get()
                && original.iroha_hash() == parent.hash()
        })
    }
}

/// Actual build request identity, before any physical parent or lane read can refuse.
/// State publication generations are deliberately absent: they do not cancel a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ProposalReadRequest {
    pub(super) height: u64,
    pub(super) view: u64,
    pub(super) max_bytes: u32,
    pub(super) exec_budget_ms: u32,
    pub(super) applied: (u64, Hash32),
}

/// Fixed cancellation coordinates for the original decoder's authenticated candidate.
/// The decoder retains and compares the complete source; these coordinates grant no authority.
/// This stays outside decoded/overlay owners so cancellation cleanup never runs in their Drop.
pub(super) struct IncomingLaneReads {
    pub(super) instance: Hash32,
    pub(super) height: u64,
    pub(super) view: u64,
    pub(super) block_hash: Hash32,
    pub(super) scope: lanes::ProposalReadScope,
}

/// One original charged payload and selected-input table; shared lends reuse their same backing.
pub(super) struct CompletedPayload {
    pub(super) scope: OriginalPayloadScope,
    pending_inputs: crate::queue::PendingPayloadLease,
    payload: PayloadBytes,
    /// The original source's canonical time, used only for local publication pacing.
    pub(super) creation_time: Duration,
    /// Same charged publication owner is lent on every original-output retry.
    pub(super) proposal_admission: Option<iroha_sumeragi::proposal_admission::ProposalAdmission>,
}

/// Clock waiting keeps the existing driver's timed retry armed without inventing new work.
pub(super) fn check_proposer_clock(
    creation_time: Duration,
    wall_time: Duration,
) -> Result<(), PublicationError> {
    if !cfg!(all(test, sumeragi_core_mutation = "HC260")) && creation_time > wall_time {
        return Err(PublicationError::Retryable(
            "ClockAhead: canonical payload time exceeds the proposer clock".into(),
        ));
    }
    Ok(())
}

/// Preserve the real original pool/allocator refusal before the payload source is constructed.
pub(super) fn lease_admission_error(
    error: iroha_allocation::ChargedBufferError,
) -> PublicationError {
    let original: crate::execution_attempt::ExecutionDeferred = match error {
        iroha_allocation::ChargedBufferError::Admission(original) => original.into(),
        iroha_allocation::ChargedBufferError::Allocator { .. } => {
            ivm::error::ExecutionDeferral::AllocationUnavailable.into()
        }
    };
    PublicationError::Deferred(original.into())
}

impl Worker<'_> {
    pub(super) fn cancel_proposal_reads(&mut self) {
        drop(self.proposal_reads.take());
        self.context.lane_blocks.release_cancelled_proposal_reads();
    }

    pub(super) fn cancel_incoming_lane_reads(&mut self) {
        drop(self.incoming_lane_reads.take());
        self.context.lane_blocks.release_cancelled_proposal_reads();
    }

    /// The original decoder's complete source equality and ordinary authentication checks
    /// precede this interest-only handoff. The fixed key only selects cancellation interest;
    /// source, lane height, original pool, schedule and QC validation remain independent.
    pub(super) fn retain_incoming_lane_reads(
        &mut self,
        source: &AvailableBody,
        block_hash: Hash32,
        references_lanes: bool,
    ) {
        let header = source.header();
        if self.incoming_lane_reads.as_ref().is_some_and(|original| {
            original.instance != header.instance
                || original.height != header.height
                || original.view != header.origin_view
                || original.block_hash != block_hash
        }) {
            self.cancel_incoming_lane_reads();
        }
        if self.incoming_lane_reads.is_none() {
            let handoff = references_lanes
                && !cfg!(all(test, sumeragi_core_mutation = "HC436"))
                && self.parent_applied(source)
                && self.proposal_reads.as_ref().is_some_and(|(request, _)| {
                    request.height == source.header().height && request.applied == self.applied
                });
            let scope = if handoff {
                // The serial executor accepts this candidate in place of its local selection.
                // Move the sole original control, keeping any partial native source intact.
                self.proposal_reads
                    .take()
                    .expect("matching local request")
                    .1
            } else {
                lanes::ProposalReadScope::new()
            };
            self.incoming_lane_reads = Some(IncomingLaneReads {
                instance: header.instance,
                height: header.height,
                view: header.origin_view,
                block_hash,
                scope,
            });
        }
    }

    pub(super) fn retain_proposal_read_request(&mut self, request: ProposalReadRequest) {
        if cfg!(all(test, sumeragi_core_mutation = "HC433"))
            || self
                .proposal_reads
                .as_ref()
                .is_some_and(|(original, _)| *original != request)
        {
            self.cancel_proposal_reads();
        }
        self.proposal_reads
            .get_or_insert_with(|| (request, lanes::ProposalReadScope::new()));
    }

    /// Resume a partial or completed job only under its fresh physical parent, exact current lane
    /// proposal and original Queue admission. A transient refusal preserves the paid job.
    pub(super) fn retained_payload_build_is_current(
        &mut self,
        scope: OriginalPayloadScope,
        physical_parent: &SignedBlock,
        current_view: &crate::state::StateView<'_>,
        merges: &payload::MergeProposal,
    ) -> Result<bool, PublicationError> {
        let Some(original) = self.payload_build.as_ref() else {
            return Ok(false);
        };
        // A real publisher may open after the nonblocking view was acquired.
        // Observe its actual release before the generation probe and retain on Busy.
        let release = self.state.view_publication_release();
        let generation = self.state.state_view_generation();
        if !generation.is_multiple_of(2) {
            return Err(PublicationError::Deferred(
                PublicationDeferral::PublicationBusy(release),
            ));
        }
        let source = original.job.source();
        let same_merges = match source.block.lane_merge() {
            Some(section) => {
                section.merges == merges.merges
                    && section.time_floor_ms == merges.time_floor_ms
                    && section.merged_count == 0
            }
            None => merges.merges.is_empty(),
        };
        let current = if original.scope != scope
            || !crate::state::is_stable_state_view_generation(scope.generation, generation)
            || !scope.matches_tip(current_view, self.applied)
            || !scope.authenticates_physical_parent(physical_parent)
            || !same_merges
        {
            false
        } else if source.block.network_entrypoint_count() == 0 {
            // A lane-only source has no Queue admission to borrow; its exact
            // authenticated ranges above remain mandatory.
            true
        } else {
            match (self.queue.as_ref(), source.pending_inputs.as_ref()) {
                (Some(queue), Some(lease))
                    if lease.belongs_to(&self.state.ivm_execution_budget()) =>
                {
                    queue
                        .pending_payload_lease_wait(self.state, current_view, lease)
                        .map_err(|release| {
                            PublicationError::Deferred(PublicationDeferral::PublicationBusy(
                                release,
                            ))
                        })?
                        .is_some()
                }
                _ => false,
            }
        };
        if !current {
            // The original refund scope outlives this borrowed State view and
            // every Queue guard. Rebuild from the current sources, never old inputs.
            self.payload_build = None;
        }
        Ok(current)
    }

    /// Reclaim only proven selected-input withdrawal without acquiring a State view.
    /// Lane-only work has no Queue residence deadline and stays owned for source retry.
    pub(super) fn partial_payload_expiry_wait(&mut self) -> Option<Duration> {
        let Some(original) = self.payload_build.as_ref() else {
            return None;
        };
        let source = original.job.source();
        if source.block.network_entrypoint_count() == 0 {
            return None;
        }
        let wait = match (self.queue.as_ref(), source.pending_inputs.as_ref()) {
            (Some(queue), Some(lease)) if lease.belongs_to(&self.state.ivm_execution_budget()) => {
                queue.pending_payload_lease_expiry_wait(self.state, lease)
            }
            _ => None,
        };
        if wait.is_none() {
            // The actual Queue fence retires before the original pool can refund.
            self.payload_build = None;
        }
        wait
    }

    /// Reclaim original partial or completed storage at actual input expiry,
    /// source withdrawal or Queue mutation. This changes no Core timer.
    pub(super) fn payload_storage_wait(&mut self) -> Option<Duration> {
        let partial_wait = self.partial_payload_expiry_wait();
        let completed_wait = self.completed_payload.as_ref().and_then(|original| {
            let queue = self.queue.as_ref()?;
            match self.state.try_view_once() {
                Ok(view) => {
                    if !original.scope.matches_tip(&view, self.applied) {
                        return None;
                    }
                    match queue.pending_payload_lease_wait(
                        self.state,
                        &view,
                        &original.pending_inputs,
                    ) {
                        Ok(wait) => wait,
                        Err(_) => queue.pending_payload_lease_expiry_wait(
                            self.state,
                            &original.pending_inputs,
                        ),
                    }
                }
                // This nonblocking reader retains its original physical Busy source.
                // Expiry/mutation checks keep storage only; they never authorize a lend.
                Err(crate::state::StateViewError::Busy(_)) => {
                    queue.pending_payload_lease_expiry_wait(self.state, &original.pending_inputs)
                }
                Err(_) => None,
            }
        });
        if completed_wait.is_none() {
            // Original State and Queue guards retire before this backing can refund.
            self.completed_payload = None;
        }
        match (partial_wait, completed_wait) {
            (Some(partial), Some(completed)) => Some(partial.min(completed)),
            (Some(wait), None) | (None, Some(wait)) => Some(wait),
            (None, None) => None,
        }
    }

    /// Only a fresh physical canonical parent and current original Queue lease permit a lend.
    pub(super) fn reusable_completed_payload(
        &mut self,
        scope: OriginalPayloadScope,
        physical_parent: &SignedBlock,
        current_view: &crate::state::StateView<'_>,
    ) -> Result<Option<PayloadBytes>, PublicationError> {
        let reusable = match self.completed_payload.as_ref() {
            None => return Ok(None),
            Some(original) => {
                if original.scope != scope
                    || !scope.matches_tip(current_view, self.applied)
                    || !scope.authenticates_physical_parent(physical_parent)
                    || !original
                        .payload
                        .admitted_to(&self.state.ivm_execution_budget())
                    || !original
                        .pending_inputs
                        .belongs_to(&self.state.ivm_execution_budget())
                {
                    false
                } else if let Some(queue) = self.queue.as_ref() {
                    queue
                        .pending_payload_lease_wait(
                            self.state,
                            current_view,
                            &original.pending_inputs,
                        )
                        .map_err(|release| {
                            PublicationError::Deferred(PublicationDeferral::PublicationBusy(
                                release,
                            ))
                        })?
                        .is_some()
                } else {
                    false
                }
            }
        };
        if !reusable {
            // Queue guards above have retired; the caller's original refund scope
            // retains same-pool callbacks until its borrowed State view also retires.
            self.completed_payload = None;
            return Ok(None);
        }
        let original = self
            .completed_payload
            .as_ref()
            .expect("exact owner checked above");
        check_proposer_clock(original.creation_time, self.context.time_source.now())?;
        Ok(Some(original.payload.clone()))
    }

    /// Keep the original nonempty funded output only while its captured queue inputs remain live.
    pub(super) fn retain_completed_payload(
        &mut self,
        scope: OriginalPayloadScope,
        pending_inputs: Option<crate::queue::PendingPayloadLease>,
        payload: &PayloadBytes,
        creation_time: Duration,
    ) {
        let current = pending_inputs.as_ref().is_some_and(|lease| {
            if payload.as_slice().len() > scope.max_bytes as usize
                || !payload.admitted_to(&self.state.ivm_execution_budget())
                || !lease.belongs_to(&self.state.ivm_execution_budget())
            {
                return false;
            }
            let Some(queue) = self.queue.as_ref() else {
                return false;
            };
            match self.state.try_view_once() {
                Ok(view) => {
                    scope.matches_tip(&view, self.applied)
                        && match queue.pending_payload_lease_wait(self.state, &view, lease) {
                            Ok(wait) => wait.is_some(),
                            Err(_) => queue
                                .pending_payload_lease_expiry_wait(self.state, lease)
                                .is_some(),
                        }
                }
                Err(crate::state::StateViewError::Busy(_)) => queue
                    .pending_payload_lease_expiry_wait(self.state, lease)
                    .is_some(),
                Err(_) => false,
            }
        });
        self.completed_payload = if current {
            Some(CompletedPayload {
                scope,
                pending_inputs: pending_inputs.expect("exact original lease checked above"),
                payload: payload.clone(),
                creation_time,
                proposal_admission: None,
            })
        } else {
            None
        };
    }

    /// Actual execution/discard of this height consumes the builder's retained original.
    pub(super) fn retire_completed_payload(&mut self, height: u64) {
        if self
            .completed_payload
            .as_ref()
            .is_some_and(|original| original.scope.height == height)
        {
            self.completed_payload = None;
        }
        if self
            .payload_build
            .as_ref()
            .is_some_and(|original| original.scope.height == height && original.job.is_completed())
        {
            self.payload_build = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sumeragi::{driver::traits::BlockStore, test_chain::CertifiedTestChain};

    fn queue_work(
        chain: &CertifiedTestChain,
        created_ms: u64,
        queue: &Queue,
        time: &iroha_primitives::time::TimeSource,
    ) -> iroha_crypto::HashOf<iroha_data_model::transaction::TransactionEntrypoint> {
        let accepted = crate::tx::AcceptedTransaction::accept_with_time_source(
            chain.tick(created_ms),
            &chain.network_id(),
            Duration::from_secs(1),
            chain.state().view().world().parameters().transaction(),
            &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
                iroha_crypto::Algorithm::Ed25519,
                iroha_crypto::Algorithm::Secp256k1,
            ])
            .expect("this stateless fixture explicitly selects Ed25519 and Secp256k1"),
            time,
        )
        .unwrap();
        let hash = accepted.hash_as_entrypoint();
        queue.push(accepted, chain.state().view()).unwrap();
        hash
    }

    fn advance_custody_fixture_clock(
        chain: &CertifiedTestChain,
        worker: &Worker<'_>,
        minimum: Duration,
    ) {
        let view = worker.state.view();
        let parent = view.latest_block().unwrap().unwrap();
        let height = parent.header().height().get().checked_add(1).unwrap();
        let cadence = Duration::from_millis(worker.scheduled(height).unwrap().params.block_time_ms);
        let floor = parent
            .header()
            .creation_time()
            .checked_add(cadence)
            .unwrap();
        let merges = lanes::merge::propose(
            &view,
            &*worker.context.lane_blocks,
            height,
            &mut crate::sumeragi::lanes::ProposalReadScope::new(),
        )
        .unwrap();
        let floor = if merges.merges.is_empty() {
            floor
        } else {
            floor.max(Duration::from_millis(merges.time_floor_ms))
        };
        chain.set_execution_time(worker.context.time_source.now().max(minimum).max(floor));
    }

    fn attach_queue(
        chain: &CertifiedTestChain,
        worker: &mut Worker<'_>,
    ) -> (
        Arc<Queue>,
        iroha_primitives::time::MockTimeHandle,
        iroha_primitives::time::TimeSource,
    ) {
        let (clock, time) =
            iroha_primitives::time::TimeSource::new_mock(Duration::from_millis(2_001));
        let queue = Arc::new(Queue::test(
            iroha_config::parameters::actual::Queue::default(),
            &time,
        ));
        // Ordinary custody fixtures must reach the original signed input's time.
        // Explicit clock tests inject a separate worker clock and retain its policy.
        advance_custody_fixture_clock(chain, worker, time.now());
        queue_work(chain, 2_000, &queue, &time);
        worker.queue = Some(Arc::clone(&queue));
        (queue, clock, time)
    }

    #[test]
    fn completed_original_payload_survives_unrelated_queue_admissions_without_recapture() {
        let (_, time) = iroha_primitives::time::TimeSource::new_mock(Duration::from_millis(30_000));
        super::super::publication_tests::with_worker_clock(
            time.clone(),
            move |chain, worker, _blocks, _events| {
                let queue = Arc::new(Queue::test(
                    iroha_config::parameters::actual::Queue::default(),
                    &time,
                ));
                let input = queue_work(chain, 2_000, &queue, &time);
                worker.queue = Some(Arc::clone(&queue));
                let original = worker.build(2, 0, 1 << 20, 100).unwrap().unwrap();
                for created in 2_001..2_009 {
                    let unrelated = queue_work(chain, created, &queue, &time);
                    assert_ne!(unrelated, input);
                    let retained = worker.build(2, 0, 1 << 20, 100).unwrap().unwrap();
                    assert_eq!(
                        retained.payload.as_slice().as_ptr(),
                        original.payload.as_slice().as_ptr(),
                        "unrelated Queue admissions must not replace the original completed Global payload"
                    );
                    assert_eq!(retained.payload.as_slice(), original.payload.as_slice());
                    let proposal = payload::decode(retained.payload.as_slice()).unwrap();
                    assert_eq!(proposal.network_entrypoint_count(), 1);
                    assert_eq!(proposal.network_entrypoints().next().unwrap().hash(), input);
                }
                queue.clear_all();
                assert_eq!(queue_work(chain, 2_000, &queue, &time), input);
                let readmitted = worker.build(2, 0, 1 << 20, 100).unwrap().unwrap();
                assert_ne!(
                    readmitted.payload.as_slice().as_ptr(),
                    original.payload.as_slice().as_ptr(),
                    "same-hash readmission must acquire its own current admission custody"
                );
                assert_eq!(worker.state.view().height(), 1);
            },
        );
    }

    #[test]
    fn fresh_view_refreshes_authenticated_block_time_without_replacing_signed_input() {
        let (clock, time) =
            iroha_primitives::time::TimeSource::new_mock(Duration::from_millis(2_001));
        super::super::publication_tests::with_worker_clock(
            time.clone(),
            move |chain, worker, _blocks, _events| {
                let queue = Arc::new(Queue::test(
                    iroha_config::parameters::actual::Queue::default(),
                    &time,
                ));
                let input = queue_work(chain, 2_000, &queue, &time);
                worker.queue = Some(Arc::clone(&queue));
                let first = worker.build(2, 0, 1 << 20, 100).unwrap().unwrap();
                let original = payload::decode(first.payload.as_slice()).unwrap();
                assert_eq!(
                    original.header().creation_time(),
                    Duration::from_millis(2_001)
                );
                assert_eq!(original.network_entrypoints().next().unwrap().hash(), input);

                clock.set(Duration::from_millis(20_000));
                let retained = worker.build(2, 0, 1 << 20, 100).unwrap().unwrap();
                assert_eq!(
                    retained.payload.as_slice().as_ptr(),
                    first.payload.as_slice().as_ptr()
                );
                assert_eq!(retained.payload.as_slice(), first.payload.as_slice());
                let fresh = worker.build(2, 1, 1 << 20, 100).unwrap().unwrap();
                let proposal = payload::decode(fresh.payload.as_slice()).unwrap();
                assert_eq!(
                    proposal.header().creation_time(),
                    Duration::from_millis(20_000),
                    "fresh view must refresh certified time without another signed transaction"
                );
                assert_eq!(proposal.network_entrypoints().count(), 1);
                assert_eq!(
                    proposal.external_entrypoints_slice(),
                    original.external_entrypoints_slice()
                );
                assert_eq!(queue.queued_len(), 1);
                assert!(queue.contains_entrypoint_hash(input));
                assert_eq!(worker.state.view().height(), 1);
            },
        );
    }

    #[test]
    fn proposer_clock_retains_final_input_and_canonical_output_until_due() {
        let (clock, time) =
            iroha_primitives::time::TimeSource::new_mock(Duration::from_millis(1_999));
        super::super::publication_tests::with_worker_clock(
            time.clone(),
            move |chain, worker, _blocks, _events| {
                let queue = Arc::new(Queue::test(
                    iroha_config::parameters::actual::Queue::default(),
                    &time,
                ));
                let hash = queue_work(chain, 2_000, &queue, &time);
                worker.queue = Some(Arc::clone(&queue));
                assert!(
                    matches!(worker.build(2, 0, 1 << 20, 100),
                        Err(PublicationError::Retryable(reason)) if reason.contains("ClockAhead")),
                    "future-only final input must retain timed retry without unrelated traffic"
                );
                assert!(worker.payload_build.is_none());
                clock.advance(Duration::from_millis(1));
                assert!(
                    matches!(worker.build(2, 0, 1 << 20, 100),
                        Err(PublicationError::Retryable(reason)) if reason.contains("ClockAhead")),
                    "canonical payload clock must wait after its signed input becomes due"
                );
                let original = worker.payload_build.as_ref().unwrap().job.source();
                let creation_time = original.block.header().creation_time();
                assert_eq!(creation_time, Duration::from_millis(2_001));
                let input_pointer = original.block.external_entrypoints_slice().as_ptr();
                assert!(original.pending_inputs.is_some());
                // Repeated source checks wait with the same original input, with no new admission.
                assert!(worker.build(2, 0, 1 << 20, 100).is_err());
                assert_eq!(
                    worker
                        .payload_build
                        .as_ref()
                        .unwrap()
                        .job
                        .source()
                        .block
                        .external_entrypoints_slice()
                        .as_ptr(),
                    input_pointer
                );
                clock.set(creation_time);
                let output = worker.build(2, 0, 1 << 20, 100).unwrap().unwrap();
                let original_pointer = output.payload.as_slice().as_ptr();
                let block = payload::decode(output.payload.as_slice()).unwrap();
                assert_eq!(block.header().creation_time(), creation_time);
                assert_eq!(block.network_entrypoints().next().unwrap().hash(), hash);
                assert!(worker.payload_build.is_none());
                assert!(worker.completed_payload.is_some());
                clock.rewind(Duration::from_millis(1));
                assert!(
                    matches!(worker.build(2, 0, 1 << 20, 100),
                        Err(PublicationError::Retryable(reason)) if reason.contains("ClockAhead")),
                    "completed original payload must wait again after clock regression"
                );
                assert_eq!(
                    worker
                        .completed_payload
                        .as_ref()
                        .unwrap()
                        .payload
                        .as_slice()
                        .as_ptr(),
                    original_pointer
                );
                clock.set(creation_time);
                let retry = worker.build(2, 0, 1 << 20, 100).unwrap().unwrap();
                assert_eq!(retry.payload.as_slice().as_ptr(), original_pointer);
                assert!(queue.contains_entrypoint_hash(hash));
                assert_eq!(queue.queued_len(), 1);
                assert_eq!(worker.state.view().height(), 1);
            },
        );
    }

    #[test]
    fn proposer_clock_retains_certified_lane_floor_and_completed_original() {
        lanes::merge::with_original_lane_merge_fixture(
            |chain, lane_blocks, certify, [first, _second]| {
                let height = chain.height() + 1;
                certify(1, chain.height(), vec![first]);
                let (clock, time) = iroha_primitives::time::TimeSource::new_mock(Duration::ZERO);
                super::super::publication_tests::with_worker_chain_and_clock(
                    chain,
                    ConsensusMode::Permissioned,
                    lane_blocks,
                    time.clone(),
                    |_, worker, _blocks, _events| {
                        let queue = Arc::new(Queue::test(
                            iroha_config::parameters::actual::Queue::default(),
                            &time,
                        ));
                        worker.queue = Some(Arc::clone(&queue));
                        assert!(
                            matches!(worker.build(height, 0, 1 << 20, 100),
                                Err(PublicationError::Retryable(reason)) if reason.contains("ClockAhead")),
                            "canonical lane merge floor must wait without empty or unrelated work"
                        );
                        let source = worker.payload_build.as_ref().unwrap().job.source();
                        let creation_time = source.block.header().creation_time();
                        let section = source.block.lane_merge().unwrap();
                        let original_range = section.merges.as_ptr();
                        assert!(creation_time >= Duration::from_millis(section.time_floor_ms));
                        assert_eq!(source.block.network_entrypoint_count(), 0);
                        clock.set(
                            creation_time.checked_sub(Duration::from_millis(1)).expect(
                                "fixture time has the original one-millisecond predecessor",
                            ),
                        );
                        assert!(worker.build(height, 0, 1 << 20, 100).is_err());
                        assert_eq!(
                            worker
                                .payload_build
                                .as_ref()
                                .unwrap()
                                .job
                                .source()
                                .block
                                .lane_merge()
                                .unwrap()
                                .merges
                                .as_ptr(),
                            original_range
                        );
                        clock.set(creation_time);
                        let output = worker.build(height, 0, 1 << 20, 100).unwrap().unwrap();
                        assert!(worker.payload_build.as_ref().unwrap().job.is_completed());
                        clock.rewind(Duration::from_millis(1));
                        assert!(
                            matches!(worker.build(height, 0, 1 << 20, 100),
                                Err(PublicationError::Retryable(reason)) if reason.contains("ClockAhead")),
                            "completed certified lane payload must obey the same clock boundary"
                        );
                        clock.set(creation_time);
                        let retry = worker.build(height, 0, 1 << 20, 100).unwrap().unwrap();
                        assert_eq!(
                            retry.payload.as_slice().as_ptr(),
                            output.payload.as_slice().as_ptr()
                        );
                        assert_eq!(queue.queued_len(), 0);
                        assert_eq!(worker.state.view().height() as u64, chain.height());
                    },
                );
            },
        );
    }

    /// Stage the actual selected source, then force only its real immutable shared
    /// control to refuse. The original limit and paid encoded backing stay unchanged.
    fn stage_original_partial(
        worker: &mut Worker<'_>,
        queue: &Arc<Queue>,
    ) -> (
        *const u8,
        iroha_crypto::HashOf<iroha_data_model::transaction::TransactionEntrypoint>,
    ) {
        let height = worker
            .applied
            .0
            .checked_add(1)
            .expect("actual next global height");
        // Test staging replaces only a retired completion, before any original
        // State view or Queue guard is acquired. Refused partial work is unchanged.
        worker.retire_completed_payload(height);
        let state = worker.state;
        let budget = state.ivm_execution_budget();
        let current_view = state.view();
        let generation = state.state_view_generation();
        assert_eq!(current_view.height() as u64, worker.applied.0);
        let parent = current_view
            .canonical_history()
            .executed_block(
                std::num::NonZeroUsize::new(current_view.height()).unwrap(),
                |_, _| Ok(()),
            )
            .unwrap();
        let scope =
            OriginalPayloadScope::capture(&current_view, generation, height, 0, 1 << 20, 100);
        let merges = lanes::merge::propose(
            &current_view,
            &*worker.context.lane_blocks,
            height,
            &mut crate::sumeragi::lanes::ProposalReadScope::new(),
        )
        .unwrap();
        let selection = queue
            .begin_pending_payload_selection(state, generation)
            .unwrap();
        let selected = payload::select(
            &current_view,
            queue,
            (1 << 20) - PAYLOAD_OVERHEAD,
            &merges,
            worker.context.time_source.now(),
        )
        .unwrap();
        assert_eq!(selected.len(), 1);
        let hash = selected[0].hash_as_entrypoint();
        let lease = queue
            .capture_pending_payload_lease(state, selection, &current_view, &selected, &budget)
            .unwrap()
            .unwrap();
        let scheduled = worker.scheduled(height).unwrap();
        let block = payload::assemble_with_merges(
            state,
            Assembly {
                parent: &parent,
                view: 0,
                cadence: Duration::from_millis(scheduled.params.block_time_ms),
                proposed_time: worker.context.time_source.now(),
            },
            &selected,
            &merges,
        )
        .unwrap();

        let wire_len = block.resultless_proposal_wire_len().unwrap();
        worker.payload_build = Some(GlobalPayloadBuild {
            scope,
            job: super::super::super::driver::payload_build::PayloadBuild::new(
                GlobalPayloadSource {
                    block,

                    pending_inputs: Some(lease),
                },
                budget.clone(),
                1 << 20,
            ),
            preparation_refusal: None,
            proposal_admission: None,
        });
        drop((current_view, parent, selected));
        worker
            .payload_build
            .as_mut()
            .unwrap()
            .job
            .prepare_source()
            .expect("original unsigned signature custody precedes wire admission");
        let limit = budget.limit_bytes();
        let occupied = budget
            .try_reserve_bytes(limit - budget.reserved_bytes() - wire_len)
            .unwrap();
        assert!(matches!(
            worker.finish_payload_build(),
            Err(PublicationError::Retryable(_))
        ));
        let encoded = worker
            .payload_build
            .as_ref()
            .unwrap()
            .job
            .encoded_backing_for_test()
            .expect("real encoding survives immutable shared-control refusal");
        assert_eq!(encoded.len(), wire_len);
        let pointer = encoded.as_ptr();
        assert_eq!(
            budget.reserved_bytes(),
            limit,
            "only the actual original-pool shared control has no headroom"
        );
        assert!(worker.completed_payload.is_none());
        assert!(queue.contains_pending_hash(hash, state));
        drop(occupied);
        assert_eq!(budget.limit_bytes(), limit);
        (pointer, hash)
    }

    fn retained_partial_pointer(worker: &Worker<'_>) -> *const u8 {
        worker
            .payload_build
            .as_ref()
            .expect("the original partial source is still owned")
            .job
            .encoded_backing_for_test()
            .expect("the original paid wire is still owned")
            .as_ptr()
    }

    #[test]
    fn retained_partial_payload_refuses_missing_original_parent_and_resumes_same_paid_wire() {
        // Pin before genesis so retired fixture State generations cannot alter exact refunds.
        struct OriginalJournal {
            path: std::path::PathBuf,
            saved: std::path::PathBuf,
        }
        impl Drop for OriginalJournal {
            fn drop(&mut self) {
                std::fs::rename(&self.saved, &self.path).unwrap();
            }
        }
        let _fixture_epoch = crossbeam_epoch::pin();
        super::super::publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let (queue, _clock, _time) = attach_queue(chain, worker);
            let budget = worker.state.ivm_execution_budget();
            let baseline = budget.reserved_bytes();
            let (pointer, hash) = stage_original_partial(worker, &queue);
            let held = budget.reserved_bytes();
            let source_hash = worker
                .payload_build
                .as_ref()
                .unwrap()
                .job
                .source()
                .block
                .hash();
            let path = crate::kura::Kura::canonical_storage_path(&chain.kura().store_root())
                .join("blocks.data");
            let saved = path.with_extension("partial-original");
            std::fs::rename(&path, &saved).unwrap();
            let missing = OriginalJournal { path, saved };
            chain.kura().reset_canonical_query_reads_for_test();
            for _ in 0..2 {
                let result = worker.build(2, 0, 1 << 20, 100);
                assert!(
                    matches!(result, Err(PublicationError::Retryable(_))),
                    "original parent journal unavailability remains retryable"
                );
                assert_eq!(retained_partial_pointer(worker), pointer);
                assert_eq!(
                    worker
                        .payload_build
                        .as_ref()
                        .unwrap()
                        .job
                        .source()
                        .block
                        .hash(),
                    source_hash
                );
                assert_eq!(budget.reserved_bytes(), held);
                assert!(worker.completed_payload.is_none());
                assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
                assert!(queue.contains_entrypoint_hash(hash));
            }
            drop(missing);
            let Some(output) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("the restored actual original source must release its same first output");
            };
            assert_eq!(output.payload.as_slice().as_ptr(), pointer);
            assert_eq!(
                payload::decode(output.payload.as_slice()).unwrap().hash(),
                source_hash
            );
            assert!(output.payload.admitted_to(&budget));
            assert!(worker.payload_build.is_none());
            assert!(chain.kura().canonical_query_reads_for_test().0 > 0);
            assert_eq!(queue.queued_len(), 1);
            assert!(queue.contains_pending_hash(hash, worker.state));
            drop(output);
            worker.retire_completed_payload(2);
            assert_eq!(budget.reserved_bytes(), baseline);
        });
    }

    #[test]
    fn retained_partial_payload_refuses_substituted_original_parent_and_resumes_same_paid_wire() {
        struct OriginalJournal {
            path: std::path::PathBuf,
            saved: std::path::PathBuf,
        }
        impl Drop for OriginalJournal {
            fn drop(&mut self) {
                std::fs::remove_file(&self.path).unwrap();
                std::fs::rename(&self.saved, &self.path).unwrap();
            }
        }
        super::super::publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let (queue, _clock, _time) = attach_queue(chain, worker);
            let budget = worker.state.ivm_execution_budget();
            let (pointer, hash) = stage_original_partial(worker, &queue);
            let held = budget.reserved_bytes();
            let path = crate::kura::Kura::canonical_storage_path(&chain.kura().store_root())
                .join("blocks.data");
            let saved = path.with_extension("partial-original");
            std::fs::rename(&path, &saved).unwrap();
            std::fs::copy(&saved, &path).unwrap();
            let replacement = OriginalJournal { path, saved };
            chain.kura().reset_canonical_query_reads_for_test();
            let result = worker.build(2, 0, 1 << 20, 100);
            assert!(
                matches!(result, Err(PublicationError::Retryable(_))),
                "original parent journal unavailability remains retryable"
            );
            assert_eq!(retained_partial_pointer(worker), pointer);
            assert_eq!(budget.reserved_bytes(), held);
            assert!(worker.completed_payload.is_none());
            assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
            assert!(queue.contains_pending_hash(hash, worker.state));
            drop(replacement);
            let Some(output) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("only the original journal object restores first-output custody");
            };
            assert_eq!(output.payload.as_slice().as_ptr(), pointer);
            assert!(output.payload.admitted_to(&budget));
            assert!(chain.kura().canonical_query_reads_for_test().0 > 0);
            assert_eq!(queue.queued_len(), 1);
            drop(output);
        });
    }

    #[test]
    fn retained_partial_payload_preserves_actual_reader_release_and_native_capacity_refusal() {
        use std::{
            future::Future,
            task::{Context, Poll, Waker},
        };
        super::super::publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let (queue, _clock, _time) = attach_queue(chain, worker);
            let state = worker.state;
            let budget = state.ivm_execution_budget();
            let mut registration = crate::unit_test_support::release_registration(&budget);
            let (pointer, hash) = stage_original_partial(worker, &queue);
            let held = budget.reserved_bytes();
            let release = state.with_held_header_for_reader_test(|release| {
                let context = &mut Context::from_waker(Waker::noop());
                let mut pending =
                    std::pin::pin!(release.clone().wait_for_release(&mut registration));
                assert_eq!(pending.as_mut().poll(context), Poll::Pending);
                let PublicationError::Deferred(PublicationDeferral::StateViewBusy(actual)) =
                    worker.build(2, 0, 1 << 20, 100).unwrap_err()
                else {
                    panic!("the original physical header must retain its actual reader release");
                };
                assert_eq!(actual, release);
                assert_eq!(retained_partial_pointer(worker), pointer);
                assert_eq!(budget.reserved_bytes(), held);
                assert_eq!(pending.as_mut().poll(context), Poll::Pending);
                release
            });
            {
                let mut released =
                    std::pin::pin!(release.clone().wait_for_release(&mut registration));
                assert_eq!(
                    released
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Ready(())
                );
            }
            let occupied = budget
                .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
                .unwrap();
            chain.kura().reset_canonical_query_reads_for_test();
            let PublicationError::Deferred(original) =
                worker.build(2, 0, 1 << 20, 100).unwrap_err()
            else {
                panic!("physical parent admission must retain its typed original-pool refusal");
            };
            let Some(iroha_allocation::AllocationRefusal::Capacity { release, .. }) =
                original.allocation_refusal()
            else {
                panic!("the real canonical frame has no original-pool capacity");
            };
            let mut pending = std::pin::pin!(release.clone().wait_for_release(&mut registration));
            assert_eq!(
                pending
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Pending
            );
            assert_eq!(retained_partial_pointer(worker), pointer);
            assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
            assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
            assert!(queue.contains_pending_hash(hash, state));
            drop(occupied);
            assert_eq!(
                pending
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(())
            );
            let Some(output) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("both actual physical releases permit the same paid original wire");
            };
            assert_eq!(output.payload.as_slice().as_ptr(), pointer);
            assert!(output.payload.admitted_to(&budget));
            assert_eq!(queue.queued_len(), 1);
            drop(output);
        });
    }

    #[test]
    fn retained_partial_payload_preserves_actual_publication_release_until_source_withdrawal() {
        // Pin before genesis so retired fixture State generations cannot alter exact refunds.
        use std::{
            future::Future,
            task::{Context, Poll, Waker},
        };
        let _fixture_epoch = crossbeam_epoch::pin();
        super::super::publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let (queue, _clock, _time) = attach_queue(chain, worker);
            let state = worker.state;
            let budget = state.ivm_execution_budget();
            let mut registration = crate::unit_test_support::release_registration(&budget);
            let baseline = budget.reserved_bytes();
            let (pointer, hash) = stage_original_partial(worker, &queue);
            let current_view = state.view();
            let parent = current_view
                .canonical_history()
                .executed_block(std::num::NonZeroUsize::MIN, |_, _| Ok(()))
                .unwrap();
            let scope = worker.payload_build.as_ref().unwrap().scope;
            let merges = lanes::merge::propose(
                &current_view,
                &*worker.context.lane_blocks,
                2,
                &mut crate::sumeragi::lanes::ProposalReadScope::new(),
            )
            .unwrap();
            let held = budget.reserved_bytes();
            let release = state.with_held_view_publication_for_reader_test(|release| {
                let context = &mut Context::from_waker(Waker::noop());
                let mut pending =
                    std::pin::pin!(release.clone().wait_for_release(&mut registration));
                assert_eq!(pending.as_mut().poll(context), Poll::Pending);
                let PublicationError::Deferred(PublicationDeferral::PublicationBusy(actual)) =
                    worker.retained_payload_build_is_current(
                        scope,
                        &parent,
                        &current_view,
                        &merges,
                    ).unwrap_err()
                else {
                    panic!("the actual publisher opens after the original view; no retained first output may finish");
                };
                assert_eq!(actual, release);
                let PublicationError::Deferred(PublicationDeferral::StateViewBusy(actual)) =
                    worker.build(2, 0, 1 << 20, 100).unwrap_err()
                else {
                    panic!("the nonblocking worker view must retain the same publisher release");
                };
                assert_eq!(actual, release);
                assert_eq!(retained_partial_pointer(worker), pointer);
                assert_eq!(budget.reserved_bytes(), held);
                assert!(worker.payload_storage_wait().is_some());
                assert_eq!(pending.as_mut().poll(context), Poll::Pending);
                release
            });
            let mut released = std::pin::pin!(release.clone().wait_for_release(&mut registration));
            assert_eq!(
                released
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(())
            );
            drop((current_view, parent));
            assert!(
                worker.payload_storage_wait().is_none(),
                "completed real publication withdraws the old selected-input source generation"
            );
            assert!(worker.payload_build.is_none());
            assert!(worker.completed_payload.is_none());
            assert_eq!(budget.reserved_bytes(), baseline);
            assert_eq!(queue.queued_len(), 1);
            assert!(queue.contains_pending_hash(hash, state));
        });
    }

    #[test]
    fn retained_partial_payload_withdraws_original_queue_admission_on_mutation_or_expiry() {
        // Pin before genesis so retired fixture State generations cannot alter exact refunds.
        let _fixture_epoch = crossbeam_epoch::pin();
        for expire in [false, true] {
            super::super::publication_tests::with_worker(move |chain, worker, _blocks, _events| {
                let budget = worker.state.ivm_execution_budget();
                let empty_queue_baseline = budget.reserved_bytes();
                let (queue, clock, time) = attach_queue(chain, worker);
                let baseline = budget.reserved_bytes();
                let (_pointer, original_hash) = stage_original_partial(worker, &queue);
                if expire {
                    clock.advance(queue.tx_time_to_live + Duration::from_secs(1));
                    assert_eq!(worker.build(2, 0, 1 << 20, 100).unwrap(), None);
                    assert!(worker.payload_build.is_none());
                    assert!(worker.completed_payload.is_none());
                    assert_eq!(queue.queued_len(), 0);
                    // Expiry drops the accepted-input shell. The live Queue
                    // still owns its original resident ledger, so the entire
                    // pre-admission baseline returns only after its last owner.
                    worker.queue = None;
                    drop(queue);
                    assert_eq!(budget.reserved_bytes(), empty_queue_baseline);
                } else {
                    queue.clear_all();
                    clock.advance(Duration::from_millis(1));
                    queue_work(chain, 2_001, &queue, &time);
                    assert!(!queue.contains_entrypoint_hash(original_hash));
                    advance_custody_fixture_clock(chain, worker, time.now());
                    let Some(output) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                        panic!("the current actual admission must replace the withdrawn selection");
                    };
                    let block = payload::decode(output.payload.as_slice()).unwrap();
                    assert_eq!(block.network_entrypoint_count(), 1);
                    assert!(
                        block
                            .network_entrypoints()
                            .all(|entry| entry.hash() != original_hash)
                    );
                    assert!(worker.payload_build.is_none());
                    assert_eq!(queue.queued_len(), 1);
                    drop((output, block));
                    worker.retire_completed_payload(2);
                    assert_eq!(budget.reserved_bytes(), baseline);
                }
            });
        }
    }

    #[test]
    fn retained_partial_payload_idle_expiry_wakes_original_commit_with_live_execution() {
        use crate::sumeragi::driver::{
            exec::{ExecDone, ExecOp, ExecSched, ExecutionRegistrations},
            persist::Backoff,
        };
        use iroha_allocation::{AllocationBudget, AllocationRefusal};
        use std::task::{Context, Poll, Waker};

        super::super::publication_tests::with_worker(|chain, worker, _blocks, events| {
            let _fixture_epoch = crossbeam_epoch::pin();
            let (queue, clock, _time) = attach_queue(chain, worker);
            let budget = worker.state.ivm_execution_budget();
            let mut registration = crate::unit_test_support::release_registration(&budget);
            let original_thread = std::thread::current();
            registration.bind_thread(original_thread.clone());
            let scheduler_registration = ExecutionRegistrations::admit(&budget).unwrap();
            let (partial_pointer, input_hash) = stage_original_partial(worker, &queue);
            assert!(!worker.payload_build.as_ref().unwrap().job.is_completed());
            let (body, qc) = super::super::publication_tests::executed(chain, worker);
            assert_eq!(retained_partial_pointer(worker), partial_pointer);
            let live = worker.live.as_ref().unwrap();
            let overlay = std::ptr::from_ref(live.overlay.as_deref().unwrap());
            let commitment = std::ptr::from_ref(live.commitment().get());
            let original_source = live.source.clone();
            let original_result = live.result;
            let mut scheduler = ExecSched::new(1, Backoff::default(), scheduler_registration);
            scheduler.bind_release_thread(original_thread);
            scheduler.commit(body.clone(), qc.clone());
            let Some(ExecOp::Prepare(original)) = scheduler.next(0) else {
                panic!("the actual completed execution enters original certificate preparation");
            };
            let pressure = budget
                .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
                .unwrap();
            let failure = worker.prepare(&original.block, &original.qc).unwrap_err();
            let PublicationError::Deferred(ref refusal) = failure else {
                panic!("original certificate preparation must retain its capacity refusal");
            };
            let original_refusal = refusal
                .allocation_refusal()
                .expect("original State pool refusal")
                .clone();
            let Some(AllocationRefusal::Capacity { release, .. }) = refusal.allocation_refusal()
            else {
                panic!("the actual original State pool supplies the release observation");
            };
            let wait = release.clone();
            let context = &mut Context::from_waker(Waker::noop());
            assert_eq!(registration.poll_wait(&wait, context), Poll::Pending);
            scheduler.done(0, ExecDone::Prepared(Err(failure)));
            assert_eq!(
                scheduler
                    .preparation_refusal()
                    .and_then(PublicationDeferral::allocation_refusal),
                Some(&original_refusal)
            );
            assert_eq!(
                scheduler
                    .preparation_refusal()
                    .and_then(PublicationDeferral::release_wait),
                Some(&wait)
            );
            assert!(scheduler.next(0).is_none());
            assert_eq!(scheduler.wakeup(), u64::MAX);
            assert_eq!(retained_partial_pointer(worker), partial_pointer);
            assert!(worker.payload_storage_wait().is_some());
            let foreign = AllocationBudget::new(1);
            drop(foreign.try_reserve_bytes(1).unwrap());
            assert_eq!(registration.poll_wait(&wait, context), Poll::Pending);
            let occupied = budget.reserved_bytes();

            clock.advance(queue.tx_time_to_live + Duration::from_secs(1));
            // The real worker receive loop performs this same retirement at the
            // original Queue deadline, without a new build or execution request.
            assert!(worker.payload_storage_wait().is_none());
            assert!(worker.payload_build.is_none());
            assert!(worker.completed_payload.is_none());
            assert!(budget.reserved_bytes() < occupied);
            assert_eq!(queue.queued_len(), 1);
            assert!(queue.contains_entrypoint_hash(input_hash));
            let live = worker.live.as_ref().unwrap();
            assert_eq!(
                std::ptr::from_ref(live.overlay.as_deref().unwrap()),
                overlay
            );
            assert_eq!(std::ptr::from_ref(live.commitment().get()), commitment);
            assert_eq!(live.source, original_source);
            assert_eq!(live.result, original_result);
            assert_eq!(worker.applied.0, 1);
            assert!(events.try_recv().is_err());
            assert_eq!(
                registration.poll_wait(&wait, context),
                Poll::Ready(()),
                "real partial payload retirement wakes the original retained execution"
            );
            let Some(ExecOp::Prepare(retry)) = scheduler.next(0) else {
                panic!("actual original-pool retirement permits the same committed head to retry");
            };
            assert!(Arc::ptr_eq(&original, &retry));
            assert_eq!(
                scheduler
                    .preparation_refusal()
                    .and_then(PublicationDeferral::allocation_refusal),
                Some(&original_refusal)
            );
            assert_eq!(
                scheduler
                    .preparation_refusal()
                    .and_then(PublicationDeferral::release_wait),
                Some(&wait)
            );
            // The independent pressure owner is deliberately still retained at
            // every retirement, identity and wake assertion above.
            drop(pressure);
        });
    }

    #[test]
    fn retained_partial_payload_idle_expiry_refunds_while_original_parent_stays_unavailable() {
        // Pin before genesis so retired fixture State generations cannot alter exact refunds.
        struct OriginalJournal {
            path: std::path::PathBuf,
            saved: std::path::PathBuf,
        }
        impl Drop for OriginalJournal {
            fn drop(&mut self) {
                std::fs::rename(&self.saved, &self.path).unwrap();
            }
        }
        let _fixture_epoch = crossbeam_epoch::pin();
        super::super::publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let (queue, clock, _time) = attach_queue(chain, worker);
            let budget = worker.state.ivm_execution_budget();
            let baseline = budget.reserved_bytes();
            let (pointer, hash) = stage_original_partial(worker, &queue);
            let path = crate::kura::Kura::canonical_storage_path(&chain.kura().store_root())
                .join("blocks.data");
            let saved = path.with_extension("partial-original");
            std::fs::rename(&path, &saved).unwrap();
            let missing = OriginalJournal { path, saved };
            chain.kura().reset_canonical_query_reads_for_test();
            assert!(
                worker.payload_storage_wait().unwrap() < queue.tx_time_to_live,
                "the idle receive loop must arm the actual selected-input deadline"
            );
            assert_eq!(retained_partial_pointer(worker), pointer);
            assert!(budget.reserved_bytes() > baseline);
            clock.advance(queue.tx_time_to_live + Duration::from_secs(1));
            // No new build request and no canonical source restoration occurs.
            assert!(worker.payload_storage_wait().is_none());
            assert!(worker.payload_build.is_none());
            assert_eq!(budget.reserved_bytes(), baseline);
            assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
            assert_eq!(queue.queued_len(), 1);
            assert!(
                queue.contains_entrypoint_hash(hash),
                "storage retirement cannot isolate signed Queue work"
            );
            drop(missing);
        });
    }

    #[test]
    fn retained_partial_payload_cannot_adopt_same_hash_readmission_as_its_original_selection() {
        super::super::publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let (queue, clock, time) = attach_queue(chain, worker);
            let (_pointer, hash) = stage_original_partial(worker, &queue);
            let original_lease = worker
                .payload_build
                .as_ref()
                .unwrap()
                .job
                .source()
                .pending_inputs
                .as_ref()
                .unwrap();
            assert!(queue.pending_payload_lease_is_current(
                worker.state,
                &worker.state.view(),
                original_lease
            ));
            queue.clear_all();
            clock.advance(Duration::from_millis(1));
            queue_work(chain, 2_000, &queue, &time);
            assert!(queue.contains_pending_hash(hash, worker.state));
            assert_eq!(queue.queued_len(), 1);
            assert!(
                !queue.pending_payload_lease_is_current(
                    worker.state,
                    &worker.state.view(),
                    original_lease
                ),
                "byte-identical signed inputs belong to a different actual admission boundary"
            );
            let Some(output) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("the fresh actual admission must create its own selected-input owner");
            };
            let fresh = worker.completed_payload.as_ref().expect(
                "the revoked partial receipt cannot masquerade as a completed owner; current admission must be captured anew"
            );
            assert!(queue.pending_payload_lease_is_current(
                worker.state,
                &worker.state.view(),
                &fresh.pending_inputs
            ));
            let block = payload::decode(output.payload.as_slice()).unwrap();
            assert_eq!(block.network_entrypoint_count(), 1);
            assert!(
                block
                    .network_entrypoints()
                    .all(|entry| entry.hash() == hash)
            );
            assert!(worker.payload_build.is_none());
            assert_eq!(queue.queued_len(), 1);
            drop((output, block));
        });
    }

    #[test]
    fn retained_partial_payload_rechecks_actual_mandatory_lane_growth_and_mixed_queue_withdrawal() {
        lanes::merge::with_original_lane_merge_fixture(
            |chain, lane_blocks, certify, [first, second]| {
                super::super::publication_tests::with_worker_chain(
                    chain,
                    ConsensusMode::Permissioned,
                    lane_blocks,
                    |chain, worker, _blocks, _events| {
                        let parent_height = chain.height();
                        assert_eq!(parent_height, 3, "the actual fixed-lane activation cut");
                        let height = parent_height.checked_add(1).unwrap();
                        assert_eq!(height, 4);
                        let (queue, clock, time) = attach_queue(chain, worker);
                        let (_pointer, original_hash) = stage_original_partial(worker, &queue);
                        assert!(
                            worker
                                .payload_build
                                .as_ref()
                                .unwrap()
                                .job
                                .source()
                                .block
                                .lane_merge()
                                .is_none()
                        );
                        let first_hash = certify(1, parent_height, vec![first]);
                        advance_custody_fixture_clock(chain, worker, time.now());
                        let Some(output) = worker.build(height, 0, 1 << 20, 100).unwrap() else {
                            panic!(
                                "newly certified mandatory lane work must rebuild the old Queue-only plan"
                            );
                        };
                        let block = payload::decode(output.payload.as_slice()).unwrap();
                        let section = block.lane_merge().unwrap();
                        assert_eq!(section.merges.len(), 1);
                        assert_eq!(section.merges[0].to, 1);
                        assert_eq!(section.merges[0].tip_hash, first_hash.0);
                        assert!(
                            worker.completed_payload.is_none(),
                            "mixed work grants no completed Queue-only lease"
                        );
                        assert!(worker.payload_build.as_ref().unwrap().job.is_completed());
                        assert!(queue.contains_pending_hash(original_hash, worker.state));
                        drop((output, block));

                        // Same global State/source parameters, but the actual original lane
                        // journal now grows. Its old signed range cannot waive the next block.
                        let (_pointer, _) = stage_original_partial(worker, &queue);
                        let original = worker.payload_build.as_ref().unwrap().job.source();
                        assert!(
                            original.pending_inputs.is_some(),
                            "mixed Queue input retains its actual admission receipt"
                        );
                        assert_eq!(original.block.lane_merge().unwrap().merges[0].to, 1);
                        let second_hash = certify(2, parent_height, vec![second]);
                        advance_custody_fixture_clock(chain, worker, time.now());
                        let current = lanes::merge::propose(
                            &worker.state.view(),
                            &*worker.context.lane_blocks,
                            height,
                            &mut crate::sumeragi::lanes::ProposalReadScope::new(),
                        )
                        .unwrap();
                        let Some(output) = worker.build(height, 0, 1 << 20, 100).unwrap() else {
                            panic!(
                                "growth of the real certified journal must rebuild the old mixed range"
                            );
                        };
                        let block = payload::decode(output.payload.as_slice()).unwrap();
                        let section = block.lane_merge().unwrap();
                        assert_eq!(section.merges, current.merges);
                        assert_eq!(section.time_floor_ms, current.time_floor_ms);
                        assert_eq!(section.merges[0].to, 2);
                        assert_eq!(section.merges[0].tip_hash, second_hash.0);
                        assert!(worker.completed_payload.is_none());
                        drop((output, block));

                        // Holding the same actual lane plan does not hide withdrawal of
                        // a mixed source's independently admitted original Queue input.
                        let (_pointer, _) = stage_original_partial(worker, &queue);
                        queue.clear_all();
                        clock.advance(Duration::from_millis(1));
                        queue_work(chain, 2_001, &queue, &time);
                        assert!(!queue.contains_entrypoint_hash(original_hash));
                        let Some(output) = worker.build(height, 0, 1 << 20, 100).unwrap() else {
                            panic!(
                                "current mixed work must preserve the mandatory lane plan and new actual admission"
                            );
                        };
                        let block = payload::decode(output.payload.as_slice()).unwrap();
                        assert_eq!(block.lane_merge().unwrap().merges, current.merges);
                        assert_eq!(block.network_entrypoint_count(), 1);
                        assert!(
                            block
                                .network_entrypoints()
                                .all(|entry| entry.hash() != original_hash)
                        );
                        assert!(worker.completed_payload.is_none());
                        assert!(worker.payload_build.as_ref().unwrap().job.is_completed());
                        assert_eq!(queue.queued_len(), 1);
                        assert_eq!(
                            worker.state.view().height(),
                            usize::try_from(parent_height).unwrap(),
                            "lane certification does not fabricate global application"
                        );
                        drop((output, block));
                    },
                );
            },
        );
    }

    #[test]
    fn completed_original_payload_reuses_actual_funded_backing_for_a_new_request() {
        // Pin before genesis so retired fixture State generations cannot alter exact refunds.
        let _fixture_epoch = crossbeam_epoch::pin();
        super::super::publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let (queue, _clock, _time) = attach_queue(chain, worker);
            let budget = worker.state.ivm_execution_budget();
            let baseline = budget.reserved_bytes();
            let Some(original) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("original real signed work must produce nonempty funded custody");
            };

            let pointer = original.payload.as_slice().as_ptr();
            let retained = budget.reserved_bytes();
            assert!(retained > baseline);
            assert!(worker.completed_payload.is_some());
            assert!(worker.payload_build.is_none());
            chain.kura().reset_canonical_query_reads_for_test();
            // A second request for the same actual applied source lends its completed owner.
            // Keeping the first output live also makes a replacement allocation observable.
            let Some(retried) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("the new request must lend the actual completed original");
            };
            assert_eq!(
                retried.payload.as_slice().as_ptr(),
                pointer,
                "no assembly or encoding allocates a replacement"
            );
            assert_eq!(retried.payload.as_slice(), original.payload.as_slice());
            assert_eq!(
                budget.reserved_bytes(),
                retained,
                "the same physical charge is retained once"
            );
            assert!(
                chain.kura().canonical_query_reads_for_test().0 > 0,
                "reuse still reads its real canonical parent"
            );
            assert_eq!(
                queue.queued_len(),
                1,
                "only actual G application removes original work"
            );
            drop(retried);
            drop(original);
            assert_eq!(
                budget.reserved_bytes(),
                retained,
                "the completed original still owns its backing"
            );
            worker.discard(2, &[]);
            assert!(worker.completed_payload.is_none());
            assert_eq!(budget.reserved_bytes(), baseline);
        });
    }

    #[test]
    fn completed_original_payload_retires_on_expiry_or_rejection_after_unrelated_admission() {
        super::super::publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let (queue, clock, time) = attach_queue(chain, worker);
            let Some(original) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("original")
            };
            let original_hash = {
                let block = payload::decode(original.payload.as_slice()).unwrap();
                assert_eq!(block.network_entrypoint_count(), 1);

                block.network_entrypoints().next().unwrap().hash()
            };
            let added_hash = queue_work(chain, 2_001, &queue, &time);
            assert_ne!(added_hash, original_hash);
            let Some(next) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("next input")
            };
            assert_eq!(
                next.payload.as_slice().as_ptr(),
                original.payload.as_slice().as_ptr()
            );
            {
                let next_block = payload::decode(next.payload.as_slice()).unwrap();
                assert_eq!(
                    next_block.network_entrypoint_count(),
                    1,
                    "unrelated input admission preserves the original completed FIFO selection"
                );
                assert_eq!(
                    next_block.network_entrypoints().next().unwrap().hash(),
                    original_hash,
                    "the completed payload retains its exact selected original admission"
                );
            }
            assert_eq!(queue.queued_len(), 2);
            assert!(queue.contains_entrypoint_hash(original_hash));
            assert!(queue.contains_entrypoint_hash(added_hash));
            let rejected = super::super::publication_tests::proposal(chain, worker);
            let rejected_hash = rejected.hash(&**worker.context.crypto.as_ref().unwrap());
            worker.reject(2, 0, rejected_hash);
            assert!(
                worker.completed_payload.is_none(),
                "actual proposal rejection withdraws reuse authority"
            );
            drop(next);
            advance_custody_fixture_clock(chain, worker, Duration::from_millis(2_002));
            let Some(expiring) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("expiring original")
            };
            clock.advance(queue.tx_time_to_live + Duration::from_secs(1));
            assert_eq!(worker.build(2, 0, 1 << 20, 100).unwrap(), None);
            assert!(
                worker.completed_payload.is_none(),
                "no completed image can survive real input expiry"
            );
            drop(expiring);
            drop(original);
        });
    }

    #[test]
    fn completed_original_payload_never_crosses_view_limit_budget_or_queue_attachment() {
        super::super::publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let (_queue, _clock, _time) = attach_queue(chain, worker);
            let Some(original) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("original")
            };
            let Some(other_view) = worker.build(2, 1, 1 << 20, 100).unwrap() else {
                panic!("view")
            };
            assert_ne!(
                other_view.payload.as_slice().as_ptr(),
                original.payload.as_slice().as_ptr()
            );
            let Some(other_limit) = worker.build(2, 1, (1 << 20) - 1, 100).unwrap() else {
                panic!("limit")
            };
            assert_ne!(
                other_limit.payload.as_slice().as_ptr(),
                other_view.payload.as_slice().as_ptr()
            );
            let Some(other_budget) = worker.build(2, 1, (1 << 20) - 1, 101).unwrap() else {
                panic!("budget")
            };
            assert_ne!(
                other_budget.payload.as_slice().as_ptr(),
                other_limit.payload.as_slice().as_ptr()
            );
            worker.serve(Request::AttachQueue(Arc::clone(
                worker.queue.as_ref().unwrap(),
            )));
            assert!(
                worker.completed_payload.is_none(),
                "even same-object explicit queue attachment retires original custody"
            );
            let Some(reattached) = worker.build(2, 1, (1 << 20) - 1, 101).unwrap() else {
                panic!("reattached")
            };
            assert_ne!(
                reattached.payload.as_slice().as_ptr(),
                other_budget.payload.as_slice().as_ptr()
            );
            worker.retire_completed_payload(2);
            assert!(worker.completed_payload.is_none());
            drop((original, other_view, other_limit, other_budget, reattached));
        });
    }

    #[test]
    fn completed_original_payload_cannot_adopt_clear_and_readmission_during_original_build() {
        super::super::publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let (queue, clock, time) = attach_queue(chain, worker);
            let generation = worker.state.state_view_generation();
            let parent = worker
                .state
                .view()
                .canonical_history()
                .executed_block(std::num::NonZeroUsize::MIN, |_, _| Ok(()))
                .unwrap();
            let scope =
                OriginalPayloadScope::capture(&worker.state.view(), generation, 2, 0, 1 << 20, 100);
            let selection = queue
                .begin_pending_payload_selection(worker.state, generation)
                .unwrap();
            let selected = payload::select(
                &worker.state.view(),
                &queue,
                (1 << 20) - PAYLOAD_OVERHEAD,
                &payload::MergeProposal::default(),
                worker.context.time_source.now(),
            )
            .unwrap();
            assert_eq!(selected.len(), 1);
            let original = selected[0].clone();
            let hash = original.hash_as_entrypoint();
            let lease = queue
                .capture_pending_payload_lease(
                    worker.state,
                    selection,
                    &worker.state.view(),
                    &selected,
                    &worker.state.ivm_execution_budget(),
                )
                .unwrap()
                .unwrap();
            let scheduled = worker.scheduled(2).unwrap();
            let block = payload::assemble(
                worker.state,
                Assembly {
                    parent: &parent,
                    view: 0,
                    cadence: Duration::from_millis(scheduled.params.block_time_ms),
                    proposed_time: worker.context.time_source.now(),
                },
                &selected,
            )
            .unwrap();

            worker.payload_build = Some(GlobalPayloadBuild {
                scope,
                job: super::super::super::driver::payload_build::PayloadBuild::new(
                    GlobalPayloadSource {
                        block,

                        pending_inputs: Some(lease),
                    },
                    worker.state.ivm_execution_budget(),
                    1 << 20,
                ),
                preparation_refusal: None,
                proposal_admission: None,
            });
            queue.clear_all();
            clock.advance(Duration::from_millis(1));
            queue.push(original, worker.state.view()).unwrap();
            assert_eq!(queue.queued_len(), 1);
            assert!(queue.contains_entrypoint_hash(hash));
            assert!(queue.contains_pending_hash(hash, worker.state));
            let Some(payload) = worker.finish_payload_build().unwrap() else {
                panic!("original funded completion");
            };
            assert!(
                worker.completed_payload.is_none(),
                "byte-identical readmission cannot authorize retention of the original selection"
            );
            assert_eq!(
                payload::decode(payload.as_slice())
                    .unwrap()
                    .network_entrypoint_count(),
                1
            );
            assert!(
                matches!(
                    worker.admit_built_payload(payload.clone(), 2, 0),
                    Err(PublicationError::Retryable(_))
                ),
                "withdrawn original input custody must retry instead of halting consensus"
            );
            // New admission has its actual current timestamp and may capture its own fresh receipt.
            assert!(queue.contains_pending_hash(hash, worker.state));
            let fresh = worker.build(2, 0, 1 << 20, 100).unwrap().unwrap();
            assert_ne!(
                fresh.payload.as_slice().as_ptr(),
                payload.as_slice().as_ptr()
            );
            let repeated = worker.build(2, 0, 1 << 20, 100).unwrap().unwrap();
            assert_eq!(fresh.admission, repeated.admission);
            drop((payload, parent, time));
        });
    }

    #[test]
    fn completed_original_payload_is_retired_by_original_execution_and_certified_publication() {
        super::super::publication_tests::with_worker(|chain, worker, blocks, _events| {
            let (_queue, _clock, _time) = attach_queue(chain, worker);
            let generation = worker.state.state_view_generation();
            let Some(original) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("original")
            };
            let original_scope = worker.completed_payload.as_ref().unwrap().scope;
            let (block, qc) = super::super::publication_tests::executed(chain, worker);
            assert!(
                worker.completed_payload.is_none(),
                "actual native execution retires reuse"
            );
            worker.prepare(&block, &qc).unwrap();
            blocks.append(&block, &qc).unwrap();
            worker.commit(&block, &qc).unwrap();
            assert_eq!(worker.state.view().height(), 2);
            assert_ne!(worker.state.state_view_generation(), generation);
            assert!(!original_scope.is_current(worker.state, &worker.state.view(), worker.applied));
            assert_eq!(worker.build(2, 0, 1 << 20, 100).unwrap(), None);
            assert!(
                worker.completed_payload.is_none(),
                "old parent never returns its retained output"
            );
            drop(original);
        });
    }

    #[test]
    fn completed_original_payload_idle_expiry_reclaims_the_actual_original_pool() {
        // Pin before genesis so retired fixture State generations cannot alter exact refunds.
        let _fixture_epoch = crossbeam_epoch::pin();
        super::super::publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let (queue, clock, _time) = attach_queue(chain, worker);
            let budget = worker.state.ivm_execution_budget();
            let baseline = budget.reserved_bytes();
            let Some(original) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("original")
            };
            drop(original);
            assert!(worker.payload_storage_wait().unwrap() < queue.tx_time_to_live);
            assert!(budget.reserved_bytes() > baseline);
            clock.advance(queue.tx_time_to_live + Duration::from_secs(1));
            assert!(worker.payload_storage_wait().is_none());
            assert!(worker.completed_payload.is_none());
            assert_eq!(budget.reserved_bytes(), baseline);
            assert_eq!(
                queue.queued_len(),
                1,
                "local idle reclamation never isolates original Queue work"
            );
        });
    }

    #[test]
    fn completed_original_payload_preserves_actual_publisher_release_and_expires_while_it_is_held()
    {
        // Pin before genesis so retired fixture State generations cannot alter exact refunds.
        use std::{
            future::Future,
            task::{Context, Poll, Waker},
        };
        let _fixture_epoch = crossbeam_epoch::pin();
        for expire_while_held in [false, true] {
            super::super::publication_tests::with_worker(move |chain, worker, _blocks, _events| {
                let (queue, clock, _time) = attach_queue(chain, worker);
                let state = worker.state;
                let budget = state.ivm_execution_budget();
                let mut registration = crate::unit_test_support::release_registration(&budget);
                let baseline = budget.reserved_bytes();
                let current_view = state.view();
                let generation = state.state_view_generation();
                let parent = current_view
                    .canonical_history()
                    .executed_block(std::num::NonZeroUsize::MIN, |_, _| Ok(()))
                    .unwrap();
                let scope =
                    OriginalPayloadScope::capture(&current_view, generation, 2, 0, 1 << 20, 100);
                let selection = queue
                    .begin_pending_payload_selection(state, generation)
                    .unwrap();
                let selected = payload::select(
                    &state.view(),
                    &queue,
                    (1 << 20) - PAYLOAD_OVERHEAD,
                    &payload::MergeProposal::default(),
                    worker.context.time_source.now(),
                )
                .unwrap();
                assert_eq!(selected.len(), 1);
                let hash = selected[0].hash_as_entrypoint();
                let lease = queue
                    .capture_pending_payload_lease(
                        state,
                        selection,
                        &current_view,
                        &selected,
                        &budget,
                    )
                    .unwrap()
                    .unwrap();
                let scheduled = worker.scheduled(2).unwrap();
                let block = payload::assemble(
                    state,
                    Assembly {
                        parent: &parent,
                        view: 0,
                        cadence: Duration::from_millis(scheduled.params.block_time_ms),
                        proposed_time: worker.context.time_source.now(),
                    },
                    &selected,
                )
                .unwrap();

                worker.payload_build = Some(GlobalPayloadBuild {
                    scope,
                    job: super::super::super::driver::payload_build::PayloadBuild::new(
                        GlobalPayloadSource {
                            block,

                            pending_inputs: Some(lease),
                        },
                        budget.clone(),
                        1 << 20,
                    ),
                    preparation_refusal: None,
                    proposal_admission: None,
                });
                // The original staged builder already owns its real signed source.
                // A genuine publisher then opens before the output physically completes.
                let release = state.with_held_view_publication_for_reader_test(|release| {
                    assert_ne!(state.state_view_generation() % 2, 0);
                    let context = &mut Context::from_waker(Waker::noop());
                    let mut pending =
                        std::pin::pin!(release.clone().wait_for_release(&mut registration));
                    assert_eq!(pending.as_mut().poll(context), Poll::Pending);
                    let Some(original) = worker.finish_payload_build().unwrap() else {
                        panic!(
                            "the real original funded builder completes while publication is busy"
                        );
                    };
                    let pointer = original.as_slice().as_ptr();
                    let occupied = budget.reserved_bytes();
                    assert!(worker.completed_payload.is_some());
                    assert_eq!(
                        worker
                            .completed_payload
                            .as_ref()
                            .unwrap()
                            .payload
                            .as_slice()
                            .as_ptr(),
                        pointer
                    );
                    assert_eq!(queue.queued_len(), 1);
                    let error = worker
                        .reusable_completed_payload(scope, &parent, &current_view)
                        .unwrap_err();
                    let PublicationError::Deferred(PublicationDeferral::PublicationBusy(actual)) =
                        error
                    else {
                        panic!("the fenced original publication must refuse every lend");
                    };
                    assert_eq!(actual, release);
                    let error = worker.build(2, 0, 1 << 20, 100).unwrap_err();
                    let PublicationError::Deferred(PublicationDeferral::StateViewBusy(actual)) =
                        error
                    else {
                        panic!(
                            "the worker's one State view probe must return the original publisher"
                        );
                    };
                    assert_eq!(actual, release);
                    assert!(worker.payload_storage_wait().is_some());
                    assert_eq!(
                        worker
                            .completed_payload
                            .as_ref()
                            .unwrap()
                            .payload
                            .as_slice()
                            .as_ptr(),
                        pointer
                    );
                    assert_eq!(
                        budget.reserved_bytes(),
                        occupied,
                        "Busy preserves the same physical charges"
                    );
                    drop(original);
                    if expire_while_held {
                        clock.advance(queue.tx_time_to_live + Duration::from_secs(1));
                        assert!(
                            worker.payload_storage_wait().is_none(),
                            "idle reclamation must not wait for this publisher"
                        );
                        assert!(worker.completed_payload.is_none());
                        assert!(budget.reserved_bytes() < occupied);
                    } else {
                        assert!(worker.payload_storage_wait().is_some());
                    }
                    assert_eq!(queue.queued_len(), 1);
                    assert!(
                        queue.contains_entrypoint_hash(hash),
                        "local retirement never isolates original signed work"
                    );
                    assert_eq!(pending.as_mut().poll(context), Poll::Pending);
                    release
                });
                // The physical writer and its genuine visibility interval end naturally.
                let mut released =
                    std::pin::pin!(release.clone().wait_for_release(&mut registration));
                assert_eq!(
                    released
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Ready(())
                );
                assert!(state.try_view_once().is_ok());
                assert!(
                    worker.payload_storage_wait().is_none(),
                    "completed publication withdraws the old source generation"
                );
                assert!(worker.completed_payload.is_none());
                drop((parent, current_view, selected));
                assert_eq!(
                    budget.reserved_bytes(),
                    baseline,
                    "the paid output and original input table both refund"
                );
                assert_eq!(queue.queued_len(), 1);
                assert!(queue.contains_entrypoint_hash(hash));
            });
        }
    }

    #[test]
    fn completed_original_payload_retries_the_same_backing_after_actual_header_reader_release() {
        // Pin before genesis so retired fixture State generations cannot alter exact refunds.
        use std::{
            future::Future,
            task::{Context, Poll, Waker},
        };
        let _fixture_epoch = crossbeam_epoch::pin();
        super::super::publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let (queue, _clock, _time) = attach_queue(chain, worker);
            let state = worker.state;
            let budget = state.ivm_execution_budget();
            let mut registration = crate::unit_test_support::release_registration(&budget);
            let baseline = budget.reserved_bytes();
            let Some(original) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("original")
            };
            let pointer = original.payload.as_slice().as_ptr();
            let occupied = budget.reserved_bytes();
            let release = state.with_held_header_for_reader_test(|release| {
                let context = &mut Context::from_waker(Waker::noop());
                let mut pending =
                    std::pin::pin!(release.clone().wait_for_release(&mut registration));
                assert_eq!(pending.as_mut().poll(context), Poll::Pending);
                let error = worker.build(2, 0, 1 << 20, 100).unwrap_err();
                let PublicationError::Deferred(PublicationDeferral::StateViewBusy(actual)) = error
                else {
                    panic!("the actual held header reader must refuse without blocking");
                };
                assert_eq!(actual, release);
                assert!(worker.payload_storage_wait().is_some());
                assert_eq!(
                    worker
                        .completed_payload
                        .as_ref()
                        .unwrap()
                        .payload
                        .as_slice()
                        .as_ptr(),
                    pointer
                );
                assert_eq!(budget.reserved_bytes(), occupied);
                assert_eq!(pending.as_mut().poll(context), Poll::Pending);
                release
            });
            let mut released = std::pin::pin!(release.clone().wait_for_release(&mut registration));
            assert_eq!(
                released
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(())
            );
            let Some(retried) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("retry")
            };
            assert_eq!(retried.payload.as_slice().as_ptr(), pointer);
            assert_eq!(retried.payload.as_slice(), original.payload.as_slice());
            assert_eq!(budget.reserved_bytes(), occupied);
            drop((retried, original));
            worker.retire_completed_payload(2);
            assert_eq!(budget.reserved_bytes(), baseline);
            assert_eq!(queue.queued_len(), 1);
        });
    }

    #[test]
    fn completed_original_payload_refund_callback_follows_the_original_build_source_and_fences() {
        use std::{
            future::Future,
            sync::{
                Mutex,
                atomic::{AtomicUsize, Ordering},
            },
            task::{Context, Poll, Wake, Waker},
        };

        struct OriginalPoolProbe {
            state: Arc<State>,
            queue: Arc<Queue>,
            input: Mutex<Option<crate::tx::AcceptedTransaction<'static>>>,
            wakes: AtomicUsize,
        }
        impl Wake for OriginalPoolProbe {
            fn wake(self: Arc<Self>) {
                self.queue.assert_payload_mutation_fence_released_for_test();
                self.state
                    .assert_view_physical_fences_released_for_reader_test();
                self.wakes.fetch_add(1, Ordering::SeqCst);
                let input = self.input.lock().unwrap().take();
                if let Some(input) = input {
                    self.queue
                        .push(input, self.state.try_view_once().unwrap())
                        .unwrap();
                }
            }
        }

        super::super::publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let (queue, _clock, time) = attach_queue(chain, worker);
            let budget = worker.state.ivm_execution_budget();
            let mut registration = crate::unit_test_support::release_registration(&budget);
            let Some(original) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("original signed input");
            };
            let original_hash = {
                let block = payload::decode(original.payload.as_slice()).unwrap();
                assert_eq!(block.network_entrypoint_count(), 1);

                block.network_entrypoints().next().unwrap().hash()
            };
            drop(original);
            assert!(worker.completed_payload.is_some());
            let new_input = crate::tx::AcceptedTransaction::accept_with_time_source(
                chain.tick(2_001),
                &chain.network_id(),
                Duration::from_secs(1),
                chain.state().view().world().parameters().transaction(),
                &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
                    iroha_crypto::Algorithm::Ed25519,
                    iroha_crypto::Algorithm::Secp256k1,
                ])
                .expect("this stateless fixture explicitly selects Ed25519 and Secp256k1"),
                &time,
            )
            .unwrap();
            let new_hash = new_input.hash_as_entrypoint();
            assert_ne!(new_hash, original_hash);
            assert!(!queue.contains_entrypoint_hash(new_hash));
            let probe = Arc::new(OriginalPoolProbe {
                state: Arc::clone(chain.state()),
                queue: Arc::clone(&queue),
                input: Mutex::new(Some(new_input)),
                wakes: AtomicUsize::new(0),
            });
            let waker = Waker::from(Arc::clone(&probe));
            let context = &mut Context::from_waker(&waker);
            // This refuses at the actual original-pool capacity boundary without
            // allocating an occupant or changing the production admission limit.
            let requested = budget.limit_bytes() - budget.reserved_bytes() + 1;
            let iroha_allocation::AllocationRefusal::Capacity { release, .. } =
                budget.try_reserve_bytes(requested).unwrap_err()
            else {
                panic!("the genuine original pool must supply its capacity release");
            };
            let mut pending = std::pin::pin!(release.wait_for_release(&mut registration));
            assert_eq!(pending.as_mut().poll(context), Poll::Pending);
            assert_eq!(probe.wakes.load(Ordering::SeqCst), 0);
            assert_eq!(queue.queued_len(), 1);
            // The execution-budget change withdraws the actual old completed owner.
            // Its original source/view and all Queue guards live inside the refund scope.
            let Some(next) = worker.build(2, 0, 1 << 20, 101).unwrap() else {
                panic!("original source must build under the changed request");
            };
            {
                let next_block = payload::decode(next.payload.as_slice()).unwrap();
                assert_eq!(
                    next_block.network_entrypoint_count(),
                    1,
                    "a reentrant real refund callback must not inject signed input into an unfinished selection"
                );
                assert_eq!(
                    next_block.network_entrypoints().next().unwrap().hash(),
                    original_hash,
                    "the unfinished selection keeps its exact original signed source"
                );
            }
            assert!(probe.wakes.load(Ordering::SeqCst) > 0);
            assert_eq!(pending.as_mut().poll(context), Poll::Ready(()));
            assert_eq!(queue.queued_len(), 2);
            assert!(queue.contains_entrypoint_hash(new_hash));
            let Some(after_wake) = worker.build(2, 0, 1 << 20, 101).unwrap() else {
                panic!("unrelated callback admission must retain the completed original");
            };
            assert_eq!(
                after_wake.payload.as_slice().as_ptr(),
                next.payload.as_slice().as_ptr()
            );
            assert_eq!(after_wake.payload.as_slice(), next.payload.as_slice());
            // A genuinely changed request retires that completed selection and can
            // select the callback's pending suffix. Mere arrival cannot revoke it.
            advance_custody_fixture_clock(chain, worker, Duration::from_millis(2_002));
            let Some(changed_request) = worker.build(2, 0, 1 << 20, 102).unwrap() else {
                panic!("a fresh request must see actual newly admitted signed work");
            };
            {
                let after_wake_block = payload::decode(changed_request.payload.as_slice()).unwrap();
                assert_eq!(
                    after_wake_block.network_entrypoint_count(),
                    1,
                    "the next bounded FIFO window selects the newly admitted suffix"
                );
                assert_eq!(
                    after_wake_block
                        .network_entrypoints()
                        .next()
                        .unwrap()
                        .hash(),
                    new_hash,
                    "the actual refund callback's new signed input is selected exactly"
                );
            }
            assert!(queue.contains_entrypoint_hash(original_hash));
            assert!(queue.contains_entrypoint_hash(new_hash));
            drop((next, after_wake, changed_request));
            worker.retire_completed_payload(2);
            assert_eq!(
                queue.queued_len(),
                2,
                "original signed inputs remain owned by the Queue"
            );
        });
    }

    #[test]
    fn completed_original_payload_refuses_missing_real_canonical_parent_and_retries_restored_source()
     {
        struct OriginalJournal {
            path: std::path::PathBuf,
            saved: std::path::PathBuf,
        }
        impl Drop for OriginalJournal {
            fn drop(&mut self) {
                std::fs::rename(&self.saved, &self.path).unwrap();
            }
        }
        super::super::publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let (_queue, _clock, _time) = attach_queue(chain, worker);
            let Some(original) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("original");
            };
            let path = crate::kura::Kura::canonical_storage_path(&chain.kura().store_root())
                .join("blocks.data");
            let saved = path.with_extension("payload-original");
            std::fs::rename(&path, &saved).unwrap();
            let missing = OriginalJournal { path, saved };
            chain.kura().reset_canonical_query_reads_for_test();
            assert!(worker.build(2, 0, 1 << 20, 100).is_err());
            assert!(
                worker.completed_payload.is_none(),
                "a retained image cannot replace missing canonical custody"
            );
            assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
            drop(missing);
            let Some(restored) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("restored");
            };
            assert_ne!(
                restored.payload.as_slice().as_ptr(),
                original.payload.as_slice().as_ptr()
            );
            assert_eq!(restored.payload.as_slice(), original.payload.as_slice());
            assert!(chain.kura().canonical_query_reads_for_test().0 > 0);
            drop((restored, original));
        });
    }

    #[test]
    fn completed_original_payload_refuses_changed_real_parent_frame_without_substitution() {
        super::super::publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let (_queue, _clock, _time) = attach_queue(chain, worker);
            let Some(original) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("original")
            };
            chain
                .kura()
                .corrupt_native_frame_for_test(std::num::NonZeroUsize::MIN);
            assert!(
                worker.build(2, 0, 1 << 20, 100).is_err(),
                "retained output cannot replace its original physical parent"
            );
            assert!(worker.completed_payload.is_none());
            assert_eq!(worker.state.view().height(), 1);
            drop(original);
        });
    }

    #[test]
    fn completed_certified_lane_payload_keeps_original_output_across_same_scope_build_retry() {
        lanes::merge::with_original_lane_merge_fixture(
            |chain, lane_blocks, certify, [first, _second]| {
                super::super::publication_tests::with_worker_chain(
                    chain,
                    ConsensusMode::Permissioned,
                    lane_blocks,
                    |chain, worker, _blocks, _events| {
                        let parent_height = chain.height();
                        assert_eq!(parent_height, 3, "actual fixed-lane activation source");
                        let height = parent_height.checked_add(1).unwrap();
                        let (_, time) = iroha_primitives::time::TimeSource::new_mock(
                            Duration::from_millis(2_001),
                        );
                        let queue = Arc::new(Queue::test(
                            iroha_config::parameters::actual::Queue::default(),
                            &time,
                        ));
                        worker.queue = Some(Arc::clone(&queue));
                        let lane_hash = certify(1, parent_height, vec![first]);
                        advance_custody_fixture_clock(chain, worker, time.now());
                        let budget = worker.state.ivm_execution_budget();
                        let original = worker
                            .build(height, 0, 1 << 20, 100)
                            .unwrap()
                            .expect("genuine certified lane work");
                        assert!(original.payload.admitted_to(&budget));
                        let decoded = payload::decode(original.payload.as_slice()).unwrap();
                        assert_eq!(decoded.network_entrypoint_count(), 0);
                        let section = decoded.lane_merge().expect("actual certified lane range");
                        assert_eq!(section.merges.len(), 1);
                        assert_eq!(section.merges[0].to, 1);
                        assert_eq!(section.merges[0].tip_hash, lane_hash.0);
                        drop(decoded);
                        assert_eq!(queue.queued_len(), 0);

                        // A deadline retry creates a new Core request, but the Worker request
                        // still names this exact height/view/parent and complete build policy.
                        // Keep the first public output alive: a newly encoded allocation cannot
                        // coincidentally reuse its address and satisfy the retention assertion.
                        let retry = worker
                            .build(height, 0, 1 << 20, 100)
                            .unwrap()
                            .expect("same original certified lane work remains mandatory");
                        assert!(
                            std::ptr::eq(
                                original.payload.as_slice().as_ptr(),
                                retry.payload.as_slice().as_ptr()
                            ),
                            "completed certified lane payload must retain its exact output across build deadline retry"
                        );
                        assert_eq!(retry.payload.as_slice(), original.payload.as_slice());
                        assert!(retry.payload.admitted_to(&budget));
                        assert_eq!(queue.queued_len(), 0);
                        worker.retire_completed_payload(height);
                        assert!(worker.payload_build.is_none());
                        drop((retry, original));
                    },
                );
            },
        );
    }

    #[test]
    fn completed_certified_lane_payload_rechecks_actual_journal_and_mixed_queue_admission() {
        lanes::merge::with_original_lane_merge_fixture(
            |chain, lane_blocks, certify, [first, second]| {
                super::super::publication_tests::with_worker_chain(
                    chain,
                    ConsensusMode::Permissioned,
                    lane_blocks,
                    |chain, worker, _blocks, _events| {
                        let parent_height = chain.height();
                        let height = parent_height.checked_add(1).unwrap();
                        let (queue, clock, time) = attach_queue(chain, worker);
                        let first_hash = certify(1, parent_height, vec![first]);
                        advance_custody_fixture_clock(chain, worker, time.now());
                        let original = worker.build(height, 0, 1 << 20, 100).unwrap().unwrap();
                        let budget = worker.state.ivm_execution_budget();
                        let source = worker.payload_build.as_ref().unwrap().job.source();
                        assert!(source.block.signatures_admitted_to(&budget));
                        assert!(source.pending_inputs.as_ref().unwrap().belongs_to(&budget));
                        let original_range = source.block.lane_merge().unwrap().merges.as_ptr();
                        let original_hash = {
                            let block = payload::decode(original.payload.as_slice()).unwrap();
                            assert_eq!(block.network_entrypoint_count(), 1);
                            assert_eq!(
                                block.lane_merge().unwrap().merges[0].tip_hash,
                                first_hash.0
                            );
                            block.network_entrypoints().next().unwrap().hash()
                        };
                        let held = budget.reserved_bytes();
                        let retry = worker.build(height, 0, 1 << 20, 100).unwrap().unwrap();
                        assert!(std::ptr::eq(
                            original.payload.as_slice().as_ptr(),
                            retry.payload.as_slice().as_ptr()
                        ));
                        assert_eq!(
                            worker
                                .payload_build
                                .as_ref()
                                .unwrap()
                                .job
                                .source()
                                .block
                                .lane_merge()
                                .unwrap()
                                .merges
                                .as_ptr(),
                            original_range
                        );
                        assert_eq!(budget.reserved_bytes(), held);
                        drop(retry);

                        // The actual certified journal changes without changing global
                        // height or generation. Its new exact range and time floor revoke
                        // the old complete source; copied tip scalars grant no reuse.
                        let second_hash = certify(2, parent_height, vec![second]);
                        advance_custody_fixture_clock(chain, worker, time.now());
                        let expected = lanes::merge::propose(
                            &worker.state.view(),
                            &*worker.context.lane_blocks,
                            height,
                            &mut crate::sumeragi::lanes::ProposalReadScope::new(),
                        )
                        .unwrap();
                        let grown = worker.build(height, 0, 1 << 20, 100).unwrap().unwrap();
                        assert!(!std::ptr::eq(
                            original.payload.as_slice().as_ptr(),
                            grown.payload.as_slice().as_ptr()
                        ));
                        {
                            let block = payload::decode(grown.payload.as_slice()).unwrap();
                            let section = block.lane_merge().unwrap();
                            assert_eq!(section.merges, expected.merges);
                            assert_eq!(section.time_floor_ms, expected.time_floor_ms);
                            assert_eq!(section.merges[0].to, 2);
                            assert_eq!(section.merges[0].tip_hash, second_hash.0);
                        }
                        assert!(worker.payload_build.as_ref().unwrap().job.is_completed());

                        // Exact current lane work does not hide withdrawal/readmission
                        // of the independently funded original Queue selection.
                        queue.clear_all();
                        clock.advance(Duration::from_millis(1));
                        let new_hash = queue_work(chain, 2_001, &queue, &time);
                        assert_ne!(new_hash, original_hash);
                        let replaced = worker.build(height, 0, 1 << 20, 100).unwrap().unwrap();
                        assert!(!std::ptr::eq(
                            grown.payload.as_slice().as_ptr(),
                            replaced.payload.as_slice().as_ptr()
                        ));
                        {
                            let block = payload::decode(replaced.payload.as_slice()).unwrap();
                            assert_eq!(block.network_entrypoint_count(), 1);
                            assert_eq!(
                                block.network_entrypoints().next().unwrap().hash(),
                                new_hash
                            );
                            assert_eq!(block.lane_merge().unwrap().merges, expected.merges);
                            assert_eq!(
                                block.lane_merge().unwrap().time_floor_ms,
                                expected.time_floor_ms
                            );
                        }
                        assert!(replaced.payload.admitted_to(&budget));
                        assert!(worker.completed_payload.is_none());
                        assert_eq!(queue.queued_len(), 1);
                        assert!(!queue.contains_entrypoint_hash(original_hash));
                        clock.advance(queue.tx_time_to_live + Duration::from_secs(1));
                        assert!(worker.payload_storage_wait().is_none());
                        assert!(
                            worker.payload_build.is_none(),
                            "completed mixed work retires at actual input expiry"
                        );
                        assert_eq!(
                            queue.queued_len(),
                            1,
                            "storage retirement never removes signed Queue work"
                        );
                        drop((replaced, grown, original));
                    },
                );
            },
        );
    }

    #[test]
    fn completed_certified_lane_payload_preserves_original_busy_source_and_retires_on_request_or_execution()
     {
        lanes::merge::with_original_lane_merge_fixture(
            |chain, lane_blocks, certify, [first, _second]| {
                super::super::publication_tests::with_worker_chain(
                    chain,
                    ConsensusMode::Permissioned,
                    lane_blocks,
                    |chain, worker, blocks, _events| {
                        let height = chain.height().checked_add(1).unwrap();
                        let (_, time) = iroha_primitives::time::TimeSource::new_mock(
                            Duration::from_millis(2_001),
                        );
                        worker.queue = Some(Arc::new(Queue::test(
                            iroha_config::parameters::actual::Queue::default(),
                            &time,
                        )));
                        certify(1, chain.height(), vec![first]);
                        advance_custody_fixture_clock(chain, worker, time.now());
                        let original = worker.build(height, 0, 1 << 20, 100).unwrap().unwrap();
                        let state = worker.state;
                        let budget = state.ivm_execution_budget();
                        let scope = worker.payload_build.as_ref().unwrap().scope;
                        let range = worker
                            .payload_build
                            .as_ref()
                            .unwrap()
                            .job
                            .source()
                            .block
                            .lane_merge()
                            .unwrap()
                            .merges
                            .as_ptr();
                        let held = budget.reserved_bytes();
                        state.with_held_header_for_reader_test(|release| {
                            let PublicationError::Deferred(PublicationDeferral::StateViewBusy(
                                actual,
                            )) = worker.build(height, 0, 1 << 20, 100).unwrap_err()
                            else {
                                panic!("actual State reader must preserve its original release");
                            };
                            assert_eq!(actual, release);
                            assert!(
                                worker.payload_storage_wait().is_none(),
                                "lane-only work borrows no Queue expiry"
                            );
                            assert_eq!(worker.payload_build.as_ref().unwrap().scope, scope);
                            assert_eq!(
                                worker
                                    .payload_build
                                    .as_ref()
                                    .unwrap()
                                    .job
                                    .source()
                                    .block
                                    .lane_merge()
                                    .unwrap()
                                    .merges
                                    .as_ptr(),
                                range
                            );
                            assert_eq!(budget.reserved_bytes(), held);
                        });
                        let retry = worker.build(height, 0, 1 << 20, 100).unwrap().unwrap();
                        assert!(std::ptr::eq(
                            original.payload.as_slice().as_ptr(),
                            retry.payload.as_slice().as_ptr()
                        ));
                        assert_eq!(budget.reserved_bytes(), held);
                        drop(retry);
                        let new_view = worker.build(height, 1, 1 << 20, 100).unwrap().unwrap();
                        assert!(!std::ptr::eq(
                            original.payload.as_slice().as_ptr(),
                            new_view.payload.as_slice().as_ptr()
                        ));
                        assert_eq!(worker.payload_build.as_ref().unwrap().scope.view, 1);
                        let new_policy = worker.build(height, 1, 1 << 20, 101).unwrap().unwrap();
                        assert!(!std::ptr::eq(
                            new_view.payload.as_slice().as_ptr(),
                            new_policy.payload.as_slice().as_ptr()
                        ));
                        let new_cap = worker
                            .build(height, 1, (1 << 20) - 1, 101)
                            .unwrap()
                            .unwrap();
                        assert!(!std::ptr::eq(
                            new_policy.payload.as_slice().as_ptr(),
                            new_cap.payload.as_slice().as_ptr()
                        ));
                        worker.reject(height, 1, Hash32::ZERO);
                        assert!(
                            worker.payload_build.is_none(),
                            "explicit original-view rejection retires completion"
                        );
                        let rebuilt = worker.build(height, 0, 1 << 20, 100).unwrap().unwrap();
                        worker.discard(height, &[]);
                        assert!(
                            worker.payload_build.is_none(),
                            "explicit original-height discard retires completion"
                        );
                        let before_execution =
                            worker.build(height, 0, 1 << 20, 100).unwrap().unwrap();
                        let (block, qc) = super::super::publication_tests::executed(chain, worker);
                        assert!(
                            worker.payload_build.is_none(),
                            "actual native execution retires the completed lane owner"
                        );
                        worker.prepare(&block, &qc).unwrap();
                        blocks.append(&block, &qc).unwrap();
                        worker.commit(&block, &qc).unwrap();
                        assert_eq!(
                            worker.state.view().height(),
                            usize::try_from(height).unwrap()
                        );
                        assert_ne!(state.state_view_generation(), scope.generation);
                        assert_eq!(worker.build(height, 0, 1 << 20, 100).unwrap(), None);
                        assert!(worker.payload_build.is_none());
                        drop((
                            before_execution,
                            rebuilt,
                            new_cap,
                            new_policy,
                            new_view,
                            original,
                        ));
                    },
                );
            },
        );
    }
}
