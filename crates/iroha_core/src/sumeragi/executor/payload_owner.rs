//! Original completed global payload custody under an exact physical parent and Queue lease.

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
    parent: Option<NativeExecutionTip>,
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

    #[cfg(test)]
    fn is_current(
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

/// One original charged payload and selected-input table; shared lends reuse their same backing.
pub(super) struct CompletedPayload {
    pub(super) scope: OriginalPayloadScope,
    pending_inputs: crate::queue::PendingPayloadLease,
    payload: PayloadBytes,
    attest: bool,
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
    /// Resume a partial job only under its fresh physical parent, exact current lane
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
        if generation % 2 != 0 {
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
    ) -> Result<Option<(Option<PayloadBytes>, bool)>, PublicationError> {
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
        Ok(Some((Some(original.payload.clone()), original.attest)))
    }

    /// Keep the original nonempty funded output only while its captured queue inputs remain live.
    pub(super) fn retain_completed_payload(
        &mut self,
        scope: OriginalPayloadScope,
        pending_inputs: Option<crate::queue::PendingPayloadLease>,
        payload: &PayloadBytes,
        attest: bool,
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
                attest,
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
            &iroha_config::parameters::actual::Crypto::default(),
            time,
        )
        .unwrap();
        let hash = accepted.hash_as_entrypoint();
        queue.push(accepted, chain.state().view()).unwrap();
        hash
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
        queue_work(chain, 2_000, &queue, &time);
        worker.queue = Some(Arc::clone(&queue));
        (queue, clock, time)
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
        let state = worker.state;
        let budget = state.ivm_execution_budget();
        let current_view = state.view();
        let generation = state.state_view_generation();
        let height = worker
            .applied
            .0
            .checked_add(1)
            .expect("actual next global height");
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
        let merges =
            lanes::merge::propose(&current_view, &*worker.context.lane_blocks, height).unwrap();
        let selection = queue
            .begin_pending_payload_selection(state, generation)
            .unwrap();
        let selected = payload::select(
            state,
            queue,
            (1 << 20) - PAYLOAD_OVERHEAD,
            merges.transactions,
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
            },
            &selected,
            &merges,
        )
        .unwrap();
        let attest = height == scheduled.epoch.authorization.last_height;
        let wire_len = block.resultless_proposal_wire_len().unwrap();
        worker.payload_build = Some(GlobalPayloadBuild {
            scope,
            job: super::super::super::driver::payload_build::PayloadBuild::new(
                GlobalPayloadSource {
                    block,
                    attest,
                    pending_inputs: Some(lease),
                },
                budget.clone(),
                1 << 20,
            ),
            preparation_refusal: None,
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
                assert!(matches!(
                    worker.build(2, 0, 1 << 20, 100),
                    Err(PublicationError::Retryable(_))
                ));
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
            let (Some(output), _) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("the restored actual original source must release its same first output");
            };
            assert_eq!(output.as_slice().as_ptr(), pointer);
            assert_eq!(
                payload::decode(output.as_slice()).unwrap().hash(),
                source_hash
            );
            assert!(output.admitted_to(&budget));
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
            assert!(matches!(
                worker.build(2, 0, 1 << 20, 100),
                Err(PublicationError::Retryable(_))
            ));
            assert_eq!(retained_partial_pointer(worker), pointer);
            assert_eq!(budget.reserved_bytes(), held);
            assert!(worker.completed_payload.is_none());
            assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
            assert!(queue.contains_pending_hash(hash, worker.state));
            drop(replacement);
            let (Some(output), _) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("only the original journal object restores first-output custody");
            };
            assert_eq!(output.as_slice().as_ptr(), pointer);
            assert!(output.admitted_to(&budget));
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
            drop(pending);
            let (Some(output), _) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("both actual physical releases permit the same paid original wire");
            };
            assert_eq!(output.as_slice().as_ptr(), pointer);
            assert!(output.admitted_to(&budget));
            assert_eq!(queue.queued_len(), 1);
            drop(output);
        });
    }

    #[test]
    fn retained_partial_payload_preserves_actual_publication_release_until_source_withdrawal() {
        use std::{
            future::Future,
            task::{Context, Poll, Waker},
        };
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
            let merges =
                lanes::merge::propose(&current_view, &*worker.context.lane_blocks, 2).unwrap();
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
            drop(released);
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
        for expire in [false, true] {
            super::super::publication_tests::with_worker(move |chain, worker, _blocks, _events| {
                let (queue, clock, time) = attach_queue(chain, worker);
                let budget = worker.state.ivm_execution_budget();
                let baseline = budget.reserved_bytes();
                let (_pointer, original_hash) = stage_original_partial(worker, &queue);
                if expire {
                    clock.advance(queue.tx_time_to_live + Duration::from_secs(1));
                    assert_eq!(worker.build(2, 0, 1 << 20, 100).unwrap(), (None, false));
                    assert!(worker.payload_build.is_none());
                    assert!(worker.completed_payload.is_none());
                    assert_eq!(budget.reserved_bytes(), baseline);
                } else {
                    queue.clear_all();
                    clock.advance(Duration::from_millis(1));
                    queue_work(chain, 2_001, &queue, &time);
                    assert!(!queue.contains_entrypoint_hash(original_hash));
                    let (Some(output), _) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                        panic!("the current actual admission must replace the withdrawn selection");
                    };
                    let block = payload::decode(output.as_slice()).unwrap();
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
    fn retained_partial_payload_idle_expiry_refunds_while_original_parent_stays_unavailable() {
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
            let (Some(output), _) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
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
            let block = payload::decode(output.as_slice()).unwrap();
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
                        let (Some(output), _) = worker.build(height, 0, 1 << 20, 100).unwrap()
                        else {
                            panic!(
                                "newly certified mandatory lane work must rebuild the old Queue-only plan"
                            );
                        };
                        let block = payload::decode(output.as_slice()).unwrap();
                        let section = block.lane_merge().unwrap();
                        assert_eq!(section.merges.len(), 1);
                        assert_eq!(section.merges[0].to, 1);
                        assert_eq!(section.merges[0].tip_hash, first_hash.0);
                        assert!(
                            worker.completed_payload.is_none(),
                            "mixed work grants no completed Queue-only lease"
                        );
                        assert!(worker.payload_build.is_none());
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
                        let current = lanes::merge::propose(
                            &worker.state.view(),
                            &*worker.context.lane_blocks,
                            height,
                        )
                        .unwrap();
                        let (Some(output), _) = worker.build(height, 0, 1 << 20, 100).unwrap()
                        else {
                            panic!(
                                "growth of the real certified journal must rebuild the old mixed range"
                            );
                        };
                        let block = payload::decode(output.as_slice()).unwrap();
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
                        let (Some(output), _) = worker.build(height, 0, 1 << 20, 100).unwrap()
                        else {
                            panic!(
                                "current mixed work must preserve the mandatory lane plan and new actual admission"
                            );
                        };
                        let block = payload::decode(output.as_slice()).unwrap();
                        assert_eq!(block.lane_merge().unwrap().merges, current.merges);
                        assert_eq!(block.network_entrypoint_count(), 1);
                        assert!(
                            block
                                .network_entrypoints()
                                .all(|entry| entry.hash() != original_hash)
                        );
                        assert!(worker.completed_payload.is_none());
                        assert!(worker.payload_build.is_none());
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
        super::super::publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let (queue, _clock, _time) = attach_queue(chain, worker);
            let budget = worker.state.ivm_execution_budget();
            let baseline = budget.reserved_bytes();
            let (Some(original), attest) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("original real signed work must produce nonempty funded custody");
            };
            assert!(!attest);
            let pointer = original.as_slice().as_ptr();
            let retained = budget.reserved_bytes();
            assert!(retained > baseline);
            assert!(worker.completed_payload.is_some());
            assert!(worker.payload_build.is_none());
            chain.kura().reset_canonical_query_reads_for_test();
            // A second request for the same actual applied source lends its completed owner.
            // Keeping the first output live also makes a replacement allocation observable.
            let (Some(retried), false) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("the new request must lend the actual completed original");
            };
            assert_eq!(
                retried.as_slice().as_ptr(),
                pointer,
                "no assembly or encoding allocates a replacement"
            );
            assert_eq!(retried.as_slice(), original.as_slice());
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
    fn completed_original_payload_retires_on_actual_queue_mutation_expiry_or_rejection() {
        super::super::publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let (queue, clock, time) = attach_queue(chain, worker);
            let (Some(original), _) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("original")
            };
            let original_hash = {
                let block = payload::decode(original.as_slice()).unwrap();
                assert_eq!(block.network_entrypoint_count(), 1);
                let hash = block.network_entrypoints().next().unwrap().hash();
                hash
            };
            let added_hash = queue_work(chain, 2_001, &queue, &time);
            assert_ne!(added_hash, original_hash);
            let (Some(next), _) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("next input")
            };
            assert_ne!(next.as_slice().as_ptr(), original.as_slice().as_ptr());
            {
                let next_block = payload::decode(next.as_slice()).unwrap();
                assert_eq!(
                    next_block.network_entrypoint_count(),
                    1,
                    "the bounded FIFO window advances from the old row to the newly admitted suffix"
                );
                assert_eq!(
                    next_block.network_entrypoints().next().unwrap().hash(),
                    added_hash,
                    "queue mutation retires old reuse authority and selects the exact new input"
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
            let (Some(expiring), _) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("expiring original")
            };
            clock.advance(queue.tx_time_to_live + Duration::from_secs(1));
            assert_eq!(worker.build(2, 0, 1 << 20, 100).unwrap(), (None, false));
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
            let (Some(original), _) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("original")
            };
            let (Some(other_view), _) = worker.build(2, 1, 1 << 20, 100).unwrap() else {
                panic!("view")
            };
            assert_ne!(other_view.as_slice().as_ptr(), original.as_slice().as_ptr());
            let (Some(other_limit), _) = worker.build(2, 1, (1 << 20) - 1, 100).unwrap() else {
                panic!("limit")
            };
            assert_ne!(
                other_limit.as_slice().as_ptr(),
                other_view.as_slice().as_ptr()
            );
            let (Some(other_budget), _) = worker.build(2, 1, (1 << 20) - 1, 101).unwrap() else {
                panic!("budget")
            };
            assert_ne!(
                other_budget.as_slice().as_ptr(),
                other_limit.as_slice().as_ptr()
            );
            worker.serve(Request::AttachQueue(Arc::clone(
                worker.queue.as_ref().unwrap(),
            )));
            assert!(
                worker.completed_payload.is_none(),
                "even same-object explicit queue attachment retires original custody"
            );
            let (Some(reattached), _) = worker.build(2, 1, (1 << 20) - 1, 101).unwrap() else {
                panic!("reattached")
            };
            assert_ne!(
                reattached.as_slice().as_ptr(),
                other_budget.as_slice().as_ptr()
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
            let selected =
                payload::select(worker.state, &queue, (1 << 20) - PAYLOAD_OVERHEAD, 0).unwrap();
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
                },
                &selected,
            )
            .unwrap();
            let attest = 2 == scheduled.epoch.authorization.last_height;
            worker.payload_build = Some(GlobalPayloadBuild {
                scope,
                job: super::super::super::driver::payload_build::PayloadBuild::new(
                    GlobalPayloadSource {
                        block,
                        attest,
                        pending_inputs: Some(lease),
                    },
                    worker.state.ivm_execution_budget(),
                    1 << 20,
                ),
                preparation_refusal: None,
            });
            queue.clear_all();
            clock.advance(Duration::from_millis(1));
            queue.push(original, worker.state.view()).unwrap();
            assert_eq!(queue.queued_len(), 1);
            assert!(queue.contains_entrypoint_hash(hash));
            assert!(queue.contains_pending_hash(hash, worker.state));
            let (Some(payload), _) = worker.finish_payload_build().unwrap() else {
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
            // New admission has its actual current timestamp and may capture its own fresh receipt.
            assert!(queue.contains_pending_hash(hash, worker.state));
            drop((payload, parent, time));
        });
    }

    #[test]
    fn completed_original_payload_is_retired_by_original_execution_and_certified_publication() {
        super::super::publication_tests::with_worker(|chain, worker, blocks, _events| {
            let (_queue, _clock, _time) = attach_queue(chain, worker);
            let generation = worker.state.state_view_generation();
            let (Some(original), _) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
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
            assert_eq!(worker.build(2, 0, 1 << 20, 100).unwrap(), (None, false));
            assert!(
                worker.completed_payload.is_none(),
                "old parent never returns its retained output"
            );
            drop(original);
        });
    }

    #[test]
    fn completed_original_payload_idle_expiry_reclaims_the_actual_original_pool() {
        super::super::publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let (queue, clock, _time) = attach_queue(chain, worker);
            let budget = worker.state.ivm_execution_budget();
            let baseline = budget.reserved_bytes();
            let (Some(original), _) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
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
        use std::{
            future::Future,
            task::{Context, Poll, Waker},
        };
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
                let selected =
                    payload::select(state, &queue, (1 << 20) - PAYLOAD_OVERHEAD, 0).unwrap();
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
                    },
                    &selected,
                )
                .unwrap();
                let attest = 2 == scheduled.epoch.authorization.last_height;
                worker.payload_build = Some(GlobalPayloadBuild {
                    scope,
                    job: super::super::super::driver::payload_build::PayloadBuild::new(
                        GlobalPayloadSource {
                            block,
                            attest,
                            pending_inputs: Some(lease),
                        },
                        budget.clone(),
                        1 << 20,
                    ),
                    preparation_refusal: None,
                });
                // The original staged builder already owns its real signed source.
                // A genuine publisher then opens before the output physically completes.
                let release = state.with_held_view_publication_for_reader_test(|release| {
                    assert_ne!(state.state_view_generation() % 2, 0);
                    let context = &mut Context::from_waker(Waker::noop());
                    let mut pending =
                        std::pin::pin!(release.clone().wait_for_release(&mut registration));
                    assert_eq!(pending.as_mut().poll(context), Poll::Pending);
                    let (Some(original), _) = worker.finish_payload_build().unwrap() else {
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
                drop(released);
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
        use std::{
            future::Future,
            task::{Context, Poll, Waker},
        };
        super::super::publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let (queue, _clock, _time) = attach_queue(chain, worker);
            let state = worker.state;
            let budget = state.ivm_execution_budget();
            let mut registration = crate::unit_test_support::release_registration(&budget);
            let baseline = budget.reserved_bytes();
            let (Some(original), _) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("original")
            };
            let pointer = original.as_slice().as_ptr();
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
            drop(released);
            let (Some(retried), _) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("retry")
            };
            assert_eq!(retried.as_slice().as_ptr(), pointer);
            assert_eq!(retried.as_slice(), original.as_slice());
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
            let (Some(original), _) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("original signed input");
            };
            let original_hash = {
                let block = payload::decode(original.as_slice()).unwrap();
                assert_eq!(block.network_entrypoint_count(), 1);
                let hash = block.network_entrypoints().next().unwrap().hash();
                hash
            };
            drop(original);
            assert!(worker.completed_payload.is_some());
            let new_input = crate::tx::AcceptedTransaction::accept_with_time_source(
                chain.tick(2_001),
                &chain.network_id(),
                Duration::from_secs(1),
                chain.state().view().world().parameters().transaction(),
                &iroha_config::parameters::actual::Crypto::default(),
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
            let (Some(next), _) = worker.build(2, 0, 1 << 20, 101).unwrap() else {
                panic!("original source must build under the changed request");
            };
            {
                let next_block = payload::decode(next.as_slice()).unwrap();
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
            let (Some(after_wake), _) = worker.build(2, 0, 1 << 20, 101).unwrap() else {
                panic!("the next request must see actual newly admitted signed work");
            };
            {
                let after_wake_block = payload::decode(after_wake.as_slice()).unwrap();
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
            drop((next, after_wake));
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
            let (Some(original), _) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
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
            let (Some(restored), _) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("restored");
            };
            assert_ne!(restored.as_slice().as_ptr(), original.as_slice().as_ptr());
            assert_eq!(restored.as_slice(), original.as_slice());
            assert!(chain.kura().canonical_query_reads_for_test().0 > 0);
            drop((restored, original));
        });
    }

    #[test]
    fn completed_original_payload_refuses_changed_real_parent_frame_without_substitution() {
        super::super::publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let (_queue, _clock, _time) = attach_queue(chain, worker);
            let (Some(original), _) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
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
}
