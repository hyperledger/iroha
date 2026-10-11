//! One physically prepaid original queue-input lease for a completed native payload.

use super::*;
use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};

/// Fixed comparison receipt captured before the actual Queue selection begins.
/// Copying it grants no custody; lease capture must recheck its original fence generation.
#[derive(Clone, Copy)]
pub(crate) struct PendingPayloadSelection {
    queue_address: usize,
    state_address: usize,
    publication_generation: u64,
    generation: u64,
}

/// Fixed original-queue identity and its finite physically funded selected-input table.
/// This comparison-only local owner has no decoder or authority outside the original Queue.
pub(crate) struct PendingPayloadLease {
    queue_address: usize,
    state_address: usize,
    publication_generation: u64,
    generation: u64,
    expires_at: Duration,
    hashes: ChargedBuffer<EntrypointHash>,
}

impl PendingPayloadLease {
    /// Verify the original operation pool without allocating replacement metadata.
    pub(crate) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.hashes.belongs_to(budget)
    }
}

impl Queue {
    /// Probe the actual Queue mutation fence from an original-pool test waker.
    #[cfg(test)]
    pub(crate) fn assert_payload_mutation_fence_released_for_test(&self) {
        let _held = self
            .push_remove_lock
            .try_lock()
            .expect("original refund callback runs after the Queue mutation fence");
    }

    /// Bind the actual pre-selection Queue and State generation without transferring inputs.
    pub(crate) fn begin_pending_payload_selection(
        &self,
        state: &State,
        publication_generation: u64,
    ) -> Option<PendingPayloadSelection> {
        let _guard = self.push_remove_lock.lock();
        if self.admission_faulted()
            || !crate::state::is_stable_state_view_generation(
                publication_generation,
                state.state_view_generation(),
            )
        {
            return None;
        }
        Some(PendingPayloadSelection {
            queue_address: std::ptr::from_ref(self).addr(),
            state_address: std::ptr::from_ref(state).addr(),
            publication_generation,
            generation: self.pending_ownership_generation.load(Ordering::Acquire),
        })
    }

    /// Called under the original mutation fence after a successful ownership transition.
    /// Overflow permanently refuses reuse and admission instead of wrapping an old lease live.
    pub(super) fn advance_pending_ownership_generation(&self, hash: EntrypointHash) {
        if self
            .pending_ownership_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |prior| {
                if cfg!(all(test, sumeragi_core_mutation = "HC145")) {
                    Some(prior.wrapping_add(1))
                } else {
                    prior.checked_add(1)
                }
            })
            .is_err()
        {
            self.mark_accepted_work_validation_fault(
                hash,
                "pending_payload_ownership_generation",
                &"original Queue ownership generation exhausted",
                None,
            );
        }
    }

    /// Capture exact admitted signed inputs under one original Queue ownership generation.
    /// No queue or accepted-input graph is retained or cloned by this lease.
    ///
    /// # Errors
    /// Keeps the original physical pool/allocator refusal before any payload is constructed.
    pub(crate) fn capture_pending_payload_lease(
        &self,
        state: &State,
        selection: PendingPayloadSelection,
        view: &StateView<'_>,
        selected: &[AcceptedTransaction<'static>],
        budget: &AllocationBudget,
    ) -> Result<Option<PendingPayloadLease>, ChargedBufferError> {
        if selected.is_empty() || selected.len() > crate::sumeragi::payload::MAX_QUEUE_SCAN.get() {
            return Ok(None);
        }
        budget.with_deferred_refund_notifications(|_| {
            #[cfg(not(all(test, sumeragi_core_mutation = "HC144")))]
            let mut hashes = ChargedBuffer::new(selected.len(), budget)?;
            #[cfg(all(test, sumeragi_core_mutation = "HC144"))]
            let mut hashes = match ChargedBuffer::new(selected.len(), budget) {
                Ok(hashes) => hashes,
                Err(ChargedBufferError::Admission(_)) => return Ok(None),
                Err(error) => return Err(error),
            };
            let guard = self.push_remove_lock.lock();
            if self.admission_faulted()
                || selection.queue_address != std::ptr::from_ref(self).addr()
                || selection.state_address != std::ptr::from_ref(state).addr()
                || (!cfg!(all(test, sumeragi_core_mutation = "HC141"))
                    && selection.generation
                        != self.pending_ownership_generation.load(Ordering::Acquire))
                || !crate::state::is_stable_state_view_generation(
                    selection.publication_generation,
                    state.state_view_generation(),
                )
            {
                return Ok(None);
            }
            let now = self.time_source.get_unix_time();
            let mut expires_at = None::<Duration>;
            for original in selected {
                let hash = original.hash_as_entrypoint();
                let Some(tracked) = self.txs.get(&hash) else {
                    return Ok(None);
                };
                if tracked.as_accepted().entrypoint() != original.entrypoint()
                    || tracked.is_in_blockchain(view)
                    || self.is_expired_at(tracked.as_accepted(), now)
                {
                    return Ok(None);
                }
                let deadline = if matches!(
                    original.entrypoint(),
                    TransactionEntrypoint::SealedCommitment(_)
                ) {
                    let Some(timestamp) = self.tx_enqueued_at_ms.get(&hash) else {
                        return Ok(None);
                    };
                    // Original sealed residence expires when the integer millisecond
                    // age exceeds the actual Queue TTL, including its rounding rule.
                    timestamp
                        .value()
                        .checked_add(Self::duration_to_millis(self.tx_time_to_live))
                        .and_then(|last_live_ms| last_live_ms.checked_add(1))
                        .map(Duration::from_millis)
                } else {
                    original
                        .creation_time()
                        .checked_add(self.effective_tx_time_to_live(original))
                        .and_then(|limit| limit.checked_add(Duration::from_nanos(1)))
                };
                let Some(deadline) = deadline else {
                    return Ok(None);
                };
                expires_at = Some(expires_at.map_or(deadline, |prior| prior.min(deadline)));
                hashes
                    .try_push(hash)
                    .expect("prepaid exact selected-input count");
            }
            let generation = self.pending_ownership_generation.load(Ordering::Acquire);
            if !crate::state::is_stable_state_view_generation(
                selection.publication_generation,
                state.state_view_generation(),
            ) {
                return Ok(None);
            }
            drop(guard);
            Ok(Some(PendingPayloadLease {
                queue_address: std::ptr::from_ref(self).addr(),
                state_address: std::ptr::from_ref(state).addr(),
                publication_generation: selection.publication_generation,
                generation,
                expires_at: expires_at
                    .expect("a nonempty original input table has its actual expiry"),
                hashes,
            }))
        })
    }

    /// Recheck live original input custody, expiry and applied-state absence as one read.
    /// Any insertion/removal conservatively retires this lease, including same-hash readmission.
    #[cfg(test)]
    pub(crate) fn pending_payload_lease_is_current(
        &self,
        state: &State,
        view: &StateView<'_>,
        lease: &PendingPayloadLease,
    ) -> bool {
        self.pending_payload_lease_wait(state, view, lease)
            .is_ok_and(|wait| wait.is_some())
    }

    /// Remaining residence of this original owner, from its exact selected-input expiry.
    /// A zero/expired or revoked lease never arms another wakeup.
    ///
    /// # Errors
    /// An unfinished State publisher returns its actual pre-probe release observation;
    /// that transient refusal authorizes no lend and does not retire the paid original.
    pub(crate) fn pending_payload_lease_wait(
        &self,
        state: &State,
        view: &StateView<'_>,
        lease: &PendingPayloadLease,
    ) -> Result<Option<Duration>, iroha_allocation::release::ReleaseWait> {
        // Observe without acquiring a State lock, before probing under the Queue fence.
        let publication_release = state.view_publication_release();
        let _guard = self.push_remove_lock.lock();
        if (!cfg!(all(test, sumeragi_core_mutation = "HC142"))
            && lease.queue_address != std::ptr::from_ref(self).addr())
            || lease.state_address != std::ptr::from_ref(state).addr()
            || self.admission_faulted()
            || lease.generation != self.pending_ownership_generation.load(Ordering::Acquire)
        {
            return Ok(None);
        }
        let now = self.time_source.get_unix_time();
        #[cfg(all(test, sumeragi_core_mutation = "HC143"))]
        let remaining = lease.expires_at.saturating_sub(now);
        #[cfg(not(all(test, sumeragi_core_mutation = "HC143")))]
        let Some(remaining) = lease
            .expires_at
            .checked_sub(now)
            .filter(|wait| !wait.is_zero())
        else {
            return Ok(None);
        };
        let before = state.state_view_generation();
        if before % 2 != 0 {
            return Err(publication_release);
        }
        if before != lease.publication_generation
            && !cfg!(all(test, sumeragi_core_mutation = "HC140"))
        {
            return Ok(None);
        }
        let live = lease.hashes.as_slice().iter().all(|hash| {
            self.txs.get(hash).is_some_and(|tracked| {
                !tracked.is_in_blockchain(view)
                    && (cfg!(all(test, sumeragi_core_mutation = "HC143"))
                        || !self.is_expired_at(tracked.as_accepted(), now))
            })
        });
        let after = state.state_view_generation();
        if after % 2 != 0 {
            return Err(publication_release);
        }
        Ok(
            (live && crate::state::is_stable_state_view_generation(before, after))
                .then_some(remaining),
        )
    }

    /// Actual remaining expiry only; this creates no current-input or publication authority.
    pub(crate) fn pending_payload_lease_expiry_wait(
        &self,
        state: &State,
        lease: &PendingPayloadLease,
    ) -> Option<Duration> {
        let _guard = self.push_remove_lock.lock();
        let publication_generation = state.state_view_generation();
        if lease.queue_address != std::ptr::from_ref(self).addr()
            || lease.state_address != std::ptr::from_ref(state).addr()
            || self.admission_faulted()
            || lease.generation != self.pending_ownership_generation.load(Ordering::Acquire)
            || (publication_generation % 2 == 0
                && publication_generation != lease.publication_generation)
        {
            return None;
        }
        lease
            .expires_at
            .checked_sub(self.time_source.get_unix_time())
            .filter(|wait| !wait.is_zero())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };

    fn capture_current(
        queue: &Queue,
        state: &State,
        view: &StateView<'_>,
        selected: &[AcceptedTransaction<'static>],
        budget: &AllocationBudget,
    ) -> Result<Option<PendingPayloadLease>, ChargedBufferError> {
        let Some(selection) =
            queue.begin_pending_payload_selection(state, state.state_view_generation())
        else {
            return Ok(None);
        };
        queue.capture_pending_payload_lease(state, selection, view, selected, budget)
    }

    fn signed_work(
        chain: &CertifiedTestChain,
        key: &iroha_crypto::KeyPair,
        created_ms: u64,
    ) -> SignedTransaction {
        chain.sign(
            key,
            [InstructionBox::from(iroha_data_model::isi::Log::new(
                iroha_data_model::level::Level::INFO,
                "original payload lease".into(),
            ))],
            created_ms,
        )
    }

    #[test]
    fn pending_payload_lease_uses_original_backing_and_retires_on_expiry_withdrawal_or_foreign_queue()
     {
        let configuration = TestChainConfig::new(World::new(), 1_000);
        let key = configuration.genesis_key.clone();
        let chain = CertifiedTestChain::start(configuration).unwrap();
        let (clock, time) = TimeSource::new_mock(Duration::from_millis(2_001));
        let configuration = Config::default();
        let queue = Queue::test(configuration.clone(), &time);
        let foreign = Queue::test(configuration, &time);
        let signed = signed_work(&chain, &key, 2_000);
        let accepted = AcceptedTransaction::accept_with_time_source(
            signed,
            &chain.network_id(),
            Duration::from_secs(1),
            chain.state().view().world().parameters().transaction(),
            &iroha_config::parameters::actual::Crypto::default(),
            &time,
        )
        .unwrap();
        let hash = accepted.hash_as_entrypoint();
        let budget = chain.state().ivm_execution_budget();
        let before_admission = budget.reserved_bytes();
        let shell_bytes = iroha_allocation::shared::Shared::<
            CheckedTransaction<'static>,
            resident_owner::QueueResidentCharge,
        >::layout()
        .size();
        let ledger_bytes =
            iroha_allocation::ChargedShared::<QueueResidentLedger>::allocation_layout().size();
        queue.push(accepted.clone(), chain.state().view()).unwrap();
        foreign
            .push(accepted.clone(), chain.state().view())
            .unwrap();
        let baseline = budget.reserved_bytes();
        assert_eq!(
            baseline,
            before_admission + 2 * (ledger_bytes + shell_bytes),
            "each original Queue prepays its own ledger and accepted-input shell"
        );
        let view = chain.state().view();
        let original = capture_current(
            &queue,
            chain.state(),
            &view,
            std::slice::from_ref(&accepted),
            &budget,
        )
        .unwrap()
        .unwrap();
        assert!(original.belongs_to(&budget));
        assert!(!original.belongs_to(&AllocationBudget::new(budget.limit_bytes())));
        assert!(
            budget.reserved_bytes() > baseline,
            "actual original input table is prepaid"
        );
        assert!(queue.pending_payload_lease_is_current(chain.state(), &view, &original));
        assert!(!foreign.pending_payload_lease_is_current(chain.state(), &view, &original));
        clock.advance(queue.tx_time_to_live + Duration::from_secs(1));
        assert!(!queue.pending_payload_lease_is_current(chain.state(), &view, &original));
        queue.cull_expired_entries_if_due();
        assert!(
            !queue.contains_entrypoint_hash(hash),
            "actual expired custody was withdrawn"
        );
        clock.set(Duration::from_millis(2_001));
        queue.push(accepted.clone(), chain.state().view()).unwrap();
        assert!(
            !queue.pending_payload_lease_is_current(chain.state(), &view, &original),
            "same hash cannot revive withdrawn original custody"
        );
        let replacement = capture_current(
            &queue,
            chain.state(),
            &view,
            std::slice::from_ref(&accepted),
            &budget,
        )
        .unwrap()
        .unwrap();
        assert!(queue.pending_payload_lease_is_current(chain.state(), &view, &replacement));
        let additional = AcceptedTransaction::accept_with_time_source(
            signed_work(&chain, &key, 2_001),
            &chain.network_id(),
            Duration::from_secs(1),
            view.world().parameters().transaction(),
            &iroha_config::parameters::actual::Crypto::default(),
            &time,
        )
        .unwrap();
        queue.push(additional, chain.state().view()).unwrap();
        assert!(!queue.pending_payload_lease_is_current(chain.state(), &view, &replacement));
        drop(replacement);
        drop(original);
        assert_eq!(
            budget.reserved_bytes(),
            baseline + shell_bytes,
            "lease hashes retire; the additional admitted input keeps its actual shell"
        );
        assert_eq!((queue.queued_len(), foreign.queued_len()), (2, 1));
        queue.clear_all();
        foreign.clear_all();
        assert_eq!((queue.queued_len(), foreign.queued_len()), (0, 0));
        assert_eq!((queue.retained_bytes(), foreign.retained_bytes()), (0, 0));
        assert_eq!(
            budget.reserved_bytes(),
            before_admission + 2 * ledger_bytes,
            "clearing the real inputs refunds all shells while both Queue ledgers remain live"
        );
        drop(queue);
        assert_eq!(budget.reserved_bytes(), before_admission + ledger_bytes);
        drop(foreign);
        assert_eq!(budget.reserved_bytes(), before_admission);
    }

    #[test]
    fn pending_payload_selection_cannot_adopt_clear_and_readmission_during_selection() {
        let configuration = TestChainConfig::new(World::new(), 1_000);
        let key = configuration.genesis_key.clone();
        let chain = CertifiedTestChain::start(configuration).unwrap();
        let (clock, time) = TimeSource::new_mock(Duration::from_millis(2_001));
        let queue = Arc::new(Queue::test(Config::default(), &time));
        let accepted = AcceptedTransaction::accept_with_time_source(
            signed_work(&chain, &key, 2_000),
            &chain.network_id(),
            Duration::from_secs(1),
            chain.state().view().world().parameters().transaction(),
            &iroha_config::parameters::actual::Crypto::default(),
            &time,
        )
        .unwrap();
        let hash = accepted.hash_as_entrypoint();
        queue.push(accepted.clone(), chain.state().view()).unwrap();
        let timestamp = *queue.tx_enqueued_at_ms.get(&hash).unwrap();
        let view = chain.state().view();
        let selection = queue
            .begin_pending_payload_selection(chain.state(), chain.state().state_view_generation())
            .unwrap();
        let selected = queue
            .bounded_pending_snapshot(&view, crate::sumeragi::payload::MAX_QUEUE_SCAN)
            .unwrap();
        assert_eq!(selected.len(), 1);
        queue.clear_all();
        clock.advance(Duration::from_millis(1));
        queue.push(accepted, chain.state().view()).unwrap();
        assert_eq!(queue.queued_len(), 1);
        assert!(queue.contains_entrypoint_hash(hash));
        assert_eq!(
            queue.time_source.get_unix_time(),
            Duration::from_millis(2_002)
        );
        assert_eq!(
            *queue.tx_enqueued_at_ms.get(&hash).unwrap(),
            timestamp,
            "readmission preserves this cloned input's exact ingress validation timestamp"
        );
        assert!(
            queue.pending_ownership_generation.load(Ordering::Acquire) > selection.generation,
            "clear and readmission create a fresh original custody boundary even with the same hash and timestamp"
        );
        let budget = chain.state().ivm_execution_budget();
        let before = budget.reserved_bytes();
        assert!(
            queue
                .capture_pending_payload_lease(chain.state(), selection, &view, &selected, &budget)
                .unwrap()
                .is_none()
        );
        assert_eq!(budget.reserved_bytes(), before);
        assert!(
            capture_current(&queue, chain.state(), &view, &selected, &budget)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn pending_payload_lease_retires_on_actual_certified_state_publication() {
        let configuration = TestChainConfig::new(World::new(), 1_000);
        let key = configuration.genesis_key.clone();
        let mut chain = CertifiedTestChain::start(configuration).unwrap();
        let (_, time) = TimeSource::new_mock(Duration::from_millis(2_001));
        let queue = Queue::test(Config::default(), &time);
        let accepted = AcceptedTransaction::accept_with_time_source(
            signed_work(&chain, &key, 2_000),
            &chain.network_id(),
            Duration::from_secs(1),
            chain.state().view().world().parameters().transaction(),
            &iroha_config::parameters::actual::Crypto::default(),
            &time,
        )
        .unwrap();
        queue.push(accepted.clone(), chain.state().view()).unwrap();
        let budget = chain.state().ivm_execution_budget();
        let generation = chain.state().state_view_generation();
        let original = capture_current(
            &queue,
            chain.state(),
            &chain.state().view(),
            std::slice::from_ref(&accepted),
            &budget,
        )
        .unwrap()
        .unwrap();
        assert!(queue.pending_payload_lease_is_current(
            chain.state(),
            &chain.state().view(),
            &original
        ));
        // CertifiedTestChain supplies a real signed clock transaction, execution and exact quorum.
        chain.commit(Vec::new());
        assert_eq!(chain.state().view().height(), 2);
        assert_ne!(chain.state().state_view_generation(), generation);
        assert!(!queue.pending_payload_lease_is_current(
            chain.state(),
            &chain.state().view(),
            &original
        ));
        assert_eq!(
            queue.queued_len(),
            1,
            "generation withdrawal does not isolate the original input"
        );
    }

    #[test]
    fn pending_payload_lease_preserves_original_capacity_refusal_and_refuses_generation_wrap() {
        let configuration = TestChainConfig::new(World::new(), 1_000);
        let key = configuration.genesis_key.clone();
        let chain = CertifiedTestChain::start(configuration).unwrap();
        let (clock, time) = TimeSource::new_mock(Duration::from_millis(2_001));
        let queue = Queue::test(Config::default(), &time);
        let accepted = AcceptedTransaction::accept_with_time_source(
            signed_work(&chain, &key, 2_000),
            &chain.network_id(),
            Duration::from_secs(1),
            chain.state().view().world().parameters().transaction(),
            &iroha_config::parameters::actual::Crypto::default(),
            &time,
        )
        .unwrap();
        let hash = accepted.hash_as_entrypoint();
        let budget = chain.state().ivm_execution_budget();
        let before_admission = budget.reserved_bytes();
        let shell_bytes = iroha_allocation::shared::Shared::<
            CheckedTransaction<'static>,
            resident_owner::QueueResidentCharge,
        >::layout()
        .size();
        let ledger_bytes =
            iroha_allocation::ChargedShared::<QueueResidentLedger>::allocation_layout().size();
        queue.push(accepted.clone(), chain.state().view()).unwrap();
        let baseline = budget.reserved_bytes();
        assert_eq!(baseline, before_admission + ledger_bytes + shell_bytes);
        let mut registration = crate::unit_test_support::release_registration(&budget);
        let registered = budget.reserved_bytes();
        let held = budget
            .try_reserve_bytes(budget.limit_bytes() - registered)
            .unwrap();
        let view = chain.state().view();
        let Err(ChargedBufferError::Admission(original_refusal)) = capture_current(
            &queue,
            chain.state(),
            &view,
            std::slice::from_ref(&accepted),
            &budget,
        ) else {
            panic!("the exact original input table must refuse its occupied pool");
        };
        let same_probe = budget
            .try_reserve(std::alloc::Layout::array::<EntrypointHash>(1).unwrap())
            .unwrap_err();
        assert_eq!(
            original_refusal, same_probe,
            "the original release observation is preserved"
        );
        let iroha_allocation::AllocationRefusal::Capacity { release, .. } = original_refusal else {
            panic!("actual temporary capacity refusal");
        };
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(registration.poll_wait(&release, &mut context).is_pending());
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        drop(held);
        assert!(registration.poll_wait(&release, &mut context).is_ready());
        assert_eq!(budget.reserved_bytes(), registered);
        let original = capture_current(
            &queue,
            chain.state(),
            &view,
            std::slice::from_ref(&accepted),
            &budget,
        )
        .unwrap()
        .unwrap();
        queue
            .pending_ownership_generation
            .store(u64::MAX, Ordering::Release);
        clock.advance(queue.tx_time_to_live + Duration::from_secs(1));
        queue.cull_expired_entries_if_due();
        assert!(!queue.contains_entrypoint_hash(hash));
        assert!(queue.admission_faulted());
        assert!(!queue.pending_payload_lease_is_current(chain.state(), &view, &original));
        assert!(
            capture_current(
                &queue,
                chain.state(),
                &view,
                std::slice::from_ref(&accepted),
                &budget
            )
            .unwrap()
            .is_none()
        );
        drop(original);
        assert_eq!(
            budget.reserved_bytes(),
            registered - shell_bytes,
            "expiry already retired the original input shell; only the registered release and Queue ledger remain"
        );
        assert_eq!((queue.queued_len(), queue.retained_bytes()), (0, 0));
        drop(registration);
        assert_eq!(budget.reserved_bytes(), baseline - shell_bytes);
        assert_eq!(budget.reserved_bytes(), before_admission + ledger_bytes);
        drop(queue);
        assert_eq!(budget.reserved_bytes(), before_admission);
    }
}
