//! The global chain as lane instances use it (`specs/sumeragi_lanes.md` §3–§5): its applied tip
//! ([`AppliedWatch`], published by the global executor), anchors read from committed State and
//! Kura ([`GlobalAnchors`]), the intrinsic transaction checks of lane admission
//! ([`StatelessChecks`]) and a lane's share of the transaction queue ([`QueueLaneTransactions`]).

use std::{
    collections::BTreeSet,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

use iroha_crypto::HashOf;
use iroha_data_model::{NetworkId, block::BlockHeader, transaction::TransactionEntrypoint};
use iroha_model_base::topology::LaneId;
use parking_lot::{Condvar, Mutex};

use super::{
    AnchorView, TransactionCheck,
    executor::{AnchorSource, LaneSelectionError, LaneTransactions},
    routing::RoutingSnapshot,
};
use crate::{
    queue::Queue,
    state::{State, StateReadOnly},
};

/// The global chain's applied tip, published by its executor after each applied block and read
/// (or awaited) by lane instances.
#[derive(Debug)]
pub struct AppliedWatch {
    tip: Mutex<(u64, Option<HashOf<BlockHeader>>)>,
    changed: Condvar,
    #[cfg(test)]
    runner_waiters: std::sync::atomic::AtomicUsize,
}

impl AppliedWatch {
    /// A watch at `height` with block hash `hash`.
    #[must_use]
    pub fn new(height: u64, hash: Option<HashOf<BlockHeader>>) -> Self {
        Self {
            tip: Mutex::new((height, hash)),
            changed: Condvar::new(),
            #[cfg(test)]
            runner_waiters: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Publish a newly applied tip (never lowers the height).
    pub fn publish(&self, height: u64, hash: HashOf<BlockHeader>) {
        let mut tip = self.tip.lock();
        if height >= tip.0 {
            *tip = (height, Some(hash));
            self.changed.notify_all();
        }
    }

    /// Wake the existing runner after its atomic queue/stop predicate changes.
    /// Taking only this short tip lock closes the predicate-to-wait lost-wake edge.
    pub(super) fn wake_runner(&self) {
        let _tip = self.tip.lock();
        self.changed.notify_all();
    }

    /// The runner waits for height, queue admission or stop under one original Condvar.
    pub(super) fn wait_for_runner(
        &self,
        height: u64,
        timeout: Duration,
        pending: &std::sync::atomic::AtomicBool,
        stopped: &std::sync::atomic::AtomicBool,
    ) {
        use std::sync::atomic::Ordering;
        let deadline = Instant::now() + timeout;
        let mut tip = self.tip.lock();
        while tip.0 < height && !pending.load(Ordering::Acquire) && !stopped.load(Ordering::Acquire)
        {
            #[cfg(test)]
            self.runner_waiters.fetch_add(1, Ordering::Release);
            let timed_out = self.changed.wait_until(&mut tip, deadline).timed_out();
            #[cfg(test)]
            self.runner_waiters.fetch_sub(1, Ordering::Release);
            if timed_out {
                break;
            }
        }
    }

    /// The applied tip height.
    #[must_use]
    pub fn height(&self) -> u64 {
        self.tip.lock().0
    }

    /// Block until the applied height reaches `height` or `timeout` passes; whether it did.
    #[must_use]
    pub fn wait_for(&self, height: u64, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut tip = self.tip.lock();
        while tip.0 < height {
            if self.changed.wait_until(&mut tip, deadline).timed_out() {
                return tip.0 >= height;
            }
        }
        true
    }
}

/// Anchors from the global chain's committed State and Kura.
pub struct GlobalAnchors {
    state: Arc<State>,
    watch: Arc<AppliedWatch>,
}

impl GlobalAnchors {
    /// Anchors of `state`, whose applied tip `watch` publishes.
    #[must_use]
    pub fn new(state: Arc<State>, watch: Arc<AppliedWatch>) -> Self {
        Self { state, watch }
    }
}

impl AnchorView for GlobalAnchors {
    fn applied_hash(&self, height: u64) -> Option<HashOf<BlockHeader>> {
        let index = usize::try_from(height).ok()?.checked_sub(1)?;
        let view = self.state.view();
        view.block_hashes().hash_at(index).copied()
    }

    fn creation_time_ms(
        &self,
        height: u64,
    ) -> Result<Option<u64>, crate::execution_attempt::ExecutionAttemptError<std::io::Error>> {
        let Some(height) = usize::try_from(height).ok().and_then(NonZeroUsize::new) else {
            return Ok(None);
        };
        let view = self.state.view();
        if height.get() > view.height() {
            return Ok(None);
        }
        let block = view
            .canonical_history()
            .executed_block(height, |_, _| Ok(()))
            .map_err(|error| error.map_rejection(std::io::Error::other))?;
        Ok(u64::try_from(block.header().creation_time().as_millis()).ok())
    }
}

impl AnchorSource for GlobalAnchors {
    fn wait_for(&self, height: u64, timeout: Duration) -> bool {
        self.watch.wait_for(height, timeout)
    }

    fn tip(&self) -> (u64, HashOf<BlockHeader>) {
        let view = self.state.view();
        let height = u64::try_from(view.height()).unwrap_or(0);
        let hash = view.latest_block_hash().unwrap_or_else(|| {
            HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed([0; 32]))
        });
        (height, hash)
    }
}

/// The intrinsic checks of lane admission (§3.2 step 4): the network and the signatures. Limits,
/// expiry and state checks belong to merge execution, where the chain's parameters of the merge
/// height apply.
#[derive(Clone, Copy, Debug)]
pub struct StatelessChecks {
    network: NetworkId,
}

impl StatelessChecks {
    /// Checks for transactions of `network`.
    #[must_use]
    pub const fn new(network: NetworkId) -> Self {
        Self { network }
    }
}

impl TransactionCheck for StatelessChecks {
    fn check(&self, tx: &TransactionEntrypoint, _anchor_time_ms: u64) -> Result<(), String> {
        match tx {
            TransactionEntrypoint::External(signed)
            | TransactionEntrypoint::SealedReveal(
                iroha_data_model::transaction::signed::SealedTransactionReveal {
                    signed_transaction: signed,
                    ..
                },
            ) => {
                if signed.network_id() != Some(&self.network) {
                    return Err("the transaction belongs to another network".into());
                }
                signed.verify_signature().map_err(|error| error.to_string())
            }
            TransactionEntrypoint::SealedCommitment(commitment) => {
                if commitment.payload().network_id != self.network {
                    return Err("the transaction belongs to another network".into());
                }
                commitment
                    .verify_signature()
                    .map_err(|error| error.to_string())
            }
        }
    }
}

/// A lane's share of the node's transaction queue: pending transactions whose route at the
/// given global height is the lane.
pub struct QueueLaneTransactions {
    lane: LaneId,
    queue: Arc<Queue>,
    state: Arc<State>,
    time_source: iroha_primitives::time::TimeSource,
}

/// Original Queue admission captured under the lane's execution allocation pool.
/// Its private lease cannot be decoded or reconstructed from selected transaction hashes.
pub struct QueueLaneLease(crate::queue::PendingPayloadLease);

impl QueueLaneTransactions {
    /// The share of `lane` in `queue`, routed with `state` and paced by the proposer clock.
    #[must_use]
    pub fn new(
        lane: LaneId,
        queue: Arc<Queue>,
        state: Arc<State>,
        time_source: iroha_primitives::time::TimeSource,
    ) -> Self {
        Self {
            lane,
            queue,
            state,
            time_source,
        }
    }
}

impl LaneTransactions for QueueLaneTransactions {
    type Lease = Option<QueueLaneLease>;

    #[cfg(test)]
    fn empty_payload_answer(&self) {
        self.queue.record_empty_lane_payload();
    }

    fn candidates(
        &self,
        height: u64,
        max_bytes: usize,
        skip: &BTreeSet<HashOf<TransactionEntrypoint>>,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<(Vec<TransactionEntrypoint>, Self::Lease), LaneSelectionError> {
        let generation = self.state.state_view_generation();
        let view = self
            .state
            .try_view_once()
            .map_err(crate::sumeragi::driver::traits::PublicationError::from)?;
        let selection = self
            .queue
            .begin_pending_payload_selection(&self.state, generation)
            .ok_or(LaneSelectionError::Changed)?;
        let Some(pending) = self
            .queue
            .bounded_pending_snapshot(&view, crate::sumeragi::payload::MAX_QUEUE_SCAN)
        else {
            return Ok((Vec::new(), None));
        };
        let routing = RoutingSnapshot::of(&view)?;
        let inputs = routing.inputs(view.world());
        let mut selected = Vec::new();
        let mut bytes = 0usize;
        let wall_time = self.time_source.now();
        let mut future = false;
        for transaction in pending {
            if skip.contains(&transaction.hash_as_entrypoint()) {
                continue;
            }
            if !cfg!(all(test, sumeragi_core_mutation = "HC259"))
                && transaction
                    .entrypoint()
                    .creation_time_ms()
                    .is_some_and(|created| Duration::from_millis(created) > wall_time)
            {
                future = true;
                continue;
            }
            if inputs.route(&transaction, height)? != Some(self.lane) {
                continue;
            }
            // The lane carries the complete original enum, including a reveal
            // commitment and salt. Admission's inner-variant length is a different bound.
            let Some(next) = bytes.checked_add(transaction.entrypoint_bytes().len()) else {
                continue;
            };
            if next > max_bytes {
                continue;
            }
            bytes = next;
            selected.push(transaction);
        }
        if selected.is_empty() && future {
            return Err(LaneSelectionError::ClockAhead);
        }
        if selected.is_empty() {
            return Ok((Vec::new(), None));
        }
        let lease = self
            .queue
            .capture_pending_payload_lease(&self.state, selection, &view, &selected, budget)
            .map_err(|error| {
                let original: crate::execution_attempt::ExecutionDeferred = match error {
                    iroha_allocation::ChargedBufferError::Admission(original) => original.into(),
                    iroha_allocation::ChargedBufferError::Allocator { .. } => {
                        ivm::error::ExecutionDeferral::AllocationUnavailable.into()
                    }
                };
                LaneSelectionError::Publication(
                    crate::sumeragi::driver::traits::PublicationError::Deferred(original.into()),
                )
            })?
            .ok_or(LaneSelectionError::Changed)?;
        Ok((
            selected
                .iter()
                .map(|transaction| transaction.entrypoint().clone())
                .collect(),
            Some(QueueLaneLease(lease)),
        ))
    }

    fn retain_prefix(&self, lease: &mut Self::Lease, count: usize) {
        if let Some(lease) = lease {
            lease.0.retain_prefix(count);
        }
    }

    fn lease_is_current(
        &self,
        lease: &Self::Lease,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<bool, crate::sumeragi::driver::traits::PublicationError> {
        use crate::sumeragi::driver::traits::{PublicationDeferral, PublicationError};
        let Some(lease) = lease.as_ref().filter(|lease| lease.0.belongs_to(budget)) else {
            return Ok(false);
        };
        let view = self.state.try_view_once()?;
        self.queue
            .pending_payload_lease_wait(&self.state, &view, &lease.0)
            .map(|wait| wait.is_some())
            .map_err(|release| {
                PublicationError::Deferred(PublicationDeferral::PublicationBusy(release))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_anchor_time_requires_original_canonical_execution_history() {
        crate::sumeragi::threads::sumeragi_thread_builder("sumeragi-lane-anchor-clock-test")
            .spawn(|| {
                let chain = crate::sumeragi::test_chain::CertifiedTestChain::start(
                    crate::sumeragi::test_chain::TestChainConfig::new(crate::state::World::new(), 1_000),
                ).unwrap();
                let anchors = GlobalAnchors::new(chain.state().clone(), Arc::new(AppliedWatch::new(1, None)));
                let expected = u64::try_from(chain.committed(1).block().header().creation_time().as_millis()).unwrap();
                assert_eq!(anchors.creation_time_ms(1).unwrap(), Some(expected));
                assert_eq!(anchors.creation_time_ms(2).unwrap(), None);
                chain.kura().corrupt_canonical_body_for_testing(NonZeroUsize::MIN).unwrap();
                assert!(anchors.creation_time_ms(1).is_err(), "an applied anchor cannot derive clock authority from unavailable canonical execution bytes");
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn original_runner_watch_keeps_preexisting_and_concurrent_admission_stop_and_height() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let watch = Arc::new(AppliedWatch::new(3, None));
        let pending = Arc::new(AtomicBool::new(true));
        let stopped = Arc::new(AtomicBool::new(false));
        watch.wait_for_runner(4, Duration::from_secs(5), &pending, &stopped);
        assert_eq!(watch.height(), 3, "admission never manufactures a height");
        pending.store(false, Ordering::Release);
        for stop in [false, true] {
            let (completed, completion) = std::sync::mpsc::sync_channel(1);
            let waiter = {
                let (watch, pending, stopped) = (
                    Arc::clone(&watch),
                    Arc::clone(&pending),
                    Arc::clone(&stopped),
                );
                std::thread::spawn(move || {
                    watch.wait_for_runner(4, Duration::from_secs(5), &pending, &stopped);
                    completed.send(()).unwrap();
                })
            };
            // This counter is written after the predicate was checked, while the tip
            // mutex is still held. wake_runner takes that same mutex, so it cannot
            // overtake the actual Condvar registration/unlock boundary.
            let entered_deadline = Instant::now() + Duration::from_secs(1);
            while watch.runner_waiters.load(Ordering::Acquire) == 0
                && Instant::now() < entered_deadline
            {
                std::thread::yield_now();
            }
            let entered = watch.runner_waiters.load(Ordering::Acquire) != 0;
            if stop {
                stopped.store(true, Ordering::Release);
            } else {
                pending.store(true, Ordering::Release);
            }
            watch.wake_runner();
            let woke = completion.recv_timeout(Duration::from_secs(1));
            // Every test child closes naturally even if the notification was omitted.
            waiter.join().expect("actual original Condvar waiter");
            assert!(
                entered,
                "actual original runner must enter its Condvar wait"
            );
            assert!(
                woke.is_ok(),
                "queue/stop wake must precede the original five-second deadline"
            );
            assert_eq!(watch.height(), 3);
            pending.store(false, Ordering::Release);
        }
        stopped.store(false, Ordering::Release);
        let hash = HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed([4; 32]));
        watch.publish(4, hash);
        watch.wait_for_runner(4, Duration::ZERO, &pending, &stopped);
        assert_eq!(watch.height(), 4);
    }

    #[test]
    fn the_watch_publishes_monotonically_and_wakes_waiters() {
        let hash =
            |seed: u8| HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed([seed; 32]));
        let watch = Arc::new(AppliedWatch::new(3, None));
        assert!(watch.wait_for(3, Duration::ZERO));
        assert!(!watch.wait_for(4, Duration::from_millis(10)));
        let waiter = {
            let watch = Arc::clone(&watch);
            std::thread::spawn(move || watch.wait_for(5, Duration::from_secs(10)))
        };
        watch.publish(4, hash(4));
        watch.publish(5, hash(5));
        assert!(waiter.join().expect("waiter"));
        watch.publish(2, hash(2));
        assert_eq!(watch.height(), 5, "a lower height is never published");
    }
}
