//! The node's lane instances (`specs/sumeragi_lanes.md` §4.1): one driver per lane incarnation,
//! as a member when the node's key is in the pinned committee and as an observer otherwise. An
//! instance starts once the global chain has applied its `active_from` height and stops after
//! the global chain retires it.
//!
//! Every instance shares the node's transport, ingress (frames carry their instance id), safety
//! record store, key and driver limits with the global instance; its blocks go to the lane
//! store the global executor merges from.
//!
//! **Record provenance.** A lane instance exists only from the global block that creates its
//! incarnation, and the node signs for it only through this record store. When the store's
//! installation log shows that the global instance started with the key, every lane signature
//! of that key is in this store, so a lane instance without a record starts from a fresh one;
//! otherwise the global instance's provenance rules (§7.4 of `specs/sumeragi.md`) apply
//! unchanged and the node follows the lane without signing.

use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

use iroha_config::parameters::actual::SumeragiLocalOverrides;
use iroha_crypto::KeyPair;
use iroha_data_model::{
    NetworkId,
    sumeragi_lanes::{SumeragiLaneRecord, SumeragiLaneStatus},
};
use iroha_model_base::topology::LaneId;
use iroha_sumeragi::types::Hash32;
use parking_lot::Mutex;

use super::{
    executor::LaneExecutor,
    global::{AppliedWatch, GlobalAnchors, QueueLaneTransactions, StatelessChecks},
    lane_genesis_result, lane_height_config, lane_instance,
    registry::LaneStores,
};
use crate::{
    queue::Queue,
    state::{State, StateReadOnly, WorldReadOnly},
    sumeragi::{
        bodies::{BodyLimits, FileBodyStore},
        crypto::{BlsCrypto, KeyPairSigner, core_key},
        driver::{
            Driver, DriverConfig, DriverStart, RunningDriver, SharedCrypto,
            persist::install_records,
            traits::{
                BlockStore as _, Frame, LogEntry, Net, Observer, RecordStore as _, SendOutcome,
                SystemClock,
            },
        },
        net::SumeragiIngress,
        node::{LogObserver, local_params, startup_nonce},
        records::{FileRecordStore, fresh_store_id},
    },
};

#[cfg(feature = "telemetry")]
use crate::sumeragi::metrics::{InstanceMetrics, MetricsInstance};

/// How often the runner re-checks the lane set without a new global height.
const IDLE_CHECK: Duration = Duration::from_millis(500);

/// The node's transport as every lane driver holds it.
struct SharedNet(Arc<dyn Net>);

impl Net for SharedNet {
    fn send(&self, to: &iroha_sumeragi::types::PublicKey, frame: &Frame) -> SendOutcome {
        self.0.send(to, frame)
    }
}

/// What lane instances share with the node's global instance.
pub struct LaneRunnerInputs {
    /// The node's state.
    pub state: Arc<State>,
    /// The transaction queue.
    pub queue: Arc<Queue>,
    /// The global chain's applied tip.
    pub watch: Arc<AppliedWatch>,
    /// The node's lane block stores.
    pub stores: Arc<LaneStores>,
    /// The node's cryptography (lane committee keys are admitted into it).
    pub crypto: Arc<BlsCrypto>,
    /// The transport.
    pub net: Arc<dyn Net>,
    /// The ingress routing inbound frames by instance, when the node is on a network.
    pub ingress: Option<Arc<SumeragiIngress>>,
    /// The node's safety record store.
    pub records: Arc<FileRecordStore>,
    /// The global instance id (its installation proves the store's custody of the key).
    pub global_instance: Hash32,
    /// Root of the body stores.
    pub bodies_dir: PathBuf,
    /// The node's consensus key pair.
    pub key_pair: KeyPair,
    /// The node's local parameter overrides.
    pub local: SumeragiLocalOverrides,
    /// Driver limits.
    pub driver: DriverConfig,
    /// The network.
    pub network: NetworkId,
    /// The chain id.
    pub chain_id: String,
}

struct RunningLane {
    instance: Hash32,
    driver: RunningDriver,
    // The original entry owns all shutdown handles until they physically finish.
    // Retirement removes delivery/status membership immediately, not join custody.
    retiring: bool,
}

mod startup;
use startup::PendingLane;

type LaneKey = (LaneId, [u8; 32]);

struct Inner {
    inputs: LaneRunnerInputs,
    net: Arc<SharedNet>,
    running: Mutex<BTreeMap<(LaneId, [u8; 32]), RunningLane>>,
    starting: Mutex<BTreeMap<LaneKey, PendingLane>>,
    stop: AtomicBool,
    transactions_pending: AtomicBool,
}

/// The node's lane instances and the thread that keeps them in step with the global chain.
pub struct LaneRunner {
    inner: Arc<Inner>,
    thread: Option<JoinHandle<()>>,
}

impl core::fmt::Debug for LaneRunner {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let running = self
            .inner
            .running
            .lock()
            .values()
            .filter(|lane| !lane.retiring)
            .count();
        #[cfg(all(test, sumeragi_core_mutation = "HC392"))]
        let _original_map = self.inner.running.lock();
        formatter
            .debug_struct("LaneRunner")
            .field("running", &running)
            .finish_non_exhaustive()
    }
}

/// One running lane instance, for status reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneInstance {
    /// The lane.
    pub lane: LaneId,
    /// Its incarnation.
    pub incarnation: [u8; 32],
    /// Its instance id.
    pub instance: Hash32,
}

/// A cheap, cloneable handle of the node's lane instances.
#[derive(Clone)]
pub struct LaneRunnerHandle {
    inner: Arc<Inner>,
}

impl core::fmt::Debug for LaneRunnerHandle {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LaneRunnerHandle")
            .finish_non_exhaustive()
    }
}

impl LaneRunnerHandle {
    /// Notify the owned runner without taking any live lane or recovery lock.
    pub fn transactions_available(&self) {
        self.inner.notify_transactions();
    }

    /// Every lane of the committed state with the status of the node's instance of it.
    #[must_use]
    pub fn statuses(&self) -> Vec<SumeragiLaneStatus> {
        let lanes = self
            .inner
            .inputs
            .state
            .view()
            .world()
            .sumeragi_lanes()
            .clone();
        let running = self.inner.running.lock();
        lanes
            .lanes
            .into_iter()
            .map(|record| {
                let instance = running
                    .get(&(record.lane, record.incarnation))
                    .filter(|lane| !lane.retiring)
                    .and_then(|lane| {
                        crate::sumeragi::node::status_dto(
                            &lane.driver.handle(),
                            iroha_crypto::Hash::prehashed(lane_genesis_result(&record).0),
                            None,
                        )
                    });
                SumeragiLaneStatus { record, instance }
            })
            .collect()
    }
}

/// Weak queue admission binding; it cannot keep State/Queue/lane drivers alive.
#[derive(Clone)]
pub(crate) struct QueueWake {
    inner: std::sync::Weak<Inner>,
    budget: iroha_allocation::AllocationBudget,
}

impl QueueWake {
    pub(crate) fn belongs_to(&self, budget: &iroha_allocation::AllocationBudget) -> bool {
        self.budget.same_pool(budget)
    }

    pub(crate) fn notify(&self) {
        self.budget.with_deferred_refund_notifications(|_| {
            if let Some(inner) = self.inner.upgrade() {
                inner.notify_transactions();
                // Concurrent shutdown can leave only this temporary original owner.
                drop(inner);
            }
        });
    }
}

impl LaneRunner {
    pub(crate) fn queue_wake(&self) -> QueueWake {
        QueueWake {
            inner: Arc::downgrade(&self.inner),
            budget: self.inner.inputs.state.ivm_execution_budget(),
        }
    }

    /// A handle of the lane instances.
    #[must_use]
    pub fn handle(&self) -> LaneRunnerHandle {
        LaneRunnerHandle {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Start the lanes the applied state has activated and the thread that follows the global
    /// chain.
    ///
    /// # Errors
    /// The thread cannot be spawned.
    pub fn spawn(inputs: LaneRunnerInputs) -> std::io::Result<Self> {
        let mut runner = Self::new(inputs);
        runner.inner.reconcile();
        let thread = {
            let inner = Arc::clone(&runner.inner);
            crate::sumeragi::threads::sumeragi_thread_builder("sumeragi-lanes").spawn(
                move || {
                    while !inner.stop.load(Ordering::Acquire) {
                        inner.drain_transactions();
                        let height = inner.inputs.watch.height();
                        inner.inputs.watch.wait_for_runner(
                            height.saturating_add(1),
                            IDLE_CHECK,
                            &inner.transactions_pending,
                            &inner.stop,
                        );
                        if inner.stop.load(Ordering::Acquire) {
                            break;
                        }
                        inner.reconcile();
                        // Arrivals during reconciliation include every newly started lane.
                        inner.drain_transactions();
                    }
                },
            )?
        };
        runner.thread = Some(thread);
        Ok(runner)
    }

    fn new(inputs: LaneRunnerInputs) -> Self {
        Self {
            inner: Arc::new(Inner {
                net: Arc::new(SharedNet(Arc::clone(&inputs.net))),
                inputs,
                running: Mutex::new(BTreeMap::new()),
                starting: Mutex::new(BTreeMap::new()),
                stop: AtomicBool::new(false),
                transactions_pending: AtomicBool::new(false),
            }),
            thread: None,
        }
    }

    /// The running lane instances.
    #[must_use]
    pub fn instances(&self) -> Vec<LaneInstance> {
        self.inner
            .running
            .lock()
            .iter()
            .filter(|(_, lane)| !lane.retiring)
            .map(|((lane, incarnation), running)| LaneInstance {
                lane: *lane,
                incarnation: *incarnation,
                instance: running.instance,
            })
            .collect()
    }

    /// Hold the real map only in the native nonblocking admission control.
    #[cfg(test)]
    pub(crate) fn with_live_lane_map_for_test(&self, observe: impl FnOnce()) {
        let lanes = self.inner.running.lock();
        assert!(
            lanes.values().any(|lane| !lane.retiring),
            "an original live lane must exist"
        );
        observe();
        drop(lanes);
    }

    /// Observe actual live lane EMPTY completion consumed by its Core; never a wake hint.
    #[cfg(test)]
    pub(crate) fn waiting_after_empty_for_test(&self) -> bool {
        self.inner
            .running
            .lock()
            .values()
            .filter(|lane| !lane.retiring)
            .any(|lane| lane.driver.handle().waiting_after_empty_for_test())
    }

    /// Stop every lane instance and the runner thread.
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        self.inner.stop.store(true, Ordering::Release);
        self.inner.inputs.watch.wake_runner();
        let first_starting = std::mem::take(&mut *self.inner.starting.lock());
        for pending in first_starting.values() {
            pending.cancel();
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        // The coordinator may have held one original outside the map when stop
        // was set. Signal every final owner before joining or refunding any one.
        let last_starting = std::mem::take(&mut *self.inner.starting.lock());
        for pending in last_starting.values() {
            pending.cancel();
        }
        for ((lane, _), pending) in first_starting.into_iter().chain(last_starting) {
            drop(pending);
            #[cfg(feature = "telemetry")]
            InstanceMetrics::retire(
                &self.inner.inputs.state.telemetry,
                MetricsInstance::Lane(lane),
            );
            #[cfg(not(feature = "telemetry"))]
            let _ = lane;
        }
        let running = std::mem::take(&mut *self.inner.running.lock());
        for (_, lane) in running {
            self.inner.stop_lane(lane);
        }
    }
}

impl Drop for LaneRunner {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Inner {
    fn notify_transactions(&self) {
        if !self.stop.load(Ordering::Acquire)
            && !self.transactions_pending.swap(true, Ordering::AcqRel)
        {
            self.inputs.watch.wake_runner();
        }
    }

    fn drain_transactions(&self) {
        if !self.stop.load(Ordering::Acquire)
            && self.transactions_pending.swap(false, Ordering::AcqRel)
        {
            for lane in self.running.lock().values().filter(|lane| !lane.retiring) {
                lane.driver.handle().transactions_available();
            }
        }
    }

    /// Stop retired incarnations and start the activated ones.
    fn reconcile(self: &Arc<Self>) {
        // Cancellation and completion remain observable even after the native
        // storage latch closes; no pending original is stranded by an early return.
        self.poll_startups();
        if self
            .inputs
            .state
            .view()
            .kura()
            .native_consensus_gate()
            .is_closed()
        {
            return;
        }
        let (applied, lanes) = {
            let view = self.inputs.state.view();
            (
                u64::try_from(view.height()).unwrap_or(0),
                view.world().sumeragi_lanes().clone(),
            )
        };
        // Reconcile has one owner: its initial turn precedes coordinator launch,
        // and final shutdown joins it before the last map drain. Keep each original
        // retiring driver until its physical joins and original publication finish.
        // Stop-before-start is
        // per LaneId, including a replacement incarnation with a different map key.
        // Every poll, owner drop and join runs outside the observation lock.
        let retired = self
            .running
            .lock()
            .iter()
            .filter(|((lane, incarnation), owner)| {
                owner.retiring
                    || lanes
                        .lane(*lane)
                        .is_none_or(|record| record.incarnation != *incarnation)
            })
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        for key in retired {
            let retired = { self.running.lock().remove(&key) };
            if let Some(mut lane) = retired {
                if !lane.retiring {
                    if let Some(ingress) = &self.inputs.ingress {
                        ingress.unregister(&lane.instance);
                    }
                    lane.retiring = true;
                }
                if lane.driver.poll_shutdown() {
                    drop(lane);
                    #[cfg(feature = "telemetry")]
                    InstanceMetrics::retire(
                        &self.inputs.state.telemetry,
                        MetricsInstance::Lane(key.0),
                    );
                    iroha_logger::info!(lane = %key.0, "sumeragi: lane instance retired");
                } else {
                    let replaced = { self.running.lock().insert(key, lane) };
                    debug_assert!(
                        replaced.is_none(),
                        "the sole reconciler retains each original retirement once"
                    );
                    drop(replaced);
                }
            }
        }
        // Every admitted write retains its original prestarted joining owner.
        // Historical owners without a write need no job. Registry reconciliation
        // only notifies original jobs, then releases idle in-memory owners.
        #[cfg(not(all(test, sumeragi_core_mutation = "HC390")))]
        self.inputs
            .stores
            .resume_retired_publications(&lanes, |key| {
                // A startup may already own protocol workers before Ready transfer.
                // Probe each map separately; neither guard crosses native continuation.
                let running = self.running.lock().contains_key(key);
                let starting = self.starting.lock().contains_key(key);
                !running && !starting
            });
        // Failed store openings never enter `running` or executor recovery. Reconcile the
        // registry itself so their original funded buffers and disk locks retire as well.
        if cfg!(all(test, sumeragi_core_mutation = "HC349")) {
            let running = self.running.lock();
            self.inputs.stores.release_retired(&lanes);
            drop(running);
        } else {
            self.inputs.stores.release_retired(&lanes);
        }
        for record in &lanes.lanes {
            let key = (record.lane, record.incarnation);
            let already_running = if cfg!(all(test, sumeragi_core_mutation = "HC394")) {
                self.running.lock().contains_key(&key)
            } else {
                self.running
                    .lock()
                    .keys()
                    .any(|(lane, _)| *lane == record.lane)
            };
            let already_starting = self
                .starting
                .lock()
                .keys()
                .any(|(lane, _)| *lane == record.lane);
            if record.active_from > applied
                || already_running
                || already_starting
                || self.stop.load(Ordering::Acquire)
            {
                continue;
            }
            let pending = PendingLane::new(self, key);
            let replaced = { self.starting.lock().insert(key, pending) };
            debug_assert!(
                replaced.is_none(),
                "the sole reconciler admits each startup generation once"
            );
            drop(replaced);
        }
    }

    fn stop_lane(&self, lane: RunningLane) {
        if !lane.retiring
            && let Some(ingress) = &self.inputs.ingress
        {
            ingress.unregister(&lane.instance);
        }
        lane.driver.shutdown();
    }
}

/// Observe this exact lane incarnation without granting raw reports monetary authority.
pub(in crate::sumeragi) fn evidence_observer(
    state: Arc<State>,
    lane: LaneId,
    incarnation: [u8; 32],
) -> Arc<dyn Observer> {
    Arc::new(LaneEvidenceObserver {
        state,
        lane,
        incarnation,
    })
}
struct LaneEvidenceObserver {
    state: Arc<State>,
    lane: LaneId,
    incarnation: [u8; 32],
}
impl Observer for LaneEvidenceObserver {
    fn evidence(&self, evidence: &iroha_sumeragi::message::Evidence) {
        if let Err(error) = crate::sumeragi::evidence::observe_lane(
            &self.state,
            self.lane,
            self.incarnation,
            evidence,
        ) {
            iroha_logger::warn!(%error, "sumeragi: lane evidence observation was not retained");
        }
        LogObserver.evidence(evidence);
    }
    fn fault(&self, fault: &iroha_sumeragi::api::LocalFault) {
        LogObserver.fault(fault);
    }
    fn halt(&self, reason: &iroha_sumeragi::api::HaltReason) {
        LogObserver.halt(reason);
    }
    fn stopped(&self, worker: crate::sumeragi::driver::Worker) {
        LogObserver.stopped(worker);
    }
    fn finished(&self) {
        LogObserver.finished();
    }
    fn frame_limit(&self, exceeded: &crate::sumeragi::driver::FrameLimitExceeded) {
        LogObserver.frame_limit(exceeded);
    }
}

/// Test observation of the actual reconciler's maps without a background polling thread.
#[cfg(test)]
pub(super) struct RetirementControl {
    runner: LaneRunner,
}

#[cfg(test)]
impl RetirementControl {
    /// Bind the real reconciler to its original test inputs without starting a thread.
    pub(super) fn new(inputs: LaneRunnerInputs) -> Self {
        Self {
            runner: LaneRunner::new(inputs),
        }
    }

    /// Probe the actual running-map mutex without waiting on an incorrect lifetime.
    pub(super) fn running_lock_available(&self) -> bool {
        self.runner.inner.running.try_lock().is_some()
    }

    /// Read the actual map after a successful nonblocking lock observation.
    pub(super) fn running_count(&self) -> usize {
        self.runner.inner.running.lock().len()
    }

    /// Execute the unchanged production reconcile entry point on these inputs.
    pub(super) fn reconcile(&self) {
        self.runner.inner.reconcile();
    }
}

#[cfg(test)]
impl RetirementControl {
    /// Observe the actual runner formatter and its original map without starting a thread.
    pub(super) fn observe_runner_debug<R>(
        self,
        observe: impl FnOnce(&LaneRunner, &dyn Fn() -> bool) -> R,
    ) -> R {
        observe(&self.runner, &|| {
            self.runner.inner.running.try_lock().is_some()
        })
    }
}

#[cfg(test)]
impl LaneRunner {
    /// Own the actual lane coordinator without its automatic polling thread.
    pub(in crate::sumeragi) fn for_retirement_test(inputs: LaneRunnerInputs) -> Self {
        Self::new(inputs)
    }

    /// Install an already running original driver at the actual topology owner boundary.
    pub(in crate::sumeragi) fn install_retirement_driver_for_test(
        &self,
        key: (LaneId, [u8; 32]),
        instance: Hash32,
        driver: RunningDriver,
    ) {
        let replaced = {
            self.inner.running.lock().insert(
                key,
                RunningLane {
                    instance,
                    driver,
                    retiring: false,
                },
            )
        };
        assert!(
            replaced.is_none(),
            "one original driver per test incarnation"
        );
        drop(replaced);
    }

    /// Run the production lifecycle and the immediately following transaction delivery turn.
    pub(in crate::sumeragi) fn drive_retirement_for_test(&self) {
        self.inner.reconcile();
        self.inner.drain_transactions();
    }

    /// Count original driver owners, including any retirement that has not physically joined.
    pub(in crate::sumeragi) fn retirement_owner_count_for_test(&self) -> usize {
        self.inner.running.lock().len()
    }
}

#[cfg(test)]
impl LaneRunner {
    /// Install one original pending generation without consuming its Ready result.
    pub(in crate::sumeragi) fn install_startup_for_test(
        &self,
        key: (LaneId, [u8; 32]),
        instance: Hash32,
        original: crate::sumeragi::driver::PendingDriver,
    ) {
        let replacement = {
            self.inner
                .starting
                .lock()
                .insert(key, PendingLane::original_for_test(instance, original))
        };
        let occupied = replacement.is_some();
        drop(replacement);
        assert!(
            !occupied,
            "one original pending generation per test incarnation"
        );
    }

    /// Drain the real coalesced wake while the Ready owner is still unexposed.
    pub(in crate::sumeragi) fn drain_startup_wake_for_test(&self) -> bool {
        self.inner.drain_transactions();
        !self.inner.transactions_pending.load(Ordering::Acquire)
    }

    /// Transfer through the real completion path, then deliver its real queued wake.
    pub(in crate::sumeragi) fn transfer_startup_for_test(&self) {
        self.inner.poll_startups();
        self.inner.drain_transactions();
    }
}

#[cfg(test)]
impl LaneRunner {
    /// Count exact pending startup owners without consuming their physical completion.
    pub(in crate::sumeragi) fn startup_owner_count_for_test(&self) -> usize {
        self.inner.starting.lock().len()
    }
}

#[cfg(test)]
impl LaneRunner {
    /// Perform final cleanup of a held original startup after the control observation.
    pub(in crate::sumeragi) fn shutdown_startup_for_test(&self, key: (LaneId, [u8; 32])) {
        let original = { self.inner.starting.lock().remove(&key) };
        if let Some(original) = original {
            original.cancel();
            drop(original);
        }
    }
}
