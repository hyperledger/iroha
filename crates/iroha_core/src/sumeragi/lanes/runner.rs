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
    executor::{LaneExecutor, LaneRecovery},
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
            Driver, DriverConfig, DriverStart, RunningDriver, SharedCrypto, assemble_init,
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
}

type PendingRecovery = LaneRecovery<GlobalAnchors, StatelessChecks, QueueLaneTransactions>;

struct Inner {
    inputs: LaneRunnerInputs,
    net: Arc<SharedNet>,
    running: Mutex<BTreeMap<(LaneId, [u8; 32]), RunningLane>>,
    recovering: Mutex<BTreeMap<(LaneId, [u8; 32]), PendingRecovery>>,
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
        formatter
            .debug_struct("LaneRunner")
            .field("running", &self.inner.running.lock().len())
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
        let inner = Arc::new(Inner {
            net: Arc::new(SharedNet(Arc::clone(&inputs.net))),
            inputs,
            running: Mutex::new(BTreeMap::new()),
            recovering: Mutex::new(BTreeMap::new()),
            stop: AtomicBool::new(false),
            transactions_pending: AtomicBool::new(false),
        });
        inner.reconcile();
        let thread = {
            let inner = Arc::clone(&inner);
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
        Ok(Self {
            inner,
            thread: Some(thread),
        })
    }

    /// The running lane instances.
    #[must_use]
    pub fn instances(&self) -> Vec<LaneInstance> {
        self.inner
            .running
            .lock()
            .iter()
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
        assert!(!lanes.is_empty(), "an original live lane must exist");
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
            .any(|lane| lane.driver.handle().waiting_after_empty_for_test())
    }

    /// Stop every lane instance and the runner thread.
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        self.inner.stop.store(true, Ordering::Release);
        self.inner.inputs.watch.wake_runner();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
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
            for lane in self.running.lock().values() {
                lane.driver.handle().transactions_available();
            }
        }
    }

    /// Stop retired incarnations and start the activated ones.
    fn reconcile(&self) {
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
        self.recovering.lock().retain(|(lane, incarnation), _| {
            lanes
                .lane(*lane)
                .is_some_and(|record| record.incarnation == *incarnation)
        });
        let mut running = self.running.lock();
        let retired = running
            .keys()
            .filter(|(lane, incarnation)| {
                lanes
                    .lane(*lane)
                    .is_none_or(|record| record.incarnation != *incarnation)
            })
            .copied()
            .collect::<Vec<_>>();
        for key in retired {
            if let Some(lane) = running.remove(&key) {
                self.stop_lane(lane);
                #[cfg(feature = "telemetry")]
                InstanceMetrics::retire(&self.inputs.state.telemetry, MetricsInstance::Lane(key.0));
                iroha_logger::info!(lane = %key.0, "sumeragi: lane instance retired");
            }
        }
        // Failed store openings never enter `running` or executor recovery. Reconcile the
        // registry itself so their original funded buffers and disk locks retire as well.
        self.inputs.stores.release_retired(&lanes);
        for record in &lanes.lanes {
            let key = (record.lane, record.incarnation);
            if record.active_from > applied || running.contains_key(&key) {
                continue;
            }
            match self.start_lane(record) {
                Ok(lane) => {
                    iroha_logger::info!(
                        lane = %record.lane,
                        instance = %hex::encode(lane.instance.0),
                        "sumeragi: lane instance started"
                    );
                    running.insert(key, lane);
                }
                Err(error) => {
                    iroha_logger::warn!(lane = %record.lane, %error, "sumeragi: lane instance did not start");
                }
            }
        }
    }

    fn stop_lane(&self, lane: RunningLane) {
        if let Some(ingress) = &self.inputs.ingress {
            ingress.unregister(&lane.instance);
        }
        lane.driver.shutdown();
    }

    fn start_lane(
        &self,
        record: &SumeragiLaneRecord,
    ) -> Result<RunningLane, crate::execution_attempt::ExecutionAttemptError<String>> {
        let inputs = &self.inputs;
        let node_gate = inputs.state.view().kura().native_consensus_gate();
        let _startup = node_gate
            .enter()
            .ok_or_else(|| "canonical storage is closed; restart is required".to_owned())?;
        let config = lane_height_config(record).map_err(|error| error.to_string())?;
        for member in &record.committee {
            inputs
                .crypto
                .admit(member.peer.public_key(), &member.pop)
                .map_err(|error| format!("committee key {}: {error:?}", member.peer))?;
        }
        let shared: SharedCrypto = inputs.crypto.clone();
        let instance = lane_instance(&*shared, &inputs.network, &inputs.chain_id, record);
        let store = inputs
            .stores
            .runtime_store(record.lane, &record.incarnation)
            .map_err(|error| error.map_rejection(|error| error.to_string()))?;
        store
            .bind_global_queue(&inputs.queue)
            .map_err(|error| error.to_string())?;
        let key = core_key(inputs.key_pair.public_key()).map_err(|error| error.to_string())?;
        let custody = inputs
            .records
            .log()
            .map_err(|error| error.to_string())?
            .iter()
            .any(|entry| {
                matches!(entry, LogEntry::Instance { instance, key: logged, .. }
                    if *instance == inputs.global_instance && *logged == key)
            });
        let found = install_records(
            &*inputs.records,
            &*shared,
            &instance,
            config.epoch.id,
            &[(key, false)],
            0,
            custody,
            &mut fresh_store_id,
        )
        .map_err(|error| error.to_string())?;
        let genesis = (
            super::lane_genesis_hash(&inputs.network, record),
            lane_genesis_result(record),
        );
        let tip = store.height();
        let configs = (tip..=tip.saturating_add(2))
            .map(|height| {
                (
                    height,
                    iroha_sumeragi::types::ConfigSlot::Ready(config.clone()),
                )
            })
            .collect();
        let init = assemble_init(
            &*store,
            instance,
            0,
            genesis,
            record.params.demotion_window.get(),
            found,
            configs,
            startup_nonce(),
        )
        .map_err(|error| error.map_rejection(|completed| completed.to_string()))?;
        let member = record
            .committee
            .iter()
            .any(|member| member.peer.public_key() == inputs.key_pair.public_key());
        let transactions = member.then(|| {
            Arc::new(QueueLaneTransactions::new(
                record.lane,
                Arc::clone(&inputs.queue),
                Arc::clone(&inputs.state),
            ))
        });
        let recovery_key = (record.lane, record.incarnation);
        let pending = self.recovering.lock().remove(&recovery_key);
        let recovery = pending.unwrap_or_else(|| {
            LaneExecutor::begin_recover(
                record.clone(),
                config.clone(),
                instance,
                Arc::new(GlobalAnchors::new(
                    Arc::clone(&inputs.state),
                    Arc::clone(&inputs.watch),
                )),
                StatelessChecks::new(inputs.network),
                transactions,
                genesis.0,
                store.clone(),
                shared.clone(),
                inputs.state.ivm_execution_budget(),
            )
        });
        let executor = match recovery.complete() {
            Ok(executor) => executor,
            Err((recovery, error)) => {
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    self.recovering.lock().insert(recovery_key, recovery);
                }
                return Err(error.to_string().into());
            }
        };
        let bodies = Arc::new(
            FileBodyStore::open(
                &inputs.bodies_dir,
                &instance,
                Arc::clone(&shared),
                BodyLimits::default(),
                inputs.state.ivm_execution_budget(),
            )
            .map_err(|error| error.to_string())?,
        );
        let signer = KeyPairSigner::new(&inputs.key_pair).map_err(|error| error.to_string())?;
        let observer =
            evidence_observer(Arc::clone(&inputs.state), record.lane, record.incarnation);
        #[cfg(feature = "telemetry")]
        let metrics = MetricsInstance::Lane(record.lane);
        let driver = Driver::new(
            Arc::clone(&self.net),
            Arc::clone(&inputs.records),
            bodies,
            store,
            Arc::new(SystemClock::new()),
            executor,
            observer,
        );
        #[cfg(feature = "telemetry")]
        let driver =
            driver.with_metrics(InstanceMetrics::for_node(&inputs.state.telemetry, metrics));
        let driver = driver
            .spawn(
                inputs.driver,
                DriverStart {
                    node_gate: inputs.state.view().kura().native_consensus_gate(),
                    allocation_budget: inputs.state.ivm_execution_budget(),
                    local: local_params(config.committee.n(), &inputs.local),
                    init,
                    signers: vec![Arc::new(signer)],
                    crypto: shared,
                },
            )
            .map_err(|error| {
                // A lane that did not start exports no series.
                #[cfg(feature = "telemetry")]
                InstanceMetrics::retire(&inputs.state.telemetry, metrics);
                error.to_string()
            })?;
        if let Some(ingress) = &inputs.ingress {
            ingress.register(instance, Arc::new(driver.handle()));
        }
        Ok(RunningLane { instance, driver })
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
