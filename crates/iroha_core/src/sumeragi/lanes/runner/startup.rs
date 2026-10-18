//! Exact lane preparation on its already-admitted original joining thread.
//!
//! The lifecycle owns only completion, eligibility and admission retry. Native
//! opening, safety records, certified history and executor recovery remain here.

use super::*;
use crate::execution_attempt::ExecutionAttemptError as Attempt;
use crate::sumeragi::driver::{
    DriverError, DriverPreparation, PendingDriver, StartupContext, StartupPoll,
    StartupPreparationError, StartupRetirement,
};

type RecoveredLane = LaneExecutor<GlobalAnchors, StatelessChecks, QueueLaneTransactions>;
type RecoveringLane =
    super::super::executor::LaneRecovery<GlobalAnchors, StatelessChecks, QueueLaneTransactions>;
type PreparedLane = DriverPreparation<
    SharedNet,
    FileRecordStore,
    FileBodyStore,
    super::super::store::FileLaneBlockStore,
    SystemClock,
    RecoveredLane,
>;

enum TerminalStartup {
    Driver(DriverError),
    Preparation(Attempt<StartupPreparationError>),
    Joiner,
}

impl core::fmt::Display for TerminalStartup {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Driver(error) => core::fmt::Display::fmt(error, formatter),
            Self::Preparation(error) => core::fmt::Display::fmt(error, formatter),
            Self::Joiner => formatter.write_str("original startup joiner failed"),
        }
    }
}

/// One original generation, including refusal before its thread can be admitted.
pub(super) struct PendingLane {
    instance: Hash32,
    original: Result<PendingDriver, DriverError>,
    // Keep the full original carrier until this generation is explicitly retired.
    // Reporting it once must not discard its source or authorize a replacement.
    terminal: Option<TerminalStartup>,
}

impl PendingLane {
    pub(super) fn new(inner: &Arc<Inner>, key: LaneKey) -> Self {
        let instance = inner.inputs.stores.instance(key.0, &key.1);
        let original = inner.spawn_startup(key, instance);
        if let Err(error) = &original {
            iroha_logger::warn!(lane = %key.0, %error, "sumeragi: lane startup admission retained for retry");
        }
        Self {
            instance,
            original,
            terminal: None,
        }
    }

    pub(super) fn cancel(&self) {
        if let Ok(original) = &self.original {
            original.cancel();
        }
    }

    /// Poll outside both maps; only a transferred owner can enter `running`.
    fn poll(&mut self, inner: &Arc<Inner>, key: LaneKey) -> StartupPoll {
        let eligible = inner.startup_eligible(key);
        if self.original.is_err() {
            if !eligible {
                return StartupPoll::Closed;
            }
            // Keep the exact old refusal alive until the next actual admission
            // returns. No preparation or physical thread exists in this phase.
            let next = inner.spawn_startup(key, self.instance);
            let previous = std::mem::replace(&mut self.original, next);
            drop(previous);
        }
        let Ok(original) = &mut self.original else {
            return StartupPoll::Pending;
        };
        if !eligible {
            if inner.stop.load(Ordering::Acquire)
                || inner
                    .inputs
                    .state
                    .view()
                    .kura()
                    .native_consensus_gate()
                    .is_closed()
            {
                original.cancel();
            } else {
                original.retire();
            }
            if self.terminal.is_some() && !cfg!(all(test, sumeragi_core_mutation = "HC410")) {
                return match original.poll_cancelled_failure() {
                    StartupRetirement::Joined => StartupPoll::Closed,
                    StartupRetirement::Pending | StartupRetirement::Failed => StartupPoll::Failed,
                };
            }
        }
        let progress = original.poll();
        match progress {
            StartupPoll::AwaitingActivation if inner.startup_eligible(key) => {
                let _ = original.activate();
                StartupPoll::Pending
            }
            StartupPoll::AwaitingActivation => {
                if inner.stop.load(Ordering::Acquire)
                    || inner
                        .inputs
                        .state
                        .view()
                        .kura()
                        .native_consensus_gate()
                        .is_closed()
                {
                    original.cancel();
                } else {
                    original.retire();
                }
                StartupPoll::Pending
            }
            StartupPoll::Refused(error) => {
                self.terminal = Some(TerminalStartup::Driver(error));
                self.report_terminal(inner, key);
                StartupPoll::Failed
            }
            StartupPoll::PreparationRefused(error) => {
                self.terminal = Some(TerminalStartup::Preparation(error));
                self.report_terminal(inner, key);
                StartupPoll::Failed
            }
            StartupPoll::Failed => {
                if self.terminal.is_none() {
                    self.terminal = Some(TerminalStartup::Joiner);
                    self.report_terminal(inner, key);
                }
                StartupPoll::Failed
            }
            progress => progress,
        }
    }

    fn report_terminal(&self, inner: &Inner, key: LaneKey) {
        #[cfg(feature = "telemetry")]
        InstanceMetrics::retire(&inner.inputs.state.telemetry, MetricsInstance::Lane(key.0));
        #[cfg(not(feature = "telemetry"))]
        let _ = inner;
        if let Some(error) = &self.terminal {
            iroha_logger::warn!(lane = %key.0, %error, "sumeragi: original lane startup generation retained until explicit retirement or shutdown");
        }
    }
}

impl Inner {
    /// Check committed current eligibility without cloning a record or opening storage.
    fn startup_eligible(&self, key: LaneKey) -> bool {
        if self.stop.load(Ordering::Acquire) {
            return false;
        }
        let view = self.inputs.state.view();
        !view.kura().native_consensus_gate().is_closed()
            && view
                .world()
                .sumeragi_lanes()
                .lane(key.0)
                .is_some_and(|record| {
                    record.incarnation == key.1
                        && record.active_from <= u64::try_from(view.height()).unwrap_or(0)
                })
    }

    fn spawn_startup(
        self: &Arc<Self>,
        key: LaneKey,
        instance: Hash32,
    ) -> Result<PendingDriver, DriverError> {
        let original = Arc::downgrade(self);
        PendingDriver::spawn(
            instance,
            &self.inputs.state.ivm_execution_budget(),
            self.inputs.driver.backoff,
            move |context| {
                let Some(inner) = original.upgrade() else {
                    return Ok(None);
                };
                if context.cancelled() || !inner.startup_eligible(key) {
                    return Ok(None);
                }
                let record = {
                    let view = inner.inputs.state.view();
                    view.world()
                        .sumeragi_lanes()
                        .lane(key.0)
                        .filter(|record| record.incarnation == key.1)
                        .cloned()
                };
                let Some(record) = record else {
                    return Ok(None);
                };
                inner.prepare_lane(&record, context)
            },
        )
    }

    /// Remove each original before callbacks; no worker writes the pending map.
    pub(super) fn poll_startups(self: &Arc<Self>) {
        use std::ops::Bound::{Excluded, Unbounded};
        let mut last = None;
        loop {
            let key = {
                let pending = self.starting.lock();
                match last {
                    Some(key) => pending.range((Excluded(key), Unbounded)).next(),
                    None => pending.iter().next(),
                }
                .map(|(key, _)| *key)
            };
            let Some(key) = key else { break };
            last = Some(key);
            let pending = { self.starting.lock().remove(&key) };
            let Some(mut pending) = pending else { continue };
            match pending.poll(self, key) {
                StartupPoll::Ready(driver) => {
                    // Ready may race committed retirement or final stop. Attach
                    // first, then retain stale workers as ordinary retirement;
                    // never expose their ingress or synchronously join them here.
                    let retiring = !self.startup_eligible(key);
                    if !retiring {
                        if let Some(ingress) = &self.inputs.ingress {
                            ingress.register(pending.instance, Arc::new(driver.handle()));
                        }
                        iroha_logger::info!(lane = %key.0, instance = %hex::encode(pending.instance.0), "sumeragi: lane instance started");
                    }
                    let lane = RunningLane {
                        instance: pending.instance,
                        driver,
                        retiring,
                    };
                    let replaced = { self.running.lock().insert(key, lane) };
                    debug_assert!(
                        replaced.is_none(),
                        "the sole reconciler transfers each original startup once"
                    );
                    drop(replaced);
                    if !retiring {
                        // A queue notification may have been drained before
                        // readiness exposed this handle. Deliver through the
                        // same coalesced wake after the original transfer.
                        #[cfg(not(all(test, sumeragi_core_mutation = "HC405")))]
                        self.notify_transactions();
                    }
                    drop(pending);
                }
                StartupPoll::Closed => {
                    drop(pending);
                    #[cfg(feature = "telemetry")]
                    InstanceMetrics::retire(
                        &self.inputs.state.telemetry,
                        MetricsInstance::Lane(key.0),
                    );
                }
                StartupPoll::Pending | StartupPoll::Failed => {
                    let replaced = { self.starting.lock().insert(key, pending) };
                    debug_assert!(
                        replaced.is_none(),
                        "the sole reconciler retains each original startup once"
                    );
                    drop(replaced);
                }
                StartupPoll::AwaitingActivation
                | StartupPoll::Refused(_)
                | StartupPoll::PreparationRefused(_) => {
                    unreachable!("pending lane retains its original activation/refusal")
                }
            }
        }
    }

    fn prepare_lane(
        &self,
        record: &SumeragiLaneRecord,
        context: &mut StartupContext,
    ) -> Result<Option<PreparedLane>, Attempt<StartupPreparationError>> {
        let inputs = &self.inputs;
        let node_gate = inputs.state.view().kura().native_consensus_gate();
        let _startup = node_gate.enter().ok_or_else(|| {
            StartupPreparationError::Message(
                "canonical storage is closed; restart is required".to_owned(),
            )
        })?;
        let config = lane_height_config(record)
            .map_err(|error| StartupPreparationError::Message(error.to_string()))?;
        for member in &record.committee {
            inputs
                .crypto
                .admit(member.peer.public_key(), &member.pop)
                .map_err(|error| {
                    StartupPreparationError::Message(format!(
                        "committee key {}: {error:?}",
                        member.peer
                    ))
                })?;
        }
        let shared: SharedCrypto = inputs.crypto.clone();
        let instance = lane_instance(&*shared, &inputs.network, &inputs.chain_id, record);
        let Some(store) = retry_preparation(
            context,
            || {
                inputs
                    .stores
                    .runtime_store(record.lane, &record.incarnation)
            },
            retry_startup_io,
        )?
        else {
            return Ok(None);
        };
        store
            .bind_global_queue(&inputs.queue)
            .map_err(StartupPreparationError::Io)?;
        let key = core_key(inputs.key_pair.public_key())
            .map_err(|error| StartupPreparationError::Message(error.to_string()))?;
        let Some(log) = retry_preparation(
            context,
            || inputs.records.log().map_err(Attempt::Rejected),
            retry_startup_io,
        )?
        else {
            return Ok(None);
        };
        let custody = log.iter().any(|entry| {
            matches!(entry,
                LogEntry::Instance { instance, key: logged, .. }
                if *instance == inputs.global_instance && *logged == key)
        });
        drop(log);
        let keys = [(key, false)];
        let Some(found) = retry_preparation(
            context,
            || {
                install_records(
                    &*inputs.records,
                    &*shared,
                    &instance,
                    config.epoch.id,
                    &keys,
                    0,
                    custody,
                    &mut fresh_store_id,
                )
                .map_err(Attempt::Rejected)
            },
            retry_startup_io,
        )?
        else {
            return Ok(None);
        };
        let genesis = (
            super::super::lane_genesis_hash(&inputs.network, record),
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
        let nonce = startup_nonce();
        // History retries borrow the store, retaining these exact installed
        // record/configuration vectors without another install or clone.
        let Some(history) = retry_preparation(
            context,
            || {
                crate::sumeragi::driver::assemble_startup_history(
                    &*store,
                    0,
                    genesis,
                    record.params.demotion_window.get(),
                )
            },
            retry_startup_history,
        )?
        else {
            return Ok(None);
        };
        let init = iroha_sumeragi::api::Init {
            instance,
            records: found,
            genesis_height: 0,
            demotion_window: record.params.demotion_window.get(),
            nonce,
            tip: history.tip,
            configs,
            recent_headers: history.recent_headers,
        };
        let member = record
            .committee
            .iter()
            .any(|member| member.peer.public_key() == inputs.key_pair.public_key());
        let transactions = member.then(|| {
            Arc::new(QueueLaneTransactions::new(
                record.lane,
                Arc::clone(&inputs.queue),
                Arc::clone(&inputs.state),
                iroha_primitives::time::TimeSource::new_system(),
            ))
        });
        let recovery = LaneExecutor::begin_recover(
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
            iroha_primitives::time::TimeSource::new_system(),
        );
        let Some(executor) = recover_lane(context, recovery)? else {
            return Ok(None);
        };
        let Some(bodies) = retry_preparation(
            context,
            || {
                FileBodyStore::open(
                    &inputs.bodies_dir,
                    &instance,
                    Arc::clone(&shared),
                    BodyLimits::default(),
                    inputs.state.ivm_execution_budget(),
                )
                .map_err(Attempt::Rejected)
            },
            retry_startup_io,
        )?
        else {
            return Ok(None);
        };
        let signer = KeyPairSigner::new(&inputs.key_pair)
            .map_err(|error| StartupPreparationError::Message(error.to_string()))?;
        let observer =
            evidence_observer(Arc::clone(&inputs.state), record.lane, record.incarnation);
        let driver = Driver::new(
            Arc::clone(&self.net),
            Arc::clone(&inputs.records),
            Arc::new(bodies),
            store,
            Arc::new(SystemClock::new()),
            executor,
            observer,
        );
        #[cfg(feature = "telemetry")]
        let driver = driver.with_metrics(InstanceMetrics::for_node(
            &inputs.state.telemetry,
            MetricsInstance::Lane(record.lane),
        ));
        Ok(Some(DriverPreparation::new(
            driver,
            inputs.driver,
            DriverStart {
                node_gate: inputs.state.view().kura().native_consensus_gate(),
                allocation_budget: inputs.state.ivm_execution_budget(),
                local: local_params(config.committee.n(), &inputs.local),
                init,
                signers: vec![Arc::new(signer)],
                crypto: shared,
            },
        )))
    }
}

/// Keep the original read/available/decode phase and refusal through every retry.
fn recover_lane(
    context: &mut StartupContext,
    mut recovery: RecoveringLane,
) -> Result<Option<RecoveredLane>, Attempt<StartupPreparationError>> {
    loop {
        if context.cancelled() {
            return Ok(None);
        }
        match recovery.complete() {
            Ok(executor) => return Ok(Some(executor)),
            Err((original, error)) => {
                recovery = original;
                if error.kind() != std::io::ErrorKind::WouldBlock {
                    return Err(StartupPreparationError::Io(error).into());
                }
                let original = recovery
                    .original_startup_refusal()
                    .and_then(|owner| owner.allocation_refusal());
                if !context.wait_retry(original) {
                    return Ok(None);
                }
                // The recovery still owns its exact carrier through the next
                // complete() call, including the original available body/QC.
            }
        }
    }
}

/// Retry only the unfinished local stage, keeping the original error through
/// the next real attempt. Completed corruption/rejection never becomes absence.
fn retry_preparation<T, E: Into<StartupPreparationError>>(
    context: &mut StartupContext,
    mut operation: impl FnMut() -> Result<T, Attempt<E>>,
    retry_completed: impl Fn(&E) -> bool,
) -> Result<Option<T>, Attempt<StartupPreparationError>> {
    let mut previous = None;
    loop {
        if context.cancelled() {
            return Ok(None);
        }
        let result = operation();
        drop(previous.take());
        match result {
            Ok(value) => return Ok(Some(value)),
            Err(error) => {
                let retry = match &error {
                    Attempt::Deferred(_) => true,
                    Attempt::Rejected(error) => retry_completed(error),
                };
                if !retry {
                    return Err(error.map_rejection(|error| {
                        let original: StartupPreparationError = error.into();
                        if cfg!(all(test, sumeragi_core_mutation = "HC411")) {
                            StartupPreparationError::Message(original.to_string())
                        } else {
                            original
                        }
                    }));
                }
                previous = Some(error);
                let original = match previous.as_ref() {
                    Some(Attempt::Deferred(owner)) => owner.allocation_refusal(),
                    _ => None,
                };
                if !context.wait_retry(original) {
                    return Ok(None);
                }
            }
        }
    }
}

#[cfg(test)]
impl PendingLane {
    /// Retain a genuine original completion at the actual runner transfer boundary.
    pub(super) fn original_for_test(instance: Hash32, original: PendingDriver) -> Self {
        Self {
            instance,
            original: Ok(original),
            terminal: None,
        }
    }
}

// Retry an original native operation failure, not an inferred replacement owner.
// Custom Other includes custody_changed and must not be guessed to be physical I/O.
fn retry_startup_io(error: &std::io::Error) -> bool {
    if cfg!(all(test, sumeragi_core_mutation = "HC408")) {
        return error.kind() == std::io::ErrorKind::WouldBlock;
    }
    (cfg!(all(test, sumeragi_core_mutation = "HC409")) && error.kind() == std::io::ErrorKind::Other)
        || error.raw_os_error().is_some()
        || matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::Interrupted
                | std::io::ErrorKind::TimedOut
        )
}

fn retry_startup_history(error: &crate::sumeragi::driver::StartupHistoryError) -> bool {
    match error {
        crate::sumeragi::driver::StartupHistoryError::Read { source, .. } => {
            retry_startup_io(source)
        }
        crate::sumeragi::driver::StartupHistoryError::Missing { .. } => false,
    }
}

#[cfg(test)]
mod tests;
