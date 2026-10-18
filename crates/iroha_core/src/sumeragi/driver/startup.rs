//! Original worker custody between admission, readiness and joiner attachment.
//!
//! Preparation never exposes a delivery handle or a partially owned RunningDriver.
//! Its private worker owner joins every acquired prefix on error or unwind. Only
//! successful readiness transfers those workers and the original prestarted joiner
//! together. Ordinary and deferred activation share this one worker constructor.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, atomic::AtomicBool, mpsc},
    thread::JoinHandle,
};

use iroha_sumeragi::{api::ConfigError, types::PublicKey};
use parking_lot::Mutex;

use super::{
    Backlog, Completion, CryptoRef, Driver, DriverConfig, DriverError, DriverHandle, DriverInputs,
    DriverJoiner, DriverStart, ExitGuard, Input, Kernel, KernelStart, LoopGuard, NodeNet,
    OriginalWorkerPanic, PendingAdmission, RunningDriver, Shared, Worker, Workers,
    check_frame_limit, discard_join_result,
    exec::ExecOp,
    ingress::Ingress,
    join_original_workers, payload_worker, persist,
    persist::Write,
    retirement::{RetirementControl, RetirementJob},
    run_exec, run_loop,
    serve::{self, ServeRequest},
    stop,
    traits::{BlockStore, BodyStore, Clock, Executor, Net, RecordStore},
    wake::ThreadWake,
};

mod pending;
use pending::WorkerOrigin;
pub use pending::{
    PendingDriver, StartupContext, StartupPoll, StartupPreparationError, StartupRetirement,
};

/// Keep the physical joiner until its exact workers are attached or preparation fails.
struct OriginalJoiner(Option<DriverJoiner>);

impl OriginalJoiner {
    fn start(retirement: Option<RetirementJob>) -> Result<Self, DriverError> {
        #[cfg(test)]
        tests::before_thread("sumeragi-join")?;
        DriverJoiner::start(retirement)
            .map(|joiner| Self(Some(joiner)))
            .map_err(Into::into)
    }

    fn start_preparing(
        run: impl FnOnce(mpsc::Receiver<Vec<JoinHandle<()>>>) + Send + 'static,
    ) -> Result<Self, DriverError> {
        #[cfg(test)]
        tests::before_thread("sumeragi-join")?;
        DriverJoiner::start_with(run)
            .map(|joiner| Self(Some(joiner)))
            .map_err(Into::into)
    }

    // Explicit refusal cleanup preserves an original joining-thread panic. Drop
    // remains non-panicking when a caller is already unwinding through startup.
    fn finish_refusal(mut self, error: DriverError) -> DriverError {
        if let Some(DriverJoiner { workers, thread }) = self.0.take() {
            drop(workers);
            if let Err(original) = thread.join() {
                OriginalWorkerPanic::new(original).resume();
            }
        }
        error
    }

    fn take(mut self) -> DriverJoiner {
        // This private owner is constructed populated and consumed exactly once.
        self.0
            .take()
            .expect("original joiner remains owned until attachment")
    }
}

impl Drop for OriginalJoiner {
    fn drop(&mut self) {
        if let Some(DriverJoiner { workers, thread }) = self.0.take() {
            // No worker list has been transferred. Closing the original sender
            // cancels its receive and never starts publication on an empty list.
            drop(workers);
            discard_join_result(thread.join());
        }
    }
}

/// An unexposed acquired worker prefix, still owned by its preparing caller.
///
/// The caller is never one of these workers: no callback receives this owner or
/// its handle before attach. After attach, RunningDriver owns the established
/// self-worker handoff semantics. The original joiner guard outlives this owner.
struct PreparedWorkers {
    handle: DriverHandle,
    threads: Vec<JoinHandle<()>>,
    retirement: Option<RetirementControl>,
    attached: bool,
    origin: Option<WorkerOrigin>,
}

impl PreparedWorkers {
    fn new(handle: DriverHandle, retirement: Option<RetirementControl>) -> Self {
        Self {
            handle,
            threads: Vec::new(),
            retirement,
            attached: false,
            origin: None,
        }
    }

    fn attach(mut self, joiner: OriginalJoiner) -> RunningDriver {
        let running = RunningDriver {
            handle: self.handle.clone(),
            threads: std::mem::take(&mut self.threads),
            joiner: Some(joiner.take()),
            joining: None,
            shutdown_requested: false,
            handoff_failed: false,
            join_failure: None,
            retirement: self.retirement.take(),
        };
        self.attached = true;
        running
    }
    // End every acquired worker before choosing a refusal or the original panic.
    // The same cleanup is safe from Drop during an already-active unwind.
    fn release_workers(&mut self) -> Option<OriginalWorkerPanic> {
        if self.attached {
            return None;
        }
        self.attached = true;
        let _ = self.handle.inputs.send(Input::Stop);
        // A deferred startup retains its already-admitted publication job on
        // this same original joining thread. An ordinary refusal cleans workers,
        // but only explicit final shutdown stops that job.
        if self.origin.is_none()
            && let Some(retirement) = &self.retirement
        {
            retirement.stop();
        }
        join_original_workers(std::mem::take(&mut self.threads))
    }

    fn finish_refusal(mut self, error: DriverError) -> DriverError {
        let failure = self.release_workers();
        if let Some(origin) = &self.origin {
            origin.retain_join_failure(failure);
        } else if let Some(original) = failure {
            original.resume();
        }
        error
    }
}

impl Drop for PreparedWorkers {
    fn drop(&mut self) {
        let failure = self.release_workers();
        if let Some(origin) = &self.origin {
            origin.retain_join_failure(failure);
        }
    }
}

/// Only the existing ordinary entry exposes a RunningDriver, after both owners attach.
///
/// # Errors
/// Preserves the original configuration, resource admission, physical allocation,
/// storage-gate, thread-creation and kernel-readiness refusal without projection.
pub fn spawn<N, R, B, K, C, E>(
    driver: Driver<N, R, B, K, C, E>,
    config: DriverConfig,
    start: DriverStart,
) -> Result<RunningDriver, DriverError>
where
    N: Net + 'static,
    R: RecordStore + 'static,
    B: BodyStore + 'static,
    K: BlockStore + 'static,
    C: Clock + 'static,
    E: Executor + 'static,
{
    let (start, retirement) = WorkerStart::new(driver, config, start)?;
    // Original joiner admission/spawn still precedes every protocol worker. Its
    // guard stays in this frame while the worker constructor cleans any prefix.
    let joiner = OriginalJoiner::start(retirement)?;
    let prepared = match start.spawn_workers() {
        Ok(prepared) => prepared,
        Err(error) => return Err(joiner.finish_refusal(error)),
    };
    Ok(prepared.attach(joiner))
}

/// Original prepared backend inputs, retained until borrowed admission succeeds.
/// No protocol worker exists and no delivery handle is exposed by this value.
pub struct DriverPreparation<N, R, B, K, C, E> {
    driver: Driver<N, R, B, K, C, E>,
    config: DriverConfig,
    start: DriverStart,
}

impl<N, R, B, K, C, E> DriverPreparation<N, R, B, K, C, E> {
    /// Move the original authenticated inputs without repeating their preparation.
    #[must_use]
    pub fn new(driver: Driver<N, R, B, K, C, E>, config: DriverConfig, start: DriverStart) -> Self {
        Self {
            driver,
            config,
            start,
        }
    }
}

/// Controls admitted by borrowing original inputs; admission refusal cannot consume them.
struct WorkerAdmission {
    shared: Arc<Shared>,
    ingress: Arc<Mutex<Ingress>>,
    net: Arc<dyn Net>,
    inputs: DriverInputs,
    rx: mpsc::Receiver<Input>,
    retirement: Option<RetirementControl>,
}

impl WorkerAdmission {
    fn new<N, R, B, K, C, E>(
        driver: &Driver<N, R, B, K, C, E>,
        config: &DriverConfig,
        start: &DriverStart,
    ) -> Result<(Self, Option<RetirementJob>), DriverError>
    where
        N: Net + 'static,
        R: RecordStore + 'static,
        B: BodyStore + 'static,
        K: BlockStore + 'static,
        C: Clock + 'static,
        E: Executor + 'static,
    {
        check_frame_limit(config, start)?;
        if start.node_gate.is_closed() {
            return Err(DriverError::StorageClosed);
        }
        // Only this exact BlockStore may supply the retained, already-admitted write.
        // Both fixed retirement controls are funded before any protocol worker starts.
        let (retirement, retirement_job) = match Arc::clone(&driver.blocks).retired_publication() {
            Some(publication) => {
                let (control, job) = RetirementJob::admit(
                    publication,
                    start.init.instance,
                    &start.allocation_budget,
                    config.backoff,
                )?;
                (Some(control), Some(job))
            }
            None => (None, None),
        };
        // Admit the original wake control before any worker can publish a completion.
        let wake = ThreadWake::admit(&start.allocation_budget)?;
        let pending_admission = PendingAdmission::admit(&start.allocation_budget, config.backoff)?;
        let instance = start.init.instance;
        let own: Vec<PublicKey> = start
            .init
            .records
            .iter()
            .map(|(k, _, _)| k.clone())
            .collect();
        let ingress = Arc::new(Mutex::new(Ingress::new(config.ingress)));
        let metrics = driver.metrics.as_ref();
        let shared = Arc::new(Shared {
            node_gate: Arc::clone(&start.node_gate),
            allocation_budget: start.allocation_budget.clone(),
            pending_admission: Mutex::new(pending_admission),
            instance,
            own,
            ingress: Arc::clone(&ingress),
            frame_limit: usize::try_from(config.frame_limit).unwrap_or(usize::MAX),
            status: Mutex::new(None),
            backlog: Mutex::new(Backlog::default()),
            wake: wake.clone(),
            transactions_pending: AtomicBool::new(false),
            #[cfg(test)]
            empty_waiting: AtomicBool::new(false),
            #[cfg(test)]
            empty_epoch: std::sync::atomic::AtomicU64::new(0),
            alive: AtomicBool::new(true),
            stopped: Mutex::new(None),
            metrics: metrics.map(|metrics| metrics.series().clone()),
        });
        let net: Arc<dyn Net> = Arc::new(NodeNet {
            net: Arc::clone(&driver.net),
            gate: Arc::clone(&shared.node_gate),
        });
        let (sender, rx) = mpsc::channel();
        let inputs = DriverInputs { sender, wake };
        Ok((
            Self {
                shared,
                ingress,
                net,
                inputs,
                rx,
                retirement,
            },
            retirement_job,
        ))
    }
}

/// All admitted inputs before the original worker creation boundary; no worker yet.
struct WorkerStart<N, R, B, K, C, E> {
    driver: Driver<N, R, B, K, C, E>,
    config: DriverConfig,
    start: DriverStart,
    shared: Arc<Shared>,
    ingress: Arc<Mutex<Ingress>>,
    net: Arc<dyn Net>,
    inputs: DriverInputs,
    rx: mpsc::Receiver<Input>,
    retirement: Option<RetirementControl>,
    origin: Option<WorkerOrigin>,
}

impl<N, R, B, K, C, E> WorkerStart<N, R, B, K, C, E>
where
    N: Net + 'static,
    R: RecordStore + 'static,
    B: BodyStore + 'static,
    K: BlockStore + 'static,
    C: Clock + 'static,
    E: Executor + 'static,
{
    fn new(
        driver: Driver<N, R, B, K, C, E>,
        config: DriverConfig,
        start: DriverStart,
    ) -> Result<(Self, Option<RetirementJob>), DriverError> {
        let (admitted, retirement) = WorkerAdmission::new(&driver, &config, &start)?;
        Ok((
            Self::from_admission(driver, config, start, admitted),
            retirement,
        ))
    }

    fn from_admission(
        driver: Driver<N, R, B, K, C, E>,
        config: DriverConfig,
        start: DriverStart,
        admitted: WorkerAdmission,
    ) -> Self {
        let WorkerAdmission {
            shared,
            ingress,
            net,
            inputs,
            rx,
            retirement,
        } = admitted;
        Self {
            driver,
            config,
            start,
            shared,
            ingress,
            net,
            inputs,
            rx,
            retirement,
            origin: None,
        }
    }

    #[allow(clippy::too_many_lines)] // one block per thread; moved with the original worker body
    fn spawn_workers(self) -> Result<PreparedWorkers, DriverError> {
        let Self {
            driver,
            config,
            start,
            shared,
            ingress,
            net,
            inputs,
            rx,
            retirement,
            origin,
        } = self;
        // Preparation may have waited for current-generation activation. Re-enter
        // the original storage gate before any protocol worker can be created.
        if let Some(retirement) = &retirement {
            retirement.wait_bound()?;
        }
        let worker_gate = Arc::clone(&start.node_gate);
        let _startup = worker_gate.enter().ok_or(DriverError::StorageClosed)?;
        let instance = start.init.instance;
        let metrics = driver.metrics;
        // Declare before the worker channels: those channels close before this
        // owner joins a partial prefix on every error and unwind path.
        let mut prepared = PreparedWorkers::new(
            DriverHandle {
                shared: Arc::clone(&shared),
                inputs: inputs.clone(),
            },
            retirement,
        );
        prepared.origin = origin.clone();
        let result = (|| -> Result<(), DriverError> {
            let (persist_tx, persist_rx) = mpsc::channel::<(u64, Write)>();
            {
                let (records, bodies, crypto) = (
                    driver.records,
                    Arc::clone(&driver.bodies),
                    Arc::clone(&start.crypto),
                );
                let tx = inputs.clone();
                let gate = Arc::clone(&shared.node_gate);
                #[cfg(test)]
                tests::before_thread("sumeragi-persist")?;
                let startup_origin = origin.clone();
                prepared.threads.push(
                    super::super::threads::sumeragi_thread_builder("sumeragi-persist").spawn(
                        move || {
                            if let Some(origin) = startup_origin {
                                origin.bind(Worker::Persist);
                            }
                            let _exit = ExitGuard {
                                worker: Worker::Persist,
                                tx: tx.clone(),
                            };
                            for (seq, write) in persist_rx {
                                let Some(_operation) = gate.enter() else {
                                    break;
                                };
                                let result = persist::perform(&*records, &*bodies, &*crypto, write);
                                if tx
                                    .send(Input::Done(Completion::Persisted { seq, result }))
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        },
                    )?,
                );
            }
            let (exec_tx, exec_rx) = mpsc::channel::<ExecOp>();
            {
                let (mut executor, blocks) = (driver.executor, Arc::clone(&driver.blocks));
                let tx = inputs.clone();
                let gate = Arc::clone(&shared.node_gate);
                #[cfg(test)]
                tests::before_thread("sumeragi-exec")?;
                let startup_origin = origin.clone();
                prepared.threads.push(
                    super::super::threads::sumeragi_thread_builder("sumeragi-exec").spawn(
                        move || {
                            if let Some(origin) = startup_origin {
                                origin.bind(Worker::Exec);
                            }
                            let _exit = ExitGuard {
                                worker: Worker::Exec,
                                tx: tx.clone(),
                            };
                            for op in exec_rx {
                                let Some(_operation) = gate.enter() else {
                                    break;
                                };
                                let done = run_exec(&mut executor, &*blocks, op);
                                if tx.send(Input::Done(Completion::Exec(done))).is_err() {
                                    break;
                                }
                            }
                        },
                    )?,
                );
            }
            let (serve_tx, serve_rx) = mpsc::channel::<ServeRequest>();
            {
                let (bodies, blocks, net) = (driver.bodies, driver.blocks, Arc::clone(&net));
                let mut payloads = payload_worker::PayloadWorker::new(
                    instance,
                    start.allocation_budget.clone(),
                    Arc::clone(&start.crypto),
                    start.signers.clone(),
                    config.serve.max_peers,
                    start.init.tip.height,
                );
                let tx = inputs.clone();
                let gate = Arc::clone(&shared.node_gate);
                #[cfg(test)]
                tests::before_thread("sumeragi-serve")?;
                let startup_origin = origin.clone();
                prepared.threads.push(
                super::super::threads::sumeragi_thread_builder("sumeragi-serve").spawn(move || {
                    if let Some(origin) = startup_origin { origin.bind(Worker::Serve); }
                    let _exit = ExitGuard {
                        worker: Worker::Serve,
                        tx: tx.clone(),
                    };
                    for request in serve_rx {
                        let Some(_operation) = gate.enter() else {
                            break;
                        };
                        let served = catch_unwind(AssertUnwindSafe(|| {
                            serve::serve(request, instance, &*bodies, &*blocks, &*net, &mut payloads)
                        }))
                        .unwrap_or_else(|_| Err(std::io::Error::other("sumeragi serving panicked")));
                        let served = match served {
                            Ok(served) => served,
                            Err(error) => { iroha_logger::error!(%error, "sumeragi availability/storage worker failed"); break; }
                        };
                        if tx.send(Input::Done(Completion::Served(served))).is_err() {
                            break;
                        }
                    }
                })?,
            );
            }
            let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<(), DriverError>>(1);
            {
                let (clock, net, observer) = (driver.clock, net, driver.observer);
                let shared = Arc::clone(&shared);
                #[cfg(test)]
                tests::before_thread("sumeragi-loop")?;
                let startup_origin = origin.clone();
                prepared.threads.push(
                    super::super::threads::sumeragi_thread_builder("sumeragi-loop").spawn(
                        move || {
                            if let Some(origin) = startup_origin {
                                origin.bind(Worker::Loop);
                            }
                            shared.wake.bind_current();
                            let _guard = LoopGuard {
                                shared: Arc::clone(&shared),
                                observer: Arc::clone(&observer),
                            };
                            let workers = Workers {
                                node_gate: Arc::clone(&shared.node_gate),
                                net,
                                observer,
                                persist: persist_tx,
                                exec: exec_tx,
                                serve: serve_tx,
                            };
                            let Some(startup) = shared.node_gate.enter() else {
                                let _ = ready_tx.send(Err(DriverError::StorageClosed));
                                return;
                            };
                            let kernel = Kernel::start(KernelStart {
                                local: start.local,
                                init: start.init,
                                allocation_budget: start.allocation_budget,
                                signers: start.signers,
                                crypto: Box::new(CryptoRef(Arc::clone(&start.crypto))),
                                hasher: Box::new(CryptoRef(start.crypto)),
                                now: clock.now(),
                                ingress,
                                config,
                            });
                            drop(startup);
                            match kernel {
                                Ok((mut kernel, _)) => {
                                    kernel
                                        .exec
                                        .bind_release_waker(shared.wake.clone().into_waker());
                                    kernel
                                        .exec
                                        .bind_release_thread(shared.wake.original_thread());
                                    shared
                                        .pending_admission
                                        .lock()
                                        .registration
                                        .bind_thread(shared.wake.original_thread());
                                    if let Some(metrics) = metrics {
                                        kernel.attach_metrics(metrics);
                                    }
                                    shared.publish(&mut kernel);
                                    let _ = ready_tx.send(Ok(()));
                                    if let Err(worker) =
                                        run_loop(kernel, &rx, &shared, &*clock, &workers)
                                    {
                                        stop(&shared, &*workers.observer, worker);
                                    }
                                }
                                Err(error) => {
                                    let _ = ready_tx.send(Err(error.into()));
                                }
                            }
                        },
                    )?,
                );
            }
            match ready_rx.recv() {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(error),
                Err(_) => Err(DriverError::Config(ConfigError::InvalidInit(
                    "event loop died",
                ))),
            }
        })();
        match result {
            Ok(()) => Ok(prepared),
            Err(error) => Err(prepared.finish_refusal(error)),
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
/// Refuse an actual worker-creation boundary on this test's original joiner.
pub(super) fn refuse_startup_thread_for_test(selected: usize) {
    tests::refuse_startup_thread(selected);
}
