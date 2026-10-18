//! Original worker custody between admission, readiness and joiner attachment.
//!
//! Preparation never exposes a delivery handle or a partially owned RunningDriver.
//! Its private worker owner joins every acquired prefix on error or unwind. Only
//! successful readiness transfers those workers and the original prestarted joiner
//! together. This is the common ordinary-start path, not asynchronous lane startup.

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
    PendingAdmission, RunningDriver, Shared, Worker, Workers, check_frame_limit,
    exec::ExecOp,
    ingress::Ingress,
    payload_worker, persist,
    persist::Write,
    retirement::{RetirementControl, RetirementJob},
    run_exec, run_loop,
    serve::{self, ServeRequest},
    stop,
    traits::{BlockStore, BodyStore, Clock, Executor, Net, RecordStore},
    wake::ThreadWake,
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
            let _ = thread.join();
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
}

impl PreparedWorkers {
    fn new(handle: DriverHandle, retirement: Option<RetirementControl>) -> Self {
        Self {
            handle,
            threads: Vec::new(),
            retirement,
            attached: false,
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
            retirement: self.retirement.take(),
        };
        self.attached = true;
        running
    }
}

impl Drop for PreparedWorkers {
    fn drop(&mut self) {
        if self.attached {
            return;
        }
        let _ = self.handle.inputs.send(Input::Stop);
        if let Some(retirement) = &self.retirement {
            retirement.stop();
        }
        for worker in std::mem::take(&mut self.threads) {
            let _ = worker.join();
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
    let prepared = start.spawn_workers()?;
    Ok(prepared.attach(joiner))
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
        check_frame_limit(&config, &start)?;
        if start.node_gate.is_closed() {
            return Err(DriverError::StorageClosed);
        }
        // Only this exact BlockStore may supply the retained, already-admitted write.
        // Both fixed controls are funded before the existing joiner or any worker starts.
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
                driver,
                config,
                start,
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
        } = self;
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
            prepared.threads.push(
                super::super::threads::sumeragi_thread_builder("sumeragi-persist").spawn(
                    move || {
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
            prepared.threads.push(
                super::super::threads::sumeragi_thread_builder("sumeragi-exec").spawn(
                    move || {
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
            prepared.threads.push(
                super::super::threads::sumeragi_thread_builder("sumeragi-serve").spawn(move || {
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
            prepared.threads.push(
                super::super::threads::sumeragi_thread_builder("sumeragi-loop").spawn(
                    move || {
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
            Ok(Ok(())) => Ok(prepared),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(DriverError::Config(ConfigError::InvalidInit(
                "event loop died",
            ))),
        }
    }
}

#[cfg(test)]
mod tests;
