//! Lightweight supervisor for tokio tasks.
//!
//! What it does:
//!
//! - Monitors multiple children (as spawned [`JoinHandle`])
//! - Provides a single shutdown signal for everything
//! - Supports graceful shutdown timeout before aborting a child (via [`OnShutdown`])
//! - If a child panics, initiates shutdown and exits with an error
//! - If a child exits before shutdown signal, also initiates shutdown and exits with an error.
//!   Note: this might not be always the desirable behaviour, but _currently_ there are no other
//!   cases in Iroha.
//!   This behaviour could be easily extended to support refined strategies.
//! - Logs children's lifecycle
//!
//! What it doesn't:
//!
//! - Doesn't support restarting child.
//!   To implement that, we need a formal actor system, i.e. actors with a unified lifecycle,
//!   messaging system, and, most importantly, address registry
//!   (for reference, see [Registry - Elixir](https://hexdocs.pm/elixir/1.17.0-rc.1/Registry.html)).

use std::{sync::RwLock, time::Duration};

use iroha_logger::{prelude::Span, InstrumentFutures};
use tokio::{
    sync::{mpsc, oneshot},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

/// Supervisor for tokio tasks.
#[derive(Debug, Default)]
pub struct Supervisor {
    children: Vec<Child>,
    shutdown_signal: ShutdownSignal,
}

impl Supervisor {
    /// Constructor
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a copy of the supervisor's shutdown signal
    pub fn shutdown_signal(&self) -> ShutdownSignal {
        self.shutdown_signal.clone()
    }

    /// Monitor a given [`Child`]
    #[track_caller]
    pub fn monitor(&mut self, child: impl Into<Child>) {
        self.children.push(child.into());
    }

    /// Spawns a task that will initiate supervisor shutdown on SIGINT/SIGTERM signals.
    /// # Errors
    /// See [`signal::unix::signal`] errors.
    pub fn setup_shutdown_on_os_signals(&mut self) -> Result<(), Error> {
        use tokio::signal;

        let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())?;
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;

        let shutdown_signal = self.shutdown_signal();
        self.monitor(tokio::spawn(async move {
            tokio::select! {
                _ = sigint.recv() => {
                    iroha_logger::info!("SIGINT received, shutting down...");
                },
                _ = sigterm.recv() => {
                    iroha_logger::info!("SIGTERM received, shutting down...");
                },
            }

            shutdown_signal.send();
        }));

        Ok(())
    }

    /// Spawns a task that will shut down the supervisor once the external
    /// [`ShutdownSignal`] is sent.
    pub fn shutdown_on_external_signal(&mut self, external_signal: ShutdownSignal) {
        let self_signal = self.shutdown_signal();

        self.monitor(tokio::spawn(async move {
            external_signal.receive().await;
            self_signal.send();
        }))
    }

    /// Start actual supervision and wait until all children terminate.
    ///
    /// Returns [`Ok`] if all children exited/aborted as expected after shutdown
    /// signal being sent.
    ///
    /// # Errors
    /// If any child panicked during execution or exited/aborted before shutdown signal being sent.
    pub async fn start(self) -> Result<(), Error> {
        // technically - should work without this check too
        if self.children.is_empty() {
            return Ok(());
        }

        SupervisorTask::new(self.shutdown_signal)
            .monitor(self.children)
            .run()
            .await
    }
}

struct SupervisorTask {
    /// A set of tasks spawned by the supervisor. Aborts all of them when on Drop
    set: JoinSet<()>,
    caught_panic: bool,
    caught_unexpected_exit: bool,
    shutdown_signal: ShutdownSignal,
    exit_tx: Option<mpsc::Sender<ChildExitResult>>,
    exit_rx: mpsc::Receiver<ChildExitResult>,
}

impl SupervisorTask {
    fn new(shutdown_signal: ShutdownSignal) -> Self {
        let (exit_tx, exit_rx) = mpsc::channel(256);
        Self {
            set: JoinSet::new(),
            caught_panic: false,
            caught_unexpected_exit: false,
            shutdown_signal,
            exit_tx: Some(exit_tx),
            exit_rx,
        }
    }

    fn monitor(mut self, children: impl IntoIterator<Item = Child>) -> Self {
        for child in children {
            self.monitor_single(child);
        }
        self
    }

    fn monitor_single(
        &mut self,
        Child {
            task,
            on_shutdown,
            span,
        }: Child,
    ) {
        let exit_tx = self
            .exit_tx
            .as_ref()
            .expect("sender should exist until `run()` is called")
            .clone();

        // FIXME: tried to use `Notify` - couldn't make it to work for all cases
        //        CancellationToken just works, although semantically not a great fit
        let exit_token = CancellationToken::new();

        let exit_token2 = exit_token.clone();
        let abort_handle = self.set.spawn(
            async move {
                iroha_logger::debug!("Start monitoring a child");
                let result = match task.await {
                    Ok(()) => {
                        iroha_logger::debug!("Child exited normally");
                        ChildExitResult::Ok
                    }
                    Err(err) if err.is_panic() => {
                        // we could use `err.into_panic()`, but it prints just `Any { .. }`
                        iroha_logger::error!("Child panicked");
                        ChildExitResult::Panic
                    }
                    Err(err) if err.is_cancelled() => {
                        iroha_logger::debug!("Child aborted"); // oh..
                        ChildExitResult::Cancel
                    }
                    _ => unreachable!(),
                };
                let _ = exit_tx.send(result).await;
                exit_token2.cancel();
            }
            .instrument(span.clone()),
        );

        // task to handle graceful shutdown
        let shutdown_signal = self.shutdown_signal.clone();
        self.set.spawn(async move {
            tokio::select! {
               () = exit_token.cancelled() => {
                   // exit
               }
               () =  shutdown_signal.receive() => {
                   match on_shutdown {
                        OnShutdown::Abort => {
                            iroha_logger::debug!("Shutdown signal received, aborting...");
                            abort_handle.abort();
                        }
                        OnShutdown::Wait(duration) => {
                            iroha_logger::debug!(?duration, "Shutdown signal received, waiting for child shutdown...");
                            if timeout(duration, exit_token.cancelled()).await.is_err() {
                                iroha_logger::debug!(expected = ?duration, "Child shutdown took longer than expected, aborting...");
                                abort_handle.abort();
                            }
                        }
                    }

               }
           }
        }.instrument(span));
    }

    fn handle_child_exit(&mut self, result: ChildExitResult) {
        match result {
            ChildExitResult::Ok | ChildExitResult::Cancel if !self.shutdown_signal.is_sent() => {
                iroha_logger::error!("Some task exited unexpectedly, shutting down everything...");
                self.caught_unexpected_exit = true;
                self.shutdown_signal.send();
            }
            ChildExitResult::Panic if !self.caught_panic => {
                iroha_logger::error!("Some task panicked, shutting down everything...");
                self.caught_panic = true;
                self.shutdown_signal.send();
            }
            _ => {}
        }
    }

    async fn run(mut self) -> Result<(), Error> {
        // no more new children monitors
        {
            self.exit_tx.take();
        }

        loop {
            tokio::select! {
                // this should naturally finish when all supervisor-spawned tasks finish
                Some(result) = self.set.join_next() => {
                    if let Err(err) = result {
                        if err.is_panic() {
                            iroha_logger::error!(?err, "Supervisor-spawned task panicked; it is probably a bug");
                        }
                    }
                }

                // this should finish when all task monitors finish
                Some(result) = self.exit_rx.recv() => {
                    iroha_logger::debug!(?result, "Child exited");
                    self.handle_child_exit(result);
                }

                else => break,
            }
        }

        // TODO: could report several reports. use error-stack?
        if self.caught_panic {
            Err(Error::ChildPanicked)
        } else if self.caught_unexpected_exit {
            Err(Error::UnexpectedExit)
        } else {
            Ok(())
        }
    }
}

#[derive(Copy, Clone, Debug)]
enum ChildExitResult {
    Ok,
    Panic,
    Cancel,
}

/// Signal indicating system shutdown. Could be cloned around.
///
/// It is effectively a wrap around [`CancellationToken`], but with different naming.
#[derive(Clone, Debug, Default)]
pub struct ShutdownSignal(CancellationToken);

impl ShutdownSignal {
    /// Constructor
    pub fn new() -> Self {
        Self::default()
    }

    /// Send the shutdown signal, resolving all [`Self::receive`] futures.
    pub fn send(&self) {
        self.0.cancel();
    }

    /// Receive the shutdown signal. Resolves after [`Self::send`].
    pub async fn receive(&self) {
        self.0.cancelled().await
    }

    /// Sync check whether the shutdown signal was sent
    pub fn is_sent(&self) -> bool {
        self.0.is_cancelled()
    }
}

/// Spawn [`std::thread`] as a future that finishes when the thread finishes and panics
/// when the thread panics.
///
/// Its intention is to link an OS thread to [`Supervisor`] in the following way:
///
/// ```
/// use std::time::Duration;
///
/// use iroha_futures::supervisor::{
///     spawn_os_thread_as_future, Child, OnShutdown, ShutdownSignal, Supervisor,
/// };
///
/// fn spawn_heavy_work(shutdown_signal: ShutdownSignal) -> Child {
///     Child::new(
///         tokio::spawn(spawn_os_thread_as_future(
///             std::thread::Builder::new().name("heavy_worker".to_owned()),
///             move || {
///                 loop {
///                     if shutdown_signal.is_sent() {
///                         break;
///                     }
///                     // do heavy work...
///                     std::thread::sleep(Duration::from_millis(100));
///                 }
///             },
///         )),
///         OnShutdown::Wait(Duration::from(1)),
///     )
/// }
///
/// #[tokio::main]
/// async fn main() {
///     let mut supervisor = Supervisor::new();
///     supervisor.monitor(spawn_heavy_work(supervisor.shutdown_signal()));
///
///     let signal = supervisor.shutdown_signal();
///     tokio::spawn(async move {
///         tokio::time::sleep(Duration::from_millis(300)).await;
///         signal.send();
///     });
///
///     supervisor.start().await.unwrap();
/// }
/// ```
///
/// **Note:** this function doesn't provide a mechanism to shut down the thread.
/// You should handle it within the closure on your own, e.g. by passing [`ShutdownSignal`] inside.
pub async fn spawn_os_thread_as_future<F>(builder: std::thread::Builder, f: F)
where
    F: FnOnce(),
    F: Send + 'static,
{
    let (ok_tx, ok_rx) = oneshot::channel();
    let (err_tx, err_rx) = oneshot::channel();

    // FIXME we cannot just _move_ `err_tx` inside of the thread's panic hook
    let err_tx = RwLock::new(Some(err_tx));

    // we are okay to drop the handle; thread will continue running in a detached way
    let _handle: std::thread::JoinHandle<_> = builder
        .spawn(move || {
            let default_hook = thread_local_panic_hook::take_hook();
            thread_local_panic_hook::set_hook(Box::new(move |info| {
                // the receiver might be dropped
                let _ = err_tx
                    .write()
                    .expect("no one else should lock this sender")
                    .take()
                    .expect("should be taken only once, on hook trigger")
                    .send(());
                // TODO: need to print info in a custom way?
                default_hook(info);
            }));

            f();

            // the receiver might be dropped
            let _ = ok_tx.send(());
        })
        .expect("should spawn thread normally");

    tokio::select! {
        _ = ok_rx => {
            // fine, do nothing
        }
        _ = err_rx => {
            panic!("thread panicked");
        }
    }
}

/// Supervisor child.
#[derive(Debug)]
pub struct Child {
    span: Span,
    task: JoinHandle<()>,
    on_shutdown: OnShutdown,
}

impl Child {
    /// Create a new supervisor child
    #[track_caller]
    pub fn new(task: JoinHandle<()>, on_shutdown: OnShutdown) -> Self {
        let caller_location = std::panic::Location::caller().to_string();
        let span = iroha_logger::debug_span!("supervisor_child_monitor", %caller_location);

        Self {
            span,
            task,
            on_shutdown,
        }
    }
}

impl From<JoinHandle<()>> for Child {
    #[track_caller]
    fn from(value: JoinHandle<()>) -> Self {
        Self::new(value, OnShutdown::Abort)
    }
}

/// Supervisor errors
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("Some of the supervisor children panicked")]
    ChildPanicked,
    #[error("Some of the supervisor children exited unexpectedly")]
    UnexpectedExit,
    #[error("IO error")]
    IO(#[from] std::io::Error),
}

/// Specifies supervisor action regarding a [`Child`] when shutdown happens.
#[derive(Default, Copy, Clone, Debug)]
pub enum OnShutdown {
    /// Abort the child immediately
    #[default]
    Abort,
    /// Wait until the child exits/aborts on its own; abort if it takes too long
    Wait(Duration),
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    use tokio::{
        sync::{mpsc, oneshot},
        time::sleep,
    };

    use super::*;

    const TICK_TIMEOUT: Duration = Duration::from_millis(10);
    /// For some reason, when all tests are run simultaneously, tests with OS spawns take longer
    /// than just [`TICK_TIMEOUT`]
    const OS_THREAD_SPAWN_TICK: Duration = Duration::from_millis(500);
    const SHUTDOWN_WITHIN_TICK: OnShutdown = OnShutdown::Wait(TICK_TIMEOUT);

    #[tokio::test]
    async fn empty_supervisor_just_exits() {
        timeout(TICK_TIMEOUT, Supervisor::new().start())
            .await
            .expect("should exit immediately")
            .expect("should not emit error");
    }

    #[tokio::test]
    async fn happy_graceful_shutdown() {
        #[derive(Debug)]
        enum Message {
            Ping { pong: oneshot::Sender<()> },
            Stopped,
        }

        let mut sup = Supervisor::new();

        let (tx_into, mut rx_into) = mpsc::channel(1);
        let (tx_out, rx_out) = oneshot::channel();

        {
            let shutdown = sup.shutdown_signal();
            sup.monitor(Child::new(
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            Some(Message::Ping { pong }) = rx_into.recv() => {
                                pong.send(()).unwrap();
                            },
                            () = shutdown.receive() => {
                                tx_out.send(Message::Stopped).unwrap();
                                break;
                            }
                        }
                    }
                }),
                SHUTDOWN_WITHIN_TICK,
            ));
        }

        // ensure task is spinning
        timeout(TICK_TIMEOUT, async {
            let (tx, rx) = oneshot::channel();
            tx_into.send(Message::Ping { pong: tx }).await.unwrap();
            rx.await.unwrap();
        })
        .await
        .unwrap();

        let shutdown = sup.shutdown_signal();
        let sup_handle = tokio::spawn(sup.start());

        // send shutdown signal
        shutdown.send();
        timeout(TICK_TIMEOUT, async {
            let Message::Stopped = rx_out.await.unwrap() else {
                panic!("expected stopped message");
            };
        })
        .await
        .unwrap();

        // we can now expect supervisor to stop without errors
        timeout(TICK_TIMEOUT, sup_handle)
            .await
            .unwrap()
            .expect("supervisor run should not panic")
            .expect("supervisor should not find any nested panics");
    }

    #[tokio::test]
    async fn supervisor_catches_panic_of_a_monitored_task() {
        let mut sup = Supervisor::new();

        sup.monitor(tokio::spawn(async {
            panic!("my panic should not be unnoticed")
        }));

        let Error::ChildPanicked = timeout(TICK_TIMEOUT, sup.start())
            .await
            .expect("should finish almost immediately")
            .expect_err("should catch the panic")
        else {
            panic!("other errors aren't expected")
        };
    }

    #[tokio::test]
    async fn supervisor_sends_shutdown_when_some_task_exits() {
        let mut sup = Supervisor::new();

        // exits immediately, not expected
        sup.monitor(tokio::spawn(async {}));

        // some task that needs shutdown gracefully
        let signal = sup.shutdown_signal();
        let (graceful_tx, graceful_rx) = oneshot::channel();
        sup.monitor(Child::new(
            tokio::spawn(async move {
                signal.receive().await;
                graceful_tx.send(()).unwrap();
            }),
            SHUTDOWN_WITHIN_TICK,
        ));

        let sup_handle = tokio::spawn(sup.start());

        timeout(TICK_TIMEOUT, graceful_rx)
            .await
            .expect("should shutdown everything immediately")
            .expect("should receive message fine");

        let Error::UnexpectedExit = timeout(TICK_TIMEOUT, sup_handle)
            .await
            .unwrap()
            .expect("supervisor should not panic")
            .expect_err("should handle unexpected exit")
        else {
            panic!("other errors aren't expected")
        };
    }

    #[tokio::test]
    async fn graceful_shutdown_when_some_task_panics() {
        let mut sup = Supervisor::new();
        let signal = sup.shutdown_signal();
        sup.monitor(tokio::spawn(async { panic!() }));

        let Error::ChildPanicked = timeout(TICK_TIMEOUT, sup.start())
            .await
            .expect("should finish immediately")
            .expect_err("should catch the panic")
        else {
            panic!("other errors aren't expected")
        };

        assert!(signal.is_sent())
    }

    fn spawn_task_with_graceful_shutdown(
        sup: &mut Supervisor,
        shutdown_time: Duration,
        timeout: Duration,
    ) -> Arc<AtomicBool> {
        let graceful = Arc::new(AtomicBool::new(false));

        let signal = sup.shutdown_signal();
        let graceful_clone = graceful.clone();
        sup.monitor(Child::new(
            tokio::spawn(async move {
                signal.receive().await;
                sleep(shutdown_time).await;
                graceful_clone.fetch_or(true, Ordering::Relaxed);
            }),
            OnShutdown::Wait(timeout),
        ));

        graceful
    }

    #[tokio::test]
    async fn actually_waits_for_shutdown() {
        const ACTUAL_SHUTDOWN: Duration = Duration::from_millis(50);
        const TIMEOUT: Duration = Duration::from_millis(100);

        let mut sup = Supervisor::new();
        let signal = sup.shutdown_signal();
        let graceful = spawn_task_with_graceful_shutdown(&mut sup, ACTUAL_SHUTDOWN, TIMEOUT);
        let sup_fut = tokio::spawn(sup.start());

        signal.send();
        timeout(ACTUAL_SHUTDOWN + TICK_TIMEOUT, sup_fut)
            .await
            .expect("should finish within this time")
            .expect("supervisor should not panic")
            .expect("supervisor should exit fine");
        assert!(graceful.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn aborts_task_if_shutdown_takes_long() {
        const ACTUAL_SHUTDOWN: Duration = Duration::from_millis(100);
        const TIMEOUT: Duration = Duration::from_millis(50);

        // Start system
        let mut sup = Supervisor::new();
        let signal = sup.shutdown_signal();
        let graceful = spawn_task_with_graceful_shutdown(&mut sup, ACTUAL_SHUTDOWN, TIMEOUT);
        let sup_fut = tokio::spawn(sup.start());

        // Initiate shutdown
        signal.send();
        timeout(TIMEOUT + TICK_TIMEOUT, sup_fut)
            .await
            .expect("should finish within this time")
            .expect("supervisor should not panic")
            .expect("shutdown took too long, but it is not an error");
        assert!(!graceful.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn can_monitor_os_thread_shutdown() {
        const LOOP_SLEEP: Duration = Duration::from_millis(5);
        const TIMEOUT: Duration = Duration::from_millis(50);

        let mut sup = Supervisor::new();
        let signal = sup.shutdown_signal();
        let signal2 = sup.shutdown_signal();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let graceful = Arc::new(AtomicBool::new(false));
        let graceful2 = graceful.clone();
        sup.monitor(Child::new(
            tokio::spawn(spawn_os_thread_as_future(
                std::thread::Builder::new(),
                move || {
                    // FIXME ready state
                    iroha_logger::info!("sending message");
                    ready_tx.send(()).unwrap();
                    iroha_logger::info!("done sending");
                    loop {
                        if signal.is_sent() {
                            graceful.fetch_or(true, Ordering::Relaxed);
                            break;
                        }
                        std::thread::sleep(LOOP_SLEEP);
                    }
                },
            )),
            OnShutdown::Wait(TIMEOUT),
        ));
        // need to yield so that it can actually start the thread
        tokio::task::yield_now().await;
        let sup_fut = tokio::spawn(sup.start());

        ready_rx
            .recv_timeout(OS_THREAD_SPAWN_TICK)
            .expect("thread should start by now");
        signal2.send();
        timeout(TICK_TIMEOUT, sup_fut)
            .await
            .expect("should shutdown within timeout")
            .expect("should not panic")
            .expect("should shutdown without errors");
        assert!(graceful2.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn can_catch_os_thread_panic() {
        let mut sup = Supervisor::new();
        sup.monitor(tokio::spawn(spawn_os_thread_as_future(
            std::thread::Builder::new(),
            || panic!("oops"),
        )));
        let Error::ChildPanicked = timeout(OS_THREAD_SPAWN_TICK, sup.start())
            .await
            .expect("should terminate immediately")
            .expect_err("should catch panic")
        else {
            panic!("no other error expected");
        };
    }
}
