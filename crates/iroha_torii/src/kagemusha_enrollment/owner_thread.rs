//! Bounded command ownership keeps blocking clients and subprocess custody on one native thread.
use super::*;
use iroha_futures::supervisor::ShutdownSignal;
use std::{
    sync::{Mutex, mpsc},
    thread,
};

type Reply = Result<EnrollmentServiceResponseV1>;
struct Command {
    call: HttpCall,
    reply: mpsc::SyncSender<Reply>,
}
pub(super) struct OwnerThread {
    sender: Mutex<Option<mpsc::SyncSender<Command>>>,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
    completed: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}
impl OwnerThread {
    pub(super) fn open(state: Arc<CoreState>, config: KagemushaEnrollmentIssuer) -> Result<Self> {
        let capacity = config.max_inflight;
        Self::start(
            capacity,
            move || {
                let providers = config
                    .providers
                    .iter()
                    .map(ProviderOwner::open)
                    .collect::<Result<Vec<_>>>()?;
                let runtime = Runtime {
                    state: Arc::clone(&state),
                    configured: Arc::new(config),
                    providers,
                };
                let owner = EnrollmentIssuerV1::open(state, runtime)?;
                Ok(owner)
            },
            execute,
        )
    }
    fn start<T: Send + 'static>(
        capacity: usize,
        initialize: impl FnOnce() -> Result<T> + Send + 'static,
        operation: fn(&mut T, &HttpCall) -> Reply,
    ) -> Result<Self> {
        if !(1..=1024).contains(&capacity) {
            return Err(IssuerError::Selection);
        }
        let (sender, commands) = mpsc::sync_channel::<Command>(capacity);
        let (ready, initialized) = mpsc::sync_channel(1);
        let (finished, completed) = tokio::sync::oneshot::channel();
        let thread = thread::Builder::new()
            .name("kagemusha-enrollment".into())
            .spawn(move || {
                let mut owner = match initialize() {
                    Ok(owner) => owner,
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                if ready.send(Ok(())).is_err() {
                    return;
                }
                // The owner is constructed, used and dropped in this same thread. Once the last
                // sender closes, every already accepted operation finishes before custody drops.
                for command in commands {
                    let result = operation(&mut owner, &command.call);
                    let _ = command.reply.send(result);
                }
                // Completion follows actual client/process/journal destruction. A panic drops
                // the sender instead, and the supervisor still joins the exact native thread.
                drop(owner);
                let _ = finished.send(());
            })
            .map_err(|_| IssuerError::Unavailable)?;
        match initialized
            .recv()
            .map_err(|_| IssuerError::Unavailable)
            .and_then(|ready| ready)
        {
            Ok(()) => Ok(Self {
                sender: Mutex::new(Some(sender)),
                thread: Mutex::new(Some(thread)),
                completed: Mutex::new(Some(completed)),
            }),
            Err(error) => {
                drop(sender);
                let _ = thread.join();
                Err(error)
            }
        }
    }
    pub(super) fn execute(&self, call: HttpCall) -> Reply {
        let (reply, result) = mpsc::sync_channel(1);
        {
            let sender = self.sender.lock().map_err(|_| IssuerError::Unavailable)?;
            sender
                .as_ref()
                .ok_or(IssuerError::Unavailable)?
                .try_send(Command { call, reply })
                .map_err(|_| IssuerError::Unavailable)?;
        }
        // Called only on the handler's blocking worker. Losing the HTTP receiver never cancels
        // an accepted monetary-authority boundary or releases its journal prematurely.
        result.recv().map_err(|_| IssuerError::Unavailable)?
    }

    /// Transfer the sole completion observer to Torii's retained critical-worker mechanism.
    pub(super) fn supervise(
        self: &Arc<Self>,
        shutdown: ShutdownSignal,
        slots: Arc<tokio::sync::Semaphore>,
    ) -> std::result::Result<tokio::task::JoinHandle<crate::ToriiCriticalWorkerExit>, &'static str>
    {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "enrollment supervision requires the existing async runtime")?;
        let completed = self
            .completed
            .lock()
            .map_err(|_| "enrollment completion state is poisoned")?
            .take()
            .ok_or("enrollment worker was already registered")?;
        let owner = Arc::clone(self);
        Ok(runtime.spawn(async move {
            let requested = tokio::select! {
                () = shutdown.receive() => true,
                _ = completed => shutdown.is_sent(),
            };
            owner.close_admission();
            slots.close();
            // Closing admission prevents new queued work; already accepted commands retain
            // their exact durable owners until completion and destruction. Never block Tokio
            // on the native thread or private process join.
            let joined = tokio::task::spawn_blocking(move || owner.close_and_join()).await;
            if requested && matches!(joined, Ok(true)) {
                crate::ToriiCriticalWorkerExit::StoppedByShutdown
            } else {
                crate::ToriiCriticalWorkerExit::UnexpectedExit
            }
        }))
    }

    fn close_and_join(&self) -> bool {
        self.close_admission();
        let owner = self
            .thread
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        owner.is_some_and(|owner| owner.join().is_ok())
    }

    fn close_admission(&self) {
        drop(
            self.sender
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take(),
        );
    }
}
impl Drop for OwnerThread {
    fn drop(&mut self) {
        drop(
            self.sender
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take(),
        );
        if let Some(owner) = self
            .thread
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            // Router handles may be destroyed by Tokio. Joining on a separate native thread
            // keeps blocking-client Drop and the subprocess join off that async dispatcher.
            // If thread creation fails, dropping JoinHandle detaches only the join handle;
            // the command channel is already closed and its thread still owns all custody.
            let _ = thread::Builder::new()
                .name("kagemusha-enrollment-join".into())
                .spawn(move || {
                    let _ = owner.join();
                });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    struct OwnedClient {
        client: Option<reqwest::blocking::Client>,
        dropped: Arc<AtomicBool>,
    }
    impl Drop for OwnedClient {
        fn drop(&mut self) {
            assert!(tokio::runtime::Handle::try_current().is_err());
            drop(self.client.take());
            self.dropped.store(true, Ordering::Release);
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn blocking_client_entire_lifetime_stays_outside_tokio() {
        let dropped = Arc::new(AtomicBool::new(false));
        let observed = dropped.clone();
        let owner = OwnerThread::start(
            1,
            move || {
                assert!(tokio::runtime::Handle::try_current().is_err());
                Ok(OwnedClient {
                    client: Some(
                        reqwest::blocking::Client::builder()
                            .no_proxy()
                            .build()
                            .unwrap(),
                    ),
                    dropped: observed,
                })
            },
            |_, _| Ok(EnrollmentServiceResponseV1::Pending),
        )
        .unwrap();
        drop(owner);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !dropped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    #[test]
    fn startup_errors_and_panics_are_not_ready_owners() {
        assert!(matches!(
            OwnerThread::start::<()>(1, || Err(IssuerError::Selection), |_, _| unreachable!()),
            Err(IssuerError::Selection)
        ));
        assert!(matches!(
            OwnerThread::start::<()>(
                1,
                || panic!("fixture initializer panic"),
                |_, _| unreachable!()
            ),
            Err(IssuerError::Unavailable)
        ));
        assert!(matches!(
            OwnerThread::start::<()>(0, || Ok(()), |_, _| unreachable!()),
            Err(IssuerError::Selection)
        ));
    }
    #[test]
    fn closing_queue_finishes_accepted_command_before_owner_custody_drops() {
        struct Custody {
            release: mpsc::Receiver<()>,
            started: mpsc::SyncSender<()>,
            completed: mpsc::SyncSender<bool>,
            finished: bool,
        }
        impl Drop for Custody {
            fn drop(&mut self) {
                self.completed.send(self.finished).unwrap();
            }
        }
        let (release, released) = mpsc::sync_channel(1);
        let (started, began) = mpsc::sync_channel(1);
        let (completed, dropped) = mpsc::sync_channel(1);
        let owner = OwnerThread::start(
            1,
            move || {
                Ok(Custody {
                    release: released,
                    started,
                    completed,
                    finished: false,
                })
            },
            |owner, _| {
                owner.started.send(()).unwrap();
                owner.release.recv().unwrap();
                owner.finished = true;
                Ok(EnrollmentServiceResponseV1::Pending)
            },
        )
        .unwrap();
        let (reply, result) = mpsc::sync_channel(1);
        owner
            .sender
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .send(Command {
                call: HttpCall {
                    method: axum::http::Method::POST,
                    uri: ENROLLMENT_SERVICE_ROUTE_V1.parse().unwrap(),
                    headers: axum::http::HeaderMap::new(),
                    body: axum::body::Bytes::new(),
                },
                reply,
            })
            .unwrap();
        began
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        drop(owner);
        assert!(matches!(dropped.try_recv(), Err(mpsc::TryRecvError::Empty)));
        release.send(()).unwrap();
        assert_eq!(
            result
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap()
                .unwrap(),
            EnrollmentServiceResponseV1::Pending
        );
        assert!(
            dropped
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap()
        );
    }

    fn empty_call() -> HttpCall {
        HttpCall {
            method: axum::http::Method::POST,
            uri: ENROLLMENT_SERVICE_ROUTE_V1.parse().unwrap(),
            headers: axum::http::HeaderMap::new(),
            body: axum::body::Bytes::new(),
        }
    }

    #[tokio::test]
    async fn supervised_shutdown_joins_accepted_operation_and_actual_custody_drop() {
        struct Custody {
            release: mpsc::Receiver<()>,
            started: mpsc::SyncSender<()>,
            dropped: Arc<AtomicBool>,
        }
        impl Drop for Custody {
            fn drop(&mut self) {
                assert!(tokio::runtime::Handle::try_current().is_err());
                self.dropped.store(true, Ordering::Release);
            }
        }
        let (release, released) = mpsc::sync_channel(1);
        let (started, began) = mpsc::sync_channel(1);
        let dropped = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&dropped);
        let owner = Arc::new(
            OwnerThread::start(
                1,
                move || {
                    Ok(Custody {
                        release: released,
                        started,
                        dropped: observed,
                    })
                },
                |owner, _| {
                    owner.started.send(()).unwrap();
                    owner.release.recv().unwrap();
                    Ok(EnrollmentServiceResponseV1::Pending)
                },
            )
            .unwrap(),
        );
        let shutdown = ShutdownSignal::new();
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let worker = owner
            .supervise(shutdown.clone(), Arc::clone(&slots))
            .unwrap();
        assert!(
            owner
                .supervise(shutdown.clone(), Arc::clone(&slots))
                .is_err()
        );
        let (reply, result) = mpsc::sync_channel(1);
        owner
            .sender
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .send(Command {
                call: empty_call(),
                reply,
            })
            .unwrap();
        began
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        shutdown.send();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !slots.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!worker.is_finished());
        assert!(!dropped.load(Ordering::Acquire));
        assert!(matches!(
            owner.execute(empty_call()),
            Err(IssuerError::Unavailable)
        ));
        release.send(()).unwrap();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), worker)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            outcome,
            crate::ToriiCriticalWorkerExit::StoppedByShutdown
        ));
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(
            result.recv().unwrap().unwrap(),
            EnrollmentServiceResponseV1::Pending
        );
        assert!(owner.thread.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn unexpected_native_owner_exit_is_reported_and_joined() {
        for shutdown_requested in [false, true] {
            let owner = Arc::new(
                OwnerThread::start(
                    1,
                    || Ok(()),
                    |_, _| {
                        panic!("fixture accepted-operation panic");
                    },
                )
                .unwrap(),
            );
            let shutdown = ShutdownSignal::new();
            let slots = Arc::new(tokio::sync::Semaphore::new(1));
            let worker = owner
                .supervise(shutdown.clone(), Arc::clone(&slots))
                .unwrap();
            let (reply, result) = mpsc::sync_channel(1);
            owner
                .sender
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .send(Command {
                    call: empty_call(),
                    reply,
                })
                .unwrap();
            if shutdown_requested {
                shutdown.send();
            }
            let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), worker)
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(
                outcome,
                crate::ToriiCriticalWorkerExit::UnexpectedExit
            ));
            // A panic remains UnexpectedExit even when it races with requested shutdown.
            assert_eq!(shutdown.is_sent(), shutdown_requested);
            assert!(slots.is_closed());
            assert!(result.recv().is_err());
            assert!(owner.thread.lock().unwrap().is_none());
            assert!(matches!(
                owner.execute(empty_call()),
                Err(IssuerError::Unavailable)
            ));
        }
    }
}
