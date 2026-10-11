//! Snapshot readiness gate: success-only startup recovery authorization for background
//! storage writers.

use iroha_futures::supervisor::ShutdownSignal;
use tokio::sync::watch;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Pending,
    Ready,
    Failed,
}

/// Read-only authorization to start background storage maintenance.
///
/// This records completion of authenticated startup recovery, not consensus
/// ingress readiness or continuing peer health. An orderly worker exit retains
/// `Ready` for delayed observers. Worker failure or unwind revokes authorization;
/// writers check it again before starting each operation.
#[derive(Clone, Debug)]
pub struct StartupRecovery {
    receiver: watch::Receiver<Phase>,
}

impl StartupRecovery {
    /// Wait for explicit successful recovery, refusing failure and shutdown.
    pub async fn wait_for_success(&mut self, shutdown: &ShutdownSignal) -> bool {
        loop {
            if shutdown.is_sent() {
                return false;
            }
            let phase = *self.receiver.borrow();
            match phase {
                Phase::Ready => return true,
                Phase::Failed => return false,
                Phase::Pending => {}
            }
            tokio::select! {
                biased;
                () = shutdown.receive() => return false,
                changed = self.receiver.changed() => {
                    if changed.is_err() {
                        return self.is_ready() && !shutdown.is_sent();
                    }
                }
            }
        }
    }

    /// Whether startup recovery currently authorizes a new storage operation.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        *self.receiver.borrow() == Phase::Ready
    }

    /// Wait until the recovery owner fails, including an unsuccessful drop.
    ///
    /// Normal completion after `Ready` is retained and never becomes failure
    /// merely because the notification sender no longer exists.
    pub async fn failed(&mut self) {
        loop {
            if *self.receiver.borrow() == Phase::Failed {
                return;
            }
            if self.receiver.changed().await.is_err() {
                if self.is_ready() {
                    std::future::pending::<()>().await;
                }
                return;
            }
        }
    }
}

/// Only the consensus worker owns the ability to publish successful recovery.
/// Its outer run guard distinguishes normal completion from failure/unwind.
pub(crate) struct StartupRecoveryPublisher {
    sender: watch::Sender<Phase>,
    finished: bool,
}

impl StartupRecoveryPublisher {
    pub(crate) fn ready(&self) {
        // Startup completion can race a worker failure. Failure is terminal.
        self.sender.send_if_modified(|phase| {
            if *phase != Phase::Pending {
                return false;
            }
            *phase = Phase::Ready;
            true
        });
    }

    /// Revoke maintenance after a runtime halt or worker failure.
    pub(crate) fn fail(&self) {
        self.sender.send_replace(Phase::Failed);
    }

    pub(crate) fn finish(&mut self) {
        if *self.sender.borrow() == Phase::Pending {
            self.sender.send_replace(Phase::Failed);
        }
        self.finished = true;
    }
}

impl Drop for StartupRecoveryPublisher {
    fn drop(&mut self) {
        if !self.finished {
            self.sender.send_replace(Phase::Failed);
        }
    }
}

/// A fresh pending readiness gate and its only publisher.
pub(crate) fn channel() -> (StartupRecoveryPublisher, StartupRecovery) {
    let (sender, receiver) = watch::channel(Phase::Pending);
    (
        StartupRecoveryPublisher {
            sender,
            finished: false,
        },
        StartupRecovery { receiver },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::SnapshotMaker;
    use std::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
        time::Duration,
    };

    fn poll_once<F: Future>(future: std::pin::Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    #[tokio::test]
    async fn maintenance_waits_for_recovery_before_budget_or_snapshot_writes() {
        let directory = tempfile::tempdir().expect("public test output directory");
        let budget = directory.path().join("budget");
        let snapshot = directory.path().join("snapshot");
        let (owner, readiness) = channel();
        let shutdown = ShutdownSignal::new();
        let work = SnapshotMaker::run_startup_maintenance(
            readiness,
            shutdown,
            || std::fs::write(&budget, b"budget").expect("budget writer"),
            |_, _| async {
                assert!(budget.exists(), "budget executes before snapshot work");
                std::fs::write(&snapshot, b"snapshot").expect("snapshot writer");
            },
        );
        let mut work = pin!(work);
        assert!(poll_once(work.as_mut()).is_pending());
        assert!(!budget.exists() && !snapshot.exists());
        owner.ready();
        work.await;
        assert_eq!(std::fs::read(&budget).unwrap(), b"budget");
        assert_eq!(std::fs::read(&snapshot).unwrap(), b"snapshot");
    }

    #[tokio::test]
    async fn maintenance_refuses_failed_dropped_and_shutdown_recovery() {
        for failure in [
            "drop_pending",
            "failure_after_ready",
            "shutdown_pending",
            "shutdown_ready",
        ] {
            let directory = tempfile::tempdir().expect("test directory");
            let budget = directory.path().join("budget");
            let snapshot = directory.path().join("snapshot");
            let (owner, readiness) = channel();
            let shutdown = ShutdownSignal::new();
            let stop = shutdown.clone();
            let work = SnapshotMaker::run_startup_maintenance(
                readiness,
                shutdown,
                || std::fs::write(&budget, b"forbidden").unwrap(),
                |_, _| async {
                    std::fs::write(&snapshot, b"forbidden").unwrap();
                },
            );
            let mut work = pin!(work);
            assert!(poll_once(work.as_mut()).is_pending());
            match failure {
                "drop_pending" => drop(owner),
                "failure_after_ready" => {
                    owner.ready();
                    drop(owner);
                }
                "shutdown_pending" => {
                    stop.send();
                    drop(owner);
                }
                "shutdown_ready" => {
                    owner.ready();
                    stop.send();
                }
                _ => unreachable!(),
            }
            work.await;
            assert!(!budget.exists() && !snapshot.exists(), "{failure}");
        }
    }

    #[tokio::test]
    async fn maintenance_retains_success_for_delayed_readonly_snapshot_subscriber() {
        let directory = tempfile::tempdir().unwrap();
        let budget = directory.path().join("budget");
        let (mut owner, readiness) = channel();
        owner.ready();
        owner.finish();
        drop(owner);
        assert!(readiness.is_ready());
        SnapshotMaker::run_startup_maintenance(
            readiness,
            ShutdownSignal::new(),
            || std::fs::write(&budget, b"once").unwrap(),
            |_, _| async {}, // Snapshot read-only mode still needs budget maintenance.
        )
        .await;
        assert_eq!(std::fs::read(&budget).unwrap(), b"once");
    }

    #[tokio::test]
    async fn snapshot_loop_stops_on_worker_failure_without_final_shutdown_write() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("snapshot-writes");
        let (owner, readiness) = channel();
        owner.ready();
        let shutdown = ShutdownSignal::new();
        let stop = shutdown.clone();
        let mut writes = 0;
        let (first_write, observed_write) = tokio::sync::oneshot::channel();
        let mut first_write = Some(first_write);
        let work = SnapshotMaker::run_snapshot_loop(
            Duration::from_secs(3600),
            readiness,
            shutdown,
            || {
                writes += 1;
                std::fs::write(&output, writes.to_string()).unwrap();
                if let Some(first_write) = first_write.take() {
                    let _ = first_write.send(());
                }
            },
        );
        let mut work = pin!(work);
        tokio::select! {
            () = &mut work => panic!("snapshot loop stopped before worker failure"),
            observed = tokio::time::timeout(Duration::from_secs(5), observed_write) => {
                observed.expect("bounded first snapshot tick").expect("first write acknowledged");
            }
        }
        assert_eq!(std::fs::read_to_string(&output).unwrap(), "1");
        drop(owner); // Later worker failure revokes authorization.
        stop.send(); // Failure wins over the usual shutdown snapshot.
        work.await;
        assert_eq!(std::fs::read_to_string(&output).unwrap(), "1");
    }
}
