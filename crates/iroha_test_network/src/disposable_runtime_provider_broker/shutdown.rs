//! Original optional broker termination evidence, separate from best-effort cleanup.

use super::*;
use color_eyre::eyre::ensure;
use std::io;

/// Retained termination evidence for the broker attached to one original daemon boot.
///
/// Capture this from the live peer before shutdown. A later provider configuration
/// cannot add or remove that boot's helper obligation. Cleanup remains best effort;
/// qualification explicitly verifies this exact retained source afterward.
#[derive(Clone, Debug)]
pub struct DisposableBrokerShutdownEvidence(Arc<OriginalBrokerShutdown>);

#[derive(Debug)]
struct OriginalBrokerShutdown {
    owner: Arc<AtomicUsize>,
    run: usize,
    daemon_pid: Option<u32>,
    expected: bool,
    broker_pid: Option<u32>,
    receipt: OnceLock<BrokerShutdownReceipt>,
    duplicate: AtomicBool,
}

#[derive(Debug)]
struct BrokerShutdownReceipt {
    broker_pid: Option<u32>,
    outcome: Option<BrokerShutdownOutcome>,
}

#[derive(Debug)]
pub(crate) enum BrokerWait {
    Terminated(ExitStatus),
    Failed(io::Error),
    TimedOut,
}

#[derive(Debug)]
struct ForcedCleanup {
    kill: io::Result<()>,
    wait: io::Result<ExitStatus>,
}

/// Preserve both the original wait and any subsequent best-effort cleanup.
#[derive(Debug)]
pub(crate) struct BrokerShutdownOutcome {
    observation_error: Option<io::Error>,
    signal_error: Option<nix::errno::Errno>,
    original: BrokerWait,
    cleanup: Option<ForcedCleanup>,
}

impl BrokerShutdownOutcome {
    fn require_success(&self) -> Result<()> {
        let cleanup = self
            .cleanup
            .as_ref()
            .map(|cleanup| (&cleanup.kill, &cleanup.wait));
        if let Some(error) = &self.observation_error {
            return Err(eyre!(
                "original broker terminal observation failed: {error}; cleanup: {cleanup:?}"
            ));
        }
        if let Some(error) = self.signal_error {
            // The original child can finish between try_wait and SIGTERM. A
            // verified successful wait is sufficient when the process is gone;
            // no other signal error or failed terminal can use this exception.
            let already_closed = error == nix::errno::Errno::ESRCH
                && matches!(&self.original, BrokerWait::Terminated(status) if status.success());
            ensure!(
                already_closed,
                "original broker SIGTERM failed: {error}; cleanup: {cleanup:?}"
            );
        }
        match &self.original {
            BrokerWait::Terminated(status) if status.success() && self.cleanup.is_none() => Ok(()),
            BrokerWait::Terminated(status) => Err(eyre!(
                "original broker terminated unsuccessfully: {status}; cleanup: {cleanup:?}"
            )),
            BrokerWait::Failed(error) => Err(eyre!(
                "original broker wait failed: {error}; cleanup: {cleanup:?}"
            )),
            BrokerWait::TimedOut => Err(eyre!(
                "original broker exceeded {BROKER_STOP_TIMEOUT:?}; cleanup: {cleanup:?}"
            )),
        }
    }
}

impl DisposableBrokerShutdownEvidence {
    pub(crate) fn new(
        peer: &NetworkPeer,
        run: usize,
        daemon_pid: Option<u32>,
        expected: bool,
        broker_pid: Option<u32>,
    ) -> Self {
        Self(Arc::new(OriginalBrokerShutdown {
            owner: Arc::clone(&peer.runs_count),
            run,
            daemon_pid,
            expected,
            broker_pid,
            receipt: OnceLock::new(),
            duplicate: AtomicBool::new(false),
        }))
    }

    pub(crate) fn complete(&self, broker_pid: Option<u32>, outcome: Option<BrokerShutdownOutcome>) {
        let receipt = BrokerShutdownReceipt {
            broker_pid,
            outcome,
        };
        // Log the actual helper outcome separately from daemon terminals. Preserve
        // the first receipt; a second completion never overwrites original evidence.
        println!(
            "TEST_NETWORK broker shutdown run={} daemon_pid={:?} expected={} original_pid={:?} observed_pid={broker_pid:?} outcome={:?}",
            self.0.run, self.0.daemon_pid, self.0.expected, self.0.broker_pid, receipt.outcome,
        );
        if self.0.receipt.set(receipt).is_err() {
            self.0.duplicate.store(true, Ordering::Relaxed);
        }
    }

    fn verify(&self, peer: &NetworkPeer, daemon_pid: u32) -> Result<()> {
        ensure!(
            Arc::ptr_eq(&self.0.owner, &peer.runs_count)
                && self.0.run == peer.runs_count.load(Ordering::Relaxed)
                && self.0.daemon_pid == Some(daemon_pid),
            "broker shutdown source belongs to another peer, daemon or boot"
        );
        ensure!(
            !self.0.duplicate.load(Ordering::Relaxed),
            "broker shutdown completed more than once"
        );
        let receipt = self
            .0
            .receipt
            .get()
            .ok_or_else(|| eyre!("original broker shutdown has no terminal receipt"))?;
        ensure!(
            receipt.broker_pid == self.0.broker_pid,
            "retiring broker PID differs from its original boot"
        );
        match (self.0.expected, self.0.broker_pid, &receipt.outcome) {
            (false, None, None) => Ok(()),
            (true, Some(_), Some(outcome)) => outcome.require_success(),
            _ => Err(eyre!(
                "original optional broker is missing or was substituted"
            )),
        }
    }
}

impl NetworkPeer {
    /// Retain the actual live boot's optional broker source before any cleanup.
    ///
    /// # Errors
    /// Refuses an absent run or a run without original broker supervision evidence.
    /// This does not inspect the current provider configuration.
    pub async fn disposable_broker_shutdown_evidence(
        &self,
    ) -> Result<DisposableBrokerShutdownEvidence> {
        let run = self.run.lock().await;
        let run = run.as_ref().ok_or_else(|| {
            eyre!("cannot capture broker evidence without the original live daemon run")
        })?;
        let source = run
            .broker_shutdown
            .as_ref()
            .ok_or_else(|| eyre!("live daemon run omitted its original optional broker source"))?;
        ensure!(
            source.0.daemon_pid == run.pid
                && source.0.expected == run.broker_child.is_some()
                && source.0.broker_pid == run.broker_child.as_ref().and_then(Child::id),
            "live broker source differs from its original daemon run"
        );
        Ok(source.clone())
    }

    /// Require successful cleanup of the exact optional broker retained before shutdown.
    ///
    /// # Errors
    /// Refuses missing, stale, duplicate or substituted evidence and preserves failed
    /// signals, unsuccessful exits, wait errors and the original timeout. Successful
    /// forced cleanup cannot turn an earlier refusal into a qualifying terminal.
    pub fn verify_disposable_broker_shutdown(
        &self,
        source: &DisposableBrokerShutdownEvidence,
        original_daemon_pid: u32,
    ) -> Result<()> {
        source.verify(self, original_daemon_pid)
    }
}

/// Stop the original helper with the existing deadline and retain every observed result.
pub(crate) async fn stop_disposable_broker(child: &mut Child) -> BrokerShutdownOutcome {
    let observation_error = match child.try_wait() {
        Ok(Some(status)) => {
            // This is the original Child's actual terminal, never a replacement
            // PID observation. A completed helper needs no shutdown signal.
            return BrokerShutdownOutcome {
                observation_error: None,
                signal_error: None,
                original: BrokerWait::Terminated(status),
                cleanup: None,
            };
        }
        Ok(None) => None,
        Err(error) => Some(error),
    };
    let signal_error = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .and_then(|pid| {
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGTERM,
            )
            .err()
        });
    let original = match timeout(BROKER_STOP_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => BrokerWait::Terminated(status),
        Ok(Err(error)) => BrokerWait::Failed(error),
        Err(_) => BrokerWait::TimedOut,
    };
    let cleanup = if matches!(&original, BrokerWait::Terminated(_)) {
        None
    } else {
        // Preserve the original fallback sequence and its timing. Both cleanup
        // results survive; neither replaces the original wait's failure/timeout.
        let kill = child.kill().await;
        let wait = child.wait().await;
        Some(ForcedCleanup { kill, wait })
    };
    BrokerShutdownOutcome {
        observation_error,
        signal_error,
        original,
        cleanup,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt as _;

    fn success() -> BrokerShutdownOutcome {
        BrokerShutdownOutcome {
            observation_error: None,
            signal_error: None,
            original: BrokerWait::Terminated(ExitStatus::from_raw(0)),
            cleanup: None,
        }
    }

    async fn child_with_term_handler(exit_code: Option<i32>) -> Result<Child> {
        let action = exit_code.map_or_else(
            || "signal.SIG_IGN".to_owned(),
            |code| format!("lambda *unused: sys.exit({code})"),
        );
        let mut child = tokio::process::Command::new("python3")
            .args(["-c", &format!("import os,signal,sys\nsignal.signal(signal.SIGTERM, {action})\nos.write(1,b'R')\nwhile True: signal.pause()\n")])
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null())
            .kill_on_drop(true).spawn().wrap_err("broker shutdown controls require python3 on PATH")?;
        let mut ready = [0; 1];
        timeout(
            Duration::from_secs(5),
            child.stdout.as_mut().unwrap().read_exact(&mut ready),
        )
        .await??;
        assert_eq!(ready, *b"R");
        Ok(child)
    }

    #[tokio::test]
    async fn actual_broker_shutdown_preserves_success_and_nonzero_terminal() -> Result<()> {
        for code in [0, 7] {
            let mut child = child_with_term_handler(Some(code)).await?;
            let original_pid = child.id().expect("original live broker");
            let outcome = stop_disposable_broker(&mut child).await;
            assert!(original_pid > 0 && child.id().is_none());
            assert!(
                matches!(&outcome.original, BrokerWait::Terminated(status) if status.code() == Some(code))
            );
            assert!(outcome.cleanup.is_none());
            assert_eq!(outcome.require_success().is_ok(), code == 0);

            let mut completed = tokio::process::Command::new("python3")
                .args(["-c", &format!("import sys; sys.exit({code})")])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .wrap_err("broker natural-terminal controls require python3 on PATH")?;
            let original_terminal = timeout(Duration::from_secs(5), completed.wait()).await??;
            let natural = stop_disposable_broker(&mut completed).await;
            assert!(matches!(&natural.original, BrokerWait::Terminated(status)
                if *status == original_terminal && status.code() == Some(code)));
            assert!(natural.observation_error.is_none() && natural.signal_error.is_none());
            assert!(natural.cleanup.is_none());
            assert_eq!(natural.require_success().is_ok(), code == 0);
        }
        // Exact ESRCH between observation and signaling is harmless only when
        // the original wait independently proves a successful terminal.
        let closed_during_signal = BrokerShutdownOutcome {
            signal_error: Some(nix::errno::Errno::ESRCH),
            ..success()
        };
        closed_during_signal.require_success()?;
        let failed_during_signal = BrokerShutdownOutcome {
            original: BrokerWait::Terminated(ExitStatus::from_raw(7 << 8)),
            signal_error: Some(nix::errno::Errno::ESRCH),
            ..success()
        };
        assert!(failed_during_signal.require_success().is_err());
        let missing_during_signal = BrokerShutdownOutcome {
            original: BrokerWait::Failed(io::Error::from_raw_os_error(5)),
            signal_error: Some(nix::errno::Errno::ESRCH),
            ..success()
        };
        assert!(missing_during_signal.require_success().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn original_broker_timeout_is_reaped_without_becoming_success() -> Result<()> {
        let mut child = child_with_term_handler(None).await?;
        let outcome = stop_disposable_broker(&mut child).await;
        assert!(matches!(&outcome.original, BrokerWait::TimedOut));
        let cleanup = outcome.cleanup.as_ref().expect("original fallback cleanup");
        assert!(cleanup.kill.is_ok());
        assert!(cleanup.wait.as_ref().is_ok_and(|status| !status.success()));
        assert!(child.id().is_none());
        assert!(outcome.require_success().is_err());
        // A successful cleanup terminal also cannot erase the earlier timeout.
        let late = BrokerShutdownOutcome {
            observation_error: None,
            signal_error: None,
            original: BrokerWait::TimedOut,
            cleanup: Some(ForcedCleanup {
                kill: Ok(()),
                wait: Ok(ExitStatus::from_raw(0)),
            }),
        };
        assert!(late.require_success().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn retiring_run_retains_actual_optional_broker_receipt_through_best_effort_cleanup()
    -> Result<()> {
        let environment = Environment::new();
        let peer = NetworkPeer::builder().build(&environment);
        peer.runs_count.store(1, Ordering::Relaxed);
        let child = child_with_term_handler(Some(7)).await?;
        let source = DisposableBrokerShutdownEvidence::new(&peer, 1, Some(100), true, child.id());
        let (shutdown, _shutdown_rx) = oneshot::channel();
        let (fatal_tx, _fatal_rx) = watch::channel(false);
        *peer.run.lock().await = Some(PeerRun {
            tasks: JoinSet::new(),
            shutdown,
            fatal_tx,
            pid: Some(100),
            broker_child: Some(child),
            broker_shutdown: Some(source),
        });
        let retained = peer.disposable_broker_shutdown_evidence().await?;
        assert!(peer.shutdown_if_started().await);
        assert!(
            peer.run.lock().await.is_none(),
            "a failed helper cannot interrupt daemon cleanup"
        );
        assert!(
            peer.disposable_broker_shutdown_evidence().await.is_err(),
            "retired evidence cannot be recaptured from a missing run"
        );
        assert!(
            peer.verify_disposable_broker_shutdown(&retained, 100)
                .is_err()
        );
        assert!(
            matches!(&retained.0.receipt.get().unwrap().outcome.as_ref().unwrap().original,
            BrokerWait::Terminated(status) if status.code() == Some(7))
        );
        assert!(
            !peer.shutdown_if_started().await,
            "cleanup is idempotent, without replacing evidence"
        );
        assert!(
            peer.verify_disposable_broker_shutdown(&retained, 100)
                .is_err()
        );
        // The next actual run has no helper, despite a current provider config.
        peer.runs_count.store(2, Ordering::Relaxed);
        let absent = DisposableBrokerShutdownEvidence::new(&peer, 2, Some(101), false, None);
        peer.provision_disposable_runtime_provider_broker(
            b"future catalog",
            Zeroizing::new(vec![1]),
            DisposableBeaconProviderBinding {
                handle: "software://iroha/global-beacon/validator-a".to_owned(),
                revision: 1,
                policy_digest: [1; 32],
            },
        )
        .await?;
        let (shutdown, _shutdown_rx) = oneshot::channel();
        let (fatal_tx, _fatal_rx) = watch::channel(false);
        *peer.run.lock().await = Some(PeerRun {
            tasks: JoinSet::new(),
            shutdown,
            fatal_tx,
            pid: Some(101),
            broker_child: None,
            broker_shutdown: Some(absent),
        });
        let retained_absence = peer.disposable_broker_shutdown_evidence().await?;
        assert!(peer.shutdown_if_started().await);
        peer.verify_disposable_broker_shutdown(&retained_absence, 101)?;
        assert!(
            peer.verify_disposable_broker_shutdown(&retained, 100)
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn original_broker_receipt_rejects_missing_stale_and_changed_boot_without_config_inference()
    -> Result<()> {
        let environment = Environment::new();
        let peer = NetworkPeer::builder().build(&environment);
        peer.runs_count.store(1, Ordering::Relaxed);
        let original = DisposableBrokerShutdownEvidence::new(&peer, 1, Some(100), true, Some(200));
        assert!(
            peer.verify_disposable_broker_shutdown(&original, 100)
                .is_err(),
            "missing terminal must fail"
        );
        original.complete(Some(200), Some(success()));
        peer.verify_disposable_broker_shutdown(&original, 100)?;
        assert!(
            peer.verify_disposable_broker_shutdown(&original, 101)
                .is_err()
        );
        let foreign = NetworkPeer::builder().build(&environment);
        foreign.runs_count.store(1, Ordering::Relaxed);
        assert!(
            foreign
                .verify_disposable_broker_shutdown(&original, 100)
                .is_err()
        );
        peer.runs_count.store(2, Ordering::Relaxed);
        assert!(
            peer.verify_disposable_broker_shutdown(&original, 100)
                .is_err(),
            "same PID cannot revive an old boot"
        );
        let changed = DisposableBrokerShutdownEvidence::new(&peer, 2, Some(100), true, Some(201));
        changed.complete(Some(200), Some(success()));
        assert!(
            peer.verify_disposable_broker_shutdown(&changed, 100)
                .is_err()
        );
        let missing = DisposableBrokerShutdownEvidence::new(&peer, 2, Some(100), true, Some(201));
        missing.complete(None, None);
        assert!(
            peer.verify_disposable_broker_shutdown(&missing, 100)
                .is_err()
        );
        // Install a future provider before retiring a boot that never had one.
        // This must not invent a helper obligation for the old boot.
        peer.provision_disposable_runtime_provider_broker(
            b"future catalog",
            Zeroizing::new(vec![1]),
            DisposableBeaconProviderBinding {
                handle: "software://iroha/global-beacon/validator-a".to_owned(),
                revision: 1,
                policy_digest: [1; 32],
            },
        )
        .await?;
        let absent = DisposableBrokerShutdownEvidence::new(&peer, 2, Some(100), false, None);
        absent.complete(None, None);
        peer.verify_disposable_broker_shutdown(&absent, 100)?;
        absent.complete(None, None);
        assert!(
            peer.verify_disposable_broker_shutdown(&absent, 100)
                .is_err(),
            "duplicate terminal must fail"
        );
        let wait_failed = BrokerShutdownOutcome {
            observation_error: None,
            signal_error: None,
            original: BrokerWait::Failed(io::Error::from_raw_os_error(5)),
            cleanup: Some(ForcedCleanup {
                kill: Ok(()),
                wait: Ok(ExitStatus::from_raw(0)),
            }),
        };
        assert!(wait_failed.require_success().is_err());
        assert!(
            matches!(&wait_failed.original, BrokerWait::Failed(error) if error.raw_os_error() == Some(5))
        );
        let observation_failed = BrokerShutdownOutcome {
            observation_error: Some(io::Error::from_raw_os_error(5)),
            ..success()
        };
        assert!(observation_failed.require_success().is_err());
        assert_eq!(
            observation_failed
                .observation_error
                .as_ref()
                .unwrap()
                .raw_os_error(),
            Some(5)
        );
        let signal_failed = BrokerShutdownOutcome {
            signal_error: Some(nix::errno::Errno::EPERM),
            ..success()
        };
        assert!(signal_failed.require_success().is_err());
        Ok(())
    }
}
